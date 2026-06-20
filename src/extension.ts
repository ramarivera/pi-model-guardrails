// Pi extension entry point — Phase 2 deterministic guard.
//
// Thin glue around guardToolCall() (the pure engine+policy+state-machine core in
// src/guard.ts). This file is ALL the Pi-specific wiring: event handlers, state
// persistence via the session-entry API, and steering injection. No LLM grader
// is involved in Phase 2 — guardToolCall is called WITHOUT a grader, and the
// state machine's "gate-required" action maps to allow (see guard.ts).
//
// Real Pi API used (verified against
//   node_modules/@earendil-works/pi-coding-agent/dist/core/extensions/types.d.ts):
//   - ExtensionAPI / ExtensionFactory: default export is `(pi: ExtensionAPI) => void`.
//   - pi.on("session_start" | "tool_call" | "before_agent_start", handler).
//   - pi.appendEntry<T>(customType, data): persist a CustomEntry (not sent to LLM).
//   - ctx.cwd, ctx.ui.setStatus / ctx.ui.notify, ctx.sessionManager.getEntries().
//   - ToolCallEventResult { block?: boolean; reason?: string }: the BLOCK shape.
//   - BeforeAgentStartEventResult { systemPrompt?: string }: steering injection.

import { complete } from "@earendil-works/pi-ai";
import type {
  ExtensionAPI,
  ExtensionContext,
  ToolCallEvent,
} from "@earendil-works/pi-coding-agent";
import { isToolCallEventType } from "@earendil-works/pi-coding-agent";
import { defaultGraderConfig, loadGuardConfig } from "./config.ts";
import {
  type Completer,
  type GradeCache,
  type GraderModel,
  grade,
  makeCompleter,
} from "./grade.ts";
import { type GuardDeps, guardToolCall } from "./guard.ts";
import {
  createNoopTelemetry,
  type GuardrailsTelemetry,
} from "./observability.ts";
import type { Constraint } from "./policy/types.ts";
import { clearHalt, initialState } from "./state/machine.ts";
import type {
  CallMeta,
  GraderSignal,
  GuardState,
  PersistedState,
} from "./state/types.ts";
import type { GraderConfig } from "./types.ts";

export type ExtensionInfo = {
  name: string;
  description: string;
};

export const extensionInfo: ExtensionInfo = {
  name: "model-guardrails",
  description:
    "Deterministic model guardrails: blocks destructive commands and arms a " +
    "deviation state machine that gates a degraded session until it is provably back on track",
};

export function createExtension() {
  return {
    name: extensionInfo.name,
    async activate() {
      return extensionInfo;
    },
  };
}

/** Session-entry customType used to persist the deviation-machine state on resume. */
export const GUARD_STATE_ENTRY_TYPE = "model-guardrails:state";

/**
 * Test-only completer override. When set, buildCompleter() returns this directly
 * instead of wiring ctx.modelRegistry + the pi-ai complete() (which needs a real
 * model + key). Production NEVER sets this — it stays undefined. Exposed so the
 * extension's grading-enforcement wiring is unit-testable without a live LLM.
 */
let completerOverride: Completer | undefined;

/** Install (or clear with undefined) the test-only completer override. */
export function __setCompleterOverrideForTest(c: Completer | undefined): void {
  completerOverride = c;
}

/** Tools that mutate the workspace (writes / arbitrary execution). */
const MUTATING_TOOLS = new Set(["bash", "write", "edit"]);
/** Pure read/no-op tools — never advance the recovery streak, never mutate. */
const TRIVIAL_TOOLS = new Set(["read", "grep", "find", "ls"]);

export default function guardrailsExtension(pi: ExtensionAPI): void {
  // Per-session runtime. session_start (re)builds all of it.
  let deps: GuardDeps | undefined;
  let telemetry: GuardrailsTelemetry = createNoopTelemetry();
  let state: PersistedState = initialState();
  let modelWhitelist: string[] | undefined;
  let modelBlacklist: string[] | undefined;

  // Phase 3 grader runtime. session_start (re)builds these.
  let graderConfig: GraderConfig | undefined;
  let completer: Completer | undefined;
  // True when grading is REQUIRED (enabled) but no completer could be built
  // (missing model/key). The gate then FAILS CLOSED rather than waving calls
  // through ungraded — a degraded session must never go ungated.
  let graderUnavailable = false;
  // Verdict cache: (toolName, argsHash, constraintsHash, epoch) -> GraderSignal.
  let gradeCache: GradeCache | undefined;

  pi.on("session_start", async (event, ctx) => {
    const config = await loadGuardConfig(ctx.cwd);
    telemetry = config.observability;
    deps = {
      registry: config.registry,
      policy: config.policy,
      machineConfig: config.machineConfig,
      evaluateOptions: config.evaluateOptions,
    };
    modelWhitelist = config.modelWhitelist;
    modelBlacklist = config.modelBlacklist;

    // Build the Phase 3 grader completer from config + the Pi model registry
    // (the same complete()/modelRegistry mechanism src/llm.ts uses — the only
    // verified way a Pi extension runs its own completion).
    graderConfig = config.grader;
    completer = buildCompleter(ctx, config.grader);
    gradeCache = config.grader.cache ? new Map() : undefined;
    // If grading is enabled but no completer could be built, the gate fails
    // CLOSED. Warn LOUD (telemetry + a user-facing notify) so a misconfigured
    // grader is never silent.
    graderUnavailable = config.grader.enabled && completer === undefined;
    if (graderUnavailable) {
      const msg =
        `[model-guardrails] grader ENABLED but unavailable (model "${config.grader.model}" ` +
        "not resolvable / no key). Degraded mode will FAIL CLOSED: gated calls are blocked.";
      ctx.ui.notify(msg, "error");
    }

    // Rehydrate the deviation state from the latest persisted session entry, so
    // a degraded session that was resumed/forked stays degraded (the machine's
    // stateEpoch defends against a fork "resetting" an armed session).
    state = rehydrateState(ctx) ?? initialState();

    await telemetry.logEvent("session_start", {
      cwd: ctx.cwd,
      reason: event.reason,
      rehydratedState: state.state,
      stateEpoch: state.stateEpoch,
      observabilityEnabled: telemetry.enabled,
      logFile: telemetry.logFile,
      modelWhitelist: modelWhitelist ?? [],
      modelBlacklist: modelBlacklist ?? [],
      graderEnabled: config.grader.enabled,
      graderModel: config.grader.model,
      graderAvailable: !graderUnavailable && completer !== undefined,
      graderUnavailable,
    });

    setStatus(ctx, state);
  });

  pi.on(
    "tool_call",
    // Return type inferred from the pi.on("tool_call") overload
    // (ToolCallEventResult | undefined). No explicit annotation needed.
    async (event, ctx) => {
      // The deterministic ENGINE only adjudicates shell commands (only bash
      // carries a command to evaluate). But the deviation STATE still applies to
      // non-bash tools — otherwise a write/edit could mutate the workspace while
      // the session is HALTED or degraded, breaking the "HALTED is terminal"
      // invariant. So before the bash-only engine path:
      //   - HALTED  => block EVERY tool call (terminal until human ack).
      //   - armed + MUTATING non-bash (write/edit) => hold it. We can't grade a
      //     non-command tool yet (Phase 3 TODO: route these through the grader),
      //     so degraded mode holds them deterministically rather than waving
      //     them through ungated.
      // Trivial read-only non-bash tools pass through in any state.
      if (!isToolCallEventType("bash", event)) {
        const tn = toolNameOf(event);
        if (state.state === "HALTED") {
          const reason =
            "Session is HALTED on an inviolable constraint. All tool calls are " +
            "blocked until a human clears it (/guardrails-clear-halt).";
          await telemetry.logEvent("tool_call_blocked_non_bash", {
            toolName: tn,
            state: state.state,
            reason: "halted_blocks_all_tools",
          });
          ctx.ui.notify(`Guardrails blocked: ${reason}`, "error");
          return { block: true, reason };
        }
        if (state.state !== "COMPLIANT" && MUTATING_TOOLS.has(tn)) {
          const reason =
            `Degraded mode (state: ${state.state}): mutating tool "${tn}" is held ` +
            "until the session is provably back on track. Make clean, on-track " +
            "shell calls to recover.";
          await telemetry.logEvent("tool_call_blocked_non_bash", {
            toolName: tn,
            state: state.state,
            reason: "degraded_holds_mutating_non_bash",
          });
          ctx.ui.notify(`Guardrails blocked: ${reason}`, "error");
          return { block: true, reason };
        }
        await telemetry.logEvent("tool_call_passthrough", {
          toolName: tn,
          reason: "non_bash_tool_passthrough",
        });
        return;
      }

      const command = event.input.command;
      if (!deps) {
        // session_start runs before tool_call in practice, so this is an
        // initialization-order safety net, not a normal path. A GUARD must FAIL
        // CLOSED when it cannot make a safe decision (coderabbit): block the
        // command rather than waving it through ungoverned.
        await telemetry.logEvent("tool_call_no_config", {
          toolName: "bash",
          reason: "deps_unset_before_session_start_fail_closed",
        });
        const reason =
          "Guardrails not initialized yet (session_start has not run); the " +
          "command is blocked rather than run ungoverned. Retry once the session " +
          "is ready.";
        ctx.ui.notify(`Guardrails blocked: ${reason}`, "error");
        return { block: true, reason };
      }
      const guardDeps = deps;

      const meta = callMeta("bash");
      // First pass: NO grader. Deterministic deny/halt is enforced here as
      // before; a clean call in an ARMED state returns action "gate-required"
      // (guard.ts maps that to block:false in this pass). That is the Phase 3
      // hook — we must actually grade before letting a gated call run.
      let outcome = guardToolCall({ command, meta, state }, guardDeps);
      // True once we have actually run a grade for this call. A post-grade
      // outcome that is STILL "gate-required" means the gate was not cleared, so
      // the call must be BLOCKED (the gate is enforcing now, not advisory).
      let graded = false;

      // Phase 3 enforcement: an armed, clean call is "gate-required". RUN THE
      // GRADE and re-decide with the verdict so the machine ENFORCES the gate.
      if (outcome.action === "gate-required") {
        if (graderUnavailable || completer === undefined) {
          // FAIL CLOSED: grading is required but unavailable. Block the call
          // rather than waving a degraded session through ungraded.
          await telemetry.logEvent("tool_call_grader_unavailable", {
            toolName: "bash",
            command: previewCommand(command),
            state: state.state,
            stateEpoch: state.stateEpoch,
          });
          const reason =
            "degraded mode: grader unavailable; command held. " +
            "Configure the grader model/key or clear the guard state out-of-band.";
          ctx.ui.notify(`Guardrails blocked: ${reason}`, "error");
          return { block: true, reason };
        }

        const verdict = await runGrade(
          command,
          guardDeps,
          state,
          completer,
          // graderConfig is defined whenever completer is (both set in session_start).
          graderConfig ?? defaultGraderConfig(),
          gradeCache,
          telemetry,
        );
        graded = true;
        // Re-run the decision WITH the grader signal — this is the enforcing
        // pass: a non-compliant verdict re-arms / holds the gate; a clean one
        // advances recovery.
        outcome = guardToolCall(
          { command, meta, state, grader: verdict },
          guardDeps,
        );

        await telemetry.logEvent("tool_call_graded", {
          toolName: "bash",
          command: previewCommand(command),
          compliant: verdict.compliant,
          backOnTrack: verdict.backOnTrack,
          confidence: verdict.confidence,
          violatedConstraintId: verdict.violatedConstraintId,
          graderReason: verdict.reason,
          action: outcome.action,
          block: outcome.block,
          fromState: state.state,
          toState: outcome.nextState.state,
        });
      }

      const previousState = state.state;
      state = outcome.nextState;
      // Persist to a session entry (survives resume/fork via pi.appendEntry) only
      // on a MEANINGFUL transition (state/epoch/streak change), NOT on every call
      // — appending per-call would bloat the session file (the v0.1.7 write-only
      // events.jsonl problem). Rehydrate always takes the latest persisted state.
      if (outcome.transitioned) {
        persistState(pi, state);
      }

      await telemetry.logEvent("tool_call_decision", {
        toolName: "bash",
        command: previewCommand(command),
        action: outcome.action,
        block: outcome.block,
        reason: outcome.reason,
        ruleId: outcome.verdict.ruleId,
        severity: outcome.verdict.severity,
        inviolable: outcome.verdict.inviolable,
        fromState: previousState,
        toState: state.state,
        stateEpoch: state.stateEpoch,
        transitioned: outcome.transitioned,
      });

      if (state.state !== previousState) {
        setStatus(ctx, state);
      }

      // A post-grade outcome that is STILL "gate-required" means the grade did
      // NOT clear the gate (non-compliant / not-yet-recovered). Enforce it: the
      // call is held. This is the teeth Phase 2 lacked — without grading,
      // gate-required mapped to allow; after grading it blocks until recovered.
      const gateHeld = graded && outcome.action === "gate-required";

      if (outcome.block || gateHeld) {
        // The steer string is the model-facing reason (it explains what to do
        // instead); fall back to the raw reason. This is what reaches the model.
        const reason =
          outcome.steer ??
          outcome.reason ??
          (gateHeld
            ? "Held in degraded mode: the grade did not clear the gate."
            : "Blocked by model guardrails.");
        ctx.ui.notify(`Guardrails blocked: ${reason}`, "error");
        return { block: true, reason };
      }

      return;
    },
  );

  pi.on(
    "before_agent_start",
    // Return type inferred from the pi.on("before_agent_start") overload
    // (BeforeAgentStartEventResult | undefined). No explicit annotation needed.
    async (_event, _ctx) => {
      // When armed (any non-COMPLIANT state), inject a steering note into the
      // system prompt every turn so the model knows it is in degraded/halted
      // mode and what it must do to recover. COMPLIANT sessions inject nothing.
      if (state.state === "COMPLIANT") {
        return;
      }

      const note = steeringNote(state);
      await telemetry.logEvent("before_agent_start_steer", {
        state: state.state,
        stateEpoch: state.stateEpoch,
        armedReason: state.armedReason,
      });
      return { systemPrompt: note };
    },
  );

  // Human-ack recovery for a HALTED session. HALTED is terminal for the model:
  // no tool call — graded or not — can clear it (that is the whole point of an
  // inviolable-constraint halt). This slash command is the documented escape
  // hatch: a HUMAN types `/guardrails-clear-halt` in the TUI, is shown what was
  // violated, and must explicitly confirm. Defense in depth — the model cannot
  // emit a slash command (those originate in the human input editor, not the
  // tool-call stream), the confirm() requires a real interactive y/n, and
  // clearHalt's literal-`true` ack guard rejects any erased/forged token. If
  // there is no interactive UI (RPC/print mode), there is no safe human-ack
  // path, so we refuse rather than clear blind.
  if (typeof pi.registerCommand === "function") {
    pi.registerCommand("guardrails-clear-halt", {
      description:
        "Clear a HALTED guardrails state (human acknowledgement required)",
      handler: async (_args, ctx) => {
        if (state.state !== "HALTED") {
          ctx.ui.notify(
            `[model-guardrails] Not halted (state: ${state.state}); nothing to clear.`,
            "info",
          );
          return;
        }
        if (!ctx.hasUI) {
          ctx.ui.notify(
            "[model-guardrails] Cannot clear a halt without an interactive UI. " +
              "Run the TUI and re-issue /guardrails-clear-halt, or clear the " +
              "persisted guard state out-of-band.",
            "error",
          );
          return;
        }

        const reason = state.armedReason
          ? `\n\nViolated: ${state.armedReason}`
          : "";
        const confirmed = await ctx.ui.confirm(
          "Clear guardrails HALT?",
          "This session was HALTED on an inviolable constraint. Clearing it " +
            "lets the model act again. Only do this if you have reviewed what " +
            `happened and accept responsibility.${reason}`,
        );
        if (!confirmed) {
          ctx.ui.notify(
            "[model-guardrails] Halt kept. Session stays HALTED.",
            "info",
          );
          return;
        }

        const previousEpoch = state.stateEpoch;
        state = clearHalt(state, true);
        persistState(pi, state);
        setStatus(ctx, state);
        await telemetry.logEvent("halt_cleared", {
          via: "guardrails-clear-halt",
          fromEpoch: previousEpoch,
          toEpoch: state.stateEpoch,
        });
        ctx.ui.notify(
          "[model-guardrails] Halt cleared by human acknowledgement. " +
            "Session is COMPLIANT.",
          "info",
        );
      },
    });
  }
}

// ---------------------------------------------------------------------------
// Helpers.
// ---------------------------------------------------------------------------

/** Build the per-call metadata the deviation machine consumes. */
function callMeta(toolName: string): CallMeta {
  return {
    toolName,
    isMutating: MUTATING_TOOLS.has(toolName),
    isTrivial: TRIVIAL_TOOLS.has(toolName),
  };
}

/**
 * Build the production grader completer by adapting ctx.modelRegistry + the
 * pi-ai complete() function into makeCompleter()'s structural config. This is the
 * SAME mechanism src/llm.ts uses (findModel by id/provider-id, getApiKeyAndHeaders,
 * complete()) — the only verified way a Pi extension runs its own completion.
 *
 * Returns undefined when grading is disabled OR no completer can be built (no
 * model id / model not in registry). The caller treats undefined as
 * "grader unavailable" and fails closed for gated calls.
 */
function buildCompleter(
  ctx: ExtensionContext,
  cfg: GraderConfig,
): Completer | undefined {
  if (!cfg.enabled) return undefined;

  // Test seam: a unit test can inject a fake completer (no live LLM / registry).
  if (completerOverride !== undefined) return completerOverride;

  const registry = ctx.modelRegistry as
    | ExtensionContext["modelRegistry"]
    | undefined;
  // No model registry on this ctx (e.g. a minimal/test harness) => no completer.
  // The caller treats undefined as "grader unavailable" and fails closed.
  if (!registry || typeof registry.getAll !== "function") return undefined;

  const findModel = (id: string | undefined): GraderModel | undefined => {
    if (!id) return undefined;
    const all = registry.getAll();
    return all.find((m) => m.id === id || `${m.provider}/${m.id}` === id);
  };

  return makeCompleter({
    model: cfg.model,
    fallbackModel: cfg.fallbackModel,
    temperature: cfg.temperature,
    maxTokens: cfg.maxTokens,
    baseUrl: cfg.baseUrl,
    apiKey: cfg.apiKey,
    findModel,
    getAuth: async (model) => {
      // model came from registry.getAll(), so the cast is sound at runtime.
      const auth = await registry.getApiKeyAndHeaders(
        model as Parameters<typeof registry.getApiKeyAndHeaders>[0],
      );
      return auth.ok
        ? { ok: true, apiKey: auth.apiKey, headers: auth.headers }
        : { ok: false, error: auth.error };
    },
    complete: async (model, context, options) => {
      const result = await complete(
        model as Parameters<typeof complete>[0],
        context as Parameters<typeof complete>[1],
        options as Parameters<typeof complete>[2],
      );
      return {
        content: result.content as Array<{ type: string; text?: string }>,
      };
    },
  });
}

/**
 * Run ONE degraded-mode grade for a bash command. Pulls the active project
 * constraints from policy and recent actions from telemetry, then calls grade()
 * (which owns the timeout / retry / fail-toward-gate / cache logic). The returned
 * GraderSignal is fed back into guardToolCall to enforce the gate.
 */
async function runGrade(
  command: string,
  guardDeps: GuardDeps,
  state: PersistedState,
  completer: Completer,
  graderConfig: GraderConfig,
  cache: GradeCache | undefined,
  telemetry: GuardrailsTelemetry,
): Promise<GraderSignal> {
  const activeConstraints = relevantConstraints(guardDeps.policy.constraints);
  const recentActions = recentActionStrings(telemetry);

  return grade(
    {
      command,
      toolName: "bash",
      activeConstraints,
      violatedConstraintId: state.violatedConstraintId,
      recentActions,
      stateEpoch: state.stateEpoch,
    },
    {
      complete: completer,
      timeoutMs: graderConfig.timeoutMs,
      maxTokens: graderConfig.maxTokens,
      maxRetries: graderConfig.maxRetries,
      temperature: graderConfig.temperature,
      cache,
    },
  );
}

/**
 * Pick the constraints worth putting in the grade prompt: inviolable + high
 * first, then the rest. Keeps the prompt focused (and token-bounded) on the
 * obligations that actually matter in degraded mode.
 */
function relevantConstraints(constraints: Constraint[]): Constraint[] {
  if (constraints.length === 0) return [];
  const rank = (c: Constraint): number => {
    switch (c.severity) {
      case "inviolable":
        return 5;
      case "critical":
        return 4;
      case "high":
        return 3;
      case "medium":
        return 2;
      case "low":
        return 1;
      default:
        return 0;
    }
  };
  return [...constraints].sort((a, b) => rank(b) - rank(a)).slice(0, 12);
}

/** Compact recent telemetry events into short strings for grade context. */
function recentActionStrings(telemetry: GuardrailsTelemetry): string[] {
  const events = telemetry.recent(12);
  const out: string[] = [];
  for (const e of events) {
    if (e.name !== "tool_call_decision" && e.name !== "tool_call_graded") {
      continue;
    }
    const tags = e.tags ?? {};
    const cmd = typeof tags.command === "string" ? tags.command : "";
    const action = typeof tags.action === "string" ? tags.action : "";
    if (cmd) out.push(`${action || e.name}: ${cmd}`);
  }
  return out;
}

/** Persist the current deviation state to a session entry (survives resume/fork). */
function persistState(pi: ExtensionAPI, state: PersistedState): void {
  // pi.appendEntry writes a CustomEntry { type:"custom", customType, data }.
  // It is intentionally NOT sent to the LLM (it's pure extension state).
  pi.appendEntry<PersistedState>(GUARD_STATE_ENTRY_TYPE, state);
}

/**
 * Scan the session entries for the LATEST persisted guard state and return it.
 * Mirrors goal-integration.ts: filter CustomEntry by customType, take the last.
 * Returns undefined when there is no prior state (a fresh session).
 */
function rehydrateState(ctx: ExtensionContext): PersistedState | undefined {
  const entries = readEntries(ctx);
  let latest: PersistedState | undefined;
  for (const entry of entries) {
    const candidate = entry as {
      type?: string;
      customType?: string;
      data?: unknown;
    };
    if (
      candidate?.type === "custom" &&
      candidate?.customType === GUARD_STATE_ENTRY_TYPE &&
      isPersistedState(candidate.data)
    ) {
      latest = candidate.data;
    }
  }
  return latest;
}

function readEntries(ctx: ExtensionContext): unknown[] {
  const sm = ctx.sessionManager as {
    getEntries?: () => unknown[];
    getBranch?: () => unknown[];
  };
  return sm?.getEntries?.() ?? sm?.getBranch?.() ?? [];
}

const GUARD_STATES: ReadonlySet<GuardState> = new Set<GuardState>([
  "COMPLIANT",
  "WATCH",
  "GATED",
  "RECOVERING",
  "HALTED",
]);

function isPersistedState(value: unknown): value is PersistedState {
  if (!value || typeof value !== "object") return false;
  const v = value as Partial<PersistedState>;
  return (
    typeof v.state === "string" &&
    GUARD_STATES.has(v.state as GuardState) &&
    typeof v.cleanStreak === "number" &&
    typeof v.stateEpoch === "number" &&
    typeof v.cooldownRemaining === "number"
  );
}

/** The steering note injected each turn while armed. */
function steeringNote(state: PersistedState): string {
  const mode = state.state === "HALTED" ? "HALTED" : "degraded";
  const reason = state.armedReason ? ` Reason: ${state.armedReason}` : "";
  if (state.state === "HALTED") {
    return (
      `[model-guardrails] This session is HALTED on an inviolable constraint.${reason} ` +
      "Stop attempting destructive actions. The halt cannot be cleared by any " +
      "tool call — a human must acknowledge it out-of-band before work continues."
    );
  }
  return (
    `[model-guardrails] You are in ${mode} mode (state: ${state.state}).${reason} ` +
    "Every tool call is being scrutinized. Do exactly what corrects the specific " +
    "violation above and nothing risky; clean, on-track calls will return the " +
    "session to compliant."
  );
}

/** Reflect the current state into the footer status bar. */
function setStatus(ctx: ExtensionContext, state: PersistedState): void {
  ctx.ui.setStatus("guardrails", statusLabel(state));
}

function statusLabel(state: PersistedState): string {
  switch (state.state) {
    case "COMPLIANT":
      return "🔒 compliant";
    case "WATCH":
      return "👀 watch";
    case "GATED":
      return "⛔ gated";
    case "RECOVERING":
      return "♻️ recovering";
    case "HALTED":
      return "🛑 halted";
  }
}

function toolNameOf(event: ToolCallEvent): string {
  return event.toolName;
}

function previewCommand(command: string): string {
  return command.length > 240 ? `${command.slice(0, 240)}…` : command;
}
