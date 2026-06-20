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

import type {
  ExtensionAPI,
  ExtensionContext,
  ToolCallEvent,
} from "@earendil-works/pi-coding-agent";
import { isToolCallEventType } from "@earendil-works/pi-coding-agent";
import { loadGuardConfig } from "./config.ts";
import { type GuardDeps, guardToolCall } from "./guard.ts";
import {
  createNoopTelemetry,
  type GuardrailsTelemetry,
} from "./observability.ts";
import { initialState } from "./state/machine.ts";
import type { CallMeta, GuardState, PersistedState } from "./state/types.ts";

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
    });

    setStatus(ctx, state);
  });

  pi.on(
    "tool_call",
    // Return type inferred from the pi.on("tool_call") overload
    // (ToolCallEventResult | undefined). No explicit annotation needed.
    async (event, ctx) => {
      // The deterministic guard only adjudicates shell commands in Phase 2.
      // Non-bash tools pass through (allow). (The deviation machine still cares
      // about mutating/trivial classification, but only bash carries a command
      // string to evaluate.) TODO(Phase 3): route non-bash mutating tools
      // through the LLM grader once degraded-mode grading lands.
      if (!isToolCallEventType("bash", event)) {
        await telemetry.logEvent("tool_call_passthrough", {
          toolName: toolNameOf(event),
          reason: "non_bash_tool_phase2_passthrough",
        });
        return;
      }

      const command = event.input.command;
      if (!deps) {
        // session_start always runs first in practice; if not, fail OPEN (we
        // have no config to make a safe decision) but say so loudly.
        await telemetry.logEvent("tool_call_no_config", {
          toolName: "bash",
          reason: "deps_unset_before_session_start",
        });
        return;
      }

      const meta = callMeta("bash");
      // Phase 2: NO grader. guardToolCall is called WITHOUT one; the machine's
      // "gate-required" action maps to allow inside guard.ts so a degraded
      // session never wedges. TODO(Phase 3): pass `grader` here once the LLM
      // degraded-mode grader is wired in.
      const outcome = guardToolCall({ command, meta, state }, deps);

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

      if (outcome.block) {
        // The steer string is the model-facing reason (it explains what to do
        // instead); fall back to the raw reason. This is what reaches the model.
        const reason =
          outcome.steer ?? outcome.reason ?? "Blocked by model guardrails.";
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
