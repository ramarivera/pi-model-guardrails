// guard.ts — the per-tool-call decision core.
//
// Composes the three layers into ONE pure decision:
//   command -> [engine] EngineDecision -> [policy] PolicyVerdict
//           -> DeterministicSignal -> [state machine] TransitionResult -> outcome
//
// Pure: no Pi, no LLM, no IO. The extension is thin glue around guardToolCall();
// keeping the composition here makes the whole Layer-1+2 decision unit-testable.
//
// Phase 2 (deterministic): no grader is supplied. The state machine's
// "gate-required" action (armed but clean) maps to ALLOW here — we do NOT
// hard-block every call once armed, because without a grader there'd be no
// recovery path and the session would wedge. Dangerous commands are still
// blocked (deterministic deny => "block"/"halt"), and the armed state is
// carried forward so Phase 3 can enforce the gate once a grader is plugged in.

import { evaluateCommand } from "./engine/evaluate.ts";
import type { Registry } from "./engine/registry.ts";
import type { EvaluateOptions, Severity } from "./engine/types.ts";
import { resolvePolicy } from "./policy/engine.ts";
import type { PolicyConfig, PolicyVerdict } from "./policy/types.ts";
import { transition } from "./state/machine.ts";
import type {
  CallMeta,
  DeterministicSignal,
  GraderSignal,
  MachineConfig,
  PersistedState,
  TransitionResult,
} from "./state/types.ts";

export interface GuardDeps {
  registry: Registry;
  policy: PolicyConfig;
  machineConfig: MachineConfig;
  evaluateOptions?: EvaluateOptions;
}

export interface GuardInput {
  command: string;
  meta: CallMeta;
  state: PersistedState;
  /** Phase 3: the grader verdict for this call, when degraded-mode grading ran. */
  grader?: GraderSignal;
}

export interface GuardOutcome {
  /** true => the caller must NOT run the tool call (block or halt). */
  block: boolean;
  /** the raw machine action, for callers that distinguish gate-required (Phase 3). */
  action: TransitionResult["action"];
  reason?: string;
  /** steering text for the model (the block reason that reaches it / the nudge). */
  steer?: string;
  verdict: PolicyVerdict;
  /** the state to persist for the next call. */
  nextState: PersistedState;
  transitioned: boolean;
}

/** Map a PolicyVerdict severity (which may be "inviolable") to an engine Severity. */
function toEngineSeverity(
  sev: PolicyVerdict["severity"],
): Severity | undefined {
  switch (sev) {
    case "critical":
    case "high":
    case "medium":
    case "low":
      return sev;
    default:
      // "inviolable" (or undefined) — the inviolable flag carries the HALT signal.
      return undefined;
  }
}

function verdictToSignal(v: PolicyVerdict): DeterministicSignal {
  return {
    blocked: v.blocked,
    severity: toEngineSeverity(v.severity),
    ruleId: v.ruleId,
    reason: v.reason,
    inviolable: v.inviolable,
    allowlistable: v.allowlistable,
    warn: v.decision === "warn",
  };
}

/**
 * Evaluate one tool call through engine -> policy -> state machine.
 * `grader` is omitted in Phase 2; supply it in Phase 3 to enforce degraded mode.
 */
export function guardToolCall(
  input: GuardInput,
  deps: GuardDeps,
): GuardOutcome {
  // When armed (any non-COMPLIANT state), the engine fails CLOSED on a guard
  // error (oversized input / match budget) — a degraded session refuses
  // ambiguous input rather than waving it through.
  const armed = input.state.state !== "COMPLIANT";

  const engineDecision = evaluateCommand(input.command, deps.registry, {
    ...deps.evaluateOptions,
    failClosed: armed,
  });

  const verdict = resolvePolicy(engineDecision, input.command, deps.policy);
  const signal = verdictToSignal(verdict);

  const t = transition({
    current: input.state,
    deterministic: signal,
    grader: input.grader,
    meta: input.meta,
    config: deps.machineConfig,
  });

  // halt + block => stop the call. gate-required/allow => let it run (Phase 2).
  const block = t.action === "halt" || t.action === "block";

  return {
    block,
    action: t.action,
    reason: t.reason,
    steer: t.steer,
    verdict,
    nextState: t.next,
    transitioned: t.transitioned,
  };
}
