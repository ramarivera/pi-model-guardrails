// Deviation state machine — public type contract (Phase 2, deterministic-only).
//
// The 5-state machine `COMPLIANT → WATCH → GATED → RECOVERING → HALTED` is the
// centerpiece of Layer 2 (design "Deviation state machine"). It NEVER calls an
// LLM. For armed states (GATED/RECOVERING) it only EXPOSES a "gate-required"
// action; the caller (Phase 3) is responsible for actually running the grade and
// feeding back a `GraderSignal` on the next transition. The machine itself is
// pure: (current state, signals, meta, config) -> (next state, action).

import type { Severity } from "../engine/types.ts";

/** The five guard states. */
export type GuardState =
  | "COMPLIANT"
  | "WATCH"
  | "GATED"
  | "RECOVERING"
  | "HALTED";

/**
 * Deterministic side of a tool call, built by the caller from a PolicyVerdict.
 *  - blocked:        verdict.decision === "deny"
 *  - inviolable:     verdict.inviolable (HALT-arming, grade-immune)
 *  - allowlistable:  verdict.allowlistable
 *  - warn:           a soft signal (medium warn / detect-regex / suspicion) that
 *                    did NOT hard-block. One soft signal arms COMPLIANT->WATCH.
 */
export interface DeterministicSignal {
  blocked: boolean;
  severity?: Severity;
  ruleId?: string;
  constraintId?: string;
  reason?: string;
  requiredBehavior?: string;
  inviolable: boolean;
  allowlistable: boolean;
  warn: boolean;
}

/**
 * Grader side (Phase 3; may be absent in Phase 2 — the machine works without it).
 *  - compliant:    the call is aligned with the project's constraints.
 *  - backOnTrack:  the grader confirms the specific violation was remediated.
 *  - confidence:   0..1; advisory (the deterministic floor never reads it).
 *  - inviolable:   grader believes an inviolable was breached (still cannot HALT
 *                  on its own — only deterministic inviolable HALTs; a grader
 *                  inviolable is treated as a non-compliant dirty grade).
 */
export interface GraderSignal {
  compliant: boolean;
  backOnTrack: boolean;
  confidence: number;
  violatedConstraintId?: string;
  inviolable: boolean;
  reason?: string;
}

/** Per-call metadata used to decide whether a call advances the recovery streak. */
export interface CallMeta {
  toolName: string;
  /** mutating tools (writes/exec) gate in WATCH; read-only ones don't. */
  isMutating: boolean;
  /** trivial/read-only calls don't advance the recovery streak when nonTrivialOnly. */
  isTrivial: boolean;
}

/** Tunables for the machine (all defaulted by defaultMachineConfig). */
export interface MachineConfig {
  /** clean non-trivial calls needed to exit WATCH -> COMPLIANT. */
  watchCleanStreak: number;
  /** clean non-trivial grades needed to fully recover RECOVERING -> COMPLIANT. */
  gatedCleanStreak: number;
  /** clean gated grades needed to promote GATED -> RECOVERING. */
  recoveringWatermark: number;
  /** turns the gate stays hot after recovery (cooldown re-arms on immediate relapse). */
  cooldownTurns: number;
  /** in WATCH, only gate mutating tools (latency bound). */
  gateOnlyMutatingInWatch: boolean;
  /** trivial/read-only calls don't advance the recovery streak. */
  nonTrivialOnly: boolean;
  /** HALTED can only be cleared by explicit human ack (never auto/grader). */
  haltRequiresHumanAck: boolean;
}

/** Persisted machine state (via pi.appendEntry; rehydrated on session_start). */
export interface PersistedState {
  state: GuardState;
  /** consecutive (NOT cumulative) clean non-trivial calls toward recovery. */
  cleanStreak: number;
  /** the specific constraint that armed the machine (steering focus). */
  violatedConstraintId?: string;
  /** human-readable arming reason (steering channel). */
  armedReason?: string;
  /** bumped on every arming/recovery transition (resume/fork can't reset a degraded session). */
  stateEpoch: number;
  /** turns of cooldown left after recovery; immediate relapse re-arms to GATED. */
  cooldownRemaining: number;
}

/** Inputs to a single transition. */
export interface TransitionInput {
  current: PersistedState;
  /** deterministic verdict signal; absent only if the engine wasn't consulted. */
  deterministic?: DeterministicSignal;
  /** grader signal; absent in Phase 2 / for non-gated states. */
  grader?: GraderSignal;
  meta: CallMeta;
  config: MachineConfig;
}

/**
 * The transition result.
 *  - action "allow":         let the call run (fail-open in COMPLIANT/WATCH-readonly).
 *  - action "block":         deterministic hard block (engine deny, no relax).
 *  - action "gate-required": armed degraded mode — caller MUST grade before running.
 *  - action "halt":          inviolable/Critical breach; hard stop, human-ack only.
 */
export interface TransitionResult {
  next: PersistedState;
  action: "allow" | "block" | "gate-required" | "halt";
  reason?: string;
  /** steering text for the model (what it must do to get back on track). */
  steer?: string;
  /** true if state/epoch/streak changed in a meaningful way. */
  transitioned: boolean;
}
