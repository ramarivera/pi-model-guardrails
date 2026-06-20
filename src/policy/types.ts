// Inviolable-constraint policy engine — public type contract (Phase 2, deterministic).
//
// The policy engine sits BETWEEN the deterministic command-guard engine
// (src/engine/*) and the deviation state machine (src/state/*). It takes a raw
// `EngineDecision` and a `PolicyConfig` and resolves the FINAL `DecisionMode`
// plus the inviolable/allowlistable flags the state machine needs to arm.
//
// Ported from DCG's `resolve_mode_at` + `apply_confidence_scoring`
// (Dicklesworthstone/destructive_command_guard), with two HARD FLOORS that the
// design ("Policy engine" / "Critical hard-floor that config physically cannot
// downgrade") requires and that config CANNOT relax:
//   - criticalFloor:  Critical/inviolable severity => DENY pre-emptively.
//   - failClosedWhenArmed: handled by the state machine (degraded mode), not here.
//
// These two floors are deliberately NOT fields on PolicyConfig: they are not
// config-downgradable. See `resolvePolicy` for where they are enforced.

import type { DecisionMode, Severity } from "../engine/types.ts";

/**
 * Severity of an inviolable-style project constraint. `"inviolable"` is the
 * strongest: detecting one pre-emptively DENIES and arms the machine straight
 * to HALTED (grade-immune). The rest mirror engine severities for floor logic.
 */
export type ConstraintSeverity =
  | "inviolable"
  | "critical"
  | "high"
  | "medium"
  | "low";

/**
 * A project-declared constraint ("never force-push to main", "never delete the
 * prod DB"). Distinct from a DestructiveRule: constraints are policy-level and
 * can be tied to engine rule-ids OR an independent regex via `detect`.
 */
export interface Constraint {
  id: string;
  title: string;
  statement: string;
  severity: ConstraintSeverity;
  /** If false/omitted, the allowlist can never relax a match against this constraint. */
  allowlistable?: boolean;
  /** Human-readable scoping note (advisory; not evaluated by the deterministic engine). */
  appliesWhen?: string;
  /** What the model MUST do instead (steering channel). */
  requiredBehavior?: string;
  /** How to detect a violation deterministically: by engine rule-id and/or a regex on the command. */
  detect?: { ruleIds?: string[]; regex?: string };
}

/** A user-approved exception ("yes, `git push --force` to this one path is fine"). */
export interface AllowEntry {
  /** Rule-id glob this entry exempts (e.g. "core.git:push-force", "core.filesystem:*"). */
  rule: string;
  reason: string;
  /** Optional epoch-ms expiry; an expired entry is INERT. */
  ttl?: number;
  /** Optional path scoping (advisory in Phase 2; recorded for Phase 3+ enforcement). */
  paths?: string[];
  /** Required for a WILDCARD rule glob to take effect (blast-radius guard). */
  riskAcknowledged?: boolean;
}

/**
 * The resolved policy config. `criticalFloor` + `failClosedWhenArmed` are
 * deliberately absent: they are HARD FLOORS, not config-downgradable.
 */
export interface PolicyConfig {
  /** Pack/global default applied when no rule/allowlist/constraint decides. */
  defaultMode: DecisionMode;
  /** Epoch-ms; while `now < observeUntil` the defaultMode is forced to "log" (observe-only rollout). */
  observeUntil?: number;
  /** Rule-id globs that are inviolable: a match here can never be relaxed. */
  inviolable: string[];
  /** Explicit per-rule-id overrides (the highest non-floor authority). */
  rules: Record<string, DecisionMode>;
  /** Project-declared constraints, detected by rule-id or regex. */
  constraints: Constraint[];
  /** User-approved exceptions that can RELAX a non-inviolable deny. */
  allowlist: AllowEntry[];
}

/** The policy engine's verdict; the caller builds a DeterministicSignal from this. */
export interface PolicyVerdict {
  decision: DecisionMode;
  /** convenience: decision === "deny". */
  blocked: boolean;
  /** true when an inviolable rule-glob or inviolable constraint matched (HALT-arming, grade-immune). */
  inviolable: boolean;
  /** true when a matching allowlist entry COULD relax this (already applied if so). */
  allowlistable: boolean;
  ruleId?: string;
  constraintId?: string;
  /** steering reason (reaches the model on block). */
  reason?: string;
  /** what the model must do instead, when a constraint with requiredBehavior matched. */
  requiredBehavior?: string;
  severity?: ConstraintSeverity | Severity;
}
