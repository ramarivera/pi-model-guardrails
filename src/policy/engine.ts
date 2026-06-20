// Policy engine — resolves an EngineDecision + PolicyConfig into a PolicyVerdict.
//
// Ported from DCG `resolve_mode_at` + `apply_confidence_scoring`. The resolution
// order below is the design's "Policy engine" section, exactly:
//
//   1. Critical / inviolable severity  => DENY pre-emptively (HARD FLOOR; config
//      CANNOT downgrade this; confidence-immune).
//   2. explicit rule override          (policy.rules[ruleId])
//   3. allowlist                       (relaxes a NON-inviolable rule; INERT
//      against inviolable; a WILDCARD glob needs riskAcknowledged)
//   4. pack/global defaultMode         (gated by observeUntil => "log")
//   5. engine severity default         (the engine's own decision)
//
// One-way relaxation rule (design): a verdict may only RELAX a non-inviolable
// deny, never tighten it. Inviolable/Critical are confidence-immune — nothing in
// the table below can soften them.

import type {
  DecisionMode,
  EngineDecision,
  Severity,
} from "../engine/types.ts";
import type {
  AllowEntry,
  Constraint,
  ConstraintSeverity,
  PolicyConfig,
  PolicyVerdict,
} from "./types.ts";

/** Safe defaults: warn-by-default, no inviolables/rules/constraints/allowlist. */
export function defaultPolicyConfig(): PolicyConfig {
  return {
    defaultMode: "warn",
    inviolable: [],
    rules: {},
    constraints: [],
    allowlist: [],
  };
}

/**
 * Resolve the final policy verdict for a single command evaluation.
 *
 * `command` is the raw command string (used for constraint `detect.regex`).
 */
export function resolvePolicy(
  engineDecision: EngineDecision,
  command: string,
  policy: PolicyConfig,
): PolicyVerdict {
  const ruleId = engineDecision.ruleId;
  const engineSeverity = engineDecision.severity;

  // Detect a matching constraint (rule-id membership OR regex on the command).
  const constraint = detectConstraint(
    engineDecision,
    command,
    policy.constraints,
  );

  // Is this match inviolable? Two independent triggers (design):
  //   (a) the matched rule-id matches a policy.inviolable glob, OR
  //   (b) an inviolable-severity constraint is detected.
  const ruleIsInviolableGlob =
    ruleId !== undefined && matchesAnyGlob(ruleId, policy.inviolable);
  const constraintIsInviolable =
    constraint !== undefined && constraint.severity === "inviolable";
  const inviolable = ruleIsInviolableGlob || constraintIsInviolable;

  // Is a matching allowlist entry available (and would it be allowed to apply)?
  const allowEntry =
    ruleId !== undefined ? findApplicableAllowEntry(ruleId, policy) : undefined;
  // allowlistable: a constraint may forbid relaxation regardless of allowlist.
  // FAIL-CLOSED / opt-in: a constraint is relaxable ONLY when it explicitly sets
  // allowlistable === true. Omitted (undefined) or false both FORBID relaxation,
  // matching the documented contract ("if false/omitted, the allowlist can never
  // relax a match against this constraint").
  const constraintForbidsAllow =
    constraint !== undefined && constraint.allowlistable !== true;
  const allowlistable =
    !inviolable && !constraintForbidsAllow && allowEntry !== undefined;

  // Steering text + severity carried into the verdict (constraint wins for text).
  const reason = constraint?.statement ?? engineDecision.reason;
  const requiredBehavior = constraint?.requiredBehavior;
  const severity: ConstraintSeverity | Severity | undefined =
    constraint?.severity ?? engineSeverity;
  const constraintId = constraint?.id;

  // ---- 1. CRITICAL / INVIOLABLE HARD FLOOR (config cannot downgrade) ----
  // Pre-emptive DENY for inviolable matches and for critical engine severity.
  // This is the one-way floor: confidence-immune, allowlist-immune.
  if (inviolable || engineSeverity === "critical" || severity === "critical") {
    return {
      decision: "deny",
      blocked: true,
      inviolable,
      // critical (non-inviolable) is still not relaxable here — it's a floor.
      allowlistable: false,
      ruleId,
      constraintId,
      reason,
      requiredBehavior,
      severity,
    };
  }

  // ---- 2. EXPLICIT RULE OVERRIDE (highest non-floor authority) ----
  // policy.rules[ruleId] sets the mode directly. One-way relaxation still holds:
  // it MAY relax a non-inviolable deny or tighten an allow — explicit operator
  // intent is authoritative below the floor.
  if (ruleId !== undefined && policy.rules[ruleId] !== undefined) {
    const decision = policy.rules[ruleId];
    return {
      decision,
      blocked: decision === "deny",
      inviolable: false,
      allowlistable,
      ruleId,
      constraintId,
      reason,
      requiredBehavior,
      severity,
    };
  }

  // ---- 3. ALLOWLIST (relax a non-inviolable deny only) ----
  // The allowlist is INERT against inviolable (handled by the floor above) and a
  // wildcard glob needs riskAcknowledged (enforced in findApplicableAllowEntry).
  // It is also INERT when a detected constraint forbids relaxation
  // (allowlistable === false). One-way: it can only relax a deny, never tighten.
  if (
    allowlistable &&
    allowEntry !== undefined &&
    engineDecision.decision === "deny"
  ) {
    return {
      decision: "allow",
      blocked: false,
      inviolable: false,
      allowlistable: true,
      ruleId,
      constraintId,
      reason: allowEntry.reason,
      requiredBehavior,
      severity,
    };
  }

  // ---- 4. PACK / GLOBAL defaultMode (gated by observeUntil) ----
  // Only applies when the engine actually matched a rule (there is something to
  // decide on).
  //   - observeUntil active => an EXPLICIT observe-only rollout override that
  //     forces "log" (a deliberate downgrade, like an operator override).
  //   - otherwise => defaultMode acts as a pack FLOOR via strictest-wins with the
  //     engine's own decision, honoring one-way relaxation: defaultMode may only
  //     TIGHTEN (raise the floor), never silently downgrade a deny the engine made
  //     (relaxation is exclusively the rules/allowlist path above).
  if (ruleId !== undefined) {
    const observing =
      policy.observeUntil !== undefined && Date.now() < policy.observeUntil;
    const decision: DecisionMode = observing
      ? "log"
      : strictestMode(engineDecision.decision, policy.defaultMode);
    return {
      decision,
      blocked: decision === "deny",
      inviolable: false,
      allowlistable,
      ruleId,
      constraintId,
      reason,
      requiredBehavior,
      severity,
    };
  }

  // ---- 5. ENGINE SEVERITY DEFAULT (no rule matched: pass through) ----
  return {
    decision: engineDecision.decision,
    blocked: engineDecision.decision === "deny",
    inviolable: false,
    allowlistable: false,
    ruleId,
    constraintId,
    reason,
    requiredBehavior,
    severity,
  };
}

/** Find a constraint whose `detect` matches the engine decision or the command. */
function detectConstraint(
  engineDecision: EngineDecision,
  command: string,
  constraints: Constraint[],
): Constraint | undefined {
  const ruleId = engineDecision.ruleId;
  let weakest: Constraint | undefined;
  let strongest: Constraint | undefined;

  for (const c of constraints) {
    if (!c.detect) continue;
    const byRuleId =
      ruleId !== undefined && (c.detect.ruleIds?.includes(ruleId) ?? false);
    const byRegex =
      c.detect.regex !== undefined && safeRegexTest(c.detect.regex, command);
    if (!byRuleId && !byRegex) continue;

    // Strictest-wins (design): if multiple constraints detect, prefer the
    // strongest severity so the floor/arming reflects the worst case.
    if (
      strongest === undefined ||
      severityRank(c.severity) > severityRank(strongest.severity)
    ) {
      strongest = c;
    }
    weakest ??= c;
  }
  return strongest ?? weakest;
}

/**
 * Find an allowlist entry whose rule-glob matches `ruleId` and that is currently
 * active. A WILDCARD glob (contains "*") only counts when riskAcknowledged.
 * An expired ttl makes the entry INERT.
 */
function findApplicableAllowEntry(
  ruleId: string,
  policy: PolicyConfig,
): AllowEntry | undefined {
  const now = Date.now();
  for (const entry of policy.allowlist) {
    if (entry.ttl !== undefined && now >= entry.ttl) continue; // expired => inert
    if (!globMatches(entry.rule, ruleId)) continue;
    const isWildcard = entry.rule.includes("*");
    if (isWildcard && entry.riskAcknowledged !== true) continue; // wildcard needs ack
    return entry;
  }
  return undefined;
}

/** True if `value` matches ANY of the globs (used for policy.inviolable). */
function matchesAnyGlob(value: string, globs: string[]): boolean {
  for (const g of globs) {
    if (globMatches(g, value)) return true;
  }
  return false;
}

/**
 * Minimal glob matcher: "*" matches any run of chars (including ":"); everything
 * else is literal. Anchored full-string. "core.git:*" matches "core.git:push".
 */
function globMatches(glob: string, value: string): boolean {
  if (glob === value) return true;
  if (!glob.includes("*")) return false;
  const escaped = glob
    .split("*")
    .map((part) => part.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"))
    .join(".*");
  return new RegExp(`^${escaped}$`).test(value);
}

/** Rank a decision mode by strictness (higher = stricter). */
function modeRank(mode: DecisionMode): number {
  switch (mode) {
    case "deny":
      return 4;
    case "warn":
      return 3;
    case "log":
      return 2;
    case "allow":
      return 1;
  }
}

/** Return the stricter of two decision modes (never relaxes via the floor path). */
function strictestMode(a: DecisionMode, b: DecisionMode): DecisionMode {
  return modeRank(a) >= modeRank(b) ? a : b;
}

// Max command length fed to an author-supplied constraint regex. A longer
// command skips constraint detection rather than risk catastrophic backtracking
// on a pathological operator/pack-authored pattern against a crafted input.
// NOTE: this is a partial mitigation — it bounds the attacker-controlled input
// length but does not stop exponential backtracking on a short crafted input.
// Proper validate-at-load (reject nested unbounded quantifiers in constraint +
// external-pack patterns) is tracked for Phase 4 hardening.
const MAX_CONSTRAINT_INPUT = 4096;

function safeRegexTest(pattern: string, input: string): boolean {
  if (input.length > MAX_CONSTRAINT_INPUT) return false;
  try {
    return new RegExp(pattern).test(input);
  } catch {
    return false;
  }
}

/** Higher rank = stricter. Used for strictest-wins constraint selection. */
function severityRank(sev: ConstraintSeverity): number {
  switch (sev) {
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
  }
}
