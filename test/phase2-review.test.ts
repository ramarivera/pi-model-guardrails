// Regression tests for the Phase 2 adversarial-review fixes (state machine +
// policy engine). Each pins a previously-broken-or-vacuous invariant.

import assert from "node:assert/strict";
import test from "node:test";
import { resolvePolicy } from "../src/policy/engine.ts";
import type { Constraint, PolicyConfig } from "../src/policy/types.ts";
import {
  defaultMachineConfig,
  initialState,
  transition,
} from "../src/state/machine.ts";
import type {
  CallMeta,
  DeterministicSignal,
  GuardState,
  PersistedState,
} from "../src/state/types.ts";

const meta: CallMeta = { toolName: "bash", isMutating: true, isTrivial: false };
const cfg = defaultMachineConfig();
const clean: DeterministicSignal = {
  blocked: false,
  inviolable: false,
  allowlistable: false,
  warn: false,
};
const warn: DeterministicSignal = {
  blocked: false,
  severity: "medium",
  inviolable: false,
  allowlistable: false,
  warn: true,
};

// FIX: cooldown was decorative. A soft relapse within the post-recovery cooldown
// window must re-arm GATED, not take the gentle COMPLIANT->WATCH path.
test("a warn during post-recovery cooldown re-arms GATED (not WATCH)", () => {
  const inCooldown: PersistedState = {
    state: "COMPLIANT",
    cleanStreak: 0,
    stateEpoch: 3,
    cooldownRemaining: 2,
  };
  const r = transition({ current: inCooldown, deterministic: warn, meta, config: cfg });
  assert.equal(r.next.state, "GATED");
  // and outside cooldown the same warn takes the gentle WATCH path
  const fresh = transition({ current: initialState(), deterministic: warn, meta, config: cfg });
  assert.equal(fresh.next.state, "WATCH");
});

// FIX: no default branch -> undefined -> guard crash -> fail-open. An unknown /
// forward-version persisted state must fail CLOSED (HALTED).
test("an unrecognized persisted state fails closed (HALTED)", () => {
  const corrupt: PersistedState = {
    state: "FROZEN" as GuardState,
    cleanStreak: 0,
    stateEpoch: 0,
    cooldownRemaining: 0,
  };
  const r = transition({ current: corrupt, deterministic: clean, meta, config: cfg });
  assert.equal(r.action, "halt");
  assert.equal(r.next.state, "HALTED");
});

// FIX: WATCH->COMPLIANT recovery returned a contradictory gate-required action.
test("the WATCH->COMPLIANT recovery call returns action 'allow'", () => {
  let s = transition({ current: initialState(), deterministic: warn, meta, config: cfg }).next;
  assert.equal(s.state, "WATCH");
  s = transition({ current: s, deterministic: clean, meta, config: cfg }).next; // streak 1
  const last = transition({ current: s, deterministic: clean, meta, config: cfg });
  assert.equal(last.next.state, "COMPLIANT");
  assert.equal(last.action, "allow");
});

// FIX: Constraint.allowlistable omitted was treated as relaxable (fail-open). An
// omitted/false flag must FORBID allowlist relaxation (opt-in).
test("a constraint with omitted allowlistable forbids allowlist relaxation", () => {
  const constraint: Constraint = {
    id: "no-force-push",
    title: "No force push",
    statement: "force push rewrites shared history",
    severity: "high",
    detect: { ruleIds: ["core.git:push-force"] },
    // allowlistable OMITTED
  };
  const policy: PolicyConfig = {
    defaultMode: "deny",
    inviolable: [],
    rules: {},
    constraints: [constraint],
    allowlist: [{ rule: "core.git:push-force", reason: "exception" }],
  };
  const verdict = resolvePolicy(
    { decision: "deny", blocked: true, ruleId: "core.git:push-force", severity: "high" },
    "git push --force",
    policy,
  );
  assert.equal(verdict.decision, "deny");
  assert.equal(verdict.blocked, true);
});

// FIX: constraint detect.regex had no input bound. An oversized command skips
// constraint detection rather than risking a hang.
test("constraint regex detection is skipped on oversized input", () => {
  const constraint: Constraint = {
    id: "huge",
    title: "x",
    statement: "x",
    severity: "high",
    detect: { regex: "danger" },
  };
  const policy: PolicyConfig = {
    defaultMode: "warn",
    inviolable: [],
    rules: {},
    constraints: [constraint],
    allowlist: [],
  };
  const huge = `danger ${"a".repeat(10000)}`;
  const verdict = resolvePolicy(
    { decision: "allow", blocked: false },
    huge,
    policy,
  );
  // oversized => constraint not detected => no constraint id attached
  assert.equal(verdict.constraintId, undefined);
});
