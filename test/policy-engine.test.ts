// Tests for the Phase 2 policy engine (resolvePolicy / defaultPolicyConfig).
//
// Covers the design's "Policy engine" resolution order and HARD FLOORS:
//  - Critical/inviolable PRE-EMPTIVE deny cannot be downgraded by
//    defaultMode / rules / allowlist.
//  - explicit rule override works for a non-critical rule.
//  - allowlist relaxes a non-inviolable deny but is INERT against an inviolable.
//  - wildcard allowlist requires riskAcknowledged.
//  - observeUntil gates defaultMode.
//  - constraint detection via detect.ruleIds and detect.regex marks inviolable.
//  - one-way relaxation: a verdict may relax a non-inviolable deny, never tighten;
//    inviolable/critical are immune (adversarial un-block test).

import assert from "node:assert/strict";
import test from "node:test";
import type { EngineDecision } from "../src/engine/types.ts";
import { defaultPolicyConfig, resolvePolicy } from "../src/policy/engine.ts";
import type { Constraint, PolicyConfig } from "../src/policy/types.ts";

// --- fixtures ---------------------------------------------------------------

/** A high-severity engine DENY for core.git:push-force on `git push --force`. */
function pushForceDeny(): EngineDecision {
  return {
    decision: "deny",
    blocked: true,
    ruleId: "core.git:push-force",
    packId: "core.git",
    ruleName: "push-force",
    severity: "high",
    reason: "force push can overwrite remote history",
  };
}

/** A critical engine DENY (e.g. core.filesystem:rm-rf-root on `rm -rf /`). */
function rmRootDeny(): EngineDecision {
  return {
    decision: "deny",
    blocked: true,
    ruleId: "core.filesystem:rm-rf-root",
    packId: "core.filesystem",
    ruleName: "rm-rf-root",
    severity: "critical",
    reason: "recursive force delete of root filesystem",
  };
}

/** A medium engine WARN for a soft rule. */
function softWarn(): EngineDecision {
  return {
    decision: "warn",
    blocked: false,
    ruleId: "core.git:reset-soft",
    packId: "core.git",
    ruleName: "reset-soft",
    severity: "medium",
    reason: "reset may discard staged work",
  };
}

/** A clean allow (no rule matched). */
function noMatchAllow(): EngineDecision {
  return { decision: "allow", blocked: false, allowReason: "no_match" };
}

function basePolicy(over: Partial<PolicyConfig> = {}): PolicyConfig {
  return { ...defaultPolicyConfig(), ...over };
}

// --- defaults ---------------------------------------------------------------

test("defaultPolicyConfig: warn default, empty inviolable/rules/constraints/allowlist", () => {
  const p = defaultPolicyConfig();
  assert.equal(p.defaultMode, "warn");
  assert.deepEqual(p.inviolable, []);
  assert.deepEqual(p.rules, {});
  assert.deepEqual(p.constraints, []);
  assert.deepEqual(p.allowlist, []);
  assert.equal(p.observeUntil, undefined);
});

// --- HARD FLOOR: critical -----------------------------------------------------

test("critical severity => pre-emptive DENY, inviolable false, not allowlistable", () => {
  const v = resolvePolicy(rmRootDeny(), "rm -rf /", basePolicy());
  assert.equal(v.decision, "deny");
  assert.equal(v.blocked, true);
  assert.equal(v.inviolable, false);
  assert.equal(v.allowlistable, false);
  assert.equal(v.severity, "critical");
});

test("critical floor cannot be downgraded by defaultMode=allow", () => {
  const v = resolvePolicy(
    rmRootDeny(),
    "rm -rf /",
    basePolicy({ defaultMode: "allow" }),
  );
  assert.equal(v.decision, "deny");
  assert.equal(v.blocked, true);
});

test("critical floor cannot be downgraded by an explicit rule override", () => {
  const v = resolvePolicy(
    rmRootDeny(),
    "rm -rf /",
    basePolicy({ rules: { "core.filesystem:rm-rf-root": "allow" } }),
  );
  assert.equal(v.decision, "deny");
  assert.equal(v.blocked, true);
});

test("critical floor cannot be downgraded by an exact-match allowlist entry", () => {
  const v = resolvePolicy(
    rmRootDeny(),
    "rm -rf /",
    basePolicy({
      allowlist: [
        { rule: "core.filesystem:rm-rf-root", reason: "trust me bro" },
      ],
    }),
  );
  assert.equal(v.decision, "deny");
  assert.equal(v.blocked, true);
});

// --- HARD FLOOR: inviolable ---------------------------------------------------

test("inviolable rule-glob => DENY, inviolable true, allowlistable false", () => {
  const v = resolvePolicy(
    pushForceDeny(),
    "git push --force",
    basePolicy({ inviolable: ["core.git:*"] }),
  );
  assert.equal(v.decision, "deny");
  assert.equal(v.inviolable, true);
  assert.equal(v.allowlistable, false);
  assert.equal(v.ruleId, "core.git:push-force");
});

test("ADVERSARIAL: an allowlist entry CANNOT un-block an inviolable rule", () => {
  const v = resolvePolicy(
    pushForceDeny(),
    "git push --force",
    basePolicy({
      inviolable: ["core.git:push-force"],
      allowlist: [
        {
          rule: "core.git:push-force",
          reason: "I really want this",
          riskAcknowledged: true,
        },
        { rule: "*", reason: "blanket", riskAcknowledged: true },
      ],
    }),
  );
  assert.equal(v.decision, "deny");
  assert.equal(v.blocked, true);
  assert.equal(v.inviolable, true);
  assert.equal(v.allowlistable, false);
});

test("ADVERSARIAL: an explicit rule override CANNOT un-block an inviolable rule", () => {
  const v = resolvePolicy(
    pushForceDeny(),
    "git push --force",
    basePolicy({
      inviolable: ["core.git:push-force"],
      rules: { "core.git:push-force": "allow" },
    }),
  );
  assert.equal(v.decision, "deny");
  assert.equal(v.inviolable, true);
});

// --- explicit rule override (non-critical) -----------------------------------

test("explicit rule override relaxes a non-critical deny (high) to warn", () => {
  const v = resolvePolicy(
    pushForceDeny(),
    "git push --force",
    basePolicy({ rules: { "core.git:push-force": "warn" } }),
  );
  assert.equal(v.decision, "warn");
  assert.equal(v.blocked, false);
  assert.equal(v.inviolable, false);
});

test("explicit rule override can tighten a warn to deny (operator intent is authoritative below the floor)", () => {
  const v = resolvePolicy(
    softWarn(),
    "git reset --soft HEAD~1",
    basePolicy({ rules: { "core.git:reset-soft": "deny" } }),
  );
  assert.equal(v.decision, "deny");
  assert.equal(v.blocked, true);
});

// --- allowlist ---------------------------------------------------------------

test("allowlist relaxes a non-inviolable (high) deny to allow", () => {
  const v = resolvePolicy(
    pushForceDeny(),
    "git push --force",
    basePolicy({
      allowlist: [
        { rule: "core.git:push-force", reason: "rebased feature branch" },
      ],
    }),
  );
  assert.equal(v.decision, "allow");
  assert.equal(v.blocked, false);
  assert.equal(v.allowlistable, true);
  assert.equal(v.inviolable, false);
  assert.equal(v.reason, "rebased feature branch");
});

test("allowlist does NOT tighten: a warn stays warn (one-way relaxation)", () => {
  // The allowlist only fires for a deny; against a warn it leaves the decision.
  const v = resolvePolicy(
    softWarn(),
    "git reset --soft HEAD~1",
    basePolicy({
      defaultMode: "warn",
      allowlist: [{ rule: "core.git:reset-soft", reason: "fine here" }],
    }),
  );
  // defaultMode warn applies (not a deny to relax) => stays warn, not allow.
  assert.notEqual(v.decision, "deny");
  assert.equal(v.blocked, false);
});

test("wildcard allowlist is INERT without riskAcknowledged", () => {
  const v = resolvePolicy(
    pushForceDeny(),
    "git push --force",
    basePolicy({ allowlist: [{ rule: "*", reason: "blanket, no ack" }] }),
  );
  // Wildcard ignored => falls through to defaultMode (warn) for the matched rule.
  assert.notEqual(v.decision, "allow");
});

test("wildcard allowlist relaxes a non-inviolable deny WITH riskAcknowledged", () => {
  const v = resolvePolicy(
    pushForceDeny(),
    "git push --force",
    basePolicy({
      allowlist: [{ rule: "*", reason: "blanket", riskAcknowledged: true }],
    }),
  );
  assert.equal(v.decision, "allow");
  assert.equal(v.allowlistable, true);
});

test("rule-glob allowlist (core.git:*) relaxes a matching non-inviolable deny with ack", () => {
  const v = resolvePolicy(
    pushForceDeny(),
    "git push --force",
    basePolicy({
      allowlist: [
        {
          rule: "core.git:*",
          reason: "git is fine in this repo",
          riskAcknowledged: true,
        },
      ],
    }),
  );
  assert.equal(v.decision, "allow");
});

test("expired allowlist (ttl in the past) is INERT", () => {
  const v = resolvePolicy(
    pushForceDeny(),
    "git push --force",
    basePolicy({
      allowlist: [
        {
          rule: "core.git:push-force",
          reason: "expired",
          ttl: Date.now() - 1000,
        },
      ],
    }),
  );
  assert.notEqual(v.decision, "allow");
});

test("live allowlist (ttl in the future) relaxes the deny", () => {
  const v = resolvePolicy(
    pushForceDeny(),
    "git push --force",
    basePolicy({
      allowlist: [
        {
          rule: "core.git:push-force",
          reason: "temp",
          ttl: Date.now() + 60_000,
        },
      ],
    }),
  );
  assert.equal(v.decision, "allow");
});

// --- defaultMode / observeUntil ----------------------------------------------

test("defaultMode applies to a matched rule when no override/allowlist decides", () => {
  const v = resolvePolicy(
    pushForceDeny(),
    "git push --force",
    basePolicy({ defaultMode: "deny" }),
  );
  assert.equal(v.decision, "deny");
  assert.equal(v.blocked, true);
});

test("observeUntil in the future suppresses defaultMode (forced to log)", () => {
  const v = resolvePolicy(
    pushForceDeny(),
    "git push --force",
    basePolicy({ defaultMode: "deny", observeUntil: Date.now() + 60_000 }),
  );
  assert.equal(v.decision, "log");
  assert.equal(v.blocked, false);
});

test("observeUntil in the past no longer suppresses defaultMode", () => {
  const v = resolvePolicy(
    pushForceDeny(),
    "git push --force",
    basePolicy({ defaultMode: "deny", observeUntil: Date.now() - 1000 }),
  );
  assert.equal(v.decision, "deny");
});

test("no rule matched => pass through the engine allow (no defaultMode synthesis)", () => {
  const v = resolvePolicy(
    noMatchAllow(),
    "ls -la",
    basePolicy({ defaultMode: "deny" }),
  );
  assert.equal(v.decision, "allow");
  assert.equal(v.blocked, false);
  assert.equal(v.inviolable, false);
});

// --- constraint detection ----------------------------------------------------

function inviolableByRuleId(): Constraint {
  return {
    id: "no-force-push-main",
    title: "No force-push to main",
    statement: "Never force-push to the main branch.",
    severity: "inviolable",
    requiredBehavior: "Open a PR instead of rewriting shared history.",
    detect: { ruleIds: ["core.git:push-force"] },
  };
}

function inviolableByRegex(): Constraint {
  return {
    id: "no-prod-db-drop",
    title: "No prod DB drop",
    statement: "Never drop the production database.",
    severity: "inviolable",
    detect: { regex: "drop\\s+database\\s+prod" },
  };
}

test("constraint detect.ruleIds marks the verdict inviolable and uses its statement", () => {
  const v = resolvePolicy(
    pushForceDeny(),
    "git push --force origin main",
    basePolicy({ constraints: [inviolableByRuleId()] }),
  );
  assert.equal(v.decision, "deny");
  assert.equal(v.inviolable, true);
  assert.equal(v.constraintId, "no-force-push-main");
  assert.equal(v.reason, "Never force-push to the main branch.");
  assert.equal(
    v.requiredBehavior,
    "Open a PR instead of rewriting shared history.",
  );
  assert.equal(v.severity, "inviolable");
});

test("constraint detect.regex marks inviolable EVEN when the engine allowed", () => {
  // Engine never matched (allow), but the inviolable constraint regex hits the
  // command => pre-emptive DENY (constraint detection is independent of engine).
  const v = resolvePolicy(
    noMatchAllow(),
    "psql -c 'drop database prod'",
    basePolicy({ constraints: [inviolableByRegex()] }),
  );
  assert.equal(v.decision, "deny");
  assert.equal(v.blocked, true);
  assert.equal(v.inviolable, true);
  assert.equal(v.constraintId, "no-prod-db-drop");
});

test("non-inviolable constraint with allowlistable:false forbids allowlist relaxation", () => {
  const constraint: Constraint = {
    id: "high-risk-git",
    title: "Risky git",
    statement: "Force push is discouraged here.",
    severity: "high",
    allowlistable: false,
    detect: { ruleIds: ["core.git:push-force"] },
  };
  const v = resolvePolicy(
    pushForceDeny(),
    "git push --force",
    basePolicy({
      constraints: [constraint],
      allowlist: [{ rule: "core.git:push-force", reason: "nope" }],
    }),
  );
  // Constraint forbids allowlisting => allowlistable false, deny still relaxes?
  // It is non-critical/non-inviolable, so it falls to defaultMode (warn), not allow.
  assert.notEqual(v.decision, "allow");
  assert.equal(v.allowlistable, false);
  assert.equal(v.inviolable, false);
});

test("strictest-wins: the strongest detected constraint severity drives the verdict", () => {
  const weak: Constraint = {
    id: "weak",
    title: "weak",
    statement: "weak",
    severity: "low",
    detect: { ruleIds: ["core.git:push-force"] },
  };
  const strong: Constraint = {
    id: "strong",
    title: "strong",
    statement: "strong inviolable",
    severity: "inviolable",
    detect: { ruleIds: ["core.git:push-force"] },
  };
  const v = resolvePolicy(
    pushForceDeny(),
    "git push --force",
    basePolicy({ constraints: [weak, strong] }),
  );
  assert.equal(v.inviolable, true);
  assert.equal(v.constraintId, "strong");
});
