// Tests for the per-pack matcher: imperative-first, per-pack safe
// short-circuit, destructive first-match-wins, and the fail-open / fail-closed
// guard semantics. Uses the real normalize.ts so segment+whole-command
// scanning is exercised end to end.

import assert from "node:assert/strict";
import test from "node:test";
import { matchPack } from "../src/engine/matcher.ts";
import { normalizeCommand } from "../src/engine/normalize.ts";
import type {
  EngineDecision,
  EvaluateOptions,
  Pack,
  SegmentContext,
} from "../src/engine/types.ts";

const OPTS: Required<EvaluateOptions> = {
  inputMaxLength: 8192,
  perMatchBudgetMs: 50,
  failClosed: false,
};

function opts(over: Partial<Required<EvaluateOptions>> = {}): Required<EvaluateOptions> {
  return { ...OPTS, ...over };
}

function segs(cmd: string): SegmentContext[] {
  return normalizeCommand(cmd);
}

test("destructive pattern denies (high => deny)", () => {
  const pack: Pack = {
    id: "core.git",
    name: "git",
    keywords: ["git"],
    safePatterns: [],
    destructivePatterns: [
      { name: "reset-hard", re: /git\s+reset\s+--hard/, severity: "high", reason: "hard reset" },
    ],
  };
  const d = matchPack(pack, segs("git reset --hard"), "git reset --hard", opts());
  assert.ok(d);
  assert.equal(d?.decision, "deny");
  assert.equal(d?.blocked, true);
  assert.equal(d?.ruleId, "core.git:reset-hard");
  assert.equal(d?.packId, "core.git");
  assert.equal(d?.ruleName, "reset-hard");
  assert.equal(d?.severity, "high");
});

test("medium => warn, low => log", () => {
  const warnPack: Pack = {
    id: "x.warn",
    name: "warn",
    keywords: ["foo"],
    safePatterns: [],
    destructivePatterns: [{ name: "m", re: /foo/, severity: "medium", reason: "m" }],
  };
  const logPack: Pack = {
    id: "x.log",
    name: "log",
    keywords: ["bar"],
    safePatterns: [],
    destructivePatterns: [{ name: "l", re: /bar/, severity: "low", reason: "l" }],
  };
  assert.equal(matchPack(warnPack, segs("foo"), "foo", opts())?.decision, "warn");
  assert.equal(matchPack(warnPack, segs("foo"), "foo", opts())?.blocked, false);
  assert.equal(matchPack(logPack, segs("bar"), "bar", opts())?.decision, "log");
});

test("per-pack safe pattern short-circuits this pack's destructive patterns", () => {
  const pack: Pack = {
    id: "containers.docker",
    name: "docker",
    keywords: ["docker"],
    safePatterns: [{ name: "docker-ps", re: /docker\s+ps/ }],
    destructivePatterns: [{ name: "prune", re: /docker\s+system\s+prune/, severity: "high", reason: "prune" }],
  };
  // Whole command is a single safe segment -> pack abstains.
  assert.equal(matchPack(pack, segs("docker ps"), "docker ps", opts()), undefined);
});

test("safe match in one segment does NOT shield a destructive segment (compound bypass guard within pack)", () => {
  // DCG: split into segments; a safe segment must not hide a destructive
  // segment. Here the pack has BOTH a safe and a destructive pattern.
  const pack: Pack = {
    id: "containers.docker",
    name: "docker",
    keywords: ["docker"],
    safePatterns: [{ name: "docker-ps", re: /^docker\s+ps$/ }],
    destructivePatterns: [{ name: "prune", re: /docker\s+system\s+prune/, severity: "high", reason: "prune" }],
  };
  const cmd = "docker ps && docker system prune";
  const d = matchPack(pack, segs(cmd), cmd, opts());
  assert.ok(d, "destructive segment must still fire even though one segment is safe");
  assert.equal(d?.ruleName, "prune");
});

test("imperative check runs before safe/destructive patterns and short-circuits", () => {
  const calls: string[] = [];
  const pack: Pack = {
    id: "core.filesystem",
    name: "fs",
    keywords: ["rm"],
    safePatterns: [{ name: "never", re: /rm/ }], // would otherwise allow
    destructivePatterns: [{ name: "never2", re: /rm/, severity: "high", reason: "x" }],
    imperative: [
      (ctx) => {
        calls.push(ctx.raw);
        if (/rm\s+-rf\s+\//.test(ctx.normalized)) {
          return {
            decision: "deny",
            blocked: true,
            ruleName: "rm-root",
            severity: "critical",
            reason: "rm -rf /",
          } satisfies EngineDecision;
        }
        return undefined;
      },
    ],
  };
  const d = matchPack(pack, segs("rm -rf /"), "rm -rf /", opts());
  assert.ok(d);
  assert.equal(d?.decision, "deny");
  assert.equal(d?.severity, "critical");
  // ruleId stamped from pack id + ruleName by matchPack.
  assert.equal(d?.ruleId, "core.filesystem:rm-root");
  assert.equal(d?.packId, "core.filesystem");
  assert.ok(calls.length >= 1);
});

test("clean miss => pack abstains (undefined)", () => {
  const pack: Pack = {
    id: "core.git",
    name: "git",
    keywords: ["git"],
    safePatterns: [],
    destructivePatterns: [{ name: "r", re: /git\s+reset\s+--hard/, severity: "high", reason: "r" }],
  };
  assert.equal(matchPack(pack, segs("git status"), "git status", opts()), undefined);
});

test("fail-open: a regex over the per-match budget abstains (default)", () => {
  // Force a guard trip by setting an impossible budget (0ms) and a pattern
  // that does work. With failClosed=false, a guard trip => abstain (undefined).
  const pack: Pack = {
    id: "x.slow",
    name: "slow",
    keywords: ["a"],
    safePatterns: [],
    destructivePatterns: [{ name: "slow", re: /a/, severity: "critical", reason: "slow" }],
  };
  const d = matchPack(pack, segs("aaaa"), "aaaa", opts({ perMatchBudgetMs: -1 }));
  assert.equal(d, undefined, "budget trip with failClosed=false must fail open");
});

test("fail-closed: a guard trip becomes a critical deny", () => {
  const pack: Pack = {
    id: "x.slow",
    name: "slow",
    keywords: ["a"],
    safePatterns: [],
    destructivePatterns: [{ name: "slow", re: /a/, severity: "critical", reason: "slow" }],
  };
  const d = matchPack(pack, segs("aaaa"), "aaaa", opts({ perMatchBudgetMs: -1, failClosed: true }));
  assert.ok(d);
  assert.equal(d?.decision, "deny");
  assert.equal(d?.severity, "critical");
});

test("length cap bites before budget: oversized input trips guard", () => {
  // inputMaxLength=2 with a 4-char input: guardedTest returns 'fail' on the
  // length check before any clock work. failClosed=false => abstain.
  const pack: Pack = {
    id: "x.cap",
    name: "cap",
    keywords: ["a"],
    safePatterns: [],
    destructivePatterns: [{ name: "d", re: /a/, severity: "high", reason: "d" }],
  };
  // Provide a single segment whose normalized text exceeds the cap.
  const cmd = "aaaa";
  assert.equal(matchPack(pack, segs(cmd), cmd, opts({ inputMaxLength: 2 })), undefined);
  // And with failClosed, the same cap trip becomes a critical deny.
  const d = matchPack(pack, segs(cmd), cmd, opts({ inputMaxLength: 2, failClosed: true }));
  assert.equal(d?.decision, "deny");
  assert.equal(d?.severity, "critical");
});
