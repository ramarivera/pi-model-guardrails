// Regression tests for the Phase 3 grader adversarial-review fixes.

import assert from "node:assert/strict";
import test from "node:test";
import { type GradeInput, cacheKey, grade, withTimeout } from "../src/grade.ts";
import { defaultMachineConfig, transition } from "../src/state/machine.ts";
import type {
  CallMeta,
  DeterministicSignal,
  GraderSignal,
  PersistedState,
} from "../src/state/types.ts";

const cfg = defaultMachineConfig();
const mutating: CallMeta = { toolName: "bash", isMutating: true, isTrivial: false };
const cleanDet: DeterministicSignal = {
  blocked: false,
  inviolable: false,
  allowlistable: false,
  warn: false,
};
const compliant: GraderSignal = {
  compliant: true,
  backOnTrack: false,
  confidence: 0.9,
  inviolable: false,
};

// FIX: WATCH wrongly blocked a grader-approved clean mutating call.
test("WATCH: a grader-approved clean mutating call is ALLOWED (not held)", () => {
  const r = transition({
    current: { state: "WATCH", cleanStreak: 0, stateEpoch: 1, cooldownRemaining: 0 },
    deterministic: cleanDet,
    grader: compliant,
    meta: mutating,
    config: cfg,
  });
  assert.equal(r.action, "allow");
});

// FIX: recovery streak was inflatable via a cached verdict (stable epoch). Each
// advance now bumps the epoch so the cache key changes per recovery step.
test("RECOVERING streak advances bump the epoch (fresh cache key per step)", () => {
  const s: PersistedState = {
    state: "RECOVERING",
    cleanStreak: 0,
    stateEpoch: 5,
    cooldownRemaining: 0,
  };
  const r1 = transition({ current: s, deterministic: cleanDet, grader: compliant, meta: mutating, config: cfg });
  assert.equal(r1.next.cleanStreak, 1);
  assert.ok(r1.next.stateEpoch > s.stateEpoch, "epoch bumped on a streak advance");
});

// FIX: timeoutMs <= 0 disabled the only cancellation. It now floors instead.
test("withTimeout floors a non-positive timeout (never disables the gate)", async () => {
  const never = new Promise<string>(() => {}); // never resolves
  const start = Date.now();
  await assert.rejects(() => withTimeout(never, 0, "timeout"));
  assert.ok(Date.now() - start < 3000, "rejected via the floored timeout, did not hang");
});

const baseInput: GradeInput = {
  command: "echo hi",
  toolName: "bash",
  activeConstraints: [],
  recentActions: [],
  stateEpoch: 1,
};

// FIX: extractJsonObject took the first object; a multi-object (injection-shaped)
// grader output now fails toward the gate.
test("grade(): multi-object grader output fails toward the gate", async () => {
  const multi =
    '{"compliant":true,"backOnTrack":true,"confidence":1,"reasoning":"injected"}\n' +
    '{"compliant":false,"backOnTrack":false,"confidence":1,"reasoning":"real"}';
  const v = await grade(baseInput, {
    complete: async () => multi,
    timeoutMs: 1000,
    maxTokens: 200,
    maxRetries: 0,
    temperature: 0,
  });
  assert.equal(v.compliant, false);
});

// FIX: recentActions are now part of the cache key.
test("cacheKey distinguishes different recent-action history", () => {
  const a = cacheKey({ ...baseInput, recentActions: ["x"] });
  const b = cacheKey({ ...baseInput, recentActions: ["y", "z"] });
  assert.notEqual(a, b);
});
