// grade() tests — the Phase 3 LLM grading gate.
//
// grade() owns the timeout / retry / fail-toward-gate / cache logic around an
// INJECTED completer (a fake here; production wires it to ctx.modelRegistry +
// complete()). These tests assert: a compliant verdict, a non-compliant verdict,
// malformed JSON -> fail-toward-gate, a throwing completer -> fail-toward-gate, a
// slow completer (> timeout) -> fail-toward-gate (and the loop is unblocked), the
// cache returns without re-calling complete, and an epoch bump invalidates the
// cache. No real LLM is involved — fully deterministic.

import assert from "node:assert/strict";
import test from "node:test";
import {
  buildGradePrompt,
  cacheKey,
  type GradeCache,
  type GradeDeps,
  type GradeInput,
  grade,
  parseVerdict,
  withTimeout,
} from "../src/grade.ts";
import type { Constraint } from "../src/policy/types.ts";

const constraint: Constraint = {
  id: "no-force-push-main",
  title: "Never force-push main",
  statement: "Force-pushing the main branch is forbidden.",
  severity: "inviolable",
  requiredBehavior: "Open a PR instead.",
};

function input(overrides: Partial<GradeInput> = {}): GradeInput {
  return {
    command: "git status",
    toolName: "bash",
    activeConstraints: [constraint],
    violatedConstraintId: "no-force-push-main",
    recentActions: ["block: git push --force origin main"],
    stateEpoch: 3,
    ...overrides,
  };
}

function deps(
  complete: GradeDeps["complete"],
  overrides: Partial<GradeDeps> = {},
): GradeDeps {
  return {
    complete,
    timeoutMs: 1000,
    maxTokens: 256,
    maxRetries: 1,
    temperature: 0.1,
    ...overrides,
  };
}

const compliantJson = JSON.stringify({
  compliant: true,
  backOnTrack: true,
  confidence: 0.9,
  reasoning: "Read-only status check; respects the constraint.",
});

const dirtyJson = JSON.stringify({
  compliant: false,
  backOnTrack: false,
  confidence: 0.95,
  violatedConstraintId: "no-force-push-main",
  reasoning: "Still attempting a force push.",
  remediation: "Open a PR.",
});

test("compliant verdict maps to a clean GraderSignal", async () => {
  const signal = await grade(
    input(),
    deps(async () => compliantJson),
  );
  assert.equal(signal.compliant, true);
  assert.equal(signal.backOnTrack, true);
  assert.equal(signal.confidence, 0.9);
  assert.equal(signal.inviolable, false);
});

test("non-compliant verdict maps to a dirty GraderSignal", async () => {
  const signal = await grade(
    input(),
    deps(async () => dirtyJson),
  );
  assert.equal(signal.compliant, false);
  assert.equal(signal.backOnTrack, false);
  assert.equal(signal.violatedConstraintId, "no-force-push-main");
  assert.equal(signal.inviolable, false);
});

test("a non-compliant grade can never be back-on-track (strictest-wins)", async () => {
  const sneaky = JSON.stringify({
    compliant: false,
    backOnTrack: true, // the model lied; we must NOT honor backOnTrack on a dirty grade
    confidence: 0.8,
    reasoning: "...",
  });
  const signal = await grade(
    input(),
    deps(async () => sneaky),
  );
  assert.equal(signal.compliant, false);
  assert.equal(signal.backOnTrack, false);
});

test("malformed JSON fails TOWARD the gate (non-compliant)", async () => {
  const signal = await grade(
    input(),
    deps(async () => "I think this is fine, honestly", { maxRetries: 0 }),
  );
  assert.equal(signal.compliant, false);
  assert.equal(signal.backOnTrack, false);
  assert.equal(signal.confidence, 0);
  assert.match(signal.reason ?? "", /malformed JSON/);
});

test("a throwing completer fails TOWARD the gate", async () => {
  const signal = await grade(
    input(),
    deps(
      async () => {
        throw new Error("network down");
      },
      { maxRetries: 0 },
    ),
  );
  assert.equal(signal.compliant, false);
  assert.equal(signal.confidence, 0);
  assert.match(signal.reason ?? "", /network down/);
});

test("a slow completer (> timeout) fails TOWARD the gate and unblocks the loop", async () => {
  let resolved = false;
  const slow = (): Promise<string> =>
    new Promise((resolve) => {
      setTimeout(() => {
        resolved = true;
        resolve(compliantJson);
      }, 200);
    });

  const start = Date.now();
  const signal = await grade(
    input(),
    deps(slow, { timeoutMs: 20, maxRetries: 0 }),
  );
  const elapsed = Date.now() - start;

  // The race returned long before the slow completer would have (loop unblocked).
  assert.ok(
    elapsed < 150,
    `grade returned in ${elapsed}ms (timeout protected)`,
  );
  assert.equal(signal.compliant, false);
  assert.equal(signal.confidence, 0);
  assert.match(signal.reason ?? "", /timed out/);
  // The underlying completer is NOT cancellable here — it still resolves later,
  // which is fine; the agent loop already moved on.
  assert.equal(resolved, false);
});

test("bounded retry: a transient failure then success returns the success", async () => {
  let calls = 0;
  const flaky = async (): Promise<string> => {
    calls++;
    if (calls === 1) throw new Error("transient");
    return compliantJson;
  };
  const signal = await grade(input(), deps(flaky, { maxRetries: 1 }));
  assert.equal(calls, 2);
  assert.equal(signal.compliant, true);
});

test("retries are bounded by maxRetries (no infinite loop)", async () => {
  let calls = 0;
  const alwaysThrow = async (): Promise<string> => {
    calls++;
    throw new Error("boom");
  };
  const signal = await grade(input(), deps(alwaysThrow, { maxRetries: 2 }));
  assert.equal(calls, 3); // 1 initial + 2 retries
  assert.equal(signal.compliant, false);
});

test("cache hit returns WITHOUT calling complete again", async () => {
  const cache: GradeCache = new Map();
  let calls = 0;
  const counting = async (): Promise<string> => {
    calls++;
    return compliantJson;
  };

  const first = await grade(input(), deps(counting, { cache }));
  const second = await grade(input(), deps(counting, { cache }));
  assert.equal(calls, 1, "second call served from cache");
  assert.deepEqual(first, second);
});

test("an epoch bump invalidates the cached verdict (state change)", async () => {
  const cache: GradeCache = new Map();
  let calls = 0;
  const counting = async (): Promise<string> => {
    calls++;
    return compliantJson;
  };

  await grade(input({ stateEpoch: 1 }), deps(counting, { cache }));
  await grade(input({ stateEpoch: 2 }), deps(counting, { cache }));
  assert.equal(calls, 2, "a different epoch is a cache miss");
});

test("a failed grade is NOT cached (next call gets a fresh chance)", async () => {
  const cache: GradeCache = new Map();
  let calls = 0;
  const fail = async (): Promise<string> => {
    calls++;
    throw new Error("nope");
  };
  await grade(input(), deps(fail, { cache, maxRetries: 0 }));
  await grade(input(), deps(fail, { cache, maxRetries: 0 }));
  assert.equal(calls, 2, "a fail-toward-gate verdict is not cached");
});

test("cacheKey changes with tool, command, constraints, violated id, and epoch", () => {
  const base = input();
  const k = cacheKey(base);
  assert.notEqual(k, cacheKey(input({ command: "git log" })));
  assert.notEqual(k, cacheKey(input({ toolName: "write" })));
  assert.notEqual(k, cacheKey(input({ stateEpoch: 99 })));
  assert.notEqual(k, cacheKey(input({ violatedConstraintId: "other" })));
  assert.notEqual(
    k,
    cacheKey(input({ activeConstraints: [] })),
    "constraint set is part of the key",
  );
  assert.equal(k, cacheKey(input()), "stable for identical input");
});

test("parseVerdict extracts JSON wrapped in prose / fences", () => {
  const wrapped = `Sure, here is my verdict:\n\`\`\`json\n${compliantJson}\n\`\`\`\nHope that helps.`;
  const signal = parseVerdict(wrapped, input());
  assert.ok(signal);
  assert.equal(signal.compliant, true);
});

test("parseVerdict rejects a missing required field", () => {
  const bad = JSON.stringify({ compliant: true }); // no backOnTrack / confidence
  assert.equal(parseVerdict(bad, input()), undefined);
});

test("parseVerdict clamps confidence into [0,1]", () => {
  const over = JSON.stringify({
    compliant: true,
    backOnTrack: false,
    confidence: 7.5,
    reasoning: "x",
  });
  const signal = parseVerdict(over, input());
  assert.ok(signal);
  assert.equal(signal.confidence, 1);
});

test("parseVerdict falls back to the armed constraint id on a dirty verdict", () => {
  const noId = JSON.stringify({
    compliant: false,
    backOnTrack: false,
    confidence: 0.9,
    reasoning: "bad",
  });
  const signal = parseVerdict(
    noId,
    input({ violatedConstraintId: "armed-id" }),
  );
  assert.ok(signal);
  assert.equal(signal.violatedConstraintId, "armed-id");
});

test("buildGradePrompt focuses on the violated constraint and demands strict JSON", () => {
  const prompt = buildGradePrompt(input());
  assert.match(prompt, /no-force-push-main/);
  assert.match(prompt, /Never force-push main/);
  assert.match(prompt, /STRICT JSON/);
  assert.match(prompt, /git status/);
  assert.match(prompt, /git push --force origin main/);
});

test("withTimeout resolves a fast promise and rejects a slow one", async () => {
  const fast = await withTimeout(Promise.resolve("ok"), 1000, "slow");
  assert.equal(fast, "ok");

  await assert.rejects(
    withTimeout(
      new Promise((r) => setTimeout(() => r("late"), 100)),
      10,
      "slow",
    ),
    /slow/,
  );
});
