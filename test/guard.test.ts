// Composition tests for guardToolCall — engine + policy + state machine wired
// into one per-call decision (Phase 2, deterministic; no grader).

import assert from "node:assert/strict";
import test from "node:test";
import { coreFilesystemPack } from "../src/engine/packs/core-filesystem.ts";
import { coreGitPack } from "../src/engine/packs/core-git.ts";
import { buildRegistry } from "../src/engine/registry.ts";
import { type GuardDeps, guardToolCall } from "../src/guard.ts";
import { defaultPolicyConfig } from "../src/policy/engine.ts";
import type { PolicyConfig } from "../src/policy/types.ts";
import { defaultMachineConfig, initialState } from "../src/state/machine.ts";
import type { CallMeta } from "../src/state/types.ts";

const registry = buildRegistry([coreGitPack, coreFilesystemPack]);
const meta: CallMeta = { toolName: "bash", isMutating: true, isTrivial: false };

function deps(policy: PolicyConfig = defaultPolicyConfig()): GuardDeps {
  return { registry, policy, machineConfig: defaultMachineConfig() };
}

test("critical command halts the session (the git-reset-incident behavior)", () => {
  const out = guardToolCall(
    { command: "git reset --hard HEAD~1", meta, state: initialState() },
    deps(),
  );
  assert.equal(out.block, true);
  assert.equal(out.action, "halt");
  assert.equal(out.nextState.state, "HALTED");
});

test("high-severity command blocks and arms GATED (recoverable)", () => {
  const out = guardToolCall(
    { command: "git restore file.txt", meta, state: initialState() },
    deps(),
  );
  assert.equal(out.block, true);
  assert.equal(out.action, "block");
  assert.equal(out.nextState.state, "GATED");
});

test("a clean command is allowed and stays COMPLIANT", () => {
  const out = guardToolCall(
    { command: "ls -la", meta, state: initialState() },
    deps(),
  );
  assert.equal(out.block, false);
  assert.equal(out.action, "allow");
  assert.equal(out.nextState.state, "COMPLIANT");
});

test("a medium-severity command warns and arms WATCH without blocking", () => {
  const out = guardToolCall(
    { command: "git branch -D feature", meta, state: initialState() },
    deps(),
  );
  assert.equal(out.block, false);
  assert.equal(out.nextState.state, "WATCH");
});

test("a project inviolable constraint escalates a HIGH rule to HALTED", () => {
  const policy: PolicyConfig = {
    ...defaultPolicyConfig(),
    inviolable: ["core.git:restore-worktree"],
  };
  const out = guardToolCall(
    { command: "git restore file.txt", meta, state: initialState() },
    deps(policy),
  );
  assert.equal(out.block, true);
  assert.equal(out.action, "halt");
  assert.equal(out.nextState.state, "HALTED");
  assert.equal(out.verdict.inviolable, true);
});

test("once GATED, Phase-2 lets clean calls through (armed, no grader) but keeps blocking dangerous ones", () => {
  const gated = guardToolCall(
    { command: "git restore a.txt", meta, state: initialState() },
    deps(),
  ).nextState;
  assert.equal(gated.state, "GATED");

  // clean call while GATED: Phase 2 allows (gate-required has no grader to adjudicate)
  const clean = guardToolCall({ command: "ls", meta, state: gated }, deps());
  assert.equal(clean.block, false);
  assert.equal(clean.action, "gate-required");
  assert.equal(clean.nextState.state, "GATED"); // still armed

  // a dangerous call while GATED is still blocked deterministically
  const danger = guardToolCall(
    { command: "git push --force", meta, state: gated },
    deps(),
  );
  assert.equal(danger.block, true);
});

test("HALTED blocks everything until human ack", () => {
  const halted = guardToolCall(
    { command: "rm -rf /", meta, state: initialState() },
    deps(),
  ).nextState;
  assert.equal(halted.state, "HALTED");
  const next = guardToolCall({ command: "ls", meta, state: halted }, deps());
  assert.equal(next.block, true);
  assert.equal(next.action, "halt");
});
