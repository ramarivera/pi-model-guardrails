// Regression tests for bypasses found in the Phase 1 adversarial review.
// Each test pins a previously-exploitable input to its correct decision.

import assert from "node:assert/strict";
import test from "node:test";
import { evaluateCommand } from "../src/engine/evaluate.ts";
import { coreFilesystemPack } from "../src/engine/packs/core-filesystem.ts";
import { coreGitPack } from "../src/engine/packs/core-git.ts";
import { buildRegistry } from "../src/engine/registry.ts";

const registry = buildRegistry([coreGitPack, coreFilesystemPack]);

function expectDeny(cmd: string) {
  const d = evaluateCommand(cmd, registry);
  assert.equal(
    d.decision,
    "deny",
    `expected DENY for ${JSON.stringify(cmd)}, got ${d.decision} (${d.allowReason ?? d.ruleId})`,
  );
}

function expectAllow(cmd: string) {
  const d = evaluateCommand(cmd, registry);
  assert.equal(
    d.decision,
    "allow",
    `expected ALLOW for ${JSON.stringify(cmd)}, got ${d.decision} (${d.ruleId})`,
  );
}

// CRITICAL (port regression): obfuscated command words must not bypass the
// keyword quick-reject. Backslash-escaped / quote-split command words hide the
// pack keyword from the raw text but normalize back to a real command.
test("obfuscated command words do not bypass quick-reject (backslash)", () => {
  expectDeny("r\\m -rf /");
  expectDeny("g\\it reset --hard");
  expectDeny("g\\it push --force");
});

test("obfuscated command words do not bypass quick-reject (quote-split)", () => {
  expectDeny("'r'm -rf /");
  expectDeny('"g"it reset --hard');
});

test("obfuscation inside a subshell still resolves and blocks", () => {
  expectDeny("echo hi $(g\\it push --force)");
});

// CRITICAL (FP family): a leading wrapper (sudo/doas/env/time) must not defeat
// the ^-anchored safe rescues while the unanchored destructive rules fire. The
// matcher runs against the wrapper-stripped whole command.
test("wrapper-prefixed safe temp deletion is allowed (not a critical root delete)", () => {
  expectAllow("sudo rm -rf /tmp/x");
  expectAllow("doas rm -rf /tmp/scratch");
});

test("wrapper-prefixed genuinely-dangerous command still blocks", () => {
  expectDeny("sudo rm -rf /");
  expectDeny("sudo rm -rf /etc");
});

// CRITICAL (FN): a temp-safe rm must not exonerate a destructive sibling in the
// same compound command.
test("temp-safe rm does not shield a destructive sibling segment", () => {
  expectDeny("mv /etc /tmp/x && rm -rf /tmp/x");
  expectDeny("find /etc -delete && rm -rf /tmp/x");
});

test("cp/ln/rsync sensitive-then-delete propagation still fires (&&)", () => {
  expectDeny("cp -a /etc /tmp/x && rm -rf /tmp/x");
});

// Sanity: a lone temp-safe rm is still allowed (no over-block from the fix).
test("lone temp-safe rm remains allowed", () => {
  expectAllow("rm -rf /tmp/x");
  expectAllow("rm -rf /tmp/build-cache");
});
