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

// HIGH (FP): git restore false positives from anchored/unbounded patterns.
test("restore --staged is allowed regardless of flag order", () => {
  expectAllow("git restore --staged file.txt");
  expectAllow("git restore --source=HEAD~1 --staged x");
  expectAllow("git restore -s HEAD~1 --staged x");
});

test("restore-worktree pattern does not bridge across a segment boundary", () => {
  // safe restore + an unrelated later command containing -W must NOT deny
  expectAllow("git restore --staged x && grep -W pattern f");
});

test("genuine working-tree restore still blocks", () => {
  expectDeny("git restore file.txt");
  expectDeny("git restore --worktree file.txt");
});

// HIGH (FN): flag-position bypasses in git pack rules.
test("reset --hard is caught with intervening flags", () => {
  expectDeny("git reset --hard");
  expectDeny("git reset -q --hard");
  expectDeny("git reset --quiet --hard HEAD~1");
  expectAllow("git reset --soft HEAD~1");
});

test("clean force is caught with separate flags", () => {
  expectDeny("git clean -fd");
  expectDeny("git clean -d -f");
  expectDeny("git clean -x -f");
  expectAllow("git clean -n");
  expectAllow("git clean -d -n"); // dry-run anywhere
});

test("checkout -f / --force is caught (coverage gap)", () => {
  expectDeny("git checkout -f main");
  expectDeny("git checkout --force main");
  expectAllow("git checkout -b feature");
  expectAllow("git checkout main");
});

// HIGH (FN, dangerous): mixed short+long rm flags must still catch root/home.
test("rm with mixed short+long recursive/force flags is caught on root/home", () => {
  expectDeny("rm -r --force /");
  expectDeny("rm --recursive -f /etc");
  expectDeny("rm -f --recursive /home/me");
  expectDeny("rm --force -r /");
  // combined + all-short + all-long still work
  expectDeny("rm -rf /");
  expectDeny("rm -r -f /etc");
  expectDeny("rm --recursive --force /");
  // mixed flags on a temp path remain safe (no over-block)
  expectAllow("rm -r --force /tmp/x");
});

// MEDIUM (crash-redos): pathologically-nested subshells must not throw — a
// guard that crashes in the hot path could fail the tool call uncontrolled.
test("deeply nested subshells degrade gracefully instead of crashing", () => {
  const nested = `echo ${"$(".repeat(9000)}rm -rf /${")".repeat(9000)}`;
  // raised cap so normalization is actually attempted (default cap would bail first)
  const d = evaluateCommand(nested, registry, { inputMaxLength: 1_000_000 });
  assert.ok(
    ["allow", "deny", "warn", "log"].includes(d.decision),
    `expected a decision, got ${JSON.stringify(d)}`,
  );
});

// HIGH (FN, dangerous): flags AFTER the path (GNU getopt permutes operands).
test("rm with flags after the path is caught on root/home", () => {
  expectDeny("rm /etc -rf");
  expectDeny("rm /home/me/proj -rf");
  expectDeny("rm / -rf");
  // flags-after-path on a temp path stays safe
  expectAllow("rm /tmp/x -rf");
});
