// Tests for evaluateCommand: strictest-wins across packs, per-pack safe
// short-circuit NOT leaking across packs, quick-reject, and the
// length-cap-before-budget (ReDoS) ordering.

import assert from "node:assert/strict";
import test from "node:test";
import { evaluateCommand } from "../src/engine/evaluate.ts";
import { buildRegistry } from "../src/engine/registry.ts";
import type { Pack } from "../src/engine/types.ts";

test("no match => allow (allowReason no_match)", () => {
  const git: Pack = {
    id: "core.git",
    name: "git",
    keywords: ["git"],
    safePatterns: [],
    destructivePatterns: [
      { name: "r", re: /git\s+reset\s+--hard/, severity: "high", reason: "r" },
    ],
  };
  const reg = buildRegistry([git]);
  const d = evaluateCommand("git status", reg);
  assert.equal(d.decision, "allow");
  assert.equal(d.blocked, false);
  assert.equal(d.allowReason, "no_match");
});

test("quick-reject: command with no matching keyword allows without touching packs", () => {
  const git: Pack = {
    id: "core.git",
    name: "git",
    keywords: ["git"],
    safePatterns: [],
    // A pattern that would match 'ls' if it were ever checked. It must NOT be,
    // because the keyword 'git' is absent.
    destructivePatterns: [
      { name: "trap", re: /ls/, severity: "critical", reason: "trap" },
    ],
  };
  const reg = buildRegistry([git]);
  const d = evaluateCommand("ls -la", reg);
  assert.equal(d.decision, "allow");
  assert.equal(d.allowReason, "quick_reject");
});

test("strictest-wins across two packs: critical deny beats medium warn regardless of pack order", () => {
  const warnPack: Pack = {
    id: "a.warn",
    name: "warn",
    keywords: ["danger"],
    safePatterns: [],
    destructivePatterns: [
      { name: "w", re: /danger/, severity: "medium", reason: "medium" },
    ],
  };
  const critPack: Pack = {
    id: "b.crit",
    name: "crit",
    keywords: ["danger"],
    safePatterns: [],
    destructivePatterns: [
      { name: "c", re: /danger/, severity: "critical", reason: "critical" },
    ],
  };
  // warn pack first in declaration order — strictest-wins must still pick crit.
  const reg = buildRegistry([warnPack, critPack]);
  const d = evaluateCommand("danger", reg);
  assert.equal(d.decision, "deny");
  assert.equal(d.severity, "critical");
  assert.equal(d.packId, "b.crit");
});

test("strictest-wins tie => earlier pack (declaration order) wins attribution", () => {
  // Mirrors DCG core.git (tier 1) winning over strict_git (tier 9) on the
  // same severity for `git reset --hard`.
  const coreGit: Pack = {
    id: "core.git",
    name: "git",
    keywords: ["git"],
    safePatterns: [],
    destructivePatterns: [
      {
        name: "reset-hard",
        re: /git\s+reset\s+--hard/,
        severity: "critical",
        reason: "core",
      },
    ],
  };
  const strictGit: Pack = {
    id: "strict_git",
    name: "strict git",
    keywords: ["git"],
    safePatterns: [],
    destructivePatterns: [
      {
        name: "reset",
        re: /git\s+reset/,
        severity: "critical",
        reason: "strict",
      },
    ],
  };
  const reg = buildRegistry([coreGit, strictGit]);
  const d = evaluateCommand("git reset --hard", reg);
  assert.equal(d.decision, "deny");
  assert.equal(d.packId, "core.git", "earlier pack wins the tie");
});

test("per-pack safe short-circuit does NOT leak across packs (compound bypass guard)", () => {
  // safePack whitelists `git checkout -b foo` for ITS pack only. A destructive
  // `rm -rf /` in another pack/segment must still fire — the safe match must
  // not become a global allow.
  const safePack: Pack = {
    id: "core.git",
    name: "git",
    keywords: ["git"],
    safePatterns: [{ name: "checkout-b", re: /git\s+checkout\s+-b\s+\S+/ }],
    destructivePatterns: [
      { name: "reset", re: /git\s+reset/, severity: "high", reason: "reset" },
    ],
  };
  const rmPack: Pack = {
    id: "core.filesystem",
    name: "fs",
    keywords: ["rm"],
    safePatterns: [],
    destructivePatterns: [
      {
        name: "rm-root",
        re: /rm\s+-rf\s+\//,
        severity: "critical",
        reason: "rm -rf /",
      },
    ],
  };
  const reg = buildRegistry([safePack, rmPack]);
  const cmd = "git checkout -b foo && rm -rf /";
  const d = evaluateCommand(cmd, reg);
  assert.equal(
    d.decision,
    "deny",
    "rm -rf / must not be shielded by git pack's safe pattern",
  );
  assert.equal(d.severity, "critical");
  assert.equal(d.packId, "core.filesystem");
});

test("ReDoS guard: inputMaxLength bites BEFORE budget (fail-open by default)", () => {
  const evil: Pack = {
    id: "x.evil",
    name: "evil",
    keywords: ["a"],
    safePatterns: [],
    // A classic catastrophic-backtracking shape. With the length cap biting
    // first, this regex is never executed on the oversized input.
    destructivePatterns: [
      { name: "redos", re: /(a+)+$/, severity: "critical", reason: "redos" },
    ],
  };
  const reg = buildRegistry([evil]);
  const long = "a".repeat(5000) + "!"; // 5001 chars, over an 8-char cap
  const d = evaluateCommand(long, reg, { inputMaxLength: 8 });
  // Cap bit at the top of evaluateCommand => allow (fail-open), never ran regex.
  assert.equal(d.decision, "allow");
  assert.equal(d.allowReason, "input_too_long");
});

test("ReDoS guard: oversized input with failClosed => critical deny", () => {
  const evil: Pack = {
    id: "x.evil",
    name: "evil",
    keywords: ["a"],
    safePatterns: [],
    destructivePatterns: [
      { name: "redos", re: /(a+)+$/, severity: "critical", reason: "redos" },
    ],
  };
  const reg = buildRegistry([evil]);
  const long = "a".repeat(5000);
  const d = evaluateCommand(long, reg, { inputMaxLength: 8, failClosed: true });
  assert.equal(d.decision, "deny");
  assert.equal(d.severity, "critical");
});

test("empty command => allow", () => {
  const reg = buildRegistry([]);
  const d = evaluateCommand("", reg);
  assert.equal(d.decision, "allow");
  assert.equal(d.allowReason, "empty");
});

test("warn-only match returns warn (not blocked)", () => {
  const warnPack: Pack = {
    id: "a.warn",
    name: "warn",
    keywords: ["meh"],
    safePatterns: [],
    destructivePatterns: [
      { name: "w", re: /meh/, severity: "medium", reason: "meh" },
    ],
  };
  const reg = buildRegistry([warnPack]);
  const d = evaluateCommand("meh", reg);
  assert.equal(d.decision, "warn");
  assert.equal(d.blocked, false);
  assert.equal(d.severity, "medium");
});
