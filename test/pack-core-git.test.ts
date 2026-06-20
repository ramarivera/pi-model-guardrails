// Golden corpus for the core.git pack, ported from DCG's own `#[test]` blocks
// in `src/packs/core/git.rs` (mod tests). Each case mirrors a DCG assertion:
//   assert_blocks / assert_blocks_with_pattern / assert_blocks_with_severity
//   -> a destructive match with the expected rule name + severity
//   assert_allows / assert_no_match / is_none()
//   -> no destructive match (safe pattern or no keyword)
//
// Because the standalone engine modules (matcher/normalize) are ported
// separately, this test embeds a minimal, faithful re-implementation of DCG
// `Pack::check` for the git pack: segment-split on shell separators, then for
// each segment run safe patterns first (any match => segment allowed) and
// destructive patterns in declaration order (first match wins). This is exactly
// DCG's `check` -> `check_single` ordering for a pack with no imperative checks.

import assert from "node:assert/strict";
import test from "node:test";

import { coreGitPack } from "../src/engine/packs/core-git.ts";
import type { Severity } from "../src/engine/types.ts";

interface Match {
  ruleName: string;
  severity: Severity;
  reason: string;
}

// Minimal quote/escape-aware splitter mirroring DCG `split_command_segments`
// for the separators the git tests exercise (`;`, `\n`, `&&`, `||`, `|`).
// NOTE: full `$(...)` / backtick subshell extraction is the engine
// splitCommandSegments module's job; this helper covers the canonical git
// cases. (See portNotes.)
function splitSegments(cmd: string): string[] {
  const segs: string[] = [];
  let buf = "";
  let inSingle = false;
  let inDouble = false;
  for (let i = 0; i < cmd.length; i++) {
    const c = cmd[i];
    if (c === "\\" && !inSingle && i + 1 < cmd.length) {
      buf += c + cmd[i + 1];
      i++;
      continue;
    }
    if (c === "'" && !inDouble) {
      inSingle = !inSingle;
      buf += c;
      continue;
    }
    if (c === '"' && !inSingle) {
      inDouble = !inDouble;
      buf += c;
      continue;
    }
    if (!inSingle && !inDouble) {
      if (c === ";" || c === "\n") {
        segs.push(buf);
        buf = "";
        continue;
      }
      if (c === "&" && cmd[i + 1] === "&") {
        segs.push(buf);
        buf = "";
        i++;
        continue;
      }
      if (c === "|" && cmd[i + 1] === "|") {
        segs.push(buf);
        buf = "";
        i++;
        continue;
      }
      if (c === "|") {
        segs.push(buf);
        buf = "";
        continue;
      }
    }
    buf += c;
  }
  segs.push(buf);
  const trimmed = segs.map((sg) => sg.trim()).filter((sg) => sg.length > 0);
  return trimmed.length > 0
    ? trimmed
    : [cmd.trim()].filter((sg) => sg.length > 0);
}

function checkSingle(seg: string): Match | undefined {
  // Quick reject if no keyword present (DCG `might_match`).
  if (!coreGitPack.keywords.some((kw) => seg.includes(kw))) return undefined;
  // Safe patterns first: any match => segment allowed.
  for (const sp of coreGitPack.safePatterns) {
    if (sp.re.test(seg)) return undefined;
  }
  // Destructive patterns: first match wins (declaration order).
  for (const dp of coreGitPack.destructivePatterns) {
    if (dp.re.test(seg)) {
      return { ruleName: dp.name, severity: dp.severity, reason: dp.reason };
    }
  }
  return undefined;
}

// Faithful port of DCG `Pack::check`: if >1 segment, check each; else check whole.
function check(cmd: string): Match | undefined {
  const segments = splitSegments(cmd);
  if (segments.length > 1) {
    for (const seg of segments) {
      const m = checkSingle(seg);
      if (m) return m;
    }
    return undefined;
  }
  return checkSingle(cmd);
}

// ---------------------------------------------------------------------------
// Critical severity pattern tests (DCG test_*_critical).
// ---------------------------------------------------------------------------

test("reset --hard is critical (reset-hard)", () => {
  const m = check("git reset --hard");
  assert.ok(m, "git reset --hard must block");
  assert.equal(m.ruleName, "reset-hard");
  assert.equal(m.severity, "critical");
  for (const cmd of [
    "git reset --hard HEAD",
    "git reset --hard HEAD~1",
    "git reset --hard origin/main",
  ]) {
    const r = check(cmd);
    assert.ok(r, `${cmd} must block`);
    assert.match(r.reason, /destroys uncommitted/);
  }
});

test("clean -f/--force is critical (clean-force)", () => {
  const m = check("git clean -f");
  assert.ok(m, "git clean -f must block");
  assert.equal(m.ruleName, "clean-force");
  assert.equal(m.severity, "critical");
  for (const cmd of ["git clean -fd", "git clean -xf"]) {
    const r = check(cmd);
    assert.ok(r, `${cmd} must block`);
    assert.match(r.reason, /removes untracked files/);
  }
});

test("force push (long and short) is critical", () => {
  const longF = check("git " + "push --force");
  assert.ok(longF, "force push (long) must block");
  assert.equal(longF.severity, "critical");

  const shortF = check("git " + "push -f");
  assert.ok(shortF, "force push (short) must block");
  assert.equal(shortF.severity, "critical");

  for (const cmd of [
    "git " + "push origin main --force",
    "git " + "push --force origin main",
  ]) {
    const r = check(cmd);
    assert.ok(r, `${cmd} must block`);
    assert.match(r.reason, /destroy remote history/);
  }

  // Combined short-flag forms resolving to -f.
  for (const cmd of [
    "git " + "push -uf origin main",
    "git " + "push -fv origin main",
    "git " + "push -fuv origin main",
    "git " + "push -vf origin main",
  ]) {
    const r = check(cmd);
    assert.ok(r, `${cmd} must block`);
    assert.equal(r.severity, "critical");
  }

  // Branch names that merely contain -f / --force must NOT trip the rule.
  assert.equal(
    check("git " + "push origin feature-f"),
    undefined,
    "branch named feature-f must not be treated as a force flag",
  );
  assert.equal(
    check("git " + "push origin hotfix-fallback"),
    undefined,
    "branch named hotfix-fallback must not be treated as a force flag",
  );
  assert.equal(
    check("git " + "push origin feature--force"),
    undefined,
    "branch name feature--force must not trigger push-force-long",
  );

  // --force-with-lease / --force-if-includes are the safer alternatives.
  assert.equal(
    check("git " + "push --force-with-lease origin main"),
    undefined,
    "--force-with-lease must not be blocked",
  );
  assert.equal(
    check("git " + "push --force-with-lease --force-if-includes origin main"),
    undefined,
    "--force-with-lease --force-if-includes must not be blocked",
  );
});

test("force push must not span shell boundaries (#124), but real ones across separators still block", () => {
  for (const cmd of [
    "git " + "push origin main && echo done --force",
    "git " + "push origin main; echo --force",
    "git " + "push origin main || echo --force",
    "git " + "push origin main | tee log --force",
    "branch=$(git rev-parse HEAD) && git " +
      "push --force-with-lease origin main",
  ]) {
    assert.equal(
      check(cmd),
      undefined,
      `force push must not span shell boundaries; cmd=${cmd}`,
    );
  }
  for (const cmd of [
    "git fetch && git " + "push --force origin main",
    "git fetch; git " + "push -f origin main",
    "git fetch || git " + "push --force",
  ]) {
    assert.ok(
      check(cmd),
      `a real force-push statement after a separator must still block; cmd=${cmd}`,
    );
  }
});

test("stash clear is critical (stash-clear)", () => {
  const m = check("git stash clear");
  assert.ok(m, "git stash clear must block");
  assert.equal(m.ruleName, "stash-clear");
  assert.equal(m.severity, "critical");
});

// ---------------------------------------------------------------------------
// High severity pattern tests (DCG test_*_high).
// ---------------------------------------------------------------------------

test("checkout -- discards uncommitted changes (checkout-discard, high)", () => {
  const m = check("git checkout -- file.txt");
  assert.ok(m, "git checkout -- file.txt must block");
  assert.equal(m.ruleName, "checkout-discard");
  assert.equal(m.severity, "high");
  const r = check("git checkout -- .");
  assert.ok(r, "git checkout -- . must block");
  assert.match(r.reason, /discards uncommitted changes/);
});

test("restore (worktree) discards changes (restore-worktree, high)", () => {
  const m = check("git restore file.txt");
  assert.ok(m, "git restore file.txt must block");
  assert.equal(m.severity, "high");
  const r = check("git restore --worktree file.txt");
  assert.ok(r, "git restore --worktree file.txt must block");
  assert.match(r.reason, /discards uncommitted/);
});

// ---------------------------------------------------------------------------
// Medium severity pattern tests (DCG test_*_medium).
// ---------------------------------------------------------------------------

test("branch force-delete is medium (branch-force-delete)", () => {
  const m = check("git branch -D feature");
  assert.ok(m, "git branch -D feature must block");
  assert.equal(m.ruleName, "branch-force-delete");
  assert.equal(m.severity, "medium");

  for (const cmd of [
    "git branch --force feature",
    "git branch -f feature",
    "git branch -Dr origin/feature",
    "git branch -vD feature",
    "git branch -fv feature",
    "git branch -vdf feature",
  ]) {
    const r = check(cmd);
    assert.ok(r, `${cmd} must block`);
    assert.equal(r.ruleName, "branch-force-delete");
  }

  // Non-forcing forms must NOT trip the rule.
  assert.equal(
    check("git branch -d merged-feature"),
    undefined,
    "-d alone must not block",
  );
  assert.equal(
    check("git branch -vd merged-feature"),
    undefined,
    "-vd must not block",
  );
  assert.equal(
    check("git branch -a"),
    undefined,
    "listing branches must not block",
  );

  // --force-with-lease / --force-if-includes must not false-match branch-force-delete (#121).
  for (const cmd of [
    "git " + "push --force-with-lease origin main",
    "git " + "push --force-if-includes origin HEAD:main",
    "git " + "push --force-with-lease=main:abc123 origin",
  ]) {
    // (push-force-long catches the first two as critical; what matters here is
    // they are NOT attributed to branch-force-delete, and the lease ones stay safe.)
    const r = check(cmd);
    if (r) {
      assert.notEqual(
        r.ruleName,
        "branch-force-delete",
        `cmd must not be branch-force-delete; cmd=${cmd}`,
      );
    }
  }

  // branch-force-delete must not span shell boundaries (#121).
  for (const cmd of [
    "branch=$(git branch --show-current) && git " +
      "push --force-with-lease origin HEAD:main",
    "git branch --show-current && git " + "push --force-with-lease origin main",
    "git branch --show-current; git " + "push --force-with-lease origin main",
    "git branch --show-current || git " + "push --force-with-lease origin main",
  ]) {
    assert.equal(
      check(cmd),
      undefined,
      `branch-force-delete must not span shell boundaries; cmd=${cmd}`,
    );
  }
});

test("stash drop is medium (stash-drop)", () => {
  const m = check("git stash drop");
  assert.ok(m, "git stash drop must block");
  assert.equal(m.ruleName, "stash-drop");
  assert.equal(m.severity, "medium");
  const r = check("git stash drop stash@{0}");
  assert.ok(r, "git stash drop stash@{0} must block");
  assert.match(r.reason, /Recoverable/);
});

// ---------------------------------------------------------------------------
// Safe pattern tests (DCG test_safe_*).
// ---------------------------------------------------------------------------

test("safe: checkout -b / --orphan", () => {
  for (const cmd of [
    "git checkout -b feature",
    "git checkout -b feature/new-thing",
    "git checkout -b fix-123",
    "git checkout --orphan gh-pages",
    "git checkout --orphan new-root",
  ]) {
    assert.equal(check(cmd), undefined, `${cmd} must be allowed`);
  }
});

test("safe: restore --staged / -S", () => {
  assert.equal(check("git restore --staged file.txt"), undefined);
  assert.equal(check("git restore -S file.txt"), undefined);
});

test("safe: clean dry-run", () => {
  for (const cmd of ["git clean -n", "git clean -dn", "git clean --dry-run"]) {
    assert.equal(check(cmd), undefined, `${cmd} must be allowed`);
  }
});

// ---------------------------------------------------------------------------
// Specificity / false-positive prevention (DCG test_specificity_*).
// ---------------------------------------------------------------------------

test("safe: ordinary read-only git commands are allowed", () => {
  for (const cmd of [
    "git status",
    "git log",
    "git log --oneline",
    "git diff",
    "git diff --cached",
    "git show HEAD",
    "git branch",
    "git branch -a",
    "git remote -v",
    "git fetch",
    "git pull",
    "git " + "push",
    "git add .",
    "git commit -m 'message'",
    "git branch -d feature",
  ]) {
    assert.equal(check(cmd), undefined, `${cmd} must be allowed`);
  }
});

test("unrelated commands do not match", () => {
  for (const cmd of ["ls -la", "cargo build", "npm install", "docker run"]) {
    assert.equal(check(cmd), undefined, `${cmd} must not match`);
  }
});

test("'git' as a substring must not trigger (.gitignore, digit)", () => {
  assert.equal(
    check("cat .gitignore"),
    undefined,
    ".gitignore must not be a false positive",
  );
  assert.equal(
    check("echo digit"),
    undefined,
    "'digit' must not be a false positive",
  );
});
