// Data-span masking tests. Two halves:
//   (A) FALSE POSITIVES the masking must FIX (dangerous text in a data position).
//   (B) the SAFETY contract: masking must NEVER hide EXECUTED text (no FN).
// Dangerous strings here are test fixtures in a source file, not shell commands.

import assert from "node:assert/strict";
import test from "node:test";

import { evaluateCommand } from "../src/engine/evaluate.ts";
import { coreFilesystemPack } from "../src/engine/packs/core-filesystem.ts";
import { coreGitPack } from "../src/engine/packs/core-git.ts";
import { buildRegistry } from "../src/engine/registry.ts";
import { sanitizeForPatternMatching } from "../src/engine/sanitize.ts";

const registry = buildRegistry([coreGitPack, coreFilesystemPack]);
const blocks = (cmd: string): boolean =>
  evaluateCommand(cmd, registry).blocked === true;

// ---------------------------------------------------------------------------
// (A) False positives the masking FIXES — data positions are not commands.
// ---------------------------------------------------------------------------

test("FP fix: dangerous string in a git -m message is allowed", () => {
  assert.equal(blocks('git commit -m "docs: do not run rm -rf /"'), false);
  assert.equal(blocks("git commit -m 'cleanup: rm -rf / is dangerous'"), false);
  assert.equal(
    blocks('git commit --message="note: rm -rf ~ deletes home"'),
    false,
  );
  assert.equal(blocks('git tag -m "rm -rf / warning" v1'), false);
});

test("FP fix: arithmetic $((…)) is not a command context", () => {
  assert.equal(blocks("echo $((rm -rf /))"), false);
});

test("FP fix: echo/printf args are inert data", () => {
  assert.equal(blocks('echo "to wipe a dir: rm -rf /"'), false);
  assert.equal(blocks("printf '%s' 'rm -rf ~'"), false);
});

test("FP fix: a trailing comment is not executed", () => {
  // The rm targets a safe temp path; the comment merely mentions a dangerous one.
  assert.equal(
    blocks("rm -rf /tmp/build # be careful: rm -rf / nukes everything"),
    false,
  );
  assert.equal(blocks("ls -la # rm -rf / would be bad"), false);
});

test("FP fix: grep/search patterns are data", () => {
  assert.equal(blocks('grep -e "rm -rf /" log.txt'), false);
  assert.equal(blocks('git --grep="rm -rf /" log'), false);
});

// ---------------------------------------------------------------------------
// (B) SAFETY: masking must NOT create false negatives. Executed text stays.
// ---------------------------------------------------------------------------

test("SAFETY: command substitution in a -m value still blocks", () => {
  // $(...) inside the message EXECUTES — must not be masked.
  assert.ok(blocks('git commit -m "$(rm -rf /)"'));
});

test("SAFETY: command substitution as an echo arg still blocks", () => {
  assert.ok(blocks("echo $(rm -rf /)"));
});

test("SAFETY: command substitution NESTED in arithmetic still blocks", () => {
  assert.ok(blocks("echo $(( $(rm -rf /) ))"));
});

test("SAFETY: backticks in a data position still block", () => {
  assert.ok(blocks("echo `rm -rf /`"));
  assert.ok(blocks('git commit -m "`rm -rf /`"'));
});

test("SAFETY: a destructive redirect target is not masked", () => {
  assert.ok(blocks("echo x > /etc/passwd"));
  assert.ok(blocks("echo data>/etc/passwd"));
});

test("SAFETY: bash -c (an inline-code executor) is NOT a data command", () => {
  // bash is not in the data table, so its quoted script is scanned.
  assert.ok(blocks('bash -c "rm -rf /"'));
});

test("SAFETY: xargs -I masks only the replstr, not the executed command", () => {
  assert.ok(blocks("xargs -I {} rm -rf /"));
});

test("SAFETY: a real destructive command next to a safe data command still blocks", () => {
  assert.ok(blocks('git commit -m "safe message"; rm -rf /'));
  assert.ok(blocks("echo hello && rm -rf /"));
});

test("SAFETY(regression): a redirect inside a data-flag value is NOT masked", () => {
  // Adversarial FN family: bash word-breaks at the redirect, so these truncate a
  // sensitive file. The redirect operator + target must stay visible.
  assert.ok(blocks("git commit -mmsg>/etc/passwd"), "attached short -m");
  assert.ok(blocks("git commit -mmsg2>/etc/passwd"), "attached short -m + fd");
  assert.ok(blocks("git commit -m foo>/etc/passwd"), "separate -m value");
  assert.ok(blocks("git commit --message=m>/etc/passwd"), "long attached");
  assert.ok(blocks("git commit -mmsg>/etc/sudoers"), "sudoers target");
  assert.ok(blocks("gh issue create -tTitle>/etc/passwd"), "gh -t attached");
  assert.ok(blocks("grep -ePat>/etc/passwd f"), "grep -e attached");
  assert.ok(blocks("echo x>/etc/passwd"), "echo attached redirect");
});

test("FP fix(regression): a QUOTED > inside a data value is still masked", () => {
  // The redirect char is inside quotes (literal data), so the value — including a
  // dangerous mention — stays masked. No false positive.
  assert.equal(
    blocks('git commit -m "pipe output > log, then rm -rf /"'),
    false,
  );
  assert.equal(blocks('echo "redirect with > and rm -rf / mention"'), false);
});

// ---------------------------------------------------------------------------
// sanitizeForPatternMatching — unit behavior
// ---------------------------------------------------------------------------

test("sanitize: no-op (returns same string) for plain commands", () => {
  for (const cmd of [
    "rm -rf /",
    "git reset --hard",
    "ls -la",
    "kubectl delete pods --all",
  ]) {
    assert.equal(sanitizeForPatternMatching(cmd), cmd);
  }
});

test("sanitize: masks a git -m value but preserves length + structure", () => {
  const out = sanitizeForPatternMatching('git commit -m "rm -rf /"');
  assert.equal(
    out.length,
    'git commit -m "rm -rf /"'.length,
    "length preserved",
  );
  assert.ok(out.startsWith("git commit -m "), "command prefix intact");
  assert.doesNotMatch(out, /rm -rf \//, "the message content is blanked");
});

test("sanitize: does NOT mask a -m value containing command substitution", () => {
  const src = 'git commit -m "$(rm -rf /)"';
  assert.equal(
    sanitizeForPatternMatching(src),
    src,
    "executed text left intact",
  );
});

test("sanitize: masks a # comment to end of line only", () => {
  const out = sanitizeForPatternMatching("ls -la # rm -rf /\npwd");
  assert.ok(out.startsWith("ls -la "), "pre-comment intact");
  assert.doesNotMatch(out.split("\n")[0], /rm -rf/, "comment blanked");
  assert.equal(out.split("\n")[1], "pwd", "next line intact");
});
