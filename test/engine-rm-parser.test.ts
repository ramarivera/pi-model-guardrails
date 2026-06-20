// test/engine-rm-parser.test.ts
//
// Golden corpus for the rm-parser port, extracted from DCG
// src/packs/core/filesystem.rs #[test] blocks (parse_rm_command tests +
// sensitive-propagation tests). Exercises rmImperativeChecks (the public
// contract) plus parseRmCommand / isPreRmPropagationRule.

import assert from "node:assert/strict";
import test from "node:test";
import {
  isPreRmPropagationRule,
  parseRmCommand,
  rmImperativeChecks,
} from "../src/engine/rm-parser.ts";
import type { EngineDecision, SegmentContext } from "../src/engine/types.ts";

const CTX: SegmentContext = { raw: "", normalized: "" };

function parseTag(cmd: string): string {
  const d = parseRmCommand(cmd);
  if (d.kind === "deny") return `deny:${d.hit.patternName}:${d.hit.severity}`;
  return d.kind;
}

function runChain(cmd: string): EngineDecision | undefined {
  for (const fn of rmImperativeChecks) {
    const d = fn(CTX, cmd);
    if (d) return d;
  }
  return undefined;
}

function chainTag(cmd: string): string {
  const d = runChain(cmd);
  if (!d) return "undefined";
  if (d.decision === "deny") return `deny:${d.ruleName}:${d.severity}`;
  return d.decision;
}

// ---------------------------------------------------------------------------
// parseRmCommand decisions (direct)
// ---------------------------------------------------------------------------

test("rm parser allows temp-safe combined/separate/long flags", () => {
  // DCG test_safe_rm_tmp + test_safe_rm_variants
  for (const cmd of [
    "rm -rf /tmp/test",
    "rm -rf /var/tmp/stuff",
    "rm -rf $TMPDIR/junk",
    "rm -rf ${TMPDIR}/junk",
    "rm -fr /tmp/test",
    "rm -r -f /tmp/test",
    "rm --recursive --force /tmp/test",
  ]) {
    assert.equal(parseTag(cmd), "allow", cmd);
  }
});

test("rm parser allows quoted $TMPDIR only for combined flags", () => {
  // DCG test_rm_parser_allows_tmpdir_quotes
  assert.equal(parseTag('rm -rf "$TMPDIR/foo"'), "allow");
  assert.equal(parseTag('rm -rf "${TMPDIR}/foo"'), "allow");
  // single-quoted is never safe
  assert.equal(parseTag("rm -rf '$TMPDIR/foo'"), "deny:rm-rf-general:high");
  // double-quoted is unsafe for separate / long styles
  assert.equal(parseTag('rm -r -f "$TMPDIR/foo"'), "deny:rm-r-f-separate:high");
  assert.equal(
    parseTag('rm -r -f "${TMPDIR}/foo"'),
    "deny:rm-r-f-separate:high",
  );
  assert.equal(
    parseTag('rm --recursive --force "$TMPDIR/foo"'),
    "deny:rm-recursive-force-long:high",
  );
  assert.equal(
    parseTag('rm --recursive --force "${TMPDIR}/foo"'),
    "deny:rm-recursive-force-long:high",
  );
  assert.equal(
    parseTag('rm --force --recursive "$TMPDIR/foo"'),
    "deny:rm-recursive-force-long:high",
  );
  assert.equal(
    parseTag('rm --force --recursive "${TMPDIR}/foo"'),
    "deny:rm-recursive-force-long:high",
  );
});

test("rm parser: ${TMPDIR_NOT} is not a safe temp var", () => {
  // DCG test_tmpdir_brace_requires_exact_var_name
  assert.equal(
    parseTag("rm -rf ${TMPDIR_NOT}/junk"),
    "deny:rm-rf-general:high",
  );
});

test("rm parser: combined flags general High on non-temp paths", () => {
  // DCG test_rm_rf_general_high
  assert.equal(parseTag("rm -rf ./build"), "deny:rm-rf-general:high");
});

test("rm parser: separate / long flags general High on non-temp paths", () => {
  // DCG test_rm_separate_and_long_flag_root_is_critical (non-root tail)
  assert.equal(parseTag("rm -r -f ./build"), "deny:rm-r-f-separate:high");
  assert.equal(parseTag("rm -f -r ./build"), "deny:rm-r-f-separate:high");
  assert.equal(
    parseTag("rm --recursive --force ./build"),
    "deny:rm-recursive-force-long:high",
  );
  assert.equal(
    parseTag("rm --force --recursive ./build"),
    "deny:rm-recursive-force-long:high",
  );
});

test("rm parser: combined-flag root/home is Critical (quoted/escaped/$HOME)", () => {
  // DCG test_rm_rf_root_critical + test_rm_separate_and_long_flag_root_is_critical
  for (const cmd of [
    "rm -rf /",
    "rm -rf /etc",
    "rm -rf /home",
    "rm -rf ~/",
    'rm -rf "/"',
    "rm -rf '/'",
    'rm -rf "~/"',
    "rm -rf '/etc'",
    "rm -rf \\/",
    "rm -rf \\~",
    "rm -rf $HOME",
    'rm -rf "$HOME"',
    "rm -rf ${HOME}",
    'rm -rf "${HOME}"',
    "rm -rf /tmp/cache /etc",
  ]) {
    assert.equal(parseTag(cmd), "deny:rm-rf-root-home:critical", cmd);
  }
});

test("rm parser: separate-flag root/home is Critical", () => {
  for (const cmd of [
    "rm -r -f /",
    "rm -f -r /",
    "rm -r -f /etc",
    "rm -r -f ~/",
    'rm -r -f "/"',
    "rm -r -f \\/",
    "rm -r -f $HOME",
  ]) {
    assert.equal(parseTag(cmd), "deny:rm-r-f-separate-root-home:critical", cmd);
  }
});

test("rm parser: long-flag root/home is Critical", () => {
  for (const cmd of [
    "rm --recursive --force /",
    "rm --force --recursive /",
    "rm --recursive --force /etc",
    "rm --recursive --force '/'",
    "rm --recursive --force \\/",
    "rm --recursive --force $HOME",
  ]) {
    assert.equal(
      parseTag(cmd),
      "deny:rm-recursive-force-root-home:critical",
      cmd,
    );
  }
});

test("rm parser: parent-dir traversal is NOT temp-safe (Critical via leading /)", () => {
  // DCG test_rm_parser_traversal_blocked + test_path_traversal_blocked
  assert.equal(parseTag("rm -rf /tmp/../etc"), "deny:rm-rf-root-home:critical");
  assert.equal(
    parseTag("rm -rf /var/tmp/../etc"),
    "deny:rm-rf-root-home:critical",
  );
});

test("rm parser: trailing redirections do not break temp-safe allow", () => {
  // DCG test_rm_rf_tmp_with_trailing_redirections_is_safe (safe cases)
  for (const cmd of [
    "rm -rf /tmp/sigtest* 2>/dev/null",
    "rm -rf /tmp/sigtest* /tmp/tardis-test /tmp/tardis-bench 2>/dev/null",
    "rm -rf /tmp/foo > /tmp/log.txt",
    "rm -rf /tmp/foo > /tmp/log.txt 2>&1",
    "rm -rf /tmp/foo &>/dev/null",
    "rm -rf /tmp/foo &>> /tmp/audit.log",
    "rm -rf /var/tmp/foo 2>/dev/null",
    "rm -r -f /tmp/foo 2>/dev/null",
    "rm -f -r /tmp/foo 2>/dev/null",
    "rm --recursive --force /tmp/foo 2>/dev/null",
  ]) {
    assert.equal(parseTag(cmd), "allow", cmd);
  }
});

test("rm parser: trailing redirections do not mask a dangerous path", () => {
  // DCG test_rm_rf_tmp_with_trailing_redirections_is_safe (unsafe cases)
  for (const cmd of [
    "rm -rf /etc 2>/dev/null",
    "rm -rf /tmp/ok /etc 2>/dev/null",
    "rm -rf / 2>/dev/null",
  ]) {
    assert.equal(parseTag(cmd).startsWith("deny:"), true, cmd);
  }
});

test("rm parser: compound segments aggregate (Allow if any safe, else carry deny)", () => {
  // DCG test_rm_parser_handles_compound_segments
  assert.equal(parseTag("cp -al /tmp/a /tmp/b && rm -rf /tmp/b"), "allow");
  assert.equal(
    parseTag("echo ok && rm -rf ./build"),
    "deny:rm-rf-general:high",
  );
});

test("rm parser: option terminator (--) handling", () => {
  // DCG test_rm_parser_option_terminator
  // `--` BEFORE flags: -rf becomes a path; no recursive/force flags -> NoMatch.
  assert.equal(parseTag("rm -- -rf /tmp/safe"), "noMatch");
  // `--` AFTER flags: saw_terminator disables the temp-safe allow -> general.
  assert.equal(parseTag("rm -rf -- /tmp/safe"), "deny:rm-rf-general:high");
  assert.equal(parseTag("rm -rf -- /"), "deny:rm-rf-root-home:critical");
  assert.equal(
    parseTag("rm -r -f -- /"),
    "deny:rm-r-f-separate-root-home:critical",
  );
  assert.equal(
    parseTag("rm --recursive --force -- /"),
    "deny:rm-recursive-force-root-home:critical",
  );
});

test("rm parser: no rm command -> noMatch", () => {
  assert.equal(parseTag("ls /etc"), "noMatch");
  assert.equal(parseTag("echo rm -rf /"), "noMatch"); // rm is an arg, not the command word
});

// ---------------------------------------------------------------------------
// rmImperativeChecks chain (removalCheck then cpLnRsyncPropagationCheck)
// ---------------------------------------------------------------------------

test("chain: removalCheck denies catastrophic rm", () => {
  assert.equal(chainTag("rm -rf /"), "deny:rm-rf-root-home:critical");
  assert.equal(
    chainTag("rm -r -f /"),
    "deny:rm-r-f-separate-root-home:critical",
  );
  assert.equal(
    chainTag("rm --recursive --force /"),
    "deny:rm-recursive-force-root-home:critical",
  );
  assert.equal(chainTag("rm -rf ./build"), "deny:rm-rf-general:high");
});

test("chain: removalCheck allows temp-safe rm", () => {
  const d = runChain("rm -rf /tmp/test");
  assert.ok(d);
  assert.equal(d?.decision, "allow");
  assert.equal(d?.blocked, false);
});

test("chain: sensitive cp/ln/rsync propagation then delete is Critical", () => {
  // DCG sensitive_propagation_then_delete_blocks_critical
  const cases: [string, string][] = [
    ["cp -al /etc /tmp/x && rm -rf /tmp/x", "cp-sensitive-then-delete"],
    [
      "cp --archive /etc/passwd /tmp/passwd && rm -fr /tmp/passwd",
      "cp-sensitive-then-delete",
    ],
    [
      "sudo cp -a /home/user/.ssh /var/tmp/keys && rm --recursive --force /var/tmp/keys",
      "cp-sensitive-then-delete",
    ],
    [
      "ln -s /etc /tmp/x && rm -rf /tmp/x/.",
      "ln-symlink-sensitive-then-delete",
    ],
    [
      "ln -sf $HOME /tmp/home && rm -rf /tmp/home/.",
      "ln-symlink-sensitive-then-delete",
    ],
    [
      "rsync -a /etc/ /tmp/dest/ && rm -rf /tmp/dest",
      "rsync-sensitive-then-delete",
    ],
    [
      "rsync --archive /home/user/ /var/tmp/home/ && rm -f -r /var/tmp/home",
      "rsync-sensitive-then-delete",
    ],
  ];
  for (const [cmd, rule] of cases) {
    assert.equal(chainTag(cmd), `deny:${rule}:critical`, cmd);
  }
});

test("chain: NEWLINE-separated propagation then delete is Critical (FN fix)", () => {
  // DCG's upstream separator alternation is (?:&&|;|\|\|) — it MISSES a newline
  // separator, a real false negative. A newline is a statement separator like
  // `;`, so these must deny just like the && forms above.
  const cases: [string, string][] = [
    ["cp -a /etc/ssh /tmp/x\nrm -rf /tmp/x", "cp-sensitive-then-delete"],
    ["cp -a /etc/ssh /tmp/x\r\nrm -rf /tmp/x", "cp-sensitive-then-delete"],
    ["cp -a /etc/ssh /tmp/x\n  rm -rf /tmp/x", "cp-sensitive-then-delete"],
    ["ln -s /etc /tmp/x\nrm -rf /tmp/x/.", "ln-symlink-sensitive-then-delete"],
    ["rsync -a /etc/ /tmp/dest/\nrm -rf /tmp/dest", "rsync-sensitive-then-delete"],
  ];
  for (const [cmd, rule] of cases) {
    assert.equal(chainTag(cmd), `deny:${rule}:critical`, JSON.stringify(cmd));
  }
  // Negative control: a benign newline-separated pair must NOT deny.
  assert.equal(
    chainTag("cp -a /tmp/a /tmp/b\nls /tmp").startsWith("deny:"),
    false,
  );
});

test("chain: propagation WITHOUT delete is not blocked", () => {
  // DCG sensitive_propagation_without_delete_is_allowed
  for (const cmd of [
    "cp -a /etc /tmp/x",
    "cp --archive /etc/passwd /tmp/passwd",
    "ln -s /etc /tmp/x",
    "rsync -a /etc/ /tmp/dest/",
  ]) {
    const tag = chainTag(cmd);
    assert.equal(tag.startsWith("deny:"), false, `${cmd} -> ${tag}`);
  }
});

test("chain: non-sensitive propagation then delete is allowed", () => {
  // DCG non_sensitive_propagation_then_delete_is_allowed
  for (const cmd of [
    "cp -al /tmp/a /tmp/b && rm -rf /tmp/b",
    "cp --archive ./build /tmp/build && rm -fr /tmp/build",
    "ln -s /tmp/a /tmp/b && rm -rf /tmp/b/.",
    "rsync -a ./target/ /tmp/target/ && rm -rf /tmp/target",
  ]) {
    const tag = chainTag(cmd);
    assert.equal(tag.startsWith("deny:"), false, `${cmd} -> ${tag}`);
  }
});

test("chain: propagation deny wins even when the trailing rm targets a safe temp path", () => {
  // Faithfulness regression: rm-parse Allow must NOT mask a propagation match.
  assert.equal(
    chainTag("cp -al /etc /tmp/x && rm -rf /tmp/x"),
    "deny:cp-sensitive-then-delete:critical",
  );
});

test("isPreRmPropagationRule recognizes the three propagation rule names", () => {
  assert.equal(isPreRmPropagationRule("cp-sensitive-then-delete"), true);
  assert.equal(
    isPreRmPropagationRule("ln-symlink-sensitive-then-delete"),
    true,
  );
  assert.equal(isPreRmPropagationRule("rsync-sensitive-then-delete"), true);
  assert.equal(isPreRmPropagationRule("rm-rf-general"), false);
  assert.equal(isPreRmPropagationRule(undefined), false);
});
