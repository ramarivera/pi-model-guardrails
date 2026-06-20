// Tier-3 indirection resolver tests — aliased-sink detection.
//
// Two layers:
//   1. resolveIndirection() unit tests — pure expansion, no engine.
//   2. evaluateCommand() integration — an aliased/var-hidden destructive sink is
//      caught by the SAME regex rule that catches the bare form, and benign
//      indirection does NOT produce a false positive.
//
// The destructive strings here are TEST FIXTURES in a source file, not shell
// commands being executed.

import assert from "node:assert/strict";
import test from "node:test";

import { evaluateCommand } from "../src/engine/evaluate.ts";
import { resolveIndirection } from "../src/engine/indirection.ts";
import { coreFilesystemPack } from "../src/engine/packs/core-filesystem.ts";
import { coreGitPack } from "../src/engine/packs/core-git.ts";
import { buildRegistry } from "../src/engine/registry.ts";

const registry = buildRegistry([coreGitPack, coreFilesystemPack]);

function blocks(cmd: string): boolean {
  return evaluateCommand(cmd, registry).blocked === true;
}

function reasonOf(cmd: string): string {
  return evaluateCommand(cmd, registry).reason ?? "";
}

// ---------------------------------------------------------------------------
// resolveIndirection() — unit
// ---------------------------------------------------------------------------

test("resolveIndirection: variable indirection expands $x", () => {
  const r = resolveIndirection("x=rm; $x -rf /tmp/data");
  assert.ok(r, "indirection detected");
  assert.match(r.expanded, /\brm -rf \/tmp\/data\b/);
  assert.ok(r.notes.includes("variable"));
});

test("resolveIndirection: braced dollar-brace form", () => {
  const r = resolveIndirection("x=rm; ${x} -rf /tmp/data");
  assert.ok(r);
  assert.match(r.expanded, /\brm -rf \/tmp\/data\b/);
});

test("resolveIndirection: alias expansion", () => {
  const r = resolveIndirection("alias nuke='rm -rf'; nuke /tmp/data");
  assert.ok(r);
  assert.match(r.expanded, /\brm -rf \/tmp\/data\b/);
  assert.ok(r.notes.includes("alias"));
});

test("resolveIndirection: multi-word var value word-splits on use", () => {
  const r = resolveIndirection('d="rm -rf"; $d /tmp/data');
  assert.ok(r);
  assert.match(r.expanded, /\brm -rf \/tmp\/data\b/);
});

test("resolveIndirection: chained vars (verb + flag)", () => {
  const r = resolveIndirection("r=rm; f=-rf; $r $f /tmp/data");
  assert.ok(r);
  assert.match(r.expanded, /\brm -rf \/tmp\/data\b/);
});

test("resolveIndirection: backslashed alias key (\\d)", () => {
  const r = resolveIndirection("alias d='rm -rf'; \\d /tmp/data");
  assert.ok(r);
  assert.match(r.expanded, /\brm -rf\b/);
});

test("resolveIndirection: no markers -> undefined", () => {
  assert.equal(resolveIndirection("rm -rf /tmp/data"), undefined);
  assert.equal(resolveIndirection("ls -la"), undefined);
  // A bare $x with no assignment is not resolvable.
  assert.equal(resolveIndirection("$x -rf /tmp/data"), undefined);
});

test("resolveIndirection: single-quoted ref is NOT expanded", () => {
  // echo '$x ...' is literal in bash; we must not substitute inside '...'.
  const r = resolveIndirection("x=rm; echo '$x -rf /tmp/data'");
  // Either no change reported, or the quoted $x survives verbatim.
  if (r) assert.match(r.expanded, /'\$x -rf \/tmp\/data'/);
});

test("resolveIndirection: alias cycle is bounded (no hang)", () => {
  const r = resolveIndirection("alias a='b'; alias b='a'; a /tmp/data");
  // Terminates; whatever it returns, it must not loop forever (test completing
  // IS the assertion) and must not fabricate a destructive verb.
  if (r) assert.doesNotMatch(r.expanded, /\brm\b/);
});

// ---------------------------------------------------------------------------
// evaluateCommand() — integration: the sink is caught, benign cases are not
// ---------------------------------------------------------------------------

// NOTE on targets: `rm -rf /tmp/...` is in the engine's SAFE allowlist (normal
// temp cleanup), so it does NOT block — by design (DCG parity). To prove the
// resolver, the EXPANSION must land on a genuinely-blocked target (root/home),
// and the indirection must hide the VERB (`x=rm`) so the assignment text itself
// carries no matchable `rm -rf` substring — otherwise the block could come from
// the general rule matching the literal in the assignment, not from resolution.

test("integration: var-hidden (verb-only) rm -rf ~ is blocked via resolution", () => {
  // `x=rm` has no `rm -rf` substring; only the resolved `rm -rf ~` matches.
  assert.ok(blocks("x=rm; $x -rf ~"));
  assert.match(reasonOf("x=rm; $x -rf ~"), /indirection/);
});

test("integration: alias verb expansion is blocked via resolution", () => {
  // `alias d=rm` carries no matchable substring; only resolved `rm -rf ~` does.
  assert.ok(blocks("alias d=rm; d -rf ~"));
  assert.match(reasonOf("alias d=rm; d -rf ~"), /alias/);
});

test("integration: var-hidden git reset --hard is blocked", () => {
  assert.ok(blocks("g=git; $g reset --hard HEAD~1"));
  assert.match(reasonOf("g=git; $g reset --hard HEAD~1"), /indirection/);
});

test("integration: bare destructive still blocked (no regression, not via resolver)", () => {
  assert.ok(blocks("rm -rf ~"));
  // The bare form is caught by the main pass, so it is NOT annotated.
  assert.doesNotMatch(reasonOf("rm -rf ~"), /indirection/);
});

test("integration: benign indirection is NOT a false positive", () => {
  assert.equal(blocks("msg=hello; echo $msg"), false);
  assert.equal(blocks("dir=/tmp; ls $dir"), false);
  // single-quoted destructive text in an echo is literal, not executed.
  assert.equal(blocks("x=rm; echo '$x -rf ~'"), false);
  // unknown var expands to empty -> harmless.
  assert.equal(blocks("$unknown -rf ~"), false);
  // verb-only var resolving to a SAFE temp deletion stays allowed (DCG parity).
  assert.equal(blocks("x=rm; $x -rf /tmp/scratch"), false);
});

test("integration: resolver never downgrades an already-blocked command", () => {
  // A real destructive sink plus a benign assignment: still blocked.
  assert.ok(blocks("rm -rf ~; x=ls; $x"));
});

// ---------------------------------------------------------------------------
// Adversarial-review regressions.
//   Round 1 (bypass hunt): keyword-built-from-concatenation must NOT be
//     quick-rejected before the Tier-3 pass runs.
//   Round 2 (FP hunt): indirection in ARGUMENT position (echo/printf/true args)
//     must NOT be escalated to a block — only an executed SINK head counts.
// ---------------------------------------------------------------------------

test("regression(bypass): verb built by concatenation is blocked", () => {
  // `a=r; b=m; $a$b -rf ~` — no literal `rm` substring anywhere, so the
  // candidate-pack quick-reject is empty; the Tier-3 pass must still fire.
  assert.ok(blocks("a=r; b=m; $a$b -rf ~"));
  assert.match(reasonOf("a=r; b=m; $a$b -rf ~"), /indirection/);
});

test("regression(bypass): partial-var verb concatenation is blocked", () => {
  assert.ok(blocks("x=m; r${x} -rf /etc"));
  assert.ok(blocks("x=gi; y=t; $x$y reset --hard HEAD~1"));
});

test("regression(bypass): one level of value indirection (b=$a)", () => {
  assert.ok(blocks("a=rm; b=$a; $b -rf ~"));
});

test("regression(FP): destructive-looking ARGS to an inert command are NOT blocked", () => {
  // The verb lands in echo/printf/true ARG position — a print, not a sink.
  assert.equal(blocks("v=rm; o=-rf; t=~; echo $v $o $t"), false);
  assert.equal(blocks("v=rm; o=-rf; printf '%s %s %s' $v $o ~"), false);
  assert.equal(blocks("g=git; true $g reset --hard HEAD~1"), false);
  assert.equal(
    blocks('verb=rm; opt=-rf; tgt=~; echo "Do not run: $verb $opt $tgt"'),
    false,
  );
});

test("regression(FP): a real sink in the SAME command still blocks", () => {
  // echo-arg expansion is inert, but the trailing `$v $o ~` IS an executed sink.
  assert.ok(blocks("v=rm; o=-rf; echo $v $o ~; $v $o ~"));
});
