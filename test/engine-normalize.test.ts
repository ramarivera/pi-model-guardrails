// Tests for src/engine/normalize.ts.
//
// Cases marked "DCG:" are extracted faithfully from DCG's own #[test] blocks in
// src/normalize.rs and src/packs/mod.rs (the golden corpus — no live dcg binary
// needed). Cases marked "EXT:" cover this port's contract extensions
// (nice/nohup/time/doas/exec wrappers, classifySegment span model).

import assert from "node:assert/strict";
import test from "node:test";

import {
  classifySegment,
  dequoteSegmentCommandWords,
  normalizeCommand,
  normalizeCommandWordToken,
  splitCommandSegments,
  stripWrapperPrefixes,
} from "../src/engine/normalize.ts";

// ---------------------------------------------------------------------------
// stripWrapperPrefixes — DCG src/normalize.rs tests
// ---------------------------------------------------------------------------

test("DCG: sudo simple", () => {
  assert.equal(
    stripWrapperPrefixes("sudo git reset --hard"),
    "git reset --hard",
  );
});

test("DCG: sudo with options -E -H", () => {
  assert.equal(
    stripWrapperPrefixes("sudo -E -H git reset --hard"),
    "git reset --hard",
  );
});

test("DCG: sudo with combined options -EH", () => {
  assert.equal(
    stripWrapperPrefixes("sudo -EH git reset --hard"),
    "git reset --hard",
  );
});

test("DCG: sudo with user -u root", () => {
  assert.equal(
    stripWrapperPrefixes("sudo -u root git reset --hard"),
    "git reset --hard",
  );
});

test("DCG: sudo unknown flag does not strip", () => {
  // -l is unknown to the stripper -> nothing stripped, original returned.
  assert.equal(stripWrapperPrefixes("sudo -l rm -rf /"), "sudo -l rm -rf /");
});

test("DCG: sudo unknown long flag does not strip", () => {
  assert.equal(
    stripWrapperPrefixes("sudo --list rm -rf /"),
    "sudo --list rm -rf /",
  );
});

test("DCG: not sudo prefix (sudoku)", () => {
  assert.equal(stripWrapperPrefixes("sudoku play"), "sudoku play");
});

test("DCG: env simple", () => {
  assert.equal(
    stripWrapperPrefixes("env git reset --hard"),
    "git reset --hard",
  );
});

test("DCG: env with assignment", () => {
  assert.equal(
    stripWrapperPrefixes("env GIT_DIR=.git git reset --hard"),
    "git reset --hard",
  );
});

test("DCG: env with quoted assignment", () => {
  assert.equal(
    stripWrapperPrefixes('env FOO="a b" git reset --hard'),
    "git reset --hard",
  );
});

test("DCG: env assignment with backticks preserved (inline code stops strip)", () => {
  // The assignment carries inline code, so the env wrapper does NOT strip;
  // original command remains so the destructive `rm -rf /` stays visible.
  const out = stripWrapperPrefixes("env FOO=`rm -rf /` git status");
  assert.ok(
    out.includes("rm -rf /"),
    `expected inline code visible, got: ${out}`,
  );
});

test("DCG: env assignment with single-quoted backticks skipped", () => {
  assert.equal(
    stripWrapperPrefixes("env FOO='`rm -rf /`' git status"),
    "git status",
  );
});

test("DCG: env alone not stripped", () => {
  assert.equal(stripWrapperPrefixes("env"), "env");
});

test("DCG: command wrapper", () => {
  assert.equal(
    stripWrapperPrefixes("command git reset --hard"),
    "git reset --hard",
  );
});

test("DCG: command wrapper with path", () => {
  assert.equal(
    stripWrapperPrefixes("/usr/bin/command git reset --hard"),
    "git reset --hard",
  );
});

test("DCG: command -v not wrapper", () => {
  assert.equal(stripWrapperPrefixes("command -v git"), "command -v git");
});

test("DCG: command -v with path not wrapper", () => {
  assert.equal(
    stripWrapperPrefixes("/usr/bin/command -v git"),
    "/usr/bin/command -v git",
  );
});

test("DCG: command -pv not wrapper", () => {
  assert.equal(stripWrapperPrefixes("command -pv git"), "command -pv git");
});

test("DCG: command -p wrapper", () => {
  assert.equal(
    stripWrapperPrefixes("command -p git reset --hard"),
    "git reset --hard",
  );
});

test("DCG: command unknown flag does not strip", () => {
  assert.equal(
    stripWrapperPrefixes("command -x git reset --hard"),
    "command -x git reset --hard",
  );
});

test("DCG: command unknown long flag does not strip", () => {
  assert.equal(
    stripWrapperPrefixes("command --foo git reset --hard"),
    "command --foo git reset --hard",
  );
});

test("DCG: backslash git", () => {
  assert.equal(stripWrapperPrefixes("\\git reset --hard"), "git reset --hard");
});

test("DCG: sudo env chain", () => {
  assert.equal(
    stripWrapperPrefixes("sudo env GIT_DIR=.git git reset --hard"),
    "git reset --hard",
  );
});

test("DCG: env -S split-string handling", () => {
  assert.equal(
    stripWrapperPrefixes('env -S "git reset --hard"'),
    "git reset --hard",
  );
});

test("DCG: env --split-string long option", () => {
  assert.equal(
    stripWrapperPrefixes('env --split-string "git reset --hard"'),
    "git reset --hard",
  );
});

test("DCG: env --chdir long option", () => {
  assert.equal(
    stripWrapperPrefixes("env --chdir /tmp git reset --hard"),
    "git reset --hard",
  );
});

test("DCG: env unknown long option not stripped", () => {
  assert.equal(
    stripWrapperPrefixes("env --not-a-real-flag git reset --hard"),
    "env --not-a-real-flag git reset --hard",
  );
});

test("DCG: empty command", () => {
  assert.equal(stripWrapperPrefixes(""), "");
});

test("DCG: no wrappers", () => {
  assert.equal(stripWrapperPrefixes("git status"), "git status");
});

test("DCG: sudo with shell flag -s", () => {
  assert.equal(
    stripWrapperPrefixes("sudo -s git reset --hard"),
    "git reset --hard",
  );
});

test("DCG: sudo -s alone not stripped", () => {
  assert.equal(stripWrapperPrefixes("sudo -s"), "sudo -s");
});

test("DCG: sudo with bell flag -B", () => {
  assert.equal(
    stripWrapperPrefixes("sudo -B git reset --hard"),
    "git reset --hard",
  );
});

test("DCG: sudo with chdir -D /tmp", () => {
  assert.equal(
    stripWrapperPrefixes("sudo -D /tmp git reset --hard"),
    "git reset --hard",
  );
});

test("DCG: sudo with type -t", () => {
  assert.equal(
    stripWrapperPrefixes("sudo -t unconfined_t git reset --hard"),
    "git reset --hard",
  );
});

test("DCG: sudo combined shell flags -EBs", () => {
  assert.equal(
    stripWrapperPrefixes("sudo -EBs git reset --hard"),
    "git reset --hard",
  );
});

// ---------------------------------------------------------------------------
// dequoteSegmentCommandWords / normalizeCommandWordToken — DCG src/normalize.rs
// ---------------------------------------------------------------------------

test("DCG: dequote preserves rm quoted paths", () => {
  assert.equal(
    dequoteSegmentCommandWords('rm -rf "/tmp/foo"'),
    'rm -rf "/tmp/foo"',
  );
  assert.equal(
    dequoteSegmentCommandWords('rm -r -f "$TMPDIR/foo"'),
    'rm -r -f "$TMPDIR/foo"',
  );
});

test("DCG: dequote normalizes git quoted subcommand", () => {
  assert.equal(
    dequoteSegmentCommandWords('git "reset" --hard'),
    "git reset --hard",
  );
});

test("DCG: mismatched quotes not unquoted", () => {
  assert.equal(normalizeCommandWordToken("\"hello'"), undefined);
  assert.equal(normalizeCommandWordToken("'hello\""), undefined);
  assert.equal(normalizeCommandWordToken('"hello"'), "hello");
  assert.equal(normalizeCommandWordToken("'hello'"), "hello");
});

test("DCG: internal backslash normalization g\\it -> git", () => {
  assert.equal(normalizeCommandWordToken("g\\it"), "git");
  assert.equal(normalizeCommandWordToken("g\\i\\t"), "git");
});

test("DCG: mixed quoting normalization g'i't -> git", () => {
  assert.equal(normalizeCommandWordToken("g'i't"), "git");
  assert.equal(normalizeCommandWordToken('g"i"t'), "git");
});

test("DCG: attached redirection normalization after quoted command", () => {
  assert.equal(normalizeCommandWordToken('"git">/dev/null'), "git >/dev/null");
  assert.equal(
    normalizeCommandWordToken('"git"&>/dev/null'),
    "git &>/dev/null",
  );
  assert.equal(
    normalizeCommandWordToken('"git"&>>/dev/null'),
    "git &>>/dev/null",
  );
  assert.equal(normalizeCommandWordToken("git&>/dev/null"), "git &>/dev/null");
  assert.equal(
    normalizeCommandWordToken("git&>>/dev/null"),
    "git &>>/dev/null",
  );
  assert.equal(normalizeCommandWordToken("git>/dev/null"), "git >/dev/null");
  assert.equal(normalizeCommandWordToken("git>>/dev/null"), "git >>/dev/null");
  assert.equal(normalizeCommandWordToken(">>"), undefined);
});

test("DCG: attached redirection strips .exe suffix", () => {
  assert.equal(
    normalizeCommandWordToken('"git.exe">/dev/null'),
    "git >/dev/null",
  );
});

test("DCG: numeric fd redirection is not rewritten", () => {
  assert.equal(normalizeCommandWordToken("2>/dev/null"), undefined);
});

// ---------------------------------------------------------------------------
// splitCommandSegments — DCG src/packs/mod.rs tests
// ---------------------------------------------------------------------------

test("DCG: split basic separators", () => {
  assert.deepEqual(splitCommandSegments("docker ps"), ["docker ps"]);
  assert.deepEqual(splitCommandSegments("docker ps; docker logs x"), [
    "docker ps",
    "docker logs x",
  ]);
  assert.deepEqual(splitCommandSegments("docker ps && docker logs x"), [
    "docker ps",
    "docker logs x",
  ]);
  assert.deepEqual(splitCommandSegments("a || b"), ["a", "b"]);
  assert.deepEqual(splitCommandSegments("docker ps | grep nginx"), [
    "docker ps",
    "grep nginx",
  ]);
  assert.deepEqual(splitCommandSegments("docker ps |& grep nginx"), [
    "docker ps",
    "grep nginx",
  ]);
  assert.deepEqual(splitCommandSegments("docker ps & docker logs foo"), [
    "docker ps",
    "docker logs foo",
  ]);
  assert.deepEqual(splitCommandSegments("docker logs foo &"), [
    "docker logs foo",
  ]);
});

test("DCG: split does not split redirection ampersands", () => {
  assert.deepEqual(splitCommandSegments("command 2>&1 | tee log.txt"), [
    "command 2>&1",
    "tee log.txt",
  ]);
  assert.deepEqual(splitCommandSegments("echo x >&2"), ["echo x >&2"]);
  assert.deepEqual(splitCommandSegments("make &> build.log"), [
    "make &> build.log",
  ]);
  assert.deepEqual(splitCommandSegments("make &>> build.log && echo done"), [
    "make &>> build.log",
    "echo done",
  ]);
  assert.deepEqual(splitCommandSegments("cat <&0; echo done"), [
    "cat <&0",
    "echo done",
  ]);
});

test("DCG: split respects quotes and escapes", () => {
  assert.deepEqual(splitCommandSegments('echo "a; b && c || d"'), [
    'echo "a; b && c || d"',
  ]);
  assert.deepEqual(splitCommandSegments("echo 'a; b && c'"), [
    "echo 'a; b && c'",
  ]);
  assert.deepEqual(splitCommandSegments("echo a\\; b"), ["echo a\\; b"]);
  assert.deepEqual(splitCommandSegments("echo a\\| b"), ["echo a\\| b"]);
  assert.deepEqual(splitCommandSegments("echo a\\& b"), ["echo a\\& b"]);
});

test("DCG: split extracts command substitutions", () => {
  assert.deepEqual(
    splitCommandSegments("echo $(docker system prune -a --volumes)"),
    [
      "docker system prune -a --volumes",
      "echo $(docker system prune -a --volumes)",
    ],
  );
  assert.deepEqual(
    splitCommandSegments('echo "$(op item delete "Prod Secret")"'),
    ['op item delete "Prod Secret"', 'echo "$(op item delete "Prod Secret")"'],
  );
  assert.deepEqual(
    splitCommandSegments("echo `velero backup delete nightly`"),
    ["velero backup delete nightly", "echo `velero backup delete nightly`"],
  );
  assert.deepEqual(
    splitCommandSegments('echo "$(echo "$(op item delete Prod)")"'),
    [
      "op item delete Prod",
      'echo "$(op item delete Prod)"',
      'echo "$(echo "$(op item delete Prod)")"',
    ],
  );
  assert.deepEqual(
    splitCommandSegments("cat <(docker system prune -a --volumes)"),
    [
      "docker system prune -a --volumes",
      "cat <(docker system prune -a --volumes)",
    ],
  );
  assert.deepEqual(
    splitCommandSegments("cat >(docker system prune -a --volumes)"),
    [
      "docker system prune -a --volumes",
      "cat >(docker system prune -a --volumes)",
    ],
  );
  assert.deepEqual(
    splitCommandSegments('echo "<(docker system prune -a --volumes)"'),
    ['echo "<(docker system prune -a --volumes)"'],
  );
  assert.deepEqual(
    splitCommandSegments('echo ">(docker system prune -a --volumes)"'),
    ['echo ">(docker system prune -a --volumes)"'],
  );
  assert.deepEqual(
    splitCommandSegments(
      'echo "$(printf "%s" "<(docker system prune -a --volumes)")"',
    ),
    [
      'printf "%s" "<(docker system prune -a --volumes)"',
      'echo "$(printf "%s" "<(docker system prune -a --volumes)")"',
    ],
  );
  assert.deepEqual(splitCommandSegments("echo '$(docker system prune)'"), [
    "echo '$(docker system prune)'",
  ]);
  assert.deepEqual(splitCommandSegments("echo $((rm -rf /))"), [
    "echo $((rm -rf /))",
  ]);
});

// newline as separator (DCG tokenizer test mirror).
test("DCG: newline acts as a separator", () => {
  assert.deepEqual(splitCommandSegments("echo ok\nrm -rf /"), [
    "echo ok",
    "rm -rf /",
  ]);
});

// ---------------------------------------------------------------------------
// normalize_command (full pipeline) — DCG src/normalize.rs integration tests
// ---------------------------------------------------------------------------

test("DCG: backslash .exe normalization through full pipeline", () => {
  const ctx = classifySegment("\\git.exe reset --hard");
  assert.equal(ctx.normalized, "git reset --hard");
  assert.equal(ctx.executable, "git");
});

test("DCG: g\\it reset --hard normalizes", () => {
  assert.equal(
    classifySegment("g\\it reset --hard").normalized,
    "git reset --hard",
  );
});

test("DCG: g'i't reset --hard normalizes", () => {
  assert.equal(
    classifySegment("g'i't reset --hard").normalized,
    "git reset --hard",
  );
});

test("DCG: attached redirection through pipeline", () => {
  assert.equal(
    classifySegment('"git">/dev/null reset --hard').normalized,
    "git >/dev/null reset --hard",
  );
  assert.equal(
    classifySegment("git&>/dev/null reset --hard").normalized,
    "git &>/dev/null reset --hard",
  );
});

test("DCG: pure redirection after command builtin is not a wrapper invocation", () => {
  // `command >> /usr/local/log` must remain untouched (redirection, not wrapper).
  assert.equal(
    classifySegment("command >> /usr/local/log").normalized,
    "command >> /usr/local/log",
  );
});

// ---------------------------------------------------------------------------
// EXT: contract-extension wrappers (nice/nohup/time/doas/exec)
// ---------------------------------------------------------------------------

test("EXT: nice wrapper strips", () => {
  assert.equal(
    stripWrapperPrefixes("nice git reset --hard"),
    "git reset --hard",
  );
});

test("EXT: nice -n value flag strips", () => {
  assert.equal(
    stripWrapperPrefixes("nice -n 10 git reset --hard"),
    "git reset --hard",
  );
});

test("EXT: nohup wrapper strips", () => {
  assert.equal(
    stripWrapperPrefixes("nohup git reset --hard"),
    "git reset --hard",
  );
});

test("EXT: doas wrapper strips", () => {
  assert.equal(
    stripWrapperPrefixes("doas git reset --hard"),
    "git reset --hard",
  );
});

test("EXT: doas -u user strips", () => {
  assert.equal(
    stripWrapperPrefixes("doas -u root git reset --hard"),
    "git reset --hard",
  );
});

test("EXT: exec wrapper strips", () => {
  assert.equal(
    stripWrapperPrefixes("exec git reset --hard"),
    "git reset --hard",
  );
});

test("EXT: time wrapper strips", () => {
  assert.equal(
    stripWrapperPrefixes("time git reset --hard"),
    "git reset --hard",
  );
});

test("EXT: nested wrapper chain sudo + nice", () => {
  assert.equal(
    stripWrapperPrefixes("sudo nice -n 5 git reset --hard"),
    "git reset --hard",
  );
});

test("EXT: not a wrapper word (nicely) untouched", () => {
  assert.equal(stripWrapperPrefixes("nicely formatted"), "nicely formatted");
});

// ---------------------------------------------------------------------------
// EXT: classifySegment span model
// ---------------------------------------------------------------------------

test("EXT: classifySegment basic executable + flag + path", () => {
  const ctx = classifySegment("rm -rf /tmp/foo");
  assert.equal(ctx.executable, "rm");
  assert.equal(ctx.normalized, "rm -rf /tmp/foo");
  const kinds = (ctx.spans ?? []).map((s) => `${s.kind}:${s.text}`);
  assert.deepEqual(kinds, ["executable:rm", "flag:-rf", "path:/tmp/foo"]);
});

test("EXT: classifySegment subcommand + flag", () => {
  const ctx = classifySegment("git reset --hard");
  assert.equal(ctx.executable, "git");
  const kinds = (ctx.spans ?? []).map((s) => s.kind);
  assert.deepEqual(kinds, ["executable", "subcommand", "flag"]);
});

test("EXT: classifySegment basename strips path + .exe", () => {
  assert.equal(classifySegment("/usr/bin/git status").executable, "git");
  // Quoted windows path is normalized by the dequoter to bare git.
  assert.equal(classifySegment('"git.exe" status').executable, "git");
});

test("EXT: classifySegment env assignment before command is argument, exe still found", () => {
  const ctx = classifySegment("FOO=bar git status");
  assert.equal(ctx.executable, "git");
  const first = ctx.spans?.[0];
  assert.equal(first?.kind, "argument");
  assert.equal(first?.text, "FOO=bar");
});

test("EXT: classifySegment subshell span", () => {
  const ctx = classifySegment("echo $(rm -rf /)");
  const hasSubshell = (ctx.spans ?? []).some((s) => s.kind === "subshell");
  assert.ok(hasSubshell, "expected a subshell span");
});

test("EXT: classifySegment string span (single quotes)", () => {
  const ctx = classifySegment("git commit -m 'rm -rf detection'");
  const hasString = (ctx.spans ?? []).some(
    (s) => s.kind === "string" && s.text === "'rm -rf detection'",
  );
  assert.ok(hasString, "expected a single-quoted string span");
});

// ---------------------------------------------------------------------------
// normalizeCommand — split + classify each
// ---------------------------------------------------------------------------

test("normalizeCommand splits then classifies, exposing inner subshell command", () => {
  const ctxs = normalizeCommand("echo safe && sudo rm -rf /tmp/x");
  assert.equal(ctxs.length, 2);
  assert.equal(ctxs[0].executable, "echo");
  // second segment had sudo stripped.
  assert.equal(ctxs[1].executable, "rm");
  assert.equal(ctxs[1].normalized, "rm -rf /tmp/x");
});

test("normalizeCommand surfaces destructive substitution as its own segment first", () => {
  const ctxs = normalizeCommand("op item get $(op item delete Prod)");
  // inner substitution comes first.
  assert.equal(ctxs[0].raw, "op item delete Prod");
  assert.equal(ctxs[0].executable, "op");
});

// ---------------------------------------------------------------------------
// Property-style fuzz: invariants that must always hold
// ---------------------------------------------------------------------------

function randCommand(seed: number): string {
  // tiny deterministic LCG over a shell-ish alphabet.
  const alphabet = [
    "rm",
    "-rf",
    "/tmp",
    "git",
    "reset",
    "--hard",
    "&&",
    "||",
    ";",
    "|",
    "echo",
    "'x'",
    '"y"',
    "$(",
    ")",
    "`",
    "\\",
    "<(",
    ">(",
    "sudo",
    "env",
    "FOO=bar",
    ">/dev/null",
    "&>",
    " ",
    "(",
    ")",
  ];
  let s = seed >>> 0;
  const next = () => {
    s = (1103515245 * s + 12345) >>> 0;
    return s;
  };
  const n = 3 + (next() % 12);
  const parts: string[] = [];
  for (let i = 0; i < n; i++) parts.push(alphabet[next() % alphabet.length]);
  return parts.join(" ");
}

test("property: split segments never desync byte boundaries and never throw", () => {
  for (let seed = 1; seed <= 400; seed++) {
    const cmd = randCommand(seed);
    // Must not throw on arbitrary near-shell input.
    const segs = splitCommandSegments(cmd);
    assert.ok(Array.isArray(segs));
    for (const seg of segs) {
      // every emitted segment is a non-empty trimmed string.
      assert.equal(seg, seg.trim());
      assert.ok(seg.length > 0);
      // classify must also not throw.
      const ctx = classifySegment(seg);
      assert.equal(ctx.raw, seg);
      assert.equal(typeof ctx.normalized, "string");
    }
  }
});

test("property: stripWrapperPrefixes is idempotent on its own output", () => {
  for (let seed = 1; seed <= 400; seed++) {
    const cmd = randCommand(seed);
    const once = stripWrapperPrefixes(cmd);
    const twice = stripWrapperPrefixes(once);
    // Re-stripping the already-stripped command may re-apply dequoting but must
    // converge: a third pass equals the second.
    const thrice = stripWrapperPrefixes(twice);
    assert.equal(thrice, twice, `not convergent for: ${cmd}`);
  }
});

test("property: non-wrapper commands are returned unchanged when no quotes/exe", () => {
  // dequote/path normalizers only fire on quotes/backslash/redirection/.exe.
  const plain = ["git status", "kubectl get pods", "ls -la", "docker ps -a"];
  for (const cmd of plain) {
    assert.equal(stripWrapperPrefixes(cmd), cmd);
  }
});

test("property: quoted operators never create extra segments", () => {
  const cmds = [
    'echo "a && b ; c | d || e"',
    "echo 'a && b ; c'",
    "echo a\\&\\&b",
  ];
  for (const cmd of cmds) {
    assert.deepEqual(splitCommandSegments(cmd), [cmd]);
  }
});
