// test/engine-heredoc.test.ts

import assert from "node:assert/strict";
import test from "node:test";
import { checkTriggers, extractHeredocBodies } from "../src/engine/heredoc.ts";

// ---------------------------------------------------------------------------
// Tier 1: trigger detection (ported from heredoc.rs tier1_triggers tests)
// ---------------------------------------------------------------------------

test("no trigger on safe commands", () => {
  const safe = [
    "git status",
    "ls -la",
    "cargo build",
    "npm install",
    "docker ps",
    "kubectl get pods",
    "cat file.txt",
    "echo hello",
    "grep pattern file",
    "find . -name '*.rs'",
  ];
  for (const cmd of safe) {
    assert.equal(checkTriggers(cmd), false, `should not trigger: ${cmd}`);
  }
});

test("triggers on basic heredoc forms", () => {
  const heredocs = [
    "cat << EOF",
    "cat <<EOF",
    "cat << 'EOF'",
    'cat << "EOF"',
    "cat <<- EOF",
    "mysql <<< 'query'",
  ];
  for (const cmd of heredocs) {
    assert.equal(checkTriggers(cmd), true, `should trigger: ${cmd}`);
  }
});

test("triggers on versioned interpreters", () => {
  const cmds = [
    "python3.11 -c 'import os'",
    "python3.12.1 -c 'import os'",
    "ruby3.0 -e 'puts 1'",
    "perl5.36 -e 'print 1'",
    "node18 -e 'console.log(1)'",
    "nodejs20.10.0 -e 'test'",
  ];
  for (const cmd of cmds) {
    assert.equal(checkTriggers(cmd), true, `should trigger: ${cmd}`);
  }
});

test("triggers on shell/eval/exec/xargs/pipe forms", () => {
  const cmds = [
    "bash -lc 'echo hello'",
    "sh -c 'ls'",
    "find . -name '*.bak' | xargs rm",
    "echo 'print(1)' | python",
    "eval 'dangerous code'",
    'exec "command"',
  ];
  for (const cmd of cmds) {
    assert.equal(checkTriggers(cmd), true, `should trigger: ${cmd}`);
  }
});

test("heredoc syntax inside quoted literals does not trigger", () => {
  const cmds = [
    'git commit -m "docs: example heredoc: cat <<EOF rm -rf / EOF"',
    'rg "<<EOF" README.md',
    "echo 'cat <<EOF (docs only)'",
  ];
  for (const cmd of cmds) {
    assert.equal(checkTriggers(cmd), false, `should NOT trigger: ${cmd}`);
  }
});

test("heredoc inside command substitution with outer quotes still triggers", () => {
  const cmd = 'echo "$(cat <<EOF\nrm -rf /\nEOF)"';
  assert.equal(checkTriggers(cmd), true);
});

// ---------------------------------------------------------------------------
// Tier 2: inline-script body extraction (ported from tier2_extraction tests)
// ---------------------------------------------------------------------------

test("extracts inline script single quotes", () => {
  assert.deepEqual(extractHeredocBodies("python -c 'import os'"), [
    "import os",
  ]);
});

test("extracts inline script double quotes", () => {
  assert.deepEqual(extractHeredocBodies('bash -c "echo hello"'), [
    "echo hello",
  ]);
});

test("extracts inline script with intervening flags", () => {
  assert.deepEqual(extractHeredocBodies("python -I -c 'import os'"), [
    "import os",
  ]);
});

test("extracts inline script with combined shell flags", () => {
  assert.deepEqual(extractHeredocBodies("bash -lc 'echo hello'"), [
    "echo hello",
  ]);
});

test("extracts inline script with combined node flags", () => {
  assert.deepEqual(extractHeredocBodies("node -pe 'process.version'"), [
    "process.version",
  ]);
});

test("extracts inline script with interleaved perl flags", () => {
  assert.deepEqual(extractHeredocBodies("perl -pi -e 'print 1'"), ["print 1"]);
});

test("extracts powershell -Command body (single quote)", () => {
  assert.deepEqual(extractHeredocBodies("powershell -Command 'echo hi'"), [
    "echo hi",
  ]);
});

test("extracts powershell.exe -Command body (double quote)", () => {
  assert.deepEqual(extractHeredocBodies('powershell.exe -Command "echo hi"'), [
    "echo hi",
  ]);
});

test("extracts pwsh -c body", () => {
  assert.deepEqual(extractHeredocBodies("pwsh -c 'echo hi'"), ["echo hi"]);
});

test("extracts powershell quoted full path -Command body", () => {
  const cmd =
    "\"C:\\WINDOWS\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\" -Command 'echo hi'";
  const bodies = extractHeredocBodies(cmd);
  assert.ok(
    bodies.includes("echo hi"),
    `expected 'echo hi' in ${JSON.stringify(bodies)}`,
  );
});

test("extracts multiple inline scripts", () => {
  assert.deepEqual(
    extractHeredocBodies("python -c 'code1' && ruby -e 'code2'"),
    ["code1", "code2"],
  );
});

test("extracts versioned interpreter scripts", () => {
  assert.deepEqual(
    extractHeredocBodies(
      "python3.11 -c 'import os' && nodejs18 -e 'console.log(1)'",
    ),
    ["import os", "console.log(1)"],
  );
});

// ---------------------------------------------------------------------------
// Tier 2: here-string body extraction
// ---------------------------------------------------------------------------

test("extracts here-string", () => {
  assert.deepEqual(extractHeredocBodies("cat <<< 'hello world'"), [
    "hello world",
  ]);
});

test("extracts here-string with nested quotes (single outer)", () => {
  assert.deepEqual(extractHeredocBodies("cat <<< 'hello \"world\" test'"), [
    'hello "world" test',
  ]);
});

test("extracts here-string with nested quotes (double outer)", () => {
  assert.deepEqual(extractHeredocBodies("cat <<< \"hello 'world' test\""), [
    "hello 'world' test",
  ]);
});

// ---------------------------------------------------------------------------
// Tier 2: heredoc body extraction
// ---------------------------------------------------------------------------

test("extracts basic heredoc body", () => {
  assert.deepEqual(extractHeredocBodies("cat << EOF\nline1\nline2\nEOF"), [
    "line1\nline2",
  ]);
});

test("extracts heredoc ignoring trailing tokens on delimiter line", () => {
  const cmd =
    "python3 <<EOF | cat\nimport shutil\nshutil.rmtree('/tmp/test')\nEOF";
  assert.deepEqual(extractHeredocBodies(cmd), [
    "import shutil\nshutil.rmtree('/tmp/test')",
  ]);
});

test("extracts heredoc with CRLF line endings", () => {
  assert.deepEqual(extractHeredocBodies("cat <<EOF\r\nline1\r\nEOF\r\n"), [
    "line1",
  ]);
});

test("extracts tab-stripped heredoc body", () => {
  assert.deepEqual(extractHeredocBodies("cat <<- EOF\n\tline1\n\tline2\nEOF"), [
    "line1\nline2",
  ]);
});

test("extracts indent-stripped heredoc body", () => {
  assert.deepEqual(
    extractHeredocBodies("cat <<~ EOF\n    line1\n    line2\n    EOF"),
    ["line1\nline2"],
  );
});

test("extracts empty heredoc body", () => {
  assert.deepEqual(extractHeredocBodies("cat << EOF\nEOF"), [""]);
});

test("indent-stripped heredoc does not throw on multibyte whitespace", () => {
  const cases = [
    "cat <<~ EOF\n  line1\n\u{00A0}line2\n  EOF",
    "cat <<~ EOF\n  line1\n\u{3000}foo\n  EOF",
    "cat <<~ EOF\n\u{00A0}line1\n\u{3000}line2\nEOF",
  ];
  for (const cmd of cases) {
    assert.doesNotThrow(() => extractHeredocBodies(cmd));
  }
});

test("parses dash-after-space as part of unquoted delimiter", () => {
  // `cat << -EOF` is a Standard heredoc whose delimiter is literal `-EOF`.
  assert.deepEqual(extractHeredocBodies("cat << -EOF\nbody line\n-EOF"), [
    "body line",
  ]);
});

test("tab-stripped quoted heredoc with space after dash", () => {
  // Issue #109: `<<- 'EOF'`, `<<-\"EOF\"`, `<<~ 'EOF'` etc. all parse delim=EOF.
  const forms = [
    "cat <<-'EOF'\n\tgh repo delete\n\tEOF",
    "cat <<- 'EOF'\n\tgh repo delete\n\tEOF",
    'cat <<-"EOF"\n\tgh repo delete\n\tEOF',
    'cat <<- "EOF"\n\tgh repo delete\n\tEOF',
    "cat <<~ 'EOF'\n\tgh repo delete\n\tEOF",
  ];
  for (const cmd of forms) {
    const bodies = extractHeredocBodies(cmd);
    assert.equal(bodies.length, 1, `${cmd}: one body`);
    assert.equal(bodies[0], "gh repo delete", `${cmd}: body`);
  }
});

// ---------------------------------------------------------------------------
// Negative / safety
// ---------------------------------------------------------------------------

test("no bodies on safe command", () => {
  assert.deepEqual(extractHeredocBodies("git status"), []);
});

test("empty command yields no bodies", () => {
  assert.deepEqual(extractHeredocBodies(""), []);
});

test("whitespace-only yields no bodies", () => {
  assert.deepEqual(extractHeredocBodies("   \t\n  "), []);
});

test("unterminated heredoc yields no body (fail-open skip)", () => {
  assert.deepEqual(
    extractHeredocBodies(
      "cat << EOF\nunterminated content without closing delimiter",
    ),
    [],
  );
});

test("respects max body bytes for inline scripts", () => {
  const big = "x".repeat(2_000_000);
  const cmd = `python -c '${big}'`;
  // Whole command exceeds maxBodyBytes (1MB) -> input-size guard -> [].
  assert.deepEqual(extractHeredocBodies(cmd), []);
});

test("respects max heredocs count", () => {
  const cmd = "cmd1 << A\na\nA && cmd2 << B\nb\nB && cmd3 << C\nc\nC";
  const bodies = extractHeredocBodies(cmd, {
    maxBodyBytes: 1024 * 1024,
    maxBodyLines: 10_000,
    maxHeredocs: 2,
    timeoutMs: 50,
  });
  assert.ok(bodies.length <= 2, `expected <= 2, got ${bodies.length}`);
});

test("timeout of 0ms fails open (no bodies)", () => {
  const cmd = "cat << EOF\nline1\nEOF";
  const bodies = extractHeredocBodies(cmd, {
    maxBodyBytes: 1024 * 1024,
    maxBodyLines: 10_000,
    maxHeredocs: 10,
    timeoutMs: 0,
  });
  assert.deepEqual(bodies, []);
});

test("interpreter heredoc body is extracted (not masked here)", () => {
  // Masking is the evaluator's job; this module surfaces the raw body so a
  // destructive token inside an executing heredoc still reaches the scan.
  const cmd = "bash <<SH\nrm -rf /important\nSH";
  assert.deepEqual(extractHeredocBodies(cmd), ["rm -rf /important"]);
});
