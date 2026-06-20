// Golden corpus for the merged `remote` pack (ssh + scp + rsync), ported from
// DCG's own `#[test]` blocks in:
//   - src/packs/remote/ssh.rs
//   - src/packs/remote/scp.rs
//   - src/packs/remote/rsync.rs
//
// Drives the REAL engine end-to-end (buildRegistry([pack]) + evaluateCommand).
// assert_blocks_with_pattern -> expected ruleName; assert_allows -> allow.
//
// SCP NOTE: the `path_traversal_does_not_bypass_via_safe` DCG test asserts on
// pack.matches_safe directly (safe-rule level): a `/tmp/../etc/passwd` target
// must NOT be treated as safe. DCG does NOT assert it blocks — its destructive
// scp-to-etc rule needs `/etc` at a ` /etc` argument boundary, which a single
// `/tmp/../etc/passwd` token does not provide. So we mirror DCG exactly and
// assert at the safe-rule level: the traversal target matches no safe pattern,
// while a normal `/tmp/` target still does.

import assert from "node:assert/strict";
import test from "node:test";
import { evaluateCommand } from "../src/engine/evaluate.ts";
import { remotePack } from "../src/engine/packs/remote.ts";
import { buildRegistry } from "../src/engine/registry.ts";
import type { Severity } from "../src/engine/types.ts";

const registry = buildRegistry([remotePack]);

function blocks(cmd: string, ruleName: string, severity?: Severity): void {
  const d = evaluateCommand(cmd, registry);
  assert.notEqual(d.decision, "allow", `expected ${cmd} to be flagged`);
  assert.equal(d.ruleName, ruleName, `rule for: ${cmd}`);
  if (severity) assert.equal(d.severity, severity, `severity for: ${cmd}`);
}

/** DCG `pack.matches_safe`: does ANY of the pack's safe rules match? */
function matchesSafe(cmd: string): boolean {
  return remotePack.safePatterns.some((r) => r.re.test(cmd));
}

function allows(cmd: string): void {
  const d = evaluateCommand(cmd, registry);
  assert.equal(
    d.decision,
    "allow",
    `expected ${cmd} to be allowed, got ${d.ruleName}`,
  );
}

// ---------------------------------------------------------------------------
// ssh (DCG src/packs/remote/ssh.rs mod tests)
// ---------------------------------------------------------------------------

test("ssh: allows safe commands", () => {
  allows("ssh -V");
  allows("ssh --version");
  allows("ssh-keygen -l");
  allows("ssh-keygen -lf ~/.ssh/id_rsa.pub");
  allows("ssh-keyscan github.com");
  allows("ssh-add -l");
  allows("ssh-add -L");
  allows("ssh-agent");
  allows("ssh --help");
  allows("ssh -h");
  allows("ssh-keygen --help");
  allows("ssh user@host");
  allows("ssh -i key.pem user@host");
  allows("ssh user@host 'ls -la'");
  allows("ssh user@host 'cat /etc/hostname'");
});

test("ssh: blocks remote rm -rf", () => {
  blocks("ssh user@host 'rm -rf /tmp/data'", "ssh-remote-rm-rf", "critical");
  blocks('ssh host "rm -rf ./build"', "ssh-remote-rm-rf", "critical");
  blocks(
    "ssh -i key.pem user@host 'rm -rf /var/log'",
    "ssh-remote-rm-rf",
    "critical",
  );
});

test("ssh: blocks remote git destructive", () => {
  blocks(
    "ssh user@host 'git reset --hard HEAD'",
    "ssh-remote-git-reset-hard",
    "high",
  );
  blocks(
    'ssh host "cd repo && git reset --hard"',
    "ssh-remote-git-reset-hard",
    "high",
  );
  blocks("ssh user@host 'git clean -fd'", "ssh-remote-git-clean", "high");
});

test("ssh: blocks ssh-keygen -R (known_hosts removal)", () => {
  blocks("ssh-keygen -R hostname", "ssh-keygen-remove-host", "medium");
  blocks(
    "ssh-keygen -f ~/.ssh/known_hosts -R 192.168.1.1",
    "ssh-keygen-remove-host",
    "medium",
  );
});

test("ssh: blocks ssh-add -d/-D", () => {
  blocks("ssh-add -d", "ssh-add-delete-all", "medium");
  blocks("ssh-add -D", "ssh-add-delete-all", "medium");
});

test("ssh: blocks remote sudo rm", () => {
  blocks(
    "ssh root@host 'sudo rm /etc/passwd'",
    "ssh-remote-sudo-rm",
    "critical",
  );
});

// ---------------------------------------------------------------------------
// scp (DCG src/packs/remote/scp.rs mod tests)
// ---------------------------------------------------------------------------

test("scp: allows safe commands", () => {
  allows("scp --help");
  allows("scp -h");
  allows("scp user@host:file.txt .");
  allows("scp -P 22 user@host:/path/file .");
  allows("scp user@host:/etc/hosts .");
  allows("scp file.txt user@host:~/documents/");
  allows("scp file.txt /tmp/");
  allows("scp file.txt user@host:/tmp/backup/");
  allows("scp file.txt user@host:/home/user/");
  allows("scp -r ./project user@host:/home/user/projects/");
});

test("scp: blocks copy to root (recursive)", () => {
  blocks("scp -r ./data user@host:/", "scp-recursive-root", "critical");
  blocks("scp -r backup/ root@server:/", "scp-recursive-root", "critical");
});

test("scp: blocks copy to /etc", () => {
  blocks("scp config.conf user@host:/etc/", "scp-to-etc", "high");
  blocks("scp passwd root@server:/etc/passwd", "scp-to-etc", "high");
});

test("scp: blocks copy to /var but allows /var/tmp", () => {
  blocks("scp data.db user@host:/var/lib/", "scp-to-var", "high");
  allows("scp file.txt user@host:/var/tmp/");
});

test("scp: blocks copy to /boot", () => {
  blocks("scp vmlinuz user@host:/boot/", "scp-to-boot", "critical");
});

test("scp: blocks copy to /usr", () => {
  blocks("scp binary user@host:/usr/local/bin/", "scp-to-usr", "high");
});

test("scp: blocks copy to /bin and /sbin", () => {
  blocks("scp script root@server:/bin/", "scp-to-bin", "critical");
  blocks("scp script root@server:/sbin/", "scp-to-bin", "critical");
});

test("scp: blocks copy to /lib and /lib64", () => {
  blocks("scp libfoo.so user@host:/lib/", "scp-to-lib", "critical");
  blocks("scp libbar.so user@host:/lib64/", "scp-to-lib", "critical");
});

test("scp: path traversal out of safe dirs is not treated as safe (matches_safe)", () => {
  // Mirrors DCG `path_traversal_does_not_bypass_via_safe` exactly (safe-rule level).
  assert.equal(
    matchesSafe("scp file user@host:/tmp/stash/"),
    true,
    "normal /tmp copies remain safe",
  );
  assert.equal(
    matchesSafe("scp file user@host:/tmp/../etc/passwd"),
    false,
    "traversal out of /tmp must NOT be safe",
  );
  assert.equal(
    matchesSafe("scp file user@host:/var/tmp/../root/.ssh/authorized_keys"),
    false,
    "traversal out of /var/tmp must NOT be safe",
  );
  assert.equal(
    matchesSafe("scp file user@host:~/../root/.bashrc"),
    false,
    "traversal out of ~ must NOT be safe",
  );
});

// ---------------------------------------------------------------------------
// rsync (DCG src/packs/remote/rsync.rs mod tests)
// ---------------------------------------------------------------------------

test("rsync: allows safe commands", () => {
  allows("rsync --dry-run src/ dest/");
  allows("rsync -avzn src/ dest/");
  allows("rsync --list-only src/ dest/");
  allows("rsync -avz src/ dest/");
});

test("rsync: blocks --delete and its variants", () => {
  blocks("rsync --delete src/ dest/", "rsync-delete", "high");
  blocks("rsync --delete-after src/ dest/", "rsync-delete", "high");
  blocks("rsync --delete-before src/ dest/", "rsync-delete", "high");
  blocks("rsync --delete-during src/ dest/", "rsync-delete", "high");
  blocks("rsync --delete-excluded src/ dest/", "rsync-delete", "high");
});

test("rsync: blocks --del short alias", () => {
  blocks("rsync --del src/ dest/", "rsync-del-short", "high");
});

test("rsync: --delete with --dry-run is allowed", () => {
  allows("rsync --delete --dry-run src/ dest/");
});

test("rsync: unrelated commands allow", () => {
  allows("git status");
  allows("echo hello");
});
