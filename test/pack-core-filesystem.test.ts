// biome-ignore-all lint/suspicious/noTemplateCurlyInString: these are literal
// shell `${TMPDIR}` / `${HOME}` command strings, not JS template placeholders.
//
// Tests for the core.filesystem pack — ported from DCG
// src/packs/core/filesystem.rs `#[cfg(test)] mod tests`.
//
// The DCG test helpers map onto this engine as follows:
// - assert_blocks_with_severity(pack, cmd, sev)  => matchPack returns a decision
//   whose severity === sev.
// - assert_blocks_with_pattern(pack, cmd, name)  => decision.ruleName === name.
// - assert_blocks(pack, cmd, reasonSubstring)    => decision.reason contains it.
// - assert_safe_pattern_matches / assert_no_match => matchPack does not block.
//
// In this engine a pack that allows a command does not block — matchPack may
// return undefined OR an explicit allow decision; both mean "not blocked". So
// the DCG "safe" and "no_match" assertions both collapse to "not blocked" here.

import assert from "node:assert/strict";
import test from "node:test";
import { matchPack } from "../src/engine/matcher.ts";
import { normalizeCommand } from "../src/engine/normalize.ts";
import { coreFilesystemPack } from "../src/engine/packs/core-filesystem.ts";
import type { EngineDecision, EvaluateOptions } from "../src/engine/types.ts";

const OPTS: Required<EvaluateOptions> = {
  inputMaxLength: 8192,
  perMatchBudgetMs: 50,
  failClosed: false,
};

function check(cmd: string): EngineDecision | undefined {
  const segments = normalizeCommand(cmd);
  return matchPack(coreFilesystemPack, segments, cmd, OPTS);
}

function assertBlocksWithSeverity(
  cmd: string,
  severity: "critical" | "high" | "medium" | "low",
): EngineDecision {
  const d = check(cmd);
  assert.ok(d, `expected ${JSON.stringify(cmd)} to block, got allow`);
  assert.equal(
    d.severity,
    severity,
    `severity mismatch for ${JSON.stringify(cmd)}`,
  );
  return d;
}

function assertBlocksWithPattern(cmd: string, name: string): EngineDecision {
  const d = check(cmd);
  assert.ok(d, `expected ${JSON.stringify(cmd)} to block, got allow`);
  assert.equal(
    d.ruleName,
    name,
    `ruleName mismatch for ${JSON.stringify(cmd)}`,
  );
  return d;
}

function assertBlocks(cmd: string, reasonSubstr: string): EngineDecision {
  const d = check(cmd);
  assert.ok(d, `expected ${JSON.stringify(cmd)} to block, got allow`);
  assert.ok(
    (d.reason ?? "").includes(reasonSubstr),
    `reason for ${JSON.stringify(cmd)} (${JSON.stringify(d.reason)}) did not contain ${JSON.stringify(reasonSubstr)}`,
  );
  return d;
}

function assertAllows(cmd: string): void {
  const d = check(cmd);
  // "Allowed" in this engine means matchPack does not BLOCK. Depending on how
  // an imperative allow (e.g. the rm-parser's safe-temp Allow) is surfaced,
  // matchPack may return undefined (no decision) OR an explicit allow decision
  // (decision === "allow" / blocked === false). Both mean "not blocked".
  const blocked =
    d !== undefined && (d.blocked === true || d.decision === "deny");
  assert.equal(
    blocked,
    false,
    `expected ${JSON.stringify(cmd)} to be allowed, got block ${JSON.stringify(d)}`,
  );
}

// ---------- pack creation ----------

test("pack metadata + force flag", () => {
  assert.equal(coreFilesystemPack.id, "core.filesystem");
  assert.equal(coreFilesystemPack.name, "Core Filesystem");
  assert.equal(coreFilesystemPack.force, true);
  for (const kw of ["rm", "find", "cp", "ln", "rsync"]) {
    assert.ok(
      coreFilesystemPack.keywords.includes(kw),
      `missing keyword ${kw}`,
    );
  }
  assert.ok(
    coreFilesystemPack.imperative && coreFilesystemPack.imperative.length > 0,
  );
});

// ---------- find -delete: closes the rm -rf bypass ----------

test("find -delete blocks root (critical)", () => {
  for (const cmd of [
    "find / -delete",
    "find /etc -delete",
    "find /usr -delete",
    "find /home -delete",
    "find /var -delete",
    "find /boot -delete",
    "find /lib -delete",
    "find /lib64 -delete",
    "find /root -delete",
    "find /sys -delete",
    "find /proc -delete",
    "find /dev -delete",
    "find /opt -delete",
    "find ~ -delete",
    "find $HOME -delete",
    "find ${HOME} -delete",
    "find / -depth -delete",
    "find / -type f -delete",
    "find /etc -name '*.conf' -delete",
    "find /home -mindepth 1 -delete",
    'find "/" -delete',
    "find '/etc' -delete",
  ]) {
    assertBlocksWithSeverity(cmd, "critical");
  }
});

test("find -delete blocks general (high)", () => {
  for (const cmd of [
    "find . -delete",
    "find ./node_modules -delete",
    "find . -name '*.pyc' -delete",
    "find /data -delete",
    "find /workspace/build -delete",
    "find ./target -type f -delete",
  ]) {
    assertBlocksWithSeverity(cmd, "high");
  }
});

test("find -delete under tmp is allowed", () => {
  for (const cmd of [
    "find /tmp -delete",
    "find /tmp/foo -delete",
    "find /tmp/foo -name '*.log' -delete",
    "find /var/tmp -delete",
    "find /var/tmp/dir -type f -delete",
    "find $TMPDIR -delete",
    "find $TMPDIR/work -name '*.tmp' -delete",
    "find ${TMPDIR} -delete",
    "find ${TMPDIR}/work -delete",
  ]) {
    assertAllows(cmd);
  }
});

test("find -delete with secondary sensitive path still blocks (critical)", () => {
  for (const cmd of [
    "find /tmp/foo /etc -delete",
    "find /tmp /usr -delete",
    "find /var/tmp/foo /home/user -delete",
    "find $TMPDIR / -delete",
  ]) {
    assertBlocksWithSeverity(cmd, "critical");
  }
});

test("find without -delete is not blocked", () => {
  for (const cmd of [
    "find . -name '*.rs'",
    "find / -type f -name passwd",
    "find /etc -ls",
    "find . -print",
    "find . -exec cat {} +",
    "find . -name -delete-this-not-a-flag",
  ]) {
    assertAllows(cmd);
  }
});

test("find -delete blocks in compound commands", () => {
  for (const cmd of [
    "true; find / -delete",
    "echo done; find /etc -delete",
    "true && find /etc -delete",
    "false || find /etc -delete",
    "(find /etc -delete)",
    "find /tmp -delete; find /etc -delete",
  ]) {
    assertBlocks(cmd, "find");
  }
});

test("find -delete blocks with terminating separator", () => {
  for (const cmd of [
    "find /etc -delete; echo done",
    "find /etc -delete && echo done",
    "find /etc -delete | tee log",
    "find /etc -delete&& echo done",
  ]) {
    assertBlocks(cmd, "find");
  }
});

test("find temp compound blocks conservatively", () => {
  for (const cmd of [
    "echo done; find /tmp -delete",
    "true && find /tmp -delete",
    "echo done; find /tmp/foo -delete",
    "echo done; find $TMPDIR -delete",
  ]) {
    assertBlocks(cmd, "find");
  }
});

// ---------- unlink ----------

test("unlink blocks root (critical)", () => {
  for (const cmd of [
    "unlink /etc/passwd",
    "unlink /etc/shadow",
    "unlink /etc/sudoers",
    "unlink /usr/bin/sudo",
    "unlink /boot/vmlinuz",
    "unlink ~/.bashrc",
    "unlink ~/.ssh/id_ed25519",
    "unlink $HOME/.gnupg/secring.gpg",
    "unlink ${HOME}/.aws/credentials",
    'unlink "/etc/passwd"',
    "unlink '/etc/shadow'",
    "echo done; unlink /etc/passwd",
    "true && unlink /etc/passwd",
    "(unlink /etc/passwd)",
    "sudo unlink /etc/passwd",
    "env FOO=bar unlink /etc/passwd",
    "/usr/bin/unlink /etc/passwd",
    "/bin/unlink /etc/shadow",
  ]) {
    assertBlocksWithSeverity(cmd, "critical");
  }
});

test("unlink blocks general (high)", () => {
  for (const cmd of [
    "unlink ./important.db",
    "unlink ./build/output.bin",
    "unlink secrets.txt",
    "unlink /data/important",
    "unlink /workspace/build/critical.bin",
  ]) {
    assertBlocksWithSeverity(cmd, "high");
  }
});

test("unlink under tmp / help is allowed", () => {
  for (const cmd of [
    "unlink /tmp/scratch",
    "unlink /tmp/foo/bar",
    "unlink /var/tmp/cache",
    "unlink $TMPDIR/file",
    "unlink ${TMPDIR}/file",
    "unlink --help",
    "unlink --version",
  ]) {
    assertAllows(cmd);
  }
});

test("unlink path traversal in tmp is blocked", () => {
  for (const cmd of [
    "unlink /tmp/../etc/passwd",
    "unlink /tmp/foo/../../etc/shadow",
    "unlink $TMPDIR/../etc/passwd",
  ]) {
    assertBlocks(cmd, "unlink");
  }
});

test("unlink no false-positive substring traps", () => {
  for (const cmd of [
    "cat /etc/unlink-script.sh",
    "ls unlink-foo.txt",
    "echo unlink",
    "unlink",
    "unlink ",
  ]) {
    assertAllows(cmd);
  }
});

// ---------- truncate ----------

test("truncate blocks zero/shrink root (critical)", () => {
  for (const cmd of [
    "truncate -s 0 /etc/passwd",
    "truncate -s 0 /etc/shadow",
    "truncate -s 0 /etc/sudoers",
    "truncate -s 0 /usr/bin/sudo",
    "truncate -s 0 /boot/vmlinuz",
    "truncate -s 0 ~/.bashrc",
    "truncate -s 0 $HOME/.aws/credentials",
    "truncate -s 0 ${HOME}/.gnupg/secring.gpg",
    "truncate --size=0 /etc/passwd",
    "truncate -s -100 /etc/passwd",
    "truncate -s -1024 /etc/hosts",
    "truncate --size=-100 /etc/passwd",
    "echo done; truncate -s 0 /etc/passwd",
    "true && truncate -s 0 /etc/passwd",
    "(truncate -s 0 /etc/passwd)",
    "sudo truncate -s 0 /etc/passwd",
    "env FOO=bar truncate -s 0 /etc/passwd",
    "/usr/bin/truncate -s 0 /etc/passwd",
    "/bin/truncate --size=0 /etc/shadow",
  ]) {
    assertBlocksWithSeverity(cmd, "critical");
  }
});

test("truncate blocks zero/shrink general (high)", () => {
  for (const cmd of [
    "truncate -s 0 ./important.db",
    "truncate -s 0 build/output.bin",
    "truncate --size=0 secrets.txt",
    "truncate -s -100 ./large.log",
    "truncate -s 0 /data/important",
  ]) {
    assertBlocksWithSeverity(cmd, "high");
  }
});

test("truncate covers attached/spaced size forms (coderabbit FN fix)", () => {
  // -s0 (attached), --size 0 (space not =), -s-1 / -s -1 (negative).
  assertBlocksWithSeverity("truncate -s0 /etc/passwd", "critical");
  assertBlocksWithSeverity("truncate --size 0 /etc/passwd", "critical");
  assertBlocksWithSeverity("truncate -s-1 /etc/shadow", "critical");
  assertBlocksWithSeverity("truncate -s -1 /etc/hosts", "critical");
  assertBlocksWithSeverity("truncate -s0 ./important.db", "high");
  assertBlocksWithSeverity("truncate --size 0 build/out.bin", "high");
  // grow (+N) and safe temp remain allowed (no regression).
  assert.equal(check("truncate -s +100 ./app.log"), undefined);
  assert.equal(check("truncate -s 0 /tmp/scratch/x"), undefined);
});

test("truncate under tmp / grow / help / reference is allowed", () => {
  for (const cmd of [
    "truncate -s 0 /tmp/scratch.bin",
    "truncate -s 1G /tmp/sparse-file.bin",
    "truncate -s 0 /var/tmp/cache.bin",
    "truncate -s 100M /var/tmp/test.img",
    "truncate -s 0 $TMPDIR/cache.bin",
    "truncate --size=0 ${TMPDIR}/scratch",
    "truncate -s -100 /tmp/log.txt",
    "truncate -s +1024 ./output.bin",
    "truncate -s +1G /var/log/sparse",
    "truncate --size=+100M ./preallocated",
    "truncate --help",
    "truncate --version",
    "truncate -r ref.bin out.bin",
    "truncate --reference=ref.bin out.bin",
  ]) {
    assertAllows(cmd);
  }
});

test("truncate no false-positive substring traps", () => {
  for (const cmd of [
    "cat /etc/truncate-readme.txt",
    "ls truncate-script.sh",
    "echo truncate",
  ]) {
    assertAllows(cmd);
  }
});

// ---------- shred ----------

test("shred blocks root (critical)", () => {
  for (const cmd of [
    "shred /etc/passwd",
    "shred -u /etc/passwd",
    "shred -fzu /etc/shadow",
    "shred --remove /etc/hosts",
    "shred -n 3 -u /etc/passwd",
    "shred -u ~/.ssh/id_ed25519",
    "shred -u $HOME/.aws/credentials",
    "shred -u ${HOME}/.gnupg/secring.gpg",
    "shred -fzu /usr/bin/sudo",
    "shred -u /boot/vmlinuz",
    "echo done; shred -u /etc/passwd",
    "true && shred -u /etc/passwd",
    "(shred -u /etc/passwd)",
    "sudo shred -u /etc/passwd",
    "env FOO=bar shred -u /etc/passwd",
    "/usr/bin/shred -fzu /etc/passwd",
    "/bin/shred -u /etc/shadow",
  ]) {
    assertBlocksWithSeverity(cmd, "critical");
  }
});

test("shred blocks general (high)", () => {
  for (const cmd of [
    "shred ./important.db",
    "shred -u ./secrets.txt",
    "shred -fzu build/output.bin",
    "shred -u /data/private",
    "shred --remove /workspace/build/critical.bin",
  ]) {
    assertBlocksWithSeverity(cmd, "high");
  }
});

test("shred under tmp / help is allowed", () => {
  for (const cmd of [
    "shred -u /tmp/scratch.bin",
    "shred -fzu /tmp/foo/cache",
    "shred -u /var/tmp/cache.bin",
    "shred -u $TMPDIR/file",
    "shred -u ${TMPDIR}/file",
    "shred -n 1 -u /tmp/scratch",
    "shred /tmp/foo/output",
    "shred --help",
    "shred --version",
  ]) {
    assertAllows(cmd);
  }
});

test("shred no false-positive substring traps", () => {
  for (const cmd of [
    "cat /etc/shred-readme.txt",
    "ls shred-script.sh",
    "echo shred",
  ]) {
    assertAllows(cmd);
  }
});

// ---------- tar --remove-files ----------

test("tar --remove-files blocks root (critical, root-home rule)", () => {
  for (const cmd of [
    "tar --remove-files -cf out.tar /etc",
    "tar --remove-files -czf out.tar.gz /home/user",
    "tar --remove-files -cf out.tar /usr/local",
    "tar -cf out.tar --remove-files /etc",
    "tar -cf out.tar /etc --remove-files",
    "tar --remove-files -cf /dev/null /etc",
    'tar --remove-files -cf out.tar "/etc"',
    "tar --remove-files -cf out.tar '/etc'",
    "tar --remove-files -cf out.tar ~/.ssh",
    "tar --remove-files -cf out.tar $HOME/.aws",
    "tar --remove-files -cf out.tar ${HOME}/.gnupg",
    "echo done; tar --remove-files -cf out.tar /etc",
    "true && tar --remove-files -cf out.tar /etc",
    "(tar --remove-files -cf out.tar /etc)",
    "sudo tar --remove-files -cf out.tar /etc",
    "env FOO=bar tar --remove-files -cf out.tar /etc",
    "/usr/bin/tar --remove-files -cf out.tar /etc",
    "/bin/tar --remove-files -cf out.tar /etc",
  ]) {
    assertBlocksWithSeverity(cmd, "critical");
    assertBlocksWithPattern(cmd, "tar-remove-files-root-home");
  }
});

test("tar --remove-files blocks general (high)", () => {
  for (const cmd of [
    "tar --remove-files -cf out.tar ./build",
    "tar --remove-files -cf out.tar important.db",
    "tar --remove-files -cf out.tar ./workspace",
    "tar -cf out.tar --remove-files data.json",
  ]) {
    assertBlocksWithSeverity(cmd, "high");
    assertBlocksWithPattern(cmd, "tar-remove-files-general");
  }
});

test("tar --remove-files under tmp / no-flag is allowed", () => {
  for (const cmd of [
    "tar --remove-files -cf out.tar /tmp/scratch",
    "tar -cf out.tar --remove-files /tmp/foo",
    "tar --remove-files -czf out.tar.gz /var/tmp/cache",
    "tar --remove-files -cf out.tar $TMPDIR/scratch",
    "tar --remove-files -cf out.tar ${TMPDIR}/scratch",
    "tar -cf out.tar /etc",
    "tar -czf out.tar.gz /home/user",
    "tar -xf in.tar",
    "tar -xzf in.tar.gz -C /tmp",
    "tar -tf in.tar",
    "tar --help",
    "tar --version",
  ]) {
    assertAllows(cmd);
  }
});

test("tar no false-positive substring traps", () => {
  for (const cmd of [
    "cat tar-readme.md",
    "ls /etc/tar-config",
    "echo --remove-files",
    "grep --remove-files docs/",
  ]) {
    assertAllows(cmd);
  }
});

test("tar --remove-files mixed sources blocks via root-home", () => {
  assertBlocksWithPattern(
    "tar --remove-files -cf out.tar /tmp/foo /etc/bar",
    "tar-remove-files-root-home",
  );
});

// ---------- dd of= ----------

test("dd of= blocks root (critical)", () => {
  for (const cmd of [
    "dd if=/dev/zero of=/etc/passwd",
    "dd if=/dev/urandom of=/etc/shadow",
    "dd if=/dev/zero of=/etc/sudoers",
    "dd if=/dev/zero of=/etc/passwd bs=1M count=10",
    "dd if=/dev/urandom of=/etc/shadow bs=4096 count=1",
    "dd of=/etc/passwd if=/dev/zero",
    "dd of=/etc/passwd if=/dev/zero bs=1M",
    "dd of=/etc/passwd",
    'dd if=/dev/zero of="/etc/passwd"',
    "dd if=/dev/zero of='/etc/shadow'",
    "dd if=/dev/zero of=~/.ssh/id_ed25519",
    "dd if=/dev/zero of=$HOME/.aws/credentials",
    "dd if=/dev/zero of=${HOME}/.gnupg/secring.gpg",
    "dd if=/dev/zero of=/usr/bin/sudo",
    "dd if=/dev/zero of=/boot/vmlinuz",
    "echo done; dd if=/dev/zero of=/etc/passwd",
    "true && dd if=/dev/zero of=/etc/passwd",
    "(dd if=/dev/zero of=/etc/passwd)",
    "sudo dd if=/dev/zero of=/etc/passwd",
    "env FOO=bar dd if=/dev/zero of=/etc/passwd",
    "/usr/bin/dd if=/dev/zero of=/etc/passwd",
    "/bin/dd if=/dev/zero of=/etc/shadow",
  ]) {
    assertBlocksWithSeverity(cmd, "critical");
    assertBlocksWithPattern(cmd, "dd-overwrite-root-home");
  }
});

test("dd of= blocks general (high)", () => {
  for (const cmd of [
    "dd if=/dev/zero of=./important.db",
    "dd if=/dev/urandom of=secrets.txt",
    "dd if=/dev/zero of=build/output.bin bs=1M count=10",
    "dd of=workspace/critical.bin",
    "dd if=/dev/zero of=/data/important",
  ]) {
    assertBlocksWithSeverity(cmd, "high");
    assertBlocksWithPattern(cmd, "dd-overwrite-general");
  }
});

test("dd to /dev sinks, devices, tmp, backups, help allowed", () => {
  for (const cmd of [
    "dd if=/etc/passwd of=/dev/null",
    "dd if=/etc/shadow of=/dev/null bs=1M",
    "dd if=/dev/sda of=/dev/null count=1024",
    "dd if=/etc/sudoers of=/dev/zero",
    "dd if=/etc/passwd of=/dev/full",
    "dd if=/dev/zero of=/dev/sda",
    "dd if=/dev/urandom of=/dev/sdb1",
    "dd of=/dev/loop0 if=/tmp/img",
    "dd if=/etc/passwd of=/tmp/passwd.bak",
    "dd if=/etc/shadow of=/tmp/shadow.backup",
    "dd if=/home/user/.ssh/id_ed25519 of=/tmp/keybackup",
    "dd if=/dev/zero of=/tmp/scratch.bin bs=1M count=10",
    "dd if=/dev/urandom of=/tmp/random.bin bs=4096 count=1",
    "dd if=/dev/zero of=/var/tmp/cache.bin",
    "dd if=/dev/zero of=$TMPDIR/cache.bin",
    "dd if=/dev/zero of=${TMPDIR}/scratch",
    "dd of=/tmp/out.bin",
    "dd of=/tmp/out.bin if=/dev/zero",
    "dd --help",
    "dd --version",
    "dd",
    "dd if=/dev/zero",
    "dd if=/etc/passwd",
  ]) {
    assertAllows(cmd);
  }
});

test("dd no false-positive substring traps", () => {
  for (const cmd of [
    "echo address",
    "ls add-ons.txt",
    "cat odd.log",
    "echo dd-script",
    "ls dd-readme.md",
  ]) {
    assertAllows(cmd);
  }
});

// ---------- mv: cross-segment recursive-force-delete bypass ----------

test("mv sensitive source/dest blocks (critical)", () => {
  for (const cmd of [
    "mv /etc /tmp/x",
    "mv /etc/passwd /tmp/passwd-deleted",
    "mv /home/user /tmp/relocated",
    "mv $HOME /tmp/x",
    "mv ${HOME} /tmp/x",
    "mv ~/.ssh /tmp/keys",
    "mv /usr/local /tmp/x",
    "mv /var/log /tmp/log-relocated",
    "mv /etc /dev/null",
    "mv /home/user /dev/null",
    "mv ./build/foo /etc/local-config.bak",
    "mv ./key.pem /home/user/.ssh/id_rsa",
    "mv /etc/hosts /etc/hosts.bak",
    "mv /etc/passwd /etc/passwd.old",
    "mv -v /etc /tmp/x",
    "mv -f /etc /tmp/x",
    "mv -t /tmp/x /etc",
    "mv --backup=numbered /etc /tmp/x",
    'mv "/etc" /tmp/x',
    "mv '/etc' /tmp/x",
    "echo done; mv /etc /tmp/x",
    "true && mv /etc /tmp/x",
    "(mv /etc /tmp/x)",
    "sudo mv /etc /tmp/x",
    "env FOO=bar mv /etc /tmp/x",
    "/usr/bin/mv /etc /tmp/x",
    "/bin/mv /etc /tmp/x",
  ]) {
    assertBlocksWithSeverity(cmd, "critical");
    assertBlocksWithPattern(cmd, "mv-sensitive-source-root-home");
  }
});

test("mv ANSI-C / locale quoted sensitive sources block", () => {
  for (const cmd of [
    "mv $'/etc' /tmp/x",
    'mv $"/etc" /tmp/x',
    "mv $'/etc/passwd' /tmp/passwd",
    'mv $"/home/user" /tmp/relocated',
  ]) {
    assertBlocksWithPattern(cmd, "mv-sensitive-source-root-home");
  }
});

test("mv with no sensitive path / tmp moves / help is allowed", () => {
  for (const cmd of [
    "mv ./old.txt ./new.txt",
    "mv build/output.bin dist/",
    "mv foo.log foo.log.1",
    "mv ./src/a.rs ./src/b.rs",
    "mv /tmp/foo /tmp/bar",
    "mv /tmp/foo /tmp/sub/bar",
    "mv -v /tmp/foo /tmp/bar",
    "mv /var/tmp/foo /var/tmp/bar",
    "mv /var/tmp/dir1 /var/tmp/dir2",
    "mv $TMPDIR/foo $TMPDIR/bar",
    "mv ${TMPDIR}/foo ${TMPDIR}/bar",
    "mv --help",
    "mv --version",
  ]) {
    assertAllows(cmd);
  }
});

test("mv no false-positive substring traps", () => {
  for (const cmd of [
    "cat mv-script.sh",
    "ls mv-readme.md",
    "echo mv",
    "echo amv-tools",
    "ls /etc",
    "cat /etc/passwd",
  ]) {
    assertAllows(cmd);
  }
});

// ---------- sensitive propagation chains ----------

test("sensitive propagation then delete blocks (critical)", () => {
  const cases: Array<[string, string]> = [
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
  for (const [cmd, pattern] of cases) {
    assertBlocksWithSeverity(cmd, "critical");
    assertBlocksWithPattern(cmd, pattern);
  }
});

test("sensitive propagation without delete is allowed", () => {
  for (const cmd of [
    "cp -a /etc /tmp/x",
    "cp --archive /etc/passwd /tmp/passwd",
    "ln -s /etc /tmp/x",
    "rsync -a /etc/ /tmp/dest/",
  ]) {
    assertAllows(cmd);
  }
});

test("non-sensitive propagation then delete is allowed", () => {
  for (const cmd of [
    "cp -al /tmp/a /tmp/b && rm -rf /tmp/b",
    "cp --archive ./build /tmp/build && rm -fr /tmp/build",
    "ln -s /tmp/a /tmp/b && rm -rf /tmp/b/.",
    "rsync -a ./target/ /tmp/target/ && rm -rf /tmp/target",
  ]) {
    assertAllows(cmd);
  }
});

// ---------- redirect-truncate: shell-syntax truncate-equivalent ----------

test("redirect truncate blocks (critical)", () => {
  for (const cmd of [
    "> /etc/passwd",
    ">/etc/passwd",
    ": > /etc/passwd",
    ": >/etc/shadow",
    "echo > /etc/passwd",
    'echo "x" > /etc/passwd',
    "cat /dev/null > /etc/passwd",
    "printf foo > /etc/sudoers",
    ">| /etc/passwd",
    "echo x >| /etc/passwd",
    "&> /etc/passwd",
    "make &> /etc/log",
    ">& /etc/passwd",
    "make >& /etc/log",
    "make >&/etc/log",
    "echo x 1> /etc/passwd",
    "echo x 2> /etc/passwd",
    "echo x 1>| /etc/passwd",
    "echo x 2>| /etc/passwd",
    "echo x > ~/.ssh/id_ed25519",
    "echo x > $HOME/.aws/credentials",
    "echo x > ${HOME}/.gnupg/secring.gpg",
    "echo x > /usr/bin/sudo",
    "echo x > /boot/vmlinuz",
    'echo x > "/etc/passwd"',
    "echo x > '/etc/shadow'",
    "echo done; > /etc/passwd",
    "true && > /etc/passwd",
    "(> /etc/passwd)",
    "sudo bash -c '> /etc/passwd'",
    "  > /etc/passwd",
    "\t> /etc/passwd",
  ]) {
    assertBlocksWithSeverity(cmd, "critical");
    assertBlocksWithPattern(cmd, "redirect-truncate-root-home");
  }
});

test("redirect glued operator blocks", () => {
  for (const cmd of [
    "echo data>/etc/passwd",
    "printf data>/etc/passwd",
    "echo data>~/.ssh/id_rsa",
    "echo data>$HOME/.aws/credentials",
    'echo "data">/etc/passwd',
    "echo data>'/etc/passwd'",
    'echo data>"/etc/passwd"',
    "echo x 2>/etc/passwd",
    "echo x 1>/etc/passwd",
    "echo x &>/etc/passwd",
    "echo x >|/etc/passwd",
  ]) {
    assertBlocksWithPattern(cmd, "redirect-truncate-root-home");
  }
});

test("redirect ANSI-C / locale quoted paths block", () => {
  for (const cmd of [
    "> $'/etc/passwd'",
    '> $"/etc/passwd"',
    ": > $'/etc/shadow'",
    "echo > $'/etc/passwd'",
    'echo > $"/etc/passwd"',
  ]) {
    assertBlocksWithPattern(cmd, "redirect-truncate-root-home");
  }
});

test("redirect to /dev devices still blocks", () => {
  for (const cmd of [
    "> /dev/sda",
    "echo zero > /dev/sda1",
    "command > /dev/sdb",
    "echo > /dev/nvme0n1",
  ]) {
    assertBlocksWithPattern(cmd, "redirect-truncate-root-home");
  }
});

test("redirect append / read / fd / non-sensitive / dev-sinks allowed", () => {
  for (const cmd of [
    "echo line >> /etc/syslog",
    "echo line >> ~/.bashrc",
    "make >> build.log",
    "echo line >> /etc/passwd",
    "echo line >> /etc/shadow",
    "command >> /usr/local/log",
    "echo x &>> /etc/log",
    "echo x 1>> /etc/passwd",
    "echo x 2>> /etc/passwd",
    "make > build.log",
    "cargo test > test.log",
    "echo x > ./output.txt",
    "echo x > foo.log",
    "ls > files.txt",
    "command > /tmp/scratch",
    "command > $TMPDIR/scratch",
    "command > ${TMPDIR}/scratch",
    "echo x >| build.log",
    "echo x &> build.log",
    "echo x >& build.log",
    "echo x 2> err.log",
    "cat < /etc/passwd",
    "wc -l < /etc/hosts",
    "while read line; do echo $line; done < /etc/hosts",
    "echo x 1>&2",
    "echo x 2>&1",
    "echo x >&2",
    "exec >&-",
    "command > /dev/null",
    "command >/dev/null",
    "command 2>&1 > /dev/null",
    "command > /dev/null 2>&1",
    "command 2> /dev/null",
    "command &> /dev/null",
    "cat /etc/passwd > /dev/null",
    "find . > /dev/null 2>&1",
    "make > /dev/zero",
    "echo test > /dev/full",
    "echo data>./local.txt",
    "echo data>build.log",
    "echo data>/tmp/scratch",
    "echo data>/dev/null",
  ]) {
    assertAllows(cmd);
  }
});

// ---------- rm -rf (imperative parser via the pack) ----------

test("rm -rf root is critical", () => {
  assertBlocksWithSeverity("rm -rf /", "critical");
  assertBlocksWithSeverity("rm -rf /etc", "critical");
  assertBlocksWithSeverity("rm -rf /home", "critical");
  assertBlocksWithSeverity("rm -rf ~/", "critical");
  assertBlocksWithSeverity("rm -rf /tmp/cache /etc", "critical");
  assertBlocksWithPattern("rm -rf /", "rm-rf-root-home");
  assertBlocksWithSeverity('rm -rf "/"', "critical");
  assertBlocksWithSeverity("rm -rf '/'", "critical");
  assertBlocksWithSeverity('rm -rf "~/"', "critical");
  assertBlocksWithSeverity("rm -rf '/etc'", "critical");
});

test("rm separate / long flags on root are critical", () => {
  assertBlocksWithSeverity("rm -r -f /", "critical");
  assertBlocksWithSeverity("rm -f -r /", "critical");
  assertBlocksWithSeverity("rm -r -f /etc", "critical");
  assertBlocksWithSeverity("rm -r -f ~/", "critical");
  assertBlocksWithPattern("rm -r -f /", "rm-r-f-separate-root-home");
  assertBlocksWithSeverity("rm --recursive --force /", "critical");
  assertBlocksWithSeverity("rm --force --recursive /", "critical");
  assertBlocksWithSeverity("rm --recursive --force /etc", "critical");
  assertBlocksWithPattern(
    "rm --recursive --force /",
    "rm-recursive-force-root-home",
  );
  assertBlocksWithSeverity('rm -r -f "/"', "critical");
  assertBlocksWithSeverity("rm --recursive --force '/'", "critical");
  assertBlocksWithSeverity("rm -rf \\/", "critical");
  assertBlocksWithSeverity("rm -rf \\~", "critical");
  assertBlocksWithSeverity("rm -r -f \\/", "critical");
  assertBlocksWithSeverity("rm --recursive --force \\/", "critical");
  assertBlocksWithSeverity("rm -rf $HOME", "critical");
  assertBlocksWithSeverity('rm -rf "$HOME"', "critical");
  assertBlocksWithSeverity("rm -rf ${HOME}", "critical");
  assertBlocksWithSeverity('rm -rf "${HOME}"', "critical");
  assertBlocksWithSeverity("rm -r -f $HOME", "critical");
  assertBlocksWithSeverity("rm --recursive --force $HOME", "critical");
  assertBlocksWithSeverity("rm -r -f ./build", "high");
  assertBlocksWithSeverity("rm --recursive --force ./build", "high");
});

test("rm -rf general is high", () => {
  assertBlocksWithSeverity("rm -rf ./build", "high");
  assertBlocksWithPattern("rm -rf ./build", "rm-rf-general");
});

test("rm -rf tmp with trailing redirections is safe", () => {
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
    assertAllows(cmd);
  }
  for (const cmd of [
    "rm -rf /etc 2>/dev/null",
    "rm -rf /tmp/ok /etc 2>/dev/null",
    "rm -rf / 2>/dev/null",
  ]) {
    assert.ok(check(cmd), `expected ${JSON.stringify(cmd)} to block`);
  }
});

test("rm flag ordering blocks", () => {
  assertBlocks("rm -r -f ./build", "separate -r -f flags");
  assertBlocks("rm -f -r ./build", "separate -r -f flags");
  assertBlocks(
    "rm --recursive --force ./build",
    "rm --recursive --force is destructive",
  );
  assertBlocks(
    "rm --force --recursive ./build",
    "rm --recursive --force is destructive",
  );
});

test("safe rm tmp + variants allowed", () => {
  for (const cmd of [
    "rm -rf /tmp/test",
    "rm -rf /var/tmp/stuff",
    "rm -rf $TMPDIR/junk",
    "rm -rf ${TMPDIR}/junk",
    "rm -fr /tmp/test",
    "rm -r -f /tmp/test",
    "rm --recursive --force /tmp/test",
  ]) {
    assertAllows(cmd);
  }
});

test("rm tmpdir brace requires exact var name", () => {
  assertBlocksWithSeverity("rm -rf ${TMPDIR_NOT}/junk", "high");
  assertBlocksWithPattern("rm -rf ${TMPDIR_NOT}/junk", "rm-rf-general");
});

test("rm path traversal blocked (root-home)", () => {
  assertBlocksWithPattern("rm -rf /tmp/../etc", "rm-rf-root-home");
});

// ---------- integration: cross-segment recursive-removal + temp-safe ----------

test("integration: temp-to-temp propagation+delete allowed, sensitive blocked", () => {
  assertAllows("cp -al /tmp/a /tmp/b && rm -rf /tmp/b");
  assertBlocksWithPattern(
    "cp -al /etc /tmp/x && rm -rf /tmp/x",
    "cp-sensitive-then-delete",
  );
});
