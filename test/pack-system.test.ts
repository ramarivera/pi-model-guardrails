// Golden corpus for the system pack, ported from DCG's own `#[test]` blocks in
// `src/packs/system/{disk,permissions,services}.rs` (mod tests). Each case
// mirrors a DCG assertion:
//   assert_blocks / assert_blocks_with_pattern / assert_blocks_with_severity
//     -> a deny/warn decision with the expected rule name + severity
//   assert_allows / assert_no_match / matches_safe / is_none()
//     -> the command is allowed (safe pattern, dry-run, or no keyword)
//
// Unlike the early core-pack tests, this exercises the REAL engine end-to-end:
// buildRegistry([systemPack]) + evaluateCommand, so wrapper-stripping (sudo),
// segmentation, the keyword quick-reject, and the per-pack safe/destructive
// matcher are all on the hot path.

import assert from "node:assert/strict";
import test from "node:test";
import { evaluateCommand } from "../src/engine/evaluate.ts";
import { systemPack } from "../src/engine/packs/system.ts";
import { buildRegistry } from "../src/engine/registry.ts";
import type { Severity } from "../src/engine/types.ts";

const registry = buildRegistry([systemPack]);

function check(cmd: string) {
  const d = evaluateCommand(cmd, registry);
  return d.decision === "allow" ? undefined : d;
}

function assertBlocks(cmd: string, sev?: Severity, rule?: string) {
  const d = check(cmd);
  assert.ok(d, `${cmd} must block`);
  if (sev) assert.equal(d.severity, sev, `${cmd} severity`);
  if (rule) assert.equal(d.ruleName, rule, `${cmd} rule`);
}

function assertAllows(cmd: string) {
  assert.equal(check(cmd), undefined, `${cmd} must be allowed`);
}

// ---------------------------------------------------------------------------
// system.disk (DCG disk.rs::tests)
// ---------------------------------------------------------------------------

test("disk: wipefs is reachable + blocks (wipefs_is_reachable_via_keywords)", () => {
  assertBlocks("wipefs --all somefile.img", "high", "wipefs");
});

test("disk: dd quote bypass is closed (dd_quote_bypass_is_closed)", () => {
  assertBlocks('dd if=/dev/zero of="/dev/sda" bs=1M', "high", "dd-device");
  assertBlocks("dd of='/dev/sdb' if=something.img", "high", "dd-device");
  // /dev/null stays safe under quotes.
  assertAllows('dd if=myfile of="/dev/null"');
});

test("disk: btrfs/dmsetup global flags do not bypass", () => {
  assertBlocks(
    "btrfs --format json subvolume delete /mnt/foo",
    "high",
    "btrfs-subvolume-delete",
  );
  assertBlocks(
    "btrfs --verbose check --repair /dev/sda1",
    "high",
    "btrfs-check-repair",
  );
  assertBlocks("dmsetup -v remove_all", "high", "dmsetup-remove-all");
  assertBlocks("dmsetup --noudevsync remove my-dev", "high", "dmsetup-remove");
});

test("disk: parted print-only forms remain allowed", () => {
  for (const cmd of [
    "parted /dev/sda print",
    "parted /dev/sda print free",
    "parted /dev/sda print all",
    "parted -s /dev/sda print 1",
  ]) {
    assertAllows(cmd);
  }
});

test("disk: parted print prefix + global flags do not bypass modifications", () => {
  for (const cmd of [
    "parted /dev/sda print rm 1",
    "parted /dev/sda p rm 1",
    "parted /dev/sda print mklabel gpt",
    "parted /dev/sda print mkpart primary ext4 1MiB 1GiB",
    "parted -s /dev/sda mklabel gpt",
    "parted --script /dev/sda rm 1",
  ]) {
    assertBlocks(cmd, "high", "parted-modify");
  }
});

test("disk: blocks with correct severity (disk_blocks_with_correct_severity)", () => {
  assertBlocks("dd if=/dev/zero of=/dev/sda bs=1M", "high");
  assertBlocks("fdisk /dev/sda", "high");
  assertBlocks("mkfs.ext4 /dev/sdb1", "high");
  assertBlocks("wipefs --all /dev/sdb", "high");
  assertBlocks("mdadm --stop /dev/md0", "high");
  assertBlocks("btrfs subvolume delete /mnt/foo", "high");
  assertBlocks("dmsetup remove my-dev", "high");
  assertBlocks("pvremove /dev/sda1", "high");
  assertBlocks("vgremove my-vg", "high");
  assertBlocks("lvremove my-vg/my-lv", "high");
});

test("disk: mkswap blocks destructive variants (mkswap_blocks_destructive_variants)", () => {
  for (const cmd of [
    "mkswap /dev/sdb",
    "mkswap /dev/sda1",
    "sudo mkswap /dev/sdb",
    "mkswap -L swap1 /dev/sdb1",
    "mkswap -U random /dev/nvme0n1p2",
  ]) {
    assertBlocks(cmd, "high", "mkswap");
  }
});

test("disk: mkswap --check allowed (mkswap_check_and_unrelated_text_allowed)", () => {
  assertAllows("mkswap --check /dev/sdb");
  assertAllows("mkswap -L swap1 --check /dev/sdb1");
});

test("disk: unrelated commands no match (disk_unrelated_commands_no_match)", () => {
  assertAllows("git status");
  assertAllows("echo hello");
  assertAllows("cargo build");
});

// ---------------------------------------------------------------------------
// system.permissions (DCG permissions.rs::tests)
// ---------------------------------------------------------------------------

test("perms: quote bypass does not evade system-dir block", () => {
  assertBlocks('chmod -R 0755 "/etc"', "critical", "chmod-recursive-root");
  assertBlocks(
    "chmod -R 0755 '/usr/local'",
    "critical",
    "chmod-recursive-root",
  );
  assertBlocks('chown -R user:user "/var"', "high", "chown-recursive-root");
  assertBlocks("chown --recursive root '/etc'", "high", "chown-recursive-root");
  assertBlocks('setfacl -R -m u:app:rwx "/etc"', "critical", "setfacl-all");
  assertBlocks("chmod -R 0755 /etc", "critical", "chmod-recursive-root");
});

test("perms: blocks each destructive pattern (permissions_blocks_each_destructive_pattern)", () => {
  assertBlocks("chmod 777 /tmp/myfile");
  assertBlocks("chmod -R 755 /etc");
  assertBlocks("chown -R user:group /var");
  assertBlocks("chmod u+s /usr/bin/myapp");
  assertBlocks("chmod g+s /shared");
  assertBlocks("chown root: /tmp/myfile");
  assertBlocks("setfacl -R -m u:app:rwx /etc");
});

test("perms: blocks with correct severity (permissions_blocks_with_correct_severity)", () => {
  assertBlocks("chmod 777 /tmp/myfile", "high");
  assertBlocks("chmod -R 755 /etc", "critical");
  assertBlocks("chown -R user:group /var", "high");
  assertBlocks("chmod u+s /usr/bin/myapp", "high");
  assertBlocks("setfacl -R -m u:app:rwx /etc", "critical");
});

test("perms: all safe patterns allow (permissions_all_safe_patterns_match)", () => {
  assertAllows("chmod 755 myfile");
  assertAllows("stat /tmp/myfile");
  assertAllows("ls -la /tmp");
  assertAllows("getfacl /tmp/myfile");
  assertAllows("namei -l /tmp/myfile");
});

// ---------------------------------------------------------------------------
// system.services (DCG services.rs::tests)
// ---------------------------------------------------------------------------

test("services: shutdown + reboot reachable & block", () => {
  assertBlocks("shutdown -h now", "critical", "shutdown");
  assertBlocks("reboot", "critical", "reboot");
});

test("services: systemctl global flags do not bypass", () => {
  assertBlocks(
    "systemctl -H remote-host stop sshd",
    "high",
    "systemctl-stop-critical",
  );
  assertBlocks("systemctl --user disable my-unit", "high", "systemctl-stop");
  assertBlocks(
    "systemctl -M machine mask containerd",
    "high",
    "systemctl-stop-critical",
  );
  assertBlocks("systemctl --system poweroff", "critical", "systemctl-power");
  assertBlocks(
    "systemctl -H host isolate rescue.target",
    "high",
    "systemctl-isolate",
  );
  // Safe patterns with global flags still short-circuit.
  assertAllows("systemctl -H remote-host status sshd");
  assertAllows("systemctl --user list-units");
});

test("services: blocks with correct severity (services_blocks_with_correct_severity)", () => {
  assertBlocks("systemctl stop sshd", "high");
  assertBlocks("systemctl disable docker", "high");
  assertBlocks("systemctl mask networking", "high");
  assertBlocks("service ssh stop", "high");
  assertBlocks("systemctl isolate rescue.target", "high");
  assertBlocks("systemctl poweroff", "critical");
  assertBlocks("systemctl reboot", "critical");
  assertBlocks("shutdown -h now", "critical");
  assertBlocks("reboot", "critical");
  assertBlocks("init 0", "critical");
  assertBlocks("init 6", "critical");
});

test("services: unrelated commands no match (services_unrelated_commands_no_match)", () => {
  assertAllows("git status");
  assertAllows("echo hello");
});
