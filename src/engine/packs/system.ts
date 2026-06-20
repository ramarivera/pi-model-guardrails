// System pack — protections for system administration commands.
//
// Faithful port of THREE DCG system sub-packs collapsed into one Pack module:
//   - DCG `src/packs/system/disk.rs`        (id "system.disk")
//   - DCG `src/packs/system/permissions.rs` (id "system.permissions")
//   - DCG `src/packs/system/services.rs`    (id "system.services")
// (https://github.com/Dicklesworthstone/destructive_command_guard).
//
// The task contract for this repo is "one TS module -> one exported Pack", so
// the three DCG packs are merged here under id "system" with their keywords,
// safe patterns, and destructive patterns concatenated in DCG sub-pack order
// (disk -> permissions -> services). Declaration order is load-bearing
// (first-match-wins per text), and within each sub-pack the order matches DCG's
// `create_safe_patterns()` / `create_destructive_patterns()` exactly.
//
// force: true — this pack carries the disk-wipe tier (DCG `system.disk`, the
// dd/mkfs/wipefs/LVM destruction floor), so the whole pack is always enabled.
//
// JS RegExp porting notes (same rules as the committed core packs):
//  - POSIX `[[:alnum:]]` does not appear in these patterns.
//  - All DCG patterns here are case-sensitive (no inline `(?i)`), so NONE of
//    these RegExp carry the "i" flag.
//  - DCG's `regex` + `fancy_regex` dual engine collapses to one JS RegExp:
//    JS RegExp natively supports the lookahead `(?!...)` / `(?=...)` and
//    `\b` word boundaries used here.
//  - Rust raw strings (`r"..."` / `r#"..."#`) preserve backslashes literally;
//    in JS regex literals `/` is escaped as `\/`. No possessive quantifiers
//    exist in these patterns.
//  - DCG `destructive_pattern!(name, re, reason)` (3-arg) defaults severity to
//    High; the 4-arg form carries the explicit severity. Each rule's severity
//    below matches DCG verbatim.

import type { DestructiveRule, Pack, SafeRule } from "../types.ts";

// ---------------------------------------------------------------------------
// Safe patterns (allowed) — concatenation of DCG disk -> permissions ->
// services `create_safe_patterns()`, in declaration order.
// ---------------------------------------------------------------------------

const safePatterns: SafeRule[] = [
  // ===== system.disk safe patterns =====
  // dd to regular files is generally safe.
  { name: "dd-file-out", re: /dd\s+.*of=['"]?[^/\s'"]+\./ },
  // dd to /dev/null|zero|full is safe (discard output). Optional quotes.
  { name: "dd-discard", re: /dd\s+.*of=['"]?\/dev\/(?:null|zero|full)['"]?(?:\s|$)/ },
  // lsblk is safe (read-only).
  { name: "lsblk", re: /\blsblk\b/ },
  // fdisk -l (list) is safe.
  { name: "fdisk-list", re: /fdisk\s+-l/ },
  // parted print is safe.
  {
    name: "parted-print",
    re: /parted\b(?:\s+--?\S+)*\s+(?:['"]?\/dev\/\S+['"]?\s+)?print(?:\s+(?:devices|free|list|all|\d+))?\s*$/,
  },
  // blkid is safe (read-only).
  { name: "blkid", re: /\bblkid\b/ },
  // df is safe.
  { name: "df", re: /\bdf\b/ },
  // mount (without arguments, just list).
  { name: "mount-list", re: /\bmount\s*$/ },
  // mkswap --check (read-only inspection of swap area).
  { name: "mkswap-check", re: /mkswap\s+(?:.*\s+)?--check\b/ },
  // --- mdadm safe patterns ---
  { name: "mdadm-detail", re: /mdadm\s+--detail\b/ },
  { name: "mdadm-examine", re: /mdadm\s+--examine\b/ },
  { name: "mdadm-query", re: /mdadm\s+--query\b/ },
  { name: "mdadm-query-short", re: /mdadm\s+-Q\b/ },
  { name: "mdadm-scan", re: /mdadm\s+--scan\b/ },
  // --- btrfs safe patterns ---
  {
    name: "btrfs-subvolume-list",
    re: /btrfs\b(?:\s+--?\S+(?:\s+\S+)?)*\s+subvolume\s+list(?=\s|$)/,
  },
  {
    name: "btrfs-subvolume-show",
    re: /btrfs\b(?:\s+--?\S+(?:\s+\S+)?)*\s+subvolume\s+show(?=\s|$)/,
  },
  {
    name: "btrfs-filesystem-show",
    re: /btrfs\b(?:\s+--?\S+(?:\s+\S+)?)*\s+filesystem\s+show(?=\s|$)/,
  },
  {
    name: "btrfs-filesystem-df",
    re: /btrfs\b(?:\s+--?\S+(?:\s+\S+)?)*\s+filesystem\s+df(?=\s|$)/,
  },
  {
    name: "btrfs-filesystem-usage",
    re: /btrfs\b(?:\s+--?\S+(?:\s+\S+)?)*\s+filesystem\s+usage(?=\s|$)/,
  },
  {
    name: "btrfs-device-stats",
    re: /btrfs\b(?:\s+--?\S+(?:\s+\S+)?)*\s+device\s+stats(?=\s|$)/,
  },
  {
    name: "btrfs-property-get",
    re: /btrfs\b(?:\s+--?\S+(?:\s+\S+)?)*\s+property\s+(?:get|list)(?=\s|$)/,
  },
  {
    name: "btrfs-scrub-status",
    re: /btrfs\b(?:\s+--?\S+(?:\s+\S+)?)*\s+scrub\s+status(?=\s|$)/,
  },
  // --- dmsetup safe patterns ---
  { name: "dmsetup-ls", re: /dmsetup\b(?:\s+--?\S+(?:\s+\S+)?)*\s+ls(?=\s|$)/ },
  { name: "dmsetup-status", re: /dmsetup\b(?:\s+--?\S+(?:\s+\S+)?)*\s+status(?=\s|$)/ },
  { name: "dmsetup-info", re: /dmsetup\b(?:\s+--?\S+(?:\s+\S+)?)*\s+info(?=\s|$)/ },
  { name: "dmsetup-table", re: /dmsetup\b(?:\s+--?\S+(?:\s+\S+)?)*\s+table(?=\s|$)/ },
  { name: "dmsetup-deps", re: /dmsetup\b(?:\s+--?\S+(?:\s+\S+)?)*\s+deps(?=\s|$)/ },
  // --- nbd-client safe patterns ---
  { name: "nbd-client-list", re: /nbd-client\s+-l\b/ },
  { name: "nbd-client-check", re: /nbd-client\s+.*-check\b/ },
  // --- LVM safe patterns (read-only) ---
  { name: "lvm-list", re: /\b(?:lvs|vgs|pvs)\b/ },
  { name: "lvm-display", re: /\b(?:lvdisplay|vgdisplay|pvdisplay)\b/ },
  { name: "lvm-scan", re: /\b(?:lvscan|vgscan|pvscan)\b/ },

  // ===== system.permissions safe patterns =====
  // chmod on files (not directories recursively).
  {
    name: "chmod-non-recursive",
    re: /chmod\s+(?!-[rR])(?:\d{3,4}|[ugoa][+-][rwxXst]+)\s+[^/]/,
  },
  // stat is safe (read-only).
  { name: "stat", re: /\bstat\b/ },
  // ls -l is safe.
  { name: "ls-perms", re: /ls\s+.*-[a-zA-Z]*l/ },
  // getfacl is safe (read-only).
  { name: "getfacl", re: /\bgetfacl\b/ },
  // namei is safe.
  { name: "namei", re: /\bnamei\b/ },

  // ===== system.services safe patterns =====
  // status commands are safe.
  {
    name: "systemctl-status",
    re: /systemctl\b(?:\s+--?\S+(?:\s+\S+)?)*\s+status(?=\s|$)/,
  },
  { name: "service-status", re: /service\s+\S+\s+status(?=\s|$)/ },
  // list commands are safe.
  {
    name: "systemctl-list",
    re: /systemctl\b(?:\s+--?\S+(?:\s+\S+)?)*\s+list-(?:units|unit-files|sockets|timers)(?=\s|$)/,
  },
  // show is safe.
  { name: "systemctl-show", re: /systemctl\b(?:\s+--?\S+(?:\s+\S+)?)*\s+show(?=\s|$)/ },
  // is-active/is-enabled are safe.
  {
    name: "systemctl-is",
    re: /systemctl\b(?:\s+--?\S+(?:\s+\S+)?)*\s+is-(?:active|enabled|failed)(?=\s|$)/,
  },
  // daemon-reload is generally safe.
  {
    name: "systemctl-reload",
    re: /systemctl\b(?:\s+--?\S+(?:\s+\S+)?)*\s+daemon-reload(?=\s|$)/,
  },
  // cat is safe (view unit file).
  { name: "systemctl-cat", re: /systemctl\b(?:\s+--?\S+(?:\s+\S+)?)*\s+cat(?=\s|$)/ },
  // journalctl is safe (logs).
  { name: "journalctl", re: /\bjournalctl\b/ },
];

// ---------------------------------------------------------------------------
// Destructive patterns (blocked) — concatenation of DCG disk -> permissions ->
// services `create_destructive_patterns()`, in declaration order
// (first-match-wins is load-bearing).
// ---------------------------------------------------------------------------

const destructivePatterns: DestructiveRule[] = [
  // ===== system.disk destructive patterns (all High, DCG 3-arg form) =====
  {
    name: "dd-device",
    re: /dd\s+.*of=['"]?\/dev\//,
    severity: "high",
    reason:
      "dd to a block device will OVERWRITE all data on that device. Extremely dangerous!",
  },
  {
    name: "dd-wipe",
    re: /dd\s+.*if=['"]?\/dev\/(?:zero|urandom|random).*of=['"]?\/dev\//,
    severity: "high",
    reason: "dd from /dev/zero or /dev/urandom to a device will WIPE all data!",
  },
  {
    name: "fdisk-edit",
    re: /fdisk\s+['"]?\/dev\/(?!.*-l)/,
    severity: "high",
    reason: "fdisk can modify partition tables and cause data loss.",
  },
  {
    name: "parted-modify",
    re: /parted\b[^\n;&|]*?['"]?\/dev\/\S+['"]?(?:\s+--)?\s+(?:(?!\s*(?:align-check|help|h|print|p|quit|q|select|unit|u)\b)|[^\n;&|]*\b(?:print|p)\b\s+(?:(?:devices|free|list|all|\d+)\s+\S+|(?!devices\b|free\b|list\b|all\b|\d+\b)\S+)|[^\n;&|]*\b(?:disk_set|disk_toggle|mklabel|mktable|mkpart|name|rescue|resizepart|rm|set|toggle|type)\b)/,
    severity: "high",
    reason: "parted can modify partition tables and cause data loss.",
  },
  {
    name: "mkfs",
    re: /mkfs(?:\.[a-z0-9]+)?\s+/,
    severity: "high",
    reason: "mkfs formats a partition/device and ERASES all existing data.",
  },
  {
    name: "mkswap",
    re: /mkswap\s+/,
    severity: "high",
    reason: "mkswap formats a partition as a swap area, ERASING any existing data.",
  },
  {
    name: "wipefs",
    re: /wipefs\s+/,
    severity: "high",
    reason: "wipefs removes filesystem signatures. Use with extreme caution.",
  },
  {
    name: "mount-bind-root",
    re: /mount\s+.*--bind\s+.*\s+['"]?\/(?:$|[^a-z])/,
    severity: "high",
    reason: "mount --bind to root directory can have system-wide effects.",
  },
  {
    name: "umount-force",
    re: /umount\s+.*-[a-z]*f/,
    severity: "high",
    reason: "umount -f force unmounts which may cause data loss if device is in use.",
  },
  {
    name: "losetup-device",
    re: /losetup\s+['"]?\/dev\/loop/,
    severity: "high",
    reason: "losetup modifies loop device associations. Verify before proceeding.",
  },
  // --- mdadm destructive patterns ---
  {
    name: "mdadm-stop",
    re: /mdadm\s+(?:.*\s+)?(?:--stop|-S)\b/,
    severity: "high",
    reason: "mdadm --stop shuts down a RAID array. Data may become inaccessible.",
  },
  {
    name: "mdadm-remove",
    re: /mdadm\s+(?:.*\s+)?--remove\b/,
    severity: "high",
    reason:
      "mdadm --remove removes a drive from a RAID array. May cause data loss if redundancy is lost.",
  },
  {
    name: "mdadm-fail",
    re: /mdadm\s+(?:.*\s+)?(?:--fail|-f)\b/,
    severity: "high",
    reason:
      "mdadm --fail marks a device as failed. Use only for intentional drive replacement.",
  },
  {
    name: "mdadm-zero-superblock",
    re: /mdadm\s+(?:.*\s+)?--zero-superblock\b/,
    severity: "high",
    reason:
      "mdadm --zero-superblock PERMANENTLY erases RAID metadata. Array cannot be reassembled.",
  },
  {
    name: "mdadm-create",
    re: /mdadm\s+(?:.*\s+)?(?:--create|-C)\b/,
    severity: "high",
    reason:
      "mdadm --create initializes a new RAID array, ERASING existing data on member devices.",
  },
  {
    name: "mdadm-grow",
    re: /mdadm\s+(?:.*\s+)?--grow\b/,
    severity: "high",
    reason:
      "mdadm --grow reshapes a RAID array. Interruption can cause data loss. Backup first.",
  },
  // --- btrfs destructive patterns ---
  {
    name: "btrfs-subvolume-delete",
    re: /btrfs\b.*?\s+subvolume\s+delete\b/,
    severity: "high",
    reason: "btrfs subvolume delete PERMANENTLY removes a subvolume and all its data.",
  },
  {
    name: "btrfs-device-remove",
    re: /btrfs\b.*?\s+device\s+(?:remove|delete)\b/,
    severity: "high",
    reason:
      "btrfs device remove redistributes data off a device. Interruption causes data loss.",
  },
  {
    name: "btrfs-device-add",
    re: /btrfs\b.*?\s+device\s+add\b/,
    severity: "high",
    reason:
      "btrfs device add incorporates a device into the filesystem. Verify the device is correct.",
  },
  {
    name: "btrfs-balance",
    re: /btrfs\b.*?\s+balance\s+start\b/,
    severity: "high",
    reason: "btrfs balance redistributes data across devices. Can be slow and disruptive.",
  },
  {
    name: "btrfs-check-repair",
    re: /btrfs\b.*?\s+check\s+(?:.*\s+)?--repair\b/,
    severity: "high",
    reason: "btrfs check --repair is DANGEROUS and can cause data loss. Backup first!",
  },
  {
    name: "btrfs-rescue",
    re: /btrfs\b.*?\s+rescue\b/,
    severity: "high",
    reason:
      "btrfs rescue operations modify filesystem metadata. Use only as last resort.",
  },
  {
    name: "btrfs-filesystem-resize",
    re: /btrfs\b.*?\s+filesystem\s+resize\b/,
    severity: "high",
    reason:
      "btrfs filesystem resize can shrink a filesystem. Data loss if size is too small.",
  },
  // --- dmsetup destructive patterns ---
  {
    name: "dmsetup-remove",
    re: /dmsetup\b.*?\s+remove\b/,
    severity: "high",
    reason:
      "dmsetup remove detaches a device-mapper device. May cause data loss if in use.",
  },
  {
    name: "dmsetup-remove-all",
    re: /dmsetup\b.*?\s+remove_all\b/,
    severity: "high",
    reason: "dmsetup remove_all removes ALL device-mapper devices. Extremely dangerous!",
  },
  {
    name: "dmsetup-wipe-table",
    re: /dmsetup\b.*?\s+wipe_table\b/,
    severity: "high",
    reason: "dmsetup wipe_table replaces the device table, causing all I/O to fail.",
  },
  {
    name: "dmsetup-clear",
    re: /dmsetup\b.*?\s+clear\b/,
    severity: "high",
    reason: "dmsetup clear removes the mapping table from a device.",
  },
  {
    name: "dmsetup-load",
    re: /dmsetup\b.*?\s+load\b/,
    severity: "high",
    reason: "dmsetup load changes device mapping. Verify the new table is correct.",
  },
  {
    name: "dmsetup-create",
    re: /dmsetup\b.*?\s+create\b/,
    severity: "high",
    reason:
      "dmsetup create sets up a new device-mapper device. Verify parameters carefully.",
  },
  // --- nbd-client destructive patterns ---
  {
    name: "nbd-client-disconnect",
    re: /nbd-client\s+(?:.*\s+)?-d\b/,
    severity: "high",
    reason:
      "nbd-client -d disconnects a network block device. Data loss if not properly unmounted.",
  },
  {
    name: "nbd-client-connect",
    re: /nbd-client\s+\S+\s+\d+\s+['"]?\/dev\/nbd/,
    severity: "high",
    reason:
      "nbd-client connecting a device can expose or overwrite data. Verify server and device.",
  },
  // --- LVM destructive patterns ---
  {
    name: "pvremove",
    re: /\bpvremove\b/,
    severity: "high",
    reason:
      "pvremove ERASES LVM metadata from a physical volume. Data becomes inaccessible.",
  },
  {
    name: "vgremove",
    re: /\bvgremove\b/,
    severity: "high",
    reason: "vgremove DELETES a volume group and all logical volumes within it.",
  },
  {
    name: "lvremove",
    re: /\blvremove\b/,
    severity: "high",
    reason: "lvremove PERMANENTLY deletes a logical volume and ALL its data.",
  },
  {
    name: "vgreduce",
    re: /\bvgreduce\b/,
    severity: "high",
    reason: "vgreduce removes a physical volume from a volume group. Data may be lost.",
  },
  {
    name: "lvreduce",
    re: /\blvreduce\b/,
    severity: "high",
    reason:
      "lvreduce SHRINKS a logical volume. Data loss if filesystem isn't resized first!",
  },
  {
    name: "lvresize-shrink",
    re: /lvresize\s+(?:.*\s+)?(?:-L\s*-|-l\s*-|--size\s+\S*-)/,
    severity: "high",
    reason:
      "lvresize with negative size SHRINKS the volume. Resize filesystem first or lose data!",
  },
  {
    name: "pvmove",
    re: /\bpvmove\b/,
    severity: "high",
    reason:
      "pvmove migrates data between physical volumes. Do NOT interrupt or data may be lost.",
  },
  {
    name: "lvconvert-merge",
    re: /lvconvert\s+(?:.*\s+)?--merge\b/,
    severity: "high",
    reason:
      "lvconvert --merge reverts LV to snapshot state, discarding changes since snapshot.",
  },

  // ===== system.permissions destructive patterns =====
  {
    name: "chmod-777",
    re: /chmod\s+(?:.*\s+)?["'=]?0*777(?:[\s"']|$)/,
    severity: "high",
    reason: "chmod 777 makes files world-writable. This is a security risk.",
    explanation:
      "chmod 777 grants read/write/execute to everyone. This can expose sensitive " +
      "files and allow unauthorized modification. Prefer least-privilege permissions " +
      "that only grant the specific access needed.",
    suggestions: [
      {
        command: "chmod 755 {path}",
        description: "Owner can write; others can read/execute (safer default)",
        platform: "all",
      },
      {
        command: "chmod u+x {path}",
        description: "Only add execute for owner instead of world-writable permissions",
        platform: "all",
      },
    ],
  },
  {
    name: "chmod-recursive-root",
    re: /chmod\s+(?:.*(?:-[rR]|--recursive)).*\s+['"]?\/(?:$|bin|boot|dev|etc|lib|lib64|opt|proc|root|run|sbin|srv|sys|usr|var)\b/,
    severity: "critical",
    reason: "chmod -R on system directories can break system permissions.",
    explanation:
      "Recursively changing permissions on system directories can render the system " +
      "unbootable, break package management, and disrupt every running service. Many " +
      "system files require specific permission bits to function correctly.\n\n" +
      "Check current permissions first:\n  " +
      "ls -la /path/to/directory\n\n" +
      "Apply changes to a specific subdirectory instead of the whole tree.",
  },
  {
    name: "chown-recursive-root",
    re: /chown\s+(?:.*(?:-[rR]|--recursive)).*\s+['"]?\/(?:$|bin|boot|dev|etc|lib|lib64|opt|proc|root|run|sbin|srv|sys|usr|var)\b/,
    severity: "high",
    reason: "chown -R on system directories can break system ownership.",
    explanation:
      "Recursive ownership changes on system directories can disrupt services, " +
      "break package-managed files, and be difficult to undo. Start with a single " +
      "path or a shallow find before applying broader changes.",
    suggestions: [
      {
        command: "chown {user} {path}",
        description: "Change ownership of a single path first",
        platform: "all",
      },
      {
        command: "find {path} -maxdepth 1 -exec chown {user} {} \\;",
        description: "Limit ownership changes to top-level entries",
        platform: "all",
      },
    ],
  },
  {
    name: "chmod-setuid",
    re: /chmod\s+.*u\+s|chmod\s+[4-7]\d{3}/,
    severity: "high",
    reason: "Setting setuid bit (chmod u+s) is a security-sensitive operation.",
    explanation:
      "The setuid bit causes a program to run with the file owner's privileges " +
      "regardless of who executes it. If set on the wrong binary, any user can " +
      "gain elevated access. This is a common privilege escalation vector.\n\n" +
      "Verify the file and owner first:\n  " +
      "ls -la <file>\n\n" +
      "Find existing setuid files:\n  " +
      "find / -perm -4000 -type f 2>/dev/null",
  },
  {
    name: "chmod-setgid",
    re: /chmod\s+.*g\+s|chmod\s+[2367]\d{3}/,
    severity: "high",
    reason: "Setting setgid bit (chmod g+s) is a security-sensitive operation.",
    explanation:
      "The setgid bit on an executable causes it to run with the file group's " +
      "privileges. On a directory, new files inherit the directory's group. " +
      "Misapplication can grant unintended group access to sensitive resources.\n\n" +
      "Check current group ownership:\n  " +
      "ls -la <file>\n\n" +
      "Find existing setgid files:\n  " +
      "find / -perm -2000 -type f 2>/dev/null",
  },
  {
    name: "chown-to-root",
    re: /chown\s+.*root[:\s]/,
    severity: "high",
    reason: "Changing ownership to root should be done carefully.",
    explanation:
      "Transferring file ownership to root makes the files inaccessible to normal " +
      "users and may break applications that need to write to those files. Services " +
      "running as non-root users will lose access.\n\n" +
      "Check who currently owns the file:\n  " +
      "ls -la <path>\n\n" +
      "Consider using group ownership instead:\n  " +
      "chgrp <group> <path>",
  },
  {
    name: "setfacl-all",
    re: /setfacl\s+.*-[rR].*\s+['"]?\/(?:$|bin|boot|dev|etc|lib|lib64|opt|proc|root|run|sbin|srv|sys|usr|var)\b/,
    severity: "critical",
    reason:
      "setfacl -R on system directories can modify access control across the filesystem.",
    explanation:
      "Recursively modifying ACLs on system directories changes fine-grained access " +
      "control for every file in the tree. This can override traditional Unix " +
      "permissions and grant or revoke access in unexpected ways, breaking services " +
      "and security boundaries.\n\n" +
      "Review current ACLs first:\n  " +
      "getfacl <path>\n\n" +
      "Apply to a specific file instead of recursively:\n  " +
      "setfacl -m u:<user>:rwx <specific-file>",
  },

  // ===== system.services destructive patterns =====
  {
    name: "systemctl-stop-critical",
    re: /systemctl\b.*?\s+(?:stop|disable|mask)\s+(?:ssh|sshd|network|networking|firewalld|ufw|docker|containerd)\b/,
    severity: "high",
    reason:
      "Stopping/disabling critical services can cause system access loss or outage.",
    explanation:
      "Stopping, disabling, or masking a critical system service can lock you out " +
      "of the machine or cause cascading failures. For example, stopping sshd severs " +
      "remote access, stopping networking drops all connections, and stopping docker " +
      "kills every running container.\n\n" +
      "Check current state first:\n  " +
      "systemctl status <service>\n\n" +
      "If you need to restart rather than stop:\n  " +
      "systemctl restart <service>",
  },
  {
    name: "systemctl-stop",
    re: /systemctl\b.*?\s+(?:stop|disable|mask)\b/,
    severity: "high",
    reason:
      "systemctl stop/disable/mask affects service availability. Verify service name.",
    explanation:
      "Stopping a service immediately terminates it; disabling prevents it from " +
      "starting at boot; masking makes it impossible to start even manually. Each " +
      "has different severity and reversibility.\n\n" +
      "Check what depends on the service:\n  " +
      "systemctl list-dependencies --reverse <service>\n\n" +
      "To temporarily stop without disabling:\n  " +
      "systemctl stop <service>  (restarts on reboot)",
  },
  {
    name: "service-stop-critical",
    re: /service\s+(?:ssh|sshd|network|networking|docker)\s+stop/,
    severity: "high",
    reason: "Stopping critical services can cause system access loss.",
    explanation:
      "The legacy 'service' command stops a critical service immediately. Stopping " +
      "sshd terminates remote access, stopping networking drops all connections. " +
      "If you are connected remotely, you may be unable to reconnect.\n\n" +
      "Check status first:\n  " +
      "service <name> status\n\n" +
      "Prefer systemctl on systemd systems:\n  " +
      "systemctl status <name>",
  },
  {
    name: "systemctl-isolate",
    re: /systemctl\b.*?\s+isolate\b/,
    severity: "high",
    reason: "systemctl isolate changes the system state significantly.",
    explanation:
      "Isolating a target stops all services not required by that target. For " +
      "example, isolating rescue.target drops to single-user mode, stopping " +
      "networking, display managers, and most daemons. This is equivalent to " +
      "changing the runlevel and can be very disruptive.\n\n" +
      "Check current target:\n  " +
      "systemctl get-default\n\n" +
      "List active targets:\n  " +
      "systemctl list-units --type=target",
  },
  {
    name: "systemctl-power",
    re: /systemctl\b.*?\s+(?:poweroff|reboot|halt|suspend|hibernate)\b/,
    severity: "critical",
    reason: "systemctl poweroff/reboot/halt will shut down or restart the system.",
    explanation:
      "This immediately initiates a system power state change. Poweroff and halt " +
      "shut down the machine, reboot restarts it, and suspend/hibernate save state " +
      "to RAM or disk. Any unsaved work, running processes, or active connections " +
      "will be interrupted.\n\n" +
      "Check who is logged in:\n  " +
      "who\n\n" +
      'Schedule a graceful shutdown instead:\n  ' +
      'shutdown +5 "Rebooting for maintenance"',
  },
  {
    name: "shutdown",
    re: /\bshutdown\b/,
    severity: "critical",
    reason: "shutdown will power off or restart the system.",
    explanation:
      "The shutdown command powers off or restarts the machine. All running " +
      "processes receive SIGTERM then SIGKILL, all filesystems are unmounted, " +
      "and the system goes down. Remote users lose access immediately.\n\n" +
      "To cancel a pending shutdown:\n  " +
      "shutdown -c\n\n" +
      "To schedule with warning:\n  " +
      'shutdown +10 "System going down for maintenance"',
  },
  {
    name: "reboot",
    re: /\breboot\b/,
    severity: "critical",
    reason: "reboot will restart the system.",
    explanation:
      "Reboot restarts the machine immediately. All processes are terminated, " +
      "connections are dropped, and the system goes through a full restart cycle. " +
      "Any unsaved work is lost and services will be briefly unavailable.\n\n" +
      "Check uptime and load before deciding:\n  " +
      "uptime\n\n" +
      "For a delayed reboot with notice:\n  " +
      'shutdown -r +5 "Rebooting in 5 minutes"',
  },
  {
    name: "init-level",
    re: /\binit\s+[06]\b/,
    severity: "critical",
    reason: "init 0 shuts down, init 6 reboots the system.",
    explanation:
      "Changing the init level to 0 halts the system and to 6 reboots it. This " +
      "is the legacy SysV method for power management and takes effect immediately. " +
      "All processes are killed and the machine goes down.\n\n" +
      "On systemd systems, prefer:\n  " +
      "systemctl poweroff  (instead of init 0)\n  " +
      "systemctl reboot    (instead of init 6)\n\n" +
      "Check current runlevel:\n  " +
      "runlevel",
  },
];

/**
 * System pack — merged DCG system.disk + system.permissions + system.services.
 *
 * `force: true` — carries the disk-wipe tier (DCG `system.disk`), the always-on
 * dd/mkfs/wipefs/LVM destruction floor.
 *
 * Keywords are the union of the three DCG sub-packs' keyword arrays, in
 * sub-pack order (disk -> permissions -> services). The quick-reject prefilter
 * stays a conservative superset (Pack::might_match), so the union never wrongly
 * rejects a command any individual sub-pack would have checked.
 *
 * Source: DCG `src/packs/system/{disk,permissions,services}.rs` (`create_pack`).
 */
export const systemPack: Pack = {
  id: "system",
  name: "System",
  description:
    "Protects against destructive system operations: disk operations " +
    "(dd to devices, mkfs, partition/RAID/LVM/device-mapper), dangerous " +
    "permission changes (chmod 777, recursive chmod/chown on system dirs), " +
    "and dangerous service operations (stopping critical services, shutdown/reboot)",
  keywords: [
    // system.disk
    "dd",
    "fdisk",
    "mkfs",
    "mkswap",
    "parted",
    "mount",
    "wipefs",
    "/dev/",
    "mdadm",
    "btrfs",
    "dmsetup",
    "nbd-client",
    "pvremove",
    "vgremove",
    "lvremove",
    "vgreduce",
    "lvreduce",
    "lvresize",
    "pvmove",
    // system.permissions
    "chmod",
    "chown",
    "chgrp",
    "setfacl",
    // system.services
    "systemctl",
    "service",
    "init",
    "upstart",
    "shutdown",
    "reboot",
  ],
  safePatterns,
  destructivePatterns,
  force: true,
};
