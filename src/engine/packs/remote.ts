// Remote pack — remote sync/access tooling (ssh, scp, rsync).
//
// Faithful port of DCG's three remote sub-packs into ONE Pack:
//   - src/packs/remote/ssh.rs    -> id "remote.ssh"
//   - src/packs/remote/scp.rs    -> id "remote.scp"
//   - src/packs/remote/rsync.rs  -> id "remote.rsync"
// (https://github.com/Dicklesworthstone/destructive_command_guard)
//
// MERGE NOTE: DCG ships these as three `create_pack()`s with their own
// snake_case ids. The Pi module contract asks for ONE `remotePack`, so the
// rule sets are concatenated into a single Pack with id "remote". Rule NAMES
// are already tool-prefixed in DCG (`ssh-*`, `scp-*`, `rsync-*`) so they stay
// unique unchanged. reason/explanation/severity and per-tool declaration
// order are preserved 1:1. ssh / scp / rsync are different executables (the
// tool groups are disjoint), so cross-tool order is not load-bearing.
//
// JS RegExp porting notes (this category):
//  - No POSIX classes, no possessive quantifiers, no inline `(?i)` flags. All
//    patterns are case-sensitive, so NONE carry the "i" flag.
//  - The ssh destructive patterns are Rust raw strings `r#"...['"]..."#` where
//    `['"]`/`['\"]` is a char class matching `'` or `"`. In JS regex literals
//    that is `['"]` (only `/` would need escaping; none appears literally).
//  - The `\.\.` (literal `..`) and `(?!\S*\.\./)` traversal guards in scp's
//    safe rules are ported verbatim.

import type { DestructiveRule, Pack, SafeRule } from "../types.ts";

// ============================================================================
// ssh — DCG src/packs/remote/ssh.rs
// ============================================================================

const sshSafe: SafeRule[] = [
  { name: "ssh-version", re: /ssh\s+-V\b/ },
  { name: "ssh-version-long", re: /ssh\s+--version\b/ },
  { name: "ssh-keygen-list", re: /ssh-keygen\s+.*-l\b/ },
  { name: "ssh-keygen-fingerprint", re: /ssh-keygen\s+.*-lf?\b/ },
  { name: "ssh-keyscan", re: /ssh-keyscan\b/ },
  { name: "ssh-add-list", re: /ssh-add\s+-[lL]\b/ },
  { name: "ssh-agent", re: /ssh-agent\b/ },
  { name: "ssh-help", re: /ssh\s+--?h(elp)?\b/ },
  { name: "ssh-keygen-help", re: /ssh-keygen\s+--?h(elp)?\b/ },
];

const sshDestructive: DestructiveRule[] = [
  {
    name: "ssh-remote-rm-rf",
    re: /ssh\s+(?:\S+\s+)*(?:-[A-Za-z]+\s+)*\S+[@:]?\S*\s+['"]?.*\brm\s+-[a-zA-Z]*r[a-zA-Z]*f/,
    severity: "critical",
    reason: "SSH remote execution contains destructive rm -rf command.",
    explanation:
      "Executing rm -rf on a remote system via SSH can cause irreversible data loss. " +
      "Remote systems often have different directory structures and you may not have " +
      "the same safety mechanisms in place.\n\n" +
      "Safer alternatives:\n" +
      "- SSH in and run commands interactively with confirmation\n" +
      "- Use --dry-run or preview flags when available\n" +
      "- Ensure backups exist on the remote system",
  },
  {
    name: "ssh-remote-git-reset-hard",
    re: /ssh\s+(?:\S+\s+)*(?:-[A-Za-z]+\s+)*\S+[@:]?\S*\s+['"]?.*\bgit\s+reset\s+--hard\b/,
    severity: "high",
    reason:
      "SSH remote execution contains destructive git reset --hard command.",
    explanation:
      "Running git reset --hard on a remote server discards all uncommitted changes. " +
      "On production servers, this might destroy deployment state or configuration " +
      "changes made directly on the server.\n\n" +
      "Safer alternatives:\n" +
      "- git stash on the remote first to save changes\n" +
      "- Use git status remotely to check for uncommitted work\n" +
      "- Consider proper deployment pipelines instead of direct remote git",
  },
  {
    name: "ssh-remote-git-clean",
    re: /ssh\s+(?:\S+\s+)*(?:-[A-Za-z]+\s+)*\S+[@:]?\S*\s+['"]?.*\bgit\s+clean\s+-[a-zA-Z]*f/,
    severity: "high",
    reason: "SSH remote execution contains destructive git clean -f command.",
    explanation:
      "Running git clean -f on a remote server permanently removes untracked files. " +
      "This might delete logs, uploads, or configuration files that were never " +
      "committed to the repository.\n\n" +
      "Safer alternatives:\n" +
      "- Run git clean -n first to preview what would be deleted\n" +
      "- Use .gitignore to protect important untracked files\n" +
      "- Back up untracked files before cleaning",
  },
  {
    name: "ssh-keygen-remove-host",
    re: /ssh-keygen\s+(?:\S+\s+)*-R\b/,
    severity: "medium",
    reason: "ssh-keygen -R removes entries from known_hosts file.",
    explanation:
      "Removing entries from known_hosts weakens protection against man-in-the-middle " +
      "attacks. The next connection will trust any key presented by the remote host.\n\n" +
      "Safer alternatives:\n" +
      "- Verify the new host key fingerprint before removing old entry\n" +
      "- Use ssh-keyscan to preview the new key\n" +
      "- Update entry rather than removing (add new key, then remove old)",
  },
  {
    name: "ssh-add-delete-all",
    re: /ssh-add\s+-[dD]\b/,
    severity: "medium",
    reason: "ssh-add -d/-D removes identities from the SSH agent.",
    explanation:
      "Removing SSH identities from the agent will require re-authentication for " +
      "subsequent connections. Using -D removes ALL identities, which may interrupt " +
      "active sessions or scripts.\n\n" +
      "Safer alternatives:\n" +
      "- Use -d to remove specific keys rather than -D for all\n" +
      "- List keys with ssh-add -l before removing\n" +
      "- Re-add keys immediately if needed",
  },
  {
    name: "ssh-remote-sudo-rm",
    re: /ssh\s+(?:\S+\s+)*\S+[@:]?\S*\s+['"]?.*\bsudo\s+rm\b/,
    severity: "critical",
    reason: "SSH remote execution with sudo rm is high-risk.",
    explanation:
      "Executing sudo rm on a remote system bypasses normal permission restrictions " +
      "and can delete system files. Combined with SSH, there's no interactive " +
      "confirmation and errors may not be visible.\n\n" +
      "Safer alternatives:\n" +
      "- SSH in and run sudo commands interactively\n" +
      "- Use mv to a backup location instead of rm\n" +
      "- Implement proper cleanup scripts with safety checks",
  },
];

// ============================================================================
// scp — DCG src/packs/remote/scp.rs
// ============================================================================

const scpSafe: SafeRule[] = [
  { name: "scp-help", re: /scp\b.*\s--?h(elp)?\b/ },
  { name: "scp-download", re: /scp\b.*\s(?:\S+@)?\S+:\S+\s+\.\S*\s*$/ },
  {
    name: "scp-to-home",
    re: /scp\b.*\s(?:(?:\S+@)?\S+:)?~\/(?!\S*\.\.\/)\S+\s*$/,
  },
  {
    name: "scp-to-tmp",
    re: /scp\b.*\s(?:(?:\S+@)?\S+:)?\/tmp\/(?!\S*\.\.\/)\S*\s*$/,
  },
  {
    name: "scp-to-var-tmp",
    re: /scp\b.*\s(?:(?:\S+@)?\S+:)?\/var\/tmp(?:\/(?!\S*\.\.\/)\S*)?\s*$/,
  },
];

const scpDestructive: DestructiveRule[] = [
  {
    name: "scp-recursive-root",
    re: /scp\b.*\s-[A-Za-z0-9]*r[A-Za-z0-9]*\b.*\s(?:(?:\S+@)?\S+:)?\/\s*$/,
    severity: "critical",
    reason: "scp -r to root (/) is extremely dangerous.",
    explanation:
      "Recursive copy to the root filesystem can overwrite critical system files, " +
      "potentially rendering the system unbootable. This affects all system directories " +
      "including /etc, /bin, /lib, and /boot.\n\n" +
      "Safer alternatives:\n" +
      "- Specify a target subdirectory instead of /\n" +
      "- Use rsync with --dry-run to preview changes\n" +
      "- Copy to /tmp first and move files individually",
  },
  {
    name: "scp-to-etc",
    re: /scp\b.*\s(?:(?:\S+@)?\S+:)?\/etc(?:\/\S*)?\s*$/,
    severity: "high",
    reason: "scp to /etc/ can overwrite system configuration.",
    explanation:
      "The /etc directory contains critical system configuration files including passwd, " +
      "shadow, fstab, and network settings. Overwriting these can lock you out of the " +
      "system or cause services to fail.\n\n" +
      "Safer alternatives:\n" +
      "- Copy to a staging directory first\n" +
      "- Back up existing files before overwriting\n" +
      "- Use configuration management tools (Ansible, etc.)",
  },
  {
    name: "scp-to-var",
    re: /scp\b.*\s(?:(?:\S+@)?\S+:)?\/var(?:\/\S*)?\s*$/,
    severity: "high",
    reason: "scp to /var/ can overwrite system data.",
    explanation:
      "The /var directory contains variable data including logs, databases, mail spools, " +
      "and application state. Overwriting this data can cause data loss and service " +
      "disruptions.\n\n" +
      "Safer alternatives:\n" +
      "- Use /var/tmp for temporary staging\n" +
      "- Stop affected services before modifying their data\n" +
      "- Back up existing data first",
  },
  {
    name: "scp-to-boot",
    re: /scp\b.*\s(?:(?:\S+@)?\S+:)?\/boot(?:\/\S*)?\s*$/,
    severity: "critical",
    reason: "scp to /boot/ can corrupt boot configuration.",
    explanation:
      "The /boot directory contains the kernel, initramfs, and bootloader configuration. " +
      "Corrupting these files will prevent the system from booting, requiring rescue " +
      "media to recover.\n\n" +
      "Safer alternatives:\n" +
      "- Use package manager for kernel updates\n" +
      "- Keep backup kernels available\n" +
      "- Test changes in a VM first",
  },
  {
    name: "scp-to-usr",
    re: /scp\b.*\s(?:(?:\S+@)?\S+:)?\/usr(?:\/\S*)?\s*$/,
    severity: "high",
    reason: "scp to /usr/ can overwrite system binaries.",
    explanation:
      "The /usr directory contains system binaries, libraries, and shared resources. " +
      "Overwriting files here can break system utilities and installed applications.\n\n" +
      "Safer alternatives:\n" +
      "- Use /usr/local for custom installations\n" +
      "- Use package managers for system updates\n" +
      "- Install to user directories when possible",
  },
  {
    name: "scp-to-bin",
    re: /scp\b.*\s(?:(?:\S+@)?\S+:)?\/(?:bin|sbin)(?:\/\S*)?\s*$/,
    severity: "critical",
    reason: "scp to /bin/ or /sbin/ can overwrite system binaries.",
    explanation:
      "The /bin and /sbin directories contain essential system binaries required for " +
      "basic operation. Overwriting these can make the system unusable and require " +
      "rescue mode recovery.\n\n" +
      "Safer alternatives:\n" +
      "- Install custom scripts to /usr/local/bin\n" +
      "- Use package managers for system updates\n" +
      "- Test binaries in user directories first",
  },
  {
    name: "scp-to-lib",
    re: /scp\b.*\s(?:(?:\S+@)?\S+:)?\/lib(?:64)?(?:\/\S*)?\s*$/,
    severity: "critical",
    reason: "scp to /lib/ can overwrite system libraries.",
    explanation:
      "The /lib and /lib64 directories contain shared libraries required by system " +
      "binaries. Overwriting these can cause immediate system instability and prevent " +
      "commands from running.\n\n" +
      "Safer alternatives:\n" +
      "- Use package managers for library updates\n" +
      "- Install custom libraries to /usr/local/lib\n" +
      "- Use LD_LIBRARY_PATH for testing",
  },
];

// ============================================================================
// rsync — DCG src/packs/remote/rsync.rs
// ============================================================================

const rsyncSafe: SafeRule[] = [
  { name: "rsync-dry-run", re: /rsync\b.*\s--dry-run\b/ },
  { name: "rsync-short-dry-run", re: /rsync\b.*\s+-[A-Za-z]*n[A-Za-z]*\b/ },
  { name: "rsync-list-only", re: /rsync\b.*\s--list-only\b/ },
];

const rsyncDestructive: DestructiveRule[] = [
  {
    name: "rsync-delete",
    re: /rsync\b.*\s--delete(?:-[a-z-]+)?\b/,
    severity: "high",
    reason: "rsync --delete removes destination files not present in source.",
    explanation:
      "The --delete flag removes files from the destination that don't exist in the " +
      "source. If source and destination are swapped, or if the source is unexpectedly " +
      "empty, important data on the destination can be permanently deleted.\n\n" +
      "Safer alternatives:\n" +
      "- rsync --dry-run --delete: Preview what would be deleted\n" +
      "- rsync without --delete: Only adds/updates, never deletes\n" +
      "- rsync --backup --delete: Keep backup copies of deleted files",
  },
  {
    name: "rsync-del-short",
    re: /rsync\b.*\s--del\b/,
    severity: "high",
    reason: "rsync --del is a short alias for --delete and is destructive.",
    explanation:
      "The --del flag is shorthand for --delete-during, which deletes destination files " +
      "not present in source during the transfer. This is slightly more dangerous than " +
      "--delete-after because deletions happen incrementally.\n\n" +
      "Safer alternatives:\n" +
      "- rsync --dry-run --del: Preview deletions first\n" +
      "- rsync without deletion flags: Additive sync only\n" +
      "- Use --delete-after for predictable batch deletion",
  },
];

/**
 * Remote pack — ssh + scp + rsync merged.
 *
 * Sources: DCG `src/packs/remote/{ssh,scp,rsync}.rs`.
 * Keywords are the UNION of the three DCG keyword sets (dedup preserving
 * order): ssh[ssh,ssh-keygen,ssh-keyscan] + scp[scp] + rsync[rsync] =>
 * [ssh,ssh-keygen,ssh-keyscan,scp,rsync].
 */
export const remotePack: Pack = {
  id: "remote",
  name: "Remote",
  description:
    "Protects against destructive remote sync and access operations across " +
    "ssh, scp, and rsync",
  keywords: ["ssh", "ssh-keygen", "ssh-keyscan", "scp", "rsync"],
  safePatterns: [...sshSafe, ...scpSafe, ...rsyncSafe],
  destructivePatterns: [
    ...sshDestructive,
    ...scpDestructive,
    ...rsyncDestructive,
  ],
};
