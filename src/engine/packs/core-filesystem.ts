// Core filesystem pack — protections against destructive rm commands and
// equivalent destruction (find -delete, unlink, truncate, shred, tar
// --remove-files, dd of=, mv to a sensitive path, shell redirect-to-device).
//
// Faithful port of DCG `src/packs/core/filesystem.rs`
// (https://github.com/Dicklesworthstone/destructive_command_guard).
//
// The recursive-removal argv parser (rm/cp/ln/rsync) lives in ../rm-parser.ts
// and is wired here via `imperative`. The regex rules below mirror DCG's
// `create_safe_patterns()` / `create_destructive_patterns()` in declaration
// order (load-bearing: first destructive match wins).
//
// JS RegExp porting notes:
// - All DCG patterns in filesystem.rs are case-sensitive (no inline `(?i)`),
//   so NONE of these RegExp carry the "i" flag.
// - DCG splits into `regex` + `fancy_regex` engines; JS RegExp supports
//   lookahead / lookbehind / alternation natively, so each rule is ONE RegExp.
// - Rust raw strings (`r"..."` / `r#"..."#`) preserve backslashes literally;
//   in JS regex literals `/` is escaped as `\/`. No other transliteration was
//   needed (no possessive quantifiers, no POSIX classes in this file).
// - `[^|;&]*?` is a lazy quantifier (valid JS), ported verbatim from DCG.
// - `(?<![<>])` in `redirect-truncate-root-home` is a fixed-width lookbehind,
//   valid in modern JS engines (Node 18+).

import { rmImperativeChecks } from "../rm-parser.ts";
import type { DestructiveRule, Pack, SafeRule, Suggestion } from "../types.ts";

// ============================================================================
// Suggestion constants (DCG: const RM_RF_*_SUGGESTIONS etc.)
// ============================================================================

const RM_RF_ROOT_HOME_SUGGESTIONS: Suggestion[] = [
  {
    command: "find {path} -type f | head -20",
    description: "Preview what files would be deleted before running",
    platform: "all",
  },
  {
    command: "ls -la {path}",
    description: "List directory contents to verify the path",
    platform: "all",
  },
  {
    command: "rm -rf /path/to/specific/subdirectory",
    description: "Use explicit, specific paths instead of root or home",
    platform: "all",
  },
];

const RM_RF_GENERAL_SUGGESTIONS: Suggestion[] = [
  {
    command: "rm -ri {path}",
    description: "Interactive mode: confirms each file before deletion",
    platform: "all",
  },
  {
    command: "trash-put {path}",
    description:
      "Move to trash instead of permanent deletion (requires trash-cli)",
    platform: "linux",
  },
  {
    command: "gio trash {path}",
    description: "Move to trash via GNOME (requires gio)",
    platform: "linux",
  },
  {
    command: "mv {path} /tmp/delete-me-{timestamp}",
    description: "Move to a temp holding area instead of deleting immediately",
    platform: "all",
  },
  {
    command: "rm -rf /tmp/{subdir}",
    description: "Safe temp directory deletion (allowed without confirmation)",
    platform: "all",
  },
  {
    command: "find {path} -type f | wc -l",
    description: "Count files that would be deleted before proceeding",
    platform: "all",
  },
  {
    command: "ls -la {path}",
    description: "List directory contents to verify the path",
    platform: "all",
  },
];

const RM_R_F_SEPARATE_SUGGESTIONS: Suggestion[] = [
  {
    command: "rm -ri {path}",
    description: "Interactive mode: confirms each file before deletion",
    platform: "all",
  },
  {
    command: "rm -r -f /tmp/{subdir}",
    description: "Safe temp directory deletion (allowed without confirmation)",
    platform: "all",
  },
  {
    command: "rm -r -f $TMPDIR/{subdir}",
    description: "Use system temp directory (allowed without confirmation)",
    platform: "all",
  },
  {
    command: "find {path} -type f | head -20",
    description: "Preview files before deletion",
    platform: "all",
  },
];

const RM_RECURSIVE_FORCE_SUGGESTIONS: Suggestion[] = [
  {
    command: "rm --interactive --recursive {path}",
    description: "Interactive mode: confirms each file before deletion",
    platform: "all",
  },
  {
    command: "find {path} --maxdepth 2 -ls | head -30",
    description: "Preview directory structure before deletion",
    platform: "all",
  },
  {
    command: "rm --recursive --force /tmp/{subdir}",
    description: "Safe temp directory deletion (allowed without confirmation)",
    platform: "all",
  },
];

const FIND_DELETE_SUGGESTIONS: Suggestion[] = [
  {
    command: "find {path} -type f | head -20",
    description:
      "Preview which files `-delete` would remove (drop the -delete flag)",
    platform: "all",
  },
  {
    command: "find {path} -type f | wc -l",
    description: "Count files that would be deleted before proceeding",
    platform: "all",
  },
  {
    command: "find /tmp/{subdir} -delete",
    description: "Safe temp directory deletion (allowed without confirmation)",
    platform: "all",
  },
  {
    command: "find {path} -print -delete",
    description: "If you must proceed: use -print to log every deletion",
    platform: "all",
  },
];

const UNLINK_SUGGESTIONS: Suggestion[] = [
  {
    command: "ls -la {path}",
    description: "Verify the path before unlinking",
    platform: "all",
  },
  {
    command: "cp {path} {path}.bak && unlink {path}",
    description: "Make a backup first if you really must remove the original",
    platform: "all",
  },
  {
    command: "unlink /tmp/{subdir}/scratch",
    description: "Safe temp-directory unlink (allowed without confirmation)",
    platform: "all",
  },
  {
    command: "trash-put {path}",
    description:
      "Move to trash instead of permanent unlink (requires trash-cli)",
    platform: "linux",
  },
];

const TRUNCATE_SUGGESTIONS: Suggestion[] = [
  {
    command: "cp {path} {path}.bak && truncate -s 0 {path}",
    description: "Make a backup before zeroing the file",
    platform: "all",
  },
  {
    command: "wc -c {path}",
    description: "Check current size before shrinking",
    platform: "all",
  },
  {
    command: "truncate -s 0 /tmp/{subdir}/scratch",
    description: "Safe temp-directory truncate (allowed without confirmation)",
    platform: "all",
  },
  {
    command: "head -c <N> {path} > {path}.head && mv {path}.head {path}",
    description: "Keep the first N bytes instead of dropping data blindly",
    platform: "all",
  },
];

const SHRED_SUGGESTIONS: Suggestion[] = [
  {
    command: "ls -la {path}",
    description: "Verify the path before shredding (no recovery)",
    platform: "all",
  },
  {
    command: "cp {path} {path}.bak && shred -u {path}",
    description: "Make a backup first if you might need the data",
    platform: "all",
  },
  {
    command: "shred -u /tmp/{subdir}/scratch",
    description: "Safe temp-directory shred (allowed without confirmation)",
    platform: "all",
  },
  {
    command: "shred -n 1 -u {path}",
    description:
      "Single-pass shred is faster (and on SSDs, multi-pass adds little)",
    platform: "all",
  },
];

const TAR_REMOVE_FILES_SUGGESTIONS: Suggestion[] = [
  {
    command: "tar -cf {path}.tar {path}",
    description: "Archive without --remove-files (sources are preserved)",
    platform: "all",
  },
  {
    command: "tar -cf {path}.tar {path} && rm -ri {path}",
    description: "Archive first, then remove with confirmation prompts",
    platform: "all",
  },
  {
    command: "tar --remove-files -cf out.tar /tmp/{subdir}",
    description:
      "Safe temp-directory archive + remove (allowed without confirmation)",
    platform: "all",
  },
  {
    command: "ls -la {path}",
    description: "Verify the source path before archive+delete",
    platform: "all",
  },
];

const DD_OVERWRITE_SUGGESTIONS: Suggestion[] = [
  {
    command: "ls -la {path}",
    description: "Verify the path before overwriting (no recovery)",
    platform: "all",
  },
  {
    command: "cp {path} {path}.bak && dd if=/dev/zero of={path} bs=1M count=10",
    description: "Make a backup first if you might need the data",
    platform: "all",
  },
  {
    command: "dd if=/dev/zero of=/tmp/{subdir}/scratch bs=1M count=10",
    description: "Safe temp-directory dd (allowed without confirmation)",
    platform: "all",
  },
  {
    command: "dd if={path} of=/dev/null",
    description:
      "Read-only dd: output discarded (useful for testing read speed)",
    platform: "all",
  },
];

const MV_SENSITIVE_SUGGESTIONS: Suggestion[] = [
  {
    command: "ls -la {path}",
    description: "Verify the source path before any move",
    platform: "all",
  },
  {
    command: "cp -a {path} {path}.bak",
    description:
      "Copy first (preserves the original) — verify the copy, then remove only after confirmation",
    platform: "all",
  },
  {
    command: "mv {path} {path}.deleted-YYYYMMDD",
    description:
      "In-place rename for soft-delete (no cross-segment hop, easy to undo)",
    platform: "all",
  },
  {
    command: "mv /tmp/{subdir}/foo /tmp/{subdir}/bar",
    description: "Safe temp-directory rename (allowed without confirmation)",
    platform: "all",
  },
];

const SENSITIVE_PROPAGATION_DELETE_SUGGESTIONS: Suggestion[] = [
  {
    command: "ls -la {path}",
    description: "Verify the sensitive source path before propagating it",
    platform: "all",
  },
  {
    command: "cp -a {path} {path}.bak",
    description:
      "Keep the backup beside the original and verify it before any later deletion",
    platform: "all",
  },
  {
    command: "diff -r {path} {path}.bak",
    description: "Compare the source and copy before considering removal",
    platform: "all",
  },
  {
    command: "rm -ri /tmp/{subdir}",
    description:
      "Use interactive removal for temp trees derived from sensitive sources",
    platform: "all",
  },
];

const REDIRECT_TRUNCATE_SUGGESTIONS: Suggestion[] = [
  {
    command: "ls -la {path}",
    description: "Verify the path before any redirect",
    platform: "all",
  },
  {
    command: "cp {path} {path}.bak && echo data > {path}",
    description: "Make a backup first if you might need the previous content",
    platform: "all",
  },
  {
    command: "echo data >> {path}",
    description:
      "Use append (>>) instead of truncate (>) to preserve existing content",
    platform: "all",
  },
  {
    command: "echo data > /tmp/{subdir}/scratch",
    description: "Safe temp-directory redirect (allowed without confirmation)",
    platform: "all",
  },
];

// ============================================================================
// Long explanations (DCG: the multi-line explanation strings)
// ============================================================================

const RM_RF_ROOT_HOME_EXPLANATION =
  "This command would recursively delete files starting from the root filesystem (/) " +
  "or home directory (~). This is catastrophic and will destroy:\n\n" +
  "- Your entire operating system\n" +
  "- All installed applications and libraries\n" +
  "- All user data, documents, and configurations\n" +
  "- Boot files, making the system unbootable\n\n" +
  "There is NO recovery without backups. Even with backups, full restoration " +
  "takes hours to days.\n\n" +
  "If you need to delete specific files, use explicit paths:\n  " +
  "rm -rf /path/to/specific/directory\n\n" +
  "Always preview what would be deleted first:\n  " +
  "find /path/to/directory -type f | head -20";

const RM_R_F_SEPARATE_ROOT_HOME_EXPLANATION =
  "Separate `-r -f` flags on `/` or `~` have identical effect to `rm -rf /`: " +
  "recursive, forced, silent deletion of the entire filesystem or home directory.\n\n" +
  "There is NO recovery without backups. Run only if truly intended.";

const RM_RECURSIVE_FORCE_ROOT_HOME_EXPLANATION =
  "The long-flag form has identical effect to `rm -rf /`: recursive, forced, " +
  "silent deletion. Run only if truly intended.";

const RM_RF_GENERAL_EXPLANATION =
  "rm -rf recursively removes files and directories without confirmation prompts. " +
  "The -f (force) flag suppresses all warnings, making accidental deletions " +
  "silent and immediate.\n\n" +
  "Why this is dangerous:\n" +
  "- Deleted files bypass the trash - they're gone immediately\n" +
  "- Typos in paths can delete unintended directories\n" +
  "- Wildcards can expand to match more than expected\n" +
  "- No undo mechanism exists\n\n" +
  "Safe alternatives:\n" +
  "- rm -ri: Interactive mode, confirms each file\n" +
  "- trash-cli: Moves files to trash instead of deleting\n" +
  "- rm -rf in /tmp, /var/tmp, $TMPDIR: Allowed (safe temp directories)\n\n" +
  "Preview what would be deleted:\n  " +
  "find /path/to/delete -type f | wc -l  # Count files\n  " +
  "ls -la /path/to/delete               # List contents";

const RM_R_F_SEPARATE_EXPLANATION =
  "rm with separate -r and -f flags has the same effect as rm -rf: recursive " +
  "forced deletion without confirmation.\n\n" +
  "Common variations that are all equivalent:\n" +
  "- rm -r -f path\n" +
  "- rm -f -r path\n" +
  "- rm -r -f -v path (verbose but still forced)\n\n" +
  "All carry the same risks as rm -rf: immediate, silent, irreversible deletion.\n\n" +
  "Safer approach for temporary directories:\n" +
  "- rm -r -f /tmp/mydir    # Allowed - temp directories are safe\n" +
  "- rm -r -f $TMPDIR/mydir # Allowed - uses system temp dir\n\n" +
  "For other paths, prefer:\n  " +
  "rm -ri /path  # Interactive confirmation";

const RM_RECURSIVE_FORCE_EXPLANATION =
  "rm --recursive --force is the long-form equivalent of rm -rf. While more " +
  "readable, it carries identical risks: silent, recursive, irreversible deletion.\n\n" +
  "The long flags may appear in:\n" +
  "- Scripts aiming for clarity\n" +
  "- Generated code from build tools\n" +
  "- Cross-platform compatibility scenarios\n\n" +
  "All standard rm -rf precautions apply:\n" +
  "- Verify the path before running\n" +
  "- Use absolute paths to avoid ambiguity\n" +
  "- Consider using trash-cli for recoverable deletion\n\n" +
  "Preview command:\n  " +
  "find /path --maxdepth 2 -ls | head -30";

const CP_SENSITIVE_THEN_DELETE_EXPLANATION =
  "`cp -al /etc /tmp/x && rm -rf /tmp/x` is a propagation variant of the " +
  "relocate-then-delete bypass: the copy segment is allowed, and the temp " +
  "delete segment is normally safe, but the compound command can destroy " +
  "sensitive content or hide irreversible deletion behind a temp path.\n\n" +
  "Safer alternatives:\n" +
  "- Copy beside the original or into a named backup path and verify with `diff -r`.\n" +
  "- Do not combine sensitive-source propagation and forced deletion in one command.\n" +
  "- Use `rm -ri` if a derived temp tree genuinely needs manual cleanup.";

const LN_SYMLINK_SENSITIVE_THEN_DELETE_EXPLANATION =
  "`ln -s /etc /tmp/x && rm -rf /tmp/x/.` can turn an apparently safe temp " +
  "cleanup into deletion through a symlink. The temp path does not make the " +
  "operation safe once it points back at a sensitive tree.\n\n" +
  "Safer alternatives:\n" +
  "- Inspect symlinks with `readlink` and `ls -la` before removing anything.\n" +
  "- Remove only the link itself with `unlink /tmp/<link>` when that is the intent.\n" +
  "- Avoid combining symlink creation and recursive deletion in one command.";

const RSYNC_SENSITIVE_THEN_DELETE_EXPLANATION =
  "`rsync -a /etc/ /tmp/dest/ && rm -rf /tmp/dest` is the rsync form of the " +
  "sensitive-source propagation bypass. Archive mode preserves enough structure " +
  "that the later temp cleanup should require human review.\n\n" +
  "Safer alternatives:\n" +
  "- Run rsync and inspect the destination in a separate step.\n" +
  "- Use `--dry-run` for rsync previews.\n" +
  "- Use `rm -ri` for manual cleanup of derived temp trees.";

const FIND_DELETE_ROOT_HOME_EXPLANATION =
  "`find <path> -delete` is the bytewise-equivalent of `rm -rf <path>`: " +
  "it recursively removes every file and (when -depth is implied) every " +
  "directory matched by the predicate. Targeting `/`, `~`, `$HOME`, or any " +
  "top-level system directory (`/etc`, `/usr`, `/var`, `/home`, `/boot`, " +
  "`/dev`, `/proc`, `/sys`, `/lib`, `/lib64`, `/opt`, `/root`) destroys " +
  "the operating system or user data the same way `rm -rf` would.\n\n" +
  "There is NO recovery without backups.\n\n" +
  "If you only need to delete files matching a pattern, use a much more " +
  "specific path:\n  " +
  "find /path/to/specific/subdir -name '*.tmp' -delete\n\n" +
  "Always preview first:\n  " +
  "find /path -type f | head -20";

const FIND_DELETE_GENERAL_EXPLANATION =
  "`find ... -delete` recursively deletes every path matched by the find " +
  "expression. The action flag `-delete` implies `-depth` (so directories " +
  "are deleted after their contents). With no path predicate it deletes " +
  "the entire starting tree. Common pitfalls:\n\n" +
  "- `find . -delete` deletes the current working directory's contents.\n" +
  "- `find <path> -delete` with a wide -name glob matches more than expected.\n" +
  "- `-delete` errors are silent by default — failures don't stop the walk.\n\n" +
  "Safer alternatives:\n" +
  "- Drop -delete to preview: `find <path> ...` (just lists matches)\n" +
  "- Add -print -delete to log each deletion as it happens\n" +
  "- Use `find /tmp/<subdir> ... -delete` (allowed under temp dirs)\n" +
  "- For a few files: `find ... | xargs -t -p rm -i` for confirmation";

const UNLINK_ROOT_HOME_EXPLANATION =
  "`unlink <file>` is the raw POSIX unlink(2) primitive: it removes a single " +
  "directory entry without prompting, without trash, without backup. On a " +
  "sensitive system file (`/etc/passwd`, `/etc/shadow`, `/etc/sudoers`) or " +
  "a home-directory key (`~/.ssh/id_ed25519`, `$HOME/.gnupg/...`) the result " +
  "is irrecoverable.\n\n" +
  "There is NO recovery without backups.\n\n" +
  "Safer alternatives:\n" +
  "- `mv <file> <file>.deleted-YYYYMMDD` then verify nothing breaks, then\n" +
  "  `unlink <file>.deleted-...` after a few days.\n" +
  "- `cp <file> <file>.bak && unlink <file>` to keep an explicit backup.\n" +
  "- `unlink /tmp/<subdir>/scratch` is allowed (temp dirs).";

const UNLINK_GENERAL_EXPLANATION =
  "`unlink <file>` removes a single directory entry without confirmation, " +
  "without trash, without backup. While not as broad as `rm -rf`, a typo in " +
  "the target path destroys an unintended file.\n\n" +
  "Safer alternatives:\n" +
  "- Verify the path with `ls -la <file>` first.\n" +
  "- Make a backup: `cp <file> <file>.bak`.\n" +
  "- For temp scratch: `unlink /tmp/<subdir>/scratch` is allowed.\n" +
  "- Use `mv <file> /tmp/quarantine-<file>` if you want a delayed delete.";

const TRUNCATE_ZERO_ROOT_HOME_EXPLANATION =
  "`truncate -s 0 <file>` zeros a file in place. `truncate -s -<N> <file>` " +
  "shrinks a file by N bytes (destroying the trailing data). On a sensitive " +
  "system file (`/etc/passwd`, `/etc/shadow`, `/etc/sudoers`) or a home-" +
  "directory key/credential the result is irrecoverable.\n\n" +
  "There is NO recovery without backups.\n\n" +
  "Safer alternatives:\n" +
  "- Make a backup first: `cp <file> <file>.bak && truncate -s 0 <file>`.\n" +
  "- For growth (NOT shrink): `truncate -s +<N>` is allowed (no data loss).\n" +
  "- For temp scratch: `truncate -s 0 /tmp/<subdir>/scratch` is allowed.";

const TRUNCATE_ZERO_GENERAL_EXPLANATION =
  "`truncate -s 0 <file>` zeros a file in place; `truncate -s -<N> <file>` " +
  "shrinks it by N bytes. Both destroy data without confirmation, without " +
  "trash, without backup. While not as broad as `rm`, a typo in the target " +
  "path destroys an unintended file.\n\n" +
  "Safer alternatives:\n" +
  "- Verify the size first: `wc -c <file>`.\n" +
  "- Make a backup: `cp <file> <file>.bak && truncate -s 0 <file>`.\n" +
  "- For growth: `truncate -s +<N>` (allowed; non-destructive).\n" +
  "- For temp scratch: `truncate -s 0 /tmp/<subdir>/scratch` is allowed.";

const SHRED_ROOT_HOME_EXPLANATION =
  "`shred` overwrites file content with random data (DoD-style multi-pass by " +
  "default). With `-u`/`--remove`/`-fzu` the file is also unlinked. On a " +
  "sensitive system file (`/etc/passwd`, `/etc/shadow`, `/etc/sudoers`) or a " +
  "home-directory key/credential the result is unrecoverable even with " +
  "specialised forensics — that is shred's entire design intent.\n\n" +
  "There is NO recovery without backups.\n\n" +
  "Safer alternatives:\n" +
  "- Verify the path with `ls -la <file>` first.\n" +
  "- Make a backup: `cp <file> <file>.bak && shred -u <file>`.\n" +
  "- For temp scratch: `shred -u /tmp/<subdir>/scratch` is allowed.\n" +
  "- For modern SSDs, single-pass is sufficient: `shred -n 1 -u <file>`.";

const SHRED_GENERAL_EXPLANATION =
  "`shred` overwrites file content with random data; `-u`/`--remove` adds an " +
  "unlink step. The whole point is that the data cannot be recovered. While " +
  "not as broad as `rm -rf`, a typo in the target path destroys an unintended " +
  "file with no possibility of undo.\n\n" +
  "Safer alternatives:\n" +
  "- Verify the path with `ls -la <file>` first.\n" +
  "- Make a backup: `cp <file> <file>.bak`.\n" +
  "- For temp scratch: `shred -u /tmp/<subdir>/scratch` is allowed.\n" +
  "- On modern SSDs `shred` may not actually overwrite the underlying flash " +
  "cells; use `cryptsetup erase` or vendor secure-erase utilities instead.";

const TAR_REMOVE_FILES_ROOT_HOME_EXPLANATION =
  "`tar --remove-files -cf <archive> <source>` first archives the source paths " +
  "into <archive>, then deletes the originals. With a sensitive source " +
  "(`/etc`, `/usr`, `/var`, `/home/<user>`, `~`, `$HOME`, ...) the result is " +
  "bytewise-equivalent to `rm -rf <source>`. With `-cf /dev/null` the archive " +
  "is discarded entirely, making this a pure recursive delete with no audit " +
  "trail.\n\n" +
  "There is NO recovery without backups.\n\n" +
  "Safer alternatives:\n" +
  "- Drop `--remove-files`: `tar -cf out.tar <source>` (sources preserved).\n" +
  "- Two-step with confirmation: `tar -cf out.tar <source> && rm -ri <source>`.\n" +
  "- Verify the source first: `ls -la <source>`.\n" +
  "- Allowed for temp dirs: `tar --remove-files -cf out.tar /tmp/<subdir>`.";

const TAR_REMOVE_FILES_GENERAL_EXPLANATION =
  "`tar --remove-files <source>` deletes the source paths once they have been " +
  "archived. While not as broad as `rm -rf`, a typo or wide glob in the source " +
  "list destroys files the agent did not intend to remove. With `-cf /dev/null` " +
  "the archive itself is discarded — the operation becomes a pure delete.\n\n" +
  "Safer alternatives:\n" +
  "- Drop `--remove-files` to preserve sources after archiving.\n" +
  "- Verify the source list with `ls -la` before running.\n" +
  "- For temp scratch: `tar --remove-files -cf out.tar /tmp/<subdir>` is allowed.";

const DD_OVERWRITE_ROOT_HOME_EXPLANATION =
  "`dd if=/dev/zero of=<file>` and `dd if=/dev/urandom of=<file>` overwrite the " +
  "file's contents in place — the `truncate -s 0` equivalent at the dd layer. " +
  "On a sensitive system file (`/etc/passwd`, `/etc/shadow`, `/etc/sudoers`) or " +
  "a home-directory key/credential the result is irrecoverable. Even without an " +
  "explicit input source (`dd of=<file>` reads from stdin), the file's content " +
  "is destroyed.\n\n" +
  "There is NO recovery without backups.\n\n" +
  "Safer alternatives:\n" +
  "- Make a backup first: `cp <file> <file>.bak && dd if=/dev/zero of=<file>`.\n" +
  "- For read-only verification: `dd if=<file> of=/dev/null` (output discarded).\n" +
  "- For temp scratch: `dd if=/dev/zero of=/tmp/<subdir>/scratch` is allowed.\n\n" +
  "Device-level dd (`dd of=/dev/sda`) is governed by the `system.disk` pack " +
  "— enable it for partition-table protection.";

const DD_OVERWRITE_GENERAL_EXPLANATION =
  "`dd of=<file>` overwrites the file's contents (with the input from `if=` " +
  "or stdin if no input source is given). While not as broad as `rm -rf`, a " +
  "typo in the target path destroys an unintended file with no possibility of " +
  "undo.\n\n" +
  "Safer alternatives:\n" +
  "- Verify the path first: `ls -la <file>`.\n" +
  "- Make a backup: `cp <file> <file>.bak && dd if=/dev/zero of=<file>`.\n" +
  "- Read-only verification: `dd if=<file> of=/dev/null`.\n" +
  "- For temp scratch: `dd if=/dev/zero of=/tmp/<subdir>/scratch` is allowed.\n" +
  "- For device writes: enable the `system.disk` pack.";

const MV_SENSITIVE_SOURCE_ROOT_HOME_EXPLANATION =
  "`mv /etc /tmp/x && rm -rf /tmp/x` is the canonical cross-segment bypass: " +
  "each segment is individually allowed (mv-to-tmp is benign; rm-rf-in-tmp " +
  "is safe) but the pair destroys `/etc`. The same shape closes via " +
  '`mv /etc /dev/null`, `mv $HOME /tmp/x`, or any "relocate then delete" chain.\n\n' +
  "Any mv that mentions a sensitive path (source OR destination — `/etc`, " +
  "`/usr`, `/var`, `/home`, `~`, `$HOME`, ...) blocks here, including " +
  "in-place renames within /etc.\n\n" +
  "Safer alternatives:\n" +
  "- Backup with copy + verify + delete:\n  " +
  "`cp -a <source> <source>.bak && diff -r <source> <source>.bak && rm -rf <source>`\n" +
  "- Soft-delete via in-place rename: `mv <file> <file>.deleted-YYYYMMDD` " +
  "(use `dcg allow-once` for the rename, then a follow-up `rm` after a soak period).\n" +
  "- Pure tmp-to-tmp moves: `mv /tmp/<a> /tmp/<b>` is allowed.";

const REDIRECT_TRUNCATE_ROOT_HOME_EXPLANATION =
  "`> /etc/passwd` (or `: > /etc/passwd`, `echo > /etc/passwd`, etc.) opens " +
  "the target file with O_WRONLY|O_CREAT|O_TRUNC — the contents are destroyed " +
  "before any write happens. This applies equally to `>|` (force-overwrite), " +
  "`&>` / `>&` (stdout+stderr to file), and numbered FD forms (`1>`, `2>`, `1>|`, " +
  "`2>|`). All of these are silent, immediate, irrecoverable.\n\n" +
  "There is NO recovery without backups.\n\n" +
  "Safer alternatives:\n" +
  "- Use append (`>>`) to preserve existing content: `echo line >> <file>`.\n" +
  "- Make a backup: `cp <file> <file>.bak && echo data > <file>`.\n" +
  "- For temp scratch: `> /tmp/<subdir>/scratch` is allowed.\n" +
  "- Read redirects (`< <file>`) are not affected — they don't truncate.";

// ============================================================================
// Safe patterns (DCG: create_safe_patterns())
// ============================================================================

const safePatterns: SafeRule[] = [
  // rm -rf in /tmp (combined flags)
  {
    name: "rm-rf-tmp",
    re: /^rm\s+-[a-zA-Z]*[rR][a-zA-Z]*f[a-zA-Z]*\s+(?:\/tmp\/(?!\.\.(?:\/|\s|$)|[^\s]*\/\.\.(?:\/|\s|$))\S*(?:\s+|$))+$/,
  },
  {
    name: "rm-fr-tmp",
    re: /^rm\s+-[a-zA-Z]*f[a-zA-Z]*[rR][a-zA-Z]*\s+(?:\/tmp\/(?!\.\.(?:\/|\s|$)|[^\s]*\/\.\.(?:\/|\s|$))\S*(?:\s+|$))+$/,
  },
  // rm -rf in /var/tmp (combined flags)
  {
    name: "rm-rf-var-tmp",
    re: /^rm\s+-[a-zA-Z]*[rR][a-zA-Z]*f[a-zA-Z]*\s+(?:\/var\/tmp\/(?!\.\.(?:\/|\s|$)|[^\s]*\/\.\.(?:\/|\s|$))\S*(?:\s+|$))+$/,
  },
  {
    name: "rm-fr-var-tmp",
    re: /^rm\s+-[a-zA-Z]*f[a-zA-Z]*[rR][a-zA-Z]*\s+(?:\/var\/tmp\/(?!\.\.(?:\/|\s|$)|[^\s]*\/\.\.(?:\/|\s|$))\S*(?:\s+|$))+$/,
  },
  // rm -rf with $TMPDIR (combined flags)
  {
    name: "rm-rf-tmpdir",
    re: /^rm\s+-[a-zA-Z]*[rR][a-zA-Z]*f[a-zA-Z]*\s+(?:\$TMPDIR\/(?!\.\.(?:\/|\s|$)|[^\s]*\/\.\.(?:\/|\s|$))\S*(?:\s+|$))+$/,
  },
  {
    name: "rm-fr-tmpdir",
    re: /^rm\s+-[a-zA-Z]*f[a-zA-Z]*[rR][a-zA-Z]*\s+(?:\$TMPDIR\/(?!\.\.(?:\/|\s|$)|[^\s]*\/\.\.(?:\/|\s|$))\S*(?:\s+|$))+$/,
  },
  // rm -rf with ${TMPDIR} (braced form)
  {
    name: "rm-rf-tmpdir-brace",
    re: /^rm\s+-[a-zA-Z]*[rR][a-zA-Z]*f[a-zA-Z]*\s+(?:\$\{TMPDIR\}\/(?!\.\.(?:\/|\s|$)|[^\s]*\/\.\.(?:\/|\s|$))\S*(?:\s+|$))+$/,
  },
  {
    name: "rm-fr-tmpdir-brace",
    re: /^rm\s+-[a-zA-Z]*f[a-zA-Z]*[rR][a-zA-Z]*\s+(?:\$\{TMPDIR\}\/(?!\.\.(?:\/|\s|$)|[^\s]*\/\.\.(?:\/|\s|$))\S*(?:\s+|$))+$/,
  },
  // rm -rf with quoted $TMPDIR
  {
    name: "rm-rf-tmpdir-quoted",
    re: /^rm\s+-[a-zA-Z]*[rR][a-zA-Z]*f[a-zA-Z]*\s+(?:"\$TMPDIR\/(?!(?:[^"]*\/)?\.\.(?:\/|"))[^"]*"(?:\s+|$))+$/,
  },
  {
    name: "rm-fr-tmpdir-quoted",
    re: /^rm\s+-[a-zA-Z]*f[a-zA-Z]*[rR][a-zA-Z]*\s+(?:"\$TMPDIR\/(?!(?:[^"]*\/)?\.\.(?:\/|"))[^"]*"(?:\s+|$))+$/,
  },
  // rm -rf with quoted ${TMPDIR}
  {
    name: "rm-rf-tmpdir-brace-quoted",
    re: /^rm\s+-[a-zA-Z]*[rR][a-zA-Z]*f[a-zA-Z]*\s+(?:"\$\{TMPDIR\}\/(?!(?:[^"]*\/)?\.\.(?:\/|"))[^"]*"(?:\s+|$))+$/,
  },
  {
    name: "rm-fr-tmpdir-brace-quoted",
    re: /^rm\s+-[a-zA-Z]*f[a-zA-Z]*[rR][a-zA-Z]*\s+(?:"\$\{TMPDIR\}\/(?!(?:[^"]*\/)?\.\.(?:\/|"))[^"]*"(?:\s+|$))+$/,
  },
  // rm -r -f (separate flags) in /tmp
  {
    name: "rm-r-f-tmp",
    re: /^rm\s+(-[a-zA-Z]+\s+)*-[rR]\s+(-[a-zA-Z]+\s+)*-f\s+(?:\/tmp\/(?!\.\.(?:\/|\s|$)|[^\s]*\/\.\.(?:\/|\s|$))\S*(?:\s+|$))+$/,
  },
  {
    name: "rm-f-r-tmp",
    re: /^rm\s+(-[a-zA-Z]+\s+)*-f\s+(-[a-zA-Z]+\s+)*-[rR]\s+(?:\/tmp\/(?!\.\.(?:\/|\s|$)|[^\s]*\/\.\.(?:\/|\s|$))\S*(?:\s+|$))+$/,
  },
  // rm -r -f (separate flags) in /var/tmp
  {
    name: "rm-r-f-var-tmp",
    re: /^rm\s+(-[a-zA-Z]+\s+)*-[rR]\s+(-[a-zA-Z]+\s+)*-f\s+(?:\/var\/tmp\/(?!\.\.(?:\/|\s|$)|[^\s]*\/\.\.(?:\/|\s|$))\S*(?:\s+|$))+$/,
  },
  {
    name: "rm-f-r-var-tmp",
    re: /^rm\s+(-[a-zA-Z]+\s+)*-f\s+(-[a-zA-Z]+\s+)*-[rR]\s+(?:\/var\/tmp\/(?!\.\.(?:\/|\s|$)|[^\s]*\/\.\.(?:\/|\s|$))\S*(?:\s+|$))+$/,
  },
  // rm -r -f (separate flags) with $TMPDIR
  {
    name: "rm-r-f-tmpdir",
    re: /^rm\s+(-[a-zA-Z]+\s+)*-[rR]\s+(-[a-zA-Z]+\s+)*-f\s+(?:\$TMPDIR\/(?!\.\.(?:\/|\s|$)|[^\s]*\/\.\.(?:\/|\s|$))\S*(?:\s+|$))+$/,
  },
  {
    name: "rm-f-r-tmpdir",
    re: /^rm\s+(-[a-zA-Z]+\s+)*-f\s+(-[a-zA-Z]+\s+)*-[rR]\s+(?:\$TMPDIR\/(?!\.\.(?:\/|\s|$)|[^\s]*\/\.\.(?:\/|\s|$))\S*(?:\s+|$))+$/,
  },
  // rm -r -f (separate flags) with ${TMPDIR}
  {
    name: "rm-r-f-tmpdir-brace",
    re: /^rm\s+(-[a-zA-Z]+\s+)*-[rR]\s+(-[a-zA-Z]+\s+)*-f\s+(?:\$\{TMPDIR\}\/(?!\.\.(?:\/|\s|$)|[^\s]*\/\.\.(?:\/|\s|$))\S*(?:\s+|$))+$/,
  },
  {
    name: "rm-f-r-tmpdir-brace",
    re: /^rm\s+(-[a-zA-Z]+\s+)*-f\s+(-[a-zA-Z]+\s+)*-[rR]\s+(?:\$\{TMPDIR\}\/(?!\.\.(?:\/|\s|$)|[^\s]*\/\.\.(?:\/|\s|$))\S*(?:\s+|$))+$/,
  },
  // rm --recursive --force (long flags) in /tmp
  {
    name: "rm-recursive-force-tmp",
    re: /^rm\s+.*--recursive.*--force\s+(?:\/tmp\/(?!\.\.(?:\/|\s|$)|[^\s]*\/\.\.(?:\/|\s|$))\S*(?:\s+|$))+$/,
  },
  {
    name: "rm-force-recursive-tmp",
    re: /^rm\s+.*--force.*--recursive\s+(?:\/tmp\/(?!\.\.(?:\/|\s|$)|[^\s]*\/\.\.(?:\/|\s|$))\S*(?:\s+|$))+$/,
  },
  // rm --recursive --force (long flags) in /var/tmp
  {
    name: "rm-recursive-force-var-tmp",
    re: /^rm\s+.*--recursive.*--force\s+(?:\/var\/tmp\/(?!\.\.(?:\/|\s|$)|[^\s]*\/\.\.(?:\/|\s|$))\S*(?:\s+|$))+$/,
  },
  {
    name: "rm-force-recursive-var-tmp",
    re: /^rm\s+.*--force.*--recursive\s+(?:\/var\/tmp\/(?!\.\.(?:\/|\s|$)|[^\s]*\/\.\.(?:\/|\s|$))\S*(?:\s+|$))+$/,
  },
  // rm --recursive --force (long flags) with $TMPDIR
  {
    name: "rm-recursive-force-tmpdir",
    re: /^rm\s+.*--recursive.*--force\s+(?:\$TMPDIR\/(?!\.\.(?:\/|\s|$)|[^\s]*\/\.\.(?:\/|\s|$))\S*(?:\s+|$))+$/,
  },
  {
    name: "rm-force-recursive-tmpdir",
    re: /^rm\s+.*--force.*--recursive\s+(?:\$TMPDIR\/(?!\.\.(?:\/|\s|$)|[^\s]*\/\.\.(?:\/|\s|$))\S*(?:\s+|$))+$/,
  },
  // rm --recursive --force (long flags) with ${TMPDIR}
  {
    name: "rm-recursive-force-tmpdir-brace",
    re: /^rm\s+.*--recursive.*--force\s+(?:\$\{TMPDIR\}\/(?!\.\.(?:\/|\s|$)|[^\s]*\/\.\.(?:\/|\s|$))\S*(?:\s+|$))+$/,
  },
  {
    name: "rm-force-recursive-tmpdir-brace",
    re: /^rm\s+.*--force.*--recursive\s+(?:\$\{TMPDIR\}\/(?!\.\.(?:\/|\s|$)|[^\s]*\/\.\.(?:\/|\s|$))\S*(?:\s+|$))+$/,
  },
  // `find ... -delete` safe whitelist for temp directories (whole-command anchored)
  {
    name: "find-delete-tmp",
    re: /^find\s+\/tmp(?:\/(?!\.\.(?:\/|\s|$)|[^\s]*\/\.\.(?:\/|\s|$))\S*)?(?:\s+(?:\/tmp(?:\/(?!\.\.(?:\/|\s|$)|[^\s]*\/\.\.(?:\/|\s|$))\S*)?|-[a-zA-Z][\S]*(?:\s+[^/~$\-\s][^|;&\s]*)?))*\s+-delete(?:\s+-[a-zA-Z][\S]*(?:\s+[^/~$\-\s][^|;&\s]*)?)*\s*$/,
  },
  {
    name: "find-delete-var-tmp",
    re: /^find\s+\/var\/tmp(?:\/(?!\.\.(?:\/|\s|$)|[^\s]*\/\.\.(?:\/|\s|$))\S*)?(?:\s+(?:\/var\/tmp(?:\/(?!\.\.(?:\/|\s|$)|[^\s]*\/\.\.(?:\/|\s|$))\S*)?|-[a-zA-Z][\S]*(?:\s+[^/~$\-\s][^|;&\s]*)?))*\s+-delete(?:\s+-[a-zA-Z][\S]*(?:\s+[^/~$\-\s][^|;&\s]*)?)*\s*$/,
  },
  {
    name: "find-delete-tmpdir",
    re: /^find\s+\$TMPDIR(?:\/(?!\.\.(?:\/|\s|$)|[^\s]*\/\.\.(?:\/|\s|$))\S*)?(?:\s+(?:\$TMPDIR(?:\/(?!\.\.(?:\/|\s|$)|[^\s]*\/\.\.(?:\/|\s|$))\S*)?|-[a-zA-Z][\S]*(?:\s+[^/~$\-\s][^|;&\s]*)?))*\s+-delete(?:\s+-[a-zA-Z][\S]*(?:\s+[^/~$\-\s][^|;&\s]*)?)*\s*$/,
  },
  {
    name: "find-delete-tmpdir-brace",
    re: /^find\s+\$\{TMPDIR\}(?:\/(?!\.\.(?:\/|\s|$)|[^\s]*\/\.\.(?:\/|\s|$))\S*)?(?:\s+(?:\$\{TMPDIR\}(?:\/(?!\.\.(?:\/|\s|$)|[^\s]*\/\.\.(?:\/|\s|$))\S*)?|-[a-zA-Z][\S]*(?:\s+[^/~$\-\s][^|;&\s]*)?))*\s+-delete(?:\s+-[a-zA-Z][\S]*(?:\s+[^/~$\-\s][^|;&\s]*)?)*\s*$/,
  },
  // `unlink <file>` safe whitelist for temp directories (whole-command anchored)
  {
    name: "unlink-tmp",
    re: /^unlink\s+\/tmp\/(?!\.\.(?:\/|\s|$)|[^\s]*\/\.\.(?:\/|\s|$))\S+\s*$/,
  },
  {
    name: "unlink-var-tmp",
    re: /^unlink\s+\/var\/tmp\/(?!\.\.(?:\/|\s|$)|[^\s]*\/\.\.(?:\/|\s|$))\S+\s*$/,
  },
  {
    name: "unlink-tmpdir",
    re: /^unlink\s+\$TMPDIR\/(?!\.\.(?:\/|\s|$)|[^\s]*\/\.\.(?:\/|\s|$))\S+\s*$/,
  },
  {
    name: "unlink-tmpdir-brace",
    re: /^unlink\s+\$\{TMPDIR\}\/(?!\.\.(?:\/|\s|$)|[^\s]*\/\.\.(?:\/|\s|$))\S+\s*$/,
  },
  { name: "unlink-help", re: /^unlink\s+(?:--help|--version)\s*$/ },
  // `truncate` safe whitelist
  { name: "truncate-help", re: /^truncate\s+(?:--help|--version)\s*$/ },
  // Growing operations: -s +<N>, --size=+<N> (pure growth — no data destroyed)
  {
    name: "truncate-grow",
    re: /^truncate\s+(?:-s\s+\+\S+|--size=\+\S+)\s+\S+\s*$/,
  },
  // Temp-directory truncate (any size)
  {
    name: "truncate-tmp",
    re: /^truncate\s+(?:-s\s+\S+|--size=\S+)\s+\/tmp\/(?!\.\.(?:\/|\s|$)|[^\s]*\/\.\.(?:\/|\s|$))\S+\s*$/,
  },
  {
    name: "truncate-var-tmp",
    re: /^truncate\s+(?:-s\s+\S+|--size=\S+)\s+\/var\/tmp\/(?!\.\.(?:\/|\s|$)|[^\s]*\/\.\.(?:\/|\s|$))\S+\s*$/,
  },
  {
    name: "truncate-tmpdir",
    re: /^truncate\s+(?:-s\s+\S+|--size=\S+)\s+\$TMPDIR\/(?!\.\.(?:\/|\s|$)|[^\s]*\/\.\.(?:\/|\s|$))\S+\s*$/,
  },
  {
    name: "truncate-tmpdir-brace",
    re: /^truncate\s+(?:-s\s+\S+|--size=\S+)\s+\$\{TMPDIR\}\/(?!\.\.(?:\/|\s|$)|[^\s]*\/\.\.(?:\/|\s|$))\S+\s*$/,
  },
  // `shred` safe whitelist
  { name: "shred-help", re: /^shred\s+(?:--help|--version)\s*$/ },
  {
    name: "shred-tmp",
    re: /^shred(?:\s+(?:-[a-zA-Z][a-zA-Z0-9_-]*(?:\s+[^/~$\-\s][^\s|;&]*)?|--[a-z-]+(?:=\S+|\s+[^/~$\-\s][^\s|;&]*)?))*\s+\/tmp\/(?!\.\.(?:\/|\s|$)|[^\s]*\/\.\.(?:\/|\s|$))\S+(?:\s+(?:-[a-zA-Z][a-zA-Z0-9_-]*(?:\s+[^/~$\-\s][^\s|;&]*)?|--[a-z-]+(?:=\S+|\s+[^/~$\-\s][^\s|;&]*)?))*\s*$/,
  },
  {
    name: "shred-var-tmp",
    re: /^shred(?:\s+(?:-[a-zA-Z][a-zA-Z0-9_-]*(?:\s+[^/~$\-\s][^\s|;&]*)?|--[a-z-]+(?:=\S+|\s+[^/~$\-\s][^\s|;&]*)?))*\s+\/var\/tmp\/(?!\.\.(?:\/|\s|$)|[^\s]*\/\.\.(?:\/|\s|$))\S+(?:\s+(?:-[a-zA-Z][a-zA-Z0-9_-]*(?:\s+[^/~$\-\s][^\s|;&]*)?|--[a-z-]+(?:=\S+|\s+[^/~$\-\s][^\s|;&]*)?))*\s*$/,
  },
  {
    name: "shred-tmpdir",
    re: /^shred(?:\s+(?:-[a-zA-Z][a-zA-Z0-9_-]*(?:\s+[^/~$\-\s][^\s|;&]*)?|--[a-z-]+(?:=\S+|\s+[^/~$\-\s][^\s|;&]*)?))*\s+\$TMPDIR\/(?!\.\.(?:\/|\s|$)|[^\s]*\/\.\.(?:\/|\s|$))\S+(?:\s+(?:-[a-zA-Z][a-zA-Z0-9_-]*(?:\s+[^/~$\-\s][^\s|;&]*)?|--[a-z-]+(?:=\S+|\s+[^/~$\-\s][^\s|;&]*)?))*\s*$/,
  },
  {
    name: "shred-tmpdir-brace",
    re: /^shred(?:\s+(?:-[a-zA-Z][a-zA-Z0-9_-]*(?:\s+[^/~$\-\s][^\s|;&]*)?|--[a-z-]+(?:=\S+|\s+[^/~$\-\s][^\s|;&]*)?))*\s+\$\{TMPDIR\}\/(?!\.\.(?:\/|\s|$)|[^\s]*\/\.\.(?:\/|\s|$))\S+(?:\s+(?:-[a-zA-Z][a-zA-Z0-9_-]*(?:\s+[^/~$\-\s][^\s|;&]*)?|--[a-z-]+(?:=\S+|\s+[^/~$\-\s][^\s|;&]*)?))*\s*$/,
  },
  // `tar --remove-files` safe whitelist
  {
    name: "tar-remove-files-tmp",
    re: /^tar(?=\s+[^|;&]*--remove-files\b)(?:\s+(?:-[a-zA-Z][a-zA-Z0-9_-]*(?:\s+[^/~$\-\s][^\s|;&]*)?|--[a-z-]+(?:=\S+|\s+[^/~$\-\s][^\s|;&]*)?))*\s+\/tmp\/(?!\.\.(?:\/|\s|$)|[^\s]*\/\.\.(?:\/|\s|$))\S+(?:\s+(?:-[a-zA-Z][a-zA-Z0-9_-]*(?:\s+[^/~$\-\s][^\s|;&]*)?|--[a-z-]+(?:=\S+|\s+[^/~$\-\s][^\s|;&]*)?))*\s*$/,
  },
  {
    name: "tar-remove-files-var-tmp",
    re: /^tar(?=\s+[^|;&]*--remove-files\b)(?:\s+(?:-[a-zA-Z][a-zA-Z0-9_-]*(?:\s+[^/~$\-\s][^\s|;&]*)?|--[a-z-]+(?:=\S+|\s+[^/~$\-\s][^\s|;&]*)?))*\s+\/var\/tmp\/(?!\.\.(?:\/|\s|$)|[^\s]*\/\.\.(?:\/|\s|$))\S+(?:\s+(?:-[a-zA-Z][a-zA-Z0-9_-]*(?:\s+[^/~$\-\s][^\s|;&]*)?|--[a-z-]+(?:=\S+|\s+[^/~$\-\s][^\s|;&]*)?))*\s*$/,
  },
  {
    name: "tar-remove-files-tmpdir",
    re: /^tar(?=\s+[^|;&]*--remove-files\b)(?:\s+(?:-[a-zA-Z][a-zA-Z0-9_-]*(?:\s+[^/~$\-\s][^\s|;&]*)?|--[a-z-]+(?:=\S+|\s+[^/~$\-\s][^\s|;&]*)?))*\s+\$TMPDIR\/(?!\.\.(?:\/|\s|$)|[^\s]*\/\.\.(?:\/|\s|$))\S+(?:\s+(?:-[a-zA-Z][a-zA-Z0-9_-]*(?:\s+[^/~$\-\s][^\s|;&]*)?|--[a-z-]+(?:=\S+|\s+[^/~$\-\s][^\s|;&]*)?))*\s*$/,
  },
  {
    name: "tar-remove-files-tmpdir-brace",
    re: /^tar(?=\s+[^|;&]*--remove-files\b)(?:\s+(?:-[a-zA-Z][a-zA-Z0-9_-]*(?:\s+[^/~$\-\s][^\s|;&]*)?|--[a-z-]+(?:=\S+|\s+[^/~$\-\s][^\s|;&]*)?))*\s+\$\{TMPDIR\}\/(?!\.\.(?:\/|\s|$)|[^\s]*\/\.\.(?:\/|\s|$))\S+(?:\s+(?:-[a-zA-Z][a-zA-Z0-9_-]*(?:\s+[^/~$\-\s][^\s|;&]*)?|--[a-z-]+(?:=\S+|\s+[^/~$\-\s][^\s|;&]*)?))*\s*$/,
  },
  // `dd` safe whitelist
  {
    name: "dd-tmp",
    re: /^dd(?=\s+[^|;&]*\bof=)(?:\s+(?:[a-zA-Z]+=\S+|--?[a-zA-Z][a-zA-Z0-9-]*(?:=\S+)?))*\s+of=['"]?\/tmp\/(?!\.\.(?:\/|\s|$)|[^\s]*\/\.\.(?:\/|\s|$))\S+(?:\s+(?:[a-zA-Z]+=\S+|--?[a-zA-Z][a-zA-Z0-9-]*(?:=\S+)?))*\s*$/,
  },
  {
    name: "dd-var-tmp",
    re: /^dd(?=\s+[^|;&]*\bof=)(?:\s+(?:[a-zA-Z]+=\S+|--?[a-zA-Z][a-zA-Z0-9-]*(?:=\S+)?))*\s+of=['"]?\/var\/tmp\/(?!\.\.(?:\/|\s|$)|[^\s]*\/\.\.(?:\/|\s|$))\S+(?:\s+(?:[a-zA-Z]+=\S+|--?[a-zA-Z][a-zA-Z0-9-]*(?:=\S+)?))*\s*$/,
  },
  {
    name: "dd-tmpdir",
    re: /^dd(?=\s+[^|;&]*\bof=)(?:\s+(?:[a-zA-Z]+=\S+|--?[a-zA-Z][a-zA-Z0-9-]*(?:=\S+)?))*\s+of=['"]?\$TMPDIR\/(?!\.\.(?:\/|\s|$)|[^\s]*\/\.\.(?:\/|\s|$))\S+(?:\s+(?:[a-zA-Z]+=\S+|--?[a-zA-Z][a-zA-Z0-9-]*(?:=\S+)?))*\s*$/,
  },
  {
    name: "dd-tmpdir-brace",
    re: /^dd(?=\s+[^|;&]*\bof=)(?:\s+(?:[a-zA-Z]+=\S+|--?[a-zA-Z][a-zA-Z0-9-]*(?:=\S+)?))*\s+of=['"]?\$\{TMPDIR\}\/(?!\.\.(?:\/|\s|$)|[^\s]*\/\.\.(?:\/|\s|$))\S+(?:\s+(?:[a-zA-Z]+=\S+|--?[a-zA-Z][a-zA-Z0-9-]*(?:=\S+)?))*\s*$/,
  },
  { name: "dd-help", re: /^dd\s+(?:--help|--version)\s*$/ },
  // `mv` safe whitelist
  {
    name: "mv-tmp",
    re: /^mv(?:\s+(?:-[a-zA-Z][a-zA-Z0-9_-]*(?:\s+[^/~$\-\s][^\s|;&]*)?|--[a-z-]+(?:=\S+|\s+[^/~$\-\s][^\s|;&]*)?))*\s+(?:\/tmp\/(?!\.\.(?:\/|\s|$)|[^\s]*\/\.\.(?:\/|\s|$))\S+\s+)+\/tmp\/(?!\.\.(?:\/|\s|$)|[^\s]*\/\.\.(?:\/|\s|$))\S+\s*$/,
  },
  {
    name: "mv-var-tmp",
    re: /^mv(?:\s+(?:-[a-zA-Z][a-zA-Z0-9_-]*(?:\s+[^/~$\-\s][^\s|;&]*)?|--[a-z-]+(?:=\S+|\s+[^/~$\-\s][^\s|;&]*)?))*\s+(?:\/var\/tmp\/(?!\.\.(?:\/|\s|$)|[^\s]*\/\.\.(?:\/|\s|$))\S+\s+)+\/var\/tmp\/(?!\.\.(?:\/|\s|$)|[^\s]*\/\.\.(?:\/|\s|$))\S+\s*$/,
  },
  {
    name: "mv-tmpdir",
    re: /^mv(?:\s+(?:-[a-zA-Z][a-zA-Z0-9_-]*(?:\s+[^/~$\-\s][^\s|;&]*)?|--[a-z-]+(?:=\S+|\s+[^/~$\-\s][^\s|;&]*)?))*\s+(?:\$TMPDIR\/(?!\.\.(?:\/|\s|$)|[^\s]*\/\.\.(?:\/|\s|$))\S+\s+)+\$TMPDIR\/(?!\.\.(?:\/|\s|$)|[^\s]*\/\.\.(?:\/|\s|$))\S+\s*$/,
  },
  {
    name: "mv-tmpdir-brace",
    re: /^mv(?:\s+(?:-[a-zA-Z][a-zA-Z0-9_-]*(?:\s+[^/~$\-\s][^\s|;&]*)?|--[a-z-]+(?:=\S+|\s+[^/~$\-\s][^\s|;&]*)?))*\s+(?:\$\{TMPDIR\}\/(?!\.\.(?:\/|\s|$)|[^\s]*\/\.\.(?:\/|\s|$))\S+\s+)+\$\{TMPDIR\}\/(?!\.\.(?:\/|\s|$)|[^\s]*\/\.\.(?:\/|\s|$))\S+\s*$/,
  },
  { name: "mv-help", re: /^mv\s+(?:--help|--version)\s*$/ },
];

// ============================================================================
// Destructive patterns (DCG: create_destructive_patterns())
// Declaration order is load-bearing: first match wins.
// ============================================================================

const destructivePatterns: DestructiveRule[] = [
  // ----- cross-segment sensitive propagation before rm fallbacks -----
  {
    name: "cp-sensitive-then-delete",
    re: /\bcp\b[^|;&]*(?:\s(?:-[A-Za-z]*a[A-Za-z]*|--archive)\b)[^|;&]*?(?:\s|=)(?:['"\\]|\$['"])?(?:\/(?:etc|usr|bin|sbin|root|boot|lib|lib64|var|home|sys|proc|dev|opt)(?:\/|(?=[\s)'"]|$))|\/(?=[\s)'"]|$)|~(?=\s|$|\/|\))|\$\{?HOME\b)[^|;&]*?(?:\s|=)(?:['"\\]|\$['"])?(?:\/tmp\/|\/var\/tmp\/|\$TMPDIR\/|\$\{TMPDIR\}\/)[^|;&\s'"]*[^|;&]*(?:&&|;|\|\|)[^|;&]*\brm\b[^|;&]*\s(?:-[A-Za-z]*[rR][A-Za-z]*f[A-Za-z]*|-[A-Za-z]*f[A-Za-z]*[rR][A-Za-z]*|-[rR]\s+-f|-f\s+-[rR]|--recursive\s+--force|--force\s+--recursive)[^|;&]*?(?:\s|=)(?:['"\\]|\$['"])?(?:\/tmp\/|\/var\/tmp\/|\$TMPDIR\/|\$\{TMPDIR\}\/)/,
    severity: "critical",
    reason:
      "archive copy of a sensitive path into temp followed by forced recursive deletion is a cross-segment data-loss bypass. EXTREMELY DANGEROUS.",
    explanation: CP_SENSITIVE_THEN_DELETE_EXPLANATION,
    suggestions: SENSITIVE_PROPAGATION_DELETE_SUGGESTIONS,
  },
  {
    name: "ln-symlink-sensitive-then-delete",
    re: /\bln\b[^|;&]*\s-[A-Za-z]*s[A-Za-z]*[^|;&]*?(?:\s|=)(?:['"\\]|\$['"])?(?:\/(?:etc|usr|bin|sbin|root|boot|lib|lib64|var|home|sys|proc|dev|opt)(?:\/|(?=[\s)'"]|$))|\/(?=[\s)'"]|$)|~(?=\s|$|\/|\))|\$\{?HOME\b)[^|;&]*?(?:\s|=)(?:['"\\]|\$['"])?(?:\/tmp\/|\/var\/tmp\/|\$TMPDIR\/|\$\{TMPDIR\}\/)[^|;&\s'"]*[^|;&]*(?:&&|;|\|\|)[^|;&]*\brm\b[^|;&]*\s(?:-[A-Za-z]*[rR][A-Za-z]*f[A-Za-z]*|-[A-Za-z]*f[A-Za-z]*[rR][A-Za-z]*|-[rR]\s+-f|-f\s+-[rR]|--recursive\s+--force|--force\s+--recursive)[^|;&]*?(?:\s|=)(?:['"\\]|\$['"])?(?:\/tmp\/|\/var\/tmp\/|\$TMPDIR\/|\$\{TMPDIR\}\/)/,
    severity: "critical",
    reason:
      "symlink from a sensitive path into temp followed by forced recursive deletion can traverse and destroy the target. EXTREMELY DANGEROUS.",
    explanation: LN_SYMLINK_SENSITIVE_THEN_DELETE_EXPLANATION,
    suggestions: SENSITIVE_PROPAGATION_DELETE_SUGGESTIONS,
  },
  {
    name: "rsync-sensitive-then-delete",
    re: /\brsync\b[^|;&]*(?:\s(?:-[A-Za-z]*a[A-Za-z]*|--archive)\b)[^|;&]*?(?:\s|=)(?:['"\\]|\$['"])?(?:\/(?:etc|usr|bin|sbin|root|boot|lib|lib64|var|home|sys|proc|dev|opt)(?:\/|(?=[\s)'"]|$))|\/(?=[\s)'"]|$)|~(?=\s|$|\/|\))|\$\{?HOME\b)[^|;&]*?(?:\s|=)(?:['"\\]|\$['"])?(?:\/tmp\/|\/var\/tmp\/|\$TMPDIR\/|\$\{TMPDIR\}\/)[^|;&\s'"]*[^|;&]*(?:&&|;|\|\|)[^|;&]*\brm\b[^|;&]*\s(?:-[A-Za-z]*[rR][A-Za-z]*f[A-Za-z]*|-[A-Za-z]*f[A-Za-z]*[rR][A-Za-z]*|-[rR]\s+-f|-f\s+-[rR]|--recursive\s+--force|--force\s+--recursive)[^|;&]*?(?:\s|=)(?:['"\\]|\$['"])?(?:\/tmp\/|\/var\/tmp\/|\$TMPDIR\/|\$\{TMPDIR\}\/)/,
    severity: "critical",
    reason:
      "rsync archive of a sensitive path into temp followed by forced recursive deletion is a cross-segment data-loss bypass. EXTREMELY DANGEROUS.",
    explanation: RSYNC_SENSITIVE_THEN_DELETE_EXPLANATION,
    suggestions: SENSITIVE_PROPAGATION_DELETE_SUGGESTIONS,
  },
  // rm -rf on root or home paths (CRITICAL - catastrophic, never allow)
  {
    name: "rm-rf-root-home",
    re: /rm\s+-[a-zA-Z]*[rR][a-zA-Z]*f[a-zA-Z]*\s+['"\\]?(?:[/~]|\$\{?HOME\b)|rm\s+-[a-zA-Z]*f[a-zA-Z]*[rR][a-zA-Z]*\s+['"\\]?(?:[/~]|\$\{?HOME\b)/,
    severity: "critical",
    reason:
      "rm -rf on root or home paths is EXTREMELY DANGEROUS. This command will NOT be executed. Ask the user to run it manually if truly needed.",
    explanation: RM_RF_ROOT_HOME_EXPLANATION,
    suggestions: RM_RF_ROOT_HOME_SUGGESTIONS,
  },
  // Same root/home catastrophe but with SEPARATE flags (`rm -r -f /`, `rm -f -r /`)
  {
    name: "rm-r-f-separate-root-home",
    re: /rm\s+(-[a-zA-Z]+\s+)*-[rR]\s+(-[a-zA-Z]+\s+)*-f\s+['"\\]?(?:[/~]|\$\{?HOME\b)|rm\s+(-[a-zA-Z]+\s+)*-f\s+(-[a-zA-Z]+\s+)*-[rR]\s+['"\\]?(?:[/~]|\$\{?HOME\b)/,
    severity: "critical",
    reason:
      "rm with separate -r -f flags targeting root or home is EXTREMELY DANGEROUS.",
    explanation: RM_R_F_SEPARATE_ROOT_HOME_EXPLANATION,
    suggestions: RM_RF_ROOT_HOME_SUGGESTIONS,
  },
  // Same root/home catastrophe but with LONG flags
  {
    name: "rm-recursive-force-root-home",
    re: /rm\s+.*--recursive.*--force\s+['"\\]?(?:[/~]|\$\{?HOME\b)|rm\s+.*--force.*--recursive\s+['"\\]?(?:[/~]|\$\{?HOME\b)/,
    severity: "critical",
    reason:
      "rm --recursive --force targeting root or home is EXTREMELY DANGEROUS.",
    explanation: RM_RECURSIVE_FORCE_ROOT_HOME_EXPLANATION,
    suggestions: RM_RF_ROOT_HOME_SUGGESTIONS,
  },
  // General rm -rf (caught after safe patterns) - High because temp paths are allowed
  {
    name: "rm-rf-general",
    re: /rm\s+-[a-zA-Z]*[rR][a-zA-Z]*f|rm\s+-[a-zA-Z]*f[a-zA-Z]*[rR]/,
    severity: "high",
    reason:
      "rm -rf is destructive and requires human approval. Explain what you want to delete and why, then ask the user to run the command manually.",
    explanation: RM_RF_GENERAL_EXPLANATION,
    suggestions: RM_RF_GENERAL_SUGGESTIONS,
  },
  // rm -r -f (separate flags)
  {
    name: "rm-r-f-separate",
    re: /rm\s+(-[a-zA-Z]+\s+)*-[rR]\s+(-[a-zA-Z]+\s+)*-f|rm\s+(-[a-zA-Z]+\s+)*-f\s+(-[a-zA-Z]+\s+)*-[rR]/,
    severity: "high",
    reason:
      "rm with separate -r -f flags is destructive and requires human approval.",
    explanation: RM_R_F_SEPARATE_EXPLANATION,
    suggestions: RM_R_F_SEPARATE_SUGGESTIONS,
  },
  // rm --recursive --force (long flags)
  {
    name: "rm-recursive-force-long",
    re: /rm\s+.*--recursive.*--force|rm\s+.*--force.*--recursive/,
    severity: "high",
    reason:
      "rm --recursive --force is destructive and requires human approval.",
    explanation: RM_RECURSIVE_FORCE_EXPLANATION,
    suggestions: RM_RECURSIVE_FORCE_SUGGESTIONS,
  },
  // ----- `find ... -delete` (Critical: root/home target) -----
  {
    name: "find-delete-root-home",
    re: /\bfind\b[^|;&]*?(?:\s|=)['"\\]?(?:\/(?:etc|usr|bin|sbin|root|boot|lib|lib64|var|home|sys|proc|dev|opt)(?:\/|(?=\s|$|['"]))|\/(?=\s|$|['"])|~(?=\s|$|\/)|\$\{?HOME\b)[^|;&]*?\s-delete(?:\s|$|[;&|)\n])/,
    severity: "critical",
    reason:
      "find <sensitive-path> -delete is bytewise-equivalent to rm -rf on root/home and is EXTREMELY DANGEROUS. This command will NOT be executed.",
    explanation: FIND_DELETE_ROOT_HOME_EXPLANATION,
    suggestions: FIND_DELETE_SUGGESTIONS,
  },
  // ----- `find ... -delete` (High: any other target) -----
  {
    name: "find-delete-general",
    re: /\bfind\b[^|;&]*\s-delete(?:\s|$|[;&|)\n])/,
    severity: "high",
    reason:
      "find ... -delete is destructive (bytewise-equivalent to rm -rf on the matched tree) and requires human approval.",
    explanation: FIND_DELETE_GENERAL_EXPLANATION,
    suggestions: FIND_DELETE_SUGGESTIONS,
  },
  // ----- `unlink <file>` (Critical: root/home/system target) -----
  {
    name: "unlink-root-home",
    re: /\bunlink\s+['"\\]?(?:\/(?:etc|usr|bin|sbin|root|boot|lib|lib64|var|home|sys|proc|dev|opt)(?:\/|(?=\s|$|['"]))|\/(?=\s|$|['"])|~(?=\s|$|\/)|\$\{?HOME\b)/,
    severity: "critical",
    reason:
      "unlink on a sensitive system or home path is one-shot data destruction with no recovery. EXTREMELY DANGEROUS.",
    explanation: UNLINK_ROOT_HOME_EXPLANATION,
    suggestions: UNLINK_SUGGESTIONS,
  },
  // ----- `unlink <file>` (High: any other target) -----
  {
    name: "unlink-general",
    re: /\bunlink\s+\S/,
    severity: "high",
    reason:
      "unlink is destructive (POSIX equivalent of rm on a single file) and requires human approval.",
    explanation: UNLINK_GENERAL_EXPLANATION,
    suggestions: UNLINK_SUGGESTIONS,
  },
  // ----- `truncate -s 0|--size=0|-s -N` (Critical: root/home/system) -----
  {
    name: "truncate-zero-root-home",
    re: /\btruncate\b[^|;&]*?(?:\s-s\s*(?:0\b|-\d+)|\s--size(?:=|\s+)(?:0\b|-\d+))[^|;&]*?\s+['"\\]?(?:\/(?:etc|usr|bin|sbin|root|boot|lib|lib64|var|home|sys|proc|dev|opt)(?:\/|(?=\s|$|['"]))|\/(?=\s|$|['"])|~(?=\s|$|\/)|\$\{?HOME\b)/,
    severity: "critical",
    reason:
      "truncate -s 0|-N on a sensitive system or home path destroys data. EXTREMELY DANGEROUS.",
    explanation: TRUNCATE_ZERO_ROOT_HOME_EXPLANATION,
    suggestions: TRUNCATE_SUGGESTIONS,
  },
  // ----- `truncate -s 0|--size=0|-s -N` (High: any other target) -----
  {
    name: "truncate-zero-general",
    re: /\btruncate\b[^|;&]*?(?:\s-s\s*(?:0\b|-\d+)|\s--size(?:=|\s+)(?:0\b|-\d+))/,
    severity: "high",
    reason:
      "truncate -s 0|-N is destructive (zeroes or shrinks file content) and requires human approval.",
    explanation: TRUNCATE_ZERO_GENERAL_EXPLANATION,
    suggestions: TRUNCATE_SUGGESTIONS,
  },
  // ----- `shred ...` (Critical: root/home/system) -----
  {
    name: "shred-root-home",
    re: /\bshred\b[^|;&]*?\s+['"\\]?(?:\/(?:etc|usr|bin|sbin|root|boot|lib|lib64|var|home|sys|proc|dev|opt)(?:\/|(?=\s|$|['"]))|\/(?=\s|$|['"])|~(?=\s|$|\/)|\$\{?HOME\b)/,
    severity: "critical",
    reason:
      "shred on a sensitive system or home path destroys data beyond forensic recovery. EXTREMELY DANGEROUS.",
    explanation: SHRED_ROOT_HOME_EXPLANATION,
    suggestions: SHRED_SUGGESTIONS,
  },
  // ----- `shred ...` (High: any other target) -----
  {
    name: "shred-general",
    re: /\bshred\s+(?:-[a-zA-Z]+\s+|--[a-z-]+\s+|--[a-z-]+=\S+\s+)*\S/,
    severity: "high",
    reason:
      "shred destroys file content beyond recovery and requires human approval.",
    explanation: SHRED_GENERAL_EXPLANATION,
    suggestions: SHRED_SUGGESTIONS,
  },
  // ----- `tar --remove-files <sensitive>` (Critical: root/home) -----
  {
    name: "tar-remove-files-root-home",
    re: /\btar\b[^|;&]*?\s--remove-files\b[^|;&]*?(?:\s|=)['"\\]?(?:\/(?:etc|usr|bin|sbin|root|boot|lib|lib64|var|home|sys|proc|dev|opt)(?:\/|(?=[\s)'"]|$))|\/(?=[\s)'"]|$)|~(?=\s|$|\/|\))|\$\{?HOME\b)|\btar\b[^|;&]*?(?:\s|=)['"\\]?(?:\/(?:etc|usr|bin|sbin|root|boot|lib|lib64|var|home|sys|proc|dev|opt)(?:\/|(?=[\s)'"]|$))|\/(?=[\s)'"]|$)|~(?=\s|$|\/|\))|\$\{?HOME\b)[^|;&]*?\s--remove-files\b/,
    severity: "critical",
    reason:
      "tar --remove-files on a sensitive system or home path is recursive deletion masquerading as an archive operation. EXTREMELY DANGEROUS.",
    explanation: TAR_REMOVE_FILES_ROOT_HOME_EXPLANATION,
    suggestions: TAR_REMOVE_FILES_SUGGESTIONS,
  },
  // ----- `tar --remove-files ...` (High: any other target) -----
  {
    name: "tar-remove-files-general",
    re: /\btar\b[^|;&]*?\s--remove-files\b/,
    severity: "high",
    reason:
      "tar --remove-files deletes source paths after archiving and requires human approval.",
    explanation: TAR_REMOVE_FILES_GENERAL_EXPLANATION,
    suggestions: TAR_REMOVE_FILES_SUGGESTIONS,
  },
  // ----- `dd of=<sensitive>` (Critical: root/home/system) -----
  {
    name: "dd-overwrite-root-home",
    re: /\bdd\b[^|;&]*?\bof=['"\\]?(?!\/dev\/)(?:\/(?:etc|usr|bin|sbin|root|boot|lib|lib64|var|home|sys|proc|opt)(?:\/|(?=[\s)'"]|$))|\/(?=[\s)'"]|$)|~(?=\s|$|\/|\))|\$\{?HOME\b)/,
    severity: "critical",
    reason:
      "dd of=<sensitive-path> overwrites file contents in place. EXTREMELY DANGEROUS on a system or home file.",
    explanation: DD_OVERWRITE_ROOT_HOME_EXPLANATION,
    suggestions: DD_OVERWRITE_SUGGESTIONS,
  },
  // ----- `dd of=<any-non-tmp>` (High: any other target) -----
  {
    name: "dd-overwrite-general",
    re: /\bdd\b[^|;&]*?\bof=['"\\]?(?!\/dev\/)\S/,
    severity: "high",
    reason:
      "dd with of=<file> overwrites file contents and requires human approval.",
    explanation: DD_OVERWRITE_GENERAL_EXPLANATION,
    suggestions: DD_OVERWRITE_SUGGESTIONS,
  },
  // ----- `mv <sensitive>` (Critical: cross-segment bypass) -----
  {
    name: "mv-sensitive-source-root-home",
    re: /\bmv\b[^|;&]*?(?:\s|=)(?:['"\\]|\$['"])?(?:\/(?:etc|usr|bin|sbin|root|boot|lib|lib64|var|home|sys|proc|dev|opt)(?:\/|(?=[\s)'"]|$))|\/(?=[\s)'"]|$)|~(?=\s|$|\/|\))|\$\{?HOME\b)/,
    severity: "critical",
    reason:
      "mv touching a sensitive system or home path is the cross-segment recursive-force-delete bypass. EXTREMELY DANGEROUS.",
    explanation: MV_SENSITIVE_SOURCE_ROOT_HOME_EXPLANATION,
    suggestions: MV_SENSITIVE_SUGGESTIONS,
  },
  // ----- `> <sensitive>` (Critical: shell redirect truncate) -----
  {
    name: "redirect-truncate-root-home",
    re: /(?<![<>])(?:&>|>&|[12]?>\|?)\s*(?:['"\\]|\$['"])?(?!\/dev\/(?:null|zero|full)\b)(?:\/(?:etc|usr|bin|sbin|root|boot|lib|lib64|var|home|sys|proc|dev|opt)(?:\/|(?=[\s)'"]|$))|\/(?=[\s)'"]|$)|~(?=\s|$|\/|\))|\$\{?HOME\b)/,
    severity: "critical",
    reason:
      "shell redirect (>, >|, &>, >&, 1>, 2>) to a sensitive system or home path truncates the file to zero bytes. EXTREMELY DANGEROUS.",
    explanation: REDIRECT_TRUNCATE_ROOT_HOME_EXPLANATION,
    suggestions: REDIRECT_TRUNCATE_SUGGESTIONS,
  },
];

/**
 * Core filesystem pack. `force: true` — DCG floor pack, always enabled.
 *
 * Keywords mirror DCG `create_pack()`'s `keywords` array exactly (including the
 * redirect-operator substrings) so the quick-reject prefilter matches the
 * same command set.
 */
export const coreFilesystemPack: Pack = {
  id: "core.filesystem",
  name: "Core Filesystem",
  description:
    "Protects against dangerous rm -rf commands and equivalent destruction (find -delete, unlink) outside temp directories",
  keywords: [
    "rm",
    "find",
    "unlink",
    "truncate",
    "shred",
    "tar",
    "dd",
    "mv",
    "cp",
    "ln",
    "rsync",
    ">/",
    "> /",
    ">~",
    "> ~",
    ">$",
    "> $",
    '>"',
    '> "',
    ">'",
    "> '",
    "&>",
    ">&",
    ">|",
    "1>",
    "2>",
  ],
  safePatterns,
  destructivePatterns,
  force: true,
  // The recursive-removal argv parser (rm/cp/ln/rsync) runs BEFORE the regex
  // safe/destructive patterns. See ../rm-parser.ts.
  imperative: rmImperativeChecks,
};
