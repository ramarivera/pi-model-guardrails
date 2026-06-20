// Core git pack — ported faithfully from DCG `src/packs/core/git.rs`.
//
// Protects against destructive git commands that can lose uncommitted work,
// rewrite history, or destroy stashes.
//
// Fidelity notes (see portNotes in the porting record):
//  - POSIX `[[:alnum:]]` -> `[A-Za-z0-9]` (`_` and `-` kept OUTSIDE the class as in DCG).
//  - Bounded shell-boundary walkers `[^\s&;|`()<>]` and the `(?![-a-z])` /
//    `(?:\s|$)` tails are kept VERBATIM from DCG.
//  - No inline flags / possessive quantifiers exist in these patterns, so the
//    Rust regexes transliterate 1:1 into JS RegExp (no flags needed; these are
//    intentionally case-sensitive — lowercase subcommands + explicit [a-z]/[A-Z]).
//  - `--force-with-lease` / `--force-if-includes` stay ALLOWED: push-force-long's
//    `--force(?![-a-z])` and branch-force-delete's `--force(?:\s|$)` both refuse
//    to match the `--force-` prefix of those safer flags.

import type { DestructiveRule, Pack, SafeRule, Suggestion } from "../types.ts";

const ALL = "all" as const;

function s(command: string, description: string): Suggestion {
  // DCG `PatternSuggestion::new` defaults to `Platform::All`.
  return { command, description, platform: ALL };
}

// ---------------------------------------------------------------------------
// Safe patterns (allowed) — DCG `create_safe_patterns`.
// ---------------------------------------------------------------------------

const safePatterns: SafeRule[] = [
  // Branch creation is safe.
  {
    name: "checkout-new-branch",
    re: /(?:^|[^A-Za-z0-9_-])git\s+(?:\S+\s+)*checkout\s+-b\s+/,
  },
  {
    name: "checkout-orphan",
    re: /(?:^|[^A-Za-z0-9_-])git\s+(?:\S+\s+)*checkout\s+--orphan\s+/,
  },
  // restore --staged / -S only affects the index, not the working tree. Match
  // --staged/-S anywhere in the restore segment (DIVERGES from DCG's
  // first-token-only form so `git restore --source=X --staged f` is allowed),
  // as long as no --worktree/-W appears in the same segment. The bounded
  // `[^&;|`()<>]*` keeps the lookahead/scan within one shell segment.
  {
    name: "restore-staged-long",
    re: /(?:^|[^A-Za-z0-9_-])git\s+(?:\S+\s+)*restore\b(?![^&;|`()<>]*(?:--worktree\b|-W\b))[^&;|`()<>]*--staged\b/,
  },
  {
    name: "restore-staged-short",
    re: /(?:^|[^A-Za-z0-9_-])git\s+(?:\S+\s+)*restore\b(?![^&;|`()<>]*(?:--worktree\b|-W\b))[^&;|`()<>]*-S\b/,
  },
  // clean dry-run just previews, doesn't delete. Match -n anywhere in the clean
  // segment (DIVERGES from DCG first-token form) so `git clean -d -n -f` is not
  // wrongly blocked by the force rule below.
  {
    name: "clean-dry-run-short",
    re: /(?:^|[^A-Za-z0-9_-])git\s+(?:\S+\s+)*clean\s+(?:[^\s&;|`()<>]+\s+)*-[a-z]*n[a-z]*/,
  },
  {
    name: "clean-dry-run-long",
    re: /(?:^|[^A-Za-z0-9_-])git\s+(?:\S+\s+)*clean\s+--dry-run/,
  },
];

// ---------------------------------------------------------------------------
// Destructive patterns (blocked) — DCG `create_destructive_patterns`.
// Declaration order is load-bearing (first-match-wins per segment / command).
// ---------------------------------------------------------------------------

const destructivePatterns: DestructiveRule[] = [
  // checkout -- discards uncommitted changes.
  {
    name: "checkout-discard",
    re: /(?:^|[^A-Za-z0-9_-])git\s+(?:\S+\s+)*checkout\s+--\s+/,
    severity: "high",
    reason:
      "git checkout -- discards uncommitted changes permanently. Use 'git stash' first.",
    explanation:
      "git checkout -- <path> discards all uncommitted changes to the specified files " +
      "in your working directory. These changes are permanently lost - they cannot be " +
      "recovered because they were never committed.\n\n" +
      "Safer alternatives:\n" +
      "- git stash: Save changes temporarily, restore later with 'git stash pop'\n" +
      "- git diff <path>: Review what would be lost before discarding\n\n" +
      "Preview changes first:\n  git diff -- <path>\n\n" +
      "Recovering from a failed `git pull --rebase`?\n" +
      "Run `dcg rebase-recover` in this repo, then retry the command. This issues a " +
      "short-lived, single-shot permit that unblocks this rule only. A rebase already " +
      "in progress (`.git/rebase-merge/` or `.git/rebase-apply/` present) auto-allows " +
      "the same rule without a permit.",
    suggestions: [
      s("git stash", "Save changes temporarily, restore later with 'git stash pop'"),
      s("git diff -- {path}", "Review what would be lost before discarding"),
    ],
  },
  {
    name: "checkout-ref-discard",
    re: /(?:^|[^A-Za-z0-9_-])git\s+(?:\S+\s+)*checkout\s+(?!-b\b)(?!--orphan\b)[^\s]+\s+--\s+/,
    severity: "high",
    reason:
      "git checkout <ref> -- <path> overwrites working tree. Use 'git stash' first.",
    explanation:
      "git checkout <ref> -- <path> replaces your working tree files with versions from " +
      "another commit or branch. Any uncommitted changes to those files are permanently " +
      "lost - they cannot be recovered.\n\n" +
      "Safer alternatives:\n" +
      "- git stash: Save changes first, then checkout, then restore with 'git stash pop'\n" +
      "- git show <ref>:<path>: View the file content without overwriting\n\n" +
      "Preview what would change:\n  git diff HEAD <ref> -- <path>",
    suggestions: [
      s("git stash", "Save changes first, then checkout, then restore with 'git stash pop'"),
      s("git show {ref}:{path}", "View the file content without overwriting"),
      s("git diff HEAD {ref} -- {path}", "Preview what would change before overwriting"),
    ],
  },
  // checkout -f / --force overwrites the working tree, discarding uncommitted
  // changes. (Coverage gap in DCG core.git; added per the Phase 1 review.)
  {
    name: "checkout-force",
    re: /(?:^|[^A-Za-z0-9_-])git\s+(?:[^\s&;|`()<>]+\s+)*checkout\s+(?:[^\s&;|`()<>]+\s+)*(?:-[a-zA-Z]*f[a-zA-Z]*\b|--force\b)/,
    severity: "high",
    reason:
      "git checkout -f/--force overwrites the working tree, discarding uncommitted changes. Use 'git stash' first.",
    explanation:
      "git checkout --force (or -f) overwrites your working tree to match the target " +
      "branch/ref, permanently discarding any uncommitted changes.\n\n" +
      "Safer alternatives:\n" +
      "- git stash: save changes first, switch, then 'git stash pop'\n" +
      "- git status && git diff: review what would be lost first",
    suggestions: [
      s("git stash", "Save changes first, then checkout, then restore with 'git stash pop'"),
      s("git status && git diff", "Review what would be lost before forcing checkout"),
    ],
  },
  // restore without --staged affects the working tree. The added
  // `(?![^&;|`()<>]*(?:--worktree|-W))` lookahead defers the --worktree/-W forms
  // to restore-worktree-explicit below (correct rule attribution), and the
  // safe restore-staged rules above already shield the index-only forms.
  {
    name: "restore-worktree",
    re: /(?:^|[^A-Za-z0-9_-])git\s+(?:\S+\s+)*restore\s+(?!--staged\b)(?!-S\b)(?![^&;|`()<>]*(?:--worktree\b|-W\b))/,
    severity: "high",
    reason:
      "git restore discards uncommitted changes. Use 'git stash' or 'git diff' first.",
    explanation:
      "git restore <path> discards uncommitted changes in your working directory, " +
      "reverting files to their last committed state. Changes that were never " +
      "committed are permanently lost.\n\n" +
      "Safer alternatives:\n" +
      "- git restore --staged <path>: Only unstage, keeps working directory changes\n" +
      "- git stash: Save all changes temporarily\n" +
      "- git diff <path>: Review what would be lost\n\n" +
      "Preview changes first:\n  git diff <path>\n\n" +
      "Recovering from a failed `git pull --rebase`?\n" +
      "Run `dcg rebase-recover` in this repo, then retry the command. This issues a " +
      "short-lived, single-shot permit that unblocks this rule only. A rebase already " +
      "in progress (`.git/rebase-merge/` or `.git/rebase-apply/` present) auto-allows " +
      "the same rule without a permit.",
    suggestions: [
      s("git restore --staged {path}", "Only unstage, keeps working directory changes intact"),
      s("git stash", "Save all changes temporarily, restore later with 'git stash pop'"),
      s("git diff {path}", "Review what would be lost before discarding"),
    ],
  },
  {
    name: "restore-worktree-explicit",
    re: /(?:^|[^A-Za-z0-9_-])git\s+(?:\S+\s+)*restore\s+[^&;|`()<>]*(?:--worktree|-W\b)/,
    severity: "high",
    reason: "git restore --worktree/-W discards uncommitted changes permanently.",
    explanation:
      "git restore --worktree (or -W) explicitly targets your working directory, " +
      "discarding uncommitted changes. Even when combined with --staged, the worktree " +
      "changes are permanently lost.\n\n" +
      "Safer alternatives:\n" +
      "- git restore --staged <path>: Only unstage, keeps working directory\n" +
      "- git stash: Save changes first\n\n" +
      "Preview changes first:\n  git diff <path>",
    suggestions: [
      s("git restore --staged {path}", "Only unstage, keeps working directory changes intact"),
      s("git stash", "Save all changes temporarily before discarding"),
      s("git diff {path}", "Review what would be lost before discarding"),
    ],
  },
  // reset --hard destroys uncommitted work (CRITICAL - extremely common mistake).
  {
    name: "reset-hard",
    // Bounded walker between `reset` and `--hard` so intervening flags don't
    // bypass it (`git reset -q --hard`, `git reset --quiet --hard HEAD~1`).
    // DIVERGES from DCG's first-token-only form to close a reviewed FN.
    re: /(?:^|[^A-Za-z0-9_-])git\s+(?:\S+\s+)*reset\s+(?:[^\s&;|`()<>]+\s+)*--hard/,
    severity: "critical",
    reason: "git reset --hard destroys uncommitted changes. Use 'git stash' first.",
    explanation:
      "git reset --hard discards ALL uncommitted changes in your working directory " +
      "AND staging area. This is one of the most dangerous git commands because " +
      "changes that were never committed cannot be recovered by any means.\n\n" +
      "What gets destroyed:\n" +
      "- All modified files revert to the target commit\n" +
      "- All staged changes are lost\n" +
      "- Untracked files remain (use git clean to remove those)\n\n" +
      "Safer alternatives:\n" +
      "- git reset --soft <ref>: Move HEAD but keep all changes staged\n" +
      "- git reset --mixed <ref>: Move HEAD, unstage changes, keep working dir (default)\n" +
      "- git stash: Save changes before resetting\n\n" +
      "Preview what would be lost:\n  git status && git diff",
    suggestions: [
      s("git stash", "Save all uncommitted changes before reset"),
      s("git reset --soft HEAD~1", "Undo commit but keep all changes staged"),
      s("git reset --mixed HEAD~1", "Undo commit, unstage changes, but keep working directory"),
      s("git checkout -- {file}", "Reset a specific file only, preserving other changes"),
    ],
  },
  {
    name: "reset-merge",
    re: /(?:^|[^A-Za-z0-9_-])git\s+(?:\S+\s+)*reset\s+--merge/,
    severity: "high",
    reason: "git reset --merge can lose uncommitted changes.",
    explanation:
      "git reset --merge resets the index and updates files in the working tree that " +
      "differ between the target commit and HEAD, but keeps changes that are not staged. " +
      "However, if there are uncommitted changes in files that need to be updated, " +
      "those changes will be lost.\n\n" +
      "Safer alternatives:\n" +
      "- git stash: Save uncommitted changes before reset\n" +
      "- git merge --abort: If in the middle of a merge, abort safely\n\n" +
      "Preview what would change:\n  git status && git diff",
    suggestions: [
      s("git stash", "Save uncommitted changes before reset"),
      s("git merge --abort", "Abort the current merge safely without losing changes"),
      s("git status && git diff", "Preview what would change before resetting"),
    ],
  },
  // clean -f deletes untracked files (CRITICAL - permanently removes files).
  {
    name: "clean-force",
    // Bounded walker between `clean` and the force flag so separate flags don't
    // bypass it (`git clean -d -f`, `git clean -x -f`, `git clean -e build -f`).
    // The order-independent clean dry-run safe pattern above still shields any
    // `-n` form. DIVERGES from DCG's first-token-only form to close a reviewed FN.
    re: /(?:^|[^A-Za-z0-9_-])git\s+(?:\S+\s+)*clean\s+(?:[^\s&;|`()<>]+\s+)*(?:-[a-z]*f|--force\b)/,
    severity: "critical",
    reason:
      "git clean -f/--force removes untracked files permanently. Review with 'git clean -n' first.",
    explanation:
      "git clean -f permanently deletes untracked files from your working directory. " +
      "These are files that have never been committed to git, so they cannot be " +
      "recovered from git history. If you haven't backed them up elsewhere, they " +
      "are gone forever.\n\n" +
      "Common dangerous combinations:\n" +
      "- git clean -fd: Also removes untracked directories\n" +
      "- git clean -xf: Also removes ignored files (build artifacts, .env, etc.)\n\n" +
      "Safer alternatives:\n" +
      "- git clean -n: Dry-run, shows what would be deleted\n" +
      "- git clean -i: Interactive mode, choose what to delete\n\n" +
      "ALWAYS preview first:\n  git clean -n -d",
    suggestions: [
      s("git clean -n", "Dry run first (shows what would be deleted)"),
      s("git clean -nd", "Dry run including directories"),
      s("git clean -i", "Interactive mode, choose what to delete"),
      s("git stash --include-untracked", "Stash instead of delete (recoverable)"),
    ],
  },
  // force push can destroy remote history (CRITICAL - affects shared history).
  // Bounded walker `[^\s&;|`()<>]` keeps the match within a single command
  // segment; `--force(?![-a-z])` refuses to match `--force-with-lease`.
  {
    name: "push-force-long",
    re: /(?:^|[^A-Za-z0-9_-])git\s+(?:[^\s&;|`()<>]+\s+)*push\s+(?:[^\s&;|`()<>]+\s+)*--force(?![-a-z])/,
    severity: "critical",
    reason: "Force push can destroy remote history. Use --force-with-lease if necessary.",
    explanation:
      "git push --force overwrites remote history with your local history. This can " +
      "permanently destroy commits that others have already pulled, causing data loss " +
      "for your entire team. Collaborators may lose work, and recovering requires " +
      "manual intervention from everyone affected.\n\n" +
      "What can go wrong:\n" +
      "- Commits others pushed are deleted from remote\n" +
      "- Team members get diverged histories\n" +
      "- CI/CD pipelines may reference deleted commits\n\n" +
      "Safer alternative:\n" +
      "- git push --force-with-lease: Only forces if remote matches your last fetch\n\n" +
      "Check remote state first:\n  git fetch && git log origin/<branch>..HEAD",
    suggestions: [
      s("git push --force-with-lease", "Fails if remote has new commits you haven't fetched"),
      s(
        "git push --force-with-lease --force-if-includes",
        "Even safer: also checks that your local ref includes the remote ref",
      ),
      s(
        "git fetch && git log origin/{branch}..HEAD",
        "Preview what you're about to overwrite on the remote",
      ),
    ],
  },
  // catch combined short forms (`-uf`, `-fv`, `-vf`, `-fuvq`) that resolve to `-f`.
  {
    name: "push-force-short",
    re: /(?:^|[^A-Za-z0-9_-])git\s+(?:[^\s&;|`()<>]+\s+)*push\s+(?:[^\s&;|`()<>]+\s+)*-[a-zA-Z]*f[a-zA-Z]*\b/,
    severity: "critical",
    reason:
      "Force push (-f) can destroy remote history. Use --force-with-lease if necessary.",
    explanation:
      "git push -f (short for --force) overwrites remote history with your local history. " +
      "This can permanently destroy commits that others have already pulled, causing data " +
      "loss for your entire team.\n\n" +
      "What can go wrong:\n" +
      "- Commits others pushed are deleted from remote\n" +
      "- Team members get diverged histories\n" +
      "- CI/CD pipelines may reference deleted commits\n\n" +
      "Safer alternative:\n" +
      "- git push --force-with-lease: Only forces if remote matches your last fetch\n\n" +
      "Check remote state first:\n  git fetch && git log origin/<branch>..HEAD",
    suggestions: [
      s("git push --force-with-lease", "Fails if remote has new commits you haven't fetched"),
      s(
        "git push --force-with-lease --force-if-includes",
        "Even safer: also checks that your local ref includes the remote ref",
      ),
      s(
        "git fetch && git log origin/{branch}..HEAD",
        "Preview what you're about to overwrite on the remote",
      ),
    ],
  },
  // branch -D/-f force deletes or overwrites without checks (Medium: recoverable via reflog).
  // `--force(?:\s|$)` tail (not `\b`) so it does not match `--force-with-lease`.
  {
    name: "branch-force-delete",
    re: /(?:^|[^A-Za-z0-9_-])git\s+(?:[^\s&;|`()<>]+\s+)*branch\s+(?:[^\s&;|`()<>]+\s+)*(?:-[a-zA-Z]*[Df][a-zA-Z]*(?:\s|$)|--force(?:\s|$))/,
    severity: "medium",
    reason:
      "git branch -D/--force deletes branches without checks. Recoverable via 'git reflog'.",
    explanation:
      "git branch -D force-deletes a branch without checking if it has been merged. " +
      "If the branch contains unmerged commits, you may lose access to that work. " +
      "However, the commits still exist in git's object database and can be recovered " +
      "using reflog (for a limited time, typically 90 days).\n\n" +
      "Safer alternatives:\n" +
      "- git branch -d <branch>: Safe delete, fails if branch is not fully merged\n" +
      "- Merge the branch first, then delete with -d\n\n" +
      "Recovery if needed:\n" +
      "  git reflog  # Find the commit hash\n" +
      "  git checkout -b <branch> <commit-hash>",
    suggestions: [
      s("git branch -d {branch}", "Safe delete: only works if branch is fully merged"),
      s("git branch -v {branch}", "Show branch info (last commit) before deleting"),
      s("git log {branch} --oneline -10", "Review branch commits before deleting"),
    ],
  },
  // stash destruction (Medium: single stash, recoverable via fsck/unreachable objects).
  {
    name: "stash-drop",
    re: /(?:^|[^A-Za-z0-9_-])git\s+(?:\S+\s+)*stash\s+drop/,
    severity: "medium",
    reason:
      "git stash drop deletes a single stash. Recoverable via `git fsck` (unreachable objects).",
    explanation:
      "git stash drop removes a specific stash entry from your stash list. The stashed " +
      "changes become unreferenced but remain in git's object database temporarily. " +
      "They can often be recovered using git fsck, but this is not guaranteed and " +
      "becomes harder over time as git garbage collects.\n\n" +
      "Safer alternatives:\n" +
      "- git stash pop: Apply and drop in one step (only drops if apply succeeds)\n" +
      "- git stash apply: Apply without dropping, verify first\n\n" +
      "Recovery if needed:\n" +
      "  git fsck --unreachable | grep commit\n" +
      "  git show <commit-hash>  # Inspect each to find your stash",
    suggestions: [
      s("git stash pop", "Apply and drop atomically (only drops if apply succeeds)"),
      s("git stash apply", "Apply without dropping, verify changes first"),
      s("git stash show stash@{0}", "Preview stash contents before dropping"),
      s("git stash list", "Review all stashes before dropping any"),
    ],
  },
  // stash clear destroys ALL stashes (CRITICAL).
  {
    name: "stash-clear",
    re: /(?:^|[^A-Za-z0-9_-])git\s+(?:\S+\s+)*stash\s+clear/,
    severity: "critical",
    reason: "git stash clear permanently deletes ALL stashed changes.",
    explanation:
      "git stash clear removes ALL stash entries at once. Unlike git stash drop, " +
      "which removes one at a time, this command wipes your entire stash list. " +
      "All stashed changes become unreferenced and are very difficult to recover.\n\n" +
      "What gets destroyed:\n" +
      "- All entries in 'git stash list' are removed\n" +
      "- Multiple sets of saved work-in-progress may be lost\n\n" +
      "Safer alternatives:\n" +
      "- git stash drop stash@{n}: Remove one specific stash at a time\n" +
      "- git stash list: Review what would be lost first\n" +
      "- git stash show stash@{n}: Inspect each stash before deciding\n\n" +
      "Recovery (difficult, not guaranteed):\n" +
      "  git fsck --unreachable | grep commit",
    suggestions: [
      s("git stash drop stash@{n}", "Remove one specific stash at a time"),
      s("git stash list", "Review all stashes before clearing"),
      s("git stash show stash@{n}", "Inspect each stash before deciding to delete"),
    ],
  },
];

/**
 * Core git pack — `force: true` (DCG floor pack, always enabled).
 *
 * Source: DCG `src/packs/core/git.rs` (`create_pack`).
 */
export const coreGitPack: Pack = {
  id: "core.git",
  name: "Core Git",
  description:
    "Protects against destructive git commands that can lose uncommitted work, " +
    "rewrite history, or destroy stashes",
  keywords: ["git"],
  safePatterns,
  destructivePatterns,
  force: true,
};
