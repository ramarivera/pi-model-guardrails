// Package managers pack — protections for package manager commands.
//
// Faithful port of DCG `src/packs/package_managers/mod.rs`
// (https://github.com/Dicklesworthstone/destructive_command_guard), a single
// flat pack (id "package_managers", no sub-packs).
//
// Covers npm/yarn/pnpm publish & unpublish, pip (un)install, apt/yum/dnf
// remove/purge, cargo publish/yank, gem push, brew uninstall, poetry
// publish/remove, and maven/gradle deploy/publish.
//
// JS RegExp porting notes (same rules as the committed core packs):
//  - No POSIX `[[:alnum:]]`, no inline `(?i)` (all case-sensitive => no "i"
//    flag), no possessive quantifiers in these patterns.
//  - DCG's `regex` + `fancy_regex` dual engine collapses to one JS RegExp:
//    the negative-lookahead `(?!...--dry-run...)` tails and the `(?=\s|$)`
//    trailing anchors port verbatim (JS RegExp supports both natively).
//  - DCG uses the 3-arg `destructive_pattern!(name, re, reason)` macro for
//    EVERY rule in this pack, which defaults severity to High — so every rule
//    below is `severity: "high"` with no explanation/suggestions.

import type { DestructiveRule, Pack, SafeRule } from "../types.ts";

// ---------------------------------------------------------------------------
// Safe patterns (allowed) — DCG `create_safe_patterns`.
// ---------------------------------------------------------------------------

const safePatterns: SafeRule[] = [
  // npm/yarn/pnpm install are generally safe.
  {
    name: "npm-install",
    re: /\bnpm\b(?:\s+--?\S+(?:\s+\S+)?)*\s+(?:install|i|ci)(?=\s|$)/,
  },
  {
    name: "yarn-add",
    re: /\byarn\b(?:\s+--?\S+(?:\s+\S+)?)*\s+(?:add|install)(?=\s|$)/,
  },
  {
    name: "pnpm-install",
    re: /\bpnpm\b(?:\s+--?\S+(?:\s+\S+)?)*\s+(?:add|install|i)(?=\s|$)/,
  },
  // list/info commands are safe.
  {
    name: "npm-list",
    re: /\bnpm\b(?:\s+--?\S+(?:\s+\S+)?)*\s+(?:list|ls|info|view)(?=\s|$)/,
  },
  {
    name: "yarn-list",
    re: /\byarn\b(?:\s+--?\S+(?:\s+\S+)?)*\s+(?:list|info|why)(?=\s|$)/,
  },
  // audit is safe.
  { name: "npm-audit", re: /\bnpm\b(?:\s+--?\S+(?:\s+\S+)?)*\s+audit(?=\s|$)/ },
  {
    name: "yarn-audit",
    re: /\byarn\b(?:\s+--?\S+(?:\s+\S+)?)*\s+audit(?=\s|$)/,
  },
  // pip list/show are safe.
  {
    name: "pip-list",
    re: /\bpip\b(?:\s+--?\S+(?:\s+\S+)?)*\s+(?:list|show|freeze)(?=\s|$)/,
  },
  // poetry show/info are safe.
  {
    name: "poetry-show",
    re: /\bpoetry\b(?:\s+--?\S+(?:\s+\S+)?)*\s+show(?=\s|$)/,
  },
  {
    name: "poetry-env-list",
    re: /\bpoetry\b(?:\s+--?\S+(?:\s+\S+)?)*\s+env\s+list(?=\s|$)/,
  },
  // cargo build/test/check are safe.
  {
    name: "cargo-safe",
    re: /\bcargo\b(?:\s+--?\S+(?:\s+\S+)?)*\s+(?:build|test|check|clippy|fmt|doc|bench)\b/,
  },
  // apt list/show are safe.
  {
    name: "apt-list",
    re: /\bapt\b(?:\s+--?\S+(?:\s+\S+)?)*\s+(?:list|show|search)(?=\s|$)/,
  },
  {
    name: "apt-get-list",
    re: /\bapt-get\b(?:\s+--?\S+(?:\s+\S+)?)*\s+(?:update|upgrade)(?!\s+.*-y)/,
  },
  // dry-run flags. Only bare `--dry-run` or explicit true count as previews;
  // false-valued flags must not mask publish rules.
  { name: "npm-dry-run", re: /\bnpm\b.*--dry-run(?:=true)?(?:\s|$)/ },
  { name: "yarn-dry-run", re: /\byarn\b.*--dry-run(?:=true)?(?:\s|$)/ },
  { name: "pnpm-dry-run", re: /\bpnpm\b.*--dry-run(?:=true)?(?:\s|$)/ },
  { name: "cargo-dry-run", re: /\bcargo\b.*--dry-run(?:=true)?(?:\s|$)/ },
  { name: "poetry-dry-run", re: /\bpoetry\b.*--dry-run(?:=true)?(?:\s|$)/ },
];

// ---------------------------------------------------------------------------
// Destructive patterns (blocked) — DCG `create_destructive_patterns`.
// Declaration order is load-bearing (first-match-wins). All severity High
// (DCG 3-arg `destructive_pattern!` => default High).
// ---------------------------------------------------------------------------

const destructivePatterns: DestructiveRule[] = [
  // npm/yarn/pnpm publish.
  {
    name: "npm-publish",
    re: /\bnpm\b.*?\bpublish\b(?!.*--dry-run(?:=true)?(?:\s|$))/,
    severity: "high",
    reason: "npm publish releases a package publicly. Use --dry-run first.",
  },
  {
    name: "yarn-publish",
    re: /\byarn\b.*?\bpublish\b(?!.*--dry-run(?:=true)?(?:\s|$))/,
    severity: "high",
    reason:
      "yarn publish releases a package publicly. Verify package.json first.",
  },
  {
    name: "pnpm-publish",
    re: /\bpnpm\b.*?\bpublish\b(?!.*--dry-run(?:=true)?(?:\s|$))/,
    severity: "high",
    reason: "pnpm publish releases a package publicly.",
  },
  // npm unpublish.
  {
    name: "npm-unpublish",
    re: /\bnpm\b.*?\bunpublish(?=\s|$)/,
    severity: "high",
    reason:
      "npm unpublish removes a published package. This can break dependent projects.",
  },
  // pip uninstall.
  {
    name: "pip-uninstall",
    re: /\bpip(?:3)?\b.*?\buninstall(?=\s|$)/,
    severity: "high",
    reason:
      "pip uninstall removes installed packages. Verify dependencies before removing.",
  },
  // pip install from URL (potential security risk).
  {
    name: "pip-url",
    re: /\bpip\b.*?\binstall\s+.*(?:https?:\/\/|git\+)/,
    severity: "high",
    reason:
      "pip install from URL can install unvetted code. Verify the source first.",
  },
  // pip install --user or --system.
  {
    name: "pip-system",
    re: /\bpip\b.*?\binstall\s+.*--(?:system|target\s*\/usr)/,
    severity: "high",
    reason: "pip install to system directories requires careful review.",
  },
  // apt remove/purge.
  {
    name: "apt-remove",
    re: /\bapt(?:-get)?\b.*?\b(?:remove|purge|autoremove)(?=\s|$)/,
    severity: "high",
    reason:
      "apt remove/purge removes packages. Verify no critical packages are affected.",
  },
  // yum/dnf remove.
  {
    name: "yum-remove",
    re: /\b(?:yum|dnf)\b.*?\b(?:remove|erase|autoremove)(?=\s|$)/,
    severity: "high",
    reason:
      "yum/dnf remove removes packages. Verify no critical packages are affected.",
  },
  // cargo publish.
  {
    name: "cargo-publish",
    re: /\bcargo\b.*?\bpublish\b(?!.*--dry-run(?:=true)?(?:\s|$))/,
    severity: "high",
    reason: "cargo publish releases a crate to crates.io. Use --dry-run first.",
  },
  // cargo yank.
  {
    name: "cargo-yank",
    re: /\bcargo\b.*?\byank(?=\s|$)/,
    severity: "high",
    reason:
      "cargo yank marks a version as unavailable. This can break dependent projects.",
  },
  // gem push.
  {
    name: "gem-push",
    re: /\bgem\b.*?\bpush\b/,
    severity: "high",
    reason:
      "gem push releases a gem to rubygems.org. Verify before publishing.",
  },
  // brew uninstall.
  {
    name: "brew-uninstall",
    re: /\bbrew\b.*?\b(?:uninstall|remove)(?=\s|$)/,
    severity: "high",
    reason:
      "brew uninstall removes packages. Verify no dependent packages are affected.",
  },
  // poetry publish/remove.
  {
    name: "poetry-publish",
    re: /\bpoetry\b.*?\bpublish\b(?!.*--dry-run(?:=true)?(?:\s|$))/,
    severity: "high",
    reason: "poetry publish releases a package. Use --dry-run first.",
  },
  {
    name: "poetry-remove",
    re: /\bpoetry\b.*?\bremove(?=\s|$)/,
    severity: "high",
    reason:
      "poetry remove uninstalls a dependency. Verify no critical packages are affected.",
  },
  // maven deploy / release.
  {
    name: "maven-deploy",
    re: /\b(?:mvn|mvnw)\b.*?\bdeploy\b/,
    severity: "high",
    reason:
      "mvn deploy publishes artifacts to a remote repository. Verify target repository.",
  },
  {
    name: "maven-release-perform",
    re: /\b(?:mvn|mvnw)\s+.*release:perform\b/,
    severity: "high",
    reason:
      "mvn release:perform publishes a release. Verify version and repository.",
  },
  // gradle publish / release.
  {
    name: "gradle-publish",
    re: /\b(?:gradle|gradlew)\s+.*\bpublish\b/,
    severity: "high",
    reason:
      "gradle publish uploads artifacts. Use --dry-run first when possible.",
  },
];

/**
 * Package managers pack — `force` is NOT set (DCG `package_managers` is a
 * regular, config-gated pack, not a floor pack).
 *
 * Source: DCG `src/packs/package_managers/mod.rs` (`create_pack`).
 */
export const packageManagersPack: Pack = {
  id: "package_managers",
  name: "Package Managers",
  description:
    "Protects against dangerous package manager operations like publishing " +
    "packages and removing critical system packages",
  keywords: [
    "npm",
    "yarn",
    "pnpm",
    "pip",
    "apt",
    "yum",
    "dnf",
    "cargo",
    "gem",
    "brew",
    "poetry",
    "mvn",
    "mvnw",
    "gradle",
    "gradlew",
    "publish",
  ],
  safePatterns,
  destructivePatterns,
};
