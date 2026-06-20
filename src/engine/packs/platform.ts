// Platform pack — hosting/platform CLIs (GitHub gh, Railway, Kamal, Modal, GitLab).
//
// Faithful port of DCG's five platform sub-packs into ONE Pack:
//   - src/packs/platform/github.rs   -> id "platform.github"   (gh)
//   - src/packs/platform/railway.rs  -> id "platform.railway"  (railway CLI + GraphQL API)
//   - src/packs/platform/kamal.rs    -> id "platform.kamal"    (kamal)
//   - src/packs/platform/modal.rs    -> id "platform.modal"    (modal)
//   - src/packs/platform/gitlab.rs   -> id "platform.gitlab"   (glab / gitlab-rails / gitlab-rake)
// (https://github.com/Dicklesworthstone/destructive_command_guard)
//
// MERGE NOTE: DCG ships these as five `create_pack()`s. The Pi module contract
// asks for ONE `platformPack`, so the rule sets are concatenated. Rule NAMES
// are already tool-prefixed in DCG (`gh-*`, `railway-*`, `kamal-*`, `modal-*`,
// `glab-*`/`gitlab-*`) so they stay unique. reason/explanation/severity/
// suggestions and per-tool declaration order are preserved 1:1. The tool
// executables are distinct (gh / railway / kamal / modal / glab / gitlab-rails
// / gitlab-rake), so cross-tool order is not load-bearing.
//
// JS RegExp porting notes (this category):
//  - SEVERITY DEFAULT: DCG's `destructive_pattern!` defaults to `High` when no
//    severity arg is given. github.rs and gitlab.rs use the 3-arg form (no
//    severity), so every gh-* and glab-*/gitlab-* destructive rule is "high".
//  - INLINE `(?i)`: the railway *-api-* patterns are authored with a leading
//    `(?i)`. JS has no inline flag, so those RegExp carry the "i" flag instead
//    (stripped from the source string, applied to the whole literal — DCG's
//    `(?i)` is also leading/whole-pattern, so this is equivalent). The railway
//    CLI rules and ALL other tools' rules are case-sensitive (no flag).
//  - github's walker uses `\x22` (hex escape for the double-quote char) inside
//    `[^\x22]`/literal positions; that is just `"` in a JS regex literal:
//    `(?:(?:"[^"]*")|(?:'[^']*')|\S+)`.
//  - PatternSuggestion::new(command, description) defaults to Platform::All.
//  - Bounded token-walkers `(?:\s+--?[A-Za-z]...)*`, `(?:[^;&|\r\n]|\\\r?\n)*`,
//    lazy `.*?`, lookaheads/negative-lookaheads, and `\b` anchors are native JS
//    and ported verbatim. No POSIX classes, no possessive quantifiers.

import type { DestructiveRule, Pack, SafeRule, Suggestion } from "../types.ts";

const ALL = "all" as const;

/** DCG `PatternSuggestion::new` — defaults to Platform::All. */
function s(command: string, description: string): Suggestion {
  return { command, description, platform: ALL };
}

// ============================================================================
// GitHub (gh) — DCG src/packs/platform/github.rs
// All gh-* destructive rules use the 3-arg macro form => default severity High.
// The shared global-flag walker (verbatim) before every subcommand:
//   (?:\s+--?[A-Za-z][A-Za-z0-9-]*\b(?:\s+(?!(?:repo|gist|release|issue|ssh-key|
//   secret|variable|run|auth|status|api)\b)(?:(?:"[^"]*")|(?:'[^']*')|\S+))?)*
// ============================================================================

const githubSafe: SafeRule[] = [
  { name: "gh-repo-list-view", re: /gh(?:\s+--?[A-Za-z][A-Za-z0-9-]*\b(?:\s+(?!(?:repo|gist|release|issue|ssh-key|secret|variable|run|auth|status|api)\b)(?:(?:"[^"]*")|(?:'[^']*')|\S+))?)*\s+repo\s+(?:list|view)\b/ },
  { name: "gh-gist-list-view", re: /gh(?:\s+--?[A-Za-z][A-Za-z0-9-]*\b(?:\s+(?!(?:repo|gist|release|issue|ssh-key|secret|variable|run|auth|status|api)\b)(?:(?:"[^"]*")|(?:'[^']*')|\S+))?)*\s+gist\s+(?:list|view)\b/ },
  { name: "gh-release-list-view", re: /gh(?:\s+--?[A-Za-z][A-Za-z0-9-]*\b(?:\s+(?!(?:repo|gist|release|issue|ssh-key|secret|variable|run|auth|status|api)\b)(?:(?:"[^"]*")|(?:'[^']*')|\S+))?)*\s+release\s+(?:list|view)\b/ },
  { name: "gh-issue-list-view", re: /gh(?:\s+--?[A-Za-z][A-Za-z0-9-]*\b(?:\s+(?!(?:repo|gist|release|issue|ssh-key|secret|variable|run|auth|status|api)\b)(?:(?:"[^"]*")|(?:'[^']*')|\S+))?)*\s+issue\s+(?:list|view)\b/ },
  { name: "gh-ssh-key-list", re: /gh(?:\s+--?[A-Za-z][A-Za-z0-9-]*\b(?:\s+(?!(?:repo|gist|release|issue|ssh-key|secret|variable|run|auth|status|api)\b)(?:(?:"[^"]*")|(?:'[^']*')|\S+))?)*\s+ssh-key\s+list\b/ },
  { name: "gh-secret-list", re: /gh(?:\s+--?[A-Za-z][A-Za-z0-9-]*\b(?:\s+(?!(?:repo|gist|release|issue|ssh-key|secret|variable|run|auth|status|api)\b)(?:(?:"[^"]*")|(?:'[^']*')|\S+))?)*\s+secret\s+list\b/ },
  { name: "gh-variable-list", re: /gh(?:\s+--?[A-Za-z][A-Za-z0-9-]*\b(?:\s+(?!(?:repo|gist|release|issue|ssh-key|secret|variable|run|auth|status|api)\b)(?:(?:"[^"]*")|(?:'[^']*')|\S+))?)*\s+variable\s+list\b/ },
  { name: "gh-auth-status", re: /gh(?:\s+--?[A-Za-z][A-Za-z0-9-]*\b(?:\s+(?!(?:repo|gist|release|issue|ssh-key|secret|variable|run|auth|status|api)\b)(?:(?:"[^"]*")|(?:'[^']*')|\S+))?)*\s+auth\s+status\b/ },
  { name: "gh-status", re: /gh(?:\s+--?[A-Za-z][A-Za-z0-9-]*\b(?:\s+(?!(?:repo|gist|release|issue|ssh-key|secret|variable|run|auth|status|api)\b)(?:(?:"[^"]*")|(?:'[^']*')|\S+))?)*\s+status\b/ },
  { name: "gh-api-explicit-get", re: /^(?!(?=.*(?:-X\s*|--method(?:=|\s+))DELETE\b))gh(?:\s+--?[A-Za-z][A-Za-z0-9-]*\b(?:\s+(?!(?:repo|gist|release|issue|ssh-key|secret|variable|run|auth|status|api)\b)(?:(?:"[^"]*")|(?:'[^']*')|\S+))?)*\s+api\b.*(?:-X\s*|--method(?:=|\s+))GET\b/ },
];

const githubDestructive: DestructiveRule[] = [
  { name: "gh-repo-delete", re: /gh(?:\s+--?[A-Za-z][A-Za-z0-9-]*\b(?:\s+(?!(?:repo|gist|release|issue|ssh-key|secret|variable|run|auth|status|api)\b)(?:(?:"[^"]*")|(?:'[^']*')|\S+))?)*\s+repo\s+delete\b/, severity: "high", reason: "gh repo delete permanently deletes a GitHub repository. This cannot be undone." },
  { name: "gh-repo-archive", re: /gh(?:\s+--?[A-Za-z][A-Za-z0-9-]*\b(?:\s+(?!(?:repo|gist|release|issue|ssh-key|secret|variable|run|auth|status|api)\b)(?:(?:"[^"]*")|(?:'[^']*')|\S+))?)*\s+repo\s+archive\b/, severity: "high", reason: "gh repo archive makes a repository read-only. While reversible, it stops all write access." },
  { name: "gh-gist-delete", re: /gh(?:\s+--?[A-Za-z][A-Za-z0-9-]*\b(?:\s+(?!(?:repo|gist|release|issue|ssh-key|secret|variable|run|auth|status|api)\b)(?:(?:"[^"]*")|(?:'[^']*')|\S+))?)*\s+gist\s+delete\b/, severity: "high", reason: "gh gist delete permanently deletes a Gist." },
  { name: "gh-release-delete", re: /gh(?:\s+--?[A-Za-z][A-Za-z0-9-]*\b(?:\s+(?!(?:repo|gist|release|issue|ssh-key|secret|variable|run|auth|status|api)\b)(?:(?:"[^"]*")|(?:'[^']*')|\S+))?)*\s+release\s+delete\b/, severity: "high", reason: "gh release delete permanently deletes a release." },
  { name: "gh-issue-delete", re: /gh(?:\s+--?[A-Za-z][A-Za-z0-9-]*\b(?:\s+(?!(?:repo|gist|release|issue|ssh-key|secret|variable|run|auth|status|api)\b)(?:(?:"[^"]*")|(?:'[^']*')|\S+))?)*\s+issue\s+delete\b/, severity: "high", reason: "gh issue delete permanently deletes an issue." },
  { name: "gh-ssh-key-delete", re: /gh(?:\s+--?[A-Za-z][A-Za-z0-9-]*\b(?:\s+(?!(?:repo|gist|release|issue|ssh-key|secret|variable|run|auth|status|api)\b)(?:(?:"[^"]*")|(?:'[^']*')|\S+))?)*\s+ssh-key\s+delete\b/, severity: "high", reason: "gh ssh-key delete removes an SSH key, potentially breaking access." },
  { name: "gh-secret-delete", re: /gh(?:\s+--?[A-Za-z][A-Za-z0-9-]*\b(?:\s+(?!(?:repo|gist|release|issue|ssh-key|secret|variable|run|auth|status|api)\b)(?:(?:"[^"]*")|(?:'[^']*')|\S+))?)*\s+secret\s+(?:delete|remove)\b/, severity: "high", reason: "gh secret delete removes GitHub Actions secrets." },
  { name: "gh-variable-delete", re: /gh(?:\s+--?[A-Za-z][A-Za-z0-9-]*\b(?:\s+(?!(?:repo|gist|release|issue|ssh-key|secret|variable|run|auth|status|api)\b)(?:(?:"[^"]*")|(?:'[^']*')|\S+))?)*\s+variable\s+(?:delete|remove)\b/, severity: "high", reason: "gh variable delete removes GitHub Actions variables." },
  { name: "gh-repo-deploy-key-delete", re: /gh(?:\s+--?[A-Za-z][A-Za-z0-9-]*\b(?:\s+(?!(?:repo|gist|release|issue|ssh-key|secret|variable|run|auth|status|api)\b)(?:(?:"[^"]*")|(?:'[^']*')|\S+))?)*\s+repo\s+deploy-key\s+delete\b/, severity: "high", reason: "gh repo deploy-key delete removes a deploy key and can break access." },
  { name: "gh-run-cancel", re: /gh(?:\s+--?[A-Za-z][A-Za-z0-9-]*\b(?:\s+(?!(?:repo|gist|release|issue|ssh-key|secret|variable|run|auth|status|api)\b)(?:(?:"[^"]*")|(?:'[^']*')|\S+))?)*\s+run\s+cancel\b/, severity: "high", reason: "gh run cancel stops a workflow run and may interrupt deployments." },
  { name: "gh-api-delete-actions-secret", re: /gh(?:\s+--?[A-Za-z][A-Za-z0-9-]*\b(?:\s+(?!(?:repo|gist|release|issue|ssh-key|secret|variable|run|auth|status|api)\b)(?:(?:"[^"]*")|(?:'[^']*')|\S+))?)*\s+api\b.*(?:-X\s*|--method(?:=|\s+))DELETE\b.*(?:\/)?repos\/[^/\s]+\/[^/\s]+\/actions\/secrets\//, severity: "high", reason: "gh api DELETE actions/secrets removes GitHub Actions secrets." },
  { name: "gh-api-delete-actions-variable", re: /gh(?:\s+--?[A-Za-z][A-Za-z0-9-]*\b(?:\s+(?!(?:repo|gist|release|issue|ssh-key|secret|variable|run|auth|status|api)\b)(?:(?:"[^"]*")|(?:'[^']*')|\S+))?)*\s+api\b.*(?:-X\s*|--method(?:=|\s+))DELETE\b.*(?:\/)?repos\/[^/\s]+\/[^/\s]+\/actions\/variables\//, severity: "high", reason: "gh api DELETE actions/variables removes GitHub Actions variables." },
  { name: "gh-api-delete-hook", re: /gh(?:\s+--?[A-Za-z][A-Za-z0-9-]*\b(?:\s+(?!(?:repo|gist|release|issue|ssh-key|secret|variable|run|auth|status|api)\b)(?:(?:"[^"]*")|(?:'[^']*')|\S+))?)*\s+api\b.*(?:-X\s*|--method(?:=|\s+))DELETE\b.*(?:\/)?repos\/[^/\s]+\/[^/\s]+\/hooks\//, severity: "high", reason: "gh api DELETE hooks removes repository webhooks." },
  { name: "gh-api-delete-deploy-key", re: /gh(?:\s+--?[A-Za-z][A-Za-z0-9-]*\b(?:\s+(?!(?:repo|gist|release|issue|ssh-key|secret|variable|run|auth|status|api)\b)(?:(?:"[^"]*")|(?:'[^']*')|\S+))?)*\s+api\b.*(?:-X\s*|--method(?:=|\s+))DELETE\b.*(?:\/)?repos\/[^/\s]+\/[^/\s]+\/keys\//, severity: "high", reason: "gh api DELETE keys removes deploy keys." },
  { name: "gh-api-delete-release", re: /gh(?:\s+--?[A-Za-z][A-Za-z0-9-]*\b(?:\s+(?!(?:repo|gist|release|issue|ssh-key|secret|variable|run|auth|status|api)\b)(?:(?:"[^"]*")|(?:'[^']*')|\S+))?)*\s+api\b.*(?:-X\s*|--method(?:=|\s+))DELETE\b.*(?:\/)?repos\/[^/\s]+\/[^/\s]+\/releases\//, severity: "high", reason: "gh api DELETE releases removes GitHub releases." },
  { name: "gh-api-delete-repo", re: /gh(?:\s+--?[A-Za-z][A-Za-z0-9-]*\b(?:\s+(?!(?:repo|gist|release|issue|ssh-key|secret|variable|run|auth|status|api)\b)(?:(?:"[^"]*")|(?:'[^']*')|\S+))?)*\s+api\b.*(?:-X\s*|--method(?:=|\s+))DELETE\b/, severity: "high", reason: "gh api DELETE calls can be destructive. Please verify the endpoint." },
];

// ============================================================================
// Railway — DCG src/packs/platform/railway.rs
// CLI rules are case-sensitive; the *-api-* rules carry "i" (DCG leading (?i)).
// ============================================================================

const RAILWAY_PROJECT_SUGGESTIONS: Suggestion[] = [
  s("railway status", "Confirm the currently linked project and environment before any project change"),
  s("railway list", "List projects to verify the target instead of deleting it"),
];
const RAILWAY_ENVIRONMENT_SUGGESTIONS: Suggestion[] = [
  s("railway environment list", "List environments and verify that production is not the target"),
  s("railway status", "Confirm the active project and environment before making changes"),
];
const RAILWAY_SERVICE_SUGGESTIONS: Suggestion[] = [
  s("railway service list", "List services before deleting or changing one"),
  s("railway logs", "Inspect the service state without removing it"),
];
const RAILWAY_FUNCTION_SUGGESTIONS: Suggestion[] = [
  s("railway functions list", "List functions before deleting one"),
  s("railway status", "Confirm the active project and environment before changing functions"),
];
const RAILWAY_VOLUME_SUGGESTIONS: Suggestion[] = [
  s("railway volume list", "List volumes and identify any database storage before changing it"),
  s("railway status", "Confirm the active project and environment before touching volumes"),
];
const RAILWAY_VARIABLE_SUGGESTIONS: Suggestion[] = [
  s("railway variable list", "Review variables before deleting or overwriting them"),
  s("railway variable list --json", "Capture the current values in a reviewable format before changing secrets"),
];
const RAILWAY_DEPLOYMENT_SUGGESTIONS: Suggestion[] = [
  s("railway status", "Confirm the target service and environment before removing deployments"),
  s("railway logs", "Inspect deployment state without stopping or removing it"),
];

const railwaySafe: SafeRule[] = [
  { name: "railway-status", re: /railway(?:\s+--?\S+(?:\s+\S+)?)*\s+status(?:\s|$)/ },
  { name: "railway-project-list", re: /railway(?:\s+--?\S+(?:\s+\S+)?)*\s+(?:list|ls)(?:\s|$)/ },
  { name: "railway-project-subcommand-list", re: /railway(?:\s+--?\S+(?:\s+\S+)?)*\s+project\s+(?:list|ls)(?:\s|$)/ },
  { name: "railway-whoami", re: /railway(?:\s+--?\S+(?:\s+\S+)?)*\s+whoami(?:\s|$)/ },
  { name: "railway-logs", re: /railway(?:\s+--?\S+(?:\s+\S+)?)*\s+logs(?:\s|$)/ },
  { name: "railway-service-list", re: /railway(?:\s+--?\S+(?:\s+\S+)?)*\s+service\s+(?:list|ls)(?:\s|$)/ },
  { name: "railway-function-list", re: /railway(?:\s+--?\S+(?:\s+\S+)?)*\s+(?:function|functions|func|funcs|fn|fns)\s+(?:list|ls)(?:\s|$)/ },
  { name: "railway-environment-list", re: /railway(?:\s+--?\S+(?:\s+\S+)?)*\s+(?:environment|env)\s+(?:list|ls)(?:\s|$)/ },
  { name: "railway-volume-list", re: /railway(?:\s+--?\S+(?:\s+\S+)?)*\s+volume\s+(?:list|ls)(?:\s|$)/ },
  { name: "railway-variable-list", re: /railway(?:\s+--?\S+(?:\s+\S+)?)*\s+(?:variable|variables|vars|var)\s+(?:list|ls)(?:\s|$)/ },
];

// DB-connection variable-name alternation, reused by several railway rules.
const RAILWAY_DB_VARS =
  "DATABASE_URL|DATABASE_PRIVATE_URL|DATABASE_PUBLIC_URL|RAILWAY_DATABASE_URL|PGHOST|PGPORT|PGUSER|PGPASSWORD|PGDATABASE|POSTGRES_HOST|POSTGRES_PORT|POSTGRES_USER|POSTGRES_PASSWORD|POSTGRES_DB|POSTGRES_DATABASE|POSTGRES_URL|POSTGRES_PRIVATE_URL|POSTGRES_PUBLIC_URL|POSTGRESQL_URL|POSTGRESQL_PRIVATE_URL|POSTGRESQL_PUBLIC_URL|MYSQL_URL|MYSQL_PRIVATE_URL|MYSQL_PUBLIC_URL|MYSQLHOST|MYSQLPORT|MYSQLUSER|MYSQLPASSWORD|MYSQLDATABASE|REDIS_URL|REDIS_PRIVATE_URL|REDIS_PUBLIC_URL|REDISHOST|REDISUSER|REDISPORT|REDISPASSWORD|MONGO_URL|MONGO_PRIVATE_URL|MONGO_PUBLIC_URL|MONGODB_URI|MONGODB_URL|MONGODB_PRIVATE_URL|MONGODB_PUBLIC_URL|MONGOHOST|MONGOPORT|MONGOUSER|MONGOPASSWORD";

const railwayDestructive: DestructiveRule[] = [
  {
    name: "railway-project-delete",
    re: /railway(?:\s+--?\S+(?:\s+\S+)?)*\s+delete(?:\s|$)/,
    severity: "critical",
    reason: "railway delete schedules deletion of the entire Railway project.",
    explanation:
      "Deleting a Railway project can remove every service, database, volume, variable, and deployment attached to it.",
    suggestions: RAILWAY_PROJECT_SUGGESTIONS,
  },
  {
    name: "railway-project-subcommand-delete",
    re: /railway(?:\s+--?\S+(?:\s+\S+)?)*\s+project\s+(?:delete|remove|rm)(?:\s|$)/,
    severity: "critical",
    reason: "railway project delete schedules deletion of the entire Railway project.",
    explanation:
      "Deleting a Railway project can remove every service, database, volume, variable, and deployment attached to it.",
    suggestions: RAILWAY_PROJECT_SUGGESTIONS,
  },
  {
    name: "railway-environment-delete",
    re: /railway(?:\s+--?\S+(?:\s+\S+)?)*\s+(?:environment|env)\s+(?:delete|remove|rm)(?:\s|$)/,
    severity: "critical",
    reason: "railway environment delete removes a Railway environment and its resources.",
    explanation:
      "Deleting an environment can remove production services, database instances, volumes, and variables in that environment.",
    suggestions: RAILWAY_ENVIRONMENT_SUGGESTIONS,
  },
  {
    name: "railway-service-delete",
    re: /railway(?:\s+--?\S+(?:\s+\S+)?)*\s+service\s+(?:delete|remove|rm)(?:\s|$)/,
    severity: "critical",
    reason: "railway service delete permanently deletes a Railway service.",
    explanation:
      "Deleting a service can remove the production app or managed database service and its deployment history.",
    suggestions: RAILWAY_SERVICE_SUGGESTIONS,
  },
  {
    name: "railway-function-delete",
    re: /railway(?:\s+--?\S+(?:\s+\S+)?)*\s+(?:function|functions|func|funcs|fn|fns)\s+(?:delete|remove|rm)(?:\s|$)/,
    severity: "critical",
    reason: "railway functions delete removes a Railway serverless function.",
    explanation:
      "Deleting a Railway function can remove production serverless code, HTTP endpoints, or scheduled jobs.",
    suggestions: RAILWAY_FUNCTION_SUGGESTIONS,
  },
  {
    name: "railway-volume-delete",
    re: /railway(?:\s+--?\S+(?:\s+\S+)?)*\s+volume\s+(?:delete|remove|rm)(?:\s|$)/,
    severity: "critical",
    reason: "railway volume delete removes persistent Railway storage.",
    explanation:
      "Deleting a Railway volume can destroy persistent database storage and is catastrophic when the volume backs production data.",
    suggestions: RAILWAY_VOLUME_SUGGESTIONS,
  },
  {
    name: "railway-volume-detach",
    re: /railway(?:\s+--?\S+(?:\s+\S+)?)*\s+volume\s+detach(?:\s|$)/,
    severity: "high",
    reason: "railway volume detach disconnects persistent storage from a service.",
    explanation:
      "Detaching a volume can take a production database or stateful service offline even when the bytes are not immediately deleted.",
    suggestions: RAILWAY_VOLUME_SUGGESTIONS,
  },
  {
    name: "railway-variable-delete",
    re: /railway(?:\s+--?\S+(?:\s+\S+)?)*\s+(?:variable|variables|vars|var)\s+(?:delete|remove|rm)(?:\s|$)/,
    severity: "high",
    reason: "railway variable delete removes Railway environment variables.",
    explanation:
      "Deleting environment variables can break production deploys, database connections, credentials, and service-to-service links.",
    suggestions: RAILWAY_VARIABLE_SUGGESTIONS,
  },
  {
    name: "railway-database-variable-set",
    re: new RegExp(
      `railway(?:\\s+--?\\S+(?:\\s+\\S+)?)*\\s+(?:variable|variables|vars|var)\\s+(?:set|upsert)(?:[^;&|\\r\\n]|\\\\\\r?\\n)*(?:\\s|[^=\\\\]\\\\?["'])(?:${RAILWAY_DB_VARS})(?:\\s|=|\\\\?["']\\s*:|$)`,
    ),
    severity: "high",
    reason: "railway variable set is changing a database connection variable.",
    explanation:
      "Overwriting database connection variables can redirect production traffic or disconnect an app from its production database.",
    suggestions: RAILWAY_VARIABLE_SUGGESTIONS,
  },
  {
    name: "railway-database-variable-legacy-set",
    re: new RegExp(
      `railway(?:\\s+--?\\S+(?:\\s+\\S+)?)*\\s+(?:variable|variables|vars|var)(?:\\s+--?\\S+(?:\\s+\\S+)?)*(?:\\s+--set(?:=|\\s+)|\\s+--set-from-stdin(?:=|\\s+))(?:${RAILWAY_DB_VARS})(?:\\s|=|$)`,
    ),
    severity: "high",
    reason: "railway variable legacy flags are changing a database connection variable.",
    explanation:
      "Legacy Railway variable flags can still overwrite database connection variables and break production database access.",
    suggestions: RAILWAY_VARIABLE_SUGGESTIONS,
  },
  {
    name: "railway-deployment-remove",
    re: /railway(?:\s+--?\S+(?:\s+\S+)?)*\s+down(?:\s|$)/,
    severity: "high",
    reason: "railway down removes the latest successful deployment.",
    explanation: "Removing a deployment can interrupt production service availability.",
    suggestions: RAILWAY_DEPLOYMENT_SUGGESTIONS,
  },
  {
    name: "railway-api-project-delete",
    re: /(?:backboard\.railway\.(?:app|com)|railway\.(?:app|com)\/graphql|RAILWAY_API_(?:URL|TOKEN)|RAILWAY_TOKEN|PROJECT_ACCESS_TOKEN|Project-Access-Token)(?:[^;&|\r\n]|\\\r?\n)*(?:projectDelete|projectScheduleDelete)|(?:projectDelete|projectScheduleDelete)(?:[^;&|\r\n]|\\\r?\n)*(?:backboard\.railway\.(?:app|com)|railway\.(?:app|com)\/graphql|RAILWAY_API_(?:URL|TOKEN)|RAILWAY_TOKEN|PROJECT_ACCESS_TOKEN|Project-Access-Token)/i,
    severity: "critical",
    reason: "Railway Public API project deletion mutation detected.",
    explanation:
      "Railway GraphQL project deletion mutations can remove an entire project and all attached production resources.",
    suggestions: RAILWAY_PROJECT_SUGGESTIONS,
  },
  {
    name: "railway-api-environment-delete",
    re: /(?:backboard\.railway\.(?:app|com)|railway\.(?:app|com)\/graphql|RAILWAY_API_(?:URL|TOKEN)|RAILWAY_TOKEN|PROJECT_ACCESS_TOKEN|Project-Access-Token)(?:[^;&|\r\n]|\\\r?\n)*environmentDelete|environmentDelete(?:[^;&|\r\n]|\\\r?\n)*(?:backboard\.railway\.(?:app|com)|railway\.(?:app|com)\/graphql|RAILWAY_API_(?:URL|TOKEN)|RAILWAY_TOKEN|PROJECT_ACCESS_TOKEN|Project-Access-Token)/i,
    severity: "critical",
    reason: "Railway Public API environment deletion mutation detected.",
    explanation:
      "Railway GraphQL environment deletion mutations can remove production services, databases, volumes, and variables.",
    suggestions: RAILWAY_ENVIRONMENT_SUGGESTIONS,
  },
  {
    name: "railway-api-service-delete",
    re: /(?:backboard\.railway\.(?:app|com)|railway\.(?:app|com)\/graphql|RAILWAY_API_(?:URL|TOKEN)|RAILWAY_TOKEN|PROJECT_ACCESS_TOKEN|Project-Access-Token)(?:[^;&|\r\n]|\\\r?\n)*serviceDelete|serviceDelete(?:[^;&|\r\n]|\\\r?\n)*(?:backboard\.railway\.(?:app|com)|railway\.(?:app|com)\/graphql|RAILWAY_API_(?:URL|TOKEN)|RAILWAY_TOKEN|PROJECT_ACCESS_TOKEN|Project-Access-Token)/i,
    severity: "critical",
    reason: "Railway Public API service deletion mutation detected.",
    explanation:
      "Railway GraphQL service deletion mutations can remove a production app or managed database service.",
    suggestions: RAILWAY_SERVICE_SUGGESTIONS,
  },
  {
    name: "railway-api-volume-delete",
    re: /(?:backboard\.railway\.(?:app|com)|railway\.(?:app|com)\/graphql|RAILWAY_API_(?:URL|TOKEN)|RAILWAY_TOKEN|PROJECT_ACCESS_TOKEN|Project-Access-Token)(?:[^;&|\r\n]|\\\r?\n)*(?:volumeDelete|volumeInstanceDelete)|(?:volumeDelete|volumeInstanceDelete)(?:[^;&|\r\n]|\\\r?\n)*(?:backboard\.railway\.(?:app|com)|railway\.(?:app|com)\/graphql|RAILWAY_API_(?:URL|TOKEN)|RAILWAY_TOKEN|PROJECT_ACCESS_TOKEN|Project-Access-Token)/i,
    severity: "critical",
    reason: "Railway Public API volume deletion mutation detected.",
    explanation: "Railway GraphQL volume deletion mutations can destroy persistent database storage.",
    suggestions: RAILWAY_VOLUME_SUGGESTIONS,
  },
  {
    name: "railway-api-volume-backup-restore",
    re: /(?:backboard\.railway\.(?:app|com)|railway\.(?:app|com)\/graphql|RAILWAY_API_(?:URL|TOKEN)|RAILWAY_TOKEN|PROJECT_ACCESS_TOKEN|Project-Access-Token)(?:[^;&|\r\n]|\\\r?\n)*volumeInstanceBackupRestore|volumeInstanceBackupRestore(?:[^;&|\r\n]|\\\r?\n)*(?:backboard\.railway\.(?:app|com)|railway\.(?:app|com)\/graphql|RAILWAY_API_(?:URL|TOKEN)|RAILWAY_TOKEN|PROJECT_ACCESS_TOKEN|Project-Access-Token)/i,
    severity: "critical",
    reason: "Railway Public API volume backup restore mutation detected.",
    explanation:
      "Restoring a Railway volume backup can replace current persistent data and roll back a production database.",
    suggestions: RAILWAY_VOLUME_SUGGESTIONS,
  },
  {
    name: "railway-api-volume-backup-delete",
    re: /(?:backboard\.railway\.(?:app|com)|railway\.(?:app|com)\/graphql|RAILWAY_API_(?:URL|TOKEN)|RAILWAY_TOKEN|PROJECT_ACCESS_TOKEN|Project-Access-Token)(?:[^;&|\r\n]|\\\r?\n)*volumeInstanceBackupDelete|volumeInstanceBackupDelete(?:[^;&|\r\n]|\\\r?\n)*(?:backboard\.railway\.(?:app|com)|railway\.(?:app|com)\/graphql|RAILWAY_API_(?:URL|TOKEN)|RAILWAY_TOKEN|PROJECT_ACCESS_TOKEN|Project-Access-Token)/i,
    severity: "high",
    reason: "Railway Public API volume backup deletion mutation detected.",
    explanation:
      "Deleting Railway volume backups removes recovery points for persistent database storage.",
    suggestions: RAILWAY_VOLUME_SUGGESTIONS,
  },
  {
    name: "railway-api-volume-backup-schedule-update",
    re: /(?:backboard\.railway\.(?:app|com)|railway\.(?:app|com)\/graphql|RAILWAY_API_(?:URL|TOKEN)|RAILWAY_TOKEN|PROJECT_ACCESS_TOKEN|Project-Access-Token)(?:[^;&|\r\n]|\\\r?\n)*volumeInstanceBackupScheduleUpdate|volumeInstanceBackupScheduleUpdate(?:[^;&|\r\n]|\\\r?\n)*(?:backboard\.railway\.(?:app|com)|railway\.(?:app|com)\/graphql|RAILWAY_API_(?:URL|TOKEN)|RAILWAY_TOKEN|PROJECT_ACCESS_TOKEN|Project-Access-Token)/i,
    severity: "high",
    reason: "Railway Public API volume backup schedule update mutation detected.",
    explanation:
      "Changing Railway volume backup schedules can disable or weaken database recovery coverage.",
    suggestions: RAILWAY_VOLUME_SUGGESTIONS,
  },
  {
    name: "railway-api-volume-detach",
    re: /(?:backboard\.railway\.(?:app|com)|railway\.(?:app|com)\/graphql|RAILWAY_API_(?:URL|TOKEN)|RAILWAY_TOKEN|PROJECT_ACCESS_TOKEN|Project-Access-Token)(?:[^;&|\r\n]|\\\r?\n)*volumeInstanceUpdate(?:[^;&|\r\n]|\\\r?\n)*["']?serviceId["']?\s*:\s*null|volumeInstanceUpdate(?:[^;&|\r\n]|\\\r?\n)*["']?serviceId["']?\s*:\s*null(?:[^;&|\r\n]|\\\r?\n)*(?:backboard\.railway\.(?:app|com)|railway\.(?:app|com)\/graphql|RAILWAY_API_(?:URL|TOKEN)|RAILWAY_TOKEN|PROJECT_ACCESS_TOKEN|Project-Access-Token)/i,
    severity: "high",
    reason: "Railway Public API volume detach mutation detected.",
    explanation:
      "Railway GraphQL volumeInstanceUpdate with serviceId null detaches persistent storage from its service.",
    suggestions: RAILWAY_VOLUME_SUGGESTIONS,
  },
  {
    name: "railway-api-variable-delete",
    re: /(?:backboard\.railway\.(?:app|com)|railway\.(?:app|com)\/graphql|RAILWAY_API_(?:URL|TOKEN)|RAILWAY_TOKEN|PROJECT_ACCESS_TOKEN|Project-Access-Token)(?:[^;&|\r\n]|\\\r?\n)*variableDelete|variableDelete(?:[^;&|\r\n]|\\\r?\n)*(?:backboard\.railway\.(?:app|com)|railway\.(?:app|com)\/graphql|RAILWAY_API_(?:URL|TOKEN)|RAILWAY_TOKEN|PROJECT_ACCESS_TOKEN|Project-Access-Token)/i,
    severity: "high",
    reason: "Railway Public API variable deletion mutation detected.",
    explanation:
      "Railway GraphQL variable deletion mutations can remove credentials or database connection variables from production environments.",
    suggestions: RAILWAY_VARIABLE_SUGGESTIONS,
  },
  {
    name: "railway-api-variable-collection-replace",
    re: /(?:(?:backboard\.railway\.(?:app|com)|railway\.(?:app|com)\/graphql|RAILWAY_API_(?:URL|TOKEN)|RAILWAY_TOKEN|PROJECT_ACCESS_TOKEN|Project-Access-Token)(?:[^;&|\r\n]|\\\r?\n)*variableCollectionUpsert(?:[^;&|\r\n]|\\\r?\n)*["']?replace["']?[ \t]*:[ \t]*true|(?:backboard\.railway\.(?:app|com)|railway\.(?:app|com)\/graphql|RAILWAY_API_(?:URL|TOKEN)|RAILWAY_TOKEN|PROJECT_ACCESS_TOKEN|Project-Access-Token)(?:[^;&|\r\n]|\\\r?\n)*["']?replace["']?[ \t]*:[ \t]*true(?:[^;&|\r\n]|\\\r?\n)*variableCollectionUpsert|variableCollectionUpsert(?:[^;&|\r\n]|\\\r?\n)*(?:backboard\.railway\.(?:app|com)|railway\.(?:app|com)\/graphql|RAILWAY_API_(?:URL|TOKEN)|RAILWAY_TOKEN|PROJECT_ACCESS_TOKEN|Project-Access-Token)(?:[^;&|\r\n]|\\\r?\n)*["']?replace["']?[ \t]*:[ \t]*true|variableCollectionUpsert(?:[^;&|\r\n]|\\\r?\n)*["']?replace["']?[ \t]*:[ \t]*true(?:[^;&|\r\n]|\\\r?\n)*(?:backboard\.railway\.(?:app|com)|railway\.(?:app|com)\/graphql|RAILWAY_API_(?:URL|TOKEN)|RAILWAY_TOKEN|PROJECT_ACCESS_TOKEN|Project-Access-Token)|["']?replace["']?[ \t]*:[ \t]*true(?:[^;&|\r\n]|\\\r?\n)*(?:backboard\.railway\.(?:app|com)|railway\.(?:app|com)\/graphql|RAILWAY_API_(?:URL|TOKEN)|RAILWAY_TOKEN|PROJECT_ACCESS_TOKEN|Project-Access-Token)(?:[^;&|\r\n]|\\\r?\n)*variableCollectionUpsert|["']?replace["']?[ \t]*:[ \t]*true(?:[^;&|\r\n]|\\\r?\n)*variableCollectionUpsert(?:[^;&|\r\n]|\\\r?\n)*(?:backboard\.railway\.(?:app|com)|railway\.(?:app|com)\/graphql|RAILWAY_API_(?:URL|TOKEN)|RAILWAY_TOKEN|PROJECT_ACCESS_TOKEN|Project-Access-Token))/i,
    severity: "high",
    reason: "Railway Public API variableCollectionUpsert with replace=true detected.",
    explanation:
      "Railway variableCollectionUpsert with replace=true deletes variables omitted from the payload, which can remove production database credentials even when their names are not present.",
    suggestions: RAILWAY_VARIABLE_SUGGESTIONS,
  },
  {
    name: "railway-api-database-variable-upsert",
    re: new RegExp(
      `(?:backboard\\.railway\\.(?:app|com)|railway\\.(?:app|com)\\/graphql|RAILWAY_API_(?:URL|TOKEN)|RAILWAY_TOKEN|PROJECT_ACCESS_TOKEN|Project-Access-Token)(?:[^;&|\\r\\n]|\\\\\\r?\\n)*(?:variableCollectionUpsert|variableUpsert)(?:[^;&|\\r\\n]|\\\\\\r?\\n)*(?:${RAILWAY_DB_VARS})|(?:variableCollectionUpsert|variableUpsert)(?:[^;&|\\r\\n]|\\\\\\r?\\n)*(?:${RAILWAY_DB_VARS})(?:[^;&|\\r\\n]|\\\\\\r?\\n)*(?:backboard\\.railway\\.(?:app|com)|railway\\.(?:app|com)\\/graphql|RAILWAY_API_(?:URL|TOKEN)|RAILWAY_TOKEN|PROJECT_ACCESS_TOKEN|Project-Access-Token)`,
      "i",
    ),
    severity: "high",
    reason: "Railway Public API upsert is changing a database connection variable.",
    explanation:
      "Bulk-upserting Railway variables that include database connection keys can redirect or sever production database access.",
    suggestions: RAILWAY_VARIABLE_SUGGESTIONS,
  },
  {
    name: "railway-api-deployment-remove",
    re: /(?:backboard\.railway\.(?:app|com)|railway\.(?:app|com)\/graphql|RAILWAY_API_(?:URL|TOKEN)|RAILWAY_TOKEN|PROJECT_ACCESS_TOKEN|Project-Access-Token)(?:[^;&|\r\n]|\\\r?\n)*(?:deploymentRemove|deploymentStop)|(?:deploymentRemove|deploymentStop)(?:[^;&|\r\n]|\\\r?\n)*(?:backboard\.railway\.(?:app|com)|railway\.(?:app|com)\/graphql|RAILWAY_API_(?:URL|TOKEN)|RAILWAY_TOKEN|PROJECT_ACCESS_TOKEN|Project-Access-Token)/i,
    severity: "high",
    reason: "Railway Public API deployment removal or stop mutation detected.",
    explanation:
      "Railway GraphQL deployment removal and stop mutations can interrupt production availability.",
    suggestions: RAILWAY_DEPLOYMENT_SUGGESTIONS,
  },
];

// ============================================================================
// Kamal — DCG src/packs/platform/kamal.rs
// ============================================================================

const KAMAL_STATUS_SUGGESTIONS: Suggestion[] = [
  s("kamal details", "Show the current containers across servers before tearing anything down"),
  s("kamal config", "Confirm which destination/servers the command targets (mind that config prints secrets)"),
];
const KAMAL_ACCESSORY_SUGGESTIONS: Suggestion[] = [
  s("kamal accessory details", "Inspect the accessory (e.g. the database) without removing or stopping it"),
  s("kamal accessory logs", "Read accessory logs instead of restarting or removing the container"),
];
const KAMAL_PROXY_SUGGESTIONS: Suggestion[] = [
  s("kamal proxy details", "Inspect the proxy without removing or rebooting it"),
  s("kamal proxy reboot --rolling", "If a proxy cycle is truly required, --rolling staggers it to reduce the outage"),
];
const KAMAL_APP_SUGGESTIONS: Suggestion[] = [
  s("kamal app details", "Inspect app containers without removing or stopping them"),
  s("kamal app maintenance", "Serve a 503 maintenance page (reversible with `kamal app live`) instead of stopping"),
];
const KAMAL_PRUNE_SUGGESTIONS: Suggestion[] = [
  s("kamal app containers", "List the deployed containers/images that rollback relies on before pruning"),
  s("kamal rollback [VERSION]", "Pruning removes older images `kamal rollback` needs; confirm a rollback target still exists"),
];

const kamalSafe: SafeRule[] = [
  { name: "kamal-audit", re: /kamal(?:\s+--?\S+(?:\s+\S+)?)*\s+audit(?:\s|$)/ },
  { name: "kamal-details", re: /kamal(?:\s+--?\S+(?:\s+\S+)?)*\s+details(?:\s|$)/ },
  { name: "kamal-config", re: /kamal(?:\s+--?\S+(?:\s+\S+)?)*\s+config(?:\s|$)/ },
  { name: "kamal-secrets", re: /kamal(?:\s+--?\S+(?:\s+\S+)?)*\s+secrets(?:\s|$)/ },
  { name: "kamal-deploy", re: /kamal(?:\s+--?\S+(?:\s+\S+)?)*\s+deploy(?:\s|$)/ },
  { name: "kamal-redeploy", re: /kamal(?:\s+--?\S+(?:\s+\S+)?)*\s+redeploy(?:\s|$)/ },
  { name: "kamal-setup", re: /kamal(?:\s+--?\S+(?:\s+\S+)?)*\s+setup(?:\s|$)/ },
  { name: "kamal-build", re: /kamal(?:\s+--?\S+(?:\s+\S+)?)*\s+build(?:\s|$)/ },
  { name: "kamal-rollback", re: /kamal(?:\s+--?\S+(?:\s+\S+)?)*\s+rollback(?:\s|$)/ },
  { name: "kamal-upgrade", re: /kamal(?:\s+--?\S+(?:\s+\S+)?)*\s+upgrade(?:\s|$)/ },
  { name: "kamal-registry", re: /kamal(?:\s+--?\S+(?:\s+\S+)?)*\s+registry\s+(?:login|logout)(?:\s|$)/ },
  { name: "kamal-lock", re: /kamal(?:\s+--?\S+(?:\s+\S+)?)*\s+lock(?:\s|$)/ },
  { name: "kamal-server-bootstrap", re: /kamal(?:\s+--?\S+(?:\s+\S+)?)*\s+server\s+bootstrap(?:\s|$)/ },
  { name: "kamal-init", re: /kamal(?:\s+--?\S+(?:\s+\S+)?)*\s+init(?:\s|$)/ },
  { name: "kamal-docs", re: /kamal(?:\s+--?\S+(?:\s+\S+)?)*\s+docs(?:\s|$)/ },
  { name: "kamal-help", re: /kamal(?:\s+--?\S+(?:\s+\S+)?)*\s+help(?:\s|$)/ },
  { name: "kamal-version", re: /kamal(?:\s+--?\S+(?:\s+\S+)?)*\s+version(?:\s|$)/ },
  { name: "kamal-app-safe", re: /kamal(?:\s+--?\S+(?:\s+\S+)?)*\s+app(?:\s+--?\S+(?:\s+\S+)?)*\s+(?:boot|start|restart|details|containers|images|logs|version|stale_containers|maintenance|live)(?:\s|$)/ },
  { name: "kamal-accessory-safe", re: /kamal(?:\s+--?\S+(?:\s+\S+)?)*\s+accessory(?:\s+--?\S+(?:\s+\S+)?)*\s+(?:boot|start|restart|details|logs|upgrade)(?:\s|$)/ },
  { name: "kamal-proxy-safe", re: /kamal(?:\s+--?\S+(?:\s+\S+)?)*\s+proxy(?:\s+--?\S+(?:\s+\S+)?)*\s+(?:boot|boot_config|start|restart|details|logs)(?:\s|$)/ },
];

const kamalDestructive: DestructiveRule[] = [
  {
    name: "kamal-remove",
    re: /kamal(?:\s+--?\S+(?:\s+\S+)?)*\s+remove(?:\s|$)/,
    severity: "critical",
    reason: "kamal remove tears down the entire deployment, including stateful accessories.",
    explanation:
      "`kamal remove` removes the app container, kamal-proxy, and all accessory containers " +
      "from the servers and logs out of the registry. Because it removes accessories, it can " +
      "destroy stateful services (Postgres/Redis/search) along with the rest of the stack. " +
      "It accepts `-y`/`--yes` to skip the confirmation prompt, so a non-interactive agent " +
      "run has no safety net. A wrong destination (e.g. a missing `-d staging` while the " +
      "shell points at production) tears down prod.\n\n" +
      "Safer alternatives:\n" +
      "- kamal details: review what is actually deployed first\n" +
      "- kamal app remove / kamal proxy remove: scope the teardown if that is the real intent\n" +
      "- Always pass the explicit destination (e.g. -d staging) and confirm it",
    suggestions: KAMAL_STATUS_SUGGESTIONS,
  },
  {
    name: "kamal-accessory-remove",
    re: /kamal(?:\s+--?\S+(?:\s+\S+)?)*\s+accessory(?:\s+--?\S+(?:\s+\S+)?)*\s+remove(?:\s|$)/,
    severity: "critical",
    reason: "kamal accessory remove deletes the accessory container, image, AND its host data directory.",
    explanation:
      "`kamal accessory remove [NAME]` removes the accessory container and image and ALSO " +
      "deletes its data directory from the host. For a database/redis/search accessory this " +
      "permanently destroys the data. `kamal accessory remove all` does this across every " +
      "accessory at once (highest blast radius). The common mistake is meaning the YAML block " +
      "in deploy.yml, not the live Postgres/Redis data on disk.\n\n" +
      "Safer alternatives:\n" +
      "- Edit the accessory block out of deploy.yml instead of deleting live data\n" +
      "- kamal accessory stop: take it offline reversibly (data preserved)\n" +
      "- Back up the data directory / take a database dump before any removal",
    suggestions: KAMAL_ACCESSORY_SUGGESTIONS,
  },
  {
    name: "kamal-app-remove",
    re: /kamal(?:\s+--?\S+(?:\s+\S+)?)*\s+app(?:\s+--?\S+(?:\s+\S+)?)*\s+remove(?:\s|$)/,
    severity: "high",
    reason: "kamal app remove takes the app offline by removing its containers and images.",
    explanation:
      "`kamal app remove` removes the app containers and images from the servers. The app goes " +
      "offline and the images must be rebuilt or re-pulled before it can serve again. This is " +
      "a frequent footgun when asked to \"clean up old containers\".\n\n" +
      "Safer alternatives:\n" +
      "- kamal app stale_containers: list leftover containers without removing the live app\n" +
      "- kamal prune: remove genuinely old images/containers (still erodes rollback)\n" +
      "- kamal app maintenance: serve a 503 reversibly instead of removing",
    suggestions: KAMAL_APP_SUGGESTIONS,
  },
  {
    name: "kamal-app-stop",
    re: /kamal(?:\s+--?\S+(?:\s+\S+)?)*\s+app(?:\s+--?\S+(?:\s+\S+)?)*\s+stop(?:\s|$)/,
    severity: "high",
    reason: "kamal app stop stops the app container, causing an outage until restarted.",
    explanation:
      "`kamal app stop` stops the app container on the servers, causing an outage until " +
      "`kamal app start`. There is no built-in confirmation prompt.\n\n" +
      "Safer alternatives:\n" +
      "- kamal app maintenance: serve a 503 maintenance page (reversible with kamal app live)\n" +
      "- kamal app details: confirm the target before stopping anything",
    suggestions: KAMAL_APP_SUGGESTIONS,
  },
  {
    name: "kamal-proxy-remove",
    re: /kamal(?:\s+--?\S+(?:\s+\S+)?)*\s+proxy(?:\s+--?\S+(?:\s+\S+)?)*\s+remove(?:\s|$)/,
    severity: "high",
    reason: "kamal proxy remove drops routing for every app behind that proxy on the host.",
    explanation:
      "`kamal proxy remove` removes the kamal-proxy container and image. Every app behind that " +
      "proxy on the host loses routing until the proxy is re-booted. There is no confirmation " +
      "prompt for `remove`.\n\n" +
      "Safer alternatives:\n" +
      "- kamal proxy details / kamal proxy logs: diagnose the proxy without removing it\n" +
      "- kamal proxy reboot --rolling: if a cycle is required, stagger it to limit the outage",
    suggestions: KAMAL_PROXY_SUGGESTIONS,
  },
  {
    name: "kamal-proxy-reboot",
    re: /kamal(?:\s+--?\S+(?:\s+\S+)?)*\s+proxy(?:\s+--?\S+(?:\s+\S+)?)*\s+reboot(?:\s|$)/,
    severity: "high",
    reason: "kamal proxy reboot stops, removes, and recreates the proxy, causing a short outage.",
    explanation:
      "`kamal proxy reboot` stops, removes, and starts a new proxy container. It is documented " +
      "to cause a small outage on each server. While it prompts interactively, a non-interactive " +
      "agent run with `-y` skips that prompt.\n\n" +
      "Safer alternatives:\n" +
      "- kamal proxy reboot --rolling: stagger the restart across servers to reduce the outage\n" +
      "- kamal proxy restart: a lighter restart of the existing proxy where applicable",
    suggestions: KAMAL_PROXY_SUGGESTIONS,
  },
  {
    name: "kamal-proxy-stop",
    re: /kamal(?:\s+--?\S+(?:\s+\S+)?)*\s+proxy(?:\s+--?\S+(?:\s+\S+)?)*\s+stop(?:\s|$)/,
    severity: "high",
    reason: "kamal proxy stop drops routing for every app behind that proxy until it is started.",
    explanation:
      "`kamal proxy stop` stops the kamal-proxy container. Every app behind that proxy on the " +
      "host loses routing until `kamal proxy start`/`boot`.\n\n" +
      "Safer alternatives:\n" +
      "- kamal proxy details: confirm what the proxy is serving before stopping it\n" +
      "- kamal proxy restart: cycle the proxy without leaving it down",
    suggestions: KAMAL_PROXY_SUGGESTIONS,
  },
  {
    name: "kamal-accessory-reboot",
    re: /kamal(?:\s+--?\S+(?:\s+\S+)?)*\s+accessory(?:\s+--?\S+(?:\s+\S+)?)*\s+reboot(?:\s|$)/,
    severity: "high",
    reason: "kamal accessory reboot stops, removes, and recreates the accessory container (downtime).",
    explanation:
      "`kamal accessory reboot [NAME]` stops, removes, and starts a new accessory container, " +
      "causing downtime for that accessory (e.g. the database). Data survives only if a volume " +
      "is mapped; an unmapped data directory is at risk. `NAME=all` reboots every accessory.\n\n" +
      "Safer alternatives:\n" +
      "- kamal accessory restart: restart the existing container without remove/recreate\n" +
      "- kamal accessory details: confirm the target accessory before cycling it",
    suggestions: KAMAL_ACCESSORY_SUGGESTIONS,
  },
  {
    name: "kamal-accessory-stop",
    re: /kamal(?:\s+--?\S+(?:\s+\S+)?)*\s+accessory(?:\s+--?\S+(?:\s+\S+)?)*\s+stop(?:\s|$)/,
    severity: "high",
    reason: "kamal accessory stop stops the accessory (e.g. the database), erroring the app.",
    explanation:
      "`kamal accessory stop [NAME]` stops the accessory container. Stopping the database (or " +
      "cache/search) errors the app until the accessory is restarted, knocking a dependency " +
      "offline mid-traffic.\n\n" +
      "Safer alternatives:\n" +
      "- kamal accessory restart: cycle it without leaving it stopped\n" +
      "- kamal accessory details / kamal accessory logs: diagnose without stopping",
    suggestions: KAMAL_ACCESSORY_SUGGESTIONS,
  },
  {
    name: "kamal-prune",
    re: /kamal(?:\s+--?\S+(?:\s+\S+)?)*\s+prune(?:\s+--?\S+(?:\s+\S+)?)*\s+(?:all|containers|images)(?:\s|$)/,
    severity: "medium",
    reason: "kamal prune removes older images/containers that kamal rollback relies on.",
    explanation:
      "`kamal prune all` prunes unused images and stopped containers, `kamal prune containers` " +
      "prunes stopped containers except the last n (default 5), and `kamal prune images` prunes " +
      "unused images. Kamal's `rollback` relies on the older deployed images/containers, so " +
      "over-pruning can strand a deployment with no rollback target.\n\n" +
      "Safer alternatives:\n" +
      "- kamal app containers / kamal app images: see what would be removed first\n" +
      "- Confirm a known-good rollback target exists before pruning",
    suggestions: KAMAL_PRUNE_SUGGESTIONS,
  },
];

// ============================================================================
// Modal — DCG src/packs/platform/modal.rs
// ============================================================================

const MODAL_APP_SUGGESTIONS: Suggestion[] = [
  s("modal app list", "List Modal apps to confirm the target before stopping it"),
  s("modal app logs <app>", "Inspect app state without terminating its containers"),
  s("modal app rollback <app> <version>", "Roll back to a previous deploy instead of stopping the app"),
];
const MODAL_CONTAINER_SUGGESTIONS: Suggestion[] = [
  s("modal container list", "List running Modal containers before terminating one"),
  s("modal container logs <container_id>", "Inspect a container without stopping it"),
];
const MODAL_ENVIRONMENT_SUGGESTIONS: Suggestion[] = [
  s("modal environment list", "List Modal environments to verify you are not deleting prod"),
  s("modal environment update", "Update an environment in place instead of deleting it"),
];
const MODAL_VOLUME_SUGGESTIONS: Suggestion[] = [
  s("modal volume list", "List Modal Volumes to verify the target before deletion"),
  s("modal volume ls <volume> <path>", "Inspect Volume contents before deleting files"),
  s("modal volume cp <volume> <src> <dest>", "Copy data out of the Volume as a backup before destructive ops"),
];
const MODAL_SECRET_SUGGESTIONS: Suggestion[] = [
  s("modal secret list", "List Modal Secrets before deleting or overwriting one"),
  s("modal secret create <new-name> ...", "Create a new secret with a versioned name instead of force-overwriting"),
];
const MODAL_DICT_SUGGESTIONS: Suggestion[] = [
  s("modal dict list", "List Modal Dicts before deleting or clearing one"),
  s("modal dict items <name>", "Inspect Dict contents before destructive ops"),
];
const MODAL_QUEUE_SUGGESTIONS: Suggestion[] = [
  s("modal queue list", "List Modal Queues before deleting or clearing one"),
  s("modal queue peek <name>", "Inspect Queue contents before destructive ops"),
  s("modal queue len <name>", "Check Queue length before clearing it"),
];

const modalSafe: SafeRule[] = [
  { name: "modal-volume-list", re: /\bmodal(?:\s+--?\S+(?:\s+\S+)?)*\s+volume\s+(?:list|ls)\b/ },
  { name: "modal-volume-get", re: /\bmodal(?:\s+--?\S+(?:\s+\S+)?)*\s+volume\s+(?:get|cp|cat)\b/ },
  { name: "modal-volume-create", re: /\bmodal(?:\s+--?\S+(?:\s+\S+)?)*\s+volume\s+(?:create|rename)\b/ },
  { name: "modal-app-readonly", re: /\bmodal(?:\s+--?\S+(?:\s+\S+)?)*\s+app\s+(?:list|ls|logs|history|dashboard|rollback|rollover)\b/ },
  { name: "modal-container-readonly", re: /\bmodal(?:\s+--?\S+(?:\s+\S+)?)*\s+container\s+(?:list|ls|logs|exec)\b/ },
  { name: "modal-secret-list", re: /\bmodal(?:\s+--?\S+(?:\s+\S+)?)*\s+secret\s+(?:list|ls)\b/ },
  { name: "modal-secret-create-no-force", re: /\bmodal(?:\s+--?\S+(?:\s+\S+)?)*\s+secret\s+create\b(?!(?:[^;&|\r\n]|\\\r?\n)*(?:--force|--overwrite)\b)/ },
  { name: "modal-environment-list", re: /\bmodal(?:\s+--?\S+(?:\s+\S+)?)*\s+environment\s+(?:list|ls)\b/ },
  { name: "modal-environment-mutate", re: /\bmodal(?:\s+--?\S+(?:\s+\S+)?)*\s+environment\s+(?:create|update)\b/ },
  { name: "modal-dict-readonly", re: /\bmodal(?:\s+--?\S+(?:\s+\S+)?)*\s+dict\s+(?:list|ls|get|items|create)\b/ },
  { name: "modal-queue-readonly", re: /\bmodal(?:\s+--?\S+(?:\s+\S+)?)*\s+queue\s+(?:list|ls|peek|len|create)\b/ },
  { name: "modal-shell", re: /\bmodal(?:\s+--?\S+(?:\s+\S+)?)*\s+shell\b/ },
  { name: "modal-deploy", re: /\bmodal(?:\s+--?\S+(?:\s+\S+)?)*\s+(?:deploy|serve|run|profile|launch)\b/ },
  { name: "modal-token", re: /\bmodal(?:\s+--?\S+(?:\s+\S+)?)*\s+token\s+(?:info|new|set)\b/ },
];

const modalDestructive: DestructiveRule[] = [
  {
    name: "modal-environment-delete",
    re: /\bmodal(?:\s+--?\S+(?:\s+\S+)?)*\s+environment\s+(?:delete|remove|rm)\b/,
    severity: "critical",
    reason: "modal environment delete schedules removal of an entire Modal environment.",
    explanation:
      "Deleting a Modal environment removes the environment and every Modal app inside it — irrecoverable. Agents passing --yes bypass Modal's confirmation prompt entirely.",
    suggestions: MODAL_ENVIRONMENT_SUGGESTIONS,
  },
  {
    name: "modal-volume-delete",
    re: /\bmodal(?:\s+--?\S+(?:\s+\S+)?)*\s+volume\s+(?:delete|remove)\b/,
    severity: "critical",
    reason: "modal volume delete removes a Modal Volume and all data inside it.",
    explanation:
      "Deleting a Modal Volume destroys persistent ML artifacts: model weights, datasets, checkpoints. There is no undo. Agents passing --yes bypass Modal's confirmation prompt entirely.",
    suggestions: MODAL_VOLUME_SUGGESTIONS,
  },
  {
    name: "modal-secret-delete",
    re: /\bmodal(?:\s+--?\S+(?:\s+\S+)?)*\s+secret\s+(?:delete|remove|rm)\b/,
    severity: "critical",
    reason: "modal secret delete permanently removes a published Modal Secret.",
    explanation:
      "Deleting a Modal Secret can immediately break every running app that references it (API keys, DB credentials, OAuth tokens). Agents passing --yes bypass Modal's confirmation prompt entirely.",
    suggestions: MODAL_SECRET_SUGGESTIONS,
  },
  {
    name: "modal-dict-delete",
    re: /\bmodal(?:\s+--?\S+(?:\s+\S+)?)*\s+dict\s+(?:delete|remove|rm)\b/,
    severity: "critical",
    reason: "modal dict delete removes a named Modal Dict and all its data.",
    explanation:
      "Deleting a Modal Dict can destroy authoritative state that an app treats as a transient cache when it actually is not. Agents passing --yes bypass Modal's confirmation prompt entirely.",
    suggestions: MODAL_DICT_SUGGESTIONS,
  },
  {
    name: "modal-queue-delete",
    re: /\bmodal(?:\s+--?\S+(?:\s+\S+)?)*\s+queue\s+(?:delete|remove|rm)\b/,
    severity: "critical",
    reason: "modal queue delete removes a named Modal Queue and all its data.",
    explanation:
      "Deleting a Modal Queue discards every message currently in flight or buffered. Agents passing --yes bypass Modal's confirmation prompt entirely.",
    suggestions: MODAL_QUEUE_SUGGESTIONS,
  },
  {
    name: "modal-app-stop",
    re: /\bmodal(?:\s+--?\S+(?:\s+\S+)?)*\s+app\s+stop\b/,
    severity: "high",
    reason: "modal app stop terminates a Modal app and its running containers.",
    explanation:
      "Stopping a Modal app permanently stops it and terminates running containers; in-progress inputs are lost or reassigned. Use `modal app rollback` to roll back without stopping.",
    suggestions: MODAL_APP_SUGGESTIONS,
  },
  {
    name: "modal-container-stop",
    re: /\bmodal(?:\s+--?\S+(?:\s+\S+)?)*\s+container\s+stop\b/,
    severity: "high",
    reason: "modal container stop terminates a running Modal container and reassigns inputs.",
    explanation:
      "Stopping a Modal container interrupts in-flight work. The platform may reassign inputs, but exactly-once semantics are not guaranteed.",
    suggestions: MODAL_CONTAINER_SUGGESTIONS,
  },
  {
    name: "modal-volume-rm-recursive",
    re: /\bmodal(?:\s+--?\S+(?:\s+\S+)?)*\s+volume\s+rm\b(?:[^;&|\r\n]|\\\r?\n)*(?:\s|=)(?:-r\b|-R\b|--recursive\b)/,
    severity: "high",
    reason: "modal volume rm -r recursively deletes files inside a Modal Volume.",
    explanation:
      "Recursive `modal volume rm` can wipe entire subdirectories of persistent storage (datasets, checkpoints). Catastrophic when the target is wrong.",
    suggestions: MODAL_VOLUME_SUGGESTIONS,
  },
  {
    name: "modal-dict-clear",
    re: /\bmodal(?:\s+--?\S+(?:\s+\S+)?)*\s+dict\s+clear\b/,
    severity: "high",
    reason: "modal dict clear empties a Modal Dict.",
    explanation:
      "Clearing a Modal Dict deletes every entry but leaves the Dict object. If the Dict holds authoritative state, this is data loss.",
    suggestions: MODAL_DICT_SUGGESTIONS,
  },
  {
    name: "modal-queue-clear",
    re: /\bmodal(?:\s+--?\S+(?:\s+\S+)?)*\s+queue\s+clear\b/,
    severity: "high",
    reason: "modal queue clear drains every message from a Modal Queue.",
    explanation:
      "Clearing a Modal Queue drops every buffered message. If consumers have not yet processed them, the work is lost.",
    suggestions: MODAL_QUEUE_SUGGESTIONS,
  },
  {
    name: "modal-volume-rm",
    re: /\bmodal(?:\s+--?\S+(?:\s+\S+)?)*\s+volume\s+rm\b(?!(?:[^;&|\r\n]|\\\r?\n)*(?:\s|=)(?:-r\b|-R\b|--recursive\b))/,
    severity: "medium",
    reason: "modal volume rm deletes a file inside a Modal Volume.",
    explanation:
      "Single-file deletion inside a Volume is recoverable only if you have an external copy. Verify the target path before running.",
    suggestions: MODAL_VOLUME_SUGGESTIONS,
  },
  {
    name: "modal-secret-create-force",
    re: /\bmodal(?:\s+--?\S+(?:\s+\S+)?)*\s+secret\s+create\b(?:[^;&|\r\n]|\\\r?\n)*(?:--force|--overwrite)\b/,
    severity: "medium",
    reason: "modal secret create --force overwrites an existing Modal Secret in place.",
    explanation:
      "Overwriting a Secret with --force changes the value used by every app that references it on next cold start — common cause of unintended prod credential rotation.",
    suggestions: MODAL_SECRET_SUGGESTIONS,
  },
];

// ============================================================================
// GitLab — DCG src/packs/platform/gitlab.rs
// All glab-*/gitlab-* destructive rules use the 3-arg macro form => severity High.
// ============================================================================

const gitlabSafe: SafeRule[] = [
  { name: "glab-repo-list", re: /glab(?:\s+--?\S+(?:\s+\S+)?)*\s+repo\s+list\b/ },
  { name: "glab-repo-view", re: /glab(?:\s+--?\S+(?:\s+\S+)?)*\s+repo\s+view\b/ },
  { name: "glab-repo-clone", re: /glab(?:\s+--?\S+(?:\s+\S+)?)*\s+repo\s+clone\b/ },
  { name: "glab-mr-list", re: /glab(?:\s+--?\S+(?:\s+\S+)?)*\s+mr\s+list\b/ },
  { name: "glab-mr-view", re: /glab(?:\s+--?\S+(?:\s+\S+)?)*\s+mr\s+view\b/ },
  { name: "glab-issue-list", re: /glab(?:\s+--?\S+(?:\s+\S+)?)*\s+issue\s+list\b/ },
  { name: "glab-issue-view", re: /glab(?:\s+--?\S+(?:\s+\S+)?)*\s+issue\s+view\b/ },
  { name: "glab-variable-list", re: /glab(?:\s+--?\S+(?:\s+\S+)?)*\s+variable\s+list\b/ },
  { name: "glab-release-list", re: /glab(?:\s+--?\S+(?:\s+\S+)?)*\s+release\s+list\b/ },
  { name: "glab-release-view", re: /glab(?:\s+--?\S+(?:\s+\S+)?)*\s+release\s+view\b/ },
  { name: "glab-api-explicit-get", re: /glab(?:\s+--?\S+(?:\s+\S+)?)*\s+api\b.*(?:-X\s*|--method(?:=|\s+))GET\b/ },
];

const gitlabDestructive: DestructiveRule[] = [
  { name: "glab-repo-delete", re: /glab(?:\s+--?\S+(?:\s+\S+)?)*\s+repo\s+delete\b/, severity: "high", reason: "glab repo delete permanently deletes a GitLab project." },
  { name: "glab-repo-archive", re: /glab(?:\s+--?\S+(?:\s+\S+)?)*\s+repo\s+archive\b/, severity: "high", reason: "glab repo archive makes a GitLab project read-only." },
  { name: "glab-release-delete", re: /glab(?:\s+--?\S+(?:\s+\S+)?)*\s+release\s+delete\b/, severity: "high", reason: "glab release delete removes GitLab releases." },
  { name: "glab-variable-delete", re: /glab(?:\s+--?\S+(?:\s+\S+)?)*\s+variable\s+(?:delete|remove)\b/, severity: "high", reason: "glab variable delete removes GitLab CI/CD variables." },
  { name: "glab-api-delete-project", re: /glab(?:\s+--?\S+(?:\s+\S+)?)*\s+api\b.*(?:-X\s*|--method(?:=|\s+))DELETE\b.*(?:\/)?projects\/[^/\s]+(?:\s|$)/, severity: "high", reason: "glab api DELETE /projects/* deletes a GitLab project." },
  { name: "glab-api-delete-release", re: /glab(?:\s+--?\S+(?:\s+\S+)?)*\s+api\b.*(?:-X\s*|--method(?:=|\s+))DELETE\b.*(?:\/)?projects\/[^/\s]+\/releases\//, severity: "high", reason: "glab api DELETE releases removes GitLab releases." },
  { name: "glab-api-delete-variable", re: /glab(?:\s+--?\S+(?:\s+\S+)?)*\s+api\b.*(?:-X\s*|--method(?:=|\s+))DELETE\b.*(?:\/)?projects\/[^/\s]+\/variables\//, severity: "high", reason: "glab api DELETE variables removes CI/CD variables." },
  { name: "glab-api-delete-protected-branch", re: /glab(?:\s+--?\S+(?:\s+\S+)?)*\s+api\b.*(?:-X\s*|--method(?:=|\s+))DELETE\b.*(?:\/)?protected_branches\//, severity: "high", reason: "glab api DELETE protected_branches removes branch protections." },
  { name: "glab-api-delete-hook", re: /glab(?:\s+--?\S+(?:\s+\S+)?)*\s+api\b.*(?:-X\s*|--method(?:=|\s+))DELETE\b.*(?:\/)?hooks\//, severity: "high", reason: "glab api DELETE hooks removes GitLab webhooks." },
  { name: "gitlab-rails-runner-destructive", re: /gitlab-rails\s+runner\b.*\b(?:destroy_all|delete_all|\.destroy\b|\.delete\b|truncate|drop)\b/, severity: "high", reason: "gitlab-rails runner destructive operations can remove data." },
  { name: "gitlab-rake-destructive", re: /gitlab-rake\b.*\b(?:gitlab:)?backup:restore\b|gitlab-rake\b.*\b(?:gitlab:)?db:(?:drop|reset)\b/, severity: "high", reason: "gitlab-rake destructive maintenance tasks can delete or replace data." },
];

/**
 * Platform pack — gh + railway + kamal + modal + gitlab merged.
 *
 * Sources: DCG `src/packs/platform/{github,railway,kamal,modal,gitlab}.rs`.
 * Keywords are the UNION of the five DCG keyword sets (dedup preserving order).
 * NOTE: platform.github keys on `gh` and cicd.github_actions also keys on `gh`;
 * both port their own gh secret/variable-delete rules faithfully (the engine
 * dedups overlapping reports downstream).
 */
export const platformPack: Pack = {
  id: "platform",
  name: "Platform",
  description:
    "Protects against destructive hosting-platform operations across GitHub (gh), " +
    "Railway, Kamal, Modal, and GitLab",
  keywords: [
    // github
    "gh",
    // railway (CLI + GraphQL API + token/mutation keywords)
    "railway",
    "backboard.railway.app",
    "backboard.railway.com",
    "railway.app/graphql",
    "railway.com/graphql",
    "Project-Access-Token",
    "PROJECT_ACCESS_TOKEN",
    "projectDelete",
    "projectScheduleDelete",
    "environmentDelete",
    "serviceDelete",
    "volumeDelete",
    "volumeInstanceDelete",
    "volumeInstanceBackupDelete",
    "volumeInstanceBackupRestore",
    "volumeInstanceBackupScheduleUpdate",
    "volumeInstanceUpdate",
    "variableDelete",
    "variableUpsert",
    "variableCollectionUpsert",
    "deploymentRemove",
    "deploymentStop",
    // kamal
    "kamal",
    // modal
    "modal",
    // gitlab
    "glab",
    "gitlab-rails",
    "gitlab-rake",
  ],
  safePatterns: [...githubSafe, ...railwaySafe, ...kamalSafe, ...modalSafe, ...gitlabSafe],
  destructivePatterns: [
    ...githubDestructive,
    ...railwayDestructive,
    ...kamalDestructive,
    ...modalDestructive,
    ...gitlabDestructive,
  ],
};
