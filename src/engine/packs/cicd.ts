// CI/CD pack — pipeline tooling (GitHub Actions gh, GitLab CI, Jenkins, CircleCI).
//
// Faithful port of DCG's four cicd sub-packs into ONE Pack:
//   - src/packs/cicd/github_actions.rs -> id "cicd.github_actions" (gh)
//   - src/packs/cicd/gitlab_ci.rs      -> id "cicd.gitlab_ci"      (glab / gitlab-runner)
//   - src/packs/cicd/jenkins.rs        -> id "cicd.jenkins"        (jenkins-cli / java -jar jenkins-cli.jar / curl doDelete)
//   - src/packs/cicd/circleci.rs       -> id "cicd.circleci"       (circleci / curl)
// (https://github.com/Dicklesworthstone/destructive_command_guard)
//
// MERGE NOTE: DCG ships these as four `create_pack()`s. The Pi module contract
// asks for ONE `cicdPack`, so the rule sets are concatenated. Rule NAMES are
// already tool-prefixed in DCG (`gh-actions-*`, `glab-*`/`gitlab-runner-*`,
// `jenkins-*`, `circleci-*`) so they stay unique. reason/explanation/severity
// and per-tool declaration order are preserved 1:1. The tools key on distinct
// executables / substrings, so cross-tool order is not load-bearing.
//
// OVERLAP NOTE (intentional, per the module contract): cicd.github_actions and
// platform.github BOTH key on `gh` and both define gh secret/variable-delete
// rules. Each is ported faithfully here vs in platform.ts; the engine dedups
// overlapping decisions at report time. Likewise cicd.gitlab_ci's
// `glab-variable-delete` mirrors platform.gitlab's — both faithful, both kept.
//
// JS RegExp porting notes (this category):
//  - SEVERITY: github_actions / gitlab_ci / jenkins / circleci all use the
//    5-arg `destructive_pattern!` form WITH explicit severity, so each rule's
//    severity is copied verbatim (no default-High guessing needed here).
//  - INLINE `(?i)`: jenkins' `jenkins-curl-explicit-get` (safe) and
//    `jenkins-curl-do-delete` (destructive) are authored with a leading `(?i)`.
//    JS has no inline flag, so those two RegExp carry the "i" flag instead
//    (DCG's `(?i)` is leading/whole-pattern, equivalent). Every other rule is
//    case-sensitive.
//  - Bounded walkers `(?:\s+--?[A-Za-z]...)*` / `(?:\s+--?\S+(?:\s+\S+)?)*`,
//    lookaheads `(?=...)`, negative lookaheads `(?!...)`, and `\b` anchors are
//    native JS and ported verbatim. No POSIX classes, no possessive quantifiers.

import type { DestructiveRule, Pack, SafeRule } from "../types.ts";

// ============================================================================
// GitHub Actions (gh) — DCG src/packs/cicd/github_actions.rs
// Walker: (?:\s+--?[A-Za-z][A-Za-z0-9-]*\b(?:\s+(?!(?:secret|variable|workflow|run|api)\b)\S+)?)*
// ============================================================================

const githubActionsSafe: SafeRule[] = [
  {
    name: "gh-actions-secret-list",
    re: /gh(?:\s+--?[A-Za-z][A-Za-z0-9-]*\b(?:\s+(?!(?:secret|variable|workflow|run|api)\b)\S+)?)*\s+secret\s+list\b/,
  },
  {
    name: "gh-actions-variable-list",
    re: /gh(?:\s+--?[A-Za-z][A-Za-z0-9-]*\b(?:\s+(?!(?:secret|variable|workflow|run|api)\b)\S+)?)*\s+variable\s+list\b/,
  },
  {
    name: "gh-actions-workflow-list",
    re: /gh(?:\s+--?[A-Za-z][A-Za-z0-9-]*\b(?:\s+(?!(?:secret|variable|workflow|run|api)\b)\S+)?)*\s+workflow\s+list\b/,
  },
  {
    name: "gh-actions-workflow-view",
    re: /gh(?:\s+--?[A-Za-z][A-Za-z0-9-]*\b(?:\s+(?!(?:secret|variable|workflow|run|api)\b)\S+)?)*\s+workflow\s+view\b/,
  },
  {
    name: "gh-actions-run-list",
    re: /gh(?:\s+--?[A-Za-z][A-Za-z0-9-]*\b(?:\s+(?!(?:secret|variable|workflow|run|api)\b)\S+)?)*\s+run\s+list\b/,
  },
  {
    name: "gh-actions-run-view",
    re: /gh(?:\s+--?[A-Za-z][A-Za-z0-9-]*\b(?:\s+(?!(?:secret|variable|workflow|run|api)\b)\S+)?)*\s+run\s+view\b/,
  },
  {
    name: "gh-actions-api-explicit-get",
    re: /^(?!(?=.*(?:-X\s*|--method(?:=|\s+))DELETE\b))gh(?:\s+--?[A-Za-z][A-Za-z0-9-]*\b(?:\s+(?!(?:secret|variable|workflow|run|api)\b)\S+)?)*\s+api\b.*(?:-X\s*|--method(?:=|\s+))GET\b/,
  },
];

const githubActionsDestructive: DestructiveRule[] = [
  {
    name: "gh-actions-secret-remove",
    re: /gh(?:\s+--?[A-Za-z][A-Za-z0-9-]*\b(?:\s+(?!(?:secret|variable|workflow|run|api)\b)\S+)?)*\s+secret\s+(?:delete|remove)\b/,
    severity: "high",
    reason:
      "gh secret delete/remove deletes GitHub Actions secrets. This can break CI and may be hard to recover.",
    explanation:
      "Deleting a GitHub Actions secret removes it from the repository, organization, " +
      "or environment. Workflows using this secret will fail with authentication or " +
      "configuration errors. Secret values are not recoverable after deletion.\n\n" +
      "Safer alternatives:\n" +
      "- gh secret list: Review existing secrets first\n" +
      "- Update the secret value instead of deleting\n" +
      "- Check workflow files for secret usage before removing",
  },
  {
    name: "gh-actions-variable-remove",
    re: /gh(?:\s+--?[A-Za-z][A-Za-z0-9-]*\b(?:\s+(?!(?:secret|variable|workflow|run|api)\b)\S+)?)*\s+variable\s+(?:delete|remove)\b/,
    severity: "medium",
    reason:
      "gh variable delete/remove deletes GitHub Actions variables. This can break workflows.",
    explanation:
      "Removing a GitHub Actions variable makes it unavailable to all workflows that " +
      "reference it. Unlike secrets, variable values are visible, but workflows may " +
      "fail with undefined variable errors after deletion.\n\n" +
      "Safer alternatives:\n" +
      "- gh variable list: Review existing variables first\n" +
      "- gh variable set: Update value instead of removing\n" +
      "- Search workflows for variable usage before removing",
  },
  {
    name: "gh-actions-workflow-disable",
    re: /gh(?:\s+--?[A-Za-z][A-Za-z0-9-]*\b(?:\s+(?!(?:secret|variable|workflow|run|api)\b)\S+)?)*\s+workflow\s+disable\b/,
    severity: "low",
    reason:
      "gh workflow disable disables workflows. This is reversible, but can disrupt CI.",
    explanation:
      "Disabling a workflow prevents it from running on any triggers. This is reversible " +
      "with 'gh workflow enable', but can disrupt CI/CD pipelines, scheduled jobs, and " +
      "automated deployments while disabled.\n\n" +
      "Safer alternatives:\n" +
      "- gh workflow list: Review workflow status first\n" +
      "- gh workflow view: Check workflow details\n" +
      "- Use workflow_dispatch for manual control instead",
  },
  {
    name: "gh-actions-run-cancel",
    re: /gh(?:\s+--?[A-Za-z][A-Za-z0-9-]*\b(?:\s+(?!(?:secret|variable|workflow|run|api)\b)\S+)?)*\s+run\s+cancel\b/,
    severity: "low",
    reason:
      "gh run cancel cancels a running workflow. This is reversible, but may disrupt deployments.",
    explanation:
      "Canceling a workflow run stops it mid-execution. Any in-progress deployments, " +
      "tests, or builds will be interrupted. The run can be re-triggered, but partial " +
      "work may leave systems in an inconsistent state.\n\n" +
      "Safer alternatives:\n" +
      "- gh run view: Check run status and progress first\n" +
      "- gh run list: Review running workflows\n" +
      "- Wait for natural completion if possible",
  },
  {
    name: "gh-actions-api-delete-secrets",
    re: /gh(?:\s+--?[A-Za-z][A-Za-z0-9-]*\b(?:\s+(?!(?:secret|variable|workflow|run|api)\b)\S+)?)*\s+api\b.*(?:-X\s*|--method(?:=|\s+))DELETE\b.*\b\/?repos\/[^\s/]+\/[^\s/]+\/actions\/secrets\b/,
    severity: "high",
    reason:
      "gh api DELETE against /actions/secrets deletes GitHub Actions secrets.",
    explanation:
      "Making DELETE requests to the GitHub Actions secrets API removes secrets from " +
      "the repository. This bypasses CLI confirmations and directly modifies repository " +
      "settings. Workflows will fail when referencing deleted secrets.\n\n" +
      "Safer alternatives:\n" +
      "- Use gh secret delete for safer deletion with prompts\n" +
      "- gh api GET first: Verify secret exists\n" +
      "- Prefer CLI commands over direct API calls",
  },
  {
    name: "gh-actions-api-delete-variables",
    re: /gh(?:\s+--?[A-Za-z][A-Za-z0-9-]*\b(?:\s+(?!(?:secret|variable|workflow|run|api)\b)\S+)?)*\s+api\b.*(?:-X\s*|--method(?:=|\s+))DELETE\b.*\b\/?repos\/[^\s/]+\/[^\s/]+\/actions\/variables\b/,
    severity: "medium",
    reason:
      "gh api DELETE against /actions/variables deletes GitHub Actions variables.",
    explanation:
      "Making DELETE requests to the GitHub Actions variables API removes variables " +
      "from the repository. This bypasses CLI confirmations and directly modifies " +
      "repository settings. Workflows referencing these variables will fail.\n\n" +
      "Safer alternatives:\n" +
      "- Use gh variable delete for safer deletion with prompts\n" +
      "- gh api GET first: Verify variable exists\n" +
      "- Prefer CLI commands over direct API calls",
  },
];

// ============================================================================
// GitLab CI — DCG src/packs/cicd/gitlab_ci.rs
// ============================================================================

const gitlabCiSafe: SafeRule[] = [
  {
    name: "glab-variable-list",
    re: /glab(?:\s+--?\S+(?:\s+\S+)?)*\s+variable\s+list\b/,
  },
  { name: "glab-ci-list", re: /glab(?:\s+--?\S+(?:\s+\S+)?)*\s+ci\s+list\b/ },
  { name: "glab-ci-view", re: /glab(?:\s+--?\S+(?:\s+\S+)?)*\s+ci\s+view\b/ },
  {
    name: "glab-ci-status",
    re: /glab(?:\s+--?\S+(?:\s+\S+)?)*\s+ci\s+status\b/,
  },
  {
    name: "gitlab-runner-list",
    re: /gitlab-runner(?:\s+--?\S+(?:\s+\S+)?)*\s+list\b/,
  },
  {
    name: "gitlab-runner-status",
    re: /gitlab-runner(?:\s+--?\S+(?:\s+\S+)?)*\s+status\b/,
  },
  {
    name: "glab-api-explicit-get",
    re: /glab(?:\s+--?\S+(?:\s+\S+)?)*\s+api\b.*(?:-X\s*|--method(?:=|\s+))GET\b/,
  },
];

const gitlabCiDestructive: DestructiveRule[] = [
  {
    name: "glab-variable-delete",
    re: /glab(?:\s+--?\S+(?:\s+\S+)?)*\s+variable\s+delete\b/,
    severity: "high",
    reason:
      "glab variable delete removes CI variables and can break pipelines.",
    explanation:
      "Deleting a GitLab CI/CD variable removes it from the project, group, or instance. " +
      "Pipelines that depend on this variable will fail with undefined variable errors. " +
      "Protected or masked variable values cannot be recovered after deletion.\n\n" +
      "Safer alternatives:\n" +
      "- glab variable list: Review existing variables first\n" +
      "- Update variable value instead of deleting\n" +
      "- Check .gitlab-ci.yml for variable usage before removing",
  },
  {
    name: "glab-ci-delete",
    re: /glab(?:\s+--?\S+(?:\s+\S+)?)*\s+ci\s+delete\b/,
    severity: "medium",
    reason: "glab ci delete removes pipeline artifacts or pipelines.",
    explanation:
      "Deleting pipelines or artifacts removes build history, job logs, and generated " +
      "files. This affects debugging capabilities and audit trails. Artifacts needed " +
      "for deployments or releases will no longer be available.\n\n" +
      "Safer alternatives:\n" +
      "- glab ci list: Review pipelines before deletion\n" +
      "- glab ci view: Inspect pipeline details\n" +
      "- Download artifacts before deletion if needed",
  },
  {
    name: "glab-api-delete-variables",
    re: /glab(?:\s+--?\S+(?:\s+\S+)?)*\s+api\b.*(?:-X\s*|--method(?:=|\s+))DELETE\b.*\bvariables\b/,
    severity: "high",
    reason: "glab api DELETE against variables endpoints removes CI variables.",
    explanation:
      "Making DELETE requests to GitLab variables API removes CI/CD variables directly. " +
      "This bypasses CLI confirmations and immediately affects all pipelines using these " +
      "variables. Protected variable values cannot be recovered.\n\n" +
      "Safer alternatives:\n" +
      "- Use glab variable delete for safer deletion\n" +
      "- GET request first: Verify variable exists\n" +
      "- Prefer CLI commands over direct API calls",
  },
  {
    name: "gitlab-runner-unregister",
    re: /gitlab-runner(?:\s+--?\S+(?:\s+\S+)?)*\s+unregister\b/,
    severity: "critical",
    reason: "gitlab-runner unregister removes runners and can halt CI.",
    explanation:
      "Unregistering a GitLab runner removes it from the GitLab instance. Jobs assigned " +
      "to this runner will be stuck pending or fail. With --all-runners, all runners " +
      "on the machine are removed, potentially halting all CI/CD for multiple projects.\n\n" +
      "Safer alternatives:\n" +
      "- gitlab-runner list: Review registered runners first\n" +
      "- Pause the runner in GitLab UI instead\n" +
      "- Verify replacement runners are available before removing",
  },
];

// ============================================================================
// Jenkins — DCG src/packs/cicd/jenkins.rs
// CLI prefix: (?:jenkins-cli|java\s+-jar\s+\S*jenkins-cli\.jar)
// jenkins-curl-* rules carry "i" (DCG leading (?i)).
// ============================================================================

const jenkinsSafe: SafeRule[] = [
  {
    name: "jenkins-cli-list-jobs",
    re: /(?:jenkins-cli|java\s+-jar\s+\S*jenkins-cli\.jar)(?:\s+--?\S+(?:\s+\S+)?)*\s+list-jobs\b/,
  },
  {
    name: "jenkins-cli-get-job",
    re: /(?:jenkins-cli|java\s+-jar\s+\S*jenkins-cli\.jar)(?:\s+--?\S+(?:\s+\S+)?)*\s+get-job\b/,
  },
  {
    name: "jenkins-cli-build",
    re: /(?:jenkins-cli|java\s+-jar\s+\S*jenkins-cli\.jar)(?:\s+--?\S+(?:\s+\S+)?)*\s+build\b/,
  },
  {
    name: "jenkins-cli-who-am-i",
    re: /(?:jenkins-cli|java\s+-jar\s+\S*jenkins-cli\.jar)(?:\s+--?\S+(?:\s+\S+)?)*\s+who-am-i\b/,
  },
  {
    name: "jenkins-cli-list-views",
    re: /(?:jenkins-cli|java\s+-jar\s+\S*jenkins-cli\.jar)(?:\s+--?\S+(?:\s+\S+)?)*\s+list-views\b/,
  },
  {
    name: "jenkins-cli-list-plugins",
    re: /(?:jenkins-cli|java\s+-jar\s+\S*jenkins-cli\.jar)(?:\s+--?\S+(?:\s+\S+)?)*\s+list-plugins\b/,
  },
  {
    name: "jenkins-cli-get-node",
    re: /(?:jenkins-cli|java\s+-jar\s+\S*jenkins-cli\.jar)(?:\s+--?\S+(?:\s+\S+)?)*\s+get-node\b/,
  },
  {
    name: "jenkins-cli-get-credentials",
    re: /(?:jenkins-cli|java\s+-jar\s+\S*jenkins-cli\.jar)(?:\s+--?\S+(?:\s+\S+)?)*\s+get-credentials\b/,
  },
  {
    name: "jenkins-curl-explicit-get",
    re: /^(?!(?=.*(?:-X\s*|--request(?:=|\s+))POST\b)(?=.*\bdoDelete\b))curl(?:\s+--?\S+(?:\s+\S+)?)*\s+(?:-X\s*|--request(?:=|\s+))GET\b.*(?:jenkins|\/job\/|\/api\/)/i,
  },
];

const jenkinsDestructive: DestructiveRule[] = [
  {
    name: "jenkins-cli-delete-job",
    re: /(?:jenkins-cli|java\s+-jar\s+\S*jenkins-cli\.jar)(?:\s+--?\S+(?:\s+\S+)?)*\s+delete-job\b/,
    severity: "critical",
    reason:
      "jenkins-cli delete-job deletes Jenkins jobs and can break pipelines.",
    explanation:
      "Deleting a Jenkins job removes the job configuration, build history, and all " +
      "associated artifacts. Downstream jobs that depend on this job will fail. The " +
      "job definition and history cannot be recovered without backups.\n\n" +
      "Safer alternatives:\n" +
      "- list-jobs: Review jobs before deletion\n" +
      "- get-job: Export job XML configuration first\n" +
      "- Disable the job instead of deleting",
  },
  {
    name: "jenkins-cli-delete-node",
    re: /(?:jenkins-cli|java\s+-jar\s+\S*jenkins-cli\.jar)(?:\s+--?\S+(?:\s+\S+)?)*\s+delete-node\b/,
    severity: "high",
    reason: "jenkins-cli delete-node deletes Jenkins nodes and can halt CI.",
    explanation:
      "Removing a Jenkins node (agent) disconnects it from the controller. Jobs " +
      "configured to run on this node will fail or remain pending. Any running builds " +
      "on the node will be aborted immediately.\n\n" +
      "Safer alternatives:\n" +
      "- get-node: Review node configuration first\n" +
      "- Take node offline temporarily instead\n" +
      "- Verify jobs don't require this specific node",
  },
  {
    name: "jenkins-cli-delete-credentials",
    re: /(?:jenkins-cli|java\s+-jar\s+\S*jenkins-cli\.jar)(?:\s+--?\S+(?:\s+\S+)?)*\s+delete-credentials\b/,
    severity: "high",
    reason: "jenkins-cli delete-credentials removes stored credentials.",
    explanation:
      "Deleting credentials from Jenkins removes them from the credential store. Jobs " +
      "and pipelines using these credentials will fail authentication. Credential " +
      "values (passwords, tokens, keys) cannot be recovered after deletion.\n\n" +
      "Safer alternatives:\n" +
      "- get-credentials: Review credential metadata first\n" +
      "- Update credentials instead of deleting\n" +
      "- Search Jenkinsfiles for credential usage",
  },
  {
    name: "jenkins-cli-delete-builds",
    re: /(?:jenkins-cli|java\s+-jar\s+\S*jenkins-cli\.jar)(?:\s+--?\S+(?:\s+\S+)?)*\s+delete-builds\b/,
    severity: "medium",
    reason: "jenkins-cli delete-builds removes build history and artifacts.",
    explanation:
      "Deleting builds removes build records, console logs, and artifacts for the " +
      "specified build range. This affects audit trails, debugging capabilities, and " +
      "any artifacts needed for deployments. Build history cannot be recovered.\n\n" +
      "Safer alternatives:\n" +
      "- list-jobs: Review job builds first\n" +
      "- Download artifacts before deletion\n" +
      "- Use build retention policies instead",
  },
  {
    name: "jenkins-cli-delete-view",
    re: /(?:jenkins-cli|java\s+-jar\s+\S*jenkins-cli\.jar)(?:\s+--?\S+(?:\s+\S+)?)*\s+delete-view\b/,
    severity: "low",
    reason: "jenkins-cli delete-view removes Jenkins views.",
    explanation:
      "Deleting a Jenkins view removes the view configuration. Jobs included in the " +
      "view are not deleted, but the organizational structure is lost. Users relying " +
      "on this view for job navigation will be affected.\n\n" +
      "Safer alternatives:\n" +
      "- list-views: Review views before deletion\n" +
      "- Export view configuration if custom filters are used\n" +
      "- Create a replacement view before removing",
  },
  {
    name: "jenkins-curl-do-delete",
    re: /\bcurl\b(?=.*(?:-X\s*|--request(?:=|\s+))POST\b)(?=.*\bdoDelete\b).*/i,
    severity: "critical",
    reason:
      "curl POST to Jenkins doDelete endpoints deletes jobs or resources.",
    explanation:
      "POSTing to Jenkins doDelete endpoints triggers immediate deletion of jobs, builds, " +
      "or other resources. This bypasses CLI safety checks and directly calls the " +
      "internal deletion API. Resources cannot be recovered without backups.\n\n" +
      "Safer alternatives:\n" +
      "- Use jenkins-cli for safer deletion with confirmation\n" +
      "- GET the resource configuration first for backup\n" +
      "- Avoid direct API calls for destructive operations",
  },
];

// ============================================================================
// CircleCI — DCG src/packs/cicd/circleci.rs
// ============================================================================

const circleciSafe: SafeRule[] = [
  {
    name: "circleci-context-list",
    re: /circleci(?:\s+--?\S+(?:\s+\S+)?)*\s+context\s+list\b/,
  },
  {
    name: "circleci-orb-list",
    re: /circleci(?:\s+--?\S+(?:\s+\S+)?)*\s+orb\s+list\b/,
  },
  {
    name: "circleci-orb-info",
    re: /circleci(?:\s+--?\S+(?:\s+\S+)?)*\s+orb\s+info\b/,
  },
  {
    name: "circleci-pipeline-list",
    re: /circleci(?:\s+--?\S+(?:\s+\S+)?)*\s+pipeline\s+list\b/,
  },
  {
    name: "circleci-project-list",
    re: /circleci(?:\s+--?\S+(?:\s+\S+)?)*\s+project\s+list\b/,
  },
  {
    name: "circleci-namespace-list",
    re: /circleci(?:\s+--?\S+(?:\s+\S+)?)*\s+namespace\s+list\b/,
  },
  {
    name: "circleci-config-validate",
    re: /circleci(?:\s+--?\S+(?:\s+\S+)?)*\s+config\s+validate\b/,
  },
  {
    name: "circleci-local-execute",
    re: /circleci(?:\s+--?\S+(?:\s+\S+)?)*\s+local\s+execute\b/,
  },
  {
    name: "circleci-policy-status",
    re: /circleci(?:\s+--?\S+(?:\s+\S+)?)*\s+policy\s+status\b/,
  },
  {
    name: "circleci-diagnostic",
    re: /circleci(?:\s+--?\S+(?:\s+\S+)?)*\s+diagnostic\b/,
  },
];

const circleciDestructive: DestructiveRule[] = [
  {
    name: "circleci-context-delete",
    re: /circleci(?:\s+--?\S+(?:\s+\S+)?)*\s+context\s+delete\b/,
    severity: "critical",
    reason: "circleci context delete removes contexts and their secrets.",
    explanation:
      "Deleting a CircleCI context removes all secrets stored within it. Any pipeline " +
      "jobs that reference this context will fail immediately. Secret values cannot be " +
      "recovered after deletion and must be manually re-entered.\n\n" +
      "Safer alternatives:\n" +
      "- circleci context list: Review contexts before deletion\n" +
      "- circleci context show: Inspect context secrets (names only)\n" +
      "- Document secret names before removing context",
  },
  {
    name: "circleci-context-remove-secret",
    re: /circleci(?:\s+--?\S+(?:\s+\S+)?)*\s+context\s+remove-secret\b/,
    severity: "high",
    reason: "circleci context remove-secret deletes secrets from a context.",
    explanation:
      "Removing a secret from a context makes it unavailable to all jobs using that " +
      "context. Pipelines depending on this secret will fail. The secret value cannot " +
      "be retrieved after removal.\n\n" +
      "Safer alternatives:\n" +
      "- circleci context show: Review secrets in context first\n" +
      "- Update the secret value instead of removing\n" +
      "- Document secret value externally before removal",
  },
  {
    name: "circleci-orb-delete",
    re: /circleci(?:\s+--?\S+(?:\s+\S+)?)*\s+orb\s+delete\b/,
    severity: "high",
    reason: "circleci orb delete removes an orb from the registry.",
    explanation:
      "Deleting an orb removes it from the CircleCI orb registry. Any pipeline using " +
      "this orb will fail on the next run. If other teams or projects depend on this " +
      "orb, their CI/CD will break without warning.\n\n" +
      "Safer alternatives:\n" +
      "- circleci orb info: Review orb details and usage\n" +
      "- Deprecate the orb instead of deleting\n" +
      "- Check for dependent projects before deletion",
  },
  {
    name: "circleci-namespace-delete",
    re: /circleci(?:\s+--?\S+(?:\s+\S+)?)*\s+namespace\s+delete\b/,
    severity: "critical",
    reason: "circleci namespace delete removes an orb namespace.",
    explanation:
      "Deleting a namespace removes all orbs within that namespace from the registry. " +
      "This is a cascading deletion that affects every orb published under this namespace. " +
      "All pipelines using any orb from this namespace will fail.\n\n" +
      "Safer alternatives:\n" +
      "- circleci namespace list: Review namespaces first\n" +
      "- circleci orb list: Inventory orbs in namespace\n" +
      "- Delete individual orbs instead if needed",
  },
  {
    name: "circleci-pipeline-delete",
    re: /circleci(?:\s+--?\S+(?:\s+\S+)?)*\s+pipeline\s+delete\b/,
    severity: "medium",
    reason: "circleci pipeline delete removes pipeline history.",
    explanation:
      "Deleting pipeline history removes records of past builds, including logs, artifacts, " +
      "and test results. This affects audit trails and debugging capabilities. The history " +
      "cannot be recovered once deleted.\n\n" +
      "Safer alternatives:\n" +
      "- circleci pipeline list: Review pipelines before deletion\n" +
      "- Export logs and artifacts before deletion\n" +
      "- Consider archiving rather than deleting",
  },
  {
    name: "circleci-api-delete-envvar",
    re: /curl(?:\s+--?\S+(?:\s+\S+)?)*\s+(?:-X\s*|--request(?:=|\s+))DELETE\b.*circleci\.com\/api\/[^\s]*\b(?:envvar|environment-variable)\b/,
    severity: "high",
    reason:
      "curl DELETE against CircleCI envvar endpoints removes environment variables.",
    explanation:
      "Making DELETE requests to CircleCI environment variable endpoints removes variables " +
      "from projects. Pipelines depending on these variables will fail on next run. " +
      "Variable values cannot be recovered after deletion.\n\n" +
      "Safer alternatives:\n" +
      "- GET request first: Review variable exists\n" +
      "- Update variable value instead of deleting\n" +
      "- Use circleci CLI for safer operations",
  },
];

/**
 * CI/CD pack — github_actions + gitlab_ci + jenkins + circleci merged.
 *
 * Sources: DCG `src/packs/cicd/{github_actions,gitlab_ci,jenkins,circleci}.rs`.
 * Keywords are the UNION of the four DCG keyword sets (dedup preserving order):
 * github_actions[gh] + gitlab_ci[glab,gitlab-runner] + jenkins[jenkins-cli,
 * jenkins,doDelete] + circleci[circleci] => [gh,glab,gitlab-runner,jenkins-cli,
 * jenkins,doDelete,circleci]. (`curl`-keyed rules — jenkins doDelete, circleci
 * envvar — qualify via the `doDelete`/`circleci` substrings present in those
 * commands.)
 */
export const cicdPack: Pack = {
  id: "cicd",
  name: "CI/CD",
  description:
    "Protects against destructive CI/CD pipeline operations across GitHub Actions " +
    "(gh), GitLab CI, Jenkins, and CircleCI",
  keywords: [
    "gh",
    "glab",
    "gitlab-runner",
    "jenkins-cli",
    "jenkins",
    "doDelete",
    "circleci",
  ],
  safePatterns: [
    ...githubActionsSafe,
    ...gitlabCiSafe,
    ...jenkinsSafe,
    ...circleciSafe,
  ],
  destructivePatterns: [
    ...githubActionsDestructive,
    ...gitlabCiDestructive,
    ...jenkinsDestructive,
    ...circleciDestructive,
  ],
};
