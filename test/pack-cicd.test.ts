// Golden corpus for the merged `cicd` pack (github_actions + gitlab_ci +
// jenkins + circleci), ported from DCG's own `#[test]` blocks in:
//   - src/packs/cicd/github_actions.rs
//   - src/packs/cicd/gitlab_ci.rs
//   - src/packs/cicd/jenkins.rs
//   - src/packs/cicd/circleci.rs
//
// Drives the REAL engine end-to-end (buildRegistry([pack]) + evaluateCommand).
// assert_blocks_with_pattern -> expected ruleName; assert_allows -> allow.
//
// NOTE: cicd.github_actions intentionally overlaps with platform.github on `gh`
// secret/variable-delete (both ported faithfully). Tested here in isolation, the
// cicd pack reports its own gh-actions-* rule names.

import test from "node:test";
import assert from "node:assert/strict";

import { cicdPack } from "../src/engine/packs/cicd.ts";
import { buildRegistry } from "../src/engine/registry.ts";
import { evaluateCommand } from "../src/engine/evaluate.ts";
import type { Severity } from "../src/engine/types.ts";

const registry = buildRegistry([cicdPack]);

function blocks(cmd: string, ruleName: string, severity?: Severity): void {
  const d = evaluateCommand(cmd, registry);
  assert.notEqual(d.decision, "allow", `expected ${cmd} to be flagged`);
  assert.equal(d.ruleName, ruleName, `rule for: ${cmd}`);
  if (severity) assert.equal(d.severity, severity, `severity for: ${cmd}`);
}

function allows(cmd: string): void {
  const d = evaluateCommand(cmd, registry);
  assert.equal(d.decision, "allow", `expected ${cmd} to be allowed, got ${d.ruleName}`);
}

// ---------------------------------------------------------------------------
// GitHub Actions gh (DCG src/packs/cicd/github_actions.rs mod tests)
// ---------------------------------------------------------------------------

test("github_actions: allows safe list/view variants", () => {
  allows("gh secret list");
  allows("gh variable list");
  allows("gh workflow list");
  allows("gh workflow view 123");
  allows("gh run list");
  allows("gh run view 456");
  allows("gh api -X GET repos/o/r/actions/secrets");
});

test("github_actions: blocks each destructive pattern with severity", () => {
  blocks("gh secret delete FOO", "gh-actions-secret-remove", "high");
  blocks("gh secret remove FOO", "gh-actions-secret-remove", "high");
  blocks("gh -R owner/repo secret remove FOO", "gh-actions-secret-remove", "high");
  blocks("gh variable delete FOO", "gh-actions-variable-remove", "medium");
  blocks("gh variable remove FOO", "gh-actions-variable-remove", "medium");
  blocks("gh workflow disable 123", "gh-actions-workflow-disable", "low");
  blocks("gh run cancel 456", "gh-actions-run-cancel", "low");
  blocks("gh api -X DELETE repos/o/r/actions/secrets/FOO", "gh-actions-api-delete-secrets", "high");
  blocks("gh api --method DELETE /repos/o/r/actions/variables/FOO", "gh-actions-api-delete-variables", "medium");
});

test("github_actions: compact -XDELETE and --method=DELETE forms", () => {
  blocks("gh api -XDELETE repos/o/r/actions/secrets/FOO", "gh-actions-api-delete-secrets", "high");
  blocks("gh api --method=DELETE /repos/o/r/actions/variables/FOO", "gh-actions-api-delete-variables", "medium");
});

test("github_actions: api GET safe pattern does not mask DELETE later", () => {
  blocks(
    "gh api -XGET repos/o/r/actions/secrets -XDELETE repos/o/r/actions/secrets/FOO",
    "gh-actions-api-delete-secrets",
  );
});

test("github_actions: unrelated commands allow", () => {
  allows("git status");
  allows("echo hello");
});

// ---------------------------------------------------------------------------
// GitLab CI (DCG src/packs/cicd/gitlab_ci.rs mod tests)
// ---------------------------------------------------------------------------

test("gitlab_ci: blocks destructive operations", () => {
  blocks("glab variable delete CI_TOKEN", "glab-variable-delete", "high");
  blocks("glab ci delete 123", "glab-ci-delete", "medium");
  blocks("glab api -X DELETE projects/1/variables/FOO", "glab-api-delete-variables", "high");
  blocks("gitlab-runner unregister --all-runners", "gitlab-runner-unregister", "critical");
});

test("gitlab_ci: compact -XDELETE and --method=DELETE forms", () => {
  blocks("glab api -XDELETE projects/1/variables/FOO", "glab-api-delete-variables", "high");
  blocks("glab api --method=DELETE projects/1/variables/FOO", "glab-api-delete-variables", "high");
});

test("gitlab_ci: allows safe commands", () => {
  allows("glab variable list");
  allows("glab ci list");
  allows("glab ci view 123");
  allows("glab ci status");
  allows("gitlab-runner list");
  allows("gitlab-runner status");
});

// ---------------------------------------------------------------------------
// Jenkins (DCG src/packs/cicd/jenkins.rs mod tests)
// ---------------------------------------------------------------------------

test("jenkins: blocks jenkins-cli destructive subcommands", () => {
  blocks(
    "java -jar jenkins-cli.jar -s http://jenkins.local/ delete-job my-job",
    "jenkins-cli-delete-job",
    "critical",
  );
  blocks(
    "java -jar jenkins-cli.jar -s http://jenkins.local/ delete-node agent-1",
    "jenkins-cli-delete-node",
    "high",
  );
  blocks(
    "java -jar jenkins-cli.jar -s http://jenkins.local/ delete-credentials system::system::foo",
    "jenkins-cli-delete-credentials",
    "high",
  );
  blocks(
    "java -jar jenkins-cli.jar -s http://jenkins.local/ delete-builds my-job 100..200",
    "jenkins-cli-delete-builds",
    "medium",
  );
  blocks(
    "java -jar jenkins-cli.jar -s http://jenkins.local/ delete-view prod-view",
    "jenkins-cli-delete-view",
    "low",
  );
});

test("jenkins: blocks curl POST doDelete", () => {
  blocks("curl -X POST https://jenkins.example/job/my-job/doDelete", "jenkins-curl-do-delete", "critical");
  blocks("curl https://jenkins.example/job/my-job/doDelete --request=POST", "jenkins-curl-do-delete", "critical");
});

test("jenkins: allows safe commands", () => {
  allows("java -jar jenkins-cli.jar -s http://jenkins.local/ list-jobs");
  allows("java -jar jenkins-cli.jar -s http://jenkins.local/ who-am-i");
  allows("java -jar jenkins-cli.jar -s http://jenkins.local/ get-job my-job");
  allows("java -jar jenkins-cli.jar -s http://jenkins.local/ list-views");
  allows("java -jar jenkins-cli.jar -s http://jenkins.local/ list-plugins");
  allows("java -jar jenkins-cli.jar -s http://jenkins.local/ get-node agent-1");
  allows("java -jar jenkins-cli.jar -s http://jenkins.local/ get-credentials system::system::foo");
  allows("jenkins-cli build my-job");
  allows("curl -X GET https://jenkins.example/api/json");
});

// ---------------------------------------------------------------------------
// CircleCI (DCG src/packs/cicd/circleci.rs mod tests)
// ---------------------------------------------------------------------------

test("circleci: blocks destructive operations", () => {
  blocks("circleci context delete org/my-org context/prod", "circleci-context-delete", "critical");
  blocks(
    "circleci context remove-secret org/my-org context/prod AWS_ACCESS_KEY_ID",
    "circleci-context-remove-secret",
    "high",
  );
  blocks("circleci orb delete my-org/my-orb", "circleci-orb-delete", "high");
  blocks("circleci namespace delete my-org", "circleci-namespace-delete", "critical");
  blocks("circleci pipeline delete 123456", "circleci-pipeline-delete", "medium");
  blocks(
    "curl -X DELETE https://circleci.com/api/v2/project/gh/org/repo/envvar/FOO",
    "circleci-api-delete-envvar",
    "high",
  );
});

test("circleci: compact -XDELETE and --request=DELETE curl forms", () => {
  blocks(
    "curl -XDELETE https://circleci.com/api/v2/project/gh/org/repo/envvar/FOO",
    "circleci-api-delete-envvar",
    "high",
  );
  blocks(
    "curl --request=DELETE https://circleci.com/api/v2/project/gh/org/repo/envvar/FOO",
    "circleci-api-delete-envvar",
    "high",
  );
});

test("circleci: allows safe commands", () => {
  allows("circleci context list org/my-org");
  allows("circleci orb list org/my-org");
  allows("circleci orb info my-org/my-orb");
  allows("circleci pipeline list org/my-org/project/app");
  allows("circleci project list");
  allows("circleci namespace list");
  allows("circleci config validate .circleci/config.yml");
  allows("circleci local execute");
  allows("circleci policy status");
  allows("circleci diagnostic");
});
