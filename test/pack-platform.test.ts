// Golden corpus for the merged `platform` pack (gh + railway + kamal + modal +
// gitlab), ported from DCG's own `#[test]` blocks in:
//   - src/packs/platform/github.rs
//   - src/packs/platform/railway.rs
//   - src/packs/platform/kamal.rs
//   - src/packs/platform/modal.rs
//   - src/packs/platform/gitlab.rs
//
// Drives the REAL engine end-to-end (buildRegistry([pack]) + evaluateCommand).
// assert_blocks_with_pattern -> expected ruleName; assert_allows -> allow.
//
// NOTE: gh rules from this pack (platform.github) intentionally overlap with
// cicd.github_actions on secret/variable-delete. Tested in isolation here, the
// platform pack reports its own gh-* rule names.

import assert from "node:assert/strict";
import test from "node:test";
import { evaluateCommand } from "../src/engine/evaluate.ts";
import { platformPack } from "../src/engine/packs/platform.ts";
import { buildRegistry } from "../src/engine/registry.ts";
import type { Severity } from "../src/engine/types.ts";

const registry = buildRegistry([platformPack]);

function blocks(cmd: string, ruleName: string, severity?: Severity): void {
  const d = evaluateCommand(cmd, registry);
  assert.notEqual(d.decision, "allow", `expected ${cmd} to be flagged`);
  assert.equal(d.ruleName, ruleName, `rule for: ${cmd}`);
  if (severity) assert.equal(d.severity, severity, `severity for: ${cmd}`);
}

function allows(cmd: string): void {
  const d = evaluateCommand(cmd, registry);
  assert.equal(
    d.decision,
    "allow",
    `expected ${cmd} to be allowed, got ${d.ruleName}`,
  );
}

// ---------------------------------------------------------------------------
// GitHub gh (DCG src/packs/platform/github.rs mod tests)
// ---------------------------------------------------------------------------

test("github: allows safe variants", () => {
  allows("gh repo list");
  allows("gh repo view");
  allows("gh gist list");
  allows("gh release view v1.0");
  allows("gh issue list");
  allows("gh ssh-key list");
  allows("gh secret list");
  allows("gh variable list");
  allows("gh auth status");
  allows("gh status");
  allows("gh -R owner/repo repo view");
  allows("gh -R owner/repo secret list");
  allows("gh api -X GET /repos/owner/repo");
});

test("github: blocks each destructive pattern (severity high)", () => {
  blocks("gh repo delete owner/repo", "gh-repo-delete", "high");
  blocks("gh -R owner/repo repo delete", "gh-repo-delete", "high");
  blocks("gh repo archive owner/repo", "gh-repo-archive", "high");
  blocks("gh gist delete 123", "gh-gist-delete", "high");
  blocks("gh release delete v1.0", "gh-release-delete", "high");
  blocks("gh issue delete 1", "gh-issue-delete", "high");
  blocks("gh ssh-key delete 1", "gh-ssh-key-delete", "high");
  blocks("gh secret delete SECRET_NAME", "gh-secret-delete", "high");
  blocks("gh secret remove SECRET_NAME", "gh-secret-delete", "high");
  blocks("gh variable delete VAR_NAME", "gh-variable-delete", "high");
  blocks("gh variable remove VAR_NAME", "gh-variable-delete", "high");
  blocks("gh repo deploy-key delete 123", "gh-repo-deploy-key-delete", "high");
  blocks("gh run cancel 123456", "gh-run-cancel", "high");
  blocks(
    "gh api -X DELETE /repos/owner/repo/actions/secrets/SECRET",
    "gh-api-delete-actions-secret",
    "high",
  );
  blocks(
    "gh api -X DELETE /repos/owner/repo/actions/variables/VAR",
    "gh-api-delete-actions-variable",
    "high",
  );
  blocks(
    "gh api -X DELETE /repos/owner/repo/hooks/123",
    "gh-api-delete-hook",
    "high",
  );
  blocks(
    "gh api -X DELETE /repos/owner/repo/keys/456",
    "gh-api-delete-deploy-key",
    "high",
  );
  blocks(
    "gh api -X DELETE /repos/owner/repo/releases/1",
    "gh-api-delete-release",
    "high",
  );
  blocks("gh api -X DELETE /repos/owner/repo", "gh-api-delete-repo", "high");
});

test("github: compact -XDELETE and --method=DELETE forms", () => {
  blocks(
    "gh api -XDELETE /repos/owner/repo/actions/secrets/SECRET",
    "gh-api-delete-actions-secret",
    "high",
  );
  blocks(
    "gh api --method=DELETE /repos/owner/repo",
    "gh-api-delete-repo",
    "high",
  );
});

test("github: api GET safe pattern does not mask DELETE later in the command", () => {
  blocks(
    "gh api -X GET /repos/owner/repo/actions/secrets -XDELETE /repos/owner/repo/actions/secrets/SECRET",
    "gh-api-delete-actions-secret",
  );
});

test("github: unrelated commands allow", () => {
  allows("git status");
  allows("echo hello");
});

// ---------------------------------------------------------------------------
// Railway CLI (DCG src/packs/platform/railway.rs mod tests)
// ---------------------------------------------------------------------------

test("railway: allows read-only CLI", () => {
  allows("railway status");
  allows("railway list");
  allows("railway project list");
  allows("railway whoami");
  allows("railway logs --service web");
  allows("railway service list --json");
  allows("railway functions list");
  allows("railway fn ls");
  allows("railway environment list");
  allows("railway env list");
  allows("railway volume list");
  allows("railway variable list");
  allows("railway vars list");
});

test("railway: blocks destructive CLI", () => {
  blocks("railway delete --yes", "railway-project-delete", "critical");
  blocks(
    "railway project remove --project prod --yes",
    "railway-project-subcommand-delete",
    "critical",
  );
  blocks(
    "railway environment delete production --yes",
    "railway-environment-delete",
    "critical",
  );
  blocks(
    "railway env rm production --yes",
    "railway-environment-delete",
    "critical",
  );
  blocks(
    "railway service delete --service postgres --yes",
    "railway-service-delete",
    "critical",
  );
  blocks(
    "railway service rm --service api --yes",
    "railway-service-delete",
    "critical",
  );
  blocks(
    "railway functions delete --function prod-worker --yes",
    "railway-function-delete",
    "critical",
  );
  blocks(
    "railway function rm --function api-handler --yes",
    "railway-function-delete",
    "critical",
  );
  blocks(
    "railway fn remove --function cron-job --yes",
    "railway-function-delete",
    "critical",
  );
  blocks(
    "railway volume delete --volume data --yes",
    "railway-volume-delete",
    "critical",
  );
  blocks(
    "railway volume detach --volume prod-db --yes",
    "railway-volume-detach",
    "high",
  );
  blocks(
    "railway variable delete DATABASE_URL",
    "railway-variable-delete",
    "high",
  );
  blocks("railway vars rm DATABASE_URL", "railway-variable-delete", "high");
  blocks("railway down --yes", "railway-deployment-remove", "high");
});

test("railway: blocks database-connection variable set", () => {
  blocks(
    "railway variable set DATABASE_URL=postgres://prod",
    "railway-database-variable-set",
    "high",
  );
  blocks(
    "railway variable set --service api DATABASE_PUBLIC_URL=postgres://prod",
    "railway-database-variable-set",
    "high",
  );
  blocks(
    "railway variable set PGHOST=prod-postgres.railway.internal",
    "railway-database-variable-set",
    "high",
  );
  blocks(
    "railway vars set REDIS_PUBLIC_URL=redis://prod",
    "railway-database-variable-set",
    "high",
  );
  blocks(
    "railway var set MYSQLHOST=mysql.railway.internal",
    "railway-database-variable-set",
    "high",
  );
  blocks(
    "railway variables set MONGO_URL=mongodb://example.invalid/app",
    "railway-database-variable-set",
    "high",
  );
});

test("railway: blocks legacy --set database-variable flags", () => {
  blocks(
    "railway variables --set DATABASE_URL=postgres://prod",
    "railway-database-variable-legacy-set",
    "high",
  );
  blocks(
    "railway variables --set REDIS_PUBLIC_URL=redis://prod",
    "railway-database-variable-legacy-set",
    "high",
  );
  blocks(
    "railway var --set-from-stdin DATABASE_URL",
    "railway-database-variable-legacy-set",
    "high",
  );
});

test("railway: allows benign variable sets and doc mentions", () => {
  allows("railway variable set FEATURE_FLAG=true");
  allows("railway variable set FEATURE_FLAG=DATABASE_URL");
  allows("railway variables --set FEATURE_FLAG=true");
  allows("grep projectDelete docs/railway.md");
  allows("echo serviceDelete is a mutation name");
});

test("railway: blocks Public API mutations", () => {
  blocks(
    `curl https://backboard.railway.app/graphql/v2 -d '{"query":"mutation { projectDelete(id:\\"p\\") }"}'`,
    "railway-api-project-delete",
    "critical",
  );
  blocks(
    `curl https://backboard.railway.com/graphql/v2 -d '{"query":"mutation { projectScheduleDelete(id:\\"p\\") }"}'`,
    "railway-api-project-delete",
    "critical",
  );
  blocks(
    `curl https://backboard.railway.app/graphql/v2 -d '{"query":"mutation { environmentDelete(id:\\"e\\") }"}'`,
    "railway-api-environment-delete",
    "critical",
  );
  blocks(
    `curl https://backboard.railway.app/graphql/v2 -d '{"query":"mutation { serviceDelete(id:\\"s\\", environmentId:\\"e\\") }"}'`,
    "railway-api-service-delete",
    "critical",
  );
  blocks(
    `curl https://backboard.railway.app/graphql/v2 -d '{"query":"mutation { volumeDelete(volumeId:\\"v\\") }"}'`,
    "railway-api-volume-delete",
    "critical",
  );
  blocks(
    `curl https://backboard.railway.app/graphql/v2 -d '{"query":"mutation { volumeInstanceBackupRestore(input:{volumeInstanceId:\\"v\\", backupId:\\"b\\"}) }"}'`,
    "railway-api-volume-backup-restore",
    "critical",
  );
  blocks(
    `curl "$RAILWAY_API_URL" -d '{"query":"mutation { volumeInstanceBackupDelete(input:{volumeInstanceId:\\"v\\", backupId:\\"b\\"}) }"}'`,
    "railway-api-volume-backup-delete",
    "high",
  );
  blocks(
    `curl https://backboard.railway.app/graphql/v2 -d '{"query":"mutation { volumeInstanceUpdate(input:{serviceId:null, volumeId:\\"v\\"}) }"}'`,
    "railway-api-volume-detach",
    "high",
  );
  blocks(
    `curl https://backboard.railway.app/graphql/v2 -d '{"query":"mutation { variableDelete(input:{projectId:\\"p\\", environmentId:\\"e\\", name:\\"DATABASE_URL\\"}) }"}'`,
    "railway-api-variable-delete",
    "high",
  );
  blocks(
    `curl https://backboard.railway.app/graphql/v2 -d '{"query":"mutation { variableCollectionUpsert(input:{variables:[{name:\\"DATABASE_URL\\", value:\\"postgres://prod\\"}]}) }"}'`,
    "railway-api-database-variable-upsert",
    "high",
  );
  blocks(
    `curl https://backboard.railway.app/graphql/v2 --data-binary '{"query":"mutation { variableCollectionUpsert(input:{projectId:\\"p\\", environmentId:\\"e\\", variables:{FEATURE_FLAG:\\"true\\"}, replace:true}) }"}'`,
    "railway-api-variable-collection-replace",
    "high",
  );
  blocks(
    `curl https://backboard.railway.app/graphql/v2 -d '{"query":"mutation { deploymentRemove(id:\\"d\\") }"}'`,
    "railway-api-deployment-remove",
    "high",
  );
});

test("railway: allows safe API queries and doc mentions", () => {
  allows(
    `curl https://backboard.railway.app/graphql/v2 -d '{"query":"query { project(id:\\"p\\") { id name } }"}'`,
  );
  allows("grep projectDelete schema.graphql");
});

test("railway: safe CLI segment does not mask a later delete", () => {
  blocks(
    "railway service list && railway volume delete --volume prod-db --yes",
    "railway-volume-delete",
  );
});

// ---------------------------------------------------------------------------
// Kamal (DCG src/packs/platform/kamal.rs mod tests)
// ---------------------------------------------------------------------------

test("kamal: blocks critical teardown/data-loss commands", () => {
  blocks("kamal remove", "kamal-remove", "critical");
  blocks("kamal remove -y", "kamal-remove", "critical");
  blocks("kamal remove --yes -d production", "kamal-remove", "critical");
  blocks("kamal -d staging remove -y", "kamal-remove", "critical");
  blocks("kamal accessory remove db", "kamal-accessory-remove", "critical");
  blocks("kamal accessory remove all", "kamal-accessory-remove", "critical");
  blocks("kamal accessory remove db -y", "kamal-accessory-remove", "critical");
  blocks(
    "kamal -d production accessory remove db",
    "kamal-accessory-remove",
    "critical",
  );
});

test("kamal: blocks high-severity outage commands", () => {
  blocks("kamal app remove", "kamal-app-remove", "high");
  blocks("kamal app stop", "kamal-app-stop", "high");
  blocks("kamal -d prod app stop", "kamal-app-stop", "high");
  blocks("kamal proxy remove", "kamal-proxy-remove", "high");
  blocks("kamal proxy reboot", "kamal-proxy-reboot", "high");
  blocks("kamal proxy reboot -y", "kamal-proxy-reboot", "high");
  blocks("kamal proxy stop", "kamal-proxy-stop", "high");
  blocks("kamal accessory reboot db", "kamal-accessory-reboot", "high");
  blocks("kamal accessory reboot all", "kamal-accessory-reboot", "high");
  blocks("kamal accessory stop db", "kamal-accessory-stop", "high");
});

test("kamal: blocks medium prune commands", () => {
  blocks("kamal prune all", "kamal-prune", "medium");
  blocks("kamal prune containers", "kamal-prune", "medium");
  blocks("kamal prune images", "kamal-prune", "medium");
  blocks("kamal -d staging prune all", "kamal-prune", "medium");
});

test("kamal: allows inspection and deploy commands", () => {
  allows("kamal audit");
  allows("kamal details");
  allows("kamal config");
  allows("kamal secrets print");
  allows("kamal deploy");
  allows("kamal redeploy");
  allows("kamal -d staging deploy");
  allows("kamal setup");
  allows("kamal build push");
  allows("kamal rollback 0123456789abcdef");
  allows("kamal upgrade");
  allows("kamal registry login");
  allows("kamal registry logout");
  allows("kamal lock status");
  allows("kamal server bootstrap");
  allows("kamal init");
  allows("kamal docs configuration");
  allows("kamal help remove");
  allows("kamal version");
});

test("kamal: allows reversible lifecycle commands", () => {
  allows("kamal app boot");
  allows("kamal app start");
  allows("kamal app details");
  allows("kamal app stale_containers");
  allows("kamal app maintenance");
  allows("kamal app live");
  allows("kamal accessory restart db");
  allows("kamal accessory details db");
  allows("kamal accessory upgrade db");
  allows("kamal proxy boot");
  allows("kamal proxy boot_config get");
  allows("kamal proxy restart");
  allows("kamal proxy details");
  allows("kamal proxy logs");
});

test("kamal: safe lookalikes do not trip destructive rules", () => {
  allows("kamal accessory restart db");
  allows("kamal proxy restart");
  allows("kamal app boot");
  allows("kamal proxy boot");
  blocks("kamal accessory reboot db", "kamal-accessory-reboot");
  blocks("kamal app remove", "kamal-app-remove");
  blocks("kamal proxy remove", "kamal-proxy-remove");
});

test("kamal: safe segment does not mask later destructive", () => {
  blocks(
    "kamal app details && kamal accessory remove db",
    "kamal-accessory-remove",
  );
  blocks("kamal config | kamal remove -y", "kamal-remove");
  blocks("kamal deploy ; kamal proxy reboot", "kamal-proxy-reboot");
});

// ---------------------------------------------------------------------------
// Modal (DCG src/packs/platform/modal.rs mod tests)
// ---------------------------------------------------------------------------

test("modal: allows read-only CLI", () => {
  allows("modal volume list");
  allows("modal volume ls my-vol");
  allows("modal volume get my-vol /file.bin ./file.bin");
  allows("modal volume cp my-vol /a /b");
  allows("modal volume create my-vol");
  allows("modal volume rename old new");
  allows("modal app list");
  allows("modal app logs my-app");
  allows("modal app rollback my-app v3");
  allows("modal container list");
  allows("modal container logs ta-1");
  allows("modal container exec ta-1 bash");
  allows("modal secret list");
  allows("modal secret create api-key VALUE=xxx");
  allows("modal environment list");
  allows("modal environment create staging");
  allows("modal environment update prod");
  allows("modal dict list");
  allows("modal dict get my-dict key");
  allows("modal dict items my-dict");
  allows("modal dict create my-dict");
  allows("modal queue list");
  allows("modal queue peek my-q");
  allows("modal queue len my-q");
  allows("modal queue create my-q");
  allows("modal shell my-fn");
  allows("modal deploy ./app.py");
  allows("modal serve ./app.py");
  allows("modal run ./app.py");
  allows("modal token info");
  allows("modal token new");
  allows("modal token set --token-id ak-abc");
});

test("modal: blocks critical resource deletion", () => {
  blocks(
    "modal environment delete prod --yes",
    "modal-environment-delete",
    "critical",
  );
  blocks(
    "modal environment rm staging -y",
    "modal-environment-delete",
    "critical",
  );
  blocks(
    "modal volume delete model-weights --yes",
    "modal-volume-delete",
    "critical",
  );
  blocks(
    "modal volume remove checkpoints -y",
    "modal-volume-delete",
    "critical",
  );
  blocks(
    "modal secret delete openai-key --yes",
    "modal-secret-delete",
    "critical",
  );
  blocks(
    "modal secret rm postgres-creds -y",
    "modal-secret-delete",
    "critical",
  );
  blocks("modal dict delete state -y", "modal-dict-delete", "critical");
  blocks("modal queue delete jobs --yes", "modal-queue-delete", "critical");
});

test("modal: blocks high-severity terminate/wipe", () => {
  blocks("modal app stop my-prod-app -y", "modal-app-stop", "high");
  blocks("modal app stop ap-abc123 --yes", "modal-app-stop", "high");
  blocks("modal container stop ta-deadbeef -y", "modal-container-stop", "high");
  blocks(
    "modal volume rm -r model-weights /old-checkpoints",
    "modal-volume-rm-recursive",
    "high",
  );
  blocks(
    "modal volume rm --recursive my-vol /subdir",
    "modal-volume-rm-recursive",
    "high",
  );
  blocks("modal dict clear state -y", "modal-dict-clear", "high");
  blocks("modal queue clear jobs --yes", "modal-queue-clear", "high");
});

test("modal: blocks medium single-file delete / force overwrite", () => {
  blocks("modal volume rm model-weights /old.bin", "modal-volume-rm", "medium");
  blocks(
    "modal secret create --force openai-key VALUE=new",
    "modal-secret-create-force",
    "medium",
  );
  blocks(
    "modal secret create openai-key VALUE=new --force",
    "modal-secret-create-force",
    "medium",
  );
});

test("modal: distinguishes create --force from create without force", () => {
  allows("modal secret create new-secret VALUE=abc");
  allows("modal secret create --from-dotenv .env new-secret");
  blocks(
    "modal secret create --force my-secret VALUE=new",
    "modal-secret-create-force",
  );
});

test("modal: distinguishes recursive volume rm from single-file", () => {
  blocks("modal volume rm my-vol /file.bin", "modal-volume-rm", "medium");
  blocks("modal volume rm -r my-vol /dir", "modal-volume-rm-recursive", "high");
});

test("modal: safe segment does not mask later delete", () => {
  blocks(
    "modal volume list && modal volume delete model-weights --yes",
    "modal-volume-delete",
  );
  blocks("modal app list | modal app stop my-app --yes", "modal-app-stop");
});

// ---------------------------------------------------------------------------
// GitLab (DCG src/packs/platform/gitlab.rs mod tests)
// ---------------------------------------------------------------------------

test("gitlab: blocks destructive glab/gitlab-rails/gitlab-rake (severity high)", () => {
  blocks("glab repo delete my/group", "glab-repo-delete", "high");
  blocks("glab repo archive my/group", "glab-repo-archive", "high");
  blocks("glab release delete v1.2.3", "glab-release-delete", "high");
  blocks("glab variable delete FOO", "glab-variable-delete", "high");
  blocks("glab api -X DELETE projects/123", "glab-api-delete-project", "high");
  blocks(
    "glab api -X DELETE /projects/123/releases/v1.2.3",
    "glab-api-delete-release",
    "high",
  );
  blocks(
    "glab api -X DELETE /projects/123/variables/SECRET",
    "glab-api-delete-variable",
    "high",
  );
  blocks(
    "glab api --method DELETE /projects/123/protected_branches/main",
    "glab-api-delete-protected-branch",
    "high",
  );
  blocks(
    "glab api -X DELETE /projects/123/hooks/456",
    "glab-api-delete-hook",
    "high",
  );
  blocks(
    'gitlab-rails runner "Project.destroy_all"',
    "gitlab-rails-runner-destructive",
    "high",
  );
  blocks(
    "gitlab-rake gitlab:backup:restore",
    "gitlab-rake-destructive",
    "high",
  );
});

test("gitlab: blocks compact -XDELETE and --method=DELETE forms", () => {
  blocks("glab api -XDELETE projects/123", "glab-api-delete-project", "high");
  blocks(
    "glab api --method=DELETE projects/123",
    "glab-api-delete-project",
    "high",
  );
  blocks(
    "glab api -XDELETE /projects/123/variables/SECRET",
    "glab-api-delete-variable",
    "high",
  );
  blocks(
    "glab api -XDELETE /projects/123/hooks/456",
    "glab-api-delete-hook",
    "high",
  );
});

test("gitlab: allows safe commands", () => {
  allows("glab repo list");
  allows("glab repo view my/group");
  allows("glab repo clone my/group");
  allows("glab mr list");
  allows("glab mr view 123");
  allows("glab issue list");
  allows("glab issue view 456");
  allows("glab variable list");
  allows("glab release list");
  allows("glab release view v1.2.3");
  allows("glab api -X GET projects/123");
});
