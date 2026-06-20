// Infrastructure pack — IaC tooling (Terraform, Ansible, Pulumi).
//
// Faithful port of DCG's three infrastructure sub-packs into ONE Pack:
//   - src/packs/infrastructure/terraform.rs  -> id "infrastructure.terraform"
//   - src/packs/infrastructure/ansible.rs    -> id "infrastructure.ansible"
//   - src/packs/infrastructure/pulumi.rs     -> id "infrastructure.pulumi"
// (https://github.com/Dicklesworthstone/destructive_command_guard)
//
// MERGE NOTE: DCG ships these as three separate `create_pack()`s, each with its
// own snake_case id. The Pi module contract asks for ONE `infrastructurePack`
// per category, so the three rule sets are concatenated into a single Pack with
// id "infrastructure". Rule NAMES are tool-prefixed (`terraform-destroy`,
// `pulumi-destroy`, `ansible-shell-rm-rf`) because DCG reuses bare names like
// "destroy" across terraform AND pulumi, and a single pack needs unique names
// (the public rule id is `${packId}:${ruleName}`). reason/explanation/severity
// and per-tool declaration order are preserved 1:1. Tool groups are disjoint
// (terraform / ansible / pulumi are different executables), so cross-tool order
// is not load-bearing; within a tool the order matches DCG exactly.
//
// JS RegExp porting notes (this category):
//  - No POSIX classes, no possessive quantifiers, no inline `(?i)` flags here.
//    All DCG patterns are case-sensitive, so NONE of these RegExp carry "i".
//  - Rust raw strings transliterate verbatim; only `/` is JS-escaped (none of
//    these patterns contain a literal `/` outside char classes anyway).
//  - `ansible-extra-vars-delete` DCG source is `r#"...['\"]..."#`: a char class
//    matching `'` or `"`. In JS that is `['"]`.
//  - Lazy `.*?` and lookahead `(?=\s|$)` / negative lookahead `(?!...)` are
//    native JS and ported unchanged.

import type { DestructiveRule, Pack, SafeRule } from "../types.ts";

// ============================================================================
// Terraform — DCG src/packs/infrastructure/terraform.rs
// ============================================================================

const terraformSafe: SafeRule[] = [
  {
    name: "terraform-plan",
    re: /terraform\b(?:\s+--?\S+(?:\s+\S+)?)*\s+plan(?=\s|$)(?!\s+.*-destroy)/,
  },
  {
    name: "terraform-init",
    re: /terraform\b(?:\s+--?\S+(?:\s+\S+)?)*\s+init(?=\s|$)/,
  },
  {
    name: "terraform-validate",
    re: /terraform\b(?:\s+--?\S+(?:\s+\S+)?)*\s+validate(?=\s|$)/,
  },
  {
    name: "terraform-fmt",
    re: /terraform\b(?:\s+--?\S+(?:\s+\S+)?)*\s+fmt(?=\s|$)/,
  },
  {
    name: "terraform-show",
    re: /terraform\b(?:\s+--?\S+(?:\s+\S+)?)*\s+show(?=\s|$)/,
  },
  {
    name: "terraform-output",
    re: /terraform\b(?:\s+--?\S+(?:\s+\S+)?)*\s+output(?=\s|$)/,
  },
  {
    name: "terraform-state-list",
    re: /terraform\b(?:\s+--?\S+(?:\s+\S+)?)*\s+state\s+list(?=\s|$)/,
  },
  {
    name: "terraform-state-show",
    re: /terraform\b(?:\s+--?\S+(?:\s+\S+)?)*\s+state\s+show(?=\s|$)/,
  },
  {
    name: "terraform-graph",
    re: /terraform\b(?:\s+--?\S+(?:\s+\S+)?)*\s+graph(?=\s|$)/,
  },
  {
    name: "terraform-version",
    re: /terraform\b(?:\s+--?\S+(?:\s+\S+)?)*\s+version(?=\s|$)/,
  },
  {
    name: "terraform-providers",
    re: /terraform\b(?:\s+--?\S+(?:\s+\S+)?)*\s+providers(?=\s|$)/,
  },
];

const terraformDestructive: DestructiveRule[] = [
  {
    name: "terraform-plan-destroy",
    re: /terraform\b.*?\bplan\s+.*-destroy/,
    severity: "medium",
    reason:
      "terraform plan -destroy shows what would be destroyed. Review carefully before applying.",
    explanation:
      "terraform plan -destroy shows destruction preview:\n\n" +
      "- This is a read-only operation (safe to run)\n" +
      "- Shows what WOULD be destroyed if you apply\n" +
      "- Review output carefully before proceeding\n\n" +
      "This is actually the safe way to preview destroy.",
  },
  {
    name: "terraform-destroy",
    re: /terraform\b.*?\bdestroy(?=\s|$)/,
    severity: "critical",
    reason:
      "terraform destroy removes ALL managed infrastructure. Use 'terraform plan -destroy' first.",
    explanation:
      "terraform destroy removes ALL managed infrastructure:\n\n" +
      "- Every resource in your state file is destroyed\n" +
      "- Cloud resources (VMs, databases, networks) deleted\n" +
      "- Cannot be undone without backups/recreation\n" +
      "- Use -target to destroy specific resources only\n\n" +
      "Preview first: terraform plan -destroy",
  },
  {
    name: "terraform-apply-auto-approve",
    re: /terraform\b.*?\bapply\s+.*-auto-approve/,
    severity: "high",
    reason:
      "terraform apply -auto-approve skips confirmation. Remove -auto-approve for safety.",
    explanation:
      "terraform apply -auto-approve skips confirmation:\n\n" +
      "- No opportunity to review changes before applying\n" +
      "- Intended for CI/CD, not interactive use\n" +
      "- Changes may destroy or recreate resources\n\n" +
      "For safety: remove -auto-approve and review the plan",
  },
  {
    name: "terraform-taint",
    re: /terraform\b.*?\btaint\b/,
    severity: "high",
    reason:
      "terraform taint marks a resource to be destroyed and recreated on next apply.",
    explanation:
      "terraform taint marks resource for recreation:\n\n" +
      "- Resource will be destroyed on next apply\n" +
      "- New resource created with same config\n" +
      "- May cause downtime during recreation\n" +
      "- IP addresses and identifiers may change\n\n" +
      "Use -replace in plan/apply instead (Terraform 0.15.2+)",
  },
  {
    name: "terraform-state-rm",
    re: /terraform\b.*?\bstate\s+rm\b/,
    severity: "high",
    reason:
      "terraform state rm removes resource from state without destroying it. Resource becomes unmanaged.",
    explanation:
      "terraform state rm orphans resources:\n\n" +
      "- Resource removed from Terraform state\n" +
      "- Actual cloud resource still exists\n" +
      "- Resource becomes 'unmanaged' (Terraform ignores it)\n" +
      "- May cause drift between state and reality\n\n" +
      "Back up state first: terraform state pull > backup.tfstate",
  },
  {
    name: "terraform-state-mv",
    re: /terraform\b.*?\bstate\s+mv\b/,
    severity: "high",
    reason:
      "terraform state mv moves resources in state. Incorrect moves can cause resource recreation.",
    explanation:
      "terraform state mv moves resources in state:\n\n" +
      "- Renames resource address in state file\n" +
      "- Wrong move can cause destruction/recreation\n" +
      "- Use -dry-run to preview the move first\n" +
      "- Does not affect actual cloud resources\n\n" +
      "Preview first: terraform state mv -dry-run SOURCE DEST",
  },
  {
    name: "terraform-force-unlock",
    re: /terraform\b.*?\bforce-unlock\b/,
    severity: "high",
    reason:
      "terraform force-unlock removes state lock. Only use if lock is stale.",
    explanation:
      "terraform force-unlock removes state locks:\n\n" +
      "- Forces removal of a state lock\n" +
      "- May cause corruption if another process is running\n" +
      "- Only use when you're sure no other operation is active\n" +
      "- Lock ID required to prevent accidents\n\n" +
      "Verify no other operations: check CI/CD pipelines, other users",
  },
  {
    name: "terraform-workspace-delete",
    re: /terraform\b.*?\bworkspace\s+delete\b/,
    severity: "medium",
    reason:
      "terraform workspace delete removes a workspace. Ensure it's not in use.",
    explanation:
      "terraform workspace delete removes workspace:\n\n" +
      "- Workspace and its state file deleted\n" +
      "- Does NOT destroy actual infrastructure\n" +
      "- Resources become unmanaged (orphaned)\n" +
      "- Cannot be undone without state backup\n\n" +
      "Destroy resources first: terraform destroy, then delete workspace",
  },
];

// ============================================================================
// Ansible — DCG src/packs/infrastructure/ansible.rs
// ============================================================================

const ansibleSafe: SafeRule[] = [
  {
    name: "ansible-check",
    re: /ansible(?:-playbook)?\b[^\n;&|]*--check(?:\s|$)[^\n;&|]*$/,
  },
  {
    name: "ansible-list-hosts",
    re: /ansible(?:-playbook)?\b[^\n;&|]*--list-hosts(?:\s|$)[^\n;&|]*$/,
  },
  {
    name: "ansible-list-tasks",
    re: /ansible(?:-playbook)?\b[^\n;&|]*--list-tasks(?:\s|$)[^\n;&|]*$/,
  },
  {
    name: "ansible-syntax",
    re: /ansible(?:-playbook)?\b[^\n;&|]*--syntax-check(?:\s|$)[^\n;&|]*$/,
  },
  { name: "ansible-inventory", re: /ansible-inventory\b[^\n;&|]*$/ },
  { name: "ansible-doc", re: /ansible-doc\b[^\n;&|]*$/ },
  { name: "ansible-config", re: /ansible-config\b[^\n;&|]*$/ },
];

const ansibleDestructive: DestructiveRule[] = [
  {
    name: "ansible-shell-rm-rf",
    re: /ansible\s+.*-m\s+(?:shell|command)\s+.*rm\s+-rf/,
    severity: "critical",
    reason:
      "Ansible shell/command with 'rm -rf' is destructive. Review carefully.",
    explanation:
      "Running 'rm -rf' via Ansible shell or command module executes destructive deletion " +
      "across all targeted hosts simultaneously. This multiplies the impact compared to " +
      "running it locally:\n\n" +
      "- Files deleted on every host in inventory or pattern\n" +
      "- No confirmation or dry-run by default\n" +
      "- Parallel execution means rapid, widespread destruction\n" +
      "- Cannot be undone without backups on each host\n\n" +
      "Safer alternatives:\n" +
      "- Use file module with state=absent for managed deletion\n" +
      "- Add --check flag to preview which hosts would be affected\n" +
      "- Use --limit to restrict to specific hosts first\n" +
      "- Verify target path with debug module before deletion",
  },
  {
    name: "ansible-shell-reboot",
    re: /ansible\s+.*-m\s+(?:shell|command)\s+.*(?:reboot|shutdown|poweroff)/,
    severity: "high",
    reason:
      "Ansible shell/command with reboot/shutdown affects system availability.",
    explanation:
      "Rebooting or shutting down systems via Ansible affects all targeted hosts at once. " +
      "This can cause service outages across your infrastructure:\n\n" +
      "- All services on affected hosts become unavailable\n" +
      "- No graceful draining of connections or traffic\n" +
      "- Database transactions may be interrupted\n" +
      "- Load balancer health checks will fail\n\n" +
      "Safer alternatives:\n" +
      "- Use the reboot module which handles wait_for_connection\n" +
      "- Add serial: 1 to playbook for rolling reboots\n" +
      "- Use --limit to test on single host first\n" +
      "- Coordinate with maintenance windows",
  },
  {
    name: "ansible-playbook-all-hosts",
    re: /ansible-playbook\s+(?!.*(?:--check(?:\s|$)|--limit)).*-i\s+\S+\s+\S+\.ya?ml/,
    severity: "high",
    reason:
      "ansible-playbook without --check or --limit may affect all hosts. Use --check first.",
    explanation:
      "Running ansible-playbook without --check or --limit applies changes to all hosts in " +
      "the inventory. This is risky for destructive playbooks:\n\n" +
      "- Every host matching the play's pattern is affected\n" +
      "- Mistakes propagate to entire infrastructure at once\n" +
      "- No opportunity to verify changes before they're applied\n" +
      "- Rollback may be difficult or impossible\n\n" +
      "Safer alternatives:\n" +
      "- Add --check --diff to preview changes\n" +
      "- Use --limit host1,host2 to test on subset\n" +
      "- Add serial: 1 to playbook for rolling updates\n" +
      "- Review the playbook tasks before running",
  },
  {
    name: "ansible-extra-vars-delete",
    re: /ansible\s+.*-e\s+['"].*(?:delete|remove|destroy|drop)/,
    severity: "medium",
    reason:
      "Ansible extra-vars contains potentially destructive keywords. Review carefully.",
    explanation:
      "Extra variables containing destructive keywords like 'delete', 'remove', 'destroy', " +
      "or 'drop' may trigger conditional destructive actions in playbooks:\n\n" +
      "- Variables may control whether resources are deleted\n" +
      "- Typos in variable values could trigger unintended paths\n" +
      "- Variable precedence may override safer defaults\n\n" +
      "Safer alternatives:\n" +
      "- Review playbook to understand how variables are used\n" +
      "- Add --check to see what tasks would run\n" +
      "- Use --limit to test on single host first\n" +
      "- Consider using vault-encrypted vars for destructive flags",
  },
];

// ============================================================================
// Pulumi — DCG src/packs/infrastructure/pulumi.rs
// ============================================================================

const pulumiSafe: SafeRule[] = [
  {
    name: "pulumi-preview",
    re: /pulumi\b(?:\s+--?\S+(?:\s+\S+)?)*\s+preview(?=\s|$)/,
  },
  {
    name: "pulumi-stack-ls",
    re: /pulumi\b(?:\s+--?\S+(?:\s+\S+)?)*\s+stack\s+ls(?=\s|$)/,
  },
  {
    name: "pulumi-stack-select",
    re: /pulumi\b(?:\s+--?\S+(?:\s+\S+)?)*\s+stack\s+select(?=\s|$)/,
  },
  {
    name: "pulumi-stack-init",
    re: /pulumi\b(?:\s+--?\S+(?:\s+\S+)?)*\s+stack\s+init(?=\s|$)/,
  },
  {
    name: "pulumi-config",
    re: /pulumi\b(?:\s+--?\S+(?:\s+\S+)?)*\s+config(?=\s|$)/,
  },
  {
    name: "pulumi-whoami",
    re: /pulumi\b(?:\s+--?\S+(?:\s+\S+)?)*\s+whoami(?=\s|$)/,
  },
  {
    name: "pulumi-version",
    re: /pulumi\b(?:\s+--?\S+(?:\s+\S+)?)*\s+version(?=\s|$)/,
  },
  {
    name: "pulumi-about",
    re: /pulumi\b(?:\s+--?\S+(?:\s+\S+)?)*\s+about(?=\s|$)/,
  },
  {
    name: "pulumi-logs",
    re: /pulumi\b(?:\s+--?\S+(?:\s+\S+)?)*\s+logs(?=\s|$)/,
  },
];

const pulumiDestructive: DestructiveRule[] = [
  {
    name: "pulumi-destroy",
    re: /pulumi\b.*?\bdestroy(?=\s|$)/,
    severity: "critical",
    reason:
      "pulumi destroy removes ALL managed infrastructure. Use 'pulumi preview --diff' first.",
    explanation:
      "pulumi destroy removes ALL managed infrastructure:\n\n" +
      "- Every resource in your stack is destroyed\n" +
      "- Cloud resources (VMs, databases, networks) deleted\n" +
      "- Cannot be undone without backups/recreation\n" +
      "- Use --target to destroy specific resources only\n\n" +
      "Preview first: pulumi preview --diff",
  },
  {
    name: "pulumi-up-yes",
    re: /pulumi\b.*?\bup\s+.*(?:-y\b|--yes\b)/,
    severity: "high",
    reason: "pulumi up -y skips confirmation. Remove -y flag for safety.",
    explanation:
      "pulumi up -y skips confirmation:\n\n" +
      "- No opportunity to review changes before applying\n" +
      "- Intended for CI/CD, not interactive use\n" +
      "- Changes may destroy or recreate resources\n" +
      "- Replacements can cause downtime\n\n" +
      "For safety: remove -y and review the preview",
  },
  {
    name: "pulumi-state-delete",
    re: /pulumi\b.*?\bstate\s+delete/,
    severity: "high",
    reason:
      "pulumi state delete removes resource from state without destroying it.",
    explanation:
      "pulumi state delete orphans resources:\n\n" +
      "- Resource removed from Pulumi state\n" +
      "- Actual cloud resource still exists\n" +
      "- Resource becomes 'unmanaged' (Pulumi ignores it)\n" +
      "- May cause drift between state and reality\n\n" +
      "Consider: pulumi refresh to sync state with reality",
  },
  {
    name: "pulumi-stack-rm",
    re: /pulumi\b.*?\bstack\s+rm/,
    severity: "high",
    reason:
      "pulumi stack rm removes the stack. Use --force only if stack is empty.",
    explanation:
      "pulumi stack rm removes the entire stack:\n\n" +
      "- Stack and its state deleted\n" +
      "- Does NOT destroy actual infrastructure (unless empty)\n" +
      "- --force required if resources still exist\n" +
      "- Resources become unmanaged (orphaned)\n\n" +
      "Destroy resources first: pulumi destroy, then rm stack",
  },
  {
    name: "pulumi-refresh-yes",
    re: /pulumi\b.*?\brefresh\s+.*(?:-y\b|--yes\b)/,
    severity: "medium",
    reason:
      "pulumi refresh -y auto-approves state changes. Review changes first.",
    explanation:
      "pulumi refresh -y auto-approves state sync:\n\n" +
      "- Syncs Pulumi state with actual cloud resources\n" +
      "- May delete resources from state if not found\n" +
      "- May update state with drift from cloud\n\n" +
      "Run without -y first to review detected changes",
  },
  {
    name: "pulumi-cancel",
    re: /pulumi\b.*?\bcancel\b/,
    severity: "high",
    reason:
      "pulumi cancel terminates an in-progress update, which may leave resources in inconsistent state.",
    explanation:
      "pulumi cancel stops in-progress operations:\n\n" +
      "- Terminates currently running update/destroy\n" +
      "- Resources may be left in inconsistent state\n" +
      "- Some resources created, others not\n" +
      "- May require manual cleanup\n\n" +
      "Use only when operation is stuck/hung",
  },
];

/**
 * Infrastructure pack — terraform + ansible + pulumi merged.
 *
 * Sources: DCG `src/packs/infrastructure/{terraform,ansible,pulumi}.rs`.
 * Keywords are the UNION of the three DCG keyword sets (dedup preserving
 * order): terraform[terraform,destroy,taint,state] + ansible[ansible,playbook]
 * + pulumi[pulumi,destroy,state] => [terraform,destroy,taint,state,ansible,
 * playbook,pulumi].
 */
export const infrastructurePack: Pack = {
  id: "infrastructure",
  name: "Infrastructure",
  description:
    "Protects against destructive Infrastructure-as-Code operations across " +
    "Terraform, Ansible, and Pulumi",
  keywords: [
    "terraform",
    "destroy",
    "taint",
    "state",
    "ansible",
    "playbook",
    "pulumi",
  ],
  safePatterns: [...terraformSafe, ...ansibleSafe, ...pulumiSafe],
  destructivePatterns: [
    ...terraformDestructive,
    ...ansibleDestructive,
    ...pulumiDestructive,
  ],
};
