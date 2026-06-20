// Golden corpus for the merged `infrastructure` pack (terraform + ansible +
// pulumi), ported from DCG's own `#[test]` blocks in:
//   - src/packs/infrastructure/terraform.rs
//   - src/packs/infrastructure/ansible.rs
//   - src/packs/infrastructure/pulumi.rs
//
// Each case mirrors a DCG assertion:
//   assert_blocks / assert_blocks_with_pattern / assert_blocks_with_severity
//     -> a destructive match (deny/warn/log) with the expected rule + severity
//   assert_allows / assert_no_match
//     -> the pack allows (safe pattern or no match)
//
// The test drives the REAL engine end-to-end: buildRegistry([pack]) +
// evaluateCommand, exercising normalization, the keyword prefilter, per-pack
// safe-then-destructive, and severity->mode mapping exactly as production does.
//
// NOTE on rule names: DCG keys terraform/pulumi both on bare `destroy`; the
// merged pack tool-prefixes them (`terraform-destroy`, `pulumi-destroy`), so the
// expected ruleName here is the prefixed form.

import assert from "node:assert/strict";
import test from "node:test";
import { evaluateCommand } from "../src/engine/evaluate.ts";
import { infrastructurePack } from "../src/engine/packs/infrastructure.ts";
import { buildRegistry } from "../src/engine/registry.ts";
import type { Severity } from "../src/engine/types.ts";

const registry = buildRegistry([infrastructurePack]);

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
// Terraform (DCG src/packs/infrastructure/terraform.rs mod tests)
// ---------------------------------------------------------------------------

test("terraform: blocks each destructive pattern", () => {
  blocks("terraform destroy", "terraform-destroy");
  blocks("terraform plan -destroy", "terraform-plan-destroy");
  blocks("terraform apply -auto-approve", "terraform-apply-auto-approve");
  blocks("terraform taint aws_instance.web", "terraform-taint");
  blocks("terraform state rm aws_s3_bucket.data", "terraform-state-rm");
  blocks(
    "terraform state mv aws_instance.a aws_instance.b",
    "terraform-state-mv",
  );
  blocks("terraform force-unlock 12345", "terraform-force-unlock");
  blocks("terraform workspace delete staging", "terraform-workspace-delete");
});

test("terraform: correct severities", () => {
  blocks("terraform destroy", "terraform-destroy", "critical");
  blocks("terraform plan -destroy", "terraform-plan-destroy", "medium");
  blocks(
    "terraform apply -auto-approve",
    "terraform-apply-auto-approve",
    "high",
  );
  blocks("terraform taint aws_instance.x", "terraform-taint", "high");
  blocks("terraform state rm aws_instance.x", "terraform-state-rm", "high");
  blocks("terraform state mv a b", "terraform-state-mv", "high");
  blocks("terraform force-unlock 123", "terraform-force-unlock", "high");
  blocks(
    "terraform workspace delete dev",
    "terraform-workspace-delete",
    "medium",
  );
});

test("terraform: -chdir global flag does not bypass", () => {
  blocks(
    "terraform -chdir=./environments/prod destroy -auto-approve",
    "terraform-destroy",
  );
  blocks(
    "terraform -chdir=./prod apply -auto-approve",
    "terraform-apply-auto-approve",
  );
  blocks(
    "terraform -chdir=./prod state rm aws_instance.important",
    "terraform-state-rm",
  );
  blocks(
    "terraform -chdir=./prod workspace delete prod-old",
    "terraform-workspace-delete",
  );
  blocks(
    "terraform -chdir=./prod force-unlock abc123",
    "terraform-force-unlock",
  );
});

test("terraform: safe patterns allow", () => {
  allows("terraform plan");
  allows("terraform -chdir=./prod plan");
  allows("terraform init");
  allows("terraform validate");
  allows("terraform fmt");
  allows("terraform show");
  allows("terraform output");
  allows("terraform state list");
  allows("terraform state show aws_instance.web");
  allows("terraform graph");
  allows("terraform version");
  allows("terraform providers");
});

test("terraform: destroy does not false-match a plan file name", () => {
  allows("terraform apply destroy-plan.tf");
});

test("terraform: subcommand-as-substring does not bypass", () => {
  blocks("terraform destroy plan-stack", "terraform-destroy");
  blocks("terraform destroy init-resources", "terraform-destroy");
});

// ---------------------------------------------------------------------------
// Ansible (DCG src/packs/infrastructure/ansible.rs mod tests)
// ---------------------------------------------------------------------------

test("ansible: safe dry-run / info modes allow", () => {
  allows("ansible --check -i inventory.ini all -m ping");
  allows("ansible-playbook --check deploy.yml");
  allows("ansible-playbook --check --diff site.yml");
  allows("ansible-playbook --list-hosts site.yml");
  allows("ansible-playbook --list-tasks site.yml");
  allows("ansible-playbook --syntax-check site.yml");
  allows("ansible-inventory --list");
  allows("ansible-doc file");
  allows("ansible-config dump");
});

test("ansible: blocks shell rm -rf", () => {
  blocks(
    "ansible all -m shell -a 'rm -rf /var/data'",
    "ansible-shell-rm-rf",
    "critical",
  );
  blocks(
    "ansible webservers -m command -a 'rm -rf /tmp/cache'",
    "ansible-shell-rm-rf",
    "critical",
  );
});

test("ansible: blocks shell reboot/shutdown/poweroff", () => {
  blocks("ansible all -m shell -a 'reboot'", "ansible-shell-reboot", "high");
  blocks(
    "ansible dbservers -m command -a 'shutdown -h now'",
    "ansible-shell-reboot",
    "high",
  );
  blocks("ansible all -m shell -a 'poweroff'", "ansible-shell-reboot", "high");
});

test("ansible: blocks playbook without --check or --limit", () => {
  blocks(
    "ansible-playbook -i production deploy.yml",
    "ansible-playbook-all-hosts",
    "high",
  );
});

test("ansible: allows playbook with --check or --limit", () => {
  allows("ansible-playbook --check -i production deploy.yml");
  allows("ansible-playbook --limit web1 -i production deploy.yml");
});

test("ansible: blocks extra-vars destructive keywords", () => {
  blocks(
    "ansible all -e 'action=delete' -m shell -a 'echo hi'",
    "ansible-extra-vars-delete",
    "medium",
  );
  blocks(
    'ansible all -e "state=destroy" -m debug',
    "ansible-extra-vars-delete",
    "medium",
  );
});

test("ansible: allows benign extra-vars", () => {
  allows("ansible all -e 'version=1.2.3' -m debug -a 'var=version'");
});

test("ansible: --check overrides destructive", () => {
  allows("ansible all --check -m shell -a 'rm -rf /data'");
});

// ---------------------------------------------------------------------------
// Pulumi (DCG src/packs/infrastructure/pulumi.rs mod tests)
// ---------------------------------------------------------------------------

test("pulumi: blocks each destructive pattern", () => {
  blocks("pulumi destroy", "pulumi-destroy");
  blocks("pulumi up -y", "pulumi-up-yes");
  blocks("pulumi up --yes", "pulumi-up-yes");
  blocks(
    "pulumi state delete urn:pulumi:prod::db::aws:rds/instance:Instance::main",
    "pulumi-state-delete",
  );
  blocks("pulumi stack rm prod-old", "pulumi-stack-rm");
  blocks("pulumi refresh -y", "pulumi-refresh-yes");
  blocks("pulumi refresh --yes", "pulumi-refresh-yes");
  blocks("pulumi cancel", "pulumi-cancel");
});

test("pulumi: correct severities", () => {
  blocks("pulumi destroy", "pulumi-destroy", "critical");
  blocks("pulumi up -y", "pulumi-up-yes", "high");
  blocks("pulumi state delete urn:foo", "pulumi-state-delete", "high");
  blocks("pulumi stack rm prod", "pulumi-stack-rm", "high");
  blocks("pulumi refresh -y", "pulumi-refresh-yes", "medium");
  blocks("pulumi cancel", "pulumi-cancel", "high");
});

test("pulumi: global flags do not bypass", () => {
  blocks("pulumi --cwd ./prod destroy", "pulumi-destroy");
  blocks("pulumi --non-interactive --cwd ./prod up -y", "pulumi-up-yes");
  blocks(
    "pulumi --cwd ./prod state delete urn:pulumi:prod::db::aws:rds/instance:Instance::main",
    "pulumi-state-delete",
  );
  blocks("pulumi --verbose --cwd ./prod stack rm prod-old", "pulumi-stack-rm");
});

test("pulumi: safe patterns allow", () => {
  allows("pulumi preview");
  allows("pulumi --cwd ./prod preview");
  allows("pulumi stack ls");
  allows("pulumi stack select prod");
  allows("pulumi stack init dev");
  allows("pulumi config");
  allows("pulumi whoami");
  allows("pulumi version");
  allows("pulumi about");
  allows("pulumi logs");
  allows("pulumi --non-interactive stack ls");
  allows("pulumi --verbose config get key");
});

test("pulumi: destroy does not false-match a stack name", () => {
  allows("pulumi up destroy-plan.yaml");
});

test("pulumi: subcommand-as-substring does not bypass", () => {
  blocks("pulumi destroy preview-stack", "pulumi-destroy");
  blocks("pulumi destroy config-backup", "pulumi-destroy");
});

// ---------------------------------------------------------------------------
// Cross-tool: unrelated commands no match
// ---------------------------------------------------------------------------

test("infrastructure: unrelated commands allow", () => {
  allows("ls -la");
  allows("git status");
  allows("echo terraform");
});
