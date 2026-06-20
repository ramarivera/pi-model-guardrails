// Golden corpus for the kubernetes pack (merged kubectl + helm + kustomize),
// ported from DCG's own `#[test]` blocks in
// `src/packs/kubernetes/{kubectl,helm,kustomize}.rs` (mod tests). Each case
// mirrors a DCG assertion:
//   assert_blocks / assert_blocks_with_pattern / assert_blocks_with_severity
//     -> a deny/warn decision (+ rule + severity)
//   assert_allows / no_safe_match / is_none()
//     -> allowed (safe pattern, --dry-run override, or no keyword)
//
// Exercises the real engine: buildRegistry([kubernetesPack]) + evaluateCommand.
// All rule names are unique across the three sub-packs, so the merged TS names
// equal the DCG names verbatim.

import assert from "node:assert/strict";
import test from "node:test";
import { evaluateCommand } from "../src/engine/evaluate.ts";
import { kubernetesPack } from "../src/engine/packs/kubernetes.ts";
import { buildRegistry } from "../src/engine/registry.ts";
import type { Severity } from "../src/engine/types.ts";

const registry = buildRegistry([kubernetesPack]);

function check(cmd: string) {
  const d = evaluateCommand(cmd, registry);
  return d.decision === "allow" ? undefined : d;
}

function assertBlocks(cmd: string, sev?: Severity, rule?: string) {
  const d = check(cmd);
  assert.ok(d, `${cmd} must block`);
  if (sev) assert.equal(d.severity, sev, `${cmd} severity`);
  if (rule) assert.equal(d.ruleName, rule, `${cmd} rule`);
}

function assertAllows(cmd: string) {
  assert.equal(check(cmd), undefined, `${cmd} must be allowed`);
}

// ---------------------------------------------------------------------------
// kubernetes.kubectl (DCG kubectl.rs::tests)
// ---------------------------------------------------------------------------

test("kubectl: global flags do not bypass", () => {
  assertBlocks(
    "kubectl --context prod delete namespace critical",
    undefined,
    "delete-namespace",
  );
  assertBlocks(
    "kubectl --kubeconfig /tmp/prod.yaml delete deployment --all",
    undefined,
    "delete-all",
  );
  // delete-all fires before delete-all-namespaces (DCG first-match within pack).
  assertBlocks(
    "kubectl --context prod delete pods --all-namespaces -l app=legacy",
    undefined,
    "delete-all",
  );
  assertBlocks(
    "kubectl --context prod drain node-1 --ignore-daemonsets",
    undefined,
    "drain-node",
  );
  assertBlocks(
    "kubectl -n prod delete pod stuck-pod --force --grace-period=0",
    undefined,
    "delete-force",
  );
  assertBlocks(
    "kubectl --context prod delete pvc prod-db-data",
    undefined,
    "delete-pvc",
  );
  assertBlocks(
    "kubectl --context prod apply -f manifest.yaml --force",
    undefined,
    "apply-force",
  );
});

test("kubectl: safe positional reads allowed after global flags", () => {
  assertAllows("kubectl get pods");
  assertAllows("kubectl --context prod get pods");
  assertAllows("kubectl describe pod foo");
  assertAllows("kubectl logs deployment/foo");
  assertAllows("kubectl -n prod get pods");
  assertAllows("kubectl --context prod delete deployment foo --dry-run=client");
});

test("kubectl: safe subcommand inside resource name does not short-circuit", () => {
  assertBlocks("kubectl delete deployment get-handler");
  assertBlocks("kubectl delete statefulset describe-worker");
  assertBlocks("kubectl delete daemonset logs-archive");
  assertBlocks("kubectl delete pvc top-disk");
  // Bare subcommands still allow.
  assertAllows("kubectl get pods");
  assertAllows("kubectl describe pod foo");
  assertAllows("kubectl logs deployment/myapp");
});

test("kubectl: blocks each destructive pattern (kubectl_blocks_each_destructive_pattern)", () => {
  assertBlocks(
    "kubectl delete namespace production",
    undefined,
    "delete-namespace",
  );
  assertBlocks("kubectl delete ns staging", undefined, "delete-namespace");
  assertBlocks("kubectl delete pods --all", undefined, "delete-all");
  assertBlocks("kubectl delete pods -A", undefined, "delete-all-namespaces");
  assertBlocks("kubectl drain node-1", undefined, "drain-node");
  assertBlocks("kubectl cordon node-1", undefined, "cordon-node");
  assertBlocks(
    "kubectl taint nodes node-1 key=val:NoExecute",
    undefined,
    "taint-noexecute",
  );
  assertBlocks(
    "kubectl delete deployment web-api",
    undefined,
    "delete-workload",
  );
  assertBlocks(
    "kubectl delete statefulset db-cluster",
    undefined,
    "delete-workload",
  );
  assertBlocks("kubectl delete pvc data-volume", undefined, "delete-pvc");
  assertBlocks("kubectl delete pv my-volume", undefined, "delete-pv");
  assertBlocks(
    "kubectl scale deployment web --replicas=0",
    undefined,
    "scale-to-zero",
  );
  assertBlocks(
    "kubectl delete pod foo --force --grace-period=0",
    undefined,
    "delete-force",
  );
  assertBlocks(
    "kubectl apply -f deploy.yaml --force",
    undefined,
    "apply-force",
  );
  assertBlocks(
    "kubectl delete -f ./manifests/",
    undefined,
    "delete-from-directory",
  );
});

test("kubectl: blocks with correct severity (kubectl_blocks_with_correct_severity)", () => {
  assertBlocks("kubectl delete namespace production", "critical");
  assertBlocks("kubectl delete pods --all", "high");
  assertBlocks("kubectl delete pods -A", "critical");
  assertBlocks("kubectl drain node-1", "high");
  assertBlocks("kubectl cordon node-1", "medium");
  assertBlocks("kubectl taint nodes n1 k=v:NoExecute", "high");
  assertBlocks("kubectl delete pvc data-vol", "critical");
  assertBlocks("kubectl delete pv my-vol", "critical");
  assertBlocks("kubectl delete pod foo --force --grace-period=0", "critical");
});

test("kubectl: all safe patterns allow (kubectl_all_safe_patterns_match)", () => {
  for (const cmd of [
    "kubectl get pods",
    "kubectl describe pod foo",
    "kubectl logs foo",
    "kubectl delete pod foo --dry-run=client",
    "kubectl diff -f deploy.yaml",
    "kubectl explain deployment",
    "kubectl top nodes",
    "kubectl config view",
    "kubectl api-resources",
    "kubectl api-versions",
    "kubectl version",
  ]) {
    assertAllows(cmd);
  }
});

test("kubectl: --dry-run overrides destructive (kubectl_dry_run_overrides_destructive)", () => {
  assertAllows("kubectl delete namespace production --dry-run=client");
  assertAllows("kubectl delete deployment web --dry-run=server");
  assertAllows("kubectl delete deployment web --dry-run");
});

test("kubectl: --dry-run=none does NOT bypass (kubectl_dry_run_none_does_not_bypass)", () => {
  assertBlocks(
    "kubectl delete deployment web --dry-run=none",
    undefined,
    "delete-workload",
  );
  assertBlocks(
    "kubectl delete pvc data --dry-run=none",
    undefined,
    "delete-pvc",
  );
  assertBlocks("kubectl delete pv data --dry-run=none", undefined, "delete-pv");
});

test("kubectl: unrelated commands no match (kubectl_unrelated_commands_no_match)", () => {
  assertAllows("ls -la");
  assertAllows("git status");
});

// ---------------------------------------------------------------------------
// kubernetes.helm (DCG helm.rs::tests)
// ---------------------------------------------------------------------------

test("helm: global flags do not bypass (helm_patterns_match_with_global_flags)", () => {
  assertBlocks(
    "helm --kube-context prod uninstall critical-release",
    undefined,
    "uninstall",
  );
  assertBlocks(
    "helm --kubeconfig /tmp/prod.yaml delete prod-svc",
    undefined,
    "uninstall",
  );
  assertBlocks(
    "helm -n prod rollback critical-release 2",
    undefined,
    "rollback",
  );
  assertBlocks(
    "helm --kube-context prod upgrade prod-svc ./chart --force",
    undefined,
    "upgrade-force",
  );
});

test("helm: blocks each destructive pattern + severity", () => {
  assertBlocks("helm uninstall my-release", "critical", "uninstall");
  assertBlocks("helm delete my-release", "critical", "uninstall");
  assertBlocks("helm rollback my-release 3", "high", "rollback");
  assertBlocks(
    "helm upgrade my-release ./chart --force",
    "high",
    "upgrade-force",
  );
  assertBlocks(
    "helm upgrade my-release ./chart --reset-values",
    "high",
    "upgrade-reset-values",
  );
});

test("helm: all safe patterns allow (helm_all_safe_patterns_match)", () => {
  for (const cmd of [
    "helm list",
    "helm status my-release",
    "helm history my-release",
    "helm show chart stable/nginx",
    "helm inspect values stable/nginx",
    "helm get all my-release",
    "helm search repo nginx",
    "helm repo list",
    "helm template my-release ./chart",
    "helm lint ./chart",
    "helm diff upgrade my-release ./chart",
  ]) {
    assertAllows(cmd);
  }
});

test("helm: --dry-run overrides; false/none do not bypass", () => {
  assertAllows("helm uninstall my-release --dry-run");
  assertAllows("helm uninstall my-release --dry-run=true");
  assertAllows("helm rollback my-release 3 --dry-run");

  assertBlocks(
    "helm uninstall my-release --dry-run=false",
    undefined,
    "uninstall",
  );
  assertBlocks(
    "helm delete my-release --dry-run=false",
    undefined,
    "uninstall",
  );
  assertBlocks(
    "helm rollback my-release 3 --dry-run=false",
    undefined,
    "rollback",
  );
  assertBlocks(
    "helm uninstall my-release --dry-run=none",
    undefined,
    "uninstall",
  );
});

test("helm: unrelated commands no match (helm_unrelated_commands_no_match)", () => {
  assertAllows("ls -la");
  assertAllows("git status");
});

// ---------------------------------------------------------------------------
// kubernetes.kustomize (DCG kustomize.rs::tests)
// ---------------------------------------------------------------------------

test("kustomize: piped delete blocks (kustomize_blocks_piped_delete)", () => {
  assertBlocks(
    "kustomize build ./overlays/prod | kubectl delete -f -",
    "critical",
    "kustomize-delete",
  );
  assertBlocks(
    "kubectl kustomize ./overlays/prod | kubectl delete -f -",
    "critical",
    "kubectl-kustomize-delete",
  );
});

test("kustomize: kubectl delete -k blocks (kustomize_blocks_kubectl_delete_k)", () => {
  assertBlocks(
    "kubectl delete -k ./overlays/prod",
    "critical",
    "kubectl-delete-k",
  );
});

test("kustomize: build alone is safe (kustomize_safe_build_alone)", () => {
  assertAllows("kustomize build ./overlays/prod");
  assertAllows("kubectl kustomize ./overlays/prod");
});

test("kustomize: diff is safe (kustomize_safe_with_diff)", () => {
  assertAllows("kustomize build ./overlays/prod | kubectl diff -f -");
});

test("kustomize: dry-run forms safe (kustomize_safe_with_dry_run)", () => {
  assertAllows(
    "kustomize build ./overlays/prod | kubectl apply --dry-run=client -f -",
  );
  assertAllows(
    "kustomize build ./overlays/prod | kubectl delete --dry-run=client -f -",
  );
  assertAllows(
    "kubectl kustomize ./overlays/prod | kubectl delete --dry-run=server -f -",
  );
  assertAllows("kubectl delete -k ./prod --dry-run=client");
});

test("kustomize: --dry-run=none does NOT bypass delete (kustomize_dry_run_none_does_not_bypass_delete)", () => {
  assertBlocks(
    "kustomize build ./overlays/prod | kubectl delete --dry-run=none -f -",
    "critical",
    "kustomize-delete",
  );
  assertBlocks(
    "kubectl delete -k ./prod --dry-run=none",
    "critical",
    "kubectl-delete-k",
  );
});

test("kustomize: unrelated commands no match (kustomize_unrelated_commands_no_match)", () => {
  assertAllows("ls -la");
  assertAllows("git status");
});
