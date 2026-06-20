// Kubernetes pack — protections for kubectl, Helm, and Kustomize.
//
// Faithful port of THREE DCG kubernetes sub-packs collapsed into one Pack
// module:
//   - DCG `src/packs/kubernetes/kubectl.rs`   (id "kubernetes.kubectl")
//   - DCG `src/packs/kubernetes/helm.rs`      (id "kubernetes.helm")
//   - DCG `src/packs/kubernetes/kustomize.rs` (id "kubernetes.kustomize")
// (https://github.com/Dicklesworthstone/destructive_command_guard).
//
// The task contract is "one TS module -> one exported Pack", so the three DCG
// packs are merged here under id "kubernetes", with safe/destructive patterns
// concatenated in DCG sub-pack order (kubectl -> helm -> kustomize).
// Declaration order is load-bearing (first-match-wins per text), and within
// each sub-pack the order matches DCG's create_*_patterns() exactly.
//
// JS RegExp porting notes (same rules as the committed core packs):
//  - No POSIX `[[:alnum:]]`, no inline `(?i)` (case-sensitive => no "i" flag),
//    no possessive quantifiers.
//  - DCG's dual `regex` + `fancy_regex` engine collapses to one JS RegExp:
//    the `(?!.*--dry-run(?:=(?:client|server))?(?:\s|$))` negative-lookahead
//    tails, the `(?=\s|$)` trailing anchors, and the `\|\s*kubectl` pipeline
//    anchors port verbatim.
//  - Rust raw strings preserve backslashes; in JS regex literals `/` => `\/`,
//    and the pipe `|` inside `\|` stays escaped.

import type { DestructiveRule, Pack, SafeRule, Suggestion } from "../types.ts";

const ALL = "all" as const;

function s(command: string, description: string): Suggestion {
  // DCG `PatternSuggestion::new` defaults to `Platform::All`.
  return { command, description, platform: ALL };
}

// ============================================================================
// Suggestion constants (DCG: const *_SUGGESTIONS in kubectl.rs).
// ============================================================================

const DELETE_NAMESPACE_SUGGESTIONS: Suggestion[] = [
  s("kubectl delete ns {ns} --dry-run=client -o yaml", "Preview what would be deleted without making changes"),
  s("kubectl get all -n {ns}", "See all resources in the namespace before deleting"),
  s("kubectl delete ns {ns} --grace-period=60", "Allow graceful shutdown with 60-second grace period"),
];

const DELETE_ALL_SUGGESTIONS: Suggestion[] = [
  s("kubectl delete {resource} --all --dry-run=client", "Preview what would be deleted without making changes"),
  s("kubectl rollout restart deployment/{name}", "Restart pods via deployment for graceful recreation"),
  s("kubectl delete {resource} {specific-name}", "Delete a specific resource instead of all"),
  s("kubectl delete {resource} -l app={label}", "Use label selectors for targeted deletion"),
];

const DELETE_PVC_SUGGESTIONS: Suggestion[] = [
  s("kubectl describe pvc {name}", "Check PVC status and usage before deleting"),
  s(
    "kubectl get pods -o json | jq '.items[] | select(.spec.volumes[]?.persistentVolumeClaim.claimName==\"{name}\")'",
    "Find pods currently using this PVC",
  ),
  s("kubectl delete pvc {name} --dry-run=client", "Preview deletion without making changes"),
  s(
    "kubectl get pv $(kubectl get pvc {name} -o jsonpath='{.spec.volumeName}') -o jsonpath='{.spec.persistentVolumeReclaimPolicy}'",
    "Check reclaim policy to understand data fate",
  ),
];

const DELETE_FORCE_SUGGESTIONS: Suggestion[] = [
  s("kubectl delete {resource} {name}", "Use default 30-second grace period for graceful shutdown"),
  s("kubectl delete {resource} {name} --grace-period=60", "Extended grace period for slower shutdown"),
  s("kubectl describe {resource} {name}", "Check resource status to understand why it's stuck"),
];

const APPLY_FORCE_SUGGESTIONS: Suggestion[] = [
  s("kubectl apply -f {file}", "Apply without --force for in-place updates"),
  s("kubectl diff -f {file}", "Preview what changes would be applied"),
  s("kubectl apply --server-side -f {file}", "Use server-side apply for safer field management"),
];

const DELETE_FROM_DIR_SUGGESTIONS: Suggestion[] = [
  s("kubectl delete -f {specific-file}", "Delete from a specific file instead of directory"),
  s("kubectl diff -f {directory}", "Preview what resources would be affected"),
  s("kubectl delete -f {directory} --dry-run=client", "Preview deletion without making changes"),
];

// ============================================================================
// Long explanations (DCG: the multi-line explanation strings).
// ============================================================================

const DELETE_NAMESPACE_EXPLANATION =
  "Deleting a namespace destroys EVERYTHING inside it:\n\n" +
  "- All deployments, pods, services\n" +
  "- All configmaps and secrets\n" +
  "- All persistent volume claims (data may be lost)\n" +
  "- All ingresses and network policies\n" +
  "- All RBAC resources scoped to the namespace\n\n" +
  "This is irreversible. Even if you recreate the namespace, all resources are gone.\n\n" +
  "Preview what would be deleted:\n  " +
  "kubectl get all -n <namespace>\n  " +
  "kubectl get pvc -n <namespace>\n\n" +
  "Safer approach:\n  " +
  "kubectl delete deployment <name> -n <namespace>  # Delete specific resources";

const DELETE_ALL_EXPLANATION =
  "The --all flag deletes EVERY resource of the specified type in the namespace.\n\n" +
  "For example:\n" +
  "- kubectl delete pods --all: Kills all pods (services go down)\n" +
  "- kubectl delete svc --all: Removes all services (networking breaks)\n" +
  "- kubectl delete pvc --all: May delete all persistent data\n\n" +
  "Always preview first:\n  " +
  "kubectl delete <resource> --all --dry-run=client\n\n" +
  "Safer alternative:\n  " +
  "kubectl delete <resource> -l app=myapp  # Use label selectors";

const DELETE_ALL_NAMESPACES_EXPLANATION =
  "The -A/--all-namespaces flag expands deletion to EVERY namespace in the cluster. " +
  "This can take down your entire cluster:\n\n" +
  "- Production, staging, and dev environments affected\n" +
  "- System namespaces (kube-system) may be impacted\n" +
  "- Cross-namespace resources and dependencies break\n\n" +
  "This is almost never what you want. Always specify a namespace:\n  " +
  "kubectl delete <resource> -n <namespace>\n\n" +
  "Preview cluster-wide resources:\n  " +
  "kubectl get <resource> -A";

const DRAIN_NODE_EXPLANATION =
  "kubectl drain evicts ALL pods from a node, typically for maintenance. " +
  "This can cause service disruption:\n\n" +
  "- All pods are evicted (respecting PodDisruptionBudgets)\n" +
  "- DaemonSet pods remain unless --ignore-daemonsets is used\n" +
  "- Pods with local storage fail unless --delete-emptydir-data is used\n" +
  "- Without replicas elsewhere, services go down\n\n" +
  "Before draining:\n  " +
  "kubectl get pods -o wide | grep <node>  # Check what's running\n  " +
  "kubectl get pdb -A                       # Check disruption budgets\n\n" +
  "Safer approach:\n  " +
  "kubectl cordon <node>  # Prevent new pods first, then drain gradually";

const CORDON_NODE_EXPLANATION =
  "kubectl cordon marks a node as unschedulable. Existing pods continue running, " +
  "but no new pods will be scheduled to this node.\n\n" +
  "Use cases:\n" +
  "- Preparing for maintenance\n" +
  "- Investigating node issues\n" +
  "- Gradual migration\n\n" +
  "To reverse:\n  " +
  "kubectl uncordon <node>\n\n" +
  "Check node status:\n  " +
  "kubectl get nodes\n  " +
  "kubectl describe node <node> | grep Taints";

const TAINT_NOEXECUTE_EXPLANATION =
  "A NoExecute taint immediately evicts pods that don't have a matching toleration. " +
  "This is more aggressive than NoSchedule:\n\n" +
  "- Existing pods are evicted (not just new scheduling blocked)\n" +
  "- Can cause immediate service disruption\n" +
  "- Pods may not have time for graceful shutdown\n\n" +
  "Check current taints:\n  " +
  "kubectl describe node <node> | grep Taints\n\n" +
  "Consider NoSchedule first:\n  " +
  "kubectl taint nodes <node> key=value:NoSchedule\n\n" +
  "Remove taint:\n  " +
  "kubectl taint nodes <node> key=value:NoExecute-";

const DELETE_WORKLOAD_EXPLANATION =
  "Deleting a workload terminates all its pods:\n\n" +
  "- Deployment: All replicas terminated, service goes down\n" +
  "- StatefulSet: Ordered shutdown, PVCs may be orphaned\n" +
  "- DaemonSet: Removed from all nodes\n" +
  "- ReplicaSet: Pods terminated (usually managed by Deployment)\n\n" +
  "Preview first:\n  " +
  "kubectl delete <type> <name> --dry-run=client\n  " +
  "kubectl get pods -l app=<name>  # Check affected pods\n\n" +
  "Consider scaling down first:\n  " +
  "kubectl scale deployment <name> --replicas=0";

const DELETE_PVC_EXPLANATION =
  "Deleting a PVC can cause permanent data loss depending on the PV's reclaimPolicy:\n\n" +
  "- Delete: Underlying storage is deleted (DATA LOST)\n" +
  "- Retain: PV is kept but becomes 'Released' (manual recovery needed)\n" +
  "- Recycle: Deprecated, data scrubbed\n\n" +
  "Check the reclaim policy:\n  " +
  "kubectl get pv <pv-name> -o jsonpath='{.spec.persistentVolumeReclaimPolicy}'\n\n" +
  "Backup first:\n  " +
  "kubectl exec <pod> -- tar czf - /data > backup.tar.gz\n\n" +
  "Preview:\n  " +
  "kubectl delete pvc <name> --dry-run=client";

const DELETE_PV_EXPLANATION =
  "Deleting a PersistentVolume can permanently destroy the underlying storage:\n\n" +
  "- Cloud disks (EBS, GCE PD, Azure Disk) may be deleted\n" +
  "- NFS mounts become orphaned\n" +
  "- Local storage data is lost\n\n" +
  "Even with Retain policy, deleting the PV may trigger storage cleanup.\n\n" +
  "Check what's using the PV:\n  " +
  "kubectl get pvc -A | grep <pv-name>\n\n" +
  "Check storage class policy:\n  " +
  "kubectl get storageclass <class> -o yaml\n\n" +
  "Preview:\n  " +
  "kubectl delete pv <name> --dry-run=client";

const SCALE_TO_ZERO_EXPLANATION =
  "Scaling to zero replicas terminates ALL pods for the workload:\n\n" +
  "- Service becomes unavailable\n" +
  "- Endpoints are removed from Service\n" +
  "- In-flight requests are dropped\n" +
  "- StatefulSets: Ordered shutdown from highest ordinal\n\n" +
  "This is often intentional but can cause outages if done accidentally.\n\n" +
  "Check current replicas:\n  " +
  "kubectl get deployment <name> -o jsonpath='{.spec.replicas}'\n\n" +
  "To restore:\n  " +
  "kubectl scale deployment <name> --replicas=<N>";

const DELETE_FORCE_EXPLANATION =
  "Force deletion with zero grace period is dangerous:\n\n" +
  "- Pods are killed immediately (no SIGTERM, just gone)\n" +
  "- In-flight requests fail\n" +
  "- Data corruption risk if writes in progress\n" +
  "- Finalizers may be skipped (resource leak)\n\n" +
  "Kubernetes warns against this. Use only for stuck pods that won't terminate.\n\n" +
  "Try graceful deletion first:\n  " +
  "kubectl delete pod <name>                    # Default 30s grace\n  " +
  "kubectl delete pod <name> --grace-period=60  # Extended grace\n\n" +
  "Check why pod is stuck:\n  " +
  "kubectl describe pod <name> | grep -A5 Status";

const APPLY_FORCE_EXPLANATION =
  "kubectl apply --force deletes the resource and recreates it from the manifest. " +
  "This causes:\n\n" +
  "- Downtime as pods are terminated before new ones start\n" +
  "- Loss of any runtime modifications\n" +
  "- Potential data loss for stateful workloads\n" +
  "- Disruption to in-flight requests\n\n" +
  "Use this only when you cannot update resources normally due to immutable field changes.\n\n" +
  "Preview changes first:\n  " +
  "kubectl diff -f <file>\n\n" +
  "Try server-side apply for safer updates:\n  " +
  "kubectl apply --server-side -f <file>";

const DELETE_FROM_DIR_EXPLANATION =
  "Deleting from a directory or recursively removes ALL resources defined in those files:\n\n" +
  "- Multiple deployments, services, configmaps deleted at once\n" +
  "- Hard to recover if wrong directory\n" +
  "- No confirmation or preview by default\n\n" +
  "Always preview first:\n  " +
  "kubectl diff -f <directory>\n  " +
  "ls -la <directory>/*.yaml\n\n" +
  "Delete specific files instead:\n  " +
  "kubectl delete -f <specific-file.yaml>";

const HELM_UNINSTALL_EXPLANATION =
  "helm uninstall deletes the release and ALL Kubernetes resources created by it:\n\n" +
  "- Deployments, services, and pods are terminated\n" +
  "- ConfigMaps and secrets are deleted\n" +
  "- Persistent volume claims may be deleted (depends on chart)\n" +
  "- Release history is purged (no rollback possible)\n\n" +
  "Safer alternatives:\n" +
  "- helm uninstall <release> --dry-run: Preview what will be deleted\n" +
  "- helm status <release>: Review current release state\n" +
  "- helm get all <release>: See all resources managed by release\n" +
  "- helm get manifest <release>: Get the actual Kubernetes manifests";

const HELM_ROLLBACK_EXPLANATION =
  "helm rollback reverts the release to a previous revision. This can cause unexpected " +
  "behavior if the previous version differs significantly:\n\n" +
  "- Pod configurations are reverted (may break dependencies)\n" +
  "- ConfigMaps and secrets are rolled back\n" +
  "- Database migrations are NOT automatically undone\n" +
  "- Downtime may occur during the transition\n\n" +
  "Safer alternatives:\n" +
  "- helm rollback <release> <revision> --dry-run: Preview changes\n" +
  "- helm history <release>: Review available revisions\n" +
  "- helm diff rollback <release> <revision>: Compare changes (requires diff plugin)";

const HELM_UPGRADE_FORCE_EXPLANATION =
  "The --force flag causes Helm to delete and recreate resources instead of updating " +
  "them in place. This can cause service disruption:\n\n" +
  "- Pods are terminated and recreated (downtime between)\n" +
  "- Persistent volume claims may be deleted and recreated\n" +
  "- In-flight requests are dropped during recreation\n" +
  "- Service IP addresses may change\n\n" +
  "Safer alternatives:\n" +
  "- Remove --force to use rolling updates\n" +
  "- helm upgrade --dry-run --debug: Preview changes\n" +
  "- helm diff upgrade: Compare before upgrading (requires diff plugin)";

const HELM_UPGRADE_RESET_VALUES_EXPLANATION =
  "The --reset-values flag discards all values from previous releases, using only " +
  "chart defaults and explicitly provided values. This can unexpectedly change:\n\n" +
  "- Resource limits and replica counts\n" +
  "- Database connection strings and credentials\n" +
  "- Feature flags and environment variables\n" +
  "- Any customization from previous 'helm upgrade' commands\n\n" +
  "Safer alternatives:\n" +
  "- helm get values <release>: Review current values first\n" +
  "- helm upgrade --reuse-values: Keep existing values (default)\n" +
  "- helm upgrade -f values.yaml: Explicitly set all needed values";

const KUSTOMIZE_DELETE_EXPLANATION =
  "Piping kustomize build to kubectl delete removes ALL resources defined in the " +
  "kustomization directory. This can delete entire applications:\n\n" +
  "- Every resource in kustomization.yaml and its bases is deleted\n" +
  "- Deployments, services, configmaps, secrets all removed\n" +
  "- Overlays may include resources you didn't expect\n" +
  "- No confirmation or preview by default\n\n" +
  "Safer alternatives:\n" +
  "- kustomize build <dir>: Review manifests first\n" +
  "- kustomize build <dir> | kubectl delete --dry-run=client -f -: Preview\n" +
  "- kustomize build <dir> | kubectl diff -f -: Compare with cluster state";

const KUBECTL_KUSTOMIZE_DELETE_EXPLANATION =
  "Piping kubectl kustomize to kubectl delete removes ALL resources defined in the " +
  "kustomization directory. This is equivalent to kustomize build | kubectl delete:\n\n" +
  "- Entire application stack can be deleted\n" +
  "- Base and overlay resources are all affected\n" +
  "- Includes resources from remote URLs if referenced\n" +
  "- Order of deletion may cause cascading failures\n\n" +
  "Safer alternatives:\n" +
  "- kubectl kustomize <dir>: Review manifests first\n" +
  "- kubectl delete --dry-run=client -k <dir>: Preview deletion\n" +
  "- kubectl diff -k <dir>: Compare with cluster state";

const KUBECTL_DELETE_K_EXPLANATION =
  "kubectl delete -k removes all resources defined in a kustomization directory. " +
  "This is a convenient but dangerous shorthand:\n\n" +
  "- All resources in kustomization.yaml are deleted\n" +
  "- Includes base resources and all overlays\n" +
  "- May include namespaces, PVCs, and other critical resources\n" +
  "- No confirmation prompt by default\n\n" +
  "Safer alternatives:\n" +
  "- kubectl delete -k <dir> --dry-run=client: Preview what will be deleted\n" +
  "- kubectl kustomize <dir>: Review manifests before deleting\n" +
  "- kubectl get -k <dir>: List resources that would be affected";

// ---------------------------------------------------------------------------
// Safe patterns (allowed) — DCG kubectl -> helm -> kustomize
// `create_safe_patterns()`, in declaration order.
// ---------------------------------------------------------------------------

const safePatterns: SafeRule[] = [
  // ===== kubernetes.kubectl safe patterns =====
  { name: "kubectl-get", re: /kubectl\b(?:\s+--?\S+(?:\s+\S+)?)*\s+get(?=\s|$)/ },
  { name: "kubectl-describe", re: /kubectl\b(?:\s+--?\S+(?:\s+\S+)?)*\s+describe(?=\s|$)/ },
  { name: "kubectl-logs", re: /kubectl\b(?:\s+--?\S+(?:\s+\S+)?)*\s+logs(?=\s|$)/ },
  { name: "kubectl-dry-run", re: /kubectl\b.*--dry-run(?:=(?:client|server))?(?:\s|$)/ },
  { name: "kubectl-diff", re: /kubectl\b(?:\s+--?\S+(?:\s+\S+)?)*\s+diff(?=\s|$)/ },
  { name: "kubectl-explain", re: /kubectl\b(?:\s+--?\S+(?:\s+\S+)?)*\s+explain(?=\s|$)/ },
  { name: "kubectl-top", re: /kubectl\b(?:\s+--?\S+(?:\s+\S+)?)*\s+top(?=\s|$)/ },
  { name: "kubectl-config", re: /kubectl\b(?:\s+--?\S+(?:\s+\S+)?)*\s+config(?=\s|$)/ },
  { name: "kubectl-api", re: /kubectl\b(?:\s+--?\S+(?:\s+\S+)?)*\s+api-(?:resources|versions)(?=\s|$)/ },
  { name: "kubectl-version", re: /kubectl\b(?:\s+--?\S+(?:\s+\S+)?)*\s+version(?=\s|$)/ },

  // ===== kubernetes.helm safe patterns =====
  { name: "helm-list", re: /helm\b(?:\s+--?\S+(?:\s+\S+)?)*\s+list(?=\s|$)/ },
  { name: "helm-status", re: /helm\b(?:\s+--?\S+(?:\s+\S+)?)*\s+status(?=\s|$)/ },
  { name: "helm-history", re: /helm\b(?:\s+--?\S+(?:\s+\S+)?)*\s+history(?=\s|$)/ },
  { name: "helm-show", re: /helm\b(?:\s+--?\S+(?:\s+\S+)?)*\s+show(?=\s|$)/ },
  { name: "helm-inspect", re: /helm\b(?:\s+--?\S+(?:\s+\S+)?)*\s+inspect(?=\s|$)/ },
  { name: "helm-get", re: /helm\b(?:\s+--?\S+(?:\s+\S+)?)*\s+get(?=\s|$)/ },
  { name: "helm-search", re: /helm\b(?:\s+--?\S+(?:\s+\S+)?)*\s+search(?=\s|$)/ },
  { name: "helm-repo", re: /helm\b(?:\s+--?\S+(?:\s+\S+)?)*\s+repo(?=\s|$)/ },
  { name: "helm-dry-run", re: /helm\b.*--dry-run(?:=(?:true|client|server))?(?:\s|$)/ },
  { name: "helm-template", re: /helm\b(?:\s+--?\S+(?:\s+\S+)?)*\s+template(?=\s|$)/ },
  { name: "helm-lint", re: /helm\b(?:\s+--?\S+(?:\s+\S+)?)*\s+lint(?=\s|$)/ },
  { name: "helm-diff", re: /helm\b(?:\s+--?\S+(?:\s+\S+)?)*\s+diff(?=\s|$)/ },

  // ===== kubernetes.kustomize safe patterns =====
  { name: "kustomize-build", re: /kustomize\b(?:\s+--?\S+(?:\s+\S+)?)*\s+build\b(?!.*\|)/ },
  { name: "kubectl-kustomize", re: /kubectl\b(?:\s+--?\S+(?:\s+\S+)?)*\s+kustomize\b(?!.*\|)/ },
  { name: "kustomize-diff", re: /kustomize\b.*?\bbuild\s+.*\|\s*kubectl\b.*?\s+diff\b/ },
  {
    name: "kustomize-dry-run",
    re: /kustomize\b.*?\bbuild\s+.*\|\s*kubectl\b.*--dry-run(?:=(?:client|server))?(?:\s|$)/,
  },
];

// ---------------------------------------------------------------------------
// Destructive patterns (blocked) — DCG kubectl -> helm -> kustomize
// `create_destructive_patterns()`, in declaration order (first-match-wins).
// ---------------------------------------------------------------------------

const destructivePatterns: DestructiveRule[] = [
  // ===== kubernetes.kubectl destructive patterns =====
  {
    name: "delete-namespace",
    re: /kubectl\b.*?\bdelete\s+(?:namespace|ns)\b/,
    severity: "critical",
    reason:
      "kubectl delete namespace removes the entire namespace and ALL resources within it.",
    explanation: DELETE_NAMESPACE_EXPLANATION,
    suggestions: DELETE_NAMESPACE_SUGGESTIONS,
  },
  {
    name: "delete-all",
    re: /kubectl\b.*?\bdelete\s+.*--all\b/,
    severity: "high",
    reason: "kubectl delete --all removes ALL resources of that type. Use --dry-run=client first.",
    explanation: DELETE_ALL_EXPLANATION,
    suggestions: DELETE_ALL_SUGGESTIONS,
  },
  {
    name: "delete-all-namespaces",
    re: /kubectl\b.*?\bdelete\s+.*(?:-A\b|--all-namespaces)/,
    severity: "critical",
    reason:
      "kubectl delete with -A/--all-namespaces affects ALL namespaces. Very dangerous!",
    explanation: DELETE_ALL_NAMESPACES_EXPLANATION,
  },
  {
    name: "drain-node",
    re: /kubectl\b.*?\bdrain\b/,
    severity: "high",
    reason: "kubectl drain evicts all pods from a node. Ensure proper pod disruption budgets.",
    explanation: DRAIN_NODE_EXPLANATION,
  },
  {
    name: "cordon-node",
    re: /kubectl\b.*?\bcordon\b/,
    severity: "medium",
    reason: "kubectl cordon marks a node unschedulable. Existing pods continue running.",
    explanation: CORDON_NODE_EXPLANATION,
  },
  {
    name: "taint-noexecute",
    re: /kubectl\b.*?\btaint\s+.*:NoExecute/,
    severity: "high",
    reason: "kubectl taint with NoExecute evicts existing pods that don't tolerate the taint.",
    explanation: TAINT_NOEXECUTE_EXPLANATION,
  },
  {
    name: "delete-workload",
    re: /kubectl\b.*?\bdelete\s+(?:deployment|statefulset|daemonset|replicaset)\b(?!.*--dry-run(?:=(?:client|server))?(?:\s|$))/,
    severity: "high",
    reason:
      "kubectl delete deployment/statefulset/daemonset removes the workload. Use --dry-run first.",
    explanation: DELETE_WORKLOAD_EXPLANATION,
  },
  {
    name: "delete-pvc",
    re: /kubectl\b.*?\bdelete\s+(?:pvc|persistentvolumeclaim)\b(?!.*--dry-run(?:=(?:client|server))?(?:\s|$))/,
    severity: "critical",
    reason: "kubectl delete pvc may permanently delete data if ReclaimPolicy is Delete.",
    explanation: DELETE_PVC_EXPLANATION,
    suggestions: DELETE_PVC_SUGGESTIONS,
  },
  {
    name: "delete-pv",
    re: /kubectl\b.*?\bdelete\s+(?:pv|persistentvolume)\b(?!.*--dry-run(?:=(?:client|server))?(?:\s|$))/,
    severity: "critical",
    reason: "kubectl delete pv may permanently delete the underlying storage.",
    explanation: DELETE_PV_EXPLANATION,
  },
  {
    name: "scale-to-zero",
    re: /kubectl\b.*?\bscale\s+.*--replicas=0/,
    severity: "high",
    reason: "kubectl scale --replicas=0 stops all pods for the workload.",
    explanation: SCALE_TO_ZERO_EXPLANATION,
  },
  {
    name: "delete-force",
    re: /kubectl\b.*?\bdelete\s+.*--force.*--grace-period=0|kubectl\b.*?\bdelete\s+.*--grace-period=0.*--force/,
    severity: "critical",
    reason:
      "kubectl delete --force --grace-period=0 immediately removes resources without graceful shutdown.",
    explanation: DELETE_FORCE_EXPLANATION,
    suggestions: DELETE_FORCE_SUGGESTIONS,
  },
  {
    name: "apply-force",
    re: /kubectl\b.*?\bapply\s+.*--force\b/,
    severity: "high",
    reason: "kubectl apply --force deletes and recreates resources, causing downtime.",
    explanation: APPLY_FORCE_EXPLANATION,
    suggestions: APPLY_FORCE_SUGGESTIONS,
  },
  {
    name: "delete-from-directory",
    re: /kubectl\b.*?\bdelete\s+-f\s+\.\s*$|kubectl\b.*?\bdelete\s+-f\s+\.\/|kubectl\b.*?\bdelete\s+--recursive\s+-f|kubectl\b.*?\bdelete\s+-f.*--recursive/,
    severity: "high",
    reason:
      "kubectl delete -f with directories or --recursive deletes many resources at once.",
    explanation: DELETE_FROM_DIR_EXPLANATION,
    suggestions: DELETE_FROM_DIR_SUGGESTIONS,
  },

  // ===== kubernetes.helm destructive patterns =====
  {
    name: "uninstall",
    re: /helm\b.*?\b(?:uninstall|delete)\b(?!.*--dry-run(?:=(?:true|client|server))?(?:\s|$))/,
    severity: "critical",
    reason: "helm uninstall removes the release and all its resources. Use --dry-run first.",
    explanation: HELM_UNINSTALL_EXPLANATION,
  },
  {
    name: "rollback",
    re: /helm\b.*?\brollback\b(?!.*--dry-run(?:=(?:true|client|server))?(?:\s|$))/,
    severity: "high",
    reason: "helm rollback reverts to a previous release. Use --dry-run to preview changes.",
    explanation: HELM_ROLLBACK_EXPLANATION,
  },
  {
    name: "upgrade-force",
    re: /helm\b.*?\bupgrade\s+.*--force/,
    severity: "high",
    reason: "helm upgrade --force deletes and recreates resources, causing downtime.",
    explanation: HELM_UPGRADE_FORCE_EXPLANATION,
  },
  {
    name: "upgrade-reset-values",
    re: /helm\b.*?\bupgrade\s+.*--reset-values/,
    severity: "high",
    reason: "helm upgrade --reset-values discards all previously set values.",
    explanation: HELM_UPGRADE_RESET_VALUES_EXPLANATION,
  },

  // ===== kubernetes.kustomize destructive patterns =====
  {
    name: "kustomize-delete",
    re: /kustomize\b.*?\bbuild\s+.*\|\s*kubectl\b(?!.*--dry-run(?:=(?:client|server))?(?:\s|$)).*?\bdelete/,
    severity: "critical",
    reason: "kustomize build | kubectl delete removes all resources in the kustomization.",
    explanation: KUSTOMIZE_DELETE_EXPLANATION,
  },
  {
    name: "kubectl-kustomize-delete",
    re: /kubectl\b.*?\bkustomize\s+.*\|\s*kubectl\b(?!.*--dry-run(?:=(?:client|server))?(?:\s|$)).*?\bdelete/,
    severity: "critical",
    reason: "kubectl kustomize | kubectl delete removes all resources in the kustomization.",
    explanation: KUBECTL_KUSTOMIZE_DELETE_EXPLANATION,
  },
  {
    name: "kubectl-delete-k",
    re: /kubectl\b.*?\bdelete\s+-k\b(?!.*--dry-run(?:=(?:client|server))?(?:\s|$))/,
    severity: "critical",
    reason:
      "kubectl delete -k removes all resources defined in the kustomization. Use --dry-run first.",
    explanation: KUBECTL_DELETE_K_EXPLANATION,
  },
];

/**
 * Kubernetes pack — merged DCG kubernetes.kubectl + kubernetes.helm +
 * kubernetes.kustomize. `force` is NOT set (DCG kubernetes packs are
 * config-gated, not floor packs).
 *
 * Keywords are the union of the three sub-packs' keyword arrays in sub-pack
 * order (kubectl -> helm -> kustomize). All rule names stay unique across the
 * three sub-packs (verified), so no renames were needed — `${packId}:${ruleName}`
 * is unique within this merged pack.
 *
 * Source: DCG `src/packs/kubernetes/{kubectl,helm,kustomize}.rs` (`create_pack`).
 */
export const kubernetesPack: Pack = {
  id: "kubernetes",
  name: "Kubernetes",
  description:
    "Protects against destructive Kubernetes operations: kubectl delete " +
    "namespace/--all/drain/force, Helm uninstall/rollback/upgrade --force, " +
    "and Kustomize-driven mass deletion",
  keywords: [
    // kubernetes.kubectl
    "kubectl",
    "delete",
    "drain",
    "cordon",
    "taint",
    // kubernetes.helm
    "helm",
    "uninstall",
    "rollback",
    // kubernetes.kustomize
    "kustomize",
  ],
  safePatterns,
  destructivePatterns,
};
