// Golden corpus for the containers pack (merged docker + compose + podman),
// ported from DCG's own `#[test]` blocks in
// `src/packs/containers/{docker,compose,podman}.rs` (mod tests). Each case
// mirrors a DCG assertion:
//   assert_blocks / assert_blocks_with_severity -> a deny/warn decision
//   assert_allows / matches_safe(false)         -> allowed (safe/no kw)
//
// Exercises the real engine: buildRegistry([containersPack]) + evaluateCommand.
//
// NOTE on rule names: two DCG rule names collided across the three sub-packs
// and were disambiguated in the merge to keep ids unique (regexes unchanged):
//   compose `rm-force` -> "rm-force-compose"
//   podman  system-prune/volume-prune/image-prune/container-prune/rm-force/
//           rmi-force/volume-rm -> "podman-"-prefixed
// These tests assert the merged (TS) rule names.

import assert from "node:assert/strict";
import test from "node:test";
import { evaluateCommand } from "../src/engine/evaluate.ts";
import { containersPack } from "../src/engine/packs/containers.ts";
import { buildRegistry } from "../src/engine/registry.ts";
import type { Severity } from "../src/engine/types.ts";

const registry = buildRegistry([containersPack]);

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
// containers.docker (DCG docker.rs::tests)
// ---------------------------------------------------------------------------

test("docker: global flags do not bypass (docker_patterns_match_with_global_flags)", () => {
  assertBlocks(
    "docker --context prod volume rm critical-vol",
    undefined,
    "volume-rm",
  );
  assertBlocks(
    "docker --host ssh://prod-host system prune --all",
    undefined,
    "system-prune",
  );
  assertBlocks(
    "docker --config /tmp/dc --context prod rm -f prod-db",
    undefined,
    "rm-force",
  );
  assertBlocks(
    "docker --log-level debug --context prod image prune --all",
    undefined,
    "image-prune",
  );
});

test("docker: rm -f force forms block, plain rm allowed (test_rm_force)", () => {
  for (const cmd of [
    "docker rm -f container",
    "docker rm --force container",
    "docker rm -vf container",
    "docker rm -fv container",
  ]) {
    assertBlocks(cmd, "high", "rm-force");
  }
  assertAllows("docker rm container");
});

test("docker: rmi -f force forms block, plain rmi allowed (test_rmi_force)", () => {
  for (const cmd of [
    "docker rmi -f image",
    "docker rmi --force image",
    "docker rmi -nf image",
  ]) {
    assertBlocks(cmd, "high", "rmi-force");
  }
  assertAllows("docker rmi image");
});

test("docker: container literally named a safe subcommand still blocks", () => {
  assertBlocks("docker rm -f ps", "high", "rm-force");
  assertBlocks("docker rm --force logs", "high", "rm-force");
  assertBlocks("docker rmi -f build", "high", "rmi-force");
});

test("docker: safe subcommand inside container name still blocks", () => {
  assertBlocks("docker rm -f ps-container", "high", "rm-force");
  assertBlocks("docker rmi -f build-server-img", "high", "rmi-force");
  assertBlocks("docker volume rm logs-archive", "high", "volume-rm");
  // Bare subcommands still allow.
  assertAllows("docker ps");
  assertAllows("docker logs mycontainer");
  assertAllows("docker build -t app .");
});

test("docker: stop/kill $(...) blocks (nested ps does not short-circuit)", () => {
  assertBlocks("docker stop $(docker ps -q)", "high", "stop-all");
  assertBlocks("docker kill $(docker ps -aq)", "high", "stop-all");
});

test("docker: blocks each destructive pattern + severity", () => {
  assertBlocks("docker system prune", "high", "system-prune");
  assertBlocks("docker system prune --all", "high", "system-prune");
  assertBlocks("docker volume prune", "high", "volume-prune");
  assertBlocks("docker network prune", "high", "network-prune");
  assertBlocks("docker image prune", "medium", "image-prune");
  assertBlocks("docker container prune", "medium", "container-prune");
  assertBlocks("docker volume rm my-volume", "high", "volume-rm");
});

test("docker: all safe patterns allow (docker_all_safe_patterns_match)", () => {
  for (const cmd of [
    "docker ps",
    "docker ps -a",
    "docker logs mycontainer",
    "docker images",
    "docker inspect mycontainer",
    "docker build -t app .",
    "docker pull nginx:latest",
    "docker run --rm hello-world",
    "docker exec -it container bash",
    "docker stats",
  ]) {
    assertAllows(cmd);
  }
});

test("docker: unrelated commands no match (docker_unrelated_commands_no_match)", () => {
  assertAllows("ls -la");
  assertAllows("git status");
});

// ---------------------------------------------------------------------------
// containers.compose (DCG compose.rs::tests)
// ---------------------------------------------------------------------------

test("compose: down -v / --volumes blocks (compose_blocks_down_with_volumes)", () => {
  for (const cmd of [
    "docker-compose down -v",
    "docker-compose down --volumes",
    "docker compose down -v",
    "docker compose down --volumes",
  ]) {
    assertBlocks(cmd, "critical", "down-volumes");
  }
});

test("compose: down --rmi all blocks (compose_blocks_down_rmi_all)", () => {
  assertBlocks("docker-compose down --rmi all", "high", "down-rmi-all");
  assertBlocks("docker compose down --rmi all", "high", "down-rmi-all");
});

test("compose: rm -v / -f blocks (severity)", () => {
  assertBlocks("docker-compose rm -v", "high", "rm-volumes");
  assertBlocks("docker compose rm --volumes", "high", "rm-volumes");
  assertBlocks("docker-compose rm -f", "medium", "rm-force-compose");
  assertBlocks("docker compose rm --force", "medium", "rm-force-compose");
});

test("compose: safe patterns + down-without-volumes allowed", () => {
  for (const cmd of [
    "docker-compose config",
    "docker compose config",
    "docker-compose ps",
    "docker-compose logs",
    "docker-compose up",
    "docker compose up -d",
    "docker-compose build",
    "docker compose pull",
    "docker-compose down",
    "docker compose down",
  ]) {
    assertAllows(cmd);
  }
});

// ---------------------------------------------------------------------------
// containers.podman (DCG podman.rs::tests)
// ---------------------------------------------------------------------------

test("podman: global flags do not bypass (podman_patterns_match_with_global_flags)", () => {
  assertBlocks(
    "podman --remote --connection prod volume rm critical-vol",
    undefined,
    "podman-volume-rm",
  );
  assertBlocks(
    "podman --url tcp://prod:8080 system prune --all",
    undefined,
    "podman-system-prune",
  );
  assertBlocks(
    "podman --log-level debug --connection prod rm -f prod-db",
    undefined,
    "podman-rm-force",
  );
});

test("podman: rm -f / rmi -f block, plain allowed", () => {
  for (const cmd of [
    "podman rm -f container",
    "podman rm --force container",
    "podman rm -af",
    "podman rm -vf container",
    "podman rm -fv container",
  ]) {
    assertBlocks(cmd, "high", "podman-rm-force");
  }
  assertAllows("podman rm container");

  for (const cmd of [
    "podman rmi -f image",
    "podman rmi --force image",
    "podman rmi -nf image",
  ]) {
    assertBlocks(cmd, "high", "podman-rmi-force");
  }
  assertAllows("podman rmi image");
});

test("podman: blocks each destructive pattern + severity", () => {
  assertBlocks("podman system prune", "high", "podman-system-prune");
  assertBlocks("podman system prune -a", "high", "podman-system-prune");
  assertBlocks("podman volume prune", "critical", "podman-volume-prune");
  assertBlocks("podman pod prune", "medium", "pod-prune");
  assertBlocks("podman image prune", "medium", "podman-image-prune");
  assertBlocks("podman container prune", "medium", "podman-container-prune");
  assertBlocks("podman volume rm data-vol", "high", "podman-volume-rm");
});

test("podman: all safe patterns allow (podman_all_safe_patterns_match)", () => {
  for (const cmd of [
    "podman ps",
    "podman ps -a",
    "podman images",
    "podman logs mycontainer",
    "podman inspect mycontainer",
    "podman build -t app .",
    "podman pull nginx:latest",
    "podman run --rm hello-world",
    "podman exec -it container bash",
  ]) {
    assertAllows(cmd);
  }
});

test("podman: unrelated commands no match (podman_unrelated_commands_no_match)", () => {
  assertAllows("ls -la");
  assertAllows("git status");
});

// ---------------------------------------------------------------------------
// ReDoS regression (gemini PR review): the docker safe patterns used
// `(?:\s+[^;&|`$()]*)*$`, where `\s+` and `[^…]*` both match spaces under a
// `*` — catastrophic backtracking on a near-match that fails the end anchor.
// Fixed to `(?:\s+[^;&|`$()\s]+)*\s*$` (disjoint). This input would hang for
// seconds pre-fix; it must now resolve effectively instantly AND the normal
// allow-cases must be unchanged.
// ---------------------------------------------------------------------------

test("docker: safe pattern is ReDoS-resilient (direct regex timing)", () => {
  const docPs = containersPack.safePatterns.find((r) => r.name === "docker-ps");
  assert.ok(docPs, "docker-ps safe pattern exists");
  // A long run of spaces, then a class-EXCLUDED char ")" that defeats the `$`
  // anchor. The OLD `(?:\s+[^;&|`$()]*)*$` re-partitions the spaces ~2^40 ways
  // (hangs for many seconds); the fixed `(?:\s+[^;&|`$()\s]+)*\s*$` is linear.
  // Tested on the regex directly so segmentation/normalization can't mask it.
  const evil = `docker ps ${" ".repeat(40)})`;
  const start = Date.now();
  const matched = docPs.re.test(evil);
  const elapsed = Date.now() - start;
  assert.equal(matched, false, "the adversarial input is not a safe match");
  assert.ok(elapsed < 500, `docker-ps regex backtracked (${elapsed}ms)`);
});

test("docker: ReDoS fix preserves normal safe-form behavior", () => {
  for (const cmd of [
    "docker ps",
    "docker ps -a",
    "docker images --all",
    "docker --context prod ps",
    "docker build -t app .",
    "docker compose --dry-run up",
  ]) {
    assertAllows(cmd);
  }
});
