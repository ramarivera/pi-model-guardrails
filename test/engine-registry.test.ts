// Tests for the registry keyword quick-reject (candidatePacks) and ordering.

import assert from "node:assert/strict";
import test from "node:test";
import { buildRegistry } from "../src/engine/registry.ts";
import type { Pack } from "../src/engine/types.ts";

function pack(id: string, keywords: string[]): Pack {
  return { id, name: id, keywords, safePatterns: [], destructivePatterns: [] };
}

test("candidatePacks substring quick-reject keeps packs whose keyword appears", () => {
  const git = pack("core.git", ["git"]);
  const docker = pack("containers.docker", ["docker"]);
  const reg = buildRegistry([git, docker]);

  assert.deepEqual(reg.candidatePacks("git reset --hard").map((p) => p.id), ["core.git"]);
  assert.deepEqual(reg.candidatePacks("docker system prune").map((p) => p.id), ["containers.docker"]);
  assert.deepEqual(reg.candidatePacks("ls -la").map((p) => p.id), []);
});

test("candidatePacks uses plain substring (DCG might_match), so .gitignore still hits 'git'", () => {
  // DCG Pack::might_match uses memmem substring (NOT word boundary). The
  // span-aware pack_aware_quick_reject is the boundary-aware layer; this
  // contract is the substring layer. Real safety is the pattern layer.
  const git = pack("core.git", ["git"]);
  const reg = buildRegistry([git]);
  assert.deepEqual(reg.candidatePacks("cat .gitignore").map((p) => p.id), ["core.git"]);
});

test("empty keyword list => pack always a candidate (no keywords = always check)", () => {
  const always = pack("safe.always", []);
  const reg = buildRegistry([always]);
  assert.deepEqual(reg.candidatePacks("anything at all").map((p) => p.id), ["safe.always"]);
  assert.deepEqual(reg.candidatePacks("").map((p) => p.id), ["safe.always"]);
});

test("multiword (whitespace) keyword matches with collapsed inter-token whitespace", () => {
  const p = pack("x.multi", ["docker system"]);
  const reg = buildRegistry([p]);
  assert.deepEqual(reg.candidatePacks("docker system prune").map((q) => q.id), ["x.multi"]);
  assert.deepEqual(reg.candidatePacks("docker   system prune").map((q) => q.id), ["x.multi"]);
  // No whitespace between => no match (parts must be separated).
  assert.deepEqual(reg.candidatePacks("dockersystem").map((q) => q.id), []);
});

test("declaration order is preserved in packs and candidatePacks output", () => {
  const a = pack("core.git", ["git"]);
  const b = pack("strict_git", ["git"]);
  const reg = buildRegistry([a, b]);
  assert.deepEqual(reg.packs.map((p) => p.id), ["core.git", "strict_git"]);
  assert.deepEqual(reg.candidatePacks("git reset --hard").map((p) => p.id), ["core.git", "strict_git"]);
});
