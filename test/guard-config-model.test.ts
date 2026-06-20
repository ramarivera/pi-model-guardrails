// loadGuardConfig — modelWhitelist/modelBlacklist are array-validated at load
// (gemini PR review): a misconfigured non-array value must not reach
// shouldGuardrailModel and crash on `.includes()`.

import assert from "node:assert/strict";
import { mkdir, mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { loadGuardConfig } from "../src/config.ts";

async function loadWith(model: unknown): Promise<{
  modelWhitelist?: string[];
  modelBlacklist?: string[];
}> {
  const dir = await mkdtemp(join(tmpdir(), "pi-guardrails-gm-"));
  await mkdir(join(dir, ".pi"));
  await writeFile(
    join(dir, ".pi/guardrails.json"),
    JSON.stringify({ modelWhitelist: model, modelBlacklist: model }),
    "utf8",
  );
  return loadGuardConfig(dir, { globalConfigPath: false });
}

test("loadGuardConfig: a valid string array is kept", async () => {
  const c = await loadWith(["glm-5.2", "gpt-5"]);
  assert.deepEqual(c.modelWhitelist, ["glm-5.2", "gpt-5"]);
  assert.deepEqual(c.modelBlacklist, ["glm-5.2", "gpt-5"]);
});

test("loadGuardConfig: a non-array (string/number/object) becomes undefined", async () => {
  for (const bad of ["glm-5.2", 42, { a: 1 }, true]) {
    const c = await loadWith(bad);
    assert.equal(
      c.modelWhitelist,
      undefined,
      `whitelist for ${JSON.stringify(bad)}`,
    );
    assert.equal(
      c.modelBlacklist,
      undefined,
      `blacklist for ${JSON.stringify(bad)}`,
    );
  }
});

test("loadGuardConfig: non-string array elements are filtered out", async () => {
  const c = await loadWith(["glm-5.2", 7, null, "gpt-5", { x: 1 }]);
  assert.deepEqual(c.modelWhitelist, ["glm-5.2", "gpt-5"]);
});
