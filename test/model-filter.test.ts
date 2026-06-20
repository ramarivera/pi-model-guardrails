import assert from "node:assert/strict";
import test from "node:test";
import { shouldGuardrailModel } from "../src/model-filter.ts";
import type { GuardrailsConfig } from "../src/types.ts";

const cfg = (partial: Partial<GuardrailsConfig>): GuardrailsConfig =>
  partial as unknown as GuardrailsConfig;

test("no whitelist/blacklist => guardrail all models", () => {
  assert.equal(shouldGuardrailModel("zai/glm-5.2", cfg({})), true);
});

test("undefined modelId => not guardrailed", () => {
  assert.equal(shouldGuardrailModel(undefined, cfg({})), false);
});

test("whitelist uses EXACT id (no loose substring, the v0.1.7 bug)", () => {
  const c = cfg({ modelWhitelist: ["glm-5.2"] });
  assert.equal(shouldGuardrailModel("glm-5.2", c), true);
  // v0.1.7's includes()-based match would have wrongly matched these:
  assert.equal(shouldGuardrailModel("glm-5.1", c), false);
  assert.equal(shouldGuardrailModel("glm-5.2-air", c), false);
  assert.equal(shouldGuardrailModel("zai/glm-5.2", c), false);
});

test("blacklist uses EXACT id and takes precedence", () => {
  const c = cfg({ modelBlacklist: ["gpt-5"] });
  assert.equal(shouldGuardrailModel("gpt-5", c), false);
  // would have been falsely blacklisted under v0.1.7 substring match:
  assert.equal(shouldGuardrailModel("gpt-5.2", c), true);
});

test("blacklist beats whitelist for the same exact id", () => {
  const c = cfg({ modelWhitelist: ["m"], modelBlacklist: ["m"] });
  assert.equal(shouldGuardrailModel("m", c), false);
});

test("misconfigured non-array lists do not crash (Array.isArray guard)", () => {
  // A bad config (string/object instead of array) must not throw on .includes();
  // a non-array list is treated as absent.
  for (const bad of ["glm-5.2", 42, { a: 1 }, true, null]) {
    const c = cfg({
      modelBlacklist: bad as never,
      modelWhitelist: bad as never,
    });
    assert.doesNotThrow(() => shouldGuardrailModel("glm-5.2", c));
    // both lists ignored => default "guardrail all".
    assert.equal(shouldGuardrailModel("glm-5.2", c), true);
  }
});
