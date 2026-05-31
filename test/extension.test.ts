import assert from "node:assert/strict";
import test from "node:test";
import extension, { createExtension, extensionInfo } from "../src/index.ts";

test("factory exposes the extension identity", async () => {
  assert.equal(extensionInfo.name, "model-guardrails");

  const created = createExtension();
  assert.equal(created.name, "model-guardrails");
  assert.equal(extension.name, created.name);
  assert.deepEqual(await created.activate(), extensionInfo);
});
