import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import { readFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import extension, {
  extensionInfo,
} from "../../.pi/extensions/model-guardrails/index.ts";

test("e2e fixture imports the live local .pi extension shim", async () => {
  const settingsPath = path.join(
    process.cwd(),
    "e2e",
    ".pi",
    "agent",
    "settings.json",
  );
  assert.equal(existsSync(settingsPath), true);

  const settings = JSON.parse(await readFile(settingsPath, "utf8"));
  assert.deepEqual(settings.extensions, [
    "../../.pi/extensions/model-guardrails/index.ts",
  ]);
  assert.equal(typeof extension, "function");
  assert.equal(
    extensionInfo.description,
    "Opinionated model guardrails that detect instruction violations and course-correct",
  );
});
