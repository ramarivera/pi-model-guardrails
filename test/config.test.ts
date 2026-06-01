import assert from "node:assert/strict";
import { mkdir, mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { loadConfig } from "../src/config.ts";

test("config defaults keep legacy pattern rules disabled and observability enabled", async () => {
  const dir = await mkdtemp(join(tmpdir(), "pi-guardrails-config-"));
  const config = await loadConfig(dir);

  assert.equal(config.patternRulesEnabled, false);
  assert.deepEqual(config.patternRules, []);
  assert.deepEqual(config.policyRules, []);
  assert.equal(config.observability?.enabled, true);
  assert.equal(
    config.observability?.logFile,
    ".pi/model-guardrails/events.jsonl",
  );
  assert.equal(config.observability?.logMessageUpdates, false);
});

test("config loads model-judged policy rules and observability overrides", async () => {
  const dir = await mkdtemp(join(tmpdir(), "pi-guardrails-config-"));
  await mkdir(join(dir, ".pi"));
  await writeFile(
    join(dir, ".pi/guardrails.json"),
    JSON.stringify({
      analysisModel: "analysis-model",
      toolGuards: { enabled: true },
      observability: {
        enabled: true,
        logFile: ".pi/custom-guardrails.jsonl",
        logMessageUpdates: true,
      },
      policyRules: [
        {
          id: "do-not-remove-features-to-fix",
          title: "Do not remove features to fix bugs",
          description: "Removing a feature is not a valid bug fix.",
          appliesWhen: "A feature fails due to missing configuration.",
          violation: "The assistant deletes the feature instead of diagnosing.",
          requiredBehavior: "Diagnose the missing dependency or ask for help.",
          severity: "error",
        },
      ],
    }),
    "utf8",
  );

  const config = await loadConfig(dir);

  assert.equal(config.policyRules.length, 1);
  assert.equal(config.policyRules[0]?.id, "do-not-remove-features-to-fix");
  assert.equal(config.patternRulesEnabled, false);
  assert.equal(config.observability?.logFile, ".pi/custom-guardrails.jsonl");
  assert.equal(config.observability?.logMessageUpdates, true);
});
