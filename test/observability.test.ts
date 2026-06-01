import assert from "node:assert/strict";
import { mkdtemp, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { createTelemetry, resolveLogFile } from "../src/observability.ts";

test("telemetry writes Effect-backed JSONL events and spans", async () => {
  const dir = await mkdtemp(join(tmpdir(), "pi-guardrails-observe-"));
  const telemetry = createTelemetry(dir, {
    enabled: true,
    logFile: "logs/events.jsonl",
  });

  await telemetry.logEvent("config_loaded", { policyRuleCount: 1 });
  const result = await telemetry.runSpan(
    "Guardrails.tool_call",
    { toolName: "bash", command: "npx playwright test" },
    async () => "allowed-for-test",
  );

  assert.equal(result, "allowed-for-test");

  const logFile = join(dir, "logs", "events.jsonl");
  const events = (await readFile(logFile, "utf8"))
    .trim()
    .split("\n")
    .map((line) => JSON.parse(line));

  assert.equal(events.length, 3);
  assert.deepEqual(
    events.map((event) => event.kind),
    ["event", "span_start", "span_end"],
  );
  assert.equal(events[0].name, "config_loaded");
  assert.equal(events[1].name, "Guardrails.tool_call");
  assert.equal(events[2].name, "Guardrails.tool_call");
  assert.equal(events[1].traceId, telemetry.traceId);
  assert.equal(events[2].spanId, events[1].spanId);
  assert.equal(events[2].tags.toolName, "bash");
});

test("telemetry records span errors before rethrowing", async () => {
  const dir = await mkdtemp(join(tmpdir(), "pi-guardrails-observe-error-"));
  const telemetry = createTelemetry(dir, {
    enabled: true,
    logFile: "events.jsonl",
  });

  await assert.rejects(
    () =>
      telemetry.runSpan("Guardrails.analyze", undefined, async () => {
        throw new Error("analysis exploded");
      }),
    /analysis exploded/,
  );

  const events = (await readFile(join(dir, "events.jsonl"), "utf8"))
    .trim()
    .split("\n")
    .map((line) => JSON.parse(line));

  assert.deepEqual(
    events.map((event) => event.kind),
    ["span_start", "span_error"],
  );
  assert.equal(events[1].error.message, "analysis exploded");
});

test("relative telemetry paths resolve from cwd", () => {
  assert.equal(
    resolveLogFile("/tmp/example", ".pi/model-guardrails/events.jsonl"),
    "/tmp/example/.pi/model-guardrails/events.jsonl",
  );
  assert.equal(
    resolveLogFile("/tmp/example", "/tmp/absolute.jsonl"),
    "/tmp/absolute.jsonl",
  );
});
