import assert from "node:assert/strict";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { createNoopTelemetry, createTelemetry } from "../src/observability.ts";

test("ring buffer records recent events and is readable back", async () => {
  const dir = await mkdtemp(join(tmpdir(), "pmg-obs-"));
  const t = createTelemetry(dir, { enabled: true, logFile: join(dir, "events.jsonl") });
  await t.logEvent("alpha", { x: 1 });
  await t.logEvent("beta");
  const spanResult = await t.runSpan("gamma", undefined, () => 42);
  assert.equal(spanResult, 42);

  const all = t.recent();
  // 2 logEvents + span_start + span_end = 4
  assert.ok(all.length >= 4, `expected >=4 events, got ${all.length}`);
  assert.ok(all.some((e) => e.name === "alpha" && e.kind === "event"));
  assert.ok(all.some((e) => e.name === "gamma" && e.kind === "span_end"));

  const last2 = t.recent(2);
  assert.equal(last2.length, 2);
  // recent() must be a copy, not the live buffer
  last2.pop();
  assert.equal(t.recent(2).length, 2);
});

test("noop telemetry recent() returns empty", () => {
  assert.deepEqual(createNoopTelemetry().recent(), []);
});

test("ring buffer is bounded (does not grow unboundedly)", async () => {
  const dir = await mkdtemp(join(tmpdir(), "pmg-obs-"));
  const t = createTelemetry(dir, { enabled: true, logFile: join(dir, "events.jsonl") });
  for (let i = 0; i < 1200; i++) await t.logEvent(`e${i}`);
  // RING_BUFFER_SIZE is 500; buffer must be capped at/below it.
  assert.ok(t.recent().length <= 500, `ring should be bounded, got ${t.recent().length}`);
  // and it keeps the MOST RECENT ones
  assert.equal(t.recent(1)[0]?.name, "e1199");
});
