// e2e: load the extension through the LIVE .pi shim — the real Pi load path
//   .pi/extensions/model-guardrails/index.ts -> src/index.ts -> src/extension.ts
// — and verify the deterministic guard works end to end.
//
// This replaces the obsolete v0.1.7 tool-contract (agent-browser/playwright
// provider-mismatch) e2e: that feature was removed in the DCG rebuild. A
// project that wants provider-preference enforcement now expresses it as a
// policy constraint (policy.constraints[]), not a bespoke toolGuards block.

import assert from "node:assert/strict";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import extension from "../../.pi/extensions/model-guardrails/index.ts";

type Handler = (event: unknown, ctx: unknown) => unknown | Promise<unknown>;

interface Entry {
  type: string;
  customType: string;
  data: unknown;
}

interface FakePi {
  on(name: string, h: Handler): void;
  appendEntry(customType: string, data: unknown): void;
  handlers: Map<string, Handler[]>;
  entries: Entry[];
}

function createFakePi(): FakePi {
  const handlers = new Map<string, Handler[]>();
  const entries: Entry[] = [];
  return {
    handlers,
    entries,
    on(name, h) {
      const list = handlers.get(name) ?? [];
      list.push(h);
      handlers.set(name, list);
    },
    appendEntry(customType, data) {
      entries.push({ type: "custom", customType, data });
    },
  };
}

function createFakeCtx(cwd: string, entries: Entry[]) {
  return {
    cwd,
    hasUI: false,
    ui: { notify() {}, setStatus() {} },
    sessionManager: { getEntries: () => entries },
  };
}

async function fire(
  pi: FakePi,
  name: string,
  event: unknown,
  ctx: unknown,
): Promise<{ block?: boolean; reason?: string } | undefined> {
  const list = pi.handlers.get(name) ?? [];
  let result: { block?: boolean; reason?: string } | undefined;
  for (const h of list) {
    const r = (await h(event, ctx)) as
      | { block?: boolean; reason?: string }
      | undefined;
    if (r) result = r;
  }
  return result;
}

test("e2e: the extension loads through the live .pi shim", () => {
  assert.equal(typeof extension, "function");
});

test("e2e: a dangerous command is blocked via the shim-loaded extension", async () => {
  const pi = createFakePi();
  extension(pi as never);
  const cwd = await mkdtemp(join(tmpdir(), "pi-guardrails-e2e-"));
  const ctx = createFakeCtx(cwd, pi.entries);
  await fire(pi, "session_start", { reason: "test" }, ctx);

  const blocked = await fire(
    pi,
    "tool_call",
    { toolCallId: "call_e2e", toolName: "bash", input: { command: "git reset --hard HEAD~1" } },
    ctx,
  );
  assert.ok(blocked?.block, "git reset --hard is blocked end to end");
});

test("e2e: a clean command passes through the shim-loaded extension", async () => {
  // Fresh session — the block test above HALTs its session (HALTED blocks
  // everything, so a clean call there would also be held).
  const pi = createFakePi();
  extension(pi as never);
  const cwd = await mkdtemp(join(tmpdir(), "pi-guardrails-e2e-"));
  const ctx = createFakeCtx(cwd, pi.entries);
  await fire(pi, "session_start", { reason: "test" }, ctx);

  const allowed = await fire(
    pi,
    "tool_call",
    { toolCallId: "call_e2e", toolName: "bash", input: { command: "ls -la" } },
    ctx,
  );
  assert.ok(!allowed?.block, "a clean command passes through");
});

test("e2e: a newly-ported breadth pack blocks via the live registry", async () => {
  const pi = createFakePi();
  extension(pi as never);
  const cwd = await mkdtemp(join(tmpdir(), "pi-guardrails-e2e-"));
  const ctx = createFakeCtx(cwd, pi.entries);
  await fire(pi, "session_start", { reason: "test" }, ctx);

  // kubectl delete --all comes from the kubernetes pack wired into the registry.
  const blocked = await fire(
    pi,
    "tool_call",
    { toolCallId: "call_e2e", toolName: "bash", input: { command: "kubectl delete pods --all" } },
    ctx,
  );
  assert.ok(blocked?.block, "a kubernetes-pack rule blocks via the live registry");
});
