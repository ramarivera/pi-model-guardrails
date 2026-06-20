// Extension wiring tests — the Phase 2 deterministic guard wired into Pi.
//
// We construct a FAKE `pi` (captures handlers registered via pi.on + records
// appendEntry calls) and a FAKE ctx (tmp cwd, no-op ui, in-memory session
// entries), fire the real handlers, and assert the deterministic decisions reach
// the Pi BLOCK shape. No real Pi runtime is involved — fully deterministic.

import assert from "node:assert/strict";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import extension, {
  createExtension,
  extensionInfo,
  GUARD_STATE_ENTRY_TYPE,
} from "../src/extension.ts";

type Handler = (event: unknown, ctx: unknown) => unknown;

interface FakePi {
  handlers: Map<string, Handler>;
  entries: Array<{ type: "custom"; customType: string; data: unknown }>;
  on(event: string, handler: Handler): void;
  appendEntry(customType: string, data?: unknown): void;
}

function createFakePi(): FakePi {
  const handlers = new Map<string, Handler>();
  const entries: FakePi["entries"] = [];
  return {
    handlers,
    entries,
    on(event, handler) {
      handlers.set(event, handler);
    },
    appendEntry(customType, data) {
      entries.push({ type: "custom", customType, data });
    },
  };
}

interface FakeCtx {
  cwd: string;
  hasUI: boolean;
  ui: {
    statuses: Record<string, string | undefined>;
    notifications: Array<{ message: string; type?: string }>;
    notify(message: string, type?: string): void;
    setStatus(key: string, text: string | undefined): void;
  };
  sessionManager: {
    getEntries(): unknown[];
  };
}

function createFakeCtx(cwd: string, entries: unknown[] = []): FakeCtx {
  return {
    cwd,
    hasUI: false,
    ui: {
      statuses: {},
      notifications: [],
      notify(message, type) {
        this.notifications.push({ message, type });
      },
      setStatus(key, text) {
        this.statuses[key] = text;
      },
    },
    sessionManager: {
      getEntries: () => entries,
    },
  };
}

async function fireToolCall(
  pi: FakePi,
  ctx: FakeCtx,
  command: string,
): Promise<{ block?: boolean; reason?: string } | undefined> {
  const handler = pi.handlers.get("tool_call");
  assert.ok(handler, "tool_call handler must be registered");
  const event = {
    type: "tool_call",
    toolCallId: "call_1",
    toolName: "bash",
    input: { command },
  };
  return (await handler(event, ctx)) as
    | { block?: boolean; reason?: string }
    | undefined;
}

async function startSession(pi: FakePi, ctx: FakeCtx): Promise<void> {
  const handler = pi.handlers.get("session_start");
  assert.ok(handler, "session_start handler must be registered");
  await handler({ type: "session_start", reason: "startup" }, ctx);
}

test("factory exposes the extension identity", async () => {
  assert.equal(extensionInfo.name, "model-guardrails");
  assert.equal(typeof extension, "function");

  const created = createExtension();
  assert.equal(created.name, "model-guardrails");
  assert.deepEqual(await created.activate(), extensionInfo);
});

test("registers the core event handlers", () => {
  const pi = createFakePi();
  extension(pi as never);
  assert.ok(pi.handlers.has("session_start"));
  assert.ok(pi.handlers.has("tool_call"));
  assert.ok(pi.handlers.has("before_agent_start"));
});

test("blocks a critical command (git reset --hard)", async () => {
  const pi = createFakePi();
  extension(pi as never);
  const cwd = await mkdtemp(join(tmpdir(), "pi-guardrails-ext-"));
  const ctx = createFakeCtx(cwd, pi.entries);

  await startSession(pi, ctx);
  const result = await fireToolCall(pi, ctx, "git reset --hard HEAD~1");

  assert.ok(result, "a blocked call returns a result");
  assert.equal(result.block, true);
  assert.ok(
    typeof result.reason === "string" && result.reason.length > 0,
    "the block reason reaches the model",
  );
});

test("does not block a clean read-only command (ls -la)", async () => {
  const pi = createFakePi();
  extension(pi as never);
  const cwd = await mkdtemp(join(tmpdir(), "pi-guardrails-ext-"));
  const ctx = createFakeCtx(cwd, pi.entries);

  await startSession(pi, ctx);
  const result = await fireToolCall(pi, ctx, "ls -la");

  // A clean pass-through returns undefined (no block).
  assert.equal(result, undefined);
});

test("blocks a force push (git push --force)", async () => {
  const pi = createFakePi();
  extension(pi as never);
  const cwd = await mkdtemp(join(tmpdir(), "pi-guardrails-ext-"));
  const ctx = createFakeCtx(cwd, pi.entries);

  await startSession(pi, ctx);
  const result = await fireToolCall(pi, ctx, "git push --force");

  assert.ok(result, "a blocked call returns a result");
  assert.equal(result.block, true);
  assert.ok(typeof result.reason === "string" && result.reason.length > 0);
});

test("non-bash tools pass through (allow) in Phase 2", async () => {
  const pi = createFakePi();
  extension(pi as never);
  const cwd = await mkdtemp(join(tmpdir(), "pi-guardrails-ext-"));
  const ctx = createFakeCtx(cwd, pi.entries);

  await startSession(pi, ctx);

  const handler = pi.handlers.get("tool_call");
  assert.ok(handler);
  const result = await handler(
    {
      type: "tool_call",
      toolCallId: "call_x",
      toolName: "read",
      input: { path: "/etc/hosts" },
    },
    ctx,
  );
  assert.equal(result, undefined);
});

test("persists state to a session entry that survives resume", async () => {
  const pi = createFakePi();
  extension(pi as never);
  const cwd = await mkdtemp(join(tmpdir(), "pi-guardrails-ext-"));
  const ctx = createFakeCtx(cwd, pi.entries);

  await startSession(pi, ctx);
  await fireToolCall(pi, ctx, "git reset --hard HEAD~1");

  // The block persisted a guard-state entry.
  const stateEntries = pi.entries.filter(
    (e) => e.customType === GUARD_STATE_ENTRY_TYPE,
  );
  assert.ok(stateEntries.length >= 1, "a guard-state entry was appended");
  const last = stateEntries[stateEntries.length - 1].data as {
    state: string;
  };
  assert.equal(last.state, "HALTED");

  // A FRESH extension instance resuming the same session rehydrates HALTED and
  // keeps blocking even a clean command.
  const pi2 = createFakePi();
  extension(pi2 as never);
  const ctx2 = createFakeCtx(cwd, pi.entries); // same persisted entries
  await startSession(pi2, ctx2);
  const afterResume = await fireToolCall(pi2, ctx2, "ls -la");
  assert.ok(afterResume, "a halted session blocks even clean calls");
  assert.equal(afterResume.block, true);
});

test("before_agent_start injects a steering note only when armed", async () => {
  const pi = createFakePi();
  extension(pi as never);
  const cwd = await mkdtemp(join(tmpdir(), "pi-guardrails-ext-"));
  const ctx = createFakeCtx(cwd, pi.entries);
  await startSession(pi, ctx);

  const before = pi.handlers.get("before_agent_start");
  assert.ok(before);
  const beforeEvent = {
    type: "before_agent_start",
    prompt: "do something",
    systemPrompt: "base prompt",
    systemPromptOptions: {},
  };

  // COMPLIANT: no steering injected.
  const clean = (await before(beforeEvent, ctx)) as
    | { systemPrompt?: string }
    | undefined;
  assert.equal(clean, undefined);

  // After a block (armed), steering is injected.
  await fireToolCall(pi, ctx, "git push --force");
  const armed = (await before(beforeEvent, ctx)) as
    | { systemPrompt?: string }
    | undefined;
  assert.ok(armed?.systemPrompt, "armed state injects a systemPrompt");
  assert.ok(
    armed.systemPrompt.includes("model-guardrails"),
    "the steering note is tagged",
  );
});
