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
  __setCompleterOverrideForTest,
  createExtension,
  extensionInfo,
  GUARD_STATE_ENTRY_TYPE,
} from "../src/extension.ts";
import type { Completer } from "../src/grade.ts";

type Handler = (event: unknown, ctx: unknown) => unknown;

type CommandHandler = (args: string, ctx: unknown) => Promise<void>;

interface FakePi {
  handlers: Map<string, Handler>;
  entries: Array<{ type: "custom"; customType: string; data: unknown }>;
  commands: Map<string, { description?: string; handler: CommandHandler }>;
  on(event: string, handler: Handler): void;
  appendEntry(customType: string, data?: unknown): void;
  registerCommand(
    name: string,
    options: { description?: string; handler: CommandHandler },
  ): void;
}

function createFakePi(): FakePi {
  const handlers = new Map<string, Handler>();
  const entries: FakePi["entries"] = [];
  const commands = new Map<
    string,
    { description?: string; handler: CommandHandler }
  >();
  return {
    handlers,
    entries,
    commands,
    on(event, handler) {
      handlers.set(event, handler);
    },
    appendEntry(customType, data) {
      entries.push({ type: "custom", customType, data });
    },
    registerCommand(name, options) {
      commands.set(name, options);
    },
  };
}

interface FakeCtx {
  cwd: string;
  hasUI: boolean;
  ui: {
    statuses: Record<string, string | undefined>;
    notifications: Array<{ message: string; type?: string }>;
    confirmReply: boolean;
    confirmCalls: Array<{ title: string; message: string }>;
    notify(message: string, type?: string): void;
    setStatus(key: string, text: string | undefined): void;
    confirm(title: string, message: string): Promise<boolean>;
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
      confirmReply: false,
      confirmCalls: [],
      notify(message, type) {
        this.notifications.push({ message, type });
      },
      setStatus(key, text) {
        this.statuses[key] = text;
      },
      async confirm(title, message) {
        this.confirmCalls.push({ title, message });
        return this.confirmReply;
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

// ---------------------------------------------------------------------------
// Phase 3 — the LLM grading gate makes degraded mode ENFORCING.
// We inject a stubbed completer (no live LLM) via the test seam and assert that
// a GATED clean call is actually graded and enforced.
// ---------------------------------------------------------------------------

const COMPLIANT_VERDICT = JSON.stringify({
  compliant: true,
  backOnTrack: true,
  confidence: 0.95,
  reasoning: "Clean, on-track call.",
});

const DIRTY_VERDICT = JSON.stringify({
  compliant: false,
  backOnTrack: false,
  confidence: 0.95,
  reasoning: "Still off track.",
  remediation: "Fix the violation.",
});

function stubCompleter(reply: string): Completer {
  return async () => reply;
}

async function gateTheSession(pi: FakePi, ctx: FakeCtx): Promise<void> {
  // A high-severity (non-critical) command blocks and arms GATED.
  const result = await fireToolCall(pi, ctx, "git restore file.txt");
  assert.ok(result?.block, "git restore should block and arm GATED");
}

test("Phase 3: a GATED clean call WITH a compliant grader advances recovery", async () => {
  __setCompleterOverrideForTest(stubCompleter(COMPLIANT_VERDICT));
  try {
    const pi = createFakePi();
    extension(pi as never);
    const cwd = await mkdtemp(join(tmpdir(), "pi-guardrails-ext-"));
    const ctx = createFakeCtx(cwd, pi.entries);
    await startSession(pi, ctx);

    await gateTheSession(pi, ctx);

    // Clean call while GATED: graded compliant. The grade IS the gate, so a
    // compliant call is ALLOWED to run, and the clean grade advances
    // GATED -> RECOVERING (recoveringWatermark=1). Only a non-compliant grade
    // (next test) holds the call.
    const graded = await fireToolCall(pi, ctx, "echo hello world");
    assert.ok(!graded?.block, "a compliant-graded call runs (not held)");

    const stateEntries = pi.entries.filter(
      (e) => e.customType === GUARD_STATE_ENTRY_TYPE,
    );
    const last = stateEntries[stateEntries.length - 1].data as {
      state: string;
    };
    assert.equal(
      last.state,
      "RECOVERING",
      "a compliant grade advanced GATED -> RECOVERING",
    );
  } finally {
    __setCompleterOverrideForTest(undefined);
  }
});

test("Phase 3: a GATED clean call WITH a non-compliant grader stays blocked/gated", async () => {
  __setCompleterOverrideForTest(stubCompleter(DIRTY_VERDICT));
  try {
    const pi = createFakePi();
    extension(pi as never);
    const cwd = await mkdtemp(join(tmpdir(), "pi-guardrails-ext-"));
    const ctx = createFakeCtx(cwd, pi.entries);
    await startSession(pi, ctx);

    await gateTheSession(pi, ctx);

    // Clean-looking call while GATED, but the grader says non-compliant: the gate
    // HOLDS — the call is blocked and the session stays GATED.
    const graded = await fireToolCall(pi, ctx, "echo hello world");
    assert.ok(graded?.block, "a non-compliant grade blocks the call");

    const stateEntries = pi.entries.filter(
      (e) => e.customType === GUARD_STATE_ENTRY_TYPE,
    );
    const last = stateEntries[stateEntries.length - 1].data as {
      state: string;
    };
    assert.equal(last.state, "GATED", "stays GATED on a dirty grade");
  } finally {
    __setCompleterOverrideForTest(undefined);
  }
});

test("Phase 3: graderUnavailable FAILS CLOSED — gated clean call is blocked", async () => {
  // No completer override and the fake ctx has no modelRegistry, so the grader is
  // unavailable. A gated clean call must be BLOCKED (fail closed), not allowed.
  __setCompleterOverrideForTest(undefined);
  const pi = createFakePi();
  extension(pi as never);
  const cwd = await mkdtemp(join(tmpdir(), "pi-guardrails-ext-"));
  const ctx = createFakeCtx(cwd, pi.entries);
  await startSession(pi, ctx);

  // session_start warned loud about the unavailable grader.
  assert.ok(
    ctx.ui.notifications.some(
      (n) => n.type === "error" && /grader/i.test(n.message),
    ),
    "session_start warns when an enabled grader is unavailable",
  );

  await gateTheSession(pi, ctx);

  const held = await fireToolCall(pi, ctx, "echo hello world");
  assert.ok(held?.block, "fail closed: gated clean call is blocked");
  assert.match(held.reason ?? "", /grader unavailable/i);
});

test("Phase 3: full recovery — enough compliant grades clear the gate to COMPLIANT", async () => {
  __setCompleterOverrideForTest(stubCompleter(COMPLIANT_VERDICT));
  try {
    const pi = createFakePi();
    extension(pi as never);
    const cwd = await mkdtemp(join(tmpdir(), "pi-guardrails-ext-"));
    const ctx = createFakeCtx(cwd, pi.entries);
    await startSession(pi, ctx);

    await gateTheSession(pi, ctx);

    // GATED -> RECOVERING (1 clean grade), then RECOVERING needs gatedCleanStreak=3
    // consecutive clean grades + backOnTrack to reach COMPLIANT. The cache must NOT
    // short-circuit these (each distinct command is a fresh grade), so vary them.
    const cmds = [
      "echo a", // GATED -> RECOVERING
      "echo b", // streak 1
      "echo c", // streak 2
      "echo d", // streak 3 + backOnTrack => COMPLIANT (this call runs)
    ];
    let lastResult: { block?: boolean } | undefined;
    for (const c of cmds) {
      lastResult = await fireToolCall(pi, ctx, c);
    }

    const stateEntries = pi.entries.filter(
      (e) => e.customType === GUARD_STATE_ENTRY_TYPE,
    );
    const last = stateEntries[stateEntries.length - 1].data as {
      state: string;
    };
    assert.equal(last.state, "COMPLIANT", "recovered to COMPLIANT");
    assert.equal(
      lastResult?.block,
      undefined,
      "the recovering call that clears the gate is allowed to run",
    );
  } finally {
    __setCompleterOverrideForTest(undefined);
  }
});

test("Phase 3: the grader cannot rescue a deterministic block (dangerous call still blocked)", async () => {
  __setCompleterOverrideForTest(stubCompleter(COMPLIANT_VERDICT));
  try {
    const pi = createFakePi();
    extension(pi as never);
    const cwd = await mkdtemp(join(tmpdir(), "pi-guardrails-ext-"));
    const ctx = createFakeCtx(cwd, pi.entries);
    await startSession(pi, ctx);

    await gateTheSession(pi, ctx);

    // A dangerous command while GATED is blocked deterministically — it never even
    // reaches the grader (action is "block"/"halt", not "gate-required").
    const danger = await fireToolCall(pi, ctx, "git push --force");
    assert.ok(
      danger?.block,
      "dangerous call stays blocked despite a clean grader",
    );
  } finally {
    __setCompleterOverrideForTest(undefined);
  }
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

// ---------------------------------------------------------------------------
// HALTED human-ack recovery — the /guardrails-clear-halt slash command.
// HALTED is terminal for the model; only a human typing the slash command and
// confirming an interactive dialog can clear it. The command is never reachable
// from the model's tool-call stream.
// ---------------------------------------------------------------------------

const CLEAR_HALT_CMD = "guardrails-clear-halt";

async function runCommand(
  pi: FakePi,
  ctx: FakeCtx,
  name: string,
): Promise<void> {
  const cmd = pi.commands.get(name);
  assert.ok(cmd, `command ${name} must be registered`);
  await cmd.handler("", ctx);
}

async function haltSession(pi: FakePi, ctx: FakeCtx): Promise<void> {
  // A critical/inviolable command HALTs (terminal). git reset --hard => HALTED.
  const result = await fireToolCall(pi, ctx, "git reset --hard HEAD~1");
  assert.ok(result?.block, "git reset --hard should HALT the session");
}

test("registers the /guardrails-clear-halt command", () => {
  const pi = createFakePi();
  extension(pi as never);
  assert.ok(
    pi.commands.has(CLEAR_HALT_CMD),
    "the HALT-clear command is registered",
  );
});

test("clear-halt: human confirm clears HALTED -> COMPLIANT and unblocks", async () => {
  const pi = createFakePi();
  extension(pi as never);
  const cwd = await mkdtemp(join(tmpdir(), "pi-guardrails-ext-"));
  const ctx = createFakeCtx(cwd, pi.entries);
  ctx.hasUI = true;
  ctx.ui.confirmReply = true; // human says YES

  await startSession(pi, ctx);
  await haltSession(pi, ctx);

  // While HALTED, even a clean call is blocked.
  const heldBefore = await fireToolCall(pi, ctx, "ls -la");
  assert.ok(heldBefore?.block, "HALTED blocks everything, even clean calls");

  await runCommand(pi, ctx, CLEAR_HALT_CMD);
  assert.equal(ctx.ui.confirmCalls.length, 1, "the human was asked to confirm");

  // State persisted COMPLIANT.
  const stateEntries = pi.entries.filter(
    (e) => e.customType === GUARD_STATE_ENTRY_TYPE,
  );
  const last = stateEntries[stateEntries.length - 1].data as { state: string };
  assert.equal(last.state, "COMPLIANT", "halt cleared to COMPLIANT");

  // A clean call now passes through.
  const after = await fireToolCall(pi, ctx, "ls -la");
  assert.equal(after, undefined, "clean calls run again after the halt clears");
});

test("clear-halt: human decline keeps the session HALTED", async () => {
  const pi = createFakePi();
  extension(pi as never);
  const cwd = await mkdtemp(join(tmpdir(), "pi-guardrails-ext-"));
  const ctx = createFakeCtx(cwd, pi.entries);
  ctx.hasUI = true;
  ctx.ui.confirmReply = false; // human says NO

  await startSession(pi, ctx);
  await haltSession(pi, ctx);

  await runCommand(pi, ctx, CLEAR_HALT_CMD);
  assert.equal(ctx.ui.confirmCalls.length, 1, "the human was asked to confirm");

  // Still HALTED — a clean call is still blocked.
  const after = await fireToolCall(pi, ctx, "ls -la");
  assert.ok(after?.block, "decline keeps the session HALTED");
});

test("clear-halt: no interactive UI refuses to clear (no blind clear)", async () => {
  const pi = createFakePi();
  extension(pi as never);
  const cwd = await mkdtemp(join(tmpdir(), "pi-guardrails-ext-"));
  const ctx = createFakeCtx(cwd, pi.entries);
  ctx.hasUI = false; // RPC/print mode — no human-ack path

  await startSession(pi, ctx);
  await haltSession(pi, ctx);

  await runCommand(pi, ctx, CLEAR_HALT_CMD);
  assert.equal(
    ctx.ui.confirmCalls.length,
    0,
    "no confirm dialog without an interactive UI",
  );
  assert.ok(
    ctx.ui.notifications.some(
      (n) => n.type === "error" && /interactive UI/i.test(n.message),
    ),
    "refusal is surfaced as an error",
  );

  // Still HALTED.
  const after = await fireToolCall(pi, ctx, "ls -la");
  assert.ok(after?.block, "stays HALTED when there is no human-ack path");
});

test("clear-halt: a no-op when the session is not halted", async () => {
  const pi = createFakePi();
  extension(pi as never);
  const cwd = await mkdtemp(join(tmpdir(), "pi-guardrails-ext-"));
  const ctx = createFakeCtx(cwd, pi.entries);
  ctx.hasUI = true;
  ctx.ui.confirmReply = true;

  await startSession(pi, ctx); // COMPLIANT, never halted
  await runCommand(pi, ctx, CLEAR_HALT_CMD);

  assert.equal(
    ctx.ui.confirmCalls.length,
    0,
    "no confirm dialog when there is nothing to clear",
  );
  assert.ok(
    ctx.ui.notifications.some((n) => /nothing to clear/i.test(n.message)),
    "tells the human there is nothing to clear",
  );
});
