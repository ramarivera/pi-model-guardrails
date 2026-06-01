import assert from "node:assert/strict";
import { mkdir, mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import extension from "../../.pi/extensions/model-guardrails/index.ts";

type Handler = (event: unknown, ctx: unknown) => unknown | Promise<unknown>;

async function writeGuardrailsConfig(cwd: string): Promise<void> {
  await mkdir(join(cwd, ".pi"), { recursive: true });
  await writeFile(
    join(cwd, ".pi", "guardrails.json"),
    JSON.stringify({
      toolGuards: {
        enabled: true,
        explicitToolContractsEnabled: true,
        providerMismatchMode: "deny",
        toolContracts: [
          {
            id: "tool.browser.required-provider.agent-browser",
            capability: "browser_automation",
            requiredProvider: "agent-browser",
            forbiddenProviders: ["playwright", "puppeteer", "cypress"],
            triggerPatterns: [
              "\\b(?:use|using|with|via|prefer|preferred|require|required|requested|explicitly\\s+requested)\\s+(?:the\\s+)?agent[-\\s]?browser\\b",
              "\\bagent[-\\s]?browser\\b[^.\\n]{0,80}\\b(?:required|requested|explicit|instead|must|only)\\b",
            ],
            severity: "error",
          },
        ],
        providerDetectors: [
          {
            provider: "agent-browser",
            capability: "browser_automation",
            toolNamePatterns: ["agent[-_\\s]?browser"],
            commandPatterns: ["\\bagent-browser\\b"],
            inputPatterns: ["\\bmcp_browser_use_cloud_"],
            confidence: 0.98,
          },
          {
            provider: "playwright",
            capability: "browser_automation",
            commandPatterns: [
              "\\b(?:npx|pnpm|yarn|bunx|npm\\s+exec)\\s+playwright\\b",
              "\\bplaywright\\s+(?:test|show-report|codegen|install|open)\\b",
              "@playwright/test\\b",
            ],
            confidence: 0.98,
          },
        ],
      },
    }),
    "utf8",
  );
}

function createHarness() {
  const handlers = new Map<string, Handler[]>();
  const notifications: Array<{ message: string; type?: string }> = [];
  const statuses: Array<{ key: string; text: string | undefined }> = [];

  const pi = {
    on(event: string, handler: Handler) {
      handlers.set(event, [...(handlers.get(event) ?? []), handler]);
    },
  } as unknown as ExtensionAPI;

  extension(pi);

  return {
    notifications,
    statuses,
    async emit(eventName: string, event: unknown, cwd: string) {
      const eventHandlers = handlers.get(eventName) ?? [];
      const ctx = {
        cwd,
        model: { provider: "openai", id: "gpt-5.5" },
        sessionManager: {
          getSessionFile: () => join(cwd, ".pi", "session.jsonl"),
        },
        ui: {
          notify(message: string, type?: string) {
            notifications.push({ message, type });
          },
          setStatus(key: string, text: string | undefined) {
            statuses.push({ key, text });
          },
        },
      };

      const results = [];
      for (const handler of eventHandlers) {
        results.push(await handler(event, ctx));
      }
      return results;
    },
  };
}

test("e2e blocks Playwright tool call after explicit agent-browser request", async () => {
  const cwd = await mkdtemp(join(tmpdir(), "pi-guardrails-e2e-contract-"));
  await writeGuardrailsConfig(cwd);
  const harness = createHarness();

  await harness.emit(
    "session_start",
    { type: "session_start", reason: "startup" },
    cwd,
  );
  await harness.emit(
    "message_start",
    {
      type: "message_start",
      message: {
        role: "user",
        content: "Use agent-browser to inspect the Clerk sign-in form.",
      },
    },
    cwd,
  );

  const [result] = await harness.emit(
    "tool_call",
    {
      type: "tool_call",
      toolCallId: "call-playwright",
      toolName: "bash",
      input: {
        command:
          "cd /Users/ramarivera/dev/agent-haven/apps/web && npx playwright test e2e/dashboard.spec.ts --debug",
      },
    },
    cwd,
  );

  assert.deepEqual(result, {
    block: true,
    reason:
      "The user explicitly requested agent-browser for browser automation. Do not use playwright; use agent-browser instead.",
  });
  assert.equal(harness.notifications.at(-1)?.type, "error");
  assert.match(harness.notifications.at(-1)?.message ?? "", /agent-browser/i);

  const telemetry = await readFile(
    join(cwd, ".pi", "model-guardrails", "events.jsonl"),
    "utf8",
  );
  const events = telemetry
    .trim()
    .split("\n")
    .map((line) => JSON.parse(line));
  const decision = events.find(
    (event) => event.kind === "event" && event.name === "tool_guard_decision",
  );

  assert.equal(decision?.tags?.decision, "deny");
  assert.equal(
    decision?.tags?.ruleId,
    "tool.browser.required-provider.agent-browser",
  );
  assert.equal(decision?.tags?.requestedProvider, "agent-browser");
  assert.equal(decision?.tags?.attemptedProvider, "playwright");
});

test("e2e allows agent-browser tool call after explicit agent-browser request", async () => {
  const cwd = await mkdtemp(join(tmpdir(), "pi-guardrails-e2e-contract-"));
  await writeGuardrailsConfig(cwd);
  const harness = createHarness();

  await harness.emit(
    "session_start",
    { type: "session_start", reason: "startup" },
    cwd,
  );
  await harness.emit(
    "message_start",
    {
      type: "message_start",
      message: {
        role: "user",
        content: "Use agent-browser to inspect the Clerk sign-in form.",
      },
    },
    cwd,
  );

  const [result] = await harness.emit(
    "tool_call",
    {
      type: "tool_call",
      toolCallId: "call-agent-browser",
      toolName: "bash",
      input: {
        command: "agent-browser open http://localhost:5173 --wait 3000",
      },
    },
    cwd,
  );

  assert.equal(result, undefined);
});
