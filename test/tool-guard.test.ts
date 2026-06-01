import assert from "node:assert/strict";
import test from "node:test";
import {
  extractToolContracts,
  normalizeToolInvocation,
  shouldBlockToolCall,
} from "../src/tool-guard.ts";
import type { ToolGuardConfig } from "../src/types.ts";

const config: ToolGuardConfig = {
  enabled: true,
  blockedTools: [],
  blockedPatterns: [],
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
        "\\bdo\\s+not\\s+use\\s+playwright\\b",
        "\\bno\\s+playwright\\b",
      ],
      severity: "error",
    },
  ],
  providerDetectors: [
    {
      provider: "agent-browser",
      capability: "browser_automation",
      toolNamePatterns: ["agent[-_\\s]?browser"],
      commandPatterns: ["\\bagent-browser\\b", "\\bagent\\s+browser\\b"],
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
    {
      provider: "puppeteer",
      capability: "browser_automation",
      commandPatterns: ["\\bpuppeteer\\b"],
      inputPatterns: ["\\bpuppeteer\\b"],
      confidence: 0.94,
    },
    {
      provider: "cypress",
      capability: "browser_automation",
      commandPatterns: [
        "\\b(?:npx|pnpm|yarn|bunx|npm\\s+exec)\\s+cypress\\b",
        "\\bcypress\\s+(?:run|open)\\b",
      ],
      confidence: 0.94,
    },
  ],
};

test("extracts an explicit agent-browser contract from configured rules", () => {
  const contracts = extractToolContracts(
    "Please use agent-browser to inspect the Clerk form, not Playwright.",
    config,
  );

  assert.equal(contracts.length, 1);
  assert.equal(
    contracts[0]?.ruleId,
    "tool.browser.required-provider.agent-browser",
  );
  assert.equal(contracts[0]?.capability, "browser_automation");
  assert.equal(contracts[0]?.requiredProvider, "agent-browser");
  assert.deepEqual(contracts[0]?.forbiddenProviders, [
    "playwright",
    "puppeteer",
    "cypress",
  ]);
});

test("does not extract tool contracts without configured rules", () => {
  const contracts = extractToolContracts(
    "Please use agent-browser to inspect the Clerk form, not Playwright.",
    { ...config, toolContracts: [] },
  );

  assert.deepEqual(contracts, []);
});

test("normalizes Playwright hidden inside bash commands using configured detectors", () => {
  const invocation = normalizeToolInvocation(
    "bash",
    {
      command:
        "cd /Users/ramarivera/dev/agent-haven/apps/web && npx playwright test --reporter=list",
    },
    config,
  );

  assert.equal(invocation.toolName, "bash");
  assert.equal(invocation.capability, "browser_automation");
  assert.equal(invocation.provider, "playwright");
  assert.equal(invocation.confidence, 0.98);
});

test("normalizes agent-browser shell calls as browser automation using configured detectors", () => {
  const invocation = normalizeToolInvocation(
    "bash",
    {
      command: "agent-browser open http://localhost:5173 --wait 3000",
    },
    config,
  );

  assert.equal(invocation.capability, "browser_automation");
  assert.equal(invocation.provider, "agent-browser");
});

test("does not normalize configured providers without detectors", () => {
  const invocation = normalizeToolInvocation(
    "bash",
    {
      command: "npx playwright test --reporter=list",
    },
    { ...config, providerDetectors: [] },
  );

  assert.equal(invocation.capability, undefined);
  assert.equal(invocation.provider, undefined);
});

test("blocks Playwright when configured contract requires agent-browser", () => {
  const [contract] = extractToolContracts(
    "Use agent-browser to inspect this browser flow.",
    config,
  );

  const decision = shouldBlockToolCall(
    "bash",
    { command: "npx playwright test e2e/dashboard.spec.ts --debug" },
    config,
    contract ? [contract] : [],
  );

  assert.equal(decision.blocked, true);
  assert.equal(decision.decision, "deny");
  assert.equal(decision.ruleId, "tool.browser.required-provider.agent-browser");
  assert.equal(decision.requestedProvider, "agent-browser");
  assert.equal(decision.attemptedProvider, "playwright");
  assert.match(decision.reason, /explicitly requested agent-browser/i);
  assert.equal(decision.remediation?.safeAlternativeTool, "agent-browser");
});

test("allows agent-browser when configured contract requires agent-browser", () => {
  const [contract] = extractToolContracts(
    "Use agent-browser to inspect this browser flow.",
    config,
  );

  const decision = shouldBlockToolCall(
    "bash",
    { command: "agent-browser snapshot -i" },
    config,
    contract ? [contract] : [],
  );

  assert.equal(decision.blocked, false);
  assert.equal(decision.decision, "allow");
  assert.equal(decision.ruleId, undefined);
});

test("allows unrelated commands while configured agent-browser contract is active", () => {
  const [contract] = extractToolContracts(
    "Use agent-browser to inspect this browser flow.",
    config,
  );

  const decision = shouldBlockToolCall(
    "bash",
    { command: "git status --short" },
    config,
    contract ? [contract] : [],
  );

  assert.equal(decision.blocked, false);
  assert.equal(decision.decision, "allow");
});

test("legacy blocked patterns still work with decision metadata", () => {
  const decision = shouldBlockToolCall(
    "bash",
    { command: "rm -rf node_modules" },
    { ...config, blockedPatterns: ["rm -rf"] },
  );

  assert.equal(decision.blocked, true);
  assert.equal(decision.decision, "deny");
  assert.equal(decision.ruleId, "tool.legacy.blocked-pattern");
});
