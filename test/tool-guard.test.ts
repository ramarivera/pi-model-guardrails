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
};

test("extracts an explicit agent-browser contract from user instructions", () => {
  const contracts = extractToolContracts(
    "Please use agent-browser to inspect the Clerk form, not Playwright.",
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

test("normalizes Playwright hidden inside bash commands", () => {
  const invocation = normalizeToolInvocation("bash", {
    command:
      "cd /Users/ramarivera/dev/agent-haven/apps/web && npx playwright test --reporter=list",
  });

  assert.equal(invocation.toolName, "bash");
  assert.equal(invocation.capability, "browser_automation");
  assert.equal(invocation.provider, "playwright");
  assert.equal(invocation.confidence, 0.98);
});

test("normalizes agent-browser shell calls as browser automation", () => {
  const invocation = normalizeToolInvocation("bash", {
    command: "agent-browser open http://localhost:5173 --wait 3000",
  });

  assert.equal(invocation.capability, "browser_automation");
  assert.equal(invocation.provider, "agent-browser");
});

test("blocks Playwright when the user explicitly required agent-browser", () => {
  const [contract] = extractToolContracts(
    "Use agent-browser to inspect this browser flow.",
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

test("allows agent-browser when agent-browser is required", () => {
  const [contract] = extractToolContracts(
    "Use agent-browser to inspect this browser flow.",
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

test("allows unrelated commands while agent-browser is required", () => {
  const [contract] = extractToolContracts(
    "Use agent-browser to inspect this browser flow.",
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
