import type {
  ActiveToolContract,
  NormalizedToolInvocation,
  ToolGuardConfig,
  ToolGuardDecision,
} from "./types.ts";

const AGENT_BROWSER_REQUIRED_PATTERNS = [
  /\b(?:use|using|with|via|prefer|preferred|require|required|requested|explicitly\s+requested)\s+(?:the\s+)?agent[-\s]?browser\b/i,
  /\bagent[-\s]?browser\b[^.\n]{0,80}\b(?:required|requested|explicit|instead|must|only)\b/i,
  /\bdo\s+not\s+use\s+playwright\b/i,
  /\bno\s+playwright\b/i,
];

export function extractToolContracts(content: string): ActiveToolContract[] {
  const normalized = content.replace(/\s+/g, " ").trim();
  if (!normalized) return [];

  if (
    !AGENT_BROWSER_REQUIRED_PATTERNS.some((pattern) => pattern.test(normalized))
  ) {
    return [];
  }

  return [
    {
      ruleId: "tool.browser.required-provider.agent-browser",
      capability: "browser_automation",
      requiredProvider: "agent-browser",
      forbiddenProviders: ["playwright", "puppeteer", "cypress"],
      source: "explicit_user_instruction",
      severity: "error",
      originalText: normalized,
    },
  ];
}

export function mergeToolContracts(
  current: ActiveToolContract[],
  incoming: ActiveToolContract[],
): ActiveToolContract[] {
  const byRule = new Map(
    current.map((contract) => [contract.ruleId, contract]),
  );
  for (const contract of incoming) {
    byRule.set(contract.ruleId, contract);
  }
  return [...byRule.values()];
}

export function normalizeToolInvocation(
  toolName: string,
  input: Record<string, unknown>,
): NormalizedToolInvocation {
  const command = extractCommand(input);
  const haystack =
    `${toolName}\n${command ?? ""}\n${JSON.stringify(input)}`.toLowerCase();

  if (isAgentBrowserTool(toolName, haystack)) {
    return {
      toolName,
      capability: "browser_automation",
      provider: "agent-browser",
      command,
      confidence: 0.98,
    };
  }

  if (isPlaywrightInvocation(haystack)) {
    return {
      toolName,
      capability: "browser_automation",
      provider: "playwright",
      command,
      confidence: 0.98,
    };
  }

  if (isPuppeteerInvocation(haystack)) {
    return {
      toolName,
      capability: "browser_automation",
      provider: "puppeteer",
      command,
      confidence: 0.94,
    };
  }

  if (isCypressInvocation(haystack)) {
    return {
      toolName,
      capability: "browser_automation",
      provider: "cypress",
      command,
      confidence: 0.94,
    };
  }

  return {
    toolName,
    command,
    confidence: command ? 0.5 : 0.3,
  };
}

export function shouldBlockToolCall(
  toolName: string,
  input: Record<string, unknown>,
  config: ToolGuardConfig,
  activeContracts: ActiveToolContract[] = [],
): ToolGuardDecision {
  const invocation = normalizeToolInvocation(toolName, input);

  if (!config.enabled) {
    return allowDecision(invocation, "tool_guards_disabled");
  }

  const contractDecision = evaluateActiveContracts(
    invocation,
    config,
    activeContracts,
  );
  if (contractDecision) {
    return contractDecision;
  }

  if (config.blockedTools?.includes(toolName)) {
    return {
      schemaVersion: 1,
      decision: "deny",
      blocked: true,
      ruleId: "tool.legacy.blocked-tool",
      severity: "error",
      reason: `Tool "${toolName}" is blocked by guardrails configuration`,
      invocation,
      attemptedProvider: invocation.provider,
      capability: invocation.capability,
      confidence: 1,
    };
  }

  if (config.blockedPatterns && config.blockedPatterns.length > 0) {
    const inputStr = JSON.stringify(input).toLowerCase();
    for (const pattern of config.blockedPatterns) {
      if (inputStr.includes(pattern.toLowerCase())) {
        return {
          schemaVersion: 1,
          decision: "deny",
          blocked: true,
          ruleId: "tool.legacy.blocked-pattern",
          severity: "error",
          reason: `Tool call blocked: input contains blocked pattern "${pattern}"`,
          invocation,
          attemptedProvider: invocation.provider,
          capability: invocation.capability,
          confidence: 1,
        };
      }
    }
  }

  return allowDecision(invocation, "no_matching_tool_guard_rule");
}

function evaluateActiveContracts(
  invocation: NormalizedToolInvocation,
  config: ToolGuardConfig,
  activeContracts: ActiveToolContract[],
): ToolGuardDecision | undefined {
  if (config.explicitToolContractsEnabled === false) {
    return undefined;
  }

  for (const contract of activeContracts) {
    if (invocation.capability !== contract.capability) {
      continue;
    }

    if (invocation.provider === contract.requiredProvider) {
      return undefined;
    }

    if (
      invocation.provider &&
      contract.forbiddenProviders.includes(invocation.provider)
    ) {
      const mode = config.providerMismatchMode ?? "deny";
      const reason = `The user explicitly requested ${contract.requiredProvider} for ${humanCapability(contract.capability)}. Do not use ${invocation.provider}; use ${contract.requiredProvider} instead.`;
      return {
        schemaVersion: 1,
        decision: mode === "warn" ? "warn" : "deny",
        blocked: mode !== "warn",
        ruleId: contract.ruleId,
        severity: contract.severity,
        reason,
        confidence: invocation.confidence,
        capability: contract.capability,
        requestedProvider: contract.requiredProvider,
        attemptedProvider: invocation.provider,
        invocation,
        remediation: {
          safeAlternativeTool: contract.requiredProvider,
          instruction: `Use ${contract.requiredProvider}. Do not retry with ${invocation.provider}.`,
        },
      };
    }
  }

  return undefined;
}

function allowDecision(
  invocation: NormalizedToolInvocation,
  reason: string,
): ToolGuardDecision {
  return {
    schemaVersion: 1,
    decision: "allow",
    blocked: false,
    reason,
    invocation,
    attemptedProvider: invocation.provider,
    capability: invocation.capability,
    confidence: invocation.confidence,
  };
}

function extractCommand(input: Record<string, unknown>): string | undefined {
  for (const key of ["command", "cmd", "script", "code"]) {
    const value = input[key];
    if (typeof value === "string") return value;
  }

  const nested = findStringValue(input, new Set());
  return nested;
}

function findStringValue(
  value: unknown,
  seen: Set<unknown>,
): string | undefined {
  if (typeof value === "string") return value;
  if (!value || typeof value !== "object") return undefined;
  if (seen.has(value)) return undefined;
  seen.add(value);

  for (const nested of Object.values(value as Record<string, unknown>)) {
    const found = findStringValue(nested, seen);
    if (found) return found;
  }
  return undefined;
}

function isAgentBrowserTool(toolName: string, haystack: string): boolean {
  return (
    /agent[-_\s]?browser/i.test(toolName) ||
    /\bagent-browser\b/.test(haystack) ||
    /\bagent\s+browser\b/.test(haystack) ||
    /\bmcp_browser_use_cloud_/.test(haystack)
  );
}

function isPlaywrightInvocation(haystack: string): boolean {
  return (
    /\b(?:npx|pnpm|yarn|bunx|npm\s+exec)\s+playwright\b/.test(haystack) ||
    /\bplaywright\s+(?:test|show-report|codegen|install|open)\b/.test(
      haystack,
    ) ||
    /@playwright\/test\b/.test(haystack)
  );
}

function isPuppeteerInvocation(haystack: string): boolean {
  return /\bpuppeteer\b/.test(haystack);
}

function isCypressInvocation(haystack: string): boolean {
  return (
    /\b(?:npx|pnpm|yarn|bunx|npm\s+exec)\s+cypress\b/.test(haystack) ||
    /\bcypress\s+(?:run|open)\b/.test(haystack)
  );
}

function humanCapability(capability: string): string {
  return capability.replaceAll("_", " ");
}

export function describeActiveToolContract(
  contract: ActiveToolContract,
): Record<string, unknown> {
  return {
    ruleId: contract.ruleId,
    capability: contract.capability,
    requiredProvider: contract.requiredProvider,
    forbiddenProviders: contract.forbiddenProviders,
    source: contract.source,
    severity: contract.severity,
  };
}
