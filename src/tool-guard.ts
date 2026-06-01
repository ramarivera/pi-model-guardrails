import type {
  ActiveToolContract,
  NormalizedToolInvocation,
  ToolContractRule,
  ToolGuardConfig,
  ToolGuardDecision,
  ToolProviderDetector,
} from "./types.ts";

export function extractToolContracts(
  content: string,
  config: ToolGuardConfig,
): ActiveToolContract[] {
  if (config.explicitToolContractsEnabled === false) return [];

  const normalized = content.replace(/\s+/g, " ").trim();
  if (!normalized) return [];

  return (config.toolContracts ?? [])
    .filter((contract) =>
      patternListMatches(contract.triggerPatterns, normalized),
    )
    .map((contract) => activeContractFromRule(contract, normalized));
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
  config: ToolGuardConfig,
): NormalizedToolInvocation {
  const command = extractCommand(input);
  const serializedInput = JSON.stringify(input);

  for (const detector of config.providerDetectors ?? []) {
    if (detectorMatches(detector, toolName, command, serializedInput)) {
      return {
        toolName,
        capability: detector.capability,
        provider: detector.provider,
        command,
        confidence: detector.confidence ?? 0.9,
      };
    }
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
  const invocation = normalizeToolInvocation(toolName, input, config);

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

function activeContractFromRule(
  rule: ToolContractRule,
  originalText: string,
): ActiveToolContract {
  return {
    ruleId: rule.id,
    capability: rule.capability,
    requiredProvider: rule.requiredProvider,
    forbiddenProviders: rule.forbiddenProviders,
    source: "explicit_user_instruction",
    severity: rule.severity ?? "error",
    originalText,
  };
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

function detectorMatches(
  detector: ToolProviderDetector,
  toolName: string,
  command: string | undefined,
  serializedInput: string,
): boolean {
  return (
    patternListMatches(detector.toolNamePatterns, toolName) ||
    patternListMatches(detector.commandPatterns, command ?? "") ||
    patternListMatches(detector.inputPatterns, serializedInput)
  );
}

function patternListMatches(
  patterns: string[] | undefined,
  value: string,
): boolean {
  if (!patterns || patterns.length === 0) return false;
  return patterns.some((pattern) => safeRegexTest(pattern, value));
}

function safeRegexTest(pattern: string, value: string): boolean {
  try {
    return new RegExp(pattern, "i").test(value);
  } catch {
    return false;
  }
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
