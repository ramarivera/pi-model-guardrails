import type { ToolGuardConfig } from "./types.ts";

export function shouldBlockToolCall(
  toolName: string,
  input: Record<string, unknown>,
  config: ToolGuardConfig,
): { blocked: boolean; reason: string } {
  if (!config.enabled) {
    return { blocked: false, reason: "" };
  }

  // Check blocked tools
  if (config.blockedTools?.includes(toolName)) {
    return {
      blocked: true,
      reason: `Tool "${toolName}" is blocked by guardrails configuration`,
    };
  }

  // Check blocked patterns in tool input
  if (config.blockedPatterns && config.blockedPatterns.length > 0) {
    const inputStr = JSON.stringify(input).toLowerCase();
    for (const pattern of config.blockedPatterns) {
      if (inputStr.includes(pattern.toLowerCase())) {
        return {
          blocked: true,
          reason: `Tool call blocked: input contains blocked pattern "${pattern}"`,
        };
      }
    }
  }

  return { blocked: false, reason: "" };
}
