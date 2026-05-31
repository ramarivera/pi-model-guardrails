import type { MessageEntry, PatternRule, Violation } from "./types.ts";

export function checkPatternRules(
  rules: PatternRule[],
  messages: MessageEntry[],
): Violation[] {
  const violations: Violation[] = [];

  for (const message of messages) {
    if (message.role === "assistant") {
      for (const rule of rules) {
        if (rule.scope === "tool_output") continue;
        const violation = checkRule(rule, message.content);
        if (violation) violations.push(violation);
      }
    } else if (message.role === "tool" && message.toolName) {
      for (const rule of rules) {
        if (rule.scope === "assistant") continue;
        const violation = checkRule(rule, message.content);
        if (violation) violations.push(violation);
      }
    }
  }

  return violations;
}

function checkRule(rule: PatternRule, content: string): Violation | null {
  const flags = rule.ignoreCase ? "gi" : "g";
  const regex = rule.isRegex
    ? new RegExp(rule.pattern, flags)
    : new RegExp(escapeRegex(rule.pattern), flags);

  const matches = content.match(regex);
  if (!matches || matches.length === 0) {
    return null;
  }

  return {
    source: "pattern_rule",
    confidence: rule.severity === "error" ? 1.0 : 0.6,
    violatedInstruction: rule.description,
    whatModelDid: `Matched forbidden pattern: ${rule.pattern} (${matches.length} occurrence${matches.length > 1 ? "s" : ""})`,
    whatShouldHaveDone: rule.explanation,
    correctionMessage: `Guardrails rule "${rule.id}" triggered: ${rule.description}`,
    reasoning: `Pattern rule ${rule.id} matched ${matches.length} time(s) in content. Pattern: ${rule.pattern}`,
  };
}

function escapeRegex(str: string): string {
  return str.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
