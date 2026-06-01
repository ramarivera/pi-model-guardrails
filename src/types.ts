/**
 * Shared types for pi-model-guardrails
 */

/** Configuration for the guardrails extension */
export interface GuardrailsConfig {
  /** Analysis model: a Pi model identifier from the model pool (e.g. "gpt-4o-mini") */
  analysisModel: string;

  /** Models that should be guardrailed (if empty, all models are guardrailed) */
  modelWhitelist?: string[];

  /** Models that should NOT be guardrailed (takes precedence over whitelist) */
  modelBlacklist?: string[];

  /** How many turns to skip between analyses (1 = every turn, 5 = every 5th turn) */
  samplingInterval?: number;

  /** Confidence threshold (0-1) to trigger a correction. Default 0.7 */
  confidenceThreshold?: number;

  /** Tool guard configuration */
  toolGuards: ToolGuardConfig;

  /**
   * Legacy regex/string pattern rules for exact textual tripwires.
   * Disabled unless patternRulesEnabled is true.
   */
  patternRules: PatternRule[];

  /** Whether legacy patternRules should be evaluated. Default false. */
  patternRulesEnabled?: boolean;

  /** Natural-language policies evaluated by the guardrails analysis model. */
  policyRules: PolicyRule[];

  /** Local observability and decision audit configuration. */
  observability?: GuardrailsObservabilityConfig;
}

/** Tool guard configuration */
export interface ToolGuardConfig {
  /** Whether tool guards are enabled */
  enabled: boolean;
  /** List of tools to block entirely */
  blockedTools?: string[];
  /** Patterns that, if found in tool input, trigger a block */
  blockedPatterns?: string[];
  /** Whether explicit user tool-provider contracts should be enforced. Default true. */
  explicitToolContractsEnabled?: boolean;
  /** How to handle deterministic provider mismatches. Default deny. */
  providerMismatchMode?: "deny" | "warn";
}

/** A deterministic runtime contract extracted from explicit user tool instructions. */
export interface ActiveToolContract {
  ruleId: string;
  capability: string;
  requiredProvider: string;
  forbiddenProviders: string[];
  source: "explicit_user_instruction";
  severity: "error" | "warn";
  originalText: string;
}

/** Normalized tool invocation used by deterministic pre-tool policy checks. */
export interface NormalizedToolInvocation {
  toolName: string;
  capability?: string;
  provider?: string;
  command?: string;
  confidence: number;
}

/** Canonical internal tool guard decision envelope. */
export interface ToolGuardDecision {
  schemaVersion: 1;
  decision: "allow" | "deny" | "warn";
  blocked: boolean;
  reason: string;
  ruleId?: string;
  severity?: "error" | "warn";
  confidence?: number;
  capability?: string;
  requestedProvider?: string;
  attemptedProvider?: string;
  invocation?: NormalizedToolInvocation;
  remediation?: {
    safeAlternativeTool?: string;
    instruction: string;
  };
}

/** Local JSONL observability for guardrail decisions and extension lifecycle. */
export interface GuardrailsObservabilityConfig {
  /** Whether local telemetry should be written. Default true. */
  enabled?: boolean;
  /** Log file path. Relative paths resolve from the session cwd. */
  logFile?: string;
  /** Whether to log high-volume token/message update events. Default false. */
  logMessageUpdates?: boolean;
}

/** A configurable pattern rule for code/instruction detection */
export interface PatternRule {
  /** Unique rule ID */
  id: string;
  /** Human-readable description of what this rule checks */
  description: string;
  /** Regex pattern or string to search for */
  pattern: string;
  /** Whether to treat pattern as a regex */
  isRegex: boolean;
  /** Where to check: 'assistant', 'tool_output', 'both' */
  scope: "assistant" | "tool_output" | "both";
  /** Case-insensitive matching */
  ignoreCase?: boolean;
  /** Severity: 'error' always blocks, 'warn' only notifies */
  severity: "error" | "warn";
  /** Explanation shown when rule triggers */
  explanation: string;
  /** File extensions this rule applies to (e.g., ['.ts', '.tsx']). Empty = all. */
  fileExtensions?: string[];
}

/** A model-judged policy rule for intent-aware guardrails. */
export interface PolicyRule {
  /** Unique rule ID */
  id: string;
  /** Short human-readable name */
  title: string;
  /** User-facing explanation of the policy */
  description: string;
  /** When this policy applies */
  appliesWhen: string;
  /** What counts as a violation */
  violation: string;
  /** What the model should do instead */
  requiredBehavior: string;
  /** Severity used by the analyzer when confidence is high enough */
  severity: "error" | "warn";
}

/** Combined violation: can be from LLM analysis or pattern rule */
export interface Violation {
  source: "llm_analysis" | "pattern_rule";
  confidence: number;
  violatedInstruction: string;
  whatModelDid: string;
  whatShouldHaveDone: string;
  correctionMessage: string;
  reasoning: string;
}

/** Result of a violation analysis */
export interface ViolationAnalysis {
  /** Whether a violation was detected */
  violation: boolean;
  /** Confidence score (0-1) */
  confidence: number;
  /** What instruction was violated */
  violatedInstruction: string;
  /** What the model did wrong */
  whatModelDid: string;
  /** What the model should have done instead */
  whatShouldHaveDone: string;
  /** Suggested correction message for the user */
  correctionMessage: string;
  /** Full reasoning from the analyzer */
  reasoning: string;
}

/** A message in the conversation */
export interface ConversationMessage {
  role: "user" | "assistant" | "system" | "tool";
  content: string;
  timestamp?: number;
}

/** A tracked message entry for guardrails analysis */
export interface MessageEntry {
  role: string;
  content: string;
  toolName?: string;
}

/** A tool call event */
export interface ToolCall {
  toolName: string;
  input: Record<string, unknown>;
}
