// Core type contract for the DCG-ported deterministic command-guard engine.
//
// Wire format (external YAML/JSON packs authored on disk) stays snake_case so
// DCG community packs load unchanged. Internal runtime types are camelCase and
// hold compiled RegExp; the loader maps wire -> internal.
//
// Source of truth for the wire shape: DCG `src/packs/external.rs`
// (https://github.com/Dicklesworthstone/destructive_command_guard).

/** Rule severity. Drives the default decision mode (see severityToMode). */
export type Severity = "critical" | "high" | "medium" | "low";

/** Final decision for a single command evaluation. */
export type DecisionMode = "deny" | "warn" | "log" | "allow";

/** Platform scoping for a remediation suggestion (DCG `platform`, "macos" alias of "macos"). */
export type Platform = "all" | "linux" | "macos" | "windows" | "bsd";

/** A safer alternative surfaced when a rule fires. */
export interface Suggestion {
  command: string;
  description?: string;
  platform: Platform;
}

/** A compiled "this is dangerous" rule within a pack. */
export interface DestructiveRule {
  /** unique within its pack; the public rule id is `${packId}:${name}`. */
  name: string;
  /** compiled trigger; the SAME engine is used at validation and evaluation time. */
  re: RegExp;
  severity: Severity;
  /** short human reason shown to the model/user. */
  reason: string;
  /** optional longer explanation for verbose/trace output. */
  explanation?: string;
  suggestions?: Suggestion[];
}

/** A compiled "this specific shape is fine" rule. PER-PACK scoped (never global). */
export interface SafeRule {
  name: string;
  re: RegExp;
}

/** Classification of a token span inside a command segment. */
export type SpanKind =
  | "executable"
  | "subcommand"
  | "flag"
  | "argument"
  | "path"
  | "string"
  | "subshell"
  | "operator"
  | "redirect";

export interface Span {
  text: string;
  kind: SpanKind;
  start: number;
  end: number;
}

/**
 * One shell segment (the command is split on `&&`, `||`, `;`, `|`, with
 * `$(...)`/backtick subshells extracted as their own segments; redirection `&`
 * is NOT a split point), carrying normalized + classified context.
 */
export interface SegmentContext {
  /** the segment exactly as written. */
  raw: string;
  /** after stripping wrapper prefixes (sudo/env/command/nice/…) and dequoting the command word. */
  normalized: string;
  /** first executable token, e.g. "git", "rm", "kubectl". */
  executable?: string;
  /** classified spans, when the classifier has run. */
  spans?: Span[];
}

/** Result of evaluating ONE command (which may contain many segments). */
export interface EngineDecision {
  decision: DecisionMode;
  /** convenience: decision === "deny". */
  blocked: boolean;
  /** `${packId}:${ruleName}` — split on the FIRST ":" to recover packId. */
  ruleId?: string;
  packId?: string;
  ruleName?: string;
  severity?: Severity;
  /** human reason (the steering channel: this string reaches the model on block). */
  reason?: string;
  /** the substring/segment that tripped the rule. */
  matched?: string;
  segment?: string;
  suggestions?: Suggestion[];
  explanation?: string;
  /** 0..1; deterministic pre-grade confidence (lower => more grader-worthy). */
  confidence?: number;
  /** why an allow happened (e.g. "safe_pattern:git-status", "no_match", "allowlist"), for tracing. */
  allowReason?: string;
}

/** Optional imperative pre-check (e.g. core.filesystem rm argv parser). */
export type ImperativeCheck = (
  ctx: SegmentContext,
  fullCommand: string,
) => EngineDecision | undefined;

/** A pack: a coherent safe + destructive rule set for one domain/tool. */
export interface Pack {
  /** `${domain}.${tool}`, e.g. "core.git", "core.filesystem". */
  id: string;
  name: string;
  description?: string;
  /** substring keywords for the quick-reject prefilter (cheap gate before regex). */
  keywords: string[];
  safePatterns: SafeRule[];
  destructivePatterns: DestructiveRule[];
  /** force-enabled regardless of config (DCG floor: e.g. core.*, system.disk). */
  force?: boolean;
  /**
   * Imperative pre-checks run, in order, BEFORE safePatterns for this pack.
   * First one to return a decision short-circuits. Used for argv-aware rules
   * (rm/cp/ln/rsync) that a single regex cannot express correctly.
   */
  imperative?: ImperativeCheck[];
}

/** Options for a single evaluation. */
export interface EvaluateOptions {
  /** hard cap on input length; bites BEFORE the wall-clock budget (ReDoS guard ordering). */
  inputMaxLength?: number;
  /** per-pattern wall-clock budget in ms. */
  perMatchBudgetMs?: number;
  /** when armed (degraded), a match error/timeout must fail CLOSED, not open. */
  failClosed?: boolean;
}

// ---------------------------------------------------------------------------
// External (on-disk) pack wire format — snake_case, DCG-compatible.
// ---------------------------------------------------------------------------

export interface ExternalSuggestion {
  command: string;
  description?: string;
  /** "all" | "linux" | "macos" | "windows" | "bsd" (default "all"). */
  platform?: Platform;
}

export interface ExternalDestructivePattern {
  name: string;
  pattern: string;
  /** default "high". */
  severity?: Severity;
  description?: string;
  explanation?: string;
  suggestions?: ExternalSuggestion[];
}

export interface ExternalSafePattern {
  name: string;
  pattern: string;
  description?: string;
}

export interface ExternalPack {
  /** default 1, max 1. */
  schema_version?: number;
  /** must match `^[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*$`. */
  id: string;
  name: string;
  /** must match `^\d+\.\d+\.\d+$`. */
  version: string;
  description?: string;
  keywords?: string[];
  destructive_patterns?: ExternalDestructivePattern[];
  safe_patterns?: ExternalSafePattern[];
}

/** Map a severity to its default decision mode (critical/high => deny, medium => warn, low => log). */
export function severityToMode(sev: Severity): DecisionMode {
  switch (sev) {
    case "critical":
    case "high":
      return "deny";
    case "medium":
      return "warn";
    case "low":
      return "log";
  }
}

/** Build a public rule id from pack + rule name. */
export function ruleId(packId: string, ruleName: string): string {
  return `${packId}:${ruleName}`;
}

/** Recover (packId, ruleName) from a rule id, splitting on the FIRST ":". */
export function parseRuleId(id: string): { packId: string; ruleName: string } {
  const i = id.indexOf(":");
  if (i < 0) return { packId: id, ruleName: "" };
  return { packId: id.slice(0, i), ruleName: id.slice(i + 1) };
}
