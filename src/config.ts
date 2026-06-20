import { existsSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { homedir } from "node:os";
import { join } from "node:path";
import { cicdPack } from "./engine/packs/cicd.ts";
import { containersPack } from "./engine/packs/containers.ts";
import { coreFilesystemPack } from "./engine/packs/core-filesystem.ts";
import { coreGitPack } from "./engine/packs/core-git.ts";
import { infrastructurePack } from "./engine/packs/infrastructure.ts";
import { kubernetesPack } from "./engine/packs/kubernetes.ts";
import { packageManagersPack } from "./engine/packs/package-managers.ts";
import { platformPack } from "./engine/packs/platform.ts";
import { remotePack } from "./engine/packs/remote.ts";
import { systemPack } from "./engine/packs/system.ts";
import { validateRegexSafety } from "./engine/regex-safety.ts";
import { buildRegistry, type Registry } from "./engine/registry.ts";
import type { EvaluateOptions } from "./engine/types.ts";
import {
  createNoopTelemetry,
  createTelemetry,
  type GuardrailsTelemetry,
} from "./observability.ts";
import { defaultPolicyConfig } from "./policy/engine.ts";
import type {
  AllowEntry,
  Constraint,
  ConstraintSeverity,
  PolicyConfig,
} from "./policy/types.ts";
import { defaultMachineConfig } from "./state/machine.ts";
import type { MachineConfig } from "./state/types.ts";
import type {
  GraderConfig,
  GraderConfigFile,
  GuardConfigFile,
  GuardrailsConfig,
  GuardrailsObservabilityConfig,
  MachineConfigFile,
  PolicyConfigFile,
} from "./types.ts";

// ===========================================================================
// Phase 2 deterministic guard config (the new entry point).
//
// loadGuardConfig() returns the RUNTIME objects the deterministic guard
// consumes: a built Registry (compiled RegExp packs), a resolved PolicyConfig,
// a MachineConfig, EvaluateOptions, telemetry, and optional model filters.
//
// Layered, deep-merged load:
//   1. global  ~/.pi/agent/guardrails.json  (or $PI_CODING_AGENT_DIR/guardrails.json,
//      or $PI_MODEL_GUARDRAILS_CONFIG override)
//   2. project  <cwd>/.pi/guardrails.json
// The project layer overrides the global layer.
// ===========================================================================

/** The runtime config the Phase 2 guard actually consumes. */
export interface GuardRuntimeConfig {
  /** Built pack registry (compiled RegExp). Defaults to the core git + filesystem packs. */
  registry: Registry;
  /** Resolved policy engine config (defaults to defaultPolicyConfig()). */
  policy: PolicyConfig;
  /** State-machine tunables (defaults to defaultMachineConfig()). */
  machineConfig: MachineConfig;
  /** Engine evaluation options (input cap / per-match budget). */
  evaluateOptions: EvaluateOptions;
  /** Local telemetry sink (noop when observability disabled). */
  observability: GuardrailsTelemetry;
  /** Phase 3 LLM degraded-mode grader config (env already resolved). */
  grader: GraderConfig;
  /** Models to guardrail (reserved for the future LLM layer). */
  modelWhitelist?: string[];
  /** Models to skip (reserved for the future LLM layer). */
  modelBlacklist?: string[];
}

export interface LoadGuardConfigOptions {
  /** Set false to skip global config, or a string to force a specific global config file. */
  globalConfigPath?: string | false;
}

const GUARD_PROJECT_PATH = ".pi/guardrails.json";

/**
 * Load the Phase 2 deterministic-guard runtime config.
 *
 * Reads the global then project guardrails.json (string-aware JSONC),
 * deep-merges them, maps the wire shape onto runtime objects, and falls back to
 * defaultPolicyConfig()/defaultMachineConfig()/the core packs for anything
 * missing. Never throws on a bad/missing file — it warns and uses defaults so a
 * broken config can never wedge the session.
 */
export async function loadGuardConfig(
  cwd: string,
  options: LoadGuardConfigOptions = {},
): Promise<GuardRuntimeConfig> {
  const partials: Partial<GuardConfigFile>[] = [];

  for (const absolutePath of guardConfigPaths(cwd, options)) {
    if (!existsSync(absolutePath)) continue;
    try {
      const content = await readFile(absolutePath, "utf-8");
      partials.push(
        JSON.parse(stripJsonComments(content)) as Partial<GuardConfigFile>,
      );
    } catch (error) {
      console.warn(
        `[guardrails] Failed to parse guard config at ${absolutePath}: ${error}`,
      );
    }
  }

  const merged = partials.reduce<Partial<GuardConfigFile>>(
    (acc, next) => deepMerge(acc, next),
    {},
  );

  // Built-in pack registry. Declaration order is load-bearing for cross-pack
  // attribution (strictest-wins ties break by order): the core floor packs first,
  // then the breadth packs. Loading arbitrary EXTERNAL packs from config is a
  // later phase; this built-in set is always present.
  const registry = buildRegistry([
    coreGitPack,
    coreFilesystemPack,
    systemPack,
    packageManagersPack,
    containersPack,
    kubernetesPack,
    infrastructurePack,
    remotePack,
    platformPack,
    cicdPack,
  ]);

  return {
    registry,
    policy: toPolicyConfig(merged.policy),
    machineConfig: toMachineConfig(merged.machine),
    evaluateOptions: toEvaluateOptions(merged.evaluate),
    observability: toTelemetry(cwd, merged.observability),
    grader: toGraderConfig(merged.grader),
    modelWhitelist: toStringArray(merged.modelWhitelist),
    modelBlacklist: toStringArray(merged.modelBlacklist),
  };
}

/**
 * Coerce an untrusted config value to a string[] or undefined. A misconfigured
 * `modelWhitelist`/`modelBlacklist` (a string, number, object, …) would
 * otherwise reach `shouldGuardrailModel` and throw on `.includes()`, crashing
 * the guard. Non-arrays => undefined; arrays are filtered to string elements.
 */
function toStringArray(value: unknown): string[] | undefined {
  if (!Array.isArray(value)) return undefined;
  return value.filter((v): v is string => typeof v === "string");
}

/** Default grader runtime config (the documented Phase 3 defaults). */
export function defaultGraderConfig(): GraderConfig {
  return {
    enabled: true,
    model: "gemini-3.5-flash",
    timeoutMs: 8000,
    maxTokens: 512,
    maxRetries: 1,
    temperature: 0.1,
    cache: true,
  };
}

/**
 * Map the wire grader block onto the runtime GraderConfig, reading secrets from
 * env (apiKeyEnv / baseUrlEnv) — never inline. Falls back to defaultGraderConfig
 * for anything missing/malformed so a broken grader block can't wedge the load.
 */
function toGraderConfig(wire: GraderConfigFile | undefined): GraderConfig {
  const base = defaultGraderConfig();
  if (!wire) return base;

  const baseUrl =
    (wire.baseUrlEnv && process.env[wire.baseUrlEnv]) ||
    wire.baseUrl ||
    undefined;
  const apiKey =
    wire.apiKeyEnv && process.env[wire.apiKeyEnv]
      ? process.env[wire.apiKeyEnv]
      : undefined;

  return {
    enabled: boolOr(wire.enabled, base.enabled),
    model:
      typeof wire.model === "string" && wire.model.trim()
        ? wire.model
        : base.model,
    fallbackModel:
      typeof wire.fallbackModel === "string" && wire.fallbackModel.trim()
        ? wire.fallbackModel
        : undefined,
    baseUrl,
    apiKey,
    timeoutMs: numberOr(wire.timeoutMs, base.timeoutMs),
    maxTokens: numberOr(wire.maxTokens, base.maxTokens),
    maxRetries: numberOr(wire.maxRetries, base.maxRetries),
    temperature: numberOr(wire.temperature, base.temperature),
    cache: boolOr(wire.cache, base.cache),
  };
}

function guardConfigPaths(
  cwd: string,
  options: LoadGuardConfigOptions,
): string[] {
  const paths: string[] = [];

  if (options.globalConfigPath !== false) {
    paths.push(
      options.globalConfigPath ??
        process.env.PI_MODEL_GUARDRAILS_CONFIG ??
        join(
          process.env.PI_CODING_AGENT_DIR ?? join(homedir(), ".pi", "agent"),
          "guardrails.json",
        ),
    );
  }

  paths.push(join(cwd, GUARD_PROJECT_PATH));
  return [...new Set(paths)];
}

// ---------------------------------------------------------------------------
// Wire -> runtime mappers. Each falls back to the safe default for missing or
// malformed input (hand-validated; no zod, no new deps).
// ---------------------------------------------------------------------------

function toEvaluateOptions(wire: GuardConfigFile["evaluate"]): EvaluateOptions {
  const opts: EvaluateOptions = {};
  if (typeof wire?.inputMaxLength === "number") {
    opts.inputMaxLength = wire.inputMaxLength;
  }
  if (typeof wire?.perMatchBudgetMs === "number") {
    opts.perMatchBudgetMs = wire.perMatchBudgetMs;
  }
  // failClosed is set per-call by the guard (armed => closed); never from config.
  return opts;
}

function toPolicyConfig(wire: PolicyConfigFile | undefined): PolicyConfig {
  const base = defaultPolicyConfig();
  if (!wire) return base;

  const decisionModes = new Set(["deny", "warn", "log", "allow"]);
  const defaultMode =
    wire.defaultMode && decisionModes.has(wire.defaultMode)
      ? wire.defaultMode
      : base.defaultMode;

  const rules: PolicyConfig["rules"] = {};
  if (wire.rules && typeof wire.rules === "object") {
    for (const [ruleId, mode] of Object.entries(wire.rules)) {
      if (typeof mode === "string" && decisionModes.has(mode)) {
        rules[ruleId] = mode;
      }
    }
  }

  return {
    defaultMode,
    observeUntil:
      typeof wire.observeUntil === "number" ? wire.observeUntil : undefined,
    inviolable: Array.isArray(wire.inviolable)
      ? wire.inviolable.filter((g): g is string => typeof g === "string")
      : base.inviolable,
    rules,
    constraints: toConstraints(wire.constraints),
    allowlist: toAllowlist(wire.allowlist),
  };
}

/**
 * Validate an untrusted constraint `detect.regex` AT LOAD. A non-string is
 * dropped silently (no detector). A ReDoS-prone / non-compiling pattern is
 * dropped with a LOUD warning — refusing it here is the only real defense, since
 * a catastrophic regex can block synchronously before any runtime budget bites.
 */
function safeConstraintRegex(
  regex: unknown,
  constraintId: string,
): string | undefined {
  if (typeof regex !== "string") return undefined;
  const verdict = validateRegexSafety(regex);
  if (!verdict.ok) {
    console.warn(
      `[guardrails] constraint "${constraintId}" detect.regex REJECTED at load ` +
        `(${verdict.reason}). The constraint keeps any ruleIds detector but its ` +
        "regex is dropped. Simplify the pattern to re-enable it.",
    );
    return undefined;
  }
  return regex;
}

function toConstraints(raw: unknown[] | undefined): Constraint[] {
  if (!Array.isArray(raw)) return [];
  const severities = new Set<ConstraintSeverity>([
    "inviolable",
    "critical",
    "high",
    "medium",
    "low",
  ]);
  const out: Constraint[] = [];
  for (const item of raw) {
    if (!item || typeof item !== "object") continue;
    const c = item as Record<string, unknown>;
    if (
      typeof c.id !== "string" ||
      typeof c.title !== "string" ||
      typeof c.statement !== "string" ||
      typeof c.severity !== "string" ||
      !severities.has(c.severity as ConstraintSeverity)
    ) {
      continue;
    }
    const detect =
      c.detect && typeof c.detect === "object"
        ? (c.detect as { ruleIds?: unknown; regex?: unknown })
        : undefined;
    out.push({
      id: c.id,
      title: c.title,
      statement: c.statement,
      severity: c.severity as ConstraintSeverity,
      allowlistable:
        typeof c.allowlistable === "boolean" ? c.allowlistable : undefined,
      appliesWhen:
        typeof c.appliesWhen === "string" ? c.appliesWhen : undefined,
      requiredBehavior:
        typeof c.requiredBehavior === "string" ? c.requiredBehavior : undefined,
      detect: detect
        ? {
            ruleIds: Array.isArray(detect.ruleIds)
              ? detect.ruleIds.filter((r): r is string => typeof r === "string")
              : undefined,
            regex: safeConstraintRegex(detect.regex, c.id),
          }
        : undefined,
    });
  }
  return out;
}

function toAllowlist(raw: unknown[] | undefined): AllowEntry[] {
  if (!Array.isArray(raw)) return [];
  const out: AllowEntry[] = [];
  for (const item of raw) {
    if (!item || typeof item !== "object") continue;
    const e = item as Record<string, unknown>;
    if (typeof e.rule !== "string" || typeof e.reason !== "string") continue;
    out.push({
      rule: e.rule,
      reason: e.reason,
      ttl: typeof e.ttl === "number" ? e.ttl : undefined,
      paths: Array.isArray(e.paths)
        ? e.paths.filter((p): p is string => typeof p === "string")
        : undefined,
      riskAcknowledged:
        typeof e.riskAcknowledged === "boolean"
          ? e.riskAcknowledged
          : undefined,
    });
  }
  return out;
}

function toMachineConfig(
  wire: Partial<MachineConfigFile> | undefined,
): MachineConfig {
  const base = defaultMachineConfig();
  if (!wire) return base;
  return {
    watchCleanStreak: numberOr(wire.watchCleanStreak, base.watchCleanStreak),
    gatedCleanStreak: numberOr(wire.gatedCleanStreak, base.gatedCleanStreak),
    recoveringWatermark: numberOr(
      wire.recoveringWatermark,
      base.recoveringWatermark,
    ),
    cooldownTurns: numberOr(wire.cooldownTurns, base.cooldownTurns),
    gateOnlyMutatingInWatch: boolOr(
      wire.gateOnlyMutatingInWatch,
      base.gateOnlyMutatingInWatch,
    ),
    nonTrivialOnly: boolOr(wire.nonTrivialOnly, base.nonTrivialOnly),
    haltRequiresHumanAck: boolOr(
      wire.haltRequiresHumanAck,
      base.haltRequiresHumanAck,
    ),
  };
}

function toTelemetry(
  cwd: string,
  wire: GuardrailsObservabilityConfig | undefined,
): GuardrailsTelemetry {
  if (wire?.enabled === false) {
    return createNoopTelemetry();
  }
  return createTelemetry(cwd, wire);
}

function numberOr(value: unknown, fallback: number): number {
  return typeof value === "number" && Number.isFinite(value) ? value : fallback;
}

function boolOr(value: unknown, fallback: boolean): boolean {
  return typeof value === "boolean" ? value : fallback;
}

// ===========================================================================
// Legacy loader (kept for the LLM-layer config consumers + existing tests).
// ===========================================================================

const DEFAULT_CONFIG: GuardrailsConfig = {
  analysisModel: "gpt-4o-mini",
  samplingInterval: 1,
  confidenceThreshold: 0.7,
  toolGuards: {
    enabled: true,
    blockedTools: [],
    blockedPatterns: [],
    explicitToolContractsEnabled: true,
    providerMismatchMode: "deny",
    toolContracts: [],
    providerDetectors: [],
  },
  patternRules: [],
  patternRulesEnabled: false,
  policyRules: [],
  observability: {
    enabled: true,
    logFile: ".pi/model-guardrails/events.jsonl",
    logMessageUpdates: false,
  },
};

const CONFIG_PATHS = [
  ".pi/guardrails.json",
  ".pi/guardrails.jsonc",
  ".pi/guardrails.config.json",
  ".config/pi/guardrails.json",
  ".config/pi/guardrails.jsonc",
  ".config/pi/guardrails.config.json",
];

export interface LoadConfigOptions {
  /** Set false to skip global config, or a string to force a specific global config file. */
  globalConfigPath?: string | false;
}

export async function loadConfig(
  cwd: string,
  options: LoadConfigOptions = {},
): Promise<GuardrailsConfig> {
  const partials: Partial<GuardrailsConfig>[] = [];

  for (const absolutePath of configPaths(cwd, options)) {
    if (!existsSync(absolutePath)) continue;
    try {
      const content = await readFile(absolutePath, "utf-8");
      partials.push(
        JSON.parse(stripJsonComments(content)) as Partial<GuardrailsConfig>,
      );
    } catch (error) {
      console.warn(
        `[guardrails] Failed to parse config at ${absolutePath}: ${error}`,
      );
    }
  }

  const partial = partials.reduce<Partial<GuardrailsConfig>>(
    (merged, next) => deepMerge(merged, next),
    {},
  );

  return mergeConfig(partial);
}

function mergeConfig(partial: Partial<GuardrailsConfig>): GuardrailsConfig {
  return {
    analysisModel: partial.analysisModel ?? DEFAULT_CONFIG.analysisModel,
    modelWhitelist: partial.modelWhitelist ?? DEFAULT_CONFIG.modelWhitelist,
    modelBlacklist: partial.modelBlacklist ?? DEFAULT_CONFIG.modelBlacklist,
    samplingInterval:
      partial.samplingInterval ?? DEFAULT_CONFIG.samplingInterval,
    confidenceThreshold:
      partial.confidenceThreshold ?? DEFAULT_CONFIG.confidenceThreshold,
    toolGuards: {
      enabled: partial.toolGuards?.enabled ?? DEFAULT_CONFIG.toolGuards.enabled,
      blockedTools:
        partial.toolGuards?.blockedTools ??
        DEFAULT_CONFIG.toolGuards.blockedTools,
      blockedPatterns:
        partial.toolGuards?.blockedPatterns ??
        DEFAULT_CONFIG.toolGuards.blockedPatterns,
      explicitToolContractsEnabled:
        partial.toolGuards?.explicitToolContractsEnabled ??
        DEFAULT_CONFIG.toolGuards.explicitToolContractsEnabled,
      providerMismatchMode:
        partial.toolGuards?.providerMismatchMode ??
        DEFAULT_CONFIG.toolGuards.providerMismatchMode,
      toolContracts:
        partial.toolGuards?.toolContracts ??
        DEFAULT_CONFIG.toolGuards.toolContracts,
      providerDetectors:
        partial.toolGuards?.providerDetectors ??
        DEFAULT_CONFIG.toolGuards.providerDetectors,
    },
    patternRules: partial.patternRules ?? DEFAULT_CONFIG.patternRules,
    patternRulesEnabled:
      partial.patternRulesEnabled ?? DEFAULT_CONFIG.patternRulesEnabled,
    policyRules: partial.policyRules ?? DEFAULT_CONFIG.policyRules,
    observability: {
      enabled:
        partial.observability?.enabled ?? DEFAULT_CONFIG.observability?.enabled,
      logFile:
        partial.observability?.logFile ?? DEFAULT_CONFIG.observability?.logFile,
      logMessageUpdates:
        partial.observability?.logMessageUpdates ??
        DEFAULT_CONFIG.observability?.logMessageUpdates,
    },
  };
}

function configPaths(cwd: string, options: LoadConfigOptions): string[] {
  const paths: string[] = [];

  if (options.globalConfigPath !== false) {
    paths.push(
      options.globalConfigPath ??
        process.env.PI_MODEL_GUARDRAILS_CONFIG ??
        join(
          process.env.PI_CODING_AGENT_DIR ?? join(homedir(), ".pi", "agent"),
          "guardrails.json",
        ),
    );
  }

  paths.push(...CONFIG_PATHS.map((relativePath) => join(cwd, relativePath)));
  return [...new Set(paths)];
}

// ===========================================================================
// Shared helpers.
// ===========================================================================

function deepMerge<T extends Record<string, unknown>>(base: T, overlay: T): T {
  const result: Record<string, unknown> = { ...base };

  for (const [key, value] of Object.entries(overlay)) {
    const existing = result[key];
    if (isPlainRecord(existing) && isPlainRecord(value)) {
      result[key] = deepMerge(existing, value);
    } else {
      result[key] = value;
    }
  }

  return result as T;
}

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === "object" && !Array.isArray(value);
}

/**
 * String-aware JSONC comment stripper.
 *
 * Replaces the old line-based stripper, which treated ANY `//` as a comment —
 * including `//` inside a JSON string value (e.g. a URL like
 * "https://example.com") — and silently corrupted the parse. This walks the
 * input char-by-char, tracks whether we are inside a double-quoted string
 * (honoring backslash escapes), and only strips `//` line comments and
 * `/* ... *​/` block comments when OUTSIDE a string. Commented-out spans are
 * replaced with spaces so character offsets in parse errors stay meaningful.
 */
export function stripJsonComments(content: string): string {
  let out = "";
  let inString = false;
  let escaped = false;
  let i = 0;
  const n = content.length;

  while (i < n) {
    const ch = content[i];

    if (inString) {
      out += ch;
      if (escaped) {
        escaped = false;
      } else if (ch === "\\") {
        escaped = true;
      } else if (ch === '"') {
        inString = false;
      }
      i++;
      continue;
    }

    // Outside a string.
    if (ch === '"') {
      inString = true;
      out += ch;
      i++;
      continue;
    }

    if (ch === "/" && i + 1 < n && content[i + 1] === "/") {
      // Line comment: skip to (but keep) the newline.
      i += 2;
      while (i < n && content[i] !== "\n") i++;
      continue;
    }

    if (ch === "/" && i + 1 < n && content[i + 1] === "*") {
      // Block comment: skip to the closing */, preserving newlines so line
      // numbers in subsequent parse errors stay accurate.
      i += 2;
      while (i < n && !(content[i] === "*" && content[i + 1] === "/")) {
        if (content[i] === "\n") out += "\n";
        i++;
      }
      i += 2; // consume the closing */
      continue;
    }

    out += ch;
    i++;
  }

  return out;
}
