import { existsSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { homedir } from "node:os";
import { join } from "node:path";
import type { GuardrailsConfig } from "./types.ts";

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

function stripJsonComments(content: string): string {
  return content
    .split("\n")
    .map((line) => {
      const commentIndex = line.indexOf("//");
      return commentIndex >= 0 ? line.slice(0, commentIndex) : line;
    })
    .join("\n");
}
