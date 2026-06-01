import { existsSync } from "node:fs";
import { readFile } from "node:fs/promises";
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

export async function loadConfig(cwd: string): Promise<GuardrailsConfig> {
  for (const relativePath of CONFIG_PATHS) {
    const absolutePath = join(cwd, relativePath);
    if (existsSync(absolutePath)) {
      try {
        const content = await readFile(absolutePath, "utf-8");
        const parsed = JSON.parse(
          stripJsonComments(content),
        ) as Partial<GuardrailsConfig>;
        return mergeConfig(parsed);
      } catch (error) {
        console.warn(
          `[guardrails] Failed to parse config at ${absolutePath}: ${error}`,
        );
      }
    }
  }

  return { ...DEFAULT_CONFIG };
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

function stripJsonComments(content: string): string {
  return content
    .split("\n")
    .map((line) => {
      const commentIndex = line.indexOf("//");
      return commentIndex >= 0 ? line.slice(0, commentIndex) : line;
    })
    .join("\n");
}
