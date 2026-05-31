import type { GuardrailsConfig } from "./types.ts";

export function shouldGuardrailModel(
  modelId: string | undefined,
  config: GuardrailsConfig,
): boolean {
  if (!modelId) {
    return false;
  }

  // Blacklist takes precedence
  if (config.modelBlacklist && config.modelBlacklist.length > 0) {
    if (
      config.modelBlacklist.some(
        (m) => modelId.includes(m) || m.includes(modelId),
      )
    ) {
      return false;
    }
  }

  // If whitelist is specified, only guardrail whitelisted models
  if (config.modelWhitelist && config.modelWhitelist.length > 0) {
    return config.modelWhitelist.some(
      (m) => modelId.includes(m) || m.includes(modelId),
    );
  }

  // If no whitelist, guardrail all models (except blacklisted)
  return true;
}
