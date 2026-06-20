/** The only fields model gating reads. GuardrailsConfig satisfies this. */
export interface ModelGatingLists {
  modelWhitelist?: string[];
  modelBlacklist?: string[];
}

/**
 * Should the guardrails ENGINE apply to a session running `modelId`?
 *
 * This scopes WHICH models get guarded (not which models may run): a blacklisted
 * model is left ungoverned; with a whitelist, ONLY whitelisted models are
 * guarded; with neither, every model is guarded. Exact-id match only.
 */
export function shouldGuardrailModel(
  modelId: string | undefined,
  config: ModelGatingLists,
): boolean {
  if (!modelId) {
    return false;
  }

  // Exact-id match only. v0.1.7's loose substring match
  // (modelId.includes(m) || m.includes(modelId)) caused both false matches
  // (e.g. "gpt-5" matching "gpt-5.2", "glm-5.1" matching "glm-5.2") and
  // accidental shielding. The guard must be unambiguous about which model id a
  // rule applies to.

  // Blacklist takes precedence.
  if (config.modelBlacklist?.includes(modelId)) {
    return false;
  }

  // If a whitelist is specified, only guardrail models on it.
  if (config.modelWhitelist && config.modelWhitelist.length > 0) {
    return config.modelWhitelist.includes(modelId);
  }

  // No whitelist => guardrail all models (except blacklisted).
  return true;
}
