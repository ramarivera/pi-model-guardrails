import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { analyzeForViolation } from "./analyzer.ts";
import { loadConfig } from "./config.ts";
import { shouldGuardrailModel } from "./model-filter.ts";
import {
  createNoopTelemetry,
  createTelemetry,
  type GuardrailsTelemetry,
} from "./observability.ts";
import { checkPatternRules } from "./pattern-rules.ts";
import {
  describeActiveToolContract,
  extractToolContracts,
  mergeToolContracts,
  shouldBlockToolCall,
} from "./tool-guard.ts";
import { TurnTracker } from "./turn-tracker.ts";
import type {
  ActiveToolContract,
  GuardrailsConfig,
  MessageEntry,
  Violation,
} from "./types.ts";

export type ExtensionInfo = {
  name: string;
  description: string;
};

export const extensionInfo: ExtensionInfo = {
  name: "model-guardrails",
  description:
    "Opinionated model guardrails that detect instruction violations and course-correct",
};

export function createExtension() {
  return {
    name: extensionInfo.name,
    async activate() {
      return extensionInfo;
    },
  };
}

export default function guardrailsExtension(pi: ExtensionAPI): void {
  let config: GuardrailsConfig;
  let turnTracker: TurnTracker;
  let telemetry: GuardrailsTelemetry = createNoopTelemetry();
  const messages: MessageEntry[] = [];
  let activeToolContracts: ActiveToolContract[] = [];
  let isAnalyzing = false;

  pi.on("session_start", async (event, ctx) => {
    config = await loadConfig(ctx.cwd);
    telemetry = createTelemetry(ctx.cwd, config.observability);

    await telemetry.runSpan(
      "Guardrails.session_start",
      contextTags(ctx, {
        reason: event.reason,
        observabilityEnabled: telemetry.enabled,
        logFile: telemetry.logFile,
      }),
      async () => {
        turnTracker = new TurnTracker(config.samplingInterval ?? 1);
        messages.length = 0;
        activeToolContracts = [];
        isAnalyzing = false;

        await telemetry.logEvent("config_loaded", {
          samplingInterval: config.samplingInterval,
          confidenceThreshold: config.confidenceThreshold,
          toolGuardsEnabled: config.toolGuards.enabled,
          blockedTools: config.toolGuards.blockedTools ?? [],
          blockedPatterns: config.toolGuards.blockedPatterns ?? [],
          explicitToolContractsEnabled:
            config.toolGuards.explicitToolContractsEnabled,
          providerMismatchMode: config.toolGuards.providerMismatchMode,
          patternRulesEnabled: config.patternRulesEnabled,
          patternRuleCount: config.patternRules.length,
          policyRuleCount: config.policyRules.length,
          analysisModel: config.analysisModel,
        });

        ctx.ui.notify("Model Guardrails loaded", "info");
        ctx.ui.setStatus(
          "guardrails",
          telemetry.enabled ? "🔒 observing" : "🔒 loaded",
        );
      },
    );
  });

  pi.on("session_shutdown", async (event, ctx) => {
    await telemetry.logEvent(
      "session_shutdown",
      contextTags(ctx, {
        reason: event.reason,
        targetSessionFile: event.targetSessionFile,
        trackedMessages: messages.length,
      }),
    );
  });

  pi.on("before_agent_start", async (event, ctx) => {
    await telemetry.runSpan(
      "Guardrails.before_agent_start",
      contextTags(ctx, {
        promptLength: event.prompt.length,
        imageCount: event.images?.length ?? 0,
        systemPromptLength: event.systemPrompt.length,
        selectedTools: event.systemPromptOptions.selectedTools,
        skillCount: event.systemPromptOptions.skills?.length ?? 0,
        contextFileCount: event.systemPromptOptions.contextFiles?.length ?? 0,
      }),
      async () => undefined,
    );
  });

  pi.on("agent_start", async (_event, ctx) => {
    await telemetry.logEvent(
      "agent_start",
      contextTags(ctx, {
        trackedMessages: messages.length,
      }),
    );
  });

  pi.on("agent_end", async (event, ctx) => {
    await telemetry.logEvent(
      "agent_end",
      contextTags(ctx, {
        agentMessageCount: event.messages.length,
        trackedMessages: messages.length,
      }),
    );
  });

  pi.on("turn_start", async (event, ctx) => {
    await telemetry.logEvent(
      "turn_start",
      contextTags(ctx, {
        turnIndex: event.turnIndex,
        timestamp: event.timestamp,
      }),
    );
  });

  pi.on("turn_end", async (event, ctx) => {
    await telemetry.logEvent(
      "turn_end",
      contextTags(ctx, {
        turnIndex: event.turnIndex,
        toolResultCount: event.toolResults.length,
        messageRole: event.message.role,
        messageContent: describeContent(messageContent(event.message)),
      }),
    );
  });

  pi.on("message_start", async (event, ctx) => {
    await telemetry.runSpan(
      "Guardrails.message_start",
      contextTags(ctx, {
        role: event.message.role,
        content: describeContent(messageContent(event.message)),
      }),
      async () => {
        if (event.message.role === "user") {
          const content = contentToString(messageContent(event.message));
          messages.push({
            role: event.message.role,
            content,
          });

          const extractedContracts = extractToolContracts(content);
          if (extractedContracts.length > 0) {
            activeToolContracts = mergeToolContracts(
              activeToolContracts,
              extractedContracts,
            );
          }

          await telemetry.logEvent("message_tracked", {
            role: event.message.role,
            contentLength: content.length,
            trackedMessages: messages.length,
            extractedToolContracts: extractedContracts.map(
              describeActiveToolContract,
            ),
            activeToolContracts: activeToolContracts.map(
              describeActiveToolContract,
            ),
          });
        }
      },
    );
  });

  pi.on("message_update", async (event, ctx) => {
    if (!config?.observability?.logMessageUpdates) {
      return;
    }

    await telemetry.logEvent(
      "message_update",
      contextTags(ctx, {
        role: event.message.role,
        content: describeContent(messageContent(event.message)),
        assistantMessageEventKeys: Object.keys(
          event.assistantMessageEvent ?? {},
        ),
      }),
    );
  });

  pi.on("message_end", async (event, ctx) =>
    telemetry.runSpan(
      "Guardrails.message_end",
      contextTags(ctx, {
        role: event.message.role,
        content: describeContent(messageContent(event.message)),
        isAnalyzing,
      }),
      async () => {
        if (event.message.role !== "assistant") {
          await telemetry.logEvent("message_end_skipped", {
            reason: "non_assistant_message",
            role: event.message.role,
          });
          return;
        }

        const content = contentToString(messageContent(event.message));
        messages.push({
          role: "assistant",
          content,
        });
        const assistantMessage = event.message as typeof event.message & {
          role: "assistant";
        };

        const modelId = modelIdentifier(ctx);
        const modelGuarded = shouldGuardrailModel(modelId, config);
        await telemetry.logEvent("model_filter_checked", {
          modelId,
          guarded: modelGuarded,
          whitelist: config.modelWhitelist ?? [],
          blacklist: config.modelBlacklist ?? [],
        });
        if (!modelGuarded) {
          return;
        }

        const sampled = turnTracker.recordTurn();
        await telemetry.logEvent("sampling_checked", {
          sampled,
          turnCount: turnTracker.getTurnCount(),
          samplingInterval: config.samplingInterval ?? 1,
        });
        if (!sampled) {
          return;
        }

        const patternViolations =
          config.patternRulesEnabled &&
          config.patternRules &&
          config.patternRules.length > 0
            ? checkPatternRules(config.patternRules, messages)
            : [];
        await telemetry.logEvent("pattern_rules_checked", {
          enabled: config.patternRulesEnabled,
          ruleCount: config.patternRules.length,
          violationCount: patternViolations.length,
          violations: patternViolations.map(describeViolation),
        });

        if (isAnalyzing) {
          await telemetry.logEvent("analysis_skipped", {
            reason: "analysis_already_running",
          });
          return;
        }

        isAnalyzing = true;
        try {
          const llmViolation = await telemetry.runSpan(
            "Guardrails.analyze",
            {
              analysisModel: config.analysisModel,
              trackedMessages: messages.length,
              policyRuleCount: config.policyRules.length,
            },
            async () => analyzeForViolation(config, messages, ctx),
          );
          const allViolations: Violation[] = [
            ...patternViolations,
            ...(llmViolation ? [llmViolation] : []),
          ];

          await telemetry.logEvent("analysis_completed", {
            llmViolation: llmViolation ? describeViolation(llmViolation) : null,
            totalViolationCount: allViolations.length,
            violations: allViolations.map(describeViolation),
          });

          if (allViolations.length > 0) {
            const primary = allViolations[0];
            const ruleNames = allViolations
              .map((v) => v.violatedInstruction)
              .join("; ");
            ctx.ui.notify(
              `Guardrails: ${primary.correctionMessage}`,
              "warning",
            );
            ctx.ui.setStatus(
              "guardrails",
              `⚠️ ${ruleNames.slice(0, 40)}${ruleNames.length > 40 ? "..." : ""}`,
            );

            const correctedText = buildCorrectedMessage(content, allViolations);
            const correctedContent = [
              { type: "text" as const, text: correctedText },
            ];
            await telemetry.logEvent("assistant_message_corrected", {
              correctedContentLength: correctedText.length,
              primaryViolation: describeViolation(primary),
            });
            return {
              message: {
                ...assistantMessage,
                content: correctedContent,
              },
            };
          }
        } catch (error) {
          await telemetry.logEvent("analysis_error", {
            error: error instanceof Error ? error.message : String(error),
          });
          console.warn("[guardrails] Analysis error:", error);
        } finally {
          isAnalyzing = false;
        }

        return;
      },
    ),
  );

  pi.on("before_provider_request", async (event, ctx) => {
    await telemetry.logEvent(
      "before_provider_request",
      contextTags(ctx, {
        payloadKeys: objectKeys(event.payload),
      }),
    );
  });

  pi.on("after_provider_response", async (event, ctx) => {
    await telemetry.logEvent(
      "after_provider_response",
      contextTags(ctx, {
        status: event.status,
        headerKeys: Object.keys(event.headers ?? {}),
      }),
    );
  });

  pi.on("tool_execution_start", async (event, ctx) => {
    await telemetry.logEvent(
      "tool_execution_start",
      contextTags(ctx, {
        toolCallId: event.toolCallId,
        toolName: event.toolName,
        args: sanitizeToolInput(event.args),
      }),
    );
  });

  pi.on("tool_execution_update", async (event, ctx) => {
    await telemetry.logEvent(
      "tool_execution_update",
      contextTags(ctx, {
        toolCallId: event.toolCallId,
        toolName: event.toolName,
        args: sanitizeToolInput(event.args),
        partialResult: describeUnknown(event.partialResult),
      }),
    );
  });

  pi.on("tool_call", async (event, ctx) =>
    telemetry.runSpan(
      "Guardrails.tool_call",
      contextTags(ctx, {
        toolCallId: event.toolCallId,
        toolName: event.toolName,
        input: sanitizeToolInput(event.input),
      }),
      async () => {
        if (!config?.toolGuards?.enabled) {
          await telemetry.logEvent("tool_guard_skipped", {
            reason: "tool_guards_disabled_or_config_missing",
            toolName: event.toolName,
          });
          return;
        }

        const modelId = modelIdentifier(ctx);
        const modelGuarded = shouldGuardrailModel(modelId, config);
        await telemetry.logEvent("tool_call_model_filter_checked", {
          toolName: event.toolName,
          modelId,
          guarded: modelGuarded,
        });
        if (!modelGuarded) {
          return;
        }

        const blockResult = shouldBlockToolCall(
          event.toolName,
          event.input as Record<string, unknown>,
          config.toolGuards,
          activeToolContracts,
        );

        await telemetry.logEvent("tool_guard_decision", {
          schemaVersion: blockResult.schemaVersion,
          toolName: event.toolName,
          decision: blockResult.decision,
          blocked: blockResult.blocked,
          reason: blockResult.reason,
          ruleId: blockResult.ruleId,
          severity: blockResult.severity,
          confidence: blockResult.confidence,
          capability: blockResult.capability,
          requestedProvider: blockResult.requestedProvider,
          attemptedProvider: blockResult.attemptedProvider,
          remediation: blockResult.remediation,
          invocation: blockResult.invocation,
          activeToolContracts: activeToolContracts.map(
            describeActiveToolContract,
          ),
          blockedTools: config.toolGuards.blockedTools ?? [],
          blockedPatterns: config.toolGuards.blockedPatterns ?? [],
        });

        if (blockResult.blocked) {
          ctx.ui.notify(
            `Guardrails blocked tool: ${blockResult.reason}`,
            "error",
          );
          ctx.ui.setStatus("guardrails", "⛔ blocked tool");
          return { block: true, reason: blockResult.reason };
        }

        return;
      },
    ),
  );

  pi.on("tool_result", async (event, ctx) => {
    await telemetry.logEvent(
      "tool_result",
      contextTags(ctx, {
        toolCallId: event.toolCallId,
        toolName: event.toolName,
        input: sanitizeToolInput(event.input),
        isError: event.isError,
        content: describeContent(event.content),
        details: describeUnknown(event.details),
      }),
    );
  });

  pi.on("tool_execution_end", async (event, ctx) => {
    await telemetry.runSpan(
      "Guardrails.tool_execution_end",
      contextTags(ctx, {
        toolCallId: event.toolCallId,
        toolName: event.toolName,
        isError: event.isError,
        result: describeUnknown(event.result),
      }),
      async () => {
        const content = contentToString(event.result.content);
        messages.push({
          role: "tool",
          content,
          toolName: event.toolName,
        });
        await telemetry.logEvent("tool_message_tracked", {
          toolName: event.toolName,
          contentLength: content.length,
          trackedMessages: messages.length,
        });
      },
    );
  });
}

function buildCorrectedMessage(
  original: string,
  violations: Violation[],
): string {
  const correctionHeader = violations
    .map((v, i) => {
      const source =
        v.source === "pattern_rule" ? "[Pattern Rule]" : "[LLM Analysis]";
      return `${i + 1}. ${source} ${v.violatedInstruction}: ${v.whatModelDid}`;
    })
    .join("\n");

  const reasons = violations
    .map((v) => v.correctionMessage)
    .filter(Boolean)
    .join("; ");

  return `${original}

---

🔒 **Course corrected** because: ${reasons}

Guardrails detected ${violations.length} violation(s):
${correctionHeader}

The model should: ${violations[0]?.whatShouldHaveDone ?? "correct the above issues"}
`;
}

function messageContent(message: unknown): unknown {
  return message && typeof message === "object" && "content" in message
    ? (message as { content: unknown }).content
    : undefined;
}

function contentToString(content: unknown): string {
  return typeof content === "string" ? content : JSON.stringify(content);
}

function describeContent(content: unknown): Record<string, unknown> {
  if (typeof content === "string") {
    return {
      shape: "string",
      length: content.length,
      preview: preview(content),
    };
  }

  if (Array.isArray(content)) {
    return {
      shape: "array",
      length: content.length,
      blockTypes: content.map((block) =>
        block && typeof block === "object" && "type" in block
          ? String((block as { type: unknown }).type)
          : typeof block,
      ),
      textLength: content
        .map((block) =>
          block && typeof block === "object" && "text" in block
            ? String((block as { text: unknown }).text).length
            : 0,
        )
        .reduce((sum, length) => sum + length, 0),
      thinkingBlocks: content.filter(
        (block) =>
          block &&
          typeof block === "object" &&
          "type" in block &&
          (block as { type: unknown }).type === "thinking",
      ).length,
      toolCallBlocks: content.filter(
        (block) =>
          block &&
          typeof block === "object" &&
          "type" in block &&
          (block as { type: unknown }).type === "toolCall",
      ).length,
    };
  }

  return describeUnknown(content);
}

function describeUnknown(value: unknown): Record<string, unknown> {
  if (value === null) return { shape: "null" };
  if (value === undefined) return { shape: "undefined" };
  if (typeof value === "object") {
    return {
      shape: "object",
      keys: Object.keys(value),
    };
  }
  return {
    shape: typeof value,
    preview: preview(String(value)),
  };
}

function describeViolation(violation: Violation): Record<string, unknown> {
  return {
    source: violation.source,
    confidence: violation.confidence,
    violatedInstruction: violation.violatedInstruction,
    correctionMessage: violation.correctionMessage,
  };
}

function contextTags(
  ctx: {
    cwd?: string;
    model?: { provider?: string; id?: string };
    sessionManager?: { getSessionFile?: () => string | undefined };
  },
  tags: Record<string, unknown>,
): Record<string, unknown> {
  return {
    cwd: ctx.cwd,
    modelId: modelIdentifier(ctx),
    sessionFile: ctx.sessionManager?.getSessionFile?.(),
    ...tags,
  };
}

function modelIdentifier(ctx: {
  model?: { provider?: string; id?: string };
}): string | undefined {
  if (!ctx.model?.id) return undefined;
  return ctx.model.provider
    ? `${ctx.model.provider}/${ctx.model.id}`
    : ctx.model.id;
}

function sanitizeToolInput(input: unknown): unknown {
  if (!input || typeof input !== "object") return input;
  const redactedKeys = new Set([
    "apiKey",
    "api_key",
    "token",
    "password",
    "secret",
  ]);
  return Object.fromEntries(
    Object.entries(input as Record<string, unknown>).map(([key, value]) => [
      key,
      redactedKeys.has(key) ? "[redacted]" : value,
    ]),
  );
}

function objectKeys(value: unknown): string[] {
  return value && typeof value === "object" ? Object.keys(value) : [];
}

function preview(value: string): string {
  return value.length > 240 ? `${value.slice(0, 240)}…` : value;
}
