import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { analyzeForViolation } from "./analyzer.ts";
import { loadConfig } from "./config.ts";
import { shouldGuardrailModel } from "./model-filter.ts";
import { checkPatternRules } from "./pattern-rules.ts";
import { shouldBlockToolCall } from "./tool-guard.ts";
import { TurnTracker } from "./turn-tracker.ts";
import type { GuardrailsConfig, MessageEntry, Violation } from "./types.ts";

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
  const messages: MessageEntry[] = [];
  let isAnalyzing = false;

  pi.on("session_start", async (_event, ctx) => {
    config = await loadConfig(ctx.cwd);
    turnTracker = new TurnTracker(config.samplingInterval ?? 1);
    messages.length = 0;
    isAnalyzing = false;

    ctx.ui.notify("Model Guardrails loaded", "info");
  });

  pi.on("message_start", async (event) => {
    if (event.message.role === "user") {
      messages.push({
        role: event.message.role,
        content:
          typeof event.message.content === "string"
            ? event.message.content
            : JSON.stringify(event.message.content),
      });
    }
  });

  pi.on("message_end", async (event, ctx) => {
    if (event.message.role !== "assistant") {
      return;
    }

    const content =
      typeof event.message.content === "string"
        ? event.message.content
        : JSON.stringify(event.message.content);
    messages.push({
      role: "assistant",
      content,
    });
    const assistantMessage = event.message as typeof event.message & {
      role: "assistant";
    };

    // Check model filtering
    const modelId = ctx.model?.id;
    if (!shouldGuardrailModel(modelId, config)) {
      return;
    }

    // Check sampling interval
    if (!turnTracker.recordTurn()) {
      return;
    }

    // Check pattern rules first (fast, local, no LLM call)
    const patternViolations =
      config.patternRules && config.patternRules.length > 0
        ? checkPatternRules(config.patternRules, messages)
        : [];

    // Check LLM-based violations
    if (isAnalyzing) {
      return;
    }

    isAnalyzing = true;
    try {
      const llmViolation = await analyzeForViolation(config, messages, ctx);
      const allViolations: Violation[] = [
        ...patternViolations,
        ...(llmViolation ? [llmViolation] : []),
      ];

      if (allViolations.length > 0) {
        const _highestConfidence = allViolations.reduce(
          (max, v) => Math.max(max, v.confidence),
          0,
        );
        const primary = allViolations[0];

        // Show notification
        const ruleNames = allViolations
          .map((v) => v.violatedInstruction)
          .join("; ");
        ctx.ui.notify(`Guardrails: ${primary.correctionMessage}`, "warning");

        // Show status
        ctx.ui.setStatus(
          "guardrails",
          `⚠️ ${ruleNames.slice(0, 40)}${ruleNames.length > 40 ? "..." : ""}`,
        );

        // Replace the assistant message with a corrected version
        const correctedText = buildCorrectedMessage(content, allViolations);
        const correctedContent = [
          { type: "text" as const, text: correctedText },
        ];
        return {
          message: {
            ...assistantMessage,
            content: correctedContent,
          },
        };
      }
    } catch (error) {
      console.warn("[guardrails] Analysis error:", error);
    } finally {
      isAnalyzing = false;
    }

    return;
  });

  pi.on("tool_call", async (event, ctx) => {
    if (!config?.toolGuards?.enabled) {
      return;
    }

    const modelId = ctx.model?.id;
    if (!shouldGuardrailModel(modelId, config)) {
      return;
    }

    const blockResult = shouldBlockToolCall(
      event.toolName,
      event.input as Record<string, unknown>,
      config.toolGuards,
    );

    if (blockResult.blocked) {
      ctx.ui.notify(`Guardrails blocked tool: ${blockResult.reason}`, "error");
      return { block: true, reason: blockResult.reason };
    }

    return;
  });

  pi.on("tool_execution_end", async (event) => {
    messages.push({
      role: "tool",
      content:
        typeof event.result.content === "string"
          ? event.result.content
          : JSON.stringify(event.result.content),
      toolName: event.toolName,
    });
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
