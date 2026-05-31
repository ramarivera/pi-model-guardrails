import type { ExtensionContext } from "@earendil-works/pi-coding-agent";
import { readActiveGoal } from "./goal-integration.ts";
import { analyzeConversation } from "./llm.ts";
import type { GuardrailsConfig, MessageEntry, Violation } from "./types.ts";

export async function analyzeForViolation(
  config: GuardrailsConfig,
  messages: MessageEntry[],
  ctx: ExtensionContext,
): Promise<Violation | null> {
  // Extract system instructions and user instructions
  const systemInstructions = extractSystemInstructions(messages);
  const appliedSkills = extractAppliedSkills(messages);
  const activeGoal = readActiveGoal(ctx);

  // Build conversation for LLM
  const conversation = messages.map((m) => ({
    role: m.role as "assistant" | "user" | "system" | "tool",
    content: m.content,
  }));

  try {
    const analysis = await analyzeConversation(
      config.analysisModel,
      conversation,
      systemInstructions,
      appliedSkills,
      activeGoal,
      ctx,
    );

    if (
      analysis.violation &&
      analysis.confidence >= (config.confidenceThreshold ?? 0.7)
    ) {
      return {
        source: "llm_analysis",
        confidence: analysis.confidence,
        violatedInstruction: analysis.violatedInstruction,
        whatModelDid: analysis.whatModelDid,
        whatShouldHaveDone: analysis.whatShouldHaveDone,
        correctionMessage: analysis.correctionMessage,
        reasoning: analysis.reasoning,
      };
    }

    return null;
  } catch (error) {
    console.warn("[guardrails] Analysis failed:", error);
    return null;
  }
}

function extractSystemInstructions(messages: MessageEntry[]): string {
  const systemMessages = messages
    .filter((m) => m.role === "system")
    .map((m) => m.content)
    .join("\n---\n");

  // Capture ALL user messages as potential instructions
  // The user might have said "everything should be functional" or "use the API"
  // without using words like "AGENTS.md" or "rule"
  const userInstructions = messages
    .filter((m) => m.role === "user")
    .map((m, i) => `[User Message ${i + 1}] ${m.content}`)
    .join("\n---\n");

  return `${systemMessages}\n${userInstructions}`.trim();
}

function extractAppliedSkills(messages: MessageEntry[]): string[] {
  const skills: string[] = [];
  for (const message of messages) {
    if (message.role !== "user") continue;
    const content = message.content;
    // Match /skill:name or /skill: name patterns
    const matches = content.match(/\/skill:([\w-]+)/g);
    if (matches) {
      for (const match of matches) {
        const skillName = match.replace("/skill:", "");
        if (!skills.includes(skillName)) {
          skills.push(skillName);
        }
      }
    }
  }
  return skills;
}
