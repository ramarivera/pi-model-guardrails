import assert from "node:assert/strict";
import test from "node:test";
import { buildAnalyzerPrompt } from "../src/llm.ts";

test("analyzer prompt treats policy rules as semantic obligations", () => {
  const prompt = buildAnalyzerPrompt(
    "System rules",
    ["agent-browser"],
    "Fix the guardrails",
    [
      {
        id: "agent-browser-must-use-cdp-9225",
        title: "Use the real browser session",
        description: "Browser work must use the persistent Chrome CDP target.",
        appliesWhen: "The user asks for agent-browser or visible browser work.",
        violation:
          "The assistant uses an unrelated browser automation path or fails to prove it used CDP 9225.",
        requiredBehavior:
          "Use the configured CDP endpoint and report concrete browser evidence.",
        severity: "error",
      },
    ],
  );

  assert.match(prompt, /Configured policy rules/);
  assert.match(prompt, /agent-browser-must-use-cdp-9225/);
  assert.match(prompt, /natural-language obligations/);
  assert.match(prompt, /not keyword filters/);
  assert.match(prompt, /semantic judgment/);
  assert.match(prompt, /devious or evasive model response/);
});
