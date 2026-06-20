// Differential golden-corpus harness.
//
// The corpus (test/fixtures/golden-corpus.json, 298 cases) was extracted by the
// porting agents from DCG's OWN #[test] blocks. Running each input through our
// TS evaluateCommand and asserting decision (+ ruleId where given) keeps
// JS-vs-Rust parity honest as packs evolve — no live `dcg` binary required.
//
// EXCLUSIONS below are documented, categorized, and each is tracked. They are
// NOT a way to hide failures — every entry has a reason and (for real gaps) a
// task. Phase 1 loads ONLY core.git + core.filesystem, so:
//
//  1. PENDING_PACKS — case expects a block from a pack not yet ported
//     (docker/database/velero/1Password "op"…). Correctly "allow" today;
//     resolves when those packs land (task #5, Phase 4).
//  2. KNOWN_MASKING_GAPS — REAL false positives: a dangerous string sitting in
//     a NON-executable context (single-quoted value, $((arith)), a quoted
//     `git commit -m` message). DCG masks these via its classify_command data
//     model, which the port deferred. Tracked to fix (data-span masking task).
//  3. HEREDOC_ARTIFACTS — corpus cases authored from the heredoc *module's*
//     extract-only view (expect "allow" = "module just returns the body");
//     heredoc is not yet wired into evaluateCommand, and our raw-text "deny" is
//     arguably more correct. Revisit when heredoc + masking land.
//  4. RULEID_ATTRIBUTION — decision is correct (deny); only the attributed rule
//     name differs (overlapping git restore rules). Cosmetic; tracked.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { evaluateCommand } from "../src/engine/evaluate.ts";
import { coreFilesystemPack } from "../src/engine/packs/core-filesystem.ts";
import { coreGitPack } from "../src/engine/packs/core-git.ts";
import { buildRegistry } from "../src/engine/registry.ts";

interface GoldenCase {
  input: string;
  expectedDecision: "deny" | "warn" | "log" | "allow";
  expectedRuleId?: string;
  module?: string;
  note?: string;
}

const __dir = dirname(fileURLToPath(import.meta.url));
const corpus: GoldenCase[] = JSON.parse(
  readFileSync(join(__dir, "fixtures/golden-corpus.json"), "utf8"),
);
const registry = buildRegistry([coreGitPack, coreFilesystemPack]);

// input -> reason. Skipped from decision parity until the referenced work lands.
const DECISION_EXCLUSIONS = new Map<string, string>([
  // 1. PENDING_PACKS (task #5, Phase 4)
  [
    "echo $(docker system prune -a --volumes)",
    "pending pack: containers.docker",
  ],
  ["docker system prune", "pending pack: containers.docker"],
  [
    "cat <(docker system prune -a --volumes)",
    "pending pack: containers.docker",
  ],
  ["echo `velero backup delete nightly`", "pending pack: backup.velero"],
  [
    'op item get $(op item delete "Prod Secret")',
    "pending pack: secrets.1password",
  ],
  [
    'echo "$(op item delete \\"Prod Secret\\")"',
    "pending pack: secrets.1password",
  ],
  ["DROP TABLE IF EXISTS foo;", "pending pack: database.*"],
  ["DROP DATABASE IF EXISTS foo;", "pending pack: database.*"],
  ["TRUNCATE TABLE foo RESTART IDENTITY;", "pending pack: database.*"],
  // 2. KNOWN_MASKING_GAPS — FIXED by the data-span masking port (src/engine/
  // sanitize.ts): `echo $((arith))` (arithmetic, echo all-args-data) and a
  // dangerous string inside a quoted `git -m` value are now masked before
  // matching, so both decide `allow` like DCG. The two former exclusions were
  // removed once they passed (the test flags stale exclusions).
  // 3. HEREDOC_ARTIFACTS — heredoc not wired into evaluate; module-perspective cases
  ['echo "$(cat <<EOF\nrm -rf /\nEOF)"', "heredoc not wired into evaluate yet"],
  ["bash <<SH\nrm -rf /important\nSH", "heredoc not wired into evaluate yet"],
]);

// input -> reason. Decision is correct; only ruleId attribution differs.
const RULEID_EXCLUSIONS = new Map<string, string>([
  [
    "git restore --worktree file.txt",
    "overlapping restore rules: -explicit vs base; decision (deny) correct",
  ],
]);

test("differential golden corpus: decision parity with DCG", () => {
  const mismatches: Array<Record<string, unknown>> = [];
  const staleExclusions: string[] = [];
  for (const c of corpus) {
    const d = evaluateCommand(c.input, registry);
    const ok = d.decision === c.expectedDecision;
    if (DECISION_EXCLUSIONS.has(c.input)) {
      // Tracked gap. If it now PASSES, the exclusion is stale — flag it so we
      // remove it (keeps the exclusion list from rotting / hiding regressions).
      if (ok) staleExclusions.push(c.input);
      continue;
    }
    if (!ok) {
      mismatches.push({
        input: c.input,
        expected: c.expectedDecision,
        got: d.decision,
        gotRuleId: d.ruleId,
        module: c.module,
      });
    }
  }
  const problems: string[] = [];
  if (mismatches.length > 0) {
    const sample = mismatches
      .slice(0, 50)
      .map((m) => `  ${JSON.stringify(m)}`)
      .join("\n");
    problems.push(
      `${mismatches.length} unexpected decision mismatch(es):\n${sample}`,
    );
  }
  if (staleExclusions.length > 0) {
    problems.push(
      `${staleExclusions.length} DECISION_EXCLUSIONS now pass (remove them):\n  ${staleExclusions.join("\n  ")}`,
    );
  }
  assert.equal(problems.length, 0, problems.join("\n\n"));
});

test("differential golden corpus: ruleId parity where specified", () => {
  const mismatches: Array<Record<string, unknown>> = [];
  for (const c of corpus) {
    if (!c.expectedRuleId) continue;
    if (DECISION_EXCLUSIONS.has(c.input) || RULEID_EXCLUSIONS.has(c.input))
      continue;
    const d = evaluateCommand(c.input, registry);
    if (d.decision === c.expectedDecision && d.ruleId !== c.expectedRuleId) {
      mismatches.push({
        input: c.input,
        expectedRuleId: c.expectedRuleId,
        got: d.ruleId,
      });
    }
  }
  if (mismatches.length > 0) {
    const sample = mismatches
      .slice(0, 50)
      .map((m) => `  ${JSON.stringify(m)}`)
      .join("\n");
    assert.fail(
      `${mismatches.length} unexpected ruleId mismatch(es):\n${sample}`,
    );
  }
});

// Visibility: how much of the corpus we assert vs defer.
test("differential golden corpus: coverage report", () => {
  const total = corpus.length;
  const excluded = corpus.filter((c) =>
    DECISION_EXCLUSIONS.has(c.input),
  ).length;
  const asserted = total - excluded;
  console.log(
    `[corpus] ${asserted}/${total} cases asserted for decision parity; ${excluded} tracked-deferred`,
  );
  assert.ok(
    asserted / total >= 0.9,
    `expected >=90% of corpus asserted, got ${asserted}/${total}`,
  );
});
