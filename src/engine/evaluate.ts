// Top-level command evaluation: normalize -> candidate packs -> matchPack each
// -> STRICTEST-wins across packs.
//
// DCG faithfulness vs. divergence:
//  - FAITHFUL: normalization/segmentation, per-pack safe short-circuit,
//    destructive first-match-wins within a pack, declaration order, the
//    keyword quick-reject, and the fail-open/fail-closed regex guard semantics.
//  - DELIBERATE DIVERGENCE: DCG's production evaluator
//    (evaluate_packs_with_allowlists in src/evaluator.rs) returns the FIRST
//    matching destructive pattern across packs in pack-declaration order. The
//    MODULE CONTRACT for pi-model-guardrails instead picks the STRICTEST match
//    across packs (critical>high>medium>low; deny>warn>log>allow), breaking
//    ties by pack declaration order (which preserves DCG attribution such as
//    core.git winning over strict_git when both are the same severity).
//
// Source: https://github.com/Dicklesworthstone/destructive_command_guard
//   - src/evaluator.rs : evaluate_command_with_pack_order_deadline_at_path
//                        (entry checks, quick-reject, fail-open ordering)
//   - src/packs/mod.rs : Severity::default_mode, PackRegistry::check_command

import { resolveIndirection } from "./indirection.ts";
import { matchPack } from "./matcher.ts";
import { normalizeCommand, stripWrapperPrefixes } from "./normalize.ts";
import type { Registry } from "./registry.ts";
import type {
  DecisionMode,
  EngineDecision,
  EvaluateOptions,
  Severity,
} from "./types.ts";

/** Defaults per the MODULE CONTRACT. */
const DEFAULT_INPUT_MAX_LENGTH = 8192;
const DEFAULT_PER_MATCH_BUDGET_MS = 50;
const DEFAULT_FAIL_CLOSED = false;

function resolveOptions(opts?: EvaluateOptions): Required<EvaluateOptions> {
  return {
    inputMaxLength: opts?.inputMaxLength ?? DEFAULT_INPUT_MAX_LENGTH,
    perMatchBudgetMs: opts?.perMatchBudgetMs ?? DEFAULT_PER_MATCH_BUDGET_MS,
    failClosed: opts?.failClosed ?? DEFAULT_FAIL_CLOSED,
  };
}

/** Strictness rank for severity (higher = stricter). */
function severityRank(sev: Severity | undefined): number {
  switch (sev) {
    case "critical":
      return 4;
    case "high":
      return 3;
    case "medium":
      return 2;
    case "low":
      return 1;
    default:
      return 0;
  }
}

/** Strictness rank for a decision mode (higher = stricter). */
function modeRank(mode: DecisionMode): number {
  switch (mode) {
    case "deny":
      return 4;
    case "warn":
      return 3;
    case "log":
      return 2;
    case "allow":
      return 1;
  }
}

/**
 * Is `candidate` strictly stricter than `current`?
 * Primary key: decision mode rank. Tie-break: severity rank. A pure tie is
 * NOT stricter (so the earlier pack — already held in `current` — wins,
 * preserving declaration-order attribution).
 */
function isStricter(
  candidate: EngineDecision,
  current: EngineDecision,
): boolean {
  const cm = modeRank(candidate.decision);
  const um = modeRank(current.decision);
  if (cm !== um) return cm > um;
  return severityRank(candidate.severity) > severityRank(current.severity);
}

/** The decision returned when nothing fires. */
function allowDecision(reason: string): EngineDecision {
  return { decision: "allow", blocked: false, allowReason: reason };
}

/**
 * Evaluate a command against the registry.
 *
 * Flow:
 *  1. inputMaxLength cap BITES FIRST. An over-cap command fails open
 *     (allow, allowReason="input_too_long") unless `failClosed`, in which case
 *     it is denied (critical) — a degraded, armed engine refuses oversized
 *     input rather than waving it through.
 *  2. Empty command => allow (DCG: empty commands are a no-op).
 *  3. Normalize into segments (splitCommandSegments + classifySegment).
 *  4. Quick-reject via registry.candidatePacks (keyword substring prefilter).
 *  5. Run matchPack on each candidate pack; keep the STRICTEST decision across
 *     packs, ties broken by declaration order.
 *  6. Tier-3 indirection pass: resolve one level of variable/alias indirection
 *     and re-run the engine on the expansion (catches `x=rm; $x -rf ~`). A
 *     stricter resolved result wins; the attribution is annotated.
 *  7. If nothing fires, allow (allowReason="no_match").
 */
export function evaluateCommand(
  command: string,
  registry: Registry,
  opts?: EvaluateOptions,
): EngineDecision {
  const resolved = resolveOptions(opts);

  // (1) Length cap bites before any normalization / budget clock.
  if (command.length > resolved.inputMaxLength) {
    if (resolved.failClosed) {
      return {
        decision: "deny",
        blocked: true,
        severity: "critical",
        reason: "command exceeds input length cap (failed closed)",
        confidence: 1,
      };
    }
    return allowDecision("input_too_long");
  }

  // (2) Empty => allow.
  if (command.length === 0) {
    return allowDecision("empty");
  }

  // Crash-safety: a guard must NEVER throw in the hot path. Normalization walks
  // nested subshells recursively and can, on pathologically-nested input (with
  // a raised inputMaxLength), hit a stack overflow. Any unexpected throw
  // degrades to the engine's standard polarity — fail-open in a clear state,
  // fail-closed when armed — rather than propagating and breaking the tool call.
  try {
    return evaluateInner(command, registry, resolved, false);
  } catch {
    if (resolved.failClosed) {
      return {
        decision: "deny",
        blocked: true,
        severity: "critical",
        reason: "command guard failed closed (evaluation error)",
        confidence: 1,
      };
    }
    return allowDecision("evaluation_error");
  }
}

function evaluateInner(
  command: string,
  registry: Registry,
  resolved: Required<EvaluateOptions>,
  skipResolution: boolean,
): EngineDecision {
  // (3) Normalize into classified segments. Also compute the wrapper-stripped
  // whole command (DCG's `command_for_packs = normalize_command(strip_wrapper_
  // prefixes(command))`) — this is what the matchers run against, so a leading
  // sudo/doas/env/time wrapper can't defeat the `^rm`-anchored safe rescues
  // while the unanchored destructive rules still fire (the wrapper-prefixed
  // false-positive family).
  const segments = normalizeCommand(command);
  const strippedCommand = stripWrapperPrefixes(command);

  // (4) Quick-reject prefilter. Scan BOTH the raw command AND the normalized
  // segment text. This ports DCG's `contains_shell_word_obfuscation` escape
  // hatch: obfuscated command words (r\m, 'r'm, g\it, f\ind, …) hide a pack
  // keyword from the RAW text, but normalization resolves them to the real
  // command word — so a quick-reject on raw text alone would wave the whole
  // command through before any pattern runs. Including the normalized text in
  // the prefilter closes that bypass.
  const normalizedText = segments.map((s) => s.normalized).join("\n");
  const prefilterText =
    normalizedText === command ? command : `${command}\n${normalizedText}`;
  const candidates = registry.candidatePacks(prefilterText);
  if (candidates.length === 0) {
    return allowDecision("quick_reject");
  }

  // (5) Strictest-wins across candidate packs.
  let best: EngineDecision | undefined;
  for (const pack of candidates) {
    const decision = matchPack(pack, segments, strippedCommand, resolved);
    if (!decision) continue;
    if (decision.decision === "allow") continue; // packs only emit deny/warn/log
    if (best === undefined || isStricter(decision, best)) {
      best = decision;
      // A critical deny is the strictest possible result — short-circuit.
      if (best.decision === "deny" && best.severity === "critical") {
        return best;
      }
    }
  }

  // (6) Tier-3 structural indirection pass. The literal text matched nothing
  // STRICTER than `best` so far, but a destructive sink may be hidden behind one
  // level of variable/alias indirection (`x=rm; $x -rf /`). Resolve it and
  // re-run the SAME engine on the expansion (skipResolution=true bounds the
  // recursion to a single re-entry). A stricter result wins; the attribution is
  // annotated so the policy/state layers can see it came via indirection.
  if (!skipResolution) {
    const indirect = resolveIndirection(command);
    if (indirect && indirect.expanded !== command) {
      const alt = evaluateInner(indirect.expanded, registry, resolved, true);
      if (alt.blocked && (best === undefined || isStricter(alt, best))) {
        return annotateIndirection(alt, indirect.notes);
      }
    }
  }

  if (best) return best;

  // (7) Nothing fired.
  return allowDecision("no_match");
}

/** Tag an indirection-resolved decision so its origin is visible downstream. */
function annotateIndirection(
  decision: EngineDecision,
  notes: string[],
): EngineDecision {
  const via = notes.length > 0 ? notes.join("+") : "indirection";
  const base = decision.reason ?? "destructive command";
  return {
    ...decision,
    reason: `${base} (resolved via ${via} indirection)`,
  };
}
