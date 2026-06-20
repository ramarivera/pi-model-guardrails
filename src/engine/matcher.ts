// Per-pack matcher: the deterministic heart of the DCG-ported engine.
//
// Faithful port of DCG `Pack::check` / `Pack::check_single`
// (src/packs/mod.rs) plus the production per-pack semantics in
// `evaluate_packs_with_allowlists` (src/evaluator.rs), where a pack's safe
// patterns ONLY shield that pack's own destructive patterns (NOT other
// packs) — the compound-command bypass fix.
//
// Source: https://github.com/Dicklesworthstone/destructive_command_guard
//   - src/packs/mod.rs  : Pack::check, check_single, matches_safe, matches_destructive
//   - src/evaluator.rs  : evaluate_packs_with_allowlists (per-pack safe short-circuit)
//   - src/packs/regex_engine.rs : is_match/find are fail-open (false/None on error)

import type {
  DestructiveRule,
  EngineDecision,
  EvaluateOptions,
  Pack,
  SafeRule,
  SegmentContext,
} from "./types.ts";
import { ruleId, severityToMode } from "./types.ts";

/**
 * Run a single regex `.test()` against `text`, guarded by:
 *  - the inputMaxLength cap (BITES FIRST — checked before any clock), and
 *  - a per-match wall-clock budget (perMatchBudgetMs).
 *
 * Returns:
 *  - true  : the pattern matched within the guards,
 *  - false : the pattern did not match (clean miss),
 *  - "fail": the guard tripped (input too long / over budget) or the regex
 *            threw. The caller decides fail-open vs fail-closed.
 *
 * DCG analog: regex_engine `is_match` returns `false` on backtracking error
 * (fail-open) and the evaluator polls a wall-clock Deadline between patterns,
 * returning `allowed_due_to_budget()` (fail-open) when it expires.
 */
function guardedTest(
  re: RegExp,
  text: string,
  opts: Required<EvaluateOptions>,
): boolean | "fail" {
  // Length cap bites first — before we even start the clock. This is the
  // ReDoS ordering guarantee: a pathologically long input never reaches the
  // regex engine.
  if (text.length > opts.inputMaxLength) {
    return "fail";
  }

  const start = Date.now();
  let matched: boolean;
  try {
    // `.test()` advances lastIndex on global/sticky regexes; reset to keep the
    // call stateless and re-runnable.
    re.lastIndex = 0;
    matched = re.test(text);
    re.lastIndex = 0;
  } catch {
    // Regex execution threw (should not happen for well-formed JS RegExp, but
    // guard anyway). Treat as a guard trip.
    return "fail";
  }

  // Wall-clock budget is checked AFTER the call: a single catastrophic match
  // is detected post-hoc, mirroring DCG's deadline poll between patterns.
  if (Date.now() - start > opts.perMatchBudgetMs) {
    return "fail";
  }

  return matched;
}

/**
 * Build the deny decision that fail-closed mode emits when a guard trips.
 * Severity is reported as "critical" so it outranks normal matches in the
 * strictest-wins comparison at the registry level — a degraded engine that is
 * armed to fail closed must not be silently outvoted.
 */
function failClosedDecision(
  pack: Pack,
  segment: string,
): EngineDecision {
  return {
    decision: "deny",
    blocked: true,
    packId: pack.id,
    severity: "critical",
    reason: "command guard failed closed (input cap or match budget exceeded)",
    segment,
    allowReason: undefined,
    confidence: 1,
  };
}

/**
 * Does ANY of this pack's safe patterns match `text`?
 * Returns the matching SafeRule, the literal `"fail"` if a guard tripped, or
 * undefined for a clean no-match.
 *
 * DCG analog: Pack::matches_safe (any safe pattern => allow this pack).
 */
function firstSafeMatch(
  pack: Pack,
  text: string,
  opts: Required<EvaluateOptions>,
): SafeRule | "fail" | undefined {
  let sawFail = false;
  for (const rule of pack.safePatterns) {
    const r = guardedTest(rule.re, text, opts);
    if (r === true) return rule;
    if (r === "fail") sawFail = true;
  }
  return sawFail ? "fail" : undefined;
}

/**
 * Find the FIRST destructive pattern (declaration order) that matches `text`.
 * Declaration order is load-bearing: DCG returns the first matching pattern.
 * Returns the rule, `"fail"` on guard trip, or undefined for a clean miss.
 *
 * DCG analog: Pack::matches_destructive (`.iter().find(...)`).
 */
function firstDestructiveMatch(
  pack: Pack,
  text: string,
  opts: Required<EvaluateOptions>,
): DestructiveRule | "fail" | undefined {
  let sawFail = false;
  for (const rule of pack.destructivePatterns) {
    const r = guardedTest(rule.re, text, opts);
    if (r === true) return rule;
    if (r === "fail") sawFail = true;
  }
  return sawFail ? "fail" : undefined;
}

/** Build a deny/warn/log EngineDecision from a matched destructive rule. */
function destructiveDecision(
  pack: Pack,
  rule: DestructiveRule,
  segment: string,
  matched: string,
): EngineDecision {
  const decision = severityToMode(rule.severity);
  return {
    decision,
    blocked: decision === "deny",
    ruleId: ruleId(pack.id, rule.name),
    packId: pack.id,
    ruleName: rule.name,
    severity: rule.severity,
    reason: rule.reason,
    matched,
    segment,
    suggestions: rule.suggestions,
    explanation: rule.explanation,
  };
}

/**
 * Evaluate ONE pack against a fully-normalized command.
 *
 * Order of operations (faithful to DCG `Pack::check_single` + the production
 * per-pack evaluator):
 *
 *   1. Imperative pre-checks (`pack.imperative[]`), in declaration order.
 *      First one to return a decision short-circuits. (DCG: the
 *      core.filesystem rm parser runs BEFORE matches_safe.)
 *   2+3. Per-TEXT safe-then-destructive: for each segment (and the whole
 *      command), a safe pattern match whitelists ONLY that text and skips its
 *      destructive check; otherwise the destructive patterns run on that text
 *      (first-match-wins, declaration order load-bearing). The safe shield is
 *      scoped to the single text — a safe segment never shields a destructive
 *      sibling segment (the compound-command bypass guard) — and to THIS pack
 *      only — it never leaks to sibling packs.
 *
 * Guards: every `.test()` is wrapped (length cap first, then per-match
 * budget). On a guard trip or regex throw, behavior is fail-open
 * (return undefined = this pack abstains) unless `opts.failClosed`, in which
 * case a degraded engine emits a critical deny.
 *
 * @returns an EngineDecision when this pack fires (deny/warn/log), or
 *          undefined when this pack allows / abstains.
 */
export function matchPack(
  pack: Pack,
  segments: SegmentContext[],
  fullCommand: string,
  opts: Required<EvaluateOptions>,
): EngineDecision | undefined {
  // ----- 1. Imperative pre-checks (rm/cp/ln/rsync argv parsers, etc.) -----
  // A deny/warn/log result is AUTHORITATIVE and returns immediately. An ALLOW
  // result is ADVISORY only: the rm/cp/ln/rsync argv parser ran against the
  // whole command and judged its own op safe, but it must NOT short-circuit the
  // pack — a destructive sibling (mv/find/dd/…) or cp/ln/rsync sensitive-then-
  // delete propagation in the SAME compound command must still be evaluated by
  // the regex pass below. (The original short-circuit-on-Allow let
  // `mv /etc /tmp/x && rm -rf /tmp/x` through — DCG's own canonical bypass.)
  // The regex pass has its own temp-safe `^rm…` safe patterns that allow a
  // genuinely-safe lone rm, so dropping the Allow here does not over-block it.
  // Pass 1: a deny/warn/log is AUTHORITATIVE (return now). Also learn whether
  // the imperative ALLOWS the full command — removalCheck returns allow only
  // when the rm op is temp-safe AND there is no cp/ln/rsync propagation, so
  // this is false in the propagation case (keeping the whole-command scan below
  // so the propagation pattern can fire).
  let imperativeAllowsFull = false;
  if (pack.imperative && pack.imperative.length > 0) {
    for (const seg of segments) {
      for (const check of pack.imperative) {
        let decision: EngineDecision | undefined;
        try {
          decision = check(seg, fullCommand);
        } catch {
          // An imperative check that throws is treated like a guard trip.
          if (opts.failClosed) return failClosedDecision(pack, seg.raw);
          decision = undefined;
        }
        if (decision === undefined) continue;
        if (decision.decision === "allow") {
          imperativeAllowsFull = true;
          continue;
        }
        // deny / warn / log => authoritative; stamp identity and return.
        return {
          ...decision,
          packId: decision.packId ?? pack.id,
          ruleId:
            decision.ruleId ??
            (decision.ruleName ? ruleId(pack.id, decision.ruleName) : undefined),
          blocked: decision.blocked ?? decision.decision === "deny",
          segment: decision.segment ?? seg.raw,
        };
      }
    }
  }

  // Pass 2: exonerate a segment iff the imperative allows it IN ISOLATION
  // (it is itself a temp-safe rm/cp/ln/rsync op) AND it allows the full command
  // (no propagation/sibling makes it dangerous). This drops a temp-safe rm from
  // the regex pass — whose rm-rf-root-home rule is broad (matches any `rm -rf
  // /path`) and would false-positive on temp paths inside a compound — WITHOUT
  // swallowing a destructive sibling (mv/find/dd), which is not exonerated and
  // is still scanned below. (`mv /etc /tmp/x && rm -rf /tmp/x` => mv still
  // fires; `cp -al /tmp/a /tmp/b && rm -rf /tmp/b` => no false positive.)
  const exonerated = new Set<SegmentContext>();
  if (imperativeAllowsFull && pack.imperative && pack.imperative.length > 0) {
    for (const seg of segments) {
      for (const check of pack.imperative) {
        let isolated: EngineDecision | undefined;
        try {
          isolated = check(seg, seg.normalized);
        } catch {
          isolated = undefined;
        }
        if (isolated?.decision === "allow") {
          exonerated.add(seg);
          break;
        }
      }
    }
  }

  // The texts we run patterns against: every NON-exonerated segment's normalized
  // form, plus the whole command (so patterns that legitimately span a pipeline
  // — e.g. cp/ln/rsync sensitive-then-delete propagation — still fire). DCG
  // checks each segment then the full command once. If any segment was
  // imperatively exonerated, we omit the whole-command text: it still contains
  // that exonerated segment, which would otherwise be re-flagged by an
  // unanchored rm pattern, reintroducing the false positive the imperative
  // parser exists to prevent.
  const segmentTexts = segments
    .filter((s) => !exonerated.has(s))
    .map((s) => s.normalized);
  // Omit the whole-command text when a segment was exonerated: it still contains
  // that temp-safe rm, which the broad rm-rf-root-home rule would otherwise
  // re-flag. The propagation case never reaches here (imperativeAllowsFull is
  // false then), so dropping the whole-command text loses no real coverage.
  const wholeTexts =
    exonerated.size > 0
      ? dedupePreserveOrder(segmentTexts)
      : dedupePreserveOrder([...segmentTexts, fullCommand]);

  // ----- 2+3. Per-TEXT safe-then-destructive (the compound-command bypass guard) -----
  // CRITICAL: a safe match shields only the SINGLE text it matched, never the
  // whole pack. A safe segment (e.g. "git status") must NOT shield a
  // destructive sibling segment (e.g. "git push --force") in the same command.
  // So we interleave per text: if THIS text is whitelisted by a safe pattern we
  // skip only THIS text's destructive check and move on; otherwise we run THIS
  // text's destructive patterns (first-match-wins, declaration order). A safe
  // match still shields a destructive pattern within the SAME text (e.g.
  // --force-with-lease vs --force), which is the intended behavior.
  for (const text of wholeTexts) {
    const safe = firstSafeMatch(pack, text, opts);
    if (safe === "fail" && opts.failClosed) {
      return failClosedDecision(pack, text);
    }
    // A real SafeRule whitelists THIS text only — skip its destructive check.
    // A guard trip ("fail") in fail-open mode does NOT shield: fall through so
    // the destructive patterns still get a chance (fail-open != fail-allow).
    if (safe && safe !== "fail") {
      continue;
    }

    const hit = firstDestructiveMatch(pack, text, opts);
    if (hit === "fail") {
      if (opts.failClosed) return failClosedDecision(pack, text);
      continue;
    }
    if (hit) {
      return destructiveDecision(pack, hit, text, text);
    }
  }

  // Clean miss: this pack allows.
  return undefined;
}

/** Stable dedupe preserving first-seen order. */
function dedupePreserveOrder(items: string[]): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const it of items) {
    if (!seen.has(it)) {
      seen.add(it);
      out.push(it);
    }
  }
  return out;
}
