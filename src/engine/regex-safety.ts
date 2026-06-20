// Validate-at-load safety check for UNTRUSTED regex patterns.
//
// Built-in pack patterns are hand-audited (and covered by the differential
// corpus), so they never run through this. But two surfaces accept patterns from
// a project's `.pi/guardrails.json`:
//   - policy constraint `detect.regex`
//   - external pack rule patterns (the ExternalPack type — not wired yet, but
//     this validator is exported so the loader uses it when it lands)
//
// At RUNTIME the matcher/`safeRegexTest` cap input length and poll a per-match
// budget — but those are POST-HOC: a catastrophic-backtracking regex on a short,
// crafted input can block the event loop synchronously for SECONDS before the
// budget is even checked (a 29-char input can stall multiple seconds). Input
// caps don't help (the input is short). The only real defense is to REFUSE the
// pattern at load so it never runs. This module is that gate.
//
// The ReDoS heuristic targets the EXPONENTIAL family — an unbounded quantifier
// applied to a group whose body itself contains an unbounded quantifier
// (`(a+)+`, `(a*)*`, `(.*)+`, `(\d+)*`, `([a-z]+)*`, …). It is intentionally
// CONSERVATIVE: it can over-reject a benign nested-quantifier pattern like
// `(ab+)+`. For a security guard rejecting untrusted patterns that is the right
// trade-off — the user gets a clear message and simplifies, versus the guard
// hanging. Polynomial slowness (`.*.*`) is left to the runtime input cap.

/** Refuse absurdly long patterns outright (a cheap pre-filter). */
const MAX_PATTERN_LENGTH = 1000;

export interface RegexSafetyResult {
  ok: boolean;
  /** Present when ok=false: why the pattern was refused. */
  reason?: string;
}

/**
 * Decide whether an untrusted regex SOURCE string is safe to compile + run.
 * Returns { ok: true } or { ok: false, reason }.
 */
export function validateRegexSafety(pattern: string): RegexSafetyResult {
  if (pattern.length > MAX_PATTERN_LENGTH) {
    return {
      ok: false,
      reason: `pattern exceeds ${MAX_PATTERN_LENGTH} chars`,
    };
  }
  try {
    new RegExp(pattern);
  } catch (e) {
    return {
      ok: false,
      reason: `invalid regex: ${(e as Error).message}`,
    };
  }
  const nested = findNestedUnboundedQuantifier(pattern);
  if (nested) return { ok: false, reason: nested };
  return { ok: true };
}

/**
 * Scan for an unbounded-quantified group whose body also contains an unbounded
 * quantifier — the exponential-ReDoS shape. Returns a human reason string when
 * found, or undefined when the pattern is clear of that shape.
 *
 * Group nesting is tracked with a stack; escapes (`\(`) and character classes
 * (`[...]`, where `(`/`)`/`*`/`+` are literals) are skipped so they never count.
 */
function findNestedUnboundedQuantifier(pattern: string): string | undefined {
  const stack: number[] = []; // body-start index of each open group
  let i = 0;
  const n = pattern.length;

  while (i < n) {
    const ch = pattern[i];

    if (ch === "\\") {
      i += 2; // skip the escaped char
      continue;
    }
    if (ch === "[") {
      i = skipCharClass(pattern, i);
      continue;
    }
    if (ch === "(") {
      // Body starts after any group-opener prefix ((?: (?= (?! (?<name> (?<= (?<!).
      stack.push(groupBodyStart(pattern, i));
      i += 1;
      continue;
    }
    if (ch === ")") {
      const bodyStart = stack.pop();
      if (bodyStart !== undefined) {
        const quant = unboundedQuantifierAt(pattern, i + 1);
        if (quant && containsUnboundedQuantifier(pattern, bodyStart, i)) {
          return `nested unbounded quantifier (\`…)${quant}\` over a group containing \`*\`/\`+\`/\`{n,}\`) — exponential backtracking risk`;
        }
      }
      i += 1;
      continue;
    }
    i += 1;
  }
  return undefined;
}

/** Index just past a group's opener prefix (handles (?: (?= (?! (?<name> (?<= (?<!)). */
function groupBodyStart(pattern: string, openParen: number): number {
  if (pattern[openParen + 1] !== "?") return openParen + 1;
  // (?: (?= (?!  -> 3 chars
  const c2 = pattern[openParen + 2];
  if (c2 === ":" || c2 === "=" || c2 === "!") return openParen + 3;
  if (c2 === "<") {
    // (?<= or (?<!  (lookbehind) -> 4 chars; (?<name>...) -> past the ">"
    const c3 = pattern[openParen + 3];
    if (c3 === "=" || c3 === "!") return openParen + 4;
    const close = pattern.indexOf(">", openParen + 3);
    return close >= 0 ? close + 1 : openParen + 3;
  }
  return openParen + 2;
}

/** Skip a character class `[...]` (respects `\]` and a leading `]`). Returns index past `]`. */
function skipCharClass(pattern: string, open: number): number {
  let i = open + 1;
  if (pattern[i] === "^") i += 1;
  if (pattern[i] === "]") i += 1; // a `]` right after `[` is a literal
  while (i < pattern.length) {
    if (pattern[i] === "\\") {
      i += 2;
      continue;
    }
    if (pattern[i] === "]") return i + 1;
    i += 1;
  }
  return pattern.length;
}

/**
 * If position `pos` begins an UNBOUNDED quantifier, return its display form
 * (`*`, `+`, or `{n,}`); otherwise undefined. `{n}` and `{n,m}` are bounded.
 */
function unboundedQuantifierAt(
  pattern: string,
  pos: number,
): string | undefined {
  const ch = pattern[pos];
  if (ch === "*" || ch === "+") return ch;
  if (ch === "{") {
    const close = pattern.indexOf("}", pos);
    if (close < 0) return undefined;
    const body = pattern.slice(pos + 1, close); // e.g. "2," or "2,5" or "3"
    // Unbounded iff it has a comma and NO upper bound: `{n,}`.
    if (/^\d+,$/.test(body)) return `{${body}}`;
  }
  return undefined;
}

/**
 * Does the substring [start, end) contain an unbounded quantifier at any depth,
 * skipping escapes and character classes (where `*`/`+` are literals)?
 */
function containsUnboundedQuantifier(
  pattern: string,
  start: number,
  end: number,
): boolean {
  let i = start;
  while (i < end) {
    const ch = pattern[i];
    if (ch === "\\") {
      i += 2;
      continue;
    }
    if (ch === "[") {
      i = skipCharClass(pattern, i);
      continue;
    }
    if (ch === "*" || ch === "+") return true;
    if (ch === "{" && unboundedQuantifierAt(pattern, i)) return true;
    i += 1;
  }
  return false;
}
