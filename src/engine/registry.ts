// Pack registry: holds an ordered pack list and provides the keyword
// quick-reject prefilter.
//
// Faithful port of the keyword gate in DCG `Pack::might_match`
// (src/packs/mod.rs): a command is a candidate for a pack iff it contains at
// least one of the pack's keywords as a substring (memmem). Multiword
// (whitespace-containing) keywords match with collapsed inter-token
// whitespace, mirroring DCG `keyword_matches_with_whitespace`.
//
// NOTE: DCG's production span-aware `pack_aware_quick_reject` is a richer,
// false-positive-reducing prefilter. The MODULE CONTRACT here specifies the
// simpler substring quick-reject over pack.keywords (== `Pack::might_match`),
// which is a conservative superset: it never wrongly rejects a pack that the
// span-aware version would keep. Real safety still comes from the safe/
// destructive patterns inside matchPack.
//
// Source: https://github.com/Dicklesworthstone/destructive_command_guard
//   - src/packs/mod.rs : Pack::might_match, keyword_matches_substring,
//                        keyword_contains_whitespace, keyword_matches_with_whitespace

import type { Pack } from "./types.ts";

export interface Registry {
  /** Packs in declaration order. Order is load-bearing for attribution. */
  packs: Pack[];
  /**
   * Substring quick-reject: returns the packs whose keyword set the command
   * could plausibly hit. A pack with no keywords always qualifies (DCG: no
   * keywords => always check patterns).
   */
  candidatePacks(command: string): Pack[];
}

/** True if the keyword contains any ASCII whitespace byte. */
function keywordContainsWhitespace(keyword: string): boolean {
  // DCG: keyword.bytes().any(|b| b.is_ascii_whitespace())
  // ASCII whitespace = space, \t, \n, \v(0x0B), \f(0x0C), \r.
  return /[ \t\n\v\f\r]/.test(keyword);
}

/** Split a whitespace keyword into its non-empty parts (DCG split_keyword_parts). */
function splitKeywordParts(keyword: string): string[] {
  return keyword.split(/[ \t\n\v\f\r]+/).filter((p) => p.length > 0);
}

/**
 * Whitespace-tolerant substring match for multiword keywords.
 *
 * Faithful to DCG `keyword_matches_with_whitespace(.., enforce_boundaries=false)`:
 * the first part must appear as a substring, and each subsequent part must
 * follow after AT LEAST ONE whitespace char (collapsed runs allowed). No word
 * boundaries are enforced in the quick-reject (`might_match`) path.
 */
function keywordMatchesWithWhitespace(
  haystack: string,
  keyword: string,
): boolean {
  const parts = splitKeywordParts(keyword);
  if (parts.length === 0) return false;

  let fromIndex = 0;
  while (true) {
    const start = haystack.indexOf(parts[0], fromIndex);
    if (start < 0) return false;

    let idx = start + parts[0].length;
    let matched = true;
    for (let p = 1; p < parts.length; p++) {
      // Require at least one whitespace char between parts (collapsed run).
      let ws = idx;
      while (ws < haystack.length && /[ \t\n\v\f\r]/.test(haystack[ws])) ws++;
      if (ws === idx) {
        matched = false;
        break;
      }
      idx = ws;
      const part = parts[p];
      if (haystack.slice(idx, idx + part.length) !== part) {
        matched = false;
        break;
      }
      idx += part.length;
    }
    if (matched) return true;
    fromIndex = start + 1;
  }
}

/**
 * Faithful port of DCG `keyword_matches_substring`:
 *  - empty keyword never matches,
 *  - plain keyword: simple substring (memmem),
 *  - whitespace keyword: whitespace-tolerant match.
 */
function keywordMatchesSubstring(haystack: string, keyword: string): boolean {
  if (keyword.length === 0) return false;
  if (!keywordContainsWhitespace(keyword)) {
    return haystack.includes(keyword);
  }
  return keywordMatchesWithWhitespace(haystack, keyword);
}

/**
 * DCG `Pack::might_match`: a pack with no keywords always matches; otherwise
 * the command must contain at least one keyword (substring semantics above).
 */
function packMightMatch(pack: Pack, command: string): boolean {
  if (pack.keywords.length === 0) return true;
  return pack.keywords.some((kw) => keywordMatchesSubstring(command, kw));
}

/**
 * Build a Registry from an ordered pack list. The order is preserved exactly
 * and is load-bearing for cross-pack attribution (ties in strictest-wins are
 * broken by this order).
 */
export function buildRegistry(packs: Pack[]): Registry {
  const list = [...packs];
  return {
    packs: list,
    candidatePacks(command: string): Pack[] {
      return list.filter((pack) => packMightMatch(pack, command));
    },
  };
}
