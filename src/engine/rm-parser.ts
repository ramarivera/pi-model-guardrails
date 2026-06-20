// src/engine/rm-parser.ts
//
// Faithful TS port of DCG's rm-command imperative analysis.
//
// Source: destructive_command_guard/src/packs/core/filesystem.rs
//   - parse_rm_command / parse_rm_command_segment / parse_rm_segment
//   - RmFlagTracker / RmFlagState / RmFlagStyle
//   - strip_outer_quotes / path_is_safe_for_style / path_is_safe_unquoted /
//     path_is_safe_double_quoted / has_dotdot_segment / path_is_root_home /
//     path_text_is_root_home
//   - the cp/ln/rsync `*-sensitive-then-delete` destructive_pattern! regexes
//     + is_pre_rm_propagation_rule
// Tokenizer source: destructive_command_guard/src/normalize.rs
//   - tokenize_for_normalization / consume_word_token /
//     consume_separator_token / consume_shell_paren_construct /
//     skip_ascii_whitespace / starts_with_shell_redirection
//
// See the StructuredOutput portNotes for every JS-incompatible regex rewrite.

import { splitCommandSegments } from "./normalize.ts";
import type {
  EngineDecision,
  ImperativeCheck,
  SegmentContext,
  Severity,
} from "./types.ts";

const PACK_ID = "core.filesystem";

// ============================================================================
// Rule name + reason constants (verbatim from filesystem.rs lines 297-312)
// ============================================================================

const RM_RF_ROOT_HOME_NAME = "rm-rf-root-home";
const RM_RF_ROOT_HOME_REASON =
  "rm -rf on root or home paths is EXTREMELY DANGEROUS. This command will NOT be executed. Ask the user to run it manually if truly needed.";
const RM_R_F_SEPARATE_ROOT_HOME_NAME = "rm-r-f-separate-root-home";
const RM_R_F_SEPARATE_ROOT_HOME_REASON =
  "rm with separate -r -f flags targeting root or home is EXTREMELY DANGEROUS.";
const RM_RECURSIVE_FORCE_ROOT_HOME_NAME = "rm-recursive-force-root-home";
const RM_RECURSIVE_FORCE_ROOT_HOME_REASON =
  "rm --recursive --force targeting root or home is EXTREMELY DANGEROUS.";
const RM_RF_GENERAL_NAME = "rm-rf-general";
const RM_RF_GENERAL_REASON =
  "rm -rf is destructive and requires human approval. Explain what you want to delete and why, then ask the user to run the command manually.";
const RM_R_F_SEPARATE_NAME = "rm-r-f-separate";
const RM_R_F_SEPARATE_REASON =
  "rm with separate -r -f flags is destructive and requires human approval.";
const RM_RECURSIVE_FORCE_NAME = "rm-recursive-force-long";
const RM_RECURSIVE_FORCE_REASON =
  "rm --recursive --force is destructive and requires human approval.";

// ============================================================================
// Word-level tokenizer — port of normalize.rs tokenize_for_normalization
// ============================================================================
//
// DCG operates on byte offsets (Rust &str is UTF-8 bytes). JS strings are
// UTF-16. We tokenize over UTF-16 code units and report ranges in those same
// units; every comparison is against ASCII bytes, so the only place this
// differs from DCG is byte vs code-unit offsets — irrelevant to all decisions
// because spans are only used for preview/highlighting downstream and we keep
// them internally consistent. (Noted in portNotes.)

type TokenKind = "word" | "separator";

interface NormalizeToken {
  kind: TokenKind;
  start: number;
  end: number;
}

function isAsciiWhitespace(ch: string): boolean {
  // Rust char::is_ascii_whitespace(): space, \t, \n, \r, \x0C (form feed)
  return ch === " " || ch === "\t" || ch === "\n" || ch === "\r" || ch === "\f";
}

function isAsciiDigit(code: number): boolean {
  return code >= 0x30 && code <= 0x39;
}

// Port of skip_ascii_whitespace (skips whitespace EXCEPT '\n').
function skipAsciiWhitespace(s: string, i: number, len: number): number {
  while (i < len) {
    const ch = s[i];
    if (!isAsciiWhitespace(ch) || ch === "\n") {
      break;
    }
    i += 1;
  }
  return i;
}

// Port of consume_shell_paren_construct (normalize.rs).
function consumeShellParenConstruct(
  s: string,
  startI: number,
  len: number,
): number {
  let i = startI;
  let depth = 1;
  while (i < len) {
    const ch = s[i];
    if (ch === "(") {
      depth += 1;
      i += 1;
    } else if (ch === ")") {
      depth = depth > 0 ? depth - 1 : 0;
      i += 1;
      if (depth === 0) {
        return i;
      }
    } else if (ch === "\\") {
      i = Math.min(i + 2, len);
    } else if (ch === "'") {
      i += 1;
      while (i < len && s[i] !== "'") {
        i += 1;
      }
      if (i < len) {
        i += 1;
      }
    } else if (ch === '"') {
      i += 1;
      while (i < len) {
        const c = s[i];
        if (c === '"') {
          i += 1;
          break;
        } else if (c === "\\") {
          i = Math.min(i + 2, len);
        } else if (c === "$" && i + 1 < len && s[i + 1] === "(") {
          i = consumeShellParenConstruct(s, i + 2, len);
        } else {
          i += 1;
        }
      }
    } else {
      i += 1;
    }
  }
  return len;
}

// Port of consume_word_token (normalize.rs).
function consumeWordToken(s: string, startI: number, len: number): number {
  let i = startI;
  while (i < len) {
    const ch = s[i];

    if (isAsciiWhitespace(ch)) {
      break;
    }

    if (ch === "$" && i + 1 < len && s[i + 1] === "(") {
      i = consumeShellParenConstruct(s, i + 2, len);
      continue;
    }

    if ((ch === "<" || ch === ">") && i + 1 < len && s[i + 1] === "(") {
      i = consumeShellParenConstruct(s, i + 2, len);
      continue;
    }

    if (ch === "&" && i + 1 < len && s[i + 1] === ">") {
      i += 2;
      if (i < len && s[i] === ">") {
        i += 1;
      }
      continue;
    }

    if (ch === "|" || ch === ";" || ch === "&" || ch === "(" || ch === ")") {
      break;
    }

    if (ch === "\\") {
      // CRLF escape consumes 3 (\, \r, \n)
      if (i + 2 < len && s[i + 1] === "\r" && s[i + 2] === "\n") {
        i += 3;
      } else {
        i = Math.min(i + 2, len);
      }
    } else if (ch === "'") {
      i += 1;
      while (i < len && s[i] !== "'") {
        i += 1;
      }
      if (i < len) {
        i += 1;
      }
    } else if (ch === '"') {
      i += 1;
      while (i < len) {
        const c = s[i];
        if (c === '"') {
          i += 1;
          break;
        } else if (c === "\\") {
          i = Math.min(i + 2, len);
        } else if (c === "$" && i + 1 < len && s[i + 1] === "(") {
          i = consumeShellParenConstruct(s, i + 2, len);
        } else {
          i += 1;
        }
      }
    } else {
      i += 1;
    }
  }
  return i;
}

// Port of consume_separator_token (normalize.rs).
// Returns the new index AND pushes a Separator token, or null if not a
// separator at position i. NOTE: `&>` is NOT a separator (it stays in a word).
function consumeSeparatorToken(
  s: string,
  i: number,
  len: number,
  tokens: NormalizeToken[],
): number | null {
  const ch = s[i];
  if (ch === "|") {
    const end = i + 1 < len && s[i + 1] === "|" ? i + 2 : i + 1;
    tokens.push({ kind: "separator", start: i, end });
    return end;
  }
  if (ch === ";" || ch === "(" || ch === ")") {
    tokens.push({ kind: "separator", start: i, end: i + 1 });
    return i + 1;
  }
  if (ch === "&" && i + 1 < len && s[i + 1] === ">") {
    return null; // redirection ampersand, not a separator
  }
  if (ch === "&") {
    const end = i + 1 < len && s[i + 1] === "&" ? i + 2 : i + 1;
    tokens.push({ kind: "separator", start: i, end });
    return end;
  }
  return null;
}

// Port of tokenize_for_normalization (normalize.rs).
function tokenizeForNormalization(command: string): NormalizeToken[] {
  const len = command.length;
  const tokens: NormalizeToken[] = [];
  let i = 0;

  while (i < len) {
    i = skipAsciiWhitespace(command, i, len);
    if (i >= len) {
      break;
    }

    if (command[i] === "\n") {
      tokens.push({ kind: "separator", start: i, end: i + 1 });
      i += 1;
      continue;
    }

    const sepEnd = consumeSeparatorToken(command, i, len, tokens);
    if (sepEnd !== null) {
      i = sepEnd;
      continue;
    }

    const start = i;
    const end = consumeWordToken(command, i, len);
    i = end;

    if (start < i) {
      tokens.push({ kind: "word", start, end });
    }
  }

  return tokens;
}

function tokenText(command: string, token: NormalizeToken): string {
  return command.slice(token.start, token.end);
}

// Port of starts_with_shell_redirection (normalize.rs).
function startsWithShellRedirection(s: string): boolean {
  const trimmed = s.replace(/^[ \t\n\r\f]+/, "");
  if (trimmed.length === 0) {
    return false;
  }
  if (trimmed[0] === ">" || trimmed[0] === "<" || trimmed.startsWith("&>")) {
    return true;
  }
  let idx = 0;
  while (idx < trimmed.length && isAsciiDigit(trimmed.charCodeAt(idx))) {
    idx += 1;
  }
  return (
    idx > 0 &&
    idx < trimmed.length &&
    (trimmed[idx] === ">" || trimmed[idx] === "<")
  );
}

// ============================================================================
// Quote / path helpers — port of filesystem.rs lines 621-728
// ============================================================================

type QuoteKind = "none" | "single" | "double";

interface PathToken {
  unquoted: string;
  quote: QuoteKind;
  start: number;
  end: number;
}

function stripPrefix(s: string, prefix: string): string | undefined {
  return s.startsWith(prefix) ? s.slice(prefix.length) : undefined;
}

// Port of strip_outer_quotes.
function stripOuterQuotes(token: string): {
  quote: QuoteKind;
  unquoted: string;
} {
  if (token.length >= 2) {
    if (token.startsWith('"') && token.endsWith('"')) {
      return { quote: "double", unquoted: token.slice(1, token.length - 1) };
    }
    if (token.startsWith("'") && token.endsWith("'")) {
      return { quote: "single", unquoted: token.slice(1, token.length - 1) };
    }
  }
  return { quote: "none", unquoted: token };
}

// Port of has_dotdot_segment.
function hasDotdotSegment(path: string): boolean {
  return path
    .split("/")
    .filter((segment) => segment.length > 0)
    .some((segment) => segment === "..");
}

// Port of path_is_safe_unquoted.
function pathIsSafeUnquoted(path: string): boolean {
  let rest: string | undefined;
  if ((rest = stripPrefix(path, "/tmp/")) !== undefined)
    return !hasDotdotSegment(rest);
  if ((rest = stripPrefix(path, "/var/tmp/")) !== undefined)
    return !hasDotdotSegment(rest);
  if ((rest = stripPrefix(path, "$TMPDIR/")) !== undefined)
    return !hasDotdotSegment(rest);
  if ((rest = stripPrefix(path, "${TMPDIR}/")) !== undefined)
    return !hasDotdotSegment(rest);
  if ((rest = stripPrefix(path, "${TMPDIR:-/tmp}/")) !== undefined)
    return !hasDotdotSegment(rest);
  if ((rest = stripPrefix(path, "${TMPDIR:-/var/tmp}/")) !== undefined)
    return !hasDotdotSegment(rest);
  return false;
}

// Port of path_is_safe_double_quoted.
function pathIsSafeDoubleQuoted(path: string): boolean {
  let rest: string | undefined;
  if ((rest = stripPrefix(path, "$TMPDIR/")) !== undefined)
    return !hasDotdotSegment(rest);
  if ((rest = stripPrefix(path, "${TMPDIR}/")) !== undefined)
    return !hasDotdotSegment(rest);
  if ((rest = stripPrefix(path, "${TMPDIR:-/tmp}/")) !== undefined)
    return !hasDotdotSegment(rest);
  if ((rest = stripPrefix(path, "${TMPDIR:-/var/tmp}/")) !== undefined)
    return !hasDotdotSegment(rest);
  return false;
}

// Port of path_is_safe_for_style.
function pathIsSafeForStyle(path: PathToken, style: RmFlagStyle): boolean {
  if (path.quote === "double" && style !== "combined") {
    return false;
  }
  switch (path.quote) {
    case "none":
      return pathIsSafeUnquoted(path.unquoted);
    case "double":
      return pathIsSafeDoubleQuoted(path.unquoted);
    case "single":
      return false;
  }
}

// Port of path_text_is_root_home.
function pathTextIsRootHome(text: string): boolean {
  if (text.startsWith("/")) return true;
  if (text.startsWith("~")) return true;
  return (
    text === "$HOME" ||
    text.startsWith("$HOME/") ||
    text === "${HOME}" ||
    text.startsWith("${HOME}/")
  );
}

// Port of path_is_root_home.
function pathIsRootHome(path: PathToken): boolean {
  const text = path.unquoted;
  if (pathTextIsRootHome(text)) {
    return true;
  }
  // Shell quote removal turns unquoted `\/` into `/` and `\~` into `~`.
  const unescaped = stripPrefix(text, "\\");
  if (unescaped !== undefined) {
    const first = unescaped[0];
    return first === "/" || first === "~";
  }
  return false;
}

// ============================================================================
// Flag tracking — port of RmFlagStyle / RmFlagState / RmFlagTracker
// ============================================================================

type RmFlagStyle = "combined" | "separate" | "long";

interface Range {
  start: number;
  end: number;
}

interface RmFlagState {
  style: RmFlagStyle;
  span?: Range;
  sawTerminator: boolean;
}

interface RmFlagTracker {
  combinedSpan?: Range;
  seenR: boolean;
  rSpan?: Range;
  seenF: boolean;
  fSpan?: Range;
  seenLongRecursive: boolean;
  recursiveSpan?: Range;
  seenLongForce: boolean;
  forceSpan?: Range;
  sawTerminator: boolean;
}

function newRmFlagTracker(): RmFlagTracker {
  return {
    seenR: false,
    seenF: false,
    seenLongRecursive: false,
    seenLongForce: false,
    sawTerminator: false,
  };
}

// Port of RmFlagTracker::resolve, with a divergence from DCG: recursion and
// force may each arrive via a SHORT (-r/-f) or LONG (--recursive/--force) flag,
// in any MIX. DCG only resolved all-short (-r -f) or all-long, so a mixed form
// like `rm -r --force /` resolved to nothing and slipped through (a reviewed
// false negative on root/home deletion). We treat recursion=(short||long) and
// force=(short||long); if both are present (and not a single combined token),
// it is a forced recursive removal.
function resolveFlags(flags: RmFlagTracker): RmFlagState | undefined {
  if (flags.combinedSpan !== undefined) {
    return {
      style: "combined",
      span: flags.combinedSpan,
      sawTerminator: flags.sawTerminator,
    };
  }
  const recursive = flags.seenR || flags.seenLongRecursive;
  const force = flags.seenF || flags.seenLongForce;
  if (recursive && force) {
    // "long" only when BOTH came from long flags (preserves DCG path-safety
    // semantics for the pure-long case); any short flag present => "separate".
    const allLong = !flags.seenR && !flags.seenF;
    return {
      style: allLong ? "long" : "separate",
      span:
        flags.rSpan ?? flags.recursiveSpan ?? flags.fSpan ?? flags.forceSpan,
      sawTerminator: flags.sawTerminator,
    };
  }
  return undefined;
}

// ============================================================================
// rm parse decision — port of RmParseDecision / RmParseMatch
// ============================================================================

interface RmParseMatch {
  patternName: string;
  reason: string;
  severity: Severity;
  span?: Range;
}

export type RmParseDecision =
  | { kind: "allow" }
  | { kind: "noMatch" }
  | { kind: "deny"; hit: RmParseMatch };

const ALLOW: RmParseDecision = { kind: "allow" };
const NO_MATCH: RmParseDecision = { kind: "noMatch" };

// Port of parse_rm_command.
export function parseRmCommand(command: string): RmParseDecision {
  const segments = splitCommandSegments(command);
  if (segments.length > 1) {
    let sawAllow = false;
    for (const segment of segments) {
      const decision = parseRmCommandSegment(segment);
      if (decision.kind === "deny") {
        return decision;
      }
      if (decision.kind === "allow") {
        sawAllow = true;
      }
    }
    return sawAllow ? ALLOW : NO_MATCH;
  }
  return parseRmCommandSegment(command);
}

// Port of parse_rm_command_segment.
function parseRmCommandSegment(command: string): RmParseDecision {
  const tokens = tokenizeForNormalization(command);
  if (tokens.length === 0) {
    return NO_MATCH;
  }

  let i = 0;
  while (i < tokens.length) {
    const current = tokens[i];
    if (current.kind === "separator") {
      i += 1;
      continue;
    }

    const text = tokenText(command, current);

    if (text === "rm") {
      return parseRmSegment(command, tokens, i + 1);
    }

    // Skip to the next separator before scanning for another command word.
    i += 1;
    while (i < tokens.length && tokens[i].kind !== "separator") {
      i += 1;
    }
  }

  return NO_MATCH;
}

function trimStartMatches(s: string, ch: string): string {
  let start = 0;
  while (start < s.length && s[start] === ch) {
    start += 1;
  }
  return s.slice(start);
}

// Port of parse_rm_segment.
function parseRmSegment(
  command: string,
  tokens: NormalizeToken[],
  startIdx: number,
): RmParseDecision {
  let optionsEnded = false;
  const flags = newRmFlagTracker();
  const paths: PathToken[] = [];

  for (let idx = startIdx; idx < tokens.length; idx += 1) {
    const token = tokens[idx];
    if (token.kind === "separator") {
      break;
    }

    const text = tokenText(command, token);

    if (!optionsEnded) {
      if (text === "--") {
        optionsEnded = true;
        flags.sawTerminator = true;
        continue;
      }

      if (text.startsWith("-") && text !== "-") {
        if (text.startsWith("--")) {
          if (text.startsWith("--recursive")) {
            flags.seenLongRecursive = true;
            if (flags.recursiveSpan === undefined) {
              flags.recursiveSpan = { start: token.start, end: token.end };
            }
          }
          if (text.startsWith("--force")) {
            flags.seenLongForce = true;
            if (flags.forceSpan === undefined) {
              flags.forceSpan = { start: token.start, end: token.end };
            }
          }
        } else {
          const flagText = trimStartMatches(text, "-");
          if (flagText.length > 0) {
            const hasR = [...flagText].some((c) => c === "r" || c === "R");
            const hasF = [...flagText].some((c) => c === "f");
            if (hasR && hasF) {
              if (flags.combinedSpan === undefined) {
                flags.combinedSpan = { start: token.start, end: token.end };
              }
            } else {
              if (hasR && !flags.seenR) {
                flags.seenR = true;
                flags.rSpan = { start: token.start, end: token.end };
              }
              if (hasF && !flags.seenF) {
                flags.seenF = true;
                flags.fSpan = { start: token.start, end: token.end };
              }
            }
          }
        }
        continue;
      }
    }

    // Skip trailing shell redirections (`> log`, `2>/dev/null`, `2>&1`,
    // `&>>file`, …). These are not arguments to `rm` (filesystem.rs #120).
    if (startsWithShellRedirection(text)) {
      optionsEnded = true;
      continue;
    }

    // NOTE: do NOT set optionsEnded here. GNU getopt permutes options past
    // operands by default, so `rm /etc -rf` is equivalent to `rm -rf /etc`.
    // Only an explicit `--` terminator ends option scanning. (DIVERGES from
    // DCG, which ended options at the first path and missed flags-after-path —
    // a reviewed root/home-deletion false negative.)
    const { quote, unquoted } = stripOuterQuotes(text);
    paths.push({ unquoted, quote, start: token.start, end: token.end });
  }

  const flagState = resolveFlags(flags);
  if (flagState === undefined) {
    return NO_MATCH;
  }

  const safePaths =
    paths.length > 0 &&
    !flagState.sawTerminator &&
    paths.every((path) => pathIsSafeForStyle(path, flagState.style));

  if (safePaths) {
    return ALLOW;
  }

  const isCritical = paths.some(
    (path) =>
      pathIsRootHome(path) && !pathIsSafeForStyle(path, flagState.style),
  );

  let patternName: string;
  let reason: string;
  let severity: Severity;

  if (isCritical) {
    switch (flagState.style) {
      case "combined":
        patternName = RM_RF_ROOT_HOME_NAME;
        reason = RM_RF_ROOT_HOME_REASON;
        severity = "critical";
        break;
      case "separate":
        patternName = RM_R_F_SEPARATE_ROOT_HOME_NAME;
        reason = RM_R_F_SEPARATE_ROOT_HOME_REASON;
        severity = "critical";
        break;
      case "long":
        patternName = RM_RECURSIVE_FORCE_ROOT_HOME_NAME;
        reason = RM_RECURSIVE_FORCE_ROOT_HOME_REASON;
        severity = "critical";
        break;
    }
  } else {
    switch (flagState.style) {
      case "combined":
        patternName = RM_RF_GENERAL_NAME;
        reason = RM_RF_GENERAL_REASON;
        severity = "high";
        break;
      case "separate":
        patternName = RM_R_F_SEPARATE_NAME;
        reason = RM_R_F_SEPARATE_REASON;
        severity = "high";
        break;
      case "long":
        patternName = RM_RECURSIVE_FORCE_NAME;
        reason = RM_RECURSIVE_FORCE_REASON;
        severity = "high";
        break;
    }
  }

  const span =
    flagState.span ??
    (paths.length > 0
      ? { start: paths[0].start, end: paths[0].end }
      : undefined);

  return { kind: "deny", hit: { patternName, reason, severity, span } };
}

// ============================================================================
// cp/ln/rsync sensitive-then-delete propagation regexes
// (filesystem.rs lines 1186-1228 + is_pre_rm_propagation_rule line 314)
// ============================================================================
//
// These are DCG `destructive_pattern!` regexes (Rust regex + fancy-regex). The
// only fancy construct used is the lookahead `(?=...)` which JS supports
// natively, so each transliterates to a SINGLE JS RegExp. No flags are set
// (DCG matches these case-sensitively). The bounded shell-boundary walkers
// `[^|;&]`, `[^|;&\s'"]`, `[\s\)'"]` are preserved verbatim. No possessive/
// atomic constructs are used. See portNotes.
//
// DELIBERATE DIVERGENCE from DCG: the copy→delete separator alternation is
// `(?:&&|;|\|\||[\r\n]+)` — DCG's upstream is `(?:&&|;|\|\|)`, which MISSES a
// NEWLINE-separated chain (`cp -a /etc/ssh /tmp/x\nrm -rf /tmp/x`) — a real
// false negative, since a newline is a statement separator exactly like `;`.
// Adding `[\r\n]+` closes that bypass (covers \n, \r\n, \r). The surrounding
// `[^|;&]*` walkers already allow newlines, so no other change is needed.

const CP_SENSITIVE_THEN_DELETE_RE =
  /\bcp\b[^|;&]*(?:\s(?:-[A-Za-z]*a[A-Za-z]*|--archive)\b)[^|;&]*?(?:\s|=)(?:['"\\]|\$['"])?(?:\/(?:etc|usr|bin|sbin|root|boot|lib|lib64|var|home|sys|proc|dev|opt)(?:\/|(?=[\s)'"]|$))|\/(?=[\s)'"]|$)|~(?=\s|$|\/|\))|\$\{?HOME\b)[^|;&]*?(?:\s|=)(?:['"\\]|\$['"])?(?:\/tmp\/|\/var\/tmp\/|\$TMPDIR\/|\$\{TMPDIR\}\/)[^|;&\s'"]*[^|;&]*(?:&&|;|\|\||[\r\n]+)[^|;&]*\brm\b[^|;&]*\s(?:-[A-Za-z]*[rR][A-Za-z]*f[A-Za-z]*|-[A-Za-z]*f[A-Za-z]*[rR][A-Za-z]*|-[rR]\s+-f|-f\s+-[rR]|--recursive\s+--force|--force\s+--recursive)[^|;&]*?(?:\s|=)(?:['"\\]|\$['"])?(?:\/tmp\/|\/var\/tmp\/|\$TMPDIR\/|\$\{TMPDIR\}\/)/;

const LN_SYMLINK_SENSITIVE_THEN_DELETE_RE =
  /\bln\b[^|;&]*\s-[A-Za-z]*s[A-Za-z]*[^|;&]*?(?:\s|=)(?:['"\\]|\$['"])?(?:\/(?:etc|usr|bin|sbin|root|boot|lib|lib64|var|home|sys|proc|dev|opt)(?:\/|(?=[\s)'"]|$))|\/(?=[\s)'"]|$)|~(?=\s|$|\/|\))|\$\{?HOME\b)[^|;&]*?(?:\s|=)(?:['"\\]|\$['"])?(?:\/tmp\/|\/var\/tmp\/|\$TMPDIR\/|\$\{TMPDIR\}\/)[^|;&\s'"]*[^|;&]*(?:&&|;|\|\||[\r\n]+)[^|;&]*\brm\b[^|;&]*\s(?:-[A-Za-z]*[rR][A-Za-z]*f[A-Za-z]*|-[A-Za-z]*f[A-Za-z]*[rR][A-Za-z]*|-[rR]\s+-f|-f\s+-[rR]|--recursive\s+--force|--force\s+--recursive)[^|;&]*?(?:\s|=)(?:['"\\]|\$['"])?(?:\/tmp\/|\/var\/tmp\/|\$TMPDIR\/|\$\{TMPDIR\}\/)/;

const RSYNC_SENSITIVE_THEN_DELETE_RE =
  /\brsync\b[^|;&]*(?:\s(?:-[A-Za-z]*a[A-Za-z]*|--archive)\b)[^|;&]*?(?:\s|=)(?:['"\\]|\$['"])?(?:\/(?:etc|usr|bin|sbin|root|boot|lib|lib64|var|home|sys|proc|dev|opt)(?:\/|(?=[\s)'"]|$))|\/(?=[\s)'"]|$)|~(?=\s|$|\/|\))|\$\{?HOME\b)[^|;&]*?(?:\s|=)(?:['"\\]|\$['"])?(?:\/tmp\/|\/var\/tmp\/|\$TMPDIR\/|\$\{TMPDIR\}\/)[^|;&\s'"]*[^|;&]*(?:&&|;|\|\||[\r\n]+)[^|;&]*\brm\b[^|;&]*\s(?:-[A-Za-z]*[rR][A-Za-z]*f[A-Za-z]*|-[A-Za-z]*f[A-Za-z]*[rR][A-Za-z]*|-[rR]\s+-f|-f\s+-[rR]|--recursive\s+--force|--force\s+--recursive)[^|;&]*?(?:\s|=)(?:['"\\]|\$['"])?(?:\/tmp\/|\/var\/tmp\/|\$TMPDIR\/|\$\{TMPDIR\}\/)/;

const PROPAGATION_RULES: ReadonlyArray<{
  name: string;
  re: RegExp;
  reason: string;
}> = [
  {
    name: "cp-sensitive-then-delete",
    re: CP_SENSITIVE_THEN_DELETE_RE,
    reason:
      "archive copy of a sensitive path into temp followed by forced recursive deletion is a cross-segment data-loss bypass. EXTREMELY DANGEROUS.",
  },
  {
    name: "ln-symlink-sensitive-then-delete",
    re: LN_SYMLINK_SENSITIVE_THEN_DELETE_RE,
    reason:
      "symlink from a sensitive path into temp followed by forced recursive deletion can traverse and destroy the target. EXTREMELY DANGEROUS.",
  },
  {
    name: "rsync-sensitive-then-delete",
    re: RSYNC_SENSITIVE_THEN_DELETE_RE,
    reason:
      "rsync archive of a sensitive path into temp followed by forced recursive deletion is a cross-segment data-loss bypass. EXTREMELY DANGEROUS.",
  },
];

// Port of is_pre_rm_propagation_rule — exported for the engine wiring.
export function isPreRmPropagationRule(name: string | undefined): boolean {
  return (
    name === "cp-sensitive-then-delete" ||
    name === "ln-symlink-sensitive-then-delete" ||
    name === "rsync-sensitive-then-delete"
  );
}

// Does ANY propagation rule match the (full) command? Mirrors the
// `has_pre_rm_propagation_match` guard in evaluator.rs (line ~1909).
function hasPreRmPropagationMatch(fullCommand: string): boolean {
  return PROPAGATION_RULES.some((rule) => rule.re.test(fullCommand));
}

// ============================================================================
// ImperativeCheck wrappers (the exported contract)
// ============================================================================

function denyDecisionFromRm(hit: RmParseMatch): EngineDecision {
  return {
    decision: "deny",
    blocked: true,
    packId: PACK_ID,
    ruleId: `${PACK_ID}:${hit.patternName}`,
    ruleName: hit.patternName,
    severity: hit.severity,
    reason: hit.reason,
  };
}

// removalCheck: port of evaluator.rs core.filesystem rm_parse handling.
//
// Faithfulness note: in DCG, an rm_parse `Allow` only short-circuits the pack
// when there is NO pre-rm propagation match; if a propagation rule matches, the
// evaluator FALLS THROUGH so the propagation `destructive_pattern!` (Critical)
// fires. We replicate that by NOT emitting an allow decision when a propagation
// match exists — letting cpLnRsyncPropagationCheck (next in the imperative
// array) deny. See evaluator.rs lines ~1909-1932 and portNotes.
const removalCheck: ImperativeCheck = (
  _ctx: SegmentContext,
  fullCommand: string,
): EngineDecision | undefined => {
  const decision = parseRmCommand(fullCommand);
  switch (decision.kind) {
    case "deny":
      return denyDecisionFromRm(decision.hit);
    case "allow":
      // Only short-circuit-allow when no propagation chain is present.
      if (hasPreRmPropagationMatch(fullCommand)) {
        return undefined;
      }
      return {
        decision: "allow",
        blocked: false,
        packId: PACK_ID,
        allowReason: "rm targets only temp-safe paths (rm-parser Allow)",
      };
    case "noMatch":
      return undefined;
  }
};

// cpLnRsyncPropagationCheck: port of the three `*-sensitive-then-delete`
// destructive_pattern! regexes, first-match-wins in declaration order
// (cp, ln, rsync). All Critical (=> deny).
const cpLnRsyncPropagationCheck: ImperativeCheck = (
  _ctx: SegmentContext,
  fullCommand: string,
): EngineDecision | undefined => {
  for (const rule of PROPAGATION_RULES) {
    if (rule.re.test(fullCommand)) {
      return {
        decision: "deny",
        blocked: true,
        packId: PACK_ID,
        ruleId: `${PACK_ID}:${rule.name}`,
        ruleName: rule.name,
        severity: "critical",
        reason: rule.reason,
      };
    }
  }
  return undefined;
};

export const rmImperativeChecks: ImperativeCheck[] = [
  removalCheck,
  cpLnRsyncPropagationCheck,
];
