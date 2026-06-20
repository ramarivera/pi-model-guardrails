// src/engine/heredoc.ts
//
// Faithful TypeScript port of DCG's two-tier heredoc / inline-script detection
// (src/heredoc.rs). The public surface here is intentionally narrow: the engine
// only needs the *bodies* that should ALSO be scanned as commands, so this module
// ports Tier 1 (trigger detection) + Tier 2 (bounded content extraction) and
// exposes the extracted body strings via `extractHeredocBodies`.
//
// Ported pieces (see src/heredoc.rs):
//   - HEREDOC_TRIGGER_PATTERNS / check_triggers / contains_active_heredoc_operator
//     (the quote-aware `<<`/`<<<` scanner that suppresses heredoc syntax inside
//      single/double quotes while still descending into $() and backticks).
//   - extract_content -> extract_inline_scripts / extract_herestrings /
//     extract_heredocs, including ExtractionLimits, binary-content guard,
//     timeout/size/line/heredoc-count bounds, and per-interpreter inline-flag
//     validation (is_inline_flag).
//   - ScriptLanguage::from_command (used for inline-script language; not exported,
//     but its matching rules drive the inline-flag validation).
//
// NOT ported here (out of scope for body extraction): tree-sitter AST shell
// command extraction (`extract_shell_commands`), masking
// (`mask_non_executing_heredocs`), git-stdin-sink detection, language confidence
// reporting. Masking and command re-scanning are the evaluator's concern; this
// module only surfaces raw bodies.

// ============================================================================
// Limits (ported from ExtractionLimits::default)
// ============================================================================

interface ExtractionLimits {
  /** Maximum bytes to extract from a body (default: 1MB). */
  maxBodyBytes: number;
  /** Maximum lines to extract from a heredoc body (default: 10,000). */
  maxBodyLines: number;
  /** Maximum number of heredocs/scripts to process per command (default: 10). */
  maxHeredocs: number;
  /** Timeout for extraction in milliseconds (default: 50ms). */
  timeoutMs: number;
}

const DEFAULT_LIMITS: ExtractionLimits = {
  maxBodyBytes: 1024 * 1024,
  maxBodyLines: 10_000,
  maxHeredocs: 10,
  timeoutMs: 50,
};

// ============================================================================
// Tier 1: Trigger detection
// ============================================================================

// Ported from HEREDOC_TRIGGER_PATTERNS (src/heredoc.rs).
//
// JS RegExp porting notes:
//   - The inline `(?i)` on the PowerShell pattern is stripped; the whole pattern
//     gets the "i" flag (it only matches the interpreter+flag, which is the part
//     DCG made case-insensitive anyway).
//   - `<<<` (here-string operator) is in the RegexSet in DCG; here it is folded
//     into the quote-aware scanner via `contains_active_heredoc_operator`, which
//     already triggers on any `<<` (and therefore `<<<`). Keeping `<<<` in the
//     trigger list too is harmless (superset semantics) but DCG actually relies
//     on the scanner for `<<<` inside quotes, so we keep it in the scanner path.
//     We retain the literal `<<<` pattern below to mirror DCG's RegexSet exactly.
//   - Bounded shell-boundary walkers (`[A-Za-z]*`, `(?:\s|['"]|$)`) are kept
//     verbatim; no `.*` substitutions.
const HEREDOC_TRIGGER_SOURCES: Array<{ src: string; flags: string }> = [
  // Here-string operator (<<<). Tier 1 must over-trigger; the scanner also
  // catches this, but DCG lists it explicitly.
  { src: String.raw`<<<`, flags: "" },
  // Python inline execution.
  {
    src: String.raw`\bpython[0-9.]*(?:\.exe)?\b(?:\s+(?:--\S+|-[A-Za-z]+))*\s+-[A-Za-z]*[ce][A-Za-z]*(?:\s|['"]|$)`,
    flags: "",
  },
  // Ruby inline execution.
  {
    src: String.raw`\bruby[0-9.]*(?:\.exe)?\b(?:\s+(?:--\S+|-[A-Za-z]+))*\s+-[A-Za-z]*e[A-Za-z]*(?:\s|['"]|$)`,
    flags: "",
  },
  {
    src: String.raw`\birb[0-9.]*(?:\.exe)?\b(?:\s+(?:--\S+|-[A-Za-z]+))*\s+-[A-Za-z]*e[A-Za-z]*(?:\s|['"]|$)`,
    flags: "",
  },
  // Perl inline execution.
  {
    src: String.raw`\bperl[0-9.]*(?:\.exe)?\b(?:\s+(?:--\S+|-[A-Za-z]+))*\s+-[A-Za-z]*[eE][A-Za-z]*(?:\s|['"]|$)`,
    flags: "",
  },
  // Node.js inline execution.
  {
    src: String.raw`\bnode(?:js)?[0-9.]*(?:\.exe)?\b(?:\s+(?:--\S+|-[A-Za-z]+))*\s+-[A-Za-z]*[ep][A-Za-z]*(?:\s|['"]|$)`,
    flags: "",
  },
  // PHP inline execution.
  {
    src: String.raw`\bphp[0-9.]*(?:\.exe)?\b(?:\s+(?:--\S+|-[A-Za-z]+))*\s+-[A-Za-z]*r[A-Za-z]*(?:\s|['"]|$)`,
    flags: "",
  },
  // Lua inline execution.
  {
    src: String.raw`\blua[0-9.]*(?:\.exe)?\b(?:\s+(?:--\S+|-[A-Za-z]+))*\s+-[A-Za-z]*e[A-Za-z]*(?:\s|['"]|$)`,
    flags: "",
  },
  // Shell inline execution.
  {
    src: String.raw`\b(?:sh|bash|zsh|fish)(?:\.exe)?\b(?:\s+(?:--\S+|-[A-Za-z]+))*\s+-[A-Za-z]*c[A-Za-z]*(?:\s|['"]|$)`,
    flags: "",
  },
  // PowerShell inline execution. DCG used inline `(?i)`; ported to the "i" flag.
  {
    src: String.raw`\b(?:powershell|pwsh)(?:\.exe)?["']?(?:\s+(?:-\S+))*\s+-c[a-z]*\s*['"]`,
    flags: "i",
  },
  // Piped execution to interpreters.
  {
    src: String.raw`\|\s*(?:python[0-9.]*|ruby[0-9.]*|perl[0-9.]*|node(?:js)?[0-9.]*|php[0-9.]*|lua[0-9.]*|sh|bash)(?:\.exe)?\b`,
    flags: "",
  },
  // Piped to xargs.
  { src: String.raw`\|\s*xargs\s`, flags: "" },
  // eval/exec with quoted argument.
  { src: String.raw`\beval\s+['"]`, flags: "" },
  { src: String.raw`\bexec\s+['"]`, flags: "" },
];

const HEREDOC_TRIGGERS: RegExp[] = HEREDOC_TRIGGER_SOURCES.map(
  ({ src, flags }) => new RegExp(src, flags),
);

/**
 * Quote-aware scanner for an *active* `<<` / `<<<` shell operator.
 *
 * Ported from `contains_active_heredoc_operator` + the recursive
 * scan_* helpers in src/heredoc.rs. It suppresses `<<` that appears inside
 * single/double-quoted literals (documentation, search patterns) while still
 * descending into `$(...)` command substitutions and backtick substitutions,
 * where a `<<` IS active even when the outer word is double-quoted.
 *
 * Operates on UTF-16 code units (JS string indices). DCG operates on bytes; for
 * the ASCII operators `< ' " $ ( ) ` \` involved this is equivalent. Recursion
 * is bounded at depth 500 -> conservatively returns `true` (Tier 1 may
 * over-trigger; it must never under-trigger).
 */
function containsActiveHeredocOperator(command: string): boolean {
  if (command.indexOf("<") === -1) {
    return false;
  }
  return scanTopLevel(command, 0, 0);
}

const MAX_DEPTH = 500;

function scanTopLevel(s: string, start: number, depth: number): boolean {
  if (depth > MAX_DEPTH) {
    return true;
  }
  const len = s.length;
  let i = Math.min(start, len);
  while (i < len) {
    const c = s[i];
    if (c === "<" && i + 1 < len && s[i + 1] === "<") {
      return true;
    } else if (c === "\\") {
      // CRLF escape consumes 3 units; otherwise skip the escaped char.
      if (i + 2 < len && s[i + 1] === "\r" && s[i + 2] === "\n") {
        i += 3;
      } else {
        i = Math.min(i + 2, len);
      }
    } else if (c === "'") {
      i += 1;
      while (i < len && s[i] !== "'") i += 1;
      if (i < len) i += 1;
    } else if (c === '"') {
      const [found, next] = scanDoubleQuotes(s, i + 1, depth);
      if (found) return true;
      i = next;
    } else if (c === "$" && i + 1 < len && s[i + 1] === "(") {
      const [found, next] = scanDollarParen(s, i, depth + 1);
      if (found) return true;
      i = next;
    } else if (c === "`") {
      const [found, next] = scanBackticks(s, i, depth + 1);
      if (found) return true;
      i = next;
    } else {
      i += 1;
    }
  }
  return false;
}

function scanDoubleQuotes(
  s: string,
  start: number,
  depth: number,
): [boolean, number] {
  if (depth > MAX_DEPTH) {
    return [true, s.length];
  }
  const len = s.length;
  let i = Math.min(start, len);
  while (i < len) {
    const c = s[i];
    if (c === '"') {
      return [false, i + 1];
    } else if (c === "\\") {
      i = Math.min(i + 2, len);
    } else if (c === "$" && i + 1 < len && s[i + 1] === "(") {
      const [found, next] = scanDollarParen(s, i, depth + 1);
      if (found) return [true, next];
      i = next;
    } else if (c === "`") {
      const [found, next] = scanBackticks(s, i, depth + 1);
      if (found) return [true, next];
      i = next;
    } else {
      i += 1;
    }
  }
  return [false, len];
}

function scanDollarParen(
  s: string,
  start: number,
  depth: number,
): [boolean, number] {
  if (depth > MAX_DEPTH) {
    return [true, s.length];
  }
  const len = s.length;
  // Caller guarantees s[start]=='$' && s[start+1]=='('.
  let i = start + 2;
  let pdepth = 1;
  while (i < len) {
    const c = s[i];
    if (c === "<" && i + 1 < len && s[i + 1] === "<") {
      return [true, i + 2];
    } else if (c === "(") {
      pdepth += 1;
      i += 1;
    } else if (c === ")") {
      if (pdepth === 1) {
        return [false, i + 1];
      }
      pdepth = pdepth > 0 ? pdepth - 1 : 0;
      i += 1;
    } else if (c === "\\") {
      i = Math.min(i + 2, len);
    } else if (c === "'") {
      i += 1;
      while (i < len && s[i] !== "'") i += 1;
      if (i < len) i += 1;
    } else if (c === '"') {
      const [found, next] = scanDoubleQuotes(s, i + 1, depth);
      if (found) return [true, next];
      i = next;
    } else if (c === "$" && i + 1 < len && s[i + 1] === "(") {
      const [found, next] = scanDollarParen(s, i, depth + 1);
      if (found) return [true, next];
      i = next;
    } else if (c === "`") {
      const [found, next] = scanBackticks(s, i, depth + 1);
      if (found) return [true, next];
      i = next;
    } else {
      i += 1;
    }
  }
  return [false, len];
}

function scanBackticks(
  s: string,
  start: number,
  depth: number,
): [boolean, number] {
  if (depth > MAX_DEPTH) {
    return [true, s.length];
  }
  const len = s.length;
  // Caller guarantees s[start]=='`'.
  let i = start + 1;
  while (i < len) {
    const c = s[i];
    if (c === "<" && i + 1 < len && s[i + 1] === "<") {
      return [true, i + 2];
    } else if (c === "\\") {
      i = Math.min(i + 2, len);
    } else if (c === "'") {
      i += 1;
      while (i < len && s[i] !== "'") i += 1;
      if (i < len) i += 1;
    } else if (c === '"') {
      const [found, next] = scanDoubleQuotes(s, i + 1, depth);
      if (found) return [true, next];
      i = next;
    } else if (c === "$" && i + 1 < len && s[i + 1] === "(") {
      const [found, next] = scanDollarParen(s, i, depth + 1);
      if (found) return [true, next];
      i = next;
    } else if (c === "`") {
      return [false, i + 1];
    } else {
      i += 1;
    }
  }
  return [false, len];
}

/**
 * Tier 1 trigger detection. Returns `true` if the command contains heredoc /
 * here-string / inline-script indicators. Ported from `check_triggers`.
 */
export function checkTriggers(command: string): boolean {
  if (containsActiveHeredocOperator(command)) {
    return true;
  }
  for (const re of HEREDOC_TRIGGERS) {
    re.lastIndex = 0;
    if (re.test(command)) {
      return true;
    }
  }
  return false;
}

// ============================================================================
// Tier 2: Content extraction
// ============================================================================

type HeredocType =
  | "standard"
  | "tab-stripped"
  | "here-string"
  | "indent-stripped";

// Heredoc extractor: <<[-~]? followed by quoted/unquoted delimiter.
// Ported verbatim from HEREDOC_EXTRACTOR (src/heredoc.rs). Group 1 = operator
// variant (-/~), Group 2 = single-quoted delim, Group 3 = double-quoted delim,
// Group 4 = unquoted delim. `*` (not `+`) allows empty delimiters.
const HEREDOC_EXTRACTOR = /<<([-~])?\s*(?:'([^']*)'|"([^"]*)"|([\w.-]+))/g;

// Here-string extractors (ported verbatim).
const HERESTRING_SINGLE_QUOTE = /<<<\s*'([^']*)'/g;
const HERESTRING_DOUBLE_QUOTE = /<<<\s*"([^"]*)"/g;
// `[^'\x22\s]` ensures we don't match quoted forms; \x22 is the double quote.
const HERESTRING_UNQUOTED = /<<<\s*([^'\x22\s]\S*)/g;

// Inline-script interpreter alternation, shared by both quote variants.
// JS RegExp porting note: DCG's `(?i:powershell|pwsh)` scoped-inline-flag group
// is invalid in JS. Rewritten to an explicit case-folded character alternation
// so ONLY the PowerShell host name is case-insensitive (matching DCG), while the
// rest of the alternation stays case-sensitive (a blanket "i" flag would wrongly
// match `PYTHON`, `BASH`, etc., which DCG does not).
const POWERSHELL_CI =
  "[Pp][Oo][Ww][Ee][Rr][Ss][Hh][Ee][Ll][Ll]|[Pp][Ww][Ss][Hh]";
const INLINE_INTERP =
  "(python[0-9.]*(?:\\.exe)?|ruby[0-9.]*(?:\\.exe)?|irb[0-9.]*(?:\\.exe)?|perl[0-9.]*(?:\\.exe)?|node(js)?[0-9.]*(?:\\.exe)?|php[0-9.]*(?:\\.exe)?|lua[0-9.]*(?:\\.exe)?|sh(?:\\.exe)?|bash(?:\\.exe)?|zsh(?:\\.exe)?|fish(?:\\.exe)?|(?:" +
  POWERSHELL_CI +
  ")(?:\\.exe)?)";

// Group layout matches DCG: (1) interpreter, (2) optional "js" suffix, (3) flag,
// (4) content.
const INLINE_SCRIPT_SINGLE_QUOTE = new RegExp(
  "\\b" +
    INLINE_INTERP +
    "\\b['\"]?(?:\\s+(?:--\\S+|-[A-Za-z]+))*\\s+(-[A-Za-z]*[ceECpr][A-Za-z]*)\\s*'([^']*)'",
  "g",
);
const INLINE_SCRIPT_DOUBLE_QUOTE = new RegExp(
  "\\b" +
    INLINE_INTERP +
    '\\b[\'"]?(?:\\s+(?:--\\S+|-[A-Za-z]+))*\\s+(-[A-Za-z]*[ceECpr][A-Za-z]*)\\s*"([^"]*)"',
  "g",
);

const BINARY_THRESHOLD = 0.3; // 30% non-printable characters.

/**
 * Detect binary-like content (null bytes or high non-printable ratio).
 * Ported from `check_binary_content`. Returns `true` if the content should be
 * skipped as binary.
 */
function isBinaryContent(content: string): boolean {
  if (content.length === 0) {
    return false;
  }
  let nullBytes = 0;
  let suspect = 0;
  let total = 0;
  for (const ch of content) {
    total += 1;
    const code = ch.codePointAt(0)!;
    if (code === 0) {
      nullBytes += 1;
    }
    // Control chars (excluding \n \r \t) and U+FFFD replacement char.
    const isControl = code < 0x20 || (code >= 0x7f && code <= 0x9f);
    if (
      (isControl && ch !== "\n" && ch !== "\r" && ch !== "\t") ||
      code === 0xfffd
    ) {
      suspect += 1;
    }
  }
  if (nullBytes > 0) {
    return true;
  }
  const ratio = suspect / Math.max(total, 1);
  return ratio > BINARY_THRESHOLD;
}

// `ScriptLanguage::from_command` matching rules, distilled to the predicates we
// need for inline-flag validation. `matchesInterpreter(base, cmd)` mirrors the
// version-suffix rule (`python` matches `python3`, `python3.11`, but not
// `pythonic`). `.exe` is stripped and matching is case-insensitive (DCG lower-
// cases the command before matching). Currently unused directly but kept for
// fidelity / future language-aware extension.
function stripExe(cmdLower: string): string {
  return cmdLower.endsWith(".exe") ? cmdLower.slice(0, -4) : cmdLower;
}

function matchesInterpreter(base: string, cmd: string): boolean {
  const cmdBase = stripExe(cmd.toLowerCase());
  if (cmdBase === base) {
    return true;
  }
  if (!cmdBase.startsWith(base)) {
    return false;
  }
  const suffix = cmdBase.slice(base.length);
  if (suffix.length === 0) {
    return false;
  }
  // All chars must be digits or dots, and the first must be a digit.
  if (!/^[0-9][0-9.]*$/.test(suffix)) {
    return false;
  }
  return true;
}
void matchesInterpreter; // retained for fidelity; not on the hot path here.

/**
 * Validate that the matched flag actually implies inline code for this
 * interpreter. Ported from the `is_inline_flag` block in `extract_inline_scripts`.
 *
 * Note: DCG uses `starts_with` (prefix, case-sensitive except PowerShell) on the
 * raw matched interpreter token, e.g. `cmd_name.starts_with("python")`.
 */
function isInlineFlag(cmdName: string, flag: string): boolean {
  const cmdLower = cmdName.toLowerCase();
  const isPowershell =
    cmdLower.startsWith("powershell") || cmdLower.startsWith("pwsh");
  if (cmdName.startsWith("python")) {
    return flag.includes("c") || flag.includes("e");
  } else if (cmdName.startsWith("ruby") || cmdName.startsWith("irb")) {
    return flag.includes("e");
  } else if (cmdName.startsWith("perl")) {
    return flag.includes("e") || flag.includes("E");
  } else if (cmdName.startsWith("node")) {
    return flag.includes("e") || flag.includes("p");
  } else if (cmdName.startsWith("php")) {
    return flag.includes("r");
  } else if (cmdName.startsWith("lua")) {
    return flag.includes("e");
  } else if (isPowershell) {
    // `-Command` is accepted as any unambiguous prefix (`-c`, `-co`, …),
    // case-insensitively.
    return flag.toLowerCase().startsWith("-c");
  } else {
    // sh/bash/zsh/fish
    return flag.includes("c");
  }
}

interface TimerState {
  start: number;
  timeoutMs: number;
  timedOut: boolean;
}

function timedOut(t: TimerState): boolean {
  if (t.timedOut) {
    return true;
  }
  // DCG checks `elapsed >= timeout`. With a 0ms budget this is immediately true.
  if (now() - t.start >= t.timeoutMs) {
    t.timedOut = true;
    return true;
  }
  return false;
}

function now(): number {
  // Monotonic-ish; Date.now is fine for the small budgets DCG uses.
  return Date.now();
}

/**
 * Extract inline-script bodies (-c/-e/... flags). Ported from
 * `extract_inline_scripts`. Pushes body strings into `out`.
 */
function extractInlineScripts(
  command: string,
  limits: ExtractionLimits,
  timer: TimerState,
  out: string[],
): void {
  if (timedOut(timer)) return;
  if (out.length >= limits.maxHeredocs) return;

  const fromPattern = (re: RegExp): boolean => {
    re.lastIndex = 0;
    let m: RegExpExecArray | null;
    // biome-ignore lint/suspicious/noAssignInExpressions: canonical regex-walk `while ((m = re.exec()) !== null)` idiom
    while ((m = re.exec(command)) !== null) {
      if (m.index === re.lastIndex) re.lastIndex += 1; // guard against zero-width
      if (timedOut(timer)) return true;
      if (out.length >= limits.maxHeredocs) {
        return true; // hit limit
      }
      const cmdName = m[1] ?? "";
      const flag = m[3] ?? "";
      const content = m[4] ?? "";
      if (!isInlineFlag(cmdName, flag)) {
        continue;
      }
      if (content.length > limits.maxBodyBytes) {
        continue;
      }
      out.push(content);
    }
    return false;
  };

  // Both quote variants, single first then double (DCG order).
  if (fromPattern(INLINE_SCRIPT_SINGLE_QUOTE)) return;
  fromPattern(INLINE_SCRIPT_DOUBLE_QUOTE);
}

/**
 * Extract here-string bodies (<<<). Ported from `extract_herestrings`.
 */
function extractHerestrings(
  command: string,
  limits: ExtractionLimits,
  timer: TimerState,
  out: string[],
): void {
  if (timedOut(timer)) return;
  if (out.length >= limits.maxHeredocs) return;

  const fromPattern = (re: RegExp): boolean => {
    re.lastIndex = 0;
    let m: RegExpExecArray | null;
    // biome-ignore lint/suspicious/noAssignInExpressions: canonical regex-walk `while ((m = re.exec()) !== null)` idiom
    while ((m = re.exec(command)) !== null) {
      if (m.index === re.lastIndex) re.lastIndex += 1;
      if (timedOut(timer)) return true;
      if (out.length >= limits.maxHeredocs) {
        return true;
      }
      const content = m[1] ?? "";
      if (content.length > limits.maxBodyBytes) {
        continue;
      }
      out.push(content);
    }
    return false;
  };

  // Quoted first (so unquoted doesn't swallow the outer quotes), then unquoted.
  if (fromPattern(HERESTRING_SINGLE_QUOTE)) return;
  if (fromPattern(HERESTRING_DOUBLE_QUOTE)) return;
  fromPattern(HERESTRING_UNQUOTED);
}

/**
 * Extract the body of a single heredoc. Returns `null` when the body could not
 * be extracted (unterminated, over a size/line bound, or timeout) — DCG returns
 * a SkipReason in those cases. Ported from `extract_heredoc_body`.
 */
function extractHeredocBody(
  command: string,
  start: number,
  delimiter: string,
  heredocType: HeredocType,
  limits: ExtractionLimits,
  timer: TimerState,
): string | null {
  if (start > command.length) {
    return null; // malformed: start out of bounds
  }
  const remaining = command.slice(start);
  // Skip leading newline if present (body starts on next line).
  const bodyStartOffset = remaining.startsWith("\n") ? 1 : 0;
  const bodyStart = remaining.slice(bodyStartOffset);

  const bodyLines: string[] = [];
  let totalBytes = 0;

  // split_inclusive('\n') -> iterate line-by-line keeping the trailing newline.
  let cursor = 0;
  const len = bodyStart.length;
  while (cursor < len) {
    if (timedOut(timer)) {
      return null; // timeout
    }
    const nl = bodyStart.indexOf("\n", cursor);
    const partEnd = nl === -1 ? len : nl + 1;
    const part = bodyStart.slice(cursor, partEnd);

    // Strip trailing '\n' then trailing '\r' (CRLF normalization).
    let line = part.endsWith("\n") ? part.slice(0, -1) : part;
    line = line.endsWith("\r") ? line.slice(0, -1) : line;

    // Terminator check (type-aware leading-whitespace stripping).
    let trimmed: string;
    if (heredocType === "tab-stripped") {
      trimmed = line.replace(/^\t+/, "");
    } else if (heredocType === "indent-stripped") {
      trimmed = line.replace(/^\s+/, "");
    } else {
      trimmed = line;
    }

    if (trimmed === delimiter) {
      return joinHeredocBody(bodyLines, heredocType);
    }

    // Enforce limits (fail-open by returning null).
    totalBytes += part.length;
    if (totalBytes > limits.maxBodyBytes) {
      return null; // exceeded size limit
    }
    if (bodyLines.length >= limits.maxBodyLines) {
      return null; // exceeded line limit
    }

    bodyLines.push(line);
    cursor = partEnd;
  }

  // Unterminated heredoc.
  return null;
}

function joinHeredocBody(
  bodyLines: string[],
  heredocType: HeredocType,
): string {
  if (heredocType === "tab-stripped") {
    return bodyLines.map((l) => l.replace(/^\t+/, "")).join("\n");
  }
  if (heredocType === "indent-stripped") {
    // Common-leading-whitespace strip (squiggly heredoc). DCG computes the min
    // indent over non-blank lines in *bytes*; in JS we operate on the leading
    // whitespace run length in code units. For the all-ASCII / consistent-
    // whitespace common case this is equivalent. For mixed multi-byte whitespace
    // DCG falls back to `trim_start()` per line when the byte offset misaligns;
    // we apply the same conservative fallback when a line is shorter than the
    // computed indent.
    const indents = bodyLines
      .filter((l) => l.trim().length > 0)
      .map((l) => l.length - l.replace(/^\s+/, "").length);
    const minIndent = indents.length > 0 ? Math.min(...indents) : 0;
    return bodyLines
      .map((l) =>
        l.length >= minIndent ? l.slice(minIndent) : l.replace(/^\s+/, ""),
      )
      .join("\n");
  }
  // standard / here-string
  return bodyLines.join("\n");
}

/**
 * Extract heredoc bodies (<<, <<-, <<~). Ported from `extract_heredocs`.
 */
function extractHeredocs(
  command: string,
  limits: ExtractionLimits,
  timer: TimerState,
  out: string[],
): void {
  if (timedOut(timer)) return;
  if (out.length >= limits.maxHeredocs) return;

  HEREDOC_EXTRACTOR.lastIndex = 0;
  let cap: RegExpExecArray | null;
  // biome-ignore lint/suspicious/noAssignInExpressions: canonical regex-walk `while ((cap = exec()) !== null)` idiom
  while ((cap = HEREDOC_EXTRACTOR.exec(command)) !== null) {
    if (cap.index === HEREDOC_EXTRACTOR.lastIndex)
      HEREDOC_EXTRACTOR.lastIndex += 1;
    if (timedOut(timer)) return;
    if (out.length >= limits.maxHeredocs) {
      return;
    }

    const operatorVariant = cap[1];
    let delimiter: string;
    if (cap[2] !== undefined) {
      delimiter = cap[2];
    } else if (cap[3] !== undefined) {
      delimiter = cap[3];
    } else if (cap[4] !== undefined) {
      delimiter = cap[4];
    } else {
      continue; // unreachable if regex matched
    }

    let heredocType: HeredocType;
    if (operatorVariant === "-") {
      heredocType = "tab-stripped";
    } else if (operatorVariant === "~") {
      heredocType = "indent-stripped";
    } else {
      heredocType = "standard";
    }

    const fullMatchEnd = cap.index + cap[0].length;
    // Body starts on the next line. Skip any trailing tokens after the
    // delimiter on the same line (pipelines, redirects, etc.).
    const nlRel = command.slice(fullMatchEnd).indexOf("\n");
    const startPos = nlRel === -1 ? command.length : fullMatchEnd + nlRel;

    const body = extractHeredocBody(
      command,
      startPos,
      delimiter,
      heredocType,
      limits,
      timer,
    );
    if (body !== null) {
      out.push(body);
    } else if (timer.timedOut) {
      return;
    }
  }
}

/**
 * Extract heredoc / here-string / inline-script bodies that the evaluator should
 * ALSO scan as commands.
 *
 * This is the public surface ported from DCG's Tier 1 + Tier 2 pipeline
 * (`check_triggers` gate -> `extract_content`). It returns the raw body strings
 * (the `ExtractedContent.content` values in DCG), in DCG's extraction order:
 * inline scripts, then here-strings, then heredocs.
 *
 * Bounded/safe: respects an input-size guard, a binary-content guard, and the
 * per-body byte/line/count limits and time budget from `ExtractionLimits`. On
 * any bound/timeout it fails open (returns what was extracted so far), exactly
 * like DCG's hook-mode fail-open contract.
 */
export function extractHeredocBodies(
  command: string,
  limits: ExtractionLimits = DEFAULT_LIMITS,
): string[] {
  // Tier 1 fast path: no trigger -> nothing to extract.
  if (!checkTriggers(command)) {
    return [];
  }

  // Input size guard (DCG: ExceededSizeLimit -> Skipped).
  if (command.length > limits.maxBodyBytes) {
    return [];
  }
  // Binary-content guard (DCG: BinaryContent -> Skipped).
  if (isBinaryContent(command)) {
    return [];
  }

  const timer: TimerState = {
    start: now(),
    timeoutMs: limits.timeoutMs,
    timedOut: false,
  };
  const out: string[] = [];

  if (timedOut(timer)) {
    return out;
  }

  extractInlineScripts(command, limits, timer, out);
  if (timedOut(timer)) {
    return out;
  }

  extractHerestrings(command, limits, timer, out);
  if (timedOut(timer)) {
    return out;
  }

  extractHeredocs(command, limits, timer, out);

  return out;
}
