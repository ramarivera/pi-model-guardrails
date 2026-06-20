// Command normalization for the DCG-ported deterministic command-guard engine.
//
// Faithful TypeScript port of:
//   - DCG `src/normalize.rs`  (wrapper stripping, command-word dequoting, tokenizer)
//   - DCG `src/packs/mod.rs`  (split_command_segments + subshell extraction helpers)
//
// Public surface (per the engine module-signature contract):
//   - stripWrapperPrefixes(command): strip leading sudo/env/command/backslash
//     wrappers (DCG) plus the contract-extension wrappers nice/nohup/time/doas/exec,
//     then dequote the leading command word, so a wrapped/quoted command normalizes
//     down to the bare underlying command.
//   - splitCommandSegments(command): quote/escape-aware split on && || ; |, with
//     $(...) / <(...) / >(...) / backtick subshells extracted as their own segments.
//     Redirection (& > >>) is NOT a split point.
//   - classifySegment(segment): produce { raw, normalized, executable, spans }.
//   - normalizeCommand(command): splitCommandSegments -> classifySegment each.
//
// Source-of-truth refs are cited inline. Where DCG splits work across a
// byte-oriented hand-rolled state machine plus `fancy_regex`, this port collapses
// to JS string/RegExp while preserving the exact byte-walking semantics. DCG walks
// raw UTF-8 bytes; JS strings are UTF-16. We operate on a byte view (utf-8) where
// DCG's logic is byte-indexed so multi-byte characters cannot desync the walkers.

import type { SegmentContext, Span, SpanKind } from "./types.ts";

// ---------------------------------------------------------------------------
// Byte helpers — DCG operates on `&[u8]`. To stay byte-faithful (its index math
// and the bounded boundary walkers like `[^\s&;|`()<>]` are byte-oriented), we
// encode to UTF-8 once, walk bytes, and slice back to strings via the same byte
// offsets. This guarantees identical behavior to the Rust on every input,
// including non-ASCII.
// ---------------------------------------------------------------------------

const ENC = new TextEncoder();
const DEC = new TextDecoder();

function toBytes(s: string): Uint8Array {
  return ENC.encode(s);
}

function fromBytes(b: Uint8Array, start: number, end: number): string {
  return DEC.decode(b.subarray(start, end));
}

// ASCII char-code constants (DCG uses byte literals like b'-').
const C = {
  TAB: 9,
  LF: 10,
  CR: 13,
  SPACE: 32,
  DQUOTE: 34, // "
  DOLLAR: 36, // $
  AMP: 38, // &
  SQUOTE: 39, // '
  LPAREN: 40, // (
  RPAREN: 41, // )
  ZERO: 48,
  NINE: 57,
  SEMI: 59, // ;
  LT: 60, // <
  GT: 62, // >
  BACKSLASH: 92, // \
  BACKTICK: 96, // `
  PIPE: 124, // |
} as const;

function isAsciiWhitespace(b: number): boolean {
  // Rust char::is_ascii_whitespace: space, \t, \n, \r, \f (0x0C).
  return b === C.SPACE || b === C.TAB || b === C.LF || b === C.CR || b === 0x0c;
}

function isAsciiDigit(b: number): boolean {
  return b >= C.ZERO && b <= C.NINE;
}

function isAsciiAlphanumeric(b: number): boolean {
  return (b >= 48 && b <= 57) || (b >= 65 && b <= 90) || (b >= 97 && b <= 122);
}

// ---------------------------------------------------------------------------
// consume_word_token / consume_shell_paren_construct
// Ported VERBATIM from DCG src/normalize.rs (consume_word_token,
// consume_shell_paren_construct). These power the normalization tokenizer.
// ---------------------------------------------------------------------------

export function consumeWordToken(
  bytes: Uint8Array,
  iStart: number,
  len: number,
): number {
  let i = iStart;
  while (i < len) {
    const b = bytes[i];

    if (isAsciiWhitespace(b)) break;

    if (b === C.DOLLAR && i + 1 < len && bytes[i + 1] === C.LPAREN) {
      i = consumeShellParenConstruct(bytes, i + 2, len);
      continue;
    }

    if (
      (b === C.LT || b === C.GT) &&
      i + 1 < len &&
      bytes[i + 1] === C.LPAREN
    ) {
      i = consumeShellParenConstruct(bytes, i + 2, len);
      continue;
    }

    if (b === C.AMP && i + 1 < len && bytes[i + 1] === C.GT) {
      i += 2;
      if (i < len && bytes[i] === C.GT) i += 1;
      continue;
    }

    if (
      b === C.PIPE ||
      b === C.SEMI ||
      b === C.AMP ||
      b === C.LPAREN ||
      b === C.RPAREN
    ) {
      break;
    }

    switch (b) {
      case C.BACKSLASH: {
        // Handle CRLF escape (consumes 3 bytes: \, \r, \n)
        if (i + 2 < len && bytes[i + 1] === C.CR && bytes[i + 2] === C.LF) {
          i += 3;
        } else {
          i = Math.min(i + 2, len);
        }
        break;
      }
      case C.SQUOTE: {
        i += 1;
        while (i < len && bytes[i] !== C.SQUOTE) i += 1;
        if (i < len) i += 1;
        break;
      }
      case C.DQUOTE: {
        i += 1;
        while (i < len) {
          const c = bytes[i];
          if (c === C.DQUOTE) {
            i += 1;
            break;
          } else if (c === C.BACKSLASH) {
            i = Math.min(i + 2, len);
          } else if (
            c === C.DOLLAR &&
            i + 1 < len &&
            bytes[i + 1] === C.LPAREN
          ) {
            i = consumeShellParenConstruct(bytes, i + 2, len);
          } else {
            i += 1;
          }
        }
        break;
      }
      default:
        i += 1;
    }
  }
  return i;
}

function consumeShellParenConstruct(
  bytes: Uint8Array,
  iStart: number,
  len: number,
): number {
  let i = iStart;
  let depth = 1;
  while (i < len) {
    switch (bytes[i]) {
      case C.LPAREN:
        depth += 1;
        i += 1;
        break;
      case C.RPAREN:
        depth = depth > 0 ? depth - 1 : 0;
        i += 1;
        if (depth === 0) return i;
        break;
      case C.BACKSLASH:
        i = Math.min(i + 2, len);
        break;
      case C.SQUOTE: {
        i += 1;
        while (i < len && bytes[i] !== C.SQUOTE) i += 1;
        if (i < len) i += 1;
        break;
      }
      case C.DQUOTE: {
        i += 1;
        while (i < len) {
          const c = bytes[i];
          if (c === C.DQUOTE) {
            i += 1;
            break;
          } else if (c === C.BACKSLASH) {
            i = Math.min(i + 2, len);
          } else if (
            c === C.DOLLAR &&
            i + 1 < len &&
            bytes[i + 1] === C.LPAREN
          ) {
            i = consumeShellParenConstruct(bytes, i + 2, len);
          } else {
            i += 1;
          }
        }
        break;
      }
      default:
        i += 1;
    }
  }
  return len;
}

// ---------------------------------------------------------------------------
// starts_with_shell_redirection — DCG src/normalize.rs
// ---------------------------------------------------------------------------

function startsWithShellRedirection(s: string): boolean {
  const bytes = toBytes(s.replace(/^[ \t\n\r\f]+/, ""));
  if (bytes.length === 0) return false;

  if (
    bytes[0] === C.GT ||
    bytes[0] === C.LT ||
    (bytes[0] === C.AMP && bytes[1] === C.GT)
  ) {
    return true;
  }

  let idx = 0;
  while (idx < bytes.length && isAsciiDigit(bytes[idx])) idx += 1;

  return (
    idx > 0 &&
    idx < bytes.length &&
    (bytes[idx] === C.GT || bytes[idx] === C.LT)
  );
}

// ---------------------------------------------------------------------------
// Wrapper stripping. DCG src/normalize.rs: strip_sudo, strip_env (+ option/
// assignment parsing), strip_command_wrapper, strip_leading_backslash, driven
// by strip_wrapper_prefixes' iterate-to-fixpoint loop.
//
// CONTRACT EXTENSION: the engine contract additionally lists nice/nohup/time/
// doas/exec as strippable wrappers. DCG only strips sudo/env/command/backslash.
// We add nice/nohup/time/doas/exec as conservative "wrapper with optional dashed
// flags (+ value flags where applicable)" strippers that follow DCG's exact
// stripping discipline. These extensions are flagged in portNotes.
// ---------------------------------------------------------------------------

interface StripStep {
  remaining: string;
  wrapperType: string;
}

const MAX_WRAPPER_ITERATIONS = 32;

export function stripWrapperPrefixes(command: string): string {
  const trimmed = command.trim();
  if (trimmed.length === 0) return command;

  let current = trimmed;
  let stripped = false;
  let iteration = 0;

  for (;;) {
    iteration += 1;
    if (iteration > MAX_WRAPPER_ITERATIONS) break;

    const before = current.length;

    const sudo = stripSudo(current);
    if (sudo) {
      current = sudo.remaining;
      stripped = true;
      continue;
    }
    const env = stripEnv(current);
    if (env) {
      current = env.remaining;
      stripped = true;
      continue;
    }
    const cmd = stripCommandWrapper(current);
    if (cmd) {
      current = cmd.remaining;
      stripped = true;
      continue;
    }
    // CONTRACT EXTENSION wrappers (not in DCG): nice/nohup/time/doas/exec.
    const ext = stripSimpleWrapper(current);
    if (ext) {
      current = ext.remaining;
      stripped = true;
      continue;
    }
    const bs = stripLeadingBackslash(current);
    if (bs) {
      current = bs.remaining;
      stripped = true;
      continue;
    }

    if (current.length === before) break;
  }

  if (!stripped) {
    // DCG returns the ORIGINAL (untrimmed) command when nothing is stripped.
    return command;
  }

  // Apply DCG's command-word dequoting on the stripped result, matching
  // DCG `normalize_command` which runs dequote_segment_command_words after
  // strip_wrapper_prefixes. (Path normalizers are intentionally NOT applied
  // here — they live in a separate concern; see portNotes.)
  return dequoteSegmentCommandWords(current);
}

// strip_sudo — DCG src/normalize.rs
const SUDO_SIMPLE_FLAGS = new Set(
  ["E", "H", "n", "k", "K", "S", "s", "b", "i", "P", "A", "B"].map((c) =>
    c.charCodeAt(0),
  ),
);
const SUDO_ARG_FLAGS = new Set(
  ["u", "g", "h", "p", "C", "r", "U", "D", "t", "a", "T"].map((c) =>
    c.charCodeAt(0),
  ),
);

function firstWordBasename(trimmedStart: string): {
  firstWord: string;
  basename: string;
  afterFirst: string;
} {
  const m = /\s/.exec(trimmedStart);
  const firstWordEnd = m ? m.index : trimmedStart.length;
  const firstWord = trimmedStart.slice(0, firstWordEnd);
  const slashIdx = firstWord.lastIndexOf("/");
  const basename = slashIdx >= 0 ? firstWord.slice(slashIdx + 1) : firstWord;
  return {
    firstWord,
    basename,
    afterFirst: trimmedStart.slice(firstWord.length),
  };
}

function stripSudo(command: string): StripStep | undefined {
  const trimmed = command.replace(/^\s+/, "");
  const { basename, afterFirst } = firstWordBasename(trimmed);
  if (basename !== "sudo") return undefined;
  if (afterFirst.length > 0 && !/^\s/.test(afterFirst)) return undefined;

  const rest = afterFirst.replace(/^\s+/, "");
  const bytes = toBytes(rest);
  // Map the rest string to its byte offsets to recover the remaining slice.
  let idx = 0;

  while (idx < bytes.length) {
    while (idx < bytes.length && isAsciiWhitespace(bytes[idx])) idx += 1;
    if (idx >= bytes.length) break;

    // "--" terminator.
    if (
      bytes[idx] === 45 /* - */ &&
      idx + 1 < bytes.length &&
      bytes[idx + 1] === 45
    ) {
      if (idx + 2 >= bytes.length || isAsciiWhitespace(bytes[idx + 2])) {
        idx += 2;
        while (idx < bytes.length && isAsciiWhitespace(bytes[idx])) idx += 1;
        break;
      }
    }

    if (bytes[idx] !== 45) break;

    const wordStart = idx;
    let wordEnd = idx + 1;
    while (wordEnd < bytes.length && !isAsciiWhitespace(bytes[wordEnd]))
      wordEnd += 1;
    if (wordEnd <= wordStart + 1) break;

    const word = fromBytes(bytes, wordStart, wordEnd);
    if (word === "--") {
      idx = wordEnd;
      while (idx < bytes.length && isAsciiWhitespace(bytes[idx])) idx += 1;
      break;
    }
    if (word.startsWith("--")) return undefined;

    let needsArg = false;
    let unknownFlag = false;
    let sawArgInline = false;
    const flagBytes = toBytes(word.slice(1));
    for (let p = 0; p < flagBytes.length; p++) {
      const flag = flagBytes[p];
      if (SUDO_SIMPLE_FLAGS.has(flag)) continue;
      if (SUDO_ARG_FLAGS.has(flag)) {
        if (p + 1 < flagBytes.length) sawArgInline = true;
        else needsArg = true;
        break;
      }
      unknownFlag = true;
      break;
    }
    if (unknownFlag) return undefined;

    idx = wordEnd;
    if (sawArgInline) continue;

    if (needsArg) {
      while (idx < bytes.length && isAsciiWhitespace(bytes[idx])) idx += 1;
      if (idx >= bytes.length) return undefined;
      idx = consumeWordToken(bytes, idx, bytes.length);
    }
  }

  while (idx < bytes.length && isAsciiWhitespace(bytes[idx])) idx += 1;

  const remaining = fromBytes(bytes, idx, bytes.length);
  if (remaining.length === 0) return undefined;

  return { remaining, wrapperType: "sudo" };
}

// strip_env (+ parse_env_options, parse_env_assignments) — DCG src/normalize.rs
type EnvParse =
  | { kind: "continue"; idx: number }
  | { kind: "abort" }
  | { kind: "split"; remaining: string };

function unquoteEnvSArg(arg: string): string {
  if (arg.length >= 2) {
    const first = arg[0];
    const last = arg[arg.length - 1];
    if ((first === '"' && last === '"') || (first === "'" && last === "'")) {
      return arg.slice(1, arg.length - 1);
    }
  }
  return arg;
}

function tokenHasInlineCode(token: Uint8Array): boolean {
  let i = 0;
  let inSingle = false;
  let inDouble = false;
  let escaped = false;
  while (i < token.length) {
    const byte = token[i];
    if (escaped) {
      escaped = false;
      i += 1;
      continue;
    }
    if (byte === C.BACKSLASH && !inSingle) {
      escaped = true;
      i = Math.min(i + 1, token.length);
      continue;
    }
    if (byte === C.SQUOTE && !inDouble) {
      inSingle = !inSingle;
    } else if (byte === C.DQUOTE && !inSingle) {
      inDouble = !inDouble;
    } else if (byte === C.BACKTICK && !inSingle) {
      return true;
    } else if (
      byte === C.DOLLAR &&
      !inSingle &&
      i + 1 < token.length &&
      token[i + 1] === C.LPAREN
    ) {
      return true;
    }
    i += 1;
  }
  return false;
}

function parseEnvOptions(bytes: Uint8Array, idxStart: number): EnvParse {
  let idx = idxStart;
  const consumeEnvArg = (from: number): number | undefined => {
    let j = from;
    while (j < bytes.length && isAsciiWhitespace(bytes[j])) j += 1;
    if (j >= bytes.length) return undefined;
    return consumeWordToken(bytes, j, bytes.length);
  };

  while (idx < bytes.length) {
    while (idx < bytes.length && isAsciiWhitespace(bytes[idx])) idx += 1;
    if (idx >= bytes.length) break;

    if (bytes[idx] !== 45 /* - */) return { kind: "continue", idx };

    const wordStart = idx;
    let wordEnd = idx + 1;
    while (wordEnd < bytes.length && !isAsciiWhitespace(bytes[wordEnd]))
      wordEnd += 1;
    if (wordEnd <= wordStart + 1) break;

    const word = fromBytes(bytes, wordStart, wordEnd);
    if (word === "-") {
      idx = wordEnd;
      continue;
    }
    if (word === "--") {
      idx = wordEnd;
      while (idx < bytes.length && isAsciiWhitespace(bytes[idx])) idx += 1;
      return { kind: "continue", idx };
    }

    if (word.startsWith("--")) {
      const eqPos = word.indexOf("=");
      const name = eqPos >= 0 ? word.slice(0, eqPos) : word;
      const valueOpt = eqPos >= 0 ? word.slice(eqPos + 1) : undefined;

      switch (name) {
        case "--ignore-environment":
        case "--null":
        case "--debug": {
          if (valueOpt !== undefined) return { kind: "abort" };
          idx = wordEnd;
          continue;
        }
        case "--unset":
        case "--chdir":
        case "--file":
        case "--argv0":
        case "--ignore-signal": {
          if (valueOpt !== undefined) {
            idx = wordEnd;
            continue;
          }
          const next = consumeEnvArg(wordEnd);
          if (next === undefined) return { kind: "abort" };
          idx = next;
          continue;
        }
        case "--split-string": {
          let rawArg: string;
          if (valueOpt !== undefined) {
            if (valueOpt.length === 0) return { kind: "abort" };
            rawArg = valueOpt;
          } else {
            const next = consumeEnvArg(wordEnd);
            if (next === undefined) return { kind: "abort" };
            rawArg = fromBytes(bytes, wordEnd, next).replace(/^\s+/, "");
          }
          const unquoted = unquoteEnvSArg(rawArg);
          idx = wordEnd;
          if (valueOpt === undefined) {
            idx = wordEnd;
            while (idx < bytes.length && isAsciiWhitespace(bytes[idx]))
              idx += 1;
            idx = consumeWordToken(bytes, idx, bytes.length);
          }
          while (idx < bytes.length && isAsciiWhitespace(bytes[idx])) idx += 1;
          const restOfLine = fromBytes(bytes, idx, bytes.length);
          const remaining =
            restOfLine.length === 0 ? unquoted : `${unquoted} ${restOfLine}`;
          return { kind: "split", remaining };
        }
        default:
          return { kind: "abort" };
      }
    }

    const wordBytes = toBytes(word);
    let pos = 1;
    while (pos < wordBytes.length) {
      const flag = String.fromCharCode(wordBytes[pos]);
      if (flag === "i" || flag === "0" || flag === "v") {
        pos += 1;
      } else if (flag === "S") {
        let rawArg: string;
        if (pos + 1 < wordBytes.length) {
          rawArg = word.slice(pos + 1);
        } else {
          const next = consumeEnvArg(wordEnd);
          if (next === undefined) return { kind: "abort" };
          rawArg = fromBytes(bytes, wordEnd, next).replace(/^\s+/, "");
        }
        const unquoted = unquoteEnvSArg(rawArg);
        idx = wordEnd;
        if (pos + 1 >= wordBytes.length) {
          while (idx < bytes.length && isAsciiWhitespace(bytes[idx])) idx += 1;
          idx = consumeWordToken(bytes, idx, bytes.length);
        }
        while (idx < bytes.length && isAsciiWhitespace(bytes[idx])) idx += 1;
        const restOfLine = fromBytes(bytes, idx, bytes.length);
        const remaining =
          restOfLine.length === 0 ? unquoted : `${unquoted} ${restOfLine}`;
        return { kind: "split", remaining };
      } else if (
        flag === "u" ||
        flag === "P" ||
        flag === "C" ||
        flag === "f" ||
        flag === "a"
      ) {
        if (pos + 1 < wordBytes.length) {
          idx = wordEnd;
        } else {
          const next = consumeEnvArg(wordEnd);
          if (next === undefined) return { kind: "abort" };
          idx = next;
        }
        pos = wordBytes.length;
      } else {
        return { kind: "abort" };
      }
    }

    if (idx < wordEnd) idx = wordEnd;
  }
  return { kind: "continue", idx };
}

function parseEnvAssignments(bytes: Uint8Array, idxStart: number): number {
  let idx = idxStart;
  while (idx < bytes.length) {
    while (idx < bytes.length && isAsciiWhitespace(bytes[idx])) idx += 1;
    if (idx >= bytes.length) break;

    const start = idx;
    const end = consumeWordToken(bytes, idx, bytes.length);
    if (start >= end) return start;

    const wordBytes = bytes.subarray(start, end);
    let eqPos = -1;
    for (let k = 0; k < wordBytes.length; k++) {
      if (wordBytes[k] === 61 /* = */) {
        eqPos = k;
        break;
      }
    }

    if (eqPos > 0) {
      if (tokenHasInlineCode(wordBytes)) return start;
      idx = end;
      continue;
    }
    return start;
  }
  return idx;
}

function stripEnv(command: string): StripStep | undefined {
  const trimmed = command.replace(/^\s+/, "");
  const { basename, afterFirst } = firstWordBasename(trimmed);
  if (basename !== "env") return undefined;
  if (afterFirst.length > 0 && !/^\s/.test(afterFirst)) return undefined;

  const rest = afterFirst.replace(/^\s+/, "");
  if (rest.length === 0) return undefined;

  const bytes = toBytes(rest);
  let idx = 0;

  const opts = parseEnvOptions(bytes, idx);
  if (opts.kind === "abort") return undefined;
  if (opts.kind === "split") {
    return { remaining: opts.remaining, wrapperType: "env" };
  }
  idx = opts.idx;

  idx = parseEnvAssignments(bytes, idx);

  while (idx < bytes.length && isAsciiWhitespace(bytes[idx])) idx += 1;

  const remaining = fromBytes(bytes, idx, bytes.length);
  if (remaining.length === 0) return undefined;

  return { remaining, wrapperType: "env" };
}

// strip_command_wrapper — DCG src/normalize.rs (NOT for `command -v/-V`).
function stripCommandWrapper(command: string): StripStep | undefined {
  const trimmed = command.replace(/^\s+/, "");
  const { basename, afterFirst } = firstWordBasename(trimmed);
  if (basename !== "command") return undefined;
  if (afterFirst.length > 0 && !/^\s/.test(afterFirst)) return undefined;

  const rest = afterFirst.replace(/^\s+/, "");
  if (rest.length === 0) return undefined;

  const bytes = toBytes(rest);
  let idx = 0;

  while (idx < bytes.length) {
    while (idx < bytes.length && isAsciiWhitespace(bytes[idx])) idx += 1;
    if (idx >= bytes.length) break;
    if (bytes[idx] !== 45 /* - */) break;

    const wordStart = idx;
    let wordEnd = idx + 1;
    while (wordEnd < bytes.length && !isAsciiWhitespace(bytes[wordEnd]))
      wordEnd += 1;
    if (wordEnd <= wordStart + 1) break;

    const word = fromBytes(bytes, wordStart, wordEnd);
    if (word === "--") {
      idx = wordEnd;
      while (idx < bytes.length && isAsciiWhitespace(bytes[idx])) idx += 1;
      break;
    }
    if (word.startsWith("--")) return undefined;

    let unknown = false;
    for (const ch of word.slice(1)) {
      if (ch === "v" || ch === "V") return undefined; // query mode
      if (ch === "p") continue;
      unknown = true;
      break;
    }
    if (unknown) return undefined;

    idx = wordEnd;
  }

  while (idx < bytes.length && isAsciiWhitespace(bytes[idx])) idx += 1;

  const remaining = fromBytes(bytes, idx, bytes.length);
  if (remaining.length === 0) return undefined;
  if (startsWithShellRedirection(remaining)) return undefined;

  return { remaining, wrapperType: "command" };
}

// CONTRACT EXTENSION (not in DCG): nice/nohup/time/doas/exec wrappers.
// Conservative strip following DCG's discipline: strip the wrapper word, then
// consume leading dashed flags; `nice`/`doas`/`time` value-taking flags are
// handled (-n N, -u user, etc). Aborts (returns undefined) on unknown long
// options or when no command follows, mirroring DCG's "only strip when
// unambiguous" stance.
interface SimpleWrapperSpec {
  name: string;
  // short flags that consume a following value token
  argFlags: Set<number>;
}
const SIMPLE_WRAPPERS: Record<string, SimpleWrapperSpec> = {
  nice: { name: "nice", argFlags: new Set(["n"].map((c) => c.charCodeAt(0))) },
  nohup: { name: "nohup", argFlags: new Set() },
  time: {
    name: "time",
    argFlags: new Set(["o", "f"].map((c) => c.charCodeAt(0))),
  },
  doas: {
    name: "doas",
    argFlags: new Set(["u", "C", "a"].map((c) => c.charCodeAt(0))),
  },
  exec: { name: "exec", argFlags: new Set(["a"].map((c) => c.charCodeAt(0))) },
};

function stripSimpleWrapper(command: string): StripStep | undefined {
  const trimmed = command.replace(/^\s+/, "");
  const { basename, afterFirst } = firstWordBasename(trimmed);
  const spec = SIMPLE_WRAPPERS[basename];
  if (!spec) return undefined;
  if (afterFirst.length > 0 && !/^\s/.test(afterFirst)) return undefined;

  const rest = afterFirst.replace(/^\s+/, "");
  if (rest.length === 0) return undefined;

  const bytes = toBytes(rest);
  let idx = 0;

  while (idx < bytes.length) {
    while (idx < bytes.length && isAsciiWhitespace(bytes[idx])) idx += 1;
    if (idx >= bytes.length) break;
    if (bytes[idx] !== 45 /* - */) break;

    const wordStart = idx;
    let wordEnd = idx + 1;
    while (wordEnd < bytes.length && !isAsciiWhitespace(bytes[wordEnd]))
      wordEnd += 1;
    if (wordEnd <= wordStart + 1) break;

    const word = fromBytes(bytes, wordStart, wordEnd);
    if (word === "--") {
      idx = wordEnd;
      while (idx < bytes.length && isAsciiWhitespace(bytes[idx])) idx += 1;
      break;
    }
    if (word.startsWith("--")) return undefined; // unknown long option

    let needsArg = false;
    let sawArgInline = false;
    const flagBytes = toBytes(word.slice(1));
    for (let p = 0; p < flagBytes.length; p++) {
      const flag = flagBytes[p];
      if (spec.argFlags.has(flag)) {
        if (p + 1 < flagBytes.length) sawArgInline = true;
        else needsArg = true;
        break;
      }
      // unknown short flag: bail (conservative)
      if (!isAsciiAlphanumeric(flag)) return undefined;
    }

    idx = wordEnd;
    if (sawArgInline) continue;
    if (needsArg) {
      while (idx < bytes.length && isAsciiWhitespace(bytes[idx])) idx += 1;
      if (idx >= bytes.length) return undefined;
      idx = consumeWordToken(bytes, idx, bytes.length);
    }
  }

  while (idx < bytes.length && isAsciiWhitespace(bytes[idx])) idx += 1;

  const remaining = fromBytes(bytes, idx, bytes.length);
  if (remaining.length === 0) return undefined;

  return { remaining, wrapperType: spec.name };
}

// strip_leading_backslash — DCG src/normalize.rs
function stripLeadingBackslash(command: string): StripStep | undefined {
  const trimmed = command.replace(/^\s+/, "");
  if (!trimmed.startsWith("\\")) return undefined;

  const rest = trimmed.slice(1);
  if (rest.length === 0) return undefined;

  const m = /\s/.exec(rest);
  const firstWordEnd = m ? m.index : rest.length;
  const firstWord = rest.slice(0, firstWordEnd);

  // Allow alphanumeric (unicode), underscore, dash, and dot.
  if (
    firstWord.length === 0 ||
    ![...firstWord].every(
      (c) =>
        /[a-zA-Z0-9]/.test(c) ||
        c === "_" ||
        c === "-" ||
        c === "." ||
        // Rust char::is_alphanumeric is unicode-aware
        /\p{L}|\p{N}/u.test(c),
    )
  ) {
    return undefined;
  }

  return { remaining: rest, wrapperType: "backslash" };
}

// ---------------------------------------------------------------------------
// Normalization tokenizer + command-word dequoting.
// Ported from DCG src/normalize.rs (tokenize_for_normalization,
// normalize_command_word_token, normalize_subcommand_token,
// dequote_segment_command_words, NormalizeWrapper).
// ---------------------------------------------------------------------------

const TokenKind = {
  Word: 0,
  Separator: 1,
} as const;
type TokenKind = (typeof TokenKind)[keyof typeof TokenKind];

interface NormToken {
  kind: TokenKind;
  start: number;
  end: number;
}

function skipAsciiWhitespaceNoNewline(
  bytes: Uint8Array,
  iStart: number,
  len: number,
): number {
  let i = iStart;
  while (i < len && isAsciiWhitespace(bytes[i]) && bytes[i] !== C.LF) i += 1;
  return i;
}

function consumeSeparatorToken(
  bytes: Uint8Array,
  i: number,
  len: number,
  tokens: NormToken[],
): number | undefined {
  switch (bytes[i]) {
    case C.PIPE: {
      const end = i + 1 < len && bytes[i + 1] === C.PIPE ? i + 2 : i + 1;
      tokens.push({ kind: TokenKind.Separator, start: i, end });
      return end;
    }
    case C.SEMI:
    case C.LPAREN:
    case C.RPAREN:
      tokens.push({ kind: TokenKind.Separator, start: i, end: i + 1 });
      return i + 1;
    case C.AMP: {
      if (i + 1 < len && bytes[i + 1] === C.GT) return undefined;
      const end = i + 1 < len && bytes[i + 1] === C.AMP ? i + 2 : i + 1;
      tokens.push({ kind: TokenKind.Separator, start: i, end });
      return end;
    }
    default:
      return undefined;
  }
}

function tokenizeForNormalization(bytes: Uint8Array): NormToken[] {
  const len = bytes.length;
  const tokens: NormToken[] = [];
  let i = 0;
  while (i < len) {
    i = skipAsciiWhitespaceNoNewline(bytes, i, len);
    if (i >= len) break;

    if (bytes[i] === C.LF) {
      tokens.push({ kind: TokenKind.Separator, start: i, end: i + 1 });
      i += 1;
      continue;
    }

    const sep = consumeSeparatorToken(bytes, i, len, tokens);
    if (sep !== undefined) {
      i = sep;
      continue;
    }

    const start = i;
    const end = consumeWordToken(bytes, i, len);
    i = end;
    if (start < i) tokens.push({ kind: TokenKind.Word, start, end: i });
  }
  return tokens;
}

function isEnvAssignment(word: string): boolean {
  const eq = word.indexOf("=");
  if (eq < 0) return false;
  const key = word.slice(0, eq);
  if (key.length === 0) return false;
  for (const ch of key) {
    if (!/[A-Za-z0-9_]/.test(ch)) return false;
  }
  return !word.startsWith("-");
}

// Commands whose every argument is treated as inert data (DCG
// SAFE_STRING_REGISTRY.all_args_data). Used to SKIP arg-dequoting.
const ALL_ARGS_DATA = new Set(["echo", "printf"]);
function isAllArgsData(cmd: string): boolean {
  const slashIdx = cmd.lastIndexOf("/");
  const base = slashIdx >= 0 ? cmd.slice(slashIdx + 1) : cmd;
  return ALL_ARGS_DATA.has(base);
}

// NormalizeWrapper state machine — DCG src/normalize.rs
type WrapperState =
  | { tag: "none" }
  | { tag: "commandQuery" }
  | { tag: "sudo"; optionsEnded: boolean; skipNext: number }
  | { tag: "env"; optionsEnded: boolean; skipNext: number }
  | { tag: "command"; optionsEnded: boolean; skipNext: number };

function wrapperFromCommandWord(word: string): WrapperState | undefined {
  const slashIdx = word.lastIndexOf("/");
  const base = slashIdx >= 0 ? word.slice(slashIdx + 1) : word;
  switch (base) {
    case "sudo":
      return { tag: "sudo", optionsEnded: false, skipNext: 0 };
    case "env":
      return { tag: "env", optionsEnded: false, skipNext: 0 };
    case "command":
      return { tag: "command", optionsEnded: false, skipNext: 0 };
    default:
      return undefined;
  }
}

function wrapperShouldSkipToken(w: WrapperState, word: string): boolean {
  if (w.tag === "none" || w.tag === "commandQuery") return false;
  const { optionsEnded, skipNext } = w;
  if (skipNext > 0) return true;
  if (!optionsEnded && word === "--") return true;
  return !optionsEnded && word.startsWith("-");
}

function wrapperAdvance(w: WrapperState, word: string): WrapperState {
  switch (w.tag) {
    case "sudo": {
      let { optionsEnded, skipNext } = w;
      if (skipNext > 0)
        return { tag: "sudo", optionsEnded, skipNext: skipNext - 1 };
      if (!optionsEnded && word === "--")
        return { tag: "sudo", optionsEnded: true, skipNext };
      if (!optionsEnded && word.startsWith("-")) {
        const takesValue =
          word === "-u" ||
          word === "-g" ||
          word === "-h" ||
          word === "-p" ||
          word.startsWith("-u") ||
          word.startsWith("-g") ||
          word.startsWith("-h") ||
          word.startsWith("-p");
        if (takesValue && word.length === 2) skipNext = 1;
        return { tag: "sudo", optionsEnded, skipNext };
      }
      return { tag: "sudo", optionsEnded, skipNext };
    }
    case "env": {
      let { optionsEnded, skipNext } = w;
      if (skipNext > 0)
        return { tag: "env", optionsEnded, skipNext: skipNext - 1 };
      if (!optionsEnded && word === "--")
        return { tag: "env", optionsEnded: true, skipNext };
      if (!optionsEnded && word.startsWith("-")) {
        const takesValue =
          word === "-u" || word === "--unset" || word.startsWith("-u");
        if (takesValue && (word === "-u" || word === "--unset")) skipNext = 1;
        return { tag: "env", optionsEnded, skipNext };
      }
      return { tag: "env", optionsEnded, skipNext };
    }
    case "command": {
      const { optionsEnded, skipNext } = w;
      if (skipNext > 0)
        return { tag: "command", optionsEnded, skipNext: skipNext - 1 };
      if (!optionsEnded && word === "--")
        return { tag: "command", optionsEnded: true, skipNext };
      if (!optionsEnded && word.startsWith("-")) {
        if (word === "-v" || word === "-V") return { tag: "commandQuery" };
        return { tag: "command", optionsEnded, skipNext };
      }
      return { tag: "command", optionsEnded, skipNext };
    }
    default:
      return w;
  }
}

function redirectionPrefixLooksLikeCommand(prefix: string): boolean {
  for (const ch of prefix) {
    const c = ch.charCodeAt(0);
    if (
      !(c === C.AMP || c === C.LT || c === C.GT || (c >= C.ZERO && c <= C.NINE))
    ) {
      return true;
    }
  }
  return false;
}

function attachedRedirectionIndex(token: string): number | undefined {
  const bytes = toBytes(token);
  let inSingle = false;
  let inDouble = false;
  let escaped = false;
  for (let idx = 0; idx < bytes.length; idx++) {
    const byte = bytes[idx];
    if (escaped) {
      escaped = false;
      continue;
    }
    if (byte === C.BACKSLASH && !inSingle) {
      escaped = true;
      continue;
    }
    if (byte === C.SQUOTE && !inDouble) {
      inSingle = !inSingle;
    } else if (byte === C.DQUOTE && !inSingle) {
      inDouble = !inDouble;
    } else if (
      byte === C.AMP &&
      !inSingle &&
      !inDouble &&
      idx + 1 < bytes.length &&
      bytes[idx + 1] === C.GT &&
      idx > 0 &&
      redirectionPrefixLooksLikeCommand(fromBytes(bytes, 0, idx)) &&
      !isAsciiWhitespace(bytes[idx - 1])
    ) {
      return idx;
    } else if (
      (byte === C.GT || byte === C.LT) &&
      !inSingle &&
      !inDouble &&
      idx > 0 &&
      redirectionPrefixLooksLikeCommand(fromBytes(bytes, 0, idx)) &&
      !isAsciiWhitespace(bytes[idx - 1])
    ) {
      return idx;
    }
  }
  return undefined;
}

// normalize_command_word_token — DCG src/normalize.rs. Returns the normalized
// token, or undefined when nothing changed.
export function normalizeCommandWordToken(token: string): string | undefined {
  let out = token;
  let changed = false;

  // Strip line continuations (backslash + newline).
  if (out.includes("\\\n") || out.includes("\\\r\n")) {
    out = out.split("\\\r\n").join("").split("\\\n").join("");
    changed = true;
  }

  // Leading backslashes when it looks like an escaped command word.
  const strippedLead = out.replace(/^\\+/, "");
  if (strippedLead.length !== 0 && strippedLead.length !== out.length) {
    const first = strippedLead.charCodeAt(0);
    const looksLikeCommand =
      isAsciiAlphanumeric(first) ||
      first === 47 /* / */ ||
      first === 46 /* . */ ||
      first === 95 /* _ */ ||
      first === 126 /* ~ */;
    if (looksLikeCommand) {
      out = strippedLead;
      changed = true;
    }
  }

  // Internal backslash escapes before alphanumeric chars: g\it -> git.
  if (out.includes("\\")) {
    let result = "";
    let localChanged = false;
    const chars = [...out];
    for (let i = 0; i < chars.length; i++) {
      const c = chars[i];
      if (c === "\\") {
        const next = chars[i + 1];
        if (next !== undefined && /[a-zA-Z0-9]/.test(next)) {
          localChanged = true;
          continue;
        }
      }
      result += c;
    }
    if (localChanged) {
      out = result;
      changed = true;
    }
  }

  // Mixed quoting concatenation: g'i't -> git, "g"it -> git.
  if ((out.includes("'") || out.includes('"')) && out.length > 2) {
    let result = "";
    let localChanged = false;
    const chars = [...out];
    let i = 0;
    while (i < chars.length) {
      const c = chars[i];
      i += 1;
      if (c === "'" || c === '"') {
        const quote = c;
        let foundClose = false;
        let inner = "";
        while (i < chars.length) {
          const ic = chars[i];
          i += 1;
          if (ic === quote) {
            foundClose = true;
            localChanged = true;
            break;
          }
          inner += ic;
        }
        if (!foundClose) result += quote;
        result += inner;
      } else {
        result += c;
      }
    }
    if (localChanged) {
      out = result;
      changed = true;
    }
  }

  // Insert a space before an attached redirection operator (unless FD redirect).
  const redirIdx = attachedRedirectionIndex(out);
  if (redirIdx !== undefined) {
    const outBytes = toBytes(out);
    const head = fromBytes(outBytes, 0, redirIdx);
    const tail = fromBytes(outBytes, redirIdx, outBytes.length);
    const isFdRedirect = [...head].every((c) => /[0-9]/.test(c));
    if (!isFdRedirect) {
      let normalizedHead = head;
      if (
        normalizedHead.toLowerCase().endsWith(".exe") &&
        normalizedHead.length > 4
      ) {
        normalizedHead = normalizedHead.slice(0, normalizedHead.length - 4);
      }
      const candidate = `${normalizedHead} ${tail}`;
      if (candidate !== out) {
        out = candidate;
        changed = true;
      }
    }
  }

  // Strip Windows .exe extension.
  if (out.toLowerCase().endsWith(".exe") && out.length > 4) {
    out = out.slice(0, out.length - 4);
    changed = true;
  }

  // Strip .exe inside surrounding quotes (Windows paths with spaces).
  {
    const fb = out.charCodeAt(0);
    const lb = out.charCodeAt(out.length - 1);
    let q: string | undefined;
    if (fb === C.DQUOTE && lb === C.DQUOTE && out.length > 6) q = '"';
    else if (fb === C.SQUOTE && lb === C.SQUOTE && out.length > 6) q = "'";
    if (q !== undefined) {
      const inner = out.slice(1, out.length - 1);
      if (inner.toLowerCase().endsWith(".exe")) {
        const innerStripped = inner.slice(0, inner.length - 4);
        out = `${q}${innerStripped}${q}`;
        changed = true;
      }
    }
  }

  // Unquote a single-token command word.
  {
    const fb = out.charCodeAt(0);
    const lb = out.charCodeAt(out.length - 1);
    let q: number | undefined;
    if (fb === C.SQUOTE && lb === C.SQUOTE) q = C.SQUOTE;
    else if (fb === C.DQUOTE && lb === C.DQUOTE) q = C.DQUOTE;
    if (q !== undefined && out.length >= 2) {
      const innerBytes = toBytes(out).subarray(1, toBytes(out).length - 1);
      const isSafe =
        innerBytes.length > 0 &&
        !Array.from(innerBytes).some((b) => isAsciiWhitespace(b)) &&
        !Array.from(innerBytes).some(
          (b) =>
            b === C.PIPE ||
            b === C.SEMI ||
            b === C.AMP ||
            b === C.LPAREN ||
            b === C.RPAREN,
        ) &&
        innerBytes[0] !== q;
      if (isSafe) {
        out = fromBytes(innerBytes, 0, innerBytes.length);
        changed = true;
      }
    }
  }

  return changed ? out : undefined;
}

function looksLikeSubcommandWord(token: string): boolean {
  if (token.length === 0) return false;
  const first = token.charCodeAt(0);
  if (
    first === 47 /* / */ ||
    first === 46 /* . */ ||
    first === 126 /* ~ */ ||
    first === C.DOLLAR
  ) {
    return false;
  }
  for (const ch of token) {
    const c = ch.charCodeAt(0);
    if (!((isAsciiAlphanumeric(c) || c === 95 /* _ */ || c === 45) /* - */))
      return false;
  }
  return true;
}

function normalizeSubcommandToken(token: string): string | undefined {
  let out = token;
  let changed = false;
  if (out.includes("\\\n") || out.includes("\\\r\n")) {
    out = out.split("\\\r\n").join("").split("\\\n").join("");
    changed = true;
  }

  const fb = out.charCodeAt(0);
  const lb = out.charCodeAt(out.length - 1);
  let q: number | undefined;
  if (fb === C.SQUOTE && lb === C.SQUOTE) q = C.SQUOTE;
  else if (fb === C.DQUOTE && lb === C.DQUOTE) q = C.DQUOTE;

  if (q !== undefined && out.length >= 2) {
    const allBytes = toBytes(out);
    const innerBytes = allBytes.subarray(1, allBytes.length - 1);
    const inner = fromBytes(innerBytes, 0, innerBytes.length);
    const isSafe =
      innerBytes.length > 0 &&
      !Array.from(innerBytes).some((b) => isAsciiWhitespace(b)) &&
      !Array.from(innerBytes).some(
        (b) =>
          b === C.PIPE ||
          b === C.SEMI ||
          b === C.AMP ||
          b === C.LPAREN ||
          b === C.RPAREN,
      ) &&
      innerBytes[0] !== q &&
      looksLikeSubcommandWord(inner);
    if (isSafe) {
      out = inner;
      changed = true;
    }
  }

  return changed ? out : undefined;
}

// dequote_segment_command_words — DCG src/normalize.rs
export function dequoteSegmentCommandWords(command: string): string {
  const lower = command.toLowerCase();
  const needsNormalization = /['"\\<>]/.test(command) || lower.includes(".exe");
  if (!needsNormalization) return command;

  const bytes = toBytes(command);
  const tokens = tokenizeForNormalization(bytes);
  if (tokens.length === 0) return command;

  const replacements: Array<{ start: number; end: number; text: string }> = [];
  let segmentHasCmd = false;
  let currentCmdWord: string | undefined;
  let wrapper: WrapperState = { tag: "none" };

  for (const tok of tokens) {
    if (tok.kind === TokenKind.Separator) {
      segmentHasCmd = false;
      currentCmdWord = undefined;
      wrapper = { tag: "none" };
      continue;
    }

    const tokenText = fromBytes(bytes, tok.start, tok.end);

    if (segmentHasCmd) {
      if (currentCmdWord !== undefined && isAllArgsData(currentCmdWord))
        continue;
      const replacement = normalizeSubcommandToken(tokenText);
      if (replacement !== undefined) {
        replacements.push({
          start: tok.start,
          end: tok.end,
          text: replacement,
        });
      }
      continue;
    }

    const current = tokenText;

    if (wrapper.tag === "commandQuery") {
      segmentHasCmd = true;
      wrapper = { tag: "none" };
      continue;
    }

    if (wrapperShouldSkipToken(wrapper, current)) {
      wrapper = wrapperAdvance(wrapper, current);
      continue;
    }

    if (wrapper.tag !== "none") wrapper = { tag: "none" };

    const nextWrapper = wrapperFromCommandWord(current);
    if (nextWrapper !== undefined) {
      wrapper = nextWrapper;
      continue;
    }

    if (isEnvAssignment(current)) continue;

    segmentHasCmd = true;
    const replacement = normalizeCommandWordToken(current);
    currentCmdWord = replacement ?? current;
    if (replacement !== undefined) {
      replacements.push({ start: tok.start, end: tok.end, text: replacement });
    }
  }

  if (replacements.length === 0) return command;

  replacements.sort((a, b) => a.start - b.start);
  const outBytes: number[] = [];
  let last = 0;
  for (const { start, end, text } of replacements) {
    if (start > last) {
      for (let k = last; k < start; k++) outBytes.push(bytes[k]);
    }
    const tb = toBytes(text);
    for (let k = 0; k < tb.length; k++) outBytes.push(tb[k]);
    last = end;
  }
  for (let k = last; k < bytes.length; k++) outBytes.push(bytes[k]);

  return fromBytes(Uint8Array.from(outBytes), 0, outBytes.length);
}

// ---------------------------------------------------------------------------
// split_command_segments — DCG src/packs/mod.rs (collect_command_segments,
// find_matching_command_substitution, find_matching_arithmetic_expansion,
// find_matching_backtick, is_redirection_ampersand, push_trimmed_segment).
//
// Subshells/substitutions are emitted BEFORE their enclosing segment so a safe
// outer command cannot hide a destructive inner one. Redirection &, > and >>
// are NOT split points.
// ---------------------------------------------------------------------------

const MAX_SEGMENT_RECURSION = 64;

export function splitCommandSegments(command: string): string[] {
  const bytes = toBytes(command);
  const segments: string[] = [];
  collectCommandSegments(bytes, 0, bytes.length, 0, true, segments);

  if (segments.length === 0) {
    const trimmed = command.trim();
    if (trimmed.length !== 0) segments.push(trimmed);
  }
  return segments;
}

function pushTrimmedSegment(
  bytes: Uint8Array,
  start: number,
  end: number,
  segments: string[],
): void {
  const raw = fromBytes(bytes, start, end);
  const segment = raw.trim();
  if (segment.length !== 0) segments.push(segment);
}

function isRedirectionAmpersand(bytes: Uint8Array, index: number): boolean {
  if (bytes[index + 1] === C.GT) return true;
  if (index >= 1) {
    const prev = bytes[index - 1];
    if (prev === C.LT || prev === C.GT) return true;
  }
  return false;
}

function collectCommandSegments(
  bytes: Uint8Array,
  start: number,
  end: number,
  recursionDepth: number,
  emitPlainSegments: boolean,
  segments: string[],
): void {
  if (recursionDepth > MAX_SEGMENT_RECURSION) {
    if (emitPlainSegments) pushTrimmedSegment(bytes, start, end, segments);
    return;
  }

  let segmentStart = start;
  let i = start;
  let inSingle = false;
  let inDouble = false;

  while (i < end) {
    const b = bytes[i];

    if (b === C.BACKSLASH && !inSingle && i + 1 < end) {
      i += 2;
      continue;
    }
    if (b === C.SQUOTE && !inDouble) {
      inSingle = !inSingle;
      i += 1;
      continue;
    }
    if (b === C.DQUOTE && !inSingle) {
      inDouble = !inDouble;
      i += 1;
      continue;
    }

    // $(( ... )) arithmetic expansion — recursed but NOT emitted as plain.
    if (
      !inSingle &&
      b === C.DOLLAR &&
      i + 2 < end &&
      bytes[i + 1] === C.LPAREN &&
      bytes[i + 2] === C.LPAREN
    ) {
      const close = findMatchingArithmeticExpansion(bytes, i + 3, end);
      if (close !== undefined) {
        collectCommandSegments(
          bytes,
          i + 3,
          close,
          recursionDepth + 1,
          false,
          segments,
        );
        i = close + 2;
        continue;
      }
    }

    // $( ... ) command substitution.
    if (
      !inSingle &&
      b === C.DOLLAR &&
      i + 1 < end &&
      bytes[i + 1] === C.LPAREN
    ) {
      const close = findMatchingCommandSubstitution(bytes, i + 2, end);
      if (close !== undefined) {
        collectCommandSegments(
          bytes,
          i + 2,
          close,
          recursionDepth + 1,
          true,
          segments,
        );
        i = close + 1;
        continue;
      }
    }

    // <( ... ) / >( ... ) process substitution.
    if (
      !inSingle &&
      !inDouble &&
      (b === C.LT || b === C.GT) &&
      i + 1 < end &&
      bytes[i + 1] === C.LPAREN
    ) {
      const close = findMatchingCommandSubstitution(bytes, i + 2, end);
      if (close !== undefined) {
        collectCommandSegments(
          bytes,
          i + 2,
          close,
          recursionDepth + 1,
          true,
          segments,
        );
        i = close + 1;
        continue;
      }
    }

    // backtick substitution.
    if (!inSingle && b === C.BACKTICK) {
      const close = findMatchingBacktick(bytes, i + 1, end);
      if (close !== undefined) {
        collectCommandSegments(
          bytes,
          i + 1,
          close,
          recursionDepth + 1,
          true,
          segments,
        );
        i = close + 1;
        continue;
      }
    }

    if (inSingle || inDouble) {
      i += 1;
      continue;
    }

    let splitWidth: number | undefined;
    if (b === C.SEMI || b === C.LF) {
      splitWidth = 1;
    } else if (b === C.AMP) {
      if (isRedirectionAmpersand(bytes, i)) {
        splitWidth = undefined;
      } else {
        splitWidth = (bytes[i + 1] === C.AMP ? 1 : 0) + 1;
      }
    } else if (b === C.PIPE) {
      const next = bytes[i + 1];
      splitWidth = (next === C.PIPE || next === C.AMP ? 1 : 0) + 1;
    } else {
      splitWidth = undefined;
    }

    if (splitWidth !== undefined) {
      if (emitPlainSegments)
        pushTrimmedSegment(bytes, segmentStart, i, segments);
      i += splitWidth;
      segmentStart = i;
      continue;
    }

    i += 1;
  }

  if (emitPlainSegments) pushTrimmedSegment(bytes, segmentStart, end, segments);
}

function findMatchingCommandSubstitution(
  bytes: Uint8Array,
  start: number,
  end: number,
): number | undefined {
  let i = start;
  let inSingle = false;
  let inDouble = false;

  while (i < end) {
    const b = bytes[i];

    if (b === C.BACKSLASH && !inSingle && i + 1 < end) {
      i += 2;
      continue;
    }
    if (b === C.SQUOTE && !inDouble) {
      inSingle = !inSingle;
      i += 1;
      continue;
    }
    if (b === C.DQUOTE && !inSingle) {
      inDouble = !inDouble;
      i += 1;
      continue;
    }
    if (inSingle) {
      i += 1;
      continue;
    }

    if (b === C.BACKTICK) {
      const close = findMatchingBacktick(bytes, i + 1, end);
      if (close !== undefined) {
        i = close + 1;
        continue;
      }
    }

    if (
      b === C.DOLLAR &&
      i + 2 < end &&
      bytes[i + 1] === C.LPAREN &&
      bytes[i + 2] === C.LPAREN
    ) {
      const close = findMatchingArithmeticExpansion(bytes, i + 3, end);
      if (close !== undefined) {
        i = close + 2;
        continue;
      }
    }

    if (b === C.DOLLAR && i + 1 < end && bytes[i + 1] === C.LPAREN) {
      const close = findMatchingCommandSubstitution(bytes, i + 2, end);
      if (close !== undefined) {
        i = close + 1;
        continue;
      }
    }

    if (
      !inDouble &&
      (b === C.LT || b === C.GT) &&
      i + 1 < end &&
      bytes[i + 1] === C.LPAREN
    ) {
      const close = findMatchingCommandSubstitution(bytes, i + 2, end);
      if (close !== undefined) {
        i = close + 1;
        continue;
      }
    }

    if (b === C.RPAREN && !inDouble) return i;

    i += 1;
  }
  return undefined;
}

function findMatchingArithmeticExpansion(
  bytes: Uint8Array,
  start: number,
  end: number,
): number | undefined {
  let i = start;
  let parenDepth = 0;
  let inSingle = false;
  let inDouble = false;

  while (i < end) {
    const b = bytes[i];

    if (b === C.BACKSLASH && !inSingle && i + 1 < end) {
      i += 2;
      continue;
    }
    if (b === C.SQUOTE && !inDouble) {
      inSingle = !inSingle;
      i += 1;
      continue;
    }
    if (b === C.DQUOTE && !inSingle) {
      inDouble = !inDouble;
      i += 1;
      continue;
    }
    if (inSingle || inDouble) {
      i += 1;
      continue;
    }

    if (b === C.BACKTICK) {
      const close = findMatchingBacktick(bytes, i + 1, end);
      if (close !== undefined) {
        i = close + 1;
        continue;
      }
    }

    if (b === C.DOLLAR && i + 1 < end && bytes[i + 1] === C.LPAREN) {
      const close = findMatchingCommandSubstitution(bytes, i + 2, end);
      if (close !== undefined) {
        i = close + 1;
        continue;
      }
    }

    if (b === C.LPAREN) {
      parenDepth += 1;
    } else if (b === C.RPAREN && parenDepth > 0) {
      parenDepth -= 1;
    } else if (b === C.RPAREN && i + 1 < end && bytes[i + 1] === C.RPAREN) {
      return i;
    }

    i += 1;
  }
  return undefined;
}

function findMatchingBacktick(
  bytes: Uint8Array,
  start: number,
  end: number,
): number | undefined {
  let i = start;
  while (i < end) {
    const b = bytes[i];
    if (b === C.BACKSLASH && i + 1 < end) {
      i += 2;
    } else if (b === C.BACKTICK) {
      return i;
    } else {
      i += 1;
    }
  }
  return undefined;
}

// ---------------------------------------------------------------------------
// classifySegment / normalizeCommand
//
// NOTE: DCG's `classify_command` (src/context.rs) produces an Executed / Data /
// InlineCode / Argument masking model — a DIFFERENT taxonomy from the engine
// contract's Span/SpanKind (executable|subcommand|flag|argument|path|string|
// subshell|operator|redirect). The contract span model is this project's own
// simplified surface, used for tracing/inspection; the matcher operates on
// `raw`/`normalized`. We therefore build a lightweight contract-shaped span
// tokenizer anchored to DCG's quote/escape-aware word boundaries. The
// load-bearing fields — `normalized` (DCG strip+dequote) and `executable`
// (DCG basename rule) — are faithful ports.
// ---------------------------------------------------------------------------

function basenameOf(word: string): string {
  // Mirror DCG basename extraction (rsplit on '/' and '\\'), trim quotes,
  // strip a trailing .exe (case-insensitive).
  let w = word.replace(/^["']+|["']+$/g, "");
  const idx = Math.max(w.lastIndexOf("/"), w.lastIndexOf("\\"));
  if (idx >= 0) w = w.slice(idx + 1);
  if (w.length >= 4 && w.slice(w.length - 4).toLowerCase() === ".exe") {
    w = w.slice(0, w.length - 4);
  }
  return w;
}

function classifySpans(normalized: string): Span[] {
  const bytes = toBytes(normalized);
  const spans: Span[] = [];
  let commandSeen = false; // first non-wrapper word => executable
  let i = 0;
  const len = bytes.length;

  while (i < len) {
    i = skipAsciiWhitespaceNoNewline(bytes, i, len);
    if (i >= len) break;

    const b = bytes[i];

    // Operators / separators.
    if (b === C.SEMI || b === C.LF) {
      spans.push(mkSpan(bytes, i, i + 1, "operator"));
      i += 1;
      commandSeen = false;
      continue;
    }
    // Bare grouping parens are operators (mirrors DCG tokenizer treating
    // '(' ')' as separators). Handled here so the word-token branch — which
    // would return a zero-width span on '(' / ')' — can never spin.
    if (b === C.LPAREN || b === C.RPAREN) {
      spans.push(mkSpan(bytes, i, i + 1, "operator"));
      i += 1;
      commandSeen = false;
      continue;
    }
    if (b === C.PIPE) {
      const e = i + 1 < len && bytes[i + 1] === C.PIPE ? i + 2 : i + 1;
      spans.push(mkSpan(bytes, i, e, "operator"));
      i = e;
      commandSeen = false;
      continue;
    }
    if (b === C.AMP) {
      if (i + 1 < len && bytes[i + 1] === C.GT) {
        const e = i + 2 < len && bytes[i + 2] === C.GT ? i + 3 : i + 2;
        spans.push(mkSpan(bytes, i, e, "redirect"));
        i = e;
        continue;
      }
      const e = i + 1 < len && bytes[i + 1] === C.AMP ? i + 2 : i + 1;
      spans.push(mkSpan(bytes, i, e, "operator"));
      i = e;
      commandSeen = false;
      continue;
    }

    // Redirections (numeric-fd prefix folded into the operator span).
    if (b === C.GT || b === C.LT) {
      // <( / >( process substitution => subshell span.
      if (i + 1 < len && bytes[i + 1] === C.LPAREN) {
        const close = findMatchingCommandSubstitution(bytes, i + 2, len);
        const e = close !== undefined ? close + 1 : len;
        spans.push(mkSpan(bytes, i, e, "subshell"));
        i = e;
        continue;
      }
      const e = i + 1 < len && bytes[i + 1] === b ? i + 2 : i + 1;
      spans.push(mkSpan(bytes, i, e, "redirect"));
      i = e;
      continue;
    }

    // $( ... ) / $(( ... )) subshell.
    if (b === C.DOLLAR && i + 1 < len && bytes[i + 1] === C.LPAREN) {
      let close: number | undefined;
      let e: number;
      if (i + 2 < len && bytes[i + 2] === C.LPAREN) {
        close = findMatchingArithmeticExpansion(bytes, i + 3, len);
        e = close !== undefined ? close + 2 : len;
      } else {
        close = findMatchingCommandSubstitution(bytes, i + 2, len);
        e = close !== undefined ? close + 1 : len;
      }
      spans.push(mkSpan(bytes, i, e, "subshell"));
      i = e;
      continue;
    }

    // backtick subshell.
    if (b === C.BACKTICK) {
      const close = findMatchingBacktick(bytes, i + 1, len);
      const e = close !== undefined ? close + 1 : len;
      spans.push(mkSpan(bytes, i, e, "subshell"));
      i = e;
      continue;
    }

    // single-quoted string.
    if (b === C.SQUOTE) {
      let j = i + 1;
      while (j < len && bytes[j] !== C.SQUOTE) j += 1;
      if (j < len) j += 1;
      spans.push(mkSpan(bytes, i, j, "string"));
      i = j;
      commandSeen = true;
      continue;
    }
    // double-quoted string.
    if (b === C.DQUOTE) {
      const e = consumeWordToken(bytes, i, len);
      spans.push(mkSpan(bytes, i, e, "string"));
      i = e;
      commandSeen = true;
      continue;
    }

    // word token.
    const start = i;
    let e = consumeWordToken(bytes, i, len);
    if (e <= start) {
      // Guarantee forward progress on any byte consumeWordToken refuses to
      // advance past (defensive; the operator branches above already cover the
      // known cases).
      e = start + 1;
    }
    const text = fromBytes(bytes, start, e);
    let kind: SpanKind;
    if (!commandSeen) {
      if (isEnvAssignment(text)) {
        kind = "argument";
      } else {
        kind = "executable";
        commandSeen = true;
      }
    } else if (text.startsWith("-")) {
      kind = "flag";
    } else if (
      text.startsWith("/") ||
      text.startsWith("./") ||
      text.startsWith("../") ||
      text.startsWith("~") ||
      text.includes("/")
    ) {
      kind = "path";
    } else if (looksLikeSubcommandWord(text)) {
      kind = "subcommand";
    } else {
      kind = "argument";
    }
    spans.push(mkSpan(bytes, start, e, kind));
    i = e;
  }

  return spans;
}

function mkSpan(
  bytes: Uint8Array,
  start: number,
  end: number,
  kind: SpanKind,
): Span {
  return { text: fromBytes(bytes, start, end), kind, start, end };
}

function extractExecutable(spans: Span[]): string | undefined {
  for (const span of spans) {
    if (span.kind === "executable") {
      return basenameOf(span.text);
    }
  }
  return undefined;
}

export function classifySegment(segment: string): SegmentContext {
  const raw = segment;
  // Apply DCG's wrapper-strip + command-word dequote to get the normalized
  // form used for matching. (Wrapper stripping internally dequotes the leading
  // command word; for a bare segment with no wrapper we still dequote.)
  const stripped = stripWrapperPrefixes(segment);
  const normalized =
    stripped === segment ? dequoteSegmentCommandWords(segment) : stripped;

  const spans = classifySpans(normalized);
  const executable = extractExecutable(spans);

  return { raw, normalized, executable, spans };
}

export function normalizeCommand(command: string): SegmentContext[] {
  return splitCommandSegments(command).map(classifySegment);
}
