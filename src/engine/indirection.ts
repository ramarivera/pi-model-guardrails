// Tier-3 structural indirection resolver — aliased-sink detection.
//
// DCG (and this engine's regex packs) match on the literal command text, so an
// agent can hide a destructive sink behind one level of shell indirection that
// the literal patterns never see:
//
//   x=rm; $x -rf ~                 (variable indirection)
//   alias d=rm; d -rf ~            (alias expansion)
//   c="rm -rf"; $c ~               (multi-word value, word-split on use)
//   a=r; b=m; $a$b -rf ~           (verb built by concatenation)
//
// This pass does a SMALL, bounded, quote-aware structural resolution of those
// vectors — variable substitution and alias expansion within a single command
// line — and returns the resolved SINK statement(s). The caller re-runs the
// (unchanged) regex engine on the expansion, so an aliased `rm -rf` is caught by
// the very same rule that catches a bare `rm -rf`. No rule duplication.
//
// WHY pure TS and not @ast-grep/napi: ast-grep's napi binding ships built-in
// grammars for web languages only (css/html/js/jsx/ts/tsx) — there is NO Bash
// language, so parsing shell would require registerDynamicLanguage() with a
// per-platform, separately-compiled tree-sitter-bash native library. A native
// binary that can fail to load is the wrong dependency for a fail-closed guard
// that MUST always load: if it failed, the whole extension would fail to load
// and the guard would vanish. A focused pure-TS resolver always loads and, on
// any unexpected input, simply returns undefined (the engine falls back to the
// regex packs — DCG parity), so this layer can only ADD detection, never remove
// the baseline.
//
// HEAD-AWARE (false-positive defense): a statement is only treated as a sink
// when indirection creates/changes its COMMAND HEAD (executable position) —
// `$x -rf ~` (x=rm) or `alias d=rm; d -rf ~`. Indirection that only touches
// ARGUMENT positions is ignored: `v=rm; o=-rf; echo $v $o ~` resolves to a
// harmless `echo rm -rf ~` print, NOT an executed sink, so re-evaluating it
// would false-positive against the position-agnostic regex packs. We resolve one
// level of value indirection too (`a=rm; b=$a; $b -rf ~`), left-to-right.
//
// SCOPE (deliberate): single-line variable indirection + alias expansion only.
// Interprocedural function-wrapper dataflow (`f(){ rm -rf "$1"; }; f /`) and
// cross-`eval`/base64 decoding are explicitly OUT — they need a real
// interpreter and carry high false-positive risk. They are documented as future
// work, not silently skipped.
//
// SECURITY-FIRST propagation: shell scopes a variable set in a `|` subshell so
// it does not reach the parent, but this resolver propagates assignments across
// ALL separators (;, &&, ||, |, newline). That can, in a contrived case
// (`x=rm | $x -rf /`), flag a command bash would actually run with an EMPTY $x.
// We accept that tiny theoretical false positive: the realistic obfuscation uses
// sequential separators, and a human deliberately relying on subshell scoping to
// smuggle a destructive verb is itself the thing we want to catch.

import { classifySegment, splitCommandSegments } from "./normalize.ts";

/** Bounded alias-expansion depth — defends against `alias a=b; alias b=a`. */
const MAX_ALIAS_EXPANSIONS = 8;
/** Don't even try on absurdly long input — the resolver is a best-effort tier. */
const MAX_INDIRECTION_INPUT = 8192;

export interface IndirectionResult {
  /**
   * The resolved SINK statement(s) — only commands whose head (executable) was
   * created/changed by indirection, fully expanded, newline-joined. Re-evaluate
   * THIS string. (Arg-only expansions like `echo $v` are deliberately excluded.)
   */
  expanded: string;
  /** What kinds of indirection produced the sink(s) (for attribution). */
  notes: string[];
}

/**
 * Resolve one level of variable/alias indirection in `command`.
 *
 * Returns undefined when there is nothing to resolve (no indirection markers,
 * or resolution produced no change) — the caller then keeps the original
 * decision. Never throws: any unexpected shape returns undefined.
 */
export function resolveIndirection(
  command: string,
): IndirectionResult | undefined {
  if (command.length === 0 || command.length > MAX_INDIRECTION_INPUT) {
    return undefined;
  }
  if (!hasIndirectionMarkers(command)) return undefined;

  try {
    return resolveInner(command);
  } catch {
    // Best-effort tier: on any parse surprise, defer to the regex engine.
    return undefined;
  }
}

/**
 * Cheap pre-check so the resolver only runs when indirection is plausible.
 * Either (a variable REFERENCE and a variable ASSIGNMENT both present) or (an
 * `alias` definition present). Without an assignment, a bare `$x` resolves to
 * nothing we know about, so there is nothing to substitute.
 */
function hasIndirectionMarkers(command: string): boolean {
  const hasVarRef = /\$\{?[A-Za-z_][A-Za-z0-9_]*\}?/.test(command);
  const hasAssign = /(?:^|[;&|\n(]|\s)[A-Za-z_][A-Za-z0-9_]*=/.test(command);
  const hasAlias = /(?:^|[;&|\n]|\s)alias\s/.test(command);
  return (hasVarRef && hasAssign) || hasAlias;
}

function resolveInner(command: string): IndirectionResult | undefined {
  const statements = splitCommandSegments(command);
  if (statements.length === 0) return undefined;

  const vars = new Map<string, string>();
  const aliases = new Map<string, string>();
  const notes = new Set<string>();

  // Collect ONLY statements whose COMMAND HEAD (the executable) was created or
  // changed by indirection — an aliased/var-hidden SINK. We do NOT collect
  // statements where indirection only touched argument positions: a resolved
  // `echo $v $o $t` -> `echo rm -rf ~` is a harmless print, and re-evaluating it
  // would false-positive (the regex packs match destructive substrings
  // position-agnostically). The feature is "aliased SINK detection" — a command
  // being EXECUTED, not destructive-looking text being passed to an inert
  // command. This also bounds the re-eval cost: only real resolved sinks (not
  // the whole input) are handed back to the engine.
  const sinks: string[] = [];

  for (const statement of statements) {
    if (statement.trim().length === 0) continue;

    const ctx = classifySegment(statement);
    const tokens = wordTokens(ctx.normalized);

    // `alias NAME=VALUE [NAME2=VALUE2 ...]` — record, contributes no sink itself.
    if (ctx.executable === "alias") {
      recordAliases(tokens.slice(1), aliases, vars);
      continue;
    }

    // Leading `NAME=VALUE` assignment words (env-prefix or a bare assignment
    // statement). `x=rm` (no executable) and `FOO=bar cmd` both land here.
    const firstCmdIdx = recordLeadingAssignments(tokens, vars);

    // A pure-assignment statement (no command word) has nothing to expand.
    if (firstCmdIdx >= tokens.length) continue;

    const cmdTokens = tokens.slice(firstCmdIdx);
    const {
      expanded,
      headChanged,
      notes: stmtNotes,
    } = expandCommand(cmdTokens, vars, aliases);
    if (headChanged) {
      // Re-attach the leading env-assignments so e.g. `FOO=bar $x` still parses.
      const prefix = tokens.slice(0, firstCmdIdx);
      sinks.push([...prefix, ...expanded].join(" "));
      for (const n of stmtNotes) notes.add(n);
    }
  }

  if (sinks.length === 0) return undefined;
  return { expanded: sinks.join("\n"), notes: [...notes] };
}

/**
 * Split a normalized segment into word-like tokens, dropping operators and
 * redirects. Reuses classifySegment's span tokenizer for quote/escape-aware
 * boundaries, so `d='rm -rf'` is one token, not three.
 */
function wordTokens(normalized: string): string[] {
  const ctx = classifySegment(normalized);
  const spans = ctx.spans ?? [];
  const out: string[] = [];
  for (const span of spans) {
    if (span.kind === "operator" || span.kind === "redirect") continue;
    if (span.text.trim().length === 0) continue;
    out.push(span.text);
  }
  return out;
}

/**
 * Record `alias NAME=VALUE` pairs from the tokens after the `alias` keyword.
 * `alias -p`/`alias` with no `=` are listings — ignored. Values resolve already-
 * known vars (`alias d=$x`).
 */
function recordAliases(
  tokens: string[],
  aliases: Map<string, string>,
  vars: Map<string, string>,
): void {
  for (const token of tokens) {
    if (token.startsWith("-")) continue; // flags like `alias -p`
    const pair = splitAssignment(token);
    if (!pair) continue;
    if (!isPlainName(pair.name)) continue;
    aliases.set(pair.name, resolveValue(pair.value, vars));
  }
}

/**
 * Record leading `NAME=VALUE` assignment tokens into `vars`. Returns the index
 * of the first NON-assignment token (the command word), or tokens.length if the
 * whole statement was assignments. Processed left-to-right, so a value can
 * reference an earlier var (`a=rm; b=$a`) — one level of value indirection,
 * resolved against the vars already seen (no recursion, no cycles).
 */
function recordLeadingAssignments(
  tokens: string[],
  vars: Map<string, string>,
): number {
  let i = 0;
  for (; i < tokens.length; i++) {
    const pair = splitAssignment(tokens[i]);
    if (!pair || !isPlainName(pair.name)) break;
    vars.set(pair.name, resolveValue(pair.value, vars));
  }
  return i;
}

/**
 * Resolve an assignment/alias VALUE: a wholly single-quoted value is literal
 * (bash does not expand inside '...'), otherwise dequote then substitute any
 * already-known vars.
 */
function resolveValue(rawValue: string, vars: Map<string, string>): string {
  if (rawValue.startsWith("'")) return dequote(rawValue);
  return substituteVars(dequote(rawValue), vars);
}

/**
 * Expand a command's tokens: alias-expand the leading word (bounded), then
 * substitute `$NAME`/`${NAME}` references from `vars`.
 *
 * Returns the expanded tokens, `headChanged` (true iff indirection created or
 * changed the COMMAND HEAD — alias-expanded the leading word, or substituted a
 * var into the executable position), and the attribution notes for that head.
 * The caller only treats a statement as a sink when `headChanged` — an
 * arg-position substitution (`echo $v`) is not a sink.
 */
function expandCommand(
  cmdTokens: string[],
  vars: Map<string, string>,
  aliases: Map<string, string>,
): { expanded: string[]; headChanged: boolean; notes: string[] } {
  let tokens = [...cmdTokens];
  let headChanged = false;
  const notes = new Set<string>();

  // Alias-expand the leading command word, one level at a time, bounded.
  const seen = new Set<string>();
  for (let n = 0; n < MAX_ALIAS_EXPANSIONS; n++) {
    const head = tokens[0];
    if (head === undefined) break;
    const key = aliasKey(head);
    if (!aliases.has(key) || seen.has(key)) break;
    seen.add(key);
    const expansion = aliases.get(key) ?? "";
    const expandedHead = wordTokens(expansion);
    if (expandedHead.length === 0) break;
    tokens = [...expandedHead, ...tokens.slice(1)];
    headChanged = true;
    notes.add("alias");
  }

  // Substitute variable references in every token. Only a change to the HEAD
  // (index 0) makes this a sink; arg-position changes still expand (so the
  // sink's flags/targets resolve) but do not by themselves trigger re-eval.
  const substituted = tokens.map((token, idx) => {
    const next = substituteVars(token, vars);
    if (next !== token && idx === 0) {
      headChanged = true;
      notes.add("variable");
    }
    return next;
  });

  // A multi-word substituted value (`d="rm -rf"` -> `$d` -> "rm -rf") must
  // word-split so the re-evaluation sees `rm -rf` as two tokens, not one.
  const flattened = substituted.flatMap((t) =>
    t.includes(" ") ? t.split(/\s+/) : t,
  );
  return {
    expanded: flattened.filter((t) => t.length > 0),
    headChanged,
    notes: [...notes],
  };
}

/**
 * Substitute `$NAME` and `${NAME}` with their recorded values. Skips
 * single-quoted regions of the token (bash does not expand inside '...'). Only
 * KNOWN variables are substituted; an unknown `$FOO` is left untouched (matches
 * neither a rule nor a false alarm).
 */
function substituteVars(token: string, vars: Map<string, string>): string {
  if (!token.includes("$")) return token;

  let out = "";
  let i = 0;
  const n = token.length;
  while (i < n) {
    const ch = token[i];
    // Skip single-quoted spans verbatim.
    if (ch === "'") {
      const close = token.indexOf("'", i + 1);
      if (close < 0) {
        out += token.slice(i);
        break;
      }
      out += token.slice(i, close + 1);
      i = close + 1;
      continue;
    }
    if (ch === "$") {
      const ref = readVarRef(token, i);
      if (ref) {
        const value = vars.get(ref.name);
        if (value !== undefined) {
          out += value;
        }
        // Unknown var: drop the reference (bash expands it to empty). This makes
        // `$x -rf /` with unknown x become ` -rf /` — harmless — rather than a
        // literal `$x` that could spuriously match nothing. KNOWN vars are the
        // only ones that can produce a destructive expansion.
        i = ref.end;
        continue;
      }
    }
    out += ch;
    i += 1;
  }
  return out;
}

/** Parse a `$NAME` / `${NAME}` reference starting at `start` (the `$`). */
function readVarRef(
  token: string,
  start: number,
): { name: string; end: number } | undefined {
  let i = start + 1;
  const braced = token[i] === "{";
  if (braced) i += 1;
  const nameStart = i;
  if (!/[A-Za-z_]/.test(token[i] ?? "")) return undefined;
  while (i < token.length && /[A-Za-z0-9_]/.test(token[i])) i += 1;
  const name = token.slice(nameStart, i);
  if (braced) {
    if (token[i] !== "}") return undefined;
    i += 1;
  }
  return { name, end: i };
}

/** Split `NAME=VALUE` at the first `=`. */
function splitAssignment(
  token: string,
): { name: string; value: string } | undefined {
  const eq = token.indexOf("=");
  if (eq <= 0) return undefined;
  return { name: token.slice(0, eq), value: token.slice(eq + 1) };
}

/** A valid shell identifier: [A-Za-z_][A-Za-z0-9_]*. */
function isPlainName(name: string): boolean {
  return /^[A-Za-z_][A-Za-z0-9_]*$/.test(name);
}

/** Strip ONE layer of matching surrounding quotes from a value. */
function dequote(value: string): string {
  if (value.length >= 2) {
    const first = value[0];
    const last = value[value.length - 1];
    if ((first === '"' || first === "'") && first === last) {
      return value.slice(1, -1);
    }
  }
  return value;
}

/** Alias lookup key: basename, leading backslash stripped (`\rm` -> `rm`). */
function aliasKey(word: string): string {
  let w = word.replace(/^\\+/, "");
  const idx = Math.max(w.lastIndexOf("/"), w.lastIndexOf("\\"));
  if (idx >= 0) w = w.slice(idx + 1);
  return w;
}
