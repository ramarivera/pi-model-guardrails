// Data-span masking — sanitize a command BEFORE pattern matching so a dangerous
// substring sitting in a KNOWN-DATA position (a commit message, a search
// pattern, an echo/printf argument, a `# comment`, an arithmetic `$((…))`)
// cannot trigger a false-positive block.
//
// Faithful port of DCG `sanitize_for_pattern_matching` (src/context.rs): it is
// deliberately CONSERVATIVE and TABLE-DRIVEN — it only masks
//   - every argument of an all-args-data command (echo, printf),
//   - the value of a KNOWN data-carrying flag of a KNOWN command
//     (`git -m/--message/--grep`, `gh --title/--body`, `grep -e`, …),
//   - `# …` comments,
// and it NEVER masks a token that contains shell-EXECUTED text (`$(cmd)`,
// backticks, `<(…)`), because that text really runs. The one refinement over
// DCG: arithmetic `$((…))` (which never executes commands) IS maskable, while a
// command substitution `$(…)` nested ANYWHERE in the token is not — so
// `echo $((rm -rf /))` is masked (safe) but `echo $(rm -rf /)` and
// `echo $(( $(rm -rf /) ))` are left visible (they execute).
//
// Masking replaces the offending span with spaces (length-preserving), so the
// rest of the engine — normalization, the rm parser, every regex pack — runs
// against the sanitized text unchanged. A command with no data-registry word and
// no `#` is returned untouched (the hot-path fast exit).

/** Commands whose EVERY argument is inert data. DCG all_args_data. */
const ALL_ARGS_DATA = new Set(["echo", "printf"]);

interface FlagDataEntry {
  command: string;
  short?: string;
  long?: string;
}

/**
 * (command, flag) pairs whose flag VALUE is data, not executed. Faithful port of
 * DCG SAFE_STRING_REGISTRY.flag_data_pairs. `git -m` is treated as data for the
 * `git` command regardless of subcommand (commit/tag), mirroring DCG's note.
 */
const FLAG_DATA: readonly FlagDataEntry[] = [
  { command: "git", short: "-m", long: "--message" },
  { command: "git", long: "--grep" },
  { command: "bd", long: "--description" },
  { command: "bd", long: "--title" },
  { command: "bd", long: "--notes" },
  { command: "bd", long: "--reason" },
  { command: "grep", short: "-e", long: "--regexp" },
  { command: "rg", short: "-e", long: "--regexp" },
  { command: "ag", short: "-e", long: "--pattern" },
  { command: "ack", short: "-e", long: "--pattern" },
  { command: "gh", short: "-t", long: "--title" },
  { command: "gh", short: "-b", long: "--body" },
  { command: "gh", short: "-m", long: "--message" },
  // DELIBERATE DIVERGENCE from DCG: DCG masks `curl -d/-H/--data-*` as data, but
  // this engine's platform/API packs (e.g. railway) inspect curl request BODIES
  // for destructive API mutations (`projectDelete`, …). Masking the payload would
  // blind those rules — a false negative. So curl data-flags are intentionally
  // NOT in this table.
  { command: "jq", long: "--arg" },
  { command: "jq", long: "--argjson" },
  { command: "jq", long: "--slurpfile" },
  { command: "docker", short: "-l", long: "--label" },
  { command: "kubectl", long: "--annotation" },
  { command: "kubectl", short: "-l", long: "--label" },
  { command: "xargs", short: "-I" },
  { command: "cargo", long: "--message" },
  { command: "npm", long: "--message" },
];

/** Quick-reject set: any registry command name (basename) that can trigger masking. */
const SAFE_COMMANDS = new Set<string>([
  ...ALL_ARGS_DATA,
  ...FLAG_DATA.map((e) => e.command),
]);

/** Wrapper prefixes whose own words are skipped to find the real command. */
const WRAPPERS = new Set([
  "sudo",
  "doas",
  "env",
  "nice",
  "ionice",
  "time",
  "nohup",
  "stdbuf",
]);

type TokKind = "word" | "separator" | "comment" | "redirect";
interface Tok {
  start: number;
  end: number;
  kind: TokKind;
}

/**
 * Sanitize `command` for pattern matching. Returns the original string when no
 * masking applies (fast path), otherwise a length-preserved copy with data spans
 * blanked to spaces.
 */
export function sanitizeForPatternMatching(command: string): string {
  if (command.length === 0) return command;
  if (!command.includes("#") && !hasSafeCommand(command)) return command;

  const tokens = tokenize(command);
  if (tokens.length === 0) return command;

  const maskRanges: Array<[number, number]> = [];

  // Per-segment state.
  let segmentCmd: string | undefined;
  let allArgsData = false;
  let pendingFlagValue = false; // the next word token is a data-flag value
  let afterRedirect = false; // the next word is a redirect target (leave visible)

  for (const tok of tokens) {
    if (tok.kind === "separator") {
      segmentCmd = undefined;
      allArgsData = false;
      pendingFlagValue = false;
      afterRedirect = false;
      continue;
    }
    if (tok.kind === "comment") {
      maskRanges.push([tok.start, tok.end]);
      continue;
    }
    if (tok.kind === "redirect") {
      afterRedirect = true;
      pendingFlagValue = false; // a redirect ends any pending data-flag value
      continue;
    }

    const text = command.slice(tok.start, tok.end);

    // The redirect TARGET stays visible so destructive-redirect rules can see it.
    if (afterRedirect) {
      afterRedirect = false;
      continue;
    }

    // No command word yet: skip wrappers + env-assignments, then this is the cmd.
    if (segmentCmd === undefined) {
      if (WRAPPERS.has(basename(text))) continue;
      if (isEnvAssignment(text)) continue;
      segmentCmd = basename(text);
      allArgsData = ALL_ARGS_DATA.has(segmentCmd);
      continue;
    }

    // A pending data-flag value: mask it (unless it executes).
    if (pendingFlagValue) {
      pendingFlagValue = false;
      if (!containsExecutableExpansion(text))
        maskRanges.push([tok.start, tok.end]);
      continue;
    }

    // Is this token a known data-flag for the current command?
    const flagValue = dataFlagValue(segmentCmd, text);
    if (flagValue === "attached") {
      // `--message=...` / `-m...` — mask only the value part after the `=` / flag.
      const valStart = attachedValueStart(text);
      if (valStart >= 0) {
        const abs = tok.start + valStart;
        const val = command.slice(abs, tok.end);
        if (!containsExecutableExpansion(val)) maskRanges.push([abs, tok.end]);
      }
      continue;
    }
    if (flagValue === "separate") {
      pendingFlagValue = true; // mask the NEXT token
      continue;
    }

    // All-args-data command (echo/printf): mask every non-executing arg. An
    // UNQUOTED redirect operator is already its own token (consumeWord breaks on
    // it) and its target flows through the `afterRedirect` visible path, so a
    // destructive overwrite (`echo x > /etc/passwd`, `echo x>/etc/passwd`) is
    // never blanked. A `>`/`<` that survives INSIDE a word is quoted (data) and
    // is correctly masked.
    if (allArgsData && !containsExecutableExpansion(text)) {
      maskRanges.push([tok.start, tok.end]);
    }
  }

  if (maskRanges.length === 0) return command;
  return applyMask(command, maskRanges);
}

/** Does the command contain any data-registry command name as a word? Cheap pre-filter. */
function hasSafeCommand(command: string): boolean {
  for (const name of SAFE_COMMANDS) {
    let from = 0;
    let idx = command.indexOf(name, from);
    while (idx >= 0) {
      const before = idx === 0 ? "" : command[idx - 1];
      const after = command[idx + name.length] ?? "";
      const wordBefore =
        before === "" || /[\s;|&([]/.test(before) || before === "/";
      const wordAfter = after === "" || /[\s;|&)\]]/.test(after);
      if (wordBefore && wordAfter) return true;
      from = idx + name.length;
      idx = command.indexOf(name, from);
    }
  }
  return false;
}

/**
 * Classify a flag token for `cmd`:
 *  - "separate": exact flag match, value is the NEXT token (`-m msg`)
 *  - "attached": `--flag=val` or short `-mval`, value is in this token
 *  - undefined:  not a data flag here
 */
function dataFlagValue(
  cmd: string,
  token: string,
): "separate" | "attached" | undefined {
  for (const e of FLAG_DATA) {
    if (e.command !== cmd) continue;
    if (e.short && token === e.short) return "separate";
    if (e.long && token === e.long) return "separate";
    if (e.long && token.startsWith(`${e.long}=`)) return "attached";
    // short attached form: `-mMessage` (only for single-dash short flags).
    if (e.short && token.length > e.short.length && token.startsWith(e.short)) {
      return "attached";
    }
  }
  return undefined;
}

/** Index where an attached value begins: after `=` for long flags, after the short flag. */
function attachedValueStart(token: string): number {
  const eq = token.indexOf("=");
  if (eq >= 0) return eq + 1;
  // short attached: `-mVALUE` -> value starts at index 2.
  return token.length > 2 ? 2 : -1;
}

/**
 * True if the token contains shell-EXECUTED text: a command substitution `$(…)`
 * (NOT arithmetic `$((…))`), a backtick, or a process substitution `<(…)`/`>(…)`.
 * Such a token is never masked — its content really runs.
 *
 * Arithmetic `$((…))` is allowed (it never runs commands), BUT a command
 * substitution nested inside it (`$(( $(cmd) ))`) is still caught, because the
 * scan flags any `$(` whose following char is not `(`.
 */
function containsExecutableExpansion(token: string): boolean {
  if (token.includes("`")) return true;
  for (let i = 0; i < token.length; i++) {
    const c = token[i];
    if (c === "\\") {
      i += 1; // skip escaped char
      continue;
    }
    if (c === "$" && token[i + 1] === "(") {
      // `$((` => arithmetic (maskable); `$(` + anything else => command sub.
      if (token[i + 2] !== "(") return true;
      i += 2;
      continue;
    }
    if ((c === "<" || c === ">") && token[i + 1] === "(") return true;
  }
  return false;
}

/** Quote/escape-aware tokenizer: words, separators, comments, redirect operators. */
function tokenize(command: string): Tok[] {
  const tokens: Tok[] = [];
  let i = 0;
  const n = command.length;
  while (i < n) {
    const c = command[i];
    if (c === " " || c === "\t" || c === "\r") {
      i += 1;
      continue;
    }
    if (c === "\n" || c === ";") {
      tokens.push({ start: i, end: i + 1, kind: "separator" });
      i += 1;
      continue;
    }
    if (c === "|") {
      const end = command[i + 1] === "|" ? i + 2 : i + 1;
      tokens.push({ start: i, end, kind: "separator" });
      i = end;
      continue;
    }
    if (c === "&") {
      if (command[i + 1] === ">") {
        const end = command[i + 2] === ">" ? i + 3 : i + 2;
        tokens.push({ start: i, end, kind: "redirect" });
        i = end;
        continue;
      }
      const end = command[i + 1] === "&" ? i + 2 : i + 1;
      tokens.push({ start: i, end, kind: "separator" });
      i = end;
      continue;
    }
    if (c === "#") {
      // Comment only at a word boundary (start of a token).
      let end = command.indexOf("\n", i);
      if (end < 0) end = n;
      tokens.push({ start: i, end, kind: "comment" });
      i = end;
      continue;
    }
    if (c === ">" || c === "<") {
      // process substitution `<(` / `>(` is part of the WORD (executable), not a
      // redirect operator — let the word consumer take it.
      if (command[i + 1] === "(") {
        const start = i;
        i = consumeWord(command, i);
        tokens.push({ start, end: i, kind: "word" });
        continue;
      }
      const end = command[i + 1] === c ? i + 2 : i + 1;
      tokens.push({ start: i, end, kind: "redirect" });
      i = end;
      continue;
    }
    // word token (quote/escape aware).
    const start = i;
    i = consumeWord(command, i);
    if (i <= start) i = start + 1; // forward-progress guard
    tokens.push({ start, end: i, kind: "word" });
  }
  return tokens;
}

/** Consume one quote/escape-aware word, returning the end index. */
function consumeWord(command: string, start: number): number {
  let i = start;
  const n = command.length;
  while (i < n) {
    const c = command[i];
    if (c === " " || c === "\t" || c === "\r" || c === "\n") break;
    if (c === ";" || c === "|" || c === "&") break;
    if (c === "\\") {
      i += 2;
      continue;
    }
    if (c === "'") {
      i += 1;
      while (i < n && command[i] !== "'") i += 1;
      if (i < n) i += 1;
      continue;
    }
    if (c === '"') {
      i += 1;
      while (i < n) {
        if (command[i] === "\\") {
          i += 2;
          continue;
        }
        if (command[i] === '"') {
          i += 1;
          break;
        }
        i += 1;
      }
      continue;
    }
    if (c === "$" && command[i + 1] === "(") {
      i = consumeParens(command, i + 1);
      continue;
    }
    if ((c === "<" || c === ">") && command[i + 1] === "(") {
      i = consumeParens(command, i + 1);
      continue;
    }
    // An UNQUOTED redirect operator terminates the word (it is shell syntax, not
    // part of the preceding token). This is load-bearing for masking: it means an
    // attached redirect inside a data-flag value (`-mmsg>/etc/passwd`) splits into
    // the value word `-mmsg` + a separate redirect + a visible target, so the
    // destructive overwrite is never blanked. A `>`/`<` INSIDE quotes is consumed
    // by the quote branches above and stays part of the (maskable) value.
    if (c === "<" || c === ">") break;
    if (c === "`") {
      i += 1;
      while (i < n && command[i] !== "`") i += 1;
      if (i < n) i += 1;
      continue;
    }
    i += 1;
  }
  return i;
}

/** Consume a balanced `( … )` starting at `open` (the `(`). Returns index past `)`. */
function consumeParens(command: string, open: number): number {
  let depth = 0;
  let i = open;
  const n = command.length;
  while (i < n) {
    if (command[i] === "(") depth += 1;
    else if (command[i] === ")") {
      depth -= 1;
      if (depth === 0) return i + 1;
    }
    i += 1;
  }
  return n;
}

/** Replace each [start,end) range with spaces (length-preserving). */
function applyMask(command: string, ranges: Array<[number, number]>): string {
  const out = command.split("");
  for (const [start, end] of ranges) {
    for (let i = start; i < end && i < out.length; i++) {
      if (out[i] !== "\n") out[i] = " ";
    }
  }
  return out.join("");
}

/** DCG basename rule (trim quotes, rsplit on / and \, strip a trailing .exe). */
function basename(word: string): string {
  let w = word.replace(/^["']+|["']+$/g, "");
  const idx = Math.max(w.lastIndexOf("/"), w.lastIndexOf("\\"));
  if (idx >= 0) w = w.slice(idx + 1);
  if (w.length >= 4 && w.slice(-4).toLowerCase() === ".exe") w = w.slice(0, -4);
  return w;
}

/** NAME=VALUE env-assignment prefix (mirrors normalize.isEnvAssignment). */
function isEnvAssignment(word: string): boolean {
  const eq = word.indexOf("=");
  if (eq <= 0) return false;
  return /^[A-Za-z_][A-Za-z0-9_]*$/.test(word.slice(0, eq));
}
