# pi-model-guardrails rebuild — session handoff / resume state

> Working doc for resuming the DCG→Pi port. Delete before the v0.2.0 release.
> Companion design doc (full): `~/dev/toolbox/projects/permissions-safety-net/pi-model-guardrails-rebuild-DESIGN.md`

## What this is

Rebuilding `@ramarivera/pi-model-guardrails` as TWO layers:
1. **Native-TS DCG port** — deterministic command-guard engine (pack/rule format + matcher + imperative rm parser + heredoc), ported from `Dicklesworthstone/destructive_command_guard` (Rust).
2. **Inviolable-constraint policy engine + deviation state machine** (`COMPLIANT→WATCH→GATED→RECOVERING→HALTED`): on deviation, steer the model back and route EVERY tool call through an LLM grading gate until provably back on track. **Layer 2 is NOT built yet** (Phase 2/3).

## Environment / how to work here (IMPORTANT)

- Repo: `~/dev/pi-model-guardrails`, branch **`feat/dcg-port-v2`** (off `main` @ v0.1.7).
- Runtime: `bun` 1.3.x, node 24. Deps installed (`node_modules` present). `bun.lock` is gitignored (repo's committed lockfile is `package-lock.json`).
- **Sandbox quirk in this Claude Code session:** plain Bash filesystem writes are EPHEMERAL, and writes outside the project are blocked. Persist code via the **Write/Edit tools**. Run install/test/lint/git via Bash with **`dangerouslyDisableSandbox: true`** (works in this added dir). Reads are fine either way.
- Commands: `bunx tsc --noEmit` (typecheck), `bun run test` (full suite, `tsx --test`), `bunx tsx --test test/<file>` (one file). Tests use `node:test` + `node:assert/strict`.
- Current suite: **269 pass / 0 fail**, tsc clean.

## Done (committed on feat/dcg-port-v2)

- `6ea36e3` Phase 1 engine: `src/engine/{types,normalize,matcher,registry,evaluate,rm-parser,heredoc}.ts` + `packs/{core-git,core-filesystem}.ts`; tests; `test/fixtures/golden-corpus.json` (298 DCG-extracted cases) + `test/differential-corpus.test.ts`.
- `2a7a46a` Phase 0 partial: exact-id `model-filter`; observability ring buffer + `recent(n)`.
- `e5d32e6` 3 CRITICAL review bypasses fixed: obfuscation quick-reject (`r\m`), wrapper-strip whole-command (`sudo rm -rf /tmp/x` FP), imperative-allow short-circuit (`mv /etc /tmp/x && rm -rf /tmp/x` FN). Two-pass exoneration in matcher.ts.
- `8f72781` core.git restore FPs: order-independent `--staged`, bounded `--worktree` (no cross-segment bridge).

## Differential corpus status

284/298 asserted; 14 tracked-deferred in `test/differential-corpus.test.ts` (DECISION_EXCLUSIONS): 9 = non-core packs not ported (Phase 4); 2 = `$((arith))` + quoted-`-m` masking gaps (task #7); 2 = heredoc-not-wired artifacts (task #7); 1 RULEID exclusion (`git restore --worktree` attribution, task #8 — MAY now be fixed by the lookahead change; re-check and remove if stale).

## Remaining review findings to fix (from the 5-lens adversarial review)

Not yet fixed (all HIGH unless noted; most are shared-DCG bugs we choose to fix):
- **core.git**: `git reset -q --hard` (intervening flag, FN) and `git clean -d -f` (separate flags, FN) — reset-hard/clean-force regexes are still first-token-only. Add a bounded `(?:[^\s&;|`()<>]+\s+)*` walker before `--hard` / the force flag (mirror push-force-long). Add a `checkout -f/--force` rule (FN coverage gap).
- **rm-parser**: `rm -r --force /` (mixed short+long flags → root deletion MISSED, dangerous FN) — make recursion=(seenR||seenLongRecursive), force=(seenF||seenLongForce). `rm /etc -rf` (flags after path, FN). `rm -rf /tmp/x > /dev/null` mis-parses redirect target as an rm path (FP) — consume the redirect target token.
- **propagation**: cp/ln/rsync-then-rm chain defeated by intervening `;`/`|`/newline (FN) — make it segment-aware.
- **ReDoS** (HIGH): `perMatchBudgetMs` can't interrupt synchronous catastrophic backtracking (a 29-char input blocked 5.6s). Core packs are safe; validate EXTERNAL pack patterns at load (reject nested unbounded quantifiers) — matters for Phase 4 external/AST packs.
- **masking** (task #7): `rm -rf /tmp/x # cleanup` (trailing comment FP), `echo $((rm -rf /))`, quoted `git commit -m "...rm -rf /..."` — port DCG `classify_command` data-span masking + wire `extractHeredocBodies` into `evaluateCommand`.
- LOW: force-push via `+refspec`; NBSP `\s` (JS is stricter — intentional). system.disk pack (device `dd`) → Phase 4.

5th reviewer "normalize-segment" output: `/private/tmp/claude-501/.../tasks/aba1bc530b1c087e1.output` (may be cleared on reboot — re-run that review lens if gone).

## Remaining phases

- **Phase 2** (task #3): policy engine (Critical pre-emptive floor, inviolable constraints, allowlist, resolveMode) + the 5-state deviation machine (deterministic only, no LLM) + steerer (block-reason + `before_agent_start` injection + context banner) + `appendEntry` persist/rehydrate. New files: `src/policy/*`, `src/state/*`. Rewrite `src/extension.ts` to wire engine→policy→state into `pi.on("tool_call")`.
- **Phase 3** (task #4): LLM grading gate (mandatory `Promise.race` timeout, cache, fail-closed-when-armed, bounded retry→HALTED), `session_start` grader-model validation, turn_end intent grading. Default grader **Gemini 3.5 Flash**, configurable. Config: JSONC parser + Effect Schema (reuse `effect` dep, NO zod) — deferred from Phase 0.
- **Phase 4** (task #5): port system/containers/k8s/infra/remote/platform/cicd packs (data + differential tests); native AST (`@ast-grep/napi`) sink detection; HALTED human-ack via `ctx.ui.custom` (TUI-only, typed phrase, no timeout — verified Pi has this surface); publish v0.2.0.

## Key decisions (from Ramiro)

- Build in this `~/dev/pi-model-guardrails` clone; toolbox only re-pins the package + re-renders `guardrails.json`.
- Grader: Gemini 3.5 Flash default, fully configurable.
- Native AST (`@ast-grep/napi`) is IN for v1.
- HALTED clears only via `ctx.ui.custom` typed-phrase confirm in TUI mode; non-TUI → terminal (verified from Pi source: `interactive-mode.ts` focus-stealing components; not model-fabricable).
- Engine DELIBERATELY DIVERGES from DCG where DCG has bugs (documented per-rule); cross-pack arbitration = strictest-wins (not DCG's first-pack-order).
