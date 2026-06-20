# @ramarivera/pi-model-guardrails

A safety extension for the [Pi coding agent](https://www.npmjs.com/package/@earendil-works/pi-coding-agent). It does two things:

1. **Deterministic destructive-command guard.** A native-TS port of the rule engine from [destructive_command_guard (DCG)](https://github.com/Dicklesworthstone/destructive_command_guard) — ~200 regex rules across 10 packs (git, filesystem, system, package managers, containers, kubernetes, infrastructure, remote, platform, ci/cd) that block catastrophic shell commands (`rm -rf ~`, `git reset --hard`, `kubectl delete --all`, `docker compose down -v`, …) before they run.
2. **Inviolable-constraint policy + a deviation state machine.** A project declares constraints it must never violate. When a deviation is detected, the session arms a state machine that routes **every** subsequent tool call through a non-deterministic LLM grader until the model has *provably* steered back on track — and won't silently backslide.

The deterministic guard is the hard floor: it cannot be downgraded by config or talked around by the model. The policy + grader layers sit on top to catch the softer "the model is drifting off the rails" failure mode that pattern rules alone can't see.

## How it works

Every `bash` tool call flows through one pipeline:

```
command
  │
  ▼
┌──────────────────────────────────────────────────────────┐
│ 1. Engine (deterministic)                                 │
│    normalize → candidate packs → regex match              │
│    + Tier-3 indirection resolution (x=rm; $x -rf ~)       │
│    → strictest decision wins                               │
└──────────────────────────────────────────────────────────┘
  │  EngineDecision (allow / warn / deny + severity)
  ▼
┌──────────────────────────────────────────────────────────┐
│ 2. Policy engine                                          │
│    Critical / inviolable floor (config CANNOT downgrade)  │
│    > per-rule override > allowlist > defaultMode > engine  │
└──────────────────────────────────────────────────────────┘
  │  Verdict
  ▼
┌──────────────────────────────────────────────────────────┐
│ 3. Deviation state machine                                │
│    COMPLIANT → WATCH → GATED → RECOVERING → HALTED         │
└──────────────────────────────────────────────────────────┘
  │  if armed & call looks clean → "gate-required"
  ▼
┌──────────────────────────────────────────────────────────┐
│ 4. LLM grader (only while armed)                          │
│    grades the call vs the active constraints + recent      │
│    actions; a clean grade advances recovery, a dirty       │
│    grade holds the gate. Fails TOWARD the gate.            │
└──────────────────────────────────────────────────────────┘
```

In a clean (`COMPLIANT`) session the grader never runs — calls are adjudicated by the deterministic engine alone, with effectively zero overhead. The grader only wakes up once the session is armed.

### The deviation state machine

| State | Meaning |
|-------|---------|
| `COMPLIANT` | Normal. Deterministic guard only; no grading. |
| `WATCH` | A soft signal fired. Mutating calls start getting graded. |
| `GATED` | A deviation is confirmed. **Every** call is graded before it runs. |
| `RECOVERING` | The model is producing clean graded calls; counting consecutive clean calls toward recovery. |
| `HALTED` | An **inviolable / critical** constraint was hit. Terminal for the model — no tool call can clear it. |

Properties that hold by construction:

- **Strictest-wins merge** — parallel/competing signals never soften the state.
- **Consecutive (not cumulative) recovery** — one dirty call resets the recovery streak.
- **Grade-immunity of the hard floor** — a clean LLM grade can *never* rescue a deterministically-denied command.
- **Fail-toward-gate** — grader timeout, crash, or malformed output holds the gate rather than waving the call through.
- **Resume-safe** — state is persisted to a session entry and rehydrated on resume/fork; a `stateEpoch` defends against a fork "resetting" an armed session.

### Recovering from `HALTED`

`HALTED` is deliberately terminal **for the model**: an inviolable-constraint breach cannot be cleared by any tool call, graded or not. The escape hatch is a human:

```
/guardrails-clear-halt
```

A human types this slash command in the Pi TUI. It shows what was violated and requires an interactive y/n confirmation before clearing the halt back to `COMPLIANT`. It is gated on an interactive UI (it refuses to clear blind in RPC/print mode), and the model cannot reach it — slash commands originate in the human input editor, never in the model's tool-call stream.

### Tier-3 indirection resolution

The regex packs match on literal command text, so one level of shell indirection can hide a sink:

```sh
x=rm;  $x -rf ~                 # variable indirection
alias d=rm;  d -rf ~            # alias expansion
```

The engine resolves these structurally (a bounded, quote-aware pure-TS pass) and re-runs the *same* rules on the expansion, so an aliased `rm -rf` is caught by the very rule that catches a bare `rm -rf`. It is fail-open *to the regex engine* — on any parsing surprise it simply defers, so it can only **add** detection, never remove the baseline. Interprocedural function-wrapper dataflow and `eval`/base64 decoding are out of scope by design.

> This is the "native structural analysis" layer, implemented in pure TS rather than via `@ast-grep/napi`: ast-grep's napi binding has no built-in Bash grammar, and a per-platform native grammar binary that can fail to load is the wrong dependency for a guard that must always load.

## Configuration

Config is layered: a global file is merged with a per-project file (project wins). Both are optional — with no config you get the deterministic guard with sensible defaults.

- **Global:** `~/.pi/agent/guardrails.json` (or `$PI_CODING_AGENT_DIR/guardrails.json`, or `$PI_MODEL_GUARDRAILS_CONFIG`)
- **Project:** `<cwd>/.pi/guardrails.json` (JSONC — comments allowed)

```jsonc
{
  // Pin which constraints can NEVER be downgraded by config or allowlist.
  "policy": {
    "defaultMode": "warn",        // deny | warn | log | allow
    "inviolable": ["no-history-rewrite"],
    "rules": {                    // override a specific engine rule's mode ("<pack.id>:<rule-name>")
      "core.git:reset-hard": "deny"
    },
    "constraints": [
      {
        "id": "no-history-rewrite",
        "title": "Never rewrite shared git history",
        "statement": "Do not force-push or hard-reset shared branches.",
        "severity": "inviolable",          // inviolable | critical | high | medium | low
        "allowlistable": false,
        "appliesWhen": "branch is shared",
        "requiredBehavior": "Ask the human to rebase locally instead.",
        "detect": { "ruleIds": ["core.git:reset-hard"], "regex": "push\\s+--force" }
      }
    ],
    "allowlist": [
      { "rule": "core.filesystem:rm-rf-general", "reason": "scratch dir cleanup", "ttl": 3600, "paths": ["/tmp/build"] }
    ]
  },

  // The degraded-mode grader. Defaults shown; secrets come from env, never inline.
  "grader": {
    "enabled": true,
    "model": "gemini-3.5-flash",
    "fallbackModel": null,
    "apiKeyEnv": "GEMINI_API_KEY",   // read process.env[...] — do NOT inline keys
    "baseUrlEnv": null,
    "timeoutMs": 8000,
    "maxTokens": 512,
    "maxRetries": 1,
    "temperature": 0.1,
    "cache": true
  },

  // Deviation state-machine tuning (defaults are sensible).
  "machine": {
    "watchCleanStreak": 2,
    "gatedCleanStreak": 3,
    "recoveringWatermark": 1,
    "cooldownTurns": 2,
    "haltRequiresHumanAck": true
  },

  // Optional model gating + telemetry.
  "modelWhitelist": [],
  "modelBlacklist": [],
  "observability": { "enabled": true, "logFile": ".pi/model-guardrails/events.jsonl" }
}
```

Notes:

- The grader is **on by default**. If it is enabled but no model/key can be resolved, the gate **fails closed** (armed sessions block gated calls) and the extension warns loudly at session start.
- `apiKeyEnv` / `baseUrlEnv` name environment variables; the key/URL are read from `process.env` at load. Never put a secret in the file.
- `allowlistable: false` on a constraint forbids ever allowlisting around it. Wildcard allowlist entries require `riskAcknowledged: true`.

## Install

```sh
pi install npm:@ramarivera/pi-model-guardrails
```

## Source map

| Path | Responsibility |
|------|----------------|
| `src/engine/` | Deterministic DCG-port engine: `normalize`, `matcher`, `evaluate`, `rm-parser`, `indirection`, `registry`, `packs/*` |
| `src/policy/` | Inviolable-constraint policy engine (`resolvePolicy`) |
| `src/state/` | Deviation state machine (`transition`, `clearHalt`) |
| `src/grade.ts` | LLM grader: prompt, timeout, retry, cache, fail-toward-gate |
| `src/guard.ts` | Pure composition: engine → policy → state machine |
| `src/extension.ts` | Pi wiring: event handlers, state persistence, steering injection, `/guardrails-clear-halt` |
| `src/config.ts` | Layered JSONC config loader |

## Local development

This checkout is live-enabled for Pi through `.pi/extensions/model-guardrails/index.ts`, which imports `src/index.ts` → `src/extension.ts`. Tests, the package entrypoint, and manual Pi runs all load the same symbol, so behavior does not drift.

```sh
npm install
npm run check       # biome + tsc
npm test            # unit suite
npm run test:e2e    # loads through the live .pi shim
npm run pack:dry-run
```

## Publishing

Publishing uses GitHub Actions trusted publishing (`.github/workflows/publish.yml`); no `NPM_TOKEN` required. Configure npm trusted publishing for `ramarivera/pi-model-guardrails` before the first publish.

## Credits

The deterministic rule engine is a faithful native-TS port of [destructive_command_guard](https://github.com/Dicklesworthstone/destructive_command_guard) by Jeffrey Emanuel. The policy engine, deviation state machine, LLM grading gate, and Tier-3 indirection resolver are additions specific to this extension.
