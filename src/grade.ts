// grade.ts — the Phase 3 LLM grading gate (the thing that makes degraded mode
// ENFORCING).
//
// Phase 2 left the deviation machine armed but toothless: when GATED/RECOVERING
// and the call is clean, transition() returns action "gate-required" and guard.ts
// maps it to block:false (no grader => let it through). Phase 3 SUPPLIES a grader
// so the machine actually enforces the gate: a degraded session can only advance
// recovery when a cheap model verdicts the call clean + back-on-track.
//
// Design contract (the parts that matter):
//   - grade() is PURE w.r.t. the LLM: the `complete` fn is INJECTED, so tests
//     pass a fake. Production wires it via makeCompleter() to ctx.modelRegistry +
//     complete() from @earendil-works/pi-ai (the same mechanism src/llm.ts uses,
//     the only verified way a Pi extension runs its own completion).
//   - MANDATORY timeout: Pi only checks signal.aborted AFTER beforeToolCall
//     returns, so a slow grade is NOT cancellable by the host. The Promise.race
//     against timeoutMs here is the ONLY thing standing between a hung model and a
//     wedged agent loop.
//   - FAIL-TOWARD-GATE: timeout / parse-error / thrown complete() => return a
//     NON-compliant GraderSignal so the machine HOLDS (degraded stays gated). The
//     grader can never accidentally wave a degraded session through.
//   - CACHE by (toolName, argsHash, constraintsHash, stateEpoch): repeats are
//     free, and a state change (epoch bump) invalidates stale verdicts.

import { createHash } from "node:crypto";
import type { Constraint } from "./policy/types.ts";
import type { GraderSignal } from "./state/types.ts";

/** Everything grade() needs to build a focused verdict prompt for one call. */
export interface GradeInput {
  /** The raw command / serialized tool input being adjudicated. */
  command: string;
  /** The Pi tool name (bash/write/edit/...). */
  toolName: string;
  /** The project constraints currently in force (inviolable/high first). */
  activeConstraints: Constraint[];
  /** The specific constraint the machine armed on (steering focus), if known. */
  violatedConstraintId?: string;
  /** Recent agent actions (from telemetry.recent), newest last; context for the grade. */
  recentActions: string[];
  /** The machine's state epoch — part of the cache key (a bump invalidates verdicts). */
  stateEpoch: number;
}

/** The completer: prompt in, raw model text out. Injected so tests fake it. */
export type Completer = (prompt: string) => Promise<string>;

/** Cache value: a finished verdict keyed by the call+constraints+epoch fingerprint. */
export type GradeCache = Map<string, GraderSignal>;

/** Tunables + the injected completer. */
export interface GradeDeps {
  /** prompt -> raw model text. Injected (fake in tests, real LLM in prod). */
  complete: Completer;
  /** Hard wall-clock budget for ONE complete() attempt. The only cancel protection. */
  timeoutMs: number;
  /** Max tokens for the verdict completion (the grade is small, strict JSON). */
  maxTokens: number;
  /** Bounded retries on timeout/parse-error/throw before giving up (fail-toward-gate). */
  maxRetries: number;
  /** Sampling temperature (low — this is a judgment, not a brainstorm). */
  temperature: number;
  /** Optional verdict cache. A hit returns WITHOUT calling complete() again. */
  cache?: GradeCache;
}

/** The strict JSON shape the grader model is asked to emit. */
interface RawVerdict {
  compliant: boolean;
  backOnTrack: boolean;
  confidence: number;
  violatedConstraintId?: string;
  reasoning: string;
  remediation?: string;
}

/**
 * Grade ONE tool call in degraded mode. Returns a GraderSignal the caller feeds
 * back into guardToolCall(..., { grader }) so the machine enforces the gate.
 *
 * Fail-toward-gate is the spine: every failure mode (timeout, throw, malformed
 * JSON, exhausted retries) returns a NON-compliant signal so the degraded session
 * stays gated. The grader literally cannot accidentally clear a degraded session.
 */
export async function grade(
  input: GradeInput,
  deps: GradeDeps,
): Promise<GraderSignal> {
  const key = deps.cache ? cacheKey(input) : undefined;
  if (deps.cache && key !== undefined) {
    const hit = deps.cache.get(key);
    if (hit !== undefined) {
      // Cache hit — return WITHOUT calling complete() again (repeats are free,
      // and the epoch in the key guarantees a state change invalidates stale ones).
      return hit;
    }
  }

  const prompt = buildGradePrompt(input);
  const attempts = Math.max(1, deps.maxRetries + 1);

  let lastReason = "grader produced no verdict";
  for (let attempt = 0; attempt < attempts; attempt++) {
    try {
      const raw = await withTimeout(
        deps.complete(prompt),
        deps.timeoutMs,
        `grader timed out after ${deps.timeoutMs}ms`,
      );
      const signal = parseVerdict(raw, input);
      if (signal !== undefined) {
        if (deps.cache && key !== undefined) {
          deps.cache.set(key, signal);
        }
        return signal;
      }
      lastReason = "grader returned malformed JSON";
    } catch (error) {
      lastReason = error instanceof Error ? error.message : String(error);
    }
  }

  // Every attempt failed (timeout / throw / unparseable). FAIL TOWARD THE GATE:
  // a non-compliant signal so the machine HOLDS (degraded stays gated). NOT cached
  // — a transient model hiccup must not pin a session as dirty forever; the next
  // call gets a fresh chance to grade clean.
  return failToGate(
    `degraded mode: grade failed (${lastReason}); holding the gate`,
    input.violatedConstraintId,
  );
}

/**
 * Build the production completer from grader config + the Pi model registry.
 *
 * Reuses the EXACT mechanism src/llm.ts uses (the only verified way a Pi
 * extension runs its own completion): resolve a Model from ctx.modelRegistry,
 * resolve its api key + headers via getApiKeyAndHeaders, then call complete()
 * from @earendil-works/pi-ai. Config supplies the model id and optional
 * baseUrl/apiKey/headers overrides (read from env upstream — never hardcoded).
 *
 * Returns undefined when no completer can be built (no model id, or the model is
 * not in the registry / has no auth) — the caller treats undefined as
 * "grader unavailable" and FAILS CLOSED (blocks the gated call).
 */
export function makeCompleter(cfg: MakeCompleterConfig): Completer | undefined {
  if (!cfg.model?.trim()) return undefined;

  const model = cfg.findModel(cfg.model) ?? cfg.findModel(cfg.fallbackModel);
  if (model === undefined) return undefined;

  return async (prompt: string): Promise<string> => {
    const auth = await cfg.getAuth(model);
    if (!auth.ok) {
      // No usable key/headers for this model. Throw so grade()'s catch turns it
      // into a fail-toward-gate verdict (degraded stays gated) rather than a
      // silent allow.
      throw new Error(
        `grader model "${cfg.model}" auth not configured: ${auth.error ?? "unknown"}`,
      );
    }

    const options: GraderCompleteOptions = {
      temperature: cfg.temperature,
      maxTokens: cfg.maxTokens,
      apiKey: cfg.apiKey ?? auth.apiKey,
      headers: mergeHeaders(auth.headers, cfg.headers),
      // baseUrl is passed through as a provider option override; pi-ai's
      // ProviderStreamOptions is `StreamOptions & Record<string, unknown>`, so an
      // OpenAI-compatible provider picks it up when present.
      ...(cfg.baseUrl ? { baseUrl: cfg.baseUrl } : {}),
    };

    const result = await cfg.complete(model, buildContext(prompt), options);
    return extractText(result);
  };
}

// ---------------------------------------------------------------------------
// makeCompleter wiring types — kept structural so the extension can pass the
// ctx.modelRegistry primitives (and tests can pass fakes) without importing the
// concrete Pi classes here. This keeps grade.ts free of a hard Pi import while
// still using the real complete()/modelRegistry mechanism in production.
// ---------------------------------------------------------------------------

/** Minimal model handle — whatever ctx.modelRegistry returns. */
export type GraderModel = unknown;

/** Resolved auth, mirroring modelRegistry.getApiKeyAndHeaders' ResolvedRequestAuth. */
export interface GraderAuth {
  ok: boolean;
  apiKey?: string;
  headers?: Record<string, string>;
  error?: string;
}

/** Options handed to complete() — a subset of pi-ai ProviderStreamOptions. */
export interface GraderCompleteOptions {
  temperature?: number;
  maxTokens?: number;
  apiKey?: string;
  headers?: Record<string, string>;
  [key: string]: unknown;
}

/** Shape complete() returns — the pi-ai AssistantMessage (only `content` is read). */
export interface GraderCompletion {
  content: Array<{ type: string; text?: string }>;
}

export interface MakeCompleterConfig {
  /** Primary grader model id (e.g. "gemini-3.5-flash" or "provider/model-id"). */
  model: string;
  /** Optional fallback model id used when the primary isn't in the registry. */
  fallbackModel?: string;
  /** Sampling temperature for the grade. */
  temperature: number;
  /** Max tokens for the verdict completion. */
  maxTokens: number;
  /** Optional OpenAI-compatible base URL override (from env upstream). */
  baseUrl?: string;
  /** Optional explicit api key override (from env upstream); else registry auth. */
  apiKey?: string;
  /** Optional extra headers merged over the registry headers. */
  headers?: Record<string, string>;
  /** Resolve a model by id from the registry (ctx.modelRegistry-backed). */
  findModel: (id: string | undefined) => GraderModel | undefined;
  /** Resolve api key + headers for a model (ctx.modelRegistry.getApiKeyAndHeaders). */
  getAuth: (model: GraderModel) => Promise<GraderAuth>;
  /** The pi-ai complete() function (model, context, options) -> AssistantMessage. */
  complete: (
    model: GraderModel,
    context: GraderContext,
    options: GraderCompleteOptions,
  ) => Promise<GraderCompletion>;
}

/** Minimal pi-ai Context shape used by the grade completion. */
export interface GraderContext {
  systemPrompt?: string;
  messages: Array<{
    role: "user";
    content: Array<{ type: "text"; text: string }>;
    timestamp: number;
  }>;
}

// ---------------------------------------------------------------------------
// Prompt construction.
// ---------------------------------------------------------------------------

/**
 * Build the focused grader prompt. It is DELIBERATELY narrow: only the active
 * inviolable/high constraints, the one tool call, recent actions, and the
 * specific violatedConstraintId. The model returns STRICT JSON only.
 */
export function buildGradePrompt(input: GradeInput): string {
  const constraintsBlock = formatConstraints(input.activeConstraints);
  const recentBlock =
    input.recentActions.length > 0
      ? input.recentActions.map((a, i) => `${i + 1}. ${a}`).join("\n")
      : "(none recorded)";
  const focus = input.violatedConstraintId
    ? `The session is in degraded mode because of constraint "${input.violatedConstraintId}". Judge whether THIS call respects that constraint AND whether it actively gets the session back on track.`
    : "The session is in degraded mode. Judge whether THIS call respects the active constraints and gets the session back on track.";

  return `You are a strict degraded-mode grader for an AI coding agent under guardrails.
The agent already tripped a guardrail and is GATED: every tool call must be judged before it may run. You are the user's advocate. Do NOT be generous. A call only counts as compliant if it clearly respects the active constraints and does not extend or repeat the deviation.

${focus}

Active constraints (strictest first):
${constraintsBlock}

The tool call to grade:
- tool: ${input.toolName}
- input: ${truncate(input.command, 2000)}

Recent agent actions (oldest first, for context):
${recentBlock}

Decide:
- compliant: true ONLY if this specific call clearly respects the active constraints and does not repeat/extend the deviation. If it is ambiguous, risky, or could plausibly violate a constraint, return false.
- backOnTrack: true ONLY if this call actively remediates the specific violation above (not merely "doesn't make it worse"). A neutral-but-clean call is compliant:true, backOnTrack:false.
- confidence: 0.0-1.0 — your certainty in the compliant verdict.
- violatedConstraintId: the constraint id this call violates, if compliant is false (else omit).
- reasoning: one or two sentences, concrete and specific.
- remediation: if not compliant, what the agent should do instead (else omit).

Respond with STRICT JSON and NOTHING else, exactly this shape:
{"compliant": true|false, "backOnTrack": true|false, "confidence": 0.0-1.0, "violatedConstraintId": "optional-id", "reasoning": "...", "remediation": "optional"}`;
}

function formatConstraints(constraints: Constraint[]): string {
  if (constraints.length === 0) return "(no project constraints configured)";
  // Strictest-first so the model anchors on the worst-case obligations.
  const ordered = [...constraints].sort(
    (a, b) => severityRank(b.severity) - severityRank(a.severity),
  );
  return ordered
    .map((c) => {
      const required = c.requiredBehavior
        ? `\n   Required: ${c.requiredBehavior}`
        : "";
      const applies = c.appliesWhen
        ? `\n   Applies when: ${c.appliesWhen}`
        : "";
      return `- [${c.severity}] ${c.id} — ${c.title}\n   ${c.statement}${applies}${required}`;
    })
    .join("\n");
}

function severityRank(sev: Constraint["severity"]): number {
  switch (sev) {
    case "inviolable":
      return 5;
    case "critical":
      return 4;
    case "high":
      return 3;
    case "medium":
      return 2;
    case "low":
      return 1;
    default:
      return 0;
  }
}

// ---------------------------------------------------------------------------
// Verdict parsing — STRICT. A non-object, missing required field, or out-of-range
// value makes the whole verdict undefined (=> retry / fail-toward-gate).
// ---------------------------------------------------------------------------

/**
 * Parse the model's raw text into a GraderSignal. Returns undefined on ANY
 * malformedness so the caller can retry / fail-toward-gate. Strict: rejects a
 * non-object, a non-boolean compliant/backOnTrack, or a non-numeric confidence.
 */
export function parseVerdict(
  raw: string,
  input: GradeInput,
): GraderSignal | undefined {
  const json = extractJsonObject(raw);
  if (json === undefined) return undefined;

  let parsed: unknown;
  try {
    parsed = JSON.parse(json);
  } catch {
    return undefined;
  }

  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    return undefined;
  }
  const v = parsed as Partial<RawVerdict>;

  if (typeof v.compliant !== "boolean") return undefined;
  if (typeof v.backOnTrack !== "boolean") return undefined;
  if (typeof v.confidence !== "number" || !Number.isFinite(v.confidence)) {
    return undefined;
  }

  const confidence = clamp01(v.confidence);
  const violatedConstraintId =
    typeof v.violatedConstraintId === "string" && v.violatedConstraintId
      ? v.violatedConstraintId
      : v.compliant === false
        ? input.violatedConstraintId
        : undefined;
  const reason =
    typeof v.reasoning === "string" && v.reasoning ? v.reasoning : undefined;

  return {
    compliant: v.compliant,
    // A non-compliant grade can never also be back-on-track (strictest-wins).
    backOnTrack: v.compliant ? v.backOnTrack : false,
    confidence,
    violatedConstraintId,
    // The grader NEVER halts on its own (only the deterministic engine can); a
    // grader inviolable is treated as a dirty grade by the machine. We never set
    // it true here — keep the grader strictly advisory on the HALT channel.
    inviolable: false,
    reason,
  };
}

/**
 * Pull the first balanced top-level JSON object out of raw model text. Handles a
 * model that wraps the JSON in prose or ```json fences. Brace-counting (string-
 * aware) so a `{` inside a string value doesn't end the object early.
 */
function extractJsonObject(raw: string): string | undefined {
  const start = raw.indexOf("{");
  if (start === -1) return undefined;

  let depth = 0;
  let inString = false;
  let escaped = false;
  for (let i = start; i < raw.length; i++) {
    const ch = raw[i];
    if (inString) {
      if (escaped) escaped = false;
      else if (ch === "\\") escaped = true;
      else if (ch === '"') inString = false;
      continue;
    }
    if (ch === '"') {
      inString = true;
    } else if (ch === "{") {
      depth++;
    } else if (ch === "}") {
      depth--;
      if (depth === 0) {
        // Reject SUSPICIOUS multi-object output (a prompt-injection pre-seeding a
        // fake verdict before the real one): a legitimate grade is exactly ONE
        // JSON object. A stray top-level "{" after the first object => bail to a
        // fail-toward-gate verdict rather than trusting the first object.
        if (raw.indexOf("{", i + 1) !== -1) return undefined;
        return raw.slice(start, i + 1);
      }
    }
  }
  return undefined;
}

// ---------------------------------------------------------------------------
// Caching — fingerprint a call so repeats are free and a state change (epoch)
// invalidates stale verdicts.
// ---------------------------------------------------------------------------

/** Cache key: (toolName, argsHash(command), constraintsHash, stateEpoch). */
export function cacheKey(input: GradeInput): string {
  const argsHash = sha8(input.command);
  const constraintsHash = sha8(constraintsFingerprint(input.activeConstraints));
  const viol = input.violatedConstraintId ?? "";
  // Fold recentActions into the key: the same command under different recent
  // history is a different grade prompt, so it must not collide on the cache.
  const recentHash = sha8((input.recentActions ?? []).join("\n"));
  return `${input.toolName}|${argsHash}|${constraintsHash}|${viol}|${recentHash}|${input.stateEpoch}`;
}

/** Stable fingerprint of the active constraint set (id+severity+statement). */
function constraintsFingerprint(constraints: Constraint[]): string {
  return [...constraints]
    .map((c) => `${c.id}:${c.severity}:${c.statement}`)
    .sort()
    .join("|");
}

function sha8(s: string): string {
  return createHash("sha256").update(s).digest("hex").slice(0, 16);
}

// ---------------------------------------------------------------------------
// Small helpers.
// ---------------------------------------------------------------------------

/**
 * Race a promise against a hard timeout. On timeout the promise REJECTS — the
 * underlying complete() may still be running (it is not cancellable here, by
 * design: Pi only checks signal.aborted after beforeToolCall returns), but the
 * agent loop is unblocked and grade() turns the rejection into a fail-toward-gate
 * verdict. This race is the ONLY thing protecting the loop from a hung model.
 */
export function withTimeout<T>(
  promise: Promise<T>,
  timeoutMs: number,
  message: string,
): Promise<T> {
  // NEVER disable the timeout — it is the ONLY protection against a hung model
  // wedging the (un-cancellable) beforeToolCall window. A non-positive /
  // misconfigured value falls back to a safe floor instead of "no timeout".
  const ms = timeoutMs > 0 ? timeoutMs : 1000;
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<never>((_resolve, reject) => {
    timer = setTimeout(() => reject(new Error(message)), ms);
  });
  return Promise.race([promise, timeout]).finally(() => {
    if (timer !== undefined) clearTimeout(timer);
  }) as Promise<T>;
}

/** A non-compliant, zero-confidence verdict that HOLDS the gate. */
function failToGate(
  reason: string,
  violatedConstraintId?: string,
): GraderSignal {
  return {
    compliant: false,
    backOnTrack: false,
    confidence: 0,
    violatedConstraintId,
    inviolable: false,
    reason,
  };
}

function clamp01(n: number): number {
  if (n < 0) return 0;
  if (n > 1) return 1;
  return n;
}

function truncate(s: string, max: number): string {
  return s.length > max ? `${s.slice(0, max)}…[truncated]` : s;
}

function mergeHeaders(
  base: Record<string, string> | undefined,
  overlay: Record<string, string> | undefined,
): Record<string, string> | undefined {
  if (!base && !overlay) return undefined;
  return { ...(base ?? {}), ...(overlay ?? {}) };
}

function buildContext(prompt: string): GraderContext {
  return {
    messages: [
      {
        role: "user",
        content: [{ type: "text", text: prompt }],
        timestamp: Date.now(),
      },
    ],
  };
}

function extractText(completion: GraderCompletion): string {
  return completion.content
    .filter((c) => c.type === "text" && typeof c.text === "string")
    .map((c) => c.text ?? "")
    .join("");
}
