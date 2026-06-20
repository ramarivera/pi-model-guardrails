import { randomUUID } from "node:crypto";
import { appendFile, mkdir } from "node:fs/promises";
import { dirname, isAbsolute, join } from "node:path";
import { Effect, Schema } from "effect";
import type { GuardrailsObservabilityConfig } from "./types.ts";

export class GuardrailsTelemetryWriteError extends Schema.TaggedError<GuardrailsTelemetryWriteError>()(
  "GuardrailsTelemetryWriteError",
  {
    message: Schema.String,
    logFile: Schema.String,
    cause: Schema.optional(Schema.String),
  },
) {}

export type GuardrailsTelemetryTags = Record<string, unknown>;

export interface GuardrailsTelemetryEvent {
  readonly timestamp: string;
  readonly traceId: string;
  readonly spanId?: string;
  readonly parentSpanId?: string;
  readonly kind: "event" | "span_start" | "span_end" | "span_error";
  readonly name: string;
  readonly durationMs?: number;
  readonly tags?: GuardrailsTelemetryTags;
  readonly error?: {
    readonly name: string;
    readonly message: string;
    readonly stack?: string;
  };
}

export interface GuardrailsTelemetry {
  readonly traceId: string;
  readonly enabled: boolean;
  readonly logFile?: string;
  logEvent(name: string, tags?: GuardrailsTelemetryTags): Promise<void>;
  runSpan<A>(
    name: string,
    tags: GuardrailsTelemetryTags | undefined,
    run: () => A | Promise<A>,
  ): Promise<A>;
  /**
   * Read back the most recent telemetry events from an in-memory ring buffer.
   * This is the read path the v0.1.7 telemetry lacked (it was write-only). The
   * deviation state machine uses it for decision traces + back-on-track checks.
   */
  recent(limit?: number): GuardrailsTelemetryEvent[];
}

/** Bounded in-memory event history kept per telemetry instance. */
const RING_BUFFER_SIZE = 500;

export function createNoopTelemetry(): GuardrailsTelemetry {
  const traceId = randomUUID();
  return {
    traceId,
    enabled: false,
    async logEvent() {},
    async runSpan(_name, _tags, run) {
      return await run();
    },
    recent: () => [],
  };
}

export function createTelemetry(
  cwd: string,
  config: GuardrailsObservabilityConfig | undefined,
): GuardrailsTelemetry {
  const enabled = config?.enabled ?? true;
  const traceId = randomUUID();
  const logFile = resolveLogFile(cwd, config?.logFile);

  if (!enabled) {
    return createNoopTelemetry();
  }

  // In-memory ring buffer so the guard can READ BACK recent events (decision
  // traces, state transitions). v0.1.7's telemetry was write-only — appended to
  // a JSONL nothing read — which is why it had no observable value. Bounded;
  // oldest entries drop.
  const ring: GuardrailsTelemetryEvent[] = [];
  const record = async (
    event: Omit<GuardrailsTelemetryEvent, "timestamp" | "traceId">,
  ): Promise<void> => {
    const full: GuardrailsTelemetryEvent = {
      ...event,
      timestamp: new Date().toISOString(),
      traceId,
    };
    ring.push(full);
    if (ring.length > RING_BUFFER_SIZE) {
      ring.splice(0, ring.length - RING_BUFFER_SIZE);
    }
    await Effect.runPromise(
      writeTelemetryEvent(logFile, full).pipe(
        Effect.catchAll((error) =>
          Effect.sync(() => {
            console.warn("[guardrails] telemetry write failed:", error);
          }),
        ),
      ),
    );
  };

  return {
    traceId,
    enabled,
    logFile,
    recent(limit?: number) {
      return limit && limit > 0 ? ring.slice(-limit) : ring.slice();
    },
    async logEvent(name, tags) {
      await record({ kind: "event", name, tags: sanitizeTags(tags) });
    },
    async runSpan(name, tags, run) {
      const spanId = randomUUID();
      const startedAt = performance.now();
      await record({
        kind: "span_start",
        name,
        spanId,
        tags: sanitizeTags(tags),
      });

      try {
        const result = await run();
        await record({
          kind: "span_end",
          name,
          spanId,
          durationMs: Math.round((performance.now() - startedAt) * 1000) / 1000,
          tags: sanitizeTags(tags),
        });
        return result;
      } catch (error) {
        await record({
          kind: "span_error",
          name,
          spanId,
          durationMs: Math.round((performance.now() - startedAt) * 1000) / 1000,
          tags: sanitizeTags(tags),
          error: serializeError(error),
        });
        throw error;
      }
    },
  };
}

export function writeTelemetryEvent(
  logFile: string,
  event: GuardrailsTelemetryEvent,
): Effect.Effect<void, GuardrailsTelemetryWriteError> {
  return Effect.gen(function* () {
    yield* Effect.annotateCurrentSpan({
      "guardrails.event": event.name,
      "guardrails.kind": event.kind,
      "guardrails.trace_id": event.traceId,
      "guardrails.log_file": logFile,
    });
    yield* Effect.tryPromise({
      try: async () => {
        await mkdir(dirname(logFile), { recursive: true });
        await appendFile(logFile, `${JSON.stringify(event)}\n`, "utf8");
      },
      catch: (cause) =>
        new GuardrailsTelemetryWriteError({
          message: "Failed to write guardrails telemetry event",
          logFile,
          cause: cause instanceof Error ? cause.message : String(cause),
        }),
    });
  }).pipe(Effect.withSpan(`GuardrailsTelemetry.write.${event.name}`));
}

export function resolveLogFile(
  cwd: string,
  configuredPath: string | undefined,
): string {
  const file = configuredPath ?? ".pi/model-guardrails/events.jsonl";
  return isAbsolute(file) ? file : join(cwd, file);
}

export function serializeError(
  error: unknown,
): GuardrailsTelemetryEvent["error"] {
  if (error instanceof Error) {
    return {
      name: error.name,
      message: error.message,
      stack: error.stack,
    };
  }

  return {
    name: "NonErrorThrown",
    message: String(error),
  };
}

function sanitizeTags(
  tags: GuardrailsTelemetryTags | undefined,
): GuardrailsTelemetryTags | undefined {
  if (!tags) return undefined;

  return Object.fromEntries(
    Object.entries(tags).map(([key, value]) => [key, sanitizeValue(value)]),
  );
}

function sanitizeValue(value: unknown): unknown {
  if (typeof value === "string") {
    return value.length > 2000 ? `${value.slice(0, 2000)}…[truncated]` : value;
  }

  if (Array.isArray(value)) {
    return value.map(sanitizeValue);
  }

  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>).map(([key, nested]) => [
        key,
        sanitizeValue(nested),
      ]),
    );
  }

  return value;
}
