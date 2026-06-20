// Deviation state machine — the centerpiece of Layer 2 (deterministic-only).
//
// `COMPLIANT → WATCH → GATED → RECOVERING → HALTED`, ported from the design's
// "Deviation state machine" section. No LLM calls anywhere: armed states only
// EXPOSE a "gate-required" action; the caller runs the actual grade (Phase 3)
// and feeds the result back as a GraderSignal on the next transition.
//
// Invariants enforced here (design "Anti-backslide"):
//   - strictest-wins merge of deterministic + grader (NEVER averaged).
//   - consecutive-not-cumulative recovery streak: ANY dirty grade resets it to 0.
//   - alternating clean/dirty NEVER recovers (corollary of the reset).
//   - inviolable / Critical => HALTED, grade-immune; HALTED is terminal and exits
//     ONLY via clearHalt(humanAck) (no model-callable, no auto, no grader bypass).
//   - cooldown after recovery keeps the gate hot; immediate relapse re-arms GATED.
//   - bumpEpoch() on every arming/recovery transition (resume/fork can't reset).
//   - trivial/read-only calls don't advance the recovery streak (nonTrivialOnly).

import type {
  CallMeta,
  DeterministicSignal,
  GraderSignal,
  MachineConfig,
  PersistedState,
  TransitionInput,
  TransitionResult,
} from "./types.ts";

/** Fresh, fully-compliant state. */
export function initialState(): PersistedState {
  return {
    state: "COMPLIANT",
    cleanStreak: 0,
    stateEpoch: 0,
    cooldownRemaining: 0,
  };
}

/** Default tunables (design defaults). */
export function defaultMachineConfig(): MachineConfig {
  return {
    watchCleanStreak: 2,
    gatedCleanStreak: 3,
    recoveringWatermark: 1,
    cooldownTurns: 2,
    gateOnlyMutatingInWatch: true,
    nonTrivialOnly: true,
    haltRequiresHumanAck: true,
  };
}

/**
 * The ONLY exit from HALTED. Requires an explicit out-of-band human ack token
 * (`humanAck: true`, supplied by a focus-stealing TUI confirm — never the model).
 * Returns a fresh COMPLIANT state with a bumped epoch.
 */
export function clearHalt(
  current: PersistedState,
  humanAck: true,
): PersistedState {
  // The literal `true` type already forbids a model-fabricated falsy token at
  // compile time; the runtime guard defends against erased/`any` callers.
  if (humanAck !== true) return current;
  return {
    state: "COMPLIANT",
    cleanStreak: 0,
    violatedConstraintId: undefined,
    armedReason: undefined,
    stateEpoch: current.stateEpoch + 1, // recovery transition => bump epoch
    cooldownRemaining: 0,
  };
}

/** Pure transition: (current, signals, meta, config) -> (next, action). */
export function transition(input: TransitionInput): TransitionResult {
  const { current, deterministic, grader, meta, config } = input;

  // ---------------------------------------------------------------------------
  // 0. HALTED is terminal and grade-immune. No signal, clean or dirty, exits it.
  //    Exit is ONLY via clearHalt(humanAck). (design: "no model-callable bypass")
  // ---------------------------------------------------------------------------
  if (current.state === "HALTED") {
    return {
      next: current,
      action: "halt",
      reason: current.armedReason ?? "Session halted by an inviolable breach.",
      steer:
        "This session is HALTED on an inviolable constraint. It cannot be " +
        "cleared by any tool call — a human must acknowledge out-of-band.",
      transitioned: false,
    };
  }

  // ---------------------------------------------------------------------------
  // 1. INVIOLABLE / CRITICAL => HALTED from ANY non-halted state. Grade-immune:
  //    deterministic inviolable OR a deterministic critical-severity hard block
  //    arms HALTED regardless of any grader signal (strictest-wins, the worst
  //    possible outcome wins). A grader "inviolable" alone does NOT halt — only
  //    the deterministic engine can (design "inviolable is grade-immune").
  // ---------------------------------------------------------------------------
  if (
    deterministic !== undefined &&
    (deterministic.inviolable ||
      (deterministic.blocked && deterministic.severity === "critical"))
  ) {
    const reason =
      deterministic.reason ??
      "Inviolable/Critical constraint breached — hard stop.";
    return {
      next: bumpEpoch({
        ...current,
        state: "HALTED",
        cleanStreak: 0,
        armedReason: reason,
        cooldownRemaining: 0,
      }),
      action: "halt",
      reason,
      steer:
        "An inviolable constraint was violated. Stop. A human must " +
        "acknowledge before this session can continue.",
      transitioned: true,
    };
  }

  // Merge the two signals strictest-wins (never averaged). `dirty` means the call
  // is NOT clean by EITHER channel (block or non-compliant grade). This strict
  // form drives GATED/RECOVERING anti-backslide — a recurring WARN never resets
  // an armed recovery streak (design: "ANY dirty grade or new block").
  const dirty = isDirty(deterministic, grader);
  // WATCH dirtiness ALSO counts a recurring soft signal as a "another deviation"
  // (design: WATCH "another deviation => GATED"); a warn is a deviation in WATCH.
  const watchDirty = dirty || deterministic?.warn === true;
  // Whether this call counts toward a recovery streak (non-trivial when configured).
  const counts = !config.nonTrivialOnly || !meta.isTrivial;

  switch (current.state) {
    case "COMPLIANT":
      return fromCompliant(current, deterministic);
    case "WATCH":
      return fromWatch(
        current,
        deterministic,
        watchDirty,
        counts,
        meta,
        config,
        grader !== undefined,
      );
    case "GATED":
      return fromGated(current, deterministic, grader, dirty, counts, config);
    case "RECOVERING":
      return fromRecovering(
        current,
        deterministic,
        grader,
        dirty,
        counts,
        config,
      );
    default: {
      // Unrecognized/corrupt persisted state — e.g. a state written by a newer
      // build and rehydrated by an older one. FAIL CLOSED: treat it as HALTED so
      // a degraded session can never silently reset to allowing (resume-safety /
      // anti-backslide). Never fall off the switch returning undefined.
      return {
        next: bumpEpoch({
          ...current,
          state: "HALTED",
          cleanStreak: 0,
          armedReason: "Unrecognized guard state — failing closed.",
          cooldownRemaining: 0,
        }),
        action: "halt",
        reason: "Unrecognized guard state; failing closed (halted).",
        steer:
          "The guard state could not be recognized; the session is halted until a human acknowledges out-of-band.",
        transitioned: true,
      };
    }
  }
}

// ---------------------------------------------------------------------------
// COMPLIANT — fail-open; the only state that allows freely.
//   - hard block (non-inviolable) => GATED (confirmed deviation).
//   - soft signal (warn)          => WATCH (one soft signal arms watch).
//   - otherwise                   => allow.
// ---------------------------------------------------------------------------
function fromCompliant(
  current: PersistedState,
  deterministic: DeterministicSignal | undefined,
): TransitionResult {
  if (deterministic?.blocked) {
    const reason = deterministic.reason ?? "Deterministic policy deny.";
    return {
      next: bumpEpoch({
        ...current,
        state: "GATED",
        cleanStreak: 0,
        armedReason: reason,
        cooldownRemaining: 0,
      }),
      action: "block",
      reason,
      steer: `Blocked: ${reason}. Every tool call is now gated until you are provably back on track.`,
      transitioned: true,
    };
  }

  if (deterministic?.warn) {
    const reason = deterministic.reason ?? "Soft policy signal.";
    // Post-recovery cooldown: a SOFT relapse within the cooldown window re-arms
    // GATED (degraded mode) instead of the gentle WATCH path — a just-recovered
    // session is treated more harshly on an immediate relapse. (A hard block
    // already arms GATED above regardless of cooldown.)
    if (current.cooldownRemaining > 0) {
      return {
        next: bumpEpoch({
          ...current,
          state: "GATED",
          cleanStreak: 0,
          armedReason: reason,
          cooldownRemaining: 0,
        }),
        action: "allow", // the warn call itself runs; subsequent calls are gated
        reason,
        steer: `Relapse during cooldown: ${reason}. Re-gated — every tool call is graded until you are provably back on track.`,
        transitioned: true,
      };
    }
    return {
      next: bumpEpoch({
        ...current,
        state: "WATCH",
        cleanStreak: 0,
        armedReason: reason,
        cooldownRemaining: 0,
      }),
      // A warn does not block the call itself; it arms WATCH for the NEXT calls.
      action: "allow",
      reason,
      steer: `Heads up: ${reason}. You are being watched; another deviation will gate every call.`,
      transitioned: true,
    };
  }

  // Clean compliant call. If we're in cooldown, tick it down but stay compliant.
  const cooldownRemaining = Math.max(0, current.cooldownRemaining - 1);
  return {
    next: { ...current, cleanStreak: 0, cooldownRemaining },
    action: "allow",
    transitioned: cooldownRemaining !== current.cooldownRemaining,
  };
}

// ---------------------------------------------------------------------------
// WATCH — engine authoritative; LLM gate on MUTATING tools only.
//   - hard block / any new deviation (dirty) => GATED.
//   - cooldown immediate relapse (dirty)      => GATED (handled by the dirty path).
//   - clean non-trivial calls accumulate; watchCleanStreak => COMPLIANT.
//   - mutating clean call => gate-required (latency-bounded WATCH grading).
//   - read-only clean call => allow.
// ---------------------------------------------------------------------------
function fromWatch(
  current: PersistedState,
  deterministic: DeterministicSignal | undefined,
  dirty: boolean,
  counts: boolean,
  meta: CallMeta,
  config: MachineConfig,
  graderPresent: boolean,
): TransitionResult {
  if (dirty) {
    const reason = deterministic?.reason ?? "Second deviation while on watch.";
    return {
      next: bumpEpoch({
        ...current,
        state: "GATED",
        cleanStreak: 0,
        armedReason: reason,
        cooldownRemaining: 0,
      }),
      action: deterministic?.blocked ? "block" : "gate-required",
      reason,
      steer: `Escalated to gated: ${reason}. Every tool call is graded until you are provably back on track.`,
      transitioned: true,
    };
  }

  // Clean call. Only non-trivial calls advance the streak (when configured).
  const nextStreak = counts ? current.cleanStreak + 1 : current.cleanStreak;

  if (nextStreak >= config.watchCleanStreak) {
    // Two clean non-trivial calls clear WATCH. Recovery transition => bump epoch,
    // and arm a short cooldown so an immediate relapse re-arms GATED.
    return {
      next: bumpEpoch({
        ...current,
        state: "COMPLIANT",
        cleanStreak: 0,
        violatedConstraintId: undefined,
        armedReason: undefined,
        cooldownRemaining: config.cooldownTurns,
      }),
      // The call that CLEARS watch has recovered the session — there is nothing
      // left to gate on it. Return allow, not the WATCH gate action.
      action: "allow",
      reason: "Cleared watch: back to compliant.",
      transitioned: true,
    };
  }

  const advanced = nextStreak !== current.cleanStreak;
  return {
    // Bump epoch on each streak advance so a repeated identical call can't be
    // served a cached grade to inflate the watch streak (the cache keys on epoch).
    next: advanced ? bumpEpoch({ ...current, cleanStreak: nextStreak }) : current,
    // A grader-confirmed clean call (graderPresent => the gate passed) is ALLOWED
    // to run; pre-grade it is gate-required (mutating) / allow (read-only).
    action: graderPresent ? "allow" : gateActionForWatch(meta, config),
    transitioned: advanced,
  };
}

/** In WATCH, gate mutating tools (gate-required), allow read-only tools. */
function gateActionForWatch(
  meta: CallMeta,
  config: MachineConfig,
): "allow" | "gate-required" {
  if (config.gateOnlyMutatingInWatch) {
    return meta.isMutating ? "gate-required" : "allow";
  }
  return "gate-required";
}

// ---------------------------------------------------------------------------
// GATED (degraded mode) — EVERY tool call awaits a grade (gate-required).
//   - new deterministic hard block => stay GATED, reset streak (re-arm).
//   - dirty grade                  => stay GATED, reset streak (anti-backslide).
//   - clean non-trivial grade      => streak++; recoveringWatermark => RECOVERING.
//   - clean trivial grade          => stay GATED, streak unchanged (no advance).
//   - no grader yet (Phase 2 / first armed call) => gate-required, hold.
// ---------------------------------------------------------------------------
function fromGated(
  current: PersistedState,
  deterministic: DeterministicSignal | undefined,
  grader: GraderSignal | undefined,
  dirty: boolean,
  counts: boolean,
  config: MachineConfig,
): TransitionResult {
  if (dirty) {
    // Either a fresh deterministic block or a non-compliant grade. Re-arm: reset
    // the streak to 0 (consecutive-not-cumulative) and stay GATED.
    const reason =
      deterministic?.reason ??
      grader?.reason ??
      "Still not aligned while gated.";
    return {
      next: { ...current, cleanStreak: 0, armedReason: reason },
      action: deterministic?.blocked ? "block" : "gate-required",
      reason,
      steer: `Still gated: ${reason}. Fix the specific violation; every call stays graded.`,
      transitioned: current.cleanStreak !== 0,
    };
  }

  // Clean. Without a grader yet (the pre-grade first pass), HOLD: "gate-required"
  // tells the caller to run the grade and re-decide with the verdict.
  if (grader === undefined) {
    return {
      next: current,
      action: "gate-required",
      reason: "Awaiting grade before this call may run.",
      transitioned: false,
    };
  }

  // Grader confirmed CLEAN => the gate PASSES, so this call is ALLOWED to run.
  // The grade IS the gate: a compliant call runs in degraded mode (only a
  // non-compliant grade / timeout / unavailable grader HOLDS it), while the
  // recovery streak advances. Trivial/read-only clean grades run but do NOT
  // advance the streak.
  if (!counts) {
    return { next: current, action: "allow", transitioned: false };
  }

  const nextStreak = current.cleanStreak + 1;
  if (nextStreak >= config.recoveringWatermark) {
    // One clean gated grade promotes to the RECOVERING staging gate. Reset the
    // streak so the full recovery streak (gatedCleanStreak) is counted fresh.
    return {
      next: bumpEpoch({
        ...current,
        state: "RECOVERING",
        cleanStreak: 0,
        violatedConstraintId:
          grader.violatedConstraintId ?? current.violatedConstraintId,
      }),
      action: "allow",
      reason: "Clean grade: call allowed, staging recovery (still grading every call).",
      transitioned: true,
    };
  }

  return {
    // Epoch bump per advance => a fresh cache key each step, so the recovery
    // streak can't be climbed by replaying one cached compliant verdict.
    next: bumpEpoch({ ...current, cleanStreak: nextStreak }),
    action: "allow",
    transitioned: true,
  };
}

// ---------------------------------------------------------------------------
// RECOVERING (staging gate) — still grades every call; lighter prompt biased to
// the violatedConstraintId. Anti-backslide is strictest here:
//   - ANY dirty grade or new block => straight back to GATED, streak reset.
//   - clean non-trivial grade      => streak++.
//   - full recovery requires: gatedCleanStreak consecutive clean non-trivial
//     grades AND grader.backOnTrack (the specific violation remediated).
//   - clean trivial grade          => stay RECOVERING, no advance.
// ---------------------------------------------------------------------------
function fromRecovering(
  current: PersistedState,
  deterministic: DeterministicSignal | undefined,
  grader: GraderSignal | undefined,
  dirty: boolean,
  counts: boolean,
  config: MachineConfig,
): TransitionResult {
  if (dirty) {
    // Backslide: any dirty grade or new block drops RECOVERING -> GATED and
    // resets the streak. This is what makes alternating clean/dirty never recover.
    const reason =
      deterministic?.reason ?? grader?.reason ?? "Relapsed during recovery.";
    return {
      next: bumpEpoch({
        ...current,
        state: "GATED",
        cleanStreak: 0,
        armedReason: reason,
      }),
      action: deterministic?.blocked ? "block" : "gate-required",
      reason,
      steer: `Recovery reset to gated: ${reason}. The clean streak is wiped; start over.`,
      transitioned: true,
    };
  }

  // Clean but no grader => HOLD (pre-grade first pass; the caller must grade).
  if (grader === undefined) {
    return {
      next: current,
      action: "gate-required",
      reason: "Awaiting grade before this call may run.",
      transitioned: false,
    };
  }

  // Grader confirmed CLEAN => the call is ALLOWED to run (the grade is the gate).
  // Trivial clean grades run but don't advance the recovery streak.
  if (!counts) {
    return { next: current, action: "allow", transitioned: false };
  }

  const nextStreak = current.cleanStreak + 1;

  // Full recovery: enough consecutive clean non-trivial grades AND the grader
  // confirms the specific violation was remediated (backOnTrack).
  if (nextStreak >= config.gatedCleanStreak && grader.backOnTrack) {
    return {
      next: bumpEpoch({
        ...current,
        state: "COMPLIANT",
        cleanStreak: 0,
        violatedConstraintId: undefined,
        armedReason: undefined,
        cooldownRemaining: config.cooldownTurns, // keep the gate hot post-recovery
      }),
      action: "allow",
      reason: "Back on track: recovered to compliant (cooldown armed).",
      transitioned: true,
    };
  }

  // Clean grade, but not yet fully recovered (streak short, or backOnTrack not
  // yet confirmed). The call still runs (clean grade => allow); recovery keeps
  // accruing and every call stays graded until COMPLIANT.
  return {
    // Epoch bump per advance => fresh cache key per recovery step (no streak
    // inflation from a replayed cached verdict).
    next: bumpEpoch({ ...current, cleanStreak: nextStreak }),
    action: "allow",
    reason:
      nextStreak >= config.gatedCleanStreak
        ? "Streak met; awaiting grader back-on-track confirmation."
        : undefined,
    transitioned: true,
  };
}

// ---------------------------------------------------------------------------
// Helpers.
// ---------------------------------------------------------------------------

/**
 * Strictest-wins merge: a call is dirty if the deterministic side hard-blocked
 * OR the grader graded it non-compliant. Either channel can dirty the call; the
 * cleaner channel never "averages out" a dirty one (design: never averaged).
 *
 * A deterministic WARN alone is NOT dirty here — warns arm WATCH from COMPLIANT,
 * but once armed (WATCH/GATED/RECOVERING) only a hard block or a non-compliant
 * grade resets the recovery streak. (A warn that recurs while armed will still
 * surface via the grader as non-compliant.)
 */
function isDirty(
  deterministic: DeterministicSignal | undefined,
  grader: GraderSignal | undefined,
): boolean {
  if (deterministic?.blocked) return true;
  if (grader !== undefined && grader.compliant === false) return true;
  // A grader-reported inviolable is treated as a dirty grade (it cannot HALT on
  // its own — only the deterministic engine halts — but it is never "clean").
  if (grader?.inviolable === true) return true;
  return false;
}

/** Bump the state epoch — every arming/recovery transition does this. */
function bumpEpoch(state: PersistedState): PersistedState {
  return { ...state, stateEpoch: state.stateEpoch + 1 };
}
