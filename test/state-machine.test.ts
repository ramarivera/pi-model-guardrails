// Exhaustive tests for the deviation state machine (src/state/machine.ts).
//
// Covers: each state x each signal kind (deterministic deny critical/high/medium,
// grader compliant/non-compliant, soft/warn), the arming paths
// (COMPLIANT->WATCH/GATED/HALTED), recovery (GATED->RECOVERING->COMPLIANT needs
// consecutive clean non-trivial grades + backOnTrack), and the anti-backslide
// invariants (alternating clean/dirty never recovers; any dirty resets streak and
// drops RECOVERING->GATED; inviolable->HALTED is grader-immune and clears ONLY via
// clearHalt(humanAck); cooldown re-arms on immediate relapse; trivial calls don't
// advance the recovery streak when nonTrivialOnly).

import assert from "node:assert/strict";
import test from "node:test";
import {
  clearHalt,
  defaultMachineConfig,
  initialState,
  transition,
} from "../src/state/machine.ts";
import type {
  CallMeta,
  DeterministicSignal,
  GraderSignal,
  GuardState,
  MachineConfig,
  PersistedState,
  TransitionResult,
} from "../src/state/types.ts";

// --- builders --------------------------------------------------------------

function cfg(over: Partial<MachineConfig> = {}): MachineConfig {
  return { ...defaultMachineConfig(), ...over };
}

const MUTATING: CallMeta = {
  toolName: "bash",
  isMutating: true,
  isTrivial: false,
};
const READONLY: CallMeta = {
  toolName: "read",
  isMutating: false,
  isTrivial: true,
};
const NONTRIVIAL_NONMUTATING: CallMeta = {
  toolName: "grep",
  isMutating: false,
  isTrivial: false,
};

function det(over: Partial<DeterministicSignal> = {}): DeterministicSignal {
  return {
    blocked: false,
    inviolable: false,
    allowlistable: false,
    warn: false,
    ...over,
  };
}

const DENY_CRITICAL = det({
  blocked: true,
  severity: "critical",
  reason: "rm -rf /",
});
const DENY_HIGH = det({
  blocked: true,
  severity: "high",
  reason: "force push main",
});
const DENY_INVIOLABLE = det({
  blocked: true,
  inviolable: true,
  severity: "high",
  reason: "never touch prod DB",
});
const WARN_MEDIUM = det({
  warn: true,
  severity: "medium",
  reason: "suspicious",
});
const CLEAN_DET = det();

function grade(over: Partial<GraderSignal> = {}): GraderSignal {
  return {
    compliant: true,
    backOnTrack: false,
    confidence: 0.9,
    inviolable: false,
    ...over,
  };
}

const GRADE_CLEAN = grade({ compliant: true });
const GRADE_DIRTY = grade({ compliant: false, reason: "still off track" });
const GRADE_BACK = grade({ compliant: true, backOnTrack: true });
const GRADE_INVIOLABLE = grade({
  compliant: false,
  inviolable: true,
  reason: "grader saw inviolable",
});

function st(
  state: GuardState,
  over: Partial<PersistedState> = {},
): PersistedState {
  return {
    state,
    cleanStreak: 0,
    stateEpoch: 0,
    cooldownRemaining: 0,
    ...over,
  };
}

function step(
  current: PersistedState,
  opts: {
    det?: DeterministicSignal;
    grader?: GraderSignal;
    meta?: CallMeta;
    config?: MachineConfig;
  } = {},
): TransitionResult {
  return transition({
    current,
    deterministic: opts.det,
    grader: opts.grader,
    meta: opts.meta ?? MUTATING,
    config: opts.config ?? cfg(),
  });
}

// --- constructors ----------------------------------------------------------

test("initialState is fresh COMPLIANT", () => {
  assert.deepEqual(initialState(), {
    state: "COMPLIANT",
    cleanStreak: 0,
    stateEpoch: 0,
    cooldownRemaining: 0,
  });
});

test("defaultMachineConfig matches the contract defaults", () => {
  assert.deepEqual(defaultMachineConfig(), {
    watchCleanStreak: 2,
    gatedCleanStreak: 3,
    recoveringWatermark: 1,
    cooldownTurns: 2,
    gateOnlyMutatingInWatch: true,
    nonTrivialOnly: true,
    haltRequiresHumanAck: true,
  });
});

// --- COMPLIANT arming paths ------------------------------------------------

test("COMPLIANT + clean => allow, stays COMPLIANT", () => {
  const r = step(st("COMPLIANT"), { det: CLEAN_DET });
  assert.equal(r.action, "allow");
  assert.equal(r.next.state, "COMPLIANT");
  assert.equal(r.transitioned, false);
});

test("COMPLIANT + no deterministic signal at all => allow", () => {
  const r = step(st("COMPLIANT"), {});
  assert.equal(r.action, "allow");
  assert.equal(r.next.state, "COMPLIANT");
});

test("COMPLIANT + warn (medium) => WATCH, allow this call, epoch bumped", () => {
  const r = step(st("COMPLIANT"), { det: WARN_MEDIUM });
  assert.equal(r.next.state, "WATCH");
  assert.equal(r.action, "allow"); // warn arms watch but does not block this call
  assert.equal(r.transitioned, true);
  assert.equal(r.next.stateEpoch, 1);
  assert.equal(r.next.armedReason, "suspicious");
});

test("COMPLIANT + deny high (non-inviolable) => GATED + block, epoch bumped", () => {
  const r = step(st("COMPLIANT"), { det: DENY_HIGH });
  assert.equal(r.next.state, "GATED");
  assert.equal(r.action, "block");
  assert.equal(r.transitioned, true);
  assert.equal(r.next.stateEpoch, 1);
});

test("COMPLIANT + deny critical => HALTED (hard floor), epoch bumped", () => {
  const r = step(st("COMPLIANT"), { det: DENY_CRITICAL });
  assert.equal(r.next.state, "HALTED");
  assert.equal(r.action, "halt");
  assert.equal(r.next.stateEpoch, 1);
});

test("COMPLIANT + inviolable => HALTED, epoch bumped", () => {
  const r = step(st("COMPLIANT"), { det: DENY_INVIOLABLE });
  assert.equal(r.next.state, "HALTED");
  assert.equal(r.action, "halt");
  assert.equal(r.next.stateEpoch, 1);
});

// --- WATCH behavior --------------------------------------------------------

test("WATCH + clean mutating => gate-required (latency-bounded WATCH grading)", () => {
  const r = step(st("WATCH"), { det: CLEAN_DET, meta: MUTATING });
  assert.equal(r.action, "gate-required");
  assert.equal(r.next.state, "WATCH");
  assert.equal(r.next.cleanStreak, 1);
});

test("WATCH + clean read-only => allow (gateOnlyMutatingInWatch), streak does not advance (trivial)", () => {
  const r = step(st("WATCH"), { det: CLEAN_DET, meta: READONLY });
  assert.equal(r.action, "allow");
  assert.equal(r.next.cleanStreak, 0); // READONLY is trivial => no advance
});

test("WATCH clears to COMPLIANT after watchCleanStreak clean non-trivial calls", () => {
  const s = st("WATCH", { stateEpoch: 1 });
  const r1 = step(s, { det: CLEAN_DET, meta: NONTRIVIAL_NONMUTATING });
  assert.equal(r1.next.state, "WATCH");
  assert.equal(r1.next.cleanStreak, 1);
  const r2 = step(r1.next, { det: CLEAN_DET, meta: NONTRIVIAL_NONMUTATING });
  assert.equal(r2.next.state, "COMPLIANT");
  assert.equal(r2.next.cleanStreak, 0);
  assert.equal(r2.next.stateEpoch, 2); // recovery transition bumps epoch
  assert.equal(r2.next.cooldownRemaining, cfg().cooldownTurns); // cooldown armed
});

test("WATCH + another warn (deviation) => GATED", () => {
  const r = step(st("WATCH", { cleanStreak: 1 }), { det: WARN_MEDIUM });
  assert.equal(r.next.state, "GATED");
  assert.equal(r.next.cleanStreak, 0);
});

test("WATCH + deny high => GATED + block", () => {
  const r = step(st("WATCH"), { det: DENY_HIGH });
  assert.equal(r.next.state, "GATED");
  assert.equal(r.action, "block");
});

test("WATCH + deny critical => HALTED (floor beats watch)", () => {
  const r = step(st("WATCH"), { det: DENY_CRITICAL });
  assert.equal(r.next.state, "HALTED");
  assert.equal(r.action, "halt");
});

test("WATCH + inviolable => HALTED", () => {
  const r = step(st("WATCH"), { det: DENY_INVIOLABLE });
  assert.equal(r.next.state, "HALTED");
});

test("WATCH + non-compliant grade (dirty) => GATED", () => {
  const r = step(st("WATCH"), { det: CLEAN_DET, grader: GRADE_DIRTY });
  assert.equal(r.next.state, "GATED");
});

test("WATCH streak is consecutive: a deviation between cleans resets it", () => {
  const r1 = step(st("WATCH"), {
    det: CLEAN_DET,
    meta: NONTRIVIAL_NONMUTATING,
  });
  assert.equal(r1.next.cleanStreak, 1);
  // a warn between cleans escalates to GATED (does not just reset back to WATCH)
  const r2 = step(r1.next, { det: WARN_MEDIUM, meta: NONTRIVIAL_NONMUTATING });
  assert.equal(r2.next.state, "GATED");
  assert.equal(r2.next.cleanStreak, 0);
});

// --- GATED behavior --------------------------------------------------------

test("GATED + clean grade (non-trivial) => RECOVERING at recoveringWatermark", () => {
  const r = step(st("GATED"), {
    det: CLEAN_DET,
    grader: GRADE_CLEAN,
    meta: NONTRIVIAL_NONMUTATING,
  });
  assert.equal(r.next.state, "RECOVERING");
  assert.equal(r.action, "allow"); // clean grade => the call runs while recovery stages
  assert.equal(r.next.cleanStreak, 0); // reset on promotion
});

test("GATED + clean but NO grader yet => holds gate-required (Phase 2 / pre-grade)", () => {
  const r = step(st("GATED"), { det: CLEAN_DET });
  assert.equal(r.action, "gate-required");
  assert.equal(r.next.state, "GATED");
  assert.equal(r.transitioned, false);
});

test("GATED + clean trivial grade does NOT advance toward recovery", () => {
  const r = step(st("GATED"), {
    det: CLEAN_DET,
    grader: GRADE_CLEAN,
    meta: READONLY,
  });
  assert.equal(r.next.state, "GATED");
  assert.equal(r.next.cleanStreak, 0);
  assert.equal(r.action, "allow"); // clean grade => runs; trivial => no streak advance
});

test("GATED + dirty grade => stays GATED, streak reset, every call still gated", () => {
  const r = step(st("GATED", { cleanStreak: 0 }), {
    det: CLEAN_DET,
    grader: GRADE_DIRTY,
  });
  assert.equal(r.next.state, "GATED");
  assert.equal(r.next.cleanStreak, 0);
  assert.equal(r.action, "gate-required");
});

test("GATED + new deterministic deny high => stays GATED + block", () => {
  const r = step(st("GATED"), { det: DENY_HIGH });
  assert.equal(r.next.state, "GATED");
  assert.equal(r.action, "block");
});

test("GATED + deny critical => HALTED (floor)", () => {
  const r = step(st("GATED"), { det: DENY_CRITICAL });
  assert.equal(r.next.state, "HALTED");
});

test("GATED + inviolable => HALTED", () => {
  const r = step(st("GATED"), { det: DENY_INVIOLABLE });
  assert.equal(r.next.state, "HALTED");
});

test("GATED with recoveringWatermark>1 accumulates clean grades before RECOVERING", () => {
  const c = cfg({ recoveringWatermark: 2 });
  const r1 = step(st("GATED"), {
    det: CLEAN_DET,
    grader: GRADE_CLEAN,
    meta: NONTRIVIAL_NONMUTATING,
    config: c,
  });
  assert.equal(r1.next.state, "GATED");
  assert.equal(r1.next.cleanStreak, 1);
  const r2 = step(r1.next, {
    det: CLEAN_DET,
    grader: GRADE_CLEAN,
    meta: NONTRIVIAL_NONMUTATING,
    config: c,
  });
  assert.equal(r2.next.state, "RECOVERING");
});

// --- RECOVERING behavior + full recovery -----------------------------------

test("RECOVERING needs gatedCleanStreak consecutive clean grades + backOnTrack => COMPLIANT", () => {
  // gatedCleanStreak = 3. First two clean grades (backOnTrack false) hold.
  const s = st("RECOVERING", { violatedConstraintId: "C1" });
  const r1 = step(s, {
    det: CLEAN_DET,
    grader: GRADE_CLEAN,
    meta: NONTRIVIAL_NONMUTATING,
  });
  assert.equal(r1.next.state, "RECOVERING");
  assert.equal(r1.next.cleanStreak, 1);
  const r2 = step(r1.next, {
    det: CLEAN_DET,
    grader: GRADE_CLEAN,
    meta: NONTRIVIAL_NONMUTATING,
  });
  assert.equal(r2.next.state, "RECOVERING");
  assert.equal(r2.next.cleanStreak, 2);
  // Third clean grade meets the streak but grader not back-on-track yet => hold.
  const r3 = step(r2.next, {
    det: CLEAN_DET,
    grader: GRADE_CLEAN,
    meta: NONTRIVIAL_NONMUTATING,
  });
  assert.equal(r3.next.state, "RECOVERING");
  assert.equal(r3.next.cleanStreak, 3);
  assert.equal(r3.action, "allow"); // clean grade runs; full recovery awaits backOnTrack
  // Fourth grade is back-on-track AND streak already met => recover.
  const r4 = step(r3.next, {
    det: CLEAN_DET,
    grader: GRADE_BACK,
    meta: NONTRIVIAL_NONMUTATING,
  });
  assert.equal(r4.next.state, "COMPLIANT");
  assert.equal(r4.action, "allow");
  assert.equal(r4.next.cooldownRemaining, cfg().cooldownTurns);
  assert.equal(r4.next.violatedConstraintId, undefined);
});

test("RECOVERING recovers exactly when streak reached AND backOnTrack on same call", () => {
  const c = cfg({ gatedCleanStreak: 1 });
  const r = step(st("RECOVERING"), {
    det: CLEAN_DET,
    grader: GRADE_BACK,
    meta: NONTRIVIAL_NONMUTATING,
    config: c,
  });
  assert.equal(r.next.state, "COMPLIANT");
});

test("RECOVERING + clean trivial grade does NOT advance the streak", () => {
  const r = step(st("RECOVERING", { cleanStreak: 1 }), {
    det: CLEAN_DET,
    grader: GRADE_BACK,
    meta: READONLY,
  });
  assert.equal(r.next.state, "RECOVERING");
  assert.equal(r.next.cleanStreak, 1);
  assert.equal(r.action, "allow"); // clean grade runs; trivial => no streak advance
});

test("RECOVERING + clean but no grader => holds (still grades every call)", () => {
  const r = step(st("RECOVERING", { cleanStreak: 2 }), { det: CLEAN_DET });
  assert.equal(r.action, "gate-required");
  assert.equal(r.next.cleanStreak, 2);
});

test("RECOVERING + dirty grade => back to GATED, streak reset, epoch bumped", () => {
  const s = st("RECOVERING", { cleanStreak: 2, stateEpoch: 4 });
  const r = step(s, { det: CLEAN_DET, grader: GRADE_DIRTY });
  assert.equal(r.next.state, "GATED");
  assert.equal(r.next.cleanStreak, 0);
  assert.equal(r.next.stateEpoch, 5);
});

test("RECOVERING + new deterministic deny => back to GATED + block", () => {
  const r = step(st("RECOVERING", { cleanStreak: 2 }), { det: DENY_HIGH });
  assert.equal(r.next.state, "GATED");
  assert.equal(r.action, "block");
  assert.equal(r.next.cleanStreak, 0);
});

test("RECOVERING + deny critical => HALTED (floor)", () => {
  const r = step(st("RECOVERING"), { det: DENY_CRITICAL });
  assert.equal(r.next.state, "HALTED");
});

test("RECOVERING + inviolable => HALTED", () => {
  const r = step(st("RECOVERING", { cleanStreak: 2 }), {
    det: DENY_INVIOLABLE,
  });
  assert.equal(r.next.state, "HALTED");
});

// --- ANTI-BACKSLIDE INVARIANTS ---------------------------------------------

test("INVARIANT: alternating clean/dirty grades NEVER recover from RECOVERING", () => {
  let s = st("RECOVERING", { violatedConstraintId: "C1" });
  for (let i = 0; i < 8; i++) {
    const clean = step(s, {
      det: CLEAN_DET,
      grader: GRADE_CLEAN,
      meta: NONTRIVIAL_NONMUTATING,
    });
    // a clean grade may advance the streak but never recovers without backOnTrack
    assert.notEqual(clean.next.state, "COMPLIANT");
    const dirty = step(clean.next, {
      det: CLEAN_DET,
      grader: GRADE_DIRTY,
      meta: NONTRIVIAL_NONMUTATING,
    });
    // the dirty grade drops to GATED and wipes the streak
    assert.equal(dirty.next.state, "GATED");
    assert.equal(dirty.next.cleanStreak, 0);
    // climbing back to RECOVERING for the next loop iteration
    const climb = step(dirty.next, {
      det: CLEAN_DET,
      grader: GRADE_CLEAN,
      meta: NONTRIVIAL_NONMUTATING,
    });
    assert.equal(climb.next.state, "RECOVERING");
    s = climb.next;
  }
});

test("INVARIANT: alternating clean/dirty in GATED never promotes to RECOVERING durably", () => {
  // recoveringWatermark=1 so a single clean grade promotes; but a dirty grade
  // immediately after recovery (in RECOVERING) drops back to GATED. Net: it
  // ping-pongs and never reaches COMPLIANT.
  let s = st("GATED");
  let reachedCompliant = false;
  for (let i = 0; i < 20; i++) {
    const sig = i % 2 === 0 ? GRADE_CLEAN : GRADE_DIRTY;
    const r = step(s, {
      det: CLEAN_DET,
      grader: sig,
      meta: NONTRIVIAL_NONMUTATING,
    });
    if (r.next.state === "COMPLIANT") reachedCompliant = true;
    s = r.next;
  }
  assert.equal(reachedCompliant, false);
});

test("INVARIANT: consecutive-not-cumulative — a single dirty grade wipes accumulated streak", () => {
  let s = st("RECOVERING", { cleanStreak: 0 });
  s = step(s, {
    det: CLEAN_DET,
    grader: GRADE_CLEAN,
    meta: NONTRIVIAL_NONMUTATING,
  }).next;
  s = step(s, {
    det: CLEAN_DET,
    grader: GRADE_CLEAN,
    meta: NONTRIVIAL_NONMUTATING,
  }).next;
  assert.equal(s.cleanStreak, 2);
  const dirty = step(s, {
    det: CLEAN_DET,
    grader: GRADE_DIRTY,
    meta: NONTRIVIAL_NONMUTATING,
  });
  assert.equal(dirty.next.cleanStreak, 0);
  assert.equal(dirty.next.state, "GATED");
});

test("INVARIANT: inviolable -> HALTED is grader-immune (a clean back-on-track grade cannot stop the halt)", () => {
  // Even with a glowing grader signal, a deterministic inviolable halts.
  const r = step(st("RECOVERING", { cleanStreak: 2 }), {
    det: DENY_INVIOLABLE,
    grader: GRADE_BACK,
  });
  assert.equal(r.next.state, "HALTED");
  assert.equal(r.action, "halt");
});

test("INVARIANT: a grader-only inviolable does NOT halt (only deterministic engine halts)", () => {
  // Grader thinks an inviolable was breached, but the engine did not block.
  // It is treated as a dirty grade, not a HALT.
  const r = step(st("GATED"), { det: CLEAN_DET, grader: GRADE_INVIOLABLE });
  assert.equal(r.next.state, "GATED"); // dirty -> stays gated, NOT halted
  assert.notEqual(r.next.state, "HALTED");
});

test("INVARIANT: HALTED is terminal — no signal exits it", () => {
  const halted = st("HALTED", { armedReason: "boom", stateEpoch: 3 });
  for (const opts of [
    { det: CLEAN_DET, grader: GRADE_BACK },
    { det: CLEAN_DET, grader: GRADE_CLEAN },
    { det: WARN_MEDIUM },
    { det: DENY_HIGH },
    {},
  ]) {
    const r = step(halted, opts);
    assert.equal(r.next.state, "HALTED");
    assert.equal(r.action, "halt");
    assert.equal(r.transitioned, false);
  }
});

test("INVARIANT: HALTED clears ONLY via clearHalt(humanAck) => COMPLIANT, epoch bumped", () => {
  const halted = st("HALTED", {
    armedReason: "boom",
    violatedConstraintId: "C9",
    stateEpoch: 7,
  });
  const cleared = clearHalt(halted, true);
  assert.equal(cleared.state, "COMPLIANT");
  assert.equal(cleared.cleanStreak, 0);
  assert.equal(cleared.violatedConstraintId, undefined);
  assert.equal(cleared.armedReason, undefined);
  assert.equal(cleared.stateEpoch, 8); // recovery transition bumps epoch
  assert.equal(cleared.cooldownRemaining, 0);
});

test("INVARIANT: cooldown re-arms GATED on immediate relapse after recovery", () => {
  // Recover from RECOVERING -> COMPLIANT with cooldown armed.
  const c = cfg({ gatedCleanStreak: 1 });
  const recovered = step(st("RECOVERING"), {
    det: CLEAN_DET,
    grader: GRADE_BACK,
    meta: NONTRIVIAL_NONMUTATING,
    config: c,
  }).next;
  assert.equal(recovered.state, "COMPLIANT");
  assert.ok(recovered.cooldownRemaining > 0);
  // Immediate relapse (a deny) while in cooldown => GATED (degraded mode), not WATCH.
  const relapse = step(recovered, { det: DENY_HIGH, config: c });
  assert.equal(relapse.next.state, "GATED");
});

test("cooldown ticks down on clean compliant calls", () => {
  const s = st("COMPLIANT", { cooldownRemaining: 2 });
  const r1 = step(s, { det: CLEAN_DET });
  assert.equal(r1.next.cooldownRemaining, 1);
  assert.equal(r1.next.state, "COMPLIANT");
  const r2 = step(r1.next, { det: CLEAN_DET });
  assert.equal(r2.next.cooldownRemaining, 0);
});

// --- strictest-wins merge --------------------------------------------------

test("strictest-wins: clean grade does NOT rescue a deterministic block", () => {
  const r = step(st("GATED"), { det: DENY_HIGH, grader: GRADE_BACK });
  // deterministic block dominates: stays GATED + block (never averaged to clean)
  assert.equal(r.next.state, "GATED");
  assert.equal(r.action, "block");
});

test("strictest-wins: dirty grade dominates a clean deterministic signal", () => {
  const r = step(st("RECOVERING", { cleanStreak: 2 }), {
    det: CLEAN_DET,
    grader: GRADE_DIRTY,
  });
  assert.equal(r.next.state, "GATED");
});

// --- nonTrivialOnly = false -------------------------------------------------

test("nonTrivialOnly=false: trivial clean grades DO advance the recovery streak", () => {
  const c = cfg({ nonTrivialOnly: false });
  const r = step(st("GATED"), {
    det: CLEAN_DET,
    grader: GRADE_CLEAN,
    meta: READONLY,
    config: c,
  });
  assert.equal(r.next.state, "RECOVERING"); // trivial now counts
});

// --- gateOnlyMutatingInWatch = false ---------------------------------------

test("gateOnlyMutatingInWatch=false: read-only clean calls in WATCH gate too", () => {
  const c = cfg({ gateOnlyMutatingInWatch: false });
  const r = step(st("WATCH"), { det: CLEAN_DET, meta: READONLY, config: c });
  assert.equal(r.action, "gate-required");
});

// --- full happy-path lifecycle ---------------------------------------------

test("full lifecycle: COMPLIANT -> WATCH -> GATED -> RECOVERING -> COMPLIANT", () => {
  let s = initialState();
  // soft signal arms WATCH
  s = step(s, { det: WARN_MEDIUM }).next;
  assert.equal(s.state, "WATCH");
  // a deny escalates to GATED
  s = step(s, { det: DENY_HIGH }).next;
  assert.equal(s.state, "GATED");
  // one clean grade promotes to RECOVERING
  s = step(s, {
    det: CLEAN_DET,
    grader: GRADE_CLEAN,
    meta: NONTRIVIAL_NONMUTATING,
  }).next;
  assert.equal(s.state, "RECOVERING");
  // three consecutive clean grades, last one back-on-track => COMPLIANT
  s = step(s, {
    det: CLEAN_DET,
    grader: GRADE_CLEAN,
    meta: NONTRIVIAL_NONMUTATING,
  }).next;
  s = step(s, {
    det: CLEAN_DET,
    grader: GRADE_CLEAN,
    meta: NONTRIVIAL_NONMUTATING,
  }).next;
  s = step(s, {
    det: CLEAN_DET,
    grader: GRADE_BACK,
    meta: NONTRIVIAL_NONMUTATING,
  }).next;
  assert.equal(s.state, "COMPLIANT");
  assert.ok(s.cooldownRemaining > 0);
});

// --- epoch monotonicity on arming/recovery ---------------------------------

test("epoch bumps on every arming and recovery transition, not on plain clean calls", () => {
  let s = initialState();
  assert.equal(s.stateEpoch, 0);
  s = step(s, { det: CLEAN_DET }).next; // plain clean compliant
  assert.equal(s.stateEpoch, 0); // no bump
  s = step(s, { det: DENY_HIGH }).next; // arm GATED
  assert.equal(s.stateEpoch, 1);
  s = step(s, {
    det: CLEAN_DET,
    grader: GRADE_CLEAN,
    meta: NONTRIVIAL_NONMUTATING,
  }).next; // -> RECOVERING
  assert.equal(s.stateEpoch, 2);
  const c = cfg({ gatedCleanStreak: 1 });
  s = step(s, {
    det: CLEAN_DET,
    grader: GRADE_BACK,
    meta: NONTRIVIAL_NONMUTATING,
    config: c,
  }).next; // -> COMPLIANT
  assert.equal(s.stateEpoch, 3);
});
