import assert from "node:assert/strict";
import test from "node:test";
import { readActiveGoal } from "../src/goal-integration.ts";

test("readActiveGoal returns undefined when no entries", () => {
  const ctx = createMockContext([]);
  const result = readActiveGoal(ctx);
  assert.equal(result, undefined);
});

test("readActiveGoal returns undefined when no goal entries", () => {
  const ctx = createMockContext([
    { type: "custom", customType: "other-extension", data: { foo: "bar" } },
  ]);
  const result = readActiveGoal(ctx);
  assert.equal(result, undefined);
});

test("readActiveGoal returns objective when active goal found", () => {
  const ctx = createMockContext([
    {
      type: "custom",
      customType: "pi-goal-state",
      data: {
        goalId: "goal_123",
        objective: "Build a functional skill marketplace",
        status: "active",
      },
    },
  ]);
  const result = readActiveGoal(ctx);
  assert.equal(result, "Build a functional skill marketplace");
});

test("readActiveGoal returns latest goal when multiple found", () => {
  const ctx = createMockContext([
    {
      type: "custom",
      customType: "pi-goal-state",
      data: {
        goalId: "goal_123",
        objective: "First goal",
        status: "active",
      },
    },
    {
      type: "custom",
      customType: "pi-goal-state",
      data: {
        goalId: "goal_456",
        objective: "Second goal",
        status: "active",
      },
    },
  ]);
  const result = readActiveGoal(ctx);
  assert.equal(result, "Second goal");
});

test("readActiveGoal returns undefined for completed goals", () => {
  const ctx = createMockContext([
    {
      type: "custom",
      customType: "pi-goal-state",
      data: {
        goalId: "goal_123",
        objective: "Build something",
        status: "complete",
      },
    },
  ]);
  const result = readActiveGoal(ctx);
  assert.equal(result, undefined);
});

test("readActiveGoal returns undefined for cleared goals", () => {
  const ctx = createMockContext([
    {
      type: "custom",
      customType: "pi-goal-state",
      data: {
        goalId: "goal_123",
        objective: "Build something",
        status: "cleared",
      },
    },
  ]);
  const result = readActiveGoal(ctx);
  assert.equal(result, undefined);
});

function createMockContext(entries: unknown[]): {
  sessionManager: {
    getEntries: () => unknown[];
    getBranch: () => unknown[];
  };
} {
  return {
    sessionManager: {
      getEntries: () => entries,
      getBranch: () => entries,
    },
  };
}
