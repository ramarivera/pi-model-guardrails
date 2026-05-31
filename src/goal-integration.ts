interface GoalState {
  goalId: string;
  objective: string;
  status: string;
}

interface SessionEntry {
  type?: string;
  customType?: string;
  data?: unknown;
}

interface SessionManagerLike {
  getEntries?: () => unknown[];
  getBranch?: () => unknown[];
}

interface GoalContextLike {
  sessionManager?: SessionManagerLike;
}

const ENTRY_TYPE = "pi-goal-state";

function isGoalState(value: unknown): value is GoalState {
  if (!value || typeof value !== "object") return false;
  const maybe = value as Partial<GoalState>;
  return (
    typeof maybe.goalId === "string" && typeof maybe.objective === "string"
  );
}

/**
 * Read the current active goal from the session manager.
 * Returns the goal objective if an active goal is found, otherwise undefined.
 */
export function readActiveGoal(ctx: GoalContextLike): string | undefined {
  const entries =
    ctx.sessionManager?.getEntries?.() ??
    ctx.sessionManager?.getBranch?.() ??
    [];

  let latest: GoalState | undefined;
  for (const entry of entries) {
    const candidate = entry as SessionEntry;
    if (
      candidate?.type === "custom" &&
      candidate?.customType === ENTRY_TYPE &&
      isGoalState(candidate.data)
    ) {
      latest = candidate.data;
    }
  }

  if (!latest || latest.status === "cleared" || latest.status === "complete") {
    return undefined;
  }

  return latest.objective;
}
