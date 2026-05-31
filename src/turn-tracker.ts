export class TurnTracker {
  private turnCount = 0;
  private readonly interval: number;

  constructor(interval: number) {
    this.interval = Math.max(1, interval);
  }

  recordTurn(): boolean {
    this.turnCount++;
    return this.turnCount % this.interval === 0;
  }

  getTurnCount(): number {
    return this.turnCount;
  }

  reset(): void {
    this.turnCount = 0;
  }
}
