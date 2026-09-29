/** A virtual clock and timer queue for scheduler and controller tests. */
import type { Timers } from "../src/sync/scheduler.ts";

export class VirtualTimers implements Timers {
  t = 0;
  private seq = 0;
  private queue = new Map<number, { at: number; fn: () => void }>();
  now = () => this.t;
  setTimeout = (fn: () => void, ms: number) => {
    const id = ++this.seq;
    this.queue.set(id, { at: this.t + ms, fn });
    return id;
  };
  clearTimeout = (h: unknown) => {
    this.queue.delete(h as number);
  };
  /** Advance time, firing timers in order and letting promises settle between them. */
  async advance(ms: number) {
    const end = this.t + ms;
    for (;;) {
      await settle();
      const next = [...this.queue.entries()].sort((a, b) => a[1].at - b[1].at)[0];
      if (!next || next[1].at > end) break;
      this.queue.delete(next[0]);
      this.t = next[1].at;
      next[1].fn();
    }
    this.t = end;
    await settle();
  }
}

export const settle = () => new Promise((r) => setImmediate(r));

