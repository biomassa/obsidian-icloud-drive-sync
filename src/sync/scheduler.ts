/**
 * When to sync. Pure: timers and the clock are injected, so every rule below
 * is a unit test.
 *
 * - A **poll** runs a full cycle (walking iCloud) every `pollMs`. iCloud has no
 *   change notifications, so this is how another device's edits arrive.
 * - A **local change** waits for `quietMs` of silence (an editor saves
 *   repeatedly while you type), then runs a cycle against the cached iCloud
 *   scan. At most one local-change cycle per `minIntervalMs`.
 * - A change that arrives while a cycle runs, or inside the minimum interval,
 *   is **deferred, never dropped** (obsisync regression: an edit made during a
 *   long forced scan was lost until the next poll).
 * - Events caused by the engine's own writes are **ignored** for `echoMs`, or
 *   every download would trigger a pointless cycle.
 */
import type { CycleOptions } from "./engine.ts";

export type Trigger = "poll" | "local" | "manual" | "start";

export interface Timers {
  now(): number;
  setTimeout(fn: () => void, ms: number): unknown;
  clearTimeout(handle: unknown): void;
}

export const realTimers: Timers = {
  now: () => Date.now(),
  setTimeout: (fn, ms) => setTimeout(fn, ms),
  clearTimeout: (h) => clearTimeout(h as ReturnType<typeof setTimeout>),
};

export interface SchedulerOptions {
  pollMs: number;
  quietMs: number;
  minIntervalMs: number;
  echoMs: number;
  timers: Timers;
}

export const DEFAULT_SCHEDULE: Omit<SchedulerOptions, "timers"> = {
  pollMs: 120_000,
  quietMs: 3_000,
  minIntervalMs: 30_000,
  echoMs: 5_000,
};

export type RunCycle = (trigger: Trigger, options: CycleOptions) => Promise<{ localWrites?: { key: string }[] } | void>;

export class SyncScheduler {
  private readonly run: RunCycle;
  private readonly opt: SchedulerOptions;
  private pollTimer: unknown = null;
  private localTimer: unknown = null;
  private running: Promise<void> | null = null;
  /** What to run once the current cycle ends. A full cycle subsumes a local one. */
  private pending: Trigger | null = null;
  private lastLocalRun = -Infinity;
  private echoUntil = new Map<string, number>();
  private active = false;
  private paused = false;

  constructor(run: RunCycle, options: Partial<SchedulerOptions> = {}) {
    this.run = run;
    this.opt = { ...DEFAULT_SCHEDULE, timers: realTimers, ...options };
  }

  get isPaused(): boolean {
    return this.paused;
  }

  get isRunning(): boolean {
    return this.running !== null;
  }

  start(): void {
    if (this.active) return;
    this.active = true;
    this.request("start");
  }

  async stop(): Promise<void> {
    this.active = false;
    this.clear("pollTimer");
    this.clear("localTimer");
    this.pending = null;
    await this.running;
  }

  /** Stop starting cycles. The one in flight finishes. */
  pause(): void {
    this.paused = true;
    this.clear("localTimer");
  }

  /** Resume, with a full cycle to catch up on everything missed. */
  resume(): void {
    if (!this.paused) return;
    this.paused = false;
    this.request("manual");
  }

  syncNow(): void {
    this.request("manual");
  }

  /** One full cycle now, without starting the poll: for "sync automatically" turned off. */
  runOnce(): void {
    if (this.active) return this.request("manual");
    if (!this.running) this.running = this.execute("manual");
  }

  /** The engine wrote these keys; their file events are ours, not the user's. */
  markWritten(keys: Iterable<string>): void {
    const until = this.opt.timers.now() + this.opt.echoMs;
    for (const k of keys) this.echoUntil.set(k, until);
  }

  /** A file in the vault changed on disk. `keys` are the affected paths (a rename has two). */
  localChange(...keys: string[]): void {
    if (!this.active || this.paused) return;
    const now = this.opt.timers.now();
    const ours = keys.length > 0 && keys.every((k) => (this.echoUntil.get(k) ?? 0) > now);
    if (ours) return;
    // Debounce: every event restarts the quiet period.
    this.clear("localTimer");
    this.localTimer = this.opt.timers.setTimeout(() => {
      this.localTimer = null;
      this.request("local");
    }, this.opt.quietMs);
  }

  private clear(which: "pollTimer" | "localTimer"): void {
    if (this[which] !== null) this.opt.timers.clearTimeout(this[which]);
    this[which] = null;
  }

  private schedulePoll(): void {
    this.clear("pollTimer");
    if (!this.active) return;
    this.pollTimer = this.opt.timers.setTimeout(() => {
      this.pollTimer = null;
      this.request("poll");
    }, this.opt.pollMs);
  }

  private request(trigger: Trigger): void {
    if (!this.active || (this.paused && trigger !== "manual")) return;
    if (this.running) {
      // Deferred, never dropped. A full cycle wins over a local one.
      if (this.pending === null || this.pending === "local") this.pending = trigger;
      return;
    }
    if (trigger === "local") {
      const wait = this.lastLocalRun + this.opt.minIntervalMs - this.opt.timers.now();
      if (wait > 0) {
        this.clear("localTimer");
        this.localTimer = this.opt.timers.setTimeout(() => {
          this.localTimer = null;
          this.request("local");
        }, wait);
        return;
      }
      this.lastLocalRun = this.opt.timers.now();
    }
    this.running = this.execute(trigger);
  }

  private async execute(trigger: Trigger): Promise<void> {
    const full = trigger !== "local";
    // A full cycle walks iCloud; the poll clock restarts from its end.
    if (full) this.clear("pollTimer");
    try {
      const result = await this.run(trigger, full ? {} : { reuseRemoteScanWithinMs: this.opt.pollMs });
      if (result?.localWrites) this.markWritten(result.localWrites.map((w) => w.key));
    } catch {
      // The caller reports failures; the schedule carries on regardless.
    } finally {
      this.running = null;
      if (full || this.pollTimer === null) this.schedulePoll();
      const next = this.pending;
      this.pending = null;
      if (next) this.request(next);
    }
  }
}
