/** The scheduler's rules, on a virtual clock. */
import { test } from "node:test";
import assert from "node:assert/strict";

import { SyncScheduler, type Trigger } from "../src/sync/scheduler.ts";
import { VirtualTimers } from "./virtual-timers.ts";

function harness(opts: { cycleMs?: number } = {}) {
  const timers = new VirtualTimers();
  const runs: { trigger: Trigger; at: number; reused: boolean }[] = [];
  let writes: { key: string }[] = [];
  const scheduler = new SyncScheduler(
    async (trigger, options) => {
      runs.push({ trigger, at: timers.t, reused: options.reuseRemoteScanWithinMs !== undefined });
      if (opts.cycleMs) await new Promise<void>((r) => timers.setTimeout(r, opts.cycleMs!));
      const w = writes;
      writes = [];
      return { localWrites: w };
    },
    { pollMs: 120_000, quietMs: 3_000, minIntervalMs: 30_000, echoMs: 5_000, timers },
  );
  return { timers, runs, scheduler, setWrites: (keys: string[]) => (writes = keys.map((key) => ({ key }))) };
}

test("starts with a full cycle and then polls", async () => {
  const h = harness();
  h.scheduler.start();
  await h.timers.advance(250_000);
  assert.deepEqual(h.runs.map((r) => r.trigger), ["start", "poll", "poll"]);
  assert.ok(h.runs.every((r) => !r.reused), "polls walk iCloud");
});

test("a local change waits for quiet, then syncs against the cached scan", async () => {
  const h = harness();
  h.scheduler.start();
  await h.timers.advance(1_000);
  await h.timers.advance(40_000); // clear of the minimum interval
  h.scheduler.localChange("a.md");
  await h.timers.advance(2_000);
  h.scheduler.localChange("a.md"); // still typing
  await h.timers.advance(2_000);
  assert.equal(h.runs.length, 1, "not yet: the quiet period restarted");
  await h.timers.advance(1_500);
  assert.equal(h.runs.length, 2);
  assert.equal(h.runs[1]!.trigger, "local");
  assert.equal(h.runs[1]!.reused, true);
});

test("local-change cycles are rate limited but the change is never dropped", async () => {
  const h = harness();
  h.scheduler.start();
  await h.timers.advance(40_000);
  h.scheduler.localChange("a.md");
  await h.timers.advance(3_000);
  h.scheduler.localChange("b.md");
  await h.timers.advance(3_000);
  const locals = () => h.runs.filter((r) => r.trigger === "local");
  assert.equal(locals().length, 1, "second change held back by the minimum interval");
  await h.timers.advance(30_000);
  assert.equal(locals().length, 2, "then it runs");
  assert.ok(locals()[1]!.at - locals()[0]!.at >= 30_000);
});

test("a change during a running cycle runs after it", async () => {
  const h = harness({ cycleMs: 20_000 });
  h.scheduler.start();
  await h.timers.advance(1_000); // the start cycle is running
  h.scheduler.localChange("a.md");
  await h.timers.advance(4_000);
  assert.equal(h.runs.length, 1);
  await h.timers.advance(20_000);
  assert.equal(h.runs.length, 2, "deferred until the cycle ended, not dropped");
  assert.equal(h.runs[1]!.trigger, "local");
});

test("the engine's own writes do not trigger a cycle", async () => {
  const h = harness();
  h.setWrites(["downloaded.md"]);
  h.scheduler.start();
  await h.timers.advance(10); // the start cycle wrote downloaded.md; Obsidian reports it at once
  h.scheduler.localChange("downloaded.md");
  await h.timers.advance(10_000);
  assert.equal(h.runs.length, 1, "the echo of our own write was ignored");
  await h.timers.advance(30_000);
  h.scheduler.localChange("typed.md");
  await h.timers.advance(4_000);
  assert.equal(h.runs.length, 2);
});

test("an echo only lasts a few seconds", async () => {
  const h = harness();
  h.setWrites(["x.md"]);
  h.scheduler.start();
  await h.timers.advance(40_000); // echo window long over
  h.scheduler.localChange("x.md");
  await h.timers.advance(4_000);
  assert.equal(h.runs.length, 2, "a later edit to the same file is the user's");
});

test("pause stops new cycles; resume catches up with a full one", async () => {
  const h = harness();
  h.scheduler.start();
  await h.timers.advance(1_000);
  h.scheduler.pause();
  h.scheduler.localChange("a.md");
  await h.timers.advance(300_000);
  assert.equal(h.runs.length, 1, "nothing while paused, not even polls");
  h.scheduler.resume();
  await h.timers.advance(1_000);
  assert.equal(h.runs.length, 2);
  assert.equal(h.runs[1]!.trigger, "manual");
  assert.equal(h.runs[1]!.reused, false);
});

test("sync now during a cycle is queued as a full cycle", async () => {
  const h = harness({ cycleMs: 10_000 });
  h.scheduler.start();
  await h.timers.advance(40_000);
  h.scheduler.localChange("a.md");
  await h.timers.advance(3_500); // local cycle running
  h.scheduler.syncNow();
  h.scheduler.localChange("b.md");
  await h.timers.advance(30_000);
  const triggers = h.runs.map((r) => r.trigger);
  assert.ok(triggers.includes("manual"));
  assert.ok(!h.runs.some((r, i) => i > 0 && r.trigger === "manual" && r.reused));
});

test("stop cancels everything and waits for the running cycle", async () => {
  const h = harness({ cycleMs: 5_000 });
  h.scheduler.start();
  await h.timers.advance(1_000);
  const stopped = h.scheduler.stop();
  await h.timers.advance(10_000);
  await stopped;
  await h.timers.advance(500_000);
  assert.equal(h.runs.length, 1);
});
