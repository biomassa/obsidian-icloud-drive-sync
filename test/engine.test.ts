/**
 * The executor against in-memory trees: every scenario that lost data in
 * obsisync, plus the races between the scan and the transfer.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { IgnoreFilter } from "../src/sync/filters.ts";
import { SyncEngine, conflictName } from "../src/sync/engine.ts";
import { MemoryStateStore } from "../src/sync/state.ts";
import { Clock, FakeLocal, FakeRemote, str } from "./fakes.ts";

function setup(opts: { concurrency?: number } = {}) {
  const clock = new Clock();
  const local = new FakeLocal(clock);
  const remote = new FakeRemote(clock);
  const store = new MemoryStateStore();
  const make = () =>
    new SyncEngine({
      local,
      remote,
      store,
      filter: new IgnoreFilter(),
      options: { now: clock.now, concurrency: opts.concurrency ?? 1 },
    });
  return { clock, local, remote, store, engine: make(), restart: make };
}

/** A vault of n notes, synced once so both sides and the base agree. */
async function synced(n = 20) {
  const s = setup();
  for (let i = 0; i < n; i++) s.local.put(`n${i}.md`, `note ${i}`);
  const first = await s.engine.runCycle();
  assert.equal(first.status, "ok");
  s.clock.tick(10_000);
  return s;
}

function sameTrees(local: FakeLocal, remote: FakeRemote) {
  const l = Object.fromEntries([...local.files].map(([k, f]) => [k, str(f.data)]));
  const r = Object.fromEntries([...remote.files].map(([k, f]) => [k, str(f.data)]));
  assert.deepEqual(l, r);
}

test("a new vault uploads; later cycles transfer nothing", async () => {
  const s = await synced(5);
  sameTrees(s.local, s.remote);
  // Files hashed in the same tick they were written are re-checked once
  // (racy clean) and the base refreshed, without transferring anything.
  const second = await s.engine.runCycle();
  assert.ok(second.done.every((d) => d.action.kind === "refreshBase"));
  s.clock.tick(10_000);
  const third = await s.engine.runCycle();
  assert.deepEqual(third.done, []);
});

test("same-size edits travel in both directions", async () => {
  const s = await synced();
  s.local.put("n1.md", "NOTE 1"); // same length as "note 1"
  s.remote.put("n2.md", "NOTE 2", s.remote.files.get("n2.md")!.docId);
  await s.engine.runCycle();
  assert.equal(s.remote.get("n1.md"), "NOTE 1");
  assert.equal(s.local.get("n2.md"), "NOTE 2");
});

test("a conflict keeps both versions on both sides", async () => {
  const s = await synced();
  s.local.put("n3.md", "mine");
  s.remote.put("n3.md", "theirs", s.remote.files.get("n3.md")!.docId);
  const r = await s.engine.runCycle();
  const aside = [...s.local.files.keys()].find((k) => k.startsWith("n3 (conflict"));
  assert.ok(aside, "a conflict copy exists");
  assert.equal(s.local.get("n3.md"), "theirs");
  assert.equal(s.local.get(aside!), "mine");
  assert.equal(s.remote.get(aside!), "mine", "the local version reached iCloud too");
  assert.ok(r.localWrites.some((w) => w.key === aside));
  sameTrees(s.local, s.remote);
});

test("identical content on both sides is adopted without a conflict copy", async () => {
  const s = setup();
  s.local.put("a.md", "same");
  s.remote.put("a.md", "same");
  await s.engine.runCycle();
  assert.deepEqual([...s.local.files.keys()], ["a.md"]);
});

test("a failed upload leaves iCloud's copy and the local edit intact, and is retried", async () => {
  const s = await synced();
  s.local.put("n4.md", "edited");
  s.remote.failUpload.add("n4.md");
  const failed = await s.engine.runCycle();
  assert.equal(failed.status, "failed");
  assert.equal(s.remote.get("n4.md"), "note 4", "obsisync deleted this before uploading");
  assert.equal(s.local.get("n4.md"), "edited", "obsisync then deleted the local copy too");
  s.remote.failUpload.clear();
  await s.engine.runCycle();
  assert.equal(s.remote.get("n4.md"), "edited");
});

test("an edit made between the scan and the upload is not lost", async () => {
  const s = await synced();
  s.local.put("n5.md", "first edit");
  s.local.afterScan = () => {
    s.clock.tick(5);
    s.local.put("n5.md", "second edit, typed during the sync");
  };
  const r = await s.engine.runCycle();
  assert.ok(r.skipped.some((x) => x.why.includes("changed during the sync")));
  s.clock.tick(10_000);
  await s.engine.runCycle();
  assert.equal(s.remote.get("n5.md"), "second edit, typed during the sync");
});

test("an edit made while a download runs is not overwritten", async () => {
  const s = await synced();
  s.remote.put("n6.md", "from the phone", s.remote.files.get("n6.md")!.docId);
  s.remote.onDownload = () => {
    s.clock.tick(5);
    s.local.put("n6.md", "typed here meanwhile");
  };
  const r = await s.engine.runCycle();
  assert.ok(r.skipped.length === 1);
  assert.equal(s.local.get("n6.md"), "typed here meanwhile");
  s.clock.tick(10_000);
  await s.engine.runCycle();
  // Next cycle both sides changed: a conflict, so both versions survive.
  const values = [...s.local.files.values()].map((f) => str(f.data));
  assert.ok(values.includes("typed here meanwhile") && values.includes("from the phone"));
});

test("an expired session stops the cycle at once and records nothing", async () => {
  const s = await synced();
  for (let i = 0; i < 10; i++) s.local.put(`n${i}.md`, `edit ${i}`);
  s.remote.authFailAfter = s.remote.calls + 3; // the scan, then two uploads succeed
  const r = await s.engine.runCycle();
  assert.equal(r.status, "aborted");
  assert.equal(r.abort?.reason, "auth-required");
  const uploads = r.done.filter((d) => d.action.kind === "upload").length;
  assert.ok(uploads <= 2, `only the uploads before the failure, got ${uploads}`);
  s.remote.authFailAfter = Infinity;
  await s.engine.runCycle();
  sameTrees(s.local, s.remote);
});

test("an unreadable local folder aborts instead of deleting its files from iCloud", async () => {
  const s = await synced(30);
  s.local.unreadable = true;
  const r = await s.engine.runCycle();
  assert.equal(r.abort?.reason, "local-scan-failed");
  assert.equal(s.remote.files.size, 30, "obsisync trashed all 30 here");
});

test("a truncated iCloud listing aborts instead of deleting local files", async () => {
  const s = await synced(30);
  s.remote.truncated = true;
  const r = await s.engine.runCycle();
  assert.equal(r.abort?.reason, "remote-scan-failed");
  assert.equal(s.local.files.size, 30);
});

test("a deletion question survives a restart and is answered either way", async () => {
  const s = await synced(50);
  for (const k of ["n1.md", "n2.md", "n3.md", "n4.md"]) s.remote.files.delete(k);
  const asked = await s.engine.runCycle();
  assert.equal(asked.parked.length, 4);
  assert.equal(s.local.files.size, 50, "nothing deleted before the answer");

  const after = s.restart();
  assert.equal((await after.pendingDeletions()).length, 4, "restored from the stored state");

  after.confirmDeletions(["n1.md", "n2.md"]);
  await after.restoreDeletions(["n3.md", "n4.md"]);
  const answered = await after.runCycle();
  assert.equal(answered.parked.length, 0);
  assert.equal(s.local.get("n1.md"), undefined);
  assert.ok(s.local.trashed.some((t) => t.key === "n1.md"), "to the trash, not deleted outright");
  assert.equal(s.remote.get("n3.md"), "note 3", "restored ones were copied back to iCloud");
});

test("a false alarm clears itself when the files reappear", async () => {
  const s = await synced(50);
  const saved = new Map([...s.remote.files].filter(([k]) => ["n1.md", "n2.md", "n3.md", "n4.md"].includes(k)));
  for (const k of saved.keys()) s.remote.files.delete(k);
  assert.equal((await s.engine.runCycle()).parked.length, 4);
  for (const [k, f] of saved) s.remote.files.set(k, f);
  const r = await s.engine.runCycle();
  assert.equal(r.parked.length, 0);
  assert.equal((await s.engine.pendingDeletions()).length, 0);
  assert.equal(s.local.files.size, 50);
});

test("a folder renamed on another device is renamed here, with no deletions", async () => {
  const s = setup();
  for (let i = 0; i < 12; i++) s.local.put(`Projects/p${i}.md`, `p${i}`);
  await s.engine.runCycle();
  for (let i = 0; i < 12; i++) s.remote.renameOnOtherDevice(`Projects/p${i}.md`, `Work/p${i}.md`);
  const r = await s.engine.runCycle();
  assert.equal(r.parked.length, 0);
  assert.equal(r.done.length, 12);
  assert.ok([...s.local.files.keys()].every((k) => k.startsWith("Work/")));
  assert.equal(s.local.trashed.length + s.remote.trashed.length, 0);
});

test("a note renamed here is moved on iCloud rather than re-uploaded", async () => {
  const s = await synced();
  s.local.move("n7.md", "Renamed/seven.md");
  const docBefore = s.remote.files.get("n7.md")!.docId;
  await s.engine.runCycle();
  assert.equal(s.remote.get("Renamed/seven.md"), "note 7");
  assert.equal(s.remote.files.get("Renamed/seven.md")!.docId, docBefore, "same document, moved");
  assert.equal(s.remote.trashed.length, 0);
});

test("conflict names are unique and keep the extension", () => {
  const when = new Date(2026, 8, 29, 14, 30);
  const taken = new Set(["a/b (conflict 2026-09-29 1430).md"]);
  assert.equal(conflictName("a/b.md", when, (k) => taken.has(k)), "a/b (conflict 2026-09-29 1430 2).md");
  assert.equal(conflictName("README", when, () => false), "README (conflict 2026-09-29 1430)");
});

test("parallel transfers reach the same result", async () => {
  const s = setup({ concurrency: 4 });
  for (let i = 0; i < 40; i++) s.local.put(`f${i}.md`, `c${i}`);
  for (let i = 0; i < 40; i++) s.remote.put(`g${i}.md`, `d${i}`);
  await s.engine.runCycle();
  sameTrees(s.local, s.remote);
  assert.equal(s.local.files.size, 80);
});
