/**
 * Randomized two-sided test: random user activity on both sides, random
 * failures and mid-cycle edits, then after every cycle:
 *
 *   No unsynced version is ever lost. Every file whose content differs from
 *   what was last synced at its path — an edit, on either side, that the sync
 *   has not yet carried across — must afterwards still exist somewhere: as a
 *   file on either side, a conflict copy, or in either trash.
 *
 * A synced version may legitimately disappear (the other side replaced it),
 * so it is not required to survive. At the end, with activity stopped and
 * pending deletions answered, both sides must converge to identical trees.
 *
 * This is the class of test that would have caught obsisync's 4 KB hash and
 * same-size shortcut: most edits here keep the file's size.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { IgnoreFilter } from "../src/sync/filters.ts";
import { SyncEngine, sha256 } from "../src/sync/engine.ts";
import { MemoryStateStore, parseState } from "../src/sync/state.ts";
import { Clock, FakeLocal, FakeRemote, str, text } from "./fakes.ts";

function prng(seed: number) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const FOLDERS = ["", "A/", "B/sub/"];
const NAMES = ["a.md", "b.md", "c.md", "d.canvas", "e.md"];

function runScenario(seed: number, rounds: number) {
  const rnd = prng(seed);
  const pick = <T>(xs: T[]): T => xs[Math.floor(rnd() * xs.length)]!;
  const chance = (p: number) => rnd() < p;
  let counter = 0;
  // Fixed-width content, so most edits keep the file's size exactly.
  const content = () => (chance(0.85) ? `v${String(++counter).padStart(7, "0")}` : `version ${++counter} ${"x".repeat(Math.floor(rnd() * 20))}`);
  const randomKey = () => pick(FOLDERS) + pick(NAMES);

  const clock = new Clock();
  const local = new FakeLocal(clock);
  const remote = new FakeRemote(clock);
  const store = new MemoryStateStore();
  const engine = new SyncEngine({
    local,
    remote,
    store,
    filter: new IgnoreFilter(),
    log: process.env.SYNC_DEBUG ? (lvl, m) => console.log(`    [${lvl}] ${m}`) : undefined,
    options: { now: clock.now, concurrency: 1 + Math.floor(rnd() * 3), deletionThreshold: 3, conflictThreshold: 1000 },
  });

  const everywhere = () => {
    const all = new Set<string>();
    for (const f of local.files.values()) all.add(sha256(f.data));
    for (const f of remote.files.values()) all.add(sha256(f.data));
    for (const t of local.trashed) all.add(sha256(t.data));
    for (const t of remote.trashed) all.add(sha256(t.data));
    return all;
  };

  const unsyncedVersions = async () => {
    const base = store.text ? parseState(store.text).base : new Map();
    const required = new Map<string, string>(); // hash → description
    for (const [k, f] of local.files) {
      const h = sha256(f.data);
      if (base.get(k)?.hash !== h) required.set(h, `local ${k}="${str(f.data)}"`);
    }
    for (const [k, f] of remote.files) {
      const h = sha256(f.data);
      if (base.get(k)?.hash !== h) required.set(h, `remote ${k}="${str(f.data)}"`);
    }
    return required;
  };

  const userActivity = () => {
    for (let i = Math.floor(rnd() * 4); i > 0; i--) {
      const keys = [...local.files.keys()];
      const op = rnd();
      if (op < 0.35 || !keys.length) {
        const k = randomKey();
        if (!local.files.has(k)) local.put(k, content());
      } else if (op < 0.75) local.put(pick(keys), content());
      else if (op < 0.9) local.files.delete(pick(keys));
      else {
        const from = pick(keys);
        const to = randomKey();
        if (!local.files.has(to)) local.move(from, to);
      }
    }
    for (let i = Math.floor(rnd() * 4); i > 0; i--) {
      const keys = [...remote.files.keys()];
      const op = rnd();
      if (op < 0.35 || !keys.length) {
        const k = randomKey();
        if (!remote.files.has(k)) remote.put(k, content());
      } else if (op < 0.75) {
        const k = pick(keys);
        remote.put(k, content(), remote.files.get(k)!.docId);
      } else if (op < 0.9) remote.files.delete(pick(keys));
      else {
        const from = pick(keys);
        const to = randomKey();
        if (!remote.files.has(to)) remote.renameOnOtherDevice(from, to);
      }
    }
  };

  return {
    async run() {
      for (let round = 0; round < rounds; round++) {
        userActivity();
        // Sometimes no time passes at all, to exercise same-tick (racy) edits.
        clock.tick(chance(0.3) ? 0 : Math.floor(rnd() * 5000));

        const required = await unsyncedVersions();
        const midCycle = new Set<string>();
        if (chance(0.15)) {
          local.afterScan = () => {
            const keys = [...local.files.keys()];
            if (!keys.length) return;
            const k = pick(keys);
            const c = content();
            // The user supersedes their own version; the new one is what must survive.
            required.delete(sha256(local.files.get(k)!.data));
            midCycle.delete(sha256(local.files.get(k)!.data));
            if (process.env.SYNC_DEBUG) console.log(`    afterScan edits ${k} = ${c}`);
            local.put(k, c);
            midCycle.add(sha256(text(c)));
          };
        }
        if (chance(0.1)) {
          remote.onDownload = (key) => {
            const c = content();
            const old = local.files.get(key);
            if (old) {
              required.delete(sha256(old.data));
              midCycle.delete(sha256(old.data));
            }
            if (process.env.SYNC_DEBUG) console.log(`    onDownload(${key}) writes local ${key} = ${c}`);
            local.put(key, c);
            midCycle.add(sha256(text(c)));
          };
        }
        if (chance(0.15)) {
          remote.afterScan = () => {
            const keys = [...remote.files.keys()];
            if (!keys.length) return;
            const k = pick(keys);
            const c = content();
            required.delete(sha256(remote.files.get(k)!.data));
            midCycle.delete(sha256(remote.files.get(k)!.data));
            remote.put(k, c, remote.files.get(k)!.docId); // another device, mid-cycle
            midCycle.add(sha256(text(c)));
          };
        }
        if (chance(0.1)) {
          const keys = [...local.files.keys()];
          if (keys.length) remote.failUpload.add(pick(keys));
        }

        if (process.env.SYNC_DEBUG) {
          console.log(`round ${round} t=${clock.t}`);
          console.log("  local ", JSON.stringify([...local.files].map(([k, f]) => `${k}=${str(f.data)}@${f.mtimeMs}`)));
          console.log("  remote", JSON.stringify([...remote.files].map(([k, f]) => `${k}=${str(f.data)}#${f.docId}`)));
          console.log("  fail", [...remote.failUpload], "afterScan", !!local.afterScan, "onDownload", !!remote.onDownload);
        }
        const result = await engine.runCycle();
        remote.failUpload.clear();
        remote.afterScan = null;
        local.afterScan = null;
        remote.onDownload = null;
        assert.notEqual(result.status === "aborted" && result.abort?.reason, "local-scan-failed");

        // The base never claims a false sync: where it matches both sides'
        // current state, the two sides must hold the same bytes.
        const base = parseState(store.text!).base;
        for (const [k, b] of base) {
          const lf = local.files.get(k);
          const rf = remote.files.get(k);
          if (!lf || !rf) continue;
          if (sha256(lf.data) === b.hash && rf.etag === b.remoteEtag) {
            assert.equal(
              str(rf.data),
              str(lf.data),
              `seed ${seed} round ${round}: base records ${k} as synced, but the sides differ`,
            );
          }
        }

        if (process.env.SYNC_TRACE) {
          const k = process.env.SYNC_TRACE;
          const lf = local.files.get(k), rf = remote.files.get(k), b = base.get(k);
          console.log(`  after round ${round}: local=${lf ? `${str(lf.data)}@${lf.mtimeMs}` : "-"} remote=${rf ? `${str(rf.data)}@${rf.modifiedMs}/${rf.etag}` : "-"} base=${b ? `mtime ${b.localMtimeMs} hashedAt ${b.hashedAtMs} etag ${b.remoteEtag} hashOK=${lf ? sha256(lf.data) === b.hash : "-"}` : "-"}`);
        }

        const present = everywhere();
        for (const [hash, what] of required) {
          assert.ok(present.has(hash), `seed ${seed} round ${round}: lost unsynced ${what}`);
        }
        for (const hash of midCycle) {
          assert.ok(present.has(hash), `seed ${seed} round ${round}: lost an edit made during the cycle`);
        }

        if (chance(0.3)) {
          const pending = await engine.pendingDeletions();
          if (chance(0.5)) engine.confirmDeletions(pending.map((p) => p.key));
          else await engine.restoreDeletions(pending.map((p) => p.key));
        }
      }

      // Quiet period: answer everything, let the engine settle, then compare.
      for (let i = 0; i < 8; i++) {
        clock.tick(10_000);
        engine.confirmDeletions((await engine.pendingDeletions()).map((p) => p.key));
        const r = await engine.runCycle();
        if (process.env.SYNC_DEBUG) {
          console.log(`quiet ${i}: status=${r.status} abort=${JSON.stringify(r.abort)} done=${r.done.length} parked=${r.parked.length} skipped=${r.skipped.map((s) => s.why)} errors=${JSON.stringify(r.errors.map((e) => e.error))}`);
        }
        if (r.status === "aborted" && r.abort && "reason" in r.abort && r.abort.reason.endsWith("root-empty")) {
          break; // everything was deleted on one side: nothing left to converge
        }
        if (!r.done.length && !r.parked.length && !r.skipped.length) break;
      }
      const l = Object.fromEntries([...local.files].map(([k, f]) => [k, str(f.data)]).sort());
      const r = Object.fromEntries([...remote.files].map(([k, f]) => [k, str(f.data)]).sort());
      if (Object.keys(l).length && Object.keys(r).length) {
        assert.deepEqual(l, r, `seed ${seed}: the two sides did not converge`);
      }
    },
  };
}

test("randomized: no unsynced version is ever lost, and both sides converge", async () => {
  const seeds = Number(process.env.SYNC_SEEDS ?? 300);
  const first = Number(process.env.SYNC_SEED ?? 1);
  for (let seed = first; seed < first + seeds; seed++) {
    await runScenario(seed, 25).run();
  }
});
