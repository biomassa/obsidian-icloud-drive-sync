/**
 * The planner's decision table, including obsisync's review findings as
 * regressions: same-size edits, edits past 4 KB, one-sided deletion guards.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { IgnoreFilter } from "../src/sync/filters.ts";
import { planSync, type PlanInput } from "../src/sync/planner.ts";
import type { Action, PendingDeletion } from "../src/sync/types.ts";
import { B, L, R, baseOf, localScan, remoteScan } from "./sync-helpers.ts";

const filter = new IgnoreFilter();

function plan(partial: Partial<PlanInput> & Pick<PlanInput, "local" | "remote">) {
  const result = planSync({ base: new Map(), pending: new Map(), filter, ...partial });
  if (!result.ok) throw new Error(`unexpected abort: ${JSON.stringify(result.abort)}`);
  return result.plan;
}

const kinds = (actions: Action[]) =>
  actions.map((a) => `${a.kind}:${"key" in a ? a.key : `${a.from}->${a.to}`}`).sort();

/** n tracked files in sync on both sides, so guards see a realistic vault. */
function vault(n: number) {
  const ls = [], rs = [], bs = [];
  for (let i = 0; i < n; i++) {
    const k = `n${i}.md`;
    ls.push(L(k, `note ${i}`, 1000, false));
    rs.push(R(k, `note ${i}`));
    bs.push(B(k, `note ${i}`));
  }
  return { ls, rs, bs };
}

test("unchanged files produce no actions and need no hashing", () => {
  const p = plan({
    base: baseOf(B("a.md", "hello")),
    local: localScan(L("a.md", "hello", 1000, false)),
    remote: remoteScan(R("a.md", "hello")),
  });
  assert.deepEqual(p.actions, []);
});

test("a same-size edit is uploaded (obsisync: '- [ ]' → '- [x]' was never synced)", () => {
  const p = plan({
    base: baseOf(B("todo.md", "- [ ] task")),
    local: localScan(L("todo.md", "- [x] task", 2000)),
    remote: remoteScan(R("todo.md", "- [ ] task")),
  });
  assert.deepEqual(kinds(p.actions), ["upload:todo.md"]);
});

test("an edit past the first 4 KB is uploaded (obsisync hashed only the head)", () => {
  const head = "A".repeat(5000);
  const p = plan({
    base: baseOf(B("long.md", head)),
    local: localScan(L("long.md", head + "\nappended", 2000)),
    remote: remoteScan(R("long.md", head)),
  });
  assert.deepEqual(kinds(p.actions), ["upload:long.md"]);
});

test("racy clean: same size and mtime, but hashed in the same tick, is re-hashed", () => {
  const racyBase = { ...B("r.md", "aaaa"), hashedAtMs: 1000 + 500 };
  const p = plan({
    base: baseOf(racyBase),
    local: localScan(L("r.md", "bbbb", 1000)), // same size, same mtime, different bytes
    remote: remoteScan(R("r.md", "aaaa")),
  });
  assert.deepEqual(kinds(p.actions), ["upload:r.md"]);
});

test("a racy base with unchanged content is refreshed so the cache is trusted next time", () => {
  const racyBase = { ...B("r.md", "aaaa"), hashedAtMs: 1000 + 500 };
  const p = plan({
    base: baseOf(racyBase),
    local: localScan(L("r.md", "aaaa", 1000)),
    remote: remoteScan(R("r.md", "aaaa")),
  });
  assert.deepEqual(kinds(p.actions), ["refreshBase:r.md"]);
});

test("the planner refuses to guess when a needed hash is missing", () => {
  assert.throws(
    () =>
      plan({
        base: baseOf(B("a.md", "x")),
        local: localScan(L("a.md", "xy", 2000, false)),
        remote: remoteScan(R("a.md", "x")),
      }),
    /needs a hash/,
  );
});

test("remote edits download, including same-size ones", () => {
  const p = plan({
    base: baseOf(B("a.md", "- [ ] t", "e1"), B("b.md", "bbb", "e1")),
    local: localScan(L("a.md", "- [ ] t", 1000, false), L("b.md", "bbb", 1000, false)),
    remote: remoteScan(R("a.md", "- [x] t", "e2"), R("b.md", "bbb", "e1")),
  });
  assert.deepEqual(kinds(p.actions), ["download:a.md"]);
});

test("edits on both sides are a conflict, never a silent overwrite", () => {
  const p = plan({
    base: baseOf(B("a.md", "v1")),
    local: localScan(L("a.md", "v2 local", 2000)),
    remote: remoteScan(R("a.md", "v2 remote", "e2")),
  });
  assert.deepEqual(kinds(p.actions), ["conflict:a.md"]);
});

test("first run: same size is compared by content, different size is a conflict", () => {
  const p = plan({
    local: localScan(L("same.md", "abc"), L("diff.md", "short")),
    remote: remoteScan(R("same.md", "abc"), R("diff.md", "much longer")),
  });
  assert.deepEqual(kinds(p.actions), ["compare:same.md", "conflict:diff.md"]);
});

test("deleted on one side and untouched on the other: the deletion propagates", () => {
  const { ls, rs, bs } = vault(20);
  const p = plan({
    base: baseOf(...bs),
    local: localScan(...ls.filter((l) => l.key !== "n1.md")),
    remote: remoteScan(...rs.filter((r) => r.key !== "n2.md")),
  });
  assert.deepEqual(kinds(p.actions), ["trashLocal:n2.md", "trashRemote:n1.md"]);
});

test("deleted on one side but edited on the other: the edit wins and is kept", () => {
  const { ls, rs, bs } = vault(20);
  const p = plan({
    base: baseOf(...bs),
    local: localScan(...ls.filter((l) => l.key !== "n1.md").map((l) => (l.key === "n2.md" ? L("n2.md", "edited", 2000) : l))),
    remote: remoteScan(...rs.filter((r) => r.key !== "n2.md").map((r) => (r.key === "n1.md" ? R("n1.md", "edited", "e2") : r))),
  });
  assert.deepEqual(kinds(p.actions), ["download:n1.md", "upload:n2.md"]);
});

test("new on one side is copied; gone from both is forgotten", () => {
  const p = plan({
    base: baseOf(B("gone.md", "x")),
    local: localScan(L("mine.md", "m")),
    remote: remoteScan(R("theirs.md", "t")),
  });
  assert.deepEqual(kinds(p.actions), ["download:theirs.md", "forget:gone.md", "upload:mine.md"]);
});

for (const side of ["remote", "local"] as const) {
  test(`bulk guard parks more than 3 deletions vanished from the ${side} side`, () => {
    const { ls, rs, bs } = vault(50);
    const gone = new Set(["n1.md", "n2.md", "n3.md", "n4.md"]);
    const p = plan({
      base: baseOf(...bs),
      local: localScan(...(side === "local" ? ls.filter((l) => !gone.has(l.key)) : ls)),
      remote: remoteScan(...(side === "remote" ? rs.filter((r) => !gone.has(r.key)) : rs)),
    });
    assert.deepEqual(p.actions, [], "nothing is trashed");
    assert.deepEqual(p.parked.map((d) => d.key).sort(), [...gone].sort());
    assert.ok(p.parked.every((d) => d.vanishedFrom === side));
  });

  test(`three deletions from the ${side} side go through without asking`, () => {
    const { ls, rs, bs } = vault(50);
    const gone = new Set(["n1.md", "n2.md", "n3.md"]);
    const p = plan({
      base: baseOf(...bs),
      local: localScan(...(side === "local" ? ls.filter((l) => !gone.has(l.key)) : ls)),
      remote: remoteScan(...(side === "remote" ? rs.filter((r) => !gone.has(r.key)) : rs)),
    });
    assert.equal(p.parked.length, 0);
    assert.equal(p.actions.length, 3);
  });
}

test("a pending question absorbs later deletions, so a shrinking set is still asked about", () => {
  const { ls, rs, bs } = vault(50);
  const pending = new Map<string, PendingDeletion>(
    ["n1.md", "n2.md", "n3.md", "n4.md", "n5.md"].map((k) => [k, { key: k, vanishedFrom: "remote", since: 1 }]),
  );
  // n3..n5 turned out to be present after all; n1 and n2 are still missing.
  const p = plan({
    base: baseOf(...bs),
    local: localScan(...ls),
    remote: remoteScan(...rs.filter((r) => r.key !== "n1.md" && r.key !== "n2.md")),
    pending,
  });
  assert.deepEqual(p.actions, [], "two deletions, but still not applied silently");
  assert.deepEqual(p.parked.map((d) => d.key).sort(), ["n1.md", "n2.md"], "the false alarms cleared themselves");
  assert.ok(p.parked.every((d) => d.since === 1), "the original time is kept");
});

test("confirmed deletions are carried out whatever the threshold", () => {
  const { ls, rs, bs } = vault(50);
  const gone = ["n1.md", "n2.md", "n3.md", "n4.md", "n5.md"];
  const p = plan({
    base: baseOf(...bs),
    local: localScan(...ls),
    remote: remoteScan(...rs.filter((r) => !gone.includes(r.key))),
    options: { confirmedDeletions: new Set(gone) },
  });
  assert.equal(p.parked.length, 0);
  assert.deepEqual(kinds(p.actions), gone.map((k) => `trashLocal:${k}`));
});

test("a folder renamed on the iPhone is 30 local renames, not 30 deletions and downloads", () => {
  const ls = [], rs = [], bs = [];
  for (let i = 0; i < 30; i++) {
    const oldKey = `Projects/p${i}.md`;
    ls.push(L(oldKey, `p${i}`, 1000, false));
    bs.push(B(oldKey, `p${i}`, "e1", 1000, `doc${i}`));
    rs.push(R(`Work/p${i}.md`, `p${i}`, "e2", `doc${i}`)); // moving changes the etag, not the id
  }
  const p = plan({ base: baseOf(...bs), local: localScan(...ls), remote: remoteScan(...rs) });
  assert.equal(p.parked.length, 0);
  assert.equal(p.actions.length, 30);
  assert.ok(p.actions.every((a) => a.kind === "renameLocal"));
});

test("a local rename is a remote move when the content is unique", () => {
  const p = plan({
    base: baseOf(B("old.md", "unique content")),
    local: localScan(L("new.md", "unique content", 2000)),
    remote: remoteScan(R("old.md", "unique content")),
  });
  assert.deepEqual(kinds(p.actions), ["moveRemote:old.md->new.md"]);
});

test("renames are not guessed when content is duplicated or empty", () => {
  const p = plan({
    base: baseOf(B("old1.md", "same"), B("old2.md", "same"), B("empty-old.md", "")),
    local: localScan(L("new1.md", "same"), L("empty-new.md", "")),
    remote: remoteScan(R("old1.md", "same"), R("old2.md", "same"), R("empty-old.md", "")),
  });
  assert.ok(!p.actions.some((a) => a.kind === "moveRemote"));
  assert.deepEqual(kinds(p.actions), [
    "trashRemote:empty-old.md",
    "trashRemote:old1.md",
    "trashRemote:old2.md",
    "upload:empty-new.md",
    "upload:new1.md",
  ]);
});

test("a remote rename is not applied over an unsynced local edit", () => {
  const p = plan({
    base: baseOf(B("old.md", "v1", "e1", 1000, "doc1")),
    local: localScan(L("old.md", "v1 edited here", 2000)),
    remote: remoteScan(R("new.md", "v1", "e2", "doc1")),
  });
  // Both versions survive: the edit is uploaded at the old path, the renamed copy downloaded.
  assert.deepEqual(kinds(p.actions), ["download:new.md", "upload:old.md"]);
});

test("a tracked file that starts matching an ignore pattern is left alone on both sides", () => {
  const p = planSync({
    base: baseOf(B("Archive/old.md", "x"), B("keep.md", "k")),
    local: localScan(L("keep.md", "k", 1000, false)),
    remote: remoteScan(R("keep.md", "k")),
    pending: new Map(),
    filter: new IgnoreFilter(["Archive/"]),
  });
  assert.ok(p.ok);
  assert.deepEqual(p.plan.actions, []);
  assert.deepEqual(p.plan.newlyIgnored, ["Archive/old.md"]);
});

test("a key the local scan refused (case collision) is never trashed remotely", () => {
  const scan = localScan(L("keep.md", "k", 1000, false));
  scan.skipped.push({ key: "note.md", reason: "case collision with Note.md" });
  const p = plan({
    base: baseOf(B("note.md", "n"), B("keep.md", "k")),
    local: scan,
    remote: remoteScan(R("note.md", "n"), R("keep.md", "k")),
  });
  assert.deepEqual(p.actions, []);
});

test("an empty tree against tracked files aborts instead of deleting everything", () => {
  const { ls, rs, bs } = vault(5);
  const noRemote = planSync({ base: baseOf(...bs), local: localScan(...ls), remote: remoteScan(), pending: new Map(), filter });
  assert.deepEqual(noRemote, { ok: false, abort: { reason: "remote-root-empty", tracked: 5 } });
  const noLocal = planSync({ base: baseOf(...bs), local: localScan(), remote: remoteScan(...rs), pending: new Map(), filter });
  assert.deepEqual(noLocal, { ok: false, abort: { reason: "local-root-empty", tracked: 5 } });
});

test("a burst of conflicts asks first; once allowed, it proceeds", () => {
  const ls = [], rs = [];
  for (let i = 0; i < 12; i++) {
    ls.push(L(`c${i}.md`, `local ${i}`));
    rs.push(R(`c${i}.md`, `remote version ${i}`));
  }
  const input = { base: new Map(), local: localScan(...ls), remote: remoteScan(...rs), pending: new Map(), filter };
  const asked = planSync(input);
  assert.equal(asked.ok, false);
  assert.equal(!asked.ok && asked.abort.reason, "too-many-conflicts");
  assert.ok(planSync({ ...input, options: { allowManyConflicts: true } }).ok);
});

test("a touched but unchanged file refreshes the base instead of transferring", () => {
  const p = plan({
    base: baseOf(B("a.md", "same")),
    local: localScan(L("a.md", "same", 5000)),
    remote: remoteScan(R("a.md", "same")),
  });
  assert.deepEqual(kinds(p.actions), ["refreshBase:a.md"]);
});

test("ignore patterns: folders cover their contents; workspaces.json is user data", () => {
  const f = new IgnoreFilter(["Archive/", "*.bak"]);
  assert.equal(f.ignores(".trash/a.md"), true, "obsisync's watcher missed files inside .trash/");
  assert.equal(f.ignores("Archive/deep/x.md"), true);
  assert.equal(f.ignores("notes/x.bak"), true);
  assert.equal(f.ignores(".obsidian/workspace.json"), true);
  assert.equal(f.ignores(".obsidian/workspace.json.conflict3"), true);
  assert.equal(f.ignores(".obsidian/workspaces.json"), false, "saved workspaces must sync");
  assert.equal(f.ignores(".obsidian/workspace 12.json"), true, "iCloud's duplicates");
  assert.equal(f.ignores(".obsidian/workspace-mobile 3.json"), true);
  assert.equal(f.ignores(".obsidian/workspace"), true);
  assert.equal(f.ignores(".obsidian/workspace(1).json"), true);
  assert.equal(f.ignores(".obsidian/app.json"), false);
  assert.equal(f.ignores("Archived.md"), false);
});
