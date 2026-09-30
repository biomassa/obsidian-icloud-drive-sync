/** The persistent activity log, against a real temporary folder. */
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, readFile, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { PersistentLog } from "../src/plugin/log-store.ts";

const tmp = () => mkdtemp(join(tmpdir(), "icloudsync-log-"));

test("keeps the latest 1000 entries across a restart", async () => {
  const path = join(await tmp(), "log.jsonl");
  const log = new PersistentLog(path, { limit: 1000, debounceMs: 60_000 });
  for (let i = 0; i < 1005; i++) log.add({ at: i, level: "info", message: `line ${i}` });
  await log.flush();
  const again = new PersistentLog(path, { limit: 1000 });
  await again.load();
  assert.equal(again.entries.length, 1000);
  assert.equal(again.entries[0]!.message, "line 5");
  assert.equal(again.entries[999]!.message, "line 1004");
});

test("the file is readable only by this user", { skip: process.platform === "win32" }, async () => {
  const path = join(await tmp(), "log.jsonl");
  const log = new PersistentLog(path);
  log.add({ at: 1, level: "warn", message: "x" });
  await log.flush();
  assert.equal((await stat(path)).mode & 0o777, 0o600);
});

test("clear empties the log on disk as well", async () => {
  const path = join(await tmp(), "log.jsonl");
  const log = new PersistentLog(path);
  log.add({ at: 1, level: "error", message: "boom" });
  await log.flush();
  await log.clear();
  assert.equal(await readFile(path, "utf8"), "");
  const again = new PersistentLog(path);
  await again.load();
  assert.equal(again.entries.length, 0);
});

test("a torn or foreign line is skipped, not fatal", async () => {
  const path = join(await tmp(), "log.jsonl");
  await writeFile(path, '{"at":1,"level":"info","message":"ok"}\n{"at":2,"lev\nnot json\n{"at":3,"level":"bogus","message":"x"}\n');
  const log = new PersistentLog(path);
  await log.load();
  assert.deepEqual(log.entries.map((e) => e.message), ["ok"]);
});

test("entries logged before loading are kept after it", async () => {
  const path = join(await tmp(), "log.jsonl");
  await writeFile(path, '{"at":1,"level":"info","message":"from last run"}\n');
  const log = new PersistentLog(path);
  log.add({ at: 2, level: "info", message: "this run" });
  await log.load();
  assert.deepEqual(log.entries.map((e) => e.message), ["from last run", "this run"]);
});
