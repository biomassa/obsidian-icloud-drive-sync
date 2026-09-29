/** NodeLocalFs against a real temporary folder. */
import { test } from "node:test";
import assert from "node:assert/strict";
import { chmod, mkdir, mkdtemp, readFile, readdir, stat, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { IgnoreFilter } from "../src/sync/filters.ts";
import { NodeLocalFs } from "../src/sync/node-local.ts";

async function vault() {
  const root = await mkdtemp(join(tmpdir(), "icloudsync-local-"));
  await mkdir(join(root, ".obsidian"));
  await mkdir(join(root, "Notes", "Deep"), { recursive: true });
  await writeFile(join(root, "Notes", "a.md"), "alpha");
  await writeFile(join(root, "Notes", "Deep", "b.md"), "beta");
  await writeFile(join(root, ".obsidian", "workspace.json"), "{}");
  await writeFile(join(root, ".obsidian", "app.json"), "{}");
  return { root, fs: new NodeLocalFs({ root, filter: new IgnoreFilter() }) };
}

test("scan returns POSIX keys, skips ignored files, and stamps inode and ctime", async () => {
  const { fs } = await vault();
  const scan = await fs.scan();
  assert.deepEqual([...scan.entries.keys()].sort(), [".obsidian/app.json", "Notes/Deep/b.md", "Notes/a.md"]);
  const a = scan.entries.get("Notes/a.md")!;
  assert.equal(a.size, 5);
  assert.ok(a.ino && a.ctimeMs && a.mtimeMs);
});

test("an unreadable folder fails the scan instead of vanishing from it", { skip: process.getuid?.() === 0 }, async () => {
  const { root, fs } = await vault();
  await chmod(join(root, "Notes", "Deep"), 0);
  try {
    await assert.rejects(fs.scan(), /EACCES|permission/i);
  } finally {
    await chmod(join(root, "Notes", "Deep"), 0o755);
  }
});

test("a backslash in a Linux file name is part of the name, not a separator", { skip: process.platform === "win32" }, async () => {
  const { root, fs } = await vault();
  await writeFile(join(root, "weird\\name.md"), "w");
  const scan = await fs.scan();
  assert.ok(scan.entries.has("weird\\name.md"));
  assert.equal(new TextDecoder().decode(await fs.read("weird\\name.md")), "w");
});

test("NFD names from a Mac get NFC keys but keep their real name for I/O", async () => {
  const { root, fs } = await vault();
  const nfd = "Café.md";
  await writeFile(join(root, nfd), "c");
  const scan = await fs.scan();
  assert.ok(scan.entries.has("Café.md"));
  assert.equal(new TextDecoder().decode(await fs.read("Café.md")), "c");
});

test("symlinks and case collisions are skipped — and the tracked name wins", async () => {
  const { root, fs } = await vault();
  await symlink(join(root, "Notes", "a.md"), join(root, "link.md"));
  await writeFile(join(root, "Notes", "A.md"), "upper");
  const scan = await fs.scan(new Set(["Notes/a.md"]));
  assert.ok(scan.entries.has("Notes/a.md"), "the tracked file is kept");
  assert.ok(!scan.entries.has("Notes/A.md"));
  const reasons = Object.fromEntries(scan.skipped.map((s) => [s.key, s.reason]));
  assert.match(reasons["link.md"]!, /symbolic link/);
  assert.match(reasons["Notes/A.md"]!, /letter case/);
});

test("write is atomic, sets the mtime, and leaves no temporary file", async () => {
  const { root, fs } = await vault();
  const mtime = Date.UTC(2025, 0, 2, 3, 4, 5);
  const stamp = await fs.write("New/Folder/c.md", new TextEncoder().encode("gamma"), mtime);
  assert.equal(await readFile(join(root, "New", "Folder", "c.md"), "utf8"), "gamma");
  assert.equal(Math.round(stamp.mtimeMs), mtime);
  assert.deepEqual(await readdir(join(root, "New", "Folder")), ["c.md"]);
  const before = (await stat(join(root, "Notes", "a.md"), { bigint: true })).ino;
  await fs.scan();
  await fs.write("Notes/a.md", new TextEncoder().encode("replaced"));
  const after = (await stat(join(root, "Notes", "a.md"), { bigint: true })).ino;
  assert.notEqual(after, before, "replaced via rename, not rewritten in place");
});

test("trash moves into the vault's .trash, never deletes", async () => {
  const { root, fs } = await vault();
  await fs.scan();
  await fs.trash("Notes/a.md");
  await writeFile(join(root, "Notes", "a.md"), "again");
  await fs.scan();
  await fs.trash("Notes/a.md");
  assert.deepEqual((await readdir(join(root, ".trash", "Notes"))).sort(), ["a 2.md", "a.md"]);
  const rescanned = await fs.scan();
  assert.ok(![...rescanned.entries.keys()].some((k) => k.startsWith(".trash/")), ".trash is never synced");
});

test("rename refuses to overwrite, and stat reports a missing file as null", async () => {
  const { fs } = await vault();
  await fs.scan();
  await assert.rejects(fs.rename("Notes/a.md", "Notes/Deep/b.md"), /already exists/);
  await fs.rename("Notes/a.md", "Moved/a.md");
  assert.equal(await fs.stat("Notes/a.md"), null);
  assert.ok(await fs.stat("Moved/a.md"));
});
