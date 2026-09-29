/**
 * The engine's LocalFs on the real filesystem, via Node's fs.
 *
 * - The scan throws if any folder cannot be read. obsisync's os.walk skipped
 *   unreadable folders silently, so their files looked deleted and were
 *   removed from iCloud (reproduced in its review: 30 of 30).
 * - Keys translate only the platform's own separator: a backslash is a legal
 *   character in a Linux file name, and replacing it blindly corrupts it.
 * - Anything the engine must not act on — symlinks, special files, names that
 *   collide by case or by Unicode normalization — is reported as skipped, and
 *   the planner leaves skipped keys alone rather than reading them as deleted.
 * - Writes go to a temporary file in the same folder and are renamed into
 *   place, so a crash never leaves a half-written note.
 */
import { randomBytes } from "node:crypto";
import { lstat, mkdir, readdir, readFile, rename, stat, utimes, writeFile, rm } from "node:fs/promises";
import { join, relative, sep, dirname } from "node:path";
import type { BigIntStats } from "node:fs";

import { caseCollisions, toKey, type IgnoreFilter } from "./filters.ts";
import type { LocalEntry, LocalFs, LocalScan, LocalStamp } from "./types.ts";

function stampOf(st: BigIntStats): LocalStamp {
  return {
    size: Number(st.size),
    // Microsecond precision survives the conversion to a double; nanoseconds would not.
    mtimeMs: Number(st.mtimeNs / 1000n) / 1000,
    ctimeMs: Number(st.ctimeNs / 1000n) / 1000,
    ino: st.ino.toString(),
  };
}

function isMissing(e: unknown): boolean {
  const code = (e as NodeJS.ErrnoException).code;
  return code === "ENOENT" || code === "ENOTDIR";
}

/** Where a file goes when the engine removes it. Must be recoverable. */
export type TrashFn = (absolutePath: string, key: string) => Promise<void>;

export class NodeLocalFs implements LocalFs {
  readonly root: string;
  private readonly filter: IgnoreFilter;
  private readonly trashFn: TrashFn;
  /** key → path relative to the root, as it exists on disk (may be NFD). */
  private names = new Map<string, string>();

  constructor(args: { root: string; filter: IgnoreFilter; trash?: TrashFn }) {
    this.root = args.root;
    this.filter = args.filter;
    this.trashFn = args.trash ?? ((abs, key) => this.vaultTrash(abs, key));
  }

  /** Obsidian's own convention: `<vault>/.trash/`, which is never synced. */
  private async vaultTrash(absolutePath: string, key: string): Promise<void> {
    let target = join(this.root, ".trash", ...key.split("/"));
    for (let n = 2; await this.exists(target); n++) {
      const dot = target.lastIndexOf(".");
      const slash = target.lastIndexOf(sep);
      target = dot > slash ? `${target.slice(0, dot)} ${n}${target.slice(dot)}` : `${target} ${n}`;
    }
    await mkdir(dirname(target), { recursive: true });
    await rename(absolutePath, target);
  }

  private async exists(p: string): Promise<boolean> {
    try {
      await lstat(p);
      return true;
    } catch (e) {
      if (isMissing(e)) return false;
      throw e;
    }
  }

  private toKeyFromRelative(rel: string): string {
    // Only the platform separator: "\" is an ordinary character on Linux.
    return toKey(sep === "/" ? rel : rel.split(sep).join("/"));
  }

  private abs(key: string): string {
    const name = this.names.get(key) ?? key;
    return join(this.root, ...name.split("/"));
  }

  async scan(tracked?: ReadonlySet<string>): Promise<LocalScan> {
    const entries = new Map<string, LocalEntry>();
    const skipped: LocalScan["skipped"] = [];
    const names = new Map<string, string>();
    const normalizedTwice = new Set<string>();

    const walk = async (dir: string): Promise<void> => {
      // Deliberately no try/catch: an unreadable folder must fail the scan.
      const dirents = await readdir(dir, { withFileTypes: true });
      for (const d of dirents) {
        const absPath = join(dir, d.name);
        const rel = relative(this.root, absPath);
        const key = this.toKeyFromRelative(rel);
        if (this.filter.ignores(key)) continue;
        if (d.isDirectory()) {
          await walk(absPath);
        } else if (d.isFile()) {
          let st: BigIntStats;
          try {
            st = await stat(absPath, { bigint: true });
          } catch (e) {
            if (isMissing(e)) continue; // deleted while scanning: genuinely gone
            throw e;
          }
          if (entries.has(key)) {
            normalizedTwice.add(key);
            continue;
          }
          entries.set(key, { key, name: rel.split(sep).join("/"), ...stampOf(st) });
          names.set(key, rel.split(sep).join("/"));
        } else {
          // Symlinks, sockets, devices: never followed, never synced, never "deleted".
          skipped.push({ key, reason: d.isSymbolicLink() ? "symbolic link" : "not a regular file" });
        }
      }
    };
    await walk(this.root);

    for (const key of normalizedTwice) {
      entries.delete(key);
      names.delete(key);
      skipped.push({ key, reason: "two files here normalize to this name (NFC/NFD)" });
    }
    for (const [key, kept] of caseCollisions(entries.keys(), tracked)) {
      entries.delete(key);
      names.delete(key);
      skipped.push({ key, reason: `differs only in letter case from ${kept}, which iPhones and Macs cannot hold side by side` });
    }
    this.names = names;
    return { entries, skipped };
  }

  async read(key: string): Promise<Uint8Array> {
    return new Uint8Array(await readFile(this.abs(key)));
  }

  async stat(key: string): Promise<LocalStamp | null> {
    try {
      return stampOf(await stat(this.abs(key), { bigint: true }));
    } catch (e) {
      if (isMissing(e)) return null;
      throw e;
    }
  }

  async write(key: string, data: Uint8Array, mtimeMs?: number): Promise<LocalStamp> {
    const target = this.abs(key);
    await mkdir(dirname(target), { recursive: true });
    const name = target.slice(target.lastIndexOf(sep) + 1);
    const tmp = join(dirname(target), `.icloudsync-tmp-${randomBytes(6).toString("hex")}-${name}`);
    try {
      await writeFile(tmp, data);
      if (mtimeMs !== undefined) await utimes(tmp, new Date(), new Date(mtimeMs));
      await rename(tmp, target);
    } catch (e) {
      await rm(tmp, { force: true });
      throw e;
    }
    if (!this.names.has(key)) this.names.set(key, key);
    return stampOf(await stat(target, { bigint: true }));
  }

  async rename(from: string, to: string): Promise<void> {
    const source = this.abs(from);
    const target = join(this.root, ...to.split("/"));
    if (await this.exists(target)) throw new Error(`cannot rename ${from}: ${to} already exists`);
    await mkdir(dirname(target), { recursive: true });
    await rename(source, target);
    this.names.delete(from);
    this.names.set(to, to);
  }

  async trash(key: string): Promise<void> {
    await this.trashFn(this.abs(key), key);
    this.names.delete(key);
  }
}
