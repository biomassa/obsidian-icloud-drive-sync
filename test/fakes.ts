/**
 * In-memory local and remote file trees with the semantics the engine relies
 * on, plus hooks for injecting failures and concurrent edits.
 */
import { AuthRequiredError } from "../src/icloud/errors.ts";
import { IgnoreFilter, caseCollisions } from "../src/sync/filters.ts";
import type { LocalEntry, LocalFs, LocalScan, Remote, RemoteEntry, RemoteScan } from "../src/sync/types.ts";

export const text = (s: string) => new TextEncoder().encode(s);
export const str = (b: Uint8Array) => new TextDecoder().decode(b);

export class Clock {
  t = 1_000_000;
  now = () => this.t;
  tick(ms = 1000) {
    this.t += ms;
  }
}

interface LocalFile {
  data: Uint8Array;
  mtimeMs: number;
  ctimeMs: number;
  ino: number;
}

let nextIno = 1;

export class FakeLocal implements LocalFs {
  files = new Map<string, LocalFile>();
  trashed: { key: string; data: Uint8Array }[] = [];
  unreadable = false;
  /** Runs once after the next scan: simulates the user editing mid-cycle. */
  afterScan: (() => void) | null = null;
  readonly clock: Clock;
  readonly filter: IgnoreFilter;

  constructor(clock: Clock, filter = new IgnoreFilter()) {
    this.clock = clock;
    this.filter = filter;
  }

  /** A user write: editors save via a new file, so a new inode, as on disk. */
  put(key: string, content: string, mtimeMs = this.clock.now()) {
    this.files.set(key, { data: text(content), mtimeMs, ctimeMs: this.clock.now(), ino: nextIno++ });
  }

  /** A user rename: same inode, new ctime, mtime untouched. */
  move(from: string, to: string) {
    const f = this.files.get(from)!;
    this.files.delete(from);
    this.files.set(to, { ...f, ctimeMs: this.clock.now() });
  }

  get(key: string): string | undefined {
    const f = this.files.get(key);
    return f && str(f.data);
  }

  async scan(): Promise<LocalScan> {
    if (this.unreadable) throw new Error("EACCES: permission denied, scandir 'Projects'");
    const entries = new Map<string, LocalEntry>();
    for (const [key, f] of this.files) {
      if (this.filter.ignores(key)) continue;
      entries.set(key, { key, name: key, size: f.data.length, mtimeMs: f.mtimeMs, ctimeMs: f.ctimeMs, ino: f.ino });
    }
    const skipped: LocalScan["skipped"] = [];
    for (const [key, kept] of caseCollisions(entries.keys())) {
      entries.delete(key);
      skipped.push({ key, reason: `case collision with ${kept}` });
    }
    const hook = this.afterScan;
    this.afterScan = null;
    hook?.();
    return { entries, skipped };
  }

  async read(key: string): Promise<Uint8Array> {
    const f = this.files.get(key);
    if (!f) throw new Error(`ENOENT: ${key}`);
    return f.data.slice();
  }

  async stat(key: string) {
    const f = this.files.get(key);
    return f ? { size: f.data.length, mtimeMs: f.mtimeMs, ctimeMs: f.ctimeMs, ino: f.ino } : null;
  }

  async write(key: string, data: Uint8Array, mtimeMs?: number) {
    // Atomic write via a temp file: a new inode, ctime now.
    const f = { data: data.slice(), mtimeMs: mtimeMs ?? this.clock.now(), ctimeMs: this.clock.now(), ino: nextIno++ };
    this.files.set(key, f);
    return { size: f.data.length, mtimeMs: f.mtimeMs, ctimeMs: f.ctimeMs, ino: f.ino };
  }

  async rename(from: string, to: string) {
    const f = this.files.get(from);
    if (!f) throw new Error(`ENOENT: ${from}`);
    if (this.files.has(to)) throw new Error(`EEXIST: ${to}`);
    this.files.delete(from);
    this.files.set(to, { ...f, ctimeMs: this.clock.now() });
  }

  async trash(key: string) {
    const f = this.files.get(key);
    if (!f) throw new Error(`ENOENT: ${key}`);
    this.files.delete(key);
    this.trashed.push({ key, data: f.data });
  }
}

interface RemoteFile {
  data: Uint8Array;
  etag: string;
  docId: string;
  modifiedMs: number;
}

export class FakeRemote implements Remote {
  files = new Map<string, RemoteFile>();
  trashed: { key: string; data: Uint8Array }[] = [];
  private seq = 0;
  failUpload = new Set<string>();
  failDownload = new Set<string>();
  authFailAfter = Infinity;
  truncated = false;
  calls = 0;
  /** Runs once during the next download: simulates a concurrent local edit. */
  onDownload: ((key: string) => void) | null = null;
  readonly clock: Clock;
  readonly filter: IgnoreFilter;

  constructor(clock: Clock, filter = new IgnoreFilter()) {
    this.clock = clock;
    this.filter = filter;
  }

  private nextEtag() {
    return `etag${++this.seq}`;
  }

  put(key: string, content: string, docId = `doc-${++this.seq}`) {
    this.files.set(key, { data: text(content), etag: this.nextEtag(), docId, modifiedMs: this.clock.now() });
  }

  get(key: string): string | undefined {
    const f = this.files.get(key);
    return f && str(f.data);
  }

  /** Another device renames a file: same document, new etag. */
  renameOnOtherDevice(from: string, to: string) {
    const f = this.files.get(from)!;
    this.files.delete(from);
    this.files.set(to, { ...f, etag: this.nextEtag() });
  }

  private tick() {
    if (++this.calls > this.authFailAfter) throw new AuthRequiredError("session expired");
  }

  private entry(key: string, f: RemoteFile): RemoteEntry {
    return { key, size: f.data.length, modifiedMs: f.modifiedMs, etag: f.etag, docId: f.docId, handle: key };
  }

  async scan(): Promise<RemoteScan> {
    this.tick();
    if (this.truncated) throw new Error("listing of Projects returned 3 of 30 items");
    const entries = new Map<string, RemoteEntry>();
    for (const [key, f] of this.files) if (!this.filter.ignores(key)) entries.set(key, this.entry(key, f));
    return { entries };
  }

  async download(entry: RemoteEntry): Promise<Uint8Array> {
    this.tick();
    if (this.failDownload.has(entry.key)) throw new Error(`network error downloading ${entry.key}`);
    const f = this.files.get(entry.key);
    if (!f) throw new Error(`gone: ${entry.key}`);
    const hook = this.onDownload;
    this.onDownload = null;
    hook?.(entry.key);
    return f.data.slice();
  }

  async upload(key: string, data: Uint8Array, mtimeMs: number, existing?: RemoteEntry): Promise<RemoteEntry> {
    this.tick();
    // Upload first, replace second: a failure leaves the old copy intact.
    if (this.failUpload.has(key)) throw new Error(`network error uploading ${key}`);
    const current = this.files.get(key);
    if (current && existing) this.trashed.push({ key, data: current.data });
    else if (current && !existing) throw new Error(`${key} already exists on iCloud`);
    const f = { data: data.slice(), etag: this.nextEtag(), docId: `doc-${++this.seq}`, modifiedMs: mtimeMs };
    this.files.set(key, f);
    return this.entry(key, f);
  }

  async move(entry: RemoteEntry, toKey: string): Promise<RemoteEntry> {
    this.tick();
    const f = this.files.get(entry.key);
    if (!f) throw new Error(`gone: ${entry.key}`);
    if (this.files.has(toKey)) throw new Error(`${toKey} already exists on iCloud`);
    this.files.delete(entry.key);
    const moved = { ...f, etag: this.nextEtag() };
    this.files.set(toKey, moved);
    return this.entry(toKey, moved);
  }

  async trash(entry: RemoteEntry): Promise<void> {
    this.tick();
    const f = this.files.get(entry.key);
    if (!f) return;
    this.files.delete(entry.key);
    this.trashed.push({ key: entry.key, data: f.data });
  }
}
