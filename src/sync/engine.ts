/**
 * One sync cycle: scan both sides, hash what needs it, plan, then carry the
 * plan out step by step.
 *
 * The executor trusts nothing the scan said about the local side. Before it
 * overwrites, renames or trashes a local file it re-checks that the file is
 * as scanned — the user may have typed in the meantime — and skips the step
 * if not; the next cycle sees the new state and decides again. What it records
 * as synced is what it actually read or wrote, never what the scan predicted.
 *
 * A path is recorded as synced only after its own transfer succeeded, so a
 * failure leaves the base untouched and the next cycle retries. (obsisync
 * recorded a conflict as resolved before uploading, so a failed upload left
 * the two sides different for good.)
 */
import { createHash } from "node:crypto";

import { AuthRequiredError } from "../icloud/errors.ts";
import type { IgnoreFilter } from "./filters.ts";
import { needsHash, planSync, type PlanOptions } from "./planner.ts";
import {
  ChangedSinceScanError,
  sameStamp,
  type Abort,
  type Action,
  type BaseEntry,
  type LocalEntry,
  type LocalFs,
  type LocalStamp,
  type PendingDeletion,
  type Remote,
  type RemoteEntry,
  type RemoteScan,
  type StateStore,
  type SyncState,
} from "./types.ts";

export type LogLevel = "debug" | "info" | "warn" | "error";
export type Logger = (level: LogLevel, message: string) => void;

export interface EngineOptions {
  deletionThreshold?: number;
  conflictThreshold?: number;
  racyWindowMs?: number;
  /** Transfers in flight at once. Each is mostly waiting on the network. */
  concurrency?: number;
  /** Persist the base after this many completed actions, not only at the end. */
  saveEvery?: number;
  now?: () => number;
}

export interface CycleResult {
  status: "ok" | "aborted" | "failed";
  abort?: Abort | { reason: "local-scan-failed" | "remote-scan-failed" | "auth-required"; message: string };
  done: { action: Action; detail?: string }[];
  skipped: { action: Action; why: string }[];
  errors: { action: Action; error: string }[];
  parked: PendingDeletion[];
  newlyIgnored: string[];
  /** Local keys this cycle wrote or renamed, with the hash written: for watcher echo suppression. */
  localWrites: { key: string; hash: string }[];
  /** True when this cycle planned against a cached iCloud scan instead of walking the tree. */
  remoteScanReused: boolean;
}

export interface CycleOptions {
  /**
   * Plan against the last iCloud scan if it is at most this old, instead of
   * walking the whole tree (98 listings, up to 37 s on the real vault). Safe
   * for local-change cycles: a stale scan cannot produce false deletions of
   * local files it has not seen change, and every write re-checks the etag.
   */
  reuseRemoteScanWithinMs?: number;
  onProgress?: (done: number, total: number) => void;
}

class SkipAction extends Error {}

export function sha256(data: Uint8Array): string {
  return createHash("sha256").update(data).digest("hex");
}

/** "Notes/idea.md" → "Notes/idea (conflict 2026-09-29 1430).md", unique against `taken`. */
export function conflictName(key: string, when: Date, taken: (k: string) => boolean): string {
  const slash = key.lastIndexOf("/");
  const dir = key.slice(0, slash + 1);
  const file = key.slice(slash + 1);
  const dot = file.lastIndexOf(".");
  const stem = dot > 0 ? file.slice(0, dot) : file;
  const ext = dot > 0 ? file.slice(dot) : "";
  const pad = (n: number) => String(n).padStart(2, "0");
  const stamp =
    `${when.getFullYear()}-${pad(when.getMonth() + 1)}-${pad(when.getDate())} ` +
    `${pad(when.getHours())}${pad(when.getMinutes())}`;
  for (let n = 1; ; n++) {
    const candidate = `${dir}${stem} (conflict ${stamp}${n > 1 ? ` ${n}` : ""})${ext}`;
    if (!taken(candidate)) return candidate;
  }
}

export class SyncEngine {
  private readonly local: LocalFs;
  private readonly remote: Remote;
  private readonly store: StateStore;
  private readonly filter: IgnoreFilter;
  private readonly log: Logger;
  private readonly opt: Required<EngineOptions>;
  private state: SyncState | null = null;
  private readonly confirmed = new Set<string>();
  private allowManyConflicts = false;
  private running = false;
  /** The last iCloud scan, kept current with this engine's own remote writes. */
  private remoteCache: { entries: Map<string, RemoteEntry>; skipped: RemoteScan["skipped"]; at: number } | null = null;

  constructor(args: {
    local: LocalFs;
    remote: Remote;
    store: StateStore;
    filter: IgnoreFilter;
    log?: Logger;
    options?: EngineOptions;
  }) {
    this.local = args.local;
    this.remote = args.remote;
    this.store = args.store;
    this.filter = args.filter;
    this.log = args.log ?? (() => undefined);
    this.opt = {
      deletionThreshold: 3,
      conflictThreshold: 10,
      racyWindowMs: 2000,
      concurrency: 4,
      saveEvery: 20,
      now: Date.now,
      ...args.options,
    };
  }

  private async loadState(): Promise<SyncState> {
    this.state ??= await this.store.load();
    return this.state;
  }

  async pendingDeletions(): Promise<PendingDeletion[]> {
    return [...(await this.loadState()).pendingDeletions.values()];
  }

  /** The user agreed: carry these deletions out on the next cycle. */
  confirmDeletions(keys: Iterable<string>): void {
    for (const k of keys) this.confirmed.add(k);
  }

  /**
   * The user said no: forget these paths, so the next cycle copies each back
   * from the side that still has it.
   */
  async restoreDeletions(keys: Iterable<string>): Promise<void> {
    const state = await this.loadState();
    for (const k of keys) {
      state.base.delete(k);
      state.pendingDeletions.delete(k);
      this.confirmed.delete(k);
    }
    await this.store.save(state);
  }

  /** Stop tracking paths (both copies stay where they are). */
  async untrack(keys: Iterable<string>): Promise<void> {
    const state = await this.loadState();
    for (const k of keys) state.base.delete(k);
    await this.store.save(state);
  }

  /** The user saw the conflict question and said to go ahead, once. */
  allowConflictsOnce(): void {
    this.allowManyConflicts = true;
  }

  get isRunning(): boolean {
    return this.running;
  }

  async runCycle(options: CycleOptions = {}): Promise<CycleResult> {
    if (this.running) throw new Error("a sync cycle is already running");
    this.running = true;
    try {
      return await this.cycle(options);
    } finally {
      this.running = false;
    }
  }

  /** Forget the cached iCloud scan; the next cycle walks the tree. */
  invalidateRemoteScan(): void {
    this.remoteCache = null;
  }

  /** Record a remote change this engine made, so a reused scan stays true. */
  private noteRemote(key: string, entry: RemoteEntry | null): void {
    if (!this.remoteCache) return;
    if (entry) this.remoteCache.entries.set(key, entry);
    else this.remoteCache.entries.delete(key);
  }

  private async cycle(options: CycleOptions): Promise<CycleResult> {
    const result: CycleResult = {
      status: "ok",
      done: [],
      skipped: [],
      errors: [],
      parked: [],
      newlyIgnored: [],
      localWrites: [],
      remoteScanReused: false,
    };
    const state = await this.loadState();

    let localScan;
    try {
      localScan = await this.local.scan(new Set(state.base.keys()));
    } catch (e) {
      result.status = "aborted";
      result.abort = { reason: "local-scan-failed", message: errorText(e) };
      this.log("error", `Local scan failed, nothing synced: ${errorText(e)}`);
      return result;
    }
    let remoteScan: RemoteScan;
    const cache = this.remoteCache;
    const reuseWithin = options.reuseRemoteScanWithinMs;
    try {
      if (cache && reuseWithin !== undefined && this.opt.now() - cache.at <= reuseWithin) {
        remoteScan = { entries: new Map(cache.entries), skipped: cache.skipped };
        result.remoteScanReused = true;
      } else {
        const at = this.opt.now();
        remoteScan = await this.remote.scan();
        this.remoteCache = { entries: new Map(remoteScan.entries), skipped: remoteScan.skipped, at };
      }
    } catch (e) {
      this.remoteCache = null;
      result.status = "aborted";
      result.abort =
        e instanceof AuthRequiredError
          ? { reason: "auth-required", message: errorText(e) }
          : { reason: "remote-scan-failed", message: errorText(e) };
      this.log("error", `iCloud scan failed, nothing synced: ${errorText(e)}`);
      return result;
    }

    try {
      await this.hashWhereNeeded(localScan.entries.values(), state.base);
    } catch (e) {
      // An unreadable file must not look like a deleted one.
      result.status = "aborted";
      result.abort = { reason: "local-scan-failed", message: `could not read a file: ${errorText(e)}` };
      this.log("error", `Could not read a local file, nothing synced: ${errorText(e)}`);
      return result;
    }

    const planOptions: Partial<PlanOptions> = {
      deletionThreshold: this.opt.deletionThreshold,
      conflictThreshold: this.opt.conflictThreshold,
      racyWindowMs: this.opt.racyWindowMs,
      confirmedDeletions: this.confirmed,
      allowManyConflicts: this.allowManyConflicts,
      now: this.opt.now(),
    };
    const planned = planSync({
      base: state.base,
      local: localScan,
      remote: remoteScan,
      pending: state.pendingDeletions,
      filter: this.filter,
      options: planOptions,
    });
    if (!planned.ok) {
      result.status = "aborted";
      result.abort = planned.abort;
      this.log("warn", `Sync paused: ${describeAbort(planned.abort)}`);
      return result;
    }
    const { plan } = planned;
    this.allowManyConflicts = false;

    state.pendingDeletions = new Map(plan.parked.map((p) => [p.key, p]));
    result.parked = plan.parked;
    result.newlyIgnored = plan.newlyIgnored;
    if (plan.parked.length) {
      this.log("warn", `${plan.parked.length} deletion(s) are waiting for your confirmation`);
    }

    const takenLocal = new Set(localScan.entries.keys());
    const takenRemote = new Set(remoteScan.entries.keys());
    const taken = (k: string) => takenLocal.has(k) || takenRemote.has(k);

    let sinceSave = 0;
    let authFailure: unknown = null;
    const queue = [...plan.actions];
    const total = queue.length;
    let finished = 0;
    options.onProgress?.(0, total);
    const worker = async () => {
      for (let action = queue.shift(); action; action = queue.shift()) {
        if (authFailure) return;
        try {
          const detail = await this.execute(action, state, result, taken, (k) => {
            takenLocal.add(k);
            takenRemote.add(k);
          });
          result.done.push({ action, detail });
          if (action.kind === "conflict" || action.kind === "compare") this.confirmed.delete(action.key);
          if (action.kind === "trashLocal" || action.kind === "trashRemote") this.confirmed.delete(action.key);
          if (++sinceSave >= this.opt.saveEvery) {
            sinceSave = 0;
            await this.store.save(state);
          }
        } catch (e) {
          if (e instanceof SkipAction || e instanceof ChangedSinceScanError) {
            // iCloud moved on since the scan; a reused scan would now mislead.
            if (e instanceof ChangedSinceScanError) this.remoteCache = null;
            result.skipped.push({ action, why: e.message });
            this.log("info", `Skipped ${describe(action)}: ${e.message}`);
          } else if (e instanceof AuthRequiredError) {
            // Every further request would fail the same way; stop, mark nothing.
            authFailure = e;
          } else {
            result.errors.push({ action, error: errorText(e) });
            this.log("error", `Failed to ${describe(action)}: ${errorText(e)}`);
          }
        }
        options.onProgress?.(++finished, total);
      }
    };
    await Promise.all(Array.from({ length: Math.max(1, this.opt.concurrency) }, worker));
    await this.store.save(state);

    if (authFailure) {
      result.status = "aborted";
      result.abort = { reason: "auth-required", message: errorText(authFailure) };
      this.log("error", "iCloud needs you to sign in again; sync stopped");
    } else if (result.errors.length) {
      result.status = "failed";
    }
    return result;
  }

  private async hashWhereNeeded(entries: Iterable<LocalEntry>, base: Map<string, BaseEntry>): Promise<void> {
    const todo = [...entries].filter((l) => l.hash === undefined && needsHash(l, base.get(l.key), this.opt.racyWindowMs));
    const worker = async () => {
      for (let l = todo.shift(); l; l = todo.shift()) {
        const hashedAtMs = this.opt.now();
        l.hash = sha256(await this.local.read(l.key));
        l.hashedAtMs = hashedAtMs;
      }
    };
    await Promise.all(Array.from({ length: 4 }, worker));
  }

  /**
   * Throws SkipAction unless the local file is exactly as the scan saw it.
   *
   * Size and mtime are enough unless the mtime is recent: on a filesystem
   * with coarse timestamps (FAT, some network mounts, HFS+) an edit in the same
   * tick keeps both, so a recent file is compared by content as well.
   */
  private async assertLocalUnchanged(entry: LocalEntry): Promise<void> {
    const now = await this.local.stat(entry.key);
    if (!now) throw new SkipAction("the local file disappeared during the sync");
    if (!sameStamp(now, entry)) throw new SkipAction("the local file changed during the sync");
    if (this.opt.now() - now.mtimeMs < this.opt.racyWindowMs) {
      if (entry.hash === undefined) throw new SkipAction("the local file was modified moments ago");
      if (sha256(await this.local.read(entry.key)) !== entry.hash) {
        throw new SkipAction("the local file changed during the sync");
      }
    }
  }

  private async assertLocalAbsent(key: string): Promise<void> {
    if (await this.local.stat(key)) throw new SkipAction("a local file appeared at this path during the sync");
  }

  private async statOrThrow(key: string): Promise<LocalStamp> {
    const st = await this.local.stat(key);
    if (!st) throw new Error(`${key} vanished right after being written`);
    return st;
  }

  private record(
    state: SyncState,
    key: string,
    content: { hash: string; size: number },
    stamp: LocalStamp,
    hashedAtMs: number,
    remote: RemoteEntry,
  ): void {
    state.base.set(key, {
      key,
      hash: content.hash,
      size: content.size,
      localMtimeMs: stamp.mtimeMs,
      localCtimeMs: stamp.ctimeMs,
      localIno: stamp.ino,
      hashedAtMs,
      remoteEtag: remote.etag,
      remoteDocId: remote.docId,
    });
  }

  private async execute(
    action: Action,
    state: SyncState,
    result: CycleResult,
    taken: (k: string) => boolean,
    claim: (k: string) => void,
  ): Promise<string | undefined> {
    const now = () => this.opt.now();
    switch (action.kind) {
      case "upload": {
        await this.assertLocalUnchanged(action.local);
        const hashedAtMs = now();
        const data = await this.local.read(action.key);
        const hash = sha256(data);
        const uploaded = await this.remote.upload(action.key, data, action.local.mtimeMs, action.remote);
        this.noteRemote(action.key, uploaded);
        // Recorded with the pre-read stamp: an edit during the read changes it,
        // so the next cycle hashes again rather than trusting this record.
        this.record(state, action.key, { hash, size: data.length }, action.local, hashedAtMs, uploaded);
        this.log("info", `Uploaded ${action.key} (${action.reason})`);
        return action.reason;
      }

      case "download": {
        const data = await this.remote.download(action.remote);
        const hash = sha256(data);
        // Checked after the download, immediately before the write: an edit
        // made while a slow download ran must not be overwritten.
        if (action.local) await this.assertLocalUnchanged(action.local);
        else await this.assertLocalAbsent(action.key);
        const written = await this.local.write(action.key, data, action.remote.modifiedMs || undefined);
        result.localWrites.push({ key: action.key, hash });
        this.record(state, action.key, { hash, size: data.length }, written, now(), action.remote);
        this.log("info", `Downloaded ${action.key} (${action.reason})`);
        return action.reason;
      }

      case "adopt": {
        this.record(
          state,
          action.key,
          { hash: action.local.hash!, size: action.local.size },
          action.local,
          action.local.hashedAtMs ?? now(),
          action.remote,
        );
        return undefined;
      }

      case "compare":
      case "conflict": {
        const remoteData = await this.remote.download(action.remote);
        const remoteHash = sha256(remoteData);
        if (remoteHash === action.local.hash) {
          // Same bytes on both sides after all: nothing to keep twice.
          this.record(
            state,
            action.key,
            { hash: remoteHash, size: remoteData.length },
            action.local,
            action.local.hashedAtMs ?? now(),
            action.remote,
          );
          return "identical on both sides";
        }
        // Keep both. The local version moves aside under a conflict name and is
        // uploaded as a new file; the iCloud version takes the original path.
        await this.assertLocalUnchanged(action.local);
        const aside = conflictName(action.key, new Date(now()), taken);
        claim(aside);
        await this.local.rename(action.key, aside);
        result.localWrites.push({ key: aside, hash: action.local.hash! });
        const written = await this.local.write(action.key, remoteData, action.remote.modifiedMs || undefined);
        result.localWrites.push({ key: action.key, hash: remoteHash });
        this.record(state, action.key, { hash: remoteHash, size: remoteData.length }, written, now(), action.remote);
        // The copy's upload is ordinary: if it fails, the next cycle sees a new
        // local file and uploads it then. Nothing is lost either way.
        const asideStamp = await this.statOrThrow(aside);
        const hashedAtMs = now();
        const asideData = await this.local.read(aside);
        const uploaded = await this.remote.upload(aside, asideData, asideStamp.mtimeMs);
        this.noteRemote(aside, uploaded);
        this.record(state, aside, { hash: sha256(asideData), size: asideData.length }, asideStamp, hashedAtMs, uploaded);
        this.log("warn", `Conflict in ${action.key}: kept both; this device's version is ${aside}`);
        return `kept both; this device's version is ${aside}`;
      }

      case "trashLocal": {
        await this.assertLocalUnchanged(action.local);
        await this.local.trash(action.key);
        state.base.delete(action.key);
        state.pendingDeletions.delete(action.key);
        this.log("info", `Moved ${action.key} to the trash (deleted on iCloud)`);
        return undefined;
      }

      case "trashRemote": {
        await this.assertLocalAbsent(action.key);
        await this.remote.trash(action.remote);
        this.noteRemote(action.key, null);
        state.base.delete(action.key);
        state.pendingDeletions.delete(action.key);
        this.log("info", `Moved ${action.key} to Recently Deleted on iCloud (deleted here)`);
        return undefined;
      }

      case "renameLocal": {
        // A move changes the etag, so the etag cannot tell a pure rename from a
        // rename plus an edit. When it differs, fetch the content first and
        // compare, or the edit would be recorded as already synced.
        let edited: Uint8Array | null = null;
        if (action.remote.etag !== action.base.remoteEtag) {
          const data = await this.remote.download(action.remote);
          if (sha256(data) !== action.base.hash) edited = data;
        }
        await this.assertLocalUnchanged(action.local);
        await this.assertLocalAbsent(action.to);
        await this.local.rename(action.from, action.to);
        state.base.delete(action.from);
        if (edited) {
          const written = await this.local.write(action.to, edited, action.remote.modifiedMs || undefined);
          const hash = sha256(edited);
          result.localWrites.push({ key: action.to, hash });
          this.record(state, action.to, { hash, size: edited.length }, written, now(), action.remote);
          this.log("info", `Renamed ${action.from} → ${action.to} and downloaded its changes (renamed and edited on iCloud)`);
        } else {
          // A rename updates ctime, so the stamp is taken afterwards.
          result.localWrites.push({ key: action.to, hash: action.base.hash });
          this.record(
            state,
            action.to,
            { hash: action.base.hash, size: action.base.size },
            await this.statOrThrow(action.to),
            action.base.hashedAtMs,
            action.remote,
          );
          this.log("info", `Renamed ${action.from} → ${action.to} (renamed on iCloud)`);
        }
        return undefined;
      }

      case "moveRemote": {
        const moved = await this.remote.move(action.remote, action.to);
        this.noteRemote(action.from, null);
        this.noteRemote(action.to, moved);
        state.base.delete(action.from);
        this.record(
          state,
          action.to,
          { hash: action.local.hash!, size: action.local.size },
          action.local,
          action.local.hashedAtMs ?? now(),
          moved,
        );
        this.log("info", `Renamed ${action.from} → ${action.to} on iCloud (renamed here)`);
        return undefined;
      }

      case "forget":
        state.base.delete(action.key);
        return undefined;

      case "refreshBase": {
        const b = state.base.get(action.key);
        if (b) {
          b.localMtimeMs = action.local.mtimeMs;
          b.localCtimeMs = action.local.ctimeMs;
          b.localIno = action.local.ino;
          b.hashedAtMs = action.local.hashedAtMs ?? b.hashedAtMs;
        }
        return undefined;
      }
    }
  }
}

function errorText(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

export function describe(action: Action): string {
  switch (action.kind) {
    case "renameLocal":
    case "moveRemote":
      return `${action.kind} ${action.from} → ${action.to}`;
    default:
      return `${action.kind} ${action.key}`;
  }
}

export function describeAbort(abort: Abort): string {
  switch (abort.reason) {
    case "local-root-missing":
      return "the vault folder is missing";
    case "remote-root-empty":
      return `iCloud shows no files, but ${abort.tracked} are tracked`;
    case "local-root-empty":
      return `the vault is empty, but ${abort.tracked} files are tracked`;
    case "too-many-conflicts":
      return `${abort.count} files changed on both sides; confirm to keep both copies of each`;
  }
}
