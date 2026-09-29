/**
 * The sync engine's vocabulary. Nothing in src/sync imports Obsidian or the
 * iCloud client: the engine sees a local and a remote file tree through the
 * interfaces below, so it can be tested completely with fakes.
 *
 * Paths are *keys*: POSIX, relative to the vault root, Unicode NFC. Each side
 * keeps its own real name alongside (`LocalEntry.name`, the remote item) for
 * I/O, because macOS writes NFD and a key must match both.
 */

export interface LocalEntry {
  key: string;
  /** The path as it exists on disk, relative to the vault root. */
  name: string;
  size: number;
  mtimeMs: number;
  /** SHA-256 hex of the whole file. Filled in before planning where needed. */
  hash?: string;
  /** When `hash` was computed; becomes `BaseEntry.hashedAtMs`. */
  hashedAtMs?: number;
}

export interface RemoteEntry {
  key: string;
  size: number;
  modifiedMs: number;
  etag: string;
  /** Stable document id; survives renames and moves (verified before relying on it). */
  docId: string;
  /** Opaque handle the Remote implementation needs for I/O. */
  handle: unknown;
}

/** What both sides looked like the last time this path was in sync. */
export interface BaseEntry {
  key: string;
  hash: string;
  size: number;
  /** Local mtime recorded with `hash`; lets an unchanged file skip hashing. */
  localMtimeMs: number;
  /**
   * When `hash` was computed. If the file's mtime is within the racy window of
   * this, a same-size edit in the same timestamp tick is possible, so the
   * size+mtime shortcut must not be trusted (git's "racy clean" problem).
   */
  hashedAtMs: number;
  remoteEtag: string;
  remoteDocId: string;
}

export interface LocalScan {
  entries: Map<string, LocalEntry>;
  /** Keys the scan refused, with why: NFC collisions, case collisions. */
  skipped: { key: string; reason: string }[];
}

export interface RemoteScan {
  entries: Map<string, RemoteEntry>;
}

/** Local file access. Every method works on keys; the implementation maps them to real names. */
export interface LocalFs {
  /** Every non-ignored file. Must throw, never return a short list, if any folder is unreadable. */
  scan(): Promise<LocalScan>;
  read(key: string): Promise<Uint8Array>;
  stat(key: string): Promise<{ size: number; mtimeMs: number } | null>;
  /** Write atomically (temp file + rename), creating folders. Returns the stat afterwards. */
  write(key: string, data: Uint8Array, mtimeMs?: number): Promise<{ size: number; mtimeMs: number }>;
  rename(from: string, to: string): Promise<void>;
  /** Move to a trash the user can recover from. Never a permanent delete. */
  trash(key: string): Promise<void>;
}

/** Remote file access. */
export interface Remote {
  /** Every non-ignored file. Must throw on any failed or truncated listing. */
  scan(): Promise<RemoteScan>;
  download(entry: RemoteEntry): Promise<Uint8Array>;
  /**
   * Create `key` or replace `existing`, never leaving a moment with neither
   * copy. Creates parent folders. Returns the entry as it now is.
   */
  upload(key: string, data: Uint8Array, mtimeMs: number, existing?: RemoteEntry): Promise<RemoteEntry>;
  /** Rename and/or move. Returns the entry as it now is. */
  move(entry: RemoteEntry, toKey: string): Promise<RemoteEntry>;
  /** Move to Recently Deleted. Never a permanent delete. */
  trash(entry: RemoteEntry): Promise<void>;
}

export interface SyncState {
  version: 1;
  base: Map<string, BaseEntry>;
  /**
   * Deletions waiting for the user, keyed by path. Persisted so an unanswered
   * question survives a restart (obsisync regression).
   */
  pendingDeletions: Map<string, PendingDeletion>;
}

export interface PendingDeletion {
  key: string;
  /** Which side the file vanished from; the deletion would be applied to the other. */
  vanishedFrom: "local" | "remote";
  since: number;
}

export interface StateStore {
  load(): Promise<SyncState>;
  save(state: SyncState): Promise<void>;
}

// ── plan ─────────────────────────────────────────────────────────────────────

export type Action =
  | { kind: "upload"; key: string; local: LocalEntry; remote?: RemoteEntry; base?: BaseEntry; reason: string }
  | { kind: "download"; key: string; remote: RemoteEntry; local?: LocalEntry; base?: BaseEntry; reason: string }
  /** Both sides hold the same bytes; record them as synced without transferring. */
  | { kind: "adopt"; key: string; local: LocalEntry; remote: RemoteEntry }
  /** Both changed, or both new and different: keep both versions as files. */
  | { kind: "conflict"; key: string; local: LocalEntry; remote: RemoteEntry; base?: BaseEntry }
  /** Both new with the same size: compare content before deciding. */
  | { kind: "compare"; key: string; local: LocalEntry; remote: RemoteEntry }
  | { kind: "trashLocal"; key: string; local: LocalEntry; base: BaseEntry }
  | { kind: "trashRemote"; key: string; remote: RemoteEntry; base: BaseEntry }
  | { kind: "renameLocal"; from: string; to: string; local: LocalEntry; remote: RemoteEntry; base: BaseEntry }
  | { kind: "moveRemote"; from: string; to: string; local: LocalEntry; remote: RemoteEntry; base: BaseEntry }
  /** Absent on both sides: forget the base entry. */
  | { kind: "forget"; key: string }
  /** Only the cached local mtime changed (same content): refresh the base. */
  | { kind: "refreshBase"; key: string; local: LocalEntry; base: BaseEntry };

export interface Plan {
  actions: Action[];
  /** Deletions held back for the user by the bulk-deletion guard. */
  parked: PendingDeletion[];
  /** Tracked paths now matching an ignore pattern: left alone on both sides. */
  newlyIgnored: string[];
}

export type Abort =
  | { reason: "local-root-missing" }
  | { reason: "remote-root-empty"; tracked: number }
  | { reason: "local-root-empty"; tracked: number }
  | { reason: "too-many-conflicts"; count: number; keys: string[] };
