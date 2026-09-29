/**
 * Persisting the sync state: what each path looked like when last in sync,
 * and the deletions still waiting for an answer.
 *
 * The state is per device and must live outside the vault. The vault —
 * including `.obsidian/plugins/` — is what gets synced, so a second desktop
 * would otherwise inherit this machine's base and believe it held files it
 * never downloaded.
 */
import { chmod, mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { dirname } from "node:path";

import type { BaseEntry, PendingDeletion, StateStore, SyncState } from "./types.ts";

export function emptyState(): SyncState {
  return { version: 1, base: new Map(), pendingDeletions: new Map() };
}

export function serializeState(state: SyncState): string {
  return JSON.stringify({
    version: 1,
    base: [...state.base.values()],
    pendingDeletions: [...state.pendingDeletions.values()],
  });
}

function isBase(v: unknown): v is BaseEntry {
  const b = v as BaseEntry;
  return (
    !!b &&
    typeof b.key === "string" &&
    typeof b.hash === "string" &&
    typeof b.size === "number" &&
    typeof b.localMtimeMs === "number" &&
    typeof b.hashedAtMs === "number" &&
    typeof b.remoteEtag === "string" &&
    typeof b.remoteDocId === "string"
  );
}

function isPending(v: unknown): v is PendingDeletion {
  const p = v as PendingDeletion;
  return !!p && typeof p.key === "string" && (p.vanishedFrom === "local" || p.vanishedFrom === "remote");
}

/**
 * Parse stored state. Malformed input throws rather than returning an empty
 * state: an empty base against a full vault is the first-run case, and quietly
 * falling into it would re-compare every file — safe, but it must be a
 * decision, not an accident.
 */
export function parseState(text: string): SyncState {
  const raw = JSON.parse(text);
  if (raw?.version !== 1 || !Array.isArray(raw.base) || !Array.isArray(raw.pendingDeletions)) {
    throw new Error("unrecognised sync state format");
  }
  const state = emptyState();
  for (const b of raw.base) if (isBase(b)) state.base.set(b.key, b);
  for (const p of raw.pendingDeletions) {
    if (isPending(p)) state.pendingDeletions.set(p.key, { ...p, since: Number(p.since) || 0 });
  }
  return state;
}

/** A JSON file outside the vault, replaced atomically, readable only by this user. */
export class FileStateStore implements StateStore {
  private readonly path: string;
  private writing: Promise<void> = Promise.resolve();

  constructor(path: string) {
    this.path = path;
  }

  async load(): Promise<SyncState> {
    let text: string;
    try {
      text = await readFile(this.path, "utf8");
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code === "ENOENT") return emptyState();
      throw e;
    }
    return parseState(text);
  }

  save(state: SyncState): Promise<void> {
    const text = serializeState(state);
    this.writing = this.writing
      .catch(() => undefined)
      .then(async () => {
        const dir = dirname(this.path);
        await mkdir(dir, { recursive: true, mode: 0o700 });
        await chmod(dir, 0o700);
        const tmp = `${this.path}.${process.pid}.tmp`;
        await writeFile(tmp, text, { mode: 0o600 });
        await rename(tmp, this.path);
      });
    return this.writing;
  }
}

/** For tests: round-trips through JSON so serialization is exercised too. */
export class MemoryStateStore implements StateStore {
  text: string | null = null;
  saves = 0;
  async load(): Promise<SyncState> {
    return this.text ? parseState(this.text) : emptyState();
  }
  async save(state: SyncState): Promise<void> {
    this.text = serializeState(state);
    this.saves++;
  }
}
