/** Builders for planner and executor tests. */
import { createHash } from "node:crypto";

import type { BaseEntry, LocalEntry, LocalScan, RemoteEntry, RemoteScan } from "../src/sync/types.ts";

export const sha = (text: string) => createHash("sha256").update(text).digest("hex");

export function L(key: string, content: string, mtimeMs = 1000, hashed = true): LocalEntry {
  return {
    key,
    name: key,
    size: Buffer.byteLength(content),
    mtimeMs,
    ...(hashed ? { hash: sha(content), hashedAtMs: mtimeMs + 10_000 } : {}),
  };
}

export function R(key: string, content: string, etag = "e1", docId = `doc:${key}`, modifiedMs = 1000): RemoteEntry {
  return { key, size: Buffer.byteLength(content), modifiedMs, etag, docId, handle: null };
}

/** A base entry for content that was in sync at `mtimeMs` with remote etag `etag`. */
export function B(key: string, content: string, etag = "e1", mtimeMs = 1000, docId = `doc:${key}`): BaseEntry {
  return {
    key,
    hash: sha(content),
    size: Buffer.byteLength(content),
    localMtimeMs: mtimeMs,
    hashedAtMs: mtimeMs + 10_000,
    remoteEtag: etag,
    remoteDocId: docId,
  };
}

export const localScan = (...entries: LocalEntry[]): LocalScan => ({
  entries: new Map(entries.map((e) => [e.key, e])),
  skipped: [],
});
export const remoteScan = (...entries: RemoteEntry[]): RemoteScan => ({ entries: new Map(entries.map((e) => [e.key, e])) });
export const baseOf = (...entries: BaseEntry[]) => new Map(entries.map((e) => [e.key, e]));
