/**
 * The planner: base state + local scan + remote scan → a list of actions.
 *
 * Pure. It reads nothing and changes nothing, so every decision is a unit
 * test. The executor then carries the plan out, one checked step at a time.
 *
 * The decision for a path, where L/R are the local and remote files and B is
 * the base (both sides at the last sync):
 *
 *   L R B   local changed?  remote changed?   action
 *   ✓ ✓ ✓   no              no                nothing (or refresh the mtime cache)
 *   ✓ ✓ ✓   yes             no                upload
 *   ✓ ✓ ✓   no              yes               download
 *   ✓ ✓ ✓   yes             yes               conflict: keep both
 *   ✓ ✓ ·   sizes differ                      conflict: keep both
 *   ✓ ✓ ·   sizes equal                       compare content, then adopt or conflict
 *   ✓ · ✓   no                                trash local   (deleted on iCloud)
 *   ✓ · ✓   yes                               upload        (edited here, deleted there: keep)
 *   · ✓ ✓                   no                trash remote  (deleted here)
 *   · ✓ ✓                   yes               download      (deleted here, edited there: keep)
 *   ✓ · ·                                     upload
 *   · ✓ ·                                     download
 *   · · ✓                                     forget
 *
 * Nothing is ever lost to a conflict. Deletions go through the bulk guard,
 * and renames on either side are recognised before any of the above, so a
 * renamed folder is a rename, not a mass deletion and re-creation.
 *
 * Differences from obsisync, each from its review: change detection hashes the
 * whole file (obsisync hashed 4 KB), equal sizes never mean equal content,
 * and the deletion guard applies in both directions.
 */
import { sameStamp, type Abort, type Action, type BaseEntry, type LocalEntry, type LocalScan, type LocalStamp, type PendingDeletion, type Plan, type RemoteEntry, type RemoteScan } from "./types.ts";
import type { IgnoreFilter } from "./filters.ts";

export interface PlanOptions {
  /** More deletions than this in one cycle are parked for the user. obsisync settled on 3. */
  deletionThreshold: number;
  /** More conflicts than this abort the cycle with a question. */
  conflictThreshold: number;
  /** Deletions the user has confirmed; executed regardless of the threshold. */
  confirmedDeletions: ReadonlySet<string>;
  /** The user saw the conflict question and said to go ahead. */
  allowManyConflicts: boolean;
  /** An mtime closer than this to its hash time is not trusted (racy clean). */
  racyWindowMs: number;
  now: number;
}

export const DEFAULT_PLAN_OPTIONS: PlanOptions = {
  deletionThreshold: 3,
  conflictThreshold: 10,
  confirmedDeletions: new Set(),
  allowManyConflicts: false,
  racyWindowMs: 2000,
  now: 0,
};

export interface PlanInput {
  base: ReadonlyMap<string, BaseEntry>;
  local: LocalScan;
  remote: RemoteScan;
  pending: ReadonlyMap<string, PendingDeletion>;
  filter: IgnoreFilter;
  options?: Partial<PlanOptions>;
}

export type PlanResult = { ok: true; plan: Plan } | { ok: false; abort: Abort };

/**
 * Whether a local file must be hashed before planning. The size+mtime
 * shortcut is trusted only when the base's hash was taken comfortably after
 * the mtime: an edit in the same timestamp tick as the last hash would
 * otherwise go unseen.
 */
export function baseStamp(base: BaseEntry): LocalStamp {
  return { size: base.size, mtimeMs: base.localMtimeMs, ctimeMs: base.localCtimeMs, ino: base.localIno };
}

export function needsHash(local: LocalEntry, base: BaseEntry | undefined, racyWindowMs: number): boolean {
  if (!base) return true;
  if (!sameStamp(local, baseStamp(base))) return true;
  return base.hashedAtMs - base.localMtimeMs < racyWindowMs;
}

function hashOf(local: LocalEntry): string {
  if (local.hash === undefined) {
    throw new Error(`planner needs a hash for ${local.key}; call needsHash() and hash it first`);
  }
  return local.hash;
}

function localChanged(local: LocalEntry, base: BaseEntry, racyWindowMs: number): boolean {
  if (!needsHash(local, base, racyWindowMs)) return false;
  return hashOf(local) !== base.hash;
}

function remoteChanged(remote: RemoteEntry, base: BaseEntry): boolean {
  if (remote.etag && base.remoteEtag) return remote.etag !== base.remoteEtag;
  // Without etags (never seen on a real vault, but not guaranteed) fall back to
  // identity and size. Weaker, so it errs towards "changed".
  return remote.docId !== base.remoteDocId || remote.size !== base.size;
}

/** Map of value → the single key that has it; values seen twice map to null. */
function uniqueIndex<T>(items: Iterable<T>, keyOf: (t: T) => string | undefined): Map<string, T | null> {
  const index = new Map<string, T | null>();
  for (const item of items) {
    const k = keyOf(item);
    if (k === undefined || k === "") continue;
    index.set(k, index.has(k) ? null : item);
  }
  return index;
}

export function planSync(input: PlanInput): PlanResult {
  const opt: PlanOptions = { ...DEFAULT_PLAN_OPTIONS, ...input.options };
  const { base, filter } = input;
  const local = input.local.entries;
  const remote = input.remote.entries;

  // ── hard aborts: only for a tree that is plainly not there ─────────────────
  // A partial drop is not an abort — it goes through the deletion guard, which
  // asks. A ratio guard firing first would shadow that question every cycle.
  const tracked = [...base.keys()].filter((k) => !filter.ignores(k)).length;
  if (tracked > 0 && remote.size === 0) return { ok: false, abort: { reason: "remote-root-empty", tracked } };
  if (tracked > 0 && local.size === 0) return { ok: false, abort: { reason: "local-root-empty", tracked } };

  const actions: Action[] = [];
  const done = new Set<string>();

  // ── keys no branch may act on ──────────────────────────────────────────────
  // Tracked but now ignored: both scans skip them, so they look deleted on
  // both sides. Refused by the local scan (collisions): they look locally
  // deleted. Either way, acting would destroy a file for a non-reason.
  const newlyIgnored = [...base.keys()].filter((k) => filter.ignores(k)).sort();
  for (const k of newlyIgnored) done.add(k);
  for (const s of input.local.skipped) done.add(s.key);
  for (const s of input.remote.skipped ?? []) done.add(s.key);

  // ── remote renames: the document id survives a rename or move ─────────────
  const vanishedRemotely = [...base.values()].filter((b) => !done.has(b.key) && !remote.has(b.key));
  const baseByDocId = uniqueIndex(vanishedRemotely, (b) => b.remoteDocId);
  for (const r of remote.values()) {
    if (done.has(r.key) || base.has(r.key) || local.has(r.key)) continue;
    const b = baseByDocId.get(r.docId);
    if (!b || done.has(b.key)) continue;
    const l = local.get(b.key);
    // Only a clean rename: the local copy is still at the old path, unchanged.
    if (!l || localChanged(l, b, opt.racyWindowMs)) continue;
    actions.push({ kind: "renameLocal", from: b.key, to: r.key, local: l, remote: r, base: b });
    done.add(b.key);
    done.add(r.key);
  }

  // ── local renames: matched by content hash ─────────────────────────────────
  const newLocals = [...local.values()].filter((l) => !done.has(l.key) && !base.has(l.key) && !remote.has(l.key));
  const vanishedLocally = [...base.values()].filter(
    (b) => !done.has(b.key) && !local.has(b.key) && b.size > 0, // empty files are too alike to pair
  );
  const newByHash = uniqueIndex(newLocals.filter((l) => l.size > 0), (l) => l.hash);
  const goneByHash = uniqueIndex(vanishedLocally, (b) => b.hash);
  for (const [hash, l] of newByHash) {
    const b = goneByHash.get(hash);
    if (!l || !b) continue;
    const r = remote.get(b.key);
    // Only a clean rename: iCloud still has the old path, unchanged.
    if (!r || remoteChanged(r, b)) continue;
    actions.push({ kind: "moveRemote", from: b.key, to: l.key, local: l, remote: r, base: b });
    done.add(b.key);
    done.add(l.key);
  }

  // ── every other path ───────────────────────────────────────────────────────
  const deletions: Action[] = [];
  const keys = new Set([...local.keys(), ...remote.keys(), ...base.keys()]);
  for (const key of [...keys].sort()) {
    // Scans already filter; this makes an ignored path inert even if one did not.
    if (done.has(key) || filter.ignores(key)) continue;
    const l = local.get(key);
    const r = remote.get(key);
    const b = base.get(key);

    if (l && r && b) {
      const lc = localChanged(l, b, opt.racyWindowMs);
      const rc = remoteChanged(r, b);
      if (lc && rc) actions.push({ kind: "conflict", key, local: l, remote: r, base: b });
      else if (lc) actions.push({ kind: "upload", key, local: l, remote: r, base: b, reason: "edited here" });
      else if (rc) actions.push({ kind: "download", key, remote: r, local: l, base: b, reason: "edited on iCloud" });
      else if (l.hash !== undefined && (!sameStamp(l, baseStamp(b)) || b.hashedAtMs - b.localMtimeMs < opt.racyWindowMs)) {
        actions.push({ kind: "refreshBase", key, local: l, base: b });
      }
    } else if (l && r) {
      if (l.size !== r.size) actions.push({ kind: "conflict", key, local: l, remote: r });
      else actions.push({ kind: "compare", key, local: l, remote: r });
    } else if (l && b) {
      if (localChanged(l, b, opt.racyWindowMs)) {
        actions.push({ kind: "upload", key, local: l, base: b, reason: "edited here, deleted on iCloud: kept" });
      } else {
        deletions.push({ kind: "trashLocal", key, local: l, base: b });
      }
    } else if (r && b) {
      if (remoteChanged(r, b)) {
        actions.push({ kind: "download", key, remote: r, base: b, reason: "deleted here, edited on iCloud: kept" });
      } else {
        deletions.push({ kind: "trashRemote", key, remote: r, base: b });
      }
    } else if (l) {
      actions.push({ kind: "upload", key, local: l, reason: "new here" });
    } else if (r) {
      actions.push({ kind: "download", key, remote: r, reason: "new on iCloud" });
    } else if (b) {
      actions.push({ kind: "forget", key });
    }
  }

  // ── bulk deletion guard, both directions ───────────────────────────────────
  // A question already pending absorbs every new deletion, so a set that later
  // shrinks below the threshold is still asked about, never applied silently.
  const parked: PendingDeletion[] = [];
  const unconfirmed = deletions.filter((d) => !opt.confirmedDeletions.has(keyOfDeletion(d)));
  const holdAll = unconfirmed.length > opt.deletionThreshold || unconfirmed.some((d) => input.pending.has(keyOfDeletion(d)));
  for (const d of deletions) {
    const key = keyOfDeletion(d);
    if (opt.confirmedDeletions.has(key) || !holdAll) actions.push(d);
    else {
      parked.push({
        key,
        vanishedFrom: d.kind === "trashLocal" ? "remote" : "local",
        since: input.pending.get(key)?.since ?? opt.now,
      });
    }
  }

  // ── conflict guard ─────────────────────────────────────────────────────────
  const conflicts = actions.filter((a) => a.kind === "conflict");
  if (conflicts.length > opt.conflictThreshold && !opt.allowManyConflicts) {
    return {
      ok: false,
      abort: { reason: "too-many-conflicts", count: conflicts.length, keys: conflicts.map((c) => (c as { key: string }).key) },
    };
  }

  return { ok: true, plan: { actions, parked, newlyIgnored } };
}

function keyOfDeletion(d: Action): string {
  return (d as { key: string }).key;
}
