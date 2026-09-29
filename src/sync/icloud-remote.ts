/**
 * The engine's Remote, on iCloud Drive, rooted at the vault folder.
 *
 * Built on what the live probes established (PLAN.md, "iCloud semantics"):
 *
 * - Replace is an in-place update of the existing document: no temporary
 *   name, no Recently Deleted entry. It is unconditional on Apple's side, so
 *   the file's etag is re-read just before and the update refused if another
 *   device changed it since the scan.
 * - A new file is created with allow_conflict=false, so a name another device
 *   took meanwhile fails instead of silently becoming "name 2".
 * - A trash with a stale etag answers 200 and does nothing; success is read
 *   from the response (parentId === TRASH_ROOT), never assumed.
 */
import { DriveClient, isFolderLike, toItem, type DriveItem } from "../icloud/drive.ts";
import { ApiError } from "../icloud/errors.ts";
import { toKey, type IgnoreFilter } from "./filters.ts";
import { ChangedSinceScanError, type Remote, type RemoteEntry, type RemoteScan } from "./types.ts";

type Json = Record<string, unknown>;

function parentKey(key: string): string {
  const i = key.lastIndexOf("/");
  return i < 0 ? "" : key.slice(0, i);
}

function baseName(key: string): string {
  return key.slice(key.lastIndexOf("/") + 1);
}

/**
 * Apple serializes writes per zone with an optimistic lock and rejects a
 * commit that races another ("Sync zone CAS Op-Lock failed … Retry request"),
 * which parallel uploads hit in the live end-to-end test. The rejected write
 * did not apply, so retrying the same commit is safe.
 */
export function isZoneLockConflict(e: unknown): boolean {
  return e instanceof ApiError && /CAS Op-Lock|concurrent write/i.test(e.message);
}

async function retryZoneLock<T>(fn: () => Promise<T>, attempts = 5): Promise<T> {
  for (let i = 1; ; i++) {
    try {
      return await fn();
    } catch (e) {
      if (!isZoneLockConflict(e) || i >= attempts) throw e;
      await new Promise((r) => setTimeout(r, 250 * 2 ** i * (0.5 + Math.random())));
    }
  }
}

function firstItem(response: Json): Json | undefined {
  return (response.items as Json[] | undefined)?.[0];
}

export class ICloudRemote implements Remote {
  private readonly drive: DriveClient;
  private readonly vaultPath: string[];
  private readonly filter: IgnoreFilter;
  private readonly concurrency: number;
  /** Folder key ("" is the vault root) → folder item, from the last scan and later mkdirs. */
  private folders = new Map<string, DriveItem>();
  private creating = new Map<string, Promise<DriveItem>>();

  constructor(args: { drive: DriveClient; vaultPath: string[]; filter: IgnoreFilter; concurrency?: number }) {
    this.drive = args.drive;
    this.vaultPath = args.vaultPath;
    this.filter = args.filter;
    this.concurrency = args.concurrency ?? 8;
  }

  private itemOf(entry: RemoteEntry): DriveItem {
    return entry.handle as DriveItem;
  }

  private entryOf(key: string, item: DriveItem): RemoteEntry {
    return { key, size: item.size, modifiedMs: item.modified, etag: item.etag, docId: item.docwsid, handle: item };
  }

  async scan(): Promise<RemoteScan> {
    const root = await this.drive.resolve(this.vaultPath);
    if (!root || !isFolderLike(root)) throw new ApiError(`vault folder ${this.vaultPath.join("/")} not found on iCloud`);

    const folders = new Map<string, DriveItem>([["", root]]);
    const entries = new Map<string, RemoteEntry>();
    const ambiguous = new Set<string>();
    const queue: { folder: DriveItem; prefix: string }[] = [{ folder: root, prefix: "" }];
    let active = 0;

    // Any failed listing rejects the whole scan: a missing subtree must never
    // look like deleted files.
    await new Promise<void>((resolve, reject) => {
      let failed = false;
      const pump = () => {
        if (failed) return;
        if (!queue.length && !active) return resolve();
        while (active < this.concurrency && queue.length) {
          const { folder, prefix } = queue.shift()!;
          active++;
          this.drive.list(folder).then(
            (children) => {
              for (const child of children) {
                const key = toKey(prefix ? `${prefix}/${child.name}` : child.name);
                if (this.filter.ignores(key)) continue;
                if (isFolderLike(child)) {
                  folders.set(key, child);
                  queue.push({ folder: child, prefix: key });
                } else if (entries.has(key)) {
                  ambiguous.add(key); // two names that normalize alike (NFC/NFD)
                } else {
                  entries.set(key, this.entryOf(key, child));
                }
              }
              active--;
              pump();
            },
            (e) => {
              failed = true;
              reject(e);
            },
          );
        }
      };
      pump();
    });

    for (const key of ambiguous) entries.delete(key);
    this.folders = folders;
    this.creating.clear();
    return {
      entries,
      skipped: [...ambiguous].map((key) => ({ key, reason: "two iCloud names normalize to this path" })),
    };
  }

  async download(entry: RemoteEntry): Promise<Uint8Array> {
    return this.drive.download(this.itemOf(entry));
  }

  /** The folder at `key`, creating it and any missing parents. Concurrent callers share one mkdir. */
  private async folder(key: string): Promise<DriveItem> {
    const known = this.folders.get(key);
    if (known) return known;
    const pending = this.creating.get(key);
    if (pending) return pending;
    const make = (async () => {
      const parent = await this.folder(parentKey(key));
      const name = baseName(key);
      // Another device may have created it since the scan.
      const existing = (await this.drive.list(parent)).find((c) => isFolderLike(c) && toKey(c.name) === toKey(name));
      const made = existing ?? (await retryZoneLock(() => this.drive.mkdir(parent, name)));
      this.folders.set(key, made);
      return made;
    })();
    this.creating.set(key, make);
    try {
      return await make;
    } finally {
      this.creating.delete(key);
    }
  }

  async upload(key: string, data: Uint8Array, mtimeMs: number, existing?: RemoteEntry): Promise<RemoteEntry> {
    const parent = await this.folder(parentKey(key));
    let response: Json;
    if (existing) {
      const old = this.itemOf(existing);
      // Apple ignores any etag on an in-place update, so check just before.
      const current = (await this.drive.list(parent)).find((c) => c.docwsid === old.docwsid);
      if (!current) throw new ChangedSinceScanError(`${key} was moved or deleted on iCloud since the scan`);
      if (current.etag !== old.etag) throw new ChangedSinceScanError(`${key} changed on iCloud since the scan`);
      const { signature } = await this.drive.stageContent(parent.zone, current.name, data);
      response = await retryZoneLock(() => this.drive.updateDocumentsRaw(parent.zone, {
        data: signature,
        command: "add_file",
        create_short_guid: true,
        document_id: current.docwsid,
        path: { starting_document_id: parent.docwsid, path: current.name },
        allow_conflict: false,
        file_flags: { is_writable: true, is_executable: false, is_hidden: false },
        mtime: Math.floor(mtimeMs),
        btime: Math.floor(mtimeMs),
      }));
    } else {
      const { documentId, signature } = await this.drive.stageContent(parent.zone, baseName(key), data);
      response = await retryZoneLock(() =>
        this.drive.updateDocumentsRaw(parent.zone, {
          data: signature,
          command: "add_file",
          create_short_guid: true,
          document_id: documentId,
          path: { starting_document_id: parent.docwsid, path: baseName(key) },
          allow_conflict: false,
          file_flags: { is_writable: true, is_executable: false, is_hidden: false },
          mtime: Math.floor(mtimeMs),
          btime: Math.floor(mtimeMs),
        }),
      );
    }
    const result = (response.results as Json[] | undefined)?.[0];
    const doc = result?.document as Json | undefined;
    const status = (result?.status as Json | undefined)?.status_code;
    if (!doc?.document_id || (status !== undefined && status !== 0)) {
      throw new ApiError(`iCloud did not confirm the upload of ${key}: ${JSON.stringify(result?.status ?? response)}`);
    }
    const item = toItem({
      drivewsid: `FILE::${parent.zone}::${String(doc.document_id)}`,
      docwsid: doc.document_id,
      zone: parent.zone,
      etag: doc.etag,
      name: baseName(key),
      type: "FILE",
      size: data.length,
      dateModified: new Date(Math.floor(mtimeMs / 1000) * 1000).toISOString(),
      parentId: parent.drivewsid,
    });
    return this.entryOf(key, item);
  }

  async move(entry: RemoteEntry, toKey_: string): Promise<RemoteEntry> {
    let item = this.itemOf(entry);
    // The engine records the moved file as holding the content it scanned; if
    // another device edited it since, that record would be false.
    const current = (await this.drive.list(await this.folder(parentKey(entry.key)))).find((c) => c.docwsid === item.docwsid);
    if (!current) throw new ChangedSinceScanError(`${entry.key} was moved or deleted on iCloud since the scan`);
    if (current.etag !== item.etag) throw new ChangedSinceScanError(`${entry.key} changed on iCloud since the scan`);
    const fromParent = parentKey(entry.key);
    const toParent = parentKey(toKey_);
    if (fromParent !== toParent) {
      const destination = await this.folder(toParent);
      const moved = firstItem(await retryZoneLock(() => this.drive.move(item, destination)));
      if (!moved?.etag) throw new ApiError(`iCloud did not confirm moving ${entry.key}`);
      item = toItem({ ...item.raw, ...moved });
    }
    const newName = baseName(toKey_);
    if (toKey(item.name) !== toKey(newName)) {
      const renamed = firstItem(await retryZoneLock(() => this.drive.rename(item, newName)));
      if (!renamed?.etag) throw new ApiError(`iCloud did not confirm renaming ${entry.key}`);
      item = toItem({ ...item.raw, ...renamed });
    }
    return this.entryOf(toKey_, item);
  }

  async trash(entry: RemoteEntry): Promise<void> {
    const item = firstItem(await retryZoneLock(() => this.drive.trash(this.itemOf(entry))));
    // A stale etag makes Apple answer 200 and do nothing; only this says it moved.
    if (item?.parentId !== "TRASH_ROOT") {
      throw new ChangedSinceScanError(`${entry.key} changed on iCloud since the scan, so it was not deleted`);
    }
  }
}
