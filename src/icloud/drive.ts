/**
 * iCloud Drive: list, download, upload, create folders, rename, trash.
 *
 * Port of icloudlite/services/drive.py, stateless on purpose: every listing is
 * a fresh request, and caching is the sync engine's decision. Changes from the
 * Python, each from the obsisync review:
 *
 * - The etag comes from `data.etag`. icloudlite read a non-existent attribute,
 *   so every stored etag was empty and remote change detection was mtime-only.
 * - Removing a file moves it to Recently Deleted (`moveItemsToTrash`). The
 *   Python's `delete()` called `/deleteItems`, the permanent-delete endpoint.
 * - Replacing a file uploads the new content first, under a hidden temporary
 *   name, and only then trashes the old one and renames. The Python deleted
 *   first, so a failed upload lost the file on both sides.
 * - A listing whose item count disagrees with `numberOfItems` is an error, not
 *   a short folder: a truncated listing looks exactly like deleted files.
 */
import { randomBytes, randomUUID } from "node:crypto";

import type { ICloudAuth } from "./auth.ts";
import { ApiError, ICloudError } from "./errors.ts";
import { multipartFile, responseJson } from "./http.ts";

const CLOUD_DOCS_ZONE = "com.apple.CloudDocs";
const ROOT_ID = `FOLDER::${CLOUD_DOCS_ZONE}::root`;

type Json = Record<string, unknown>;

export class IncompleteListingError extends ICloudError {
  override name = "IncompleteListingError";
}

export interface DriveItem {
  drivewsid: string;
  docwsid: string;
  zone: string;
  etag: string;
  /** Full name including extension. */
  name: string;
  /** "file", "folder", "app_library", … lowercased. */
  type: string;
  size: number;
  /** Milliseconds since the epoch; 0 when Apple gives none (folders). */
  modified: number;
  raw: Json;
}

export function isFolderLike(item: DriveItem): boolean {
  return item.type === "folder" || item.type === "app_library";
}

/** Apple's dates carry a numeric offset or a Z; both parse as ISO 8601. */
function parseDate(value: unknown): number {
  if (typeof value !== "string" || !value) return 0;
  const t = Date.parse(value);
  return Number.isNaN(t) ? 0 : t;
}

export function toItem(data: Json): DriveItem {
  let name = typeof data.name === "string" && data.name ? data.name : String(data.drivewsid ?? "");
  if (data.drivewsid === ROOT_ID && !data.name) name = "root";
  // An empty extension must not produce "name." (review finding).
  if (typeof data.extension === "string" && data.extension) name = `${name}.${data.extension}`;
  const size = Number(data.size ?? 0);
  return {
    drivewsid: String(data.drivewsid ?? ""),
    docwsid: String(data.docwsid ?? ""),
    zone: String(data.zone ?? CLOUD_DOCS_ZONE),
    etag: String(data.etag ?? ""),
    name,
    type: String(data.type ?? "unknown").toLowerCase(),
    size: Number.isFinite(size) ? size : 0,
    modified: parseDate(data.dateModified),
    raw: data,
  };
}

function guessContentType(name: string): string {
  const ext = name.slice(name.lastIndexOf(".") + 1).toLowerCase();
  const types: Record<string, string> = {
    md: "text/markdown",
    txt: "text/plain",
    json: "application/json",
    css: "text/css",
    js: "text/javascript",
    png: "image/png",
    jpg: "image/jpeg",
    jpeg: "image/jpeg",
    gif: "image/gif",
    webp: "image/webp",
    svg: "image/svg+xml",
    pdf: "application/pdf",
    canvas: "application/json",
  };
  return types[ext] ?? "";
}

/** A dot-prefixed temporary name: Obsidian and the sync filters both skip dotfiles in folders. */
export function temporaryUploadName(name: string): string {
  return `.icloudsync-tmp-${randomBytes(6).toString("hex")}-${name}`;
}

export class DriveClient {
  private readonly auth: ICloudAuth;

  constructor(auth: ICloudAuth) {
    this.auth = auth;
  }

  private get serviceRoot(): string {
    return this.auth.webserviceUrl("drivews");
  }

  private get documentRoot(): string {
    return this.auth.webserviceUrl("docws");
  }

  private get params(): Record<string, string> {
    return { ...this.auth.params };
  }

  /** Fetch a folder's details, including its children. */
  async folderDetails(drivewsid: string, shareID?: unknown): Promise<Json> {
    const payload: Json = { drivewsid, partialData: false };
    if (shareID) payload.shareID = shareID;
    const res = await this.auth.session.request("POST", `${this.serviceRoot}/retrieveItemDetailsInFolders`, {
      params: this.params,
      json: [payload],
    });
    const body = responseJson<Json[]>(res);
    const first = Array.isArray(body) ? body[0] : undefined;
    if (!first) throw new ApiError("empty folder details response");
    return first;
  }

  async root(): Promise<DriveItem> {
    return toItem(await this.folderDetails(ROOT_ID));
  }

  /** The children of a folder, always fresh. Throws rather than return a short list. */
  async list(folder: DriveItem): Promise<DriveItem[]> {
    const data = await this.folderDetails(folder.drivewsid, folder.raw.shareID);
    if (!Array.isArray(data.items)) {
      throw new IncompleteListingError(`no items in listing of ${folder.name} (status ${String(data.status)})`);
    }
    const expected = data.numberOfItems;
    if (typeof expected === "number" && expected !== data.items.length) {
      throw new IncompleteListingError(
        `listing of ${folder.name} returned ${data.items.length} of ${expected} items`,
      );
    }
    return (data.items as Json[]).map(toItem);
  }

  async child(folder: DriveItem, name: string): Promise<DriveItem | undefined> {
    return (await this.list(folder)).find((c) => c.name === name);
  }

  /** Walk names from the root, e.g. ["Obsidian", "Obsidian"]. */
  async resolve(parts: string[]): Promise<DriveItem | undefined> {
    let node: DriveItem | undefined = await this.root();
    for (const part of parts.filter(Boolean)) {
      if (!node || !isFolderLike(node)) return undefined;
      node = await this.child(node, part);
    }
    return node;
  }

  async download(file: DriveItem): Promise<Uint8Array> {
    // iCloud answers 400 for a zero-byte document.
    if (file.size === 0) return new Uint8Array(0);
    const res = await this.auth.session.request(
      "GET",
      `${this.documentRoot}/ws/${file.zone}/download/by_id`,
      { params: { ...this.params, document_id: file.docwsid } },
    );
    const body = responseJson<Json>(res);
    const token = (body.data_token ?? body.package_token) as { url?: string } | undefined;
    if (!token?.url) throw new ApiError(`no download URL for ${file.name}`);
    // Raw, not request(): file content is user data, and a vault JSON file that
    // happens to contain an "error" key must not be read as an Apple error.
    const content = await this.auth.session.requestRaw("GET", token.url, { params: this.params });
    if (content.status < 200 || content.status >= 300) {
      throw new ApiError(`download of ${file.name} failed with HTTP ${content.status}`, content.status);
    }
    return content.body;
  }

  private uploadToken(): string {
    const cookie = this.auth.session.cookies.get("X-APPLE-WEBAUTH-VALIDATE");
    if (!cookie) throw new ApiError("upload token cookie not found; sign in again");
    // The value may or may not be quoted; the token never contains a quote or colon.
    const m = /\bt=([^:"]+)/.exec(cookie);
    if (!m) throw new ApiError("could not read the upload token");
    return m[1]!;
  }

  /**
   * Upload `data` as a new file named `name` in `folder`.
   *
   * Apple allows a conflict here: if the name is taken it creates "name 2".
   * Callers that mean to replace use `replace()`.
   */
  async upload(folder: DriveItem, name: string, data: Uint8Array, mtimeMs = Date.now()): Promise<void> {
    const zone = folder.zone || CLOUD_DOCS_ZONE;
    const contentType = guessContentType(name);
    const init = await this.auth.session.request("POST", `${this.documentRoot}/ws/${zone}/upload/web`, {
      params: { ...this.params, token: this.uploadToken() },
      headers: { "Content-Type": "plain/text" },
      // The file name only, never a local path (review finding: icloudlite sent the full path).
      json: { filename: name, type: "FILE", content_type: contentType, size: data.length },
    });
    const slot = responseJson<Json[]>(init)[0];
    if (!slot?.url || !slot.document_id) throw new ApiError("upload was not accepted");

    const form = multipartFile(name, name, data, contentType || "application/octet-stream");
    const put = await this.auth.session.request("POST", String(slot.url), {
      body: form.body,
      headers: { "Content-Type": form.contentType },
    });
    const single = responseJson<Json>(put).singleFile as Json | undefined;
    if (!single) throw new ApiError("upload content was not stored");

    const signature: Json = {
      signature: single.fileChecksum,
      wrapping_key: single.wrappingKey,
      reference_signature: single.referenceChecksum,
      size: single.size,
    };
    if (single.receipt) signature.receipt = single.receipt; // absent for zero-byte files
    await this.auth.session.request("POST", `${this.documentRoot}/ws/${zone}/update/documents`, {
      params: this.params,
      headers: { "Content-Type": "plain/text" },
      json: {
        data: signature,
        command: "add_file",
        create_short_guid: true,
        document_id: slot.document_id,
        path: { starting_document_id: folder.docwsid, path: name },
        allow_conflict: true,
        file_flags: { is_writable: true, is_executable: false, is_hidden: false },
        mtime: Math.floor(mtimeMs),
        btime: Math.floor(mtimeMs),
      },
    });
  }

  /**
   * Replace `existing` with `data`, never leaving a moment with neither copy:
   * upload under a temporary name, trash the old file, then rename.
   *
   * If the final rename fails, the new content is safe under the temporary name
   * and the old copy is in Recently Deleted; the error says so.
   */
  async replace(folder: DriveItem, existing: DriveItem, data: Uint8Array, mtimeMs = Date.now()): Promise<void> {
    const temp = temporaryUploadName(existing.name);
    await this.upload(folder, temp, data, mtimeMs);
    const uploaded = await this.child(folder, temp);
    if (!uploaded) throw new ApiError(`uploaded copy of ${existing.name} did not appear`);
    await this.trash(existing);
    try {
      await this.rename(uploaded, existing.name);
    } catch (e) {
      throw new ApiError(
        `${existing.name}: the new version was uploaded as ${temp} and the old one moved to ` +
          `Recently Deleted, but renaming failed (${e instanceof Error ? e.message : String(e)})`,
      );
    }
  }

  async mkdir(parent: DriveItem, name: string): Promise<DriveItem> {
    const res = await this.auth.session.request("POST", `${this.serviceRoot}/createFolders`, {
      params: this.params,
      headers: { "Content-Type": "plain/text" },
      json: {
        destinationDrivewsId: parent.drivewsid,
        folders: [{ clientId: `FOLDER::UNKNOWN_ZONE::TempId-${randomUUID()}`, name }],
      },
    });
    const created = (responseJson<Json>(res).folders as Json[] | undefined)?.[0];
    if (created?.drivewsid) return toItem({ zone: parent.zone, ...created });
    const found = await this.child(parent, name);
    if (!found) throw new ApiError(`folder ${name} was not created`);
    return found;
  }

  /** Move to Recently Deleted, where the user can still recover it for 30 days. */
  async trash(item: DriveItem): Promise<void> {
    await this.auth.session.request("POST", `${this.serviceRoot}/moveItemsToTrash`, {
      params: this.params,
      json: { items: [{ drivewsid: item.drivewsid, etag: item.etag, clientId: item.drivewsid }] },
    });
  }

  async rename(item: DriveItem, name: string): Promise<void> {
    await this.auth.session.request("POST", `${this.serviceRoot}/renameItems`, {
      params: this.params,
      json: { items: [{ drivewsid: item.drivewsid, etag: item.etag, name }] },
    });
  }
}
