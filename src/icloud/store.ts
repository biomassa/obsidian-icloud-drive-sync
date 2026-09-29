/**
 * Where the session tokens and cookies live between runs.
 *
 * These are credentials: with them, anyone can use the iCloud session without
 * the password or a 2FA code. They must never be written inside the vault,
 * because the vault is what gets synced to iCloud and every other device. The
 * plugin stores them in Obsidian's secret storage (outside the vault, encrypted
 * by the OS keychain); the spike stores them in a 0600 file.
 */
import { mkdir, readFile, rename, rm, writeFile, chmod } from "node:fs/promises";
import { dirname } from "node:path";

import type { StoredCookie } from "./cookies.ts";

export interface PersistedSession {
  version: 1;
  accountName: string;
  /** Apple session values: session_token, trust_token, scnt, client_id, … */
  data: Record<string, string>;
  cookies: StoredCookie[];
}

export interface SessionStore {
  load(): Promise<PersistedSession | null>;
  save(session: PersistedSession): Promise<void>;
  clear(): Promise<void>;
}

export function parsePersisted(text: string | null, accountName: string): PersistedSession | null {
  if (!text) return null;
  try {
    const parsed = JSON.parse(text);
    if (parsed?.version !== 1 || parsed.accountName !== accountName) return null;
    const data: Record<string, string> = {};
    for (const [k, v] of Object.entries(parsed.data ?? {})) {
      if (typeof v === "string") data[k] = v;
    }
    return {
      version: 1,
      accountName,
      data,
      cookies: Array.isArray(parsed.cookies) ? parsed.cookies : [],
    };
  } catch {
    return null;
  }
}

/** A 0600 JSON file in a 0700 directory, replaced atomically. */
export class FileSessionStore implements SessionStore {
  private readonly path: string;
  private readonly accountName: string;

  constructor(path: string, accountName: string) {
    this.path = path;
    this.accountName = accountName;
  }

  async load(): Promise<PersistedSession | null> {
    try {
      return parsePersisted(await readFile(this.path, "utf8"), this.accountName);
    } catch {
      return null;
    }
  }

  async save(session: PersistedSession): Promise<void> {
    const dir = dirname(this.path);
    await mkdir(dir, { recursive: true, mode: 0o700 });
    await chmod(dir, 0o700);
    const tmp = `${this.path}.${process.pid}.tmp`;
    await writeFile(tmp, JSON.stringify(session), { mode: 0o600 });
    await rename(tmp, this.path);
  }

  async clear(): Promise<void> {
    await rm(this.path, { force: true });
  }
}

/** For tests. */
export class MemorySessionStore implements SessionStore {
  value: PersistedSession | null = null;
  async load() {
    return this.value && structuredClone(this.value);
  }
  async save(session: PersistedSession) {
    this.value = structuredClone(session);
  }
  async clear() {
    this.value = null;
  }
}
