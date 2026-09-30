/**
 * Where things live on this machine, outside the vault, and what else is
 * already managing the vault.
 */
import { createHash } from "node:crypto";
import { readFile, realpath } from "node:fs/promises";
import { homedir } from "node:os";
import { join } from "node:path";

import { parsePersisted, type PersistedSession, type SessionStore } from "../icloud/store.ts";

/** Per-user data directory for this plugin: never inside a vault, never synced. */
export function dataDir(): string {
  if (process.platform === "win32") {
    return join(process.env.LOCALAPPDATA ?? join(homedir(), "AppData", "Local"), "icloud-drive-sync");
  }
  if (process.platform === "darwin") return join(homedir(), "Library", "Application Support", "icloud-drive-sync");
  return join(process.env.XDG_DATA_HOME || join(homedir(), ".local", "share"), "icloud-drive-sync");
}

/**
 * The sync state for one vault on this machine. Keyed by the vault's path, so
 * two vaults — or the same vault on two machines — never share a base.
 */
export function stateFilePath(vaultRoot: string): string {
  const id = createHash("sha256").update(vaultRoot).digest("hex").slice(0, 16);
  return join(dataDir(), `state-${id}.json`);
}

/** The activity log for one vault on this machine, next to its sync state. */
export function logFilePath(vaultRoot: string): string {
  const id = createHash("sha256").update(vaultRoot).digest("hex").slice(0, 16);
  return join(dataDir(), `log-${id}.jsonl`);
}

/** obsisync's config, if it is installed. */
function obsisyncConfigPath(): string {
  if (process.platform === "win32") {
    return join(process.env.APPDATA ?? join(homedir(), "AppData", "Roaming"), "obsisync", "config.json");
  }
  return join(process.env.XDG_CONFIG_HOME || join(homedir(), ".config"), "obsisync", "config.json");
}

/**
 * True when obsisync is configured to sync this same folder. Two sync engines
 * on one vault would each see the other's writes as edits and fight.
 */
export async function obsisyncManages(vaultRoot: string): Promise<boolean> {
  try {
    const cfg = JSON.parse(await readFile(obsisyncConfigPath(), "utf8"));
    if (typeof cfg.local_path !== "string" || !cfg.local_path) return false;
    const [a, b] = await Promise.all([realpath(cfg.local_path).catch(() => cfg.local_path), realpath(vaultRoot)]);
    return a === b;
  } catch {
    return false;
  }
}

// ── Obsidian secret storage ─────────────────────────────────────────────────

/** The part of Obsidian's App.secretStorage this plugin uses (Obsidian 1.11.4+). */
export interface SecretStorageLike {
  setSecret(id: string, secret: string): void;
  getSecret(id: string): string | null;
}

export const SESSION_SECRET_ID = "icloud-drive-sync-session";

/**
 * Session tokens and cookies in Obsidian's secret storage: encrypted with the
 * OS keychain (libsecret/KWallet, DPAPI) and kept in Obsidian's own profile,
 * outside every vault — verified in the Obsidian 1.13 app bundle.
 */
export class SecretSessionStore implements SessionStore {
  private readonly secrets: SecretStorageLike;
  private readonly accountName: string;
  private readonly id: string;

  constructor(secrets: SecretStorageLike, accountName: string, id = SESSION_SECRET_ID) {
    this.secrets = secrets;
    this.accountName = accountName;
    this.id = id;
  }

  async load(): Promise<PersistedSession | null> {
    return parsePersisted(this.secrets.getSecret(this.id), this.accountName);
  }

  async save(session: PersistedSession): Promise<void> {
    this.secrets.setSecret(this.id, JSON.stringify(session));
  }

  async clear(): Promise<void> {
    this.secrets.setSecret(this.id, "");
  }
}

/**
 * Whether Obsidian's secret storage is really encrypted. With no keyring on
 * Linux, Electron falls back to "basic_text" and Obsidian would store secrets
 * in the clear — still outside the vault, but the plugin refuses, as obsisync
 * refused a plaintext keyring. Reads an undocumented Obsidian internal;
 * returns "unknown" if it is not there.
 */
export function secretStorageEncryption(): "encrypted" | "plaintext" | "unknown" {
  try {
    const safe = (globalThis as { electron?: { remote?: { safeStorage?: Record<string, () => unknown> } } }).electron
      ?.remote?.safeStorage;
    if (!safe) return "unknown";
    if (typeof safe.isEncryptionAvailable === "function" && safe.isEncryptionAvailable() === false) return "plaintext";
    if (typeof safe.getSelectedStorageBackend === "function" && safe.getSelectedStorageBackend() === "basic_text") {
      return "plaintext";
    }
    return "encrypted";
  } catch {
    return "unknown";
  }
}
