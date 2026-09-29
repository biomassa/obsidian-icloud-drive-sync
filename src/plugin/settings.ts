/**
 * Plugin settings, stored by Obsidian in the plugin folder's data.json.
 *
 * data.json lives inside the vault, and the vault is what gets synced — to
 * iCloud and every other device. So settings are read and written through an
 * allow-list: anything not named here is dropped, and nothing secret is ever
 * named here. The session and any password live in Obsidian's secret storage.
 */

export interface Settings {
  /** The Apple ID. An identifier, not a secret. */
  appleId: string;
  /** The vault's folder in iCloud Drive, e.g. "Obsidian/My Vault". */
  icloudVaultPath: string;
  autoSync: boolean;
  pollSeconds: number;
  /** More deletions than this in one cycle wait for confirmation. */
  deletionThreshold: number;
  /** Sync plugins' code (main.js, styles.css, manifest.json) as well as their settings. */
  syncPluginCode: boolean;
  /** Extra ignore patterns, one per entry. "folder/" matches a folder and its contents. */
  extraIgnore: string[];
  /** Force IPv4, for networks that advertise IPv6 but do not route it. */
  forceIpv4: boolean;
}

export const DEFAULT_SETTINGS: Settings = {
  appleId: "",
  icloudVaultPath: "",
  autoSync: true,
  pollSeconds: 120,
  deletionThreshold: 3,
  syncPluginCode: false,
  extraIgnore: [],
  forceIpv4: false,
};

const clamp = (n: number, lo: number, hi: number) => Math.min(hi, Math.max(lo, n));

/** Keep only known keys with sane values. Unknown keys — anything secret — are dropped. */
export function sanitizeSettings(raw: unknown): Settings {
  const r = (raw && typeof raw === "object" ? raw : {}) as Record<string, unknown>;
  const s = { ...DEFAULT_SETTINGS };
  if (typeof r.appleId === "string") s.appleId = r.appleId.trim();
  if (typeof r.icloudVaultPath === "string") s.icloudVaultPath = r.icloudVaultPath.trim().replace(/^\/+|\/+$/g, "");
  if (typeof r.autoSync === "boolean") s.autoSync = r.autoSync;
  if (typeof r.pollSeconds === "number" && Number.isFinite(r.pollSeconds)) s.pollSeconds = clamp(Math.round(r.pollSeconds), 30, 3600);
  if (typeof r.deletionThreshold === "number" && Number.isFinite(r.deletionThreshold)) {
    s.deletionThreshold = clamp(Math.round(r.deletionThreshold), 0, 1000);
  }
  if (typeof r.syncPluginCode === "boolean") s.syncPluginCode = r.syncPluginCode;
  if (Array.isArray(r.extraIgnore)) {
    s.extraIgnore = r.extraIgnore.filter((p): p is string => typeof p === "string").map((p) => p.trim()).filter(Boolean);
  }
  if (typeof r.forceIpv4 === "boolean") s.forceIpv4 = r.forceIpv4;
  return s;
}

/** Ignore patterns for everything the plugin itself must never sync. */
export function pluginIgnorePatterns(settings: Settings, configDir: string, pluginId: string): string[] {
  const patterns = [
    // This plugin's own folder: its code is per version, its settings per device.
    `${configDir}/plugins/${pluginId}/`,
    ...settings.extraIgnore,
  ];
  if (!settings.syncPluginCode) {
    // Plugin versions differ between desktop and mobile; syncing their code
    // produced the only conflicts in the real vault's dry run.
    patterns.push(
      `${configDir}/plugins/*/main.js`,
      `${configDir}/plugins/*/styles.css`,
      `${configDir}/plugins/*/manifest.json`,
    );
  }
  return patterns;
}
