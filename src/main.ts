import { existsSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

import { FileSystemAdapter, Notice, Plugin, TAbstractFile, TFolder } from "obsidian";

import { SyncController } from "./plugin/controller.ts";
import { SESSION_SECRET_ID } from "./plugin/environment.ts";
import { sanitizeSettings, type Settings } from "./plugin/settings.ts";
import { CodeModal, SettingsTab, StatusModal, statusText, type SettingsHost } from "./plugin/ui.ts";

/** Where the Node spike keeps the session it trusted; for development only. */
const SPIKE_SESSION = join(homedir(), ".local", "share", "icloud-obsi-spike", "session.json");

export default class ICloudDriveSyncPlugin extends Plugin implements SettingsHost {
  syncSettings!: Settings;
  controller!: SyncController;

  override async onload(): Promise<void> {
    this.syncSettings = sanitizeSettings(await this.loadData());
    const adapter = this.app.vault.adapter;
    if (!(adapter instanceof FileSystemAdapter)) {
      new Notice("iCloud Drive Sync works only on desktop.");
      return;
    }

    this.controller = new SyncController({
      settings: () => this.syncSettings,
      vaultRoot: adapter.getBasePath(),
      configDir: this.app.vault.configDir,
      pluginId: this.manifest.id,
      secrets: this.app.secretStorage,
      ui: {
        notify: (message, timeout) => new Notice(message, timeout ?? 8000),
        askCode: (prompt) => new CodeModal(this.app, prompt).ask(),
      },
    });

    const bar = this.addStatusBarItem();
    bar.addClass("mod-clickable");
    bar.addEventListener("click", () => new StatusModal(this.app, this.controller).open());
    const paint = () => {
      const { text, tooltip } = statusText(this.controller.status);
      bar.setText(text);
      bar.setAttribute("aria-label", tooltip);
      bar.setAttribute("data-tooltip-position", "top");
    };
    this.register(this.controller.onStatus(paint));
    this.registerInterval(window.setInterval(paint, 30_000));

    this.addRibbonIcon("refresh-cw", "iCloud Drive Sync: sync now", () => this.controller.syncNow());
    this.addCommand({ id: "sync-now", name: "Sync now", callback: () => this.controller.syncNow() });
    this.addCommand({ id: "show-status", name: "Show status", callback: () => new StatusModal(this.app, this.controller).open() });
    this.addCommand({ id: "pause", name: "Pause syncing", callback: () => this.controller.pause() });
    this.addCommand({ id: "resume", name: "Resume syncing", callback: () => this.controller.resume() });
    if (existsSync(SPIKE_SESSION)) {
      this.addCommand({
        id: "dev-import-spike-session",
        name: "Developer: use the session from the Node spike",
        callback: () => this.importSpikeSession(),
      });
    }
    this.addSettingTab(new SettingsTab(this.app, this));

    this.app.workspace.onLayoutReady(() => {
      // Registered after layout-ready, so loading the vault is not a flood of "create" events.
      const changed = (file: TAbstractFile, ...extra: string[]) => {
        if (!(file instanceof TFolder)) this.controller.localChange(file.path, ...extra);
      };
      this.registerEvent(this.app.vault.on("create", (f) => changed(f)));
      this.registerEvent(this.app.vault.on("modify", (f) => changed(f)));
      this.registerEvent(this.app.vault.on("delete", (f) => changed(f)));
      this.registerEvent(this.app.vault.on("rename", (f, oldPath) => changed(f, oldPath)));
      void this.controller.start();
    });
  }

  override async onunload(): Promise<void> {
    await this.controller?.stop();
  }

  async saveSettings(restart = true): Promise<void> {
    this.syncSettings = sanitizeSettings(this.syncSettings);
    await this.saveData(this.syncSettings);
    if (restart) await this.controller.restart();
  }

  /**
   * Development only: reuse the session the Node spike already trusted, so
   * the plugin never has to make its first password sign-in from Electron
   * while that path is unverified. Copies session tokens between two stores
   * on this machine; nothing touches the vault.
   */
  private async importSpikeSession(): Promise<void> {
    try {
      const text = readFileSync(SPIKE_SESSION, "utf8");
      const parsed = JSON.parse(text);
      if (!this.syncSettings.appleId) this.syncSettings.appleId = parsed.accountName;
      if (parsed.accountName !== this.syncSettings.appleId) {
        new Notice(`The spike session is for ${parsed.accountName}, not ${this.syncSettings.appleId}.`);
        return;
      }
      this.app.secretStorage.setSecret(SESSION_SECRET_ID, text);
      await this.saveSettings(false);
      new Notice("Imported the spike's iCloud session. Connecting…");
      await this.controller.restart();
    } catch (e) {
      new Notice(`Could not import the spike session: ${e instanceof Error ? e.message : String(e)}`);
    }
  }
}
