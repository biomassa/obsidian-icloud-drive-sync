/**
 * The Obsidian UI: sign-in and code dialogs, the status view with the
 * deletion and conflict decisions, and the settings tab.
 */
import { App, Modal, Notice, PluginSettingTab, Setting, type Plugin } from "obsidian";

import type { CodePrompt, Status, SyncController } from "./controller.ts";
import type { Settings } from "./settings.ts";

export function statusText(s: Status): { text: string; tooltip: string } {
  switch (s.kind) {
    case "starting":
      return { text: "iCloud …", tooltip: "Connecting to iCloud" };
    case "signed-out":
      return { text: "iCloud: signed out", tooltip: s.message ?? "Sign in in the plugin settings" };
    case "blocked":
      return { text: "iCloud: not syncing", tooltip: s.message };
    case "idle":
      return { text: "iCloud ✓", tooltip: s.lastSync ? `Synced ${ago(s.lastSync)}` : "Up to date" };
    case "syncing":
      return {
        text: s.total ? `iCloud ${s.done}/${s.total}` : "iCloud ⟳",
        tooltip: s.total ? `Syncing: ${s.done} of ${s.total} changes` : "Checking for changes",
      };
    case "paused":
      return { text: "iCloud ⏸", tooltip: "Sync is paused" };
    case "attention":
      return { text: "iCloud ⚠", tooltip: s.message };
    case "error":
      return { text: "iCloud ✗", tooltip: s.message };
  }
}

/** Open the system file manager with this file selected (Electron's shell). */
export function showInFileManager(path: string): void {
  const { shell } = require("electron") as { shell: { showItemInFolder(fullPath: string): void } };
  shell.showItemInFolder(path);
}

export function ago(at: number): string {
  const s = Math.round((Date.now() - at) / 1000);
  if (s < 60) return "just now";
  if (s < 3600) return `${Math.round(s / 60)} min ago`;
  return `${Math.round(s / 3600)} h ago`;
}

// ── sign-in ───────────────────────────────────────────────────────────────────

export class SignInModal extends Modal {
  private readonly controller: SyncController;
  private readonly appleId: string;

  constructor(app: App, controller: SyncController, appleId: string) {
    super(app);
    this.controller = controller;
    this.appleId = appleId;
  }

  override onOpen(): void {
    this.titleEl.setText("Sign in to iCloud");
    const { contentEl } = this;
    contentEl.createEl("p", { text: `Apple ID: ${this.appleId}` });
    contentEl.createEl("p", {
      cls: "setting-item-description",
      text:
        "Your password is used once, now, and is not stored. Apple will then ask for a two-factor code. " +
        "The resulting session is kept in Obsidian's encrypted secret storage, outside the vault.",
    });
    let password = "";
    const error = contentEl.createEl("p", { cls: "mod-warning" });
    let button: HTMLButtonElement | null = null;
    const submit = async () => {
      if (!password || !button) return;
      button.disabled = true;
      button.setText("Signing in…");
      error.setText("");
      try {
        const ok = await this.controller.signIn(password);
        if (ok) {
          new Notice("Signed in to iCloud");
          this.close();
        } else {
          error.setText("Sign-in was not completed.");
        }
      } catch (e) {
        error.setText(e instanceof Error ? e.message : String(e));
      } finally {
        button.disabled = false;
        button.setText("Sign in");
      }
    };
    new Setting(contentEl).setName("Password").addText((t) => {
      t.inputEl.type = "password";
      t.inputEl.autocomplete = "current-password";
      t.onChange((v) => (password = v));
      t.inputEl.addEventListener("keydown", (ev) => {
        if (ev.key === "Enter") void submit();
      });
      setTimeout(() => t.inputEl.focus(), 0);
    });
    new Setting(contentEl).addButton((b) => {
      button = b.buttonEl;
      b.setButtonText("Sign in").setCta().onClick(() => void submit());
    });
  }

  override onClose(): void {
    this.contentEl.empty();
  }
}

/** Asks for a two-factor code; resolves null if closed without one. */
export class CodeModal extends Modal {
  private readonly prompt: CodePrompt;
  private resolve: ((code: string | null) => void) | null = null;

  constructor(app: App, prompt: CodePrompt) {
    super(app);
    this.prompt = prompt;
  }

  ask(): Promise<string | null> {
    return new Promise((resolve) => {
      this.resolve = resolve;
      this.open();
    });
  }

  private finish(code: string | null): void {
    const r = this.resolve;
    this.resolve = null;
    r?.(code);
    this.close();
  }

  override onOpen(): void {
    this.titleEl.setText("Two-factor authentication");
    const { contentEl } = this;
    const description = contentEl.createEl("p", { text: this.prompt.description });
    let code = "";
    new Setting(contentEl).setName("Verification code").addText((t) => {
      t.inputEl.inputMode = "numeric";
      t.inputEl.autocomplete = "one-time-code";
      t.inputEl.maxLength = 7;
      t.onChange((v) => (code = v));
      t.inputEl.addEventListener("keydown", (ev) => {
        if (ev.key === "Enter" && code.trim()) this.finish(code.trim());
      });
      setTimeout(() => t.inputEl.focus(), 0);
    });
    const buttons = new Setting(contentEl);
    if (this.prompt.canUseSms) {
      buttons.addButton((b) =>
        b.setButtonText("Text me a code instead").onClick(async () => {
          b.setDisabled(true);
          try {
            description.setText(await this.prompt.sendSms());
          } catch (e) {
            description.setText(`Could not send an SMS: ${e instanceof Error ? e.message : String(e)}`);
          }
        }),
      );
    }
    buttons.addButton((b) => b.setButtonText("Verify").setCta().onClick(() => code.trim() && this.finish(code.trim())));
  }

  override onClose(): void {
    this.contentEl.empty();
    if (this.resolve) this.finish(null);
  }
}

// ── status and decisions ─────────────────────────────────────────────────────

export class StatusModal extends Modal {
  private readonly controller: SyncController;

  constructor(app: App, controller: SyncController) {
    super(app);
    this.controller = controller;
  }

  override onOpen(): void {
    this.render();
  }

  private render(): void {
    const c = this.controller;
    const { contentEl } = this;
    contentEl.empty();
    this.titleEl.setText("iCloud Drive Sync");
    const { tooltip } = statusText(c.status);
    contentEl.createEl("p", { text: tooltip });

    const actions = new Setting(contentEl);
    actions.addButton((b) => b.setButtonText("Sync now").setCta().onClick(() => c.syncNow()));
    actions.addButton((b) =>
      c.status.kind === "paused"
        ? b.setButtonText("Resume").onClick(() => (c.resume(), this.render()))
        : b.setButtonText("Pause").onClick(() => (c.pause(), this.render())),
    );

    if (c.pendingDeletions.length) {
      contentEl.createEl("h3", { text: `${c.pendingDeletions.length} deletions waiting` });
      contentEl.createEl("p", {
        cls: "setting-item-description",
        text:
          "These files were deleted on one side. More than the threshold at once can mean something " +
          "went wrong, so they wait for you. Deleting moves them to the trash (this vault's .trash, or " +
          "Recently Deleted on iCloud); keeping copies them back to where they were deleted.",
      });
      const list = contentEl.createEl("ul", { cls: "icloud-sync-list" });
      for (const d of c.pendingDeletions) {
        list.createEl("li", { text: `${d.key} — deleted ${d.vanishedFrom === "local" ? "here" : "on iCloud"}` });
      }
      const keys = c.pendingDeletions.map((d) => d.key);
      new Setting(contentEl)
        .addButton((b) =>
          b.setButtonText("Delete them on both sides").setWarning().onClick(async () => {
            await c.confirmDeletions(keys);
            this.close();
          }),
        )
        .addButton((b) =>
          b.setButtonText("Keep them").onClick(async () => {
            await c.restoreDeletions(keys);
            this.close();
          }),
        );
    }

    if (c.conflictBurst) {
      contentEl.createEl("h3", { text: `${c.conflictBurst.count} files changed on both sides` });
      contentEl.createEl("p", {
        cls: "setting-item-description",
        text:
          "Each would be kept twice: iCloud's version under the original name, this device's as a " +
          '"(conflict …)" copy. Nothing is lost either way; this only asks because it is a lot of copies.',
      });
      const list = contentEl.createEl("ul", { cls: "icloud-sync-list" });
      for (const k of c.conflictBurst.keys.slice(0, 50)) list.createEl("li", { text: k });
      new Setting(contentEl).addButton((b) =>
        b.setButtonText("Keep both copies of each").setCta().onClick(() => {
          c.allowConflicts();
          this.close();
        }),
      );
    }

    if (c.newlyIgnored.length) {
      contentEl.createEl("h3", { text: `${c.newlyIgnored.length} synced files now match an ignore pattern` });
      contentEl.createEl("p", {
        cls: "setting-item-description",
        text: "They are left untouched on both sides. Stop tracking them to clear this, or remove the pattern.",
      });
      new Setting(contentEl).addButton((b) =>
        b.setButtonText("Stop tracking them").onClick(async () => {
          await c.untrackIgnored();
          this.render();
        }),
      );
    }

    const r = c.lastResult;
    if (r) {
      contentEl.createEl("h3", { text: "Last sync" });
      contentEl.createEl("p", {
        text:
          `${r.done.filter((d) => d.action.kind !== "refreshBase").length} changes, ` +
          `${r.skipped.length} skipped for the next sync, ${r.errors.length} failed` +
          (r.remoteScanReused ? " (used the cached iCloud listing)" : ""),
      });
      for (const e of r.errors.slice(0, 10)) contentEl.createEl("p", { cls: "mod-warning", text: e.error });
    }

    contentEl.createEl("h3", { text: "Activity" });
    const log = contentEl.createEl("div", { cls: "icloud-sync-log" });
    for (const line of c.log.slice(-60).reverse()) {
      const time = new Date(line.at).toLocaleTimeString();
      log.createEl("div", { cls: `icloud-sync-log-${line.level}`, text: `${time}  ${line.message}` });
    }
  }

  override onClose(): void {
    this.contentEl.empty();
  }
}

// ── settings ─────────────────────────────────────────────────────────────────

export interface SettingsHost extends Plugin {
  syncSettings: Settings;
  controller: SyncController;
  saveSettings(restart?: boolean): Promise<void>;
}

export class SettingsTab extends PluginSettingTab {
  private readonly host: SettingsHost;
  private unsubscribe: (() => void) | null = null;
  /** Vault folders found by the last "Find vaults", kept while the tab is open. */
  private found: string[] | null = null;

  constructor(app: App, host: SettingsHost) {
    super(app, host);
    this.host = host;
  }

  override display(): void {
    const { containerEl } = this;
    const { syncSettings: settings, controller } = this.host;
    containerEl.empty();
    this.unsubscribe?.();

    const status = new Setting(containerEl).setName("Status");
    this.unsubscribe = controller.onStatus((s) => status.setDesc(statusText(s).tooltip));

    new Setting(containerEl).setHeading().setName("Account");
    new Setting(containerEl)
      .setName("Apple ID")
      .setDesc("The email address of the Apple ID whose iCloud Drive holds the vault.")
      .addText((t) =>
        t
          .setPlaceholder("name@example.com")
          .setValue(settings.appleId)
          .onChange(async (v) => {
            settings.appleId = v.trim();
            await this.host.saveSettings(false);
          }),
      );
    const account = new Setting(containerEl);
    if (controller.isSignedIn) {
      account.setName(`Signed in as ${controller.accountName}`).addButton((b) =>
        b.setButtonText("Sign out").onClick(async () => {
          await controller.signOut();
          this.display();
        }),
      );
    } else {
      account
        .setName("Not signed in")
        .setDesc("Signing in asks for your password once and then a two-factor code.")
        .addButton((b) =>
          b
            .setButtonText("Sign in…")
            .setCta()
            .onClick(() => {
              if (!settings.appleId) return new Notice("Enter your Apple ID first");
              const modal = new SignInModal(this.app, controller, settings.appleId);
              modal.onClose = () => {
                modal.contentEl.empty();
                this.display();
              };
              modal.open();
            }),
        );
    }

    new Setting(containerEl).setHeading().setName("Vault");
    const folder = new Setting(containerEl)
      .setName("iCloud Drive folder")
      .setDesc('The vault\'s folder in iCloud Drive, for example "Obsidian/My Vault". It must already exist.')
      .addText((t) =>
        t
          .setPlaceholder("Obsidian/My Vault")
          .setValue(settings.icloudVaultPath)
          .onChange(async (v) => {
            settings.icloudVaultPath = v.trim().replace(/^\/+|\/+$/g, "");
            await this.host.saveSettings(false);
          }),
      );
    folder.addButton((b) =>
      b
        .setButtonText("Find vaults")
        .setDisabled(!controller.isSignedIn)
        .setTooltip(controller.isSignedIn ? "List the Obsidian vaults in your iCloud Drive" : "Sign in first")
        .onClick(async () => {
          b.setDisabled(true).setButtonText("Searching…");
          try {
            this.found = await controller.findVaults();
            if (!this.found.length) new Notice("No Obsidian vaults found in iCloud Drive");
          } catch (e) {
            new Notice(`Could not list iCloud Drive: ${e instanceof Error ? e.message : String(e)}`);
          }
          this.display();
        }),
    );
    folder.addButton((b) =>
      b.setButtonText("Apply").onClick(async () => {
        await this.host.saveSettings(true);
        new Notice("iCloud Drive Sync restarted with the new folder");
      }),
    );
    if (this.found?.length) {
      new Setting(containerEl)
        .setName("Vaults in your iCloud Drive")
        .setDesc(
          "Choose one to sync with this vault. If this vault is new and empty, the first sync " +
            "simply downloads it; otherwise both sides are compared file by file and nothing is overwritten.",
        )
        .addDropdown((d) => {
          d.addOption("", "Choose a vault…");
          for (const path of this.found!) d.addOption(path, path);
          d.setValue(this.found!.includes(settings.icloudVaultPath) ? settings.icloudVaultPath : "");
          d.onChange(async (path) => {
            if (!path || path === settings.icloudVaultPath) return;
            settings.icloudVaultPath = path;
            await this.host.saveSettings(true);
            new Notice(`Syncing with ${path} in iCloud Drive`);
            this.display();
          });
        });
    }

    new Setting(containerEl).setHeading().setName("Syncing");
    new Setting(containerEl)
      .setName("Sync automatically")
      .setDesc("Sync on changes here and poll iCloud for changes from other devices. Off: only “Sync now”.")
      .addToggle((t) =>
        t.setValue(settings.autoSync).onChange(async (v) => {
          settings.autoSync = v;
          await this.host.saveSettings(true);
        }),
      );
    new Setting(containerEl)
      .setName("Check iCloud every (seconds)")
      .setDesc("iCloud cannot notify of changes, so other devices' edits arrive on this schedule.")
      .addText((t) =>
        t.setValue(String(settings.pollSeconds)).onChange(async (v) => {
          const n = Number(v);
          if (Number.isFinite(n) && n >= 30) {
            settings.pollSeconds = Math.round(n);
            await this.host.saveSettings(true);
          }
        }),
      );
    new Setting(containerEl)
      .setName("Ask before more than this many deletions")
      .setDesc("Deletions beyond this, in one sync, wait for your confirmation.")
      .addText((t) =>
        t.setValue(String(settings.deletionThreshold)).onChange(async (v) => {
          const n = Number(v);
          if (Number.isInteger(n) && n >= 0) {
            settings.deletionThreshold = n;
            await this.host.saveSettings(true);
          }
        }),
      );
    new Setting(containerEl)
      .setName("Sync plugin code")
      .setDesc("Plugins' settings always sync. Their code (main.js, styles.css, manifest.json) differs between desktop and mobile versions, so it is off by default.")
      .addToggle((t) =>
        t.setValue(settings.syncPluginCode).onChange(async (v) => {
          settings.syncPluginCode = v;
          await this.host.saveSettings(true);
        }),
      );
    new Setting(containerEl)
      .setName("Also ignore")
      .setDesc('One pattern per line. "Archive/" ignores a folder and everything in it; "*.bak" matches any file name.')
      .addTextArea((t) => {
        t.setValue(settings.extraIgnore.join("\n"));
        t.inputEl.rows = 4;
        t.inputEl.addEventListener("blur", async () => {
          settings.extraIgnore = t.getValue().split("\n").map((l) => l.trim()).filter(Boolean);
          await this.host.saveSettings(true);
        });
      });
    new Setting(containerEl).setHeading().setName("Activity log");
    const logPath = controller.logPath;
    new Setting(containerEl)
      .setName("Log file")
      .setDesc(
        logPath
          ? `The latest ${1000} entries. The file is outside the vault and does not sync: ${logPath}`
          : "The log is kept in memory only.",
      )
      .addButton((b) =>
        b
          .setButtonText("Show in file manager")
          .setDisabled(!logPath)
          .onClick(async () => {
            try {
              await controller.flushLog();
              showInFileManager(logPath!);
            } catch (e) {
              new Notice(`Could not show the log file: ${e instanceof Error ? e.message : String(e)}`);
            }
          }),
      )
      .addButton((b) =>
        b
          .setButtonText("Clear log")
          .setWarning()
          .onClick(async () => {
            await controller.clearLog();
            new Notice("Activity log cleared");
          }),
      );

    new Setting(containerEl).setHeading().setName("Network");
    new Setting(containerEl)
      .setName("Use IPv4 only")
      .setDesc("For networks that advertise IPv6 but do not route it, where every connection stalls.")
      .addToggle((t) =>
        t.setValue(settings.forceIpv4).onChange(async (v) => {
          settings.forceIpv4 = v;
          await this.host.saveSettings(true);
        }),
      );
  }

  override hide(): void {
    this.unsubscribe?.();
    this.unsubscribe = null;
  }
}
