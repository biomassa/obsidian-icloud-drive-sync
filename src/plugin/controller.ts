/**
 * The plugin's brain, without any Obsidian UI: sign-in, starting and stopping
 * sync, and what to do with each cycle's outcome. main.ts wires it to
 * Obsidian; tests wire it to fakes.
 *
 * Sign-in rules, from the lockout on 2026-09-29:
 * - The password is used only when the user clicks Sign in. Never on a timer,
 *   never retried automatically after Apple rejects it.
 * - An expired session is first re-established from the stored tokens alone
 *   (no password, no code); only if that fails does the user get asked.
 * - A 2FA code is requested only when the user is there to type it.
 */
import { ICloudAuth } from "../icloud/auth.ts";
import { DriveClient, isFolderLike } from "../icloud/drive.ts";
import { FailedLoginError, ICloudError } from "../icloud/errors.ts";
import { nodeTransport, type Transport } from "../icloud/http.ts";
import { discoverVaults } from "../icloud/vaults.ts";
import { SyncEngine, describeAbort, type CycleOptions, type CycleResult, type LogLevel } from "../sync/engine.ts";
import { IgnoreFilter } from "../sync/filters.ts";
import { ICloudRemote } from "../sync/icloud-remote.ts";
import { NodeLocalFs } from "../sync/node-local.ts";
import { SyncScheduler, type Timers, type Trigger } from "../sync/scheduler.ts";
import { FileStateStore } from "../sync/state.ts";
import type { LocalFs, PendingDeletion, Remote, StateStore } from "../sync/types.ts";
import { toKey } from "../sync/filters.ts";
import {
  SecretSessionStore,
  obsisyncManages,
  secretStorageEncryption,
  stateFilePath,
  type SecretStorageLike,
} from "./environment.ts";
import { pluginIgnorePatterns, type Settings } from "./settings.ts";

export type Status =
  | { kind: "starting" }
  | { kind: "signed-out"; message?: string }
  | { kind: "blocked"; message: string }
  | { kind: "idle"; lastSync?: number }
  | { kind: "syncing"; done: number; total: number }
  | { kind: "paused" }
  | { kind: "attention"; message: string }
  | { kind: "error"; message: string };

export interface CodePrompt {
  description: string;
  canUseSms: boolean;
  /** Switch delivery to SMS; resolves with the new description. */
  sendSms: () => Promise<string>;
}

export interface ControllerUI {
  notify(message: string, timeoutMs?: number): void;
  /** Ask for a 2FA code. Resolves null if the user cancels. */
  askCode(prompt: CodePrompt): Promise<string | null>;
}

export interface LogLine {
  at: number;
  level: LogLevel;
  message: string;
}

export interface ControllerDeps {
  settings: () => Settings;
  vaultRoot: string;
  configDir: string;
  pluginId: string;
  secrets: SecretStorageLike;
  ui: ControllerUI;
  /** Tests substitute these. */
  transport?: Transport;
  openRemote?: (auth: ICloudAuth, settings: Settings, filter: IgnoreFilter) => Promise<Remote>;
  openLocal?: (root: string, filter: IgnoreFilter) => LocalFs;
  stateStore?: StateStore;
  timers?: Timers;
  skipEnvironmentChecks?: boolean;
}

export class SyncController {
  private readonly deps: ControllerDeps;
  private auth: ICloudAuth | null = null;
  private engine: SyncEngine | null = null;
  private scheduler: SyncScheduler | null = null;
  private signingIn = false;
  private listeners = new Set<(s: Status) => void>();
  private lastSync: number | undefined;
  private lastParkedSignature = "";

  status: Status = { kind: "starting" };
  readonly log: LogLine[] = [];
  lastResult: CycleResult | null = null;
  pendingDeletions: PendingDeletion[] = [];
  conflictBurst: { count: number; keys: string[] } | null = null;
  newlyIgnored: string[] = [];

  constructor(deps: ControllerDeps) {
    this.deps = deps;
  }

  onStatus(listener: (s: Status) => void): () => void {
    this.listeners.add(listener);
    listener(this.status);
    return () => this.listeners.delete(listener);
  }

  private setStatus(s: Status): void {
    this.status = s;
    for (const l of this.listeners) l(s);
  }

  private record(level: LogLevel, message: string): void {
    this.log.push({ at: Date.now(), level, message });
    if (this.log.length > 300) this.log.splice(0, this.log.length - 300);
  }

  get isSignedIn(): boolean {
    return this.auth?.isTrustedSession === true;
  }

  get accountName(): string | undefined {
    return this.auth?.accountName;
  }

  private transport(settings: Settings): Transport {
    return this.deps.transport ?? nodeTransport({ family: settings.forceIpv4 ? 4 : 0 });
  }

  private async openAuth(settings: Settings): Promise<ICloudAuth> {
    return ICloudAuth.open({
      accountName: settings.appleId,
      store: new SecretSessionStore(this.deps.secrets, settings.appleId),
      transport: this.transport(settings),
      bridge: { family: settings.forceIpv4 ? 4 : 0 },
    });
  }

  /** Reasons not to run at all, checked before anything touches the network. */
  private async blocker(settings: Settings): Promise<string | null> {
    if (this.deps.skipEnvironmentChecks) return null;
    if (secretStorageEncryption() === "plaintext") return plaintextSecretsMessage();
    if (await obsisyncManages(this.deps.vaultRoot)) {
      return "obsisync is set up to sync this same folder. Two sync tools on one vault would fight; stop obsisync first.";
    }
    if (!settings.appleId) return null; // handled as signed-out
    return null;
  }

  /** On plugin load: resume a stored session if there is one; never prompts. */
  async start(): Promise<void> {
    const settings = this.deps.settings();
    const blocked = await this.blocker(settings);
    if (blocked) return this.setStatus({ kind: "blocked", message: blocked });
    if (!settings.appleId) return this.setStatus({ kind: "signed-out", message: "Enter your Apple ID in settings" });
    try {
      this.auth = await this.openAuth(settings);
      if (!(await this.auth.resume())) {
        return this.setStatus({ kind: "signed-out", message: "Sign in to iCloud in settings" });
      }
      await this.startSync();
    } catch (e) {
      this.record("error", `Could not connect: ${errorText(e)}`);
      this.setStatus({ kind: "error", message: `Could not connect to iCloud: ${errorText(e)}` });
    }
  }

  /**
   * The user clicked Sign in. Runs the password sign-in once, then two-factor
   * with the user at the keyboard. Resolves true when signed in.
   */
  async signIn(password: string): Promise<boolean> {
    if (this.signingIn) throw new Error("a sign-in is already in progress");
    this.signingIn = true;
    const settings = this.deps.settings();
    try {
      const blocked = await this.blocker(settings);
      if (blocked) {
        this.setStatus({ kind: "blocked", message: blocked });
        return false;
      }
      await this.stopSync();
      this.auth = await this.openAuth(settings);
      const result = await this.auth.signIn(password);
      if (result.status === "needs-2fa" && !(await this.twoFactor(this.auth))) {
        this.setStatus({ kind: "signed-out", message: "Two-factor authentication was cancelled" });
        return false;
      }
      await this.auth.session.persist();
      this.record("info", `Signed in as ${settings.appleId}`);
    } catch (e) {
      const message =
        e instanceof FailedLoginError
          ? `${e.message}. Not retried: repeated failures can lock the Apple ID.`
          : errorText(e);
      this.record("error", `Sign-in failed: ${message}`);
      this.setStatus({ kind: "signed-out", message });
      throw new Error(message);
    } finally {
      this.signingIn = false;
    }
    // Signed in. A problem starting sync (say, the iCloud folder is missing)
    // is reported as such; it does not undo the sign-in.
    try {
      await this.startSync();
    } catch (e) {
      this.record("error", `Could not start syncing: ${errorText(e)}`);
      this.setStatus({ kind: "error", message: `Signed in, but could not start syncing: ${errorText(e)}` });
    }
    return true;
  }

  private async twoFactor(auth: ICloudAuth): Promise<boolean> {
    let method = await auth.requestCode();
    for (let attempt = 1; attempt <= 3; attempt++) {
      const code = await this.deps.ui.askCode({
        description: auth.deliveryDescription ?? "Enter the verification code Apple sent you.",
        canUseSms: auth.canUseSms && method !== "sms",
        sendSms: async () => {
          method = await auth.requestCode({ preferSms: true });
          return auth.deliveryDescription ?? "Apple sent a code by SMS.";
        },
      });
      if (code === null) {
        auth.cancelChallenge();
        return false;
      }
      if (await auth.submitCode(code)) return true;
      if (attempt === 3) break;
      if (method === "trusted_device") {
        // A device prompt is single-use once a code has been tried.
        this.deps.ui.notify("That code was not accepted. Apple is sending a new prompt.");
        method = await auth.requestCode();
      } else {
        this.deps.ui.notify("That code was not accepted. Try again.");
      }
    }
    throw new ICloudError("the verification code was not accepted");
  }

  async signOut(): Promise<void> {
    await this.stopSync();
    await this.auth?.signOut();
    this.auth = null;
    this.record("info", "Signed out");
    this.setStatus({ kind: "signed-out", message: "Signed out" });
  }

  /** Vault folders found in iCloud Drive; needs a signed-in session. */
  async findVaults(): Promise<string[]> {
    if (!this.auth || !this.isSignedIn) throw new Error("sign in first");
    await this.auth.ensureDriveAccess();
    return discoverVaults(new DriveClient(this.auth));
  }

  private filter(settings: Settings): IgnoreFilter {
    return new IgnoreFilter(pluginIgnorePatterns(settings, this.deps.configDir, this.deps.pluginId));
  }

  private async startSync(): Promise<void> {
    const settings = this.deps.settings();
    const auth = this.auth!;
    if (!settings.icloudVaultPath) {
      return this.setStatus({ kind: "blocked", message: "Choose the vault's folder in iCloud Drive in settings" });
    }
    const filter = this.filter(settings);
    const remote = this.deps.openRemote
      ? await this.deps.openRemote(auth, settings, filter)
      : await this.openICloudRemote(auth, settings, filter);
    const local = this.deps.openLocal
      ? this.deps.openLocal(this.deps.vaultRoot, filter)
      : new NodeLocalFs({ root: this.deps.vaultRoot, filter });
    this.engine = new SyncEngine({
      local,
      remote,
      store: this.deps.stateStore ?? new FileStateStore(stateFilePath(this.deps.vaultRoot)),
      filter,
      log: (level, message) => this.record(level, message),
      options: { deletionThreshold: settings.deletionThreshold },
    });
    this.pendingDeletions = await this.engine.pendingDeletions();
    this.scheduler = new SyncScheduler((trigger, options) => this.cycle(trigger, options), {
      pollMs: settings.pollSeconds * 1000,
      ...(this.deps.timers ? { timers: this.deps.timers } : {}),
    });
    if (settings.autoSync) {
      this.scheduler.start();
    } else {
      this.setStatus({ kind: "paused" });
    }
  }

  private async openICloudRemote(auth: ICloudAuth, settings: Settings, filter: IgnoreFilter): Promise<Remote> {
    await auth.ensureDriveAccess();
    const drive = new DriveClient(auth);
    const parts = settings.icloudVaultPath.split("/").filter(Boolean);
    const folder = await drive.resolve(parts);
    if (!folder || !isFolderLike(folder)) {
      throw new ICloudError(`the folder "${settings.icloudVaultPath}" was not found in iCloud Drive`);
    }
    return new ICloudRemote({ drive, vaultPath: parts, filter });
  }

  private async stopSync(): Promise<void> {
    const scheduler = this.scheduler;
    this.scheduler = null;
    await scheduler?.stop();
    this.engine = null;
  }

  /** Settings changed: rebuild the engine with the new filter and schedule. */
  async restart(): Promise<void> {
    await this.stopSync();
    if (this.isSignedIn) {
      try {
        await this.startSync();
      } catch (e) {
        this.setStatus({ kind: "error", message: errorText(e) });
      }
    } else {
      await this.start();
    }
  }

  async stop(): Promise<void> {
    await this.stopSync();
  }

  // ── running cycles ─────────────────────────────────────────────────────────

  private async cycle(trigger: Trigger, options: CycleOptions): Promise<CycleResult | void> {
    const engine = this.engine;
    if (!engine) return;
    this.setStatus({ kind: "syncing", done: 0, total: 0 });
    const result = await engine.runCycle({
      ...options,
      onProgress: (done, total) => this.setStatus({ kind: "syncing", done, total }),
    });
    this.lastResult = result;
    await this.handle(result, engine, trigger);
    return result;
  }

  private async handle(result: CycleResult, engine: SyncEngine, trigger: Trigger): Promise<void> {
    this.pendingDeletions = result.parked;
    this.newlyIgnored = result.newlyIgnored;
    const abort = result.abort;

    if (abort?.reason === "auth-required") {
      // First try the stored tokens alone — no password, no code.
      if (this.auth && (await this.auth.resume().catch(() => false))) {
        engine.invalidateRemoteScan();
        this.record("info", "Reconnected to iCloud");
        this.setStatus({ kind: "idle", lastSync: this.lastSync });
        return;
      }
      this.scheduler?.pause();
      this.setStatus({ kind: "signed-out", message: "iCloud needs you to sign in again" });
      this.deps.ui.notify("iCloud Drive Sync: iCloud needs you to sign in again (Settings → iCloud Drive Sync).", 0);
      return;
    }
    if (abort && "tracked" in abort) {
      // An empty side against tracked files: stop and ask, never guess.
      this.scheduler?.pause();
      const message = `Sync paused: ${describeAbort(abort)}. Check the vault and the iCloud folder, then resume.`;
      this.setStatus({ kind: "attention", message });
      this.deps.ui.notify(`iCloud Drive Sync: ${message}`, 0);
      return;
    }
    if (abort?.reason === "too-many-conflicts") {
      this.conflictBurst = { count: abort.count, keys: abort.keys };
      const message = `${abort.count} files changed both here and on iCloud. Open the sync status to decide.`;
      this.setStatus({ kind: "attention", message });
      this.deps.ui.notify(`iCloud Drive Sync: ${message}`, 0);
      return;
    }
    this.conflictBurst = null;
    if (abort?.reason === "cancelled") {
      this.setStatus({ kind: "paused" });
      return;
    }
    if (abort) {
      this.setStatus({ kind: "error", message: "message" in abort ? abort.message : describeAbort(abort) });
      return;
    }

    this.lastSync = Date.now();
    if (result.parked.length) {
      const signature = result.parked.map((p) => p.key).sort().join("\n");
      const message = `${result.parked.length} deletions are waiting for your confirmation`;
      this.setStatus({ kind: "attention", message });
      if (signature !== this.lastParkedSignature) {
        this.lastParkedSignature = signature;
        this.deps.ui.notify(`iCloud Drive Sync: ${message}. Open the sync status to review them.`, 0);
      }
      return;
    }
    this.lastParkedSignature = "";
    if (result.errors.length) {
      this.setStatus({ kind: "error", message: `${result.errors.length} file(s) failed; retrying on the next sync` });
      return;
    }
    if (trigger !== "local" && result.newlyIgnored.length) {
      this.setStatus({
        kind: "attention",
        message: `${result.newlyIgnored.length} synced files now match an ignore pattern and are left untouched`,
      });
      return;
    }
    this.setStatus(this.scheduler?.isPaused ? { kind: "paused" } : { kind: "idle", lastSync: this.lastSync });
  }

  // ── user actions ───────────────────────────────────────────────────────────

  /** A file in the vault changed on disk (vault-relative paths). */
  localChange(...paths: string[]): void {
    this.scheduler?.localChange(...paths.map(toKey));
  }

  syncNow(): void {
    if (!this.scheduler) return;
    if (this.scheduler.isPaused) this.scheduler.resume();
    else if (!this.deps.settings().autoSync) this.scheduler.runOnce();
    else this.scheduler.syncNow();
  }

  pause(): void {
    this.scheduler?.pause();
    this.engine?.cancel();
    if (this.status.kind !== "syncing") this.setStatus({ kind: "paused" });
  }

  resume(): void {
    this.scheduler?.resume();
  }

  async confirmDeletions(keys: string[]): Promise<void> {
    this.engine?.confirmDeletions(keys);
    this.record("info", `Confirmed ${keys.length} deletion(s)`);
    this.syncNow();
  }

  async restoreDeletions(keys: string[]): Promise<void> {
    await this.engine?.restoreDeletions(keys);
    this.record("info", `Kept ${keys.length} file(s); they will be copied back`);
    this.syncNow();
  }

  allowConflicts(): void {
    this.engine?.allowConflictsOnce();
    this.conflictBurst = null;
    this.record("info", "Keeping both copies of each conflicting file");
    this.syncNow();
  }

  async untrackIgnored(): Promise<void> {
    await this.engine?.untrack(this.newlyIgnored);
    this.record("info", `Stopped tracking ${this.newlyIgnored.length} ignored file(s); both copies kept`);
    this.newlyIgnored = [];
    this.syncNow();
  }
}

/**
 * Electron picks its Linux secret backend from the desktop session and only
 * recognises GNOME and KDE. Under anything else (niri, Hyprland, Sway…) it
 * falls back to plaintext even with a keyring running — found on the
 * developer's niri machine, where gnome-keyring was serving the Secret Service.
 */
function plaintextSecretsMessage(): string {
  const desktop = process.env.XDG_CURRENT_DESKTOP;
  if (process.platform === "linux") {
    return (
      "Obsidian is storing secrets unencrypted, so the iCloud session is not saved. " +
      `On Linux, Electron only detects the keyring under GNOME or KDE${desktop ? ` (this session: ${desktop})` : ""}. ` +
      "If a keyring is running, add the line --password-store=gnome-libsecret (gnome-keyring, KeePassXC) " +
      "or --password-store=kwallet6 (KWallet) to ~/.config/obsidian/user-flags.conf and restart Obsidian. " +
      "Otherwise start a keyring first."
    );
  }
  return "Obsidian cannot encrypt secrets on this system, so the iCloud session is not saved.";
}

function errorText(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}
