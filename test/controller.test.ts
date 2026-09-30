/**
 * The controller: sign-in rules, session reuse, and what the user is told.
 * Apple is scripted (FakeApple), both file trees are in memory, and time is
 * virtual.
 */
import { test } from "node:test";
import assert from "node:assert/strict";

import { SyncController, mergePluginLists, type ControllerUI, type Status } from "../src/plugin/controller.ts";
import { SESSION_SECRET_ID, type SecretStorageLike } from "../src/plugin/environment.ts";
import { DEFAULT_SETTINGS, sanitizeSettings, pluginIgnorePatterns, type Settings } from "../src/plugin/settings.ts";
import { IgnoreFilter } from "../src/sync/filters.ts";
import { MemoryStateStore } from "../src/sync/state.ts";
import { PersistentLog } from "../src/plugin/log-store.ts";
import { FakeApple } from "./fake-apple.ts";
import { Clock, FakeLocal, FakeRemote } from "./fakes.ts";
import { VirtualTimers } from "./virtual-timers.ts";

class MemorySecrets implements SecretStorageLike {
  values = new Map<string, string>();
  setSecret(id: string, secret: string) {
    this.values.set(id, secret);
  }
  getSecret(id: string) {
    return this.values.get(id) ?? null;
  }
}

function harness(opts: {
  apple?: FakeApple;
  secrets?: MemorySecrets;
  codes?: (string | null)[];
  settings?: Partial<Settings>;
  platform?: NodeJS.Platform;
} = {}) {
  const apple = opts.apple ?? new FakeApple();
  const secrets = opts.secrets ?? new MemorySecrets();
  const timers = new VirtualTimers();
  const clock = new Clock();
  const local = new FakeLocal(clock);
  const remote = new FakeRemote(clock);
  const notes: string[] = [];
  const statuses: Status[] = [];
  const codes = [...(opts.codes ?? ["123456"])];
  const prompts: string[] = [];
  const ui: ControllerUI = {
    notify: (m) => notes.push(m),
    askCode: async (p) => {
      prompts.push(p.description);
      return codes.length ? codes.shift()! : null;
    },
  };
  const settings: Settings = { ...DEFAULT_SETTINGS, appleId: "user@example.com", icloudVaultPath: "Vault", ...opts.settings };
  const controller = new SyncController({
    settings: () => settings,
    vaultRoot: "/vault",
    configDir: ".obsidian",
    pluginId: "icloud-drive-sync",
    secrets,
    ui,
    transport: apple.transport,
    openRemote: async () => remote,
    openLocal: () => local,
    stateStore: new MemoryStateStore(),
    logStore: new PersistentLog(null),
    timers,
    skipEnvironmentChecks: true,
    platform: opts.platform ?? "linux",
  });
  controller.onStatus((s) => statuses.push(s));
  return { apple, secrets, timers, local, remote, notes, statuses, controller, prompts };
}

test("with no stored session, start asks for sign-in and contacts no one", async () => {
  const h = harness();
  await h.controller.start();
  assert.equal(h.controller.status.kind, "signed-out");
  assert.equal(h.apple.calls.length, 0);
});

test("sign-in with two-factor: a wrong code, then the right one, then sync starts", async () => {
  const h = harness({ codes: ["000000", "123456"] });
  h.local.put("hello.md", "hi");
  assert.equal(await h.controller.signIn("pw"), true);
  assert.equal(h.prompts.length, 2);
  assert.ok(h.notes.some((n) => /not accepted/.test(n)));
  await h.timers.advance(10);
  assert.equal(h.remote.get("hello.md"), "hi", "the first cycle ran");
  assert.equal(h.controller.status.kind, "idle");
  const stored = JSON.parse(h.secrets.getSecret(SESSION_SECRET_ID)!);
  assert.equal(stored.data.trust_token, "trust-1", "the session went to secret storage");
  await h.controller.stop();
});

test("a rejected password is reported once and never retried", async () => {
  const h = harness({ apple: new FakeApple({ wrongPassword: true }) });
  await assert.rejects(h.controller.signIn("wrong"), /Not retried/);
  assert.equal(h.apple.count("POST", "/signin/complete"), 1);
  assert.equal(h.controller.status.kind, "signed-out");
  await h.timers.advance(600_000);
  assert.equal(h.apple.count("POST", "/signin/complete"), 1, "no retry on any timer");
});

test("cancelling two-factor leaves the user signed out", async () => {
  const h = harness({ codes: [null] });
  assert.equal(await h.controller.signIn("pw"), false);
  assert.equal(h.controller.status.kind, "signed-out");
});

test("a later start resumes from secret storage: no password, no code", async () => {
  const first = harness();
  await first.controller.signIn("pw");
  await first.controller.stop();

  const again = harness({ apple: first.apple, secrets: first.secrets, codes: [] });
  const before = first.apple.calls.length;
  await again.controller.start();
  await again.timers.advance(10);
  const later = first.apple.calls.slice(before);
  assert.ok(later.every((c) => !c.path.includes("/signin/") && !c.path.includes("/verify/")));
  assert.equal(again.prompts.length, 0);
  assert.equal(again.controller.status.kind, "idle");
  await again.controller.stop();
});

test("an expired session mid-sync is re-established from tokens alone when possible", async () => {
  const h = harness();
  await h.controller.signIn("pw");
  await h.timers.advance(10);
  h.remote.authFailAfter = h.remote.calls; // the next iCloud request fails
  h.controller.syncNow();
  await h.timers.advance(10);
  h.remote.authFailAfter = Infinity;
  assert.equal(h.controller.status.kind, "idle", "reconnected without asking");
  assert.ok(h.controller.log.some((l) => /Reconnected/.test(l.message)));
  await h.controller.stop();
});

test("when the tokens are no longer accepted, sync pauses and the user is told once", async () => {
  const h = harness();
  await h.controller.signIn("pw");
  await h.timers.advance(10);
  h.apple.expireSession();
  h.remote.authFailAfter = h.remote.calls;
  h.controller.syncNow();
  await h.timers.advance(10);
  assert.equal(h.controller.status.kind, "signed-out");
  assert.equal(h.notes.filter((n) => /sign in again/.test(n)).length, 1);
  const signIns = h.apple.count("POST", "/signin/complete");
  await h.timers.advance(3_600_000);
  assert.equal(h.apple.count("POST", "/signin/complete"), signIns, "never signs in with a password by itself");
  await h.controller.stop();
});

test("parked deletions ask once, and the answer is carried out", async () => {
  const h = harness();
  for (let i = 0; i < 20; i++) h.local.put(`n${i}.md`, `note ${i}`);
  await h.controller.signIn("pw");
  await h.timers.advance(10);
  for (const k of ["n1.md", "n2.md", "n3.md", "n4.md"]) h.remote.files.delete(k);
  h.controller.syncNow();
  await h.timers.advance(10);
  assert.equal(h.controller.status.kind, "attention");
  assert.equal(h.controller.pendingDeletions.length, 4);
  h.controller.syncNow();
  await h.timers.advance(10);
  assert.equal(h.notes.filter((n) => /waiting for your confirmation/.test(n)).length, 1, "asked once, not every cycle");
  await h.controller.confirmDeletions(h.controller.pendingDeletions.map((p) => p.key));
  await h.timers.advance(10);
  assert.equal(h.local.files.size, 16);
  assert.equal(h.controller.status.kind, "idle");
  await h.controller.stop();
});

test("settings keep only known keys, so data.json can never hold a secret", () => {
  const s = sanitizeSettings({
    appleId: " someone@example.com ",
    password: "hunter2",
    session_token: "abc",
    icloudVaultPath: "/Obsidian/Vault/",
    pollSeconds: 5,
    extraIgnore: ["Archive/", 3, ""],
  });
  assert.deepEqual(Object.keys(s).sort(), Object.keys(DEFAULT_SETTINGS).sort());
  assert.equal(s.appleId, "someone@example.com");
  assert.equal(s.icloudVaultPath, "Obsidian/Vault");
  assert.equal(s.pollSeconds, 30, "clamped");
  assert.deepEqual(s.extraIgnore, ["Archive/"]);
  assert.ok(!JSON.stringify(s).includes("hunter2"));
});

test("plugin code and this plugin's folder are not synced; plugin settings are", () => {
  const f = new IgnoreFilter(pluginIgnorePatterns(DEFAULT_SETTINGS, ".obsidian", "icloud-drive-sync"));
  assert.equal(f.ignores(".obsidian/plugins/obsidian-tasks-plugin/main.js"), true);
  assert.equal(f.ignores(".obsidian/plugins/colored-tags/styles.css"), true);
  assert.equal(f.ignores(".obsidian/plugins/colored-tags/manifest.json"), true);
  assert.equal(f.ignores(".obsidian/plugins/colored-tags/data.json"), false, "settings still sync");
  assert.equal(f.ignores(".obsidian/plugins/icloud-drive-sync/data.json"), true, "our own folder never syncs");
  const withCode = new IgnoreFilter(pluginIgnorePatterns({ ...DEFAULT_SETTINGS, syncPluginCode: true }, ".obsidian", "x"));
  assert.equal(withCode.ignores(".obsidian/plugins/obsidian-tasks-plugin/main.js"), false);
});

test("on a Mac the plugin refuses: iCloud Drive already syncs the vault there", async () => {
  const h = harness({ platform: "darwin" });
  await h.controller.start();
  assert.equal(h.controller.status.kind, "blocked");
  assert.match((h.controller.status as { message: string }).message, /iCloud Drive already syncs/);
  assert.equal(h.apple.calls.length, 0, "nothing contacted");
  await assert.doesNotReject(async () => assert.equal(await h.controller.signIn("pw"), false));
  assert.equal(h.apple.calls.length, 0, "not even a sign-in");
});

test("the enabled-plugins merge keeps iCloud's list and adds this vault's", () => {
  const enc = (v: unknown) => new TextEncoder().encode(JSON.stringify(v));
  const merged = mergePluginLists(enc(["icloud-drive-sync", "dataview"]), enc(["dataview", "calendar"]));
  assert.deepEqual(JSON.parse(new TextDecoder().decode(merged!)), ["dataview", "calendar", "icloud-drive-sync"]);
  assert.equal(mergePluginLists(enc({ not: "a list" }), enc([])), null);
  assert.equal(mergePluginLists(new TextEncoder().encode("{broken"), enc([])), null);
});

test("a temporary iCloud server error shows as a warning, not an error", async () => {
  const { ApiError } = await import("../src/icloud/errors.ts");
  const h = harness();
  await h.controller.signIn("pw");
  await h.timers.advance(10);
  h.remote.scanError = new ApiError("Service Unavailable", 503);
  h.controller.syncNow();
  await h.timers.advance(10);
  assert.equal(h.controller.status.kind, "attention");
  assert.equal((h.controller.status as { message: string }).message, "iCloud had a temporary server error. The next check tries again.");
  h.remote.scanError = null;
  h.controller.syncNow();
  await h.timers.advance(10);
  assert.equal(h.controller.status.kind, "idle");
  await h.controller.stop();
});
