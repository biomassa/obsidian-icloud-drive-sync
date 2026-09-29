/**
 * Phase-1 spike: prove the TypeScript iCloud client works against Apple, from
 * plain Node, before any plugin code depends on it.
 *
 *   node spike/cli.ts login [--sms]    sign in; 2FA if needed
 *   node spike/cli.ts status           resume from stored tokens only
 *   node spike/cli.ts ls [path]        list a folder (default: the vault)
 *   node spike/cli.ts compare <path>   download a vault file, compare with the local copy
 *   node spike/cli.ts write-test       upload/replace/trash in a throwaway root folder
 *
 * The Apple ID and vault come from obsisync's config; the password from the
 * system keyring entry obsisync already stores (service "obsisync"). Session
 * state goes to ~/.local/share/icloud-obsi-spike/session.json, mode 0600. The
 * 2FA code is read from stdin, or from a file named `code` in that directory
 * (so the spike can run unattended while someone else types the code).
 *
 * Read-only against the vault. write-test touches only a new top-level folder
 * named `icloudsync-spike-test`, outside every vault.
 */
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, readFileSync, rmSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { createInterface } from "node:readline";

import { ICloudAuth } from "../src/icloud/auth.ts";
import { DriveClient, isFolderLike, type DriveItem } from "../src/icloud/drive.ts";
import { nodeTransport } from "../src/icloud/http.ts";
import { FileSessionStore } from "../src/icloud/store.ts";

const STATE_DIR = join(homedir(), ".local/share/icloud-obsi-spike");
const CODE_FILE = join(STATE_DIR, "code");
const TEST_FOLDER = "icloudsync-spike-test";

interface ObsisyncConfig {
  apple_id: string;
  vault_name: string;
  local_path: string;
  force_ipv4?: boolean;
}

function obsisyncConfig(): ObsisyncConfig {
  const path = join(homedir(), ".config/obsisync/config.json");
  return JSON.parse(readFileSync(path, "utf8"));
}

function keyringPassword(account: string): string {
  try {
    return execFileSync("secret-tool", ["lookup", "service", "obsisync", "username", account], {
      encoding: "utf8",
    }).replace(/\n$/, "");
  } catch {
    throw new Error(`no password for ${account} in the keyring (service "obsisync")`);
  }
}

function sha(data: Uint8Array): string {
  return createHash("sha256").update(data).digest("hex").slice(0, 16);
}

function log(msg: string): void {
  console.log(`[${new Date().toISOString().slice(11, 19)}] ${msg}`);
}

async function waitForCode(timeoutMs = 10 * 60_000): Promise<string> {
  rmSync(CODE_FILE, { force: true });
  log(`waiting for the 2FA code: type it here, or write it to ${CODE_FILE}`);
  const deadline = Date.now() + timeoutMs;
  let typed: string | undefined;
  if (process.stdin.isTTY) {
    const rl = createInterface({ input: process.stdin });
    rl.once("line", (line) => {
      typed = line.trim();
      rl.close();
    });
  }
  while (Date.now() < deadline) {
    if (typed) return typed;
    if (existsSync(CODE_FILE)) {
      const code = readFileSync(CODE_FILE, "utf8").trim();
      rmSync(CODE_FILE, { force: true });
      if (code) return code;
    }
    await new Promise((r) => setTimeout(r, 500));
  }
  throw new Error("timed out waiting for the 2FA code");
}

async function openAuth(cfg: ObsisyncConfig): Promise<ICloudAuth> {
  return ICloudAuth.open({
    accountName: cfg.apple_id,
    store: new FileSessionStore(join(STATE_DIR, "session.json"), cfg.apple_id),
    transport: nodeTransport({ family: cfg.force_ipv4 ? 4 : 0 }),
    bridge: { family: cfg.force_ipv4 ? 4 : 0 },
  });
}

async function signedIn(cfg: ObsisyncConfig): Promise<ICloudAuth> {
  const auth = await openAuth(cfg);
  if (!(await auth.resume())) throw new Error("no usable session; run `login` first");
  await auth.ensureDriveAccess();
  return auth;
}

async function login(cfg: ObsisyncConfig, preferSms: boolean): Promise<void> {
  const auth = await openAuth(cfg);
  log(`signing in as ${cfg.apple_id}`);
  const result = await auth.signIn(keyringPassword(cfg.apple_id));
  if (result.status === "signed-in") {
    log("signed in without a code (stored trust token accepted)");
  } else {
    log(`two-factor required; requesting a code (${preferSms ? "SMS" : "trusted device if available"})`);
    const method = await auth.requestCode({ preferSms });
    log(`delivery: ${method}. ${auth.deliveryDescription ?? ""}`);
    for (let attempt = 1; ; attempt++) {
      const code = await waitForCode();
      if (await auth.submitCode(code)) break;
      if (attempt >= 3 || method === "trusted_device") {
        // A device-prompt session is single-use once a code has been tried.
        throw new Error("the code was not accepted");
      }
      log("that code was not accepted; try again");
    }
    log("code accepted; session trusted");
  }
  await auth.session.persist();
  log(`trusted=${auth.isTrustedSession} dsid=${auth.params.dsid ? "present" : "missing"} ` +
    `trust_token=${auth.session.data.trust_token ? "stored" : "missing"}`);
}

async function vaultRoot(drive: DriveClient, cfg: ObsisyncConfig): Promise<DriveItem> {
  const node = await drive.resolve(cfg.vault_name.split("/"));
  if (!node || !isFolderLike(node)) throw new Error(`vault ${cfg.vault_name} not found`);
  return node;
}

/** Count files under a folder, walking every subfolder with fresh listings. */
async function walk(drive: DriveClient, folder: DriveItem, prefix = ""): Promise<Map<string, DriveItem>> {
  const out = new Map<string, DriveItem>();
  for (const child of await drive.list(folder)) {
    const rel = prefix ? `${prefix}/${child.name}` : child.name;
    if (isFolderLike(child)) for (const [k, v] of await walk(drive, child, rel)) out.set(k, v);
    else out.set(rel, child);
  }
  return out;
}

async function ls(cfg: ObsisyncConfig, path?: string): Promise<void> {
  const auth = await signedIn(cfg);
  const drive = new DriveClient(auth);
  const root = await vaultRoot(drive, cfg);
  const folder = path ? await drive.resolve([...cfg.vault_name.split("/"), ...path.split("/")]) : root;
  if (!folder) throw new Error(`${path} not found`);
  const children = await drive.list(folder);
  log(`${children.length} entries in ${path ?? cfg.vault_name}`);
  for (const c of children.slice(0, 15)) {
    log(`  ${isFolderLike(c) ? "d" : "-"} ${c.name}  size=${c.size} etag=${c.etag ? "yes" : "EMPTY"}`);
  }
  if (!path) {
    const started = Date.now();
    const files = await walk(drive, root);
    log(`full walk: ${files.size} files in ${((Date.now() - started) / 1000).toFixed(1)}s`);
    const noEtag = [...files.values()].filter((f) => !f.etag).length;
    log(`files without an etag: ${noEtag}`);
  }
  await auth.session.persist();
}

async function compare(cfg: ObsisyncConfig, relPath: string): Promise<void> {
  const auth = await signedIn(cfg);
  const drive = new DriveClient(auth);
  const file = await drive.resolve([...cfg.vault_name.split("/"), ...relPath.split("/")]);
  if (!file || isFolderLike(file)) throw new Error(`${relPath} is not a file on iCloud`);
  const remote = await drive.download(file);
  const local = readFileSync(join(cfg.local_path, relPath));
  log(`remote ${remote.length} bytes sha=${sha(remote)} | local ${local.length} bytes sha=${sha(local)}`);
  log(Buffer.compare(Buffer.from(remote), local) === 0 ? "IDENTICAL" : "DIFFERENT");
  await auth.session.persist();
}

async function writeTest(cfg: ObsisyncConfig): Promise<void> {
  const auth = await signedIn(cfg);
  const drive = new DriveClient(auth);
  const root = await drive.root();
  let folder = (await drive.list(root)).find((c) => c.name === TEST_FOLDER);
  if (folder) throw new Error(`${TEST_FOLDER} already exists at the iCloud Drive root; remove it first`);

  const step = async <T>(label: string, fn: () => Promise<T>): Promise<T> => {
    const t = Date.now();
    const v = await fn();
    log(`ok  ${label} (${Date.now() - t} ms)`);
    return v;
  };

  folder = await step("mkdir test folder", () => drive.mkdir(root, TEST_FOLDER));
  const v1 = new TextEncoder().encode("# spike\n\n- [ ] first version\n" + "x".repeat(5000) + "\n");
  const v2 = new TextEncoder().encode("# spike\n\n- [x] first version\n" + "x".repeat(5000) + "\n"); // same size
  await step("upload note.md (v1)", () => drive.upload(folder!, "note.md", v1));
  let listing = await drive.list(folder);
  const first = listing.find((c) => c.name === "note.md");
  if (!first) throw new Error(`upload did not appear; saw ${listing.map((c) => c.name).join(", ")}`);
  log(`    note.md size=${first.size} etag=${first.etag || "EMPTY"} modified=${new Date(first.modified).toISOString()}`);
  const down1 = await step("download v1", () => drive.download(first));
  log(`    v1 round-trip ${Buffer.compare(Buffer.from(down1), Buffer.from(v1)) === 0 ? "IDENTICAL" : "DIFFERENT"}`);

  await step("replace with v2 (same size, one byte differs)", () => drive.replace(folder!, first, v2));
  listing = await drive.list(folder);
  log(`    folder now holds: ${listing.map((c) => c.name).join(", ")}`);
  const second = listing.find((c) => c.name === "note.md");
  if (!second) throw new Error("replaced note.md is missing");
  log(`    etag changed: ${second.etag !== first.etag}`);
  const down2 = await step("download v2", () => drive.download(second));
  log(`    v2 round-trip ${Buffer.compare(Buffer.from(down2), Buffer.from(v2)) === 0 ? "IDENTICAL" : "DIFFERENT"}`);

  await step("upload an empty file", () => drive.upload(folder!, "empty.md", new Uint8Array()));
  await step("mkdir nested", () => drive.mkdir(folder!, "sub folder"));

  await step("trash the test folder", () => drive.trash(folder!));
  log(`done: ${TEST_FOLDER} is in Recently Deleted; delete it there to tidy up`);
  await auth.session.persist();
}

async function main(): Promise<void> {
  const [command, ...rest] = process.argv.slice(2);
  const cfg = obsisyncConfig();
  switch (command) {
    case "login":
      return login(cfg, rest.includes("--sms"));
    case "status": {
      const auth = await openAuth(cfg);
      const ok = await auth.resume();
      log(ok ? `session valid, trusted=${auth.isTrustedSession}` : "no valid session");
      if (ok) await auth.session.persist();
      return;
    }
    case "ls":
      return ls(cfg, rest[0]);
    case "compare":
      if (!rest[0]) throw new Error("usage: compare <path inside the vault>");
      return compare(cfg, rest[0]);
    case "write-test":
      return writeTest(cfg);
    default:
      console.log("usage: node spike/cli.ts login [--sms] | status | ls [path] | compare <path> | write-test");
  }
}

main().then(
  () => process.exit(0),
  (e) => {
    console.error(`FAILED: ${e instanceof Error ? `${e.name}: ${e.message}` : String(e)}`);
    process.exit(1);
  },
);
