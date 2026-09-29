/**
 * Phase-1 spike: prove the TypeScript iCloud client works against Apple, from
 * plain Node, before any plugin code depends on it.
 *
 *   node spike/cli.ts login [--sms] [--ask-password] [--dry-run]
 *                                      sign in; 2FA if needed. Before the proof
 *                                      is sent, it is recomputed by obsisync's
 *                                      Python and the sign-in aborts on any
 *                                      difference. --dry-run stops there, so
 *                                      Apple never receives a proof at all.
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
import { DatabaseSync } from "node:sqlite";

import { ICloudAuth, type SrpProofCheck } from "../src/icloud/auth.ts";
import { b64encode } from "../src/icloud/bytes.ts";
import { DriveClient, isFolderLike, type DriveItem } from "../src/icloud/drive.ts";
import { nodeTransport, type Transport } from "../src/icloud/http.ts";
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
    });
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

/** Read a line from the terminal without echoing it. */
function askHidden(prompt: string): Promise<string> {
  return new Promise((resolve, reject) => {
    if (!process.stdin.isTTY) return reject(new Error("--ask-password needs a terminal"));
    process.stdout.write(prompt);
    const stdin = process.stdin;
    stdin.setRawMode(true);
    stdin.resume();
    let value = "";
    const onData = (chunk: Buffer) => {
      for (const ch of chunk.toString("utf8")) {
        if (ch === "\r" || ch === "\n") {
          stdin.setRawMode(false);
          stdin.pause();
          stdin.off("data", onData);
          process.stdout.write("\n");
          return resolve(value);
        }
        if (ch === "\u0003") {
          stdin.setRawMode(false);
          process.exit(130);
        }
        if (ch === "\u007f") value = value.slice(0, -1);
        else value += ch;
      }
    };
    stdin.on("data", onData);
  });
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

const PYTHON = join(homedir(), "scripts/obsisync/.venv/bin/python");
const CROSSCHECK = new URL("../tools/srp_crosscheck.py", import.meta.url).pathname;

class DryRunStop extends Error {}

/**
 * Recompute the proof with obsisync's Python and refuse to continue unless
 * both agree. Runs after Apple's challenge and before the proof is sent, so a
 * disagreement costs no sign-in attempt.
 */
function crossCheck(dryRun: boolean) {
  return async (c: SrpProofCheck): Promise<void> => {
    const out = execFileSync(PYTHON, [CROSSCHECK], {
      // The password goes over stdin, never on the command line.
      input: JSON.stringify({
        account: c.accountName,
        password: c.password,
        a: b64encode(c.ephemeral),
        salt: b64encode(c.salt),
        B: b64encode(c.B),
        iterations: c.iterations,
        protocol: c.protocol,
      }),
      encoding: "utf8",
    });
    const py = JSON.parse(out) as { backend: string; A: string; M1: string; M2: string };
    const same = {
      A: py.A === b64encode(c.A),
      M1: py.M1 === b64encode(c.M1),
      M2: py.M2 === b64encode(c.M2),
    };
    log(`cross-check vs ${py.backend}: A ${same.A ? "match" : "DIFFER"}, ` +
      `M1 ${same.M1 ? "match" : "DIFFER"}, M2 ${same.M2 ? "match" : "DIFFER"}`);
    if (!same.A || !same.M1 || !same.M2) {
      throw new Error("TypeScript and Python disagree on the SRP proof; nothing was sent to Apple");
    }
    if (dryRun) throw new DryRunStop("dry run: proofs agree; stopping before sending anything to Apple");
  };
}

/**
 * Log each request's path and status, with the *names* of the cookies sent and
 * set. Values are never printed. Shows whether cookies Apple sets during
 * sign-in are sent back on the following requests.
 */
function tracing(inner: Transport): Transport {
  return async (req) => {
    const res = await inner(req);
    const url = new URL(req.url);
    const sent = (req.headers["Cookie"] ?? "")
      .split("; ")
      .filter(Boolean)
      .map((c) => c.split("=")[0]);
    const set = res.setCookies.map((c) => {
      const domain = /;\s*domain=([^;]+)/i.exec(c)?.[1]?.trim();
      const path = /;\s*path=([^;]+)/i.exec(c)?.[1]?.trim();
      return `${c.split("=")[0]}@${domain ?? "(host)"}${path ?? "(default path)"}`;
    });
    const appleHeaders = Object.keys(res.headers).filter((h) => h.startsWith("x-apple") || h === "scnt");
    log(`  ${req.method} ${url.hostname}${url.pathname} -> ${res.status}`);
    log(`      cookies sent: [${sent.join(", ")}]  set: [${set.join(", ")}]`);
    log(`      apple headers: [${appleHeaders.join(", ")}]`);
    return res;
  };
}

async function openAuth(cfg: ObsisyncConfig, verify?: (c: SrpProofCheck) => Promise<void>, trace = false): Promise<ICloudAuth> {
  return ICloudAuth.open({
    accountName: cfg.apple_id,
    store: new FileSessionStore(join(STATE_DIR, "session.json"), cfg.apple_id),
    transport: trace
      ? tracing(nodeTransport({ family: cfg.force_ipv4 ? 4 : 0 }))
      : nodeTransport({ family: cfg.force_ipv4 ? 4 : 0 }),
    bridge: { family: cfg.force_ipv4 ? 4 : 0 },
    onDiagnostic: (m) => log(m),
    verifySrpProof: verify,
  });
}

async function signedIn(cfg: ObsisyncConfig): Promise<ICloudAuth> {
  const auth = await openAuth(cfg);
  if (!(await auth.resume())) throw new Error("no usable session; run `login` first");
  await auth.ensureDriveAccess();
  return auth;
}

async function login(
  cfg: ObsisyncConfig,
  preferSms: boolean,
  askPassword: boolean,
  dryRun: boolean,
): Promise<void> {
  if (!existsSync(PYTHON)) throw new Error(`obsisync's Python is needed for the cross-check: ${PYTHON}`);
  const auth = await openAuth(cfg, crossCheck(dryRun), dryRun);
  log(`signing in as ${cfg.apple_id}`);
  // One attempt only. A rejected password is not retried: repeated SRP failures
  // count toward an Apple ID lockout, and the diagnostic line above says why.
  const password = askPassword
    ? await askHidden(`Apple ID password for ${cfg.apple_id}: `)
    : keyringPassword(cfg.apple_id);
  let result;
  try {
    result = await auth.signIn(password);
  } catch (e) {
    if (e instanceof DryRunStop) return log(e.message);
    throw e;
  }
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
    const s = drive.listingStats;
    log(`listings: ${s.listings}, with numberOfItems: ${s.withCount}, mismatched: ${s.mismatches.length}`);
    for (const m of s.mismatches.slice(0, 10)) log(`  count mismatch: ${m}`);
    diffAgainstObsisync(new Set(files.keys()));
  }
  await auth.session.persist();
}

/**
 * Compare the walked paths with what obsisync tracks. Differences should all be
 * explained by obsisync's ignore patterns; anything else is a naming bug here
 * (extension joining, Unicode normalization).
 */
function diffAgainstObsisync(remote: Set<string>): void {
  const dbPath = join(homedir(), ".local/share/obsisync/sync_state.db");
  if (!existsSync(dbPath)) return log("no obsisync database to compare against");
  const db = new DatabaseSync(`file:${dbPath}?mode=ro`, { readOnly: true });
  const tracked = new Set(
    (db.prepare("SELECT path FROM file_states").all() as { path: string }[]).map((r) => r.path),
  );
  db.close();
  const onlyRemote = [...remote].filter((p) => !tracked.has(p));
  const onlyTracked = [...tracked].filter((p) => !remote.has(p));
  log(`obsisync tracks ${tracked.size}; walk found ${remote.size}`);
  log(`only on iCloud walk: ${onlyRemote.length}; only in obsisync: ${onlyTracked.length}`);
  for (const p of onlyRemote.slice(0, 15)) log(`  + ${p}`);
  for (const p of onlyTracked.slice(0, 15)) log(`  - ${p}`);
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
      return login(cfg, rest.includes("--sms"), rest.includes("--ask-password"), rest.includes("--dry-run"));
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
