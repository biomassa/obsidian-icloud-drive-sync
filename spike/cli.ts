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
import { existsSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { createInterface } from "node:readline";
import { DatabaseSync } from "node:sqlite";

import { ICloudAuth, type SrpProofCheck } from "../src/icloud/auth.ts";
import { b64encode } from "../src/icloud/bytes.ts";
import { DriveClient, isFolderLike, type DriveItem } from "../src/icloud/drive.ts";
import { nodeTransport, type Transport } from "../src/icloud/http.ts";
import { FileSessionStore } from "../src/icloud/store.ts";
import { SyncEngine, describe, sha256 } from "../src/sync/engine.ts";
import { planSync } from "../src/sync/planner.ts";
import { IgnoreFilter } from "../src/sync/filters.ts";
import { ICloudRemote } from "../src/sync/icloud-remote.ts";
import { NodeLocalFs } from "../src/sync/node-local.ts";
import { FileStateStore } from "../src/sync/state.ts";
import { mkdtemp, mkdir as mkdirp, writeFile as writeFileP, rename as renameP, rm as rmP, readFile as readFileP } from "node:fs/promises";
import { tmpdir } from "node:os";

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
  // Renamed when the plugin took over the vault; the spike still reads it.
  const live = join(homedir(), ".config/obsisync/config.json");
  const parked = `${live}.disabled-for-icloud-plugin`;
  return JSON.parse(readFileSync(existsSync(live) ? live : parked, "utf8"));
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

/**
 * Every file under a folder, with fresh listings, `concurrency` folders at a
 * time. Listing one folder at a time took 209 s for 98 folders; each request
 * is mostly waiting on Apple, so they overlap well.
 */
async function walk(drive: DriveClient, root: DriveItem, concurrency = 8): Promise<Map<string, DriveItem>> {
  const out = new Map<string, DriveItem>();
  const queue: { folder: DriveItem; prefix: string }[] = [{ folder: root, prefix: "" }];
  let active = 0;
  await new Promise<void>((resolve, reject) => {
    const pump = () => {
      if (!queue.length && !active) return resolve();
      while (active < concurrency && queue.length) {
        const { folder, prefix } = queue.shift()!;
        active++;
        drive.list(folder).then(
          (children) => {
            for (const child of children) {
              const rel = prefix ? `${prefix}/${child.name}` : child.name;
              if (isFolderLike(child)) queue.push({ folder: child, prefix: rel });
              else out.set(rel, child);
            }
            active--;
            pump();
          },
          reject,
        );
      }
    };
    pump();
  });
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
  const report = join(STATE_DIR, "walk-diff.txt");
  writeFileSync(report, [...onlyRemote.map((p) => `+ ${p}`), ...onlyTracked.map((p) => `- ${p}`)].join("\n") + "\n");
  log(`full list: ${report}`);
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

  await step("replace with v2 in place (same size, one byte differs)", async () => {
    const { signature } = await drive.stageContent(folder!.zone, "note.md", v2);
    await drive.updateDocumentsRaw(folder!.zone, {
      data: signature, command: "add_file", create_short_guid: true, document_id: first.docwsid,
      path: { starting_document_id: folder!.docwsid, path: "note.md" }, allow_conflict: false,
      file_flags: { is_writable: true, is_executable: false, is_hidden: false }, mtime: Date.now(), btime: Date.now(),
    });
  });
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

/**
 * Answer the questions the sync executor depends on, in a throwaway folder:
 * does a document keep its id through a rename and a move, is a stale etag
 * refused, what does allow_conflict=false do, are names case-sensitive, and
 * what does update/documents return.
 */
async function semantics(cfg: ObsisyncConfig): Promise<void> {
  const auth = await signedIn(cfg);
  const drive = new DriveClient(auth);
  const root = await drive.root();
  const NAME = "icloudsync-semantics-test";
  if ((await drive.list(root)).some((c) => c.name === NAME)) throw new Error(`${NAME} already exists; remove it first`);
  const top = await drive.mkdir(root, NAME);
  const a = await drive.mkdir(top, "A");
  const b = await drive.mkdir(top, "B");
  const data = new TextEncoder().encode("semantics probe\n");
  const find = async (folder: DriveItem, name: string) => (await drive.list(folder)).find((c) => c.name === name);
  const show = (i: DriveItem | undefined) =>
    i ? `docwsid=${i.docwsid} drivewsid=${i.drivewsid.slice(0, 40)} etag=${i.etag}` : "MISSING";
  const attempt = async (label: string, fn: () => Promise<unknown>) => {
    try {
      const r = await fn();
      log(`  ${label}: succeeded${r !== undefined ? ` → ${JSON.stringify(r).slice(0, 300)}` : ""}`);
      return true;
    } catch (e) {
      log(`  ${label}: FAILED → ${e instanceof Error ? `${e.name}: ${e.message}` : String(e)}`);
      return false;
    }
  };

  try {
    log("1. what update/documents returns");
    const resp = await drive.upload(a, "x.md", data);
    log(`  top-level keys: ${Object.keys(resp).join(", ")}`);
    log(`  body: ${JSON.stringify(resp).slice(0, 600)}`);
    const x0 = await find(a, "x.md");
    log(`  listed: ${show(x0)}`);

    log("2. rename x.md → y.md in the same folder");
    await drive.rename(x0!, "y.md");
    const y = await find(a, "y.md");
    log(`  after:  ${show(y)}`);
    log(`  docwsid kept: ${y?.docwsid === x0!.docwsid}  drivewsid kept: ${y?.drivewsid === x0!.drivewsid}  etag changed: ${y?.etag !== x0!.etag}`);
    log(`  name, extension fields: ${JSON.stringify({ name: y?.raw.name, extension: y?.raw.extension })}`);

    log("3. move A/y.md → B/");
    const moveResp = await drive.move(y!, b);
    log(`  response: ${JSON.stringify(moveResp).slice(0, 400)}`);
    const moved = await find(b, "y.md");
    log(`  after:  ${show(moved)}`);
    log(`  docwsid kept: ${moved?.docwsid === y?.docwsid}  etag changed: ${moved?.etag !== y?.etag}`);

    log("4. trash with a stale etag");
    await drive.upload(a, "z.md", data);
    const z1 = await find(a, "z.md");
    await drive.rename(z1!, "z2.md");
    const z2 = await find(a, "z2.md");
    log(`  etag before rename ${z1?.etag}, after ${z2?.etag}`);
    const staleOk = await attempt("moveItemsToTrash with the pre-rename etag", () => drive.trash(z1!));
    log(`  z2.md still present: ${Boolean(await find(a, "z2.md"))}`);
    if (!staleOk) await attempt("moveItemsToTrash with the current etag", () => drive.trash(z2!));

    log("5. allow_conflict=false onto a taken name");
    await drive.upload(a, "c.md", data);
    await attempt("second upload of c.md with allowConflict=false", () =>
      drive.upload(a, "c.md", new TextEncoder().encode("second"), Date.now(), { allowConflict: false }),
    );
    log(`  folder A now: ${(await drive.list(a)).map((c) => c.name).join(", ")}`);

    log("6. case sensitivity");
    await drive.upload(b, "Case.md", data);
    await attempt("upload case.md next to Case.md", () => drive.upload(b, "case.md", data));
    log(`  folder B now: ${(await drive.list(b)).map((c) => c.name).join(", ")}`);
  } finally {
    await drive.trash((await find(root, NAME)) ?? top).catch((e) => log(`cleanup failed: ${e}`));
    log(`cleanup: ${NAME} moved to Recently Deleted`);
    await auth.session.persist();
  }
}

/** Second probe: the stale-trash response, and whether a document can be updated in place. */
async function semantics2(cfg: ObsisyncConfig): Promise<void> {
  const auth = await signedIn(cfg);
  const drive = new DriveClient(auth);
  const root = await drive.root();
  const NAME = "icloudsync-semantics-test-2";
  if ((await drive.list(root)).some((c) => c.name === NAME)) throw new Error(`${NAME} already exists; remove it first`);
  const top = await drive.mkdir(root, NAME);
  const enc = (s: string) => new TextEncoder().encode(s);
  const find = async (name: string) => (await drive.list(top)).find((c) => c.name === name);
  const text = async (i: DriveItem) => new TextDecoder().decode(await drive.download(i));
  try {
    log("1. stale-etag trash: the response");
    await drive.upload(top, "z.md", enc("z"));
    const z1 = (await find("z.md"))!;
    await drive.rename(z1, "z2.md");
    log(`  stale:   ${JSON.stringify(await drive.trash(z1)).slice(0, 500)}`);
    const z2 = (await find("z2.md"))!;
    log(`  current: ${JSON.stringify(await drive.trash(z2)).slice(0, 500)}`);
    log(`  z2.md present afterwards: ${Boolean(await find("z2.md"))}`);

    log("2. update in place");
    const zone = top.zone;
    const variants: [string, (docId: string, sig: Record<string, unknown>, stagedId: string) => Record<string, unknown>][] = [
      ["add_file onto the existing document_id", (docId, sig) => ({
        data: sig, command: "add_file", create_short_guid: true, document_id: docId,
        path: { starting_document_id: top.docwsid, path: "u.md" }, allow_conflict: false,
        file_flags: { is_writable: true, is_executable: false, is_hidden: false }, mtime: Date.now(), btime: Date.now(),
      })],
      ["update_file on the existing document_id", (docId, sig) => ({
        data: sig, command: "update_file", document_id: docId,
        file_flags: { is_writable: true, is_executable: false, is_hidden: false }, mtime: Date.now(),
      })],
      ["modify_file on the existing document_id", (docId, sig) => ({
        data: sig, command: "modify_file", document_id: docId, mtime: Date.now(),
      })],
    ];
    for (const [label, body] of variants) {
      const before = await find("u.md") ?? (await drive.upload(top, "u.md", enc("version one")), await find("u.md"));
      const original = await text(before!);
      const { signature } = await drive.stageContent(zone, "u.md", enc("version TWO"));
      let outcome: string;
      try {
        const r = await drive.updateDocumentsRaw(zone, body(before!.docwsid, signature, ""));
        outcome = `ok ${JSON.stringify(r).slice(0, 250)}`;
      } catch (e) {
        outcome = `error ${e instanceof Error ? e.message : String(e)}`;
      }
      const listing = await drive.list(top);
      const after = listing.find((c) => c.name === "u.md");
      log(`  ${label}: ${outcome}`);
      log(`    folder: ${listing.map((c) => c.name).join(", ")}`);
      log(`    u.md docwsid kept: ${after?.docwsid === before!.docwsid}; content now: ${after ? JSON.stringify(await text(after)) : "-"} (was ${JSON.stringify(original)})`);
      for (const c of listing) if (c.name !== "u.md") await drive.trash(c);
      if (after && (await text(after)) !== "version one") {
        await drive.trash(after);
      }
    }
  } finally {
    await drive.trash((await drive.list(root)).find((c) => c.name === NAME) ?? top).catch((e) => log(`cleanup failed: ${e}`));
    log(`cleanup: ${NAME} moved to Recently Deleted`);
    await auth.session.persist();
  }
}

/** Third probe: can an in-place update be made conditional on the etag? */
async function semantics3(cfg: ObsisyncConfig): Promise<void> {
  const auth = await signedIn(cfg);
  const drive = new DriveClient(auth);
  const root = await drive.root();
  const NAME = "icloudsync-semantics-test-3";
  if ((await drive.list(root)).some((c) => c.name === NAME)) throw new Error(`${NAME} already exists; remove it first`);
  const top = await drive.mkdir(root, NAME);
  const enc = (s: string) => new TextEncoder().encode(s);
  const find = async () => (await drive.list(top)).find((c) => c.name === "u.md");
  const text = async (i: DriveItem) => new TextDecoder().decode(await drive.download(i));
  try {
    await drive.upload(top, "u.md", enc("v1"));
    const stale = (await find())!;
    // Another device edits it: an in-place update moves the etag on.
    const s1 = await drive.stageContent(top.zone, "u.md", enc("v2 from another device"));
    await drive.updateDocumentsRaw(top.zone, {
      data: s1.signature, command: "add_file", create_short_guid: true, document_id: stale.docwsid,
      path: { starting_document_id: top.docwsid, path: "u.md" }, allow_conflict: false,
      file_flags: { is_writable: true, is_executable: false, is_hidden: false }, mtime: Date.now(), btime: Date.now(),
    });
    const current = (await find())!;
    log(`etag scanned ${stale.etag}, now ${current.etag}`);
    for (const field of ["etag", "document_etag", "if_match"]) {
      const s2 = await drive.stageContent(top.zone, "u.md", enc(`v3 with stale ${field}`));
      let outcome: string;
      try {
        const r = await drive.updateDocumentsRaw(top.zone, {
          data: s2.signature, command: "add_file", create_short_guid: true, document_id: stale.docwsid,
          path: { starting_document_id: top.docwsid, path: "u.md" }, allow_conflict: false,
          file_flags: { is_writable: true, is_executable: false, is_hidden: false }, mtime: Date.now(), btime: Date.now(),
          [field]: stale.etag,
        });
        const st = (r.results as Record<string, unknown>[] | undefined)?.[0]?.status;
        outcome = `accepted, status ${JSON.stringify(st)}`;
      } catch (e) {
        outcome = `REJECTED ${e instanceof Error ? e.message : String(e)}`;
      }
      const now = (await find())!;
      log(`  stale ${field}: ${outcome}; content now ${JSON.stringify(await text(now))}`);
    }
  } finally {
    await drive.trash((await drive.list(root)).find((c) => c.name === NAME) ?? top).catch((e) => log(`cleanup failed: ${e}`));
    log(`cleanup: ${NAME} moved to Recently Deleted`);
    await auth.session.persist();
  }
}

/**
 * The real engine, end to end, between a throwaway local folder and a
 * throwaway iCloud folder. Every step is verified by comparing both trees byte
 * for byte, with the iCloud side read back through fresh downloads.
 */
async function e2e(cfg: ObsisyncConfig): Promise<void> {
  const auth = await signedIn(cfg);
  const drive = new DriveClient(auth);
  const root = await drive.root();
  const NAME = "icloudsync-e2e-test";
  if ((await drive.list(root)).some((c) => c.name === NAME)) throw new Error(`${NAME} already exists; remove it first`);
  await drive.mkdir(root, NAME);
  const localRoot = await mkdtemp(join(tmpdir(), "icloudsync-e2e-"));
  const statePath = join(STATE_DIR, `e2e-state-${Date.now()}.json`);
  const filter = new IgnoreFilter();
  const local = new NodeLocalFs({ root: localRoot, filter });
  const remote = new ICloudRemote({ drive, vaultPath: [NAME], filter });
  const engine = new SyncEngine({
    local,
    remote,
    store: new FileStateStore(statePath),
    filter,
    log: (level, m) => log(`    [${level}] ${m}`),
  });
  const other = new ICloudRemote({ drive, vaultPath: [NAME], filter }); // "another device"
  const enc = (s: string) => new TextEncoder().encode(s);
  const put = async (rel: string, text: string) => {
    await mkdirp(join(localRoot, dirname(rel)), { recursive: true });
    await writeFileP(join(localRoot, rel), text);
  };
  let failures = 0;
  const cycle = async (label: string) => {
    const t = Date.now();
    const r = await engine.runCycle();
    log(`${label}: ${r.status}${r.abort ? ` (${JSON.stringify(r.abort)})` : ""} in ${Date.now() - t} ms — ` +
      `${r.done.map((d) => describe(d.action)).join("; ") || "nothing to do"}` +
      `${r.skipped.length ? ` | skipped: ${r.skipped.map((s) => `${describe(s.action)} (${s.why})`).join("; ")}` : ""}` +
      `${r.errors.length ? ` | ERRORS: ${r.errors.map((e) => `${describe(e.action)}: ${e.error}`).join("; ")}` : ""}`);
    if (r.errors.length || r.status === "aborted") failures++;
    return r;
  };
  const compareTrees = async (label: string) => {
    const l = await local.scan();
    const r = await other.scan();
    const diffs: string[] = [];
    for (const k of new Set([...l.entries.keys(), ...r.entries.keys()])) {
      const le = l.entries.get(k);
      const re = r.entries.get(k);
      if (!le || !re) {
        diffs.push(`${k}: only ${le ? "local" : "iCloud"}`);
        continue;
      }
      const lb = await local.read(k);
      const rb = await other.download(re);
      if (Buffer.compare(Buffer.from(lb), Buffer.from(rb)) !== 0) diffs.push(`${k}: content differs`);
    }
    log(`  ${label}: ${l.entries.size} files each side — ${diffs.length ? `DIFFERENT: ${diffs.join(", ")}` : "IDENTICAL"}`);
    if (diffs.length) failures++;
  };

  try {
    log("step 1: a new local vault is uploaded");
    await put(".obsidian/app.json", "{}");
    await put(".obsidian/workspace.json", "{\"ignored\": true}");
    await put("Welcome.md", "# Welcome\n");
    await put("Notes/todo.md", "- [ ] buy milk\n");
    await put("Notes/long.md", "A".repeat(6000) + "\n");
    await put("Notes/Deep/idea.md", "an idea\n");
    await put("Attachments/empty.md", "");
    await cycle("cycle 1");
    await compareTrees("after step 1");

    log("step 2: edits and renames on both sides");
    await put("Notes/todo.md", "- [x] buy milk\n"); // same size, one byte differs
    await put("Notes/long.md", "A".repeat(6000) + "\nappended past 4 KB\n");
    await renameP(join(localRoot, "Notes/Deep/idea.md"), join(localRoot, "Notes/idea-renamed.md"));
    const snap = await other.scan();
    await other.upload("Welcome.md", enc("# Welcome, from the phone\n"), Date.now(), snap.entries.get("Welcome.md"));
    const emptyItem = snap.entries.get("Attachments/empty.md")!;
    await drive.rename(emptyItem.handle as DriveItem, "renamed-on-phone.md");
    await cycle("cycle 2");
    await compareTrees("after step 2");

    log("step 2b: the base recorded after an in-place update matches iCloud");
    await new Promise((r) => setTimeout(r, 2500));
    await put("Notes/todo.md", "- [x] buy MILK\n");
    await cycle("cycle 2b-1");
    const stored = JSON.parse(await readFileP(statePath, "utf8")).base.find((b: { key: string }) => b.key === "Notes/todo.md");
    const listed = (await other.scan()).entries.get("Notes/todo.md")!;
    const docOk = stored?.remoteDocId === listed.docId;
    const etagOk = stored?.remoteEtag === listed.etag;
    log(`  stored docId ${stored?.remoteDocId} vs listed ${listed.docId}: ${docOk ? "match" : "MISMATCH"}`);
    log(`  stored etag  ${stored?.remoteEtag} vs listed ${listed.etag}: ${etagOk ? "match" : "MISMATCH"}`);
    if (!docOk || !etagOk) failures++;
    await new Promise((r) => setTimeout(r, 2500));
    const settle = await cycle("cycle 2b-2 (should do nothing)");
    if (settle.done.some((d) => d.action.kind !== "refreshBase")) {
      log("  UNEXPECTED: the cycle after an in-place update transferred something");
      failures++;
    }
    await put("Notes/todo.md", "- [x] buy milk!\n");
    const again = await cycle("cycle 2b-3 (second edit: a plain upload)");
    if (!again.done.some((d) => d.action.kind === "upload") || again.done.some((d) => d.action.kind === "conflict")) {
      log("  UNEXPECTED: a second local edit was not a plain upload");
      failures++;
    }
    const todoItem = (await other.scan()).entries.get("Notes/todo.md")!;
    await drive.rename(todoItem.handle as DriveItem, "todo-renamed-on-phone.md");
    const renamed = await cycle("cycle 2b-4 (phone renamed a file this device updated)");
    if (!renamed.done.some((d) => d.action.kind === "renameLocal")) {
      log("  UNEXPECTED: the rename was not recognised (document id not tracked after update)");
      failures++;
    }
    await compareTrees("after step 2b");

    log("step 3: the same note edited on both sides");
    await put("Welcome.md", "# Welcome, edited on this computer\n");
    const snap3 = await other.scan();
    await other.upload("Welcome.md", enc("# Welcome, edited on the phone again\n"), Date.now(), snap3.entries.get("Welcome.md"));
    await cycle("cycle 3");
    await compareTrees("after step 3");

    log("step 4: one deletion on each side");
    await rmP(join(localRoot, "Notes/todo-renamed-on-phone.md"));
    const snap4 = await other.scan();
    await other.trash(snap4.entries.get("Notes/long.md")!);
    await cycle("cycle 4");
    await compareTrees("after step 4");
    log(`  local .trash holds: ${readdirSync(join(localRoot, ".trash"), { recursive: true }).join(", ")}`);

    log("step 5: a quiet cycle does nothing");
    await new Promise((r) => setTimeout(r, 2500)); // outlast the racy window
    await cycle("cycle 5");
    const quiet = await cycle("cycle 6");
    if (quiet.done.some((d) => d.action.kind !== "refreshBase")) {
      log("  UNEXPECTED: a quiet cycle transferred something");
      failures++;
    }
    const state = JSON.parse(await readFileP(statePath, "utf8"));
    log(`  state file: ${state.base.length} tracked, ${state.pendingDeletions.length} pending`);
  } finally {
    await drive.trash((await drive.list(root)).find((c) => c.name === NAME)!).catch((e) => log(`cleanup failed: ${e}`));
    await rmP(localRoot, { recursive: true, force: true });
    await rmP(statePath, { force: true });
    log(`cleanup: ${NAME} moved to Recently Deleted; local folder and state removed`);
    await auth.session.persist();
  }
  log(failures ? `E2E: ${failures} problem(s)` : "E2E: all steps verified");
  if (failures) process.exitCode = 1;
}

/**
 * What would the first run do to the real vault? Scans and hashes both sides
 * and prints the plan against an empty base. Read-only: nothing is executed
 * and no state is written, locally or on iCloud.
 */
async function planReal(cfg: ObsisyncConfig): Promise<void> {
  const auth = await signedIn(cfg);
  const drive = new DriveClient(auth);
  const filter = new IgnoreFilter();
  const local = new NodeLocalFs({ root: cfg.local_path, filter });
  const remote = new ICloudRemote({ drive, vaultPath: cfg.vault_name.split("/"), filter });
  let t = Date.now();
  const ls = await local.scan();
  log(`local scan: ${ls.entries.size} files, ${ls.skipped.length} skipped, ${Date.now() - t} ms`);
  for (const s of ls.skipped) log(`  skipped ${s.key}: ${s.reason}`);
  t = Date.now();
  let bytes = 0;
  for (const e of ls.entries.values()) {
    const data = await local.read(e.key);
    bytes += data.length;
    e.hash = sha256(data);
    e.hashedAtMs = Date.now();
  }
  log(`hashing: ${(bytes / 1e6).toFixed(1)} MB in ${Date.now() - t} ms`);
  t = Date.now();
  const rs = await remote.scan();
  log(`iCloud scan: ${rs.entries.size} files, ${(rs.skipped ?? []).length} skipped, ${Date.now() - t} ms`);
  const largest = [...ls.entries.values()].sort((a, b) => b.size - a.size).slice(0, 5);
  log(`largest local files: ${largest.map((e) => `${e.key} (${(e.size / 1e6).toFixed(1)} MB)`).join(", ")}`);
  const result = planSync({
    base: new Map(),
    local: ls,
    remote: rs,
    pending: new Map(),
    filter,
    options: { allowManyConflicts: true, now: Date.now() },
  });
  if (!result.ok) return log(`plan aborted: ${JSON.stringify(result.abort)}`);
  const byKind = new Map<string, string[]>();
  for (const a of result.plan.actions) {
    const k = "key" in a ? a.key : `${a.from} → ${a.to}`;
    byKind.set(a.kind, [...(byKind.get(a.kind) ?? []), k]);
  }
  log("first-run plan (nothing executed):");
  for (const [kind, keys] of byKind) {
    log(`  ${kind}: ${keys.length}`);
    if (kind !== "compare") for (const k of keys.slice(0, 60)) log(`      ${k}`);
  }
  const compareBytes = result.plan.actions
    .filter((a) => a.kind === "compare")
    .reduce((n, a) => n + (a as { remote: { size: number } }).remote.size, 0);
  log(`  compare would download ${(compareBytes / 1e6).toFixed(1)} MB to check content`);
  log(`peak memory: rss ${(process.memoryUsage().rss / 1e6).toFixed(0)} MB`);
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
    case "semantics":
      return semantics(cfg);
    case "semantics2":
      return semantics2(cfg);
    case "semantics3":
      return semantics3(cfg);
    case "e2e":
      return e2e(cfg);
    case "plan-real":
      return planReal(cfg);
    case "compare-tree": {
      // Byte-compare a local folder with an iCloud folder (read-only).
      const [localDir, icloudPath] = rest;
      if (!localDir || !icloudPath) throw new Error("usage: compare-tree <local folder> <iCloud folder path>");
      const auth = await signedIn(cfg);
      const drive = new DriveClient(auth);
      const filter = new IgnoreFilter([".obsidian/plugins/icloud-drive-sync/", ".obsidian/plugins/*/main.js", ".obsidian/plugins/*/styles.css", ".obsidian/plugins/*/manifest.json"]);
      const local = new NodeLocalFs({ root: localDir, filter });
      const remote = new ICloudRemote({ drive, vaultPath: icloudPath.split("/"), filter });
      const [l, r] = [await local.scan(), await remote.scan()];
      let diffs = 0;
      for (const k of [...new Set([...l.entries.keys(), ...r.entries.keys()])].sort()) {
        const le = l.entries.get(k), re = r.entries.get(k);
        let state = "same";
        if (!le || !re) state = le ? "ONLY LOCAL" : "ONLY ICLOUD";
        else if (Buffer.compare(Buffer.from(await local.read(k)), Buffer.from(await remote.download(re))) !== 0) state = "DIFFERENT";
        if (state !== "same") diffs++;
        log(`  ${state.padEnd(11)} ${k}`);
      }
      log(diffs ? `${diffs} difference(s)` : `identical: ${l.entries.size} files`);
      await auth.session.persist();
      return;
    }
    case "mkroot": {
      // Create an empty folder at the iCloud Drive root, for a throwaway test vault.
      const name = rest[0];
      if (!name || !/^icloudsync-[a-z0-9-]+$/.test(name)) throw new Error("usage: mkroot icloudsync-<name>");
      const auth = await signedIn(cfg);
      const drive = new DriveClient(auth);
      const root = await drive.root();
      if ((await drive.list(root)).some((c) => c.name === name)) return log(`${name} already exists`);
      await drive.mkdir(root, name);
      await auth.session.persist();
      return log(`created ${name} at the iCloud Drive root`);
    }
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
