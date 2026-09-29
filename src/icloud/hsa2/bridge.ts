/**
 * Apple's HSA2 trusted-device ("bridge") flow: the path that makes a sign-in
 * prompt appear on the user's iPhone or Mac, rather than an SMS.
 *
 * Port of icloudlite/hsa2_bridge.py. In outline:
 *
 * 1. Open a websocket to Apple's push courier, authenticated by an ephemeral
 *    P-256 key signing a timestamped nonce, and receive a push token.
 * 2. Subscribe to the auth topic and POST bridge step 0 with that token. Apple
 *    pushes back a session payload carrying the SPAKE2 salt; the device shows
 *    the prompt and the code.
 * 3. When the user types the code, run the prover (prover.ts) through steps 2
 *    and 4, decrypt the code Apple returns, and POST it to code/validate.
 *
 * The websocket must stay open between 2 and 3, which is why this flow cannot
 * be split across processes the way the SMS flow can.
 */
import { createSign, generateKeyPairSync, randomBytes, randomUUID, createHash } from "node:crypto";

import { b64decode, b64encode, bytesToHex, concatBytes, hexToBytes } from "../bytes.ts";
import { TrustedDevicePromptError, TrustedDeviceVerificationError } from "../errors.ts";
import type { ICloudSession } from "../session.ts";
import { responseText } from "../http.ts";
import { TrustedDeviceProver } from "./prover.ts";
import {
  decodeServerMessage,
  encodeAckMessage,
  encodeConnectionMessage,
  encodeWebFilterMessage,
} from "./protobuf.ts";
import { openWebSocket, type BridgeSocket, type WebSocketFactory } from "./websocket.ts";

const STATUS_OK = 0;
const STATUS_INVALID_NONCE = 2;
const WEBSOCKET_TIMEOUT_MS = 30_000;
const WEBSOCKET_HOSTS: Record<string, string> = {
  prod: "websocket.push.apple.com",
  sandbox: "websocket.sandbox.push.apple.com",
};
const DONE_DATA_B64 = Buffer.from("done").toString("base64");

type Json = Record<string, unknown>;

function isObject(v: unknown): v is Json {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

// ── boot context ─────────────────────────────────────────────────────────────

export interface Hsa2BootContext {
  authInitialRoute: string;
  hasTrustedDevices: boolean;
  authFactors: string[];
  bridgeInitiateData: Json;
  phoneNumberVerification: Json;
  sourceAppId?: string;
}

export function bootContextFromAuthOptions(options: Json): Hsa2BootContext {
  const bridge = isObject(options.bridgeInitiateData) ? options.bridgeInitiateData : {};
  let pnv = options.phoneNumberVerification;
  if (!isObject(pnv)) pnv = bridge.phoneNumberVerification;
  return {
    authInitialRoute: String(options.authInitialRoute ?? ""),
    hasTrustedDevices: Boolean(options.hasTrustedDevices),
    authFactors: Array.isArray(options.authFactors)
      ? options.authFactors.filter((f): f is string => typeof f === "string")
      : [],
    bridgeInitiateData: { ...bridge },
    phoneNumberVerification: isObject(pnv) ? { ...pnv } : {},
    sourceAppId: options.sourceAppId != null ? String(options.sourceAppId) : undefined,
  };
}

/** Extract the boot context from the HTML `GET /appleauth/auth` returns. */
export function parseBootArgsHtml(html: string): Hsa2BootContext {
  const re = /<script\b([^>]*)>([\s\S]*?)<\/script>/gi;
  let payloadText: string | undefined;
  for (let m = re.exec(html); m; m = re.exec(html)) {
    const classAttr = /\bclass\s*=\s*("([^"]*)"|'([^']*)'|([^\s>]+))/i.exec(m[1] ?? "");
    const classes = (classAttr?.[2] ?? classAttr?.[3] ?? classAttr?.[4] ?? "").split(/\s+/);
    if (classes.includes("boot_args")) {
      payloadText = (m[2] ?? "").trim();
      break;
    }
  }
  if (!payloadText) throw new TrustedDevicePromptError("missing HSA2 boot args payload");

  let payload: unknown;
  try {
    payload = JSON.parse(payloadText); // <script> contents are raw text, not entity-encoded
  } catch {
    throw new TrustedDevicePromptError("malformed HSA2 boot args payload");
  }
  const direct = isObject(payload) ? payload.direct : undefined;
  if (!isObject(direct)) throw new TrustedDevicePromptError("missing HSA2 direct boot data");
  const twoSV = isObject(direct.twoSV) ? direct.twoSV : {};
  const bridge = isObject(twoSV.bridgeInitiateData) ? twoSV.bridgeInitiateData : {};
  const pnv = isObject(bridge.phoneNumberVerification) ? bridge.phoneNumberVerification : {};
  return {
    authInitialRoute: String(direct.authInitialRoute ?? ""),
    hasTrustedDevices: Boolean(direct.hasTrustedDevices),
    authFactors: Array.isArray(twoSV.authFactors)
      ? twoSV.authFactors.filter((f): f is string => typeof f === "string")
      : [],
    bridgeInitiateData: { ...bridge },
    phoneNumberVerification: { ...pnv },
    sourceAppId: twoSV.sourceAppId != null ? String(twoSV.sourceAppId) : undefined,
  };
}

export function bootContextAsAuthData(ctx: Hsa2BootContext): Json {
  const data: Json = {
    authInitialRoute: ctx.authInitialRoute,
    hasTrustedDevices: ctx.hasTrustedDevices,
    authFactors: [...ctx.authFactors],
  };
  if (Object.keys(ctx.bridgeInitiateData).length) data.bridgeInitiateData = { ...ctx.bridgeInitiateData };
  if (Object.keys(ctx.phoneNumberVerification).length) {
    data.phoneNumberVerification = { ...ctx.phoneNumberVerification };
    const tpn = ctx.phoneNumberVerification.trustedPhoneNumber;
    if (isObject(tpn)) data.trustedPhoneNumber = { ...tpn };
  }
  if (ctx.sourceAppId !== undefined) data.sourceAppId = ctx.sourceAppId;
  return data;
}

export function supportsBridge(ctx: Hsa2BootContext): boolean {
  return (
    ctx.authInitialRoute === "auth/bridge/step" &&
    ctx.hasTrustedDevices &&
    Object.keys(ctx.bridgeInitiateData).length > 0
  );
}

// ── push payloads ────────────────────────────────────────────────────────────

export interface BridgePushPayload {
  payload: Json;
  sessionUUID: string;
  nextStep?: string;
  txnid?: string;
  salt?: string;
  idmsdata?: string;
  akdata?: unknown;
  data?: string;
  encryptedCode?: string;
  errorCode?: number;
}

function optionalString(p: Json, key: string): string | undefined {
  const v = p[key];
  if (v === undefined || v === null) return undefined;
  if (typeof v !== "string" || !v.trim()) {
    throw new TrustedDevicePromptError(`malformed trusted-device push payload (${key})`);
  }
  return v;
}

export function parsePushPayload(payload: Json): BridgePushPayload {
  // Apple's newer protocol sends flowid instead of echoing sessionUUID.
  const sessionUUID = optionalString(payload, "sessionUUID") ?? optionalString(payload, "flowid");
  if (!sessionUUID) {
    throw new TrustedDevicePromptError("trusted-device push payload is missing sessionUUID/flowid");
  }
  const next = payload.nextStep;
  if (next !== undefined && next !== null && typeof next !== "string" && !Number.isInteger(next)) {
    throw new TrustedDevicePromptError("malformed trusted-device push payload (nextStep)");
  }
  if (typeof next === "string" && !next.trim()) {
    throw new TrustedDevicePromptError("malformed trusted-device push payload (nextStep)");
  }
  const ec = payload.ec;
  if (ec !== undefined && ec !== null && !Number.isInteger(ec)) {
    throw new TrustedDevicePromptError("malformed trusted-device push payload (ec)");
  }
  return {
    payload,
    sessionUUID,
    nextStep: next === undefined || next === null ? undefined : String(next),
    txnid: optionalString(payload, "txnid"),
    salt: optionalString(payload, "salt"),
    idmsdata: optionalString(payload, "idmsdata"),
    akdata: payload.akdata ?? undefined,
    data: optionalString(payload, "data"),
    encryptedCode: optionalString(payload, "encryptedCode"),
    errorCode: typeof ec === "number" ? ec : undefined,
  };
}

/** The JSON object embedded in a push payload, which may carry leading binary. */
export function extractJsonPayload(raw: Uint8Array): Json {
  const text = Buffer.from(raw).toString("utf8");
  try {
    const v = JSON.parse(text);
    if (isObject(v)) return v;
  } catch {
    // fall through to scanning
  }
  for (let start = text.indexOf("{"); start >= 0; start = text.indexOf("{", start + 1)) {
    let depth = 0;
    let inString = false;
    let escaped = false;
    for (let i = start; i < text.length; i++) {
      const ch = text[i];
      if (inString) {
        if (escaped) escaped = false;
        else if (ch === "\\") escaped = true;
        else if (ch === '"') inString = false;
        continue;
      }
      if (ch === '"') inString = true;
      else if (ch === "{") depth++;
      else if (ch === "}" && --depth === 0) {
        try {
          const v = JSON.parse(text.slice(start, i + 1));
          if (isObject(v)) return v;
        } catch {
          // try the next opening brace
        }
        break;
      }
    }
  }
  throw new TrustedDevicePromptError("could not decode the trusted-device push payload");
}

// ── bridge state and flow ────────────────────────────────────────────────────

export interface BridgeState {
  pushTokenHex: string;
  sessionUUID: string;
  socket: BridgeSocket | null;
  topic: string;
  topicsByHash: Map<string, string>;
  sourceAppId?: string;
  push?: BridgePushPayload;
}

/** Apple routes some challenges to the legacy verifier; their txnid ends in "_W". */
export function usesLegacyVerifier(state: BridgeState): boolean {
  return Boolean(state.push?.txnid?.endsWith("_W"));
}

class InvalidNonce extends Error {
  readonly serverTimestampMs: number;
  constructor(ms: number) {
    super("invalid nonce from bridge server");
    this.serverTimestampMs = ms;
  }
}

function topicHash(topic: string): string {
  return createHash("sha1").update(topic).digest("hex");
}

function topicName(topic: Uint8Array, byHash: Map<string, string>): string {
  return byHash.get(bytesToHex(topic)) ?? Buffer.from(topic).toString("utf8");
}

function buildNonce(timestampMs: number): Uint8Array {
  const ts = new Uint8Array(8);
  new DataView(ts.buffer).setBigUint64(0, BigInt(timestampMs));
  return concatBytes(new Uint8Array([0]), ts, new Uint8Array(randomBytes(8)));
}

function resolveWebsocketHost(ctx: Hsa2BootContext): string {
  const url = ctx.bridgeInitiateData.webSocketUrl;
  if (typeof url === "string" && url) {
    if (url.includes("://")) {
      try {
        return new URL(url).hostname;
      } catch {
        // fall through
      }
    }
    return url.split("/")[0]!;
  }
  const env = ctx.bridgeInitiateData.apnsEnvironment;
  if (typeof env === "string" && WEBSOCKET_HOSTS[env]) return WEBSOCKET_HOSTS[env];
  throw new TrustedDevicePromptError("missing HSA2 websocket host for the trusted-device bridge");
}

function resolveTopic(ctx: Hsa2BootContext): string {
  const topic = ctx.bridgeInitiateData.apnsTopic;
  if (typeof topic === "string" && topic) return topic;
  throw new TrustedDevicePromptError("missing HSA2 APNS topic for the trusted-device bridge");
}

function originOf(authEndpoint: string): string {
  const u = new URL(authEndpoint);
  return `${u.protocol}//${u.hostname}`;
}

const OK_STATUSES = new Set([200, 204, 409]);

export interface BridgeOptions {
  timeoutMs?: number;
  websocketFactory?: WebSocketFactory;
  family?: 0 | 4;
  /** For tests: a fixed prover scalar. */
  proverFactory?: () => TrustedDeviceProver;
}

export class TrustedDeviceBridge {
  private readonly timeoutMs: number;
  private readonly wsFactory: WebSocketFactory;
  private readonly family: 0 | 4;
  private readonly proverFactory: () => TrustedDeviceProver;

  constructor(options: BridgeOptions = {}) {
    this.timeoutMs = options.timeoutMs ?? WEBSOCKET_TIMEOUT_MS;
    this.wsFactory = options.websocketFactory ?? openWebSocket;
    this.family = options.family ?? 0;
    this.proverFactory = options.proverFactory ?? (() => new TrustedDeviceProver());
  }

  /** Steps 1–2: returns once Apple has pushed the prompt to the user's devices. */
  async start(args: {
    session: ICloudSession;
    authEndpoint: string;
    headers: Record<string, string>;
    boot: Hsa2BootContext;
    userAgent: string;
  }): Promise<BridgeState> {
    const topic = resolveTopic(args.boot);
    const host = resolveWebsocketHost(args.boot);
    const origin = originOf(args.authEndpoint);
    const topicsByHash = new Map([[topicHash(topic), topic]]);
    const { publicKey, privateKey } = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
    const jwk = publicKey.export({ format: "jwk" });
    // X9.62 uncompressed point, as Python's cryptography exports it.
    const rawPublic = concatBytes(
      new Uint8Array([4]),
      Buffer.from(jwk.x!, "base64url"),
      Buffer.from(jwk.y!, "base64url"),
    );
    if (rawPublic.length !== 65) throw new TrustedDevicePromptError("could not encode bridge public key");

    let timestampMs: number | undefined;
    let lastError: unknown;
    for (let attempt = 0; attempt < 2; attempt++) {
      const nonce = buildNonce(timestampMs ?? Date.now());
      const signature = new Uint8Array(createSign("sha256").update(nonce).sign(privateKey));
      const connectionPath = bytesToHex(encodeConnectionMessage(rawPublic, nonce, signature));
      let socket: BridgeSocket | null = null;
      let keep = false;
      try {
        socket = await this.wsFactory(`wss://${host}/v2/${connectionPath}`, {
          origin,
          userAgent: args.userAgent,
          timeoutMs: this.timeoutMs,
          family: this.family,
        });
        const pushToken = await this.waitForPushToken(socket);
        const pushTokenHex = bytesToHex(pushToken);
        socket.sendBinary(encodeWebFilterMessage([topic]));

        const sessionUUID = `${randomUUID()}-${Math.floor(Date.now() / 1000)}`;
        const headers = { ...args.headers };
        if (args.boot.sourceAppId) headers["X-Apple-App-Id"] = args.boot.sourceAppId;

        // Apple's browser posts step 0 as soon as it has the push token; waiting
        // for the first push first makes the flow stall.
        const step0 = await args.session.requestRaw("POST", `${args.authEndpoint}/bridge/step/0`, {
          json: { sessionUUID, ptkn: pushTokenHex },
          headers,
        });
        if (!OK_STATUSES.has(step0.status)) {
          throw new TrustedDevicePromptError(`trusted-device bridge step 0 failed with status ${step0.status}`);
        }

        const push = await this.waitForPush(socket, topic, topicsByHash);
        if (push.payload.sessionUUID !== undefined && push.sessionUUID !== sessionUUID) {
          throw new TrustedDevicePromptError("trusted-device bridge returned a mismatched session UUID");
        }
        keep = true;
        return {
          pushTokenHex,
          sessionUUID: push.sessionUUID,
          socket,
          topic,
          topicsByHash,
          sourceAppId: args.boot.sourceAppId,
          push,
        };
      } catch (e) {
        lastError = e;
        if (e instanceof InvalidNonce) {
          timestampMs = e.serverTimestampMs;
          continue;
        }
        break;
      } finally {
        if (!keep) socket?.close();
      }
    }
    throw new TrustedDevicePromptError(
      `failed to start the trusted-device prompt: ${lastError instanceof Error ? lastError.message : String(lastError)}`,
    );
  }

  close(state: BridgeState | null | undefined): void {
    if (!state?.socket) return;
    const s = state.socket;
    state.socket = null;
    s.close();
  }

  /** Step 3: prove knowledge of the code and have Apple validate it. False means a wrong code. */
  async validateCode(args: {
    session: ICloudSession;
    authEndpoint: string;
    headers: Record<string, string>;
    state: BridgeState;
    code: string;
  }): Promise<boolean> {
    const { state } = args;
    const socket = state.socket;
    try {
      if (!socket) throw new TrustedDeviceVerificationError("trusted-device bridge session is not active");
      if (usesLegacyVerifier(state)) {
        throw new TrustedDeviceVerificationError("legacy trusted-device verification bypasses the bridge");
      }
      if (state.push?.nextStep !== "2") {
        throw new TrustedDeviceVerificationError("trusted-device bridge is not ready for step 2");
      }
      if (!state.push.salt) throw new TrustedDeviceVerificationError("bridge payload is missing the step-2 salt");

      const headers = { ...args.headers };
      if (state.sourceAppId) headers["X-Apple-App-Id"] = state.sourceAppId;

      const prover = this.proverFactory();
      prover.initWithSalt(state.push.salt, args.code);
      await this.postStep(args, headers, 2, b64encode(hexToBytes(prover.getMessage1())));

      const step4 = await this.waitForPush(socket, state.topic, state.topicsByHash);
      this.applyPush(state, step4);
      if (step4.nextStep !== "4" || !step4.data) {
        throw new TrustedDeviceVerificationError("trusted-device bridge returned an unexpected post-step-2 payload");
      }
      let serverMsg1Hex: string;
      let serverMsg2Hex: string;
      try {
        const decoded = Buffer.from(b64decode(step4.data)).toString("utf8");
        const sep = decoded.indexOf("_");
        if (sep < 0) throw new Error("no separator");
        serverMsg1Hex = bytesToHex(b64decode(decoded.slice(0, sep)));
        serverMsg2Hex = bytesToHex(b64decode(decoded.slice(sep + 1)));
      } catch {
        throw new TrustedDeviceVerificationError("trusted-device bridge step 4 payload is malformed");
      }

      let confirmation: string;
      try {
        confirmation = prover.processMessage1(serverMsg1Hex);
      } catch {
        throw new TrustedDeviceVerificationError("trusted-device bridge step 4 payload is malformed");
      }
      try {
        prover.processMessage2(serverMsg2Hex);
      } catch {
        return false; // the server's confirmation does not match: wrong code
      }

      await this.postStep(args, headers, 4, b64encode(hexToBytes(confirmation)));
      const final = await this.waitForPush(socket, state.topic, state.topicsByHash);
      this.applyPush(state, final);
      // Apple finishes with either nextStep 6 or 4, both carrying encryptedCode.
      if (!["4", "6"].includes(final.nextStep ?? "") || !final.encryptedCode) {
        throw new TrustedDeviceVerificationError("trusted-device bridge returned an unexpected final payload");
      }
      let derivedCode: string;
      try {
        derivedCode = prover.decryptMessage(final.encryptedCode);
      } catch {
        throw new TrustedDeviceVerificationError("failed to decrypt the trusted-device validation code");
      }

      const verify = await args.session.requestRaw("POST", `${args.authEndpoint}/bridge/code/validate`, {
        json: { sessionUUID: state.sessionUUID, code: derivedCode },
        headers,
      });
      if (![200, 204, 409, 412].includes(verify.status)) {
        throw new TrustedDeviceVerificationError(
          `trusted-device code validation failed with status ${verify.status}`,
        );
      }
      const completion = final.nextStep === "6" ? 6 : 4;
      await this.postStep(args, headers, completion, DONE_DATA_B64);
      return verify.status !== 412;
    } catch (e) {
      if (e instanceof TrustedDeviceVerificationError) throw e;
      throw new TrustedDeviceVerificationError(
        `trusted-device verification failed: ${e instanceof Error ? e.message : String(e)}`,
      );
    } finally {
      this.close(state);
    }
  }

  private async postStep(
    args: { session: ICloudSession; authEndpoint: string; state: BridgeState },
    headers: Record<string, string>,
    step: number,
    data: string,
  ): Promise<void> {
    const { state } = args;
    const body: Json = {
      sessionUUID: state.sessionUUID,
      data,
      ptkn: state.pushTokenHex,
      nextStep: step,
    };
    if (state.push?.idmsdata !== undefined) body.idmsdata = state.push.idmsdata;
    if (state.push?.akdata !== undefined) {
      body.akdata = isObject(state.push.akdata) ? JSON.stringify(state.push.akdata) : state.push.akdata;
    }
    const res = await args.session.requestRaw("POST", `${args.authEndpoint}/bridge/step/${step}`, {
      json: body,
      headers,
    });
    if (!OK_STATUSES.has(res.status)) {
      throw new TrustedDeviceVerificationError(
        `trusted-device bridge step ${step} failed with status ${res.status}: ${responseText(res).slice(0, 200)}`,
      );
    }
  }

  private applyPush(state: BridgeState, push: BridgePushPayload): void {
    if (push.sessionUUID !== state.sessionUUID) {
      throw new TrustedDeviceVerificationError("trusted-device bridge returned a mismatched session UUID");
    }
    if (push.errorCode !== undefined && push.errorCode !== 0) {
      throw new TrustedDeviceVerificationError(
        `trusted-device bridge returned an error (nextStep=${push.nextStep}, ec=${push.errorCode})`,
      );
    }
    state.push = push;
  }

  private async waitForPushToken(socket: BridgeSocket): Promise<Uint8Array> {
    const deadline = Date.now() + this.timeoutMs;
    while (Date.now() < deadline) {
      const msg = decodeServerMessage(await socket.readMessage(deadline - Date.now()));
      const conn = msg.connection;
      if (!conn) continue;
      if (conn.status === STATUS_OK && conn.pushTokenB64) {
        try {
          return b64decode(conn.pushTokenB64);
        } catch {
          throw new TrustedDevicePromptError("malformed bridge push token");
        }
      }
      if (conn.status === STATUS_INVALID_NONCE && conn.serverTimestampSeconds !== undefined) {
        throw new InvalidNonce(conn.serverTimestampSeconds * 1000);
      }
      throw new TrustedDevicePromptError(`bridge server returned status ${conn.status}`);
    }
    throw new TrustedDevicePromptError("timed out waiting for the bridge push token");
  }

  private async waitForPush(
    socket: BridgeSocket,
    topic: string,
    topicsByHash: Map<string, string>,
  ): Promise<BridgePushPayload> {
    const deadline = Date.now() + this.timeoutMs;
    while (Date.now() < deadline) {
      const msg = decodeServerMessage(await socket.readMessage(deadline - Date.now()));
      if (msg.subscription && msg.subscription.status !== STATUS_OK) {
        throw new TrustedDevicePromptError(
          `trusted-device topic subscription failed (status ${msg.subscription.status})`,
        );
      }
      if (!msg.push) continue;
      socket.sendBinary(encodeAckMessage(msg.push.topic, msg.push.messageId));
      if (topicName(msg.push.topic, topicsByHash) !== topic) continue;
      return parsePushPayload(extractJsonPayload(msg.push.payload));
    }
    throw new TrustedDevicePromptError("timed out waiting for the trusted-device bridge payload");
  }
}
