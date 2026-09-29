/**
 * The trusted-device bridge, end to end against a simulated Apple: a fake push
 * websocket and a fake auth endpoint that runs the verifier side of SPAKE2.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash, randomInt } from "node:crypto";

import { b64decode, b64encode, bytesToHex, concatBytes, hexToBytes } from "../src/icloud/bytes.ts";
import { TrustedDeviceBridge, parseBootArgsHtml, type Hsa2BootContext } from "../src/icloud/hsa2/bridge.ts";
import { TestVerifier } from "../src/icloud/hsa2/prover.ts";
import { bytesField, decodeFields, uintField } from "../src/icloud/hsa2/protobuf.ts";
import type { BridgeSocket } from "../src/icloud/hsa2/websocket.ts";
import type { HttpResponse } from "../src/icloud/http.ts";
import type { ICloudSession } from "../src/icloud/session.ts";

const TOPIC = "com.apple.idmsauthwidget";
const topicBytes = hexToBytes(createHash("sha1").update(TOPIC).digest("hex"));
const SALT = b64encode(new Uint8Array(16).fill(5));

class FakeSocket implements BridgeSocket {
  inbox: Uint8Array[] = [];
  sent: Uint8Array[] = [];
  closed = false;
  private waiting: (() => void) | null = null;

  deliver(frame: Uint8Array) {
    this.inbox.push(frame);
    this.waiting?.();
  }
  sendBinary(p: Uint8Array) {
    this.sent.push(p);
  }
  async readMessage(timeoutMs: number): Promise<Uint8Array> {
    const deadline = Date.now() + timeoutMs;
    while (!this.inbox.length) {
      if (this.closed) throw new Error("closed");
      if (Date.now() > deadline) throw new Error("timeout");
      await new Promise<void>((r) => {
        this.waiting = r;
        setTimeout(r, 20);
      });
    }
    return this.inbox.shift()!;
  }
  close() {
    this.closed = true;
  }
}

let messageId = 1;
function pushFrame(payload: object): Uint8Array {
  return bytesField(
    2,
    concatBytes(
      bytesField(1, topicBytes),
      uintField(2, messageId++),
      bytesField(4, new TextEncoder().encode(JSON.stringify(payload))),
    ),
  );
}

function ok(status = 200): HttpResponse {
  return { status, statusText: "", headers: {}, setCookies: [], body: new Uint8Array(), url: "" };
}

/** Apple's side of the flow, keyed by the code shown on the "device". */
function simulateApple(deviceCode: string) {
  const socket = new FakeSocket();
  const verifier = new TestVerifier(deviceCode, SALT);
  const finalCode = String(randomInt(100000, 999999));
  let sessionUUID = "";
  const posts: string[] = [];

  const session = {
    async requestRaw(_m: string, url: string, opts?: { json?: Record<string, unknown> }) {
      const path = new URL(url).pathname;
      posts.push(path);
      const body = opts?.json ?? {};
      if (path.endsWith("/bridge/step/0")) {
        sessionUUID = String(body.sessionUUID);
        assert.match(String(body.ptkn), /^[0-9a-f]+$/, "push token is sent as hex");
        socket.deliver(pushFrame({ sessionUUID, nextStep: 2, salt: SALT, txnid: "t-1" }));
      } else if (path.endsWith("/bridge/step/2")) {
        const clientMsg = bytesToHex(b64decode(String(body.data)));
        const serverConfirm = verifier.processMessage1(clientMsg);
        const data = `${b64encode(hexToBytes(verifier.getMessage1()))}_${b64encode(hexToBytes(serverConfirm))}`;
        socket.deliver(pushFrame({ sessionUUID, nextStep: 4, data: Buffer.from(data).toString("base64") }));
      } else if (path.endsWith("/bridge/step/4")) {
        const good = verifier.verifyClient(bytesToHex(b64decode(String(body.data))));
        assert.ok(good, "client confirmation verifies");
        socket.deliver(pushFrame({ sessionUUID, nextStep: 6, encryptedCode: verifier.encryptCode(finalCode) }));
      } else if (path.endsWith("/bridge/code/validate")) {
        return ok(body.code === finalCode ? 200 : 412);
      } else if (path.endsWith("/bridge/step/6")) {
        assert.equal(Buffer.from(String(body.data), "base64").toString(), "done");
      }
      return ok();
    },
  } as unknown as ICloudSession;

  const factory = async () => {
    socket.deliver(
      bytesField(1, concatBytes(bytesField(1, new TextEncoder().encode(b64encode(new Uint8Array([1, 2, 3])))), uintField(2, 0))),
    );
    return socket;
  };
  return { socket, session, factory, posts };
}

const boot: Hsa2BootContext = {
  authInitialRoute: "auth/bridge/step",
  hasTrustedDevices: true,
  authFactors: ["web_sa_bridge"],
  bridgeInitiateData: { apnsTopic: TOPIC, apnsEnvironment: "prod" },
  phoneNumberVerification: {},
};

async function run(deviceCode: string, typedCode: string) {
  const apple = simulateApple(deviceCode);
  const bridge = new TrustedDeviceBridge({ websocketFactory: apple.factory, timeoutMs: 2000 });
  const args = {
    session: apple.session,
    authEndpoint: "https://idmsa.apple.com/appleauth/auth",
    headers: {},
  };
  const state = await bridge.start({ ...args, boot, userAgent: "test" });
  assert.equal(state.push?.nextStep, "2");
  const filter = decodeFields(apple.socket.sent[0]!);
  assert.ok(filter.has(3), "subscribed to the topic");
  const result = await bridge.validateCode({ ...args, state, code: typedCode });
  return { result, apple, state };
}

test("bridge: the code shown on the device verifies end to end", async () => {
  const { result, apple, state } = await run("482913", "482913");
  assert.equal(result, true);
  assert.deepEqual(
    apple.posts.map((p) => p.split("/").slice(-2).join("/")),
    ["step/0", "step/2", "step/4", "code/validate", "step/6"],
  );
  assert.equal(state.socket, null, "websocket closed afterwards");
  assert.ok(apple.socket.sent.length >= 4, "each push was acknowledged");
});

test("bridge: a mistyped code is reported as wrong, not as an error", async () => {
  const apple = simulateApple("482913");
  const bridge = new TrustedDeviceBridge({ websocketFactory: apple.factory, timeoutMs: 2000 });
  const args = { session: apple.session, authEndpoint: "https://idmsa.apple.com/appleauth/auth", headers: {} };
  const state = await bridge.start({ ...args, boot, userAgent: "test" });
  // The verifier confirms with its own key, which a wrong code cannot reproduce,
  // so the prover detects the mismatch itself and never posts step 4.
  const result = await bridge.validateCode({ ...args, state, code: "111111" }).catch((e) => e);
  assert.equal(result, false);
  assert.ok(!apple.posts.some((p) => p.endsWith("/bridge/step/4")));
});

test("boot args are read from the HTML auth shell", () => {
  const html = `<html><head><script type="application/json" class="boot_args">
    {"direct":{"authInitialRoute":"auth/bridge/step","hasTrustedDevices":true,
      "twoSV":{"authFactors":["web_sa_bridge"],"sourceAppId":"1159",
        "bridgeInitiateData":{"apnsTopic":"t","apnsEnvironment":"prod",
          "phoneNumberVerification":{"trustedPhoneNumber":{"id":2,"pushMode":"sms"}}}}}}
  </script></head></html>`;
  const ctx = parseBootArgsHtml(html);
  assert.equal(ctx.authInitialRoute, "auth/bridge/step");
  assert.equal(ctx.sourceAppId, "1159");
  assert.equal(ctx.bridgeInitiateData.apnsTopic, "t");
  assert.deepEqual(ctx.phoneNumberVerification.trustedPhoneNumber, { id: 2, pushMode: "sms" });
});
