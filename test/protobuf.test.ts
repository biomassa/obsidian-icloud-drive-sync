import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";

import { bytesToHex, hexToBytes } from "../src/icloud/bytes.ts";
import {
  ProtocolError,
  decodeFields,
  decodeServerMessage,
  encodeAckMessage,
  encodeConnectionMessage,
  encodeWebFilterMessage,
} from "../src/icloud/hsa2/protobuf.ts";

const v = JSON.parse(
  readFileSync(new URL("./fixtures/protobuf-vectors.json", import.meta.url), "utf8"),
);

test("connection message matches icloudlite byte for byte", () => {
  const msg = encodeConnectionMessage(
    hexToBytes(v.publicKey),
    hexToBytes(v.nonce),
    hexToBytes(v.signature),
  );
  assert.equal(bytesToHex(msg), v.connectionMessage);
});

test("web filter and ack messages match icloudlite", () => {
  assert.equal(bytesToHex(encodeWebFilterMessage(["com.apple.idmsauthwidget"])), v.webFilterMessage);
  assert.equal(bytesToHex(encodeAckMessage(new TextEncoder().encode("topic-bytes"), 300)), v.ackMessage);
});

test("topic hash is SHA-1 of the topic name", () => {
  const hash = createHash("sha1").update("com.apple.idmsauthwidget").digest("hex");
  assert.equal(hash, v.topicHash);
});

test("server push and connection frames decode", () => {
  const push = decodeServerMessage(hexToBytes(v.serverPushFrame));
  assert.equal(push.push?.messageId, 300);
  assert.equal(Buffer.from(push.push!.topic).toString(), "topic-bytes");
  assert.equal(Buffer.from(push.push!.payload).toString(), v.serverPushPayload);

  const conn = decodeServerMessage(hexToBytes(v.serverConnectionFrame));
  assert.equal(conn.connection?.pushTokenB64, "cHVzaHRva2Vu");
  assert.equal(conn.connection?.status, 0);
  assert.equal(conn.connection?.serverTimestampSeconds, 1_700_000_000);
});

test("malformed frames are rejected, not skipped", () => {
  assert.throws(() => decodeFields(new Uint8Array([0x0a, 0x05, 0x01])), ProtocolError);
  assert.throws(() => decodeFields(new Uint8Array([0x0d, 0, 0, 0, 0])), ProtocolError);
  assert.throws(() => decodeFields(new Uint8Array([0x08, 0xff])), ProtocolError);
});
