import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import {
  TrustedDeviceProver,
  computeW0W1,
  decryptBridgeCode,
  deriveProverAndVerifierKeys,
  encryptBridgeCode,
} from "../src/icloud/hsa2/prover.ts";

const v = JSON.parse(
  readFileSync(new URL("./fixtures/spake2-vectors.json", import.meta.url), "utf8"),
);

test("scrypt-derived SPAKE2 scalars match icloudlite", () => {
  const [w0, w1] = computeW0W1(v.code, v.salt);
  assert.equal(w0.toString(16), v.w0);
  assert.equal(w1.toString(16), v.w1);
});

test("full prover exchange matches icloudlite", () => {
  const prover = new TrustedDeviceProver();
  prover.initWithSalt(v.salt, v.code, BigInt("0x" + v.x));
  assert.equal(prover.getMessage1(), v.clientMessage, "message 1");
  assert.equal(prover.processMessage1(v.serverMessage), v.clientConfirmation, "confirmation");
  assert.equal(prover.processMessage2(v.serverConfirmation), v.rawKey, "shared key");
  assert.equal(prover.decryptMessage(v.encryptedCode), v.decryptedCode, "decrypted code");
});

test("prover and verifier keys match icloudlite", () => {
  assert.deepEqual(deriveProverAndVerifierKeys(v.rawKey), [v.verifierKey, v.proverKey]);
});

test("a wrong code fails the server confirmation", () => {
  const prover = new TrustedDeviceProver();
  prover.initWithSalt(v.salt, "000000", BigInt("0x" + v.x));
  prover.getMessage1();
  prover.processMessage1(v.serverMessage);
  assert.throws(() => prover.processMessage2(v.serverConfirmation), /invalid confirmation/);
});

test("AES-GCM code envelope round-trips and rejects tampering", () => {
  const sealed = encryptBridgeCode(v.verifierKey, "424242");
  assert.equal(decryptBridgeCode(v.verifierKey, sealed), "424242");
  const bytes = Buffer.from(sealed, "base64");
  bytes[bytes.length - 1]! ^= 1;
  assert.throws(() => decryptBridgeCode(v.verifierKey, bytes.toString("base64")));
});
