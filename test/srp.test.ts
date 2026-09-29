import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import { b64decode, b64encode } from "../src/icloud/bytes.ts";
import { SrpClient, derivePassword, type SrpProtocol } from "../src/icloud/srp.ts";

interface Vector {
  account: string;
  password: string;
  protocol: SrpProtocol;
  a: string;
  salt: string;
  iterations: number;
  B: string;
  A: string;
  derivedPassword: string;
  u: string;
  x: string;
  S: string;
  K: string;
  M1: string;
  M2: string;
}

const vectors: Vector[] = JSON.parse(
  readFileSync(new URL("./fixtures/srp-vectors.json", import.meta.url), "utf8"),
);

for (const v of vectors) {
  test(`SRP matches icloudlite (${v.protocol}, ${v.account})`, () => {
    const salt = b64decode(v.salt);
    assert.equal(
      b64encode(derivePassword(v.password, salt, v.iterations, v.protocol)),
      v.derivedPassword,
      "PBKDF2 password derivation",
    );

    const client = new SrpClient(v.account, b64decode(v.a));
    assert.equal(b64encode(client.publicKey), v.A, "A");

    const proof = client.processChallenge(v.password, {
      salt,
      B: b64decode(v.B),
      iterations: v.iterations,
      protocol: v.protocol,
    });
    assert.equal(proof.debug.u.toString(16), v.u, "u");
    assert.equal(proof.debug.x.toString(16), v.x, "x");
    assert.equal(proof.debug.S.toString(16), v.S, "S");
    assert.equal(b64encode(proof.debug.K), v.K, "K");
    assert.equal(b64encode(proof.M1), v.M1, "M1");
    assert.equal(b64encode(proof.M2), v.M2, "M2");
  });
}

test("SRP rejects B ≡ 0 mod N", () => {
  const client = new SrpClient("a@b.c", new Uint8Array(32).fill(7));
  assert.throws(() =>
    client.processChallenge("pw", {
      salt: new Uint8Array(16).fill(1),
      B: new Uint8Array(0),
      iterations: 1000,
      protocol: "s2k",
    }),
  );
});
