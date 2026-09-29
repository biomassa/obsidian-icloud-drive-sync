/**
 * The pre-send guard, and the production SRP path against obsisync's Python on
 * random challenges. The second half needs obsisync's virtualenv and is skipped
 * without it.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { existsSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

import { ICloudAuth } from "../src/icloud/auth.ts";
import { b64encode } from "../src/icloud/bytes.ts";
import { SrpClient, type SrpProtocol } from "../src/icloud/srp.ts";
import { MemorySessionStore } from "../src/icloud/store.ts";
import { FakeApple } from "./fake-apple.ts";

test("a throwing proof check aborts before signin/complete is sent", async () => {
  const fake = new FakeApple();
  let checked = 0;
  const auth = await ICloudAuth.open({
    accountName: "user@example.com",
    store: new MemorySessionStore(),
    transport: fake.transport,
    verifySrpProof: async (c) => {
      checked++;
      assert.equal(c.ephemeral.length, 32, "32-byte ephemeral, as obsisync's backend uses");
      assert.ok(c.ephemeral[0]! & 0x80, "top bit set, as BN_rand(a, 256, 0, 0) produces");
      assert.equal(c.iterations, 1000);
      throw new Error("refuse");
    },
  });
  await assert.rejects(auth.signIn("pw"), /refuse/);
  assert.equal(checked, 1);
  assert.equal(fake.count("POST", "/signin/complete"), 0, "Apple never saw a proof");
});

const PYTHON = join(homedir(), "scripts/obsisync/.venv/bin/python");
const SCRIPT = new URL("../tools/srp_crosscheck.py", import.meta.url).pathname;

test("production SRP path matches obsisync's Python on random challenges", { skip: !existsSync(PYTHON) }, () => {
  const passwords = ["hunter2", "Pässwörd — ünïcode ✓", " spaces at both ends ", "x".repeat(64)];
  for (let i = 0; i < 12; i++) {
    const protocol: SrpProtocol = i % 2 ? "s2k_fo" : "s2k";
    const password = passwords[i % passwords.length]!;
    const account = i % 3 ? "Some.User@Example.com" : "another.user@example.com";
    const salt = new Uint8Array(randomBytes(16));
    salt[0] ||= 1; // the leading-zero divergence is covered separately
    const B = new Uint8Array(randomBytes(256));
    B[0]! &= 0x7f; // keep B below N
    const iterations = 1000 + i * 997;

    const client = new SrpClient(account);
    const proof = client.processChallenge(password, { salt, B, iterations, protocol });
    const py = JSON.parse(
      execFileSync(PYTHON, [SCRIPT], {
        input: JSON.stringify({
          account,
          password,
          a: b64encode(client.ephemeral),
          salt: b64encode(salt),
          B: b64encode(B),
          iterations,
          protocol,
        }),
        encoding: "utf8",
      }),
    );
    const label = `case ${i} (${protocol}, ${iterations} iterations)`;
    assert.equal(py.A, b64encode(client.publicKey), `${label}: A`);
    assert.equal(py.M1, b64encode(proof.M1), `${label}: M1`);
    assert.equal(py.M2, b64encode(proof.M2), `${label}: M2`);
  }
});
