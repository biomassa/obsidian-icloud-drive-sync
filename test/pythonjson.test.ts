import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";

import { pythonJson } from "../src/icloud/http.ts";

const samples: unknown[] = [
  { accountName: "user@example.com", c: "d-123-456", m1: "abc+/=", rememberMe: true, trustTokens: [] },
  { a: "x", protocols: ["s2k", "s2k_fo"], n: 20961, nested: { z: null, f: false } },
  { text: "Pässwörd — ünïcode ✓ 😀", ctrl: "a\u0001b\n\t\"\\/\u007f" },
  [1, [2, [3, {}]], "", -5],
];

test("pythonJson is byte-identical to Python's json.dumps", () => {
  for (const s of samples) {
    const py = execFileSync("python3", ["-c", "import json,sys; sys.stdout.write(json.dumps(json.load(sys.stdin)))"], {
      input: JSON.stringify(s),
      encoding: "utf8",
    });
    assert.equal(pythonJson(s), py);
  }
});
