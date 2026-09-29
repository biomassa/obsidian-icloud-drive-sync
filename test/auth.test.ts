import { test } from "node:test";
import assert from "node:assert/strict";

import { ICloudAuth } from "../src/icloud/auth.ts";
import { CookieJar } from "../src/icloud/cookies.ts";
import { MemorySessionStore } from "../src/icloud/store.ts";
import { FakeApple } from "./fake-apple.ts";

async function open(fake: FakeApple, store = new MemorySessionStore()) {
  const auth = await ICloudAuth.open({ accountName: "user@example.com", store, transport: fake.transport });
  return { auth, store };
}

test("signIn reports needs-2fa and does not request a code by itself", async () => {
  const fake = new FakeApple();
  const { auth } = await open(fake);
  const result = await auth.signIn("pw");
  assert.equal(result.status, "needs-2fa");
  assert.equal(fake.count("PUT", "/verify/phone"), 0, "no SMS was requested");
  assert.equal(fake.count("GET", "/verify/trusteddevice"), 0, "no device push was requested");
});

test("SMS two-factor: request, reject a wrong code, accept the right one, trust", async () => {
  const fake = new FakeApple({ code: "654321" });
  const { auth, store } = await open(fake);
  await auth.signIn("pw");

  assert.equal(await auth.requestCode(), "sms");
  assert.equal(fake.count("PUT", "/verify/phone"), 1);
  assert.match(auth.deliveryDescription ?? "", /•••• 42/);

  assert.equal(await auth.submitCode("111111"), false, "wrong code");
  assert.equal(await auth.submitCode("654 321"), true, "right code, spaces tolerated");
  assert.equal(auth.isTrustedSession, true);
  assert.equal(auth.params.dsid, "12345");

  await auth.session.persist();
  assert.equal(store.value?.data.trust_token, "trust-1");
  assert.equal(store.value?.data.session_token, "session-2");
});

test("resume uses stored tokens only: no password, no SRP, no code", async () => {
  const fake = new FakeApple();
  const { auth, store } = await open(fake);
  await auth.signIn("pw");
  await auth.requestCode();
  await auth.submitCode("123456");
  await auth.session.persist();

  const before = fake.calls.length;
  const { auth: again } = await open(fake, store);
  assert.equal(await again.resume(), true);
  const later = fake.calls.slice(before);
  assert.ok(later.every((c) => !c.path.includes("/signin/")), "no SRP on resume");
  assert.ok(later.every((c) => !c.path.includes("/verify/")), "no code requested on resume");
});

test("resume without a stored session says so instead of signing in", async () => {
  const fake = new FakeApple();
  const { auth } = await open(fake);
  assert.equal(await auth.resume(), false);
  assert.equal(fake.calls.length, 0);
});

test("a valid trust token signs in without any two-factor step", async () => {
  const fake = new FakeApple({ trustedAlready: true });
  const { auth } = await open(fake);
  assert.deepEqual(await auth.signIn("pw"), { status: "signed-in" });
  assert.equal(
    fake.calls.filter((c) => c.path === "/appleauth/auth").length,
    0,
    "no two-factor options were loaded",
  );
});

test("cookie jar: domain, path, secure, expiry and quoted values", () => {
  let now = 1_000_000;
  const jar = new CookieJar(() => now);
  const url = new URL("https://setup.icloud.com/setup/ws/1/accountLogin");
  jar.setCookie('X-APPLE-WEBAUTH-TOKEN="v=2:t=abc"; Domain=.icloud.com; Path=/; Secure', url);
  jar.setCookie("short=1; Max-Age=10", url);
  jar.setCookie("evil=1; Domain=apple.com", url); // not a domain of this host: refused

  assert.equal(jar.get("X-APPLE-WEBAUTH-TOKEN"), '"v=2:t=abc"');
  assert.match(jar.cookieHeader(new URL("https://p30-drivews.icloud.com/x")), /X-APPLE-WEBAUTH-TOKEN/);
  assert.equal(jar.cookieHeader(new URL("http://p30-drivews.icloud.com/x")).includes("WEBAUTH"), false);
  assert.equal(jar.get("evil"), undefined);
  assert.equal(jar.cookieHeader(new URL("https://idmsa.apple.com/")), "");

  assert.equal(jar.get("short"), "1");
  now += 11_000;
  assert.equal(jar.get("short"), undefined);

  const restored = CookieJar.fromJSON(JSON.parse(JSON.stringify(jar.toJSON())), () => now);
  assert.equal(restored.get("X-APPLE-WEBAUTH-TOKEN"), '"v=2:t=abc"');
});
