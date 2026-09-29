/**
 * A scripted stand-in for Apple's auth and iCloud endpoints, enough to drive
 * ICloudAuth through SRP, SMS two-factor, trust and resume without a network.
 */
import type { HttpRequest, HttpResponse, Transport } from "../src/icloud/http.ts";

export interface Call {
  method: string;
  path: string;
  body: unknown;
  headers: Record<string, string>;
}

export interface FakeAppleOptions {
  /** The code the fake accepts. */
  code?: string;
  /** When true, signin/complete trusts immediately (a valid trust token was sent). */
  trustedAlready?: boolean;
  /** When true, signin/complete rejects the password. */
  wrongPassword?: boolean;
}

function res(
  status: number,
  body: unknown,
  headers: Record<string, string> = {},
  setCookies: string[] = [],
  contentType = "application/json",
): HttpResponse {
  const text = typeof body === "string" ? body : JSON.stringify(body);
  return {
    status,
    statusText: String(status),
    headers: { "content-type": contentType, ...headers },
    setCookies,
    body: new TextEncoder().encode(text),
    url: "",
  };
}

export class FakeApple {
  readonly calls: Call[] = [];
  trusted = false;
  sessionValid = false;
  private readonly code: string;
  private readonly trustedAlready: boolean;
  private readonly wrongPassword: boolean;

  constructor(options: FakeAppleOptions = {}) {
    this.code = options.code ?? "123456";
    this.trustedAlready = options.trustedAlready ?? false;
    this.wrongPassword = options.wrongPassword ?? false;
  }

  /** Invalidate the session, as Apple does when a session expires. */
  expireSession() {
    this.sessionValid = false;
    this.trusted = false;
  }

  count(method: string, pathFragment: string): number {
    return this.calls.filter((c) => c.method === method && c.path.includes(pathFragment)).length;
  }

  private accountData() {
    return {
      dsInfo: { dsid: "12345", hsaVersion: 2 },
      hsaTrustedBrowser: this.trusted,
      webservices: {
        drivews: { url: "https://drive.fake" },
        docws: { url: "https://docs.fake" },
      },
    };
  }

  transport: Transport = async (req: HttpRequest) => {
    const url = new URL(req.url);
    const body = req.body ? safeJson(new TextDecoder().decode(req.body)) : undefined;
    this.calls.push({ method: req.method, path: url.pathname, body, headers: req.headers });
    const p = url.pathname;

    if (p.endsWith("/authorize/signin")) return res(200, "", {}, [], "text/html");
    if (p.endsWith("/signin/init")) {
      return res(200, {
        salt: Buffer.alloc(16, 3).toString("base64"),
        b: Buffer.alloc(256, 9).toString("base64"),
        c: "challenge-c",
        iteration: 1000,
        protocol: "s2k",
      });
    }
    if (p.endsWith("/signin/complete") && this.wrongPassword) {
      return res(401, { serviceErrors: [{ code: "-20101", message: "Your Apple ID or password was incorrect." }] });
    }
    if (p.endsWith("/signin/complete")) {
      const sessionHeaders = {
        "x-apple-session-token": "session-1",
        "x-apple-id-session-id": "sid-1",
        scnt: "scnt-1",
        "x-apple-id-account-country": "USA",
      };
      if (this.trustedAlready) {
        this.trusted = true;
        return res(200, {}, sessionHeaders);
      }
      return res(409, { authType: "hsa2" }, sessionHeaders);
    }
    if (p === "/appleauth/auth" && req.method === "GET") {
      const boot = {
        direct: {
          authInitialRoute: "auth/verify/phone",
          hasTrustedDevices: false,
          twoSV: {
            phoneNumberVerification: {},
            bridgeInitiateData: {
              phoneNumberVerification: {
                trustedPhoneNumber: { id: 1, pushMode: "sms", obfuscatedNumber: "•••• 42" },
              },
            },
          },
        },
      };
      return res(
        200,
        `<html><script type="application/json" class="boot_args">${JSON.stringify(boot)}</script></html>`,
        {},
        [],
        "text/html",
      );
    }
    if (p.endsWith("/verify/phone") && req.method === "PUT") return res(200, {});
    if (p.endsWith("/verify/phone/securitycode")) {
      const code = (body as { securityCode?: { code?: string } })?.securityCode?.code;
      return code === this.code
        ? res(200, {})
        : res(400, { service_errors: [{ code: "-21669" }], errorMessage: "Incorrect code" });
    }
    if (p.endsWith("/2sv/trust")) {
      this.trusted = true;
      return res(204, "", { "x-apple-twosv-trust-token": "trust-1", "x-apple-session-token": "session-2" });
    }
    if (p.endsWith("/accountLogin")) {
      this.sessionValid = true;
      return res(200, this.accountData(), {}, [
        "X-APPLE-WEBAUTH-TOKEN=\"v=2:t=abc\"; Domain=.icloud.com; Path=/; Secure",
        "X-APPLE-WEBAUTH-VALIDATE=\"v=1:t=UPLOADTOKEN\"; Domain=.icloud.com; Path=/; Secure",
      ]);
    }
    if (p.endsWith("/validate")) {
      return this.sessionValid ? res(200, this.accountData()) : res(421, { error: "Missing token" });
    }
    return res(404, { error: `fake has no route for ${req.method} ${p}` });
  };
}

function safeJson(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
}
