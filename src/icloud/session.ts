/**
 * The iCloud request pipeline: Apple's session headers, persistence, and the
 * translation of Apple's many error shapes into the classes in errors.ts.
 *
 * Port of icloudlite/session.py, with two deliberate changes found in review:
 *
 * - Persisting is serialized and skipped when nothing changed. The Python
 *   rewrote the session file non-atomically on every request, from several
 *   threads, and a torn write lost the tokens (forcing a new 2FA).
 * - HTTP 500 is a server error, not "authentication required". Only 421 and
 *   450 mean the session itself is gone.
 */
import { CookieJar } from "./cookies.ts";
import {
  ApiError,
  AuthRequiredError,
  ServiceNotActivatedError,
  TwoFactorRequiredError,
} from "./errors.ts";
import {
  HttpClient,
  isJsonResponse,
  responseText,
  type HttpResponse,
  type RequestOptions,
  type Transport,
} from "./http.ts";
import type { PersistedSession, SessionStore } from "./store.ts";

/** Response headers Apple uses to hand back session state, and where each is kept. */
const HEADER_DATA: Record<string, string> = {
  "x-apple-id-account-country": "account_country",
  "x-apple-id-session-id": "session_id",
  "x-apple-auth-attributes": "auth_attributes",
  "x-apple-session-token": "session_token",
  "x-apple-twosv-trust-token": "trust_token",
  "x-apple-twosv-trust-eligible": "trust_eligible",
  "x-apple-oauth-grant-code": "grant_code",
  "x-apple-i-rscd": "apple_rscd",
  "x-apple-i-ercd": "apple_ercd",
  scnt: "scnt",
};

export const USER_AGENT =
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) " +
  "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.3.1 Safari/605.1.15";

export class ICloudSession {
  readonly accountName: string;
  readonly http: HttpClient;
  data: Record<string, string>;
  private readonly store: SessionStore;
  private lastSaved = "";
  private saving: Promise<void> = Promise.resolve();

  constructor(
    accountName: string,
    transport: Transport,
    store: SessionStore,
    persisted: PersistedSession | null,
    homeEndpoint: string,
  ) {
    this.accountName = accountName;
    this.store = store;
    this.data = { ...(persisted?.data ?? {}) };
    const jar = CookieJar.fromJSON(persisted?.cookies ?? []);
    this.http = new HttpClient(transport, jar, {
      "User-Agent": USER_AGENT,
      Origin: homeEndpoint,
      Referer: `${homeEndpoint}/`,
    });
    if (persisted) this.lastSaved = JSON.stringify(this.snapshot());
  }

  get cookies(): CookieJar {
    return this.http.jar;
  }

  snapshot(): PersistedSession {
    return {
      version: 1,
      accountName: this.accountName,
      data: { ...this.data },
      cookies: this.http.jar.toJSON(),
    };
  }

  /** Write the session if it changed. Writes are queued, so they never interleave. */
  persist(): Promise<void> {
    const snapshot = this.snapshot();
    const text = JSON.stringify(snapshot);
    if (text === this.lastSaved) return this.saving;
    this.lastSaved = text;
    this.saving = this.saving
      .catch(() => undefined)
      .then(() => this.store.save(snapshot));
    return this.saving;
  }

  async clear(): Promise<void> {
    this.data = {};
    this.http.jar.clear();
    this.lastSaved = "";
    await this.saving.catch(() => undefined);
    await this.store.clear();
  }

  private absorb(res: HttpResponse): void {
    for (const [header, key] of Object.entries(HEADER_DATA)) {
      const value = res.headers[header];
      if (value) this.data[key] = value;
    }
    void this.persist().catch(() => undefined);
  }

  /** A request with no status handling, for flows that interpret statuses themselves. */
  async requestRaw(method: string, url: string, opts?: RequestOptions): Promise<HttpResponse> {
    const res = await this.http.request(method, url, opts);
    this.absorb(res);
    return res;
  }

  /** A request whose failures, including error payloads inside a 200, throw. */
  async request(method: string, url: string, opts?: RequestOptions): Promise<HttpResponse> {
    const res = await this.requestRaw(method, url, opts);
    const ok = res.status >= 200 && res.status < 300;

    if (!ok) {
      if (res.status === 409 && isJsonResponse(res)) {
        const body = tryJson(res);
        if (body && typeof body === "object" && (body as Record<string, unknown>).authType === "hsa2") {
          throw new TwoFactorRequiredError("Two-factor authentication required");
        }
      }
      if (res.status === 421 || res.status === 450) {
        throw new AuthRequiredError(`iCloud session is no longer valid (HTTP ${res.status})`);
      }
      const body = isJsonResponse(res) ? tryJson(res) : undefined;
      const detail = body ? errorReason(body) : undefined;
      throw classify(detail?.reason ?? (res.statusText || `HTTP ${res.status}`), res.status, detail?.code);
    }

    if (isJsonResponse(res) && res.body.length) {
      const body = tryJson(res);
      const detail = body ? errorReason(body) : undefined;
      if (detail) throw classify(detail.reason, res.status, detail.code);
    }
    return res;
  }
}

function tryJson(res: HttpResponse): unknown {
  try {
    return JSON.parse(responseText(res));
  } catch {
    return undefined;
  }
}

function errorReason(body: unknown): { reason: string; code?: string | number } | undefined {
  if (!body || typeof body !== "object" || Array.isArray(body)) return undefined;
  const b = body as Record<string, unknown>;
  // idmsa reports failures as serviceErrors: [{ code: "-20101", message: "…" }].
  const serviceError = Array.isArray(b.serviceErrors) ? (b.serviceErrors[0] as Record<string, unknown>) : undefined;
  if (serviceError && (serviceError.message || serviceError.code)) {
    return {
      reason: String(serviceError.message ?? "Apple reported an error"),
      code: serviceError.code as string | number | undefined,
    };
  }
  let reason = b.errorMessage ?? b.reason ?? b.errorReason ?? b.error;
  if (!reason) return undefined;
  if (typeof reason !== "string") reason = "Unknown reason";
  const code = (b.errorCode ?? b.serverErrorCode) as string | number | undefined;
  return { reason: reason as string, code };
}

function classify(reason: string, status: number, code?: string | number): Error {
  if (code === "ZONE_NOT_FOUND" || code === "AUTHENTICATION_FAILED") {
    return new ServiceNotActivatedError(
      "Please log into https://icloud.com/ to finish setting up your iCloud service",
      status,
      code,
    );
  }
  if (code === "ACCESS_DENIED") {
    return new ApiError(
      `${reason}. Please wait a few minutes and try again; iCloud may be throttling requests.`,
      status,
      code,
    );
  }
  return new ApiError(reason, status, code);
}
