/**
 * iCloud sign-in: SRP, session tokens, and two-factor authentication.
 *
 * Port of icloudlite/base.py, restructured around one rule found in review:
 * **nothing here sends a 2FA code unless the user asked for one.** icloudlite's
 * SRP path requested a code (push *and* SMS) whenever Apple answered 409, and
 * obsisync re-authenticated every sync cycle, so an expired trust token meant a
 * new push and SMS every two minutes plus a password login each time.
 *
 * The lifecycle is therefore explicit:
 *
 *   resume()             cheap; token only. Never uses the password.
 *   signIn(password)     SRP when resume() is not enough. Reports whether a
 *                        second factor is needed; does not request one.
 *   requestCode()        the user asked: start the device prompt or send SMS.
 *   submitCode(code)     validate, then trust the session.
 */
import { randomUUID } from "node:crypto";

import { b64decode, b64encode } from "./bytes.ts";
import {
  ApiError,
  AuthRequiredError,
  FailedLoginError,
  ICloudError,
  NoTrustedPhoneNumberError,
  TermsAcceptanceRequiredError,
  TrustedDevicePromptError,
  TrustedDeviceVerificationError,
  TwoFactorRequiredError,
} from "./errors.ts";
import { responseJson, responseText, nodeTransport, type Transport } from "./http.ts";
import {
  TrustedDeviceBridge,
  bootContextAsAuthData,
  bootContextFromAuthOptions,
  parseBootArgsHtml,
  supportsBridge,
  usesLegacyVerifier,
  type BridgeOptions,
  type BridgeState,
  type Hsa2BootContext,
} from "./hsa2/bridge.ts";
import { ICloudSession, USER_AGENT } from "./session.ts";
import { SRP_PROTOCOLS, SrpClient, type SrpProtocol } from "./srp.ts";
import type { SessionStore } from "./store.ts";

const WIDGET_KEY = "d39ba9916b7251055b22c7f910e2ea796ee65e98b2ddecea8f5dde8d9d1a815d";

const AUTH_HEADERS: Record<string, string> = {
  Accept: "application/json, text/javascript",
  "Content-Type": "application/json",
  "X-Apple-OAuth-Client-Id": WIDGET_KEY,
  "X-Apple-OAuth-Client-Type": "firstPartyAuth",
  "X-Apple-OAuth-Redirect-URI": "https://www.icloud.com",
  "X-Apple-OAuth-Require-Grant-Code": "true",
  "X-Apple-OAuth-Response-Mode": "web_message",
  "X-Apple-OAuth-Response-Type": "code",
  "X-Apple-OAuth-State": "",
  "X-Apple-Widget-Key": WIDGET_KEY,
  "X-Apple-FD-Client-Info": JSON.stringify({ U: USER_AGENT, L: "en-US", Z: "GMT+00:00", V: "1.1", F: "" }),
};

const PARAMS = { clientBuildNumber: "2534Project66", clientMasteringNumber: "2534B22" };

export type DeliveryMethod = "trusted_device" | "sms" | "unknown";

export type SignInResult = { status: "signed-in" } | { status: "needs-2fa" };

type Json = Record<string, unknown>;

interface TrustedPhone {
  id: number | string;
  nonFTEU?: boolean;
  pushMode?: string;
  obfuscatedNumber?: string;
}

function asPhone(v: unknown): TrustedPhone | undefined {
  if (!v || typeof v !== "object") return undefined;
  const o = v as Json;
  if (typeof o.id !== "number" && typeof o.id !== "string") return undefined;
  return {
    id: o.id,
    nonFTEU: typeof o.nonFTEU === "boolean" ? o.nonFTEU : undefined,
    pushMode: o.pushMode != null ? String(o.pushMode) : undefined,
    obfuscatedNumber:
      typeof o.obfuscatedNumber === "string"
        ? o.obfuscatedNumber
        : typeof o.numberWithDialCode === "string"
          ? o.numberWithDialCode
          : undefined,
  };
}

function phonePayload(p: TrustedPhone): Json {
  const out: Json = { id: p.id };
  if (p.nonFTEU !== undefined) out.nonFTEU = p.nonFTEU;
  return out;
}

export interface ICloudAuthOptions {
  accountName: string;
  store: SessionStore;
  transport?: Transport;
  /** Apple IDs registered in mainland China use the .cn endpoints. */
  chinaMainland?: boolean;
  bridge?: BridgeOptions;
  /** Non-secret facts about a sign-in, for diagnosing a rejected password. */
  onDiagnostic?: (message: string) => void;
  /**
   * Called with the SRP proof after Apple's challenge and *before* it is sent.
   * Throwing aborts the sign-in without Apple ever seeing the proof — which is
   * what a failed attempt, and so an account lockout, is counted from.
   */
  verifySrpProof?: (check: SrpProofCheck) => Promise<void>;
}

export interface SrpProofCheck {
  accountName: string;
  password: string;
  ephemeral: Uint8Array;
  salt: Uint8Array;
  B: Uint8Array;
  iterations: number;
  protocol: SrpProtocol;
  A: Uint8Array;
  M1: Uint8Array;
  M2: Uint8Array;
}

export class ICloudAuth {
  readonly accountName: string;
  readonly session: ICloudSession;
  /** The accountLogin / validate payload: dsInfo, webservices, hsaTrustedBrowser… */
  data: Json = {};
  readonly params: Record<string, string>;

  private readonly idmsa: string;
  private readonly authEndpoint: string;
  private readonly setupEndpoint: string;
  private readonly bridge: TrustedDeviceBridge;
  private readonly diagnostic: (message: string) => void;
  private readonly verifySrpProof: ((check: SrpProofCheck) => Promise<void>) | undefined;

  private authData: Json = {};
  private boot: Hsa2BootContext | null = null;
  private bridgeState: BridgeState | null = null;
  private delivery: DeliveryMethod = "unknown";
  private deliveryNotice: string | undefined;
  private mfaPending = false;
  private pcsChecked = false;

  private constructor(options: ICloudAuthOptions, session: ICloudSession) {
    const cn = options.chinaMainland ? ".cn" : "";
    this.accountName = options.accountName;
    this.idmsa = `https://idmsa.apple.com${cn}`;
    this.authEndpoint = `${this.idmsa}/appleauth/auth`;
    this.setupEndpoint = `https://setup.icloud.com${cn}/setup/ws/1`;
    this.session = session;
    this.bridge = new TrustedDeviceBridge(options.bridge);
    this.diagnostic = options.onDiagnostic ?? (() => undefined);
    this.verifySrpProof = options.verifySrpProof;
    if (!session.data.client_id) session.data.client_id = randomUUID().toLowerCase();
    this.params = { ...PARAMS, clientId: session.data.client_id };
  }

  static async open(options: ICloudAuthOptions): Promise<ICloudAuth> {
    const persisted = await options.store.load();
    const cn = options.chinaMainland ? ".cn" : "";
    const session = new ICloudSession(
      options.accountName,
      options.transport ?? nodeTransport(),
      options.store,
      persisted,
      `https://www.icloud.com${cn}`,
    );
    return new ICloudAuth(options, session);
  }

  // ── state ──────────────────────────────────────────────────────────────────

  get isTrustedSession(): boolean {
    return this.data.hsaTrustedBrowser === true;
  }

  get requires2fa(): boolean {
    const hsaVersion = (this.data.dsInfo as Json | undefined)?.hsaVersion;
    return (
      (this.data.hsaChallengeRequired === true || !this.isTrustedSession || this.mfaPending) &&
      hsaVersion === 2
    );
  }

  get deliveryMethod(): DeliveryMethod {
    if (this.delivery !== "unknown") return this.delivery;
    if (this.boot && supportsBridge(this.boot)) return "trusted_device";
    if (this.twoFactorMode() === "sms") return "sms";
    return "unknown";
  }

  /** A sentence telling the user which code to type — Apple often sends two. */
  get deliveryDescription(): string | undefined {
    if (this.delivery === "sms") {
      const where = this.trustedPhone()?.obfuscatedNumber;
      return (
        `Apple sent a code by SMS${where ? ` to ${where}` : ""}. Type the code from the text ` +
        "message; if a prompt also appeared on one of your devices, ignore it."
      );
    }
    if (this.delivery === "trusted_device") {
      return "Apple sent a prompt to your trusted devices. Allow it, then type the code it shows.";
    }
    return this.deliveryNotice;
  }

  get canUseSms(): boolean {
    return this.trustedPhone() !== undefined;
  }

  /** The webservice URL for a service key (e.g. "drivews"), once signed in. */
  webserviceUrl(key: string): string {
    const ws = (this.data.webservices as Record<string, { url?: string }> | undefined)?.[key];
    if (!ws?.url) throw new ApiError(`iCloud service not available: ${key}`);
    return ws.url;
  }

  private updateState(): void {
    const dsid = (this.data.dsInfo as Json | undefined)?.dsid;
    if (dsid !== undefined) this.params.dsid = String(dsid);
  }

  // ── sign-in ────────────────────────────────────────────────────────────────

  /**
   * Re-establish a session from stored tokens alone. Never sends the password
   * and never triggers 2FA. Returns false when a real sign-in is needed.
   */
  async resume(): Promise<boolean> {
    if (!this.session.data.session_token) return false;
    try {
      if (this.session.cookies.get("X-APPLE-WEBAUTH-TOKEN")) {
        const res = await this.session.request("POST", `${this.setupEndpoint}/validate`, { body: "null" });
        this.data = responseJson<Json>(res);
        this.updateState();
        if (this.isTrustedSession) return true;
      }
    } catch (e) {
      if (!(e instanceof ICloudError)) throw e;
    }
    try {
      await this.accountLogin();
      return this.isTrustedSession;
    } catch (e) {
      if (e instanceof ICloudError) return false;
      throw e;
    }
  }

  /**
   * Full sign-in with the password. Resolves "needs-2fa" when Apple wants a
   * second factor; call requestCode() only once the user is ready to type it.
   */
  async signIn(password: string): Promise<SignInResult> {
    if (await this.resume()) return { status: "signed-in" };

    await this.srpSignIn(password);
    try {
      await this.accountLogin();
    } catch (e) {
      if (e instanceof TwoFactorRequiredError) {
        this.mfaPending = true;
        return { status: "needs-2fa" };
      }
      // Apple normally sends a session token with its 409; if it did not, the
      // challenge is still pending and the token arrives with 2sv/trust.
      if (e instanceof FailedLoginError && this.mfaPending) return { status: "needs-2fa" };
      throw e;
    }
    if (!this.isTrustedSession || this.mfaPending) {
      this.mfaPending = true;
      return { status: "needs-2fa" };
    }
    return { status: "signed-in" };
  }

  private authHeaders(overrides: Record<string, string> = {}): Record<string, string> {
    const h: Record<string, string> = {
      ...AUTH_HEADERS,
      Referer: this.idmsa,
      "X-Apple-OAuth-State": this.session.data.client_id!,
      "X-Apple-Frame-Id": this.session.data.client_id!,
    };
    if (this.session.data.scnt) h.scnt = this.session.data.scnt;
    if (this.session.data.session_id) h["X-Apple-ID-Session-Id"] = this.session.data.session_id;
    if (this.session.data.auth_attributes) h["X-Apple-Auth-Attributes"] = this.session.data.auth_attributes;
    return { ...h, ...overrides };
  }

  private async srpSignIn(password: string): Promise<void> {
    const headers = this.authHeaders();
    await this.session.request("GET", `${this.authEndpoint}/authorize/signin`, {
      params: {
        frame_id: headers["X-Apple-OAuth-State"],
        skVersion: "7",
        iframeid: headers["X-Apple-OAuth-State"],
        client_id: headers["X-Apple-Widget-Key"],
        response_type: headers["X-Apple-OAuth-Response-Type"],
        redirect_uri: headers["X-Apple-OAuth-Redirect-URI"],
        response_mode: headers["X-Apple-OAuth-Response-Mode"],
        state: headers["X-Apple-OAuth-State"],
        authVersion: "latest",
      },
    });

    const client = new SrpClient(this.accountName);
    let init: Json;
    try {
      const res = await this.session.request("POST", `${this.authEndpoint}/signin/init`, {
        json: { a: b64encode(client.publicKey), accountName: this.accountName, protocols: SRP_PROTOCOLS },
        headers: this.authHeaders(),
      });
      init = responseJson<Json>(res);
    } catch (e) {
      if (e instanceof ICloudError) throw new FailedLoginError(`failed to start sign-in: ${e.message}`);
      throw e;
    }

    const protocol = init.protocol as SrpProtocol;
    if (!SRP_PROTOCOLS.includes(protocol)) throw new FailedLoginError(`unsupported SRP protocol: ${protocol}`);
    const salt = b64decode(String(init.salt));
    this.diagnostic(
      `srp: protocol=${protocol} iterations=${String(init.iteration)} salt=${salt.length}B ` +
        `leadingZero=${salt[0] === 0} trustToken=${this.session.data.trust_token ? "sent" : "none"}`,
    );
    const challenge = {
      salt,
      B: b64decode(String(init.b)),
      iterations: Number(init.iteration),
      protocol,
    };
    const proof = client.processChallenge(password, challenge);
    await this.verifySrpProof?.({
      accountName: this.accountName,
      password,
      ephemeral: client.ephemeral,
      ...challenge,
      A: client.publicKey,
      M1: proof.M1,
      M2: proof.M2,
    });

    const body: Json = {
      accountName: this.accountName,
      c: init.c,
      m1: b64encode(proof.M1),
      m2: b64encode(proof.M2),
      rememberMe: true,
      trustTokens: this.session.data.trust_token ? [this.session.data.trust_token] : [],
    };
    try {
      await this.session.request("POST", `${this.authEndpoint}/signin/complete`, {
        params: { isRememberMeEnabled: "true" },
        json: body,
        headers: this.authHeaders(),
      });
    } catch (e) {
      if (e instanceof TwoFactorRequiredError) {
        // Load the challenge options, but do NOT request a code: the user may
        // not be at their device, and every request supersedes the last code.
        this.mfaPending = true;
        await this.loadMfaOptions();
        return;
      }
      if (e instanceof ApiError) {
        throw new FailedLoginError(
          `Apple rejected the sign-in (HTTP ${e.status ?? "?"}, code ${e.code ?? "none"}): ${e.message}`,
        );
      }
      throw e;
    }
  }

  private async accountLogin(): Promise<void> {
    if (!this.session.data.session_token) throw new FailedLoginError("no session token available");
    const login = {
      accountCountryCode: this.session.data.account_country,
      dsWebAuthToken: this.session.data.session_token,
      extended_login: true,
      trustToken: this.session.data.trust_token ?? "",
    };
    let res;
    try {
      res = await this.session.request("POST", `${this.setupEndpoint}/accountLogin`, { json: login });
    } catch (e) {
      if (e instanceof ApiError || e instanceof AuthRequiredError) {
        throw new FailedLoginError(`session token was not accepted: ${e.message}`);
      }
      throw e;
    }
    this.data = responseJson<Json>(res);
    this.updateState();
    if (this.data.termsUpdateNeeded) {
      throw new TermsAcceptanceRequiredError(
        "Apple requires you to accept updated iCloud terms. Sign in at https://www.icloud.com once, then retry.",
      );
    }
    if (!this.isTrustedSession) throw new TwoFactorRequiredError("session is not trusted yet");
    this.mfaPending = false;
    this.authData = {};
    this.boot = null;
    this.closeBridge();
    this.delivery = "unknown";
  }

  // ── two-factor ─────────────────────────────────────────────────────────────

  private async loadMfaOptions(): Promise<void> {
    // The HTML shell carries the bridge bootstrap; asking for JSON collapses the
    // response to the SMS-only shape.
    const res = await this.session.requestRaw("GET", this.authEndpoint, {
      headers: this.authHeaders({ Accept: "text/html" }),
    });
    const options: Json = {};
    let boot: Hsa2BootContext;
    let parsed: unknown;
    try {
      parsed = JSON.parse(responseText(res));
    } catch {
      parsed = undefined;
    }
    if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
      Object.assign(options, parsed);
      boot = bootContextFromAuthOptions(options);
    } else {
      boot = parseBootArgsHtml(responseText(res));
    }
    Object.assign(options, bootContextAsAuthData(boot));
    this.authData = options;
    this.boot = boot;
    this.closeBridge();
    this.delivery = "unknown";
    this.deliveryNotice = undefined;
  }

  private trustedPhone(): TrustedPhone | undefined {
    const direct = asPhone(this.authData.trustedPhoneNumber);
    if (direct) return direct;
    const pnv = this.authData.phoneNumberVerification as Json | undefined;
    if (!pnv) return undefined;
    return (
      asPhone(pnv.trustedPhoneNumber) ??
      (Array.isArray(pnv.trustedPhoneNumbers) ? pnv.trustedPhoneNumbers.map(asPhone).find(Boolean) : undefined)
    );
  }

  private twoFactorMode(): string | undefined {
    if (typeof this.authData.mode === "string") return this.authData.mode;
    return this.trustedPhone()?.pushMode;
  }

  private closeBridge(): void {
    this.bridge.close(this.bridgeState);
    this.bridgeState = null;
  }

  /**
   * Ask Apple to deliver a code: the trusted-device prompt when the account
   * supports it (falling back to SMS if that fails), else SMS.
   */
  async requestCode(options: { preferSms?: boolean } = {}): Promise<DeliveryMethod> {
    if (!this.mfaPending) throw new ICloudError("no two-factor challenge is pending");
    if (!this.boot) await this.loadMfaOptions();
    this.closeBridge();

    if (!options.preferSms && this.boot && supportsBridge(this.boot)) {
      try {
        this.bridgeState = await this.bridge.start({
          session: this.session,
          authEndpoint: this.authEndpoint,
          headers: this.authHeaders({ Accept: "application/json" }),
          boot: this.boot,
          userAgent: USER_AGENT,
        });
        this.delivery = "trusted_device";
        this.deliveryNotice = undefined;
        return this.delivery;
      } catch (e) {
        if (!(e instanceof TrustedDevicePromptError) || !this.canUseSms) throw e;
        this.deliveryNotice = "The trusted-device prompt failed, so Apple is sending an SMS instead.";
      }
    }
    await this.requestSms();
    return this.delivery;
  }

  private async requestSms(): Promise<void> {
    const phone = this.trustedPhone();
    if (!phone) throw new NoTrustedPhoneNumberError("Apple reported no trusted phone number on this account");
    await this.session.request("PUT", `${this.authEndpoint}/verify/phone`, {
      json: { phoneNumber: phonePayload(phone), mode: "sms" },
      headers: this.authHeaders({ Accept: "application/json" }),
    });
    this.closeBridge();
    this.delivery = "sms";
  }

  /** Validate a code and trust the session. Resolves false for a wrong code. */
  async submitCode(code: string): Promise<boolean> {
    const trimmed = code.replace(/\s+/g, "");
    if (!/^\d{6}$/.test(trimmed)) return false;
    const state = this.bridgeState;
    try {
      if (this.deliveryMethod === "sms") {
        const phone = this.trustedPhone();
        if (!phone) throw new NoTrustedPhoneNumberError("no trusted phone number");
        await this.session.request("POST", `${this.authEndpoint}/verify/phone/securitycode`, {
          json: { phoneNumber: phonePayload(phone), securityCode: { code: trimmed }, mode: phone.pushMode ?? "sms" },
          headers: this.authHeaders({ Accept: "application/json, plain/text" }),
        });
      } else if (state && !usesLegacyVerifier(state)) {
        const ok = await this.bridge.validateCode({
          session: this.session,
          authEndpoint: this.authEndpoint,
          headers: this.authHeaders({ Accept: "application/json" }),
          state,
          code: trimmed,
        });
        if (!ok) return false;
      } else {
        await this.session.request("POST", `${this.authEndpoint}/verify/trusteddevice/securitycode`, {
          json: { securityCode: { code: trimmed } },
          headers: this.authHeaders({ Accept: "application/json" }),
        });
      }
    } catch (e) {
      if (e instanceof TrustedDeviceVerificationError) throw e;
      if (e instanceof ApiError) return false; // Apple's answer to a wrong code
      throw e;
    } finally {
      if (state) this.closeBridge();
    }
    return this.trustSession();
  }

  /** Ask Apple to remember this session, so the next sign-in needs no code. */
  async trustSession(): Promise<boolean> {
    try {
      await this.session.request("GET", `${this.authEndpoint}/2sv/trust`, { headers: this.authHeaders() });
      this.mfaPending = false;
      await this.accountLogin();
      return true;
    } catch (e) {
      if (e instanceof ICloudError) return false;
      throw e;
    }
  }

  /** Abandon a pending challenge, closing the push connection if one is open. */
  cancelChallenge(): void {
    this.closeBridge();
  }

  // ── service access ─────────────────────────────────────────────────────────

  /**
   * Ask for iCloud Drive web access when the account needs device consent
   * (accounts with Advanced Data Protection off but web access gated).
   *
   * Done once per session, not on every Drive access: icloudlite repeated it
   * for every `api.drive`, each time up to 100 seconds of polling.
   */
  async ensureDriveAccess(sleep = (ms: number) => new Promise((r) => setTimeout(r, ms))): Promise<void> {
    if (this.pcsChecked) return;
    const state = async () =>
      responseJson<Json>(
        await this.session.request("POST", `${this.setupEndpoint}/requestWebAccessState`, { params: this.params }),
      );
    let status = await state();
    if (!status.isICDRSDisabled) {
      this.pcsChecked = true;
      return;
    }
    if (status.isDeviceConsentedForPCS === false) {
      const res = responseJson<Json>(
        await this.session.request("POST", `${this.setupEndpoint}/enableDeviceConsentForPCS`, { params: this.params }),
      );
      if (!res.isDeviceConsentNotificationSent) throw new ApiError("unable to request iCloud Drive web access");
    }
    for (let i = 0; i < 10 && status.isDeviceConsentedForPCS === false; i++) {
      await sleep(5000);
      status = await state();
    }
    for (let attempt = 0; attempt < 10; attempt++) {
      const res = responseJson<Json>(
        await this.session.request("POST", `${this.setupEndpoint}/requestPCS`, {
          params: this.params,
          json: { appName: "iclouddrive", derivedFromUserAction: attempt === 0 },
        }),
      );
      if (res.status === "success") {
        this.pcsChecked = true;
        return;
      }
      if (
        res.message === "Requested the device to upload cookies." ||
        res.message === "Cookies not available yet on server."
      ) {
        await sleep(5000);
        continue;
      }
      throw new ApiError(`unable to get iCloud Drive web access: ${String(res.message)}`);
    }
    throw new ApiError("timed out waiting for iCloud Drive web access");
  }

  /** Forget the session locally. */
  async signOut(): Promise<void> {
    this.closeBridge();
    this.data = {};
    this.authData = {};
    this.boot = null;
    this.mfaPending = false;
    this.pcsChecked = false;
    delete this.params.dsid;
    await this.session.clear();
  }
}
