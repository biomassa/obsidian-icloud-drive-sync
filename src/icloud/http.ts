/**
 * HTTP for the iCloud client, on Node's `https` rather than `fetch`.
 *
 * Inside Obsidian `fetch` is Chromium's: it applies CORS, hides Set-Cookie and
 * will not send the Origin header Apple checks. Obsidian's own `requestUrl`
 * does not carry cookies across redirects. Node's `https` is available to
 * desktop plugins and gives full control, which is why the plugin is
 * desktop-only.
 *
 * Every request has a timeout. An unbounded call in a long-running sync loop
 * wedges it with no recovery short of a restart (see obsisync's session.py).
 */
import { request as httpsRequest } from "node:https";
import * as zlib from "node:zlib";
import { gunzipSync, inflateSync, brotliDecompressSync } from "node:zlib";

// zstd arrived in Node 22.15; offer it only where it can be decoded.
const zstdDecompress = (zlib as { zstdDecompressSync?: (b: Buffer) => Buffer }).zstdDecompressSync;
const ACCEPT_ENCODING = zstdDecompress ? "gzip, deflate, zstd" : "gzip, deflate";

import type { CookieJar } from "./cookies.ts";

export interface HttpRequest {
  method: string;
  url: string;
  headers: Record<string, string>;
  body?: Uint8Array;
}

export interface HttpResponse {
  status: number;
  statusText: string;
  /** Lowercased names. `set-cookie` is joined with "\n" by the transport. */
  headers: Record<string, string>;
  setCookies: string[];
  body: Uint8Array;
  url: string;
}

/** The single network primitive; tests substitute a fake. */
export type Transport = (req: HttpRequest) => Promise<HttpResponse>;

export class NetworkError extends Error {
  override readonly cause?: unknown;
  constructor(message: string, cause?: unknown) {
    super(message);
    this.cause = cause;
  }
}

export interface NodeTransportOptions {
  /** Milliseconds to establish a connection. */
  connectTimeoutMs?: number;
  /** Milliseconds a socket may sit idle mid-response. Bounds one read, not a whole transfer. */
  idleTimeoutMs?: number;
  /** 4 forces IPv4; 0 lets Node race both families (Happy Eyeballs). */
  family?: 0 | 4;
}

export function nodeTransport(options: NodeTransportOptions = {}): Transport {
  const connectTimeout = options.connectTimeoutMs ?? 10_000;
  const idleTimeout = options.idleTimeoutMs ?? 60_000;
  return (req) =>
    new Promise<HttpResponse>((resolve, reject) => {
      const url = new URL(req.url);
      const r = httpsRequest(
        url,
        {
          method: req.method,
          headers: req.headers,
          // Without a family, Node races IPv6 and IPv4 (autoSelectFamily is
          // on by default), so a dead IPv6 route cannot stall a request the way
          // it stalled Python's requests.
          ...(options.family ? { family: options.family } : {}),
        },
        (res) => {
          clearTimeout(connectTimer);
          const chunks: Buffer[] = [];
          res.on("data", (c: Buffer) => chunks.push(c));
          res.on("error", (e) => reject(new NetworkError(`response error: ${e.message}`, e)));
          res.on("end", () => {
            let body: Buffer = Buffer.concat(chunks);
            try {
              const enc = String(res.headers["content-encoding"] ?? "").toLowerCase();
              if (enc === "gzip") body = gunzipSync(body);
              else if (enc === "deflate") body = inflateSync(body);
              else if (enc === "br") body = brotliDecompressSync(body);
              else if (enc === "zstd" && zstdDecompress) body = zstdDecompress(body);
            } catch (e) {
              reject(new NetworkError("could not decode response body", e));
              return;
            }
            const headers: Record<string, string> = {};
            for (const [k, v] of Object.entries(res.headers)) {
              if (v === undefined || k === "set-cookie") continue;
              headers[k] = Array.isArray(v) ? v.join(", ") : v;
            }
            resolve({
              status: res.statusCode ?? 0,
              statusText: res.statusMessage ?? "",
              headers,
              setCookies: res.headers["set-cookie"] ?? [],
              body: new Uint8Array(body),
              url: req.url,
            });
          });
        },
      );
      const connectTimer = setTimeout(() => {
        r.destroy(new NetworkError(`connection to ${url.hostname} timed out`));
      }, connectTimeout);
      r.on("socket", (s) => {
        // A keep-alive socket from the agent's pool is already connected and
        // never emits secureConnect; leaving the timer armed would kill any
        // request on it that runs longer than the connect timeout.
        if (!s.connecting) clearTimeout(connectTimer);
        else s.once("secureConnect", () => clearTimeout(connectTimer));
      });
      r.setTimeout(idleTimeout, () => {
        r.destroy(new NetworkError(`request to ${url.hostname} stalled for ${idleTimeout / 1000}s`));
      });
      r.on("error", (e) => {
        clearTimeout(connectTimer);
        reject(e instanceof NetworkError ? e : new NetworkError(`request to ${url.hostname} failed: ${e.message}`, e));
      });
      if (req.body) r.write(req.body);
      r.end();
    });
}

/**
 * JSON exactly as Python's `json.dumps` writes it with default settings, which
 * is what python-requests sends for `json=`: ", " and ": " separators, and
 * non-ASCII escaped as \uXXXX. Apple's servers parse either form, but
 * matching the client that works byte for byte removes one variable when a
 * sign-in is rejected.
 */
export function pythonJson(value: unknown): string {
  if (value === null || value === undefined) return "null";
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new TypeError("non-finite number in JSON body");
    return String(value);
  }
  if (typeof value === "string") {
    return JSON.stringify(value).replace(
      /[\u007f-\uffff]/g,
      (ch) => "\\u" + ch.charCodeAt(0).toString(16).padStart(4, "0"),
    );
  }
  if (Array.isArray(value)) return "[" + value.map(pythonJson).join(", ") + "]";
  if (typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>).filter(([, v]) => v !== undefined);
    return "{" + entries.map(([k, v]) => `${pythonJson(k)}: ${pythonJson(v)}`).join(", ") + "}";
  }
  throw new TypeError(`cannot serialize ${typeof value} to JSON`);
}

export interface RequestOptions {
  params?: Record<string, string | number | boolean | undefined>;
  headers?: Record<string, string>;
  json?: unknown;
  body?: Uint8Array | string;
  /** Follow redirects (default true), carrying cookies across each hop. */
  followRedirects?: boolean;
}

const REDIRECTS = new Set([301, 302, 303, 307, 308]);
const MAX_REDIRECTS = 5;

/** A cookie-carrying client with default headers, over any Transport. */
export class HttpClient {
  readonly jar: CookieJar;
  readonly defaultHeaders: Record<string, string>;
  private readonly transport: Transport;

  constructor(transport: Transport, jar: CookieJar, defaultHeaders: Record<string, string> = {}) {
    this.transport = transport;
    this.jar = jar;
    this.defaultHeaders = defaultHeaders;
  }

  async request(method: string, url: string, opts: RequestOptions = {}): Promise<HttpResponse> {
    const target = new URL(url);
    for (const [k, v] of Object.entries(opts.params ?? {})) {
      if (v !== undefined) target.searchParams.set(k, String(v));
    }

    // python-requests' default headers, in its order. Later spreads override a
    // value in place without moving it, as requests does, so the wire order
    // matches the client Apple accepts today.
    const headers: Record<string, string> = {
      "User-Agent": this.defaultHeaders["User-Agent"] ?? "icloud-drive-sync",
      "Accept-Encoding": ACCEPT_ENCODING,
      Accept: "*/*",
      Connection: "keep-alive",
      ...this.defaultHeaders,
      ...opts.headers,
    };
    let body: Uint8Array | undefined;
    if (opts.json !== undefined) {
      body = new TextEncoder().encode(pythonJson(opts.json));
      if (!hasHeader(headers, "content-type")) headers["Content-Type"] = "application/json";
    } else if (typeof opts.body === "string") {
      body = new TextEncoder().encode(opts.body);
    } else {
      body = opts.body;
    }

    let currentMethod = method.toUpperCase();
    let currentUrl = target;
    for (let hop = 0; ; hop++) {
      const cookie = this.jar.cookieHeader(currentUrl);
      const hopHeaders = { ...headers };
      if (cookie) hopHeaders["Cookie"] = cookie;
      if (body) hopHeaders["Content-Length"] = String(body.length);
      else delete hopHeaders["Content-Length"];

      const res = await this.transport({
        method: currentMethod,
        url: currentUrl.toString(),
        headers: hopHeaders,
        body,
      });
      for (const sc of res.setCookies) this.jar.setCookie(sc, currentUrl);

      if (opts.followRedirects === false || !REDIRECTS.has(res.status) || !res.headers["location"]) {
        return res;
      }
      if (hop >= MAX_REDIRECTS) throw new NetworkError(`too many redirects from ${url}`);
      currentUrl = new URL(res.headers["location"], currentUrl);
      // Browsers and requests turn a redirected POST into a GET for 301-303.
      if (res.status <= 303 && currentMethod !== "GET" && currentMethod !== "HEAD") {
        currentMethod = "GET";
        body = undefined;
        for (const k of Object.keys(headers)) {
          if (k.toLowerCase() === "content-type") delete headers[k];
        }
      }
    }
  }
}

function hasHeader(headers: Record<string, string>, name: string): boolean {
  return Object.keys(headers).some((k) => k.toLowerCase() === name);
}

export function responseText(res: HttpResponse): string {
  return new TextDecoder().decode(res.body);
}

export function isJsonResponse(res: HttpResponse): boolean {
  const type = (res.headers["content-type"] ?? "").split(";")[0]!.trim();
  return type === "application/json" || type === "text/json";
}

export function responseJson<T = unknown>(res: HttpResponse): T {
  return JSON.parse(responseText(res)) as T;
}

/** multipart/form-data with one file part, as requests builds for `files={name: f}`. */
export function multipartFile(
  fieldName: string,
  fileName: string,
  data: Uint8Array,
  contentType = "application/octet-stream",
): { body: Uint8Array; contentType: string } {
  const boundary = "----icloudsync" + Math.random().toString(16).slice(2) + Date.now().toString(16);
  const esc = (s: string) => s.replace(/[\r\n"]/g, (c) => encodeURIComponent(c));
  const head = new TextEncoder().encode(
    `--${boundary}\r\n` +
      `Content-Disposition: form-data; name="${esc(fieldName)}"; filename="${esc(fileName)}"\r\n` +
      `Content-Type: ${contentType}\r\n\r\n`,
  );
  const tail = new TextEncoder().encode(`\r\n--${boundary}--\r\n`);
  const body = new Uint8Array(head.length + data.length + tail.length);
  body.set(head, 0);
  body.set(data, head.length);
  body.set(tail, head.length + data.length);
  return { body, contentType: `multipart/form-data; boundary=${boundary}` };
}
