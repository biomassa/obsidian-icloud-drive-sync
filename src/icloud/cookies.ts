/**
 * A small RFC 6265 cookie jar, sufficient for Apple's auth and iCloud hosts.
 *
 * Deliberately minimal: no public-suffix list, because every cookie here comes
 * from *.apple.com or *.icloud.com, and a Domain attribute that does not match
 * the responding host is simply refused. The jar serializes to plain JSON so it
 * can live in Obsidian's secret storage alongside the session tokens.
 */

export interface StoredCookie {
  name: string;
  value: string;
  /** Lowercase, no leading dot. */
  domain: string;
  /** True when the cookie had no Domain attribute: exact host match only. */
  hostOnly: boolean;
  path: string;
  secure: boolean;
  /** Milliseconds since the epoch, or null for a session cookie. */
  expires: number | null;
}

function defaultPath(url: URL): string {
  const p = url.pathname;
  if (!p.startsWith("/") || p.lastIndexOf("/") === 0) return "/";
  return p.slice(0, p.lastIndexOf("/"));
}

function domainMatches(host: string, domain: string): boolean {
  return host === domain || host.endsWith("." + domain);
}

function pathMatches(requestPath: string, cookiePath: string): boolean {
  if (requestPath === cookiePath) return true;
  if (!requestPath.startsWith(cookiePath)) return false;
  return cookiePath.endsWith("/") || requestPath[cookiePath.length] === "/";
}

export class CookieJar {
  private cookies: StoredCookie[] = [];
  private readonly now: () => number;

  constructor(now: () => number = Date.now) {
    this.now = now;
  }

  /** Parse one Set-Cookie header value received from `url`. */
  setCookie(header: string, url: URL): void {
    const [pair = "", ...attrs] = header.split(";");
    const eq = pair.indexOf("=");
    if (eq <= 0) return;
    const name = pair.slice(0, eq).trim();
    const value = pair.slice(eq + 1).trim();
    const host = url.hostname.toLowerCase();

    let domain = host;
    let hostOnly = true;
    let path = defaultPath(url);
    let secure = false;
    let expires: number | null = null;
    let maxAge: number | null = null;

    for (const attr of attrs) {
      const i = attr.indexOf("=");
      const key = (i < 0 ? attr : attr.slice(0, i)).trim().toLowerCase();
      const val = i < 0 ? "" : attr.slice(i + 1).trim();
      if (key === "domain" && val) {
        const d = val.replace(/^\./, "").toLowerCase();
        if (!domainMatches(host, d)) return; // a host may not set cookies for another
        domain = d;
        hostOnly = false;
      } else if (key === "path" && val.startsWith("/")) {
        path = val;
      } else if (key === "secure") {
        secure = true;
      } else if (key === "expires") {
        const t = Date.parse(val);
        if (!Number.isNaN(t)) expires = t;
      } else if (key === "max-age" && /^-?\d+$/.test(val)) {
        maxAge = Number(val);
      }
    }
    if (maxAge !== null) expires = maxAge <= 0 ? 0 : this.now() + maxAge * 1000;

    this.cookies = this.cookies.filter(
      (c) => !(c.name === name && c.domain === domain && c.path === path),
    );
    if (expires !== null && expires <= this.now()) return; // deletion
    this.cookies.push({ name, value, domain, hostOnly, path, secure, expires });
  }

  /** The Cookie header value for a request to `url`, or "" when none apply. */
  cookieHeader(url: URL): string {
    const host = url.hostname.toLowerCase();
    const now = this.now();
    this.cookies = this.cookies.filter((c) => c.expires === null || c.expires > now);
    return this.cookies
      .filter(
        (c) =>
          (c.hostOnly ? host === c.domain : domainMatches(host, c.domain)) &&
          pathMatches(url.pathname || "/", c.path) &&
          (!c.secure || url.protocol === "https:"),
      )
      // RFC 6265 5.4: longer paths first.
      .sort((a, b) => b.path.length - a.path.length)
      .map((c) => `${c.name}=${c.value}`)
      .join("; ");
  }

  /** The value of the first live cookie with this name, on any domain. */
  get(name: string): string | undefined {
    const now = this.now();
    return this.cookies.find((c) => c.name === name && (c.expires === null || c.expires > now))
      ?.value;
  }

  remove(name: string): void {
    this.cookies = this.cookies.filter((c) => c.name !== name);
  }

  clear(): void {
    this.cookies = [];
  }

  toJSON(): StoredCookie[] {
    return this.cookies.map((c) => ({ ...c }));
  }

  static fromJSON(data: unknown, now: () => number = Date.now): CookieJar {
    const jar = new CookieJar(now);
    if (Array.isArray(data)) {
      for (const c of data) {
        if (c && typeof c.name === "string" && typeof c.value === "string" && typeof c.domain === "string") {
          jar.cookies.push({
            name: c.name,
            value: c.value,
            domain: c.domain,
            hostOnly: Boolean(c.hostOnly),
            path: typeof c.path === "string" ? c.path : "/",
            secure: Boolean(c.secure),
            expires: typeof c.expires === "number" ? c.expires : null,
          });
        }
      }
    }
    return jar;
  }
}
