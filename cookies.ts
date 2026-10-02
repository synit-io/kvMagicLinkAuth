import {
  DEFAULT_MAGIC_LINK_VERIFY_PATH,
  DEFAULT_SESSION_COOKIE_TTL_DAYS,
} from "./defaults.ts";

/** Configuration for session and magic-link binding cookies. */
export interface MagicLinkCookieConfig {
  /** Cookie name used for persisted login sessions. Defaults to `"__Host-session"`. */
  sessionCookieName?: string;
  /** Cookie name used to bind the verification request to the issuing browser. Defaults to `"__Host-ml-bind"`. */
  bindingCookieName?: string;
  /** Adds the `Secure` attribute. Enabled by default; set to `false` only for local HTTP development. */
  secure?: boolean;
  /** Same-site policy. Defaults to `"Lax"` so emailed links can carry binding and session cookies. */
  sameSite?: "Lax" | "Strict";
  /**
   * Session cookie lifetime in seconds. Use `DenoKvMagicLinkAuth.sessionCookieMaxAgeSeconds()`
   * so the cookie expires with the session.
   */
  maxAgeSeconds?: number;
  /**
   * Session cookie lifetime in days when `maxAgeSeconds` is omitted.
   * Defaults to the effective session lifetime of 7 days.
   */
  sessionAbsoluteTtlDays?: number;
  /**
   * Path for a non-`__Host-` binding cookie. Must be the verify pathname.
   * `__Host-` cookies always use `Path=/`.
   */
  bindingCookiePath?: string;
}

const COOKIE_NAME_PATTERN = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;
const DEFAULT_SESSION_COOKIE_NAME = "__Host-session";
const DEFAULT_BINDING_COOKIE_NAME = "__Host-ml-bind";

function assertCookieName(
  name: string,
  label: string,
  secure: boolean,
): string {
  if (!COOKIE_NAME_PATTERN.test(name)) {
    throw new Error(`Invalid ${label} cookie name.`);
  }
  if (/^__(?:Host|Secure)-/i.test(name) && !secure) {
    throw new Error(
      "Cookie names starting with __Host- or __Secure- require secure: true.",
    );
  }
  return name;
}

function assertPositiveInteger(value: number, label: string): number {
  if (!Number.isInteger(value) || value <= 0) {
    throw new Error(`${label} must be a positive integer.`);
  }
  return value;
}

function cookiePath(path: string): string {
  if (
    !path.startsWith("/") || path.startsWith("//") || /[\s?#\\]/.test(path)
  ) {
    throw new Error(
      "bindingCookiePath must be an absolute path without a query or hash.",
    );
  }
  return path;
}

function sessionMaxAgeSeconds(config: MagicLinkCookieConfig): number {
  if (config.maxAgeSeconds !== undefined) {
    return assertPositiveInteger(config.maxAgeSeconds, "maxAgeSeconds");
  }
  const days = assertPositiveInteger(
    config.sessionAbsoluteTtlDays ?? DEFAULT_SESSION_COOKIE_TTL_DAYS,
    "sessionAbsoluteTtlDays",
  );
  return days * 24 * 60 * 60;
}

function cookieBase(
  maxAgeSeconds: number,
  secure: boolean,
  sameSite: "Lax" | "Strict",
): string {
  const parts = [
    "Path=/",
    "HttpOnly",
    `SameSite=${sameSite}`,
    `Max-Age=${maxAgeSeconds}`,
  ];
  if (secure) parts.push("Secure");
  return parts.join("; ");
}

function bindingCookieBase(
  maxAgeSeconds: number,
  secure: boolean,
  sameSite: "Lax" | "Strict",
  cookieName: string,
  bindingCookiePath: string | undefined,
): string {
  const path = /^__Host-/i.test(cookieName)
    ? "/"
    : cookiePath(bindingCookiePath ?? DEFAULT_MAGIC_LINK_VERIFY_PATH);
  const parts = [
    `Path=${path}`,
    "HttpOnly",
    `SameSite=${sameSite}`,
    `Max-Age=${maxAgeSeconds}`,
  ];
  if (secure) parts.push("Secure");
  return parts.join("; ");
}

/** Reads a cookie value from the request headers. Returns `null` if the cookie is missing, duplicated, or malformed. */
export function getCookie(headers: Headers, name: string): string | null {
  const raw = headers.get("cookie");
  if (!raw) return null;
  const chunks = raw.split(";");
  let value: string | null = null;
  for (const chunk of chunks) {
    const [key, ...rest] = chunk.trim().split("=");
    if (key !== name) continue;
    // Two cookies with the same name are ambiguous. Fail closed.
    if (value !== null) return null;
    try {
      value = decodeURIComponent(rest.join("="));
    } catch {
      return null;
    }
  }
  return value;
}

/** Builds a `Set-Cookie` header value for the authenticated session cookie. */
export function buildSessionSetCookie(
  sessionId: string,
  config: MagicLinkCookieConfig = {},
): string {
  const secure = config.secure ?? true;
  const cookieName = assertCookieName(
    config.sessionCookieName ?? DEFAULT_SESSION_COOKIE_NAME,
    "session",
    secure,
  );
  return `${cookieName}=${encodeURIComponent(sessionId)}; ${
    cookieBase(
      sessionMaxAgeSeconds(config),
      secure,
      config.sameSite ?? "Lax",
    )
  }`;
}

/** Builds a `Set-Cookie` header value that clears the authenticated session cookie. */
export function buildSessionClearCookie(
  config: MagicLinkCookieConfig = {},
): string {
  const secure = config.secure ?? true;
  const cookieName = assertCookieName(
    config.sessionCookieName ?? DEFAULT_SESSION_COOKIE_NAME,
    "session",
    secure,
  );
  return `${cookieName}=; ${
    cookieBase(0, secure, config.sameSite ?? "Lax")
  }; Expires=Thu, 01 Jan 1970 00:00:00 GMT`;
}

/** Builds a `Set-Cookie` header value for the short-lived magic-link binding cookie. */
export function buildBindingSetCookie(
  value: string,
  maxAgeSeconds: number,
  config: MagicLinkCookieConfig = {},
): string {
  const secure = config.secure ?? true;
  const cookieName = assertCookieName(
    config.bindingCookieName ?? DEFAULT_BINDING_COOKIE_NAME,
    "binding",
    secure,
  );
  return `${cookieName}=${encodeURIComponent(value)}; ${
    bindingCookieBase(
      assertPositiveInteger(maxAgeSeconds, "maxAgeSeconds"),
      secure,
      config.sameSite ?? "Lax",
      cookieName,
      config.bindingCookiePath,
    )
  }`;
}

/** Builds a `Set-Cookie` header value that clears the magic-link binding cookie. */
export function buildBindingClearCookie(
  config: MagicLinkCookieConfig = {},
): string {
  const secure = config.secure ?? true;
  const cookieName = assertCookieName(
    config.bindingCookieName ?? DEFAULT_BINDING_COOKIE_NAME,
    "binding",
    secure,
  );
  return `${cookieName}=; ${
    bindingCookieBase(
      0,
      secure,
      config.sameSite ?? "Lax",
      cookieName,
      config.bindingCookiePath,
    )
  }; Expires=Thu, 01 Jan 1970 00:00:00 GMT`;
}

/**
 * Headers for a magic-link verification response.
 * `Referrer-Policy: no-referrer` keeps the one-time token out of the next request.
 */
export function buildVerifyResponseHeaders(
  location: string,
  cookies: readonly string[],
): Headers {
  if (
    /[\r\n]/.test(location) || cookies.some((cookie) => /[\r\n]/.test(cookie))
  ) {
    throw new Error("Header values must not contain line breaks.");
  }
  const headers = new Headers();
  headers.set("location", location);
  headers.set("referrer-policy", "no-referrer");
  headers.set("cache-control", "no-store");
  for (const cookie of cookies) {
    headers.append("set-cookie", cookie);
  }
  return headers;
}
