export interface MagicLinkCookieConfig {
  sessionCookieName?: string;
  bindingCookieName?: string;
  secure?: boolean;
  sessionAbsoluteTtlDays?: number;
}

const COOKIE_NAME_PATTERN = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;

function assertCookieName(name: string, label: string): string {
  if (!COOKIE_NAME_PATTERN.test(name)) {
    throw new Error(`Invalid ${label} cookie name.`);
  }
  return name;
}

function cookieBase(maxAgeSeconds: number, secure: boolean): string {
  const parts = [
    "Path=/",
    "HttpOnly",
    "SameSite=Lax",
    `Max-Age=${maxAgeSeconds}`,
  ];
  if (secure) parts.push("Secure");
  return parts.join("; ");
}

function bindingCookieBase(maxAgeSeconds: number, secure: boolean): string {
  const parts = [
    "Path=/api/auth/magic-link/verify",
    "HttpOnly",
    "SameSite=Lax",
    `Max-Age=${maxAgeSeconds}`,
  ];
  if (secure) parts.push("Secure");
  return parts.join("; ");
}

export function getCookie(headers: Headers, name: string): string | null {
  const raw = headers.get("cookie");
  if (!raw) return null;
  const chunks = raw.split(";");
  for (const chunk of chunks) {
    const [key, ...rest] = chunk.trim().split("=");
    if (key !== name) continue;
    try {
      return decodeURIComponent(rest.join("="));
    } catch {
      return null;
    }
  }
  return null;
}

export function buildSessionSetCookie(
  sessionId: string,
  config: MagicLinkCookieConfig = {},
): string {
  const cookieName = assertCookieName(
    config.sessionCookieName ?? "session",
    "session",
  );
  const ttlDays = config.sessionAbsoluteTtlDays ?? 30;
  return `${cookieName}=${encodeURIComponent(sessionId)}; ${
    cookieBase(ttlDays * 24 * 60 * 60, Boolean(config.secure))
  }`;
}

export function buildSessionClearCookie(
  config: MagicLinkCookieConfig = {},
): string {
  const cookieName = assertCookieName(
    config.sessionCookieName ?? "session",
    "session",
  );
  return `${cookieName}=; ${
    cookieBase(0, Boolean(config.secure))
  }; Expires=Thu, 01 Jan 1970 00:00:00 GMT`;
}

export function buildBindingSetCookie(
  value: string,
  maxAgeSeconds: number,
  config: MagicLinkCookieConfig = {},
): string {
  const cookieName = assertCookieName(
    config.bindingCookieName ?? "ml_bind",
    "binding",
  );
  return `${cookieName}=${encodeURIComponent(value)}; ${
    bindingCookieBase(maxAgeSeconds, Boolean(config.secure))
  }`;
}

export function buildBindingClearCookie(
  config: MagicLinkCookieConfig = {},
): string {
  const cookieName = assertCookieName(
    config.bindingCookieName ?? "ml_bind",
    "binding",
  );
  return `${cookieName}=; ${
    bindingCookieBase(0, Boolean(config.secure))
  }; Expires=Thu, 01 Jan 1970 00:00:00 GMT`;
}
