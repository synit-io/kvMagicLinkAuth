import type {
  DenoKvMagicLinkAuthConfig,
  DenoKvMagicLinkAuthDeps,
  MagicLinkIssueInput,
  MagicLinkIssueResult,
  MagicLinkRecord,
  MagicLinkVerifyInput,
  MagicLinkVerifyResult,
  SessionRecord,
} from "./types.ts";

function normalizeEmail(email: string): string {
  return email.trim().toLowerCase();
}

function normalizeOptionalString(value?: string | null): string | null {
  if (!value) return null;
  const normalized = value.trim();
  return normalized || null;
}

function normalizeUserAgent(value?: string | null): string | null {
  const normalized = normalizeOptionalString(value)?.toLowerCase();
  return normalized || null;
}

function randomToken(bytes = 32): string {
  return btoa(
    String.fromCharCode(...crypto.getRandomValues(new Uint8Array(bytes))),
  )
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replaceAll("=", "");
}

async function sha256Hex(value: string): Promise<string> {
  const bytes = new TextEncoder().encode(value);
  const hash = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(hash)).map((b) =>
    b.toString(16).padStart(2, "0")
  ).join("");
}

function assertPositiveInteger(value: number, label: string): number {
  if (!Number.isInteger(value) || value <= 0) {
    throw new Error(`${label} must be a positive integer.`);
  }
  return value;
}

function assertAppBaseUrl(value: string): string {
  const url = new URL(value);
  if (!/^https?:$/.test(url.protocol)) {
    throw new Error("appBaseUrl must use http or https.");
  }
  return url.toString().replace(/\/$/, "");
}

function sanitizeRedirectTo(
  value: string | undefined,
  appBaseUrl: string,
): string {
  const fallback = "/admin/dashboard";
  if (!value) return fallback;
  const trimmed = value.trim();
  if (!trimmed) return fallback;

  try {
    const appUrl = new URL(appBaseUrl);
    const resolved = new URL(trimmed, appUrl);
    if (resolved.origin !== appUrl.origin) return fallback;
    return `${resolved.pathname}${resolved.search}${resolved.hash}`;
  } catch {
    return fallback;
  }
}

export class DenoKvMagicLinkAuth {
  private config: Required<Omit<DenoKvMagicLinkAuthConfig, "appBaseUrl">> & {
    appBaseUrl: string;
  };
  private deps: DenoKvMagicLinkAuthDeps;

  constructor(
    config: DenoKvMagicLinkAuthConfig,
    deps: DenoKvMagicLinkAuthDeps,
  ) {
    this.config = {
      appBaseUrl: assertAppBaseUrl(config.appBaseUrl),
      appName: config.appName ?? "App",
      magicLinkTtlMinutes: assertPositiveInteger(
        config.magicLinkTtlMinutes ?? 15,
        "magicLinkTtlMinutes",
      ),
      sessionIdleTtlDays: assertPositiveInteger(
        config.sessionIdleTtlDays ?? 7,
        "sessionIdleTtlDays",
      ),
      sessionAbsoluteTtlDays: assertPositiveInteger(
        config.sessionAbsoluteTtlDays ?? 30,
        "sessionAbsoluteTtlDays",
      ),
      authDevExposeMagicLink: config.authDevExposeMagicLink ?? false,
      sendEmailInDebugMode: config.sendEmailInDebugMode ?? false,
      keyPrefix: normalizeOptionalString(config.keyPrefix) ?? "dka",
    };
    this.deps = deps;
  }

  private now(): Date {
    return this.deps.now ? this.deps.now() : new Date();
  }

  private key(scope: string, id: string): Deno.KvKey {
    return [this.config.keyPrefix, scope, id];
  }

  async issueMagicLink(
    input: MagicLinkIssueInput,
  ): Promise<MagicLinkIssueResult> {
    const normalizedEmail = normalizeEmail(input.email);
    if (!normalizedEmail) {
      return { sent: false };
    }

    const user = await this.deps.findUserByEmail(normalizedEmail);
    if (!user || !user.active) {
      return { sent: false };
    }

    const token = randomToken();
    const tokenHash = await sha256Hex(token);
    const now = this.now();
    const nowIso = now.toISOString();
    const ttlMs = this.config.magicLinkTtlMinutes * 60 * 1000;

    const normalizedUa = normalizeUserAgent(input.userAgent);
    const issuedUserAgentHash = normalizedUa
      ? await sha256Hex(normalizedUa)
      : null;
    const normalizedBindingSecret = normalizeOptionalString(
      input.bindingSecret,
    );
    const bindingHash = normalizedBindingSecret
      ? await sha256Hex(normalizedBindingSecret)
      : null;

    const record: MagicLinkRecord = {
      userId: user.id,
      emailNormalized: normalizeEmail(user.email),
      createdAt: nowIso,
      expiresAt: new Date(now.getTime() + ttlMs).toISOString(),
      usedAt: null,
      redirectTo: sanitizeRedirectTo(input.redirectTo, this.config.appBaseUrl),
      issuedFromIp: normalizeOptionalString(input.requestIp),
      issuedUserAgentHash,
      bindingHash,
    };

    await this.deps.kv.set(this.key("magic_links", tokenHash), record, {
      expireIn: ttlMs,
    });

    const verificationUrl =
      `${this.config.appBaseUrl}/api/auth/magic-link/verify?token=${
        encodeURIComponent(token)
      }`;

    if (
      this.config.authDevExposeMagicLink && !this.config.sendEmailInDebugMode
    ) {
      return { sent: false, debugUrl: verificationUrl };
    }

    const sendMail = this.deps.sendMail;
    if (!sendMail) {
      return {
        sent: false,
        debugUrl: this.config.authDevExposeMagicLink
          ? verificationUrl
          : undefined,
      };
    }

    const result = await sendMail({
      to: user.email,
      subject: `${this.config.appName}: Dein Login-Link`,
      text:
        `Bitte nutze diesen Link fur den Login:\n\n${verificationUrl}\n\nDieser Link ist zeitlich begrenzt.`,
      html:
        `<p>Bitte nutze diesen Link fur den Login:</p><p><a href="${verificationUrl}">Jetzt einloggen</a></p><p>Dieser Link ist zeitlich begrenzt.</p>`,
    });

    return {
      sent: result.ok,
      debugUrl: this.config.authDevExposeMagicLink
        ? verificationUrl
        : undefined,
    };
  }

  async verifyMagicLink(
    input: MagicLinkVerifyInput,
  ): Promise<MagicLinkVerifyResult | null> {
    const token = input.token.trim();
    if (!token) return null;

    const tokenHash = await sha256Hex(token);
    const linkEntry = await this.deps.kv.get<MagicLinkRecord>(
      this.key("magic_links", tokenHash),
      { consistency: "strong" },
    );
    if (!linkEntry.value) return null;

    const contextUa = normalizeUserAgent(input.userAgent);
    const contextUserAgentHash = contextUa ? await sha256Hex(contextUa) : null;
    const normalizedBindingSecret = normalizeOptionalString(
      input.bindingSecret,
    );
    const contextBindingHash = normalizedBindingSecret
      ? await sha256Hex(normalizedBindingSecret)
      : null;
    const requestIp = normalizeOptionalString(input.requestIp);

    const cookieMatch = Boolean(
      linkEntry.value.bindingHash && contextBindingHash &&
        linkEntry.value.bindingHash === contextBindingHash,
    );
    const ipMatch = Boolean(
      linkEntry.value.issuedFromIp && requestIp &&
        linkEntry.value.issuedFromIp === requestIp,
    );
    const userAgentMatch = Boolean(
      linkEntry.value.issuedUserAgentHash && contextUserAgentHash &&
        linkEntry.value.issuedUserAgentHash === contextUserAgentHash,
    );

    if (!cookieMatch && !(ipMatch && userAgentMatch)) {
      return null;
    }

    const now = this.now();
    const nowMs = now.getTime();
    if (
      linkEntry.value.usedAt || Date.parse(linkEntry.value.expiresAt) <= nowMs
    ) {
      return null;
    }

    const user = await this.deps.findUserById(linkEntry.value.userId);
    if (!user || !user.active) return null;

    const sessionId = randomToken(24);
    const session: SessionRecord = {
      userId: user.id,
      userEmail: user.email,
      role: user.role ?? "viewer",
      authVersion: user.authVersion,
      createdAt: now.toISOString(),
      lastSeenAt: now.toISOString(),
      idleExpiresAt: new Date(
        nowMs + this.config.sessionIdleTtlDays * 24 * 60 * 60 * 1000,
      ).toISOString(),
      absoluteExpiresAt: new Date(
        nowMs + this.config.sessionAbsoluteTtlDays * 24 * 60 * 60 * 1000,
      ).toISOString(),
      revokedAt: null,
    };

    const tx = await this.deps.kv.atomic()
      .check({
        key: this.key("magic_links", tokenHash),
        versionstamp: linkEntry.versionstamp,
      })
      .set(this.key("magic_links", tokenHash), {
        ...linkEntry.value,
        usedAt: now.toISOString(),
      }, { expireIn: 24 * 60 * 60 * 1000 })
      .set(this.key("sessions", sessionId), session, {
        expireIn: this.config.sessionAbsoluteTtlDays * 24 * 60 * 60 * 1000,
      })
      .commit();

    if (!tx.ok) return null;

    return {
      sessionId,
      redirectTo: linkEntry.value.redirectTo || "/admin/dashboard",
      user,
    };
  }

  async getSession(sessionId: string): Promise<SessionRecord | null> {
    const entry = await this.deps.kv.get<SessionRecord>(
      this.key("sessions", sessionId),
      { consistency: "strong" },
    );
    if (!entry.value) return null;

    const nowMs = this.now().getTime();
    if (entry.value.revokedAt) return null;
    if (Date.parse(entry.value.idleExpiresAt) <= nowMs) return null;
    if (Date.parse(entry.value.absoluteExpiresAt) <= nowMs) return null;
    return entry.value;
  }

  async revokeSession(sessionId: string): Promise<void> {
    await this.deps.kv.delete(this.key("sessions", sessionId));
  }
}
