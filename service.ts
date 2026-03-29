import type {
  DenoKvMagicLinkAuthConfig,
  DenoKvMagicLinkAuthDeps,
  FailedAuthAttemptRecord,
  MagicLinkAuthUser,
  MagicLinkIssueInput,
  MagicLinkIssueResult,
  MagicLinkRbacConfig,
  MagicLinkRecord,
  MagicLinkVerifyInput,
  MagicLinkVerifyResult,
  SessionAuthorizationSnapshot,
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

function normalizeKey(value: string): string {
  return value.trim().toLowerCase();
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

function assertOptionalEmailPattern(
  value: string,
  label: string,
): string {
  const normalized = normalizeEmail(value);
  if (!normalized) {
    throw new Error(`${label} entries must not be empty.`);
  }
  if (normalized.startsWith("*@")) {
    const domain = normalized.slice(2);
    if (!domain || domain.includes("*") || !domain.includes(".")) {
      throw new Error(
        `${label} wildcard entries must use the format "*@domain.tld".`,
      );
    }
    return `*@${domain}`;
  }
  if (normalized.includes("*")) {
    throw new Error(
      `${label} entries must be exact email addresses or "*@domain.tld".`,
    );
  }
  const atIndex = normalized.indexOf("@");
  if (atIndex <= 0 || atIndex === normalized.length - 1) {
    throw new Error(
      `${label} entries must be exact email addresses or "*@domain.tld".`,
    );
  }
  return normalized;
}

function assertEmailAddress(value: string, label: string): string {
  const normalized = normalizeEmail(value);
  const atIndex = normalized.indexOf("@");
  if (
    !normalized || normalized.includes("*") || atIndex <= 0 ||
    atIndex === normalized.length - 1
  ) {
    throw new Error(`${label} must be an exact email address.`);
  }
  return normalized;
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

interface NormalizedRbacConfig {
  enabled: boolean;
  roles: Readonly<Record<string, readonly string[]>>;
  defaultRole: string | null;
  permissionsVersion: number;
}

interface InternalConfig {
  appBaseUrl: string;
  appName: string;
  magicLinkTtlMinutes: number;
  sessionIdleTtlDays: number;
  sessionAbsoluteTtlDays: number;
  authDevExposeMagicLink: boolean;
  sendEmailInDebugMode: boolean;
  allowedEmailPatterns: string[];
  initialSuperAdminEmail: string;
  failedAuthRateLimitMaxAttempts: number;
  failedAuthRateLimitWindowMinutes: number;
  failedAuthRateLimitBlockMinutes: number;
  keyPrefix: string;
  rbac: NormalizedRbacConfig;
}

function assertNonEmptyKey(value: string, label: string): string {
  const normalized = normalizeKey(value);
  if (!normalized) {
    throw new Error(`${label} must not be empty.`);
  }
  return normalized;
}

function assertRbacConfig(
  value: MagicLinkRbacConfig | undefined,
): NormalizedRbacConfig {
  if (!value?.enabled) {
    return {
      enabled: false,
      roles: Object.freeze({}),
      defaultRole: null,
      permissionsVersion: 1,
    };
  }

  const normalizedRoles = Object.entries(value.roles ?? {}).reduce<
    Record<string, readonly string[]>
  >((acc, [role, permissions]) => {
    const normalizedRole = assertNonEmptyKey(role, "rbac role");
    if (!Array.isArray(permissions) || permissions.length === 0) {
      throw new Error(
        `rbac role "${normalizedRole}" must define at least one permission.`,
      );
    }
    acc[normalizedRole] = Object.freeze(Array.from(
      new Set(
        permissions.map((permission) =>
          assertNonEmptyKey(
            permission,
            `rbac role "${normalizedRole}" permission`,
          )
        ),
      ),
    ));
    return acc;
  }, {});

  if (Object.keys(normalizedRoles).length === 0) {
    throw new Error(
      "rbac.roles must define at least one role when RBAC is enabled.",
    );
  }

  const defaultRole = value.defaultRole
    ? assertNonEmptyKey(value.defaultRole, "rbac.defaultRole")
    : null;
  if (defaultRole && !normalizedRoles[defaultRole]) {
    throw new Error("rbac.defaultRole must reference a configured role.");
  }

  return {
    enabled: true,
    roles: Object.freeze(normalizedRoles),
    defaultRole,
    permissionsVersion: assertPositiveInteger(
      value.permissionsVersion ?? 1,
      "rbac.permissionsVersion",
    ),
  };
}

/** Deno KV backed magic-link authentication service for server-side Deno applications. */
export class DenoKvMagicLinkAuth {
  private config: InternalConfig;
  private deps: DenoKvMagicLinkAuthDeps;

  /** Creates a new auth service with package configuration and injected application dependencies. */
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
      allowedEmailPatterns: Array.from(
        new Set(
          (config.allowedEmailPatterns ?? []).map((entry) =>
            assertOptionalEmailPattern(entry, "allowedEmailPatterns")
          ),
        ),
      ),
      initialSuperAdminEmail: config.initialSuperAdminEmail
        ? assertEmailAddress(
          config.initialSuperAdminEmail,
          "initialSuperAdminEmail",
        )
        : "",
      failedAuthRateLimitMaxAttempts: assertPositiveInteger(
        config.failedAuthRateLimitMaxAttempts ?? 5,
        "failedAuthRateLimitMaxAttempts",
      ),
      failedAuthRateLimitWindowMinutes: assertPositiveInteger(
        config.failedAuthRateLimitWindowMinutes ?? 15,
        "failedAuthRateLimitWindowMinutes",
      ),
      failedAuthRateLimitBlockMinutes: assertPositiveInteger(
        config.failedAuthRateLimitBlockMinutes ?? 15,
        "failedAuthRateLimitBlockMinutes",
      ),
      keyPrefix: normalizeOptionalString(config.keyPrefix) ?? "dka",
      rbac: assertRbacConfig(config.rbac),
    };
    this.deps = deps;
  }

  private now(): Date {
    return this.deps.now ? this.deps.now() : new Date();
  }

  private key(scope: string, id: string): Deno.KvKey {
    return [this.config.keyPrefix, scope, id];
  }

  private isEmailAllowed(email: string): boolean {
    if (this.config.allowedEmailPatterns.length === 0) return true;
    return this.config.allowedEmailPatterns.some((pattern) => {
      if (pattern.startsWith("*@")) {
        return email.endsWith(pattern.slice(1));
      }
      return email === pattern;
    });
  }

  private isInitialSuperAdmin(email: string): boolean {
    return Boolean(
      this.config.initialSuperAdminEmail &&
        email === this.config.initialSuperAdminEmail,
    );
  }

  private resolveUser(user: MagicLinkAuthUser): MagicLinkAuthUser {
    const normalizedEmail = normalizeEmail(user.email);
    const isSuperAdmin = user.isSuperAdmin ??
      this.isInitialSuperAdmin(normalizedEmail);
    return {
      ...user,
      email: normalizedEmail,
      role: user.role ? normalizeKey(user.role) : undefined,
      isSuperAdmin,
    };
  }

  private resolveAuthorization(
    user: MagicLinkAuthUser,
  ): SessionAuthorizationSnapshot | undefined {
    if (!this.config.rbac.enabled) return undefined;

    // Resolve RBAC state once during login so later permission checks do not
    // require additional KV or database lookups.
    const configuredRole = user.role ? normalizeKey(user.role) : "";
    const effectiveRole = configuredRole || this.config.rbac.defaultRole || "";
    if (!effectiveRole || !this.config.rbac.roles[effectiveRole]) {
      throw new Error(
        "Authenticated user does not resolve to a configured RBAC role.",
      );
    }

    return {
      role: effectiveRole,
      permissions: [...this.config.rbac.roles[effectiveRole]],
      permissionsVersion: this.config.rbac.permissionsVersion,
    };
  }

  private async getFailedAttemptState(
    requestIp: string | null,
  ): Promise<Deno.KvEntryMaybe<FailedAuthAttemptRecord> | null> {
    if (!requestIp) return null;
    return await this.deps.kv.get<FailedAuthAttemptRecord>(
      this.key("failed_auth_attempts", requestIp),
      { consistency: "strong" },
    );
  }

  private isBlockedAttempt(
    entry: Deno.KvEntryMaybe<FailedAuthAttemptRecord> | null,
    now: Date,
  ): boolean {
    if (!entry?.value?.blockedUntil) return false;
    return Date.parse(entry.value.blockedUntil) > now.getTime();
  }

  private async registerFailedAttempt(
    requestIp: string | null,
    entry: Deno.KvEntryMaybe<FailedAuthAttemptRecord> | null,
    now: Date,
  ): Promise<void> {
    if (!requestIp) return;

    const nowMs = now.getTime();
    const windowMs = this.config.failedAuthRateLimitWindowMinutes * 60 * 1000;
    const blockMs = this.config.failedAuthRateLimitBlockMinutes * 60 * 1000;
    const count = entry?.value &&
        Date.parse(entry.value.lastAttemptAt) > nowMs - windowMs
      ? entry.value.count + 1
      : 1;
    const blockedUntil = count >= this.config.failedAuthRateLimitMaxAttempts
      ? new Date(nowMs + blockMs).toISOString()
      : null;
    const record: FailedAuthAttemptRecord = {
      count,
      lastAttemptAt: now.toISOString(),
      blockedUntil,
    };

    if (entry?.value) {
      const tx = await this.deps.kv.atomic()
        .check({ key: entry.key, versionstamp: entry.versionstamp })
        .set(this.key("failed_auth_attempts", requestIp), record, {
          expireIn: Math.max(windowMs, blockMs),
        })
        .commit();
      if (tx.ok) return;
    }

    await this.deps.kv.set(
      this.key("failed_auth_attempts", requestIp),
      record,
      {
        expireIn: Math.max(windowMs, blockMs),
      },
    );
  }

  /** Issues a one-time magic link for an active user and stores its verification record in Deno KV. */
  async issueMagicLink(
    input: MagicLinkIssueInput,
  ): Promise<MagicLinkIssueResult> {
    const normalizedEmail = normalizeEmail(input.email);
    const requestIp = normalizeOptionalString(input.requestIp);
    if (!normalizedEmail) {
      return { sent: false };
    }

    const now = this.now();
    const failedAttemptEntry = await this.getFailedAttemptState(requestIp);
    if (this.isBlockedAttempt(failedAttemptEntry, now)) {
      return { sent: false };
    }

    if (!this.isEmailAllowed(normalizedEmail)) {
      await this.registerFailedAttempt(requestIp, failedAttemptEntry, now);
      return { sent: false };
    }

    const user = await this.deps.findUserByEmail(normalizedEmail);
    if (!user || !user.active) {
      await this.registerFailedAttempt(requestIp, failedAttemptEntry, now);
      return { sent: false };
    }

    const token = randomToken();
    const tokenHash = await sha256Hex(token);
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
      issuedFromIp: requestIp,
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

  /** Verifies and consumes a magic link, then creates a session when the verification context matches. */
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
    const resolvedUser = this.resolveUser(user);

    // The session stores only a minimal authorization snapshot so request-time
    // RBAC checks can stay in memory after a single session load.
    const authorization = this.resolveAuthorization(resolvedUser);
    const sessionId = randomToken(24);
    const session: SessionRecord = {
      userId: resolvedUser.id,
      userEmail: resolvedUser.email,
      role: authorization?.role ?? resolvedUser.role ?? "viewer",
      isSuperAdmin: resolvedUser.isSuperAdmin ?? false,
      authVersion: resolvedUser.authVersion,
      authorization,
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
      user: resolvedUser,
    };
  }

  /** Returns the current session record if it exists and has not expired or been revoked. */
  async getSession(sessionId: string): Promise<SessionRecord | null> {
    const entry = await this.deps.kv.get<SessionRecord>(
      this.key("sessions", sessionId),
      { consistency: "strong" },
    );
    if (!entry.value) return null;

    // Keep session reads side-effect free so normal authenticated requests stay
    // at one KV read and do not turn into read-plus-write traffic.
    const nowMs = this.now().getTime();
    if (entry.value.revokedAt) return null;
    if (Date.parse(entry.value.idleExpiresAt) <= nowMs) return null;
    if (Date.parse(entry.value.absoluteExpiresAt) <= nowMs) return null;
    return entry.value;
  }

  /** Revokes a session by deleting it from Deno KV. */
  async revokeSession(sessionId: string): Promise<void> {
    await this.deps.kv.delete(this.key("sessions", sessionId));
  }
}
