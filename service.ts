import {
  BINDING_SECRET_MAX_LENGTH,
  BINDING_SECRET_MIN_LENGTH,
  DEFAULT_MAGIC_LINK_VERIFY_PATH,
  DEFAULT_SESSION_ABSOLUTE_TTL_DAYS,
  DEFAULT_SESSION_IDLE_TTL_DAYS,
} from "./defaults.ts";
import type {
  DenoKvMagicLinkAuthConfig,
  DenoKvMagicLinkAuthDeps,
  FailedAuthAttemptRecord,
  MagicLinkAuthUser,
  MagicLinkEmailContent,
  MagicLinkEmailContext,
  MagicLinkIssueInput,
  MagicLinkIssueResult,
  MagicLinkRbacConfig,
  MagicLinkRecord,
  MagicLinkVerifyInput,
  MagicLinkVerifyResult,
  SessionAuthorizationSnapshot,
  SessionRecord,
} from "./types.ts";

const EMAIL_MAX_LENGTH = 320;
const TOKEN_MAX_LENGTH = 512;
const USER_AGENT_MAX_LENGTH = 1024;
const REDIRECT_MAX_LENGTH = 2048;
const IP_MAX_LENGTH = 128;
const USER_ID_MAX_LENGTH = 256;
const KEY_PREFIX_MAX_LENGTH = 64;
const APP_NAME_MAX_LENGTH = 120;
const ERROR_MAX_LENGTH = 300;
const VERIFY_PATH_MAX_LENGTH = 256;
const RATE_LIMIT_ATTEMPTS = 8;
const MAGIC_LINK_TTL_MINUTES_MAX = 10_080;
const SESSION_TTL_DAYS_MAX = 3_650;
const RATE_WINDOW_MINUTES_MAX = 10_080;
const RATE_ATTEMPTS_MAX = 1_000;
const USED_LINK_RETENTION_MS = 24 * 60 * 60 * 1000;
const DAY_MS = 24 * 60 * 60 * 1000;

interface NormalizedRbacConfig {
  enabled: boolean;
  roles: Readonly<Record<string, readonly string[]>>;
  defaultRole: string | null;
  permissionsVersion: number;
}

interface InternalConfig {
  appBaseUrl: string;
  appName: string;
  magicLinkVerifyPath: string;
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
  sendRateLimitMaxPerEmail: number;
  sendRateLimitMaxPerIp: number;
  sendRateLimitWindowMinutes: number;
  keyPrefix: string;
  rbac: NormalizedRbacConfig;
  renderMagicLinkEmail?: DenoKvMagicLinkAuthConfig["renderMagicLinkEmail"];
}

interface WindowCounterRecord {
  count: number;
  windowStartedAt: string;
}

interface StoredLink {
  token: string;
  tokenHash: string;
}

function normalizeEmail(email: string): string {
  return email.trim().toLowerCase();
}

function normalizeOptionalString(value?: string | null): string | null {
  if (typeof value !== "string") return null;
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
  return Array.from(new Uint8Array(hash)).map((byte) =>
    byte.toString(16).padStart(2, "0")
  ).join("");
}

function constantTimeEqual(left: string, right: string): boolean {
  const a = new TextEncoder().encode(left);
  const b = new TextEncoder().encode(right);
  const length = Math.max(a.length, b.length, 1);
  let diff = a.length ^ b.length;
  for (let index = 0; index < length; index++) {
    diff |= (a[index] ?? 0) ^ (b[index] ?? 0);
  }
  return diff === 0;
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function assertPositiveInteger(value: number, label: string): number {
  if (!Number.isInteger(value) || value <= 0) {
    throw new Error(`${label} must be a positive integer.`);
  }
  return value;
}

function assertBoundedInteger(
  value: number,
  label: string,
  max: number,
): number {
  const integer = assertPositiveInteger(value, label);
  if (integer > max) {
    throw new Error(`${label} must be at most ${max}.`);
  }
  return integer;
}

function isDomain(domain: string): boolean {
  if (!domain || !domain.includes(".") || domain.includes("*")) return false;
  if (
    domain.startsWith(".") || domain.endsWith(".") || domain.includes("..")
  ) {
    return false;
  }
  if (domain.includes("/") || domain.includes(":") || /\s/.test(domain)) {
    return false;
  }
  return true;
}

function splitEmail(
  value: string,
): { local: string; domain: string } | null {
  const normalized = normalizeEmail(value);
  if (
    !normalized || normalized.length > EMAIL_MAX_LENGTH ||
    normalized.includes("*") || /[\s/:]/.test(normalized)
  ) return null;
  const at = normalized.indexOf("@");
  if (at <= 0 || at !== normalized.lastIndexOf("@")) return null;
  const local = normalized.slice(0, at);
  const domain = normalized.slice(at + 1);
  if (!local || !isDomain(domain)) return null;
  return { local, domain };
}

function assertOptionalEmailPattern(value: string, label: string): string {
  const normalized = normalizeEmail(value);
  if (!normalized) {
    throw new Error(`${label} entries must not be empty.`);
  }
  if (normalized.startsWith("*@")) {
    const domain = normalized.slice(2);
    if (!isDomain(domain)) {
      throw new Error(
        `${label} wildcard entries must use the format "*@domain.tld".`,
      );
    }
    return `*@${domain}`;
  }
  if (!splitEmail(normalized)) {
    throw new Error(
      `${label} entries must be exact email addresses or "*@domain.tld".`,
    );
  }
  return normalized;
}

function assertEmailAddress(value: string, label: string): string {
  const normalized = normalizeEmail(value);
  if (!splitEmail(normalized)) {
    throw new Error(`${label} must be an exact email address.`);
  }
  return normalized;
}

function assertAppBaseUrl(value: string): string {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new Error("appBaseUrl must use http or https.");
  }
  if (!/^https?:$/.test(url.protocol)) {
    throw new Error("appBaseUrl must use http or https.");
  }
  if (url.username || url.password) {
    throw new Error("appBaseUrl must not include credentials.");
  }
  if (url.search || url.hash) {
    throw new Error("appBaseUrl must not include a query or hash.");
  }
  return `${url.origin}${url.pathname.replace(/\/$/, "")}`;
}

function assertVerifyPath(value: string, appBaseUrl: string): string {
  if (
    value.length > VERIFY_PATH_MAX_LENGTH || !value.startsWith("/") ||
    value.startsWith("//") || /[\s?#\\]/.test(value)
  ) {
    throw new Error(
      "magicLinkVerifyPath must be a same-origin absolute path.",
    );
  }
  const base = new URL(
    appBaseUrl.endsWith("/") ? appBaseUrl : `${appBaseUrl}/`,
  );
  const resolved = new URL(value.replace(/^\/+/, ""), base);
  if (resolved.origin !== base.origin || resolved.search || resolved.hash) {
    throw new Error(
      "magicLinkVerifyPath must be a same-origin absolute path.",
    );
  }
  const basePath = base.pathname;
  if (basePath !== "/" && !resolved.pathname.startsWith(basePath)) {
    throw new Error("magicLinkVerifyPath escaped the application base path.");
  }
  return resolved.pathname;
}

function sanitizeRedirectTo(
  value: string | undefined,
  appBaseUrl: string,
): string {
  const fallback = "/admin/dashboard";
  if (!value) return fallback;
  const trimmed = value.trim();
  if (!trimmed || trimmed.length > REDIRECT_MAX_LENGTH) return fallback;

  try {
    const appUrl = new URL(appBaseUrl);
    const resolved = new URL(trimmed, appUrl);
    if (resolved.origin !== appUrl.origin) return fallback;
    // A same-origin URL can have a network-path pathname. Returning that
    // pathname would change the origin when a caller resolves it again.
    if (resolved.pathname.startsWith("//")) return fallback;
    return `${resolved.pathname}${resolved.search}${resolved.hash}`;
  } catch {
    return fallback;
  }
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
    if (Object.hasOwn(acc, normalizedRole)) {
      throw new Error(
        `rbac role "${normalizedRole}" is declared more than once.`,
      );
    }
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
    permissionsVersion: assertBoundedInteger(
      value.permissionsVersion ?? 1,
      "rbac.permissionsVersion",
      RATE_ATTEMPTS_MAX,
    ),
  };
}

function canonicalIpv4(value: string): string | null {
  const parts = value.split(".");
  if (parts.length !== 4) return null;
  const octets: number[] = [];
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return null;
    const octet = Number(part);
    if (octet > 255) return null;
    octets.push(octet);
  }
  return octets.join(".");
}

function canonicalIpv6(value: string): string | null {
  const input = value.toLowerCase();
  const halves = input.split("::");
  if (halves.length > 2) return null;

  const parseSide = (side: string): number[] | null => {
    if (!side) return [];
    const parts = side.split(":");
    const groups: number[] = [];
    for (let index = 0; index < parts.length; index++) {
      const part = parts[index];
      if (part.includes(".")) {
        if (index !== parts.length - 1) return null;
        const dotted = canonicalIpv4(part);
        if (!dotted) return null;
        const [a, b, c, d] = dotted.split(".").map(Number);
        groups.push((a << 8) | b, (c << 8) | d);
        continue;
      }
      if (!/^[0-9a-f]{1,4}$/.test(part)) return null;
      groups.push(Number.parseInt(part, 16));
    }
    return groups;
  };

  let groups: number[];
  if (halves.length === 2) {
    const left = parseSide(halves[0]);
    const right = parseSide(halves[1]);
    if (!left || !right) return null;
    const missing = 8 - left.length - right.length;
    if (missing < 1) return null;
    groups = [...left, ...new Array<number>(missing).fill(0), ...right];
  } else {
    const full = parseSide(input);
    if (!full || full.length !== 8) return null;
    groups = full;
  }
  if (groups.length !== 8) return null;

  const mapped = groups.slice(0, 5).every((group) => group === 0) &&
    groups[5] === 0xffff;
  if (mapped) {
    const high = groups[6];
    const low = groups[7];
    return [
      (high >> 8) & 255,
      high & 255,
      (low >> 8) & 255,
      low & 255,
    ].join(".");
  }

  let bestStart = -1;
  let bestLength = 0;
  let runStart = -1;
  for (let index = 0; index <= groups.length; index++) {
    if (index < groups.length && groups[index] === 0) {
      if (runStart < 0) runStart = index;
      continue;
    }
    if (runStart < 0) continue;
    const length = index - runStart;
    if (length > bestLength) {
      bestStart = runStart;
      bestLength = length;
    }
    runStart = -1;
  }

  const parts = groups.map((group) => group.toString(16));
  if (bestLength < 2) return parts.join(":");
  const left = parts.slice(0, bestStart).join(":");
  const right = parts.slice(bestStart + bestLength).join(":");
  if (!left && !right) return "::";
  if (!left) return `::${right}`;
  if (!right) return `${left}::`;
  return `${left}::${right}`;
}

function canonicalizeIp(value?: string | null): string | null {
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  if (!trimmed || trimmed.length > IP_MAX_LENGTH) return null;
  const withoutZone = trimmed.split("%", 1)[0] ?? "";
  if (!withoutZone) return null;
  if (withoutZone.includes(":")) return canonicalIpv6(withoutZone);
  return canonicalIpv4(withoutZone);
}

function escapeHtml(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

function sanitizeHeader(value: string): string {
  return value.replace(/[\r\n]+/g, " ").trim().slice(0, 200);
}

function sanitizeError(value: string | undefined, fallback: string): string {
  const cleaned = (value ?? fallback).replace(/[\r\n]+/g, " ").trim();
  return (cleaned || fallback).slice(0, ERROR_MAX_LENGTH);
}

function defaultMagicLinkEmail(
  context: MagicLinkEmailContext,
): MagicLinkEmailContent {
  const safeUrl = escapeHtml(context.verificationUrl);
  return {
    subject: sanitizeHeader(`${context.appName}: Your login link`),
    text:
      `Use this link to sign in:\n\n${context.verificationUrl}\n\nThis link expires in ${context.ttlMinutes} minutes.`,
    html:
      `<p>Use this link to sign in:</p><p><a href="${safeUrl}">Sign in</a></p><p>This link expires in ${context.ttlMinutes} minutes.</p>`,
  };
}

function timestampExpired(value: string | undefined, nowMs: number): boolean {
  const parsed = Date.parse(value ?? "");
  return !Number.isFinite(parsed) || parsed <= nowMs;
}

function denied(error?: string): MagicLinkIssueResult {
  return error
    ? { issued: false, sent: false, error }
    : { issued: false, sent: false };
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
    const appBaseUrl = assertAppBaseUrl(config.appBaseUrl);
    const sessionIdleTtlDays = assertBoundedInteger(
      config.sessionIdleTtlDays ?? DEFAULT_SESSION_IDLE_TTL_DAYS,
      "sessionIdleTtlDays",
      SESSION_TTL_DAYS_MAX,
    );
    const sessionAbsoluteTtlDays = assertBoundedInteger(
      config.sessionAbsoluteTtlDays ?? DEFAULT_SESSION_ABSOLUTE_TTL_DAYS,
      "sessionAbsoluteTtlDays",
      SESSION_TTL_DAYS_MAX,
    );
    if (sessionIdleTtlDays > sessionAbsoluteTtlDays) {
      throw new Error(
        "sessionIdleTtlDays must not exceed sessionAbsoluteTtlDays.",
      );
    }
    const keyPrefix = normalizeOptionalString(config.keyPrefix) ?? "dka";
    if (keyPrefix.length > KEY_PREFIX_MAX_LENGTH) {
      throw new Error(
        `keyPrefix must be at most ${KEY_PREFIX_MAX_LENGTH} characters.`,
      );
    }

    this.config = {
      appBaseUrl,
      appName: sanitizeHeader(config.appName ?? "App").slice(
        0,
        APP_NAME_MAX_LENGTH,
      ) || "App",
      magicLinkVerifyPath: assertVerifyPath(
        config.magicLinkVerifyPath ?? DEFAULT_MAGIC_LINK_VERIFY_PATH,
        appBaseUrl,
      ),
      magicLinkTtlMinutes: assertBoundedInteger(
        config.magicLinkTtlMinutes ?? 15,
        "magicLinkTtlMinutes",
        MAGIC_LINK_TTL_MINUTES_MAX,
      ),
      sessionIdleTtlDays,
      sessionAbsoluteTtlDays,
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
      failedAuthRateLimitMaxAttempts: assertBoundedInteger(
        config.failedAuthRateLimitMaxAttempts ?? 5,
        "failedAuthRateLimitMaxAttempts",
        RATE_ATTEMPTS_MAX,
      ),
      failedAuthRateLimitWindowMinutes: assertBoundedInteger(
        config.failedAuthRateLimitWindowMinutes ?? 15,
        "failedAuthRateLimitWindowMinutes",
        RATE_WINDOW_MINUTES_MAX,
      ),
      failedAuthRateLimitBlockMinutes: assertBoundedInteger(
        config.failedAuthRateLimitBlockMinutes ?? 15,
        "failedAuthRateLimitBlockMinutes",
        RATE_WINDOW_MINUTES_MAX,
      ),
      sendRateLimitMaxPerEmail: assertBoundedInteger(
        config.sendRateLimitMaxPerEmail ?? 10,
        "sendRateLimitMaxPerEmail",
        RATE_ATTEMPTS_MAX,
      ),
      sendRateLimitMaxPerIp: assertBoundedInteger(
        config.sendRateLimitMaxPerIp ?? 30,
        "sendRateLimitMaxPerIp",
        RATE_ATTEMPTS_MAX,
      ),
      sendRateLimitWindowMinutes: assertBoundedInteger(
        config.sendRateLimitWindowMinutes ?? 15,
        "sendRateLimitWindowMinutes",
        RATE_WINDOW_MINUTES_MAX,
      ),
      keyPrefix,
      rbac: assertRbacConfig(config.rbac),
      renderMagicLinkEmail: config.renderMagicLinkEmail,
    };
    this.deps = deps;
  }

  /** Verify pathname joined onto `appBaseUrl`, including a configured base path. */
  get magicLinkVerifyPath(): string {
    return this.config.magicLinkVerifyPath;
  }

  /**
   * Cookie lifetime in seconds. This is the earlier of the fixed idle and
   * absolute deadlines, measured from issuance.
   */
  sessionCookieMaxAgeSeconds(): number {
    return Math.floor(this.sessionLifetimeMs() / 1000);
  }

  private now(): Date {
    return this.deps.now ? this.deps.now() : new Date();
  }

  private sessionLifetimeMs(): number {
    const days = Math.min(
      this.config.sessionIdleTtlDays,
      this.config.sessionAbsoluteTtlDays,
    );
    return days * DAY_MS;
  }

  private key(scope: string, id: string): Deno.KvKey {
    return [this.config.keyPrefix, scope, id];
  }

  private userSessionKey(userId: string, sessionHash: string): Deno.KvKey {
    return [this.config.keyPrefix, "user_sessions", userId, sessionHash];
  }

  private isEmailAllowed(email: string): boolean {
    const parsed = splitEmail(email);
    if (!parsed) return false;
    if (this.config.allowedEmailPatterns.length === 0) return true;
    return this.config.allowedEmailPatterns.some((pattern) => {
      if (pattern.startsWith("*@")) return parsed.domain === pattern.slice(2);
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
  ): SessionAuthorizationSnapshot | undefined | null {
    if (!this.config.rbac.enabled) return undefined;

    // Resolve RBAC state once during login so later permission checks do not
    // require additional KV lookups. A null result rejects the login.
    const configuredRole = user.role ? normalizeKey(user.role) : "";
    const effectiveRole = configuredRole || this.config.rbac.defaultRole || "";
    if (!effectiveRole || !this.config.rbac.roles[effectiveRole]) return null;

    return {
      role: effectiveRole,
      permissions: [...this.config.rbac.roles[effectiveRole]],
      permissionsVersion: this.config.rbac.permissionsVersion,
    };
  }

  private async getFailedAttemptState(
    scope: string,
    requestIp: string,
  ): Promise<Deno.KvEntryMaybe<FailedAuthAttemptRecord>> {
    return await this.deps.kv.get<FailedAuthAttemptRecord>(
      this.key(scope, requestIp),
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
    scope: string,
    requestIp: string,
    entry: Deno.KvEntryMaybe<FailedAuthAttemptRecord> | null,
    now: Date,
  ): Promise<void> {
    const key = this.key(scope, requestIp);
    const windowMs = this.config.failedAuthRateLimitWindowMinutes * 60 * 1000;
    const blockMs = this.config.failedAuthRateLimitBlockMinutes * 60 * 1000;
    let current = entry;
    let attemptTime = now;

    for (let attempt = 0; attempt < RATE_LIMIT_ATTEMPTS; attempt++) {
      // A delayed failure must not overwrite a block established by another
      // request. Recompute from fresh state after every conflicting write.
      if (this.isBlockedAttempt(current, attemptTime)) return;
      const nowMs = attemptTime.getTime();
      const count = current?.value &&
          Date.parse(current.value.lastAttemptAt) > nowMs - windowMs
        ? current.value.count + 1
        : 1;
      const record: FailedAuthAttemptRecord = {
        count,
        lastAttemptAt: attemptTime.toISOString(),
        blockedUntil: count >= this.config.failedAuthRateLimitMaxAttempts
          ? new Date(nowMs + blockMs).toISOString()
          : null,
      };

      const tx = await this.deps.kv.atomic()
        .check({ key, versionstamp: current?.versionstamp ?? null })
        .set(key, record, { expireIn: Math.max(windowMs, blockMs) })
        .commit();
      if (tx.ok) return;
      await delay(Math.min(5 * 2 ** attempt, 40));
      current = await this.getFailedAttemptState(scope, requestIp);
      attemptTime = this.now();
    }
  }

  private async reserveWindowCounter(
    scope: string,
    id: string,
    max: number,
  ): Promise<boolean> {
    const key = this.key(scope, id);
    let current = await this.deps.kv.get<WindowCounterRecord>(key, {
      consistency: "strong",
    });
    const windowMs = this.config.sendRateLimitWindowMinutes * 60 * 1000;

    for (let attempt = 0; attempt < RATE_LIMIT_ATTEMPTS; attempt++) {
      const now = this.now();
      const fresh = !current.value ||
        Date.parse(current.value.windowStartedAt) <= now.getTime() - windowMs;
      if (!fresh && current.value && current.value.count >= max) return false;
      const record: WindowCounterRecord = {
        count: fresh ? 1 : (current.value?.count ?? 0) + 1,
        windowStartedAt: fresh
          ? now.toISOString()
          : current.value?.windowStartedAt ?? now.toISOString(),
      };
      const tx = await this.deps.kv.atomic()
        .check({ key, versionstamp: current.versionstamp })
        .set(key, record, { expireIn: windowMs })
        .commit();
      if (tx.ok) return true;
      await delay(Math.min(5 * 2 ** attempt, 40));
      current = await this.deps.kv.get<WindowCounterRecord>(key, {
        consistency: "strong",
      });
    }
    return false;
  }

  private async reserveSendBudget(
    requestIp: string,
    email: string,
  ): Promise<boolean> {
    const emailKey = await sha256Hex(email);
    const emailAllowed = await this.reserveWindowCounter(
      "send_budget_email",
      emailKey,
      this.config.sendRateLimitMaxPerEmail,
    );
    if (!emailAllowed) return false;
    return await this.reserveWindowCounter(
      "send_budget_ip",
      requestIp,
      this.config.sendRateLimitMaxPerIp,
    );
  }

  private bindingSecretForIssue(
    value: string | null | undefined,
  ): string | null {
    if (value == null) return null;
    if (typeof value !== "string") {
      throw new Error(
        `bindingSecret must be between ${BINDING_SECRET_MIN_LENGTH} and ${BINDING_SECRET_MAX_LENGTH} characters.`,
      );
    }
    const secret = value.trim();
    if (
      secret.length < BINDING_SECRET_MIN_LENGTH ||
      secret.length > BINDING_SECRET_MAX_LENGTH
    ) {
      throw new Error(
        `bindingSecret must be between ${BINDING_SECRET_MIN_LENGTH} and ${BINDING_SECRET_MAX_LENGTH} characters.`,
      );
    }
    return secret;
  }

  private verificationUrl(token: string): string {
    // The stored path is absolute on the origin, so it replaces any base path.
    const url = new URL(
      this.config.magicLinkVerifyPath,
      this.config.appBaseUrl,
    );
    url.searchParams.set("token", token);
    return url.toString();
  }

  private emailContent(verificationUrl: string): MagicLinkEmailContent {
    const context: MagicLinkEmailContext = {
      appName: this.config.appName,
      verificationUrl,
      ttlMinutes: this.config.magicLinkTtlMinutes,
    };
    const fallback = defaultMagicLinkEmail(context);
    const rendered = this.config.renderMagicLinkEmail?.(context);
    if (!rendered) return fallback;
    const text = typeof rendered.text === "string" ? rendered.text : "";
    const html = typeof rendered.html === "string" ? rendered.html : "";
    const includesUrl = text.includes(verificationUrl) ||
      html.includes(verificationUrl) ||
      html.includes(escapeHtml(verificationUrl));
    if (!includesUrl) return fallback;
    return {
      subject: sanitizeHeader(rendered.subject || "") || fallback.subject,
      text: text || fallback.text,
      html: html || fallback.html,
    };
  }

  private async storeMagicLink(
    user: MagicLinkAuthUser,
    recordWithoutTimes: Omit<MagicLinkRecord, "createdAt" | "expiresAt">,
  ): Promise<StoredLink | null> {
    const pointerKey = this.key("magic_link_current", user.id);
    const ttlMs = this.config.magicLinkTtlMinutes * 60 * 1000;
    let pointer = await this.deps.kv.get<string>(pointerKey, {
      consistency: "strong",
    });

    for (let attempt = 0; attempt < RATE_LIMIT_ATTEMPTS; attempt++) {
      const token = randomToken();
      const tokenHash = await sha256Hex(token);
      const issuedAt = this.now();
      const record: MagicLinkRecord = {
        ...recordWithoutTimes,
        createdAt: issuedAt.toISOString(),
        expiresAt: new Date(issuedAt.getTime() + ttlMs).toISOString(),
      };
      const tx = this.deps.kv.atomic().check({
        key: pointerKey,
        versionstamp: pointer.versionstamp,
      });
      if (pointer.value) tx.delete(this.key("magic_links", pointer.value));
      const committed = await tx
        .set(pointerKey, tokenHash, { expireIn: ttlMs })
        .set(this.key("magic_links", tokenHash), record, { expireIn: ttlMs })
        .commit();
      if (committed.ok) return { token, tokenHash };
      await delay(Math.min(5 * 2 ** attempt, 40));
      pointer = await this.deps.kv.get<string>(pointerKey, {
        consistency: "strong",
      });
    }
    return null;
  }

  private async deleteLinkIfCurrent(
    userId: string,
    tokenHash: string,
  ): Promise<void> {
    const pointerKey = this.key("magic_link_current", userId);
    const pointer = await this.deps.kv.get<string>(pointerKey, {
      consistency: "strong",
    });
    if (pointer.value !== tokenHash) return;
    await this.deps.kv.atomic()
      .check({ key: pointerKey, versionstamp: pointer.versionstamp })
      .delete(pointerKey)
      .delete(this.key("magic_links", tokenHash))
      .commit();
  }

  /** Issues a one-time magic link for an active user and stores its verification record in Deno KV. */
  async issueMagicLink(
    input: MagicLinkIssueInput,
  ): Promise<MagicLinkIssueResult> {
    const requestIp = canonicalizeIp(input.requestIp);
    if (!requestIp) return denied();

    const bindingSecret = this.bindingSecretForIssue(input.bindingSecret);
    const rawUserAgent = typeof input.userAgent === "string"
      ? input.userAgent
      : "";
    const userAgent = rawUserAgent.length > USER_AGENT_MAX_LENGTH
      ? null
      : normalizeUserAgent(rawUserAgent);

    const now = this.now();
    const failedAttemptEntry = await this.getFailedAttemptState(
      "failed_auth_attempts",
      requestIp,
    );
    if (this.isBlockedAttempt(failedAttemptEntry, now)) {
      return denied("rate_limited");
    }

    const normalizedEmail = splitEmail(
      typeof input.email === "string" ? input.email : "",
    );
    if (!normalizedEmail) {
      await this.registerFailedAttempt(
        "failed_auth_attempts",
        requestIp,
        failedAttemptEntry,
        now,
      );
      return denied();
    }
    const email = `${normalizedEmail.local}@${normalizedEmail.domain}`;

    if (!this.isEmailAllowed(email)) {
      await this.registerFailedAttempt(
        "failed_auth_attempts",
        requestIp,
        failedAttemptEntry,
        now,
      );
      return denied();
    }

    const user = await this.deps.findUserByEmail(email);
    const userEmail = user ? normalizeEmail(user.email) : "";
    if (
      !user || !user.active || typeof user.id !== "string" || !user.id ||
      user.id.length > USER_ID_MAX_LENGTH || userEmail !== email ||
      !this.isEmailAllowed(userEmail) ||
      typeof user.authVersion !== "number" || !Number.isFinite(user.authVersion)
    ) {
      await this.registerFailedAttempt(
        "failed_auth_attempts",
        requestIp,
        failedAttemptEntry,
        now,
      );
      return denied();
    }

    const resolvedUser = this.resolveUser(user);
    if (this.resolveAuthorization(resolvedUser) === null) return denied();
    // A link with neither a binding secret nor a user agent can never be verified.
    if (!bindingSecret && !userAgent) return denied();

    if (!await this.reserveSendBudget(requestIp, email)) {
      return denied("rate_limited");
    }

    const redirectTo = typeof input.redirectTo === "string" &&
        input.redirectTo.length <= REDIRECT_MAX_LENGTH
      ? input.redirectTo
      : undefined;
    const issuedUserAgentHash = userAgent ? await sha256Hex(userAgent) : null;
    const bindingHash = bindingSecret ? await sha256Hex(bindingSecret) : null;
    const stored = await this.storeMagicLink(user, {
      userId: user.id,
      emailNormalized: email,
      authVersion: user.authVersion,
      usedAt: null,
      redirectTo: sanitizeRedirectTo(redirectTo, this.config.appBaseUrl),
      issuedFromIp: requestIp,
      issuedUserAgentHash,
      bindingHash,
    });
    if (!stored) return denied("rate_limited");

    const verificationUrl = this.verificationUrl(stored.token);
    const exposeDebugUrl = this.config.authDevExposeMagicLink;
    if (exposeDebugUrl && !this.config.sendEmailInDebugMode) {
      return { issued: true, sent: false, debugUrl: verificationUrl };
    }

    const sendMail = this.deps.sendMail;
    if (!sendMail) {
      if (!exposeDebugUrl) {
        await this.deleteLinkIfCurrent(user.id, stored.tokenHash);
        return denied("mail_not_configured");
      }
      return {
        issued: true,
        sent: false,
        debugUrl: verificationUrl,
        error: "mail_not_configured",
      };
    }

    let delivery;
    try {
      delivery = await sendMail({
        to: email,
        ...this.emailContent(verificationUrl),
      });
    } catch (error) {
      delivery = {
        ok: false,
        error: error instanceof Error ? error.message : "mail_failed",
      };
    }
    if (!delivery.ok) {
      if (!exposeDebugUrl) {
        await this.deleteLinkIfCurrent(user.id, stored.tokenHash);
        return {
          issued: false,
          sent: false,
          error: sanitizeError(delivery.error, "mail_failed"),
        };
      }
      return {
        issued: true,
        sent: false,
        debugUrl: verificationUrl,
        error: sanitizeError(delivery.error, "mail_failed"),
      };
    }

    return {
      issued: true,
      sent: true,
      debugUrl: exposeDebugUrl ? verificationUrl : undefined,
    };
  }

  private async recordVerifyFailure(
    requestIp: string,
    entry: Deno.KvEntryMaybe<FailedAuthAttemptRecord>,
    now: Date,
  ): Promise<null> {
    await this.registerFailedAttempt(
      "failed_verify_attempts",
      requestIp,
      entry,
      now,
    );
    return null;
  }

  /** Verifies and consumes a magic link, then creates a session when the verification context matches. */
  async verifyMagicLink(
    input: MagicLinkVerifyInput,
  ): Promise<MagicLinkVerifyResult | null> {
    const requestIp = canonicalizeIp(input.requestIp);
    if (!requestIp) return null;

    const now = this.now();
    const failedAttemptEntry = await this.getFailedAttemptState(
      "failed_verify_attempts",
      requestIp,
    );
    if (this.isBlockedAttempt(failedAttemptEntry, now)) return null;

    const token = typeof input.token === "string" ? input.token.trim() : "";
    if (!token || token.length > TOKEN_MAX_LENGTH) {
      if (!token) return null;
      return await this.recordVerifyFailure(
        requestIp,
        failedAttemptEntry,
        now,
      );
    }

    const rawUserAgent = typeof input.userAgent === "string"
      ? input.userAgent
      : "";
    if (rawUserAgent.length > USER_AGENT_MAX_LENGTH) {
      return await this.recordVerifyFailure(
        requestIp,
        failedAttemptEntry,
        now,
      );
    }
    const tokenHash = await sha256Hex(token);
    const linkKey = this.key("magic_links", tokenHash);
    const linkEntry = await this.deps.kv.get<MagicLinkRecord>(linkKey, {
      consistency: "strong",
    });
    if (
      !linkEntry.value || linkEntry.value.userId.length > USER_ID_MAX_LENGTH
    ) {
      return await this.recordVerifyFailure(
        requestIp,
        failedAttemptEntry,
        now,
      );
    }

    const pointerKey = this.key("magic_link_current", linkEntry.value.userId);
    const pointer = await this.deps.kv.get<string>(pointerKey, {
      consistency: "strong",
    });
    if (pointer.value !== tokenHash) {
      return await this.recordVerifyFailure(
        requestIp,
        failedAttemptEntry,
        now,
      );
    }

    const bindingSecret = normalizeOptionalString(input.bindingSecret);
    const bindingAccepted = bindingSecret !== null &&
      bindingSecret.length >= BINDING_SECRET_MIN_LENGTH &&
      bindingSecret.length <= BINDING_SECRET_MAX_LENGTH;
    const contextBindingHash = bindingAccepted && bindingSecret
      ? await sha256Hex(bindingSecret)
      : null;
    const contextUserAgentHash = normalizeUserAgent(rawUserAgent);
    const contextUserAgentDigest = contextUserAgentHash
      ? await sha256Hex(contextUserAgentHash)
      : null;
    const link = linkEntry.value;
    const bindingMatch = Boolean(
      link.bindingHash && contextBindingHash &&
        constantTimeEqual(link.bindingHash, contextBindingHash),
    );
    const contextMatch = link.bindingHash ? bindingMatch : Boolean(
      link.issuedFromIp &&
        constantTimeEqual(link.issuedFromIp, requestIp) &&
        link.issuedUserAgentHash && contextUserAgentDigest &&
        constantTimeEqual(link.issuedUserAgentHash, contextUserAgentDigest),
    );
    if (
      !contextMatch || link.usedAt ||
      timestampExpired(link.expiresAt, now.getTime())
    ) {
      return await this.recordVerifyFailure(
        requestIp,
        failedAttemptEntry,
        now,
      );
    }

    const user = await this.deps.findUserById(link.userId);
    const userEmail = user ? normalizeEmail(user.email) : "";
    const identityMatches = Boolean(
      user && user.active && userEmail === link.emailNormalized &&
        this.isEmailAllowed(userEmail) &&
        typeof link.authVersion === "number" &&
        user.authVersion === link.authVersion,
    );
    const resolvedUser = identityMatches && user
      ? this.resolveUser(user)
      : null;
    const authorization = resolvedUser
      ? this.resolveAuthorization(resolvedUser)
      : null;
    if (!resolvedUser || authorization === null) {
      await this.deps.kv.atomic()
        .check({ key: linkKey, versionstamp: linkEntry.versionstamp })
        .check({ key: pointerKey, versionstamp: pointer.versionstamp })
        .set(linkKey, { ...link, usedAt: now.toISOString() }, {
          expireIn: USED_LINK_RETENTION_MS,
        })
        .commit();
      return null;
    }

    const sessionId = randomToken(24);
    const sessionHash = await sha256Hex(sessionId);
    const nowMs = now.getTime();
    const session: SessionRecord = {
      userId: resolvedUser.id,
      userEmail: resolvedUser.email,
      role: authorization?.role ?? resolvedUser.role ?? "",
      isSuperAdmin: resolvedUser.isSuperAdmin ?? false,
      authVersion: resolvedUser.authVersion,
      authorization,
      createdAt: now.toISOString(),
      idleExpiresAt: new Date(nowMs + this.config.sessionIdleTtlDays * DAY_MS)
        .toISOString(),
      absoluteExpiresAt: new Date(
        nowMs + this.config.sessionAbsoluteTtlDays * DAY_MS,
      ).toISOString(),
    };
    const lifetimeMs = this.sessionLifetimeMs();
    const tx = await this.deps.kv.atomic()
      .check({ key: linkKey, versionstamp: linkEntry.versionstamp })
      .check({ key: pointerKey, versionstamp: pointer.versionstamp })
      .set(linkKey, { ...link, usedAt: now.toISOString() }, {
        expireIn: USED_LINK_RETENTION_MS,
      })
      .set(this.key("sessions", sessionHash), session, { expireIn: lifetimeMs })
      .set(this.userSessionKey(resolvedUser.id, sessionHash), true, {
        expireIn: lifetimeMs,
      })
      .commit();
    if (!tx.ok) return null;

    return {
      sessionId,
      redirectTo: sanitizeRedirectTo(link.redirectTo, this.config.appBaseUrl),
      user: resolvedUser,
    };
  }

  private presentSession(value: SessionRecord): SessionRecord {
    return {
      userId: value.userId,
      userEmail: value.userEmail,
      role: value.role,
      isSuperAdmin: value.isSuperAdmin,
      authVersion: value.authVersion,
      authorization: this.config.rbac.enabled ? value.authorization : undefined,
      createdAt: value.createdAt,
      idleExpiresAt: value.idleExpiresAt,
      absoluteExpiresAt: value.absoluteExpiresAt,
    };
  }

  private async deleteStoredSession(
    sessionHash: string,
    userId: string | undefined,
  ): Promise<void> {
    await this.deps.kv.delete(this.key("sessions", sessionHash));
    if (userId) {
      await this.deps.kv.delete(this.userSessionKey(userId, sessionHash));
    }
  }

  /** Returns the current session when it is unexpired and the user is still allowed to authenticate. */
  async getSession(sessionId: string): Promise<SessionRecord | null> {
    if (
      typeof sessionId !== "string" || !sessionId ||
      sessionId.length > TOKEN_MAX_LENGTH
    ) {
      return null;
    }
    const sessionHash = await sha256Hex(sessionId);
    const entry = await this.deps.kv.get<
      SessionRecord & { revokedAt?: string | null }
    >(
      this.key("sessions", sessionHash),
      { consistency: "strong" },
    );
    if (!entry.value) return null;

    const nowMs = this.now().getTime();
    const legacyRevoked = Boolean(entry.value.revokedAt);
    const expired = legacyRevoked ||
      timestampExpired(entry.value.idleExpiresAt, nowMs) ||
      timestampExpired(entry.value.absoluteExpiresAt, nowMs);
    if (expired) {
      await this.deleteStoredSession(sessionHash, entry.value.userId);
      return null;
    }

    const user = await this.deps.findUserById(entry.value.userId);
    const resolved = user && user.active ? this.resolveUser(user) : null;
    const authorizationCurrent = Boolean(
      resolved && resolved.email === entry.value.userEmail &&
        resolved.authVersion === entry.value.authVersion &&
        (resolved.isSuperAdmin ?? false) === entry.value.isSuperAdmin,
    );
    const permissionsCurrent = !this.config.rbac.enabled ||
      (entry.value.authorization?.permissionsVersion ===
        this.config.rbac.permissionsVersion);
    if (!resolved || !authorizationCurrent || !permissionsCurrent) {
      await this.deleteStoredSession(sessionHash, entry.value.userId);
      return null;
    }
    return this.presentSession(entry.value);
  }

  /** Revokes a session by deleting its hashed KV record. */
  async revokeSession(sessionId: string): Promise<void> {
    if (
      typeof sessionId !== "string" || !sessionId ||
      sessionId.length > TOKEN_MAX_LENGTH
    ) {
      return;
    }
    const sessionHash = await sha256Hex(sessionId);
    const entry = await this.deps.kv.get<SessionRecord>(
      this.key("sessions", sessionHash),
    );
    await this.deleteStoredSession(sessionHash, entry.value?.userId);
  }

  /** Revokes every session previously issued for a user. */
  async revokeUserSessions(userId: string): Promise<void> {
    if (
      typeof userId !== "string" || !userId ||
      userId.length > USER_ID_MAX_LENGTH
    ) {
      return;
    }
    const prefix = [this.config.keyPrefix, "user_sessions", userId];
    const entries = this.deps.kv.list<boolean>({ prefix });
    for await (const entry of entries) {
      const sessionHash = entry.key[3];
      if (typeof sessionHash === "string" && sessionHash) {
        await this.deps.kv.delete(this.key("sessions", sessionHash));
      }
      await this.deps.kv.delete(entry.key);
    }
  }
}
