/** Application user model required by the magic-link auth service. */
export interface MagicLinkAuthUser {
  /** Stable user identifier stored in issued links and sessions. */
  id: string;
  /** User email address used for login and session display. */
  email: string;
  /** Credential version recorded in links and sessions; increment when credentials change. */
  authVersion: number;
  /** Whether the user is currently allowed to authenticate. */
  active: boolean;
  /** Optional application role copied into the session record. */
  role?: string;
  /** Whether the authenticated user should be treated as a super administrator. */
  isSuperAdmin?: boolean;
}

/** Static RBAC role-to-permission mapping configured by the application. */
export interface MagicLinkRbacConfig {
  enabled?: boolean;
  roles: Record<string, readonly string[]>;
  defaultRole?: string;
  permissionsVersion?: number;
}

/** Minimal authorization snapshot cached on the session for fast request-time checks. */
export interface SessionAuthorizationSnapshot {
  role: string;
  permissions: string[];
  permissionsVersion: number;
}

/** Stored Deno KV record for an issued magic link. */
export interface MagicLinkRecord {
  userId: string;
  emailNormalized: string;
  /** Credential version at issuance. Legacy records without this field cannot authenticate. */
  authVersion: number;
  createdAt: string;
  expiresAt: string;
  usedAt: string | null;
  redirectTo: string;
  issuedFromIp: string | null;
  issuedUserAgentHash: string | null;
  bindingHash: string | null;
}

/** Stored Deno KV record for an authenticated session. */
export interface SessionRecord {
  userId: string;
  userEmail: string;
  role: string;
  isSuperAdmin: boolean;
  authVersion: number;
  authorization?: SessionAuthorizationSnapshot;
  createdAt: string;
  /** Fixed deadline from issuance. It does not move when the session is read. */
  idleExpiresAt: string;
  /** Fixed deadline from issuance. The effective lifetime is the earlier of the two deadlines. */
  absoluteExpiresAt: string;
}

/** Stored failed-auth state for one originating IP address. */
export interface FailedAuthAttemptRecord {
  count: number;
  lastAttemptAt: string;
  blockedUntil: string | null;
}

/** Input payload for issuing a magic link. */
export interface MagicLinkIssueInput {
  email: string;
  redirectTo?: string;
  /** Trusted client IP from the transport or a validated proxy, never a raw client header. */
  requestIp?: string | null;
  userAgent?: string | null;
  bindingSecret?: string | null;
}

/** Input payload for verifying a magic link token. */
export interface MagicLinkVerifyInput {
  token: string;
  /** Trusted client IP from the transport or a validated proxy, never a raw client header. */
  requestIp?: string | null;
  userAgent?: string | null;
  bindingSecret?: string | null;
}

/** Result returned after attempting to issue a magic link. */
export interface MagicLinkIssueResult {
  /** A usable link was stored and its raw token is available to mail or `debugUrl`. */
  issued: boolean;
  /** Mail delivery succeeded. Debug-only issuance leaves this false. */
  sent: boolean;
  debugUrl?: string;
  /**
   * Application-facing failure detail, such as `rate_limited` or a mailer error.
   * Do not copy this value into a public HTTP response.
   */
  error?: string;
}

/** Message content produced for a magic-link email. */
export interface MagicLinkEmailContent {
  subject: string;
  text: string;
  html: string;
}

/** Values supplied to a custom magic-link email renderer. */
export interface MagicLinkEmailContext {
  appName: string;
  verificationUrl: string;
  ttlMinutes: number;
}

/** Optional application renderer for the login email. */
export type RenderMagicLinkEmail = (
  context: MagicLinkEmailContext,
) => MagicLinkEmailContent;

/** Result returned after a successful magic-link verification. */
export interface MagicLinkVerifyResult {
  sessionId: string;
  redirectTo: string;
  user: MagicLinkAuthUser;
}

/** Mail payload passed to the injected `sendMail` dependency. */
export interface SendMailPayload {
  to: string;
  subject: string;
  text: string;
  html: string;
}

/** Mail delivery result returned by the injected `sendMail` dependency. */
export interface SendMailResult {
  ok: boolean;
  error?: string;
}

/** Async mail delivery function used to send the login link to the user. */
export type SendMailFn = (payload: SendMailPayload) => Promise<SendMailResult>;

/** Configuration options for the magic-link auth service. */
export interface DenoKvMagicLinkAuthConfig {
  appBaseUrl: string;
  appName?: string;
  magicLinkTtlMinutes?: number;
  sessionIdleTtlDays?: number;
  sessionAbsoluteTtlDays?: number;
  authDevExposeMagicLink?: boolean;
  sendEmailInDebugMode?: boolean;
  allowedEmailPatterns?: string[];
  initialSuperAdminEmail?: string;
  failedAuthRateLimitMaxAttempts?: number;
  failedAuthRateLimitWindowMinutes?: number;
  failedAuthRateLimitBlockMinutes?: number;
  /** Successful login emails allowed for one address in the send window. Defaults to `10`. */
  sendRateLimitMaxPerEmail?: number;
  /** Successful login emails allowed for one IP in the send window. Defaults to `30`. */
  sendRateLimitMaxPerIp?: number;
  /** Window used by the successful-send limits. Defaults to `15` minutes. */
  sendRateLimitWindowMinutes?: number;
  /** Absolute path joined onto `appBaseUrl`. Defaults to `/api/auth/magic-link/verify`. */
  magicLinkVerifyPath?: string;
  /** Replaces the built-in English login email. */
  renderMagicLinkEmail?: RenderMagicLinkEmail;
  keyPrefix?: string;
  rbac?: MagicLinkRbacConfig;
}

/** Dependencies injected into the magic-link auth service. */
export interface DenoKvMagicLinkAuthDeps {
  kv: Deno.Kv;
  findUserByEmail: (email: string) => Promise<MagicLinkAuthUser | null>;
  findUserById: (id: string) => Promise<MagicLinkAuthUser | null>;
  sendMail?: SendMailFn;
  now?: () => Date;
}
