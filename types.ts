/** Application user model required by the magic-link auth service. */
export interface MagicLinkAuthUser {
  /** Stable user identifier stored in issued links and sessions. */
  id: string;
  /** User email address used for login and session display. */
  email: string;
  /** Version used by applications to invalidate older sessions when credentials change. */
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
  lastSeenAt: string;
  idleExpiresAt: string;
  absoluteExpiresAt: string;
  revokedAt: string | null;
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
  requestIp?: string | null;
  userAgent?: string | null;
  bindingSecret?: string | null;
}

/** Input payload for verifying a magic link token. */
export interface MagicLinkVerifyInput {
  token: string;
  requestIp?: string | null;
  userAgent?: string | null;
  bindingSecret?: string | null;
}

/** Result returned after attempting to issue a magic link. */
export interface MagicLinkIssueResult {
  sent: boolean;
  debugUrl?: string;
}

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
