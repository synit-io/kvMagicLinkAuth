export interface MagicLinkAuthUser {
  id: string;
  email: string;
  authVersion: number;
  active: boolean;
  role?: string;
}

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

export interface SessionRecord {
  userId: string;
  userEmail: string;
  role: string;
  authVersion: number;
  createdAt: string;
  lastSeenAt: string;
  idleExpiresAt: string;
  absoluteExpiresAt: string;
  revokedAt: string | null;
}

export interface MagicLinkIssueInput {
  email: string;
  redirectTo?: string;
  requestIp?: string | null;
  userAgent?: string | null;
  bindingSecret?: string | null;
}

export interface MagicLinkVerifyInput {
  token: string;
  requestIp?: string | null;
  userAgent?: string | null;
  bindingSecret?: string | null;
}

export interface MagicLinkIssueResult {
  sent: boolean;
  debugUrl?: string;
}

export interface MagicLinkVerifyResult {
  sessionId: string;
  redirectTo: string;
  user: MagicLinkAuthUser;
}

export interface SendMailPayload {
  to: string;
  subject: string;
  text: string;
  html: string;
}

export interface SendMailResult {
  ok: boolean;
  error?: string;
}

export type SendMailFn = (payload: SendMailPayload) => Promise<SendMailResult>;

export interface DenoKvMagicLinkAuthConfig {
  appBaseUrl: string;
  appName?: string;
  magicLinkTtlMinutes?: number;
  sessionIdleTtlDays?: number;
  sessionAbsoluteTtlDays?: number;
  authDevExposeMagicLink?: boolean;
  sendEmailInDebugMode?: boolean;
  keyPrefix?: string;
}

export interface DenoKvMagicLinkAuthDeps {
  kv: Deno.Kv;
  findUserByEmail: (email: string) => Promise<MagicLinkAuthUser | null>;
  findUserById: (id: string) => Promise<MagicLinkAuthUser | null>;
  sendMail?: SendMailFn;
  now?: () => Date;
}
