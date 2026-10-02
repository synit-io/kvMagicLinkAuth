export {
  BINDING_SECRET_MAX_LENGTH,
  BINDING_SECRET_MIN_LENGTH,
  DEFAULT_MAGIC_LINK_VERIFY_PATH,
  DEFAULT_SESSION_ABSOLUTE_TTL_DAYS,
  DEFAULT_SESSION_COOKIE_TTL_DAYS,
  DEFAULT_SESSION_IDLE_TTL_DAYS,
} from "./defaults.ts";

export {
  buildBindingClearCookie,
  buildBindingSetCookie,
  buildSessionClearCookie,
  buildSessionSetCookie,
  buildVerifyResponseHeaders,
  getCookie,
  type MagicLinkCookieConfig,
} from "./cookies.ts";

export {
  hasAnyPermission,
  hasPermission,
  hasRole,
  isSessionAuthorizationCurrent,
  isSuperAdmin,
} from "./authorization.ts";

export { DenoKvMagicLinkAuth } from "./service.ts";

export type {
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
  RenderMagicLinkEmail,
  SendMailFn,
  SendMailPayload,
  SendMailResult,
  SessionAuthorizationSnapshot,
  SessionRecord,
} from "./types.ts";
