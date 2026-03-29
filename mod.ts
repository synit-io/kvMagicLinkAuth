export {
  buildBindingClearCookie,
  buildBindingSetCookie,
  buildSessionClearCookie,
  buildSessionSetCookie,
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
  MagicLinkIssueInput,
  MagicLinkIssueResult,
  MagicLinkRbacConfig,
  MagicLinkRecord,
  MagicLinkVerifyInput,
  MagicLinkVerifyResult,
  SendMailFn,
  SendMailPayload,
  SendMailResult,
  SessionAuthorizationSnapshot,
  SessionRecord,
} from "./types.ts";
