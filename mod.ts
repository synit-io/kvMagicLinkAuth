export {
  buildBindingClearCookie,
  buildBindingSetCookie,
  buildSessionClearCookie,
  buildSessionSetCookie,
  getCookie,
  type MagicLinkCookieConfig,
} from "./cookies.ts";

export { DenoKvMagicLinkAuth } from "./service.ts";

export type {
  DenoKvMagicLinkAuthConfig,
  DenoKvMagicLinkAuthDeps,
  MagicLinkAuthUser,
  MagicLinkIssueInput,
  MagicLinkIssueResult,
  MagicLinkRecord,
  MagicLinkVerifyInput,
  MagicLinkVerifyResult,
  SendMailFn,
  SendMailPayload,
  SendMailResult,
  SessionRecord,
} from "./types.ts";
