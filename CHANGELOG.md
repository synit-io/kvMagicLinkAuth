# Changelog

All notable changes to this package are documented in this file.

## 0.4.0 - 2026-10-02

- Revalidated every session against `findUserById`. A session ends when the user
  is missing, inactive, or no longer matches the stored email, `authVersion`, or
  super-admin flag. With RBAC enabled, `permissionsVersion` must match too.
  Added `revokeUserSessions(userId)`.
- Stored session ids as SHA-256 hashes. The cookie still carries the raw id.
- Kept one outstanding magic link per user and required its current-user pointer
  during verification. Links written before this version cannot be consumed.
- Required the binding secret whenever a link stored one. IP and user-agent
  matching remains the path for links issued without a binding secret.
- Canonicalized `requestIp` before rate-limit keys and IP binding, and rejected
  missing or invalid addresses. Added a separate verifier-failure limiter.
- Tightened email checks and made `*@domain` match that domain only. Mail is
  sent to the normalized address that passed the allowlist.
- Added successful-send quotas of 10 per email and 30 per IP each 15 minutes.
  Unknown users do not consume that budget. KV retries stop after 8 attempts.
- Replaced the 30 day cookie default with the 7 day session lifetime. Default
  cookie names are `__Host-session` and `__Host-ml-bind`.
- Added `buildVerifyResponseHeaders`, `magicLinkVerifyPath`,
  `renderMagicLinkEmail`, and `sessionCookieMaxAgeSeconds()`. The built-in login
  email is English.
- Rejected `appBaseUrl` values that contain credentials, a query, or a hash. An
  unknown RBAC role no longer throws, and a missing role is no longer stored as
  `viewer`.
- Stopped publishing `nodemailer` and `playwright` on the package import map.
  Unit tests use in-memory KV. Dependency-update cleanup deletes only the merged
  branch, and that workflow also runs the E2E and browser suites.

Upgrade: existing sessions and magic links stop working, so users need a new
link. HTTP development must set non-prefix cookie names and `secure: false`.
`findUserById` must return the live user or `getSession()` ends the session.
Idle expiry is a fixed deadline measured from issuance.

## 0.3.0 - 2026-09-10

- Bound newly issued magic links to the user's email and credential version.
  Verification also enforces the current allowlist. Outstanding links issued by
  older versions cannot authenticate after upgrading; request a new link.
- Prevented same-origin URLs with network-path pathnames from becoming external
  redirects, including redirect values in existing KV records.
- Fixed failed-login rate limiting under concurrent requests by retrying checked
  atomic writes and preserving established blocks.
- Changed session and binding cookie defaults to `SameSite=Lax` for emailed
  login navigation. Applications can explicitly configure `sameSite: "Strict"`
  when using a same-site confirmation flow.
- Corrected `__Host-` binding cookies to use `Path=/` and reject insecure
  configurations for `__Host-` and `__Secure-` cookie names.
- Fixed documentation examples to use matching verification routes, retain
  response cookies, deliver email, and derive client IPs from trusted transport
  information. Added upgrade and public-endpoint guidance.
- Restricted E2E service ports to loopback and fixed runner paths containing
  spaces or Unicode. E2E tests now reject spoofed forwarding headers.
- Added security, browser-cookie, and executable documentation regression tests
  to the development and CI checks.

## 0.2.1 - 2026-04-07

- Hardened cookie helpers to default to `Secure` and `SameSite=Strict` while
  keeping `HttpOnly`.
- Added tests that enforce strict cookie attributes and verify that magic-link
  URLs do not include an `email` query parameter.
- Updated security documentation to reflect strict cookie defaults and
  query-parameter protections.
- Fixed the E2E Docker image build by copying `authorization.ts`, which is
  re-exported by `mod.ts` and required during `deno cache e2e/app.ts`.

## 0.2.0 - 2026-03-29

- Added optional RBAC support with config-driven role-to-permission mappings,
  session-cached authorization snapshots, and pure helper APIs for role and
  permission checks.
- Added `hasRole()`, `hasPermission()`, `hasAnyPermission()`, `isSuperAdmin()`,
  and `isSessionAuthorizationCurrent()` exports.
- Reduced failed-auth KV overhead by reusing the same failed-attempt state read
  during `issueMagicLink()` instead of reloading it for each failed attempt.
- Expanded tests to cover RBAC snapshots, helper behavior, super-admin bypass,
  and RBAC config validation.
- Rewrote `README.md` with improved getting-started guidance, secure
  authentication flow examples, low-KV usage guidance, and basic plus advanced
  RBAC examples.

## 0.1.2 - 2026-03-27

- Added `allowedEmailPatterns` config support for exact email-address
  whitelisting and `*@domain.tld` domain whitelisting.
- Added failed-auth IP throttling during `issueMagicLink()` with configurable
  attempt, window, and block durations.
- Added `initialSuperAdminEmail` config support and propagated `isSuperAdmin`
  into verified users and persisted sessions.
- Expanded test coverage and README examples for allowlists, super-admin
  propagation, and rate limiting.
- Added a Docker Compose based E2E stack with Mailpit, a containerized Deno auth
  app, and `deno task e2e`.

## 0.1.0 - 2026-03-20

- Hardened auth configuration validation for `appBaseUrl` and TTL settings.
- Normalized and sanitized email, IP, user-agent, and binding-secret inputs.
- Improved cookie parsing and cookie-name validation to avoid malformed header
  handling.
- Added automated Deno tests for token issuance, verification, expiry, replay
  prevention, session handling, and cookie helpers.
- Added `deno.json` tasks/imports for `deno fmt`, `deno lint`, and `deno test`.
- Expanded package documentation with maintainer attribution, minimum usage,
  advanced usage, and contributor development guidance.
