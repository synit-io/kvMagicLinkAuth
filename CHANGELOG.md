# Changelog

All notable changes to this package are documented in this file.

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
