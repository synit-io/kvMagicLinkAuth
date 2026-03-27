# Changelog

All notable changes to this package are documented in this file.

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
