# Changelog

All notable changes to this package are documented in this file.

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
