# kv-magic-link-auth

Deno KV backed magic-link authentication with optional RBAC for server-side Deno
applications.

Maintained by [synit.io](https://www.synit.io).

## Features

- One outstanding magic link per user, stored as a hash and consumed atomically
- Session identifiers stored as hashes, with live user checks on every load
- Optional email-address and exact-domain allowlist support
- Failed-attempt and successful-send limits per canonical client IP
- Initial super-admin propagation into verified users and stored sessions
- Binding-secret checks when a link was issued with one, otherwise IP plus
  user-agent
- Optional RBAC with session-cached role and permission snapshots
- Pure role and permission helper APIs for request-time checks
- `__Host-` cookie helpers for session and verification-bound cookies
- Docker Compose backed E2E coverage with Mailpit and a local auth test app
- Works well with Fresh, Hono, and custom Deno HTTP services

## Why this package

This package is designed for apps that want:

- passwordless sign-in with a small API surface
- secure one-time magic links
- low operational overhead on Deno KV
- optional authorization without adding per-request policy lookups

The package keeps the normal authenticated request path small:

- one session read from KV, plus the application `findUserById` lookup
- zero extra KV reads for RBAC checks after the session is loaded

## Install

### Deno

```sh
deno add jsr:@synitio/kv-magic-link-auth
```

```ts
import {
  buildSessionSetCookie,
  DenoKvMagicLinkAuth,
  getCookie,
  hasPermission,
} from "jsr:@synitio/kv-magic-link-auth";
```

## Requirements

- Deno 2 with Deno KV support
- `--unstable-kv` when opening a local KV database
- application-provided user lookups
- optional application-provided mail sender

## Quick Start

This is the shortest useful setup. It shows the full auth lifecycle:

- request a magic link
- verify the link
- set a session cookie
- load the session later

Each handler below accepts the transport context supplied by `Deno.serve`.
Register it with `Deno.serve(handleRequest)` after providing your application
lookups and mail adapter. `info.remoteAddr.hostname` is the connected peer's IP;
`User-Agent` is read from the request. For a different framework, pass an
address obtained from its trusted connection metadata.

Do not use a client-supplied `X-Forwarded-For` value as `requestIp`. Behind a
reverse proxy, configure an explicit trusted-proxy boundary that overwrites or
validates forwarding headers before passing the resolved client IP. The direct
peer address otherwise identifies the proxy, so clients share its rate-limit
bucket. Use the same trusted address resolution for issuance and verification.

```ts
import {
  buildSessionSetCookie,
  buildVerifyResponseHeaders,
  DenoKvMagicLinkAuth,
  getCookie,
} from "jsr:@synitio/kv-magic-link-auth";

const kv = await Deno.openKv();

const auth = new DenoKvMagicLinkAuth(
  {
    appBaseUrl: "https://app.example.local",
    appName: "Synit Console",
    authDevExposeMagicLink: true,
  },
  {
    kv,
    findUserByEmail: async (email) => {
      if (email !== "admin@example.local") return null;
      return {
        id: "u_1",
        email,
        authVersion: 1,
        active: true,
        role: "admin",
      };
    },
    findUserById: async (id) => {
      if (id !== "u_1") return null;
      return {
        id,
        email: "admin@example.local",
        authVersion: 1,
        active: true,
        role: "admin",
      };
    },
  },
);

export async function handleRequest(
  request: Request,
  info: Deno.ServeHandlerInfo<Deno.NetAddr>,
): Promise<Response> {
  const url = new URL(request.url);

  if (url.pathname === "/auth/request" && request.method === "POST") {
    // `issueMagicLink()` creates a one-time token record in KV.
    const issued = await auth.issueMagicLink({
      email: "admin@example.local",
      redirectTo: "/admin/dashboard",
      requestIp: info.remoteAddr.hostname,
      userAgent: request.headers.get("user-agent"),
    });

    return Response.json({
      // Local debug only. Do not return `debugUrl`, `sent`, or `error` from
      // a production login endpoint.
      debugUrl: issued.debugUrl,
    });
  }

  if (url.pathname === "/api/auth/magic-link/verify") {
    // `verifyMagicLink()` consumes the one-time token and writes one session.
    const verified = await auth.verifyMagicLink({
      token: url.searchParams.get("token") ?? "",
      requestIp: info.remoteAddr.hostname,
      userAgent: request.headers.get("user-agent"),
    });

    if (!verified) {
      return new Response("invalid or expired link", { status: 401 });
    }

    return new Response(null, {
      status: 302,
      headers: buildVerifyResponseHeaders(
        new URL(verified.redirectTo, "https://app.example.local").href,
        [
          buildSessionSetCookie(verified.sessionId, {
            secure: true,
            maxAgeSeconds: auth.sessionCookieMaxAgeSeconds(),
            sessionCookieName: "__Host-session",
          }),
        ],
      ),
    });
  }

  if (url.pathname === "/me") {
    const sessionId = getCookie(request.headers, "__Host-session");
    if (!sessionId) {
      return new Response("not authenticated", { status: 401 });
    }

    // Loads the hashed session and rechecks the live user. `findUserById`
    // must return that account or the session is deleted.
    const session = await auth.getSession(sessionId);
    if (!session) {
      return new Response("session expired", { status: 401 });
    }

    return Response.json({
      userId: session.userId,
      email: session.userEmail,
      role: session.role,
    });
  }

  return new Response("not found", { status: 404 });
}
```

## Core Concepts

### How login works

1. `issueMagicLink()` canonicalizes the client IP, checks allowlists and rate
   limits, then stores one hashed token for that user. A newer link replaces the
   previous unconsumed link.
2. `verifyMagicLink()` loads the token, requires the current-user pointer to
   match, checks the binding secret or the IP plus user-agent, and atomically
   marks the token as used while creating a session.
3. `getSession()` loads the hashed session, enforces the fixed idle and absolute
   deadlines, and calls `findUserById`. A missing, inactive, or changed user
   deletes the session. The idle deadline does not move on read.

### Why the session is safe to use for RBAC

When RBAC is enabled, the session stores only a minimal authorization snapshot:

- `role`
- `authorization.permissions`
- `isSuperAdmin`
- `authVersion`
- `authorization.permissionsVersion`

The session does not store:

- raw magic-link tokens
- unhashed binding secrets
- mutable policy source documents

That keeps request-time authorization fast while limiting the sensitivity of the
session payload.

### KV usage model

The package is tuned to avoid unnecessary KV traffic:

- successful login request: failed-attempt read, send-budget reservations, and
  one atomic write of the new link plus the current-user pointer
- link verification: link and pointer reads, then one atomic consume that also
  writes the hashed session and its user index
- authenticated request: one session read, then `findUserById` in application
  code
- RBAC helper checks after the session is loaded: zero KV operations

## Basic Auth Example

This example shows a production-oriented setup with allowlists and real mail
delivery. Return the same `202` response whether an account exists, is blocked,
or receives mail; keep the internal `sent` result out of public responses. The
example addresses and mail endpoint are placeholders for your application.

Successful sends are limited to 10 per email address and 30 per IP in a 15
minute window. Failed attempts have a separate limiter. Unknown addresses do not
consume the send budget. Keep any additional edge limits in front of the
application.

```ts
import {
  buildSessionClearCookie,
  buildSessionSetCookie,
  buildVerifyResponseHeaders,
  DenoKvMagicLinkAuth,
  getCookie,
} from "jsr:@synitio/kv-magic-link-auth";

const kv = await Deno.openKv();

const auth = new DenoKvMagicLinkAuth(
  {
    appBaseUrl: "https://console.example.local",
    appName: "Example Console",
    allowedEmailPatterns: ["*@example.local", "owner@partner.example"],
    initialSuperAdminEmail: "admin@example.local",
    failedAuthRateLimitMaxAttempts: 5,
    failedAuthRateLimitWindowMinutes: 15,
    failedAuthRateLimitBlockMinutes: 15,
  },
  {
    kv,
    findUserByEmail: async (email) => {
      const row = await lookupUserByEmail(email);
      if (!row) return null;
      return {
        id: row.id,
        email: row.email,
        authVersion: row.authVersion,
        active: row.active,
        role: row.role,
      };
    },
    findUserById: async (id) => {
      const row = await lookupUserById(id);
      if (!row) return null;
      return {
        id: row.id,
        email: row.email,
        authVersion: row.authVersion,
        active: row.active,
        role: row.role,
      };
    },
    sendMail: async ({ to, subject, text, html }) => {
      const response = await fetch("https://mailer.example.local/send", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ to, subject, text, html }),
      });
      return { ok: response.ok };
    },
  },
);

export async function handleRequest(
  request: Request,
  info: Deno.ServeHandlerInfo<Deno.NetAddr>,
): Promise<Response> {
  const url = new URL(request.url);

  if (url.pathname === "/auth/request" && request.method === "POST") {
    await auth.issueMagicLink({
      email: "admin@example.local",
      redirectTo: "/admin/dashboard",
      requestIp: info.remoteAddr.hostname,
      userAgent: request.headers.get("user-agent"),
    });

    return Response.json({ accepted: true }, { status: 202 });
  }

  if (url.pathname === "/api/auth/magic-link/verify") {
    const verified = await auth.verifyMagicLink({
      token: url.searchParams.get("token") ?? "",
      requestIp: info.remoteAddr.hostname,
      userAgent: request.headers.get("user-agent"),
    });

    if (!verified) {
      return new Response("invalid or expired link", { status: 401 });
    }

    return new Response(null, {
      status: 302,
      headers: buildVerifyResponseHeaders(
        new URL(verified.redirectTo, "https://console.example.local").href,
        [
          buildSessionSetCookie(verified.sessionId, {
            secure: true,
            maxAgeSeconds: auth.sessionCookieMaxAgeSeconds(),
            sessionCookieName: "__Host-session",
          }),
        ],
      ),
    });
  }

  if (url.pathname === "/auth/logout" && request.method === "POST") {
    if (request.headers.get("origin") !== "https://console.example.local") {
      return new Response("invalid origin", { status: 403 });
    }

    const sessionId = getCookie(request.headers, "__Host-session");
    if (sessionId) {
      await auth.revokeSession(sessionId);
    }

    return new Response("logged out", {
      headers: {
        "set-cookie": buildSessionClearCookie({
          secure: true,
          sessionCookieName: "__Host-session",
        }),
      },
    });
  }

  return new Response("not found", { status: 404 });
}

declare function lookupUserByEmail(email: string): Promise<
  {
    id: string;
    email: string;
    authVersion: number;
    active: boolean;
    role?: string;
  } | null
>;

declare function lookupUserById(id: string): Promise<
  {
    id: string;
    email: string;
    authVersion: number;
    active: boolean;
    role?: string;
  } | null
>;
```

## Advanced Auth Example

This variant adds binding-secret verification. A link issued with a binding
secret can be redeemed only with that secret, including after the client IP
changes. IP and user-agent matching applies only to links issued without a
binding secret. The secret must be 16 to 512 characters.

```ts
import {
  buildBindingClearCookie,
  buildBindingSetCookie,
  buildSessionSetCookie,
  buildVerifyResponseHeaders,
  DenoKvMagicLinkAuth,
  getCookie,
} from "jsr:@synitio/kv-magic-link-auth";

const kv = await Deno.openKv();

const auth = new DenoKvMagicLinkAuth(
  {
    appBaseUrl: "https://console.example.local",
    appName: "Example Console",
    magicLinkTtlMinutes: 10,
    sessionIdleTtlDays: 7,
    sessionAbsoluteTtlDays: 30,
  },
  {
    kv,
    findUserByEmail: lookupUserByEmail,
    findUserById: lookupUserById,
    sendMail: async ({ to, subject, text, html }) => {
      const response = await fetch("https://mailer.example.local/send", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ to, subject, text, html }),
      });
      return { ok: response.ok };
    },
  },
);

export async function handleRequest(
  request: Request,
  info: Deno.ServeHandlerInfo<Deno.NetAddr>,
): Promise<Response> {
  const url = new URL(request.url);

  if (url.pathname === "/auth/request" && request.method === "POST") {
    // This cookie never stores the login token. It stores a separate secret
    // that is hashed and matched during verification.
    const bindingSecret = crypto.randomUUID();
    await auth.issueMagicLink({
      email: "admin@example.local",
      redirectTo: "/admin/dashboard",
      requestIp: info.remoteAddr.hostname,
      userAgent: request.headers.get("user-agent"),
      bindingSecret,
    });

    const headers = new Headers({ "content-type": "application/json" });
    headers.append(
      "set-cookie",
      buildBindingSetCookie(bindingSecret, 10 * 60, {
        secure: true,
        bindingCookieName: "__Host-ml-bind",
      }),
    );

    return new Response(JSON.stringify({ accepted: true }), {
      status: 202,
      headers,
    });
  }

  if (url.pathname === "/api/auth/magic-link/verify") {
    const bindingSecret = getCookie(request.headers, "__Host-ml-bind");
    const verified = await auth.verifyMagicLink({
      token: url.searchParams.get("token") ?? "",
      requestIp: info.remoteAddr.hostname,
      userAgent: request.headers.get("user-agent"),
      bindingSecret,
    });

    if (!verified) {
      return new Response("invalid or expired link", { status: 401 });
    }

    return new Response(null, {
      status: 302,
      headers: buildVerifyResponseHeaders(
        new URL(verified.redirectTo, "https://console.example.local").href,
        [
          buildBindingClearCookie({
            secure: true,
            bindingCookieName: "__Host-ml-bind",
          }),
          buildSessionSetCookie(verified.sessionId, {
            secure: true,
            maxAgeSeconds: auth.sessionCookieMaxAgeSeconds(),
            sessionCookieName: "__Host-session",
          }),
        ],
      ),
    });
  }

  return new Response("not found", { status: 404 });
}

declare function lookupUserByEmail(email: string): Promise<
  {
    id: string;
    email: string;
    authVersion: number;
    active: boolean;
    role?: string;
  } | null
>;

declare function lookupUserById(id: string): Promise<
  {
    id: string;
    email: string;
    authVersion: number;
    active: boolean;
    role?: string;
  } | null
>;
```

## RBAC Quick Start

RBAC is optional. When enabled, role permissions are resolved during login and
stored in the session as a minimal authorization snapshot.

```ts
import {
  buildSessionSetCookie,
  buildVerifyResponseHeaders,
  DenoKvMagicLinkAuth,
  getCookie,
  hasPermission,
} from "jsr:@synitio/kv-magic-link-auth";

const kv = await Deno.openKv();

const auth = new DenoKvMagicLinkAuth(
  {
    appBaseUrl: "https://console.example.local",
    authDevExposeMagicLink: true,
    rbac: {
      enabled: true,
      roles: {
        viewer: ["dashboard:read"],
        editor: ["dashboard:read", "posts:edit"],
        admin: ["dashboard:read", "posts:edit", "users:manage"],
      },
      defaultRole: "viewer",
      permissionsVersion: 1,
    },
  },
  {
    kv,
    findUserByEmail: async (email) => {
      const row = await lookupUserByEmail(email);
      if (!row) return null;
      return {
        id: row.id,
        email: row.email,
        authVersion: row.authVersion,
        active: row.active,
        // The package resolves this role to permissions during login.
        role: row.role,
        isSuperAdmin: row.isSuperAdmin,
      };
    },
    findUserById: async (id) => {
      const row = await lookupUserById(id);
      if (!row) return null;
      return {
        id: row.id,
        email: row.email,
        authVersion: row.authVersion,
        active: row.active,
        role: row.role,
        isSuperAdmin: row.isSuperAdmin,
      };
    },
  },
);

export async function handleRequest(
  request: Request,
  info: Deno.ServeHandlerInfo<Deno.NetAddr>,
): Promise<Response> {
  const url = new URL(request.url);

  if (url.pathname === "/api/auth/magic-link/verify") {
    const verified = await auth.verifyMagicLink({
      token: url.searchParams.get("token") ?? "",
      requestIp: info.remoteAddr.hostname,
      userAgent: request.headers.get("user-agent"),
    });

    if (!verified) {
      return new Response("invalid or expired link", { status: 401 });
    }

    return new Response(null, {
      status: 302,
      headers: buildVerifyResponseHeaders(
        new URL(verified.redirectTo, "https://console.example.local").href,
        [
          buildSessionSetCookie(verified.sessionId, {
            secure: true,
            maxAgeSeconds: auth.sessionCookieMaxAgeSeconds(),
            sessionCookieName: "__Host-session",
          }),
        ],
      ),
    });
  }

  if (url.pathname === "/admin/users") {
    const sessionId = getCookie(request.headers, "__Host-session");
    if (!sessionId) {
      return new Response("not authenticated", { status: 401 });
    }

    const session = await auth.getSession(sessionId);
    if (!session) {
      return new Response("session expired", { status: 401 });
    }

    // The check below is pure and does not hit KV.
    if (!hasPermission(session, "users:manage")) {
      return new Response("forbidden", { status: 403 });
    }

    return Response.json({
      role: session.role,
      permissions: session.authorization?.permissions ?? [],
    });
  }

  return new Response("not found", { status: 404 });
}

declare function lookupUserByEmail(email: string): Promise<
  {
    id: string;
    email: string;
    authVersion: number;
    active: boolean;
    role?: string;
    isSuperAdmin?: boolean;
  } | null
>;

declare function lookupUserById(id: string): Promise<
  {
    id: string;
    email: string;
    authVersion: number;
    active: boolean;
    role?: string;
    isSuperAdmin?: boolean;
  } | null
>;
```

## Advanced RBAC Example

This example shows:

- request-scope session loading
- super-admin support
- version-based authorization invalidation
- route checks with `hasRole()` and `hasPermission()`

```ts
import {
  buildSessionSetCookie,
  buildVerifyResponseHeaders,
  DenoKvMagicLinkAuth,
  getCookie,
  hasPermission,
  hasRole,
  isSessionAuthorizationCurrent,
} from "jsr:@synitio/kv-magic-link-auth";

const kv = await Deno.openKv();

const RBAC_PERMISSIONS_VERSION = 4;

const auth = new DenoKvMagicLinkAuth(
  {
    appBaseUrl: "https://console.example.local",
    appName: "Example Console",
    rbac: {
      enabled: true,
      roles: {
        viewer: ["dashboard:read"],
        billing_admin: ["dashboard:read", "billing:read", "billing:manage"],
        workspace_admin: ["dashboard:read", "users:manage", "settings:manage"],
      },
      defaultRole: "viewer",
      permissionsVersion: RBAC_PERMISSIONS_VERSION,
    },
  },
  {
    kv,
    findUserByEmail: lookupUserByEmail,
    findUserById: lookupUserById,
    sendMail: async ({ to, subject, text, html }) => {
      const response = await fetch("https://mailer.example.local/send", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ to, subject, text, html }),
      });
      return { ok: response.ok };
    },
  },
);

export async function handleRequest(
  request: Request,
  info: Deno.ServeHandlerInfo<Deno.NetAddr>,
): Promise<Response> {
  const url = new URL(request.url);

  if (url.pathname === "/api/auth/magic-link/verify") {
    const verified = await auth.verifyMagicLink({
      token: url.searchParams.get("token") ?? "",
      requestIp: info.remoteAddr.hostname,
      userAgent: request.headers.get("user-agent"),
    });

    if (!verified) {
      return new Response("invalid or expired link", { status: 401 });
    }

    return new Response(null, {
      status: 302,
      headers: buildVerifyResponseHeaders(
        new URL(verified.redirectTo, "https://console.example.local").href,
        [
          buildSessionSetCookie(verified.sessionId, {
            secure: true,
            maxAgeSeconds: auth.sessionCookieMaxAgeSeconds(),
            sessionCookieName: "__Host-session",
          }),
        ],
      ),
    });
  }

  const sessionId = getCookie(request.headers, "__Host-session");
  if (!sessionId) {
    return new Response("not authenticated", { status: 401 });
  }

  // Load once, then reuse for all checks in this request.
  const session = await auth.getSession(sessionId);
  if (!session) {
    return new Response("session expired", { status: 401 });
  }

  // If your app already loads fresh user state elsewhere, compare versions
  // instead of doing any session fan-out updates in KV.
  const currentUser = await lookupCurrentUserById(session.userId);
  if (
    !currentUser ||
    !isSessionAuthorizationCurrent(session, {
      authVersion: currentUser.authVersion,
      permissionsVersion: RBAC_PERMISSIONS_VERSION,
    })
  ) {
    return new Response("session requires re-authentication", { status: 401 });
  }

  if (url.pathname === "/admin/billing") {
    if (!hasPermission(session, "billing:manage")) {
      return new Response("forbidden", { status: 403 });
    }
    return new Response("billing admin area");
  }

  if (url.pathname === "/admin/workspace") {
    if (!hasRole(session, "workspace_admin")) {
      return new Response("forbidden", { status: 403 });
    }
    return new Response("workspace admin area");
  }

  return new Response("not found", { status: 404 });
}

declare function lookupUserByEmail(email: string): Promise<
  {
    id: string;
    email: string;
    authVersion: number;
    active: boolean;
    role?: string;
    isSuperAdmin?: boolean;
  } | null
>;

declare function lookupUserById(id: string): Promise<
  {
    id: string;
    email: string;
    authVersion: number;
    active: boolean;
    role?: string;
    isSuperAdmin?: boolean;
  } | null
>;

declare function lookupCurrentUserById(id: string): Promise<
  {
    id: string;
    authVersion: number;
  } | null
>;
```

## API Summary

### `DenoKvMagicLinkAuth`

- `issueMagicLink(input)` issues one login link for the user and stores its
  hashed verification record in Deno KV. `issued` means a link is stored. `sent`
  means mail was delivered. `error` is for the application only.
- `verifyMagicLink(input)` validates and consumes a link, then creates a session
- `getSession(sessionId)` returns a current session or `null`. It calls
  `findUserById` and deletes the session when that user can no longer sign in.
- `revokeSession(sessionId)` deletes one hashed session
- `revokeUserSessions(userId)` deletes every session issued for that user
- `sessionCookieMaxAgeSeconds()` returns the cookie lifetime shared with the
  session record
- `magicLinkVerifyPath` is the verify pathname joined onto `appBaseUrl`

### RBAC helpers

- `hasRole(session, role)`
- `hasPermission(session, permission)`
- `hasAnyPermission(session, permissions)`
- `isSuperAdmin(session)`
- `isSessionAuthorizationCurrent(session, expectedVersions)`

These helpers are pure. They do not read from KV.

### Config highlights

- `allowedEmailPatterns` accepts exact addresses such as `"admin@example.com"`
  and domain patterns such as `"*@example.com"`. A domain pattern matches that
  domain only.
- `initialSuperAdminEmail` marks the matching authenticated user as
  `isSuperAdmin` when the user record does not set the flag itself
- `failedAuthRateLimitMaxAttempts`, `failedAuthRateLimitWindowMinutes`, and
  `failedAuthRateLimitBlockMinutes` throttle repeated failed login and
  verification requests from the same canonical IP address
- `sendRateLimitMaxPerEmail`, `sendRateLimitMaxPerIp`, and
  `sendRateLimitWindowMinutes` limit successful login mail
- `magicLinkVerifyPath` sets the verify path joined onto `appBaseUrl`
- `renderMagicLinkEmail` replaces the English login message. The rendered text
  or HTML must contain the verification URL.
- `appBaseUrl` is an `http` or `https` origin plus an optional path.
  Credentials, query strings, and hashes are rejected.
- `rbac` enables optional role-to-permission mapping and session-cached
  authorization snapshots. Duplicate role names are rejected. A user with no
  role is not assigned `viewer` unless `defaultRole` says so.

### Cookie helpers

- `buildSessionSetCookie`
- `buildSessionClearCookie`
- `buildBindingSetCookie`
- `buildBindingClearCookie`
- `buildVerifyResponseHeaders`
- `getCookie`

Cookie names default to `__Host-session` and `__Host-ml-bind`. Both require
`Secure`, and `__Host-` cookies use `Path=/`. On local HTTP, choose names
without a `__Host-` or `__Secure-` prefix and set `secure: false`. Pass
`maxAgeSeconds: auth.sessionCookieMaxAgeSeconds()` so the cookie ends with the
session. The default lifetime is 7 days. `getCookie` returns `null` when the
same name appears twice. `buildVerifyResponseHeaders` sets `Location`,
`Referrer-Policy: no-referrer`, `Cache-Control: no-store`, and the session
cookie. The login token stays in the verification query string; the referrer
policy keeps that URL out of the next request.

## Security Notes

- Email requests can be restricted to explicit addresses or one exact domain
- Repeated failed login and verification requests from the same canonical IP are
  temporarily blocked
- Redirect targets are constrained to the configured application origin
- Verification links include only a one-time token in query params and never
  include an email address
- A link issued with a binding secret requires that secret. IP plus user-agent
  matching is used only when no binding secret was issued.
- Used, expired, and superseded links are rejected. Verification rechecks the
  current email allowlist and the user's email and `authVersion` from issuance.
- Session and binding cookies are `HttpOnly`, `Secure`, and `SameSite=Lax` by
  default, allowing top-level navigation from an email link
- `requestIp` is required. Pass a canonical address from transport metadata or
  an explicitly trusted proxy, never an unchecked forwarding header.
- `getSession()` keeps a session only while `findUserById` returns the same
  active user, email, `authVersion`, and super-admin flag. With RBAC enabled,
  `permissionsVersion` must match too.
- RBAC permission data is stored as a minimal session snapshot, not as a policy
  source of truth
- Login responses that callers can see should carry a generic acceptance. Keep
  `sent`, `debugUrl`, and `error` in server logs.

### Upgrading to 0.4.0

Sessions and magic links written by 0.3.0 stop working. Session keys are now
hashes of the cookie value, and a magic link without the current-user pointer is
rejected. Ask users to request a new link after deploying.

Cookie helpers default to `__Host-session` and `__Host-ml-bind`, with a 7 day
`Max-Age`. HTTP development cannot use those names: set a name without the
prefix and pass `secure: false`. Clear any legacy `ml_bind` cookie at
`Path=/api/auth/magic-link/verify` when a deployed binding cookie moves to
`Path=/`.

`appBaseUrl` can no longer contain credentials, a query string, or a hash.
`requestIp` must be present and is canonicalized before it is used as a key or a
binding value. A binding secret shorter than 16 characters is rejected at
issuance. The built-in login mail is English unless `renderMagicLinkEmail` is
set. `getSession()` now calls `findUserById` on every load.

Keep state-changing routes protected with POST plus origin or CSRF validation.
`SameSite=Lax` lets an emailed link carry the binding cookie, and it is not a
complete CSRF defense. Set `sameSite: "Strict"` only when verification finishes
on a later same-site request. Use the same cookie configuration when setting and
clearing cookies.

Return the verification response from `buildVerifyResponseHeaders` so the
browser receives `Location`, `Set-Cookie`, and `Referrer-Policy: no-referrer`
together. Increment `authVersion` when credentials change, and
`permissionsVersion` when role permissions change. `revokeUserSessions(userId)`
clears every session for one user.

## Low-KV Deployment Guidance

- Load the session once per request and pass the loaded object through your
  handlers. That load is one KV read plus `findUserById`.
- Use RBAC helpers on the loaded session object instead of reading policy from
  KV
- Keep role-to-permission mapping in application config, not in KV
- Bump `authVersion` or `permissionsVersion` when authorization changes.
  `getSession()` drops sessions that no longer match, and `revokeUserSessions()`
  can delete them immediately.
- Idle and absolute deadlines are fixed at issuance. The effective lifetime is
  the earlier of the two.

## Development

See [DEVELOPMENT.md](./DEVELOPMENT.md) for local checks and release workflow.
GitHub Actions also runs `deno task check` plus `deno task e2e` on pull requests
targeting `main` and pushes to `main`, and a scheduled workflow opens
dependency-update PRs for Deno imports. After merged `chore/deno-dependencies*`
PRs, a cleanup workflow removes orphaned update branches.

## E2E Testing

Run the Docker Compose based end-to-end suite with:

```bash
deno task e2e
```

This boots a local Mailpit SMTP server plus a small Deno HTTP app that uses this
package with a real SMTP transport, runs the E2E tests, and tears the stack down
automatically.

## License

MIT. See `LICENSE.md`.
