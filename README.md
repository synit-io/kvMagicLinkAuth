# kv-magic-link-auth

Deno KV backed magic-link authentication with optional RBAC for server-side Deno
applications.

Maintained by [synit.io](https://www.synit.io).

## Features

- One-time magic-link issuance backed by Deno KV
- Atomic link consumption to prevent replay races
- Session persistence in Deno KV
- Optional email-address and domain allowlist support
- Failed-login rate limiting per originating IP address
- Initial super-admin propagation into verified users and stored sessions
- Optional binding checks with cookie secret or IP plus user-agent matching
- Optional RBAC with session-cached role and permission snapshots
- Pure role and permission helper APIs for request-time checks
- Cookie helpers for session and verification-bound cookies
- Docker Compose backed E2E coverage with Mailpit and a local auth test app
- Works well with Fresh, Hono, and custom Deno HTTP services

## Why this package

This package is designed for apps that want:

- passwordless sign-in with a small API surface
- secure one-time magic links
- low operational overhead on Deno KV
- optional authorization without adding per-request policy lookups

The package keeps the normal authenticated request path small:

- one session read from KV
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
      sent: issued.sent,
      // Debug URLs are useful locally. Do not expose them in production APIs.
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

    const headers = new Headers();
    headers.append(
      "set-cookie",
      buildSessionSetCookie(verified.sessionId, {
        secure: true,
        sessionCookieName: "__Host-session",
      }),
    );

    headers.set(
      "location",
      new URL(verified.redirectTo, "https://app.example.local").href,
    );
    return new Response(null, { status: 302, headers });
  }

  if (url.pathname === "/me") {
    const sessionId = getCookie(request.headers, "__Host-session");
    if (!sessionId) {
      return new Response("not authenticated", { status: 401 });
    }

    // Keep this to one read per request. Reuse the loaded session object below.
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

1. `issueMagicLink()` normalizes the login request, checks allowlists and rate
   limits, then stores a hashed token record in Deno KV.
2. `verifyMagicLink()` loads the token record, validates the verification
   context, atomically marks the token as used, and creates a session.
3. `getSession()` loads the session and enforces idle and absolute expiry
   without mutating KV on every request.

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

- successful login request: one failed-attempt read plus one magic-link write
- link verification: one link read and one atomic consume-plus-session write
- authenticated request: one session read
- RBAC helper checks after the session is loaded: zero KV operations

## Basic Auth Example

This example shows a production-oriented setup with allowlists and real mail
delivery. Return the same `202` response whether an account exists, is blocked,
or receives mail; keep the internal `sent` result out of public responses. The
example addresses and mail endpoint are placeholders for your application.

Apply ingress limits per trusted client IP and per recipient before issuing
links. The package's failed-attempt limiter does not limit successful email
issuance, so separate delivery quotas are required to prevent mailbox flooding
and excessive mail or storage costs.

```ts
import {
  buildSessionClearCookie,
  buildSessionSetCookie,
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

    const headers = new Headers();
    headers.append(
      "set-cookie",
      buildSessionSetCookie(verified.sessionId, {
        secure: true,
        sessionCookieName: "__Host-session",
      }),
    );

    headers.set(
      "location",
      new URL(verified.redirectTo, "https://console.example.local").href,
    );
    return new Response(null, { status: 302, headers });
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

This variant adds binding-secret verification. A cookie set on the device that
requested the link can complete verification even if its IP changes. Matching IP
and user-agent values remain an alternative; the cookie is not mandatory.

```ts
import {
  buildBindingClearCookie,
  buildBindingSetCookie,
  buildSessionSetCookie,
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

    const headers = new Headers();
    headers.append(
      "set-cookie",
      buildBindingClearCookie({
        secure: true,
        bindingCookieName: "__Host-ml-bind",
      }),
    );
    headers.append(
      "set-cookie",
      buildSessionSetCookie(verified.sessionId, {
        secure: true,
        sessionCookieName: "__Host-session",
      }),
    );

    headers.set(
      "location",
      new URL(verified.redirectTo, "https://console.example.local").href,
    );
    return new Response(null, { status: 302, headers });
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
      headers: {
        location: new URL(
          verified.redirectTo,
          "https://console.example.local",
        ).href,
        "set-cookie": buildSessionSetCookie(verified.sessionId, {
          secure: true,
          sessionCookieName: "__Host-session",
        }),
      },
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
      headers: {
        location: new URL(
          verified.redirectTo,
          "https://console.example.local",
        ).href,
        "set-cookie": buildSessionSetCookie(verified.sessionId, {
          secure: true,
          sessionCookieName: "__Host-session",
        }),
      },
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

- `issueMagicLink(input)` issues a one-time login link and stores its hashed
  verification record in Deno KV
- `verifyMagicLink(input)` validates and consumes a link, then creates a session
- `getSession(sessionId)` returns a valid session record or `null`
- `revokeSession(sessionId)` deletes a session from Deno KV

### RBAC helpers

- `hasRole(session, role)`
- `hasPermission(session, permission)`
- `hasAnyPermission(session, permissions)`
- `isSuperAdmin(session)`
- `isSessionAuthorizationCurrent(session, expectedVersions)`

These helpers are pure. They do not read from KV.

### Config highlights

- `allowedEmailPatterns` accepts exact addresses such as `"admin@example.com"`
  and domain wildcards such as `"*@example.com"`
- `initialSuperAdminEmail` marks the matching authenticated user as
  `isSuperAdmin`
- `failedAuthRateLimitMaxAttempts`, `failedAuthRateLimitWindowMinutes`, and
  `failedAuthRateLimitBlockMinutes` throttle repeated failed login requests from
  the same IP address
- `rbac` enables optional role-to-permission mapping and session-cached
  authorization snapshots

### Cookie helpers

- `buildSessionSetCookie`
- `buildSessionClearCookie`
- `buildBindingSetCookie`
- `buildBindingClearCookie`
- `getCookie`

## Security Notes

- Email requests can be restricted to explicit addresses or whole domains
- Repeated failed login requests from the same IP are temporarily blocked
- Redirect targets are constrained to the configured application origin
- Verification links include only a one-time token in query params and never
  include an email address
- Link verification requires either a matching binding secret or a matching IP
  plus user-agent pair
- Used and expired links are rejected; verification rechecks the current email
  allowlist and the user's email and `authVersion` from issuance
- Session and binding cookies are `HttpOnly`, `Secure`, and `SameSite=Lax` by
  default, allowing top-level navigation from an email link
- `requestIp` must come from transport metadata or an explicitly trusted proxy,
  not an unchecked forwarding header
- RBAC permission data is stored as a minimal session snapshot, not as a policy
  source of truth

### Upgrading existing integrations

New magic links are bound to the user's email and `authVersion` at issuance.
Links issued before this change lack that version snapshot and are rejected; ask
users to request a fresh link after deploying the upgrade. Increment
`authVersion` when changing credentials or revoking outstanding links. Existing
sessions still require the application's version check shown in the Advanced
RBAC Example.

Cookie helpers now default to `SameSite=Lax` so browsers can send the binding
cookie when following a top-level email link. `__Host-` cookies use `Path=/` and
require `Secure`. Keep state-changing routes protected with POST plus origin or
CSRF validation; SameSite alone is not a complete CSRF defense. Clear any legacy
`ml_bind` cookie at `Path=/api/auth/magic-link/verify` when switching a deployed
binding cookie to `Path=/`.

Set `sameSite: "Strict"` explicitly on cookie helpers only when your login flow
provides an intermediate page that completes verification through a subsequent
same-site request. Use the same cookie configuration when setting and clearing
cookies.

Update verification handlers to `/api/auth/magic-link/verify`, and return a
response containing both `Location` and `Set-Cookie`. The examples above show
this response and the trusted transport context required for IP checks.

## Low-KV Deployment Guidance

- Load the session once per request and pass the loaded object through your
  handlers
- Use RBAC helpers on the loaded session object instead of reloading state
- Keep role-to-permission mapping in application config, not in KV
- Use version invalidation for auth changes instead of rewriting every session
- If you later add sliding sessions, throttle any write-back behavior heavily

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
