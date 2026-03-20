# kv-magic-link-auth

Deno KV backed magic-link authentication for server-side Deno applications.

Maintained by [synit.io](https://www.synit.io).

## Features

- One-time magic-link issuance backed by Deno KV.
- Atomic link consumption to prevent replay races.
- Session persistence in Deno KV.
- Optional binding checks with cookie secret or IP plus user-agent matching.
- Cookie helpers for session and verification-bound cookies.
- Works well with Fresh, Hono, and custom Deno HTTP services.

## Install

### Deno

```sh
deno add jsr:@synitio/kv-magic-link-auth
```

```ts
import { DenoKvMagicLinkAuth } from "jsr:@synitio/kv-magic-link-auth";
```

## Requirements

- Deno 2 with Deno KV support.
- Run applications and tests with `--unstable-kv` when opening a KV database
  locally.
- Your application provides user lookup functions and an optional mail sender.

## Minimal example

```ts
import {
  buildSessionSetCookie,
  DenoKvMagicLinkAuth,
} from "jsr:@synitio/kv-magic-link-auth";

const kv = await Deno.openKv();

const auth = new DenoKvMagicLinkAuth(
  {
    appBaseUrl: "https://app.example.local",
    appName: "Synit Console",
  },
  {
    kv,
    findUserByEmail: async (email) => {
      if (email !== "admin@example.local") return null;
      return {
        id: "u_1",
        email: "admin@example.local",
        authVersion: 1,
        active: true,
        role: "admin",
      };
    },
    findUserById: async (id) => {
      if (id !== "u_1") return null;
      return {
        id: "u_1",
        email: "admin@example.local",
        authVersion: 1,
        active: true,
        role: "admin",
      };
    },
  },
);

const issued = await auth.issueMagicLink({
  email: "admin@example.local",
  redirectTo: "/admin/dashboard",
  requestIp: "203.0.113.10",
  userAgent: "Mozilla/5.0",
});

if (issued.debugUrl) {
  console.log("Debug login URL:", issued.debugUrl);
}

const verified = await auth.verifyMagicLink({
  token: "token-from-query-param",
  requestIp: "203.0.113.10",
  userAgent: "Mozilla/5.0",
});

if (verified) {
  const setCookie = buildSessionSetCookie(verified.sessionId, { secure: true });
  console.log(setCookie);
}
```

## Advanced example

This example combines binding-secret verification, redirect sanitization, and
real mail delivery hooks.

```ts
import {
  buildBindingSetCookie,
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
    magicLinkTtlMinutes: 10,
    sessionIdleTtlDays: 7,
    sessionAbsoluteTtlDays: 30,
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

export async function handleRequest(request: Request): Promise<Response> {
  const url = new URL(request.url);

  if (url.pathname === "/auth/request" && request.method === "POST") {
    const bindingSecret = crypto.randomUUID();
    const issued = await auth.issueMagicLink({
      email: "admin@example.local",
      redirectTo: url.searchParams.get("redirectTo") ?? "/admin/dashboard",
      requestIp: request.headers.get("x-forwarded-for"),
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

    return new Response(JSON.stringify({ sent: issued.sent }), { headers });
  }

  if (url.pathname === "/auth/verify") {
    const bindingSecret = getCookie(request.headers, "__Host-ml-bind");
    const verified = await auth.verifyMagicLink({
      token: url.searchParams.get("token") ?? "",
      requestIp: request.headers.get("x-forwarded-for"),
      userAgent: request.headers.get("user-agent"),
      bindingSecret,
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

    return Response.redirect(
      new URL(verified.redirectTo, "https://console.example.local"),
      302,
      { headers },
    );
  }

  if (url.pathname === "/auth/logout") {
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

## API summary

### `DenoKvMagicLinkAuth`

- `issueMagicLink(input)` issues a one-time login link and stores its
  verification record in Deno KV.
- `verifyMagicLink(input)` validates and consumes a link, then creates a session
  record.
- `getSession(sessionId)` returns a valid session record or `null`.
- `revokeSession(sessionId)` deletes a session from Deno KV.

### Cookie helpers

- `buildSessionSetCookie`
- `buildSessionClearCookie`
- `buildBindingSetCookie`
- `buildBindingClearCookie`
- `getCookie`

## Security notes

- Redirect targets are constrained to the configured application origin.
- Link verification requires either a matching binding secret or a matching IP
  plus user-agent pair.
- Used and expired links are rejected.
- Session and binding cookies are `HttpOnly` and `SameSite=Lax` by default.

## Development

See [DEVELOPMENT.md](./DEVELOPMENT.md) for local checks and release workflow.

## License

MIT. See `LICENSE.md`.
