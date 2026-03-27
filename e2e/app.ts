import nodemailer from "nodemailer";

import { DenoKvMagicLinkAuth } from "../mod.ts";
import type { MagicLinkAuthUser } from "../types.ts";

const PORT = Number(Deno.env.get("PORT") ?? "8080");
const SMTP_HOST = Deno.env.get("SMTP_HOST") ?? "mailpit";
const SMTP_PORT = Number(Deno.env.get("SMTP_PORT") ?? "1025");
const APP_BASE_URL = Deno.env.get("APP_BASE_URL") ??
  `http://127.0.0.1:${PORT}`;
const KV_PATH = Deno.env.get("KV_PATH") ?? "/tmp/kv-magic-link-e2e.sqlite3";

const USERS: MagicLinkAuthUser[] = [
  {
    id: "admin-1",
    email: "admin@example.com",
    authVersion: 1,
    active: true,
    role: "admin",
  },
  {
    id: "user-1",
    email: "member@example.com",
    authVersion: 1,
    active: true,
    role: "viewer",
  },
  {
    id: "guest-1",
    email: "special@outside.example",
    authVersion: 1,
    active: true,
    role: "editor",
  },
];

const kv = await Deno.openKv(KV_PATH);
const transporter = nodemailer.createTransport({
  host: SMTP_HOST,
  port: SMTP_PORT,
  secure: false,
  ignoreTLS: true,
});

const auth = new DenoKvMagicLinkAuth(
  {
    appBaseUrl: APP_BASE_URL,
    appName: "KV Magic Link E2E",
    allowedEmailPatterns: ["*@example.com", "special@outside.example"],
    initialSuperAdminEmail: "admin@example.com",
    failedAuthRateLimitMaxAttempts: 3,
    failedAuthRateLimitWindowMinutes: 15,
    failedAuthRateLimitBlockMinutes: 15,
  },
  {
    kv,
    findUserByEmail: (email) =>
      Promise.resolve(USERS.find((user) => user.email === email) ?? null),
    findUserById: (id) =>
      Promise.resolve(USERS.find((user) => user.id === id) ?? null),
    sendMail: async ({ to, subject, text, html }) => {
      try {
        await transporter.sendMail({
          from: "auth@example.com",
          to,
          subject,
          text,
          html,
        });
        return { ok: true };
      } catch (error) {
        return {
          ok: false,
          error: error instanceof Error ? error.message : String(error),
        };
      }
    },
  },
);

function json(data: unknown, init?: ResponseInit): Response {
  return new Response(JSON.stringify(data), {
    ...init,
    headers: {
      "content-type": "application/json",
      ...(init?.headers ?? {}),
    },
  });
}

function requestContext(request: Request) {
  return {
    requestIp: request.headers.get("x-forwarded-for"),
    userAgent: request.headers.get("user-agent"),
  };
}

Deno.addSignalListener("SIGTERM", async () => {
  kv.close();
  await transporter.close();
  Deno.exit(0);
});

Deno.serve({ port: PORT }, async (request) => {
  const url = new URL(request.url);

  if (url.pathname === "/health") {
    return json({ ok: true });
  }

  if (
    (url.pathname === "/auth/request" ||
      url.pathname === "/api/auth/magic-link/request") &&
    request.method === "POST"
  ) {
    const body = await request.json().catch(() => null) as
      | { email?: string; redirectTo?: string }
      | null;
    const issued = await auth.issueMagicLink({
      email: body?.email ?? "",
      redirectTo: body?.redirectTo,
      ...requestContext(request),
    });
    return json(issued, { status: issued.sent ? 200 : 401 });
  }

  if (
    (url.pathname === "/auth/verify" ||
      url.pathname === "/api/auth/magic-link/verify") &&
    request.method === "GET"
  ) {
    const verified = await auth.verifyMagicLink({
      token: url.searchParams.get("token") ?? "",
      ...requestContext(request),
    });
    if (!verified) {
      return json({ ok: false }, { status: 401 });
    }
    const session = await auth.getSession(verified.sessionId);
    return json({
      ok: true,
      sessionId: verified.sessionId,
      redirectTo: verified.redirectTo,
      user: verified.user,
      session,
    });
  }

  return json({ error: "not found" }, { status: 404 });
});
