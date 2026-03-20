import {
  assert,
  assertEquals,
  assertMatch,
  assertRejects,
  assertThrows,
} from "@std/assert";

import {
  buildBindingClearCookie,
  buildBindingSetCookie,
  buildSessionClearCookie,
  buildSessionSetCookie,
  DenoKvMagicLinkAuth,
  getCookie,
} from "./mod.ts";
import type {
  DenoKvMagicLinkAuthDeps,
  MagicLinkAuthUser,
  SendMailPayload,
} from "./types.ts";

const DEFAULT_USER: MagicLinkAuthUser = {
  id: "user-1",
  email: "Admin@Example.com",
  authVersion: 1,
  active: true,
  role: "admin",
};

function createNow(start = "2026-03-20T10:00:00.000Z") {
  let current = new Date(start);
  return {
    now: () => new Date(current),
    advanceMs(ms: number) {
      current = new Date(current.getTime() + ms);
    },
  };
}

async function withTestKv(fn: (kv: Deno.Kv) => Promise<void>) {
  const path = await Deno.makeTempFile({ suffix: ".sqlite3" });
  const kv = await Deno.openKv(path);
  try {
    await fn(kv);
  } finally {
    kv.close();
    await Deno.remove(path);
  }
}

function createDeps(
  kv: Deno.Kv,
  options: {
    user?: MagicLinkAuthUser | null;
    now?: () => Date;
    onSendMail?: (payload: SendMailPayload) => void;
  } = {},
): DenoKvMagicLinkAuthDeps {
  const user = options.user ?? DEFAULT_USER;
  return {
    kv,
    now: options.now,
    findUserByEmail: (email) =>
      Promise.resolve(
        user && user.email.trim().toLowerCase() === email ? user : null,
      ),
    findUserById: (id) => Promise.resolve(user && user.id === id ? user : null),
    sendMail: options.onSendMail
      ? (payload) => {
        options.onSendMail?.(payload);
        return Promise.resolve({ ok: true });
      }
      : undefined,
  };
}

function tokenFromUrl(url: string): string {
  const token = new URL(url).searchParams.get("token");
  if (!token) {
    throw new Error("Expected token in debug URL.");
  }
  return token;
}

Deno.test("issueMagicLink normalizes email and exposes debug URL in debug mode", async () => {
  await withTestKv(async (kv) => {
    const auth = new DenoKvMagicLinkAuth(
      {
        appBaseUrl: "https://app.example.com/",
        authDevExposeMagicLink: true,
      },
      createDeps(kv),
    );

    const result = await auth.issueMagicLink({
      email: "  ADMIN@example.com ",
      redirectTo: "/dashboard",
      requestIp: " 127.0.0.1 ",
      userAgent: " Firefox ",
      bindingSecret: " cookie-secret ",
    });

    assertEquals(result.sent, false);
    assert(result.debugUrl);

    const token = tokenFromUrl(result.debugUrl);
    const verified = await auth.verifyMagicLink({
      token,
      requestIp: "127.0.0.1",
      userAgent: "firefox",
      bindingSecret: "cookie-secret",
    });

    assert(verified);
    assertEquals(verified.redirectTo, "/dashboard");
    assertEquals(verified.user.id, DEFAULT_USER.id);
  });
});

Deno.test("verifyMagicLink rejects open redirects and mismatched verification context", async () => {
  await withTestKv(async (kv) => {
    const auth = new DenoKvMagicLinkAuth(
      {
        appBaseUrl: "https://app.example.com",
        authDevExposeMagicLink: true,
      },
      createDeps(kv),
    );

    const issued = await auth.issueMagicLink({
      email: DEFAULT_USER.email,
      redirectTo: "https://evil.example/steal",
      requestIp: "10.0.0.5",
      userAgent: "Browser",
    });

    const token = tokenFromUrl(issued.debugUrl!);

    const rejected = await auth.verifyMagicLink({
      token,
      requestIp: "10.0.0.5",
      userAgent: "DifferentBrowser",
    });
    assertEquals(rejected, null);

    const verified = await auth.verifyMagicLink({
      token,
      requestIp: "10.0.0.5",
      userAgent: "browser",
    });

    assert(verified);
    assertEquals(verified.redirectTo, "/admin/dashboard");
  });
});

Deno.test("verifyMagicLink only allows a token to be consumed once", async () => {
  await withTestKv(async (kv) => {
    const auth = new DenoKvMagicLinkAuth(
      {
        appBaseUrl: "https://app.example.com",
        authDevExposeMagicLink: true,
      },
      createDeps(kv),
    );

    const issued = await auth.issueMagicLink({
      email: DEFAULT_USER.email,
      requestIp: "10.0.0.5",
      userAgent: "Browser",
    });

    const token = tokenFromUrl(issued.debugUrl!);

    const first = await auth.verifyMagicLink({
      token,
      requestIp: "10.0.0.5",
      userAgent: "browser",
    });
    const second = await auth.verifyMagicLink({
      token,
      requestIp: "10.0.0.5",
      userAgent: "browser",
    });

    assert(first);
    assertEquals(second, null);
  });
});

Deno.test("getSession respects idle and absolute expiry and revokeSession deletes the session", async () => {
  await withTestKv(async (kv) => {
    const clock = createNow();
    const auth = new DenoKvMagicLinkAuth(
      {
        appBaseUrl: "https://app.example.com",
        authDevExposeMagicLink: true,
        magicLinkTtlMinutes: 5,
        sessionIdleTtlDays: 1,
        sessionAbsoluteTtlDays: 2,
      },
      createDeps(kv, { now: clock.now }),
    );

    const issued = await auth.issueMagicLink({
      email: DEFAULT_USER.email,
      requestIp: "10.0.0.5",
      userAgent: "Browser",
    });

    const verified = await auth.verifyMagicLink({
      token: tokenFromUrl(issued.debugUrl!),
      requestIp: "10.0.0.5",
      userAgent: "browser",
    });
    assert(verified);

    assert(await auth.getSession(verified.sessionId));

    clock.advanceMs(24 * 60 * 60 * 1000 + 1);
    assertEquals(await auth.getSession(verified.sessionId), null);

    await auth.revokeSession(verified.sessionId);
    assertEquals(await auth.getSession(verified.sessionId), null);
  });
});

Deno.test("issueMagicLink expires old tokens", async () => {
  await withTestKv(async (kv) => {
    const clock = createNow();
    const auth = new DenoKvMagicLinkAuth(
      {
        appBaseUrl: "https://app.example.com",
        authDevExposeMagicLink: true,
        magicLinkTtlMinutes: 1,
      },
      createDeps(kv, { now: clock.now }),
    );

    const issued = await auth.issueMagicLink({
      email: DEFAULT_USER.email,
      requestIp: "10.0.0.5",
      userAgent: "Browser",
    });

    clock.advanceMs(60_001);

    const verified = await auth.verifyMagicLink({
      token: tokenFromUrl(issued.debugUrl!),
      requestIp: "10.0.0.5",
      userAgent: "browser",
    });

    assertEquals(verified, null);
  });
});

Deno.test("sendMail is used when enabled and issueMagicLink reports sent=true", async () => {
  await withTestKv(async (kv) => {
    const sentPayloads: SendMailPayload[] = [];
    const auth = new DenoKvMagicLinkAuth(
      {
        appBaseUrl: "https://app.example.com",
        appName: "Synit Auth",
        authDevExposeMagicLink: true,
        sendEmailInDebugMode: true,
      },
      createDeps(kv, {
        onSendMail(payload) {
          sentPayloads.push(payload);
        },
      }),
    );

    const result = await auth.issueMagicLink({
      email: DEFAULT_USER.email,
      requestIp: "10.0.0.5",
      userAgent: "Browser",
    });

    assertEquals(result.sent, true);
    assert(result.debugUrl);
    const payload = sentPayloads[0];
    assert(payload);
    assertEquals(payload.to, DEFAULT_USER.email);
    assertMatch(payload.subject, /Synit Auth/);
  });
});

Deno.test("cookie helpers encode values, reject invalid names, and tolerate malformed input", () => {
  const headers = new Headers({
    cookie: "session=abc%20123; other=test",
  });
  assertEquals(getCookie(headers, "session"), "abc 123");
  assertEquals(
    getCookie(new Headers({ cookie: "session=%E0%A4%A" }), "session"),
    null,
  );

  const sessionCookie = buildSessionSetCookie("session value", {
    secure: true,
    sessionCookieName: "__Host-session",
    sessionAbsoluteTtlDays: 14,
  });
  assertMatch(sessionCookie, /^__Host-session=session%20value;/);
  assertMatch(sessionCookie, /HttpOnly/);
  assertMatch(sessionCookie, /Secure/);

  const clearSessionCookie = buildSessionClearCookie({
    sessionCookieName: "__Host-session",
  });
  assertMatch(clearSessionCookie, /Expires=Thu, 01 Jan 1970 00:00:00 GMT/);

  const bindingCookie = buildBindingSetCookie("bind=value", 60, {
    bindingCookieName: "__Host-ml-bind",
  });
  assertMatch(bindingCookie, /^__Host-ml-bind=bind%3Dvalue;/);

  const clearBindingCookie = buildBindingClearCookie({
    bindingCookieName: "__Host-ml-bind",
  });
  assertMatch(clearBindingCookie, /Path=\/api\/auth\/magic-link\/verify/);

  assertThrows(
    () => {
      buildSessionSetCookie("x", { sessionCookieName: "bad name" });
    },
    Error,
    "Invalid session cookie name.",
  );
});

Deno.test("constructor validates config", () => {
  assertRejects(
    () =>
      withTestKv((kv) => {
        new DenoKvMagicLinkAuth(
          {
            appBaseUrl: "javascript:alert(1)",
          },
          createDeps(kv),
        );
        return Promise.resolve();
      }),
    Error,
    "appBaseUrl must use http or https.",
  );
});
