import {
  assert,
  assertEquals,
  assertMatch,
  assertRejects,
  assertStrictEquals,
  assertThrows,
} from "@std/assert";

import {
  buildBindingClearCookie,
  buildBindingSetCookie,
  buildSessionClearCookie,
  buildSessionSetCookie,
  DenoKvMagicLinkAuth,
  getCookie,
  hasAnyPermission,
  hasPermission,
  hasRole,
  isSessionAuthorizationCurrent,
} from "./mod.ts";
import type {
  DenoKvMagicLinkAuthDeps,
  MagicLinkAuthUser,
  SendMailPayload,
  SessionRecord,
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
    const debugQuery = new URL(result.debugUrl).searchParams;
    assertEquals(debugQuery.has("email"), false);

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
    assertEquals(verified.user.email, "admin@example.com");
  });
});

Deno.test("issueMagicLink only allows configured email addresses and domains", async () => {
  await withTestKv(async (kv) => {
    const allowedUser: MagicLinkAuthUser = {
      id: "user-2",
      email: "allowed@other.example",
      authVersion: 1,
      active: true,
      role: "editor",
    };
    const auth = new DenoKvMagicLinkAuth(
      {
        appBaseUrl: "https://app.example.com",
        authDevExposeMagicLink: true,
        allowedEmailPatterns: ["*@example.com", "allowed@other.example"],
      },
      {
        kv,
        findUserByEmail: (email) =>
          Promise.resolve(
            [DEFAULT_USER, allowedUser].find((user) =>
              user.email.toLowerCase() === email
            ) ?? null,
          ),
        findUserById: (id) =>
          Promise.resolve(
            [DEFAULT_USER, allowedUser].find((user) => user.id === id) ?? null,
          ),
      },
    );

    const allowedByDomain = await auth.issueMagicLink({
      email: DEFAULT_USER.email,
      requestIp: "10.0.0.5",
    });
    const blocked = await auth.issueMagicLink({
      email: "blocked@outside.example",
      requestIp: "10.0.0.5",
    });
    const allowedByExactAddress = await auth.issueMagicLink({
      email: "allowed@other.example",
      requestIp: "10.0.0.6",
    });

    assert(allowedByDomain.debugUrl);
    assertEquals(blocked.sent, false);
    assertStrictEquals(blocked.debugUrl, undefined);
    assert(allowedByExactAddress.debugUrl);
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

Deno.test("verifyMagicLink marks the configured initial super admin in user and session state", async () => {
  await withTestKv(async (kv) => {
    const auth = new DenoKvMagicLinkAuth(
      {
        appBaseUrl: "https://app.example.com",
        authDevExposeMagicLink: true,
        initialSuperAdminEmail: "admin@example.com",
      },
      createDeps(kv),
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
    assertEquals(verified.user.isSuperAdmin, true);

    const session = await auth.getSession(verified.sessionId);
    assert(session);
    assertEquals(session.isSuperAdmin, true);
  });
});

Deno.test("verifyMagicLink persists an RBAC authorization snapshot for fast permission checks", async () => {
  await withTestKv(async (kv) => {
    const auth = new DenoKvMagicLinkAuth(
      {
        appBaseUrl: "https://app.example.com",
        authDevExposeMagicLink: true,
        rbac: {
          enabled: true,
          roles: {
            viewer: ["dashboard:read"],
            admin: ["dashboard:read", "users:manage"],
          },
          defaultRole: "viewer",
          permissionsVersion: 3,
        },
      },
      createDeps(kv),
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
    const session = await auth.getSession(verified.sessionId);
    assert(session);
    assertEquals(session.role, "admin");
    assertEquals(session.authorization, {
      role: "admin",
      permissions: ["dashboard:read", "users:manage"],
      permissionsVersion: 3,
    });
    assertEquals(hasRole(session, "admin"), true);
    assertEquals(hasPermission(session, "users:manage"), true);
    assertEquals(
      hasAnyPermission(session, ["billing:manage", "users:manage"]),
      true,
    );
    assertEquals(hasPermission(session, "billing:manage"), false);
    assertEquals(
      isSessionAuthorizationCurrent(session, {
        authVersion: DEFAULT_USER.authVersion,
        permissionsVersion: 3,
      }),
      true,
    );

    const storedSession = session as unknown as Record<string, unknown>;
    assertEquals("bindingHash" in storedSession, false);
    assertEquals("token" in storedSession, false);
  });
});

Deno.test("RBAC default role applies when the user has no explicit role", async () => {
  await withTestKv(async (kv) => {
    const auth = new DenoKvMagicLinkAuth(
      {
        appBaseUrl: "https://app.example.com",
        authDevExposeMagicLink: true,
        rbac: {
          enabled: true,
          roles: {
            viewer: ["dashboard:read"],
            editor: ["dashboard:read", "posts:edit"],
          },
          defaultRole: "viewer",
        },
      },
      createDeps(kv, {
        user: {
          ...DEFAULT_USER,
          role: undefined,
        },
      }),
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
    const session = await auth.getSession(verified.sessionId);
    assert(session);
    assertEquals(session.role, "viewer");
    assertEquals(hasPermission(session, "dashboard:read"), true);
  });
});

Deno.test("authorization helpers fail closed for legacy sessions without an RBAC snapshot", () => {
  const session: SessionRecord = {
    userId: "user-1",
    userEmail: "admin@example.com",
    role: "admin",
    isSuperAdmin: false,
    authVersion: 1,
    createdAt: "2026-03-20T10:00:00.000Z",
    lastSeenAt: "2026-03-20T10:00:00.000Z",
    idleExpiresAt: "2026-03-21T10:00:00.000Z",
    absoluteExpiresAt: "2026-03-22T10:00:00.000Z",
    revokedAt: null,
  };

  assertEquals(hasRole(session, "admin"), true);
  assertEquals(hasPermission(session, "users:manage"), false);
  assertEquals(hasAnyPermission(session, ["users:manage"]), false);
  assertEquals(
    isSessionAuthorizationCurrent(session, { permissionsVersion: 1 }),
    false,
  );
});

Deno.test("super admins bypass RBAC permission checks", () => {
  const session: SessionRecord = {
    userId: "user-1",
    userEmail: "admin@example.com",
    role: "viewer",
    isSuperAdmin: true,
    authVersion: 1,
    authorization: {
      role: "viewer",
      permissions: ["dashboard:read"],
      permissionsVersion: 1,
    },
    createdAt: "2026-03-20T10:00:00.000Z",
    lastSeenAt: "2026-03-20T10:00:00.000Z",
    idleExpiresAt: "2026-03-21T10:00:00.000Z",
    absoluteExpiresAt: "2026-03-22T10:00:00.000Z",
    revokedAt: null,
  };

  assertEquals(hasRole(session, "admin"), true);
  assertEquals(hasPermission(session, "users:manage"), true);
});

Deno.test("issueMagicLink rate limits repeated failed attempts per IP", async () => {
  await withTestKv(async (kv) => {
    const auth = new DenoKvMagicLinkAuth(
      {
        appBaseUrl: "https://app.example.com",
        authDevExposeMagicLink: true,
        failedAuthRateLimitMaxAttempts: 3,
        failedAuthRateLimitWindowMinutes: 15,
        failedAuthRateLimitBlockMinutes: 30,
      },
      createDeps(kv),
    );

    for (let index = 0; index < 3; index += 1) {
      const result = await auth.issueMagicLink({
        email: `unknown-${index}@example.com`,
        requestIp: "203.0.113.10",
      });
      assertEquals(result.sent, false);
    }

    const blocked = await auth.issueMagicLink({
      email: DEFAULT_USER.email,
      requestIp: "203.0.113.10",
    });

    assertEquals(blocked.sent, false);
    assertStrictEquals(blocked.debugUrl, undefined);
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
  assertMatch(sessionCookie, /SameSite=Strict/);
  assertMatch(sessionCookie, /Secure/);

  const clearSessionCookie = buildSessionClearCookie({
    sessionCookieName: "__Host-session",
  });
  assertMatch(clearSessionCookie, /Secure/);
  assertMatch(clearSessionCookie, /SameSite=Strict/);
  assertMatch(clearSessionCookie, /Expires=Thu, 01 Jan 1970 00:00:00 GMT/);

  const bindingCookie = buildBindingSetCookie("bind=value", 60, {
    bindingCookieName: "__Host-ml-bind",
  });
  assertMatch(bindingCookie, /^__Host-ml-bind=bind%3Dvalue;/);
  assertMatch(bindingCookie, /Secure/);
  assertMatch(bindingCookie, /SameSite=Strict/);

  const clearBindingCookie = buildBindingClearCookie({
    bindingCookieName: "__Host-ml-bind",
  });
  assertMatch(clearBindingCookie, /Secure/);
  assertMatch(clearBindingCookie, /SameSite=Strict/);
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

  assertRejects(
    () =>
      withTestKv((kv) => {
        new DenoKvMagicLinkAuth(
          {
            appBaseUrl: "https://app.example.com",
            allowedEmailPatterns: ["admin*@example.com"],
          },
          createDeps(kv),
        );
        return Promise.resolve();
      }),
    Error,
    'allowedEmailPatterns entries must be exact email addresses or "*@domain.tld".',
  );

  assertRejects(
    () =>
      withTestKv((kv) => {
        new DenoKvMagicLinkAuth(
          {
            appBaseUrl: "https://app.example.com",
            rbac: {
              enabled: true,
              roles: {},
            },
          },
          createDeps(kv),
        );
        return Promise.resolve();
      }),
    Error,
    "rbac.roles must define at least one role when RBAC is enabled.",
  );

  assertRejects(
    () =>
      withTestKv((kv) => {
        new DenoKvMagicLinkAuth(
          {
            appBaseUrl: "https://app.example.com",
            rbac: {
              enabled: true,
              roles: {
                viewer: ["dashboard:read"],
              },
              defaultRole: "admin",
            },
          },
          createDeps(kv),
        );
        return Promise.resolve();
      }),
    Error,
    "rbac.defaultRole must reference a configured role.",
  );
});
