import { assert, assertEquals, assertRejects, assertThrows } from "@std/assert";

import {
  buildSessionSetCookie,
  buildVerifyResponseHeaders,
  DenoKvMagicLinkAuth,
  getCookie,
  hasRole,
} from "./mod.ts";
import type {
  MagicLinkAuthUser,
  SendMailPayload,
  SessionRecord,
} from "./types.ts";

const NOW = new Date("2026-10-02T12:00:00.000Z");

function createUser(
  overrides: Partial<MagicLinkAuthUser> = {},
): MagicLinkAuthUser {
  return {
    id: "user-1",
    email: "admin@example.com",
    authVersion: 1,
    active: true,
    role: "admin",
    ...overrides,
  };
}

async function withKv(run: (kv: Deno.Kv) => Promise<void> | void) {
  const kv = await Deno.openKv(":memory:");
  try {
    await run(kv);
  } finally {
    kv.close();
  }
}

function createAuth(
  kv: Deno.Kv,
  options: {
    user?: MagicLinkAuthUser;
    config?: ConstructorParameters<typeof DenoKvMagicLinkAuth>[0];
    onSendMail?: (payload: SendMailPayload) => { ok: boolean; error?: string };
    users?: MagicLinkAuthUser[];
  } = {},
) {
  let user = options.user ?? createUser();
  const users = options.users;
  const auth = new DenoKvMagicLinkAuth(
    {
      appBaseUrl: "https://app.example.com",
      authDevExposeMagicLink: true,
      ...options.config,
    },
    {
      kv,
      now: () => new Date(NOW),
      findUserByEmail: (email) => {
        if (users) {
          return Promise.resolve(
            users.find((entry) => entry.email.toLowerCase() === email) ?? null,
          );
        }
        return Promise.resolve(
          user.email.trim().toLowerCase() === email ? user : null,
        );
      },
      findUserById: (id) => {
        if (users) {
          return Promise.resolve(
            users.find((entry) => entry.id === id) ?? null,
          );
        }
        return Promise.resolve(user.id === id ? user : null);
      },
      sendMail: options.onSendMail
        ? (payload) => Promise.resolve(options.onSendMail!(payload))
        : undefined,
    },
  );
  return {
    auth,
    updateUser(changes: Partial<MagicLinkAuthUser>) {
      user = { ...user, ...changes };
    },
  };
}

async function tokenFrom(auth: DenoKvMagicLinkAuth, input: {
  email?: string;
  redirectTo?: string;
  requestIp?: string;
  userAgent?: string;
  bindingSecret?: string;
} = {}) {
  const issued = await auth.issueMagicLink({
    email: input.email ?? "admin@example.com",
    redirectTo: input.redirectTo,
    requestIp: input.requestIp ?? "203.0.113.10",
    userAgent: input.userAgent ?? "Browser",
    bindingSecret: input.bindingSecret,
  });
  assert(issued.debugUrl, issued.error);
  const token = new URL(issued.debugUrl).searchParams.get("token");
  assert(token);
  return { issued, token };
}

Deno.test("appBaseUrl rejects credentials, queries, and hashes", async () => {
  await withKv((kv) => {
    for (
      const appBaseUrl of [
        "https://user:secret@app.example.com",
        "https://app.example.com?x=1",
        "https://app.example.com#frag",
      ]
    ) {
      assertThrows(
        () => {
          new DenoKvMagicLinkAuth({ appBaseUrl }, {
            kv,
            findUserByEmail: () => Promise.resolve(null),
            findUserById: () => Promise.resolve(null),
          });
        },
        Error,
        "appBaseUrl",
      );
    }
  });
});

Deno.test("verification links join a base path and a custom verify path", async () => {
  await withKv(async (kv) => {
    const { auth } = createAuth(kv, {
      config: {
        appBaseUrl: "https://app.example.com/base",
        magicLinkVerifyPath: "/sign-in",
        authDevExposeMagicLink: true,
      },
    });
    const { issued } = await tokenFrom(auth);
    assertEquals(
      issued.debugUrl?.split("?")[0],
      "https://app.example.com/base/sign-in",
    );
    assertEquals(auth.magicLinkVerifyPath, "/base/sign-in");
  });
});

Deno.test("a new magic link supersedes the previous unconsumed link", async () => {
  await withKv(async (kv) => {
    const { auth } = createAuth(kv);
    const first = await tokenFrom(auth);
    const second = await tokenFrom(auth);
    assertEquals(
      await auth.verifyMagicLink({
        token: first.token,
        requestIp: "203.0.113.10",
        userAgent: "browser",
      }),
      null,
    );
    assert(
      await auth.verifyMagicLink({
        token: second.token,
        requestIp: "203.0.113.10",
        userAgent: "browser",
      }),
    );
  });
});

Deno.test("a stored binding secret is required even when IP and user agent match", async () => {
  await withKv(async (kv) => {
    const { auth } = createAuth(kv);
    const { token } = await tokenFrom(auth, {
      bindingSecret: "binding-secret-value",
    });
    assertEquals(
      await auth.verifyMagicLink({
        token,
        requestIp: "203.0.113.10",
        userAgent: "browser",
        bindingSecret: "wrong-binding-secret",
      }),
      null,
    );
    const verified = await auth.verifyMagicLink({
      token,
      requestIp: "198.51.100.8",
      userAgent: "other-browser",
      bindingSecret: "binding-secret-value",
    });
    assert(verified);
  });
});

Deno.test("live sessions end when the user is disabled, changes email, or loses super-admin", async () => {
  await withKv(async (kv) => {
    const { auth, updateUser } = createAuth(kv, {
      config: {
        appBaseUrl: "https://app.example.com",
        authDevExposeMagicLink: true,
        initialSuperAdminEmail: "admin@example.com",
      },
    });
    const { token } = await tokenFrom(auth);
    const verified = await auth.verifyMagicLink({
      token,
      requestIp: "203.0.113.10",
      userAgent: "browser",
    });
    assert(verified);
    assertEquals(
      (await auth.getSession(verified.sessionId))?.isSuperAdmin,
      true,
    );

    updateUser({ isSuperAdmin: false });
    assertEquals(await auth.getSession(verified.sessionId), null);

    const second = await tokenFrom(auth);
    const again = await auth.verifyMagicLink({
      token: second.token,
      requestIp: "203.0.113.10",
      userAgent: "browser",
    });
    assert(again);
    updateUser({ active: false });
    assertEquals(await auth.getSession(again.sessionId), null);
    const sessions = await Array.fromAsync(
      kv.list({ prefix: ["dka", "sessions"] }),
    );
    assertEquals(sessions.length, 0);
  });
});

Deno.test("credential and permission version changes revoke the stored session", async () => {
  await withKv(async (kv) => {
    const { auth, updateUser } = createAuth(kv, {
      config: {
        appBaseUrl: "https://app.example.com",
        authDevExposeMagicLink: true,
        rbac: {
          enabled: true,
          roles: { admin: ["dashboard:read"] },
          permissionsVersion: 1,
        },
      },
    });
    const { token } = await tokenFrom(auth);
    const verified = await auth.verifyMagicLink({
      token,
      requestIp: "203.0.113.10",
      userAgent: "browser",
    });
    assert(verified);
    updateUser({ authVersion: 2 });
    assertEquals(await auth.getSession(verified.sessionId), null);

    updateUser({ authVersion: 1 });
    const nextLink = await tokenFrom(auth);
    const next = await auth.verifyMagicLink({
      token: nextLink.token,
      requestIp: "203.0.113.10",
      userAgent: "browser",
    });
    assert(next);
    const { auth: upgraded } = createAuth(kv, {
      config: {
        appBaseUrl: "https://app.example.com",
        authDevExposeMagicLink: true,
        rbac: {
          enabled: true,
          roles: { admin: ["dashboard:read"] },
          permissionsVersion: 2,
        },
      },
    });
    assertEquals(await upgraded.getSession(next.sessionId), null);
  });
});

Deno.test("session ids are not stored as KV keys and revokeUserSessions clears them", async () => {
  await withKv(async (kv) => {
    const { auth } = createAuth(kv);
    const first = await tokenFrom(auth);
    const firstSession = await auth.verifyMagicLink({
      token: first.token,
      requestIp: "203.0.113.10",
      userAgent: "browser",
    });
    assert(firstSession);
    const second = await tokenFrom(auth);
    const secondSession = await auth.verifyMagicLink({
      token: second.token,
      requestIp: "203.0.113.10",
      userAgent: "browser",
    });
    assert(secondSession);

    const raw = await kv.get(["dka", "sessions", firstSession.sessionId]);
    assertEquals(raw.value, null);
    const stored = await Array.fromAsync(
      kv.list({ prefix: ["dka", "sessions"] }),
    );
    assertEquals(stored.length, 2);
    assert(stored.every((entry) => entry.key[2] !== firstSession.sessionId));

    await auth.revokeUserSessions("user-1");
    assertEquals(await auth.getSession(firstSession.sessionId), null);
    assertEquals(await auth.getSession(secondSession.sessionId), null);
  });
});

Deno.test("IP literals share one rate-limit bucket and a missing IP fails closed", async () => {
  await withKv(async (kv) => {
    const { auth } = createAuth(kv, {
      config: {
        appBaseUrl: "https://app.example.com",
        authDevExposeMagicLink: true,
        failedAuthRateLimitMaxAttempts: 1,
      },
    });
    await auth.issueMagicLink({
      email: "missing@example.com",
      requestIp: "2001:DB8::1",
      userAgent: "Browser",
    });
    const mixedCase = await auth.issueMagicLink({
      email: "admin@example.com",
      requestIp: "2001:db8::1",
      userAgent: "Browser",
    });
    assertEquals(mixedCase.error, "rate_limited");
    const keys = await Array.fromAsync(
      kv.list({ prefix: ["dka", "failed_auth_attempts"] }),
    );
    assertEquals(keys.map((entry) => entry.key[2]), ["2001:db8::1"]);

    const { auth: mapped } = createAuth(kv, {
      config: {
        appBaseUrl: "https://app.example.com",
        authDevExposeMagicLink: true,
        failedAuthRateLimitMaxAttempts: 1,
        keyPrefix: "mapped",
      },
    });
    await mapped.issueMagicLink({
      email: "missing@example.com",
      requestIp: "203.0.113.010",
      userAgent: "Browser",
    });
    const canonical = await mapped.issueMagicLink({
      email: "admin@example.com",
      requestIp: "::ffff:203.0.113.10",
      userAgent: "Browser",
    });
    assertEquals(canonical.error, "rate_limited");

    const missingIp = await auth.issueMagicLink({
      email: "admin@example.com",
      userAgent: "Browser",
    });
    assertEquals(missingIp.issued, false);
    assertEquals(missingIp.debugUrl, undefined);
  });
});

Deno.test("allowlist rejects ambiguous addresses and a mismatched directory email", async () => {
  await withKv(async (kv) => {
    const sent: string[] = [];
    const { auth } = createAuth(kv, {
      user: createUser({ email: "a@b@example.com" }),
      config: {
        appBaseUrl: "https://app.example.com",
        authDevExposeMagicLink: true,
        allowedEmailPatterns: ["*@example.com"],
      },
      onSendMail: (payload) => {
        sent.push(payload.to);
        return { ok: true };
      },
    });
    const ambiguous = await auth.issueMagicLink({
      email: "a@b@example.com",
      requestIp: "203.0.113.10",
      userAgent: "Browser",
    });
    assertEquals(ambiguous.issued, false);

    const relayed = await new DenoKvMagicLinkAuth({
      appBaseUrl: "https://app.example.com",
      authDevExposeMagicLink: true,
      allowedEmailPatterns: ["*@example.com"],
      sendEmailInDebugMode: true,
    }, {
      kv,
      findUserByEmail: (email) =>
        Promise.resolve(
          email === "admin@example.com"
            ? createUser({ email: "attacker@evil.test" })
            : null,
        ),
      findUserById: () => Promise.resolve(null),
      sendMail: (payload) => {
        sent.push(payload.to);
        return Promise.resolve({ ok: true });
      },
    }).issueMagicLink({
      email: "admin@example.com",
      requestIp: "203.0.113.44",
      userAgent: "Browser",
    });
    assertEquals(relayed.issued, false);
    assertEquals(sent, []);
  });
});

Deno.test("mail failures keep the delivery error and do not leave a hidden live link", async () => {
  await withKv(async (kv) => {
    const { auth } = createAuth(kv, {
      config: {
        appBaseUrl: "https://app.example.com",
        authDevExposeMagicLink: false,
        appName: "A\nB <Admin>",
      },
      onSendMail: () => ({ ok: false, error: "smtp down" }),
    });
    const hidden = await auth.issueMagicLink({
      email: "admin@example.com",
      requestIp: "203.0.113.10",
      userAgent: "Browser",
    });
    assertEquals(hidden, {
      issued: false,
      sent: false,
      error: "smtp down",
    });
    assertEquals(
      (await Array.fromAsync(kv.list({ prefix: ["dka", "magic_links"] })))
        .length,
      0,
    );

    const payloads: SendMailPayload[] = [];
    const { auth: debugAuth } = createAuth(kv, {
      config: {
        appBaseUrl: "https://app.example.com",
        authDevExposeMagicLink: true,
        sendEmailInDebugMode: true,
        appName: "A\nB <Admin>",
        renderMagicLinkEmail: ({ appName, verificationUrl, ttlMinutes }) => ({
          subject: `${appName} login`,
          text: verificationUrl,
          html: `<a href="${verificationUrl}">${ttlMinutes}</a>`,
        }),
      },
      onSendMail: (payload) => {
        payloads.push(payload);
        return { ok: false, error: "smtp down" };
      },
    });
    const visible = await debugAuth.issueMagicLink({
      email: "admin@example.com",
      requestIp: "203.0.113.11",
      userAgent: "Browser",
    });
    assertEquals(visible.issued, true);
    assertEquals(visible.sent, false);
    assertEquals(visible.error, "smtp down");
    assert(visible.debugUrl);
    assertEquals(payloads[0]?.subject.includes("\n"), false);
    assert(payloads[0]?.text.includes("token="));
  });
});

Deno.test("successful send and failed verification budgets are enforced", async () => {
  await withKv(async (kv) => {
    const { auth } = createAuth(kv, {
      config: {
        appBaseUrl: "https://app.example.com",
        authDevExposeMagicLink: true,
        sendRateLimitMaxPerEmail: 2,
        failedAuthRateLimitMaxAttempts: 2,
      },
    });
    assert((await tokenFrom(auth)).issued.issued);
    assert((await tokenFrom(auth)).issued.issued);
    const limited = await auth.issueMagicLink({
      email: "admin@example.com",
      requestIp: "203.0.113.10",
      userAgent: "Browser",
    });
    assertEquals(limited.error, "rate_limited");
    assertEquals(limited.debugUrl, undefined);

    const { auth: verifyAuth } = createAuth(kv, {
      config: {
        appBaseUrl: "https://app.example.com",
        authDevExposeMagicLink: true,
        failedAuthRateLimitMaxAttempts: 2,
        keyPrefix: "verify-budget",
      },
    });
    const { token } = await tokenFrom(verifyAuth);
    for (const attempt of ["bad-token-one", "bad-token-two"]) {
      assertEquals(
        await verifyAuth.verifyMagicLink({
          token: attempt,
          requestIp: "203.0.113.80",
          userAgent: "Browser",
        }),
        null,
      );
    }
    assertEquals(
      await verifyAuth.verifyMagicLink({
        token,
        requestIp: "203.0.113.80",
        userAgent: "browser",
      }),
      null,
    );
    const blocked = await kv.get([
      "verify-budget",
      "failed_verify_attempts",
      "203.0.113.80",
    ]);
    assert(blocked.value);
  });
});

Deno.test("an unknown RBAC role does not throw or leave a usable link", async () => {
  await withKv(async (kv) => {
    const { auth } = createAuth(kv, {
      user: createUser({ role: "nope" }),
      config: {
        appBaseUrl: "https://app.example.com",
        authDevExposeMagicLink: true,
        rbac: { enabled: true, roles: { admin: ["dashboard:read"] } },
      },
    });
    const issued = await auth.issueMagicLink({
      email: "admin@example.com",
      requestIp: "203.0.113.10",
      userAgent: "Browser",
    });
    assertEquals(issued.issued, false);
    assertEquals(
      (await Array.fromAsync(kv.list({ prefix: ["dka", "magic_links"] })))
        .length,
      0,
    );

    const { auth: changing, updateUser } = createAuth(kv, {
      config: {
        appBaseUrl: "https://app.example.com",
        authDevExposeMagicLink: true,
        rbac: { enabled: true, roles: { admin: ["dashboard:read"] } },
        keyPrefix: "rbac-change",
      },
    });
    const { token } = await tokenFrom(changing);
    updateUser({ role: "nope" });
    assertEquals(
      await changing.verifyMagicLink({
        token,
        requestIp: "203.0.113.10",
        userAgent: "browser",
      }),
      null,
    );
    assertEquals(
      (await Array.fromAsync(kv.list({ prefix: ["rbac-change", "sessions"] })))
        .length,
      0,
    );
  });
});

Deno.test("users without a role are not treated as viewers", async () => {
  await withKv(async (kv) => {
    const { auth } = createAuth(kv, {
      user: createUser({ role: undefined }),
    });
    const { token } = await tokenFrom(auth);
    const verified = await auth.verifyMagicLink({
      token,
      requestIp: "203.0.113.10",
      userAgent: "browser",
    });
    assert(verified);
    const session = await auth.getSession(verified.sessionId);
    assert(session);
    assertEquals(session.role, "");
    assertEquals(hasRole(session, "viewer"), false);
  });
});

Deno.test("configuration rejects duplicate roles, inverted TTLs, and short binding secrets", async () => {
  await withKv(async (kv) => {
    assertThrows(
      () => {
        new DenoKvMagicLinkAuth({
          appBaseUrl: "https://app.example.com",
          sessionIdleTtlDays: 30,
          sessionAbsoluteTtlDays: 7,
        }, {
          kv,
          findUserByEmail: () => Promise.resolve(null),
          findUserById: () => Promise.resolve(null),
        });
      },
      Error,
      "sessionIdleTtlDays must not exceed sessionAbsoluteTtlDays.",
    );
    assertThrows(
      () => {
        new DenoKvMagicLinkAuth({
          appBaseUrl: "https://app.example.com",
          rbac: {
            enabled: true,
            roles: { Admin: ["a:one"], admin: ["b:two"] },
          },
        }, {
          kv,
          findUserByEmail: () => Promise.resolve(null),
          findUserById: () => Promise.resolve(null),
        });
      },
      Error,
      'rbac role "admin" is declared more than once.',
    );
    const { auth } = createAuth(kv);
    await assertRejects(
      () =>
        auth.issueMagicLink({
          email: "admin@example.com",
          requestIp: "203.0.113.10",
          userAgent: "Browser",
          bindingSecret: "too-short",
        }),
      Error,
      "bindingSecret must be between 16 and 512 characters.",
    );
  });
});

Deno.test("a link without the current-user pointer cannot be consumed", async () => {
  await withKv(async (kv) => {
    const { auth } = createAuth(kv);
    const { token } = await tokenFrom(auth);
    for await (
      const entry of kv.list({ prefix: ["dka", "magic_link_current"] })
    ) {
      await kv.delete(entry.key);
    }
    assertEquals(
      await auth.verifyMagicLink({
        token,
        requestIp: "203.0.113.10",
        userAgent: "browser",
      }),
      null,
    );
  });
});

Deno.test("failed-attempt writes stop after the retry cap", async () => {
  await withKv(async (kv) => {
    let commits = 0;
    const wrapped = new Proxy(kv, {
      get(target, property, receiver) {
        if (property === "atomic") {
          return () => {
            const atomic = target.atomic();
            atomic.commit = () => {
              commits += 1;
              return Promise.resolve({ ok: false });
            };
            return atomic;
          };
        }
        const value = Reflect.get(target, property, receiver);
        return typeof value === "function" ? value.bind(target) : value;
      },
    });
    const { auth } = createAuth(wrapped);
    const started = Date.now();
    const result = await auth.issueMagicLink({
      email: "missing@example.com",
      requestIp: "203.0.113.70",
      userAgent: "Browser",
    });
    assertEquals(result.issued, false);
    assert(Date.now() - started < 1_000);
    assert(commits > 0);
    assert(commits <= 8);
  });
});

Deno.test("sessions fail closed when stored state or the live user is no longer valid", async () => {
  await withKv(async (kv) => {
    let now = new Date(NOW);
    const user = createUser({ isSuperAdmin: false });
    const auth = new DenoKvMagicLinkAuth({
      appBaseUrl: "https://app.example.com",
      authDevExposeMagicLink: true,
      initialSuperAdminEmail: "admin@example.com",
    }, {
      kv,
      now: () => now,
      findUserByEmail: () => Promise.resolve(user),
      findUserById: () => Promise.resolve(user),
    });
    const { token } = await tokenFrom(auth);
    const verified = await auth.verifyMagicLink({
      token,
      requestIp: "203.0.113.10",
      userAgent: "browser",
    });
    assert(verified);
    assertEquals(verified.user.isSuperAdmin, false);
    const session = await auth.getSession(verified.sessionId);
    assert(session);
    assertEquals(session.isSuperAdmin, false);
    assertEquals(session.authorization, undefined);
    now = new Date(now.getTime() + 60_000);
    assertEquals(
      (await auth.getSession(verified.sessionId))?.idleExpiresAt,
      session.idleExpiresAt,
    );

    const stored = await Array.fromAsync(
      kv.list<SessionRecord>({ prefix: ["dka", "sessions"] }),
    );
    assertEquals(stored.length, 1);
    await kv.set(stored[0].key, {
      ...stored[0].value,
      authorization: {
        role: "admin",
        permissions: ["secret:read"],
        permissionsVersion: 1,
      },
    });
    assertEquals(
      (await auth.getSession(verified.sessionId))?.authorization,
      undefined,
    );

    await kv.set(stored[0].key, {
      ...stored[0].value,
      revokedAt: NOW.toISOString(),
    });
    assertEquals(await auth.getSession(verified.sessionId), null);
    assertEquals(
      (await Array.fromAsync(kv.list({ prefix: ["dka", "sessions"] }))).length,
      0,
    );
    assertEquals(
      (await Array.fromAsync(kv.list({ prefix: ["dka", "user_sessions"] })))
        .length,
      0,
    );

    const again = await auth.verifyMagicLink({
      token: (await tokenFrom(auth)).token,
      requestIp: "203.0.113.10",
      userAgent: "browser",
    });
    assert(again);
    const rows = await Array.fromAsync(
      kv.list<SessionRecord>({ prefix: ["dka", "sessions"] }),
    );
    await kv.set(rows[0].key, { ...rows[0].value, idleExpiresAt: "" });
    assertEquals(await auth.getSession(again.sessionId), null);
  });
});

Deno.test("delivery and verification keep the remaining review boundaries", async () => {
  await withKv(async (kv) => {
    const sent: string[] = [];
    const { auth } = createAuth(kv, {
      user: createUser({ email: "Admin@Example.com" }),
      config: {
        appBaseUrl: "https://app.example.com",
        authDevExposeMagicLink: true,
        sendEmailInDebugMode: true,
        allowedEmailPatterns: ["*@example.com"],
        failedAuthRateLimitMaxAttempts: 100,
        renderMagicLinkEmail: () => ({
          subject: "Hello\r\nBcc: attacker@evil.test",
          text: "missing link",
          html: "<p>missing link</p>",
        }),
      },
      onSendMail: (payload) => {
        sent.push(`${payload.to}|${payload.subject}|${payload.text}`);
        return { ok: true };
      },
    });

    for (
      const email of [
        "admin/root@example.com",
        "admin:root@example.com",
        "ad min@example.com",
        "user@sub.example.com",
        "user@example.com.evil",
      ]
    ) {
      assertEquals(
        (await auth.issueMagicLink({
          email,
          requestIp: "203.0.113.10",
          userAgent: "Browser",
        })).issued,
        false,
        email,
      );
    }

    const issued = await auth.issueMagicLink({
      email: "admin@example.com",
      requestIp: "203.0.113.10",
      userAgent: "Browser",
      redirectTo: `https://evil.example/${"a".repeat(2048)}`,
    });
    assert(issued.debugUrl);
    assertEquals(sent[0]?.split("|")[0], "admin@example.com");
    assert(sent[0]?.includes("Your login link"));
    assertEquals(sent[0]?.includes("Bcc:"), false);
    assert(sent[0]?.includes(issued.debugUrl));
    const verified = await auth.verifyMagicLink({
      token: new URL(issued.debugUrl).searchParams.get("token") ?? "",
      requestIp: "203.0.113.10",
      userAgent: "browser",
    });
    assertEquals(verified?.redirectTo, "/admin/dashboard");

    assertEquals(
      (await auth.issueMagicLink({
        email: "missing@example.com",
        requestIp: "203.0.113.90",
        userAgent: "Browser",
      })).issued,
      false,
    );
    assertEquals(
      (await Array.fromAsync(kv.list({ prefix: ["dka", "send_budget_ip"] })))
        .some((entry) => entry.key[2] === "203.0.113.90"),
      false,
    );

    assertEquals(
      (await auth.issueMagicLink({
        email: "admin@example.com",
        requestIp: "203.0.113.91",
        userAgent: "x".repeat(1025),
      })).issued,
      false,
    );

    const bound = await tokenFrom(auth, {
      bindingSecret: "binding-secret-value",
      requestIp: "203.0.113.92",
    });
    assertEquals(
      await auth.verifyMagicLink({
        token: bound.token,
        requestIp: "203.0.113.92",
        userAgent: "browser",
        bindingSecret: "short",
      }),
      null,
    );
    assertEquals(
      await auth.verifyMagicLink({
        token: "   ",
        requestIp: "203.0.113.93",
        userAgent: "browser",
      }),
      null,
    );
    assertEquals(
      (await Array.fromAsync(kv.list({
        prefix: ["dka", "failed_verify_attempts", "203.0.113.93"],
      }))).length,
      0,
    );

    const sanitized: string[] = [];
    const { auth: custom } = createAuth(kv, {
      config: {
        appBaseUrl: "https://app.example.com",
        authDevExposeMagicLink: true,
        sendEmailInDebugMode: true,
        keyPrefix: "custom-mail",
        renderMagicLinkEmail: ({ verificationUrl }) => ({
          subject: "Sign in\r\nBcc: attacker@evil.test",
          text: verificationUrl,
          html: `<a href="${verificationUrl}">Sign in</a>`,
        }),
      },
      onSendMail: (payload) => {
        sanitized.push(payload.subject);
        return { ok: true };
      },
    });
    assert((await tokenFrom(custom)).issued.issued);
    assertEquals(sanitized[0], "Sign in Bcc: attacker@evil.test");

    const { auth: failing } = createAuth(kv, {
      config: {
        appBaseUrl: "https://app.example.com",
        authDevExposeMagicLink: false,
        keyPrefix: "mail-error",
      },
      onSendMail: () => ({ ok: false, error: "smtp\r\ndown" }),
    });
    assertEquals(
      (await failing.issueMagicLink({
        email: "admin@example.com",
        requestIp: "203.0.113.94",
        userAgent: "Browser",
      })).error,
      "smtp down",
    );

    const { auth: zoned } = createAuth(kv, {
      config: {
        appBaseUrl: "https://app.example.com",
        authDevExposeMagicLink: true,
        failedAuthRateLimitMaxAttempts: 1,
        keyPrefix: "zone",
      },
    });
    await zoned.issueMagicLink({
      email: "missing@example.com",
      requestIp: "2001:db8::5%eth0",
    });
    assertEquals(
      (await zoned.issueMagicLink({
        email: "admin@example.com",
        requestIp: "2001:DB8::5",
        userAgent: "Browser",
      })).error,
      "rate_limited",
    );
  });
});

Deno.test("cookie defaults match the effective session lifetime and reject ambiguous cookies", () => {
  const sessionCookie = buildSessionSetCookie("session-id");
  assert(sessionCookie.startsWith("__Host-session="));
  assert(sessionCookie.includes("Max-Age=604800"));
  const headers = buildVerifyResponseHeaders("https://app.example.com/admin", [
    sessionCookie,
  ]);
  assertEquals(headers.get("referrer-policy"), "no-referrer");
  assertEquals(headers.get("cache-control"), "no-store");
  assertEquals(
    getCookie(new Headers({ cookie: "session=one; session=two" }), "session"),
    null,
  );
  const emptyRole: SessionRecord = {
    userId: "user-1",
    userEmail: "admin@example.com",
    role: "",
    isSuperAdmin: false,
    authVersion: 1,
    createdAt: NOW.toISOString(),
    idleExpiresAt: NOW.toISOString(),
    absoluteExpiresAt: NOW.toISOString(),
  };
  assertEquals(hasRole(emptyRole, "viewer"), false);
});
