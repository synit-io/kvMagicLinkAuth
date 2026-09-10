import { assert, assertEquals } from "@std/assert";

import { DenoKvMagicLinkAuth } from "./mod.ts";
import type {
  DenoKvMagicLinkAuthConfig,
  FailedAuthAttemptRecord,
  MagicLinkAuthUser,
  MagicLinkRecord,
} from "./types.ts";

const APP_BASE_URL = "https://app.example.com";
const NOW = new Date("2026-09-10T12:00:00.000Z");
const CONTEXT = {
  requestIp: "203.0.113.10",
  userAgent: "Security Test Browser",
  bindingSecret: "security-test-binding-secret",
};

async function withKv(run: (kv: Deno.Kv) => Promise<void>) {
  const kv = await Deno.openKv(":memory:");
  try {
    await run(kv);
  } finally {
    kv.close();
  }
}

function createAuth(
  kv: Deno.Kv,
  config: Partial<DenoKvMagicLinkAuthConfig> = {},
) {
  let user: MagicLinkAuthUser = {
    id: "user-1",
    email: "Admin@Example.com",
    authVersion: 1,
    active: true,
    role: "viewer",
  };
  const auth = new DenoKvMagicLinkAuth({
    appBaseUrl: APP_BASE_URL,
    authDevExposeMagicLink: true,
    ...config,
  }, {
    kv,
    now: () => new Date(NOW),
    findUserByEmail: (email) =>
      Promise.resolve(user.email.trim().toLowerCase() === email ? user : null),
    findUserById: (id) => Promise.resolve(user.id === id ? user : null),
  });
  return {
    auth,
    updateUser(changes: Partial<MagicLinkAuthUser>) {
      user = { ...user, ...changes };
    },
  };
}

async function issueToken(auth: DenoKvMagicLinkAuth, redirectTo?: string) {
  const issued = await auth.issueMagicLink({
    email: "admin@example.com",
    redirectTo,
    ...CONTEXT,
  });
  assert(issued.debugUrl);
  const token = new URL(issued.debugUrl).searchParams.get("token");
  assert(token);
  return token;
}

async function entries<T>(kv: Deno.Kv, scope: string) {
  return await Array.fromAsync(kv.list<T>({ prefix: ["dka", scope] }));
}

async function bounded<T>(promise: Promise<T>, label: string): Promise<T> {
  let timeout: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      promise,
      new Promise<never>((_, reject) => {
        timeout = setTimeout(() => reject(new Error(label)), 5_000);
      }),
    ]);
  } finally {
    clearTimeout(timeout);
  }
}

function interceptReads(
  kv: Deno.Kv,
  afterRead: (key: Deno.KvKey) => Promise<void>,
): Deno.Kv {
  return new Proxy(kv, {
    get(target, property) {
      if (property === "get") {
        return async <T>(
          key: Deno.KvKey,
          options?: Parameters<Deno.Kv["get"]>[1],
        ) => {
          const entry = await target.get<T>(key, options);
          await afterRead(key);
          return entry;
        };
      }
      const value = Reflect.get(target, property, target);
      return typeof value === "function" ? value.bind(target) : value;
    },
  });
}

function readBarrier(kv: Deno.Kv, scope: string, participants: number) {
  let captured = 0;
  const release = Promise.withResolvers<void>();
  return interceptReads(kv, async (key) => {
    if (key[1] !== scope || captured >= participants) return;
    captured++;
    if (captured === participants) release.resolve();
    await bounded(release.promise, `Timed out waiting for ${scope} reads`);
  });
}

Deno.test("magic links preserve issuance identity and accept normalized unchanged email", async () => {
  await withKv(async (kv) => {
    const { auth, updateUser } = createAuth(kv);
    const token = await issueToken(auth);
    const [record] = await entries<MagicLinkRecord>(kv, "magic_links");
    assertEquals(record.value.emailNormalized, "admin@example.com");
    assertEquals(Reflect.get(record.value, "authVersion"), 1);

    updateUser({ email: "  ADMIN@EXAMPLE.COM  " });
    const verified = await auth.verifyMagicLink({ token, ...CONTEXT });
    assert(verified);
    const session = await auth.getSession(verified.sessionId);
    assert(session);
    assertEquals(session.userEmail, "admin@example.com");
    assertEquals(session.authVersion, 1);
  });
});

for (
  const [description, changes] of [
    ["email changes", { email: "replacement@example.com" }],
    ["authVersion changes", { authVersion: 2 }],
  ] satisfies [string, Partial<MagicLinkAuthUser>][]
) {
  Deno.test(`magic links reject outstanding tokens after ${description}`, async () => {
    await withKv(async (kv) => {
      const { auth, updateUser } = createAuth(kv);
      const token = await issueToken(auth);
      updateUser(changes);

      assertEquals(await auth.verifyMagicLink({ token, ...CONTEXT }), null);
      assertEquals((await entries(kv, "sessions")).length, 0);
    });
  });
}

Deno.test("magic links respect email allowlist changes made after issuance", async () => {
  await withKv(async (kv) => {
    const { auth } = createAuth(kv);
    const token = await issueToken(auth);
    const { auth: restrictedAuth } = createAuth(kv, {
      allowedEmailPatterns: ["*@other.example"],
    });

    assertEquals(
      await restrictedAuth.verifyMagicLink({ token, ...CONTEXT }),
      null,
    );
    assertEquals((await entries(kv, "sessions")).length, 0);
  });
});

Deno.test("magic links reject legacy records without an issuance authVersion", async () => {
  await withKv(async (kv) => {
    const { auth } = createAuth(kv);
    const token = await issueToken(auth);
    const [record] = await entries<MagicLinkRecord>(kv, "magic_links");
    const legacyRecord = { ...record.value };
    Reflect.deleteProperty(legacyRecord, "authVersion");
    await kv.set(record.key, legacyRecord);

    assertEquals(await auth.verifyMagicLink({ token, ...CONTEXT }), null);
    assertEquals((await entries(kv, "sessions")).length, 0);
  });
});

Deno.test("magic links keep redirect targets on the application origin after serialization", async () => {
  await withKv(async (kv) => {
    const { auth } = createAuth(kv);
    for (
      const redirectTo of [
        `${APP_BASE_URL}//evil.example/phish`,
        `${APP_BASE_URL}/safe/..//evil.example/phish`,
        "/safe/..//evil.example/phish",
        "//evil.example/phish",
        "https://evil.example/phish",
      ]
    ) {
      const token = await issueToken(auth, redirectTo);
      const verified = await auth.verifyMagicLink({ token, ...CONTEXT });
      assert(verified);
      assertEquals(
        new URL(verified.redirectTo, APP_BASE_URL).origin,
        APP_BASE_URL,
        redirectTo,
      );
    }

    const token = await issueToken(auth, "/dashboard?tab=security#sessions");
    const verified = await auth.verifyMagicLink({ token, ...CONTEXT });
    assert(verified);
    assertEquals(verified.redirectTo, "/dashboard?tab=security#sessions");
  });
});

Deno.test("magic links sanitize unsafe redirect targets already stored in KV", async () => {
  await withKv(async (kv) => {
    const { auth } = createAuth(kv);
    for (
      const redirectTo of [
        "//evil.example/phish",
        "https://evil.example/phish",
        `${APP_BASE_URL}//evil.example/phish`,
      ]
    ) {
      const token = await issueToken(auth);
      const record = (await entries<MagicLinkRecord>(kv, "magic_links"))
        .find((entry) => !entry.value.usedAt);
      assert(record);
      await kv.set(record.key, { ...record.value, redirectTo });

      const verified = await auth.verifyMagicLink({ token, ...CONTEXT });
      assert(verified);
      assertEquals(
        new URL(verified.redirectTo, APP_BASE_URL).origin,
        APP_BASE_URL,
        redirectTo,
      );
    }
  });
});

for (const initialCount of [0, 1]) {
  Deno.test(`concurrent failed requests enforce rate limit from count ${initialCount}`, async () => {
    await withKv(async (kv) => {
      const key = ["dka", "failed_auth_attempts", CONTEXT.requestIp];
      if (initialCount) {
        await kv.set(
          key,
          {
            count: initialCount,
            lastAttemptAt: NOW.toISOString(),
            blockedUntil: null,
          } satisfies FailedAuthAttemptRecord,
        );
      }
      const attempts = 12;
      const { auth } = createAuth(
        readBarrier(kv, "failed_auth_attempts", attempts),
        { failedAuthRateLimitMaxAttempts: 3 },
      );
      const results = await Promise.allSettled(
        Array.from({ length: attempts }, (_, index) =>
          auth.issueMagicLink({
            email: `unknown-${index}@example.com`,
            ...CONTEXT,
          })),
      );
      for (const result of results) {
        assertEquals(result.status, "fulfilled");
      }

      const record = (await kv.get<FailedAuthAttemptRecord>(key)).value;
      assert(record);
      assert(record.count >= 3);
      assert(record.blockedUntil);
      assert(Date.parse(record.blockedUntil) > NOW.getTime());
      const blocked = await auth.issueMagicLink({
        email: "admin@example.com",
        ...CONTEXT,
      });
      assertEquals(blocked.sent, false);
      assertEquals(blocked.debugUrl, undefined);
    });
  });
}

Deno.test("a delayed failed request cannot overwrite an established IP block", async () => {
  await withKv(async (kv) => {
    const key = ["dka", "failed_auth_attempts", CONTEXT.requestIp];
    await kv.set(
      key,
      {
        count: 1,
        lastAttemptAt: NOW.toISOString(),
        blockedUntil: null,
      } satisfies FailedAuthAttemptRecord,
    );
    const captured = Promise.withResolvers<void>();
    const release = Promise.withResolvers<void>();
    let paused = false;
    const delayedKv = interceptReads(kv, async (readKey) => {
      if (readKey[1] !== "failed_auth_attempts" || paused) return;
      paused = true;
      captured.resolve();
      await bounded(
        release.promise,
        "Timed out releasing stale rate-limit read",
      );
    });
    const { auth } = createAuth(delayedKv, {
      failedAuthRateLimitMaxAttempts: 3,
    });
    const staleRequest = auth.issueMagicLink({
      email: "delayed@example.com",
      ...CONTEXT,
    });
    const completion = Promise.allSettled([staleRequest]);
    try {
      await bounded(
        captured.promise,
        "Timed out capturing stale rate-limit read",
      );
      for (let index = 0; index < 2; index++) {
        await auth.issueMagicLink({
          email: `unknown-${index}@example.com`,
          ...CONTEXT,
        });
      }
      const established = (await kv.get<FailedAuthAttemptRecord>(key)).value;
      assert(established?.blockedUntil);
      release.resolve();
      const [result] = await completion;
      assertEquals(result.status, "fulfilled");
      assertEquals(
        (await kv.get<FailedAuthAttemptRecord>(key)).value,
        established,
      );

      const blocked = await auth.issueMagicLink({
        email: "admin@example.com",
        ...CONTEXT,
      });
      assertEquals(blocked.debugUrl, undefined);
    } finally {
      release.resolve();
      await completion;
    }
  });
});

Deno.test("concurrent verification consumes a magic link once and creates one session", async () => {
  await withKv(async (kv) => {
    const { auth } = createAuth(readBarrier(kv, "magic_links", 2));
    const token = await issueToken(auth);
    const results = await Promise.allSettled([
      auth.verifyMagicLink({ token, ...CONTEXT }),
      auth.verifyMagicLink({ token, ...CONTEXT }),
    ]);
    for (const result of results) {
      assertEquals(result.status, "fulfilled");
    }
    const verified = results.flatMap((result) =>
      result.status === "fulfilled" && result.value ? [result.value] : []
    );
    assertEquals(verified.length, 1);
    assertEquals((await entries(kv, "sessions")).length, 1);
  });
});
