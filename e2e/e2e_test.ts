import { assert, assertEquals, assertMatch } from "@std/assert";

const AUTH_BASE_URL = Deno.env.get("E2E_AUTH_BASE_URL") ??
  "http://127.0.0.1:8080";
const MAILPIT_BASE_URL = Deno.env.get("E2E_MAILPIT_BASE_URL") ??
  "http://127.0.0.1:8025";

interface MailpitAddress {
  Address?: string;
}

interface MailpitMessage {
  ID: string;
  To?: MailpitAddress[];
  Text?: string;
}

interface MailpitMessagesResponse {
  messages?: MailpitMessage[];
}

async function fetchJson<T>(url: string, init?: RequestInit): Promise<T> {
  const response = await fetch(url, init);
  if (!response.ok) {
    throw new Error(`Unexpected ${response.status} for ${url}`);
  }
  return await response.json() as T;
}

async function waitFor(
  check: () => Promise<boolean>,
  description: string,
  timeoutMs = 30_000,
): Promise<void> {
  const startedAt = Date.now();
  while (Date.now() - startedAt < timeoutMs) {
    if (await check()) return;
    await new Promise((resolve) => setTimeout(resolve, 500));
  }
  throw new Error(`Timed out waiting for ${description}.`);
}

async function findLatestMessage(recipient: string): Promise<MailpitMessage> {
  let result: MailpitMessage | null = null;
  await waitFor(async () => {
    const messages = await fetchJson<MailpitMessagesResponse>(
      `${MAILPIT_BASE_URL}/api/v1/search?query=${
        encodeURIComponent(recipient)
      }`,
    );
    const candidate = (messages.messages ?? []).find((message) =>
      message.To?.some((entry) => entry.Address === recipient)
    );
    if (!candidate) {
      result = null;
      return false;
    }
    result = await fetchJson<MailpitMessage>(
      `${MAILPIT_BASE_URL}/api/v1/message/${candidate.ID}`,
    );
    return Boolean(result.Text);
  }, `email for ${recipient}`);
  return result!;
}

function extractVerificationUrl(message: MailpitMessage): string {
  const url = message.Text?.match(/https?:\/\/\S+/)?.[0];
  if (!url) {
    throw new Error("Could not find login URL in SMTP message.");
  }
  return url;
}

Deno.test("e2e request and verify flow delivers mail through SMTP and marks super admin", async () => {
  const headers = {
    "content-type": "application/json",
    "x-forwarded-for": "198.51.100.10",
    "user-agent": "e2e-suite/1.0",
  };

  const requestResponse = await fetch(`${AUTH_BASE_URL}/auth/request`, {
    method: "POST",
    headers,
    body: JSON.stringify({
      email: "admin@example.com",
      redirectTo: "/admin/dashboard",
    }),
  });

  assertEquals(requestResponse.status, 200);
  assertEquals(await requestResponse.json(), { sent: true });

  const message = await findLatestMessage("admin@example.com");
  const verificationUrl = extractVerificationUrl(message);
  const verifyResponse = await fetch(verificationUrl, { headers });
  assertEquals(verifyResponse.status, 200);

  const payload = await verifyResponse.json() as {
    ok: boolean;
    redirectTo: string;
    user: { email: string; isSuperAdmin?: boolean };
    session: { isSuperAdmin: boolean; userEmail: string } | null;
  };

  assertEquals(payload.ok, true);
  assertEquals(payload.redirectTo, "/admin/dashboard");
  assertEquals(payload.user.email, "admin@example.com");
  assertEquals(payload.user.isSuperAdmin, true);
  assert(payload.session);
  assertEquals(payload.session.userEmail, "admin@example.com");
  assertEquals(payload.session.isSuperAdmin, true);
});

Deno.test("e2e allowlist and failed-attempt throttling are enforced", async () => {
  const blockedHeaders = {
    "content-type": "application/json",
    "x-forwarded-for": "198.51.100.20",
    "user-agent": "e2e-suite/1.0",
  };

  const outsideAllowlist = await fetch(`${AUTH_BASE_URL}/auth/request`, {
    method: "POST",
    headers: blockedHeaders,
    body: JSON.stringify({
      email: "intruder@blocked.example",
    }),
  });
  assertEquals(outsideAllowlist.status, 401);
  await outsideAllowlist.text();

  for (let index = 0; index < 2; index += 1) {
    const failed = await fetch(`${AUTH_BASE_URL}/auth/request`, {
      method: "POST",
      headers: blockedHeaders,
      body: JSON.stringify({
        email: `missing-${index}@example.com`,
      }),
    });
    assertEquals(failed.status, 401);
    await failed.text();
  }

  const throttled = await fetch(`${AUTH_BASE_URL}/auth/request`, {
    method: "POST",
    headers: blockedHeaders,
    body: JSON.stringify({
      email: "member@example.com",
    }),
  });
  assertEquals(throttled.status, 401);
  await throttled.text();

  const allowedHeaders = {
    "content-type": "application/json",
    "x-forwarded-for": "198.51.100.21",
    "user-agent": "e2e-suite/1.0",
  };
  const allowed = await fetch(`${AUTH_BASE_URL}/auth/request`, {
    method: "POST",
    headers: allowedHeaders,
    body: JSON.stringify({
      email: "special@outside.example",
    }),
  });
  assertEquals(allowed.status, 200);
  assertEquals(await allowed.json(), { sent: true });

  const message = await findLatestMessage("special@outside.example");
  assertMatch(message.Text ?? "", /token=/);
});
