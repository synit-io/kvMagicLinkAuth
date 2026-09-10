import { assert, assertEquals } from "@std/assert";
import { pathToFileURL } from "node:url";

const exampleNames = [
  "Quick Start",
  "Basic Auth Example",
  "Advanced Auth Example",
  "RBAC Quick Start",
  "Advanced RBAC Example",
];

// Each subprocess supplies only the application's external dependencies. The
// documented handlers and service configuration run without source rewriting.
const runner = String.raw`
import { getCookie } from "jsr:@synitio/kv-magic-link-auth";
import type {
  DenoKvMagicLinkAuth,
  MagicLinkIssueResult,
} from "jsr:@synitio/kv-magic-link-auth";

function check(condition: unknown, message: string): asserts condition {
  if (!condition) throw new Error(message);
}

const name = Deno.args[1];
const origin = name === "Quick Start"
  ? "https://app.example.local"
  : "https://console.example.local";
const user = {
  id: "u_1",
  email: "admin@example.local",
  authVersion: 1,
  active: true,
  role: name === "Advanced RBAC Example" ? "billing_admin" : "admin",
};
let userExists = true;
Object.assign(globalThis, {
  lookupUserByEmail: async (email: string) =>
    userExists && email === user.email ? user : null,
  lookupUserById: async (id: string) =>
    userExists && id === user.id ? user : null,
  lookupCurrentUserById: async (id: string) =>
    userExists && id === user.id ? user : null,
});

const messages: { to: string; text: string }[] = [];
globalThis.fetch = async (input, init) => {
  check(String(input) === "https://mailer.example.local/send", "Unexpected network request");
  check(init && "method" in init && init.method === "POST", "Mail adapter must POST the message");
  check("body" in init, "Mail adapter must include a message body");
  messages.push(JSON.parse(String(init.body)));
  return Response.json({ ok: true });
};
const openKv = Deno.openKv;
Object.defineProperty(Deno, "openKv", { value: () => openKv(":memory:") });

const example: {
  auth: DenoKvMagicLinkAuth;
  kv: Deno.Kv;
  handleRequest: (
    request: Request,
    info: Deno.ServeHandlerInfo<Deno.NetAddr>,
  ) => Promise<Response>;
} = await import(Deno.args[0]);

const info: Deno.ServeHandlerInfo<Deno.NetAddr> = {
  remoteAddr: { transport: "tcp", hostname: "198.51.100.10", port: 12345 },
  completed: Promise.resolve(),
};
const headers = new Headers({
  "user-agent": "readme-tests/1.0",
  "x-forwarded-for": "203.0.113.1",
});
const request = (path: string, init: RequestInit = {}) =>
  new Request(new URL(path, origin), { ...init, headers: init.headers ?? headers });

try {
  const hasRequestHandler = !name.includes("RBAC");
  const sendsMail = name !== "Quick Start" && name !== "RBAC Quick Start";
  let issued: MagicLinkIssueResult | undefined;
  let bindingCookie: string | undefined;
  if (hasRequestHandler) {
    const response = await example.handleRequest(request("/auth/request", { method: "POST" }), info);
    const body = await response.json();
    if (sendsMail) {
      check(response.status === 202 && body.accepted === true, "Public issuance must return generic 202");
      check(!("sent" in body) && !("debugUrl" in body), "Public issuance leaked an internal result");
    } else {
      issued = body;
    }
    bindingCookie = response.headers.getSetCookie()
      .find((cookie) => cookie.startsWith("__Host-ml-bind="));
    if (name === "Advanced Auth Example") {
      check(bindingCookie, "Advanced example did not set a binding cookie");
      check(bindingCookie.split("; ").includes("Path=/"), "__Host binding cookie must use root path");
      check(bindingCookie.includes("SameSite=Lax"), "Email navigation needs a Lax binding cookie");
    }
  } else {
    // RBAC examples document verification and protected routes; use the public
    // issuance API to obtain the URL for those handlers.
    issued = await example.auth.issueMagicLink({
      email: user.email,
      redirectTo: "/admin/dashboard",
      requestIp: info.remoteAddr.hostname,
      userAgent: headers.get("user-agent"),
    });
  }

  if (sendsMail) {
    check(messages.length === 1, "Example did not deliver exactly one email");
    check(messages[0].to === user.email, "Message went to the wrong recipient");
  }
  const verificationUrl = issued?.debugUrl ?? messages[0]?.text.match(/https?:\/\/\S+/)?.[0];
  check(verificationUrl, "Example produced no usable verification link");

  // The forwarding header remains identical, but the real peer changes. A
  // handler that trusts the header would incorrectly accept this request.
  const wrongPeer = await example.handleRequest(request(verificationUrl), {
    ...info,
    remoteAddr: { ...info.remoteAddr, hostname: "198.51.100.99" },
  });
  check(wrongPeer.status === 401, "Client-supplied forwarding header bypassed peer binding");
  await wrongPeer.text();

  // Follow the exact generated URL. A forged forwarding header must not prevent
  // the same transport peer from authenticating.
  const verifyHeaders = new Headers(headers);
  verifyHeaders.set("x-forwarded-for", "203.0.113.2");
  if (bindingCookie) verifyHeaders.set("cookie", bindingCookie.split(";")[0]);
  const verified = await example.handleRequest(request(verificationUrl, { headers: verifyHeaders }), info);
  check(verified.status === 302, "Generated verification URL did not reach a successful handler");
  check(verified.headers.get("location") === origin + "/admin/dashboard", "Redirect destination changed");
  const sessionCookie = verified.headers.getSetCookie()
    .find((cookie) => cookie.startsWith("__Host-session="));
  check(sessionCookie, "Verification did not deliver the session cookie");
  for (const attribute of ["Path=/", "HttpOnly", "Secure", "SameSite=Lax"]) {
    check(sessionCookie.split("; ").includes(attribute), "Session cookie is missing " + attribute);
  }
  const authenticatedHeaders = new Headers(headers);
  authenticatedHeaders.set("cookie", sessionCookie.split(";")[0]);
  const sessionId = getCookie(authenticatedHeaders, "__Host-session");
  check(sessionId, "Session cookie cannot be parsed");
  const session = await example.auth.getSession(sessionId);
  check(session?.userId === user.id, "Delivered cookie does not identify a valid session");

  const protectedPath = name === "Quick Start" ? "/me"
    : name === "RBAC Quick Start" ? "/admin/users"
    : name === "Advanced RBAC Example" ? "/admin/billing" : null;
  if (protectedPath) {
    const response = await example.handleRequest(request(protectedPath, { headers: authenticatedHeaders }), info);
    check(response.status === 200, "Authenticated follow-up request failed");
    await response.text();
  }
  if (name === "Basic Auth Example") {
    const crossSiteLogout = await example.handleRequest(request("/auth/logout", {
      method: "POST", headers: authenticatedHeaders,
    }), info);
    check(crossSiteLogout.status === 403, "Logout accepted a missing origin");
    await crossSiteLogout.text();
    authenticatedHeaders.set("origin", origin);
    const logout = await example.handleRequest(request("/auth/logout", {
      method: "POST", headers: authenticatedHeaders,
    }), info);
    check(logout.headers.get("set-cookie")?.includes("Max-Age=0"), "Logout did not clear the browser cookie");
    check(await example.auth.getSession(sessionId) === null, "Logout did not revoke the session");
    await logout.text();
  }
  if (hasRequestHandler && sendsMail) {
    userExists = false;
    const unavailable = await example.handleRequest(request("/auth/request", { method: "POST" }), info);
    check(unavailable.status === 202, "Missing account changed the public status");
    check(JSON.stringify(await unavailable.json()) === JSON.stringify({ accepted: true }), "Missing account changed the public result");
    check(messages.length === 1, "Missing account received mail");
  }
} finally {
  example.kv.close();
}
`;

Deno.test("README examples typecheck and complete their authentication flows", async (test) => {
  const readme = await Deno.readTextFile(
    new URL("./README.md", import.meta.url),
  );
  const directory = await Deno.makeTempDir({ prefix: "kv-auth-readme-" });
  try {
    const configPath = `${directory}/deno.json`;
    await Deno.writeTextFile(
      configPath,
      JSON.stringify({
        imports: {
          "jsr:@synitio/kv-magic-link-auth":
            new URL("./mod.ts", import.meta.url).href,
        },
      }),
    );
    const paths: string[] = [];
    for (const [index, name] of exampleNames.entries()) {
      const section = readme.split(`## ${name}\n`)[1]?.split("\n## ")[0];
      const code = section?.match(/```ts\n([\s\S]*?)```/)?.[1];
      assert(code, `Missing TypeScript example: ${name}`);
      const path = `${directory}/example-${index}.ts`;
      await Deno.writeTextFile(path, `${code}\nexport { auth, kv };\n`);
      paths.push(path);
    }
    const runnerPath = `${directory}/runner.ts`;
    await Deno.writeTextFile(runnerPath, runner);

    const run = async (args: string[]): Promise<void> => {
      const result = await new Deno.Command(Deno.execPath(), {
        args,
        cwd: directory,
        stdout: "piped",
        stderr: "piped",
      }).output();
      assertEquals(
        result.code,
        0,
        new TextDecoder().decode(result.stderr) +
          new TextDecoder().decode(result.stdout),
      );
    };

    await test.step("typecheck all extracted examples and test harness", () =>
      run([
        "check",
        "--unstable-kv",
        "--no-lock",
        "--config",
        configPath,
        ...paths,
        runnerPath,
      ]));
    for (const [index, name] of exampleNames.entries()) {
      await test.step(name, () =>
        run([
          "run",
          "--unstable-kv",
          "--allow-read",
          "--no-lock",
          "--config",
          configPath,
          runnerPath,
          pathToFileURL(paths[index]).href,
          name,
        ]));
    }
  } finally {
    await Deno.remove(directory, { recursive: true });
  }
});
