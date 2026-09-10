import { assert, assertEquals } from "@std/assert";
import { chromium } from "playwright";

import {
  buildBindingClearCookie,
  buildBindingSetCookie,
  buildSessionClearCookie,
  buildSessionSetCookie,
  DenoKvMagicLinkAuth,
  getCookie,
} from "../mod.ts";

Deno.test("emailed login preserves browser binding and the redirected session", async (t) => {
  const browser = await chromium.launch({
    executablePath: Deno.env.get("PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH"),
    headless: true,
  });

  try {
    for (const bindingCookieName of ["ml_bind", "__Host-ml-bind"]) {
      await t.step(bindingCookieName, async () => {
        const context = await browser.newContext();
        const kv = await Deno.openKv(":memory:");
        const cookieConfig = {
          bindingCookieName,
          sessionCookieName: "__Host-session",
        };
        const bindingSecret = crypto.randomUUID();
        const user = {
          id: "browser-user",
          email: "browser@example.com",
          authVersion: 1,
          active: true,
        };
        let verificationUrl = "";
        let receivedBindingSecret: string | null = null;
        let verificationSite: string | null = null;

        const server = Deno.serve(
          { hostname: "127.0.0.1", port: 0, onListen() {} },
          async (request): Promise<Response> => {
            const url = new URL(request.url);
            if (url.pathname === "/request") {
              const issued = await auth.issueMagicLink({
                email: user.email,
                requestIp: "192.0.2.10",
                userAgent: request.headers.get("user-agent"),
                bindingSecret,
              });
              verificationUrl = issued.debugUrl!;
              return new Response("Check your email", {
                headers: {
                  "set-cookie": buildBindingSetCookie(
                    bindingSecret,
                    60,
                    cookieConfig,
                  ),
                },
              });
            }

            if (url.pathname === "/mail") {
              return new Response(
                `<a href="${verificationUrl}">Sign in</a>`,
                { headers: { "content-type": "text/html" } },
              );
            }

            if (url.pathname === "/api/auth/magic-link/verify") {
              receivedBindingSecret = getCookie(
                request.headers,
                bindingCookieName,
              );
              verificationSite = request.headers.get("sec-fetch-site");
              const verified = await auth.verifyMagicLink({
                token: url.searchParams.get("token") ?? "",
                // A different network must still work through browser binding.
                requestIp: "198.51.100.20",
                userAgent: request.headers.get("user-agent"),
                bindingSecret: receivedBindingSecret,
              });
              if (!verified) {
                return new Response("Verification failed", { status: 401 });
              }

              const headers = new Headers({ location: "/dashboard" });
              headers.append(
                "set-cookie",
                buildBindingClearCookie(cookieConfig),
              );
              headers.append(
                "set-cookie",
                buildSessionSetCookie(verified.sessionId, cookieConfig),
              );
              return new Response(null, { status: 302, headers });
            }

            const sessionId = getCookie(
              request.headers,
              cookieConfig.sessionCookieName,
            );
            if (url.pathname === "/logout") {
              if (sessionId) await auth.revokeSession(sessionId);
              return new Response("Logged out", {
                headers: {
                  "set-cookie": buildSessionClearCookie(cookieConfig),
                },
              });
            }
            if (url.pathname === "/dashboard") {
              const session = sessionId
                ? await auth.getSession(sessionId)
                : null;
              return session
                ? new Response(`Signed in as ${session.userEmail}`)
                : new Response("Not authenticated", { status: 401 });
            }
            return new Response("Not found", { status: 404 });
          },
        );
        const appOrigin = `http://localhost:${server.addr.port}`;
        const mailOrigin = `http://127.0.0.1:${server.addr.port}`;
        const auth = new DenoKvMagicLinkAuth(
          { appBaseUrl: appOrigin, authDevExposeMagicLink: true },
          {
            kv,
            findUserByEmail: (email) =>
              Promise.resolve(email === user.email ? user : null),
            findUserById: (id) => Promise.resolve(id === user.id ? user : null),
          },
        );

        try {
          const page = await context.newPage();
          await page.goto(`${appOrigin}/request`);
          const storedBinding = (await context.cookies()).find((cookie) =>
            cookie.name === bindingCookieName
          );
          assert(storedBinding, "The browser must accept the binding cookie");
          assertEquals(
            storedBinding.path,
            bindingCookieName === "__Host-ml-bind"
              ? "/"
              : "/api/auth/magic-link/verify",
          );
          assertEquals(storedBinding.secure, true);
          assertEquals(storedBinding.httpOnly, true);
          assertEquals(storedBinding.sameSite, "Lax");

          await page.goto(`${mailOrigin}/mail`);
          await Promise.all([
            page.waitForURL(`${appOrigin}/dashboard`),
            page.getByRole("link", { name: "Sign in" }).click(),
          ]);
          assertEquals(verificationSite, "cross-site");
          assertEquals(receivedBindingSecret, bindingSecret);
          assertEquals(
            await page.locator("body").innerText(),
            `Signed in as ${user.email}`,
          );

          const authenticatedCookies = await context.cookies();
          assertEquals(
            authenticatedCookies.some((cookie) =>
              cookie.name === bindingCookieName
            ),
            false,
          );
          assert(
            authenticatedCookies.some((cookie) =>
              cookie.name === cookieConfig.sessionCookieName
            ),
          );

          await page.goto(`${appOrigin}/logout`);
          assertEquals(
            (await context.cookies()).some((cookie) =>
              cookie.name === cookieConfig.sessionCookieName
            ),
            false,
          );
        } finally {
          await context.close();
          await server.shutdown();
          kv.close();
        }
      });
    }
  } finally {
    await browser.close();
  }
});
