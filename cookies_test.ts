import { assertEquals, assertThrows } from "@std/assert";

import {
  buildBindingClearCookie,
  buildBindingSetCookie,
  buildSessionClearCookie,
  buildSessionSetCookie,
  buildVerifyResponseHeaders,
  getCookie,
  type MagicLinkCookieConfig,
} from "./cookies.ts";

function cookieAttributes(cookie: string): string[] {
  return cookie.split("; ").slice(1);
}

Deno.test("cookie defaults allow emailed navigation and preserve secure attributes", () => {
  const sessionCookie = buildSessionSetCookie("session");
  const bindingCookie = buildBindingSetCookie("binding", 60);
  assertEquals(sessionCookie.startsWith("__Host-session="), true);
  assertEquals(bindingCookie.startsWith("__Host-ml-bind="), true);
  assertEquals(
    cookieAttributes(sessionCookie).includes("Max-Age=604800"),
    true,
  );
  assertEquals(cookieAttributes(bindingCookie).includes("Path=/"), true);
  for (
    const cookie of [
      sessionCookie,
      buildSessionClearCookie(),
      bindingCookie,
      buildBindingClearCookie(),
    ]
  ) {
    const attributes = cookieAttributes(cookie);
    assertEquals(attributes.includes("SameSite=Lax"), true);
    assertEquals(attributes.includes("Secure"), true);
    assertEquals(attributes.includes("HttpOnly"), true);
  }
});

Deno.test("cookie helpers retain an explicit Strict policy when setting and clearing", () => {
  const config: MagicLinkCookieConfig = { sameSite: "Strict" };
  for (
    const cookie of [
      buildSessionSetCookie("session", config),
      buildSessionClearCookie(config),
      buildBindingSetCookie("binding", 60, config),
      buildBindingClearCookie(config),
    ]
  ) {
    const attributes = cookieAttributes(cookie);
    assertEquals(attributes.includes("SameSite=Strict"), true);
    assertEquals(attributes.includes("SameSite=Lax"), false);
  }
});

Deno.test("binding cookie paths satisfy Host prefixes and match when clearing", () => {
  for (
    const [bindingCookieName, path] of [
      ["ml_bind", "/api/auth/magic-link/verify"],
      ["__Secure-ml-bind", "/api/auth/magic-link/verify"],
      ["__Host-ml-bind", "/"],
      ["__host-ml-bind", "/"],
    ]
  ) {
    const config = { bindingCookieName };
    for (
      const cookie of [
        buildBindingSetCookie("binding", 60, config),
        buildBindingClearCookie(config),
      ]
    ) {
      assertEquals(cookieAttributes(cookie).includes(`Path=${path}`), true);
    }
  }
});

Deno.test("duplicate cookie names fail closed and verify headers hide the token", () => {
  assertEquals(
    getCookie(
      new Headers({ cookie: "__Host-session=one; __Host-session=two" }),
      "__Host-session",
    ),
    null,
  );
  const headers = buildVerifyResponseHeaders("https://app.example.com/dash", [
    buildSessionSetCookie("abc"),
  ]);
  assertEquals(headers.get("location"), "https://app.example.com/dash");
  assertEquals(headers.get("referrer-policy"), "no-referrer");
  assertEquals(headers.get("cache-control"), "no-store");
  assertThrows(
    () =>
      buildVerifyResponseHeaders(
        "https://app.example.com/\r\nSet-Cookie: a",
        [],
      ),
    Error,
    "Header values must not contain line breaks.",
  );
  assertThrows(
    () => buildSessionSetCookie("abc", { maxAgeSeconds: 1.5 }),
    Error,
    "maxAgeSeconds must be a positive integer.",
  );
  assertThrows(
    () =>
      buildBindingSetCookie("binding-secret-value", 60, {
        bindingCookieName: "ml_bind",
        bindingCookiePath: "//evil.example",
      }),
    Error,
    "bindingCookiePath must be an absolute path",
  );
});

Deno.test("all cookie helpers reject secure prefixes with secure disabled", () => {
  for (const name of ["__Host-auth", "__Secure-auth", "__host-auth"]) {
    const config = {
      sessionCookieName: name,
      bindingCookieName: name,
      secure: false,
    };
    for (
      const build of [
        () => buildSessionSetCookie("session", config),
        () => buildSessionClearCookie(config),
        () => buildBindingSetCookie("binding", 60, config),
        () => buildBindingClearCookie(config),
      ]
    ) {
      assertThrows(
        build,
        Error,
        "Cookie names starting with __Host- or __Secure- require secure: true.",
      );
    }
  }
});
