import { assertEquals, assertThrows } from "@std/assert";

import {
  buildBindingClearCookie,
  buildBindingSetCookie,
  buildSessionClearCookie,
  buildSessionSetCookie,
  type MagicLinkCookieConfig,
} from "./cookies.ts";

function cookieAttributes(cookie: string): string[] {
  return cookie.split("; ").slice(1);
}

Deno.test("cookie defaults allow emailed navigation and preserve secure attributes", () => {
  for (
    const cookie of [
      buildSessionSetCookie("session"),
      buildSessionClearCookie(),
      buildBindingSetCookie("binding", 60),
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
