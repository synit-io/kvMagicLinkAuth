import type { SessionAuthorizationSnapshot, SessionRecord } from "./types.ts";

function normalizeKey(value: string): string {
  return value.trim().toLowerCase();
}

function getAuthorizationSnapshot(
  session: SessionRecord,
): SessionAuthorizationSnapshot | null {
  return session.authorization ?? null;
}

/** Returns whether the session should bypass normal RBAC checks. */
export function isSuperAdmin(session: SessionRecord): boolean {
  return session.isSuperAdmin === true;
}

/** Returns whether the session matches the given role. */
export function hasRole(session: SessionRecord, role: string): boolean {
  if (isSuperAdmin(session)) return true;
  const normalizedRole = normalizeKey(role);
  if (!normalizedRole) return false;

  const snapshot = getAuthorizationSnapshot(session);
  if (snapshot) {
    return normalizeKey(snapshot.role) === normalizedRole;
  }

  return normalizeKey(session.role) === normalizedRole;
}

/** Returns whether the session contains the given permission. */
export function hasPermission(
  session: SessionRecord,
  permission: string,
): boolean {
  if (isSuperAdmin(session)) return true;
  const normalizedPermission = normalizeKey(permission);
  if (!normalizedPermission) return false;

  // Permissions intentionally come only from the session snapshot so request
  // handlers can stay KV-free after the session has already been loaded.
  const snapshot = getAuthorizationSnapshot(session);
  if (!snapshot) return false;

  return snapshot.permissions.some((entry) =>
    normalizeKey(entry) === normalizedPermission
  );
}

/** Returns whether the session contains at least one permission from the list. */
export function hasAnyPermission(
  session: SessionRecord,
  permissions: readonly string[],
): boolean {
  if (isSuperAdmin(session)) return true;
  return permissions.some((permission) => hasPermission(session, permission));
}

/** Compares an already-loaded session snapshot against known authorization versions. */
export function isSessionAuthorizationCurrent(
  session: SessionRecord,
  expected: {
    authVersion?: number;
    permissionsVersion?: number;
  } = {},
): boolean {
  if (
    typeof expected.authVersion === "number" &&
    session.authVersion !== expected.authVersion
  ) {
    return false;
  }

  if (typeof expected.permissionsVersion !== "number") {
    return true;
  }

  const snapshot = getAuthorizationSnapshot(session);
  if (!snapshot) return false;
  return snapshot.permissionsVersion === expected.permissionsVersion;
}
