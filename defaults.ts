/** Default verify route appended to `appBaseUrl`. */
export const DEFAULT_MAGIC_LINK_VERIFY_PATH = "/api/auth/magic-link/verify";

/** Fixed session lifetime measured from issuance. This is not a sliding idle timeout. */
export const DEFAULT_SESSION_IDLE_TTL_DAYS = 7;

/** Upper bound on session lifetime measured from issuance. */
export const DEFAULT_SESSION_ABSOLUTE_TTL_DAYS = 30;

/**
 * Cookie lifetime. Matches the effective session lifetime, which is the idle
 * deadline when it is shorter than the absolute deadline.
 */
export const DEFAULT_SESSION_COOKIE_TTL_DAYS = DEFAULT_SESSION_IDLE_TTL_DAYS;

/** Minimum accepted binding secret length. Shorter secrets are rejected. */
export const BINDING_SECRET_MIN_LENGTH = 16;

/** Maximum accepted binding secret length. */
export const BINDING_SECRET_MAX_LENGTH = 512;
