import crypto from "node:crypto";
import { ValidationDomainError } from "@relayquill/domain";

export const BREAK_GLASS_MAX_TTL_MINUTES = 15 as const;
export const BREAK_GLASS_MIN_REASON_LENGTH = 12 as const;
export const BREAK_GLASS_TOKEN_PREFIX = "rq_bg_" as const;
export const BREAK_GLASS_HEADER_NAME = "x-relayquill-break-glass" as const;

/**
 * Issues a single-use plaintext support break-glass bearer token alongside its SHA-256 database digest.
 */
export function mintBreakGlassToken(): {
  readonly token: string;
  readonly tokenSha256: Buffer;
} {
  const token = `${BREAK_GLASS_TOKEN_PREFIX}${crypto.randomBytes(32).toString("base64url")}`;
  const tokenSha256 = crypto.createHash("sha256").update(token, "utf8").digest();
  return { token, tokenSha256 };
}

/**
 * Computes the SHA-256 digest for an incoming `rq_bg_*` token, or returns `null` when malformed.
 */
export function hashBreakGlassToken(rawToken: string): Buffer | null {
  const trimmed = rawToken.trim();
  if (!trimmed.startsWith(BREAK_GLASS_TOKEN_PREFIX)) {
    return null;
  }
  const secretPart = trimmed.slice(BREAK_GLASS_TOKEN_PREFIX.length);
  if (!/^[A-Za-z0-9_-]{32,128}$/.test(secretPart)) {
    return null;
  }
  return crypto.createHash("sha256").update(trimmed, "utf8").digest();
}

/**
 * Validates operator justification and builds a bounded `<= 15 minute` break-glass window.
 */
export function buildBreakGlassWindow(
  reason: string,
  requestedMinutes: number,
  now: Date
): { readonly startedAt: Date; readonly expiresAt: Date; readonly ttlMinutes: number } {
  if (typeof reason !== "string" || reason.trim().length < BREAK_GLASS_MIN_REASON_LENGTH) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Break-glass justification must be at least ${BREAK_GLASS_MIN_REASON_LENGTH} non-whitespace characters`,
      fieldErrors: [{ path: "reason", code: "INVALID_VALUE" }]
    });
  }
  if (
    !Number.isInteger(requestedMinutes) ||
    requestedMinutes < 1 ||
    requestedMinutes > BREAK_GLASS_MAX_TTL_MINUTES
  ) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Break-glass TTL must be an integer between 1 and ${BREAK_GLASS_MAX_TTL_MINUTES} minutes`,
      fieldErrors: [{ path: "ttl_minutes", code: "INVALID_VALUE" }]
    });
  }
  return {
    startedAt: now,
    expiresAt: new Date(now.getTime() + requestedMinutes * 60_000),
    ttlMinutes: requestedMinutes
  };
}

export type BreakGlassDenyCode =
  | "BREAK_GLASS_EXPIRED_OR_REVOKED"
  | "BREAK_GLASS_READ_ONLY_VIOLATION"
  | "BREAK_GLASS_FORBIDDEN_RESOURCE";

export interface BreakGlassScopeDecision {
  readonly allowed: boolean;
  readonly status?: 401 | 403;
  readonly code?: BreakGlassDenyCode;
}

/**
 * Enforces strict expiry, revocation, HTTP read-only, and secret-path denial for break-glass sessions.
 */
export function validateBreakGlassReadScope(
  session: {
    readonly expiresAt: Date;
    readonly revokedAt: Date | null;
    readonly readOnly: boolean;
    readonly operatorId: string;
    readonly tenantId: string;
  },
  httpMethod: string,
  routePath: string,
  now: Date
): BreakGlassScopeDecision {
  if (session.revokedAt !== null || now >= session.expiresAt) {
    return {
      allowed: false,
      status: 401,
      code: "BREAK_GLASS_EXPIRED_OR_REVOKED"
    };
  }
  const upperMethod = httpMethod.toUpperCase();
  if (!session.readOnly || (upperMethod !== "GET" && upperMethod !== "HEAD")) {
    return {
      allowed: false,
      status: 403,
      code: "BREAK_GLASS_READ_ONLY_VIOLATION"
    };
  }
  if (
    routePath.includes("/signing-keys") ||
    routePath.includes("/credentials") ||
    routePath.includes("/billing/portal") ||
    routePath.includes("/erasure-request")
  ) {
    return {
      allowed: false,
      status: 403,
      code: "BREAK_GLASS_FORBIDDEN_RESOURCE"
    };
  }
  return { allowed: true };
}
