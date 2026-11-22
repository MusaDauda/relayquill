import crypto from "node:crypto";
import { createEnumGuard, ValidationDomainError } from "@relayquill/domain";

export const COMMERCIAL_USER_ROLES = [
  "owner",
  "admin",
  "developer",
  "auditor",
  "viewer"
] as const;
export type CommercialUserRole = (typeof COMMERCIAL_USER_ROLES)[number];
export const isCommercialUserRole = createEnumGuard(COMMERCIAL_USER_ROLES);

export interface OidcConnectionConfig {
  readonly issuerUrl: string;
  readonly clientId: string;
  readonly clientSecretRef: string;
  readonly roleMapping: Readonly<Record<string, CommercialUserRole>>;
  readonly enabled: boolean;
}

const LOCAL_HOST_NAMES = new Set(["localhost", "127.0.0.1", "::1", "[::1]"]);

/**
 * Validates that an OIDC issuer URL uses HTTPS and avoids loopback hosts in production checks.
 */
export function validateOidcIssuerUrl(
  issuerUrl: string,
  options: { readonly allowLocalhost?: boolean | undefined } = {}
): string {
  const trimmed = issuerUrl.trim();
  let parsed: URL;
  try {
    parsed = new URL(trimmed);
  } catch {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: "OIDC issuer_url must be a valid URL",
      fieldErrors: [{ path: "issuer_url", code: "INVALID_VALUE" }]
    });
  }
  if (parsed.protocol !== "https:" || parsed.username !== "" || parsed.password !== "") {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: "OIDC issuer_url must use https:// without embedded credentials",
      fieldErrors: [{ path: "issuer_url", code: "INVALID_VALUE" }]
    });
  }
  if (parsed.hostname.length === 0) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: "OIDC issuer_url requires a hostname",
      fieldErrors: [{ path: "issuer_url", code: "INVALID_VALUE" }]
    });
  }
  if (options.allowLocalhost !== true && LOCAL_HOST_NAMES.has(parsed.hostname.toLowerCase())) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: "OIDC issuer_url cannot target a loopback host",
      fieldErrors: [{ path: "issuer_url", code: "INVALID_VALUE" }]
    });
  }
  return parsed.toString().replace(/\/+$/, "");
}

/**
 * Generates an RFC 7636 PKCE verifier and S256 challenge pair.
 */
export function generatePkcePair(): {
  readonly codeVerifier: string;
  readonly codeChallenge: string;
  readonly method: "S256";
} {
  const verifier = crypto.randomBytes(32).toString("base64url");
  const challenge = crypto.createHash("sha256").update(verifier, "utf8").digest("base64url");
  return {
    codeVerifier: verifier,
    codeChallenge: challenge,
    method: "S256"
  };
}

/**
 * Constant-time verification of a PKCE S256 `code_verifier` against a stored `code_challenge`.
 */
export function verifyPkceCodeChallenge(
  codeVerifier: string,
  expectedChallenge: string
): boolean {
  if (typeof codeVerifier !== "string" || codeVerifier.length < 43 || codeVerifier.length > 128) {
    return false;
  }
  if (typeof expectedChallenge !== "string" || expectedChallenge.length === 0) {
    return false;
  }
  const computed = crypto.createHash("sha256").update(codeVerifier, "utf8").digest("base64url");
  const a = Buffer.from(computed, "utf8");
  const b = Buffer.from(expectedChallenge, "utf8");
  if (a.byteLength !== b.byteLength) {
    return false;
  }
  return crypto.timingSafeEqual(a, b);
}

/**
 * Builds an authorization endpoint URL with PKCE S256 parameters.
 */
export function buildOidcAuthorizationUrl(
  config: { readonly issuerUrl: string; readonly clientId: string },
  params: {
    readonly redirectUri: string;
    readonly state: string;
    readonly nonce: string;
    readonly codeChallenge: string;
    readonly scope?: string | undefined;
  }
): string {
  const base = config.issuerUrl.replace(/\/+$/, "");
  const authUrl = new URL(`${base}/authorize`);
  authUrl.searchParams.set("response_type", "code");
  authUrl.searchParams.set("client_id", config.clientId);
  authUrl.searchParams.set("redirect_uri", params.redirectUri);
  authUrl.searchParams.set("scope", params.scope ?? "openid profile email groups");
  authUrl.searchParams.set("state", params.state);
  authUrl.searchParams.set("nonce", params.nonce);
  authUrl.searchParams.set("code_challenge", params.codeChallenge);
  authUrl.searchParams.set("code_challenge_method", "S256");
  return authUrl.toString();
}

const ROLE_PRECEDENCE: readonly CommercialUserRole[] = COMMERCIAL_USER_ROLES;

/**
 * Maps OIDC group claims to the highest-privilege Relayquill tenant role, or `null` if unmapped.
 */
export function mapOidcClaimsToTenantRole(
  groups: readonly string[],
  roleMapping: Readonly<Record<string, CommercialUserRole>>
): CommercialUserRole | null {
  const matched = new Set<CommercialUserRole>();
  for (const group of groups) {
    const mapped = roleMapping[group];
    if (mapped !== undefined && isCommercialUserRole(mapped)) {
      matched.add(mapped);
    }
  }
  for (const candidate of ROLE_PRECEDENCE) {
    if (matched.has(candidate)) {
      return candidate;
    }
  }
  return null;
}
