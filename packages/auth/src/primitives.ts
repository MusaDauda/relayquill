import crypto from "node:crypto";
import type { Temporal } from "@js-temporal/polyfill";
import {
  AuthenticationDomainError,
  AuthorizationDomainError,
  type ControlEpoch,
  type InstallationMode,
  OpaqueSecret,
  type PrincipalId,
  type PrincipalKind,
  type PrincipalState,
  type ProducerCredentialId,
  type Sha256Hex,
  ValidationDomainError,
  isCanonicalUuid,
  nowUtcInstant,
  parseProducerCredentialId,
  parseSha256Hex
} from "@relayquill/domain";
import {
  type Base64UrlString,
  decodeBase64UrlStrict,
  encodeBase64Url,
  encodeDomainLengthPrefixed,
  sha256HexToBytes
} from "@relayquill/contracts";
import type { AuthConfig } from "@relayquill/runtime";

export const RELEASE_SESSION_COOKIE_NAME = "__Host-rq_session" as const;
export const DEV_SESSION_COOKIE_NAME = "rq_session_dev" as const;
export const RELEASE_PREAUTH_COOKIE_NAME = "__Host-rq_pre" as const;
export const DEV_PREAUTH_COOKIE_NAME = "rq_pre_dev" as const;

export const SESSION_TOKEN_BYTE_LENGTH = 32 as const;
export const BROWSER_PROOF_BYTE_LENGTH = 32 as const;
export const CSRF_TOKEN_BYTE_LENGTH = 32 as const;
export const PRODUCER_SECRET_BYTE_LENGTH = 32 as const;

export const DIGEST_DOMAIN_BROWSER_PROOF = "rq.browser-proof.v1" as const;
export const DIGEST_DOMAIN_SESSION_BROWSER_PROOF = "rq.session-browser-proof.v1" as const;
export const DIGEST_DOMAIN_SESSION_TOKEN = "rq.session.v1" as const;
export const DIGEST_DOMAIN_CSRF_TOKEN = "rq.csrf.v1" as const;
export const DIGEST_DOMAIN_CSRF_DIGEST = "rq.csrf-digest.v1" as const;
export const DIGEST_DOMAIN_PRODUCER_CREDENTIAL = "rq.producer-credential.v1" as const;
export const DIGEST_DOMAIN_ENROLLMENT_COMPARISON = "rq.enrollment-comparison.v1" as const;
export const DIGEST_DOMAIN_STEP_UP_TARGET = "rq.step-up-target.v1" as const;

export type AuthCookieProfile = "development_only" | "release_https";

export interface AuthClock {
  now(): Temporal.Instant;
}

export const defaultAuthClock: AuthClock = Object.freeze({
  now(): Temporal.Instant {
    return nowUtcInstant();
  }
});

export interface InstallationAuthoritySnapshot {
  readonly mode: InstallationMode;
  readonly controlEpoch: ControlEpoch;
  readonly allowEventAdmission: boolean;
  readonly allowPublication: boolean;
  readonly allowFanout: boolean;
  readonly allowSend: boolean;
  readonly allowEndpointVerification: boolean;
  readonly governanceVersion: bigint;
  readonly version: bigint;
}

export interface InstallationAuthorityReader {
  getInstallationAuthority(): Promise<InstallationAuthoritySnapshot>;
}

export interface PrincipalRecord {
  readonly principalId: PrincipalId;
  readonly kind: PrincipalKind;
  readonly state: PrincipalState;
  readonly authorityEpoch: bigint;
  readonly version: bigint;
}

export interface HumanRecord {
  readonly principalId: PrincipalId;
  readonly displayName: string;
  readonly webauthnUserId: Uint8Array;
  readonly version: bigint;
}

export interface NormalizedAuthPolicyConfig {
  readonly rpId: string;
  readonly rpName: string;
  readonly allowedOrigins: readonly string[];
  readonly cookieProfile: AuthCookieProfile;
}

export interface AuthPolicyInput {
  readonly rp_id?: string | undefined;
  readonly rpId?: string | undefined;
  readonly rp_name?: string | undefined;
  readonly rpName?: string | undefined;
  readonly allowed_origins?: readonly string[] | undefined;
  readonly allowedOrigins?: readonly string[] | undefined;
  readonly cookie_profile?: AuthCookieProfile | undefined;
  readonly cookieProfile?: AuthCookieProfile | undefined;
}

const DISALLOWED_RELEASE_HOSTS = new Set([
  "localhost",
  "127.0.0.1",
  "::1",
  "[::1]",
  "0.0.0.0",
  "receiver.fixture.test"
]);

const RESERVED_RELEASE_SUFFIXES = [".localhost", ".local", ".internal", ".test"];

function isDisallowedReleaseHost(hostname: string): boolean {
  const lower = hostname.toLowerCase();
  if (DISALLOWED_RELEASE_HOSTS.has(lower)) {
    return true;
  }
  return RESERVED_RELEASE_SUFFIXES.some((suffix) => lower.endsWith(suffix));
}

function isOriginAllowedForRpId(hostname: string, rpId: string): boolean {
  const lowerHost = hostname.toLowerCase();
  const lowerRp = rpId.toLowerCase();
  return lowerHost === lowerRp || lowerHost.endsWith(`.${lowerRp}`);
}

export function normalizeAuthPolicyConfig(
  input: AuthConfig | AuthPolicyInput
): NormalizedAuthPolicyConfig {
  const rawRpId =
    "rp_id" in input && input.rp_id !== undefined
      ? input.rp_id
      : "rpId" in input
        ? input.rpId
        : undefined;
  const rawOrigins =
    "allowed_origins" in input && input.allowed_origins !== undefined
      ? input.allowed_origins
      : "allowedOrigins" in input
        ? input.allowedOrigins
        : undefined;
  const rawCookieProfile =
    "cookie_profile" in input && input.cookie_profile !== undefined
      ? input.cookie_profile
      : "cookieProfile" in input
        ? input.cookieProfile
        : undefined;
  const rawRpName =
    "rp_name" in input && input.rp_name !== undefined
      ? input.rp_name
      : "rpName" in input
        ? input.rpName
        : undefined;

  if (typeof rawRpId !== "string" || rawRpId.length === 0 || rawRpId.length > 255) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: "WebAuthn rp_id must be a non-empty hostname",
      fieldErrors: [{ path: "auth.rp_id", code: "INVALID_VALUE" }]
    });
  }

  let parsedRpHostname: string;
  try {
    const url = new URL(`https://${rawRpId}`);
    if (url.hostname !== rawRpId || url.port.length > 0 || url.pathname !== "/") {
      throw new Error("Non-canonical RP ID");
    }
    parsedRpHostname = url.hostname;
  } catch {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: "WebAuthn rp_id must be a canonical ASCII hostname without scheme, port, or path",
      fieldErrors: [{ path: "auth.rp_id", code: "INVALID_VALUE" }]
    });
  }

  if (rawCookieProfile !== "development_only" && rawCookieProfile !== "release_https") {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: "cookie_profile must be development_only or release_https",
      fieldErrors: [{ path: "auth.cookie_profile", code: "INVALID_VALUE" }]
    });
  }

  if (rawCookieProfile === "release_https" && isDisallowedReleaseHost(parsedRpHostname)) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: "Development or loopback rp_id is forbidden in release_https mode",
      fieldErrors: [{ path: "auth.rp_id", code: "INVALID_VALUE" }]
    });
  }

  if (!Array.isArray(rawOrigins) || rawOrigins.length === 0) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: "allowed_origins must contain at least one explicit origin",
      fieldErrors: [{ path: "auth.allowed_origins", code: "INVALID_VALUE" }]
    });
  }
  const originsList: readonly unknown[] = rawOrigins;

  const normalizedOrigins: string[] = [];
  const seenOrigins = new Set<string>();
  for (let i = 0; i < originsList.length; i += 1) {
    const candidate = originsList[i];
    if (typeof candidate !== "string" || candidate.length === 0 || candidate.endsWith("/")) {
      throw new ValidationDomainError({
        code: "INVALID_VALUE",
        message: "Origin must be a canonical scheme://host[:port] string without trailing slash",
        fieldErrors: [{ path: `auth.allowed_origins[${i}]`, code: "INVALID_VALUE" }]
      });
    }
    let parsedUrl: URL;
    try {
      parsedUrl = new URL(candidate);
    } catch {
      throw new ValidationDomainError({
        code: "INVALID_VALUE",
        message: "Malformed origin in allowed_origins",
        fieldErrors: [{ path: `auth.allowed_origins[${i}]`, code: "INVALID_VALUE" }]
      });
    }
    if (parsedUrl.origin !== candidate) {
      throw new ValidationDomainError({
        code: "INVALID_VALUE",
        message: "Origin must be canonical without path, query, fragment, or userinfo",
        fieldErrors: [{ path: `auth.allowed_origins[${i}]`, code: "INVALID_VALUE" }]
      });
    }
    if (rawCookieProfile === "release_https") {
      if (parsedUrl.protocol !== "https:" || isDisallowedReleaseHost(parsedUrl.hostname)) {
        throw new ValidationDomainError({
          code: "INVALID_VALUE",
          message: "release_https requires HTTPS non-development origins",
          fieldErrors: [{ path: `auth.allowed_origins[${i}]`, code: "INVALID_VALUE" }]
        });
      }
    } else if (parsedUrl.protocol !== "http:" && parsedUrl.protocol !== "https:") {
      throw new ValidationDomainError({
        code: "INVALID_VALUE",
        message: "Origin scheme must be http: or https:",
        fieldErrors: [{ path: `auth.allowed_origins[${i}]`, code: "INVALID_VALUE" }]
      });
    }

    if (!isOriginAllowedForRpId(parsedUrl.hostname, parsedRpHostname)) {
      throw new ValidationDomainError({
        code: "INVALID_VALUE",
        message: "Allowed origin hostname must match or be a subdomain of configured rp_id",
        fieldErrors: [{ path: `auth.allowed_origins[${i}]`, code: "INVALID_VALUE" }]
      });
    }

    if (!seenOrigins.has(candidate)) {
      seenOrigins.add(candidate);
      normalizedOrigins.push(candidate);
    }
  }

  const rpName = rawRpName ?? "Relayquill";
  if (typeof rpName !== "string" || rpName.trim().length === 0 || rpName.length > 128) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: "WebAuthn rp_name must be a bounded non-empty string",
      fieldErrors: [{ path: "auth.rp_name", code: "INVALID_VALUE" }]
    });
  }

  return Object.freeze({
    rpId: parsedRpHostname,
    rpName,
    allowedOrigins: Object.freeze(normalizedOrigins),
    cookieProfile: rawCookieProfile
  });
}

export function resolveSessionCookieName(cookieProfile: AuthCookieProfile): string {
  return cookieProfile === "release_https" ? RELEASE_SESSION_COOKIE_NAME : DEV_SESSION_COOKIE_NAME;
}

export function resolvePreauthCookieName(cookieProfile: AuthCookieProfile): string {
  return cookieProfile === "release_https" ? RELEASE_PREAUTH_COOKIE_NAME : DEV_PREAUTH_COOKIE_NAME;
}

export function randomBytesCopy(length: number): Uint8Array {
  return new Uint8Array(crypto.randomBytes(length));
}

export function generateRandomBase64UrlToken(byteLength = 32): {
  readonly bytes: Uint8Array;
  readonly token: OpaqueSecret<Base64UrlString>;
} {
  const bytes = randomBytesCopy(byteLength);
  const encoded = encodeBase64Url(bytes);
  return Object.freeze({
    bytes,
    token: new OpaqueSecret<Base64UrlString>(encoded)
  });
}

export function digestWithDomain(domain: string, payload: Uint8Array): Uint8Array {
  const domainBytes = Buffer.from(domain, "utf8");
  const hash = crypto.createHash("sha256");
  hash.update(domainBytes);
  hash.update(Uint8Array.of(0x00));
  hash.update(payload);
  return new Uint8Array(hash.digest());
}

export function computeBrowserProofDigest(rawBrowserProofBytes: Uint8Array): Uint8Array {
  if (rawBrowserProofBytes.byteLength !== BROWSER_PROOF_BYTE_LENGTH) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Browser proof must be ${BROWSER_PROOF_BYTE_LENGTH} bytes`
    });
  }
  return digestWithDomain(DIGEST_DOMAIN_BROWSER_PROOF, rawBrowserProofBytes);
}

export function computeSessionTokenDigest(rawSessionBytes: Uint8Array): Uint8Array {
  if (rawSessionBytes.byteLength !== SESSION_TOKEN_BYTE_LENGTH) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Session token must be ${SESSION_TOKEN_BYTE_LENGTH} bytes`
    });
  }
  return digestWithDomain(DIGEST_DOMAIN_SESSION_TOKEN, rawSessionBytes);
}

export function computeSessionBrowserProofDigest(rawSessionBytes: Uint8Array): Uint8Array {
  if (rawSessionBytes.byteLength !== SESSION_TOKEN_BYTE_LENGTH) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Session token must be ${SESSION_TOKEN_BYTE_LENGTH} bytes`
    });
  }
  return digestWithDomain(DIGEST_DOMAIN_SESSION_BROWSER_PROOF, rawSessionBytes);
}

export function deriveCsrfTokenBytes(rawSessionBytes: Uint8Array): Uint8Array {
  if (rawSessionBytes.byteLength !== SESSION_TOKEN_BYTE_LENGTH) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Session token must be ${SESSION_TOKEN_BYTE_LENGTH} bytes`
    });
  }
  const mac = crypto
    .createHmac("sha256", rawSessionBytes)
    .update(Buffer.from(DIGEST_DOMAIN_CSRF_TOKEN, "utf8"))
    .digest();
  return new Uint8Array(mac);
}

export function deriveCsrfTokenBase64Url(rawSessionBytes: Uint8Array): OpaqueSecret<Base64UrlString> {
  const bytes = deriveCsrfTokenBytes(rawSessionBytes);
  try {
    return new OpaqueSecret<Base64UrlString>(encodeBase64Url(bytes));
  } finally {
    bytes.fill(0);
  }
}

export function computeCsrfDigest(rawCsrfBytes: Uint8Array): Uint8Array {
  if (rawCsrfBytes.byteLength !== CSRF_TOKEN_BYTE_LENGTH) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `CSRF token must be ${CSRF_TOKEN_BYTE_LENGTH} bytes`
    });
  }
  return digestWithDomain(DIGEST_DOMAIN_CSRF_DIGEST, rawCsrfBytes);
}

export function computeProducerCredentialDigest(
  credentialId: ProducerCredentialId | string,
  rawSecretBytes: Uint8Array
): Uint8Array {
  if (typeof credentialId !== "string" || !isCanonicalUuid(credentialId)) {
    throw new ValidationDomainError({
      code: "INVALID_CREDENTIAL_SELECTOR",
      message: "Producer credential digest requires lowercase canonical UUID selector",
      fieldErrors: [{ path: "credential_id", code: "INVALID_CREDENTIAL_SELECTOR" }]
    });
  }
  const canonicalId = parseProducerCredentialId(credentialId, "credential_id");
  if (rawSecretBytes.byteLength !== PRODUCER_SECRET_BYTE_LENGTH) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Producer credential secret must be ${PRODUCER_SECRET_BYTE_LENGTH} bytes`
    });
  }
  const preimage = encodeDomainLengthPrefixed(DIGEST_DOMAIN_PRODUCER_CREDENTIAL, [
    canonicalId,
    rawSecretBytes
  ]);
  return new Uint8Array(crypto.createHash("sha256").update(preimage).digest());
}

export function constantTimeEqualBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.byteLength !== b.byteLength) {
    return false;
  }
  return crypto.timingSafeEqual(a, b);
}

export function digestBytesToSha256Hex(bytes: Uint8Array, fieldPath = "sha256"): Sha256Hex {
  if (bytes.byteLength !== 32) {
    throw new ValidationDomainError({
      code: "INVALID_HASH",
      message: `Expected 32-byte SHA-256 digest for ${fieldPath}`,
      fieldErrors: [{ path: fieldPath, code: "INVALID_HASH" }]
    });
  }
  return parseSha256Hex(Buffer.from(bytes).toString("hex"), fieldPath);
}

export function sha256HexToFixedBytes(hex: Sha256Hex | string, fieldPath = "sha256"): Uint8Array {
  const canonical = parseSha256Hex(hex, fieldPath);
  return sha256HexToBytes(canonical);
}

export function extractRawHeaderValues(
  rawHeaders: readonly string[],
  headerName: string
): readonly string[] {
  const target = headerName.toLowerCase();
  const values: string[] = [];
  for (let i = 0; i + 1 < rawHeaders.length; i += 2) {
    const name = rawHeaders[i];
    const value = rawHeaders[i + 1];
    if (typeof name === "string" && typeof value === "string" && name.toLowerCase() === target) {
      values.push(value);
    }
  }
  return Object.freeze(values);
}

export function parseSingleCookieFromHeaderValues(
  cookieHeaderValues: string | readonly string[] | undefined,
  expectedCookieName: string
): string | null {
  if (cookieHeaderValues === undefined) {
    return null;
  }
  const headers =
    typeof cookieHeaderValues === "string" ? [cookieHeaderValues] : cookieHeaderValues;

  let matchedValue: string | null = null;
  let matchCount = 0;

  for (const headerLine of headers) {
    if (typeof headerLine !== "string" || headerLine.length === 0) {
      continue;
    }
    const pairs = headerLine.split(";");
    for (const pair of pairs) {
      const trimmed = pair.trim();
      if (trimmed.length === 0) {
        continue;
      }
      const eqIdx = trimmed.indexOf("=");
      if (eqIdx <= 0) {
        continue;
      }
      const name = trimmed.slice(0, eqIdx).trim();
      if (name !== expectedCookieName) {
        continue;
      }
      matchCount += 1;
      if (matchCount > 1) {
        throw new AuthenticationDomainError({
          code: "UNAUTHENTICATED",
          message: `Duplicate or conflicting "${expectedCookieName}" cookie`
        });
      }
      const rawVal = trimmed.slice(eqIdx + 1).trim();
      if (rawVal.length === 0) {
        throw new AuthenticationDomainError({
          code: "UNAUTHENTICATED",
          message: `Empty "${expectedCookieName}" cookie`
        });
      }
      matchedValue = rawVal;
    }
  }

  return matchedValue;
}

export function parseSingleCookieFromRawHeaders(
  rawHeaders: readonly string[],
  expectedCookieName: string
): string | null {
  const cookieHeaders = extractRawHeaderValues(rawHeaders, "cookie");
  return parseSingleCookieFromHeaderValues(cookieHeaders, expectedCookieName);
}

export function decodeStrict32ByteTokenCookie(
  rawCookieValue: string,
  fieldPath = "cookie"
): Uint8Array {
  try {
    return decodeBase64UrlStrict(rawCookieValue, fieldPath, { exactByteLength: 32 });
  } catch {
    throw new AuthenticationDomainError({
      code: "UNAUTHENTICATED",
      message: "Invalid or malformed authentication cookie token"
    });
  }
}

export function formatSetCookieHeader(options: {
  readonly name: string;
  readonly value: string;
  readonly maxAgeSeconds: number;
  readonly cookieProfile: AuthCookieProfile;
}): string {
  const secure = options.cookieProfile === "release_https";
  if (options.name.startsWith("__Host-") && !secure) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: "__Host- cookies require release_https Secure profile"
    });
  }
  const maxAge = Math.max(0, Math.floor(options.maxAgeSeconds));
  const parts = [`${options.name}=${options.value}`, "Path=/", "HttpOnly", "SameSite=Lax", `Max-Age=${maxAge}`];
  if (secure) {
    parts.push("Secure");
  }
  return parts.join("; ");
}

export function formatClearCookieHeader(options: {
  readonly name: string;
  readonly cookieProfile: AuthCookieProfile;
}): string {
  return formatSetCookieHeader({
    name: options.name,
    value: "",
    maxAgeSeconds: 0,
    cookieProfile: options.cookieProfile
  });
}

export function resolveSingleHeaderValue(
  headerValue: string | readonly string[] | undefined,
  duplicateMessage: string,
  createError: (message: string) => Error
): string | null {
  if (headerValue === undefined) {
    return null;
  }
  if (typeof headerValue === "string") {
    return headerValue;
  }
  const values: readonly string[] = headerValue;
  if (values.length !== 1) {
    throw createError(duplicateMessage);
  }
  return values[0] ?? null;
}

export function assertAllowedMutationOrigin(
  originHeader: string | readonly string[] | undefined,
  allowedOrigins: readonly string[]
): string {
  const singleOrigin = resolveSingleHeaderValue(
    originHeader,
    "Mutation request requires a single Origin header",
    (message) => new AuthorizationDomainError({ code: "FORBIDDEN", message })
  );
  if (singleOrigin === null || singleOrigin.length === 0 || singleOrigin === "null") {
    throw new AuthorizationDomainError({
      code: "FORBIDDEN",
      message: "Mutation request missing allowed Origin header"
    });
  }
  if (!allowedOrigins.includes(singleOrigin)) {
    throw new AuthorizationDomainError({
      code: "FORBIDDEN",
      message: "Mutation request Origin is not allowlisted"
    });
  }
  return singleOrigin;
}

export function assertInstallationAllowsOrdinaryAccess(
  installation: InstallationAuthoritySnapshot,
  operationLabel = "ordinary authentication"
): void {
  if (installation.mode === "recovery_quarantine" || installation.mode === "retired") {
    throw new AuthenticationDomainError({
      code: "UNAUTHENTICATED",
      message: `Installation mode "${installation.mode}" denies ${operationLabel}`
    });
  }
}

export function assertInstallationAllowsRestrictedRecovery(
  installation: InstallationAuthoritySnapshot,
  operationLabel = "restricted recovery"
): void {
  if (installation.mode === "retired") {
    throw new AuthenticationDomainError({
      code: "UNAUTHENTICATED",
      message: `Installation mode "retired" denies ${operationLabel}`
    });
  }
}

export function extractSafeSingleHeaderValue(
  rawHeaders: readonly string[],
  headerName: string
): string | null {
  const values = extractRawHeaderValues(rawHeaders, headerName);
  if (values.length === 0) {
    return null;
  }
  if (values.length > 1) {
    throw new AuthenticationDomainError({
      code: "UNAUTHENTICATED",
      message: `Duplicate "${headerName}" header rejected`
    });
  }
  return values[0] ?? null;
}
