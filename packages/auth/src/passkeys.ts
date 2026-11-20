import type { Temporal } from "@js-temporal/polyfill";
import {
  AuthenticationDomainError,
  type CanonicalUuid,
  ConflictDomainError,
  NotFoundDomainError,
  type PasskeyState,
  type PrincipalId,
  ValidationDomainError,
  compareInstants,
  isPasskeyState,
  parseCanonicalUuid
} from "@relayquill/domain";
import {
  type Base64UrlString,
  decodeBase64UrlStrict,
  encodeBase64Url,
  parseBoundedString
} from "@relayquill/contracts";
import type { AuthConfig } from "@relayquill/runtime";
import {
  type AuthenticationResponseJSON,
  type CredentialDeviceType,
  type PublicKeyCredentialCreationOptionsJSON,
  type PublicKeyCredentialRequestOptionsJSON,
  type RegistrationResponseJSON,
  generateAuthenticationOptions,
  generateRegistrationOptions,
  getDefaultSupportedAlgorithmIDs,
  verifyAuthenticationResponse,
  verifyRegistrationResponse
} from "@simplewebauthn/server";
import {
  type AuthPolicyInput,
  type NormalizedAuthPolicyConfig,
  constantTimeEqualBytes,
  normalizeAuthPolicyConfig,
  randomBytesCopy
} from "./primitives.js";

export const WEBAUTHN_USER_ID_BYTE_LENGTH = 32 as const;
export const WEBAUTHN_USER_ID_MIN_BYTES = 16 as const;
export const WEBAUTHN_USER_ID_MAX_BYTES = 64 as const;
export const WEBAUTHN_DEFAULT_TIMEOUT_MS = 60_000 as const;

export const ALLOWED_PASSKEY_TRANSPORTS = [
  "usb",
  "nfc",
  "ble",
  "smart-card",
  "hybrid",
  "internal"
] as const;

export type AllowedPasskeyTransport = (typeof ALLOWED_PASSKEY_TRANSPORTS)[number];
const ALLOWED_TRANSPORT_SET = new Set<string>(ALLOWED_PASSKEY_TRANSPORTS);

export interface PasskeyRecord {
  readonly id: CanonicalUuid;
  readonly humanPrincipalId: PrincipalId;
  readonly credentialId: Uint8Array;
  readonly publicKey: Uint8Array;
  readonly webauthnUserId: Uint8Array;
  readonly signCount: bigint;
  readonly deviceType: CredentialDeviceType;
  readonly backedUp: boolean;
  readonly transports: readonly AllowedPasskeyTransport[];
  readonly state: PasskeyState;
  readonly enrolledAt: Temporal.Instant;
  readonly lastUsedAt: Temporal.Instant | null;
  readonly revokedAt: Temporal.Instant | null;
  readonly version: bigint;
}

export interface CreatePasskeyInput {
  readonly id: CanonicalUuid;
  readonly humanPrincipalId: PrincipalId;
  readonly credentialId: Uint8Array;
  readonly publicKey: Uint8Array;
  readonly webauthnUserId: Uint8Array;
  readonly signCount: bigint;
  readonly deviceType: CredentialDeviceType;
  readonly backedUp: boolean;
  readonly transports: readonly AllowedPasskeyTransport[];
  readonly state: PasskeyState;
  readonly enrolledAt: Temporal.Instant;
}

export interface RecordPasskeyUseInput {
  readonly passkeyId: CanonicalUuid;
  readonly expectedVersion: bigint;
  readonly newSignCount: bigint;
  readonly deviceType: CredentialDeviceType;
  readonly backedUp: boolean;
  readonly usedAt: Temporal.Instant;
}

export interface UpdatePasskeyStateInput {
  readonly passkeyId: CanonicalUuid;
  readonly expectedVersion: bigint;
  readonly toState: PasskeyState;
  readonly revokedAt?: Temporal.Instant | null | undefined;
}

export interface PasskeyRepository {
  findPasskeyByCredentialId(credentialId: Uint8Array): Promise<PasskeyRecord | null>;
  listPasskeysForHuman(humanPrincipalId: PrincipalId): Promise<readonly PasskeyRecord[]>;
  createPasskey(input: CreatePasskeyInput): Promise<PasskeyRecord>;
  recordPasskeyUse(input: RecordPasskeyUseInput): Promise<PasskeyRecord>;
  updatePasskeyState(input: UpdatePasskeyStateInput): Promise<PasskeyRecord>;
}

export class InMemoryPasskeyRepository implements PasskeyRepository {
  readonly #byId = new Map<CanonicalUuid, PasskeyRecord>();
  readonly #byCredentialHex = new Map<string, CanonicalUuid>();

  findPasskeyByCredentialId(credentialId: Uint8Array): Promise<PasskeyRecord | null> {
    const key = Buffer.from(credentialId).toString("hex");
    const id = this.#byCredentialHex.get(key);
    if (id === undefined) {
      return Promise.resolve(null);
    }
    return Promise.resolve(this.#byId.get(id) ?? null);
  }

  listPasskeysForHuman(humanPrincipalId: PrincipalId): Promise<readonly PasskeyRecord[]> {
    const out: PasskeyRecord[] = [];
    for (const record of this.#byId.values()) {
      if (record.humanPrincipalId === humanPrincipalId) {
        out.push(record);
      }
    }
    out.sort((a, b) => compareInstants(a.enrolledAt, b.enrolledAt));
    return Promise.resolve(Object.freeze(out));
  }

  createPasskey(input: CreatePasskeyInput): Promise<PasskeyRecord> {
    const credHex = Buffer.from(input.credentialId).toString("hex");
    if (this.#byId.has(input.id) || this.#byCredentialHex.has(credHex)) {
      return Promise.reject(
        new ConflictDomainError({
          code: "VERSION_CONFLICT",
          message: "Passkey credential already exists"
        })
      );
    }
    const record: PasskeyRecord = Object.freeze({
      id: parseCanonicalUuid(input.id, "passkey.id"),
      humanPrincipalId: input.humanPrincipalId,
      credentialId: new Uint8Array(input.credentialId),
      publicKey: new Uint8Array(input.publicKey),
      webauthnUserId: new Uint8Array(input.webauthnUserId),
      signCount: input.signCount,
      deviceType: input.deviceType,
      backedUp: input.backedUp,
      transports: Object.freeze([...input.transports]),
      state: input.state,
      enrolledAt: input.enrolledAt,
      lastUsedAt: null,
      revokedAt: null,
      version: 1n
    });
    this.#byId.set(record.id, record);
    this.#byCredentialHex.set(credHex, record.id);
    return Promise.resolve(record);
  }

  recordPasskeyUse(input: RecordPasskeyUseInput): Promise<PasskeyRecord> {
    const current = this.#byId.get(input.passkeyId);
    if (current === undefined) {
      return Promise.reject(
        new NotFoundDomainError({ code: "NOT_FOUND", message: "Passkey not found" })
      );
    }
    if (current.version !== input.expectedVersion) {
      return Promise.reject(
        new ConflictDomainError({ code: "VERSION_CONFLICT", message: "Passkey version conflict" })
      );
    }
    const updated: PasskeyRecord = Object.freeze({
      ...current,
      signCount: input.newSignCount,
      deviceType: input.deviceType,
      backedUp: input.backedUp,
      lastUsedAt: input.usedAt,
      version: current.version + 1n
    });
    this.#byId.set(updated.id, updated);
    return Promise.resolve(updated);
  }

  updatePasskeyState(input: UpdatePasskeyStateInput): Promise<PasskeyRecord> {
    const current = this.#byId.get(input.passkeyId);
    if (current === undefined) {
      return Promise.reject(
        new NotFoundDomainError({ code: "NOT_FOUND", message: "Passkey not found" })
      );
    }
    if (current.version !== input.expectedVersion) {
      return Promise.reject(
        new ConflictDomainError({ code: "VERSION_CONFLICT", message: "Passkey version conflict" })
      );
    }
    if (!isPasskeyState(input.toState)) {
      return Promise.reject(
        new ValidationDomainError({ code: "INVALID_VALUE", message: "Invalid passkey state" })
      );
    }
    const updated: PasskeyRecord = Object.freeze({
      ...current,
      state: input.toState,
      revokedAt: input.revokedAt !== undefined ? input.revokedAt : current.revokedAt,
      version: current.version + 1n
    });
    this.#byId.set(updated.id, updated);
    return Promise.resolve(updated);
  }
}

export function generateOpaqueWebAuthnUserId(): Uint8Array {
  return randomBytesCopy(WEBAUTHN_USER_ID_BYTE_LENGTH);
}

export function assertValidWebAuthnUserId(bytes: Uint8Array, fieldPath = "webauthn_user_id"): void {
  if (
    !(bytes instanceof Uint8Array) ||
    bytes.byteLength < WEBAUTHN_USER_ID_MIN_BYTES ||
    bytes.byteLength > WEBAUTHN_USER_ID_MAX_BYTES
  ) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `${fieldPath} must be between ${WEBAUTHN_USER_ID_MIN_BYTES} and ${WEBAUTHN_USER_ID_MAX_BYTES} bytes`,
      fieldErrors: [{ path: fieldPath, code: "INVALID_VALUE" }]
    });
  }
}

export function normalizeWebAuthnHumanLabel(value: unknown, fieldPath: string): string {
  const parsed = parseBoundedString(value, {
    fieldPath,
    minUtf8Bytes: 1,
    maxUtf8Bytes: 256,
    rejectControlChars: true
  });
  const trimmed = parsed.trim();
  if (trimmed.length === 0) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `${fieldPath} cannot be whitespace-only`,
      fieldErrors: [{ path: fieldPath, code: "INVALID_VALUE" }]
    });
  }
  return trimmed;
}

export function sanitizePasskeyTransports(
  transports: readonly string[] | undefined
): readonly AllowedPasskeyTransport[] {
  if (!Array.isArray(transports) || transports.length === 0) {
    return Object.freeze([]);
  }
  const unique: AllowedPasskeyTransport[] = [];
  const seen = new Set<string>();
  for (const item of transports) {
    if (typeof item === "string" && ALLOWED_TRANSPORT_SET.has(item) && !seen.has(item)) {
      seen.add(item);
      unique.push(item as AllowedPasskeyTransport);
      if (unique.length >= ALLOWED_PASSKEY_TRANSPORTS.length) {
        break;
      }
    }
  }
  return Object.freeze(unique);
}

export interface CreatePasskeyRegistrationOptionsInput {
  readonly policy: NormalizedAuthPolicyConfig | AuthConfig | AuthPolicyInput;
  readonly challengeBytes: Uint8Array;
  readonly webauthnUserId: Uint8Array;
  readonly userName: string;
  readonly userDisplayName?: string | undefined;
  readonly excludeCredentials?: readonly PasskeyRecord[] | undefined;
  readonly timeoutMs?: number | undefined;
  readonly supportedAlgorithmIDs?: readonly number[] | undefined;
}

export async function createPasskeyRegistrationOptions(
  input: CreatePasskeyRegistrationOptionsInput
): Promise<PublicKeyCredentialCreationOptionsJSON> {
  const policy = normalizeAuthPolicyConfig(input.policy);
  assertValidWebAuthnUserId(input.webauthnUserId, "webauthn_user_id");
  if (input.challengeBytes.byteLength < 16 || input.challengeBytes.byteLength > 128) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: "WebAuthn registration challenge must be 16..128 bytes"
    });
  }

  const userName = normalizeWebAuthnHumanLabel(input.userName, "user.name");
  const userDisplayName =
    input.userDisplayName !== undefined
      ? normalizeWebAuthnHumanLabel(input.userDisplayName, "user.displayName")
      : userName;

  const excludeCredentials = (input.excludeCredentials ?? [])
    .filter((cred) => cred.state !== "revoked")
    .map((cred) => ({
      id: encodeBase64Url(cred.credentialId),
      ...(cred.transports.length > 0 ? { transports: [...cred.transports] } : {})
    }));

  const supportedAlgorithmIDs =
    input.supportedAlgorithmIDs !== undefined
      ? [...input.supportedAlgorithmIDs]
      : getDefaultSupportedAlgorithmIDs();

  return generateRegistrationOptions({
    rpName: policy.rpName,
    rpID: policy.rpId,
    userName,
    userDisplayName,
    userID: new Uint8Array(input.webauthnUserId).slice(),
    challenge: new Uint8Array(input.challengeBytes).slice(),
    timeout: input.timeoutMs ?? WEBAUTHN_DEFAULT_TIMEOUT_MS,
    attestationType: "none",
    excludeCredentials,
    authenticatorSelection: {
      residentKey: "required",
      requireResidentKey: true,
      userVerification: "required"
    },
    supportedAlgorithmIDs
  });
}

export interface VerifyPasskeyRegistrationInput {
  readonly policy: NormalizedAuthPolicyConfig | AuthConfig | AuthPolicyInput;
  readonly response: unknown;
  readonly expectedChallengeBytes: Uint8Array;
  readonly supportedAlgorithmIDs?: readonly number[] | undefined;
}

export interface VerifiedPasskeyRegistration {
  readonly credentialId: Uint8Array;
  readonly credentialIdBase64Url: Base64UrlString;
  readonly publicKey: Uint8Array;
  readonly signCount: bigint;
  readonly deviceType: CredentialDeviceType;
  readonly backedUp: boolean;
  readonly transports: readonly AllowedPasskeyTransport[];
  readonly aaguid: string;
  readonly origin: string;
  readonly rpId: string;
}

function assertBoundedRegistrationResponseShape(raw: unknown): RegistrationResponseJSON {
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: "Malformed passkey registration ceremony payload"
    });
  }
  const rec = raw as Record<string, unknown>;
  if (
    typeof rec.id !== "string" ||
    typeof rec.rawId !== "string" ||
    rec.type !== "public-key" ||
    typeof rec.response !== "object" ||
    rec.response === null ||
    Array.isArray(rec.response)
  ) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: "Malformed passkey registration response fields"
    });
  }
  const inner = rec.response as Record<string, unknown>;
  if (typeof inner.clientDataJSON !== "string" || typeof inner.attestationObject !== "string") {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: "Passkey registration response missing clientDataJSON or attestationObject"
    });
  }
  decodeBase64UrlStrict(rec.id, "response.id", { maxDecodedBytes: 1024 });
  decodeBase64UrlStrict(inner.clientDataJSON, "response.clientDataJSON", { maxDecodedBytes: 16_384 });
  decodeBase64UrlStrict(inner.attestationObject, "response.attestationObject", {
    maxDecodedBytes: 32_768
  });
  return raw as RegistrationResponseJSON;
}

export async function verifyPasskeyRegistration(
  input: VerifyPasskeyRegistrationInput
): Promise<VerifiedPasskeyRegistration> {
  const policy = normalizeAuthPolicyConfig(input.policy);
  const response = assertBoundedRegistrationResponseShape(input.response);
  const expectedChallenge = encodeBase64Url(input.expectedChallengeBytes);
  const supportedAlgorithmIDs =
    input.supportedAlgorithmIDs !== undefined
      ? [...input.supportedAlgorithmIDs]
      : getDefaultSupportedAlgorithmIDs();

  let verification: Awaited<ReturnType<typeof verifyRegistrationResponse>>;
  try {
    verification = await verifyRegistrationResponse({
      response,
      expectedChallenge,
      expectedOrigin: [...policy.allowedOrigins],
      expectedRPID: policy.rpId,
      requireUserPresence: true,
      requireUserVerification: true,
      supportedAlgorithmIDs
    });
  } catch {
    throw new AuthenticationDomainError({
      code: "UNAUTHENTICATED",
      message: "Passkey registration verification failed"
    });
  }

  if (!verification.verified || verification.registrationInfo === undefined) {
    throw new AuthenticationDomainError({
      code: "UNAUTHENTICATED",
      message: "Passkey registration verification failed"
    });
  }

  const info = verification.registrationInfo;
  if (
    !info.userVerified ||
    info.rpID !== policy.rpId ||
    !policy.allowedOrigins.includes(info.origin)
  ) {
    throw new AuthenticationDomainError({
      code: "UNAUTHENTICATED",
      message: "Passkey registration verification failed"
    });
  }

  const credentialIdBytes = decodeBase64UrlStrict(info.credential.id, "credential.id", {
    maxDecodedBytes: 1024
  });
  if (credentialIdBytes.byteLength < 16 || credentialIdBytes.byteLength > 1024) {
    throw new AuthenticationDomainError({
      code: "UNAUTHENTICATED",
      message: "Passkey credential length outside supported bounds"
    });
  }
  if (info.credential.publicKey.byteLength < 32 || info.credential.publicKey.byteLength > 4096) {
    throw new AuthenticationDomainError({
      code: "UNAUTHENTICATED",
      message: "Passkey public key length outside supported bounds"
    });
  }

  return Object.freeze({
    credentialId: credentialIdBytes,
    credentialIdBase64Url: encodeBase64Url(credentialIdBytes),
    publicKey: new Uint8Array(info.credential.publicKey),
    signCount: BigInt(info.credential.counter),
    deviceType: info.credentialDeviceType,
    backedUp: info.credentialBackedUp,
    transports: sanitizePasskeyTransports(info.credential.transports),
    aaguid: info.aaguid,
    origin: info.origin,
    rpId: info.rpID
  });
}

export interface CreatePasskeyAuthenticationOptionsInput {
  readonly policy: NormalizedAuthPolicyConfig | AuthConfig | AuthPolicyInput;
  readonly challengeBytes: Uint8Array;
  readonly allowCredentials?: readonly PasskeyRecord[] | undefined;
  readonly timeoutMs?: number | undefined;
}

export async function createPasskeyAuthenticationOptions(
  input: CreatePasskeyAuthenticationOptionsInput
): Promise<PublicKeyCredentialRequestOptionsJSON> {
  const policy = normalizeAuthPolicyConfig(input.policy);
  if (input.challengeBytes.byteLength < 16 || input.challengeBytes.byteLength > 128) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: "WebAuthn authentication challenge must be 16..128 bytes"
    });
  }

  const allowCredentials =
    input.allowCredentials !== undefined
      ? input.allowCredentials
          .filter((cred) => cred.state === "active")
          .map((cred) => ({
            id: encodeBase64Url(cred.credentialId),
            ...(cred.transports.length > 0 ? { transports: [...cred.transports] } : {})
          }))
      : undefined;

  return generateAuthenticationOptions({
    rpID: policy.rpId,
    challenge: new Uint8Array(input.challengeBytes).slice(),
    timeout: input.timeoutMs ?? WEBAUTHN_DEFAULT_TIMEOUT_MS,
    userVerification: "required",
    ...(allowCredentials !== undefined ? { allowCredentials } : {})
  });
}

export interface ParsedAuthenticationAssertionShape {
  readonly response: AuthenticationResponseJSON;
  readonly credentialId: Uint8Array;
  readonly userHandle: Uint8Array | null;
}

export function parsePasskeyAuthenticationAssertionShape(
  raw: unknown
): ParsedAuthenticationAssertionShape {
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: "Malformed passkey authentication ceremony payload"
    });
  }
  const rec = raw as Record<string, unknown>;
  if (
    typeof rec.id !== "string" ||
    typeof rec.rawId !== "string" ||
    rec.type !== "public-key" ||
    typeof rec.response !== "object" ||
    rec.response === null ||
    Array.isArray(rec.response)
  ) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: "Malformed passkey authentication response fields"
    });
  }
  const inner = rec.response as Record<string, unknown>;
  if (
    typeof inner.clientDataJSON !== "string" ||
    typeof inner.authenticatorData !== "string" ||
    typeof inner.signature !== "string"
  ) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: "Passkey assertion missing clientDataJSON, authenticatorData, or signature"
    });
  }

  const credentialId = decodeBase64UrlStrict(rec.id, "response.id", { maxDecodedBytes: 1024 });
  if (credentialId.byteLength < 16 || credentialId.byteLength > 1024) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: "Passkey credential ID length outside supported bounds"
    });
  }
  decodeBase64UrlStrict(inner.clientDataJSON, "response.clientDataJSON", { maxDecodedBytes: 16_384 });
  decodeBase64UrlStrict(inner.authenticatorData, "response.authenticatorData", {
    maxDecodedBytes: 8_192
  });
  decodeBase64UrlStrict(inner.signature, "response.signature", { maxDecodedBytes: 2_048 });

  let userHandle: Uint8Array | null = null;
  if (inner.userHandle !== undefined && inner.userHandle !== null) {
    if (typeof inner.userHandle !== "string") {
      throw new ValidationDomainError({
        code: "INVALID_VALUE",
        message: "Passkey userHandle must be a base64url string when present"
      });
    }
    if (inner.userHandle.length > 0) {
      userHandle = decodeBase64UrlStrict(inner.userHandle, "response.userHandle", {
        maxDecodedBytes: WEBAUTHN_USER_ID_MAX_BYTES
      });
    }
  }

  return Object.freeze({
    response: raw as AuthenticationResponseJSON,
    credentialId,
    userHandle
  });
}

export interface VerifyPasskeyAuthenticationInput {
  readonly policy: NormalizedAuthPolicyConfig | AuthConfig | AuthPolicyInput;
  readonly assertion: ParsedAuthenticationAssertionShape;
  readonly storedPasskey: PasskeyRecord;
  readonly expectedChallengeBytes: Uint8Array;
  readonly requireUserHandle?: boolean | undefined;
  readonly allowedCredentialStates?: readonly PasskeyState[] | undefined;
}

export interface VerifiedPasskeyAuthentication {
  readonly passkeyId: CanonicalUuid;
  readonly humanPrincipalId: PrincipalId;
  readonly newSignCount: bigint;
  readonly deviceType: CredentialDeviceType;
  readonly backedUp: boolean;
  readonly origin: string;
  readonly rpId: string;
}

export async function verifyPasskeyAuthentication(
  input: VerifyPasskeyAuthenticationInput
): Promise<VerifiedPasskeyAuthentication> {
  const policy = normalizeAuthPolicyConfig(input.policy);
  const allowedStates = input.allowedCredentialStates ?? ["active"];
  if (!allowedStates.includes(input.storedPasskey.state)) {
    throw new AuthenticationDomainError({
      code: "UNAUTHENTICATED",
      message: "Passkey verification failed"
    });
  }
  if (!constantTimeEqualBytes(input.assertion.credentialId, input.storedPasskey.credentialId)) {
    throw new AuthenticationDomainError({
      code: "UNAUTHENTICATED",
      message: "Passkey verification failed"
    });
  }

  const requireUserHandle = input.requireUserHandle !== false;
  if (requireUserHandle && input.assertion.userHandle === null) {
    throw new AuthenticationDomainError({
      code: "UNAUTHENTICATED",
      message: "Passkey verification failed"
    });
  }
  if (
    input.assertion.userHandle !== null &&
    !constantTimeEqualBytes(input.assertion.userHandle, input.storedPasskey.webauthnUserId)
  ) {
    throw new AuthenticationDomainError({
      code: "UNAUTHENTICATED",
      message: "Passkey verification failed"
    });
  }

  const expectedChallenge = encodeBase64Url(input.expectedChallengeBytes);

  let verification: Awaited<ReturnType<typeof verifyAuthenticationResponse>>;
  try {
    verification = await verifyAuthenticationResponse({
      response: input.assertion.response,
      expectedChallenge,
      expectedOrigin: [...policy.allowedOrigins],
      expectedRPID: policy.rpId,
      credential: {
        id: encodeBase64Url(input.storedPasskey.credentialId),
        publicKey: new Uint8Array(input.storedPasskey.publicKey).slice(),
        counter: Number(input.storedPasskey.signCount),
        ...(input.storedPasskey.transports.length > 0
          ? { transports: [...input.storedPasskey.transports] }
          : {})
      },
      requireUserVerification: true
    });
  } catch {
    throw new AuthenticationDomainError({
      code: "UNAUTHENTICATED",
      message: "Passkey verification failed"
    });
  }

  const info = verification.authenticationInfo;
  if (
    !verification.verified ||
    !info.userVerified ||
    info.rpID !== policy.rpId ||
    !policy.allowedOrigins.includes(info.origin)
  ) {
    throw new AuthenticationDomainError({
      code: "UNAUTHENTICATED",
      message: "Passkey verification failed"
    });
  }

  return Object.freeze({
    passkeyId: input.storedPasskey.id,
    humanPrincipalId: input.storedPasskey.humanPrincipalId,
    newSignCount: BigInt(info.newCounter),
    deviceType: info.credentialDeviceType,
    backedUp: info.credentialBackedUp,
    origin: info.origin,
    rpId: info.rpID
  });
}
