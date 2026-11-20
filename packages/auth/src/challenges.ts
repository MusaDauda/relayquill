import crypto from "node:crypto";
import type { Temporal } from "@js-temporal/polyfill";
import {
  AUTH_CHALLENGE_MAX_FAILURES,
  AUTH_CHALLENGE_TTL_MS,
  type AuthChallengeId,
  type AuthChallengeKind,
  type AuthChallengeState,
  AuthenticationDomainError,
  ConflictDomainError,
  type ControlEpoch,
  ExpiredDomainError,
  LimitExceededDomainError,
  NotFoundDomainError,
  OpaqueSecret,
  PREAUTH_CONTEXT_TTL_MS,
  type PreauthContextId,
  type PreauthContextState,
  type PrincipalId,
  type SessionId,
  ValidationDomainError,
  addMilliseconds,
  assertCanConsumeAuthChallenge,
  compareInstants,
  minInstant,
  parseAuthChallengeId,
  parseControlEpoch,
  parsePreauthContextId
} from "@relayquill/domain";
import type { AuthConfig } from "@relayquill/runtime";
import {
  type AuthPolicyInput,
  type InstallationAuthoritySnapshot,
  type NormalizedAuthPolicyConfig,
  computeBrowserProofDigest,
  constantTimeEqualBytes,
  decodeStrict32ByteTokenCookie,
  formatClearCookieHeader,
  formatSetCookieHeader,
  generateRandomBase64UrlToken,
  normalizeAuthPolicyConfig,
  parseSingleCookieFromHeaderValues,
  randomBytesCopy,
  resolvePreauthCookieName
} from "./primitives.js";

export const AUTH_CHALLENGE_BYTE_LENGTH = 32 as const;

export interface PreauthContextRecord {
  readonly id: PreauthContextId;
  readonly proofDigest: Uint8Array;
  readonly state: PreauthContextState;
  readonly createdAt: Temporal.Instant;
  readonly expiresAt: Temporal.Instant;
  readonly version: bigint;
}

export interface CreatePreauthContextInput {
  readonly id: PreauthContextId;
  readonly proofDigest: Uint8Array;
  readonly createdAt: Temporal.Instant;
  readonly expiresAt: Temporal.Instant;
}

export interface PreauthContextRepository {
  findPreauthContextByProofDigest(proofDigest: Uint8Array): Promise<PreauthContextRecord | null>;
  findPreauthContextById(id: PreauthContextId): Promise<PreauthContextRecord | null>;
  createPreauthContext(input: CreatePreauthContextInput): Promise<PreauthContextRecord>;
  revokePreauthContext(id: PreauthContextId, expectedVersion: bigint): Promise<PreauthContextRecord>;
}

export class InMemoryPreauthContextRepository implements PreauthContextRepository {
  readonly #byId = new Map<PreauthContextId, PreauthContextRecord>();
  readonly #byDigestHex = new Map<string, PreauthContextId>();

  findPreauthContextByProofDigest(proofDigest: Uint8Array): Promise<PreauthContextRecord | null> {
    const key = Buffer.from(proofDigest).toString("hex");
    const id = this.#byDigestHex.get(key);
    if (id === undefined) {
      return Promise.resolve(null);
    }
    return Promise.resolve(this.#byId.get(id) ?? null);
  }

  findPreauthContextById(id: PreauthContextId): Promise<PreauthContextRecord | null> {
    return Promise.resolve(this.#byId.get(id) ?? null);
  }

  createPreauthContext(input: CreatePreauthContextInput): Promise<PreauthContextRecord> {
    const digestHex = Buffer.from(input.proofDigest).toString("hex");
    if (this.#byId.has(input.id) || this.#byDigestHex.has(digestHex)) {
      return Promise.reject(
        new ConflictDomainError({
          code: "VERSION_CONFLICT",
          message: "Preauthentication context already exists"
        })
      );
    }
    if (compareInstants(input.expiresAt, input.createdAt) <= 0) {
      return Promise.reject(
        new ValidationDomainError({
          code: "INVALID_TIMESTAMP",
          message: "Preauthentication context expiresAt must exceed createdAt"
        })
      );
    }
    const record: PreauthContextRecord = Object.freeze({
      id: parsePreauthContextId(input.id, "preauth_context.id"),
      proofDigest: new Uint8Array(input.proofDigest),
      state: "active",
      createdAt: input.createdAt,
      expiresAt: input.expiresAt,
      version: 1n
    });
    this.#byId.set(record.id, record);
    this.#byDigestHex.set(digestHex, record.id);
    return Promise.resolve(record);
  }

  revokePreauthContext(
    id: PreauthContextId,
    expectedVersion: bigint
  ): Promise<PreauthContextRecord> {
    const current = this.#byId.get(id);
    if (current === undefined) {
      return Promise.reject(
        new NotFoundDomainError({ code: "NOT_FOUND", message: "Preauthentication context not found" })
      );
    }
    if (current.version !== expectedVersion) {
      return Promise.reject(
        new ConflictDomainError({
          code: "VERSION_CONFLICT",
          message: "Preauthentication context version conflict"
        })
      );
    }
    const updated: PreauthContextRecord = Object.freeze({
      ...current,
      state: "revoked",
      version: current.version + 1n
    });
    this.#byId.set(updated.id, updated);
    return Promise.resolve(updated);
  }
}

export interface AuthChallengeRecord {
  readonly id: AuthChallengeId;
  readonly controlEpoch: ControlEpoch;
  readonly humanPrincipalId: PrincipalId | null;
  readonly purpose: AuthChallengeKind;
  readonly challengeBytes: Uint8Array;
  readonly browserProofDigest: Uint8Array;
  readonly preauthContextId: PreauthContextId | null;
  readonly sessionId: SessionId | null;
  readonly action: string | null;
  readonly targetSha256: Uint8Array | null;
  readonly state: AuthChallengeState;
  readonly failureCount: number;
  readonly createdAt: Temporal.Instant;
  readonly expiresAt: Temporal.Instant;
  readonly version: bigint;
}

export interface CreateAuthChallengeInput {
  readonly id: AuthChallengeId;
  readonly controlEpoch: ControlEpoch;
  readonly humanPrincipalId: PrincipalId | null;
  readonly purpose: AuthChallengeKind;
  readonly challengeBytes: Uint8Array;
  readonly browserProofDigest: Uint8Array;
  readonly preauthContextId: PreauthContextId | null;
  readonly sessionId: SessionId | null;
  readonly action: string | null;
  readonly targetSha256: Uint8Array | null;
  readonly createdAt: Temporal.Instant;
  readonly expiresAt: Temporal.Instant;
}

export interface RecordAuthChallengeFailureInput {
  readonly challengeId: AuthChallengeId;
  readonly expectedVersion: bigint;
  readonly now: Temporal.Instant;
}

export interface ConsumeAuthChallengeInput {
  readonly challengeId: AuthChallengeId;
  readonly expectedVersion: bigint;
  readonly expectedControlEpoch: ControlEpoch;
  readonly now: Temporal.Instant;
}

export interface AuthChallengeRepository {
  findChallengeById(id: AuthChallengeId): Promise<AuthChallengeRecord | null>;
  createChallenge(input: CreateAuthChallengeInput): Promise<AuthChallengeRecord>;
  recordChallengeFailure(input: RecordAuthChallengeFailureInput): Promise<AuthChallengeRecord>;
  consumeChallenge(input: ConsumeAuthChallengeInput): Promise<AuthChallengeRecord>;
  revokeChallenge(id: AuthChallengeId, expectedVersion: bigint): Promise<AuthChallengeRecord>;
}

export class InMemoryAuthChallengeRepository implements AuthChallengeRepository {
  readonly #byId = new Map<AuthChallengeId, AuthChallengeRecord>();

  findChallengeById(id: AuthChallengeId): Promise<AuthChallengeRecord | null> {
    return Promise.resolve(this.#byId.get(id) ?? null);
  }

  createChallenge(input: CreateAuthChallengeInput): Promise<AuthChallengeRecord> {
    if (this.#byId.has(input.id)) {
      return Promise.reject(
        new ConflictDomainError({
          code: "VERSION_CONFLICT",
          message: "Auth challenge already exists"
        })
      );
    }
    assertChallengePurposeBinding(input);
    if (compareInstants(input.expiresAt, input.createdAt) <= 0) {
      return Promise.reject(
        new ValidationDomainError({
          code: "INVALID_TIMESTAMP",
          message: "Auth challenge expiresAt must exceed createdAt"
        })
      );
    }
    const record: AuthChallengeRecord = Object.freeze({
      id: parseAuthChallengeId(input.id, "auth_challenge.id"),
      controlEpoch: parseControlEpoch(input.controlEpoch, "auth_challenge.control_epoch"),
      humanPrincipalId: input.humanPrincipalId,
      purpose: input.purpose,
      challengeBytes: new Uint8Array(input.challengeBytes),
      browserProofDigest: new Uint8Array(input.browserProofDigest),
      preauthContextId: input.preauthContextId,
      sessionId: input.sessionId,
      action: input.action,
      targetSha256: input.targetSha256 !== null ? new Uint8Array(input.targetSha256) : null,
      state: "pending",
      failureCount: 0,
      createdAt: input.createdAt,
      expiresAt: input.expiresAt,
      version: 1n
    });
    this.#byId.set(record.id, record);
    return Promise.resolve(record);
  }

  recordChallengeFailure(input: RecordAuthChallengeFailureInput): Promise<AuthChallengeRecord> {
    const current = this.#byId.get(input.challengeId);
    if (current === undefined) {
      return Promise.reject(
        new NotFoundDomainError({ code: "NOT_FOUND", message: "Auth challenge not found" })
      );
    }
    if (current.version !== input.expectedVersion) {
      return Promise.reject(
        new ConflictDomainError({
          code: "VERSION_CONFLICT",
          message: "Auth challenge version conflict"
        })
      );
    }
    if (current.state !== "pending") {
      return Promise.resolve(current);
    }
    if (compareInstants(input.now, current.expiresAt) >= 0) {
      const expired: AuthChallengeRecord = Object.freeze({
        ...current,
        state: "expired",
        version: current.version + 1n
      });
      this.#byId.set(expired.id, expired);
      return Promise.resolve(expired);
    }

    const nextFailures = Math.min(AUTH_CHALLENGE_MAX_FAILURES, current.failureCount + 1);
    const nextState: AuthChallengeState =
      nextFailures >= AUTH_CHALLENGE_MAX_FAILURES ? "denied" : "pending";
    const updated: AuthChallengeRecord = Object.freeze({
      ...current,
      failureCount: nextFailures,
      state: nextState,
      version: current.version + 1n
    });
    this.#byId.set(updated.id, updated);
    return Promise.resolve(updated);
  }

  consumeChallenge(input: ConsumeAuthChallengeInput): Promise<AuthChallengeRecord> {
    const current = this.#byId.get(input.challengeId);
    if (current === undefined) {
      return Promise.reject(
        new NotFoundDomainError({ code: "NOT_FOUND", message: "Auth challenge not found" })
      );
    }
    if (current.version !== input.expectedVersion) {
      return Promise.reject(
        new ConflictDomainError({
          code: "VERSION_CONFLICT",
          message: "Auth challenge version conflict"
        })
      );
    }
    if (current.controlEpoch !== input.expectedControlEpoch) {
      return Promise.reject(
        new AuthenticationDomainError({
          code: "UNAUTHENTICATED",
          message: "Auth challenge control epoch mismatch"
        })
      );
    }
    assertCanConsumeAuthChallenge({
      state: current.state,
      failureCount: current.failureCount,
      expiresAt: current.expiresAt,
      now: input.now
    });
    const consumed: AuthChallengeRecord = Object.freeze({
      ...current,
      state: "consumed",
      version: current.version + 1n
    });
    this.#byId.set(consumed.id, consumed);
    return Promise.resolve(consumed);
  }

  revokeChallenge(id: AuthChallengeId, expectedVersion: bigint): Promise<AuthChallengeRecord> {
    const current = this.#byId.get(id);
    if (current === undefined) {
      return Promise.reject(
        new NotFoundDomainError({ code: "NOT_FOUND", message: "Auth challenge not found" })
      );
    }
    if (current.version !== expectedVersion) {
      return Promise.reject(
        new ConflictDomainError({
          code: "VERSION_CONFLICT",
          message: "Auth challenge version conflict"
        })
      );
    }
    if (current.state !== "pending") {
      return Promise.reject(
        new ConflictDomainError({
          code: "STATE_TRANSITION_NOT_ALLOWED",
          message: `Cannot revoke challenge in state "${current.state}"`
        })
      );
    }
    const revoked: AuthChallengeRecord = Object.freeze({
      ...current,
      state: "revoked",
      version: current.version + 1n
    });
    this.#byId.set(revoked.id, revoked);
    return Promise.resolve(revoked);
  }
}

function assertChallengePurposeBinding(input: {
  readonly purpose: AuthChallengeKind;
  readonly humanPrincipalId: PrincipalId | null;
  readonly preauthContextId: PreauthContextId | null;
  readonly sessionId: SessionId | null;
  readonly action: string | null;
  readonly targetSha256: Uint8Array | null;
}): void {
  if (input.purpose === "step_up") {
    if (
      input.sessionId === null ||
      input.preauthContextId !== null ||
      input.humanPrincipalId === null ||
      input.action === null ||
      input.targetSha256 === null ||
      input.targetSha256.byteLength !== 32
    ) {
      throw new ValidationDomainError({
        code: "INVALID_VALUE",
        message: "step_up challenge requires sessionId, humanPrincipalId, action, and 32-byte targetSha256"
      });
    }
    return;
  }
  if (input.preauthContextId === null || input.sessionId !== null) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `${input.purpose} challenge requires preauthContextId and null sessionId`
    });
  }
}

export interface ResolvedPreauthContext {
  readonly context: PreauthContextRecord;
  readonly proofDigest: Uint8Array;
  readonly reused: boolean;
  readonly cookieName: string;
  readonly setCookieHeader?: OpaqueSecret<string> | undefined;
}

export async function resolveOrCreatePreauthContext(input: {
  readonly policy: NormalizedAuthPolicyConfig | AuthConfig | AuthPolicyInput;
  readonly cookieHeaders: string | readonly string[] | undefined;
  readonly preauthRepo: PreauthContextRepository;
  readonly now: Temporal.Instant;
}): Promise<ResolvedPreauthContext> {
  const policy = normalizeAuthPolicyConfig(input.policy);
  const cookieName = resolvePreauthCookieName(policy.cookieProfile);
  const rawCookie = parseSingleCookieFromHeaderValues(input.cookieHeaders, cookieName);

  if (rawCookie !== null) {
    const rawProofBytes = decodeStrict32ByteTokenCookie(rawCookie, cookieName);
    let proofDigest: Uint8Array;
    try {
      proofDigest = computeBrowserProofDigest(rawProofBytes);
    } finally {
      rawProofBytes.fill(0);
    }
    const existing = await input.preauthRepo.findPreauthContextByProofDigest(proofDigest);
    if (
      existing !== null &&
      existing.state === "active" &&
      compareInstants(input.now, existing.expiresAt) < 0 &&
      constantTimeEqualBytes(existing.proofDigest, proofDigest)
    ) {
      return Object.freeze({
        context: existing,
        proofDigest,
        reused: true,
        cookieName
      });
    }
  }

  const generated = generateRandomBase64UrlToken(32);
  let proofDigest: Uint8Array;
  let cookieHeaderValue: OpaqueSecret<string>;
  try {
    proofDigest = computeBrowserProofDigest(generated.bytes);
    const context = await input.preauthRepo.createPreauthContext({
      id: parsePreauthContextId(crypto.randomUUID(), "preauth_context_id"),
      proofDigest,
      createdAt: input.now,
      expiresAt: addMilliseconds(input.now, PREAUTH_CONTEXT_TTL_MS, "preauth_expires_at")
    });
    cookieHeaderValue = new OpaqueSecret(
      formatSetCookieHeader({
        name: cookieName,
        value: generated.token.expose(),
        maxAgeSeconds: Number(PREAUTH_CONTEXT_TTL_MS / 1000n),
        cookieProfile: policy.cookieProfile
      })
    );
    return Object.freeze({
      context,
      proofDigest,
      reused: false,
      cookieName,
      setCookieHeader: cookieHeaderValue
    });
  } finally {
    generated.bytes.fill(0);
  }
}

export async function requireExistingPreauthContext(input: {
  readonly policy: NormalizedAuthPolicyConfig | AuthConfig | AuthPolicyInput;
  readonly cookieHeaders: string | readonly string[] | undefined;
  readonly preauthRepo: PreauthContextRepository;
  readonly now: Temporal.Instant;
}): Promise<{
  readonly context: PreauthContextRecord;
  readonly proofDigest: Uint8Array;
  readonly cookieName: string;
}> {
  const policy = normalizeAuthPolicyConfig(input.policy);
  const cookieName = resolvePreauthCookieName(policy.cookieProfile);
  const rawCookie = parseSingleCookieFromHeaderValues(input.cookieHeaders, cookieName);
  if (rawCookie === null) {
    throw new AuthenticationDomainError({
      code: "UNAUTHENTICATED",
      message: "Missing preauthentication browser context cookie"
    });
  }
  const rawProofBytes = decodeStrict32ByteTokenCookie(rawCookie, cookieName);
  let proofDigest: Uint8Array;
  try {
    proofDigest = computeBrowserProofDigest(rawProofBytes);
  } finally {
    rawProofBytes.fill(0);
  }
  const existing = await input.preauthRepo.findPreauthContextByProofDigest(proofDigest);
  if (existing === null || !constantTimeEqualBytes(existing.proofDigest, proofDigest)) {
    throw new AuthenticationDomainError({
      code: "UNAUTHENTICATED",
      message: "Unknown or invalid preauthentication browser context"
    });
  }
  if (existing.state !== "active") {
    throw new AuthenticationDomainError({
      code: "UNAUTHENTICATED",
      message: "Preauthentication browser context is no longer active"
    });
  }
  if (compareInstants(input.now, existing.expiresAt) >= 0) {
    throw new ExpiredDomainError({
      code: "EXPIRED",
      message: "Preauthentication browser context has expired"
    });
  }
  return Object.freeze({
    context: existing,
    proofDigest,
    cookieName
  });
}

export function formatClearPreauthCookieHeader(
  policyInput: NormalizedAuthPolicyConfig | AuthConfig | AuthPolicyInput
): string {
  const policy = normalizeAuthPolicyConfig(policyInput);
  return formatClearCookieHeader({
    name: resolvePreauthCookieName(policy.cookieProfile),
    cookieProfile: policy.cookieProfile
  });
}

export function computeClippedChallengeExpiry(input: {
  readonly now: Temporal.Instant;
  readonly parentCutoffs: readonly Temporal.Instant[];
}): Temporal.Instant {
  let expiry = addMilliseconds(input.now, AUTH_CHALLENGE_TTL_MS, "challenge_expires_at");
  for (const cutoff of input.parentCutoffs) {
    expiry = minInstant(expiry, cutoff);
  }
  if (compareInstants(expiry, input.now) <= 0) {
    throw new ExpiredDomainError({
      code: "EXPIRED",
      message: "Parent authentication context has expired"
    });
  }
  return expiry;
}

export function createBrowserBoundChallengeInput(input: {
  readonly controlEpoch: ControlEpoch;
  readonly humanPrincipalId: PrincipalId | null;
  readonly purpose: "enroll_passkey" | "sign_in" | "restricted_recovery";
  readonly preauthContext: PreauthContextRecord;
  readonly extraCutoff?: Temporal.Instant | undefined;
  readonly now: Temporal.Instant;
}): CreateAuthChallengeInput {
  const cutoffs =
    input.extraCutoff !== undefined
      ? [input.preauthContext.expiresAt, input.extraCutoff]
      : [input.preauthContext.expiresAt];
  return Object.freeze({
    id: parseAuthChallengeId(crypto.randomUUID(), "auth_challenge_id"),
    controlEpoch: input.controlEpoch,
    humanPrincipalId: input.humanPrincipalId,
    purpose: input.purpose,
    challengeBytes: randomBytesCopy(AUTH_CHALLENGE_BYTE_LENGTH),
    browserProofDigest: new Uint8Array(input.preauthContext.proofDigest),
    preauthContextId: input.preauthContext.id,
    sessionId: null,
    action: null,
    targetSha256: null,
    createdAt: input.now,
    expiresAt: computeClippedChallengeExpiry({ now: input.now, parentCutoffs: cutoffs })
  });
}

export function assertChallengeReadyForVerification(input: {
  readonly challenge: AuthChallengeRecord | null;
  readonly expectedPurpose: AuthChallengeKind;
  readonly expectedBrowserProofDigest: Uint8Array;
  readonly installation: InstallationAuthoritySnapshot;
  readonly now: Temporal.Instant;
  readonly expectedPreauthContextId?: PreauthContextId | undefined;
  readonly expectedSessionId?: SessionId | undefined;
  readonly expectedHumanPrincipalId?: PrincipalId | undefined;
  readonly expectedAction?: string | undefined;
  readonly expectedTargetSha256?: Uint8Array | undefined;
}): AuthChallengeRecord {
  const ch = input.challenge;
  if (ch === null) {
    throw new AuthenticationDomainError({
      code: "UNAUTHENTICATED",
      message: "Authentication challenge is invalid or expired"
    });
  }
  if (ch.purpose !== input.expectedPurpose) {
    throw new AuthenticationDomainError({
      code: "UNAUTHENTICATED",
      message: "Authentication challenge purpose mismatch"
    });
  }
  if (ch.controlEpoch !== input.installation.controlEpoch) {
    throw new AuthenticationDomainError({
      code: "UNAUTHENTICATED",
      message: "Authentication challenge control epoch is stale"
    });
  }
  if (!constantTimeEqualBytes(ch.browserProofDigest, input.expectedBrowserProofDigest)) {
    throw new AuthenticationDomainError({
      code: "UNAUTHENTICATED",
      message: "Authentication challenge browser binding mismatch"
    });
  }
  if (
    input.expectedPreauthContextId !== undefined &&
    ch.preauthContextId !== input.expectedPreauthContextId
  ) {
    throw new AuthenticationDomainError({
      code: "UNAUTHENTICATED",
      message: "Authentication challenge preauthentication context mismatch"
    });
  }
  if (input.expectedSessionId !== undefined && ch.sessionId !== input.expectedSessionId) {
    throw new AuthenticationDomainError({
      code: "UNAUTHENTICATED",
      message: "Authentication challenge session mismatch"
    });
  }
  if (
    input.expectedHumanPrincipalId !== undefined &&
    ch.humanPrincipalId !== input.expectedHumanPrincipalId
  ) {
    throw new AuthenticationDomainError({
      code: "UNAUTHENTICATED",
      message: "Authentication challenge principal mismatch"
    });
  }
  if (input.expectedAction !== undefined && ch.action !== input.expectedAction) {
    throw new AuthenticationDomainError({
      code: "UNAUTHENTICATED",
      message: "Authentication challenge action mismatch"
    });
  }
  if (input.expectedTargetSha256 !== undefined) {
    if (
      ch.targetSha256 === null ||
      !constantTimeEqualBytes(ch.targetSha256, input.expectedTargetSha256)
    ) {
      throw new AuthenticationDomainError({
        code: "UNAUTHENTICATED",
        message: "Authentication challenge target hash mismatch"
      });
    }
  }
  if (ch.failureCount >= AUTH_CHALLENGE_MAX_FAILURES) {
    throw new LimitExceededDomainError({
      code: "RATE_LIMITED",
      message: "Auth challenge exceeded maximum failed attempts"
    });
  }
  assertCanConsumeAuthChallenge({
    state: ch.state,
    failureCount: ch.failureCount,
    expiresAt: ch.expiresAt,
    now: input.now
  });
  return ch;
}
