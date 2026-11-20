import crypto from "node:crypto";
import type { Temporal } from "@js-temporal/polyfill";
import {
  AuthenticationDomainError,
  AuthorizationDomainError,
  ConflictDomainError,
  type ControlEpoch,
  ExpiredDomainError,
  HUMAN_SESSION_ABSOLUTE_TTL_MS,
  HUMAN_SESSION_IDLE_TTL_MS,
  type HumanSessionKind,
  type HumanSessionState,
  NotFoundDomainError,
  OpaqueSecret,
  type PrincipalId,
  type SessionId,
  ValidationDomainError,
  addMilliseconds,
  clampDeadline,
  compareInstants,
  diffMilliseconds,
  formatUtcTimestamp,
  isHumanSessionExpired,
  parseCanonicalUuid,
  parseSessionId
} from "@relayquill/domain";
import {
  type Base64UrlString,
  decodeBase64UrlStrict,
  encodeBase64Url
} from "@relayquill/contracts";
import type { AuthConfig } from "@relayquill/runtime";
import type { PublicKeyCredentialRequestOptionsJSON } from "@simplewebauthn/server";
import {
  type AuthChallengeRecord,
  type AuthChallengeRepository,
  type PreauthContextRepository,
  assertChallengeReadyForVerification,
  createBrowserBoundChallengeInput,
  requireExistingPreauthContext,
  resolveOrCreatePreauthContext
} from "./challenges.js";
import {
  type PasskeyRecord,
  type PasskeyRepository,
  type VerifiedPasskeyAuthentication,
  createPasskeyAuthenticationOptions,
  parsePasskeyAuthenticationAssertionShape,
  verifyPasskeyAuthentication
} from "./passkeys.js";
import {
  type AuthPolicyInput,
  type HumanRecord,
  type InstallationAuthoritySnapshot,
  type NormalizedAuthPolicyConfig,
  type PrincipalRecord,
  assertAllowedMutationOrigin,
  assertInstallationAllowsOrdinaryAccess,
  assertInstallationAllowsRestrictedRecovery,
  computeCsrfDigest,
  computeSessionBrowserProofDigest,
  computeSessionTokenDigest,
  constantTimeEqualBytes,
  decodeStrict32ByteTokenCookie,
  deriveCsrfTokenBase64Url,
  deriveCsrfTokenBytes,
  formatClearCookieHeader,
  formatSetCookieHeader,
  generateRandomBase64UrlToken,
  normalizeAuthPolicyConfig,
  parseSingleCookieFromHeaderValues,
  resolveSessionCookieName,
  resolveSingleHeaderValue
} from "./primitives.js";

export const DEFAULT_SESSION_IDLE_TOUCH_MIN_INTERVAL_MS = 60_000n as const;

export interface HumanSessionRecord {
  readonly id: SessionId;
  readonly principalId: PrincipalId;
  readonly controlEpoch: ControlEpoch;
  readonly tokenDigest: Uint8Array;
  readonly csrfDigest: Uint8Array;
  readonly principalAuthorityEpoch: bigint;
  readonly purpose: HumanSessionKind;
  readonly state: HumanSessionState;
  readonly createdAt: Temporal.Instant;
  readonly lastSeenAt: Temporal.Instant;
  readonly idleExpiresAt: Temporal.Instant;
  readonly absoluteExpiresAt: Temporal.Instant;
  readonly revokedAt: Temporal.Instant | null;
  readonly version: bigint;
}

export interface CreateHumanSessionInput {
  readonly id: SessionId;
  readonly principalId: PrincipalId;
  readonly controlEpoch: ControlEpoch;
  readonly tokenDigest: Uint8Array;
  readonly csrfDigest: Uint8Array;
  readonly principalAuthorityEpoch: bigint;
  readonly purpose: HumanSessionKind;
  readonly createdAt: Temporal.Instant;
  readonly idleExpiresAt: Temporal.Instant;
  readonly absoluteExpiresAt: Temporal.Instant;
}

export interface TouchHumanSessionIdleInput {
  readonly sessionId: SessionId;
  readonly expectedVersion: bigint;
  readonly lastSeenAt: Temporal.Instant;
  readonly idleExpiresAt: Temporal.Instant;
}

export interface CompleteSignInAtomicInput {
  readonly challengeId: AuthChallengeRecord["id"];
  readonly expectedChallengeVersion: bigint;
  readonly expectedControlEpoch: ControlEpoch;
  readonly passkeyId: PasskeyRecord["id"];
  readonly expectedPasskeyVersion: bigint;
  readonly verifiedPasskey: VerifiedPasskeyAuthentication;
  readonly session: CreateHumanSessionInput;
  readonly now: Temporal.Instant;
}

export interface HumanSessionPrincipalLookup {
  readonly principal: PrincipalRecord;
  readonly human: HumanRecord;
}

export interface HumanSessionRepository {
  findSessionByTokenDigest(tokenDigest: Uint8Array): Promise<HumanSessionRecord | null>;
  findSessionById(sessionId: SessionId): Promise<HumanSessionRecord | null>;
  getPrincipalAndHumanForSession(
    principalId: PrincipalId
  ): Promise<HumanSessionPrincipalLookup | null>;
  getPrincipalAndHumanByPasskey(
    principalId: PrincipalId
  ): Promise<HumanSessionPrincipalLookup | null>;
  createSession(input: CreateHumanSessionInput): Promise<HumanSessionRecord>;
  completeSignInAtomic(input: CompleteSignInAtomicInput): Promise<HumanSessionRecord>;
  touchSessionIdle(input: TouchHumanSessionIdleInput): Promise<HumanSessionRecord>;
  revokeSession(input: {
    readonly sessionId: SessionId;
    readonly expectedVersion: bigint;
    readonly revokedAt: Temporal.Instant;
  }): Promise<HumanSessionRecord>;
  revokeOtherSessionsForPrincipal(input: {
    readonly principalId: PrincipalId;
    readonly keepSessionId: SessionId;
    readonly revokedAt: Temporal.Instant;
  }): Promise<number>;
}

export class InMemoryHumanSessionRepository implements HumanSessionRepository {
  readonly #byId = new Map<SessionId, HumanSessionRecord>();
  readonly #byTokenDigestHex = new Map<string, SessionId>();
  readonly #principals = new Map<PrincipalId, PrincipalRecord>();
  readonly #humans = new Map<PrincipalId, HumanRecord>();
  readonly #challenges: AuthChallengeRepository;
  readonly #passkeys: PasskeyRepository;
  readonly #externalLookup:
    | ((principalId: PrincipalId) => Promise<HumanSessionPrincipalLookup | null>)
    | undefined;

  constructor(deps: {
    readonly challengeRepo: AuthChallengeRepository;
    readonly passkeyRepo: PasskeyRepository;
    readonly principalLookup?: (principalId: PrincipalId) => Promise<HumanSessionPrincipalLookup | null>;
  }) {
    this.#challenges = deps.challengeRepo;
    this.#passkeys = deps.passkeyRepo;
    this.#externalLookup = deps.principalLookup;
  }

  seedHuman(lookup: HumanSessionPrincipalLookup): void {
    this.#principals.set(lookup.principal.principalId, lookup.principal);
    this.#humans.set(lookup.human.principalId, lookup.human);
  }

  updateSeededPrincipal(principal: PrincipalRecord): void {
    this.#principals.set(principal.principalId, principal);
  }

  async #resolveHuman(principalId: PrincipalId): Promise<HumanSessionPrincipalLookup | null> {
    const localPrincipal = this.#principals.get(principalId);
    const localHuman = this.#humans.get(principalId);
    if (localPrincipal !== undefined && localHuman !== undefined) {
      return { principal: localPrincipal, human: localHuman };
    }
    if (this.#externalLookup !== undefined) {
      const ext = await this.#externalLookup(principalId);
      if (ext !== null) {
        return ext;
      }
    }
    return null;
  }

  findSessionByTokenDigest(tokenDigest: Uint8Array): Promise<HumanSessionRecord | null> {
    const key = Buffer.from(tokenDigest).toString("hex");
    const id = this.#byTokenDigestHex.get(key);
    if (id === undefined) {
      return Promise.resolve(null);
    }
    return Promise.resolve(this.#byId.get(id) ?? null);
  }

  findSessionById(sessionId: SessionId): Promise<HumanSessionRecord | null> {
    return Promise.resolve(this.#byId.get(sessionId) ?? null);
  }

  getPrincipalAndHumanForSession(
    principalId: PrincipalId
  ): Promise<HumanSessionPrincipalLookup | null> {
    return this.#resolveHuman(principalId);
  }

  getPrincipalAndHumanByPasskey(
    principalId: PrincipalId
  ): Promise<HumanSessionPrincipalLookup | null> {
    return this.#resolveHuman(principalId);
  }

  createSession(input: CreateHumanSessionInput): Promise<HumanSessionRecord> {
    const digestHex = Buffer.from(input.tokenDigest).toString("hex");
    if (this.#byId.has(input.id) || this.#byTokenDigestHex.has(digestHex)) {
      return Promise.reject(
        new ConflictDomainError({
          code: "VERSION_CONFLICT",
          message: "Human session already exists"
        })
      );
    }
    if (
      compareInstants(input.idleExpiresAt, input.createdAt) <= 0 ||
      compareInstants(input.absoluteExpiresAt, input.idleExpiresAt) < 0
    ) {
      return Promise.reject(
        new ValidationDomainError({
          code: "INVALID_TIMESTAMP",
          message: "Human session expiry bounds are invalid"
        })
      );
    }
    const record: HumanSessionRecord = Object.freeze({
      id: parseSessionId(input.id, "session.id"),
      principalId: input.principalId,
      controlEpoch: input.controlEpoch,
      tokenDigest: new Uint8Array(input.tokenDigest),
      csrfDigest: new Uint8Array(input.csrfDigest),
      principalAuthorityEpoch: input.principalAuthorityEpoch,
      purpose: input.purpose,
      state: "active",
      createdAt: input.createdAt,
      lastSeenAt: input.createdAt,
      idleExpiresAt: input.idleExpiresAt,
      absoluteExpiresAt: input.absoluteExpiresAt,
      revokedAt: null,
      version: 1n
    });
    this.#byId.set(record.id, record);
    this.#byTokenDigestHex.set(digestHex, record.id);
    return Promise.resolve(record);
  }

  async completeSignInAtomic(input: CompleteSignInAtomicInput): Promise<HumanSessionRecord> {
    await this.#challenges.consumeChallenge({
      challengeId: input.challengeId,
      expectedVersion: input.expectedChallengeVersion,
      expectedControlEpoch: input.expectedControlEpoch,
      now: input.now
    });
    await this.#passkeys.recordPasskeyUse({
      passkeyId: input.passkeyId,
      expectedVersion: input.expectedPasskeyVersion,
      newSignCount: input.verifiedPasskey.newSignCount,
      deviceType: input.verifiedPasskey.deviceType,
      backedUp: input.verifiedPasskey.backedUp,
      usedAt: input.now
    });
    return this.createSession(input.session);
  }

  touchSessionIdle(input: TouchHumanSessionIdleInput): Promise<HumanSessionRecord> {
    const current = this.#byId.get(input.sessionId);
    if (current === undefined) {
      return Promise.reject(
        new NotFoundDomainError({ code: "NOT_FOUND", message: "Human session not found" })
      );
    }
    if (current.version !== input.expectedVersion) {
      return Promise.resolve(current);
    }
    if (current.state !== "active") {
      return Promise.reject(
        new ConflictDomainError({
          code: "STATE_TRANSITION_NOT_ALLOWED",
          message: "Cannot refresh non-active session"
        })
      );
    }
    const clampedIdle = clampDeadline(input.idleExpiresAt, current.absoluteExpiresAt);
    const updated: HumanSessionRecord = Object.freeze({
      ...current,
      lastSeenAt: input.lastSeenAt,
      idleExpiresAt: clampedIdle,
      version: current.version + 1n
    });
    this.#byId.set(updated.id, updated);
    return Promise.resolve(updated);
  }

  revokeSession(input: {
    readonly sessionId: SessionId;
    readonly expectedVersion: bigint;
    readonly revokedAt: Temporal.Instant;
  }): Promise<HumanSessionRecord> {
    const current = this.#byId.get(input.sessionId);
    if (current === undefined) {
      return Promise.reject(
        new NotFoundDomainError({ code: "NOT_FOUND", message: "Human session not found" })
      );
    }
    if (current.version !== input.expectedVersion) {
      return Promise.reject(
        new ConflictDomainError({
          code: "VERSION_CONFLICT",
          message: "Human session version conflict"
        })
      );
    }
    if (current.state === "revoked") {
      return Promise.resolve(current);
    }
    const revoked: HumanSessionRecord = Object.freeze({
      ...current,
      state: "revoked",
      revokedAt: input.revokedAt,
      version: current.version + 1n
    });
    this.#byId.set(revoked.id, revoked);
    return Promise.resolve(revoked);
  }

  revokeOtherSessionsForPrincipal(input: {
    readonly principalId: PrincipalId;
    readonly keepSessionId: SessionId;
    readonly revokedAt: Temporal.Instant;
  }): Promise<number> {
    let count = 0;
    for (const [id, session] of this.#byId.entries()) {
      if (
        session.principalId === input.principalId &&
        session.id !== input.keepSessionId &&
        session.state === "active"
      ) {
        this.#byId.set(
          id,
          Object.freeze({
            ...session,
            state: "revoked",
            revokedAt: input.revokedAt,
            version: session.version + 1n
          })
        );
        count += 1;
      }
    }
    return Promise.resolve(count);
  }
}

export interface CreateSignInOptionsResult {
  readonly auth_challenge_id: AuthChallengeRecord["id"];
  readonly public_key: PublicKeyCredentialRequestOptionsJSON;
  readonly preauthSetCookieHeader?: OpaqueSecret<string> | undefined;
}

export async function createSignInOptions(input: {
  readonly policy: NormalizedAuthPolicyConfig | AuthConfig | AuthPolicyInput;
  readonly installation: InstallationAuthoritySnapshot;
  readonly cookieHeaders: string | readonly string[] | undefined;
  readonly schemaVersion: unknown;
  readonly preauthRepo: PreauthContextRepository;
  readonly challengeRepo: AuthChallengeRepository;
  readonly now: Temporal.Instant;
  readonly timeoutMs?: number | undefined;
}): Promise<CreateSignInOptionsResult> {
  if (input.schemaVersion !== 1) {
    throw new ValidationDomainError({
      code: "UNSUPPORTED_SCHEMA_VERSION",
      message: "Sign-in options request requires schema_version 1",
      fieldErrors: [{ path: "schema_version", code: "UNSUPPORTED_SCHEMA_VERSION" }]
    });
  }
  assertInstallationAllowsOrdinaryAccess(input.installation, "ordinary sign-in");

  const preauth = await resolveOrCreatePreauthContext({
    policy: input.policy,
    cookieHeaders: input.cookieHeaders,
    preauthRepo: input.preauthRepo,
    now: input.now
  });

  const challenge = await input.challengeRepo.createChallenge(
    createBrowserBoundChallengeInput({
      controlEpoch: input.installation.controlEpoch,
      humanPrincipalId: null,
      purpose: "sign_in",
      preauthContext: preauth.context,
      now: input.now
    })
  );

  const publicKey = await createPasskeyAuthenticationOptions({
    policy: input.policy,
    challengeBytes: challenge.challengeBytes,
    timeoutMs: input.timeoutMs
  });

  return Object.freeze({
    auth_challenge_id: challenge.id,
    public_key: publicKey,
    ...(preauth.setCookieHeader !== undefined
      ? { preauthSetCookieHeader: preauth.setCookieHeader }
      : {})
  });
}

export interface SignInMetadataDto {
  readonly session_id: SessionId;
  readonly principal_id: PrincipalId;
  readonly display_name: string;
  readonly purpose: HumanSessionKind;
  readonly created_at: string;
  readonly idle_expires_at: string;
  readonly absolute_expires_at: string;
}

export interface CompleteSignInResult {
  readonly session: SignInMetadataDto;
  readonly sessionSetCookieHeader: OpaqueSecret<string>;
  readonly cacheControl: "no-store";
}

export async function completeSignIn(input: {
  readonly policy: NormalizedAuthPolicyConfig | AuthConfig | AuthPolicyInput;
  readonly installation: InstallationAuthoritySnapshot;
  readonly authChallengeId: AuthChallengeRecord["id"] | string;
  readonly response: unknown;
  readonly cookieHeaders: string | readonly string[] | undefined;
  readonly preauthRepo: PreauthContextRepository;
  readonly challengeRepo: AuthChallengeRepository;
  readonly passkeyRepo: PasskeyRepository;
  readonly sessionRepo: HumanSessionRepository;
  readonly now: Temporal.Instant;
}): Promise<CompleteSignInResult> {
  const policy = normalizeAuthPolicyConfig(input.policy);
  assertInstallationAllowsOrdinaryAccess(input.installation, "ordinary sign-in");

  const challengeId = parseCanonicalUuid(input.authChallengeId, "auth_challenge_id") as AuthChallengeRecord["id"];
  const preauth = await requireExistingPreauthContext({
    policy,
    cookieHeaders: input.cookieHeaders,
    preauthRepo: input.preauthRepo,
    now: input.now
  });

  const storedChallenge = await input.challengeRepo.findChallengeById(challengeId);
  const challenge = assertChallengeReadyForVerification({
    challenge: storedChallenge,
    expectedPurpose: "sign_in",
    expectedBrowserProofDigest: preauth.proofDigest,
    installation: input.installation,
    now: input.now,
    expectedPreauthContextId: preauth.context.id
  });

  let verified: VerifiedPasskeyAuthentication;
  let storedPasskey: PasskeyRecord | null = null;
  let humanLookup: HumanSessionPrincipalLookup | null = null;

  try {
    const assertion = parsePasskeyAuthenticationAssertionShape(input.response);
    storedPasskey = await input.passkeyRepo.findPasskeyByCredentialId(assertion.credentialId);
    if (storedPasskey === null) {
      throw new AuthenticationDomainError({
        code: "UNAUTHENTICATED",
        message: "Passkey verification failed"
      });
    }
    humanLookup = await input.sessionRepo.getPrincipalAndHumanByPasskey(
      storedPasskey.humanPrincipalId
    );
    if (
      humanLookup === null ||
      humanLookup.principal.kind !== "human" ||
      humanLookup.principal.state !== "active"
    ) {
      throw new AuthenticationDomainError({
        code: "UNAUTHENTICATED",
        message: "Passkey verification failed"
      });
    }
    verified = await verifyPasskeyAuthentication({
      policy,
      assertion,
      storedPasskey,
      expectedChallengeBytes: challenge.challengeBytes,
      requireUserHandle: true,
      allowedCredentialStates: ["active"]
    });
  } catch (err) {
    await input.challengeRepo.recordChallengeFailure({
      challengeId: challenge.id,
      expectedVersion: challenge.version,
      now: input.now
    });
    if (err instanceof AuthenticationDomainError || err instanceof ValidationDomainError) {
      throw err;
    }
    throw new AuthenticationDomainError({
      code: "UNAUTHENTICATED",
      message: "Passkey verification failed"
    });
  }

  const generated = generateRandomBase64UrlToken(32);
  let rawCsrfBytes: Uint8Array | null = null;
  try {
    const tokenDigest = computeSessionTokenDigest(generated.bytes);
    rawCsrfBytes = deriveCsrfTokenBytes(generated.bytes);
    const csrfDigest = computeCsrfDigest(rawCsrfBytes);

    const idleExpiresAt = addMilliseconds(input.now, HUMAN_SESSION_IDLE_TTL_MS, "idle_expires_at");
    const absoluteExpiresAt = addMilliseconds(
      input.now,
      HUMAN_SESSION_ABSOLUTE_TTL_MS,
      "absolute_expires_at"
    );

    const createdSession = await input.sessionRepo.completeSignInAtomic({
      challengeId: challenge.id,
      expectedChallengeVersion: challenge.version,
      expectedControlEpoch: input.installation.controlEpoch,
      passkeyId: storedPasskey.id,
      expectedPasskeyVersion: storedPasskey.version,
      verifiedPasskey: verified,
      session: {
        id: parseSessionId(crypto.randomUUID(), "session_id"),
        principalId: humanLookup.principal.principalId,
        controlEpoch: input.installation.controlEpoch,
        tokenDigest,
        csrfDigest,
        principalAuthorityEpoch: humanLookup.principal.authorityEpoch,
        purpose: "ordinary",
        createdAt: input.now,
        idleExpiresAt,
        absoluteExpiresAt
      },
      now: input.now
    });

    const setCookie = new OpaqueSecret(
      formatSetCookieHeader({
        name: resolveSessionCookieName(policy.cookieProfile),
        value: generated.token.expose(),
        maxAgeSeconds: Number(HUMAN_SESSION_ABSOLUTE_TTL_MS / 1000n),
        cookieProfile: policy.cookieProfile
      })
    );

    return Object.freeze({
      session: Object.freeze({
        session_id: createdSession.id,
        principal_id: createdSession.principalId,
        display_name: humanLookup.human.displayName,
        purpose: createdSession.purpose,
        created_at: formatUtcTimestamp(createdSession.createdAt),
        idle_expires_at: formatUtcTimestamp(createdSession.idleExpiresAt),
        absolute_expires_at: formatUtcTimestamp(createdSession.absoluteExpiresAt)
      }),
      sessionSetCookieHeader: setCookie,
      cacheControl: "no-store"
    });
  } finally {
    generated.bytes.fill(0);
    rawCsrfBytes?.fill(0);
  }
}

export interface AuthenticatedHumanSession {
  readonly session: HumanSessionRecord;
  readonly principal: PrincipalRecord;
  readonly human: HumanRecord;
  readonly sessionBrowserProofDigest: Uint8Array;
  deriveCsrfToken(): OpaqueSecret<Base64UrlString>;
  verifyCsrfTokenHeader(csrfHeader: string | readonly string[] | undefined): void;
  destroySecrets(): void;
}

export async function authenticateHumanSession(input: {
  readonly policy: NormalizedAuthPolicyConfig | AuthConfig | AuthPolicyInput;
  readonly installation: InstallationAuthoritySnapshot;
  readonly cookieHeaders: string | readonly string[] | undefined;
  readonly sessionRepo: HumanSessionRepository;
  readonly now: Temporal.Instant;
  readonly idleTouchMinIntervalMs?: bigint | undefined;
  readonly allowRecoveryRestricted?: boolean | undefined;
}): Promise<AuthenticatedHumanSession> {
  const policy = normalizeAuthPolicyConfig(input.policy);
  const cookieName = resolveSessionCookieName(policy.cookieProfile);
  const rawCookie = parseSingleCookieFromHeaderValues(input.cookieHeaders, cookieName);
  if (rawCookie === null) {
    throw new AuthenticationDomainError({
      code: "UNAUTHENTICATED",
      message: "Missing authenticated session cookie"
    });
  }

  const rawSessionBytes = decodeStrict32ByteTokenCookie(rawCookie, cookieName);
  let keepBytes = false;
  try {
    const tokenDigest = computeSessionTokenDigest(rawSessionBytes);
    const session = await input.sessionRepo.findSessionByTokenDigest(tokenDigest);
    if (session === null || !constantTimeEqualBytes(session.tokenDigest, tokenDigest)) {
      throw new AuthenticationDomainError({
        code: "UNAUTHENTICATED",
        message: "Session not found or invalid"
      });
    }

    if (session.purpose === "ordinary") {
      assertInstallationAllowsOrdinaryAccess(input.installation, "human session");
    } else {
      assertInstallationAllowsRestrictedRecovery(input.installation, "restricted session");
      if (input.allowRecoveryRestricted !== true) {
        throw new AuthorizationDomainError({
          code: "FORBIDDEN",
          message: "Restricted recovery session cannot perform ordinary access"
        });
      }
    }

    if (session.controlEpoch !== input.installation.controlEpoch) {
      throw new AuthenticationDomainError({
        code: "UNAUTHENTICATED",
        message: "Session control epoch is stale"
      });
    }

    if (session.state !== "active") {
      throw new AuthenticationDomainError({
        code: "UNAUTHENTICATED",
        message: "Session is no longer active"
      });
    }

    if (
      isHumanSessionExpired({
        state: session.state,
        absoluteExpiresAt: session.absoluteExpiresAt,
        idleExpiresAt: session.idleExpiresAt,
        now: input.now
      })
    ) {
      throw new ExpiredDomainError({
        code: "EXPIRED",
        message: "Human session has expired"
      });
    }

    const humanLookup = await input.sessionRepo.getPrincipalAndHumanForSession(session.principalId);
    if (humanLookup === null || humanLookup.principal.kind !== "human") {
      throw new AuthenticationDomainError({
        code: "UNAUTHENTICATED",
        message: "Session principal is unavailable"
      });
    }
    if (session.purpose === "ordinary" && humanLookup.principal.state !== "active") {
      throw new AuthenticationDomainError({
        code: "UNAUTHENTICATED",
        message: "Human principal is not active"
      });
    }
    if (
      session.purpose === "recovery_restricted" &&
      (humanLookup.principal.state === "suspended" || humanLookup.principal.state === "retired")
    ) {
      throw new AuthenticationDomainError({
        code: "UNAUTHENTICATED",
        message: "Human principal is not eligible for restricted recovery"
      });
    }
    if (session.principalAuthorityEpoch !== humanLookup.principal.authorityEpoch) {
      throw new AuthenticationDomainError({
        code: "UNAUTHENTICATED",
        message: "Session authority epoch is stale"
      });
    }

    let currentSession = session;
    const minInterval = input.idleTouchMinIntervalMs ?? DEFAULT_SESSION_IDLE_TOUCH_MIN_INTERVAL_MS;
    const elapsedSinceTouch = diffMilliseconds(input.now, session.lastSeenAt);
    if (elapsedSinceTouch >= minInterval) {
      const candidateIdle = clampDeadline(
        addMilliseconds(input.now, HUMAN_SESSION_IDLE_TTL_MS, "idle_expires_at"),
        session.absoluteExpiresAt
      );
      currentSession = await input.sessionRepo.touchSessionIdle({
        sessionId: session.id,
        expectedVersion: session.version,
        lastSeenAt: input.now,
        idleExpiresAt: candidateIdle
      });
    }

    const sessionBrowserProofDigest = computeSessionBrowserProofDigest(rawSessionBytes);
    const retainedBytes = new Uint8Array(rawSessionBytes);
    let destroyed = false;
    keepBytes = true;

    const assertLiveBytes = (): Uint8Array => {
      if (destroyed) {
        throw new AuthenticationDomainError({
          code: "UNAUTHENTICATED",
          message: "Session secret material has been destroyed"
        });
      }
      return retainedBytes;
    };

    return Object.freeze({
      session: currentSession,
      principal: humanLookup.principal,
      human: humanLookup.human,
      sessionBrowserProofDigest,
      deriveCsrfToken(): OpaqueSecret<Base64UrlString> {
        const bytes = assertLiveBytes();
        const derived = deriveCsrfTokenBytes(bytes);
        try {
          const derivedDigest = computeCsrfDigest(derived);
          if (!constantTimeEqualBytes(derivedDigest, currentSession.csrfDigest)) {
            throw new AuthenticationDomainError({
              code: "UNAUTHENTICATED",
              message: "Session CSRF binding mismatch"
            });
          }
          return new OpaqueSecret<Base64UrlString>(encodeBase64Url(derived));
        } finally {
          derived.fill(0);
        }
      },
      verifyCsrfTokenHeader(csrfHeader: string | readonly string[] | undefined): void {
        const bytes = assertLiveBytes();
        const singleCsrf = resolveSingleHeaderValue(
          csrfHeader,
          "Duplicate X-CSRF-Token header rejected",
          (message) => new AuthorizationDomainError({ code: "FORBIDDEN", message })
        );
        if (singleCsrf === null || singleCsrf.length === 0) {
          throw new AuthorizationDomainError({
            code: "FORBIDDEN",
            message: "Missing X-CSRF-Token header"
          });
        }
        let presentedBytes: Uint8Array;
        try {
          presentedBytes = decodeBase64UrlStrict(singleCsrf, "x-csrf-token", {
            exactByteLength: 32
          });
        } catch {
          throw new AuthorizationDomainError({
            code: "FORBIDDEN",
            message: "Malformed X-CSRF-Token header"
          });
        }
        const expectedDerived = deriveCsrfTokenBytes(bytes);
        try {
          const presentedDigest = computeCsrfDigest(presentedBytes);
          const digestOk = constantTimeEqualBytes(presentedDigest, currentSession.csrfDigest);
          const derivedOk = constantTimeEqualBytes(presentedBytes, expectedDerived);
          if (!digestOk || !derivedOk) {
            throw new AuthorizationDomainError({
              code: "FORBIDDEN",
              message: "CSRF token verification failed"
            });
          }
        } finally {
          presentedBytes.fill(0);
          expectedDerived.fill(0);
        }
      },
      destroySecrets(): void {
        if (!destroyed) {
          retainedBytes.fill(0);
          destroyed = true;
        }
      }
    });
  } finally {
    if (!keepBytes || rawSessionBytes.byteLength > 0) {
      rawSessionBytes.fill(0);
    }
  }
}

export async function authenticateSessionMutation(input: {
  readonly policy: NormalizedAuthPolicyConfig | AuthConfig | AuthPolicyInput;
  readonly installation: InstallationAuthoritySnapshot;
  readonly cookieHeaders: string | readonly string[] | undefined;
  readonly originHeader: string | readonly string[] | undefined;
  readonly csrfHeader: string | readonly string[] | undefined;
  readonly sessionRepo: HumanSessionRepository;
  readonly now: Temporal.Instant;
  readonly idleTouchMinIntervalMs?: bigint | undefined;
  readonly allowRecoveryRestricted?: boolean | undefined;
}): Promise<AuthenticatedHumanSession> {
  const policy = normalizeAuthPolicyConfig(input.policy);
  assertAllowedMutationOrigin(input.originHeader, policy.allowedOrigins);

  const auth = await authenticateHumanSession({
    policy,
    installation: input.installation,
    cookieHeaders: input.cookieHeaders,
    sessionRepo: input.sessionRepo,
    now: input.now,
    idleTouchMinIntervalMs: input.idleTouchMinIntervalMs,
    allowRecoveryRestricted: input.allowRecoveryRestricted
  });
  try {
    auth.verifyCsrfTokenHeader(input.csrfHeader);
    return auth;
  } catch (err) {
    auth.destroySecrets();
    throw err;
  }
}

export interface SessionContextDto {
  readonly session_id: SessionId;
  readonly principal_id: PrincipalId;
  readonly display_name: string;
  readonly purpose: HumanSessionKind;
  readonly authority_epoch: string;
  readonly created_at: string;
  readonly idle_expires_at: string;
  readonly absolute_expires_at: string;
  readonly csrf_token: OpaqueSecret<Base64UrlString>;
  readonly cacheControl: "no-store";
}

export async function getAuthenticatedSessionContext(input: {
  readonly policy: NormalizedAuthPolicyConfig | AuthConfig | AuthPolicyInput;
  readonly installation: InstallationAuthoritySnapshot;
  readonly cookieHeaders: string | readonly string[] | undefined;
  readonly sessionRepo: HumanSessionRepository;
  readonly now: Temporal.Instant;
  readonly idleTouchMinIntervalMs?: bigint | undefined;
  readonly allowRecoveryRestricted?: boolean | undefined;
}): Promise<SessionContextDto> {
  const auth = await authenticateHumanSession(input);
  try {
    const csrfToken = auth.deriveCsrfToken();
    return Object.freeze({
      session_id: auth.session.id,
      principal_id: auth.principal.principalId,
      display_name: auth.human.displayName,
      purpose: auth.session.purpose,
      authority_epoch: auth.principal.authorityEpoch.toString(10),
      created_at: formatUtcTimestamp(auth.session.createdAt),
      idle_expires_at: formatUtcTimestamp(auth.session.idleExpiresAt),
      absolute_expires_at: formatUtcTimestamp(auth.session.absoluteExpiresAt),
      csrf_token: csrfToken,
      cacheControl: "no-store"
    });
  } finally {
    auth.destroySecrets();
  }
}

export async function logoutHumanSession(input: {
  readonly policy: NormalizedAuthPolicyConfig | AuthConfig | AuthPolicyInput;
  readonly installation: InstallationAuthoritySnapshot;
  readonly cookieHeaders: string | readonly string[] | undefined;
  readonly originHeader: string | readonly string[] | undefined;
  readonly csrfHeader: string | readonly string[] | undefined;
  readonly sessionRepo: HumanSessionRepository;
  readonly now: Temporal.Instant;
}): Promise<{
  readonly logged_out: true;
  readonly session_id: SessionId;
  readonly clearCookieHeader: string;
}> {
  const policy = normalizeAuthPolicyConfig(input.policy);
  const auth = await authenticateSessionMutation({
    ...input,
    policy,
    allowRecoveryRestricted: true
  });
  try {
    await input.sessionRepo.revokeSession({
      sessionId: auth.session.id,
      expectedVersion: auth.session.version,
      revokedAt: input.now
    });
    return Object.freeze({
      logged_out: true,
      session_id: auth.session.id,
      clearCookieHeader: formatClearCookieHeader({
        name: resolveSessionCookieName(policy.cookieProfile),
        cookieProfile: policy.cookieProfile
      })
    });
  } finally {
    auth.destroySecrets();
  }
}

export function deriveSessionCsrfForRawToken(rawSessionTokenBase64Url: string): OpaqueSecret<Base64UrlString> {
  const bytes = decodeBase64UrlStrict(rawSessionTokenBase64Url, "session_token", {
    exactByteLength: 32
  });
  try {
    return deriveCsrfTokenBase64Url(bytes);
  } finally {
    bytes.fill(0);
  }
}
