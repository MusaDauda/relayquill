import crypto from "node:crypto";
import type { Temporal } from "@js-temporal/polyfill";
import {
  AuthenticationDomainError,
  AuthorizationDomainError,
  type CanonicalUuid,
  type CommandReceiptId,
  type CommandReceiptScopeKind,
  ConflictDomainError,
  type ControlEpoch,
  ExpiredDomainError,
  NotFoundDomainError,
  OPERATION_PROOF_TTL_MS,
  type OperationProofId,
  type OperationProofState,
  type PrincipalId,
  type ProjectId,
  type SessionId,
  type Sha256Hex,
  type TenantId,
  ValidationDomainError,
  addMilliseconds,
  compareInstants,
  formatUtcTimestamp,
  isCommandReceiptScopeKind,
  minInstant,
  parseAuthChallengeId,
  parseCanonicalUuid,
  parseCommandReceiptId,
  parseNonNegativeInt64BigInt,
  parseOperationProofId,
  parseProjectId,
  parseSha256Hex,
  parseTenantId
} from "@relayquill/domain";
import {
  CAPABILITY_ACTION_REGISTRY,
  encodeDomainLengthPrefixed,
  isCapabilityAction,
  parseSafeReasonCode
} from "@relayquill/contracts";
import type { AuthConfig } from "@relayquill/runtime";
import type { PublicKeyCredentialRequestOptionsJSON } from "@simplewebauthn/server";
import {
  type AuthChallengeRecord,
  type AuthChallengeRepository,
  assertChallengeReadyForVerification,
  computeClippedChallengeExpiry
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
  DIGEST_DOMAIN_STEP_UP_TARGET,
  type InstallationAuthoritySnapshot,
  type NormalizedAuthPolicyConfig,
  constantTimeEqualBytes,
  digestBytesToSha256Hex,
  normalizeAuthPolicyConfig,
  randomBytesCopy,
  sha256HexToFixedBytes
} from "./primitives.js";
import {
  type AuthenticatedHumanSession,
  type HumanSessionRepository,
  authenticateSessionMutation
} from "./sessions.js";

const EXTRA_STEP_UP_ACTIONS = [
  "sessions.revoke_others",
  "tenants.create",
  "platform.identity_manage",
  "platform.recovery_controls",
  "projects.create",
  "tenant.limits.update",
  "tenant_memberships.grant",
  "tenant_memberships.change_role",
  "tenant_memberships.suspend",
  "tenant_memberships.revoke",
  "memberships.grant",
  "project_admins.assign",
  "signing_keys.activate",
  "signing_keys.rotate",
  "producers.scope_versions.create"
] as const;

export const STEP_UP_ALLOWED_ACTIONS: ReadonlySet<string> = new Set([
  ...Object.values(CAPABILITY_ACTION_REGISTRY)
    .filter((entry) => entry.requiresStepUp)
    .map((entry) => entry.action),
  ...EXTRA_STEP_UP_ACTIONS
]);

export function isStepUpAllowedAction(action: unknown): boolean {
  return typeof action === "string" && STEP_UP_ALLOWED_ACTIONS.has(action);
}

export interface StepUpTargetBindingInput {
  readonly action: string;
  readonly scopeKind: CommandReceiptScopeKind;
  readonly tenantId: TenantId | string | null;
  readonly projectId: ProjectId | string | null;
  readonly targetResourceId: CanonicalUuid | string;
  readonly targetVersion: bigint | string | number;
  readonly canonicalCommandSha256: Sha256Hex | string;
}

export interface NormalizedStepUpTargetBinding {
  readonly action: string;
  readonly scopeKind: CommandReceiptScopeKind;
  readonly tenantId: TenantId | null;
  readonly projectId: ProjectId | null;
  readonly targetResourceId: CanonicalUuid;
  readonly targetVersion: bigint;
  readonly canonicalCommandSha256: Sha256Hex;
  readonly targetSha256: Uint8Array;
  readonly targetSha256Hex: Sha256Hex;
}

export function normalizeAndHashStepUpTarget(
  input: StepUpTargetBindingInput
): NormalizedStepUpTargetBinding {
  const action = parseSafeReasonCode(input.action, "action");
  if (!isStepUpAllowedAction(action)) {
    const knownNonStepUp = isCapabilityAction(action);
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: knownNonStepUp
        ? `Action "${action}" does not permit or require operation-bound step-up`
        : `Unsupported step-up action "${action}"`,
      fieldErrors: [{ path: "action", code: "INVALID_VALUE" }]
    });
  }
  if (!isCommandReceiptScopeKind(input.scopeKind)) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Invalid scope_kind "${String(input.scopeKind)}"`,
      fieldErrors: [{ path: "scope_kind", code: "INVALID_VALUE" }]
    });
  }

  let tenantId: TenantId | null = null;
  let projectId: ProjectId | null = null;
  if (input.scopeKind === "installation") {
    if (input.tenantId !== null || input.projectId !== null) {
      throw new ValidationDomainError({
        code: "INVALID_VALUE",
        message: "installation step-up scope requires tenant_id=null and project_id=null"
      });
    }
  } else if (input.scopeKind === "tenant") {
    if (input.tenantId === null || input.projectId !== null) {
      throw new ValidationDomainError({
        code: "INVALID_VALUE",
        message: "tenant step-up scope requires tenant_id and project_id=null"
      });
    }
    tenantId = parseTenantId(input.tenantId, "tenant_id");
  } else {
    if (input.tenantId === null || input.projectId === null) {
      throw new ValidationDomainError({
        code: "INVALID_VALUE",
        message: "project step-up scope requires both tenant_id and project_id"
      });
    }
    tenantId = parseTenantId(input.tenantId, "tenant_id");
    projectId = parseProjectId(input.projectId, "project_id");
  }

  const targetResourceId = parseCanonicalUuid(input.targetResourceId, "target_resource_id");
  const targetVersion = parseNonNegativeInt64BigInt(input.targetVersion, "target_version");
  const canonicalCommandSha256 = parseSha256Hex(
    input.canonicalCommandSha256,
    "canonical_command_sha256"
  );
  const commandHashBytes = sha256HexToFixedBytes(
    canonicalCommandSha256,
    "canonical_command_sha256"
  );

  const preimage = encodeDomainLengthPrefixed(DIGEST_DOMAIN_STEP_UP_TARGET, [
    action,
    input.scopeKind,
    tenantId ?? "",
    projectId ?? "",
    targetResourceId,
    targetVersion.toString(10),
    commandHashBytes
  ]);
  const targetSha256 = new Uint8Array(crypto.createHash("sha256").update(preimage).digest());
  const targetSha256Hex = digestBytesToSha256Hex(targetSha256, "target_sha256");

  return Object.freeze({
    action,
    scopeKind: input.scopeKind,
    tenantId,
    projectId,
    targetResourceId,
    targetVersion,
    canonicalCommandSha256,
    targetSha256,
    targetSha256Hex
  });
}

export function computeStepUpTargetSha256(input: StepUpTargetBindingInput): Uint8Array {
  return normalizeAndHashStepUpTarget(input).targetSha256;
}

export interface OperationProofRecord {
  readonly id: OperationProofId;
  readonly sessionId: SessionId;
  readonly principalId: PrincipalId;
  readonly controlEpoch: ControlEpoch;
  readonly action: string;
  readonly targetSha256: Uint8Array;
  readonly challengeId: AuthChallengeRecord["id"];
  readonly verifiedAt: Temporal.Instant;
  readonly expiresAt: Temporal.Instant;
  readonly state: OperationProofState;
  readonly acceptedReceiptId: CommandReceiptId | null;
  readonly version: bigint;
}

export interface CompleteStepUpAtomicInput {
  readonly proofId: OperationProofId;
  readonly challengeId: AuthChallengeRecord["id"];
  readonly expectedChallengeVersion: bigint;
  readonly expectedControlEpoch: ControlEpoch;
  readonly passkeyId: PasskeyRecord["id"];
  readonly expectedPasskeyVersion: bigint;
  readonly verifiedPasskey: VerifiedPasskeyAuthentication;
  readonly sessionId: SessionId;
  readonly principalId: PrincipalId;
  readonly action: string;
  readonly targetSha256: Uint8Array;
  readonly verifiedAt: Temporal.Instant;
  readonly expiresAt: Temporal.Instant;
}

export interface ConsumeOperationProofInput {
  readonly proofId: OperationProofId;
  readonly expectedVersion: bigint;
  readonly expectedSessionId: SessionId;
  readonly expectedPrincipalId: PrincipalId;
  readonly expectedControlEpoch: ControlEpoch;
  readonly expectedAction: string;
  readonly expectedTargetSha256: Uint8Array;
  readonly acceptedReceiptId: CommandReceiptId;
  readonly now: Temporal.Instant;
}

export interface OperationProofRepository {
  findProofById(id: OperationProofId): Promise<OperationProofRecord | null>;
  completeStepUpAtomic(input: CompleteStepUpAtomicInput): Promise<OperationProofRecord>;
  consumeOperationProof(input: ConsumeOperationProofInput): Promise<OperationProofRecord>;
  revokeOperationProof(id: OperationProofId, expectedVersion: bigint): Promise<OperationProofRecord>;
}

export class InMemoryOperationProofRepository implements OperationProofRepository {
  readonly #byId = new Map<OperationProofId, OperationProofRecord>();
  readonly #byChallengeId = new Set<AuthChallengeRecord["id"]>();
  readonly #challenges: AuthChallengeRepository;
  readonly #passkeys: PasskeyRepository;

  constructor(deps: {
    readonly challengeRepo: AuthChallengeRepository;
    readonly passkeyRepo: PasskeyRepository;
  }) {
    this.#challenges = deps.challengeRepo;
    this.#passkeys = deps.passkeyRepo;
  }

  findProofById(id: OperationProofId): Promise<OperationProofRecord | null> {
    return Promise.resolve(this.#byId.get(id) ?? null);
  }

  async completeStepUpAtomic(input: CompleteStepUpAtomicInput): Promise<OperationProofRecord> {
    if (this.#byId.has(input.proofId) || this.#byChallengeId.has(input.challengeId)) {
      throw new ConflictDomainError({
        code: "VERSION_CONFLICT",
        message: "Operation proof already exists for challenge"
      });
    }
    if (compareInstants(input.expiresAt, input.verifiedAt) <= 0) {
      throw new ExpiredDomainError({
        code: "EXPIRED",
        message: "Session cutoff reached before operation proof issuance"
      });
    }

    await this.#challenges.consumeChallenge({
      challengeId: input.challengeId,
      expectedVersion: input.expectedChallengeVersion,
      expectedControlEpoch: input.expectedControlEpoch,
      now: input.verifiedAt
    });

    await this.#passkeys.recordPasskeyUse({
      passkeyId: input.passkeyId,
      expectedVersion: input.expectedPasskeyVersion,
      newSignCount: input.verifiedPasskey.newSignCount,
      deviceType: input.verifiedPasskey.deviceType,
      backedUp: input.verifiedPasskey.backedUp,
      usedAt: input.verifiedAt
    });

    const record: OperationProofRecord = Object.freeze({
      id: input.proofId,
      sessionId: input.sessionId,
      principalId: input.principalId,
      controlEpoch: input.expectedControlEpoch,
      action: input.action,
      targetSha256: new Uint8Array(input.targetSha256),
      challengeId: input.challengeId,
      verifiedAt: input.verifiedAt,
      expiresAt: input.expiresAt,
      state: "active",
      acceptedReceiptId: null,
      version: 1n
    });
    this.#byId.set(record.id, record);
    this.#byChallengeId.add(record.challengeId);
    return record;
  }

  consumeOperationProof(input: ConsumeOperationProofInput): Promise<OperationProofRecord> {
    const current = this.#byId.get(input.proofId);
    if (current === undefined) {
      return Promise.reject(
        new NotFoundDomainError({ code: "NOT_FOUND", message: "Operation proof not found" })
      );
    }
    if (current.version !== input.expectedVersion) {
      return Promise.reject(
        new ConflictDomainError({
          code: "VERSION_CONFLICT",
          message: "Operation proof version conflict"
        })
      );
    }
    if (
      current.sessionId !== input.expectedSessionId ||
      current.principalId !== input.expectedPrincipalId ||
      current.controlEpoch !== input.expectedControlEpoch
    ) {
      return Promise.reject(
        new AuthorizationDomainError({
          code: "FORBIDDEN",
          message: "Operation proof does not belong to current session or control epoch"
        })
      );
    }
    if (current.state !== "active") {
      return Promise.reject(
        new ConflictDomainError({
          code: "STATE_TRANSITION_NOT_ALLOWED",
          message: `Operation proof is already ${current.state}`
        })
      );
    }
    if (compareInstants(input.now, current.expiresAt) >= 0) {
      return Promise.reject(
        new ExpiredDomainError({
          code: "EXPIRED",
          message: "Operation step-up proof has expired"
        })
      );
    }
    if (
      current.action !== input.expectedAction ||
      !constantTimeEqualBytes(current.targetSha256, input.expectedTargetSha256)
    ) {
      return Promise.reject(
        new AuthorizationDomainError({
          code: "FORBIDDEN",
          message: "Operation proof action or target hash mismatch"
        })
      );
    }

    const consumed: OperationProofRecord = Object.freeze({
      ...current,
      state: "consumed",
      acceptedReceiptId: input.acceptedReceiptId,
      version: current.version + 1n
    });
    this.#byId.set(consumed.id, consumed);
    return Promise.resolve(consumed);
  }

  revokeOperationProof(id: OperationProofId, expectedVersion: bigint): Promise<OperationProofRecord> {
    const current = this.#byId.get(id);
    if (current === undefined) {
      return Promise.reject(
        new NotFoundDomainError({ code: "NOT_FOUND", message: "Operation proof not found" })
      );
    }
    if (current.version !== expectedVersion) {
      return Promise.reject(
        new ConflictDomainError({
          code: "VERSION_CONFLICT",
          message: "Operation proof version conflict"
        })
      );
    }
    if (current.state !== "active") {
      return Promise.reject(
        new ConflictDomainError({
          code: "STATE_TRANSITION_NOT_ALLOWED",
          message: `Cannot revoke operation proof in state "${current.state}"`
        })
      );
    }
    const revoked: OperationProofRecord = Object.freeze({
      ...current,
      state: "revoked",
      version: current.version + 1n
    });
    this.#byId.set(revoked.id, revoked);
    return Promise.resolve(revoked);
  }
}

export interface CreateStepUpOptionsResult {
  readonly auth_challenge_id: AuthChallengeRecord["id"];
  readonly action: string;
  readonly target_sha256: Sha256Hex;
  readonly expires_at: string;
  readonly public_key: PublicKeyCredentialRequestOptionsJSON;
}

export async function createStepUpOptions(input: {
  readonly policy: NormalizedAuthPolicyConfig | AuthConfig | AuthPolicyInput;
  readonly authenticatedSession: AuthenticatedHumanSession;
  readonly installation: InstallationAuthoritySnapshot;
  readonly target: StepUpTargetBindingInput;
  readonly challengeRepo: AuthChallengeRepository;
  readonly passkeyRepo: PasskeyRepository;
  readonly now: Temporal.Instant;
  readonly timeoutMs?: number | undefined;
}): Promise<CreateStepUpOptionsResult> {
  const policy = normalizeAuthPolicyConfig(input.policy);
  const auth = input.authenticatedSession;
  if (auth.session.purpose !== "ordinary") {
    throw new AuthorizationDomainError({
      code: "FORBIDDEN",
      message: "Restricted recovery sessions cannot create ordinary step-up challenges"
    });
  }
  if (auth.session.controlEpoch !== input.installation.controlEpoch) {
    throw new AuthenticationDomainError({
      code: "UNAUTHENTICATED",
      message: "Session control epoch is stale"
    });
  }

  const binding = normalizeAndHashStepUpTarget(input.target);
  const humanPasskeys = await input.passkeyRepo.listPasskeysForHuman(auth.principal.principalId);
  const activePasskeys = humanPasskeys.filter((p) => p.state === "active");
  if (activePasskeys.length === 0) {
    throw new ConflictDomainError({
      code: "STATE_TRANSITION_NOT_ALLOWED",
      message: "No active passkey available for step-up verification"
    });
  }

  const expiresAt = computeClippedChallengeExpiry({
    now: input.now,
    parentCutoffs: [auth.session.idleExpiresAt, auth.session.absoluteExpiresAt]
  });

  const challenge = await input.challengeRepo.createChallenge({
    id: parseAuthChallengeId(crypto.randomUUID(), "auth_challenge_id"),
    controlEpoch: input.installation.controlEpoch,
    humanPrincipalId: auth.principal.principalId,
    purpose: "step_up",
    challengeBytes: randomBytesCopy(32),
    browserProofDigest: auth.sessionBrowserProofDigest,
    preauthContextId: null,
    sessionId: auth.session.id,
    action: binding.action,
    targetSha256: binding.targetSha256,
    createdAt: input.now,
    expiresAt
  });

  const publicKey = await createPasskeyAuthenticationOptions({
    policy,
    challengeBytes: challenge.challengeBytes,
    allowCredentials: activePasskeys,
    timeoutMs: input.timeoutMs
  });

  return Object.freeze({
    auth_challenge_id: challenge.id,
    action: binding.action,
    target_sha256: binding.targetSha256Hex,
    expires_at: formatUtcTimestamp(challenge.expiresAt),
    public_key: publicKey
  });
}

export interface CompleteStepUpResult {
  readonly operation_proof_id: OperationProofId;
  readonly action: string;
  readonly target_sha256: Sha256Hex;
  readonly expires_at: string;
}

export async function completeStepUpChallenge(input: {
  readonly policy: NormalizedAuthPolicyConfig | AuthConfig | AuthPolicyInput;
  readonly authenticatedSession: AuthenticatedHumanSession;
  readonly installation: InstallationAuthoritySnapshot;
  readonly authChallengeId: AuthChallengeRecord["id"] | string;
  readonly response: unknown;
  readonly challengeRepo: AuthChallengeRepository;
  readonly passkeyRepo: PasskeyRepository;
  readonly proofRepo: OperationProofRepository;
  readonly now: Temporal.Instant;
}): Promise<CompleteStepUpResult> {
  const policy = normalizeAuthPolicyConfig(input.policy);
  const auth = input.authenticatedSession;
  const challengeId = parseAuthChallengeId(input.authChallengeId, "auth_challenge_id");

  const storedChallenge = await input.challengeRepo.findChallengeById(challengeId);
  const challenge = assertChallengeReadyForVerification({
    challenge: storedChallenge,
    expectedPurpose: "step_up",
    expectedBrowserProofDigest: auth.sessionBrowserProofDigest,
    installation: input.installation,
    now: input.now,
    expectedSessionId: auth.session.id,
    expectedHumanPrincipalId: auth.principal.principalId
  });
  if (challenge.action === null || challenge.targetSha256 === null) {
    throw new AuthenticationDomainError({
      code: "UNAUTHENTICATED",
      message: "Step-up challenge missing action or target binding"
    });
  }

  let storedPasskey: PasskeyRecord | null = null;
  let verified: VerifiedPasskeyAuthentication;
  try {
    const assertion = parsePasskeyAuthenticationAssertionShape(input.response);
    storedPasskey = await input.passkeyRepo.findPasskeyByCredentialId(assertion.credentialId);
    if (
      storedPasskey === null ||
      storedPasskey.humanPrincipalId !== auth.principal.principalId ||
      storedPasskey.state !== "active"
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
      requireUserHandle: false,
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
      message: "Step-up passkey verification failed"
    });
  }

  const proofExpiresAt = minInstant(
    addMilliseconds(input.now, OPERATION_PROOF_TTL_MS, "operation_proof_expires_at"),
    minInstant(auth.session.idleExpiresAt, auth.session.absoluteExpiresAt)
  );

  const proof = await input.proofRepo.completeStepUpAtomic({
    proofId: parseOperationProofId(crypto.randomUUID(), "operation_proof_id"),
    challengeId: challenge.id,
    expectedChallengeVersion: challenge.version,
    expectedControlEpoch: input.installation.controlEpoch,
    passkeyId: storedPasskey.id,
    expectedPasskeyVersion: storedPasskey.version,
    verifiedPasskey: verified,
    sessionId: auth.session.id,
    principalId: auth.principal.principalId,
    action: challenge.action,
    targetSha256: challenge.targetSha256,
    verifiedAt: input.now,
    expiresAt: proofExpiresAt
  });

  return Object.freeze({
    operation_proof_id: proof.id,
    action: proof.action,
    target_sha256: digestBytesToSha256Hex(proof.targetSha256, "target_sha256"),
    expires_at: formatUtcTimestamp(proof.expiresAt)
  });
}

export async function verifyAndConsumeOperationProof(input: {
  readonly proofId: OperationProofId | string;
  readonly authenticatedSession: AuthenticatedHumanSession;
  readonly installation: InstallationAuthoritySnapshot;
  readonly expectedBinding: StepUpTargetBindingInput;
  readonly acceptedReceiptId: CommandReceiptId | string;
  readonly proofRepo: OperationProofRepository;
  readonly now: Temporal.Instant;
}): Promise<OperationProofRecord> {
  const proofId = parseOperationProofId(input.proofId, "operation_proof_id");
  const receiptId = parseCommandReceiptId(input.acceptedReceiptId, "accepted_receipt_id");
  const binding = normalizeAndHashStepUpTarget(input.expectedBinding);
  const auth = input.authenticatedSession;

  if (auth.session.purpose !== "ordinary") {
    throw new AuthorizationDomainError({
      code: "FORBIDDEN",
      message: "Restricted recovery session cannot consume ordinary operation proof"
    });
  }
  if (auth.session.controlEpoch !== input.installation.controlEpoch) {
    throw new AuthenticationDomainError({
      code: "UNAUTHENTICATED",
      message: "Session control epoch is stale"
    });
  }

  const proof = await input.proofRepo.findProofById(proofId);
  if (proof === null) {
    throw new AuthorizationDomainError({
      code: "FORBIDDEN",
      message: "Operation step-up proof not found"
    });
  }
  if (proof.sessionId !== auth.session.id || proof.principalId !== auth.principal.principalId) {
    throw new AuthorizationDomainError({
      code: "FORBIDDEN",
      message: "Operation step-up proof does not match current session principal"
    });
  }
  if (proof.controlEpoch !== input.installation.controlEpoch) {
    throw new AuthorizationDomainError({
      code: "FORBIDDEN",
      message: "Operation step-up proof control epoch is stale"
    });
  }
  if (proof.state !== "active") {
    throw new ConflictDomainError({
      code: "STATE_TRANSITION_NOT_ALLOWED",
      message: `Operation step-up proof is already ${proof.state}`
    });
  }
  if (compareInstants(input.now, proof.expiresAt) >= 0) {
    throw new ExpiredDomainError({
      code: "EXPIRED",
      message: "Operation step-up proof has expired"
    });
  }
  if (
    proof.action !== binding.action ||
    !constantTimeEqualBytes(proof.targetSha256, binding.targetSha256)
  ) {
    throw new AuthorizationDomainError({
      code: "FORBIDDEN",
      message: "Operation step-up proof is bound to a different action, resource, version, or command hash"
    });
  }

  return input.proofRepo.consumeOperationProof({
    proofId: proof.id,
    expectedVersion: proof.version,
    expectedSessionId: auth.session.id,
    expectedPrincipalId: auth.principal.principalId,
    expectedControlEpoch: input.installation.controlEpoch,
    expectedAction: binding.action,
    expectedTargetSha256: binding.targetSha256,
    acceptedReceiptId: receiptId,
    now: input.now
  });
}

export async function revokeOtherHumanSessionsWithStepUp(input: {
  readonly policy: NormalizedAuthPolicyConfig | AuthConfig | AuthPolicyInput;
  readonly installation: InstallationAuthoritySnapshot;
  readonly cookieHeaders: string | readonly string[] | undefined;
  readonly originHeader: string | readonly string[] | undefined;
  readonly csrfHeader: string | readonly string[] | undefined;
  readonly operationProofId: OperationProofId | string;
  readonly canonicalCommandSha256: Sha256Hex | string;
  readonly acceptedReceiptId: CommandReceiptId | string;
  readonly sessionRepo: HumanSessionRepository;
  readonly proofRepo: OperationProofRepository;
  readonly now: Temporal.Instant;
}): Promise<{
  readonly revoked_count: number;
  readonly kept_session_id: SessionId;
}> {
  const auth = await authenticateSessionMutation({
    policy: input.policy,
    installation: input.installation,
    cookieHeaders: input.cookieHeaders,
    originHeader: input.originHeader,
    csrfHeader: input.csrfHeader,
    sessionRepo: input.sessionRepo,
    now: input.now
  });

  try {
    await verifyAndConsumeOperationProof({
      proofId: input.operationProofId,
      authenticatedSession: auth,
      installation: input.installation,
      expectedBinding: {
        action: "sessions.revoke_others",
        scopeKind: "installation",
        tenantId: null,
        projectId: null,
        targetResourceId: auth.principal.principalId,
        targetVersion: auth.principal.version,
        canonicalCommandSha256: input.canonicalCommandSha256
      },
      acceptedReceiptId: input.acceptedReceiptId,
      proofRepo: input.proofRepo,
      now: input.now
    });

    const revokedCount = await input.sessionRepo.revokeOtherSessionsForPrincipal({
      principalId: auth.principal.principalId,
      keepSessionId: auth.session.id,
      revokedAt: input.now
    });

    return Object.freeze({
      revoked_count: revokedCount,
      kept_session_id: auth.session.id
    });
  } finally {
    auth.destroySecrets();
  }
}
