import crypto from "node:crypto";
import type { Temporal } from "@js-temporal/polyfill";
import {
  AuthenticationDomainError,
  AuthorizationDomainError,
  ConflictDomainError,
  type ControlEpoch,
  ENROLLMENT_INTENT_TTL_MS,
  type EnrollmentIntentId,
  type EnrollmentIntentKind,
  type EnrollmentIntentState,
  ExpiredDomainError,
  LimitExceededDomainError,
  NotFoundDomainError,
  type OpaqueSecret,
  type PasskeyState,
  type PreauthContextId,
  type PrincipalId,
  type ProjectId,
  type Sha256Hex,
  type TenantId,
  ValidationDomainError,
  addMilliseconds,
  compareInstants,
  formatUtcTimestamp,
  isEnrollmentIntentKind,
  minInstant,
  parseCanonicalUuid,
  parseEnrollmentIntentId,
  parsePrincipalId,
  parseProjectId,
  parseTenantId
} from "@relayquill/domain";
import {
  encodeDomainLengthPrefixed,
  parseBoundedString,
  parseSafeReasonCode
} from "@relayquill/contracts";
import type { AuthConfig } from "@relayquill/runtime";
import type { PublicKeyCredentialCreationOptionsJSON } from "@simplewebauthn/server";
import {
  type AuthChallengeRecord,
  type AuthChallengeRepository,
  type PreauthContextRecord,
  type PreauthContextRepository,
  assertChallengeReadyForVerification,
  createBrowserBoundChallengeInput,
  requireExistingPreauthContext,
  resolveOrCreatePreauthContext
} from "./challenges.js";
import {
  type PasskeyRecord,
  type PasskeyRepository,
  type VerifiedPasskeyRegistration,
  createPasskeyRegistrationOptions,
  generateOpaqueWebAuthnUserId,
  normalizeWebAuthnHumanLabel,
  verifyPasskeyRegistration
} from "./passkeys.js";
import {
  type AuthPolicyInput,
  DIGEST_DOMAIN_ENROLLMENT_COMPARISON,
  type HumanRecord,
  type InstallationAuthoritySnapshot,
  type NormalizedAuthPolicyConfig,
  type PrincipalRecord,
  assertInstallationAllowsOrdinaryAccess,
  assertInstallationAllowsRestrictedRecovery,
  constantTimeEqualBytes,
  digestBytesToSha256Hex,
  normalizeAuthPolicyConfig,
  sha256HexToFixedBytes
} from "./primitives.js";

export const MAX_LIVE_ENROLLMENT_INTENTS_PER_BROWSER = 5 as const;
export const MAX_PENDING_INSTALLATION_ENROLLMENT_INTENTS = 1000 as const;

const LIVE_ENROLLMENT_STATES: ReadonlySet<EnrollmentIntentState> = new Set([
  "requested",
  "approved",
  "enrolling"
]);

export function isLiveEnrollmentState(state: EnrollmentIntentState): boolean {
  return LIVE_ENROLLMENT_STATES.has(state);
}

export interface EnrollmentIntentRecord {
  readonly id: EnrollmentIntentId;
  readonly controlEpoch: ControlEpoch;
  readonly purpose: EnrollmentIntentKind;
  readonly targetPrincipalId: PrincipalId | null;
  readonly tenantId: TenantId | null;
  readonly projectId: ProjectId | null;
  readonly browserProofDigest: Uint8Array;
  readonly preauthContextId: PreauthContextId;
  readonly comparisonSha256: Uint8Array;
  readonly referenceTag: string;
  readonly state: EnrollmentIntentState;
  readonly approvedBy: PrincipalId | null;
  readonly operatorEventReference: string | null;
  readonly createdAt: Temporal.Instant;
  readonly expiresAt: Temporal.Instant;
  readonly version: bigint;
}

export interface CreateEnrollmentIntentRecordInput {
  readonly id: EnrollmentIntentId;
  readonly controlEpoch: ControlEpoch;
  readonly purpose: EnrollmentIntentKind;
  readonly targetPrincipalId: PrincipalId | null;
  readonly tenantId: TenantId | null;
  readonly projectId: ProjectId | null;
  readonly browserProofDigest: Uint8Array;
  readonly preauthContextId: PreauthContextId;
  readonly comparisonSha256: Uint8Array;
  readonly referenceTag: string;
  readonly createdAt: Temporal.Instant;
  readonly expiresAt: Temporal.Instant;
  readonly maxLivePerBrowser: number;
  readonly maxLiveInstallation: number;
}

export interface ApproveEnrollmentIntentRecordInput {
  readonly intentId: EnrollmentIntentId;
  readonly expectedVersion: bigint;
  readonly targetPrincipalId: PrincipalId;
  readonly tenantId: TenantId | null;
  readonly projectId: ProjectId | null;
  readonly approvedBy: PrincipalId | null;
  readonly operatorEventReference: string | null;
  readonly provisionHuman?: {
    readonly principalId: PrincipalId;
    readonly displayName: string;
    readonly webauthnUserId: Uint8Array;
    readonly now: Temporal.Instant;
  } | undefined;
}

export interface CompleteEnrollmentAtomicInput {
  readonly intentId: EnrollmentIntentId;
  readonly expectedIntentVersion: bigint;
  readonly challengeId: AuthChallengeRecord["id"];
  readonly expectedChallengeVersion: bigint;
  readonly expectedControlEpoch: ControlEpoch;
  readonly principalId: PrincipalId;
  readonly passkeyId: PasskeyRecord["id"];
  readonly verifiedPasskey: VerifiedPasskeyRegistration;
  readonly passkeyState: PasskeyState;
  readonly webauthnUserId: Uint8Array;
  readonly activateHumanPrincipal: boolean;
  readonly grantPlatformAdmin: boolean;
  readonly now: Temporal.Instant;
}

export interface BootstrapAuthorityPort {
  hasActivePlatformAdmin(): Promise<boolean>;
  getPrincipalAndHuman(principalId: PrincipalId): Promise<{
    readonly principal: PrincipalRecord;
    readonly human: HumanRecord | null;
  } | null>;
}

export interface EnrollmentIntentRepository extends BootstrapAuthorityPort {
  findIntentById(id: EnrollmentIntentId): Promise<EnrollmentIntentRecord | null>;
  countLiveIntentsForPreauth(
    preauthContextId: PreauthContextId,
    now: Temporal.Instant
  ): Promise<number>;
  countLiveInstallationIntents(now: Temporal.Instant): Promise<number>;
  createIntent(input: CreateEnrollmentIntentRecordInput): Promise<EnrollmentIntentRecord>;
  approveIntent(input: ApproveEnrollmentIntentRecordInput): Promise<EnrollmentIntentRecord>;
  markEnrolling(intentId: EnrollmentIntentId, expectedVersion: bigint): Promise<EnrollmentIntentRecord>;
  rejectOrRevokeIntent(
    intentId: EnrollmentIntentId,
    expectedVersion: bigint,
    toState: "rejected" | "revoked"
  ): Promise<EnrollmentIntentRecord>;
  completeEnrollmentAtomic(input: CompleteEnrollmentAtomicInput): Promise<{
    readonly intent: EnrollmentIntentRecord;
    readonly passkey: PasskeyRecord;
  }>;
}

export class InMemoryEnrollmentIntentRepository implements EnrollmentIntentRepository {
  readonly #intents = new Map<EnrollmentIntentId, EnrollmentIntentRecord>();
  readonly #principals = new Map<PrincipalId, PrincipalRecord>();
  readonly #humans = new Map<PrincipalId, HumanRecord>();
  readonly #platformAdmins = new Set<PrincipalId>();
  readonly #challenges: AuthChallengeRepository;
  readonly #passkeys: PasskeyRepository;

  constructor(deps: {
    readonly challengeRepo: AuthChallengeRepository;
    readonly passkeyRepo: PasskeyRepository;
  }) {
    this.#challenges = deps.challengeRepo;
    this.#passkeys = deps.passkeyRepo;
  }

  seedHumanPrincipal(input: {
    readonly principal: PrincipalRecord;
    readonly human: HumanRecord;
    readonly isPlatformAdmin?: boolean | undefined;
  }): void {
    this.#principals.set(input.principal.principalId, input.principal);
    this.#humans.set(input.human.principalId, input.human);
    if (input.isPlatformAdmin) {
      this.#platformAdmins.add(input.principal.principalId);
    }
  }

  hasActivePlatformAdmin(): Promise<boolean> {
    for (const principalId of this.#platformAdmins) {
      const p = this.#principals.get(principalId);
      if (p !== undefined && p.kind === "human" && p.state === "active") {
        return Promise.resolve(true);
      }
    }
    return Promise.resolve(false);
  }

  getPrincipalAndHuman(principalId: PrincipalId): Promise<{
    readonly principal: PrincipalRecord;
    readonly human: HumanRecord | null;
  } | null> {
    const principal = this.#principals.get(principalId);
    if (principal === undefined) {
      return Promise.resolve(null);
    }
    return Promise.resolve({
      principal,
      human: this.#humans.get(principalId) ?? null
    });
  }

  findIntentById(id: EnrollmentIntentId): Promise<EnrollmentIntentRecord | null> {
    return Promise.resolve(this.#intents.get(id) ?? null);
  }

  countLiveIntentsForPreauth(
    preauthContextId: PreauthContextId,
    now: Temporal.Instant
  ): Promise<number> {
    let count = 0;
    for (const intent of this.#intents.values()) {
      if (
        intent.preauthContextId === preauthContextId &&
        isLiveEnrollmentState(intent.state) &&
        compareInstants(now, intent.expiresAt) < 0
      ) {
        count += 1;
      }
    }
    return Promise.resolve(count);
  }

  countLiveInstallationIntents(now: Temporal.Instant): Promise<number> {
    let count = 0;
    for (const intent of this.#intents.values()) {
      if (isLiveEnrollmentState(intent.state) && compareInstants(now, intent.expiresAt) < 0) {
        count += 1;
      }
    }
    return Promise.resolve(count);
  }

  async createIntent(input: CreateEnrollmentIntentRecordInput): Promise<EnrollmentIntentRecord> {
    if (this.#intents.has(input.id)) {
      throw new ConflictDomainError({
        code: "VERSION_CONFLICT",
        message: "Enrollment intent already exists"
      });
    }
    const perBrowserCount = await this.countLiveIntentsForPreauth(
      input.preauthContextId,
      input.createdAt
    );
    if (perBrowserCount >= input.maxLivePerBrowser) {
      throw new LimitExceededDomainError({
        code: "RATE_LIMITED",
        message: `Live enrollment intents per browser exceed limit ${input.maxLivePerBrowser}`
      });
    }
    const totalPending = await this.countLiveInstallationIntents(input.createdAt);
    if (totalPending >= input.maxLiveInstallation) {
      throw new LimitExceededDomainError({
        code: "CAPACITY_EXCEEDED",
        message: `Pending installation enrollment intents exceed limit ${input.maxLiveInstallation}`
      });
    }
    const record: EnrollmentIntentRecord = Object.freeze({
      id: input.id,
      controlEpoch: input.controlEpoch,
      purpose: input.purpose,
      targetPrincipalId: input.targetPrincipalId,
      tenantId: input.tenantId,
      projectId: input.projectId,
      browserProofDigest: new Uint8Array(input.browserProofDigest),
      preauthContextId: input.preauthContextId,
      comparisonSha256: new Uint8Array(input.comparisonSha256),
      referenceTag: input.referenceTag,
      state: "requested",
      approvedBy: null,
      operatorEventReference: null,
      createdAt: input.createdAt,
      expiresAt: input.expiresAt,
      version: 1n
    });
    this.#intents.set(record.id, record);
    return record;
  }

  approveIntent(input: ApproveEnrollmentIntentRecordInput): Promise<EnrollmentIntentRecord> {
    const current = this.#intents.get(input.intentId);
    if (current === undefined) {
      return Promise.reject(
        new NotFoundDomainError({ code: "NOT_FOUND", message: "Enrollment intent not found" })
      );
    }
    if (current.version !== input.expectedVersion) {
      return Promise.reject(
        new ConflictDomainError({
          code: "VERSION_CONFLICT",
          message: "Enrollment intent version conflict"
        })
      );
    }
    if (current.state !== "requested") {
      return Promise.reject(
        new ConflictDomainError({
          code: "STATE_TRANSITION_NOT_ALLOWED",
          message: `Cannot approve enrollment intent in state "${current.state}"`
        })
      );
    }

    if (input.provisionHuman !== undefined) {
      if (this.#principals.has(input.provisionHuman.principalId)) {
        return Promise.reject(
          new ConflictDomainError({
            code: "VERSION_CONFLICT",
            message: "Target principal already exists"
          })
        );
      }
      this.#principals.set(
        input.provisionHuman.principalId,
        Object.freeze({
          principalId: input.provisionHuman.principalId,
          kind: "human",
          state: "pending",
          authorityEpoch: 1n,
          version: 1n
        })
      );
      this.#humans.set(
        input.provisionHuman.principalId,
        Object.freeze({
          principalId: input.provisionHuman.principalId,
          displayName: input.provisionHuman.displayName,
          webauthnUserId: new Uint8Array(input.provisionHuman.webauthnUserId),
          version: 1n
        })
      );
    }

    const updated: EnrollmentIntentRecord = Object.freeze({
      ...current,
      targetPrincipalId: input.targetPrincipalId,
      tenantId: input.tenantId,
      projectId: input.projectId,
      state: "approved",
      approvedBy: input.approvedBy,
      operatorEventReference: input.operatorEventReference,
      version: current.version + 1n
    });
    this.#intents.set(updated.id, updated);
    return Promise.resolve(updated);
  }

  markEnrolling(intentId: EnrollmentIntentId, expectedVersion: bigint): Promise<EnrollmentIntentRecord> {
    const current = this.#intents.get(intentId);
    if (current === undefined) {
      return Promise.reject(
        new NotFoundDomainError({ code: "NOT_FOUND", message: "Enrollment intent not found" })
      );
    }
    if (current.version !== expectedVersion) {
      return Promise.reject(
        new ConflictDomainError({
          code: "VERSION_CONFLICT",
          message: "Enrollment intent version conflict"
        })
      );
    }
    if (current.state !== "approved" && current.state !== "enrolling") {
      return Promise.reject(
        new ConflictDomainError({
          code: "STATE_TRANSITION_NOT_ALLOWED",
          message: `Cannot begin passkey enrollment from state "${current.state}"`
        })
      );
    }
    const updated: EnrollmentIntentRecord = Object.freeze({
      ...current,
      state: "enrolling",
      version: current.version + 1n
    });
    this.#intents.set(updated.id, updated);
    return Promise.resolve(updated);
  }

  rejectOrRevokeIntent(
    intentId: EnrollmentIntentId,
    expectedVersion: bigint,
    toState: "rejected" | "revoked"
  ): Promise<EnrollmentIntentRecord> {
    const current = this.#intents.get(intentId);
    if (current === undefined) {
      return Promise.reject(
        new NotFoundDomainError({ code: "NOT_FOUND", message: "Enrollment intent not found" })
      );
    }
    if (current.version !== expectedVersion) {
      return Promise.reject(
        new ConflictDomainError({
          code: "VERSION_CONFLICT",
          message: "Enrollment intent version conflict"
        })
      );
    }
    if (!isLiveEnrollmentState(current.state)) {
      return Promise.reject(
        new ConflictDomainError({
          code: "STATE_TRANSITION_NOT_ALLOWED",
          message: `Cannot transition enrollment intent from terminal state "${current.state}"`
        })
      );
    }
    const updated: EnrollmentIntentRecord = Object.freeze({
      ...current,
      state: toState,
      version: current.version + 1n
    });
    this.#intents.set(updated.id, updated);
    return Promise.resolve(updated);
  }

  async completeEnrollmentAtomic(input: CompleteEnrollmentAtomicInput): Promise<{
    readonly intent: EnrollmentIntentRecord;
    readonly passkey: PasskeyRecord;
  }> {
    const current = this.#intents.get(input.intentId);
    if (current === undefined) {
      throw new NotFoundDomainError({ code: "NOT_FOUND", message: "Enrollment intent not found" });
    }
    if (current.version !== input.expectedIntentVersion) {
      throw new ConflictDomainError({
        code: "VERSION_CONFLICT",
        message: "Enrollment intent version conflict"
      });
    }
    if (current.state !== "approved" && current.state !== "enrolling") {
      throw new ConflictDomainError({
        code: "STATE_TRANSITION_NOT_ALLOWED",
        message: `Cannot complete enrollment intent in state "${current.state}"`
      });
    }
    if (compareInstants(input.now, current.expiresAt) >= 0) {
      throw new ExpiredDomainError({
        code: "EXPIRED",
        message: "Enrollment intent has expired"
      });
    }
    if (current.purpose === "first_platform_admin" && (await this.hasActivePlatformAdmin())) {
      throw new ConflictDomainError({
        code: "STATE_TRANSITION_NOT_ALLOWED",
        message: "Platform bootstrap already completed; active platform_admin exists"
      });
    }

    await this.#challenges.consumeChallenge({
      challengeId: input.challengeId,
      expectedVersion: input.expectedChallengeVersion,
      expectedControlEpoch: input.expectedControlEpoch,
      now: input.now
    });

    const passkey = await this.#passkeys.createPasskey({
      id: input.passkeyId,
      humanPrincipalId: input.principalId,
      credentialId: input.verifiedPasskey.credentialId,
      publicKey: input.verifiedPasskey.publicKey,
      webauthnUserId: input.webauthnUserId,
      signCount: input.verifiedPasskey.signCount,
      deviceType: input.verifiedPasskey.deviceType,
      backedUp: input.verifiedPasskey.backedUp,
      transports: input.verifiedPasskey.transports,
      state: input.passkeyState,
      enrolledAt: input.now
    });

    if (input.activateHumanPrincipal) {
      const principal = this.#principals.get(input.principalId);
      if (principal === undefined) {
        throw new NotFoundDomainError({ code: "NOT_FOUND", message: "Target human principal missing" });
      }
      this.#principals.set(
        principal.principalId,
        Object.freeze({
          ...principal,
          state: "active",
          version: principal.version + 1n
        })
      );
    }

    if (input.grantPlatformAdmin) {
      this.#platformAdmins.add(input.principalId);
    }

    const completed: EnrollmentIntentRecord = Object.freeze({
      ...current,
      state: "completed",
      version: current.version + 1n
    });
    this.#intents.set(completed.id, completed);

    return Object.freeze({ intent: completed, passkey });
  }
}

export function computeEnrollmentComparisonSha256(input: {
  readonly controlEpoch: ControlEpoch;
  readonly purpose: EnrollmentIntentKind;
  readonly preauthContextId: PreauthContextId;
  readonly browserProofDigest: Uint8Array;
  readonly targetPrincipalId: PrincipalId | null;
  readonly tenantId: TenantId | null;
  readonly projectId: ProjectId | null;
  readonly referenceTag: string;
}): Uint8Array {
  if (input.browserProofDigest.byteLength !== 32) {
    throw new ValidationDomainError({
      code: "INVALID_HASH",
      message: "Enrollment comparison requires 32-byte browserProofDigest"
    });
  }
  const preimage = encodeDomainLengthPrefixed(DIGEST_DOMAIN_ENROLLMENT_COMPARISON, [
    input.controlEpoch,
    input.purpose,
    input.preauthContextId,
    input.browserProofDigest,
    input.targetPrincipalId ?? "",
    input.tenantId ?? "",
    input.projectId ?? "",
    input.referenceTag
  ]);
  return new Uint8Array(crypto.createHash("sha256").update(preimage).digest());
}

export interface CreateEnrollmentIntentRequestInput {
  readonly policy: NormalizedAuthPolicyConfig | AuthConfig | AuthPolicyInput;
  readonly installation: InstallationAuthoritySnapshot;
  readonly cookieHeaders: string | readonly string[] | undefined;
  readonly body: unknown;
  readonly resolvedTarget?: {
    readonly targetPrincipalId?: PrincipalId | null | undefined;
    readonly tenantId?: TenantId | null | undefined;
    readonly projectId?: ProjectId | null | undefined;
  } | undefined;
  readonly preauthRepo: PreauthContextRepository;
  readonly enrollmentRepo: EnrollmentIntentRepository;
  readonly now: Temporal.Instant;
}

export interface CreatedEnrollmentIntentResult {
  readonly intent_id: EnrollmentIntentId;
  readonly purpose: EnrollmentIntentKind;
  readonly state: EnrollmentIntentState;
  readonly version: string;
  readonly expires_at: string;
  readonly comparison_sha256: Sha256Hex;
  readonly next_step: "await_protected_approval";
  readonly preauthSetCookieHeader?: OpaqueSecret<string> | undefined;
}

const CREATE_INTENT_ALLOWED_KEYS = new Set([
  "schema_version",
  "purpose",
  "invited_intent_reference",
  "target_recovery_reference"
]);

function parseCreateEnrollmentBody(raw: unknown): {
  readonly purpose: EnrollmentIntentKind;
  readonly referenceTag: string;
} {
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: "Enrollment intent request body must be a JSON object"
    });
  }
  const rec = raw as Record<string, unknown>;
  for (const key of Object.keys(rec)) {
    if (!CREATE_INTENT_ALLOWED_KEYS.has(key)) {
      throw new ValidationDomainError({
        code: "INVALID_VALUE",
        message: `Unexpected field "${key}" in enrollment intent request`,
        fieldErrors: [{ path: `body.${key}`, code: "INVALID_VALUE" }]
      });
    }
  }
  if (rec.schema_version !== 1) {
    throw new ValidationDomainError({
      code: "UNSUPPORTED_SCHEMA_VERSION",
      message: "Enrollment intent request requires schema_version 1",
      fieldErrors: [{ path: "body.schema_version", code: "UNSUPPORTED_SCHEMA_VERSION" }]
    });
  }
  if (!isEnrollmentIntentKind(rec.purpose)) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: "Invalid enrollment intent purpose",
      fieldErrors: [{ path: "body.purpose", code: "INVALID_VALUE" }]
    });
  }

  let referenceTag = "first_platform_admin";
  if (rec.purpose === "invited_human") {
    if (rec.invited_intent_reference === undefined || rec.target_recovery_reference !== undefined) {
      throw new ValidationDomainError({
        code: "INVALID_VALUE",
        message: "invited_human enrollment requires invited_intent_reference only",
        fieldErrors: [{ path: "body.invited_intent_reference", code: "INVALID_VALUE" }]
      });
    }
    referenceTag = parseBoundedString(rec.invited_intent_reference, {
      fieldPath: "body.invited_intent_reference",
      minUtf8Bytes: 1,
      maxUtf8Bytes: 256,
      rejectControlChars: true
    });
  } else if (rec.purpose === "restricted_factor_recovery") {
    if (rec.target_recovery_reference === undefined || rec.invited_intent_reference !== undefined) {
      throw new ValidationDomainError({
        code: "INVALID_VALUE",
        message: "restricted_factor_recovery requires target_recovery_reference only",
        fieldErrors: [{ path: "body.target_recovery_reference", code: "INVALID_VALUE" }]
      });
    }
    referenceTag = parseBoundedString(rec.target_recovery_reference, {
      fieldPath: "body.target_recovery_reference",
      minUtf8Bytes: 1,
      maxUtf8Bytes: 256,
      rejectControlChars: true
    });
  } else if (
    rec.invited_intent_reference !== undefined ||
    rec.target_recovery_reference !== undefined
  ) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: "first_platform_admin does not accept invitation or recovery reference overrides"
    });
  }

  return { purpose: rec.purpose, referenceTag };
}

export async function createEnrollmentIntent(
  input: CreateEnrollmentIntentRequestInput
): Promise<CreatedEnrollmentIntentResult> {
  const parsedBody = parseCreateEnrollmentBody(input.body);

  if (parsedBody.purpose === "restricted_factor_recovery") {
    assertInstallationAllowsRestrictedRecovery(input.installation, "restricted_factor_recovery");
  } else {
    assertInstallationAllowsOrdinaryAccess(input.installation, "enrollment_intent");
  }

  if (parsedBody.purpose === "first_platform_admin") {
    if (await input.enrollmentRepo.hasActivePlatformAdmin()) {
      throw new ConflictDomainError({
        code: "STATE_TRANSITION_NOT_ALLOWED",
        message: "Platform bootstrap is already completed"
      });
    }
  }

  const targetPrincipalId =
    input.resolvedTarget?.targetPrincipalId !== undefined &&
    input.resolvedTarget.targetPrincipalId !== null
      ? parsePrincipalId(input.resolvedTarget.targetPrincipalId, "target_principal_id")
      : null;
  const tenantId =
    input.resolvedTarget?.tenantId !== undefined && input.resolvedTarget.tenantId !== null
      ? parseTenantId(input.resolvedTarget.tenantId, "tenant_id")
      : null;
  const projectId =
    input.resolvedTarget?.projectId !== undefined && input.resolvedTarget.projectId !== null
      ? parseProjectId(input.resolvedTarget.projectId, "project_id")
      : null;
  if (projectId !== null && tenantId === null) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: "project_id requires non-null tenant_id"
    });
  }

  const preauth = await resolveOrCreatePreauthContext({
    policy: input.policy,
    cookieHeaders: input.cookieHeaders,
    preauthRepo: input.preauthRepo,
    now: input.now
  });

  const expiresAt = minInstant(
    addMilliseconds(input.now, ENROLLMENT_INTENT_TTL_MS, "enrollment_expires_at"),
    preauth.context.expiresAt
  );
  if (compareInstants(expiresAt, input.now) <= 0) {
    throw new ExpiredDomainError({
      code: "EXPIRED",
      message: "Preauthentication context has expired"
    });
  }

  const comparisonSha256 = computeEnrollmentComparisonSha256({
    controlEpoch: input.installation.controlEpoch,
    purpose: parsedBody.purpose,
    preauthContextId: preauth.context.id,
    browserProofDigest: preauth.proofDigest,
    targetPrincipalId,
    tenantId,
    projectId,
    referenceTag: parsedBody.referenceTag
  });

  const created = await input.enrollmentRepo.createIntent({
    id: parseEnrollmentIntentId(crypto.randomUUID(), "enrollment_intent_id"),
    controlEpoch: input.installation.controlEpoch,
    purpose: parsedBody.purpose,
    targetPrincipalId,
    tenantId,
    projectId,
    browserProofDigest: preauth.proofDigest,
    preauthContextId: preauth.context.id,
    comparisonSha256,
    referenceTag: parsedBody.referenceTag,
    createdAt: input.now,
    expiresAt,
    maxLivePerBrowser: MAX_LIVE_ENROLLMENT_INTENTS_PER_BROWSER,
    maxLiveInstallation: MAX_PENDING_INSTALLATION_ENROLLMENT_INTENTS
  });

  return Object.freeze({
    intent_id: created.id,
    purpose: created.purpose,
    state: created.state,
    version: created.version.toString(10),
    expires_at: formatUtcTimestamp(created.expiresAt),
    comparison_sha256: digestBytesToSha256Hex(created.comparisonSha256, "comparison_sha256"),
    next_step: "await_protected_approval",
    ...(preauth.setCookieHeader !== undefined
      ? { preauthSetCookieHeader: preauth.setCookieHeader }
      : {})
  });
}

export interface EnrollmentIntentStatusDto {
  readonly intent_id: EnrollmentIntentId;
  readonly purpose: EnrollmentIntentKind;
  readonly state: EnrollmentIntentState;
  readonly version: string;
  readonly expires_at: string;
  readonly comparison_sha256: Sha256Hex;
}

export async function getEnrollmentIntentStatus(input: {
  readonly policy: NormalizedAuthPolicyConfig | AuthConfig | AuthPolicyInput;
  readonly installation: InstallationAuthoritySnapshot;
  readonly intentId: EnrollmentIntentId | string;
  readonly cookieHeaders: string | readonly string[] | undefined;
  readonly preauthRepo: PreauthContextRepository;
  readonly enrollmentRepo: EnrollmentIntentRepository;
  readonly now: Temporal.Instant;
}): Promise<EnrollmentIntentStatusDto> {
  const intentId = parseEnrollmentIntentId(input.intentId, "intent_id");
  const preauth = await requireExistingPreauthContext({
    policy: input.policy,
    cookieHeaders: input.cookieHeaders,
    preauthRepo: input.preauthRepo,
    now: input.now
  });
  const intent = await input.enrollmentRepo.findIntentById(intentId);
  if (
    intent === null ||
    intent.preauthContextId !== preauth.context.id ||
    !constantTimeEqualBytes(intent.browserProofDigest, preauth.proofDigest)
  ) {
    throw new NotFoundDomainError({
      code: "NOT_FOUND",
      message: "Enrollment intent not found"
    });
  }
  const effectiveState: EnrollmentIntentState =
    isLiveEnrollmentState(intent.state) &&
    (compareInstants(input.now, intent.expiresAt) >= 0 ||
      intent.controlEpoch !== input.installation.controlEpoch)
      ? "expired"
      : intent.state;

  return Object.freeze({
    intent_id: intent.id,
    purpose: intent.purpose,
    state: effectiveState,
    version: intent.version.toString(10),
    expires_at: formatUtcTimestamp(intent.expiresAt),
    comparison_sha256: digestBytesToSha256Hex(intent.comparisonSha256, "comparison_sha256")
  });
}

export interface ApproveEnrollmentIntentInput {
  readonly installation: InstallationAuthoritySnapshot;
  readonly intentId: EnrollmentIntentId | string;
  readonly expectedVersion: bigint;
  readonly expectedComparisonSha256: Sha256Hex | string;
  readonly operatorEventReference?: string | undefined;
  readonly approvedByPrincipalId?: PrincipalId | string | undefined;
  readonly targetPrincipalId?: PrincipalId | string | undefined;
  readonly provisionDisplayName?: string | undefined;
  readonly tenantId?: TenantId | string | null | undefined;
  readonly projectId?: ProjectId | string | null | undefined;
  readonly enrollmentRepo: EnrollmentIntentRepository;
  readonly now: Temporal.Instant;
}

export async function approveEnrollmentIntent(
  input: ApproveEnrollmentIntentInput
): Promise<EnrollmentIntentRecord> {
  const intentId = parseEnrollmentIntentId(input.intentId, "intent_id");
  const expectedComparisonBytes = sha256HexToFixedBytes(
    input.expectedComparisonSha256,
    "expected_comparison_sha256"
  );

  const intent = await input.enrollmentRepo.findIntentById(intentId);
  if (intent === null) {
    throw new NotFoundDomainError({
      code: "NOT_FOUND",
      message: "Enrollment intent not found"
    });
  }

  if (intent.purpose === "restricted_factor_recovery") {
    assertInstallationAllowsRestrictedRecovery(input.installation, "restricted_factor_recovery");
  } else {
    assertInstallationAllowsOrdinaryAccess(input.installation, "enrollment_approval");
  }

  if (intent.controlEpoch !== input.installation.controlEpoch) {
    throw new ConflictDomainError({
      code: "STATE_TRANSITION_NOT_ALLOWED",
      message: "Enrollment intent belongs to a stale control epoch"
    });
  }
  if (compareInstants(input.now, intent.expiresAt) >= 0) {
    throw new ExpiredDomainError({
      code: "EXPIRED",
      message: "Enrollment intent has expired"
    });
  }
  if (intent.version !== input.expectedVersion) {
    throw new ConflictDomainError({
      code: "VERSION_CONFLICT",
      message: "Enrollment intent version mismatch"
    });
  }
  if (intent.state !== "requested") {
    throw new ConflictDomainError({
      code: "STATE_TRANSITION_NOT_ALLOWED",
      message: `Cannot approve enrollment intent in state "${intent.state}"`
    });
  }
  if (!constantTimeEqualBytes(expectedComparisonBytes, intent.comparisonSha256)) {
    throw new AuthorizationDomainError({
      code: "FORBIDDEN",
      message: "Enrollment intent comparison_sha256 verification failed"
    });
  }

  const operatorRef =
    input.operatorEventReference !== undefined
      ? parseBoundedString(input.operatorEventReference, {
          fieldPath: "operator_event_reference",
          minUtf8Bytes: 1,
          maxUtf8Bytes: 256,
          rejectControlChars: true
        })
      : null;

  const approvedBy =
    input.approvedByPrincipalId !== undefined
      ? parsePrincipalId(input.approvedByPrincipalId, "approved_by")
      : null;

  if (intent.purpose === "first_platform_admin") {
    if (operatorRef === null) {
      throw new AuthorizationDomainError({
        code: "FORBIDDEN",
        message: "first_platform_admin approval requires protected operator_event_reference"
      });
    }
    if (await input.enrollmentRepo.hasActivePlatformAdmin()) {
      throw new ConflictDomainError({
        code: "STATE_TRANSITION_NOT_ALLOWED",
        message: "Platform bootstrap already completed; active platform_admin exists"
      });
    }
  } else if (intent.purpose === "restricted_factor_recovery") {
    if (operatorRef === null) {
      throw new AuthorizationDomainError({
        code: "FORBIDDEN",
        message: "restricted_factor_recovery approval requires protected operator_event_reference"
      });
    }
  } else if (approvedBy === null && operatorRef === null) {
    throw new AuthorizationDomainError({
      code: "FORBIDDEN",
      message: "invited_human approval requires approved_by or operator_event_reference"
    });
  }

  const resolvedTargetId =
    intent.targetPrincipalId ??
    (input.targetPrincipalId !== undefined
      ? parsePrincipalId(input.targetPrincipalId, "target_principal_id")
      : intent.purpose === "restricted_factor_recovery"
        ? (() => {
            throw new ValidationDomainError({
              code: "INVALID_VALUE",
              message: "restricted_factor_recovery requires existing target_principal_id"
            });
          })()
        : parsePrincipalId(crypto.randomUUID(), "target_principal_id"));

  const existingTarget = await input.enrollmentRepo.getPrincipalAndHuman(resolvedTargetId);
  let provisionHuman: ApproveEnrollmentIntentRecordInput["provisionHuman"];

  if (intent.purpose === "restricted_factor_recovery") {
    if (existingTarget === null || existingTarget.human === null) {
      throw new NotFoundDomainError({
        code: "NOT_FOUND",
        message: "Target human principal for recovery not found"
      });
    }
    if (existingTarget.principal.kind !== "human" || existingTarget.principal.state === "retired") {
      throw new ConflictDomainError({
        code: "STATE_TRANSITION_NOT_ALLOWED",
        message: "Target principal is not eligible for factor recovery"
      });
    }
  } else if (existingTarget === null) {
    const displayName = normalizeWebAuthnHumanLabel(
      input.provisionDisplayName ??
        (intent.purpose === "first_platform_admin" ? "Platform Administrator" : intent.referenceTag),
      "provision_display_name"
    );
    provisionHuman = {
      principalId: resolvedTargetId,
      displayName,
      webauthnUserId: generateOpaqueWebAuthnUserId(),
      now: input.now
    };
  } else if (existingTarget.principal.kind !== "human" || existingTarget.human === null) {
    throw new ConflictDomainError({
      code: "STATE_TRANSITION_NOT_ALLOWED",
      message: "Target principal must be a human principal"
    });
  }

  const resolvedTenantId =
    intent.tenantId ??
    (input.tenantId !== undefined && input.tenantId !== null
      ? parseTenantId(input.tenantId, "tenant_id")
      : null);
  const resolvedProjectId =
    intent.projectId ??
    (input.projectId !== undefined && input.projectId !== null
      ? parseProjectId(input.projectId, "project_id")
      : null);
  if (resolvedProjectId !== null && resolvedTenantId === null) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: "project_id requires non-null tenant_id"
    });
  }

  return input.enrollmentRepo.approveIntent({
    intentId: intent.id,
    expectedVersion: intent.version,
    targetPrincipalId: resolvedTargetId,
    tenantId: resolvedTenantId,
    projectId: resolvedProjectId,
    approvedBy,
    operatorEventReference: operatorRef,
    ...(provisionHuman !== undefined ? { provisionHuman } : {})
  });
}

export interface BeginEnrollmentPasskeyOptionsInput {
  readonly policy: NormalizedAuthPolicyConfig | AuthConfig | AuthPolicyInput;
  readonly installation: InstallationAuthoritySnapshot;
  readonly intentId: EnrollmentIntentId | string;
  readonly expectedIntentVersion: bigint;
  readonly authenticatorLabel: string;
  readonly userAccountLabel?: string | undefined;
  readonly cookieHeaders: string | readonly string[] | undefined;
  readonly preauthRepo: PreauthContextRepository;
  readonly enrollmentRepo: EnrollmentIntentRepository;
  readonly challengeRepo: AuthChallengeRepository;
  readonly passkeyRepo: PasskeyRepository;
  readonly now: Temporal.Instant;
  readonly timeoutMs?: number | undefined;
  readonly supportedAlgorithmIDs?: readonly number[] | undefined;
}

export interface EnrollmentPasskeyOptionsResult {
  readonly auth_challenge_id: AuthChallengeRecord["id"];
  readonly intent_version: string;
  readonly authenticator_label: string;
  readonly public_key: PublicKeyCredentialCreationOptionsJSON;
}

async function requireMatchingBrowserIntent(input: {
  readonly policy: NormalizedAuthPolicyConfig | AuthConfig | AuthPolicyInput;
  readonly installation: InstallationAuthoritySnapshot;
  readonly intentId: EnrollmentIntentId;
  readonly cookieHeaders: string | readonly string[] | undefined;
  readonly preauthRepo: PreauthContextRepository;
  readonly enrollmentRepo: EnrollmentIntentRepository;
  readonly now: Temporal.Instant;
}): Promise<{
  readonly intent: EnrollmentIntentRecord;
  readonly preauthContext: PreauthContextRecord;
  readonly proofDigest: Uint8Array;
}> {
  const preauth = await requireExistingPreauthContext({
    policy: input.policy,
    cookieHeaders: input.cookieHeaders,
    preauthRepo: input.preauthRepo,
    now: input.now
  });
  const intent = await input.enrollmentRepo.findIntentById(input.intentId);
  if (
    intent === null ||
    intent.preauthContextId !== preauth.context.id ||
    !constantTimeEqualBytes(intent.browserProofDigest, preauth.proofDigest)
  ) {
    throw new NotFoundDomainError({
      code: "NOT_FOUND",
      message: "Enrollment intent not found"
    });
  }
  if (intent.purpose === "restricted_factor_recovery") {
    assertInstallationAllowsRestrictedRecovery(input.installation, "restricted_factor_recovery");
  } else {
    assertInstallationAllowsOrdinaryAccess(input.installation, "enrollment_ceremony");
  }
  if (intent.controlEpoch !== input.installation.controlEpoch) {
    throw new AuthenticationDomainError({
      code: "UNAUTHENTICATED",
      message: "Enrollment intent control epoch is stale"
    });
  }
  if (compareInstants(input.now, intent.expiresAt) >= 0) {
    throw new ExpiredDomainError({
      code: "EXPIRED",
      message: "Enrollment intent has expired"
    });
  }
  return { intent, preauthContext: preauth.context, proofDigest: preauth.proofDigest };
}

export async function beginEnrollmentPasskeyOptions(
  input: BeginEnrollmentPasskeyOptionsInput
): Promise<EnrollmentPasskeyOptionsResult> {
  const policy = normalizeAuthPolicyConfig(input.policy);
  const intentId = parseEnrollmentIntentId(input.intentId, "intent_id");
  const authenticatorLabel = parseSafeReasonCode(input.authenticatorLabel, "authenticator_label");

  const { intent, preauthContext } = await requireMatchingBrowserIntent({
    policy,
    installation: input.installation,
    intentId,
    cookieHeaders: input.cookieHeaders,
    preauthRepo: input.preauthRepo,
    enrollmentRepo: input.enrollmentRepo,
    now: input.now
  });

  if (intent.version !== input.expectedIntentVersion) {
    throw new ConflictDomainError({
      code: "VERSION_CONFLICT",
      message: "Enrollment intent version mismatch"
    });
  }
  if (intent.state !== "approved" && intent.state !== "enrolling") {
    throw new ConflictDomainError({
      code: "STATE_TRANSITION_NOT_ALLOWED",
      message: `Enrollment intent must be approved before passkey options (state="${intent.state}")`
    });
  }
  if (intent.targetPrincipalId === null) {
    throw new ConflictDomainError({
      code: "STATE_TRANSITION_NOT_ALLOWED",
      message: "Enrollment intent has no resolved target human principal"
    });
  }

  const target = await input.enrollmentRepo.getPrincipalAndHuman(intent.targetPrincipalId);
  if (target === null || target.human === null) {
    throw new NotFoundDomainError({
      code: "NOT_FOUND",
      message: "Target human principal not found"
    });
  }

  const updatedIntent =
    intent.state === "approved"
      ? await input.enrollmentRepo.markEnrolling(intent.id, intent.version)
      : intent;

  const challengePurpose =
    intent.purpose === "restricted_factor_recovery" ? "restricted_recovery" : "enroll_passkey";
  const challenge = await input.challengeRepo.createChallenge(
    createBrowserBoundChallengeInput({
      controlEpoch: input.installation.controlEpoch,
      humanPrincipalId: target.human.principalId,
      purpose: challengePurpose,
      preauthContext,
      extraCutoff: updatedIntent.expiresAt,
      now: input.now
    })
  );

  const existingPasskeys = await input.passkeyRepo.listPasskeysForHuman(target.human.principalId);
  const humanDisplayName = normalizeWebAuthnHumanLabel(target.human.displayName, "user.displayName");
  const humanUserName = normalizeWebAuthnHumanLabel(
    input.userAccountLabel ?? humanDisplayName,
    "user.name"
  );

  const publicKey = await createPasskeyRegistrationOptions({
    policy,
    challengeBytes: challenge.challengeBytes,
    webauthnUserId: target.human.webauthnUserId,
    userName: humanUserName,
    userDisplayName: humanDisplayName,
    excludeCredentials: existingPasskeys,
    timeoutMs: input.timeoutMs,
    supportedAlgorithmIDs: input.supportedAlgorithmIDs
  });

  return Object.freeze({
    auth_challenge_id: challenge.id,
    intent_version: updatedIntent.version.toString(10),
    authenticator_label: authenticatorLabel,
    public_key: publicKey
  });
}

export interface CompleteEnrollmentPasskeyInput {
  readonly policy: NormalizedAuthPolicyConfig | AuthConfig | AuthPolicyInput;
  readonly installation: InstallationAuthoritySnapshot;
  readonly intentId: EnrollmentIntentId | string;
  readonly authChallengeId: AuthChallengeRecord["id"] | string;
  readonly response: unknown;
  readonly cookieHeaders: string | readonly string[] | undefined;
  readonly preauthRepo: PreauthContextRepository;
  readonly enrollmentRepo: EnrollmentIntentRepository;
  readonly challengeRepo: AuthChallengeRepository;
  readonly now: Temporal.Instant;
  readonly supportedAlgorithmIDs?: readonly number[] | undefined;
}

export interface CompletedEnrollmentResult {
  readonly completed: true;
  readonly intent_id: EnrollmentIntentId;
  readonly purpose: EnrollmentIntentKind;
  readonly principal_id: PrincipalId;
  readonly passkey_id: PasskeyRecord["id"];
  readonly passkey_state: PasskeyState;
  readonly next_action: "sign_in" | "restricted_recovery_review";
}

export async function completeEnrollmentPasskey(
  input: CompleteEnrollmentPasskeyInput
): Promise<CompletedEnrollmentResult> {
  const policy = normalizeAuthPolicyConfig(input.policy);
  const intentId = parseEnrollmentIntentId(input.intentId, "intent_id");
  const challengeId = parseCanonicalUuid(input.authChallengeId, "auth_challenge_id") as AuthChallengeRecord["id"];

  const { intent, preauthContext, proofDigest } = await requireMatchingBrowserIntent({
    policy,
    installation: input.installation,
    intentId,
    cookieHeaders: input.cookieHeaders,
    preauthRepo: input.preauthRepo,
    enrollmentRepo: input.enrollmentRepo,
    now: input.now
  });

  if (intent.state !== "approved" && intent.state !== "enrolling") {
    throw new ConflictDomainError({
      code: "STATE_TRANSITION_NOT_ALLOWED",
      message: `Enrollment intent cannot complete from state "${intent.state}"`
    });
  }
  if (intent.targetPrincipalId === null) {
    throw new ConflictDomainError({
      code: "STATE_TRANSITION_NOT_ALLOWED",
      message: "Enrollment intent missing target principal"
    });
  }

  const expectedChallengePurpose =
    intent.purpose === "restricted_factor_recovery" ? "restricted_recovery" : "enroll_passkey";
  const storedChallenge = await input.challengeRepo.findChallengeById(challengeId);
  const verifiedChallenge = assertChallengeReadyForVerification({
    challenge: storedChallenge,
    expectedPurpose: expectedChallengePurpose,
    expectedBrowserProofDigest: proofDigest,
    installation: input.installation,
    now: input.now,
    expectedPreauthContextId: preauthContext.id,
    expectedHumanPrincipalId: intent.targetPrincipalId
  });

  const target = await input.enrollmentRepo.getPrincipalAndHuman(intent.targetPrincipalId);
  if (target === null || target.human === null) {
    throw new NotFoundDomainError({
      code: "NOT_FOUND",
      message: "Target human principal not found"
    });
  }

  let verifiedPasskey: VerifiedPasskeyRegistration;
  try {
    verifiedPasskey = await verifyPasskeyRegistration({
      policy,
      response: input.response,
      expectedChallengeBytes: verifiedChallenge.challengeBytes,
      supportedAlgorithmIDs: input.supportedAlgorithmIDs
    });
  } catch (err) {
    await input.challengeRepo.recordChallengeFailure({
      challengeId: verifiedChallenge.id,
      expectedVersion: verifiedChallenge.version,
      now: input.now
    });
    if (err instanceof AuthenticationDomainError || err instanceof ValidationDomainError) {
      throw err;
    }
    throw new AuthenticationDomainError({
      code: "UNAUTHENTICATED",
      message: "Passkey enrollment verification failed"
    });
  }

  const passkeyState: PasskeyState =
    intent.purpose === "restricted_factor_recovery" ? "recovery_pending" : "active";
  const passkeyId = parseCanonicalUuid(crypto.randomUUID(), "passkey_id");

  const { passkey } = await input.enrollmentRepo.completeEnrollmentAtomic({
    intentId: intent.id,
    expectedIntentVersion: intent.version,
    challengeId: verifiedChallenge.id,
    expectedChallengeVersion: verifiedChallenge.version,
    expectedControlEpoch: input.installation.controlEpoch,
    principalId: target.human.principalId,
    passkeyId,
    verifiedPasskey,
    passkeyState,
    webauthnUserId: target.human.webauthnUserId,
    activateHumanPrincipal: intent.purpose !== "restricted_factor_recovery",
    grantPlatformAdmin: intent.purpose === "first_platform_admin",
    now: input.now
  });

  return Object.freeze({
    completed: true,
    intent_id: intent.id,
    purpose: intent.purpose,
    principal_id: target.human.principalId,
    passkey_id: passkey.id,
    passkey_state: passkey.state,
    next_action:
      intent.purpose === "restricted_factor_recovery" ? "restricted_recovery_review" : "sign_in"
  });
}
