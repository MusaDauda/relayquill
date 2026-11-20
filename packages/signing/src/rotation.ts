import { type Temporal } from "@js-temporal/polyfill";
import {
  SIGNING_OVERLAP_MAX_MS,
  SIGNING_VERIFY_BUFFER_MS,
  ValidationDomainError,
  assertSigningPolicyInvariants,
  assertTransition,
  compareInstants,
  createEnumGuard,
  type EndpointId,
  type KeyId,
  type ProjectId,
  type SignatureMode,
  type SigningKeyVersionId,
  type SigningKeyVersionState,
  type TransitionMatrix,
  type WebhookPurpose
} from "@relayquill/domain";

export const KEY_LIFECYCLE_STATES = [
  "pending",
  "active",
  "overlap",
  "retired",
  "revoked"
] as const;

export type KeyLifecycleState = (typeof KEY_LIFECYCLE_STATES)[number];
export const isKeyLifecycleState = createEnumGuard(KEY_LIFECYCLE_STATES);

export const ALLOWED_KEY_LIFECYCLE_TRANSITIONS: TransitionMatrix<KeyLifecycleState> = Object.freeze({
  pending: ["active", "revoked"],
  active: ["overlap", "retired", "revoked"],
  overlap: ["retired", "revoked"],
  retired: ["revoked"],
  revoked: []
});

export function toKeyLifecycleState(
  state: KeyLifecycleState | SigningKeyVersionState
): KeyLifecycleState {
  if (state === "prepared" || state === "receiver_verified" || state === "pending") {
    return "pending";
  }
  return state;
}

export function assertKeyLifecycleTransition(
  from: KeyLifecycleState,
  to: KeyLifecycleState,
  keyId?: string
): void {
  assertTransition(
    "signing_key",
    ALLOWED_KEY_LIFECYCLE_TRANSITIONS,
    from,
    to,
    keyId !== undefined ? { kind: "signing_key", id: keyId } : undefined
  );
}

export interface EndpointKeyMetadata {
  readonly keyId: KeyId;
  readonly keyVersionId?: SigningKeyVersionId | undefined;
  readonly endpointId?: EndpointId | undefined;
  readonly projectId?: ProjectId | undefined;
  readonly keyVersion?: bigint | undefined;
  readonly state: KeyLifecycleState | SigningKeyVersionState;
  readonly activateNotBefore?: Temporal.Instant | null | undefined;
  readonly signUntil?: Temporal.Instant | null | undefined;
  readonly verifyUntil?: Temporal.Instant | null | undefined;
  readonly revokedAt?: Temporal.Instant | null | undefined;
  readonly snapshotObservedAt?: Temporal.Instant | null | undefined;
  readonly snapshotExpiresAt?: Temporal.Instant | null | undefined;
}

export type KeyEligibilityRejectionReason =
  | "key_snapshot_expired"
  | "key_revoked"
  | "key_retired"
  | "pending_key_forbidden_for_delivery"
  | "key_not_yet_active"
  | "key_sign_cutoff_exceeded"
  | "key_verify_cutoff_exceeded"
  | "overlap_key_missing_cutoff"
  | "overlap_key_forbidden_for_verification_probe";

export type KeyEligibilityResult =
  | { readonly eligible: true; readonly lifecycleState: KeyLifecycleState }
  | {
      readonly eligible: false;
      readonly lifecycleState: KeyLifecycleState;
      readonly reason: KeyEligibilityRejectionReason;
    };

function isSnapshotExpired(metadata: EndpointKeyMetadata, now: Temporal.Instant): boolean {
  if (metadata.snapshotExpiresAt !== undefined && metadata.snapshotExpiresAt !== null) {
    if (compareInstants(now, metadata.snapshotExpiresAt) >= 0) {
      return true;
    }
  }
  return false;
}

function isKeyRevoked(
  metadata: EndpointKeyMetadata,
  lifecycleState: KeyLifecycleState,
  now: Temporal.Instant
): boolean {
  if (lifecycleState === "revoked") {
    return true;
  }
  if (metadata.revokedAt !== undefined && metadata.revokedAt !== null) {
    return compareInstants(now, metadata.revokedAt) >= 0;
  }
  return false;
}

export function checkKeySigningEligibility(
  metadata: EndpointKeyMetadata,
  purpose: WebhookPurpose,
  now: Temporal.Instant
): KeyEligibilityResult {
  const lifecycleState = toKeyLifecycleState(metadata.state);

  if (isSnapshotExpired(metadata, now)) {
    return Object.freeze({ eligible: false, lifecycleState, reason: "key_snapshot_expired" });
  }
  if (isKeyRevoked(metadata, lifecycleState, now)) {
    return Object.freeze({ eligible: false, lifecycleState, reason: "key_revoked" });
  }
  if (lifecycleState === "retired") {
    return Object.freeze({ eligible: false, lifecycleState, reason: "key_retired" });
  }

  if (purpose === "endpoint_verification") {
    if (lifecycleState === "overlap") {
      return Object.freeze({
        eligible: false,
        lifecycleState,
        reason: "overlap_key_forbidden_for_verification_probe"
      });
    }
    if (
      metadata.signUntil !== undefined &&
      metadata.signUntil !== null &&
      compareInstants(now, metadata.signUntil) > 0
    ) {
      return Object.freeze({ eligible: false, lifecycleState, reason: "key_sign_cutoff_exceeded" });
    }
    return Object.freeze({ eligible: true, lifecycleState });
  }

  // Ordinary delivery signing strictly forbids pending keys.
  if (lifecycleState === "pending") {
    return Object.freeze({
      eligible: false,
      lifecycleState,
      reason: "pending_key_forbidden_for_delivery"
    });
  }

  if (
    metadata.activateNotBefore !== undefined &&
    metadata.activateNotBefore !== null &&
    compareInstants(now, metadata.activateNotBefore) < 0
  ) {
    return Object.freeze({ eligible: false, lifecycleState, reason: "key_not_yet_active" });
  }

  if (lifecycleState === "overlap") {
    if (metadata.signUntil === undefined || metadata.signUntil === null) {
      return Object.freeze({ eligible: false, lifecycleState, reason: "overlap_key_missing_cutoff" });
    }
    if (compareInstants(now, metadata.signUntil) > 0) {
      return Object.freeze({ eligible: false, lifecycleState, reason: "key_sign_cutoff_exceeded" });
    }
    if (
      metadata.verifyUntil !== undefined &&
      metadata.verifyUntil !== null &&
      compareInstants(now, metadata.verifyUntil) > 0
    ) {
      return Object.freeze({ eligible: false, lifecycleState, reason: "key_verify_cutoff_exceeded" });
    }
    return Object.freeze({ eligible: true, lifecycleState });
  }

  if (
    metadata.signUntil !== undefined &&
    metadata.signUntil !== null &&
    compareInstants(now, metadata.signUntil) > 0
  ) {
    return Object.freeze({ eligible: false, lifecycleState, reason: "key_sign_cutoff_exceeded" });
  }

  return Object.freeze({ eligible: true, lifecycleState });
}

export function checkKeyVerificationEligibility(
  metadata: EndpointKeyMetadata,
  purpose: WebhookPurpose,
  now: Temporal.Instant
): KeyEligibilityResult {
  const lifecycleState = toKeyLifecycleState(metadata.state);

  if (isSnapshotExpired(metadata, now)) {
    return Object.freeze({ eligible: false, lifecycleState, reason: "key_snapshot_expired" });
  }
  if (isKeyRevoked(metadata, lifecycleState, now)) {
    return Object.freeze({ eligible: false, lifecycleState, reason: "key_revoked" });
  }
  if (lifecycleState === "retired") {
    return Object.freeze({ eligible: false, lifecycleState, reason: "key_retired" });
  }

  if (purpose === "endpoint_verification") {
    if (lifecycleState === "overlap") {
      return Object.freeze({
        eligible: false,
        lifecycleState,
        reason: "overlap_key_forbidden_for_verification_probe"
      });
    }
    if (
      metadata.verifyUntil !== undefined &&
      metadata.verifyUntil !== null &&
      compareInstants(now, metadata.verifyUntil) > 0
    ) {
      return Object.freeze({ eligible: false, lifecycleState, reason: "key_verify_cutoff_exceeded" });
    }
    return Object.freeze({ eligible: true, lifecycleState });
  }

  // Pending keys can never authorize ordinary business delivery.
  if (lifecycleState === "pending") {
    return Object.freeze({
      eligible: false,
      lifecycleState,
      reason: "pending_key_forbidden_for_delivery"
    });
  }

  if (
    metadata.activateNotBefore !== undefined &&
    metadata.activateNotBefore !== null &&
    compareInstants(now, metadata.activateNotBefore) < 0
  ) {
    return Object.freeze({ eligible: false, lifecycleState, reason: "key_not_yet_active" });
  }

  if (lifecycleState === "overlap") {
    if (metadata.verifyUntil === undefined || metadata.verifyUntil === null) {
      return Object.freeze({ eligible: false, lifecycleState, reason: "overlap_key_missing_cutoff" });
    }
    if (compareInstants(now, metadata.verifyUntil) > 0) {
      return Object.freeze({ eligible: false, lifecycleState, reason: "key_verify_cutoff_exceeded" });
    }
    return Object.freeze({ eligible: true, lifecycleState });
  }

  if (
    metadata.verifyUntil !== undefined &&
    metadata.verifyUntil !== null &&
    compareInstants(now, metadata.verifyUntil) > 0
  ) {
    return Object.freeze({ eligible: false, lifecycleState, reason: "key_verify_cutoff_exceeded" });
  }

  return Object.freeze({ eligible: true, lifecycleState });
}

export interface EndpointSigningPolicyConfig {
  readonly signatureMode: SignatureMode;
  readonly primaryKey: EndpointKeyMetadata;
  readonly overlapKey?: EndpointKeyMetadata | null | undefined;
  readonly overlapStartedAt?: Temporal.Instant | null | undefined;
  readonly overlapEndsAt?: Temporal.Instant | null | undefined;
  readonly oldKeySignUntil?: Temporal.Instant | null | undefined;
  readonly oldKeyVerifyUntil?: Temporal.Instant | null | undefined;
}

export interface ResolvedSigningPlan {
  readonly signatureMode: SignatureMode;
  readonly signingKeys: readonly EndpointKeyMetadata[];
  readonly dualSigningActive: boolean;
}

export function resolveSigningPlan(
  policy: EndpointSigningPolicyConfig,
  now: Temporal.Instant
): ResolvedSigningPlan {
  const primaryVersionId =
    policy.primaryKey.keyVersionId ?? ("00000000-0000-4000-8000-000000000001" as SigningKeyVersionId);
  const overlapVersionId =
    policy.overlapKey !== undefined && policy.overlapKey !== null
      ? (policy.overlapKey.keyVersionId ??
          ("00000000-0000-4000-8000-000000000002" as SigningKeyVersionId))
      : null;

  assertSigningPolicyInvariants({
    signatureMode: policy.signatureMode,
    primaryKeyVersionId: primaryVersionId,
    overlapKeyVersionId: overlapVersionId,
    overlapStartedAt: policy.overlapStartedAt ?? null,
    overlapEndsAt: policy.overlapEndsAt ?? null,
    oldKeySignUntil: policy.oldKeySignUntil ?? null,
    oldKeyVerifyUntil: policy.oldKeyVerifyUntil ?? null
  });

  const primaryCheck = checkKeySigningEligibility(policy.primaryKey, "delivery", now);
  if (!primaryCheck.eligible) {
    throw new ValidationDomainError({
      code: "STATE_TRANSITION_NOT_ALLOWED",
      message: `Primary signing key "${policy.primaryKey.keyId}" is ineligible (${primaryCheck.reason})`
    });
  }

  if (policy.signatureMode === "primary_only") {
    return Object.freeze({
      signatureMode: "primary_only",
      signingKeys: Object.freeze([policy.primaryKey]),
      dualSigningActive: false
    });
  }

  const overlapKey = policy.overlapKey;
  const overlapStartedAt = policy.overlapStartedAt;
  const overlapEndsAt = policy.overlapEndsAt;
  const oldKeySignUntil = policy.oldKeySignUntil;
  const oldKeyVerifyUntil = policy.oldKeyVerifyUntil;

  if (
    overlapKey === undefined ||
    overlapKey === null ||
    overlapStartedAt === undefined ||
    overlapStartedAt === null ||
    overlapEndsAt === undefined ||
    overlapEndsAt === null ||
    oldKeySignUntil === undefined ||
    oldKeySignUntil === null ||
    oldKeyVerifyUntil === undefined ||
    oldKeyVerifyUntil === null
  ) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: "bounded_dual_signature requires overlap key and bounded cutoff timestamps"
    });
  }

  if (overlapKey.keyId === policy.primaryKey.keyId) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: "bounded_dual_signature primary and overlap key IDs must be distinct"
    });
  }

  if (compareInstants(now, overlapStartedAt) < 0 || compareInstants(now, overlapEndsAt) > 0) {
    throw new ValidationDomainError({
      code: "EXPIRED",
      message: "bounded_dual_signature overlap window is not active at current time"
    });
  }

  if (compareInstants(now, oldKeySignUntil) > 0) {
    // Past sign cutoff inside the verify tail window: emit primary signature only.
    return Object.freeze({
      signatureMode: "bounded_dual_signature",
      signingKeys: Object.freeze([policy.primaryKey]),
      dualSigningActive: false
    });
  }

  const effectiveOverlapMeta: EndpointKeyMetadata = {
    ...overlapKey,
    signUntil: overlapKey.signUntil ?? oldKeySignUntil,
    verifyUntil: overlapKey.verifyUntil ?? oldKeyVerifyUntil
  };
  const overlapCheck = checkKeySigningEligibility(effectiveOverlapMeta, "delivery", now);
  if (!overlapCheck.eligible) {
    throw new ValidationDomainError({
      code: "STATE_TRANSITION_NOT_ALLOWED",
      message: `Overlap signing key "${overlapKey.keyId}" is ineligible (${overlapCheck.reason})`
    });
  }

  return Object.freeze({
    signatureMode: "bounded_dual_signature",
    signingKeys: Object.freeze([policy.primaryKey, effectiveOverlapMeta]),
    dualSigningActive: true
  });
}

export { SIGNING_OVERLAP_MAX_MS, SIGNING_VERIFY_BUFFER_MS };
