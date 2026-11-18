import { type Temporal } from "@js-temporal/polyfill";
import {
  type ChannelKind,
  createEnumGuard,
  type PrincipalKind
} from "./enums.js";
import {
  ConflictDomainError,
  ExpiredDomainError,
  InvariantViolationError,
  LimitExceededDomainError,
  ValidationDomainError
} from "./errors.js";
import {
  isHumanWorkflowNamespace,
  type ProducerCredentialId,
  type ProducerNamespace
} from "./ids.js";
import { type TransitionMatrix } from "./state-machine.js";
import { compareInstants, diffMilliseconds } from "./time.js";

export const PRODUCER_STATES = ["pending", "active", "suspended", "retired"] as const;
export type ProducerState = (typeof PRODUCER_STATES)[number];
export const isProducerState = createEnumGuard(PRODUCER_STATES);

export const PRODUCER_SCOPE_VERSION_STATES = ["draft", "approved", "active", "retired"] as const;
export type ProducerScopeVersionState = (typeof PRODUCER_SCOPE_VERSION_STATES)[number];
export const isProducerScopeVersionState = createEnumGuard(PRODUCER_SCOPE_VERSION_STATES);

export const PRODUCER_CREDENTIAL_STATES = [
  "pending_activation",
  "active",
  "overlap",
  "revoked",
  "expired"
] as const;
export type ProducerCredentialState = (typeof PRODUCER_CREDENTIAL_STATES)[number];
export const isProducerCredentialState = createEnumGuard(PRODUCER_CREDENTIAL_STATES);

export const PRODUCER_CREDENTIAL_INTENT_STATES = [
  "requested",
  "approved",
  "delivering",
  "delivery_unknown",
  "delivered",
  "activated",
  "revoked",
  "expired",
  "failed_reissue_required"
] as const;
export type ProducerCredentialIntentState = (typeof PRODUCER_CREDENTIAL_INTENT_STATES)[number];
export const isProducerCredentialIntentState = createEnumGuard(PRODUCER_CREDENTIAL_INTENT_STATES);

export const PASSKEY_STATES = ["active", "revoked", "recovery_pending"] as const;
export type PasskeyState = (typeof PASSKEY_STATES)[number];
export const isPasskeyState = createEnumGuard(PASSKEY_STATES);

export const AUTH_CHALLENGE_KINDS = [
  "enroll_passkey",
  "sign_in",
  "step_up",
  "restricted_recovery"
] as const;
export type AuthChallengeKind = (typeof AUTH_CHALLENGE_KINDS)[number];
export const isAuthChallengeKind = createEnumGuard(AUTH_CHALLENGE_KINDS);

export const AUTH_CHALLENGE_STATES = [
  "pending",
  "consumed",
  "denied",
  "expired",
  "revoked"
] as const;
export type AuthChallengeState = (typeof AUTH_CHALLENGE_STATES)[number];
export const isAuthChallengeState = createEnumGuard(AUTH_CHALLENGE_STATES);

export const HUMAN_SESSION_KINDS = ["ordinary", "recovery_restricted"] as const;
export type HumanSessionKind = (typeof HUMAN_SESSION_KINDS)[number];
export const isHumanSessionKind = createEnumGuard(HUMAN_SESSION_KINDS);

export const HUMAN_SESSION_STATES = ["active", "revoked", "expired"] as const;
export type HumanSessionState = (typeof HUMAN_SESSION_STATES)[number];
export const isHumanSessionState = createEnumGuard(HUMAN_SESSION_STATES);

export const PREAUTH_CONTEXT_STATES = ["active", "revoked", "expired"] as const;
export type PreauthContextState = (typeof PREAUTH_CONTEXT_STATES)[number];
export const isPreauthContextState = createEnumGuard(PREAUTH_CONTEXT_STATES);

export const ENROLLMENT_INTENT_KINDS = [
  "first_platform_admin",
  "invited_human",
  "restricted_factor_recovery"
] as const;
export type EnrollmentIntentKind = (typeof ENROLLMENT_INTENT_KINDS)[number];
export const isEnrollmentIntentKind = createEnumGuard(ENROLLMENT_INTENT_KINDS);

export const ENROLLMENT_INTENT_STATES = [
  "requested",
  "approved",
  "enrolling",
  "completed",
  "rejected",
  "expired",
  "revoked"
] as const;
export type EnrollmentIntentState = (typeof ENROLLMENT_INTENT_STATES)[number];
export const isEnrollmentIntentState = createEnumGuard(ENROLLMENT_INTENT_STATES);

export const OPERATION_PROOF_STATES = ["active", "consumed", "revoked"] as const;
export type OperationProofState = (typeof OPERATION_PROOF_STATES)[number];
export const isOperationProofState = createEnumGuard(OPERATION_PROOF_STATES);

export const RUNTIME_INSTANCE_STATES = ["active", "draining", "quarantined", "ended"] as const;
export type RuntimeInstanceState = (typeof RUNTIME_INSTANCE_STATES)[number];
export const isRuntimeInstanceState = createEnumGuard(RUNTIME_INSTANCE_STATES);

export const PRODUCER_MAX_SCOPE_EVENT_TYPES = 64 as const;
export const PRODUCER_MAX_SCHEMA_VERSIONS_PER_EVENT_TYPE = 16 as const;
export const PRODUCER_CREDENTIAL_MAX_TTL_MS = 2_592_000_000n;
export const PRODUCER_CREDENTIAL_MAX_OVERLAP_MS = 900_000n;
export const PRODUCER_CREDENTIAL_INTENT_TTL_MS = 300_000n;

export const AUTH_CHALLENGE_TTL_MS = 180_000n;
export const AUTH_CHALLENGE_MAX_FAILURES = 5 as const;
export const HUMAN_SESSION_ABSOLUTE_TTL_MS = 28_800_000n;
export const HUMAN_SESSION_IDLE_TTL_MS = 1_800_000n;
export const PREAUTH_CONTEXT_TTL_MS = 300_000n;
export const ENROLLMENT_INTENT_TTL_MS = 300_000n;
export const OPERATION_PROOF_TTL_MS = 300_000n;
export const RUNTIME_INSTANCE_LEASE_MS = 60_000n;
export const RUNTIME_INSTANCE_HEARTBEAT_INTERVAL_MS = 20_000n;

export const ALLOWED_PRODUCER_CREDENTIAL_TRANSITIONS: TransitionMatrix<ProducerCredentialState> =
  Object.freeze({
    pending_activation: ["active", "revoked", "expired"],
    active: ["overlap", "revoked", "expired"],
    overlap: ["revoked", "expired"],
    revoked: [],
    expired: []
  });

export const ALLOWED_RUNTIME_INSTANCE_TRANSITIONS: TransitionMatrix<RuntimeInstanceState> =
  Object.freeze({
    active: ["draining", "quarantined", "ended"],
    draining: ["quarantined", "ended"],
    quarantined: ["ended"],
    ended: []
  });

export function assertProducerChannelBinding(
  channelKind: ChannelKind,
  principalKind: PrincipalKind,
  namespace: ProducerNamespace
): void {
  const isHumanNs = isHumanWorkflowNamespace(namespace);
  if (channelKind === "machine_producer") {
    if (principalKind !== "producer" || isHumanNs) {
      throw new InvariantViolationError({
        message: "machine_producer channel requires producer principal and non-human.* namespace"
      });
    }
    return;
  }
  if (principalKind !== "human" || !isHumanNs) {
    throw new InvariantViolationError({
      message: "human_workflow channel requires human principal and human.<uuid> namespace"
    });
  }
}

export function assertProducerScopeBounds(
  eventTypeCount: number,
  maxVersionsForAnyType: number
): void {
  if (!Number.isInteger(eventTypeCount) || eventTypeCount < 0) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: "Producer scope eventTypeCount must be a non-negative integer"
    });
  }
  if (eventTypeCount > PRODUCER_MAX_SCOPE_EVENT_TYPES) {
    throw new LimitExceededDomainError({
      code: "CAPACITY_EXCEEDED",
      message: `Producer scope event types ${eventTypeCount} exceeds max ${PRODUCER_MAX_SCOPE_EVENT_TYPES}`
    });
  }
  if (!Number.isInteger(maxVersionsForAnyType) || maxVersionsForAnyType < 0) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: "Producer scope schema versions count must be a non-negative integer"
    });
  }
  if (maxVersionsForAnyType > PRODUCER_MAX_SCHEMA_VERSIONS_PER_EVENT_TYPE) {
    throw new LimitExceededDomainError({
      code: "CAPACITY_EXCEEDED",
      message: `Producer scope schema versions ${maxVersionsForAnyType} exceeds max ${PRODUCER_MAX_SCHEMA_VERSIONS_PER_EVENT_TYPE}`
    });
  }
}

export function assertProducerCredentialTiming(input: {
  readonly credentialId: ProducerCredentialId;
  readonly issuedAt: Temporal.Instant;
  readonly expiresAt: Temporal.Instant;
  readonly overlapStartedAt?: Temporal.Instant | null | undefined;
  readonly overlapEndsAt?: Temporal.Instant | null | undefined;
}): void {
  const ttlMs = diffMilliseconds(input.expiresAt, input.issuedAt);
  if (ttlMs <= 0n || ttlMs > PRODUCER_CREDENTIAL_MAX_TTL_MS) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Producer credential TTL must be within (0, ${PRODUCER_CREDENTIAL_MAX_TTL_MS.toString(10)}ms]`,
      resourceRef: { kind: "producer_credential", id: input.credentialId }
    });
  }
  if ((input.overlapStartedAt == null) !== (input.overlapEndsAt == null)) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: "Producer credential overlap requires both overlapStartedAt and overlapEndsAt",
      resourceRef: { kind: "producer_credential", id: input.credentialId }
    });
  }
  if (input.overlapStartedAt != null && input.overlapEndsAt != null) {
    const overlapMs = diffMilliseconds(input.overlapEndsAt, input.overlapStartedAt);
    if (overlapMs <= 0n || overlapMs > PRODUCER_CREDENTIAL_MAX_OVERLAP_MS) {
      throw new ValidationDomainError({
        code: "INVALID_VALUE",
        message: `Producer credential overlap must be within (0, ${PRODUCER_CREDENTIAL_MAX_OVERLAP_MS.toString(10)}ms]`,
        resourceRef: { kind: "producer_credential", id: input.credentialId }
      });
    }
  }
}

export function assertCanConsumeAuthChallenge(input: {
  readonly state: AuthChallengeState;
  readonly failureCount: number;
  readonly expiresAt: Temporal.Instant;
  readonly now: Temporal.Instant;
}): void {
  if (compareInstants(input.now, input.expiresAt) >= 0) {
    throw new ExpiredDomainError({
      code: "EXPIRED",
      message: "Auth challenge (3m) has expired"
    });
  }
  if (input.state !== "pending") {
    throw new ConflictDomainError({
      code: "STATE_TRANSITION_NOT_ALLOWED",
      message: `Auth challenge is not pending (state="${input.state}")`
    });
  }
  if (input.failureCount >= AUTH_CHALLENGE_MAX_FAILURES) {
    throw new LimitExceededDomainError({
      code: "RATE_LIMITED",
      message: "Auth challenge exceeded maximum failed attempts"
    });
  }
}

export function isHumanSessionExpired(input: {
  readonly state: HumanSessionState;
  readonly absoluteExpiresAt: Temporal.Instant;
  readonly idleExpiresAt: Temporal.Instant;
  readonly now: Temporal.Instant;
}): boolean {
  if (input.state !== "active") {
    return true;
  }
  return (
    compareInstants(input.now, input.absoluteExpiresAt) >= 0 ||
    compareInstants(input.now, input.idleExpiresAt) >= 0
  );
}
