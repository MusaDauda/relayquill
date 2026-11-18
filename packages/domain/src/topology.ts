import { type Temporal } from "@js-temporal/polyfill";
import { createEnumGuard, type SignatureMode } from "./enums.js";
import {
  ConflictDomainError,
  ExpiredDomainError,
  InvariantViolationError,
  LimitExceededDomainError,
  ValidationDomainError
} from "./errors.js";
import {
  type EndpointId,
  type EndpointVerificationIntentId,
  type SigningKeyVersionId,
  type SubscriptionId
} from "./ids.js";
import { assertTransition, type TransitionMatrix } from "./state-machine.js";
import { addMilliseconds, compareInstants, diffMilliseconds } from "./time.js";

export const ENDPOINT_STATES = [
  "draft",
  "verification_pending",
  "active",
  "paused",
  "quarantined",
  "retired"
] as const;
export type EndpointState = (typeof ENDPOINT_STATES)[number];
export const isEndpointState = createEnumGuard(ENDPOINT_STATES);

export const ENDPOINT_DISPATCH_GRANT_CLASSES = [
  "current_destination",
  "retained_destination_dispatch"
] as const;
export type EndpointDispatchGrantClass = (typeof ENDPOINT_DISPATCH_GRANT_CLASSES)[number];
export const isEndpointDispatchGrantClass = createEnumGuard(ENDPOINT_DISPATCH_GRANT_CLASSES);

export const ENDPOINT_DISPATCH_GRANT_STATES = ["active", "revoked", "expired"] as const;
export type EndpointDispatchGrantState = (typeof ENDPOINT_DISPATCH_GRANT_STATES)[number];
export const isEndpointDispatchGrantState = createEnumGuard(ENDPOINT_DISPATCH_GRANT_STATES);

export const ENDPOINT_VERIFICATION_INTENT_STATES = [
  "requested",
  "approved",
  "probing",
  "verified",
  "failed",
  "expired",
  "revoked"
] as const;
export type EndpointVerificationIntentState =
  (typeof ENDPOINT_VERIFICATION_INTENT_STATES)[number];
export const isEndpointVerificationIntentState = createEnumGuard(
  ENDPOINT_VERIFICATION_INTENT_STATES
);

export const ENDPOINT_VERIFICATION_ATTEMPT_STATES = [
  "prepared",
  "send_started",
  "verified",
  "failed",
  "expired",
  "abandoned"
] as const;
export type EndpointVerificationAttemptState =
  (typeof ENDPOINT_VERIFICATION_ATTEMPT_STATES)[number];
export const isEndpointVerificationAttemptState = createEnumGuard(
  ENDPOINT_VERIFICATION_ATTEMPT_STATES
);

export const ENDPOINT_VERIFICATION_EVENT_OUTCOMES = [
  "verified",
  "denied",
  "unavailable",
  "expired"
] as const;
export type EndpointVerificationEventOutcome =
  (typeof ENDPOINT_VERIFICATION_EVENT_OUTCOMES)[number];
export const isEndpointVerificationEventOutcome = createEnumGuard(
  ENDPOINT_VERIFICATION_EVENT_OUTCOMES
);

export const SUBSCRIPTION_STATES = [
  "draft",
  "active",
  "paused",
  "retired",
  "quarantined"
] as const;
export type SubscriptionState = (typeof SUBSCRIPTION_STATES)[number];
export const isSubscriptionState = createEnumGuard(SUBSCRIPTION_STATES);

export const SUBSCRIPTION_CONTROL_ACTIONS = [
  "activate",
  "pause_future",
  "hold_sends",
  "pause_all",
  "resume_future",
  "release_send_hold",
  "retire",
  "quarantine",
  "cutover_activate"
] as const;
export type SubscriptionControlAction = (typeof SUBSCRIPTION_CONTROL_ACTIONS)[number];
export const isSubscriptionControlAction = createEnumGuard(SUBSCRIPTION_CONTROL_ACTIONS);

export const SIGNING_KEY_VERSION_STATES = [
  "prepared",
  "receiver_verified",
  "active",
  "overlap",
  "retired",
  "revoked"
] as const;
export type SigningKeyVersionState = (typeof SIGNING_KEY_VERSION_STATES)[number];
export const isSigningKeyVersionState = createEnumGuard(SIGNING_KEY_VERSION_STATES);

export const SIGNING_DELIVERY_INTENT_STATES = [
  "requested",
  "approved",
  "delivering",
  "delivery_unknown",
  "delivered",
  "failed_reissue_required",
  "revoked",
  "expired"
] as const;
export type SigningDeliveryIntentState = (typeof SIGNING_DELIVERY_INTENT_STATES)[number];
export const isSigningDeliveryIntentState = createEnumGuard(SIGNING_DELIVERY_INTENT_STATES);

export const RECEIVER_CONTRACT_STATES = ["draft", "verified", "active", "retired"] as const;
export type ReceiverContractState = (typeof RECEIVER_CONTRACT_STATES)[number];
export const isReceiverContractState = createEnumGuard(RECEIVER_CONTRACT_STATES);

export const RATE_POLICY_CHANGE_STATES = [
  "proposed",
  "draining",
  "activated",
  "rejected",
  "expired",
  "revoked"
] as const;
export type RatePolicyChangeState = (typeof RATE_POLICY_CHANGE_STATES)[number];
export const isRatePolicyChangeState = createEnumGuard(RATE_POLICY_CHANGE_STATES);

export const ENDPOINT_VERIFICATION_TTL_MS = 120_000n;
export const ENDPOINT_VERIFICATION_MAX_ATTEMPTS = 3 as const;
export const ENDPOINT_VERIFICATION_NONCE_BYTES = 32 as const;
export const SUBSCRIPTION_MAX_SCHEMA_VERSIONS = 16 as const;
export const SIGNING_OVERLAP_MAX_MS = 900_000n;
export const SIGNING_VERIFY_BUFFER_MS = 300_000n;
export const SIGNING_DELIVERY_INTENT_TTL_MS = 300_000n;

export const ALLOWED_ENDPOINT_TRANSITIONS: TransitionMatrix<EndpointState> = Object.freeze({
  draft: ["verification_pending", "retired"],
  verification_pending: ["active", "paused", "quarantined", "retired"],
  active: ["paused", "quarantined", "retired"],
  paused: ["active", "verification_pending", "quarantined", "retired"],
  quarantined: ["verification_pending", "paused", "retired"],
  retired: []
});

export const ALLOWED_SUBSCRIPTION_TRANSITIONS: TransitionMatrix<SubscriptionState> = Object.freeze({
  draft: ["active", "retired"],
  active: ["paused", "quarantined", "retired"],
  paused: ["active", "quarantined", "retired"],
  quarantined: ["paused", "active", "retired"],
  retired: []
});

export const ALLOWED_SIGNING_KEY_VERSION_TRANSITIONS: TransitionMatrix<SigningKeyVersionState> =
  Object.freeze({
    prepared: ["receiver_verified", "revoked"],
    receiver_verified: ["active", "revoked"],
    active: ["overlap", "retired", "revoked"],
    overlap: ["retired", "revoked"],
    retired: ["revoked"],
    revoked: []
  });

export interface SubscriptionTopologyRange {
  readonly fromTopologyVersion: bigint;
  readonly untilTopologyVersion: bigint | null;
}

export function assertValidSubscriptionTopologyRange(range: SubscriptionTopologyRange): void {
  if (range.fromTopologyVersion <= 0n) {
    throw new ValidationDomainError({
      code: "INVALID_INT64",
      message: "fromTopologyVersion must be >= 1",
      fieldErrors: [{ path: "from_topology_version", code: "INVALID_INT64" }]
    });
  }
  if (
    range.untilTopologyVersion !== null &&
    range.untilTopologyVersion <= range.fromTopologyVersion
  ) {
    throw new ValidationDomainError({
      code: "INVALID_INT64",
      message: "untilTopologyVersion must be strictly greater than fromTopologyVersion",
      fieldErrors: [{ path: "until_topology_version", code: "INVALID_INT64" }]
    });
  }
}

export function isTopologyVersionInRange(
  range: SubscriptionTopologyRange,
  topologyVersion: bigint
): boolean {
  assertValidSubscriptionTopologyRange(range);
  if (topologyVersion < range.fromTopologyVersion) {
    return false;
  }
  if (range.untilTopologyVersion !== null && topologyVersion >= range.untilTopologyVersion) {
    return false;
  }
  return true;
}

export function assertSubscriptionSchemaVersions(versions: readonly number[]): readonly number[] {
  if (versions.length < 1) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: "Subscription must select at least 1 schema version",
      fieldErrors: [{ path: "schema_versions", code: "INVALID_VALUE" }]
    });
  }
  if (versions.length > SUBSCRIPTION_MAX_SCHEMA_VERSIONS) {
    throw new LimitExceededDomainError({
      code: "CAPACITY_EXCEEDED",
      message: `Subscription schema_versions count ${versions.length} exceeds max ${SUBSCRIPTION_MAX_SCHEMA_VERSIONS}`,
      fieldErrors: [{ path: "schema_versions", code: "CAPACITY_EXCEEDED" }]
    });
  }
  const seen = new Set<number>();
  for (const v of versions) {
    if (!Number.isInteger(v) || v < 1) {
      throw new ValidationDomainError({
        code: "INVALID_VALUE",
        message: "Subscription schema version must be a positive integer",
        fieldErrors: [{ path: "schema_versions", code: "INVALID_VALUE" }]
      });
    }
    if (seen.has(v)) {
      throw new ValidationDomainError({
        code: "INVALID_VALUE",
        message: `Duplicate subscription schema version ${v}`,
        fieldErrors: [{ path: "schema_versions", code: "INVALID_VALUE" }]
      });
    }
    seen.add(v);
  }
  return versions;
}

export interface SigningPolicySnapshot {
  readonly signatureMode: SignatureMode;
  readonly primaryKeyVersionId: SigningKeyVersionId;
  readonly overlapKeyVersionId: SigningKeyVersionId | null;
  readonly overlapStartedAt: Temporal.Instant | null;
  readonly overlapEndsAt: Temporal.Instant | null;
  readonly oldKeySignUntil: Temporal.Instant | null;
  readonly oldKeyVerifyUntil: Temporal.Instant | null;
}

export function assertSigningPolicyInvariants(policy: SigningPolicySnapshot): void {
  if (policy.signatureMode === "primary_only") {
    if (policy.overlapKeyVersionId !== null) {
      throw new InvariantViolationError({
        message: "primary_only signing policy must not set overlapKeyVersionId"
      });
    }
    return;
  }

  if (
    policy.overlapKeyVersionId === null ||
    policy.overlapStartedAt === null ||
    policy.overlapEndsAt === null ||
    policy.oldKeySignUntil === null ||
    policy.oldKeyVerifyUntil === null
  ) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: "bounded_dual_signature requires overlap key and sign/verify cutoffs"
    });
  }

  if (policy.primaryKeyVersionId === policy.overlapKeyVersionId) {
    throw new InvariantViolationError({
      message: "bounded_dual_signature primary and overlap key versions must be distinct"
    });
  }

  const overlapDurationMs = diffMilliseconds(policy.overlapEndsAt, policy.overlapStartedAt);
  if (overlapDurationMs <= 0n || overlapDurationMs > SIGNING_OVERLAP_MAX_MS) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Signing overlap window must be within (0, ${SIGNING_OVERLAP_MAX_MS.toString(10)}ms]`
    });
  }

  const maxAllowedSignUntil = addMilliseconds(
    policy.oldKeyVerifyUntil,
    -SIGNING_VERIFY_BUFFER_MS,
    "old_key_sign_until"
  );
  if (compareInstants(policy.oldKeySignUntil, maxAllowedSignUntil) > 0) {
    throw new InvariantViolationError({
      message: "bounded_dual_signature requires old.sign_until <= old.verify_until - 300s"
    });
  }
}

export interface EndpointVerificationIntentSnapshot {
  readonly intentId: EndpointVerificationIntentId;
  readonly endpointId: EndpointId;
  readonly state: EndpointVerificationIntentState;
  readonly attemptsUsed: number;
  readonly expiresAt: Temporal.Instant;
}

export function assertCanBeginVerificationAttempt(
  intent: EndpointVerificationIntentSnapshot,
  now: Temporal.Instant
): void {
  if (compareInstants(now, intent.expiresAt) >= 0) {
    throw new ExpiredDomainError({
      code: "EXPIRED",
      message: "Endpoint verification intent (2m) has expired",
      resourceRef: { kind: "endpoint_verification_intent", id: intent.intentId }
    });
  }
  if (intent.state !== "approved" && intent.state !== "probing") {
    throw new ConflictDomainError({
      code: "STATE_TRANSITION_NOT_ALLOWED",
      message: `Cannot begin verification attempt in intent state "${intent.state}"`,
      resourceRef: { kind: "endpoint_verification_intent", id: intent.intentId }
    });
  }
  if (intent.attemptsUsed >= ENDPOINT_VERIFICATION_MAX_ATTEMPTS) {
    throw new LimitExceededDomainError({
      code: "CAPACITY_EXCEEDED",
      message: `Endpoint verification intent reached max ${ENDPOINT_VERIFICATION_MAX_ATTEMPTS} attempts`,
      resourceRef: { kind: "endpoint_verification_intent", id: intent.intentId }
    });
  }
}

export interface SubscriptionControlSnapshot {
  readonly subscriptionId: SubscriptionId;
  readonly state: SubscriptionState;
  readonly sendHold: boolean;
  readonly controlSequence: bigint;
}

export function applySubscriptionControlAction(
  sub: SubscriptionControlSnapshot,
  action: SubscriptionControlAction
): SubscriptionControlSnapshot {
  let nextState: SubscriptionState = sub.state;
  let nextSendHold = sub.sendHold;

  switch (action) {
    case "activate":
    case "resume_future":
      assertTransition("subscription", ALLOWED_SUBSCRIPTION_TRANSITIONS, sub.state, "active", {
        kind: "subscription",
        id: sub.subscriptionId
      });
      nextState = "active";
      break;
    case "pause_future":
      assertTransition("subscription", ALLOWED_SUBSCRIPTION_TRANSITIONS, sub.state, "paused", {
        kind: "subscription",
        id: sub.subscriptionId
      });
      nextState = "paused";
      break;
    case "hold_sends":
      if (sub.state === "retired") {
        throw new ConflictDomainError({
          code: "STATE_TRANSITION_NOT_ALLOWED",
          message: "Cannot hold sends on a retired subscription",
          resourceRef: { kind: "subscription", id: sub.subscriptionId }
        });
      }
      nextSendHold = true;
      break;
    case "release_send_hold":
      if (sub.state === "retired") {
        throw new ConflictDomainError({
          code: "STATE_TRANSITION_NOT_ALLOWED",
          message: "Cannot release send hold on a retired subscription",
          resourceRef: { kind: "subscription", id: sub.subscriptionId }
        });
      }
      nextSendHold = false;
      break;
    case "pause_all":
      if (sub.state !== "paused") {
        assertTransition("subscription", ALLOWED_SUBSCRIPTION_TRANSITIONS, sub.state, "paused", {
          kind: "subscription",
          id: sub.subscriptionId
        });
      }
      nextState = "paused";
      nextSendHold = true;
      break;
    case "retire":
      assertTransition("subscription", ALLOWED_SUBSCRIPTION_TRANSITIONS, sub.state, "retired", {
        kind: "subscription",
        id: sub.subscriptionId
      });
      nextState = "retired";
      break;
    case "quarantine":
      assertTransition(
        "subscription",
        ALLOWED_SUBSCRIPTION_TRANSITIONS,
        sub.state,
        "quarantined",
        { kind: "subscription", id: sub.subscriptionId }
      );
      nextState = "quarantined";
      nextSendHold = true;
      break;
    case "cutover_activate":
      if (sub.state !== "draft" && sub.state !== "paused" && sub.state !== "active") {
        throw new ConflictDomainError({
          code: "STATE_TRANSITION_NOT_ALLOWED",
          message: `Cannot cutover-activate subscription in state "${sub.state}"`,
          resourceRef: { kind: "subscription", id: sub.subscriptionId }
        });
      }
      nextState = "active";
      break;
  }

  return Object.freeze({
    ...sub,
    state: nextState,
    sendHold: nextSendHold,
    controlSequence: sub.controlSequence + 1n
  });
}

export function quarantineEndpoint(
  currentState: EndpointState,
  securityEpoch: bigint,
  endpointId: EndpointId
): { readonly state: EndpointState; readonly securityEpoch: bigint } {
  assertTransition("endpoint", ALLOWED_ENDPOINT_TRANSITIONS, currentState, "quarantined", {
    kind: "endpoint",
    id: endpointId
  });
  return Object.freeze({
    state: "quarantined",
    securityEpoch: securityEpoch + 1n
  });
}
