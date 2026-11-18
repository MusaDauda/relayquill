import { type Temporal } from "@js-temporal/polyfill";
import { type DeliveryState } from "./delivery.js";
import {
  createEnumGuard,
  type OrderDispositionDecision,
  type OrderingMode,
  type ReceiverAcceptanceKind
} from "./enums.js";
import {
  ConflictDomainError,
  ExpiredDomainError,
  InvariantViolationError,
  ValidationDomainError
} from "./errors.js";
import {
  computeUtf8ByteLength,
  hasLoneSurrogate,
  type OrderingCutoverPlanId,
  type OrderingDomainId,
  type OrderingKeyId,
  type ProjectId
} from "./ids.js";
import { assertTransition, type TransitionMatrix } from "./state-machine.js";
import { compareInstants } from "./time.js";

export const ORDERING_MEMBER_KINDS = ["original", "replay_append"] as const;
export type OrderingMemberKind = (typeof ORDERING_MEMBER_KINDS)[number];
export const isOrderingMemberKind = createEnumGuard(ORDERING_MEMBER_KINDS);

export const ORDERING_MEMBER_STATES = [
  "waiting",
  "eligible",
  "acknowledged",
  "reviewed_skip",
  "blocked"
] as const;
export type OrderingMemberState = (typeof ORDERING_MEMBER_STATES)[number];
export const isOrderingMemberState = createEnumGuard(ORDERING_MEMBER_STATES);

export const ORDERING_DOMAIN_STATES = ["prepared", "active", "draining", "retired"] as const;
export type OrderingDomainState = (typeof ORDERING_DOMAIN_STATES)[number];
export const isOrderingDomainState = createEnumGuard(ORDERING_DOMAIN_STATES);

export const ORDERING_CUTOVER_PLAN_STATES = [
  "proposed",
  "draining",
  "ready",
  "activated",
  "rejected",
  "expired",
  "revoked"
] as const;
export type OrderingCutoverPlanState = (typeof ORDERING_CUTOVER_PLAN_STATES)[number];
export const isOrderingCutoverPlanState = createEnumGuard(ORDERING_CUTOVER_PLAN_STATES);

export const RECEIVER_ORDER_HEAD_STATES = ["active", "held"] as const;
export type ReceiverOrderHeadState = (typeof RECEIVER_ORDER_HEAD_STATES)[number];
export const isReceiverOrderHeadState = createEnumGuard(RECEIVER_ORDER_HEAD_STATES);

export const ORDERING_KEY_MAX_UTF8_BYTES = 128 as const;
export const ORDER_SKIP_PROPOSAL_TTL_MS = 900_000n;

export const ALLOWED_ORDERING_DOMAIN_TRANSITIONS: TransitionMatrix<OrderingDomainState> =
  Object.freeze({
    prepared: ["active", "retired"],
    active: ["draining", "retired"],
    draining: ["retired"],
    retired: []
  });

export const ALLOWED_ORDERING_CUTOVER_TRANSITIONS: TransitionMatrix<OrderingCutoverPlanState> =
  Object.freeze({
    proposed: ["draining", "rejected", "expired", "revoked"],
    draining: ["ready", "expired", "revoked"],
    ready: ["activated", "expired", "revoked"],
    activated: [],
    rejected: [],
    expired: [],
    revoked: []
  });

export const ALLOWED_ORDERING_MEMBER_TRANSITIONS: TransitionMatrix<OrderingMemberState> =
  Object.freeze({
    waiting: ["eligible", "blocked"],
    eligible: ["acknowledged", "blocked", "reviewed_skip"],
    blocked: ["reviewed_skip"],
    acknowledged: [],
    reviewed_skip: []
  });

export function validateExtractedOrderingKey(key: unknown): string {
  if (typeof key !== "string" || key.length === 0 || hasLoneSurrogate(key)) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: "Strict ordering key must be a non-empty valid string",
      fieldErrors: [{ path: "ordering_key", code: "INVALID_VALUE" }]
    });
  }
  const bytes = computeUtf8ByteLength(key);
  if (bytes < 1 || bytes > ORDERING_KEY_MAX_UTF8_BYTES) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Strict ordering key exceeds ${ORDERING_KEY_MAX_UTF8_BYTES} UTF-8 bytes`,
      fieldErrors: [{ path: "ordering_key", code: "INVALID_VALUE" }]
    });
  }
  return key;
}

export function assertStrictOrderingConfiguration(
  mode: OrderingMode,
  orderingDomainId: OrderingDomainId | null,
  hasOrderingKeyPointer: boolean
): void {
  if (mode === "strict_per_key") {
    if (orderingDomainId === null) {
      throw new InvariantViolationError({
        message: "strict_per_key mode requires a non-null orderingDomainId"
      });
    }
    if (!hasOrderingKeyPointer) {
      throw new ValidationDomainError({
        code: "INVALID_VALUE",
        message: "strict_per_key mode requires an ordering key JSON Pointer",
        fieldErrors: [{ path: "ordering_key_pointer", code: "INVALID_VALUE" }]
      });
    }
  }
}

export function isOrderingHead(orderingSequence: bigint, nextEligibleSequence: bigint): boolean {
  return orderingSequence >= 1n && orderingSequence === nextEligibleSequence;
}

export function assertCanPrepareOrderedDelivery(input: {
  readonly orderingKeyId: OrderingKeyId;
  readonly orderingSequence: bigint;
  readonly nextEligibleSequence: bigint;
  readonly memberState: OrderingMemberState;
}): void {
  if (!isOrderingHead(input.orderingSequence, input.nextEligibleSequence)) {
    throw new ConflictDomainError({
      code: "STATE_TRANSITION_NOT_ALLOWED",
      message: `Ordering member seq=${input.orderingSequence.toString(10)} is behind head seq=${input.nextEligibleSequence.toString(10)}`,
      resourceRef: { kind: "ordering_key", id: input.orderingKeyId }
    });
  }
  if (input.memberState !== "eligible") {
    throw new ConflictDomainError({
      code: "STATE_TRANSITION_NOT_ALLOWED",
      message: `Ordering head member must be "eligible", got "${input.memberState}"`,
      resourceRef: { kind: "ordering_key", id: input.orderingKeyId }
    });
  }
}

export function assertCanSkipOrderingMember(input: {
  readonly orderingKeyId: OrderingKeyId;
  readonly orderingSequence: bigint;
  readonly nextEligibleSequence: bigint;
  readonly memberState: OrderingMemberState;
  readonly deliveryState: DeliveryState;
  readonly hasActiveSendStartedAttempt: boolean;
}): { readonly decision: OrderDispositionDecision; readonly nextEligibleSequence: bigint } {
  if (input.hasActiveSendStartedAttempt) {
    throw new ConflictDomainError({
      code: "STATE_TRANSITION_NOT_ALLOWED",
      message: "Cannot skip ordering member while a send_started attempt is active",
      resourceRef: { kind: "ordering_key", id: input.orderingKeyId }
    });
  }
  if (!isOrderingHead(input.orderingSequence, input.nextEligibleSequence)) {
    throw new ConflictDomainError({
      code: "STATE_TRANSITION_NOT_ALLOWED",
      message: "Only the active head ordering member can receive a skip disposition",
      resourceRef: { kind: "ordering_key", id: input.orderingKeyId }
    });
  }
  if (input.deliveryState === "acknowledged") {
    throw new ConflictDomainError({
      code: "ALREADY_COMPLETE",
      message: "Cannot skip an already acknowledged delivery",
      resourceRef: { kind: "ordering_key", id: input.orderingKeyId }
    });
  }
  assertTransition(
    "ordering_member",
    ALLOWED_ORDERING_MEMBER_TRANSITIONS,
    input.memberState,
    "reviewed_skip",
    { kind: "ordering_key", id: input.orderingKeyId }
  );
  return Object.freeze({
    decision: "reviewed_skip_without_processing_claim",
    nextEligibleSequence: input.nextEligibleSequence + 1n
  });
}

export interface OrderingCutoverPlanSnapshot {
  readonly planId: OrderingCutoverPlanId;
  readonly projectId: ProjectId;
  readonly state: OrderingCutoverPlanState;
  readonly sourceConsumerScope: string;
  readonly targetConsumerScope: string;
  readonly boundaryProjectSequence: bigint | null;
  readonly expiresAt: Temporal.Instant;
}

export function beginOrderingCutover(
  plan: OrderingCutoverPlanSnapshot,
  input: {
    readonly activeProjectCutoverPlanId: OrderingCutoverPlanId | null;
    readonly currentProjectSequence: bigint;
    readonly now: Temporal.Instant;
  }
): OrderingCutoverPlanSnapshot {
  if (compareInstants(input.now, plan.expiresAt) >= 0) {
    throw new ExpiredDomainError({
      code: "EXPIRED",
      message: "Ordering cutover plan has expired",
      resourceRef: { kind: "ordering_cutover_plan", id: plan.planId }
    });
  }
  if (plan.sourceConsumerScope !== plan.targetConsumerScope) {
    throw new InvariantViolationError({
      message: "Ordering cutover requires source_consumer_scope === target_consumer_scope",
      resourceRef: { kind: "ordering_cutover_plan", id: plan.planId }
    });
  }
  if (
    input.activeProjectCutoverPlanId !== null &&
    input.activeProjectCutoverPlanId !== plan.planId
  ) {
    throw new ConflictDomainError({
      code: "VERSION_CONFLICT",
      message: "Another ordering cutover plan is already active for this project",
      resourceRef: { kind: "ordering_cutover_plan", id: plan.planId }
    });
  }
  assertTransition(
    "ordering_cutover_plan",
    ALLOWED_ORDERING_CUTOVER_TRANSITIONS,
    plan.state,
    "draining",
    { kind: "ordering_cutover_plan", id: plan.planId }
  );
  return Object.freeze({
    ...plan,
    state: "draining",
    boundaryProjectSequence: input.currentProjectSequence
  });
}

export function markOrderingCutoverReady(
  plan: OrderingCutoverPlanSnapshot,
  input: {
    readonly materializedThroughEventSequence: bigint;
    readonly oldHeadsDrained: boolean;
    readonly now: Temporal.Instant;
  }
): OrderingCutoverPlanSnapshot {
  if (compareInstants(input.now, plan.expiresAt) >= 0) {
    throw new ExpiredDomainError({
      code: "EXPIRED",
      message: "Ordering cutover plan has expired",
      resourceRef: { kind: "ordering_cutover_plan", id: plan.planId }
    });
  }
  assertTransition(
    "ordering_cutover_plan",
    ALLOWED_ORDERING_CUTOVER_TRANSITIONS,
    plan.state,
    "ready",
    { kind: "ordering_cutover_plan", id: plan.planId }
  );
  if (plan.boundaryProjectSequence === null) {
    throw new InvariantViolationError({
      message: "Draining cutover plan is missing boundaryProjectSequence",
      resourceRef: { kind: "ordering_cutover_plan", id: plan.planId }
    });
  }
  if (input.materializedThroughEventSequence < plan.boundaryProjectSequence) {
    throw new ConflictDomainError({
      code: "STATE_TRANSITION_NOT_ALLOWED",
      message: "Project fanout watermark has not yet reached cutover boundary sequence",
      resourceRef: { kind: "ordering_cutover_plan", id: plan.planId }
    });
  }
  if (!input.oldHeadsDrained) {
    throw new ConflictDomainError({
      code: "STATE_TRANSITION_NOT_ALLOWED",
      message: "Old ordering heads/unknown attempts must drain before cutover readiness",
      resourceRef: { kind: "ordering_cutover_plan", id: plan.planId }
    });
  }
  return Object.freeze({
    ...plan,
    state: "ready"
  });
}

export function activateOrderingCutover(
  plan: OrderingCutoverPlanSnapshot,
  input: { readonly now: Temporal.Instant }
): OrderingCutoverPlanSnapshot {
  if (compareInstants(input.now, plan.expiresAt) >= 0) {
    throw new ExpiredDomainError({
      code: "EXPIRED",
      message: "Ordering cutover plan has expired",
      resourceRef: { kind: "ordering_cutover_plan", id: plan.planId }
    });
  }
  assertTransition(
    "ordering_cutover_plan",
    ALLOWED_ORDERING_CUTOVER_TRANSITIONS,
    plan.state,
    "activated",
    { kind: "ordering_cutover_plan", id: plan.planId }
  );
  return Object.freeze({
    ...plan,
    state: "activated"
  });
}

export function evaluateReceiverOrderAcceptance(input: {
  readonly headState: ReceiverOrderHeadState;
  readonly nextExpectedSequence: bigint;
  readonly incomingSequence: bigint;
  readonly alreadyCommittedAtSequence: boolean;
  readonly incomingMatchesCommittedAnchor: boolean;
}): {
  readonly acceptanceKind: ReceiverAcceptanceKind;
  readonly nextExpectedSequence: bigint;
  readonly mutatesBusinessCounter: boolean;
} {
  if (input.headState === "held") {
    throw new ConflictDomainError({
      code: "STATE_TRANSITION_NOT_ALLOWED",
      message: "Receiver order head is held"
    });
  }
  if (input.alreadyCommittedAtSequence) {
    if (!input.incomingMatchesCommittedAnchor) {
      throw new ConflictDomainError({
        code: "CONSUMER_ORDER_POSITION_CONFLICT",
        message: "Conflicting event at already-committed receiver ordering sequence"
      });
    }
    return Object.freeze({
      acceptanceKind: "duplicate_business_anchor",
      nextExpectedSequence: input.nextExpectedSequence,
      mutatesBusinessCounter: false
    });
  }
  if (input.incomingSequence > input.nextExpectedSequence) {
    throw new ConflictDomainError({
      code: "CONSUMER_ORDER_GAP",
      message: `Receiver order gap: expected ${input.nextExpectedSequence.toString(10)}, got ${input.incomingSequence.toString(10)}`
    });
  }
  if (input.incomingSequence < input.nextExpectedSequence) {
    throw new ConflictDomainError({
      code: "CONSUMER_ORDER_POSITION_CONFLICT",
      message: `Receiver order position ${input.incomingSequence.toString(10)} is below expected ${input.nextExpectedSequence.toString(10)}`
    });
  }
  return Object.freeze({
    acceptanceKind: "first_business_commit",
    nextExpectedSequence: input.nextExpectedSequence + 1n,
    mutatesBusinessCounter: true
  });
}
