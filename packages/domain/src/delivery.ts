import { type Temporal } from "@js-temporal/polyfill";
import { type AttemptState } from "./attempt.js";
import { createEnumGuard, type ReceiptVerificationState } from "./enums.js";
import {
  ConflictDomainError,
  InvariantViolationError,
  ValidationDomainError
} from "./errors.js";
import {
  type AttemptId,
  type DeliveryFamilyId,
  type DeliveryId,
  type EndpointId,
  type EventId,
  type LateObservationId,
  type ReceiverReceiptObservationId,
  type Sha256Hex,
  type SubscriptionId
} from "./ids.js";
import { assertNever, assertTransition, type TransitionMatrix } from "./state-machine.js";
import { compareInstants } from "./time.js";

export const DELIVERY_STATES = [
  "pending",
  "ready",
  "sending",
  "retry_wait",
  "acknowledged",
  "dead_letter",
  "suppressed",
  "expired"
] as const;
export type DeliveryState = (typeof DELIVERY_STATES)[number];
export const isDeliveryState = createEnumGuard(DELIVERY_STATES);

export const TERMINAL_DELIVERY_STATES = [
  "acknowledged",
  "dead_letter",
  "suppressed",
  "expired"
] as const;
export type TerminalDeliveryState = (typeof TERMINAL_DELIVERY_STATES)[number];

export const DELIVERY_EXECUTION_BUCKETS = [
  "pending",
  "active",
  "acknowledged",
  "dead_letter",
  "suppressed",
  "expired"
] as const;
export type DeliveryExecutionBucket = (typeof DELIVERY_EXECUTION_BUCKETS)[number];
export const isDeliveryExecutionBucket = createEnumGuard(DELIVERY_EXECUTION_BUCKETS);

export const LATE_OBSERVATION_KINDS = [
  "late_http_response",
  "late_transport_report",
  "reviewed_receiver_receipt_reference"
] as const;
export type LateObservationKind = (typeof LATE_OBSERVATION_KINDS)[number];
export const isLateObservationKind = createEnumGuard(LATE_OBSERVATION_KINDS);

export const DEFAULT_MAX_SEND_STARTS = 12 as const;
export const DEFAULT_MAX_PREP_FAILURES = 24 as const;

export const ALLOWED_DELIVERY_TRANSITIONS: TransitionMatrix<DeliveryState> = Object.freeze({
  pending: ["ready", "suppressed", "expired", "dead_letter"],
  ready: ["sending", "pending", "suppressed", "expired"],
  sending: ["acknowledged", "retry_wait", "ready", "pending", "dead_letter", "expired"],
  retry_wait: ["ready", "sending", "pending", "suppressed", "expired"],
  acknowledged: [],
  dead_letter: [],
  suppressed: [],
  expired: []
});

export function isTerminalDeliveryState(state: DeliveryState): state is TerminalDeliveryState {
  return (
    state === "acknowledged" ||
    state === "dead_letter" ||
    state === "suppressed" ||
    state === "expired"
  );
}

export function toDeliveryExecutionBucket(state: DeliveryState): DeliveryExecutionBucket {
  switch (state) {
    case "pending":
    case "ready":
    case "retry_wait":
      return "pending";
    case "sending":
      return "active";
    case "acknowledged":
      return "acknowledged";
    case "dead_letter":
      return "dead_letter";
    case "suppressed":
      return "suppressed";
    case "expired":
      return "expired";
    default:
      return assertNever(state, "Unhandled DeliveryState");
  }
}

export function assertDeliveryTransition(
  from: DeliveryState,
  to: DeliveryState,
  deliveryId?: DeliveryId
): void {
  assertTransition(
    "delivery",
    ALLOWED_DELIVERY_TRANSITIONS,
    from,
    to,
    deliveryId !== undefined ? { kind: "delivery", id: deliveryId } : undefined
  );
}

export interface DeliverySnapshot {
  readonly deliveryId: DeliveryId;
  readonly familyId: DeliveryFamilyId;
  readonly eventId: EventId;
  readonly subscriptionId: SubscriptionId;
  readonly endpointId: EndpointId;
  readonly deliveryGeneration: bigint;
  readonly state: DeliveryState;
  readonly attemptCount: number;
  readonly maximumAttempts: number;
  readonly preparedAttemptCount: number;
  readonly preparationFailureCount: number;
  readonly nextAttemptNumber: number;
  readonly currentFence: bigint;
  readonly currentAttemptId: AttemptId | null;
  readonly nextEligibleAt: Temporal.Instant;
  readonly deadlineAt: Temporal.Instant;
  readonly acknowledgedAt: Temporal.Instant | null;
  readonly terminalAt: Temporal.Instant | null;
  readonly consumerEventKeySha256: Sha256Hex;
}

export interface DeliveryPreparationPrerequisites {
  readonly endpointActive: boolean;
  readonly hasValidDispatchGrant: boolean;
  readonly subscriptionActive: boolean;
  readonly subscriptionSendHold: boolean;
  readonly circuitAllowsAttempt: boolean;
  readonly orderingAllowsAttempt: boolean;
}

export function canPrepareDelivery(
  delivery: DeliverySnapshot,
  prereqs: DeliveryPreparationPrerequisites,
  now: Temporal.Instant
): boolean {
  if (delivery.state !== "ready" && delivery.state !== "retry_wait") {
    return false;
  }
  if (delivery.currentAttemptId !== null) {
    return false;
  }
  if (compareInstants(now, delivery.deadlineAt) >= 0) {
    return false;
  }
  if (compareInstants(now, delivery.nextEligibleAt) < 0) {
    return false;
  }
  return (
    prereqs.endpointActive &&
    prereqs.hasValidDispatchGrant &&
    prereqs.subscriptionActive &&
    !prereqs.subscriptionSendHold &&
    prereqs.circuitAllowsAttempt &&
    prereqs.orderingAllowsAttempt
  );
}

export function startDeliveryPreparation(
  delivery: DeliverySnapshot,
  prereqs: DeliveryPreparationPrerequisites,
  newAttemptId: AttemptId,
  now: Temporal.Instant
): DeliverySnapshot {
  if (!canPrepareDelivery(delivery, prereqs, now)) {
    throw new ConflictDomainError({
      code: "STATE_TRANSITION_NOT_ALLOWED",
      message: "Delivery prerequisites or timing window do not permit preparation",
      resourceRef: { kind: "delivery", id: delivery.deliveryId }
    });
  }
  assertDeliveryTransition(delivery.state, "sending", delivery.deliveryId);
  return Object.freeze({
    ...delivery,
    state: "sending",
    preparedAttemptCount: delivery.preparedAttemptCount + 1,
    nextAttemptNumber: delivery.nextAttemptNumber + 1,
    currentFence: delivery.currentFence + 1n,
    currentAttemptId: newAttemptId
  });
}

export interface DeliveryFinalizationContext {
  readonly attemptId: AttemptId;
  readonly expectedFence: bigint;
  readonly attemptState: AttemptState;
  readonly targetState: Exclude<DeliveryState, "sending">;
  readonly decidedAt: Temporal.Instant;
  readonly nextEligibleAt?: Temporal.Instant | undefined;
  readonly maxPrepFailures?: number | undefined;
}

export function finalizeDeliveryAttempt(
  delivery: DeliverySnapshot,
  ctx: DeliveryFinalizationContext
): DeliverySnapshot {
  assertDeliveryTransition(delivery.state, ctx.targetState, delivery.deliveryId);
  if (delivery.currentAttemptId !== ctx.attemptId || delivery.currentFence !== ctx.expectedFence) {
    throw new ConflictDomainError({
      code: "VERSION_CONFLICT",
      message: "Delivery attempt or fence does not match active sending owner",
      resourceRef: { kind: "delivery", id: delivery.deliveryId }
    });
  }

  const maxPrepFailures = ctx.maxPrepFailures ?? DEFAULT_MAX_PREP_FAILURES;
  const isUnstartedOutcome =
    ctx.attemptState === "deferred_before_send" || ctx.attemptState === "failed_before_send";
  const isStartedOutcome =
    ctx.attemptState === "response_observed" ||
    ctx.attemptState === "transport_unknown" ||
    ctx.attemptState === "abandoned";

  if (ctx.targetState === "acknowledged") {
    if (ctx.attemptState !== "response_observed") {
      throw new InvariantViolationError({
        message: "Delivery cannot become acknowledged without a response_observed attempt",
        resourceRef: { kind: "delivery", id: delivery.deliveryId }
      });
    }
    return Object.freeze({
      ...delivery,
      state: "acknowledged",
      attemptCount: delivery.attemptCount + 1,
      currentAttemptId: null,
      acknowledgedAt: ctx.decidedAt,
      terminalAt: ctx.decidedAt
    });
  }

  if (!isUnstartedOutcome && !isStartedOutcome) {
    throw new InvariantViolationError({
      message: `Attempt state "${ctx.attemptState}" cannot finalize a sending delivery`,
      resourceRef: { kind: "delivery", id: delivery.deliveryId }
    });
  }

  const nextAttemptCount = isStartedOutcome ? delivery.attemptCount + 1 : delivery.attemptCount;
  const nextPrepFailures =
    ctx.attemptState === "failed_before_send"
      ? delivery.preparationFailureCount + 1
      : delivery.preparationFailureCount;

  if (ctx.targetState === "ready" || ctx.targetState === "pending") {
    if (!isUnstartedOutcome) {
      throw new InvariantViolationError({
        message: "Started attempt cannot revert delivery to ready or pending",
        resourceRef: { kind: "delivery", id: delivery.deliveryId }
      });
    }
    if (nextPrepFailures >= maxPrepFailures) {
      throw new InvariantViolationError({
        message: "Exhausted preparation failure budget must transition to dead_letter",
        resourceRef: { kind: "delivery", id: delivery.deliveryId }
      });
    }
  }

  if (ctx.targetState === "retry_wait") {
    if (ctx.nextEligibleAt === undefined) {
      throw new ValidationDomainError({
        code: "INVALID_TIMESTAMP",
        message: "retry_wait transition requires nextEligibleAt",
        resourceRef: { kind: "delivery", id: delivery.deliveryId }
      });
    }
    if (compareInstants(ctx.decidedAt, delivery.deadlineAt) >= 0) {
      throw new InvariantViolationError({
        message: "Cannot enter retry_wait when decidedAt >= deadlineAt",
        resourceRef: { kind: "delivery", id: delivery.deliveryId }
      });
    }
    return Object.freeze({
      ...delivery,
      state: "retry_wait",
      attemptCount: nextAttemptCount,
      preparationFailureCount: nextPrepFailures,
      currentAttemptId: null,
      nextEligibleAt: ctx.nextEligibleAt
    });
  }

  const isTerminal = isTerminalDeliveryState(ctx.targetState);
  return Object.freeze({
    ...delivery,
    state: ctx.targetState,
    attemptCount: nextAttemptCount,
    preparationFailureCount: nextPrepFailures,
    currentAttemptId: null,
    terminalAt: isTerminal ? ctx.decidedAt : delivery.terminalAt
  });
}

export interface LateDeliveryObservationInput {
  readonly observationId: LateObservationId;
  readonly kind: LateObservationKind;
  readonly observedAt: Temporal.Instant;
  readonly receiptVerificationState?: ReceiptVerificationState | undefined;
  readonly receiptObservationId?: ReceiverReceiptObservationId | undefined;
}

export interface LateObservationAttachment {
  readonly deliveryId: DeliveryId;
  readonly preservedState: TerminalDeliveryState;
  readonly preservedAcknowledgedAt: Temporal.Instant | null;
  readonly preservedCurrentAttemptId: AttemptId | null;
  readonly observation: LateDeliveryObservationInput;
}

export function attachLateObservationToTerminalDelivery(
  delivery: DeliverySnapshot,
  observation: LateDeliveryObservationInput
): LateObservationAttachment {
  if (!isTerminalDeliveryState(delivery.state)) {
    throw new ConflictDomainError({
      code: "STATE_TRANSITION_NOT_ALLOWED",
      message: `Late observation requires terminal delivery, got "${delivery.state}"`,
      resourceRef: { kind: "delivery", id: delivery.deliveryId }
    });
  }
  return Object.freeze({
    deliveryId: delivery.deliveryId,
    preservedState: delivery.state,
    preservedAcknowledgedAt: delivery.acknowledgedAt,
    preservedCurrentAttemptId: delivery.currentAttemptId,
    observation: Object.freeze({ ...observation })
  });
}

export interface DeliveryFamilySnapshot {
  readonly familyId: DeliveryFamilyId;
  readonly eventId: EventId;
  readonly subscriptionId: SubscriptionId;
  readonly nextGeneration: bigint;
  readonly consumerEventKeySha256: Sha256Hex;
}

export function createReplayDeliverySeed(
  family: DeliveryFamilySnapshot,
  newDeliveryId: DeliveryId,
  endpointId: EndpointId,
  options: {
    readonly maximumAttempts?: number | undefined;
    readonly now: Temporal.Instant;
    readonly deadlineAt: Temporal.Instant;
  }
): { readonly nextFamily: DeliveryFamilySnapshot; readonly newDelivery: DeliverySnapshot } {
  if (family.nextGeneration < 1n) {
    throw new InvariantViolationError({
      message: "Replay delivery generation must be >= 1",
      resourceRef: { kind: "delivery_family", id: family.familyId }
    });
  }
  if (compareInstants(options.now, options.deadlineAt) >= 0) {
    throw new ValidationDomainError({
      code: "EXPIRED",
      message: "Replay delivery deadline must be in the future",
      resourceRef: { kind: "delivery_family", id: family.familyId }
    });
  }
  const maximumAttempts = options.maximumAttempts ?? DEFAULT_MAX_SEND_STARTS;
  const newDelivery: DeliverySnapshot = Object.freeze({
    deliveryId: newDeliveryId,
    familyId: family.familyId,
    eventId: family.eventId,
    subscriptionId: family.subscriptionId,
    endpointId,
    deliveryGeneration: family.nextGeneration,
    state: "pending",
    attemptCount: 0,
    maximumAttempts,
    preparedAttemptCount: 0,
    preparationFailureCount: 0,
    nextAttemptNumber: 1,
    currentFence: 0n,
    currentAttemptId: null,
    nextEligibleAt: options.now,
    deadlineAt: options.deadlineAt,
    acknowledgedAt: null,
    terminalAt: null,
    consumerEventKeySha256: family.consumerEventKeySha256
  });

  const nextFamily: DeliveryFamilySnapshot = Object.freeze({
    ...family,
    nextGeneration: family.nextGeneration + 1n
  });

  return Object.freeze({ nextFamily, newDelivery });
}
