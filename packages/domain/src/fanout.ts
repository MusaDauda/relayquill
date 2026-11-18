import { createEnumGuard } from "./enums.js";
import { ConflictDomainError, InvariantViolationError, ValidationDomainError } from "./errors.js";
import { type EventId, type ProjectId } from "./ids.js";
import { assertTransition, type TransitionMatrix } from "./state-machine.js";

export const BROKER_INBOX_STATES = [
  "received",
  "materializing",
  "completed",
  "blocked"
] as const;
export type BrokerInboxState = (typeof BROKER_INBOX_STATES)[number];
export const isBrokerInboxState = createEnumGuard(BROKER_INBOX_STATES);

export const EVENT_FANOUT_STATES = [
  "pending",
  "materializing",
  "completed",
  "blocked"
] as const;
export type EventFanoutState = (typeof EVENT_FANOUT_STATES)[number];
export const isEventFanoutState = createEnumGuard(EVENT_FANOUT_STATES);

export const FANOUT_OUTCOME_KINDS = [
  "matched",
  "filtered_out",
  "schema_not_selected",
  "explicitly_suppressed"
] as const;
export type FanoutOutcomeKind = (typeof FANOUT_OUTCOME_KINDS)[number];
export const isFanoutOutcomeKind = createEnumGuard(FANOUT_OUTCOME_KINDS);

export const FANOUT_RESERVATION_STATES = [
  "held",
  "partially_converted",
  "completed"
] as const;
export type FanoutReservationState = (typeof FANOUT_RESERVATION_STATES)[number];
export const isFanoutReservationState = createEnumGuard(FANOUT_RESERVATION_STATES);

export const FANOUT_PAGE_SIZE = 100 as const;
export const FANOUT_CLAIM_LEASE_MS = 30_000n;
export const MAX_ACTIVE_SUBSCRIPTIONS_PER_PROJECT = 1_000 as const;

export const FANOUT_CONSUMER_NAME = "RELAYQUILL_FANOUT_V1" as const;
export const FANOUT_ACK_WAIT_MS = 30_000n;
export const FANOUT_MAX_DELIVER = 10 as const;
export const FANOUT_MAX_ACK_PENDING = 128 as const;
export const FANOUT_PULL_MAX_BATCH = 32 as const;
export const FANOUT_PULL_MAX_BYTES = 262_144 as const;
export const FANOUT_OUT_OF_ORDER_NAK_MS = 2_000n;

export const ALLOWED_BROKER_INBOX_TRANSITIONS: TransitionMatrix<BrokerInboxState> = Object.freeze({
  received: ["materializing", "completed", "blocked"],
  materializing: ["completed", "blocked"],
  blocked: ["materializing", "completed"],
  completed: []
});

export const ALLOWED_EVENT_FANOUT_TRANSITIONS: TransitionMatrix<EventFanoutState> = Object.freeze({
  pending: ["materializing", "completed", "blocked"],
  materializing: ["materializing", "completed", "blocked"],
  blocked: ["materializing", "completed"],
  completed: []
});

export const ALLOWED_FANOUT_RESERVATION_TRANSITIONS: TransitionMatrix<FanoutReservationState> =
  Object.freeze({
    held: ["partially_converted", "completed"],
    partially_converted: ["partially_converted", "completed"],
    completed: []
  });

export function isTerminalBrokerInboxState(state: BrokerInboxState): boolean {
  return state === "completed";
}

export function isTerminalEventFanoutState(state: EventFanoutState): boolean {
  return state === "completed";
}

export function isContiguousFanoutSequence(
  eventProjectSequence: bigint,
  materializedThroughEventSequence: bigint
): boolean {
  if (eventProjectSequence < 1n || materializedThroughEventSequence < 0n) {
    return false;
  }
  return eventProjectSequence === materializedThroughEventSequence + 1n;
}

export function assertContiguousFanoutSequence(
  projectId: ProjectId,
  eventId: EventId,
  eventProjectSequence: bigint,
  materializedThroughEventSequence: bigint
): void {
  if (eventProjectSequence < 1n || materializedThroughEventSequence < 0n) {
    throw new ValidationDomainError({
      code: "INVALID_INT64",
      message: "Fanout sequence numbers must be valid non-negative/positive integers",
      resourceRef: { kind: "event", id: eventId }
    });
  }
  if (eventProjectSequence !== materializedThroughEventSequence + 1n) {
    throw new ConflictDomainError({
      code: "VERSION_CONFLICT",
      message: `Project ${projectId} watermark ${materializedThroughEventSequence.toString(10)} cannot materialize sequence ${eventProjectSequence.toString(10)}`,
      resourceRef: { kind: "event", id: eventId }
    });
  }
}

export interface FanoutReservationCounts {
  readonly reservedCandidateSlots: bigint;
  readonly unresolvedCandidateSlots: bigint;
  readonly convertedDeliverySlots: bigint;
  readonly releasedNonmatchSlots: bigint;
}

export function assertReservationConservation(
  counts: FanoutReservationCounts,
  resourceId?: string
): void {
  if (
    counts.reservedCandidateSlots < 0n ||
    counts.unresolvedCandidateSlots < 0n ||
    counts.convertedDeliverySlots < 0n ||
    counts.releasedNonmatchSlots < 0n
  ) {
    throw new ValidationDomainError({
      code: "INVALID_INT64",
      message: "Fanout reservation slot counts must be non-negative",
      ...(resourceId !== undefined
        ? { resourceRef: { kind: "event", id: resourceId } }
        : {})
    });
  }
  const sum =
    counts.unresolvedCandidateSlots +
    counts.convertedDeliverySlots +
    counts.releasedNonmatchSlots;
  if (counts.reservedCandidateSlots !== sum) {
    throw new InvariantViolationError({
      message: `Fanout reservation conservation violated: reserved=${counts.reservedCandidateSlots.toString(10)} vs sum=${sum.toString(10)}`,
      ...(resourceId !== undefined
        ? { resourceRef: { kind: "event", id: resourceId } }
        : {})
    });
  }
}

export interface EventFanoutSnapshot {
  readonly eventId: EventId;
  readonly projectId: ProjectId;
  readonly projectEventSequence: bigint;
  readonly state: EventFanoutState;
  readonly candidateCount: number;
  readonly examinedCount: number;
}

export function canCompleteEventFanout(
  fanout: EventFanoutSnapshot,
  reservation: FanoutReservationCounts
): boolean {
  if (fanout.examinedCount !== fanout.candidateCount) {
    return false;
  }
  if (reservation.unresolvedCandidateSlots !== 0n) {
    return false;
  }
  assertReservationConservation(reservation, fanout.eventId);
  return true;
}

export function transitionBrokerInboxState(
  currentState: BrokerInboxState,
  targetState: BrokerInboxState,
  inboxId: string
): BrokerInboxState {
  assertTransition("broker_inbox", ALLOWED_BROKER_INBOX_TRANSITIONS, currentState, targetState, {
    kind: "broker_inbox",
    id: inboxId
  });
  return targetState;
}

export function transitionEventFanoutState(
  fanout: EventFanoutSnapshot,
  targetState: EventFanoutState,
  context: {
    readonly materializedThroughEventSequence: bigint;
    readonly reservation?: FanoutReservationCounts | undefined;
  }
): EventFanoutSnapshot {
  assertTransition("event_fanout", ALLOWED_EVENT_FANOUT_TRANSITIONS, fanout.state, targetState, {
    kind: "event",
    id: fanout.eventId
  });

  if (targetState === "materializing" || targetState === "completed") {
    assertContiguousFanoutSequence(
      fanout.projectId,
      fanout.eventId,
      fanout.projectEventSequence,
      context.materializedThroughEventSequence
    );
  }

  if (targetState === "completed") {
    if (context.reservation === undefined) {
      throw new InvariantViolationError({
        message: "Completing event_fanout requires reservation conservation proof",
        resourceRef: { kind: "event", id: fanout.eventId }
      });
    }
    assertReservationConservation(context.reservation, fanout.eventId);
    if (
      fanout.examinedCount !== fanout.candidateCount ||
      context.reservation.unresolvedCandidateSlots !== 0n
    ) {
      throw new InvariantViolationError({
        message: "Cannot complete event_fanout with unexamined candidates or unresolved reservation slots",
        resourceRef: { kind: "event", id: fanout.eventId }
      });
    }
  }

  return Object.freeze({
    ...fanout,
    state: targetState
  });
}
