import { type Temporal } from "@js-temporal/polyfill";
import { createEnumGuard } from "./enums.js";
import { ConflictDomainError, ValidationDomainError } from "./errors.js";
import { type AttemptId, type ControlEpoch, type DeliveryId, type RuntimeInstanceId } from "./ids.js";
import { assertTransition, type TransitionMatrix } from "./state-machine.js";
import { addMilliseconds, clampDeadline, minInstant } from "./time.js";

export const ATTEMPT_STATES = [
  "prepared",
  "send_started",
  "response_observed",
  "failed_before_send",
  "deferred_before_send",
  "transport_unknown",
  "abandoned"
] as const;
export type AttemptState = (typeof ATTEMPT_STATES)[number];
export const isAttemptState = createEnumGuard(ATTEMPT_STATES);

export const TERMINAL_ATTEMPT_STATES = [
  "response_observed",
  "failed_before_send",
  "deferred_before_send",
  "transport_unknown",
  "abandoned"
] as const;
export type TerminalAttemptState = (typeof TERMINAL_ATTEMPT_STATES)[number];

export const ATTEMPT_CLAIM_LEASE_MS = 30_000n;
export const ATTEMPT_PREFLIGHT_BUDGET_MS = 5_000n;
export const ATTEMPT_NETWORK_BUDGET_MS = 10_000n;
export const MIN_HTTP_STATUS = 100 as const;
export const MAX_HTTP_STATUS = 599 as const;

export const ALLOWED_ATTEMPT_TRANSITIONS: TransitionMatrix<AttemptState> = Object.freeze({
  prepared: ["send_started", "failed_before_send", "deferred_before_send", "abandoned"],
  send_started: ["response_observed", "transport_unknown", "abandoned"],
  response_observed: [],
  failed_before_send: [],
  deferred_before_send: [],
  transport_unknown: [],
  abandoned: []
});

export function isTerminalAttemptState(state: AttemptState): state is TerminalAttemptState {
  return (
    state === "response_observed" ||
    state === "failed_before_send" ||
    state === "deferred_before_send" ||
    state === "transport_unknown" ||
    state === "abandoned"
  );
}

export function isValidHttpStatus(status: unknown): status is number {
  return (
    typeof status === "number" &&
    Number.isInteger(status) &&
    status >= MIN_HTTP_STATUS &&
    status <= MAX_HTTP_STATUS
  );
}

export function computeAttemptClaimExpiry(
  now: Temporal.Instant,
  deliveryDeadline: Temporal.Instant
): Temporal.Instant {
  return clampDeadline(
    addMilliseconds(now, ATTEMPT_CLAIM_LEASE_MS, "claim_expires_at"),
    deliveryDeadline
  );
}

export function computeAttemptRequestDeadline(
  now: Temporal.Instant,
  claimExpiresAt: Temporal.Instant,
  deliveryDeadline: Temporal.Instant
): Temporal.Instant {
  const networkCap = addMilliseconds(now, ATTEMPT_NETWORK_BUDGET_MS, "request_deadline_at");
  return minInstant(networkCap, minInstant(claimExpiresAt, deliveryDeadline));
}

export interface AttemptSnapshot {
  readonly attemptId: AttemptId;
  readonly deliveryId: DeliveryId;
  readonly attemptNumber: number;
  readonly state: AttemptState;
  readonly fencingToken: bigint;
  readonly ownerInstanceId: RuntimeInstanceId;
  readonly controlEpoch: ControlEpoch;
  readonly claimExpiresAt: Temporal.Instant;
  readonly requestDeadlineAt: Temporal.Instant | null;
  readonly responseStatus: number | null;
}

export interface AttemptCounterDeltas {
  readonly attemptCountDelta: 0 | 1;
  readonly preparationFailureDelta: 0 | 1;
  readonly releasesReservation: boolean;
}

export interface AttemptTransitionResult {
  readonly attempt: AttemptSnapshot;
  readonly counterDeltas: AttemptCounterDeltas;
}

export function transitionAttemptState(
  snapshot: AttemptSnapshot,
  targetState: AttemptState,
  context: {
    readonly expectedFencingToken: bigint;
    readonly ownerInstanceId?: RuntimeInstanceId | undefined;
    readonly controlEpoch?: ControlEpoch | undefined;
    readonly requestDeadlineAt?: Temporal.Instant | undefined;
    readonly responseStatus?: number | undefined;
    readonly allowReaperBypass?: boolean | undefined;
  }
): AttemptTransitionResult {
  assertTransition("delivery_attempt", ALLOWED_ATTEMPT_TRANSITIONS, snapshot.state, targetState, {
    kind: "delivery_attempt",
    id: snapshot.attemptId
  });

  if (snapshot.fencingToken !== context.expectedFencingToken) {
    throw new ConflictDomainError({
      code: "VERSION_CONFLICT",
      message: "Attempt fencing token mismatch",
      resourceRef: { kind: "delivery_attempt", id: snapshot.attemptId }
    });
  }

  if (targetState !== "abandoned" || !context.allowReaperBypass) {
    if (
      context.ownerInstanceId !== undefined &&
      context.ownerInstanceId !== snapshot.ownerInstanceId
    ) {
      throw new ConflictDomainError({
        code: "VERSION_CONFLICT",
        message: "Attempt owner instance mismatch",
        resourceRef: { kind: "delivery_attempt", id: snapshot.attemptId }
      });
    }
    if (context.controlEpoch !== undefined && context.controlEpoch !== snapshot.controlEpoch) {
      throw new ConflictDomainError({
        code: "VERSION_CONFLICT",
        message: "Attempt control epoch mismatch",
        resourceRef: { kind: "delivery_attempt", id: snapshot.attemptId }
      });
    }
  }

  if (targetState === "send_started") {
    if (context.requestDeadlineAt === undefined) {
      throw new ValidationDomainError({
        code: "INVALID_TIMESTAMP",
        message: "send_started transition requires requestDeadlineAt",
        resourceRef: { kind: "delivery_attempt", id: snapshot.attemptId }
      });
    }
    return Object.freeze({
      attempt: Object.freeze({
        ...snapshot,
        state: "send_started",
        requestDeadlineAt: context.requestDeadlineAt
      }),
      counterDeltas: Object.freeze({
        attemptCountDelta: 1,
        preparationFailureDelta: 0,
        releasesReservation: false
      })
    });
  }

  if (targetState === "response_observed") {
    if (!isValidHttpStatus(context.responseStatus)) {
      throw new ValidationDomainError({
        code: "INVALID_VALUE",
        message: "response_observed requires integer HTTP status in 100..599",
        fieldErrors: [{ path: "response_status", code: "INVALID_VALUE" }],
        resourceRef: { kind: "delivery_attempt", id: snapshot.attemptId }
      });
    }
    return Object.freeze({
      attempt: Object.freeze({
        ...snapshot,
        state: "response_observed",
        responseStatus: context.responseStatus
      }),
      counterDeltas: Object.freeze({
        attemptCountDelta: 0,
        preparationFailureDelta: 0,
        releasesReservation: true
      })
    });
  }

  if (targetState === "failed_before_send") {
    return Object.freeze({
      attempt: Object.freeze({
        ...snapshot,
        state: "failed_before_send"
      }),
      counterDeltas: Object.freeze({
        attemptCountDelta: 0,
        preparationFailureDelta: 1,
        releasesReservation: true
      })
    });
  }

  return Object.freeze({
    attempt: Object.freeze({
      ...snapshot,
      state: targetState
    }),
    counterDeltas: Object.freeze({
      attemptCountDelta: 0,
      preparationFailureDelta: 0,
      releasesReservation: true
    })
  });
}
