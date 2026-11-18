import { type Temporal } from "@js-temporal/polyfill";
import { createEnumGuard } from "./enums.js";
import { LimitExceededDomainError, ValidationDomainError } from "./errors.js";
import { type RetentionHoldId } from "./ids.js";
import { assertTransition, type TransitionMatrix } from "./state-machine.js";
import { addMilliseconds, compareInstants } from "./time.js";

export const CONTENT_RETENTION_STATES = [
  "required",
  "release_eligible",
  "expired",
  "held"
] as const;
export type ContentRetentionState = (typeof CONTENT_RETENTION_STATES)[number];
export const isContentRetentionState = createEnumGuard(CONTENT_RETENTION_STATES);

export const RETENTION_HOLD_TARGET_KINDS = [
  "event",
  "delivery_family",
  "endpoint_version",
  "signing_metadata",
  "project"
] as const;
export type RetentionHoldTargetKind = (typeof RETENTION_HOLD_TARGET_KINDS)[number];
export const isRetentionHoldTargetKind = createEnumGuard(RETENTION_HOLD_TARGET_KINDS);

export const RETENTION_HOLD_STATES = ["active", "released", "expired"] as const;
export type RetentionHoldState = (typeof RETENTION_HOLD_STATES)[number];
export const isRetentionHoldState = createEnumGuard(RETENTION_HOLD_STATES);

export const RETENTION_ACTION_KINDS = [
  "expire_payload",
  "expire_wire",
  "retire_history",
  "retire_metadata"
] as const;
export type RetentionActionKind = (typeof RETENTION_ACTION_KINDS)[number];
export const isRetentionActionKind = createEnumGuard(RETENTION_ACTION_KINDS);

export const RETENTION_ACTION_STATES = [
  "ready",
  "claimed",
  "completed",
  "failed_retryable",
  "review_required"
] as const;
export type RetentionActionState = (typeof RETENTION_ACTION_STATES)[number];
export const isRetentionActionState = createEnumGuard(RETENTION_ACTION_STATES);

export const CONTENT_RETENTION_POST_TERMINAL_MS = 2_592_000_000n;
export const HISTORY_RETENTION_MIN_MS = 7_776_000_000n;
export const RETENTION_MAX_CLAIM_BATCH = 100 as const;

export const ALLOWED_CONTENT_RETENTION_TRANSITIONS: TransitionMatrix<ContentRetentionState> =
  Object.freeze({
    required: ["release_eligible", "held"],
    held: ["required", "release_eligible"],
    release_eligible: ["expired", "held"],
    expired: []
  });

export const ALLOWED_RETENTION_HOLD_TRANSITIONS: TransitionMatrix<RetentionHoldState> =
  Object.freeze({
    active: ["released", "expired"],
    released: [],
    expired: []
  });

export const ALLOWED_RETENTION_ACTION_TRANSITIONS: TransitionMatrix<RetentionActionState> =
  Object.freeze({
    ready: ["claimed"],
    claimed: ["completed", "failed_retryable", "review_required", "ready"],
    failed_retryable: ["ready", "claimed", "review_required"],
    review_required: ["ready", "completed"],
    completed: []
  });

export interface RetentionHoldSnapshot {
  readonly holdId: RetentionHoldId;
  readonly targetKind: RetentionHoldTargetKind;
  readonly state: RetentionHoldState;
  readonly expiresAt: Temporal.Instant | null;
}

export function isRetentionHoldActive(
  hold: RetentionHoldSnapshot,
  now: Temporal.Instant
): boolean {
  if (hold.state !== "active") {
    return false;
  }
  if (hold.expiresAt !== null && compareInstants(now, hold.expiresAt) >= 0) {
    return false;
  }
  return true;
}

export interface ContentExpirationEvaluationInput {
  readonly currentState: ContentRetentionState;
  readonly allObligationsTerminal: boolean;
  readonly allObligationsTerminalAt: Temporal.Instant | null;
  readonly hasLiveMandatoryDependencies: boolean;
  readonly holds: readonly RetentionHoldSnapshot[];
  readonly now: Temporal.Instant;
}

export interface ContentExpirationEvaluationResult {
  readonly eligible: boolean;
  readonly recommendedState: ContentRetentionState;
  readonly blockingReason:
    | null
    | "already_expired"
    | "active_hold"
    | "live_mandatory_dependency"
    | "obligations_not_terminal"
    | "retention_window_open";
}

export function evaluateContentExpirationEligibility(
  input: ContentExpirationEvaluationInput
): ContentExpirationEvaluationResult {
  if (input.currentState === "expired") {
    return Object.freeze({
      eligible: false,
      recommendedState: "expired",
      blockingReason: "already_expired"
    });
  }

  const hasActiveHold = input.holds.some((hold) => isRetentionHoldActive(hold, input.now));
  if (hasActiveHold) {
    return Object.freeze({
      eligible: false,
      recommendedState: "held",
      blockingReason: "active_hold"
    });
  }

  // Optional hold expiry never overrides mandatory dependencies or unfinished obligations.
  if (input.hasLiveMandatoryDependencies) {
    return Object.freeze({
      eligible: false,
      recommendedState: "required",
      blockingReason: "live_mandatory_dependency"
    });
  }

  if (!input.allObligationsTerminal || input.allObligationsTerminalAt === null) {
    return Object.freeze({
      eligible: false,
      recommendedState: "required",
      blockingReason: "obligations_not_terminal"
    });
  }

  const releaseAt = addMilliseconds(
    input.allObligationsTerminalAt,
    CONTENT_RETENTION_POST_TERMINAL_MS,
    "retention_release_at"
  );
  if (compareInstants(input.now, releaseAt) < 0) {
    return Object.freeze({
      eligible: false,
      recommendedState: "required",
      blockingReason: "retention_window_open"
    });
  }

  return Object.freeze({
    eligible: true,
    recommendedState: "release_eligible",
    blockingReason: null
  });
}

export function isHistoryRetirementEligible(
  terminalizedAt: Temporal.Instant,
  hasLiveMandatoryDependencies: boolean,
  holds: readonly RetentionHoldSnapshot[],
  now: Temporal.Instant
): boolean {
  if (hasLiveMandatoryDependencies) {
    return false;
  }
  if (holds.some((hold) => isRetentionHoldActive(hold, now))) {
    return false;
  }
  const retireAt = addMilliseconds(terminalizedAt, HISTORY_RETENTION_MIN_MS, "history_retire_at");
  return compareInstants(now, retireAt) >= 0;
}

export function assertRetentionClaimBatchSize(batchSize: number): number {
  if (!Number.isInteger(batchSize) || batchSize < 1) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: "Retention claim batch size must be a positive integer",
      fieldErrors: [{ path: "batch_size", code: "INVALID_VALUE" }]
    });
  }
  if (batchSize > RETENTION_MAX_CLAIM_BATCH) {
    throw new LimitExceededDomainError({
      code: "CAPACITY_EXCEEDED",
      message: `Retention claim batch size ${batchSize} exceeds max ${RETENTION_MAX_CLAIM_BATCH}`,
      fieldErrors: [{ path: "batch_size", code: "CAPACITY_EXCEEDED" }]
    });
  }
  return batchSize;
}

export function transitionContentRetentionState(
  from: ContentRetentionState,
  to: ContentRetentionState,
  resourceId: string
): ContentRetentionState {
  assertTransition(
    "content_retention",
    ALLOWED_CONTENT_RETENTION_TRANSITIONS,
    from,
    to,
    { kind: "content_retention", id: resourceId }
  );
  return to;
}
