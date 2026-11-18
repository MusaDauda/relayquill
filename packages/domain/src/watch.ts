import { type Temporal } from "@js-temporal/polyfill";
import { createEnumGuard } from "./enums.js";
import {
  ConflictDomainError,
  ExpiredDomainError,
  LimitExceededDomainError,
  RateLimitDomainError,
  ValidationDomainError
} from "./errors.js";
import { type WatchLeaseId } from "./ids.js";
import { addMilliseconds, compareInstants, minInstant } from "./time.js";

export const WATCH_RESOURCE_KINDS = ["event", "delivery"] as const;
export type WatchResourceKind = (typeof WATCH_RESOURCE_KINDS)[number];
export const isWatchResourceKind = createEnumGuard(WATCH_RESOURCE_KINDS);

export const WATCH_LEASE_STATES = ["open", "closed"] as const;
export type WatchLeaseState = (typeof WATCH_LEASE_STATES)[number];
export const isWatchLeaseState = createEnumGuard(WATCH_LEASE_STATES);

export const WATCH_SLOT_STATES = ["held", "released"] as const;
export type WatchSlotState = (typeof WATCH_SLOT_STATES)[number];
export const isWatchSlotState = createEnumGuard(WATCH_SLOT_STATES);

export const WATCH_MAX_STREAMS_PER_ACTOR = 2 as const;
export const WATCH_MAX_STREAMS_PER_PROJECT = 10 as const;
export const WATCH_MAX_STREAMS_PER_TENANT = 20 as const;
export const WATCH_MAX_STREAM_DURATION_MS = 60_000n;
export const WATCH_LEASE_TTL_MS = 5_000n;
export const WATCH_MIN_RENEW_INTERVAL_MS = 1_000n;

export interface WatchQuotaCounts {
  readonly actorActiveCount: number;
  readonly projectActiveCount: number;
  readonly tenantActiveCount: number;
}

export function assertWatchQuotaAvailable(counts: WatchQuotaCounts): void {
  if (
    !Number.isInteger(counts.actorActiveCount) ||
    !Number.isInteger(counts.projectActiveCount) ||
    !Number.isInteger(counts.tenantActiveCount) ||
    counts.actorActiveCount < 0 ||
    counts.projectActiveCount < 0 ||
    counts.tenantActiveCount < 0
  ) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: "Watch active stream counts must be non-negative integers"
    });
  }

  if (counts.actorActiveCount >= WATCH_MAX_STREAMS_PER_ACTOR) {
    throw new LimitExceededDomainError({
      code: "CAPACITY_EXCEEDED",
      message: `Actor watch stream quota (${WATCH_MAX_STREAMS_PER_ACTOR}) reached`
    });
  }
  if (counts.projectActiveCount >= WATCH_MAX_STREAMS_PER_PROJECT) {
    throw new LimitExceededDomainError({
      code: "CAPACITY_EXCEEDED",
      message: `Project watch stream quota (${WATCH_MAX_STREAMS_PER_PROJECT}) reached`
    });
  }
  if (counts.tenantActiveCount >= WATCH_MAX_STREAMS_PER_TENANT) {
    throw new LimitExceededDomainError({
      code: "CAPACITY_EXCEEDED",
      message: `Tenant watch stream quota (${WATCH_MAX_STREAMS_PER_TENANT}) reached`
    });
  }
}

export function computeWatchStreamCutoff(
  openedAt: Temporal.Instant,
  requestedCutoff?: Temporal.Instant
): Temporal.Instant {
  const maxCutoff = addMilliseconds(
    openedAt,
    WATCH_MAX_STREAM_DURATION_MS,
    "stream_cutoff_at"
  );
  if (requestedCutoff === undefined) {
    return maxCutoff;
  }
  if (compareInstants(requestedCutoff, openedAt) <= 0) {
    throw new ValidationDomainError({
      code: "INVALID_TIMESTAMP",
      message: "Requested watch stream cutoff must be after openedAt"
    });
  }
  return minInstant(requestedCutoff, maxCutoff);
}

export function computeWatchLeaseExpiry(
  now: Temporal.Instant,
  authCutoffAt: Temporal.Instant,
  streamCutoffAt: Temporal.Instant
): Temporal.Instant {
  const leaseHorizon = addMilliseconds(now, WATCH_LEASE_TTL_MS, "lease_expires_at");
  return minInstant(leaseHorizon, minInstant(authCutoffAt, streamCutoffAt));
}

export interface WatchLeaseSnapshot {
  readonly leaseId: WatchLeaseId;
  readonly state: WatchLeaseState;
  readonly slotState: WatchSlotState;
  readonly openedAt: Temporal.Instant;
  readonly lastRenewedAt: Temporal.Instant;
  readonly leaseExpiresAt: Temporal.Instant;
  readonly streamCutoffAt: Temporal.Instant;
}

export function renewWatchLease(
  lease: WatchLeaseSnapshot,
  now: Temporal.Instant,
  authCutoffAt: Temporal.Instant
): WatchLeaseSnapshot {
  if (lease.state !== "open" || lease.slotState !== "held") {
    throw new ConflictDomainError({
      code: "STATE_TRANSITION_NOT_ALLOWED",
      message: "Cannot renew a closed or released watch lease",
      resourceRef: { kind: "watch_lease", id: lease.leaseId }
    });
  }
  if (
    compareInstants(now, lease.streamCutoffAt) >= 0 ||
    compareInstants(now, authCutoffAt) >= 0
  ) {
    throw new ExpiredDomainError({
      code: "EXPIRED",
      message: "Watch stream or auth cutoff has expired",
      resourceRef: { kind: "watch_lease", id: lease.leaseId }
    });
  }
  const earliestRenew = addMilliseconds(
    lease.lastRenewedAt,
    WATCH_MIN_RENEW_INTERVAL_MS,
    "next_renew_at"
  );
  if (compareInstants(now, earliestRenew) < 0) {
    throw new RateLimitDomainError({
      code: "RATE_LIMITED",
      message: "Watch lease renewal cannot occur more than once per second",
      resourceRef: { kind: "watch_lease", id: lease.leaseId }
    });
  }

  return Object.freeze({
    ...lease,
    lastRenewedAt: now,
    leaseExpiresAt: computeWatchLeaseExpiry(now, authCutoffAt, lease.streamCutoffAt)
  });
}

export function closeWatchLease(lease: WatchLeaseSnapshot): WatchLeaseSnapshot {
  return Object.freeze({
    ...lease,
    state: "closed",
    slotState: "released"
  });
}
