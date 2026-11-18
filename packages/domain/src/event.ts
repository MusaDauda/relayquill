import { type Temporal } from "@js-temporal/polyfill";
import { createEnumGuard } from "./enums.js";
import {
  ConflictDomainError,
  InvariantViolationError,
  RateLimitDomainError,
  UnsupportedStateTransitionError,
  ValidationDomainError
} from "./errors.js";
import {
  type BrokerGenerationId,
  type ControlEpoch,
  type EventId,
  type OutboxId,
  type ProjectId,
  type PublicationObservationId,
  type PublicationRecoveryEpisodeId,
  type RuntimeInstanceId
} from "./ids.js";
import { assertTransition, type TransitionMatrix } from "./state-machine.js";
import { addMilliseconds, compareInstants } from "./time.js";

export const EVENT_STATES = [
  "accepted",
  "fanout_in_progress",
  "fanout_complete",
  "fanout_blocked",
  "retired"
] as const;
export type EventState = (typeof EVENT_STATES)[number];
export const isEventState = createEnumGuard(EVENT_STATES);

export const OUTBOX_STATES = [
  "pending",
  "claimed",
  "published",
  "blocked",
  "retired"
] as const;
export type OutboxState = (typeof OUTBOX_STATES)[number];
export const isOutboxState = createEnumGuard(OUTBOX_STATES);

export const PUBLICATION_STATES = [
  "prepared",
  "publish_unknown",
  "ack_observed",
  "recovery_superseded"
] as const;
export type PublicationState = (typeof PUBLICATION_STATES)[number];
export const isPublicationState = createEnumGuard(PUBLICATION_STATES);

export const PUBLICATION_RECOVERY_EPISODE_STATES = [
  "active",
  "completed",
  "review_required",
  "revoked"
] as const;
export type PublicationRecoveryEpisodeState =
  (typeof PUBLICATION_RECOVERY_EPISODE_STATES)[number];
export const isPublicationRecoveryEpisodeState = createEnumGuard(
  PUBLICATION_RECOVERY_EPISODE_STATES
);

export const DEFAULT_DELIVERY_WINDOW_MS = 86_400_000n;
export const MAX_DELIVERY_WINDOW_MS = 604_800_000n;
export const EVENT_MAX_CONTENT_BYTES = 262_144 as const;
export const EVENT_MAX_ENVELOPE_BYTES = 524_288 as const;
export const EVENT_MAX_JSON_DEPTH = 32 as const;
export const EVENT_MAX_JSON_NODES = 32_768 as const;
export const EVENT_MAX_NUMERIC_TOKEN_BYTES = 256 as const;

export const OUTBOX_CLAIM_LEASE_MS = 30_000n;
export const OUTBOX_PUBLISH_TIMEOUT_MS = 5_000n;
export const RELAY_MAX_IN_FLIGHT = 16 as const;
export const BROKER_EVENT_STREAM_NAME = "RELAYQUILL_EVENTS_V1" as const;
export const BROKER_EVENT_MAX_PAYLOAD_BYTES = 4_096 as const;
export const BROKER_DEDUP_WINDOW_MS = 120_000n;

export const RECOVERY_GENERATION_MIN_INTERVAL_MS = 60_000n;
export const MAX_NO_PROGRESS_RECOVERY_GENERATIONS = 5 as const;

export const ALLOWED_EVENT_TRANSITIONS: TransitionMatrix<EventState> = Object.freeze({
  accepted: ["fanout_in_progress", "fanout_complete", "fanout_blocked"],
  fanout_in_progress: ["fanout_complete", "fanout_blocked"],
  fanout_blocked: ["fanout_in_progress", "fanout_complete", "retired"],
  fanout_complete: ["retired"],
  retired: []
});

export const ALLOWED_OUTBOX_TRANSITIONS: TransitionMatrix<OutboxState> = Object.freeze({
  pending: ["claimed", "blocked"],
  claimed: ["published", "pending", "blocked"],
  published: ["pending", "retired"],
  blocked: ["pending", "retired"],
  retired: []
});

export const ALLOWED_PUBLICATION_TRANSITIONS: TransitionMatrix<PublicationState> = Object.freeze({
  prepared: ["publish_unknown", "ack_observed", "recovery_superseded"],
  publish_unknown: ["publish_unknown", "ack_observed", "recovery_superseded"],
  ack_observed: ["recovery_superseded"],
  recovery_superseded: []
});

export const ALLOWED_PUBLICATION_RECOVERY_EPISODE_TRANSITIONS: TransitionMatrix<PublicationRecoveryEpisodeState> =
  Object.freeze({
    active: ["completed", "review_required", "revoked"],
    review_required: ["active", "completed", "revoked"],
    completed: [],
    revoked: []
  });

export function isTerminalEventState(state: EventState): boolean {
  return state === "retired";
}

export function isTerminalOutboxState(state: OutboxState): boolean {
  return state === "retired";
}

export function isTerminalPublicationState(state: PublicationState): boolean {
  return state === "recovery_superseded";
}

export function formatBrokerEventSubject(projectId: ProjectId): string {
  return `rq.events.${projectId}.accepted`;
}

export function formatBrokerMessageId(outboxId: OutboxId, publicationGeneration: bigint): string {
  if (publicationGeneration < 1n) {
    throw new ValidationDomainError({
      code: "INVALID_INT64",
      message: "Publication generation must be >= 1",
      fieldErrors: [{ path: "publication_generation", code: "INVALID_INT64" }]
    });
  }
  return `rq:${outboxId}:${publicationGeneration.toString(10)}`;
}

export function computeEventDeliveryDeadline(
  admittedAt: Temporal.Instant,
  windowMs: bigint = DEFAULT_DELIVERY_WINDOW_MS
): Temporal.Instant {
  if (windowMs <= 0n || windowMs > MAX_DELIVERY_WINDOW_MS) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Delivery window must be between 1ms and ${MAX_DELIVERY_WINDOW_MS.toString(10)}ms`,
      fieldErrors: [{ path: "delivery_window_ms", code: "INVALID_VALUE" }]
    });
  }
  return addMilliseconds(admittedAt, windowMs, "delivery_deadline_at");
}

export interface EventStateSnapshot {
  readonly eventId: EventId;
  readonly state: EventState;
  readonly blockingReason: string | null;
  readonly retiredAt: Temporal.Instant | null;
}

export function transitionEventState(
  snapshot: EventStateSnapshot,
  targetState: EventState,
  options?: {
    readonly blockingReason?: string | undefined;
    readonly retiredAt?: Temporal.Instant | undefined;
  }
): EventStateSnapshot {
  assertTransition("event", ALLOWED_EVENT_TRANSITIONS, snapshot.state, targetState, {
    kind: "event",
    id: snapshot.eventId
  });

  if (targetState === "fanout_blocked") {
    const reason = options?.blockingReason?.trim();
    if (reason === undefined || reason.length === 0) {
      throw new ValidationDomainError({
        code: "INVALID_VALUE",
        message: "Transitioning event to fanout_blocked requires a non-empty blockingReason",
        resourceRef: { kind: "event", id: snapshot.eventId }
      });
    }
    return Object.freeze({
      ...snapshot,
      state: targetState,
      blockingReason: reason
    });
  }

  if (targetState === "retired") {
    if (options?.retiredAt === undefined) {
      throw new ValidationDomainError({
        code: "INVALID_TIMESTAMP",
        message: "Retiring event requires retiredAt timestamp",
        resourceRef: { kind: "event", id: snapshot.eventId }
      });
    }
    return Object.freeze({
      ...snapshot,
      state: targetState,
      retiredAt: options.retiredAt
    });
  }

  return Object.freeze({
    ...snapshot,
    state: targetState,
    blockingReason: null
  });
}

export interface OutboxSnapshot {
  readonly outboxId: OutboxId;
  readonly state: OutboxState;
  readonly currentPublicationGeneration: bigint;
  readonly claimGeneration: bigint;
  readonly claimOwnerInstanceId: RuntimeInstanceId | null;
  readonly claimControlEpoch: ControlEpoch | null;
  readonly claimExpiresAt: Temporal.Instant | null;
  readonly nextPublishAt: Temporal.Instant;
  readonly lastSafeErrorCode: string | null;
}

export interface OutboxClaimInput {
  readonly ownerInstanceId: RuntimeInstanceId;
  readonly controlEpoch: ControlEpoch;
  readonly now: Temporal.Instant;
}

export function claimOutboxRow(
  outbox: OutboxSnapshot,
  input: OutboxClaimInput
): OutboxSnapshot {
  assertTransition("outbox", ALLOWED_OUTBOX_TRANSITIONS, outbox.state, "claimed", {
    kind: "outbox",
    id: outbox.outboxId
  });
  if (compareInstants(input.now, outbox.nextPublishAt) < 0) {
    throw new ConflictDomainError({
      code: "STATE_TRANSITION_NOT_ALLOWED",
      message: "Outbox row is not yet due for publish claim",
      resourceRef: { kind: "outbox", id: outbox.outboxId }
    });
  }
  return Object.freeze({
    ...outbox,
    state: "claimed",
    claimGeneration: outbox.claimGeneration + 1n,
    claimOwnerInstanceId: input.ownerInstanceId,
    claimControlEpoch: input.controlEpoch,
    claimExpiresAt: addMilliseconds(input.now, OUTBOX_CLAIM_LEASE_MS, "claim_expires_at")
  });
}

export interface PublicationSnapshot {
  readonly outboxId: OutboxId;
  readonly publicationGeneration: bigint;
  readonly state: PublicationState;
  readonly brokerMessageId: string;
  readonly sendCount: number;
  readonly firstBrokerGenerationId: BrokerGenerationId | null;
  readonly firstObservationId: PublicationObservationId | null;
  readonly streamSequence: number | null;
  readonly ackObservedAt: Temporal.Instant | null;
}

export interface OutboxAckInput {
  readonly ownerInstanceId: RuntimeInstanceId;
  readonly controlEpoch: ControlEpoch;
  readonly expectedClaimGeneration: bigint;
  readonly streamName: string;
  readonly streamSequence: number;
  readonly brokerGenerationId: BrokerGenerationId;
  readonly observationId: PublicationObservationId;
  readonly ackObservedAt: Temporal.Instant;
}

export function assertActiveOutboxClaim(
  outbox: OutboxSnapshot,
  ownerInstanceId: RuntimeInstanceId,
  controlEpoch: ControlEpoch,
  expectedClaimGeneration: bigint
): void {
  if (
    outbox.state !== "claimed" ||
    outbox.claimOwnerInstanceId !== ownerInstanceId ||
    outbox.claimControlEpoch !== controlEpoch ||
    outbox.claimGeneration !== expectedClaimGeneration
  ) {
    throw new ConflictDomainError({
      code: "VERSION_CONFLICT",
      message: "Stale or mismatched outbox claim fence",
      boundary: "published",
      resourceRef: { kind: "outbox", id: outbox.outboxId }
    });
  }
}

export function acknowledgeOutboxPublication(
  outbox: OutboxSnapshot,
  publication: PublicationSnapshot,
  input: OutboxAckInput
): { readonly outbox: OutboxSnapshot; readonly publication: PublicationSnapshot } {
  assertActiveOutboxClaim(
    outbox,
    input.ownerInstanceId,
    input.controlEpoch,
    input.expectedClaimGeneration
  );
  if (publication.outboxId !== outbox.outboxId) {
    throw new InvariantViolationError({
      message: "Publication record does not belong to outbox row",
      resourceRef: { kind: "outbox", id: outbox.outboxId }
    });
  }
  if (publication.publicationGeneration !== outbox.currentPublicationGeneration) {
    throw new ConflictDomainError({
      code: "VERSION_CONFLICT",
      message: "Publication generation does not match current outbox generation",
      resourceRef: { kind: "outbox", id: outbox.outboxId }
    });
  }
  if (input.streamName !== BROKER_EVENT_STREAM_NAME) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Unexpected broker stream name "${input.streamName}"`,
      boundary: "published"
    });
  }
  if (!Number.isSafeInteger(input.streamSequence) || input.streamSequence <= 0) {
    throw new ValidationDomainError({
      code: "INVALID_INT64",
      message: "Broker stream sequence must be a positive safe integer",
      boundary: "published"
    });
  }

  assertTransition("outbox", ALLOWED_OUTBOX_TRANSITIONS, outbox.state, "published", {
    kind: "outbox",
    id: outbox.outboxId
  });
  assertTransition(
    "outbox_publication",
    ALLOWED_PUBLICATION_TRANSITIONS,
    publication.state,
    "ack_observed",
    { kind: "outbox", id: outbox.outboxId }
  );

  return Object.freeze({
    outbox: Object.freeze({
      ...outbox,
      state: "published",
      claimOwnerInstanceId: null,
      claimControlEpoch: null,
      claimExpiresAt: null,
      lastSafeErrorCode: null
    }),
    publication: Object.freeze({
      ...publication,
      state: "ack_observed",
      sendCount: publication.sendCount + 1,
      firstBrokerGenerationId: publication.firstBrokerGenerationId ?? input.brokerGenerationId,
      firstObservationId: publication.firstObservationId ?? input.observationId,
      streamSequence: publication.streamSequence ?? input.streamSequence,
      ackObservedAt: publication.ackObservedAt ?? input.ackObservedAt
    })
  });
}

export function releaseOutboxClaimToPending(
  outbox: OutboxSnapshot,
  publication: PublicationSnapshot,
  options: {
    readonly nextPublishAt: Temporal.Instant;
    readonly markPublishUnknown: boolean;
    readonly lastSafeErrorCode?: string | null | undefined;
  }
): { readonly outbox: OutboxSnapshot; readonly publication: PublicationSnapshot } {
  assertTransition("outbox", ALLOWED_OUTBOX_TRANSITIONS, outbox.state, "pending", {
    kind: "outbox",
    id: outbox.outboxId
  });

  let nextPublication = publication;
  if (options.markPublishUnknown) {
    assertTransition(
      "outbox_publication",
      ALLOWED_PUBLICATION_TRANSITIONS,
      publication.state,
      "publish_unknown",
      { kind: "outbox", id: outbox.outboxId }
    );
    nextPublication = Object.freeze({
      ...publication,
      state: "publish_unknown",
      sendCount: publication.sendCount + 1
    });
  }

  return Object.freeze({
    outbox: Object.freeze({
      ...outbox,
      state: "pending",
      // Normal uncertain retry preserves currentPublicationGeneration.
      claimOwnerInstanceId: null,
      claimControlEpoch: null,
      claimExpiresAt: null,
      nextPublishAt: options.nextPublishAt,
      lastSafeErrorCode:
        options.lastSafeErrorCode !== undefined ? options.lastSafeErrorCode : outbox.lastSafeErrorCode
    }),
    publication: nextPublication
  });
}

export function blockOutboxRow(
  outbox: OutboxSnapshot,
  safeErrorCode: string
): OutboxSnapshot {
  const trimmed = safeErrorCode.trim();
  if (trimmed.length === 0) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: "Blocking an outbox row requires a non-empty safeErrorCode",
      resourceRef: { kind: "outbox", id: outbox.outboxId }
    });
  }
  assertTransition("outbox", ALLOWED_OUTBOX_TRANSITIONS, outbox.state, "blocked", {
    kind: "outbox",
    id: outbox.outboxId
  });
  return Object.freeze({
    ...outbox,
    state: "blocked",
    claimOwnerInstanceId: null,
    claimControlEpoch: null,
    claimExpiresAt: null,
    lastSafeErrorCode: trimmed
  });
}

export interface PublicationRecoveryEpisodeSnapshot {
  readonly episodeId: PublicationRecoveryEpisodeId;
  readonly outboxId: OutboxId;
  readonly state: PublicationRecoveryEpisodeState;
  readonly successiveNoProgressGenerations: number;
  readonly lastGenerationIssuedAt: Temporal.Instant | null;
}

export function allocateOutboxRecoveryGeneration(
  outbox: OutboxSnapshot,
  currentPublication: PublicationSnapshot,
  episode: PublicationRecoveryEpisodeSnapshot,
  now: Temporal.Instant
): {
  readonly outbox: OutboxSnapshot;
  readonly supersededPublication: PublicationSnapshot;
  readonly nextPublication: PublicationSnapshot | null;
  readonly episode: PublicationRecoveryEpisodeSnapshot;
} {
  if (episode.outboxId !== outbox.outboxId || currentPublication.outboxId !== outbox.outboxId) {
    throw new InvariantViolationError({
      message: "Outbox recovery entities must reference the same outboxId",
      resourceRef: { kind: "outbox", id: outbox.outboxId }
    });
  }
  if (episode.state !== "active") {
    throw new ConflictDomainError({
      code: "STATE_TRANSITION_NOT_ALLOWED",
      message: `Cannot allocate recovery generation when episode state is "${episode.state}"`,
      resourceRef: { kind: "publication_recovery_episode", id: episode.episodeId }
    });
  }
  if (episode.lastGenerationIssuedAt !== null) {
    const earliestNext = addMilliseconds(
      episode.lastGenerationIssuedAt,
      RECOVERY_GENERATION_MIN_INTERVAL_MS
    );
    if (compareInstants(now, earliestNext) < 0) {
      throw new RateLimitDomainError({
        code: "RATE_LIMITED",
        message: "Publication recovery generation interval (60s) has not elapsed",
        resourceRef: { kind: "outbox", id: outbox.outboxId }
      });
    }
  }

  const nextNoProgressCount = episode.successiveNoProgressGenerations + 1;
  const requiresReview = nextNoProgressCount >= MAX_NO_PROGRESS_RECOVERY_GENERATIONS;
  const nextEpisodeState: PublicationRecoveryEpisodeState = requiresReview
    ? "review_required"
    : "active";

  const nextGeneration = requiresReview
    ? outbox.currentPublicationGeneration
    : outbox.currentPublicationGeneration + 1n;
  const nextOutboxState: OutboxState = requiresReview ? "blocked" : "pending";

  if (outbox.state !== "published" && outbox.state !== "blocked" && outbox.state !== "pending") {
    throw new UnsupportedStateTransitionError({
      code: "STATE_TRANSITION_NOT_ALLOWED",
      message: `Cannot allocate recovery generation while outbox is in state "${outbox.state}"`,
      resourceRef: { kind: "outbox", id: outbox.outboxId }
    });
  }
  assertTransition(
    "outbox_publication",
    ALLOWED_PUBLICATION_TRANSITIONS,
    currentPublication.state,
    "recovery_superseded",
    { kind: "outbox", id: outbox.outboxId }
  );

  if (requiresReview) {
    assertTransition(
      "publication_recovery_episode",
      ALLOWED_PUBLICATION_RECOVERY_EPISODE_TRANSITIONS,
      episode.state,
      nextEpisodeState,
      { kind: "publication_recovery_episode", id: episode.episodeId }
    );
  }

  const nextPublication: PublicationSnapshot | null = requiresReview
    ? null
    : Object.freeze({
        outboxId: outbox.outboxId,
        publicationGeneration: nextGeneration,
        state: "prepared",
        brokerMessageId: formatBrokerMessageId(outbox.outboxId, nextGeneration),
        sendCount: 0,
        firstBrokerGenerationId: null,
        firstObservationId: null,
        streamSequence: null,
        ackObservedAt: null
      });

  return Object.freeze({
    outbox: Object.freeze({
      ...outbox,
      state: nextOutboxState,
      currentPublicationGeneration: nextGeneration,
      claimOwnerInstanceId: null,
      claimControlEpoch: null,
      claimExpiresAt: null,
      nextPublishAt: now,
      lastSafeErrorCode: requiresReview
        ? "RECOVERY_NO_PROGRESS_THRESHOLD"
        : outbox.lastSafeErrorCode
    }),
    supersededPublication: Object.freeze({
      ...currentPublication,
      state: "recovery_superseded"
    }),
    nextPublication,
    episode: Object.freeze({
      ...episode,
      state: nextEpisodeState,
      successiveNoProgressGenerations: nextNoProgressCount,
      lastGenerationIssuedAt: now
    })
  });
}

export function recordRecoveryEpisodeProgress(
  episode: PublicationRecoveryEpisodeSnapshot,
  completed: boolean
): PublicationRecoveryEpisodeSnapshot {
  if (episode.state !== "active" && episode.state !== "review_required") {
    throw new UnsupportedStateTransitionError({
      code: "STATE_TRANSITION_NOT_ALLOWED",
      message: `Cannot record recovery episode progress in terminal state "${episode.state}"`,
      resourceRef: { kind: "publication_recovery_episode", id: episode.episodeId }
    });
  }
  if (completed) {
    assertTransition(
      "publication_recovery_episode",
      ALLOWED_PUBLICATION_RECOVERY_EPISODE_TRANSITIONS,
      episode.state,
      "completed",
      { kind: "publication_recovery_episode", id: episode.episodeId }
    );
  }
  return Object.freeze({
    ...episode,
    state: completed ? "completed" : episode.state,
    successiveNoProgressGenerations: 0
  });
}
