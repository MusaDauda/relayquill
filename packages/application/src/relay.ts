import {
  AuthorizationDomainError,
  FANOUT_OUT_OF_ORDER_NAK_MS,
  MAX_NO_PROGRESS_RECOVERY_GENERATIONS,
  OUTBOX_PUBLISH_TIMEOUT_MS,
  ValidationDomainError,
  addMilliseconds,
  formatUtcTimestamp,
  parseBrokerGenerationId,
  parseControlEpoch,
  parseOutboxId,
  parsePublicationObservationId,
  parsePublicationRecoveryEpisodeId,
  parseRuntimeInstanceId,
  type BrokerGenerationId,
  type ControlEpoch,
  type EventId,
  type OutboxId,
  type OutboxState,
  type PublicationRecoveryEpisodeId,
  type RuntimeInstanceId
} from "@relayquill/domain";
import {
  decodeBrokerNotificationEnvelope,
  encodeBrokerMessageId,
  encodeBrokerNotificationEnvelope,
  parseCanonicalUtcTimestamp
} from "@relayquill/contracts";
import {
  BrokerCapacityError,
  BrokerPublishError
} from "@relayquill/broker";
import {
  type BrokerPublishPort,
  type ClockPort,
  type IdGeneratorPort,
  type RelayRepositoryPort,
  type TelemetryPort,
  type UnitOfWorkPort,
  cryptoIdGeneratorPort,
  noopTelemetryPort,
  systemClockPort
} from "./ports.js";

export const DEFAULT_OUTBOX_CLAIM_LEASE_MS = 15_000n as const;
export const DEFAULT_OUTBOX_RETRY_BACKOFF_MS = 2_000 as const;

export interface RelayPublishAttemptInput {
  readonly outboxId: OutboxId | string;
  readonly instanceId: RuntimeInstanceId | string;
  readonly controlEpoch: ControlEpoch | string;
  readonly claimLeaseMs?: bigint | undefined;
  readonly publishTimeoutMs?: number | undefined;
  readonly retryBackoffMs?: number | undefined;
}

export interface RelayPublishAttemptOutput {
  readonly outboxId: OutboxId;
  readonly eventId: EventId;
  readonly publicationGeneration: bigint;
  readonly claimGeneration: bigint;
  readonly brokerMessageId: string;
  readonly outcome: "published" | "publish_unknown" | "retry_pending" | "blocked";
  readonly acceptedAsCurrent: boolean;
  readonly outboxState: OutboxState;
  readonly streamName?: string | undefined;
  readonly streamSequence?: bigint | undefined;
  readonly duplicate?: boolean | undefined;
  readonly safeErrorCode?: string | undefined;
}

export interface RecoverUnknownOutboxInput {
  readonly outboxId: OutboxId | string;
  readonly episodeId: PublicationRecoveryEpisodeId | string;
  readonly instanceId: RuntimeInstanceId | string;
  readonly controlEpoch: ControlEpoch | string;
  readonly noProgressGenerationCount: number;
  readonly forceNewGeneration?: boolean | undefined;
  readonly reasonCode?: string | undefined;
}

export interface RecoverUnknownOutboxOutput {
  readonly outboxId: OutboxId;
  readonly action:
    | "republished_same_generation"
    | "allocated_and_published_new_generation"
    | "still_unknown"
    | "review_required"
    | "already_complete";
  readonly publicationGeneration: bigint;
  readonly brokerMessageId: string;
  readonly outboxState?: OutboxState | undefined;
}

export interface RelayServiceDeps<TTx> {
  readonly uow: UnitOfWorkPort<TTx>;
  readonly relayRepo: RelayRepositoryPort<TTx>;
  readonly broker: BrokerPublishPort;
  readonly clock?: ClockPort | undefined;
  readonly idGenerator?: IdGeneratorPort | undefined;
  readonly telemetry?: TelemetryPort | undefined;
}

function classifyBrokerPublishFailure(err: unknown): {
  readonly outcome: "publish_unknown" | "retry_pending" | "blocked";
  readonly safeErrorCode: string;
} {
  if (err instanceof BrokerPublishError) {
    if (
      err.classification === "publish_unknown" ||
      err.code === "ACCEPTANCE_UNKNOWN" ||
      err.acceptance === "unknown"
    ) {
      return {
        outcome: "publish_unknown",
        safeErrorCode: err.reasonCode ?? "BROKER_PUBACK_UNKNOWN"
      };
    }
    if (!err.retryable && err.acceptance === "known_rejected") {
      return {
        outcome: "blocked",
        safeErrorCode: err.reasonCode ?? "BROKER_PUBLISH_REJECTED"
      };
    }
    return {
      outcome: "retry_pending",
      safeErrorCode: err.reasonCode ?? "BROKER_PUBLISH_RETRYABLE"
    };
  }
  if (err instanceof BrokerCapacityError) {
    return {
      outcome: "retry_pending",
      safeErrorCode: err.reasonCode ?? "BROKER_CAPACITY_EXCEEDED"
    };
  }
  if (
    typeof err === "object" &&
    err !== null &&
    "acceptance" in err &&
    (err as { acceptance?: unknown }).acceptance === "unknown"
  ) {
    return {
      outcome: "publish_unknown",
      safeErrorCode: "BROKER_PUBACK_TIMEOUT"
    };
  }
  return {
    outcome: "retry_pending",
    safeErrorCode: "BROKER_UNAVAILABLE"
  };
}

export class RelayService<TTx> {
  readonly #uow: UnitOfWorkPort<TTx>;
  readonly #relayRepo: RelayRepositoryPort<TTx>;
  readonly #broker: BrokerPublishPort;
  readonly #clock: ClockPort;
  readonly #ids: IdGeneratorPort;
  readonly #telemetry: TelemetryPort;

  constructor(deps: RelayServiceDeps<TTx>) {
    this.#uow = deps.uow;
    this.#relayRepo = deps.relayRepo;
    this.#broker = deps.broker;
    this.#clock = deps.clock ?? systemClockPort;
    this.#ids = deps.idGenerator ?? cryptoIdGeneratorPort;
    this.#telemetry = deps.telemetry ?? noopTelemetryPort;
  }

  /**
   * Claims a single pending outbox row under a fenced lease, publishes the immutable
   * notification envelope to JetStream with its deterministic `rq:<outboxId>:<gen>` ID,
   * and finalizes the observation in a short transaction.
   */
  async publishClaimedOutbox(input: RelayPublishAttemptInput): Promise<RelayPublishAttemptOutput> {
    const span = this.#telemetry.startSpan("relayquill.relay.publish_outbox");
    try {
      const outboxId = parseOutboxId(input.outboxId, "outboxId");
      const instanceId = parseRuntimeInstanceId(input.instanceId, "instanceId");
      const controlEpoch = parseControlEpoch(input.controlEpoch, "controlEpoch");
      const claimLeaseMs = input.claimLeaseMs ?? DEFAULT_OUTBOX_CLAIM_LEASE_MS;
      const publishTimeoutMs = input.publishTimeoutMs ?? OUTBOX_PUBLISH_TIMEOUT_MS;
      const retryBackoffMs = input.retryBackoffMs ?? DEFAULT_OUTBOX_RETRY_BACKOFF_MS;

      const claimNow = parseCanonicalUtcTimestamp(
        formatUtcTimestamp(this.#clock.nowInstant()),
        "now"
      );

      // Transaction 1: Verify installation gate and claim outbox lease with fencing token.
      const claimed = await this.#uow.inTransaction(async (tx) => {
        const installation = await this.#relayRepo.readInstallationAuthority(tx);
        if (
          installation.mode === "recovery_quarantine" ||
          !installation.allowPublication ||
          installation.controlEpoch !== controlEpoch
        ) {
          throw new AuthorizationDomainError({
            code: "FORBIDDEN",
            message: "Installation disallows outbox publication or control epoch is stale"
          });
        }
        return this.#relayRepo.claimOutboxEvent(tx, {
          outboxId,
          instanceId,
          controlEpoch,
          claimLeaseMs,
          now: claimNow
        });
      });

      const expectedMsgId = encodeBrokerMessageId(claimed.outboxId, claimed.publicationGeneration);
      if (claimed.brokerMessageId !== expectedMsgId) {
        throw new ValidationDomainError({
          code: "INVARIANT_VIOLATION",
          message: `Outbox broker_message_id "${claimed.brokerMessageId}" does not match deterministic "${expectedMsgId}"`
        });
      }

      // Network step outside DB transaction: publish with deterministic Nats-Msg-Id.
      let outcome: "published" | "publish_unknown" | "retry_pending" | "blocked" = "published";
      let brokerGenerationId: BrokerGenerationId | null = null;
      let streamName: string | null = null;
      let streamSequence: bigint | null = null;
      let ackDuplicate = false;
      let safeErrorCode: string | null = null;

      try {
        const pubAck = await this.#broker.publish({
          outboxId: claimed.outboxId,
          projectId: claimed.projectId,
          publicationGeneration: claimed.publicationGeneration,
          envelopeBytes: claimed.envelopeBytes,
          timeoutMs: Number(publishTimeoutMs),
          expectedBrokerGenerationId: this.#broker.brokerGenerationId,
          ...(claimed.traceparent !== undefined
            ? {
                traceContext: {
                  traceparent: claimed.traceparent,
                  ...(claimed.tracestate !== undefined ? { tracestate: claimed.tracestate } : {})
                }
              }
            : {})
        });
        outcome = "published";
        brokerGenerationId = parseBrokerGenerationId(
          pubAck.brokerGenerationId,
          "brokerGenerationId"
        );
        streamName = pubAck.stream;
        streamSequence = BigInt(pubAck.seq);
        ackDuplicate = pubAck.duplicate;
      } catch (err) {
        const classified = classifyBrokerPublishFailure(err);
        outcome = classified.outcome;
        safeErrorCode = classified.safeErrorCode;
      }

      const observeNowInstant = this.#clock.nowInstant();
      const observeNow = parseCanonicalUtcTimestamp(
        formatUtcTimestamp(observeNowInstant),
        "observeNow"
      );
      const nextPublishAt =
        outcome === "retry_pending"
          ? parseCanonicalUtcTimestamp(
              formatUtcTimestamp(addMilliseconds(observeNowInstant, retryBackoffMs)),
              "nextPublishAt"
            )
          : null;
      const observationId = parsePublicationObservationId(this.#ids.nextUuid(), "observationId");

      // Transaction 2: Record fenced observation result.
      const observed = await this.#uow.inTransaction(async (tx) =>
        this.#relayRepo.observeOutboxPublication(tx, {
          outboxId: claimed.outboxId,
          publicationGeneration: claimed.publicationGeneration,
          instanceId,
          controlEpoch,
          expectedClaimGeneration: claimed.claimGeneration,
          outcome,
          brokerGenerationId,
          streamName,
          streamSequence,
          ackDuplicate,
          safeErrorCode,
          nextPublishAt,
          observationId,
          now: observeNow
        })
      );

      span.end({ code: outcome === "published" ? "OK" : "ERROR" });
      return Object.freeze<RelayPublishAttemptOutput>({
        outboxId: claimed.outboxId,
        eventId: claimed.eventId,
        publicationGeneration: claimed.publicationGeneration,
        claimGeneration: claimed.claimGeneration,
        brokerMessageId: claimed.brokerMessageId,
        outcome,
        acceptedAsCurrent: observed.acceptedAsCurrent,
        outboxState: observed.outboxState,
        ...(streamName !== null ? { streamName } : {}),
        ...(streamSequence !== null ? { streamSequence } : {}),
        ...(outcome === "published" ? { duplicate: ackDuplicate } : {}),
        ...(safeErrorCode !== null ? { safeErrorCode } : {})
      });
    } catch (err) {
      span.end({ code: "ERROR", message: err instanceof Error ? err.message : "relay_failed" });
      throw err;
    }
  }

  /**
   * Scans due pending outbox events and relays up to `limit` items.
   */
  async runRelayBatch(input: {
    readonly instanceId: RuntimeInstanceId | string;
    readonly controlEpoch: ControlEpoch | string;
    readonly limit?: number | undefined;
    readonly claimLeaseMs?: bigint | undefined;
  }): Promise<readonly RelayPublishAttemptOutput[]> {
    const instanceId = parseRuntimeInstanceId(input.instanceId, "instanceId");
    const controlEpoch = parseControlEpoch(input.controlEpoch, "controlEpoch");
    const limit = Math.min(64, Math.max(1, Math.trunc(input.limit ?? 16)));
    const now = parseCanonicalUtcTimestamp(formatUtcTimestamp(this.#clock.nowInstant()), "now");

    const due = await this.#uow.inTransaction(async (tx) =>
      this.#relayRepo.listDueOutboxEvents(tx, now, limit)
    );

    const results: RelayPublishAttemptOutput[] = [];
    for (const row of due) {
      const res = await this.publishClaimedOutbox({
        outboxId: row.outboxId,
        instanceId,
        controlEpoch,
        ...(input.claimLeaseMs !== undefined ? { claimLeaseMs: input.claimLeaseMs } : {})
      });
      results.push(res);
    }
    return Object.freeze(results);
  }

  /**
   * Recovers an outbox row in `publish_unknown` state:
   * - Within the JetStream dedup window (when `forceNewGeneration !== true`), re-attempts
   *   publishing the exact existing `(outboxId, publicationGeneration)` and `rq:<outboxId>:<gen>`
   *   so JetStream deduplicates any prior commit.
   * - When allocating a new recovery generation, enforces the max 5 no-progress generation ceiling
   *   (`review_required`) before allocating generation `N + 1`.
   */
  async recoverUnknownPublication(
    input: RecoverUnknownOutboxInput
  ): Promise<RecoverUnknownOutboxOutput> {
    const outboxId = parseOutboxId(input.outboxId, "outboxId");
    const episodeId = parsePublicationRecoveryEpisodeId(input.episodeId, "episodeId");
    const instanceId = parseRuntimeInstanceId(input.instanceId, "instanceId");
    const controlEpoch = parseControlEpoch(input.controlEpoch, "controlEpoch");

    if (input.noProgressGenerationCount >= MAX_NO_PROGRESS_RECOVERY_GENERATIONS) {
      return Object.freeze({
        outboxId,
        action: "review_required",
        publicationGeneration: 0n,
        brokerMessageId: ""
      });
    }

    const publications = await this.#uow.inTransaction(async (tx) =>
      this.#relayRepo.listOutboxPublications(tx, outboxId)
    );
    const latest = publications[publications.length - 1];
    if (latest === undefined) {
      throw new ValidationDomainError({
        code: "NOT_FOUND",
        message: `No publication history found for outbox "${outboxId}"`
      });
    }
    if (latest.state === "published") {
      return Object.freeze({
        outboxId,
        action: "already_complete",
        publicationGeneration: latest.publicationGeneration,
        brokerMessageId: latest.brokerMessageId,
        outboxState: "published"
      });
    }

    if (input.forceNewGeneration !== true) {
      const retried = await this.publishClaimedOutbox({
        outboxId,
        instanceId,
        controlEpoch
      });
      if (retried.outcome === "published") {
        return Object.freeze({
          outboxId,
          action: "republished_same_generation",
          publicationGeneration: retried.publicationGeneration,
          brokerMessageId: retried.brokerMessageId,
          outboxState: retried.outboxState
        });
      }
      return Object.freeze({
        outboxId,
        action: "still_unknown",
        publicationGeneration: retried.publicationGeneration,
        brokerMessageId: retried.brokerMessageId,
        outboxState: retried.outboxState
      });
    }

    const decoded = decodeBrokerNotificationEnvelope(latest.envelopeBytes);
    const nextGeneration = latest.publicationGeneration + 1n;
    const nextEncoded = encodeBrokerNotificationEnvelope({
      envelope_version: 1,
      outbox_id: outboxId,
      event_id: decoded.event_id,
      project_id: decoded.project_id,
      topology_version: decoded.topology_version,
      publication_generation: nextGeneration,
      content_sha256: decoded.content_sha256,
      ...(decoded.traceparent !== undefined
        ? { traceparent: decoded.traceparent }
        : {}),
      ...(decoded.tracestate !== undefined
        ? { tracestate: decoded.tracestate }
        : {})
    });

    const now = parseCanonicalUtcTimestamp(formatUtcTimestamp(this.#clock.nowInstant()), "now");
    const allocation = await this.#uow.inTransaction(async (tx) =>
      this.#relayRepo.allocateOutboxRecoveryGeneration(tx, {
        outboxId,
        episodeId,
        instanceId,
        controlEpoch,
        envelopeBytes: nextEncoded.bytes,
        envelopeSha256: nextEncoded.envelope_sha256,
        brokerMessageId: nextEncoded.broker_message_id,
        reasonCode: input.reasonCode ?? "DEDUP_WINDOW_ELAPSED_RECOVERY",
        now
      })
    );

    if (allocation.outcome === "already_complete") {
      return Object.freeze({
        outboxId,
        action: "already_complete",
        publicationGeneration: latest.publicationGeneration,
        brokerMessageId: latest.brokerMessageId,
        outboxState: "published"
      });
    }
    if (allocation.outcome === "review_required") {
      return Object.freeze({
        outboxId,
        action: "review_required",
        publicationGeneration: latest.publicationGeneration,
        brokerMessageId: latest.brokerMessageId
      });
    }

    const published = await this.publishClaimedOutbox({
      outboxId,
      instanceId,
      controlEpoch
    });

    return Object.freeze({
      outboxId,
      action:
        published.outcome === "published"
          ? "allocated_and_published_new_generation"
          : "still_unknown",
      publicationGeneration: published.publicationGeneration,
      brokerMessageId: published.brokerMessageId,
      outboxState: published.outboxState
    });
  }
}

export { FANOUT_OUT_OF_ORDER_NAK_MS };
