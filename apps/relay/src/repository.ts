import {
  type CanonicalUtcTimestamp,
  type ControlEpoch,
  type EventId,
  type OutboxId,
  type OutboxState,
  OUTBOX_STATES,
  parseBrokerGenerationId,
  parseEventId,
  parseOutboxId,
  parseProjectId,
  parseRuntimeInstanceId,
  parseTenantId,
  type PublicationRecoveryEpisodeId,
  type RuntimeInstanceId,
  type Sha256Hex
} from "@relayquill/domain";
import {
  decodeBrokerMessageId,
  decodeBrokerNotificationEnvelope,
  encodeBrokerMessageId
} from "@relayquill/contracts";
import {
  type ClaimOutboxRecord,
  type InstallationAuthoritySnapshot,
  type OutboxPublicationRecord,
  type OutboxRowRecord,
  type RelayRepositoryPort
} from "@relayquill/application";
import {
  allocateOutboxRecoveryGeneration as pgAllocateOutboxRecoveryGeneration,
  byteaToBuffer,
  byteaToSha256Hex,
  claimOutboxEvent as pgClaimOutboxEvent,
  observeOutboxPublication as pgObserveOutboxPublication,
  type PgTransactionClient,
  readInstallationStatus,
  readOptionalString,
  readOptionalUtcTimestamp,
  readOptionalUuid,
  readRequiredEnum,
  readRequiredInt64BigInt,
  readRequiredString,
  readRequiredUtcTimestamp,
  readRequiredUuid
} from "@relayquill/postgres";

function mapDbPublicationState(
  rawState: string
): OutboxPublicationRecord["state"] {
  switch (rawState) {
    case "ack_observed":
      return "published";
    case "publish_unknown":
      return "publish_unknown";
    case "recovery_superseded":
      return "abandoned";
    case "prepared":
    default:
      return "pending";
  }
}

function tryExtractTraceContext(
  envelopeBytes: Uint8Array
): { readonly traceparent?: string | undefined; readonly tracestate?: string | undefined } {
  try {
    const decoded = decodeBrokerNotificationEnvelope(envelopeBytes);
    return {
      ...(decoded.traceparent !== undefined ? { traceparent: decoded.traceparent } : {}),
      ...(decoded.tracestate !== undefined ? { tracestate: decoded.tracestate } : {})
    };
  } catch {
    return {};
  }
}

export class PostgresRelayRepository implements RelayRepositoryPort<PgTransactionClient> {
  async readInstallationAuthority(tx: PgTransactionClient): Promise<InstallationAuthoritySnapshot> {
    return readInstallationStatus(tx);
  }

  async listDueOutboxEvents(
    tx: PgTransactionClient,
    _now: CanonicalUtcTimestamp,
    limit: number
  ): Promise<readonly OutboxRowRecord[]> {
    const clamped = Math.min(500, Math.max(1, Math.trunc(limit)));
    const res = await tx.query<Record<string, unknown>>(
      `SELECT o.id, o.event_id, o.tenant_id, o.project_id, o.topology_version, o.state,
              o.current_publication_generation, o.next_publish_at,
              op.broker_message_id, o.claim_owner_instance_id, o.claim_generation,
              o.claim_expires_at, o.last_safe_error_code, o.version
         FROM rq.outbox_events o
         LEFT JOIN rq.outbox_publications op
           ON op.outbox_id = o.id
          AND op.publication_generation = o.current_publication_generation
        WHERE o.state IN ('pending', 'claimed')
          AND o.next_publish_at <= pg_catalog.clock_timestamp()
          AND (o.claim_expires_at IS NULL OR o.claim_expires_at <= pg_catalog.clock_timestamp())
        ORDER BY o.next_publish_at ASC, o.id ASC
        LIMIT $1::integer`,
      [clamped]
    );

    return res.rows.map((row): OutboxRowRecord => {
      const outboxId = readRequiredUuid(row, "id", parseOutboxId);
      const generation = readRequiredInt64BigInt(row, "current_publication_generation");
      const rawMsgId = readOptionalString(row, "broker_message_id");
      const brokerMessageId =
        rawMsgId !== undefined
          ? decodeBrokerMessageId(rawMsgId, "broker_message_id").message_id
          : encodeBrokerMessageId(outboxId, generation);
      const claimOwnerInstanceId = readOptionalUuid(
        row,
        "claim_owner_instance_id",
        parseRuntimeInstanceId
      );
      const claimExpiresAt = readOptionalUtcTimestamp(row, "claim_expires_at");
      const lastSafeErrorCode = readOptionalString(row, "last_safe_error_code");

      return {
        outboxId,
        eventId: readRequiredUuid(row, "event_id", parseEventId),
        tenantId: readRequiredUuid(row, "tenant_id", parseTenantId),
        projectId: readRequiredUuid(row, "project_id", parseProjectId),
        topologyVersion: readRequiredInt64BigInt(row, "topology_version"),
        state: readRequiredEnum(row, "state", OUTBOX_STATES),
        currentPublicationGeneration: generation,
        nextPublishAt: readRequiredUtcTimestamp(row, "next_publish_at"),
        brokerMessageId,
        ...(claimOwnerInstanceId !== undefined ? { claimOwnerInstanceId } : {}),
        claimGeneration: readRequiredInt64BigInt(row, "claim_generation"),
        ...(claimExpiresAt !== undefined ? { claimExpiresAt } : {}),
        recoveryAttemptCount: 0,
        noProgressGenerationCount: 0,
        ...(lastSafeErrorCode !== undefined ? { lastSafeErrorCode } : {}),
        version: readRequiredInt64BigInt(row, "version")
      };
    });
  }

  async claimOutboxEvent(
    tx: PgTransactionClient,
    params: {
      readonly outboxId: OutboxId;
      readonly instanceId: RuntimeInstanceId;
      readonly controlEpoch: ControlEpoch;
      readonly claimLeaseMs: bigint;
      readonly now: CanonicalUtcTimestamp;
    }
  ): Promise<ClaimOutboxRecord> {
    const claimed = await pgClaimOutboxEvent(tx, {
      outboxId: params.outboxId,
      instanceId: params.instanceId,
      controlEpoch: params.controlEpoch,
      claimLeaseMs: params.claimLeaseMs
    });
    const trace = tryExtractTraceContext(claimed.envelopeBytes);
    return {
      outboxId: claimed.outboxId,
      eventId: claimed.eventId,
      projectId: claimed.projectId,
      publicationGeneration: claimed.publicationGeneration,
      claimGeneration: claimed.claimGeneration,
      claimExpiresAt: claimed.claimExpiresAt,
      brokerMessageId: decodeBrokerMessageId(claimed.brokerMessageId, "broker_message_id").message_id,
      envelopeBytes: new Uint8Array(claimed.envelopeBytes),
      ...trace
    };
  }

  async observeOutboxPublication(
    tx: PgTransactionClient,
    params: Parameters<RelayRepositoryPort<PgTransactionClient>["observeOutboxPublication"]>[1]
  ): Promise<{
    readonly acceptedAsCurrent: boolean;
    readonly outboxState: OutboxState;
    readonly publicationState: string;
  }> {
    const observed = await pgObserveOutboxPublication(tx, {
      outboxId: params.outboxId,
      publicationGeneration: params.publicationGeneration,
      instanceId: params.instanceId,
      controlEpoch: params.controlEpoch,
      expectedClaimGeneration: params.expectedClaimGeneration,
      outcome: params.outcome,
      brokerGenerationId: params.brokerGenerationId,
      streamName: params.streamName,
      streamSequence: params.streamSequence,
      ackDuplicate: params.ackDuplicate,
      safeErrorCode: params.safeErrorCode,
      nextPublishAt: params.nextPublishAt,
      observationId: params.observationId
    });
    return {
      acceptedAsCurrent: observed.acceptedAsCurrent,
      outboxState: observed.outboxState,
      publicationState: observed.publicationState ?? "unknown"
    };
  }

  async listOutboxPublications(
    tx: PgTransactionClient,
    outboxId: OutboxId
  ): Promise<readonly OutboxPublicationRecord[]> {
    const res = await tx.query<Record<string, unknown>>(
      `SELECT publication_generation, envelope_sha256, envelope_bytes,
              broker_message_id, state, stream_name, stream_sequence,
              first_broker_generation_id
         FROM rq.outbox_publications
        WHERE outbox_id = $1::uuid
        ORDER BY publication_generation ASC`,
      [outboxId]
    );

    return res.rows.map((row): OutboxPublicationRecord => {
      const streamName = readOptionalString(row, "stream_name");
      const rawSeq = row["stream_sequence"];
      const streamSequence =
        rawSeq === null || rawSeq === undefined
          ? undefined
          : readRequiredInt64BigInt(row, "stream_sequence");
      const firstBrokerGenerationId = readOptionalUuid(
        row,
        "first_broker_generation_id",
        parseBrokerGenerationId
      );

      return {
        publicationGeneration: readRequiredInt64BigInt(row, "publication_generation"),
        envelopeSha256: byteaToSha256Hex(row["envelope_sha256"], "envelope_sha256"),
        envelopeBytes: new Uint8Array(byteaToBuffer(row["envelope_bytes"], "envelope_bytes")),
        brokerMessageId: decodeBrokerMessageId(
          readRequiredString(row, "broker_message_id"),
          "broker_message_id"
        ).message_id,
        state: mapDbPublicationState(readRequiredString(row, "state")),
        ...(streamName !== undefined ? { streamName } : {}),
        ...(streamSequence !== undefined ? { streamSequence } : {}),
        ...(firstBrokerGenerationId !== undefined ? { firstBrokerGenerationId } : {})
      };
    });
  }

  async allocateOutboxRecoveryGeneration(
    tx: PgTransactionClient,
    params: {
      readonly outboxId: OutboxId;
      readonly episodeId: PublicationRecoveryEpisodeId;
      readonly instanceId: RuntimeInstanceId;
      readonly controlEpoch: ControlEpoch;
      readonly envelopeBytes: Uint8Array;
      readonly envelopeSha256: Sha256Hex;
      readonly brokerMessageId: ReturnType<typeof encodeBrokerMessageId>;
      readonly reasonCode: string;
      readonly now: CanonicalUtcTimestamp;
    }
  ): Promise<{
    readonly outcome: "already_complete" | "review_required" | "allocated";
    readonly episodeId?: PublicationRecoveryEpisodeId | undefined;
    readonly eventId?: EventId | undefined;
    readonly publicationGeneration?: bigint | undefined;
  }> {
    const res = await pgAllocateOutboxRecoveryGeneration(tx, {
      outboxId: params.outboxId,
      episodeId: params.episodeId,
      instanceId: params.instanceId,
      controlEpoch: params.controlEpoch,
      envelopeBytes: params.envelopeBytes,
      envelopeSha256: params.envelopeSha256,
      brokerMessageId: params.brokerMessageId,
      reasonCode: params.reasonCode
    });
    return {
      outcome: res.outcome,
      ...(res.episodeId !== undefined
        ? { episodeId: res.episodeId as PublicationRecoveryEpisodeId }
        : {}),
      ...(res.eventId !== undefined ? { eventId: res.eventId } : {}),
      ...(res.publicationGeneration !== undefined
        ? { publicationGeneration: res.publicationGeneration }
        : {})
    };
  }
}
