import {
  OUTBOX_STATES,
  parseBrokerGenerationId,
  parseEventId,
  parseOutboxId,
  parseProjectId,
  parseRuntimeInstanceId,
  parseTenantId,
  type BrokerGenerationId,
  type CanonicalUtcTimestamp,
  type ControlEpoch,
  type EventId,
  type OutboxId,
  type OutboxState,
  type ProjectId,
  type PublicationObservationId,
  type PublicationRecoveryEpisodeId,
  type RuntimeInstanceId,
  type Sha256Hex,
  type TenantId
} from "@relayquill/domain";
import {
  byteaToSha256Hex,
  readOptionalString,
  readOptionalUtcTimestamp,
  readRequiredBoolean,
  readRequiredEnum,
  readRequiredInt64BigInt,
  readRequiredString,
  readRequiredUtcTimestamp,
  readRequiredUuid,
  sha256HexToBytea,
  toBytea
} from "../mappers.js";
import { type PgTransactionClient } from "../types.js";
import {
  callJsonbFunction,
  decodeBase64Field,
  readJsonbInt64BigInt,
  readJsonbTimestamp,
  toBigIntSqlParam,
  toOptionalBigIntSqlParam,
  toOptionalTimestampSqlParam,
  type BigIntInput,
  type TimestampInput
} from "./_sql.js";

export interface ClaimOutboxParams {
  readonly outboxId: OutboxId;
  readonly instanceId: RuntimeInstanceId;
  readonly controlEpoch: ControlEpoch;
  readonly claimLeaseMs: BigIntInput;
}

export interface ClaimOutboxResult {
  readonly outboxId: OutboxId;
  readonly eventId: EventId;
  readonly projectId: ProjectId;
  readonly publicationGeneration: bigint;
  readonly claimGeneration: bigint;
  readonly claimExpiresAt: CanonicalUtcTimestamp;
  readonly brokerMessageId: string;
  readonly envelopeBytes: Buffer;
}

export type OutboxObservationOutcome =
  | "published"
  | "publish_unknown"
  | "retry_pending"
  | "blocked";

export interface ObserveOutboxPublicationParams {
  readonly outboxId: OutboxId;
  readonly publicationGeneration: BigIntInput;
  readonly instanceId: RuntimeInstanceId;
  readonly controlEpoch: ControlEpoch;
  readonly expectedClaimGeneration: BigIntInput;
  readonly outcome: OutboxObservationOutcome;
  readonly brokerGenerationId?: BrokerGenerationId | null | undefined;
  readonly streamName?: string | null | undefined;
  readonly streamSequence?: BigIntInput | null | undefined;
  readonly ackDuplicate?: boolean | undefined;
  readonly safeErrorCode?: string | null | undefined;
  readonly nextPublishAt?: TimestampInput | null | undefined;
  readonly observationId: PublicationObservationId;
}

export interface ObserveOutboxPublicationResult {
  readonly acceptedAsCurrent: boolean;
  readonly outboxState: OutboxState;
  readonly publicationState?: string | undefined;
}

export interface AllocateOutboxRecoveryGenerationParams {
  readonly outboxId: OutboxId;
  readonly episodeId: PublicationRecoveryEpisodeId;
  readonly instanceId: RuntimeInstanceId;
  readonly controlEpoch: ControlEpoch;
  readonly envelopeBytes: Uint8Array | Buffer;
  readonly envelopeSha256: Sha256Hex;
  readonly brokerMessageId: string;
  readonly reasonCode: string;
}

export interface AllocateOutboxRecoveryGenerationResult {
  readonly outcome: "already_complete" | "review_required" | "allocated";
  readonly episodeId?: string | undefined;
  readonly eventId?: EventId | undefined;
  readonly publicationGeneration?: bigint | undefined;
}

export interface OutboxEventSummary {
  readonly id: OutboxId;
  readonly eventId: EventId;
  readonly tenantId: TenantId;
  readonly projectId: ProjectId;
  readonly topologyVersion: bigint;
  readonly state: OutboxState;
  readonly currentPublicationGeneration: bigint;
  readonly nextPublishAt: CanonicalUtcTimestamp;
  readonly claimOwnerInstanceId?: string | undefined;
  readonly claimGeneration: bigint;
  readonly claimExpiresAt?: CanonicalUtcTimestamp | undefined;
  readonly lastSafeErrorCode?: string | undefined;
  readonly version: bigint;
}

export async function claimOutboxEvent(
  tx: PgTransactionClient,
  input: ClaimOutboxParams
): Promise<ClaimOutboxResult> {
  const data = await callJsonbFunction(
    tx,
    "rq.cmd_outbox_claim",
    ["uuid", "uuid", "uuid", "bigint"],
    [
      input.outboxId,
      input.instanceId,
      input.controlEpoch,
      toBigIntSqlParam(input.claimLeaseMs, "claimLeaseMs")
    ],
    "rq.cmd_outbox_claim"
  );

  return {
    outboxId: readRequiredUuid(data, "outbox_id", parseOutboxId),
    eventId: readRequiredUuid(data, "event_id", parseEventId),
    projectId: readRequiredUuid(data, "project_id", parseProjectId),
    publicationGeneration: readJsonbInt64BigInt(
      data,
      "publication_generation",
      "rq.cmd_outbox_claim"
    ),
    claimGeneration: readJsonbInt64BigInt(data, "claim_generation", "rq.cmd_outbox_claim"),
    claimExpiresAt: readJsonbTimestamp(data, "claim_expires_at", "rq.cmd_outbox_claim"),
    brokerMessageId: readRequiredString(data, "broker_message_id"),
    envelopeBytes: decodeBase64Field(data, "envelope_bytes_b64", "envelope_bytes_b64")
  };
}

export async function observeOutboxPublication(
  tx: PgTransactionClient,
  input: ObserveOutboxPublicationParams
): Promise<ObserveOutboxPublicationResult> {
  const sqlOutcome =
    input.outcome === "published"
      ? "ack_observed"
      : input.outcome === "retry_pending"
        ? "publish_unknown"
        : input.outcome;
  const data = await callJsonbFunction(
    tx,
    "rq.cmd_outbox_observe",
    [
      "uuid",
      "bigint",
      "uuid",
      "uuid",
      "bigint",
      "text",
      "uuid",
      "text",
      "bigint",
      "boolean",
      "text",
      "timestamptz",
      "uuid"
    ],
    [
      input.outboxId,
      toBigIntSqlParam(input.publicationGeneration, "publicationGeneration"),
      input.instanceId,
      input.controlEpoch,
      toBigIntSqlParam(input.expectedClaimGeneration, "expectedClaimGeneration"),
      sqlOutcome,
      input.brokerGenerationId ?? null,
      input.streamName ?? null,
      toOptionalBigIntSqlParam(input.streamSequence, "streamSequence"),
      input.ackDuplicate ?? false,
      input.safeErrorCode ?? null,
      toOptionalTimestampSqlParam(input.nextPublishAt, "nextPublishAt"),
      input.observationId
    ],
    "rq.cmd_outbox_observe"
  );

  return {
    acceptedAsCurrent: readRequiredBoolean(data, "accepted_as_current"),
    outboxState: readRequiredEnum(data, "outbox_state", OUTBOX_STATES),
    publicationState: readOptionalString(data, "publication_state")
  };
}

export async function allocateOutboxRecoveryGeneration(
  tx: PgTransactionClient,
  input: AllocateOutboxRecoveryGenerationParams
): Promise<AllocateOutboxRecoveryGenerationResult> {
  const data = await callJsonbFunction(
    tx,
    "rq.cmd_outbox_recovery_generation",
    ["uuid", "uuid", "uuid", "uuid", "bytea", "bytea", "text", "text"],
    [
      input.outboxId,
      input.episodeId,
      input.instanceId,
      input.controlEpoch,
      toBytea(input.envelopeBytes),
      sha256HexToBytea(input.envelopeSha256, "envelopeSha256"),
      input.brokerMessageId,
      input.reasonCode
    ],
    "rq.cmd_outbox_recovery_generation"
  );

  const outcome = readRequiredEnum(
    data,
    "outcome",
    ["already_complete", "review_required", "allocated"] as const
  );

  return {
    outcome,
    episodeId:
      data["episode_id"] === undefined || data["episode_id"] === null
        ? undefined
        : readRequiredUuid(data, "episode_id"),
    eventId:
      data["event_id"] === undefined || data["event_id"] === null
        ? undefined
        : readRequiredUuid(data, "event_id", parseEventId),
    publicationGeneration:
      data["publication_generation"] === undefined || data["publication_generation"] === null
        ? undefined
        : readJsonbInt64BigInt(
            data,
            "publication_generation",
            "rq.cmd_outbox_recovery_generation"
          )
  };
}

export async function listDueOutboxEvents(
  tx: PgTransactionClient,
  limit = 64
): Promise<readonly OutboxEventSummary[]> {
  const clamped = Math.min(500, Math.max(1, Math.trunc(limit)));
  const res = await tx.query<Record<string, unknown>>(
    `SELECT id, event_id, tenant_id, project_id, topology_version, state,
            current_publication_generation, next_publish_at, claim_owner_instance_id,
            claim_generation, claim_expires_at, last_safe_error_code, version
       FROM rq.outbox_events
      WHERE state = 'pending'
        AND next_publish_at <= pg_catalog.clock_timestamp()
        AND (claim_expires_at IS NULL OR claim_expires_at <= pg_catalog.clock_timestamp())
      ORDER BY next_publish_at ASC, id ASC
      LIMIT $1::integer`,
    [clamped]
  );

  return res.rows.map((row) => ({
    id: readRequiredUuid(row, "id", parseOutboxId),
    eventId: readRequiredUuid(row, "event_id", parseEventId),
    tenantId: readRequiredUuid(row, "tenant_id", parseTenantId),
    projectId: readRequiredUuid(row, "project_id", parseProjectId),
    topologyVersion: readRequiredInt64BigInt(row, "topology_version"),
    state: readRequiredEnum(row, "state", OUTBOX_STATES),
    currentPublicationGeneration: readRequiredInt64BigInt(row, "current_publication_generation"),
    nextPublishAt: readRequiredUtcTimestamp(row, "next_publish_at"),
    claimOwnerInstanceId:
      row["claim_owner_instance_id"] === null || row["claim_owner_instance_id"] === undefined
        ? undefined
        : readRequiredUuid(row, "claim_owner_instance_id", parseRuntimeInstanceId),
    claimGeneration: readRequiredInt64BigInt(row, "claim_generation"),
    claimExpiresAt: readOptionalUtcTimestamp(row, "claim_expires_at"),
    lastSafeErrorCode: readOptionalString(row, "last_safe_error_code"),
    version: readRequiredInt64BigInt(row, "version")
  }));
}

export async function listOutboxPublications(
  tx: PgTransactionClient,
  outboxId: OutboxId
): Promise<
  readonly {
    readonly publicationGeneration: bigint;
    readonly envelopeSha256: Sha256Hex;
    readonly brokerMessageId: string;
    readonly state: string;
    readonly streamName?: string | undefined;
    readonly streamSequence?: bigint | undefined;
    readonly firstBrokerGenerationId?: BrokerGenerationId | undefined;
  }[]
> {
  const res = await tx.query<Record<string, unknown>>(
    `SELECT publication_generation, envelope_sha256, broker_message_id, state,
            stream_name, stream_sequence, first_broker_generation_id
       FROM rq.outbox_publications
      WHERE outbox_id = $1::uuid
      ORDER BY publication_generation ASC`,
    [outboxId]
  );

  return res.rows.map((row) => ({
    publicationGeneration: readRequiredInt64BigInt(row, "publication_generation"),
    envelopeSha256: byteaToSha256Hex(row["envelope_sha256"], "envelope_sha256"),
    brokerMessageId: readRequiredString(row, "broker_message_id"),
    state: readRequiredString(row, "state"),
    streamName: readOptionalString(row, "stream_name"),
    streamSequence:
      row["stream_sequence"] === null || row["stream_sequence"] === undefined
        ? undefined
        : readRequiredInt64BigInt(row, "stream_sequence"),
    firstBrokerGenerationId:
      row["first_broker_generation_id"] === null ||
      row["first_broker_generation_id"] === undefined
        ? undefined
        : readRequiredUuid(row, "first_broker_generation_id", parseBrokerGenerationId)
  }));
}
