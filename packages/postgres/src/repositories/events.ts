import {
  EVENT_STATES,
  parseEventId,
  parseEventTypeId,
  parseProducerId,
  parseProjectId,
  parseTenantId,
  type CanonicalUtcTimestamp,
  type CommandReceiptId,
  type EventId,
  type EventPayloadId,
  type EventState,
  type EventTypeId,
  type OutboxId,
  type PrincipalId,
  type ProducerId,
  type ProjectId,
  type Sha256Hex,
  type TenantId,
  type WireEnvelopeId
} from "@relayquill/domain";
import {
  byteaToSha256Hex,
  readOptionalString,
  readOptionalUtcTimestamp,
  readRequiredInt32,
  readRequiredInt64BigInt,
  readRequiredJsonRecord,
  readRequiredString,
  readRequiredUtcTimestamp,
  readRequiredUuid,
  readRequiredEnum,
  sha256HexToBytea,
  toBytea
} from "../mappers.js";
import { type PgTransactionClient } from "../types.js";
import {
  callJsonbFunction,
  callOptionalJsonbFunction,
  decodeOptionalBase64Field,
  readJsonbInt64BigInt,
  readJsonbTimestamp,
  toOptionalTimestampSqlParam,
  toTimestampSqlParam,
  type BigIntInput,
  type TimestampInput
} from "./_sql.js";

export interface AdmitEventParams {
  readonly tenantId: TenantId;
  readonly projectId: ProjectId;
  readonly actorPrincipalId: PrincipalId;
  readonly producerId: ProducerId;
  readonly producerNamespace: string;
  readonly businessKey: string;
  readonly businessKeySha256: Sha256Hex;
  readonly idempotencyKeySha256: Sha256Hex;
  readonly submittedShapeSha256: Sha256Hex;
  readonly effectiveRequestSha256: Sha256Hex;
  readonly eventTypeId: EventTypeId;
  readonly eventSchemaVersion: number;
  readonly content: Uint8Array | Buffer;
  readonly contentSha256: Sha256Hex;
  readonly wireEnvelopeBytes: Uint8Array | Buffer;
  readonly wireEnvelopeSha256: Sha256Hex;
  readonly brokerEnvelopeBytes: Uint8Array | Buffer;
  readonly brokerEnvelopeSha256: Sha256Hex;
  readonly producerEventTime?: TimestampInput | null | undefined;
  readonly deliveryDeadlineAt: TimestampInput;
  readonly appliedDefaults: Readonly<Record<string, unknown>>;
  readonly retentionPolicyVersion: string;
  readonly eventId: EventId;
  readonly payloadId: EventPayloadId;
  readonly wireEnvelopeId: WireEnvelopeId;
  readonly outboxId: OutboxId;
  readonly receiptId: CommandReceiptId;
  readonly auditId: string;
}

export interface AdmitEventResult {
  readonly outcome: "accepted" | "idempotent_recovery" | "business_anchor_recovery";
  readonly eventId: EventId;
  readonly receiptId?: string | undefined;
  readonly outboxId?: string | undefined;
  readonly projectEventSequence: bigint;
  readonly topologyVersion: bigint;
  readonly candidateCount?: bigint | undefined;
  readonly admittedAt: CanonicalUtcTimestamp;
  readonly deliveryDeadlineAt: CanonicalUtcTimestamp;
  readonly state: EventState;
  readonly appliedDefaults: Record<string, unknown>;
}

export interface ResolveAdmittedEventParams {
  readonly tenantId: TenantId;
  readonly projectId: ProjectId;
  readonly actorPrincipalId: PrincipalId;
  readonly producerNamespace: string;
  readonly businessKeySha256: Sha256Hex;
  readonly idempotencyKeySha256: Sha256Hex;
  readonly submittedShapeSha256: Sha256Hex;
}

export type ResolveAdmittedEventResult =
  | { readonly found: false }
  | {
      readonly found: true;
      readonly eventId: EventId;
      readonly receiptId?: string | undefined;
      readonly projectEventSequence: bigint;
      readonly state: EventState;
      readonly admittedAt: CanonicalUtcTimestamp;
      readonly deliveryDeadlineAt: CanonicalUtcTimestamp;
    };

export interface SafeEventSummary {
  readonly eventId: EventId;
  readonly tenantId: TenantId;
  readonly projectId: ProjectId;
  readonly producerId?: ProducerId | undefined;
  readonly producerNamespace: string;
  readonly eventTypeId: EventTypeId;
  readonly eventSchemaVersion: number;
  readonly contentSha256: Sha256Hex;
  readonly contentByteCount: number;
  readonly topologyVersion: bigint;
  readonly projectEventSequence: bigint;
  readonly state: EventState;
  readonly blockingReason?: string | undefined;
  readonly producerEventTime?: CanonicalUtcTimestamp | undefined;
  readonly admittedAt: CanonicalUtcTimestamp;
  readonly deliveryDeadlineAt: CanonicalUtcTimestamp;
  readonly retiredAt?: CanonicalUtcTimestamp | undefined;
  readonly version?: bigint | undefined;
}

export interface EventPayloadBytesResult {
  readonly eventId: EventId;
  readonly payloadId: string;
  readonly retentionState: string;
  readonly contentSha256: Sha256Hex;
  readonly byteCount: number;
  readonly content?: Buffer | undefined;
}

export interface WireEnvelopeBytesResult {
  readonly wireEnvelopeId: WireEnvelopeId;
  readonly eventId: EventId;
  readonly representationVersion: number;
  readonly retentionState: string;
  readonly bodySha256: Sha256Hex;
  readonly byteCount: number;
  readonly bodyBytes?: Buffer | undefined;
}

export interface EventHistoryRecord {
  readonly eventId: EventId;
  readonly eventSequence: bigint;
  readonly kind: string;
  readonly eventSchemaVersion: number;
  readonly recordedAt: CanonicalUtcTimestamp;
  readonly safeFacts: Record<string, unknown>;
}

export async function admitEvent(
  tx: PgTransactionClient,
  input: AdmitEventParams
): Promise<AdmitEventResult> {
  const data = await callJsonbFunction(
    tx,
    "rq.cmd_event_admit",
    [
      "uuid",
      "uuid",
      "uuid",
      "uuid",
      "text",
      "text",
      "bytea",
      "bytea",
      "bytea",
      "bytea",
      "uuid",
      "integer",
      "bytea",
      "bytea",
      "bytea",
      "bytea",
      "bytea",
      "bytea",
      "timestamptz",
      "timestamptz",
      "jsonb",
      "text",
      "uuid",
      "uuid",
      "uuid",
      "uuid",
      "uuid",
      "uuid"
    ],
    [
      input.tenantId,
      input.projectId,
      input.actorPrincipalId,
      input.producerId,
      input.producerNamespace,
      input.businessKey,
      sha256HexToBytea(input.businessKeySha256, "businessKeySha256"),
      sha256HexToBytea(input.idempotencyKeySha256, "idempotencyKeySha256"),
      sha256HexToBytea(input.submittedShapeSha256, "submittedShapeSha256"),
      sha256HexToBytea(input.effectiveRequestSha256, "effectiveRequestSha256"),
      input.eventTypeId,
      input.eventSchemaVersion,
      toBytea(input.content),
      sha256HexToBytea(input.contentSha256, "contentSha256"),
      toBytea(input.wireEnvelopeBytes),
      sha256HexToBytea(input.wireEnvelopeSha256, "wireEnvelopeSha256"),
      toBytea(input.brokerEnvelopeBytes),
      sha256HexToBytea(input.brokerEnvelopeSha256, "brokerEnvelopeSha256"),
      toOptionalTimestampSqlParam(input.producerEventTime, "producerEventTime"),
      toTimestampSqlParam(input.deliveryDeadlineAt, "deliveryDeadlineAt"),
      JSON.stringify(input.appliedDefaults),
      input.retentionPolicyVersion,
      input.eventId,
      input.payloadId,
      input.wireEnvelopeId,
      input.outboxId,
      input.receiptId,
      input.auditId
    ],
    "rq.cmd_event_admit"
  );

  const outcome = readRequiredEnum(
    data,
    "outcome",
    ["accepted", "idempotent_recovery", "business_anchor_recovery"] as const,
    "rq.cmd_event_admit.outcome"
  );

  return {
    outcome,
    eventId: readRequiredUuid(data, "event_id", parseEventId),
    receiptId:
      data["receipt_id"] === null || data["receipt_id"] === undefined
        ? undefined
        : readRequiredUuid(data, "receipt_id"),
    outboxId:
      data["outbox_id"] === null || data["outbox_id"] === undefined
        ? undefined
        : readRequiredUuid(data, "outbox_id"),
    projectEventSequence: readJsonbInt64BigInt(
      data,
      "project_event_sequence",
      "rq.cmd_event_admit"
    ),
    topologyVersion: readJsonbInt64BigInt(data, "topology_version", "rq.cmd_event_admit"),
    candidateCount:
      data["candidate_count"] === null || data["candidate_count"] === undefined
        ? undefined
        : readJsonbInt64BigInt(data, "candidate_count", "rq.cmd_event_admit"),
    admittedAt: readJsonbTimestamp(data, "admitted_at", "rq.cmd_event_admit"),
    deliveryDeadlineAt: readJsonbTimestamp(data, "delivery_deadline_at", "rq.cmd_event_admit"),
    state: readRequiredEnum(data, "state", EVENT_STATES),
    appliedDefaults: readRequiredJsonRecord(data, "applied_defaults")
  };
}

export async function resolveAdmittedEvent(
  tx: PgTransactionClient,
  input: ResolveAdmittedEventParams
): Promise<ResolveAdmittedEventResult> {
  const data = await callJsonbFunction(
    tx,
    "rq.cmd_event_resolve",
    ["uuid", "uuid", "uuid", "text", "bytea", "bytea", "bytea"],
    [
      input.tenantId,
      input.projectId,
      input.actorPrincipalId,
      input.producerNamespace,
      sha256HexToBytea(input.businessKeySha256, "businessKeySha256"),
      sha256HexToBytea(input.idempotencyKeySha256, "idempotencyKeySha256"),
      sha256HexToBytea(input.submittedShapeSha256, "submittedShapeSha256")
    ],
    "rq.cmd_event_resolve"
  );
  if (data["found"] !== true) {
    return { found: false };
  }
  return {
    found: true,
    eventId: readRequiredUuid(data, "event_id", parseEventId),
    receiptId:
      data["receipt_id"] === null || data["receipt_id"] === undefined
        ? undefined
        : readRequiredUuid(data, "receipt_id"),
    projectEventSequence: readJsonbInt64BigInt(
      data,
      "project_event_sequence",
      "rq.cmd_event_resolve"
    ),
    state: readRequiredEnum(data, "state", EVENT_STATES),
    admittedAt: readJsonbTimestamp(data, "admitted_at", "rq.cmd_event_resolve"),
    deliveryDeadlineAt: readJsonbTimestamp(data, "delivery_deadline_at", "rq.cmd_event_resolve")
  };
}

export async function readEventSafe(
  tx: PgTransactionClient,
  tenantId: TenantId,
  projectId: ProjectId,
  eventId: EventId
): Promise<SafeEventSummary | undefined> {
  const data = await callOptionalJsonbFunction(
    tx,
    "rq.read_event_safe",
    ["uuid", "uuid", "uuid"],
    [tenantId, projectId, eventId],
    "rq.read_event_safe"
  );
  if (data === undefined) {
    return undefined;
  }
  return {
    eventId: readRequiredUuid(data, "event_id", parseEventId),
    tenantId: readRequiredUuid(data, "tenant_id", parseTenantId),
    projectId: readRequiredUuid(data, "project_id", parseProjectId),
    producerNamespace: readRequiredString(data, "producer_namespace"),
    eventTypeId: readRequiredUuid(data, "event_type_id", parseEventTypeId),
    eventSchemaVersion: readRequiredInt32(data, "event_schema_version"),
    contentSha256: byteaToSha256Hex(data["content_sha256"], "content_sha256"),
    contentByteCount: readRequiredInt32(data, "content_byte_count"),
    topologyVersion: readJsonbInt64BigInt(data, "topology_version", "rq.read_event_safe"),
    projectEventSequence: readJsonbInt64BigInt(
      data,
      "project_event_sequence",
      "rq.read_event_safe"
    ),
    state: readRequiredEnum(data, "state", EVENT_STATES),
    admittedAt: readJsonbTimestamp(data, "admitted_at", "rq.read_event_safe"),
    deliveryDeadlineAt: readJsonbTimestamp(data, "delivery_deadline_at", "rq.read_event_safe")
  };
}

export async function readEventPayloadBytes(
  tx: PgTransactionClient,
  tenantId: TenantId,
  projectId: ProjectId,
  eventId: EventId
): Promise<EventPayloadBytesResult | undefined> {
  const data = await callOptionalJsonbFunction(
    tx,
    "rq.read_event_payload_bytes",
    ["uuid", "uuid", "uuid"],
    [tenantId, projectId, eventId],
    "rq.read_event_payload_bytes"
  );
  if (data === undefined) {
    return undefined;
  }
  return {
    eventId: readRequiredUuid(data, "event_id", parseEventId),
    payloadId: readRequiredUuid(data, "payload_id"),
    retentionState: readRequiredString(data, "retention_state"),
    contentSha256: byteaToSha256Hex(data["content_sha256"], "content_sha256"),
    byteCount: readRequiredInt32(data, "byte_count"),
    content: decodeOptionalBase64Field(data, "content_b64", "content_b64")
  };
}

export async function readWireEnvelopeBytes(
  tx: PgTransactionClient,
  tenantId: TenantId,
  projectId: ProjectId,
  wireEnvelopeId: WireEnvelopeId
): Promise<WireEnvelopeBytesResult | undefined> {
  const data = await callOptionalJsonbFunction(
    tx,
    "rq.read_wire_envelope_bytes",
    ["uuid", "uuid", "uuid"],
    [tenantId, projectId, wireEnvelopeId],
    "rq.read_wire_envelope_bytes"
  );
  if (data === undefined) {
    return undefined;
  }
  return {
    wireEnvelopeId: readRequiredUuid(data, "wire_envelope_id"),
    eventId: readRequiredUuid(data, "event_id", parseEventId),
    representationVersion: readRequiredInt32(data, "representation_version"),
    retentionState: readRequiredString(data, "retention_state"),
    bodySha256: byteaToSha256Hex(data["body_sha256"], "body_sha256"),
    byteCount: readRequiredInt32(data, "byte_count"),
    bodyBytes: decodeOptionalBase64Field(data, "body_b64", "body_b64")
  };
}

export async function listProjectSafeEvents(
  tx: PgTransactionClient,
  tenantId: TenantId,
  projectId: ProjectId,
  options?: { readonly limit?: number | undefined; readonly afterSequence?: BigIntInput | undefined }
): Promise<readonly SafeEventSummary[]> {
  const limit = Math.min(200, Math.max(1, Math.trunc(options?.limit ?? 50)));
  const res = await tx.query<Record<string, unknown>>(
    `SELECT id, tenant_id, project_id, producer_id, producer_namespace, event_type_id,
            event_schema_version, content_sha256, content_byte_count, topology_version,
            project_event_sequence, state, blocking_reason, producer_event_time,
            admitted_at, delivery_deadline_at, retired_at, version
       FROM rq.v_safe_events
      WHERE tenant_id = $1::uuid
        AND project_id = $2::uuid
        AND ($3::bigint IS NULL OR project_event_sequence > $3::bigint)
      ORDER BY project_event_sequence ASC
      LIMIT $4::integer`,
    [
      tenantId,
      projectId,
      options?.afterSequence !== undefined
        ? String(readJsonbInt64BigInt({ v: options.afterSequence }, "v", "afterSequence"))
        : null,
      limit
    ]
  );

  return res.rows.map((row) => ({
    eventId: readRequiredUuid(row, "id", parseEventId),
    tenantId: readRequiredUuid(row, "tenant_id", parseTenantId),
    projectId: readRequiredUuid(row, "project_id", parseProjectId),
    producerId: readRequiredUuid(row, "producer_id", parseProducerId),
    producerNamespace: readRequiredString(row, "producer_namespace"),
    eventTypeId: readRequiredUuid(row, "event_type_id", parseEventTypeId),
    eventSchemaVersion: readRequiredInt32(row, "event_schema_version"),
    contentSha256: byteaToSha256Hex(row["content_sha256"], "content_sha256"),
    contentByteCount: readRequiredInt32(row, "content_byte_count"),
    topologyVersion: readRequiredInt64BigInt(row, "topology_version"),
    projectEventSequence: readRequiredInt64BigInt(row, "project_event_sequence"),
    state: readRequiredEnum(row, "state", EVENT_STATES),
    blockingReason: readOptionalString(row, "blocking_reason"),
    producerEventTime: readOptionalUtcTimestamp(row, "producer_event_time"),
    admittedAt: readRequiredUtcTimestamp(row, "admitted_at"),
    deliveryDeadlineAt: readRequiredUtcTimestamp(row, "delivery_deadline_at"),
    retiredAt: readOptionalUtcTimestamp(row, "retired_at"),
    version: readRequiredInt64BigInt(row, "version")
  }));
}

export async function listEventHistory(
  tx: PgTransactionClient,
  tenantId: TenantId,
  projectId: ProjectId,
  eventId: EventId,
  limit = 100
): Promise<readonly EventHistoryRecord[]> {
  const clamped = Math.min(500, Math.max(1, Math.trunc(limit)));
  const res = await tx.query<Record<string, unknown>>(
    `SELECT event_id, event_sequence, event_kind, event_schema_version, recorded_at, safe_facts
       FROM rq.event_history
      WHERE tenant_id = $1::uuid AND project_id = $2::uuid AND event_id = $3::uuid
      ORDER BY event_sequence ASC
      LIMIT $4::integer`,
    [tenantId, projectId, eventId, clamped]
  );
  return res.rows.map((row) => ({
    eventId: readRequiredUuid(row, "event_id", parseEventId),
    eventSequence: readRequiredInt64BigInt(row, "event_sequence"),
    kind: readRequiredString(row, "event_kind"),
    eventSchemaVersion: readRequiredInt32(row, "event_schema_version"),
    recordedAt: readRequiredUtcTimestamp(row, "recorded_at"),
    safeFacts: readRequiredJsonRecord(row, "safe_facts")
  }));
}
