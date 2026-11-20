import {
  BROKER_INBOX_STATES,
  EVENT_FANOUT_STATES,
  parseBrokerInboxId,
  parseEventId,
  parseEventTypeId,
  parseProjectId,
  parseSubscriptionId,
  parseTenantId,
  type BrokerGenerationId,
  type BrokerInboxId,
  type BrokerInboxState,
  type CanonicalUtcTimestamp,
  type ControlEpoch,
  type EventFanoutState,
  type EventId,
  type EventTypeId,
  type OutboxId,
  type ProjectId,
  type RuntimeInstanceId,
  type Sha256Hex,
  type SubscriptionId,
  type TenantId
} from "@relayquill/domain";
import {
  byteaToSha256Hex,
  readOptionalString,
  readOptionalUtcTimestamp,
  readOptionalUuid,
  readRequiredBoolean,
  readRequiredEnum,
  readRequiredInt64BigInt,
  readRequiredJsonRecord,
  readRequiredUuid,
  sha256HexToBytea
} from "../mappers.js";
import { type PgTransactionClient } from "../types.js";
import {
  callJsonbFunction,
  readJsonbInt64BigInt,
  readJsonbTimestamp,
  toBigIntSqlParam,
  type BigIntInput
} from "./_sql.js";

export interface AcceptBrokerInboxParams {
  readonly outboxId: OutboxId;
  readonly publicationGeneration: BigIntInput;
  readonly eventId: EventId;
  readonly projectId: ProjectId;
  readonly topologyVersion: BigIntInput;
  readonly envelopeSha256: Sha256Hex;
  readonly brokerGenerationId: BrokerGenerationId;
  readonly streamSequence: BigIntInput;
  readonly inboxId: BrokerInboxId;
  readonly instanceId: RuntimeInstanceId;
  readonly controlEpoch: ControlEpoch;
}

export interface AcceptBrokerInboxResult {
  readonly inboxId: BrokerInboxId;
  readonly inboxState: BrokerInboxState;
  readonly fanoutState: EventFanoutState;
  readonly projectEventSequence: bigint;
  readonly materializedThroughEventSequence: bigint;
  readonly isNextContiguous: boolean;
}

export interface ClaimEventFanoutParams {
  readonly eventId: EventId;
  readonly instanceId: RuntimeInstanceId;
  readonly controlEpoch: ControlEpoch;
  readonly claimLeaseMs: BigIntInput;
}

export type ClaimEventFanoutResult =
  | { readonly outcome: "already_complete"; readonly eventId: EventId }
  | {
      readonly outcome: "claimed";
      readonly eventId: EventId;
      readonly topologyVersion: bigint;
      readonly subscriptionCursor?: SubscriptionId | undefined;
      readonly claimGeneration: bigint;
      readonly claimExpiresAt: CanonicalUtcTimestamp;
      readonly candidateCount: bigint;
      readonly examinedCount: bigint;
    };

export interface FanoutOutcomeItem {
  readonly subscription_id: SubscriptionId;
  readonly subscription_version: string;
  readonly outcome: "matched" | "filtered_out" | "blocked" | "failed";
  readonly filter_profile_version?: string | undefined;
  readonly filter_sha256?: Sha256Hex | undefined;
  readonly delivery_id?: string | undefined;
  readonly family_id?: string | undefined;
  readonly endpoint_id?: string | undefined;
  readonly endpoint_version?: string | undefined;
  readonly wire_envelope_id?: string | undefined;
  readonly consumer_contract_scope?: string | undefined;
  readonly consumer_event_key_sha256?: Sha256Hex | undefined;
  readonly ordering_key_sha256?: Sha256Hex | undefined;
  readonly maximum_attempts?: number | undefined;
  readonly safe_reason_code?: string | undefined;
}

export interface CommitFanoutPageParams {
  readonly eventId: EventId;
  readonly instanceId: RuntimeInstanceId;
  readonly controlEpoch: ControlEpoch;
  readonly expectedClaimGeneration: BigIntInput;
  readonly nextCursor?: SubscriptionId | null | undefined;
  readonly complete: boolean;
  readonly outcomes: readonly FanoutOutcomeItem[];
}

export interface CommitFanoutPageResult {
  readonly outcome: "already_complete" | "completed" | "page_committed";
  readonly eventId: EventId;
  readonly newExamined?: bigint | undefined;
  readonly newDeliveries?: bigint | undefined;
}

export interface EventFanoutStateRecord {
  readonly eventId: EventId;
  readonly tenantId: TenantId;
  readonly projectId: ProjectId;
  readonly topologyVersion: bigint;
  readonly projectEventSequence: bigint;
  readonly state: EventFanoutState;
  readonly candidateCount: bigint;
  readonly examinedCount: bigint;
  readonly matchedCount: bigint;
  readonly deliveryCount: bigint;
  readonly subscriptionCursor?: SubscriptionId | undefined;
  readonly claimGeneration: bigint;
  readonly claimExpiresAt?: CanonicalUtcTimestamp | undefined;
  readonly completedAt?: CanonicalUtcTimestamp | undefined;
  readonly version: bigint;
}

export async function acceptBrokerInbox(
  tx: PgTransactionClient,
  input: AcceptBrokerInboxParams
): Promise<AcceptBrokerInboxResult> {
  const data = await callJsonbFunction(
    tx,
    "rq.cmd_inbox_accept",
    [
      "uuid",
      "bigint",
      "uuid",
      "uuid",
      "bigint",
      "bytea",
      "uuid",
      "bigint",
      "uuid",
      "uuid",
      "uuid"
    ],
    [
      input.outboxId,
      toBigIntSqlParam(input.publicationGeneration, "publicationGeneration"),
      input.eventId,
      input.projectId,
      toBigIntSqlParam(input.topologyVersion, "topologyVersion"),
      sha256HexToBytea(input.envelopeSha256, "envelopeSha256"),
      input.brokerGenerationId,
      toBigIntSqlParam(input.streamSequence, "streamSequence"),
      input.inboxId,
      input.instanceId,
      input.controlEpoch
    ],
    "rq.cmd_inbox_accept"
  );

  return {
    inboxId: readRequiredUuid(data, "inbox_id", parseBrokerInboxId),
    inboxState: readRequiredEnum(data, "inbox_state", BROKER_INBOX_STATES),
    fanoutState: readRequiredEnum(data, "fanout_state", EVENT_FANOUT_STATES),
    projectEventSequence: readJsonbInt64BigInt(
      data,
      "project_event_sequence",
      "rq.cmd_inbox_accept"
    ),
    materializedThroughEventSequence: readJsonbInt64BigInt(
      data,
      "materialized_through_event_sequence",
      "rq.cmd_inbox_accept"
    ),
    isNextContiguous: readRequiredBoolean(data, "is_next_contiguous")
  };
}

export async function claimEventFanout(
  tx: PgTransactionClient,
  input: ClaimEventFanoutParams
): Promise<ClaimEventFanoutResult> {
  const data = await callJsonbFunction(
    tx,
    "rq.cmd_fanout_claim",
    ["uuid", "uuid", "uuid", "bigint"],
    [
      input.eventId,
      input.instanceId,
      input.controlEpoch,
      toBigIntSqlParam(input.claimLeaseMs, "claimLeaseMs")
    ],
    "rq.cmd_fanout_claim"
  );

  const outcome = readRequiredEnum(data, "outcome", ["already_complete", "claimed"] as const);
  const eventId = readRequiredUuid(data, "event_id", parseEventId);
  if (outcome === "already_complete") {
    return { outcome: "already_complete", eventId };
  }

  return {
    outcome: "claimed",
    eventId,
    topologyVersion: readJsonbInt64BigInt(data, "topology_version", "rq.cmd_fanout_claim"),
    subscriptionCursor: readOptionalUuid(data, "subscription_cursor", parseSubscriptionId),
    claimGeneration: readJsonbInt64BigInt(data, "claim_generation", "rq.cmd_fanout_claim"),
    claimExpiresAt: readJsonbTimestamp(data, "claim_expires_at", "rq.cmd_fanout_claim"),
    candidateCount: readJsonbInt64BigInt(data, "candidate_count", "rq.cmd_fanout_claim"),
    examinedCount: readJsonbInt64BigInt(data, "examined_count", "rq.cmd_fanout_claim")
  };
}

export async function commitFanoutPage(
  tx: PgTransactionClient,
  input: CommitFanoutPageParams
): Promise<CommitFanoutPageResult> {
  const data = await callJsonbFunction(
    tx,
    "rq.cmd_fanout_page",
    ["uuid", "uuid", "uuid", "bigint", "uuid", "boolean", "jsonb"],
    [
      input.eventId,
      input.instanceId,
      input.controlEpoch,
      toBigIntSqlParam(input.expectedClaimGeneration, "expectedClaimGeneration"),
      input.nextCursor ?? null,
      input.complete,
      JSON.stringify(input.outcomes)
    ],
    "rq.cmd_fanout_page"
  );

  const outcome = readRequiredEnum(
    data,
    "outcome",
    ["already_complete", "completed", "page_committed"] as const
  );
  const eventId = readRequiredUuid(data, "event_id", parseEventId);
  if (outcome === "already_complete") {
    return { outcome: "already_complete", eventId };
  }
  return {
    outcome,
    eventId,
    newExamined: readJsonbInt64BigInt(data, "new_examined", "rq.cmd_fanout_page"),
    newDeliveries: readJsonbInt64BigInt(data, "new_deliveries", "rq.cmd_fanout_page")
  };
}

export async function findEventFanoutState(
  tx: PgTransactionClient,
  eventId: EventId
): Promise<EventFanoutStateRecord | undefined> {
  const res = await tx.query<Record<string, unknown>>(
    `SELECT event_id, tenant_id, project_id, topology_version, project_event_sequence,
            state, candidate_count, examined_count, matched_count, delivery_count,
            subscription_cursor, claim_generation, claim_expires_at, completed_at, version
       FROM rq.event_fanout
      WHERE event_id = $1::uuid`,
    [eventId]
  );
  const row = res.rows[0];
  if (row === undefined) {
    return undefined;
  }
  return {
    eventId: readRequiredUuid(row, "event_id", parseEventId),
    tenantId: readRequiredUuid(row, "tenant_id", parseTenantId),
    projectId: readRequiredUuid(row, "project_id", parseProjectId),
    topologyVersion: readRequiredInt64BigInt(row, "topology_version"),
    projectEventSequence: readRequiredInt64BigInt(row, "project_event_sequence"),
    state: readRequiredEnum(row, "state", EVENT_FANOUT_STATES),
    candidateCount: readRequiredInt64BigInt(row, "candidate_count"),
    examinedCount: readRequiredInt64BigInt(row, "examined_count"),
    matchedCount: readRequiredInt64BigInt(row, "matched_count"),
    deliveryCount: readRequiredInt64BigInt(row, "delivery_count"),
    subscriptionCursor: readOptionalUuid(row, "subscription_cursor", parseSubscriptionId),
    claimGeneration: readRequiredInt64BigInt(row, "claim_generation"),
    claimExpiresAt: readOptionalUtcTimestamp(row, "claim_expires_at"),
    completedAt: readOptionalUtcTimestamp(row, "completed_at"),
    version: readRequiredInt64BigInt(row, "version")
  };
}

export async function listActiveSubscriptionsForTopology(
  tx: PgTransactionClient,
  params: {
    readonly tenantId: TenantId;
    readonly projectId: ProjectId;
    readonly eventTypeId: EventTypeId;
    readonly schemaVersion: number;
    readonly topologyVersion: BigIntInput;
    readonly afterSubscriptionId?: SubscriptionId | undefined;
    readonly limit?: number | undefined;
  }
): Promise<
  readonly {
    readonly subscriptionId: SubscriptionId;
    readonly subscriptionVersion: bigint;
    readonly endpointId: string;
    readonly endpointVersion: bigint;
    readonly eventTypeId: EventTypeId;
    readonly filterProfileVersion: string;
    readonly filterAst: Record<string, unknown>;
    readonly filterSha256: Sha256Hex;
    readonly orderingMode: string;
    readonly consumerContractScope: string;
    readonly retryPolicyVersion: string;
  }[]
> {
  const limit = Math.min(200, Math.max(1, Math.trunc(params.limit ?? 100)));
  const res = await tx.query<Record<string, unknown>>(
    `SELECT sv.subscription_id, sv.subscription_version, sv.endpoint_id, sv.endpoint_version,
            sv.event_type_id, sv.filter_profile_version, sv.filter_ast, sv.filter_sha256,
            sv.ordering_mode, sv.consumer_contract_scope, sv.retry_policy_version
       FROM rq.subscription_topology_ranges tr
       JOIN rq.subscription_versions sv
         ON sv.subscription_id = tr.subscription_id
        AND sv.subscription_version = tr.subscription_version
       JOIN rq.subscription_schema_versions ssv
         ON ssv.subscription_id = sv.subscription_id
        AND ssv.subscription_version = sv.subscription_version
      WHERE tr.tenant_id = $1::uuid
        AND tr.project_id = $2::uuid
        AND sv.event_type_id = $3::uuid
        AND ssv.event_schema_version = $4::integer
        AND tr.from_topology_version <= $5::bigint
        AND (tr.until_topology_version IS NULL OR tr.until_topology_version > $5::bigint)
        AND ($6::uuid IS NULL OR sv.subscription_id > $6::uuid)
      ORDER BY sv.subscription_id ASC
      LIMIT $7::integer`,
    [
      params.tenantId,
      params.projectId,
      params.eventTypeId,
      params.schemaVersion,
      toBigIntSqlParam(params.topologyVersion, "topologyVersion"),
      params.afterSubscriptionId ?? null,
      limit
    ]
  );

  return res.rows.map((row) => ({
    subscriptionId: readRequiredUuid(row, "subscription_id", parseSubscriptionId),
    subscriptionVersion: readRequiredInt64BigInt(row, "subscription_version"),
    endpointId: readRequiredUuid(row, "endpoint_id"),
    endpointVersion: readRequiredInt64BigInt(row, "endpoint_version"),
    eventTypeId: readRequiredUuid(row, "event_type_id", parseEventTypeId),
    filterProfileVersion: readOptionalString(row, "filter_profile_version") ?? "filter.v1",
    filterAst: readRequiredJsonRecord(row, "filter_ast"),
    filterSha256: byteaToSha256Hex(row["filter_sha256"], "filter_sha256"),
    orderingMode: readOptionalString(row, "ordering_mode") ?? "unordered",
    consumerContractScope: readOptionalString(row, "consumer_contract_scope") ?? "default",
    retryPolicyVersion: readOptionalString(row, "retry_policy_version") ?? "default"
  }));
}
