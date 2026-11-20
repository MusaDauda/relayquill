import {
  parseEventId,
  parseProjectId,
  parseTenantId,
  type CanonicalUtcTimestamp,
  type EventId,
  type ProjectId,
  type TenantId
} from "@relayquill/domain";
import {
  readOptionalUtcTimestamp,
  readOptionalUuid,
  readRequiredInt32,
  readRequiredInt64BigInt,
  readRequiredUuid
} from "../mappers.js";
import { type PgTransactionClient } from "../types.js";
import {
  callJsonbFunction,
  readJsonbInt64BigInt,
  readJsonbOptionalTimestamp,
  readJsonbTimestamp
} from "./_sql.js";

export const DELIVERY_DELTA_SHARD_COUNT = 16 as const;

export interface ProjectDeliveryTotalsResult {
  readonly projectId: ProjectId;
  readonly tenantId: TenantId;
  readonly totalDeliveries: bigint;
  readonly pendingCount: bigint;
  readonly activeCount: bigint;
  readonly acknowledgedCount: bigint;
  readonly deadLetterCount: bigint;
  readonly suppressedCount: bigint;
  readonly expiredCount: bigint;
  readonly unknownAttemptObservations: bigint;
  readonly version: bigint;
}

export interface EventDeliveryTotalsResult {
  readonly eventId: EventId;
  readonly projectId: ProjectId;
  readonly tenantId: TenantId;
  readonly totalDeliveries: bigint;
  readonly terminalDeliveries: bigint;
  readonly acknowledgedDeliveries: bigint;
  readonly lastOutcomeAt?: CanonicalUtcTimestamp | undefined;
  readonly version: bigint;
}

export interface EventDeliveryDeltaShardRow {
  readonly eventId: EventId;
  readonly shardId: number;
  readonly totalDeliveriesDelta: bigint;
  readonly terminalDeliveriesDelta: bigint;
  readonly acknowledgedDeliveriesDelta: bigint;
  readonly lastOutcomeAt?: CanonicalUtcTimestamp | undefined;
  readonly version: bigint;
}

export interface ProjectDeliveryDeltaShardRow {
  readonly projectId: ProjectId;
  readonly shardId: number;
  readonly totalDeliveriesDelta: bigint;
  readonly pendingDelta: bigint;
  readonly activeDelta: bigint;
  readonly acknowledgedDelta: bigint;
  readonly deadLetterDelta: bigint;
  readonly suppressedDelta: bigint;
  readonly expiredDelta: bigint;
  readonly unknownAttemptObservationsDelta: bigint;
  readonly version: bigint;
}

export interface CompactDeliveryDeltasResult {
  readonly compactedAt: CanonicalUtcTimestamp;
  readonly projectId: ProjectId;
  readonly eventId?: EventId | undefined;
}

export async function readProjectDeliveryTotals(
  tx: PgTransactionClient,
  tenantId: TenantId,
  projectId: ProjectId
): Promise<ProjectDeliveryTotalsResult> {
  const data = await callJsonbFunction(
    tx,
    "rq.read_project_delivery_totals",
    ["uuid", "uuid"],
    [tenantId, projectId],
    "rq.read_project_delivery_totals"
  );
  return {
    projectId: readRequiredUuid(data, "project_id", parseProjectId),
    tenantId: readRequiredUuid(data, "tenant_id", parseTenantId),
    totalDeliveries: readJsonbInt64BigInt(data, "total_deliveries", "read_project_delivery_totals"),
    pendingCount: readJsonbInt64BigInt(data, "pending_count", "read_project_delivery_totals"),
    activeCount: readJsonbInt64BigInt(data, "active_count", "read_project_delivery_totals"),
    acknowledgedCount: readJsonbInt64BigInt(
      data,
      "acknowledged_count",
      "read_project_delivery_totals"
    ),
    deadLetterCount: readJsonbInt64BigInt(
      data,
      "dead_letter_count",
      "read_project_delivery_totals"
    ),
    suppressedCount: readJsonbInt64BigInt(data, "suppressed_count", "read_project_delivery_totals"),
    expiredCount: readJsonbInt64BigInt(data, "expired_count", "read_project_delivery_totals"),
    unknownAttemptObservations: readJsonbInt64BigInt(
      data,
      "unknown_attempt_observations",
      "read_project_delivery_totals"
    ),
    version: readJsonbInt64BigInt(data, "version", "read_project_delivery_totals")
  };
}

export async function readEventDeliveryTotals(
  tx: PgTransactionClient,
  tenantId: TenantId,
  projectId: ProjectId,
  eventId: EventId
): Promise<EventDeliveryTotalsResult> {
  const data = await callJsonbFunction(
    tx,
    "rq.read_event_delivery_totals",
    ["uuid", "uuid", "uuid"],
    [tenantId, projectId, eventId],
    "rq.read_event_delivery_totals"
  );
  return {
    eventId: readRequiredUuid(data, "event_id", parseEventId),
    projectId: readRequiredUuid(data, "project_id", parseProjectId),
    tenantId: readRequiredUuid(data, "tenant_id", parseTenantId),
    totalDeliveries: readJsonbInt64BigInt(data, "total_deliveries", "read_event_delivery_totals"),
    terminalDeliveries: readJsonbInt64BigInt(
      data,
      "terminal_deliveries",
      "read_event_delivery_totals"
    ),
    acknowledgedDeliveries: readJsonbInt64BigInt(
      data,
      "acknowledged_deliveries",
      "read_event_delivery_totals"
    ),
    lastOutcomeAt: readJsonbOptionalTimestamp(
      data,
      "last_outcome_at",
      "read_event_delivery_totals"
    ),
    version: readJsonbInt64BigInt(data, "version", "read_event_delivery_totals")
  };
}

export async function compactDeliveryTotalDeltas(
  tx: PgTransactionClient,
  input: {
    readonly tenantId: TenantId;
    readonly projectId: ProjectId;
    readonly eventId?: EventId | null | undefined;
  }
): Promise<CompactDeliveryDeltasResult> {
  const data = await callJsonbFunction(
    tx,
    "rq.cmd_compact_delivery_total_deltas",
    ["uuid", "uuid", "uuid"],
    [input.tenantId, input.projectId, input.eventId ?? null],
    "rq.cmd_compact_delivery_total_deltas"
  );
  return {
    compactedAt: readJsonbTimestamp(data, "compacted_at", "rq.cmd_compact_delivery_total_deltas"),
    projectId: readRequiredUuid(data, "project_id", parseProjectId),
    eventId: readOptionalUuid(data, "event_id", parseEventId)
  };
}

/**
 * Reads all non-zero sharded delta rows (0..15) for an event from `rq.event_delivery_total_deltas`
 * and computes exact aggregated bigint totals without locking the base event projection row.
 */
export async function readEventDeliveryDeltaShards(
  tx: PgTransactionClient,
  tenantId: TenantId,
  projectId: ProjectId,
  eventId: EventId
): Promise<{
  readonly shards: readonly EventDeliveryDeltaShardRow[];
  readonly aggregated: {
    readonly totalDeliveriesDelta: bigint;
    readonly terminalDeliveriesDelta: bigint;
    readonly acknowledgedDeliveriesDelta: bigint;
  };
}> {
  const res = await tx.query<Record<string, unknown>>(
    `SELECT event_id, shard_id, total_deliveries_delta, terminal_deliveries_delta,
            acknowledged_deliveries_delta, last_outcome_at, version
       FROM rq.event_delivery_total_deltas
      WHERE tenant_id = $1::uuid AND project_id = $2::uuid AND event_id = $3::uuid
      ORDER BY shard_id ASC`,
    [tenantId, projectId, eventId]
  );

  let totalDeliveriesDelta = 0n;
  let terminalDeliveriesDelta = 0n;
  let acknowledgedDeliveriesDelta = 0n;

  const shards: EventDeliveryDeltaShardRow[] = res.rows.map((row) => {
    const tot = readRequiredInt64BigInt(row, "total_deliveries_delta");
    const term = readRequiredInt64BigInt(row, "terminal_deliveries_delta");
    const ack = readRequiredInt64BigInt(row, "acknowledged_deliveries_delta");
    totalDeliveriesDelta += tot;
    terminalDeliveriesDelta += term;
    acknowledgedDeliveriesDelta += ack;
    return {
      eventId: readRequiredUuid(row, "event_id", parseEventId),
      shardId: readRequiredInt32(row, "shard_id"),
      totalDeliveriesDelta: tot,
      terminalDeliveriesDelta: term,
      acknowledgedDeliveriesDelta: ack,
      lastOutcomeAt: readOptionalUtcTimestamp(row, "last_outcome_at"),
      version: readRequiredInt64BigInt(row, "version")
    };
  });

  return {
    shards,
    aggregated: {
      totalDeliveriesDelta,
      terminalDeliveriesDelta,
      acknowledgedDeliveriesDelta
    }
  };
}

/**
 * Reads all 16-shard delta rows for a project from `rq.project_delivery_total_deltas`
 * and computes exact aggregated bigint totals.
 */
export async function readProjectDeliveryDeltaShards(
  tx: PgTransactionClient,
  tenantId: TenantId,
  projectId: ProjectId
): Promise<{
  readonly shards: readonly ProjectDeliveryDeltaShardRow[];
  readonly aggregated: {
    readonly totalDeliveriesDelta: bigint;
    readonly pendingDelta: bigint;
    readonly activeDelta: bigint;
    readonly acknowledgedDelta: bigint;
    readonly deadLetterDelta: bigint;
    readonly suppressedDelta: bigint;
    readonly expiredDelta: bigint;
    readonly unknownAttemptObservationsDelta: bigint;
  };
}> {
  const res = await tx.query<Record<string, unknown>>(
    `SELECT project_id, shard_id, total_deliveries_delta, pending_delta, active_delta,
            acknowledged_delta, dead_letter_delta, suppressed_delta, expired_delta,
            unknown_attempt_observations_delta, version
       FROM rq.project_delivery_total_deltas
      WHERE tenant_id = $1::uuid AND project_id = $2::uuid
      ORDER BY shard_id ASC`,
    [tenantId, projectId]
  );

  let totalDeliveriesDelta = 0n;
  let pendingDelta = 0n;
  let activeDelta = 0n;
  let acknowledgedDelta = 0n;
  let deadLetterDelta = 0n;
  let suppressedDelta = 0n;
  let expiredDelta = 0n;
  let unknownAttemptObservationsDelta = 0n;

  const shards: ProjectDeliveryDeltaShardRow[] = res.rows.map((row) => {
    const tot = readRequiredInt64BigInt(row, "total_deliveries_delta");
    const pend = readRequiredInt64BigInt(row, "pending_delta");
    const act = readRequiredInt64BigInt(row, "active_delta");
    const ack = readRequiredInt64BigInt(row, "acknowledged_delta");
    const dlq = readRequiredInt64BigInt(row, "dead_letter_delta");
    const sup = readRequiredInt64BigInt(row, "suppressed_delta");
    const exp = readRequiredInt64BigInt(row, "expired_delta");
    const unk = readRequiredInt64BigInt(row, "unknown_attempt_observations_delta");
    totalDeliveriesDelta += tot;
    pendingDelta += pend;
    activeDelta += act;
    acknowledgedDelta += ack;
    deadLetterDelta += dlq;
    suppressedDelta += sup;
    expiredDelta += exp;
    unknownAttemptObservationsDelta += unk;
    return {
      projectId: readRequiredUuid(row, "project_id", parseProjectId),
      shardId: readRequiredInt32(row, "shard_id"),
      totalDeliveriesDelta: tot,
      pendingDelta: pend,
      activeDelta: act,
      acknowledgedDelta: ack,
      deadLetterDelta: dlq,
      suppressedDelta: sup,
      expiredDelta: exp,
      unknownAttemptObservationsDelta: unk,
      version: readRequiredInt64BigInt(row, "version")
    };
  });

  return {
    shards,
    aggregated: {
      totalDeliveriesDelta,
      pendingDelta,
      activeDelta,
      acknowledgedDelta,
      deadLetterDelta,
      suppressedDelta,
      expiredDelta,
      unknownAttemptObservationsDelta
    }
  };
}
