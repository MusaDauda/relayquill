import { type EventId, type ProjectId, type TenantId } from "@relayquill/domain";
import { readRequiredInt64BigInt } from "../mappers.js";
import { type PgTransactionClient } from "../types.js";
import {
  listDeliveryAttempts,
  listProjectSafeDeliveries,
  type SafeDeliverySummary
} from "./deliveries.js";
import {
  listEventHistory,
  readEventSafe,
  type EventHistoryRecord,
  type SafeEventSummary
} from "./events.js";
import { findEventFanoutState, type EventFanoutStateRecord } from "./inbox.js";
import {
  readEventDeliveryTotals,
  type EventDeliveryTotalsResult
} from "./projections.js";

const MAX_DIAGNOSTIC_LIMIT = 200 as const;

export interface EventCausalChainDiagnostic {
  readonly event?: SafeEventSummary | undefined;
  readonly totals?: EventDeliveryTotalsResult | undefined;
  readonly fanout?: EventFanoutStateRecord | undefined;
  readonly history: readonly EventHistoryRecord[];
  readonly deliveries: readonly SafeDeliverySummary[];
  readonly attemptsByDeliveryId: ReadonlyMap<
    string,
    Awaited<ReturnType<typeof listDeliveryAttempts>>
  >;
}

export interface ProjectQueueHealthDiagnostic {
  readonly pendingOutboxCount: bigint;
  readonly activeFanoutCount: bigint;
  readonly readyDeliveryCount: bigint;
  readonly sendingDeliveryCount: bigint;
  readonly retryWaitDeliveryCount: bigint;
  readonly openHoldCount: bigint;
}

/**
 * Reads a bounded causal chain for an event without ever exposing raw payload, envelope,
 * signing key, or credential bytes.
 */
export async function readEventCausalChain(
  tx: PgTransactionClient,
  tenantId: TenantId,
  projectId: ProjectId,
  eventId: EventId,
  limit = 50
): Promise<EventCausalChainDiagnostic> {
  const boundedLimit = Math.min(MAX_DIAGNOSTIC_LIMIT, Math.max(1, Math.trunc(limit)));
  const event = await readEventSafe(tx, tenantId, projectId, eventId);
  if (event === undefined) {
    return {
      history: [],
      deliveries: [],
      attemptsByDeliveryId: new Map()
    };
  }

  const [totals, fanout, history, allProjectDeliveries] = await Promise.all([
    readEventDeliveryTotals(tx, tenantId, projectId, eventId),
    findEventFanoutState(tx, eventId),
    listEventHistory(tx, tenantId, projectId, eventId, boundedLimit),
    listProjectSafeDeliveries(tx, tenantId, projectId, boundedLimit)
  ]);

  const deliveries = allProjectDeliveries.filter((d) => d.eventId === eventId);
  const attemptsByDeliveryId = new Map<string, Awaited<ReturnType<typeof listDeliveryAttempts>>>();
  for (const delivery of deliveries) {
    const attempts = await listDeliveryAttempts(tx, tenantId, projectId, delivery.deliveryId);
    attemptsByDeliveryId.set(delivery.deliveryId, attempts);
  }

  return {
    event,
    totals,
    fanout,
    history,
    deliveries,
    attemptsByDeliveryId
  };
}

export async function readProjectQueueHealth(
  tx: PgTransactionClient,
  tenantId: TenantId,
  projectId: ProjectId
): Promise<ProjectQueueHealthDiagnostic> {
  const res = await tx.query<Record<string, unknown>>(
    `SELECT
       (SELECT pg_catalog.count(*)::bigint FROM rq.outbox_events o WHERE o.tenant_id = $1::uuid AND o.project_id = $2::uuid AND o.state = 'pending') AS pending_outbox_count,
       (SELECT pg_catalog.count(*)::bigint FROM rq.event_fanout f WHERE f.tenant_id = $1::uuid AND f.project_id = $2::uuid AND f.state IN ('pending', 'in_progress')) AS active_fanout_count,
       (SELECT pg_catalog.count(*)::bigint FROM rq.v_safe_deliveries d WHERE d.tenant_id = $1::uuid AND d.project_id = $2::uuid AND d.state = 'ready') AS ready_delivery_count,
       (SELECT pg_catalog.count(*)::bigint FROM rq.v_safe_deliveries d WHERE d.tenant_id = $1::uuid AND d.project_id = $2::uuid AND d.state = 'sending') AS sending_delivery_count,
       (SELECT pg_catalog.count(*)::bigint FROM rq.v_safe_deliveries d WHERE d.tenant_id = $1::uuid AND d.project_id = $2::uuid AND d.state = 'retry_wait') AS retry_wait_delivery_count,
       (SELECT pg_catalog.count(*)::bigint FROM rq.retention_holds h WHERE h.tenant_id = $1::uuid AND (h.project_id IS NULL OR h.project_id = $2::uuid) AND h.state = 'active') AS open_hold_count`,
    [tenantId, projectId]
  );

  const row = res.rows[0] ?? {};
  return {
    pendingOutboxCount: readRequiredInt64BigInt(row, "pending_outbox_count"),
    activeFanoutCount: readRequiredInt64BigInt(row, "active_fanout_count"),
    readyDeliveryCount: readRequiredInt64BigInt(row, "ready_delivery_count"),
    sendingDeliveryCount: readRequiredInt64BigInt(row, "sending_delivery_count"),
    retryWaitDeliveryCount: readRequiredInt64BigInt(row, "retry_wait_delivery_count"),
    openHoldCount: readRequiredInt64BigInt(row, "open_hold_count")
  };
}
