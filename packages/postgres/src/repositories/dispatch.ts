import {
  parseDeliveryId,
  parseEndpointId,
  parseProjectId,
  parseTenantId,
  type CanonicalUtcTimestamp,
  type DeliveryId,
  type EndpointId,
  type ProjectId,
  type TenantId
} from "@relayquill/domain";
import {
  readOptionalUtcTimestamp,
  readOptionalUuid,
  readRequiredInt32,
  readRequiredInt64BigInt,
  readRequiredString,
  readRequiredUtcTimestamp,
  readRequiredUuid
} from "../mappers.js";
import { type PgTransactionClient } from "../types.js";
import {
  lockInstallationShare,
  lockProjectShare,
  type InstallationStatusRecord,
  type ProjectRecord
} from "./access.js";

export interface DispatchDomainRecord {
  readonly id: string;
  readonly name: string;
  readonly state: string;
  readonly policyKind: string;
  readonly policyVersion: string;
  readonly updatedAt: CanonicalUtcTimestamp;
  readonly version: bigint;
}

export interface EndpointDispatchStateRecord {
  readonly dispatchDomainId: string;
  readonly endpointId: EndpointId;
  readonly tenantId: TenantId;
  readonly projectId: ProjectId;
  readonly weight: number;
  readonly deficitUnits: number;
  readonly lastServedAt?: CanonicalUtcTimestamp | undefined;
  readonly version: bigint;
}

export interface ProjectCapacityRecord {
  readonly projectId: ProjectId;
  readonly tenantId: TenantId;
  readonly pendingEvents: bigint;
  readonly unmaterializedCandidateSlots: bigint;
  readonly pendingDeliveries: bigint;
  readonly activeAttemptSlots: number;
  readonly retainedPayloadBytes: bigint;
  readonly reservedPayloadBytes: bigint;
  readonly version: bigint;
}

export interface DispatchShareLockBundle {
  readonly installation: InstallationStatusRecord;
  readonly project: ProjectRecord;
}

/**
 * Acquires shared (`FOR SHARE`) locks on `rq.installation_state` and `rq.projects` in strict
 * lock-ranking order so delivery preparation/send paths never block peer senders on `FOR UPDATE`.
 */
export async function lockDeliveryDispatchAuthoritiesShare(
  tx: PgTransactionClient,
  tenantId: TenantId,
  projectId: ProjectId
): Promise<DispatchShareLockBundle> {
  const installation = await lockInstallationShare(tx);
  const project = await lockProjectShare(tx, tenantId, projectId);
  return { installation, project };
}

export async function listDispatchDomains(
  tx: PgTransactionClient
): Promise<readonly DispatchDomainRecord[]> {
  const res = await tx.query<Record<string, unknown>>(
    `SELECT id, name, state, policy_kind, policy_version, updated_at, version
       FROM rq.dispatch_domains
      ORDER BY name ASC`
  );
  return res.rows.map((row) => ({
    id: readRequiredUuid(row, "id"),
    name: readRequiredString(row, "name"),
    state: readRequiredString(row, "state"),
    policyKind: readRequiredString(row, "policy_kind"),
    policyVersion: readRequiredString(row, "policy_version"),
    updatedAt: readRequiredUtcTimestamp(row, "updated_at"),
    version: readRequiredInt64BigInt(row, "version")
  }));
}

export async function listDueReadyDeliveries(
  tx: PgTransactionClient,
  params: {
    readonly dispatchDomainId?: string | undefined;
    readonly limit?: number | undefined;
  } = {}
): Promise<
  readonly {
    readonly deliveryId: DeliveryId;
    readonly tenantId: TenantId;
    readonly projectId: ProjectId;
    readonly endpointId: EndpointId;
    readonly state: string;
    readonly nextEligibleAt?: CanonicalUtcTimestamp | undefined;
    readonly deadlineAt: CanonicalUtcTimestamp;
  }[]
> {
  const limit = Math.min(200, Math.max(1, Math.trunc(params.limit ?? 64)));
  const res = await tx.query<Record<string, unknown>>(
    `SELECT d.id, d.tenant_id, d.project_id, d.endpoint_id, d.state,
            d.next_eligible_at, d.deadline_at
       FROM rq.deliveries d
       JOIN rq.project_dispatch_memberships m
         ON m.project_id = d.project_id
        AND m.tenant_id = d.tenant_id
        AND m.state = 'active'
      WHERE d.state IN ('ready', 'retry_wait')
        AND ($1::uuid IS NULL OR m.dispatch_domain_id = $1::uuid)
        AND (d.next_eligible_at IS NULL OR d.next_eligible_at <= pg_catalog.clock_timestamp())
        AND d.deadline_at > pg_catalog.clock_timestamp()
      ORDER BY d.created_at ASC, d.id ASC
      LIMIT $2::integer`,
    [params.dispatchDomainId ?? null, limit]
  );

  return res.rows.map((row) => ({
    deliveryId: readRequiredUuid(row, "id", parseDeliveryId),
    tenantId: readRequiredUuid(row, "tenant_id", parseTenantId),
    projectId: readRequiredUuid(row, "project_id", parseProjectId),
    endpointId: readRequiredUuid(row, "endpoint_id", parseEndpointId),
    state: readRequiredString(row, "state"),
    nextEligibleAt: readOptionalUtcTimestamp(row, "next_eligible_at"),
    deadlineAt: readRequiredUtcTimestamp(row, "deadline_at")
  }));
}

export async function listEndpointDispatchStates(
  tx: PgTransactionClient,
  dispatchDomainId: string,
  projectId: ProjectId,
  limit = 100
): Promise<readonly EndpointDispatchStateRecord[]> {
  const clamped = Math.min(500, Math.max(1, Math.trunc(limit)));
  const res = await tx.query<Record<string, unknown>>(
    `SELECT dispatch_domain_id, endpoint_id, tenant_id, project_id, weight,
            deficit_units, last_served_at, version
       FROM rq.endpoint_dispatch_state
      WHERE dispatch_domain_id = $1::uuid AND project_id = $2::uuid
      ORDER BY endpoint_id ASC
      LIMIT $3::integer`,
    [dispatchDomainId, projectId, clamped]
  );
  return res.rows.map((row) => ({
    dispatchDomainId: readRequiredUuid(row, "dispatch_domain_id"),
    endpointId: readRequiredUuid(row, "endpoint_id", parseEndpointId),
    tenantId: readRequiredUuid(row, "tenant_id", parseTenantId),
    projectId: readRequiredUuid(row, "project_id", parseProjectId),
    weight: readRequiredInt32(row, "weight"),
    deficitUnits: readRequiredInt32(row, "deficit_units"),
    lastServedAt: readOptionalUtcTimestamp(row, "last_served_at"),
    version: readRequiredInt64BigInt(row, "version")
  }));
}

export async function findProjectCapacity(
  tx: PgTransactionClient,
  tenantId: TenantId,
  projectId: ProjectId
): Promise<ProjectCapacityRecord | undefined> {
  const res = await tx.query<Record<string, unknown>>(
    `SELECT project_id, tenant_id, pending_events, unmaterialized_candidate_slots,
            pending_deliveries, active_attempt_slots, retained_payload_bytes,
            reserved_payload_bytes, version
       FROM rq.project_capacity
      WHERE tenant_id = $1::uuid AND project_id = $2::uuid`,
    [tenantId, projectId]
  );
  const row = res.rows[0];
  if (row === undefined) {
    return undefined;
  }
  return {
    projectId: readRequiredUuid(row, "project_id", parseProjectId),
    tenantId: readRequiredUuid(row, "tenant_id", parseTenantId),
    pendingEvents: readRequiredInt64BigInt(row, "pending_events"),
    unmaterializedCandidateSlots: readRequiredInt64BigInt(row, "unmaterialized_candidate_slots"),
    pendingDeliveries: readRequiredInt64BigInt(row, "pending_deliveries"),
    activeAttemptSlots: readRequiredInt32(row, "active_attempt_slots"),
    retainedPayloadBytes: readRequiredInt64BigInt(row, "retained_payload_bytes"),
    reservedPayloadBytes: readRequiredInt64BigInt(row, "reserved_payload_bytes"),
    version: readRequiredInt64BigInt(row, "version")
  };
}

export async function findDispatchDomainState(
  tx: PgTransactionClient,
  dispatchDomainId: string
): Promise<
  | {
      readonly dispatchDomainId: string;
      readonly policyEpoch: bigint;
      readonly roundNumber: bigint;
      readonly tenantCursor?: TenantId | undefined;
      readonly version: bigint;
    }
  | undefined
> {
  const res = await tx.query<Record<string, unknown>>(
    `SELECT dispatch_domain_id, policy_epoch, round_number, tenant_cursor, version
       FROM rq.dispatch_state
      WHERE dispatch_domain_id = $1::uuid`,
    [dispatchDomainId]
  );
  const row = res.rows[0];
  if (row === undefined) {
    return undefined;
  }
  return {
    dispatchDomainId: readRequiredUuid(row, "dispatch_domain_id"),
    policyEpoch: readRequiredInt64BigInt(row, "policy_epoch"),
    roundNumber: readRequiredInt64BigInt(row, "round_number"),
    tenantCursor: readOptionalUuid(row, "tenant_cursor", parseTenantId),
    version: readRequiredInt64BigInt(row, "version")
  };
}
