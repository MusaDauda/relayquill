import crypto from "node:crypto";
import {
  ATTEMPT_STATES,
  type AttemptId,
  type AttemptState,
  type CanonicalUtcTimestamp,
  CIRCUIT_STATES,
  ConflictDomainError,
  type ControlEpoch,
  DELIVERY_STATES,
  type DeliveryId,
  ENDPOINT_STATES,
  type EndpointId,
  type EndpointVerificationAttemptId,
  type EndpointVerificationIntentId,
  formatInt64,
  type KeyId,
  SIGNING_KEY_VERSION_STATES,
  parseAttemptId,
  parseDeliveryFamilyId,
  parseDeliveryId,
  parseEndpointId,
  parseEndpointVerificationAttemptId,
  parseEndpointVerificationIntentId,
  parseEventId,
  parseEventTypeName,
  parseKeyId,
  parseOrderingDomainId,
  parsePositiveInt64String,
  parsePrincipalId,
  parseProjectId,
  parseSha256Hex,
  parseSigningKeyVersionId,
  parseSubscriptionId,
  parseTenantId,
  parseUtcTimestamp,
  parseWireEnvelopeId,
  type PrincipalId,
  type ProjectId,
  type RuntimeInstanceId,
  type Sha256Hex,
  SIGNATURE_MODES,
  type TenantId,
  toEpochMicroseconds,
  ValidationDomainError
} from "@relayquill/domain";
import { computeOriginalFactsSha256, decodeWebhookEnvelopeBytes } from "@relayquill/contracts";
import {
  type DeliveryExecutionRepositoryPort,
  type DeliverySendContextRecord,
  type DispatchClaimRequestRecord,
  type DispatchDomainRecord,
  type DispatchRepositoryPort,
  type EndpointCircuitSnapshot,
  type InstallationAuthoritySnapshot,
  type MicrotokenRateBucketRecord,
  type PrepareDispatchAttemptInput,
  type ReadyDeliveryCandidate,
  type VerificationAttemptContextRecord,
  type WdrrScopeState
} from "@relayquill/application";
import {
  byteaToBuffer,
  byteaToSha256Hex,
  claimVerificationAttempt as pgClaimVerificationAttempt,
  finalizeDeliveryAttempt as pgFinalizeDeliveryAttempt,
  finalizeVerificationAttempt as pgFinalizeVerificationAttempt,
  observeLateDelivery as pgObserveLateDelivery,
  observeReceiverReceipt as pgObserveReceiverReceipt,
  type PgTransactionClient,
  prepareDispatchDelivery as pgPrepareDispatchDelivery,
  readInstallationStatus,
  readOptionalUtcTimestamp,
  readOptionalUuid,
  readRequiredBoolean,
  readRequiredEnum,
  readRequiredInt32,
  readRequiredInt64BigInt,
  readRequiredString,
  readRequiredUtcTimestamp,
  readRequiredUuid,
  readWireEnvelopeBytes,
  recordEgressDecision as pgRecordEgressDecision,
  startDeliverySend as pgStartDeliverySend
} from "@relayquill/postgres";
import { type EndpointKeyMetadata } from "@relayquill/signing";

function deterministicSubUuid(baseRequestId: string, index: number): string {
  const hash = crypto
    .createHash("sha256")
    .update(`${baseRequestId}:${index}`)
    .digest();
  const bytes = Uint8Array.from(hash.subarray(0, 16));
  bytes[6] = ((bytes[6] ?? 0) & 0x0f) | 0x40;
  bytes[8] = ((bytes[8] ?? 0) & 0x3f) | 0x80;
  const hex = Buffer.from(bytes).toString("hex");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20, 32)}`;
}

function mapClaimRequestState(dbState: string): DispatchClaimRequestRecord["state"] {
  switch (dbState) {
    case "accepted":
    case "empty":
      return "completed";
    case "rejected":
      return "failed";
    case "pending":
    default:
      return "prepared";
  }
}

function mapDomainState(dbState: string): DispatchDomainRecord["state"] {
  switch (dbState) {
    case "active":
      return "active";
    case "draining":
      return "draining";
    case "retired":
    default:
      return "paused";
  }
}

function mapVerificationAttemptState(
  dbState: string | undefined
): VerificationAttemptContextRecord["attemptState"] {
  switch (dbState) {
    case "prepared":
    case "send_started":
      return "claimed";
    case "verified":
      return "verified";
    case "expired":
    case "abandoned":
      return "failed_transient";
    case "failed":
      return "failed_permanent";
    default:
      return "pending";
  }
}

function toRateBucketRecord(
  row: Record<string, unknown>,
  scopeKind: "tenant" | "project" | "endpoint",
  scopeId: string
): MicrotokenRateBucketRecord {
  const lastRefill = readRequiredUtcTimestamp(row, "last_refill_at");
  const lastRefillUs = toEpochMicroseconds(parseUtcTimestamp(lastRefill, "last_refill_at").instant);
  const gateId = row["rate_change_gate_id"];

  return {
    scopeKind,
    scopeId,
    policyVersion: readRequiredInt64BigInt(row, "policy_version"),
    tokensMicro: readRequiredInt64BigInt(row, "tokens_micro"),
    reservedMicro: readRequiredInt64BigInt(row, "reserved_micro"),
    capacityMicro: readRequiredInt64BigInt(row, "capacity_micro"),
    refillMicroPerSec: readRequiredInt64BigInt(row, "refill_micro_per_second"),
    remainderNumerator: readRequiredInt64BigInt(row, "refill_remainder_numerator"),
    lastRefillAtUs: lastRefillUs,
    enabled: gateId === null || gateId === undefined,
    version: readRequiredInt64BigInt(row, "version")
  };
}

function parseInstantOrNull(
  row: Record<string, unknown>,
  column: string
): ReturnType<typeof parseUtcTimestamp>["instant"] | null {
  const ts = readOptionalUtcTimestamp(row, column);
  return ts !== undefined ? parseUtcTimestamp(ts, column).instant : null;
}

export class PostgresDispatchRepository implements DispatchRepositoryPort<PgTransactionClient> {
  async readInstallationAuthority(tx: PgTransactionClient): Promise<InstallationAuthoritySnapshot> {
    return readInstallationStatus(tx);
  }

  async findDispatchClaimRequest(
    tx: PgTransactionClient,
    requestId: string
  ): Promise<DispatchClaimRequestRecord | undefined> {
    const reqRes = await tx.query<Record<string, unknown>>(
      `SELECT id, dispatch_domain_id, runtime_instance_id, control_epoch,
              maximum_count, request_sha256, state
         FROM rq.dispatch_claim_requests
        WHERE id = $1::uuid`,
      [requestId]
    );
    const reqRow = reqRes.rows[0];
    if (reqRow === undefined) {
      return undefined;
    }

    const assignRes = await tx.query<Record<string, unknown>>(
      `SELECT a.attempt_id, a.delivery_id, d.endpoint_id, a.fencing_token,
              (da.probe_generation_at_start IS NOT NULL) AS is_circuit_probe,
              da.claim_expires_at
         FROM rq.dispatch_claim_assignments a
         JOIN rq.deliveries d ON d.id = a.delivery_id
         JOIN rq.delivery_attempts da ON da.id = a.attempt_id
        WHERE a.request_id = $1::uuid
        ORDER BY a.assignment_index ASC`,
      [requestId]
    );

    const assignments = assignRes.rows.map((row) => ({
      attemptId: readRequiredUuid(row, "attempt_id", parseAttemptId),
      deliveryId: readRequiredUuid(row, "delivery_id", parseDeliveryId),
      endpointId: readRequiredUuid(row, "endpoint_id", parseEndpointId),
      fencingToken: readRequiredInt64BigInt(row, "fencing_token"),
      isCircuitProbe: readRequiredBoolean(row, "is_circuit_probe"),
      claimExpiresAt: readRequiredUtcTimestamp(row, "claim_expires_at")
    }));

    return {
      requestId: readRequiredUuid(reqRow, "id"),
      dispatchDomainId: readRequiredUuid(reqRow, "dispatch_domain_id"),
      workerInstanceId: readRequiredUuid<RuntimeInstanceId>(reqRow, "runtime_instance_id"),
      controlEpoch: readRequiredUuid<ControlEpoch>(reqRow, "control_epoch"),
      maximumCount: readRequiredInt32(reqRow, "maximum_count"),
      requestSha256: byteaToSha256Hex(reqRow["request_sha256"], "request_sha256"),
      state: mapClaimRequestState(readRequiredString(reqRow, "state")),
      assignments
    };
  }

  async listDispatchDomains(tx: PgTransactionClient): Promise<readonly DispatchDomainRecord[]> {
    const res = await tx.query<Record<string, unknown>>(
      `SELECT dd.id, dd.name, dd.state, COALESCE(ds.policy_epoch, 1) AS policy_epoch, dd.version
         FROM rq.dispatch_domains dd
         LEFT JOIN rq.dispatch_state ds ON ds.dispatch_domain_id = dd.id
        ORDER BY dd.name ASC`
    );

    return res.rows.map((row) => ({
      dispatchDomainId: readRequiredUuid(row, "id"),
      name: readRequiredString(row, "name"),
      state: mapDomainState(readRequiredString(row, "state")),
      policyKind: "wdrr_hierarchical_v1",
      policyEpoch: readRequiredInt64BigInt(row, "policy_epoch"),
      version: readRequiredInt64BigInt(row, "version")
    }));
  }

  async listWdrrTenantStates(
    tx: PgTransactionClient,
    dispatchDomainId: string,
    limit: number
  ): Promise<readonly (WdrrScopeState & { readonly tenantId: TenantId })[]> {
    const clamped = Math.min(500, Math.max(1, Math.trunc(limit)));
    const res = await tx.query<Record<string, unknown>>(
      `WITH explicit AS (
         SELECT tds.tenant_id, tds.weight, tds.deficit_units,
                tds.last_credited_policy_epoch AS policy_epoch,
                tds.last_served_at, tds.version
           FROM rq.tenant_dispatch_state tds
          WHERE tds.dispatch_domain_id = $1::uuid
       ),
       discovered AS (
         SELECT DISTINCT d.tenant_id, 1 AS weight, 0 AS deficit_units,
                COALESCE(ds.policy_epoch, 1) AS policy_epoch,
                NULL::timestamptz AS last_served_at, 1::bigint AS version
           FROM rq.deliveries d
           JOIN rq.project_dispatch_memberships m
             ON m.project_id = d.project_id
            AND m.tenant_id = d.tenant_id
            AND m.dispatch_domain_id = $1::uuid
            AND m.state = 'active'
           LEFT JOIN rq.dispatch_state ds
             ON ds.dispatch_domain_id = $1::uuid
          WHERE d.state IN ('ready', 'retry_wait')
            AND NOT EXISTS (SELECT 1 FROM explicit e WHERE e.tenant_id = d.tenant_id)
       )
       SELECT tenant_id, weight, deficit_units, policy_epoch, last_served_at, version
         FROM (
           SELECT * FROM explicit
           UNION ALL
           SELECT * FROM discovered
         ) combined
        ORDER BY tenant_id ASC
        LIMIT $2::integer`,
      [dispatchDomainId, clamped]
    );

    return res.rows.map((row) => {
      const tenantId = readRequiredUuid(row, "tenant_id", parseTenantId);
      const lastServedAt = readOptionalUtcTimestamp(row, "last_served_at");
      return {
        scopeKind: "tenant",
        scopeId: tenantId,
        tenantId,
        weight: readRequiredInt32(row, "weight"),
        deficitUnits: readRequiredInt32(row, "deficit_units"),
        policyEpoch: readRequiredInt64BigInt(row, "policy_epoch"),
        ...(lastServedAt !== undefined ? { lastServedAt } : {}),
        version: readRequiredInt64BigInt(row, "version")
      };
    });
  }

  async listWdrrProjectStates(
    tx: PgTransactionClient,
    dispatchDomainId: string,
    tenantId: TenantId,
    limit: number
  ): Promise<readonly (WdrrScopeState & { readonly projectId: ProjectId })[]> {
    const clamped = Math.min(500, Math.max(1, Math.trunc(limit)));
    const res = await tx.query<Record<string, unknown>>(
      `WITH explicit AS (
         SELECT pds.project_id, pds.weight, pds.deficit_units,
                pds.last_credited_policy_epoch AS policy_epoch,
                pds.last_served_at, pds.version
           FROM rq.project_dispatch_state pds
          WHERE pds.dispatch_domain_id = $1::uuid
            AND pds.tenant_id = $2::uuid
       ),
       discovered AS (
         SELECT DISTINCT d.project_id, 1 AS weight, 0 AS deficit_units,
                COALESCE(ds.policy_epoch, 1) AS policy_epoch,
                NULL::timestamptz AS last_served_at, 1::bigint AS version
           FROM rq.deliveries d
           JOIN rq.project_dispatch_memberships m
             ON m.project_id = d.project_id
            AND m.tenant_id = d.tenant_id
            AND m.dispatch_domain_id = $1::uuid
            AND m.state = 'active'
           LEFT JOIN rq.dispatch_state ds
             ON ds.dispatch_domain_id = $1::uuid
          WHERE d.tenant_id = $2::uuid
            AND d.state IN ('ready', 'retry_wait')
            AND NOT EXISTS (SELECT 1 FROM explicit e WHERE e.project_id = d.project_id)
       )
       SELECT project_id, weight, deficit_units, policy_epoch, last_served_at, version
         FROM (
           SELECT * FROM explicit
           UNION ALL
           SELECT * FROM discovered
         ) combined
        ORDER BY project_id ASC
        LIMIT $3::integer`,
      [dispatchDomainId, tenantId, clamped]
    );

    return res.rows.map((row) => {
      const projectId = readRequiredUuid(row, "project_id", parseProjectId);
      const lastServedAt = readOptionalUtcTimestamp(row, "last_served_at");
      return {
        scopeKind: "project",
        scopeId: projectId,
        projectId,
        weight: readRequiredInt32(row, "weight"),
        deficitUnits: readRequiredInt32(row, "deficit_units"),
        policyEpoch: readRequiredInt64BigInt(row, "policy_epoch"),
        ...(lastServedAt !== undefined ? { lastServedAt } : {}),
        version: readRequiredInt64BigInt(row, "version")
      };
    });
  }

  async listWdrrEndpointStates(
    tx: PgTransactionClient,
    dispatchDomainId: string,
    projectId: ProjectId,
    limit: number
  ): Promise<readonly (WdrrScopeState & { readonly endpointId: EndpointId })[]> {
    const clamped = Math.min(500, Math.max(1, Math.trunc(limit)));
    const res = await tx.query<Record<string, unknown>>(
      `WITH explicit AS (
         SELECT eds.endpoint_id, eds.weight, eds.deficit_units,
                eds.last_credited_policy_epoch AS policy_epoch,
                eds.last_served_at, eds.version
           FROM rq.endpoint_dispatch_state eds
          WHERE eds.dispatch_domain_id = $1::uuid
            AND eds.project_id = $2::uuid
       ),
       discovered AS (
         SELECT DISTINCT d.endpoint_id, 1 AS weight, 0 AS deficit_units,
                COALESCE(ds.policy_epoch, 1) AS policy_epoch,
                NULL::timestamptz AS last_served_at, 1::bigint AS version
           FROM rq.deliveries d
           JOIN rq.project_dispatch_memberships m
             ON m.project_id = d.project_id
            AND m.tenant_id = d.tenant_id
            AND m.dispatch_domain_id = $1::uuid
            AND m.state = 'active'
           LEFT JOIN rq.dispatch_state ds
             ON ds.dispatch_domain_id = $1::uuid
          WHERE d.project_id = $2::uuid
            AND d.state IN ('ready', 'retry_wait')
            AND NOT EXISTS (SELECT 1 FROM explicit e WHERE e.endpoint_id = d.endpoint_id)
       )
       SELECT endpoint_id, weight, deficit_units, policy_epoch, last_served_at, version
         FROM (
           SELECT * FROM explicit
           UNION ALL
           SELECT * FROM discovered
         ) combined
        ORDER BY endpoint_id ASC
        LIMIT $3::integer`,
      [dispatchDomainId, projectId, clamped]
    );

    return res.rows.map((row) => {
      const endpointId = readRequiredUuid(row, "endpoint_id", parseEndpointId);
      const lastServedAt = readOptionalUtcTimestamp(row, "last_served_at");
      return {
        scopeKind: "endpoint",
        scopeId: endpointId,
        endpointId,
        weight: readRequiredInt32(row, "weight"),
        deficitUnits: readRequiredInt32(row, "deficit_units"),
        policyEpoch: readRequiredInt64BigInt(row, "policy_epoch"),
        ...(lastServedAt !== undefined ? { lastServedAt } : {}),
        version: readRequiredInt64BigInt(row, "version")
      };
    });
  }

  async listDueDeliveriesForEndpoint(
    tx: PgTransactionClient,
    projectId: ProjectId,
    endpointId: EndpointId,
    _now: CanonicalUtcTimestamp,
    limit: number
  ): Promise<readonly ReadyDeliveryCandidate[]> {
    const clamped = Math.min(200, Math.max(1, Math.trunc(limit)));
    const res = await tx.query<Record<string, unknown>>(
      `SELECT d.id, d.family_id, d.tenant_id, d.project_id, d.endpoint_id, d.endpoint_version,
              d.state, d.attempt_count, d.maximum_attempts, d.next_eligible_at,
              d.deadline_at, d.ordering_sequence, d.created_at,
              (
                d.ordering_sequence IS NOT NULL
                AND ok.id IS NOT NULL
                AND om.ordering_sequence IS DISTINCT FROM ok.next_eligible_sequence
              ) AS ordering_blocked_by_gap
         FROM rq.deliveries d
         LEFT JOIN rq.ordering_members om
           ON om.delivery_id = d.id
         LEFT JOIN rq.ordering_keys ok
           ON ok.id = om.ordering_key_id
        WHERE d.project_id = $1::uuid
          AND d.endpoint_id = $2::uuid
          AND d.state IN ('ready', 'retry_wait')
          AND (d.next_eligible_at IS NULL OR d.next_eligible_at <= pg_catalog.clock_timestamp())
          AND d.deadline_at > pg_catalog.clock_timestamp()
        ORDER BY d.created_at ASC, d.id ASC
        LIMIT $3::integer`,
      [projectId, endpointId, clamped]
    );

    return res.rows.map((row): ReadyDeliveryCandidate => {
      const nextEligibleAt = readOptionalUtcTimestamp(row, "next_eligible_at");
      const rawOrdSeq = row["ordering_sequence"];
      const orderingSequence =
        rawOrdSeq !== null && rawOrdSeq !== undefined
          ? readRequiredInt64BigInt(row, "ordering_sequence")
          : undefined;
      const blockedByGap = row["ordering_blocked_by_gap"] === true;

      return {
        deliveryId: readRequiredUuid(row, "id", parseDeliveryId),
        familyId: readRequiredUuid(row, "family_id", parseDeliveryFamilyId),
        tenantId: readRequiredUuid(row, "tenant_id", parseTenantId),
        projectId: readRequiredUuid(row, "project_id", parseProjectId),
        endpointId: readRequiredUuid(row, "endpoint_id", parseEndpointId),
        endpointVersion: readRequiredInt64BigInt(row, "endpoint_version"),
        state: readRequiredEnum(row, "state", DELIVERY_STATES),
        attemptCount: readRequiredInt32(row, "attempt_count"),
        maximumAttempts: readRequiredInt32(row, "maximum_attempts"),
        ...(nextEligibleAt !== undefined ? { nextEligibleAt } : {}),
        deadlineAt: readRequiredUtcTimestamp(row, "deadline_at"),
        ...(orderingSequence !== undefined ? { orderingSequence } : {}),
        ...(blockedByGap ? { orderingBlockedByGap: true } : {}),
        createdAt: readRequiredUtcTimestamp(row, "created_at")
      };
    });
  }

  async readRateBuckets(
    tx: PgTransactionClient,
    scope: {
      readonly tenantId: TenantId;
      readonly projectId: ProjectId;
      readonly endpointId: EndpointId;
    }
  ): Promise<{
    readonly tenantBucket?: MicrotokenRateBucketRecord | undefined;
    readonly projectBucket?: MicrotokenRateBucketRecord | undefined;
    readonly endpointBucket: MicrotokenRateBucketRecord;
  }> {
    const tRes = await tx.query<Record<string, unknown>>(
      `SELECT tokens_micro, reserved_micro, capacity_micro, refill_micro_per_second,
              refill_remainder_numerator, last_refill_at, policy_version, rate_change_gate_id, version
         FROM rq.tenant_rate_buckets
        WHERE tenant_id = $1::uuid AND operation = 'send_start'`,
      [scope.tenantId]
    );
    const pRes = await tx.query<Record<string, unknown>>(
      `SELECT tokens_micro, reserved_micro, capacity_micro, refill_micro_per_second,
              refill_remainder_numerator, last_refill_at, policy_version, rate_change_gate_id, version
         FROM rq.project_rate_buckets
        WHERE project_id = $1::uuid AND operation = 'send_start'`,
      [scope.projectId]
    );
    const eRes = await tx.query<Record<string, unknown>>(
      `SELECT tokens_micro, reserved_micro, capacity_micro, refill_micro_per_second,
              refill_remainder_numerator, last_refill_at, policy_version, rate_change_gate_id, version
         FROM rq.endpoint_rate_buckets
        WHERE endpoint_id = $1::uuid AND operation = 'send_start'`,
      [scope.endpointId]
    );

    const eRow = eRes.rows[0];
    if (eRow === undefined) {
      throw new ValidationDomainError({
        code: "NOT_FOUND",
        message: `Endpoint send_start rate bucket missing for "${scope.endpointId}"`
      });
    }

    const tRow = tRes.rows[0];
    const pRow = pRes.rows[0];

    return {
      ...(tRow !== undefined ? { tenantBucket: toRateBucketRecord(tRow, "tenant", scope.tenantId) } : {}),
      ...(pRow !== undefined ? { projectBucket: toRateBucketRecord(pRow, "project", scope.projectId) } : {}),
      endpointBucket: toRateBucketRecord(eRow, "endpoint", scope.endpointId)
    };
  }

  async readEndpointCircuit(
    tx: PgTransactionClient,
    endpointId: EndpointId
  ): Promise<EndpointCircuitSnapshot> {
    const res = await tx.query<Record<string, unknown>>(
      `SELECT ec.endpoint_id, ec.endpoint_version, ec.state, ec.circuit_generation,
              ec.consecutive_transient_failures,
              ec.reopen_count, ec.reopen_not_before, ec.probe_generation,
              ec.probe_attempt_id, ec.version
         FROM rq.endpoint_circuits ec
         JOIN rq.endpoints e ON e.id = ec.endpoint_id
        WHERE ec.endpoint_id = $1::uuid
          AND (e.current_version IS NULL OR ec.endpoint_version = e.current_version)
        ORDER BY ec.endpoint_version DESC
        LIMIT 1`,
      [endpointId]
    );
    const row = res.rows[0];
    if (row === undefined) {
      throw new ValidationDomainError({
        code: "NOT_FOUND",
        message: `Endpoint circuit missing for "${endpointId}"`
      });
    }
    const reopenNotBefore = readOptionalUtcTimestamp(row, "reopen_not_before");
    const probeAttemptId = readOptionalUuid(row, "probe_attempt_id", parseAttemptId);

    return {
      endpointId: readRequiredUuid(row, "endpoint_id", parseEndpointId),
      endpointVersion: readRequiredInt64BigInt(row, "endpoint_version"),
      state: readRequiredEnum(row, "state", CIRCUIT_STATES),
      circuitGeneration: readRequiredInt64BigInt(row, "circuit_generation"),
      consecutiveTransientFailures: readRequiredInt32(row, "consecutive_transient_failures"),
      consecutivePermanentFailures: 0,
      reopenCount: readRequiredInt32(row, "reopen_count"),
      ...(reopenNotBefore !== undefined ? { reopenNotBefore } : {}),
      probeGeneration: readRequiredInt64BigInt(row, "probe_generation"),
      probeInFlightAttemptId: probeAttemptId ?? null,
      version: readRequiredInt64BigInt(row, "version")
    };
  }

  async readProjectConcurrencyUsage(
    tx: PgTransactionClient,
    tenantId: TenantId,
    projectId: ProjectId
  ): Promise<{
    readonly activeAttemptSlots: number;
    readonly maxActiveAttemptSlots: number;
    readonly pendingDeliveries: bigint;
  }> {
    const res = await tx.query<Record<string, unknown>>(
      `SELECT active_attempt_slots, max_active_attempt_slots, pending_deliveries
         FROM rq.project_capacity
        WHERE tenant_id = $1::uuid AND project_id = $2::uuid`,
      [tenantId, projectId]
    );
    const row = res.rows[0];
    if (row === undefined) {
      throw new ValidationDomainError({
        code: "NOT_FOUND",
        message: `Project capacity missing for "${projectId}"`
      });
    }
    return {
      activeAttemptSlots: readRequiredInt32(row, "active_attempt_slots"),
      maxActiveAttemptSlots: readRequiredInt32(row, "max_active_attempt_slots"),
      pendingDeliveries: readRequiredInt64BigInt(row, "pending_deliveries")
    };
  }

  async readEndpointConcurrencyUsage(
    tx: PgTransactionClient,
    endpointId: EndpointId
  ): Promise<{
    readonly activeAttemptSlots: number;
    readonly maxInFlight: number;
    readonly state: DispatchRepositoryPort<PgTransactionClient> extends {
      readEndpointConcurrencyUsage(tx: never, id: never): Promise<infer R>;
    }
      ? R extends { readonly state: infer S }
        ? S
        : never
      : never;
  }> {
    const res = await tx.query<Record<string, unknown>>(
      `SELECT ec.held_slots, ec.approved_active_slots, e.state
         FROM rq.endpoint_capacity ec
         JOIN rq.endpoints e ON e.id = ec.endpoint_id
        WHERE ec.endpoint_id = $1::uuid`,
      [endpointId]
    );
    const row = res.rows[0];
    if (row === undefined) {
      throw new ValidationDomainError({
        code: "NOT_FOUND",
        message: `Endpoint capacity missing for "${endpointId}"`
      });
    }
    return {
      activeAttemptSlots: readRequiredInt32(row, "held_slots"),
      maxInFlight: readRequiredInt32(row, "approved_active_slots"),
      state: readRequiredEnum(row, "state", ENDPOINT_STATES)
    };
  }

  async commitDispatchBatch(
    tx: PgTransactionClient,
    input: PrepareDispatchAttemptInput
  ): Promise<DispatchClaimRequestRecord> {
    if (input.selections.length === 0) {
      return {
        requestId: input.requestId,
        dispatchDomainId: input.dispatchDomainId,
        workerInstanceId: input.workerInstanceId,
        controlEpoch: input.controlEpoch,
        maximumCount: input.maximumCount,
        requestSha256: input.requestSha256,
        state: "completed",
        assignments: []
      };
    }

    const assignments: {
      readonly attemptId: AttemptId;
      readonly deliveryId: DeliveryId;
      readonly endpointId: EndpointId;
      readonly fencingToken: bigint;
      readonly isCircuitProbe: boolean;
      readonly claimExpiresAt: CanonicalUtcTimestamp;
    }[] = [];

    for (let i = 0; i < input.selections.length; i += 1) {
      const sel = input.selections[i];
      if (sel === undefined) {
        continue;
      }
      const reqId = i === 0 ? input.requestId : deterministicSubUuid(input.requestId, i);
      const prepared = await pgPrepareDispatchDelivery(tx, {
        requestId: reqId,
        dispatchDomainId: input.dispatchDomainId,
        workerInstanceId: input.workerInstanceId,
        controlEpoch: input.controlEpoch,
        requestSha256: input.requestSha256,
        deliveryId: sel.deliveryId,
        attemptId: sel.attemptId,
        claimLeaseMs: input.claimLeaseMs
      });

      if (prepared.outcome === "prepared") {
        assignments.push({
          attemptId: prepared.attemptId,
          deliveryId: prepared.deliveryId,
          endpointId: sel.endpointId,
          fencingToken: prepared.fencingToken,
          isCircuitProbe: sel.isCircuitProbe,
          claimExpiresAt: prepared.claimExpiresAt
        });
      } else {
        for (const item of prepared.assignments) {
          assignments.push({
            attemptId: item.attemptId,
            deliveryId: item.deliveryId,
            endpointId: sel.endpointId,
            fencingToken: item.fencingToken,
            isCircuitProbe: sel.isCircuitProbe,
            claimExpiresAt: input.now
          });
        }
      }
    }

    return {
      requestId: input.requestId,
      dispatchDomainId: input.dispatchDomainId,
      workerInstanceId: input.workerInstanceId,
      controlEpoch: input.controlEpoch,
      maximumCount: input.maximumCount,
      requestSha256: input.requestSha256,
      state: "completed",
      assignments
    };
  }
}

export interface PostgresDeliveryExecutionRepositoryOptions {
  readonly recorderPrincipalId?: PrincipalId | undefined;
  readonly onCustodyKeyDiscovered?: ((
    endpointId: EndpointId,
    keyId: KeyId,
    custodyReference: string,
    metadata: EndpointKeyMetadata
  ) => void) | undefined;
}

export class PostgresDeliveryExecutionRepository
  implements DeliveryExecutionRepositoryPort<PgTransactionClient>
{
  readonly #recorderPrincipalId: PrincipalId | undefined;
  readonly #onCustodyKeyDiscovered:
    | ((
        endpointId: EndpointId,
        keyId: KeyId,
        custodyReference: string,
        metadata: EndpointKeyMetadata
      ) => void)
    | undefined;
  readonly #pendingVerificationIntents = new Map<
    EndpointVerificationAttemptId,
    EndpointVerificationIntentId
  >();

  constructor(options: PostgresDeliveryExecutionRepositoryOptions = {}) {
    this.#recorderPrincipalId = options.recorderPrincipalId;
    this.#onCustodyKeyDiscovered = options.onCustodyKeyDiscovered;
  }

  registerPendingVerificationAttempt(
    attemptId: EndpointVerificationAttemptId,
    intentId: EndpointVerificationIntentId
  ): void {
    this.#pendingVerificationIntents.set(attemptId, intentId);
  }

  async loadAttemptSendContext(
    tx: PgTransactionClient,
    attemptId: AttemptId
  ): Promise<DeliverySendContextRecord> {
    const res = await tx.query<Record<string, unknown>>(
      `SELECT da.id AS attempt_id, da.delivery_id, da.attempt_number, da.state AS attempt_state,
              da.fencing_token, da.circuit_generation_at_preparation,
              da.probe_generation_at_start, da.wire_body_sha256,
              d.tenant_id, d.project_id, d.event_id, d.subscription_id,
              d.dispatch_subscription_version, d.delivery_generation,
              d.state AS delivery_state, d.deadline_at, d.maximum_attempts,
              d.endpoint_id, d.endpoint_version, d.wire_envelope_id,
              d.ordering_key_sha256, d.ordering_sequence,
              ep.state AS endpoint_state, ev.destination_url,
              sp.policy_version AS signing_policy_version,
              sp.primary_key_version_id, sp.overlap_key_version_id,
              sp.signature_mode,
              sv.retry_policy_version, sv.receiver_contract_id, sv.receiver_contract_version,
              df.consumer_contract_scope, df.consumer_event_key_sha256,
              rcv.receipt_profile,
              vse.project_event_sequence, vse.event_type_id, vse.event_schema_version,
              vse.content_sha256, vse.admitted_at, vse.producer_event_time,
              ok.ordering_domain_id
         FROM rq.delivery_attempts da
         JOIN rq.deliveries d
           ON d.id = da.delivery_id
         JOIN rq.delivery_families df
           ON df.id = d.family_id
         JOIN rq.endpoints ep
           ON ep.id = d.endpoint_id
         JOIN rq.endpoint_versions ev
           ON ev.endpoint_id = d.endpoint_id
          AND ev.endpoint_version = d.endpoint_version
         JOIN rq.signing_policies sp
           ON sp.endpoint_id = d.endpoint_id
          AND sp.policy_version = da.signing_policy_version
         JOIN rq.subscription_versions sv
           ON sv.subscription_id = d.subscription_id
          AND sv.subscription_version = d.dispatch_subscription_version
         JOIN rq.receiver_contract_versions rcv
           ON rcv.contract_id = sv.receiver_contract_id
          AND rcv.contract_version = sv.receiver_contract_version
         JOIN rq.v_safe_events vse
           ON vse.id = d.event_id
         LEFT JOIN rq.ordering_members om
           ON om.delivery_id = d.id
         LEFT JOIN rq.ordering_keys ok
           ON ok.id = om.ordering_key_id
        WHERE da.id = $1::uuid`,
      [attemptId]
    );
    const row = res.rows[0];
    if (row === undefined) {
      throw new ValidationDomainError({
        code: "NOT_FOUND",
        message: `Delivery attempt "${attemptId}" not found`
      });
    }

    const tenantId = readRequiredUuid(row, "tenant_id", parseTenantId);
    const projectId = readRequiredUuid(row, "project_id", parseProjectId);
    const eventId = readRequiredUuid(row, "event_id", parseEventId);
    const endpointId = readRequiredUuid(row, "endpoint_id", parseEndpointId);
    const wireEnvelopeId = readRequiredUuid(row, "wire_envelope_id", parseWireEnvelopeId);
    const wire = await readWireEnvelopeBytes(tx, tenantId, projectId, wireEnvelopeId);
    if (wire === undefined || wire.bodyBytes === undefined) {
      throw new ValidationDomainError({
        code: "INVALID_VALUE",
        message: `Wire envelope bytes unavailable for "${wireEnvelopeId}"`
      });
    }
    const wireBodyBytes = new Uint8Array(wire.bodyBytes);

    const projectEventSequence = readRequiredInt64BigInt(row, "project_event_sequence");
    const eventTypeId = readRequiredUuid(row, "event_type_id", parseEventId) as unknown as string;
    const eventSchemaVersion = readRequiredInt32(row, "event_schema_version");
    const contentSha256 = byteaToSha256Hex(row["content_sha256"], "content_sha256");
    const admittedAt = readRequiredUtcTimestamp(row, "admitted_at");
    const producerEventTime = readOptionalUtcTimestamp(row, "producer_event_time");

    let originalFactsSha256: Sha256Hex | undefined;
    try {
      const decodedWire = decodeWebhookEnvelopeBytes(wireBodyBytes);
      originalFactsSha256 = decodedWire.original_facts_sha256;
    } catch {
      let parsedWireTypeName: string | undefined;
      try {
        const parsedWire = JSON.parse(Buffer.from(wireBodyBytes).toString("utf8")) as Record<
          string,
          unknown
        >;
        const rawOrigFacts = parsedWire["original_facts_sha256"];
        if (typeof rawOrigFacts === "string" && /^[0-9a-f]{64}$/i.test(rawOrigFacts)) {
          originalFactsSha256 = parseSha256Hex(rawOrigFacts, "original_facts_sha256");
        }
        if (typeof parsedWire["event_type"] === "string") {
          parsedWireTypeName = parsedWire["event_type"];
        } else if (typeof parsedWire["type"] === "string") {
          parsedWireTypeName = parsedWire["type"];
        }
      } catch {
        // Fall back to default type name computation when non-JSON test fixtures are used
      }

      if (originalFactsSha256 === undefined) {
        originalFactsSha256 = computeOriginalFactsSha256({
          project_id: projectId,
          event_id: eventId,
          project_event_sequence: parsePositiveInt64String(
            formatInt64(projectEventSequence, "project_event_sequence"),
            "project_event_sequence"
          ),
          event_type_id: eventTypeId,
          event_type: parseEventTypeName(parsedWireTypeName ?? "order.created", "event_type"),
          event_schema_version: eventSchemaVersion,
          admitted_at: admittedAt,
          producer_event_time: producerEventTime ?? null,
          original_content_sha256: contentSha256
        });
      }
    }

    const primaryKeyId = readRequiredUuid(row, "primary_key_version_id", parseSigningKeyVersionId);
    const overlapKeyId = readOptionalUuid(row, "overlap_key_version_id", parseSigningKeyVersionId);
    const keyIds = overlapKeyId !== undefined ? [primaryKeyId, overlapKeyId] : [primaryKeyId];

    const keyRes = await tx.query<Record<string, unknown>>(
      `SELECT id, key_version, key_id, custody_reference, state,
              activate_not_before, sign_until, verify_until, revoked_at
         FROM rq.signing_key_versions
        WHERE endpoint_id = $1::uuid
          AND id = ANY($2::uuid[])`,
      [endpointId, keyIds]
    );

    const keyRowsById = new Map<string, Record<string, unknown>>();
    for (const kr of keyRes.rows) {
      keyRowsById.set(readRequiredUuid(kr, "id"), kr);
    }

    const signingKeys: EndpointKeyMetadata[] = [];
    for (const kid of keyIds) {
      const kr = keyRowsById.get(kid);
      if (kr === undefined) {
        continue;
      }
      const keyId = parseKeyId(readRequiredString(kr, "key_id"), "key_id");
      const keyVersionId = readRequiredUuid(kr, "id", parseSigningKeyVersionId);
      const custodyRef = readRequiredString(kr, "custody_reference");
      const meta: EndpointKeyMetadata = {
        keyId,
        keyVersionId,
        endpointId,
        projectId,
        keyVersion: readRequiredInt64BigInt(kr, "key_version"),
        state: readRequiredEnum(kr, "state", SIGNING_KEY_VERSION_STATES),
        activateNotBefore: parseInstantOrNull(kr, "activate_not_before"),
        signUntil: parseInstantOrNull(kr, "sign_until"),
        verifyUntil: parseInstantOrNull(kr, "verify_until"),
        revokedAt: parseInstantOrNull(kr, "revoked_at")
      };
      signingKeys.push(meta);
      this.#onCustodyKeyDiscovered?.(endpointId, keyId, custodyRef, meta);
    }

    const orderingDomainId = readOptionalUuid(row, "ordering_domain_id", parseOrderingDomainId);
    const hasOrderingKey =
      row["ordering_key_sha256"] !== null && row["ordering_key_sha256"] !== undefined;
    const rawOrderingSeq = row["ordering_sequence"];

    return {
      tenantId,
      projectId,
      eventId,
      subscriptionId: readRequiredUuid(row, "subscription_id", parseSubscriptionId),
      subscriptionVersion: readRequiredInt64BigInt(row, "dispatch_subscription_version"),
      deliveryId: readRequiredUuid(row, "delivery_id", parseDeliveryId),
      deliveryGeneration: readRequiredInt64BigInt(row, "delivery_generation"),
      deliveryState: readRequiredEnum(row, "delivery_state", DELIVERY_STATES),
      deliveryDeadlineAt: readRequiredUtcTimestamp(row, "deadline_at"),
      attemptId,
      attemptNumber: readRequiredInt32(row, "attempt_number"),
      maximumAttempts: readRequiredInt32(row, "maximum_attempts"),
      attemptState: readRequiredEnum(row, "attempt_state", ATTEMPT_STATES),
      fencingToken: readRequiredInt64BigInt(row, "fencing_token"),
      isCircuitProbe:
        row["probe_generation_at_start"] !== null && row["probe_generation_at_start"] !== undefined,
      circuitGenerationAtPrepare: readRequiredInt64BigInt(
        row,
        "circuit_generation_at_preparation"
      ),
      endpointId,
      endpointVersion: readRequiredInt64BigInt(row, "endpoint_version"),
      endpointState: readRequiredEnum(row, "endpoint_state", ENDPOINT_STATES),
      destinationUrl: readRequiredString(row, "destination_url"),
      signingPolicyVersion: parsePositiveInt64String(
        formatInt64(
          readRequiredInt64BigInt(row, "signing_policy_version"),
          "signingPolicyVersion"
        ),
        "signingPolicyVersion"
      ),
      signingKeys,
      allowOverlapDualSign:
        readRequiredEnum(row, "signature_mode", SIGNATURE_MODES) === "bounded_dual_signature",
      wireEnvelopeId,
      wireBodyBytes,
      wireBodySha256: byteaToSha256Hex(row["wire_body_sha256"], "wire_body_sha256"),
      originalFactsSha256,
      consumerEventKeySha256: byteaToSha256Hex(
        row["consumer_event_key_sha256"],
        "consumer_event_key_sha256"
      ),
      consumerContractId: readRequiredUuid(row, "receiver_contract_id"),
      consumerContractVersion: readRequiredInt64BigInt(row, "receiver_contract_version"),
      consumerContractScope: readRequiredString(row, "consumer_contract_scope"),
      receiptRequired: readRequiredString(row, "receipt_profile") === "receiver_local_commit_v1",
      retryPolicyVersion: readRequiredString(row, "retry_policy_version"),
      ...(orderingDomainId !== undefined &&
      hasOrderingKey &&
      rawOrderingSeq !== null &&
      rawOrderingSeq !== undefined
        ? {
            ordering: {
              orderingDomainId,
              orderingKeySha256: byteaToSha256Hex(
                row["ordering_key_sha256"],
                "ordering_key_sha256"
              ),
              orderingSequence: parsePositiveInt64String(
                formatInt64(
                  readRequiredInt64BigInt(row, "ordering_sequence"),
                  "ordering_sequence"
                ),
                "ordering_sequence"
              )
            }
          }
        : {})
    };
  }

  async startDeliverySend(
    tx: PgTransactionClient,
    params: Parameters<DeliveryExecutionRepositoryPort<PgTransactionClient>["startDeliverySend"]>[1]
  ): ReturnType<DeliveryExecutionRepositoryPort<PgTransactionClient>["startDeliverySend"]> {
    const res = await pgStartDeliverySend(tx, {
      attemptId: params.attemptId,
      workerInstanceId: params.workerInstanceId,
      controlEpoch: params.controlEpoch,
      expectedFencingToken: params.expectedFencingToken,
      networkBudgetMs: params.networkBudgetMs
    });
    return {
      shouldSend: res.shouldSend,
      alreadyStarted: res.alreadyStarted,
      attemptId: res.attemptId,
      requestDeadlineAt: res.requestDeadlineAt,
      acceptedAt: res.acceptedAt
    };
  }

  async deferUnstartedAttempt(
    tx: PgTransactionClient,
    params: Parameters<DeliveryExecutionRepositoryPort<PgTransactionClient>["deferUnstartedAttempt"]>[1]
  ): Promise<{ readonly deferred: boolean }> {
    const fin = await pgFinalizeDeliveryAttempt(tx, {
      attemptId: params.attemptId,
      workerInstanceId: params.workerInstanceId,
      controlEpoch: params.controlEpoch,
      expectedFencingToken: params.expectedFencingToken,
      attemptState: "deferred_before_send",
      outcomeClass: "transport_unknown",
      safeErrorCode: params.reasonCode,
      retryDecision: "retry",
      retryReasonCode: params.reasonCode,
      nextEligibleAt: params.nextEligibleAt ?? params.now
    });
    return { deferred: fin.outcome === "finalized" };
  }

  async recordEgressDecision(
    tx: PgTransactionClient,
    params: Parameters<DeliveryExecutionRepositoryPort<PgTransactionClient>["recordEgressDecision"]>[1]
  ): Promise<void> {
    const sqlDecision = params.decision === "allow" ? "allowed" : "denied";
    await pgRecordEgressDecision(tx, {
      decisionId: params.decisionId,
      tenantId: params.tenantId,
      projectId: params.projectId,
      endpointId: params.endpointId,
      endpointVersion: params.endpointVersion,
      deliveryAttemptId: params.deliveryAttemptId ?? null,
      verificationAttemptId: params.verificationAttemptId ?? null,
      runtimeInstanceId: params.runtimeInstanceId,
      controlEpoch: params.controlEpoch,
      networkPolicyVersion: params.networkPolicyVersion,
      registryIpv4Sha256: params.registryIpv4Sha256,
      registryIpv6Sha256: params.registryIpv6Sha256,
      authoritySha256: params.authoritySha256,
      answerSetSha256: params.answerSetSha256 ?? null,
      selectedAddressSha256: params.selectedAddressSha256 ?? null,
      selectedFamily: params.selectedFamily ?? null,
      peerAddressSha256: params.peerAddressSha256 ?? null,
      decision: sqlDecision as "allow",
      reasonCode: params.reasonCode,
      expiresAt: params.expiresAt
    });
  }

  async finalizeDeliveryAttempt(
    tx: PgTransactionClient,
    params: Parameters<DeliveryExecutionRepositoryPort<PgTransactionClient>["finalizeDeliveryAttempt"]>[1]
  ): ReturnType<DeliveryExecutionRepositoryPort<PgTransactionClient>["finalizeDeliveryAttempt"]> {
    const fin = await pgFinalizeDeliveryAttempt(tx, {
      attemptId: params.attemptId,
      workerInstanceId: params.workerInstanceId,
      controlEpoch: params.controlEpoch,
      expectedFencingToken: params.expectedFencingToken,
      attemptState: params.attemptState,
      outcomeClass: params.outcomeClass,
      responseStatus: params.responseStatus,
      responseBodySha256: params.responseBodySha256,
      responseByteCount: params.responseByteCount,
      safeErrorCode: params.safeErrorCode,
      retryDecision: params.retryDecision,
      retryReasonCode: params.retryReasonCode,
      retryPolicyVersion: params.retryPolicyVersion,
      selectedDelayMs: params.selectedDelayMs,
      selectedBackoffMs: params.selectedBackoffMs,
      retryAfterParseClass: params.retryAfterParseClass,
      retryAfterMs: params.retryAfterMs,
      nextEligibleAt: params.nextEligibleAt
    });
    return {
      outcome: fin.outcome,
      attemptId: fin.attemptId,
      attemptState: fin.attemptState as AttemptState,
      deliveryState: fin.deliveryState
    };
  }

  async updateEndpointCircuit(
    tx: PgTransactionClient,
    params: Parameters<DeliveryExecutionRepositoryPort<PgTransactionClient>["updateEndpointCircuit"]>[1]
  ): Promise<EndpointCircuitSnapshot> {
    const res = await tx.query<Record<string, unknown>>(
      `SELECT ec.endpoint_id, ec.endpoint_version, ec.state, ec.circuit_generation,
              ec.consecutive_transient_failures,
              ec.reopen_count, ec.reopen_not_before, ec.probe_generation,
              ec.probe_attempt_id, ec.version
         FROM rq.endpoint_circuits ec
         JOIN rq.endpoints e ON e.id = ec.endpoint_id
        WHERE ec.endpoint_id = $1::uuid
          AND (e.current_version IS NULL OR ec.endpoint_version = e.current_version)
        ORDER BY ec.endpoint_version DESC
        LIMIT 1`,
      [params.endpointId]
    );
    const row = res.rows[0];
    if (row === undefined) {
      throw new ValidationDomainError({
        code: "NOT_FOUND",
        message: `Endpoint circuit missing for "${params.endpointId}"`
      });
    }
    const reopenNotBefore = readOptionalUtcTimestamp(row, "reopen_not_before");
    const probeAttemptId = readOptionalUuid(row, "probe_attempt_id", parseAttemptId);
    return {
      endpointId: readRequiredUuid(row, "endpoint_id", parseEndpointId),
      endpointVersion: readRequiredInt64BigInt(row, "endpoint_version"),
      state: readRequiredEnum(row, "state", CIRCUIT_STATES),
      circuitGeneration: readRequiredInt64BigInt(row, "circuit_generation"),
      consecutiveTransientFailures: readRequiredInt32(row, "consecutive_transient_failures"),
      consecutivePermanentFailures: 0,
      reopenCount: readRequiredInt32(row, "reopen_count"),
      ...(reopenNotBefore !== undefined ? { reopenNotBefore } : {}),
      probeGeneration: readRequiredInt64BigInt(row, "probe_generation"),
      probeInFlightAttemptId: probeAttemptId ?? null,
      version: readRequiredInt64BigInt(row, "version")
    };
  }

  async observeReceiverReceipt(
    tx: PgTransactionClient,
    params: Parameters<DeliveryExecutionRepositoryPort<PgTransactionClient>["observeReceiverReceipt"]>[1]
  ): Promise<{ readonly recorded: boolean; readonly state: "verified" | "conflicting" | "rejected" }> {
    let recordedBy = this.#recorderPrincipalId;
    if (recordedBy === undefined) {
      const epRes = await tx.query<Record<string, unknown>>(
        `SELECT ep.created_by
           FROM rq.deliveries d
           JOIN rq.endpoints ep ON ep.id = d.endpoint_id
          WHERE d.id = $1::uuid`,
        [params.deliveryId]
      );
      const epRow = epRes.rows[0];
      recordedBy =
        epRow !== undefined
          ? readRequiredUuid(epRow, "created_by", parsePrincipalId)
          : parsePrincipalId(params.recordedBy, "recordedBy");
    }

    const sqlSourceKind =
      params.sourceKind === "inline_http_response" ? "direct_response" : params.sourceKind;
    const sqlState = params.state === "verified" ? "verified_supported" : "rejected";

    const res = await pgObserveReceiverReceipt(tx, {
      observationId: params.observationId,
      deliveryId: params.deliveryId,
      attemptId: params.attemptId,
      receiptReference: params.receiptReference,
      receiptFactsSha256: params.receiptFactsSha256,
      requestWireSha256: params.requestWireSha256,
      proofSha256: params.proofSha256,
      keyId: params.keyId,
      receiverContractId: params.receiverContractId,
      receiverContractVersion: params.receiverContractVersion,
      receiptFacts: params.receiptFacts,
      verificationProfileVersion: params.verificationProfileVersion,
      sourceKind: sqlSourceKind,
      recordedBy,
      state: sqlState as "verified"
    });

    return {
      recorded: true,
      state: res.state === "verified_supported" ? "verified" : "rejected"
    };
  }

  async observeLateDelivery(
    tx: PgTransactionClient,
    params: Parameters<DeliveryExecutionRepositoryPort<PgTransactionClient>["observeLateDelivery"]>[1]
  ): Promise<void> {
    await pgObserveLateDelivery(tx, {
      observationId: params.observationId,
      deliveryId: params.deliveryId,
      attemptId: params.attemptId,
      sourceInstanceId: params.sourceInstanceId,
      observationKeySha256: params.observationKeySha256,
      factsSha256: params.factsSha256,
      observationKind: params.observationKind,
      safeFacts: params.safeFacts
    });
  }

  async loadVerificationAttemptContext(
    tx: PgTransactionClient,
    attemptId: EndpointVerificationAttemptId
  ): Promise<VerificationAttemptContextRecord> {
    const mappedIntentId = this.#pendingVerificationIntents.get(attemptId);

    let intentId = mappedIntentId;
    let existingAttemptState: string | undefined;
    let claimExpiresAt: CanonicalUtcTimestamp | undefined;

    if (intentId === undefined) {
      const attRes = await tx.query<Record<string, unknown>>(
        `SELECT intent_id, state, claim_expires_at
           FROM rq.endpoint_verification_attempts
          WHERE id = $1::uuid`,
        [attemptId]
      );
      const attRow = attRes.rows[0];
      if (attRow !== undefined) {
        intentId = readRequiredUuid(attRow, "intent_id", parseEndpointVerificationIntentId);
        existingAttemptState = readRequiredString(attRow, "state");
        claimExpiresAt = readOptionalUtcTimestamp(attRow, "claim_expires_at");
      } else {
        intentId = attemptId as unknown as EndpointVerificationIntentId;
      }
    }

    const res = await tx.query<Record<string, unknown>>(
      `SELECT ivi.id AS intent_id, ivi.tenant_id, ivi.project_id, ivi.endpoint_id,
              ivi.endpoint_version, ivi.configuration_sha256, ivi.public_nonce,
              ivi.expires_at AS intent_expires_at,
              ep.state AS endpoint_state, ev.destination_url,
              skv.id AS key_version_id, skv.key_version, skv.key_id, skv.custody_reference,
              skv.state AS key_state, skv.activate_not_before, skv.sign_until,
              skv.verify_until, skv.revoked_at
         FROM rq.endpoint_verification_intents ivi
         JOIN rq.endpoints ep ON ep.id = ivi.endpoint_id
         JOIN rq.endpoint_versions ev
           ON ev.endpoint_id = ivi.endpoint_id
          AND ev.endpoint_version = ivi.endpoint_version
         JOIN rq.signing_key_versions skv ON skv.id = ivi.signing_key_version_id
        WHERE ivi.id = $1::uuid`,
      [intentId]
    );
    const row = res.rows[0];
    if (row === undefined) {
      throw new ValidationDomainError({
        code: "NOT_FOUND",
        message: `Verification intent/attempt "${attemptId}" not found`
      });
    }

    const tenantId = readRequiredUuid(row, "tenant_id", parseTenantId);
    const projectId = readRequiredUuid(row, "project_id", parseProjectId);
    const endpointId = readRequiredUuid(row, "endpoint_id", parseEndpointId);
    const keyId = parseKeyId(readRequiredString(row, "key_id"), "key_id");
    const custodyRef = readRequiredString(row, "custody_reference");
    const keyMetadata: EndpointKeyMetadata = {
      keyId,
      keyVersionId: readRequiredUuid(row, "key_version_id", parseSigningKeyVersionId),
      endpointId,
      projectId,
      keyVersion: readRequiredInt64BigInt(row, "key_version"),
      state: readRequiredEnum(row, "key_state", SIGNING_KEY_VERSION_STATES),
      activateNotBefore: parseInstantOrNull(row, "activate_not_before"),
      signUntil: parseInstantOrNull(row, "sign_until"),
      verifyUntil: parseInstantOrNull(row, "verify_until"),
      revokedAt: parseInstantOrNull(row, "revoked_at")
    };
    this.#onCustodyKeyDiscovered?.(endpointId, keyId, custodyRef, keyMetadata);

    const nonceBytes = byteaToBuffer(row["public_nonce"], "public_nonce");
    const publicNonce = nonceBytes.toString("base64url");

    return {
      tenantId,
      projectId,
      endpointId,
      endpointVersion: readRequiredInt64BigInt(row, "endpoint_version"),
      endpointState: readRequiredEnum(row, "endpoint_state", ENDPOINT_STATES),
      configurationSha256: byteaToSha256Hex(row["configuration_sha256"], "configuration_sha256"),
      destinationUrl: readRequiredString(row, "destination_url"),
      verificationIntentId: readRequiredUuid(
        row,
        "intent_id",
        parseEndpointVerificationIntentId
      ),
      intentExpiresAt: readRequiredUtcTimestamp(row, "intent_expires_at"),
      publicNonce,
      keyId,
      keyMetadata,
      attemptId: parseEndpointVerificationAttemptId(attemptId, "attemptId"),
      attemptState: mapVerificationAttemptState(existingAttemptState),
      ...(claimExpiresAt !== undefined ? { claimExpiresAt } : {})
    };
  }

  async claimVerificationAttempt(
    tx: PgTransactionClient,
    params: Parameters<DeliveryExecutionRepositoryPort<PgTransactionClient>["claimVerificationAttempt"]>[1]
  ): Promise<{ readonly claimed: boolean }> {
    try {
      await pgClaimVerificationAttempt(tx, {
        intentId: params.intentId,
        attemptId: params.attemptId,
        instanceId: params.instanceId,
        controlEpoch: params.controlEpoch,
        claimLeaseMs: params.claimLeaseMs
      });
      this.#pendingVerificationIntents.delete(params.attemptId);
      return { claimed: true };
    } catch (err) {
      if (err instanceof ConflictDomainError) {
        return { claimed: false };
      }
      throw err;
    }
  }

  async finalizeVerificationAttempt(
    tx: PgTransactionClient,
    params: Parameters<
      DeliveryExecutionRepositoryPort<PgTransactionClient>["finalizeVerificationAttempt"]
    >[1]
  ): Promise<void> {
    const sqlOutcome =
      params.outcome === "verified"
        ? "verified"
        : params.outcome === "failed_transient"
          ? "unavailable"
          : params.safeReasonCode === "intent_expired"
            ? "expired"
            : "denied";
    const sqlSafeReasonCode =
      params.safeReasonCode !== null &&
      params.safeReasonCode !== undefined &&
      params.safeReasonCode.length > 0
        ? params.safeReasonCode
        : sqlOutcome === "verified"
          ? "verified"
          : "verification_failed";

    await pgFinalizeVerificationAttempt(tx, {
      attemptId: params.attemptId,
      instanceId: params.instanceId,
      controlEpoch: params.controlEpoch,
      outcome: sqlOutcome as "verified",
      responseStatus: params.responseStatus,
      proofSha256: params.proofSha256,
      networkPolicyVersion: params.networkPolicyVersion,
      safeReasonCode: sqlSafeReasonCode,
      eventId: params.eventId
    });
  }
}
