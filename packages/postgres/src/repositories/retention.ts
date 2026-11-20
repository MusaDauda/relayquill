import {
  RETENTION_ACTION_KINDS,
  RETENTION_ACTION_STATES,
  RETENTION_HOLD_STATES,
  parseProjectId,
  parseRetentionActionId,
  parseRetentionHoldId,
  parseTenantId,
  parseWatchLeaseId,
  type ActorKind,
  type CanonicalUtcTimestamp,
  type ControlEpoch,
  type PrincipalId,
  type ProducerCredentialId,
  type ProjectId,
  type RetentionActionId,
  type RetentionActionKind,
  type RetentionActionState,
  type RetentionHoldId,
  type RetentionHoldState,
  type RuntimeInstanceId,
  type SessionId,
  type TenantId,
  type WatchLeaseId,
  type WatchResourceKind
} from "@relayquill/domain";
import {
  readOptionalUtcTimestamp,
  readRequiredEnum,
  readRequiredInt32,
  readRequiredInt64BigInt,
  readRequiredString,
  readRequiredUtcTimestamp,
  readRequiredUuid
} from "../mappers.js";
import { type PgTransactionClient } from "../types.js";
import {
  callJsonbFunction,
  readJsonbTimestamp,
  toBigIntSqlParam,
  toTimestampSqlParam,
  type BigIntInput,
  type TimestampInput
} from "./_sql.js";

export interface OpenWatchLeaseParams {
  readonly leaseId: WatchLeaseId;
  readonly tenantId: TenantId;
  readonly projectId: ProjectId;
  readonly principalId: PrincipalId;
  readonly actorKind: ActorKind;
  readonly sessionId?: SessionId | null | undefined;
  readonly producerCredentialId?: ProducerCredentialId | null | undefined;
  readonly resourceKind: WatchResourceKind;
  readonly resourceId: string;
  readonly runtimeInstanceId: RuntimeInstanceId;
  readonly controlEpoch: ControlEpoch;
  readonly authCutoffAt: TimestampInput;
  readonly streamCutoffAt: TimestampInput;
}

export interface RenewWatchLeaseParams {
  readonly leaseId: WatchLeaseId;
  readonly controlEpoch: ControlEpoch;
  readonly authCutoffAt: TimestampInput;
}

export interface ReapExpiredCoordinatorWorkParams {
  readonly instanceId: RuntimeInstanceId;
  readonly controlEpoch: ControlEpoch;
  readonly batchLimit?: number | undefined;
}

export interface FinalizeRetentionActionParams {
  readonly actionId: RetentionActionId;
  readonly instanceId: RuntimeInstanceId;
  readonly controlEpoch: ControlEpoch;
  readonly claimGeneration: BigIntInput;
}

export interface RetentionHoldRecord {
  readonly id: RetentionHoldId;
  readonly tenantId: TenantId;
  readonly projectId?: ProjectId | undefined;
  readonly targetKind: string;
  readonly targetId: string;
  readonly reasonCode: string;
  readonly state: RetentionHoldState;
  readonly reviewAt?: CanonicalUtcTimestamp | undefined;
  readonly expiresAt?: CanonicalUtcTimestamp | undefined;
  readonly version: bigint;
}

export interface RetentionActionRecord {
  readonly id: RetentionActionId;
  readonly tenantId: TenantId;
  readonly projectId?: ProjectId | undefined;
  readonly targetKind: string;
  readonly targetId: string;
  readonly action: RetentionActionKind;
  readonly state: RetentionActionState;
  readonly claimGeneration: bigint;
  readonly nextAttemptAt: CanonicalUtcTimestamp;
  readonly version: bigint;
}

export async function openWatchLease(
  tx: PgTransactionClient,
  input: OpenWatchLeaseParams
): Promise<{
  readonly leaseId: WatchLeaseId;
  readonly expiresAt: CanonicalUtcTimestamp;
  readonly streamCutoffAt: CanonicalUtcTimestamp;
}> {
  const data = await callJsonbFunction(
    tx,
    "rq.cmd_watch_lease_open",
    [
      "uuid",
      "uuid",
      "uuid",
      "uuid",
      "text",
      "uuid",
      "uuid",
      "text",
      "uuid",
      "uuid",
      "uuid",
      "timestamptz",
      "timestamptz"
    ],
    [
      input.leaseId,
      input.tenantId,
      input.projectId,
      input.principalId,
      input.actorKind,
      input.sessionId ?? null,
      input.producerCredentialId ?? null,
      input.resourceKind,
      input.resourceId,
      input.runtimeInstanceId,
      input.controlEpoch,
      toTimestampSqlParam(input.authCutoffAt, "authCutoffAt"),
      toTimestampSqlParam(input.streamCutoffAt, "streamCutoffAt")
    ],
    "rq.cmd_watch_lease_open"
  );

  return {
    leaseId: readRequiredUuid(data, "lease_id", parseWatchLeaseId),
    expiresAt: readJsonbTimestamp(data, "expires_at", "rq.cmd_watch_lease_open"),
    streamCutoffAt: readJsonbTimestamp(data, "stream_cutoff_at", "rq.cmd_watch_lease_open")
  };
}

export async function renewWatchLease(
  tx: PgTransactionClient,
  input: RenewWatchLeaseParams
): Promise<{ readonly leaseId: WatchLeaseId; readonly expiresAt: CanonicalUtcTimestamp }> {
  const data = await callJsonbFunction(
    tx,
    "rq.cmd_watch_lease_renew",
    ["uuid", "uuid", "timestamptz"],
    [
      input.leaseId,
      input.controlEpoch,
      toTimestampSqlParam(input.authCutoffAt, "authCutoffAt")
    ],
    "rq.cmd_watch_lease_renew"
  );
  return {
    leaseId: readRequiredUuid(data, "lease_id", parseWatchLeaseId),
    expiresAt: readJsonbTimestamp(data, "expires_at", "rq.cmd_watch_lease_renew")
  };
}

export async function closeWatchLease(
  tx: PgTransactionClient,
  leaseId: WatchLeaseId
): Promise<{ readonly outcome: "not_found" | "already_closed" | "closed"; readonly leaseId?: WatchLeaseId | undefined }> {
  const data = await callJsonbFunction(
    tx,
    "rq.cmd_watch_lease_close",
    ["uuid"],
    [leaseId],
    "rq.cmd_watch_lease_close"
  );
  const outcome = readRequiredEnum(data, "outcome", ["not_found", "already_closed", "closed"] as const);
  if (outcome === "not_found") {
    return { outcome: "not_found" };
  }
  return {
    outcome,
    leaseId: readRequiredUuid(data, "lease_id", parseWatchLeaseId)
  };
}

export async function reapExpiredCoordinatorWork(
  tx: PgTransactionClient,
  input: ReapExpiredCoordinatorWorkParams
): Promise<{ readonly reapedAttempts: number; readonly reapedWatchLeases: number }> {
  const data = await callJsonbFunction(
    tx,
    "rq.cmd_coordinator_reap_expired",
    ["uuid", "uuid", "integer"],
    [input.instanceId, input.controlEpoch, Math.min(500, Math.max(1, input.batchLimit ?? 50))],
    "rq.cmd_coordinator_reap_expired"
  );
  return {
    reapedAttempts: readRequiredInt32(data, "reaped_attempts"),
    reapedWatchLeases: readRequiredInt32(data, "reaped_watch_leases")
  };
}

export async function finalizeRetentionAction(
  tx: PgTransactionClient,
  input: FinalizeRetentionActionParams
): Promise<{
  readonly outcome: "already_complete" | "completed";
  readonly actionId: RetentionActionId;
  readonly action?: RetentionActionKind | undefined;
}> {
  const data = await callJsonbFunction(
    tx,
    "rq.cmd_retention_finalize",
    ["uuid", "uuid", "uuid", "bigint"],
    [
      input.actionId,
      input.instanceId,
      input.controlEpoch,
      toBigIntSqlParam(input.claimGeneration, "claimGeneration")
    ],
    "rq.cmd_retention_finalize"
  );
  const outcome = readRequiredEnum(data, "outcome", ["already_complete", "completed"] as const);
  return {
    outcome,
    actionId: readRequiredUuid(data, "action_id", parseRetentionActionId),
    action:
      data["action"] === undefined || data["action"] === null
        ? undefined
        : readRequiredEnum(data, "action", RETENTION_ACTION_KINDS)
  };
}

export async function listActiveRetentionHolds(
  tx: PgTransactionClient,
  tenantId: TenantId,
  projectId?: ProjectId
): Promise<readonly RetentionHoldRecord[]> {
  const res = await tx.query<Record<string, unknown>>(
    `SELECT id, tenant_id, project_id, target_kind, target_id, reason_code, state,
            review_at, expires_at, version
       FROM rq.retention_holds
      WHERE tenant_id = $1::uuid
        AND ($2::uuid IS NULL OR project_id = $2::uuid)
        AND state = 'active'
      ORDER BY created_at ASC`,
    [tenantId, projectId ?? null]
  );

  return res.rows.map((row) => ({
    id: readRequiredUuid(row, "id", parseRetentionHoldId),
    tenantId: readRequiredUuid(row, "tenant_id", parseTenantId),
    projectId:
      row["project_id"] === null || row["project_id"] === undefined
        ? undefined
        : readRequiredUuid(row, "project_id", parseProjectId),
    targetKind: readRequiredString(row, "target_kind"),
    targetId: readRequiredUuid(row, "target_id"),
    reasonCode: readRequiredString(row, "reason_code"),
    state: readRequiredEnum(row, "state", RETENTION_HOLD_STATES),
    reviewAt: readOptionalUtcTimestamp(row, "review_at"),
    expiresAt: readOptionalUtcTimestamp(row, "expires_at"),
    version: readRequiredInt64BigInt(row, "version")
  }));
}

export async function listDueRetentionActions(
  tx: PgTransactionClient,
  limit = 100
): Promise<readonly RetentionActionRecord[]> {
  const clamped = Math.min(100, Math.max(1, Math.trunc(limit)));
  const res = await tx.query<Record<string, unknown>>(
    `SELECT id, tenant_id, project_id, target_kind, target_id, action, state,
            claim_generation, next_attempt_at, version
       FROM rq.retention_actions
      WHERE state IN ('ready', 'failed_retryable')
        AND next_attempt_at <= pg_catalog.clock_timestamp()
      ORDER BY next_attempt_at ASC, id ASC
      LIMIT $1::integer`,
    [clamped]
  );

  return res.rows.map((row) => ({
    id: readRequiredUuid(row, "id", parseRetentionActionId),
    tenantId: readRequiredUuid(row, "tenant_id", parseTenantId),
    projectId:
      row["project_id"] === null || row["project_id"] === undefined
        ? undefined
        : readRequiredUuid(row, "project_id", parseProjectId),
    targetKind: readRequiredString(row, "target_kind"),
    targetId: readRequiredUuid(row, "target_id"),
    action: readRequiredEnum(row, "action", RETENTION_ACTION_KINDS),
    state: readRequiredEnum(row, "state", RETENTION_ACTION_STATES),
    claimGeneration: readRequiredInt64BigInt(row, "claim_generation"),
    nextAttemptAt: readRequiredUtcTimestamp(row, "next_attempt_at"),
    version: readRequiredInt64BigInt(row, "version")
  }));
}
