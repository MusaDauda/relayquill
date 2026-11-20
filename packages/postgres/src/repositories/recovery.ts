import {
  RECOVERY_ACTION_KINDS,
  RECOVERY_SCOPE_KINDS,
  parseControlEpoch,
  parseProjectId,
  parseRecoveryActionId,
  parseRecoveryIncidentId,
  parseRecoveryOperationId,
  parseRuntimeInstanceId,
  parseTenantId,
  type CanonicalUtcTimestamp,
  type ControlEpoch,
  type EventId,
  type ProjectId,
  type RecoveryActionId,
  type RecoveryActionKind,
  type RecoveryIncidentId,
  type RecoveryOperationId,
  type RecoveryScopeKind,
  type RuntimeInstanceId,
  type Sha256Hex,
  type TenantId
} from "@relayquill/domain";
import { mapPostgresError } from "../errors.js";
import {
  byteaToSha256Hex,
  readOptionalString,
  readOptionalUtcTimestamp,
  readOptionalUuid,
  readRequiredEnum,
  readRequiredInt32,
  readRequiredInt64BigInt,
  readRequiredJsonRecord,
  readRequiredString,
  readRequiredUuid,
  sha256HexToBytea
} from "../mappers.js";
import { type PgTransactionClient } from "../types.js";
import {
  callJsonbFunction,
  readJsonbInt64BigInt,
  toBigIntSqlParam,
  toTimestampSqlParam,
  type BigIntInput,
  type TimestampInput
} from "./_sql.js";

export interface OpenRecoveryIncidentParams {
  readonly incidentId: RecoveryIncidentId;
  readonly externalOperationId: string;
  readonly incidentReference: string;
  readonly scopeKind: RecoveryScopeKind;
  readonly tenantId?: TenantId | null | undefined;
  readonly projectId?: ProjectId | null | undefined;
}

export interface CloseRecoveryIncidentParams {
  readonly incidentId: RecoveryIncidentId;
  readonly expectedVersion: BigIntInput;
  readonly remainingRiskDecisionCode: string;
  readonly operatorReference: string;
}

export interface CreateRecoveryOperationParams {
  readonly operationId: RecoveryOperationId;
  readonly incidentId: RecoveryIncidentId;
  readonly externalOperationId: string;
  readonly sourceEpoch: ControlEpoch;
  readonly targetEpoch: ControlEpoch;
  readonly targetDatabaseIdentityDigest: Sha256Hex;
  readonly planSha256: Sha256Hex;
  readonly requesterReference: string;
}

export interface PlanRecoveryActionParams {
  readonly actionId: RecoveryActionId;
  readonly operationId: RecoveryOperationId;
  readonly ordinal: number;
  readonly kind: RecoveryActionKind;
  readonly scopeKind: RecoveryScopeKind;
  readonly tenantId?: TenantId | null | undefined;
  readonly projectId?: ProjectId | null | undefined;
  readonly targetId?: string | null | undefined;
  readonly expectedTargetVersion?: BigIntInput | null | undefined;
  readonly expectedControlEpoch?: ControlEpoch | null | undefined;
  readonly expectedFactsSha256: Sha256Hex;
  readonly proposedFactsSha256: Sha256Hex;
  readonly requesterReference: string;
  readonly reasonCode: string;
  readonly evidenceReference: string;
  readonly typedPlan: Readonly<Record<string, unknown>>;
}

export interface ReviewRecoveryActionParams {
  readonly reviewId: string;
  readonly actionId: RecoveryActionId;
  readonly planSha256: Sha256Hex;
  readonly targetEpoch: ControlEpoch;
  readonly expectedFactsSha256: Sha256Hex;
  readonly proposedFactsSha256: Sha256Hex;
  readonly reviewerReference: string;
  readonly decision: "approve" | "reject" | "approved" | "rejected";
  readonly rejectReasonCode?: string | null | undefined;
  readonly expiresAt: TimestampInput;
  readonly authorityEvidenceDigest: Sha256Hex;
}

export interface ExecuteRecoveryActionParams {
  readonly actionId: RecoveryActionId;
  readonly operatorReference: string;
  readonly executionNonceDigest: Sha256Hex;
  readonly targetDatabaseIdentityDigest: Sha256Hex;
}

export interface RecoveryExecutionResult {
  readonly outcome: string;
  readonly operationId: RecoveryOperationId;
  readonly actionId: RecoveryActionId;
  readonly newTargetVersion: bigint;
  readonly resultingFactsSha256: Sha256Hex;
  readonly safeResultFacts: Record<string, unknown>;
}

export interface ProjectMaintenanceParams {
  readonly operationId: RecoveryOperationId;
  readonly tenantId: TenantId;
  readonly projectId: ProjectId;
  readonly expectedVersion: BigIntInput;
  readonly operatorReference: string;
}

export interface ClaimInventoryEntry {
  readonly claimKind: string;
  readonly resourceId: string;
  readonly tenantId: TenantId;
  readonly projectId: ProjectId;
  readonly ownerInstanceId?: RuntimeInstanceId | undefined;
  readonly controlEpoch?: ControlEpoch | undefined;
  readonly claimGeneration?: bigint | undefined;
  readonly claimExpiresAt?: CanonicalUtcTimestamp | undefined;
  readonly state: string;
  readonly version: bigint;
}

export interface ObligationInventoryEntry {
  readonly projectId: ProjectId;
  readonly storedPendingEvents: bigint;
  readonly derivedPendingEvents: bigint;
  readonly storedActiveSlots: number;
  readonly derivedHeldSlots: bigint;
  readonly storedUnmaterializedSlots: bigint;
  readonly derivedUnresolvedSlots: bigint;
}

export async function openRecoveryIncident(
  tx: PgTransactionClient,
  input: OpenRecoveryIncidentParams
): Promise<{
  readonly outcome: "idempotent" | "opened";
  readonly incidentId: RecoveryIncidentId;
  readonly state: string;
  readonly version: bigint;
}> {
  const data = await callJsonbFunction(
    tx,
    "rq_recovery.cmd_incident_open",
    ["uuid", "uuid", "text", "text", "uuid", "uuid"],
    [
      input.incidentId,
      input.externalOperationId,
      input.incidentReference,
      input.scopeKind,
      input.tenantId ?? null,
      input.projectId ?? null
    ],
    "rq_recovery.cmd_incident_open"
  );
  return {
    outcome: readRequiredEnum(data, "outcome", ["idempotent", "opened"] as const),
    incidentId: readRequiredUuid(data, "incident_id", parseRecoveryIncidentId),
    state: readRequiredString(data, "state"),
    version: readJsonbInt64BigInt(data, "version", "rq_recovery.cmd_incident_open")
  };
}

export async function closeRecoveryIncident(
  tx: PgTransactionClient,
  input: CloseRecoveryIncidentParams
): Promise<{
  readonly outcome: "idempotent" | "closed";
  readonly incidentId: RecoveryIncidentId;
  readonly state: string;
  readonly version: bigint;
}> {
  const data = await callJsonbFunction(
    tx,
    "rq_recovery.cmd_incident_close",
    ["uuid", "bigint", "text", "text"],
    [
      input.incidentId,
      toBigIntSqlParam(input.expectedVersion, "expectedVersion"),
      input.remainingRiskDecisionCode,
      input.operatorReference
    ],
    "rq_recovery.cmd_incident_close"
  );
  return {
    outcome: readRequiredEnum(data, "outcome", ["idempotent", "closed"] as const),
    incidentId: readRequiredUuid(data, "incident_id", parseRecoveryIncidentId),
    state: readRequiredString(data, "state"),
    version: readJsonbInt64BigInt(data, "version", "rq_recovery.cmd_incident_close")
  };
}

export async function createRecoveryOperation(
  tx: PgTransactionClient,
  input: CreateRecoveryOperationParams
): Promise<{
  readonly outcome: "idempotent" | "planned";
  readonly operationId: RecoveryOperationId;
  readonly state: string;
  readonly version: bigint;
}> {
  const data = await callJsonbFunction(
    tx,
    "rq_recovery.cmd_operation_create",
    ["uuid", "uuid", "uuid", "uuid", "uuid", "bytea", "bytea", "text"],
    [
      input.operationId,
      input.incidentId,
      input.externalOperationId,
      input.sourceEpoch,
      input.targetEpoch,
      sha256HexToBytea(input.targetDatabaseIdentityDigest, "targetDatabaseIdentityDigest"),
      sha256HexToBytea(input.planSha256, "planSha256"),
      input.requesterReference
    ],
    "rq_recovery.cmd_operation_create"
  );
  return {
    outcome: readRequiredEnum(data, "outcome", ["idempotent", "planned"] as const),
    operationId: readRequiredUuid(data, "operation_id", parseRecoveryOperationId),
    state: readRequiredString(data, "state"),
    version: readJsonbInt64BigInt(data, "version", "rq_recovery.cmd_operation_create")
  };
}

export async function planRecoveryAction(
  tx: PgTransactionClient,
  input: PlanRecoveryActionParams
): Promise<{
  readonly outcome: "idempotent" | "planned";
  readonly actionId: RecoveryActionId;
  readonly kind: RecoveryActionKind;
  readonly operationId?: RecoveryOperationId | undefined;
  readonly ordinal?: number | undefined;
  readonly state?: string | undefined;
}> {
  void RECOVERY_SCOPE_KINDS;
  const data = await callJsonbFunction(
    tx,
    "rq_recovery.cmd_action_plan",
    [
      "uuid",
      "uuid",
      "integer",
      "text",
      "text",
      "uuid",
      "uuid",
      "uuid",
      "bigint",
      "uuid",
      "bytea",
      "bytea",
      "text",
      "text",
      "text",
      "jsonb"
    ],
    [
      input.actionId,
      input.operationId,
      input.ordinal,
      input.kind,
      input.scopeKind,
      input.tenantId ?? null,
      input.projectId ?? null,
      input.targetId ?? null,
      input.expectedTargetVersion !== null && input.expectedTargetVersion !== undefined
        ? toBigIntSqlParam(input.expectedTargetVersion, "expectedTargetVersion")
        : null,
      input.expectedControlEpoch ?? null,
      sha256HexToBytea(input.expectedFactsSha256, "expectedFactsSha256"),
      sha256HexToBytea(input.proposedFactsSha256, "proposedFactsSha256"),
      input.requesterReference,
      input.reasonCode,
      input.evidenceReference,
      JSON.stringify(input.typedPlan)
    ],
    "rq_recovery.cmd_action_plan"
  );
  return {
    outcome: readRequiredEnum(data, "outcome", ["idempotent", "planned"] as const),
    actionId: readRequiredUuid(data, "action_id", parseRecoveryActionId),
    kind: readRequiredEnum(data, "kind", RECOVERY_ACTION_KINDS),
    operationId: readOptionalUuid(data, "operation_id", parseRecoveryOperationId),
    ordinal:
      data["ordinal"] === undefined || data["ordinal"] === null
        ? undefined
        : readRequiredInt32(data, "ordinal"),
    state: readOptionalString(data, "state")
  };
}

export async function reviewRecoveryAction(
  tx: PgTransactionClient,
  input: ReviewRecoveryActionParams
): Promise<{
  readonly outcome: "recorded";
  readonly reviewId: string;
  readonly actionId: RecoveryActionId;
  readonly decision: string;
}> {
  const sqlDecision =
    input.decision === "approved"
      ? "approve"
      : input.decision === "rejected"
        ? "reject"
        : input.decision;
  const data = await callJsonbFunction(
    tx,
    "rq_recovery.cmd_action_review",
    [
      "uuid",
      "uuid",
      "bytea",
      "uuid",
      "bytea",
      "bytea",
      "text",
      "text",
      "text",
      "timestamptz",
      "bytea"
    ],
    [
      input.reviewId,
      input.actionId,
      sha256HexToBytea(input.planSha256, "planSha256"),
      input.targetEpoch,
      sha256HexToBytea(input.expectedFactsSha256, "expectedFactsSha256"),
      sha256HexToBytea(input.proposedFactsSha256, "proposedFactsSha256"),
      input.reviewerReference,
      sqlDecision,
      input.rejectReasonCode ?? null,
      toTimestampSqlParam(input.expiresAt, "expiresAt"),
      sha256HexToBytea(input.authorityEvidenceDigest, "authorityEvidenceDigest")
    ],
    "rq_recovery.cmd_action_review"
  );
  return {
    outcome: readRequiredEnum(data, "outcome", ["recorded"] as const),
    reviewId: readRequiredUuid(data, "review_id"),
    actionId: readRequiredUuid(data, "action_id", parseRecoveryActionId),
    decision: readRequiredString(data, "decision")
  };
}

async function executeRecoveryEntrypoint(
  tx: PgTransactionClient,
  qualifiedFn: string,
  input: ExecuteRecoveryActionParams
): Promise<RecoveryExecutionResult> {
  const data = await callJsonbFunction(
    tx,
    qualifiedFn,
    ["uuid", "text", "bytea", "bytea"],
    [
      input.actionId,
      input.operatorReference,
      sha256HexToBytea(input.executionNonceDigest, "executionNonceDigest"),
      sha256HexToBytea(input.targetDatabaseIdentityDigest, "targetDatabaseIdentityDigest")
    ],
    qualifiedFn
  );
  return {
    outcome: readRequiredString(data, "outcome"),
    operationId: readRequiredUuid(data, "operation_id", parseRecoveryOperationId),
    actionId: readRequiredUuid(data, "action_id", parseRecoveryActionId),
    newTargetVersion: readJsonbInt64BigInt(data, "new_target_version", qualifiedFn),
    resultingFactsSha256: byteaToSha256Hex(data["resulting_facts_sha256"], "resulting_facts_sha256"),
    safeResultFacts: readRequiredJsonRecord(data, "safe_result_facts")
  };
}

export function executeEstablishTargetEpoch(
  tx: PgTransactionClient,
  input: ExecuteRecoveryActionParams
): Promise<RecoveryExecutionResult> {
  return executeRecoveryEntrypoint(tx, "rq_recovery.cmd_establish_target_epoch", input);
}

export function executeRetireStaleClaim(
  tx: PgTransactionClient,
  input: ExecuteRecoveryActionParams
): Promise<RecoveryExecutionResult> {
  return executeRecoveryEntrypoint(tx, "rq_recovery.cmd_retire_stale_claim", input);
}

export function executeReconcileReservations(
  tx: PgTransactionClient,
  input: ExecuteRecoveryActionParams
): Promise<RecoveryExecutionResult> {
  return executeRecoveryEntrypoint(tx, "rq_recovery.cmd_reconcile_reservations", input);
}

export function executeContinuePublicationEpisode(
  tx: PgTransactionClient,
  input: ExecuteRecoveryActionParams
): Promise<RecoveryExecutionResult> {
  return executeRecoveryEntrypoint(tx, "rq_recovery.cmd_continue_publication_episode", input);
}

export function executeRecordReceiverComparison(
  tx: PgTransactionClient,
  input: ExecuteRecoveryActionParams
): Promise<RecoveryExecutionResult> {
  return executeRecoveryEntrypoint(tx, "rq_recovery.cmd_record_receiver_comparison", input);
}

export function executeSetRecoveryGate(
  tx: PgTransactionClient,
  input: ExecuteRecoveryActionParams
): Promise<RecoveryExecutionResult> {
  return executeRecoveryEntrypoint(tx, "rq_recovery.cmd_set_recovery_gate", input);
}

export function executeRebuildProjection(
  tx: PgTransactionClient,
  input: ExecuteRecoveryActionParams
): Promise<RecoveryExecutionResult> {
  return executeRecoveryEntrypoint(tx, "rq_recovery.cmd_rebuild_projection", input);
}

export async function acquireProjectMaintenance(
  tx: PgTransactionClient,
  input: ProjectMaintenanceParams
): Promise<{
  readonly outcome: "idempotent" | "acquired";
  readonly projectId: ProjectId;
  readonly maintenanceVersion: bigint;
  readonly projectVersion: bigint;
}> {
  const data = await callJsonbFunction(
    tx,
    "rq_recovery.cmd_project_maintenance_acquire",
    ["uuid", "uuid", "uuid", "bigint", "text"],
    [
      input.operationId,
      input.tenantId,
      input.projectId,
      toBigIntSqlParam(input.expectedVersion, "expectedVersion"),
      input.operatorReference
    ],
    "rq_recovery.cmd_project_maintenance_acquire"
  );
  return {
    outcome: readRequiredEnum(data, "outcome", ["idempotent", "acquired"] as const),
    projectId: readRequiredUuid(data, "project_id", parseProjectId),
    maintenanceVersion: readJsonbInt64BigInt(
      data,
      "maintenance_version",
      "rq_recovery.cmd_project_maintenance_acquire"
    ),
    projectVersion: readJsonbInt64BigInt(
      data,
      "project_version",
      "rq_recovery.cmd_project_maintenance_acquire"
    )
  };
}

export async function releaseProjectMaintenance(
  tx: PgTransactionClient,
  input: ProjectMaintenanceParams
): Promise<{
  readonly outcome: "already_released" | "released";
  readonly projectId: ProjectId;
  readonly maintenanceVersion: bigint;
  readonly projectVersion: bigint;
}> {
  const data = await callJsonbFunction(
    tx,
    "rq_recovery.cmd_project_maintenance_release",
    ["uuid", "uuid", "uuid", "bigint", "text"],
    [
      input.operationId,
      input.tenantId,
      input.projectId,
      toBigIntSqlParam(input.expectedVersion, "expectedVersion"),
      input.operatorReference
    ],
    "rq_recovery.cmd_project_maintenance_release"
  );
  return {
    outcome: readRequiredEnum(data, "outcome", ["already_released", "released"] as const),
    projectId: readRequiredUuid(data, "project_id", parseProjectId),
    maintenanceVersion: readJsonbInt64BigInt(
      data,
      "maintenance_version",
      "rq_recovery.cmd_project_maintenance_release"
    ),
    projectVersion: readJsonbInt64BigInt(
      data,
      "project_version",
      "rq_recovery.cmd_project_maintenance_release"
    )
  };
}

export async function readRecoveryOperationResult(
  tx: PgTransactionClient,
  actionId: RecoveryActionId
): Promise<Record<string, unknown>> {
  return callJsonbFunction(
    tx,
    "rq_recovery.read_operation_result",
    ["uuid"],
    [actionId],
    "rq_recovery.read_operation_result"
  );
}

export async function readClaimInventory(
  tx: PgTransactionClient,
  tenantId?: TenantId | null,
  projectId?: ProjectId | null
): Promise<readonly ClaimInventoryEntry[]> {
  try {
    const res = await tx.query<Record<string, unknown>>(
      `SELECT claim_kind, resource_id, tenant_id, project_id, owner_instance_id,
              control_epoch, claim_generation, claim_expires_at, state, version
         FROM rq_recovery.read_claim_inventory($1::uuid, $2::uuid)`,
      [tenantId ?? null, projectId ?? null]
    );
    return res.rows.map((row) => ({
      claimKind: readRequiredString(row, "claim_kind"),
      resourceId: readRequiredUuid(row, "resource_id"),
      tenantId: readRequiredUuid(row, "tenant_id", parseTenantId),
      projectId: readRequiredUuid(row, "project_id", parseProjectId),
      ownerInstanceId: readOptionalUuid(row, "owner_instance_id", parseRuntimeInstanceId),
      controlEpoch: readOptionalUuid(row, "control_epoch", parseControlEpoch),
      claimGeneration:
        row["claim_generation"] === null || row["claim_generation"] === undefined
          ? undefined
          : readRequiredInt64BigInt(row, "claim_generation"),
      claimExpiresAt: readOptionalUtcTimestamp(row, "claim_expires_at"),
      state: readRequiredString(row, "state"),
      version: readRequiredInt64BigInt(row, "version")
    }));
  } catch (err) {
    throw mapPostgresError(err, { operation: "rq_recovery.read_claim_inventory" });
  }
}

export async function readObligationInventory(
  tx: PgTransactionClient,
  tenantId: TenantId,
  projectId?: ProjectId | null
): Promise<readonly ObligationInventoryEntry[]> {
  try {
    const res = await tx.query<Record<string, unknown>>(
      `SELECT project_id, stored_pending_events, derived_pending_events,
              stored_active_slots, derived_held_slots,
              stored_unmaterialized_slots, derived_unresolved_slots
         FROM rq_recovery.read_obligation_inventory($1::uuid, $2::uuid)`,
      [tenantId, projectId ?? null]
    );
    return res.rows.map((row) => ({
      projectId: readRequiredUuid(row, "project_id", parseProjectId),
      storedPendingEvents: readRequiredInt64BigInt(row, "stored_pending_events"),
      derivedPendingEvents: readRequiredInt64BigInt(row, "derived_pending_events"),
      storedActiveSlots: readRequiredInt32(row, "stored_active_slots"),
      derivedHeldSlots: readRequiredInt64BigInt(row, "derived_held_slots"),
      storedUnmaterializedSlots: readRequiredInt64BigInt(row, "stored_unmaterialized_slots"),
      derivedUnresolvedSlots: readRequiredInt64BigInt(row, "derived_unresolved_slots")
    }));
  } catch (err) {
    throw mapPostgresError(err, { operation: "rq_recovery.read_obligation_inventory" });
  }
}

export async function readProjectionSourceCounts(
  tx: PgTransactionClient,
  tenantId: TenantId,
  projectId: ProjectId,
  eventId?: EventId | null
): Promise<Record<string, unknown>> {
  return callJsonbFunction(
    tx,
    "rq_recovery.read_projection_source_counts",
    ["uuid", "uuid", "uuid"],
    [tenantId, projectId, eventId ?? null],
    "rq_recovery.read_projection_source_counts"
  );
}
