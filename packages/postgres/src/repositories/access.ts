import { Temporal } from "@js-temporal/polyfill";
import {
  ALLOWED_RUNTIME_INSTANCE_TRANSITIONS,
  ConflictDomainError,
  NotFoundDomainError,
  INSTALLATION_MODES,
  PROJECT_STATES,
  TENANT_STATES,
  assertTransition,
  nowUtcInstant,
  parseControlEpoch,
  parseDataGrantId,
  parsePrincipalId,
  parseProducerCredentialId,
  parseProducerId,
  parseProjectId,
  parseRuntimeInstanceId,
  parseSigningDeliveryIntentId,
  parseTenantId,
  parseUtcTimestamp,
  type CanonicalUtcTimestamp,
  type ControlEpoch,
  type DataGrantAction,
  type DataGrantId,
  type DataGrantProjection,
  type InstallationMode,
  type PrincipalId,
  type ProcessRole,
  type ProducerCredentialId,
  type ProducerId,
  type ProjectId,
  type ProjectRole,
  type ProjectState,
  type RuntimeInstanceId,
  type RuntimeInstanceState,
  type Sha256Hex,
  type SigningDeliveryIntentId,
  type TenantId,
  type TenantRole,
  type TenantState
} from "@relayquill/domain";
import {
  type HeartbeatRuntimeInstanceInput,
  type RegisterRuntimeInstanceInput,
  type RuntimeInstanceRegistration,
  type RuntimeRegistryStore,
  type TransitionRuntimeInstanceInput
} from "@relayquill/runtime";
import { mapPostgresError } from "../errors.js";
import {
  byteaToBuffer,
  byteaToSha256Hex,
  readOptionalString,
  readOptionalUuid,
  readRequiredBoolean,
  readRequiredEnum,
  readRequiredInstant,
  readRequiredInt64BigInt,
  readRequiredJsonRecord,
  readRequiredString,
  readRequiredUtcTimestamp,
  readRequiredUuid,
  sha256HexToBytea
} from "../mappers.js";
import { type PgAdapter, type PgTransactionClient } from "../types.js";
import {
  callJsonbFunction,
  readJsonbTimestamp,
  toBigIntSqlParam,
  toTimestampSqlParam,
  type BigIntInput,
  type TimestampInput
} from "./_sql.js";

export interface InstallationStatusRecord {
  readonly controlEpoch: ControlEpoch;
  readonly mode: InstallationMode;
  readonly allowEventAdmission: boolean;
  readonly allowPublication: boolean;
  readonly allowFanout: boolean;
  readonly allowSend: boolean;
  readonly allowEndpointVerification: boolean;
  readonly governanceVersion: bigint;
  readonly updatedAt: CanonicalUtcTimestamp;
  readonly version: bigint;
}

export interface SchemaMigrationRecord {
  readonly migrationId: string;
  readonly checksum: Buffer;
  readonly appliedAt: CanonicalUtcTimestamp;
  readonly sourceReference: string;
  readonly runnerVersion: string;
}

export interface RegisterRuntimeInstanceParams {
  readonly instanceId: RuntimeInstanceId;
  readonly processRole: ProcessRole;
  readonly databaseRole: string;
  readonly controlEpoch: ControlEpoch;
  readonly buildReference: string;
  readonly leaseMs: BigIntInput;
  readonly approvedSlots?: number | undefined;
}

export interface RuntimeRegistrationResult {
  readonly instanceId: RuntimeInstanceId;
  readonly processRole: string;
  readonly controlEpoch: ControlEpoch;
  readonly expiresAt: CanonicalUtcTimestamp;
}

export interface HeartbeatRuntimeInstanceParams {
  readonly instanceId: RuntimeInstanceId;
  readonly controlEpoch: ControlEpoch;
  readonly leaseMs: BigIntInput;
}

export interface RuntimeHeartbeatResult {
  readonly instanceId: RuntimeInstanceId;
  readonly state: RuntimeInstanceState;
  readonly expiresAt: CanonicalUtcTimestamp;
  readonly version: bigint;
}

export interface TenantRecord {
  readonly id: TenantId;
  readonly slug: string;
  readonly displayName: string;
  readonly state: TenantState;
  readonly governanceVersion: bigint;
  readonly createdAt: CanonicalUtcTimestamp;
  readonly updatedAt: CanonicalUtcTimestamp;
  readonly version: bigint;
}

export interface ProjectRecord {
  readonly id: ProjectId;
  readonly tenantId: TenantId;
  readonly name: string;
  readonly state: ProjectState;
  readonly topologyVersion: bigint;
  readonly nextEventSequence: bigint;
  readonly governanceVersion: bigint;
  readonly activeOrderingCutoverPlanId?: string | undefined;
  readonly projectionMaintenanceOperationId?: string | undefined;
  readonly projectionMaintenanceVersion: bigint;
  readonly createdAt: CanonicalUtcTimestamp;
  readonly updatedAt: CanonicalUtcTimestamp;
  readonly version: bigint;
}

export interface HumanDataGrantRecord {
  readonly id: DataGrantId;
  readonly membershipId: string;
  readonly tenantId: TenantId;
  readonly projectId: ProjectId;
  readonly action: DataGrantAction;
  readonly projection: DataGrantProjection;
  readonly producerNamespace?: string | undefined;
  readonly state: string;
  readonly expiresAt?: CanonicalUtcTimestamp | undefined;
  readonly version: bigint;
}

export interface FinalizeSigningDeliveryIntentParams {
  readonly intentId: SigningDeliveryIntentId;
  readonly controlEpoch: ControlEpoch;
  readonly nextState: "delivered" | "failed" | "expired" | "revoked";
}

export interface FinalizeProducerCredentialIntentParams {
  readonly intentId: string;
  readonly controlEpoch: ControlEpoch;
  readonly nextState: "delivered" | "failed" | "expired" | "revoked";
  readonly credentialId: ProducerCredentialId;
  readonly secretDigestSha256: Sha256Hex;
  readonly expiresAt: TimestampInput;
}

const RUNTIME_STATES = ["active", "draining", "quarantined", "ended"] as const;

export async function readInstallationStatus(
  tx: PgTransactionClient
): Promise<InstallationStatusRecord> {
  const data = await callJsonbFunction(
    tx,
    "rq.read_installation_status",
    [],
    [],
    "rq.read_installation_status"
  );
  return {
    controlEpoch: parseControlEpoch(data["control_epoch"], "read_installation_status.control_epoch"),
    mode: readRequiredEnum(data, "mode", INSTALLATION_MODES, "read_installation_status.mode"),
    allowEventAdmission: readRequiredBoolean(data, "allow_event_admission"),
    allowPublication: readRequiredBoolean(data, "allow_publication"),
    allowFanout: readRequiredBoolean(data, "allow_fanout"),
    allowSend: readRequiredBoolean(data, "allow_send"),
    allowEndpointVerification: readRequiredBoolean(data, "allow_endpoint_verification"),
    governanceVersion: readRequiredInt64BigInt(data, "governance_version"),
    updatedAt: readJsonbTimestamp(data, "updated_at", "rq.read_installation_status"),
    version: readRequiredInt64BigInt(data, "version")
  };
}

export async function lockInstallationShare(
  tx: PgTransactionClient
): Promise<InstallationStatusRecord> {
  const res = await tx.query<Record<string, unknown>>(
    `SELECT control_epoch, mode, allow_event_admission, allow_publication, allow_fanout,
            allow_send, allow_endpoint_verification, governance_version, updated_at, version
       FROM rq.installation_state
      WHERE id = 1
      FOR SHARE`
  );
  const row = res.rows[0];
  if (row === undefined) {
    throw new NotFoundDomainError({
      code: "NOT_FOUND",
      message: "Installation state row (id = 1) not found"
    });
  }
  return {
    controlEpoch: readRequiredUuid(row, "control_epoch", parseControlEpoch),
    mode: readRequiredEnum(row, "mode", INSTALLATION_MODES),
    allowEventAdmission: readRequiredBoolean(row, "allow_event_admission"),
    allowPublication: readRequiredBoolean(row, "allow_publication"),
    allowFanout: readRequiredBoolean(row, "allow_fanout"),
    allowSend: readRequiredBoolean(row, "allow_send"),
    allowEndpointVerification: readRequiredBoolean(row, "allow_endpoint_verification"),
    governanceVersion: readRequiredInt64BigInt(row, "governance_version"),
    updatedAt: readRequiredUtcTimestamp(row, "updated_at"),
    version: readRequiredInt64BigInt(row, "version")
  };
}

export async function readSchemaMigrations(
  tx: PgTransactionClient
): Promise<readonly SchemaMigrationRecord[]> {
  try {
    const res = await tx.query<Record<string, unknown>>(
      "SELECT migration_id, checksum, applied_at, source_reference, runner_version FROM rq.read_schema_migrations()"
    );
    return res.rows.map((row) => ({
      migrationId: readRequiredString(row, "migration_id"),
      checksum: byteaToBuffer(row["checksum"], "checksum"),
      appliedAt: readRequiredUtcTimestamp(row, "applied_at"),
      sourceReference: readRequiredString(row, "source_reference"),
      runnerVersion: readRequiredString(row, "runner_version")
    }));
  } catch (err) {
    throw mapPostgresError(err, { operation: "rq.read_schema_migrations" });
  }
}

export async function registerRuntimeInstance(
  tx: PgTransactionClient,
  input: RegisterRuntimeInstanceParams
): Promise<RuntimeRegistrationResult> {
  const data = await callJsonbFunction(
    tx,
    "rq.cmd_runtime_register",
    ["uuid", "text", "text", "uuid", "text", "bigint", "integer"],
    [
      input.instanceId,
      input.processRole,
      input.databaseRole,
      input.controlEpoch,
      input.buildReference,
      toBigIntSqlParam(input.leaseMs, "leaseMs"),
      input.approvedSlots ?? 8
    ],
    "rq.cmd_runtime_register"
  );
  return {
    instanceId: readRequiredUuid(data, "instance_id", parseRuntimeInstanceId),
    processRole: readRequiredString(data, "process_role"),
    controlEpoch: readRequiredUuid(data, "control_epoch", parseControlEpoch),
    expiresAt: readJsonbTimestamp(data, "expires_at", "rq.cmd_runtime_register")
  };
}

export async function heartbeatRuntimeInstance(
  tx: PgTransactionClient,
  input: HeartbeatRuntimeInstanceParams
): Promise<RuntimeHeartbeatResult> {
  const data = await callJsonbFunction(
    tx,
    "rq.cmd_runtime_heartbeat",
    ["uuid", "uuid", "bigint"],
    [input.instanceId, input.controlEpoch, toBigIntSqlParam(input.leaseMs, "leaseMs")],
    "rq.cmd_runtime_heartbeat"
  );
  return {
    instanceId: readRequiredUuid(data, "instance_id", parseRuntimeInstanceId),
    state: readRequiredEnum(data, "state", RUNTIME_STATES),
    expiresAt: readJsonbTimestamp(data, "expires_at", "rq.cmd_runtime_heartbeat"),
    version: readRequiredInt64BigInt(data, "version")
  };
}

export async function findRuntimeInstanceById(
  tx: PgTransactionClient,
  instanceId: RuntimeInstanceId
): Promise<RuntimeInstanceRegistration | undefined> {
  const res = await tx.query<Record<string, unknown>>(
    `SELECT id, process_role, database_role, control_epoch, build_reference, state,
            started_at, last_seen_at, expires_at, version
       FROM rq.runtime_instances
      WHERE id = $1::uuid`,
    [instanceId]
  );
  const row = res.rows[0];
  if (row === undefined) {
    return undefined;
  }
  return {
    instanceId: readRequiredUuid(row, "id", parseRuntimeInstanceId),
    processRole: readRequiredString(row, "process_role") as ProcessRole,
    databaseRole: readRequiredString(row, "database_role"),
    controlEpoch: readRequiredUuid(row, "control_epoch", parseControlEpoch),
    buildReference: readRequiredString(row, "build_reference"),
    state: readRequiredEnum(row, "state", RUNTIME_STATES),
    startedAt: readRequiredInstant(row, "started_at"),
    lastSeenAt: readRequiredInstant(row, "last_seen_at"),
    expiresAt: readRequiredInstant(row, "expires_at"),
    version: readRequiredInt64BigInt(row, "version")
  };
}

export async function findTenantById(
  tx: PgTransactionClient,
  tenantId: TenantId
): Promise<TenantRecord | undefined> {
  const res = await tx.query<Record<string, unknown>>(
    `SELECT id, slug, display_name, state, governance_version, created_at, updated_at, version
       FROM rq.tenants
      WHERE id = $1::uuid`,
    [tenantId]
  );
  const row = res.rows[0];
  if (row === undefined) {
    return undefined;
  }
  return {
    id: readRequiredUuid(row, "id", parseTenantId),
    slug: readRequiredString(row, "slug"),
    displayName: readRequiredString(row, "display_name"),
    state: readRequiredEnum(row, "state", TENANT_STATES),
    governanceVersion: readRequiredInt64BigInt(row, "governance_version"),
    createdAt: readRequiredUtcTimestamp(row, "created_at"),
    updatedAt: readRequiredUtcTimestamp(row, "updated_at"),
    version: readRequiredInt64BigInt(row, "version")
  };
}

export async function findProjectById(
  tx: PgTransactionClient,
  tenantId: TenantId,
  projectId: ProjectId
): Promise<ProjectRecord | undefined> {
  const res = await tx.query<Record<string, unknown>>(
    `SELECT id, tenant_id, name, state, topology_version, next_event_sequence,
            governance_version, active_ordering_cutover_plan_id,
            projection_maintenance_operation_id, projection_maintenance_version,
            created_at, updated_at, version
       FROM rq.projects
      WHERE id = $1::uuid AND tenant_id = $2::uuid`,
    [projectId, tenantId]
  );
  const row = res.rows[0];
  if (row === undefined) {
    return undefined;
  }
  return mapProjectRow(row);
}

/**
 * Acquires a non-exclusive `FOR SHARE` row lock on `rq.projects` so ordinary delivery paths
 * never contend on `FOR UPDATE` locks against projection/fanout work.
 */
export async function lockProjectShare(
  tx: PgTransactionClient,
  tenantId: TenantId,
  projectId: ProjectId
): Promise<ProjectRecord> {
  const res = await tx.query<Record<string, unknown>>(
    `SELECT id, tenant_id, name, state, topology_version, next_event_sequence,
            governance_version, active_ordering_cutover_plan_id,
            projection_maintenance_operation_id, projection_maintenance_version,
            created_at, updated_at, version
       FROM rq.projects
      WHERE id = $1::uuid AND tenant_id = $2::uuid
      FOR SHARE`,
    [projectId, tenantId]
  );
  const row = res.rows[0];
  if (row === undefined) {
    throw new NotFoundDomainError({
      code: "NOT_FOUND",
      message: `Project ${projectId} not found in tenant ${tenantId}`,
      resourceRef: { kind: "project", id: projectId }
    });
  }
  return mapProjectRow(row);
}

function mapProjectRow(row: Record<string, unknown>): ProjectRecord {
  return {
    id: readRequiredUuid(row, "id", parseProjectId),
    tenantId: readRequiredUuid(row, "tenant_id", parseTenantId),
    name: readRequiredString(row, "name"),
    state: readRequiredEnum(row, "state", PROJECT_STATES),
    topologyVersion: readRequiredInt64BigInt(row, "topology_version"),
    nextEventSequence: readRequiredInt64BigInt(row, "next_event_sequence"),
    governanceVersion: readRequiredInt64BigInt(row, "governance_version"),
    activeOrderingCutoverPlanId: readOptionalUuid(row, "active_ordering_cutover_plan_id"),
    projectionMaintenanceOperationId: readOptionalUuid(row, "projection_maintenance_operation_id"),
    projectionMaintenanceVersion: readRequiredInt64BigInt(row, "projection_maintenance_version"),
    createdAt: readRequiredUtcTimestamp(row, "created_at"),
    updatedAt: readRequiredUtcTimestamp(row, "updated_at"),
    version: readRequiredInt64BigInt(row, "version")
  };
}

export async function findTenantMembership(
  tx: PgTransactionClient,
  tenantId: TenantId,
  principalId: PrincipalId
): Promise<
  | {
      readonly id: string;
      readonly role: TenantRole;
      readonly state: string;
      readonly authorityVersion: bigint;
    }
  | undefined
> {
  const res = await tx.query<Record<string, unknown>>(
    `SELECT id, role, state, authority_version
       FROM rq.tenant_memberships
      WHERE tenant_id = $1::uuid AND principal_id = $2::uuid`,
    [tenantId, principalId]
  );
  const row = res.rows[0];
  if (row === undefined) {
    return undefined;
  }
  return {
    id: readRequiredUuid(row, "id"),
    role: readRequiredString(row, "role") as TenantRole,
    state: readRequiredString(row, "state"),
    authorityVersion: readRequiredInt64BigInt(row, "authority_version")
  };
}

export async function findProjectMembership(
  tx: PgTransactionClient,
  tenantId: TenantId,
  projectId: ProjectId,
  principalId: PrincipalId
): Promise<
  | {
      readonly id: string;
      readonly role: ProjectRole;
      readonly state: string;
      readonly authorityVersion: bigint;
    }
  | undefined
> {
  const res = await tx.query<Record<string, unknown>>(
    `SELECT id, role, state, authority_version
       FROM rq.project_memberships
      WHERE tenant_id = $1::uuid AND project_id = $2::uuid AND principal_id = $3::uuid`,
    [tenantId, projectId, principalId]
  );
  const row = res.rows[0];
  if (row === undefined) {
    return undefined;
  }
  return {
    id: readRequiredUuid(row, "id"),
    role: readRequiredString(row, "role") as ProjectRole,
    state: readRequiredString(row, "state"),
    authorityVersion: readRequiredInt64BigInt(row, "authority_version")
  };
}

export async function listActiveHumanDataGrants(
  tx: PgTransactionClient,
  tenantId: TenantId,
  projectId: ProjectId,
  membershipId: string
): Promise<readonly HumanDataGrantRecord[]> {
  const res = await tx.query<Record<string, unknown>>(
    `SELECT id, membership_id, tenant_id, project_id, action, projection,
            producer_namespace, state, expires_at, version
       FROM rq.human_data_grants
      WHERE tenant_id = $1::uuid
        AND project_id = $2::uuid
        AND membership_id = $3::uuid
        AND state = 'active'
        AND (expires_at IS NULL OR expires_at > pg_catalog.clock_timestamp())
      ORDER BY created_at ASC`,
    [tenantId, projectId, membershipId]
  );
  return res.rows.map((row) => ({
    id: readRequiredUuid(row, "id", parseDataGrantId),
    membershipId: readRequiredUuid(row, "membership_id"),
    tenantId: readRequiredUuid(row, "tenant_id", parseTenantId),
    projectId: readRequiredUuid(row, "project_id", parseProjectId),
    action: readRequiredString(row, "action") as DataGrantAction,
    projection: readRequiredString(row, "projection") as DataGrantProjection,
    producerNamespace: readOptionalString(row, "producer_namespace"),
    state: readRequiredString(row, "state"),
    expiresAt:
      row["expires_at"] === null || row["expires_at"] === undefined
        ? undefined
        : readRequiredUtcTimestamp(row, "expires_at"),
    version: readRequiredInt64BigInt(row, "version")
  }));
}

export async function findProducerById(
  tx: PgTransactionClient,
  tenantId: TenantId,
  projectId: ProjectId,
  producerId: ProducerId
): Promise<
  | {
      readonly id: ProducerId;
      readonly principalId: PrincipalId;
      readonly name: string;
      readonly businessNamespace: string;
      readonly state: string;
      readonly currentScopeVersion: bigint;
      readonly authorityEpoch: bigint;
      readonly version: bigint;
    }
  | undefined
> {
  const res = await tx.query<Record<string, unknown>>(
    `SELECT id, principal_id, name, business_namespace, state,
            current_scope_version, authority_epoch, version
       FROM rq.producers
      WHERE id = $1::uuid AND tenant_id = $2::uuid AND project_id = $3::uuid`,
    [producerId, tenantId, projectId]
  );
  const row = res.rows[0];
  if (row === undefined) {
    return undefined;
  }
  return {
    id: readRequiredUuid(row, "id", parseProducerId),
    principalId: readRequiredUuid(row, "principal_id", parsePrincipalId),
    name: readRequiredString(row, "name"),
    businessNamespace: readRequiredString(row, "business_namespace"),
    state: readRequiredString(row, "state"),
    currentScopeVersion: readRequiredInt64BigInt(row, "current_scope_version"),
    authorityEpoch: readRequiredInt64BigInt(row, "authority_epoch"),
    version: readRequiredInt64BigInt(row, "version")
  };
}

export async function findActiveProducerScope(
  tx: PgTransactionClient,
  tenantId: TenantId,
  projectId: ProjectId,
  producerId: ProducerId,
  scopeVersion: BigIntInput
): Promise<
  | {
      readonly producerId: ProducerId;
      readonly scopeVersion: bigint;
      readonly scopeDefinition: Record<string, unknown>;
      readonly scopeSha256: Sha256Hex;
      readonly state: string;
    }
  | undefined
> {
  const res = await tx.query<Record<string, unknown>>(
    `SELECT producer_id, scope_version, scope_definition, scope_sha256, state
       FROM rq.producer_scope_versions
      WHERE producer_id = $1::uuid
        AND tenant_id = $2::uuid
        AND project_id = $3::uuid
        AND scope_version = $4::bigint`,
    [producerId, tenantId, projectId, toBigIntSqlParam(scopeVersion, "scopeVersion")]
  );
  const row = res.rows[0];
  if (row === undefined) {
    return undefined;
  }
  return {
    producerId: readRequiredUuid(row, "producer_id", parseProducerId),
    scopeVersion: readRequiredInt64BigInt(row, "scope_version"),
    scopeDefinition: readRequiredJsonRecord(row, "scope_definition"),
    scopeSha256: byteaToSha256Hex(row["scope_sha256"], "scope_sha256"),
    state: readRequiredString(row, "state")
  };
}

export async function finalizeSigningDeliveryIntent(
  tx: PgTransactionClient,
  input: FinalizeSigningDeliveryIntentParams
): Promise<{ readonly intentId: SigningDeliveryIntentId; readonly state: string }> {
  const data = await callJsonbFunction(
    tx,
    "rq.cmd_signing_delivery_finalize",
    ["uuid", "uuid", "text"],
    [input.intentId, input.controlEpoch, input.nextState],
    "rq.cmd_signing_delivery_finalize"
  );
  return {
    intentId: readRequiredUuid(data, "intent_id", parseSigningDeliveryIntentId),
    state: readRequiredString(data, "state")
  };
}

export async function finalizeProducerCredentialIntent(
  tx: PgTransactionClient,
  input: FinalizeProducerCredentialIntentParams
): Promise<{
  readonly intentId: string;
  readonly state: string;
  readonly credentialId: ProducerCredentialId;
}> {
  const data = await callJsonbFunction(
    tx,
    "rq.cmd_producer_credential_intent_finalize",
    ["uuid", "uuid", "text", "uuid", "bytea", "timestamptz"],
    [
      input.intentId,
      input.controlEpoch,
      input.nextState,
      input.credentialId,
      sha256HexToBytea(input.secretDigestSha256, "secretDigestSha256"),
      toTimestampSqlParam(input.expiresAt, "expiresAt")
    ],
    "rq.cmd_producer_credential_intent_finalize"
  );
  return {
    intentId: readRequiredUuid(data, "intent_id"),
    state: readRequiredString(data, "state"),
    credentialId: readRequiredUuid(data, "credential_id", parseProducerCredentialId)
  };
}

/**
 * PostgreSQL-backed `RuntimeRegistryStore` satisfying `@relayquill/runtime`'s interface
 * via `rq.cmd_runtime_register`, `rq.cmd_runtime_heartbeat`, and bounded transactions.
 */
export class PostgresRuntimeRegistryStore implements RuntimeRegistryStore {
  readonly #adapter: PgAdapter;
  readonly #databaseRole: string;

  constructor(adapter: PgAdapter, databaseRole = adapter.configuredRole) {
    this.#adapter = adapter;
    this.#databaseRole = databaseRole;
  }

  async registerInstance(input: RegisterRuntimeInstanceInput): Promise<RuntimeInstanceRegistration> {
    return this.#adapter.withTransaction(
      this.#databaseRole,
      async (tx) => {
        await registerRuntimeInstance(tx, {
          instanceId: input.instanceId,
          processRole: input.processRole,
          databaseRole: input.databaseRole,
          controlEpoch: input.controlEpoch,
          buildReference: input.buildReference,
          leaseMs: input.leaseMs
        });
        const stored = await findRuntimeInstanceById(tx, input.instanceId);
        if (stored !== undefined) {
          return stored;
        }
        return {
          instanceId: input.instanceId,
          processRole: input.processRole,
          databaseRole: input.databaseRole,
          controlEpoch: input.controlEpoch,
          buildReference: input.buildReference,
          state: "active",
          startedAt: input.now,
          lastSeenAt: input.now,
          expiresAt: Temporal.Instant.from(
            nowUtcInstant().add({ milliseconds: Number(input.leaseMs) })
          ),
          version: 1n
        };
      },
      { retryOnContention: true }
    );
  }

  async heartbeatInstance(
    input: HeartbeatRuntimeInstanceInput
  ): Promise<RuntimeInstanceRegistration> {
    return this.#adapter.withTransaction(
      this.#databaseRole,
      async (tx) => {
        const before = await findRuntimeInstanceById(tx, input.instanceId);
        if (before !== undefined && before.version !== input.expectedVersion) {
          throw new ConflictDomainError({
            code: "VERSION_CONFLICT",
            message: `Runtime instance ${input.instanceId} expected version ${input.expectedVersion}, found ${before.version}`
          });
        }
        const beat = await heartbeatRuntimeInstance(tx, {
          instanceId: input.instanceId,
          controlEpoch: input.controlEpoch,
          leaseMs: input.leaseMs
        });
        const after = await findRuntimeInstanceById(tx, input.instanceId);
        if (after !== undefined) {
          return after;
        }
        const expiresAt = parseUtcTimestamp(beat.expiresAt, "expiresAt").instant;
        return {
          instanceId: input.instanceId,
          processRole: before?.processRole ?? "api",
          databaseRole: before?.databaseRole ?? this.#databaseRole,
          controlEpoch: input.controlEpoch,
          buildReference: before?.buildReference ?? "unknown",
          state: beat.state,
          startedAt: before?.startedAt ?? input.now,
          lastSeenAt: input.now,
          expiresAt,
          version: beat.version
        };
      },
      { retryOnContention: true }
    );
  }

  async transitionInstanceState(
    input: TransitionRuntimeInstanceInput
  ): Promise<RuntimeInstanceRegistration> {
    return this.#adapter.withTransaction(
      this.#databaseRole,
      async (tx) => {
        const current = await findRuntimeInstanceById(tx, input.instanceId);
        if (current === undefined) {
          throw new NotFoundDomainError({
            code: "NOT_FOUND",
            message: `Runtime instance ${input.instanceId} not found`
          });
        }
        if (current.controlEpoch !== input.controlEpoch) {
          throw new ConflictDomainError({
            code: "VERSION_CONFLICT",
            message: `Runtime instance ${input.instanceId} control epoch mismatch`
          });
        }
        if (current.version !== input.expectedVersion) {
          throw new ConflictDomainError({
            code: "VERSION_CONFLICT",
            message: `Runtime instance ${input.instanceId} expected version ${input.expectedVersion}, found ${current.version}`
          });
        }
        assertTransition(
          `runtime_instances(${input.instanceId})`,
          ALLOWED_RUNTIME_INSTANCE_TRANSITIONS,
          current.state,
          input.toState
        );
        throw new ConflictDomainError({
          code: "STATE_TRANSITION_NOT_ALLOWED",
          message: `Direct runtime instance transition to "${input.toState}" is restricted to coordinator reaper or recovery commands`
        });
      },
      { readOnly: true }
    );
  }
}
