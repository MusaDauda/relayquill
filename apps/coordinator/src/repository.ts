import {
  ConflictDomainError,
  OUTBOX_STATES,
  RETENTION_ACTION_KINDS,
  RETENTION_ACTION_STATES,
  formatUtcTimestamp,
  nowUtcInstant,
  parseBrokerGenerationId,
  parseEventId,
  parseOutboxId,
  parseProjectId,
  parseRetentionActionId,
  parseRuntimeInstanceId,
  parseTenantId,
  type BrokerGenerationId,
  type CanonicalUtcTimestamp,
  type ControlEpoch,
  type EventId,
  type OutboxId,
  type OutboxState,
  type ProjectId,
  type PublicationRecoveryEpisodeId,
  type RetentionActionId,
  type RuntimeInstanceId,
  type TenantId
} from "@relayquill/domain";
import {
  decodeBrokerMessageId,
  decodeBrokerNotificationEnvelope,
  encodeBrokerMessageId,
  parseCanonicalUtcTimestamp
} from "@relayquill/contracts";
import {
  type ClaimOutboxRecord,
  type InstallationAuthoritySnapshot,
  type MaintenanceRepositoryPort,
  type OutboxPublicationRecord,
  type OutboxRowRecord,
  type ProjectProjectionDriftReport,
  type RelayRepositoryPort,
  type RetentionActionRecord,
  type RetentionHoldRecord
} from "@relayquill/application";
import {
  allocateOutboxRecoveryGeneration as pgAllocateOutboxRecoveryGeneration,
  byteaToBuffer,
  byteaToSha256Hex,
  claimOutboxEvent as pgClaimOutboxEvent,
  compactDeliveryTotalDeltas,
  finalizeRetentionAction as pgFinalizeRetentionAction,
  listActiveRetentionHolds as pgListActiveRetentionHolds,
  observeOutboxPublication as pgObserveOutboxPublication,
  type PgTransactionClient,
  readInstallationStatus,
  readOptionalString,
  readOptionalUtcTimestamp,
  readOptionalUuid,
  readProjectDeliveryTotals,
  readRequiredEnum,
  readRequiredInt64BigInt,
  readRequiredString,
  readRequiredUtcTimestamp,
  readRequiredUuid
} from "@relayquill/postgres";

export interface CoordinatorProjectScope {
  readonly tenantId: TenantId;
  readonly projectId: ProjectId;
}

export interface CoordinatorDeltaCompactionSummary {
  readonly compactedEvents: number;
  readonly compactedProjects: number;
}

function mapDbPublicationState(rawState: string): OutboxPublicationRecord["state"] {
  switch (rawState) {
    case "ack_observed":
      return "published";
    case "publish_unknown":
      return "publish_unknown";
    case "recovery_superseded":
      return "abandoned";
    case "prepared":
    default:
      return "pending";
  }
}

function tryExtractTraceContext(
  envelopeBytes: Uint8Array
): { readonly traceparent?: string | undefined; readonly tracestate?: string | undefined } {
  try {
    const decoded = decodeBrokerNotificationEnvelope(envelopeBytes);
    return {
      ...(decoded.traceparent !== undefined ? { traceparent: decoded.traceparent } : {}),
      ...(decoded.tracestate !== undefined ? { tracestate: decoded.tracestate } : {})
    };
  } catch {
    return {};
  }
}

function toCountBigInt(value: unknown): bigint {
  if (typeof value === "bigint") {
    return value;
  }
  if (typeof value === "number") {
    return BigInt(Math.trunc(value));
  }
  if (typeof value === "string" && /^-?\d+$/.test(value.trim())) {
    return BigInt(value.trim());
  }
  return 0n;
}

function mapApplicationHold(
  hold: Awaited<ReturnType<typeof pgListActiveRetentionHolds>>[number]
): RetentionHoldRecord {
  const mapped: RetentionHoldRecord = {
    id: hold.id,
    tenantId: hold.tenantId,
    targetKind: hold.targetKind,
    targetId: hold.targetId,
    reasonCode: hold.reasonCode,
    state: hold.state,
    version: hold.version,
    ...(hold.projectId !== undefined ? { projectId: hold.projectId } : {}),
    ...(hold.expiresAt !== undefined ? { expiresAt: hold.expiresAt } : {})
  };
  return mapped;
}

function clampLimit(limit: number, min = 1, max = 1000): number {
  return Math.max(min, Math.min(max, Math.trunc(limit)));
}

/**
 * Relay repository implementation for coordinator-initiated `publish_unknown`
 * recovery (read publications, recovery generation allocation, and broker publish).
 */
export class CoordinatorRelayRepository implements RelayRepositoryPort<PgTransactionClient> {
  async readInstallationAuthority(tx: PgTransactionClient): Promise<InstallationAuthoritySnapshot> {
    return readInstallationStatus(tx);
  }

  async listDueOutboxEvents(
    tx: PgTransactionClient,
    now: CanonicalUtcTimestamp,
    limit: number
  ): Promise<readonly OutboxRowRecord[]> {
    const clamped = clampLimit(limit, 1, 500);
    const res = await tx.query<Record<string, unknown>>(
      `SELECT o.id, o.event_id, o.tenant_id, o.project_id, o.topology_version, o.state,
              o.current_publication_generation, o.next_publish_at,
              op.broker_message_id, o.claim_owner_instance_id, o.claim_generation,
              o.claim_expires_at, o.last_safe_error_code, o.version,
              COALESCE(pre.successive_no_progress_generations, 0) AS no_progress_generations
         FROM rq.outbox_events o
         LEFT JOIN rq.outbox_publications op
           ON op.outbox_id = o.id
          AND op.publication_generation = o.current_publication_generation
         LEFT JOIN rq.publication_recovery_episodes pre
           ON pre.outbox_id = o.id
          AND pre.state = 'active'
        WHERE o.state IN ('pending', 'claimed')
          AND o.next_publish_at <= $1::timestamptz
          AND (o.claim_expires_at IS NULL OR o.claim_expires_at <= $1::timestamptz)
        ORDER BY o.next_publish_at ASC, o.id ASC
        LIMIT $2::integer`,
      [now, clamped]
    );

    return res.rows.map((row) => mapOutboxRow(row));
  }

  async claimOutboxEvent(
    tx: PgTransactionClient,
    params: {
      readonly outboxId: OutboxId;
      readonly instanceId: RuntimeInstanceId;
      readonly controlEpoch: ControlEpoch;
      readonly claimLeaseMs: bigint;
      readonly now: CanonicalUtcTimestamp;
    }
  ): Promise<ClaimOutboxRecord> {
    const claimed = await pgClaimOutboxEvent(tx, {
      outboxId: params.outboxId,
      instanceId: params.instanceId,
      controlEpoch: params.controlEpoch,
      claimLeaseMs: params.claimLeaseMs
    });
    const trace = tryExtractTraceContext(claimed.envelopeBytes);
    return {
      outboxId: claimed.outboxId,
      eventId: claimed.eventId,
      projectId: claimed.projectId,
      publicationGeneration: claimed.publicationGeneration,
      claimGeneration: claimed.claimGeneration,
      claimExpiresAt: claimed.claimExpiresAt,
      brokerMessageId: decodeBrokerMessageId(claimed.brokerMessageId, "broker_message_id").message_id,
      envelopeBytes: new Uint8Array(claimed.envelopeBytes),
      ...trace
    };
  }

  async observeOutboxPublication(
    tx: PgTransactionClient,
    params: Parameters<RelayRepositoryPort<PgTransactionClient>["observeOutboxPublication"]>[1]
  ): Promise<{
    readonly acceptedAsCurrent: boolean;
    readonly outboxState: OutboxState;
    readonly publicationState: string;
  }> {
    const observed = await pgObserveOutboxPublication(tx, {
      outboxId: params.outboxId,
      publicationGeneration: params.publicationGeneration,
      instanceId: params.instanceId,
      controlEpoch: params.controlEpoch,
      expectedClaimGeneration: params.expectedClaimGeneration,
      outcome: params.outcome,
      brokerGenerationId: params.brokerGenerationId,
      streamName: params.streamName,
      streamSequence: params.streamSequence,
      ackDuplicate: params.ackDuplicate,
      safeErrorCode: params.safeErrorCode,
      nextPublishAt: params.nextPublishAt,
      observationId: params.observationId
    });
    return {
      acceptedAsCurrent: observed.acceptedAsCurrent,
      outboxState: observed.outboxState,
      publicationState: observed.publicationState ?? "unknown"
    };
  }

  async listOutboxPublications(
    tx: PgTransactionClient,
    outboxId: OutboxId
  ): Promise<readonly OutboxPublicationRecord[]> {
    const res = await tx.query<Record<string, unknown>>(
      `SELECT publication_generation, envelope_sha256, envelope_bytes,
              broker_message_id, state, stream_name, stream_sequence,
              first_broker_generation_id
         FROM rq.outbox_publications
        WHERE outbox_id = $1::uuid
        ORDER BY publication_generation ASC`,
      [outboxId]
    );

    return res.rows.map((row): OutboxPublicationRecord => {
      const streamName = readOptionalString(row, "stream_name");
      const rawSeq = row["stream_sequence"];
      const streamSequence =
        rawSeq === null || rawSeq === undefined
          ? undefined
          : readRequiredInt64BigInt(row, "stream_sequence");
      const firstBrokerGenerationId: BrokerGenerationId | undefined = readOptionalUuid(
        row,
        "first_broker_generation_id",
        parseBrokerGenerationId
      );

      return {
        publicationGeneration: readRequiredInt64BigInt(row, "publication_generation"),
        envelopeSha256: byteaToSha256Hex(row["envelope_sha256"], "envelope_sha256"),
        envelopeBytes: new Uint8Array(byteaToBuffer(row["envelope_bytes"], "envelope_bytes")),
        brokerMessageId: decodeBrokerMessageId(
          readRequiredString(row, "broker_message_id"),
          "broker_message_id"
        ).message_id,
        state: mapDbPublicationState(readRequiredString(row, "state")),
        ...(streamName !== undefined ? { streamName } : {}),
        ...(streamSequence !== undefined ? { streamSequence } : {}),
        ...(firstBrokerGenerationId !== undefined ? { firstBrokerGenerationId } : {})
      };
    });
  }

  async allocateOutboxRecoveryGeneration(
    tx: PgTransactionClient,
    params: Parameters<RelayRepositoryPort<PgTransactionClient>["allocateOutboxRecoveryGeneration"]>[1]
  ): Promise<{
    readonly outcome: "already_complete" | "review_required" | "allocated";
    readonly episodeId?: PublicationRecoveryEpisodeId | undefined;
    readonly eventId?: EventId | undefined;
    readonly publicationGeneration?: bigint | undefined;
  }> {
    const res = await pgAllocateOutboxRecoveryGeneration(tx, {
      outboxId: params.outboxId,
      episodeId: params.episodeId,
      instanceId: params.instanceId,
      controlEpoch: params.controlEpoch,
      envelopeBytes: params.envelopeBytes,
      envelopeSha256: params.envelopeSha256,
      brokerMessageId: params.brokerMessageId,
      reasonCode: params.reasonCode
    });
    return {
      outcome: res.outcome,
      ...(res.episodeId !== undefined
        ? { episodeId: res.episodeId as PublicationRecoveryEpisodeId }
        : {}),
      ...(res.eventId !== undefined ? { eventId: res.eventId } : {}),
      ...(res.publicationGeneration !== undefined
        ? { publicationGeneration: res.publicationGeneration }
        : {})
    };
  }
}

function mapOutboxRow(row: Record<string, unknown>): OutboxRowRecord {
  const outboxId = readRequiredUuid(row, "id", parseOutboxId);
  const generation = readRequiredInt64BigInt(row, "current_publication_generation");
  const rawMsgId = readOptionalString(row, "broker_message_id");
  const brokerMessageId =
    rawMsgId !== undefined
      ? decodeBrokerMessageId(rawMsgId, "broker_message_id").message_id
      : encodeBrokerMessageId(outboxId, generation);
  const claimOwnerInstanceId = readOptionalUuid(
    row,
    "claim_owner_instance_id",
    parseRuntimeInstanceId
  );
  const claimExpiresAt = readOptionalUtcTimestamp(row, "claim_expires_at");
  const lastSafeErrorCode = readOptionalString(row, "last_safe_error_code");
  const rawNoProgress = row["no_progress_generations"];
  const noProgressGenerationCount =
    rawNoProgress === undefined || rawNoProgress === null ? 0 : Number(rawNoProgress);

  return {
    outboxId,
    eventId: readRequiredUuid(row, "event_id", parseEventId),
    tenantId: readRequiredUuid(row, "tenant_id", parseTenantId),
    projectId: readRequiredUuid(row, "project_id", parseProjectId),
    topologyVersion: readRequiredInt64BigInt(row, "topology_version"),
    state: readRequiredEnum(row, "state", OUTBOX_STATES),
    currentPublicationGeneration: generation,
    nextPublishAt: readRequiredUtcTimestamp(row, "next_publish_at"),
    brokerMessageId,
    ...(claimOwnerInstanceId !== undefined ? { claimOwnerInstanceId } : {}),
    claimGeneration: readRequiredInt64BigInt(row, "claim_generation"),
    ...(claimExpiresAt !== undefined ? { claimExpiresAt } : {}),
    recoveryAttemptCount: noProgressGenerationCount,
    noProgressGenerationCount,
    ...(lastSafeErrorCode !== undefined ? { lastSafeErrorCode } : {}),
    version: readRequiredInt64BigInt(row, "version")
  };
}

/**
 * PostgreSQL maintenance repository implementing `MaintenanceRepositoryPort`
 * over `rq.*` tables and `SECURITY DEFINER` coordinator procedures.
 */
export class PostgresMaintenanceRepository implements MaintenanceRepositoryPort<PgTransactionClient> {
  async promoteDueWork(
    tx: PgTransactionClient,
    now: CanonicalUtcTimestamp,
    limit: number
  ): Promise<{ readonly promotedDeliveries: number; readonly promotedOutbox: number }> {
    const bounded = clampLimit(limit, 1, 1000);

    const deliveryRes = await tx.query<{ id: string }>(
      `WITH candidates AS (
         SELECT d.id
           FROM rq.deliveries d
           JOIN rq.projects p
             ON p.id = d.project_id
            AND p.tenant_id = d.tenant_id
          WHERE d.state IN ('pending', 'retry_wait')
            AND d.next_eligible_at <= $1::timestamptz
            AND d.deadline_at > $1::timestamptz
            AND d.current_attempt_id IS NULL
            AND p.projection_maintenance_operation_id IS NULL
          ORDER BY d.next_eligible_at ASC, d.id ASC
          LIMIT $2::integer
          FOR UPDATE OF d SKIP LOCKED
       )
       UPDATE rq.deliveries d
          SET state = 'ready',
              updated_at = $1::timestamptz,
              version = d.version + 1
         FROM candidates c
        WHERE d.id = c.id
        RETURNING d.id`,
      [now, bounded]
    );

    const outboxRes = await tx.query<{ id: string }>(
      `WITH candidates AS (
         SELECT o.id
           FROM rq.outbox_events o
           JOIN rq.outbox_publications op
             ON op.outbox_id = o.id
            AND op.publication_generation = o.current_publication_generation
          WHERE o.state = 'pending'
            AND o.next_publish_at <= $1::timestamptz
            AND o.last_safe_error_code IS NOT NULL
            AND op.state <> 'publish_unknown'
          ORDER BY o.next_publish_at ASC, o.id ASC
          LIMIT $2::integer
          FOR UPDATE OF o SKIP LOCKED
       )
       UPDATE rq.outbox_events o
          SET last_safe_error_code = NULL,
              updated_at = $1::timestamptz,
              version = o.version + 1
         FROM candidates c
        WHERE o.id = c.id
        RETURNING o.id`,
      [now, bounded]
    );

    return {
      promotedDeliveries: deliveryRes.rows.length,
      promotedOutbox: outboxRes.rows.length
    };
  }

  async reapExpiredCoordinatorWork(
    tx: PgTransactionClient,
    params: {
      readonly instanceId: RuntimeInstanceId;
      readonly controlEpoch: ControlEpoch;
      readonly batchLimit: number;
      readonly now: CanonicalUtcTimestamp;
    }
  ): Promise<{
    readonly reapedAttempts: number;
    readonly reapedOutboxClaims: number;
    readonly reapedFanoutClaims: number;
    readonly reapedWatchLeases: number;
  }> {
    const bounded = clampLimit(params.batchLimit, 1, 500);
    const procRes = await tx.query<Record<string, unknown>>(
      `SELECT rq.cmd_coordinator_reap_expired($1::uuid, $2::uuid, $3::integer) AS result`,
      [params.instanceId, params.controlEpoch, bounded]
    );
    const procData = procRes.rows[0]?.["result"] as Record<string, unknown> | undefined;
    const reapedAttempts = Number(procData?.["reaped_attempts"] ?? 0);
    const reapedWatchLeases = Number(procData?.["reaped_watch_leases"] ?? 0);

    const reapedOutbox = await tx.query<{ id: string }>(
      `WITH candidates AS (
         SELECT id
           FROM rq.outbox_events
          WHERE state = 'claimed'
            AND claim_expires_at <= $1::timestamptz
          ORDER BY claim_expires_at ASC, id ASC
          LIMIT $2::integer
          FOR UPDATE SKIP LOCKED
       )
       UPDATE rq.outbox_events o
          SET state = 'pending',
              claim_owner_instance_id = NULL,
              claim_control_epoch = NULL,
              claim_expires_at = NULL,
              next_publish_at = LEAST(o.next_publish_at, $1::timestamptz),
              last_safe_error_code = 'OUTBOX_CLAIM_EXPIRED',
              updated_at = $1::timestamptz,
              version = o.version + 1
         FROM candidates c
        WHERE o.id = c.id
        RETURNING o.id`,
      [params.now, bounded]
    );

    const reapedFanout = await tx.query<{ event_id: string }>(
      `WITH candidates AS (
         SELECT event_id
           FROM rq.event_fanout
          WHERE state IN ('pending', 'materializing')
            AND claim_owner_instance_id IS NOT NULL
            AND claim_expires_at <= $1::timestamptz
          ORDER BY claim_expires_at ASC, event_id ASC
          LIMIT $2::integer
          FOR UPDATE SKIP LOCKED
       )
       UPDATE rq.event_fanout ef
          SET claim_owner_instance_id = NULL,
              claim_control_epoch = NULL,
              claim_expires_at = NULL,
              safe_error_code = 'FANOUT_CLAIM_EXPIRED',
              version = ef.version + 1
         FROM candidates c
        WHERE ef.event_id = c.event_id
        RETURNING ef.event_id`,
      [params.now, bounded]
    );

    return {
      reapedAttempts,
      reapedOutboxClaims: reapedOutbox.rows.length,
      reapedFanoutClaims: reapedFanout.rows.length,
      reapedWatchLeases
    };
  }

  async listUnknownPublicationOutbox(
    tx: PgTransactionClient,
    now: CanonicalUtcTimestamp,
    limit: number
  ): Promise<readonly OutboxRowRecord[]> {
    const clamped = clampLimit(limit, 1, 100);
    const res = await tx.query<Record<string, unknown>>(
      `SELECT o.id, o.event_id, o.tenant_id, o.project_id, o.topology_version, o.state,
              o.current_publication_generation, o.next_publish_at,
              op.broker_message_id, o.claim_owner_instance_id, o.claim_generation,
              o.claim_expires_at, o.last_safe_error_code, o.version,
              COALESCE(pre.successive_no_progress_generations, 0) AS no_progress_generations
         FROM rq.outbox_events o
         JOIN rq.outbox_publications op
           ON op.outbox_id = o.id
          AND op.publication_generation = o.current_publication_generation
         LEFT JOIN rq.publication_recovery_episodes pre
           ON pre.outbox_id = o.id
          AND pre.state = 'active'
        WHERE o.state IN ('pending', 'claimed')
          AND op.state = 'publish_unknown'
          AND o.next_publish_at <= $1::timestamptz
          AND (o.claim_expires_at IS NULL OR o.claim_expires_at <= $1::timestamptz)
        ORDER BY o.next_publish_at ASC, o.id ASC
        LIMIT $2::integer`,
      [now, clamped]
    );

    return res.rows.map((row) => mapOutboxRow(row));
  }

  async markOutboxReviewRequired(
    tx: PgTransactionClient,
    params: {
      readonly outboxId: OutboxId;
      readonly episodeId: PublicationRecoveryEpisodeId;
      readonly reasonCode: string;
      readonly now: CanonicalUtcTimestamp;
    }
  ): Promise<void> {
    const outboxRes = await tx.query<Record<string, unknown>>(
      `SELECT id, event_id, current_publication_generation, claim_control_epoch
         FROM rq.outbox_events
        WHERE id = $1::uuid
        FOR UPDATE`,
      [params.outboxId]
    );
    const outboxRow = outboxRes.rows[0];
    if (outboxRow === undefined) {
      return;
    }
    const eventId = readRequiredUuid(outboxRow, "event_id", parseEventId);
    const currentGen = readRequiredInt64BigInt(outboxRow, "current_publication_generation");

    await tx.query(
      `UPDATE rq.outbox_publications
          SET state = 'recovery_superseded'
        WHERE outbox_id = $1::uuid
          AND publication_generation = $2::bigint
          AND state IN ('prepared', 'publish_unknown')`,
      [params.outboxId, currentGen.toString(10)]
    );

    const epRes = await tx.query<{ id: string }>(
      `UPDATE rq.publication_recovery_episodes
          SET state = 'review_required',
              last_generation_at = $2::timestamptz,
              version = version + 1
        WHERE outbox_id = $1::uuid
          AND state = 'active'
        RETURNING id`,
      [params.outboxId, params.now]
    );

    if (epRes.rows.length === 0) {
      const fanoutRes = await tx.query<Record<string, unknown>>(
        `SELECT ef.version, i.control_epoch
           FROM rq.event_fanout ef
           CROSS JOIN rq.installation_state i
          WHERE ef.event_id = $1::uuid
            AND i.id = 1`,
        [eventId]
      );
      const fanoutRow = fanoutRes.rows[0];
      const fanoutVersion =
        fanoutRow !== undefined ? readRequiredInt64BigInt(fanoutRow, "version") : 1n;
      const controlEpoch =
        fanoutRow !== undefined
          ? readRequiredString(fanoutRow, "control_epoch")
          : (await readInstallationStatus(tx)).controlEpoch;

      await tx.query(
        `INSERT INTO rq.publication_recovery_episodes (
           id, outbox_id, event_id, control_epoch, state, starting_fanout_version,
           last_progress_boundary_sha256, successive_no_progress_generations,
           last_generation_at, created_at, version
         )
         VALUES (
           $1::uuid, $2::uuid, $3::uuid, $4::uuid, 'review_required', $5::bigint,
           pg_catalog.sha256(pg_catalog.convert_to($6::text, 'UTF8')), 5,
           $7::timestamptz, $7::timestamptz, 1
         )
         ON CONFLICT DO NOTHING`,
        [
          params.episodeId,
          params.outboxId,
          eventId,
          controlEpoch,
          fanoutVersion.toString(10),
          fanoutVersion.toString(10),
          params.now
        ]
      );
    }

    await tx.query(
      `UPDATE rq.outbox_events
          SET state = 'blocked',
              claim_owner_instance_id = NULL,
              claim_control_epoch = NULL,
              claim_expires_at = NULL,
              last_safe_error_code = $2::text,
              updated_at = $3::timestamptz,
              version = version + 1
        WHERE id = $1::uuid`,
      [params.outboxId, params.reasonCode, params.now]
    );
  }

  async listActiveRetentionHolds(
    tx: PgTransactionClient,
    tenantId: TenantId,
    projectId?: ProjectId
  ): Promise<readonly RetentionHoldRecord[]> {
    const holds = await pgListActiveRetentionHolds(tx, tenantId, projectId);
    return holds.map((hold) => mapApplicationHold(hold));
  }

  async listDueRetentionActions(
    tx: PgTransactionClient,
    now: CanonicalUtcTimestamp,
    limit: number
  ): Promise<readonly RetentionActionRecord[]> {
    const clamped = clampLimit(limit, 1, 100);
    const res = await tx.query<Record<string, unknown>>(
      `SELECT id, tenant_id, project_id, target_kind, target_id, action, state,
              claim_generation, next_attempt_at, version
         FROM rq.retention_actions
        WHERE state IN ('ready', 'failed_retryable')
          AND next_attempt_at <= $1::timestamptz
        ORDER BY next_attempt_at ASC, id ASC
        LIMIT $2::integer`,
      [now, clamped]
    );

    return res.rows.map((row): RetentionActionRecord => {
      const projectId = readOptionalUuid(row, "project_id", parseProjectId);
      return {
        actionId: readRequiredUuid(row, "id", parseRetentionActionId),
        tenantId: readRequiredUuid(row, "tenant_id", parseTenantId),
        ...(projectId !== undefined ? { projectId } : {}),
        targetKind: readRequiredString(row, "target_kind"),
        targetId: readRequiredUuid(row, "target_id"),
        action: readRequiredEnum(row, "action", RETENTION_ACTION_KINDS),
        state: readRequiredEnum(row, "state", RETENTION_ACTION_STATES),
        claimGeneration: readRequiredInt64BigInt(row, "claim_generation"),
        nextAttemptAt: readRequiredUtcTimestamp(row, "next_attempt_at"),
        version: readRequiredInt64BigInt(row, "version")
      };
    });
  }

  async claimRetentionAction(
    tx: PgTransactionClient,
    params: {
      readonly actionId: RetentionActionId;
      readonly instanceId: RuntimeInstanceId;
      readonly controlEpoch: ControlEpoch;
      readonly claimLeaseMs: bigint;
      readonly now: CanonicalUtcTimestamp;
    }
  ): Promise<{ readonly claimed: boolean; readonly claimGeneration: bigint }> {
    const leaseMs = params.claimLeaseMs > 0n ? params.claimLeaseMs : 30_000n;
    const res = await tx.query<Record<string, unknown>>(
      `UPDATE rq.retention_actions
          SET state = 'claimed',
              owner_instance_id = $2::uuid,
              claim_control_epoch = $3::uuid,
              claim_generation = claim_generation + 1,
              claim_expires_at = $5::timestamptz + ($4::bigint * interval '1 millisecond'),
              version = version + 1
        WHERE id = $1::uuid
          AND (
            (state IN ('ready', 'failed_retryable') AND next_attempt_at <= $5::timestamptz)
            OR (state = 'claimed' AND claim_expires_at <= $5::timestamptz)
          )
        RETURNING claim_generation`,
      [params.actionId, params.instanceId, params.controlEpoch, leaseMs.toString(10), params.now]
    );

    const row = res.rows[0];
    if (row === undefined) {
      return { claimed: false, claimGeneration: 0n };
    }
    return {
      claimed: true,
      claimGeneration: readRequiredInt64BigInt(row, "claim_generation")
    };
  }

  async finalizeRetentionAction(
    tx: PgTransactionClient,
    params: {
      readonly actionId: RetentionActionId;
      readonly instanceId: RuntimeInstanceId;
      readonly controlEpoch: ControlEpoch;
      readonly claimGeneration: bigint;
      readonly now: CanonicalUtcTimestamp;
    }
  ): Promise<{ readonly outcome: "already_complete" | "completed"; readonly actionId: RetentionActionId }> {
    const finalized = await pgFinalizeRetentionAction(tx, {
      actionId: params.actionId,
      instanceId: params.instanceId,
      controlEpoch: params.controlEpoch,
      claimGeneration: params.claimGeneration
    });
    return {
      outcome: finalized.outcome,
      actionId: finalized.actionId
    };
  }

  async verifyProjectDeliveryProjection(
    tx: PgTransactionClient,
    tenantId: TenantId,
    projectId: ProjectId
  ): Promise<ProjectProjectionDriftReport> {
    const totals = await readProjectDeliveryTotals(tx, tenantId, projectId);
    const liveRes = await tx.query<Record<string, unknown>>(
      `SELECT COUNT(*)::bigint AS total_deliveries,
              COUNT(*) FILTER (WHERE state IN ('pending', 'ready', 'retry_wait'))::bigint AS pending_count,
              COUNT(*) FILTER (WHERE state = 'sending')::bigint AS active_count,
              COUNT(*) FILTER (WHERE state = 'acknowledged')::bigint AS acknowledged_count,
              COUNT(*) FILTER (WHERE state = 'dead_letter')::bigint AS dead_letter_count,
              COUNT(*) FILTER (WHERE state = 'suppressed')::bigint AS suppressed_count,
              COUNT(*) FILTER (WHERE state = 'expired')::bigint AS expired_count
         FROM rq.deliveries
        WHERE tenant_id = $1::uuid
          AND project_id = $2::uuid`,
      [tenantId, projectId]
    );
    const live = liveRes.rows[0] ?? {};

    const stored = {
      totalDeliveries: totals.totalDeliveries,
      pendingCount: totals.pendingCount,
      activeCount: totals.activeCount,
      acknowledgedCount: totals.acknowledgedCount,
      deadLetterCount: totals.deadLetterCount,
      suppressedCount: totals.suppressedCount,
      expiredCount: totals.expiredCount
    };
    const computed = {
      totalDeliveries: toCountBigInt(live["total_deliveries"]),
      pendingCount: toCountBigInt(live["pending_count"]),
      activeCount: toCountBigInt(live["active_count"]),
      acknowledgedCount: toCountBigInt(live["acknowledged_count"]),
      deadLetterCount: toCountBigInt(live["dead_letter_count"]),
      suppressedCount: toCountBigInt(live["suppressed_count"]),
      expiredCount: toCountBigInt(live["expired_count"])
    };

    const consistent =
      stored.totalDeliveries === computed.totalDeliveries &&
      stored.pendingCount === computed.pendingCount &&
      stored.activeCount === computed.activeCount &&
      stored.acknowledgedCount === computed.acknowledgedCount &&
      stored.deadLetterCount === computed.deadLetterCount &&
      stored.suppressedCount === computed.suppressedCount &&
      stored.expiredCount === computed.expiredCount;

    return {
      tenantId,
      projectId,
      consistent,
      stored,
      computed
    };
  }

  async rebuildProjectDeliveryProjection(
    tx: PgTransactionClient,
    tenantId: TenantId,
    projectId: ProjectId,
    now: CanonicalUtcTimestamp
  ): Promise<ProjectProjectionDriftReport> {
    await this.#compactEventsForProject(tx, tenantId, projectId, 100);
    return this.#rebuildProjectTotalsOnly(tx, tenantId, projectId, now);
  }

  async #rebuildProjectTotalsOnly(
    tx: PgTransactionClient,
    tenantId: TenantId,
    projectId: ProjectId,
    now: CanonicalUtcTimestamp
  ): Promise<ProjectProjectionDriftReport> {
    const liveRes = await tx.query<Record<string, unknown>>(
      `SELECT COUNT(*)::bigint AS total_deliveries,
              COUNT(*) FILTER (WHERE state IN ('pending', 'ready', 'retry_wait'))::bigint AS pending_count,
              COUNT(*) FILTER (WHERE state = 'sending')::bigint AS active_count,
              COUNT(*) FILTER (WHERE state = 'acknowledged')::bigint AS acknowledged_count,
              COUNT(*) FILTER (WHERE state = 'dead_letter')::bigint AS dead_letter_count,
              COUNT(*) FILTER (WHERE state = 'suppressed')::bigint AS suppressed_count,
              COUNT(*) FILTER (WHERE state = 'expired')::bigint AS expired_count
         FROM rq.deliveries
        WHERE tenant_id = $1::uuid
          AND project_id = $2::uuid`,
      [tenantId, projectId]
    );
    const live = liveRes.rows[0] ?? {};
    const computed = {
      totalDeliveries: toCountBigInt(live["total_deliveries"]),
      pendingCount: toCountBigInt(live["pending_count"]),
      activeCount: toCountBigInt(live["active_count"]),
      acknowledgedCount: toCountBigInt(live["acknowledged_count"]),
      deadLetterCount: toCountBigInt(live["dead_letter_count"]),
      suppressedCount: toCountBigInt(live["suppressed_count"]),
      expiredCount: toCountBigInt(live["expired_count"])
    };

    const deltaObsRes = await tx.query<Record<string, unknown>>(
      `SELECT COALESCE(SUM(unknown_attempt_observations_delta), 0)::bigint AS unk
         FROM rq.project_delivery_total_deltas
        WHERE tenant_id = $1::uuid AND project_id = $2::uuid`,
      [tenantId, projectId]
    );
    const unknownObsDelta = toCountBigInt(deltaObsRes.rows[0]?.["unk"]);

    await tx.query(
      `DELETE FROM rq.project_delivery_total_deltas
        WHERE tenant_id = $1::uuid AND project_id = $2::uuid`,
      [tenantId, projectId]
    );

    await tx.query(
      `INSERT INTO rq.project_delivery_totals (
         project_id, tenant_id, total_deliveries, pending_count, active_count,
         acknowledged_count, dead_letter_count, suppressed_count, expired_count,
         unknown_attempt_observations, updated_at, version
       )
       VALUES (
         $2::uuid, $1::uuid, $3::bigint, $4::bigint, $5::bigint,
         $6::bigint, $7::bigint, $8::bigint, $9::bigint,
         $11::bigint, $10::timestamptz, 1
       )
       ON CONFLICT (project_id) DO UPDATE
         SET total_deliveries = EXCLUDED.total_deliveries,
             pending_count = EXCLUDED.pending_count,
             active_count = EXCLUDED.active_count,
             acknowledged_count = EXCLUDED.acknowledged_count,
             dead_letter_count = EXCLUDED.dead_letter_count,
             suppressed_count = EXCLUDED.suppressed_count,
             expired_count = EXCLUDED.expired_count,
             unknown_attempt_observations = rq.project_delivery_totals.unknown_attempt_observations + EXCLUDED.unknown_attempt_observations,
             updated_at = $10::timestamptz,
             version = rq.project_delivery_totals.version + 1`,
      [
        tenantId,
        projectId,
        computed.totalDeliveries.toString(10),
        computed.pendingCount.toString(10),
        computed.activeCount.toString(10),
        computed.acknowledgedCount.toString(10),
        computed.deadLetterCount.toString(10),
        computed.suppressedCount.toString(10),
        computed.expiredCount.toString(10),
        now,
        unknownObsDelta.toString(10)
      ]
    );

    return {
      tenantId,
      projectId,
      consistent: true,
      stored: { ...computed },
      computed
    };
  }

  async #safeCompactScope(
    tx: PgTransactionClient,
    tenantId: TenantId,
    projectId: ProjectId,
    eventId?: EventId
  ): Promise<void> {
    await tx.query("SAVEPOINT rq_coord_compact");
    try {
      await compactDeliveryTotalDeltas(tx, {
        tenantId,
        projectId,
        ...(eventId !== undefined ? { eventId } : {})
      });
      await tx.query("RELEASE SAVEPOINT rq_coord_compact");
    } catch (err) {
      await tx.query("ROLLBACK TO SAVEPOINT rq_coord_compact");
      // PostgreSQL checks table CHECK constraints on INSERT VALUES before checking ON CONFLICT DO UPDATE;
      // fall back cleanly when aggregated shard deltas contain negative adjustments against an existing base row.
      if (err instanceof ConflictDomainError && err.code === "STATE_TRANSITION_NOT_ALLOWED") {
        const now = parseCanonicalUtcTimestamp(formatUtcTimestamp(nowUtcInstant()), "now");
        if (eventId !== undefined) {
          await tx.query(
            `UPDATE rq.event_delivery_totals edt
                SET total_deliveries = live.total_deliveries,
                    terminal_deliveries = live.terminal_deliveries,
                    acknowledged_deliveries = live.acknowledged_deliveries,
                    updated_at = $4::timestamptz,
                    version = edt.version + 1
               FROM (
                 SELECT COUNT(*)::bigint AS total_deliveries,
                        COUNT(*) FILTER (WHERE state IN ('acknowledged', 'dead_letter', 'suppressed', 'expired'))::bigint AS terminal_deliveries,
                        COUNT(*) FILTER (WHERE state = 'acknowledged')::bigint AS acknowledged_deliveries
                   FROM rq.deliveries
                  WHERE tenant_id = $1::uuid AND project_id = $2::uuid AND event_id = $3::uuid
               ) live
              WHERE edt.tenant_id = $1::uuid AND edt.project_id = $2::uuid AND edt.event_id = $3::uuid`,
            [tenantId, projectId, eventId, now]
          );
          await tx.query(
            `DELETE FROM rq.event_delivery_total_deltas
              WHERE tenant_id = $1::uuid AND project_id = $2::uuid AND event_id = $3::uuid`,
            [tenantId, projectId, eventId]
          );
        }
        await this.#rebuildProjectTotalsOnly(tx, tenantId, projectId, now);
        return;
      }
      throw err;
    }
  }

  async #compactEventsForProject(
    tx: PgTransactionClient,
    tenantId: TenantId,
    projectId: ProjectId,
    limit: number
  ): Promise<void> {
    const bounded = clampLimit(limit, 1, 500);
    const eventRows = await tx.query<Record<string, unknown>>(
      `SELECT DISTINCT event_id
         FROM rq.event_delivery_total_deltas
        WHERE tenant_id = $1::uuid AND project_id = $2::uuid
        LIMIT $3::integer`,
      [tenantId, projectId, bounded]
    );
    for (const row of eventRows.rows) {
      const eventId = readRequiredUuid(row, "event_id", parseEventId);
      await this.#safeCompactScope(tx, tenantId, projectId, eventId);
    }
  }

  /**
   * Compacts up to `batchLimit` pending 16-shard event/project delivery delta buckets
   * into `rq.event_delivery_totals` and `rq.project_delivery_totals`.
   */
  async compactDueDeltaShards(
    tx: PgTransactionClient,
    batchLimit: number
  ): Promise<CoordinatorDeltaCompactionSummary> {
    const bounded = clampLimit(batchLimit, 1, 500);

    const eventScopesRes = await tx.query<Record<string, unknown>>(
      `SELECT DISTINCT tenant_id, project_id, event_id
         FROM rq.event_delivery_total_deltas
        ORDER BY project_id ASC, event_id ASC
        LIMIT $1::integer`,
      [bounded]
    );

    let compactedEvents = 0;
    const touchedProjects = new Set<string>();
    const projectScopes: CoordinatorProjectScope[] = [];

    for (const row of eventScopesRes.rows) {
      const tenantId = readRequiredUuid(row, "tenant_id", parseTenantId);
      const projectId = readRequiredUuid(row, "project_id", parseProjectId);
      const eventId = readRequiredUuid(row, "event_id", parseEventId);
      await this.#safeCompactScope(tx, tenantId, projectId, eventId);
      compactedEvents += 1;
      touchedProjects.add(`${tenantId}:${projectId}`);
    }

    const projectScopesRes = await tx.query<Record<string, unknown>>(
      `SELECT DISTINCT tenant_id, project_id
         FROM rq.project_delivery_total_deltas
        ORDER BY project_id ASC
        LIMIT $1::integer`,
      [bounded]
    );

    for (const row of projectScopesRes.rows) {
      const tenantId = readRequiredUuid(row, "tenant_id", parseTenantId);
      const projectId = readRequiredUuid(row, "project_id", parseProjectId);
      const key = `${tenantId}:${projectId}`;
      if (!touchedProjects.has(key)) {
        touchedProjects.add(key);
        projectScopes.push({ tenantId, projectId });
      }
    }

    for (const scope of projectScopes) {
      await this.#safeCompactScope(tx, scope.tenantId, scope.projectId);
    }

    return {
      compactedEvents,
      compactedProjects: touchedProjects.size
    };
  }

  async compactProjectAndEventDeltas(
    tx: PgTransactionClient,
    tenantId: TenantId,
    projectId: ProjectId,
    limit: number
  ): Promise<void> {
    await this.#compactEventsForProject(tx, tenantId, projectId, limit);
    await this.#safeCompactScope(tx, tenantId, projectId);
  }

  async listProjectsForProjectionVerification(
    tx: PgTransactionClient,
    limit: number
  ): Promise<readonly CoordinatorProjectScope[]> {
    const bounded = clampLimit(limit, 1, 500);
    const res = await tx.query<Record<string, unknown>>(
      `SELECT id AS project_id, tenant_id
         FROM rq.projects
        WHERE state = 'active'
          AND projection_maintenance_operation_id IS NULL
        ORDER BY id ASC
        LIMIT $1::integer`,
      [bounded]
    );
    return res.rows.map((row) => ({
      tenantId: readRequiredUuid(row, "tenant_id", parseTenantId),
      projectId: readRequiredUuid(row, "project_id", parseProjectId)
    }));
  }
}
