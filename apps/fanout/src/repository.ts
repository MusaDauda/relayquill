import crypto from "node:crypto";
import {
  type BrokerGenerationId,
  type BrokerInboxId,
  type BrokerInboxState,
  type CanonicalUtcTimestamp,
  type ControlEpoch,
  type EventFanoutState,
  type EventId,
  type EventTypeId,
  formatInt64,
  ORDERING_MODES,
  type OutboxId,
  parseEndpointId,
  parseEventTypeId,
  parseEventTypeName,
  parseOrderingDomainId,
  parsePositiveInt64String,
  parseProjectId,
  parseRepresentationProfileId,
  parseSubscriptionId,
  parseTenantId,
  parseWireEnvelopeId,
  type ProjectId,
  type RuntimeInstanceId,
  type Sha256Hex,
  type SubscriptionId,
  type TenantId,
  ValidationDomainError
} from "@relayquill/domain";
import {
  type CanonicalJsonValue,
  computeOriginalFactsSha256,
  hashCanonicalJson,
  sha256Hex
} from "@relayquill/contracts";
import {
  type FanoutEventContextRecord,
  type FanoutOutcomeRecord,
  type FanoutRepositoryPort,
  type InstallationAuthoritySnapshot,
  type SubscriptionCandidateRecord
} from "@relayquill/application";
import {
  acceptBrokerInbox as pgAcceptBrokerInbox,
  byteaToBuffer,
  byteaToSha256Hex,
  claimEventFanout as pgClaimEventFanout,
  commitFanoutPage as pgCommitFanoutPage,
  type FanoutOutcomeItem,
  type PgTransactionClient,
  readEventPayloadBytes,
  readInstallationStatus,
  readOptionalJsonRecord,
  readOptionalString,
  readOptionalUtcTimestamp,
  readOptionalUuid,
  readRequiredEnum,
  readRequiredInt32,
  readRequiredInt64BigInt,
  readRequiredString,
  readRequiredUtcTimestamp,
  readRequiredUuid,
  sha256HexToBytea,
  toBytea
} from "@relayquill/postgres";

const DEFAULT_MATCH_ALL_FILTER: Readonly<Record<string, unknown>> = Object.freeze({ all: [] });
const DEFAULT_MATCH_ALL_FILTER_SHA256 = hashCanonicalJson(
  DEFAULT_MATCH_ALL_FILTER as unknown as CanonicalJsonValue,
  "default_filter"
).sha256;

export interface PostgresFanoutRepositoryOptions {
  readonly onTargetSchemaDiscovered?: (
    profileSha256: Sha256Hex,
    targetSchemaBytes: Uint8Array
  ) => void;
}

function mapOutcomeForSql(outcome: FanoutOutcomeRecord["outcome"]): FanoutOutcomeItem["outcome"] {
  switch (outcome) {
    case "matched":
      return "matched";
    case "filtered_out":
      return "filtered_out";
    case "blocked":
      return "explicitly_suppressed" as FanoutOutcomeItem["outcome"];
    case "failed":
      return "schema_not_selected" as FanoutOutcomeItem["outcome"];
  }
}

export class PostgresFanoutRepository implements FanoutRepositoryPort<PgTransactionClient> {
  readonly #onTargetSchemaDiscovered:
    | ((profileSha256: Sha256Hex, targetSchemaBytes: Uint8Array) => void)
    | undefined;

  constructor(options: PostgresFanoutRepositoryOptions = {}) {
    this.#onTargetSchemaDiscovered = options.onTargetSchemaDiscovered;
  }

  async readInstallationAuthority(tx: PgTransactionClient): Promise<InstallationAuthoritySnapshot> {
    return readInstallationStatus(tx);
  }

  async acceptBrokerInbox(
    tx: PgTransactionClient,
    params: {
      readonly outboxId: OutboxId;
      readonly publicationGeneration: bigint;
      readonly eventId: EventId;
      readonly projectId: ProjectId;
      readonly topologyVersion: bigint;
      readonly envelopeSha256: Sha256Hex;
      readonly brokerGenerationId: BrokerGenerationId;
      readonly streamSequence: bigint;
      readonly inboxId: BrokerInboxId;
      readonly instanceId: RuntimeInstanceId;
      readonly controlEpoch: ControlEpoch;
      readonly now: CanonicalUtcTimestamp;
    }
  ): Promise<{
    readonly inboxId: BrokerInboxId;
    readonly inboxState: BrokerInboxState;
    readonly fanoutState: EventFanoutState;
    readonly projectEventSequence: bigint;
    readonly materializedThroughEventSequence: bigint;
    readonly isNextContiguous: boolean;
  }> {
    return pgAcceptBrokerInbox(tx, {
      outboxId: params.outboxId,
      publicationGeneration: params.publicationGeneration,
      eventId: params.eventId,
      projectId: params.projectId,
      topologyVersion: params.topologyVersion,
      envelopeSha256: params.envelopeSha256,
      brokerGenerationId: params.brokerGenerationId,
      streamSequence: params.streamSequence,
      inboxId: params.inboxId,
      instanceId: params.instanceId,
      controlEpoch: params.controlEpoch
    });
  }

  claimEventFanout(
    tx: PgTransactionClient,
    params: {
      readonly eventId: EventId;
      readonly instanceId: RuntimeInstanceId;
      readonly controlEpoch: ControlEpoch;
      readonly claimLeaseMs: bigint;
      readonly now: CanonicalUtcTimestamp;
    }
  ): ReturnType<FanoutRepositoryPort<PgTransactionClient>["claimEventFanout"]> {
    return pgClaimEventFanout(tx, {
      eventId: params.eventId,
      instanceId: params.instanceId,
      controlEpoch: params.controlEpoch,
      claimLeaseMs: params.claimLeaseMs
    });
  }

  async readEventForFanout(
    tx: PgTransactionClient,
    eventId: EventId
  ): Promise<FanoutEventContextRecord> {
    const evRes = await tx.query<Record<string, unknown>>(
      `SELECT e.id, e.tenant_id, e.project_id, e.event_type_id, et.type_name,
              e.event_schema_version, esv.profile_version, esv.definition_bytes,
              e.topology_version, e.project_event_sequence, e.content_sha256,
              e.delivery_deadline_at, e.admitted_at, e.producer_event_time
         FROM rq.events e
         JOIN rq.event_types et
           ON et.id = e.event_type_id
          AND et.project_id = e.project_id
          AND et.tenant_id = e.tenant_id
         JOIN rq.event_schema_versions esv
           ON esv.event_type_id = e.event_type_id
          AND esv.schema_version = e.event_schema_version
          AND esv.project_id = e.project_id
          AND esv.tenant_id = e.tenant_id
        WHERE e.id = $1::uuid`,
      [eventId]
    );
    const row = evRes.rows[0];
    if (row === undefined) {
      throw new ValidationDomainError({
        code: "NOT_FOUND",
        message: `Event "${eventId}" not found for fanout`
      });
    }

    const tenantId = readRequiredUuid(row, "tenant_id", parseTenantId);
    const projectId = readRequiredUuid(row, "project_id", parseProjectId);
    const eventTypeId = readRequiredUuid(row, "event_type_id", parseEventTypeId);
    const eventTypeName = parseEventTypeName(
      readRequiredString(row, "type_name"),
      "event_type"
    );
    const eventSchemaVersion = readRequiredInt32(row, "event_schema_version");
    const schemaProfileVersion = readRequiredString(row, "profile_version");
    const schemaBytes = new Uint8Array(
      byteaToBuffer(row["definition_bytes"], "definition_bytes")
    );
    const topologyVersion = readRequiredInt64BigInt(row, "topology_version");
    const projectEventSequence = readRequiredInt64BigInt(row, "project_event_sequence");
    const contentSha256 = byteaToSha256Hex(row["content_sha256"], "content_sha256");
    const deliveryDeadlineAt = readRequiredUtcTimestamp(row, "delivery_deadline_at");
    const admittedAt = readRequiredUtcTimestamp(row, "admitted_at");
    const producerEventTime = readOptionalUtcTimestamp(row, "producer_event_time");

    const payload = await readEventPayloadBytes(tx, tenantId, projectId, eventId);
    if (payload === undefined || payload.content === undefined) {
      throw new ValidationDomainError({
        code: "STATE_TRANSITION_NOT_ALLOWED",
        message: `Payload bytes unavailable for event "${eventId}"`
      });
    }
    const contentBytes = new Uint8Array(payload.content);

    const wireRes = await tx.query<Record<string, unknown>>(
      `SELECT id, body_sha256
         FROM rq.event_wire_envelopes
        WHERE event_id = $1::uuid
          AND project_id = $2::uuid
          AND tenant_id = $3::uuid
          AND representation_version = 1
        ORDER BY created_at ASC
        LIMIT 1`,
      [eventId, projectId, tenantId]
    );
    const wireRow = wireRes.rows[0];
    if (wireRow === undefined) {
      throw new ValidationDomainError({
        code: "NOT_FOUND",
        message: `Canonical v1 wire envelope not found for event "${eventId}"`
      });
    }
    const wireEnvelopeId = readRequiredUuid(wireRow, "id", parseWireEnvelopeId);
    const wireEnvelopeSha256 = byteaToSha256Hex(wireRow["body_sha256"], "body_sha256");

    const originalFactsSha256 = computeOriginalFactsSha256({
      project_id: projectId,
      event_id: eventId,
      project_event_sequence: parsePositiveInt64String(
        formatInt64(projectEventSequence, "project_event_sequence"),
        "project_event_sequence"
      ),
      event_type_id: eventTypeId,
      event_type: eventTypeName,
      event_schema_version: eventSchemaVersion,
      admitted_at: admittedAt,
      producer_event_time: producerEventTime ?? null,
      original_content_sha256: contentSha256
    });

    return {
      eventId,
      tenantId,
      projectId,
      eventTypeId,
      eventTypeName,
      eventSchemaVersion,
      schemaProfileVersion,
      schemaBytes,
      originalFactsSha256,
      topologyVersion,
      projectEventSequence,
      contentBytes,
      contentSha256,
      wireEnvelopeId,
      wireEnvelopeSha256,
      deliveryDeadlineAt,
      admittedAt
    };
  }

  async listActiveSubscriptionsPage(
    tx: PgTransactionClient,
    params: {
      readonly tenantId: TenantId;
      readonly projectId: ProjectId;
      readonly eventTypeId: EventTypeId;
      readonly schemaVersion: number;
      readonly topologyVersion: bigint;
      readonly afterSubscriptionId?: SubscriptionId | undefined;
      readonly limit: number;
    }
  ): Promise<readonly SubscriptionCandidateRecord[]> {
    const clamped = Math.min(200, Math.max(1, Math.trunc(params.limit)));
    const res = await tx.query<Record<string, unknown>>(
      `SELECT sv.subscription_id, sv.subscription_version, sv.endpoint_id, sv.endpoint_version,
              sv.event_type_id, et.type_name, ssv.event_schema_version,
              sv.filter_profile_version, sv.filter_ast, sv.filter_sha256,
              sv.ordering_mode, sv.ordering_domain_id, sv.ordering_extractor, sv.ordering_extractor_sha256,
              sv.consumer_contract_scope, sv.retry_policy_version, rpv.maximum_send_starts,
              srb.profile_id AS representation_profile_id,
              srb.profile_version AS representation_profile_version,
              repv.definition_bytes AS representation_profile_bytes,
              repv.definition_sha256 AS representation_profile_sha256,
              repv.proven_output_max_bytes,
              tesv.definition_bytes AS target_schema_bytes
         FROM rq.subscription_topology_ranges tr
         JOIN rq.subscriptions s
           ON s.id = tr.subscription_id
          AND s.tenant_id = tr.tenant_id
          AND s.project_id = tr.project_id
         JOIN rq.subscription_versions sv
           ON sv.subscription_id = tr.subscription_id
          AND sv.subscription_version = tr.subscription_version
         JOIN rq.subscription_schema_versions ssv
           ON ssv.subscription_id = sv.subscription_id
          AND ssv.subscription_version = sv.subscription_version
         JOIN rq.event_types et
           ON et.id = sv.event_type_id
          AND et.project_id = sv.project_id
          AND et.tenant_id = sv.tenant_id
         JOIN rq.retry_policy_versions rpv
           ON rpv.policy_version = sv.retry_policy_version
         LEFT JOIN rq.subscription_representation_bindings srb
           ON srb.subscription_id = sv.subscription_id
          AND srb.subscription_version = sv.subscription_version
          AND srb.source_schema_version = $4::integer
         LEFT JOIN rq.representation_profile_versions repv
           ON repv.profile_id = srb.profile_id
          AND repv.profile_version = srb.profile_version
         LEFT JOIN rq.event_schema_versions tesv
           ON tesv.event_type_id = sv.event_type_id
          AND tesv.schema_version = repv.target_schema_version
          AND tesv.project_id = tr.project_id
          AND tesv.tenant_id = tr.tenant_id
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
        params.topologyVersion.toString(10),
        params.afterSubscriptionId ?? null,
        clamped
      ]
    );

    return res.rows.map((row): SubscriptionCandidateRecord => {
      const filterAst = readOptionalJsonRecord(row, "filter_ast") ?? DEFAULT_MATCH_ALL_FILTER;
      const filterSha256 =
        row["filter_sha256"] !== null && row["filter_sha256"] !== undefined
          ? byteaToSha256Hex(row["filter_sha256"], "filter_sha256")
          : DEFAULT_MATCH_ALL_FILTER_SHA256;
      const orderingMode = readRequiredEnum(row, "ordering_mode", ORDERING_MODES);
      const orderingDomainId = readOptionalUuid(
        row,
        "ordering_domain_id",
        parseOrderingDomainId
      );
      const orderingExtractorSpec = readOptionalJsonRecord(row, "ordering_extractor");
      const orderingExtractorSha256 =
        row["ordering_extractor_sha256"] !== null && row["ordering_extractor_sha256"] !== undefined
          ? byteaToSha256Hex(row["ordering_extractor_sha256"], "ordering_extractor_sha256")
          : undefined;
      const representationProfileId = readOptionalUuid(
        row,
        "representation_profile_id",
        parseRepresentationProfileId
      );
      const rawRepVersion = row["representation_profile_version"];
      const representationProfileVersion =
        rawRepVersion !== null && rawRepVersion !== undefined
          ? readRequiredInt64BigInt(row, "representation_profile_version")
          : undefined;
      const representationProfileBytes =
        row["representation_profile_bytes"] !== null &&
        row["representation_profile_bytes"] !== undefined
          ? new Uint8Array(
              byteaToBuffer(row["representation_profile_bytes"], "representation_profile_bytes")
            )
          : undefined;
      const representationProfileSha256 =
        row["representation_profile_sha256"] !== null &&
        row["representation_profile_sha256"] !== undefined
          ? byteaToSha256Hex(row["representation_profile_sha256"], "representation_profile_sha256")
          : undefined;

      if (
        representationProfileBytes !== undefined &&
        row["target_schema_bytes"] !== null &&
        row["target_schema_bytes"] !== undefined
      ) {
        const repSha = representationProfileSha256 ?? sha256Hex(representationProfileBytes);
        const targetSchemaBytes = new Uint8Array(
          byteaToBuffer(row["target_schema_bytes"], "target_schema_bytes")
        );
        this.#onTargetSchemaDiscovered?.(repSha, targetSchemaBytes);
      }

      const rawMaxBytes = row["proven_output_max_bytes"];
      const reservedSlotBytes =
        rawMaxBytes !== null && rawMaxBytes !== undefined
          ? BigInt(readRequiredInt32(row, "proven_output_max_bytes"))
          : 0n;

      return {
        subscriptionId: readRequiredUuid(row, "subscription_id", parseSubscriptionId),
        subscriptionVersion: readRequiredInt64BigInt(row, "subscription_version"),
        endpointId: readRequiredUuid(row, "endpoint_id", parseEndpointId),
        endpointVersion: readRequiredInt64BigInt(row, "endpoint_version"),
        eventTypeId: readRequiredUuid(row, "event_type_id", parseEventTypeId),
        eventTypeName: parseEventTypeName(readRequiredString(row, "type_name"), "event_type"),
        schemaVersion: readRequiredInt32(row, "event_schema_version"),
        filterProfileVersion:
          readOptionalString(row, "filter_profile_version") ?? "relayquill.filter.v1",
        filterAst,
        filterSha256,
        orderingMode,
        ...(orderingDomainId !== undefined ? { orderingDomainId } : {}),
        ...(orderingExtractorSpec !== undefined ? { orderingExtractorSpec } : {}),
        ...(orderingExtractorSha256 !== undefined ? { orderingExtractorSha256 } : {}),
        ...(representationProfileId !== undefined ? { representationProfileId } : {}),
        ...(representationProfileVersion !== undefined ? { representationProfileVersion } : {}),
        ...(representationProfileBytes !== undefined ? { representationProfileBytes } : {}),
        ...(representationProfileSha256 !== undefined ? { representationProfileSha256 } : {}),
        consumerContractScope: readRequiredString(row, "consumer_contract_scope"),
        retryPolicyVersion: readRequiredString(row, "retry_policy_version"),
        maxAttempts: readRequiredInt32(row, "maximum_send_starts"),
        reservedSlotBytes
      };
    });
  }

  reserveOrderingSequence(
    _tx: PgTransactionClient,
    _params: {
      readonly tenantId: TenantId;
      readonly projectId: ProjectId;
      readonly subscriptionId: SubscriptionId;
      readonly orderingDomainId: ReturnType<typeof parseOrderingDomainId>;
      readonly orderingKeySha256: Sha256Hex;
      readonly consumerContractScope: string;
    }
  ): Promise<{ readonly orderingSequence: bigint; readonly blockedHead: boolean }> {
    // Authoritative ordering sequence allocation happens atomically inside rq.cmd_fanout_page.
    return Promise.resolve({ orderingSequence: 1n, blockedHead: false });
  }

  async commitFanoutPage(
    tx: PgTransactionClient,
    params: {
      readonly eventId: EventId;
      readonly instanceId: RuntimeInstanceId;
      readonly controlEpoch: ControlEpoch;
      readonly expectedClaimGeneration: bigint;
      readonly nextCursor?: SubscriptionId | null | undefined;
      readonly complete: boolean;
      readonly outcomes: readonly FanoutOutcomeRecord[];
      readonly now: CanonicalUtcTimestamp;
    }
  ): Promise<
    | { readonly outcome: "already_complete"; readonly eventId: EventId }
    | {
        readonly outcome: "completed" | "page_committed";
        readonly eventId: EventId;
        readonly newExamined: bigint;
        readonly newDeliveries: bigint;
        readonly materializedThroughEventSequence: bigint;
      }
  > {
    const derivedOutcomes = params.outcomes.filter(
      (o) => o.outcome === "matched" && o.deliverySeed?.derivedWireEnvelope !== undefined
    );

    if (derivedOutcomes.length > 0) {
      const evMeta = await tx.query<Record<string, unknown>>(
        `SELECT tenant_id, project_id, content_sha256 FROM rq.events WHERE id = $1::uuid`,
        [params.eventId]
      );
      const evRow = evMeta.rows[0];
      if (evRow !== undefined) {
        const tenantId = readRequiredUuid(evRow, "tenant_id");
        const projectId = readRequiredUuid(evRow, "project_id");
        const contentShaBytea = byteaToBuffer(evRow["content_sha256"], "content_sha256");

        for (const item of derivedOutcomes) {
          const seed = item.deliverySeed;
          const derived = seed?.derivedWireEnvelope;
          if (seed === undefined || derived === undefined) {
            continue;
          }
          await tx.query(
            `INSERT INTO rq.event_wire_envelopes (
               id, event_id, tenant_id, project_id, representation_version,
               profile_id, profile_version, target_schema_version,
               source_content_sha256, body_bytes, body_sha256, byte_count, retention_state
             ) VALUES (
               $1::uuid, $2::uuid, $3::uuid, $4::uuid, 2,
               $5::uuid, $6::bigint, $7::integer,
               $8::bytea, $9::bytea, $10::bytea, $11::integer, 'required'
             )
             ON CONFLICT (id) DO NOTHING`,
            [
              seed.wireEnvelopeId,
              params.eventId,
              tenantId,
              projectId,
              derived.representationProfileId,
              derived.representationProfileVersion.toString(10),
              derived.provenance.target_schema_version,
              contentShaBytea,
              toBytea(derived.bodyBytes),
              sha256HexToBytea(derived.bodySha256, "bodySha256"),
              derived.bodyBytes.byteLength
            ]
          );
        }
      }
    }

    const sqlOutcomes: (FanoutOutcomeItem & {
      readonly ordering_domain_id?: string | undefined;
      readonly ordering_key_id?: string | undefined;
    })[] = params.outcomes.map((item) => {
      if (item.outcome === "matched" && item.deliverySeed !== undefined) {
        const seed = item.deliverySeed;
        return {
          subscription_id: item.subscriptionId,
          subscription_version: item.subscriptionVersion.toString(10),
          outcome: "matched",
          filter_profile_version: item.filterProfileVersion,
          filter_sha256: item.filterSha256,
          delivery_id: seed.deliveryId,
          family_id: seed.familyId,
          endpoint_id: seed.endpointId,
          endpoint_version: seed.endpointVersion.toString(10),
          wire_envelope_id: seed.wireEnvelopeId,
          consumer_contract_scope: item.consumerContractScope,
          consumer_event_key_sha256: seed.consumerEventKeySha256,
          ...(seed.ordering !== undefined
            ? {
                ordering_domain_id: seed.ordering.orderingDomainId,
                ordering_key_id: crypto.randomUUID(),
                ordering_key_sha256: seed.ordering.orderingKeySha256
              }
            : {}),
          maximum_attempts: seed.maxAttempts
        };
      }

      return {
        subscription_id: item.subscriptionId,
        subscription_version: item.subscriptionVersion.toString(10),
        outcome: mapOutcomeForSql(item.outcome),
        filter_profile_version: item.filterProfileVersion,
        filter_sha256: item.filterSha256,
        ...(item.blockingReason !== undefined ? { safe_reason_code: item.blockingReason } : {})
      };
    });

    const pageRes = await pgCommitFanoutPage(tx, {
      eventId: params.eventId,
      instanceId: params.instanceId,
      controlEpoch: params.controlEpoch,
      expectedClaimGeneration: params.expectedClaimGeneration,
      nextCursor: params.nextCursor,
      complete: params.complete,
      outcomes: sqlOutcomes
    });

    if (pageRes.outcome === "already_complete") {
      return {
        outcome: "already_complete",
        eventId: pageRes.eventId
      };
    }

    const wmRes = await tx.query<Record<string, unknown>>(
      `SELECT pfs.materialized_through_event_sequence,
              ef.examined_count,
              ef.delivery_count
         FROM rq.project_fanout_state pfs
         JOIN rq.events e
           ON e.project_id = pfs.project_id
         JOIN rq.event_fanout ef
           ON ef.event_id = e.id
        WHERE e.id = $1::uuid`,
      [params.eventId]
    );
    const wmRow = wmRes.rows[0];
    const materializedThroughEventSequence =
      wmRow !== undefined
        ? readRequiredInt64BigInt(wmRow, "materialized_through_event_sequence")
        : 0n;
    const totalExaminedCount =
      wmRow !== undefined
        ? readRequiredInt64BigInt(wmRow, "examined_count")
        : (pageRes.newExamined ?? 0n);
    const totalDeliveryCount =
      wmRow !== undefined
        ? readRequiredInt64BigInt(wmRow, "delivery_count")
        : (pageRes.newDeliveries ?? 0n);

    return {
      outcome: pageRes.outcome,
      eventId: pageRes.eventId,
      newExamined: totalExaminedCount,
      newDeliveries: totalDeliveryCount,
      materializedThroughEventSequence
    };
  }
}
