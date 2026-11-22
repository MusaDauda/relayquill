import {
  type AdmitEventCommandOutcome,
  type AdmitEventCommandRecord,
  type AdmissionRepositoryPort,
  type EventSchemaDefinitionRecord,
  type InstallationAuthoritySnapshot,
  type ProducerScopeGrantRecord,
  type ProjectAuthoritySnapshot,
  type ProjectCapacitySnapshot,
  type ProjectQuotaLimits,
  type ResolveAdmittedEventOutcome,
  type ResolveAdmittedEventQuery,
  type SchemaEvaluatorPort,
  type TenantAuthoritySnapshot
} from "@relayquill/application";
import { computeDerivedWireEnvelopeUpperBoundBytes } from "@relayquill/event-schema";
import { DERIVED_MAX_CONTENT_BYTES } from "@relayquill/contracts";
import {
  ConflictDomainError,
  type EventTypeId,
  EVENT_MAX_CONTENT_BYTES,
  EVENT_MAX_ENVELOPE_BYTES,
  NotFoundDomainError,
  type ProducerId,
  type ProducerNamespace,
  type ProjectId,
  type Sha256Hex,
  type TenantId,
  parseCommandReceiptId,
  parseEventTypeName,
  parseOutboxId,
  parseProducerNamespace
} from "@relayquill/domain";
import {
  compileEventSchemaFromBytes,
  compileFilterAst,
  compileOrderingExtractor,
  compileProjectionProfile,
  evaluateEventBytes,
  evaluateFilter,
  executeProjection,
  extractOrderingKey,
  parseEventJsonBytes
} from "@relayquill/event-schema";
import {
  type PgTransactionClient,
  admitEvent as pgAdmitEvent,
  findTenantById,
  readInstallationStatus,
  resolveAdmittedEvent as pgResolveAdmittedEvent
} from "@relayquill/postgres";
import { readByteaUint8, toBigIntSafe, toIntSafe } from "./sql-helpers.js";

function toHexString(val: unknown): Sha256Hex {
  if (Buffer.isBuffer(val)) {
    return val.toString("hex") as Sha256Hex;
  }
  if (val instanceof Uint8Array) {
    return Buffer.from(val).toString("hex") as Sha256Hex;
  }
  return String(val).replace(/^\\x/, "") as Sha256Hex;
}

export function createEventSchemaEvaluatorPort(): SchemaEvaluatorPort {
  return {
    validateEvent(input) {
      const compiled = compileEventSchemaFromBytes(input.schemaBytes);
      const parsed = parseEventJsonBytes(input.eventBytes);
      const res = evaluateEventBytes(compiled, input.eventBytes);
      return Promise.resolve({
        valid: res.valid,
        diagnostics: res.diagnostics,
        byteCount: res.byteCount ?? parsed.byteCount,
        sha256: res.sha256 ?? parsed.sha256
      });
    },
    evaluateFilterAndExtract(input) {
      const compiledSchema = compileEventSchemaFromBytes(input.schemaBytes);
      const parsed = parseEventJsonBytes(input.eventBytes);
      const schemaRes = evaluateEventBytes(compiledSchema, input.eventBytes);
      if (!schemaRes.valid) {
        return Promise.resolve({
          schemaValid: false,
          diagnostics: schemaRes.diagnostics,
          matched: false
        });
      }
      const filterAst = compileFilterAst(input.filterAst, [compiledSchema]);
      const matched = evaluateFilter(filterAst, parsed.value);
      let ordering;
      let orderingErrorCode: string | undefined;
      if (matched && input.orderingExtractorSpec !== undefined) {
        try {
          const compiledExtractor = compileOrderingExtractor(input.orderingExtractorSpec, [
            compiledSchema
          ]);
          ordering = extractOrderingKey(parsed.value, compiledExtractor, input.orderingDigestScope);
        } catch (err) {
          orderingErrorCode = err instanceof Error ? err.name : "ORDERING_EXTRACT_ERROR";
        }
      }
      return Promise.resolve({
        schemaValid: true,
        diagnostics: schemaRes.diagnostics,
        matched,
        ...(ordering !== undefined ? { ordering } : {}),
        ...(orderingErrorCode !== undefined ? { orderingErrorCode } : {})
      });
    },
    executeProjection(input) {
      const compiledSource = compileEventSchemaFromBytes(input.sourceSchemaBytes);
      const targetSpec = JSON.parse(Buffer.from(input.profileBytes).toString("utf8")) as {
        target_schema_bytes?: unknown;
      };
      const compiledTarget =
        typeof targetSpec.target_schema_bytes === "string"
          ? compileEventSchemaFromBytes(Buffer.from(targetSpec.target_schema_bytes, "base64"))
          : compiledSource;
      const compiledProfile = compileProjectionProfile(
        input.profileBytes,
        compiledSource,
        compiledTarget
      );
      const result = executeProjection(compiledProfile, input.sourceEventBytes);
      return Promise.resolve({
        derivedJson: result.derivedJson,
        derivedBytes: result.derivedBytes,
        derivedByteCount: result.derivedByteCount,
        derivedContentSha256: result.derivedContentSha256,
        targetSchemaVersion: result.targetSchemaVersion,
        provenance: result.provenance
      });
    }
  };
}

export function createPgAdmissionRepository(): AdmissionRepositoryPort<PgTransactionClient> {
  return {
    async readAuthorities(tx, tenantId: TenantId, projectId: ProjectId) {
      const inst = await readInstallationStatus(tx);
      const installation: InstallationAuthoritySnapshot = {
        controlEpoch: inst.controlEpoch,
        mode: inst.mode,
        allowEventAdmission: inst.allowEventAdmission,
        allowPublication: inst.allowPublication,
        allowFanout: inst.allowFanout,
        allowSend: inst.allowSend,
        allowEndpointVerification: inst.allowEndpointVerification,
        governanceVersion: inst.governanceVersion,
        updatedAt: inst.updatedAt,
        version: inst.version
      };

      const tenantRow = await findTenantById(tx, tenantId);
      if (tenantRow === undefined) {
        throw new NotFoundDomainError({
          code: "NOT_FOUND",
          message: `Tenant ${tenantId} not found`,
          resourceRef: { kind: "tenant", id: tenantId }
        });
      }
      const tenant: TenantAuthoritySnapshot = {
        tenantId: tenantRow.id,
        slug: tenantRow.slug,
        displayName: tenantRow.displayName,
        state: tenantRow.state,
        governanceVersion: tenantRow.governanceVersion,
        version: tenantRow.version
      };

      const projRes = await tx.query<Record<string, unknown>>(
        `SELECT p.id, p.tenant_id, p.name, p.state, p.topology_version, p.next_event_sequence,
                p.governance_version, p.active_ordering_cutover_plan_id, p.version,
                COALESCE(f.materialized_through_event_sequence, 0) AS materialized_through_event_sequence
           FROM rq.projects p
           LEFT JOIN rq.project_fanout_state f ON f.project_id = p.id
          WHERE p.id = $1::uuid AND p.tenant_id = $2::uuid`,
        [projectId, tenantId]
      );
      const pRow = projRes.rows[0];
      if (pRow === undefined) {
        throw new NotFoundDomainError({
          code: "NOT_FOUND",
          message: `Project ${projectId} not found in tenant ${tenantId}`,
          resourceRef: { kind: "project", id: projectId }
        });
      }

      const policyRes = await tx.query<{ normalized_definition: Record<string, unknown> }>(
        `SELECT normalized_definition
           FROM rq.policy_versions
          WHERE policy_kind = 'admission' AND policy_version = 'admission_v1'`
      );
      const admDef = policyRes.rows[0]?.normalized_definition ?? {};
      const defaultWindowMs = toBigIntSafe(
        admDef["default_window_ms"] ?? 86_400_000,
        "default_window_ms"
      );
      const maxWindowMs = toBigIntSafe(admDef["max_window_ms"] ?? 604_800_000, "max_window_ms");

      const project: ProjectAuthoritySnapshot = {
        tenantId,
        projectId,
        name: String(pRow["name"]),
        state: String(pRow["state"]) as ProjectAuthoritySnapshot["state"],
        admissionPaused: String(pRow["state"]) === "admission_paused",
        recoveryQuarantined: String(pRow["state"]) === "quarantined",
        topologyVersion: toBigIntSafe(pRow["topology_version"], "topology_version"),
        nextEventSequence: toBigIntSafe(pRow["next_event_sequence"], "next_event_sequence"),
        materializedThroughEventSequence: toBigIntSafe(
          pRow["materialized_through_event_sequence"],
          "materialized_through_event_sequence"
        ),
        governanceVersion: toBigIntSafe(pRow["governance_version"], "governance_version"),
        ...(typeof pRow["active_ordering_cutover_plan_id"] === "string"
          ? {
              activeOrderingCutoverPlanId: pRow[
                "active_ordering_cutover_plan_id"
              ] as ProjectAuthoritySnapshot["activeOrderingCutoverPlanId"]
            }
          : {}),
        defaultDeliveryWindowMs: defaultWindowMs,
        maxDeliveryWindowMs: maxWindowMs,
        version: toBigIntSafe(pRow["version"], "version")
      };

      const capRes = await tx.query<Record<string, unknown>>(
        `SELECT pending_events, unmaterialized_candidate_slots, pending_deliveries,
                active_attempt_slots, retained_payload_bytes, reserved_payload_bytes,
                max_pending_events, max_downstream_obligations, max_active_attempt_slots,
                max_retained_payload_bytes, version
           FROM rq.project_capacity
          WHERE project_id = $1::uuid`,
        [projectId]
      );
      const capRow = capRes.rows[0];
      const quota: ProjectQuotaLimits = {
        maxPendingEvents: toBigIntSafe(capRow?.["max_pending_events"] ?? 1000, "max_pending_events"),
        maxUnmaterializedCandidateSlots: toBigIntSafe(
          capRow?.["max_downstream_obligations"] ?? 10000,
          "max_downstream_obligations"
        ),
        maxPendingDeliveries: toBigIntSafe(
          capRow?.["max_downstream_obligations"] ?? 10000,
          "max_downstream_obligations"
        ),
        maxActiveAttemptSlots: toIntSafe(
          capRow?.["max_active_attempt_slots"] ?? 16,
          "max_active_attempt_slots"
        ),
        maxRetainedPayloadBytes: toBigIntSafe(
          capRow?.["max_retained_payload_bytes"] ?? 536870912,
          "max_retained_payload_bytes"
        )
      };
      const capacity: ProjectCapacitySnapshot = {
        projectId,
        tenantId,
        pendingEvents: toBigIntSafe(capRow?.["pending_events"] ?? 0, "pending_events"),
        unmaterializedCandidateSlots: toBigIntSafe(
          capRow?.["unmaterialized_candidate_slots"] ?? 0,
          "unmaterialized_candidate_slots"
        ),
        pendingDeliveries: toBigIntSafe(capRow?.["pending_deliveries"] ?? 0, "pending_deliveries"),
        activeAttemptSlots: toIntSafe(capRow?.["active_attempt_slots"] ?? 0, "active_attempt_slots"),
        retainedPayloadBytes: toBigIntSafe(
          capRow?.["retained_payload_bytes"] ?? 0,
          "retained_payload_bytes"
        ),
        reservedPayloadBytes: toBigIntSafe(
          capRow?.["reserved_payload_bytes"] ?? 0,
          "reserved_payload_bytes"
        ),
        version: toBigIntSafe(capRow?.["version"] ?? 1, "version")
      };

      return { installation, tenant, project, quota, capacity };
    },

    async findProducerScope(
      tx,
      tenantId: TenantId,
      projectId: ProjectId,
      producerId: ProducerId,
      namespace: ProducerNamespace
    ): Promise<ProducerScopeGrantRecord | undefined> {
      const prodRes = await tx.query<Record<string, unknown>>(
        `SELECT id, channel_kind, state, current_scope_version, business_namespace
           FROM rq.producers
          WHERE id = $1::uuid AND tenant_id = $2::uuid AND project_id = $3::uuid
            AND business_namespace = $4::text`,
        [producerId, tenantId, projectId, namespace]
      );
      const prod = prodRes.rows[0];
      if (prod === undefined || prod["current_scope_version"] === null) {
        return undefined;
      }
      const scopeVersion = toBigIntSafe(prod["current_scope_version"], "current_scope_version");
      const scopeRes = await tx.query<Record<string, unknown>>(
        `SELECT scope_definition, state
           FROM rq.producer_scope_versions
          WHERE producer_id = $1::uuid AND scope_version = $2::bigint`,
        [producerId, scopeVersion.toString(10)]
      );
      const scopeRow = scopeRes.rows[0];
      if (scopeRow === undefined) {
        return undefined;
      }

      const rawDef = (scopeRow["scope_definition"] ?? {}) as Record<string, unknown>;
      const rawEvents = Array.isArray(rawDef["allowed_events"])
        ? rawDef["allowed_events"]
        : Array.isArray(rawDef["allowedEvents"])
          ? rawDef["allowedEvents"]
          : [];
      const eventTypeIds = rawEvents
        .map((item) => {
          const rec = item as Record<string, unknown>;
          return rec["event_type_id"] ?? rec["eventTypeId"];
        })
        .filter((x): x is string => typeof x === "string");

      const nameMap = new Map<string, string>();
      if (eventTypeIds.length > 0) {
        const etRes = await tx.query<{ id: string; type_name: string }>(
          `SELECT id, type_name FROM rq.event_types WHERE id = ANY($1::uuid[]) AND project_id = $2::uuid`,
          [eventTypeIds, projectId]
        );
        for (const r of etRes.rows) {
          nameMap.set(r.id, r.type_name);
        }
      }

      const allowedEventTypeVersions = rawEvents.map((item) => {
        const rec = item as Record<string, unknown>;
        const eventTypeId = String(rec["event_type_id"] ?? rec["eventTypeId"]) as EventTypeId;
        const typeNameRaw =
          (typeof rec["event_type_name"] === "string" ? rec["event_type_name"] : undefined) ??
          nameMap.get(eventTypeId) ??
          "unknown.event";
        const rawVers = Array.isArray(rec["allowed_schema_versions"])
          ? rec["allowed_schema_versions"]
          : Array.isArray(rec["schemaVersions"])
            ? rec["schemaVersions"]
            : [];
        return {
          eventTypeId,
          eventTypeName: parseEventTypeName(typeNameRaw, "event_type_name"),
          schemaVersions: rawVers.map((v) => toIntSafe(v, "schema_version"))
        };
      });

      let resolvedAllowedEvents = allowedEventTypeVersions;
      if (String(prod["channel_kind"]) === "human_workflow" && resolvedAllowedEvents.length === 0) {
        const pubRes = await tx.query<Record<string, unknown>>(
          `SELECT et.id AS event_type_id, et.type_name, esv.schema_version
             FROM rq.event_types et
             JOIN rq.event_schema_versions esv
               ON esv.event_type_id = et.id AND esv.project_id = et.project_id
            WHERE et.tenant_id = $1::uuid AND et.project_id = $2::uuid
              AND esv.state = 'published'
            ORDER BY et.type_name ASC, esv.schema_version ASC`,
          [tenantId, projectId]
        );
        const grouped = new Map<
          string,
          {
            eventTypeId: EventTypeId;
            eventTypeName: ReturnType<typeof parseEventTypeName>;
            schemaVersions: number[];
          }
        >();
        for (const r of pubRes.rows) {
          const id = String(r["event_type_id"]) as EventTypeId;
          let entry = grouped.get(id);
          if (entry === undefined) {
            entry = {
              eventTypeId: id,
              eventTypeName: parseEventTypeName(String(r["type_name"]), "type_name"),
              schemaVersions: []
            };
            grouped.set(id, entry);
          }
          entry.schemaVersions.push(toIntSafe(r["schema_version"], "schema_version"));
        }
        resolvedAllowedEvents = Array.from(grouped.values());
      }

      const rawActions = Array.isArray(rawDef["allowed_actions"])
        ? rawDef["allowed_actions"]
        : Array.isArray(rawDef["actions"])
          ? rawDef["actions"]
          : ["admit", "read_status", "watch"];

      return {
        producerId,
        tenantId,
        projectId,
        producerNamespace: parseProducerNamespace(prod["business_namespace"], "producer_namespace"),
        enabled: String(prod["state"]) === "active" && String(scopeRow["state"]) === "active",
        scopeVersion,
        allowedActions: rawActions.map(
          (a) => String(a) as ProducerScopeGrantRecord["allowedActions"][number]
        ),
        allowedEventTypeVersions: resolvedAllowedEvents,
        maxEncodedBodyBytes: EVENT_MAX_ENVELOPE_BYTES,
        maxDecodedContentBytes: EVENT_MAX_CONTENT_BYTES
      };
    },

    async findEventSchema(
      tx,
      tenantId: TenantId,
      projectId: ProjectId,
      eventTypeId: EventTypeId,
      schemaVersion: number
    ): Promise<EventSchemaDefinitionRecord | undefined> {
      const res = await tx.query<Record<string, unknown>>(
        `SELECT esv.event_type_id, et.type_name, esv.schema_version, esv.tenant_id, esv.project_id,
                esv.state, esv.profile_version, esv.definition_bytes, esv.definition_sha256
           FROM rq.event_schema_versions esv
           JOIN rq.event_types et
             ON et.id = esv.event_type_id AND et.project_id = esv.project_id AND et.tenant_id = esv.tenant_id
          WHERE esv.event_type_id = $1::uuid
            AND esv.schema_version = $2::integer
            AND esv.project_id = $3::uuid
            AND esv.tenant_id = $4::uuid`,
        [eventTypeId, schemaVersion, projectId, tenantId]
      );
      const row = res.rows[0];
      if (row === undefined) {
        return undefined;
      }
      const rawState = String(row["state"]);
      const mappedState: EventSchemaDefinitionRecord["state"] =
        rawState === "published" ? "active" : (rawState as EventSchemaDefinitionRecord["state"]);
      return {
        eventTypeId,
        eventTypeName: parseEventTypeName(row["type_name"], "type_name"),
        schemaVersion,
        tenantId,
        projectId,
        state: mappedState,
        profileVersion: String(row["profile_version"]),
        schemaBytes: readByteaUint8(row["definition_bytes"], "definition_bytes"),
        schemaSha256: toHexString(row["definition_sha256"])
      };
    },

    async countCandidateSubscriptions(
      tx,
      tenantId: TenantId,
      projectId: ProjectId,
      eventTypeId: EventTypeId,
      _schemaVersion: number,
      topologyVersion: bigint
    ) {
      const res = await tx.query<{ cnt: string }>(
        `SELECT pg_catalog.count(*)::text AS cnt
           FROM rq.subscription_topology_ranges str
           JOIN rq.subscription_versions sv
             ON sv.subscription_id = str.subscription_id
            AND sv.subscription_version = str.subscription_version
            AND sv.project_id = str.project_id
            AND sv.tenant_id = str.tenant_id
          WHERE str.project_id = $1::uuid
            AND str.tenant_id = $2::uuid
            AND sv.event_type_id = $3::uuid
            AND str.from_topology_version <= $4::bigint
            AND (str.until_topology_version IS NULL OR $4::bigint < str.until_topology_version)`,
        [projectId, tenantId, eventTypeId, topologyVersion.toString(10)]
      );
      const count = toBigIntSafe(res.rows[0]?.cnt ?? "0", "cnt");
      const maxDerivedEnvelopeUpperBoundBytes =
        count > 0n
          ? BigInt(
              computeDerivedWireEnvelopeUpperBoundBytes({
                originalContentByteCount: EVENT_MAX_CONTENT_BYTES,
                provenDerivedMaxBytes: DERIVED_MAX_CONTENT_BYTES
              })
            ) * count
          : 0n;
      return { count, maxDerivedEnvelopeUpperBoundBytes };
    },

    async resolveAdmittedEvent(
      tx,
      query: ResolveAdmittedEventQuery
    ): Promise<ResolveAdmittedEventOutcome> {
      try {
        const res = await pgResolveAdmittedEvent(tx, query);
        if (!res.found) {
          return { found: false };
        }
        const extra = await tx.query<Record<string, unknown>>(
          `SELECT e.topology_version, o.id AS outbox_id, ef.candidate_count,
                  COALESCE(cr.applied_defaults, bea.applied_defaults, '{}'::jsonb) AS applied_defaults,
                  cr.id AS found_receipt_id
             FROM rq.events e
             LEFT JOIN rq.outbox_events o ON o.event_id = e.id
             LEFT JOIN rq.event_fanout ef ON ef.event_id = e.id
             LEFT JOIN rq.command_receipts cr
               ON cr.scope_kind = 'project'
              AND cr.project_id = e.project_id
              AND cr.actor_principal_id = $2::uuid
              AND cr.command_family = 'events.admit'
              AND cr.key_sha256 = $3::bytea
             LEFT JOIN rq.business_event_anchors bea
               ON bea.event_id = e.id
            WHERE e.id = $1::uuid`,
          [
            res.eventId,
            query.actorPrincipalId,
            Buffer.from(query.idempotencyKeySha256, "hex")
          ]
        );
        const row = extra.rows[0];
        const appliedRaw = row?.["applied_defaults"];
        const appliedDefaults =
          appliedRaw !== null && typeof appliedRaw === "object"
            ? (appliedRaw as Record<string, unknown>)
            : {};
        const receiptIdRaw = res.receiptId ?? row?.["found_receipt_id"];
        const receiptId = parseCommandReceiptId(
          typeof receiptIdRaw === "string" ? receiptIdRaw : res.eventId,
          "receipt_id"
        );
        const outboxId = parseOutboxId(
          typeof row?.["outbox_id"] === "string" ? row["outbox_id"] : res.eventId,
          "outbox_id"
        );
        return {
          found: true,
          matchKind:
            res.receiptId !== undefined ? "idempotent_recovery" : "business_anchor_recovery",
          eventId: res.eventId,
          receiptId,
          outboxId,
          projectEventSequence: res.projectEventSequence,
          topologyVersion: toBigIntSafe(row?.["topology_version"] ?? 1, "topology_version"),
          candidateCount: toBigIntSafe(row?.["candidate_count"] ?? 0, "candidate_count"),
          state: res.state,
          admittedAt: res.admittedAt,
          deliveryDeadlineAt: res.deliveryDeadlineAt,
          appliedDefaults
        };
      } catch (err) {
        if (err instanceof ConflictDomainError) {
          const msg = err.message;
          const conflictCode = msg.toLowerCase().includes("idempotency")
            ? "IDEMPOTENCY_CONFLICT"
            : msg.toLowerCase().includes("context")
              ? "PUBLICATION_CONTEXT_CHANGED"
              : "BUSINESS_IDENTITY_CONFLICT";
          return {
            found: true,
            matchKind: "conflict",
            conflictCode,
            message: msg
          };
        }
        throw err;
      }
    },

    async admitEvent(tx, record: AdmitEventCommandRecord): Promise<AdmitEventCommandOutcome> {
      const outcome = await pgAdmitEvent(tx, {
        tenantId: record.tenantId,
        projectId: record.projectId,
        actorPrincipalId: record.actorPrincipalId,
        producerId: record.producerId,
        producerNamespace: record.producerNamespace,
        businessKey: record.businessKey,
        businessKeySha256: record.businessKeySha256,
        idempotencyKeySha256: record.idempotencyKeySha256,
        submittedShapeSha256: record.submittedShapeSha256,
        effectiveRequestSha256: record.effectiveRequestSha256,
        eventTypeId: record.eventTypeId,
        eventSchemaVersion: record.eventSchemaVersion,
        content: record.contentBytes,
        contentSha256: record.contentSha256,
        wireEnvelopeBytes: record.wireEnvelopeBytes,
        wireEnvelopeSha256: record.wireEnvelopeSha256,
        brokerEnvelopeBytes: record.brokerEnvelopeBytes,
        brokerEnvelopeSha256: record.brokerEnvelopeSha256,
        producerEventTime: record.producerEventTime ?? null,
        deliveryDeadlineAt: record.deliveryDeadlineAt,
        appliedDefaults: record.appliedDefaults,
        retentionPolicyVersion: record.retentionPolicyVersion,
        eventId: record.eventId,
        payloadId: record.payloadId,
        wireEnvelopeId: record.wireEnvelopeId,
        outboxId: record.outboxId,
        receiptId: record.receiptId,
        auditId: record.auditId
      });

      const resolvedReceiptId = parseCommandReceiptId(
        outcome.receiptId ?? record.receiptId,
        "receipt_id"
      );
      const resolvedOutboxId = parseOutboxId(
        outcome.outboxId ?? record.outboxId,
        "outbox_id"
      );

      return {
        outcome: outcome.outcome,
        eventId: outcome.eventId,
        receiptId: resolvedReceiptId,
        outboxId: resolvedOutboxId,
        projectEventSequence: outcome.projectEventSequence,
        topologyVersion: outcome.topologyVersion,
        candidateCount: outcome.candidateCount ?? record.candidateCount,
        admittedAt: outcome.admittedAt,
        deliveryDeadlineAt: outcome.deliveryDeadlineAt,
        state: outcome.state,
        appliedDefaults: outcome.appliedDefaults
      };
    }
  };
}
