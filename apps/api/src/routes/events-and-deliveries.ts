import { type AdmissionActorInput } from "@relayquill/application";
import {
  authenticateProducerCredential,
  extractBearerTokenFromAuthorizationHeader,
  hasActiveProjectDataGrant
} from "@relayquill/auth";
import { evaluateQuotaGuard } from "@relayquill/billing";
import {
  computeBusinessKeySha256,
  computeRequestKeySha256,
  encodeBase64,
  formatSseFrame,
  formatSseHeartbeatFrame,
  parseAdmitEventRequest,
  parseInt64String,
  parseNonNegativeInt64String,
  parseResolveEventRequest
} from "@relayquill/contracts";
import {
  AuthorizationDomainError,
  ConflictDomainError,
  EVENT_MAX_CONTENT_BYTES,
  EVENT_MAX_ENVELOPE_BYTES,
  NotFoundDomainError,
  type PrincipalId,
  type ProjectId,
  type TenantId,
  ValidationDomainError,
  formatUtcTimestamp,
  parseCanonicalUuid,
  parseCommandReceiptId,
  parseDeliveryId,
  parseEventId,
  parseInt64BigInt,
  parsePrincipalId,
  parseProducerNamespace,
  parseProjectId,
  parseTenantId,
  parseWatchLeaseId
} from "@relayquill/domain";
import {
  closeWatchLease,
  openWatchLease,
  readEventPayloadBytes,
  readWireEnvelopeBytes,
  renewWatchLease
} from "@relayquill/postgres";
import { type FastifyInstance, type FastifyReply } from "fastify";
import {
  type ApiContext,
  authenticateHumanMutation,
  authenticateHumanOrProducerRead,
  authenticateHumanRead,
  authorizeAction,
  buildCapabilitiesForActions,
  decodeApiCursor,
  encodeApiCursor,
  ensureApiRuntimeRegistered,
  formatPgTimestamp,
  getRawRequestHeaderMap,
  getRequestJsonBody,
  parseCursorQueryParams,
  readInstallationSnapshot,
  requireIdempotencyKeyHeader
} from "../context.js";
import { sendSuccessEnvelope } from "../http/errors.js";
import { extractSingleRawHeader } from "../http/headers.js";
import { EVENT_ADMISSION_BODY_LIMIT_BYTES } from "../http/json-parser.js";
import { asOptionalText, asText } from "../repos/sql-helpers.js";

function toHex(val: unknown): string {
  if (Buffer.isBuffer(val)) {
    return val.toString("hex");
  }
  if (val instanceof Uint8Array) {
    return Buffer.from(val).toString("hex");
  }
  return asText(val).replace(/^\\x/, "");
}

function buildBoundedSseEventFrame(input: {
  readonly id: string;
  readonly resourceKind: "event" | "delivery";
  readonly resourceId: ReturnType<typeof parseCanonicalUuid>;
  readonly eventId: ReturnType<typeof parseEventId>;
  readonly sequence: ReturnType<typeof parseNonNegativeInt64String>;
  readonly eventType: string;
  readonly eventSchemaVersion: number;
  readonly recordedAt: ReturnType<typeof formatPgTimestamp>;
  readonly safeDetails: Readonly<Record<string, unknown>>;
}): string {
  try {
    return formatSseFrame({
      id: input.id,
      payload: {
        response_schema_version: 1,
        frame_type: "event",
        resource_kind: input.resourceKind,
        resource_id: input.resourceId,
        event_id: input.eventId,
        event_sequence: input.sequence,
        event_type: input.eventType,
        event_schema_version: input.eventSchemaVersion,
        recorded_at: input.recordedAt,
        safe_details: input.safeDetails
      }
    });
  } catch {
    return formatSseFrame({
      id: input.id,
      payload: {
        response_schema_version: 1,
        frame_type: "event",
        resource_kind: input.resourceKind,
        resource_id: input.resourceId,
        event_id: input.eventId,
        event_sequence: input.sequence,
        event_type: input.eventType,
        event_schema_version: input.eventSchemaVersion,
        recorded_at: input.recordedAt,
        safe_details: { truncated: true }
      }
    });
  }
}

async function resolveAdmissionActorFromRequest(
  ctx: ApiContext,
  request: Parameters<typeof authenticateHumanMutation>[1],
  tenantId: TenantId,
  projectId: ProjectId
): Promise<{
  readonly actor: AdmissionActorInput;
  readonly idempotencyKey: string;
  readonly headerMap: ReadonlyMap<string, readonly string[]>;
  readonly cleanup: () => void;
}> {
  const headerMap = getRawRequestHeaderMap(request);
  const idempotencyKey = requireIdempotencyKeyHeader(headerMap);
  const authHeader = extractSingleRawHeader(headerMap, "authorization");

  if (authHeader !== undefined && authHeader.length > 0) {
    const bearerToken = extractBearerTokenFromAuthorizationHeader(authHeader);
    return {
      actor: { kind: "producer_credential", bearerToken },
      idempotencyKey,
      headerMap,
      cleanup: () => {}
    };
  }

  const inst = await ctx.pgAdapter.withTransaction(
    ctx.pgAdapter.configuredRole,
    (tx) => readInstallationSnapshot(ctx, tx),
    { readOnly: true }
  );
  const { auth } = await authenticateHumanMutation(ctx, request, inst);
  let channelInfo: { id: string; business_namespace: string } | undefined;
  let scopeAuthorized = false;
  try {
    const decision = await authorizeAction(ctx, auth, "events.admit", {
      installation: inst,
      tenantId,
      projectId
    });
    scopeAuthorized = decision.allowed;

    channelInfo = await ctx.pgAdapter.withTransaction(
      ctx.pgAdapter.configuredRole,
      async (tx) => {
        const res = await tx.query<{ id: string; business_namespace: string }>(
          `SELECT id, business_namespace
             FROM rq.producers
            WHERE tenant_id = $1::uuid AND project_id = $2::uuid
              AND principal_id = $3::uuid AND channel_kind = 'human_workflow' AND state = 'active'`,
          [tenantId, projectId, auth.principal.principalId]
        );
        return res.rows[0];
      },
      { readOnly: true }
    );
    if (channelInfo === undefined) {
      throw new AuthorizationDomainError({
        code: "FORBIDDEN",
        message: "Enable your personal human workflow publication channel before admitting events"
      });
    }
  } catch (err) {
    auth.destroySecrets();
    throw err;
  }

  return {
    actor: {
      kind: "human_workflow",
      actorPrincipalId: auth.principal.principalId,
      publicationChannelId: channelInfo.id,
      producerNamespace: channelInfo.business_namespace,
      scopeAuthorized
    },
    idempotencyKey,
    headerMap,
    cleanup: () => auth.destroySecrets()
  };
}

export function registerEventsAndDeliveriesRoutes(app: FastifyInstance, ctx: ApiContext): void {
  const activeSseShutdowns = new Set<() => Promise<void>>();
  app.addHook("onClose", async () => {
    await Promise.allSettled([...activeSseShutdowns].map((fn) => fn()));
  });

  // Publication Context (Human workflow or Machine Producer)
  app.get<{ Params: { tenant_id: string; project_id: string } }>(
    "/api/v1/tenants/:tenant_id/projects/:project_id/publication-context",
    async (request, reply) => {
      const tenantId = parseTenantId(request.params.tenant_id, "tenant_id");
      const projectId = parseProjectId(request.params.project_id, "project_id");
      const inst = await ctx.pgAdapter.withTransaction(
        ctx.pgAdapter.configuredRole,
        (tx) => readInstallationSnapshot(ctx, tx),
        { readOnly: true }
      );
      const { actor } = await authenticateHumanOrProducerRead(ctx, request, inst);

      try {
        const data = await ctx.pgAdapter.withTransaction(
          ctx.pgAdapter.configuredRole,
          async (tx) => {
            let channelRow: Record<string, unknown> | undefined;
            if (actor.kind === "producer") {
              if (actor.metadata.tenant_id !== tenantId || actor.metadata.project_id !== projectId) {
                throw new AuthorizationDomainError({
                  code: "FORBIDDEN",
                  message: "Producer credential belongs to a different project"
                });
              }
              const res = await tx.query<Record<string, unknown>>(
                `SELECT id, channel_kind, business_namespace, state, current_scope_version, authority_epoch
                   FROM rq.producers
                  WHERE id = $1::uuid AND tenant_id = $2::uuid AND project_id = $3::uuid`,
                [actor.metadata.producer_id, tenantId, projectId]
              );
              channelRow = res.rows[0];
            } else {
              await authorizeAction(ctx, actor.session, "events.read_safe", {
                installation: inst,
                tenantId,
                projectId
              });
              const res = await tx.query<Record<string, unknown>>(
                `SELECT id, channel_kind, business_namespace, state, current_scope_version, authority_epoch
                   FROM rq.producers
                  WHERE tenant_id = $1::uuid AND project_id = $2::uuid
                    AND principal_id = $3::uuid AND channel_kind = 'human_workflow'`,
                [tenantId, projectId, actor.session.principal.principalId]
              );
              channelRow = res.rows[0];
            }

            const etRes = await tx.query<Record<string, unknown>>(
              `SELECT et.id AS event_type_id, et.type_name, esv.schema_version
                 FROM rq.event_types et
                 JOIN rq.event_schema_versions esv
                   ON esv.event_type_id = et.id AND esv.project_id = et.project_id
                WHERE et.tenant_id = $1::uuid AND et.project_id = $2::uuid
                  AND esv.state = 'published'
                ORDER BY et.type_name ASC, esv.schema_version ASC`,
              [tenantId, projectId]
            );
            const grouped = new Map<string, { event_type_id: string; event_type_name: string; allowed_schema_versions: number[] }>();
            for (const r of etRes.rows) {
              const id = String(r["event_type_id"]);
              let entry = grouped.get(id);
              if (entry === undefined) {
                entry = {
                  event_type_id: id,
                  event_type_name: String(r["type_name"]),
                  allowed_schema_versions: []
                };
                grouped.set(id, entry);
              }
              entry.allowed_schema_versions.push(Number(r["schema_version"]));
            }

            const enabled = channelRow !== undefined && String(channelRow["state"]) === "active";
            return {
              actor_kind: actor.kind,
              channel_enabled: enabled,
              channel_kind:
                channelRow !== undefined
                  ? String(channelRow["channel_kind"])
                  : actor.kind === "producer"
                    ? "machine_producer"
                    : "human_workflow",
              publication_channel_id: channelRow !== undefined ? String(channelRow["id"]) : null,
              namespace:
                channelRow !== undefined
                  ? String(channelRow["business_namespace"])
                  : actor.kind === "human"
                    ? `human.${actor.session.principal.principalId}`
                    : null,
              scope_version:
                channelRow !== undefined
                  ? asOptionalText(channelRow["current_scope_version"])
                  : null,
              authority_epoch:
                channelRow !== undefined ? String(channelRow["authority_epoch"]) : "1",
              allowed_actions: enabled ? ["admit", "read_status", "watch"] : [],
              allowed_events: Array.from(grouped.values()),
              budgets: {
                max_encoded_body_bytes: EVENT_MAX_ENVELOPE_BYTES,
                max_decoded_content_bytes: EVENT_MAX_CONTENT_BYTES,
                default_delivery_window_ms: "86400000",
                max_delivery_window_ms: "604800000"
              }
            };
          },
          { readOnly: true }
        );

        return sendSuccessEnvelope(reply, 200, data, { requestId: request.id });
      } finally {
        if (actor.kind === "human") {
          actor.session.destroySecrets();
        }
      }
    }
  );

  // Enable personal human publication channel
  app.post<{ Params: { tenant_id: string; project_id: string } }>(
    "/api/v1/tenants/:tenant_id/projects/:project_id/publication-context/enable",
    async (request, reply) => {
      const tenantId = parseTenantId(request.params.tenant_id, "tenant_id");
      const projectId = parseProjectId(request.params.project_id, "project_id");
      const inst = await ctx.pgAdapter.withTransaction(
        ctx.pgAdapter.configuredRole,
        (tx) => readInstallationSnapshot(ctx, tx),
        { readOnly: true }
      );
      const { auth, idempotencyKey } = await authenticateHumanMutation(ctx, request, inst);
      try {
        await authorizeAction(ctx, auth, "publication_context.enable", {
          installation: inst,
          tenantId,
          projectId
        });
        const now = formatUtcTimestamp(ctx.clock.nowInstant());
        const producerId = ctx.ids.nextUuid();
        const namespace = `human.${auth.principal.principalId}`;
        const receiptId = parseCommandReceiptId(ctx.ids.nextUuid(), "receipt_id");

        const result = await ctx.pgAdapter.withTransaction(ctx.pgAdapter.configuredRole, async (tx) => {
          const existing = await tx.query<Record<string, unknown>>(
            `SELECT id, state, current_scope_version, authority_epoch
               FROM rq.producers
              WHERE tenant_id = $1::uuid AND project_id = $2::uuid
                AND principal_id = $3::uuid AND channel_kind = 'human_workflow'`,
            [tenantId, projectId, auth.principal.principalId]
          );
          if (existing.rows[0] !== undefined) {
            return { id: String(existing.rows[0]["id"]), created: false };
          }
          await tx.query(
            `INSERT INTO rq.producers (
               id, tenant_id, project_id, principal_id, principal_kind, channel_kind,
               name, business_namespace, state, current_scope_version, authority_epoch,
               created_at, updated_at, version
             ) VALUES (
               $1::uuid, $2::uuid, $3::uuid, $4::uuid, 'human', 'human_workflow',
               $5::text, $6::text, 'active', 1, 1, $7::timestamptz, $7::timestamptz, 1
             )`,
            [
              producerId,
              tenantId,
              projectId,
              auth.principal.principalId,
              `Human workflow (${auth.human.displayName})`,
              namespace,
              now
            ]
          );
          const scopeDef = { allowed_actions: ["admit", "read_status", "watch"], allowed_events: [] };
          await tx.query(
            `INSERT INTO rq.producer_scope_versions (
               producer_id, scope_version, tenant_id, project_id, scope_definition,
               scope_sha256, state, created_by, created_at, activated_at
             ) VALUES (
               $1::uuid, 1, $2::uuid, $3::uuid, $4::jsonb, $5::bytea, 'active', $6::uuid, $7::timestamptz, $7::timestamptz
             )`,
            [
              producerId,
              tenantId,
              projectId,
              JSON.stringify(scopeDef),
              Buffer.alloc(32, 3),
              auth.principal.principalId,
              now
            ]
          );
          await tx.query(
            `INSERT INTO rq.producer_rate_buckets (
               producer_id, tenant_id, project_id, operation, tokens_micro, reserved_micro,
               capacity_micro, refill_micro_per_second, refill_remainder_numerator,
               last_refill_at, updated_at
             ) VALUES (
               $1::uuid, $2::uuid, $3::uuid, 'event_admission', 20000000, 0,
               20000000, 10000000, 0, $4::timestamptz, $4::timestamptz
             ) ON CONFLICT DO NOTHING`,
            [producerId, tenantId, projectId, now]
          );
          await tx.query(
            `INSERT INTO rq.command_receipts (
               id, scope_kind, tenant_id, project_id, actor_principal_id, command_family,
               key_sha256, submitted_shape_sha256, effective_request_sha256, resource_kind,
               resource_id, accepted_version, applied_defaults, accepted_at, hash_schema_version
             ) VALUES (
               $1::uuid, 'project', $2::uuid, $3::uuid, $4::uuid, 'publication_context.enable',
               $5::bytea, $5::bytea, $5::bytea, 'producer', $6::uuid, 1, '{}'::jsonb, $7::timestamptz, 1
             ) ON CONFLICT DO NOTHING`,
            [
              receiptId,
              tenantId,
              projectId,
              auth.principal.principalId,
              Buffer.from(computeRequestKeySha256(idempotencyKey), "hex"),
              producerId,
              now
            ]
          );
          return { id: producerId, created: true };
        });

        return sendSuccessEnvelope(
          reply,
          result.created ? 201 : 200,
          {
            publication_channel_id: result.id,
            channel_enabled: true,
            namespace
          },
          { requestId: request.id, observedAt: now }
        );
      } finally {
        auth.destroySecrets();
      }
    }
  );
  app.post<{ Params: { tenant_id: string; project_id: string } }>(
    "/api/v1/tenants/:tenant_id/projects/:project_id/events",
    {
      config: { rawBodyLimit: EVENT_ADMISSION_BODY_LIMIT_BYTES },
      bodyLimit: EVENT_ADMISSION_BODY_LIMIT_BYTES
    },
    async (request, reply) => {
      const tenantId = parseTenantId(request.params.tenant_id, "tenant_id");
      const projectId = parseProjectId(request.params.project_id, "project_id");
      const body = getRequestJsonBody(request);
      const parsedReq = parseAdmitEventRequest(body);
      const resolved = await resolveAdmissionActorFromRequest(ctx, request, tenantId, projectId);

      try {
        // Resolve eventTypeName from project schema registry
        const schemaInfo = await ctx.pgAdapter.withTransaction(
          ctx.pgAdapter.configuredRole,
          async (tx) => {
            const res = await tx.query<{ type_name: string }>(
              `SELECT type_name FROM rq.event_types
                WHERE id = $1::uuid AND tenant_id = $2::uuid AND project_id = $3::uuid`,
              [parsedReq.event_type_id, tenantId, projectId]
            );
            return res.rows[0];
          },
          { readOnly: true }
        );
        if (schemaInfo === undefined) {
          throw new NotFoundDomainError({
            code: "NOT_FOUND",
            message: `Event type ${parsedReq.event_type_id} not found`
          });
        }

        if (ctx.enableQuotaGuard) {
          let actorPrincipalId: PrincipalId;
          if (resolved.actor.kind === "human_workflow") {
            actorPrincipalId = parsePrincipalId(resolved.actor.actorPrincipalId, "actor_principal_id");
          } else {
            const inst = await ctx.pgAdapter.withTransaction(
              ctx.pgAdapter.configuredRole,
              (tx) => readInstallationSnapshot(ctx, tx),
              { readOnly: true }
            );
            const authRes = await authenticateProducerCredential({
              installation: inst,
              bearerToken: resolved.actor.bearerToken,
              repo: ctx.authRepos.producerCredentials,
              now: ctx.clock.nowInstant()
            });
            if (
              authRes.producer.tenantId !== tenantId ||
              authRes.producer.projectId !== projectId
            ) {
              throw new AuthorizationDomainError({
                code: "FORBIDDEN",
                message: "Producer credential belongs to a different project"
              });
            }
            actorPrincipalId = authRes.principal.principalId;
          }

          const keyHashBuf = Buffer.from(
            computeRequestKeySha256(resolved.idempotencyKey),
            "hex"
          );
          const isIdempotentReplay = await ctx.pgAdapter.withTransaction(
            ctx.pgAdapter.configuredRole,
            async (tx) => {
              const dup = await tx.query<{ id: string }>(
                `SELECT id
                   FROM rq.command_receipts
                  WHERE tenant_id = $1::uuid
                    AND project_id = $2::uuid
                    AND actor_principal_id = $3::uuid
                    AND command_family = 'events.admit'
                    AND key_sha256 = $4::bytea
                  LIMIT 1`,
                [tenantId, projectId, actorPrincipalId, keyHashBuf]
              );
              return dup.rows[0] !== undefined;
            },
            { readOnly: true }
          );

          await evaluateQuotaGuard({
            pgAdapter: ctx.pgAdapter,
            redis: ctx.quotaRedis,
            orgId: tenantId,
            idempotencyKey: resolved.idempotencyKey,
            metricCode: "outbound_deliveries",
            requestedUnits: 1,
            isIdempotentReplay,
            now: new Date(ctx.clock.nowInstant().epochMilliseconds)
          });
        }

        const traceparent = extractSingleRawHeader(resolved.headerMap, "traceparent");
        const tracestate = extractSingleRawHeader(resolved.headerMap, "tracestate");

        const outcome = await ctx.admissionService.admitEvent({
          tenantId,
          projectId,
          actor: resolved.actor,
          eventTypeId: parsedReq.event_type_id,
          eventTypeName: schemaInfo.type_name,
          eventSchemaVersion: parsedReq.event_schema_version,
          businessKey: parsedReq.business_key,
          idempotencyKey: resolved.idempotencyKey,
          contentBytes: parsedReq.content.bytes,
          ...(parsedReq.producer_event_time !== undefined
            ? { producerEventTime: parsedReq.producer_event_time }
            : {}),
          ...(parsedReq.deadline_at !== undefined ? { deadlineAt: parsedReq.deadline_at } : {}),
          ...(traceparent !== undefined ? { traceparent } : {}),
          ...(tracestate !== undefined ? { tracestate } : {})
        });

        const evDetails = await ctx.pgAdapter.withTransaction(
          ctx.pgAdapter.configuredRole,
          async (tx) => {
            const res = await tx.query<Record<string, unknown>>(
              `SELECT producer_id, producer_namespace, content_byte_count, producer_event_time,
                      effective_request_sha256, version
                 FROM rq.events
                WHERE id = $1::uuid`,
              [outcome.eventId]
            );
            return res.rows[0]!;
          },
          { readOnly: true }
        );

        const defaults = outcome.appliedDefaults;
        const deliveryWindowMs =
          typeof defaults["delivery_window_ms"] === "string"
            ? defaults["delivery_window_ms"]
            : "86400000";

        const now = formatUtcTimestamp(ctx.clock.nowInstant());
        return sendSuccessEnvelope(
          reply,
          outcome.statusCode,
          {
            receipt: {
              id: outcome.receiptId,
              accepted_at: outcome.admittedAt,
              resource_kind: "event",
              resource_id: outcome.eventId,
              accepted_version: "1"
            },
            event: {
              event_id: outcome.eventId,
              event_type_id: parsedReq.event_type_id,
              event_type: schemaInfo.type_name,
              event_schema_version: parsedReq.event_schema_version,
              publication_channel_id: String(evDetails["producer_id"]),
              namespace: String(evDetails["producer_namespace"]),
              business_key: parsedReq.business_key,
              accepted_at: outcome.admittedAt,
              project_event_sequence: outcome.projectEventSequence.toString(10),
              topology_version: outcome.topologyVersion.toString(10),
              original_content_sha256: outcome.contentSha256,
              original_content_byte_count: Number(evDetails["content_byte_count"]),
              deadline_at: outcome.deliveryDeadlineAt,
              state_at_acceptance: outcome.state,
              producer_event_time:
                evDetails["producer_event_time"] !== null
                  ? formatPgTimestamp(evDetails["producer_event_time"])
                  : null,
              submitted_shape_sha256: outcome.submittedShapeSha256,
              effective_request_sha256: toHex(evDetails["effective_request_sha256"]),
              hash_schema_version: 1
            },
            applied_defaults: {
              delivery_window_ms: deliveryWindowMs,
              deadline_at: outcome.deliveryDeadlineAt,
              producer_event_time_present: Boolean(defaults["producer_event_time_present"] ?? false),
              deadline_at_present: Boolean(defaults["deadline_at_present"] ?? false)
            },
            matched_existing: outcome.statusCode === 200,
            current_observation: {
              current_version: asText(evDetails["version"], "1"),
              current_state: outcome.state,
              observed_at: now
            }
          },
          { requestId: request.id, observedAt: now }
        );
      } finally {
        resolved.cleanup();
      }
    }
  );

  // Lost-response recovery endpoint
  app.post<{ Params: { tenant_id: string; project_id: string } }>(
    "/api/v1/tenants/:tenant_id/projects/:project_id/events/resolve",
    async (request, reply) => {
      const tenantId = parseTenantId(request.params.tenant_id, "tenant_id");
      const projectId = parseProjectId(request.params.project_id, "project_id");
      const body = getRequestJsonBody(request);
      const parsedReq = parseResolveEventRequest(body);
      const headerMap = getRawRequestHeaderMap(request);
      const idempotencyKey = requireIdempotencyKeyHeader(headerMap);
      const authHeader = extractSingleRawHeader(headerMap, "authorization");

      const inst = await ctx.pgAdapter.withTransaction(
        ctx.pgAdapter.configuredRole,
        (tx) => readInstallationSnapshot(ctx, tx),
        { readOnly: true }
      );

      let actorPrincipalId: PrincipalId;
      let producerNamespace: string;
      let cleanup = (): void => {};

      if (authHeader !== undefined && authHeader.length > 0) {
        const bearerToken = extractBearerTokenFromAuthorizationHeader(authHeader);
        const authRes = await authenticateProducerCredential({
          installation: inst,
          bearerToken,
          repo: ctx.authRepos.producerCredentials,
          now: ctx.clock.nowInstant()
        });
        if (authRes.producer.tenantId !== tenantId || authRes.producer.projectId !== projectId) {
          throw new AuthorizationDomainError({
            code: "FORBIDDEN",
            message: "Producer credential belongs to a different project"
          });
        }
        actorPrincipalId = authRes.principal.principalId;
        producerNamespace = authRes.producer.businessNamespace;
      } else {
        const { auth } = await authenticateHumanRead(ctx, request, inst);
        cleanup = () => auth.destroySecrets();
        try {
          await authorizeAction(ctx, auth, "events.resolve", {
            installation: inst,
            tenantId,
            projectId
          });
        } catch (err) {
          auth.destroySecrets();
          throw err;
        }
        actorPrincipalId = auth.principal.principalId;
        producerNamespace = `human.${actorPrincipalId}`;
      }

      try {
        const bizKeySha = Buffer.from(computeBusinessKeySha256(parsedReq.business_key), "hex");
        const idemSha = Buffer.from(computeRequestKeySha256(idempotencyKey), "hex");
        const now = formatUtcTimestamp(ctx.clock.nowInstant());

        const row = await ctx.pgAdapter.withTransaction(
          ctx.pgAdapter.configuredRole,
          async (tx) => {
            const crRes = await tx.query<Record<string, unknown>>(
              `SELECT cr.id AS receipt_id, cr.submitted_shape_sha256, cr.applied_defaults, cr.accepted_at,
                      e.*, et.type_name
                 FROM rq.command_receipts cr
                 JOIN rq.events e ON e.id = cr.resource_id
                 JOIN rq.event_types et ON et.id = e.event_type_id
                WHERE cr.scope_kind = 'project'
                  AND cr.project_id = $1::uuid
                  AND cr.actor_principal_id = $2::uuid
                  AND cr.command_family = 'events.admit'
                  AND cr.key_sha256 = $3::bytea`,
              [projectId, actorPrincipalId, idemSha]
            );
            let match = crRes.rows[0];
            if (match === undefined) {
              const anchorRes = await tx.query<Record<string, unknown>>(
                `SELECT bea.submitted_shape_sha256, bea.applied_defaults, bea.accepted_at,
                        NULL::uuid AS receipt_id, e.*, et.type_name
                   FROM rq.business_event_anchors bea
                   JOIN rq.events e ON e.id = bea.event_id
                   JOIN rq.event_types et ON et.id = e.event_type_id
                  WHERE bea.project_id = $1::uuid
                    AND bea.producer_namespace = $2::text
                    AND bea.business_key_sha256 = $3::bytea`,
                [projectId, producerNamespace, bizKeySha]
              );
              match = anchorRes.rows[0];
            }
            if (match === undefined) {
              throw new NotFoundDomainError({
                code: "NOT_FOUND",
                message: "No admitted event matched the idempotency or business key"
              });
            }
            const storedShapeHex = toHex(match["submitted_shape_sha256"]);
            if (
              parsedReq.submitted_shape_sha256 !== undefined &&
              parsedReq.submitted_shape_sha256 !== storedShapeHex
            ) {
              throw new ConflictDomainError({
                code: "BUSINESS_IDENTITY_CONFLICT",
                message: "Submitted shape fingerprint conflicts with existing admitted event"
              });
            }

            const payloadRes = await tx.query<{ retention_state: string }>(
              `SELECT retention_state FROM rq.event_payloads WHERE id = $1::uuid`,
              [match["content_payload_id"]]
            );
            const retState = payloadRes.rows[0]?.retention_state ?? "required";

            return { match, storedShapeHex, retState };
          },
          { readOnly: true }
        );

        const m = row.match;
        const defaults = (m["applied_defaults"] ?? {}) as Record<string, unknown>;
        const admittedAt = formatPgTimestamp(m["admitted_at"]);
        const deadlineAt = formatPgTimestamp(m["delivery_deadline_at"]);

        return sendSuccessEnvelope(
          reply,
          200,
          {
            receipt: {
              id: parseCommandReceiptId(
                typeof m["receipt_id"] === "string" ? m["receipt_id"] : m["id"],
                "receipt_id"
              ),
              accepted_at: admittedAt,
              resource_kind: "event",
              resource_id: String(m["id"]),
              accepted_version: "1"
            },
            event: {
              event_id: String(m["id"]),
              event_type_id: String(m["event_type_id"]),
              event_type: String(m["type_name"]),
              event_schema_version: Number(m["event_schema_version"]),
              publication_channel_id: String(m["producer_id"]),
              namespace: String(m["producer_namespace"]),
              business_key: String(m["business_key"]),
              accepted_at: admittedAt,
              project_event_sequence: String(m["project_event_sequence"]),
              topology_version: String(m["topology_version"]),
              original_content_sha256: toHex(m["content_sha256"]),
              original_content_byte_count: Number(m["content_byte_count"]),
              deadline_at: deadlineAt,
              state_at_acceptance: String(m["state"]),
              producer_event_time:
                m["producer_event_time"] !== null ? formatPgTimestamp(m["producer_event_time"]) : null,
              submitted_shape_sha256: row.storedShapeHex,
              effective_request_sha256: toHex(m["effective_request_sha256"]),
              hash_schema_version: 1
            },
            applied_defaults: {
              delivery_window_ms:
                typeof defaults["delivery_window_ms"] === "string"
                  ? defaults["delivery_window_ms"]
                  : "86400000",
              deadline_at: deadlineAt,
              producer_event_time_present: Boolean(defaults["producer_event_time_present"] ?? false),
              deadline_at_present: Boolean(defaults["deadline_at_present"] ?? false)
            },
            fingerprint_verified: parsedReq.submitted_shape_sha256 !== undefined,
            content_availability: {
              view: "original",
              availability: row.retState === "expired" ? "expired" : "available",
              media_type: "application/json",
              byte_count: Number(m["content_byte_count"]),
              sha256: toHex(m["content_sha256"])
            },
            current_observation: {
              current_version: asText(m["version"], "1"),
              current_state: String(m["state"]),
              observed_at: now
            }
          },
          { requestId: request.id, observedAt: now }
        );
      } finally {
        cleanup();
      }
    }
  );

  // List / Inspect Events
  app.get<{ Params: { tenant_id: string; project_id: string }; Querystring: Record<string, unknown> }>(
    "/api/v1/tenants/:tenant_id/projects/:project_id/events",
    async (request, reply) => {
      const tenantId = parseTenantId(request.params.tenant_id, "tenant_id");
      const projectId = parseProjectId(request.params.project_id, "project_id");
      const inst = await ctx.pgAdapter.withTransaction(
        ctx.pgAdapter.configuredRole,
        (tx) => readInstallationSnapshot(ctx, tx),
        { readOnly: true }
      );
      const { auth } = await authenticateHumanRead(ctx, request, inst);
      try {
        await authorizeAction(ctx, auth, "events.read_safe", {
          installation: inst,
          tenantId,
          projectId
        });
        const { limit, rawCursor } = parseCursorQueryParams(request.query);
        const stateFilter =
          typeof request.query["state"] === "string" && request.query["state"].trim().length > 0
            ? request.query["state"].trim()
            : null;
        const eventTypeIdFilter =
          typeof request.query["event_type_id"] === "string" &&
          request.query["event_type_id"].trim().length > 0
            ? parseCanonicalUuid(request.query["event_type_id"], "query.event_type_id")
            : null;
        const namespaceFilter =
          typeof request.query["namespace"] === "string" &&
          request.query["namespace"].trim().length > 0
            ? request.query["namespace"].trim()
            : null;
        const filterObj = {
          ...(stateFilter !== null ? { state: stateFilter } : {}),
          ...(eventTypeIdFilter !== null ? { event_type_id: eventTypeIdFilter } : {}),
          ...(namespaceFilter !== null ? { namespace: namespaceFilter } : {})
        };
        const cursor = decodeApiCursor(ctx, rawCursor, {
          resource: "events",
          tenantId,
          projectId,
          order: "project_event_sequence_desc",
          filter: filterObj
        });
        const boundarySeq = cursor?.boundary.sequence ?? null;

        const rows = await ctx.pgAdapter.withTransaction(
          ctx.pgAdapter.configuredRole,
          async (tx) => {
            const res = await tx.query<Record<string, unknown>>(
              `SELECT e.id, e.producer_id, e.producer_namespace, e.event_type_id, et.type_name,
                      e.event_schema_version, e.content_sha256, e.content_byte_count,
                      e.topology_version, e.project_event_sequence, e.state, e.blocking_reason,
                      e.producer_event_time, e.admitted_at, e.delivery_deadline_at, e.version,
                      o.state AS outbox_state, ef.state AS fanout_state,
                      COALESCE(edt.total_deliveries, 0)::text AS total_deliveries,
                      COALESCE(edt.acknowledged_deliveries, 0)::text AS acknowledged_deliveries
                 FROM rq.v_safe_events e
                 JOIN rq.event_types et ON et.id = e.event_type_id
                 LEFT JOIN rq.outbox_events o ON o.event_id = e.id
                 LEFT JOIN rq.event_fanout ef ON ef.event_id = e.id
                 LEFT JOIN rq.event_delivery_totals edt ON edt.event_id = e.id
                WHERE e.tenant_id = $1::uuid AND e.project_id = $2::uuid
                  AND ($3::text IS NULL OR e.state = $3::text)
                  AND ($4::uuid IS NULL OR e.event_type_id = $4::uuid)
                  AND ($5::text IS NULL OR e.producer_namespace = $5::text)
                  AND ($6::bigint IS NULL OR e.project_event_sequence < $6::bigint)
                ORDER BY e.project_event_sequence DESC
                LIMIT $7::integer`,
              [tenantId, projectId, stateFilter, eventTypeIdFilter, namespaceFilter, boundarySeq, limit + 1]
            );
            return res.rows;
          },
          { readOnly: true }
        );

        const hasMore = rows.length > limit;
        const pageRows = rows.slice(0, limit);
        const items = pageRows.map((r) => ({
          event_id: String(r["id"]),
          event_type_id: String(r["event_type_id"]),
          event_type: String(r["type_name"]),
          event_schema_version: Number(r["event_schema_version"]),
          publication_channel_id: String(r["producer_id"]),
          namespace: String(r["producer_namespace"]),
          project_event_sequence: String(r["project_event_sequence"]),
          topology_version: String(r["topology_version"]),
          state: String(r["state"]),
          blocking_reason: r["blocking_reason"] ?? null,
          outbox_state: r["outbox_state"] ?? "pending",
          fanout_state: r["fanout_state"] ?? "pending",
          content_sha256: toHex(r["content_sha256"]),
          content_byte_count: Number(r["content_byte_count"]),
          admitted_at: formatPgTimestamp(r["admitted_at"]),
          delivery_deadline_at: formatPgTimestamp(r["delivery_deadline_at"]),
          total_deliveries: String(r["total_deliveries"]),
          acknowledged_deliveries: String(r["acknowledged_deliveries"]),
          version: String(r["version"])
        }));

        const last = pageRows[pageRows.length - 1];
        const next_cursor =
          hasMore && last !== undefined
            ? encodeApiCursor(ctx, {
                resource: "events",
                tenantId,
                projectId,
                order: "project_event_sequence_desc",
                filter: filterObj,
                boundary: {
                  sequence: parseInt64String(
                    String(last["project_event_sequence"]),
                    "project_event_sequence"
                  )
                }
              })
            : null;

        return sendSuccessEnvelope(
          reply,
          200,
          { items, page: { next_cursor, limit, has_more: hasMore } },
          { requestId: request.id }
        );
      } finally {
        auth.destroySecrets();
      }
    }
  );

  app.get<{ Params: { tenant_id: string; project_id: string; event_id: string } }>(
    "/api/v1/tenants/:tenant_id/projects/:project_id/events/:event_id",
    async (request, reply) => {
      const tenantId = parseTenantId(request.params.tenant_id, "tenant_id");
      const projectId = parseProjectId(request.params.project_id, "project_id");
      const eventId = parseEventId(request.params.event_id, "event_id");
      const inst = await ctx.pgAdapter.withTransaction(
        ctx.pgAdapter.configuredRole,
        (tx) => readInstallationSnapshot(ctx, tx),
        { readOnly: true }
      );
      const { actor } = await authenticateHumanOrProducerRead(ctx, request, inst);
      try {
        let canReadContent = false;
        let capabilities: ReturnType<typeof buildCapabilitiesForActions> | undefined;

        if (actor.kind === "producer") {
          if (actor.metadata.tenant_id !== tenantId || actor.metadata.project_id !== projectId) {
            throw new AuthorizationDomainError({
              code: "FORBIDDEN",
              message: "Producer credential belongs to a different project"
            });
          }
        } else {
          const decision = await authorizeAction(ctx, actor.session, "events.read_safe", {
            installation: inst,
            tenantId,
            projectId
          });
          const evNsRes = await ctx.pgAdapter.withTransaction(
            ctx.pgAdapter.configuredRole,
            async (tx) => {
              const res = await tx.query<{ producer_namespace: string }>(
                `SELECT producer_namespace FROM rq.v_safe_events WHERE id = $1::uuid AND tenant_id = $2::uuid AND project_id = $3::uuid`,
                [eventId, tenantId, projectId]
              );
              return res.rows[0]?.producer_namespace;
            },
            { readOnly: true }
          );
          if (evNsRes === undefined) {
            throw new NotFoundDomainError({ code: "NOT_FOUND", message: "Event not found" });
          }
          canReadContent = await hasActiveProjectDataGrant({
            principalId: actor.session.principal.principalId,
            action: "events.content.read",
            tenantId,
            projectId,
            resourceProducerNamespace: parseProducerNamespace(evNsRes, "producer_namespace"),
            repo: ctx.authRepos.humanAuthorization,
            now: ctx.clock.nowInstant()
          });
          capabilities = buildCapabilitiesForActions(
            ctx,
            decision,
            "event",
            eventId,
            ["events.content.read"],
            { grantSatisfied: () => canReadContent }
          );
        }

        const data = await ctx.pgAdapter.withTransaction(
          ctx.pgAdapter.configuredRole,
          async (tx) => {
            const evRes = await tx.query<Record<string, unknown>>(
              `SELECT e.id, e.producer_id, e.producer_namespace, e.event_type_id, et.type_name,
                      e.event_schema_version, e.content_sha256, e.content_byte_count,
                      e.topology_version, e.project_event_sequence, e.state, e.blocking_reason,
                      e.producer_event_time, e.admitted_at, e.delivery_deadline_at, e.version,
                      o.id AS outbox_id, o.current_publication_generation, o.state AS outbox_state,
                      o.next_publish_at, o.last_safe_error_code,
                      ef.state AS fanout_state, ef.examined_count, ef.matched_count,
                      ef.delivery_count, ef.candidate_count, ef.last_progress_at, ef.completed_at,
                      COALESCE(edt.total_deliveries, 0)::text AS total_deliveries,
                      COALESCE(edt.terminal_deliveries, 0)::text AS terminal_deliveries,
                      COALESCE(edt.acknowledged_deliveries, 0)::text AS acknowledged_deliveries,
                      ep.retention_state
                 FROM rq.v_safe_events e
                 JOIN rq.event_types et ON et.id = e.event_type_id
                 LEFT JOIN rq.outbox_events o ON o.event_id = e.id
                 LEFT JOIN rq.event_fanout ef ON ef.event_id = e.id
                 LEFT JOIN rq.event_delivery_totals edt ON edt.event_id = e.id
                 LEFT JOIN rq.events re ON re.id = e.id
                 LEFT JOIN rq.event_payloads ep ON ep.id = re.content_payload_id
                WHERE e.id = $1::uuid AND e.tenant_id = $2::uuid AND e.project_id = $3::uuid`,
              [eventId, tenantId, projectId]
            );
            const r = evRes.rows[0];
            if (r === undefined) {
              throw new NotFoundDomainError({ code: "NOT_FOUND", message: "Event not found" });
            }
            const retState = asText(r["retention_state"], "required");
            return {
              event_id: eventId,
              event_type_id: String(r["event_type_id"]),
              event_type: String(r["type_name"]),
              event_schema_version: Number(r["event_schema_version"]),
              publication_channel_id: String(r["producer_id"]),
              namespace: String(r["producer_namespace"]),
              project_event_sequence: String(r["project_event_sequence"]),
              topology_version: String(r["topology_version"]),
              state: String(r["state"]),
              blocking_reason: r["blocking_reason"] ?? null,
              content_sha256: toHex(r["content_sha256"]),
              content_byte_count: Number(r["content_byte_count"]),
              admitted_at: formatPgTimestamp(r["admitted_at"]),
              delivery_deadline_at: formatPgTimestamp(r["delivery_deadline_at"]),
              producer_event_time:
                r["producer_event_time"] !== null ? formatPgTimestamp(r["producer_event_time"]) : null,
              version: String(r["version"]),
              publication: r["outbox_id"]
                ? {
                    outbox_id: asText(r["outbox_id"]),
                    current_publication_generation: asText(
                      r["current_publication_generation"],
                      "1"
                    ),
                    state: asText(r["outbox_state"], "pending"),
                    next_publish_at:
                      r["next_publish_at"] !== null ? formatPgTimestamp(r["next_publish_at"]) : null,
                    observation_state:
                      asText(r["outbox_state"]) === "published" ? "observed" : "not_observed",
                    first_observation: null,
                    latest_observation: null,
                    last_safe_error_code: r["last_safe_error_code"] ?? null
                  }
                : null,
              fanout: {
                event_id: eventId,
                state: asText(r["fanout_state"], "pending"),
                project_event_sequence: String(r["project_event_sequence"]),
                topology_version: String(r["topology_version"]),
                examined_count: asText(r["examined_count"], "0"),
                matched_count: asText(r["matched_count"], "0"),
                delivery_count: asText(r["delivery_count"], "0"),
                candidate_count: asText(r["candidate_count"], "0"),
                last_progress_at:
                  r["last_progress_at"] !== null ? formatPgTimestamp(r["last_progress_at"]) : null,
                completed_at:
                  r["completed_at"] !== null ? formatPgTimestamp(r["completed_at"]) : null,
                project_materialized_through_event_sequence: "0"
              },
              delivery_totals: {
                unit: "delivery_generation",
                population: "all_deliveries",
                total_deliveries: String(r["total_deliveries"]),
                terminal_deliveries: String(r["terminal_deliveries"]),
                acknowledged_deliveries: String(r["acknowledged_deliveries"])
              },
              content_availability: {
                view: "original",
                availability:
                  retState === "expired"
                    ? "expired"
                    : actor.kind === "human" && !canReadContent
                      ? "unavailable"
                      : "available",
                media_type: "application/json",
                byte_count: Number(r["content_byte_count"]),
                sha256: toHex(r["content_sha256"])
              },
              ...(capabilities !== undefined ? { capabilities } : {})
            };
          },
          { readOnly: true }
        );

        return sendSuccessEnvelope(reply, 200, data, { requestId: request.id });
      } finally {
        if (actor.kind === "human") {
          actor.session.destroySecrets();
        }
      }
    }
  );

  // Grant-gated Original Event Content Inspection
  app.get<{ Params: { tenant_id: string; project_id: string; event_id: string } }>(
    "/api/v1/tenants/:tenant_id/projects/:project_id/events/:event_id/content",
    async (request, reply) => {
      const tenantId = parseTenantId(request.params.tenant_id, "tenant_id");
      const projectId = parseProjectId(request.params.project_id, "project_id");
      const eventId = parseEventId(request.params.event_id, "event_id");
      const inst = await ctx.pgAdapter.withTransaction(
        ctx.pgAdapter.configuredRole,
        (tx) => readInstallationSnapshot(ctx, tx),
        { readOnly: true }
      );
      const { actor } = await authenticateHumanOrProducerRead(ctx, request, inst);
      try {
        const meta = await ctx.pgAdapter.withTransaction(
          ctx.pgAdapter.configuredRole,
          async (tx) => {
            const res = await tx.query<{ producer_id: string; producer_namespace: string }>(
              `SELECT producer_id, producer_namespace FROM rq.v_safe_events
                WHERE id = $1::uuid AND tenant_id = $2::uuid AND project_id = $3::uuid`,
              [eventId, tenantId, projectId]
            );
            return res.rows[0];
          },
          { readOnly: true }
        );
        if (meta === undefined) {
          throw new NotFoundDomainError({ code: "NOT_FOUND", message: "Event not found" });
        }

        if (actor.kind === "producer") {
          if (
            actor.metadata.tenant_id !== tenantId ||
            actor.metadata.project_id !== projectId ||
            meta.producer_id !== actor.metadata.producer_id
          ) {
            throw new AuthorizationDomainError({ code: "FORBIDDEN", message: "Forbidden" });
          }
          const payload = await ctx.pgAdapter.withTransaction(
            ctx.pgAdapter.configuredRole,
            (tx) => readEventPayloadBytes(tx, tenantId, projectId, eventId),
            { readOnly: true }
          );
          if (payload === undefined || payload.content === undefined) {
            throw new ConflictDomainError({
              code: "CONTENT_EXPIRED",
              message: "Event content has expired"
            });
          }
          return sendSuccessEnvelope(
            reply,
            200,
            {
              view: "original",
              availability: "available",
              media_type: "application/json",
              encoding: "base64",
              byte_count: payload.byteCount,
              sha256: payload.contentSha256,
              data: encodeBase64(payload.content)
            },
            { requestId: request.id }
          );
        }

        const view = await ctx.governanceService.readLosslessEventContent({
          session: actor.session,
          tenantId,
          projectId,
          eventId,
          producerNamespace: meta.producer_namespace
        });
        if (view.contentBytes === undefined) {
          throw new ConflictDomainError({
            code: "CONTENT_EXPIRED",
            message: "Event content has expired"
          });
        }

        return sendSuccessEnvelope(
          reply,
          200,
          {
            view: "original",
            availability: "available",
            media_type: "application/json",
            encoding: "base64",
            byte_count: view.byteCount,
            sha256: view.contentSha256,
            data: encodeBase64(view.contentBytes)
          },
          { requestId: request.id }
        );
      } finally {
        if (actor.kind === "human") {
          actor.session.destroySecrets();
        }
      }
    }
  );

  app.get<{ Params: { tenant_id: string; project_id: string; event_id: string } }>(
    "/api/v1/tenants/:tenant_id/projects/:project_id/events/:event_id/history",
    async (request, reply) => {
      const tenantId = parseTenantId(request.params.tenant_id, "tenant_id");
      const projectId = parseProjectId(request.params.project_id, "project_id");
      const eventId = parseEventId(request.params.event_id, "event_id");
      const inst = await ctx.pgAdapter.withTransaction(
        ctx.pgAdapter.configuredRole,
        (tx) => readInstallationSnapshot(ctx, tx),
        { readOnly: true }
      );
      const { auth } = await authenticateHumanRead(ctx, request, inst);
      try {
        await authorizeAction(ctx, auth, "events.read_safe", {
          installation: inst,
          tenantId,
          projectId
        });
        const rows = await ctx.pgAdapter.withTransaction(
          ctx.pgAdapter.configuredRole,
          async (tx) => {
            const res = await tx.query<Record<string, unknown>>(
              `SELECT event_id, event_sequence, event_kind, event_schema_version, recorded_at, safe_facts
                 FROM rq.event_history
                WHERE tenant_id = $1::uuid AND project_id = $2::uuid AND event_id = $3::uuid
                ORDER BY event_sequence ASC
                LIMIT 100`,
              [tenantId, projectId, eventId]
            );
            return res.rows;
          },
          { readOnly: true }
        );
        return sendSuccessEnvelope(
          reply,
          200,
          {
            items: rows.map((r) => ({
              event_id: String(r["event_id"]),
              event_sequence: String(r["event_sequence"]),
              event_kind: String(r["event_kind"]),
              supported_event_type: true,
              event_schema_version: Number(r["event_schema_version"]),
              recorded_at: formatPgTimestamp(r["recorded_at"]),
              safe_facts: r["safe_facts"] ?? {}
            })),
            page: { next_cursor: null, limit: 100, has_more: false }
          },
          { requestId: request.id }
        );
      } finally {
        auth.destroySecrets();
      }
    }
  );

  app.get<{ Params: { tenant_id: string; project_id: string; event_id: string } }>(
    "/api/v1/tenants/:tenant_id/projects/:project_id/events/:event_id/representations",
    async (request, reply) => {
      const tenantId = parseTenantId(request.params.tenant_id, "tenant_id");
      const projectId = parseProjectId(request.params.project_id, "project_id");
      const eventId = parseEventId(request.params.event_id, "event_id");
      const inst = await ctx.pgAdapter.withTransaction(
        ctx.pgAdapter.configuredRole,
        (tx) => readInstallationSnapshot(ctx, tx),
        { readOnly: true }
      );
      const { auth } = await authenticateHumanRead(ctx, request, inst);
      try {
        await authorizeAction(ctx, auth, "events.read_safe", {
          installation: inst,
          tenantId,
          projectId
        });
        const rows = await ctx.pgAdapter.withTransaction(
          ctx.pgAdapter.configuredRole,
          async (tx) => {
            const res = await tx.query<Record<string, unknown>>(
              `SELECT id, representation_version, profile_id, profile_version, target_schema_version,
                      source_content_sha256, body_sha256, byte_count, retention_state, created_at
                 FROM rq.event_wire_envelopes
                WHERE tenant_id = $1::uuid AND project_id = $2::uuid AND event_id = $3::uuid
                ORDER BY representation_version ASC`,
              [tenantId, projectId, eventId]
            );
            return res.rows;
          },
          { readOnly: true }
        );
        return sendSuccessEnvelope(
          reply,
          200,
          {
            items: rows.map((r) => ({
              wire_envelope_id: String(r["id"]),
              representation_version: Number(r["representation_version"]),
              profile_id: r["profile_id"] ?? null,
              profile_version: asOptionalText(r["profile_version"]),
              target_schema_version: r["target_schema_version"] ?? null,
              source_content_sha256: toHex(r["source_content_sha256"]),
              derived_content_sha256: null,
              body_sha256: toHex(r["body_sha256"]),
              byte_count: Number(r["byte_count"]),
              availability: String(r["retention_state"]) === "expired" ? "expired" : "available",
              retention_state: String(r["retention_state"]),
              created_at: formatPgTimestamp(r["created_at"])
            })),
            page: { next_cursor: null, limit: 100, has_more: false }
          },
          { requestId: request.id }
        );
      } finally {
        auth.destroySecrets();
      }
    }
  );

  app.get<{
    Params: { tenant_id: string; project_id: string; event_id: string; representation_version: string };
  }>(
    "/api/v1/tenants/:tenant_id/projects/:project_id/events/:event_id/representations/:representation_version/content",
    async (request, reply) => {
      const tenantId = parseTenantId(request.params.tenant_id, "tenant_id");
      const projectId = parseProjectId(request.params.project_id, "project_id");
      const eventId = parseEventId(request.params.event_id, "event_id");
      const repVersion = Number.parseInt(request.params.representation_version, 10);
      const inst = await ctx.pgAdapter.withTransaction(
        ctx.pgAdapter.configuredRole,
        (tx) => readInstallationSnapshot(ctx, tx),
        { readOnly: true }
      );
      const { auth } = await authenticateHumanRead(ctx, request, inst);
      try {
        await authorizeAction(ctx, auth, "events.content.read", {
          installation: inst,
          tenantId,
          projectId
        });
        const hasGrant = await hasActiveProjectDataGrant({
          principalId: auth.principal.principalId,
          action: "events.content.read",
          tenantId,
          projectId,
          repo: ctx.authRepos.humanAuthorization,
          now: ctx.clock.nowInstant()
        });
        if (!hasGrant) {
          throw new AuthorizationDomainError({
            code: "FORBIDDEN",
            message: "Explicit data grant is required to inspect event representation content"
          });
        }
        const payload = await ctx.pgAdapter.withTransaction(
          ctx.pgAdapter.configuredRole,
          async (tx) => {
            const envRes = await tx.query<{ id: string }>(
              `SELECT id FROM rq.event_wire_envelopes
                WHERE event_id = $1::uuid AND tenant_id = $2::uuid AND project_id = $3::uuid
                  AND representation_version = $4::integer`,
              [eventId, tenantId, projectId, repVersion]
            );
            const envId = envRes.rows[0]?.id;
            if (envId === undefined) {
              throw new NotFoundDomainError({ code: "NOT_FOUND", message: "Representation not found" });
            }
            return readWireEnvelopeBytes(tx, tenantId, projectId, parseCanonicalUuid(envId) as never);
          },
          { readOnly: true }
        );
        if (payload === undefined || payload.bodyBytes === undefined) {
          throw new ConflictDomainError({
            code: "CONTENT_EXPIRED",
            message: "Representation body expired"
          });
        }
        return sendSuccessEnvelope(
          reply,
          200,
          {
            view: "wire_envelope",
            availability: "available",
            representation_version: repVersion,
            media_type: "application/json",
            encoding: "base64",
            byte_count: payload.byteCount,
            sha256: payload.bodySha256,
            data: encodeBase64(payload.bodyBytes)
          },
          { requestId: request.id }
        );
      } finally {
        auth.destroySecrets();
      }
    }
  );

  // Deliveries
  app.get<{ Params: { tenant_id: string; project_id: string }; Querystring: Record<string, unknown> }>(
    "/api/v1/tenants/:tenant_id/projects/:project_id/deliveries",
    async (request, reply) => {
      const tenantId = parseTenantId(request.params.tenant_id, "tenant_id");
      const projectId = parseProjectId(request.params.project_id, "project_id");
      const inst = await ctx.pgAdapter.withTransaction(
        ctx.pgAdapter.configuredRole,
        (tx) => readInstallationSnapshot(ctx, tx),
        { readOnly: true }
      );
      const { actor } = await authenticateHumanOrProducerRead(ctx, request, inst);
      try {
        if (actor.kind === "producer") {
          if (actor.metadata.tenant_id !== tenantId || actor.metadata.project_id !== projectId) {
            throw new AuthorizationDomainError({
              code: "FORBIDDEN",
              message: "Producer credential belongs to a different project"
            });
          }
        } else {
          await authorizeAction(ctx, actor.session, "deliveries.read_safe", {
            installation: inst,
            tenantId,
            projectId
          });
        }
        const { limit, rawCursor } = parseCursorQueryParams(request.query);
        const eventIdFilter =
          typeof request.query["event_id"] === "string" && request.query["event_id"].trim().length > 0
            ? parseCanonicalUuid(request.query["event_id"], "query.event_id")
            : null;
        const endpointIdFilter =
          typeof request.query["endpoint_id"] === "string" &&
          request.query["endpoint_id"].trim().length > 0
            ? parseCanonicalUuid(request.query["endpoint_id"], "query.endpoint_id")
            : null;
        const stateFilter =
          typeof request.query["state"] === "string" && request.query["state"].trim().length > 0
            ? request.query["state"].trim()
            : null;
        const outcomeClassFilter =
          typeof request.query["outcome_class"] === "string" &&
          request.query["outcome_class"].trim().length > 0
            ? request.query["outcome_class"].trim()
            : null;
        const filterObj = {
          ...(eventIdFilter !== null ? { event_id: eventIdFilter } : {}),
          ...(endpointIdFilter !== null ? { endpoint_id: endpointIdFilter } : {}),
          ...(stateFilter !== null ? { state: stateFilter } : {}),
          ...(outcomeClassFilter !== null ? { outcome_class: outcomeClassFilter } : {})
        };
        const cursor = decodeApiCursor(ctx, rawCursor, {
          resource: "deliveries",
          tenantId,
          projectId,
          order: "created_at_desc_id_desc",
          filter: filterObj
        });
        const boundaryId = cursor?.boundary.id ?? null;

        const rows = await ctx.pgAdapter.withTransaction(
          ctx.pgAdapter.configuredRole,
          async (tx) => {
            const res = await tx.query<Record<string, unknown>>(
              `SELECT id, family_id, event_id, delivery_generation, replay_proposal_id,
                      subscription_id, original_subscription_version, dispatch_subscription_version,
                      endpoint_id, endpoint_version, wire_envelope_id, state, blocking_reason,
                      attempt_count, maximum_attempts, deadline_at, next_eligible_at,
                      acknowledged_at, terminal_at, last_outcome_class, created_at, version
                 FROM rq.v_safe_deliveries
                WHERE tenant_id = $1::uuid AND project_id = $2::uuid
                  AND ($3::uuid IS NULL OR event_id = $3::uuid)
                  AND ($4::uuid IS NULL OR endpoint_id = $4::uuid)
                  AND ($5::text IS NULL OR state = $5::text)
                  AND ($6::text IS NULL OR last_outcome_class = $6::text)
                  AND ($7::uuid IS NULL OR id < $7::uuid)
                ORDER BY created_at DESC, id DESC
                LIMIT $8::integer`,
              [
                tenantId,
                projectId,
                eventIdFilter,
                endpointIdFilter,
                stateFilter,
                outcomeClassFilter,
                boundaryId,
                limit + 1
              ]
            );
            return res.rows;
          },
          { readOnly: true }
        );

        const hasMore = rows.length > limit;
        const pageRows = rows.slice(0, limit);
        const items = pageRows.map((r) => ({
          delivery_id: String(r["id"]),
          family_id: String(r["family_id"]),
          event_id: String(r["event_id"]),
          delivery_generation: String(r["delivery_generation"]),
          is_replay: Number(r["delivery_generation"]) > 0,
          replay_proposal_id: r["replay_proposal_id"] ?? null,
          subscription_id: String(r["subscription_id"]),
          original_subscription_version: String(r["original_subscription_version"]),
          dispatch_subscription_version: String(r["dispatch_subscription_version"]),
          endpoint_id: String(r["endpoint_id"]),
          endpoint_version: String(r["endpoint_version"]),
          wire_envelope_id: String(r["wire_envelope_id"]),
          state: String(r["state"]),
          execution_bucket:
            String(r["state"]) === "ready" || String(r["state"]) === "sending"
              ? "eligible_now"
              : "terminal",
          blocking_reason: r["blocking_reason"] ?? null,
          attempt_count: Number(r["attempt_count"]),
          maximum_attempts: Number(r["maximum_attempts"]),
          deadline_at: formatPgTimestamp(r["deadline_at"]),
          next_eligible_at: formatPgTimestamp(r["next_eligible_at"]),
          acknowledged_at:
            r["acknowledged_at"] !== null ? formatPgTimestamp(r["acknowledged_at"]) : null,
          terminal_at: r["terminal_at"] !== null ? formatPgTimestamp(r["terminal_at"]) : null,
          last_outcome_class: r["last_outcome_class"] ?? null,
          version: String(r["version"])
        }));

        const last = pageRows[pageRows.length - 1];
        const next_cursor =
          hasMore && last !== undefined
            ? encodeApiCursor(ctx, {
                resource: "deliveries",
                tenantId,
                projectId,
                order: "created_at_desc_id_desc",
                filter: filterObj,
                boundary: {
                  id: parseCanonicalUuid(last["id"], "id"),
                  timestamp: formatPgTimestamp(last["created_at"])
                }
              })
            : null;

        return sendSuccessEnvelope(
          reply,
          200,
          { items, page: { next_cursor, limit, has_more: hasMore } },
          { requestId: request.id }
        );
      } finally {
        if (actor.kind === "human") {
          actor.session.destroySecrets();
        }
      }
    }
  );

  app.get<{ Params: { tenant_id: string; project_id: string; delivery_id: string } }>(
    "/api/v1/tenants/:tenant_id/projects/:project_id/deliveries/:delivery_id",
    async (request, reply) => {
      const tenantId = parseTenantId(request.params.tenant_id, "tenant_id");
      const projectId = parseProjectId(request.params.project_id, "project_id");
      const deliveryId = parseDeliveryId(request.params.delivery_id, "delivery_id");
      const inst = await ctx.pgAdapter.withTransaction(
        ctx.pgAdapter.configuredRole,
        (tx) => readInstallationSnapshot(ctx, tx),
        { readOnly: true }
      );
      const { actor } = await authenticateHumanOrProducerRead(ctx, request, inst);
      try {
        let capabilities: ReturnType<typeof buildCapabilitiesForActions> | undefined;
        if (actor.kind === "producer") {
          if (actor.metadata.tenant_id !== tenantId || actor.metadata.project_id !== projectId) {
            throw new AuthorizationDomainError({
              code: "FORBIDDEN",
              message: "Producer credential belongs to a different project"
            });
          }
        } else {
          const decision = await authorizeAction(ctx, actor.session, "deliveries.read_safe", {
            installation: inst,
            tenantId,
            projectId
          });
          capabilities = buildCapabilitiesForActions(
            ctx,
            decision,
            "delivery",
            deliveryId,
            ["deliveries.replay.propose", "deliveries.suppression.propose", "deliveries.request.read"]
          );
        }
        const row = await ctx.pgAdapter.withTransaction(
          ctx.pgAdapter.configuredRole,
          async (tx) => {
            const res = await tx.query<Record<string, unknown>>(
              `SELECT * FROM rq.v_safe_deliveries
                WHERE id = $1::uuid AND tenant_id = $2::uuid AND project_id = $3::uuid`,
              [deliveryId, tenantId, projectId]
            );
            return res.rows[0];
          },
          { readOnly: true }
        );
        if (row === undefined) {
          throw new NotFoundDomainError({ code: "NOT_FOUND", message: "Delivery not found" });
        }
        return sendSuccessEnvelope(
          reply,
          200,
          {
            delivery_id: deliveryId,
            family_id: String(row["family_id"]),
            event_id: String(row["event_id"]),
            delivery_generation: String(row["delivery_generation"]),
            is_replay: Number(row["delivery_generation"]) > 0,
            replay_proposal_id: row["replay_proposal_id"] ?? null,
            subscription_id: String(row["subscription_id"]),
            original_subscription_version: String(row["original_subscription_version"]),
            dispatch_subscription_version: String(row["dispatch_subscription_version"]),
            endpoint_id: String(row["endpoint_id"]),
            endpoint_version: String(row["endpoint_version"]),
            wire_envelope_id: String(row["wire_envelope_id"]),
            state: String(row["state"]),
            blocking_reason: row["blocking_reason"] ?? null,
            attempt_count: Number(row["attempt_count"]),
            maximum_attempts: Number(row["maximum_attempts"]),
            deadline_at: formatPgTimestamp(row["deadline_at"]),
            next_eligible_at: formatPgTimestamp(row["next_eligible_at"]),
            acknowledged_at:
              row["acknowledged_at"] !== null ? formatPgTimestamp(row["acknowledged_at"]) : null,
            terminal_at:
              row["terminal_at"] !== null ? formatPgTimestamp(row["terminal_at"]) : null,
            last_outcome_class: row["last_outcome_class"] ?? null,
            version: String(row["version"]),
            ...(capabilities !== undefined ? { capabilities } : {})
          },
          { requestId: request.id }
        );
      } finally {
        if (actor.kind === "human") {
          actor.session.destroySecrets();
        }
      }
    }
  );

  // Delivery sub-resources: attempts, attempt detail, history, late-observations, network-decisions, request-content, receiver-receipts, trace-references
  app.get<{ Params: { tenant_id: string; project_id: string; delivery_id: string } }>(
    "/api/v1/tenants/:tenant_id/projects/:project_id/deliveries/:delivery_id/attempts",
    async (request, reply) => {
      const tenantId = parseTenantId(request.params.tenant_id, "tenant_id");
      const projectId = parseProjectId(request.params.project_id, "project_id");
      const deliveryId = parseDeliveryId(request.params.delivery_id, "delivery_id");
      const inst = await ctx.pgAdapter.withTransaction(
        ctx.pgAdapter.configuredRole,
        (tx) => readInstallationSnapshot(ctx, tx),
        { readOnly: true }
      );
      const { auth } = await authenticateHumanRead(ctx, request, inst);
      try {
        await authorizeAction(ctx, auth, "deliveries.read_safe", {
          installation: inst,
          tenantId,
          projectId
        });
        const rows = await ctx.pgAdapter.withTransaction(
          ctx.pgAdapter.configuredRole,
          async (tx) => {
            const res = await tx.query<Record<string, unknown>>(
              `SELECT da.id, da.attempt_number, da.state, da.prepared_at, da.send_started_at,
                      da.finished_at, da.response_status, da.response_body_sha256,
                      da.outcome_class, da.safe_error_code
                 FROM rq.delivery_attempts da
                WHERE da.tenant_id = $1::uuid AND da.project_id = $2::uuid AND da.delivery_id = $3::uuid
                ORDER BY da.attempt_number ASC`,
              [tenantId, projectId, deliveryId]
            );
            return res.rows;
          },
          { readOnly: true }
        );
        return sendSuccessEnvelope(
          reply,
          200,
          {
            items: rows.map((r) => ({
              attempt_id: String(r["id"]),
              delivery_id: deliveryId,
              attempt_number: Number(r["attempt_number"]),
              state: String(r["state"]),
              prepared_at: formatPgTimestamp(r["prepared_at"]),
              send_started_at:
                r["send_started_at"] !== null ? formatPgTimestamp(r["send_started_at"]) : null,
              finished_at: r["finished_at"] !== null ? formatPgTimestamp(r["finished_at"]) : null,
              response_status: r["response_status"] ?? null,
              response_body_sha256:
                r["response_body_sha256"] !== null ? toHex(r["response_body_sha256"]) : null,
              outcome_class: r["outcome_class"] ?? null,
              safe_error_code: r["safe_error_code"] ?? null
            })),
            page: { next_cursor: null, limit: 100, has_more: false }
          },
          { requestId: request.id }
        );
      } finally {
        auth.destroySecrets();
      }
    }
  );

  app.get<{
    Params: { tenant_id: string; project_id: string; delivery_id: string; attempt_id: string };
  }>(
    "/api/v1/tenants/:tenant_id/projects/:project_id/deliveries/:delivery_id/attempts/:attempt_id",
    async (request, reply) => {
      const tenantId = parseTenantId(request.params.tenant_id, "tenant_id");
      const projectId = parseProjectId(request.params.project_id, "project_id");
      const deliveryId = parseDeliveryId(request.params.delivery_id, "delivery_id");
      const attemptId = parseCanonicalUuid(request.params.attempt_id, "attempt_id");
      const inst = await ctx.pgAdapter.withTransaction(
        ctx.pgAdapter.configuredRole,
        (tx) => readInstallationSnapshot(ctx, tx),
        { readOnly: true }
      );
      const { auth } = await authenticateHumanRead(ctx, request, inst);
      try {
        await authorizeAction(ctx, auth, "deliveries.read_safe", {
          installation: inst,
          tenantId,
          projectId
        });
        const row = await ctx.pgAdapter.withTransaction(
          ctx.pgAdapter.configuredRole,
          async (tx) => {
            const res = await tx.query<Record<string, unknown>>(
              `SELECT * FROM rq.delivery_attempts
                WHERE id = $1::uuid AND delivery_id = $2::uuid AND project_id = $3::uuid AND tenant_id = $4::uuid`,
              [attemptId, deliveryId, projectId, tenantId]
            );
            return res.rows[0];
          },
          { readOnly: true }
        );
        if (row === undefined) {
          throw new NotFoundDomainError({ code: "NOT_FOUND", message: "Attempt not found" });
        }
        return sendSuccessEnvelope(
          reply,
          200,
          {
            attempt_id: attemptId,
            delivery_id: deliveryId,
            attempt_number: Number(row["attempt_number"]),
            state: String(row["state"]),
            prepared_at: formatPgTimestamp(row["prepared_at"]),
            send_started_at:
              row["send_started_at"] !== null ? formatPgTimestamp(row["send_started_at"]) : null,
            finished_at:
              row["finished_at"] !== null ? formatPgTimestamp(row["finished_at"]) : null,
            response_status: row["response_status"] ?? null,
            outcome_class: row["outcome_class"] ?? null,
            safe_error_code: row["safe_error_code"] ?? null
          },
          { requestId: request.id }
        );
      } finally {
        auth.destroySecrets();
      }
    }
  );

  app.get<{ Params: { tenant_id: string; project_id: string; delivery_id: string } }>(
    "/api/v1/tenants/:tenant_id/projects/:project_id/deliveries/:delivery_id/history",
    async (request, reply) => {
      const tenantId = parseTenantId(request.params.tenant_id, "tenant_id");
      const projectId = parseProjectId(request.params.project_id, "project_id");
      const deliveryId = parseDeliveryId(request.params.delivery_id, "delivery_id");
      const inst = await ctx.pgAdapter.withTransaction(
        ctx.pgAdapter.configuredRole,
        (tx) => readInstallationSnapshot(ctx, tx),
        { readOnly: true }
      );
      const { auth } = await authenticateHumanRead(ctx, request, inst);
      try {
        await authorizeAction(ctx, auth, "deliveries.read_safe", {
          installation: inst,
          tenantId,
          projectId
        });
        const rows = await ctx.pgAdapter.withTransaction(
          ctx.pgAdapter.configuredRole,
          async (tx) => {
            const res = await tx.query<Record<string, unknown>>(
              `SELECT delivery_id, history_sequence, event_kind, recorded_at, safe_facts
                 FROM rq.delivery_history
                WHERE tenant_id = $1::uuid AND project_id = $2::uuid AND delivery_id = $3::uuid
                ORDER BY history_sequence ASC`,
              [tenantId, projectId, deliveryId]
            );
            return res.rows;
          },
          { readOnly: true }
        );
        return sendSuccessEnvelope(
          reply,
          200,
          {
            items: rows.map((r) => ({
              delivery_id: String(r["delivery_id"]),
              history_sequence: String(r["history_sequence"]),
              event_kind: String(r["event_kind"]),
              supported_event_type: true,
              recorded_at: formatPgTimestamp(r["recorded_at"]),
              safe_facts: r["safe_facts"] ?? {}
            })),
            page: { next_cursor: null, limit: 100, has_more: false }
          },
          { requestId: request.id }
        );
      } finally {
        auth.destroySecrets();
      }
    }
  );

  app.get<{ Params: { tenant_id: string; project_id: string; delivery_id: string } }>(
    "/api/v1/tenants/:tenant_id/projects/:project_id/deliveries/:delivery_id/late-observations",
    async (request, reply) => {
      const tenantId = parseTenantId(request.params.tenant_id, "tenant_id");
      const projectId = parseProjectId(request.params.project_id, "project_id");
      const deliveryId = parseDeliveryId(request.params.delivery_id, "delivery_id");
      const inst = await ctx.pgAdapter.withTransaction(
        ctx.pgAdapter.configuredRole,
        (tx) => readInstallationSnapshot(ctx, tx),
        { readOnly: true }
      );
      const { auth } = await authenticateHumanRead(ctx, request, inst);
      try {
        await authorizeAction(ctx, auth, "deliveries.read_safe", {
          installation: inst,
          tenantId,
          projectId
        });
        const rows = await ctx.pgAdapter.withTransaction(
          ctx.pgAdapter.configuredRole,
          async (tx) => {
            const res = await tx.query<Record<string, unknown>>(
              `SELECT id, attempt_id, observation_kind, facts_sha256, safe_facts, recorded_at
                 FROM rq.late_delivery_observations
                WHERE tenant_id = $1::uuid AND project_id = $2::uuid AND delivery_id = $3::uuid
                ORDER BY recorded_at ASC`,
              [tenantId, projectId, deliveryId]
            );
            return res.rows;
          },
          { readOnly: true }
        );
        return sendSuccessEnvelope(
          reply,
          200,
          {
            items: rows.map((r) => ({
              observation_id: String(r["id"]),
              attempt_id: String(r["attempt_id"]),
              observation_kind: String(r["observation_kind"]),
              facts_sha256: toHex(r["facts_sha256"]),
              safe_facts: r["safe_facts"] ?? {},
              recorded_at: formatPgTimestamp(r["recorded_at"])
            })),
            page: { next_cursor: null, limit: 100, has_more: false }
          },
          { requestId: request.id }
        );
      } finally {
        auth.destroySecrets();
      }
    }
  );

  app.get<{ Params: { tenant_id: string; project_id: string; delivery_id: string } }>(
    "/api/v1/tenants/:tenant_id/projects/:project_id/deliveries/:delivery_id/network-decisions",
    async (request, reply) => {
      const tenantId = parseTenantId(request.params.tenant_id, "tenant_id");
      const projectId = parseProjectId(request.params.project_id, "project_id");
      const deliveryId = parseDeliveryId(request.params.delivery_id, "delivery_id");
      const inst = await ctx.pgAdapter.withTransaction(
        ctx.pgAdapter.configuredRole,
        (tx) => readInstallationSnapshot(ctx, tx),
        { readOnly: true }
      );
      const { auth } = await authenticateHumanRead(ctx, request, inst);
      try {
        await authorizeAction(ctx, auth, "deliveries.read_safe", {
          installation: inst,
          tenantId,
          projectId
        });
        const rows = await ctx.pgAdapter.withTransaction(
          ctx.pgAdapter.configuredRole,
          async (tx) => {
            const res = await tx.query<Record<string, unknown>>(
              `SELECT ed.id, ed.delivery_attempt_id, ed.authority_sha256, ed.registry_ipv4_sha256,
                      ed.answer_set_sha256, ed.selected_address_sha256, ed.selected_family,
                      ed.decision, ed.reason_code, ed.observed_at
                 FROM rq.egress_decisions ed
                 JOIN rq.delivery_attempts da ON da.id = ed.delivery_attempt_id
                WHERE ed.tenant_id = $1::uuid AND ed.project_id = $2::uuid AND da.delivery_id = $3::uuid
                ORDER BY ed.observed_at ASC`,
              [tenantId, projectId, deliveryId]
            );
            return res.rows;
          },
          { readOnly: true }
        );
        return sendSuccessEnvelope(
          reply,
          200,
          {
            items: rows.map((r) => ({
              decision_id: String(r["id"]),
              attempt_id: String(r["delivery_attempt_id"]),
              policy_sha256: toHex(r["authority_sha256"]),
              registry_sha256: toHex(r["registry_ipv4_sha256"]),
              dns_answer_sha256: toHex(r["answer_set_sha256"]),
              pinned_peer_sha256: toHex(r["selected_address_sha256"] ?? r["answer_set_sha256"]),
              ip_family: Number(r["selected_family"] ?? 4) === 6 ? "ipv6" : "ipv4",
              decision: String(r["decision"]) === "allowed" ? "allowed" : "denied",
              reason_code: r["reason_code"] ?? null,
              observed_at: formatPgTimestamp(r["observed_at"])
            })),
            page: { next_cursor: null, limit: 100, has_more: false }
          },
          { requestId: request.id }
        );
      } finally {
        auth.destroySecrets();
      }
    }
  );

  app.get<{ Params: { tenant_id: string; project_id: string; delivery_id: string } }>(
    "/api/v1/tenants/:tenant_id/projects/:project_id/deliveries/:delivery_id/request-content",
    async (request, reply) => {
      const tenantId = parseTenantId(request.params.tenant_id, "tenant_id");
      const projectId = parseProjectId(request.params.project_id, "project_id");
      const deliveryId = parseDeliveryId(request.params.delivery_id, "delivery_id");
      const inst = await ctx.pgAdapter.withTransaction(
        ctx.pgAdapter.configuredRole,
        (tx) => readInstallationSnapshot(ctx, tx),
        { readOnly: true }
      );
      const { auth } = await authenticateHumanRead(ctx, request, inst);
      try {
        await authorizeAction(ctx, auth, "deliveries.request.read", {
          installation: inst,
          tenantId,
          projectId
        });
        const hasGrant = await hasActiveProjectDataGrant({
          principalId: auth.principal.principalId,
          action: "deliveries.request.read",
          tenantId,
          projectId,
          repo: ctx.authRepos.humanAuthorization,
          now: ctx.clock.nowInstant()
        });
        if (!hasGrant) {
          throw new AuthorizationDomainError({
            code: "FORBIDDEN",
            message: "Explicit data grant is required to inspect delivery request content"
          });
        }
        const envData = await ctx.pgAdapter.withTransaction(
          ctx.pgAdapter.configuredRole,
          async (tx) => {
            const dRes = await tx.query<{ wire_envelope_id: string }>(
              `SELECT wire_envelope_id FROM rq.v_safe_deliveries
                WHERE id = $1::uuid AND tenant_id = $2::uuid AND project_id = $3::uuid`,
              [deliveryId, tenantId, projectId]
            );
            const envId = dRes.rows[0]?.wire_envelope_id;
            if (envId === undefined) {
              throw new NotFoundDomainError({ code: "NOT_FOUND", message: "Delivery not found" });
            }
            return readWireEnvelopeBytes(tx, tenantId, projectId, parseCanonicalUuid(envId) as never);
          },
          { readOnly: true }
        );
        if (envData === undefined || envData.bodyBytes === undefined) {
          throw new ConflictDomainError({
            code: "CONTENT_EXPIRED",
            message: "Delivery wire content has expired"
          });
        }
        return sendSuccessEnvelope(
          reply,
          200,
          {
            representation_version: envData.representationVersion,
            wire_envelope_id: envData.wireEnvelopeId,
            media_type: "application/json",
            encoding: "base64",
            byte_count: envData.byteCount,
            sha256: envData.bodySha256,
            data: encodeBase64(envData.bodyBytes),
            availability: "available"
          },
          { requestId: request.id }
        );
      } finally {
        auth.destroySecrets();
      }
    }
  );

  app.get<{ Params: { tenant_id: string; project_id: string; delivery_id: string } }>(
    "/api/v1/tenants/:tenant_id/projects/:project_id/deliveries/:delivery_id/receiver-receipts",
    async (request, reply) => {
      const tenantId = parseTenantId(request.params.tenant_id, "tenant_id");
      const projectId = parseProjectId(request.params.project_id, "project_id");
      const deliveryId = parseDeliveryId(request.params.delivery_id, "delivery_id");
      const inst = await ctx.pgAdapter.withTransaction(
        ctx.pgAdapter.configuredRole,
        (tx) => readInstallationSnapshot(ctx, tx),
        { readOnly: true }
      );
      const { auth } = await authenticateHumanRead(ctx, request, inst);
      try {
        await authorizeAction(ctx, auth, "receiver_receipts.read", {
          installation: inst,
          tenantId,
          projectId
        });
        const hasGrant = await hasActiveProjectDataGrant({
          principalId: auth.principal.principalId,
          action: "receiver_receipts.read",
          tenantId,
          projectId,
          repo: ctx.authRepos.humanAuthorization,
          now: ctx.clock.nowInstant()
        });
        if (!hasGrant) {
          throw new AuthorizationDomainError({
            code: "FORBIDDEN",
            message: "Explicit data grant is required to inspect receiver receipts"
          });
        }
        const rows = await ctx.pgAdapter.withTransaction(
          ctx.pgAdapter.configuredRole,
          async (tx) => {
            const res = await tx.query<Record<string, unknown>>(
              `SELECT id, attempt_id, consumer_contract_scope, receipt_reference, receipt_facts_sha256,
                      key_id, state, observed_at, receipt_facts
                 FROM rq.receiver_receipt_observations
                WHERE tenant_id = $1::uuid AND project_id = $2::uuid AND delivery_id = $3::uuid
                ORDER BY observed_at ASC`,
              [tenantId, projectId, deliveryId]
            );
            return res.rows;
          },
          { readOnly: true }
        );
        return sendSuccessEnvelope(
          reply,
          200,
          {
            items: rows.map((r) => ({
              observation_id: String(r["id"]),
              delivery_id: deliveryId,
              attempt_id: r["attempt_id"] ?? null,
              consumer_contract_scope: String(r["consumer_contract_scope"]),
              receipt_reference: String(r["receipt_reference"]),
              receipt_facts_sha256: toHex(r["receipt_facts_sha256"]),
              key_id: String(r["key_id"]),
              state: String(r["state"]),
              observed_at: formatPgTimestamp(r["observed_at"]),
              receipt_facts: r["receipt_facts"] ?? {}
            })),
            page: { next_cursor: null, limit: 100, has_more: false }
          },
          { requestId: request.id }
        );
      } finally {
        auth.destroySecrets();
      }
    }
  );

  app.get<{ Params: { tenant_id: string; project_id: string; delivery_id: string } }>(
    "/api/v1/tenants/:tenant_id/projects/:project_id/deliveries/:delivery_id/trace-references",
    async (request, reply) => {
      const tenantId = parseTenantId(request.params.tenant_id, "tenant_id");
      const projectId = parseProjectId(request.params.project_id, "project_id");
      const deliveryId = parseDeliveryId(request.params.delivery_id, "delivery_id");
      const inst = await ctx.pgAdapter.withTransaction(
        ctx.pgAdapter.configuredRole,
        (tx) => readInstallationSnapshot(ctx, tx),
        { readOnly: true }
      );
      const { auth } = await authenticateHumanRead(ctx, request, inst);
      try {
        await authorizeAction(ctx, auth, "deliveries.read_safe", {
          installation: inst,
          tenantId,
          projectId
        });
        const rows = await ctx.pgAdapter.withTransaction(
          ctx.pgAdapter.configuredRole,
          async (tx) => {
            const res = await tx.query<Record<string, unknown>>(
              `SELECT trace_id, span_id, context_kind
                 FROM rq.trace_references
                WHERE tenant_id = $1::uuid AND project_id = $2::uuid AND resource_id = $3::uuid
                ORDER BY recorded_at ASC`,
              [tenantId, projectId, deliveryId]
            );
            return res.rows;
          },
          { readOnly: true }
        );
        return sendSuccessEnvelope(
          reply,
          200,
          {
            items: rows.map((r) => ({
              trace_id: String(r["trace_id"]),
              span_id: String(r["span_id"]),
              view_url: null,
              availability: "available"
            })),
            page: { next_cursor: null, limit: 100, has_more: false }
          },
          { requestId: request.id }
        );
      } finally {
        auth.destroySecrets();
      }
    }
  );

  // Authenticated SSE Watch Streams (events, deliveries, and generic /api/v1/watch)
  const handleSseWatch = async (
    request: Parameters<typeof authenticateHumanOrProducerRead>[1],
    reply: FastifyReply,
    params: {
      readonly tenantId: TenantId;
      readonly projectId: ProjectId;
      readonly resourceKind: "event" | "delivery";
      readonly resourceId: string;
    }
  ): Promise<void> => {
    const inst = await ctx.pgAdapter.withTransaction(
      ctx.pgAdapter.configuredRole,
      (tx) => readInstallationSnapshot(ctx, tx),
      { readOnly: true }
    );
    const { actor, headerMap } = await authenticateHumanOrProducerRead(ctx, request, inst);

    let principalId: PrincipalId;
    let sessionId: string | null = null;
    let producerCredentialId: string | null = null;
    let authCutoffAt: string;

    try {
      if (actor.kind === "human") {
        await authorizeAction(
          ctx,
          actor.session,
          params.resourceKind === "event" ? "events.read_safe" : "deliveries.read_safe",
          { installation: inst, tenantId: params.tenantId, projectId: params.projectId }
        );
        principalId = actor.session.principal.principalId;
        sessionId = actor.session.session.id;
        authCutoffAt = formatUtcTimestamp(actor.session.session.idleExpiresAt);
      } else {
        if (
          actor.metadata.tenant_id !== params.tenantId ||
          actor.metadata.project_id !== params.projectId
        ) {
          throw new AuthorizationDomainError({
            code: "FORBIDDEN",
            message: "Producer credential belongs to a different project"
          });
        }
        principalId = actor.metadata.producer_id as unknown as PrincipalId;
        const prodPrincipal = await ctx.pgAdapter.withTransaction(
          ctx.pgAdapter.configuredRole,
          async (tx) => {
            const res = await tx.query<{ principal_id: string }>(
              `SELECT principal_id FROM rq.producers WHERE id = $1::uuid`,
              [actor.metadata.producer_id]
            );
            return res.rows[0]?.principal_id;
          },
          { readOnly: true }
        );
        if (prodPrincipal === undefined) {
          throw new AuthorizationDomainError({
            code: "FORBIDDEN",
            message: "Producer principal not found"
          });
        }
        principalId = prodPrincipal as PrincipalId;
        producerCredentialId = actor.metadata.credential_id;
        authCutoffAt = actor.metadata.expires_at;
      }

      const lastEventIdHeader = extractSingleRawHeader(headerMap, "last-event-id");
      const afterSeq =
        lastEventIdHeader !== undefined && /^\d+$/.test(lastEventIdHeader)
          ? parseInt64BigInt(lastEventIdHeader, "Last-Event-ID")
          : 0n;

      const leaseId = parseWatchLeaseId(ctx.ids.nextUuid(), "lease_id");
      const nowInstant = ctx.clock.nowInstant();
      const streamCutoffAt = formatUtcTimestamp(nowInstant.add({ milliseconds: ctx.sseMaxLifetimeMs }));

      // Open lease inside DB enforcing actor/tenant/project watch capacity caps & state verification
      const snapshotData = await ctx.pgAdapter.withTransaction(ctx.pgAdapter.configuredRole, async (tx) => {
        await ensureApiRuntimeRegistered(ctx, tx, inst.controlEpoch);

        // Verify target resource exists in scope
        const stateQuery =
          params.resourceKind === "event"
            ? await tx.query<{ state: string; version: string; event_id: string }>(
                `SELECT state, version::text AS version, id::text AS event_id FROM rq.v_safe_events
                  WHERE id = $1::uuid AND tenant_id = $2::uuid AND project_id = $3::uuid`,
                [params.resourceId, params.tenantId, params.projectId]
              )
            : await tx.query<{ state: string; version: string; event_id: string }>(
                `SELECT state, version::text AS version, event_id::text AS event_id FROM rq.v_safe_deliveries
                  WHERE id = $1::uuid AND tenant_id = $2::uuid AND project_id = $3::uuid`,
                [params.resourceId, params.tenantId, params.projectId]
              );
        const target = stateQuery.rows[0];
        if (target === undefined) {
          throw new NotFoundDomainError({
            code: "NOT_FOUND",
            message: `${params.resourceKind} ${params.resourceId} not found`
          });
        }

        await openWatchLease(tx, {
          leaseId,
          tenantId: params.tenantId,
          projectId: params.projectId,
          principalId,
          actorKind: actor.kind,
          sessionId: sessionId as never,
          producerCredentialId: producerCredentialId as never,
          resourceKind: params.resourceKind,
          resourceId: params.resourceId,
          runtimeInstanceId: ctx.runtimeInstanceId,
          controlEpoch: inst.controlEpoch,
          authCutoffAt,
          streamCutoffAt
        });

        const historyRows =
          params.resourceKind === "event"
            ? await tx.query<Record<string, unknown>>(
                `SELECT event_sequence AS seq, event_kind, event_schema_version, recorded_at, safe_facts
                   FROM rq.event_history
                  WHERE tenant_id = $1::uuid AND project_id = $2::uuid AND event_id = $3::uuid
                    AND event_sequence > $4::bigint
                  ORDER BY event_sequence ASC
                  LIMIT 25`,
                [params.tenantId, params.projectId, params.resourceId, afterSeq.toString(10)]
              )
            : await tx.query<Record<string, unknown>>(
                `SELECT history_sequence AS seq, event_kind, 1 AS event_schema_version, recorded_at, safe_facts
                   FROM rq.delivery_history
                  WHERE tenant_id = $1::uuid AND project_id = $2::uuid AND delivery_id = $3::uuid
                    AND history_sequence > $4::bigint
                  ORDER BY history_sequence ASC
                  LIMIT 25`,
                [params.tenantId, params.projectId, params.resourceId, afterSeq.toString(10)]
              );

        return {
          eventId: parseEventId(target.event_id, "event_id"),
          state: target.state,
          version: target.version,
          history: historyRows.rows
        };
      });

      const observedAt = formatUtcTimestamp(ctx.clock.nowInstant());
      const latestSeq =
        snapshotData.history.length > 0
          ? asText(snapshotData.history[snapshotData.history.length - 1]?.["seq"], "0")
          : afterSeq.toString(10);

      const safeResourceId = parseCanonicalUuid(params.resourceId, "resource_id");
      const latestSeqNonNeg = parseNonNegativeInt64String(latestSeq, "high_water_sequence");
      const snapshotCursor = encodeApiCursor(ctx, {
        resource: params.resourceKind === "event" ? "watch_events" : "watch_deliveries",
        tenantId: params.tenantId,
        projectId: params.projectId,
        parentId: safeResourceId,
        order: params.resourceKind === "event" ? "event_sequence_asc" : "history_sequence_asc",
        boundary: { sequence: latestSeqNonNeg }
      });

      const snapshotFrame = formatSseFrame({
        id: latestSeq,
        payload: {
          response_schema_version: 1,
          frame_type: "snapshot",
          resource_kind: params.resourceKind,
          resource_id: safeResourceId,
          cursor: snapshotCursor,
          high_water_sequence: latestSeqNonNeg,
          observed_at: observedAt,
          state: snapshotData.state,
          current_version: parseInt64String(snapshotData.version, "current_version"),
          summary: {
            lease_id: leaseId
          }
        }
      });

      const eventFrames = snapshotData.history.map((h) =>
        buildBoundedSseEventFrame({
          id: String(h["seq"]),
          resourceKind: params.resourceKind,
          resourceId: safeResourceId,
          eventId: snapshotData.eventId,
          sequence: parseNonNegativeInt64String(String(h["seq"]), "event_sequence"),
          eventType: String(h["event_kind"]),
          eventSchemaVersion: Number(h["event_schema_version"] ?? 1),
          recordedAt: formatPgTimestamp(h["recorded_at"]),
          safeDetails: (h["safe_facts"] ?? {}) as Record<string, unknown>
        })
      );

      reply.hijack();
      reply.raw.writeHead(200, {
        "Content-Type": "text/event-stream; charset=utf-8",
        "Cache-Control": "no-store, no-transform",
        Connection: "keep-alive",
        "X-Accel-Buffering": "no"
      });
      reply.raw.flushHeaders?.();
      reply.raw.write(snapshotFrame);
      for (const frame of eventFrames) {
        reply.raw.write(frame);
      }

      const onceParam = (request.query as Record<string, unknown> | undefined)?.["once"];
      if (onceParam === "true" || onceParam === "1") {
        await ctx.pgAdapter
          .withTransaction(ctx.pgAdapter.configuredRole, (tx) => closeWatchLease(tx, leaseId))
          .catch(() => undefined);
        reply.raw.end();
        return;
      }

      reply.raw.write(formatSseHeartbeatFrame(`lease:${leaseId}`));

      let lastSentSeq = parseInt64BigInt(latestSeq, "latestSeq");
      let closed = false;
      const timers: { poll?: NodeJS.Timeout | undefined; life?: NodeJS.Timeout | undefined } = {};

      const shutdownStream = async (): Promise<void> => {
        if (closed) {
          return;
        }
        closed = true;
        activeSseShutdowns.delete(shutdownStream);
        if (timers.poll !== undefined) {
          clearInterval(timers.poll);
        }
        if (timers.life !== undefined) {
          clearTimeout(timers.life);
        }
        await ctx.pgAdapter
          .withTransaction(ctx.pgAdapter.configuredRole, (tx) => closeWatchLease(tx, leaseId))
          .catch(() => undefined);
        if (!reply.raw.destroyed) {
          reply.raw.end();
        }
      };

      activeSseShutdowns.add(shutdownStream);
      request.raw.on("close", () => {
        void shutdownStream();
      });
      reply.raw.on("close", () => {
        void shutdownStream();
      });

      timers.life = setTimeout(() => {
        void shutdownStream();
      }, ctx.sseMaxLifetimeMs);
      timers.life.unref?.();

      const intervalMs = Math.max(250, Math.min(ctx.sseHeartbeatMs, 10_000));
      timers.poll = setInterval(() => {
        if (closed) {
          return;
        }
        void ctx.pgAdapter
          .withTransaction(ctx.pgAdapter.configuredRole, async (tx) => {
            await renewWatchLease(tx, {
              leaseId,
              controlEpoch: inst.controlEpoch,
              authCutoffAt
            });
            const newRows =
              params.resourceKind === "event"
                ? await tx.query<Record<string, unknown>>(
                    `SELECT event_sequence AS seq, event_kind, event_schema_version, recorded_at, safe_facts
                       FROM rq.event_history
                      WHERE tenant_id = $1::uuid AND project_id = $2::uuid AND event_id = $3::uuid
                        AND event_sequence > $4::bigint
                      ORDER BY event_sequence ASC
                      LIMIT 10`,
                    [params.tenantId, params.projectId, params.resourceId, lastSentSeq.toString(10)]
                  )
                : await tx.query<Record<string, unknown>>(
                    `SELECT history_sequence AS seq, event_kind, 1 AS event_schema_version, recorded_at, safe_facts
                       FROM rq.delivery_history
                      WHERE tenant_id = $1::uuid AND project_id = $2::uuid AND delivery_id = $3::uuid
                        AND history_sequence > $4::bigint
                      ORDER BY history_sequence ASC
                      LIMIT 10`,
                    [params.tenantId, params.projectId, params.resourceId, lastSentSeq.toString(10)]
                  );
            return newRows.rows;
          })
          .then((newRows) => {
            if (closed) {
              return;
            }
            for (const h of newRows) {
              const seqVal = parseInt64BigInt(h["seq"], "seq");
              if (seqVal > lastSentSeq) {
                lastSentSeq = seqVal;
              }
              reply.raw.write(
                buildBoundedSseEventFrame({
                  id: String(h["seq"]),
                  resourceKind: params.resourceKind,
                  resourceId: safeResourceId,
                  eventId: snapshotData.eventId,
                  sequence: parseNonNegativeInt64String(String(h["seq"]), "event_sequence"),
                  eventType: String(h["event_kind"]),
                  eventSchemaVersion: Number(h["event_schema_version"] ?? 1),
                  recordedAt: formatPgTimestamp(h["recorded_at"]),
                  safeDetails: (h["safe_facts"] ?? {}) as Record<string, unknown>
                })
              );
            }
            if (newRows.length === 0) {
              reply.raw.write(formatSseHeartbeatFrame(`lease:${leaseId}`));
            }
          })
          .catch(() => {
            void shutdownStream();
          });
      }, intervalMs);
      timers.poll.unref?.();
    } finally {
      if (actor.kind === "human") {
        actor.session.destroySecrets();
      }
    }
  };

  app.get<{ Params: { tenant_id: string; project_id: string; event_id: string } }>(
    "/api/v1/tenants/:tenant_id/projects/:project_id/events/:event_id/watch",
    async (request, reply) => {
      const tenantId = parseTenantId(request.params.tenant_id, "tenant_id");
      const projectId = parseProjectId(request.params.project_id, "project_id");
      const eventId = parseEventId(request.params.event_id, "event_id");
      await handleSseWatch(request, reply, {
        tenantId,
        projectId,
        resourceKind: "event",
        resourceId: eventId
      });
    }
  );

  app.get<{ Params: { tenant_id: string; project_id: string; delivery_id: string } }>(
    "/api/v1/tenants/:tenant_id/projects/:project_id/deliveries/:delivery_id/watch",
    async (request, reply) => {
      const tenantId = parseTenantId(request.params.tenant_id, "tenant_id");
      const projectId = parseProjectId(request.params.project_id, "project_id");
      const deliveryId = parseDeliveryId(request.params.delivery_id, "delivery_id");
      await handleSseWatch(request, reply, {
        tenantId,
        projectId,
        resourceKind: "delivery",
        resourceId: deliveryId
      });
    }
  );

  app.get<{ Querystring: Record<string, unknown> }>("/api/v1/watch", async (request, reply) => {
    const q = request.query;
    const tenantId = parseTenantId(q["tenant_id"], "query.tenant_id");
    const projectId = parseProjectId(q["project_id"], "query.project_id");
    const kind = asText(q["resource_kind"]);
    if (kind !== "event" && kind !== "delivery") {
      throw new ValidationDomainError({
        code: "INVALID_VALUE",
        message: 'query.resource_kind must be "event" or "delivery"'
      });
    }
    const resourceId = parseCanonicalUuid(q["resource_id"], "query.resource_id");
    await handleSseWatch(request, reply, {
      tenantId,
      projectId,
      resourceKind: kind,
      resourceId
    });
  });
}
