import { hashCanonicalJson, parsePositiveInt64String } from "@relayquill/contracts";
import {
  ConflictDomainError,
  type DataGrantAction,
  type DataGrantProjection,
  NotFoundDomainError,
  type RetentionHoldTargetKind,
  type Sha256Hex,
  ValidationDomainError,
  type CanonicalUuid,
  formatUtcTimestamp,
  isProjectRole,
  parseCanonicalUuid,
  parseCommandReceiptId,
  parsePrincipalId,
  parseProducerNamespace,
  parseProjectId,
  parseTenantId
} from "@relayquill/domain";
import { type FastifyInstance } from "fastify";
import {
  type ApiContext,
  authenticateHumanMutation,
  authenticateHumanRead,
  authorizeAction,
  checkCommandReceiptIdempotency,
  consumeStepUpProofFromBody,
  deterministicUuid,
  extractStepUpHeader,
  formatPgTimestamp,
  insertCommandReceiptAndAudit,
  parseCursorQueryParams,
  readInstallationSnapshot,
  stripUndefinedJson
} from "../context.js";
import { sendSuccessEnvelope } from "../http/errors.js";
import { asOptionalText, asText, readByteaBuffer } from "../repos/sql-helpers.js";

function toHex(val: unknown): Sha256Hex {
  return readByteaBuffer(val, "sha256").toString("hex") as Sha256Hex;
}

function parseUuidOrThrow(raw: unknown, fieldPath: string): CanonicalUuid {
  if (typeof raw !== "string") {
    throw new ValidationDomainError({
      code: "INVALID_UUID",
      message: `Expected UUID at ${fieldPath}`,
      fieldErrors: [{ path: fieldPath, code: "INVALID_UUID" }]
    });
  }
  return parseCanonicalUuid(raw.trim(), fieldPath);
}

function parseNonEmptyString(raw: unknown, fieldPath: string, maxBytes: number): string {
  if (typeof raw !== "string" || raw.trim().length === 0) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `${fieldPath} must be a non-empty string`,
      fieldErrors: [{ path: fieldPath, code: "INVALID_VALUE" }]
    });
  }
  const trimmed = raw.trim();
  if (Buffer.byteLength(trimmed, "utf8") > maxBytes) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `${fieldPath} exceeds maximum ${maxBytes} UTF-8 bytes`,
      fieldErrors: [{ path: fieldPath, code: "INVALID_VALUE" }]
    });
  }
  return trimmed;
}

function parsePositiveNumber(raw: unknown, fieldPath: string): number {
  const num =
    typeof raw === "string" && raw.trim().length > 0 ? Number(raw.trim()) : Number(raw);
  if (!Number.isFinite(num) || num <= 0) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `${fieldPath} must be a positive number`,
      fieldErrors: [{ path: fieldPath, code: "INVALID_VALUE" }]
    });
  }
  return num;
}

function buildStepUpFallbackSha(
  body: Record<string, unknown>,
  excludedKeys: readonly string[] = ["operation_proof_id", "step_up_proof_id"]
): Sha256Hex {
  const clean: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(body)) {
    if (!excludedKeys.includes(k) && v !== undefined) {
      clean[k] = v;
    }
  }
  return hashCanonicalJson(stripUndefinedJson(clean)).sha256;
}

function parseDataGrantActionStrict(raw: unknown): DataGrantAction {
  if (
    raw === "events.content.read" ||
    raw === "deliveries.request.read" ||
    raw === "receiver_receipts.read"
  ) {
    return raw;
  }
  throw new ValidationDomainError({
    code: "INVALID_VALUE",
    message: "action must be events.content.read, deliveries.request.read, or receiver_receipts.read",
    fieldErrors: [{ path: "action", code: "INVALID_VALUE" }]
  });
}

function parseDataGrantProjectionStrict(raw: unknown): DataGrantProjection {
  if (raw === "own_namespace" || raw === "approved_project") {
    return raw;
  }
  throw new ValidationDomainError({
    code: "INVALID_VALUE",
    message: "projection must be own_namespace or approved_project",
    fieldErrors: [{ path: "projection", code: "INVALID_VALUE" }]
  });
}

function parseRetentionHoldTargetKindStrict(raw: unknown): RetentionHoldTargetKind {
  if (
    raw === "event" ||
    raw === "delivery_family" ||
    raw === "endpoint_version" ||
    raw === "signing_metadata" ||
    raw === "project"
  ) {
    return raw;
  }
  throw new ValidationDomainError({
    code: "INVALID_VALUE",
    message: "Invalid retention hold target_kind",
    fieldErrors: [{ path: "target_kind", code: "INVALID_VALUE" }]
  });
}

const VALID_RATE_OPERATIONS = new Set([
  "event_admission",
  "send_start",
  "endpoint_verification",
  "replay_admission"
]);

export function registerProducerAndGovernanceRoutes(
  app: FastifyInstance,
  ctx: ApiContext
): void {
  const base = "/api/v1/tenants/:tenant_id/projects/:project_id";

  // ---------------------------------------------------------------------------
  // Producers, Scopes & Credentials (rq_p1 custody intents only; zero secrets)
  // ---------------------------------------------------------------------------
  app.get<{ Params: { tenant_id: string; project_id: string } }>(
    `${base}/producers`,
    async (request, reply) => {
      const tenantId = parseTenantId(request.params.tenant_id, "tenant_id");
      const projectId = parseProjectId(request.params.project_id, "project_id");
      const { limit } = parseCursorQueryParams((request.query as Record<string, unknown>) ?? {});
      const inst = await ctx.pgAdapter.withTransaction(
        ctx.pgAdapter.configuredRole,
        (tx) => readInstallationSnapshot(ctx, tx),
        { readOnly: true }
      );
      const { auth } = await authenticateHumanRead(ctx, request, inst);
      try {
        await authorizeAction(ctx, auth, "producers.read_safe", {
          installation: inst,
          tenantId,
          projectId
        });

        const resData = await ctx.pgAdapter.withTransaction(
          ctx.pgAdapter.configuredRole,
          async (tx) => {
            const prodRes = await tx.query<Record<string, unknown>>(
              `SELECT id, name, business_namespace, state, current_scope_version, authority_epoch, version
               FROM rq.producers
               WHERE tenant_id = $1::uuid AND project_id = $2::uuid
               ORDER BY created_at DESC, id ASC
               LIMIT $3::integer`,
              [tenantId, projectId, limit + 1]
            );
            const rows = prodRes.rows.slice(0, limit);
            const prodIds = rows.map((r) => asText(r["id"]));

            const scopesByProd = new Map<string, Array<Record<string, unknown>>>();
            const credsByProd = new Map<string, Array<Record<string, unknown>>>();
            const intentsByProd = new Map<string, Array<Record<string, unknown>>>();

            if (prodIds.length > 0) {
              const scopesRes = await tx.query<Record<string, unknown>>(
                `SELECT producer_id, scope_version, scope_definition, scope_sha256, state
                 FROM rq.producer_scope_versions
                 WHERE tenant_id = $1::uuid AND project_id = $2::uuid
                   AND producer_id = ANY($3::uuid[])
                 ORDER BY scope_version DESC`,
                [tenantId, projectId, prodIds]
              );
              for (const sr of scopesRes.rows) {
                const pid = asText(sr["producer_id"]);
                const sver = asText(sr["scope_version"]);
                const def = (sr["scope_definition"] as Record<string, unknown> | null) ?? {};
                const allowedActions = Array.isArray(def["allowed_actions"])
                  ? def["allowed_actions"]
                  : ["events.admit"];
                const allowedTypes = Array.isArray(def["allowed_event_types"])
                  ? def["allowed_event_types"]
                  : [];
                const list = scopesByProd.get(pid) ?? [];
                list.push({
                  scope_id: deterministicUuid("producer_scope_version", pid, sver),
                  scope_version: sver,
                  state: asText(sr["state"]),
                  scope_sha256: toHex(sr["scope_sha256"]),
                  allowed_actions: allowedActions,
                  allowed_event_count: allowedTypes.length,
                  version: "1"
                });
                scopesByProd.set(pid, list);
              }

              const credsRes = await tx.query<Record<string, unknown>>(
                `SELECT id, producer_id, state, scope_version, created_at, expires_at, version
                 FROM rq.producer_credentials
                 WHERE tenant_id = $1::uuid AND project_id = $2::uuid
                   AND producer_id = ANY($3::uuid[])
                 ORDER BY created_at DESC`,
                [tenantId, projectId, prodIds]
              );
              for (const cr of credsRes.rows) {
                const pid = asText(cr["producer_id"]);
                const cid = asText(cr["id"]);
                const cstate = asText(cr["state"]);
                const list = credsByProd.get(pid) ?? [];
                list.push({
                  credential_id: cid,
                  selector_prefix: `rq_p1.${cid.slice(0, 8)}`,
                  state: cstate,
                  scope_version: asText(cr["scope_version"]),
                  created_at: formatPgTimestamp(cr["created_at"]),
                  expires_at: formatPgTimestamp(cr["expires_at"]),
                  overlap_ends_at:
                    cstate === "overlap" ? formatPgTimestamp(cr["expires_at"]) : null,
                  version: asText(cr["version"])
                });
                credsByProd.set(pid, list);
              }

              const intRes = await tx.query<Record<string, unknown>>(
                `SELECT id, producer_id, scope_version, scope_sha256, custody_destination_reference,
                        state, requested_expiry, expires_at, version
                 FROM rq.producer_credential_intents
                 WHERE tenant_id = $1::uuid AND project_id = $2::uuid
                   AND producer_id = ANY($3::uuid[])
                 ORDER BY created_at DESC`,
                [tenantId, projectId, prodIds]
              );
              for (const ir of intRes.rows) {
                const pid = asText(ir["producer_id"]);
                const list = intentsByProd.get(pid) ?? [];
                list.push({
                  intent_id: asText(ir["id"]),
                  scope_version: asText(ir["scope_version"]),
                  scope_sha256: toHex(ir["scope_sha256"]),
                  custody_destination_id: asText(ir["custody_destination_reference"]),
                  state: asText(ir["state"]),
                  requested_expires_at: formatPgTimestamp(ir["requested_expiry"]),
                  expires_at: formatPgTimestamp(ir["expires_at"]),
                  version: asText(ir["version"])
                });
                intentsByProd.set(pid, list);
              }
            }

            return {
              hasMore: prodRes.rows.length > limit,
              items: rows.map((r) => {
                const id = asText(r["id"]);
                return {
                  producer_id: id,
                  name: asText(r["name"]),
                  business_namespace: asText(r["business_namespace"]),
                  state: asText(r["state"]),
                  current_scope_version: asOptionalText(r["current_scope_version"]),
                  authority_epoch: asText(r["authority_epoch"], "1"),
                  version: asText(r["version"]),
                  scopes: scopesByProd.get(id) ?? [],
                  credentials: credsByProd.get(id) ?? [],
                  credential_intents: intentsByProd.get(id) ?? []
                };
              })
            };
          },
          { readOnly: true }
        );

        return sendSuccessEnvelope(
          reply,
          200,
          { items: resData.items, page: { next_cursor: null, limit, has_more: resData.hasMore } },
          { requestId: request.id }
        );
      } finally {
        auth.destroySecrets();
      }
    }
  );

  app.post<{ Params: { tenant_id: string; project_id: string } }>(
    `${base}/producers`,
    async (request, reply) => {
      const tenantId = parseTenantId(request.params.tenant_id, "tenant_id");
      const projectId = parseProjectId(request.params.project_id, "project_id");
      const inst = await ctx.pgAdapter.withTransaction(
        ctx.pgAdapter.configuredRole,
        (tx) => readInstallationSnapshot(ctx, tx),
        { readOnly: true }
      );
      const { auth, headerMap, idempotencyKey, body } = await authenticateHumanMutation(
        ctx,
        request,
        inst
      );
      try {
        const rawProof = body["operation_proof_id"] ?? extractStepUpHeader(headerMap);
        const hasProof = typeof rawProof === "string" && rawProof.trim().length > 0;
        await authorizeAction(ctx, auth, "producers.create", {
          installation: inst,
          tenantId,
          projectId,
          stepUpProofId: hasProof ? rawProof : undefined
        });

        const name = parseNonEmptyString(body["name"], "name", 128);
        const namespace = parseProducerNamespace(body["business_namespace"], "business_namespace");
        if (namespace.startsWith("human.")) {
          throw new ValidationDomainError({
            code: "INVALID_VALUE",
            message: "Machine producer business_namespace cannot begin with 'human.'",
            fieldErrors: [{ path: "business_namespace", code: "INVALID_VALUE" }]
          });
        }
        const now = formatUtcTimestamp(ctx.clock.nowInstant());
        const receiptId = parseCommandReceiptId(ctx.ids.nextUuid(), "receipt_id");
        const shapeSha = buildStepUpFallbackSha(body);

        const out = await ctx.pgAdapter.withTransaction(ctx.pgAdapter.configuredRole, async (tx) => {
          const existing = await checkCommandReceiptIdempotency(tx, {
            scopeKind: "project",
            tenantId,
            projectId,
            actorPrincipalId: auth.principal.principalId,
            commandFamily: "producers.create",
            idempotencyKey,
            submittedShapeSha256: shapeSha
          });
          if (existing !== null) {
            return { existing: true, producerId: existing.resource_id, receipt: existing };
          }

          const dup = await tx.query(
            `SELECT id FROM rq.producers WHERE project_id = $1::uuid AND business_namespace = $2::text`,
            [projectId, namespace]
          );
          if (dup.rows.length > 0) {
            throw new ConflictDomainError({
              code: "STATE_TRANSITION_NOT_ALLOWED",
              message: `Producer with namespace "${namespace}" already exists in project`
            });
          }

          if (hasProof) {
            await consumeStepUpProofFromBody({
              ctx,
              auth,
              installation: inst,
              body,
              headerMap,
              action: "producers.create",
              scopeKind: "project",
              tenantId,
              projectId,
              targetResourceId: projectId,
              targetVersion: 1n,
              receiptId,
              expectedCommandSha256: shapeSha
            });
          }

          const producerId = parseCanonicalUuid(ctx.ids.nextUuid(), "producer_id");
          const principalId = parsePrincipalId(ctx.ids.nextUuid(), "principal_id");
          await tx.query(`INSERT INTO rq.principals (id, kind) VALUES ($1::uuid, 'producer')`, [
            principalId
          ]);
          await tx.query(
            `INSERT INTO rq.producers (
               id, tenant_id, project_id, principal_id, principal_kind, channel_kind,
               name, business_namespace, state, authority_epoch, version
             ) VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid, 'producer', 'machine_producer', $5::text, $6::text, 'active', 1, 1)`,
            [producerId, tenantId, projectId, principalId, name, namespace]
          );

          const receipt = await insertCommandReceiptAndAudit(tx, {
            receiptId,
            scopeKind: "project",
            tenantId,
            projectId,
            actorPrincipalId: auth.principal.principalId,
            commandFamily: "producers.create",
            idempotencyKey,
            submittedShapeSha256: shapeSha,
            resourceKind: "producer",
            resourceId: producerId,
            acceptedVersion: 1n,
            safeFacts: { name, business_namespace: namespace },
            now
          });
          return { existing: false, producerId, receipt };
        });

        return sendSuccessEnvelope(
          reply,
          out.existing ? 200 : 201,
          {
            receipt: out.receipt,
            producer_id: out.producerId,
            name,
            business_namespace: namespace,
            state: "active",
            current_scope_version: null,
            authority_epoch: "1",
            version: "1",
            scopes: [],
            credentials: [],
            credential_intents: []
          },
          { requestId: request.id, observedAt: now }
        );
      } finally {
        auth.destroySecrets();
      }
    }
  );

  app.post<{ Params: { tenant_id: string; project_id: string; producer_id: string } }>(
    `${base}/producers/:producer_id/scope-versions`,
    async (request, reply) => {
      const tenantId = parseTenantId(request.params.tenant_id, "tenant_id");
      const projectId = parseProjectId(request.params.project_id, "project_id");
      const producerId = parseUuidOrThrow(request.params.producer_id, "producer_id");
      const inst = await ctx.pgAdapter.withTransaction(
        ctx.pgAdapter.configuredRole,
        (tx) => readInstallationSnapshot(ctx, tx),
        { readOnly: true }
      );
      const { auth, headerMap, idempotencyKey, body } = await authenticateHumanMutation(
        ctx,
        request,
        inst
      );
      try {
        const rawProof = body["operation_proof_id"] ?? extractStepUpHeader(headerMap);
        const hasProof = typeof rawProof === "string" && rawProof.trim().length > 0;
        await authorizeAction(ctx, auth, "producers.scope_versions.create", {
          installation: inst,
          tenantId,
          projectId,
          stepUpProofId: hasProof ? rawProof : undefined
        });

        const allowedActions = Array.isArray(body["allowed_actions"])
          ? body["allowed_actions"].filter((x): x is string => typeof x === "string")
          : ["events.admit"];
        const allowedEventTypes = Array.isArray(body["allowed_event_types"])
          ? body["allowed_event_types"].filter((x): x is string => typeof x === "string")
          : [];
        const scopeDef = {
          allowed_actions: allowedActions,
          allowed_event_types: allowedEventTypes
        };
        const scopeSha256 = hashCanonicalJson(stripUndefinedJson(scopeDef)).sha256;
        const now = formatUtcTimestamp(ctx.clock.nowInstant());
        const receiptId = parseCommandReceiptId(ctx.ids.nextUuid(), "receipt_id");
        const shapeSha = buildStepUpFallbackSha(body);

        const out = await ctx.pgAdapter.withTransaction(ctx.pgAdapter.configuredRole, async (tx) => {
          const existing = await checkCommandReceiptIdempotency(tx, {
            scopeKind: "project",
            tenantId,
            projectId,
            actorPrincipalId: auth.principal.principalId,
            commandFamily: "producers.scope_versions.create",
            idempotencyKey,
            submittedShapeSha256: shapeSha
          });
          if (existing !== null) {
            return {
              existing: true,
              scopeId: existing.resource_id,
              scopeVersion: existing.accepted_version ?? "1",
              receipt: existing
            };
          }

          const pRes = await tx.query<Record<string, unknown>>(
            `SELECT id, version FROM rq.producers WHERE id = $1::uuid AND tenant_id = $2::uuid AND project_id = $3::uuid FOR UPDATE`,
            [producerId, tenantId, projectId]
          );
          if (pRes.rows.length === 0) {
            throw new NotFoundDomainError({
              code: "NOT_FOUND",
              message: `Producer "${producerId}" not found`
            });
          }

          if (hasProof) {
            await consumeStepUpProofFromBody({
              ctx,
              auth,
              installation: inst,
              body,
              headerMap,
              action: "producers.scope_versions.create",
              scopeKind: "project",
              tenantId,
              projectId,
              targetResourceId: producerId,
              targetVersion: BigInt(asText(pRes.rows[0]?.["version"], "1")),
              receiptId,
              expectedCommandSha256: shapeSha
            });
          }

          const nextVerRes = await tx.query<Record<string, unknown>>(
            `SELECT COALESCE(MAX(scope_version), 0) + 1 AS next_version
             FROM rq.producer_scope_versions WHERE producer_id = $1::uuid`,
            [producerId]
          );
          const scopeVersion = asText(nextVerRes.rows[0]?.["next_version"], "1");
          const scopeId = deterministicUuid("producer_scope_version", producerId, scopeVersion);

          await tx.query(
            `INSERT INTO rq.producer_scope_versions (
               producer_id, scope_version, tenant_id, project_id,
               scope_definition, scope_sha256, state, created_by
             ) VALUES ($1::uuid, $2::bigint, $3::uuid, $4::uuid, $5::jsonb, $6::bytea, 'draft', $7::uuid)`,
            [
              producerId,
              scopeVersion,
              tenantId,
              projectId,
              JSON.stringify(scopeDef),
              Buffer.from(scopeSha256, "hex"),
              auth.principal.principalId
            ]
          );

          const receipt = await insertCommandReceiptAndAudit(tx, {
            receiptId,
            scopeKind: "project",
            tenantId,
            projectId,
            actorPrincipalId: auth.principal.principalId,
            commandFamily: "producers.scope_versions.create",
            idempotencyKey,
            submittedShapeSha256: shapeSha,
            resourceKind: "producer_scope_version",
            resourceId: scopeId,
            acceptedVersion: BigInt(scopeVersion),
            safeFacts: { producer_id: producerId, scope_version: scopeVersion },
            now
          });
          return { existing: false, scopeId, scopeVersion, receipt };
        });

        return sendSuccessEnvelope(
          reply,
          out.existing ? 200 : 201,
          {
            receipt: out.receipt,
            scope_id: out.scopeId,
            scope_version: out.scopeVersion,
            state: "draft",
            scope_sha256: scopeSha256,
            allowed_actions: allowedActions,
            allowed_event_count: allowedEventTypes.length,
            version: "1"
          },
          { requestId: request.id, observedAt: now }
        );
      } finally {
        auth.destroySecrets();
      }
    }
  );

  app.post<{ Params: { tenant_id: string; project_id: string; scope_id: string } }>(
    `${base}/producer-scopes/:scope_id/activate`,
    async (request, reply) => {
      const tenantId = parseTenantId(request.params.tenant_id, "tenant_id");
      const projectId = parseProjectId(request.params.project_id, "project_id");
      const scopeId = parseUuidOrThrow(request.params.scope_id, "scope_id");
      const inst = await ctx.pgAdapter.withTransaction(
        ctx.pgAdapter.configuredRole,
        (tx) => readInstallationSnapshot(ctx, tx),
        { readOnly: true }
      );
      const { auth, headerMap, idempotencyKey, body } = await authenticateHumanMutation(
        ctx,
        request,
        inst
      );
      try {
        const rawProof = body["operation_proof_id"] ?? extractStepUpHeader(headerMap);
        const hasProof = typeof rawProof === "string" && rawProof.trim().length > 0;
        await authorizeAction(ctx, auth, "producers.scope_activate", {
          installation: inst,
          tenantId,
          projectId,
          stepUpProofId: hasProof ? rawProof : undefined
        });
        const now = formatUtcTimestamp(ctx.clock.nowInstant());
        const receiptId = parseCommandReceiptId(ctx.ids.nextUuid(), "receipt_id");
        const shapeSha = buildStepUpFallbackSha(body);

        const out = await ctx.pgAdapter.withTransaction(ctx.pgAdapter.configuredRole, async (tx) => {
          const existing = await checkCommandReceiptIdempotency(tx, {
            scopeKind: "project",
            tenantId,
            projectId,
            actorPrincipalId: auth.principal.principalId,
            commandFamily: "producers.scope_activate",
            idempotencyKey,
            submittedShapeSha256: shapeSha
          });
          if (existing !== null) {
            return { receipt: existing, scopeVersion: existing.accepted_version ?? "1" };
          }

          const scopesRes = await tx.query<Record<string, unknown>>(
            `SELECT producer_id, scope_version FROM rq.producer_scope_versions
             WHERE tenant_id = $1::uuid AND project_id = $2::uuid`,
            [tenantId, projectId]
          );
          const row = scopesRes.rows.find(
            (r) =>
              deterministicUuid(
                "producer_scope_version",
                asText(r["producer_id"]),
                asText(r["scope_version"])
              ) === scopeId
          );
          if (row === undefined) {
            throw new NotFoundDomainError({
              code: "NOT_FOUND",
              message: `Producer scope version "${scopeId}" not found`
            });
          }
          const producerId = asText(row["producer_id"]);
          const scopeVer = asText(row["scope_version"]);

          if (hasProof) {
            await consumeStepUpProofFromBody({
              ctx,
              auth,
              installation: inst,
              body,
              headerMap,
              action: "producers.scope_activate",
              scopeKind: "project",
              tenantId,
              projectId,
              targetResourceId: scopeId,
              targetVersion: BigInt(scopeVer),
              receiptId,
              expectedCommandSha256: shapeSha
            });
          }

          await tx.query(
            `UPDATE rq.producer_scope_versions
             SET state = CASE WHEN scope_version = $2::bigint THEN 'active' ELSE CASE WHEN state = 'active' THEN 'retired' ELSE state END END,
                 published_by = CASE WHEN scope_version = $2::bigint THEN $3::uuid ELSE published_by END,
                 activated_at = CASE WHEN scope_version = $2::bigint THEN COALESCE(activated_at, pg_catalog.clock_timestamp()) ELSE activated_at END
             WHERE producer_id = $1::uuid AND tenant_id = $4::uuid AND project_id = $5::uuid`,
            [producerId, scopeVer, auth.principal.principalId, tenantId, projectId]
          );
          await tx.query(
            `UPDATE rq.producers
             SET state = 'active', current_scope_version = $2::bigint, authority_epoch = authority_epoch + 1,
                 updated_at = pg_catalog.clock_timestamp(), version = version + 1
             WHERE id = $1::uuid AND tenant_id = $3::uuid AND project_id = $4::uuid`,
            [producerId, scopeVer, tenantId, projectId]
          );

          const receipt = await insertCommandReceiptAndAudit(tx, {
            receiptId,
            scopeKind: "project",
            tenantId,
            projectId,
            actorPrincipalId: auth.principal.principalId,
            commandFamily: "producers.scope_activate",
            idempotencyKey,
            submittedShapeSha256: shapeSha,
            resourceKind: "producer_scope_version",
            resourceId: scopeId,
            acceptedVersion: BigInt(scopeVer),
            safeFacts: { producer_id: producerId, scope_version: scopeVer },
            now
          });
          return { receipt, scopeVersion: scopeVer };
        });

        return sendSuccessEnvelope(
          reply,
          200,
          { receipt: out.receipt, scope_id: scopeId, scope_version: out.scopeVersion, state: "active" },
          { requestId: request.id, observedAt: now }
        );
      } finally {
        auth.destroySecrets();
      }
    }
  );

  for (const kind of ["credential-intents", "credential-rotations"] as const) {
    app.post<{ Params: { tenant_id: string; project_id: string; producer_id: string } }>(
      `${base}/producers/:producer_id/${kind}`,
      async (request, reply) => {
        const tenantId = parseTenantId(request.params.tenant_id, "tenant_id");
        const projectId = parseProjectId(request.params.project_id, "project_id");
        const producerId = parseUuidOrThrow(request.params.producer_id, "producer_id");
        const inst = await ctx.pgAdapter.withTransaction(
          ctx.pgAdapter.configuredRole,
          (tx) => readInstallationSnapshot(ctx, tx),
          { readOnly: true }
        );
        const { auth, headerMap, idempotencyKey, body } = await authenticateHumanMutation(
          ctx,
          request,
          inst
        );
        const govAction =
          kind === "credential-rotations"
            ? "producers.credential_rotate"
            : "producers.credential_issue";
        try {
          const rawProof = body["operation_proof_id"] ?? extractStepUpHeader(headerMap);
          await authorizeAction(ctx, auth, govAction, {
            installation: inst,
            tenantId,
            projectId,
            stepUpProofId: typeof rawProof === "string" ? rawProof : undefined
          });

          const custodyRef = parseNonEmptyString(
            body["custody_destination_id"] ?? body["custody_destination_reference"],
            "custody_destination_id",
            256
          );
          const requestedExpiresAtRaw = parseNonEmptyString(
            body["requested_expires_at"] ??
              new Date(Date.now() + 7 * 86_400_000).toISOString(),
            "requested_expires_at",
            64
          );
          const parsedExpiry = new Date(requestedExpiresAtRaw);
          if (Number.isNaN(parsedExpiry.getTime()) || parsedExpiry.getTime() <= Date.now()) {
            throw new ValidationDomainError({
              code: "INVALID_TIMESTAMP",
              message: "requested_expires_at must be a future UTC timestamp",
              fieldErrors: [{ path: "requested_expires_at", code: "INVALID_TIMESTAMP" }]
            });
          }

          const now = formatUtcTimestamp(ctx.clock.nowInstant());
          const receiptId = parseCommandReceiptId(ctx.ids.nextUuid(), "receipt_id");
          const shapeSha = buildStepUpFallbackSha(body);

          const out = await ctx.pgAdapter.withTransaction(
            ctx.pgAdapter.configuredRole,
            async (tx) => {
              const existing = await checkCommandReceiptIdempotency(tx, {
                scopeKind: "project",
                tenantId,
                projectId,
                actorPrincipalId: auth.principal.principalId,
                commandFamily: govAction,
                idempotencyKey,
                submittedShapeSha256: shapeSha
              });
              if (existing !== null) {
                return {
                  existing: true,
                  dto: { intent_id: existing.resource_id, custody_destination_id: custodyRef },
                  receipt: existing
                };
              }

              const prodRes = await tx.query<Record<string, unknown>>(
                `SELECT id, current_scope_version, version
                 FROM rq.producers
                 WHERE id = $1::uuid AND tenant_id = $2::uuid AND project_id = $3::uuid
                   AND channel_kind = 'machine_producer'
                 FOR UPDATE`,
                [producerId, tenantId, projectId]
              );
              if (prodRes.rows.length === 0) {
                throw new NotFoundDomainError({
                  code: "NOT_FOUND",
                  message: `Machine producer "${producerId}" not found`
                });
              }
              const prodVer = BigInt(asText(prodRes.rows[0]?.["version"], "1"));
              const scopeVersion =
                body["scope_version"] !== undefined && body["scope_version"] !== ""
                  ? parsePositiveInt64String(asText(body["scope_version"]), "scope_version")
                  : asOptionalText(prodRes.rows[0]?.["current_scope_version"]) ?? "1";

              const scopeRes = await tx.query<Record<string, unknown>>(
                `SELECT scope_sha256
                 FROM rq.producer_scope_versions
                 WHERE producer_id = $1::uuid AND scope_version = $2::bigint
                   AND tenant_id = $3::uuid AND project_id = $4::uuid`,
                [producerId, scopeVersion, tenantId, projectId]
              );
              if (scopeRes.rows.length === 0) {
                throw new ConflictDomainError({
                  code: "STATE_TRANSITION_NOT_ALLOWED",
                  message: `Producer scope version ${scopeVersion} must exist before issuing credential intent`
                });
              }
              const scopeShaBuf = readByteaBuffer(scopeRes.rows[0]?.["scope_sha256"], "scope_sha256");

              await consumeStepUpProofFromBody({
                ctx,
                auth,
                installation: inst,
                body,
                headerMap,
                action: govAction,
                scopeKind: "project",
                tenantId,
                projectId,
                targetResourceId: producerId,
                targetVersion: prodVer,
                receiptId,
                expectedCommandSha256: shapeSha
              });

              const intentId = parseCanonicalUuid(ctx.ids.nextUuid(), "intent_id");
              const intentExpiryIso = new Date(
                Math.min(parsedExpiry.getTime(), Date.now() + 30 * 86_400_000)
              ).toISOString();

              const insRes = await tx.query<Record<string, unknown>>(
                `INSERT INTO rq.producer_credential_intents (
                   id, producer_id, tenant_id, project_id, channel_kind, control_epoch,
                   scope_version, scope_sha256, requested_expiry, custody_destination_reference,
                   state, issuer_principal_id, expires_at, version
                 ) VALUES (
                   $1::uuid, $2::uuid, $3::uuid, $4::uuid, 'machine_producer', $5::uuid,
                   $6::bigint, $7::bytea, $8::timestamptz, $9::text,
                   'requested', $10::uuid, $11::timestamptz, 1
                 )
                 RETURNING requested_expiry, expires_at`,
                [
                  intentId,
                  producerId,
                  tenantId,
                  projectId,
                  inst.controlEpoch,
                  scopeVersion,
                  scopeShaBuf,
                  parsedExpiry.toISOString(),
                  custodyRef,
                  auth.principal.principalId,
                  intentExpiryIso
                ]
              );

              const receipt = await insertCommandReceiptAndAudit(tx, {
                receiptId,
                scopeKind: "project",
                tenantId,
                projectId,
                actorPrincipalId: auth.principal.principalId,
                commandFamily: govAction,
                idempotencyKey,
                submittedShapeSha256: shapeSha,
                resourceKind: "producer_credential_intent",
                resourceId: intentId,
                acceptedVersion: 1n,
                safeFacts: { producer_id: producerId, custody_destination_id: custodyRef },
                now
              });

              return {
                existing: false,
                receipt,
                dto: {
                  intent_id: intentId,
                  scope_version: scopeVersion,
                  scope_sha256: scopeShaBuf.toString("hex"),
                  custody_destination_id: custodyRef,
                  state: "requested",
                  requested_expires_at: formatPgTimestamp(
                    insRes.rows[0]?.["requested_expiry"] ?? parsedExpiry
                  ),
                  expires_at: formatPgTimestamp(insRes.rows[0]?.["expires_at"] ?? intentExpiryIso),
                  version: "1"
                }
              };
            }
          );

          return sendSuccessEnvelope(
            reply,
            out.existing ? 200 : 201,
            { receipt: out.receipt, ...out.dto },
            { requestId: request.id, observedAt: now }
          );
        } finally {
          auth.destroySecrets();
        }
      }
    );
  }

  app.post<{ Params: { tenant_id: string; project_id: string; credential_id: string } }>(
    `${base}/producer-credentials/:credential_id/revoke`,
    async (request, reply) => {
      const tenantId = parseTenantId(request.params.tenant_id, "tenant_id");
      const projectId = parseProjectId(request.params.project_id, "project_id");
      const credentialId = parseUuidOrThrow(request.params.credential_id, "credential_id");
      const inst = await ctx.pgAdapter.withTransaction(
        ctx.pgAdapter.configuredRole,
        (tx) => readInstallationSnapshot(ctx, tx),
        { readOnly: true }
      );
      const { auth, headerMap, idempotencyKey, body } = await authenticateHumanMutation(
        ctx,
        request,
        inst
      );
      try {
        const rawProof = body["operation_proof_id"] ?? extractStepUpHeader(headerMap);
        await authorizeAction(ctx, auth, "producers.credential_revoke", {
          installation: inst,
          tenantId,
          projectId,
          stepUpProofId: typeof rawProof === "string" ? rawProof : undefined
        });
        const now = formatUtcTimestamp(ctx.clock.nowInstant());
        const receiptId = parseCommandReceiptId(ctx.ids.nextUuid(), "receipt_id");
        const shapeSha = buildStepUpFallbackSha(body);

        const out = await ctx.pgAdapter.withTransaction(ctx.pgAdapter.configuredRole, async (tx) => {
          const existing = await checkCommandReceiptIdempotency(tx, {
            scopeKind: "project",
            tenantId,
            projectId,
            actorPrincipalId: auth.principal.principalId,
            commandFamily: "producers.credential_revoke",
            idempotencyKey,
            submittedShapeSha256: shapeSha
          });
          if (existing !== null) {
            return { receipt: existing, version: existing.accepted_version ?? "1" };
          }

          const credRes = await tx.query<Record<string, unknown>>(
            `SELECT id, version FROM rq.producer_credentials
             WHERE id = $1::uuid AND tenant_id = $2::uuid AND project_id = $3::uuid FOR UPDATE`,
            [credentialId, tenantId, projectId]
          );
          if (credRes.rows.length === 0) {
            throw new NotFoundDomainError({
              code: "NOT_FOUND",
              message: `Producer credential "${credentialId}" not found`
            });
          }
          const curVer = BigInt(asText(credRes.rows[0]?.["version"], "1"));

          await consumeStepUpProofFromBody({
            ctx,
            auth,
            installation: inst,
            body,
            headerMap,
            action: "producers.credential_revoke",
            scopeKind: "project",
            tenantId,
            projectId,
            targetResourceId: credentialId,
            targetVersion: curVer,
            receiptId,
            expectedCommandSha256: shapeSha
          });

          await tx.query(
            `UPDATE rq.producer_credentials
             SET state = 'revoked', revoked_at = COALESCE(revoked_at, pg_catalog.clock_timestamp()), version = version + 1
             WHERE id = $1::uuid AND tenant_id = $2::uuid AND project_id = $3::uuid`,
            [credentialId, tenantId, projectId]
          );

          const receipt = await insertCommandReceiptAndAudit(tx, {
            receiptId,
            scopeKind: "project",
            tenantId,
            projectId,
            actorPrincipalId: auth.principal.principalId,
            commandFamily: "producers.credential_revoke",
            idempotencyKey,
            submittedShapeSha256: shapeSha,
            resourceKind: "producer_credential",
            resourceId: credentialId,
            acceptedVersion: curVer + 1n,
            priorVersion: curVer,
            safeFacts: { state: "revoked" },
            now
          });
          return { receipt, version: (curVer + 1n).toString(10) };
        });

        return sendSuccessEnvelope(
          reply,
          200,
          { receipt: out.receipt, credential_id: credentialId, state: "revoked", version: out.version },
          { requestId: request.id, observedAt: now }
        );
      } finally {
        auth.destroySecrets();
      }
    }
  );

  for (const actionName of ["suspend", "retire"] as const) {
    app.post<{ Params: { tenant_id: string; project_id: string; producer_id: string } }>(
      `${base}/producers/:producer_id/${actionName}`,
      async (request, reply) => {
        const tenantId = parseTenantId(request.params.tenant_id, "tenant_id");
        const projectId = parseProjectId(request.params.project_id, "project_id");
        const producerId = parseUuidOrThrow(request.params.producer_id, "producer_id");
        const inst = await ctx.pgAdapter.withTransaction(
          ctx.pgAdapter.configuredRole,
          (tx) => readInstallationSnapshot(ctx, tx),
          { readOnly: true }
        );
        const { auth, headerMap, idempotencyKey, body } = await authenticateHumanMutation(
          ctx,
          request,
          inst
        );
        const govAction = actionName === "suspend" ? "producers.suspend" : "producers.retire";
        try {
          const rawProof = body["operation_proof_id"] ?? extractStepUpHeader(headerMap);
          await authorizeAction(ctx, auth, govAction, {
            installation: inst,
            tenantId,
            projectId,
            stepUpProofId: typeof rawProof === "string" ? rawProof : undefined
          });
          const now = formatUtcTimestamp(ctx.clock.nowInstant());
          const receiptId = parseCommandReceiptId(ctx.ids.nextUuid(), "receipt_id");
          const shapeSha = buildStepUpFallbackSha(body);
          const nextState = actionName === "suspend" ? "suspended" : "retired";

          const out = await ctx.pgAdapter.withTransaction(
            ctx.pgAdapter.configuredRole,
            async (tx) => {
              const existing = await checkCommandReceiptIdempotency(tx, {
                scopeKind: "project",
                tenantId,
                projectId,
                actorPrincipalId: auth.principal.principalId,
                commandFamily: govAction,
                idempotencyKey,
                submittedShapeSha256: shapeSha
              });
              if (existing !== null) {
                return { receipt: existing, version: existing.accepted_version ?? "1" };
              }

              const pRes = await tx.query<Record<string, unknown>>(
                `SELECT id, version FROM rq.producers
                 WHERE id = $1::uuid AND tenant_id = $2::uuid AND project_id = $3::uuid FOR UPDATE`,
                [producerId, tenantId, projectId]
              );
              if (pRes.rows.length === 0) {
                throw new NotFoundDomainError({
                  code: "NOT_FOUND",
                  message: `Producer "${producerId}" not found`
                });
              }
              const curVer = BigInt(asText(pRes.rows[0]?.["version"], "1"));

              await consumeStepUpProofFromBody({
                ctx,
                auth,
                installation: inst,
                body,
                headerMap,
                action: govAction,
                scopeKind: "project",
                tenantId,
                projectId,
                targetResourceId: producerId,
                targetVersion: curVer,
                receiptId,
                expectedCommandSha256: shapeSha
              });

              await tx.query(
                `UPDATE rq.producers
                 SET state = $2::text, authority_epoch = authority_epoch + 1,
                     updated_at = pg_catalog.clock_timestamp(), version = version + 1
                 WHERE id = $1::uuid AND tenant_id = $3::uuid AND project_id = $4::uuid`,
                [producerId, nextState, tenantId, projectId]
              );
              if (actionName === "retire") {
                await tx.query(
                  `UPDATE rq.producer_credentials
                   SET state = 'revoked', revoked_at = COALESCE(revoked_at, pg_catalog.clock_timestamp()), version = version + 1
                   WHERE producer_id = $1::uuid AND state IN ('pending_activation', 'active', 'overlap')`,
                  [producerId]
                );
              }

              const receipt = await insertCommandReceiptAndAudit(tx, {
                receiptId,
                scopeKind: "project",
                tenantId,
                projectId,
                actorPrincipalId: auth.principal.principalId,
                commandFamily: govAction,
                idempotencyKey,
                submittedShapeSha256: shapeSha,
                resourceKind: "producer",
                resourceId: producerId,
                acceptedVersion: curVer + 1n,
                priorVersion: curVer,
                safeFacts: { state: nextState },
                now
              });
              return { receipt, version: (curVer + 1n).toString(10) };
            }
          );

          return sendSuccessEnvelope(
            reply,
            200,
            { receipt: out.receipt, producer_id: producerId, state: nextState, version: out.version },
            { requestId: request.id, observedAt: now }
          );
        } finally {
          auth.destroySecrets();
        }
      }
    );
  }

  // ---------------------------------------------------------------------------
  // Capacity & Rate Policy Changes
  // ---------------------------------------------------------------------------
  app.get<{ Params: { tenant_id: string; project_id: string } }>(
    `${base}/capacity`,
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
        await authorizeAction(ctx, auth, "deliveries.read_safe", {
          installation: inst,
          tenantId,
          projectId
        });

        const dto = await ctx.pgAdapter.withTransaction(
          ctx.pgAdapter.configuredRole,
          async (tx) => {
            const capRes = await tx.query<Record<string, unknown>>(
              `SELECT pc.active_attempt_slots, pc.max_active_attempt_slots, pc.updated_at,
                      COALESCE(pdm.dispatch_domain_id, '00000000-0000-4000-8000-000000000001'::uuid) AS dispatch_domain_id,
                      COALESCE(pdm.project_weight, 100) AS project_weight,
                      COALESCE(ds.policy_epoch, 1) AS policy_epoch
               FROM rq.project_capacity pc
               LEFT JOIN rq.project_dispatch_memberships pdm ON pdm.project_id = pc.project_id
               LEFT JOIN rq.dispatch_state ds ON ds.id = true
               WHERE pc.project_id = $1::uuid AND pc.tenant_id = $2::uuid`,
              [projectId, tenantId]
            );
            const capRow = capRes.rows[0];
            const bucketRes = await tx.query<Record<string, unknown>>(
              `SELECT capacity_micro, refill_micro_per_second, reserved_micro
               FROM rq.project_rate_buckets
               WHERE project_id = $1::uuid AND tenant_id = $2::uuid
               LIMIT 1`,
              [projectId, tenantId]
            );
            const bucketRow = bucketRes.rows[0];
            const rpsMicro = bucketRow
              ? Number(bucketRow["refill_micro_per_second"] ?? 100_000_000)
              : 100_000_000;
            const burstMicro = bucketRow
              ? Number(bucketRow["capacity_micro"] ?? 200_000_000)
              : 200_000_000;
            const heldMicro = bucketRow ? Number(bucketRow["reserved_micro"] ?? 0) : 0;

            return {
              dispatch_domain_id: asText(
                capRow?.["dispatch_domain_id"],
                "00000000-0000-4000-8000-000000000001"
              ),
              policy_epoch: asText(capRow?.["policy_epoch"], "1"),
              eligible_population_label: "active_project_deliveries",
              project_weight: Number(capRow?.["project_weight"] ?? 100),
              active_send_slots: Number(capRow?.["active_attempt_slots"] ?? 0),
              approved_send_slots: Number(capRow?.["max_active_attempt_slots"] ?? 16),
              held_rate_reservations: Math.floor(heldMicro / 1_000_000),
              rate_requests_per_second: Math.max(1, Math.floor(rpsMicro / 1_000_000)),
              rate_burst: Math.max(1, Math.floor(burstMicro / 1_000_000)),
              microtokens_per_request: "1000000",
              observed_at: capRow?.["updated_at"]
                ? formatPgTimestamp(capRow["updated_at"])
                : formatUtcTimestamp(ctx.clock.nowInstant())
            };
          },
          { readOnly: true }
        );

        return sendSuccessEnvelope(reply, 200, dto, { requestId: request.id });
      } finally {
        auth.destroySecrets();
      }
    }
  );

  app.get<{ Params: { tenant_id: string; project_id: string } }>(
    `${base}/rate-policy-changes`,
    async (request, reply) => {
      const tenantId = parseTenantId(request.params.tenant_id, "tenant_id");
      const projectId = parseProjectId(request.params.project_id, "project_id");
      const { limit } = parseCursorQueryParams((request.query as Record<string, unknown>) ?? {});
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

        const resData = await ctx.pgAdapter.withTransaction(
          ctx.pgAdapter.configuredRole,
          async (tx) => {
            const res = await tx.query<Record<string, unknown>>(
              `SELECT id, tenant_id, project_id, endpoint_id, producer_id, scope_kind,
                      operation, candidate_sha256, candidate_definition, state, version
               FROM rq.rate_policy_changes
               WHERE tenant_id = $1::uuid AND (project_id = $2::uuid OR project_id IS NULL)
               ORDER BY created_at DESC, id ASC
               LIMIT $3::integer`,
              [tenantId, projectId, limit + 1]
            );
            return {
              hasMore: res.rows.length > limit,
              items: res.rows.slice(0, limit).map((r) => {
                const scopeKind = asText(r["scope_kind"]);
                const ownerId =
                  scopeKind === "endpoint"
                    ? asText(r["endpoint_id"])
                    : scopeKind === "producer"
                      ? asText(r["producer_id"])
                      : scopeKind === "project"
                        ? asText(r["project_id"])
                        : asText(r["tenant_id"]);
                const def = (r["candidate_definition"] as Record<string, unknown> | null) ?? {};
                return {
                  change_id: asText(r["id"]),
                  scope_kind: scopeKind,
                  owner_id: ownerId,
                  operation: asText(r["operation"]),
                  state: asText(r["state"]),
                  requests_per_second: Number(def["requests_per_second"] ?? 100),
                  burst: Number(def["burst"] ?? 200),
                  microtokens_per_request: asText(def["microtokens_per_request"], "1000000"),
                  held_reservation_count: 0,
                  candidate_sha256: toHex(r["candidate_sha256"]),
                  version: asText(r["version"])
                };
              })
            };
          },
          { readOnly: true }
        );

        return sendSuccessEnvelope(
          reply,
          200,
          { items: resData.items, page: { next_cursor: null, limit, has_more: resData.hasMore } },
          { requestId: request.id }
        );
      } finally {
        auth.destroySecrets();
      }
    }
  );

  app.post<{ Params: { tenant_id: string; project_id: string } }>(
    `${base}/rate-policy-changes`,
    async (request, reply) => {
      const tenantId = parseTenantId(request.params.tenant_id, "tenant_id");
      const projectId = parseProjectId(request.params.project_id, "project_id");
      const inst = await ctx.pgAdapter.withTransaction(
        ctx.pgAdapter.configuredRole,
        (tx) => readInstallationSnapshot(ctx, tx),
        { readOnly: true }
      );
      const { auth, headerMap, idempotencyKey, body } = await authenticateHumanMutation(
        ctx,
        request,
        inst
      );
      try {
        const rawProof = body["operation_proof_id"] ?? extractStepUpHeader(headerMap);
        const hasProof = typeof rawProof === "string" && rawProof.trim().length > 0;
        await authorizeAction(ctx, auth, "rate_policy_changes.propose", {
          installation: inst,
          tenantId,
          projectId,
          stepUpProofId: hasProof ? rawProof : undefined
        });

        const scopeKind =
          body["scope_kind"] === "tenant" ||
          body["scope_kind"] === "project" ||
          body["scope_kind"] === "endpoint" ||
          body["scope_kind"] === "producer"
            ? body["scope_kind"]
            : "project";
        const ownerId =
          typeof body["owner_id"] === "string" && body["owner_id"].trim().length > 0
            ? parseUuidOrThrow(body["owner_id"], "owner_id")
            : scopeKind === "tenant"
              ? tenantId
              : projectId;
        const operation =
          typeof body["operation"] === "string" && VALID_RATE_OPERATIONS.has(body["operation"])
            ? body["operation"]
            : "event_admission";
        const rps = parsePositiveNumber(body["requests_per_second"], "requests_per_second");
        const burst = parsePositiveNumber(body["burst"], "burst");
        const microtokensPerReq = parsePositiveInt64String(
          asText(body["microtokens_per_request"], "1000000"),
          "microtokens_per_request"
        );
        const now = formatUtcTimestamp(ctx.clock.nowInstant());
        const receiptId = parseCommandReceiptId(ctx.ids.nextUuid(), "receipt_id");
        const shapeSha = buildStepUpFallbackSha(body);
        const candidateDef = {
          requests_per_second: rps,
          burst,
          microtokens_per_request: microtokensPerReq
        };
        const candidateSha256 = hashCanonicalJson({
          scope_kind: scopeKind,
          owner_id: ownerId,
          operation,
          ...candidateDef
        }).sha256;

        const out = await ctx.pgAdapter.withTransaction(ctx.pgAdapter.configuredRole, async (tx) => {
          const existing = await checkCommandReceiptIdempotency(tx, {
            scopeKind: "project",
            tenantId,
            projectId,
            actorPrincipalId: auth.principal.principalId,
            commandFamily: "rate_policy_changes.propose",
            idempotencyKey,
            submittedShapeSha256: shapeSha
          });
          if (existing !== null) {
            return { existing: true, changeId: existing.resource_id, receipt: existing };
          }

          if (hasProof) {
            await consumeStepUpProofFromBody({
              ctx,
              auth,
              installation: inst,
              body,
              headerMap,
              action: "rate_policy_changes.propose",
              scopeKind: "project",
              tenantId,
              projectId,
              targetResourceId: projectId,
              targetVersion: 1n,
              receiptId,
              expectedCommandSha256: shapeSha
            });
          }

          const changeId = parseCanonicalUuid(ctx.ids.nextUuid(), "change_id");
          await tx.query(
            `INSERT INTO rq.rate_policy_changes (
               id, tenant_id, project_id, endpoint_id, producer_id, scope_kind, operation,
               candidate_sha256, candidate_definition, state, expected_policy_version,
               created_by, expires_at, version
             ) VALUES (
               $1::uuid, $2::uuid, $3::uuid, $4::uuid, $5::uuid, $6::text, $7::text,
               $8::bytea, $9::jsonb, 'proposed', 1,
               $10::uuid, pg_catalog.clock_timestamp() + interval '1 day', 1
             )`,
            [
              changeId,
              tenantId,
              scopeKind === "tenant" ? null : projectId,
              scopeKind === "endpoint" ? ownerId : null,
              scopeKind === "producer" ? ownerId : null,
              scopeKind,
              operation,
              Buffer.from(candidateSha256, "hex"),
              JSON.stringify(candidateDef),
              auth.principal.principalId
            ]
          );

          const receipt = await insertCommandReceiptAndAudit(tx, {
            receiptId,
            scopeKind: "project",
            tenantId,
            projectId,
            actorPrincipalId: auth.principal.principalId,
            commandFamily: "rate_policy_changes.propose",
            idempotencyKey,
            submittedShapeSha256: shapeSha,
            resourceKind: "rate_policy_change",
            resourceId: changeId,
            acceptedVersion: 1n,
            safeFacts: { scope_kind: scopeKind, operation, rps },
            now
          });
          return { existing: false, changeId, receipt };
        });

        return sendSuccessEnvelope(
          reply,
          out.existing ? 200 : 201,
          {
            receipt: out.receipt,
            change_id: out.changeId,
            scope_kind: scopeKind,
            owner_id: ownerId,
            operation,
            state: "proposed",
            requests_per_second: rps,
            burst,
            microtokens_per_request: microtokensPerReq,
            held_reservation_count: 0,
            candidate_sha256: candidateSha256,
            version: "1"
          },
          { requestId: request.id, observedAt: now }
        );
      } finally {
        auth.destroySecrets();
      }
    }
  );

  app.post<{ Params: { tenant_id: string; project_id: string; change_id: string } }>(
    `${base}/rate-policy-changes/:change_id/activate`,
    async (request, reply) => {
      const tenantId = parseTenantId(request.params.tenant_id, "tenant_id");
      const projectId = parseProjectId(request.params.project_id, "project_id");
      const changeId = parseUuidOrThrow(request.params.change_id, "change_id");
      const inst = await ctx.pgAdapter.withTransaction(
        ctx.pgAdapter.configuredRole,
        (tx) => readInstallationSnapshot(ctx, tx),
        { readOnly: true }
      );
      const { auth, headerMap, idempotencyKey, body } = await authenticateHumanMutation(
        ctx,
        request,
        inst
      );
      try {
        const rawProof = body["operation_proof_id"] ?? extractStepUpHeader(headerMap);
        await authorizeAction(ctx, auth, "rate_policy_changes.activate", {
          installation: inst,
          tenantId,
          projectId,
          stepUpProofId: typeof rawProof === "string" ? rawProof : undefined
        });
        const now = formatUtcTimestamp(ctx.clock.nowInstant());
        const receiptId = parseCommandReceiptId(ctx.ids.nextUuid(), "receipt_id");
        const shapeSha = buildStepUpFallbackSha(body);

        const out = await ctx.pgAdapter.withTransaction(ctx.pgAdapter.configuredRole, async (tx) => {
          const existing = await checkCommandReceiptIdempotency(tx, {
            scopeKind: "project",
            tenantId,
            projectId,
            actorPrincipalId: auth.principal.principalId,
            commandFamily: "rate_policy_changes.activate",
            idempotencyKey,
            submittedShapeSha256: shapeSha
          });
          if (existing !== null) {
            return { receipt: existing, version: existing.accepted_version ?? "2" };
          }

          const chRes = await tx.query<Record<string, unknown>>(
            `SELECT id, scope_kind, operation, candidate_definition, state, version
             FROM rq.rate_policy_changes
             WHERE id = $1::uuid AND tenant_id = $2::uuid FOR UPDATE`,
            [changeId, tenantId]
          );
          const row = chRes.rows[0];
          if (row === undefined) {
            throw new NotFoundDomainError({
              code: "NOT_FOUND",
              message: `Rate policy change "${changeId}" not found`
            });
          }
          const curState = asText(row["state"]);
          const curVer = BigInt(asText(row["version"], "1"));
          if (curState !== "proposed" && curState !== "draining") {
            throw new ConflictDomainError({
              code: "STATE_TRANSITION_NOT_ALLOWED",
              message: `Cannot activate rate policy change in state "${curState}"`
            });
          }

          await consumeStepUpProofFromBody({
            ctx,
            auth,
            installation: inst,
            body,
            headerMap,
            action: "rate_policy_changes.activate",
            scopeKind: "project",
            tenantId,
            projectId,
            targetResourceId: changeId,
            targetVersion: curVer,
            receiptId,
            expectedCommandSha256: shapeSha
          });

          await tx.query(`UPDATE rq.rate_policy_changes SET state = 'activated', version = version + 1 WHERE id = $1::uuid`, [
            changeId
          ]);

          const def = (row["candidate_definition"] as Record<string, unknown> | null) ?? {};
          const rps = Math.max(1, Math.trunc(Number(def["requests_per_second"] ?? 100)));
          const burst = Math.max(1, Math.trunc(Number(def["burst"] ?? 200)));
          if (asText(row["scope_kind"]) === "project") {
            await tx.query(
              `UPDATE rq.project_rate_buckets
               SET capacity_micro = $3::bigint * 1000000,
                   refill_micro_per_second = $4::bigint * 1000000,
                   updated_at = pg_catalog.clock_timestamp(),
                   version = version + 1
               WHERE project_id = $1::uuid AND operation = $2::text`,
              [projectId, asText(row["operation"]), String(burst), String(rps)]
            );
          }

          const receipt = await insertCommandReceiptAndAudit(tx, {
            receiptId,
            scopeKind: "project",
            tenantId,
            projectId,
            actorPrincipalId: auth.principal.principalId,
            commandFamily: "rate_policy_changes.activate",
            idempotencyKey,
            submittedShapeSha256: shapeSha,
            resourceKind: "rate_policy_change",
            resourceId: changeId,
            acceptedVersion: curVer + 1n,
            priorVersion: curVer,
            safeFacts: { state: "activated" },
            now
          });
          return { receipt, version: (curVer + 1n).toString(10) };
        });

        return sendSuccessEnvelope(
          reply,
          200,
          { receipt: out.receipt, change_id: changeId, state: "activated", version: out.version },
          { requestId: request.id, observedAt: now }
        );
      } finally {
        auth.destroySecrets();
      }
    }
  );

  // ---------------------------------------------------------------------------
  // Project Memberships (Preserving Last Active Project Admin)
  // ---------------------------------------------------------------------------
  app.get<{ Params: { tenant_id: string; project_id: string } }>(
    `${base}/memberships`,
    async (request, reply) => {
      const tenantId = parseTenantId(request.params.tenant_id, "tenant_id");
      const projectId = parseProjectId(request.params.project_id, "project_id");
      const { limit } = parseCursorQueryParams((request.query as Record<string, unknown>) ?? {});
      const inst = await ctx.pgAdapter.withTransaction(
        ctx.pgAdapter.configuredRole,
        (tx) => readInstallationSnapshot(ctx, tx),
        { readOnly: true }
      );
      const { auth } = await authenticateHumanRead(ctx, request, inst);
      try {
        await authorizeAction(ctx, auth, "audit.read_safe", {
          installation: inst,
          tenantId,
          projectId
        });

        const resData = await ctx.pgAdapter.withTransaction(
          ctx.pgAdapter.configuredRole,
          async (tx) => {
            const res = await tx.query<Record<string, unknown>>(
              `SELECT pm.id, pm.principal_id, h.display_name, pm.role, pm.state,
                      pm.authority_version, p.governance_version, pm.version
               FROM rq.project_memberships pm
               JOIN rq.humans h ON h.principal_id = pm.principal_id
               JOIN rq.projects p ON p.id = pm.project_id
               WHERE pm.tenant_id = $1::uuid AND pm.project_id = $2::uuid
               ORDER BY pm.created_at ASC, pm.id ASC
               LIMIT $3::integer`,
              [tenantId, projectId, limit + 1]
            );
            return {
              hasMore: res.rows.length > limit,
              items: res.rows.slice(0, limit).map((r) => ({
                membership_id: asText(r["id"]),
                principal_id: asText(r["principal_id"]),
                display_name: asText(r["display_name"]),
                role: asText(r["role"]),
                state: asText(r["state"]),
                authority_version: asText(r["authority_version"], "1"),
                governance_version: asText(r["governance_version"], "1"),
                version: asText(r["version"], "1")
              }))
            };
          },
          { readOnly: true }
        );

        return sendSuccessEnvelope(
          reply,
          200,
          { items: resData.items, page: { next_cursor: null, limit, has_more: resData.hasMore } },
          { requestId: request.id }
        );
      } finally {
        auth.destroySecrets();
      }
    }
  );

  app.post<{ Params: { tenant_id: string; project_id: string } }>(
    `${base}/memberships`,
    async (request, reply) => {
      const tenantId = parseTenantId(request.params.tenant_id, "tenant_id");
      const projectId = parseProjectId(request.params.project_id, "project_id");
      const inst = await ctx.pgAdapter.withTransaction(
        ctx.pgAdapter.configuredRole,
        (tx) => readInstallationSnapshot(ctx, tx),
        { readOnly: true }
      );
      const { auth, headerMap, idempotencyKey, body } = await authenticateHumanMutation(
        ctx,
        request,
        inst
      );
      try {
        const rawProof = body["operation_proof_id"] ?? extractStepUpHeader(headerMap);
        await authorizeAction(ctx, auth, "memberships.change_role", {
          installation: inst,
          tenantId,
          projectId,
          stepUpProofId: typeof rawProof === "string" ? rawProof : undefined
        });

        const targetPrincipalId = parsePrincipalId(body["principal_id"], "principal_id");
        if (!isProjectRole(body["role"])) {
          throw new ValidationDomainError({
            code: "INVALID_VALUE",
            message: "role must be a valid project role",
            fieldErrors: [{ path: "role", code: "INVALID_VALUE" }]
          });
        }
        const role = body["role"];
        const now = formatUtcTimestamp(ctx.clock.nowInstant());
        const receiptId = parseCommandReceiptId(ctx.ids.nextUuid(), "receipt_id");
        const shapeSha = buildStepUpFallbackSha(body);

        const out = await ctx.pgAdapter.withTransaction(ctx.pgAdapter.configuredRole, async (tx) => {
          const existing = await checkCommandReceiptIdempotency(tx, {
            scopeKind: "project",
            tenantId,
            projectId,
            actorPrincipalId: auth.principal.principalId,
            commandFamily: "memberships.change_role",
            idempotencyKey,
            submittedShapeSha256: shapeSha
          });
          if (existing !== null) {
            return {
              existing: true,
              membershipId: existing.resource_id,
              displayName: "",
              govVer: "1",
              receipt: existing
            };
          }

          const humanRes = await tx.query<Record<string, unknown>>(
            `SELECT principal_id, display_name FROM rq.humans WHERE principal_id = $1::uuid`,
            [targetPrincipalId]
          );
          if (humanRes.rows.length === 0) {
            throw new NotFoundDomainError({
              code: "NOT_FOUND",
              message: `Human principal "${targetPrincipalId}" not found`
            });
          }
          const displayName = asText(humanRes.rows[0]?.["display_name"]);

          const dupRes = await tx.query(
            `SELECT id FROM rq.project_memberships
             WHERE project_id = $1::uuid AND principal_id = $2::uuid AND role = $3::text AND state = 'active'`,
            [projectId, targetPrincipalId, role]
          );
          if (dupRes.rows.length > 0) {
            throw new ConflictDomainError({
              code: "STATE_TRANSITION_NOT_ALLOWED",
              message: `Principal already holds active role "${role}" on project`
            });
          }

          await consumeStepUpProofFromBody({
            ctx,
            auth,
            installation: inst,
            body,
            headerMap,
            action: "memberships.change_role",
            scopeKind: "project",
            tenantId,
            projectId,
            targetResourceId: targetPrincipalId,
            targetVersion: 1n,
            receiptId,
            expectedCommandSha256: shapeSha
          });

          const membershipId = parseCanonicalUuid(ctx.ids.nextUuid(), "membership_id");
          await tx.query(
            `INSERT INTO rq.project_memberships (
               id, tenant_id, project_id, principal_id, role, state, authority_version, version
             ) VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid, $5::text, 'active', 1, 1)`,
            [membershipId, tenantId, projectId, targetPrincipalId, role]
          );
          const govRes = await tx.query<Record<string, unknown>>(
            `UPDATE rq.projects
             SET governance_version = governance_version + 1, updated_at = pg_catalog.clock_timestamp()
             WHERE id = $1::uuid AND tenant_id = $2::uuid
             RETURNING governance_version`,
            [projectId, tenantId]
          );
          const govVer = asText(govRes.rows[0]?.["governance_version"], "1");

          const receipt = await insertCommandReceiptAndAudit(tx, {
            receiptId,
            scopeKind: "project",
            tenantId,
            projectId,
            actorPrincipalId: auth.principal.principalId,
            commandFamily: "memberships.change_role",
            idempotencyKey,
            submittedShapeSha256: shapeSha,
            resourceKind: "project_membership",
            resourceId: membershipId,
            acceptedVersion: 1n,
            safeFacts: { target_principal_id: targetPrincipalId, role },
            now
          });
          return { existing: false, membershipId, displayName, govVer, receipt };
        });

        return sendSuccessEnvelope(
          reply,
          out.existing ? 200 : 201,
          {
            receipt: out.receipt,
            membership_id: out.membershipId,
            principal_id: targetPrincipalId,
            display_name: out.displayName,
            role,
            state: "active",
            authority_version: "1",
            governance_version: out.govVer,
            version: "1"
          },
          { requestId: request.id, observedAt: now }
        );
      } finally {
        auth.destroySecrets();
      }
    }
  );

  for (const actionSlug of ["change-role", "suspend", "revoke"] as const) {
    app.post<{ Params: { tenant_id: string; project_id: string; membership_id: string } }>(
      `${base}/memberships/:membership_id/${actionSlug}`,
      async (request, reply) => {
        const tenantId = parseTenantId(request.params.tenant_id, "tenant_id");
        const projectId = parseProjectId(request.params.project_id, "project_id");
        const membershipId = parseUuidOrThrow(request.params.membership_id, "membership_id");
        const inst = await ctx.pgAdapter.withTransaction(
          ctx.pgAdapter.configuredRole,
          (tx) => readInstallationSnapshot(ctx, tx),
          { readOnly: true }
        );
        const { auth, headerMap, idempotencyKey, body } = await authenticateHumanMutation(
          ctx,
          request,
          inst
        );
        const govAction =
          actionSlug === "change-role"
            ? "memberships.change_role"
            : actionSlug === "suspend"
              ? "memberships.suspend"
              : "memberships.revoke";
        try {
          const rawProof = body["operation_proof_id"] ?? extractStepUpHeader(headerMap);
          await authorizeAction(ctx, auth, govAction, {
            installation: inst,
            tenantId,
            projectId,
            stepUpProofId: typeof rawProof === "string" ? rawProof : undefined
          });
          if (actionSlug === "change-role" && !isProjectRole(body["role"])) {
            throw new ValidationDomainError({
              code: "INVALID_VALUE",
              message: "role must be a valid project role",
              fieldErrors: [{ path: "role", code: "INVALID_VALUE" }]
            });
          }
          const now = formatUtcTimestamp(ctx.clock.nowInstant());
          const receiptId = parseCommandReceiptId(ctx.ids.nextUuid(), "receipt_id");
          const shapeSha = buildStepUpFallbackSha(body);

          const out = await ctx.pgAdapter.withTransaction(
            ctx.pgAdapter.configuredRole,
            async (tx) => {
              const existing = await checkCommandReceiptIdempotency(tx, {
                scopeKind: "project",
                tenantId,
                projectId,
                actorPrincipalId: auth.principal.principalId,
                commandFamily: govAction,
                idempotencyKey,
                submittedShapeSha256: shapeSha
              });
              if (existing !== null) {
                return { receipt: existing, role: "project_admin", state: "active", version: "1" };
              }

              const mRes = await tx.query<Record<string, unknown>>(
                `SELECT id, role, state, version
                 FROM rq.project_memberships
                 WHERE id = $1::uuid AND tenant_id = $2::uuid AND project_id = $3::uuid FOR UPDATE`,
                [membershipId, tenantId, projectId]
              );
              const row = mRes.rows[0];
              if (row === undefined) {
                throw new NotFoundDomainError({
                  code: "NOT_FOUND",
                  message: `Project membership "${membershipId}" not found`
                });
              }
              const curRole = asText(row["role"]);
              const curState = asText(row["state"]);
              const curVer = BigInt(asText(row["version"], "1"));
              const nextRole =
                actionSlug === "change-role" && typeof body["role"] === "string"
                  ? body["role"]
                  : curRole;
              const nextState =
                actionSlug === "suspend"
                  ? "suspended"
                  : actionSlug === "revoke"
                    ? "revoked"
                    : curState;

              if (
                curRole === "project_admin" &&
                curState === "active" &&
                (nextRole !== "project_admin" || nextState !== "active")
              ) {
                const cntRes = await tx.query<Record<string, unknown>>(
                  `SELECT COUNT(*)::int AS cnt
                   FROM rq.project_memberships
                   WHERE project_id = $1::uuid AND role = 'project_admin' AND state = 'active' AND id <> $2::uuid`,
                  [projectId, membershipId]
                );
                if (Number(cntRes.rows[0]?.["cnt"] ?? 0) < 1) {
                  throw new ConflictDomainError({
                    code: "STATE_TRANSITION_NOT_ALLOWED",
                    message: "Cannot remove or demote the last active project_admin"
                  });
                }
              }

              await consumeStepUpProofFromBody({
                ctx,
                auth,
                installation: inst,
                body,
                headerMap,
                action: govAction,
                scopeKind: "project",
                tenantId,
                projectId,
                targetResourceId: membershipId,
                targetVersion: curVer,
                receiptId,
                expectedCommandSha256: shapeSha
              });

              await tx.query(
                `UPDATE rq.project_memberships
                 SET role = $2::text, state = $3::text, authority_version = authority_version + 1,
                     updated_at = pg_catalog.clock_timestamp(), version = version + 1
                 WHERE id = $1::uuid`,
                [membershipId, nextRole, nextState]
              );
              await tx.query(
                `UPDATE rq.projects SET governance_version = governance_version + 1, updated_at = pg_catalog.clock_timestamp()
                 WHERE id = $1::uuid`,
                [projectId]
              );

              const receipt = await insertCommandReceiptAndAudit(tx, {
                receiptId,
                scopeKind: "project",
                tenantId,
                projectId,
                actorPrincipalId: auth.principal.principalId,
                commandFamily: govAction,
                idempotencyKey,
                submittedShapeSha256: shapeSha,
                resourceKind: "project_membership",
                resourceId: membershipId,
                acceptedVersion: curVer + 1n,
                priorVersion: curVer,
                safeFacts: { role: nextRole, state: nextState },
                now
              });
              return {
                receipt,
                role: nextRole,
                state: nextState,
                version: (curVer + 1n).toString(10)
              };
            }
          );

          return sendSuccessEnvelope(
            reply,
            200,
            {
              receipt: out.receipt,
              membership_id: membershipId,
              role: out.role,
              state: out.state,
              version: out.version
            },
            { requestId: request.id, observedAt: now }
          );
        } finally {
          auth.destroySecrets();
        }
      }
    );
  }

  // ---------------------------------------------------------------------------
  // Human Data Grants (rq.human_data_grants)
  // ---------------------------------------------------------------------------
  app.get<{ Params: { tenant_id: string; project_id: string } }>(
    `${base}/data-grants`,
    async (request, reply) => {
      const tenantId = parseTenantId(request.params.tenant_id, "tenant_id");
      const projectId = parseProjectId(request.params.project_id, "project_id");
      const { limit } = parseCursorQueryParams((request.query as Record<string, unknown>) ?? {});
      const inst = await ctx.pgAdapter.withTransaction(
        ctx.pgAdapter.configuredRole,
        (tx) => readInstallationSnapshot(ctx, tx),
        { readOnly: true }
      );
      const { auth } = await authenticateHumanRead(ctx, request, inst);
      try {
        await authorizeAction(ctx, auth, "audit.read_safe", {
          installation: inst,
          tenantId,
          projectId
        });

        const resData = await ctx.pgAdapter.withTransaction(
          ctx.pgAdapter.configuredRole,
          async (tx) => {
            const res = await tx.query<Record<string, unknown>>(
              `SELECT g.id, g.membership_id, pm.principal_id, g.action, g.projection,
                      g.producer_namespace, g.state, g.expires_at, g.created_at, g.version
               FROM rq.human_data_grants g
               JOIN rq.project_memberships pm ON pm.id = g.membership_id
               WHERE g.tenant_id = $1::uuid AND g.project_id = $2::uuid
               ORDER BY g.created_at DESC, g.id ASC
               LIMIT $3::integer`,
              [tenantId, projectId, limit + 1]
            );
            return {
              hasMore: res.rows.length > limit,
              items: res.rows.slice(0, limit).map((r) => ({
                grant_id: asText(r["id"]),
                membership_id: asText(r["membership_id"]),
                principal_id: asText(r["principal_id"]),
                action: asText(r["action"]),
                projection: asText(r["projection"]),
                producer_namespace: asOptionalText(r["producer_namespace"]),
                state: asText(r["state"]),
                expires_at:
                  r["expires_at"] === null || r["expires_at"] === undefined
                    ? null
                    : formatPgTimestamp(r["expires_at"]),
                created_at: formatPgTimestamp(r["created_at"]),
                version: asText(r["version"], "1")
              }))
            };
          },
          { readOnly: true }
        );

        return sendSuccessEnvelope(
          reply,
          200,
          { items: resData.items, page: { next_cursor: null, limit, has_more: resData.hasMore } },
          { requestId: request.id }
        );
      } finally {
        auth.destroySecrets();
      }
    }
  );

  app.post<{ Params: { tenant_id: string; project_id: string } }>(
    `${base}/data-grants`,
    async (request, reply) => {
      const tenantId = parseTenantId(request.params.tenant_id, "tenant_id");
      const projectId = parseProjectId(request.params.project_id, "project_id");
      const inst = await ctx.pgAdapter.withTransaction(
        ctx.pgAdapter.configuredRole,
        (tx) => readInstallationSnapshot(ctx, tx),
        { readOnly: true }
      );
      const { auth, headerMap, idempotencyKey, body } = await authenticateHumanMutation(
        ctx,
        request,
        inst
      );
      try {
        const rawProof = body["operation_proof_id"] ?? extractStepUpHeader(headerMap);
        await authorizeAction(ctx, auth, "data_grants.create", {
          installation: inst,
          tenantId,
          projectId,
          stepUpProofId: typeof rawProof === "string" ? rawProof : undefined
        });

        const membershipId = parseUuidOrThrow(body["membership_id"], "membership_id");
        const action = parseDataGrantActionStrict(body["action"]);
        const projection = parseDataGrantProjectionStrict(body["projection"]);
        const producerNamespace =
          projection === "own_namespace"
            ? parseProducerNamespace(body["producer_namespace"], "producer_namespace")
            : null;
        if (
          projection === "approved_project" &&
          body["producer_namespace"] !== undefined &&
          body["producer_namespace"] !== null &&
          body["producer_namespace"] !== ""
        ) {
          throw new ValidationDomainError({
            code: "INVALID_VALUE",
            message: "approved_project grant must not specify producer_namespace",
            fieldErrors: [{ path: "producer_namespace", code: "INVALID_VALUE" }]
          });
        }
        const expiresAtRaw =
          typeof body["expires_at"] === "string" && body["expires_at"].trim().length > 0
            ? body["expires_at"].trim()
            : null;
        if (expiresAtRaw !== null && Number.isNaN(new Date(expiresAtRaw).getTime())) {
          throw new ValidationDomainError({
            code: "INVALID_TIMESTAMP",
            message: "Invalid expires_at timestamp",
            fieldErrors: [{ path: "expires_at", code: "INVALID_TIMESTAMP" }]
          });
        }

        const now = formatUtcTimestamp(ctx.clock.nowInstant());
        const receiptId = parseCommandReceiptId(ctx.ids.nextUuid(), "receipt_id");
        const shapeSha = buildStepUpFallbackSha(body);

        const out = await ctx.pgAdapter.withTransaction(ctx.pgAdapter.configuredRole, async (tx) => {
          const existing = await checkCommandReceiptIdempotency(tx, {
            scopeKind: "project",
            tenantId,
            projectId,
            actorPrincipalId: auth.principal.principalId,
            commandFamily: "data_grants.create",
            idempotencyKey,
            submittedShapeSha256: shapeSha
          });
          if (existing !== null) {
            return {
              existing: true,
              grantId: existing.resource_id,
              granteePrincipalId: auth.principal.principalId,
              createdAt: existing.accepted_at,
              receipt: existing
            };
          }

          const pmRes = await tx.query<Record<string, unknown>>(
            `SELECT id, principal_id, state
             FROM rq.project_memberships
             WHERE id = $1::uuid AND tenant_id = $2::uuid AND project_id = $3::uuid`,
            [membershipId, tenantId, projectId]
          );
          const pmRow = pmRes.rows[0];
          if (pmRow === undefined) {
            throw new NotFoundDomainError({
              code: "NOT_FOUND",
              message: `Project membership "${membershipId}" not found`
            });
          }
          if (asText(pmRow["state"]) !== "active") {
            throw new ConflictDomainError({
              code: "STATE_TRANSITION_NOT_ALLOWED",
              message: "Cannot issue data grant on inactive project membership"
            });
          }
          const granteePrincipalId = parsePrincipalId(pmRow["principal_id"], "principal_id");

          await consumeStepUpProofFromBody({
            ctx,
            auth,
            installation: inst,
            body,
            headerMap,
            action: "data_grants.create",
            scopeKind: "project",
            tenantId,
            projectId,
            targetResourceId: membershipId,
            targetVersion: 1n,
            receiptId,
            expectedCommandSha256: shapeSha
          });

          const grantId = parseCanonicalUuid(ctx.ids.nextUuid(), "grant_id");
          const insRes = await tx.query<Record<string, unknown>>(
            `INSERT INTO rq.human_data_grants (
               id, membership_id, tenant_id, project_id, action, projection,
               producer_namespace, state, expires_at, created_by, version
             ) VALUES (
               $1::uuid, $2::uuid, $3::uuid, $4::uuid, $5::text, $6::text,
               $7::text, 'active', $8::timestamptz, $9::uuid, 1
             )
             RETURNING created_at`,
            [
              grantId,
              membershipId,
              tenantId,
              projectId,
              action,
              projection,
              producerNamespace,
              expiresAtRaw,
              auth.principal.principalId
            ]
          );

          const receipt = await insertCommandReceiptAndAudit(tx, {
            receiptId,
            scopeKind: "project",
            tenantId,
            projectId,
            actorPrincipalId: auth.principal.principalId,
            commandFamily: "data_grants.create",
            idempotencyKey,
            submittedShapeSha256: shapeSha,
            resourceKind: "human_data_grant",
            resourceId: grantId,
            acceptedVersion: 1n,
            safeFacts: { action, projection, membership_id: membershipId },
            now
          });
          return {
            existing: false,
            grantId,
            granteePrincipalId,
            createdAt: formatPgTimestamp(insRes.rows[0]?.["created_at"] ?? now),
            receipt
          };
        });

        return sendSuccessEnvelope(
          reply,
          out.existing ? 200 : 201,
          {
            receipt: out.receipt,
            grant_id: out.grantId,
            membership_id: membershipId,
            principal_id: out.granteePrincipalId,
            action,
            projection,
            producer_namespace: producerNamespace,
            state: "active",
            expires_at: expiresAtRaw,
            created_at: out.createdAt,
            version: "1"
          },
          { requestId: request.id, observedAt: now }
        );
      } finally {
        auth.destroySecrets();
      }
    }
  );

  app.post<{ Params: { tenant_id: string; project_id: string; grant_id: string } }>(
    `${base}/data-grants/:grant_id/revoke`,
    async (request, reply) => {
      const tenantId = parseTenantId(request.params.tenant_id, "tenant_id");
      const projectId = parseProjectId(request.params.project_id, "project_id");
      const grantId = parseUuidOrThrow(request.params.grant_id, "grant_id");
      const inst = await ctx.pgAdapter.withTransaction(
        ctx.pgAdapter.configuredRole,
        (tx) => readInstallationSnapshot(ctx, tx),
        { readOnly: true }
      );
      const { auth, headerMap, idempotencyKey, body } = await authenticateHumanMutation(
        ctx,
        request,
        inst
      );
      try {
        const rawProof = body["operation_proof_id"] ?? extractStepUpHeader(headerMap);
        await authorizeAction(ctx, auth, "data_grants.revoke", {
          installation: inst,
          tenantId,
          projectId,
          stepUpProofId: typeof rawProof === "string" ? rawProof : undefined
        });
        const now = formatUtcTimestamp(ctx.clock.nowInstant());
        const receiptId = parseCommandReceiptId(ctx.ids.nextUuid(), "receipt_id");
        const shapeSha = buildStepUpFallbackSha(body);

        const out = await ctx.pgAdapter.withTransaction(ctx.pgAdapter.configuredRole, async (tx) => {
          const existing = await checkCommandReceiptIdempotency(tx, {
            scopeKind: "project",
            tenantId,
            projectId,
            actorPrincipalId: auth.principal.principalId,
            commandFamily: "data_grants.revoke",
            idempotencyKey,
            submittedShapeSha256: shapeSha
          });
          if (existing !== null) {
            return { receipt: existing, version: existing.accepted_version ?? "2" };
          }

          const gRes = await tx.query<Record<string, unknown>>(
            `SELECT id, version FROM rq.human_data_grants
             WHERE id = $1::uuid AND tenant_id = $2::uuid AND project_id = $3::uuid FOR UPDATE`,
            [grantId, tenantId, projectId]
          );
          if (gRes.rows.length === 0) {
            throw new NotFoundDomainError({
              code: "NOT_FOUND",
              message: `Human data grant "${grantId}" not found`
            });
          }
          const curVer = BigInt(asText(gRes.rows[0]?.["version"], "1"));

          await consumeStepUpProofFromBody({
            ctx,
            auth,
            installation: inst,
            body,
            headerMap,
            action: "data_grants.revoke",
            scopeKind: "project",
            tenantId,
            projectId,
            targetResourceId: grantId,
            targetVersion: curVer,
            receiptId,
            expectedCommandSha256: shapeSha
          });

          await tx.query(
            `UPDATE rq.human_data_grants SET state = 'revoked', version = version + 1 WHERE id = $1::uuid`,
            [grantId]
          );

          const receipt = await insertCommandReceiptAndAudit(tx, {
            receiptId,
            scopeKind: "project",
            tenantId,
            projectId,
            actorPrincipalId: auth.principal.principalId,
            commandFamily: "data_grants.revoke",
            idempotencyKey,
            submittedShapeSha256: shapeSha,
            resourceKind: "human_data_grant",
            resourceId: grantId,
            acceptedVersion: curVer + 1n,
            priorVersion: curVer,
            safeFacts: { state: "revoked" },
            now
          });
          return { receipt, version: (curVer + 1n).toString(10) };
        });

        return sendSuccessEnvelope(
          reply,
          200,
          { receipt: out.receipt, grant_id: grantId, state: "revoked", version: out.version },
          { requestId: request.id, observedAt: now }
        );
      } finally {
        auth.destroySecrets();
      }
    }
  );

  // ---------------------------------------------------------------------------
  // Retention Holds
  // ---------------------------------------------------------------------------
  app.get<{ Params: { tenant_id: string; project_id: string } }>(
    `${base}/retention-holds`,
    async (request, reply) => {
      const tenantId = parseTenantId(request.params.tenant_id, "tenant_id");
      const projectId = parseProjectId(request.params.project_id, "project_id");
      const { limit } = parseCursorQueryParams((request.query as Record<string, unknown>) ?? {});
      const inst = await ctx.pgAdapter.withTransaction(
        ctx.pgAdapter.configuredRole,
        (tx) => readInstallationSnapshot(ctx, tx),
        { readOnly: true }
      );
      const { auth } = await authenticateHumanRead(ctx, request, inst);
      try {
        await authorizeAction(ctx, auth, "audit.read_safe", {
          installation: inst,
          tenantId,
          projectId
        });

        const resData = await ctx.pgAdapter.withTransaction(
          ctx.pgAdapter.configuredRole,
          async (tx) => {
            const res = await tx.query<Record<string, unknown>>(
              `SELECT id, target_kind, target_id, reason_code, state, review_at, expires_at, version
               FROM rq.retention_holds
               WHERE tenant_id = $1::uuid AND project_id = $2::uuid
               ORDER BY created_at DESC, id ASC
               LIMIT $3::integer`,
              [tenantId, projectId, limit + 1]
            );
            return {
              hasMore: res.rows.length > limit,
              items: res.rows.slice(0, limit).map((r) => ({
                hold_id: asText(r["id"]),
                target_kind: asText(r["target_kind"]),
                target_id: asText(r["target_id"]),
                reason_code: asText(r["reason_code"]),
                state: asText(r["state"]),
                review_at: formatPgTimestamp(r["review_at"]),
                expires_at:
                  r["expires_at"] === null || r["expires_at"] === undefined
                    ? null
                    : formatPgTimestamp(r["expires_at"]),
                version: asText(r["version"], "1")
              }))
            };
          },
          { readOnly: true }
        );

        return sendSuccessEnvelope(
          reply,
          200,
          { items: resData.items, page: { next_cursor: null, limit, has_more: resData.hasMore } },
          { requestId: request.id }
        );
      } finally {
        auth.destroySecrets();
      }
    }
  );

  app.post<{ Params: { tenant_id: string; project_id: string } }>(
    `${base}/retention-holds`,
    async (request, reply) => {
      const tenantId = parseTenantId(request.params.tenant_id, "tenant_id");
      const projectId = parseProjectId(request.params.project_id, "project_id");
      const inst = await ctx.pgAdapter.withTransaction(
        ctx.pgAdapter.configuredRole,
        (tx) => readInstallationSnapshot(ctx, tx),
        { readOnly: true }
      );
      const { auth, headerMap, idempotencyKey, body } = await authenticateHumanMutation(
        ctx,
        request,
        inst
      );
      try {
        const rawProof = body["operation_proof_id"] ?? extractStepUpHeader(headerMap);
        const hasProof = typeof rawProof === "string" && rawProof.trim().length > 0;
        await authorizeAction(ctx, auth, "retention_holds.create", {
          installation: inst,
          tenantId,
          projectId,
          stepUpProofId: hasProof ? rawProof : undefined
        });

        const targetKind = parseRetentionHoldTargetKindStrict(body["target_kind"]);
        const targetId = parseUuidOrThrow(body["target_id"], "target_id");
        const reasonCode = parseNonEmptyString(body["reason_code"], "reason_code", 128);
        const reviewAtRaw = parseNonEmptyString(
          body["review_at"] ?? new Date(Date.now() + 7 * 86_400_000).toISOString(),
          "review_at",
          64
        );
        const expiresAtRaw =
          typeof body["expires_at"] === "string" && body["expires_at"].trim().length > 0
            ? body["expires_at"].trim()
            : null;
        const now = formatUtcTimestamp(ctx.clock.nowInstant());
        const receiptId = parseCommandReceiptId(ctx.ids.nextUuid(), "receipt_id");
        const shapeSha = buildStepUpFallbackSha(body);

        const out = await ctx.pgAdapter.withTransaction(ctx.pgAdapter.configuredRole, async (tx) => {
          const existing = await checkCommandReceiptIdempotency(tx, {
            scopeKind: "project",
            tenantId,
            projectId,
            actorPrincipalId: auth.principal.principalId,
            commandFamily: "retention_holds.create",
            idempotencyKey,
            submittedShapeSha256: shapeSha
          });
          if (existing !== null) {
            return {
              existing: true,
              holdId: existing.resource_id,
              reviewAt: reviewAtRaw,
              expiresAt: expiresAtRaw,
              receipt: existing
            };
          }

          if (hasProof) {
            await consumeStepUpProofFromBody({
              ctx,
              auth,
              installation: inst,
              body,
              headerMap,
              action: "retention_holds.create",
              scopeKind: "project",
              tenantId,
              projectId,
              targetResourceId: targetId,
              targetVersion: 1n,
              receiptId,
              expectedCommandSha256: shapeSha
            });
          }

          const holdId = parseCanonicalUuid(ctx.ids.nextUuid(), "hold_id");
          const insRes = await tx.query<Record<string, unknown>>(
            `INSERT INTO rq.retention_holds (
               id, tenant_id, project_id, target_kind, target_id, reason_code,
               state, created_by, review_at, expires_at, version
             ) VALUES (
               $1::uuid, $2::uuid, $3::uuid, $4::text, $5::uuid, $6::text,
               'active', $7::uuid, $8::timestamptz, $9::timestamptz, 1
             )
             RETURNING review_at, expires_at`,
            [
              holdId,
              tenantId,
              projectId,
              targetKind,
              targetId,
              reasonCode,
              auth.principal.principalId,
              reviewAtRaw,
              expiresAtRaw
            ]
          );

          const receipt = await insertCommandReceiptAndAudit(tx, {
            receiptId,
            scopeKind: "project",
            tenantId,
            projectId,
            actorPrincipalId: auth.principal.principalId,
            commandFamily: "retention_holds.create",
            idempotencyKey,
            submittedShapeSha256: shapeSha,
            resourceKind: "retention_hold",
            resourceId: holdId,
            acceptedVersion: 1n,
            safeFacts: { target_kind: targetKind, target_id: targetId, reason_code: reasonCode },
            now
          });
          return {
            existing: false,
            holdId,
            reviewAt: formatPgTimestamp(insRes.rows[0]?.["review_at"] ?? reviewAtRaw),
            expiresAt:
              insRes.rows[0]?.["expires_at"] !== null &&
              insRes.rows[0]?.["expires_at"] !== undefined
                ? formatPgTimestamp(insRes.rows[0]?.["expires_at"])
                : expiresAtRaw,
            receipt
          };
        });

        return sendSuccessEnvelope(
          reply,
          out.existing ? 200 : 201,
          {
            receipt: out.receipt,
            hold_id: out.holdId,
            target_kind: targetKind,
            target_id: targetId,
            reason_code: reasonCode,
            state: "active",
            review_at: out.reviewAt,
            expires_at: out.expiresAt,
            version: "1"
          },
          { requestId: request.id, observedAt: now }
        );
      } finally {
        auth.destroySecrets();
      }
    }
  );

  app.post<{ Params: { tenant_id: string; project_id: string; hold_id: string } }>(
    `${base}/retention-holds/:hold_id/release`,
    async (request, reply) => {
      const tenantId = parseTenantId(request.params.tenant_id, "tenant_id");
      const projectId = parseProjectId(request.params.project_id, "project_id");
      const holdId = parseUuidOrThrow(request.params.hold_id, "hold_id");
      const inst = await ctx.pgAdapter.withTransaction(
        ctx.pgAdapter.configuredRole,
        (tx) => readInstallationSnapshot(ctx, tx),
        { readOnly: true }
      );
      const { auth, headerMap, idempotencyKey, body } = await authenticateHumanMutation(
        ctx,
        request,
        inst
      );
      try {
        const rawProof = body["operation_proof_id"] ?? extractStepUpHeader(headerMap);
        await authorizeAction(ctx, auth, "retention_holds.release", {
          installation: inst,
          tenantId,
          projectId,
          stepUpProofId: typeof rawProof === "string" ? rawProof : undefined
        });
        const now = formatUtcTimestamp(ctx.clock.nowInstant());
        const receiptId = parseCommandReceiptId(ctx.ids.nextUuid(), "receipt_id");
        const shapeSha = buildStepUpFallbackSha(body);

        const out = await ctx.pgAdapter.withTransaction(ctx.pgAdapter.configuredRole, async (tx) => {
          const existing = await checkCommandReceiptIdempotency(tx, {
            scopeKind: "project",
            tenantId,
            projectId,
            actorPrincipalId: auth.principal.principalId,
            commandFamily: "retention_holds.release",
            idempotencyKey,
            submittedShapeSha256: shapeSha
          });
          if (existing !== null) {
            return { receipt: existing, version: existing.accepted_version ?? "2" };
          }

          const hRes = await tx.query<Record<string, unknown>>(
            `SELECT id, version FROM rq.retention_holds
             WHERE id = $1::uuid AND tenant_id = $2::uuid AND project_id = $3::uuid FOR UPDATE`,
            [holdId, tenantId, projectId]
          );
          if (hRes.rows.length === 0) {
            throw new NotFoundDomainError({
              code: "NOT_FOUND",
              message: `Retention hold "${holdId}" not found`
            });
          }
          const curVer = BigInt(asText(hRes.rows[0]?.["version"], "1"));

          await consumeStepUpProofFromBody({
            ctx,
            auth,
            installation: inst,
            body,
            headerMap,
            action: "retention_holds.release",
            scopeKind: "project",
            tenantId,
            projectId,
            targetResourceId: holdId,
            targetVersion: curVer,
            receiptId,
            expectedCommandSha256: shapeSha
          });

          await tx.query(
            `UPDATE rq.retention_holds SET state = 'released', version = version + 1 WHERE id = $1::uuid`,
            [holdId]
          );

          const receipt = await insertCommandReceiptAndAudit(tx, {
            receiptId,
            scopeKind: "project",
            tenantId,
            projectId,
            actorPrincipalId: auth.principal.principalId,
            commandFamily: "retention_holds.release",
            idempotencyKey,
            submittedShapeSha256: shapeSha,
            resourceKind: "retention_hold",
            resourceId: holdId,
            acceptedVersion: curVer + 1n,
            priorVersion: curVer,
            safeFacts: { state: "released" },
            now
          });
          return { receipt, version: (curVer + 1n).toString(10) };
        });

        return sendSuccessEnvelope(
          reply,
          200,
          { receipt: out.receipt, hold_id: holdId, state: "released", version: out.version },
          { requestId: request.id, observedAt: now }
        );
      } finally {
        auth.destroySecrets();
      }
    }
  );
}
