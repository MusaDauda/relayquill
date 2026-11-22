import {
  hashCanonicalJson,
  parsePositiveInt64String
} from "@relayquill/contracts";
import {
  ConflictDomainError,
  NotFoundDomainError,
  ValidationDomainError,
  type CanonicalUuid,
  type Sha256Hex,
  formatUtcTimestamp,
  parseCanonicalUuid,
  parseCommandReceiptId,
  parseProjectId,
  parseTenantId
} from "@relayquill/domain";
import {
  type CompiledEventSchema,
  EVENT_SCHEMA_DIALECT_2020_12,
  EVENT_SCHEMA_PROFILE_V1,
  compileEventSchemaFromBytes,
  compileFilterAst,
  compileOrderingExtractor,
  compileProjectionProfile
} from "@relayquill/event-schema";
import { type PgTransactionClient } from "@relayquill/postgres";
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
import { asOptionalText, asText, readByteaBuffer, toParamBuffer } from "../repos/sql-helpers.js";

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

function parsePositiveInteger(raw: unknown, fieldPath: string): number {
  const num =
    typeof raw === "string" && /^\d+$/.test(raw.trim()) ? Number(raw.trim()) : Number(raw);
  if (!Number.isInteger(num) || num < 1) {
    throw new ValidationDomainError({
      code: "INVALID_INT64",
      message: `${fieldPath} must be a positive integer`,
      fieldErrors: [{ path: fieldPath, code: "INVALID_INT64" }]
    });
  }
  return num;
}

function normalizeConsoleProjectionDefinition(
  rawDef: unknown,
  eventTypeId: string,
  sourceVersion: number,
  targetVersion: number
): Record<string, unknown> {
  if (rawDef === null || typeof rawDef !== "object" || Array.isArray(rawDef)) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: "Projection definition must be an object",
      fieldErrors: [{ path: "definition", code: "INVALID_VALUE" }]
    });
  }
  const rec = rawDef as Record<string, unknown>;
  const rawMappings: readonly unknown[] = Array.isArray(rec["mappings"])
    ? (rec["mappings"] as readonly unknown[])
    : [];
  const normalizedMappings = rawMappings.map((item): unknown => {
    if (item === null || typeof item !== "object" || Array.isArray(item)) {
      return item;
    }
    const r = item as Record<string, unknown>;
    const op = r["operation"] ?? r["op"];
    const targetPath = r["target_path"] ?? r["targetPointer"];
    if (op === "copy") {
      return {
        operation: "copy",
        target_path: targetPath,
        source_path: r["source_path"] ?? r["sourcePointer"]
      };
    }
    if (op === "constant") {
      return {
        operation: "constant",
        target_path: targetPath,
        value: r["value"]
      };
    }
    if (op === "copy_or_default") {
      return {
        operation: "copy_or_default",
        target_path: targetPath,
        source_path: r["source_path"] ?? r["sourcePointer"],
        default_value: r["default_value"] ?? r["defaultValue"]
      };
    }
    return r;
  });

  return {
    profile_schema_version:
      typeof rec["profile_schema_version"] === "number" ? rec["profile_schema_version"] : 1,
    compiler_profile_version:
      typeof rec["compiler_profile_version"] === "string"
        ? rec["compiler_profile_version"]
        : typeof rec["profile_version"] === "string"
          ? rec["profile_version"]
          : "relayquill.lossless-projection.v1",
    source_event_type_id:
      typeof rec["source_event_type_id"] === "string" ? rec["source_event_type_id"] : eventTypeId,
    source_schema_version:
      typeof rec["source_schema_version"] === "number" ? rec["source_schema_version"] : sourceVersion,
    target_schema_version:
      typeof rec["target_schema_version"] === "number" ? rec["target_schema_version"] : targetVersion,
    mappings: normalizedMappings
  };
}

function normalizeConsoleFilterNode(rawNode: unknown): unknown {
  if (rawNode === null || typeof rawNode !== "object" || Array.isArray(rawNode)) {
    return rawNode;
  }
  const node = rawNode as Record<string, unknown>;
  if (typeof node["kind"] === "string") {
    return node;
  }
  const op = node["op"];
  if (op === "and" || op === "or") {
    const children = Array.isArray(node["children"])
      ? node["children"].map((c) => normalizeConsoleFilterNode(c))
      : [];
    return {
      kind: "boolean",
      operation: op === "and" ? "all" : "any",
      children
    };
  }
  if (op === "not") {
    return {
      kind: "boolean",
      operation: "not",
      child: normalizeConsoleFilterNode(node["child"])
    };
  }
  const path = typeof node["path"] === "string" ? node["path"] : node["pointer"];
  if (op === "exists") {
    return { kind: "leaf", operation: "exists", path };
  }
  if (op === "neq") {
    return {
      kind: "boolean",
      operation: "not",
      child: { kind: "leaf", operation: "eq", path, value: node["value"] }
    };
  }
  if (op === "not_in") {
    return {
      kind: "boolean",
      operation: "not",
      child: { kind: "leaf", operation: "in", path, values: node["values"] }
    };
  }
  if (op === "in") {
    return { kind: "leaf", operation: "in", path, values: node["values"] };
  }
  if (op === "eq" || op === "lt" || op === "lte" || op === "gt" || op === "gte") {
    return { kind: "leaf", operation: op, path, value: node["value"] };
  }
  return node;
}

function normalizeFilterInput(rawFilter: unknown): unknown {
  if (rawFilter === undefined || rawFilter === null) {
    return null;
  }
  if (typeof rawFilter !== "object" || Array.isArray(rawFilter)) {
    return rawFilter;
  }
  const rec = rawFilter as Record<string, unknown>;
  const root = rec["root"];
  if (root !== undefined && typeof root === "object" && root !== null && !Array.isArray(root)) {
    const rootObj = root as Record<string, unknown>;
    if (
      (rootObj["op"] === "and" || rootObj["op"] === "or") &&
      Array.isArray(rootObj["children"]) &&
      rootObj["children"].length === 0
    ) {
      return null;
    }
    return {
      profile_version:
        typeof rec["profile_version"] === "string"
          ? rec["profile_version"]
          : typeof rec["version"] === "string"
            ? rec["version"]
            : "relayquill.filter.v1",
      root: normalizeConsoleFilterNode(root)
    };
  }
  return rawFilter;
}

function summarizeFilterAst(rawFilter: unknown): string {
  if (rawFilter === null || rawFilter === undefined) {
    return "match_all";
  }
  try {
    return JSON.stringify(rawFilter).slice(0, 120);
  } catch {
    return "filter";
  }
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

export function registerSchemaAndSubscriptionRoutes(
  app: FastifyInstance,
  ctx: ApiContext
): void {
  const base = "/api/v1/tenants/:tenant_id/projects/:project_id";

  // ---------------------------------------------------------------------------
  // Event Types & Schema Versions
  // ---------------------------------------------------------------------------
  app.get<{ Params: { tenant_id: string; project_id: string } }>(
    `${base}/event-types`,
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
        await authorizeAction(ctx, auth, "subscriptions.read_safe", {
          installation: inst,
          tenantId,
          projectId
        });

        const items = await ctx.pgAdapter.withTransaction(
          ctx.pgAdapter.configuredRole,
          async (tx) => {
            const res = await tx.query<Record<string, unknown>>(
              `SELECT id, type_name, state, current_schema_version, version
               FROM rq.event_types
               WHERE tenant_id = $1::uuid AND project_id = $2::uuid
               ORDER BY type_name ASC
               LIMIT $3::integer`,
              [tenantId, projectId, limit + 1]
            );
            const rows = res.rows.slice(0, limit);
            const typeIds = rows.map((r) => asText(r["id"]));
            const versionsByType = new Map<string, Array<Record<string, unknown>>>();

            if (typeIds.length > 0) {
              const verRes = await tx.query<Record<string, unknown>>(
                `SELECT event_type_id, schema_version, dialect, profile_version,
                        compatibility_policy, definition_sha256, state
                 FROM rq.event_schema_versions
                 WHERE tenant_id = $1::uuid AND project_id = $2::uuid
                   AND event_type_id = ANY($3::uuid[])
                 ORDER BY schema_version DESC`,
                [tenantId, projectId, typeIds]
              );
              for (const vr of verRes.rows) {
                const typeId = asText(vr["event_type_id"]);
                const schemaVer = Number(vr["schema_version"]);
                const schemaId = deterministicUuid(
                  "event_schema_version",
                  typeId,
                  String(schemaVer)
                );
                const list = versionsByType.get(typeId) ?? [];
                list.push({
                  schema_id: schemaId,
                  event_type_id: typeId,
                  schema_version: schemaVer,
                  dialect: asText(vr["dialect"]),
                  profile_version: asText(vr["profile_version"]),
                  compatibility_policy: asText(vr["compatibility_policy"]),
                  definition_sha256: toHex(vr["definition_sha256"]),
                  state: asText(vr["state"]),
                  version: "1"
                });
                versionsByType.set(typeId, list);
              }
            }

            return {
              hasMore: res.rows.length > limit,
              list: rows.map((r) => {
                const id = asText(r["id"]);
                return {
                  event_type_id: id,
                  type_name: asText(r["type_name"]),
                  state: asText(r["state"]),
                  version: asText(r["version"]),
                  current_schema_version:
                    r["current_schema_version"] === null ||
                    r["current_schema_version"] === undefined
                      ? null
                      : Number(r["current_schema_version"]),
                  schema_versions: versionsByType.get(id) ?? []
                };
              })
            };
          },
          { readOnly: true }
        );

        return sendSuccessEnvelope(
          reply,
          200,
          { items: items.list, page: { next_cursor: null, limit, has_more: items.hasMore } },
          { requestId: request.id }
        );
      } finally {
        auth.destroySecrets();
      }
    }
  );

  app.post<{ Params: { tenant_id: string; project_id: string } }>(
    `${base}/event-types`,
    async (request, reply) => {
      const tenantId = parseTenantId(request.params.tenant_id, "tenant_id");
      const projectId = parseProjectId(request.params.project_id, "project_id");
      const inst = await ctx.pgAdapter.withTransaction(
        ctx.pgAdapter.configuredRole,
        (tx) => readInstallationSnapshot(ctx, tx),
        { readOnly: true }
      );
      const { auth, idempotencyKey, body } = await authenticateHumanMutation(ctx, request, inst);
      try {
        await authorizeAction(ctx, auth, "event_schemas.draft", {
          installation: inst,
          tenantId,
          projectId
        });
        const typeName = parseNonEmptyString(body["type_name"], "type_name", 128);
        if (!/^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*){0,7}$/.test(typeName)) {
          throw new ValidationDomainError({
            code: "INVALID_VALUE",
            message: "type_name must match dotted lowercase identifier grammar",
            fieldErrors: [{ path: "type_name", code: "INVALID_VALUE" }]
          });
        }
        const now = formatUtcTimestamp(ctx.clock.nowInstant());
        const shapeSha = hashCanonicalJson({ op: "event_types.create", projectId, typeName }).sha256;

        const out = await ctx.pgAdapter.withTransaction(ctx.pgAdapter.configuredRole, async (tx) => {
          const existing = await checkCommandReceiptIdempotency(tx, {
            scopeKind: "project",
            tenantId,
            projectId,
            actorPrincipalId: auth.principal.principalId,
            commandFamily: "event_types.create",
            idempotencyKey,
            submittedShapeSha256: shapeSha
          });
          if (existing !== null) {
            return {
              existing: true,
              eventTypeId: existing.resource_id,
              receipt: existing
            };
          }

          const dup = await tx.query(
            `SELECT id FROM rq.event_types WHERE project_id = $1::uuid AND type_name = $2::text LIMIT 1`,
            [projectId, typeName]
          );
          if (dup.rows.length > 0) {
            throw new ConflictDomainError({
              code: "STATE_TRANSITION_NOT_ALLOWED",
              message: `Event type "${typeName}" already exists in project`
            });
          }

          const eventTypeId = parseCanonicalUuid(ctx.ids.nextUuid(), "event_type_id");
          const receiptId = parseCommandReceiptId(ctx.ids.nextUuid(), "receipt_id");
          await tx.query(
            `INSERT INTO rq.event_types (id, tenant_id, project_id, type_name, state, version)
             VALUES ($1::uuid, $2::uuid, $3::uuid, $4::text, 'draft', 1)`,
            [eventTypeId, tenantId, projectId, typeName]
          );

          const receipt = await insertCommandReceiptAndAudit(tx, {
            receiptId,
            scopeKind: "project",
            tenantId,
            projectId,
            actorPrincipalId: auth.principal.principalId,
            commandFamily: "event_types.create",
            idempotencyKey,
            submittedShapeSha256: shapeSha,
            resourceKind: "event_type",
            resourceId: eventTypeId,
            acceptedVersion: 1n,
            safeFacts: { type_name: typeName },
            now
          });
          return { existing: false, eventTypeId, receipt };
        });

        return sendSuccessEnvelope(
          reply,
          out.existing ? 200 : 201,
          {
            receipt: out.receipt,
            event_type_id: out.eventTypeId,
            type_name: typeName,
            state: "draft",
            version: "1",
            current_schema_version: null,
            schema_versions: []
          },
          { requestId: request.id, observedAt: now }
        );
      } finally {
        auth.destroySecrets();
      }
    }
  );

  app.post<{ Params: { tenant_id: string; project_id: string; type_id: string } }>(
    `${base}/event-types/:type_id/schema-versions`,
    async (request, reply) => {
      const tenantId = parseTenantId(request.params.tenant_id, "tenant_id");
      const projectId = parseProjectId(request.params.project_id, "project_id");
      const eventTypeId = parseUuidOrThrow(request.params.type_id, "type_id");
      const inst = await ctx.pgAdapter.withTransaction(
        ctx.pgAdapter.configuredRole,
        (tx) => readInstallationSnapshot(ctx, tx),
        { readOnly: true }
      );
      const { auth, idempotencyKey, body } = await authenticateHumanMutation(ctx, request, inst);
      try {
        await authorizeAction(ctx, auth, "event_schemas.draft", {
          installation: inst,
          tenantId,
          projectId
        });

        const compatPolicy =
          typeof body["compatibility_policy"] === "string"
            ? body["compatibility_policy"]
            : "additive_compatible";
        if (compatPolicy !== "additive_compatible" && compatPolicy !== "new_breaking_version") {
          throw new ValidationDomainError({
            code: "INVALID_VALUE",
            message: "compatibility_policy must be additive_compatible or new_breaking_version",
            fieldErrors: [{ path: "compatibility_policy", code: "INVALID_VALUE" }]
          });
        }

        const rawDefinition = body["definition"];
        const defBytes =
          typeof rawDefinition === "string"
            ? Buffer.from(rawDefinition, "utf8")
            : rawDefinition !== null &&
                typeof rawDefinition === "object" &&
                !Array.isArray(rawDefinition)
              ? Buffer.from(
                  hashCanonicalJson(stripUndefinedJson(rawDefinition as Record<string, unknown>)).bytes
                )
              : null;
        if (defBytes === null || defBytes.byteLength < 2 || defBytes.byteLength > 65536) {
          throw new ValidationDomainError({
            code: "INVALID_VALUE",
            message: "definition must be a valid JSON Schema object within 2..65536 bytes",
            fieldErrors: [{ path: "definition", code: "INVALID_VALUE" }]
          });
        }

        const compiled = compileEventSchemaFromBytes(defBytes);
        const now = formatUtcTimestamp(ctx.clock.nowInstant());
        const shapeSha = hashCanonicalJson({
          op: "event_schema_versions.create",
          eventTypeId,
          compatPolicy,
          defSha: compiled.definitionSha256
        }).sha256;

        const out = await ctx.pgAdapter.withTransaction(ctx.pgAdapter.configuredRole, async (tx) => {
          const existing = await checkCommandReceiptIdempotency(tx, {
            scopeKind: "project",
            tenantId,
            projectId,
            actorPrincipalId: auth.principal.principalId,
            commandFamily: "event_schema_versions.create",
            idempotencyKey,
            submittedShapeSha256: shapeSha
          });
          if (existing !== null) {
            return {
              existing: true,
              schemaId: existing.resource_id,
              schemaVersion: Number(existing.accepted_version ?? "1"),
              receipt: existing
            };
          }

          const etRes = await tx.query(
            `SELECT id FROM rq.event_types WHERE id = $1::uuid AND tenant_id = $2::uuid AND project_id = $3::uuid FOR UPDATE`,
            [eventTypeId, tenantId, projectId]
          );
          if (etRes.rows.length === 0) {
            throw new NotFoundDomainError({
              code: "NOT_FOUND",
              message: `Event type "${eventTypeId}" not found`
            });
          }

          const nextVerRes = await tx.query<Record<string, unknown>>(
            `SELECT COALESCE(MAX(schema_version), 0) + 1 AS next_version
             FROM rq.event_schema_versions
             WHERE event_type_id = $1::uuid AND tenant_id = $2::uuid AND project_id = $3::uuid`,
            [eventTypeId, tenantId, projectId]
          );
          const nextSchemaVersion = Number(nextVerRes.rows[0]?.["next_version"] ?? 1);
          const schemaId = deterministicUuid(
            "event_schema_version",
            eventTypeId,
            String(nextSchemaVersion)
          );
          const receiptId = parseCommandReceiptId(ctx.ids.nextUuid(), "receipt_id");

          await tx.query(
            `INSERT INTO rq.event_schema_versions (
               event_type_id, schema_version, tenant_id, project_id,
               dialect, profile_version, definition_bytes, definition_sha256,
               normalized_profile, compatibility_policy, state, created_by
             ) VALUES (
               $1::uuid, $2::integer, $3::uuid, $4::uuid,
               $5::text, $6::text, $7::bytea, $8::bytea,
               $9::jsonb, $10::text, 'draft', $11::uuid
             )`,
            [
              eventTypeId,
              nextSchemaVersion,
              tenantId,
              projectId,
              EVENT_SCHEMA_DIALECT_2020_12,
              EVENT_SCHEMA_PROFILE_V1,
              defBytes,
              Buffer.from(compiled.definitionSha256, "hex"),
              JSON.stringify(compiled.normalizedProfile),
              compatPolicy,
              auth.principal.principalId
            ]
          );

          const receipt = await insertCommandReceiptAndAudit(tx, {
            receiptId,
            scopeKind: "project",
            tenantId,
            projectId,
            actorPrincipalId: auth.principal.principalId,
            commandFamily: "event_schema_versions.create",
            idempotencyKey,
            submittedShapeSha256: shapeSha,
            resourceKind: "event_schema_version",
            resourceId: schemaId,
            acceptedVersion: BigInt(nextSchemaVersion),
            safeFacts: { event_type_id: eventTypeId, schema_version: nextSchemaVersion },
            now
          });
          return { existing: false, schemaId, schemaVersion: nextSchemaVersion, receipt };
        });

        return sendSuccessEnvelope(
          reply,
          out.existing ? 200 : 201,
          {
            receipt: out.receipt,
            schema_id: out.schemaId,
            event_type_id: eventTypeId,
            schema_version: out.schemaVersion,
            dialect: EVENT_SCHEMA_DIALECT_2020_12,
            profile_version: EVENT_SCHEMA_PROFILE_V1,
            compatibility_policy: compatPolicy,
            definition_sha256: compiled.definitionSha256,
            state: "draft",
            version: "1"
          },
          { requestId: request.id, observedAt: now }
        );
      } finally {
        auth.destroySecrets();
      }
    }
  );

  for (const actionName of ["validate", "publish", "retire"] as const) {
    app.post<{ Params: { tenant_id: string; project_id: string; schema_id: string } }>(
      `${base}/event-schema-versions/:schema_id/${actionName}`,
      async (request, reply) => {
        const tenantId = parseTenantId(request.params.tenant_id, "tenant_id");
        const projectId = parseProjectId(request.params.project_id, "project_id");
        const schemaId = parseUuidOrThrow(request.params.schema_id, "schema_id");
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
          actionName === "validate"
            ? "event_schema_versions.validate"
            : actionName === "publish"
              ? "event_schema_versions.publish"
              : "event_schema_versions.retire";
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

          if (actionName !== "validate") {
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
              targetResourceId: schemaId,
              targetVersion: 1n,
              receiptId,
              expectedCommandSha256: shapeSha
            });
          }

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
                return { receipt: existing, state: actionName === "publish" ? "published" : "retired" };
              }

              const candidates = await tx.query<Record<string, unknown>>(
                `SELECT event_type_id, schema_version, definition_bytes, definition_sha256, state
                 FROM rq.event_schema_versions
                 WHERE tenant_id = $1::uuid AND project_id = $2::uuid`,
                [tenantId, projectId]
              );
              const row = candidates.rows.find(
                (r) =>
                  deterministicUuid(
                    "event_schema_version",
                    asText(r["event_type_id"]),
                    String(r["schema_version"])
                  ) === schemaId
              );
              if (row === undefined) {
                throw new NotFoundDomainError({
                  code: "NOT_FOUND",
                  message: `Event schema version "${schemaId}" not found`
                });
              }

              const eventTypeId = asText(row["event_type_id"]);
              const schemaVer = Number(row["schema_version"]);
              const curState = asText(row["state"]);

              if (actionName === "validate") {
                const defBytes = readByteaBuffer(row["definition_bytes"], "definition_bytes");
                compileEventSchemaFromBytes(defBytes, toHex(row["definition_sha256"]));
              } else if (actionName === "publish") {
                if (curState !== "draft" && curState !== "published") {
                  throw new ConflictDomainError({
                    code: "STATE_TRANSITION_NOT_ALLOWED",
                    message: `Cannot publish schema version from state "${curState}"`
                  });
                }
                await tx.query(
                  `UPDATE rq.event_schema_versions
                   SET state = 'published', published_by = $4::uuid,
                       published_at = COALESCE(published_at, pg_catalog.clock_timestamp())
                   WHERE event_type_id = $1::uuid AND schema_version = $2::integer AND tenant_id = $3::uuid`,
                  [eventTypeId, schemaVer, tenantId, auth.principal.principalId]
                );
                await tx.query(
                  `UPDATE rq.event_types
                   SET state = 'active',
                       current_schema_version = GREATEST(COALESCE(current_schema_version, 0), $2::integer),
                       updated_at = pg_catalog.clock_timestamp(),
                       version = version + 1
                   WHERE id = $1::uuid AND tenant_id = $3::uuid AND project_id = $4::uuid`,
                  [eventTypeId, schemaVer, tenantId, projectId]
                );
              } else {
                if (curState === "retired") {
                  throw new ConflictDomainError({
                    code: "STATE_TRANSITION_NOT_ALLOWED",
                    message: "Schema version is already retired"
                  });
                }
                await tx.query(
                  `UPDATE rq.event_schema_versions
                   SET state = 'retired'
                   WHERE event_type_id = $1::uuid AND schema_version = $2::integer AND tenant_id = $3::uuid`,
                  [eventTypeId, schemaVer, tenantId]
                );
              }

              const outState =
                actionName === "publish"
                  ? "published"
                  : actionName === "retire"
                    ? "retired"
                    : curState;
              const receipt = await insertCommandReceiptAndAudit(tx, {
                receiptId,
                scopeKind: "project",
                tenantId,
                projectId,
                actorPrincipalId: auth.principal.principalId,
                commandFamily: govAction,
                idempotencyKey,
                submittedShapeSha256: shapeSha,
                resourceKind: "event_schema_version",
                resourceId: schemaId,
                acceptedVersion: BigInt(schemaVer),
                safeFacts: { state: outState },
                now
              });
              return { receipt, state: outState };
            }
          );

          return sendSuccessEnvelope(
            reply,
            200,
            { receipt: out.receipt, schema_id: schemaId, state: out.state },
            { requestId: request.id, observedAt: now }
          );
        } finally {
          auth.destroySecrets();
        }
      }
    );
  }

  // ---------------------------------------------------------------------------
  // Representation Profiles & Versions
  // ---------------------------------------------------------------------------
  app.get<{ Params: { tenant_id: string; project_id: string } }>(
    `${base}/representation-profiles`,
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
        await authorizeAction(ctx, auth, "subscriptions.read_safe", {
          installation: inst,
          tenantId,
          projectId
        });

        const resData = await ctx.pgAdapter.withTransaction(
          ctx.pgAdapter.configuredRole,
          async (tx) => {
            const profRes = await tx.query<Record<string, unknown>>(
              `SELECT id, name, event_type_id, state, current_version, version
               FROM rq.representation_profiles
               WHERE tenant_id = $1::uuid AND project_id = $2::uuid
               ORDER BY created_at DESC, id ASC
               LIMIT $3::integer`,
              [tenantId, projectId, limit + 1]
            );
            const rows = profRes.rows.slice(0, limit);
            const profileIds = rows.map((r) => asText(r["id"]));
            const versionsByProfile = new Map<string, Array<Record<string, unknown>>>();

            if (profileIds.length > 0) {
              const verRes = await tx.query<Record<string, unknown>>(
                `SELECT profile_id, profile_version, source_schema_version, target_schema_version,
                        compiler_profile_version, definition_sha256, proven_output_max_bytes, published_at
                 FROM rq.representation_profile_versions
                 WHERE tenant_id = $1::uuid AND project_id = $2::uuid
                   AND profile_id = ANY($3::uuid[])
                 ORDER BY profile_version DESC`,
                [tenantId, projectId, profileIds]
              );
              for (const vr of verRes.rows) {
                const pid = asText(vr["profile_id"]);
                const pver = asText(vr["profile_version"]);
                const versionId = deterministicUuid("representation_profile_version", pid, pver);
                const parent = rows.find((p) => asText(p["id"]) === pid);
                const parentState = parent ? asText(parent["state"]) : "draft";
                const parentCurrVer = parent ? asOptionalText(parent["current_version"]) : null;
                const verState =
                  parentState === "retired"
                    ? "retired"
                    : parentCurrVer === pver || vr["published_at"] !== null
                      ? "active"
                      : "draft";
                const list = versionsByProfile.get(pid) ?? [];
                list.push({
                  version_id: versionId,
                  profile_id: pid,
                  profile_version: pver,
                  source_schema_version: Number(vr["source_schema_version"]),
                  target_schema_version: Number(vr["target_schema_version"]),
                  compiler_profile_version: asText(vr["compiler_profile_version"]),
                  definition_sha256: toHex(vr["definition_sha256"]),
                  proven_output_max_bytes: Number(vr["proven_output_max_bytes"]),
                  state: verState,
                  version: "1"
                });
                versionsByProfile.set(pid, list);
              }
            }

            return {
              hasMore: profRes.rows.length > limit,
              items: rows.map((r) => {
                const id = asText(r["id"]);
                return {
                  profile_id: id,
                  name: asText(r["name"]),
                  event_type_id: asText(r["event_type_id"]),
                  current_version: asOptionalText(r["current_version"]),
                  version: asText(r["version"]),
                  versions: versionsByProfile.get(id) ?? []
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
    `${base}/representation-profiles`,
    async (request, reply) => {
      const tenantId = parseTenantId(request.params.tenant_id, "tenant_id");
      const projectId = parseProjectId(request.params.project_id, "project_id");
      const inst = await ctx.pgAdapter.withTransaction(
        ctx.pgAdapter.configuredRole,
        (tx) => readInstallationSnapshot(ctx, tx),
        { readOnly: true }
      );
      const { auth, idempotencyKey, body } = await authenticateHumanMutation(ctx, request, inst);
      try {
        await authorizeAction(ctx, auth, "event_schemas.draft", {
          installation: inst,
          tenantId,
          projectId
        });
        const name = parseNonEmptyString(body["name"], "name", 128);
        const eventTypeId = parseUuidOrThrow(body["event_type_id"], "event_type_id");
        const now = formatUtcTimestamp(ctx.clock.nowInstant());
        const shapeSha = hashCanonicalJson({
          op: "representation_profiles.create",
          projectId,
          name,
          eventTypeId
        }).sha256;

        const out = await ctx.pgAdapter.withTransaction(ctx.pgAdapter.configuredRole, async (tx) => {
          const existing = await checkCommandReceiptIdempotency(tx, {
            scopeKind: "project",
            tenantId,
            projectId,
            actorPrincipalId: auth.principal.principalId,
            commandFamily: "representation_profiles.create",
            idempotencyKey,
            submittedShapeSha256: shapeSha
          });
          if (existing !== null) {
            return { existing: true, profileId: existing.resource_id, receipt: existing };
          }

          const etCheck = await tx.query(
            `SELECT id FROM rq.event_types WHERE id = $1::uuid AND tenant_id = $2::uuid AND project_id = $3::uuid`,
            [eventTypeId, tenantId, projectId]
          );
          if (etCheck.rows.length === 0) {
            throw new NotFoundDomainError({
              code: "NOT_FOUND",
              message: `Event type "${eventTypeId}" not found`
            });
          }
          const dup = await tx.query(
            `SELECT id FROM rq.representation_profiles WHERE project_id = $1::uuid AND name = $2::text`,
            [projectId, name]
          );
          if (dup.rows.length > 0) {
            throw new ConflictDomainError({
              code: "STATE_TRANSITION_NOT_ALLOWED",
              message: `Representation profile "${name}" already exists`
            });
          }

          const profileId = parseCanonicalUuid(ctx.ids.nextUuid(), "profile_id");
          const receiptId = parseCommandReceiptId(ctx.ids.nextUuid(), "receipt_id");
          await tx.query(
            `INSERT INTO rq.representation_profiles (
               id, tenant_id, project_id, event_type_id, name, state, created_by, version
             ) VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid, $5::text, 'draft', $6::uuid, 1)`,
            [profileId, tenantId, projectId, eventTypeId, name, auth.principal.principalId]
          );

          const receipt = await insertCommandReceiptAndAudit(tx, {
            receiptId,
            scopeKind: "project",
            tenantId,
            projectId,
            actorPrincipalId: auth.principal.principalId,
            commandFamily: "representation_profiles.create",
            idempotencyKey,
            submittedShapeSha256: shapeSha,
            resourceKind: "representation_profile",
            resourceId: profileId,
            acceptedVersion: 1n,
            safeFacts: { name, event_type_id: eventTypeId },
            now
          });
          return { existing: false, profileId, receipt };
        });

        return sendSuccessEnvelope(
          reply,
          out.existing ? 200 : 201,
          {
            receipt: out.receipt,
            profile_id: out.profileId,
            name,
            event_type_id: eventTypeId,
            current_version: null,
            version: "1",
            versions: []
          },
          { requestId: request.id, observedAt: now }
        );
      } finally {
        auth.destroySecrets();
      }
    }
  );

  app.post<{ Params: { tenant_id: string; project_id: string; profile_id: string } }>(
    `${base}/representation-profiles/:profile_id/versions`,
    async (request, reply) => {
      const tenantId = parseTenantId(request.params.tenant_id, "tenant_id");
      const projectId = parseProjectId(request.params.project_id, "project_id");
      const profileId = parseUuidOrThrow(request.params.profile_id, "profile_id");
      const inst = await ctx.pgAdapter.withTransaction(
        ctx.pgAdapter.configuredRole,
        (tx) => readInstallationSnapshot(ctx, tx),
        { readOnly: true }
      );
      const { auth, idempotencyKey, body } = await authenticateHumanMutation(ctx, request, inst);
      try {
        await authorizeAction(ctx, auth, "event_schemas.draft", {
          installation: inst,
          tenantId,
          projectId
        });

        const sourceSchemaVersion = parsePositiveInteger(
          body["source_schema_version"],
          "source_schema_version"
        );
        const targetSchemaVersion = parsePositiveInteger(
          body["target_schema_version"],
          "target_schema_version"
        );
        const now = formatUtcTimestamp(ctx.clock.nowInstant());
        const shapeSha = hashCanonicalJson({
          op: "representation_profile_versions.create",
          profileId,
          sourceSchemaVersion,
          targetSchemaVersion,
          body: stripUndefinedJson(body)
        }).sha256;

        const out = await ctx.pgAdapter.withTransaction(ctx.pgAdapter.configuredRole, async (tx) => {
          const existing = await checkCommandReceiptIdempotency(tx, {
            scopeKind: "project",
            tenantId,
            projectId,
            actorPrincipalId: auth.principal.principalId,
            commandFamily: "representation_profile_versions.create",
            idempotencyKey,
            submittedShapeSha256: shapeSha
          });
          if (existing !== null) {
            return {
              existing: true,
              versionId: existing.resource_id,
              profileVersion: existing.accepted_version ?? "1",
              compilerProfileVersion: "relayquill.lossless-projection.v1",
              definitionSha256: shapeSha,
              provenOutputMaxBytes: 1,
              receipt: existing
            };
          }

          const profRes = await tx.query<Record<string, unknown>>(
            `SELECT p.id, p.event_type_id, et.type_name
             FROM rq.representation_profiles p
             JOIN rq.event_types et ON et.id = p.event_type_id
             WHERE p.id = $1::uuid AND p.tenant_id = $2::uuid AND p.project_id = $3::uuid
             FOR UPDATE OF p`,
            [profileId, tenantId, projectId]
          );
          if (profRes.rows.length === 0) {
            throw new NotFoundDomainError({
              code: "NOT_FOUND",
              message: `Representation profile "${profileId}" not found`
            });
          }
          const eventTypeId = asText(profRes.rows[0]?.["event_type_id"]);
          const eventTypeName = asText(profRes.rows[0]?.["type_name"]);

          const schemaRowsRes = await tx.query<Record<string, unknown>>(
            `SELECT schema_version, definition_bytes
             FROM rq.event_schema_versions
             WHERE event_type_id = $1::uuid AND tenant_id = $2::uuid AND project_id = $3::uuid
               AND schema_version IN ($4::integer, $5::integer)`,
            [eventTypeId, tenantId, projectId, sourceSchemaVersion, targetSchemaVersion]
          );
          const sourceRow = schemaRowsRes.rows.find(
            (r) => Number(r["schema_version"]) === sourceSchemaVersion
          );
          const targetRow = schemaRowsRes.rows.find(
            (r) => Number(r["schema_version"]) === targetSchemaVersion
          );
          if (sourceRow === undefined || targetRow === undefined) {
            throw new NotFoundDomainError({
              code: "NOT_FOUND",
              message: "Source or target event schema version not found for event type"
            });
          }

          const sourceCompiled = compileEventSchemaFromBytes(
            readByteaBuffer(sourceRow["definition_bytes"], "source.definition_bytes")
          );
          const targetCompiled = compileEventSchemaFromBytes(
            readByteaBuffer(targetRow["definition_bytes"], "target.definition_bytes")
          );
          const normalizedDef = normalizeConsoleProjectionDefinition(
            body["definition"],
            eventTypeId,
            sourceSchemaVersion,
            targetSchemaVersion
          );
          const compiledProjection = compileProjectionProfile(
            normalizedDef,
            sourceCompiled,
            targetCompiled,
            { eventType: eventTypeName }
          );
          const defBytes = Buffer.from(hashCanonicalJson(stripUndefinedJson(normalizedDef)).bytes);

          const nextVerRes = await tx.query<Record<string, unknown>>(
            `SELECT COALESCE(MAX(profile_version), 0) + 1 AS next_version
             FROM rq.representation_profile_versions
             WHERE profile_id = $1::uuid AND tenant_id = $2::uuid AND project_id = $3::uuid`,
            [profileId, tenantId, projectId]
          );
          const profileVersion = asText(nextVerRes.rows[0]?.["next_version"], "1");
          const versionId = deterministicUuid(
            "representation_profile_version",
            profileId,
            profileVersion
          );
          const receiptId = parseCommandReceiptId(ctx.ids.nextUuid(), "receipt_id");

          await tx.query(
            `INSERT INTO rq.representation_profile_versions (
               profile_id, profile_version, tenant_id, project_id, event_type_id,
               source_schema_version, target_schema_version, definition_bytes,
               definition_sha256, normalized_mapping, compiler_profile_version,
               proven_output_max_bytes, created_by
             ) VALUES (
               $1::uuid, $2::bigint, $3::uuid, $4::uuid, $5::uuid,
               $6::integer, $7::integer, $8::bytea,
               $9::bytea, $10::jsonb, $11::text,
               $12::integer, $13::uuid
             )`,
            [
              profileId,
              profileVersion,
              tenantId,
              projectId,
              eventTypeId,
              sourceSchemaVersion,
              targetSchemaVersion,
              defBytes,
              Buffer.from(compiledProjection.definitionSha256, "hex"),
              JSON.stringify(compiledProjection.normalizedMapping),
              compiledProjection.compilerProfileVersion,
              compiledProjection.provenOutputMaxBytes,
              auth.principal.principalId
            ]
          );

          const receipt = await insertCommandReceiptAndAudit(tx, {
            receiptId,
            scopeKind: "project",
            tenantId,
            projectId,
            actorPrincipalId: auth.principal.principalId,
            commandFamily: "representation_profile_versions.create",
            idempotencyKey,
            submittedShapeSha256: shapeSha,
            resourceKind: "representation_profile_version",
            resourceId: versionId,
            acceptedVersion: BigInt(profileVersion),
            safeFacts: {
              profile_id: profileId,
              proven_output_max_bytes: compiledProjection.provenOutputMaxBytes
            },
            now
          });
          return {
            existing: false,
            versionId,
            profileVersion,
            compilerProfileVersion: compiledProjection.compilerProfileVersion,
            definitionSha256: compiledProjection.definitionSha256,
            provenOutputMaxBytes: compiledProjection.provenOutputMaxBytes,
            receipt
          };
        });

        return sendSuccessEnvelope(
          reply,
          out.existing ? 200 : 201,
          {
            receipt: out.receipt,
            version_id: out.versionId,
            profile_id: profileId,
            profile_version: out.profileVersion,
            source_schema_version: sourceSchemaVersion,
            target_schema_version: targetSchemaVersion,
            compiler_profile_version: out.compilerProfileVersion,
            definition_sha256: out.definitionSha256,
            proven_output_max_bytes: out.provenOutputMaxBytes,
            state: "draft",
            version: "1"
          },
          { requestId: request.id, observedAt: now }
        );
      } finally {
        auth.destroySecrets();
      }
    }
  );

  for (const actionName of ["activate", "retire"] as const) {
    app.post<{ Params: { tenant_id: string; project_id: string; version_id: string } }>(
      `${base}/representation-profile-versions/:version_id/${actionName}`,
      async (request, reply) => {
        const tenantId = parseTenantId(request.params.tenant_id, "tenant_id");
        const projectId = parseProjectId(request.params.project_id, "project_id");
        const versionId = parseUuidOrThrow(request.params.version_id, "version_id");
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
          actionName === "activate"
            ? "representation_profiles.activate"
            : "representation_profiles.retire";
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
            targetResourceId: versionId,
            targetVersion: 1n,
            receiptId,
            expectedCommandSha256: shapeSha
          });

          const receipt = await ctx.pgAdapter.withTransaction(
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
                return existing;
              }

              const allVers = await tx.query<Record<string, unknown>>(
                `SELECT profile_id, profile_version
                 FROM rq.representation_profile_versions
                 WHERE tenant_id = $1::uuid AND project_id = $2::uuid`,
                [tenantId, projectId]
              );
              const row = allVers.rows.find(
                (r) =>
                  deterministicUuid(
                    "representation_profile_version",
                    asText(r["profile_id"]),
                    asText(r["profile_version"])
                  ) === versionId
              );
              if (row === undefined) {
                throw new NotFoundDomainError({
                  code: "NOT_FOUND",
                  message: `Representation profile version "${versionId}" not found`
                });
              }
              const profileId = asText(row["profile_id"]);
              const profileVersion = asText(row["profile_version"]);

              if (actionName === "activate") {
                await tx.query(
                  `UPDATE rq.representation_profile_versions
                   SET published_by = $4::uuid, published_at = COALESCE(published_at, pg_catalog.clock_timestamp())
                   WHERE profile_id = $1::uuid AND profile_version = $2::bigint AND tenant_id = $3::uuid`,
                  [profileId, profileVersion, tenantId, auth.principal.principalId]
                );
                await tx.query(
                  `UPDATE rq.representation_profiles
                   SET state = 'active', current_version = $2::bigint, version = version + 1
                   WHERE id = $1::uuid AND tenant_id = $3::uuid AND project_id = $4::uuid`,
                  [profileId, profileVersion, tenantId, projectId]
                );
              } else {
                await tx.query(
                  `UPDATE rq.representation_profiles
                   SET state = 'retired', version = version + 1
                   WHERE id = $1::uuid AND tenant_id = $2::uuid AND project_id = $3::uuid`,
                  [profileId, tenantId, projectId]
                );
              }

              return insertCommandReceiptAndAudit(tx, {
                receiptId,
                scopeKind: "project",
                tenantId,
                projectId,
                actorPrincipalId: auth.principal.principalId,
                commandFamily: govAction,
                idempotencyKey,
                submittedShapeSha256: shapeSha,
                resourceKind: "representation_profile_version",
                resourceId: versionId,
                acceptedVersion: BigInt(profileVersion),
                safeFacts: { state: actionName === "activate" ? "active" : "retired" },
                now
              });
            }
          );

          return sendSuccessEnvelope(
            reply,
            200,
            {
              receipt,
              version_id: versionId,
              state: actionName === "activate" ? "active" : "retired"
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
  // Receiver Contracts & Versions
  // ---------------------------------------------------------------------------
  app.get<{ Params: { tenant_id: string; project_id: string } }>(
    `${base}/receiver-contracts`,
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
        await authorizeAction(ctx, auth, "subscriptions.read_safe", {
          installation: inst,
          tenantId,
          projectId
        });

        const resData = await ctx.pgAdapter.withTransaction(
          ctx.pgAdapter.configuredRole,
          async (tx) => {
            const rcRes = await tx.query<Record<string, unknown>>(
              `SELECT id, endpoint_id, name, state, current_version, version
               FROM rq.receiver_contracts
               WHERE tenant_id = $1::uuid AND project_id = $2::uuid
               ORDER BY created_at DESC, id ASC
               LIMIT $3::integer`,
              [tenantId, projectId, limit + 1]
            );
            const rows = rcRes.rows.slice(0, limit);
            const contractIds = rows.map((r) => asText(r["id"]));
            const versionsByContract = new Map<string, Array<Record<string, unknown>>>();
            const scopeByContract = new Map<string, string>();

            if (contractIds.length > 0) {
              const verRes = await tx.query<Record<string, unknown>>(
                `SELECT contract_id, contract_version, consumer_contract_scope, definition_bytes,
                        definition_sha256, receipt_profile, ordering_profile, verified_at
                 FROM rq.receiver_contract_versions
                 WHERE tenant_id = $1::uuid AND project_id = $2::uuid
                   AND contract_id = ANY($3::uuid[])
                 ORDER BY contract_version DESC`,
                [tenantId, projectId, contractIds]
              );
              for (const vr of verRes.rows) {
                const cid = asText(vr["contract_id"]);
                const cver = asText(vr["contract_version"]);
                if (!scopeByContract.has(cid)) {
                  scopeByContract.set(cid, asText(vr["consumer_contract_scope"], "default"));
                }
                let parsedDef: Record<string, unknown> = {};
                try {
                  parsedDef = JSON.parse(
                    readByteaBuffer(vr["definition_bytes"], "definition_bytes").toString("utf8")
                  ) as Record<string, unknown>;
                } catch {
                  parsedDef = {};
                }
                const parent = rows.find((p) => asText(p["id"]) === cid);
                const parentState = parent ? asText(parent["state"]) : "draft";
                const parentCurrVer = parent ? asOptionalText(parent["current_version"]) : null;
                const verState =
                  parentState === "retired"
                    ? "retired"
                    : parentCurrVer === cver && parentState === "active"
                      ? "active"
                      : vr["verified_at"] !== null
                        ? "verified"
                        : "draft";
                const list = versionsByContract.get(cid) ?? [];
                list.push({
                  version_id: deterministicUuid("receiver_contract_version", cid, cver),
                  contract_id: cid,
                  contract_version: cver,
                  envelope_version:
                    typeof parsedDef["envelope_version"] === "number"
                      ? parsedDef["envelope_version"]
                      : 1,
                  receipt_profile: asText(vr["receipt_profile"]),
                  ordering_profile: asText(vr["ordering_profile"]),
                  allowed_business_key_ids: Array.isArray(parsedDef["allowed_business_key_ids"])
                    ? parsedDef["allowed_business_key_ids"]
                    : ["order_id"],
                  definition_sha256: toHex(vr["definition_sha256"]),
                  state: verState,
                  verified_at:
                    vr["verified_at"] === null || vr["verified_at"] === undefined
                      ? null
                      : formatPgTimestamp(vr["verified_at"]),
                  version: "1"
                });
                versionsByContract.set(cid, list);
              }
            }

            return {
              hasMore: rcRes.rows.length > limit,
              items: rows.map((r) => {
                const id = asText(r["id"]);
                return {
                  contract_id: id,
                  endpoint_id: asText(r["endpoint_id"]),
                  name: asText(r["name"]),
                  consumer_contract_scope: scopeByContract.get(id) ?? "default",
                  current_version: asOptionalText(r["current_version"]),
                  versions: versionsByContract.get(id) ?? []
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
    `${base}/receiver-contracts`,
    async (request, reply) => {
      const tenantId = parseTenantId(request.params.tenant_id, "tenant_id");
      const projectId = parseProjectId(request.params.project_id, "project_id");
      const inst = await ctx.pgAdapter.withTransaction(
        ctx.pgAdapter.configuredRole,
        (tx) => readInstallationSnapshot(ctx, tx),
        { readOnly: true }
      );
      const { auth, idempotencyKey, body } = await authenticateHumanMutation(ctx, request, inst);
      try {
        await authorizeAction(ctx, auth, "event_schemas.draft", {
          installation: inst,
          tenantId,
          projectId
        });
        const endpointId = parseUuidOrThrow(body["endpoint_id"], "endpoint_id");
        const name = parseNonEmptyString(body["name"], "name", 128);
        const consumerScope =
          typeof body["consumer_contract_scope"] === "string" &&
          body["consumer_contract_scope"].trim().length > 0
            ? body["consumer_contract_scope"].trim()
            : "default";
        const now = formatUtcTimestamp(ctx.clock.nowInstant());
        const shapeSha = hashCanonicalJson({
          op: "receiver_contracts.create",
          endpointId,
          name
        }).sha256;

        const out = await ctx.pgAdapter.withTransaction(ctx.pgAdapter.configuredRole, async (tx) => {
          const existing = await checkCommandReceiptIdempotency(tx, {
            scopeKind: "project",
            tenantId,
            projectId,
            actorPrincipalId: auth.principal.principalId,
            commandFamily: "receiver_contracts.create",
            idempotencyKey,
            submittedShapeSha256: shapeSha
          });
          if (existing !== null) {
            return { existing: true, contractId: existing.resource_id, receipt: existing };
          }

          const epRes = await tx.query(
            `SELECT id FROM rq.endpoints WHERE id = $1::uuid AND tenant_id = $2::uuid AND project_id = $3::uuid`,
            [endpointId, tenantId, projectId]
          );
          if (epRes.rows.length === 0) {
            throw new NotFoundDomainError({
              code: "NOT_FOUND",
              message: `Endpoint "${endpointId}" not found`
            });
          }
          const dup = await tx.query(
            `SELECT id FROM rq.receiver_contracts WHERE endpoint_id = $1::uuid AND name = $2::text`,
            [endpointId, name]
          );
          if (dup.rows.length > 0) {
            throw new ConflictDomainError({
              code: "STATE_TRANSITION_NOT_ALLOWED",
              message: `Receiver contract "${name}" already exists on endpoint`
            });
          }

          const contractId = parseCanonicalUuid(ctx.ids.nextUuid(), "contract_id");
          const receiptId = parseCommandReceiptId(ctx.ids.nextUuid(), "receipt_id");
          await tx.query(
            `INSERT INTO rq.receiver_contracts (
               id, tenant_id, project_id, endpoint_id, name, state, created_by, version
             ) VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid, $5::text, 'draft', $6::uuid, 1)`,
            [contractId, tenantId, projectId, endpointId, name, auth.principal.principalId]
          );

          const receipt = await insertCommandReceiptAndAudit(tx, {
            receiptId,
            scopeKind: "project",
            tenantId,
            projectId,
            actorPrincipalId: auth.principal.principalId,
            commandFamily: "receiver_contracts.create",
            idempotencyKey,
            submittedShapeSha256: shapeSha,
            resourceKind: "receiver_contract",
            resourceId: contractId,
            acceptedVersion: 1n,
            safeFacts: { endpoint_id: endpointId, name },
            now
          });
          return { existing: false, contractId, receipt };
        });

        return sendSuccessEnvelope(
          reply,
          out.existing ? 200 : 201,
          {
            receipt: out.receipt,
            contract_id: out.contractId,
            endpoint_id: endpointId,
            name,
            consumer_contract_scope: consumerScope,
            current_version: null,
            versions: []
          },
          { requestId: request.id, observedAt: now }
        );
      } finally {
        auth.destroySecrets();
      }
    }
  );

  app.post<{ Params: { tenant_id: string; project_id: string; contract_id: string } }>(
    `${base}/receiver-contracts/:contract_id/versions`,
    async (request, reply) => {
      const tenantId = parseTenantId(request.params.tenant_id, "tenant_id");
      const projectId = parseProjectId(request.params.project_id, "project_id");
      const contractId = parseUuidOrThrow(request.params.contract_id, "contract_id");
      const inst = await ctx.pgAdapter.withTransaction(
        ctx.pgAdapter.configuredRole,
        (tx) => readInstallationSnapshot(ctx, tx),
        { readOnly: true }
      );
      const { auth, idempotencyKey, body } = await authenticateHumanMutation(ctx, request, inst);
      try {
        await authorizeAction(ctx, auth, "event_schemas.draft", {
          installation: inst,
          tenantId,
          projectId
        });

        const receiptProfile =
          body["receipt_profile"] === "http_ack_only" ||
          body["receipt_profile"] === "receiver_local_commit_v1"
            ? body["receipt_profile"]
            : "receiver_local_commit_v1";
        const orderingProfile =
          body["ordering_profile"] === "unordered" ||
          body["ordering_profile"] === "receiver_strict_key_v1"
            ? body["ordering_profile"]
            : "receiver_strict_key_v1";
        const envelopeVersion =
          body["envelope_version"] !== undefined
            ? parsePositiveInteger(body["envelope_version"], "envelope_version")
            : 1;
        const minRetention =
          body["minimum_inbox_retention_seconds"] !== undefined
            ? Math.max(
                7_776_000,
                parsePositiveInteger(
                  body["minimum_inbox_retention_seconds"],
                  "minimum_inbox_retention_seconds"
                )
              )
            : 7_776_000;
        const allowedKeys = Array.isArray(body["allowed_business_key_ids"])
          ? body["allowed_business_key_ids"].filter(
              (x): x is string => typeof x === "string" && x.trim().length > 0
            )
          : ["order_id"];
        const consumerScope =
          typeof body["consumer_contract_scope"] === "string" &&
          body["consumer_contract_scope"].trim().length > 0
            ? body["consumer_contract_scope"].trim()
            : "default";

        const defObj = {
          schema_version: 1,
          envelope_version: envelopeVersion,
          consumer_contract_scope: consumerScope,
          receipt_profile: receiptProfile,
          ordering_profile: orderingProfile,
          allowed_business_key_ids: allowedKeys,
          minimum_inbox_retention_seconds: minRetention
        };
        const defHashed = hashCanonicalJson(defObj);
        const defBytes = Buffer.from(defHashed.bytes);
        const defSha256 = defHashed.sha256;
        const now = formatUtcTimestamp(ctx.clock.nowInstant());
        const shapeSha = hashCanonicalJson({
          op: "receiver_contract_versions.create",
          contractId,
          defSha256
        }).sha256;

        const out = await ctx.pgAdapter.withTransaction(ctx.pgAdapter.configuredRole, async (tx) => {
          const existing = await checkCommandReceiptIdempotency(tx, {
            scopeKind: "project",
            tenantId,
            projectId,
            actorPrincipalId: auth.principal.principalId,
            commandFamily: "receiver_contract_versions.create",
            idempotencyKey,
            submittedShapeSha256: shapeSha
          });
          if (existing !== null) {
            return {
              existing: true,
              versionId: existing.resource_id,
              contractVersion: existing.accepted_version ?? "1",
              receipt: existing
            };
          }

          const rcRes = await tx.query<Record<string, unknown>>(
            `SELECT id, endpoint_id
             FROM rq.receiver_contracts
             WHERE id = $1::uuid AND tenant_id = $2::uuid AND project_id = $3::uuid
             FOR UPDATE`,
            [contractId, tenantId, projectId]
          );
          if (rcRes.rows.length === 0) {
            throw new NotFoundDomainError({
              code: "NOT_FOUND",
              message: `Receiver contract "${contractId}" not found`
            });
          }
          const endpointId = asText(rcRes.rows[0]?.["endpoint_id"]);

          const nextVerRes = await tx.query<Record<string, unknown>>(
            `SELECT COALESCE(MAX(contract_version), 0) + 1 AS next_version
             FROM rq.receiver_contract_versions
             WHERE contract_id = $1::uuid AND tenant_id = $2::uuid AND project_id = $3::uuid`,
            [contractId, tenantId, projectId]
          );
          const contractVersion = asText(nextVerRes.rows[0]?.["next_version"], "1");
          const versionId = deterministicUuid(
            "receiver_contract_version",
            contractId,
            contractVersion
          );
          const receiptId = parseCommandReceiptId(ctx.ids.nextUuid(), "receipt_id");

          await tx.query(
            `INSERT INTO rq.receiver_contract_versions (
               contract_id, contract_version, tenant_id, project_id, endpoint_id,
               consumer_contract_scope, definition_bytes, definition_sha256,
               receipt_profile, ordering_profile, minimum_inbox_retention_seconds, published_by
             ) VALUES (
               $1::uuid, $2::bigint, $3::uuid, $4::uuid, $5::uuid,
               $6::text, $7::bytea, $8::bytea,
               $9::text, $10::text, $11::bigint, $12::uuid
             )`,
            [
              contractId,
              contractVersion,
              tenantId,
              projectId,
              endpointId,
              consumerScope,
              defBytes,
              Buffer.from(defSha256, "hex"),
              receiptProfile,
              orderingProfile,
              String(minRetention),
              auth.principal.principalId
            ]
          );

          const receipt = await insertCommandReceiptAndAudit(tx, {
            receiptId,
            scopeKind: "project",
            tenantId,
            projectId,
            actorPrincipalId: auth.principal.principalId,
            commandFamily: "receiver_contract_versions.create",
            idempotencyKey,
            submittedShapeSha256: shapeSha,
            resourceKind: "receiver_contract_version",
            resourceId: versionId,
            acceptedVersion: BigInt(contractVersion),
            safeFacts: { contract_id: contractId, receipt_profile: receiptProfile },
            now
          });
          return { existing: false, versionId, contractVersion, receipt };
        });

        return sendSuccessEnvelope(
          reply,
          out.existing ? 200 : 201,
          {
            receipt: out.receipt,
            version_id: out.versionId,
            contract_id: contractId,
            contract_version: out.contractVersion,
            envelope_version: envelopeVersion,
            receipt_profile: receiptProfile,
            ordering_profile: orderingProfile,
            allowed_business_key_ids: allowedKeys,
            definition_sha256: defSha256,
            state: "draft",
            verified_at: null,
            version: "1"
          },
          { requestId: request.id, observedAt: now }
        );
      } finally {
        auth.destroySecrets();
      }
    }
  );

  for (const actionName of ["verify", "activate"] as const) {
    app.post<{ Params: { tenant_id: string; project_id: string; version_id: string } }>(
      `${base}/receiver-contract-versions/:version_id/${actionName}`,
      async (request, reply) => {
        const tenantId = parseTenantId(request.params.tenant_id, "tenant_id");
        const projectId = parseProjectId(request.params.project_id, "project_id");
        const versionId = parseUuidOrThrow(request.params.version_id, "version_id");
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
          actionName === "verify" ? "receiver_contracts.verify" : "receiver_contracts.activate";
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
            targetResourceId: versionId,
            targetVersion: 1n,
            receiptId,
            expectedCommandSha256: shapeSha
          });

          const receipt = await ctx.pgAdapter.withTransaction(
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
                return existing;
              }

              const allVers = await tx.query<Record<string, unknown>>(
                `SELECT contract_id, contract_version, verified_at
                 FROM rq.receiver_contract_versions
                 WHERE tenant_id = $1::uuid AND project_id = $2::uuid`,
                [tenantId, projectId]
              );
              const row = allVers.rows.find(
                (r) =>
                  deterministicUuid(
                    "receiver_contract_version",
                    asText(r["contract_id"]),
                    asText(r["contract_version"])
                  ) === versionId
              );
              if (row === undefined) {
                throw new NotFoundDomainError({
                  code: "NOT_FOUND",
                  message: `Receiver contract version "${versionId}" not found`
                });
              }
              const contractId = asText(row["contract_id"]);
              const contractVersion = asText(row["contract_version"]);

              if (actionName === "verify") {
                await tx.query(
                  `UPDATE rq.receiver_contract_versions
                   SET verified_at = COALESCE(verified_at, pg_catalog.clock_timestamp())
                   WHERE contract_id = $1::uuid AND contract_version = $2::bigint AND tenant_id = $3::uuid`,
                  [contractId, contractVersion, tenantId]
                );
                await tx.query(
                  `UPDATE rq.receiver_contracts
                   SET state = CASE WHEN state = 'draft' THEN 'verified' ELSE state END, version = version + 1
                   WHERE id = $1::uuid AND tenant_id = $2::uuid AND project_id = $3::uuid`,
                  [contractId, tenantId, projectId]
                );
              } else {
                await tx.query(
                  `UPDATE rq.receiver_contract_versions
                   SET verified_at = COALESCE(verified_at, pg_catalog.clock_timestamp())
                   WHERE contract_id = $1::uuid AND contract_version = $2::bigint AND tenant_id = $3::uuid`,
                  [contractId, contractVersion, tenantId]
                );
                await tx.query(
                  `UPDATE rq.receiver_contracts
                   SET state = 'active', current_version = $2::bigint, version = version + 1
                   WHERE id = $1::uuid AND tenant_id = $3::uuid AND project_id = $4::uuid`,
                  [contractId, contractVersion, tenantId, projectId]
                );
              }

              return insertCommandReceiptAndAudit(tx, {
                receiptId,
                scopeKind: "project",
                tenantId,
                projectId,
                actorPrincipalId: auth.principal.principalId,
                commandFamily: govAction,
                idempotencyKey,
                submittedShapeSha256: shapeSha,
                resourceKind: "receiver_contract_version",
                resourceId: versionId,
                acceptedVersion: BigInt(contractVersion),
                safeFacts: { state: actionName === "verify" ? "verified" : "active" },
                now
              });
            }
          );

          return sendSuccessEnvelope(
            reply,
            200,
            {
              receipt,
              version_id: versionId,
              state: actionName === "verify" ? "verified" : "active"
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
  // Subscriptions & Version / Control Lifecycle
  // ---------------------------------------------------------------------------
  app.get<{ Params: { tenant_id: string; project_id: string } }>(
    `${base}/subscriptions`,
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
        await authorizeAction(ctx, auth, "subscriptions.read_safe", {
          installation: inst,
          tenantId,
          projectId
        });

        const resData = await ctx.pgAdapter.withTransaction(
          ctx.pgAdapter.configuredRole,
          async (tx) => {
            const res = await tx.query<Record<string, unknown>>(
              `SELECT s.id, s.name, s.state, s.send_hold, s.current_version, s.version,
                      sv.subscription_version, sv.endpoint_id, sv.endpoint_version, sv.event_type_id,
                      sv.filter_ast, sv.ordering_mode, sv.ordering_domain_id, sv.ordering_extractor,
                      sv.consumer_contract_scope, sv.receiver_contract_id, sv.receiver_contract_version,
                      sv.configuration_sha256,
                      (
                        SELECT COALESCE(ARRAY_AGG(ssv.event_schema_version ORDER BY ssv.event_schema_version ASC), ARRAY[]::integer[])
                        FROM rq.subscription_schema_versions ssv
                        WHERE ssv.subscription_id = s.id AND ssv.subscription_version = sv.subscription_version
                      ) AS selected_schema_versions,
                      (
                        SELECT MIN(str.from_topology_version)
                        FROM rq.subscription_topology_ranges str
                        WHERE str.subscription_id = s.id AND str.subscription_version = sv.subscription_version
                      ) AS topology_from_version,
                      (
                        SELECT MAX(str.until_topology_version)
                        FROM rq.subscription_topology_ranges str
                        WHERE str.subscription_id = s.id AND str.subscription_version = sv.subscription_version
                      ) AS topology_until_version,
                      (
                        SELECT COUNT(*)::text
                        FROM rq.deliveries d
                        WHERE d.subscription_id = s.id AND d.state IN ('pending', 'ready', 'sending', 'retry_wait')
                      ) AS pending_delivery_count
               FROM rq.subscriptions s
               JOIN rq.subscription_versions sv
                 ON sv.subscription_id = s.id
                AND sv.subscription_version = COALESCE(
                      s.current_version,
                      (SELECT MAX(sv2.subscription_version) FROM rq.subscription_versions sv2 WHERE sv2.subscription_id = s.id)
                    )
               WHERE s.tenant_id = $1::uuid AND s.project_id = $2::uuid
               ORDER BY s.created_at DESC, s.id ASC
               LIMIT $3::integer`,
              [tenantId, projectId, limit + 1]
            );

            return {
              hasMore: res.rows.length > limit,
              items: res.rows.slice(0, limit).map((r) => {
                const subId = asText(r["id"]);
                const subVer = asText(r["subscription_version"]);
                const extractorRaw = r["ordering_extractor"] as Record<string, unknown> | null;
                const orderingKeyPointer =
                  extractorRaw !== null && typeof extractorRaw["pointer"] === "string"
                    ? extractorRaw["pointer"]
                    : null;
                const schemaVersRaw = Array.isArray(r["selected_schema_versions"])
                  ? (r["selected_schema_versions"] as unknown[]).map((v) => Number(v))
                  : [];
                return {
                  subscription_id: subId,
                  name: asText(r["name"]),
                  state: asText(r["state"]),
                  send_hold: Boolean(r["send_hold"]),
                  current_version: subVer,
                  version_id: deterministicUuid("subscription_version", subId, subVer),
                  endpoint_id: asText(r["endpoint_id"]),
                  endpoint_version: asText(r["endpoint_version"]),
                  event_type_id: asText(r["event_type_id"]),
                  selected_schema_versions: schemaVersRaw,
                  ordering_mode: asText(r["ordering_mode"]),
                  ordering_domain_id: asOptionalText(r["ordering_domain_id"]),
                  ordering_key_pointer: orderingKeyPointer,
                  consumer_contract_scope: asText(r["consumer_contract_scope"]),
                  receiver_contract_id: asText(r["receiver_contract_id"]),
                  receiver_contract_version: asText(r["receiver_contract_version"]),
                  configuration_sha256: toHex(r["configuration_sha256"]),
                  filter_summary: summarizeFilterAst(r["filter_ast"]),
                  topology_from_version: asOptionalText(r["topology_from_version"]),
                  topology_until_version: asOptionalText(r["topology_until_version"]),
                  pending_delivery_count: asText(r["pending_delivery_count"], "0")
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

  async function insertSubscriptionVersionInTx(params: {
    readonly tx: PgTransactionClient;
    readonly tenantId: CanonicalUuid;
    readonly projectId: CanonicalUuid;
    readonly actorPrincipalId: string;
    readonly subscriptionId: string;
    readonly subscriptionName: string;
    readonly subscriptionState: string;
    readonly sendHold: boolean;
    readonly body: Record<string, unknown>;
  }): Promise<{ readonly dto: Record<string, unknown>; readonly versionNum: bigint }> {
    const {
      tx,
      tenantId,
      projectId,
      actorPrincipalId,
      subscriptionId,
      subscriptionName,
      subscriptionState,
      sendHold,
      body
    } = params;
    const endpointId = parseUuidOrThrow(body["endpoint_id"], "endpoint_id");
    const eventTypeId = parseUuidOrThrow(body["event_type_id"], "event_type_id");
    const endpointVerStr =
      body["endpoint_version"] !== undefined
        ? parsePositiveInt64String(asText(body["endpoint_version"]), "endpoint_version")
        : "1";
    const selectedVersionsRaw = Array.isArray(body["selected_schema_versions"])
      ? body["selected_schema_versions"].map((v, i) =>
          parsePositiveInteger(v, `selected_schema_versions[${i}]`)
        )
      : [1];
    const selectedVersions = Array.from(new Set(selectedVersionsRaw)).sort((a, b) => a - b);
    if (selectedVersions.length === 0) {
      throw new ValidationDomainError({
        code: "INVALID_VALUE",
        message: "selected_schema_versions must contain at least one schema version",
        fieldErrors: [{ path: "selected_schema_versions", code: "INVALID_VALUE" }]
      });
    }

    const epVerCheck = await tx.query(
      `SELECT endpoint_version
       FROM rq.endpoint_versions
       WHERE endpoint_id = $1::uuid AND endpoint_version = $2::bigint AND tenant_id = $3::uuid AND project_id = $4::uuid`,
      [endpointId, endpointVerStr, tenantId, projectId]
    );
    if (epVerCheck.rows.length === 0) {
      throw new NotFoundDomainError({
        code: "NOT_FOUND",
        message: `Endpoint "${endpointId}" version ${endpointVerStr} not found`
      });
    }

    const schemaRes = await tx.query<Record<string, unknown>>(
      `SELECT schema_version, definition_bytes
       FROM rq.event_schema_versions
       WHERE event_type_id = $1::uuid AND tenant_id = $2::uuid AND project_id = $3::uuid
         AND schema_version = ANY($4::integer[])`,
      [eventTypeId, tenantId, projectId, selectedVersions]
    );
    if (schemaRes.rows.length !== selectedVersions.length) {
      throw new NotFoundDomainError({
        code: "NOT_FOUND",
        message: "One or more selected_schema_versions do not exist for event_type_id"
      });
    }
    const compiledSchemas: CompiledEventSchema[] = schemaRes.rows.map((r) =>
      compileEventSchemaFromBytes(readByteaBuffer(r["definition_bytes"], "definition_bytes"))
    );

    const normalizedFilterInput = normalizeFilterInput(body["filter"] ?? body["filter_ast"]);
    const compiledFilter =
      normalizedFilterInput !== null
        ? compileFilterAst(normalizedFilterInput, compiledSchemas, { fieldPath: "filter" })
        : null;

    const orderingMode =
      body["ordering_mode"] === "strict_per_key" ? "strict_per_key" : "unordered";
    const consumerContractScope =
      typeof body["consumer_contract_scope"] === "string" &&
      body["consumer_contract_scope"].trim().length > 0
        ? body["consumer_contract_scope"].trim()
        : "default";

    let compiledExtractor: ReturnType<typeof compileOrderingExtractor> | null = null;
    let orderingDomainId: string | null = null;
    if (orderingMode === "strict_per_key") {
      const extractorInput = body["ordering_extractor"] ?? body["ordering_key_pointer"];
      if (extractorInput === undefined || extractorInput === null || extractorInput === "") {
        throw new ValidationDomainError({
          code: "INVALID_VALUE",
          message: "strict_per_key ordering requires ordering_key_pointer or ordering_extractor",
          fieldErrors: [{ path: "ordering_key_pointer", code: "INVALID_VALUE" }]
        });
      }
      compiledExtractor = compileOrderingExtractor(extractorInput, compiledSchemas, {
        fieldPath: "ordering_key_pointer"
      });
      orderingDomainId = ctx.ids.nextUuid();
      await tx.query(
        `INSERT INTO rq.ordering_domains (
           id, tenant_id, project_id, subscription_id, domain_generation,
           consumer_contract_scope, extractor_sha256, state, created_by
         )
         SELECT $1::uuid, $2::uuid, $3::uuid, $4::uuid,
                COALESCE(MAX(domain_generation), 0) + 1,
                $5::text, $6::bytea, 'prepared', $7::uuid
         FROM rq.ordering_domains
         WHERE subscription_id = $4::uuid`,
        [
          orderingDomainId,
          tenantId,
          projectId,
          subscriptionId,
          consumerContractScope,
          Buffer.from(compiledExtractor.extractorSha256, "hex"),
          actorPrincipalId
        ]
      );
    }

    let receiverContractId =
      body["receiver_contract_id"] !== undefined && body["receiver_contract_id"] !== ""
        ? parseUuidOrThrow(body["receiver_contract_id"], "receiver_contract_id")
        : null;
    let receiverContractVer =
      body["receiver_contract_version"] !== undefined && body["receiver_contract_version"] !== ""
        ? parsePositiveInt64String(
            asText(body["receiver_contract_version"]),
            "receiver_contract_version"
          )
        : "1";
    if (receiverContractId === null) {
      const rcLookup = await tx.query<Record<string, unknown>>(
        `SELECT rc.id, COALESCE(rc.current_version, 1)::text AS ver
         FROM rq.receiver_contracts rc
         WHERE rc.endpoint_id = $1::uuid AND rc.tenant_id = $2::uuid AND rc.project_id = $3::uuid
         ORDER BY rc.created_at DESC
         LIMIT 1`,
        [endpointId, tenantId, projectId]
      );
      if (rcLookup.rows.length > 0) {
        receiverContractId = parseCanonicalUuid(
          asText(rcLookup.rows[0]?.["id"]),
          "receiver_contract_id"
        );
        receiverContractVer = asText(rcLookup.rows[0]?.["ver"], "1");
      } else {
        receiverContractId = deterministicUuid("default_receiver_contract", endpointId);
        receiverContractVer = "1";
        const defaultDef = hashCanonicalJson({
          schema_version: 1,
          receipt_profile: "http_ack_only",
          ordering_profile: "unordered"
        });
        await tx.query(
          `INSERT INTO rq.receiver_contracts (
             id, tenant_id, project_id, endpoint_id, name, state, current_version, created_by, version
           ) VALUES (
             $1::uuid, $2::uuid, $3::uuid, $4::uuid, 'default', 'active', 1, $5::uuid, 1
           ) ON CONFLICT (id) DO NOTHING`,
          [receiverContractId, tenantId, projectId, endpointId, actorPrincipalId]
        );
        await tx.query(
          `INSERT INTO rq.receiver_contract_versions (
             contract_id, contract_version, tenant_id, project_id, endpoint_id,
             consumer_contract_scope, definition_bytes, definition_sha256,
             receipt_profile, ordering_profile, minimum_inbox_retention_seconds, published_by
           ) VALUES (
             $1::uuid, 1, $2::uuid, $3::uuid, $4::uuid,
             $5::text, $6::bytea, $7::bytea,
             'http_ack_only', 'unordered', 7776000, $8::uuid
           ) ON CONFLICT (contract_id, contract_version) DO NOTHING`,
          [
            receiverContractId,
            tenantId,
            projectId,
            endpointId,
            consumerContractScope,
            Buffer.from(defaultDef.bytes),
            Buffer.from(defaultDef.sha256, "hex"),
            actorPrincipalId
          ]
        );
      }
    }

    const retryPolicyVersion =
      typeof body["retry_policy_version"] === "string" &&
      body["retry_policy_version"].trim().length > 0
        ? body["retry_policy_version"].trim()
        : "retry_v1";
    const responsePolicyVersion =
      typeof body["response_policy_version"] === "string" &&
      body["response_policy_version"].trim().length > 0
        ? body["response_policy_version"].trim()
        : "response_v1";

    const nextVerRes = await tx.query<Record<string, unknown>>(
      `SELECT COALESCE(MAX(subscription_version), 0) + 1 AS next_version
       FROM rq.subscription_versions
       WHERE subscription_id = $1::uuid AND tenant_id = $2::uuid AND project_id = $3::uuid`,
      [subscriptionId, tenantId, projectId]
    );
    const subVersion = asText(nextVerRes.rows[0]?.["next_version"], "1");
    const versionId = deterministicUuid("subscription_version", subscriptionId, subVersion);

    const configSha256 = hashCanonicalJson({
      endpoint_id: endpointId,
      endpoint_version: endpointVerStr,
      event_type_id: eventTypeId,
      selected_schema_versions: selectedVersions,
      filter_sha256: compiledFilter?.filterSha256 ?? null,
      ordering_mode: orderingMode,
      ordering_extractor_sha256: compiledExtractor?.extractorSha256 ?? null,
      consumer_contract_scope: consumerContractScope,
      receiver_contract_id: receiverContractId,
      receiver_contract_version: receiverContractVer,
      retry_policy_version: retryPolicyVersion,
      response_policy_version: responsePolicyVersion
    }).sha256;

    await tx.query(
      `INSERT INTO rq.subscription_versions (
         subscription_id, subscription_version, tenant_id, project_id,
         endpoint_id, endpoint_version, event_type_id,
         filter_ast, filter_sha256,
         ordering_mode, ordering_domain_id, ordering_extractor, ordering_extractor_sha256,
         retry_policy_version, response_policy_kind, response_policy_version,
         consumer_contract_scope, receiver_contract_id, receiver_contract_version,
         configuration_sha256, created_by
       ) VALUES (
         $1::uuid, $2::bigint, $3::uuid, $4::uuid,
         $5::uuid, $6::bigint, $7::uuid,
         $8::jsonb, $9::bytea,
         $10::text, $11::uuid, $12::jsonb, $13::bytea,
         $14::text, 'response', $15::text,
         $16::text, $17::uuid, $18::bigint,
         $19::bytea, $20::uuid
       )`,
      [
        subscriptionId,
        subVersion,
        tenantId,
        projectId,
        endpointId,
        endpointVerStr,
        eventTypeId,
        compiledFilter ? JSON.stringify(compiledFilter.filterAst) : null,
        compiledFilter ? Buffer.from(compiledFilter.filterSha256, "hex") : null,
        orderingMode,
        orderingDomainId,
        compiledExtractor ? JSON.stringify(compiledExtractor.normalizedExtractor) : null,
        compiledExtractor ? Buffer.from(compiledExtractor.extractorSha256, "hex") : null,
        retryPolicyVersion,
        responsePolicyVersion,
        consumerContractScope,
        receiverContractId,
        receiverContractVer,
        Buffer.from(configSha256, "hex"),
        actorPrincipalId
      ]
    );

    for (const schemaVer of selectedVersions) {
      await tx.query(
        `INSERT INTO rq.subscription_schema_versions (
           subscription_id, subscription_version, tenant_id, project_id,
           event_type_id, event_schema_version
         ) VALUES ($1::uuid, $2::bigint, $3::uuid, $4::uuid, $5::uuid, $6::integer)`,
        [subscriptionId, subVersion, tenantId, projectId, eventTypeId, schemaVer]
      );
    }

    return {
      versionNum: BigInt(subVersion),
      dto: {
        subscription_id: subscriptionId,
        name: subscriptionName,
        state: subscriptionState,
        send_hold: sendHold,
        current_version: subVersion,
        version_id: versionId,
        endpoint_id: endpointId,
        endpoint_version: endpointVerStr,
        event_type_id: eventTypeId,
        selected_schema_versions: selectedVersions,
        ordering_mode: orderingMode,
        ordering_domain_id: orderingDomainId,
        ordering_key_pointer: compiledExtractor?.pointer.raw ?? null,
        consumer_contract_scope: consumerContractScope,
        receiver_contract_id: receiverContractId,
        receiver_contract_version: receiverContractVer,
        configuration_sha256: configSha256,
        filter_summary: summarizeFilterAst(compiledFilter?.filterAst ?? null),
        topology_from_version: null,
        topology_until_version: null,
        pending_delivery_count: "0"
      }
    };
  }

  app.post<{ Params: { tenant_id: string; project_id: string } }>(
    `${base}/subscriptions`,
    async (request, reply) => {
      const tenantId = parseTenantId(request.params.tenant_id, "tenant_id");
      const projectId = parseProjectId(request.params.project_id, "project_id");
      const inst = await ctx.pgAdapter.withTransaction(
        ctx.pgAdapter.configuredRole,
        (tx) => readInstallationSnapshot(ctx, tx),
        { readOnly: true }
      );
      const { auth, idempotencyKey, body } = await authenticateHumanMutation(ctx, request, inst);
      try {
        await authorizeAction(ctx, auth, "subscriptions.create_version", {
          installation: inst,
          tenantId,
          projectId
        });
        const name = parseNonEmptyString(body["name"], "name", 128);
        const now = formatUtcTimestamp(ctx.clock.nowInstant());
        const shapeSha = hashCanonicalJson({
          op: "subscriptions.create",
          projectId,
          body: stripUndefinedJson(body)
        }).sha256;

        const out = await ctx.pgAdapter.withTransaction(ctx.pgAdapter.configuredRole, async (tx) => {
          const existing = await checkCommandReceiptIdempotency(tx, {
            scopeKind: "project",
            tenantId,
            projectId,
            actorPrincipalId: auth.principal.principalId,
            commandFamily: "subscriptions.create",
            idempotencyKey,
            submittedShapeSha256: shapeSha
          });
          if (existing !== null) {
            return {
              existing: true,
              dto: { subscription_id: existing.resource_id, name },
              receipt: existing
            };
          }

          const dup = await tx.query(
            `SELECT id FROM rq.subscriptions WHERE project_id = $1::uuid AND name = $2::text`,
            [projectId, name]
          );
          if (dup.rows.length > 0) {
            throw new ConflictDomainError({
              code: "STATE_TRANSITION_NOT_ALLOWED",
              message: `Subscription "${name}" already exists`
            });
          }

          const subscriptionId = parseCanonicalUuid(ctx.ids.nextUuid(), "subscription_id");
          const receiptId = parseCommandReceiptId(ctx.ids.nextUuid(), "receipt_id");
          await tx.query(
            `INSERT INTO rq.subscriptions (
               id, tenant_id, project_id, name, state, created_by, version
             ) VALUES ($1::uuid, $2::uuid, $3::uuid, $4::text, 'draft', $5::uuid, 1)`,
            [subscriptionId, tenantId, projectId, name, auth.principal.principalId]
          );

          const inserted = await insertSubscriptionVersionInTx({
            tx,
            tenantId,
            projectId,
            actorPrincipalId: auth.principal.principalId,
            subscriptionId,
            subscriptionName: name,
            subscriptionState: "draft",
            sendHold: false,
            body
          });

          const receipt = await insertCommandReceiptAndAudit(tx, {
            receiptId,
            scopeKind: "project",
            tenantId,
            projectId,
            actorPrincipalId: auth.principal.principalId,
            commandFamily: "subscriptions.create",
            idempotencyKey,
            submittedShapeSha256: shapeSha,
            resourceKind: "subscription",
            resourceId: subscriptionId,
            acceptedVersion: inserted.versionNum,
            safeFacts: { name },
            now
          });
          return { existing: false, dto: inserted.dto, receipt };
        });

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

  app.post<{ Params: { tenant_id: string; project_id: string; subscription_id: string } }>(
    `${base}/subscriptions/:subscription_id/versions`,
    async (request, reply) => {
      const tenantId = parseTenantId(request.params.tenant_id, "tenant_id");
      const projectId = parseProjectId(request.params.project_id, "project_id");
      const subscriptionId = parseUuidOrThrow(request.params.subscription_id, "subscription_id");
      const inst = await ctx.pgAdapter.withTransaction(
        ctx.pgAdapter.configuredRole,
        (tx) => readInstallationSnapshot(ctx, tx),
        { readOnly: true }
      );
      const { auth, idempotencyKey, body } = await authenticateHumanMutation(ctx, request, inst);
      try {
        await authorizeAction(ctx, auth, "subscriptions.create_version", {
          installation: inst,
          tenantId,
          projectId
        });
        const now = formatUtcTimestamp(ctx.clock.nowInstant());
        const shapeSha = hashCanonicalJson({
          op: "subscriptions.create_version",
          subscriptionId,
          body: stripUndefinedJson(body)
        }).sha256;

        const out = await ctx.pgAdapter.withTransaction(ctx.pgAdapter.configuredRole, async (tx) => {
          const existing = await checkCommandReceiptIdempotency(tx, {
            scopeKind: "project",
            tenantId,
            projectId,
            actorPrincipalId: auth.principal.principalId,
            commandFamily: "subscriptions.create_version",
            idempotencyKey,
            submittedShapeSha256: shapeSha
          });
          if (existing !== null) {
            return {
              existing: true,
              dto: { subscription_id: subscriptionId },
              receipt: existing
            };
          }

          const subRes = await tx.query<Record<string, unknown>>(
            `SELECT id, name, state, send_hold
             FROM rq.subscriptions
             WHERE id = $1::uuid AND tenant_id = $2::uuid AND project_id = $3::uuid
             FOR UPDATE`,
            [subscriptionId, tenantId, projectId]
          );
          if (subRes.rows.length === 0) {
            throw new NotFoundDomainError({
              code: "NOT_FOUND",
              message: `Subscription "${subscriptionId}" not found`
            });
          }

          const inserted = await insertSubscriptionVersionInTx({
            tx,
            tenantId,
            projectId,
            actorPrincipalId: auth.principal.principalId,
            subscriptionId,
            subscriptionName: asText(subRes.rows[0]?.["name"]),
            subscriptionState: asText(subRes.rows[0]?.["state"]),
            sendHold: Boolean(subRes.rows[0]?.["send_hold"]),
            body
          });

          const receiptId = parseCommandReceiptId(ctx.ids.nextUuid(), "receipt_id");
          const receipt = await insertCommandReceiptAndAudit(tx, {
            receiptId,
            scopeKind: "project",
            tenantId,
            projectId,
            actorPrincipalId: auth.principal.principalId,
            commandFamily: "subscriptions.create_version",
            idempotencyKey,
            submittedShapeSha256: shapeSha,
            resourceKind: "subscription",
            resourceId: subscriptionId,
            acceptedVersion: inserted.versionNum,
            safeFacts: { subscription_version: inserted.versionNum.toString(10) },
            now
          });
          return { existing: false, dto: inserted.dto, receipt };
        });

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

  for (const actionName of ["validate", "activate"] as const) {
    app.post<{ Params: { tenant_id: string; project_id: string; version_id: string } }>(
      `${base}/subscription-versions/:version_id/${actionName}`,
      async (request, reply) => {
        const tenantId = parseTenantId(request.params.tenant_id, "tenant_id");
        const projectId = parseProjectId(request.params.project_id, "project_id");
        const versionId = parseUuidOrThrow(request.params.version_id, "version_id");
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
          actionName === "validate" ? "subscriptions.validate" : "subscriptions.activate";
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
                return { receipt: existing, state: actionName === "activate" ? "active" : "draft" };
              }

              const svList = await tx.query<Record<string, unknown>>(
                `SELECT sv.subscription_id, sv.subscription_version,
                        sv.ordering_domain_id, sv.configuration_sha256,
                        s.state AS sub_state, s.current_version, s.control_sequence
                 FROM rq.subscription_versions sv
                 JOIN rq.subscriptions s ON s.id = sv.subscription_id
                 WHERE sv.tenant_id = $1::uuid AND sv.project_id = $2::uuid`,
                [tenantId, projectId]
              );
              const row = svList.rows.find(
                (r) =>
                  deterministicUuid(
                    "subscription_version",
                    asText(r["subscription_id"]),
                    asText(r["subscription_version"])
                  ) === versionId
              );
              if (row === undefined) {
                throw new NotFoundDomainError({
                  code: "NOT_FOUND",
                  message: `Subscription version "${versionId}" not found`
                });
              }

              const subId = asText(row["subscription_id"]);
              const subVer = asText(row["subscription_version"]);
              const priorVer = asOptionalText(row["current_version"]);
              const controlSeq = BigInt(asText(row["control_sequence"])) + 1n;

              const outState = actionName === "activate" ? "active" : asText(row["sub_state"]);
              if (actionName === "activate") {
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
                  targetResourceId: versionId,
                  targetVersion: BigInt(subVer),
                  receiptId,
                  expectedCommandSha256: shapeSha
                });
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
                resourceKind: "subscription_version",
                resourceId: versionId,
                acceptedVersion: BigInt(subVer),
                safeFacts: { subscription_id: subId, state: outState },
                now
              });

              if (actionName === "activate") {
                const topRes = await tx.query<Record<string, unknown>>(
                  `UPDATE rq.projects
                   SET topology_version = topology_version + 1,
                       updated_at = pg_catalog.clock_timestamp()
                   WHERE id = $1::uuid AND tenant_id = $2::uuid
                   RETURNING topology_version`,
                  [projectId, tenantId]
                );
                const newTopologyVer = asText(topRes.rows[0]?.["topology_version"], "1");

                await tx.query(
                  `UPDATE rq.subscription_topology_ranges
                   SET until_topology_version = $2::bigint
                   WHERE subscription_id = $1::uuid AND until_topology_version IS NULL`,
                  [subId, newTopologyVer]
                );

                const ctrlEventId = ctx.ids.nextUuid();
                await tx.query(
                  `UPDATE rq.subscription_versions
                   SET activated_at = COALESCE(activated_at, pg_catalog.clock_timestamp())
                   WHERE subscription_id = $1::uuid AND subscription_version = $2::bigint AND tenant_id = $3::uuid`,
                  [subId, subVer, tenantId]
                );
                await tx.query(
                  `UPDATE rq.subscriptions
                   SET state = 'active',
                       current_version = $2::bigint,
                       control_sequence = $3::bigint,
                       updated_at = pg_catalog.clock_timestamp(),
                       version = version + 1
                   WHERE id = $1::uuid AND tenant_id = $4::uuid AND project_id = $5::uuid`,
                  [subId, subVer, controlSeq.toString(10), tenantId, projectId]
                );
                if (row["ordering_domain_id"] !== null && row["ordering_domain_id"] !== undefined) {
                  await tx.query(
                    `UPDATE rq.ordering_domains
                     SET state = 'active', version = version + 1
                     WHERE id = $1::uuid AND tenant_id = $2::uuid AND project_id = $3::uuid`,
                    [asText(row["ordering_domain_id"]), tenantId, projectId]
                  );
                }

                await tx.query(
                  `INSERT INTO rq.subscription_control_events (
                     id, subscription_id, tenant_id, project_id, control_sequence,
                     action, prior_version, resulting_version, topology_version,
                     actor_principal_id, command_receipt_id, configuration_sha256, safe_reason_code
                   ) VALUES (
                     $1::uuid, $2::uuid, $3::uuid, $4::uuid, $5::bigint,
                     'activate', $6::bigint, $7::bigint, $8::bigint,
                     $9::uuid, $10::uuid, $11::bytea, $12::text
                   )`,
                  [
                    ctrlEventId,
                    subId,
                    tenantId,
                    projectId,
                    controlSeq.toString(10),
                    priorVer,
                    subVer,
                    newTopologyVer,
                    auth.principal.principalId,
                    receiptId,
                    toParamBuffer(readByteaBuffer(row["configuration_sha256"], "configuration_sha256")),
                    typeof body["reason_code"] === "string" && body["reason_code"].trim().length > 0
                      ? body["reason_code"].trim()
                      : "subscription_activate"
                  ]
                );

                await tx.query(
                  `INSERT INTO rq.subscription_topology_ranges (
                     project_id, tenant_id, subscription_id, subscription_version,
                     from_topology_version, until_topology_version, activation_event_id
                   ) VALUES ($1::uuid, $2::uuid, $3::uuid, $4::bigint, $5::bigint, NULL, $6::uuid)`,
                  [projectId, tenantId, subId, subVer, newTopologyVer, ctrlEventId]
                );
              }

              return { receipt, state: outState };
            }
          );

          return sendSuccessEnvelope(
            reply,
            200,
            { receipt: out.receipt, version_id: versionId, state: out.state, valid: true },
            { requestId: request.id, observedAt: now }
          );
        } finally {
          auth.destroySecrets();
        }
      }
    );
  }

  for (const actionSlug of [
    "pause-future",
    "hold-sends",
    "pause-all",
    "resume-future",
    "release-send-hold",
    "retire"
  ] as const) {
    app.post<{ Params: { tenant_id: string; project_id: string; subscription_id: string } }>(
      `${base}/subscriptions/:subscription_id/${actionSlug}`,
      async (request, reply) => {
        const tenantId = parseTenantId(request.params.tenant_id, "tenant_id");
        const projectId = parseProjectId(request.params.project_id, "project_id");
        const subscriptionId = parseUuidOrThrow(request.params.subscription_id, "subscription_id");
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
        const dbAction = actionSlug.replace(/-/g, "_");
        const govAction = `subscriptions.${dbAction}` as const;
        try {
          const rawProof = body["operation_proof_id"] ?? extractStepUpHeader(headerMap);
          const hasProof = typeof rawProof === "string" && rawProof.trim().length > 0;
          await authorizeAction(ctx, auth, govAction, {
            installation: inst,
            tenantId,
            projectId,
            stepUpProofId: hasProof ? rawProof : undefined
          });
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
                return { receipt: existing, state: "active", sendHold: false };
              }

              const subRes = await tx.query<Record<string, unknown>>(
                `SELECT id, state, send_hold, current_version, control_sequence
                 FROM rq.subscriptions
                 WHERE id = $1::uuid AND tenant_id = $2::uuid AND project_id = $3::uuid
                 FOR UPDATE`,
                [subscriptionId, tenantId, projectId]
              );
              if (subRes.rows.length === 0) {
                throw new NotFoundDomainError({
                  code: "NOT_FOUND",
                  message: `Subscription "${subscriptionId}" not found`
                });
              }

              const curState = asText(subRes.rows[0]?.["state"]);
              const curSendHold = Boolean(subRes.rows[0]?.["send_hold"]);
              const curVer = asOptionalText(subRes.rows[0]?.["current_version"]);
              const nextCtrlSeq = BigInt(asText(subRes.rows[0]?.["control_sequence"])) + 1n;

              if (hasProof) {
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
                  targetResourceId: subscriptionId,
                  targetVersion: curVer !== null ? BigInt(curVer) : 1n,
                  receiptId,
                  expectedCommandSha256: shapeSha
                });
              }

              let nextState = curState;
              let nextSendHold = curSendHold;
              if (actionSlug === "pause-future") {
                nextState = "paused";
              } else if (actionSlug === "hold-sends") {
                nextSendHold = true;
              } else if (actionSlug === "pause-all") {
                nextState = "paused";
                nextSendHold = true;
              } else if (actionSlug === "resume-future") {
                nextState = "active";
              } else if (actionSlug === "release-send-hold") {
                nextSendHold = false;
              } else if (actionSlug === "retire") {
                nextState = "retired";
                nextSendHold = true;
              }

              let topologyVer: string | null = null;
              if (
                actionSlug === "pause-future" ||
                actionSlug === "pause-all" ||
                actionSlug === "retire"
              ) {
                const topRes = await tx.query<Record<string, unknown>>(
                  `UPDATE rq.projects
                   SET topology_version = topology_version + 1, updated_at = pg_catalog.clock_timestamp()
                   WHERE id = $1::uuid AND tenant_id = $2::uuid
                   RETURNING topology_version`,
                  [projectId, tenantId]
                );
                topologyVer = asText(topRes.rows[0]?.["topology_version"], "1");
                await tx.query(
                  `UPDATE rq.subscription_topology_ranges
                   SET until_topology_version = $2::bigint
                   WHERE subscription_id = $1::uuid AND until_topology_version IS NULL`,
                  [subscriptionId, topologyVer]
                );
              }

              await tx.query(
                `UPDATE rq.subscriptions
                 SET state = $2::text,
                     send_hold = $3::boolean,
                     control_sequence = $4::bigint,
                     updated_at = pg_catalog.clock_timestamp(),
                     version = version + 1
                 WHERE id = $1::uuid AND tenant_id = $5::uuid AND project_id = $6::uuid`,
                [
                  subscriptionId,
                  nextState,
                  nextSendHold,
                  nextCtrlSeq.toString(10),
                  tenantId,
                  projectId
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
                resourceKind: "subscription",
                resourceId: subscriptionId,
                acceptedVersion: nextCtrlSeq,
                safeFacts: { state: nextState, send_hold: nextSendHold },
                now
              });

              await tx.query(
                `INSERT INTO rq.subscription_control_events (
                   id, subscription_id, tenant_id, project_id, control_sequence,
                   action, prior_version, resulting_version, topology_version,
                   actor_principal_id, command_receipt_id, safe_reason_code
                 ) VALUES (
                   $1::uuid, $2::uuid, $3::uuid, $4::uuid, $5::bigint,
                   $6::text, $7::bigint, $7::bigint, $8::bigint,
                   $9::uuid, $10::uuid, $11::text
                 )`,
                [
                  ctx.ids.nextUuid(),
                  subscriptionId,
                  tenantId,
                  projectId,
                  nextCtrlSeq.toString(10),
                  dbAction,
                  curVer,
                  topologyVer,
                  auth.principal.principalId,
                  receiptId,
                  typeof body["reason_code"] === "string" && body["reason_code"].trim().length > 0
                    ? body["reason_code"].trim()
                    : govAction
                ]
              );
              return { receipt, state: nextState, sendHold: nextSendHold };
            }
          );

          return sendSuccessEnvelope(
            reply,
            200,
            {
              receipt: out.receipt,
              subscription_id: subscriptionId,
              state: out.state,
              send_hold: out.sendHold
            },
            { requestId: request.id, observedAt: now }
          );
        } finally {
          auth.destroySecrets();
        }
      }
    );
  }
}
