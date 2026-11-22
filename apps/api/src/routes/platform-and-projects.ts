import crypto from "node:crypto";
import {
  AuthorizationDomainError,
  ConflictDomainError,
  NotFoundDomainError,
  type PlatformRole,
  ValidationDomainError,
  formatUtcTimestamp,
  isPlatformRole,
  parseCanonicalUuid,
  parseCommandReceiptId,
  parseInt64BigInt,
  parsePrincipalId,
  parseProjectId,
  parseTenantId
} from "@relayquill/domain";
import { hashCanonicalJson } from "@relayquill/contracts";
import { type PgTransactionClient, readInstallationStatus } from "@relayquill/postgres";
import { type FastifyInstance } from "fastify";
import {
  type ApiContext,
  authenticateHumanMutation,
  authenticateHumanRead,
  authorizeAction,
  buildCapabilitiesForActions,
  checkCommandReceiptIdempotency,
  consumeStepUpProofFromBody,
  decodeApiCursor,
  encodeApiCursor,
  extractStepUpHeader,
  formatPgTimestamp,
  insertCommandReceiptAndAudit,
  parseCursorQueryParams,
  readInstallationSnapshot,
  stripUndefinedJson
} from "../context.js";
import { sendSuccessEnvelope } from "../http/errors.js";
import { asOptionalText, asText } from "../repos/sql-helpers.js";

function parsePlatformRoleStrict(val: unknown, fieldPath = "role"): PlatformRole {
  if (!isPlatformRole(val)) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Invalid platform role for ${fieldPath}`,
      fieldErrors: [{ path: fieldPath, code: "INVALID_VALUE" }]
    });
  }
  return val;
}

function toHex(val: unknown): string {
  if (Buffer.isBuffer(val)) {
    return val.toString("hex");
  }
  if (val instanceof Uint8Array) {
    return Buffer.from(val).toString("hex");
  }
  return asText(val).replace(/^\\x/, "");
}

async function seedTenantDefaults(
  tx: PgTransactionClient,
  tenantId: string,
  nowIso: string
): Promise<void> {
  await tx.query(
    `INSERT INTO rq.tenant_capacity (tenant_id, updated_at) VALUES ($1::uuid, $2::timestamptz) ON CONFLICT DO NOTHING`,
    [tenantId, nowIso]
  );
  await tx.query(
    `INSERT INTO rq.tenant_watch_capacity (tenant_id, updated_at) VALUES ($1::uuid, $2::timestamptz) ON CONFLICT DO NOTHING`,
    [tenantId, nowIso]
  );
  const ops: readonly [string, number, number][] = [
    ["event_admission", 100_000_000, 50_000_000],
    ["send_start", 100_000_000, 50_000_000],
    ["endpoint_verification", 20_000_000, 5_000_000],
    ["replay_admission", 20_000_000, 5_000_000]
  ];
  for (const [op, cap, refill] of ops) {
    await tx.query(
      `INSERT INTO rq.tenant_rate_buckets (
         tenant_id, operation, tokens_micro, reserved_micro, capacity_micro,
         refill_micro_per_second, refill_remainder_numerator, last_refill_at, updated_at
       ) VALUES ($1::uuid, $2::text, $3::bigint, 0, $3::bigint, $4::bigint, 0, $5::timestamptz, $5::timestamptz)
       ON CONFLICT DO NOTHING`,
      [tenantId, op, cap, refill, nowIso]
    );
  }
}

async function seedProjectDefaults(
  tx: PgTransactionClient,
  tenantId: string,
  projectId: string,
  nowIso: string
): Promise<void> {
  await tx.query(
    `INSERT INTO rq.project_capacity (project_id, tenant_id, updated_at)
     VALUES ($1::uuid, $2::uuid, $3::timestamptz)
     ON CONFLICT DO NOTHING`,
    [projectId, tenantId, nowIso]
  );
  await tx.query(
    `INSERT INTO rq.project_watch_capacity (project_id, tenant_id, updated_at)
     VALUES ($1::uuid, $2::uuid, $3::timestamptz)
     ON CONFLICT DO NOTHING`,
    [projectId, tenantId, nowIso]
  );
  await tx.query(
    `INSERT INTO rq.project_fanout_state (project_id, tenant_id, materialized_through_event_sequence)
     VALUES ($1::uuid, $2::uuid, 0)
     ON CONFLICT DO NOTHING`,
    [projectId, tenantId]
  );
  await tx.query(
    `INSERT INTO rq.project_delivery_totals (project_id, tenant_id, updated_at)
     VALUES ($1::uuid, $2::uuid, $3::timestamptz)
     ON CONFLICT DO NOTHING`,
    [projectId, tenantId, nowIso]
  );
  const ops: readonly [string, number, number][] = [
    ["event_admission", 40_000_000, 20_000_000],
    ["send_start", 40_000_000, 20_000_000],
    ["endpoint_verification", 10_000_000, 5_000_000],
    ["replay_admission", 10_000_000, 5_000_000]
  ];
  for (const [op, cap, refill] of ops) {
    await tx.query(
      `INSERT INTO rq.project_rate_buckets (
         project_id, tenant_id, operation, tokens_micro, reserved_micro, capacity_micro,
         refill_micro_per_second, refill_remainder_numerator, last_refill_at, updated_at
       ) VALUES ($1::uuid, $2::uuid, $3::text, $4::bigint, 0, $4::bigint, $5::bigint, 0, $6::timestamptz, $6::timestamptz)
       ON CONFLICT DO NOTHING`,
      [projectId, tenantId, op, cap, refill, nowIso]
    );
  }

  let domainRes = await tx.query<{ id: string }>(
    `SELECT id FROM rq.dispatch_domains WHERE name = 'primary' LIMIT 1`
  );
  let domainId = domainRes.rows[0]?.id;
  if (domainId === undefined) {
    domainId = crypto.randomUUID();
    await tx.query(
      `INSERT INTO rq.dispatch_domains (id, name, state, policy_kind, policy_version, policy_sha256, updated_at, version)
       SELECT $1::uuid, 'primary', 'active', 'dispatch', 'dispatch_v1', pv.definition_sha256, $2::timestamptz, 1
         FROM rq.policy_versions pv
        WHERE pv.policy_kind = 'dispatch' AND pv.policy_version = 'dispatch_v1'
       ON CONFLICT (name) DO NOTHING`,
      [domainId, nowIso]
    );
    domainRes = await tx.query<{ id: string }>(
      `SELECT id FROM rq.dispatch_domains WHERE name = 'primary' LIMIT 1`
    );
    domainId = domainRes.rows[0]!.id;
  }
  await tx.query(
    `INSERT INTO rq.dispatch_state (dispatch_domain_id, policy_epoch, version)
     VALUES ($1::uuid, 1, 1) ON CONFLICT DO NOTHING`,
    [domainId]
  );
  await tx.query(
    `INSERT INTO rq.tenant_dispatch_state (dispatch_domain_id, tenant_id, weight, deficit_units, version)
     VALUES ($1::uuid, $2::uuid, 100, 0, 1) ON CONFLICT DO NOTHING`,
    [domainId, tenantId]
  );
  await tx.query(
    `INSERT INTO rq.project_dispatch_memberships (dispatch_domain_id, project_id, tenant_id, state, created_at)
     VALUES ($1::uuid, $2::uuid, $3::uuid, 'active', $4::timestamptz) ON CONFLICT DO NOTHING`,
    [domainId, projectId, tenantId, nowIso]
  );
  await tx.query(
    `INSERT INTO rq.project_dispatch_state (dispatch_domain_id, project_id, tenant_id, weight, deficit_units, version)
     VALUES ($1::uuid, $2::uuid, $3::uuid, 100, 0, 1) ON CONFLICT DO NOTHING`,
    [domainId, projectId, tenantId]
  );
}

export function registerPlatformAndProjectRoutes(app: FastifyInstance, ctx: ApiContext): void {
  // Platform installation status
  app.get("/api/v1/platform/installation", async (request, reply) => {
    const inst = await ctx.pgAdapter.withTransaction(
      ctx.pgAdapter.configuredRole,
      (tx) => readInstallationSnapshot(ctx, tx),
      { readOnly: true }
    );
    const { auth } = await authenticateHumanRead(ctx, request, inst);
    try {
      await authorizeAction(ctx, auth, "platform.health.read", { installation: inst });
      const status = await ctx.pgAdapter.withTransaction(
        ctx.pgAdapter.configuredRole,
        (tx) => readInstallationStatus(tx),
        { readOnly: true }
      );
      return sendSuccessEnvelope(
        reply,
        200,
        {
          mode: status.mode,
          control_epoch: status.controlEpoch,
          allow_event_admission: status.allowEventAdmission,
          allow_publication: status.allowPublication,
          allow_fanout: status.allowFanout,
          allow_send: status.allowSend,
          allow_endpoint_verification: status.allowEndpointVerification,
          governance_version: status.governanceVersion.toString(10),
          version: status.version.toString(10),
          updated_at: status.updatedAt
        },
        { requestId: request.id }
      );
    } finally {
      auth.destroySecrets();
    }
  });

  // Platform Tenants
  app.get<{ Querystring: Record<string, unknown> }>(
    "/api/v1/platform/tenants",
    async (request, reply) => {
      const inst = await ctx.pgAdapter.withTransaction(
        ctx.pgAdapter.configuredRole,
        (tx) => readInstallationSnapshot(ctx, tx),
        { readOnly: true }
      );
      const { auth } = await authenticateHumanRead(ctx, request, inst);
      try {
        const decision = await authorizeAction(ctx, auth, "platform.health.read", {
          installation: inst
        });
        const { limit, rawCursor } = parseCursorQueryParams(request.query);
        const cursor = decodeApiCursor(ctx, rawCursor, {
          resource: "audit",
          tenantId: null,
          projectId: null,
          order: "created_at_desc_id_desc"
        });
        const boundaryId = cursor?.boundary.id ?? null;

        const rows = await ctx.pgAdapter.withTransaction(
          ctx.pgAdapter.configuredRole,
          async (tx) => {
            const res = await tx.query<Record<string, unknown>>(
              `SELECT id, slug, display_name, state, governance_version, version, created_at
                 FROM rq.tenants
                WHERE ($1::uuid IS NULL OR id < $1::uuid)
                ORDER BY created_at DESC, id DESC
                LIMIT $2::integer`,
              [boundaryId, limit + 1]
            );
            return res.rows;
          },
          { readOnly: true }
        );

        const hasMore = rows.length > limit;
        const pageRows = rows.slice(0, limit);
        const items = pageRows.map((row) => {
          const tenantId = String(row["id"]);
          const state = String(row["state"]);
          return {
            tenant_id: tenantId,
            slug: String(row["slug"]),
            display_name: String(row["display_name"]),
            state,
            governance_version: String(row["governance_version"]),
            version: String(row["version"]),
            created_at: formatPgTimestamp(row["created_at"]),
            capabilities: buildCapabilitiesForActions(
              ctx,
              decision,
              "tenant",
              tenantId,
              ["tenants.suspend", "tenants.restore", "tenants.retire"],
              {
                expectedVersion: BigInt(String(row["version"])),
                stateAllowed: (act) => ({
                  allowed:
                    (act === "tenants.suspend" && state === "active") ||
                    (act === "tenants.restore" && state === "suspended") ||
                    (act === "tenants.retire" && state !== "retired")
                })
              }
            )
          };
        });

        const last = pageRows[pageRows.length - 1];
        const next_cursor =
          hasMore && last !== undefined
            ? encodeApiCursor(ctx, {
                resource: "audit",
                tenantId: null,
                projectId: null,
                order: "created_at_desc_id_desc",
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
        auth.destroySecrets();
      }
    }
  );

  app.post("/api/v1/platform/tenants", async (request, reply) => {
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
      const rawProofId = body["operation_proof_id"] ?? extractStepUpHeader(headerMap);
      await authorizeAction(ctx, auth, "tenants.create", {
        installation: inst,
        stepUpProofId: typeof rawProofId === "string" ? rawProofId : undefined
      });
      if (body["schema_version"] !== 1) {
        throw new ValidationDomainError({
          code: "UNSUPPORTED_SCHEMA_VERSION",
          message: "createTenant requires schema_version: 1"
        });
      }
      const slug = asText(body["slug"]).trim();
      const displayName = asText(body["display_name"]).trim();
      if (!/^[a-z][a-z0-9-]{1,62}[a-z0-9]$/.test(slug) || displayName.length === 0) {
        throw new ValidationDomainError({
          code: "INVALID_VALUE",
          message: "Tenant slug and display_name are required"
        });
      }

      const now = formatUtcTimestamp(ctx.clock.nowInstant());
      const receiptId = parseCommandReceiptId(ctx.ids.nextUuid(), "receipt_id");
      const tenantId = parseTenantId(body["tenant_id"] ?? ctx.ids.nextUuid(), "tenant_id");
      const stepUpTargetId = parseCanonicalUuid(
        body["target_resource_id"] ?? body["tenant_id"] ?? "00000000-0000-4000-8000-000000000001",
        "target_resource_id"
      );
      await consumeStepUpProofFromBody({
        ctx,
        auth,
        installation: inst,
        body,
        headerMap,
        action: "tenants.create",
        scopeKind: "installation",
        tenantId: null,
        projectId: null,
        targetResourceId: stepUpTargetId,
        targetVersion: 1n,
        receiptId
      });
      const shapeSha = hashCanonicalJson({
        op: "tenants.create",
        slug,
        display_name: displayName
      }).sha256;

      const result = await ctx.pgAdapter.withTransaction(ctx.pgAdapter.configuredRole, async (tx) => {
        const existing = await checkCommandReceiptIdempotency(tx, {
          scopeKind: "installation",
          tenantId: null,
          projectId: null,
          actorPrincipalId: auth.principal.principalId,
          commandFamily: "tenants.create",
          idempotencyKey,
          submittedShapeSha256: shapeSha
        });
        if (existing !== null) {
          return { existing: true, receipt: existing, tenantId: existing.resource_id };
        }

        await tx.query(
          `INSERT INTO rq.tenants (id, slug, display_name, state, governance_version, created_at, updated_at, version)
           VALUES ($1::uuid, $2::text, $3::text, 'active', 1, $4::timestamptz, $4::timestamptz, 1)`,
          [tenantId, slug, displayName, now]
        );
        await seedTenantDefaults(tx, tenantId, now);
        await tx.query(
          `INSERT INTO rq.tenant_memberships (
             id, tenant_id, principal_id, role, state, authority_version, created_at, updated_at, version
           ) VALUES ($1::uuid, $2::uuid, $3::uuid, 'tenant_admin', 'active', 1, $4::timestamptz, $4::timestamptz, 1)
           ON CONFLICT DO NOTHING`,
          [ctx.ids.nextUuid(), tenantId, auth.principal.principalId, now]
        );
        const receipt = await insertCommandReceiptAndAudit(tx, {
          receiptId,
          scopeKind: "installation",
          tenantId: null,
          projectId: null,
          actorPrincipalId: auth.principal.principalId,
          commandFamily: "tenants.create",
          idempotencyKey,
          submittedShapeSha256: shapeSha,
          resourceKind: "tenant",
          resourceId: tenantId,
          acceptedVersion: 1n,
          safeFacts: { slug },
          now
        });
        return { existing: false, receipt, tenantId };
      });

      return sendSuccessEnvelope(
        reply,
        result.existing ? 200 : 201,
        {
          receipt: result.receipt,
          tenant_id: result.tenantId,
          slug,
          display_name: displayName,
          state: "active"
        },
        { requestId: request.id, observedAt: now }
      );
    } finally {
      auth.destroySecrets();
    }
  });

  // Tenant suspend / restore / retire
  for (const [routePath, targetAction] of [
    ["/api/v1/platform/tenants/:tenant_id/suspend", "tenants.suspend"],
    ["/api/v1/platform/tenants/:tenant_id/restore", "tenants.restore"],
    ["/api/v1/tenants/:tenant_id/retire", "tenants.retire"]
  ] as const) {
    app.post<{ Params: { tenant_id: string } }>(routePath, async (request, reply) => {
      const tenantId = parseTenantId(request.params.tenant_id, "tenant_id");
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
        const rawProofId = body["operation_proof_id"] ?? extractStepUpHeader(headerMap);
        await authorizeAction(ctx, auth, targetAction, {
          installation: inst,
          tenantId,
          stepUpProofId: typeof rawProofId === "string" ? rawProofId : undefined
        });
        const expectedVersion = parseInt64BigInt(body["expected_version"] ?? 1, "expected_version");
        const nextState =
          targetAction === "tenants.suspend"
            ? "suspended"
            : targetAction === "tenants.restore"
              ? "active"
              : "retired";
        const now = formatUtcTimestamp(ctx.clock.nowInstant());
        const receiptId = parseCommandReceiptId(ctx.ids.nextUuid(), "receipt_id");

        await consumeStepUpProofFromBody({
          ctx,
          auth,
          installation: inst,
          body,
          headerMap,
          action: targetAction,
          scopeKind: "tenant",
          tenantId,
          projectId: null,
          targetResourceId: tenantId,
          targetVersion: expectedVersion,
          receiptId
        });

        const shapeSha = hashCanonicalJson({
          op: targetAction,
          tenant_id: tenantId,
          expected_version: expectedVersion.toString(10)
        }).sha256;

        const receipt = await ctx.pgAdapter.withTransaction(ctx.pgAdapter.configuredRole, async (tx) => {
          const existing = await checkCommandReceiptIdempotency(tx, {
            scopeKind: "tenant",
            tenantId,
            projectId: null,
            actorPrincipalId: auth.principal.principalId,
            commandFamily: targetAction,
            idempotencyKey,
            submittedShapeSha256: shapeSha
          });
          if (existing !== null) {
            return existing;
          }

          const upd = await tx.query<Record<string, unknown>>(
            `UPDATE rq.tenants
                SET state = $3::text,
                    governance_version = governance_version + 1,
                    updated_at = $4::timestamptz,
                    version = version + 1
              WHERE id = $1::uuid AND version = $2::bigint
              RETURNING version`,
            [tenantId, expectedVersion.toString(10), nextState, now]
          );
          if (upd.rows[0] === undefined) {
            throw new ConflictDomainError({
              code: "VERSION_CONFLICT",
              message: `Tenant ${tenantId} version mismatch`
            });
          }
          const newVersion = parseInt64BigInt(upd.rows[0]["version"], "version");
          return insertCommandReceiptAndAudit(tx, {
            receiptId,
            scopeKind: "tenant",
            tenantId,
            projectId: null,
            actorPrincipalId: auth.principal.principalId,
            commandFamily: targetAction,
            idempotencyKey,
            submittedShapeSha256: shapeSha,
            resourceKind: "tenant",
            resourceId: tenantId,
            acceptedVersion: newVersion,
            priorVersion: expectedVersion,
            safeFacts: { next_state: nextState },
            now
          });
        });

        return sendSuccessEnvelope(
          reply,
          200,
          { receipt, tenant_id: tenantId, state: nextState },
          { requestId: request.id, observedAt: now }
        );
      } finally {
        auth.destroySecrets();
      }
    });
  }

  // Platform Role Assignments
  app.get<{ Querystring: Record<string, unknown> }>(
    "/api/v1/platform/role-assignments",
    async (request, reply) => {
      const inst = await ctx.pgAdapter.withTransaction(
        ctx.pgAdapter.configuredRole,
        (tx) => readInstallationSnapshot(ctx, tx),
        { readOnly: true }
      );
      const { auth } = await authenticateHumanRead(ctx, request, inst);
      try {
        await authorizeAction(ctx, auth, "platform.health.read", { installation: inst });
        const { limit } = parseCursorQueryParams(request.query);
        const rows = await ctx.pgAdapter.withTransaction(
          ctx.pgAdapter.configuredRole,
          async (tx) => {
            const res = await tx.query<Record<string, unknown>>(
              `SELECT pra.id, pra.principal_id, COALESCE(h.display_name, pra.principal_id::text) AS display_name,
                      pra.role, pra.state, pra.governance_version, pra.created_at, pra.version
                 FROM rq.platform_role_assignments pra
                 LEFT JOIN rq.humans h ON h.principal_id = pra.principal_id
                ORDER BY pra.created_at DESC
                LIMIT $1::integer`,
              [limit]
            );
            return res.rows;
          },
          { readOnly: true }
        );
        const items = rows.map((r) => ({
          assignment_id: String(r["id"]),
          principal_id: String(r["principal_id"]),
          display_name: String(r["display_name"]),
          role: String(r["role"]),
          state: String(r["state"]),
          governance_version: String(r["governance_version"]),
          created_at: formatPgTimestamp(r["created_at"]),
          version: String(r["version"])
        }));
        return sendSuccessEnvelope(
          reply,
          200,
          { items, page: { next_cursor: null, limit, has_more: false } },
          { requestId: request.id }
        );
      } finally {
        auth.destroySecrets();
      }
    }
  );

  app.post("/api/v1/platform/role-assignments", async (request, reply) => {
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
      const rawProofId = body["operation_proof_id"] ?? extractStepUpHeader(headerMap);
      await authorizeAction(ctx, auth, "platform.identity_manage", {
        installation: inst,
        stepUpProofId: typeof rawProofId === "string" ? rawProofId : undefined
      });
      const principalId = parsePrincipalId(body["principal_id"], "principal_id");
      const role = parsePlatformRoleStrict(body["role"], "role");
      const receiptId = parseCommandReceiptId(ctx.ids.nextUuid(), "receipt_id");
      await consumeStepUpProofFromBody({
        ctx,
        auth,
        installation: inst,
        body,
        headerMap,
        action: "platform.identity_manage",
        scopeKind: "installation",
        tenantId: null,
        projectId: null,
        targetResourceId: principalId,
        targetVersion: 1n,
        receiptId
      });
      const now = formatUtcTimestamp(ctx.clock.nowInstant());
      const assignmentId = ctx.ids.nextUuid();
      const shapeSha = hashCanonicalJson({
        op: "platform.role_assignments.assign",
        principalId,
        role
      }).sha256;
      const receipt = await ctx.pgAdapter.withTransaction(ctx.pgAdapter.configuredRole, async (tx) => {
        await tx.query(
          `INSERT INTO rq.platform_role_assignments (
             id, principal_id, role, state, governance_version, created_by, created_at, version
           ) VALUES ($1::uuid, $2::uuid, $3::text, 'active', 1, $4::uuid, $5::timestamptz, 1)`,
          [assignmentId, principalId, role, auth.principal.principalId, now]
        );
        return insertCommandReceiptAndAudit(tx, {
          receiptId,
          scopeKind: "installation",
          tenantId: null,
          projectId: null,
          actorPrincipalId: auth.principal.principalId,
          commandFamily: "platform.role_assignments.assign",
          idempotencyKey,
          submittedShapeSha256: shapeSha,
          resourceKind: "platform_role_assignment",
          resourceId: assignmentId,
          acceptedVersion: 1n,
          now
        });
      });
      return sendSuccessEnvelope(
        reply,
        201,
        { receipt, assignment_id: assignmentId },
        { requestId: request.id, observedAt: now }
      );
    } finally {
      auth.destroySecrets();
    }
  });

  app.post<{ Params: { assignment_id: string } }>(
    "/api/v1/platform/role-assignments/:assignment_id/revoke",
    async (request, reply) => {
      const assignmentId = parseCanonicalUuid(request.params.assignment_id, "assignment_id");
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
        const rawProofId = body["operation_proof_id"] ?? extractStepUpHeader(headerMap);
        await authorizeAction(ctx, auth, "platform.identity_manage", {
          installation: inst,
          stepUpProofId: typeof rawProofId === "string" ? rawProofId : undefined
        });
        const expectedVersion = parseInt64BigInt(body["expected_version"] ?? 1, "expected_version");
        const receiptId = parseCommandReceiptId(ctx.ids.nextUuid(), "receipt_id");
        await consumeStepUpProofFromBody({
          ctx,
          auth,
          installation: inst,
          body,
          headerMap,
          action: "platform.identity_manage",
          scopeKind: "installation",
          tenantId: null,
          projectId: null,
          targetResourceId: assignmentId,
          targetVersion: expectedVersion,
          receiptId
        });
        const now = formatUtcTimestamp(ctx.clock.nowInstant());
        const shapeSha = hashCanonicalJson({
          op: "platform.role_assignments.revoke",
          assignmentId
        }).sha256;

        const receipt = await ctx.pgAdapter.withTransaction(ctx.pgAdapter.configuredRole, async (tx) => {
          const curRes = await tx.query<{ role: string; state: string }>(
            `SELECT role, state FROM rq.platform_role_assignments WHERE id = $1::uuid FOR UPDATE`,
            [assignmentId]
          );
          const cur = curRes.rows[0];
          if (cur === undefined) {
            throw new NotFoundDomainError({ code: "NOT_FOUND", message: "Assignment not found" });
          }
          if (cur.role === "platform_admin" && cur.state === "active") {
            const cnt = await ctx.authRepos.humanAuthorization.countActivePlatformAdmins(
              assignmentId as never
            );
            if (cnt < 1) {
              throw new ConflictDomainError({
                code: "STATE_TRANSITION_NOT_ALLOWED",
                message: "Cannot revoke the last active platform administrator"
              });
            }
          }
          const upd = await tx.query<{ version: string }>(
            `UPDATE rq.platform_role_assignments
                SET state = 'revoked', revoked_at = $3::timestamptz, version = version + 1
              WHERE id = $1::uuid AND version = $2::bigint
              RETURNING version`,
            [assignmentId, expectedVersion.toString(10), now]
          );
          if (upd.rows[0] === undefined) {
            throw new ConflictDomainError({ code: "VERSION_CONFLICT", message: "Version mismatch" });
          }
          return insertCommandReceiptAndAudit(tx, {
            receiptId,
            scopeKind: "installation",
            tenantId: null,
            projectId: null,
            actorPrincipalId: auth.principal.principalId,
            commandFamily: "platform.role_assignments.revoke",
            idempotencyKey,
            submittedShapeSha256: shapeSha,
            resourceKind: "platform_role_assignment",
            resourceId: assignmentId,
            acceptedVersion: parseInt64BigInt(upd.rows[0].version, "version"),
            now
          });
        });

        return sendSuccessEnvelope(
          reply,
          200,
          { receipt, assignment_id: assignmentId, state: "revoked" },
          { requestId: request.id, observedAt: now }
        );
      } finally {
        auth.destroySecrets();
      }
    }
  );

  // Recovery references & Platform Audit
  app.get<{ Querystring: Record<string, unknown> }>(
    "/api/v1/platform/recovery-references",
    async (request, reply) => {
      const inst = await ctx.pgAdapter.withTransaction(
        ctx.pgAdapter.configuredRole,
        (tx) => readInstallationSnapshot(ctx, tx),
        { readOnly: true }
      );
      const { auth } = await authenticateHumanRead(ctx, request, inst);
      try {
        await authorizeAction(ctx, auth, "platform.health.read", { installation: inst });
        const { limit } = parseCursorQueryParams(request.query);
        const rows = await ctx.pgAdapter.withTransaction(
          ctx.pgAdapter.configuredRole,
          async (tx) => {
            const res = await tx.query<Record<string, unknown>>(
              `SELECT target_id, target_kind, action, recorded_at, safe_facts
                 FROM rq.audit_events
                WHERE target_kind LIKE '%recovery%' OR action LIKE 'recovery%'
                ORDER BY recorded_at DESC
                LIMIT $1::integer`,
              [limit]
            );
            return res.rows;
          },
          { readOnly: true }
        );
        const items = rows.map((r) => {
          const facts = (r["safe_facts"] ?? {}) as Record<string, unknown>;
          return {
            incident_id: String(r["target_id"]),
            scope_kind: typeof facts["scope_kind"] === "string" ? facts["scope_kind"] : "installation",
            state: typeof facts["state"] === "string" ? facts["state"] : "recorded",
            summary_code: String(r["action"]),
            created_at: formatPgTimestamp(r["recorded_at"])
          };
        });
        return sendSuccessEnvelope(
          reply,
          200,
          { items, page: { next_cursor: null, limit, has_more: false } },
          { requestId: request.id }
        );
      } finally {
        auth.destroySecrets();
      }
    }
  );

  app.get<{ Querystring: Record<string, unknown> }>(
    "/api/v1/platform/audit",
    async (request, reply) => {
      const inst = await ctx.pgAdapter.withTransaction(
        ctx.pgAdapter.configuredRole,
        (tx) => readInstallationSnapshot(ctx, tx),
        { readOnly: true }
      );
      const { auth } = await authenticateHumanRead(ctx, request, inst);
      try {
        await authorizeAction(ctx, auth, "platform.audit.read", { installation: inst });
        const { limit, rawCursor } = parseCursorQueryParams(request.query);
        const actionFilter =
          typeof request.query["action"] === "string" && request.query["action"].trim().length > 0
            ? request.query["action"].trim()
            : null;
        const targetKindFilter =
          typeof request.query["target_kind"] === "string" &&
          request.query["target_kind"].trim().length > 0
            ? request.query["target_kind"].trim()
            : null;
        const cursor = decodeApiCursor(ctx, rawCursor, {
          resource: "audit",
          tenantId: null,
          projectId: null,
          order: "created_at_desc_id_desc",
          filter: {
            ...(actionFilter !== null ? { action: actionFilter } : {}),
            ...(targetKindFilter !== null ? { target_kind: targetKindFilter } : {})
          }
        });
        const boundaryId = cursor?.boundary.id ?? null;

        const rows = await ctx.pgAdapter.withTransaction(
          ctx.pgAdapter.configuredRole,
          async (tx) => {
            const res = await tx.query<Record<string, unknown>>(
              `SELECT id, tenant_id, project_id, actor_kind, actor_reference, operator_reference,
                      action, target_kind, target_id, prior_version, resulting_version,
                      candidate_sha256, command_receipt_id, recorded_at, safe_facts
                 FROM rq.audit_events
                WHERE ($1::text IS NULL OR action = $1::text)
                  AND ($2::text IS NULL OR target_kind = $2::text)
                  AND ($3::uuid IS NULL OR id < $3::uuid)
                ORDER BY recorded_at DESC, id DESC
                LIMIT $4::integer`,
              [actionFilter, targetKindFilter, boundaryId, limit + 1]
            );
            return res.rows;
          },
          { readOnly: true }
        );
        const hasMore = rows.length > limit;
        const pageRows = rows.slice(0, limit);
        const items = pageRows.map((r) => ({
          audit_id: String(r["id"]),
          tenant_id: r["tenant_id"] ?? null,
          project_id: r["project_id"] ?? null,
          actor_kind: String(r["actor_kind"]),
          actor_reference: r["actor_reference"] ?? null,
          operator_reference: r["operator_reference"] ?? null,
          action: String(r["action"]),
          target_kind: String(r["target_kind"]),
          target_id: String(r["target_id"]),
          prior_version: asOptionalText(r["prior_version"]),
          resulting_version: asOptionalText(r["resulting_version"]),
          candidate_sha256: r["candidate_sha256"] !== null ? toHex(r["candidate_sha256"]) : null,
          command_receipt_id: r["command_receipt_id"] ?? null,
          recorded_at: formatPgTimestamp(r["recorded_at"]),
          safe_facts: r["safe_facts"] ?? {}
        }));
        const last = pageRows[pageRows.length - 1];
        const next_cursor =
          hasMore && last !== undefined
            ? encodeApiCursor(ctx, {
                resource: "audit",
                tenantId: null,
                projectId: null,
                order: "created_at_desc_id_desc",
                filter: {
                  ...(actionFilter !== null ? { action: actionFilter } : {}),
                  ...(targetKindFilter !== null ? { target_kind: targetKindFilter } : {})
                },
                boundary: {
                  id: parseCanonicalUuid(last["id"], "id"),
                  timestamp: formatPgTimestamp(last["recorded_at"])
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

  // Tenant Projects
  app.get<{ Params: { tenant_id: string } }>(
    "/api/v1/tenants/:tenant_id/projects",
    async (request, reply) => {
      const tenantId = parseTenantId(request.params.tenant_id, "tenant_id");
      const inst = await ctx.pgAdapter.withTransaction(
        ctx.pgAdapter.configuredRole,
        (tx) => readInstallationSnapshot(ctx, tx),
        { readOnly: true }
      );
      const { auth } = await authenticateHumanRead(ctx, request, inst);
      try {
        const hasTenantAccess = await ctx.pgAdapter.withTransaction(
          ctx.pgAdapter.configuredRole,
          async (tx) => {
            const res = await tx.query<{ ok: boolean }>(
              `SELECT (
                 EXISTS (
                   SELECT 1 FROM rq.platform_role_assignments
                    WHERE principal_id = $1::uuid AND state = 'active'
                 )
                 OR EXISTS (
                   SELECT 1 FROM rq.tenant_memberships
                    WHERE principal_id = $1::uuid AND tenant_id = $2::uuid AND state = 'active'
                 )
                 OR EXISTS (
                   SELECT 1 FROM rq.project_memberships
                    WHERE principal_id = $1::uuid AND tenant_id = $2::uuid AND state = 'active'
                 )
               ) AS ok`,
              [auth.principal.principalId, tenantId]
            );
            return res.rows[0]?.ok === true;
          },
          { readOnly: true }
        );
        if (!hasTenantAccess) {
          throw new NotFoundDomainError({ code: "NOT_FOUND", message: "Tenant not found" });
        }
        const rows = await ctx.pgAdapter.withTransaction(
          ctx.pgAdapter.configuredRole,
          async (tx) => {
            const res = await tx.query<Record<string, unknown>>(
              `SELECT id, tenant_id, name, state, topology_version, next_event_sequence,
                      governance_version, created_at, version
                 FROM rq.projects
                WHERE tenant_id = $1::uuid
                ORDER BY created_at DESC`,
              [tenantId]
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
              project_id: String(r["id"]),
              tenant_id: String(r["tenant_id"]),
              name: String(r["name"]),
              state: String(r["state"]),
              topology_version: String(r["topology_version"]),
              next_event_sequence: String(r["next_event_sequence"]),
              governance_version: String(r["governance_version"]),
              version: String(r["version"]),
              created_at: formatPgTimestamp(r["created_at"])
            })),
            page: { next_cursor: null, limit: 50, has_more: false }
          },
          { requestId: request.id }
        );
      } finally {
        auth.destroySecrets();
      }
    }
  );

  app.post<{ Params: { tenant_id: string } }>(
    "/api/v1/tenants/:tenant_id/projects",
    async (request, reply) => {
      const tenantId = parseTenantId(request.params.tenant_id, "tenant_id");
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
        const rawProofId = body["operation_proof_id"] ?? extractStepUpHeader(headerMap);
        await authorizeAction(ctx, auth, "projects.create", {
          installation: inst,
          tenantId,
          stepUpProofId: typeof rawProofId === "string" ? rawProofId : undefined
        });
        if (body["schema_version"] !== 1) {
          throw new ValidationDomainError({
            code: "UNSUPPORTED_SCHEMA_VERSION",
            message: "createProject requires schema_version: 1"
          });
        }
        const name = asText(body["name"]).trim();
        if (name.length === 0 || name.length > 128) {
          throw new ValidationDomainError({
            code: "INVALID_VALUE",
            message: "Project name must be 1..128 characters"
          });
        }
        const now = formatUtcTimestamp(ctx.clock.nowInstant());
        const projectId = parseProjectId(body["project_id"] ?? ctx.ids.nextUuid(), "project_id");
        const receiptId = parseCommandReceiptId(ctx.ids.nextUuid(), "receipt_id");
        const stepUpTargetId = parseCanonicalUuid(
          body["target_resource_id"] ?? body["project_id"] ?? tenantId,
          "target_resource_id"
        );
        await consumeStepUpProofFromBody({
          ctx,
          auth,
          installation: inst,
          body,
          headerMap,
          action: "projects.create",
          scopeKind: "tenant",
          tenantId,
          projectId: null,
          targetResourceId: stepUpTargetId,
          targetVersion: 1n,
          receiptId
        });
        const shapeSha = hashCanonicalJson({ op: "projects.create", tenant_id: tenantId, name }).sha256;

        const out = await ctx.pgAdapter.withTransaction(ctx.pgAdapter.configuredRole, async (tx) => {
          const existing = await checkCommandReceiptIdempotency(tx, {
            scopeKind: "tenant",
            tenantId,
            projectId: null,
            actorPrincipalId: auth.principal.principalId,
            commandFamily: "projects.create",
            idempotencyKey,
            submittedShapeSha256: shapeSha
          });
          if (existing !== null) {
            return { existing: true, receipt: existing, projectId: existing.resource_id };
          }
          await tx.query(
            `INSERT INTO rq.projects (
               id, tenant_id, name, state, topology_version, next_event_sequence,
               governance_version, created_at, updated_at, version
             ) VALUES ($1::uuid, $2::uuid, $3::text, 'active', 1, 1, 1, $4::timestamptz, $4::timestamptz, 1)`,
            [projectId, tenantId, name, now]
          );
          await seedProjectDefaults(tx, tenantId, projectId, now);
          await tx.query(
            `INSERT INTO rq.project_memberships (
               id, tenant_id, project_id, principal_id, role, state, authority_version, version
             ) VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid, 'project_admin', 'active', 1, 1)
             ON CONFLICT DO NOTHING`,
            [ctx.ids.nextUuid(), tenantId, projectId, auth.principal.principalId]
          );
          const receipt = await insertCommandReceiptAndAudit(tx, {
            receiptId,
            scopeKind: "tenant",
            tenantId,
            projectId: null,
            actorPrincipalId: auth.principal.principalId,
            commandFamily: "projects.create",
            idempotencyKey,
            submittedShapeSha256: shapeSha,
            resourceKind: "project",
            resourceId: projectId,
            acceptedVersion: 1n,
            safeFacts: { name },
            now
          });
          return { existing: false, receipt, projectId };
        });

        return sendSuccessEnvelope(
          reply,
          out.existing ? 200 : 201,
          { receipt: out.receipt, tenant_id: tenantId, project_id: out.projectId, name, state: "active" },
          { requestId: request.id, observedAt: now }
        );
      } finally {
        auth.destroySecrets();
      }
    }
  );

  // Project Overview & Delivery Summary
  app.get<{ Params: { tenant_id: string; project_id: string }; Querystring: Record<string, unknown> }>(
    "/api/v1/tenants/:tenant_id/projects/:project_id/overview",
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
        const decision = await authorizeAction(ctx, auth, "events.read_safe", {
          installation: inst,
          tenantId,
          projectId
        });
        const windowLabel =
          typeof request.query["window"] === "string" ? request.query["window"] : "last_24h";
        const now = formatUtcTimestamp(ctx.clock.nowInstant());

        const data = await ctx.pgAdapter.withTransaction(
          ctx.pgAdapter.configuredRole,
          async (tx) => {
            const pRes = await tx.query<Record<string, unknown>>(
              `SELECT id, name, state, version, topology_version, active_ordering_cutover_plan_id
                 FROM rq.projects
                WHERE id = $1::uuid AND tenant_id = $2::uuid`,
              [projectId, tenantId]
            );
            const proj = pRes.rows[0];
            if (proj === undefined) {
              throw new NotFoundDomainError({ code: "NOT_FOUND", message: "Project not found" });
            }

            const countsRes = await tx.query<Record<string, unknown>>(
              `SELECT
                 (SELECT count(*) FROM rq.v_safe_events WHERE tenant_id = $1::uuid AND project_id = $2::uuid)::text AS accepted_events,
                 (SELECT count(*) FROM rq.outbox_events WHERE tenant_id = $1::uuid AND project_id = $2::uuid AND state = 'published')::text AS published_outbox,
                 (SELECT count(*) FROM rq.outbox_events WHERE tenant_id = $1::uuid AND project_id = $2::uuid AND state = 'blocked')::text AS blocked_outbox,
                 (SELECT count(*) FROM rq.v_safe_deliveries WHERE tenant_id = $1::uuid AND project_id = $2::uuid AND state IN ('pending','ready','sending','retry_wait'))::text AS inflight_deliveries,
                 (SELECT count(*) FROM rq.v_safe_deliveries WHERE tenant_id = $1::uuid AND project_id = $2::uuid AND state = 'ready')::text AS ready_count,
                 (SELECT count(*) FROM rq.v_safe_deliveries WHERE tenant_id = $1::uuid AND project_id = $2::uuid AND state = 'retry_wait')::text AS retry_wait_count,
                 (SELECT count(*) FROM rq.v_safe_deliveries WHERE tenant_id = $1::uuid AND project_id = $2::uuid AND state = 'sending')::text AS sending_count,
                 (SELECT count(*) FROM rq.v_safe_deliveries WHERE tenant_id = $1::uuid AND project_id = $2::uuid AND state = 'acknowledged')::text AS ack_count,
                 (SELECT count(*) FROM rq.v_safe_deliveries WHERE tenant_id = $1::uuid AND project_id = $2::uuid AND state = 'dead_letter')::text AS dead_letter_count,
                 (SELECT count(*) FROM rq.receiver_receipt_observations WHERE tenant_id = $1::uuid AND project_id = $2::uuid AND state = 'verified_supported')::text AS receipt_count,
                 (SELECT count(*) FROM rq.endpoint_circuits WHERE tenant_id = $1::uuid AND project_id = $2::uuid AND state = 'open')::integer AS open_circuits,
                 (SELECT count(*) FROM rq.endpoint_circuits WHERE tenant_id = $1::uuid AND project_id = $2::uuid AND state = 'half_open')::integer AS half_open_circuits,
                 (SELECT count(*) FROM rq.endpoints WHERE tenant_id = $1::uuid AND project_id = $2::uuid AND state = 'quarantined')::integer AS quarantined_endpoints,
                 (SELECT active_attempt_slots FROM rq.project_capacity WHERE project_id = $2::uuid) AS active_slots,
                 (SELECT max_active_attempt_slots FROM rq.project_capacity WHERE project_id = $2::uuid) AS max_slots`,
              [tenantId, projectId]
            );
            const c = countsRes.rows[0] ?? {};
            const state = String(proj["state"]);

            return {
              project_id: projectId,
              project_name: String(proj["name"]),
              project_state: state,
              project_version: String(proj["version"]),
              topology_version: String(proj["topology_version"]),
              active_cutover_plan_id: proj["active_ordering_cutover_plan_id"] ?? null,
              window_label: windowLabel,
              observed_at: now,
              stages: [
                {
                  stage: "accepted",
                  label: "Accepted Events",
                  count: asText(c["accepted_events"], "0"),
                  availability: "current",
                  unit: "events",
                  population: "accepted_events",
                  window_label: windowLabel,
                  observed_at: now,
                  note: "Committed source events admitted into authority log"
                },
                {
                  stage: "published_to_broker",
                  label: "Published Notifications",
                  count: asText(c["published_outbox"], "0"),
                  availability: "current",
                  unit: "notifications",
                  population: "all_deliveries",
                  window_label: windowLabel,
                  observed_at: now,
                  note: "Relay outbox rows acknowledged by JetStream"
                },
                {
                  stage: "in_flight",
                  label: "In-Flight Deliveries",
                  count: asText(c["inflight_deliveries"], "0"),
                  availability: "current",
                  unit: "delivery_generations",
                  population: "all_deliveries",
                  window_label: windowLabel,
                  observed_at: now,
                  note: "Pending, ready, sending, and retry-wait deliveries"
                },
                {
                  stage: "http_acknowledged",
                  label: "HTTP Acknowledged",
                  count: asText(c["ack_count"], "0"),
                  availability: "current",
                  unit: "delivery_generations",
                  population: "all_deliveries",
                  window_label: windowLabel,
                  observed_at: now,
                  note: "Deliveries acknowledged by receiver HTTP status"
                },
                {
                  stage: "receiver_verified",
                  label: "Receiver Receipts Verified",
                  count: asText(c["receipt_count"], "0"),
                  availability: "current",
                  unit: "receipt_observations",
                  population: "all_deliveries",
                  window_label: windowLabel,
                  observed_at: now,
                  note: "Cryptographically verified receiver receipts"
                },
                {
                  stage: "dead_lettered",
                  label: "Dead-Lettered",
                  count: asText(c["dead_letter_count"], "0"),
                  availability: "current",
                  unit: "delivery_generations",
                  population: "all_deliveries",
                  window_label: windowLabel,
                  observed_at: now,
                  note: "Deliveries exhausted or rejected permanently"
                }
              ],
              outbox_pressure: {
                oldest_pending_age_seconds: null,
                blocked_outbox_count: asText(c["blocked_outbox"], "0"),
                blocked_fanout_predecessor_sequence: null,
                blocked_fanout_reason_code: null
              },
              delivery_pressure: {
                ready_count: asText(c["ready_count"], "0"),
                retry_wait_count: asText(c["retry_wait_count"], "0"),
                sending_count: asText(c["sending_count"], "0"),
                unknown_outcome_count: "0",
                open_circuits_count: Number(c["open_circuits"] ?? 0),
                half_open_circuits_count: Number(c["half_open_circuits"] ?? 0),
                quarantined_endpoints_count: Number(c["quarantined_endpoints"] ?? 0)
              },
              budgets: {
                active_send_slots: Number(c["active_slots"] ?? 0),
                approved_send_slots: Number(c["max_slots"] ?? 16),
                held_rate_reservations: 0,
                rate_requests_per_second: 20,
                rate_burst: 40,
                draining_policy_count: 0
              },
              capabilities: buildCapabilitiesForActions(
                ctx,
                decision,
                "project",
                projectId,
                ["projects.pause_admission", "projects.resume_admission", "projects.retire"],
                {
                  expectedVersion: BigInt(String(proj["version"])),
                  stateAllowed: (act) => ({
                    allowed:
                      (act === "projects.pause_admission" && state === "active") ||
                      (act === "projects.resume_admission" && state === "admission_paused") ||
                      (act === "projects.retire" && state !== "retired")
                  })
                }
              )
            };
          },
          { readOnly: true }
        );

        return sendSuccessEnvelope(reply, 200, data, { requestId: request.id, observedAt: now });
      } finally {
        auth.destroySecrets();
      }
    }
  );

  app.get<{ Params: { tenant_id: string; project_id: string }; Querystring: Record<string, unknown> }>(
    "/api/v1/tenants/:tenant_id/projects/:project_id/delivery-summary",
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
        const totals = await ctx.pgAdapter.withTransaction(
          ctx.pgAdapter.configuredRole,
          async (tx) => {
            const res = await tx.query<Record<string, unknown>>(
              `SELECT state, count(*)::text AS cnt
                 FROM rq.v_safe_deliveries
                WHERE tenant_id = $1::uuid AND project_id = $2::uuid
                GROUP BY state`,
              [tenantId, projectId]
            );
            return res.rows;
          },
          { readOnly: true }
        );
        const byState: Record<string, string> = {};
        let total = 0n;
        for (const r of totals) {
          const st = String(r["state"]);
          const c = String(r["cnt"]);
          byState[st] = c;
          total += BigInt(c);
        }
        return sendSuccessEnvelope(
          reply,
          200,
          {
            unit: "delivery_generation",
            population:
              typeof request.query["population"] === "string"
                ? request.query["population"]
                : "all_deliveries",
            total_deliveries: total.toString(10),
            by_state: byState
          },
          { requestId: request.id }
        );
      } finally {
        auth.destroySecrets();
      }
    }
  );

  // Project pause-admission / resume-admission / retire / limit-changes
  for (const [subpath, action, nextState] of [
    ["pause-admission", "projects.pause_admission", "admission_paused"],
    ["resume-admission", "projects.resume_admission", "active"],
    ["retire", "projects.retire", "retired"]
  ] as const) {
    app.post<{ Params: { tenant_id: string; project_id: string } }>(
      `/api/v1/tenants/:tenant_id/projects/:project_id/${subpath}`,
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
          const rawProofId = body["operation_proof_id"] ?? extractStepUpHeader(headerMap);
          await authorizeAction(ctx, auth, action, {
            installation: inst,
            tenantId,
            projectId,
            stepUpProofId: typeof rawProofId === "string" ? rawProofId : undefined
          });
          const expectedVersion = parseInt64BigInt(body["expected_version"] ?? 1, "expected_version");
          const receiptId = parseCommandReceiptId(ctx.ids.nextUuid(), "receipt_id");
          await consumeStepUpProofFromBody({
            ctx,
            auth,
            installation: inst,
            body,
            headerMap,
            action,
            scopeKind: "project",
            tenantId,
            projectId,
            targetResourceId: projectId,
            targetVersion: expectedVersion,
            receiptId
          });
          const now = formatUtcTimestamp(ctx.clock.nowInstant());
          const shapeSha = hashCanonicalJson({
            op: action,
            projectId,
            expectedVersion: expectedVersion.toString(10)
          }).sha256;

          const receipt = await ctx.pgAdapter.withTransaction(ctx.pgAdapter.configuredRole, async (tx) => {
            const existing = await checkCommandReceiptIdempotency(tx, {
              scopeKind: "project",
              tenantId,
              projectId,
              actorPrincipalId: auth.principal.principalId,
              commandFamily: action,
              idempotencyKey,
              submittedShapeSha256: shapeSha
            });
            if (existing !== null) {
              return existing;
            }
            const upd = await tx.query<{ version: string }>(
              `UPDATE rq.projects
                  SET state = $3::text,
                      governance_version = governance_version + 1,
                      updated_at = $4::timestamptz,
                      version = version + 1
                WHERE id = $1::uuid AND tenant_id = $5::uuid AND version = $2::bigint
                RETURNING version`,
              [projectId, expectedVersion.toString(10), nextState, now, tenantId]
            );
            if (upd.rows[0] === undefined) {
              throw new ConflictDomainError({ code: "VERSION_CONFLICT", message: "Project version mismatch" });
            }
            return insertCommandReceiptAndAudit(tx, {
              receiptId,
              scopeKind: "project",
              tenantId,
              projectId,
              actorPrincipalId: auth.principal.principalId,
              commandFamily: action,
              idempotencyKey,
              submittedShapeSha256: shapeSha,
              resourceKind: "project",
              resourceId: projectId,
              acceptedVersion: parseInt64BigInt(upd.rows[0].version, "version"),
              priorVersion: expectedVersion,
              now
            });
          });
          return sendSuccessEnvelope(
            reply,
            200,
            { receipt, project_id: projectId, state: nextState },
            { requestId: request.id, observedAt: now }
          );
        } finally {
          auth.destroySecrets();
        }
      }
    );
  }

  app.post<{ Params: { tenant_id: string; project_id: string } }>(
    "/api/v1/tenants/:tenant_id/projects/:project_id/limit-changes",
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
        const rawProofId = body["operation_proof_id"] ?? extractStepUpHeader(headerMap);
        await authorizeAction(ctx, auth, "dispatch_policy_changes.apply", {
          installation: inst,
          tenantId,
          projectId,
          stepUpProofId: typeof rawProofId === "string" ? rawProofId : undefined
        });
        const maxActiveSlots =
          typeof body["max_active_attempt_slots"] === "number"
            ? body["max_active_attempt_slots"]
            : undefined;
        const maxPendingEvents =
          body["max_pending_events"] !== undefined
            ? parseInt64BigInt(body["max_pending_events"], "max_pending_events")
            : undefined;
        const expectedVersion = parseInt64BigInt(body["expected_version"] ?? 1, "expected_version");
        const now = formatUtcTimestamp(ctx.clock.nowInstant());
        const receiptId = parseCommandReceiptId(ctx.ids.nextUuid(), "receipt_id");
        await consumeStepUpProofFromBody({
          ctx,
          auth,
          installation: inst,
          body,
          headerMap,
          action: "dispatch_policy_changes.apply",
          scopeKind: "project",
          tenantId,
          projectId,
          targetResourceId: projectId,
          targetVersion: expectedVersion,
          receiptId
        });
        const shapeSha = hashCanonicalJson(
          stripUndefinedJson({
            op: "limit-changes",
            projectId,
            maxActiveSlots,
            maxPendingEvents: maxPendingEvents !== undefined ? maxPendingEvents.toString(10) : undefined
          })
        ).sha256;
        const receipt = await ctx.pgAdapter.withTransaction(ctx.pgAdapter.configuredRole, async (tx) => {
          await tx.query(
            `UPDATE rq.project_capacity
                SET max_active_attempt_slots = COALESCE($2::integer, max_active_attempt_slots),
                    max_pending_events = COALESCE($3::bigint, max_pending_events),
                    updated_at = $4::timestamptz,
                    version = version + 1
              WHERE project_id = $1::uuid AND tenant_id = $5::uuid`,
            [
              projectId,
              maxActiveSlots ?? null,
              maxPendingEvents !== undefined ? maxPendingEvents.toString(10) : null,
              now,
              tenantId
            ]
          );
          return insertCommandReceiptAndAudit(tx, {
            receiptId,
            scopeKind: "project",
            tenantId,
            projectId,
            actorPrincipalId: auth.principal.principalId,
            commandFamily: "projects.limit_changes",
            idempotencyKey,
            submittedShapeSha256: shapeSha,
            resourceKind: "project",
            resourceId: projectId,
            acceptedVersion: 1n,
            now
          });
        });
        return sendSuccessEnvelope(
          reply,
          200,
          { receipt, project_id: projectId },
          { requestId: request.id, observedAt: now }
        );
      } finally {
        auth.destroySecrets();
      }
    }
  );

  // Lifecycle operations
  app.get<{ Params: { tenant_id: string; operation_id: string } }>(
    "/api/v1/tenants/:tenant_id/lifecycle-operations/:operation_id",
    async (request, reply) => {
      const tenantId = parseTenantId(request.params.tenant_id, "tenant_id");
      const operationId = parseCanonicalUuid(request.params.operation_id, "operation_id");
      const inst = await ctx.pgAdapter.withTransaction(
        ctx.pgAdapter.configuredRole,
        (tx) => readInstallationSnapshot(ctx, tx),
        { readOnly: true }
      );
      const { auth } = await authenticateHumanRead(ctx, request, inst);
      try {
        await authorizeAction(ctx, auth, "tenant.limits.update", {
          installation: inst,
          tenantId,
          stepUpVerified: true
        }).catch(async () => {
          await authorizeAction(ctx, auth, "platform.health.read", { installation: inst });
        });
        const row = await ctx.pgAdapter.withTransaction(
          ctx.pgAdapter.configuredRole,
          async (tx) => {
            const res = await tx.query<Record<string, unknown>>(
              `SELECT id, tenant_id, project_id, kind, target_version, state, created_at, safe_reason_code, version
                 FROM rq.lifecycle_operations
                WHERE id = $1::uuid AND tenant_id = $2::uuid`,
              [operationId, tenantId]
            );
            return res.rows[0];
          },
          { readOnly: true }
        );
        if (row === undefined) {
          throw new NotFoundDomainError({ code: "NOT_FOUND", message: "Lifecycle operation not found" });
        }
        return sendSuccessEnvelope(reply, 200, row, { requestId: request.id });
      } finally {
        auth.destroySecrets();
      }
    }
  );

  app.get<{ Params: { tenant_id: string; project_id: string; operation_id: string } }>(
    "/api/v1/tenants/:tenant_id/projects/:project_id/lifecycle-operations/:operation_id",
    async (request, reply) => {
      const tenantId = parseTenantId(request.params.tenant_id, "tenant_id");
      const projectId = parseProjectId(request.params.project_id, "project_id");
      const operationId = parseCanonicalUuid(request.params.operation_id, "operation_id");
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
        const row = await ctx.pgAdapter.withTransaction(
          ctx.pgAdapter.configuredRole,
          async (tx) => {
            const res = await tx.query<Record<string, unknown>>(
              `SELECT id, tenant_id, project_id, kind, target_version, state, created_at, safe_reason_code, version
                 FROM rq.lifecycle_operations
                WHERE id = $1::uuid AND tenant_id = $2::uuid AND project_id = $3::uuid`,
              [operationId, tenantId, projectId]
            );
            return res.rows[0];
          },
          { readOnly: true }
        );
        if (row === undefined) {
          throw new NotFoundDomainError({ code: "NOT_FOUND", message: "Lifecycle operation not found" });
        }
        return sendSuccessEnvelope(reply, 200, row, { requestId: request.id });
      } finally {
        auth.destroySecrets();
      }
    }
  );

  // Project audit
  app.get<{ Params: { tenant_id: string; project_id: string }; Querystring: Record<string, unknown> }>(
    "/api/v1/tenants/:tenant_id/projects/:project_id/audit",
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
        await authorizeAction(ctx, auth, "audit.read_safe", {
          installation: inst,
          tenantId,
          projectId
        });
        const { limit } = parseCursorQueryParams(request.query);
        const actionFilter =
          typeof request.query["action"] === "string" && request.query["action"].trim().length > 0
            ? request.query["action"].trim()
            : null;
        const targetKindFilter =
          typeof request.query["target_kind"] === "string" &&
          request.query["target_kind"].trim().length > 0
            ? request.query["target_kind"].trim()
            : null;
        const rows = await ctx.pgAdapter.withTransaction(
          ctx.pgAdapter.configuredRole,
          async (tx) => {
            const res = await tx.query<Record<string, unknown>>(
              `SELECT id, tenant_id, project_id, actor_kind, actor_reference, operator_reference,
                      action, target_kind, target_id, prior_version, resulting_version,
                      candidate_sha256, command_receipt_id, recorded_at, safe_facts
                 FROM rq.audit_events
                WHERE tenant_id = $1::uuid AND project_id = $2::uuid
                  AND ($3::text IS NULL OR action = $3::text)
                  AND ($4::text IS NULL OR target_kind = $4::text)
                ORDER BY recorded_at DESC, id DESC
                LIMIT $5::integer`,
              [tenantId, projectId, actionFilter, targetKindFilter, limit]
            );
            return res.rows;
          },
          { readOnly: true }
        );
        const items = rows.map((r) => ({
          audit_id: String(r["id"]),
          tenant_id: r["tenant_id"] ?? null,
          project_id: r["project_id"] ?? null,
          actor_kind: String(r["actor_kind"]),
          actor_reference: r["actor_reference"] ?? null,
          operator_reference: r["operator_reference"] ?? null,
          action: String(r["action"]),
          target_kind: String(r["target_kind"]),
          target_id: String(r["target_id"]),
          prior_version: asOptionalText(r["prior_version"]),
          resulting_version: asOptionalText(r["resulting_version"]),
          candidate_sha256: r["candidate_sha256"] !== null ? toHex(r["candidate_sha256"]) : null,
          command_receipt_id: r["command_receipt_id"] ?? null,
          recorded_at: formatPgTimestamp(r["recorded_at"]),
          safe_facts: r["safe_facts"] ?? {}
        }));
        return sendSuccessEnvelope(
          reply,
          200,
          { items, page: { next_cursor: null, limit, has_more: false } },
          { requestId: request.id }
        );
      } finally {
        auth.destroySecrets();
      }
    }
  );
  void AuthorizationDomainError;
}
