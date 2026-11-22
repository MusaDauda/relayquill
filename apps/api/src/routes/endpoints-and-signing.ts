import crypto from "node:crypto";
import { hashCanonicalJson } from "@relayquill/contracts";
import {
  ConflictDomainError,
  type EndpointState,
  NotFoundDomainError,
  type Sha256Hex,
  ValidationDomainError,
  formatUtcTimestamp,
  parseCanonicalUuid,
  parseCommandReceiptId,
  parseEndpointId,
  parseInt64BigInt,
  parseProjectId,
  parseSha256Hex,
  parseTenantId
} from "@relayquill/domain";
import { requestCircuitProbe } from "@relayquill/postgres";
import { type FastifyInstance } from "fastify";
import {
  type ApiContext,
  authenticateHumanMutation,
  authenticateHumanRead,
  authorizeAction,
  buildCapabilitiesForActions,
  checkCommandReceiptIdempotency,
  consumeStepUpProofFromBody,
  deterministicUuid,
  extractStepUpHeader,
  formatPgTimestamp,
  insertCommandReceiptAndAudit,
  parseCursorQueryParams,
  readInstallationSnapshot
} from "../context.js";
import { sendSuccessEnvelope } from "../http/errors.js";
import { asOptionalText, asText } from "../repos/sql-helpers.js";

function toHex(val: unknown): Sha256Hex {
  if (Buffer.isBuffer(val)) {
    return val.toString("hex") as Sha256Hex;
  }
  if (val instanceof Uint8Array) {
    return Buffer.from(val).toString("hex") as Sha256Hex;
  }
  return asText(val).replace(/^\\x/, "") as Sha256Hex;
}

function parseDestinationUrlParts(rawUrl: unknown): {
  readonly destinationUrl: string;
  readonly normalizedHostname: string;
  readonly port: number;
  readonly pathAndQuerySha256: Buffer;
} {
  if (typeof rawUrl !== "string" || rawUrl.trim().length === 0) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: "destination_url is required",
      fieldErrors: [{ path: "body.destination_url", code: "INVALID_VALUE" }]
    });
  }
  let parsed: URL;
  try {
    parsed = new URL(rawUrl.trim());
  } catch {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: "destination_url must be a valid absolute URL",
      fieldErrors: [{ path: "body.destination_url", code: "INVALID_VALUE" }]
    });
  }
  if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: "destination_url must use https or http scheme",
      fieldErrors: [{ path: "body.destination_url", code: "INVALID_VALUE" }]
    });
  }
  const normalizedHostname = parsed.hostname.toLowerCase();
  const port =
    parsed.port.length > 0
      ? Number.parseInt(parsed.port, 10)
      : parsed.protocol === "https:"
        ? 443
        : 80;
  const pathAndQuery = `${parsed.pathname}${parsed.search}`;
  const pathAndQuerySha256 = crypto.createHash("sha256").update(pathAndQuery, "utf8").digest();
  return {
    destinationUrl: parsed.toString(),
    normalizedHostname,
    port,
    pathAndQuerySha256
  };
}

export function registerEndpointAndSigningRoutes(app: FastifyInstance, ctx: ApiContext): void {
  const base = "/api/v1/tenants/:tenant_id/projects/:project_id";

  // List Endpoints
  app.get<{ Params: { tenant_id: string; project_id: string }; Querystring: Record<string, unknown> }>(
    `${base}/endpoints`,
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
        const decision = await authorizeAction(ctx, auth, "endpoints.read_safe", {
          installation: inst,
          tenantId,
          projectId
        });
        const { limit } = parseCursorQueryParams(request.query);
        const stateFilter = asOptionalText(request.query["state"]);
        const rows = await ctx.pgAdapter.withTransaction(
          ctx.pgAdapter.configuredRole,
          async (tx) => {
            const res = await tx.query<Record<string, unknown>>(
              `SELECT e.id, e.name, e.state, COALESCE(e.current_version, 1) AS current_version,
                      e.security_epoch, e.current_signing_policy_version, e.version,
                      ev.destination_url, ev.normalized_hostname, ev.configuration_sha256,
                      ev.url_policy_version, ev.network_policy_version,
                      ev.request_profile_version, ev.response_profile_version,
                      (SELECT evi.state FROM rq.endpoint_verification_intents evi
                        WHERE evi.endpoint_id = e.id AND evi.project_id = e.project_id
                        ORDER BY evi.created_at DESC LIMIT 1) AS verification_state,
                      (SELECT sv.receiver_contract_id FROM rq.subscription_versions sv
                        JOIN rq.subscriptions s ON s.id = sv.subscription_id AND s.current_version = sv.subscription_version
                        WHERE sv.endpoint_id = e.id AND sv.project_id = e.project_id
                        ORDER BY sv.created_at DESC LIMIT 1) AS active_receiver_contract_id,
                      (SELECT sv.receiver_contract_version FROM rq.subscription_versions sv
                        JOIN rq.subscriptions s ON s.id = sv.subscription_id AND s.current_version = sv.subscription_version
                        WHERE sv.endpoint_id = e.id AND sv.project_id = e.project_id
                        ORDER BY sv.created_at DESC LIMIT 1) AS active_receiver_contract_version
                 FROM rq.endpoints e
                 LEFT JOIN rq.endpoint_versions ev
                   ON ev.endpoint_id = e.id
                  AND ev.endpoint_version = COALESCE(e.current_version, 1)
                WHERE e.tenant_id = $1::uuid AND e.project_id = $2::uuid
                  AND ($3::text IS NULL OR e.state = $3::text)
                ORDER BY e.created_at DESC, e.id DESC
                LIMIT $4::integer`,
              [tenantId, projectId, stateFilter, limit]
            );
            return res.rows;
          },
          { readOnly: true }
        );

        const items = rows.map((r) => {
          const endpointId = asText(r["id"]);
          const state = asText(r["state"]) as EndpointState;
          const ver = BigInt(asText(r["version"], "1"));
          const canViewUrl =
            decision.matchedPlatformRoles.includes("platform_admin") ||
            decision.matchedTenantRoles.includes("tenant_admin") ||
            decision.matchedProjectRoles.includes("project_admin") ||
            decision.matchedProjectRoles.includes("integrator");
          return {
            endpoint_id: endpointId,
            name: asText(r["name"]),
            state,
            current_version: asText(r["current_version"], "1"),
            security_epoch: asText(r["security_epoch"], "1"),
            ...(canViewUrl && typeof r["destination_url"] === "string"
              ? {
                  destination_url: r["destination_url"],
                  normalized_hostname: asText(r["normalized_hostname"])
                }
              : {}),
            configuration_sha256:
              r["configuration_sha256"] !== null && r["configuration_sha256"] !== undefined
                ? toHex(r["configuration_sha256"])
                : ("0".repeat(64) as Sha256Hex),
            url_policy_version: asText(r["url_policy_version"], "url_v1"),
            network_policy_version: asText(r["network_policy_version"], "network_v1"),
            request_profile_version: asText(r["request_profile_version"], "request_v1"),
            response_profile_version: asText(r["response_profile_version"], "response_v1"),
            active_signing_policy_version: asOptionalText(r["current_signing_policy_version"]),
            active_receiver_contract_id: asOptionalText(r["active_receiver_contract_id"]),
            active_receiver_contract_version: asOptionalText(r["active_receiver_contract_version"]),
            verification_state: asText(r["verification_state"], "not_started"),
            version: ver.toString(10),
            capabilities: buildCapabilitiesForActions(
              ctx,
              decision,
              "endpoint",
              endpointId,
              [
                "endpoints.create_version",
                "endpoints.verify",
                "endpoints.activate",
                "endpoints.pause",
                "endpoints.quarantine",
                "endpoints.resume",
                "endpoints.retire",
                "endpoints.retained_dispatch_grant.create",
                "signing_key_intents.create",
                "signing_policies.create"
              ],
              {
                expectedVersion: ver,
                stateAllowed: (act) => ({
                  allowed:
                    act === "endpoints.create_version" ||
                    act === "signing_key_intents.create" ||
                    act === "signing_policies.create" ||
                    act === "endpoints.retained_dispatch_grant.create" ||
                    (act === "endpoints.verify" && state !== "retired") ||
                    (act === "endpoints.activate" && (state === "draft" || state === "verification_pending")) ||
                    (act === "endpoints.pause" && state === "active") ||
                    (act === "endpoints.quarantine" && state === "active") ||
                    (act === "endpoints.resume" && (state === "paused" || state === "quarantined")) ||
                    (act === "endpoints.retire" && state !== "retired")
                })
              }
            )
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

  // Create Endpoint + Version 1
  app.post<{ Params: { tenant_id: string; project_id: string } }>(
    `${base}/endpoints`,
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
        await authorizeAction(ctx, auth, "endpoints.create_version", {
          installation: inst,
          tenantId,
          projectId
        });
        const name = asText(body["name"]).trim();
        if (name.length === 0 || name.length > 128) {
          throw new ValidationDomainError({
            code: "INVALID_VALUE",
            message: "Endpoint name must be 1..128 bytes"
          });
        }
        const urlParts = parseDestinationUrlParts(body["destination_url"]);
        const urlPolicyVersion = asText(body["url_policy_version"], "url_v1");
        const networkPolicyVersion = asText(body["network_policy_version"], "network_v1");
        const requestProfileVersion = asText(body["request_profile_version"], "request_v1");
        const responseProfileVersion = asText(body["response_profile_version"], "response_v1");
        const cfgHash = hashCanonicalJson({
          destination_url: urlParts.destinationUrl,
          url_policy_version: urlPolicyVersion,
          network_policy_version: networkPolicyVersion,
          request_profile_version: requestProfileVersion,
          response_profile_version: responseProfileVersion
        });

        const now = formatUtcTimestamp(ctx.clock.nowInstant());
        const endpointId = parseEndpointId(ctx.ids.nextUuid(), "endpoint_id");
        const receiptId = parseCommandReceiptId(ctx.ids.nextUuid(), "receipt_id");

        const res = await ctx.pgAdapter.withTransaction(ctx.pgAdapter.configuredRole, async (tx) => {
          const existing = await checkCommandReceiptIdempotency(tx, {
            scopeKind: "project",
            tenantId,
            projectId,
            actorPrincipalId: auth.principal.principalId,
            commandFamily: "endpoints.create",
            idempotencyKey,
            submittedShapeSha256: cfgHash.sha256
          });
          if (existing !== null) {
            return { existing: true, receipt: existing, endpointId: existing.resource_id };
          }
          await tx.query(
            `INSERT INTO rq.endpoints (
               id, tenant_id, project_id, name, state, current_version, security_epoch,
               created_by, created_at, updated_at, version
             ) VALUES ($1::uuid, $2::uuid, $3::uuid, $4::text, 'draft', 1, 1, $5::uuid, $6::timestamptz, $6::timestamptz, 1)`,
            [endpointId, tenantId, projectId, name, auth.principal.principalId, now]
          );
          await tx.query(
            `INSERT INTO rq.endpoint_versions (
               endpoint_id, endpoint_version, tenant_id, project_id, destination_url,
               normalized_hostname, port, path_and_query_sha256, url_policy_version,
               network_policy_version, request_profile_version, response_profile_version,
               configuration_sha256, created_by, created_at
             ) VALUES (
               $1::uuid, 1, $2::uuid, $3::uuid, $4::text, $5::text, $6::integer, $7::bytea,
               $8::text, $9::text, $10::text, $11::text, $12::bytea, $13::uuid, $14::timestamptz
             )`,
            [
              endpointId,
              tenantId,
              projectId,
              urlParts.destinationUrl,
              urlParts.normalizedHostname,
              urlParts.port,
              urlParts.pathAndQuerySha256,
              urlPolicyVersion,
              networkPolicyVersion,
              requestProfileVersion,
              responseProfileVersion,
              Buffer.from(cfgHash.sha256, "hex"),
              auth.principal.principalId,
              now
            ]
          );
          await tx.query(
            `INSERT INTO rq.endpoint_circuits (
               endpoint_id, endpoint_version, tenant_id, project_id, state,
               policy_kind, policy_version, updated_at, version
             ) VALUES ($1::uuid, 1, $2::uuid, $3::uuid, 'closed', 'circuit', 'circuit_v1', $4::timestamptz, 1)`,
            [endpointId, tenantId, projectId, now]
          );
          const receipt = await insertCommandReceiptAndAudit(tx, {
            receiptId,
            scopeKind: "project",
            tenantId,
            projectId,
            actorPrincipalId: auth.principal.principalId,
            commandFamily: "endpoints.create",
            idempotencyKey,
            submittedShapeSha256: cfgHash.sha256,
            resourceKind: "endpoint",
            resourceId: endpointId,
            acceptedVersion: 1n,
            safeFacts: { name },
            now
          });
          return { existing: false, receipt, endpointId };
        });

        return sendSuccessEnvelope(
          reply,
          res.existing ? 200 : 201,
          { receipt: res.receipt, endpoint_id: res.endpointId, name, state: "draft", current_version: "1" },
          { requestId: request.id, observedAt: now }
        );
      } finally {
        auth.destroySecrets();
      }
    }
  );

  // Create new Endpoint Version
  app.post<{ Params: { tenant_id: string; project_id: string; endpoint_id: string } }>(
    `${base}/endpoints/:endpoint_id/versions`,
    async (request, reply) => {
      const tenantId = parseTenantId(request.params.tenant_id, "tenant_id");
      const projectId = parseProjectId(request.params.project_id, "project_id");
      const endpointId = parseEndpointId(request.params.endpoint_id, "endpoint_id");
      const inst = await ctx.pgAdapter.withTransaction(
        ctx.pgAdapter.configuredRole,
        (tx) => readInstallationSnapshot(ctx, tx),
        { readOnly: true }
      );
      const { auth, idempotencyKey, body } = await authenticateHumanMutation(ctx, request, inst);
      try {
        await authorizeAction(ctx, auth, "endpoints.create_version", {
          installation: inst,
          tenantId,
          projectId
        });
        const urlParts = parseDestinationUrlParts(body["destination_url"]);
        const urlPolicyVersion = asText(body["url_policy_version"], "url_v1");
        const networkPolicyVersion = asText(body["network_policy_version"], "network_v1");
        const requestProfileVersion = asText(body["request_profile_version"], "request_v1");
        const responseProfileVersion = asText(body["response_profile_version"], "response_v1");
        const cfgHash = hashCanonicalJson({
          endpoint_id: endpointId,
          destination_url: urlParts.destinationUrl,
          url_policy_version: urlPolicyVersion,
          network_policy_version: networkPolicyVersion,
          request_profile_version: requestProfileVersion,
          response_profile_version: responseProfileVersion
        });
        const now = formatUtcTimestamp(ctx.clock.nowInstant());
        const receiptId = parseCommandReceiptId(ctx.ids.nextUuid(), "receipt_id");

        const out = await ctx.pgAdapter.withTransaction(ctx.pgAdapter.configuredRole, async (tx) => {
          const existing = await checkCommandReceiptIdempotency(tx, {
            scopeKind: "project",
            tenantId,
            projectId,
            actorPrincipalId: auth.principal.principalId,
            commandFamily: "endpoints.create_version",
            idempotencyKey,
            submittedShapeSha256: cfgHash.sha256
          });
          if (existing !== null) {
            return { existing: true, receipt: existing, nextVer: existing.accepted_version ?? "1" };
          }
          const maxRes = await tx.query<{ max_ver: string }>(
            `SELECT COALESCE(max(endpoint_version), 0)::text AS max_ver
               FROM rq.endpoint_versions WHERE endpoint_id = $1::uuid AND tenant_id = $2::uuid AND project_id = $3::uuid`,
            [endpointId, tenantId, projectId]
          );
          const nextVer = BigInt(asText(maxRes.rows[0]?.max_ver, "0")) + 1n;
          await tx.query(
            `INSERT INTO rq.endpoint_versions (
               endpoint_id, endpoint_version, tenant_id, project_id, destination_url,
               normalized_hostname, port, path_and_query_sha256, url_policy_version,
               network_policy_version, request_profile_version, response_profile_version,
               configuration_sha256, created_by, created_at
             ) VALUES (
               $1::uuid, $2::bigint, $3::uuid, $4::uuid, $5::text, $6::text, $7::integer, $8::bytea,
               $9::text, $10::text, $11::text, $12::text, $13::bytea, $14::uuid, $15::timestamptz
             )`,
            [
              endpointId,
              nextVer.toString(10),
              tenantId,
              projectId,
              urlParts.destinationUrl,
              urlParts.normalizedHostname,
              urlParts.port,
              urlParts.pathAndQuerySha256,
              urlPolicyVersion,
              networkPolicyVersion,
              requestProfileVersion,
              responseProfileVersion,
              Buffer.from(cfgHash.sha256, "hex"),
              auth.principal.principalId,
              now
            ]
          );
          await tx.query(
            `INSERT INTO rq.endpoint_circuits (
               endpoint_id, endpoint_version, tenant_id, project_id, state,
               policy_kind, policy_version, updated_at, version
             ) VALUES ($1::uuid, $2::bigint, $3::uuid, $4::uuid, 'closed', 'circuit', 'circuit_v1', $5::timestamptz, 1)`,
            [endpointId, nextVer.toString(10), tenantId, projectId, now]
          );
          const receipt = await insertCommandReceiptAndAudit(tx, {
            receiptId,
            scopeKind: "project",
            tenantId,
            projectId,
            actorPrincipalId: auth.principal.principalId,
            commandFamily: "endpoints.create_version",
            idempotencyKey,
            submittedShapeSha256: cfgHash.sha256,
            resourceKind: "endpoint",
            resourceId: endpointId,
            acceptedVersion: nextVer,
            now
          });
          return { existing: false, receipt, nextVer: nextVer.toString(10) };
        });
        return sendSuccessEnvelope(
          reply,
          out.existing ? 200 : 201,
          { receipt: out.receipt, endpoint_id: endpointId, endpoint_version: out.nextVer },
          { requestId: request.id, observedAt: now }
        );
      } finally {
        auth.destroySecrets();
      }
    }
  );

  // Endpoint lifecycle transitions (activate, pause, quarantine, resume, retire)
  for (const [subpath, action, targetState, requiresStepUp] of [
    ["activate", "endpoints.activate", "active", true],
    ["pause", "endpoints.pause", "paused", false],
    ["quarantine", "endpoints.quarantine", "quarantined", true],
    ["resume", "endpoints.resume", "active", true],
    ["retire", "endpoints.retire", "retired", true]
  ] as const) {
    app.post<{ Params: { tenant_id: string; project_id: string; endpoint_id: string } }>(
      `${base}/endpoints/:endpoint_id/${subpath}`,
      async (request, reply) => {
        const tenantId = parseTenantId(request.params.tenant_id, "tenant_id");
        const projectId = parseProjectId(request.params.project_id, "project_id");
        const endpointId = parseEndpointId(request.params.endpoint_id, "endpoint_id");
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
          await authorizeAction(ctx, auth, action, {
            installation: inst,
            tenantId,
            projectId,
            stepUpProofId: typeof rawProof === "string" ? rawProof : undefined
          });
          const expectedVersion = parseInt64BigInt(body["expected_version"] ?? 1, "expected_version");
          const receiptId = parseCommandReceiptId(ctx.ids.nextUuid(), "receipt_id");
          if (requiresStepUp) {
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
              targetResourceId: endpointId,
              targetVersion: expectedVersion,
              receiptId
            });
          }
          const now = formatUtcTimestamp(ctx.clock.nowInstant());
          const shapeSha = hashCanonicalJson({
            op: action,
            endpointId,
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
            const targetVerRaw = body["endpoint_version"];
            const targetVerSql =
              targetVerRaw !== undefined && targetVerRaw !== null
                ? parseInt64BigInt(targetVerRaw, "endpoint_version").toString(10)
                : null;
            const upd = await tx.query<{ version: string; current_version: string }>(
              `UPDATE rq.endpoints
                  SET state = $3::text,
                      current_version = COALESCE($5::bigint, current_version),
                      updated_at = $4::timestamptz,
                      version = version + 1
                WHERE id = $1::uuid AND tenant_id = $6::uuid AND project_id = $7::uuid AND version = $2::bigint
                RETURNING version::text, current_version::text`,
              [endpointId, expectedVersion.toString(10), targetState, now, targetVerSql, tenantId, projectId]
            );
            const row = upd.rows[0];
            if (row === undefined) {
              throw new ConflictDomainError({
                code: "VERSION_CONFLICT",
                message: `Endpoint ${endpointId} version mismatch`
              });
            }
            if (action === "endpoints.activate") {
              await tx.query(
                `UPDATE rq.endpoint_versions
                    SET activated_at = COALESCE(activated_at, $3::timestamptz)
                  WHERE endpoint_id = $1::uuid AND endpoint_version = $2::bigint`,
                [endpointId, row.current_version, now]
              );
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
              resourceKind: "endpoint",
              resourceId: endpointId,
              acceptedVersion: parseInt64BigInt(row.version, "version"),
              priorVersion: expectedVersion,
              now
            });
          });
          return sendSuccessEnvelope(
            reply,
            200,
            { receipt, endpoint_id: endpointId, state: targetState },
            { requestId: request.id, observedAt: now }
          );
        } finally {
          auth.destroySecrets();
        }
      }
    );
  }

  // Endpoint Verification Intents
  app.get<{ Params: { tenant_id: string; project_id: string; endpoint_id: string } }>(
    `${base}/endpoints/:endpoint_id/verification-intents`,
    async (request, reply) => {
      const tenantId = parseTenantId(request.params.tenant_id, "tenant_id");
      const projectId = parseProjectId(request.params.project_id, "project_id");
      const endpointId = parseEndpointId(request.params.endpoint_id, "endpoint_id");
      const inst = await ctx.pgAdapter.withTransaction(
        ctx.pgAdapter.configuredRole,
        (tx) => readInstallationSnapshot(ctx, tx),
        { readOnly: true }
      );
      const { auth } = await authenticateHumanRead(ctx, request, inst);
      try {
        await authorizeAction(ctx, auth, "endpoints.read_safe", {
          installation: inst,
          tenantId,
          projectId
        });
        const rows = await ctx.pgAdapter.withTransaction(
          ctx.pgAdapter.configuredRole,
          async (tx) => {
            const res = await tx.query<Record<string, unknown>>(
              `SELECT evi.*,
                      (SELECT eva.proof_sha256 FROM rq.endpoint_verification_attempts eva
                        WHERE eva.intent_id = evi.id ORDER BY eva.prepared_at DESC LIMIT 1) AS proof_digest
                 FROM rq.endpoint_verification_intents evi
                WHERE evi.tenant_id = $1::uuid AND evi.project_id = $2::uuid AND evi.endpoint_id = $3::uuid
                ORDER BY evi.created_at DESC`,
              [tenantId, projectId, endpointId]
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
              intent_id: asText(r["id"]),
              endpoint_id: endpointId,
              endpoint_version: asText(r["endpoint_version"]),
              key_version_id: asText(r["signing_key_version_id"]),
              purpose: asText(r["purpose"]),
              configuration_sha256: toHex(r["configuration_sha256"]),
              receiver_contract_id: asOptionalText(r["receiver_contract_id"]),
              receiver_contract_version: asOptionalText(r["receiver_contract_version"]),
              receiver_contract_sha256:
                r["receiver_contract_sha256"] !== null && r["receiver_contract_sha256"] !== undefined
                  ? toHex(r["receiver_contract_sha256"])
                  : null,
              state: asText(r["state"]),
              attempts_used: Number(r["attempt_count"] ?? 0),
              max_attempts: 3,
              proof_digest_sha256:
                r["proof_digest"] !== null && r["proof_digest"] !== undefined
                  ? toHex(r["proof_digest"])
                  : null,
              failure_reason_code: asOptionalText(r["safe_error_code"]),
              expires_at: formatPgTimestamp(r["expires_at"]),
              version: asText(r["version"], "1")
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

  app.post<{ Params: { tenant_id: string; project_id: string; endpoint_id: string } }>(
    `${base}/endpoints/:endpoint_id/verification-intents`,
    async (request, reply) => {
      const tenantId = parseTenantId(request.params.tenant_id, "tenant_id");
      const projectId = parseProjectId(request.params.project_id, "project_id");
      const endpointId = parseEndpointId(request.params.endpoint_id, "endpoint_id");
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
        await authorizeAction(ctx, auth, "endpoints.verify", {
          installation: inst,
          tenantId,
          projectId,
          stepUpProofId: typeof rawProof === "string" ? rawProof : undefined
        });
        const expectedVersion = parseInt64BigInt(body["expected_version"] ?? 1, "expected_version");
        const receiptId = parseCommandReceiptId(ctx.ids.nextUuid(), "receipt_id");
        await consumeStepUpProofFromBody({
          ctx,
          auth,
          installation: inst,
          body,
          headerMap,
          action: "endpoints.verify",
          scopeKind: "project",
          tenantId,
          projectId,
          targetResourceId: endpointId,
          targetVersion: expectedVersion,
          receiptId
        });
        const purpose =
          body["purpose"] === "verify_rotation_key"
            ? "verify_rotation_key"
            : "verify_destination_and_key";
        const nowInstant = ctx.clock.nowInstant();
        const now = formatUtcTimestamp(nowInstant);
        const expiresAt = formatUtcTimestamp(nowInstant.add({ seconds: 1800 }));
        const intentId = ctx.ids.nextUuid();
        const shapeSha = hashCanonicalJson({ op: "endpoints.verify", endpointId, purpose }).sha256;

        const out = await ctx.pgAdapter.withTransaction(ctx.pgAdapter.configuredRole, async (tx) => {
          const existing = await checkCommandReceiptIdempotency(tx, {
            scopeKind: "project",
            tenantId,
            projectId,
            actorPrincipalId: auth.principal.principalId,
            commandFamily: "endpoints.verify",
            idempotencyKey,
            submittedShapeSha256: shapeSha
          });
          if (existing !== null) {
            return { existing: true, receipt: existing, intentId: existing.resource_id };
          }
          const epRes = await tx.query<Record<string, unknown>>(
            `SELECT e.current_version, e.security_epoch, ev.configuration_sha256
               FROM rq.endpoints e
               JOIN rq.endpoint_versions ev
                 ON ev.endpoint_id = e.id AND ev.endpoint_version = COALESCE($2::bigint, e.current_version, 1)
              WHERE e.id = $1::uuid AND e.tenant_id = $3::uuid AND e.project_id = $4::uuid`,
            [
              endpointId,
              body["endpoint_version"] !== undefined
                ? parseInt64BigInt(body["endpoint_version"], "endpoint_version").toString(10)
                : null,
              tenantId,
              projectId
            ]
          );
          const ep = epRes.rows[0];
          if (ep === undefined) {
            throw new NotFoundDomainError({ code: "NOT_FOUND", message: "Endpoint version not found" });
          }
          let keyVerId = asOptionalText(body["key_version_id"] ?? body["signing_key_version_id"]);
          if (keyVerId === null) {
            const kRes = await tx.query<{ id: string }>(
              `SELECT id FROM rq.signing_key_versions
                WHERE endpoint_id = $1::uuid AND tenant_id = $2::uuid AND project_id = $3::uuid
                  AND state <> 'revoked'
                ORDER BY key_version DESC LIMIT 1`,
              [endpointId, tenantId, projectId]
            );
            keyVerId = kRes.rows[0]?.id ?? null;
          }
          if (keyVerId === null) {
            throw new ConflictDomainError({
              code: "STATE_TRANSITION_NOT_ALLOWED",
              message: "Create a signing key before requesting endpoint verification"
            });
          }
          await tx.query(
            `INSERT INTO rq.endpoint_verification_intents (
               id, tenant_id, project_id, endpoint_id, endpoint_version, security_epoch,
               configuration_sha256, signing_key_version_id, purpose, public_nonce,
               state, created_by, created_at, expires_at, version
             ) VALUES (
               $1::uuid, $2::uuid, $3::uuid, $4::uuid, $5::bigint, $6::bigint,
               $7::bytea, $8::uuid, $9::text, $10::bytea,
               'approved', $11::uuid, $12::timestamptz, $13::timestamptz, 1
             )`,
            [
              intentId,
              tenantId,
              projectId,
              endpointId,
              asText(ep["current_version"], "1"),
              asText(ep["security_epoch"], "1"),
              ep["configuration_sha256"],
              keyVerId,
              purpose,
              crypto.randomBytes(32),
              auth.principal.principalId,
              now,
              expiresAt
            ]
          );
          await tx.query(
            `UPDATE rq.endpoints
                SET state = CASE WHEN state = 'draft' THEN 'verification_pending' ELSE state END,
                    updated_at = $2::timestamptz
              WHERE id = $1::uuid`,
            [endpointId, now]
          );
          const receipt = await insertCommandReceiptAndAudit(tx, {
            receiptId,
            scopeKind: "project",
            tenantId,
            projectId,
            actorPrincipalId: auth.principal.principalId,
            commandFamily: "endpoints.verify",
            idempotencyKey,
            submittedShapeSha256: shapeSha,
            resourceKind: "endpoint_verification_intent",
            resourceId: intentId,
            acceptedVersion: 1n,
            now
          });
          return { existing: false, receipt, intentId };
        });

        return sendSuccessEnvelope(
          reply,
          out.existing ? 200 : 201,
          { receipt: out.receipt, intent_id: out.intentId, endpoint_id: endpointId, state: "approved" },
          { requestId: request.id, observedAt: now }
        );
      } finally {
        auth.destroySecrets();
      }
    }
  );

  // Retained Dispatch Grants
  app.get<{ Params: { tenant_id: string; project_id: string; endpoint_id: string } }>(
    `${base}/endpoints/:endpoint_id/retained-dispatch-grants`,
    async (request, reply) => {
      const tenantId = parseTenantId(request.params.tenant_id, "tenant_id");
      const projectId = parseProjectId(request.params.project_id, "project_id");
      const endpointId = parseEndpointId(request.params.endpoint_id, "endpoint_id");
      const inst = await ctx.pgAdapter.withTransaction(
        ctx.pgAdapter.configuredRole,
        (tx) => readInstallationSnapshot(ctx, tx),
        { readOnly: true }
      );
      const { auth } = await authenticateHumanRead(ctx, request, inst);
      try {
        const decision = await authorizeAction(ctx, auth, "endpoints.read_safe", {
          installation: inst,
          tenantId,
          projectId
        });
        const rows = await ctx.pgAdapter.withTransaction(
          ctx.pgAdapter.configuredRole,
          async (tx) => {
            const res = await tx.query<Record<string, unknown>>(
              `SELECT id, endpoint_id, endpoint_version, state, expires_at, created_at, version
                 FROM rq.endpoint_dispatch_grants
                WHERE tenant_id = $1::uuid AND project_id = $2::uuid AND endpoint_id = $3::uuid
                ORDER BY created_at DESC`,
              [tenantId, projectId, endpointId]
            );
            return res.rows;
          },
          { readOnly: true }
        );
        return sendSuccessEnvelope(
          reply,
          200,
          {
            items: rows.map((r) => {
              const grantId = asText(r["id"]);
              const state = asText(r["state"]);
              const ver = BigInt(asText(r["version"], "1"));
              return {
                grant_id: grantId,
                endpoint_id: endpointId,
                retained_endpoint_version: asText(r["endpoint_version"]),
                state,
                expires_at:
                  r["expires_at"] !== null
                    ? formatPgTimestamp(r["expires_at"])
                    : formatPgTimestamp(r["created_at"]),
                version: ver.toString(10),
                capabilities: buildCapabilitiesForActions(
                  ctx,
                  decision,
                  "retained_dispatch_grant",
                  grantId,
                  ["endpoints.retained_dispatch_grant.revoke"],
                  {
                    expectedVersion: ver,
                    stateAllowed: () => ({ allowed: state === "active" })
                  }
                )
              };
            }),
            page: { next_cursor: null, limit: 50, has_more: false }
          },
          { requestId: request.id }
        );
      } finally {
        auth.destroySecrets();
      }
    }
  );

  app.post<{ Params: { tenant_id: string; project_id: string; endpoint_id: string } }>(
    `${base}/endpoints/:endpoint_id/retained-dispatch-grants`,
    async (request, reply) => {
      const tenantId = parseTenantId(request.params.tenant_id, "tenant_id");
      const projectId = parseProjectId(request.params.project_id, "project_id");
      const endpointId = parseEndpointId(request.params.endpoint_id, "endpoint_id");
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
        await authorizeAction(ctx, auth, "endpoints.retained_dispatch_grant.create", {
          installation: inst,
          tenantId,
          projectId,
          stepUpProofId: typeof rawProof === "string" ? rawProof : undefined
        });
        const epVer = parseInt64BigInt(
          body["retained_endpoint_version"] ?? body["endpoint_version"] ?? 1,
          "retained_endpoint_version"
        );
        const expectedVersion = parseInt64BigInt(body["expected_version"] ?? 1, "expected_version");
        const receiptId = parseCommandReceiptId(ctx.ids.nextUuid(), "receipt_id");
        await consumeStepUpProofFromBody({
          ctx,
          auth,
          installation: inst,
          body,
          headerMap,
          action: "endpoints.retained_dispatch_grant.create",
          scopeKind: "project",
          tenantId,
          projectId,
          targetResourceId: endpointId,
          targetVersion: expectedVersion,
          receiptId
        });
        const nowInstant = ctx.clock.nowInstant();
        const now = formatUtcTimestamp(nowInstant);
        const expiresAt = asOptionalText(body["expires_at"]) ?? formatUtcTimestamp(nowInstant.add({ seconds: 86400 }));
        const grantId = ctx.ids.nextUuid();
        const shapeSha = hashCanonicalJson({
          op: "retained_dispatch_grant.create",
          endpointId,
          epVer: epVer.toString(10)
        }).sha256;

        const out = await ctx.pgAdapter.withTransaction(ctx.pgAdapter.configuredRole, async (tx) => {
          const evRes = await tx.query<Record<string, unknown>>(
            `SELECT e.security_epoch, ev.configuration_sha256
               FROM rq.endpoints e
               JOIN rq.endpoint_versions ev ON ev.endpoint_id = e.id AND ev.endpoint_version = $2::bigint
              WHERE e.id = $1::uuid AND e.tenant_id = $3::uuid AND e.project_id = $4::uuid`,
            [endpointId, epVer.toString(10), tenantId, projectId]
          );
          const evRow = evRes.rows[0];
          if (evRow === undefined) {
            throw new NotFoundDomainError({ code: "NOT_FOUND", message: "Endpoint version not found" });
          }
          await tx.query(
            `INSERT INTO rq.endpoint_dispatch_grants (
               id, tenant_id, project_id, endpoint_id, endpoint_version, security_epoch,
               grant_class, state, approved_by, approved_configuration_sha256,
               created_at, expires_at, version
             ) VALUES (
               $1::uuid, $2::uuid, $3::uuid, $4::uuid, $5::bigint, $6::bigint,
               'retained_destination_dispatch', 'active', $7::uuid, $8::bytea,
               $9::timestamptz, $10::timestamptz, 1
             )`,
            [
              grantId,
              tenantId,
              projectId,
              endpointId,
              epVer.toString(10),
              asText(evRow["security_epoch"], "1"),
              auth.principal.principalId,
              evRow["configuration_sha256"],
              now,
              expiresAt
            ]
          );
          return insertCommandReceiptAndAudit(tx, {
            receiptId,
            scopeKind: "project",
            tenantId,
            projectId,
            actorPrincipalId: auth.principal.principalId,
            commandFamily: "endpoints.retained_dispatch_grant.create",
            idempotencyKey,
            submittedShapeSha256: shapeSha,
            resourceKind: "retained_dispatch_grant",
            resourceId: grantId,
            acceptedVersion: 1n,
            now
          });
        });

        return sendSuccessEnvelope(
          reply,
          201,
          { receipt: out, grant_id: grantId, state: "active" },
          { requestId: request.id, observedAt: now }
        );
      } finally {
        auth.destroySecrets();
      }
    }
  );

  app.post<{ Params: { tenant_id: string; project_id: string; grant_id: string } }>(
    `${base}/retained-dispatch-grants/:grant_id/revoke`,
    async (request, reply) => {
      const tenantId = parseTenantId(request.params.tenant_id, "tenant_id");
      const projectId = parseProjectId(request.params.project_id, "project_id");
      const grantId = parseCanonicalUuid(request.params.grant_id, "grant_id");
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
        await authorizeAction(ctx, auth, "endpoints.retained_dispatch_grant.revoke", {
          installation: inst,
          tenantId,
          projectId,
          stepUpProofId: typeof rawProof === "string" ? rawProof : undefined
        });
        const expectedVersion = parseInt64BigInt(body["expected_version"] ?? 1, "expected_version");
        const receiptId = parseCommandReceiptId(ctx.ids.nextUuid(), "receipt_id");
        await consumeStepUpProofFromBody({
          ctx,
          auth,
          installation: inst,
          body,
          headerMap,
          action: "endpoints.retained_dispatch_grant.revoke",
          scopeKind: "project",
          tenantId,
          projectId,
          targetResourceId: grantId,
          targetVersion: expectedVersion,
          receiptId
        });
        const now = formatUtcTimestamp(ctx.clock.nowInstant());
        const shapeSha = hashCanonicalJson({ op: "retained_dispatch_grant.revoke", grantId }).sha256;
        const receipt = await ctx.pgAdapter.withTransaction(ctx.pgAdapter.configuredRole, async (tx) => {
          const upd = await tx.query<{ version: string }>(
            `UPDATE rq.endpoint_dispatch_grants
                SET state = 'revoked', version = version + 1
              WHERE id = $1::uuid AND tenant_id = $2::uuid AND project_id = $3::uuid AND version = $4::bigint
              RETURNING version::text`,
            [grantId, tenantId, projectId, expectedVersion.toString(10)]
          );
          if (upd.rows[0] === undefined) {
            throw new ConflictDomainError({ code: "VERSION_CONFLICT", message: "Grant version mismatch" });
          }
          return insertCommandReceiptAndAudit(tx, {
            receiptId,
            scopeKind: "project",
            tenantId,
            projectId,
            actorPrincipalId: auth.principal.principalId,
            commandFamily: "endpoints.retained_dispatch_grant.revoke",
            idempotencyKey,
            submittedShapeSha256: shapeSha,
            resourceKind: "retained_dispatch_grant",
            resourceId: grantId,
            acceptedVersion: parseInt64BigInt(upd.rows[0].version, "version"),
            priorVersion: expectedVersion,
            now
          });
        });
        return sendSuccessEnvelope(
          reply,
          200,
          { receipt, grant_id: grantId, state: "revoked" },
          { requestId: request.id, observedAt: now }
        );
      } finally {
        auth.destroySecrets();
      }
    }
  );

  // Signing Key Intents & Signing Keys & Policies
  app.get<{ Params: { tenant_id: string; project_id: string; endpoint_id: string } }>(
    `${base}/endpoints/:endpoint_id/signing-key-intents`,
    async (request, reply) => {
      const tenantId = parseTenantId(request.params.tenant_id, "tenant_id");
      const projectId = parseProjectId(request.params.project_id, "project_id");
      const endpointId = parseEndpointId(request.params.endpoint_id, "endpoint_id");
      const inst = await ctx.pgAdapter.withTransaction(
        ctx.pgAdapter.configuredRole,
        (tx) => readInstallationSnapshot(ctx, tx),
        { readOnly: true }
      );
      const { auth } = await authenticateHumanRead(ctx, request, inst);
      try {
        await authorizeAction(ctx, auth, "endpoints.read_safe", {
          installation: inst,
          tenantId,
          projectId
        });
        const rows = await ctx.pgAdapter.withTransaction(
          ctx.pgAdapter.configuredRole,
          async (tx) => {
            const res = await tx.query<Record<string, unknown>>(
              `SELECT sdi.*, skv.key_id
                 FROM rq.signing_delivery_intents sdi
                 JOIN rq.signing_key_versions skv ON skv.id = sdi.key_version_id
                WHERE sdi.tenant_id = $1::uuid AND sdi.project_id = $2::uuid AND sdi.endpoint_id = $3::uuid
                ORDER BY sdi.created_at DESC`,
              [tenantId, projectId, endpointId]
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
              intent_id: asText(r["id"]),
              endpoint_id: endpointId,
              endpoint_version: asText(r["endpoint_version"]),
              key_version_id: asText(r["key_version_id"]),
              key_id: asText(r["key_id"]),
              state: asText(r["state"]),
              sender_custody_destination_id: asText(r["sender_destination_reference"]),
              receiver_custody_destination_id: asText(r["receiver_destination_reference"]),
              candidate_sha256: toHex(r["candidate_sha256"]),
              expires_at: formatPgTimestamp(r["expires_at"]),
              version: asText(r["version"], "1")
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

  app.post<{ Params: { tenant_id: string; project_id: string; endpoint_id: string } }>(
    `${base}/endpoints/:endpoint_id/signing-key-intents`,
    async (request, reply) => {
      const tenantId = parseTenantId(request.params.tenant_id, "tenant_id");
      const projectId = parseProjectId(request.params.project_id, "project_id");
      const endpointId = parseEndpointId(request.params.endpoint_id, "endpoint_id");
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
        await authorizeAction(ctx, auth, "signing_key_intents.create", {
          installation: inst,
          tenantId,
          projectId,
          stepUpProofId: typeof rawProof === "string" ? rawProof : undefined
        });
        const expectedVersion = parseInt64BigInt(body["expected_version"] ?? 1, "expected_version");
        const receiptId = parseCommandReceiptId(ctx.ids.nextUuid(), "receipt_id");
        await consumeStepUpProofFromBody({
          ctx,
          auth,
          installation: inst,
          body,
          headerMap,
          action: "signing_key_intents.create",
          scopeKind: "project",
          tenantId,
          projectId,
          targetResourceId: endpointId,
          targetVersion: expectedVersion,
          receiptId
        });
        const nowInstant = ctx.clock.nowInstant();
        const now = formatUtcTimestamp(nowInstant);
        const expiresAt = formatUtcTimestamp(nowInstant.add({ seconds: 3600 }));
        const keyVersionId = ctx.ids.nextUuid();
        const intentId = ctx.ids.nextUuid();
        const keyId = asText(body["key_id"], `k-${keyVersionId.slice(0, 8)}`);
        if (!/^[a-z0-9][a-z0-9._-]{0,63}$/.test(keyId)) {
          throw new ValidationDomainError({
            code: "INVALID_KEY_ID",
            message: "Invalid signing key_id format"
          });
        }
        const senderDest = asText(body["sender_custody_destination_id"], "local_memory_sender");
        const receiverDest = asText(body["receiver_custody_destination_id"], "receiver_custody_outbox");
        const candHash = hashCanonicalJson({
          endpointId,
          keyId,
          senderDest,
          receiverDest
        });

        const out = await ctx.pgAdapter.withTransaction(ctx.pgAdapter.configuredRole, async (tx) => {
          const epRes = await tx.query<{ current_version: string }>(
            `SELECT COALESCE(current_version, 1)::text AS current_version
               FROM rq.endpoints WHERE id = $1::uuid AND tenant_id = $2::uuid AND project_id = $3::uuid`,
            [endpointId, tenantId, projectId]
          );
          const epRow = epRes.rows[0];
          if (epRow === undefined) {
            throw new NotFoundDomainError({ code: "NOT_FOUND", message: "Endpoint not found" });
          }
          const kvRes = await tx.query<{ next_ver: string }>(
            `SELECT (COALESCE(max(key_version), 0) + 1)::text AS next_ver
               FROM rq.signing_key_versions WHERE endpoint_id = $1::uuid`,
            [endpointId]
          );
          const nextKeyVer = asText(kvRes.rows[0]?.next_ver, "1");
          await tx.query(
            `INSERT INTO rq.signing_key_versions (
               id, tenant_id, project_id, endpoint_id, key_version, key_id, algorithm,
               custody_reference, custody_version_reference, state, created_at, version
             ) VALUES (
               $1::uuid, $2::uuid, $3::uuid, $4::uuid, $5::bigint, $6::text, 'hmac-sha256-v1',
               $7::text, 'v1', 'prepared', $8::timestamptz, 1
             )`,
            [keyVersionId, tenantId, projectId, endpointId, nextKeyVer, keyId, senderDest, now]
          );
          await tx.query(
            `INSERT INTO rq.signing_delivery_intents (
               id, tenant_id, project_id, endpoint_id, endpoint_version, key_version_id,
               control_epoch, sender_destination_reference, receiver_destination_reference,
               candidate_sha256, state, created_by, created_at, expires_at, version
             ) VALUES (
               $1::uuid, $2::uuid, $3::uuid, $4::uuid, $5::bigint, $6::uuid,
               $7::uuid, $8::text, $9::text, $10::bytea, 'requested', $11::uuid, $12::timestamptz, $13::timestamptz, 1
             )`,
            [
              intentId,
              tenantId,
              projectId,
              endpointId,
              epRow.current_version,
              keyVersionId,
              inst.controlEpoch,
              senderDest,
              receiverDest,
              Buffer.from(candHash.sha256, "hex"),
              auth.principal.principalId,
              now,
              expiresAt
            ]
          );
          return insertCommandReceiptAndAudit(tx, {
            receiptId,
            scopeKind: "project",
            tenantId,
            projectId,
            actorPrincipalId: auth.principal.principalId,
            commandFamily: "signing_key_intents.create",
            idempotencyKey,
            submittedShapeSha256: candHash.sha256,
            resourceKind: "signing_delivery_intent",
            resourceId: intentId,
            acceptedVersion: 1n,
            now
          });
        });

        return sendSuccessEnvelope(
          reply,
          201,
          { receipt: out, intent_id: intentId, key_version_id: keyVersionId, key_id: keyId, state: "requested" },
          { requestId: request.id, observedAt: now }
        );
      } finally {
        auth.destroySecrets();
      }
    }
  );

  app.get<{ Params: { tenant_id: string; project_id: string; endpoint_id: string } }>(
    `${base}/endpoints/:endpoint_id/signing-keys`,
    async (request, reply) => {
      const tenantId = parseTenantId(request.params.tenant_id, "tenant_id");
      const projectId = parseProjectId(request.params.project_id, "project_id");
      const endpointId = parseEndpointId(request.params.endpoint_id, "endpoint_id");
      const inst = await ctx.pgAdapter.withTransaction(
        ctx.pgAdapter.configuredRole,
        (tx) => readInstallationSnapshot(ctx, tx),
        { readOnly: true }
      );
      const { auth } = await authenticateHumanRead(ctx, request, inst);
      try {
        const decision = await authorizeAction(ctx, auth, "endpoints.read_safe", {
          installation: inst,
          tenantId,
          projectId
        });
        const rows = await ctx.pgAdapter.withTransaction(
          ctx.pgAdapter.configuredRole,
          async (tx) => {
            const res = await tx.query<Record<string, unknown>>(
              `SELECT id, key_id, algorithm, state, created_at, sign_until, verify_until, version
                 FROM rq.signing_key_versions
                WHERE tenant_id = $1::uuid AND project_id = $2::uuid AND endpoint_id = $3::uuid
                ORDER BY key_version DESC`,
              [tenantId, projectId, endpointId]
            );
            return res.rows;
          },
          { readOnly: true }
        );
        return sendSuccessEnvelope(
          reply,
          200,
          {
            items: rows.map((r) => {
              const kvId = asText(r["id"]);
              const state = asText(r["state"]);
              const ver = BigInt(asText(r["version"], "1"));
              return {
                key_version_id: kvId,
                key_id: asText(r["key_id"]),
                endpoint_id: endpointId,
                algorithm: asText(r["algorithm"]),
                state,
                created_at: formatPgTimestamp(r["created_at"]),
                sign_until: r["sign_until"] !== null ? formatPgTimestamp(r["sign_until"]) : null,
                verify_until: r["verify_until"] !== null ? formatPgTimestamp(r["verify_until"]) : null,
                version: ver.toString(10),
                capabilities: buildCapabilitiesForActions(
                  ctx,
                  decision,
                  "signing_key_version",
                  kvId,
                  ["signing_keys.revoke"],
                  { expectedVersion: ver, stateAllowed: () => ({ allowed: state !== "revoked" }) }
                )
              };
            }),
            page: { next_cursor: null, limit: 50, has_more: false }
          },
          { requestId: request.id }
        );
      } finally {
        auth.destroySecrets();
      }
    }
  );

  app.post<{ Params: { tenant_id: string; project_id: string; key_version_id: string } }>(
    `${base}/signing-keys/:key_version_id/revoke`,
    async (request, reply) => {
      const tenantId = parseTenantId(request.params.tenant_id, "tenant_id");
      const projectId = parseProjectId(request.params.project_id, "project_id");
      const keyVersionId = parseCanonicalUuid(request.params.key_version_id, "key_version_id");
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
        await authorizeAction(ctx, auth, "signing_keys.revoke", {
          installation: inst,
          tenantId,
          projectId,
          stepUpProofId: typeof rawProof === "string" ? rawProof : undefined
        });
        const expectedVersion = parseInt64BigInt(body["expected_version"] ?? 1, "expected_version");
        const receiptId = parseCommandReceiptId(ctx.ids.nextUuid(), "receipt_id");
        await consumeStepUpProofFromBody({
          ctx,
          auth,
          installation: inst,
          body,
          headerMap,
          action: "signing_keys.revoke",
          scopeKind: "project",
          tenantId,
          projectId,
          targetResourceId: keyVersionId,
          targetVersion: expectedVersion,
          receiptId
        });
        const now = formatUtcTimestamp(ctx.clock.nowInstant());
        const shapeSha = hashCanonicalJson({ op: "signing_keys.revoke", keyVersionId }).sha256;
        const receipt = await ctx.pgAdapter.withTransaction(ctx.pgAdapter.configuredRole, async (tx) => {
          const upd = await tx.query<{ version: string }>(
            `UPDATE rq.signing_key_versions
                SET state = 'revoked', revoked_at = $4::timestamptz, version = version + 1
              WHERE id = $1::uuid AND tenant_id = $2::uuid AND project_id = $3::uuid AND version = $5::bigint
              RETURNING version::text`,
            [keyVersionId, tenantId, projectId, now, expectedVersion.toString(10)]
          );
          if (upd.rows[0] === undefined) {
            throw new ConflictDomainError({ code: "VERSION_CONFLICT", message: "Signing key version mismatch" });
          }
          return insertCommandReceiptAndAudit(tx, {
            receiptId,
            scopeKind: "project",
            tenantId,
            projectId,
            actorPrincipalId: auth.principal.principalId,
            commandFamily: "signing_keys.revoke",
            idempotencyKey,
            submittedShapeSha256: shapeSha,
            resourceKind: "signing_key_version",
            resourceId: keyVersionId,
            acceptedVersion: parseInt64BigInt(upd.rows[0].version, "version"),
            priorVersion: expectedVersion,
            now
          });
        });
        return sendSuccessEnvelope(
          reply,
          200,
          { receipt, key_version_id: keyVersionId, state: "revoked" },
          { requestId: request.id, observedAt: now }
        );
      } finally {
        auth.destroySecrets();
      }
    }
  );

  // Signing Policies
  app.get<{ Params: { tenant_id: string; project_id: string; endpoint_id: string } }>(
    `${base}/endpoints/:endpoint_id/signing-policies`,
    async (request, reply) => {
      const tenantId = parseTenantId(request.params.tenant_id, "tenant_id");
      const projectId = parseProjectId(request.params.project_id, "project_id");
      const endpointId = parseEndpointId(request.params.endpoint_id, "endpoint_id");
      const inst = await ctx.pgAdapter.withTransaction(
        ctx.pgAdapter.configuredRole,
        (tx) => readInstallationSnapshot(ctx, tx),
        { readOnly: true }
      );
      const { auth } = await authenticateHumanRead(ctx, request, inst);
      try {
        const decision = await authorizeAction(ctx, auth, "endpoints.read_safe", {
          installation: inst,
          tenantId,
          projectId
        });
        const rows = await ctx.pgAdapter.withTransaction(
          ctx.pgAdapter.configuredRole,
          async (tx) => {
            const res = await tx.query<Record<string, unknown>>(
              `SELECT sp.*, e.current_signing_policy_version
                 FROM rq.signing_policies sp
                 JOIN rq.endpoints e ON e.id = sp.endpoint_id
                WHERE sp.tenant_id = $1::uuid AND sp.project_id = $2::uuid AND sp.endpoint_id = $3::uuid
                ORDER BY sp.policy_version DESC`,
              [tenantId, projectId, endpointId]
            );
            return res.rows;
          },
          { readOnly: true }
        );
        return sendSuccessEnvelope(
          reply,
          200,
          {
            items: rows.map((r) => {
              const pVer = asText(r["policy_version"]);
              const policyId = deterministicUuid("signing_policy", endpointId, pVer);
              const isActive =
                r["activated_at"] !== null &&
                asOptionalText(r["current_signing_policy_version"]) === pVer;
              const state = isActive ? "active" : r["activated_at"] !== null ? "retired" : "draft";
              return {
                policy_id: policyId,
                endpoint_id: endpointId,
                policy_version: pVer,
                signature_mode: asText(r["signature_mode"]),
                primary_key_version_id: asText(r["primary_key_version_id"]),
                overlap_key_version_id: asOptionalText(r["overlap_key_version_id"]),
                overlap_started_at:
                  r["activated_at"] !== null && r["overlap_key_version_id"] !== null
                    ? formatPgTimestamp(r["activated_at"])
                    : null,
                overlap_ends_at:
                  r["overlap_until"] !== null ? formatPgTimestamp(r["overlap_until"]) : null,
                old_key_sign_until:
                  r["overlap_until"] !== null ? formatPgTimestamp(r["overlap_until"]) : null,
                old_key_verify_until:
                  r["overlap_until"] !== null ? formatPgTimestamp(r["overlap_until"]) : null,
                policy_sha256: toHex(r["policy_sha256"]),
                state,
                capabilities: buildCapabilitiesForActions(
                  ctx,
                  decision,
                  "signing_policy",
                  policyId,
                  ["signing_policies.activate"],
                  {
                    expectedVersion: BigInt(pVer),
                    stateAllowed: () => ({ allowed: state === "draft" })
                  }
                )
              };
            }),
            page: { next_cursor: null, limit: 50, has_more: false }
          },
          { requestId: request.id }
        );
      } finally {
        auth.destroySecrets();
      }
    }
  );

  app.post<{ Params: { tenant_id: string; project_id: string; endpoint_id: string } }>(
    `${base}/endpoints/:endpoint_id/signing-policies`,
    async (request, reply) => {
      const tenantId = parseTenantId(request.params.tenant_id, "tenant_id");
      const projectId = parseProjectId(request.params.project_id, "project_id");
      const endpointId = parseEndpointId(request.params.endpoint_id, "endpoint_id");
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
        await authorizeAction(ctx, auth, "signing_policies.create", {
          installation: inst,
          tenantId,
          projectId,
          stepUpProofId: typeof rawProof === "string" ? rawProof : undefined
        });
        const expectedVersion = parseInt64BigInt(body["expected_version"] ?? 1, "expected_version");
        const receiptId = parseCommandReceiptId(ctx.ids.nextUuid(), "receipt_id");
        await consumeStepUpProofFromBody({
          ctx,
          auth,
          installation: inst,
          body,
          headerMap,
          action: "signing_policies.create",
          scopeKind: "project",
          tenantId,
          projectId,
          targetResourceId: endpointId,
          targetVersion: expectedVersion,
          receiptId
        });
        const primaryKeyVersionId = parseCanonicalUuid(
          body["primary_key_version_id"],
          "primary_key_version_id"
        );
        const signatureMode =
          body["signature_mode"] === "bounded_dual_signature"
            ? "bounded_dual_signature"
            : "primary_only";
        const overlapKeyVersionId =
          body["overlap_key_version_id"] !== undefined && body["overlap_key_version_id"] !== null
            ? parseCanonicalUuid(body["overlap_key_version_id"], "overlap_key_version_id")
            : null;
        const overlapUntil = asOptionalText(body["overlap_until"]);
        const now = formatUtcTimestamp(ctx.clock.nowInstant());
        const policyHash = hashCanonicalJson({
          endpointId,
          signatureMode,
          primaryKeyVersionId,
          overlapKeyVersionId: overlapKeyVersionId ?? null
        });

        const res = await ctx.pgAdapter.withTransaction(ctx.pgAdapter.configuredRole, async (tx) => {
          const maxRes = await tx.query<{ next_ver: string }>(
            `SELECT (COALESCE(max(policy_version), 0) + 1)::text AS next_ver
               FROM rq.signing_policies WHERE endpoint_id = $1::uuid`,
            [endpointId]
          );
          const pVer = asText(maxRes.rows[0]?.next_ver, "1");
          const policyId = deterministicUuid("signing_policy", endpointId, pVer);
          await tx.query(
            `INSERT INTO rq.signing_policies (
               endpoint_id, policy_version, tenant_id, project_id, primary_key_version_id,
               overlap_key_version_id, signature_mode, overlap_until, policy_sha256,
               created_by, created_at
             ) VALUES (
               $1::uuid, $2::bigint, $3::uuid, $4::uuid, $5::uuid, $6::uuid,
               $7::text, $8::timestamptz, $9::bytea, $10::uuid, $11::timestamptz
             )`,
            [
              endpointId,
              pVer,
              tenantId,
              projectId,
              primaryKeyVersionId,
              overlapKeyVersionId,
              signatureMode,
              overlapUntil,
              Buffer.from(policyHash.sha256, "hex"),
              auth.principal.principalId,
              now
            ]
          );
          const receipt = await insertCommandReceiptAndAudit(tx, {
            receiptId,
            scopeKind: "project",
            tenantId,
            projectId,
            actorPrincipalId: auth.principal.principalId,
            commandFamily: "signing_policies.create",
            idempotencyKey,
            submittedShapeSha256: policyHash.sha256,
            resourceKind: "signing_policy",
            resourceId: policyId,
            acceptedVersion: parseInt64BigInt(pVer, "policy_version"),
            now
          });
          return { receipt, policyId, pVer };
        });

        return sendSuccessEnvelope(
          reply,
          201,
          { receipt: res.receipt, policy_id: res.policyId, policy_version: res.pVer, state: "draft" },
          { requestId: request.id, observedAt: now }
        );
      } finally {
        auth.destroySecrets();
      }
    }
  );

  app.post<{ Params: { tenant_id: string; project_id: string; policy_id: string } }>(
    `${base}/signing-policies/:policy_id/activate`,
    async (request, reply) => {
      const tenantId = parseTenantId(request.params.tenant_id, "tenant_id");
      const projectId = parseProjectId(request.params.project_id, "project_id");
      const policyId = parseCanonicalUuid(request.params.policy_id, "policy_id");
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
        await authorizeAction(ctx, auth, "signing_policies.activate", {
          installation: inst,
          tenantId,
          projectId,
          stepUpProofId: typeof rawProof === "string" ? rawProof : undefined
        });
        const expectedVersion = parseInt64BigInt(body["expected_version"] ?? 1, "expected_version");
        const receiptId = parseCommandReceiptId(ctx.ids.nextUuid(), "receipt_id");
        await consumeStepUpProofFromBody({
          ctx,
          auth,
          installation: inst,
          body,
          headerMap,
          action: "signing_policies.activate",
          scopeKind: "project",
          tenantId,
          projectId,
          targetResourceId: policyId,
          targetVersion: expectedVersion,
          receiptId
        });
        const now = formatUtcTimestamp(ctx.clock.nowInstant());
        const shapeSha = hashCanonicalJson({ op: "signing_policies.activate", policyId }).sha256;

        const out = await ctx.pgAdapter.withTransaction(ctx.pgAdapter.configuredRole, async (tx) => {
          const listRes = await tx.query<Record<string, unknown>>(
            `SELECT endpoint_id, policy_version, primary_key_version_id
               FROM rq.signing_policies WHERE tenant_id = $1::uuid AND project_id = $2::uuid`,
            [tenantId, projectId]
          );
          const match = listRes.rows.find(
            (r) => deterministicUuid("signing_policy", asText(r["endpoint_id"]), asText(r["policy_version"])) === policyId
          );
          if (match === undefined) {
            throw new NotFoundDomainError({ code: "NOT_FOUND", message: "Signing policy not found" });
          }
          const endpointId = asText(match["endpoint_id"]);
          const pVer = asText(match["policy_version"]);
          await tx.query(
            `UPDATE rq.signing_policies SET activated_at = $3::timestamptz
              WHERE endpoint_id = $1::uuid AND policy_version = $2::bigint`,
            [endpointId, pVer, now]
          );
          await tx.query(
            `UPDATE rq.signing_key_versions SET state = 'active' WHERE id = $1::uuid`,
            [asText(match["primary_key_version_id"])]
          );
          await tx.query(
            `UPDATE rq.endpoints SET current_signing_policy_version = $2::bigint, updated_at = $3::timestamptz
              WHERE id = $1::uuid`,
            [endpointId, pVer, now]
          );
          const receipt = await insertCommandReceiptAndAudit(tx, {
            receiptId,
            scopeKind: "project",
            tenantId,
            projectId,
            actorPrincipalId: auth.principal.principalId,
            commandFamily: "signing_policies.activate",
            idempotencyKey,
            submittedShapeSha256: shapeSha,
            resourceKind: "signing_policy",
            resourceId: policyId,
            acceptedVersion: parseInt64BigInt(pVer, "policy_version"),
            now
          });
          return { receipt, pVer };
        });
        return sendSuccessEnvelope(
          reply,
          200,
          { receipt: out.receipt, policy_id: policyId, state: "active" },
          { requestId: request.id, observedAt: now }
        );
      } finally {
        auth.destroySecrets();
      }
    }
  );

  // Endpoint Circuits & Probe Request
  app.get<{ Params: { tenant_id: string; project_id: string; endpoint_id: string } }>(
    `${base}/endpoints/:endpoint_id/circuits`,
    async (request, reply) => {
      const tenantId = parseTenantId(request.params.tenant_id, "tenant_id");
      const projectId = parseProjectId(request.params.project_id, "project_id");
      const endpointId = parseEndpointId(request.params.endpoint_id, "endpoint_id");
      const inst = await ctx.pgAdapter.withTransaction(
        ctx.pgAdapter.configuredRole,
        (tx) => readInstallationSnapshot(ctx, tx),
        { readOnly: true }
      );
      const { auth } = await authenticateHumanRead(ctx, request, inst);
      try {
        const decision = await authorizeAction(ctx, auth, "endpoints.read_safe", {
          installation: inst,
          tenantId,
          projectId
        });
        const rows = await ctx.pgAdapter.withTransaction(
          ctx.pgAdapter.configuredRole,
          async (tx) => {
            const res = await tx.query<Record<string, unknown>>(
              `SELECT ec.*, e.state AS endpoint_state,
                      cpr.id AS req_id, cpr.state AS req_state,
                      cpr.prepared_attempt_id AS req_attempt_id, cpr.expires_at AS req_expires_at
                 FROM rq.endpoint_circuits ec
                 JOIN rq.endpoints e ON e.id = ec.endpoint_id
                 LEFT JOIN rq.circuit_probe_requests cpr
                   ON cpr.endpoint_id = ec.endpoint_id
                  AND cpr.endpoint_version = ec.endpoint_version
                  AND cpr.state IN ('pending', 'prepared')
                WHERE ec.tenant_id = $1::uuid AND ec.project_id = $2::uuid AND ec.endpoint_id = $3::uuid
                ORDER BY ec.endpoint_version DESC`,
              [tenantId, projectId, endpointId]
            );
            return res.rows;
          },
          { readOnly: true }
        );
        return sendSuccessEnvelope(
          reply,
          200,
          {
            items: rows.map((r) => {
              const epVer = asText(r["endpoint_version"]);
              const circuitId = deterministicUuid("endpoint_circuit", endpointId, epVer);
              const cState = asText(r["state"]);
              const ver = BigInt(asText(r["version"], "1"));
              return {
                circuit_id: circuitId,
                endpoint_id: endpointId,
                endpoint_version: epVer,
                endpoint_state: asText(r["endpoint_state"]),
                state: cState,
                circuit_generation: asText(r["circuit_generation"], "0"),
                probe_generation: asText(r["probe_generation"], "0"),
                consecutive_transient_failures: Number(r["consecutive_transient_failures"] ?? 0),
                reopen_count: Number(r["reopen_count"] ?? 0),
                reopen_not_before:
                  r["reopen_not_before"] !== null ? formatPgTimestamp(r["reopen_not_before"]) : null,
                probe_attempt_id: asOptionalText(r["probe_attempt_id"]),
                probe_expires_at:
                  r["probe_expires_at"] !== null ? formatPgTimestamp(r["probe_expires_at"]) : null,
                window_started_at: formatPgTimestamp(r["window_started_at"]),
                window_success_count: Number(r["window_success_count"] ?? 0),
                window_failure_count: Number(r["window_failure_count"] ?? 0),
                active_probe_request:
                  typeof r["req_id"] === "string"
                    ? {
                        request_id: r["req_id"],
                        state: asText(r["req_state"]),
                        prepared_attempt_id: asOptionalText(r["req_attempt_id"]),
                        expires_at: formatPgTimestamp(r["req_expires_at"])
                      }
                    : null,
                version: ver.toString(10),
                capabilities: buildCapabilitiesForActions(
                  ctx,
                  decision,
                  "endpoint_circuit",
                  circuitId,
                  ["circuits.request_probe"],
                  { expectedVersion: ver, stateAllowed: () => ({ allowed: cState === "open" }) }
                )
              };
            }),
            page: { next_cursor: null, limit: 50, has_more: false }
          },
          { requestId: request.id }
        );
      } finally {
        auth.destroySecrets();
      }
    }
  );

  app.post<{ Params: { tenant_id: string; project_id: string; endpoint_id: string } }>(
    `${base}/endpoints/:endpoint_id/circuits/request-probe`,
    async (request, reply) => {
      const tenantId = parseTenantId(request.params.tenant_id, "tenant_id");
      const projectId = parseProjectId(request.params.project_id, "project_id");
      const endpointId = parseEndpointId(request.params.endpoint_id, "endpoint_id");
      const inst = await ctx.pgAdapter.withTransaction(
        ctx.pgAdapter.configuredRole,
        (tx) => readInstallationSnapshot(ctx, tx),
        { readOnly: true }
      );
      const { auth, idempotencyKey, body } = await authenticateHumanMutation(ctx, request, inst);
      try {
        await authorizeAction(ctx, auth, "circuits.request_probe", {
          installation: inst,
          tenantId,
          projectId
        });
        const epVer = parseInt64BigInt(body["endpoint_version"] ?? 1, "endpoint_version");
        const expectedGen = parseInt64BigInt(
          body["expected_circuit_generation"] ?? 0,
          "expected_circuit_generation"
        );
        const requestId = parseCanonicalUuid(ctx.ids.nextUuid(), "request_id") as never;
        const receiptId = parseCommandReceiptId(ctx.ids.nextUuid(), "receipt_id");
        const keySha = crypto.createHash("sha256").update(idempotencyKey, "utf8").digest("hex") as Sha256Hex;
        const shapeSha = hashCanonicalJson({
          op: "circuits.request_probe",
          endpointId,
          endpointVersion: epVer.toString(10),
          expectedGen: expectedGen.toString(10)
        }).sha256;
        const out = await ctx.pgAdapter.withTransaction(ctx.pgAdapter.configuredRole, (tx) =>
          requestCircuitProbe(tx, {
            requestId,
            tenantId,
            projectId,
            endpointId,
            endpointVersion: epVer,
            expectedCircuitGeneration: expectedGen,
            requestedBy: auth.principal.principalId,
            receiptId,
            keySha256: keySha,
            submittedShapeSha256: shapeSha
          })
        );
        return sendSuccessEnvelope(
          reply,
          201,
          { request_id: out.requestId, receipt_id: out.receiptId, state: out.state },
          { requestId: request.id }
        );
      } finally {
        auth.destroySecrets();
      }
    }
  );
  void parseSha256Hex;
}
