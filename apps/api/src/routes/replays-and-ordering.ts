import { hashCanonicalJson, parsePositiveInt64String } from "@relayquill/contracts";
import {
  ConflictDomainError,
  NotFoundDomainError,
  type Sha256Hex,
  ValidationDomainError,
  type CanonicalUuid,
  formatUtcTimestamp,
  parseCanonicalUuid,
  parseCommandReceiptId,
  parseDeliveryId,
  parseInt64BigInt,
  parseProjectId,
  parseReplayProposalId,
  parseSha256Hex,
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

function mapReplayRowToDto(r: Record<string, unknown>): Record<string, unknown> {
  return {
    proposal_id: asText(r["id"]),
    family_id: asText(r["family_id"]),
    source_delivery_id: asText(r["source_delivery_id"]),
    event_id: asText(r["event_id"]),
    state: asText(r["state"]),
    version: asText(r["version"]),
    candidate_sha256: toHex(r["candidate_sha256"]),
    strategy: asText(r["strategy"]),
    ordering_strategy: asText(r["ordering_strategy"]),
    target_subscription_version: asText(r["target_subscription_version"]),
    target_endpoint_version: asText(r["target_endpoint_version"]),
    wire_envelope_id: asText(r["wire_envelope_id"]),
    requested_deadline_at: formatPgTimestamp(r["requested_deadline_at"]),
    proposer_principal_id: asText(r["proposer_principal_id"]),
    created_at: formatPgTimestamp(r["created_at"]),
    expires_at: formatPgTimestamp(r["expires_at"]),
    accepted_delivery_id: asOptionalText(r["accepted_delivery_id"])
  };
}

export function registerReplayAndOrderingRoutes(app: FastifyInstance, ctx: ApiContext): void {
  const base = "/api/v1/tenants/:tenant_id/projects/:project_id";

  // ---------------------------------------------------------------------------
  // Replay Proposals & Two-Person Reviews
  // ---------------------------------------------------------------------------
  app.get<{ Params: { tenant_id: string; project_id: string } }>(
    `${base}/replay-proposals`,
    async (request, reply) => {
      const tenantId = parseTenantId(request.params.tenant_id, "tenant_id");
      const projectId = parseProjectId(request.params.project_id, "project_id");
      const q = (request.query as Record<string, unknown>) ?? {};
      const { limit } = parseCursorQueryParams(q);
      const stateFilter =
        typeof q["state"] === "string" && q["state"].trim().length > 0 ? q["state"].trim() : null;
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
              `SELECT rp.id, rp.source_delivery_id, rp.state, rp.version,
                      rp.candidate_sha256, rp.strategy, rp.ordering_strategy,
                      rp.target_subscription_version, rp.target_endpoint_version,
                      rp.wire_envelope_id, rp.requested_deadline_at,
                      rp.proposer_principal_id, rp.created_at, rp.expires_at,
                      rp.accepted_delivery_id,
                      d.family_id, d.event_id
               FROM rq.replay_proposals rp
               JOIN rq.deliveries d ON d.id = rp.source_delivery_id
               WHERE rp.tenant_id = $1::uuid AND rp.project_id = $2::uuid
                 AND ($3::text IS NULL OR rp.state = $3::text)
               ORDER BY rp.created_at DESC, rp.id ASC
               LIMIT $4::integer`,
              [tenantId, projectId, stateFilter, limit + 1]
            );
            return {
              hasMore: res.rows.length > limit,
              items: res.rows.slice(0, limit).map((r) => mapReplayRowToDto(r))
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

  app.post<{ Params: { tenant_id: string; project_id: string; delivery_id: string } }>(
    `${base}/deliveries/:delivery_id/replay-proposals`,
    async (request, reply) => {
      const tenantId = parseTenantId(request.params.tenant_id, "tenant_id");
      const projectId = parseProjectId(request.params.project_id, "project_id");
      const deliveryId = parseDeliveryId(request.params.delivery_id, "delivery_id");
      const inst = await ctx.pgAdapter.withTransaction(
        ctx.pgAdapter.configuredRole,
        (tx) => readInstallationSnapshot(ctx, tx),
        { readOnly: true }
      );
      const { auth, idempotencyKey, body } = await authenticateHumanMutation(ctx, request, inst);
      try {
        const strategy =
          body["strategy"] === "replay_with_reviewed_representation"
            ? "replay_with_reviewed_representation"
            : "replay_exact_original";
        const now = formatUtcTimestamp(ctx.clock.nowInstant());
        const shapeSha = hashCanonicalJson({
          op: "deliveries.replay.propose",
          deliveryId,
          strategy,
          body: stripUndefinedJson(body)
        }).sha256;

        const existing = await ctx.pgAdapter.withTransaction(
          ctx.pgAdapter.configuredRole,
          (tx) =>
            checkCommandReceiptIdempotency(tx, {
              scopeKind: "project",
              tenantId,
              projectId,
              actorPrincipalId: auth.principal.principalId,
              commandFamily: "deliveries.replay.propose",
              idempotencyKey,
              submittedShapeSha256: shapeSha
            }),
          { readOnly: true }
        );
        if (existing !== null) {
          const cachedDto = await ctx.pgAdapter.withTransaction(
            ctx.pgAdapter.configuredRole,
            async (tx) => {
              const rowRes = await tx.query<Record<string, unknown>>(
                `SELECT rp.id, rp.source_delivery_id, rp.state, rp.version,
                        rp.candidate_sha256, rp.strategy, rp.ordering_strategy,
                        rp.target_subscription_version, rp.target_endpoint_version,
                        rp.wire_envelope_id, rp.requested_deadline_at,
                        rp.proposer_principal_id, rp.created_at, rp.expires_at,
                        rp.accepted_delivery_id, d.family_id, d.event_id
                 FROM rq.replay_proposals rp
                 JOIN rq.deliveries d ON d.id = rp.source_delivery_id
                 WHERE rp.id = $1::uuid`,
                [existing.resource_id]
              );
              return rowRes.rows[0] ? mapReplayRowToDto(rowRes.rows[0]) : {};
            },
            { readOnly: true }
          );
          return sendSuccessEnvelope(
            reply,
            200,
            { receipt: existing, ...cachedDto },
            { requestId: request.id, observedAt: now }
          );
        }

        const created = await ctx.replayService.proposeReplay({
          session: auth,
          tenantId,
          projectId,
          deliveryId,
          strategy,
          ...(body["target_subscription_version"] !== undefined
            ? {
                targetSubscriptionVersion: parseInt64BigInt(
                  body["target_subscription_version"],
                  "target_subscription_version"
                )
              }
            : {}),
          ...(body["target_endpoint_version"] !== undefined
            ? {
                targetEndpointVersion: parseInt64BigInt(
                  body["target_endpoint_version"],
                  "target_endpoint_version"
                )
              }
            : {}),
          ...(typeof body["requested_deadline_at"] === "string"
            ? { requestedDeadlineAt: body["requested_deadline_at"] }
            : {}),
          ...(typeof body["representation_profile_id"] === "string" &&
          body["representation_profile_id"].trim().length > 0
            ? { representationProfileId: body["representation_profile_id"].trim() }
            : {}),
          ...(body["representation_profile_version"] !== undefined &&
          body["representation_profile_version"] !== null &&
          body["representation_profile_version"] !== ""
            ? {
                representationProfileVersion: parseInt64BigInt(
                  body["representation_profile_version"],
                  "representation_profile_version"
                )
              }
            : {})
        });

        const out = await ctx.pgAdapter.withTransaction(ctx.pgAdapter.configuredRole, async (tx) => {
          const rowRes = await tx.query<Record<string, unknown>>(
            `SELECT rp.id, rp.source_delivery_id, rp.state, rp.version,
                    rp.candidate_sha256, rp.strategy, rp.ordering_strategy,
                    rp.target_subscription_version, rp.target_endpoint_version,
                    rp.wire_envelope_id, rp.requested_deadline_at,
                    rp.proposer_principal_id, rp.created_at, rp.expires_at,
                    rp.accepted_delivery_id, d.family_id, d.event_id
             FROM rq.replay_proposals rp
             JOIN rq.deliveries d ON d.id = rp.source_delivery_id
             WHERE rp.id = $1::uuid`,
            [created.proposalId]
          );
          const dto = rowRes.rows[0]
            ? mapReplayRowToDto(rowRes.rows[0])
            : {
                proposal_id: created.proposalId,
                source_delivery_id: created.deliveryId,
                state: created.state,
                version: created.version.toString(10),
                candidate_sha256: created.candidateSha256,
                strategy: created.strategy,
                ordering_strategy: created.orderingStrategy,
                target_subscription_version: created.targetSubscriptionVersion.toString(10),
                target_endpoint_version: created.targetEndpointVersion.toString(10),
                wire_envelope_id: created.wireEnvelopeId,
                proposer_principal_id: created.proposerPrincipalId
              };
          const receiptId = parseCommandReceiptId(ctx.ids.nextUuid(), "receipt_id");
          const receipt = await insertCommandReceiptAndAudit(tx, {
            receiptId,
            scopeKind: "project",
            tenantId,
            projectId,
            actorPrincipalId: auth.principal.principalId,
            commandFamily: "deliveries.replay.propose",
            idempotencyKey,
            submittedShapeSha256: shapeSha,
            resourceKind: "replay_proposal",
            resourceId: created.proposalId,
            acceptedVersion: created.version,
            safeFacts: { delivery_id: deliveryId, strategy },
            now
          });
          return { dto, receipt };
        });

        return sendSuccessEnvelope(
          reply,
          201,
          { receipt: out.receipt, ...out.dto },
          { requestId: request.id, observedAt: now }
        );
      } finally {
        auth.destroySecrets();
      }
    }
  );

  app.post<{ Params: { tenant_id: string; project_id: string; proposal_id: string } }>(
    `${base}/replay-proposals/:proposal_id/reviews`,
    async (request, reply) => {
      const tenantId = parseTenantId(request.params.tenant_id, "tenant_id");
      const projectId = parseProjectId(request.params.project_id, "project_id");
      const proposalId = parseReplayProposalId(request.params.proposal_id, "proposal_id");
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
        const decision =
          body["decision"] === "reject"
            ? "reject"
            : body["decision"] === "approve"
              ? "approve"
              : null;
        if (decision === null) {
          throw new ValidationDomainError({
            code: "INVALID_VALUE",
            message: "decision must be 'approve' or 'reject'",
            fieldErrors: [{ path: "decision", code: "INVALID_VALUE" }]
          });
        }
        const expectedVersion =
          body["expected_proposal_version"] !== undefined
            ? parseInt64BigInt(body["expected_proposal_version"], "expected_proposal_version")
            : 1n;
        const candidateSha256 = parseSha256Hex(body["candidate_sha256"], "candidate_sha256");
        const proofRaw = body["operation_proof_id"] ?? extractStepUpHeader(headerMap);
        if (typeof proofRaw !== "string" || proofRaw.trim().length === 0) {
          throw new ValidationDomainError({
            code: "INVALID_VALUE",
            message: "operation_proof_id or X-Relayquill-Step-Up is required to review replay proposal",
            fieldErrors: [{ path: "operation_proof_id", code: "INVALID_VALUE" }]
          });
        }
        const now = formatUtcTimestamp(ctx.clock.nowInstant());
        const shapeSha = hashCanonicalJson({
          op: "replay_proposals.review",
          proposalId,
          decision,
          candidateSha256
        }).sha256;

        const existing = await ctx.pgAdapter.withTransaction(
          ctx.pgAdapter.configuredRole,
          (tx) =>
            checkCommandReceiptIdempotency(tx, {
              scopeKind: "project",
              tenantId,
              projectId,
              actorPrincipalId: auth.principal.principalId,
              commandFamily: "replay_proposals.review",
              idempotencyKey,
              submittedShapeSha256: shapeSha
            }),
          { readOnly: true }
        );
        if (existing !== null) {
          return sendSuccessEnvelope(
            reply,
            200,
            { receipt: existing, proposal_id: proposalId, decision },
            { requestId: request.id, observedAt: now }
          );
        }

        const reviewed = await ctx.replayService.reviewReplayProposal({
          session: auth,
          tenantId,
          projectId,
          proposalId,
          expectedProposalVersion: expectedVersion,
          expectedCandidateSha256: candidateSha256,
          decision,
          stepUpProofId: proofRaw
        });

        const receipt = await ctx.pgAdapter.withTransaction(
          ctx.pgAdapter.configuredRole,
          async (tx) => {
            const receiptId = parseCommandReceiptId(ctx.ids.nextUuid(), "receipt_id");
            return insertCommandReceiptAndAudit(tx, {
              receiptId,
              scopeKind: "project",
              tenantId,
              projectId,
              actorPrincipalId: auth.principal.principalId,
              commandFamily: "replay_proposals.review",
              idempotencyKey,
              submittedShapeSha256: shapeSha,
              resourceKind: "replay_proposal",
              resourceId: reviewed.proposalId,
              acceptedVersion: reviewed.version,
              priorVersion: expectedVersion,
              safeFacts: { decision, state: reviewed.state },
              now
            });
          }
        );

        return sendSuccessEnvelope(
          reply,
          200,
          {
            receipt,
            proposal_id: reviewed.proposalId,
            review_id: reviewed.reviewId ?? null,
            state: reviewed.state,
            version: reviewed.version.toString(10),
            candidate_sha256: reviewed.candidateSha256,
            proposer_principal_id: reviewed.proposerPrincipalId,
            reviewer_principal_id: reviewed.reviewerPrincipalId ?? auth.principal.principalId
          },
          { requestId: request.id, observedAt: now }
        );
      } finally {
        auth.destroySecrets();
      }
    }
  );

  app.post<{ Params: { tenant_id: string; project_id: string; proposal_id: string } }>(
    `${base}/replay-proposals/:proposal_id/admit`,
    async (request, reply) => {
      const tenantId = parseTenantId(request.params.tenant_id, "tenant_id");
      const projectId = parseProjectId(request.params.project_id, "project_id");
      const proposalId = parseReplayProposalId(request.params.proposal_id, "proposal_id");
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
        const expectedVersion =
          body["expected_proposal_version"] !== undefined
            ? parseInt64BigInt(body["expected_proposal_version"], "expected_proposal_version")
            : 2n;
        const candidateSha256 = parseSha256Hex(body["candidate_sha256"], "candidate_sha256");
        const proofRaw = body["operation_proof_id"] ?? extractStepUpHeader(headerMap);
        if (typeof proofRaw !== "string" || proofRaw.trim().length === 0) {
          throw new ValidationDomainError({
            code: "INVALID_VALUE",
            message: "operation_proof_id or X-Relayquill-Step-Up is required to admit replay proposal",
            fieldErrors: [{ path: "operation_proof_id", code: "INVALID_VALUE" }]
          });
        }
        const now = formatUtcTimestamp(ctx.clock.nowInstant());
        const shapeSha = hashCanonicalJson({
          op: "replay_proposals.admit",
          proposalId,
          expectedVersion: expectedVersion.toString(10),
          candidateSha256
        }).sha256;

        const existing = await ctx.pgAdapter.withTransaction(
          ctx.pgAdapter.configuredRole,
          (tx) =>
            checkCommandReceiptIdempotency(tx, {
              scopeKind: "project",
              tenantId,
              projectId,
              actorPrincipalId: auth.principal.principalId,
              commandFamily: "replay_proposals.admit",
              idempotencyKey,
              submittedShapeSha256: shapeSha
            }),
          { readOnly: true }
        );
        if (existing !== null) {
          return sendSuccessEnvelope(
            reply,
            200,
            { receipt: existing, proposal_id: proposalId, state: "admitted" },
            { requestId: request.id, observedAt: now }
          );
        }

        const admitted = await ctx.replayService.admitApprovedReplay({
          session: auth,
          tenantId,
          projectId,
          proposalId,
          expectedProposalVersion: expectedVersion,
          expectedCandidateSha256: candidateSha256,
          stepUpProofId: proofRaw,
          idempotencyKey
        });

        const receipt = await ctx.pgAdapter.withTransaction(
          ctx.pgAdapter.configuredRole,
          async (tx) =>
            insertCommandReceiptAndAudit(tx, {
              receiptId: admitted.receiptId,
              scopeKind: "project",
              tenantId,
              projectId,
              actorPrincipalId: auth.principal.principalId,
              commandFamily: "replay_proposals.admit",
              idempotencyKey,
              submittedShapeSha256: shapeSha,
              resourceKind: "replay_proposal",
              resourceId: proposalId,
              acceptedVersion: expectedVersion + 1n,
              priorVersion: expectedVersion,
              safeFacts: {
                new_delivery_id: admitted.newDeliveryId,
                delivery_generation: admitted.deliveryGeneration.toString(10)
              },
              now
            })
        );

        return sendSuccessEnvelope(
          reply,
          200,
          {
            receipt,
            proposal_id: proposalId,
            delivery_id: admitted.newDeliveryId,
            delivery_generation: admitted.deliveryGeneration.toString(10),
            state: "admitted"
          },
          { requestId: request.id, observedAt: now }
        );
      } finally {
        auth.destroySecrets();
      }
    }
  );

  app.post<{ Params: { tenant_id: string; project_id: string; proposal_id: string } }>(
    `${base}/replay-proposals/:proposal_id/withdraw`,
    async (request, reply) => {
      const tenantId = parseTenantId(request.params.tenant_id, "tenant_id");
      const projectId = parseProjectId(request.params.project_id, "project_id");
      const proposalId = parseReplayProposalId(request.params.proposal_id, "proposal_id");
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
        await authorizeAction(ctx, auth, "replay_proposals.withdraw", {
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
            commandFamily: "replay_proposals.withdraw",
            idempotencyKey,
            submittedShapeSha256: shapeSha
          });
          if (existing !== null) {
            return { receipt: existing, version: existing.accepted_version ?? "1" };
          }

          const propRes = await tx.query<Record<string, unknown>>(
            `SELECT id, state, version FROM rq.replay_proposals
             WHERE id = $1::uuid AND tenant_id = $2::uuid AND project_id = $3::uuid FOR UPDATE`,
            [proposalId, tenantId, projectId]
          );
          if (propRes.rows.length === 0) {
            throw new NotFoundDomainError({
              code: "NOT_FOUND",
              message: `Replay proposal "${proposalId}" not found`
            });
          }
          const curState = asText(propRes.rows[0]?.["state"]);
          const curVer = BigInt(asText(propRes.rows[0]?.["version"], "1"));
          if (curState !== "proposed" && curState !== "approved") {
            throw new ConflictDomainError({
              code: "STATE_TRANSITION_NOT_ALLOWED",
              message: `Cannot withdraw replay proposal in state "${curState}"`
            });
          }
          if (hasProof) {
            await consumeStepUpProofFromBody({
              ctx,
              auth,
              installation: inst,
              body,
              headerMap,
              action: "replay_proposals.withdraw",
              scopeKind: "project",
              tenantId,
              projectId,
              targetResourceId: proposalId,
              targetVersion: curVer,
              receiptId,
              expectedCommandSha256: shapeSha
            });
          }

          await tx.query(
            `UPDATE rq.replay_proposals SET state = 'revoked', version = version + 1
             WHERE id = $1::uuid AND tenant_id = $2::uuid AND project_id = $3::uuid`,
            [proposalId, tenantId, projectId]
          );

          const receipt = await insertCommandReceiptAndAudit(tx, {
            receiptId,
            scopeKind: "project",
            tenantId,
            projectId,
            actorPrincipalId: auth.principal.principalId,
            commandFamily: "replay_proposals.withdraw",
            idempotencyKey,
            submittedShapeSha256: shapeSha,
            resourceKind: "replay_proposal",
            resourceId: proposalId,
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
          { receipt: out.receipt, proposal_id: proposalId, state: "revoked", version: out.version },
          { requestId: request.id, observedAt: now }
        );
      } finally {
        auth.destroySecrets();
      }
    }
  );

  // ---------------------------------------------------------------------------
  // Suppression Proposals
  // ---------------------------------------------------------------------------
  app.get<{ Params: { tenant_id: string; project_id: string } }>(
    `${base}/suppression-proposals`,
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
              `SELECT id, delivery_id, state, version, candidate_sha256, prior_outcome_class,
                      proposer_principal_id, created_at, expires_at
               FROM rq.suppression_proposals
               WHERE tenant_id = $1::uuid AND project_id = $2::uuid
               ORDER BY created_at DESC, id ASC
               LIMIT $3::integer`,
              [tenantId, projectId, limit + 1]
            );
            return {
              hasMore: res.rows.length > limit,
              items: res.rows.slice(0, limit).map((r) => ({
                proposal_id: asText(r["id"]),
                delivery_id: asText(r["delivery_id"]),
                state: asText(r["state"]),
                version: asText(r["version"]),
                candidate_sha256: toHex(r["candidate_sha256"]),
                prior_outcome_class: asOptionalText(r["prior_outcome_class"]),
                proposer_principal_id: asText(r["proposer_principal_id"]),
                created_at: formatPgTimestamp(r["created_at"]),
                expires_at: formatPgTimestamp(r["expires_at"])
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

  app.post<{ Params: { tenant_id: string; project_id: string; delivery_id: string } }>(
    `${base}/deliveries/:delivery_id/suppression-proposals`,
    async (request, reply) => {
      const tenantId = parseTenantId(request.params.tenant_id, "tenant_id");
      const projectId = parseProjectId(request.params.project_id, "project_id");
      const deliveryId = parseDeliveryId(request.params.delivery_id, "delivery_id");
      const inst = await ctx.pgAdapter.withTransaction(
        ctx.pgAdapter.configuredRole,
        (tx) => readInstallationSnapshot(ctx, tx),
        { readOnly: true }
      );
      const { auth, idempotencyKey, body } = await authenticateHumanMutation(ctx, request, inst);
      try {
        const reasonCode =
          typeof body["reason_code"] === "string" && body["reason_code"].trim().length > 0
            ? body["reason_code"].trim()
            : "dead_letter_suppression";
        const now = formatUtcTimestamp(ctx.clock.nowInstant());
        const shapeSha = hashCanonicalJson({
          op: "deliveries.suppression.propose",
          deliveryId,
          reasonCode
        }).sha256;

        const existing = await ctx.pgAdapter.withTransaction(
          ctx.pgAdapter.configuredRole,
          (tx) =>
            checkCommandReceiptIdempotency(tx, {
              scopeKind: "project",
              tenantId,
              projectId,
              actorPrincipalId: auth.principal.principalId,
              commandFamily: "deliveries.suppression.propose",
              idempotencyKey,
              submittedShapeSha256: shapeSha
            }),
          { readOnly: true }
        );
        if (existing !== null) {
          return sendSuccessEnvelope(
            reply,
            200,
            { receipt: existing, proposal_id: existing.resource_id, delivery_id: deliveryId },
            { requestId: request.id, observedAt: now }
          );
        }

        const out = await ctx.replayService.proposeSuppression({
          session: auth,
          tenantId,
          projectId,
          deliveryId,
          reasonCode
        });

        const resData = await ctx.pgAdapter.withTransaction(
          ctx.pgAdapter.configuredRole,
          async (tx) => {
            const rowRes = await tx.query<Record<string, unknown>>(
              `SELECT id, delivery_id, state, version, candidate_sha256, prior_outcome_class,
                      proposer_principal_id, created_at, expires_at
               FROM rq.suppression_proposals WHERE id = $1::uuid`,
              [out.proposalId]
            );
            const r = rowRes.rows[0];
            const dto = r
              ? {
                  proposal_id: asText(r["id"]),
                  delivery_id: asText(r["delivery_id"]),
                  state: asText(r["state"]),
                  version: asText(r["version"]),
                  candidate_sha256: toHex(r["candidate_sha256"]),
                  prior_outcome_class: asOptionalText(r["prior_outcome_class"]),
                  proposer_principal_id: asText(r["proposer_principal_id"]),
                  created_at: formatPgTimestamp(r["created_at"]),
                  expires_at: formatPgTimestamp(r["expires_at"])
                }
              : {
                  proposal_id: out.proposalId,
                  delivery_id: deliveryId,
                  state: out.state,
                  version: "1",
                  proposer_principal_id: out.proposerPrincipalId
                };
            const receiptId = parseCommandReceiptId(ctx.ids.nextUuid(), "receipt_id");
            const receipt = await insertCommandReceiptAndAudit(tx, {
              receiptId,
              scopeKind: "project",
              tenantId,
              projectId,
              actorPrincipalId: auth.principal.principalId,
              commandFamily: "deliveries.suppression.propose",
              idempotencyKey,
              submittedShapeSha256: shapeSha,
              resourceKind: "suppression_proposal",
              resourceId: out.proposalId,
              acceptedVersion: 1n,
              safeFacts: { delivery_id: deliveryId },
              now
            });
            return { dto, receipt };
          }
        );

        return sendSuccessEnvelope(
          reply,
          201,
          { receipt: resData.receipt, ...resData.dto },
          { requestId: request.id, observedAt: now }
        );
      } finally {
        auth.destroySecrets();
      }
    }
  );

  app.post<{ Params: { tenant_id: string; project_id: string; proposal_id: string } }>(
    `${base}/suppression-proposals/:proposal_id/reviews`,
    async (request, reply) => {
      const tenantId = parseTenantId(request.params.tenant_id, "tenant_id");
      const projectId = parseProjectId(request.params.project_id, "project_id");
      const proposalId = parseUuidOrThrow(request.params.proposal_id, "proposal_id");
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
        const decision =
          body["decision"] === "reject"
            ? "reject"
            : body["decision"] === "approve"
              ? "approve"
              : null;
        if (decision === null) {
          throw new ValidationDomainError({
            code: "INVALID_VALUE",
            message: "decision must be 'approve' or 'reject'",
            fieldErrors: [{ path: "decision", code: "INVALID_VALUE" }]
          });
        }
        const proofRaw = body["operation_proof_id"] ?? extractStepUpHeader(headerMap);
        if (typeof proofRaw !== "string" || proofRaw.trim().length === 0) {
          throw new ValidationDomainError({
            code: "INVALID_VALUE",
            message: "operation_proof_id or X-Relayquill-Step-Up is required",
            fieldErrors: [{ path: "operation_proof_id", code: "INVALID_VALUE" }]
          });
        }
        const now = formatUtcTimestamp(ctx.clock.nowInstant());
        const shapeSha = hashCanonicalJson({
          op: "suppression_proposals.review",
          proposalId,
          decision
        }).sha256;

        const lookup = await ctx.pgAdapter.withTransaction(
          ctx.pgAdapter.configuredRole,
          async (tx) => {
            const existing = await checkCommandReceiptIdempotency(tx, {
              scopeKind: "project",
              tenantId,
              projectId,
              actorPrincipalId: auth.principal.principalId,
              commandFamily: "suppression_proposals.review",
              idempotencyKey,
              submittedShapeSha256: shapeSha
            });
            if (existing !== null) {
              return { existing } as const;
            }
            const r = await tx.query<Record<string, unknown>>(
              `SELECT delivery_id, version FROM rq.suppression_proposals
               WHERE id = $1::uuid AND tenant_id = $2::uuid AND project_id = $3::uuid`,
              [proposalId, tenantId, projectId]
            );
            if (r.rows.length === 0) {
              throw new NotFoundDomainError({
                code: "NOT_FOUND",
                message: `Suppression proposal "${proposalId}" not found`
              });
            }
            return {
              existing: null,
              deliveryId: asText(r.rows[0]?.["delivery_id"]),
              version: BigInt(asText(r.rows[0]?.["version"], "1"))
            } as const;
          },
          { readOnly: true }
        );
        if (lookup.existing !== null) {
          return sendSuccessEnvelope(
            reply,
            200,
            { receipt: lookup.existing, proposal_id: proposalId, decision },
            { requestId: request.id, observedAt: now }
          );
        }

        const out = await ctx.replayService.reviewSuppression({
          session: auth,
          tenantId,
          projectId,
          proposalId,
          deliveryId: lookup.deliveryId,
          expectedVersion:
            body["expected_proposal_version"] !== undefined
              ? parseInt64BigInt(body["expected_proposal_version"], "expected_proposal_version")
              : lookup.version,
          decision,
          stepUpProofId: proofRaw
        });

        const receipt = await ctx.pgAdapter.withTransaction(ctx.pgAdapter.configuredRole, async (tx) =>
          insertCommandReceiptAndAudit(tx, {
            receiptId: parseCommandReceiptId(ctx.ids.nextUuid(), "receipt_id"),
            scopeKind: "project",
            tenantId,
            projectId,
            actorPrincipalId: auth.principal.principalId,
            commandFamily: "suppression_proposals.review",
            idempotencyKey,
            submittedShapeSha256: shapeSha,
            resourceKind: "suppression_proposal",
            resourceId: proposalId,
            acceptedVersion: lookup.version + 1n,
            priorVersion: lookup.version,
            safeFacts: { decision, state: out.state },
            now
          })
        );

        return sendSuccessEnvelope(
          reply,
          200,
          {
            receipt,
            proposal_id: out.proposalId,
            state: out.state,
            proposer_principal_id: out.proposerPrincipalId,
            reviewer_principal_id: out.reviewerPrincipalId ?? auth.principal.principalId
          },
          { requestId: request.id, observedAt: now }
        );
      } finally {
        auth.destroySecrets();
      }
    }
  );

  app.post<{ Params: { tenant_id: string; project_id: string; proposal_id: string } }>(
    `${base}/suppression-proposals/:proposal_id/admit`,
    async (request, reply) => {
      const tenantId = parseTenantId(request.params.tenant_id, "tenant_id");
      const projectId = parseProjectId(request.params.project_id, "project_id");
      const proposalId = parseUuidOrThrow(request.params.proposal_id, "proposal_id");
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
        const proofRaw = body["operation_proof_id"] ?? extractStepUpHeader(headerMap);
        if (typeof proofRaw !== "string" || proofRaw.trim().length === 0) {
          throw new ValidationDomainError({
            code: "INVALID_VALUE",
            message: "operation_proof_id or X-Relayquill-Step-Up is required",
            fieldErrors: [{ path: "operation_proof_id", code: "INVALID_VALUE" }]
          });
        }
        const now = formatUtcTimestamp(ctx.clock.nowInstant());
        const shapeSha = hashCanonicalJson({ op: "suppression_proposals.admit", proposalId }).sha256;

        const lookup = await ctx.pgAdapter.withTransaction(
          ctx.pgAdapter.configuredRole,
          async (tx) => {
            const existing = await checkCommandReceiptIdempotency(tx, {
              scopeKind: "project",
              tenantId,
              projectId,
              actorPrincipalId: auth.principal.principalId,
              commandFamily: "suppression_proposals.admit",
              idempotencyKey,
              submittedShapeSha256: shapeSha
            });
            if (existing !== null) {
              return { existing } as const;
            }
            const r = await tx.query<Record<string, unknown>>(
              `SELECT delivery_id, version FROM rq.suppression_proposals
               WHERE id = $1::uuid AND tenant_id = $2::uuid AND project_id = $3::uuid`,
              [proposalId, tenantId, projectId]
            );
            if (r.rows.length === 0) {
              throw new NotFoundDomainError({
                code: "NOT_FOUND",
                message: `Suppression proposal "${proposalId}" not found`
              });
            }
            return {
              existing: null,
              deliveryId: asText(r.rows[0]?.["delivery_id"]),
              version: BigInt(asText(r.rows[0]?.["version"], "2"))
            } as const;
          },
          { readOnly: true }
        );
        if (lookup.existing !== null) {
          return sendSuccessEnvelope(
            reply,
            200,
            { receipt: lookup.existing, proposal_id: proposalId, resulting_delivery_state: "suppressed" },
            { requestId: request.id, observedAt: now }
          );
        }

        const out = await ctx.replayService.admitSuppression({
          session: auth,
          tenantId,
          projectId,
          proposalId,
          deliveryId: lookup.deliveryId,
          expectedVersion:
            body["expected_proposal_version"] !== undefined
              ? parseInt64BigInt(body["expected_proposal_version"], "expected_proposal_version")
              : lookup.version,
          stepUpProofId: proofRaw,
          idempotencyKey
        });

        const receipt = await ctx.pgAdapter.withTransaction(ctx.pgAdapter.configuredRole, async (tx) =>
          insertCommandReceiptAndAudit(tx, {
            receiptId: parseCommandReceiptId(ctx.ids.nextUuid(), "receipt_id"),
            scopeKind: "project",
            tenantId,
            projectId,
            actorPrincipalId: auth.principal.principalId,
            commandFamily: "suppression_proposals.admit",
            idempotencyKey,
            submittedShapeSha256: shapeSha,
            resourceKind: "suppression_proposal",
            resourceId: proposalId,
            acceptedVersion: lookup.version + 1n,
            priorVersion: lookup.version,
            safeFacts: { delivery_id: out.deliveryId, outcome: out.suppressionOutcome },
            now
          })
        );

        return sendSuccessEnvelope(
          reply,
          200,
          {
            receipt,
            outcome: out.suppressionOutcome,
            proposal_id: out.proposalId,
            delivery_id: out.deliveryId,
            resulting_delivery_state: "suppressed",
            advances_strict_ordering_head: false
          },
          { requestId: request.id, observedAt: now }
        );
      } finally {
        auth.destroySecrets();
      }
    }
  );

  // ---------------------------------------------------------------------------
  // Ordering Keys, Members, Order Skip Proposals & Extractor Cutovers
  // ---------------------------------------------------------------------------
  app.get<{ Params: { tenant_id: string; project_id: string } }>(
    `${base}/ordering-keys`,
    async (request, reply) => {
      const tenantId = parseTenantId(request.params.tenant_id, "tenant_id");
      const projectId = parseProjectId(request.params.project_id, "project_id");
      const q = (request.query as Record<string, unknown>) ?? {};
      const { limit } = parseCursorQueryParams(q);
      const subFilter =
        typeof q["subscription_id"] === "string" && q["subscription_id"].trim().length > 0
          ? parseUuidOrThrow(q["subscription_id"], "subscription_id")
          : null;
      const stateFilter =
        typeof q["state"] === "string" && q["state"].trim().length > 0 ? q["state"].trim() : null;
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
              `SELECT ok.id, ok.subscription_id, ok.ordering_domain_id, ok.consumer_contract_scope,
                      ok.ordering_key_sha256, ok.next_eligible_sequence, ok.next_allocate_sequence,
                      ok.blocked_delivery_id, ok.version,
                      CASE WHEN ok.blocked_delivery_id IS NOT NULL THEN 'blocked' ELSE 'active' END AS computed_state,
                      d.last_outcome_class AS blocked_reason_code
               FROM rq.ordering_keys ok
               LEFT JOIN rq.deliveries d ON d.id = ok.blocked_delivery_id
               WHERE ok.tenant_id = $1::uuid AND ok.project_id = $2::uuid
                 AND ($3::uuid IS NULL OR ok.subscription_id = $3::uuid)
                 AND ($4::text IS NULL OR ($4::text = 'blocked' AND ok.blocked_delivery_id IS NOT NULL) OR ($4::text = 'active' AND ok.blocked_delivery_id IS NULL))
               ORDER BY ok.updated_at DESC, ok.id ASC
               LIMIT $5::integer`,
              [tenantId, projectId, subFilter, stateFilter, limit + 1]
            );
            return {
              hasMore: res.rows.length > limit,
              items: res.rows.slice(0, limit).map((r) => ({
                ordering_key_id: asText(r["id"]),
                subscription_id: asText(r["subscription_id"]),
                ordering_domain_id: asText(r["ordering_domain_id"]),
                consumer_contract_scope: asText(r["consumer_contract_scope"]),
                key_digest_sha256: toHex(r["ordering_key_sha256"]),
                state: asText(r["computed_state"]),
                next_eligible_sequence: asText(r["next_eligible_sequence"]),
                next_allocate_sequence: asText(r["next_allocate_sequence"]),
                blocked_delivery_id: asOptionalText(r["blocked_delivery_id"]),
                blocked_reason_code: asOptionalText(r["blocked_reason_code"]),
                version: asText(r["version"])
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

  app.get<{ Params: { tenant_id: string; project_id: string; key_id: string } }>(
    `${base}/ordering-keys/:key_id/members`,
    async (request, reply) => {
      const tenantId = parseTenantId(request.params.tenant_id, "tenant_id");
      const projectId = parseProjectId(request.params.project_id, "project_id");
      const keyId = parseUuidOrThrow(request.params.key_id, "key_id");
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
              `SELECT om.ordering_key_id, om.ordering_sequence, om.member_kind, om.delivery_id,
                      om.state, d.delivery_generation, d.created_at,
                      od.decision AS disposition_decision
               FROM rq.ordering_members om
               JOIN rq.deliveries d ON d.id = om.delivery_id
               LEFT JOIN rq.order_dispositions od ON od.delivery_id = om.delivery_id
               WHERE om.ordering_key_id = $1::uuid AND om.tenant_id = $2::uuid AND om.project_id = $3::uuid
               ORDER BY om.ordering_sequence ASC
               LIMIT $4::integer`,
              [keyId, tenantId, projectId, limit + 1]
            );
            return {
              hasMore: res.rows.length > limit,
              items: res.rows.slice(0, limit).map((r) => ({
                ordering_key_id: asText(r["ordering_key_id"]),
                ordering_sequence: asText(r["ordering_sequence"]),
                member_kind: asText(r["member_kind"]),
                delivery_id: asText(r["delivery_id"]),
                delivery_generation: asText(r["delivery_generation"], "1"),
                state: asText(r["state"]),
                disposition_decision: asOptionalText(r["disposition_decision"]),
                recorded_at: formatPgTimestamp(r["created_at"])
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

  app.get<{ Params: { tenant_id: string; project_id: string } }>(
    `${base}/order-skip-proposals`,
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
              `SELECT p.id, p.ordering_key_id, p.delivery_id, p.state, p.version,
                      p.candidate_sha256, p.known_outcome_class, p.proposer_principal_id,
                      p.created_at, p.expires_at,
                      COALESCE(om.ordering_sequence, ok.next_eligible_sequence) AS prior_sequence
               FROM rq.order_skip_proposals p
               JOIN rq.ordering_keys ok ON ok.id = p.ordering_key_id
               LEFT JOIN rq.ordering_members om ON om.delivery_id = p.delivery_id
               WHERE p.tenant_id = $1::uuid AND p.project_id = $2::uuid
               ORDER BY p.created_at DESC, p.id ASC
               LIMIT $3::integer`,
              [tenantId, projectId, limit + 1]
            );
            return {
              hasMore: res.rows.length > limit,
              items: res.rows.slice(0, limit).map((r) => {
                const prior = BigInt(asText(r["prior_sequence"], "1"));
                return {
                  proposal_id: asText(r["id"]),
                  ordering_key_id: asText(r["ordering_key_id"]),
                  delivery_id: asText(r["delivery_id"]),
                  state: asText(r["state"]),
                  version: asText(r["version"]),
                  candidate_sha256: toHex(r["candidate_sha256"]),
                  prior_sequence: prior.toString(10),
                  resulting_sequence: (prior + 1n).toString(10),
                  known_outcome_class: asOptionalText(r["known_outcome_class"]),
                  proposer_principal_id: asText(r["proposer_principal_id"]),
                  created_at: formatPgTimestamp(r["created_at"]),
                  expires_at: formatPgTimestamp(r["expires_at"])
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

  app.post<{ Params: { tenant_id: string; project_id: string; key_id: string } }>(
    `${base}/ordering-keys/:key_id/skip-proposals`,
    async (request, reply) => {
      const tenantId = parseTenantId(request.params.tenant_id, "tenant_id");
      const projectId = parseProjectId(request.params.project_id, "project_id");
      const keyId = parseUuidOrThrow(request.params.key_id, "key_id");
      const inst = await ctx.pgAdapter.withTransaction(
        ctx.pgAdapter.configuredRole,
        (tx) => readInstallationSnapshot(ctx, tx),
        { readOnly: true }
      );
      const { auth, idempotencyKey, body } = await authenticateHumanMutation(ctx, request, inst);
      try {
        const reasonCode =
          typeof body["reason_code"] === "string" && body["reason_code"].trim().length > 0
            ? body["reason_code"].trim()
            : "reviewed_gap_skip_after_triage";
        const now = formatUtcTimestamp(ctx.clock.nowInstant());
        const shapeSha = hashCanonicalJson({
          op: "order_skip_proposals.propose",
          keyId,
          reasonCode
        }).sha256;

        const keyLookup = await ctx.pgAdapter.withTransaction(
          ctx.pgAdapter.configuredRole,
          async (tx) => {
            const existing = await checkCommandReceiptIdempotency(tx, {
              scopeKind: "project",
              tenantId,
              projectId,
              actorPrincipalId: auth.principal.principalId,
              commandFamily: "order_skip_proposals.propose",
              idempotencyKey,
              submittedShapeSha256: shapeSha
            });
            if (existing !== null) {
              return { existing } as const;
            }
            const kr = await tx.query<Record<string, unknown>>(
              `SELECT ordering_domain_id, ordering_key_sha256, next_eligible_sequence
               FROM rq.ordering_keys
               WHERE id = $1::uuid AND tenant_id = $2::uuid AND project_id = $3::uuid`,
              [keyId, tenantId, projectId]
            );
            if (kr.rows.length === 0) {
              throw new NotFoundDomainError({
                code: "NOT_FOUND",
                message: `Ordering key "${keyId}" not found`
              });
            }
            return {
              existing: null,
              orderingDomainId: asText(kr.rows[0]?.["ordering_domain_id"]),
              orderingKeySha256: toHex(kr.rows[0]?.["ordering_key_sha256"]),
              blockedSequence: BigInt(asText(kr.rows[0]?.["next_eligible_sequence"], "1"))
            } as const;
          },
          { readOnly: true }
        );
        if (keyLookup.existing !== null) {
          return sendSuccessEnvelope(
            reply,
            200,
            { receipt: keyLookup.existing, proposal_id: keyLookup.existing.resource_id },
            { requestId: request.id, observedAt: now }
          );
        }

        const out = await ctx.orderingService.proposeOrderSkip({
          session: auth,
          tenantId,
          projectId,
          orderingDomainId: keyLookup.orderingDomainId,
          orderingKeySha256: keyLookup.orderingKeySha256,
          blockedSequence: keyLookup.blockedSequence,
          reasonCode
        });

        const resData = await ctx.pgAdapter.withTransaction(
          ctx.pgAdapter.configuredRole,
          async (tx) => {
            const pr = await tx.query<Record<string, unknown>>(
              `SELECT id, ordering_key_id, delivery_id, state, version, candidate_sha256,
                      known_outcome_class, proposer_principal_id, created_at, expires_at
               FROM rq.order_skip_proposals WHERE id = $1::uuid`,
              [out.proposalId]
            );
            const r = pr.rows[0];
            const prior = keyLookup.blockedSequence;
            const dto = r
              ? {
                  proposal_id: asText(r["id"]),
                  ordering_key_id: asText(r["ordering_key_id"]),
                  delivery_id: asText(r["delivery_id"]),
                  state: asText(r["state"]),
                  version: asText(r["version"]),
                  candidate_sha256: toHex(r["candidate_sha256"]),
                  prior_sequence: prior.toString(10),
                  resulting_sequence: (prior + 1n).toString(10),
                  known_outcome_class: asOptionalText(r["known_outcome_class"]),
                  proposer_principal_id: asText(r["proposer_principal_id"]),
                  created_at: formatPgTimestamp(r["created_at"]),
                  expires_at: formatPgTimestamp(r["expires_at"])
                }
              : {
                  proposal_id: out.proposalId,
                  ordering_key_id: keyId,
                  state: out.state,
                  proposer_principal_id: out.proposerPrincipalId
                };
            const receipt = await insertCommandReceiptAndAudit(tx, {
              receiptId: parseCommandReceiptId(ctx.ids.nextUuid(), "receipt_id"),
              scopeKind: "project",
              tenantId,
              projectId,
              actorPrincipalId: auth.principal.principalId,
              commandFamily: "order_skip_proposals.propose",
              idempotencyKey,
              submittedShapeSha256: shapeSha,
              resourceKind: "order_skip_proposal",
              resourceId: out.proposalId,
              acceptedVersion: 1n,
              safeFacts: { ordering_key_id: keyId },
              now
            });
            return { dto, receipt };
          }
        );

        return sendSuccessEnvelope(
          reply,
          201,
          { receipt: resData.receipt, ...resData.dto },
          { requestId: request.id, observedAt: now }
        );
      } finally {
        auth.destroySecrets();
      }
    }
  );

  app.post<{ Params: { tenant_id: string; project_id: string; proposal_id: string } }>(
    `${base}/order-skip-proposals/:proposal_id/reviews`,
    async (request, reply) => {
      const tenantId = parseTenantId(request.params.tenant_id, "tenant_id");
      const projectId = parseProjectId(request.params.project_id, "project_id");
      const proposalId = parseUuidOrThrow(request.params.proposal_id, "proposal_id");
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
        const decision =
          body["decision"] === "reject"
            ? "reject"
            : body["decision"] === "approve"
              ? "approve"
              : null;
        if (decision === null) {
          throw new ValidationDomainError({
            code: "INVALID_VALUE",
            message: "decision must be 'approve' or 'reject'",
            fieldErrors: [{ path: "decision", code: "INVALID_VALUE" }]
          });
        }
        const proofRaw = body["operation_proof_id"] ?? extractStepUpHeader(headerMap);
        if (typeof proofRaw !== "string" || proofRaw.trim().length === 0) {
          throw new ValidationDomainError({
            code: "INVALID_VALUE",
            message: "operation_proof_id or X-Relayquill-Step-Up is required",
            fieldErrors: [{ path: "operation_proof_id", code: "INVALID_VALUE" }]
          });
        }
        const now = formatUtcTimestamp(ctx.clock.nowInstant());
        const shapeSha = hashCanonicalJson({
          op: "order_skip_proposals.review",
          proposalId,
          decision
        }).sha256;

        const existing = await ctx.pgAdapter.withTransaction(
          ctx.pgAdapter.configuredRole,
          (tx) =>
            checkCommandReceiptIdempotency(tx, {
              scopeKind: "project",
              tenantId,
              projectId,
              actorPrincipalId: auth.principal.principalId,
              commandFamily: "order_skip_proposals.review",
              idempotencyKey,
              submittedShapeSha256: shapeSha
            }),
          { readOnly: true }
        );
        if (existing !== null) {
          return sendSuccessEnvelope(
            reply,
            200,
            { receipt: existing, proposal_id: proposalId, decision },
            { requestId: request.id, observedAt: now }
          );
        }

        const out = await ctx.orderingService.reviewOrderSkip({
          session: auth,
          tenantId,
          projectId,
          proposalId,
          expectedVersion:
            body["expected_proposal_version"] !== undefined
              ? parseInt64BigInt(body["expected_proposal_version"], "expected_proposal_version")
              : 1n,
          decision,
          stepUpProofId: proofRaw
        });

        const receipt = await ctx.pgAdapter.withTransaction(ctx.pgAdapter.configuredRole, async (tx) =>
          insertCommandReceiptAndAudit(tx, {
            receiptId: parseCommandReceiptId(ctx.ids.nextUuid(), "receipt_id"),
            scopeKind: "project",
            tenantId,
            projectId,
            actorPrincipalId: auth.principal.principalId,
            commandFamily: "order_skip_proposals.review",
            idempotencyKey,
            submittedShapeSha256: shapeSha,
            resourceKind: "order_skip_proposal",
            resourceId: proposalId,
            acceptedVersion: 2n,
            safeFacts: { decision, state: out.state },
            now
          })
        );

        return sendSuccessEnvelope(
          reply,
          200,
          {
            receipt,
            proposal_id: out.proposalId,
            state: out.state,
            proposer_principal_id: out.proposerPrincipalId,
            reviewer_principal_id: out.reviewerPrincipalId
          },
          { requestId: request.id, observedAt: now }
        );
      } finally {
        auth.destroySecrets();
      }
    }
  );

  app.post<{ Params: { tenant_id: string; project_id: string; proposal_id: string } }>(
    `${base}/order-skip-proposals/:proposal_id/admit`,
    async (request, reply) => {
      const tenantId = parseTenantId(request.params.tenant_id, "tenant_id");
      const projectId = parseProjectId(request.params.project_id, "project_id");
      const proposalId = parseUuidOrThrow(request.params.proposal_id, "proposal_id");
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
        const proofRaw = body["operation_proof_id"] ?? extractStepUpHeader(headerMap);
        if (typeof proofRaw !== "string" || proofRaw.trim().length === 0) {
          throw new ValidationDomainError({
            code: "INVALID_VALUE",
            message: "operation_proof_id or X-Relayquill-Step-Up is required",
            fieldErrors: [{ path: "operation_proof_id", code: "INVALID_VALUE" }]
          });
        }
        const now = formatUtcTimestamp(ctx.clock.nowInstant());
        const shapeSha = hashCanonicalJson({ op: "order_skip_proposals.admit", proposalId }).sha256;

        const lookup = await ctx.pgAdapter.withTransaction(
          ctx.pgAdapter.configuredRole,
          async (tx) => {
            const existing = await checkCommandReceiptIdempotency(tx, {
              scopeKind: "project",
              tenantId,
              projectId,
              actorPrincipalId: auth.principal.principalId,
              commandFamily: "order_skip_proposals.admit",
              idempotencyKey,
              submittedShapeSha256: shapeSha
            });
            if (existing !== null) {
              return { existing } as const;
            }
            const pr = await tx.query<Record<string, unknown>>(
              `SELECT p.id, p.ordering_key_id, p.delivery_id, p.proposer_principal_id, p.version,
                      ok.ordering_domain_id, ok.ordering_key_sha256, ok.next_eligible_sequence,
                      d.state AS delivery_state,
                      (
                        SELECT osr.id FROM rq.order_skip_reviews osr
                        WHERE osr.proposal_id = p.id AND osr.state = 'active' AND osr.decision = 'approve'
                        ORDER BY osr.created_at DESC LIMIT 1
                      ) AS review_id,
                      (
                        SELECT osr.reviewer_principal_id FROM rq.order_skip_reviews osr
                        WHERE osr.proposal_id = p.id AND osr.state = 'active' AND osr.decision = 'approve'
                        ORDER BY osr.created_at DESC LIMIT 1
                      ) AS reviewer_principal_id
               FROM rq.order_skip_proposals p
               JOIN rq.ordering_keys ok ON ok.id = p.ordering_key_id
               JOIN rq.deliveries d ON d.id = p.delivery_id
               WHERE p.id = $1::uuid AND p.tenant_id = $2::uuid AND p.project_id = $3::uuid`,
              [proposalId, tenantId, projectId]
            );
            const row = pr.rows[0];
            if (row === undefined) {
              throw new NotFoundDomainError({
                code: "NOT_FOUND",
                message: `Order skip proposal "${proposalId}" not found`
              });
            }
            const reviewId =
              typeof body["review_id"] === "string" && body["review_id"].trim().length > 0
                ? parseUuidOrThrow(body["review_id"], "review_id")
                : asOptionalText(row["review_id"]);
            const reviewerPrincipalId = asOptionalText(row["reviewer_principal_id"]);
            if (reviewId === null || reviewerPrincipalId === null) {
              throw new ConflictDomainError({
                code: "STATE_TRANSITION_NOT_ALLOWED",
                message: "Order skip proposal has no active approval review"
              });
            }
            return {
              existing: null,
              orderingKeyId: asText(row["ordering_key_id"]),
              orderingDomainId: asText(row["ordering_domain_id"]),
              orderingKeySha256: toHex(row["ordering_key_sha256"]),
              nextEligibleSequence: BigInt(asText(row["next_eligible_sequence"], "1")),
              proposerPrincipalId: asText(row["proposer_principal_id"]),
              reviewerPrincipalId,
              reviewId,
              deliveryAcknowledged: asText(row["delivery_state"]) === "acknowledged",
              version: BigInt(asText(row["version"], "2"))
            } as const;
          },
          { readOnly: true }
        );
        if (lookup.existing !== null) {
          return sendSuccessEnvelope(
            reply,
            200,
            { receipt: lookup.existing, proposal_id: proposalId, state: "admitted" },
            { requestId: request.id, observedAt: now }
          );
        }

        const out = await ctx.orderingService.applyOrderSkipDisposition({
          session: auth,
          tenantId,
          projectId,
          proposalId,
          reviewId: lookup.reviewId,
          expectedVersion:
            body["expected_proposal_version"] !== undefined
              ? parseInt64BigInt(body["expected_proposal_version"], "expected_proposal_version")
              : lookup.version,
          proposerPrincipalId: lookup.proposerPrincipalId,
          reviewerPrincipalId: lookup.reviewerPrincipalId,
          orderingDomainId: lookup.orderingDomainId,
          orderingKeyId: lookup.orderingKeyId,
          orderingKeySha256: lookup.orderingKeySha256,
          blockedSequence: lookup.nextEligibleSequence,
          deliveryAcknowledged: lookup.deliveryAcknowledged,
          nextEligibleSequence: lookup.nextEligibleSequence,
          idempotencyKey,
          stepUpProofId: proofRaw
        });

        const receipt = await ctx.pgAdapter.withTransaction(ctx.pgAdapter.configuredRole, async (tx) =>
          insertCommandReceiptAndAudit(tx, {
            receiptId: parseCommandReceiptId(ctx.ids.nextUuid(), "receipt_id"),
            scopeKind: "project",
            tenantId,
            projectId,
            actorPrincipalId: auth.principal.principalId,
            commandFamily: "order_skip_proposals.admit",
            idempotencyKey,
            submittedShapeSha256: shapeSha,
            resourceKind: "order_skip_proposal",
            resourceId: proposalId,
            acceptedVersion: lookup.version + 1n,
            priorVersion: lookup.version,
            safeFacts: {
              disposition_id: out.dispositionId,
              new_head_sequence: out.newHeadSequence.toString(10)
            },
            now
          })
        );

        return sendSuccessEnvelope(
          reply,
          200,
          {
            receipt,
            proposal_id: proposalId,
            disposition_id: out.dispositionId,
            new_head_sequence: out.newHeadSequence.toString(10),
            state: "admitted"
          },
          { requestId: request.id, observedAt: now }
        );
      } finally {
        auth.destroySecrets();
      }
    }
  );

  // ---------------------------------------------------------------------------
  // Ordering Extractor Cutover Plans
  // ---------------------------------------------------------------------------
  app.get<{ Params: { tenant_id: string; project_id: string } }>(
    `${base}/ordering-cutovers`,
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
              `SELECT id, subscription_id, source_version, target_version,
                      state, candidate_sha256, boundary_project_sequence, expires_at, version
               FROM rq.ordering_cutover_plans
               WHERE tenant_id = $1::uuid AND project_id = $2::uuid
               ORDER BY created_at DESC, id ASC
               LIMIT $3::integer`,
              [tenantId, projectId, limit + 1]
            );
            return {
              hasMore: res.rows.length > limit,
              items: res.rows.slice(0, limit).map((r) => ({
                plan_id: asText(r["id"]),
                subscription_id: asText(r["subscription_id"]),
                source_version: asText(r["source_version"]),
                target_version: asText(r["target_version"]),
                state: asText(r["state"]),
                candidate_sha256: toHex(r["candidate_sha256"]),
                boundary_project_sequence: asOptionalText(r["boundary_project_sequence"]),
                materialized_through_event_sequence: "0",
                old_heads_remaining: "0",
                unknown_attempts_remaining: "0",
                expires_at: formatPgTimestamp(r["expires_at"]),
                version: asText(r["version"])
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

  app.post<{ Params: { tenant_id: string; project_id: string; subscription_id: string } }>(
    `${base}/subscriptions/:subscription_id/ordering-cutovers`,
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
      try {
        const rawProof = body["operation_proof_id"] ?? extractStepUpHeader(headerMap);
        const hasProof = typeof rawProof === "string" && rawProof.trim().length > 0;
        await authorizeAction(ctx, auth, "ordering_cutovers.propose", {
          installation: inst,
          tenantId,
          projectId,
          stepUpProofId: hasProof ? rawProof : undefined
        });

        const targetVersion = parsePositiveInt64String(
          asText(body["target_version"]),
          "target_version"
        );
        const now = formatUtcTimestamp(ctx.clock.nowInstant());
        const receiptId = parseCommandReceiptId(ctx.ids.nextUuid(), "receipt_id");
        const shapeSha = buildStepUpFallbackSha(body);

        const out = await ctx.pgAdapter.withTransaction(ctx.pgAdapter.configuredRole, async (tx) => {
          const existing = await checkCommandReceiptIdempotency(tx, {
            scopeKind: "project",
            tenantId,
            projectId,
            actorPrincipalId: auth.principal.principalId,
            commandFamily: "ordering_cutovers.propose",
            idempotencyKey,
            submittedShapeSha256: shapeSha
          });
          if (existing !== null) {
            return {
              existing: true,
              dto: { plan_id: existing.resource_id, subscription_id: subscriptionId },
              receipt: existing
            };
          }

          const subRes = await tx.query<Record<string, unknown>>(
            `SELECT current_version FROM rq.subscriptions
             WHERE id = $1::uuid AND tenant_id = $2::uuid AND project_id = $3::uuid`,
            [subscriptionId, tenantId, projectId]
          );
          if (subRes.rows.length === 0) {
            throw new NotFoundDomainError({
              code: "NOT_FOUND",
              message: `Subscription "${subscriptionId}" not found`
            });
          }
          const sourceVersion = asOptionalText(subRes.rows[0]?.["current_version"]) ?? "1";

          const versRes = await tx.query<Record<string, unknown>>(
            `SELECT subscription_version, ordering_extractor_sha256, consumer_contract_scope
             FROM rq.subscription_versions
             WHERE subscription_id = $1::uuid AND tenant_id = $2::uuid AND project_id = $3::uuid
               AND subscription_version IN ($4::bigint, $5::bigint)`,
            [subscriptionId, tenantId, projectId, sourceVersion, targetVersion]
          );
          const srcVer = versRes.rows.find(
            (r) => asText(r["subscription_version"]) === sourceVersion
          );
          const tgtVer = versRes.rows.find(
            (r) => asText(r["subscription_version"]) === targetVersion
          );
          if (srcVer === undefined || tgtVer === undefined) {
            throw new NotFoundDomainError({
              code: "NOT_FOUND",
              message: "Source or target subscription version not found for cutover"
            });
          }

          if (hasProof) {
            await consumeStepUpProofFromBody({
              ctx,
              auth,
              installation: inst,
              body,
              headerMap,
              action: "ordering_cutovers.propose",
              scopeKind: "project",
              tenantId,
              projectId,
              targetResourceId: subscriptionId,
              targetVersion: BigInt(sourceVersion),
              receiptId,
              expectedCommandSha256: shapeSha
            });
          }

          const srcSha =
            srcVer["ordering_extractor_sha256"] !== null &&
            srcVer["ordering_extractor_sha256"] !== undefined
              ? toHex(srcVer["ordering_extractor_sha256"])
              : hashCanonicalJson({ version: sourceVersion }).sha256;
          const tgtSha =
            tgtVer["ordering_extractor_sha256"] !== null &&
            tgtVer["ordering_extractor_sha256"] !== undefined
              ? toHex(tgtVer["ordering_extractor_sha256"])
              : hashCanonicalJson({ version: targetVersion }).sha256;
          const scope = asText(srcVer["consumer_contract_scope"], "default");
          const candidateSha256 = hashCanonicalJson({
            subscription_id: subscriptionId,
            source_version: sourceVersion,
            target_version: targetVersion,
            source_extractor_sha256: srcSha,
            target_extractor_sha256: tgtSha,
            scope
          }).sha256;
          const planId = parseCanonicalUuid(ctx.ids.nextUuid(), "plan_id");

          const insRes = await tx.query<Record<string, unknown>>(
            `INSERT INTO rq.ordering_cutover_plans (
               id, tenant_id, project_id, subscription_id,
               source_version, target_version,
               source_extractor_sha256, target_extractor_sha256,
               source_consumer_scope, target_consumer_scope,
               state, boundary_project_sequence, candidate_sha256,
               created_by, expires_at, version
             ) VALUES (
               $1::uuid, $2::uuid, $3::uuid, $4::uuid,
               $5::bigint, $6::bigint,
               $7::bytea, $8::bytea,
               $9::text, $9::text,
               'proposed', 0, $10::bytea,
               $11::uuid, pg_catalog.clock_timestamp() + interval '1 day', 1
             )
             RETURNING expires_at`,
            [
              planId,
              tenantId,
              projectId,
              subscriptionId,
              sourceVersion,
              targetVersion,
              Buffer.from(srcSha, "hex"),
              Buffer.from(tgtSha, "hex"),
              scope,
              Buffer.from(candidateSha256, "hex"),
              auth.principal.principalId
            ]
          );

          const dto = {
            plan_id: planId,
            subscription_id: subscriptionId,
            source_version: sourceVersion,
            target_version: targetVersion,
            state: "proposed",
            candidate_sha256: candidateSha256,
            boundary_project_sequence: null,
            materialized_through_event_sequence: "0",
            old_heads_remaining: "0",
            unknown_attempts_remaining: "0",
            expires_at: formatPgTimestamp(insRes.rows[0]?.["expires_at"] ?? now),
            version: "1"
          };

          const receipt = await insertCommandReceiptAndAudit(tx, {
            receiptId,
            scopeKind: "project",
            tenantId,
            projectId,
            actorPrincipalId: auth.principal.principalId,
            commandFamily: "ordering_cutovers.propose",
            idempotencyKey,
            submittedShapeSha256: shapeSha,
            resourceKind: "ordering_cutover_plan",
            resourceId: planId,
            acceptedVersion: 1n,
            safeFacts: { subscription_id: subscriptionId, target_version: targetVersion },
            now
          });
          return { existing: false, dto, receipt };
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

  for (const action of ["begin", "activate", "abort"] as const) {
    app.post<{ Params: { tenant_id: string; project_id: string; plan_id: string } }>(
      `${base}/ordering-cutovers/:plan_id/${action}`,
      async (request, reply) => {
        const tenantId = parseTenantId(request.params.tenant_id, "tenant_id");
        const projectId = parseProjectId(request.params.project_id, "project_id");
        const planId = parseUuidOrThrow(request.params.plan_id, "plan_id");
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
        const govAction = `ordering_cutovers.${action}` as const;
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
                return { receipt: existing, state: action, boundarySeq: "0" };
              }

              const planRes = await tx.query<Record<string, unknown>>(
                `SELECT id, subscription_id, source_version, target_version, state,
                        boundary_project_sequence, version
                 FROM rq.ordering_cutover_plans
                 WHERE id = $1::uuid AND tenant_id = $2::uuid AND project_id = $3::uuid
                 FOR UPDATE`,
                [planId, tenantId, projectId]
              );
              if (planRes.rows.length === 0) {
                throw new NotFoundDomainError({
                  code: "NOT_FOUND",
                  message: `Ordering cutover plan "${planId}" not found`
                });
              }
              const curState = asText(planRes.rows[0]?.["state"]);
              const curVer = BigInt(asText(planRes.rows[0]?.["version"], "1"));

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
                  targetResourceId: planId,
                  targetVersion: curVer,
                  receiptId,
                  expectedCommandSha256: shapeSha
                });
              }

              let nextState = curState;
              let boundarySeq = asText(planRes.rows[0]?.["boundary_project_sequence"], "0");
              if (action === "begin") {
                if (curState !== "proposed") {
                  throw new ConflictDomainError({
                    code: "STATE_TRANSITION_NOT_ALLOWED",
                    message: `Cannot begin cutover plan from state "${curState}"`
                  });
                }
                const seqRes = await tx.query<Record<string, unknown>>(
                  `SELECT next_event_sequence FROM rq.projects WHERE id = $1::uuid`,
                  [projectId]
                );
                boundarySeq = asText(seqRes.rows[0]?.["next_event_sequence"], "1");
                nextState = "draining";
              } else if (action === "activate") {
                if (curState !== "draining" && curState !== "ready") {
                  throw new ConflictDomainError({
                    code: "STATE_TRANSITION_NOT_ALLOWED",
                    message: `Cannot activate cutover plan from state "${curState}"`
                  });
                }
                nextState = "activated";
                await tx.query(
                  `UPDATE rq.subscriptions
                   SET current_version = $2::bigint, updated_at = pg_catalog.clock_timestamp(), version = version + 1
                   WHERE id = $1::uuid AND tenant_id = $3::uuid AND project_id = $4::uuid`,
                  [
                    asText(planRes.rows[0]?.["subscription_id"]),
                    asText(planRes.rows[0]?.["target_version"]),
                    tenantId,
                    projectId
                  ]
                );
              } else {
                if (curState === "activated" || curState === "revoked") {
                  throw new ConflictDomainError({
                    code: "STATE_TRANSITION_NOT_ALLOWED",
                    message: `Cannot abort cutover plan from state "${curState}"`
                  });
                }
                nextState = "revoked";
              }

              await tx.query(
                `UPDATE rq.ordering_cutover_plans
                 SET state = $2::text, boundary_project_sequence = $3::bigint, version = version + 1
                 WHERE id = $1::uuid AND tenant_id = $4::uuid AND project_id = $5::uuid`,
                [planId, nextState, boundarySeq, tenantId, projectId]
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
                resourceKind: "ordering_cutover_plan",
                resourceId: planId,
                acceptedVersion: curVer + 1n,
                priorVersion: curVer,
                safeFacts: { state: nextState, boundary_project_sequence: boundarySeq },
                now
              });
              return { receipt, state: nextState, boundarySeq };
            }
          );

          return sendSuccessEnvelope(
            reply,
            200,
            {
              receipt: out.receipt,
              plan_id: planId,
              state: out.state,
              boundary_project_sequence: out.boundarySeq
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
