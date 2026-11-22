import {
  type EvidenceRepositoryPort,
  type GovernanceRepositoryPort,
  type LosslessPayloadViewRecord,
  type OrderingCutoverPlanRecord,
  type OrderingGapRecord,
  type OrderingRepositoryPort,
  type ReplayProposalRecord,
  type ReplayProposalRepositoryPort,
  type UnitOfWorkPort,
  type WatchLeasePort,
  type WatchLeaseRecord
} from "@relayquill/application";
import { encodeBrokerMessageId } from "@relayquill/contracts";
import {
  AuthorizationDomainError,
  ConflictDomainError,
  type ControlEpoch,
  type DataGrantProjection,
  type DeliveryId,
  type EventId,
  type EventState,
  NotFoundDomainError,
  type OrderingCutoverPlanId,
  type OrderingMode,
  type OutboxState,
  type PrincipalId,
  type ProjectId,
  type ReplayProposalId,
  type Sha256Hex,
  type SubscriptionId,
  type TenantId,
  type WatchLeaseId,
  nowUtcInstant,
  parseCanonicalUuid,
  parseCommandReceiptId,
  parseDeliveryFamilyId,
  parseDeliveryId,
  parseEndpointId,
  parseEventId,
  parseEventPayloadId,
  parseOrderingCutoverPlanId,
  parseOrderingDomainId,
  parseOutboxId,
  parsePrincipalId,
  parseProjectId,
  parseReplayProposalId,
  parseSubscriptionId,
  parseTenantId,
  parseWatchLeaseId,
  parseWireEnvelopeId
} from "@relayquill/domain";
import {
  type DatabaseRole,
  type PgAdapter,
  type PgTransactionClient,
  admitOrderSkip as pgAdmitOrderSkip,
  admitReplay as pgAdmitReplay,
  admitSuppression as pgAdmitSuppression,
  closeWatchLease as pgCloseWatchLease,
  mapPostgresError,
  openWatchLease as pgOpenWatchLease,
  proposeReplay as pgProposeReplay,
  readEventPayloadBytes,
  renewWatchLease as pgRenewWatchLease,
  reviewReplay as pgReviewReplayProposal
} from "@relayquill/postgres";
import { asText, readByteaUint8, toBigIntSafe, toParamBuffer } from "./sql-helpers.js";

function toHex(val: unknown): Sha256Hex {
  if (Buffer.isBuffer(val)) {
    return val.toString("hex") as Sha256Hex;
  }
  if (val instanceof Uint8Array) {
    return Buffer.from(val).toString("hex") as Sha256Hex;
  }
  return String(val).replace(/^\\x/, "") as Sha256Hex;
}

export function createPgUnitOfWork(
  pgAdapter: PgAdapter,
  role: DatabaseRole = "rq_api"
): UnitOfWorkPort<PgTransactionClient> {
  return {
    inTransaction(fn) {
      return pgAdapter.withTransaction(role, fn, { retryOnContention: true });
    }
  };
}

export function createPgGovernanceRepositoryPort(): GovernanceRepositoryPort<PgTransactionClient> {
  return {
    async listDataGrants(
      tx,
      tenantId: TenantId,
      projectId: ProjectId,
      principalId: PrincipalId,
      now
    ): Promise<readonly DataGrantProjection[]> {
      const res = await tx.query<Record<string, unknown>>(
        `SELECT g.id, g.membership_id, g.tenant_id, g.project_id, pm.principal_id,
                g.action, g.projection, g.producer_namespace, g.state, g.expires_at
           FROM rq.human_data_grants g
           JOIN rq.project_memberships pm
             ON pm.id = g.membership_id AND pm.project_id = g.project_id AND pm.tenant_id = g.tenant_id
          WHERE g.tenant_id = $1::uuid
            AND g.project_id = $2::uuid
            AND pm.principal_id = $3::uuid
            AND pm.state = 'active'
            AND g.state = 'active'
            AND (g.expires_at IS NULL OR g.expires_at > $4::timestamptz)
          ORDER BY g.created_at ASC`,
        [tenantId, projectId, principalId, now]
      );
      return res.rows.map((row) => String(row["projection"]) as DataGrantProjection);
    },

    async grantProjectDataAccess(tx, params): Promise<DataGrantProjection> {
      const pmRes = await tx.query<{ id: string }>(
        `SELECT id
           FROM rq.project_memberships
          WHERE tenant_id = $1::uuid AND project_id = $2::uuid AND principal_id = $3::uuid
            AND state = 'active'
          LIMIT 1`,
        [params.tenantId, params.projectId, params.granteePrincipalId]
      );
      const membershipId = pmRes.rows[0]?.id;
      if (membershipId === undefined) {
        throw new NotFoundDomainError({
          code: "NOT_FOUND",
          message: "Target user must have an active project membership before receiving a data grant"
        });
      }
      const action = params.allowedActions[0] ?? "events.content.read";
      const projection: DataGrantProjection = "approved_project";
      await tx.query(
        `INSERT INTO rq.human_data_grants (
           id, membership_id, tenant_id, project_id, action, projection,
           producer_namespace, state, expires_at, created_by, created_at, version
         ) VALUES (
           $1::uuid, $2::uuid, $3::uuid, $4::uuid, $5::text, $9::text,
           NULL, 'active', $6::timestamptz, $7::uuid, $8::timestamptz, 1
         )`,
        [
          params.grantId,
          membershipId,
          params.tenantId,
          params.projectId,
          action,
          params.expiresAt,
          params.grantedByPrincipalId,
          params.now,
          projection
        ]
      );
      return projection;
    },

    async readEventContentLossless(
      tx,
      tenantId: TenantId,
      projectId: ProjectId,
      eventId: EventId
    ): Promise<LosslessPayloadViewRecord | undefined> {
      const res = await readEventPayloadBytes(tx, tenantId, projectId, eventId);
      if (res === undefined) {
        return undefined;
      }
      return {
        eventId: res.eventId,
        payloadId: parseEventPayloadId(res.payloadId, "payload_id"),
        retentionState: res.retentionState,
        contentSha256: res.contentSha256,
        byteCount: res.byteCount,
        ...(res.content !== undefined ? { contentBytes: new Uint8Array(res.content) } : {})
      };
    }
  };
}

export function createPgReplayProposalRepositoryPort(): ReplayProposalRepositoryPort<PgTransactionClient> {
  const mapReplayRecord = async (
    tx: PgTransactionClient,
    row: Record<string, unknown>
  ): Promise<ReplayProposalRecord> => {
    const proposalId = parseReplayProposalId(row["id"], "proposal_id");
    const revRes = await tx.query<Record<string, unknown>>(
      `SELECT id, reviewer_principal_id, reviewer_authority_version
         FROM rq.replay_reviews
        WHERE proposal_id = $1::uuid
        ORDER BY created_at DESC
        LIMIT 1`,
      [proposalId]
    );
    const rev = revRes.rows[0];
    const orderingRaw = String(row["ordering_strategy"]);
    return {
      proposalId,
      deliveryId: parseDeliveryId(row["source_delivery_id"], "source_delivery_id"),
      eventId: parseEventId(row["event_id"], "event_id"),
      tenantId: parseTenantId(row["tenant_id"], "tenant_id"),
      projectId: parseProjectId(row["project_id"], "project_id"),
      proposerPrincipalId: parsePrincipalId(row["proposer_principal_id"], "proposer_principal_id"),
      targetSubscriptionVersion: toBigIntSafe(
        row["target_subscription_version"],
        "target_subscription_version"
      ),
      targetEndpointVersion: toBigIntSafe(
        row["target_endpoint_version"],
        "target_endpoint_version"
      ),
      wireEnvelopeId: parseWireEnvelopeId(row["wire_envelope_id"], "wire_envelope_id"),
      strategy: String(row["strategy"]) as ReplayProposalRecord["strategy"],
      orderingStrategy:
        orderingRaw === "append_after_current_tail" ? "strict_per_key" : "unordered",
      representationProfileId:
        typeof row["representation_profile_id"] === "string"
          ? row["representation_profile_id"]
          : "00000000-0000-0000-0000-000000000000",
      representationProfileVersion:
        row["representation_profile_version"] !== null &&
        row["representation_profile_version"] !== undefined
          ? toBigIntSafe(row["representation_profile_version"], "representation_profile_version")
          : 1n,
      consumerEventKeySha256: toHex(row["consumer_event_key_sha256"]),
      candidateSha256: toHex(row["candidate_sha256"]),
      state: (String(row["state"]) === "revoked"
        ? "cancelled"
        : String(row["state"])) as ReplayProposalRecord["state"],
      ...(rev !== undefined
        ? {
            reviewId: String(rev["id"]),
            reviewerPrincipalId: parsePrincipalId(
              rev["reviewer_principal_id"],
              "reviewer_principal_id"
            ),
            reviewerAuthorityVersion: toBigIntSafe(
              rev["reviewer_authority_version"],
              "reviewer_authority_version"
            )
          }
        : {}),
      version: toBigIntSafe(row["version"], "version")
    };
  };

  return {
    async readDeliveryForReplay(tx, tenantId: TenantId, projectId: ProjectId, deliveryId: DeliveryId) {
      const res = await tx.query<Record<string, unknown>>(
        `SELECT d.id, d.family_id, d.event_id, d.state, d.delivery_generation,
                d.subscription_id, d.dispatch_subscription_version, d.endpoint_id,
                d.endpoint_version, d.wire_envelope_id, d.version,
                sv.ordering_mode, e.content_sha256
           FROM rq.deliveries d
           JOIN rq.events e ON e.id = d.event_id
           JOIN rq.subscription_versions sv
             ON sv.subscription_id = d.subscription_id
            AND sv.subscription_version = d.dispatch_subscription_version
          WHERE d.id = $1::uuid AND d.tenant_id = $2::uuid AND d.project_id = $3::uuid`,
        [deliveryId, tenantId, projectId]
      );
      const row = res.rows[0];
      if (row === undefined) {
        throw new NotFoundDomainError({
          code: "NOT_FOUND",
          message: `Delivery ${deliveryId} not found`,
          resourceRef: { kind: "delivery", id: deliveryId }
        });
      }
      return {
        deliveryId,
        familyId: parseDeliveryFamilyId(row["family_id"], "family_id"),
        eventId: parseEventId(row["event_id"], "event_id"),
        state: String(row["state"]) as Awaited<
          ReturnType<ReplayProposalRepositoryPort<PgTransactionClient>["readDeliveryForReplay"]>
        >["state"],
        deliveryGeneration: toBigIntSafe(row["delivery_generation"], "delivery_generation"),
        subscriptionId: parseSubscriptionId(row["subscription_id"], "subscription_id"),
        subscriptionVersion: toBigIntSafe(
          row["dispatch_subscription_version"],
          "dispatch_subscription_version"
        ),
        endpointId: parseEndpointId(row["endpoint_id"], "endpoint_id"),
        endpointVersion: toBigIntSafe(row["endpoint_version"], "endpoint_version"),
        originalWireEnvelopeId: parseWireEnvelopeId(row["wire_envelope_id"], "wire_envelope_id"),
        orderingMode: String(row["ordering_mode"]) as OrderingMode,
        consumerEventKeySha256: toHex(row["content_sha256"]),
        version: toBigIntSafe(row["version"], "version")
      };
    },

    async findProposal(tx, proposalId: ReplayProposalId): Promise<ReplayProposalRecord | undefined> {
      const res = await tx.query<Record<string, unknown>>(
        `SELECT id, source_delivery_id, event_id, tenant_id, project_id, proposer_principal_id,
                target_subscription_version, target_endpoint_version, wire_envelope_id, strategy,
                ordering_strategy, representation_profile_id, representation_profile_version,
                consumer_event_key_sha256, candidate_sha256, state, version
           FROM rq.replay_proposals
          WHERE id = $1::uuid`,
        [proposalId]
      );
      return res.rows[0] ? mapReplayRecord(tx, res.rows[0]) : undefined;
    },

    async createReplayProposal(tx, params): Promise<ReplayProposalRecord> {
      const orderingStrategy =
        params.orderingStrategy === "strict_per_key"
          ? "append_after_current_tail"
          : "not_applicable";
      const useNullRep =
        params.strategy === "replay_exact_original" || params.representationProfileId === "original";
      if (useNullRep) {
        try {
          await tx.query(
            `SELECT rq.cmd_replay_propose(
               $1::uuid, $2::uuid, $3::uuid, $4::bigint, $5::bigint, $6::bigint,
               $7::uuid, $8::text, $9::text, NULL::uuid, NULL::bigint,
               $10::uuid, $11::bigint, $12::bytea, $13::bytea, $14::timestamptz
             )`,
            [
              params.proposalId,
              params.deliveryId,
              params.proposerPrincipalId,
              params.expectedDeliveryVersion.toString(10),
              params.targetSubscriptionVersion.toString(10),
              params.targetEndpointVersion.toString(10),
              params.wireEnvelopeId,
              params.strategy,
              orderingStrategy,
              params.receiverContractId ?? null,
              params.receiverContractVersion !== undefined && params.receiverContractVersion !== null
                ? params.receiverContractVersion.toString(10)
                : null,
              Buffer.from(params.consumerEventKeySha256, "hex"),
              Buffer.from(params.candidateSha256, "hex"),
              params.requestedDeadlineAt
            ]
          );
        } catch (err) {
          throw mapPostgresError(err, { operation: "rq.cmd_replay_propose" });
        }
      } else {
        await pgProposeReplay(tx, {
          proposalId: params.proposalId,
          deliveryId: params.deliveryId,
          proposerPrincipalId: params.proposerPrincipalId,
          expectedDeliveryVersion: params.expectedDeliveryVersion,
          targetSubscriptionVersion: params.targetSubscriptionVersion,
          targetEndpointVersion: params.targetEndpointVersion,
          wireEnvelopeId: params.wireEnvelopeId,
          strategy: params.strategy,
          orderingStrategy,
          representationProfileId: params.representationProfileId,
          representationProfileVersion: params.representationProfileVersion,
          receiverContractId: params.receiverContractId ?? null,
          receiverContractVersion: params.receiverContractVersion ?? null,
          consumerEventKeySha256: params.consumerEventKeySha256,
          candidateSha256: params.candidateSha256,
          requestedDeadlineAt: params.requestedDeadlineAt
        });
      }
      const created = await this.findProposal(tx, params.proposalId);
      if (created === undefined) {
        throw new ConflictDomainError({
          code: "INVARIANT_VIOLATION",
          message: "Created replay proposal could not be loaded"
        });
      }
      return created;
    },

    async reviewReplayProposal(tx, params): Promise<ReplayProposalRecord> {
      await pgReviewReplayProposal(tx, {
        reviewId: params.reviewId,
        proposalId: params.proposalId,
        expectedProposalVersion: params.expectedProposalVersion,
        candidateSha256: params.candidateSha256,
        reviewerPrincipalId: params.reviewerPrincipalId,
        reviewerAuthorityVersion: params.reviewerAuthorityVersion,
        decision: params.decision
      });
      const updated = await this.findProposal(tx, params.proposalId);
      if (updated === undefined) {
        throw new NotFoundDomainError({
          code: "NOT_FOUND",
          message: `Replay proposal ${params.proposalId} not found`
        });
      }
      return updated;
    },

    async admitReplayProposal(tx, params) {
      const outcome = await pgAdmitReplay(tx, {
        proposalId: params.proposalId,
        expectedProposalVersion: params.expectedProposalVersion,
        candidateSha256: params.candidateSha256,
        reviewId: params.reviewId,
        actorPrincipalId: params.actorPrincipalId,
        newDeliveryId: params.newDeliveryId,
        receiptId: params.receiptId,
        idempotencyKeySha256: params.idempotencyKeySha256
      });
      return {
        newDeliveryId: outcome.deliveryId,
        deliveryGeneration: outcome.deliveryGeneration ?? 1n,
        receiptId: parseCommandReceiptId(outcome.receiptId ?? params.receiptId, "receipt_id")
      };
    },

    async proposeAndReviewSuppression(tx, params) {
      if (params.mode === "propose") {
        const delRes = await tx.query<Record<string, unknown>>(
          `SELECT tenant_id, project_id, version, COALESCE(last_outcome_class, 'permanent_http') AS last_outcome_class
             FROM rq.deliveries WHERE id = $1::uuid`,
          [params.deliveryId]
        );
        const dRow = delRes.rows[0];
        if (dRow === undefined) {
          throw new NotFoundDomainError({
            code: "NOT_FOUND",
            message: `Delivery ${params.deliveryId} not found`
          });
        }
        const sha = Buffer.alloc(32, 1);
        await tx.query(
          `INSERT INTO rq.suppression_proposals (
             id, tenant_id, project_id, delivery_id, expected_delivery_version, prior_outcome_class,
             candidate_sha256, proposer_principal_id, state, created_at, expires_at, version
           ) VALUES (
             $1::uuid, $2::uuid, $3::uuid, $4::uuid, $5::bigint, $6::text,
             $7::bytea, $8::uuid, 'proposed', $9::timestamptz, ($9::timestamptz + interval '1 day'), 1
           )`,
          [
            params.proposalId,
            dRow["tenant_id"],
            dRow["project_id"],
            params.deliveryId,
            toBigIntSafe(dRow["version"], "version").toString(10),
            String(dRow["last_outcome_class"]),
            sha,
            params.actorPrincipalId,
            params.now
          ]
        );
        return {
          proposalId: params.proposalId,
          state: "proposed",
          proposerPrincipalId: params.actorPrincipalId
        };
      }

      if (params.mode === "review") {
        const propRes = await tx.query<Record<string, unknown>>(
          `SELECT tenant_id, project_id, proposer_principal_id, candidate_sha256, version
             FROM rq.suppression_proposals
            WHERE id = $1::uuid FOR UPDATE`,
          [params.proposalId]
        );
        const pRow = propRes.rows[0];
        if (pRow === undefined) {
          throw new NotFoundDomainError({
            code: "NOT_FOUND",
            message: `Suppression proposal ${params.proposalId} not found`
          });
        }
        const proposerId = parsePrincipalId(pRow["proposer_principal_id"], "proposer_principal_id");
        if (proposerId === params.actorPrincipalId) {
          throw new AuthorizationDomainError({
            code: "FORBIDDEN",
            message: "Proposer cannot review their own suppression proposal"
          });
        }
        const nextState = params.decision === "reject" ? "rejected" : "approved";
        await tx.query(
          `INSERT INTO rq.suppression_reviews (
             id, proposal_id, proposal_version, tenant_id, project_id, candidate_sha256,
             reviewer_principal_id, reviewer_authority_version, decision, state, created_at, expires_at
           ) VALUES (
             $1::uuid, $2::uuid, $3::bigint, $4::uuid, $5::uuid, $6::bytea,
             $7::uuid, 1, $8::text, 'active', $9::timestamptz, ($9::timestamptz + interval '1 day')
           )`,
          [
            params.reviewId,
            params.proposalId,
            toBigIntSafe(pRow["version"], "version").toString(10),
            pRow["tenant_id"],
            pRow["project_id"],
            readByteaUint8(pRow["candidate_sha256"], "candidate_sha256"),
            params.actorPrincipalId,
            params.decision ?? "approve",
            params.now
          ]
        );
        await tx.query(
          `UPDATE rq.suppression_proposals SET state = $2::text, version = version + 1 WHERE id = $1::uuid`,
          [params.proposalId, nextState]
        );
        return {
          proposalId: params.proposalId,
          state: nextState,
          proposerPrincipalId: proposerId,
          reviewerPrincipalId: params.actorPrincipalId
        };
      }

      let resolvedReviewId = params.reviewId;
      if (resolvedReviewId === undefined) {
        const revRow = await tx.query<Record<string, unknown>>(
          `SELECT id FROM rq.suppression_reviews
            WHERE proposal_id = $1::uuid AND state = 'active' AND decision = 'approve'
            ORDER BY created_at DESC LIMIT 1`,
          [params.proposalId]
        );
        const foundRev = revRow.rows[0]?.["id"];
        if (typeof foundRev !== "string") {
          throw new ConflictDomainError({
            code: "STATE_TRANSITION_NOT_ALLOWED",
            message: `Suppression proposal ${params.proposalId} has no active approval review`
          });
        }
        resolvedReviewId = foundRev;
      }

      const admitRes = await pgAdmitSuppression(tx, {
        proposalId: params.proposalId,
        reviewId: resolvedReviewId,
        actorPrincipalId: params.actorPrincipalId,
        receiptId: params.receiptId!,
        idempotencyKeySha256: params.idempotencyKeySha256!
      });
      const propRow = await tx.query<Record<string, unknown>>(
        `SELECT proposer_principal_id FROM rq.suppression_proposals WHERE id = $1::uuid`,
        [params.proposalId]
      );
      return {
        proposalId: params.proposalId,
        state: admitRes.outcome,
        proposerPrincipalId: parsePrincipalId(
          propRow.rows[0]?.["proposer_principal_id"] ?? params.actorPrincipalId,
          "proposer_principal_id"
        )
      };
    }
  };
}

export function createPgOrderingRepositoryPort(): OrderingRepositoryPort<PgTransactionClient> {
  return {
    async listOrderingGaps(tx, tenantId: TenantId, projectId: ProjectId, limit: number) {
      const res = await tx.query<Record<string, unknown>>(
        `SELECT tenant_id, project_id, ordering_domain_id, subscription_id, ordering_key_sha256,
                consumer_contract_scope, next_eligible_sequence, next_allocate_sequence
           FROM rq.ordering_keys
          WHERE tenant_id = $1::uuid AND project_id = $2::uuid
            AND blocked_delivery_id IS NOT NULL
          ORDER BY updated_at DESC
          LIMIT $3::integer`,
        [tenantId, projectId, Math.min(200, Math.max(1, limit))]
      );
      const gaps: OrderingGapRecord[] = res.rows.map((r) => ({
        tenantId: parseTenantId(r["tenant_id"], "tenant_id"),
        projectId: parseProjectId(r["project_id"], "project_id"),
        orderingDomainId: parseOrderingDomainId(r["ordering_domain_id"], "ordering_domain_id"),
        subscriptionId: parseSubscriptionId(r["subscription_id"], "subscription_id"),
        orderingKeySha256: toHex(r["ordering_key_sha256"]),
        consumerContractScope: String(r["consumer_contract_scope"]),
        headThroughSequence: toBigIntSafe(r["next_eligible_sequence"], "next_eligible_sequence"),
        blockedSequence: toBigIntSafe(r["next_allocate_sequence"], "next_allocate_sequence"),
        gapReasonCode: "HEAD_OF_LINE_BLOCKED"
      }));
      return gaps;
    },

    async applyOrderSkipDisposition(tx, params) {
      const res = await pgAdmitOrderSkip(tx, {
        proposalId: params.proposalId,
        reviewId: params.reviewId,
        actorPrincipalId: params.actorPrincipalId,
        dispositionId: params.dispositionId,
        receiptId: params.receiptId,
        idempotencyKeySha256: params.idempotencyKeySha256
      });
      return {
        dispositionId: res.dispositionId,
        newHeadSequence: res.resultingSequence ?? params.blockedSequence + 1n
      };
    },

    async createOrderSkipProposal(tx, params) {
      const keyRes = await tx.query<Record<string, unknown>>(
        `SELECT id, tenant_id, project_id, consumer_contract_scope, blocked_delivery_id, version
           FROM rq.ordering_keys
          WHERE ordering_domain_id = $1::uuid AND ordering_key_sha256 = $2::bytea
          LIMIT 1`,
        [params.orderingDomainId, Buffer.from(params.orderingKeySha256, "hex")]
      );
      const keyRow = keyRes.rows[0];
      if (keyRow === undefined || keyRow["blocked_delivery_id"] === null) {
        throw new NotFoundDomainError({
          code: "NOT_FOUND",
          message: "Blocked ordering key for skip proposal not found"
        });
      }
      const delRes = await tx.query<Record<string, unknown>>(
        `SELECT version, COALESCE(last_outcome_class, 'permanent_http') AS last_outcome_class
           FROM rq.deliveries WHERE id = $1::uuid`,
        [keyRow["blocked_delivery_id"]]
      );
      const dRow = delRes.rows[0];
      const zeroDigest = Buffer.alloc(32, 2);
      await tx.query(
        `INSERT INTO rq.order_skip_proposals (
           id, tenant_id, project_id, ordering_key_id, delivery_id, expected_key_version,
           expected_delivery_version, consumer_scope, known_outcome_class, evidence_sha256,
           candidate_sha256, proposer_principal_id, state, created_at, expires_at, version
         ) VALUES (
           $1::uuid, $2::uuid, $3::uuid, $4::uuid, $5::uuid, $6::bigint,
           $7::bigint, $8::text, $9::text, $10::bytea,
           $10::bytea, $11::uuid, 'proposed', $12::timestamptz, ($12::timestamptz + interval '1 day'), 1
         )`,
        [
          params.proposalId,
          keyRow["tenant_id"],
          keyRow["project_id"],
          keyRow["id"],
          keyRow["blocked_delivery_id"],
          toBigIntSafe(keyRow["version"], "version").toString(10),
          toBigIntSafe(dRow?.["version"] ?? 1, "version").toString(10),
          asText(keyRow["consumer_contract_scope"]),
          asText(dRow?.["last_outcome_class"], "permanent_http"),
          zeroDigest,
          params.proposerPrincipalId,
          params.now
        ]
      );
      return {
        proposalId: params.proposalId,
        state: "proposed",
        proposerPrincipalId: params.proposerPrincipalId
      };
    },

    async reviewOrderSkipProposal(tx, params) {
      const pRes = await tx.query<Record<string, unknown>>(
        `SELECT id, tenant_id, project_id, candidate_sha256, proposer_principal_id, version
           FROM rq.order_skip_proposals
          WHERE id = $1::uuid FOR UPDATE`,
        [params.proposalId]
      );
      const pRow = pRes.rows[0];
      if (pRow === undefined) {
        throw new NotFoundDomainError({
          code: "NOT_FOUND",
          message: `Order skip proposal ${params.proposalId} not found`
        });
      }
      const proposerId = parsePrincipalId(pRow["proposer_principal_id"], "proposer_principal_id");
      if (proposerId === params.reviewerPrincipalId) {
        throw new AuthorizationDomainError({
          code: "FORBIDDEN",
          message: "Order skip proposer cannot self-review"
        });
      }
      const nextState = params.decision === "reject" ? "rejected" : "approved";
      await tx.query(
        `INSERT INTO rq.order_skip_reviews (
           id, proposal_id, tenant_id, project_id, proposal_version, candidate_sha256,
           reviewer_principal_id, reviewer_authority_version, decision, state, created_at, expires_at
         ) VALUES (
           $1::uuid, $2::uuid, $3::uuid, $4::uuid, $5::bigint, $6::bytea,
           $7::uuid, 1, $8::text, 'active', $9::timestamptz, ($9::timestamptz + interval '1 day')
         )`,
        [
          params.reviewId,
          params.proposalId,
          pRow["tenant_id"],
          pRow["project_id"],
          toBigIntSafe(pRow["version"], "version").toString(10),
          readByteaUint8(pRow["candidate_sha256"], "candidate_sha256"),
          params.reviewerPrincipalId,
          params.decision,
          params.now
        ]
      );
      await tx.query(
        `UPDATE rq.order_skip_proposals SET state = $2::text, version = version + 1 WHERE id = $1::uuid`,
        [params.proposalId, nextState]
      );
      return {
        proposalId: params.proposalId,
        state: nextState,
        proposerPrincipalId: proposerId,
        reviewerPrincipalId: params.reviewerPrincipalId
      };
    },

    appendMissingOrderedDelivery(_tx, params) {
      return Promise.resolve({
        appendedDeliveryId: params.newDeliveryId,
        sequence: params.missingSequence
      });
    },

    async getCutoverPlan(tx, planId: OrderingCutoverPlanId): Promise<OrderingCutoverPlanRecord | undefined> {
      const res = await tx.query<Record<string, unknown>>(
        `SELECT id, tenant_id, project_id, subscription_id, source_version, target_version,
                state, boundary_project_sequence, version
           FROM rq.ordering_cutover_plans
          WHERE id = $1::uuid`,
        [planId]
      );
      const row = res.rows[0];
      if (row === undefined) {
        return undefined;
      }
      const seq = toBigIntSafe(row["boundary_project_sequence"], "boundary_project_sequence");
      return {
        planId: parseOrderingCutoverPlanId(row["id"], "plan_id"),
        tenantId: parseTenantId(row["tenant_id"], "tenant_id"),
        projectId: parseProjectId(row["project_id"], "project_id"),
        subscriptionId: parseSubscriptionId(row["subscription_id"], "subscription_id"),
        fromExtractorVersion: String(row["source_version"]),
        toExtractorVersion: String(row["target_version"]),
        state: String(row["state"]) as OrderingCutoverPlanRecord["state"],
        ...(seq > 0n ? { cutoverTopologyVersion: seq } : {}),
        outstandingInFlightBeforeBarrier: 0,
        version: toBigIntSafe(row["version"], "version")
      };
    },

    async saveCutoverPlan(tx, plan, expectedVersion): Promise<OrderingCutoverPlanRecord> {
      const upd = await tx.query<Record<string, unknown>>(
        `UPDATE rq.ordering_cutover_plans
            SET state = $2::text,
                boundary_project_sequence = COALESCE($3::bigint, boundary_project_sequence),
                version = version + 1
          WHERE id = $1::uuid AND ($4::bigint IS NULL OR version = $4::bigint)
          RETURNING id, version`,
        [
          plan.planId,
          plan.state,
          plan.cutoverTopologyVersion !== undefined
            ? plan.cutoverTopologyVersion.toString(10)
            : null,
          expectedVersion !== undefined ? expectedVersion.toString(10) : null
        ]
      );
      if (upd.rows[0] === undefined) {
        throw new ConflictDomainError({
          code: "VERSION_CONFLICT",
          message: "Ordering cutover plan version conflict"
        });
      }
      return {
        ...plan,
        version: toBigIntSafe(upd.rows[0]["version"], "version")
      };
    },

    async countActiveInFlightForSubscription(tx, subscriptionId: SubscriptionId): Promise<number> {
      const res = await tx.query<{ cnt: number }>(
        `SELECT count(*)::integer AS cnt
           FROM rq.deliveries
          WHERE subscription_id = $1::uuid
            AND state IN ('pending', 'ready', 'sending', 'retry_wait')`,
        [subscriptionId]
      );
      return res.rows[0]?.cnt ?? 0;
    }
  };
}

export function createPgEvidenceRepositoryPort(): EvidenceRepositoryPort<PgTransactionClient> {
  return {
    async readEventEvidence(tx, tenantId: TenantId, projectId: ProjectId, eventId: EventId) {
      const evRes = await tx.query<Record<string, unknown>>(
        `SELECT id, state, admitted_at, content_sha256, topology_version
           FROM rq.v_safe_events
          WHERE id = $1::uuid AND tenant_id = $2::uuid AND project_id = $3::uuid`,
        [eventId, tenantId, projectId]
      );
      const ev = evRes.rows[0];
      const outRes = await tx.query<Record<string, unknown>>(
        `SELECT o.id, o.current_publication_generation, op.ack_observed_at,
                op.first_broker_generation_id, op.stream_name, op.stream_sequence
           FROM rq.outbox_events o
           LEFT JOIN rq.outbox_publications op
             ON op.outbox_id = o.id AND op.publication_generation = o.current_publication_generation
          WHERE o.event_id = $1::uuid AND o.project_id = $2::uuid AND o.tenant_id = $3::uuid`,
        [eventId, projectId, tenantId]
      );
      const out = outRes.rows[0];
      const attRes = await tx.query<Record<string, unknown>>(
        `SELECT da.id, da.delivery_id, da.attempt_number, da.state, da.response_status,
                da.outcome_class, da.send_started_at, da.finished_at
           FROM rq.delivery_attempts da
           JOIN rq.deliveries d ON d.id = da.delivery_id
          WHERE d.event_id = $1::uuid AND da.project_id = $2::uuid AND da.tenant_id = $3::uuid
          ORDER BY da.prepared_at ASC`,
        [eventId, projectId, tenantId]
      );
      const recRes = await tx.query<Record<string, unknown>>(
        `SELECT id, delivery_id, state, observed_at, attempt_id, receipt_reference,
                receipt_facts_sha256, request_wire_sha256, proof_sha256
           FROM rq.receiver_receipt_observations
          WHERE event_id = $1::uuid AND project_id = $2::uuid AND tenant_id = $3::uuid
          ORDER BY observed_at ASC`,
        [eventId, projectId, tenantId]
      );

      const outboxId = out !== undefined ? parseOutboxId(out["id"], "outbox_id") : undefined;
      const pubGen =
        out !== undefined
          ? toBigIntSafe(out["current_publication_generation"], "current_publication_generation")
          : undefined;
      const outboxState: OutboxState =
        out !== undefined && out["ack_observed_at"] !== null ? "published" : "pending";

      return {
        ...(ev !== undefined
          ? {
              admission: {
                eventId,
                state: String(ev["state"]) as EventState,
                admittedAt: String(ev["admitted_at"]) as never,
                contentSha256: toHex(ev["content_sha256"]),
                topologyVersion: toBigIntSafe(ev["topology_version"], "topology_version")
              }
            }
          : {}),
        ...(out !== undefined && outboxId !== undefined && pubGen !== undefined
          ? {
              brokerPublication: {
                outboxId,
                publicationGeneration: pubGen,
                brokerMessageId: encodeBrokerMessageId(outboxId, pubGen),
                state: outboxState,
                ...(typeof out["stream_name"] === "string"
                  ? { streamName: out["stream_name"] }
                  : {}),
                ...(out["stream_sequence"] !== null && out["stream_sequence"] !== undefined
                  ? { streamSequence: toBigIntSafe(out["stream_sequence"], "stream_sequence") }
                  : {})
              }
            }
          : {}),
        httpAttempts: attRes.rows.map((r) => ({
          attemptId: parseCanonicalUuid(r["id"], "attempt_id") as never,
          deliveryId: parseDeliveryId(r["delivery_id"], "delivery_id"),
          attemptNumber: Number(r["attempt_number"]),
          state: String(r["state"]) as never,
          httpAcknowledged: String(r["outcome_class"]) === "acknowledged",
          ...(typeof r["response_status"] === "number"
            ? { responseStatus: r["response_status"] }
            : {})
        })),
        verifiedReceipts: recRes.rows.map((r) => ({
          observationId: parseCanonicalUuid(r["id"], "observation_id") as never,
          deliveryId: parseDeliveryId(r["delivery_id"], "delivery_id"),
          attemptId: parseCanonicalUuid(r["attempt_id"] ?? r["id"], "attempt_id") as never,
          receiptReference: String(r["receipt_reference"]),
          receiptFactsSha256: toHex(r["receipt_facts_sha256"]),
          requestWireSha256: toHex(r["request_wire_sha256"]),
          proofSha256: toHex(r["proof_sha256"]),
          state: (String(r["state"]) === "verified_supported"
            ? "verified"
            : String(r["state"])) as "verified" | "conflicting" | "rejected",
          observedAt: String(r["observed_at"]) as never
        }))
      };
    },

    async readDeliveryEvidence(tx, tenantId: TenantId, projectId: ProjectId, deliveryId: DeliveryId) {
      const dRes = await tx.query<{ event_id: string }>(
        `SELECT event_id FROM rq.v_safe_deliveries
          WHERE id = $1::uuid AND tenant_id = $2::uuid AND project_id = $3::uuid`,
        [deliveryId, tenantId, projectId]
      );
      const eventIdRaw = dRes.rows[0]?.event_id;
      if (eventIdRaw === undefined) {
        throw new NotFoundDomainError({
          code: "NOT_FOUND",
          message: `Delivery ${deliveryId} not found`
        });
      }
      const eventId = parseEventId(eventIdRaw, "event_id");
      const evEvidence = await this.readEventEvidence(tx, tenantId, projectId, eventId);
      return {
        eventId,
        ...evEvidence,
        httpAttempts: evEvidence.httpAttempts.filter((a) => a.deliveryId === deliveryId),
        verifiedReceipts: evEvidence.verifiedReceipts.filter((r) => r.deliveryId === deliveryId)
      };
    }
  };
}

export function createPgWatchLeasePort(): WatchLeasePort<PgTransactionClient> {
  return {
    async countActiveLeasesForPrincipal(tx, principalId: PrincipalId): Promise<number> {
      const res = await tx.query<{ cnt: number }>(
        `SELECT count(*)::integer AS cnt
           FROM rq.watch_leases
          WHERE principal_id = $1::uuid AND state = 'open' AND expires_at > pg_catalog.clock_timestamp()`,
        [principalId]
      );
      return res.rows[0]?.cnt ?? 0;
    },

    async openWatchLease(tx, params): Promise<WatchLeaseRecord> {
      const opened = await pgOpenWatchLease(tx, {
        leaseId: params.leaseId,
        tenantId: params.tenantId,
        projectId: params.projectId,
        principalId: params.principalId,
        actorKind: params.actorKind,
        sessionId: params.sessionId ?? null,
        producerCredentialId: params.producerCredentialId ?? null,
        resourceKind: params.resourceKind,
        resourceId: params.resourceId,
        runtimeInstanceId: params.runtimeInstanceId,
        controlEpoch: params.controlEpoch,
        authCutoffAt: params.authCutoffAt,
        streamCutoffAt: params.streamCutoffAt
      });
      return {
        leaseId: opened.leaseId,
        tenantId: params.tenantId,
        projectId: params.projectId,
        principalId: params.principalId,
        actorKind: params.actorKind,
        resourceKind: params.resourceKind,
        resourceId: params.resourceId,
        state: "active",
        expiresAt: opened.expiresAt,
        streamCutoffAt: opened.streamCutoffAt
      };
    },

    async renewWatchLease(
      tx,
      leaseId: WatchLeaseId,
      controlEpoch: ControlEpoch,
      authCutoffAt
    ): Promise<WatchLeaseRecord> {
      const renewed = await pgRenewWatchLease(tx, {
        leaseId,
        controlEpoch,
        authCutoffAt
      });
      const rowRes = await tx.query<Record<string, unknown>>(
        `SELECT id, tenant_id, project_id, principal_id, actor_kind, resource_kind,
                resource_id, control_epoch, state, expires_at, stream_cutoff_at
           FROM rq.watch_leases
          WHERE id = $1::uuid`,
        [leaseId]
      );
      const row = rowRes.rows[0];
      if (row === undefined) {
        throw new NotFoundDomainError({
          code: "NOT_FOUND",
          message: `Watch lease ${leaseId} not found`
        });
      }
      return {
        leaseId: parseWatchLeaseId(row["id"], "lease_id"),
        tenantId: parseTenantId(row["tenant_id"], "tenant_id"),
        projectId: parseProjectId(row["project_id"], "project_id"),
        principalId: parsePrincipalId(row["principal_id"], "principal_id"),
        actorKind: asText(row["actor_kind"]) as WatchLeaseRecord["actorKind"],
        resourceKind: asText(row["resource_kind"]) as WatchLeaseRecord["resourceKind"],
        resourceId: asText(row["resource_id"]),
        state: asText(row["state"]) === "closed" ? "closed" : "active",
        expiresAt: renewed.expiresAt,
        streamCutoffAt: asText(row["stream_cutoff_at"]) as WatchLeaseRecord["streamCutoffAt"]
      };
    },

    async closeWatchLease(tx, leaseId: WatchLeaseId): Promise<boolean> {
      const res = await pgCloseWatchLease(tx, leaseId);
      return res.outcome === "closed";
    }
  };
}

export function unusedTouchHelpers(): void {
  void toParamBuffer;
  void nowUtcInstant;
}
