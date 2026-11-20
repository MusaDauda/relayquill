import {
  AuthorizationDomainError,
  ConflictDomainError,
  type CanonicalUtcTimestamp,
  type CommandReceiptId,
  type DeliveryId,
  NotFoundDomainError,
  type OperationProofId,
  type OrderingMode,
  type PrincipalId,
  type ProjectId,
  type ProposalState,
  type ReplayOrderingStrategy,
  type ReplayProposalId,
  type ReplayStrategy,
  type Sha256Hex,
  type TenantId,
  ValidationDomainError,
  addMilliseconds,
  admitReplayProposal,
  admitSuppressionProposal,
  computeProposalExpiresAt,
  formatUtcTimestamp,
  parseCommandReceiptId,
  parseDeliveryId,
  parseOperationProofId,
  parsePrincipalId,
  parseProjectId,
  parseReplayProposalId,
  parseSha256Hex,
  parseTenantId,
  parseUtcTimestamp
} from "@relayquill/domain";
import {
  type AuthenticatedHumanSession,
  authorizeHumanAction,
  authorizeProposalAdmission,
  authorizeProposalReview,
  hasActiveProjectDataGrant,
  verifyAndConsumeOperationProof
} from "@relayquill/auth";
import {
  computeCommandGuardKey,
  hashCanonicalJson,
  parseCanonicalUtcTimestamp,
  parseCanonicalUuid,
  sha256Utf8Hex
} from "@relayquill/contracts";
import {
  type AuthRepositoriesBundle,
  type ClockPort,
  type IdGeneratorPort,
  type InstallationAuthoritySnapshot,
  type ReplayProposalRecord,
  type ReplayProposalRepositoryPort,
  type TelemetryPort,
  type UnitOfWorkPort,
  cryptoIdGeneratorPort,
  noopTelemetryPort,
  systemClockPort
} from "./ports.js";

export interface ReplayServiceDeps<TTx> {
  readonly uow: UnitOfWorkPort<TTx>;
  readonly replayRepo: ReplayProposalRepositoryPort<TTx>;
  readonly authRepos: AuthRepositoriesBundle;
  readonly readInstallationAuthority: (tx: TTx) => Promise<InstallationAuthoritySnapshot>;
  readonly clock?: ClockPort | undefined;
  readonly idGenerator?: IdGeneratorPort | undefined;
  readonly telemetry?: TelemetryPort | undefined;
}

export interface ProposeReplayInput {
  readonly session: AuthenticatedHumanSession;
  readonly tenantId: TenantId | string;
  readonly projectId: ProjectId | string;
  readonly deliveryId: DeliveryId | string;
  readonly targetSubscriptionVersion?: bigint | undefined;
  readonly targetEndpointVersion?: bigint | undefined;
  readonly wireEnvelopeId?: ReplayProposalRecord["wireEnvelopeId"] | string | undefined;
  readonly strategy: ReplayStrategy;
  readonly orderingStrategy?: ReplayOrderingStrategy | undefined;
  readonly representationProfileId?: string | undefined;
  readonly representationProfileVersion?: bigint | undefined;
  readonly receiverContractId?: string | null | undefined;
  readonly receiverContractVersion?: bigint | null | undefined;
  readonly requestedDeadlineAt?: CanonicalUtcTimestamp | string | undefined;
}

export interface ReviewReplayProposalInput {
  readonly session: AuthenticatedHumanSession;
  readonly tenantId: TenantId | string;
  readonly projectId: ProjectId | string;
  readonly proposalId: ReplayProposalId | string;
  readonly expectedProposalVersion: bigint;
  readonly expectedCandidateSha256: Sha256Hex | string;
  readonly decision: "approve" | "reject";
  readonly stepUpProofId: OperationProofId | string;
  readonly authorityVersion?: bigint | undefined;
}

export interface AdmitApprovedReplayInput {
  readonly session: AuthenticatedHumanSession;
  readonly tenantId: TenantId | string;
  readonly projectId: ProjectId | string;
  readonly proposalId: ReplayProposalId | string;
  readonly expectedProposalVersion: bigint;
  readonly expectedCandidateSha256: Sha256Hex | string;
  readonly destinationChanged?: boolean | undefined;
  readonly stepUpProofId: OperationProofId | string;
  readonly idempotencyKey: string;
}

export interface ProposeSuppressionInput {
  readonly session: AuthenticatedHumanSession;
  readonly tenantId: TenantId | string;
  readonly projectId: ProjectId | string;
  readonly deliveryId: DeliveryId | string;
  readonly reasonCode: string;
}

export interface ReviewSuppressionInput {
  readonly session: AuthenticatedHumanSession;
  readonly tenantId: TenantId | string;
  readonly projectId: ProjectId | string;
  readonly proposalId: string;
  readonly deliveryId: DeliveryId | string;
  readonly expectedVersion?: bigint | undefined;
  readonly decision: "approve" | "reject";
  readonly stepUpProofId: OperationProofId | string;
}

export interface AdmitSuppressionInput {
  readonly session: AuthenticatedHumanSession;
  readonly tenantId: TenantId | string;
  readonly projectId: ProjectId | string;
  readonly proposalId: string;
  readonly deliveryId: DeliveryId | string;
  readonly expectedVersion?: bigint | undefined;
  readonly stepUpProofId: OperationProofId | string;
  readonly idempotencyKey: string;
}

function mapRepoProposalStateToDomain(state: ReplayProposalRecord["state"]): ProposalState {
  if (state === "cancelled") {
    return "revoked";
  }
  return state;
}

function resolveReplayOrderingStrategy(
  orderingMode: OrderingMode,
  requested?: ReplayOrderingStrategy
): ReplayOrderingStrategy {
  if (orderingMode === "strict_per_key") {
    if (requested !== undefined && requested !== "append_after_current_tail") {
      throw new ConflictDomainError({
        code: "STATE_TRANSITION_NOT_ALLOWED",
        message: "Strict per-key replay requires orderingStrategy=\"append_after_current_tail\""
      });
    }
    return "append_after_current_tail";
  }
  return requested ?? "not_applicable";
}

export class ReplayGovernanceService<TTx> {
  readonly #uow: UnitOfWorkPort<TTx>;
  readonly #replayRepo: ReplayProposalRepositoryPort<TTx>;
  readonly #authRepos: AuthRepositoriesBundle;
  readonly #readInstallationAuthority: (tx: TTx) => Promise<InstallationAuthoritySnapshot>;
  readonly #clock: ClockPort;
  readonly #ids: IdGeneratorPort;
  readonly #telemetry: TelemetryPort;

  constructor(deps: ReplayServiceDeps<TTx>) {
    this.#uow = deps.uow;
    this.#replayRepo = deps.replayRepo;
    this.#authRepos = deps.authRepos;
    this.#readInstallationAuthority = deps.readInstallationAuthority;
    this.#clock = deps.clock ?? systemClockPort;
    this.#ids = deps.idGenerator ?? cryptoIdGeneratorPort;
    this.#telemetry = deps.telemetry ?? noopTelemetryPort;
  }

  /**
   * Creates a replay proposal after verifying RBAC and active `events.content.read`
   * grants when `replay_with_reviewed_representation` is requested.
   */
  async proposeReplay(input: ProposeReplayInput): Promise<ReplayProposalRecord> {
    const span = this.#telemetry.startSpan("relayquill.replays.propose");
    try {
      const tenantId = parseTenantId(input.tenantId, "tenantId");
      const projectId = parseProjectId(input.projectId, "projectId");
      const deliveryId = parseDeliveryId(input.deliveryId, "deliveryId");
      const nowInstant = this.#clock.nowInstant();
      const now = parseCanonicalUtcTimestamp(formatUtcTimestamp(nowInstant), "now");
      const proposalId = parseReplayProposalId(this.#ids.nextUuid(), "proposalId");

      const installation = await this.#uow.inTransaction((tx) =>
        this.#readInstallationAuthority(tx)
      );

      await authorizeHumanAction({
        installation,
        principalId: input.session.principal.principalId,
        action: "deliveries.replay.propose",
        tenantId,
        projectId,
        repo: this.#authRepos.humanAuthorization,
        now: nowInstant
      });

      if (input.strategy === "replay_with_reviewed_representation") {
        const hasGrant = await hasActiveProjectDataGrant({
          principalId: input.session.principal.principalId,
          tenantId,
          projectId,
          action: "events.content.read",
          repo: this.#authRepos.humanAuthorization,
          now: nowInstant
        });
        if (!hasGrant) {
          throw new AuthorizationDomainError({
            code: "FORBIDDEN",
            message: "replay_with_reviewed_representation requires active events.content.read grant"
          });
        }
      }

      const created = await this.#uow.inTransaction(async (tx) => {
        const delivery = await this.#replayRepo.readDeliveryForReplay(
          tx,
          tenantId,
          projectId,
          deliveryId
        );
        resolveReplayOrderingStrategy(delivery.orderingMode, input.orderingStrategy);

        const targetSubscriptionVersion =
          input.targetSubscriptionVersion ?? delivery.subscriptionVersion;
        const targetEndpointVersion = input.targetEndpointVersion ?? delivery.endpointVersion;
        const wireEnvelopeId = (input.wireEnvelopeId ??
          delivery.originalWireEnvelopeId) as ReplayProposalRecord["wireEnvelopeId"];
        const representationProfileId = input.representationProfileId ?? "original";
        const representationProfileVersion = input.representationProfileVersion ?? 1n;

        const candidateSha256 = hashCanonicalJson(
          {
            delivery_id: deliveryId,
            event_id: delivery.eventId,
            target_subscription_version: targetSubscriptionVersion.toString(10),
            target_endpoint_version: targetEndpointVersion.toString(10),
            wire_envelope_id: wireEnvelopeId,
            strategy: input.strategy,
            ordering_strategy: delivery.orderingMode,
            representation_profile_id: representationProfileId,
            representation_profile_version: representationProfileVersion.toString(10),
            consumer_event_key_sha256: delivery.consumerEventKeySha256
          },
          "replay_proposal_candidate"
        ).sha256;

        const requestedDeadlineAt =
          input.requestedDeadlineAt !== undefined
            ? parseCanonicalUtcTimestamp(input.requestedDeadlineAt, "requestedDeadlineAt")
            : parseCanonicalUtcTimestamp(
                formatUtcTimestamp(addMilliseconds(nowInstant, 3_600_000n, "requested_deadline")),
                "requestedDeadlineAt"
              );

        return this.#replayRepo.createReplayProposal(tx, {
          proposalId,
          deliveryId,
          proposerPrincipalId: input.session.principal.principalId,
          expectedDeliveryVersion: delivery.version,
          targetSubscriptionVersion,
          targetEndpointVersion,
          wireEnvelopeId,
          strategy: input.strategy,
          orderingStrategy: delivery.orderingMode,
          representationProfileId,
          representationProfileVersion,
          receiverContractId: input.receiverContractId ?? null,
          receiverContractVersion: input.receiverContractVersion ?? null,
          consumerEventKeySha256: delivery.consumerEventKeySha256,
          candidateSha256,
          requestedDeadlineAt,
          now
        });
      });

      span.end({ code: "OK" });
      return created;
    } catch (err) {
      span.end({
        code: "ERROR",
        message: err instanceof Error ? err.message : "propose_replay_failed"
      });
      throw err;
    }
  }

  /**
   * Reviews a replay proposal enforcing two-person separation (`proposer !== reviewer`),
   * RBAC project-admin verification, and single-use step-up operation proof consumption.
   */
  async reviewReplayProposal(input: ReviewReplayProposalInput): Promise<ReplayProposalRecord> {
    const span = this.#telemetry.startSpan("relayquill.replays.review");
    try {
      const tenantId = parseTenantId(input.tenantId, "tenantId");
      const projectId = parseProjectId(input.projectId, "projectId");
      const proposalId = parseReplayProposalId(input.proposalId, "proposalId");
      const expectedCandidateSha256 = parseSha256Hex(
        input.expectedCandidateSha256,
        "expectedCandidateSha256"
      );
      const proofId = parseOperationProofId(input.stepUpProofId, "stepUpProofId");
      const nowInstant = this.#clock.nowInstant();
      const now = parseCanonicalUtcTimestamp(formatUtcTimestamp(nowInstant), "now");
      const reviewId = this.#ids.nextUuid();
      const receiptId = parseCommandReceiptId(this.#ids.nextUuid(), "receiptId");

      const installation = await this.#uow.inTransaction((tx) =>
        this.#readInstallationAuthority(tx)
      );

      await verifyAndConsumeOperationProof({
        proofId,
        authenticatedSession: input.session,
        installation,
        expectedBinding: {
          action: "replay_proposals.review",
          scopeKind: "project",
          tenantId,
          projectId,
          targetResourceId: parseCanonicalUuid(proposalId, "proposalId"),
          targetVersion: input.expectedProposalVersion,
          canonicalCommandSha256: expectedCandidateSha256
        },
        acceptedReceiptId: receiptId,
        proofRepo: this.#authRepos.stepUp,
        now: nowInstant
      });

      const reviewed = await this.#uow.inTransaction(async (tx) => {
        const proposal = await this.#replayRepo.findProposal(tx, proposalId);
        if (proposal === undefined) {
          throw new NotFoundDomainError({
            code: "NOT_FOUND",
            message: `Replay proposal "${proposalId}" not found`
          });
        }
        if (proposal.tenantId !== tenantId || proposal.projectId !== projectId) {
          throw new NotFoundDomainError({
            code: "NOT_FOUND",
            message: `Replay proposal "${proposalId}" not found in project "${projectId}"`
          });
        }

        const requiresContentReadGrant =
          proposal.strategy === "replay_with_reviewed_representation";

        await authorizeProposalReview({
          installation,
          tenantId,
          projectId,
          action: "replay_proposals.review",
          proposal: {
            proposalId: proposal.proposalId,
            state: mapRepoProposalStateToDomain(proposal.state),
            proposerPrincipalId: proposal.proposerPrincipalId,
            candidateSha256: proposal.candidateSha256,
            version: proposal.version,
            expiresAt: computeProposalExpiresAt(nowInstant)
          },
          reviewerPrincipalId: input.session.principal.principalId,
          decision: input.decision,
          expectedVersion: input.expectedProposalVersion,
          expectedCandidateSha256,
          stepUpVerified: true,
          requiresContentReadGrant,
          repo: this.#authRepos.humanAuthorization,
          now: nowInstant
        });

        return this.#replayRepo.reviewReplayProposal(tx, {
          reviewId,
          proposalId,
          expectedProposalVersion: input.expectedProposalVersion,
          candidateSha256: expectedCandidateSha256,
          reviewerPrincipalId: input.session.principal.principalId,
          reviewerAuthorityVersion:
            input.authorityVersion ?? input.session.principal.authorityEpoch,
          decision: input.decision,
          now
        });
      });

      span.end({ code: "OK" });
      return reviewed;
    } catch (err) {
      span.end({
        code: "ERROR",
        message: err instanceof Error ? err.message : "review_replay_failed"
      });
      throw err;
    }
  }

  /**
   * Admits an approved replay proposal after verifying RBAC, two-person review distinction,
   * candidate hash stability, strict ordering strategy, and step-up proof consumption.
   */
  async admitApprovedReplay(input: AdmitApprovedReplayInput): Promise<{
    readonly newDeliveryId: DeliveryId;
    readonly deliveryGeneration: bigint;
    readonly receiptId: CommandReceiptId;
  }> {
    const span = this.#telemetry.startSpan("relayquill.replays.admit");
    try {
      const tenantId = parseTenantId(input.tenantId, "tenantId");
      const projectId = parseProjectId(input.projectId, "projectId");
      const proposalId = parseReplayProposalId(input.proposalId, "proposalId");
      const expectedCandidateSha256 = parseSha256Hex(
        input.expectedCandidateSha256,
        "expectedCandidateSha256"
      );
      const proofId = parseOperationProofId(input.stepUpProofId, "stepUpProofId");
      const nowInstant = this.#clock.nowInstant();
      const now = parseCanonicalUtcTimestamp(formatUtcTimestamp(nowInstant), "now");
      const newDeliveryId = parseDeliveryId(this.#ids.nextUuid(), "newDeliveryId");
      const receiptId = parseCommandReceiptId(this.#ids.nextUuid(), "receiptId");
      const idempotencyKeySha256 = computeCommandGuardKey({
        scope_kind: "project",
        tenant_id: tenantId,
        project_id: projectId,
        actor_principal_id: input.session.principal.principalId,
        command_family: "replay_proposals.admit",
        key_sha256: sha256Utf8Hex(input.idempotencyKey)
      }).digest_sha256;

      const installation = await this.#uow.inTransaction((tx) =>
        this.#readInstallationAuthority(tx)
      );

      await verifyAndConsumeOperationProof({
        proofId,
        authenticatedSession: input.session,
        installation,
        expectedBinding: {
          action: "replay_proposals.admit",
          scopeKind: "project",
          tenantId,
          projectId,
          targetResourceId: parseCanonicalUuid(proposalId, "proposalId"),
          targetVersion: input.expectedProposalVersion,
          canonicalCommandSha256: expectedCandidateSha256
        },
        acceptedReceiptId: receiptId,
        proofRepo: this.#authRepos.stepUp,
        now: nowInstant
      });

      const admitted = await this.#uow.inTransaction(async (tx) => {
        const proposal = await this.#replayRepo.findProposal(tx, proposalId);
        if (proposal === undefined) {
          throw new NotFoundDomainError({
            code: "NOT_FOUND",
            message: `Replay proposal "${proposalId}" not found`
          });
        }
        if (proposal.tenantId !== tenantId || proposal.projectId !== projectId) {
          throw new NotFoundDomainError({
            code: "NOT_FOUND",
            message: `Replay proposal "${proposalId}" not found in project "${projectId}"`
          });
        }
        if (proposal.reviewerPrincipalId === undefined) {
          throw new ConflictDomainError({
            code: "STATE_TRANSITION_NOT_ALLOWED",
            message: "Replay proposal has not been reviewed by a distinct reviewer"
          });
        }

        const delivery = await this.#replayRepo.readDeliveryForReplay(
          tx,
          tenantId,
          projectId,
          proposal.deliveryId
        );

        const proposerHasContentRead = await hasActiveProjectDataGrant({
          principalId: proposal.proposerPrincipalId,
          tenantId,
          projectId,
          action: "events.content.read",
          repo: this.#authRepos.humanAuthorization,
          now: nowInstant
        });
        const reviewerHasContentRead = await hasActiveProjectDataGrant({
          principalId: proposal.reviewerPrincipalId,
          tenantId,
          projectId,
          action: "events.content.read",
          repo: this.#authRepos.humanAuthorization,
          now: nowInstant
        });

        const proposalSnapshot = {
          proposalId: proposal.proposalId,
          state: mapRepoProposalStateToDomain(proposal.state),
          proposerPrincipalId: proposal.proposerPrincipalId,
          candidateSha256: proposal.candidateSha256,
          version: proposal.version,
          expiresAt: computeProposalExpiresAt(nowInstant)
        };
        const reviewId = proposal.reviewId ?? this.#ids.nextUuid();

        await authorizeProposalAdmission({
          installation,
          tenantId,
          projectId,
          action: "replay_proposals.admit",
          proposal: proposalSnapshot,
          review: {
            reviewId,
            proposalId: proposal.proposalId,
            proposalVersion: proposal.version,
            candidateSha256: proposal.candidateSha256,
            reviewerPrincipalId: proposal.reviewerPrincipalId,
            decision: "approve",
            reviewedAt: nowInstant
          },
          admitterPrincipalId: input.session.principal.principalId,
          expectedVersion: input.expectedProposalVersion,
          expectedCandidateSha256,
          stepUpVerified: true,
          repo: this.#authRepos.humanAuthorization,
          now: nowInstant
        });

        admitReplayProposal({
          proposal: proposalSnapshot,
          strategy: proposal.strategy,
          orderingStrategy: resolveReplayOrderingStrategy(delivery.orderingMode),
          destinationChanged: input.destinationChanged ?? false,
          strictPerKeyOrdering: delivery.orderingMode === "strict_per_key",
          proposerHasContentRead,
          reviewerHasContentRead,
          expectedCandidateSha256,
          expectedVersion: input.expectedProposalVersion,
          now: nowInstant
        });

        return this.#replayRepo.admitReplayProposal(tx, {
          proposalId,
          expectedProposalVersion: input.expectedProposalVersion,
          candidateSha256: expectedCandidateSha256,
          reviewId,
          actorPrincipalId: input.session.principal.principalId,
          newDeliveryId,
          receiptId,
          idempotencyKeySha256,
          now
        });
      });

      span.end({ code: "OK" });
      return admitted;
    } catch (err) {
      span.end({
        code: "ERROR",
        message: err instanceof Error ? err.message : "admit_replay_failed"
      });
      throw err;
    }
  }

  /**
   * Proposes, reviews (two-person `proposer !== reviewer`), or admits a delivery suppression.
   */
  async proposeSuppression(input: ProposeSuppressionInput): Promise<{
    readonly proposalId: string;
    readonly state: string;
    readonly proposerPrincipalId: PrincipalId;
  }> {
    const tenantId = parseTenantId(input.tenantId, "tenantId");
    const projectId = parseProjectId(input.projectId, "projectId");
    const deliveryId = parseDeliveryId(input.deliveryId, "deliveryId");
    const reasonCode = input.reasonCode.trim();
    if (reasonCode.length === 0) {
      throw new ValidationDomainError({
        code: "INVALID_VALUE",
        message: "Suppression reasonCode is required",
        fieldErrors: [{ path: "reason_code", code: "INVALID_VALUE" }]
      });
    }

    const nowInstant = this.#clock.nowInstant();
    const now = parseCanonicalUtcTimestamp(formatUtcTimestamp(nowInstant), "now");
    const proposalId = this.#ids.nextUuid();

    const installation = await this.#uow.inTransaction((tx) =>
      this.#readInstallationAuthority(tx)
    );

    await authorizeHumanAction({
      installation,
      principalId: input.session.principal.principalId,
      action: "deliveries.suppression.propose",
      tenantId,
      projectId,
      repo: this.#authRepos.humanAuthorization,
      now: nowInstant
    });

    return this.#uow.inTransaction((tx) =>
      this.#replayRepo.proposeAndReviewSuppression(tx, {
        mode: "propose",
        proposalId,
        deliveryId,
        actorPrincipalId: input.session.principal.principalId,
        reasonCode,
        now
      })
    );
  }

  async reviewSuppression(input: ReviewSuppressionInput): Promise<{
    readonly proposalId: string;
    readonly state: string;
    readonly proposerPrincipalId: PrincipalId;
    readonly reviewerPrincipalId?: PrincipalId | undefined;
  }> {
    const tenantId = parseTenantId(input.tenantId, "tenantId");
    const projectId = parseProjectId(input.projectId, "projectId");
    const deliveryId = parseDeliveryId(input.deliveryId, "deliveryId");
    const proofId = parseOperationProofId(input.stepUpProofId, "stepUpProofId");
    const reviewerId = parsePrincipalId(input.session.principal.principalId, "reviewerPrincipalId");
    const nowInstant = this.#clock.nowInstant();
    const now = parseCanonicalUtcTimestamp(formatUtcTimestamp(nowInstant), "now");
    const reviewId = this.#ids.nextUuid();
    const receiptId = parseCommandReceiptId(this.#ids.nextUuid(), "receiptId");
    const canonicalCommandSha256 = hashCanonicalJson({
      proposal_id: input.proposalId,
      delivery_id: deliveryId,
      decision: input.decision
    }).sha256;

    const installation = await this.#uow.inTransaction((tx) =>
      this.#readInstallationAuthority(tx)
    );

    await verifyAndConsumeOperationProof({
      proofId,
      authenticatedSession: input.session,
      installation,
      expectedBinding: {
        action: "suppression_proposals.review",
        scopeKind: "project",
        tenantId,
        projectId,
        targetResourceId: parseCanonicalUuid(input.proposalId, "proposalId"),
        targetVersion: input.expectedVersion ?? 1n,
        canonicalCommandSha256
      },
      acceptedReceiptId: receiptId,
      proofRepo: this.#authRepos.stepUp,
      now: nowInstant
    });

    await authorizeHumanAction({
      installation,
      principalId: reviewerId,
      action: "suppression_proposals.review",
      tenantId,
      projectId,
      stepUpVerified: true,
      repo: this.#authRepos.humanAuthorization,
      now: nowInstant
    });

    const out = await this.#uow.inTransaction((tx) =>
      this.#replayRepo.proposeAndReviewSuppression(tx, {
        mode: "review",
        proposalId: input.proposalId,
        deliveryId,
        actorPrincipalId: reviewerId,
        reviewId,
        decision: input.decision,
        now
      })
    );

    if (out.proposerPrincipalId === reviewerId) {
      throw new AuthorizationDomainError({
        code: "FORBIDDEN",
        message: "Two-person suppression review forbids self-approval by proposer"
      });
    }
    return out;
  }

  async admitSuppression(input: AdmitSuppressionInput): Promise<{
    readonly proposalId: string;
    readonly state: string;
    readonly deliveryId: DeliveryId;
    readonly suppressionOutcome: "suppressed" | "already_terminal";
  }> {
    const tenantId = parseTenantId(input.tenantId, "tenantId");
    const projectId = parseProjectId(input.projectId, "projectId");
    const deliveryId = parseDeliveryId(input.deliveryId, "deliveryId");
    const proofId = parseOperationProofId(input.stepUpProofId, "stepUpProofId");
    const actorId = parsePrincipalId(input.session.principal.principalId, "actorPrincipalId");
    const nowInstant = this.#clock.nowInstant();
    const now = parseCanonicalUtcTimestamp(formatUtcTimestamp(nowInstant), "now");
    const receiptId = parseCommandReceiptId(this.#ids.nextUuid(), "receiptId");
    const idempotencyKeySha256 = computeCommandGuardKey({
      scope_kind: "project",
      tenant_id: tenantId,
      project_id: projectId,
      actor_principal_id: actorId,
      command_family: "suppression_proposals.admit",
      key_sha256: sha256Utf8Hex(input.idempotencyKey)
    }).digest_sha256;
    const candidateSha256 = hashCanonicalJson({ delivery_id: deliveryId }).sha256;

    const installation = await this.#uow.inTransaction((tx) =>
      this.#readInstallationAuthority(tx)
    );

    await verifyAndConsumeOperationProof({
      proofId,
      authenticatedSession: input.session,
      installation,
      expectedBinding: {
        action: "suppression_proposals.admit",
        scopeKind: "project",
        tenantId,
        projectId,
        targetResourceId: parseCanonicalUuid(input.proposalId, "proposalId"),
        targetVersion: input.expectedVersion ?? 1n,
        canonicalCommandSha256: candidateSha256
      },
      acceptedReceiptId: receiptId,
      proofRepo: this.#authRepos.stepUp,
      now: nowInstant
    });

    await authorizeHumanAction({
      installation,
      principalId: actorId,
      action: "suppression_proposals.admit",
      tenantId,
      projectId,
      stepUpVerified: true,
      repo: this.#authRepos.humanAuthorization,
      now: nowInstant
    });

    const delivery = await this.#uow.inTransaction((tx) =>
      this.#replayRepo.readDeliveryForReplay(tx, tenantId, projectId, deliveryId)
    );
    const targetVersion = input.expectedVersion ?? 1n;
    const domainCheck = admitSuppressionProposal(
      {
        proposalId: input.proposalId,
        state: "approved",
        proposerPrincipalId: actorId,
        candidateSha256,
        version: targetVersion,
        expiresAt: computeProposalExpiresAt(nowInstant)
      },
      {
        deliveryId,
        state: delivery.state,
        currentAttemptId: null
      },
      {
        expectedCandidateSha256: candidateSha256,
        expectedVersion: targetVersion,
        now: nowInstant
      }
    );

    const out = await this.#uow.inTransaction((tx) =>
      this.#replayRepo.proposeAndReviewSuppression(tx, {
        mode: "admit",
        proposalId: input.proposalId,
        deliveryId,
        actorPrincipalId: actorId,
        receiptId,
        idempotencyKeySha256,
        now
      })
    );

    return Object.freeze({
      proposalId: out.proposalId,
      state: out.state,
      deliveryId,
      suppressionOutcome: domainCheck.outcome
    });
  }
}

export function assertProposalExpiryUtc(createdAt: CanonicalUtcTimestamp): CanonicalUtcTimestamp {
  const createdInstant = parseUtcTimestamp(createdAt, "createdAt").instant;
  return parseCanonicalUtcTimestamp(
    formatUtcTimestamp(computeProposalExpiresAt(createdInstant)),
    "expiresAt"
  );
}
