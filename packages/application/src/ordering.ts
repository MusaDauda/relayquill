import {
  AuthorizationDomainError,
  ConflictDomainError,
  type DeliveryId,
  NotFoundDomainError,
  type OperationProofId,
  type OrderingCutoverPlanId,
  type OrderingCutoverPlanSnapshot,
  type OrderingDomainId,
  type OrderingKeyId,
  type PrincipalId,
  type ProjectId,
  type Sha256Hex,
  type TenantId,
  ValidationDomainError,
  activateOrderingCutover,
  addMilliseconds,
  assertCanSkipOrderingMember,
  beginOrderingCutover,
  formatUtcTimestamp,
  markOrderingCutoverReady,
  parseCommandReceiptId,
  parseDeliveryId,
  parseOperationProofId,
  parseOrderingCutoverPlanId,
  parseOrderingDomainId,
  parseOrderingKeyId,
  parsePrincipalId,
  parseProjectId,
  parseSha256Hex,
  parseTenantId
} from "@relayquill/domain";
import {
  type AuthenticatedHumanSession,
  authorizeHumanAction,
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
  type OrderingCutoverPlanRecord,
  type OrderingGapRecord,
  type OrderingRepositoryPort,
  type TelemetryPort,
  type UnitOfWorkPort,
  cryptoIdGeneratorPort,
  noopTelemetryPort,
  systemClockPort
} from "./ports.js";

export interface OrderingServiceDeps<TTx> {
  readonly uow: UnitOfWorkPort<TTx>;
  readonly orderingRepo: OrderingRepositoryPort<TTx>;
  readonly authRepos: AuthRepositoriesBundle;
  readonly readInstallationAuthority: (tx: TTx) => Promise<InstallationAuthoritySnapshot>;
  readonly readProjectAuthority?: (
    tx: TTx,
    tenantId: TenantId,
    projectId: ProjectId
  ) => Promise<{
    readonly nextEventSequence: bigint;
    readonly materializedThroughEventSequence: bigint;
    readonly activeOrderingCutoverPlanId?: OrderingCutoverPlanId | undefined;
  }>;
  readonly clock?: ClockPort | undefined;
  readonly idGenerator?: IdGeneratorPort | undefined;
  readonly telemetry?: TelemetryPort | undefined;
}

export interface ProposeOrderSkipInput {
  readonly session: AuthenticatedHumanSession;
  readonly tenantId: TenantId | string;
  readonly projectId: ProjectId | string;
  readonly orderingDomainId: OrderingDomainId | string;
  readonly orderingKeySha256: Sha256Hex | string;
  readonly blockedSequence: bigint;
  readonly reasonCode: string;
}

export interface ReviewOrderSkipInput {
  readonly session: AuthenticatedHumanSession;
  readonly tenantId: TenantId | string;
  readonly projectId: ProjectId | string;
  readonly proposalId: string;
  readonly expectedVersion?: bigint | undefined;
  readonly decision: "approve" | "reject";
  readonly stepUpProofId: OperationProofId | string;
}

export interface ApplyOrderSkipInput {
  readonly session: AuthenticatedHumanSession;
  readonly tenantId: TenantId | string;
  readonly projectId: ProjectId | string;
  readonly proposalId: string;
  readonly reviewId: string;
  readonly expectedVersion?: bigint | undefined;
  readonly proposerPrincipalId: PrincipalId | string;
  readonly reviewerPrincipalId: PrincipalId | string;
  readonly orderingDomainId: OrderingDomainId | string;
  readonly orderingKeyId?: OrderingKeyId | string | undefined;
  readonly orderingKeySha256: Sha256Hex | string;
  readonly blockedSequence: bigint;
  readonly deliveryAcknowledged: boolean;
  readonly nextEligibleSequence: bigint;
  readonly idempotencyKey: string;
  readonly stepUpProofId: OperationProofId | string;
}

export interface ReplayAppendOrderingMemberInput {
  readonly session: AuthenticatedHumanSession;
  readonly tenantId: TenantId | string;
  readonly projectId: ProjectId | string;
  readonly orderingDomainId: OrderingDomainId | string;
  readonly orderingKeySha256: Sha256Hex | string;
  readonly missingSequence: bigint;
  readonly expectedVersion?: bigint | undefined;
  readonly stepUpProofId: OperationProofId | string;
}

export interface AdvanceOrderingCutoverInput {
  readonly session: AuthenticatedHumanSession;
  readonly tenantId: TenantId | string;
  readonly projectId: ProjectId | string;
  readonly planId: OrderingCutoverPlanId | string;
  readonly targetPhase: "begin_draining" | "mark_ready" | "activate";
  readonly expectedVersion: bigint;
  readonly throughTopologyVersion?: bigint | undefined;
  readonly sourceConsumerScope?: string | undefined;
  readonly targetConsumerScope?: string | undefined;
  readonly stepUpProofId?: OperationProofId | string | undefined;
}

export class OrderingService<TTx> {
  readonly #uow: UnitOfWorkPort<TTx>;
  readonly #orderingRepo: OrderingRepositoryPort<TTx>;
  readonly #authRepos: AuthRepositoriesBundle;
  readonly #readInstallationAuthority: (tx: TTx) => Promise<InstallationAuthoritySnapshot>;
  readonly #readProjectAuthority: OrderingServiceDeps<TTx>["readProjectAuthority"];
  readonly #clock: ClockPort;
  readonly #ids: IdGeneratorPort;
  readonly #telemetry: TelemetryPort;

  constructor(deps: OrderingServiceDeps<TTx>) {
    this.#uow = deps.uow;
    this.#orderingRepo = deps.orderingRepo;
    this.#authRepos = deps.authRepos;
    this.#readInstallationAuthority = deps.readInstallationAuthority;
    this.#readProjectAuthority = deps.readProjectAuthority;
    this.#clock = deps.clock ?? systemClockPort;
    this.#ids = deps.idGenerator ?? cryptoIdGeneratorPort;
    this.#telemetry = deps.telemetry ?? noopTelemetryPort;
  }

  async listOrderingGaps(input: {
    readonly tenantId: TenantId | string;
    readonly projectId: ProjectId | string;
    readonly limit?: number | undefined;
  }): Promise<readonly OrderingGapRecord[]> {
    const tenantId = parseTenantId(input.tenantId, "tenantId");
    const projectId = parseProjectId(input.projectId, "projectId");
    const limit = Math.max(1, Math.min(200, Math.trunc(input.limit ?? 100)));
    return this.#uow.inTransaction((tx) =>
      this.#orderingRepo.listOrderingGaps(tx, tenantId, projectId, limit)
    );
  }

  /**
   * Appends a reviewed replacement ordered delivery (`replay_append`) for a blocked
   * sequence without touching existing head state outside the ordering domain.
   */
  async replayAppendMissingOrderedDelivery(
    input: ReplayAppendOrderingMemberInput
  ): Promise<{ readonly appendedDeliveryId: DeliveryId; readonly sequence: bigint }> {
    const span = this.#telemetry.startSpan("relayquill.ordering.replay_append");
    try {
      const tenantId = parseTenantId(input.tenantId, "tenantId");
      const projectId = parseProjectId(input.projectId, "projectId");
      const orderingDomainId = parseOrderingDomainId(input.orderingDomainId, "orderingDomainId");
      const orderingKeySha256 = parseSha256Hex(input.orderingKeySha256, "orderingKeySha256");
      const proofId = parseOperationProofId(input.stepUpProofId, "stepUpProofId");

      if (input.missingSequence < 1n) {
        throw new ValidationDomainError({
          code: "INVALID_INT64",
          message: "missingSequence must be >= 1"
        });
      }

      const nowInstant = this.#clock.nowInstant();
      const now = parseCanonicalUtcTimestamp(formatUtcTimestamp(nowInstant), "now");
      const newDeliveryId = parseDeliveryId(this.#ids.nextUuid(), "newDeliveryId");
      const receiptId = parseCommandReceiptId(this.#ids.nextUuid(), "receiptId");
      const canonicalCommandSha256 = hashCanonicalJson({
        ordering_domain_id: orderingDomainId,
        ordering_key_sha256: orderingKeySha256,
        missing_sequence: input.missingSequence.toString(10)
      }).sha256;

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
          targetResourceId: parseCanonicalUuid(orderingDomainId, "orderingDomainId"),
          targetVersion: input.expectedVersion ?? 1n,
          canonicalCommandSha256
        },
        acceptedReceiptId: receiptId,
        proofRepo: this.#authRepos.stepUp,
        now: nowInstant
      });

      await authorizeHumanAction({
        installation,
        principalId: input.session.principal.principalId,
        action: "replay_proposals.admit",
        tenantId,
        projectId,
        stepUpVerified: true,
        repo: this.#authRepos.humanAuthorization,
        now: nowInstant
      });

      const out = await this.#uow.inTransaction((tx) =>
        this.#orderingRepo.appendMissingOrderedDelivery(tx, {
          tenantId,
          projectId,
          orderingDomainId,
          orderingKeySha256,
          missingSequence: input.missingSequence,
          newDeliveryId,
          actorPrincipalId: input.session.principal.principalId,
          now
        })
      );

      span.end({ code: "OK" });
      return out;
    } catch (err) {
      span.end({
        code: "ERROR",
        message: err instanceof Error ? err.message : "replay_append_failed"
      });
      throw err;
    }
  }

  /**
   * Proposes an order-skip disposition for a blocked sequence (`gap_skip`).
   */
  async proposeOrderSkip(input: ProposeOrderSkipInput): Promise<{
    readonly proposalId: string;
    readonly state: string;
    readonly proposerPrincipalId: PrincipalId;
  }> {
    const tenantId = parseTenantId(input.tenantId, "tenantId");
    const projectId = parseProjectId(input.projectId, "projectId");
    const orderingDomainId = parseOrderingDomainId(input.orderingDomainId, "orderingDomainId");
    const orderingKeySha256 = parseSha256Hex(input.orderingKeySha256, "orderingKeySha256");
    const reasonCode = input.reasonCode.trim();
    if (reasonCode.length === 0) {
      throw new ValidationDomainError({
        code: "INVALID_VALUE",
        message: "Order skip reasonCode is required"
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
      action: "order_skip_proposals.propose",
      tenantId,
      projectId,
      repo: this.#authRepos.humanAuthorization,
      now: nowInstant
    });

    return this.#uow.inTransaction((tx) =>
      this.#orderingRepo.createOrderSkipProposal(tx, {
        proposalId,
        proposerPrincipalId: input.session.principal.principalId,
        orderingDomainId,
        orderingKeySha256,
        blockedSequence: input.blockedSequence,
        reasonCode,
        now
      })
    );
  }

  /**
   * Reviews an order-skip proposal enforcing two-person separation (`proposer !== reviewer`).
   */
  async reviewOrderSkip(input: ReviewOrderSkipInput): Promise<{
    readonly proposalId: string;
    readonly state: string;
    readonly proposerPrincipalId: PrincipalId;
    readonly reviewerPrincipalId: PrincipalId;
  }> {
    const tenantId = parseTenantId(input.tenantId, "tenantId");
    const projectId = parseProjectId(input.projectId, "projectId");
    const proofId = parseOperationProofId(input.stepUpProofId, "stepUpProofId");
    const reviewerId = parsePrincipalId(input.session.principal.principalId, "reviewerPrincipalId");
    const nowInstant = this.#clock.nowInstant();
    const now = parseCanonicalUtcTimestamp(formatUtcTimestamp(nowInstant), "now");
    const reviewId = this.#ids.nextUuid();
    const receiptId = parseCommandReceiptId(this.#ids.nextUuid(), "receiptId");
    const canonicalCommandSha256 = hashCanonicalJson({
      proposal_id: input.proposalId,
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
        action: "order_skip_proposals.review",
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
      action: "order_skip_proposals.review",
      tenantId,
      projectId,
      stepUpVerified: true,
      repo: this.#authRepos.humanAuthorization,
      now: nowInstant
    });

    const out = await this.#uow.inTransaction((tx) =>
      this.#orderingRepo.reviewOrderSkipProposal(tx, {
        proposalId: input.proposalId,
        reviewId,
        reviewerPrincipalId: reviewerId,
        decision: input.decision,
        now
      })
    );

    if (out.proposerPrincipalId === reviewerId) {
      throw new AuthorizationDomainError({
        code: "FORBIDDEN",
        message: "Two-person order-skip review forbids self-approval by proposer"
      });
    }
    return out;
  }

  /**
   * Applies an approved `gap_skip` disposition (`reviewed_skip_without_processing_claim`).
   */
  async applyOrderSkipDisposition(input: ApplyOrderSkipInput): Promise<{
    readonly dispositionId: string;
    readonly newHeadSequence: bigint;
  }> {
    const tenantId = parseTenantId(input.tenantId, "tenantId");
    const projectId = parseProjectId(input.projectId, "projectId");
    const proposerId = parsePrincipalId(input.proposerPrincipalId, "proposerPrincipalId");
    const reviewerId = parsePrincipalId(input.reviewerPrincipalId, "reviewerPrincipalId");
    if (proposerId === reviewerId) {
      throw new AuthorizationDomainError({
        code: "FORBIDDEN",
        message: "Order-skip disposition requires distinct proposer and reviewer principals"
      });
    }

    const orderingDomainId = parseOrderingDomainId(input.orderingDomainId, "orderingDomainId");
    const orderingKeyId = parseOrderingKeyId(
      input.orderingKeyId ?? this.#ids.nextUuid(),
      "orderingKeyId"
    );
    const orderingKeySha256 = parseSha256Hex(input.orderingKeySha256, "orderingKeySha256");
    const proofId = parseOperationProofId(input.stepUpProofId, "stepUpProofId");
    const nowInstant = this.#clock.nowInstant();
    const now = parseCanonicalUtcTimestamp(formatUtcTimestamp(nowInstant), "now");
    const dispositionId = this.#ids.nextUuid();
    const receiptId = parseCommandReceiptId(this.#ids.nextUuid(), "receiptId");
    const idempotencyKeySha256 = computeCommandGuardKey({
      scope_kind: "project",
      tenant_id: tenantId,
      project_id: projectId,
      actor_principal_id: input.session.principal.principalId,
      command_family: "order_skip_proposals.admit",
      key_sha256: sha256Utf8Hex(input.idempotencyKey)
    }).digest_sha256;

    assertCanSkipOrderingMember({
      orderingKeyId,
      orderingSequence: input.blockedSequence,
      nextEligibleSequence: input.nextEligibleSequence,
      memberState: "eligible",
      deliveryState: input.deliveryAcknowledged ? "acknowledged" : "dead_letter",
      hasActiveSendStartedAttempt: false
    });

    const canonicalCommandSha256 = hashCanonicalJson({
      proposal_id: input.proposalId,
      review_id: input.reviewId,
      ordering_domain_id: orderingDomainId,
      ordering_key_sha256: orderingKeySha256,
      blocked_sequence: input.blockedSequence.toString(10)
    }).sha256;

    const installation = await this.#uow.inTransaction((tx) =>
      this.#readInstallationAuthority(tx)
    );

    await verifyAndConsumeOperationProof({
      proofId,
      authenticatedSession: input.session,
      installation,
      expectedBinding: {
        action: "order_skip_proposals.admit",
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
      principalId: input.session.principal.principalId,
      action: "order_skip_proposals.admit",
      tenantId,
      projectId,
      stepUpVerified: true,
      repo: this.#authRepos.humanAuthorization,
      now: nowInstant
    });

    return this.#uow.inTransaction((tx) =>
      this.#orderingRepo.applyOrderSkipDisposition(tx, {
        proposalId: input.proposalId,
        reviewId: input.reviewId,
        actorPrincipalId: input.session.principal.principalId,
        dispositionId,
        receiptId,
        idempotencyKeySha256,
        orderingDomainId,
        orderingKeySha256,
        blockedSequence: input.blockedSequence,
        now
      })
    );
  }

  /**
   * Advances an ordering extractor cutover barrier plan (`proposed -> draining -> ready -> activated`)
   * verifying contiguous fanout watermark completion and zero in-flight old-extractor work.
   */
  async advanceExtractorCutoverBarrier(
    input: AdvanceOrderingCutoverInput
  ): Promise<OrderingCutoverPlanRecord> {
    const span = this.#telemetry.startSpan("relayquill.ordering.advance_cutover_barrier");
    try {
      const tenantId = parseTenantId(input.tenantId, "tenantId");
      const projectId = parseProjectId(input.projectId, "projectId");
      const planId = parseOrderingCutoverPlanId(input.planId, "planId");
      const nowInstant = this.#clock.nowInstant();
      const receiptId = parseCommandReceiptId(this.#ids.nextUuid(), "receiptId");
      const action =
        input.targetPhase === "begin_draining"
          ? "ordering_cutovers.begin"
          : input.targetPhase === "activate"
            ? "ordering_cutovers.activate"
            : "subscriptions.pause_future";

      const canonicalCommandSha256 = hashCanonicalJson({
        plan_id: planId,
        target_phase: input.targetPhase,
        expected_version: input.expectedVersion.toString(10)
      }).sha256;

      const installation = await this.#uow.inTransaction((tx) =>
        this.#readInstallationAuthority(tx)
      );

      let stepUpVerified = false;
      if (input.targetPhase !== "mark_ready") {
        if (input.stepUpProofId === undefined) {
          throw new AuthorizationDomainError({
            code: "FORBIDDEN",
            message: `Action "${action}" requires stepUpProofId`
          });
        }
        await verifyAndConsumeOperationProof({
          proofId: parseOperationProofId(input.stepUpProofId, "stepUpProofId"),
          authenticatedSession: input.session,
          installation,
          expectedBinding: {
            action,
            scopeKind: "project",
            tenantId,
            projectId,
            targetResourceId: parseCanonicalUuid(planId, "planId"),
            targetVersion: input.expectedVersion,
            canonicalCommandSha256
          },
          acceptedReceiptId: receiptId,
          proofRepo: this.#authRepos.stepUp,
          now: nowInstant
        });
        stepUpVerified = true;
      }

      await authorizeHumanAction({
        installation,
        principalId: input.session.principal.principalId,
        action,
        tenantId,
        projectId,
        stepUpVerified,
        repo: this.#authRepos.humanAuthorization,
        now: nowInstant
      });

      const saved = await this.#uow.inTransaction(async (tx) => {
        const plan = await this.#orderingRepo.getCutoverPlan(tx, planId);
        if (plan === undefined || plan.tenantId !== tenantId || plan.projectId !== projectId) {
          throw new NotFoundDomainError({
            code: "NOT_FOUND",
            message: `Ordering cutover plan "${planId}" not found`
          });
        }
        if (plan.version !== input.expectedVersion) {
          throw new ConflictDomainError({
            code: "VERSION_CONFLICT",
            message: `Ordering cutover plan version mismatch: expected ${input.expectedVersion}, got ${plan.version}`
          });
        }

        const projectAuth = this.#readProjectAuthority
          ? await this.#readProjectAuthority(tx, tenantId, projectId)
          : {
              nextEventSequence: 1n,
              materializedThroughEventSequence: 0n,
              activeOrderingCutoverPlanId: plan.planId
            };

        const scope = input.sourceConsumerScope ?? `${plan.subscriptionId}:v1`;
        const targetScope = input.targetConsumerScope ?? scope;
        const barrierTopologyVersion =
          input.throughTopologyVersion ?? plan.cutoverTopologyVersion ?? 1n;

        const planSnapshot: OrderingCutoverPlanSnapshot = {
          planId: plan.planId,
          projectId: plan.projectId,
          state: plan.state,
          sourceConsumerScope: scope,
          targetConsumerScope: targetScope,
          boundaryProjectSequence:
            plan.cutoverTopologyVersion ??
            (projectAuth.nextEventSequence - 1n > 0n ? projectAuth.nextEventSequence - 1n : 1n),
          expiresAt: addMilliseconds(nowInstant, 3_600_000n, "cutover_expires_at")
        };

        let nextSnapshot: OrderingCutoverPlanSnapshot = planSnapshot;
        if (input.targetPhase === "begin_draining") {
          nextSnapshot = beginOrderingCutover(planSnapshot, {
            activeProjectCutoverPlanId: projectAuth.activeOrderingCutoverPlanId ?? null,
            currentProjectSequence: projectAuth.nextEventSequence - 1n,
            now: nowInstant
          });
        } else if (input.targetPhase === "mark_ready") {
          const activeInFlight = await this.#orderingRepo.countActiveInFlightForSubscription(
            tx,
            plan.subscriptionId,
            barrierTopologyVersion
          );
          const drained =
            plan.outstandingInFlightBeforeBarrier === 0 && activeInFlight === 0;
          nextSnapshot = markOrderingCutoverReady(planSnapshot, {
            materializedThroughEventSequence: projectAuth.materializedThroughEventSequence,
            oldHeadsDrained: drained,
            now: nowInstant
          });
        } else {
          const activeInFlight = await this.#orderingRepo.countActiveInFlightForSubscription(
            tx,
            plan.subscriptionId,
            barrierTopologyVersion
          );
          if (plan.outstandingInFlightBeforeBarrier > 0 || activeInFlight > 0) {
            throw new ConflictDomainError({
              code: "STATE_TRANSITION_NOT_ALLOWED",
              message: `Cutover plan still has active in-flight old-extractor deliveries`
            });
          }
          nextSnapshot = activateOrderingCutover(planSnapshot, {
            now: nowInstant
          });
        }

        const updatedRecord: OrderingCutoverPlanRecord = {
          ...plan,
          state: nextSnapshot.state,
          cutoverTopologyVersion:
            input.throughTopologyVersion ??
            nextSnapshot.boundaryProjectSequence ??
            plan.cutoverTopologyVersion,
          version: plan.version + 1n
        };

        return this.#orderingRepo.saveCutoverPlan(tx, updatedRecord, input.expectedVersion);
      });

      span.end({ code: "OK" });
      return saved;
    } catch (err) {
      span.end({
        code: "ERROR",
        message: err instanceof Error ? err.message : "cutover_barrier_failed"
      });
      throw err;
    }
  }
}
