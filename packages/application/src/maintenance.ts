import {
  type CanonicalUtcTimestamp,
  type ContentExpirationEvaluationResult,
  type ContentRetentionState,
  type ControlEpoch,
  MAX_NO_PROGRESS_RECOVERY_GENERATIONS,
  type OutboxId,
  type ProjectId,
  type PublicationRecoveryEpisodeId,
  type RetentionActionId,
  type RetentionHoldSnapshot,
  type RuntimeInstanceId,
  type TenantId,
  ValidationDomainError,
  assertRetentionClaimBatchSize,
  evaluateContentExpirationEligibility,
  formatUtcTimestamp,
  isHistoryRetirementEligible,
  isRetentionHoldActive,
  parseControlEpoch,
  parseProjectId,
  parsePublicationRecoveryEpisodeId,
  parseRuntimeInstanceId,
  parseTenantId,
  parseUtcTimestamp
} from "@relayquill/domain";
import { parseCanonicalUtcTimestamp } from "@relayquill/contracts";
import {
  type ClockPort,
  type IdGeneratorPort,
  type MaintenanceRepositoryPort,
  type ProjectProjectionDriftReport,
  type TelemetryPort,
  type UnitOfWorkPort,
  cryptoIdGeneratorPort,
  noopTelemetryPort,
  systemClockPort
} from "./ports.js";
import { type RecoverUnknownOutboxInput, type RecoverUnknownOutboxOutput } from "./relay.js";

export const DEFAULT_COORDINATOR_PROMOTE_LIMIT = 200 as const;
export const DEFAULT_COORDINATOR_REAP_LIMIT = 200 as const;
export const DEFAULT_PUBLICATION_RECOVERY_RATE_LIMIT = 25 as const;
export const DEFAULT_RETENTION_ACTION_CLAIM_LEASE_MS = 30_000n as const;
export const DEFAULT_RETENTION_BATCH_LIMIT = 100 as const;

export interface MaintenanceServiceDeps<TTx> {
  readonly uow: UnitOfWorkPort<TTx>;
  readonly maintenanceRepo: MaintenanceRepositoryPort<TTx>;
  readonly recoverUnknownOutbox?: (
    input: RecoverUnknownOutboxInput
  ) => Promise<RecoverUnknownOutboxOutput>;
  readonly clock?: ClockPort | undefined;
  readonly idGenerator?: IdGeneratorPort | undefined;
  readonly telemetry?: TelemetryPort | undefined;
}

export interface CoordinatorPromoteSweepOutput {
  readonly promotedDeliveries: number;
  readonly promotedOutbox: number;
}

export interface CoordinatorReapSweepOutput {
  readonly reapedAttempts: number;
  readonly reapedOutboxClaims: number;
  readonly reapedFanoutClaims: number;
  readonly reapedWatchLeases: number;
}

export interface PublicationRecoverySweepOutput {
  readonly scannedCount: number;
  readonly republishedCount: number;
  readonly newGenerationCount: number;
  readonly reviewRequiredCount: number;
  readonly stillUnknownCount: number;
  readonly quarantinedOutboxIds: readonly OutboxId[];
}

export interface RetentionTombstoneSweepOutput {
  readonly examinedCount: number;
  readonly skippedHeldCount: number;
  readonly completedCount: number;
  readonly alreadyCompleteCount: number;
  readonly completedActionIds: readonly RetentionActionId[];
}

export class MaintenanceService<TTx> {
  readonly #uow: UnitOfWorkPort<TTx>;
  readonly #maintenanceRepo: MaintenanceRepositoryPort<TTx>;
  readonly #recoverUnknownOutbox:
    | ((input: RecoverUnknownOutboxInput) => Promise<RecoverUnknownOutboxOutput>)
    | undefined;
  readonly #clock: ClockPort;
  readonly #ids: IdGeneratorPort;
  readonly #telemetry: TelemetryPort;

  constructor(deps: MaintenanceServiceDeps<TTx>) {
    this.#uow = deps.uow;
    this.#maintenanceRepo = deps.maintenanceRepo;
    this.#recoverUnknownOutbox = deps.recoverUnknownOutbox;
    this.#clock = deps.clock ?? systemClockPort;
    this.#ids = deps.idGenerator ?? cryptoIdGeneratorPort;
    this.#telemetry = deps.telemetry ?? noopTelemetryPort;
  }

  /**
   * Promotes due delayed deliveries and due outbox rows into ready eligibility.
   */
  async runEligibilityPromoter(limit = DEFAULT_COORDINATOR_PROMOTE_LIMIT): Promise<CoordinatorPromoteSweepOutput> {
    const span = this.#telemetry.startSpan("relayquill.maintenance.promote_due_work");
    try {
      const boundedLimit = Math.max(1, Math.min(1_000, Math.trunc(limit)));
      const now = parseCanonicalUtcTimestamp(formatUtcTimestamp(this.#clock.nowInstant()), "now");
      const out = await this.#uow.inTransaction((tx) =>
        this.#maintenanceRepo.promoteDueWork(tx, now, boundedLimit)
      );
      span.end({ code: "OK" });
      return Object.freeze(out);
    } catch (err) {
      span.end({ code: "ERROR", message: err instanceof Error ? err.message : "promote_failed" });
      throw err;
    }
  }

  /**
   * Reaps expired delivery attempt claims, outbox claims, fanout claims, and `watch_leases`.
   */
  async reapExpiredWorkAndWatchLeases(input: {
    readonly instanceId: RuntimeInstanceId | string;
    readonly controlEpoch: ControlEpoch | string;
    readonly batchLimit?: number | undefined;
  }): Promise<CoordinatorReapSweepOutput> {
    const span = this.#telemetry.startSpan("relayquill.maintenance.reap_expired_work");
    try {
      const instanceId = parseRuntimeInstanceId(input.instanceId, "instanceId");
      const controlEpoch = parseControlEpoch(input.controlEpoch, "controlEpoch");
      const batchLimit = Math.max(
        1,
        Math.min(1_000, Math.trunc(input.batchLimit ?? DEFAULT_COORDINATOR_REAP_LIMIT))
      );
      const now = parseCanonicalUtcTimestamp(formatUtcTimestamp(this.#clock.nowInstant()), "now");
      const out = await this.#uow.inTransaction((tx) =>
        this.#maintenanceRepo.reapExpiredCoordinatorWork(tx, {
          instanceId,
          controlEpoch,
          batchLimit,
          now
        })
      );
      span.end({ code: "OK" });
      return Object.freeze(out);
    } catch (err) {
      span.end({ code: "ERROR", message: err instanceof Error ? err.message : "reap_failed" });
      throw err;
    }
  }

  /**
   * Rate-bounded sweep over `publish_unknown` outbox entries. Any entry at or beyond
   * `MAX_NO_PROGRESS_RECOVERY_GENERATIONS` (= 5) transitions to `review_required`.
   */
  async runPublicationRecoverySweep(input: {
    readonly instanceId: RuntimeInstanceId | string;
    readonly controlEpoch: ControlEpoch | string;
    readonly maxPerSweep?: number | undefined;
    readonly forceNewGeneration?: boolean | undefined;
  }): Promise<PublicationRecoverySweepOutput> {
    const span = this.#telemetry.startSpan("relayquill.maintenance.publication_recovery_sweep");
    try {
      const instanceId = parseRuntimeInstanceId(input.instanceId, "instanceId");
      const controlEpoch = parseControlEpoch(input.controlEpoch, "controlEpoch");
      const maxPerSweep = Math.max(
        1,
        Math.min(100, Math.trunc(input.maxPerSweep ?? DEFAULT_PUBLICATION_RECOVERY_RATE_LIMIT))
      );
      const now = parseCanonicalUtcTimestamp(formatUtcTimestamp(this.#clock.nowInstant()), "now");

      const candidates = await this.#uow.inTransaction((tx) =>
        this.#maintenanceRepo.listUnknownPublicationOutbox(tx, now, maxPerSweep)
      );

      let republishedCount = 0;
      let newGenerationCount = 0;
      let reviewRequiredCount = 0;
      let stillUnknownCount = 0;
      const quarantinedOutboxIds: OutboxId[] = [];

      for (const row of candidates) {
        const episodeId = parsePublicationRecoveryEpisodeId(this.#ids.nextUuid(), "episodeId");

        if (row.noProgressGenerationCount >= MAX_NO_PROGRESS_RECOVERY_GENERATIONS) {
          await this.#quarantineUnknownOutbox(row.outboxId, episodeId, "NO_PROGRESS_LIMIT_EXCEEDED", now);
          reviewRequiredCount += 1;
          quarantinedOutboxIds.push(row.outboxId);
          continue;
        }

        if (this.#recoverUnknownOutbox === undefined) {
          stillUnknownCount += 1;
          continue;
        }

        const recovered = await this.#recoverUnknownOutbox({
          outboxId: row.outboxId,
          episodeId,
          instanceId,
          controlEpoch,
          noProgressGenerationCount: row.noProgressGenerationCount,
          forceNewGeneration: input.forceNewGeneration,
          reasonCode: "COORDINATOR_PUBLICATION_RECOVERY"
        });

        if (recovered.action === "review_required") {
          await this.#quarantineUnknownOutbox(row.outboxId, episodeId, "NO_PROGRESS_LIMIT_EXCEEDED", now);
          reviewRequiredCount += 1;
          quarantinedOutboxIds.push(row.outboxId);
        } else if (
          recovered.action === "republished_same_generation" ||
          recovered.action === "already_complete"
        ) {
          republishedCount += 1;
        } else if (recovered.action === "allocated_and_published_new_generation") {
          newGenerationCount += 1;
        } else {
          stillUnknownCount += 1;
        }
      }

      span.end({ code: "OK" });
      return Object.freeze({
        scannedCount: candidates.length,
        republishedCount,
        newGenerationCount,
        reviewRequiredCount,
        stillUnknownCount,
        quarantinedOutboxIds: Object.freeze(quarantinedOutboxIds)
      });
    } catch (err) {
      span.end({
        code: "ERROR",
        message: err instanceof Error ? err.message : "publication_recovery_sweep_failed"
      });
      throw err;
    }
  }

  /**
   * Executes bounded retention tombstone/expiration actions while strictly skipping any
   * target covered by an active non-expired retention hold.
   */
  async runBoundedRetentionSweep(input: {
    readonly instanceId: RuntimeInstanceId | string;
    readonly controlEpoch: ControlEpoch | string;
    readonly batchLimit?: number | undefined;
    readonly claimLeaseMs?: bigint | undefined;
  }): Promise<RetentionTombstoneSweepOutput> {
    const span = this.#telemetry.startSpan("relayquill.maintenance.retention_sweep");
    try {
      const instanceId = parseRuntimeInstanceId(input.instanceId, "instanceId");
      const controlEpoch = parseControlEpoch(input.controlEpoch, "controlEpoch");
      const batchLimit = Math.trunc(input.batchLimit ?? DEFAULT_RETENTION_BATCH_LIMIT);
      assertRetentionClaimBatchSize(batchLimit);
      const claimLeaseMs = input.claimLeaseMs ?? DEFAULT_RETENTION_ACTION_CLAIM_LEASE_MS;
      if (claimLeaseMs <= 0n) {
        throw new ValidationDomainError({
          code: "INVALID_VALUE",
          message: "claimLeaseMs must be positive"
        });
      }

      const nowInstant = this.#clock.nowInstant();
      const now = parseCanonicalUtcTimestamp(formatUtcTimestamp(nowInstant), "now");

      const dueActions = await this.#uow.inTransaction((tx) =>
        this.#maintenanceRepo.listDueRetentionActions(tx, now, batchLimit)
      );

      let skippedHeldCount = 0;
      let completedCount = 0;
      let alreadyCompleteCount = 0;
      const completedActionIds: RetentionActionId[] = [];
      const holdCache = new Map<string, readonly RetentionHoldSnapshot[]>();

      for (const action of dueActions) {
        const cacheKey = `${action.tenantId}:${action.projectId ?? "*"}`;
        let holdSnapshots = holdCache.get(cacheKey);
        if (holdSnapshots === undefined) {
          const rawHolds = await this.#uow.inTransaction((tx) =>
            this.#maintenanceRepo.listActiveRetentionHolds(tx, action.tenantId, action.projectId)
          );
          holdSnapshots = rawHolds.map((hold) => ({
            holdId: hold.id,
            targetKind: hold.targetKind as RetentionHoldSnapshot["targetKind"],
            state: hold.state,
            expiresAt:
              hold.expiresAt !== undefined
                ? parseUtcTimestamp(hold.expiresAt, "hold.expiresAt").instant
                : null
          }));
          holdCache.set(cacheKey, holdSnapshots);
        }

        const isHeld = holdSnapshots.some(
          (hold) =>
            isRetentionHoldActive(hold, nowInstant) &&
            (hold.targetKind === "project" || hold.targetKind === action.targetKind)
        );
        if (isHeld) {
          skippedHeldCount += 1;
          continue;
        }

        const claimed = await this.#uow.inTransaction((tx) =>
          this.#maintenanceRepo.claimRetentionAction(tx, {
            actionId: action.actionId,
            instanceId,
            controlEpoch,
            claimLeaseMs,
            now
          })
        );
        if (!claimed.claimed) {
          continue;
        }

        const finalized = await this.#uow.inTransaction((tx) =>
          this.#maintenanceRepo.finalizeRetentionAction(tx, {
            actionId: action.actionId,
            instanceId,
            controlEpoch,
            claimGeneration: claimed.claimGeneration,
            now
          })
        );

        if (finalized.outcome === "already_complete") {
          alreadyCompleteCount += 1;
        } else {
          completedCount += 1;
        }
        completedActionIds.push(finalized.actionId);
      }

      span.end({ code: "OK" });
      return Object.freeze({
        examinedCount: dueActions.length,
        skippedHeldCount,
        completedCount,
        alreadyCompleteCount,
        completedActionIds: Object.freeze(completedActionIds)
      });
    } catch (err) {
      span.end({ code: "ERROR", message: err instanceof Error ? err.message : "retention_failed" });
      throw err;
    }
  }

  evaluateContentRetention(input: {
    readonly currentState: ContentRetentionState;
    readonly allObligationsTerminal: boolean;
    readonly allObligationsTerminalAt: CanonicalUtcTimestamp | null;
    readonly hasLiveMandatoryDependencies: boolean;
    readonly holds: readonly RetentionHoldSnapshot[];
  }): ContentExpirationEvaluationResult {
    const nowInstant = this.#clock.nowInstant();
    return evaluateContentExpirationEligibility({
      currentState: input.currentState,
      allObligationsTerminal: input.allObligationsTerminal,
      allObligationsTerminalAt:
        input.allObligationsTerminalAt !== null
          ? parseUtcTimestamp(input.allObligationsTerminalAt, "allObligationsTerminalAt").instant
          : null,
      hasLiveMandatoryDependencies: input.hasLiveMandatoryDependencies,
      holds: input.holds,
      now: nowInstant
    });
  }

  evaluateHistoryRetirement(input: {
    readonly allDeliveryGenerationsTerminalAt: CanonicalUtcTimestamp | null;
    readonly hasLiveMandatoryDependencies?: boolean | undefined;
    readonly holds: readonly RetentionHoldSnapshot[];
  }): boolean {
    if (input.allDeliveryGenerationsTerminalAt === null) {
      return false;
    }
    const nowInstant = this.#clock.nowInstant();
    return isHistoryRetirementEligible(
      parseUtcTimestamp(
        input.allDeliveryGenerationsTerminalAt,
        "allDeliveryGenerationsTerminalAt"
      ).instant,
      input.hasLiveMandatoryDependencies ?? false,
      input.holds,
      nowInstant
    );
  }

  async verifyProjectProjection(input: {
    readonly tenantId: TenantId | string;
    readonly projectId: ProjectId | string;
  }): Promise<ProjectProjectionDriftReport> {
    const tenantId = parseTenantId(input.tenantId, "tenantId");
    const projectId = parseProjectId(input.projectId, "projectId");
    return this.#uow.inTransaction((tx) =>
      this.#maintenanceRepo.verifyProjectDeliveryProjection(tx, tenantId, projectId)
    );
  }

  async rebuildProjectProjection(input: {
    readonly tenantId: TenantId | string;
    readonly projectId: ProjectId | string;
  }): Promise<ProjectProjectionDriftReport> {
    const tenantId = parseTenantId(input.tenantId, "tenantId");
    const projectId = parseProjectId(input.projectId, "projectId");
    const now = parseCanonicalUtcTimestamp(formatUtcTimestamp(this.#clock.nowInstant()), "now");
    return this.#uow.inTransaction((tx) =>
      this.#maintenanceRepo.rebuildProjectDeliveryProjection(tx, tenantId, projectId, now)
    );
  }

  async #quarantineUnknownOutbox(
    outboxId: OutboxId,
    episodeId: PublicationRecoveryEpisodeId,
    reasonCode: string,
    now: CanonicalUtcTimestamp
  ): Promise<void> {
    await this.#uow.inTransaction((tx) =>
      this.#maintenanceRepo.markOutboxReviewRequired(tx, {
        outboxId,
        episodeId,
        reasonCode,
        now
      })
    );
  }
}
