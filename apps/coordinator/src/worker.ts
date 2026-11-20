import crypto from "node:crypto";
import {
  ConflictDomainError,
  LimitExceededDomainError,
  MAX_NO_PROGRESS_RECOVERY_GENERATIONS,
  RateLimitDomainError,
  formatUtcTimestamp,
  nowUtcInstant,
  parseControlEpoch,
  parseOutboxId,
  parsePublicationRecoveryEpisodeId,
  parseRuntimeInstanceId,
  type ControlEpoch,
  type RuntimeInstanceId
} from "@relayquill/domain";
import {
  decodeBrokerNotificationEnvelope,
  encodeBrokerNotificationEnvelope,
  parseCanonicalUtcTimestamp
} from "@relayquill/contracts";
import {
  MaintenanceService,
  RelayService,
  cryptoIdGeneratorPort,
  noopTelemetryPort,
  systemClockPort,
  type BrokerPublishPort,
  type ClockPort,
  type CoordinatorPromoteSweepOutput,
  type CoordinatorReapSweepOutput,
  type IdGeneratorPort,
  type PublicationRecoverySweepOutput,
  type RecoverUnknownOutboxInput,
  type RecoverUnknownOutboxOutput,
  type RetentionTombstoneSweepOutput,
  type TelemetryPort,
  type UnitOfWorkPort
} from "@relayquill/application";
import {
  PostgresRuntimeRegistryStore,
  findRuntimeInstanceById,
  readInstallationStatus,
  registerRuntimeInstance,
  type PgAdapter,
  type PgTransactionClient
} from "@relayquill/postgres";
import {
  RuntimeLifecycleManager,
  type CoordinatorSettings,
  type ShutdownReport
} from "@relayquill/runtime";
import {
  CoordinatorRelayRepository,
  PostgresMaintenanceRepository
} from "./repository.js";

export interface CoordinatorProjectionSweepOutput {
  readonly compactedEvents: number;
  readonly compactedProjects: number;
  readonly verifiedProjects: number;
  readonly driftedProjects: number;
  readonly rebuiltProjects: number;
}

export interface CoordinatorWorkerRunResult {
  readonly controlEpoch: ControlEpoch;
  readonly promotion: CoordinatorPromoteSweepOutput;
  readonly reaper: CoordinatorReapSweepOutput;
  readonly publicationRecovery: PublicationRecoverySweepOutput;
  readonly retention: RetentionTombstoneSweepOutput;
  readonly projections: CoordinatorProjectionSweepOutput;
}

export interface CoordinatorWorkerHealthSnapshot {
  readonly live: boolean;
  readonly ready: boolean;
  readonly role: "coordinator";
  readonly instanceId: RuntimeInstanceId;
  readonly controlEpoch?: ControlEpoch | undefined;
  readonly started: boolean;
  readonly draining: boolean;
  readonly ticksCompleted: number;
  readonly promotedDeliveriesTotal: number;
  readonly reapedItemsTotal: number;
  readonly quarantinedOutboxTotal: number;
  readonly retentionCompletedTotal: number;
  readonly rebuiltProjectionsTotal: number;
  readonly lastTickAt?: string | undefined;
  readonly lastTickDurationMs?: number | undefined;
  readonly lastError?: string | undefined;
}

export interface CoordinatorWorkerOptions {
  readonly pgAdapter: PgAdapter;
  readonly broker?: BrokerPublishPort | undefined;
  readonly databaseRole?: string | undefined;
  readonly relayDatabaseRole?: string | undefined;
  readonly instanceId?: string | undefined;
  readonly controlEpoch?: string | undefined;
  readonly buildReference?: string | undefined;
  readonly settings?: Partial<CoordinatorSettings> | undefined;
  readonly publicationRecoveryBatchSize?: number | undefined;
  readonly verifyProjectionsOnTick?: boolean | undefined;
  readonly autoRebuildDriftedProjections?: boolean | undefined;
  readonly forceNewRecoveryGeneration?: boolean | undefined;
  readonly clock?: ClockPort | undefined;
  readonly idGenerator?: IdGeneratorPort | undefined;
  readonly telemetry?: TelemetryPort | undefined;
  readonly drainTimeoutMs?: number | undefined;
  readonly heartbeatIntervalMs?: bigint | undefined;
  readonly leaseMs?: bigint | undefined;
  readonly onError?: ((err: unknown) => void) | undefined;
}

const DEFAULT_COORDINATOR_SETTINGS: CoordinatorSettings = Object.freeze({
  loop_interval_ms: 1000,
  reaper_batch_size: 100,
  retention_batch_size: 100,
  projection_batch_size: 64
});

export class CoordinatorWorker {
  readonly instanceId: RuntimeInstanceId;
  readonly #pgAdapter: PgAdapter;
  readonly #broker: BrokerPublishPort | undefined;
  readonly #databaseRole: string;
  readonly #relayDatabaseRole: string;
  readonly #buildReference: string;
  readonly #settings: CoordinatorSettings;
  readonly #publicationRecoveryBatchSize: number;
  readonly #verifyProjectionsOnTick: boolean;
  readonly #autoRebuildDriftedProjections: boolean;
  readonly #forceNewRecoveryGeneration: boolean;
  readonly #clock: ClockPort;
  readonly #ids: IdGeneratorPort;
  readonly #drainTimeoutMs: number;
  readonly #heartbeatIntervalMs: bigint;
  readonly #leaseMs: bigint;
  readonly #onError: ((err: unknown) => void) | undefined;
  readonly #maintenanceRepo: PostgresMaintenanceRepository;
  readonly #relayRepo: CoordinatorRelayRepository;
  readonly #service: MaintenanceService<PgTransactionClient>;
  readonly #relayService: RelayService<PgTransactionClient> | undefined;

  #controlEpoch: ControlEpoch | undefined;
  #lifecycle: RuntimeLifecycleManager | undefined;
  #tickPromise: Promise<CoordinatorWorkerRunResult> | undefined;
  #registered = false;
  #started = false;
  #draining = false;
  #stopped = false;
  #ticksCompleted = 0;
  #promotedDeliveriesTotal = 0;
  #reapedItemsTotal = 0;
  #quarantinedOutboxTotal = 0;
  #retentionCompletedTotal = 0;
  #rebuiltProjectionsTotal = 0;
  #lastTickAt: string | undefined;
  #lastTickDurationMs: number | undefined;
  #lastError: string | undefined;

  constructor(options: CoordinatorWorkerOptions) {
    this.#pgAdapter = options.pgAdapter;
    this.#broker = options.broker;
    this.#databaseRole = options.databaseRole ?? "rq_coordinator";
    this.#relayDatabaseRole = options.relayDatabaseRole ?? "rq_relay";
    this.instanceId = parseRuntimeInstanceId(
      options.instanceId ?? crypto.randomUUID(),
      "instanceId"
    );
    this.#controlEpoch =
      options.controlEpoch !== undefined
        ? parseControlEpoch(options.controlEpoch, "controlEpoch")
        : undefined;
    this.#buildReference = options.buildReference ?? "relayquill-coordinator@0.1.0";
    this.#settings = Object.freeze({
      loop_interval_ms:
        options.settings?.loop_interval_ms ?? DEFAULT_COORDINATOR_SETTINGS.loop_interval_ms,
      reaper_batch_size:
        options.settings?.reaper_batch_size ?? DEFAULT_COORDINATOR_SETTINGS.reaper_batch_size,
      retention_batch_size:
        options.settings?.retention_batch_size ?? DEFAULT_COORDINATOR_SETTINGS.retention_batch_size,
      projection_batch_size:
        options.settings?.projection_batch_size ??
        DEFAULT_COORDINATOR_SETTINGS.projection_batch_size
    });
    this.#publicationRecoveryBatchSize = Math.max(
      1,
      Math.min(100, options.publicationRecoveryBatchSize ?? 25)
    );
    this.#verifyProjectionsOnTick = options.verifyProjectionsOnTick ?? true;
    this.#autoRebuildDriftedProjections = options.autoRebuildDriftedProjections ?? true;
    this.#forceNewRecoveryGeneration = options.forceNewRecoveryGeneration ?? false;
    this.#clock = options.clock ?? systemClockPort;
    this.#ids = options.idGenerator ?? cryptoIdGeneratorPort;
    const telemetry = options.telemetry ?? noopTelemetryPort;
    this.#drainTimeoutMs = options.drainTimeoutMs ?? 5_000;
    this.#heartbeatIntervalMs = options.heartbeatIntervalMs ?? 5_000n;
    this.#leaseMs = options.leaseMs ?? 20_000n;
    this.#onError = options.onError;

    this.#maintenanceRepo = new PostgresMaintenanceRepository();
    this.#relayRepo = new CoordinatorRelayRepository();

    const coordinatorUow: UnitOfWorkPort<PgTransactionClient> = {
      inTransaction: async <T>(fn: (tx: PgTransactionClient) => Promise<T>): Promise<T> =>
        this.#pgAdapter.withTransaction(this.#databaseRole, fn, { retryOnContention: true })
    };
    const relayUow: UnitOfWorkPort<PgTransactionClient> = {
      inTransaction: async <T>(fn: (tx: PgTransactionClient) => Promise<T>): Promise<T> =>
        this.#pgAdapter.withTransaction(this.#relayDatabaseRole, fn, { retryOnContention: true })
    };

    if (this.#broker !== undefined) {
      this.#relayService = new RelayService({
        uow: relayUow,
        relayRepo: this.#relayRepo,
        broker: this.#broker,
        clock: this.#clock,
        idGenerator: this.#ids,
        telemetry
      });
    }

    this.#service = new MaintenanceService({
      uow: coordinatorUow,
      maintenanceRepo: this.#maintenanceRepo,
      recoverUnknownOutbox: (input) => this.#recoverUnknownOutbox(coordinatorUow, input),
      clock: this.#clock,
      idGenerator: this.#ids,
      telemetry
    });
  }

  get controlEpoch(): ControlEpoch | undefined {
    return this.#controlEpoch;
  }

  get service(): MaintenanceService<PgTransactionClient> {
    return this.#service;
  }

  get relayService(): RelayService<PgTransactionClient> | undefined {
    return this.#relayService;
  }

  getHealth(): CoordinatorWorkerHealthSnapshot {
    const live = !this.#stopped;
    const ready =
      !this.#stopped && !this.#draining && (this.#started || this.#ticksCompleted > 0);
    return Object.freeze({
      live,
      ready,
      role: "coordinator",
      instanceId: this.instanceId,
      ...(this.#controlEpoch !== undefined ? { controlEpoch: this.#controlEpoch } : {}),
      started: this.#started,
      draining: this.#draining,
      ticksCompleted: this.#ticksCompleted,
      promotedDeliveriesTotal: this.#promotedDeliveriesTotal,
      reapedItemsTotal: this.#reapedItemsTotal,
      quarantinedOutboxTotal: this.#quarantinedOutboxTotal,
      retentionCompletedTotal: this.#retentionCompletedTotal,
      rebuiltProjectionsTotal: this.#rebuiltProjectionsTotal,
      ...(this.#lastTickAt !== undefined ? { lastTickAt: this.#lastTickAt } : {}),
      ...(this.#lastTickDurationMs !== undefined
        ? { lastTickDurationMs: this.#lastTickDurationMs }
        : {}),
      ...(this.#lastError !== undefined ? { lastError: this.#lastError } : {})
    });
  }

  async #resolveControlEpoch(): Promise<ControlEpoch> {
    const status = await this.#pgAdapter.withTransaction(
      this.#databaseRole,
      (tx) => readInstallationStatus(tx),
      { readOnly: true }
    );
    this.#controlEpoch = status.controlEpoch;
    return status.controlEpoch;
  }

  async #ensureRegistered(controlEpoch: ControlEpoch): Promise<void> {
    if (this.#registered) {
      return;
    }
    await this.#pgAdapter.withTransaction(
      this.#databaseRole,
      async (tx) => {
        const existing = await findRuntimeInstanceById(tx, this.instanceId);
        if (existing === undefined) {
          await registerRuntimeInstance(tx, {
            instanceId: this.instanceId,
            processRole: "coordinator",
            databaseRole: this.#databaseRole,
            controlEpoch,
            buildReference: this.#buildReference,
            leaseMs: this.#leaseMs
          });
        }
      },
      { retryOnContention: true }
    );
    this.#registered = true;
  }

  async #recoverUnknownOutbox(
    coordinatorUow: UnitOfWorkPort<PgTransactionClient>,
    input: RecoverUnknownOutboxInput
  ): Promise<RecoverUnknownOutboxOutput> {
    const outboxId = parseOutboxId(input.outboxId, "outboxId");
    const episodeId = parsePublicationRecoveryEpisodeId(input.episodeId, "episodeId");
    const instanceId = parseRuntimeInstanceId(input.instanceId, "instanceId");
    const controlEpoch = parseControlEpoch(input.controlEpoch, "controlEpoch");

    if (input.noProgressGenerationCount >= MAX_NO_PROGRESS_RECOVERY_GENERATIONS) {
      return Object.freeze({
        outboxId,
        action: "review_required",
        publicationGeneration: 0n,
        brokerMessageId: ""
      });
    }

    const publications = await coordinatorUow.inTransaction((tx) =>
      this.#relayRepo.listOutboxPublications(tx, outboxId)
    );
    const latest = publications[publications.length - 1];
    if (latest === undefined) {
      return Object.freeze({
        outboxId,
        action: "still_unknown",
        publicationGeneration: 0n,
        brokerMessageId: ""
      });
    }
    if (latest.state === "published") {
      return Object.freeze({
        outboxId,
        action: "already_complete",
        publicationGeneration: latest.publicationGeneration,
        brokerMessageId: latest.brokerMessageId,
        outboxState: "published"
      });
    }

    if (input.forceNewGeneration !== true) {
      if (this.#relayService === undefined) {
        return Object.freeze({
          outboxId,
          action: "still_unknown",
          publicationGeneration: latest.publicationGeneration,
          brokerMessageId: latest.brokerMessageId
        });
      }
      try {
        const retried = await this.#relayService.publishClaimedOutbox({
          outboxId,
          instanceId,
          controlEpoch
        });
        if (retried.outcome === "published") {
          return Object.freeze({
            outboxId,
            action: "republished_same_generation",
            publicationGeneration: retried.publicationGeneration,
            brokerMessageId: retried.brokerMessageId,
            outboxState: retried.outboxState
          });
        }
        return Object.freeze({
          outboxId,
          action: "still_unknown",
          publicationGeneration: retried.publicationGeneration,
          brokerMessageId: retried.brokerMessageId,
          outboxState: retried.outboxState
        });
      } catch (err) {
        if (err instanceof ConflictDomainError) {
          return Object.freeze({
            outboxId,
            action: "still_unknown",
            publicationGeneration: latest.publicationGeneration,
            brokerMessageId: latest.brokerMessageId
          });
        }
        throw err;
      }
    }

    const decoded = decodeBrokerNotificationEnvelope(latest.envelopeBytes);
    const nextGeneration = latest.publicationGeneration + 1n;
    const nextEncoded = encodeBrokerNotificationEnvelope({
      envelope_version: 1,
      outbox_id: outboxId,
      event_id: decoded.event_id,
      project_id: decoded.project_id,
      topology_version: decoded.topology_version,
      publication_generation: nextGeneration,
      content_sha256: decoded.content_sha256,
      ...(decoded.traceparent !== undefined ? { traceparent: decoded.traceparent } : {}),
      ...(decoded.tracestate !== undefined ? { tracestate: decoded.tracestate } : {})
    });
    const now = parseCanonicalUtcTimestamp(formatUtcTimestamp(this.#clock.nowInstant()), "now");

    let allocation: {
      readonly outcome: "already_complete" | "review_required" | "allocated";
    };
    try {
      allocation = await coordinatorUow.inTransaction((tx) =>
        this.#relayRepo.allocateOutboxRecoveryGeneration(tx, {
          outboxId,
          episodeId,
          instanceId,
          controlEpoch,
          envelopeBytes: nextEncoded.bytes,
          envelopeSha256: nextEncoded.envelope_sha256,
          brokerMessageId: nextEncoded.broker_message_id,
          reasonCode: input.reasonCode ?? "DEDUP_WINDOW_ELAPSED_RECOVERY",
          now
        })
      );
    } catch (err) {
      // Rate limit (1 recovery generation per minute per episode, SQLSTATE 53400) leaves item unknown for next sweep.
      if (err instanceof RateLimitDomainError || err instanceof LimitExceededDomainError) {
        return Object.freeze({
          outboxId,
          action: "still_unknown",
          publicationGeneration: latest.publicationGeneration,
          brokerMessageId: latest.brokerMessageId
        });
      }
      throw err;
    }

    if (allocation.outcome === "already_complete") {
      return Object.freeze({
        outboxId,
        action: "already_complete",
        publicationGeneration: latest.publicationGeneration,
        brokerMessageId: latest.brokerMessageId,
        outboxState: "published"
      });
    }
    if (allocation.outcome === "review_required") {
      return Object.freeze({
        outboxId,
        action: "review_required",
        publicationGeneration: latest.publicationGeneration,
        brokerMessageId: latest.brokerMessageId
      });
    }

    if (this.#relayService === undefined) {
      return Object.freeze({
        outboxId,
        action: "still_unknown",
        publicationGeneration: nextGeneration,
        brokerMessageId: nextEncoded.broker_message_id,
        outboxState: "pending"
      });
    }

    const published = await this.#relayService.publishClaimedOutbox({
      outboxId,
      instanceId,
      controlEpoch
    });

    return Object.freeze({
      outboxId,
      action:
        published.outcome === "published"
          ? "allocated_and_published_new_generation"
          : "still_unknown",
      publicationGeneration: published.publicationGeneration,
      brokerMessageId: published.brokerMessageId,
      outboxState: published.outboxState
    });
  }

  async #runProjectionCompactionAndVerification(
    verifyProjections: boolean
  ): Promise<CoordinatorProjectionSweepOutput> {
    const compacted = await this.#pgAdapter.withTransaction(
      this.#databaseRole,
      (tx) =>
        this.#maintenanceRepo.compactDueDeltaShards(tx, this.#settings.projection_batch_size),
      { retryOnContention: true }
    );

    if (!verifyProjections) {
      return Object.freeze({
        compactedEvents: compacted.compactedEvents,
        compactedProjects: compacted.compactedProjects,
        verifiedProjects: 0,
        driftedProjects: 0,
        rebuiltProjects: 0
      });
    }

    const projects = await this.#pgAdapter.withTransaction(this.#databaseRole, (tx) =>
      this.#maintenanceRepo.listProjectsForProjectionVerification(
        tx,
        this.#settings.projection_batch_size
      )
    );

    let verifiedProjects = 0;
    let driftedProjects = 0;
    let rebuiltProjects = 0;

    for (const scope of projects) {
      const report = await this.#service.verifyProjectProjection({
        tenantId: scope.tenantId,
        projectId: scope.projectId
      });
      verifiedProjects += 1;
      if (!report.consistent) {
        driftedProjects += 1;
        if (this.#autoRebuildDriftedProjections) {
          await this.#service.rebuildProjectProjection({
            tenantId: scope.tenantId,
            projectId: scope.projectId
          });
          rebuiltProjects += 1;
        }
      }
    }

    return Object.freeze({
      compactedEvents: compacted.compactedEvents,
      compactedProjects: compacted.compactedProjects,
      verifiedProjects,
      driftedProjects,
      rebuiltProjects
    });
  }

  async runOnce(options?: {
    readonly forceNewGeneration?: boolean | undefined;
    readonly verifyProjections?: boolean | undefined;
    readonly signal?: AbortSignal | undefined;
  }): Promise<CoordinatorWorkerRunResult> {
    if (options?.signal?.aborted) {
      throw new DOMException("Coordinator tick aborted", "AbortError");
    }
    if (this.#tickPromise !== undefined) {
      return this.#tickPromise;
    }

    const startedMs = this.#clock.monotonicNowMs();
    this.#tickPromise = (async () => {
      const controlEpoch = this.#controlEpoch ?? (await this.#resolveControlEpoch());
      await this.#ensureRegistered(controlEpoch);

      const promotion = await this.#service.runEligibilityPromoter();
      const reaper = await this.#service.reapExpiredWorkAndWatchLeases({
        instanceId: this.instanceId,
        controlEpoch,
        batchLimit: this.#settings.reaper_batch_size
      });
      const publicationRecovery = await this.#service.runPublicationRecoverySweep({
        instanceId: this.instanceId,
        controlEpoch,
        maxPerSweep: this.#publicationRecoveryBatchSize,
        forceNewGeneration: options?.forceNewGeneration ?? this.#forceNewRecoveryGeneration
      });
      const retention = await this.#service.runBoundedRetentionSweep({
        instanceId: this.instanceId,
        controlEpoch,
        batchLimit: this.#settings.retention_batch_size
      });
      const projections = await this.#runProjectionCompactionAndVerification(
        options?.verifyProjections ?? this.#verifyProjectionsOnTick
      );

      this.#ticksCompleted += 1;
      this.#promotedDeliveriesTotal += promotion.promotedDeliveries;
      this.#reapedItemsTotal +=
        reaper.reapedAttempts +
        reaper.reapedOutboxClaims +
        reaper.reapedFanoutClaims +
        reaper.reapedWatchLeases;
      this.#quarantinedOutboxTotal += publicationRecovery.reviewRequiredCount;
      this.#retentionCompletedTotal += retention.completedCount;
      this.#rebuiltProjectionsTotal += projections.rebuiltProjects;
      this.#lastTickAt = formatUtcTimestamp(this.#clock.nowInstant());
      this.#lastTickDurationMs = Math.max(0, this.#clock.monotonicNowMs() - startedMs);
      this.#lastError = undefined;

      return Object.freeze({
        controlEpoch,
        promotion,
        reaper,
        publicationRecovery,
        retention,
        projections
      });
    })();

    try {
      return await this.#tickPromise;
    } catch (err) {
      this.#lastTickAt = formatUtcTimestamp(this.#clock.nowInstant());
      this.#lastTickDurationMs = Math.max(0, this.#clock.monotonicNowMs() - startedMs);
      this.#lastError = err instanceof Error ? err.message : String(err);
      throw err;
    } finally {
      this.#tickPromise = undefined;
    }
  }

  async start(): Promise<void> {
    if (this.#started) {
      return;
    }
    this.#stopped = false;
    this.#draining = false;

    const controlEpoch = this.#controlEpoch ?? (await this.#resolveControlEpoch());
    const registryStore = new PostgresRuntimeRegistryStore(this.#pgAdapter, this.#databaseRole);

    const lifecycle = new RuntimeLifecycleManager({
      instanceId: this.instanceId,
      processRole: "coordinator",
      databaseRole: this.#databaseRole,
      controlEpoch,
      buildReference: this.#buildReference,
      store: registryStore,
      drainTimeoutMs: this.#drainTimeoutMs,
      leaseMs: this.#leaseMs,
      heartbeatIntervalMs: this.#heartbeatIntervalMs,
      nowFn: () => nowUtcInstant(),
      onAuthorityInvalidated: (reason) => {
        this.#lastError = reason;
        this.#draining = true;
      }
    });

    lifecycle.registerWorkerLoop({
      name: "coordinator-maintenance-loop",
      intervalMs: this.#settings.loop_interval_ms,
      runOnce: async (signal) => {
        await this.runOnce({ signal });
      },
      onError: (err) => {
        this.#lastError = err instanceof Error ? err.message : String(err);
        this.#onError?.(err);
      }
    });

    this.#lifecycle = lifecycle;
    await lifecycle.start();
    this.#registered = true;
    this.#started = true;
  }

  async stop(reason = "worker_stop"): Promise<ShutdownReport | undefined> {
    this.#draining = true;
    let report: ShutdownReport | undefined;
    if (this.#lifecycle !== undefined) {
      report = await this.#lifecycle.shutdown(reason);
      this.#lifecycle = undefined;
    }
    this.#started = false;
    this.#stopped = true;
    return report;
  }
}

export function createCoordinatorWorker(
  options: CoordinatorWorkerOptions
): CoordinatorWorker {
  return new CoordinatorWorker(options);
}
