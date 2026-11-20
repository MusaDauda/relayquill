import crypto from "node:crypto";
import {
  ConflictDomainError,
  type ControlEpoch,
  formatUtcTimestamp,
  nowUtcInstant,
  parseControlEpoch,
  parseRuntimeInstanceId,
  type RuntimeInstanceId
} from "@relayquill/domain";
import { parseCanonicalUtcTimestamp } from "@relayquill/contracts";
import {
  type BrokerPublishPort,
  type ClockPort,
  type IdGeneratorPort,
  type RelayPublishAttemptOutput,
  RelayService,
  type TelemetryPort,
  type UnitOfWorkPort,
  cryptoIdGeneratorPort,
  noopTelemetryPort,
  systemClockPort
} from "@relayquill/application";
import {
  findRuntimeInstanceById,
  type PgAdapter,
  type PgTransactionClient,
  PostgresRuntimeRegistryStore,
  readInstallationStatus,
  registerRuntimeInstance
} from "@relayquill/postgres";
import {
  type RelaySettings,
  RuntimeLifecycleManager,
  type ShutdownReport
} from "@relayquill/runtime";
import { PostgresRelayRepository } from "./repository.js";

export interface RelayWorkerHealthSnapshot {
  readonly live: boolean;
  readonly ready: boolean;
  readonly role: "relay";
  readonly instanceId: RuntimeInstanceId;
  readonly controlEpoch?: ControlEpoch | undefined;
  readonly started: boolean;
  readonly draining: boolean;
  readonly ticksCompleted: number;
  readonly publishedCount: number;
  readonly publishUnknownCount: number;
  readonly retryPendingCount: number;
  readonly blockedCount: number;
  readonly lastTickAt?: string | undefined;
  readonly lastTickDurationMs?: number | undefined;
  readonly lastError?: string | undefined;
}

export interface RelayWorkerRunResult {
  readonly controlEpoch: ControlEpoch;
  readonly scannedCount: number;
  readonly publishedCount: number;
  readonly publishUnknownCount: number;
  readonly retryPendingCount: number;
  readonly blockedCount: number;
  readonly skippedContentionCount: number;
  readonly outcomes: readonly RelayPublishAttemptOutput[];
}

export interface RelayWorkerOptions {
  readonly pgAdapter: PgAdapter;
  readonly broker: BrokerPublishPort;
  readonly databaseRole?: string | undefined;
  readonly instanceId?: string | undefined;
  readonly controlEpoch?: string | undefined;
  readonly buildReference?: string | undefined;
  readonly settings?: Partial<RelaySettings> | undefined;
  readonly clock?: ClockPort | undefined;
  readonly idGenerator?: IdGeneratorPort | undefined;
  readonly telemetry?: TelemetryPort | undefined;
  readonly drainTimeoutMs?: number | undefined;
  readonly heartbeatIntervalMs?: bigint | undefined;
  readonly leaseMs?: bigint | undefined;
  readonly onError?: ((err: unknown) => void) | undefined;
}

const DEFAULT_RELAY_SETTINGS: RelaySettings = Object.freeze({
  poll_interval_ms: 100,
  batch_size: 32,
  claim_lease_ms: 15_000,
  publish_concurrency: 4,
  publish_timeout_ms: 2_000
});

export class RelayWorker {
  readonly instanceId: RuntimeInstanceId;
  readonly #pgAdapter: PgAdapter;
  readonly #broker: BrokerPublishPort;
  readonly #databaseRole: string;
  readonly #buildReference: string;
  readonly #settings: RelaySettings;
  readonly #clock: ClockPort;
  readonly #repo: PostgresRelayRepository;
  readonly #service: RelayService<PgTransactionClient>;
  readonly #drainTimeoutMs: number;
  readonly #heartbeatIntervalMs: bigint | undefined;
  readonly #leaseMs: bigint | undefined;
  readonly #onError: ((err: unknown) => void) | undefined;

  #controlEpoch: ControlEpoch | undefined;
  #lifecycle: RuntimeLifecycleManager | undefined;
  #registered = false;
  #started = false;
  #draining = false;
  #stopped = false;
  #ticksCompleted = 0;
  #publishedCount = 0;
  #publishUnknownCount = 0;
  #retryPendingCount = 0;
  #blockedCount = 0;
  #lastTickAt: string | undefined;
  #lastTickDurationMs: number | undefined;
  #lastError: string | undefined;

  constructor(options: RelayWorkerOptions) {
    this.instanceId = parseRuntimeInstanceId(
      options.instanceId ?? crypto.randomUUID(),
      "instanceId"
    );
    this.#pgAdapter = options.pgAdapter;
    this.#broker = options.broker;
    this.#databaseRole = options.databaseRole ?? "rq_relay";
    this.#buildReference = options.buildReference ?? "relay-worker";
    this.#settings = Object.freeze({
      poll_interval_ms: options.settings?.poll_interval_ms ?? DEFAULT_RELAY_SETTINGS.poll_interval_ms,
      batch_size: options.settings?.batch_size ?? DEFAULT_RELAY_SETTINGS.batch_size,
      claim_lease_ms: options.settings?.claim_lease_ms ?? DEFAULT_RELAY_SETTINGS.claim_lease_ms,
      publish_concurrency:
        options.settings?.publish_concurrency ?? DEFAULT_RELAY_SETTINGS.publish_concurrency,
      publish_timeout_ms:
        options.settings?.publish_timeout_ms ?? DEFAULT_RELAY_SETTINGS.publish_timeout_ms
    });
    this.#clock = options.clock ?? systemClockPort;
    this.#drainTimeoutMs = options.drainTimeoutMs ?? 10_000;
    this.#heartbeatIntervalMs = options.heartbeatIntervalMs;
    this.#leaseMs = options.leaseMs;
    this.#onError = options.onError;

    if (options.controlEpoch !== undefined) {
      this.#controlEpoch = parseControlEpoch(options.controlEpoch, "controlEpoch");
    }

    const uow: UnitOfWorkPort<PgTransactionClient> = {
      inTransaction: <T>(fn: (tx: PgTransactionClient) => Promise<T>): Promise<T> =>
        this.#pgAdapter.withTransaction(this.#databaseRole, fn, { retryOnContention: true })
    };

    this.#repo = new PostgresRelayRepository();
    this.#service = new RelayService<PgTransactionClient>({
      uow,
      relayRepo: this.#repo,
      broker: this.#broker,
      clock: this.#clock,
      idGenerator: options.idGenerator ?? cryptoIdGeneratorPort,
      telemetry: options.telemetry ?? noopTelemetryPort
    });
  }

  get controlEpoch(): ControlEpoch | undefined {
    return this.#controlEpoch;
  }

  get service(): RelayService<PgTransactionClient> {
    return this.#service;
  }

  getHealth(): RelayWorkerHealthSnapshot {
    const live = !this.#stopped;
    const ready = !this.#stopped && !this.#draining && (this.#started || this.#ticksCompleted > 0);
    return Object.freeze({
      live,
      ready,
      role: "relay",
      instanceId: this.instanceId,
      ...(this.#controlEpoch !== undefined ? { controlEpoch: this.#controlEpoch } : {}),
      started: this.#started,
      draining: this.#draining,
      ticksCompleted: this.#ticksCompleted,
      publishedCount: this.#publishedCount,
      publishUnknownCount: this.#publishUnknownCount,
      retryPendingCount: this.#retryPendingCount,
      blockedCount: this.#blockedCount,
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
    const leaseMs = this.#leaseMs ?? 30_000n;
    await this.#pgAdapter.withTransaction(
      this.#databaseRole,
      async (tx) => {
        const existing = await findRuntimeInstanceById(tx, this.instanceId);
        if (existing === undefined) {
          await registerRuntimeInstance(tx, {
            instanceId: this.instanceId,
            processRole: "relay",
            databaseRole: this.#databaseRole,
            controlEpoch,
            buildReference: this.#buildReference,
            leaseMs
          });
        }
      },
      { retryOnContention: true }
    );
    this.#registered = true;
  }

  async runOnce(signal?: AbortSignal): Promise<RelayWorkerRunResult> {
    if (signal?.aborted) {
      throw new DOMException("Relay tick aborted", "AbortError");
    }

    const startedMs = this.#clock.monotonicNowMs();
    try {
      const controlEpoch = this.#controlEpoch ?? (await this.#resolveControlEpoch());
      await this.#ensureRegistered(controlEpoch);

      const now = parseCanonicalUtcTimestamp(
        formatUtcTimestamp(this.#clock.nowInstant()),
        "now"
      );

      const dueRows = await this.#pgAdapter.withTransaction(
        this.#databaseRole,
        (tx) => this.#repo.listDueOutboxEvents(tx, now, this.#settings.batch_size),
        { readOnly: true, ...(signal !== undefined ? { signal } : {}) }
      );

      const outcomes: RelayPublishAttemptOutput[] = [];
      let skippedContentionCount = 0;

      const concurrency = Math.max(
        1,
        Math.min(this.#settings.publish_concurrency, dueRows.length || 1)
      );
      let cursor = 0;

      const workerLane = async (): Promise<void> => {
        while (cursor < dueRows.length) {
          if (signal?.aborted) {
            return;
          }
          const idx = cursor;
          cursor += 1;
          const row = dueRows[idx];
          if (row === undefined) {
            return;
          }
          try {
            const published = await this.#service.publishClaimedOutbox({
              outboxId: row.outboxId,
              instanceId: this.instanceId,
              controlEpoch,
              claimLeaseMs: BigInt(this.#settings.claim_lease_ms),
              publishTimeoutMs: this.#settings.publish_timeout_ms
            });
            outcomes.push(published);
          } catch (err) {
            if (err instanceof ConflictDomainError) {
              skippedContentionCount += 1;
              continue;
            }
            throw err;
          }
        }
      };

      const lanes: Promise<void>[] = [];
      for (let i = 0; i < concurrency; i += 1) {
        lanes.push(workerLane());
      }
      await Promise.all(lanes);

      let publishedCount = 0;
      let publishUnknownCount = 0;
      let retryPendingCount = 0;
      let blockedCount = 0;

      for (const item of outcomes) {
        if (item.outcome === "published") {
          publishedCount += 1;
        } else if (item.outcome === "publish_unknown") {
          publishUnknownCount += 1;
        } else if (item.outcome === "retry_pending") {
          retryPendingCount += 1;
        } else {
          blockedCount += 1;
        }
      }

      this.#ticksCompleted += 1;
      this.#publishedCount += publishedCount;
      this.#publishUnknownCount += publishUnknownCount;
      this.#retryPendingCount += retryPendingCount;
      this.#blockedCount += blockedCount;
      this.#lastTickAt = formatUtcTimestamp(this.#clock.nowInstant());
      this.#lastTickDurationMs = Math.max(0, this.#clock.monotonicNowMs() - startedMs);
      this.#lastError = undefined;

      return Object.freeze({
        controlEpoch,
        scannedCount: dueRows.length,
        publishedCount,
        publishUnknownCount,
        retryPendingCount,
        blockedCount,
        skippedContentionCount,
        outcomes: Object.freeze(outcomes)
      });
    } catch (err) {
      this.#lastTickAt = formatUtcTimestamp(this.#clock.nowInstant());
      this.#lastTickDurationMs = Math.max(0, this.#clock.monotonicNowMs() - startedMs);
      this.#lastError = err instanceof Error ? err.message : String(err);
      throw err;
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
      processRole: "relay",
      databaseRole: this.#databaseRole,
      controlEpoch,
      buildReference: this.#buildReference,
      store: registryStore,
      drainTimeoutMs: this.#drainTimeoutMs,
      ...(this.#leaseMs !== undefined ? { leaseMs: this.#leaseMs } : {}),
      ...(this.#heartbeatIntervalMs !== undefined
        ? { heartbeatIntervalMs: this.#heartbeatIntervalMs }
        : {}),
      nowFn: () => nowUtcInstant(),
      onAuthorityInvalidated: (reason) => {
        this.#lastError = reason;
        this.#draining = true;
      }
    });

    lifecycle.registerWorkerLoop({
      name: "relay-outbox-poll",
      intervalMs: this.#settings.poll_interval_ms,
      runOnce: async (signal) => {
        await this.runOnce(signal);
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

export function createRelayWorker(options: RelayWorkerOptions): RelayWorker {
  return new RelayWorker(options);
}

export async function runRelayTick(options: RelayWorkerOptions): Promise<RelayWorkerRunResult> {
  const worker = createRelayWorker(options);
  return worker.runOnce();
}
