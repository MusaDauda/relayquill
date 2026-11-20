import crypto from "node:crypto";
import {
  ConflictDomainError,
  type ControlEpoch,
  FANOUT_OUT_OF_ORDER_NAK_MS,
  FANOUT_PAGE_SIZE,
  formatUtcTimestamp,
  nowUtcInstant,
  parseControlEpoch,
  parseRuntimeInstanceId,
  type RuntimeInstanceId
} from "@relayquill/domain";
import {
  type BrokerConsumePort,
  type ClockPort,
  FanoutService,
  type IdGeneratorPort,
  type ProcessBrokerMessageOutput,
  type TelemetryPort,
  type UnitOfWorkPort,
  cryptoIdGeneratorPort,
  noopTelemetryPort,
  systemClockPort
} from "@relayquill/application";
import { type SchemaWorkerPool } from "@relayquill/event-schema";
import {
  findRuntimeInstanceById,
  type PgAdapter,
  type PgTransactionClient,
  PostgresRuntimeRegistryStore,
  readInstallationStatus,
  registerRuntimeInstance
} from "@relayquill/postgres";
import {
  type FanoutSettings,
  RuntimeLifecycleManager,
  type ShutdownReport
} from "@relayquill/runtime";
import { PostgresFanoutRepository } from "./repository.js";
import { WorkerSchemaEvaluatorAdapter } from "./schema-adapter.js";

export interface FanoutWorkerHealthSnapshot {
  readonly live: boolean;
  readonly ready: boolean;
  readonly role: "fanout";
  readonly instanceId: RuntimeInstanceId;
  readonly controlEpoch?: ControlEpoch | undefined;
  readonly started: boolean;
  readonly draining: boolean;
  readonly ticksCompleted: number;
  readonly messagesPulledCount: number;
  readonly completedCount: number;
  readonly alreadyCompletedCount: number;
  readonly nakedOutOfOrderCount: number;
  readonly claimedByPeerCount: number;
  readonly deliveriesCreatedCount: number;
  readonly lastTickAt?: string | undefined;
  readonly lastTickDurationMs?: number | undefined;
  readonly lastError?: string | undefined;
}

export interface FanoutWorkerRunResult {
  readonly controlEpoch: ControlEpoch;
  readonly pulledCount: number;
  readonly completedCount: number;
  readonly alreadyCompletedCount: number;
  readonly nakedOutOfOrderCount: number;
  readonly claimedByPeerCount: number;
  readonly deliveriesCreatedCount: number;
  readonly results: readonly ProcessBrokerMessageOutput[];
}

export interface FanoutWorkerOptions {
  readonly pgAdapter: PgAdapter;
  readonly broker: BrokerConsumePort;
  readonly schemaPool?: SchemaWorkerPool | undefined;
  readonly databaseRole?: string | undefined;
  readonly instanceId?: string | undefined;
  readonly controlEpoch?: string | undefined;
  readonly buildReference?: string | undefined;
  readonly settings?: Partial<FanoutSettings> | undefined;
  readonly pageSize?: number | undefined;
  readonly claimLeaseMs?: bigint | undefined;
  readonly pollIntervalMs?: number | undefined;
  readonly clock?: ClockPort | undefined;
  readonly idGenerator?: IdGeneratorPort | undefined;
  readonly telemetry?: TelemetryPort | undefined;
  readonly drainTimeoutMs?: number | undefined;
  readonly heartbeatIntervalMs?: bigint | undefined;
  readonly leaseMs?: bigint | undefined;
  readonly onError?: ((err: unknown) => void) | undefined;
}

const DEFAULT_FANOUT_SETTINGS: FanoutSettings = Object.freeze({
  ack_wait_ms: 30_000,
  max_deliver: 10,
  max_ack_pending: 100,
  max_batch: 32,
  max_bytes: 262_144,
  max_expires_ms: 250
});

export class FanoutWorker {
  readonly instanceId: RuntimeInstanceId;
  readonly #pgAdapter: PgAdapter;
  readonly #broker: BrokerConsumePort;
  readonly #databaseRole: string;
  readonly #buildReference: string;
  readonly #settings: FanoutSettings;
  readonly #pageSize: number;
  readonly #claimLeaseMs: bigint;
  readonly #pollIntervalMs: number;
  readonly #clock: ClockPort;
  readonly #schemaAdapter: WorkerSchemaEvaluatorAdapter;
  readonly #repo: PostgresFanoutRepository;
  readonly #service: FanoutService<PgTransactionClient>;
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
  #messagesPulledCount = 0;
  #completedCount = 0;
  #alreadyCompletedCount = 0;
  #nakedOutOfOrderCount = 0;
  #claimedByPeerCount = 0;
  #deliveriesCreatedCount = 0;
  #lastTickAt: string | undefined;
  #lastTickDurationMs: number | undefined;
  #lastError: string | undefined;

  constructor(options: FanoutWorkerOptions) {
    this.instanceId = parseRuntimeInstanceId(
      options.instanceId ?? crypto.randomUUID(),
      "instanceId"
    );
    this.#pgAdapter = options.pgAdapter;
    this.#broker = options.broker;
    this.#databaseRole = options.databaseRole ?? "rq_fanout";
    this.#buildReference = options.buildReference ?? "fanout-worker";
    this.#settings = Object.freeze({
      ack_wait_ms: options.settings?.ack_wait_ms ?? DEFAULT_FANOUT_SETTINGS.ack_wait_ms,
      max_deliver: options.settings?.max_deliver ?? DEFAULT_FANOUT_SETTINGS.max_deliver,
      max_ack_pending:
        options.settings?.max_ack_pending ?? DEFAULT_FANOUT_SETTINGS.max_ack_pending,
      max_batch: options.settings?.max_batch ?? DEFAULT_FANOUT_SETTINGS.max_batch,
      max_bytes: options.settings?.max_bytes ?? DEFAULT_FANOUT_SETTINGS.max_bytes,
      max_expires_ms: options.settings?.max_expires_ms ?? DEFAULT_FANOUT_SETTINGS.max_expires_ms
    });
    this.#pageSize = options.pageSize ?? FANOUT_PAGE_SIZE;
    this.#claimLeaseMs = options.claimLeaseMs ?? BigInt(this.#settings.ack_wait_ms);
    this.#pollIntervalMs = options.pollIntervalMs ?? 50;
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

    this.#schemaAdapter = new WorkerSchemaEvaluatorAdapter({
      pool: options.schemaPool
    });
    this.#repo = new PostgresFanoutRepository({
      onTargetSchemaDiscovered: (profileSha256, targetSchemaBytes) => {
        this.#schemaAdapter.registerTargetSchema(profileSha256, targetSchemaBytes);
      }
    });
    this.#service = new FanoutService<PgTransactionClient>({
      uow,
      fanoutRepo: this.#repo,
      schemaEvaluator: this.#schemaAdapter,
      clock: this.#clock,
      idGenerator: options.idGenerator ?? cryptoIdGeneratorPort,
      telemetry: options.telemetry ?? noopTelemetryPort
    });
  }

  get controlEpoch(): ControlEpoch | undefined {
    return this.#controlEpoch;
  }

  get service(): FanoutService<PgTransactionClient> {
    return this.#service;
  }

  getHealth(): FanoutWorkerHealthSnapshot {
    const live = !this.#stopped;
    const ready = !this.#stopped && !this.#draining && (this.#started || this.#ticksCompleted > 0);
    return Object.freeze({
      live,
      ready,
      role: "fanout",
      instanceId: this.instanceId,
      ...(this.#controlEpoch !== undefined ? { controlEpoch: this.#controlEpoch } : {}),
      started: this.#started,
      draining: this.#draining,
      ticksCompleted: this.#ticksCompleted,
      messagesPulledCount: this.#messagesPulledCount,
      completedCount: this.#completedCount,
      alreadyCompletedCount: this.#alreadyCompletedCount,
      nakedOutOfOrderCount: this.#nakedOutOfOrderCount,
      claimedByPeerCount: this.#claimedByPeerCount,
      deliveriesCreatedCount: this.#deliveriesCreatedCount,
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
            processRole: "fanout",
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

  async runOnce(signal?: AbortSignal): Promise<FanoutWorkerRunResult> {
    if (signal?.aborted) {
      throw new DOMException("Fanout tick aborted", "AbortError");
    }

    const startedMs = this.#clock.monotonicNowMs();
    try {
      const controlEpoch = this.#controlEpoch ?? (await this.#resolveControlEpoch());
      await this.#ensureRegistered(controlEpoch);

      const batch = await this.#broker.pullBatch({
        maxBatch: this.#settings.max_batch,
        maxBytes: this.#settings.max_bytes,
        expiresMs: this.#settings.max_expires_ms,
        ...(signal !== undefined ? { signal } : {})
      });

      const results: ProcessBrokerMessageOutput[] = [];
      let completedCount = 0;
      let alreadyCompletedCount = 0;
      let nakedOutOfOrderCount = 0;
      let claimedByPeerCount = 0;
      let deliveriesCreatedCount = 0;

      for (const message of batch) {
        if (signal?.aborted) {
          break;
        }
        try {
          const out = await this.#service.processBrokerMessage({
            message,
            instanceId: this.instanceId,
            controlEpoch,
            claimLeaseMs: this.#claimLeaseMs,
            pageSize: this.#pageSize
          });
          results.push(out);
          deliveriesCreatedCount += Number(out.deliveriesCreated);
          if (out.disposition === "completed") {
            completedCount += 1;
          } else if (out.disposition === "already_completed") {
            alreadyCompletedCount += 1;
          } else if (out.disposition === "out_of_order_naked") {
            nakedOutOfOrderCount += 1;
          } else {
            claimedByPeerCount += 1;
          }
        } catch (err) {
          if (err instanceof ConflictDomainError) {
            await message.nak(Number(FANOUT_OUT_OF_ORDER_NAK_MS)).catch(() => undefined);
            claimedByPeerCount += 1;
            continue;
          }
          throw err;
        }
      }

      this.#ticksCompleted += 1;
      this.#messagesPulledCount += batch.length;
      this.#completedCount += completedCount;
      this.#alreadyCompletedCount += alreadyCompletedCount;
      this.#nakedOutOfOrderCount += nakedOutOfOrderCount;
      this.#claimedByPeerCount += claimedByPeerCount;
      this.#deliveriesCreatedCount += deliveriesCreatedCount;
      this.#lastTickAt = formatUtcTimestamp(this.#clock.nowInstant());
      this.#lastTickDurationMs = Math.max(0, this.#clock.monotonicNowMs() - startedMs);
      this.#lastError = undefined;

      return Object.freeze({
        controlEpoch,
        pulledCount: batch.length,
        completedCount,
        alreadyCompletedCount,
        nakedOutOfOrderCount,
        claimedByPeerCount,
        deliveriesCreatedCount,
        results: Object.freeze(results)
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
      processRole: "fanout",
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
      name: "fanout-broker-pull",
      intervalMs: this.#pollIntervalMs,
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
    await this.#schemaAdapter.close().catch(() => undefined);
    this.#started = false;
    this.#stopped = true;
    return report;
  }
}

export function createFanoutWorker(options: FanoutWorkerOptions): FanoutWorker {
  return new FanoutWorker(options);
}

export async function runFanoutTick(options: FanoutWorkerOptions): Promise<FanoutWorkerRunResult> {
  const worker = createFanoutWorker(options);
  try {
    return await worker.runOnce();
  } finally {
    await worker.stop("single_tick");
  }
}
