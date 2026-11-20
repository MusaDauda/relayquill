import crypto from "node:crypto";
import {
  AuthorizationDomainError,
  ConflictDomainError,
  type ControlEpoch,
  formatUtcTimestamp,
  nowUtcInstant,
  parseControlEpoch,
  parseEndpointVerificationAttemptId,
  parseEndpointVerificationIntentId,
  parseRuntimeInstanceId,
  type PrincipalId,
  type RuntimeInstanceId
} from "@relayquill/domain";
import {
  type ClockPort,
  DeliveryExecutionService,
  DISPATCH_CLAIM_MAX_BATCH,
  DispatchService,
  type EgressExecutorPort,
  type EgressResolverPort,
  type ExecuteEndpointVerificationAttemptOutput,
  type ExecutePreparedAttemptOutput,
  type IdGeneratorPort,
  type TelemetryPort,
  type UnitOfWorkPort,
  type WebhookSignerPort,
  cryptoIdGeneratorPort,
  noopTelemetryPort,
  systemClockPort
} from "@relayquill/application";
import {
  PinnedEgressConnector,
  resolveAndValidateEgress
} from "@relayquill/egress";
import {
  findRuntimeInstanceById,
  type PgAdapter,
  type PgTransactionClient,
  PostgresRuntimeRegistryStore,
  readInstallationStatus,
  registerRuntimeInstance
} from "@relayquill/postgres";
import {
  type EgressConfig,
  type ProfileKind,
  RuntimeLifecycleManager,
  type SenderSettings,
  type ShutdownReport
} from "@relayquill/runtime";
import {
  signEndpointVerificationRequest,
  signWebhookDelivery,
  verifyEndpointProofResponse,
  verifyReceiverLocalCommitReceiptResponse
} from "@relayquill/signing";
import {
  createSenderCustodyKeyProvider,
  type SenderKeyCustodyOptions
} from "./custody.js";
import {
  PostgresDeliveryExecutionRepository,
  PostgresDispatchRepository
} from "./repository.js";

const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export interface SenderWorkerHealthSnapshot {
  readonly live: boolean;
  readonly ready: boolean;
  readonly role: "sender";
  readonly instanceId: RuntimeInstanceId;
  readonly controlEpoch?: ControlEpoch | undefined;
  readonly started: boolean;
  readonly draining: boolean;
  readonly ticksCompleted: number;
  readonly deliveriesClaimedCount: number;
  readonly deliveriesAcknowledgedCount: number;
  readonly deliveriesRetryCount: number;
  readonly deliveriesDeadLetterCount: number;
  readonly deliveriesFailedBeforeSendCount: number;
  readonly verificationsAttemptedCount: number;
  readonly verificationsVerifiedCount: number;
  readonly lastTickAt?: string | undefined;
  readonly lastTickDurationMs?: number | undefined;
  readonly lastError?: string | undefined;
}

export interface SenderWorkerRunResult {
  readonly controlEpoch: ControlEpoch;
  readonly dispatchDomainId?: string | undefined;
  readonly claimedDeliveriesCount: number;
  readonly deliveryOutcomes: readonly ExecutePreparedAttemptOutput[];
  readonly verificationOutcomes: readonly ExecuteEndpointVerificationAttemptOutput[];
}

export interface SenderWorkerOptions extends SenderKeyCustodyOptions {
  readonly pgAdapter: PgAdapter;
  readonly databaseRole?: string | undefined;
  readonly instanceId?: string | undefined;
  readonly controlEpoch?: string | undefined;
  readonly buildReference?: string | undefined;
  readonly profile?: ProfileKind | undefined;
  readonly egressConfig?: EgressConfig | undefined;
  readonly ca?: string | Buffer | readonly (string | Buffer)[] | undefined;
  readonly settings?: Partial<SenderSettings> | undefined;
  readonly claimLeaseMs?: bigint | undefined;
  readonly recorderPrincipalId?: PrincipalId | undefined;
  readonly egressResolver?: EgressResolverPort | undefined;
  readonly egressExecutor?: EgressExecutorPort | undefined;
  readonly clock?: ClockPort | undefined;
  readonly idGenerator?: IdGeneratorPort | undefined;
  readonly telemetry?: TelemetryPort | undefined;
  readonly drainTimeoutMs?: number | undefined;
  readonly heartbeatIntervalMs?: bigint | undefined;
  readonly leaseMs?: bigint | undefined;
  readonly onError?: ((err: unknown) => void) | undefined;
}

const DEFAULT_SENDER_SETTINGS: SenderSettings = Object.freeze({
  dispatch_domain: "default",
  approved_slots: 8,
  poll_interval_ms: 100,
  request_timeout_ms: 10_000,
  max_response_bytes: 65_536
});

export class SenderWorker {
  readonly instanceId: RuntimeInstanceId;
  readonly #pgAdapter: PgAdapter;
  readonly #databaseRole: string;
  readonly #buildReference: string;
  readonly #settings: SenderSettings;
  readonly #claimLeaseMs: bigint;
  readonly #clock: ClockPort;
  readonly #ids: IdGeneratorPort;
  readonly #dispatchRepo: PostgresDispatchRepository;
  readonly #deliveryRepo: PostgresDeliveryExecutionRepository;
  readonly #dispatchService: DispatchService<PgTransactionClient>;
  readonly #deliveryService: DeliveryExecutionService<PgTransactionClient>;
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
  #deliveriesClaimedCount = 0;
  #deliveriesAcknowledgedCount = 0;
  #deliveriesRetryCount = 0;
  #deliveriesDeadLetterCount = 0;
  #deliveriesFailedBeforeSendCount = 0;
  #verificationsAttemptedCount = 0;
  #verificationsVerifiedCount = 0;
  #lastTickAt: string | undefined;
  #lastTickDurationMs: number | undefined;
  #lastError: string | undefined;

  constructor(options: SenderWorkerOptions) {
    this.instanceId = parseRuntimeInstanceId(
      options.instanceId ?? crypto.randomUUID(),
      "instanceId"
    );
    this.#pgAdapter = options.pgAdapter;
    this.#databaseRole = options.databaseRole ?? "rq_sender";
    this.#buildReference = options.buildReference ?? "sender-worker";
    this.#settings = Object.freeze({
      dispatch_domain:
        options.settings?.dispatch_domain ?? DEFAULT_SENDER_SETTINGS.dispatch_domain,
      approved_slots: options.settings?.approved_slots ?? DEFAULT_SENDER_SETTINGS.approved_slots,
      poll_interval_ms:
        options.settings?.poll_interval_ms ?? DEFAULT_SENDER_SETTINGS.poll_interval_ms,
      request_timeout_ms:
        options.settings?.request_timeout_ms ?? DEFAULT_SENDER_SETTINGS.request_timeout_ms,
      max_response_bytes:
        options.settings?.max_response_bytes ?? DEFAULT_SENDER_SETTINGS.max_response_bytes
    });
    this.#claimLeaseMs = options.claimLeaseMs ?? 30_000n;
    this.#clock = options.clock ?? systemClockPort;
    this.#ids = options.idGenerator ?? cryptoIdGeneratorPort;
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

    const custody = createSenderCustodyKeyProvider({
      getKeyMaterial: options.getKeyMaterial,
      secretProvider: options.secretProvider,
      secretProviderConfig: options.secretProviderConfig,
      ipcChannel: options.ipcChannel,
      initialInMemorySecrets: options.initialInMemorySecrets,
      env: options.env,
      resolveCustodyReference: options.resolveCustodyReference
    });

    this.#dispatchRepo = new PostgresDispatchRepository();
    this.#deliveryRepo = new PostgresDeliveryExecutionRepository({
      recorderPrincipalId: options.recorderPrincipalId,
      onCustodyKeyDiscovered: (endpointId, keyId, custodyReference, metadata) => {
        custody.recordKeyCustody(endpointId, keyId, custodyReference, metadata);
      }
    });

    const egressResolver: EgressResolverPort = options.egressResolver ?? {
      resolve: (url, resolveOpts) =>
        resolveAndValidateEgress({
          target: url,
          ...(resolveOpts !== undefined ? resolveOpts : {})
        })
    };

    const defaultConnector = new PinnedEgressConnector({
      profile: options.profile,
      egressConfig: options.egressConfig,
      ca: options.ca
    });
    const egressExecutor: EgressExecutorPort = options.egressExecutor ?? {
      execute: (input) => defaultConnector.execute(input)
    };

    const fixtureAuthorityAllowed =
      options.profile !== "release" &&
      options.profile !== "self_hosted" &&
      options.egressConfig?.allow_fixture_receiver === true;
    const authorityValidation = fixtureAuthorityAllowed
      ? {
          allowFixtureAuthority: true as const,
          ...(options.egressConfig?.fixture_receiver_authority !== undefined
            ? { expectedFixtureAuthority: options.egressConfig.fixture_receiver_authority }
            : {})
        }
      : undefined;

    const webhookSigner: WebhookSignerPort = {
      signDelivery: (input) =>
        signWebhookDelivery({
          ...(authorityValidation !== undefined ? { authorityValidation } : {}),
          ...input
        }),
      signEndpointVerification: (input) =>
        signEndpointVerificationRequest({
          ...(authorityValidation !== undefined ? { authorityValidation } : {}),
          ...input
        }),
      verifyEndpointProof: (input) => verifyEndpointProofResponse(input),
      verifyReceiverReceipt: (input) => verifyReceiverLocalCommitReceiptResponse(input)
    };

    this.#dispatchService = new DispatchService<PgTransactionClient>({
      uow,
      dispatchRepo: this.#dispatchRepo,
      clock: this.#clock,
      idGenerator: this.#ids,
      telemetry: options.telemetry ?? noopTelemetryPort
    });

    this.#deliveryService = new DeliveryExecutionService<PgTransactionClient>({
      uow,
      deliveryRepo: this.#deliveryRepo,
      egressResolver,
      egressExecutor,
      webhookSigner,
      getKeyMaterial: custody.asResolver(),
      profile: options.profile,
      egressConfig: options.egressConfig,
      ca: options.ca,
      clock: this.#clock,
      idGenerator: this.#ids,
      telemetry: options.telemetry ?? noopTelemetryPort
    });
  }

  get controlEpoch(): ControlEpoch | undefined {
    return this.#controlEpoch;
  }

  get dispatchService(): DispatchService<PgTransactionClient> {
    return this.#dispatchService;
  }

  get deliveryService(): DeliveryExecutionService<PgTransactionClient> {
    return this.#deliveryService;
  }

  getHealth(): SenderWorkerHealthSnapshot {
    const live = !this.#stopped;
    const ready = !this.#stopped && !this.#draining && (this.#started || this.#ticksCompleted > 0);
    return Object.freeze({
      live,
      ready,
      role: "sender",
      instanceId: this.instanceId,
      ...(this.#controlEpoch !== undefined ? { controlEpoch: this.#controlEpoch } : {}),
      started: this.#started,
      draining: this.#draining,
      ticksCompleted: this.#ticksCompleted,
      deliveriesClaimedCount: this.#deliveriesClaimedCount,
      deliveriesAcknowledgedCount: this.#deliveriesAcknowledgedCount,
      deliveriesRetryCount: this.#deliveriesRetryCount,
      deliveriesDeadLetterCount: this.#deliveriesDeadLetterCount,
      deliveriesFailedBeforeSendCount: this.#deliveriesFailedBeforeSendCount,
      verificationsAttemptedCount: this.#verificationsAttemptedCount,
      verificationsVerifiedCount: this.#verificationsVerifiedCount,
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
            processRole: "sender",
            databaseRole: this.#databaseRole,
            controlEpoch,
            buildReference: this.#buildReference,
            leaseMs,
            approvedSlots: this.#settings.approved_slots
          });
        }
      },
      { retryOnContention: true }
    );
    this.#registered = true;
  }

  async #resolveDispatchDomainId(tx: PgTransactionClient): Promise<string | undefined> {
    const domains = await this.#dispatchRepo.listDispatchDomains(tx);
    if (UUID_REGEX.test(this.#settings.dispatch_domain)) {
      const byId = domains.find(
        (d) => d.dispatchDomainId.toLowerCase() === this.#settings.dispatch_domain.toLowerCase()
      );
      if (byId !== undefined) {
        return byId.dispatchDomainId;
      }
    }
    const byName = domains.find((d) => d.name === this.#settings.dispatch_domain);
    return byName?.dispatchDomainId;
  }

  async #listDueVerificationIntents(
    tx: PgTransactionClient,
    limit: number
  ): Promise<readonly string[]> {
    const res = await tx.query<Record<string, unknown>>(
      `SELECT ivi.id
         FROM rq.endpoint_verification_intents ivi
        WHERE ivi.state IN ('approved', 'probing')
          AND ivi.expires_at > pg_catalog.clock_timestamp()
          AND ivi.attempt_count < 3
          AND NOT EXISTS (
            SELECT 1
              FROM rq.endpoint_verification_attempts eva
             WHERE eva.intent_id = ivi.id
               AND eva.state IN ('prepared', 'send_started')
               AND eva.claim_expires_at > pg_catalog.clock_timestamp()
          )
        ORDER BY ivi.created_at ASC
        LIMIT $1::integer`,
      [limit]
    );
    return res.rows.map((r) => String(r["id"]));
  }

  async runOnce(signal?: AbortSignal): Promise<SenderWorkerRunResult> {
    if (signal?.aborted) {
      throw new DOMException("Sender tick aborted", "AbortError");
    }

    const startedMs = this.#clock.monotonicNowMs();
    try {
      const controlEpoch = this.#controlEpoch ?? (await this.#resolveControlEpoch());
      await this.#ensureRegistered(controlEpoch);

      const { dispatchDomainId, dueVerificationIntents, allowVerification, allowSend } =
        await this.#pgAdapter.withTransaction(
          this.#databaseRole,
          async (tx) => {
            const auth = await readInstallationStatus(tx);
            const domainId = await this.#resolveDispatchDomainId(tx);
            const intents = auth.allowEndpointVerification
              ? await this.#listDueVerificationIntents(tx, 8)
              : [];
            return {
              dispatchDomainId: domainId,
              dueVerificationIntents: intents,
              allowVerification: auth.allowEndpointVerification,
              allowSend: auth.allowSend
            };
          },
          { readOnly: true, ...(signal !== undefined ? { signal } : {}) }
        );

      const verificationOutcomes: ExecuteEndpointVerificationAttemptOutput[] = [];
      if (allowVerification) {
        for (const rawIntentId of dueVerificationIntents) {
          if (signal?.aborted) {
            break;
          }
          const intentId = parseEndpointVerificationIntentId(rawIntentId, "intentId");
          const attemptId = parseEndpointVerificationAttemptId(
            this.#ids.nextUuid(),
            "verificationAttemptId"
          );
          this.#deliveryRepo.registerPendingVerificationAttempt(attemptId, intentId);
          try {
            const outcome = await this.#deliveryService.executeEndpointVerificationAttempt({
              attemptId,
              workerInstanceId: this.instanceId,
              controlEpoch,
              claimLeaseMs: this.#claimLeaseMs,
              ...(signal !== undefined ? { signal } : {})
            });
            verificationOutcomes.push(outcome);
            this.#verificationsAttemptedCount += 1;
            if (outcome.outcome === "verified") {
              this.#verificationsVerifiedCount += 1;
            }
          } catch (err) {
            if (
              err instanceof ConflictDomainError &&
              (err.code === "LOCK_CONTENTION" || err.code === "VERSION_CONFLICT")
            ) {
              continue;
            }
            throw err;
          }
        }
      }

      const deliveryOutcomes: ExecutePreparedAttemptOutput[] = [];
      let claimedDeliveriesCount = 0;

      if (allowSend && dispatchDomainId !== undefined) {
        const maximumCount = Math.max(
          1,
          Math.min(DISPATCH_CLAIM_MAX_BATCH, this.#settings.approved_slots)
        );
        const batch = await this.#dispatchService.claimDispatchBatch({
          requestId: this.#ids.nextUuid(),
          dispatchDomainId,
          workerInstanceId: this.instanceId,
          controlEpoch,
          maximumCount,
          claimLeaseMs: this.#claimLeaseMs
        });

        claimedDeliveriesCount = batch.assignments.length;
        this.#deliveriesClaimedCount += claimedDeliveriesCount;

        const executions = await Promise.all(
          batch.assignments.map(async (assignment) => {
            try {
              return await this.#deliveryService.executePreparedAttempt({
                attemptId: assignment.attemptId,
                workerInstanceId: this.instanceId,
                controlEpoch,
                expectedFencingToken: assignment.fencingToken,
                ...(signal !== undefined ? { signal } : {})
              });
            } catch (err) {
              if (err instanceof ConflictDomainError || err instanceof AuthorizationDomainError) {
                return undefined;
              }
              throw err;
            }
          })
        );

        for (const outcome of executions) {
          if (outcome === undefined) {
            continue;
          }
          deliveryOutcomes.push(outcome);
          if (outcome.disposition === "acknowledged") {
            this.#deliveriesAcknowledgedCount += 1;
          } else if (
            outcome.disposition === "retry_scheduled" ||
            outcome.disposition === "deferred_before_send"
          ) {
            this.#deliveriesRetryCount += 1;
          } else if (outcome.disposition === "dead_lettered") {
            this.#deliveriesDeadLetterCount += 1;
          } else if (outcome.disposition === "failed_before_send") {
            this.#deliveriesFailedBeforeSendCount += 1;
          }
        }
      }

      this.#ticksCompleted += 1;
      this.#lastTickAt = formatUtcTimestamp(this.#clock.nowInstant());
      this.#lastTickDurationMs = Math.max(0, this.#clock.monotonicNowMs() - startedMs);
      this.#lastError = undefined;

      return Object.freeze({
        controlEpoch,
        ...(dispatchDomainId !== undefined ? { dispatchDomainId } : {}),
        claimedDeliveriesCount,
        deliveryOutcomes: Object.freeze(deliveryOutcomes),
        verificationOutcomes: Object.freeze(verificationOutcomes)
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
      processRole: "sender",
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
      name: "sender-dispatch-and-deliver",
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

export function createSenderWorker(options: SenderWorkerOptions): SenderWorker {
  return new SenderWorker(options);
}

export async function runSenderTick(options: SenderWorkerOptions): Promise<SenderWorkerRunResult> {
  const worker = createSenderWorker(options);
  return worker.runOnce();
}
