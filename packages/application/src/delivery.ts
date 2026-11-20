import crypto from "node:crypto";
import { type Temporal } from "@js-temporal/polyfill";
import {
  ATTEMPT_NETWORK_BUDGET_MS,
  AuthorizationDomainError,
  ConflictDomainError,
  type CanonicalUtcTimestamp,
  type ControlEpoch,
  type DeliveryId,
  type DeliveryOutcomeClass,
  type DeliveryState,
  type EndpointId,
  type EndpointVerificationAttemptId,
  type KeyId,
  type LocalInvocationOwner,
  type LocalInvocationSnapshot,
  RETRY_V1_POLICY,
  type RetryAfterParseClass,
  type RetryDecisionOutcome,
  type RuntimeInstanceId,
  type Sha256Hex,
  ValidationDomainError,
  type AttemptId,
  type AttemptState,
  addMilliseconds,
  compareInstants,
  computeRetryDecision,
  enterLocalInvocation,
  finishLocalInvocation,
  formatInt64,
  formatUtcTimestamp,
  isTerminalDeliveryState,
  parseAttemptId,
  parseControlEpoch,
  parseEndpointVerificationAttemptId,
  parseNonNegativeInt64String,
  parsePositiveInt64String,
  parseReceiverReceiptObservationId,
  parseLateObservationId,
  parseRuntimeInstanceId,
  parseSha256Hex,
  parseUtcTimestamp,
  resolveLocalInvocationPermission
} from "@relayquill/domain";
import {
  type EndpointVerificationBodyV1,
  hashCanonicalJson,
  parseCanonicalUtcTimestamp
} from "@relayquill/contracts";
import {
  type EgressDecision,
  type EgressExecutionResult,
  assertAllowedEgressDecision
} from "@relayquill/egress";
import { type EgressConfig, type ProfileKind } from "@relayquill/runtime";
import {
  type SignedWebhookRequest,
  type WebhookKeyMaterialResolver,
  normalizeResolvedKeyMaterial,
  sha256HexNode
} from "@relayquill/signing";
import {
  type ClockPort,
  type DeliveryExecutionRepositoryPort,
  type DeliverySendContextRecord,
  type EgressExecutorPort,
  type EgressResolverPort,
  type IdGeneratorPort,
  type MicrotokenRateBucketRecord,
  type TelemetryPort,
  type UnitOfWorkPort,
  type VerificationAttemptContextRecord,
  type WebhookSignerPort,
  cryptoIdGeneratorPort,
  noopTelemetryPort,
  systemClockPort
} from "./ports.js";

const EMPTY_BODY_SHA256 = sha256HexNode(new Uint8Array(0));
const DEFAULT_NETWORK_POLICY_VERSION = "egress_v1" as const;

export type UniformBigIntDraw = (maxInclusive: bigint) => bigint;

function defaultMonotonicNowNs(): bigint {
  return process.hrtime.bigint();
}

function defaultDrawUniformBigIntInclusive(maxInclusive: bigint): bigint {
  if (maxInclusive <= 0n) {
    return 0n;
  }
  const span = maxInclusive + 1n;
  if (span <= 281_474_976_710_656n) {
    return BigInt(crypto.randomInt(0, Number(span)));
  }
  const bitLength = span.toString(2).length;
  const byteLength = Math.ceil(bitLength / 8);
  const mask = (1n << BigInt(bitLength)) - 1n;
  while (true) {
    const buf = crypto.randomBytes(byteLength);
    let candidate = 0n;
    for (const byte of buf) {
      candidate = (candidate << 8n) | BigInt(byte);
    }
    candidate &= mask;
    if (candidate < span) {
      return candidate;
    }
  }
}

export interface ParsedRetryAfterHeader {
  readonly parseClass: RetryAfterParseClass;
  readonly retryAfterMs: bigint | null;
}

export function parseRetryAfterHeaders(
  rawHeaders: ReadonlyArray<readonly [string, string]>,
  nowInstant: Temporal.Instant,
  maxCapMs: bigint = RETRY_V1_POLICY.retryAfterCapMs
): ParsedRetryAfterHeader {
  const values: string[] = [];
  for (const [name, value] of rawHeaders) {
    if (name.toLowerCase() === "retry-after") {
      const trimmed = value.trim();
      if (trimmed.length > 0) {
        values.push(trimmed);
      }
    }
  }

  if (values.length === 0) {
    return Object.freeze({ parseClass: "none", retryAfterMs: null });
  }
  if (values.length > 1) {
    return Object.freeze({ parseClass: "conflicting", retryAfterMs: null });
  }

  const rawValue = values[0] ?? "";
  if (rawValue.length > 128) {
    return Object.freeze({ parseClass: "oversized", retryAfterMs: null });
  }

  if (/^[0-9]+$/.test(rawValue)) {
    const seconds = BigInt(rawValue);
    if (seconds > maxCapMs / 1_000n) {
      return Object.freeze({ parseClass: "oversized", retryAfterMs: maxCapMs });
    }
    return Object.freeze({
      parseClass: "delay_seconds",
      retryAfterMs: seconds * 1_000n
    });
  }

  const parsedMs = Date.parse(rawValue);
  if (!Number.isFinite(parsedMs)) {
    return Object.freeze({ parseClass: "invalid", retryAfterMs: null });
  }

  const deltaMs = BigInt(Math.trunc(parsedMs - nowInstant.epochMilliseconds));
  if (deltaMs <= 0n) {
    return Object.freeze({ parseClass: "past_date", retryAfterMs: 0n });
  }
  if (deltaMs > maxCapMs) {
    return Object.freeze({ parseClass: "oversized", retryAfterMs: maxCapMs });
  }
  return Object.freeze({ parseClass: "http_date", retryAfterMs: deltaMs });
}

export interface DeliveryExecutionServiceDeps<TTx> {
  readonly uow: UnitOfWorkPort<TTx>;
  readonly deliveryRepo: DeliveryExecutionRepositoryPort<TTx>;
  readonly egressResolver: EgressResolverPort;
  readonly egressExecutor: EgressExecutorPort;
  readonly webhookSigner: WebhookSignerPort;
  readonly getKeyMaterial: WebhookKeyMaterialResolver;
  readonly profile?: ProfileKind | undefined;
  readonly egressConfig?: EgressConfig | undefined;
  readonly networkPolicyVersion?: string | undefined;
  readonly ca?: string | Buffer | readonly (string | Buffer)[] | undefined;
  readonly monotonicNowNs?: (() => bigint) | undefined;
  readonly drawUniformBigIntInclusive?: UniformBigIntDraw | undefined;
  readonly clock?: ClockPort | undefined;
  readonly idGenerator?: IdGeneratorPort | undefined;
  readonly telemetry?: TelemetryPort | undefined;
}

export interface ExecutePreparedAttemptInput {
  readonly attemptId: AttemptId | string;
  readonly workerInstanceId: RuntimeInstanceId | string;
  readonly controlEpoch: ControlEpoch | string;
  readonly expectedFencingToken: bigint;
  readonly spendBuckets?: readonly MicrotokenRateBucketRecord[] | undefined;
  readonly signal?: AbortSignal | undefined;
}

export interface ExecutePreparedAttemptOutput {
  readonly deliveryId: DeliveryId;
  readonly attemptId: AttemptId;
  readonly disposition:
    | "acknowledged"
    | "retry_scheduled"
    | "dead_lettered"
    | "expired"
    | "deferred_before_send"
    | "failed_before_send"
    | "already_started"
    | "aborted_pre_send";
  readonly attemptState: AttemptState;
  readonly deliveryState: DeliveryState;
  readonly outcomeClass?: DeliveryOutcomeClass | undefined;
  readonly responseStatus?: number | null | undefined;
  readonly retryDecision?: RetryDecisionOutcome | null | undefined;
  readonly receiptState?: "verified" | "rejected" | "not_applicable" | undefined;
  readonly nextEligibleAt?: CanonicalUtcTimestamp | null | undefined;
}

export interface ExecuteEndpointVerificationAttemptInput {
  readonly attemptId: EndpointVerificationAttemptId | string;
  readonly workerInstanceId: RuntimeInstanceId | string;
  readonly controlEpoch: ControlEpoch | string;
  readonly claimLeaseMs?: bigint | undefined;
  readonly signal?: AbortSignal | undefined;
}

export interface ExecuteEndpointVerificationAttemptOutput {
  readonly attemptId: EndpointVerificationAttemptId;
  readonly endpointId: EndpointId;
  readonly outcome: "verified" | "failed_transient" | "failed_permanent" | "already_claimed";
  readonly responseStatus?: number | null | undefined;
  readonly proofSha256?: Sha256Hex | null | undefined;
  readonly safeReasonCode?: string | null | undefined;
}

export class DeliveryExecutionService<TTx> {
  readonly #uow: UnitOfWorkPort<TTx>;
  readonly #deliveryRepo: DeliveryExecutionRepositoryPort<TTx>;
  readonly #egressResolver: EgressResolverPort;
  readonly #egressExecutor: EgressExecutorPort;
  readonly #webhookSigner: WebhookSignerPort;
  readonly #getKeyMaterial: WebhookKeyMaterialResolver;
  readonly #profile: ProfileKind | undefined;
  readonly #egressConfig: EgressConfig | undefined;
  readonly #networkPolicyVersion: string;
  readonly #ca: string | Buffer | readonly (string | Buffer)[] | undefined;
  readonly #monotonicNowNs: () => bigint;
  readonly #drawUniformBigIntInclusive: UniformBigIntDraw;
  readonly #clock: ClockPort;
  readonly #ids: IdGeneratorPort;
  readonly #telemetry: TelemetryPort;

  constructor(deps: DeliveryExecutionServiceDeps<TTx>) {
    this.#uow = deps.uow;
    this.#deliveryRepo = deps.deliveryRepo;
    this.#egressResolver = deps.egressResolver;
    this.#egressExecutor = deps.egressExecutor;
    this.#webhookSigner = deps.webhookSigner;
    this.#getKeyMaterial = deps.getKeyMaterial;
    this.#profile = deps.profile;
    this.#egressConfig = deps.egressConfig;
    this.#networkPolicyVersion = deps.networkPolicyVersion ?? DEFAULT_NETWORK_POLICY_VERSION;
    this.#ca = deps.ca;
    this.#monotonicNowNs = deps.monotonicNowNs ?? defaultMonotonicNowNs;
    this.#drawUniformBigIntInclusive =
      deps.drawUniformBigIntInclusive ?? defaultDrawUniformBigIntInclusive;
    this.#clock = deps.clock ?? systemClockPort;
    this.#ids = deps.idGenerator ?? cryptoIdGeneratorPort;
    this.#telemetry = deps.telemetry ?? noopTelemetryPort;
  }

  /**
   * Executes a prepared delivery attempt with sender preflight rechecks, pinned egress,
   * strict monotonic request deadlines, delivery signing, bounded retry decisions,
   * and independent receiver local commit receipt MAC verification.
   */
  async executePreparedAttempt(
    input: ExecutePreparedAttemptInput
  ): Promise<ExecutePreparedAttemptOutput> {
    const span = this.#telemetry.startSpan("relayquill.delivery.execute_prepared_attempt");
    try {
      const attemptId = parseAttemptId(input.attemptId, "attemptId");
      const workerInstanceId = parseRuntimeInstanceId(input.workerInstanceId, "workerInstanceId");
      const controlEpoch = parseControlEpoch(input.controlEpoch, "controlEpoch");
      const buckets = input.spendBuckets ?? [];

      const context = await this.#uow.inTransaction((tx) =>
        this.#deliveryRepo.loadAttemptSendContext(tx, attemptId)
      );

      this.#assertAttemptPreflightContext(context, input.expectedFencingToken);

      const resolveNow = parseCanonicalUtcTimestamp(
        formatUtcTimestamp(this.#clock.nowInstant()),
        "now"
      );

      // Step 1: Resolve & record egress preflight decision before marking send_started.
      const decision = await this.#resolveAndRecordEgress(
        context.destinationUrl,
        {
          tenantId: context.tenantId,
          projectId: context.projectId,
          endpointId: context.endpointId,
          endpointVersion: context.endpointVersion,
          deliveryAttemptId: context.attemptId,
          workerInstanceId,
          controlEpoch
        },
        resolveNow
      );

      if (decision.decision !== "allowed") {
        const result = await this.#handlePreflightEgressBlock(
          context,
          decision,
          workerInstanceId,
          controlEpoch,
          buckets
        );
        span.end({ code: "OK" });
        return result;
      }

      // Step 2: Capture pre-RPC monotonic clock, request send permission, capture post-RPC clock.
      const m0Ns = this.#monotonicNowNs();
      const startNow = parseCanonicalUtcTimestamp(
        formatUtcTimestamp(this.#clock.nowInstant()),
        "startNow"
      );
      const owner: LocalInvocationOwner = {
        workerInstanceId,
        attemptId: context.attemptId,
        fencingToken: input.expectedFencingToken,
        controlEpoch
      };
      const initialSnapshot: LocalInvocationSnapshot = {
        owner,
        state: "permission_pending",
        m0Ns,
        m1Ns: null,
        localCutoffNs: null
      };

      const startResult = await this.#uow.inTransaction((tx) =>
        this.#deliveryRepo.startDeliverySend(tx, {
          attemptId: context.attemptId,
          workerInstanceId,
          controlEpoch,
          expectedFencingToken: input.expectedFencingToken,
          networkBudgetMs: ATTEMPT_NETWORK_BUDGET_MS,
          now: startNow,
          spendBuckets: buckets
        })
      );

      const m1Ns = this.#monotonicNowNs();

      if (startResult.alreadyStarted) {
        span.end({ code: "OK" });
        return Object.freeze({
          deliveryId: context.deliveryId,
          attemptId: context.attemptId,
          disposition: "already_started",
          attemptState: "send_started",
          deliveryState: context.deliveryState
        });
      }

      if (!startResult.shouldSend) {
        const deferredAt = parseCanonicalUtcTimestamp(
          formatUtcTimestamp(this.#clock.nowInstant()),
          "deferredAt"
        );
        await this.#uow.inTransaction((tx) =>
          this.#deliveryRepo.deferUnstartedAttempt(tx, {
            attemptId: context.attemptId,
            workerInstanceId,
            controlEpoch,
            expectedFencingToken: input.expectedFencingToken,
            reasonCode: startResult.abortReason ?? "SEND_PERMISSION_DECLINED",
            releaseBuckets: buckets,
            now: deferredAt
          })
        );
        span.end({ code: "OK" });
        return Object.freeze({
          deliveryId: context.deliveryId,
          attemptId: context.attemptId,
          disposition: "aborted_pre_send",
          attemptState: "deferred_before_send",
          deliveryState: context.deliveryState
        });
      }

      // Step 3: Resolve monotonic deadline budget strictly before touching network.
      const permittedSnapshot = resolveLocalInvocationPermission(initialSnapshot, {
        owner,
        m0Ns,
        m1Ns,
        requestDeadlineAt: parseUtcTimestamp(startResult.requestDeadlineAt, "requestDeadlineAt")
          .instant,
        acceptanceDbClock: parseUtcTimestamp(startResult.acceptedAt, "acceptedAt").instant
      });

      const beforeInvokeNs = this.#monotonicNowNs();
      const invokingSnapshot =
        permittedSnapshot.state === "permission_accepted"
          ? enterLocalInvocation(permittedSnapshot, owner, beforeInvokeNs, true)
          : permittedSnapshot;

      if (invokingSnapshot.state !== "invoking" || invokingSnapshot.localCutoffNs === null) {
        const abortNowInstant = this.#clock.nowInstant();
        const abortNow = parseCanonicalUtcTimestamp(formatUtcTimestamp(abortNowInstant), "abortNow");
        const deadlineInstant = parseUtcTimestamp(context.deliveryDeadlineAt, "deadline").instant;
        const expired = compareInstants(abortNowInstant, deadlineInstant) >= 0;
        const retryDecision: RetryDecisionOutcome = expired ? "expired" : "retry_wait";

        const finalized = await this.#uow.inTransaction((tx) =>
          this.#deliveryRepo.finalizeDeliveryAttempt(tx, {
            attemptId: context.attemptId,
            workerInstanceId,
            controlEpoch,
            expectedFencingToken: input.expectedFencingToken,
            attemptState: "abandoned",
            outcomeClass: "transport_unknown",
            safeErrorCode:
              permittedSnapshot.state === "unusable"
                ? "MONOTONIC_CLOCK_DISCONTINUITY"
                : "LOCAL_DEADLINE_BUDGET_EXHAUSTED",
            retryDecision,
            retryReasonCode:
              permittedSnapshot.state === "unusable"
                ? "MONOTONIC_CLOCK_DISCONTINUITY"
                : "LOCAL_DEADLINE_BUDGET_EXHAUSTED",
            nextEligibleAt: expired ? null : abortNow,
            now: abortNow
          })
        );
        span.end({ code: "OK" });
        return Object.freeze({
          deliveryId: context.deliveryId,
          attemptId: context.attemptId,
          disposition: expired ? "expired" : "retry_scheduled",
          attemptState: finalized.attemptState,
          deliveryState: finalized.deliveryState,
          outcomeClass: "transport_unknown",
          retryDecision,
          nextEligibleAt: expired ? null : abortNow
        });
      }

      // Step 4: Sign webhook delivery headers right before pinned egress call.
      const signNow = this.#clock.nowInstant();
      const signed = await this.#webhookSigner.signDelivery({
        method: "POST",
        externalAuthority: decision.target.externalAuthority,
        requestTarget: decision.target.requestTarget,
        projectId: context.projectId,
        eventId: context.eventId,
        subscriptionId: context.subscriptionId,
        endpointId: context.endpointId,
        endpointVersion: parsePositiveInt64String(
          formatInt64(context.endpointVersion, "endpointVersion"),
          "endpointVersion"
        ),
        deliveryId: context.deliveryId,
        deliveryGeneration: parsePositiveInt64String(
          formatInt64(context.deliveryGeneration, "deliveryGeneration"),
          "deliveryGeneration"
        ),
        attemptId: context.attemptId,
        signingPolicyVersion: context.signingPolicyVersion,
        consumerEventKey: context.consumerEventKeySha256,
        rawWireBodyBytes: context.wireBodyBytes,
        expectedBodySha256: context.wireBodySha256,
        signingKeys: context.signingKeys,
        now: signNow,
        ...(context.ordering !== undefined ? { ordering: context.ordering } : {}),
        ...(context.traceparent !== undefined ? { traceparent: context.traceparent } : {}),
        ...(context.tracestate !== undefined ? { tracestate: context.tracestate } : {}),
        getKeyMaterial: this.#getKeyMaterial
      });

      // Step 5: Assert one-shot egress decision freshness and enforce monotonic network cap.
      const remainingBudgetNs = invokingSnapshot.localCutoffNs - beforeInvokeNs;
      const remainingBudgetMs = Math.max(1, Number(remainingBudgetNs / 1_000_000n));
      assertAllowedEgressDecision(decision, this.#clock.nowInstant().epochMilliseconds);

      let execResult: EgressExecutionResult;
      try {
        execResult = await this.#egressExecutor.execute({
          decision,
          method: "POST",
          headers: signed.headers,
          bodyBytes: context.wireBodyBytes,
          ...(this.#profile !== undefined ? { profile: this.#profile } : {}),
          ...(this.#egressConfig !== undefined ? { egressConfig: this.#egressConfig } : {}),
          ...(this.#ca !== undefined ? { ca: this.#ca } : {}),
          timeouts: {
            totalNetworkMs: remainingBudgetMs
          },
          ...(input.signal !== undefined ? { signal: input.signal } : {}),
          monotonicNowMs: () => Number(this.#monotonicNowNs() / 1_000_000n)
        });
        finishLocalInvocation(invokingSnapshot, "finished");
      } catch (err) {
        finishLocalInvocation(invokingSnapshot, "aborted");
        throw err;
      }

      // Step 6: Independently evaluate HTTP acknowledgment & receiver local commit receipt MAC.
      const decidedAtInstant = this.#clock.nowInstant();
      const decidedAt = parseCanonicalUtcTimestamp(formatUtcTimestamp(decidedAtInstant), "decidedAt");

      const receiptState = await this.#verifyAndRecordReceiptIfApplicable(
        context,
        signed,
        execResult,
        workerInstanceId,
        decidedAtInstant,
        decidedAt
      );

      // Step 7: Compute bounded retry decision and commit atomic attempt + circuit finalization.
      const retryAfter = execResult.response
        ? parseRetryAfterHeaders(execResult.response.rawHeaders, decidedAtInstant)
        : { parseClass: "none" as const, retryAfterMs: null };

      const retryEval = computeRetryDecision({
        outcomeClass: execResult.outcomeClass,
        attemptCount: context.attemptNumber,
        maximumAttempts: context.maximumAttempts,
        decidedAt: decidedAtInstant,
        deadlineAt: parseUtcTimestamp(context.deliveryDeadlineAt, "deliveryDeadlineAt").instant,
        retryAfterMs: retryAfter.retryAfterMs,
        retryAfterParseClass: retryAfter.parseClass,
        drawUniformBigIntInclusive: this.#drawUniformBigIntInclusive
      });

      const nextEligibleCanonical =
        retryEval.nextEligibleAt !== null
          ? parseCanonicalUtcTimestamp(formatUtcTimestamp(retryEval.nextEligibleAt), "nextEligibleAt")
          : null;

      const attemptState: AttemptState =
        execResult.response !== undefined
          ? "response_observed"
          : execResult.sendStarted
            ? "transport_unknown"
            : "failed_before_send";

      const commitOut = await this.#uow.inTransaction(async (tx) => {
        const finalized = await this.#deliveryRepo.finalizeDeliveryAttempt(tx, {
          attemptId: context.attemptId,
          workerInstanceId,
          controlEpoch,
          expectedFencingToken: input.expectedFencingToken,
          attemptState,
          outcomeClass: execResult.outcomeClass,
          responseStatus: execResult.response?.status ?? null,
          responseBodySha256: execResult.response?.bodySha256 ?? null,
          responseByteCount: execResult.response?.bodyByteCount ?? null,
          safeErrorCode: execResult.safeErrorCode,
          retryDecision: retryEval.decision,
          retryReasonCode: retryEval.reasonCode,
          retryPolicyVersion: retryEval.policyVersion,
          selectedDelayMs: retryEval.selectedDelayMs,
          selectedBackoffMs: retryEval.backoffCeilingMs,
          retryAfterParseClass: retryAfter.parseClass,
          retryAfterMs: retryEval.cappedRetryAfterMs,
          nextEligibleAt: nextEligibleCanonical,
          now: decidedAt
        });

        if (finalized.outcome === "already_finalized") {
          const safeFacts: Record<string, unknown> = {
            attempt_state: attemptState,
            outcome_class: execResult.outcomeClass,
            response_status: execResult.response?.status ?? null,
            safe_error_code: execResult.safeErrorCode
          };
          const factsSha256 = hashCanonicalJson(
            {
              attempt_id: context.attemptId,
              outcome_class: execResult.outcomeClass,
              response_status: execResult.response?.status ?? null
            },
            "late_observation"
          ).sha256;
          const observationKeySha256 = hashCanonicalJson(
            {
              delivery_id: context.deliveryId,
              attempt_id: context.attemptId,
              observed_at: decidedAt,
              outcome_class: execResult.outcomeClass
            },
            "late_observation_key"
          ).sha256;
          await this.#deliveryRepo.observeLateDelivery(tx, {
            observationId: parseLateObservationId(this.#ids.nextUuid(), "lateObservationId"),
            deliveryId: context.deliveryId,
            attemptId: context.attemptId,
            sourceInstanceId: workerInstanceId,
            observationKeySha256,
            factsSha256,
            observationKind: "late_http_response",
            safeFacts,
            now: decidedAt
          });
        }

        await this.#deliveryRepo.updateEndpointCircuit(tx, {
          endpointId: context.endpointId,
          observedGeneration: context.circuitGenerationAtPrepare,
          isCircuitProbe: context.isCircuitProbe,
          attemptId: context.attemptId,
          outcomeClass: execResult.outcomeClass,
          now: decidedAt
        });

        return finalized;
      });

      const disposition =
        retryEval.decision === "acknowledged"
          ? "acknowledged"
          : retryEval.decision === "retry_wait"
            ? "retry_scheduled"
            : retryEval.decision === "expired"
              ? "expired"
              : "dead_lettered";

      span.end({ code: "OK" });
      return Object.freeze({
        deliveryId: context.deliveryId,
        attemptId: context.attemptId,
        disposition,
        attemptState: commitOut.attemptState,
        deliveryState: commitOut.deliveryState,
        outcomeClass: execResult.outcomeClass,
        responseStatus: execResult.response?.status ?? null,
        retryDecision: retryEval.decision,
        receiptState,
        nextEligibleAt: nextEligibleCanonical
      });
    } catch (err) {
      span.end({ code: "ERROR", message: err instanceof Error ? err.message : "delivery_failed" });
      throw err;
    }
  }

  /**
   * Executes a single active endpoint verification probe and checks the `204`
   * `rq.endpoint-proof.v1\0` proof header against the endpoint's custody key.
   */
  async executeEndpointVerificationAttempt(
    input: ExecuteEndpointVerificationAttemptInput
  ): Promise<ExecuteEndpointVerificationAttemptOutput> {
    const span = this.#telemetry.startSpan("relayquill.delivery.execute_endpoint_verification");
    try {
      const attemptId = parseEndpointVerificationAttemptId(input.attemptId, "attemptId");
      const workerInstanceId = parseRuntimeInstanceId(input.workerInstanceId, "workerInstanceId");
      const controlEpoch = parseControlEpoch(input.controlEpoch, "controlEpoch");
      const claimLeaseMs = input.claimLeaseMs ?? ATTEMPT_NETWORK_BUDGET_MS;

      const context = await this.#uow.inTransaction((tx) =>
        this.#deliveryRepo.loadVerificationAttemptContext(tx, attemptId)
      );

      const claimNow = parseCanonicalUtcTimestamp(
        formatUtcTimestamp(this.#clock.nowInstant()),
        "claimNow"
      );
      const claimed = await this.#uow.inTransaction((tx) =>
        this.#deliveryRepo.claimVerificationAttempt(tx, {
          intentId: context.verificationIntentId,
          attemptId: context.attemptId,
          instanceId: workerInstanceId,
          controlEpoch,
          claimLeaseMs,
          now: claimNow
        })
      );

      if (!claimed.claimed) {
        span.end({ code: "OK" });
        return Object.freeze({
          attemptId: context.attemptId,
          endpointId: context.endpointId,
          outcome: "already_claimed"
        });
      }

      const decision = await this.#resolveAndRecordEgress(
        context.destinationUrl,
        {
          tenantId: context.tenantId,
          projectId: context.projectId,
          endpointId: context.endpointId,
          endpointVersion: context.endpointVersion,
          verificationAttemptId: context.attemptId,
          workerInstanceId,
          controlEpoch
        },
        claimNow
      );

      if (decision.decision !== "allowed") {
        const outcome = decision.decision === "denied" ? "failed_permanent" : "failed_transient";
        await this.#finalizeVerification(context, workerInstanceId, controlEpoch, {
          outcome,
          responseStatus: null,
          proofSha256: null,
          safeReasonCode: decision.reasonCode
        });
        span.end({ code: "OK" });
        return Object.freeze({
          attemptId: context.attemptId,
          endpointId: context.endpointId,
          outcome,
          safeReasonCode: decision.reasonCode
        });
      }

      const endpointVersionStr = parsePositiveInt64String(
        formatInt64(context.endpointVersion, "endpointVersion"),
        "endpointVersion"
      );
      const signNow = this.#clock.nowInstant();
      const verificationBody: EndpointVerificationBodyV1 = {
        envelope_version: 1,
        verification_id: context.verificationIntentId,
        endpoint_id: context.endpointId,
        endpoint_version: endpointVersionStr,
        key_id: context.keyId,
        purpose: "verify_destination_and_key",
        public_nonce: context.publicNonce as EndpointVerificationBodyV1["public_nonce"],
        configuration_sha256: context.configurationSha256
      };

      const signed = await this.#webhookSigner.signEndpointVerification({
        method: "POST",
        externalAuthority: decision.target.externalAuthority,
        requestTarget: decision.target.requestTarget,
        projectId: context.projectId,
        endpointId: context.endpointId,
        endpointVersion: endpointVersionStr,
        attemptId: context.attemptId,
        verificationId: context.verificationIntentId,
        body: verificationBody,
        signingKey: context.keyMetadata,
        now: signNow,
        getKeyMaterial: this.#getKeyMaterial
      });

      assertAllowedEgressDecision(decision, this.#clock.nowInstant().epochMilliseconds);
      const execResult = await this.#egressExecutor.execute({
        decision,
        method: "POST",
        headers: signed.headers,
        bodyBytes: signed.bodyBytes,
        ...(this.#profile !== undefined ? { profile: this.#profile } : {}),
        ...(this.#egressConfig !== undefined ? { egressConfig: this.#egressConfig } : {}),
        ...(this.#ca !== undefined ? { ca: this.#ca } : {}),
        ...(input.signal !== undefined ? { signal: input.signal } : {}),
        monotonicNowMs: () => Number(this.#monotonicNowNs() / 1_000_000n)
      });

      if (execResult.response === undefined) {
        const outcome =
          execResult.outcomeClass === "permanent_policy_or_security" ||
          execResult.outcomeClass === "permanent_redirect" ||
          execResult.outcomeClass === "permanent_http"
            ? "failed_permanent"
            : "failed_transient";
        await this.#finalizeVerification(context, workerInstanceId, controlEpoch, {
          outcome,
          responseStatus: null,
          proofSha256: null,
          safeReasonCode: execResult.safeErrorCode ?? "VERIFICATION_TRANSPORT_ERROR"
        });
        span.end({ code: "OK" });
        return Object.freeze({
          attemptId: context.attemptId,
          endpointId: context.endpointId,
          outcome,
          safeReasonCode: execResult.safeErrorCode ?? "VERIFICATION_TRANSPORT_ERROR"
        });
      }

      const rawKey = await this.#getKeyMaterial({
        projectId: context.projectId,
        endpointId: context.endpointId,
        keyId: context.keyId,
        purpose: "endpoint_verification"
      });
      if (rawKey === null) {
        await this.#finalizeVerification(context, workerInstanceId, controlEpoch, {
          outcome: "failed_permanent",
          responseStatus: execResult.response.status,
          proofSha256: null,
          safeReasonCode: "KEY_MATERIAL_UNAVAILABLE"
        });
        span.end({ code: "OK" });
        return Object.freeze({
          attemptId: context.attemptId,
          endpointId: context.endpointId,
          outcome: "failed_permanent",
          responseStatus: execResult.response.status,
          safeReasonCode: "KEY_MATERIAL_UNAVAILABLE"
        });
      }

      const resolvedKey = normalizeResolvedKeyMaterial(rawKey);
      let proofVerification;
      try {
        proofVerification = this.#webhookSigner.verifyEndpointProof({
          statusCode: execResult.response.status,
          rawHeaders: execResult.response.rawHeaders,
          rawBodyBytes: execResult.response.bodyBytes,
          expected: {
            verificationIntentId: context.verificationIntentId,
            endpointId: context.endpointId,
            endpointVersion: endpointVersionStr,
            configurationSha256: context.configurationSha256,
            keyId: context.keyId,
            publicNonce: context.publicNonce,
            verificationAttemptId: context.attemptId,
            requestTimestampSeconds: parseNonNegativeInt64String(
              signed.timestampSeconds,
              "timestampSeconds"
            ),
            requestWireBodySha256: signed.bodySha256,
            intentExpiresAt: parseUtcTimestamp(context.intentExpiresAt, "intentExpiresAt").instant
          },
          keyHandle: resolvedKey.handle,
          keyMetadata: resolvedKey.metadata ?? context.keyMetadata,
          now: this.#clock.nowInstant()
        });
      } finally {
        if (resolvedKey.releaseAfterUse === true) {
          resolvedKey.handle.destroy?.();
        }
      }

      const outcome = proofVerification.ok
        ? "verified"
        : execResult.response.status >= 500 || execResult.response.status === 429
          ? "failed_transient"
          : "failed_permanent";

      await this.#finalizeVerification(context, workerInstanceId, controlEpoch, {
        outcome,
        responseStatus: execResult.response.status,
        proofSha256: proofVerification.ok ? proofVerification.proofSha256 : null,
        safeReasonCode: proofVerification.ok ? null : proofVerification.safeReason
      });

      span.end({ code: "OK" });
      return Object.freeze({
        attemptId: context.attemptId,
        endpointId: context.endpointId,
        outcome,
        responseStatus: execResult.response.status,
        proofSha256: proofVerification.ok ? proofVerification.proofSha256 : null,
        safeReasonCode: proofVerification.ok ? null : proofVerification.safeReason
      });
    } catch (err) {
      span.end({
        code: "ERROR",
        message: err instanceof Error ? err.message : "verification_failed"
      });
      throw err;
    }
  }

  #assertAttemptPreflightContext(
    context: DeliverySendContextRecord,
    expectedFencingToken: bigint
  ): void {
    if (context.attemptState !== "prepared") {
      throw new ConflictDomainError({
        code: "STATE_TRANSITION_NOT_ALLOWED",
        message: `Attempt "${context.attemptId}" cannot start from state "${context.attemptState}"`
      });
    }
    if (context.fencingToken !== expectedFencingToken) {
      throw new ConflictDomainError({
        code: "VERSION_CONFLICT",
        message: `Attempt "${context.attemptId}" fencing token mismatch`
      });
    }
    if (isTerminalDeliveryState(context.deliveryState)) {
      throw new ConflictDomainError({
        code: "STATE_TRANSITION_NOT_ALLOWED",
        message: `Delivery "${context.deliveryId}" is already terminal ("${context.deliveryState}")`
      });
    }
    if (context.endpointState !== "active") {
      throw new AuthorizationDomainError({
        code: "FORBIDDEN",
        message: `Endpoint "${context.endpointId}" is "${context.endpointState}", refusing send`
      });
    }
    if (context.signingKeys.length === 0) {
      throw new ValidationDomainError({
        code: "SECRET_CUSTODY_ERROR",
        message: `Endpoint "${context.endpointId}" has no active signing keys`
      });
    }
  }

  async #resolveAndRecordEgress(
    destinationUrl: string,
    ref: {
      readonly tenantId: DeliverySendContextRecord["tenantId"];
      readonly projectId: DeliverySendContextRecord["projectId"];
      readonly endpointId: DeliverySendContextRecord["endpointId"];
      readonly endpointVersion: bigint;
      readonly deliveryAttemptId?: AttemptId | undefined;
      readonly verificationAttemptId?: EndpointVerificationAttemptId | undefined;
      readonly workerInstanceId: RuntimeInstanceId;
      readonly controlEpoch: ControlEpoch;
    },
    now: CanonicalUtcTimestamp
  ): Promise<EgressDecision> {
    const decision = await this.#egressResolver.resolve(destinationUrl, {
      target: destinationUrl,
      ...(this.#profile !== undefined || this.#egressConfig !== undefined
        ? {
            urlPolicyOptions: {
              ...(this.#profile !== undefined ? { profile: this.#profile } : {}),
              ...(this.#egressConfig !== undefined ? { egressConfig: this.#egressConfig } : {})
            }
          }
        : {})
    });

    await this.#uow.inTransaction((tx) =>
      this.#deliveryRepo.recordEgressDecision(tx, {
        decisionId: decision.decisionId,
        tenantId: ref.tenantId,
        projectId: ref.projectId,
        endpointId: ref.endpointId,
        endpointVersion: ref.endpointVersion,
        deliveryAttemptId: ref.deliveryAttemptId ?? null,
        verificationAttemptId: ref.verificationAttemptId ?? null,
        runtimeInstanceId: ref.workerInstanceId,
        controlEpoch: ref.controlEpoch,
        networkPolicyVersion: decision.networkPolicyVersion || this.#networkPolicyVersion,
        registryIpv4Sha256: decision.registryIpv4Sha256,
        registryIpv6Sha256: decision.registryIpv6Sha256,
        authoritySha256: decision.authoritySha256,
        answerSetSha256: decision.answerSetSha256,
        selectedAddressSha256: decision.selectedAddressSha256,
        selectedFamily: decision.selectedFamily,
        peerAddressSha256: null,
        decision: decision.decision === "allowed" ? "allow" : "deny",
        reasonCode: decision.reasonCode,
        expiresAt: decision.expiresAt,
        now
      })
    );

    return decision;
  }

  async #handlePreflightEgressBlock(
    context: DeliverySendContextRecord,
    decision: EgressDecision,
    workerInstanceId: RuntimeInstanceId,
    controlEpoch: ControlEpoch,
    buckets: readonly MicrotokenRateBucketRecord[]
  ): Promise<ExecutePreparedAttemptOutput> {
    const nowInstant = this.#clock.nowInstant();
    const now = parseCanonicalUtcTimestamp(formatUtcTimestamp(nowInstant), "now");

    if (decision.decision === "unavailable" || decision.decision === "expired") {
      const nextEligible = parseCanonicalUtcTimestamp(
        formatUtcTimestamp(addMilliseconds(nowInstant, 5_000n, "next_eligible_at")),
        "nextEligible"
      );
      await this.#uow.inTransaction((tx) =>
        this.#deliveryRepo.deferUnstartedAttempt(tx, {
          attemptId: context.attemptId,
          workerInstanceId,
          controlEpoch,
          expectedFencingToken: context.fencingToken,
          reasonCode: decision.reasonCode,
          nextEligibleAt: nextEligible,
          releaseBuckets: buckets,
          now
        })
      );
      return Object.freeze({
        deliveryId: context.deliveryId,
        attemptId: context.attemptId,
        disposition: "deferred_before_send",
        attemptState: "deferred_before_send",
        deliveryState: context.deliveryState,
        nextEligibleAt: nextEligible
      });
    }

    const finalized = await this.#uow.inTransaction(async (tx) => {
      const out = await this.#deliveryRepo.finalizeDeliveryAttempt(tx, {
        attemptId: context.attemptId,
        workerInstanceId,
        controlEpoch,
        expectedFencingToken: context.fencingToken,
        attemptState: "failed_before_send",
        outcomeClass: "permanent_policy_or_security",
        safeErrorCode: decision.reasonCode,
        retryDecision: "dead_letter",
        retryReasonCode: decision.reasonCode,
        retryPolicyVersion: context.retryPolicyVersion,
        now
      });
      await this.#deliveryRepo.updateEndpointCircuit(tx, {
        endpointId: context.endpointId,
        observedGeneration: context.circuitGenerationAtPrepare,
        isCircuitProbe: context.isCircuitProbe,
        attemptId: context.attemptId,
        outcomeClass: "permanent_policy_or_security",
        now
      });
      return out;
    });

    return Object.freeze({
      deliveryId: context.deliveryId,
      attemptId: context.attemptId,
      disposition: "failed_before_send",
      attemptState: finalized.attemptState,
      deliveryState: finalized.deliveryState,
      outcomeClass: "permanent_policy_or_security",
      retryDecision: "dead_letter"
    });
  }

  async #verifyAndRecordReceiptIfApplicable(
    context: DeliverySendContextRecord,
    signed: SignedWebhookRequest,
    execResult: EgressExecutionResult,
    workerInstanceId: RuntimeInstanceId,
    nowInstant: Temporal.Instant,
    now: CanonicalUtcTimestamp
  ): Promise<"verified" | "rejected" | "not_applicable"> {
    const res = execResult.response;
    if (res === undefined || !res.httpAcknowledged) {
      return "not_applicable";
    }
    if (!res.receiptEligible && !context.receiptRequired) {
      return "not_applicable";
    }

    const allowedKeyIds = new Set<KeyId>(signed.signedKeyIds);
    const keyMap = new Map(context.signingKeys.map((meta) => [meta.keyId, meta]));

    const verifyResult = await this.#webhookSigner.verifyReceiverReceipt({
      statusCode: res.status,
      rawHeaders: res.rawHeaders,
      rawBodyBytes: res.bodyBytes,
      bodyOversizedOrIncomplete: res.bodyDisposition !== "complete",
      receiptProfile: "receiver_local_commit_v1",
      expected: {
        projectId: context.projectId,
        eventId: context.eventId,
        consumerEventKey: context.consumerEventKeySha256,
        originalFactsSha256: context.originalFactsSha256,
        deliveryAttemptId: context.attemptId,
        requestWireBodySha256: context.wireBodySha256,
        allowedKeyIds
      },
      resolveVerificationKey: async (keyId) => {
        const resolved = await this.#getKeyMaterial({
          projectId: context.projectId,
          endpointId: context.endpointId,
          keyId,
          purpose: "delivery"
        });
        if (resolved === null) {
          return null;
        }
        const normalized = normalizeResolvedKeyMaterial(resolved);
        return {
          handle: normalized.handle,
          metadata: normalized.metadata ?? keyMap.get(keyId),
          releaseAfterUse: normalized.releaseAfterUse
        };
      },
      now: nowInstant
    });

    const fallbackKeyId = context.signingKeys[0]?.keyId ?? signed.signedKeyIds[0];
    if (fallbackKeyId === undefined) {
      return "not_applicable";
    }

    const observationId = parseReceiverReceiptObservationId(
      this.#ids.nextUuid(),
      "observationId"
    );

    if (verifyResult.ok) {
      const recorded = await this.#uow.inTransaction((tx) =>
        this.#deliveryRepo.observeReceiverReceipt(tx, {
          observationId,
          deliveryId: context.deliveryId,
          attemptId: context.attemptId,
          receiptReference: verifyResult.safeReceiptFacts.receipt_id,
          receiptFactsSha256: verifyResult.receiptFactsSha256,
          requestWireSha256: context.wireBodySha256,
          proofSha256: verifyResult.proofSha256,
          keyId: verifyResult.safeReceiptFacts.key_id,
          receiverContractId: context.consumerContractId,
          receiverContractVersion: context.consumerContractVersion,
          receiptFacts: verifyResult.safeReceiptFacts as unknown as Record<string, unknown>,
          verificationProfileVersion: "receiver_local_commit_v1",
          sourceKind: "inline_http_response",
          recordedBy: workerInstanceId,
          state: "verified",
          now
        })
      );
      return recorded.state === "verified" ? "verified" : "rejected";
    }

    await this.#uow.inTransaction((tx) =>
      this.#deliveryRepo.observeReceiverReceipt(tx, {
        observationId,
        deliveryId: context.deliveryId,
        attemptId: context.attemptId,
        receiptReference: context.attemptId,
        receiptFactsSha256: res.bodySha256 ?? EMPTY_BODY_SHA256,
        requestWireSha256: context.wireBodySha256,
        proofSha256: parseSha256Hex(res.bodySha256 ?? EMPTY_BODY_SHA256, "proofSha256"),
        keyId: fallbackKeyId,
        receiverContractId: context.consumerContractId,
        receiverContractVersion: context.consumerContractVersion,
        receiptFacts: { rejection_reason: verifyResult.safeReason },
        verificationProfileVersion: "receiver_local_commit_v1",
        sourceKind: "inline_http_response",
        recordedBy: workerInstanceId,
        state: "rejected",
        safeReason: verifyResult.safeReason,
        now
      })
    );
    return "rejected";
  }

  async #finalizeVerification(
    context: VerificationAttemptContextRecord,
    instanceId: RuntimeInstanceId,
    controlEpoch: ControlEpoch,
    outcomeInput: {
      readonly outcome: "verified" | "failed_transient" | "failed_permanent";
      readonly responseStatus: number | null;
      readonly proofSha256: Sha256Hex | null;
      readonly safeReasonCode: string | null;
    }
  ): Promise<void> {
    const now = parseCanonicalUtcTimestamp(formatUtcTimestamp(this.#clock.nowInstant()), "now");
    const eventId = this.#ids.nextUuid();
    await this.#uow.inTransaction((tx) =>
      this.#deliveryRepo.finalizeVerificationAttempt(tx, {
        attemptId: context.attemptId,
        instanceId,
        controlEpoch,
        outcome: outcomeInput.outcome,
        responseStatus: outcomeInput.responseStatus,
        proofSha256: outcomeInput.proofSha256,
        networkPolicyVersion: this.#networkPolicyVersion,
        safeReasonCode: outcomeInput.safeReasonCode,
        eventId,
        now
      })
    );
  }
}
