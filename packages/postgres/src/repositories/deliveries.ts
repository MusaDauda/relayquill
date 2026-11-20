import {
  CIRCUIT_STATES,
  DELIVERY_STATES,
  parseAttemptId,
  parseCircuitProbeRequestId,
  parseDeliveryFamilyId,
  parseDeliveryId,
  parseEndpointId,
  parseEventId,
  parseProjectId,
  type AttemptId,
  type AttemptState,
  type CanonicalUtcTimestamp,
  type CircuitProbeRequestId,
  type CircuitState,
  type ControlEpoch,
  type DeliveryFamilyId,
  type DeliveryId,
  type DeliveryOutcomeClass,
  type DeliveryState,
  type EndpointId,
  type EndpointVerificationAttemptId,
  type EndpointVerificationIntentId,
  type EventId,
  type LateObservationId,
  type PrincipalId,
  type ProjectId,
  type ReceiverReceiptObservationId,
  type ReplayProposalId,
  type RuntimeInstanceId,
  type Sha256Hex,
  type TenantId,
  type WireEnvelopeId
} from "@relayquill/domain";
import {
  byteaToSha256Hex,
  readOptionalInt32,
  readOptionalString,
  readOptionalUtcTimestamp,
  readOptionalUuid,
  readRequiredBoolean,
  readRequiredEnum,
  readRequiredInt32,
  readRequiredInt64BigInt,
  readRequiredString,
  readRequiredUtcTimestamp,
  readRequiredUuid,
  sha256HexToBytea
} from "../mappers.js";
import { type PgTransactionClient } from "../types.js";
import {
  callJsonbFunction,
  callOptionalJsonbFunction,
  readJsonbInt64BigInt,
  readJsonbTimestamp,
  toBigIntSqlParam,
  toOptionalBigIntSqlParam,
  toOptionalSha256ByteaSqlParam,
  toOptionalTimestampSqlParam,
  toTimestampSqlParam,
  type BigIntInput,
  type TimestampInput
} from "./_sql.js";

export interface PrepareDispatchDeliveryParams {
  readonly requestId: string;
  readonly dispatchDomainId: string;
  readonly workerInstanceId: RuntimeInstanceId;
  readonly controlEpoch: ControlEpoch;
  readonly requestSha256: Sha256Hex;
  readonly deliveryId: DeliveryId;
  readonly attemptId: AttemptId;
  readonly claimLeaseMs: BigIntInput;
}

export type PrepareDispatchDeliveryResult =
  | {
      readonly outcome: "idempotent_recovery";
      readonly requestId: string;
      readonly state: string;
      readonly assignments: readonly {
        readonly attemptId: AttemptId;
        readonly deliveryId: DeliveryId;
        readonly fencingToken: bigint;
      }[];
    }
  | {
      readonly outcome: "prepared";
      readonly attemptId: AttemptId;
      readonly deliveryId: DeliveryId;
      readonly attemptNumber: number;
      readonly fencingToken: bigint;
      readonly claimExpiresAt: CanonicalUtcTimestamp;
    };

export interface StartDeliverySendParams {
  readonly attemptId: AttemptId;
  readonly workerInstanceId: RuntimeInstanceId;
  readonly controlEpoch: ControlEpoch;
  readonly expectedFencingToken: BigIntInput;
  readonly networkBudgetMs: BigIntInput;
}

export interface StartDeliverySendResult {
  readonly shouldSend: boolean;
  readonly alreadyStarted: boolean;
  readonly attemptId: AttemptId;
  readonly requestDeadlineAt: CanonicalUtcTimestamp;
  readonly acceptedAt: CanonicalUtcTimestamp;
}

export interface FinalizeDeliveryAttemptParams {
  readonly attemptId: AttemptId;
  readonly workerInstanceId: RuntimeInstanceId;
  readonly controlEpoch: ControlEpoch;
  readonly expectedFencingToken: BigIntInput;
  readonly attemptState: AttemptState;
  readonly outcomeClass: DeliveryOutcomeClass;
  readonly responseStatus?: number | null | undefined;
  readonly responseBodySha256?: Sha256Hex | null | undefined;
  readonly responseByteCount?: number | null | undefined;
  readonly safeErrorCode?: string | null | undefined;
  readonly retryDecision?: string | null | undefined;
  readonly retryReasonCode?: string | null | undefined;
  readonly retryPolicyVersion?: string | null | undefined;
  readonly selectedDelayMs?: BigIntInput | null | undefined;
  readonly selectedBackoffMs?: BigIntInput | null | undefined;
  readonly retryAfterParseClass?: string | null | undefined;
  readonly retryAfterMs?: BigIntInput | null | undefined;
  readonly nextEligibleAt?: TimestampInput | null | undefined;
}

export interface FinalizeDeliveryAttemptResult {
  readonly outcome: "already_finalized" | "finalized";
  readonly attemptId: AttemptId;
  readonly attemptState: string;
  readonly deliveryState: DeliveryState;
  readonly shardId?: number | undefined;
}

export interface ObserveLateDeliveryParams {
  readonly observationId: LateObservationId;
  readonly deliveryId: DeliveryId;
  readonly attemptId: AttemptId;
  readonly sourceInstanceId: RuntimeInstanceId;
  readonly observationKeySha256: Sha256Hex;
  readonly factsSha256: Sha256Hex;
  readonly observationKind: string;
  readonly safeFacts: Readonly<Record<string, unknown>>;
}

export interface RecordEgressDecisionParams {
  readonly decisionId: string;
  readonly tenantId: TenantId;
  readonly projectId: ProjectId;
  readonly endpointId: EndpointId;
  readonly endpointVersion: BigIntInput;
  readonly deliveryAttemptId?: AttemptId | null | undefined;
  readonly verificationAttemptId?: EndpointVerificationAttemptId | null | undefined;
  readonly runtimeInstanceId: RuntimeInstanceId;
  readonly controlEpoch: ControlEpoch;
  readonly networkPolicyVersion: string;
  readonly registryIpv4Sha256: Sha256Hex;
  readonly registryIpv6Sha256: Sha256Hex;
  readonly authoritySha256: Sha256Hex;
  readonly answerSetSha256?: Sha256Hex | null | undefined;
  readonly selectedAddressSha256?: Sha256Hex | null | undefined;
  readonly selectedFamily?: number | null | undefined;
  readonly peerAddressSha256?: Sha256Hex | null | undefined;
  readonly decision: "allow" | "deny";
  readonly reasonCode: string;
  readonly expiresAt: TimestampInput;
}

export interface ClaimVerificationAttemptParams {
  readonly intentId: EndpointVerificationIntentId;
  readonly attemptId: EndpointVerificationAttemptId;
  readonly instanceId: RuntimeInstanceId;
  readonly controlEpoch: ControlEpoch;
  readonly claimLeaseMs: BigIntInput;
}

export interface FinalizeVerificationAttemptParams {
  readonly attemptId: EndpointVerificationAttemptId;
  readonly instanceId: RuntimeInstanceId;
  readonly controlEpoch: ControlEpoch;
  readonly outcome: "verified" | "failed_transient" | "failed_permanent";
  readonly responseStatus?: number | null | undefined;
  readonly proofSha256?: Sha256Hex | null | undefined;
  readonly networkPolicyVersion: string;
  readonly safeReasonCode?: string | null | undefined;
  readonly eventId: string;
}

export interface ObserveReceiverReceiptParams {
  readonly observationId: ReceiverReceiptObservationId;
  readonly deliveryId: DeliveryId;
  readonly attemptId: AttemptId;
  readonly receiptReference: string;
  readonly receiptFactsSha256: Sha256Hex;
  readonly requestWireSha256: Sha256Hex;
  readonly proofSha256: Sha256Hex;
  readonly keyId: string;
  readonly receiverContractId: string;
  readonly receiverContractVersion: BigIntInput;
  readonly receiptFacts: Readonly<Record<string, unknown>>;
  readonly verificationProfileVersion: string;
  readonly sourceKind: string;
  readonly recordedBy: string;
  readonly state: "verified" | "conflicting" | "rejected";
}

export interface RequestCircuitProbeParams {
  readonly requestId: CircuitProbeRequestId;
  readonly tenantId: TenantId;
  readonly projectId: ProjectId;
  readonly endpointId: EndpointId;
  readonly endpointVersion: BigIntInput;
  readonly expectedCircuitGeneration: BigIntInput;
  readonly requestedBy: PrincipalId;
  readonly receiptId: string;
  readonly keySha256: Sha256Hex;
  readonly submittedShapeSha256: Sha256Hex;
}

export interface ProposeReplayParams {
  readonly proposalId: ReplayProposalId;
  readonly deliveryId: DeliveryId;
  readonly proposerPrincipalId: PrincipalId;
  readonly expectedDeliveryVersion: BigIntInput;
  readonly targetSubscriptionVersion: BigIntInput;
  readonly targetEndpointVersion: BigIntInput;
  readonly wireEnvelopeId: WireEnvelopeId;
  readonly strategy: string;
  readonly orderingStrategy: string;
  readonly representationProfileId: string;
  readonly representationProfileVersion: BigIntInput;
  readonly receiverContractId?: string | null | undefined;
  readonly receiverContractVersion?: BigIntInput | null | undefined;
  readonly consumerEventKeySha256: Sha256Hex;
  readonly candidateSha256: Sha256Hex;
  readonly requestedDeadlineAt: TimestampInput;
}

export interface ReviewReplayParams {
  readonly reviewId: string;
  readonly proposalId: ReplayProposalId;
  readonly expectedProposalVersion: BigIntInput;
  readonly candidateSha256: Sha256Hex;
  readonly reviewerPrincipalId: PrincipalId;
  readonly reviewerAuthorityVersion: BigIntInput;
  readonly decision: "approve" | "reject";
}

export interface AdmitReplayParams {
  readonly proposalId: ReplayProposalId;
  readonly expectedProposalVersion: BigIntInput;
  readonly candidateSha256: Sha256Hex;
  readonly reviewId: string;
  readonly actorPrincipalId: PrincipalId;
  readonly newDeliveryId: DeliveryId;
  readonly receiptId: string;
  readonly idempotencyKeySha256: Sha256Hex;
}

export interface AdmitOrderSkipParams {
  readonly proposalId: string;
  readonly reviewId: string;
  readonly actorPrincipalId: PrincipalId;
  readonly dispositionId: string;
  readonly receiptId: string;
  readonly idempotencyKeySha256: Sha256Hex;
}

export interface AdmitSuppressionParams {
  readonly proposalId: string;
  readonly reviewId: string;
  readonly actorPrincipalId: PrincipalId;
  readonly receiptId: string;
  readonly idempotencyKeySha256: Sha256Hex;
}

export interface SafeDeliverySummary {
  readonly deliveryId: DeliveryId;
  readonly familyId: DeliveryFamilyId;
  readonly eventId: EventId;
  readonly projectId: ProjectId;
  readonly endpointId: EndpointId;
  readonly endpointVersion: bigint;
  readonly deliveryGeneration: bigint;
  readonly state: DeliveryState;
  readonly blockingReason?: string | undefined;
  readonly attemptCount: number;
  readonly maximumAttempts: number;
  readonly deadlineAt: CanonicalUtcTimestamp;
  readonly nextEligibleAt?: CanonicalUtcTimestamp | undefined;
  readonly lastOutcomeClass?: string | undefined;
  readonly acknowledgedAt?: CanonicalUtcTimestamp | undefined;
  readonly terminalAt?: CanonicalUtcTimestamp | undefined;
}

export interface EndpointCircuitRecord {
  readonly endpointId: EndpointId;
  readonly endpointVersion: bigint;
  readonly state: CircuitState;
  readonly circuitGeneration: bigint;
  readonly consecutiveTransientFailures: number;
  readonly reopenCount: number;
  readonly reopenNotBefore?: CanonicalUtcTimestamp | undefined;
  readonly probeGeneration: bigint;
  readonly version: bigint;
}

export async function prepareDispatchDelivery(
  tx: PgTransactionClient,
  input: PrepareDispatchDeliveryParams
): Promise<PrepareDispatchDeliveryResult> {
  const data = await callJsonbFunction(
    tx,
    "rq.cmd_dispatch_prepare",
    ["uuid", "uuid", "uuid", "uuid", "bytea", "uuid", "uuid", "bigint"],
    [
      input.requestId,
      input.dispatchDomainId,
      input.workerInstanceId,
      input.controlEpoch,
      sha256HexToBytea(input.requestSha256, "requestSha256"),
      input.deliveryId,
      input.attemptId,
      toBigIntSqlParam(input.claimLeaseMs, "claimLeaseMs")
    ],
    "rq.cmd_dispatch_prepare"
  );

  const outcome = readRequiredEnum(data, "outcome", ["idempotent_recovery", "prepared"] as const);
  if (outcome === "idempotent_recovery") {
    const rawAssignments = data["assignments"];
    const items = Array.isArray(rawAssignments) ? rawAssignments : [];
    const assignments = items.map((item) => {
      const rec = item as Record<string, unknown>;
      return {
        attemptId: readRequiredUuid(rec, "attempt_id", parseAttemptId),
        deliveryId: readRequiredUuid(rec, "delivery_id", parseDeliveryId),
        fencingToken: readJsonbInt64BigInt(rec, "fencing_token", "rq.cmd_dispatch_prepare")
      };
    });
    return {
      outcome: "idempotent_recovery",
      requestId: readRequiredUuid(data, "request_id"),
      state: readRequiredString(data, "state"),
      assignments
    };
  }

  return {
    outcome: "prepared",
    attemptId: readRequiredUuid(data, "attempt_id", parseAttemptId),
    deliveryId: readRequiredUuid(data, "delivery_id", parseDeliveryId),
    attemptNumber: readRequiredInt32(data, "attempt_number"),
    fencingToken: readJsonbInt64BigInt(data, "fencing_token", "rq.cmd_dispatch_prepare"),
    claimExpiresAt: readJsonbTimestamp(data, "claim_expires_at", "rq.cmd_dispatch_prepare")
  };
}

export async function startDeliverySend(
  tx: PgTransactionClient,
  input: StartDeliverySendParams
): Promise<StartDeliverySendResult> {
  const data = await callJsonbFunction(
    tx,
    "rq.cmd_send_start",
    ["uuid", "uuid", "uuid", "bigint", "bigint"],
    [
      input.attemptId,
      input.workerInstanceId,
      input.controlEpoch,
      toBigIntSqlParam(input.expectedFencingToken, "expectedFencingToken"),
      toBigIntSqlParam(input.networkBudgetMs, "networkBudgetMs")
    ],
    "rq.cmd_send_start"
  );

  return {
    shouldSend: readRequiredBoolean(data, "should_send"),
    alreadyStarted: readRequiredBoolean(data, "already_started"),
    attemptId: readRequiredUuid(data, "attempt_id", parseAttemptId),
    requestDeadlineAt: readJsonbTimestamp(data, "request_deadline_at", "rq.cmd_send_start"),
    acceptedAt: readJsonbTimestamp(data, "accepted_at", "rq.cmd_send_start")
  };
}

export async function finalizeDeliveryAttempt(
  tx: PgTransactionClient,
  input: FinalizeDeliveryAttemptParams
): Promise<FinalizeDeliveryAttemptResult> {
  const data = await callJsonbFunction(
    tx,
    "rq.cmd_attempt_finalize",
    [
      "uuid",
      "uuid",
      "uuid",
      "bigint",
      "text",
      "text",
      "integer",
      "bytea",
      "integer",
      "text",
      "text",
      "text",
      "text",
      "bigint",
      "bigint",
      "text",
      "bigint",
      "timestamptz"
    ],
    [
      input.attemptId,
      input.workerInstanceId,
      input.controlEpoch,
      toBigIntSqlParam(input.expectedFencingToken, "expectedFencingToken"),
      input.attemptState,
      input.outcomeClass,
      input.responseStatus ?? null,
      toOptionalSha256ByteaSqlParam(input.responseBodySha256, "responseBodySha256"),
      input.responseByteCount ?? null,
      input.safeErrorCode ?? null,
      input.retryDecision ?? null,
      input.retryReasonCode ?? null,
      input.retryPolicyVersion ?? null,
      toOptionalBigIntSqlParam(input.selectedDelayMs, "selectedDelayMs"),
      toOptionalBigIntSqlParam(input.selectedBackoffMs, "selectedBackoffMs"),
      input.retryAfterParseClass ?? null,
      toOptionalBigIntSqlParam(input.retryAfterMs, "retryAfterMs"),
      toOptionalTimestampSqlParam(input.nextEligibleAt, "nextEligibleAt")
    ],
    "rq.cmd_attempt_finalize"
  );

  return {
    outcome: readRequiredEnum(data, "outcome", ["already_finalized", "finalized"] as const),
    attemptId: readRequiredUuid(data, "attempt_id", parseAttemptId),
    attemptState: readRequiredString(data, "attempt_state"),
    deliveryState: readRequiredEnum(data, "delivery_state", DELIVERY_STATES),
    shardId: readOptionalInt32(data, "shard_id")
  };
}

export async function observeLateDelivery(
  tx: PgTransactionClient,
  input: ObserveLateDeliveryParams
): Promise<{ readonly observationId: string; readonly attemptId: AttemptId }> {
  const data = await callJsonbFunction(
    tx,
    "rq.cmd_late_delivery_observe",
    ["uuid", "uuid", "uuid", "uuid", "bytea", "bytea", "text", "jsonb"],
    [
      input.observationId,
      input.deliveryId,
      input.attemptId,
      input.sourceInstanceId,
      sha256HexToBytea(input.observationKeySha256, "observationKeySha256"),
      sha256HexToBytea(input.factsSha256, "factsSha256"),
      input.observationKind,
      JSON.stringify(input.safeFacts)
    ],
    "rq.cmd_late_delivery_observe"
  );

  return {
    observationId: readRequiredUuid(data, "observation_id"),
    attemptId: readRequiredUuid(data, "attempt_id", parseAttemptId)
  };
}

export async function recordEgressDecision(
  tx: PgTransactionClient,
  input: RecordEgressDecisionParams
): Promise<{ readonly egressDecisionId: string; readonly decision: string }> {
  const data = await callJsonbFunction(
    tx,
    "rq.cmd_egress_decision_record",
    [
      "uuid",
      "uuid",
      "uuid",
      "uuid",
      "bigint",
      "uuid",
      "uuid",
      "uuid",
      "uuid",
      "text",
      "bytea",
      "bytea",
      "bytea",
      "bytea",
      "bytea",
      "integer",
      "bytea",
      "text",
      "text",
      "timestamptz"
    ],
    [
      input.decisionId,
      input.tenantId,
      input.projectId,
      input.endpointId,
      toBigIntSqlParam(input.endpointVersion, "endpointVersion"),
      input.deliveryAttemptId ?? null,
      input.verificationAttemptId ?? null,
      input.runtimeInstanceId,
      input.controlEpoch,
      input.networkPolicyVersion,
      sha256HexToBytea(input.registryIpv4Sha256, "registryIpv4Sha256"),
      sha256HexToBytea(input.registryIpv6Sha256, "registryIpv6Sha256"),
      sha256HexToBytea(input.authoritySha256, "authoritySha256"),
      toOptionalSha256ByteaSqlParam(input.answerSetSha256, "answerSetSha256"),
      toOptionalSha256ByteaSqlParam(input.selectedAddressSha256, "selectedAddressSha256"),
      input.selectedFamily ?? null,
      toOptionalSha256ByteaSqlParam(input.peerAddressSha256, "peerAddressSha256"),
      input.decision,
      input.reasonCode,
      toTimestampSqlParam(input.expiresAt, "expiresAt")
    ],
    "rq.cmd_egress_decision_record"
  );

  return {
    egressDecisionId: readRequiredUuid(data, "egress_decision_id"),
    decision: readRequiredString(data, "decision")
  };
}

export async function claimVerificationAttempt(
  tx: PgTransactionClient,
  input: ClaimVerificationAttemptParams
): Promise<{
  readonly attemptId: string;
  readonly intentId: string;
  readonly claimExpiresAt: CanonicalUtcTimestamp;
}> {
  const data = await callJsonbFunction(
    tx,
    "rq.cmd_verification_attempt_claim",
    ["uuid", "uuid", "uuid", "uuid", "bigint"],
    [
      input.intentId,
      input.attemptId,
      input.instanceId,
      input.controlEpoch,
      toBigIntSqlParam(input.claimLeaseMs, "claimLeaseMs")
    ],
    "rq.cmd_verification_attempt_claim"
  );

  return {
    attemptId: readRequiredUuid(data, "attempt_id"),
    intentId: readRequiredUuid(data, "intent_id"),
    claimExpiresAt: readJsonbTimestamp(data, "claim_expires_at", "rq.cmd_verification_attempt_claim")
  };
}

export async function finalizeVerificationAttempt(
  tx: PgTransactionClient,
  input: FinalizeVerificationAttemptParams
): Promise<{ readonly intentId: string; readonly intentState: string }> {
  const data = await callJsonbFunction(
    tx,
    "rq.cmd_verification_attempt_finalize",
    ["uuid", "uuid", "uuid", "text", "integer", "bytea", "text", "text", "uuid"],
    [
      input.attemptId,
      input.instanceId,
      input.controlEpoch,
      input.outcome,
      input.responseStatus ?? null,
      toOptionalSha256ByteaSqlParam(input.proofSha256, "proofSha256"),
      input.networkPolicyVersion,
      input.safeReasonCode ?? null,
      input.eventId
    ],
    "rq.cmd_verification_attempt_finalize"
  );

  return {
    intentId: readRequiredUuid(data, "intent_id"),
    intentState: readRequiredString(data, "intent_state")
  };
}

export async function observeReceiverReceipt(
  tx: PgTransactionClient,
  input: ObserveReceiverReceiptParams
): Promise<{ readonly observationId: string; readonly state: string }> {
  const data = await callJsonbFunction(
    tx,
    "rq.cmd_receiver_receipt_observe",
    [
      "uuid",
      "uuid",
      "uuid",
      "text",
      "bytea",
      "bytea",
      "bytea",
      "text",
      "uuid",
      "bigint",
      "jsonb",
      "text",
      "text",
      "uuid",
      "text"
    ],
    [
      input.observationId,
      input.deliveryId,
      input.attemptId,
      input.receiptReference,
      sha256HexToBytea(input.receiptFactsSha256, "receiptFactsSha256"),
      sha256HexToBytea(input.requestWireSha256, "requestWireSha256"),
      sha256HexToBytea(input.proofSha256, "proofSha256"),
      input.keyId,
      input.receiverContractId,
      toBigIntSqlParam(input.receiverContractVersion, "receiverContractVersion"),
      JSON.stringify(input.receiptFacts),
      input.verificationProfileVersion,
      input.sourceKind,
      input.recordedBy,
      input.state
    ],
    "rq.cmd_receiver_receipt_observe"
  );

  return {
    observationId: readRequiredUuid(data, "observation_id"),
    state: readRequiredString(data, "state")
  };
}

export async function requestCircuitProbe(
  tx: PgTransactionClient,
  input: RequestCircuitProbeParams
): Promise<{ readonly requestId: CircuitProbeRequestId; readonly receiptId: string; readonly state: string }> {
  const data = await callJsonbFunction(
    tx,
    "rq.cmd_circuit_probe_request",
    ["uuid", "uuid", "uuid", "uuid", "bigint", "bigint", "uuid", "uuid", "bytea", "bytea"],
    [
      input.requestId,
      input.tenantId,
      input.projectId,
      input.endpointId,
      toBigIntSqlParam(input.endpointVersion, "endpointVersion"),
      toBigIntSqlParam(input.expectedCircuitGeneration, "expectedCircuitGeneration"),
      input.requestedBy,
      input.receiptId,
      sha256HexToBytea(input.keySha256, "keySha256"),
      sha256HexToBytea(input.submittedShapeSha256, "submittedShapeSha256")
    ],
    "rq.cmd_circuit_probe_request"
  );

  return {
    requestId: readRequiredUuid(data, "request_id", parseCircuitProbeRequestId),
    receiptId: readRequiredUuid(data, "receipt_id"),
    state: readRequiredString(data, "state")
  };
}

export async function proposeReplay(
  tx: PgTransactionClient,
  input: ProposeReplayParams
): Promise<{
  readonly proposalId: string;
  readonly state: string;
  readonly expiresAt: CanonicalUtcTimestamp;
}> {
  const data = await callJsonbFunction(
    tx,
    "rq.cmd_replay_propose",
    [
      "uuid",
      "uuid",
      "uuid",
      "bigint",
      "bigint",
      "bigint",
      "uuid",
      "text",
      "text",
      "uuid",
      "bigint",
      "uuid",
      "bigint",
      "bytea",
      "bytea",
      "timestamptz"
    ],
    [
      input.proposalId,
      input.deliveryId,
      input.proposerPrincipalId,
      toBigIntSqlParam(input.expectedDeliveryVersion, "expectedDeliveryVersion"),
      toBigIntSqlParam(input.targetSubscriptionVersion, "targetSubscriptionVersion"),
      toBigIntSqlParam(input.targetEndpointVersion, "targetEndpointVersion"),
      input.wireEnvelopeId,
      input.strategy,
      input.orderingStrategy,
      input.representationProfileId,
      toBigIntSqlParam(input.representationProfileVersion, "representationProfileVersion"),
      input.receiverContractId ?? null,
      toOptionalBigIntSqlParam(input.receiverContractVersion, "receiverContractVersion"),
      sha256HexToBytea(input.consumerEventKeySha256, "consumerEventKeySha256"),
      sha256HexToBytea(input.candidateSha256, "candidateSha256"),
      toTimestampSqlParam(input.requestedDeadlineAt, "requestedDeadlineAt")
    ],
    "rq.cmd_replay_propose"
  );

  return {
    proposalId: readRequiredUuid(data, "proposal_id"),
    state: readRequiredString(data, "state"),
    expiresAt: readJsonbTimestamp(data, "expires_at", "rq.cmd_replay_propose")
  };
}

export async function reviewReplay(
  tx: PgTransactionClient,
  input: ReviewReplayParams
): Promise<{ readonly reviewId: string; readonly proposalId: string; readonly state: string }> {
  const data = await callJsonbFunction(
    tx,
    "rq.cmd_replay_review",
    ["uuid", "uuid", "bigint", "bytea", "uuid", "bigint", "text"],
    [
      input.reviewId,
      input.proposalId,
      toBigIntSqlParam(input.expectedProposalVersion, "expectedProposalVersion"),
      sha256HexToBytea(input.candidateSha256, "candidateSha256"),
      input.reviewerPrincipalId,
      toBigIntSqlParam(input.reviewerAuthorityVersion, "reviewerAuthorityVersion"),
      input.decision
    ],
    "rq.cmd_replay_review"
  );

  return {
    reviewId: readRequiredUuid(data, "review_id"),
    proposalId: readRequiredUuid(data, "proposal_id"),
    state: readRequiredString(data, "state")
  };
}

export async function admitReplay(
  tx: PgTransactionClient,
  input: AdmitReplayParams
): Promise<{
  readonly outcome: "idempotent_recovery" | "admitted";
  readonly deliveryId: DeliveryId;
  readonly deliveryGeneration?: bigint | undefined;
  readonly receiptId?: string | undefined;
  readonly proposalId?: string | undefined;
}> {
  const data = await callJsonbFunction(
    tx,
    "rq.cmd_replay_admit",
    ["uuid", "bigint", "bytea", "uuid", "uuid", "uuid", "uuid", "bytea"],
    [
      input.proposalId,
      toBigIntSqlParam(input.expectedProposalVersion, "expectedProposalVersion"),
      sha256HexToBytea(input.candidateSha256, "candidateSha256"),
      input.reviewId,
      input.actorPrincipalId,
      input.newDeliveryId,
      input.receiptId,
      sha256HexToBytea(input.idempotencyKeySha256, "idempotencyKeySha256")
    ],
    "rq.cmd_replay_admit"
  );

  const outcome = readRequiredEnum(data, "outcome", ["idempotent_recovery", "admitted"] as const);
  return {
    outcome,
    deliveryId: readRequiredUuid(data, "delivery_id", parseDeliveryId),
    deliveryGeneration:
      data["delivery_generation"] === undefined || data["delivery_generation"] === null
        ? undefined
        : readJsonbInt64BigInt(data, "delivery_generation", "rq.cmd_replay_admit"),
    receiptId: readOptionalUuid(data, "receipt_id"),
    proposalId: readOptionalUuid(data, "proposal_id")
  };
}

export async function admitOrderSkip(
  tx: PgTransactionClient,
  input: AdmitOrderSkipParams
): Promise<{
  readonly outcome: "idempotent_recovery" | "admitted";
  readonly dispositionId: string;
  readonly resultingSequence?: bigint | undefined;
}> {
  const data = await callJsonbFunction(
    tx,
    "rq.cmd_order_skip_admit",
    ["uuid", "uuid", "uuid", "uuid", "uuid", "bytea"],
    [
      input.proposalId,
      input.reviewId,
      input.actorPrincipalId,
      input.dispositionId,
      input.receiptId,
      sha256HexToBytea(input.idempotencyKeySha256, "idempotencyKeySha256")
    ],
    "rq.cmd_order_skip_admit"
  );

  return {
    outcome: readRequiredEnum(data, "outcome", ["idempotent_recovery", "admitted"] as const),
    dispositionId: readRequiredUuid(data, "disposition_id"),
    resultingSequence:
      data["resulting_sequence"] === undefined || data["resulting_sequence"] === null
        ? undefined
        : readJsonbInt64BigInt(data, "resulting_sequence", "rq.cmd_order_skip_admit")
  };
}

export async function admitSuppression(
  tx: PgTransactionClient,
  input: AdmitSuppressionParams
): Promise<{
  readonly outcome: "idempotent_recovery" | "already_terminal" | "suppressed";
  readonly receiptId: string;
  readonly deliveryId?: DeliveryId | undefined;
  readonly deliveryState?: DeliveryState | undefined;
}> {
  const data = await callJsonbFunction(
    tx,
    "rq.cmd_suppression_admit",
    ["uuid", "uuid", "uuid", "uuid", "bytea"],
    [
      input.proposalId,
      input.reviewId,
      input.actorPrincipalId,
      input.receiptId,
      sha256HexToBytea(input.idempotencyKeySha256, "idempotencyKeySha256")
    ],
    "rq.cmd_suppression_admit"
  );

  return {
    outcome: readRequiredEnum(
      data,
      "outcome",
      ["idempotent_recovery", "already_terminal", "suppressed"] as const
    ),
    receiptId: readRequiredUuid(data, "receipt_id"),
    deliveryId: readOptionalUuid(data, "delivery_id", parseDeliveryId),
    deliveryState:
      data["delivery_state"] === undefined || data["delivery_state"] === null
        ? undefined
        : readRequiredEnum(data, "delivery_state", DELIVERY_STATES)
  };
}

export async function readDeliverySafe(
  tx: PgTransactionClient,
  tenantId: TenantId,
  projectId: ProjectId,
  deliveryId: DeliveryId
): Promise<SafeDeliverySummary | undefined> {
  const data = await callOptionalJsonbFunction(
    tx,
    "rq.read_delivery_safe",
    ["uuid", "uuid", "uuid"],
    [tenantId, projectId, deliveryId],
    "rq.read_delivery_safe"
  );
  if (data === undefined) {
    return undefined;
  }
  return {
    deliveryId: readRequiredUuid(data, "delivery_id", parseDeliveryId),
    familyId: readRequiredUuid(data, "family_id", parseDeliveryFamilyId),
    eventId: readRequiredUuid(data, "event_id", parseEventId),
    projectId: readRequiredUuid(data, "project_id", parseProjectId),
    endpointId: readRequiredUuid(data, "endpoint_id", parseEndpointId),
    endpointVersion: readJsonbInt64BigInt(data, "endpoint_version", "rq.read_delivery_safe"),
    deliveryGeneration: readJsonbInt64BigInt(data, "delivery_generation", "rq.read_delivery_safe"),
    state: readRequiredEnum(data, "state", DELIVERY_STATES),
    blockingReason: readOptionalString(data, "blocking_reason"),
    attemptCount: readRequiredInt32(data, "attempt_count"),
    maximumAttempts: readRequiredInt32(data, "maximum_attempts"),
    deadlineAt: readJsonbTimestamp(data, "deadline_at", "rq.read_delivery_safe"),
    nextEligibleAt: readOptionalUtcTimestamp(data, "next_eligible_at"),
    lastOutcomeClass: readOptionalString(data, "last_outcome_class"),
    acknowledgedAt: readOptionalUtcTimestamp(data, "acknowledged_at"),
    terminalAt: readOptionalUtcTimestamp(data, "terminal_at")
  };
}

export async function listProjectSafeDeliveries(
  tx: PgTransactionClient,
  tenantId: TenantId,
  projectId: ProjectId,
  limit = 50
): Promise<readonly SafeDeliverySummary[]> {
  const clamped = Math.min(200, Math.max(1, Math.trunc(limit)));
  const res = await tx.query<Record<string, unknown>>(
    `SELECT id, family_id, event_id, project_id, endpoint_id, endpoint_version,
            delivery_generation, state, blocking_reason, attempt_count, maximum_attempts,
            deadline_at, next_eligible_at, last_outcome_class, acknowledged_at, terminal_at
       FROM rq.v_safe_deliveries
      WHERE tenant_id = $1::uuid AND project_id = $2::uuid
      ORDER BY created_at ASC, id ASC
      LIMIT $3::integer`,
    [tenantId, projectId, clamped]
  );

  return res.rows.map((row) => ({
    deliveryId: readRequiredUuid(row, "id", parseDeliveryId),
    familyId: readRequiredUuid(row, "family_id", parseDeliveryFamilyId),
    eventId: readRequiredUuid(row, "event_id", parseEventId),
    projectId: readRequiredUuid(row, "project_id", parseProjectId),
    endpointId: readRequiredUuid(row, "endpoint_id", parseEndpointId),
    endpointVersion: readRequiredInt64BigInt(row, "endpoint_version"),
    deliveryGeneration: readRequiredInt64BigInt(row, "delivery_generation"),
    state: readRequiredEnum(row, "state", DELIVERY_STATES),
    blockingReason: readOptionalString(row, "blocking_reason"),
    attemptCount: readRequiredInt32(row, "attempt_count"),
    maximumAttempts: readRequiredInt32(row, "maximum_attempts"),
    deadlineAt: readRequiredUtcTimestamp(row, "deadline_at"),
    nextEligibleAt: readOptionalUtcTimestamp(row, "next_eligible_at"),
    lastOutcomeClass: readOptionalString(row, "last_outcome_class"),
    acknowledgedAt: readOptionalUtcTimestamp(row, "acknowledged_at"),
    terminalAt: readOptionalUtcTimestamp(row, "terminal_at")
  }));
}

export async function findEndpointCircuit(
  tx: PgTransactionClient,
  endpointId: EndpointId,
  endpointVersion: BigIntInput
): Promise<EndpointCircuitRecord | undefined> {
  const res = await tx.query<Record<string, unknown>>(
    `SELECT endpoint_id, endpoint_version, state, circuit_generation,
            consecutive_transient_failures, reopen_count, reopen_not_before,
            probe_generation, version
       FROM rq.endpoint_circuits
      WHERE endpoint_id = $1::uuid AND endpoint_version = $2::bigint`,
    [endpointId, toBigIntSqlParam(endpointVersion, "endpointVersion")]
  );
  const row = res.rows[0];
  if (row === undefined) {
    return undefined;
  }
  return {
    endpointId: readRequiredUuid(row, "endpoint_id", parseEndpointId),
    endpointVersion: readRequiredInt64BigInt(row, "endpoint_version"),
    state: readRequiredEnum(row, "state", CIRCUIT_STATES),
    circuitGeneration: readRequiredInt64BigInt(row, "circuit_generation"),
    consecutiveTransientFailures: readRequiredInt32(row, "consecutive_transient_failures"),
    reopenCount: readRequiredInt32(row, "reopen_count"),
    reopenNotBefore: readOptionalUtcTimestamp(row, "reopen_not_before"),
    probeGeneration: readRequiredInt64BigInt(row, "probe_generation"),
    version: readRequiredInt64BigInt(row, "version")
  };
}

export async function listDeliveryAttempts(
  tx: PgTransactionClient,
  tenantId: TenantId,
  projectId: ProjectId,
  deliveryId: DeliveryId
): Promise<
  readonly {
    readonly attemptId: AttemptId;
    readonly attemptNumber: number;
    readonly state: string;
    readonly fencingToken: bigint;
    readonly outcomeClass?: string | undefined;
    readonly responseStatus?: number | undefined;
    readonly responseBodySha256?: Sha256Hex | undefined;
    readonly preparedAt: CanonicalUtcTimestamp;
    readonly finishedAt?: CanonicalUtcTimestamp | undefined;
  }[]
> {
  const res = await tx.query<Record<string, unknown>>(
    `SELECT id, attempt_number, state, fencing_token, outcome_class, response_status,
            response_body_sha256, prepared_at, finished_at
       FROM rq.delivery_attempts
      WHERE tenant_id = $1::uuid AND project_id = $2::uuid AND delivery_id = $3::uuid
      ORDER BY attempt_number ASC`,
    [tenantId, projectId, deliveryId]
  );

  return res.rows.map((row) => ({
    attemptId: readRequiredUuid(row, "id", parseAttemptId),
    attemptNumber: readRequiredInt32(row, "attempt_number"),
    state: readRequiredString(row, "state"),
    fencingToken: readRequiredInt64BigInt(row, "fencing_token"),
    outcomeClass: readOptionalString(row, "outcome_class"),
    responseStatus: readOptionalInt32(row, "response_status"),
    responseBodySha256:
      row["response_body_sha256"] === null || row["response_body_sha256"] === undefined
        ? undefined
        : byteaToSha256Hex(row["response_body_sha256"], "response_body_sha256"),
    preparedAt: readRequiredUtcTimestamp(row, "prepared_at"),
    finishedAt: readOptionalUtcTimestamp(row, "finished_at")
  }));
}
