import {
  type DeliveryExecutionBucket,
  type DeliveryOutcomeClass,
  type DeliveryPopulation,
  type DeliveryState,
  type LateObservationKind,
  type ProposalReviewDecision,
  type ProposalState,
  type ReceiptVerificationState,
  type ReplayOrderingStrategy,
  type ReplayStrategy,
  type SuppressionAdmitOutcome,
  ValidationDomainError,
  isDeliveryExecutionBucket,
  isDeliveryOutcomeClass,
  isDeliveryPopulation,
  isDeliveryState,
  isLateObservationKind,
  isProposalReviewDecision,
  isProposalState,
  isReceiptVerificationState,
  isReplayOrderingStrategy,
  isReplayStrategy,
  isValidHttpStatus
} from "@relayquill/domain";
import { type CapabilityEntryDto, parseCapabilities } from "./capabilities.js";
import {
  type AttemptId,
  type CanonicalUtcTimestamp,
  type CanonicalUuid,
  type DeliveryFamilyId,
  type DeliveryId,
  type EndpointId,
  type EventId,
  type Int64String,
  type LateObservationId,
  type NonNegativeInt64String,
  type OrderingKeyId,
  type PositiveInt64String,
  type PrincipalId,
  type ReceiverContractId,
  type ReceiverReceiptObservationId,
  type ReplayProposalId,
  type RepresentationProfileId,
  type Sha256Hex,
  type SubscriptionId,
  type WireEnvelopeId,
  assertAllowedKeys,
  assertPlainRecord,
  parseAttemptId,
  parseBooleanField,
  parseBoundedInteger,
  parseBoundedString,
  parseCanonicalUtcTimestamp,
  parseCanonicalUuid,
  parseDeliveryFamilyId,
  parseDeliveryId,
  parseEndpointId,
  parseEventId,
  parseInt64String,
  parseNonNegativeInt64String,
  parseNullableUtcTimestamp,
  parsePositiveInt32,
  parsePositiveInt64String,
  parseReceiverContractId,
  parseReceiverReceiptObservationId,
  parseReplayProposalId,
  parseRepresentationProfileId,
  parseSafeReasonCode,
  parseSha256Hex,
  parseSubscriptionId,
  parseWireEnvelopeId
} from "./values.js";

export interface DeliveryLatestResponseSummaryDto {
  readonly attempt_id: AttemptId;
  readonly observed_at: CanonicalUtcTimestamp;
  readonly response_status: number | null;
  readonly outcome_class: DeliveryOutcomeClass;
  readonly safe_error_code: string | null;
}

export interface DeliveryLatestReceiptSummaryDto {
  readonly observation_id: ReceiverReceiptObservationId;
  readonly verification_state: ReceiptVerificationState;
  readonly observed_at: CanonicalUtcTimestamp;
  readonly committed_at: CanonicalUtcTimestamp | null;
}

export interface DeliverySummaryDto {
  readonly delivery_id: DeliveryId;
  readonly family_id: DeliveryFamilyId;
  readonly event_id: EventId;
  readonly delivery_generation: NonNegativeInt64String;
  readonly is_replay: boolean;
  readonly replay_proposal_id: ReplayProposalId | null;
  readonly subscription_id: SubscriptionId;
  readonly original_subscription_version: PositiveInt64String;
  readonly dispatch_subscription_version: PositiveInt64String;
  readonly endpoint_id: EndpointId;
  readonly endpoint_version: PositiveInt64String;
  readonly wire_envelope_id: WireEnvelopeId;
  readonly representation_version: number;
  readonly consumer_event_key_sha256: Sha256Hex;
  readonly state: DeliveryState;
  readonly execution_bucket: DeliveryExecutionBucket;
  readonly blocking_reason: string | null;
  readonly last_outcome_class: DeliveryOutcomeClass | null;
  readonly attempt_count: number;
  readonly maximum_attempts: number;
  readonly prepared_attempt_count: number;
  readonly preparation_failure_count: number;
  readonly next_attempt_number: number;
  readonly deadline_at: CanonicalUtcTimestamp;
  readonly next_eligible_at: CanonicalUtcTimestamp;
  readonly acknowledged_at: CanonicalUtcTimestamp | null;
  readonly terminal_at: CanonicalUtcTimestamp | null;
  readonly current_version: Int64String;
  readonly current_fence: NonNegativeInt64String;
  readonly current_attempt_id: AttemptId | null;
  readonly latest_response_summary: DeliveryLatestResponseSummaryDto | null;
  readonly latest_receipt_summary: DeliveryLatestReceiptSummaryDto | null;
  readonly capabilities?: readonly CapabilityEntryDto[] | undefined;
}

export interface DeliveryAggregateSummaryDto {
  readonly unit: "delivery_generation";
  readonly population: DeliveryPopulation;
  readonly observed_at: CanonicalUtcTimestamp;
  readonly pending_count: NonNegativeInt64String;
  readonly active_count: NonNegativeInt64String;
  readonly acknowledged_count: NonNegativeInt64String;
  readonly dead_letter_count: NonNegativeInt64String;
  readonly suppressed_count: NonNegativeInt64String;
  readonly expired_count: NonNegativeInt64String;
  readonly verified_receipt_count: NonNegativeInt64String;
  readonly unknown_attempt_count: NonNegativeInt64String;
  readonly distinct_receipt_summary?: {
    readonly grouped_by: "integration_consumer_scope";
    readonly count: NonNegativeInt64String;
    readonly grouping_note: string;
  } | undefined;
}

export interface LateDeliveryObservationDto {
  readonly observation_id: LateObservationId;
  readonly delivery_id: DeliveryId;
  readonly attempt_id: AttemptId;
  readonly observation_kind: LateObservationKind;
  readonly facts_sha256: Sha256Hex;
  readonly recorded_at: CanonicalUtcTimestamp;
  readonly safe_facts: Readonly<Record<string, unknown>>;
}

export interface CreateReplayProposalRequestDto {
  readonly schema_version: 1;
  readonly expected_delivery_version: Int64String;
  readonly target_subscription_version: PositiveInt64String;
  readonly target_endpoint_version: PositiveInt64String;
  readonly wire_envelope_id: WireEnvelopeId;
  readonly strategy: ReplayStrategy;
  readonly ordering_strategy: ReplayOrderingStrategy;
  readonly requested_deadline_at: CanonicalUtcTimestamp;
  readonly consumer_event_key_sha256: Sha256Hex;
  readonly representation_profile_id?: RepresentationProfileId | undefined;
  readonly representation_profile_version?: PositiveInt64String | undefined;
  readonly receiver_contract_id?: ReceiverContractId | undefined;
  readonly receiver_contract_version?: PositiveInt64String | undefined;
  readonly evidence_references: readonly string[];
  readonly reason_code: string;
}

export interface ReplayProposalDto {
  readonly proposal_id: ReplayProposalId;
  readonly family_id: DeliveryFamilyId;
  readonly source_delivery_id: DeliveryId;
  readonly event_id: EventId;
  readonly state: ProposalState;
  readonly version: Int64String;
  readonly candidate_sha256: Sha256Hex;
  readonly strategy: ReplayStrategy;
  readonly ordering_strategy: ReplayOrderingStrategy;
  readonly target_subscription_version: PositiveInt64String;
  readonly target_endpoint_version: PositiveInt64String;
  readonly wire_envelope_id: WireEnvelopeId;
  readonly requested_deadline_at: CanonicalUtcTimestamp;
  readonly proposer_principal_id: PrincipalId;
  readonly created_at: CanonicalUtcTimestamp;
  readonly expires_at: CanonicalUtcTimestamp;
  readonly accepted_delivery_id: DeliveryId | null;
  readonly capabilities?: readonly CapabilityEntryDto[] | undefined;
}

export interface ReviewProposalRequestDto {
  readonly schema_version: 1;
  readonly expected_proposal_version: Int64String;
  readonly candidate_sha256: Sha256Hex;
  readonly decision: ProposalReviewDecision;
  readonly operation_proof_id: CanonicalUuid;
  readonly evidence_references: readonly string[];
  readonly reason_code: string;
}

export interface AdmitProposalRequestDto {
  readonly schema_version: 1;
  readonly expected_proposal_version: Int64String;
  readonly candidate_sha256: Sha256Hex;
  readonly review_id: CanonicalUuid;
  readonly operation_proof_id?: CanonicalUuid | undefined;
  readonly reason_code: string;
}

export interface CreateSuppressionProposalRequestDto {
  readonly schema_version: 1;
  readonly expected_delivery_version: Int64String;
  readonly prior_outcome_class: DeliveryOutcomeClass | null;
  readonly evidence_references: readonly string[];
  readonly reason_code: string;
}

export interface SuppressionProposalDto {
  readonly proposal_id: CanonicalUuid;
  readonly delivery_id: DeliveryId;
  readonly state: ProposalState;
  readonly version: Int64String;
  readonly candidate_sha256: Sha256Hex;
  readonly prior_outcome_class: DeliveryOutcomeClass | null;
  readonly proposer_principal_id: PrincipalId;
  readonly created_at: CanonicalUtcTimestamp;
  readonly expires_at: CanonicalUtcTimestamp;
  readonly capabilities?: readonly CapabilityEntryDto[] | undefined;
}

export interface AdmitSuppressionResultDto {
  readonly outcome: SuppressionAdmitOutcome;
  readonly proposal: SuppressionProposalDto;
  readonly delivery_id: DeliveryId;
  readonly resulting_delivery_state: DeliveryState;
  readonly advances_strict_ordering_head: false;
}

export interface CreateOrderSkipProposalRequestDto {
  readonly schema_version: 1;
  readonly ordering_key_id: OrderingKeyId;
  readonly delivery_id: DeliveryId;
  readonly expected_key_version: Int64String;
  readonly expected_delivery_version: Int64String;
  readonly known_outcome_class: DeliveryOutcomeClass | null;
  readonly evidence_references: readonly string[];
  readonly reason_code: string;
}

export interface OrderSkipProposalDto {
  readonly proposal_id: CanonicalUuid;
  readonly ordering_key_id: OrderingKeyId;
  readonly delivery_id: DeliveryId;
  readonly state: ProposalState;
  readonly version: Int64String;
  readonly candidate_sha256: Sha256Hex;
  readonly prior_sequence: PositiveInt64String;
  readonly resulting_sequence: PositiveInt64String;
  readonly proposer_principal_id: PrincipalId;
  readonly created_at: CanonicalUtcTimestamp;
  readonly expires_at: CanonicalUtcTimestamp;
  readonly capabilities?: readonly CapabilityEntryDto[] | undefined;
}

const LATEST_RESPONSE_KEYS = new Set([
  "attempt_id",
  "observed_at",
  "response_status",
  "outcome_class",
  "safe_error_code"
]);

const LATEST_RECEIPT_KEYS = new Set([
  "observation_id",
  "verification_state",
  "observed_at",
  "committed_at"
]);

const DELIVERY_SUMMARY_KEYS = new Set([
  "delivery_id",
  "family_id",
  "event_id",
  "delivery_generation",
  "is_replay",
  "replay_proposal_id",
  "subscription_id",
  "original_subscription_version",
  "dispatch_subscription_version",
  "endpoint_id",
  "endpoint_version",
  "wire_envelope_id",
  "representation_version",
  "consumer_event_key_sha256",
  "state",
  "execution_bucket",
  "blocking_reason",
  "last_outcome_class",
  "attempt_count",
  "maximum_attempts",
  "prepared_attempt_count",
  "preparation_failure_count",
  "next_attempt_number",
  "deadline_at",
  "next_eligible_at",
  "acknowledged_at",
  "terminal_at",
  "current_version",
  "current_fence",
  "current_attempt_id",
  "latest_response_summary",
  "latest_receipt_summary",
  "capabilities"
]);

const DELIVERY_AGGREGATE_SUMMARY_KEYS = new Set([
  "unit",
  "population",
  "observed_at",
  "pending_count",
  "active_count",
  "acknowledged_count",
  "dead_letter_count",
  "suppressed_count",
  "expired_count",
  "verified_receipt_count",
  "unknown_attempt_count",
  "distinct_receipt_summary"
]);

const CREATE_REPLAY_PROPOSAL_KEYS = new Set([
  "schema_version",
  "expected_delivery_version",
  "target_subscription_version",
  "target_endpoint_version",
  "wire_envelope_id",
  "strategy",
  "ordering_strategy",
  "requested_deadline_at",
  "consumer_event_key_sha256",
  "representation_profile_id",
  "representation_profile_version",
  "receiver_contract_id",
  "receiver_contract_version",
  "evidence_references",
  "reason_code"
]);

const REVIEW_PROPOSAL_KEYS = new Set([
  "schema_version",
  "expected_proposal_version",
  "candidate_sha256",
  "decision",
  "operation_proof_id",
  "evidence_references",
  "reason_code"
]);

const ADMIT_PROPOSAL_KEYS = new Set([
  "schema_version",
  "expected_proposal_version",
  "candidate_sha256",
  "review_id",
  "operation_proof_id",
  "reason_code"
]);

function parseEvidenceReferences(value: unknown, fieldPath: string): readonly string[] {
  if (!Array.isArray(value) || value.length > 16) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `${fieldPath} must be an array of at most 16 bounded references`,
      fieldErrors: [{ path: fieldPath, code: "INVALID_VALUE" }]
    });
  }
  return Object.freeze(
    value.map((item, idx) =>
      parseBoundedString(item, {
        fieldPath: `${fieldPath}[${idx}]`,
        minUtf8Bytes: 1,
        maxUtf8Bytes: 256,
        rejectControlChars: true
      })
    )
  );
}

export function parseDeliverySummary(
  value: unknown,
  fieldPath = "delivery"
): DeliverySummaryDto {
  const rec = assertPlainRecord(value, fieldPath);
  assertAllowedKeys(rec, DELIVERY_SUMMARY_KEYS, fieldPath);

  if (!isDeliveryState(rec.state)) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Invalid delivery state in ${fieldPath}.state`,
      fieldErrors: [{ path: `${fieldPath}.state`, code: "INVALID_VALUE" }]
    });
  }
  if (!isDeliveryExecutionBucket(rec.execution_bucket)) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Invalid execution_bucket in ${fieldPath}.execution_bucket`,
      fieldErrors: [{ path: `${fieldPath}.execution_bucket`, code: "INVALID_VALUE" }]
    });
  }

  let lastOutcomeClass: DeliveryOutcomeClass | null = null;
  if (rec.last_outcome_class !== null) {
    if (!isDeliveryOutcomeClass(rec.last_outcome_class)) {
      throw new ValidationDomainError({
        code: "INVALID_VALUE",
        message: `Invalid last_outcome_class in ${fieldPath}.last_outcome_class`,
        fieldErrors: [{ path: `${fieldPath}.last_outcome_class`, code: "INVALID_VALUE" }]
      });
    }
    lastOutcomeClass = rec.last_outcome_class;
  }

  let latestResponseSummary: DeliveryLatestResponseSummaryDto | null = null;
  if (rec.latest_response_summary !== null) {
    const respRec = assertPlainRecord(
      rec.latest_response_summary,
      `${fieldPath}.latest_response_summary`
    );
    assertAllowedKeys(respRec, LATEST_RESPONSE_KEYS, `${fieldPath}.latest_response_summary`);
    if (!isDeliveryOutcomeClass(respRec.outcome_class)) {
      throw new ValidationDomainError({
        code: "INVALID_VALUE",
        message: `Invalid outcome_class in ${fieldPath}.latest_response_summary`,
        fieldErrors: [{ path: `${fieldPath}.latest_response_summary.outcome_class`, code: "INVALID_VALUE" }]
      });
    }
    if (respRec.response_status !== null && !isValidHttpStatus(respRec.response_status)) {
      throw new ValidationDomainError({
        code: "INVALID_VALUE",
        message: `Invalid response_status in ${fieldPath}.latest_response_summary`,
        fieldErrors: [{ path: `${fieldPath}.latest_response_summary.response_status`, code: "INVALID_VALUE" }]
      });
    }
    latestResponseSummary = Object.freeze({
      attempt_id: parseAttemptId(
        respRec.attempt_id,
        `${fieldPath}.latest_response_summary.attempt_id`
      ),
      observed_at: parseCanonicalUtcTimestamp(
        respRec.observed_at,
        `${fieldPath}.latest_response_summary.observed_at`
      ),
      response_status: respRec.response_status,
      outcome_class: respRec.outcome_class,
      safe_error_code:
        respRec.safe_error_code === null
          ? null
          : parseSafeReasonCode(
              respRec.safe_error_code,
              `${fieldPath}.latest_response_summary.safe_error_code`
            )
    });
  }

  let latestReceiptSummary: DeliveryLatestReceiptSummaryDto | null = null;
  if (rec.latest_receipt_summary !== null) {
    const receiptRec = assertPlainRecord(
      rec.latest_receipt_summary,
      `${fieldPath}.latest_receipt_summary`
    );
    assertAllowedKeys(receiptRec, LATEST_RECEIPT_KEYS, `${fieldPath}.latest_receipt_summary`);
    if (!isReceiptVerificationState(receiptRec.verification_state)) {
      throw new ValidationDomainError({
        code: "INVALID_VALUE",
        message: `Invalid verification_state in ${fieldPath}.latest_receipt_summary`,
        fieldErrors: [
          { path: `${fieldPath}.latest_receipt_summary.verification_state`, code: "INVALID_VALUE" }
        ]
      });
    }
    latestReceiptSummary = Object.freeze({
      observation_id: parseReceiverReceiptObservationId(
        receiptRec.observation_id,
        `${fieldPath}.latest_receipt_summary.observation_id`
      ),
      verification_state: receiptRec.verification_state,
      observed_at: parseCanonicalUtcTimestamp(
        receiptRec.observed_at,
        `${fieldPath}.latest_receipt_summary.observed_at`
      ),
      committed_at: parseNullableUtcTimestamp(
        receiptRec.committed_at,
        `${fieldPath}.latest_receipt_summary.committed_at`
      )
    });
  }

  const deliveryGeneration = parseNonNegativeInt64String(
    rec.delivery_generation,
    `${fieldPath}.delivery_generation`
  );
  const isReplay = parseBooleanField(rec.is_replay, `${fieldPath}.is_replay`);
  const replayProposalId =
    rec.replay_proposal_id === null
      ? null
      : parseReplayProposalId(rec.replay_proposal_id, `${fieldPath}.replay_proposal_id`);

  if (deliveryGeneration === "0" && (isReplay || replayProposalId !== null)) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Original generation 0 cannot be marked replay in ${fieldPath}`,
      fieldErrors: [{ path: `${fieldPath}.delivery_generation`, code: "INVALID_VALUE" }]
    });
  }

  const capabilities =
    rec.capabilities !== undefined
      ? parseCapabilities(rec.capabilities, `${fieldPath}.capabilities`)
      : undefined;

  return Object.freeze({
    delivery_id: parseDeliveryId(rec.delivery_id, `${fieldPath}.delivery_id`),
    family_id: parseDeliveryFamilyId(rec.family_id, `${fieldPath}.family_id`),
    event_id: parseEventId(rec.event_id, `${fieldPath}.event_id`),
    delivery_generation: deliveryGeneration,
    is_replay: isReplay,
    replay_proposal_id: replayProposalId,
    subscription_id: parseSubscriptionId(rec.subscription_id, `${fieldPath}.subscription_id`),
    original_subscription_version: parsePositiveInt64String(
      rec.original_subscription_version,
      `${fieldPath}.original_subscription_version`
    ),
    dispatch_subscription_version: parsePositiveInt64String(
      rec.dispatch_subscription_version,
      `${fieldPath}.dispatch_subscription_version`
    ),
    endpoint_id: parseEndpointId(rec.endpoint_id, `${fieldPath}.endpoint_id`),
    endpoint_version: parsePositiveInt64String(
      rec.endpoint_version,
      `${fieldPath}.endpoint_version`
    ),
    wire_envelope_id: parseWireEnvelopeId(rec.wire_envelope_id, `${fieldPath}.wire_envelope_id`),
    representation_version: parsePositiveInt32(
      rec.representation_version,
      `${fieldPath}.representation_version`
    ),
    consumer_event_key_sha256: parseSha256Hex(
      rec.consumer_event_key_sha256,
      `${fieldPath}.consumer_event_key_sha256`
    ),
    state: rec.state,
    execution_bucket: rec.execution_bucket,
    blocking_reason:
      rec.blocking_reason === null
        ? null
        : parseSafeReasonCode(rec.blocking_reason, `${fieldPath}.blocking_reason`),
    last_outcome_class: lastOutcomeClass,
    attempt_count: parseBoundedInteger(rec.attempt_count, {
      fieldPath: `${fieldPath}.attempt_count`,
      min: 0,
      max: 1_000_000
    }),
    maximum_attempts: parseBoundedInteger(rec.maximum_attempts, {
      fieldPath: `${fieldPath}.maximum_attempts`,
      min: 1,
      max: 1_000_000
    }),
    prepared_attempt_count: parseBoundedInteger(rec.prepared_attempt_count, {
      fieldPath: `${fieldPath}.prepared_attempt_count`,
      min: 0,
      max: 1_000_000
    }),
    preparation_failure_count: parseBoundedInteger(rec.preparation_failure_count, {
      fieldPath: `${fieldPath}.preparation_failure_count`,
      min: 0,
      max: 1_000_000
    }),
    next_attempt_number: parsePositiveInt32(
      rec.next_attempt_number,
      `${fieldPath}.next_attempt_number`
    ),
    deadline_at: parseCanonicalUtcTimestamp(rec.deadline_at, `${fieldPath}.deadline_at`),
    next_eligible_at: parseCanonicalUtcTimestamp(
      rec.next_eligible_at,
      `${fieldPath}.next_eligible_at`
    ),
    acknowledged_at: parseNullableUtcTimestamp(rec.acknowledged_at, `${fieldPath}.acknowledged_at`),
    terminal_at: parseNullableUtcTimestamp(rec.terminal_at, `${fieldPath}.terminal_at`),
    current_version: parseInt64String(rec.current_version, `${fieldPath}.current_version`),
    current_fence: parseNonNegativeInt64String(rec.current_fence, `${fieldPath}.current_fence`),
    current_attempt_id:
      rec.current_attempt_id === null
        ? null
        : parseAttemptId(rec.current_attempt_id, `${fieldPath}.current_attempt_id`),
    latest_response_summary: latestResponseSummary,
    latest_receipt_summary: latestReceiptSummary,
    ...(capabilities !== undefined ? { capabilities } : {})
  });
}

export function parseDeliveryAggregateSummary(
  value: unknown,
  fieldPath = "delivery_summary"
): DeliveryAggregateSummaryDto {
  const rec = assertPlainRecord(value, fieldPath);
  assertAllowedKeys(rec, DELIVERY_AGGREGATE_SUMMARY_KEYS, fieldPath);

  if (rec.unit !== "delivery_generation") {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Expected unit="delivery_generation" at ${fieldPath}.unit`,
      fieldErrors: [{ path: `${fieldPath}.unit`, code: "INVALID_VALUE" }]
    });
  }
  if (!isDeliveryPopulation(rec.population)) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Invalid population at ${fieldPath}.population`,
      fieldErrors: [{ path: `${fieldPath}.population`, code: "INVALID_VALUE" }]
    });
  }

  let distinctSummary: DeliveryAggregateSummaryDto["distinct_receipt_summary"];
  if (rec.distinct_receipt_summary !== undefined) {
    const distRec = assertPlainRecord(
      rec.distinct_receipt_summary,
      `${fieldPath}.distinct_receipt_summary`
    );
    assertAllowedKeys(
      distRec,
      new Set(["grouped_by", "count", "grouping_note"]),
      `${fieldPath}.distinct_receipt_summary`
    );
    if (distRec.grouped_by !== "integration_consumer_scope") {
      throw new ValidationDomainError({
        code: "INVALID_VALUE",
        message: `Unsupported grouped_by in ${fieldPath}.distinct_receipt_summary`,
        fieldErrors: [
          { path: `${fieldPath}.distinct_receipt_summary.grouped_by`, code: "INVALID_VALUE" }
        ]
      });
    }
    distinctSummary = Object.freeze({
      grouped_by: "integration_consumer_scope",
      count: parseNonNegativeInt64String(
        distRec.count,
        `${fieldPath}.distinct_receipt_summary.count`
      ),
      grouping_note: parseBoundedString(distRec.grouping_note, {
        fieldPath: `${fieldPath}.distinct_receipt_summary.grouping_note`,
        minUtf8Bytes: 1,
        maxUtf8Bytes: 256,
        rejectControlChars: true
      })
    });
  }

  return Object.freeze({
    unit: "delivery_generation",
    population: rec.population,
    observed_at: parseCanonicalUtcTimestamp(rec.observed_at, `${fieldPath}.observed_at`),
    pending_count: parseNonNegativeInt64String(rec.pending_count, `${fieldPath}.pending_count`),
    active_count: parseNonNegativeInt64String(rec.active_count, `${fieldPath}.active_count`),
    acknowledged_count: parseNonNegativeInt64String(
      rec.acknowledged_count,
      `${fieldPath}.acknowledged_count`
    ),
    dead_letter_count: parseNonNegativeInt64String(
      rec.dead_letter_count,
      `${fieldPath}.dead_letter_count`
    ),
    suppressed_count: parseNonNegativeInt64String(
      rec.suppressed_count,
      `${fieldPath}.suppressed_count`
    ),
    expired_count: parseNonNegativeInt64String(rec.expired_count, `${fieldPath}.expired_count`),
    verified_receipt_count: parseNonNegativeInt64String(
      rec.verified_receipt_count,
      `${fieldPath}.verified_receipt_count`
    ),
    unknown_attempt_count: parseNonNegativeInt64String(
      rec.unknown_attempt_count,
      `${fieldPath}.unknown_attempt_count`
    ),
    ...(distinctSummary !== undefined ? { distinct_receipt_summary: distinctSummary } : {})
  });
}

export function parseCreateReplayProposalRequest(
  value: unknown,
  fieldPath = "body"
): CreateReplayProposalRequestDto {
  const rec = assertPlainRecord(value, fieldPath);
  assertAllowedKeys(rec, CREATE_REPLAY_PROPOSAL_KEYS, fieldPath);

  const schemaVersion = parseBoundedInteger(rec.schema_version, {
    fieldPath: `${fieldPath}.schema_version`,
    min: 1,
    max: 1
  });
  if (schemaVersion !== 1) {
    throw new ValidationDomainError({
      code: "UNSUPPORTED_SCHEMA_VERSION",
      message: `Unsupported replay proposal schema_version ${schemaVersion}`,
      fieldErrors: [{ path: `${fieldPath}.schema_version`, code: "UNSUPPORTED_SCHEMA_VERSION" }]
    });
  }
  if (!isReplayStrategy(rec.strategy)) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Invalid replay strategy in ${fieldPath}.strategy`,
      fieldErrors: [{ path: `${fieldPath}.strategy`, code: "INVALID_VALUE" }]
    });
  }
  if (!isReplayOrderingStrategy(rec.ordering_strategy)) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Invalid ordering_strategy in ${fieldPath}.ordering_strategy`,
      fieldErrors: [{ path: `${fieldPath}.ordering_strategy`, code: "INVALID_VALUE" }]
    });
  }

  const profileId =
    rec.representation_profile_id !== undefined
      ? parseRepresentationProfileId(
          rec.representation_profile_id,
          `${fieldPath}.representation_profile_id`
        )
      : undefined;
  const profileVersion =
    rec.representation_profile_version !== undefined
      ? parsePositiveInt64String(
          rec.representation_profile_version,
          `${fieldPath}.representation_profile_version`
        )
      : undefined;
  const receiverContractId =
    rec.receiver_contract_id !== undefined
      ? parseReceiverContractId(rec.receiver_contract_id, `${fieldPath}.receiver_contract_id`)
      : undefined;
  const receiverContractVersion =
    rec.receiver_contract_version !== undefined
      ? parsePositiveInt64String(
          rec.receiver_contract_version,
          `${fieldPath}.receiver_contract_version`
        )
      : undefined;

  if (rec.strategy === "replay_with_reviewed_representation") {
    if (
      profileId === undefined ||
      profileVersion === undefined ||
      receiverContractId === undefined ||
      receiverContractVersion === undefined
    ) {
      throw new ValidationDomainError({
        code: "INVALID_VALUE",
        message:
          "replay_with_reviewed_representation requires representation_profile_id, representation_profile_version, receiver_contract_id, and receiver_contract_version",
        fieldErrors: [{ path: `${fieldPath}.strategy`, code: "INVALID_VALUE" }]
      });
    }
  } else if (profileId !== undefined || profileVersion !== undefined) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: "replay_exact_original cannot specify representation_profile_id/version",
      fieldErrors: [{ path: `${fieldPath}.representation_profile_id`, code: "INVALID_VALUE" }]
    });
  }

  return Object.freeze({
    schema_version: 1,
    expected_delivery_version: parseInt64String(
      rec.expected_delivery_version,
      `${fieldPath}.expected_delivery_version`
    ),
    target_subscription_version: parsePositiveInt64String(
      rec.target_subscription_version,
      `${fieldPath}.target_subscription_version`
    ),
    target_endpoint_version: parsePositiveInt64String(
      rec.target_endpoint_version,
      `${fieldPath}.target_endpoint_version`
    ),
    wire_envelope_id: parseWireEnvelopeId(rec.wire_envelope_id, `${fieldPath}.wire_envelope_id`),
    strategy: rec.strategy,
    ordering_strategy: rec.ordering_strategy,
    requested_deadline_at: parseCanonicalUtcTimestamp(
      rec.requested_deadline_at,
      `${fieldPath}.requested_deadline_at`
    ),
    consumer_event_key_sha256: parseSha256Hex(
      rec.consumer_event_key_sha256,
      `${fieldPath}.consumer_event_key_sha256`
    ),
    ...(profileId !== undefined ? { representation_profile_id: profileId } : {}),
    ...(profileVersion !== undefined ? { representation_profile_version: profileVersion } : {}),
    ...(receiverContractId !== undefined ? { receiver_contract_id: receiverContractId } : {}),
    ...(receiverContractVersion !== undefined
      ? { receiver_contract_version: receiverContractVersion }
      : {}),
    evidence_references: parseEvidenceReferences(
      rec.evidence_references,
      `${fieldPath}.evidence_references`
    ),
    reason_code: parseSafeReasonCode(rec.reason_code, `${fieldPath}.reason_code`)
  });
}

export function parseReviewProposalRequest(
  value: unknown,
  fieldPath = "body"
): ReviewProposalRequestDto {
  const rec = assertPlainRecord(value, fieldPath);
  assertAllowedKeys(rec, REVIEW_PROPOSAL_KEYS, fieldPath);
  parseBoundedInteger(rec.schema_version, {
    fieldPath: `${fieldPath}.schema_version`,
    min: 1,
    max: 1
  });
  if (!isProposalReviewDecision(rec.decision)) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Invalid review decision in ${fieldPath}.decision`,
      fieldErrors: [{ path: `${fieldPath}.decision`, code: "INVALID_VALUE" }]
    });
  }
  return Object.freeze({
    schema_version: 1,
    expected_proposal_version: parseInt64String(
      rec.expected_proposal_version,
      `${fieldPath}.expected_proposal_version`
    ),
    candidate_sha256: parseSha256Hex(rec.candidate_sha256, `${fieldPath}.candidate_sha256`),
    decision: rec.decision,
    operation_proof_id: parseCanonicalUuid(
      rec.operation_proof_id,
      `${fieldPath}.operation_proof_id`
    ),
    evidence_references: parseEvidenceReferences(
      rec.evidence_references,
      `${fieldPath}.evidence_references`
    ),
    reason_code: parseSafeReasonCode(rec.reason_code, `${fieldPath}.reason_code`)
  });
}

export function parseAdmitProposalRequest(
  value: unknown,
  fieldPath = "body"
): AdmitProposalRequestDto {
  const rec = assertPlainRecord(value, fieldPath);
  assertAllowedKeys(rec, ADMIT_PROPOSAL_KEYS, fieldPath);
  parseBoundedInteger(rec.schema_version, {
    fieldPath: `${fieldPath}.schema_version`,
    min: 1,
    max: 1
  });
  const operationProofId =
    rec.operation_proof_id !== undefined
      ? parseCanonicalUuid(rec.operation_proof_id, `${fieldPath}.operation_proof_id`)
      : undefined;

  return Object.freeze({
    schema_version: 1,
    expected_proposal_version: parseInt64String(
      rec.expected_proposal_version,
      `${fieldPath}.expected_proposal_version`
    ),
    candidate_sha256: parseSha256Hex(rec.candidate_sha256, `${fieldPath}.candidate_sha256`),
    review_id: parseCanonicalUuid(rec.review_id, `${fieldPath}.review_id`),
    ...(operationProofId !== undefined ? { operation_proof_id: operationProofId } : {}),
    reason_code: parseSafeReasonCode(rec.reason_code, `${fieldPath}.reason_code`)
  });
}

export const DELIVERY_PROPOSAL_TYPE_GUARDS = {
  isLateObservationKind,
  isProposalState
};
