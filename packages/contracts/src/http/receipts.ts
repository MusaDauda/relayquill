import {
  type ReceiptProfile,
  type ReceiptVerificationState,
  ValidationDomainError,
  isReceiptProfile,
  isReceiptVerificationState
} from "@relayquill/domain";
import {
  type AttemptId,
  type CanonicalUtcTimestamp,
  type CanonicalUuid,
  type DeliveryId,
  type EventId,
  type KeyId,
  type PositiveInt64String,
  type ProjectId,
  type ReceiverContractId,
  type ReceiverReceiptObservationId,
  type Sha256Hex,
  assertAllowedKeys,
  assertPlainRecord,
  parseAttemptId,
  parseBoundedString,
  parseCanonicalUtcTimestamp,
  parseCanonicalUuid,
  parseDeliveryId,
  parseEventId,
  parseKeyId,
  parseNullableUtcTimestamp,
  parsePositiveInt64String,
  parseProjectId,
  parseReceiverContractId,
  parseReceiverReceiptObservationId,
  parseSafeReasonCode,
  parseSha256Hex
} from "./values.js";

export interface AllowlistedReceiptFactsDto {
  readonly receipt_version: 1;
  readonly project_id: ProjectId;
  readonly event_id: EventId;
  readonly consumer_event_key: Sha256Hex;
  readonly original_facts_sha256: Sha256Hex;
  readonly receipt_id: CanonicalUuid;
  readonly business_status: "committed";
  readonly committed_at: CanonicalUtcTimestamp;
  readonly delivery_attempt_id: AttemptId;
  readonly key_id: KeyId;
}

export interface ReceiverReceiptObservationDto {
  readonly observation_id: ReceiverReceiptObservationId;
  readonly delivery_id: DeliveryId;
  readonly attempt_id: AttemptId | null;
  readonly receipt_reference: string;
  readonly verification_state: ReceiptVerificationState;
  readonly verification_profile_version: ReceiptProfile;
  readonly receiver_contract_id: ReceiverContractId;
  readonly receiver_contract_version: PositiveInt64String;
  readonly receipt_facts_sha256: Sha256Hex;
  readonly observed_at: CanonicalUtcTimestamp;
  readonly committed_at: CanonicalUtcTimestamp | null;
  readonly key_id: KeyId | null;
  readonly consumer_contract_scope?: string | undefined;
  readonly source_kind?: string | undefined;
  readonly safe_receipt_facts?: AllowlistedReceiptFactsDto | undefined;
}

const RECEIPT_OBSERVATION_KEYS = new Set([
  "observation_id",
  "delivery_id",
  "attempt_id",
  "receipt_reference",
  "verification_state",
  "verification_profile_version",
  "receiver_contract_id",
  "receiver_contract_version",
  "receipt_facts_sha256",
  "observed_at",
  "committed_at",
  "key_id",
  "consumer_contract_scope",
  "source_kind",
  "safe_receipt_facts"
]);

const ALLOWLISTED_RECEIPT_FACTS_KEYS = new Set([
  "receipt_version",
  "project_id",
  "event_id",
  "consumer_event_key",
  "original_facts_sha256",
  "receipt_id",
  "business_status",
  "committed_at",
  "delivery_attempt_id",
  "key_id"
]);

export function parseAllowlistedReceiptFacts(
  value: unknown,
  fieldPath = "safe_receipt_facts"
): AllowlistedReceiptFactsDto {
  const rec = assertPlainRecord(value, fieldPath);
  assertAllowedKeys(rec, ALLOWLISTED_RECEIPT_FACTS_KEYS, fieldPath);

  if (rec.receipt_version !== 1) {
    throw new ValidationDomainError({
      code: "UNSUPPORTED_SCHEMA_VERSION",
      message: `Unsupported receipt_version in ${fieldPath}`,
      fieldErrors: [{ path: `${fieldPath}.receipt_version`, code: "UNSUPPORTED_SCHEMA_VERSION" }]
    });
  }
  if (rec.business_status !== "committed") {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Expected business_status="committed" in ${fieldPath}`,
      fieldErrors: [{ path: `${fieldPath}.business_status`, code: "INVALID_VALUE" }]
    });
  }

  return Object.freeze({
    receipt_version: 1,
    project_id: parseProjectId(rec.project_id, `${fieldPath}.project_id`),
    event_id: parseEventId(rec.event_id, `${fieldPath}.event_id`),
    consumer_event_key: parseSha256Hex(
      rec.consumer_event_key,
      `${fieldPath}.consumer_event_key`
    ),
    original_facts_sha256: parseSha256Hex(
      rec.original_facts_sha256,
      `${fieldPath}.original_facts_sha256`
    ),
    receipt_id: parseCanonicalUuid(rec.receipt_id, `${fieldPath}.receipt_id`),
    business_status: "committed",
    committed_at: parseCanonicalUtcTimestamp(rec.committed_at, `${fieldPath}.committed_at`),
    delivery_attempt_id: parseAttemptId(
      rec.delivery_attempt_id,
      `${fieldPath}.delivery_attempt_id`
    ),
    key_id: parseKeyId(rec.key_id, `${fieldPath}.key_id`)
  });
}

export function parseReceiverReceiptObservation(
  value: unknown,
  fieldPath = "receipt_observation"
): ReceiverReceiptObservationDto {
  const rec = assertPlainRecord(value, fieldPath);
  assertAllowedKeys(rec, RECEIPT_OBSERVATION_KEYS, fieldPath);

  if (!isReceiptVerificationState(rec.verification_state)) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Invalid verification_state in ${fieldPath}.verification_state`,
      fieldErrors: [{ path: `${fieldPath}.verification_state`, code: "INVALID_VALUE" }]
    });
  }
  if (!isReceiptProfile(rec.verification_profile_version)) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Invalid verification_profile_version in ${fieldPath}.verification_profile_version`,
      fieldErrors: [{ path: `${fieldPath}.verification_profile_version`, code: "INVALID_VALUE" }]
    });
  }

  const attemptId =
    rec.attempt_id === null ? null : parseAttemptId(rec.attempt_id, `${fieldPath}.attempt_id`);
  const keyId = rec.key_id === null ? null : parseKeyId(rec.key_id, `${fieldPath}.key_id`);
  const consumerContractScope =
    rec.consumer_contract_scope !== undefined
      ? parseBoundedString(rec.consumer_contract_scope, {
          fieldPath: `${fieldPath}.consumer_contract_scope`,
          minUtf8Bytes: 1,
          maxUtf8Bytes: 128,
          rejectControlChars: true
        })
      : undefined;
  const sourceKind =
    rec.source_kind !== undefined
      ? parseSafeReasonCode(rec.source_kind, `${fieldPath}.source_kind`)
      : undefined;
  const safeReceiptFacts =
    rec.safe_receipt_facts !== undefined
      ? parseAllowlistedReceiptFacts(rec.safe_receipt_facts, `${fieldPath}.safe_receipt_facts`)
      : undefined;

  return Object.freeze({
    observation_id: parseReceiverReceiptObservationId(
      rec.observation_id,
      `${fieldPath}.observation_id`
    ),
    delivery_id: parseDeliveryId(rec.delivery_id, `${fieldPath}.delivery_id`),
    attempt_id: attemptId,
    receipt_reference: parseBoundedString(rec.receipt_reference, {
      fieldPath: `${fieldPath}.receipt_reference`,
      minUtf8Bytes: 1,
      maxUtf8Bytes: 256,
      rejectControlChars: true
    }),
    verification_state: rec.verification_state,
    verification_profile_version: rec.verification_profile_version,
    receiver_contract_id: parseReceiverContractId(
      rec.receiver_contract_id,
      `${fieldPath}.receiver_contract_id`
    ),
    receiver_contract_version: parsePositiveInt64String(
      rec.receiver_contract_version,
      `${fieldPath}.receiver_contract_version`
    ),
    receipt_facts_sha256: parseSha256Hex(
      rec.receipt_facts_sha256,
      `${fieldPath}.receipt_facts_sha256`
    ),
    observed_at: parseCanonicalUtcTimestamp(rec.observed_at, `${fieldPath}.observed_at`),
    committed_at: parseNullableUtcTimestamp(rec.committed_at, `${fieldPath}.committed_at`),
    key_id: keyId,
    ...(consumerContractScope !== undefined
      ? { consumer_contract_scope: consumerContractScope }
      : {}),
    ...(sourceKind !== undefined ? { source_kind: sourceKind } : {}),
    ...(safeReceiptFacts !== undefined ? { safe_receipt_facts: safeReceiptFacts } : {})
  });
}
