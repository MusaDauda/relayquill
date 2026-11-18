import {
  type AttemptState,
  type DeliveryOutcomeClass,
  type ExternalAttemptOutcome,
  ValidationDomainError,
  isAttemptState,
  isDeliveryOutcomeClass,
  isExternalAttemptOutcome,
  isValidHttpStatus
} from "@relayquill/domain";
import {
  type AttemptId,
  type CanonicalUtcTimestamp,
  type ControlEpoch,
  type DeliveryId,
  type EndpointId,
  type NonNegativeInt64String,
  type PositiveInt64String,
  type RuntimeInstanceId,
  type Sha256Hex,
  assertAllowedKeys,
  assertPlainRecord,
  parseAttemptId,
  parseBoundedInteger,
  parseCanonicalUtcTimestamp,
  parseControlEpoch,
  parseDeliveryId,
  parseEndpointId,
  parseNonNegativeInt64String,
  parseNullableUtcTimestamp,
  parsePositiveInt32,
  parsePositiveInt64String,
  parseRuntimeInstanceId,
  parseSafeReasonCode,
  parseSha256Hex
} from "./values.js";

export interface AttemptOwnerReferenceDto {
  readonly worker_instance_id: RuntimeInstanceId;
}

export interface AttemptSummaryDto {
  readonly attempt_id: AttemptId;
  readonly delivery_id: DeliveryId;
  readonly attempt_number: number;
  readonly prepared_at: CanonicalUtcTimestamp;
  readonly send_started_at: CanonicalUtcTimestamp | null;
  readonly finished_at: CanonicalUtcTimestamp | null;
  readonly claim_expires_at: CanonicalUtcTimestamp;
  readonly request_deadline_at: CanonicalUtcTimestamp;
  readonly state: AttemptState;
  readonly control_epoch: ControlEpoch;
  readonly fencing_token: NonNegativeInt64String;
  readonly external_outcome: ExternalAttemptOutcome;
  readonly response_status: number | null;
  readonly outcome_class: DeliveryOutcomeClass | null;
  readonly safe_error_code: string | null;
  readonly endpoint_id: EndpointId;
  readonly endpoint_version: PositiveInt64String;
  readonly signing_policy_version: PositiveInt64String;
  readonly wire_body_sha256: Sha256Hex;
  readonly response_body_sha256: Sha256Hex | null;
  readonly response_byte_count: number | null;
  readonly owner_reference?: AttemptOwnerReferenceDto | undefined;
}

const ATTEMPT_SUMMARY_KEYS = new Set([
  "attempt_id",
  "delivery_id",
  "attempt_number",
  "prepared_at",
  "send_started_at",
  "finished_at",
  "claim_expires_at",
  "request_deadline_at",
  "state",
  "control_epoch",
  "fencing_token",
  "external_outcome",
  "response_status",
  "outcome_class",
  "safe_error_code",
  "endpoint_id",
  "endpoint_version",
  "signing_policy_version",
  "wire_body_sha256",
  "response_body_sha256",
  "response_byte_count",
  "owner_reference"
]);

export function deriveExternalAttemptOutcome(input: {
  readonly state: AttemptState;
  readonly send_started_at: CanonicalUtcTimestamp | null;
  readonly response_status: number | null;
}): ExternalAttemptOutcome {
  if (
    input.state === "prepared" ||
    input.state === "failed_before_send" ||
    input.state === "deferred_before_send"
  ) {
    return "not_started";
  }
  if (input.state === "abandoned") {
    return input.send_started_at === null ? "not_started" : "unknown";
  }
  if (input.state === "send_started" || input.state === "transport_unknown") {
    return "unknown";
  }
  if (input.response_status === null) {
    return "unavailable";
  }
  if (input.response_status >= 200 && input.response_status <= 299) {
    return "acknowledged";
  }
  return "observed_non_success";
}

export function parseAttemptSummary(value: unknown, fieldPath = "attempt"): AttemptSummaryDto {
  const rec = assertPlainRecord(value, fieldPath);
  assertAllowedKeys(rec, ATTEMPT_SUMMARY_KEYS, fieldPath);

  if (!isAttemptState(rec.state)) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Invalid attempt state in ${fieldPath}.state`,
      fieldErrors: [{ path: `${fieldPath}.state`, code: "INVALID_VALUE" }]
    });
  }
  if (!isExternalAttemptOutcome(rec.external_outcome)) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Invalid external_outcome in ${fieldPath}.external_outcome`,
      fieldErrors: [{ path: `${fieldPath}.external_outcome`, code: "INVALID_VALUE" }]
    });
  }

  let responseStatus: number | null = null;
  if (rec.response_status !== null) {
    if (!isValidHttpStatus(rec.response_status)) {
      throw new ValidationDomainError({
        code: "INVALID_VALUE",
        message: `HTTP response_status must be null or integer in 100..599 at ${fieldPath}.response_status`,
        fieldErrors: [{ path: `${fieldPath}.response_status`, code: "INVALID_VALUE" }]
      });
    }
    responseStatus = rec.response_status;
  }

  const sendStartedAt = parseNullableUtcTimestamp(
    rec.send_started_at,
    `${fieldPath}.send_started_at`
  );

  if (rec.external_outcome === "acknowledged" && (responseStatus === null || responseStatus < 200 || responseStatus > 299)) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Cannot report external_outcome="acknowledged" without observed 2xx response_status in ${fieldPath}`,
      fieldErrors: [{ path: `${fieldPath}.external_outcome`, code: "INVALID_VALUE" }]
    });
  }
  if (
    (rec.state === "failed_before_send" || rec.state === "deferred_before_send") &&
    sendStartedAt !== null
  ) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Unstarted attempt state "${rec.state}" cannot set send_started_at in ${fieldPath}`,
      fieldErrors: [{ path: `${fieldPath}.send_started_at`, code: "INVALID_VALUE" }]
    });
  }

  let outcomeClass: DeliveryOutcomeClass | null = null;
  if (rec.outcome_class !== null) {
    if (!isDeliveryOutcomeClass(rec.outcome_class)) {
      throw new ValidationDomainError({
        code: "INVALID_VALUE",
        message: `Invalid outcome_class in ${fieldPath}.outcome_class`,
        fieldErrors: [{ path: `${fieldPath}.outcome_class`, code: "INVALID_VALUE" }]
      });
    }
    outcomeClass = rec.outcome_class;
  }

  let ownerReference: AttemptOwnerReferenceDto | undefined;
  if (rec.owner_reference !== undefined) {
    const ownerRec = assertPlainRecord(rec.owner_reference, `${fieldPath}.owner_reference`);
    assertAllowedKeys(
      ownerRec,
      new Set(["worker_instance_id"]),
      `${fieldPath}.owner_reference`
    );
    ownerReference = Object.freeze({
      worker_instance_id: parseRuntimeInstanceId(
        ownerRec.worker_instance_id,
        `${fieldPath}.owner_reference.worker_instance_id`
      )
    });
  }

  return Object.freeze({
    attempt_id: parseAttemptId(rec.attempt_id, `${fieldPath}.attempt_id`),
    delivery_id: parseDeliveryId(rec.delivery_id, `${fieldPath}.delivery_id`),
    attempt_number: parsePositiveInt32(rec.attempt_number, `${fieldPath}.attempt_number`),
    prepared_at: parseCanonicalUtcTimestamp(rec.prepared_at, `${fieldPath}.prepared_at`),
    send_started_at: sendStartedAt,
    finished_at: parseNullableUtcTimestamp(rec.finished_at, `${fieldPath}.finished_at`),
    claim_expires_at: parseCanonicalUtcTimestamp(
      rec.claim_expires_at,
      `${fieldPath}.claim_expires_at`
    ),
    request_deadline_at: parseCanonicalUtcTimestamp(
      rec.request_deadline_at,
      `${fieldPath}.request_deadline_at`
    ),
    state: rec.state,
    control_epoch: parseControlEpoch(rec.control_epoch, `${fieldPath}.control_epoch`),
    fencing_token: parseNonNegativeInt64String(rec.fencing_token, `${fieldPath}.fencing_token`),
    external_outcome: rec.external_outcome,
    response_status: responseStatus,
    outcome_class: outcomeClass,
    safe_error_code:
      rec.safe_error_code === null
        ? null
        : parseSafeReasonCode(rec.safe_error_code, `${fieldPath}.safe_error_code`),
    endpoint_id: parseEndpointId(rec.endpoint_id, `${fieldPath}.endpoint_id`),
    endpoint_version: parsePositiveInt64String(
      rec.endpoint_version,
      `${fieldPath}.endpoint_version`
    ),
    signing_policy_version: parsePositiveInt64String(
      rec.signing_policy_version,
      `${fieldPath}.signing_policy_version`
    ),
    wire_body_sha256: parseSha256Hex(rec.wire_body_sha256, `${fieldPath}.wire_body_sha256`),
    response_body_sha256:
      rec.response_body_sha256 === null
        ? null
        : parseSha256Hex(rec.response_body_sha256, `${fieldPath}.response_body_sha256`),
    response_byte_count:
      rec.response_byte_count === null
        ? null
        : parseBoundedInteger(rec.response_byte_count, {
            fieldPath: `${fieldPath}.response_byte_count`,
            min: 0,
            max: 1_048_576
          }),
    ...(ownerReference !== undefined ? { owner_reference: ownerReference } : {})
  });
}
