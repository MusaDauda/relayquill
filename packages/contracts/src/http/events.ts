import {
  type ActorKind,
  type ChannelKind,
  type DeliveryPopulation,
  EVENT_MAX_CONTENT_BYTES,
  EVENT_MAX_ENVELOPE_BYTES,
  type EventFanoutState,
  type EventState,
  type OutboxState,
  type ProducerScopeAction,
  ValidationDomainError,
  isActorKind,
  isChannelKind,
  isDeliveryPopulation,
  isEventFanoutState,
  isEventState,
  isOutboxState
} from "@relayquill/domain";
import {
  type CapabilityEntryDto,
  parseCapabilities
} from "./capabilities.js";
import {
  type ContentAvailabilityMetadataDto,
  type EventContentInputDto,
  type ParsedEventContentInput,
  parseContentAvailabilityMetadata,
  parseEventContentInput
} from "./content.js";
import { type AcceptedReceiptDto, parseAcceptedReceipt } from "./envelope.js";
import {
  type BrokerGenerationId,
  type BusinessKey,
  type CanonicalUtcTimestamp,
  type CommandReceiptId,
  type EventId,
  type EventTypeId,
  type EventTypeName,
  type Int64String,
  type NonNegativeInt64String,
  type OutboxId,
  type PositiveInt64String,
  type ProducerId,
  type ProducerNamespace,
  type PublicationObservationId,
  type Sha256Hex,
  assertAllowedKeys,
  assertPlainRecord,
  parseBooleanField,
  parseBoundedInteger,
  parseBrokerGenerationId,
  parseBusinessKey,
  parseCanonicalUtcTimestamp,
  parseCommandReceiptId,
  parseEventId,
  parseEventTypeId,
  parseEventTypeName,
  parseInt64String,
  parseNonNegativeInt64String,
  parseNullableUtcTimestamp,
  parseOptionalStrictUtcTimestamp,
  parseOutboxId,
  parsePositiveInt32,
  parsePositiveInt64String,
  parseProducerId,
  parseProducerNamespace,
  parsePublicationObservationId,
  parseSafeReasonCode,
  parseSha256Hex
} from "./values.js";

export interface PublicationAllowedEventDto {
  readonly event_type_id: EventTypeId;
  readonly event_type_name: EventTypeName;
  readonly allowed_schema_versions: readonly number[];
}

export interface PublicationBudgetsDto {
  readonly max_encoded_body_bytes: number;
  readonly max_decoded_content_bytes: number;
  readonly default_delivery_window_ms: PositiveInt64String;
  readonly max_delivery_window_ms: PositiveInt64String;
}

export interface PublicationContextDto {
  readonly actor_kind: ActorKind;
  readonly channel_enabled: boolean;
  readonly channel_kind: ChannelKind;
  readonly publication_channel_id: ProducerId | null;
  readonly namespace: ProducerNamespace | null;
  readonly scope_version: PositiveInt64String | null;
  readonly authority_epoch: NonNegativeInt64String;
  readonly allowed_actions: readonly ProducerScopeAction[];
  readonly allowed_events: readonly PublicationAllowedEventDto[];
  readonly budgets: PublicationBudgetsDto;
  readonly capabilities?: readonly CapabilityEntryDto[] | undefined;
}

export interface AdmitEventRequestDto {
  readonly schema_version: 1;
  readonly expected_publication_channel_id: ProducerId;
  readonly event_type_id: EventTypeId;
  readonly event_schema_version: number;
  readonly business_key: BusinessKey;
  readonly content: EventContentInputDto;
  readonly producer_event_time?: CanonicalUtcTimestamp | undefined;
  readonly deadline_at?: CanonicalUtcTimestamp | undefined;
}

export interface ParsedAdmitEventRequest {
  readonly schema_version: 1;
  readonly expected_publication_channel_id: ProducerId;
  readonly event_type_id: EventTypeId;
  readonly event_schema_version: number;
  readonly business_key: BusinessKey;
  readonly content: ParsedEventContentInput;
  readonly producer_event_time?: CanonicalUtcTimestamp | undefined;
  readonly deadline_at?: CanonicalUtcTimestamp | undefined;
}

export interface AppliedAdmissionDefaultsDto {
  readonly delivery_window_ms: PositiveInt64String;
  readonly deadline_at: CanonicalUtcTimestamp;
  readonly producer_event_time_present: boolean;
  readonly deadline_at_present: boolean;
}

export interface AcceptedEventProjectionDto {
  readonly event_id: EventId;
  readonly event_type_id: EventTypeId;
  readonly event_type?: EventTypeName | undefined;
  readonly event_schema_version: number;
  readonly publication_channel_id: ProducerId;
  readonly namespace: ProducerNamespace;
  readonly business_key: BusinessKey;
  readonly accepted_at: CanonicalUtcTimestamp;
  readonly project_event_sequence: PositiveInt64String;
  readonly topology_version: PositiveInt64String;
  readonly original_content_sha256: Sha256Hex;
  readonly original_content_byte_count: number;
  readonly deadline_at: CanonicalUtcTimestamp;
  readonly state_at_acceptance: EventState;
  readonly producer_event_time: CanonicalUtcTimestamp | null;
  readonly submitted_shape_sha256: Sha256Hex;
  readonly effective_request_sha256: Sha256Hex;
  readonly hash_schema_version: 1;
}

export interface AdmitEventResultDto {
  readonly receipt: AcceptedReceiptDto<"event">;
  readonly event: AcceptedEventProjectionDto;
  readonly applied_defaults: AppliedAdmissionDefaultsDto;
  readonly matched_existing: boolean;
  readonly current_observation?: {
    readonly current_version: Int64String;
    readonly current_state: EventState;
    readonly observed_at: CanonicalUtcTimestamp;
  } | undefined;
}

export interface ResolveEventRequestDto {
  readonly schema_version: 1;
  readonly business_key: BusinessKey;
  readonly submitted_shape_sha256?: Sha256Hex | undefined;
}

export interface ResolveEventResultDto {
  readonly receipt: AcceptedReceiptDto<"event">;
  readonly event: AcceptedEventProjectionDto;
  readonly applied_defaults: AppliedAdmissionDefaultsDto;
  readonly fingerprint_verified: boolean;
  readonly content_availability: ContentAvailabilityMetadataDto;
  readonly current_observation: {
    readonly current_version: Int64String;
    readonly current_state: EventState;
    readonly observed_at: CanonicalUtcTimestamp;
  };
}

export interface PublicationObservationRefDto {
  readonly observation_id: PublicationObservationId;
  readonly broker_generation_id: BrokerGenerationId;
  readonly stream_name: string;
  readonly stream_sequence: PositiveInt64String;
  readonly observed_at: CanonicalUtcTimestamp;
  readonly ack_duplicate: boolean;
}

export interface PublicationSummaryDto {
  readonly outbox_id: OutboxId;
  readonly current_publication_generation: PositiveInt64String;
  readonly state: OutboxState;
  readonly next_publish_at: CanonicalUtcTimestamp | null;
  readonly observation_state: "observed" | "not_observed";
  readonly first_observation: PublicationObservationRefDto | null;
  readonly latest_observation: PublicationObservationRefDto | null;
  readonly last_safe_error_code: string | null;
}

export interface FanoutSummaryDto {
  readonly event_id: EventId;
  readonly state: EventFanoutState;
  readonly project_event_sequence: PositiveInt64String;
  readonly topology_version: PositiveInt64String;
  readonly examined_count: NonNegativeInt64String;
  readonly matched_count: NonNegativeInt64String;
  readonly delivery_count: NonNegativeInt64String;
  readonly candidate_count: NonNegativeInt64String;
  readonly last_progress_at: CanonicalUtcTimestamp | null;
  readonly completed_at: CanonicalUtcTimestamp | null;
  readonly project_materialized_through_event_sequence: NonNegativeInt64String;
  readonly blocked_predecessor?: {
    readonly project_event_sequence: PositiveInt64String;
    readonly reason_code: string;
  } | null | undefined;
}

export interface DeliveryAggregateCountsDto {
  readonly unit: "delivery_generation";
  readonly population: DeliveryPopulation;
  readonly total_deliveries: NonNegativeInt64String;
  readonly pending_count: NonNegativeInt64String;
  readonly sending_count: NonNegativeInt64String;
  readonly http_acknowledged_count: NonNegativeInt64String;
  readonly dead_letter_count: NonNegativeInt64String;
  readonly suppressed_count: NonNegativeInt64String;
  readonly expired_count: NonNegativeInt64String;
  readonly verified_receipt_count: NonNegativeInt64String;
}

export interface EventListItemDto extends AcceptedEventProjectionDto {
  readonly current_version: Int64String;
  readonly current_state: EventState;
  readonly fanout_state: EventFanoutState;
}

export interface EventDetailDto extends AcceptedEventProjectionDto {
  readonly accepted_version: Int64String;
  readonly current_version: Int64String;
  readonly current_state: EventState;
  readonly observed_at: CanonicalUtcTimestamp;
  readonly fanout: FanoutSummaryDto;
  readonly publication: PublicationSummaryDto;
  readonly delivery_counts: {
    readonly original: DeliveryAggregateCountsDto;
    readonly replay: DeliveryAggregateCountsDto;
    readonly all: DeliveryAggregateCountsDto;
  };
  readonly content_availability: ContentAvailabilityMetadataDto;
  readonly capabilities: readonly CapabilityEntryDto[];
}

export interface EventHistoryEntryDto {
  readonly event_id: EventId;
  readonly event_sequence: PositiveInt64String;
  readonly event_kind: string;
  readonly event_schema_version: number;
  readonly recorded_at: CanonicalUtcTimestamp;
  readonly safe_facts: Readonly<Record<string, unknown>>;
  readonly causing_command_id: CommandReceiptId | null;
}

const ADMIT_EVENT_REQUEST_KEYS = new Set([
  "schema_version",
  "expected_publication_channel_id",
  "event_type_id",
  "event_schema_version",
  "business_key",
  "content",
  "producer_event_time",
  "deadline_at"
]);

const RESOLVE_EVENT_REQUEST_KEYS = new Set([
  "schema_version",
  "business_key",
  "submitted_shape_sha256"
]);

const APPLIED_DEFAULTS_KEYS = new Set([
  "delivery_window_ms",
  "deadline_at",
  "producer_event_time_present",
  "deadline_at_present"
]);

const ACCEPTED_EVENT_KEYS = new Set([
  "event_id",
  "event_type_id",
  "event_type",
  "event_schema_version",
  "publication_channel_id",
  "namespace",
  "business_key",
  "accepted_at",
  "project_event_sequence",
  "topology_version",
  "original_content_sha256",
  "original_content_byte_count",
  "deadline_at",
  "state_at_acceptance",
  "producer_event_time",
  "submitted_shape_sha256",
  "effective_request_sha256",
  "hash_schema_version"
]);

const PUBLICATION_OBS_REF_KEYS = new Set([
  "observation_id",
  "broker_generation_id",
  "stream_name",
  "stream_sequence",
  "observed_at",
  "ack_duplicate"
]);

const PUBLICATION_SUMMARY_KEYS = new Set([
  "outbox_id",
  "current_publication_generation",
  "state",
  "next_publish_at",
  "observation_state",
  "first_observation",
  "latest_observation",
  "last_safe_error_code"
]);

const FANOUT_SUMMARY_KEYS = new Set([
  "event_id",
  "state",
  "project_event_sequence",
  "topology_version",
  "examined_count",
  "matched_count",
  "delivery_count",
  "candidate_count",
  "last_progress_at",
  "completed_at",
  "project_materialized_through_event_sequence",
  "blocked_predecessor"
]);

const DELIVERY_AGGREGATE_COUNTS_KEYS = new Set([
  "unit",
  "population",
  "total_deliveries",
  "pending_count",
  "sending_count",
  "http_acknowledged_count",
  "dead_letter_count",
  "suppressed_count",
  "expired_count",
  "verified_receipt_count"
]);

const ADMIT_EVENT_RESULT_KEYS = new Set([
  "receipt",
  "event",
  "applied_defaults",
  "matched_existing",
  "current_observation"
]);

const CURRENT_OBSERVATION_KEYS = new Set([
  "current_version",
  "current_state",
  "observed_at"
]);

const EVENT_DETAIL_KEYS = new Set([
  ...ACCEPTED_EVENT_KEYS,
  "accepted_version",
  "current_version",
  "current_state",
  "observed_at",
  "fanout",
  "publication",
  "delivery_counts",
  "content_availability",
  "capabilities"
]);

const EVENT_HISTORY_ENTRY_KEYS = new Set([
  "event_id",
  "event_sequence",
  "event_kind",
  "event_schema_version",
  "recorded_at",
  "safe_facts",
  "causing_command_id"
]);

export function parseAdmitEventRequest(
  value: unknown,
  options?: { readonly maxDecodedContentBytes?: number | undefined; readonly fieldPath?: string | undefined }
): ParsedAdmitEventRequest {
  const fieldPath = options?.fieldPath ?? "body";
  const rec = assertPlainRecord(value, fieldPath);
  assertAllowedKeys(rec, ADMIT_EVENT_REQUEST_KEYS, fieldPath);

  const schemaVersion = parseBoundedInteger(rec.schema_version, {
    fieldPath: `${fieldPath}.schema_version`,
    min: 1,
    max: 1
  });
  if (schemaVersion !== 1) {
    throw new ValidationDomainError({
      code: "UNSUPPORTED_SCHEMA_VERSION",
      message: `Unsupported admit event schema_version ${schemaVersion}`,
      fieldErrors: [{ path: `${fieldPath}.schema_version`, code: "UNSUPPORTED_SCHEMA_VERSION" }]
    });
  }

  const expectedPublicationChannelId = parseProducerId(
    rec.expected_publication_channel_id,
    `${fieldPath}.expected_publication_channel_id`
  );
  const eventTypeId = parseEventTypeId(rec.event_type_id, `${fieldPath}.event_type_id`);
  const eventSchemaVersion = parsePositiveInt32(
    rec.event_schema_version,
    `${fieldPath}.event_schema_version`
  );
  const businessKey = parseBusinessKey(rec.business_key, `${fieldPath}.business_key`);
  const content = parseEventContentInput(rec.content, {
    fieldPath: `${fieldPath}.content`,
    maxDecodedBytes: options?.maxDecodedContentBytes ?? EVENT_MAX_CONTENT_BYTES
  });
  const producerEventTime = parseOptionalStrictUtcTimestamp(
    rec,
    "producer_event_time",
    fieldPath
  );
  const deadlineAt = parseOptionalStrictUtcTimestamp(rec, "deadline_at", fieldPath);

  return Object.freeze({
    schema_version: 1,
    expected_publication_channel_id: expectedPublicationChannelId,
    event_type_id: eventTypeId,
    event_schema_version: eventSchemaVersion,
    business_key: businessKey,
    content,
    ...(producerEventTime !== undefined ? { producer_event_time: producerEventTime } : {}),
    ...(deadlineAt !== undefined ? { deadline_at: deadlineAt } : {})
  });
}

export function parseResolveEventRequest(
  value: unknown,
  fieldPath = "body"
): ResolveEventRequestDto {
  const rec = assertPlainRecord(value, fieldPath);
  assertAllowedKeys(rec, RESOLVE_EVENT_REQUEST_KEYS, fieldPath);

  const schemaVersion = parseBoundedInteger(rec.schema_version, {
    fieldPath: `${fieldPath}.schema_version`,
    min: 1,
    max: 1
  });
  if (schemaVersion !== 1) {
    throw new ValidationDomainError({
      code: "UNSUPPORTED_SCHEMA_VERSION",
      message: `Unsupported resolve event schema_version ${schemaVersion}`,
      fieldErrors: [{ path: `${fieldPath}.schema_version`, code: "UNSUPPORTED_SCHEMA_VERSION" }]
    });
  }
  const businessKey = parseBusinessKey(rec.business_key, `${fieldPath}.business_key`);
  const submittedShapeSha256 =
    rec.submitted_shape_sha256 !== undefined
      ? parseSha256Hex(rec.submitted_shape_sha256, `${fieldPath}.submitted_shape_sha256`)
      : undefined;

  return Object.freeze({
    schema_version: 1,
    business_key: businessKey,
    ...(submittedShapeSha256 !== undefined
      ? { submitted_shape_sha256: submittedShapeSha256 }
      : {})
  });
}

export function parseAppliedAdmissionDefaults(
  value: unknown,
  fieldPath = "applied_defaults"
): AppliedAdmissionDefaultsDto {
  const rec = assertPlainRecord(value, fieldPath);
  assertAllowedKeys(rec, APPLIED_DEFAULTS_KEYS, fieldPath);
  return Object.freeze({
    delivery_window_ms: parsePositiveInt64String(
      rec.delivery_window_ms,
      `${fieldPath}.delivery_window_ms`
    ),
    deadline_at: parseCanonicalUtcTimestamp(rec.deadline_at, `${fieldPath}.deadline_at`),
    producer_event_time_present: parseBooleanField(
      rec.producer_event_time_present,
      `${fieldPath}.producer_event_time_present`
    ),
    deadline_at_present: parseBooleanField(
      rec.deadline_at_present,
      `${fieldPath}.deadline_at_present`
    )
  });
}

export function parseAcceptedEventProjection(
  value: unknown,
  fieldPath = "event"
): AcceptedEventProjectionDto {
  const rec = assertPlainRecord(value, fieldPath);
  assertAllowedKeys(rec, ACCEPTED_EVENT_KEYS, fieldPath);
  return parseAcceptedEventFields(rec, fieldPath);
}

function parseAcceptedEventFields(
  rec: Record<string, unknown>,
  fieldPath: string
): AcceptedEventProjectionDto {
  if (!isEventState(rec.state_at_acceptance)) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Invalid state_at_acceptance in ${fieldPath}`,
      fieldErrors: [{ path: `${fieldPath}.state_at_acceptance`, code: "INVALID_VALUE" }]
    });
  }
  const hashSchemaVersion = parseBoundedInteger(rec.hash_schema_version, {
    fieldPath: `${fieldPath}.hash_schema_version`,
    min: 1,
    max: 1
  });
  if (hashSchemaVersion !== 1) {
    throw new ValidationDomainError({
      code: "UNSUPPORTED_SCHEMA_VERSION",
      message: `Unsupported hash_schema_version ${hashSchemaVersion}`,
      fieldErrors: [{ path: `${fieldPath}.hash_schema_version`, code: "UNSUPPORTED_SCHEMA_VERSION" }]
    });
  }
  const eventType =
    rec.event_type !== undefined
      ? parseEventTypeName(rec.event_type, `${fieldPath}.event_type`)
      : undefined;

  return Object.freeze({
    event_id: parseEventId(rec.event_id, `${fieldPath}.event_id`),
    event_type_id: parseEventTypeId(rec.event_type_id, `${fieldPath}.event_type_id`),
    ...(eventType !== undefined ? { event_type: eventType } : {}),
    event_schema_version: parsePositiveInt32(
      rec.event_schema_version,
      `${fieldPath}.event_schema_version`
    ),
    publication_channel_id: parseProducerId(
      rec.publication_channel_id,
      `${fieldPath}.publication_channel_id`
    ),
    namespace: parseProducerNamespace(rec.namespace, `${fieldPath}.namespace`),
    business_key: parseBusinessKey(rec.business_key, `${fieldPath}.business_key`),
    accepted_at: parseCanonicalUtcTimestamp(rec.accepted_at, `${fieldPath}.accepted_at`),
    project_event_sequence: parsePositiveInt64String(
      rec.project_event_sequence,
      `${fieldPath}.project_event_sequence`
    ),
    topology_version: parsePositiveInt64String(
      rec.topology_version,
      `${fieldPath}.topology_version`
    ),
    original_content_sha256: parseSha256Hex(
      rec.original_content_sha256,
      `${fieldPath}.original_content_sha256`
    ),
    original_content_byte_count: parseBoundedInteger(rec.original_content_byte_count, {
      fieldPath: `${fieldPath}.original_content_byte_count`,
      min: 1,
      max: EVENT_MAX_CONTENT_BYTES
    }),
    deadline_at: parseCanonicalUtcTimestamp(rec.deadline_at, `${fieldPath}.deadline_at`),
    state_at_acceptance: rec.state_at_acceptance,
    producer_event_time: parseNullableUtcTimestamp(
      rec.producer_event_time,
      `${fieldPath}.producer_event_time`
    ),
    submitted_shape_sha256: parseSha256Hex(
      rec.submitted_shape_sha256,
      `${fieldPath}.submitted_shape_sha256`
    ),
    effective_request_sha256: parseSha256Hex(
      rec.effective_request_sha256,
      `${fieldPath}.effective_request_sha256`
    ),
    hash_schema_version: 1
  });
}

export function parsePublicationObservationRef(
  value: unknown,
  fieldPath = "observation"
): PublicationObservationRefDto {
  const rec = assertPlainRecord(value, fieldPath);
  assertAllowedKeys(rec, PUBLICATION_OBS_REF_KEYS, fieldPath);
  return Object.freeze({
    observation_id: parsePublicationObservationId(
      rec.observation_id,
      `${fieldPath}.observation_id`
    ),
    broker_generation_id: parseBrokerGenerationId(
      rec.broker_generation_id,
      `${fieldPath}.broker_generation_id`
    ),
    stream_name: parseSafeReasonCode(rec.stream_name, `${fieldPath}.stream_name`),
    stream_sequence: parsePositiveInt64String(
      rec.stream_sequence,
      `${fieldPath}.stream_sequence`
    ),
    observed_at: parseCanonicalUtcTimestamp(rec.observed_at, `${fieldPath}.observed_at`),
    ack_duplicate: parseBooleanField(rec.ack_duplicate, `${fieldPath}.ack_duplicate`)
  });
}

export function parsePublicationSummary(
  value: unknown,
  fieldPath = "publication"
): PublicationSummaryDto {
  const rec = assertPlainRecord(value, fieldPath);
  assertAllowedKeys(rec, PUBLICATION_SUMMARY_KEYS, fieldPath);

  if (!isOutboxState(rec.state)) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Invalid outbox state in ${fieldPath}.state`,
      fieldErrors: [{ path: `${fieldPath}.state`, code: "INVALID_VALUE" }]
    });
  }
  if (rec.observation_state !== "observed" && rec.observation_state !== "not_observed") {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Invalid observation_state in ${fieldPath}.observation_state`,
      fieldErrors: [{ path: `${fieldPath}.observation_state`, code: "INVALID_VALUE" }]
    });
  }

  const firstObservation =
    rec.first_observation === null
      ? null
      : parsePublicationObservationRef(rec.first_observation, `${fieldPath}.first_observation`);
  const latestObservation =
    rec.latest_observation === null
      ? null
      : parsePublicationObservationRef(rec.latest_observation, `${fieldPath}.latest_observation`);

  if (rec.observation_state === "not_observed" && (firstObservation !== null || latestObservation !== null)) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `not_observed publication cannot include observations in ${fieldPath}`,
      fieldErrors: [{ path: `${fieldPath}.observation_state`, code: "INVALID_VALUE" }]
    });
  }
  if (rec.observation_state === "observed" && firstObservation === null) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `observed publication requires first_observation in ${fieldPath}`,
      fieldErrors: [{ path: `${fieldPath}.first_observation`, code: "INVALID_VALUE" }]
    });
  }

  return Object.freeze({
    outbox_id: parseOutboxId(rec.outbox_id, `${fieldPath}.outbox_id`),
    current_publication_generation: parsePositiveInt64String(
      rec.current_publication_generation,
      `${fieldPath}.current_publication_generation`
    ),
    state: rec.state,
    next_publish_at: parseNullableUtcTimestamp(rec.next_publish_at, `${fieldPath}.next_publish_at`),
    observation_state: rec.observation_state,
    first_observation: firstObservation,
    latest_observation: latestObservation,
    last_safe_error_code:
      rec.last_safe_error_code === null
        ? null
        : parseSafeReasonCode(rec.last_safe_error_code, `${fieldPath}.last_safe_error_code`)
  });
}

export function parseFanoutSummary(value: unknown, fieldPath = "fanout"): FanoutSummaryDto {
  const rec = assertPlainRecord(value, fieldPath);
  assertAllowedKeys(rec, FANOUT_SUMMARY_KEYS, fieldPath);

  if (!isEventFanoutState(rec.state)) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Invalid fanout state in ${fieldPath}.state`,
      fieldErrors: [{ path: `${fieldPath}.state`, code: "INVALID_VALUE" }]
    });
  }

  let blockedPredecessor: FanoutSummaryDto["blocked_predecessor"];
  if (rec.blocked_predecessor !== undefined) {
    if (rec.blocked_predecessor === null) {
      blockedPredecessor = null;
    } else {
      const predRec = assertPlainRecord(
        rec.blocked_predecessor,
        `${fieldPath}.blocked_predecessor`
      );
      assertAllowedKeys(
        predRec,
        new Set(["project_event_sequence", "reason_code"]),
        `${fieldPath}.blocked_predecessor`
      );
      blockedPredecessor = Object.freeze({
        project_event_sequence: parsePositiveInt64String(
          predRec.project_event_sequence,
          `${fieldPath}.blocked_predecessor.project_event_sequence`
        ),
        reason_code: parseSafeReasonCode(
          predRec.reason_code,
          `${fieldPath}.blocked_predecessor.reason_code`
        )
      });
    }
  }

  return Object.freeze({
    event_id: parseEventId(rec.event_id, `${fieldPath}.event_id`),
    state: rec.state,
    project_event_sequence: parsePositiveInt64String(
      rec.project_event_sequence,
      `${fieldPath}.project_event_sequence`
    ),
    topology_version: parsePositiveInt64String(
      rec.topology_version,
      `${fieldPath}.topology_version`
    ),
    examined_count: parseNonNegativeInt64String(rec.examined_count, `${fieldPath}.examined_count`),
    matched_count: parseNonNegativeInt64String(rec.matched_count, `${fieldPath}.matched_count`),
    delivery_count: parseNonNegativeInt64String(rec.delivery_count, `${fieldPath}.delivery_count`),
    candidate_count: parseNonNegativeInt64String(
      rec.candidate_count,
      `${fieldPath}.candidate_count`
    ),
    last_progress_at: parseNullableUtcTimestamp(
      rec.last_progress_at,
      `${fieldPath}.last_progress_at`
    ),
    completed_at: parseNullableUtcTimestamp(rec.completed_at, `${fieldPath}.completed_at`),
    project_materialized_through_event_sequence: parseNonNegativeInt64String(
      rec.project_materialized_through_event_sequence,
      `${fieldPath}.project_materialized_through_event_sequence`
    ),
    ...(blockedPredecessor !== undefined ? { blocked_predecessor: blockedPredecessor } : {})
  });
}

export function parseDeliveryAggregateCounts(
  value: unknown,
  expectedPopulation?: DeliveryPopulation,
  fieldPath = "delivery_counts"
): DeliveryAggregateCountsDto {
  const rec = assertPlainRecord(value, fieldPath);
  assertAllowedKeys(rec, DELIVERY_AGGREGATE_COUNTS_KEYS, fieldPath);

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
  if (expectedPopulation !== undefined && rec.population !== expectedPopulation) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Expected population "${expectedPopulation}" at ${fieldPath}.population`,
      fieldErrors: [{ path: `${fieldPath}.population`, code: "INVALID_VALUE" }]
    });
  }

  return Object.freeze({
    unit: "delivery_generation",
    population: rec.population,
    total_deliveries: parseNonNegativeInt64String(
      rec.total_deliveries,
      `${fieldPath}.total_deliveries`
    ),
    pending_count: parseNonNegativeInt64String(rec.pending_count, `${fieldPath}.pending_count`),
    sending_count: parseNonNegativeInt64String(rec.sending_count, `${fieldPath}.sending_count`),
    http_acknowledged_count: parseNonNegativeInt64String(
      rec.http_acknowledged_count,
      `${fieldPath}.http_acknowledged_count`
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
    )
  });
}

export function parseAdmitEventResult(
  value: unknown,
  fieldPath = "data"
): AdmitEventResultDto {
  const rec = assertPlainRecord(value, fieldPath);
  assertAllowedKeys(rec, ADMIT_EVENT_RESULT_KEYS, fieldPath);

  const receipt = parseAcceptedReceipt(rec.receipt, "event", `${fieldPath}.receipt`);
  const event = parseAcceptedEventProjection(rec.event, `${fieldPath}.event`);
  const appliedDefaults = parseAppliedAdmissionDefaults(
    rec.applied_defaults,
    `${fieldPath}.applied_defaults`
  );
  const matchedExisting = parseBooleanField(
    rec.matched_existing,
    `${fieldPath}.matched_existing`
  );

  let currentObservation: AdmitEventResultDto["current_observation"];
  if (rec.current_observation !== undefined) {
    const obsRec = assertPlainRecord(rec.current_observation, `${fieldPath}.current_observation`);
    assertAllowedKeys(obsRec, CURRENT_OBSERVATION_KEYS, `${fieldPath}.current_observation`);
    if (!isEventState(obsRec.current_state)) {
      throw new ValidationDomainError({
        code: "INVALID_VALUE",
        message: `Invalid current_state in ${fieldPath}.current_observation`,
        fieldErrors: [{ path: `${fieldPath}.current_observation.current_state`, code: "INVALID_VALUE" }]
      });
    }
    currentObservation = Object.freeze({
      current_version: parseInt64String(
        obsRec.current_version,
        `${fieldPath}.current_observation.current_version`
      ),
      current_state: obsRec.current_state,
      observed_at: parseCanonicalUtcTimestamp(
        obsRec.observed_at,
        `${fieldPath}.current_observation.observed_at`
      )
    });
  }

  return Object.freeze({
    receipt,
    event,
    applied_defaults: appliedDefaults,
    matched_existing: matchedExisting,
    ...(currentObservation !== undefined ? { current_observation: currentObservation } : {})
  });
}

export function parseEventDetail(value: unknown, fieldPath = "event"): EventDetailDto {
  const rec = assertPlainRecord(value, fieldPath);
  assertAllowedKeys(rec, EVENT_DETAIL_KEYS, fieldPath);
  const accepted = parseAcceptedEventFields(rec, fieldPath);

  if (!isEventState(rec.current_state)) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Invalid current_state in ${fieldPath}`,
      fieldErrors: [{ path: `${fieldPath}.current_state`, code: "INVALID_VALUE" }]
    });
  }
  const countsRec = assertPlainRecord(rec.delivery_counts, `${fieldPath}.delivery_counts`);
  assertAllowedKeys(
    countsRec,
    new Set(["original", "replay", "all"]),
    `${fieldPath}.delivery_counts`
  );

  return Object.freeze({
    ...accepted,
    accepted_version: parseInt64String(rec.accepted_version, `${fieldPath}.accepted_version`),
    current_version: parseInt64String(rec.current_version, `${fieldPath}.current_version`),
    current_state: rec.current_state,
    observed_at: parseCanonicalUtcTimestamp(rec.observed_at, `${fieldPath}.observed_at`),
    fanout: parseFanoutSummary(rec.fanout, `${fieldPath}.fanout`),
    publication: parsePublicationSummary(rec.publication, `${fieldPath}.publication`),
    delivery_counts: Object.freeze({
      original: parseDeliveryAggregateCounts(
        countsRec.original,
        "original",
        `${fieldPath}.delivery_counts.original`
      ),
      replay: parseDeliveryAggregateCounts(
        countsRec.replay,
        "replay",
        `${fieldPath}.delivery_counts.replay`
      ),
      all: parseDeliveryAggregateCounts(
        countsRec.all,
        "all",
        `${fieldPath}.delivery_counts.all`
      )
    }),
    content_availability: parseContentAvailabilityMetadata(
      rec.content_availability,
      `${fieldPath}.content_availability`
    ),
    capabilities: parseCapabilities(rec.capabilities, `${fieldPath}.capabilities`)
  });
}

export function parseEventHistoryEntry(
  value: unknown,
  fieldPath = "history_entry"
): EventHistoryEntryDto {
  const rec = assertPlainRecord(value, fieldPath);
  assertAllowedKeys(rec, EVENT_HISTORY_ENTRY_KEYS, fieldPath);

  const safeFacts = assertPlainRecord(rec.safe_facts, `${fieldPath}.safe_facts`);
  return Object.freeze({
    event_id: parseEventId(rec.event_id, `${fieldPath}.event_id`),
    event_sequence: parsePositiveInt64String(rec.event_sequence, `${fieldPath}.event_sequence`),
    event_kind: parseSafeReasonCode(rec.event_kind, `${fieldPath}.event_kind`),
    event_schema_version: parsePositiveInt32(
      rec.event_schema_version,
      `${fieldPath}.event_schema_version`
    ),
    recorded_at: parseCanonicalUtcTimestamp(rec.recorded_at, `${fieldPath}.recorded_at`),
    safe_facts: Object.freeze({ ...safeFacts }),
    causing_command_id:
      rec.causing_command_id === null
        ? null
        : parseCommandReceiptId(rec.causing_command_id, `${fieldPath}.causing_command_id`)
  });
}

export const EVENT_ADMISSION_MAX_BODY_BYTES = EVENT_MAX_ENVELOPE_BYTES;
export const EVENT_DEFAULT_ACTOR_KIND_CHECK = { isActorKind, isChannelKind };
