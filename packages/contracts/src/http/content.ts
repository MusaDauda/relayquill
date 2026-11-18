import {
  type ContentAvailability,
  type ContentRetentionState,
  type ContentView,
  EVENT_MAX_CONTENT_BYTES,
  EVENT_MAX_ENVELOPE_BYTES,
  ValidationDomainError,
  isContentAvailability,
  isContentRetentionState,
  isContentView
} from "@relayquill/domain";
import {
  type Base64String,
  type CanonicalUtcTimestamp,
  type PositiveInt64String,
  type RepresentationProfileId,
  type Sha256Hex,
  type WireEnvelopeId,
  assertAllowedKeys,
  assertPlainRecord,
  parseBoundedInteger,
  parseCanonicalUtcTimestamp,
  parsePositiveInt32,
  parsePositiveInt64String,
  parseRepresentationProfileId,
  parseSafeReasonCode,
  parseSha256Hex,
  parseStrictBase64,
  parseWireEnvelopeId,
  sha256Hex
} from "./values.js";

export const DERIVED_MAX_CONTENT_BYTES = 98_304 as const;
export const DELIVERY_REQUEST_CONTENT_MAX_ENCODED_BYTES = 1_048_576 as const;
export const EVENT_CONTENT_MEDIA_TYPE = "application/json" as const;
export const EVENT_CONTENT_ENCODING = "base64" as const;

export interface EventContentInputDto {
  readonly media_type: typeof EVENT_CONTENT_MEDIA_TYPE;
  readonly encoding: typeof EVENT_CONTENT_ENCODING;
  readonly data: Base64String;
  readonly sha256?: Sha256Hex | undefined;
}

export interface ParsedEventContentInput {
  readonly media_type: typeof EVENT_CONTENT_MEDIA_TYPE;
  readonly encoding: typeof EVENT_CONTENT_ENCODING;
  readonly data: Base64String;
  readonly bytes: Uint8Array;
  readonly byte_count: number;
  readonly sha256: Sha256Hex;
}

export interface ContentAvailabilityMetadataDto {
  readonly view: ContentView;
  readonly availability: ContentAvailability;
  readonly media_type: typeof EVENT_CONTENT_MEDIA_TYPE;
  readonly byte_count: number | null;
  readonly sha256: Sha256Hex | null;
  readonly representation_version?: number | undefined;
  readonly reason_code?: string | null | undefined;
}

export interface EventContentDto {
  readonly view: ContentView;
  readonly availability: "available";
  readonly representation_version?: number | undefined;
  readonly media_type: typeof EVENT_CONTENT_MEDIA_TYPE;
  readonly encoding: typeof EVENT_CONTENT_ENCODING;
  readonly byte_count: number;
  readonly sha256: Sha256Hex;
  readonly data: Base64String;
}

export interface DeliveryRequestContentDto {
  readonly representation_version: number;
  readonly wire_envelope_id: WireEnvelopeId;
  readonly media_type: typeof EVENT_CONTENT_MEDIA_TYPE;
  readonly encoding: typeof EVENT_CONTENT_ENCODING;
  readonly byte_count: number;
  readonly sha256: Sha256Hex;
  readonly data: Base64String;
  readonly availability: "available";
}

export interface EventRepresentationSummaryDto {
  readonly wire_envelope_id: WireEnvelopeId;
  readonly representation_version: number;
  readonly profile_id: RepresentationProfileId | null;
  readonly profile_version: PositiveInt64String | null;
  readonly target_schema_version: number | null;
  readonly source_content_sha256: Sha256Hex;
  readonly derived_content_sha256: Sha256Hex | null;
  readonly body_sha256: Sha256Hex;
  readonly byte_count: number;
  readonly availability: ContentAvailability;
  readonly retention_state: ContentRetentionState;
  readonly created_at: CanonicalUtcTimestamp;
}

const CONTENT_INPUT_KEYS = new Set(["media_type", "encoding", "data", "sha256"]);
const CONTENT_AVAILABILITY_KEYS = new Set([
  "view",
  "availability",
  "media_type",
  "byte_count",
  "sha256",
  "representation_version",
  "reason_code"
]);
const EVENT_CONTENT_DTO_KEYS = new Set([
  "view",
  "availability",
  "representation_version",
  "media_type",
  "encoding",
  "byte_count",
  "sha256",
  "data"
]);
const DELIVERY_REQUEST_CONTENT_KEYS = new Set([
  "representation_version",
  "wire_envelope_id",
  "media_type",
  "encoding",
  "byte_count",
  "sha256",
  "data",
  "availability"
]);
const REPRESENTATION_SUMMARY_KEYS = new Set([
  "wire_envelope_id",
  "representation_version",
  "profile_id",
  "profile_version",
  "target_schema_version",
  "source_content_sha256",
  "derived_content_sha256",
  "body_sha256",
  "byte_count",
  "availability",
  "retention_state",
  "created_at"
]);

export function parseEventContentInput(
  value: unknown,
  options?: {
    readonly fieldPath?: string | undefined;
    readonly maxDecodedBytes?: number | undefined;
  }
): ParsedEventContentInput {
  const fieldPath = options?.fieldPath ?? "content";
  const maxDecodedBytes = options?.maxDecodedBytes ?? EVENT_MAX_CONTENT_BYTES;
  const rec = assertPlainRecord(value, fieldPath);
  assertAllowedKeys(rec, CONTENT_INPUT_KEYS, fieldPath);

  if (rec.media_type !== EVENT_CONTENT_MEDIA_TYPE) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Unsupported media_type for ${fieldPath}.media_type`,
      fieldErrors: [{ path: `${fieldPath}.media_type`, code: "INVALID_VALUE" }]
    });
  }
  if (rec.encoding !== EVENT_CONTENT_ENCODING) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Unsupported encoding for ${fieldPath}.encoding`,
      fieldErrors: [{ path: `${fieldPath}.encoding`, code: "INVALID_VALUE" }]
    });
  }

  const decoded = parseStrictBase64(rec.data, `${fieldPath}.data`, {
    minDecodedBytes: 1,
    maxDecodedBytes
  });
  const computedSha256 = sha256Hex(decoded.bytes);

  if (rec.sha256 !== undefined) {
    const declaredSha256 = parseSha256Hex(rec.sha256, `${fieldPath}.sha256`);
    if (declaredSha256 !== computedSha256) {
      throw new ValidationDomainError({
        code: "INVALID_HASH",
        message: `Declared sha256 does not match decoded bytes for ${fieldPath}.sha256`,
        fieldErrors: [{ path: `${fieldPath}.sha256`, code: "INVALID_HASH" }]
      });
    }
  }

  return Object.freeze({
    media_type: EVENT_CONTENT_MEDIA_TYPE,
    encoding: EVENT_CONTENT_ENCODING,
    data: decoded.encoded,
    bytes: decoded.bytes,
    byte_count: decoded.bytes.length,
    sha256: computedSha256
  });
}

export function parseContentAvailabilityMetadata(
  value: unknown,
  fieldPath = "content_availability"
): ContentAvailabilityMetadataDto {
  const rec = assertPlainRecord(value, fieldPath);
  assertAllowedKeys(rec, CONTENT_AVAILABILITY_KEYS, fieldPath);

  if (!isContentView(rec.view)) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Invalid content view for ${fieldPath}.view`,
      fieldErrors: [{ path: `${fieldPath}.view`, code: "INVALID_VALUE" }]
    });
  }
  if (!isContentAvailability(rec.availability)) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Invalid content availability for ${fieldPath}.availability`,
      fieldErrors: [{ path: `${fieldPath}.availability`, code: "INVALID_VALUE" }]
    });
  }
  if (rec.media_type !== EVENT_CONTENT_MEDIA_TYPE) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Invalid media_type for ${fieldPath}.media_type`,
      fieldErrors: [{ path: `${fieldPath}.media_type`, code: "INVALID_VALUE" }]
    });
  }

  const representationVersion =
    rec.representation_version !== undefined
      ? parsePositiveInt32(rec.representation_version, `${fieldPath}.representation_version`)
      : undefined;
  if (rec.view === "derived" && representationVersion === 1) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Derived content view is invalid for representation_version 1 in ${fieldPath}`,
      fieldErrors: [{ path: `${fieldPath}.view`, code: "INVALID_VALUE" }]
    });
  }

  const maxBytes = rec.view === "wire" ? EVENT_MAX_ENVELOPE_BYTES : EVENT_MAX_CONTENT_BYTES;
  const byteCount =
    rec.byte_count === null
      ? null
      : parseBoundedInteger(rec.byte_count, {
          fieldPath: `${fieldPath}.byte_count`,
          min: 1,
          max: maxBytes
        });
  const sha256 =
    rec.sha256 === null ? null : parseSha256Hex(rec.sha256, `${fieldPath}.sha256`);

  let reasonCode: string | null | undefined;
  if (rec.reason_code !== undefined) {
    reasonCode =
      rec.reason_code === null
        ? null
        : parseSafeReasonCode(rec.reason_code, `${fieldPath}.reason_code`);
  }

  return Object.freeze({
    view: rec.view,
    availability: rec.availability,
    media_type: EVENT_CONTENT_MEDIA_TYPE,
    byte_count: byteCount,
    sha256,
    ...(representationVersion !== undefined ? { representation_version: representationVersion } : {}),
    ...(reasonCode !== undefined ? { reason_code: reasonCode } : {})
  });
}

export function parseEventContentDto(
  value: unknown,
  fieldPath = "content"
): EventContentDto {
  const rec = assertPlainRecord(value, fieldPath);
  assertAllowedKeys(rec, EVENT_CONTENT_DTO_KEYS, fieldPath);

  if (!isContentView(rec.view)) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Invalid content view for ${fieldPath}.view`,
      fieldErrors: [{ path: `${fieldPath}.view`, code: "INVALID_VALUE" }]
    });
  }
  if (rec.availability !== "available") {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Expected availability="available" for ${fieldPath}.availability`,
      fieldErrors: [{ path: `${fieldPath}.availability`, code: "INVALID_VALUE" }]
    });
  }
  if (rec.media_type !== EVENT_CONTENT_MEDIA_TYPE) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Invalid media_type for ${fieldPath}.media_type`,
      fieldErrors: [{ path: `${fieldPath}.media_type`, code: "INVALID_VALUE" }]
    });
  }
  if (rec.encoding !== EVENT_CONTENT_ENCODING) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Invalid encoding for ${fieldPath}.encoding`,
      fieldErrors: [{ path: `${fieldPath}.encoding`, code: "INVALID_VALUE" }]
    });
  }

  const representationVersion =
    rec.representation_version !== undefined
      ? parsePositiveInt32(rec.representation_version, `${fieldPath}.representation_version`)
      : undefined;
  if (rec.view === "derived" && representationVersion === 1) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Derived view is invalid for representation_version 1 in ${fieldPath}`,
      fieldErrors: [{ path: `${fieldPath}.view`, code: "INVALID_VALUE" }]
    });
  }

  const maxDecodedBytes =
    rec.view === "wire"
      ? EVENT_MAX_ENVELOPE_BYTES
      : rec.view === "derived"
        ? DERIVED_MAX_CONTENT_BYTES
        : EVENT_MAX_CONTENT_BYTES;
  const decoded = parseStrictBase64(rec.data, `${fieldPath}.data`, {
    minDecodedBytes: 1,
    maxDecodedBytes
  });
  const byteCount = parseBoundedInteger(rec.byte_count, {
    fieldPath: `${fieldPath}.byte_count`,
    min: 1,
    max: maxDecodedBytes
  });
  if (byteCount !== decoded.bytes.length) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `byte_count (${byteCount}) does not match decoded bytes (${decoded.bytes.length}) in ${fieldPath}`,
      fieldErrors: [{ path: `${fieldPath}.byte_count`, code: "INVALID_VALUE" }]
    });
  }
  const declaredSha256 = parseSha256Hex(rec.sha256, `${fieldPath}.sha256`);
  const actualSha256 = sha256Hex(decoded.bytes);
  if (declaredSha256 !== actualSha256) {
    throw new ValidationDomainError({
      code: "INVALID_HASH",
      message: `sha256 mismatch in ${fieldPath}`,
      fieldErrors: [{ path: `${fieldPath}.sha256`, code: "INVALID_HASH" }]
    });
  }

  return Object.freeze({
    view: rec.view,
    availability: "available",
    ...(representationVersion !== undefined ? { representation_version: representationVersion } : {}),
    media_type: EVENT_CONTENT_MEDIA_TYPE,
    encoding: EVENT_CONTENT_ENCODING,
    byte_count: byteCount,
    sha256: declaredSha256,
    data: decoded.encoded
  });
}

export function parseDeliveryRequestContentDto(
  value: unknown,
  fieldPath = "request_content"
): DeliveryRequestContentDto {
  const rec = assertPlainRecord(value, fieldPath);
  assertAllowedKeys(rec, DELIVERY_REQUEST_CONTENT_KEYS, fieldPath);

  const representationVersion = parsePositiveInt32(
    rec.representation_version,
    `${fieldPath}.representation_version`
  );
  const wireEnvelopeId = parseWireEnvelopeId(
    rec.wire_envelope_id,
    `${fieldPath}.wire_envelope_id`
  );
  if (rec.media_type !== EVENT_CONTENT_MEDIA_TYPE) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Invalid media_type for ${fieldPath}.media_type`,
      fieldErrors: [{ path: `${fieldPath}.media_type`, code: "INVALID_VALUE" }]
    });
  }
  if (rec.encoding !== EVENT_CONTENT_ENCODING) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Invalid encoding for ${fieldPath}.encoding`,
      fieldErrors: [{ path: `${fieldPath}.encoding`, code: "INVALID_VALUE" }]
    });
  }
  if (rec.availability !== "available") {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Expected availability="available" for ${fieldPath}.availability`,
      fieldErrors: [{ path: `${fieldPath}.availability`, code: "INVALID_VALUE" }]
    });
  }
  const decoded = parseStrictBase64(rec.data, `${fieldPath}.data`, {
    minDecodedBytes: 1,
    maxDecodedBytes: EVENT_MAX_ENVELOPE_BYTES
  });
  const byteCount = parseBoundedInteger(rec.byte_count, {
    fieldPath: `${fieldPath}.byte_count`,
    min: 1,
    max: EVENT_MAX_ENVELOPE_BYTES
  });
  if (byteCount !== decoded.bytes.length) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `byte_count mismatch in ${fieldPath}`,
      fieldErrors: [{ path: `${fieldPath}.byte_count`, code: "INVALID_VALUE" }]
    });
  }
  const declaredSha256 = parseSha256Hex(rec.sha256, `${fieldPath}.sha256`);
  if (declaredSha256 !== sha256Hex(decoded.bytes)) {
    throw new ValidationDomainError({
      code: "INVALID_HASH",
      message: `sha256 mismatch in ${fieldPath}`,
      fieldErrors: [{ path: `${fieldPath}.sha256`, code: "INVALID_HASH" }]
    });
  }

  return Object.freeze({
    representation_version: representationVersion,
    wire_envelope_id: wireEnvelopeId,
    media_type: EVENT_CONTENT_MEDIA_TYPE,
    encoding: EVENT_CONTENT_ENCODING,
    byte_count: byteCount,
    sha256: declaredSha256,
    data: decoded.encoded,
    availability: "available"
  });
}

export function parseEventRepresentationSummary(
  value: unknown,
  fieldPath = "representation"
): EventRepresentationSummaryDto {
  const rec = assertPlainRecord(value, fieldPath);
  assertAllowedKeys(rec, REPRESENTATION_SUMMARY_KEYS, fieldPath);

  const wireEnvelopeId = parseWireEnvelopeId(
    rec.wire_envelope_id,
    `${fieldPath}.wire_envelope_id`
  );
  const representationVersion = parsePositiveInt32(
    rec.representation_version,
    `${fieldPath}.representation_version`
  );
  const profileId =
    rec.profile_id === null
      ? null
      : parseRepresentationProfileId(rec.profile_id, `${fieldPath}.profile_id`);
  const profileVersion =
    rec.profile_version === null
      ? null
      : parsePositiveInt64String(rec.profile_version, `${fieldPath}.profile_version`);
  const targetSchemaVersion =
    rec.target_schema_version === null
      ? null
      : parsePositiveInt32(rec.target_schema_version, `${fieldPath}.target_schema_version`);

  if (representationVersion === 1) {
    if (profileId !== null || profileVersion !== null || targetSchemaVersion !== null) {
      throw new ValidationDomainError({
        code: "INVALID_VALUE",
        message: "Representation version 1 cannot specify profile_id, profile_version, or target_schema_version",
        fieldErrors: [{ path: `${fieldPath}.representation_version`, code: "INVALID_VALUE" }]
      });
    }
  } else if (profileId === null || profileVersion === null || targetSchemaVersion === null) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: "Derived representation version >= 2 requires profile_id, profile_version, and target_schema_version",
      fieldErrors: [{ path: `${fieldPath}.profile_id`, code: "INVALID_VALUE" }]
    });
  }

  if (!isContentAvailability(rec.availability)) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Invalid availability for ${fieldPath}.availability`,
      fieldErrors: [{ path: `${fieldPath}.availability`, code: "INVALID_VALUE" }]
    });
  }
  if (!isContentRetentionState(rec.retention_state)) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Invalid retention_state for ${fieldPath}.retention_state`,
      fieldErrors: [{ path: `${fieldPath}.retention_state`, code: "INVALID_VALUE" }]
    });
  }

  return Object.freeze({
    wire_envelope_id: wireEnvelopeId,
    representation_version: representationVersion,
    profile_id: profileId,
    profile_version: profileVersion,
    target_schema_version: targetSchemaVersion,
    source_content_sha256: parseSha256Hex(
      rec.source_content_sha256,
      `${fieldPath}.source_content_sha256`
    ),
    derived_content_sha256:
      rec.derived_content_sha256 === null
        ? null
        : parseSha256Hex(rec.derived_content_sha256, `${fieldPath}.derived_content_sha256`),
    body_sha256: parseSha256Hex(rec.body_sha256, `${fieldPath}.body_sha256`),
    byte_count: parseBoundedInteger(rec.byte_count, {
      fieldPath: `${fieldPath}.byte_count`,
      min: 1,
      max: EVENT_MAX_ENVELOPE_BYTES
    }),
    availability: rec.availability,
    retention_state: rec.retention_state,
    created_at: parseCanonicalUtcTimestamp(rec.created_at, `${fieldPath}.created_at`)
  });
}
