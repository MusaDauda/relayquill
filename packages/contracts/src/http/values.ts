import {
  type AttemptId,
  type BrokerGenerationId,
  type BusinessKey,
  type CanonicalUtcTimestamp,
  type CanonicalUuid,
  type CommandReceiptId,
  type ControlEpoch,
  type DeliveryFamilyId,
  type DeliveryId,
  type EndpointId,
  type EndpointVerificationIntentId,
  type EventId,
  type EventTypeId,
  type EventTypeName,
  type IdempotencyKey,
  INT64_MAX,
  INT64_MIN,
  type Int64String,
  type KeyId,
  type LateObservationId,
  type NonNegativeInt64String,
  type OrderingDomainId,
  type OrderingKeyId,
  type OutboxId,
  type ParsedUtcTimestamp,
  type PositiveInt64String,
  type PrincipalId,
  type ProducerId,
  type ProducerNamespace,
  type ProjectId,
  type PublicationObservationId,
  type ReceiverContractId,
  type ReceiverReceiptObservationId,
  type ReplayProposalId,
  type ReplayReviewId,
  type RepresentationProfileId,
  type RuntimeInstanceId,
  type Sha256Hex,
  type SigningKeyVersionId,
  type SigningPolicyId,
  type SubscriptionId,
  type TenantId,
  type WatchLeaseId,
  type WireEnvelopeId,
  ValidationDomainError,
  computeUtf8ByteLength,
  formatInt64,
  formatUtcTimestamp,
  hasLoneSurrogate,
  isBusinessKey,
  isCanonicalUtcTimestamp,
  isCanonicalUuid,
  isEventTypeName,
  isIdempotencyKey,
  isInt64String,
  isKeyId,
  isNonNegativeInt64String,
  isPositiveInt64String,
  isProducerNamespace,
  isSha256Hex,
  normalizeCanonicalUuid,
  parseAttemptId,
  parseBrokerGenerationId,
  parseBusinessKey,
  parseCanonicalUuid,
  parseCommandReceiptId,
  parseControlEpoch,
  parseDeliveryFamilyId,
  parseDeliveryId,
  parseEndpointId,
  parseEndpointVerificationIntentId,
  parseEventId,
  parseEventTypeId,
  parseEventTypeName,
  parseIdempotencyKey,
  parseInt64BigInt,
  parseInt64String,
  parseKeyId,
  parseLateObservationId,
  parseNonNegativeInt64BigInt,
  parseNonNegativeInt64String,
  parseOrderingDomainId,
  parseOrderingKeyId,
  parseOutboxId,
  parsePositiveInt64BigInt,
  parsePositiveInt64String,
  parsePrincipalId,
  parseProducerId,
  parseProducerNamespace,
  parseProjectId,
  parsePublicationObservationId,
  parseReceiverContractId,
  parseReceiverReceiptObservationId,
  parseReplayProposalId,
  parseReplayReviewId,
  parseRepresentationProfileId,
  parseRuntimeInstanceId,
  parseSha256Hex,
  parseSigningKeyVersionId,
  parseSigningPolicyId,
  parseSubscriptionId,
  parseTenantId,
  parseUtcTimestamp,
  parseWatchLeaseId,
  parseWireEnvelopeId
} from "@relayquill/domain";
import {
  type Base64String,
  type Base64UrlString,
  type StrictJsonParseOptions,
  type StrictJsonValue,
  assertAllowedKeys,
  assertPlainRecord,
  bytesToLowerHex,
  constantTimeEqual,
  decodeBase64Strict,
  decodeBase64UrlStrict,
  decodeUtf8BytesStrict,
  encodeBase64,
  encodeBase64Url,
  encodeDomainLengthPrefixed,
  encodeUtf8Bytes,
  hmacSha256Digest,
  isStrictBase64,
  isStrictBase64Url,
  parseStrictJsonObject,
  parseStrictJsonValue,
  sha256Digest,
  sha256Hex,
  sha256HexToBytes,
  sha256Utf8Hex
} from "../internal/primitives.js";

export {
  type AttemptId,
  type Base64String,
  type Base64UrlString,
  type BrokerGenerationId,
  type BusinessKey,
  type CanonicalUtcTimestamp,
  type CanonicalUuid,
  type CommandReceiptId,
  type ControlEpoch,
  type DeliveryFamilyId,
  type DeliveryId,
  type EndpointId,
  type EndpointVerificationIntentId,
  type EventId,
  type EventTypeId,
  type EventTypeName,
  type IdempotencyKey,
  INT64_MAX,
  INT64_MIN,
  type Int64String,
  type KeyId,
  type LateObservationId,
  type NonNegativeInt64String,
  type OrderingDomainId,
  type OrderingKeyId,
  type OutboxId,
  type ParsedUtcTimestamp,
  type PositiveInt64String,
  type PrincipalId,
  type ProducerId,
  type ProducerNamespace,
  type ProjectId,
  type PublicationObservationId,
  type ReceiverContractId,
  type ReceiverReceiptObservationId,
  type ReplayProposalId,
  type ReplayReviewId,
  type RepresentationProfileId,
  type RuntimeInstanceId,
  type Sha256Hex,
  type SigningKeyVersionId,
  type SigningPolicyId,
  type StrictJsonParseOptions,
  type StrictJsonValue,
  type SubscriptionId,
  type TenantId,
  type WatchLeaseId,
  type WireEnvelopeId,
  assertAllowedKeys,
  assertPlainRecord,
  bytesToLowerHex,
  computeUtf8ByteLength,
  constantTimeEqual,
  decodeBase64Strict,
  decodeBase64UrlStrict,
  decodeUtf8BytesStrict,
  encodeBase64,
  encodeBase64Url,
  encodeDomainLengthPrefixed,
  encodeUtf8Bytes,
  formatInt64,
  formatUtcTimestamp,
  hasLoneSurrogate,
  hmacSha256Digest,
  isBusinessKey,
  isCanonicalUtcTimestamp,
  isCanonicalUuid,
  isEventTypeName,
  isIdempotencyKey,
  isInt64String,
  isKeyId,
  isNonNegativeInt64String,
  isPositiveInt64String,
  isProducerNamespace,
  isSha256Hex,
  isStrictBase64,
  isStrictBase64Url,
  normalizeCanonicalUuid,
  parseAttemptId,
  parseBrokerGenerationId,
  parseBusinessKey,
  parseCanonicalUuid,
  parseCommandReceiptId,
  parseControlEpoch,
  parseDeliveryFamilyId,
  parseDeliveryId,
  parseEndpointId,
  parseEndpointVerificationIntentId,
  parseEventId,
  parseEventTypeId,
  parseEventTypeName,
  parseIdempotencyKey,
  parseInt64BigInt,
  parseInt64String,
  parseKeyId,
  parseLateObservationId,
  parseNonNegativeInt64BigInt,
  parseNonNegativeInt64String,
  parseOrderingDomainId,
  parseOrderingKeyId,
  parseOutboxId,
  parsePositiveInt64BigInt,
  parsePositiveInt64String,
  parsePrincipalId,
  parseProducerId,
  parseProducerNamespace,
  parseProjectId,
  parsePublicationObservationId,
  parseReceiverContractId,
  parseReceiverReceiptObservationId,
  parseReplayProposalId,
  parseReplayReviewId,
  parseRepresentationProfileId,
  parseRuntimeInstanceId,
  parseSha256Hex,
  parseSigningKeyVersionId,
  parseSigningPolicyId,
  parseStrictJsonObject,
  parseStrictJsonValue,
  parseSubscriptionId,
  parseTenantId,
  parseUtcTimestamp,
  parseWatchLeaseId,
  parseWireEnvelopeId,
  sha256Digest,
  sha256Hex,
  sha256HexToBytes,
  sha256Utf8Hex
};

export const INT32_MAX = 2_147_483_647 as const;
export const DEFAULT_PAGE_LIMIT = 25 as const;
export const MAX_PAGE_LIMIT = 100 as const;

const SAFE_IDENTIFIER_REGEX = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const SAFE_REASON_CODE_REGEX = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;

export function parseCanonicalUtcTimestamp(
  value: unknown,
  fieldPath = "timestamp"
): CanonicalUtcTimestamp {
  return parseUtcTimestamp(value, fieldPath).canonical;
}

export function parseNullableUtcTimestamp(
  value: unknown,
  fieldPath = "timestamp"
): CanonicalUtcTimestamp | null {
  if (value === null) {
    return null;
  }
  return parseCanonicalUtcTimestamp(value, fieldPath);
}

export function parseOptionalStrictUtcTimestamp(
  record: Record<string, unknown>,
  key: string,
  parentPath = "body"
): CanonicalUtcTimestamp | undefined {
  if (!Object.prototype.hasOwnProperty.call(record, key)) {
    return undefined;
  }
  const value = record[key];
  if (value === undefined) {
    return undefined;
  }
  if (value === null) {
    throw new ValidationDomainError({
      code: "INVALID_TIMESTAMP",
      message: `Field ${parentPath}.${key} cannot be explicitly null; omit when absent`,
      fieldErrors: [{ path: `${parentPath}.${key}`, code: "INVALID_TIMESTAMP" }]
    });
  }
  return parseCanonicalUtcTimestamp(value, `${parentPath}.${key}`);
}

export function parseBoundedInteger(
  value: unknown,
  options: {
    readonly fieldPath: string;
    readonly min: number;
    readonly max: number;
  }
): number {
  if (typeof value !== "number" || !Number.isInteger(value) || !Number.isSafeInteger(value)) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Expected integer for ${options.fieldPath}`,
      fieldErrors: [{ path: options.fieldPath, code: "INVALID_VALUE" }]
    });
  }
  if (value < options.min || value > options.max) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Integer for ${options.fieldPath} must be within [${options.min}, ${options.max}]`,
      fieldErrors: [{ path: options.fieldPath, code: "INVALID_VALUE" }]
    });
  }
  return value;
}

export function parsePositiveInt32(value: unknown, fieldPath = "value"): number {
  return parseBoundedInteger(value, { fieldPath, min: 1, max: INT32_MAX });
}

export function parseNonNegativeInt32(value: unknown, fieldPath = "value"): number {
  return parseBoundedInteger(value, { fieldPath, min: 0, max: INT32_MAX });
}

export function parseSchemaVersion(value: unknown, fieldPath = "schema_version"): number {
  return parsePositiveInt32(value, fieldPath);
}

export function parsePageLimit(value: unknown, fieldPath = "limit"): number {
  if (value === undefined) {
    return DEFAULT_PAGE_LIMIT;
  }
  return parseBoundedInteger(value, { fieldPath, min: 1, max: MAX_PAGE_LIMIT });
}

export function parseStrictBase64(
  value: unknown,
  fieldPath = "data",
  options?: { readonly maxDecodedBytes?: number | undefined; readonly minDecodedBytes?: number | undefined }
): { readonly encoded: Base64String; readonly bytes: Uint8Array } {
  const bytes = decodeBase64Strict(value, fieldPath, {
    maxDecodedBytes: options?.maxDecodedBytes
  });
  if (options?.minDecodedBytes !== undefined && bytes.length < options.minDecodedBytes) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Decoded base64 length ${bytes.length} is below minimum ${options.minDecodedBytes} for ${fieldPath}`,
      fieldErrors: [{ path: fieldPath, code: "INVALID_VALUE" }]
    });
  }
  return Object.freeze({
    encoded: value as Base64String,
    bytes
  });
}

export function parseStrictBase64Url(
  value: unknown,
  fieldPath = "token",
  options?: {
    readonly exactByteLength?: number | undefined;
    readonly maxDecodedBytes?: number | undefined;
  }
): { readonly encoded: Base64UrlString; readonly bytes: Uint8Array } {
  const bytes = decodeBase64UrlStrict(value, fieldPath, options);
  return Object.freeze({
    encoded: value as Base64UrlString,
    bytes
  });
}

export function parseBooleanField(value: unknown, fieldPath = "flag"): boolean {
  if (typeof value !== "boolean") {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Expected boolean for ${fieldPath}`,
      fieldErrors: [{ path: fieldPath, code: "INVALID_VALUE" }]
    });
  }
  return value;
}

export function parseBoundedString(
  value: unknown,
  options: {
    readonly fieldPath: string;
    readonly minUtf8Bytes?: number | undefined;
    readonly maxUtf8Bytes: number;
    readonly rejectControlChars?: boolean | undefined;
  }
): string {
  if (typeof value !== "string" || hasLoneSurrogate(value)) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Invalid string for ${options.fieldPath}`,
      fieldErrors: [{ path: options.fieldPath, code: "INVALID_VALUE" }]
    });
  }
  if (options.rejectControlChars) {
    for (let i = 0; i < value.length; i += 1) {
      const code = value.charCodeAt(i);
      if (code < 0x20 || code === 0x7f) {
        throw new ValidationDomainError({
          code: "INVALID_VALUE",
          message: `Control characters are not allowed in ${options.fieldPath}`,
          fieldErrors: [{ path: options.fieldPath, code: "INVALID_VALUE" }]
        });
      }
    }
  }
  const byteLen = computeUtf8ByteLength(value);
  const minBytes = options.minUtf8Bytes ?? 1;
  if (byteLen < minBytes || byteLen > options.maxUtf8Bytes) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `String UTF-8 length ${byteLen} out of bounds [${minBytes}, ${options.maxUtf8Bytes}] for ${options.fieldPath}`,
      fieldErrors: [{ path: options.fieldPath, code: "INVALID_VALUE" }]
    });
  }
  return value;
}

export function parseSafeCorrelationId(value: unknown, fieldPath = "request_id"): string {
  if (typeof value !== "string" || !SAFE_IDENTIFIER_REGEX.test(value)) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Invalid correlation identifier for ${fieldPath}`,
      fieldErrors: [{ path: fieldPath, code: "INVALID_VALUE" }]
    });
  }
  return value;
}

export function parseSafeReasonCode(value: unknown, fieldPath = "reason_code"): string {
  if (typeof value !== "string" || !SAFE_REASON_CODE_REGEX.test(value)) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Invalid reason code for ${fieldPath}`,
      fieldErrors: [{ path: fieldPath, code: "INVALID_VALUE" }]
    });
  }
  return value;
}
