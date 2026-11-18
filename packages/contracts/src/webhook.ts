import {
  EVENT_MAX_CONTENT_BYTES,
  EVENT_MAX_ENVELOPE_BYTES,
  type EndpointVerificationPurpose,
  ValidationDomainError,
  type WebhookPurpose,
  isEndpointVerificationPurpose,
  isWebhookPurpose
} from "@relayquill/domain";
import {
  type CanonicalJsonValue,
  canonicalizeJson,
  computeOriginalFactsSha256
} from "./canonical-command.js";
import {
  DERIVED_MAX_CONTENT_BYTES,
  EVENT_CONTENT_ENCODING,
  EVENT_CONTENT_MEDIA_TYPE
} from "./http/content.js";
import {
  type AttemptId,
  type Base64String,
  type Base64UrlString,
  type CanonicalUtcTimestamp,
  type DeliveryId,
  type EndpointId,
  type EndpointVerificationIntentId,
  type EventId,
  type EventTypeId,
  type EventTypeName,
  type KeyId,
  type NonNegativeInt64String,
  type OrderingDomainId,
  type PositiveInt64String,
  type ProjectId,
  type RepresentationProfileId,
  type Sha256Hex,
  type SubscriptionId,
  assertAllowedKeys,
  assertPlainRecord,
  decodeBase64UrlStrict,
  decodeUtf8BytesStrict,
  encodeDomainLengthPrefixed,
  encodeUtf8Bytes,
  parseAttemptId,
  parseBoundedInteger,
  parseCanonicalUtcTimestamp,
  parseDeliveryId,
  parseEndpointId,
  parseEndpointVerificationIntentId,
  parseEventId,
  parseEventTypeId,
  parseEventTypeName,
  parseKeyId,
  parseNonNegativeInt64BigInt,
  parseNonNegativeInt64String,
  parseNullableUtcTimestamp,
  parseOrderingDomainId,
  parsePositiveInt32,
  parsePositiveInt64String,
  parseProjectId,
  parseRepresentationProfileId,
  parseSha256Hex,
  parseStrictBase64,
  parseStrictBase64Url,
  parseStrictJsonObject,
  parseSubscriptionId,
  sha256Hex
} from "./http/values.js";
import { parseW3CTraceparent, parseW3CTracestate } from "./internal/trace.js";

export const WEBHOOK_PROTOCOL_VERSION = "1" as const;
export const WEBHOOK_MAX_HEADER_BYTES = 8_192 as const;
export const WEBHOOK_MAX_BODY_BYTES = EVENT_MAX_ENVELOPE_BYTES;
export const WEBHOOK_MAX_PREIMAGE_BYTES = 532_480 as const;
export const WEBHOOK_RECEIPT_MAX_BODY_BYTES = 4_096 as const;
export const WEBHOOK_FRESHNESS_PAST_SECONDS = 300n;
export const WEBHOOK_FRESHNESS_FUTURE_SECONDS = 30n;

export const WEBHOOK_HEADER_NAMES = Object.freeze({
  version: "Relayquill-Version",
  purpose: "Relayquill-Purpose",
  projectId: "Relayquill-Project-Id",
  eventId: "Relayquill-Event-Id",
  subscriptionId: "Relayquill-Subscription-Id",
  endpointId: "Relayquill-Endpoint-Id",
  endpointVersion: "Relayquill-Endpoint-Version",
  deliveryId: "Relayquill-Delivery-Id",
  deliveryGeneration: "Relayquill-Delivery-Generation",
  attemptId: "Relayquill-Attempt-Id",
  verificationId: "Relayquill-Verification-Id",
  signingPolicy: "Relayquill-Signing-Policy",
  timestamp: "Relayquill-Timestamp",
  consumerKey: "Relayquill-Consumer-Key",
  bodySha256: "Relayquill-Body-SHA256",
  signatures: "Relayquill-Signatures",
  orderingDomain: "Relayquill-Ordering-Domain",
  orderingKey: "Relayquill-Ordering-Key",
  orderingSequence: "Relayquill-Ordering-Sequence",
  endpointProof: "Relayquill-Endpoint-Proof",
  traceparent: "traceparent",
  tracestate: "tracestate"
} as const);

const PROTECTED_SINGLE_HEADER_NAMES = new Set<string>([
  "content-type",
  "content-encoding",
  "traceparent",
  "tracestate",
  WEBHOOK_HEADER_NAMES.version.toLowerCase(),
  WEBHOOK_HEADER_NAMES.purpose.toLowerCase(),
  WEBHOOK_HEADER_NAMES.projectId.toLowerCase(),
  WEBHOOK_HEADER_NAMES.eventId.toLowerCase(),
  WEBHOOK_HEADER_NAMES.subscriptionId.toLowerCase(),
  WEBHOOK_HEADER_NAMES.endpointId.toLowerCase(),
  WEBHOOK_HEADER_NAMES.endpointVersion.toLowerCase(),
  WEBHOOK_HEADER_NAMES.deliveryId.toLowerCase(),
  WEBHOOK_HEADER_NAMES.deliveryGeneration.toLowerCase(),
  WEBHOOK_HEADER_NAMES.attemptId.toLowerCase(),
  WEBHOOK_HEADER_NAMES.verificationId.toLowerCase(),
  WEBHOOK_HEADER_NAMES.signingPolicy.toLowerCase(),
  WEBHOOK_HEADER_NAMES.timestamp.toLowerCase(),
  WEBHOOK_HEADER_NAMES.consumerKey.toLowerCase(),
  WEBHOOK_HEADER_NAMES.bodySha256.toLowerCase(),
  WEBHOOK_HEADER_NAMES.signatures.toLowerCase(),
  WEBHOOK_HEADER_NAMES.orderingDomain.toLowerCase(),
  WEBHOOK_HEADER_NAMES.orderingKey.toLowerCase(),
  WEBHOOK_HEADER_NAMES.orderingSequence.toLowerCase()
]);

export interface WebhookContentBlock {
  readonly media_type: typeof EVENT_CONTENT_MEDIA_TYPE;
  readonly encoding: typeof EVENT_CONTENT_ENCODING;
  readonly byte_count: number;
  readonly sha256: Sha256Hex;
  readonly data: Base64String;
}

export interface WebhookDerivedBlock {
  readonly profile_id: RepresentationProfileId;
  readonly profile_version: PositiveInt64String;
  readonly profile_sha256: Sha256Hex;
  readonly target_event_schema_version: number;
  readonly media_type: typeof EVENT_CONTENT_MEDIA_TYPE;
  readonly encoding: typeof EVENT_CONTENT_ENCODING;
  readonly byte_count: number;
  readonly sha256: Sha256Hex;
  readonly data: Base64String;
}

export interface WebhookEnvelopeV1 {
  readonly envelope_version: 1;
  readonly representation_version: 1;
  readonly project_id: ProjectId;
  readonly event_id: EventId;
  readonly project_event_sequence: PositiveInt64String;
  readonly event_type_id: EventTypeId;
  readonly event_type: EventTypeName;
  readonly event_schema_version: number;
  readonly admitted_at: CanonicalUtcTimestamp;
  readonly producer_event_time: CanonicalUtcTimestamp | null;
  readonly content: WebhookContentBlock;
}

export interface WebhookEnvelopeV2 {
  readonly envelope_version: 2;
  readonly representation_version: number;
  readonly project_id: ProjectId;
  readonly event_id: EventId;
  readonly project_event_sequence: PositiveInt64String;
  readonly event_type_id: EventTypeId;
  readonly event_type: EventTypeName;
  readonly event_schema_version: number;
  readonly admitted_at: CanonicalUtcTimestamp;
  readonly producer_event_time: CanonicalUtcTimestamp | null;
  readonly content: WebhookContentBlock;
  readonly derived: WebhookDerivedBlock;
}

export type WebhookEnvelope = WebhookEnvelopeV1 | WebhookEnvelopeV2;

export interface SerializedWebhookEnvelope {
  readonly envelope: WebhookEnvelope;
  readonly body_json: string;
  readonly body_bytes: Uint8Array;
  readonly byte_count: number;
  readonly body_sha256: Sha256Hex;
  readonly original_facts_sha256: Sha256Hex;
}

export interface DecodedWebhookEnvelope {
  readonly envelope: WebhookEnvelope;
  readonly original_content_bytes: Uint8Array;
  readonly derived_content_bytes?: Uint8Array | undefined;
  readonly original_facts_sha256: Sha256Hex;
}

export interface WebhookSignatureEntry {
  readonly version: "v1";
  readonly kid: KeyId;
  readonly mac: Base64UrlString;
  readonly mac_bytes: Uint8Array;
}

export interface ParsedWebhookDeliveryHeaders {
  readonly version: typeof WEBHOOK_PROTOCOL_VERSION;
  readonly purpose: "delivery";
  readonly project_id: ProjectId;
  readonly event_id: EventId;
  readonly subscription_id: SubscriptionId;
  readonly endpoint_id: EndpointId;
  readonly endpoint_version: PositiveInt64String;
  readonly delivery_id: DeliveryId;
  readonly delivery_generation: NonNegativeInt64String;
  readonly attempt_id: AttemptId;
  readonly signing_policy_version: PositiveInt64String;
  readonly timestamp_seconds: NonNegativeInt64String;
  readonly consumer_key: Sha256Hex;
  readonly body_sha256: Sha256Hex;
  readonly signatures: readonly WebhookSignatureEntry[];
  readonly ordering?: {
    readonly ordering_domain_id: OrderingDomainId;
    readonly ordering_key_sha256: Sha256Hex;
    readonly ordering_sequence: PositiveInt64String;
  } | undefined;
  readonly traceparent?: string | undefined;
  readonly tracestate?: string | undefined;
}

export interface ParsedWebhookVerificationHeaders {
  readonly version: typeof WEBHOOK_PROTOCOL_VERSION;
  readonly purpose: "endpoint_verification";
  readonly verification_id: EndpointVerificationIntentId;
  readonly project_id: ProjectId;
  readonly endpoint_id: EndpointId;
  readonly endpoint_version: PositiveInt64String;
  readonly attempt_id: AttemptId;
  readonly signing_policy_version: "0";
  readonly timestamp_seconds: NonNegativeInt64String;
  readonly body_sha256: Sha256Hex;
  readonly signatures: readonly [WebhookSignatureEntry];
  readonly traceparent?: string | undefined;
  readonly tracestate?: string | undefined;
}

export type ParsedWebhookHeaders =
  | ParsedWebhookDeliveryHeaders
  | ParsedWebhookVerificationHeaders;

export interface EndpointVerificationBodyV1 {
  readonly envelope_version: 1;
  readonly verification_id: EndpointVerificationIntentId;
  readonly endpoint_id: EndpointId;
  readonly endpoint_version: PositiveInt64String;
  readonly key_id: KeyId;
  readonly purpose: EndpointVerificationPurpose;
  readonly public_nonce: Base64UrlString;
  readonly configuration_sha256: Sha256Hex;
  readonly receiver_contract_sha256?: Sha256Hex | undefined;
}

export interface ReceiverLocalCommitReceiptV1 {
  readonly receipt_version: 1;
  readonly project_id: ProjectId;
  readonly event_id: EventId;
  readonly consumer_event_key: Sha256Hex;
  readonly original_facts_sha256: Sha256Hex;
  readonly receipt_id: string;
  readonly business_status: "committed";
  readonly committed_at: CanonicalUtcTimestamp;
  readonly delivery_attempt_id: AttemptId;
  readonly key_id: KeyId;
  readonly mac: Base64UrlString;
}

const CONTENT_BLOCK_KEYS = new Set(["media_type", "encoding", "byte_count", "sha256", "data"]);
const DERIVED_BLOCK_KEYS = new Set([
  "profile_id",
  "profile_version",
  "profile_sha256",
  "target_event_schema_version",
  "media_type",
  "encoding",
  "byte_count",
  "sha256",
  "data"
]);
const ENVELOPE_V1_KEYS = new Set([
  "envelope_version",
  "representation_version",
  "project_id",
  "event_id",
  "project_event_sequence",
  "event_type_id",
  "event_type",
  "event_schema_version",
  "admitted_at",
  "producer_event_time",
  "content"
]);
const ENVELOPE_V2_KEYS = new Set([...ENVELOPE_V1_KEYS, "derived"]);

const ENDPOINT_VERIFICATION_KEYS = new Set([
  "envelope_version",
  "verification_id",
  "endpoint_id",
  "endpoint_version",
  "key_id",
  "purpose",
  "public_nonce",
  "configuration_sha256",
  "receiver_contract_sha256"
]);

const RECEIPT_V1_KEYS = new Set([
  "receipt_version",
  "project_id",
  "event_id",
  "consumer_event_key",
  "original_facts_sha256",
  "receipt_id",
  "business_status",
  "committed_at",
  "delivery_attempt_id",
  "key_id",
  "mac"
]);

const SIGNATURE_ENTRY_REGEX = /^v1;kid=([a-z0-9][a-z0-9._-]{0,63});mac=([A-Za-z0-9_-]{43})$/;
const CANONICAL_UUID_LOWER_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

function parseContentBlock(
  value: unknown,
  maxBytes: number,
  fieldPath: string
): { readonly block: WebhookContentBlock; readonly bytes: Uint8Array } {
  const rec = assertPlainRecord(value, fieldPath);
  assertAllowedKeys(rec, CONTENT_BLOCK_KEYS, fieldPath);

  if (rec.media_type !== EVENT_CONTENT_MEDIA_TYPE) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Unsupported media_type at ${fieldPath}.media_type`,
      fieldErrors: [{ path: `${fieldPath}.media_type`, code: "INVALID_VALUE" }]
    });
  }
  if (rec.encoding !== EVENT_CONTENT_ENCODING) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Unsupported encoding at ${fieldPath}.encoding`,
      fieldErrors: [{ path: `${fieldPath}.encoding`, code: "INVALID_VALUE" }]
    });
  }

  const decoded = parseStrictBase64(rec.data, `${fieldPath}.data`, {
    minDecodedBytes: 1,
    maxDecodedBytes: maxBytes
  });
  const byteCount = parseBoundedInteger(rec.byte_count, {
    fieldPath: `${fieldPath}.byte_count`,
    min: 1,
    max: maxBytes
  });
  if (byteCount !== decoded.bytes.length) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `byte_count mismatch at ${fieldPath}.byte_count`,
      fieldErrors: [{ path: `${fieldPath}.byte_count`, code: "INVALID_VALUE" }]
    });
  }
  const declaredSha256 = parseSha256Hex(rec.sha256, `${fieldPath}.sha256`);
  if (declaredSha256 !== sha256Hex(decoded.bytes)) {
    throw new ValidationDomainError({
      code: "INVALID_HASH",
      message: `sha256 mismatch at ${fieldPath}.sha256`,
      fieldErrors: [{ path: `${fieldPath}.sha256`, code: "INVALID_HASH" }]
    });
  }

  return {
    block: Object.freeze({
      media_type: EVENT_CONTENT_MEDIA_TYPE,
      encoding: EVENT_CONTENT_ENCODING,
      byte_count: byteCount,
      sha256: declaredSha256,
      data: decoded.encoded
    }),
    bytes: decoded.bytes
  };
}

function parseDerivedBlock(
  value: unknown,
  fieldPath: string
): { readonly block: WebhookDerivedBlock; readonly bytes: Uint8Array } {
  const rec = assertPlainRecord(value, fieldPath);
  assertAllowedKeys(rec, DERIVED_BLOCK_KEYS, fieldPath);

  if (rec.media_type !== EVENT_CONTENT_MEDIA_TYPE) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Unsupported media_type at ${fieldPath}.media_type`,
      fieldErrors: [{ path: `${fieldPath}.media_type`, code: "INVALID_VALUE" }]
    });
  }
  if (rec.encoding !== EVENT_CONTENT_ENCODING) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Unsupported encoding at ${fieldPath}.encoding`,
      fieldErrors: [{ path: `${fieldPath}.encoding`, code: "INVALID_VALUE" }]
    });
  }

  const decoded = parseStrictBase64(rec.data, `${fieldPath}.data`, {
    minDecodedBytes: 1,
    maxDecodedBytes: DERIVED_MAX_CONTENT_BYTES
  });
  const byteCount = parseBoundedInteger(rec.byte_count, {
    fieldPath: `${fieldPath}.byte_count`,
    min: 1,
    max: DERIVED_MAX_CONTENT_BYTES
  });
  if (byteCount !== decoded.bytes.length) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `byte_count mismatch at ${fieldPath}.byte_count`,
      fieldErrors: [{ path: `${fieldPath}.byte_count`, code: "INVALID_VALUE" }]
    });
  }
  const declaredSha256 = parseSha256Hex(rec.sha256, `${fieldPath}.sha256`);
  if (declaredSha256 !== sha256Hex(decoded.bytes)) {
    throw new ValidationDomainError({
      code: "INVALID_HASH",
      message: `sha256 mismatch at ${fieldPath}.sha256`,
      fieldErrors: [{ path: `${fieldPath}.sha256`, code: "INVALID_HASH" }]
    });
  }

  return {
    block: Object.freeze({
      profile_id: parseRepresentationProfileId(rec.profile_id, `${fieldPath}.profile_id`),
      profile_version: parsePositiveInt64String(
        rec.profile_version,
        `${fieldPath}.profile_version`
      ),
      profile_sha256: parseSha256Hex(rec.profile_sha256, `${fieldPath}.profile_sha256`),
      target_event_schema_version: parsePositiveInt32(
        rec.target_event_schema_version,
        `${fieldPath}.target_event_schema_version`
      ),
      media_type: EVENT_CONTENT_MEDIA_TYPE,
      encoding: EVENT_CONTENT_ENCODING,
      byte_count: byteCount,
      sha256: declaredSha256,
      data: decoded.encoded
    }),
    bytes: decoded.bytes
  };
}

function validateWebhookEnvelopeObject(
  value: unknown,
  fieldPath = "webhook_envelope"
): DecodedWebhookEnvelope {
  const rec = assertPlainRecord(value, fieldPath);
  const envVer = parseBoundedInteger(rec.envelope_version, {
    fieldPath: `${fieldPath}.envelope_version`,
    min: 1,
    max: 2
  });

  if (envVer === 1) {
    assertAllowedKeys(rec, ENVELOPE_V1_KEYS, fieldPath);
    const repVer = parseBoundedInteger(rec.representation_version, {
      fieldPath: `${fieldPath}.representation_version`,
      min: 1,
      max: 1
    });
    if (repVer !== 1) {
      throw new ValidationDomainError({
        code: "INVALID_VALUE",
        message: "envelope_version 1 requires representation_version 1",
        fieldErrors: [{ path: `${fieldPath}.representation_version`, code: "INVALID_VALUE" }]
      });
    }
    const contentParsed = parseContentBlock(
      rec.content,
      EVENT_MAX_CONTENT_BYTES,
      `${fieldPath}.content`
    );
    const envelope: WebhookEnvelopeV1 = Object.freeze({
      envelope_version: 1,
      representation_version: 1,
      project_id: parseProjectId(rec.project_id, `${fieldPath}.project_id`),
      event_id: parseEventId(rec.event_id, `${fieldPath}.event_id`),
      project_event_sequence: parsePositiveInt64String(
        rec.project_event_sequence,
        `${fieldPath}.project_event_sequence`
      ),
      event_type_id: parseEventTypeId(rec.event_type_id, `${fieldPath}.event_type_id`),
      event_type: parseEventTypeName(rec.event_type, `${fieldPath}.event_type`),
      event_schema_version: parsePositiveInt32(
        rec.event_schema_version,
        `${fieldPath}.event_schema_version`
      ),
      admitted_at: parseCanonicalUtcTimestamp(rec.admitted_at, `${fieldPath}.admitted_at`),
      producer_event_time: parseNullableUtcTimestamp(
        rec.producer_event_time,
        `${fieldPath}.producer_event_time`
      ),
      content: contentParsed.block
    });

    const originalFactsSha256 = computeOriginalFactsSha256({
      project_id: envelope.project_id,
      event_id: envelope.event_id,
      project_event_sequence: envelope.project_event_sequence,
      event_type_id: envelope.event_type_id,
      event_type: envelope.event_type,
      event_schema_version: envelope.event_schema_version,
      admitted_at: envelope.admitted_at,
      producer_event_time: envelope.producer_event_time,
      original_content_sha256: envelope.content.sha256
    });

    return Object.freeze({
      envelope,
      original_content_bytes: contentParsed.bytes,
      original_facts_sha256: originalFactsSha256
    });
  }

  assertAllowedKeys(rec, ENVELOPE_V2_KEYS, fieldPath);
  const repVer = parseBoundedInteger(rec.representation_version, {
    fieldPath: `${fieldPath}.representation_version`,
    min: 2,
    max: 2_147_483_647
  });
  const contentParsed = parseContentBlock(
    rec.content,
    EVENT_MAX_CONTENT_BYTES,
    `${fieldPath}.content`
  );
  const derivedParsed = parseDerivedBlock(rec.derived, `${fieldPath}.derived`);

  const envelope: WebhookEnvelopeV2 = Object.freeze({
    envelope_version: 2,
    representation_version: repVer,
    project_id: parseProjectId(rec.project_id, `${fieldPath}.project_id`),
    event_id: parseEventId(rec.event_id, `${fieldPath}.event_id`),
    project_event_sequence: parsePositiveInt64String(
      rec.project_event_sequence,
      `${fieldPath}.project_event_sequence`
    ),
    event_type_id: parseEventTypeId(rec.event_type_id, `${fieldPath}.event_type_id`),
    event_type: parseEventTypeName(rec.event_type, `${fieldPath}.event_type`),
    event_schema_version: parsePositiveInt32(
      rec.event_schema_version,
      `${fieldPath}.event_schema_version`
    ),
    admitted_at: parseCanonicalUtcTimestamp(rec.admitted_at, `${fieldPath}.admitted_at`),
    producer_event_time: parseNullableUtcTimestamp(
      rec.producer_event_time,
      `${fieldPath}.producer_event_time`
    ),
    content: contentParsed.block,
    derived: derivedParsed.block
  });

  const originalFactsSha256 = computeOriginalFactsSha256({
    project_id: envelope.project_id,
    event_id: envelope.event_id,
    project_event_sequence: envelope.project_event_sequence,
    event_type_id: envelope.event_type_id,
    event_type: envelope.event_type,
    event_schema_version: envelope.event_schema_version,
    admitted_at: envelope.admitted_at,
    producer_event_time: envelope.producer_event_time,
    original_content_sha256: envelope.content.sha256
  });

  return Object.freeze({
    envelope,
    original_content_bytes: contentParsed.bytes,
    derived_content_bytes: derivedParsed.bytes,
    original_facts_sha256: originalFactsSha256
  });
}

export function parseWebhookEnvelope(
  value: unknown,
  fieldPath = "webhook_envelope"
): DecodedWebhookEnvelope {
  return validateWebhookEnvelopeObject(value, fieldPath);
}

export function serializeWebhookEnvelope(
  input: WebhookEnvelope
): SerializedWebhookEnvelope {
  const validated = validateWebhookEnvelopeObject(input, "webhook_envelope");
  const bodyJson = canonicalizeJson(
    validated.envelope as unknown as CanonicalJsonValue,
    "webhook_envelope"
  );
  const bodyBytes = encodeUtf8Bytes(bodyJson, "webhook_envelope");
  if (bodyBytes.length > WEBHOOK_MAX_BODY_BYTES) {
    throw new ValidationDomainError({
      code: "PAYLOAD_TOO_LARGE",
      message: `Serialized webhook body (${bodyBytes.length} bytes) exceeds ${WEBHOOK_MAX_BODY_BYTES} bytes`
    });
  }
  return Object.freeze({
    envelope: validated.envelope,
    body_json: bodyJson,
    body_bytes: bodyBytes,
    byte_count: bodyBytes.length,
    body_sha256: sha256Hex(bodyBytes),
    original_facts_sha256: validated.original_facts_sha256
  });
}

export function decodeWebhookEnvelopeBytes(rawBytes: Uint8Array): DecodedWebhookEnvelope {
  if (!(rawBytes instanceof Uint8Array)) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: "Webhook body must be Uint8Array bytes"
    });
  }
  if (rawBytes.length === 0 || rawBytes.length > WEBHOOK_MAX_BODY_BYTES) {
    throw new ValidationDomainError({
      code: rawBytes.length > WEBHOOK_MAX_BODY_BYTES ? "PAYLOAD_TOO_LARGE" : "INVALID_VALUE",
      message: `Webhook body size ${rawBytes.length} out of bounds [1, ${WEBHOOK_MAX_BODY_BYTES}]`
    });
  }
  const text = decodeUtf8BytesStrict(rawBytes, "webhook_body");
  const obj = parseStrictJsonObject(text, {
    fieldPath: "webhook_body",
    maxDepth: 8,
    maxNodes: 256
  });
  return validateWebhookEnvelopeObject(obj, "webhook_body");
}

export function parseWebhookSignaturesHeader(
  headerValue: unknown,
  fieldPath = WEBHOOK_HEADER_NAMES.signatures
): readonly WebhookSignatureEntry[] {
  if (typeof headerValue !== "string" || headerValue.length === 0) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Missing or empty ${fieldPath}`,
      fieldErrors: [{ path: fieldPath, code: "INVALID_VALUE" }]
    });
  }
  const rawEntries = headerValue.split(",");
  if (rawEntries.length < 1 || rawEntries.length > 2) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `${fieldPath} must contain 1 or 2 signature entries`,
      fieldErrors: [{ path: fieldPath, code: "INVALID_VALUE" }]
    });
  }
  const seenKids = new Set<KeyId>();
  const parsed: WebhookSignatureEntry[] = [];

  for (let i = 0; i < rawEntries.length; i += 1) {
    const entry = rawEntries[i]!;
    const match = SIGNATURE_ENTRY_REGEX.exec(entry);
    if (match === null || match[1] === undefined || match[2] === undefined) {
      throw new ValidationDomainError({
        code: "INVALID_VALUE",
        message: `Malformed signature entry at ${fieldPath}[${i}]`,
        fieldErrors: [{ path: fieldPath, code: "INVALID_VALUE" }]
      });
    }
    const kid = parseKeyId(match[1], `${fieldPath}[${i}].kid`);
    if (seenKids.has(kid)) {
      throw new ValidationDomainError({
        code: "INVALID_VALUE",
        message: `Duplicate key ID "${kid}" in ${fieldPath}`,
        fieldErrors: [{ path: fieldPath, code: "INVALID_VALUE" }]
      });
    }
    seenKids.add(kid);
    const macDecoded = parseStrictBase64Url(match[2], `${fieldPath}[${i}].mac`, {
      exactByteLength: 32
    });
    parsed.push(
      Object.freeze({
        version: "v1",
        kid,
        mac: macDecoded.encoded,
        mac_bytes: macDecoded.bytes
      })
    );
  }

  return Object.freeze(parsed);
}

export function formatWebhookSignaturesHeader(
  entries: readonly { readonly kid: KeyId | string; readonly mac: Base64UrlString | string }[]
): string {
  if (entries.length < 1 || entries.length > 2) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: "Relayquill-Signatures requires 1 or 2 entries"
    });
  }
  const seen = new Set<KeyId>();
  const parts: string[] = [];
  for (const entry of entries) {
    const kid = parseKeyId(entry.kid, "signatures.kid");
    if (seen.has(kid)) {
      throw new ValidationDomainError({
        code: "INVALID_VALUE",
        message: `Duplicate kid "${kid}" in Relayquill-Signatures`
      });
    }
    seen.add(kid);
    const mac = parseStrictBase64Url(entry.mac, "signatures.mac", {
      exactByteLength: 32
    }).encoded;
    parts.push(`v1;kid=${kid};mac=${mac}`);
  }
  return parts.join(",");
}

export function parseWebhookRawHeaders(
  rawHeaders: ReadonlyArray<readonly [string, string]>
): ParsedWebhookHeaders {
  const singleMap = new Map<string, string>();
  let totalProtectedHeaderBytes = 0;

  for (const [rawName, rawValue] of rawHeaders) {
    if (typeof rawName !== "string" || typeof rawValue !== "string") {
      throw new ValidationDomainError({
        code: "INVALID_VALUE",
        message: "Header pair must be [string, string]"
      });
    }
    const lowerName = rawName.toLowerCase();
    if (PROTECTED_SINGLE_HEADER_NAMES.has(lowerName) || lowerName.startsWith("relayquill-")) {
      totalProtectedHeaderBytes +=
        encodeUtf8Bytes(rawName, "header_name").length +
        encodeUtf8Bytes(rawValue, "header_value").length +
        4;
      if (totalProtectedHeaderBytes > WEBHOOK_MAX_HEADER_BYTES) {
        throw new ValidationDomainError({
          code: "PAYLOAD_TOO_LARGE",
          message: `Protected webhook headers exceed ${WEBHOOK_MAX_HEADER_BYTES} bytes`
        });
      }
      if (singleMap.has(lowerName)) {
        throw new ValidationDomainError({
          code: "INVALID_VALUE",
          message: `Duplicate protected header "${rawName}" is forbidden`,
          fieldErrors: [{ path: lowerName, code: "INVALID_VALUE" }]
        });
      }
      singleMap.set(lowerName, rawValue);
    }
  }

  if (singleMap.has("content-encoding")) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: "Content-Encoding is unsupported by Relayquill webhook profile",
      fieldErrors: [{ path: "content-encoding", code: "INVALID_VALUE" }]
    });
  }

  const contentType = singleMap.get("content-type");
  if (contentType !== undefined) {
    const mediaType = contentType.split(";")[0]?.trim().toLowerCase();
    if (mediaType !== EVENT_CONTENT_MEDIA_TYPE) {
      throw new ValidationDomainError({
        code: "INVALID_VALUE",
        message: `Unsupported Content-Type "${contentType}"`,
        fieldErrors: [{ path: "content-type", code: "INVALID_VALUE" }]
      });
    }
  }

  const version = singleMap.get(WEBHOOK_HEADER_NAMES.version.toLowerCase());
  if (version !== WEBHOOK_PROTOCOL_VERSION) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Unsupported or missing ${WEBHOOK_HEADER_NAMES.version}`,
      fieldErrors: [{ path: WEBHOOK_HEADER_NAMES.version, code: "INVALID_VALUE" }]
    });
  }

  const purposeRaw = singleMap.get(WEBHOOK_HEADER_NAMES.purpose.toLowerCase());
  if (!isWebhookPurpose(purposeRaw)) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Invalid or missing ${WEBHOOK_HEADER_NAMES.purpose}`,
      fieldErrors: [{ path: WEBHOOK_HEADER_NAMES.purpose, code: "INVALID_VALUE" }]
    });
  }
  const purpose: WebhookPurpose = purposeRaw;

  const projectId = parseProjectId(
    singleMap.get(WEBHOOK_HEADER_NAMES.projectId.toLowerCase()),
    WEBHOOK_HEADER_NAMES.projectId
  );
  const endpointId = parseEndpointId(
    singleMap.get(WEBHOOK_HEADER_NAMES.endpointId.toLowerCase()),
    WEBHOOK_HEADER_NAMES.endpointId
  );
  const endpointVersion = parsePositiveInt64String(
    singleMap.get(WEBHOOK_HEADER_NAMES.endpointVersion.toLowerCase()),
    WEBHOOK_HEADER_NAMES.endpointVersion
  );
  const attemptId = parseAttemptId(
    singleMap.get(WEBHOOK_HEADER_NAMES.attemptId.toLowerCase()),
    WEBHOOK_HEADER_NAMES.attemptId
  );
  const timestampSeconds = parseNonNegativeInt64String(
    singleMap.get(WEBHOOK_HEADER_NAMES.timestamp.toLowerCase()),
    WEBHOOK_HEADER_NAMES.timestamp
  );
  const bodySha256 = parseSha256Hex(
    singleMap.get(WEBHOOK_HEADER_NAMES.bodySha256.toLowerCase()),
    WEBHOOK_HEADER_NAMES.bodySha256
  );
  const signatures = parseWebhookSignaturesHeader(
    singleMap.get(WEBHOOK_HEADER_NAMES.signatures.toLowerCase()),
    WEBHOOK_HEADER_NAMES.signatures
  );

  const traceparentRaw = singleMap.get("traceparent");
  const tracestateRaw = singleMap.get("tracestate");
  const traceparent =
    traceparentRaw !== undefined
      ? parseW3CTraceparent(traceparentRaw, "traceparent").raw
      : undefined;
  const tracestate =
    tracestateRaw !== undefined
      ? parseW3CTracestate(tracestateRaw, "tracestate")
      : undefined;

  if (purpose === "endpoint_verification") {
    for (const forbidden of [
      WEBHOOK_HEADER_NAMES.eventId,
      WEBHOOK_HEADER_NAMES.subscriptionId,
      WEBHOOK_HEADER_NAMES.deliveryId,
      WEBHOOK_HEADER_NAMES.deliveryGeneration,
      WEBHOOK_HEADER_NAMES.consumerKey,
      WEBHOOK_HEADER_NAMES.orderingDomain,
      WEBHOOK_HEADER_NAMES.orderingKey,
      WEBHOOK_HEADER_NAMES.orderingSequence
    ]) {
      if (singleMap.has(forbidden.toLowerCase())) {
        throw new ValidationDomainError({
          code: "INVALID_VALUE",
          message: `Header ${forbidden} is forbidden for purpose=endpoint_verification`,
          fieldErrors: [{ path: forbidden, code: "INVALID_VALUE" }]
        });
      }
    }
    const signingPolicy = singleMap.get(WEBHOOK_HEADER_NAMES.signingPolicy.toLowerCase());
    if (signingPolicy !== "0") {
      throw new ValidationDomainError({
        code: "INVALID_VALUE",
        message: `${WEBHOOK_HEADER_NAMES.signingPolicy} must be "0" for endpoint_verification`,
        fieldErrors: [{ path: WEBHOOK_HEADER_NAMES.signingPolicy, code: "INVALID_VALUE" }]
      });
    }
    if (signatures.length !== 1) {
      throw new ValidationDomainError({
        code: "INVALID_VALUE",
        message: "endpoint_verification permits exactly 1 signature entry",
        fieldErrors: [{ path: WEBHOOK_HEADER_NAMES.signatures, code: "INVALID_VALUE" }]
      });
    }
    const verificationId = parseEndpointVerificationIntentId(
      singleMap.get(WEBHOOK_HEADER_NAMES.verificationId.toLowerCase()),
      WEBHOOK_HEADER_NAMES.verificationId
    );
    return Object.freeze({
      version: WEBHOOK_PROTOCOL_VERSION,
      purpose: "endpoint_verification",
      verification_id: verificationId,
      project_id: projectId,
      endpoint_id: endpointId,
      endpoint_version: endpointVersion,
      attempt_id: attemptId,
      signing_policy_version: "0",
      timestamp_seconds: timestampSeconds,
      body_sha256: bodySha256,
      signatures: Object.freeze([signatures[0]!] as const),
      ...(traceparent !== undefined ? { traceparent } : {}),
      ...(tracestate !== undefined ? { tracestate } : {})
    });
  }

  if (singleMap.has(WEBHOOK_HEADER_NAMES.verificationId.toLowerCase())) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `${WEBHOOK_HEADER_NAMES.verificationId} is forbidden for purpose=delivery`,
      fieldErrors: [{ path: WEBHOOK_HEADER_NAMES.verificationId, code: "INVALID_VALUE" }]
    });
  }

  const eventId = parseEventId(
    singleMap.get(WEBHOOK_HEADER_NAMES.eventId.toLowerCase()),
    WEBHOOK_HEADER_NAMES.eventId
  );
  const subscriptionId = parseSubscriptionId(
    singleMap.get(WEBHOOK_HEADER_NAMES.subscriptionId.toLowerCase()),
    WEBHOOK_HEADER_NAMES.subscriptionId
  );
  const deliveryId = parseDeliveryId(
    singleMap.get(WEBHOOK_HEADER_NAMES.deliveryId.toLowerCase()),
    WEBHOOK_HEADER_NAMES.deliveryId
  );
  const deliveryGeneration = parseNonNegativeInt64String(
    singleMap.get(WEBHOOK_HEADER_NAMES.deliveryGeneration.toLowerCase()),
    WEBHOOK_HEADER_NAMES.deliveryGeneration
  );
  const signingPolicyVersion = parsePositiveInt64String(
    singleMap.get(WEBHOOK_HEADER_NAMES.signingPolicy.toLowerCase()),
    WEBHOOK_HEADER_NAMES.signingPolicy
  );
  const consumerKey = parseSha256Hex(
    singleMap.get(WEBHOOK_HEADER_NAMES.consumerKey.toLowerCase()),
    WEBHOOK_HEADER_NAMES.consumerKey
  );

  const ordDomainRaw = singleMap.get(WEBHOOK_HEADER_NAMES.orderingDomain.toLowerCase());
  const ordKeyRaw = singleMap.get(WEBHOOK_HEADER_NAMES.orderingKey.toLowerCase());
  const ordSeqRaw = singleMap.get(WEBHOOK_HEADER_NAMES.orderingSequence.toLowerCase());
  const ordCount =
    (ordDomainRaw !== undefined ? 1 : 0) +
    (ordKeyRaw !== undefined ? 1 : 0) +
    (ordSeqRaw !== undefined ? 1 : 0);

  if (ordCount !== 0 && ordCount !== 3) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: "Partial ordering header tuple is forbidden; provide all 3 or omit all 3",
      fieldErrors: [{ path: WEBHOOK_HEADER_NAMES.orderingDomain, code: "INVALID_VALUE" }]
    });
  }

  const ordering =
    ordCount === 3
      ? Object.freeze({
          ordering_domain_id: parseOrderingDomainId(
            ordDomainRaw,
            WEBHOOK_HEADER_NAMES.orderingDomain
          ),
          ordering_key_sha256: parseSha256Hex(ordKeyRaw, WEBHOOK_HEADER_NAMES.orderingKey),
          ordering_sequence: parsePositiveInt64String(
            ordSeqRaw,
            WEBHOOK_HEADER_NAMES.orderingSequence
          )
        })
      : undefined;

  return Object.freeze({
    version: WEBHOOK_PROTOCOL_VERSION,
    purpose: "delivery",
    project_id: projectId,
    event_id: eventId,
    subscription_id: subscriptionId,
    endpoint_id: endpointId,
    endpoint_version: endpointVersion,
    delivery_id: deliveryId,
    delivery_generation: deliveryGeneration,
    attempt_id: attemptId,
    signing_policy_version: signingPolicyVersion,
    timestamp_seconds: timestampSeconds,
    consumer_key: consumerKey,
    body_sha256: bodySha256,
    signatures,
    ...(ordering !== undefined ? { ordering } : {}),
    ...(traceparent !== undefined ? { traceparent } : {}),
    ...(tracestate !== undefined ? { tracestate } : {})
  });
}

export function isWebhookTimestampFresh(
  signedTimestampSeconds: NonNegativeInt64String | bigint,
  nowUnixSeconds: bigint
): boolean {
  const ts = parseNonNegativeInt64BigInt(signedTimestampSeconds, "timestamp_seconds");
  return (
    ts >= nowUnixSeconds - WEBHOOK_FRESHNESS_PAST_SECONDS &&
    ts <= nowUnixSeconds + WEBHOOK_FRESHNESS_FUTURE_SECONDS
  );
}

export interface WebhookSignaturePreimageInput {
  readonly version?: typeof WEBHOOK_PROTOCOL_VERSION | undefined;
  readonly purpose: WebhookPurpose;
  readonly key_id: KeyId | string;
  readonly method?: "POST" | undefined;
  readonly external_authority: string;
  readonly request_target: string;
  readonly project_id: ProjectId | string;
  readonly event_id?: EventId | string | undefined;
  readonly subscription_id?: SubscriptionId | string | undefined;
  readonly endpoint_id: EndpointId | string;
  readonly endpoint_version: PositiveInt64String | string;
  readonly signing_policy_version: NonNegativeInt64String | string;
  readonly delivery_id?: DeliveryId | string | undefined;
  readonly delivery_generation?: NonNegativeInt64String | string | undefined;
  readonly attempt_id: AttemptId | string;
  readonly verification_id?: EndpointVerificationIntentId | string | undefined;
  readonly timestamp_seconds: NonNegativeInt64String | string;
  readonly consumer_event_key?: Sha256Hex | string | undefined;
  readonly ordering_domain_id?: OrderingDomainId | string | undefined;
  readonly ordering_key_sha256?: Sha256Hex | string | undefined;
  readonly ordering_sequence?: PositiveInt64String | string | undefined;
  readonly traceparent?: string | undefined;
  readonly tracestate?: string | undefined;
  readonly wire_body_sha256: Sha256Hex | string;
  readonly raw_wire_body_bytes: Uint8Array;
}

export function buildWebhookSignaturePreimage(input: WebhookSignaturePreimageInput): Uint8Array {
  if (!isWebhookPurpose(input.purpose)) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Invalid webhook purpose "${String(input.purpose)}"`
    });
  }
  const method = input.method ?? "POST";
  if (method !== "POST") {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Webhook signature profile requires uppercase POST method, got "${String(method)}"`
    });
  }
  if (
    typeof input.external_authority !== "string" ||
    input.external_authority.length === 0 ||
    input.external_authority.includes("/") ||
    input.external_authority.includes("?")
  ) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: "external_authority must be normalized host:port"
    });
  }
  if (
    typeof input.request_target !== "string" ||
    !input.request_target.startsWith("/") ||
    input.request_target.includes("?") ||
    input.request_target.includes("#")
  ) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: "request_target must be a normalized ASCII path with no query or fragment"
    });
  }
  if (!(input.raw_wire_body_bytes instanceof Uint8Array)) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: "raw_wire_body_bytes must be Uint8Array"
    });
  }
  const wireBodySha = parseSha256Hex(input.wire_body_sha256, "wire_body_sha256");
  if (sha256Hex(input.raw_wire_body_bytes) !== wireBodySha) {
    throw new ValidationDomainError({
      code: "INVALID_HASH",
      message: "wire_body_sha256 does not match raw_wire_body_bytes"
    });
  }

  const version = input.version ?? WEBHOOK_PROTOCOL_VERSION;
  const keyId = parseKeyId(input.key_id, "key_id");
  const projectId = parseProjectId(input.project_id, "project_id");
  const endpointId = parseEndpointId(input.endpoint_id, "endpoint_id");
  const endpointVersion = parsePositiveInt64String(input.endpoint_version, "endpoint_version");
  const attemptId = parseAttemptId(input.attempt_id, "attempt_id");
  const timestampSeconds = parseNonNegativeInt64String(
    input.timestamp_seconds,
    "timestamp_seconds"
  );
  const traceparent =
    input.traceparent !== undefined ? parseW3CTraceparent(input.traceparent).raw : "";
  const tracestate =
    input.tracestate !== undefined ? parseW3CTracestate(input.tracestate) : "";

  let eventId = "";
  let subscriptionId = "";
  let signingPolicyVersion = "";
  let deliveryId = "";
  let deliveryGeneration = "";
  let verificationId = "";
  let consumerKey = "";
  let orderingDomainId = "";
  let orderingKeySha256 = "";
  let orderingSequence = "";

  if (input.purpose === "delivery") {
    eventId = parseEventId(input.event_id, "event_id");
    subscriptionId = parseSubscriptionId(input.subscription_id, "subscription_id");
    signingPolicyVersion = parsePositiveInt64String(
      input.signing_policy_version,
      "signing_policy_version"
    );
    deliveryId = parseDeliveryId(input.delivery_id, "delivery_id");
    deliveryGeneration = parseNonNegativeInt64String(
      input.delivery_generation,
      "delivery_generation"
    );
    consumerKey = parseSha256Hex(input.consumer_event_key, "consumer_event_key");
    const hasOrd =
      input.ordering_domain_id !== undefined ||
      input.ordering_key_sha256 !== undefined ||
      input.ordering_sequence !== undefined;
    if (hasOrd) {
      orderingDomainId = parseOrderingDomainId(input.ordering_domain_id, "ordering_domain_id");
      orderingKeySha256 = parseSha256Hex(input.ordering_key_sha256, "ordering_key_sha256");
      orderingSequence = parsePositiveInt64String(input.ordering_sequence, "ordering_sequence");
    }
  } else {
    if (input.signing_policy_version !== "0") {
      throw new ValidationDomainError({
        code: "INVALID_VALUE",
        message: "endpoint_verification signing_policy_version must be '0'"
      });
    }
    signingPolicyVersion = "0";
    verificationId = parseEndpointVerificationIntentId(input.verification_id, "verification_id");
  }

  const preimage = encodeDomainLengthPrefixed("rq.webhook-signature.v1", [
    version,
    input.purpose,
    keyId,
    method,
    input.external_authority,
    input.request_target,
    projectId,
    eventId,
    subscriptionId,
    endpointId,
    endpointVersion,
    signingPolicyVersion,
    deliveryId,
    deliveryGeneration,
    attemptId,
    verificationId,
    timestampSeconds,
    consumerKey,
    orderingDomainId,
    orderingKeySha256,
    orderingSequence,
    traceparent,
    tracestate,
    wireBodySha,
    input.raw_wire_body_bytes
  ]);

  if (preimage.length > WEBHOOK_MAX_PREIMAGE_BYTES) {
    throw new ValidationDomainError({
      code: "PAYLOAD_TOO_LARGE",
      message: `Webhook signature preimage (${preimage.length} bytes) exceeds ${WEBHOOK_MAX_PREIMAGE_BYTES} bytes`
    });
  }
  return preimage;
}

export function buildEndpointProofPreimage(input: {
  readonly verification_intent_id: EndpointVerificationIntentId | string;
  readonly endpoint_id: EndpointId | string;
  readonly endpoint_version: PositiveInt64String | string;
  readonly configuration_sha256: Sha256Hex | string;
  readonly key_id: KeyId | string;
  readonly public_nonce: Base64UrlString | string;
  readonly verification_attempt_id: AttemptId | string;
  readonly request_timestamp_seconds: NonNegativeInt64String | string;
  readonly request_wire_body_sha256: Sha256Hex | string;
}): Uint8Array {
  const nonceBytes = decodeBase64UrlStrict(input.public_nonce, "public_nonce", {
    exactByteLength: 32
  });
  return encodeDomainLengthPrefixed("rq.endpoint-proof.v1", [
    parseEndpointVerificationIntentId(input.verification_intent_id, "verification_intent_id"),
    parseEndpointId(input.endpoint_id, "endpoint_id"),
    parsePositiveInt64String(input.endpoint_version, "endpoint_version"),
    parseSha256Hex(input.configuration_sha256, "configuration_sha256"),
    parseKeyId(input.key_id, "key_id"),
    nonceBytes,
    parseAttemptId(input.verification_attempt_id, "verification_attempt_id"),
    parseNonNegativeInt64String(input.request_timestamp_seconds, "request_timestamp_seconds"),
    parseSha256Hex(input.request_wire_body_sha256, "request_wire_body_sha256")
  ]);
}

export function buildReceiverReceiptPreimage(input: {
  readonly key_id: KeyId | string;
  readonly project_id: ProjectId | string;
  readonly event_id: EventId | string;
  readonly consumer_event_key: Sha256Hex | string;
  readonly original_facts_sha256: Sha256Hex | string;
  readonly receipt_id: string;
  readonly business_status: "committed";
  readonly committed_at: CanonicalUtcTimestamp | string;
  readonly delivery_attempt_id: AttemptId | string;
  readonly request_wire_body_sha256: Sha256Hex | string;
}): Uint8Array {
  if (input.business_status !== "committed") {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Receipt business_status must be "committed"`
    });
  }
  const receiptId = input.receipt_id.toLowerCase();
  if (!CANONICAL_UUID_LOWER_REGEX.test(receiptId)) {
    throw new ValidationDomainError({
      code: "INVALID_UUID",
      message: "Invalid receipt_id UUID"
    });
  }
  return encodeDomainLengthPrefixed("rq.receiver-receipt.v1", [
    parseKeyId(input.key_id, "key_id"),
    parseProjectId(input.project_id, "project_id"),
    parseEventId(input.event_id, "event_id"),
    parseSha256Hex(input.consumer_event_key, "consumer_event_key"),
    parseSha256Hex(input.original_facts_sha256, "original_facts_sha256"),
    receiptId,
    "committed",
    parseCanonicalUtcTimestamp(input.committed_at, "committed_at"),
    parseAttemptId(input.delivery_attempt_id, "delivery_attempt_id"),
    parseSha256Hex(input.request_wire_body_sha256, "request_wire_body_sha256")
  ]);
}

export function parseEndpointVerificationBody(
  value: unknown,
  fieldPath = "endpoint_verification"
): EndpointVerificationBodyV1 {
  const rec = assertPlainRecord(value, fieldPath);
  assertAllowedKeys(rec, ENDPOINT_VERIFICATION_KEYS, fieldPath);

  if (rec.envelope_version !== 1) {
    throw new ValidationDomainError({
      code: "UNSUPPORTED_SCHEMA_VERSION",
      message: `Unsupported endpoint_verification envelope_version at ${fieldPath}`,
      fieldErrors: [{ path: `${fieldPath}.envelope_version`, code: "UNSUPPORTED_SCHEMA_VERSION" }]
    });
  }
  if (!isEndpointVerificationPurpose(rec.purpose)) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Invalid endpoint verification purpose at ${fieldPath}.purpose`,
      fieldErrors: [{ path: `${fieldPath}.purpose`, code: "INVALID_VALUE" }]
    });
  }

  const receiverContractSha256 =
    rec.receiver_contract_sha256 !== undefined
      ? parseSha256Hex(rec.receiver_contract_sha256, `${fieldPath}.receiver_contract_sha256`)
      : undefined;

  return Object.freeze({
    envelope_version: 1,
    verification_id: parseEndpointVerificationIntentId(
      rec.verification_id,
      `${fieldPath}.verification_id`
    ),
    endpoint_id: parseEndpointId(rec.endpoint_id, `${fieldPath}.endpoint_id`),
    endpoint_version: parsePositiveInt64String(
      rec.endpoint_version,
      `${fieldPath}.endpoint_version`
    ),
    key_id: parseKeyId(rec.key_id, `${fieldPath}.key_id`),
    purpose: rec.purpose,
    public_nonce: parseStrictBase64Url(rec.public_nonce, `${fieldPath}.public_nonce`, {
      exactByteLength: 32
    }).encoded,
    configuration_sha256: parseSha256Hex(
      rec.configuration_sha256,
      `${fieldPath}.configuration_sha256`
    ),
    ...(receiverContractSha256 !== undefined
      ? { receiver_contract_sha256: receiverContractSha256 }
      : {})
  });
}

export function serializeEndpointVerificationBody(
  input: EndpointVerificationBodyV1
): {
  readonly body: EndpointVerificationBodyV1;
  readonly body_json: string;
  readonly body_bytes: Uint8Array;
  readonly body_sha256: Sha256Hex;
} {
  const validated = parseEndpointVerificationBody(input);
  const bodyJson = canonicalizeJson(
    validated as unknown as CanonicalJsonValue,
    "endpoint_verification"
  );
  const bodyBytes = encodeUtf8Bytes(bodyJson, "endpoint_verification");
  if (bodyBytes.length > WEBHOOK_MAX_BODY_BYTES) {
    throw new ValidationDomainError({
      code: "PAYLOAD_TOO_LARGE",
      message: `Endpoint verification body exceeds ${WEBHOOK_MAX_BODY_BYTES} bytes`
    });
  }
  return Object.freeze({
    body: validated,
    body_json: bodyJson,
    body_bytes: bodyBytes,
    body_sha256: sha256Hex(bodyBytes)
  });
}

export function decodeEndpointVerificationBodyBytes(
  rawBytes: Uint8Array
): EndpointVerificationBodyV1 {
  if (!(rawBytes instanceof Uint8Array) || rawBytes.length === 0 || rawBytes.length > WEBHOOK_MAX_BODY_BYTES) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: "Invalid endpoint_verification body size"
    });
  }
  const text = decodeUtf8BytesStrict(rawBytes, "endpoint_verification");
  const obj = parseStrictJsonObject(text, {
    fieldPath: "endpoint_verification",
    maxDepth: 4,
    maxNodes: 32
  });
  return parseEndpointVerificationBody(obj, "endpoint_verification");
}

export function parseReceiverLocalCommitReceipt(
  value: unknown,
  fieldPath = "receiver_receipt"
): ReceiverLocalCommitReceiptV1 {
  const rec = assertPlainRecord(value, fieldPath);
  assertAllowedKeys(rec, RECEIPT_V1_KEYS, fieldPath);

  if (rec.receipt_version !== 1) {
    throw new ValidationDomainError({
      code: "UNSUPPORTED_SCHEMA_VERSION",
      message: `Unsupported receipt_version at ${fieldPath}`,
      fieldErrors: [{ path: `${fieldPath}.receipt_version`, code: "UNSUPPORTED_SCHEMA_VERSION" }]
    });
  }
  if (rec.business_status !== "committed") {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Expected business_status="committed" at ${fieldPath}`,
      fieldErrors: [{ path: `${fieldPath}.business_status`, code: "INVALID_VALUE" }]
    });
  }
  if (typeof rec.receipt_id !== "string" || !CANONICAL_UUID_LOWER_REGEX.test(rec.receipt_id.toLowerCase())) {
    throw new ValidationDomainError({
      code: "INVALID_UUID",
      message: `Invalid receipt_id UUID at ${fieldPath}.receipt_id`,
      fieldErrors: [{ path: `${fieldPath}.receipt_id`, code: "INVALID_UUID" }]
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
    receipt_id: rec.receipt_id.toLowerCase(),
    business_status: "committed",
    committed_at: parseCanonicalUtcTimestamp(rec.committed_at, `${fieldPath}.committed_at`),
    delivery_attempt_id: parseAttemptId(
      rec.delivery_attempt_id,
      `${fieldPath}.delivery_attempt_id`
    ),
    key_id: parseKeyId(rec.key_id, `${fieldPath}.key_id`),
    mac: parseStrictBase64Url(rec.mac, `${fieldPath}.mac`, { exactByteLength: 32 }).encoded
  });
}

export function serializeReceiverLocalCommitReceipt(
  input: ReceiverLocalCommitReceiptV1
): { readonly receipt: ReceiverLocalCommitReceiptV1; readonly body_json: string; readonly body_bytes: Uint8Array } {
  const validated = parseReceiverLocalCommitReceipt(input);
  const bodyJson = canonicalizeJson(
    validated as unknown as CanonicalJsonValue,
    "receiver_receipt"
  );
  const bodyBytes = encodeUtf8Bytes(bodyJson, "receiver_receipt");
  if (bodyBytes.length > WEBHOOK_RECEIPT_MAX_BODY_BYTES) {
    throw new ValidationDomainError({
      code: "PAYLOAD_TOO_LARGE",
      message: `Receiver receipt body (${bodyBytes.length} bytes) exceeds ${WEBHOOK_RECEIPT_MAX_BODY_BYTES} bytes`
    });
  }
  return Object.freeze({
    receipt: validated,
    body_json: bodyJson,
    body_bytes: bodyBytes
  });
}

export function decodeReceiverLocalCommitReceiptBytes(
  rawBytes: Uint8Array
): ReceiverLocalCommitReceiptV1 {
  if (!(rawBytes instanceof Uint8Array)) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: "Receiver receipt must be Uint8Array bytes"
    });
  }
  if (rawBytes.length === 0 || rawBytes.length > WEBHOOK_RECEIPT_MAX_BODY_BYTES) {
    throw new ValidationDomainError({
      code: rawBytes.length > WEBHOOK_RECEIPT_MAX_BODY_BYTES ? "PAYLOAD_TOO_LARGE" : "INVALID_VALUE",
      message: `Receiver receipt body size ${rawBytes.length} out of bounds [1, ${WEBHOOK_RECEIPT_MAX_BODY_BYTES}]`
    });
  }
  const text = decodeUtf8BytesStrict(rawBytes, "receiver_receipt");
  const obj = parseStrictJsonObject(text, {
    fieldPath: "receiver_receipt",
    maxDepth: 4,
    maxNodes: 32
  });
  return parseReceiverLocalCommitReceipt(obj, "receiver_receipt");
}
