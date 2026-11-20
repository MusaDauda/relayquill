import {
  EVENT_CONTENT_MEDIA_TYPE,
  WEBHOOK_FRESHNESS_FUTURE_SECONDS,
  WEBHOOK_FRESHNESS_PAST_SECONDS,
  WEBHOOK_HEADER_NAMES,
  WEBHOOK_MAX_BODY_BYTES,
  WEBHOOK_MAX_HEADER_BYTES,
  WEBHOOK_MAX_PREIMAGE_BYTES,
  WEBHOOK_PROTOCOL_VERSION,
  WEBHOOK_RECEIPT_MAX_BODY_BYTES,
  type AttemptId,
  type Base64UrlString,
  type DeliveryId,
  type EndpointId,
  type EndpointVerificationIntentId,
  type EventId,
  type NonNegativeInt64String,
  type OrderingDomainId,
  type ParsedWebhookDeliveryHeaders,
  type ParsedWebhookHeaders,
  type ParsedWebhookVerificationHeaders,
  type PositiveInt64String,
  type ProjectId,
  type Sha256Hex,
  type SubscriptionId,
  type WebhookSignatureEntry,
  type WebhookSignaturePreimageInput,
  buildEndpointProofPreimage,
  buildReceiverReceiptPreimage,
  buildWebhookSignaturePreimage,
  decodeBase64UrlStrict,
  encodeBase64Url,
  encodeDomainLengthPrefixed,
  encodeUtf8Bytes,
  formatWebhookSignaturesHeader,
  isWebhookTimestampFresh,
  parseAttemptId,
  parseDeliveryId,
  parseEndpointId,
  parseEndpointVerificationIntentId,
  parseEventId,
  parseKeyId,
  parseNonNegativeInt64String,
  parseOrderingDomainId,
  parsePositiveInt64String,
  parseProjectId,
  parseSha256Hex,
  parseStrictBase64Url,
  parseSubscriptionId,
  parseW3CTraceparent,
  parseW3CTracestate,
  parseWebhookRawHeaders,
  parseWebhookSignaturesHeader
} from "@relayquill/contracts";
import { ValidationDomainError, hasLoneSurrogate, type WebhookPurpose } from "@relayquill/domain";

export const WEBHOOK_SIGNATURE_DOMAIN = "rq.webhook-signature.v1" as const;
export const ENDPOINT_PROOF_DOMAIN = "rq.endpoint-proof.v1" as const;
export const RECEIVER_RECEIPT_DOMAIN = "rq.receiver-receipt.v1" as const;
export const WEBHOOK_KEY_ID_REGEX = /^[a-z0-9][a-z0-9._-]{0,63}$/;
export const REQUEST_TARGET_MAX_ASCII_BYTES = 1024 as const;
export const DEFAULT_FIXTURE_AUTHORITY = "receiver.fixture.test:19095" as const;
export const DEFAULT_FIXTURE_PATH = "/hooks/relayquill" as const;

export {
  WEBHOOK_FRESHNESS_FUTURE_SECONDS,
  WEBHOOK_FRESHNESS_PAST_SECONDS,
  WEBHOOK_HEADER_NAMES,
  WEBHOOK_MAX_BODY_BYTES,
  WEBHOOK_MAX_HEADER_BYTES,
  WEBHOOK_MAX_PREIMAGE_BYTES,
  WEBHOOK_PROTOCOL_VERSION,
  WEBHOOK_RECEIPT_MAX_BODY_BYTES,
  buildEndpointProofPreimage,
  buildReceiverReceiptPreimage,
  isWebhookTimestampFresh,
  parseWebhookSignaturesHeader as parseSignaturesHeader,
  formatWebhookSignaturesHeader as formatSignaturesHeader
};

export type RawHeaderInput = readonly string[] | ReadonlyArray<readonly [string, string]>;

export interface ValidateRawWebhookHeadersOptions {
  readonly requireContentType?: boolean | undefined;
  readonly maxHeaderBytes?: number | undefined;
}

export interface SignedAuthorityValidationOptions {
  readonly allowFixtureAuthority?: boolean | undefined;
  readonly expectedFixtureAuthority?: string | undefined;
}

export interface EndpointProofHeaderValidationResult {
  readonly proofHeader: Base64UrlString;
  readonly proofBytes: Uint8Array;
}

export interface ReceiptResponseHeaderValidationResult {
  readonly contentType: string;
  readonly rawHeaderBytes: number;
}

const SINGLE_OCCURRENCE_FRAMING_HEADERS = new Set<string>([
  "host",
  "content-type",
  "content-encoding",
  "content-length",
  "transfer-encoding",
  "traceparent",
  "tracestate"
]);

const HEADER_NAME_TOKEN_REGEX = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;
const LOWERCASE_DNS_HOST_REGEX =
  /^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/;

function assertValidHeaderString(value: unknown, label: string): string {
  if (typeof value !== "string" || hasLoneSurrogate(value)) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Invalid header string for ${label}`,
      fieldErrors: [{ path: label, code: "INVALID_VALUE" }]
    });
  }
  for (let i = 0; i < value.length; i += 1) {
    const code = value.charCodeAt(i);
    if (code === 0x00 || code === 0x0a || code === 0x0d || (code < 0x20 && code !== 0x09) || code === 0x7f) {
      throw new ValidationDomainError({
        code: "INVALID_VALUE",
        message: `Forbidden control character in ${label}`,
        fieldErrors: [{ path: label, code: "INVALID_VALUE" }]
      });
    }
  }
  return value;
}

export function normalizeRawHeaderPairs(
  rawHeaders: RawHeaderInput,
  maxHeaderBytes: number = WEBHOOK_MAX_HEADER_BYTES
): { readonly pairs: ReadonlyArray<readonly [string, string]>; readonly totalBytes: number } {
  if (!Array.isArray(rawHeaders)) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: "rawHeaders must be an array",
      fieldErrors: [{ path: "rawHeaders", code: "INVALID_VALUE" }]
    });
  }

  const pairs: Array<readonly [string, string]> = [];
  let totalBytes = 0;

  if (rawHeaders.length === 0) {
    return Object.freeze({ pairs: Object.freeze(pairs), totalBytes: 0 });
  }

  const first: unknown = rawHeaders[0];
  if (typeof first === "string") {
    if (rawHeaders.length % 2 !== 0) {
      throw new ValidationDomainError({
        code: "INVALID_VALUE",
        message: "Flat rawHeaders array must have even length",
        fieldErrors: [{ path: "rawHeaders", code: "INVALID_VALUE" }]
      });
    }
    const flat = rawHeaders as readonly string[];
    for (let i = 0; i < flat.length; i += 2) {
      const name = assertValidHeaderString(flat[i], `rawHeaders[${i}]`);
      const value = assertValidHeaderString(flat[i + 1], `rawHeaders[${i + 1}]`);
      if (!HEADER_NAME_TOKEN_REGEX.test(name)) {
        throw new ValidationDomainError({
          code: "INVALID_VALUE",
          message: `Invalid HTTP header name at rawHeaders[${i}]`,
          fieldErrors: [{ path: "rawHeaders", code: "INVALID_VALUE" }]
        });
      }
      totalBytes += encodeUtf8Bytes(name, "header_name").length + encodeUtf8Bytes(value, "header_value").length + 4;
      if (totalBytes > maxHeaderBytes) {
        throw new ValidationDomainError({
          code: "PAYLOAD_TOO_LARGE",
          message: `HTTP header block exceeds ${maxHeaderBytes} bytes`
        });
      }
      pairs.push(Object.freeze([name, value] as const));
    }
  } else {
    const tupleList = rawHeaders as ReadonlyArray<readonly [string, string]>;
    for (let i = 0; i < tupleList.length; i += 1) {
      const entry = tupleList[i];
      if (!Array.isArray(entry) || entry.length !== 2) {
        throw new ValidationDomainError({
          code: "INVALID_VALUE",
          message: `rawHeaders[${i}] must be a [name, value] pair`,
          fieldErrors: [{ path: `rawHeaders[${i}]`, code: "INVALID_VALUE" }]
        });
      }
      const name = assertValidHeaderString(entry[0], `rawHeaders[${i}][0]`);
      const value = assertValidHeaderString(entry[1], `rawHeaders[${i}][1]`);
      if (!HEADER_NAME_TOKEN_REGEX.test(name)) {
        throw new ValidationDomainError({
          code: "INVALID_VALUE",
          message: `Invalid HTTP header name at rawHeaders[${i}][0]`,
          fieldErrors: [{ path: `rawHeaders[${i}][0]`, code: "INVALID_VALUE" }]
        });
      }
      totalBytes += encodeUtf8Bytes(name, "header_name").length + encodeUtf8Bytes(value, "header_value").length + 4;
      if (totalBytes > maxHeaderBytes) {
        throw new ValidationDomainError({
          code: "PAYLOAD_TOO_LARGE",
          message: `HTTP header block exceeds ${maxHeaderBytes} bytes`
        });
      }
      pairs.push(Object.freeze([name, value] as const));
    }
  }

  return Object.freeze({ pairs: Object.freeze(pairs), totalBytes });
}

function assertSingleOccurrenceMap(
  pairs: ReadonlyArray<readonly [string, string]>,
  additionalSingleNames: ReadonlySet<string> = new Set()
): Map<string, string> {
  const seen = new Map<string, string>();
  for (const [rawName, rawValue] of pairs) {
    const lower = rawName.toLowerCase();
    const isProtected =
      SINGLE_OCCURRENCE_FRAMING_HEADERS.has(lower) ||
      lower.startsWith("relayquill-") ||
      additionalSingleNames.has(lower);
    if (isProtected) {
      if (seen.has(lower)) {
        throw new ValidationDomainError({
          code: "INVALID_VALUE",
          message: `Duplicate protected header "${rawName}" is forbidden`,
          fieldErrors: [{ path: lower, code: "INVALID_VALUE" }]
        });
      }
      seen.set(lower, rawValue);
    }
  }
  return seen;
}

function assertStrictJsonContentType(rawValue: string | undefined, required: boolean): string {
  if (rawValue === undefined) {
    if (required) {
      throw new ValidationDomainError({
        code: "INVALID_VALUE",
        message: "Missing required Content-Type application/json header",
        fieldErrors: [{ path: "content-type", code: "INVALID_VALUE" }]
      });
    }
    return EVENT_CONTENT_MEDIA_TYPE;
  }
  if (rawValue.includes(",")) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: "Coalesced or multi-value Content-Type header is forbidden",
      fieldErrors: [{ path: "content-type", code: "INVALID_VALUE" }]
    });
  }
  const segments = rawValue.split(";");
  const mediaType = segments[0]?.trim().toLowerCase();
  if (mediaType !== EVENT_CONTENT_MEDIA_TYPE) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Unsupported Content-Type "${rawValue}"`,
      fieldErrors: [{ path: "content-type", code: "INVALID_VALUE" }]
    });
  }
  for (let i = 1; i < segments.length; i += 1) {
    const param = segments[i]!.trim().toLowerCase();
    if (param.length === 0) {
      throw new ValidationDomainError({
        code: "INVALID_VALUE",
        message: "Malformed empty Content-Type parameter",
        fieldErrors: [{ path: "content-type", code: "INVALID_VALUE" }]
      });
    }
    if (param !== "charset=utf-8" && param !== 'charset="utf-8"') {
      throw new ValidationDomainError({
        code: "INVALID_VALUE",
        message: `Unsupported Content-Type parameter "${param}"`,
        fieldErrors: [{ path: "content-type", code: "INVALID_VALUE" }]
      });
    }
  }
  return rawValue;
}

export function validateRawWebhookHeaders(
  rawHeaders: RawHeaderInput,
  options: ValidateRawWebhookHeadersOptions = {}
): ParsedWebhookHeaders {
  const maxHeaderBytes = options.maxHeaderBytes ?? WEBHOOK_MAX_HEADER_BYTES;
  const { pairs } = normalizeRawHeaderPairs(rawHeaders, maxHeaderBytes);
  const singleMap = assertSingleOccurrenceMap(pairs);

  if (singleMap.has(WEBHOOK_HEADER_NAMES.endpointProof.toLowerCase())) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `${WEBHOOK_HEADER_NAMES.endpointProof} is not permitted on webhook requests`,
      fieldErrors: [{ path: WEBHOOK_HEADER_NAMES.endpointProof, code: "INVALID_VALUE" }]
    });
  }

  assertStrictJsonContentType(
    singleMap.get("content-type"),
    options.requireContentType ?? true
  );

  // Reject any coalesced single-valued security header before downstream contract parsing.
  for (const [name, value] of singleMap.entries()) {
    if (
      name.startsWith("relayquill-") &&
      name !== WEBHOOK_HEADER_NAMES.signatures.toLowerCase() &&
      value.includes(",")
    ) {
      throw new ValidationDomainError({
        code: "INVALID_VALUE",
        message: `Coalesced value in single-valued header "${name}" is forbidden`,
        fieldErrors: [{ path: name, code: "INVALID_VALUE" }]
      });
    }
  }

  normalizeOptionalTraceContext(
    singleMap.get(WEBHOOK_HEADER_NAMES.traceparent.toLowerCase()),
    singleMap.get(WEBHOOK_HEADER_NAMES.tracestate.toLowerCase())
  );

  return parseWebhookRawHeaders(pairs);
}

export function validateRawEndpointProofResponseHeaders(
  rawHeaders: RawHeaderInput,
  maxHeaderBytes = WEBHOOK_MAX_HEADER_BYTES
): EndpointProofHeaderValidationResult {
  const { pairs } = normalizeRawHeaderPairs(rawHeaders, maxHeaderBytes);
  const singleMap = assertSingleOccurrenceMap(pairs);

  if (singleMap.has("content-encoding")) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: "Content-Encoding is forbidden on endpoint verification 204 response",
      fieldErrors: [{ path: "content-encoding", code: "INVALID_VALUE" }]
    });
  }

  const contentLength = singleMap.get("content-length");
  if (contentLength !== undefined && contentLength.trim() !== "0") {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: "Endpoint verification 204 response must have zero Content-Length",
      fieldErrors: [{ path: "content-length", code: "INVALID_VALUE" }]
    });
  }

  const rawProof = singleMap.get(WEBHOOK_HEADER_NAMES.endpointProof.toLowerCase());
  if (rawProof === undefined || rawProof.length === 0 || rawProof.includes(",")) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Missing or invalid ${WEBHOOK_HEADER_NAMES.endpointProof} header`,
      fieldErrors: [{ path: WEBHOOK_HEADER_NAMES.endpointProof, code: "INVALID_VALUE" }]
    });
  }

  const decoded = parseStrictBase64Url(rawProof, WEBHOOK_HEADER_NAMES.endpointProof, {
    exactByteLength: 32
  });
  return Object.freeze({
    proofHeader: decoded.encoded,
    proofBytes: decoded.bytes
  });
}

export function validateRawReceiptResponseHeaders(
  rawHeaders: RawHeaderInput,
  maxHeaderBytes = WEBHOOK_MAX_HEADER_BYTES
): ReceiptResponseHeaderValidationResult {
  const { pairs, totalBytes } = normalizeRawHeaderPairs(rawHeaders, maxHeaderBytes);
  const singleMap = assertSingleOccurrenceMap(pairs);

  if (singleMap.has("content-encoding")) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: "Content-Encoding is unsupported on verified receipt responses",
      fieldErrors: [{ path: "content-encoding", code: "INVALID_VALUE" }]
    });
  }

  const contentType = assertStrictJsonContentType(singleMap.get("content-type"), true);
  return Object.freeze({
    contentType,
    rawHeaderBytes: totalBytes
  });
}

export function validateSignedExternalAuthority(
  authority: unknown,
  options: SignedAuthorityValidationOptions = {}
): string {
  if (typeof authority !== "string" || authority.length === 0 || hasLoneSurrogate(authority)) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: "external_authority must be a non-empty normalized host:port",
      fieldErrors: [{ path: "external_authority", code: "INVALID_VALUE" }]
    });
  }
  for (let i = 0; i < authority.length; i += 1) {
    const c = authority.charCodeAt(i);
    if (c <= 0x20 || c >= 0x7f) {
      throw new ValidationDomainError({
        code: "INVALID_VALUE",
        message: "external_authority contains non-ASCII or control characters",
        fieldErrors: [{ path: "external_authority", code: "INVALID_VALUE" }]
      });
    }
  }
  if (
    authority.includes("/") ||
    authority.includes("\\") ||
    authority.includes("?") ||
    authority.includes("#") ||
    authority.includes("@")
  ) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: "external_authority must contain only normalized hostname:port",
      fieldErrors: [{ path: "external_authority", code: "INVALID_VALUE" }]
    });
  }

  const colonIdx = authority.lastIndexOf(":");
  if (colonIdx <= 0 || colonIdx === authority.length - 1 || authority.indexOf(":") !== colonIdx) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: "external_authority must use explicit host:port format",
      fieldErrors: [{ path: "external_authority", code: "INVALID_VALUE" }]
    });
  }

  const host = authority.slice(0, colonIdx);
  const portStr = authority.slice(colonIdx + 1);
  if (!LOWERCASE_DNS_HOST_REGEX.test(host)) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: "external_authority hostname must be lowercase multi-label DNS name",
      fieldErrors: [{ path: "external_authority", code: "INVALID_VALUE" }]
    });
  }

  if (options.allowFixtureAuthority === true) {
    const expectedFixture = options.expectedFixtureAuthority ?? DEFAULT_FIXTURE_AUTHORITY;
    if (authority === expectedFixture) {
      return authority;
    }
  }

  if (portStr !== "443") {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: "Release external_authority must bind port :443",
      fieldErrors: [{ path: "external_authority", code: "INVALID_VALUE" }]
    });
  }
  return authority;
}

export function validateSignedRequestTarget(requestTarget: unknown): string {
  if (
    typeof requestTarget !== "string" ||
    requestTarget.length === 0 ||
    requestTarget.length > REQUEST_TARGET_MAX_ASCII_BYTES ||
    hasLoneSurrogate(requestTarget)
  ) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `request_target must be 1..${REQUEST_TARGET_MAX_ASCII_BYTES} ASCII bytes`,
      fieldErrors: [{ path: "request_target", code: "INVALID_VALUE" }]
    });
  }
  if (!requestTarget.startsWith("/")) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: "request_target must start with '/'",
      fieldErrors: [{ path: "request_target", code: "INVALID_VALUE" }]
    });
  }
  for (let i = 0; i < requestTarget.length; i += 1) {
    const c = requestTarget.charCodeAt(i);
    if (c <= 0x20 || c >= 0x7f) {
      throw new ValidationDomainError({
        code: "INVALID_VALUE",
        message: "request_target contains invalid or non-printable ASCII characters",
        fieldErrors: [{ path: "request_target", code: "INVALID_VALUE" }]
      });
    }
  }
  if (
    requestTarget.includes("?") ||
    requestTarget.includes("#") ||
    requestTarget.includes("\\") ||
    requestTarget.includes("//")
  ) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: "request_target must not contain queries, fragments, backslashes, or repeated slashes",
      fieldErrors: [{ path: "request_target", code: "INVALID_VALUE" }]
    });
  }
  for (let i = 0; i < requestTarget.length; i += 1) {
    if (requestTarget.charCodeAt(i) === 0x25) {
      const hex = requestTarget.slice(i + 1, i + 3);
      if (!/^[0-9A-F]{2}$/.test(hex)) {
        throw new ValidationDomainError({
          code: "INVALID_VALUE",
          message: "request_target percent escapes must use uppercase hex digits",
          fieldErrors: [{ path: "request_target", code: "INVALID_VALUE" }]
        });
      }
      const byteVal = Number.parseInt(hex, 16);
      if (byteVal === 0x25 || byteVal === 0x2f || byteVal === 0x5c || byteVal < 0x20 || byteVal === 0x7f) {
        throw new ValidationDomainError({
          code: "INVALID_VALUE",
          message: "request_target contains forbidden percent-encoded separator, control, or %25 escape",
          fieldErrors: [{ path: "request_target", code: "INVALID_VALUE" }]
        });
      }
      i += 2;
    }
  }
  for (const segment of requestTarget.slice(1).split("/")) {
    if (segment === "." || segment === "..") {
      throw new ValidationDomainError({
        code: "INVALID_VALUE",
        message: "request_target must not contain dot segments",
        fieldErrors: [{ path: "request_target", code: "INVALID_VALUE" }]
      });
    }
  }
  return requestTarget;
}

export function encodeLengthPrefixedPreimage(
  domain: string,
  fields: readonly (string | Uint8Array)[],
  maxBytes = WEBHOOK_MAX_PREIMAGE_BYTES
): Uint8Array {
  const preimage = encodeDomainLengthPrefixed(domain, fields);
  if (preimage.length > maxBytes) {
    throw new ValidationDomainError({
      code: "PAYLOAD_TOO_LARGE",
      message: `Preimage (${preimage.length} bytes) exceeds max ${maxBytes} bytes`
    });
  }
  return preimage;
}

export function encodeWebhookSignaturePreimage(
  input: WebhookSignaturePreimageInput,
  options: SignedAuthorityValidationOptions = {}
): Uint8Array {
  validateSignedExternalAuthority(input.external_authority, options);
  validateSignedRequestTarget(input.request_target);
  const normalizedTrace = normalizeOptionalTraceContext(input.traceparent, input.tracestate);
  return buildWebhookSignaturePreimage({
    ...input,
    traceparent: normalizedTrace.traceparent,
    tracestate: normalizedTrace.tracestate
  });
}

export interface NormalizedOptionalTraceContext {
  readonly traceparent?: string | undefined;
  readonly tracestate?: string | undefined;
}

export function normalizeOptionalTraceContext(
  traceparent: string | undefined,
  tracestate: string | undefined
): NormalizedOptionalTraceContext {
  const normalizedRawParent =
    traceparent !== undefined && traceparent.length > 0 ? traceparent : undefined;
  const normalizedRawState =
    tracestate !== undefined && tracestate.length > 0 ? tracestate : undefined;

  if (normalizedRawParent === undefined) {
    if (normalizedRawState !== undefined) {
      throw new ValidationDomainError({
        code: "INVALID_VALUE",
        message: "tracestate requires traceparent",
        fieldErrors: [{ path: WEBHOOK_HEADER_NAMES.tracestate, code: "INVALID_VALUE" }]
      });
    }
    return Object.freeze({});
  }

  const normalizedTraceparent = parseW3CTraceparent(
    normalizedRawParent,
    WEBHOOK_HEADER_NAMES.traceparent
  ).raw;
  const normalizedTracestate =
    normalizedRawState !== undefined
      ? parseW3CTracestate(normalizedRawState, WEBHOOK_HEADER_NAMES.tracestate)
      : undefined;

  return Object.freeze({
    traceparent: normalizedTraceparent,
    ...(normalizedTracestate !== undefined ? { tracestate: normalizedTracestate } : {})
  });
}

export interface SerializeDeliveryHeadersInput {
  readonly projectId: ProjectId | string;
  readonly eventId: EventId | string;
  readonly subscriptionId: SubscriptionId | string;
  readonly endpointId: EndpointId | string;
  readonly endpointVersion: PositiveInt64String | string;
  readonly deliveryId: DeliveryId | string;
  readonly deliveryGeneration: NonNegativeInt64String | string;
  readonly attemptId: AttemptId | string;
  readonly signingPolicyVersion: PositiveInt64String | string;
  readonly timestampSeconds: NonNegativeInt64String | string;
  readonly consumerEventKey: Sha256Hex | string;
  readonly bodySha256: Sha256Hex | string;
  readonly signaturesHeader: string;
  readonly ordering?: {
    readonly orderingDomainId: OrderingDomainId | string;
    readonly orderingKeySha256: Sha256Hex | string;
    readonly orderingSequence: PositiveInt64String | string;
  } | undefined;
  readonly traceparent?: string | undefined;
  readonly tracestate?: string | undefined;
}

export function serializeWebhookDeliveryHeaders(input: SerializeDeliveryHeadersInput): {
  readonly headers: Readonly<Record<string, string>>;
  readonly rawHeaderPairs: ReadonlyArray<readonly [string, string]>;
} {
  parseWebhookSignaturesHeader(input.signaturesHeader, WEBHOOK_HEADER_NAMES.signatures);
  const pairs: Array<readonly [string, string]> = [
    ["Content-Type", EVENT_CONTENT_MEDIA_TYPE],
    [WEBHOOK_HEADER_NAMES.version, WEBHOOK_PROTOCOL_VERSION],
    [WEBHOOK_HEADER_NAMES.purpose, "delivery"],
    [WEBHOOK_HEADER_NAMES.projectId, parseProjectId(input.projectId, WEBHOOK_HEADER_NAMES.projectId)],
    [WEBHOOK_HEADER_NAMES.eventId, parseEventId(input.eventId, WEBHOOK_HEADER_NAMES.eventId)],
    [
      WEBHOOK_HEADER_NAMES.subscriptionId,
      parseSubscriptionId(input.subscriptionId, WEBHOOK_HEADER_NAMES.subscriptionId)
    ],
    [WEBHOOK_HEADER_NAMES.endpointId, parseEndpointId(input.endpointId, WEBHOOK_HEADER_NAMES.endpointId)],
    [
      WEBHOOK_HEADER_NAMES.endpointVersion,
      parsePositiveInt64String(input.endpointVersion, WEBHOOK_HEADER_NAMES.endpointVersion)
    ],
    [WEBHOOK_HEADER_NAMES.deliveryId, parseDeliveryId(input.deliveryId, WEBHOOK_HEADER_NAMES.deliveryId)],
    [
      WEBHOOK_HEADER_NAMES.deliveryGeneration,
      parseNonNegativeInt64String(input.deliveryGeneration, WEBHOOK_HEADER_NAMES.deliveryGeneration)
    ],
    [WEBHOOK_HEADER_NAMES.attemptId, parseAttemptId(input.attemptId, WEBHOOK_HEADER_NAMES.attemptId)],
    [
      WEBHOOK_HEADER_NAMES.signingPolicy,
      parsePositiveInt64String(input.signingPolicyVersion, WEBHOOK_HEADER_NAMES.signingPolicy)
    ],
    [
      WEBHOOK_HEADER_NAMES.timestamp,
      parseNonNegativeInt64String(input.timestampSeconds, WEBHOOK_HEADER_NAMES.timestamp)
    ],
    [
      WEBHOOK_HEADER_NAMES.consumerKey,
      parseSha256Hex(input.consumerEventKey, WEBHOOK_HEADER_NAMES.consumerKey)
    ],
    [WEBHOOK_HEADER_NAMES.bodySha256, parseSha256Hex(input.bodySha256, WEBHOOK_HEADER_NAMES.bodySha256)],
    [WEBHOOK_HEADER_NAMES.signatures, input.signaturesHeader]
  ];

  if (input.ordering !== undefined) {
    pairs.push(
      [
        WEBHOOK_HEADER_NAMES.orderingDomain,
        parseOrderingDomainId(input.ordering.orderingDomainId, WEBHOOK_HEADER_NAMES.orderingDomain)
      ],
      [
        WEBHOOK_HEADER_NAMES.orderingKey,
        parseSha256Hex(input.ordering.orderingKeySha256, WEBHOOK_HEADER_NAMES.orderingKey)
      ],
      [
        WEBHOOK_HEADER_NAMES.orderingSequence,
        parsePositiveInt64String(input.ordering.orderingSequence, WEBHOOK_HEADER_NAMES.orderingSequence)
      ]
    );
  }

  const traceContext = normalizeOptionalTraceContext(input.traceparent, input.tracestate);
  if (traceContext.traceparent !== undefined) {
    pairs.push([WEBHOOK_HEADER_NAMES.traceparent, traceContext.traceparent]);
    if (traceContext.tracestate !== undefined) {
      pairs.push([WEBHOOK_HEADER_NAMES.tracestate, traceContext.tracestate]);
    }
  }

  const headers: Record<string, string> = {};
  for (const [k, v] of pairs) {
    headers[k] = v;
  }

  return Object.freeze({
    headers: Object.freeze(headers),
    rawHeaderPairs: Object.freeze(pairs.map((pair) => Object.freeze(pair)))
  });
}

export interface SerializeVerificationHeadersInput {
  readonly verificationId: EndpointVerificationIntentId | string;
  readonly projectId: ProjectId | string;
  readonly endpointId: EndpointId | string;
  readonly endpointVersion: PositiveInt64String | string;
  readonly attemptId: AttemptId | string;
  readonly timestampSeconds: NonNegativeInt64String | string;
  readonly bodySha256: Sha256Hex | string;
  readonly signaturesHeader: string;
  readonly traceparent?: string | undefined;
  readonly tracestate?: string | undefined;
}

export function serializeEndpointVerificationHeaders(input: SerializeVerificationHeadersInput): {
  readonly headers: Readonly<Record<string, string>>;
  readonly rawHeaderPairs: ReadonlyArray<readonly [string, string]>;
} {
  const entries = parseWebhookSignaturesHeader(input.signaturesHeader, WEBHOOK_HEADER_NAMES.signatures);
  if (entries.length !== 1) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: "endpoint_verification requires exactly 1 signature entry",
      fieldErrors: [{ path: WEBHOOK_HEADER_NAMES.signatures, code: "INVALID_VALUE" }]
    });
  }

  const pairs: Array<readonly [string, string]> = [
    ["Content-Type", EVENT_CONTENT_MEDIA_TYPE],
    [WEBHOOK_HEADER_NAMES.version, WEBHOOK_PROTOCOL_VERSION],
    [WEBHOOK_HEADER_NAMES.purpose, "endpoint_verification"],
    [
      WEBHOOK_HEADER_NAMES.verificationId,
      parseEndpointVerificationIntentId(input.verificationId, WEBHOOK_HEADER_NAMES.verificationId)
    ],
    [WEBHOOK_HEADER_NAMES.projectId, parseProjectId(input.projectId, WEBHOOK_HEADER_NAMES.projectId)],
    [WEBHOOK_HEADER_NAMES.endpointId, parseEndpointId(input.endpointId, WEBHOOK_HEADER_NAMES.endpointId)],
    [
      WEBHOOK_HEADER_NAMES.endpointVersion,
      parsePositiveInt64String(input.endpointVersion, WEBHOOK_HEADER_NAMES.endpointVersion)
    ],
    [WEBHOOK_HEADER_NAMES.attemptId, parseAttemptId(input.attemptId, WEBHOOK_HEADER_NAMES.attemptId)],
    [WEBHOOK_HEADER_NAMES.signingPolicy, "0"],
    [
      WEBHOOK_HEADER_NAMES.timestamp,
      parseNonNegativeInt64String(input.timestampSeconds, WEBHOOK_HEADER_NAMES.timestamp)
    ],
    [WEBHOOK_HEADER_NAMES.bodySha256, parseSha256Hex(input.bodySha256, WEBHOOK_HEADER_NAMES.bodySha256)],
    [WEBHOOK_HEADER_NAMES.signatures, input.signaturesHeader]
  ];

  const traceContext = normalizeOptionalTraceContext(input.traceparent, input.tracestate);
  if (traceContext.traceparent !== undefined) {
    pairs.push([WEBHOOK_HEADER_NAMES.traceparent, traceContext.traceparent]);
    if (traceContext.tracestate !== undefined) {
      pairs.push([WEBHOOK_HEADER_NAMES.tracestate, traceContext.tracestate]);
    }
  }

  const headers: Record<string, string> = {};
  for (const [k, v] of pairs) {
    headers[k] = v;
  }

  return Object.freeze({
    headers: Object.freeze(headers),
    rawHeaderPairs: Object.freeze(pairs.map((pair) => Object.freeze(pair)))
  });
}

export type {
  ParsedWebhookDeliveryHeaders,
  ParsedWebhookHeaders,
  ParsedWebhookVerificationHeaders,
  WebhookPurpose,
  WebhookSignatureEntry,
  WebhookSignaturePreimageInput
};
export { decodeBase64UrlStrict, encodeBase64Url, parseKeyId };
