import {
  type AcceptanceStatus,
  type DomainError,
  type DomainErrorCode,
  type EvidenceBoundary,
  MAX_DOMAIN_FIELD_ERRORS,
  type SafeResourceRef,
  ValidationDomainError,
  isAcceptanceStatus,
  isEvidenceBoundary
} from "@relayquill/domain";
import {
  type CanonicalUtcTimestamp,
  type CanonicalUuid,
  type CommandReceiptId,
  type Int64String,
  type NonNegativeInt64String,
  assertAllowedKeys,
  assertPlainRecord,
  parseBooleanField,
  parseBoundedInteger,
  parseBoundedString,
  parseCanonicalUtcTimestamp,
  parseCanonicalUuid,
  parseCommandReceiptId,
  parseInt64String,
  parseNonNegativeInt64String,
  parseSafeCorrelationId,
  parseSafeReasonCode
} from "./values.js";

export const RESPONSE_SCHEMA_VERSION = 1 as const;
export const HTTP_ERROR_MAX_MESSAGE_BYTES = 512 as const;

export interface ResponseMeta {
  readonly request_id: string;
  readonly response_schema_version: typeof RESPONSE_SCHEMA_VERSION;
  readonly observed_at: CanonicalUtcTimestamp;
}

export interface SuccessEnvelope<T> {
  readonly data: T;
  readonly meta: ResponseMeta;
}

export interface PageInfo {
  readonly next_cursor: string | null;
  readonly limit?: number | undefined;
  readonly has_more?: boolean | undefined;
  readonly total?: NonNegativeInt64String | undefined;
}

export interface PaginatedData<T> {
  readonly items: readonly T[];
  readonly page: PageInfo;
}

export interface AcceptedReceiptDto<K extends string = string> {
  readonly id: CommandReceiptId;
  readonly accepted_at: CanonicalUtcTimestamp;
  readonly resource_kind: K;
  readonly resource_id: CanonicalUuid;
  readonly accepted_version: Int64String | null;
}

export interface HttpFieldError {
  readonly path: string;
  readonly code: string;
}

export interface HttpErrorBody {
  readonly code: DomainErrorCode | (string & {});
  readonly message: string;
  readonly retryable: boolean;
  readonly acceptance: AcceptanceStatus;
  readonly boundary?: EvidenceBoundary | undefined;
  readonly field_errors?: readonly HttpFieldError[] | undefined;
  readonly resource_ref?: SafeResourceRef | undefined;
}

export interface ErrorEnvelope {
  readonly error: HttpErrorBody;
  readonly meta: ResponseMeta;
}

export type ClassifiedResponseEnvelope<T> =
  | { readonly supported: true; readonly kind: "success"; readonly envelope: SuccessEnvelope<T> }
  | { readonly supported: true; readonly kind: "error"; readonly envelope: ErrorEnvelope }
  | {
      readonly supported: false;
      readonly reason: "unsupported_response_schema_version" | "malformed_envelope";
      readonly response_schema_version?: number | undefined;
    };

const META_KEYS = new Set(["request_id", "response_schema_version", "observed_at"]);
const SUCCESS_ENVELOPE_KEYS = new Set(["data", "meta"]);
const ERROR_ENVELOPE_KEYS = new Set(["error", "meta"]);
const ERROR_BODY_KEYS = new Set([
  "code",
  "message",
  "retryable",
  "acceptance",
  "boundary",
  "field_errors",
  "resource_ref"
]);
const FIELD_ERROR_KEYS = new Set(["path", "code"]);
const RESOURCE_REF_KEYS = new Set(["kind", "id"]);
const RECEIPT_KEYS = new Set([
  "id",
  "accepted_at",
  "resource_kind",
  "resource_id",
  "accepted_version"
]);
const PAGE_INFO_KEYS = new Set(["next_cursor", "limit", "has_more", "total"]);
const PAGINATED_DATA_KEYS = new Set(["items", "page"]);

export function createResponseMeta(input: {
  readonly request_id: string;
  readonly observed_at: CanonicalUtcTimestamp | string;
}): ResponseMeta {
  return Object.freeze({
    request_id: parseSafeCorrelationId(input.request_id, "meta.request_id"),
    response_schema_version: RESPONSE_SCHEMA_VERSION,
    observed_at: parseCanonicalUtcTimestamp(input.observed_at, "meta.observed_at")
  });
}

export function createSuccessEnvelope<T>(
  data: T,
  meta: {
    readonly request_id: string;
    readonly observed_at: CanonicalUtcTimestamp | string;
  }
): SuccessEnvelope<T> {
  return Object.freeze({
    data,
    meta: createResponseMeta(meta)
  });
}

export function createPaginatedData<T>(input: {
  readonly items: readonly T[];
  readonly next_cursor: string | null;
  readonly limit?: number | undefined;
  readonly has_more?: boolean | undefined;
  readonly total?: NonNegativeInt64String | undefined;
}): PaginatedData<T> {
  const page: PageInfo = Object.freeze({
    next_cursor: input.next_cursor,
    ...(input.limit !== undefined ? { limit: input.limit } : {}),
    ...(input.has_more !== undefined ? { has_more: input.has_more } : {}),
    ...(input.total !== undefined ? { total: input.total } : {})
  });
  return Object.freeze({
    items: Object.freeze([...input.items]),
    page
  });
}

export function errorBodyFromDomainError(error: DomainError): HttpErrorBody {
  const fieldErrors = error.fieldErrors
    ?.slice(0, MAX_DOMAIN_FIELD_ERRORS)
    .map((entry) => Object.freeze({ path: entry.path, code: entry.code }));
  return Object.freeze({
    code: error.code,
    message: error.message,
    retryable: error.retryable,
    acceptance: error.acceptance,
    ...(error.boundary !== undefined ? { boundary: error.boundary } : {}),
    ...(fieldErrors !== undefined && fieldErrors.length > 0
      ? { field_errors: Object.freeze(fieldErrors) }
      : {}),
    ...(error.resourceRef !== undefined ? { resource_ref: Object.freeze({ ...error.resourceRef }) } : {})
  });
}

export function createErrorEnvelope(
  error: HttpErrorBody | DomainError,
  meta: {
    readonly request_id: string;
    readonly observed_at: CanonicalUtcTimestamp | string;
  }
): ErrorEnvelope {
  const errorBody =
    "name" in error && typeof error.code === "string" && error instanceof Error
      ? errorBodyFromDomainError(error)
      : parseHttpErrorBody(error);
  return Object.freeze({
    error: errorBody,
    meta: createResponseMeta(meta)
  });
}

export function mapDomainErrorCodeToHttpStatus(code: DomainErrorCode): number {
  switch (code) {
    case "INVALID_VALUE":
    case "INVALID_UUID":
    case "INVALID_TIMESTAMP":
    case "INVALID_INT64":
    case "INVALID_HASH":
    case "INVALID_IDEMPOTENCY_KEY":
    case "INVALID_BUSINESS_KEY":
    case "INVALID_PRODUCER_NAMESPACE":
    case "INVALID_KEY_ID":
    case "INVALID_EVENT_TYPE_NAME":
    case "INVALID_CREDENTIAL_SELECTOR":
    case "INVALID_CURSOR":
      return 400;
    case "UNAUTHENTICATED":
    case "SIGNATURE_VERIFICATION_FAILED":
      return 401;
    case "QUOTA_HARD_CAP_REACHED":
      return 402;
    case "FORBIDDEN":
    case "EGRESS_POLICY_DENIED":
      return 403;
    case "NOT_FOUND":
      return 404;
    case "PUBLICATION_CONTEXT_CHANGED":
    case "BUSINESS_IDENTITY_CONFLICT":
    case "IDEMPOTENCY_CONFLICT":
    case "VERSION_CONFLICT":
    case "STATE_TRANSITION_NOT_ALLOWED":
    case "ALREADY_TERMINAL":
    case "ALREADY_COMPLETE":
    case "ORIGINAL_EVENT_CONFLICT":
    case "CONSUMER_ORDER_POSITION_CONFLICT":
    case "CONSUMER_ORDER_GAP":
    case "LOCK_CONTENTION":
      return 409;
    case "EXPIRED":
    case "CONTENT_EXPIRED":
    case "CURSOR_EXPIRED":
      return 410;
    case "PAYLOAD_TOO_LARGE":
      return 413;
    case "UNSUPPORTED_SCHEMA_VERSION":
    case "SCHEMA_EVALUATION_LIMIT":
    case "REDIRECT_NOT_ALLOWED":
    case "NO_RETRY_WITHIN_WINDOW":
    case "RETRY_BUDGET_EXHAUSTED":
      return 422;
    case "RATE_LIMITED":
    case "CAPACITY_EXCEEDED":
      return 429;
    case "DEPENDENCY_UNAVAILABLE":
    case "ACCEPTANCE_UNKNOWN":
      return 503;
    case "SECRET_CUSTODY_ERROR":
    case "INVARIANT_VIOLATION":
      return 500;
  }
}

export function parseResponseMeta(value: unknown, fieldPath = "meta"): ResponseMeta {
  const rec = assertPlainRecord(value, fieldPath);
  assertAllowedKeys(rec, META_KEYS, fieldPath);
  const requestId = parseSafeCorrelationId(rec.request_id, `${fieldPath}.request_id`);
  const schemaVersion = parseBoundedInteger(rec.response_schema_version, {
    fieldPath: `${fieldPath}.response_schema_version`,
    min: RESPONSE_SCHEMA_VERSION,
    max: RESPONSE_SCHEMA_VERSION
  });
  if (schemaVersion !== RESPONSE_SCHEMA_VERSION) {
    throw new ValidationDomainError({
      code: "UNSUPPORTED_SCHEMA_VERSION",
      message: `Unsupported response_schema_version ${schemaVersion}`,
      fieldErrors: [{ path: `${fieldPath}.response_schema_version`, code: "UNSUPPORTED_SCHEMA_VERSION" }]
    });
  }
  const observedAt = parseCanonicalUtcTimestamp(rec.observed_at, `${fieldPath}.observed_at`);
  return Object.freeze({
    request_id: requestId,
    response_schema_version: RESPONSE_SCHEMA_VERSION,
    observed_at: observedAt
  });
}

export function parseHttpErrorBody(value: unknown, fieldPath = "error"): HttpErrorBody {
  const rec = assertPlainRecord(value, fieldPath);
  assertAllowedKeys(rec, ERROR_BODY_KEYS, fieldPath);

  const code = parseSafeReasonCode(rec.code, `${fieldPath}.code`);
  const message = parseBoundedString(rec.message, {
    fieldPath: `${fieldPath}.message`,
    minUtf8Bytes: 1,
    maxUtf8Bytes: HTTP_ERROR_MAX_MESSAGE_BYTES,
    rejectControlChars: true
  });
  const retryable = parseBooleanField(rec.retryable, `${fieldPath}.retryable`);
  if (!isAcceptanceStatus(rec.acceptance)) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Invalid acceptance status for ${fieldPath}.acceptance`,
      fieldErrors: [{ path: `${fieldPath}.acceptance`, code: "INVALID_VALUE" }]
    });
  }

  let boundary: EvidenceBoundary | undefined;
  if (rec.boundary !== undefined) {
    if (!isEvidenceBoundary(rec.boundary)) {
      throw new ValidationDomainError({
        code: "INVALID_VALUE",
        message: `Invalid boundary for ${fieldPath}.boundary`,
        fieldErrors: [{ path: `${fieldPath}.boundary`, code: "INVALID_VALUE" }]
      });
    }
    boundary = rec.boundary;
  }

  let fieldErrors: readonly HttpFieldError[] | undefined;
  if (rec.field_errors !== undefined) {
    if (!Array.isArray(rec.field_errors)) {
      throw new ValidationDomainError({
        code: "INVALID_VALUE",
        message: `Expected array for ${fieldPath}.field_errors`,
        fieldErrors: [{ path: `${fieldPath}.field_errors`, code: "INVALID_VALUE" }]
      });
    }
    if (rec.field_errors.length > MAX_DOMAIN_FIELD_ERRORS) {
      throw new ValidationDomainError({
        code: "INVALID_VALUE",
        message: `${fieldPath}.field_errors exceeds maximum ${MAX_DOMAIN_FIELD_ERRORS} entries`,
        fieldErrors: [{ path: `${fieldPath}.field_errors`, code: "INVALID_VALUE" }]
      });
    }
    fieldErrors = Object.freeze(
      rec.field_errors.map((item, idx) => {
        const entry = assertPlainRecord(item, `${fieldPath}.field_errors[${idx}]`);
        assertAllowedKeys(entry, FIELD_ERROR_KEYS, `${fieldPath}.field_errors[${idx}]`);
        return Object.freeze({
          path: parseBoundedString(entry.path, {
            fieldPath: `${fieldPath}.field_errors[${idx}].path`,
            maxUtf8Bytes: 256,
            rejectControlChars: true
          }),
          code: parseSafeReasonCode(entry.code, `${fieldPath}.field_errors[${idx}].code`)
        });
      })
    );
  }

  let resourceRef: SafeResourceRef | undefined;
  if (rec.resource_ref !== undefined) {
    const refRec = assertPlainRecord(rec.resource_ref, `${fieldPath}.resource_ref`);
    assertAllowedKeys(refRec, RESOURCE_REF_KEYS, `${fieldPath}.resource_ref`);
    resourceRef = Object.freeze({
      kind: parseSafeReasonCode(refRec.kind, `${fieldPath}.resource_ref.kind`),
      id: parseCanonicalUuid(refRec.id, `${fieldPath}.resource_ref.id`)
    });
  }

  return Object.freeze({
    code,
    message,
    retryable,
    acceptance: rec.acceptance,
    ...(boundary !== undefined ? { boundary } : {}),
    ...(fieldErrors !== undefined ? { field_errors: fieldErrors } : {}),
    ...(resourceRef !== undefined ? { resource_ref: resourceRef } : {})
  });
}

export function parseSuccessEnvelope<T>(
  value: unknown,
  parseData: (raw: unknown) => T
): SuccessEnvelope<T> {
  const rec = assertPlainRecord(value, "envelope");
  assertAllowedKeys(rec, SUCCESS_ENVELOPE_KEYS, "envelope");
  const meta = parseResponseMeta(rec.meta, "envelope.meta");
  const data = parseData(rec.data);
  return Object.freeze({ data, meta });
}

export function parseErrorEnvelope(value: unknown): ErrorEnvelope {
  const rec = assertPlainRecord(value, "envelope");
  assertAllowedKeys(rec, ERROR_ENVELOPE_KEYS, "envelope");
  const meta = parseResponseMeta(rec.meta, "envelope.meta");
  const error = parseHttpErrorBody(rec.error, "envelope.error");
  return Object.freeze({ error, meta });
}

export function classifyResponseEnvelope<T>(
  value: unknown,
  parseData: (raw: unknown) => T
): ClassifiedResponseEnvelope<T> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return Object.freeze({ supported: false, reason: "malformed_envelope" });
  }
  const rec = value as Record<string, unknown>;
  const rawMeta = rec.meta;
  if (rawMeta === null || typeof rawMeta !== "object" || Array.isArray(rawMeta)) {
    return Object.freeze({ supported: false, reason: "malformed_envelope" });
  }
  const versionRaw = (rawMeta as Record<string, unknown>).response_schema_version;
  if (typeof versionRaw === "number" && versionRaw !== RESPONSE_SCHEMA_VERSION) {
    return Object.freeze({
      supported: false,
      reason: "unsupported_response_schema_version",
      response_schema_version: versionRaw
    });
  }
  if (Object.prototype.hasOwnProperty.call(rec, "error") && !Object.prototype.hasOwnProperty.call(rec, "data")) {
    try {
      return Object.freeze({
        supported: true,
        kind: "error",
        envelope: parseErrorEnvelope(value)
      });
    } catch {
      return Object.freeze({ supported: false, reason: "malformed_envelope" });
    }
  }
  if (Object.prototype.hasOwnProperty.call(rec, "data") && !Object.prototype.hasOwnProperty.call(rec, "error")) {
    try {
      return Object.freeze({
        supported: true,
        kind: "success",
        envelope: parseSuccessEnvelope(value, parseData)
      });
    } catch {
      return Object.freeze({ supported: false, reason: "malformed_envelope" });
    }
  }
  return Object.freeze({ supported: false, reason: "malformed_envelope" });
}

export function parseAcceptedReceipt<K extends string = string>(
  value: unknown,
  expectedKind?: K,
  fieldPath = "receipt"
): AcceptedReceiptDto<K> {
  const rec = assertPlainRecord(value, fieldPath);
  assertAllowedKeys(rec, RECEIPT_KEYS, fieldPath);
  const id = parseCommandReceiptId(rec.id, `${fieldPath}.id`);
  const acceptedAt = parseCanonicalUtcTimestamp(rec.accepted_at, `${fieldPath}.accepted_at`);
  const resourceKind = parseSafeReasonCode(rec.resource_kind, `${fieldPath}.resource_kind`);
  if (expectedKind !== undefined && resourceKind !== expectedKind) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Expected receipt resource_kind "${expectedKind}", got "${resourceKind}"`,
      fieldErrors: [{ path: `${fieldPath}.resource_kind`, code: "INVALID_VALUE" }]
    });
  }
  const resourceId = parseCanonicalUuid(rec.resource_id, `${fieldPath}.resource_id`);
  const acceptedVersion =
    rec.accepted_version === null
      ? null
      : parseInt64String(rec.accepted_version, `${fieldPath}.accepted_version`);

  return Object.freeze({
    id,
    accepted_at: acceptedAt,
    resource_kind: resourceKind as K,
    resource_id: resourceId,
    accepted_version: acceptedVersion
  });
}

export function parsePaginatedData<T>(
  value: unknown,
  parseItem: (raw: unknown, index: number) => T,
  fieldPath = "data"
): PaginatedData<T> {
  const rec = assertPlainRecord(value, fieldPath);
  assertAllowedKeys(rec, PAGINATED_DATA_KEYS, fieldPath);
  if (!Array.isArray(rec.items)) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Expected array for ${fieldPath}.items`,
      fieldErrors: [{ path: `${fieldPath}.items`, code: "INVALID_VALUE" }]
    });
  }
  const pageRec = assertPlainRecord(rec.page, `${fieldPath}.page`);
  assertAllowedKeys(pageRec, PAGE_INFO_KEYS, `${fieldPath}.page`);
  let nextCursor: string | null = null;
  if (pageRec.next_cursor !== null) {
    nextCursor = parseBoundedString(pageRec.next_cursor, {
      fieldPath: `${fieldPath}.page.next_cursor`,
      minUtf8Bytes: 1,
      maxUtf8Bytes: 2048,
      rejectControlChars: true
    });
  }
  const limit =
    pageRec.limit !== undefined
      ? parseBoundedInteger(pageRec.limit, {
          fieldPath: `${fieldPath}.page.limit`,
          min: 1,
          max: 100
        })
      : undefined;
  const hasMore =
    pageRec.has_more !== undefined
      ? parseBooleanField(pageRec.has_more, `${fieldPath}.page.has_more`)
      : undefined;
  const total =
    pageRec.total !== undefined
      ? parseNonNegativeInt64String(pageRec.total, `${fieldPath}.page.total`)
      : undefined;

  const items = Object.freeze(rec.items.map((item, idx) => parseItem(item, idx)));
  return Object.freeze({
    items,
    page: Object.freeze({
      next_cursor: nextCursor,
      ...(limit !== undefined ? { limit } : {}),
      ...(hasMore !== undefined ? { has_more: hasMore } : {}),
      ...(total !== undefined ? { total } : {})
    })
  });
}
