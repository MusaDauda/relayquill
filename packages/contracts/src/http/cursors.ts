import {
  ExpiredDomainError,
  ValidationDomainError,
  createEnumGuard
} from "@relayquill/domain";
import { type CanonicalJsonValue, canonicalizeJsonBytes, hashCanonicalJson } from "../canonical-command.js";
import {
  type Base64UrlString,
  type CanonicalUtcTimestamp,
  type CanonicalUuid,
  type Int64String,
  type ProjectId,
  type Sha256Hex,
  type TenantId,
  assertAllowedKeys,
  assertPlainRecord,
  constantTimeEqual,
  decodeBase64UrlStrict,
  decodeUtf8BytesStrict,
  encodeBase64Url,
  encodeUtf8Bytes,
  hmacSha256Digest,
  parseBoundedInteger,
  parseCanonicalUtcTimestamp,
  parseCanonicalUuid,
  parseInt64BigInt,
  parseInt64String,
  parseProjectId,
  parseSha256Hex,
  parseStrictBase64Url,
  parseStrictJsonObject,
  parseTenantId,
  parseUtcTimestamp
} from "./values.js";

export const CURSOR_FORMAT_VERSION = 1 as const;
export const CURSOR_MAX_DECODED_BYTES = 1024 as const;
const CURSOR_MAC_DOMAIN = "rq.cursor.v1\0";

export const CURSOR_RESOURCE_KINDS = [
  "events",
  "event_history",
  "deliveries",
  "delivery_history",
  "attempts",
  "receiver_receipts",
  "ordering_keys",
  "ordering_members",
  "replay_proposals",
  "audit",
  "watch_events",
  "watch_deliveries"
] as const;

export type CursorResourceKind = (typeof CURSOR_RESOURCE_KINDS)[number];
export const isCursorResourceKind = createEnumGuard(CURSOR_RESOURCE_KINDS);

export const CURSOR_SORT_ORDERS = [
  "project_event_sequence_desc",
  "created_at_desc_id_desc",
  "event_sequence_asc",
  "history_sequence_asc",
  "attempt_number_asc",
  "ordering_sequence_asc",
  "observed_at_desc_id_desc"
] as const;

export type CursorSortOrder = (typeof CURSOR_SORT_ORDERS)[number];
export const isCursorSortOrder = createEnumGuard(CURSOR_SORT_ORDERS);

export interface CursorBoundary {
  readonly sequence?: Int64String | undefined;
  readonly timestamp?: CanonicalUtcTimestamp | undefined;
  readonly id?: CanonicalUuid | undefined;
}

export interface CursorPayloadV1 {
  readonly v: typeof CURSOR_FORMAT_VERSION;
  readonly resource: CursorResourceKind;
  readonly tenant_id: TenantId | null;
  readonly project_id: ProjectId | null;
  readonly parent_id: CanonicalUuid | null;
  readonly order: CursorSortOrder;
  readonly filter_sha256: Sha256Hex;
  readonly boundary: CursorBoundary;
  readonly snapshot_cutoff_at?: CanonicalUtcTimestamp | undefined;
  readonly mac?: Base64UrlString | undefined;
}

export interface ExpectedCursorContext {
  readonly resource: CursorResourceKind;
  readonly tenant_id: TenantId | string | null;
  readonly project_id: ProjectId | string | null;
  readonly parent_id?: CanonicalUuid | string | null | undefined;
  readonly order: CursorSortOrder;
  readonly filter_sha256: Sha256Hex | string;
}

export interface RetainedCursorFloor {
  readonly min_sequence?: bigint | Int64String | undefined;
  readonly min_timestamp?: CanonicalUtcTimestamp | string | undefined;
}

const CURSOR_PAYLOAD_KEYS = new Set([
  "v",
  "resource",
  "tenant_id",
  "project_id",
  "parent_id",
  "order",
  "filter_sha256",
  "boundary",
  "snapshot_cutoff_at",
  "mac"
]);

const CURSOR_BOUNDARY_KEYS = new Set(["sequence", "timestamp", "id"]);

function invalidCursorError(message: string): ValidationDomainError {
  return new ValidationDomainError({
    code: "INVALID_CURSOR",
    message,
    fieldErrors: [{ path: "cursor", code: "INVALID_CURSOR" }]
  });
}

export function computeCursorFilterSha256(filterObject: CanonicalJsonValue): Sha256Hex {
  return hashCanonicalJson(filterObject, "cursor_filter").sha256;
}

function buildUnsignedCursorObject(payload: Omit<CursorPayloadV1, "mac">): CanonicalJsonValue {
  const boundaryObj: Record<string, CanonicalJsonValue> = {};
  if (payload.boundary.sequence !== undefined) {
    boundaryObj.sequence = payload.boundary.sequence;
  }
  if (payload.boundary.timestamp !== undefined) {
    boundaryObj.timestamp = payload.boundary.timestamp;
  }
  if (payload.boundary.id !== undefined) {
    boundaryObj.id = payload.boundary.id;
  }

  const out: Record<string, CanonicalJsonValue> = {
    v: payload.v,
    resource: payload.resource,
    tenant_id: payload.tenant_id,
    project_id: payload.project_id,
    parent_id: payload.parent_id,
    order: payload.order,
    filter_sha256: payload.filter_sha256,
    boundary: boundaryObj
  };
  if (payload.snapshot_cutoff_at !== undefined) {
    out.snapshot_cutoff_at = payload.snapshot_cutoff_at;
  }
  return out;
}

function computeCursorMac(signingKey: Uint8Array, unsignedObj: CanonicalJsonValue): Base64UrlString {
  if (!(signingKey instanceof Uint8Array) || signingKey.length === 0) {
    throw new ValidationDomainError({
      code: "SECRET_CUSTODY_ERROR",
      message: "Cursor signing key must be non-empty bytes"
    });
  }
  const domainBytes = encodeUtf8Bytes(CURSOR_MAC_DOMAIN, "cursor_domain");
  const payloadBytes = canonicalizeJsonBytes(unsignedObj, "cursor");
  const preimage = new Uint8Array(domainBytes.length + payloadBytes.length);
  preimage.set(domainBytes, 0);
  preimage.set(payloadBytes, domainBytes.length);
  return encodeBase64Url(hmacSha256Digest(signingKey, preimage));
}

function validateAndNormalizeCursorInput(
  input: Omit<CursorPayloadV1, "v" | "mac"> & { readonly v?: 1 | undefined }
): Omit<CursorPayloadV1, "mac"> {
  if (input.v !== undefined && input.v !== CURSOR_FORMAT_VERSION) {
    throw invalidCursorError(`Unsupported cursor version ${String(input.v)}`);
  }
  if (!isCursorResourceKind(input.resource)) {
    throw invalidCursorError(`Invalid cursor resource "${String(input.resource)}"`);
  }
  if (!isCursorSortOrder(input.order)) {
    throw invalidCursorError(`Invalid cursor order "${String(input.order)}"`);
  }

  const tenantId = input.tenant_id === null ? null : parseTenantId(input.tenant_id, "cursor.tenant_id");
  const projectId = input.project_id === null ? null : parseProjectId(input.project_id, "cursor.project_id");
  const parentId = input.parent_id === null ? null : parseCanonicalUuid(input.parent_id, "cursor.parent_id");

  if (projectId !== null && tenantId === null) {
    throw invalidCursorError("Cursor with project_id requires tenant_id");
  }

  const filterSha256 = parseSha256Hex(input.filter_sha256, "cursor.filter_sha256");

  const boundaryRec = assertPlainRecord(input.boundary, "cursor.boundary");
  assertAllowedKeys(boundaryRec, CURSOR_BOUNDARY_KEYS, "cursor.boundary");
  const sequence =
    boundaryRec.sequence !== undefined
      ? parseInt64String(boundaryRec.sequence, "cursor.boundary.sequence")
      : undefined;
  const timestamp =
    boundaryRec.timestamp !== undefined
      ? parseCanonicalUtcTimestamp(boundaryRec.timestamp, "cursor.boundary.timestamp")
      : undefined;
  const id =
    boundaryRec.id !== undefined
      ? parseCanonicalUuid(boundaryRec.id, "cursor.boundary.id")
      : undefined;

  if (sequence === undefined && timestamp === undefined && id === undefined) {
    throw invalidCursorError("Cursor boundary must include at least one key");
  }

  const snapshotCutoffAt =
    input.snapshot_cutoff_at !== undefined
      ? parseCanonicalUtcTimestamp(input.snapshot_cutoff_at, "cursor.snapshot_cutoff_at")
      : undefined;

  return Object.freeze({
    v: CURSOR_FORMAT_VERSION,
    resource: input.resource,
    tenant_id: tenantId,
    project_id: projectId,
    parent_id: parentId,
    order: input.order,
    filter_sha256: filterSha256,
    boundary: Object.freeze({
      ...(sequence !== undefined ? { sequence } : {}),
      ...(timestamp !== undefined ? { timestamp } : {}),
      ...(id !== undefined ? { id } : {})
    }),
    ...(snapshotCutoffAt !== undefined ? { snapshot_cutoff_at: snapshotCutoffAt } : {})
  });
}

export function encodeCursor(
  input: Omit<CursorPayloadV1, "v" | "mac"> & { readonly v?: 1 | undefined },
  options?: { readonly signingKey?: Uint8Array | undefined }
): Base64UrlString {
  let normalized: Omit<CursorPayloadV1, "mac">;
  try {
    normalized = validateAndNormalizeCursorInput(input);
  } catch (err) {
    if (err instanceof ValidationDomainError) {
      throw invalidCursorError(err.message);
    }
    throw err;
  }

  const unsignedObj = buildUnsignedCursorObject(normalized);
  const fullObj: Record<string, CanonicalJsonValue> = {
    ...(unsignedObj as Record<string, CanonicalJsonValue>)
  };
  if (options?.signingKey !== undefined) {
    fullObj.mac = computeCursorMac(options.signingKey, unsignedObj);
  }

  const jsonBytes = canonicalizeJsonBytes(fullObj, "cursor");
  if (jsonBytes.length > CURSOR_MAX_DECODED_BYTES) {
    throw invalidCursorError(
      `Encoded cursor decoded payload (${jsonBytes.length} bytes) exceeds ${CURSOR_MAX_DECODED_BYTES} bytes`
    );
  }
  return encodeBase64Url(jsonBytes);
}

export function decodeCursor(
  rawCursor: unknown,
  expectedContext: ExpectedCursorContext,
  options?: {
    readonly signingKey?: Uint8Array | undefined;
    readonly retainedFloor?: RetainedCursorFloor | undefined;
  }
): CursorPayloadV1 {
  if (typeof rawCursor !== "string" || rawCursor.length === 0 || rawCursor.length > 1400) {
    throw invalidCursorError("Malformed or oversized cursor");
  }

  let decodedBytes: Uint8Array;
  try {
    decodedBytes = decodeBase64UrlStrict(rawCursor, "cursor", {
      maxDecodedBytes: CURSOR_MAX_DECODED_BYTES
    });
  } catch {
    throw invalidCursorError("Malformed cursor encoding");
  }

  let jsonText: string;
  let parsedObj: Record<string, unknown>;
  try {
    jsonText = decodeUtf8BytesStrict(decodedBytes, "cursor");
    parsedObj = parseStrictJsonObject(jsonText, {
      fieldPath: "cursor",
      maxDepth: 6,
      maxNodes: 64
    });
    assertAllowedKeys(parsedObj, CURSOR_PAYLOAD_KEYS, "cursor");
  } catch {
    throw invalidCursorError("Malformed cursor payload");
  }

  let v: number;
  try {
    v = parseBoundedInteger(parsedObj.v, {
      fieldPath: "cursor.v",
      min: CURSOR_FORMAT_VERSION,
      max: CURSOR_FORMAT_VERSION
    });
  } catch {
    throw invalidCursorError("Unsupported cursor version");
  }
  if (v !== CURSOR_FORMAT_VERSION) {
    throw invalidCursorError("Unsupported cursor version");
  }

  let normalizedUnsigned: Omit<CursorPayloadV1, "mac">;
  try {
    normalizedUnsigned = validateAndNormalizeCursorInput({
      v: CURSOR_FORMAT_VERSION,
      resource: parsedObj.resource as CursorResourceKind,
      tenant_id: parsedObj.tenant_id as TenantId | null,
      project_id: parsedObj.project_id as ProjectId | null,
      parent_id: parsedObj.parent_id as CanonicalUuid | null,
      order: parsedObj.order as CursorSortOrder,
      filter_sha256: parsedObj.filter_sha256 as Sha256Hex,
      boundary: parsedObj.boundary as CursorBoundary,
      ...(parsedObj.snapshot_cutoff_at !== undefined
        ? { snapshot_cutoff_at: parsedObj.snapshot_cutoff_at as CanonicalUtcTimestamp }
        : {})
    });
  } catch {
    throw invalidCursorError("Invalid cursor metadata");
  }

  let mac: Base64UrlString | undefined;
  if (parsedObj.mac !== undefined) {
    try {
      mac = parseStrictBase64Url(parsedObj.mac, "cursor.mac", { exactByteLength: 32 }).encoded;
    } catch {
      throw invalidCursorError("Invalid cursor integrity tag");
    }
  }

  if (options?.signingKey !== undefined) {
    if (mac === undefined) {
      throw invalidCursorError("Missing required cursor integrity tag");
    }
    const expectedMac = computeCursorMac(
      options.signingKey,
      buildUnsignedCursorObject(normalizedUnsigned)
    );
    const actualMacBytes = decodeBase64UrlStrict(mac, "cursor.mac", { exactByteLength: 32 });
    const expectedMacBytes = decodeBase64UrlStrict(expectedMac, "cursor.mac", {
      exactByteLength: 32
    });
    if (!constantTimeEqual(actualMacBytes, expectedMacBytes)) {
      throw invalidCursorError("Invalid cursor integrity tag");
    }
  }

  const expectedTenant =
    expectedContext.tenant_id === null
      ? null
      : parseTenantId(expectedContext.tenant_id, "expected_context.tenant_id");
  const expectedProject =
    expectedContext.project_id === null
      ? null
      : parseProjectId(expectedContext.project_id, "expected_context.project_id");
  const expectedParent =
    expectedContext.parent_id === undefined || expectedContext.parent_id === null
      ? null
      : parseCanonicalUuid(expectedContext.parent_id, "expected_context.parent_id");
  const expectedFilter = parseSha256Hex(
    expectedContext.filter_sha256,
    "expected_context.filter_sha256"
  );

  if (
    normalizedUnsigned.resource !== expectedContext.resource ||
    normalizedUnsigned.tenant_id !== expectedTenant ||
    normalizedUnsigned.project_id !== expectedProject ||
    normalizedUnsigned.parent_id !== expectedParent ||
    normalizedUnsigned.order !== expectedContext.order ||
    normalizedUnsigned.filter_sha256 !== expectedFilter
  ) {
    throw invalidCursorError("Cursor does not match requested scope, order, or filter");
  }

  const result: CursorPayloadV1 = Object.freeze({
    ...normalizedUnsigned,
    ...(mac !== undefined ? { mac } : {})
  });

  if (options?.retainedFloor !== undefined) {
    assertCursorNotExpired(result, options.retainedFloor);
  }

  return result;
}

export function assertCursorNotExpired(
  cursor: CursorPayloadV1,
  floor: RetainedCursorFloor
): void {
  if (floor.min_sequence !== undefined && cursor.boundary.sequence !== undefined) {
    const minSeq = parseInt64BigInt(floor.min_sequence, "retained_floor.min_sequence");
    const cursorSeq = parseInt64BigInt(cursor.boundary.sequence, "cursor.boundary.sequence");
    if (cursorSeq < minSeq) {
      throw new ExpiredDomainError({
        code: "CURSOR_EXPIRED",
        message: "Cursor boundary is older than retained sequence floor"
      });
    }
  }
  if (floor.min_timestamp !== undefined) {
    const minParsed = parseUtcTimestamp(floor.min_timestamp, "retained_floor.min_timestamp");
    const cursorTimeStr = cursor.boundary.timestamp ?? cursor.snapshot_cutoff_at;
    if (cursorTimeStr !== undefined) {
      const cursorParsed = parseUtcTimestamp(cursorTimeStr, "cursor.timestamp");
      if (cursorParsed.epochMicroseconds < minParsed.epochMicroseconds) {
        throw new ExpiredDomainError({
          code: "CURSOR_EXPIRED",
          message: "Cursor boundary is older than retained timestamp floor"
        });
      }
    }
  }
}
