import { type Temporal } from "@js-temporal/polyfill";
import {
  InvariantViolationError,
  NotFoundDomainError,
  ValidationDomainError,
  formatInt64,
  parseCanonicalUuid,
  parseInt64BigInt,
  parseSha256Hex,
  parseUtcTimestamp,
  type CanonicalUtcTimestamp,
  type CanonicalUuid,
  type Int64String,
  type Sha256Hex
} from "@relayquill/domain";
import { bytesToLowerHex, sha256HexToBytes } from "@relayquill/contracts";
import { parsePgTimestampToCanonicalUtc } from "./parsers.js";
import { type PgQueryResult } from "./types.js";

const INT32_MIN = -2_147_483_648;
const INT32_MAX = 2_147_483_647;
const PG_HEX_BYTEA_REGEX = /^\\x([0-9a-fA-F]*)$/;

export function toBytea(value: Uint8Array | Buffer): Buffer {
  return Buffer.isBuffer(value)
    ? value
    : Buffer.from(value.buffer, value.byteOffset, value.byteLength);
}

export function sha256HexToBytea(hex: Sha256Hex, fieldPath = "sha256"): Buffer {
  return toBytea(sha256HexToBytes(parseSha256Hex(hex, fieldPath)));
}

export function optionalSha256HexToBytea(
  hex: Sha256Hex | null | undefined,
  fieldPath = "sha256"
): Buffer | null {
  return hex === null || hex === undefined ? null : sha256HexToBytea(hex, fieldPath);
}

export function byteaToBuffer(value: unknown, fieldPath = "bytea"): Buffer {
  if (Buffer.isBuffer(value)) {
    return value;
  }
  if (value instanceof Uint8Array) {
    return toBytea(value);
  }
  if (typeof value === "string") {
    const match = PG_HEX_BYTEA_REGEX.exec(value);
    if (match !== null && match[1] !== undefined && match[1].length % 2 === 0) {
      return Buffer.from(match[1], "hex");
    }
  }
  throw new ValidationDomainError({
    code: "INVALID_VALUE",
    message: `Expected bytea value for ${fieldPath}`,
    fieldErrors: [{ path: fieldPath, code: "INVALID_VALUE" }]
  });
}

export function byteaToSha256Hex(value: unknown, fieldPath = "sha256"): Sha256Hex {
  if (typeof value === "string" && !value.startsWith("\\x")) {
    return parseSha256Hex(value, fieldPath);
  }
  const bytes = byteaToBuffer(value, fieldPath);
  if (bytes.byteLength !== 32) {
    throw new ValidationDomainError({
      code: "INVALID_HASH",
      message: `Expected 32-byte SHA-256 digest for ${fieldPath}, received ${bytes.byteLength} bytes`,
      fieldErrors: [{ path: fieldPath, code: "INVALID_HASH" }]
    });
  }
  return parseSha256Hex(bytesToLowerHex(bytes), fieldPath);
}

export function optionalByteaToSha256Hex(
  value: unknown,
  fieldPath = "sha256"
): Sha256Hex | undefined {
  if (value === null || value === undefined) {
    return undefined;
  }
  return byteaToSha256Hex(value, fieldPath);
}

export function readRequiredString(
  row: Record<string, unknown>,
  column: string,
  fieldPath = column
): string {
  const value = row[column];
  if (typeof value !== "string") {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Expected string for ${fieldPath}`,
      fieldErrors: [{ path: fieldPath, code: "INVALID_VALUE" }]
    });
  }
  return value;
}

export function readOptionalString(
  row: Record<string, unknown>,
  column: string,
  fieldPath = column
): string | undefined {
  const value = row[column];
  if (value === null || value === undefined) {
    return undefined;
  }
  if (typeof value !== "string") {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Expected string or null for ${fieldPath}`,
      fieldErrors: [{ path: fieldPath, code: "INVALID_VALUE" }]
    });
  }
  return value;
}

export function readRequiredBoolean(
  row: Record<string, unknown>,
  column: string,
  fieldPath = column
): boolean {
  const value = row[column];
  if (typeof value !== "boolean") {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Expected boolean for ${fieldPath}`,
      fieldErrors: [{ path: fieldPath, code: "INVALID_VALUE" }]
    });
  }
  return value;
}

export function readOptionalBoolean(
  row: Record<string, unknown>,
  column: string,
  fieldPath = column
): boolean | undefined {
  const value = row[column];
  if (value === null || value === undefined) {
    return undefined;
  }
  if (typeof value !== "boolean") {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Expected boolean or null for ${fieldPath}`,
      fieldErrors: [{ path: fieldPath, code: "INVALID_VALUE" }]
    });
  }
  return value;
}

export function readRequiredInt32(
  row: Record<string, unknown>,
  column: string,
  fieldPath = column
): number {
  const value = row[column];
  if (typeof value === "number") {
    if (!Number.isInteger(value) || value < INT32_MIN || value > INT32_MAX) {
      throw new ValidationDomainError({
        code: "INVALID_VALUE",
        message: `Integer out of 32-bit bounds for ${fieldPath}`,
        fieldErrors: [{ path: fieldPath, code: "INVALID_VALUE" }]
      });
    }
    return value;
  }
  if (typeof value === "string" && /^-?\d+$/.test(value.trim())) {
    const parsed = Number(value.trim());
    if (Number.isInteger(parsed) && parsed >= INT32_MIN && parsed <= INT32_MAX) {
      return parsed;
    }
  }
  throw new ValidationDomainError({
    code: "INVALID_VALUE",
    message: `Expected 32-bit integer for ${fieldPath}`,
    fieldErrors: [{ path: fieldPath, code: "INVALID_VALUE" }]
  });
}

export function readOptionalInt32(
  row: Record<string, unknown>,
  column: string,
  fieldPath = column
): number | undefined {
  const value = row[column];
  if (value === null || value === undefined) {
    return undefined;
  }
  return readRequiredInt32(row, column, fieldPath);
}

export function readRequiredInt64BigInt(
  row: Record<string, unknown>,
  column: string,
  fieldPath = column
): bigint {
  return parseInt64BigInt(row[column], fieldPath);
}

export function readOptionalInt64BigInt(
  row: Record<string, unknown>,
  column: string,
  fieldPath = column
): bigint | undefined {
  const value = row[column];
  if (value === null || value === undefined) {
    return undefined;
  }
  return parseInt64BigInt(value, fieldPath);
}

export function readRequiredInt64String(
  row: Record<string, unknown>,
  column: string,
  fieldPath = column
): Int64String {
  return formatInt64(parseInt64BigInt(row[column], fieldPath), fieldPath);
}

export function readOptionalInt64String(
  row: Record<string, unknown>,
  column: string,
  fieldPath = column
): Int64String | undefined {
  const value = row[column];
  if (value === null || value === undefined) {
    return undefined;
  }
  return readRequiredInt64String(row, column, fieldPath);
}

export function readRequiredUtcTimestamp(
  row: Record<string, unknown>,
  column: string,
  fieldPath = column
): CanonicalUtcTimestamp {
  const value = row[column];
  if (typeof value !== "string") {
    throw new ValidationDomainError({
      code: "INVALID_TIMESTAMP",
      message: `Expected timestamp string for ${fieldPath}; Date objects are forbidden`,
      fieldErrors: [{ path: fieldPath, code: "INVALID_TIMESTAMP" }]
    });
  }
  try {
    return parseUtcTimestamp(value, fieldPath).canonical;
  } catch {
    return parsePgTimestampToCanonicalUtc(value, false, fieldPath);
  }
}

export function readOptionalUtcTimestamp(
  row: Record<string, unknown>,
  column: string,
  fieldPath = column
): CanonicalUtcTimestamp | undefined {
  const value = row[column];
  if (value === null || value === undefined) {
    return undefined;
  }
  return readRequiredUtcTimestamp(row, column, fieldPath);
}

export function readRequiredInstant(
  row: Record<string, unknown>,
  column: string,
  fieldPath = column
): Temporal.Instant {
  const canonical = readRequiredUtcTimestamp(row, column, fieldPath);
  return parseUtcTimestamp(canonical, fieldPath).instant;
}

export function readOptionalInstant(
  row: Record<string, unknown>,
  column: string,
  fieldPath = column
): Temporal.Instant | undefined {
  const value = row[column];
  if (value === null || value === undefined) {
    return undefined;
  }
  return readRequiredInstant(row, column, fieldPath);
}

export function readRequiredUuid<T extends CanonicalUuid = CanonicalUuid>(
  row: Record<string, unknown>,
  column: string,
  parser: (value: unknown, fieldPath?: string) => T = parseCanonicalUuid as (
    value: unknown,
    fieldPath?: string
  ) => T,
  fieldPath = column
): T {
  return parser(row[column], fieldPath);
}

export function readOptionalUuid<T extends CanonicalUuid = CanonicalUuid>(
  row: Record<string, unknown>,
  column: string,
  parser: (value: unknown, fieldPath?: string) => T = parseCanonicalUuid as (
    value: unknown,
    fieldPath?: string
  ) => T,
  fieldPath = column
): T | undefined {
  const value = row[column];
  if (value === null || value === undefined) {
    return undefined;
  }
  return parser(value, fieldPath);
}

export function readRequiredEnum<T extends string>(
  row: Record<string, unknown>,
  column: string,
  allowed: readonly T[],
  fieldPath = column
): T {
  const value = readRequiredString(row, column, fieldPath);
  if (!allowed.includes(value as T)) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Unexpected enum value "${value}" for ${fieldPath}`,
      fieldErrors: [{ path: fieldPath, code: "INVALID_VALUE" }]
    });
  }
  return value as T;
}

export function readOptionalEnum<T extends string>(
  row: Record<string, unknown>,
  column: string,
  allowed: readonly T[],
  fieldPath = column
): T | undefined {
  const value = row[column];
  if (value === null || value === undefined) {
    return undefined;
  }
  return readRequiredEnum(row, column, allowed, fieldPath);
}

export function readRequiredJsonRecord(
  row: Record<string, unknown>,
  column: string,
  fieldPath = column
): Record<string, unknown> {
  const raw = row[column];
  let parsed: unknown = raw;
  if (typeof raw === "string") {
    try {
      parsed = JSON.parse(raw) as unknown;
    } catch {
      throw new ValidationDomainError({
        code: "INVALID_VALUE",
        message: `Invalid JSON payload in column ${fieldPath}`,
        fieldErrors: [{ path: fieldPath, code: "INVALID_VALUE" }]
      });
    }
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Expected JSON object for ${fieldPath}`,
      fieldErrors: [{ path: fieldPath, code: "INVALID_VALUE" }]
    });
  }
  return parsed as Record<string, unknown>;
}

export function readOptionalJsonRecord(
  row: Record<string, unknown>,
  column: string,
  fieldPath = column
): Record<string, unknown> | undefined {
  const raw = row[column];
  if (raw === null || raw === undefined) {
    return undefined;
  }
  return readRequiredJsonRecord(row, column, fieldPath);
}

export function assertSingleRow<TRow extends Record<string, unknown>>(
  result: PgQueryResult<TRow>,
  operation: string
): TRow {
  const first = result.rows[0];
  if (first === undefined) {
    throw new NotFoundDomainError({
      code: "NOT_FOUND",
      message: `${operation} returned no rows`
    });
  }
  if (result.rows.length > 1) {
    throw new InvariantViolationError({
      code: "INVARIANT_VIOLATION",
      message: `${operation} expected 1 row, received ${result.rows.length}`
    });
  }
  return first;
}

export function readSingleFunctionJsonb(
  result: PgQueryResult<Record<string, unknown>>,
  operation: string,
  column = "result"
): Record<string, unknown> {
  const row = assertSingleRow(result, operation);
  return readRequiredJsonRecord(row, column, `${operation}.${column}`);
}
