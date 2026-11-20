import { Temporal } from "@js-temporal/polyfill";
import {
  ValidationDomainError,
  formatInt64,
  formatUtcTimestamp,
  parseInt64BigInt,
  parseUtcTimestamp,
  type CanonicalUtcTimestamp,
  type Sha256Hex
} from "@relayquill/domain";
import { mapPostgresError } from "../errors.js";
import {
  readOptionalInt64BigInt,
  readOptionalString,
  readOptionalUtcTimestamp,
  readRequiredBoolean,
  readRequiredString,
  readRequiredUtcTimestamp,
  readSingleFunctionJsonb,
  sha256HexToBytea,
  toBytea
} from "../mappers.js";
import { type PgQueryResult, type PgTransactionClient } from "../types.js";

export type SqlParamCast =
  | "uuid"
  | "text"
  | "bigint"
  | "integer"
  | "smallint"
  | "boolean"
  | "bytea"
  | "timestamptz"
  | "jsonb";

export type BigIntInput = bigint | string | number;
export type TimestampInput = CanonicalUtcTimestamp | Temporal.Instant | string;

export function toBigIntSqlParam(value: BigIntInput, fieldPath = "bigint"): string {
  return formatInt64(parseInt64BigInt(value, fieldPath), fieldPath);
}

export function toOptionalBigIntSqlParam(
  value: BigIntInput | null | undefined,
  fieldPath = "bigint"
): string | null {
  return value === null || value === undefined ? null : toBigIntSqlParam(value, fieldPath);
}

export function toTimestampSqlParam(
  value: TimestampInput,
  fieldPath = "timestamp"
): CanonicalUtcTimestamp {
  if (value instanceof Temporal.Instant) {
    return formatUtcTimestamp(value, fieldPath);
  }
  return parseUtcTimestamp(value, fieldPath).canonical;
}

export function toOptionalTimestampSqlParam(
  value: TimestampInput | null | undefined,
  fieldPath = "timestamp"
): CanonicalUtcTimestamp | null {
  return value === null || value === undefined ? null : toTimestampSqlParam(value, fieldPath);
}

export function toOptionalSha256ByteaSqlParam(
  value: Sha256Hex | null | undefined,
  fieldPath = "sha256"
): Buffer | null {
  return value === null || value === undefined ? null : sha256HexToBytea(value, fieldPath);
}

export function toOptionalByteaSqlParam(value: Uint8Array | Buffer | null | undefined): Buffer | null {
  return value === null || value === undefined ? null : toBytea(value);
}

export function decodeBase64Field(
  row: Record<string, unknown>,
  column: string,
  fieldPath = column
): Buffer {
  const b64 = readRequiredString(row, column, fieldPath);
  return Buffer.from(b64, "base64");
}

export function decodeOptionalBase64Field(
  row: Record<string, unknown>,
  column: string,
  fieldPath = column
): Buffer | undefined {
  const b64 = readOptionalString(row, column, fieldPath);
  return b64 === undefined ? undefined : Buffer.from(b64, "base64");
}

export async function callJsonbFunction(
  tx: PgTransactionClient,
  qualifiedFunctionName: string,
  casts: readonly SqlParamCast[],
  args: readonly unknown[],
  operation = qualifiedFunctionName
): Promise<Record<string, unknown>> {
  const placeholders = casts.map((cast, index) => `$${index + 1}::${cast}`).join(", ");
  const sql = `SELECT ${qualifiedFunctionName}(${placeholders}) AS result`;
  try {
    const result = await tx.query<Record<string, unknown>>(sql, args);
    return readSingleFunctionJsonb(result, operation, "result");
  } catch (err) {
    throw mapPostgresError(err, { operation });
  }
}

export async function callOptionalJsonbFunction(
  tx: PgTransactionClient,
  qualifiedFunctionName: string,
  casts: readonly SqlParamCast[],
  args: readonly unknown[],
  operation = qualifiedFunctionName
): Promise<Record<string, unknown> | undefined> {
  const placeholders = casts.map((cast, index) => `$${index + 1}::${cast}`).join(", ");
  const sql = `SELECT ${qualifiedFunctionName}(${placeholders}) AS result`;
  let result: PgQueryResult<Record<string, unknown>>;
  try {
    result = await tx.query<Record<string, unknown>>(sql, args);
  } catch (err) {
    throw mapPostgresError(err, { operation });
  }
  const first = result.rows[0];
  if (first === undefined || first["result"] === null || first["result"] === undefined) {
    return undefined;
  }
  return readSingleFunctionJsonb(result, operation, "result");
}

export function readJsonbInt64BigInt(
  payload: Record<string, unknown>,
  key: string,
  operation: string
): bigint {
  const value = payload[key];
  if (typeof value !== "string" && typeof value !== "bigint" && typeof value !== "number") {
    throw new ValidationDomainError({
      code: "INVALID_INT64",
      message: `Expected int64 field "${key}" in ${operation}`,
      fieldErrors: [{ path: `${operation}.${key}`, code: "INVALID_INT64" }]
    });
  }
  return parseInt64BigInt(
    typeof value === "number" ? String(value) : value,
    `${operation}.${key}`
  );
}

export function readJsonbOptionalInt64BigInt(
  payload: Record<string, unknown>,
  key: string,
  operation: string
): bigint | undefined {
  return readOptionalInt64BigInt(payload, key, `${operation}.${key}`);
}

export function readJsonbTimestamp(
  payload: Record<string, unknown>,
  key: string,
  operation: string
): CanonicalUtcTimestamp {
  return readRequiredUtcTimestamp(payload, key, `${operation}.${key}`);
}

export function readJsonbOptionalTimestamp(
  payload: Record<string, unknown>,
  key: string,
  operation: string
): CanonicalUtcTimestamp | undefined {
  return readOptionalUtcTimestamp(payload, key, `${operation}.${key}`);
}

export function readJsonbBoolean(
  payload: Record<string, unknown>,
  key: string,
  operation: string
): boolean {
  return readRequiredBoolean(payload, key, `${operation}.${key}`);
}
