import { Temporal } from "@js-temporal/polyfill";
import pg from "pg";
import {
  ValidationDomainError,
  formatInt64,
  formatUtcTimestamp,
  parseInt64BigInt,
  type CanonicalUtcTimestamp,
  type Int64String
} from "@relayquill/domain";

export const PG_OID_INT8 = 20 as const;
export const PG_OID_INT8_ARRAY = 1016 as const;
export const PG_OID_TIMESTAMP = 1114 as const;
export const PG_OID_TIMESTAMP_ARRAY = 1115 as const;
export const PG_OID_TIMESTAMPTZ = 1184 as const;
export const PG_OID_TIMESTAMPTZ_ARRAY = 1185 as const;

const PG_TIMESTAMP_TEXT_REGEX =
  /^(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}:\d{2})(?:\.(\d+))?(?:([Zz])|([+-])(\d{2})(?::?(\d{2}))?(?::?(\d{2}))?)?$/;

/**
 * Converts a PostgreSQL `timestamp` (OID 1114) or `timestamptz` (OID 1184) wire string
 * to a canonical 6-fractional-digit UTC RFC3339 string using Temporal without `Date`.
 */
export function parsePgTimestampToCanonicalUtc(
  raw: string,
  assumeUtc: boolean,
  fieldPath = "pg_timestamp"
): CanonicalUtcTimestamp {
  const trimmed = raw.trim();
  if (trimmed.length === 0 || trimmed === "infinity" || trimmed === "-infinity") {
    throw new ValidationDomainError({
      code: "INVALID_TIMESTAMP",
      message: `Unsupported PostgreSQL timestamp value for ${fieldPath}`,
      fieldErrors: [{ path: fieldPath, code: "INVALID_TIMESTAMP" }]
    });
  }

  const match = PG_TIMESTAMP_TEXT_REGEX.exec(trimmed);
  if (match === null) {
    throw new ValidationDomainError({
      code: "INVALID_TIMESTAMP",
      message: `Unrecognized PostgreSQL timestamp wire format for ${fieldPath}`,
      fieldErrors: [{ path: fieldPath, code: "INVALID_TIMESTAMP" }]
    });
  }

  const datePart = match[1];
  const timePart = match[2];
  const fracRaw = match[3] ?? "";
  const zuluPart = match[4];
  const offsetSign = match[5];
  const offsetHour = match[6];
  const offsetMin = match[7] ?? "00";
  const offsetSec = match[8];

  if (datePart === undefined || timePart === undefined) {
    throw new ValidationDomainError({
      code: "INVALID_TIMESTAMP",
      message: `Malformed PostgreSQL timestamp components for ${fieldPath}`,
      fieldErrors: [{ path: fieldPath, code: "INVALID_TIMESTAMP" }]
    });
  }

  if (fracRaw.length > 6) {
    throw new ValidationDomainError({
      code: "INVALID_TIMESTAMP",
      message: `PostgreSQL timestamp ${fieldPath} exceeds microsecond precision`,
      fieldErrors: [{ path: fieldPath, code: "INVALID_TIMESTAMP" }]
    });
  }

  if (offsetSec !== undefined && offsetSec !== "00") {
    throw new ValidationDomainError({
      code: "INVALID_TIMESTAMP",
      message: `PostgreSQL timestamp ${fieldPath} uses sub-minute UTC offset`,
      fieldErrors: [{ path: fieldPath, code: "INVALID_TIMESTAMP" }]
    });
  }

  const fracPadded = fracRaw.length > 0 ? `.${fracRaw.padEnd(6, "0")}` : "";
  let offsetSuffix: string;
  if (zuluPart !== undefined) {
    offsetSuffix = "Z";
  } else if (offsetSign !== undefined && offsetHour !== undefined) {
    offsetSuffix =
      offsetSign === "+" && offsetHour === "00" && offsetMin === "00"
        ? "Z"
        : `${offsetSign}${offsetHour}:${offsetMin}`;
  } else if (assumeUtc) {
    offsetSuffix = "Z";
  } else {
    throw new ValidationDomainError({
      code: "INVALID_TIMESTAMP",
      message: `PostgreSQL timestamptz ${fieldPath} is missing UTC offset`,
      fieldErrors: [{ path: fieldPath, code: "INVALID_TIMESTAMP" }]
    });
  }

  try {
    const instant = Temporal.Instant.from(`${datePart}T${timePart}${fracPadded}${offsetSuffix}`);
    return formatUtcTimestamp(instant, fieldPath);
  } catch (err) {
    if (err instanceof ValidationDomainError) {
      throw err;
    }
    throw new ValidationDomainError({
      code: "INVALID_TIMESTAMP",
      message: `Invalid PostgreSQL timestamp value for ${fieldPath}`,
      fieldErrors: [{ path: fieldPath, code: "INVALID_TIMESTAMP" }]
    });
  }
}

/**
 * Validates a PostgreSQL `int8` (OID 20) wire string and returns its canonical decimal string.
 */
export function parsePgInt8String(raw: string, fieldPath = "pg_int8"): Int64String {
  return formatInt64(parseInt64BigInt(raw.trim(), fieldPath), fieldPath);
}

/**
 * Parses a one-dimensional PostgreSQL text-encoded array literal (`{...}`).
 */
export function parsePgArrayLiteral<T>(
  raw: string,
  parseElement: (element: string) => T,
  fieldPath = "pg_array"
): readonly (T | null)[] {
  const trimmed = raw.trim();
  if (!trimmed.startsWith("{") || !trimmed.endsWith("}")) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Malformed PostgreSQL array literal for ${fieldPath}`,
      fieldErrors: [{ path: fieldPath, code: "INVALID_VALUE" }]
    });
  }
  const inner = trimmed.slice(1, -1);
  if (inner.length === 0) {
    return [];
  }

  const out: (T | null)[] = [];
  let index = 0;

  while (index < inner.length) {
    if (inner[index] === '"') {
      index += 1;
      let token = "";
      let closed = false;
      while (index < inner.length) {
        const ch = inner[index];
        if (ch === "\\") {
          index += 1;
          if (index >= inner.length) {
            throw new ValidationDomainError({
              code: "INVALID_VALUE",
              message: `Unterminated escape inside PostgreSQL array for ${fieldPath}`
            });
          }
          token += inner[index] ?? "";
          index += 1;
          continue;
        }
        if (ch === '"') {
          closed = true;
          index += 1;
          break;
        }
        token += ch ?? "";
        index += 1;
      }
      if (!closed) {
        throw new ValidationDomainError({
          code: "INVALID_VALUE",
          message: `Unterminated quoted element in PostgreSQL array for ${fieldPath}`
        });
      }
      out.push(parseElement(token));
      if (index < inner.length) {
        if (inner[index] !== ",") {
          throw new ValidationDomainError({
            code: "INVALID_VALUE",
            message: `Expected comma separator in PostgreSQL array for ${fieldPath}`
          });
        }
        index += 1;
      }
      continue;
    }

    const nextComma = inner.indexOf(",", index);
    const token = nextComma === -1 ? inner.slice(index) : inner.slice(index, nextComma);
    out.push(token === "NULL" ? null : parseElement(token));
    if (nextComma === -1) {
      break;
    }
    index = nextComma + 1;
  }

  return out;
}

export function parsePgTimestamptz(raw: string): CanonicalUtcTimestamp {
  return parsePgTimestampToCanonicalUtc(raw, false, "timestamptz");
}

export function parsePgTimestamp(raw: string): CanonicalUtcTimestamp {
  return parsePgTimestampToCanonicalUtc(raw, true, "timestamp");
}

export function parsePgInt8(raw: string): Int64String {
  return parsePgInt8String(raw, "int8");
}

export const RELAYQUILL_PGLITE_PARSERS: Readonly<Record<number, (value: string) => unknown>> =
  Object.freeze({
    [PG_OID_TIMESTAMPTZ]: parsePgTimestamptz,
    [PG_OID_TIMESTAMP]: parsePgTimestamp,
    [PG_OID_INT8]: parsePgInt8,
    [PG_OID_TIMESTAMPTZ_ARRAY]: (raw: string) =>
      parsePgArrayLiteral(raw, parsePgTimestamptz, "timestamptz[]"),
    [PG_OID_TIMESTAMP_ARRAY]: (raw: string) =>
      parsePgArrayLiteral(raw, parsePgTimestamp, "timestamp[]"),
    [PG_OID_INT8_ARRAY]: (raw: string) =>
      parsePgArrayLiteral(raw, parsePgInt8, "int8[]")
  });

const PG_PARSER_OVERRIDES = new Map<number, (value: string) => unknown>([
  [PG_OID_TIMESTAMPTZ, parsePgTimestamptz],
  [PG_OID_TIMESTAMP, parsePgTimestamp],
  [PG_OID_INT8, parsePgInt8],
  [
    PG_OID_TIMESTAMPTZ_ARRAY,
    (raw: string) => parsePgArrayLiteral(raw, parsePgTimestamptz, "timestamptz[]")
  ],
  [
    PG_OID_TIMESTAMP_ARRAY,
    (raw: string) => parsePgArrayLiteral(raw, parsePgTimestamp, "timestamp[]")
  ],
  [PG_OID_INT8_ARRAY, (raw: string) => parsePgArrayLiteral(raw, parsePgInt8, "int8[]")]
]);

/**
 * Returns a pool/client-scoped `pg` `CustomTypesConfig` sharing the exact same OID parsers
 * for `timestamptz` (1184), `timestamp` (1114), and `int8` (20) as `PGlite`.
 */
export function createScopedPgTypes(): pg.CustomTypesConfig {
  const fallbackGetParser = pg.types.getTypeParser as (
    id: number,
    format?: "text" | "binary"
  ) => (value: string) => unknown;

  const getTypeParser = (
    oid: number,
    format?: "text" | "binary"
  ): ((value: string) => unknown) => {
    const resolvedFormat = format ?? "text";
    if (resolvedFormat === "text") {
      const override = PG_PARSER_OVERRIDES.get(oid);
      if (override !== undefined) {
        return override;
      }
    }
    return fallbackGetParser(oid, resolvedFormat);
  };

  return {
    getTypeParser: getTypeParser as typeof pg.types.getTypeParser
  };
}
