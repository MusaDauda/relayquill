import { Temporal } from "@js-temporal/polyfill";
import { ValidationDomainError } from "./errors.js";
import { type Brand } from "./ids.js";

export type CanonicalUtcTimestamp = Brand<string, "CanonicalUtcTimestamp">;

export const MILLISECONDS_PER_SECOND = 1_000n;
export const MILLISECONDS_PER_MINUTE = 60_000n;
export const MILLISECONDS_PER_HOUR = 3_600_000n;
export const MILLISECONDS_PER_DAY = 86_400_000n;
export const NANOSECONDS_PER_MICROSECOND = 1_000n;
export const NANOSECONDS_PER_MILLISECOND = 1_000_000n;
export const MICROSECONDS_PER_MILLISECOND = 1_000n;

const STRICT_RFC3339_PREPARSE_REGEX =
  /^(\d{4})-(\d{2})-(\d{2})[Tt](\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,6}))?(?:([Zz])|([+-])(\d{2}):(\d{2}))$/;

const CANONICAL_UTC_OUTPUT_REGEX =
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$/;

export interface ParsedUtcTimestamp {
  readonly instant: Temporal.Instant;
  readonly canonical: CanonicalUtcTimestamp;
  readonly epochMicroseconds: bigint;
}

export function nowUtcInstant(): Temporal.Instant {
  const now = Temporal.Now.instant();
  const remainder = now.epochNanoseconds % NANOSECONDS_PER_MICROSECOND;
  if (remainder === 0n) {
    return now;
  }
  return Temporal.Instant.fromEpochNanoseconds(now.epochNanoseconds - remainder);
}

export function assertMicrosecondAligned(
  instant: Temporal.Instant,
  fieldPath = "timestamp"
): void {
  if (instant.epochNanoseconds % NANOSECONDS_PER_MICROSECOND !== 0n) {
    throw new ValidationDomainError({
      code: "INVALID_TIMESTAMP",
      message: `Timestamp ${fieldPath} must be aligned to whole microseconds`,
      fieldErrors: [{ path: fieldPath, code: "INVALID_TIMESTAMP" }]
    });
  }
}

export function formatUtcTimestamp(
  instant: Temporal.Instant,
  fieldPath = "timestamp"
): CanonicalUtcTimestamp {
  assertMicrosecondAligned(instant, fieldPath);
  return instant.toString({ fractionalSecondDigits: 6 }) as CanonicalUtcTimestamp;
}

export function parseUtcTimestamp(
  input: unknown,
  fieldPath = "timestamp"
): ParsedUtcTimestamp {
  if (typeof input !== "string") {
    throw new ValidationDomainError({
      code: "INVALID_TIMESTAMP",
      message: `Timestamp ${fieldPath} must be a string`,
      fieldErrors: [{ path: fieldPath, code: "INVALID_TIMESTAMP" }]
    });
  }

  const match = STRICT_RFC3339_PREPARSE_REGEX.exec(input);
  if (match === null) {
    throw new ValidationDomainError({
      code: "INVALID_TIMESTAMP",
      message: `Timestamp ${fieldPath} must be strict RFC3339 with up to 6 fractional digits and explicit offset`,
      fieldErrors: [{ path: fieldPath, code: "INVALID_TIMESTAMP" }]
    });
  }

  const secondStr = match[6];
  if (secondStr === undefined || Number(secondStr) > 59) {
    throw new ValidationDomainError({
      code: "INVALID_TIMESTAMP",
      message: `Timestamp ${fieldPath} contains invalid or leap second`,
      fieldErrors: [{ path: fieldPath, code: "INVALID_TIMESTAMP" }]
    });
  }

  const offsetSign = match[9];
  const offsetHours = match[10];
  const offsetMinutes = match[11];
  if (offsetSign === "-" && offsetHours === "00" && offsetMinutes === "00") {
    throw new ValidationDomainError({
      code: "INVALID_TIMESTAMP",
      message: `Timestamp ${fieldPath} must not use unknown offset -00:00`,
      fieldErrors: [{ path: fieldPath, code: "INVALID_TIMESTAMP" }]
    });
  }

  let instant: Temporal.Instant;
  try {
    instant = Temporal.Instant.from(input);
  } catch {
    throw new ValidationDomainError({
      code: "INVALID_TIMESTAMP",
      message: `Invalid calendar date or offset in timestamp ${fieldPath}`,
      fieldErrors: [{ path: fieldPath, code: "INVALID_TIMESTAMP" }]
    });
  }

  assertMicrosecondAligned(instant, fieldPath);
  const canonical = formatUtcTimestamp(instant, fieldPath);
  const epochMicroseconds = instant.epochNanoseconds / NANOSECONDS_PER_MICROSECOND;

  return Object.freeze({
    instant,
    canonical,
    epochMicroseconds
  });
}

export function isCanonicalUtcTimestamp(value: unknown): value is CanonicalUtcTimestamp {
  if (typeof value !== "string" || !CANONICAL_UTC_OUTPUT_REGEX.test(value)) {
    return false;
  }
  try {
    const parsed = parseUtcTimestamp(value);
    return parsed.canonical === value;
  } catch {
    return false;
  }
}

export function toEpochMicroseconds(
  instant: Temporal.Instant,
  fieldPath = "timestamp"
): bigint {
  assertMicrosecondAligned(instant, fieldPath);
  return instant.epochNanoseconds / NANOSECONDS_PER_MICROSECOND;
}

export function fromEpochMicroseconds(
  epochMicroseconds: bigint,
  fieldPath = "epoch_microseconds"
): Temporal.Instant {
  try {
    return Temporal.Instant.fromEpochNanoseconds(epochMicroseconds * NANOSECONDS_PER_MICROSECOND);
  } catch {
    throw new ValidationDomainError({
      code: "INVALID_TIMESTAMP",
      message: `Epoch microseconds out of range for ${fieldPath}`,
      fieldErrors: [{ path: fieldPath, code: "INVALID_TIMESTAMP" }]
    });
  }
}

function toSafeBigIntInteger(value: number | bigint, fieldPath: string): bigint {
  if (typeof value === "bigint") {
    return value;
  }
  if (!Number.isSafeInteger(value)) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Expected safe integer duration for ${fieldPath}`,
      fieldErrors: [{ path: fieldPath, code: "INVALID_VALUE" }]
    });
  }
  return BigInt(value);
}

export function addMicroseconds(
  instant: Temporal.Instant,
  microseconds: bigint,
  fieldPath = "timestamp"
): Temporal.Instant {
  assertMicrosecondAligned(instant, fieldPath);
  try {
    return Temporal.Instant.fromEpochNanoseconds(
      instant.epochNanoseconds + microseconds * NANOSECONDS_PER_MICROSECOND
    );
  } catch {
    throw new ValidationDomainError({
      code: "INVALID_TIMESTAMP",
      message: `Timestamp overflow in addMicroseconds for ${fieldPath}`,
      fieldErrors: [{ path: fieldPath, code: "INVALID_TIMESTAMP" }]
    });
  }
}

export function addMilliseconds(
  instant: Temporal.Instant,
  milliseconds: number | bigint,
  fieldPath = "timestamp"
): Temporal.Instant {
  const ms = toSafeBigIntInteger(milliseconds, fieldPath);
  return addMicroseconds(instant, ms * MICROSECONDS_PER_MILLISECOND, fieldPath);
}

export function addSeconds(
  instant: Temporal.Instant,
  seconds: number | bigint,
  fieldPath = "timestamp"
): Temporal.Instant {
  const secs = toSafeBigIntInteger(seconds, fieldPath);
  return addMilliseconds(instant, secs * MILLISECONDS_PER_SECOND, fieldPath);
}

export function diffMicroseconds(later: Temporal.Instant, earlier: Temporal.Instant): bigint {
  assertMicrosecondAligned(later, "later");
  assertMicrosecondAligned(earlier, "earlier");
  return (later.epochNanoseconds - earlier.epochNanoseconds) / NANOSECONDS_PER_MICROSECOND;
}

export function diffMilliseconds(later: Temporal.Instant, earlier: Temporal.Instant): bigint {
  return diffMicroseconds(later, earlier) / MICROSECONDS_PER_MILLISECOND;
}

export function compareInstants(a: Temporal.Instant, b: Temporal.Instant): -1 | 0 | 1 {
  return Temporal.Instant.compare(a, b);
}

export function isExpired(deadline: Temporal.Instant, now: Temporal.Instant): boolean {
  return Temporal.Instant.compare(now, deadline) >= 0;
}

export function isBefore(a: Temporal.Instant, b: Temporal.Instant): boolean {
  return Temporal.Instant.compare(a, b) < 0;
}

export function isAfter(a: Temporal.Instant, b: Temporal.Instant): boolean {
  return Temporal.Instant.compare(a, b) > 0;
}

export function clampDeadline(
  candidate: Temporal.Instant,
  maxDeadline: Temporal.Instant
): Temporal.Instant {
  return Temporal.Instant.compare(candidate, maxDeadline) > 0 ? maxDeadline : candidate;
}

export function minInstant(a: Temporal.Instant, b: Temporal.Instant): Temporal.Instant {
  return Temporal.Instant.compare(a, b) <= 0 ? a : b;
}

export function maxInstant(a: Temporal.Instant, b: Temporal.Instant): Temporal.Instant {
  return Temporal.Instant.compare(a, b) >= 0 ? a : b;
}
