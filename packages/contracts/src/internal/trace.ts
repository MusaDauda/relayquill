import { ValidationDomainError, hasLoneSurrogate } from "@relayquill/domain";

export const W3C_TRACEPARENT_LENGTH = 55 as const;
export const W3C_TRACESTATE_MAX_BYTES = 256 as const;
export const W3C_TRACESTATE_MAX_ENTRIES = 8 as const;

const TRACEPARENT_REGEX = /^00-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})$/;
const TRACESTATE_KEY_REGEX =
  /^(?:[a-z][a-z0-9_*/-]{0,255}|[a-z0-9][a-z0-9_*/-]{0,240}@[a-z][a-z0-9_*/-]{0,13})$/;

export interface ParsedW3CTraceparent {
  readonly raw: string;
  readonly version: "00";
  readonly trace_id: string;
  readonly parent_id: string;
  readonly trace_flags: string;
}

export function parseW3CTraceparent(
  value: unknown,
  fieldPath = "traceparent"
): ParsedW3CTraceparent {
  if (typeof value !== "string" || value.length !== W3C_TRACEPARENT_LENGTH) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Invalid W3C traceparent length for ${fieldPath}`,
      fieldErrors: [{ path: fieldPath, code: "INVALID_VALUE" }]
    });
  }
  const match = TRACEPARENT_REGEX.exec(value);
  if (match === null || match[1] === undefined || match[2] === undefined || match[3] === undefined) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Invalid W3C traceparent format for ${fieldPath}`,
      fieldErrors: [{ path: fieldPath, code: "INVALID_VALUE" }]
    });
  }
  const traceId = match[1];
  const parentId = match[2];
  const traceFlags = match[3];
  if (traceId === "00000000000000000000000000000000" || parentId === "0000000000000000") {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `All-zero trace_id or parent_id is forbidden in ${fieldPath}`,
      fieldErrors: [{ path: fieldPath, code: "INVALID_VALUE" }]
    });
  }
  return Object.freeze({
    raw: value,
    version: "00",
    trace_id: traceId,
    parent_id: parentId,
    trace_flags: traceFlags
  });
}

export function parseW3CTracestate(value: unknown, fieldPath = "tracestate"): string {
  if (typeof value !== "string" || value.length === 0 || hasLoneSurrogate(value)) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Invalid W3C tracestate for ${fieldPath}`,
      fieldErrors: [{ path: fieldPath, code: "INVALID_VALUE" }]
    });
  }
  if (value.length > W3C_TRACESTATE_MAX_BYTES) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `W3C tracestate exceeds ${W3C_TRACESTATE_MAX_BYTES} ASCII bytes at ${fieldPath}`,
      fieldErrors: [{ path: fieldPath, code: "INVALID_VALUE" }]
    });
  }
  for (let i = 0; i < value.length; i += 1) {
    const code = value.charCodeAt(i);
    if (code < 0x20 || code > 0x7e) {
      throw new ValidationDomainError({
        code: "INVALID_VALUE",
        message: `W3C tracestate must be printable ASCII at ${fieldPath}`,
        fieldErrors: [{ path: fieldPath, code: "INVALID_VALUE" }]
      });
    }
  }

  const rawEntries = value.split(",");
  if (rawEntries.length > W3C_TRACESTATE_MAX_ENTRIES) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `W3C tracestate exceeds ${W3C_TRACESTATE_MAX_ENTRIES} entries at ${fieldPath}`,
      fieldErrors: [{ path: fieldPath, code: "INVALID_VALUE" }]
    });
  }

  const seenKeys = new Set<string>();
  for (const rawEntry of rawEntries) {
    const trimmed = rawEntry.trim();
    if (trimmed.length === 0) {
      throw new ValidationDomainError({
        code: "INVALID_VALUE",
        message: `Empty entry in W3C tracestate at ${fieldPath}`,
        fieldErrors: [{ path: fieldPath, code: "INVALID_VALUE" }]
      });
    }
    const eqIdx = trimmed.indexOf("=");
    if (eqIdx <= 0 || eqIdx === trimmed.length - 1) {
      throw new ValidationDomainError({
        code: "INVALID_VALUE",
        message: `Malformed key=value member in W3C tracestate at ${fieldPath}`,
        fieldErrors: [{ path: fieldPath, code: "INVALID_VALUE" }]
      });
    }
    const key = trimmed.slice(0, eqIdx);
    const val = trimmed.slice(eqIdx + 1);
    if (!TRACESTATE_KEY_REGEX.test(key) || seenKeys.has(key)) {
      throw new ValidationDomainError({
        code: "INVALID_VALUE",
        message: `Invalid or duplicate key "${key}" in W3C tracestate at ${fieldPath}`,
        fieldErrors: [{ path: fieldPath, code: "INVALID_VALUE" }]
      });
    }
    for (let i = 0; i < val.length; i += 1) {
      const code = val.charCodeAt(i);
      if (code < 0x20 || code === 0x2c || code === 0x3d || code > 0x7e) {
        throw new ValidationDomainError({
          code: "INVALID_VALUE",
          message: `Invalid character in W3C tracestate value at ${fieldPath}`,
          fieldErrors: [{ path: fieldPath, code: "INVALID_VALUE" }]
        });
      }
    }
    seenKeys.add(key);
  }

  return value;
}
