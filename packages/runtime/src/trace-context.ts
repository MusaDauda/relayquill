import crypto from "node:crypto";
import { ValidationDomainError } from "@relayquill/domain";
import { isSecretHandle } from "./secret-provider.js";

export const TRACEPARENT_VERSION = "00" as const;
export const TRACEPARENT_LENGTH = 55 as const;
export const MAX_TRACESTATE_ENTRIES = 8 as const;
export const MAX_TRACESTATE_BYTES = 256 as const;
export const MAX_TELEMETRY_ATTRIBUTES = 32 as const;
export const MAX_TELEMETRY_ATTRIBUTE_LENGTH = 512 as const;
export const TELEMETRY_MAX_QUEUE_SIZE = 2048 as const;
export const TELEMETRY_MAX_EXPORT_BATCH_SIZE = 256 as const;

const TRACEPARENT_REGEX = /^00-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})$/;
const TRACE_ID_REGEX = /^[0-9a-f]{32}$/;
const SPAN_ID_REGEX = /^[0-9a-f]{16}$/;
const ALL_ZERO_TRACE_ID = "00000000000000000000000000000000";
const ALL_ZERO_SPAN_ID = "0000000000000000";

const TRACESTATE_SIMPLE_KEY_REGEX = /^[a-z][a-z0-9_*/-]{0,255}$/;
const TRACESTATE_TENANT_KEY_REGEX = /^[a-z0-9][a-z0-9_*/-]{0,240}@[a-z][a-z0-9_*/-]{0,13}$/;
const TRACESTATE_VALUE_REGEX = /^[\x20-\x2b\x2d-\x3c\x3e-\x7e]{0,255}[\x21-\x2b\x2d-\x3c\x3e-\x7e]$/;

const SENSITIVE_ATTR_KEY_REGEX =
  /(?:password|passwd|secret|token|authorization|cookie|csrf|nkey|seed|creds|private_key|signing_key|signature|hmac|credential|dsn|raw_body|payload|body|api_key)/i;
const SENSITIVE_VALUE_PATTERNS: readonly RegExp[] = [
  /rq_p1\.[A-Za-z0-9_-]+/g,
  /-----BEGIN [A-Z0-9 ]+-----/g,
  /postgres(?:ql)?:\/\/[^/\s:@]+:[^/\s@]+@/gi,
  /Bearer\s+[A-Za-z0-9._~+/=-]+/gi
];

export interface ParsedTraceparent {
  readonly valid: true;
  readonly version: typeof TRACEPARENT_VERSION;
  readonly traceId: string;
  readonly spanId: string;
  readonly traceFlags: number;
  readonly traceFlagsHex: string;
  readonly sampled: boolean;
  readonly canonical: string;
}

export interface InvalidTraceparent {
  readonly valid: false;
  readonly reason: string;
}

export type TraceparentParseResult = ParsedTraceparent | InvalidTraceparent;

export function isValidTraceId(value: unknown): value is string {
  return (
    typeof value === "string" &&
    TRACE_ID_REGEX.test(value) &&
    value !== ALL_ZERO_TRACE_ID
  );
}

export function isValidSpanId(value: unknown): value is string {
  return (
    typeof value === "string" &&
    SPAN_ID_REGEX.test(value) &&
    value !== ALL_ZERO_SPAN_ID
  );
}

export function parseTraceparent(header: unknown): TraceparentParseResult {
  if (typeof header !== "string") {
    return { valid: false, reason: "traceparent_not_string" };
  }
  const trimmed = header.trim();
  if (trimmed.length !== TRACEPARENT_LENGTH) {
    return { valid: false, reason: "traceparent_invalid_length" };
  }
  const match = TRACEPARENT_REGEX.exec(trimmed);
  if (match === null) {
    return { valid: false, reason: "traceparent_invalid_format" };
  }
  const traceId = match[1] ?? "";
  const spanId = match[2] ?? "";
  const flagsHex = match[3] ?? "";

  if (traceId === ALL_ZERO_TRACE_ID) {
    return { valid: false, reason: "traceparent_zero_trace_id" };
  }
  if (spanId === ALL_ZERO_SPAN_ID) {
    return { valid: false, reason: "traceparent_zero_span_id" };
  }
  const traceFlags = Number.parseInt(flagsHex, 16);
  return Object.freeze({
    valid: true,
    version: TRACEPARENT_VERSION,
    traceId,
    spanId,
    traceFlags,
    traceFlagsHex: flagsHex,
    sampled: (traceFlags & 0x01) === 0x01,
    canonical: `${TRACEPARENT_VERSION}-${traceId}-${spanId}-${flagsHex}`
  });
}

export function formatTraceparent(input: {
  readonly traceId: string;
  readonly spanId: string;
  readonly traceFlags?: number | undefined;
}): string {
  if (!isValidTraceId(input.traceId)) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: "Cannot format traceparent with invalid or all-zero traceId"
    });
  }
  if (!isValidSpanId(input.spanId)) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: "Cannot format traceparent with invalid or all-zero spanId"
    });
  }
  const flags = input.traceFlags ?? 1;
  if (!Number.isInteger(flags) || flags < 0 || flags > 255) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: "Trace flags must be an integer between 0 and 255"
    });
  }
  const flagsHex = flags.toString(16).padStart(2, "0");
  return `${TRACEPARENT_VERSION}-${input.traceId}-${input.spanId}-${flagsHex}`;
}

export function generateTraceId(): string {
  for (;;) {
    const hex = crypto.randomBytes(16).toString("hex");
    if (hex !== ALL_ZERO_TRACE_ID) {
      return hex;
    }
  }
}

export function generateSpanId(): string {
  for (;;) {
    const hex = crypto.randomBytes(8).toString("hex");
    if (hex !== ALL_ZERO_SPAN_ID) {
      return hex;
    }
  }
}

export function createTraceparent(traceFlags = 1): string {
  return formatTraceparent({
    traceId: generateTraceId(),
    spanId: generateSpanId(),
    traceFlags
  });
}

function isValidTracestateKey(key: string): boolean {
  return TRACESTATE_SIMPLE_KEY_REGEX.test(key) || TRACESTATE_TENANT_KEY_REGEX.test(key);
}

export interface SanitizeTracestateOptions {
  readonly allowedVendorKeys?: ReadonlySet<string> | readonly string[] | undefined;
  readonly allowAnyValidVendorKey?: boolean | undefined;
  readonly maxEntries?: number | undefined;
  readonly maxBytes?: number | undefined;
}

export function sanitizeTracestate(
  raw: unknown,
  options: SanitizeTracestateOptions = {}
): string {
  if (typeof raw !== "string" || raw.trim().length === 0) {
    return "";
  }
  const allowAny = options.allowAnyValidVendorKey === true;
  const allowedSet =
    options.allowedVendorKeys === undefined
      ? null
      : options.allowedVendorKeys instanceof Set
        ? options.allowedVendorKeys
        : new Set(options.allowedVendorKeys);

  // Default external tracestate propagation is empty unless vendor keys are explicitly approved.
  if (!allowAny && (allowedSet === null || allowedSet.size === 0)) {
    return "";
  }

  const maxEntries = Math.min(
    MAX_TRACESTATE_ENTRIES,
    options.maxEntries ?? MAX_TRACESTATE_ENTRIES
  );
  const maxBytes = Math.min(MAX_TRACESTATE_BYTES, options.maxBytes ?? MAX_TRACESTATE_BYTES);

  const seenKeys = new Set<string>();
  const kept: string[] = [];
  let currentBytes = 0;

  for (const part of raw.split(",")) {
    const trimmed = part.trim();
    if (trimmed.length === 0) {
      continue;
    }
    const eqIdx = trimmed.indexOf("=");
    if (eqIdx <= 0 || eqIdx === trimmed.length - 1) {
      continue;
    }
    const key = trimmed.slice(0, eqIdx).trim();
    const val = trimmed.slice(eqIdx + 1).trim();
    if (!isValidTracestateKey(key) || !TRACESTATE_VALUE_REGEX.test(val)) {
      continue;
    }
    if ((!allowAny && !allowedSet?.has(key)) || seenKeys.has(key)) {
      continue;
    }
    if (kept.length >= maxEntries) {
      break;
    }
    const entry = `${key}=${val}`;
    const entryBytes = Buffer.byteLength(entry, "ascii");
    const addedBytes = kept.length === 0 ? entryBytes : entryBytes + 1;
    if (currentBytes + addedBytes > maxBytes) {
      break;
    }
    seenKeys.add(key);
    kept.push(entry);
    currentBytes += addedBytes;
  }

  return kept.join(",");
}

export interface SanitizedIncomingTraceContext {
  readonly suppliedValidTraceparent: boolean;
  readonly traceparent?: ParsedTraceparent | undefined;
  readonly tracestate: string;
  readonly invalidReason?: string | undefined;
  readonly baggageDropped: boolean;
}

function readHeaderString(
  headers: Readonly<Record<string, string | readonly string[] | undefined>>,
  name: string
): string | undefined {
  const direct = headers[name] ?? headers[name.toLowerCase()];
  if (typeof direct === "string") {
    return direct;
  }
  if (Array.isArray(direct) && direct.length > 0 && typeof direct[0] === "string") {
    return direct[0];
  }
  for (const [k, v] of Object.entries(headers)) {
    if (k.toLowerCase() === name.toLowerCase()) {
      if (typeof v === "string") {
        return v;
      }
      if (Array.isArray(v) && v.length > 0 && typeof v[0] === "string") {
        return v[0];
      }
    }
  }
  return undefined;
}

export function sanitizeIncomingTraceHeaders(
  headers: Readonly<Record<string, string | readonly string[] | undefined>>,
  options: SanitizeTracestateOptions = {}
): SanitizedIncomingTraceContext {
  const rawTraceparent = readHeaderString(headers, "traceparent");
  const rawTracestate = readHeaderString(headers, "tracestate");
  const rawBaggage = readHeaderString(headers, "baggage");
  const baggageDropped = rawBaggage !== undefined && rawBaggage.trim().length > 0;

  if (rawTraceparent === undefined) {
    return Object.freeze({
      suppliedValidTraceparent: false,
      tracestate: "",
      baggageDropped
    });
  }

  const parsed = parseTraceparent(rawTraceparent);
  if (!parsed.valid) {
    return Object.freeze({
      suppliedValidTraceparent: false,
      tracestate: "",
      invalidReason: parsed.reason,
      baggageDropped
    });
  }

  return Object.freeze({
    suppliedValidTraceparent: true,
    traceparent: parsed,
    tracestate: sanitizeTracestate(rawTracestate, options),
    baggageDropped
  });
}

export type TelemetryAttributePrimitive = string | number | boolean;
export type TelemetryAttributes = Readonly<Record<string, TelemetryAttributePrimitive>>;

export function redactTelemetryText(input: string): string {
  let out = input;
  for (const pattern of SENSITIVE_VALUE_PATTERNS) {
    out = out.replace(pattern, "[REDACTED]");
  }
  if (out.length > MAX_TELEMETRY_ATTRIBUTE_LENGTH) {
    return `${out.slice(0, MAX_TELEMETRY_ATTRIBUTE_LENGTH - 3)}...`;
  }
  return out;
}

export function sanitizeTelemetryAttributes(
  input: Readonly<Record<string, unknown>> | undefined
): TelemetryAttributes {
  if (input === undefined) {
    return Object.freeze({});
  }
  const clean: Record<string, TelemetryAttributePrimitive> = {};
  let count = 0;

  for (const [key, value] of Object.entries(input)) {
    if (count >= MAX_TELEMETRY_ATTRIBUTES) {
      break;
    }
    if (key.length === 0 || value === undefined || value === null) {
      continue;
    }
    if (SENSITIVE_ATTR_KEY_REGEX.test(key) || isSecretHandle(value)) {
      continue;
    }
    if (typeof value === "boolean") {
      clean[key] = value;
      count += 1;
    } else if (typeof value === "number") {
      if (Number.isFinite(value)) {
        clean[key] = value;
        count += 1;
      }
    } else if (typeof value === "bigint") {
      clean[key] = value.toString(10);
      count += 1;
    } else if (typeof value === "string") {
      clean[key] = redactTelemetryText(value);
      count += 1;
    }
  }

  return Object.freeze(clean);
}

export function buildSafeTraceViewUrl(
  traceViewOrigin: string | undefined,
  traceId: string,
  options: { readonly allowHttpLocalhost?: boolean | undefined } = {}
): string | undefined {
  if (traceViewOrigin === undefined || !isValidTraceId(traceId)) {
    return undefined;
  }
  let parsed: URL;
  try {
    parsed = new URL(traceViewOrigin);
  } catch {
    return undefined;
  }
  const isHttps = parsed.protocol === "https:";
  const isLocalDevHttp =
    options.allowHttpLocalhost === true &&
    parsed.protocol === "http:" &&
    (parsed.hostname === "127.0.0.1" || parsed.hostname === "localhost");
  if (!isHttps && !isLocalDevHttp) {
    return undefined;
  }
  if (parsed.username.length > 0 || parsed.password.length > 0) {
    return undefined;
  }
  const base = parsed.origin;
  return `${base}/trace/${traceId}`;
}
