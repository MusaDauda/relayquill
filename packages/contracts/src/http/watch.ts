import {
  type WatchResourceKind,
  ValidationDomainError,
  createEnumGuard,
  isWatchResourceKind
} from "@relayquill/domain";
import { RESPONSE_SCHEMA_VERSION } from "./envelope.js";
import {
  type CanonicalUtcTimestamp,
  type CanonicalUuid,
  type EventId,
  type Int64String,
  type NonNegativeInt64String,
  assertAllowedKeys,
  assertPlainRecord,
  decodeUtf8BytesStrict,
  encodeUtf8Bytes,
  parseBooleanField,
  parseBoundedString,
  parseCanonicalUtcTimestamp,
  parseCanonicalUuid,
  parseEventId,
  parseInt64String,
  parseNonNegativeInt64String,
  parsePositiveInt32,
  parseSafeReasonCode,
  parseStrictJsonObject
} from "./values.js";

export const WATCH_MAX_FRAME_BYTES = 8_192 as const;
export const WATCH_HEARTBEAT_MAX_INTERVAL_MS = 10_000 as const;

export const WATCH_FRAME_TYPES = [
  "snapshot",
  "event",
  "heartbeat",
  "resync_required",
  "authorization_lost",
  "unavailable"
] as const;

export type WatchFrameType = (typeof WATCH_FRAME_TYPES)[number];
export const isWatchFrameType = createEnumGuard(WATCH_FRAME_TYPES);

export const WATCH_EVENT_TYPES = [
  "event.accepted",
  "fanout.progress",
  "delivery.prepared",
  "send.started",
  "delivery.acknowledged",
  "delivery.retry_scheduled",
  "delivery.dead_lettered",
  "receiver.receipt_verified",
  "control.changed",
  "event.delivery_aggregate_changed"
] as const;

export type WatchEventType = (typeof WATCH_EVENT_TYPES)[number];
export const isWatchEventType = createEnumGuard(WATCH_EVENT_TYPES);

export interface WatchSnapshotFrameData {
  readonly response_schema_version: typeof RESPONSE_SCHEMA_VERSION;
  readonly frame_type: "snapshot";
  readonly resource_kind: WatchResourceKind;
  readonly resource_id: CanonicalUuid;
  readonly cursor: string;
  readonly high_water_sequence: NonNegativeInt64String;
  readonly observed_at: CanonicalUtcTimestamp;
  readonly state: string;
  readonly current_version: Int64String;
  readonly summary: Readonly<Record<string, unknown>>;
}

export interface WatchEventFrameData {
  readonly response_schema_version: typeof RESPONSE_SCHEMA_VERSION;
  readonly frame_type: "event";
  readonly resource_kind: WatchResourceKind;
  readonly resource_id: CanonicalUuid;
  readonly event_id: EventId;
  readonly event_sequence: NonNegativeInt64String;
  readonly event_type: string;
  readonly supported_event_type: boolean;
  readonly event_schema_version: number;
  readonly recorded_at: CanonicalUtcTimestamp;
  readonly safe_details: Readonly<Record<string, unknown>>;
}

export interface WatchResyncRequiredFrameData {
  readonly response_schema_version: typeof RESPONSE_SCHEMA_VERSION;
  readonly frame_type: "resync_required";
  readonly reason_code: string;
  readonly snapshot_path: string;
  readonly recorded_at: CanonicalUtcTimestamp;
}

export interface WatchAuthorizationLostFrameData {
  readonly response_schema_version: typeof RESPONSE_SCHEMA_VERSION;
  readonly frame_type: "authorization_lost";
  readonly reason_code: string;
  readonly recorded_at: CanonicalUtcTimestamp;
}

export interface WatchUnavailableFrameData {
  readonly response_schema_version: typeof RESPONSE_SCHEMA_VERSION;
  readonly frame_type: "unavailable";
  readonly reason_code: string;
  readonly retryable: boolean;
  readonly recorded_at: CanonicalUtcTimestamp;
}

export type WatchDataFramePayload =
  | WatchSnapshotFrameData
  | WatchEventFrameData
  | WatchResyncRequiredFrameData
  | WatchAuthorizationLostFrameData
  | WatchUnavailableFrameData;

export type ParsedSseFrame =
  | { readonly supported: true; readonly frame_type: "heartbeat"; readonly comment: string }
  | {
      readonly supported: true;
      readonly frame_type: "snapshot";
      readonly id: string;
      readonly data: WatchSnapshotFrameData;
    }
  | {
      readonly supported: true;
      readonly frame_type: "event";
      readonly id: string;
      readonly data: WatchEventFrameData;
    }
  | {
      readonly supported: true;
      readonly frame_type: "resync_required";
      readonly data: WatchResyncRequiredFrameData;
    }
  | {
      readonly supported: true;
      readonly frame_type: "authorization_lost";
      readonly data: WatchAuthorizationLostFrameData;
    }
  | {
      readonly supported: true;
      readonly frame_type: "unavailable";
      readonly data: WatchUnavailableFrameData;
    }
  | {
      readonly supported: false;
      readonly reason:
        | "unsupported_response_schema_version"
        | "unsupported_frame_type"
        | "malformed_frame";
      readonly response_schema_version?: number | undefined;
      readonly frame_type?: string | undefined;
    };

const SNAPSHOT_KEYS = new Set([
  "response_schema_version",
  "frame_type",
  "resource_kind",
  "resource_id",
  "cursor",
  "high_water_sequence",
  "observed_at",
  "state",
  "current_version",
  "summary"
]);

const EVENT_KEYS = new Set([
  "response_schema_version",
  "frame_type",
  "resource_kind",
  "resource_id",
  "event_id",
  "event_sequence",
  "event_type",
  "event_schema_version",
  "recorded_at",
  "safe_details"
]);

const RESYNC_KEYS = new Set([
  "response_schema_version",
  "frame_type",
  "reason_code",
  "snapshot_path",
  "recorded_at"
]);

const AUTH_LOST_KEYS = new Set([
  "response_schema_version",
  "frame_type",
  "reason_code",
  "recorded_at"
]);

const UNAVAILABLE_KEYS = new Set([
  "response_schema_version",
  "frame_type",
  "reason_code",
  "retryable",
  "recorded_at"
]);

function encodeSafeSseJson(value: unknown): string {
  const raw = JSON.stringify(value);
  if (typeof raw !== "string") {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: "Watch frame payload is not JSON-serializable"
    });
  }
  return raw
    .replace(/\u2028/g, "\\u2028")
    .replace(/\u2029/g, "\\u2029");
}

function validateSseHeaderToken(value: string, fieldPath: string): string {
  if (typeof value !== "string" || value.length === 0) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `SSE ${fieldPath} must be non-empty`,
      fieldErrors: [{ path: fieldPath, code: "INVALID_VALUE" }]
    });
  }
  for (let i = 0; i < value.length; i += 1) {
    const code = value.charCodeAt(i);
    if (code === 0x00 || code === 0x0a || code === 0x0d) {
      throw new ValidationDomainError({
        code: "INVALID_VALUE",
        message: `SSE ${fieldPath} cannot contain CR, LF, or NUL`,
        fieldErrors: [{ path: fieldPath, code: "INVALID_VALUE" }]
      });
    }
  }
  return value;
}

export function formatSseHeartbeatFrame(comment = "heartbeat"): string {
  const safeComment = validateSseHeaderToken(comment, "comment");
  const frame = `: ${safeComment}\n\n`;
  const bytes = encodeUtf8Bytes(frame, "sse_frame");
  if (bytes.length > WATCH_MAX_FRAME_BYTES) {
    throw new ValidationDomainError({
      code: "PAYLOAD_TOO_LARGE",
      message: `SSE frame exceeds ${WATCH_MAX_FRAME_BYTES} bytes`
    });
  }
  return frame;
}

export function formatSseFrame(input: {
  readonly id?: string | undefined;
  readonly payload:
    | WatchSnapshotFrameData
    | Omit<WatchEventFrameData, "supported_event_type">
    | WatchResyncRequiredFrameData
    | WatchAuthorizationLostFrameData
    | WatchUnavailableFrameData;
}): string {
  const frameType = input.payload.frame_type;
  const requiresId = frameType === "snapshot" || frameType === "event";
  if (requiresId && (input.id === undefined || input.id.length === 0)) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `SSE frame "${frameType}" requires a non-empty committed cursor id`
    });
  }
  if (!requiresId && input.id !== undefined) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `SSE frame "${frameType}" must not emit an id field`
    });
  }

  let serializedPayload: unknown = input.payload;
  if (frameType === "event") {
    const {
      supported_event_type: _ignored,
      ...wireObj
    } = input.payload as WatchEventFrameData;
    serializedPayload = wireObj;
  }

  const lines: string[] = [`event: ${frameType}`];
  if (input.id !== undefined) {
    lines.push(`id: ${validateSseHeaderToken(input.id, "id")}`);
  }
  lines.push(`data: ${encodeSafeSseJson(serializedPayload)}`);

  const frame = `${lines.join("\n")}\n\n`;
  const bytes = encodeUtf8Bytes(frame, "sse_frame");
  if (bytes.length > WATCH_MAX_FRAME_BYTES) {
    throw new ValidationDomainError({
      code: "PAYLOAD_TOO_LARGE",
      message: `SSE frame (${bytes.length} bytes) exceeds ${WATCH_MAX_FRAME_BYTES} byte limit`
    });
  }
  return frame;
}

export function parseWatchFrameData(
  rawJsonObj: Record<string, unknown>,
  expectedEventName?: string
):
  | { readonly supported: true; readonly data: WatchDataFramePayload }
  | {
      readonly supported: false;
      readonly reason:
        | "unsupported_response_schema_version"
        | "unsupported_frame_type"
        | "malformed_frame";
      readonly response_schema_version?: number | undefined;
      readonly frame_type?: string | undefined;
    } {
  const versionRaw = rawJsonObj.response_schema_version;
  if (typeof versionRaw === "number" && versionRaw !== RESPONSE_SCHEMA_VERSION) {
    return Object.freeze({
      supported: false,
      reason: "unsupported_response_schema_version",
      response_schema_version: versionRaw,
      ...(typeof rawJsonObj.frame_type === "string"
        ? { frame_type: rawJsonObj.frame_type }
        : {})
    });
  }
  if (versionRaw !== RESPONSE_SCHEMA_VERSION) {
    return Object.freeze({ supported: false, reason: "malformed_frame" });
  }

  const frameTypeRaw = rawJsonObj.frame_type;
  if (typeof frameTypeRaw !== "string") {
    return Object.freeze({ supported: false, reason: "malformed_frame" });
  }
  if (expectedEventName !== undefined && expectedEventName !== frameTypeRaw) {
    return Object.freeze({ supported: false, reason: "malformed_frame" });
  }
  if (!isWatchFrameType(frameTypeRaw) || frameTypeRaw === "heartbeat") {
    return Object.freeze({
      supported: false,
      reason: "unsupported_frame_type",
      frame_type: frameTypeRaw
    });
  }

  try {
    switch (frameTypeRaw) {
      case "snapshot": {
        assertAllowedKeys(rawJsonObj, SNAPSHOT_KEYS, "watch.snapshot");
        if (!isWatchResourceKind(rawJsonObj.resource_kind)) {
          return Object.freeze({ supported: false, reason: "malformed_frame" });
        }
        const summary = assertPlainRecord(rawJsonObj.summary, "watch.snapshot.summary");
        return Object.freeze({
          supported: true,
          data: Object.freeze({
            response_schema_version: RESPONSE_SCHEMA_VERSION,
            frame_type: "snapshot",
            resource_kind: rawJsonObj.resource_kind,
            resource_id: parseCanonicalUuid(rawJsonObj.resource_id, "watch.snapshot.resource_id"),
            cursor: parseBoundedString(rawJsonObj.cursor, {
              fieldPath: "watch.snapshot.cursor",
              minUtf8Bytes: 1,
              maxUtf8Bytes: 1400,
              rejectControlChars: true
            }),
            high_water_sequence: parseNonNegativeInt64String(
              rawJsonObj.high_water_sequence,
              "watch.snapshot.high_water_sequence"
            ),
            observed_at: parseCanonicalUtcTimestamp(
              rawJsonObj.observed_at,
              "watch.snapshot.observed_at"
            ),
            state: parseSafeReasonCode(rawJsonObj.state, "watch.snapshot.state"),
            current_version: parseInt64String(
              rawJsonObj.current_version,
              "watch.snapshot.current_version"
            ),
            summary: Object.freeze({ ...summary })
          })
        });
      }
      case "event": {
        assertAllowedKeys(rawJsonObj, EVENT_KEYS, "watch.event");
        if (!isWatchResourceKind(rawJsonObj.resource_kind)) {
          return Object.freeze({ supported: false, reason: "malformed_frame" });
        }
        const eventType = parseSafeReasonCode(rawJsonObj.event_type, "watch.event.event_type");
        const safeDetails = assertPlainRecord(rawJsonObj.safe_details, "watch.event.safe_details");
        return Object.freeze({
          supported: true,
          data: Object.freeze({
            response_schema_version: RESPONSE_SCHEMA_VERSION,
            frame_type: "event",
            resource_kind: rawJsonObj.resource_kind,
            resource_id: parseCanonicalUuid(rawJsonObj.resource_id, "watch.event.resource_id"),
            event_id: parseEventId(rawJsonObj.event_id, "watch.event.event_id"),
            event_sequence: parseNonNegativeInt64String(
              rawJsonObj.event_sequence,
              "watch.event.event_sequence"
            ),
            event_type: eventType,
            supported_event_type: isWatchEventType(eventType),
            event_schema_version: parsePositiveInt32(
              rawJsonObj.event_schema_version,
              "watch.event.event_schema_version"
            ),
            recorded_at: parseCanonicalUtcTimestamp(
              rawJsonObj.recorded_at,
              "watch.event.recorded_at"
            ),
            safe_details: Object.freeze({ ...safeDetails })
          })
        });
      }
      case "resync_required": {
        assertAllowedKeys(rawJsonObj, RESYNC_KEYS, "watch.resync_required");
        return Object.freeze({
          supported: true,
          data: Object.freeze({
            response_schema_version: RESPONSE_SCHEMA_VERSION,
            frame_type: "resync_required",
            reason_code: parseSafeReasonCode(
              rawJsonObj.reason_code,
              "watch.resync_required.reason_code"
            ),
            snapshot_path: parseBoundedString(rawJsonObj.snapshot_path, {
              fieldPath: "watch.resync_required.snapshot_path",
              minUtf8Bytes: 1,
              maxUtf8Bytes: 512,
              rejectControlChars: true
            }),
            recorded_at: parseCanonicalUtcTimestamp(
              rawJsonObj.recorded_at,
              "watch.resync_required.recorded_at"
            )
          })
        });
      }
      case "authorization_lost": {
        assertAllowedKeys(rawJsonObj, AUTH_LOST_KEYS, "watch.authorization_lost");
        return Object.freeze({
          supported: true,
          data: Object.freeze({
            response_schema_version: RESPONSE_SCHEMA_VERSION,
            frame_type: "authorization_lost",
            reason_code: parseSafeReasonCode(
              rawJsonObj.reason_code,
              "watch.authorization_lost.reason_code"
            ),
            recorded_at: parseCanonicalUtcTimestamp(
              rawJsonObj.recorded_at,
              "watch.authorization_lost.recorded_at"
            )
          })
        });
      }
      case "unavailable": {
        assertAllowedKeys(rawJsonObj, UNAVAILABLE_KEYS, "watch.unavailable");
        return Object.freeze({
          supported: true,
          data: Object.freeze({
            response_schema_version: RESPONSE_SCHEMA_VERSION,
            frame_type: "unavailable",
            reason_code: parseSafeReasonCode(
              rawJsonObj.reason_code,
              "watch.unavailable.reason_code"
            ),
            retryable: parseBooleanField(rawJsonObj.retryable, "watch.unavailable.retryable"),
            recorded_at: parseCanonicalUtcTimestamp(
              rawJsonObj.recorded_at,
              "watch.unavailable.recorded_at"
            )
          })
        });
      }
    }
  } catch {
    return Object.freeze({ supported: false, reason: "malformed_frame" });
  }
}

export function parseSseFrame(rawFrameText: string): ParsedSseFrame {
  const frameBytes = encodeUtf8Bytes(rawFrameText, "sse_frame");
  if (frameBytes.length > WATCH_MAX_FRAME_BYTES) {
    throw new ValidationDomainError({
      code: "PAYLOAD_TOO_LARGE",
      message: `SSE frame (${frameBytes.length} bytes) exceeds ${WATCH_MAX_FRAME_BYTES} bytes`
    });
  }

  const lines = rawFrameText.split(/\r\n|\r|\n/);
  let eventName: string | undefined;
  let id: string | undefined;
  let retryMs: number | undefined;
  const dataLines: string[] = [];
  const comments: string[] = [];

  for (const line of lines) {
    if (line.length === 0) {
      continue;
    }
    if (line.startsWith(":")) {
      comments.push(line.slice(1).trimStart());
      continue;
    }
    const colonIdx = line.indexOf(":");
    const field = colonIdx === -1 ? line : line.slice(0, colonIdx);
    const rawVal = colonIdx === -1 ? "" : line.slice(colonIdx + 1);
    const value = rawVal.startsWith(" ") ? rawVal.slice(1) : rawVal;

    if (field === "event") {
      eventName = value;
    } else if (field === "data") {
      dataLines.push(value);
    } else if (field === "id") {
      if (value.includes("\0")) {
        return Object.freeze({ supported: false, reason: "malformed_frame" });
      }
      id = value;
    } else if (field === "retry") {
      const parsedRetry = Number(value);
      if (Number.isInteger(parsedRetry) && parsedRetry >= 0) {
        retryMs = parsedRetry;
      }
    }
  }

  if (dataLines.length === 0) {
    if (comments.length > 0 && eventName === undefined && id === undefined && retryMs === undefined) {
      return Object.freeze({
        supported: true,
        frame_type: "heartbeat",
        comment: comments.join("\n")
      });
    }
    return Object.freeze({ supported: false, reason: "malformed_frame" });
  }

  let jsonObj: Record<string, unknown>;
  try {
    jsonObj = parseStrictJsonObject(dataLines.join("\n"), {
      fieldPath: "sse.data",
      maxDepth: 12,
      maxNodes: 1024
    });
  } catch {
    return Object.freeze({ supported: false, reason: "malformed_frame" });
  }

  const classified = parseWatchFrameData(jsonObj, eventName);
  if (!classified.supported) {
    return classified;
  }

  const data = classified.data;
  if (data.frame_type === "snapshot") {
    if (id === undefined || id.length === 0) {
      return Object.freeze({ supported: false, reason: "malformed_frame" });
    }
    return Object.freeze({ supported: true, frame_type: "snapshot", id, data });
  }
  if (data.frame_type === "event") {
    if (id === undefined || id.length === 0) {
      return Object.freeze({ supported: false, reason: "malformed_frame" });
    }
    return Object.freeze({ supported: true, frame_type: "event", id, data });
  }
  if (id !== undefined) {
    return Object.freeze({ supported: false, reason: "malformed_frame" });
  }
  if (data.frame_type === "resync_required") {
    return Object.freeze({ supported: true, frame_type: "resync_required", data });
  }
  if (data.frame_type === "authorization_lost") {
    return Object.freeze({ supported: true, frame_type: "authorization_lost", data });
  }
  return Object.freeze({ supported: true, frame_type: "unavailable", data });
}

export interface SseChunkDecoder {
  push(chunk: Uint8Array | string): readonly ParsedSseFrame[];
  finish(): readonly ParsedSseFrame[];
}

export function createSseChunkDecoder(): SseChunkDecoder {
  let byteBuffer = new Uint8Array(0);

  function appendBytes(chunkBytes: Uint8Array): void {
    const next = new Uint8Array(byteBuffer.length + chunkBytes.length);
    next.set(byteBuffer, 0);
    next.set(chunkBytes, byteBuffer.length);
    byteBuffer = next;
  }

  function findNextDelimiter(buf: Uint8Array): { readonly index: number; readonly length: number } | null {
    for (let i = 0; i < buf.length; i += 1) {
      const b0 = buf[i]!;
      if (b0 === 0x0a && i + 1 < buf.length && buf[i + 1] === 0x0a) {
        return { index: i, length: 2 };
      }
      if (b0 === 0x0d) {
        if (i + 1 < buf.length && buf[i + 1] === 0x0d) {
          return { index: i, length: 2 };
        }
        if (
          i + 3 < buf.length &&
          buf[i + 1] === 0x0a &&
          buf[i + 2] === 0x0d &&
          buf[i + 3] === 0x0a
        ) {
          return { index: i, length: 4 };
        }
      }
    }
    return null;
  }

  return {
    push(chunk: Uint8Array | string): readonly ParsedSseFrame[] {
      const chunkBytes =
        typeof chunk === "string" ? encodeUtf8Bytes(chunk, "sse_chunk") : chunk;
      appendBytes(chunkBytes);

      const frames: ParsedSseFrame[] = [];
      while (true) {
        const delim = findNextDelimiter(byteBuffer);
        if (delim === null) {
          if (byteBuffer.length > WATCH_MAX_FRAME_BYTES) {
            throw new ValidationDomainError({
              code: "PAYLOAD_TOO_LARGE",
              message: `Incomplete SSE frame buffer (${byteBuffer.length} bytes) exceeds ${WATCH_MAX_FRAME_BYTES} byte limit`
            });
          }
          break;
        }
        const frameSlice = byteBuffer.subarray(0, delim.index);
        byteBuffer = byteBuffer.subarray(delim.index + delim.length);
        if (frameSlice.length === 0) {
          continue;
        }
        if (frameSlice.length > WATCH_MAX_FRAME_BYTES) {
          throw new ValidationDomainError({
            code: "PAYLOAD_TOO_LARGE",
            message: `SSE frame (${frameSlice.length} bytes) exceeds ${WATCH_MAX_FRAME_BYTES} byte limit`
          });
        }
        const text = decodeUtf8BytesStrict(frameSlice, "sse_frame");
        if (text.trim().length > 0) {
          frames.push(parseSseFrame(text));
        }
      }
      return Object.freeze(frames);
    },

    finish(): readonly ParsedSseFrame[] {
      if (byteBuffer.length === 0) {
        return Object.freeze([]);
      }
      if (byteBuffer.length > WATCH_MAX_FRAME_BYTES) {
        throw new ValidationDomainError({
          code: "PAYLOAD_TOO_LARGE",
          message: `Trailing SSE frame (${byteBuffer.length} bytes) exceeds ${WATCH_MAX_FRAME_BYTES} byte limit`
        });
      }
      const text = decodeUtf8BytesStrict(byteBuffer, "sse_frame");
      byteBuffer = new Uint8Array(0);
      if (text.trim().length === 0) {
        return Object.freeze([]);
      }
      return Object.freeze([parseSseFrame(text)]);
    }
  };
}
