import {
  BROKER_DEDUP_WINDOW_MS,
  BROKER_EVENT_MAX_PAYLOAD_BYTES,
  BROKER_EVENT_STREAM_NAME,
  type Brand,
  FANOUT_CONSUMER_NAME,
  ValidationDomainError,
  formatBrokerEventSubject,
  formatBrokerMessageId
} from "@relayquill/domain";
import { type CanonicalJsonValue, canonicalizeJson } from "./canonical-command.js";
import {
  type EventId,
  type OutboxId,
  type PositiveInt64String,
  type ProjectId,
  type Sha256Hex,
  assertAllowedKeys,
  assertPlainRecord,
  decodeUtf8BytesStrict,
  encodeUtf8Bytes,
  parseBoundedInteger,
  parseEventId,
  parseOutboxId,
  parsePositiveInt64BigInt,
  parsePositiveInt64String,
  parseProjectId,
  parseSha256Hex,
  parseStrictJsonObject,
  sha256Hex
} from "./http/values.js";
import {
  type ParsedW3CTraceparent,
  W3C_TRACEPARENT_LENGTH,
  W3C_TRACESTATE_MAX_BYTES,
  W3C_TRACESTATE_MAX_ENTRIES,
  parseW3CTraceparent,
  parseW3CTracestate
} from "./internal/trace.js";

export {
  BROKER_DEDUP_WINDOW_MS,
  BROKER_EVENT_MAX_PAYLOAD_BYTES,
  BROKER_EVENT_STREAM_NAME,
  FANOUT_CONSUMER_NAME,
  type ParsedW3CTraceparent,
  W3C_TRACEPARENT_LENGTH,
  W3C_TRACESTATE_MAX_BYTES,
  W3C_TRACESTATE_MAX_ENTRIES,
  formatBrokerEventSubject,
  formatBrokerMessageId,
  parseW3CTraceparent,
  parseW3CTracestate
};

export const BROKER_ENVELOPE_VERSION = 1 as const;

export type BrokerMessageId = Brand<string, "BrokerMessageId">;

export interface DecodedBrokerMessageId {
  readonly message_id: BrokerMessageId;
  readonly outbox_id: OutboxId;
  readonly publication_generation: PositiveInt64String;
}

export interface BrokerNotificationEnvelopeV1 {
  readonly envelope_version: typeof BROKER_ENVELOPE_VERSION;
  readonly outbox_id: OutboxId;
  readonly event_id: EventId;
  readonly project_id: ProjectId;
  readonly topology_version: PositiveInt64String;
  readonly publication_generation: PositiveInt64String;
  readonly content_sha256: Sha256Hex;
  readonly traceparent?: string | undefined;
  readonly tracestate?: string | undefined;
}

export interface BrokerNotificationInput {
  readonly envelope_version?: 1 | undefined;
  readonly outbox_id: OutboxId | string;
  readonly event_id: EventId | string;
  readonly project_id: ProjectId | string;
  readonly topology_version: PositiveInt64String | bigint | string;
  readonly publication_generation: PositiveInt64String | bigint | string;
  readonly content_sha256: Sha256Hex | string;
  readonly traceparent?: string | undefined;
  readonly tracestate?: string | undefined;
}

export interface EncodedBrokerNotification {
  readonly envelope: BrokerNotificationEnvelopeV1;
  readonly broker_message_id: BrokerMessageId;
  readonly subject: string;
  readonly json: string;
  readonly bytes: Uint8Array;
  readonly byte_count: number;
  readonly envelope_sha256: Sha256Hex;
}

const BROKER_MESSAGE_ID_REGEX =
  /^rq:([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}):([1-9][0-9]*)$/;
const BROKER_EVENT_SUBJECT_REGEX =
  /^rq\.events\.([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\.accepted$/;

const BROKER_ENVELOPE_KEYS = new Set([
  "envelope_version",
  "outbox_id",
  "event_id",
  "project_id",
  "topology_version",
  "publication_generation",
  "content_sha256",
  "traceparent",
  "tracestate"
]);

export function encodeBrokerMessageId(
  outboxId: OutboxId | string,
  publicationGeneration: PositiveInt64String | bigint | number
): BrokerMessageId {
  const validOutboxId = parseOutboxId(outboxId, "outbox_id");
  const gen = parsePositiveInt64BigInt(publicationGeneration, "publication_generation");
  return formatBrokerMessageId(validOutboxId, gen) as BrokerMessageId;
}

export function decodeBrokerMessageId(
  value: unknown,
  fieldPath = "broker_message_id"
): DecodedBrokerMessageId {
  if (typeof value !== "string") {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Expected string for ${fieldPath}`,
      fieldErrors: [{ path: fieldPath, code: "INVALID_VALUE" }]
    });
  }
  const match = BROKER_MESSAGE_ID_REGEX.exec(value);
  if (match === null || match[1] === undefined || match[2] === undefined) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Malformed broker_message_id for ${fieldPath}`,
      fieldErrors: [{ path: fieldPath, code: "INVALID_VALUE" }]
    });
  }
  const outboxId = parseOutboxId(match[1], `${fieldPath}.outbox_id`);
  const generation = parsePositiveInt64String(match[2], `${fieldPath}.publication_generation`);
  return Object.freeze({
    message_id: value as BrokerMessageId,
    outbox_id: outboxId,
    publication_generation: generation
  });
}

export function parseBrokerEventSubject(
  value: unknown,
  fieldPath = "subject"
): { readonly subject: string; readonly project_id: ProjectId } {
  if (typeof value !== "string") {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Expected string for ${fieldPath}`,
      fieldErrors: [{ path: fieldPath, code: "INVALID_VALUE" }]
    });
  }
  const match = BROKER_EVENT_SUBJECT_REGEX.exec(value);
  if (match === null || match[1] === undefined) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Invalid broker event subject "${value}"`,
      fieldErrors: [{ path: fieldPath, code: "INVALID_VALUE" }]
    });
  }
  const projectId = parseProjectId(match[1], `${fieldPath}.project_id`);
  return Object.freeze({
    subject: value,
    project_id: projectId
  });
}

export function parseBrokerNotificationEnvelope(
  value: unknown,
  fieldPath = "broker_envelope"
): BrokerNotificationEnvelopeV1 {
  const rec = assertPlainRecord(value, fieldPath);
  assertAllowedKeys(rec, BROKER_ENVELOPE_KEYS, fieldPath);

  const envVer = parseBoundedInteger(rec.envelope_version, {
    fieldPath: `${fieldPath}.envelope_version`,
    min: BROKER_ENVELOPE_VERSION,
    max: BROKER_ENVELOPE_VERSION
  });
  if (envVer !== BROKER_ENVELOPE_VERSION) {
    throw new ValidationDomainError({
      code: "UNSUPPORTED_SCHEMA_VERSION",
      message: `Unsupported broker envelope_version ${envVer}`,
      fieldErrors: [{ path: `${fieldPath}.envelope_version`, code: "UNSUPPORTED_SCHEMA_VERSION" }]
    });
  }

  const outboxId = parseOutboxId(rec.outbox_id, `${fieldPath}.outbox_id`);
  const eventId = parseEventId(rec.event_id, `${fieldPath}.event_id`);
  const projectId = parseProjectId(rec.project_id, `${fieldPath}.project_id`);
  const topologyVersion = parsePositiveInt64String(
    rec.topology_version,
    `${fieldPath}.topology_version`
  );
  const publicationGeneration = parsePositiveInt64String(
    rec.publication_generation,
    `${fieldPath}.publication_generation`
  );
  const contentSha256 = parseSha256Hex(rec.content_sha256, `${fieldPath}.content_sha256`);

  const traceparent =
    rec.traceparent !== undefined
      ? parseW3CTraceparent(rec.traceparent, `${fieldPath}.traceparent`).raw
      : undefined;
  const tracestate =
    rec.tracestate !== undefined
      ? parseW3CTracestate(rec.tracestate, `${fieldPath}.tracestate`)
      : undefined;

  return Object.freeze({
    envelope_version: BROKER_ENVELOPE_VERSION,
    outbox_id: outboxId,
    event_id: eventId,
    project_id: projectId,
    topology_version: topologyVersion,
    publication_generation: publicationGeneration,
    content_sha256: contentSha256,
    ...(traceparent !== undefined ? { traceparent } : {}),
    ...(tracestate !== undefined ? { tracestate } : {})
  });
}

export function encodeBrokerNotificationEnvelope(
  input: BrokerNotificationInput
): EncodedBrokerNotification {
  const normalizedInput: Record<string, unknown> = {
    envelope_version: input.envelope_version ?? BROKER_ENVELOPE_VERSION,
    outbox_id: input.outbox_id,
    event_id: input.event_id,
    project_id: input.project_id,
    topology_version:
      typeof input.topology_version === "bigint"
        ? input.topology_version.toString(10)
        : input.topology_version,
    publication_generation:
      typeof input.publication_generation === "bigint"
        ? input.publication_generation.toString(10)
        : input.publication_generation,
    content_sha256: input.content_sha256,
    ...(input.traceparent !== undefined ? { traceparent: input.traceparent } : {}),
    ...(input.tracestate !== undefined ? { tracestate: input.tracestate } : {})
  };

  const envelope = parseBrokerNotificationEnvelope(normalizedInput, "broker_envelope");
  const json = canonicalizeJson(
    envelope as unknown as CanonicalJsonValue,
    "broker_envelope"
  );
  const bytes = encodeUtf8Bytes(json, "broker_envelope");
  if (bytes.length > BROKER_EVENT_MAX_PAYLOAD_BYTES) {
    throw new ValidationDomainError({
      code: "PAYLOAD_TOO_LARGE",
      message: `Broker notification payload (${bytes.length} bytes) exceeds ${BROKER_EVENT_MAX_PAYLOAD_BYTES} bytes`,
      fieldErrors: [{ path: "broker_envelope", code: "PAYLOAD_TOO_LARGE" }]
    });
  }

  const brokerMessageId = encodeBrokerMessageId(
    envelope.outbox_id,
    envelope.publication_generation
  );
  const subject = formatBrokerEventSubject(envelope.project_id);

  return Object.freeze({
    envelope,
    broker_message_id: brokerMessageId,
    subject,
    json,
    bytes,
    byte_count: bytes.length,
    envelope_sha256: sha256Hex(bytes)
  });
}

export function decodeBrokerNotificationEnvelope(
  payload: Uint8Array | string
): BrokerNotificationEnvelopeV1 & {
  readonly broker_message_id: BrokerMessageId;
  readonly envelope_sha256: Sha256Hex;
} {
  let bytes: Uint8Array;
  let text: string;

  if (payload instanceof Uint8Array) {
    bytes = payload;
    if (bytes.length === 0 || bytes.length > BROKER_EVENT_MAX_PAYLOAD_BYTES) {
      throw new ValidationDomainError({
        code: bytes.length > BROKER_EVENT_MAX_PAYLOAD_BYTES ? "PAYLOAD_TOO_LARGE" : "INVALID_VALUE",
        message: `Broker notification payload size ${bytes.length} out of bounds [1, ${BROKER_EVENT_MAX_PAYLOAD_BYTES}]`
      });
    }
    text = decodeUtf8BytesStrict(bytes, "broker_envelope");
  } else if (typeof payload === "string") {
    bytes = encodeUtf8Bytes(payload, "broker_envelope");
    if (bytes.length === 0 || bytes.length > BROKER_EVENT_MAX_PAYLOAD_BYTES) {
      throw new ValidationDomainError({
        code: bytes.length > BROKER_EVENT_MAX_PAYLOAD_BYTES ? "PAYLOAD_TOO_LARGE" : "INVALID_VALUE",
        message: `Broker notification payload size ${bytes.length} out of bounds [1, ${BROKER_EVENT_MAX_PAYLOAD_BYTES}]`
      });
    }
    text = payload;
  } else {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: "Broker notification payload must be Uint8Array or string"
    });
  }

  const obj = parseStrictJsonObject(text, {
    fieldPath: "broker_envelope",
    maxDepth: 4,
    maxNodes: 32
  });
  const envelope = parseBrokerNotificationEnvelope(obj, "broker_envelope");
  return Object.freeze({
    ...envelope,
    broker_message_id: encodeBrokerMessageId(
      envelope.outbox_id,
      envelope.publication_generation
    ),
    envelope_sha256: sha256Hex(bytes)
  });
}
