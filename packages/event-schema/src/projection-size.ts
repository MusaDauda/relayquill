import {
  EVENT_MAX_CONTENT_BYTES,
  EVENT_MAX_ENVELOPE_BYTES,
  EVENT_MAX_NUMERIC_TOKEN_BYTES,
  LimitExceededDomainError,
  ValidationDomainError,
  computeUtf8ByteLength
} from "@relayquill/domain";
import {
  DERIVED_MAX_CONTENT_BYTES,
  EVENT_CONTENT_ENCODING,
  EVENT_CONTENT_MEDIA_TYPE,
  type CanonicalJsonValue,
  canonicalizeJsonBytes
} from "@relayquill/contracts";
import { type NormalizedDecimal, formatNormalizedDecimal } from "./numeric.js";
import { serializeStrictJsonString } from "./parser.js";
import {
  type CompiledEventSchema,
  type NormalizedScalarLiteral,
  type NormalizedSchemaNode,
  dereferenceSchemaNode
} from "./profile.js";

export { DERIVED_MAX_CONTENT_BYTES, EVENT_MAX_ENVELOPE_BYTES };

export type ProjectionLiteralValue =
  | null
  | boolean
  | string
  | { readonly kind: "normalized_number"; readonly value: NormalizedDecimal }
  | readonly ProjectionLiteralValue[]
  | { readonly [key: string]: ProjectionLiteralValue };

function compareCodeUnits(a: string, b: string): number {
  if (a === b) {
    return 0;
  }
  return a < b ? -1 : 1;
}

export function serializeScalarLiteralJson(literal: NormalizedScalarLiteral): string {
  switch (literal.kind) {
    case "null":
      return "null";
    case "boolean":
      return literal.value ? "true" : "false";
    case "string":
      return serializeStrictJsonString(literal.value);
    case "number":
      return formatNormalizedDecimal(literal.value);
  }
}

export function serializePolicyLiteralJson(value: ProjectionLiteralValue): string {
  if (value === null) {
    return "null";
  }
  if (typeof value === "boolean") {
    return value ? "true" : "false";
  }
  if (typeof value === "string") {
    return serializeStrictJsonString(value);
  }
  if (Array.isArray(value)) {
    const items = value as readonly ProjectionLiteralValue[];
    const parts: string[] = [];
    for (const item of items) {
      parts.push(serializePolicyLiteralJson(item));
    }
    return `[${parts.join(",")}]`;
  }
  if (typeof value === "object") {
    const rec = value as Record<string, unknown>;
    if (
      rec.kind === "normalized_number" &&
      Object.prototype.hasOwnProperty.call(rec, "value") &&
      Object.keys(rec).length === 2
    ) {
      return formatNormalizedDecimal(rec.value as NormalizedDecimal);
    }
    const keys = Object.keys(rec).sort(compareCodeUnits);
    const parts: string[] = [];
    for (const key of keys) {
      parts.push(
        `${serializeStrictJsonString(key)}:${serializePolicyLiteralJson(
          rec[key] as ProjectionLiteralValue
        )}`
      );
    }
    return `{${parts.join(",")}}`;
  }
  throw new ValidationDomainError({
    code: "INVALID_VALUE",
    message: `Unsupported policy literal type "${typeof value}"`
  });
}

function addBoundedBytes(a: number, b: number, limit: number, context: string): number {
  const sum = a + b;
  if (!Number.isSafeInteger(sum) || sum > limit) {
    throw new LimitExceededDomainError({
      code: "SCHEMA_EVALUATION_LIMIT",
      message: `${context} worst-case byte bound exceeds ${limit} bytes`
    });
  }
  return sum;
}

function mulBoundedBytes(count: number, unit: number, limit: number, context: string): number {
  if (count === 0 || unit === 0) {
    return 0;
  }
  if (count > limit || unit > limit) {
    throw new LimitExceededDomainError({
      code: "SCHEMA_EVALUATION_LIMIT",
      message: `${context} worst-case byte bound exceeds ${limit} bytes`
    });
  }
  const prod = count * unit;
  if (!Number.isSafeInteger(prod) || prod > limit) {
    throw new LimitExceededDomainError({
      code: "SCHEMA_EVALUATION_LIMIT",
      message: `${context} worst-case byte bound exceeds ${limit} bytes`
    });
  }
  return prod;
}

export function computeWorstCaseSchemaValueBytes(
  schemaNode: NormalizedSchemaNode,
  schema: CompiledEventSchema,
  limit: number = DERIVED_MAX_CONTENT_BYTES
): number {
  const node = dereferenceSchemaNode(schemaNode, schema);
  let baseMax = 0;

  switch (node.kind) {
    case "null": {
      baseMax = 4;
      break;
    }
    case "boolean": {
      if (node.const !== undefined) {
        baseMax = computeUtf8ByteLength(serializeScalarLiteralJson(node.const));
      } else if (node.enum !== undefined) {
        for (const lit of node.enum) {
          baseMax = Math.max(baseMax, computeUtf8ByteLength(serializeScalarLiteralJson(lit)));
        }
      } else {
        baseMax = 5;
      }
      break;
    }
    case "string": {
      if (node.const !== undefined) {
        baseMax = computeUtf8ByteLength(serializeScalarLiteralJson(node.const));
      } else if (node.enum !== undefined) {
        for (const lit of node.enum) {
          baseMax = Math.max(baseMax, computeUtf8ByteLength(serializeScalarLiteralJson(lit)));
        }
      } else {
        // Every Unicode scalar can expand to at most 6 JSON bytes (\u00XX).
        baseMax = addBoundedBytes(
          2,
          mulBoundedBytes(node.maxLength, 6, limit, "string"),
          limit,
          "string"
        );
      }
      break;
    }
    case "integer":
    case "number": {
      // Copied numeric values retain their original source lexeme (up to 256B).
      baseMax = EVENT_MAX_NUMERIC_TOKEN_BYTES;
      break;
    }
    case "array": {
      if (node.maxItems === 0) {
        baseMax = 2;
      } else {
        const itemMax = computeWorstCaseSchemaValueBytes(node.items, schema, limit);
        const itemsTotal = mulBoundedBytes(node.maxItems, itemMax, limit, "array");
        const commas = node.maxItems - 1;
        baseMax = addBoundedBytes(2 + commas, itemsTotal, limit, "array");
      }
      break;
    }
    case "object": {
      const propNames = Object.keys(node.properties).sort(compareCodeUnits);
      let total = 2;
      for (let i = 0; i < propNames.length; i += 1) {
        const key = propNames[i]!;
        const keySerializedBytes = computeUtf8ByteLength(serializeStrictJsonString(key));
        const valBytes = computeWorstCaseSchemaValueBytes(node.properties[key]!, schema, limit);
        const comma = i > 0 ? 1 : 0;
        total = addBoundedBytes(total, keySerializedBytes + 1 + comma + valBytes, limit, "object");
      }
      baseMax = total;
      break;
    }
  }

  const finalMax = node.nullable ? Math.max(4, baseMax) : baseMax;
  if (finalMax > limit) {
    throw new LimitExceededDomainError({
      code: "SCHEMA_EVALUATION_LIMIT",
      message: `Projected value worst-case size (${finalMax}) exceeds ${limit} bytes`
    });
  }
  return finalMax;
}

export interface DerivedWireEnvelopeUpperBoundInput {
  readonly originalContentByteCount: number;
  readonly provenDerivedMaxBytes: number;
  readonly eventType?: string | undefined;
  readonly hasProducerEventTime?: boolean | undefined;
}

export function base64EncodedByteLength(rawByteCount: number): number {
  if (!Number.isInteger(rawByteCount) || rawByteCount < 0) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: "rawByteCount must be a non-negative integer"
    });
  }
  return Math.ceil(rawByteCount / 3) * 4;
}

export function computeDerivedWireEnvelopeUpperBoundBytes(
  input: DerivedWireEnvelopeUpperBoundInput
): number {
  if (
    !Number.isInteger(input.originalContentByteCount) ||
    input.originalContentByteCount < 1 ||
    input.originalContentByteCount > EVENT_MAX_CONTENT_BYTES
  ) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `originalContentByteCount must be within [1, ${EVENT_MAX_CONTENT_BYTES}]`
    });
  }
  if (
    !Number.isInteger(input.provenDerivedMaxBytes) ||
    input.provenDerivedMaxBytes < 1 ||
    input.provenDerivedMaxBytes > DERIVED_MAX_CONTENT_BYTES
  ) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `provenDerivedMaxBytes must be within [1, ${DERIVED_MAX_CONTENT_BYTES}]`
    });
  }

  const maxEventType = input.eventType ?? "a".repeat(128);
  const origB64Len = base64EncodedByteLength(input.originalContentByteCount);
  const derivedB64Len = base64EncodedByteLength(input.provenDerivedMaxBytes);

  const skeleton: Record<string, CanonicalJsonValue> = {
    envelope_version: 2,
    representation_version: 2_147_483_647,
    project_id: "00000000-0000-4000-8000-000000000000",
    event_id: "00000000-0000-4000-8000-000000000000",
    project_event_sequence: "9223372036854775807",
    event_type_id: "00000000-0000-4000-8000-000000000000",
    event_type: maxEventType,
    event_schema_version: 2_147_483_647,
    admitted_at: "2026-11-01T12:00:00.123456Z",
    producer_event_time:
      input.hasProducerEventTime === false ? null : "2026-11-01T12:00:00.123456Z",
    content: {
      media_type: EVENT_CONTENT_MEDIA_TYPE,
      encoding: EVENT_CONTENT_ENCODING,
      byte_count: input.originalContentByteCount,
      sha256: "0".repeat(64),
      data: "A".repeat(origB64Len)
    },
    derived: {
      profile_id: "00000000-0000-4000-8000-000000000000",
      profile_version: "9223372036854775807",
      profile_sha256: "0".repeat(64),
      target_event_schema_version: 2_147_483_647,
      media_type: EVENT_CONTENT_MEDIA_TYPE,
      encoding: EVENT_CONTENT_ENCODING,
      byte_count: input.provenDerivedMaxBytes,
      sha256: "0".repeat(64),
      data: "A".repeat(derivedB64Len)
    }
  };

  const wireBytes = canonicalizeJsonBytes(skeleton, "derived_wire_upper_bound").length;
  if (wireBytes > EVENT_MAX_ENVELOPE_BYTES) {
    throw new LimitExceededDomainError({
      code: "PAYLOAD_TOO_LARGE",
      message: `Derived wire envelope upper bound (${wireBytes} bytes) exceeds ${EVENT_MAX_ENVELOPE_BYTES} bytes`
    });
  }
  return wireBytes;
}
