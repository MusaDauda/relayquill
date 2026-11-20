import {
  type CanonicalUtcTimestamp,
  type EventId,
  type EventTypeId,
  type EventTypeName,
  InvariantViolationError,
  type PositiveInt64String,
  type ProjectId,
  type RepresentationProfileId,
  type Sha256Hex,
  ValidationDomainError
} from "@relayquill/domain";
import {
  DERIVED_MAX_CONTENT_BYTES,
  EVENT_CONTENT_ENCODING,
  EVENT_CONTENT_MEDIA_TYPE,
  type SerializedWebhookEnvelope,
  type WebhookEnvelopeV2,
  encodeBase64,
  encodeUtf8Bytes,
  serializeWebhookEnvelope,
  sha256Hex
} from "@relayquill/contracts";
import { isLosslessNumber } from "lossless-json";
import { evaluateParsedEvent } from "./evaluator.js";
import { normalizeNumericToken } from "./numeric.js";
import {
  type LosslessJsonValue,
  type ParsedLosslessJsonResult,
  isPlainObjectRecord,
  parseEventJsonBytes,
  parseEventJsonString,
  serializeStrictJsonString
} from "./parser.js";
import { resolveJsonPointer } from "./pointer.js";
import {
  type CompiledProjectionProfile,
  PROJECTION_COMPILER_VERSION,
  type ProjectionWriterNode
} from "./projection-profile.js";
import {
  type ProjectionLiteralValue,
  computeDerivedWireEnvelopeUpperBoundBytes,
  serializePolicyLiteralJson
} from "./projection-size.js";

export * from "./projection-size.js";
export * from "./projection-profile.js";

export interface ProjectionProvenanceRecord {
  readonly compiler_profile_version: typeof PROJECTION_COMPILER_VERSION;
  readonly source_content_sha256: Sha256Hex;
  readonly derived_content_sha256: Sha256Hex;
  readonly profile_sha256: Sha256Hex;
  readonly source_schema_version: number;
  readonly target_schema_version: number;
  readonly policy_constant_paths: readonly string[];
  readonly applied_default_paths: readonly string[];
  readonly contains_original_provenance: true;
  readonly is_private_data_redaction: false;
}

export interface ExecutedProjectionResult {
  readonly compilerProfileVersion: typeof PROJECTION_COMPILER_VERSION;
  readonly sourceBytes: Uint8Array;
  readonly sourceByteCount: number;
  readonly sourceContentSha256: Sha256Hex;
  readonly derivedJson: string;
  readonly derivedBytes: Uint8Array;
  readonly derivedByteCount: number;
  readonly derivedContentSha256: Sha256Hex;
  readonly targetSchemaVersion: number;
  readonly provenance: ProjectionProvenanceRecord;
}

type RuntimeSerializedSlot =
  | { readonly kind: "lossless"; readonly value: LosslessJsonValue }
  | { readonly kind: "policy"; readonly value: ProjectionLiteralValue };

function compareCodeUnits(a: string, b: string): number {
  if (a === b) {
    return 0;
  }
  return a < b ? -1 : 1;
}

function serializeLosslessSourceValue(value: LosslessJsonValue, fieldPath = "$"): string {
  if (value === null) {
    return "null";
  }
  if (typeof value === "boolean") {
    return value ? "true" : "false";
  }
  if (typeof value === "string") {
    return serializeStrictJsonString(value, fieldPath);
  }
  if (isLosslessNumber(value)) {
    // Re-validate numeric token bounds without rounding or Number conversion
    normalizeNumericToken(value.value, fieldPath);
    return value.value;
  }
  if (Array.isArray(value)) {
    const items = value as readonly LosslessJsonValue[];
    const parts: string[] = [];
    for (let i = 0; i < items.length; i += 1) {
      parts.push(serializeLosslessSourceValue(items[i]!, `${fieldPath}[${i}]`));
    }
    return `[${parts.join(",")}]`;
  }
  if (isPlainObjectRecord(value)) {
    const keys = Object.keys(value).sort(compareCodeUnits);
    const parts: string[] = [];
    for (const key of keys) {
      parts.push(
        `${serializeStrictJsonString(key, `${fieldPath}.${key}`)}:${serializeLosslessSourceValue(
          value[key] as LosslessJsonValue,
          `${fieldPath}.${key}`
        )}`
      );
    }
    return `{${parts.join(",")}}`;
  }
  throw new InvariantViolationError({
    message: `Unsupported lossless value encountered during projection serialization at ${fieldPath}`
  });
}

function buildWriterOutputJson(
  node: ProjectionWriterNode & { readonly kind: "object" },
  sourceAst: LosslessJsonValue,
  appliedDefaults: string[],
  constantPaths: string[]
): { readonly present: boolean; readonly json: string } {
  const keys = Array.from(node.children.keys()).sort(compareCodeUnits);
  const parts: string[] = [];

  for (const key of keys) {
    const child = node.children.get(key)!;
    if (child.kind === "object") {
      const sub = buildWriterOutputJson(child, sourceAst, appliedDefaults, constantPaths);
      if (sub.present) {
        parts.push(`${serializeStrictJsonString(key)}:${sub.json}`);
      }
      continue;
    }

    const rule = child.rule;
    let slot: RuntimeSerializedSlot | undefined;

    if (rule.operation === "constant") {
      constantPaths.push(rule.targetPointer.raw);
      slot = { kind: "policy", value: rule.value };
    } else if (rule.operation === "copy") {
      const res = resolveJsonPointer(sourceAst, rule.sourcePointer);
      if (res.present) {
        slot = { kind: "lossless", value: res.value as LosslessJsonValue };
      }
    } else {
      // copy_or_default substitutes ONLY on missing source, never on null/0/false.
      const res = resolveJsonPointer(sourceAst, rule.sourcePointer);
      if (res.present) {
        slot = { kind: "lossless", value: res.value as LosslessJsonValue };
      } else {
        appliedDefaults.push(rule.targetPointer.raw);
        slot = { kind: "policy", value: rule.defaultValue };
      }
    }

    if (slot !== undefined) {
      const serialized =
        slot.kind === "lossless"
          ? serializeLosslessSourceValue(slot.value, rule.targetPointer.raw)
          : serializePolicyLiteralJson(slot.value);
      parts.push(`${serializeStrictJsonString(key)}:${serialized}`);
    }
  }

  if (parts.length === 0 && !node.requiredInTarget) {
    return { present: false, json: "{}" };
  }

  return { present: true, json: `{${parts.join(",")}}` };
}

export function executeProjection(
  compiledProfile: CompiledProjectionProfile,
  sourceInput: Uint8Array | string | ParsedLosslessJsonResult
): ExecutedProjectionResult {
  const parsedSource: ParsedLosslessJsonResult =
    sourceInput instanceof Uint8Array
      ? parseEventJsonBytes(sourceInput)
      : typeof sourceInput === "string"
        ? parseEventJsonString(sourceInput)
        : sourceInput;

  const sourceEval = evaluateParsedEvent(compiledProfile.sourceSchema, parsedSource.value);
  if (!sourceEval.valid) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Source event does not conform to source schema: ${sourceEval.diagnostics[0]?.message ?? "invalid"}`,
      fieldErrors: sourceEval.diagnostics.map((d) => ({ path: d.path, code: d.code }))
    });
  }

  const appliedDefaultPaths: string[] = [];
  const policyConstantPaths: string[] = [];

  const built = buildWriterOutputJson(
    compiledProfile.writerRoot,
    parsedSource.value,
    appliedDefaultPaths,
    policyConstantPaths
  );
  const derivedJson = built.json;
  const derivedBytes = encodeUtf8Bytes(derivedJson, "derived_projection");

  if (derivedBytes.length > DERIVED_MAX_CONTENT_BYTES) {
    throw new InvariantViolationError({
      message: `Derived projection output (${derivedBytes.length} bytes) exceeds ${DERIVED_MAX_CONTENT_BYTES} bytes`
    });
  }
  if (derivedBytes.length > compiledProfile.provenOutputMaxBytes) {
    throw new InvariantViolationError({
      message: `Derived projection output (${derivedBytes.length} bytes) exceeded proven upper bound (${compiledProfile.provenOutputMaxBytes} bytes)`
    });
  }

  // Defensive post-serialization target schema validation
  const parsedDerived = parseEventJsonBytes(derivedBytes, {
    fieldPath: "derived_projection",
    maxDecodedBytes: DERIVED_MAX_CONTENT_BYTES
  });
  const targetEval = evaluateParsedEvent(compiledProfile.targetSchema, parsedDerived.value);
  if (!targetEval.valid) {
    throw new InvariantViolationError({
      message: `Derived projection output failed defensive target schema verification: ${targetEval.diagnostics[0]?.message ?? "invalid"}`
    });
  }

  const derivedContentSha256 = sha256Hex(derivedBytes);

  return Object.freeze({
    compilerProfileVersion: PROJECTION_COMPILER_VERSION,
    sourceBytes: parsedSource.rawBytes,
    sourceByteCount: parsedSource.byteCount,
    sourceContentSha256: parsedSource.sha256,
    derivedJson,
    derivedBytes,
    derivedByteCount: derivedBytes.length,
    derivedContentSha256,
    targetSchemaVersion: compiledProfile.targetSchemaVersion,
    provenance: Object.freeze({
      compiler_profile_version: PROJECTION_COMPILER_VERSION,
      source_content_sha256: parsedSource.sha256,
      derived_content_sha256: derivedContentSha256,
      profile_sha256: compiledProfile.definitionSha256,
      source_schema_version: compiledProfile.sourceSchemaVersion,
      target_schema_version: compiledProfile.targetSchemaVersion,
      policy_constant_paths: Object.freeze(policyConstantPaths.sort(compareCodeUnits)),
      applied_default_paths: Object.freeze(appliedDefaultPaths.sort(compareCodeUnits)),
      contains_original_provenance: true,
      is_private_data_redaction: false
    })
  });
}

export interface BuildDerivedWebhookEnvelopeV2Input {
  readonly representation_version: number;
  readonly project_id: ProjectId;
  readonly event_id: EventId;
  readonly project_event_sequence: PositiveInt64String;
  readonly event_type_id: EventTypeId;
  readonly event_type: EventTypeName;
  readonly event_schema_version: number;
  readonly admitted_at: CanonicalUtcTimestamp;
  readonly producer_event_time: CanonicalUtcTimestamp | null;
  readonly profile_id: RepresentationProfileId;
  readonly profile_version: PositiveInt64String;
  readonly profile_sha256: Sha256Hex;
  readonly projection: ExecutedProjectionResult;
}

export function buildDerivedWebhookEnvelopeV2(
  input: BuildDerivedWebhookEnvelopeV2Input
): SerializedWebhookEnvelope {
  computeDerivedWireEnvelopeUpperBoundBytes({
    originalContentByteCount: input.projection.sourceByteCount,
    provenDerivedMaxBytes: input.projection.derivedByteCount,
    eventType: input.event_type,
    hasProducerEventTime: input.producer_event_time !== null
  });

  const envelope: WebhookEnvelopeV2 = Object.freeze({
    envelope_version: 2,
    representation_version: input.representation_version,
    project_id: input.project_id,
    event_id: input.event_id,
    project_event_sequence: input.project_event_sequence,
    event_type_id: input.event_type_id,
    event_type: input.event_type,
    event_schema_version: input.event_schema_version,
    admitted_at: input.admitted_at,
    producer_event_time: input.producer_event_time,
    content: Object.freeze({
      media_type: EVENT_CONTENT_MEDIA_TYPE,
      encoding: EVENT_CONTENT_ENCODING,
      byte_count: input.projection.sourceByteCount,
      sha256: input.projection.sourceContentSha256,
      data: encodeBase64(input.projection.sourceBytes)
    }),
    derived: Object.freeze({
      profile_id: input.profile_id,
      profile_version: input.profile_version,
      profile_sha256: input.profile_sha256,
      target_event_schema_version: input.projection.targetSchemaVersion,
      media_type: EVENT_CONTENT_MEDIA_TYPE,
      encoding: EVENT_CONTENT_ENCODING,
      byte_count: input.projection.derivedByteCount,
      sha256: input.projection.derivedContentSha256,
      data: encodeBase64(input.projection.derivedBytes)
    })
  });

  return serializeWebhookEnvelope(envelope);
}
