import {
  type ChannelKind,
  type CommandReceiptScopeKind,
  EVENT_MAX_CONTENT_BYTES,
  ValidationDomainError,
  assertProducerChannelBinding,
  hasLoneSurrogate,
  isChannelKind,
  isCommandReceiptScopeKind
} from "@relayquill/domain";
import {
  type BusinessKey,
  type CanonicalUtcTimestamp,
  type EventId,
  type EventTypeId,
  type EventTypeName,
  type IdempotencyKey,
  type OrderingDomainId,
  type PositiveInt64String,
  type PrincipalId,
  type ProducerId,
  type ProducerNamespace,
  type ProjectId,
  type Sha256Hex,
  type SubscriptionId,
  type TenantId,
  encodeDomainLengthPrefixed,
  encodeUtf8Bytes,
  formatInt64,
  parseBoundedInteger,
  parseBusinessKey,
  parseCanonicalUtcTimestamp,
  parseEventId,
  parseEventTypeId,
  parseEventTypeName,
  parseIdempotencyKey,
  parseNullableUtcTimestamp,
  parseOrderingDomainId,
  parsePositiveInt32,
  parsePositiveInt64String,
  parsePrincipalId,
  parseProducerId,
  parseProducerNamespace,
  parseProjectId,
  parseSafeReasonCode,
  parseSha256Hex,
  parseSubscriptionId,
  parseTenantId,
  sha256Digest,
  sha256Hex,
  sha256HexToBytes
} from "./http/values.js";

export const COMMAND_HASH_SCHEMA_V1 = "relayquill.command.v1" as const;
export const EFFECTIVE_HASH_SCHEMA_V1 = "relayquill.effective.v1" as const;
export const CANONICAL_HASH_SCHEMA_VERSION = 1 as const;
export const CANONICAL_MAX_DEPTH = 32 as const;
export const ORDERING_KEY_MAX_UTF8_BYTES = 128 as const;

export type CanonicalJsonPrimitive = null | boolean | number | string;
export type CanonicalJsonValue =
  | CanonicalJsonPrimitive
  | readonly CanonicalJsonValue[]
  | { readonly [key: string]: CanonicalJsonValue };

function compareCodeUnits(a: string, b: string): number {
  if (a === b) {
    return 0;
  }
  return a < b ? -1 : 1;
}

function serializeCanonicalString(value: string, fieldPath: string): string {
  if (hasLoneSurrogate(value)) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Lone UTF-16 surrogate disallowed in canonical string at ${fieldPath}`,
      fieldErrors: [{ path: fieldPath, code: "INVALID_VALUE" }]
    });
  }
  let out = "\"";
  for (let i = 0; i < value.length; i += 1) {
    const code = value.charCodeAt(i);
    if (code === 0x22) {
      out += "\\\"";
    } else if (code === 0x5c) {
      out += "\\\\";
    } else if (code === 0x08) {
      out += "\\b";
    } else if (code === 0x09) {
      out += "\\t";
    } else if (code === 0x0a) {
      out += "\\n";
    } else if (code === 0x0c) {
      out += "\\f";
    } else if (code === 0x0d) {
      out += "\\r";
    } else if (code < 0x20) {
      out += `\\u00${code.toString(16).padStart(2, "0")}`;
    } else {
      out += value[i]!;
    }
  }
  out += "\"";
  return out;
}

function serializeCanonicalValue(
  value: unknown,
  depth: number,
  fieldPath: string
): string {
  if (depth > CANONICAL_MAX_DEPTH) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Canonical JSON nesting depth exceeds ${CANONICAL_MAX_DEPTH} at ${fieldPath}`,
      fieldErrors: [{ path: fieldPath, code: "INVALID_VALUE" }]
    });
  }
  if (value === null) {
    return "null";
  }
  if (typeof value === "boolean") {
    return value ? "true" : "false";
  }
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) {
      throw new ValidationDomainError({
        code: "INVALID_VALUE",
        message: `Canonical metadata accepts safe integers only; got ${String(value)} at ${fieldPath}`,
        fieldErrors: [{ path: fieldPath, code: "INVALID_VALUE" }]
      });
    }
    return Object.is(value, -0) ? "0" : value.toString(10);
  }
  if (typeof value === "string") {
    return serializeCanonicalString(value, fieldPath);
  }
  if (Array.isArray(value)) {
    const parts: string[] = [];
    for (let i = 0; i < value.length; i += 1) {
      parts.push(serializeCanonicalValue(value[i], depth + 1, `${fieldPath}[${i}]`));
    }
    return `[${parts.join(",")}]`;
  }
  if (typeof value === "object") {
    const proto: unknown = Object.getPrototypeOf(value);
    if (proto !== null && proto !== Object.prototype) {
      throw new ValidationDomainError({
        code: "INVALID_VALUE",
        message: `Non-plain object cannot be canonicalized at ${fieldPath}`,
        fieldErrors: [{ path: fieldPath, code: "INVALID_VALUE" }]
      });
    }
    const rec = value as Record<string, unknown>;
    const keys = Object.keys(rec).sort(compareCodeUnits);
    const parts: string[] = [];
    for (const key of keys) {
      const propVal = rec[key];
      if (propVal === undefined) {
        throw new ValidationDomainError({
          code: "INVALID_VALUE",
          message: `Canonical object property "${key}" cannot be undefined at ${fieldPath}`,
          fieldErrors: [{ path: `${fieldPath}.${key}`, code: "INVALID_VALUE" }]
        });
      }
      parts.push(
        `${serializeCanonicalString(key, `${fieldPath}.${key}`)}:${serializeCanonicalValue(
          propVal,
          depth + 1,
          `${fieldPath}.${key}`
        )}`
      );
    }
    return `{${parts.join(",")}}`;
  }
  throw new ValidationDomainError({
    code: "INVALID_VALUE",
    message: `Unsupported canonical value type "${typeof value}" at ${fieldPath}`,
    fieldErrors: [{ path: fieldPath, code: "INVALID_VALUE" }]
  });
}

export function canonicalizeJson(value: CanonicalJsonValue, fieldPath = "canonical"): string {
  return serializeCanonicalValue(value, 0, fieldPath);
}

export function canonicalizeJsonBytes(
  value: CanonicalJsonValue,
  fieldPath = "canonical"
): Uint8Array {
  return encodeUtf8Bytes(canonicalizeJson(value, fieldPath), fieldPath);
}

export function hashCanonicalJson(
  value: CanonicalJsonValue,
  fieldPath = "canonical"
): { readonly canonical_json: string; readonly bytes: Uint8Array; readonly sha256: Sha256Hex } {
  const canonicalJson = canonicalizeJson(value, fieldPath);
  const bytes = encodeUtf8Bytes(canonicalJson, fieldPath);
  return Object.freeze({
    canonical_json: canonicalJson,
    bytes,
    sha256: sha256Hex(bytes)
  });
}

export interface CommandOptionPresence {
  readonly producer_event_time: boolean;
  readonly deadline_at: boolean;
}

export interface EventAdmissionCommandScope {
  readonly tenant_id: TenantId;
  readonly project_id: ProjectId;
  readonly publication_channel_id: ProducerId;
  readonly channel_kind: ChannelKind;
  readonly actor_principal_id: PrincipalId;
  readonly producer_namespace: ProducerNamespace;
}

export interface EventAdmissionCommandSubmission {
  readonly business_key: BusinessKey;
  readonly event_type_id: EventTypeId;
  readonly event_schema_version: number;
  readonly content_sha256: Sha256Hex;
  readonly byte_count: number;
  readonly producer_event_time?: CanonicalUtcTimestamp | undefined;
  readonly deadline_at?: CanonicalUtcTimestamp | undefined;
}

export interface CanonicalEventAdmissionCommand {
  readonly hash_schema: typeof COMMAND_HASH_SCHEMA_V1;
  readonly action: "events.admit";
  readonly scope: EventAdmissionCommandScope;
  readonly submission: EventAdmissionCommandSubmission;
  readonly option_presence: CommandOptionPresence;
}

export interface EventAdmissionCommandInput {
  readonly scope: {
    readonly tenant_id: TenantId | string;
    readonly project_id: ProjectId | string;
    readonly publication_channel_id: ProducerId | string;
    readonly channel_kind: ChannelKind;
    readonly actor_principal_id: PrincipalId | string;
    readonly producer_namespace: ProducerNamespace | string;
  };
  readonly submission: {
    readonly business_key: BusinessKey | string;
    readonly event_type_id: EventTypeId | string;
    readonly event_schema_version: number;
    readonly content_sha256: Sha256Hex | string;
    readonly byte_count: number;
    readonly producer_event_time?: CanonicalUtcTimestamp | string | undefined;
    readonly deadline_at?: CanonicalUtcTimestamp | string | undefined;
  };
}

export interface CanonicalFingerprintResult<T> {
  readonly hash_schema: string;
  readonly canonical_object: T;
  readonly canonical_json: string;
  readonly bytes: Uint8Array;
  readonly sha256: Sha256Hex;
}

export function buildEventAdmissionCommandObject(
  input: EventAdmissionCommandInput
): CanonicalEventAdmissionCommand {
  if (!isChannelKind(input.scope.channel_kind)) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Invalid channel_kind "${String(input.scope.channel_kind)}"`,
      fieldErrors: [{ path: "scope.channel_kind", code: "INVALID_VALUE" }]
    });
  }

  const tenantId = parseTenantId(input.scope.tenant_id, "scope.tenant_id");
  const projectId = parseProjectId(input.scope.project_id, "scope.project_id");
  const publicationChannelId = parseProducerId(
    input.scope.publication_channel_id,
    "scope.publication_channel_id"
  );
  const actorPrincipalId = parsePrincipalId(
    input.scope.actor_principal_id,
    "scope.actor_principal_id"
  );
  const producerNamespace = parseProducerNamespace(
    input.scope.producer_namespace,
    "scope.producer_namespace"
  );
  assertProducerChannelBinding(
    input.scope.channel_kind,
    input.scope.channel_kind === "machine_producer" ? "producer" : "human",
    producerNamespace
  );

  const subRecord = input.submission as Record<string, unknown>;
  if (
    Object.prototype.hasOwnProperty.call(subRecord, "producer_event_time") &&
    subRecord.producer_event_time === null
  ) {
    throw new ValidationDomainError({
      code: "INVALID_TIMESTAMP",
      message: "submission.producer_event_time cannot be explicitly null; omit when absent",
      fieldErrors: [{ path: "submission.producer_event_time", code: "INVALID_TIMESTAMP" }]
    });
  }
  if (
    Object.prototype.hasOwnProperty.call(subRecord, "deadline_at") &&
    subRecord.deadline_at === null
  ) {
    throw new ValidationDomainError({
      code: "INVALID_TIMESTAMP",
      message: "submission.deadline_at cannot be explicitly null; omit when absent",
      fieldErrors: [{ path: "submission.deadline_at", code: "INVALID_TIMESTAMP" }]
    });
  }

  const producerEventTime =
    input.submission.producer_event_time !== undefined
      ? parseCanonicalUtcTimestamp(
          input.submission.producer_event_time,
          "submission.producer_event_time"
        )
      : undefined;
  const deadlineAt =
    input.submission.deadline_at !== undefined
      ? parseCanonicalUtcTimestamp(input.submission.deadline_at, "submission.deadline_at")
      : undefined;

  const submission: EventAdmissionCommandSubmission = Object.freeze({
    business_key: parseBusinessKey(input.submission.business_key, "submission.business_key"),
    event_type_id: parseEventTypeId(input.submission.event_type_id, "submission.event_type_id"),
    event_schema_version: parsePositiveInt32(
      input.submission.event_schema_version,
      "submission.event_schema_version"
    ),
    content_sha256: parseSha256Hex(
      input.submission.content_sha256,
      "submission.content_sha256"
    ),
    byte_count: parseBoundedInteger(input.submission.byte_count, {
      fieldPath: "submission.byte_count",
      min: 1,
      max: EVENT_MAX_CONTENT_BYTES
    }),
    ...(producerEventTime !== undefined ? { producer_event_time: producerEventTime } : {}),
    ...(deadlineAt !== undefined ? { deadline_at: deadlineAt } : {})
  });

  return Object.freeze({
    hash_schema: COMMAND_HASH_SCHEMA_V1,
    action: "events.admit",
    scope: Object.freeze({
      tenant_id: tenantId,
      project_id: projectId,
      publication_channel_id: publicationChannelId,
      channel_kind: input.scope.channel_kind,
      actor_principal_id: actorPrincipalId,
      producer_namespace: producerNamespace
    }),
    submission,
    option_presence: Object.freeze({
      producer_event_time: producerEventTime !== undefined,
      deadline_at: deadlineAt !== undefined
    })
  });
}

function toCanonicalJsonCommandObject(cmd: CanonicalEventAdmissionCommand): CanonicalJsonValue {
  const submissionObj: Record<string, CanonicalJsonValue> = {
    business_key: cmd.submission.business_key,
    event_type_id: cmd.submission.event_type_id,
    event_schema_version: cmd.submission.event_schema_version,
    content_sha256: cmd.submission.content_sha256,
    byte_count: cmd.submission.byte_count
  };
  if (cmd.submission.producer_event_time !== undefined) {
    submissionObj.producer_event_time = cmd.submission.producer_event_time;
  }
  if (cmd.submission.deadline_at !== undefined) {
    submissionObj.deadline_at = cmd.submission.deadline_at;
  }

  return {
    hash_schema: cmd.hash_schema,
    action: cmd.action,
    scope: {
      tenant_id: cmd.scope.tenant_id,
      project_id: cmd.scope.project_id,
      publication_channel_id: cmd.scope.publication_channel_id,
      channel_kind: cmd.scope.channel_kind,
      actor_principal_id: cmd.scope.actor_principal_id,
      producer_namespace: cmd.scope.producer_namespace
    },
    submission: submissionObj,
    option_presence: {
      producer_event_time: cmd.option_presence.producer_event_time,
      deadline_at: cmd.option_presence.deadline_at
    }
  };
}

export function computeEventAdmissionCommandFingerprint(
  input: EventAdmissionCommandInput
): CanonicalFingerprintResult<CanonicalEventAdmissionCommand> {
  const canonicalObject = buildEventAdmissionCommandObject(input);
  const hashed = hashCanonicalJson(
    toCanonicalJsonCommandObject(canonicalObject),
    COMMAND_HASH_SCHEMA_V1
  );
  return Object.freeze({
    hash_schema: COMMAND_HASH_SCHEMA_V1,
    canonical_object: canonicalObject,
    canonical_json: hashed.canonical_json,
    bytes: hashed.bytes,
    sha256: hashed.sha256
  });
}

export interface CanonicalEffectiveAdmission {
  readonly hash_schema: typeof EFFECTIVE_HASH_SCHEMA_V1;
  readonly action: "events.admit";
  readonly submitted_shape_sha256: Sha256Hex;
  readonly accepted_defaults: {
    readonly admitted_at: CanonicalUtcTimestamp;
    readonly delivery_deadline_at: CanonicalUtcTimestamp;
    readonly delivery_window_ms: PositiveInt64String;
    readonly producer_event_time: CanonicalUtcTimestamp | null;
    readonly option_presence: CommandOptionPresence;
  };
  readonly policy_references: {
    readonly hash_schema_version: typeof CANONICAL_HASH_SCHEMA_VERSION;
    readonly topology_version: PositiveInt64String;
    readonly admission_policy_version: string;
    readonly retention_policy_version: string;
  };
}

export interface EffectiveAdmissionInput {
  readonly submitted_shape_sha256: Sha256Hex | string;
  readonly admitted_at: CanonicalUtcTimestamp | string;
  readonly delivery_deadline_at: CanonicalUtcTimestamp | string;
  readonly delivery_window_ms: PositiveInt64String | bigint;
  readonly producer_event_time: CanonicalUtcTimestamp | string | null;
  readonly option_presence: CommandOptionPresence;
  readonly topology_version: PositiveInt64String | bigint;
  readonly admission_policy_version?: string | undefined;
  readonly retention_policy_version?: string | undefined;
}

export function buildEffectiveAdmissionObject(
  input: EffectiveAdmissionInput
): CanonicalEffectiveAdmission {
  const deliveryWindowStr =
    typeof input.delivery_window_ms === "bigint"
      ? parsePositiveInt64String(
          formatInt64(input.delivery_window_ms, "accepted_defaults.delivery_window_ms"),
          "accepted_defaults.delivery_window_ms"
        )
      : parsePositiveInt64String(
          input.delivery_window_ms,
          "accepted_defaults.delivery_window_ms"
        );
  const topologyVersionStr =
    typeof input.topology_version === "bigint"
      ? parsePositiveInt64String(
          formatInt64(input.topology_version, "policy_references.topology_version"),
          "policy_references.topology_version"
        )
      : parsePositiveInt64String(
          input.topology_version,
          "policy_references.topology_version"
        );

  const producerEventTime = parseNullableUtcTimestamp(
    input.producer_event_time,
    "accepted_defaults.producer_event_time"
  );
  if (input.option_presence.producer_event_time && producerEventTime === null) {
    throw new ValidationDomainError({
      code: "INVALID_TIMESTAMP",
      message: "option_presence.producer_event_time=true requires non-null producer_event_time",
      fieldErrors: [{ path: "accepted_defaults.producer_event_time", code: "INVALID_TIMESTAMP" }]
    });
  }
  if (!input.option_presence.producer_event_time && producerEventTime !== null) {
    throw new ValidationDomainError({
      code: "INVALID_TIMESTAMP",
      message: "option_presence.producer_event_time=false requires producer_event_time=null",
      fieldErrors: [{ path: "accepted_defaults.producer_event_time", code: "INVALID_TIMESTAMP" }]
    });
  }

  return Object.freeze({
    hash_schema: EFFECTIVE_HASH_SCHEMA_V1,
    action: "events.admit",
    submitted_shape_sha256: parseSha256Hex(
      input.submitted_shape_sha256,
      "submitted_shape_sha256"
    ),
    accepted_defaults: Object.freeze({
      admitted_at: parseCanonicalUtcTimestamp(input.admitted_at, "accepted_defaults.admitted_at"),
      delivery_deadline_at: parseCanonicalUtcTimestamp(
        input.delivery_deadline_at,
        "accepted_defaults.delivery_deadline_at"
      ),
      delivery_window_ms: deliveryWindowStr,
      producer_event_time: producerEventTime,
      option_presence: Object.freeze({
        producer_event_time: Boolean(input.option_presence.producer_event_time),
        deadline_at: Boolean(input.option_presence.deadline_at)
      })
    }),
    policy_references: Object.freeze({
      hash_schema_version: CANONICAL_HASH_SCHEMA_VERSION,
      topology_version: topologyVersionStr,
      admission_policy_version: parseSafeReasonCode(
        input.admission_policy_version ?? "admission_v1",
        "policy_references.admission_policy_version"
      ),
      retention_policy_version: parseSafeReasonCode(
        input.retention_policy_version ?? "retention_v1",
        "policy_references.retention_policy_version"
      )
    })
  });
}

export function computeEffectiveAdmissionFingerprint(
  input: EffectiveAdmissionInput
): CanonicalFingerprintResult<CanonicalEffectiveAdmission> {
  const canonicalObject = buildEffectiveAdmissionObject(input);
  const hashed = hashCanonicalJson(
    canonicalObject as unknown as CanonicalJsonValue,
    EFFECTIVE_HASH_SCHEMA_V1
  );
  return Object.freeze({
    hash_schema: EFFECTIVE_HASH_SCHEMA_V1,
    canonical_object: canonicalObject,
    canonical_json: hashed.canonical_json,
    bytes: hashed.bytes,
    sha256: hashed.sha256
  });
}

export interface OriginalSemanticFacts {
  readonly project_id: ProjectId;
  readonly event_id: EventId;
  readonly project_event_sequence: PositiveInt64String;
  readonly event_type_id: EventTypeId;
  readonly event_type: EventTypeName;
  readonly event_schema_version: number;
  readonly admitted_at: CanonicalUtcTimestamp;
  readonly producer_event_time: CanonicalUtcTimestamp | null;
  readonly original_content_sha256: Sha256Hex;
}

export interface OriginalSemanticFactsInput {
  readonly project_id: ProjectId | string;
  readonly event_id: EventId | string;
  readonly project_event_sequence: PositiveInt64String | bigint;
  readonly event_type_id: EventTypeId | string;
  readonly event_type: EventTypeName | string;
  readonly event_schema_version: number;
  readonly admitted_at: CanonicalUtcTimestamp | string;
  readonly producer_event_time: CanonicalUtcTimestamp | string | null;
  readonly original_content_sha256: Sha256Hex | string;
}

export function buildOriginalSemanticFactsObject(
  input: OriginalSemanticFactsInput
): OriginalSemanticFacts {
  const seqStr =
    typeof input.project_event_sequence === "bigint"
      ? parsePositiveInt64String(
          formatInt64(input.project_event_sequence, "project_event_sequence"),
          "project_event_sequence"
        )
      : parsePositiveInt64String(input.project_event_sequence, "project_event_sequence");

  return Object.freeze({
    project_id: parseProjectId(input.project_id, "project_id"),
    event_id: parseEventId(input.event_id, "event_id"),
    project_event_sequence: seqStr,
    event_type_id: parseEventTypeId(input.event_type_id, "event_type_id"),
    event_type: parseEventTypeName(input.event_type, "event_type"),
    event_schema_version: parsePositiveInt32(
      input.event_schema_version,
      "event_schema_version"
    ),
    admitted_at: parseCanonicalUtcTimestamp(input.admitted_at, "admitted_at"),
    producer_event_time: parseNullableUtcTimestamp(
      input.producer_event_time,
      "producer_event_time"
    ),
    original_content_sha256: parseSha256Hex(
      input.original_content_sha256,
      "original_content_sha256"
    )
  });
}

export function computeOriginalFactsSha256(
  input: OriginalSemanticFactsInput
): Sha256Hex {
  const facts = buildOriginalSemanticFactsObject(input);
  return hashCanonicalJson(facts as unknown as CanonicalJsonValue, "original_facts").sha256;
}

export function computeBusinessKeySha256(businessKey: BusinessKey | string): Sha256Hex {
  const validated = parseBusinessKey(businessKey, "business_key");
  const domainBytes = encodeUtf8Bytes("rq.business-key.v1", "domain");
  const keyBytes = encodeUtf8Bytes(validated, "business_key");
  const preimage = new Uint8Array(domainBytes.length + 1 + keyBytes.length);
  preimage.set(domainBytes, 0);
  preimage[domainBytes.length] = 0x00;
  preimage.set(keyBytes, domainBytes.length + 1);
  return sha256Hex(preimage);
}

export function computeRequestKeySha256(idempotencyKey: IdempotencyKey | string): Sha256Hex {
  const validated = parseIdempotencyKey(idempotencyKey, "idempotency_key");
  const domainBytes = encodeUtf8Bytes("rq.request-key.v1", "domain");
  const keyBytes = encodeUtf8Bytes(validated, "idempotency_key");
  const preimage = new Uint8Array(domainBytes.length + 1 + keyBytes.length);
  preimage.set(domainBytes, 0);
  preimage[domainBytes.length] = 0x00;
  preimage.set(keyBytes, domainBytes.length + 1);
  return sha256Hex(preimage);
}

export interface CommandGuardKeyInput {
  readonly scope_kind: CommandReceiptScopeKind;
  readonly tenant_id: TenantId | string | null;
  readonly project_id: ProjectId | string | null;
  readonly actor_principal_id: PrincipalId | string;
  readonly command_family: string;
  readonly key_sha256: Sha256Hex | string;
}

export interface CommandGuardKeyResult {
  readonly digest_sha256: Sha256Hex;
  readonly advisory_lock_key: bigint;
}

export function computeCommandGuardKey(input: CommandGuardKeyInput): CommandGuardKeyResult {
  if (!isCommandReceiptScopeKind(input.scope_kind)) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Invalid scope_kind "${String(input.scope_kind)}"`,
      fieldErrors: [{ path: "scope_kind", code: "INVALID_VALUE" }]
    });
  }

  let tenantStr = "";
  let projectStr = "";
  if (input.scope_kind === "installation") {
    if (input.tenant_id !== null || input.project_id !== null) {
      throw new ValidationDomainError({
        code: "INVALID_VALUE",
        message: "installation command guard requires tenant_id=null and project_id=null",
        fieldErrors: [{ path: "scope_kind", code: "INVALID_VALUE" }]
      });
    }
  } else if (input.scope_kind === "tenant") {
    if (input.tenant_id === null || input.project_id !== null) {
      throw new ValidationDomainError({
        code: "INVALID_VALUE",
        message: "tenant command guard requires tenant_id non-null and project_id=null",
        fieldErrors: [{ path: "tenant_id", code: "INVALID_VALUE" }]
      });
    }
    tenantStr = parseTenantId(input.tenant_id, "tenant_id");
  } else {
    if (input.tenant_id === null || input.project_id === null) {
      throw new ValidationDomainError({
        code: "INVALID_VALUE",
        message: "project command guard requires both tenant_id and project_id",
        fieldErrors: [{ path: "project_id", code: "INVALID_VALUE" }]
      });
    }
    tenantStr = parseTenantId(input.tenant_id, "tenant_id");
    projectStr = parseProjectId(input.project_id, "project_id");
  }

  const actorId = parsePrincipalId(input.actor_principal_id, "actor_principal_id");
  const commandFamily = parseSafeReasonCode(input.command_family, "command_family");
  const keyDigestHex = parseSha256Hex(input.key_sha256, "key_sha256");
  const keyDigestBytes = sha256HexToBytes(keyDigestHex);

  const preimage = encodeDomainLengthPrefixed("rq.command-guard.v1", [
    input.scope_kind,
    tenantStr,
    projectStr,
    actorId,
    commandFamily,
    keyDigestBytes
  ]);
  const digest = sha256Digest(preimage);
  const view = new DataView(digest.buffer, digest.byteOffset, 8);
  return Object.freeze({
    digest_sha256: sha256Hex(preimage),
    advisory_lock_key: view.getBigInt64(0, false)
  });
}

export function computeConsumerEventKeySha256(input: {
  readonly project_id: ProjectId | string;
  readonly event_id: EventId | string;
  readonly consumer_contract_scope: string;
}): Sha256Hex {
  const projectId = parseProjectId(input.project_id, "project_id");
  const eventId = parseEventId(input.event_id, "event_id");
  if (
    typeof input.consumer_contract_scope !== "string" ||
    input.consumer_contract_scope.length === 0 ||
    hasLoneSurrogate(input.consumer_contract_scope)
  ) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: "consumer_contract_scope must be a non-empty valid UTF-8 string",
      fieldErrors: [{ path: "consumer_contract_scope", code: "INVALID_VALUE" }]
    });
  }
  const scopeBytes = encodeUtf8Bytes(input.consumer_contract_scope, "consumer_contract_scope");
  if (scopeBytes.length > 128) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: "consumer_contract_scope exceeds 128 UTF-8 bytes",
      fieldErrors: [{ path: "consumer_contract_scope", code: "INVALID_VALUE" }]
    });
  }

  const preimage = encodeDomainLengthPrefixed("rq.consumer-event.v1", [
    projectId,
    eventId,
    scopeBytes
  ]);
  return sha256Hex(preimage);
}

export function computeOrderingKeySha256(input: {
  readonly ordering_domain_id: OrderingDomainId | string;
  readonly subscription_id: SubscriptionId | string;
  readonly consumer_contract_scope: string;
  readonly ordering_key: string;
}): Sha256Hex {
  const orderingDomainId = parseOrderingDomainId(
    input.ordering_domain_id,
    "ordering_domain_id"
  );
  const subscriptionId = parseSubscriptionId(input.subscription_id, "subscription_id");
  if (
    typeof input.consumer_contract_scope !== "string" ||
    input.consumer_contract_scope.length === 0 ||
    hasLoneSurrogate(input.consumer_contract_scope)
  ) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: "consumer_contract_scope must be a non-empty valid UTF-8 string",
      fieldErrors: [{ path: "consumer_contract_scope", code: "INVALID_VALUE" }]
    });
  }
  const scopeBytes = encodeUtf8Bytes(input.consumer_contract_scope, "consumer_contract_scope");
  if (scopeBytes.length > 128) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: "consumer_contract_scope exceeds 128 UTF-8 bytes",
      fieldErrors: [{ path: "consumer_contract_scope", code: "INVALID_VALUE" }]
    });
  }
  if (
    typeof input.ordering_key !== "string" ||
    input.ordering_key.length === 0 ||
    hasLoneSurrogate(input.ordering_key)
  ) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: "ordering_key must be a non-empty valid UTF-8 string",
      fieldErrors: [{ path: "ordering_key", code: "INVALID_VALUE" }]
    });
  }
  const keyBytes = encodeUtf8Bytes(input.ordering_key, "ordering_key");
  if (keyBytes.length < 1 || keyBytes.length > ORDERING_KEY_MAX_UTF8_BYTES) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `ordering_key exceeds ${ORDERING_KEY_MAX_UTF8_BYTES} UTF-8 bytes`,
      fieldErrors: [{ path: "ordering_key", code: "INVALID_VALUE" }]
    });
  }

  const preimage = encodeDomainLengthPrefixed("rq.order-key.v1", [
    orderingDomainId,
    subscriptionId,
    scopeBytes,
    keyBytes
  ]);
  return sha256Hex(preimage);
}
