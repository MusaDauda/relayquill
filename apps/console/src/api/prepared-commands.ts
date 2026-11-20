import {
  type Base64String,
  type BusinessKey,
  type CanonicalUtcTimestamp,
  type EventTypeId,
  type IdempotencyKey,
  type PrincipalId,
  type ProducerId,
  type ProducerNamespace,
  type ProjectId,
  type Sha256Hex,
  type TenantId,
  computeEventAdmissionCommandFingerprint,
  encodeBase64,
  encodeUtf8Bytes,
  parseBusinessKey,
  parseCanonicalUtcTimestamp,
  parseEventTypeId,
  parseIdempotencyKey,
  parsePositiveInt32,
  parsePrincipalId,
  parseProducerId,
  parseProducerNamespace,
  parseProjectId,
  parseTenantId,
  sha256Hex
} from "@relayquill/contracts";
import { type ChannelKind, EVENT_MAX_CONTENT_BYTES, ValidationDomainError } from "@relayquill/domain";

export interface PrepareEventCommandInput {
  readonly scope: {
    readonly tenantId: TenantId | string;
    readonly projectId: ProjectId | string;
    readonly publicationChannelId: ProducerId | string;
    readonly channelKind: ChannelKind;
    readonly actorPrincipalId: PrincipalId | string;
    readonly namespace: ProducerNamespace | string;
  };
  readonly eventTypeId: EventTypeId | string;
  readonly eventSchemaVersion: number;
  readonly businessKey: string;
  readonly idempotencyKey: string;
  readonly rawJsonText: string;
  readonly producerEventTime?: string | undefined;
  readonly deadlineAt?: string | undefined;
}

export interface PreparedEventCommand {
  readonly scopeKey: string;
  readonly tenantId: TenantId;
  readonly projectId: ProjectId;
  readonly actorPrincipalId: PrincipalId;
  readonly publicationChannelId: ProducerId;
  readonly channelKind: ChannelKind;
  readonly namespace: ProducerNamespace;
  readonly eventTypeId: EventTypeId;
  readonly eventSchemaVersion: number;
  readonly businessKey: BusinessKey;
  readonly idempotencyKey: IdempotencyKey;
  readonly contentSha256: Sha256Hex;
  readonly contentByteCount: number;
  readonly contentBase64: Base64String;
  readonly submittedShapeSha256: Sha256Hex;
  readonly producerEventTimePresent: boolean;
  readonly deadlineAtPresent: boolean;
  readonly producerEventTime?: CanonicalUtcTimestamp | undefined;
  readonly deadlineAt?: CanonicalUtcTimestamp | undefined;
  readonly frozenBodyJson: string;
  readonly createdAtMs: number;
  readonly status: "prepared" | "acceptance_unknown" | "accepted" | "rejected";
  readonly lastErrorCode?: string | undefined;
  readonly lastErrorMessage?: string | undefined;
  readonly acceptedEventId?: string | undefined;
  getRawBytesCopy(): Uint8Array;
}

export function buildScopePartitionKey(
  principalId: string,
  tenantId: string,
  projectId: string
): string {
  return `${principalId}:${tenantId}:${projectId}`;
}

export function prepareEventAdmissionCommand(input: PrepareEventCommandInput): PreparedEventCommand {
  const tenantId = parseTenantId(input.scope.tenantId, "scope.tenant_id");
  const projectId = parseProjectId(input.scope.projectId, "scope.project_id");
  const publicationChannelId = parseProducerId(
    input.scope.publicationChannelId,
    "scope.publication_channel_id"
  );
  const actorPrincipalId = parsePrincipalId(
    input.scope.actorPrincipalId,
    "scope.actor_principal_id"
  );
  const namespace = parseProducerNamespace(input.scope.namespace, "scope.namespace");
  const eventTypeId = parseEventTypeId(input.eventTypeId, "event_type_id");
  const eventSchemaVersion = parsePositiveInt32(input.eventSchemaVersion, "event_schema_version");
  const businessKey = parseBusinessKey(input.businessKey, "business_key");
  const idempotencyKey = parseIdempotencyKey(input.idempotencyKey, "idempotency_key");

  const utf8Bytes = encodeUtf8Bytes(input.rawJsonText, "content");
  if (utf8Bytes.length < 1 || utf8Bytes.length > EVENT_MAX_CONTENT_BYTES) {
    throw new ValidationDomainError({
      code: utf8Bytes.length > EVENT_MAX_CONTENT_BYTES ? "PAYLOAD_TOO_LARGE" : "INVALID_VALUE",
      message: `Decoded event content byte count (${utf8Bytes.length}) must be within [1, ${EVENT_MAX_CONTENT_BYTES}]`,
      fieldErrors: [{ path: "content", code: "INVALID_VALUE" }]
    });
  }
  const ownedBytes = new Uint8Array(utf8Bytes.length);
  ownedBytes.set(utf8Bytes);

  const contentSha256 = sha256Hex(ownedBytes);
  const contentBase64 = encodeBase64(ownedBytes);

  const producerEventTime =
    input.producerEventTime !== undefined && input.producerEventTime.trim().length > 0
      ? parseCanonicalUtcTimestamp(input.producerEventTime.trim(), "producer_event_time")
      : undefined;
  const deadlineAt =
    input.deadlineAt !== undefined && input.deadlineAt.trim().length > 0
      ? parseCanonicalUtcTimestamp(input.deadlineAt.trim(), "deadline_at")
      : undefined;

  const fingerprint = computeEventAdmissionCommandFingerprint({
    scope: {
      tenant_id: tenantId,
      project_id: projectId,
      publication_channel_id: publicationChannelId,
      channel_kind: input.scope.channelKind,
      actor_principal_id: actorPrincipalId,
      producer_namespace: namespace
    },
    submission: {
      business_key: businessKey,
      event_type_id: eventTypeId,
      event_schema_version: eventSchemaVersion,
      content_sha256: contentSha256,
      byte_count: ownedBytes.length,
      ...(producerEventTime !== undefined ? { producer_event_time: producerEventTime } : {}),
      ...(deadlineAt !== undefined ? { deadline_at: deadlineAt } : {})
    }
  });

  const wireBody: Record<string, unknown> = {
    schema_version: 1,
    expected_publication_channel_id: publicationChannelId,
    event_type_id: eventTypeId,
    event_schema_version: eventSchemaVersion,
    business_key: businessKey,
    content: {
      media_type: "application/json",
      encoding: "base64",
      data: contentBase64,
      sha256: contentSha256
    }
  };
  if (producerEventTime !== undefined) {
    wireBody.producer_event_time = producerEventTime;
  }
  if (deadlineAt !== undefined) {
    wireBody.deadline_at = deadlineAt;
  }

  const frozenBodyJson = JSON.stringify(wireBody);
  const scopeKey = buildScopePartitionKey(actorPrincipalId, tenantId, projectId);

  return Object.freeze({
    scopeKey,
    tenantId,
    projectId,
    actorPrincipalId,
    publicationChannelId,
    channelKind: input.scope.channelKind,
    namespace,
    eventTypeId,
    eventSchemaVersion,
    businessKey,
    idempotencyKey,
    contentSha256,
    contentByteCount: ownedBytes.length,
    contentBase64,
    submittedShapeSha256: fingerprint.sha256,
    producerEventTimePresent: producerEventTime !== undefined,
    deadlineAtPresent: deadlineAt !== undefined,
    ...(producerEventTime !== undefined ? { producerEventTime } : {}),
    ...(deadlineAt !== undefined ? { deadlineAt } : {}),
    frozenBodyJson,
    createdAtMs: Date.now(),
    status: "prepared",
    getRawBytesCopy(): Uint8Array {
      return new Uint8Array(ownedBytes);
    }
  });
}

export class PreparedCommandMemoryStore {
  readonly #commands = new Map<string, PreparedEventCommand>();

  #storageKey(cmd: Pick<PreparedEventCommand, "scopeKey" | "idempotencyKey">): string {
    return `${cmd.scopeKey}::${cmd.idempotencyKey}`;
  }

  save(cmd: PreparedEventCommand): PreparedEventCommand {
    this.#commands.set(this.#storageKey(cmd), cmd);
    return cmd;
  }

  updateStatus(
    scopeKey: string,
    idempotencyKey: string,
    update: {
      readonly status: PreparedEventCommand["status"];
      readonly lastErrorCode?: string | undefined;
      readonly lastErrorMessage?: string | undefined;
      readonly acceptedEventId?: string | undefined;
    }
  ): PreparedEventCommand | undefined {
    const key = `${scopeKey}::${idempotencyKey}`;
    const existing = this.#commands.get(key);
    if (existing === undefined) {
      return undefined;
    }
    const next: PreparedEventCommand = Object.freeze({
      ...existing,
      status: update.status,
      ...(update.lastErrorCode !== undefined ? { lastErrorCode: update.lastErrorCode } : {}),
      ...(update.lastErrorMessage !== undefined ? { lastErrorMessage: update.lastErrorMessage } : {}),
      ...(update.acceptedEventId !== undefined ? { acceptedEventId: update.acceptedEventId } : {})
    });
    this.#commands.set(key, next);
    return next;
  }

  listForScope(scopeKey: string): readonly PreparedEventCommand[] {
    const out: PreparedEventCommand[] = [];
    for (const cmd of this.#commands.values()) {
      if (cmd.scopeKey === scopeKey) {
        out.push(cmd);
      }
    }
    return out.toSorted((a, b) => b.createdAtMs - a.createdAtMs);
  }

  remove(scopeKey: string, idempotencyKey: string): void {
    this.#commands.delete(`${scopeKey}::${idempotencyKey}`);
  }

  clearForPrincipal(principalId: string): void {
    for (const [key, cmd] of this.#commands.entries()) {
      if (cmd.actorPrincipalId === principalId) {
        this.#commands.delete(key);
      }
    }
  }

  clearAll(): void {
    this.#commands.clear();
  }
}
