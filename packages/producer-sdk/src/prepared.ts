import {
  type AdmitEventRequestDto,
  type Base64String,
  type BusinessKey,
  COMMAND_HASH_SCHEMA_V1,
  type CanonicalEventAdmissionCommand,
  type CanonicalJsonValue,
  type CanonicalUtcTimestamp,
  type CommandOptionPresence,
  EVENT_CONTENT_ENCODING,
  EVENT_CONTENT_MEDIA_TYPE,
  type EventTypeId,
  type IdempotencyKey,
  type PrincipalId,
  type ProducerId,
  type ProducerNamespace,
  type ProjectId,
  type PublicationContextDto,
  type Sha256Hex,
  type TenantId,
  buildEventAdmissionCommandObject,
  canonicalizeJson,
  encodeBase64,
  parseBusinessKey,
  parseCanonicalUtcTimestamp,
  parseEventTypeId,
  parseIdempotencyKey,
  parsePositiveInt32,
  parseProducerId
} from "@relayquill/contracts";
import { type ChannelKind, DomainError } from "@relayquill/domain";
import { ProducerValidationError } from "./errors.js";
import {
  type LosslessJsonInput,
  type WebCryptoLike,
  copyUint8Array,
  encodeEventContentBytes,
  generateIdempotencyKey,
  sha256HexWebCrypto,
  utf8EncodeText
} from "./values.js";

export const PRODUCER_PREPARE_SCHEMA_V1 = "relayquill.producer-prepare.v1" as const;

export interface PrepareEventScopeInput {
  readonly tenantId: TenantId | string;
  readonly projectId: ProjectId | string;
  readonly actorPrincipalId: PrincipalId | string;
  readonly channelKind?: ChannelKind | undefined;
  readonly producerNamespace?: ProducerNamespace | string | undefined;
}

export interface PrepareEventInput {
  readonly expectedPublicationChannelId?: ProducerId | string | undefined;
  readonly publicationContext?: PublicationContextDto | undefined;
  readonly eventTypeId: EventTypeId | string;
  readonly eventSchemaVersion: number;
  readonly businessKey: BusinessKey | string;
  readonly content: Uint8Array | string | LosslessJsonInput;
  readonly idempotencyKey?: IdempotencyKey | string | undefined;
  readonly producerEventTime?: CanonicalUtcTimestamp | string | undefined;
  readonly deadlineAt?: CanonicalUtcTimestamp | string | undefined;
  readonly scope?: PrepareEventScopeInput | undefined;
  readonly enforceContextAllowedEvents?: boolean | undefined;
  readonly crypto?: WebCryptoLike | undefined;
}

export interface SafePreparedEventMetadata {
  readonly schema_version: 1;
  readonly hash_schema: typeof COMMAND_HASH_SCHEMA_V1 | typeof PRODUCER_PREPARE_SCHEMA_V1;
  readonly action: "events.admit";
  readonly expected_publication_channel_id: ProducerId;
  readonly event_type_id: EventTypeId;
  readonly event_schema_version: number;
  readonly business_key: BusinessKey;
  readonly business_event_key: Sha256Hex;
  readonly idempotency_key: IdempotencyKey;
  readonly request_key_sha256: Sha256Hex;
  readonly content_sha256: Sha256Hex;
  readonly byte_count: number;
  readonly option_presence: CommandOptionPresence;
  readonly producer_event_time?: CanonicalUtcTimestamp;
  readonly deadline_at?: CanonicalUtcTimestamp;
  readonly producer_prepare_digest: Sha256Hex;
  readonly submitted_shape_sha256?: Sha256Hex;
}

async function computeDomainPrefixedSha256WebCrypto(
  domain: string,
  valueUtf8: string,
  customCrypto?: WebCryptoLike
): Promise<Sha256Hex> {
  const domainBytes = utf8EncodeText(domain, "domain");
  const valueBytes = utf8EncodeText(valueUtf8, "value");
  const preimage = new Uint8Array(domainBytes.byteLength + 1 + valueBytes.byteLength);
  preimage.set(domainBytes, 0);
  preimage[domainBytes.byteLength] = 0x00;
  preimage.set(valueBytes, domainBytes.byteLength + 1);
  return sha256HexWebCrypto(preimage, customCrypto);
}

export class PreparedEvent {
  readonly schemaVersion = 1 as const;
  readonly hashSchema: typeof COMMAND_HASH_SCHEMA_V1 | typeof PRODUCER_PREPARE_SCHEMA_V1;
  readonly action = "events.admit" as const;
  readonly expectedPublicationChannelId: ProducerId;
  readonly eventTypeId: EventTypeId;
  readonly eventSchemaVersion: number;
  readonly businessKey: BusinessKey;
  readonly businessEventKey: Sha256Hex;
  readonly idempotencyKey: IdempotencyKey;
  readonly requestKeySha256: Sha256Hex;
  readonly contentSha256: Sha256Hex;
  readonly byteCount: number;
  readonly producerEventTime?: CanonicalUtcTimestamp;
  readonly deadlineAt?: CanonicalUtcTimestamp;
  readonly optionPresence: CommandOptionPresence;
  readonly producerPrepareDigest: Sha256Hex;
  readonly submittedShapeSha256?: Sha256Hex;
  readonly canonicalCommandJson: string;
  readonly canonicalCommandObject?: CanonicalEventAdmissionCommand;

  readonly #contentBytes: Uint8Array;
  readonly #contentBase64: Base64String;

  constructor(init: {
    readonly hashSchema: typeof COMMAND_HASH_SCHEMA_V1 | typeof PRODUCER_PREPARE_SCHEMA_V1;
    readonly expectedPublicationChannelId: ProducerId;
    readonly eventTypeId: EventTypeId;
    readonly eventSchemaVersion: number;
    readonly businessKey: BusinessKey;
    readonly businessEventKey: Sha256Hex;
    readonly idempotencyKey: IdempotencyKey;
    readonly requestKeySha256: Sha256Hex;
    readonly contentBytes: Uint8Array;
    readonly contentBase64: Base64String;
    readonly contentSha256: Sha256Hex;
    readonly producerEventTime?: CanonicalUtcTimestamp | undefined;
    readonly deadlineAt?: CanonicalUtcTimestamp | undefined;
    readonly optionPresence: CommandOptionPresence;
    readonly producerPrepareDigest: Sha256Hex;
    readonly submittedShapeSha256?: Sha256Hex | undefined;
    readonly canonicalCommandJson: string;
    readonly canonicalCommandObject?: CanonicalEventAdmissionCommand | undefined;
  }) {
    this.hashSchema = init.hashSchema;
    this.expectedPublicationChannelId = init.expectedPublicationChannelId;
    this.eventTypeId = init.eventTypeId;
    this.eventSchemaVersion = init.eventSchemaVersion;
    this.businessKey = init.businessKey;
    this.businessEventKey = init.businessEventKey;
    this.idempotencyKey = init.idempotencyKey;
    this.requestKeySha256 = init.requestKeySha256;
    this.#contentBytes = copyUint8Array(init.contentBytes);
    this.#contentBase64 = init.contentBase64;
    this.contentSha256 = init.contentSha256;
    this.byteCount = this.#contentBytes.byteLength;
    this.optionPresence = Object.freeze({
      producer_event_time: init.optionPresence.producer_event_time,
      deadline_at: init.optionPresence.deadline_at
    });
    if (init.producerEventTime !== undefined) {
      this.producerEventTime = init.producerEventTime;
    }
    if (init.deadlineAt !== undefined) {
      this.deadlineAt = init.deadlineAt;
    }
    this.producerPrepareDigest = init.producerPrepareDigest;
    if (init.submittedShapeSha256 !== undefined) {
      this.submittedShapeSha256 = init.submittedShapeSha256;
    }
    this.canonicalCommandJson = init.canonicalCommandJson;
    if (init.canonicalCommandObject !== undefined) {
      this.canonicalCommandObject = init.canonicalCommandObject;
    }
    Object.freeze(this);
  }

  get business_key(): BusinessKey {
    return this.businessKey;
  }

  get business_event_key(): Sha256Hex {
    return this.businessEventKey;
  }

  get producer_prepare_digest(): Sha256Hex {
    return this.producerPrepareDigest;
  }

  get submitted_shape_sha256(): Sha256Hex | undefined {
    return this.submittedShapeSha256;
  }

  get content_sha256(): Sha256Hex {
    return this.contentSha256;
  }

  get byte_count(): number {
    return this.byteCount;
  }

  get idempotency_key(): IdempotencyKey {
    return this.idempotencyKey;
  }

  get expected_publication_channel_id(): ProducerId {
    return this.expectedPublicationChannelId;
  }

  get event_type_id(): EventTypeId {
    return this.eventTypeId;
  }

  get event_schema_version(): number {
    return this.eventSchemaVersion;
  }

  /**
   * Returns a defensive copy of the owned raw event content bytes.
   * Mutating the returned Uint8Array never alters the prepared command's internal buffer.
   */
  getContentBytesCopy(): Uint8Array {
    return copyUint8Array(this.#contentBytes);
  }

  toAdmitRequestDto(): AdmitEventRequestDto {
    return Object.freeze({
      schema_version: 1,
      expected_publication_channel_id: this.expectedPublicationChannelId,
      event_type_id: this.eventTypeId,
      event_schema_version: this.eventSchemaVersion,
      business_key: this.businessKey,
      content: Object.freeze({
        media_type: EVENT_CONTENT_MEDIA_TYPE,
        encoding: EVENT_CONTENT_ENCODING,
        data: this.#contentBase64,
        sha256: this.contentSha256
      }),
      ...(this.producerEventTime !== undefined
        ? { producer_event_time: this.producerEventTime }
        : {}),
      ...(this.deadlineAt !== undefined ? { deadline_at: this.deadlineAt } : {})
    });
  }

  toSafeMetadata(): SafePreparedEventMetadata {
    return Object.freeze({
      schema_version: 1,
      hash_schema: this.hashSchema,
      action: "events.admit",
      expected_publication_channel_id: this.expectedPublicationChannelId,
      event_type_id: this.eventTypeId,
      event_schema_version: this.eventSchemaVersion,
      business_key: this.businessKey,
      business_event_key: this.businessEventKey,
      idempotency_key: this.idempotencyKey,
      request_key_sha256: this.requestKeySha256,
      content_sha256: this.contentSha256,
      byte_count: this.byteCount,
      option_presence: this.optionPresence,
      ...(this.producerEventTime !== undefined
        ? { producer_event_time: this.producerEventTime }
        : {}),
      ...(this.deadlineAt !== undefined ? { deadline_at: this.deadlineAt } : {}),
      producer_prepare_digest: this.producerPrepareDigest,
      ...(this.submittedShapeSha256 !== undefined
        ? { submitted_shape_sha256: this.submittedShapeSha256 }
        : {})
    });
  }

  toJSON(): SafePreparedEventMetadata {
    return this.toSafeMetadata();
  }

  toString(): string {
    return `[PreparedEvent business_key=${this.businessKey} sha256=${this.contentSha256} digest=${this.producerPrepareDigest}]`;
  }

  [Symbol.for("nodejs.util.inspect.custom")](): SafePreparedEventMetadata {
    return this.toSafeMetadata();
  }
}

function toCanonicalJsonCommandValue(cmd: CanonicalEventAdmissionCommand): CanonicalJsonValue {
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

export async function prepareEvent(input: PrepareEventInput): Promise<PreparedEvent> {
  if (typeof input !== "object" || input === null) {
    throw new ProducerValidationError({
      message: "prepareEvent requires an input object"
    });
  }

  const rawRec = input as unknown as Record<string, unknown>;
  if (
    Object.prototype.hasOwnProperty.call(rawRec, "producerEventTime") &&
    rawRec.producerEventTime === null
  ) {
    throw new ProducerValidationError({
      code: "INVALID_TIMESTAMP",
      message: "producerEventTime cannot be explicitly null; omit when absent",
      fieldErrors: [{ path: "producerEventTime", code: "INVALID_TIMESTAMP" }]
    });
  }
  if (Object.prototype.hasOwnProperty.call(rawRec, "deadlineAt") && rawRec.deadlineAt === null) {
    throw new ProducerValidationError({
      code: "INVALID_TIMESTAMP",
      message: "deadlineAt cannot be explicitly null; omit when absent",
      fieldErrors: [{ path: "deadlineAt", code: "INVALID_TIMESTAMP" }]
    });
  }

  try {
    const channelRaw =
      input.expectedPublicationChannelId ?? input.publicationContext?.publication_channel_id;
    if (channelRaw === undefined || channelRaw === null) {
      throw new ProducerValidationError({
        message:
          "expectedPublicationChannelId (or an enabled publicationContext with publication_channel_id) is required",
        fieldErrors: [{ path: "expectedPublicationChannelId", code: "INVALID_VALUE" }]
      });
    }
    const expectedPublicationChannelId = parseProducerId(
      channelRaw,
      "expectedPublicationChannelId"
    );

    if (
      input.publicationContext !== undefined &&
      input.publicationContext.publication_channel_id !== null &&
      input.publicationContext.publication_channel_id !== expectedPublicationChannelId
    ) {
      throw new ProducerValidationError({
        code: "PUBLICATION_CONTEXT_CHANGED",
        message: "expectedPublicationChannelId does not match supplied publicationContext",
        fieldErrors: [
          { path: "expectedPublicationChannelId", code: "PUBLICATION_CONTEXT_CHANGED" }
        ]
      });
    }

    const eventTypeId = parseEventTypeId(input.eventTypeId, "eventTypeId");
    const eventSchemaVersion = parsePositiveInt32(input.eventSchemaVersion, "eventSchemaVersion");
    const businessKey = parseBusinessKey(input.businessKey, "businessKey");
    const idempotencyKey =
      input.idempotencyKey !== undefined
        ? parseIdempotencyKey(input.idempotencyKey, "idempotencyKey")
        : generateIdempotencyKey(input.crypto);

    const producerEventTime =
      input.producerEventTime !== undefined
        ? parseCanonicalUtcTimestamp(input.producerEventTime, "producerEventTime")
        : undefined;
    const deadlineAt =
      input.deadlineAt !== undefined
        ? parseCanonicalUtcTimestamp(input.deadlineAt, "deadlineAt")
        : undefined;

    if (input.publicationContext !== undefined && input.enforceContextAllowedEvents !== false) {
      if (!input.publicationContext.channel_enabled) {
        throw new ProducerValidationError({
          code: "FORBIDDEN",
          message: "Publication channel is not enabled in publicationContext"
        });
      }
      if (input.publicationContext.allowed_events.length > 0) {
        const typeEntry = input.publicationContext.allowed_events.find(
          (e) => e.event_type_id === eventTypeId
        );
        if (
          typeEntry === undefined ||
          !typeEntry.allowed_schema_versions.includes(eventSchemaVersion)
        ) {
          throw new ProducerValidationError({
            code: "FORBIDDEN",
            message: `Event type ${eventTypeId}@v${String(eventSchemaVersion)} is not permitted by publicationContext`
          });
        }
      }
    }

    // Copy & validate raw content bytes before hashing
    const ownedContentBytes = encodeEventContentBytes(input.content, "content");
    if (
      input.publicationContext !== undefined &&
      ownedContentBytes.byteLength > input.publicationContext.budgets.max_decoded_content_bytes
    ) {
      throw new ProducerValidationError({
        code: "PAYLOAD_TOO_LARGE",
        httpStatus: 413,
        message: `Decoded content (${ownedContentBytes.byteLength} bytes) exceeds publicationContext budget (${input.publicationContext.budgets.max_decoded_content_bytes} bytes)`
      });
    }

    const contentBase64 = encodeBase64(ownedContentBytes);
    const [contentSha256, businessEventKey, requestKeySha256] = await Promise.all([
      sha256HexWebCrypto(ownedContentBytes, input.crypto),
      computeDomainPrefixedSha256WebCrypto("rq.business-key.v1", businessKey, input.crypto),
      computeDomainPrefixedSha256WebCrypto("rq.request-key.v1", idempotencyKey, input.crypto)
    ]);

    const optionPresence: CommandOptionPresence = Object.freeze({
      producer_event_time: producerEventTime !== undefined,
      deadline_at: deadlineAt !== undefined
    });

    const resolvedChannelKind =
      input.scope?.channelKind ?? input.publicationContext?.channel_kind;
    const resolvedNamespace =
      input.scope?.producerNamespace ?? input.publicationContext?.namespace ?? undefined;

    if (
      input.scope !== undefined &&
      resolvedChannelKind !== undefined &&
      resolvedNamespace !== undefined
    ) {
      const commandObj = buildEventAdmissionCommandObject({
        scope: {
          tenant_id: input.scope.tenantId,
          project_id: input.scope.projectId,
          publication_channel_id: expectedPublicationChannelId,
          channel_kind: resolvedChannelKind,
          actor_principal_id: input.scope.actorPrincipalId,
          producer_namespace: resolvedNamespace
        },
        submission: {
          business_key: businessKey,
          event_type_id: eventTypeId,
          event_schema_version: eventSchemaVersion,
          content_sha256: contentSha256,
          byte_count: ownedContentBytes.byteLength,
          ...(producerEventTime !== undefined ? { producer_event_time: producerEventTime } : {}),
          ...(deadlineAt !== undefined ? { deadline_at: deadlineAt } : {})
        }
      });

      const canonicalCommandJson = canonicalizeJson(
        toCanonicalJsonCommandValue(commandObj),
        COMMAND_HASH_SCHEMA_V1
      );
      const canonicalBytes = utf8EncodeText(canonicalCommandJson, COMMAND_HASH_SCHEMA_V1);
      const submittedShapeSha256 = await sha256HexWebCrypto(canonicalBytes, input.crypto);

      return new PreparedEvent({
        hashSchema: COMMAND_HASH_SCHEMA_V1,
        expectedPublicationChannelId,
        eventTypeId,
        eventSchemaVersion,
        businessKey,
        businessEventKey,
        idempotencyKey,
        requestKeySha256,
        contentBytes: ownedContentBytes,
        contentBase64,
        contentSha256,
        producerEventTime,
        deadlineAt,
        optionPresence,
        producerPrepareDigest: submittedShapeSha256,
        submittedShapeSha256,
        canonicalCommandJson,
        canonicalCommandObject: commandObj
      });
    }

    const submissionObj: Record<string, CanonicalJsonValue> = {
      business_key: businessKey,
      business_event_key: businessEventKey,
      byte_count: ownedContentBytes.byteLength,
      content_sha256: contentSha256,
      event_schema_version: eventSchemaVersion,
      event_type_id: eventTypeId,
      expected_publication_channel_id: expectedPublicationChannelId
    };
    if (producerEventTime !== undefined) {
      submissionObj.producer_event_time = producerEventTime;
    }
    if (deadlineAt !== undefined) {
      submissionObj.deadline_at = deadlineAt;
    }

    const prepareCanonicalValue: CanonicalJsonValue = {
      action: "events.admit",
      hash_schema: PRODUCER_PREPARE_SCHEMA_V1,
      option_presence: {
        deadline_at: optionPresence.deadline_at,
        producer_event_time: optionPresence.producer_event_time
      },
      schema_version: 1,
      submission: submissionObj
    };

    const canonicalCommandJson = canonicalizeJson(
      prepareCanonicalValue,
      PRODUCER_PREPARE_SCHEMA_V1
    );
    const canonicalBytes = utf8EncodeText(canonicalCommandJson, PRODUCER_PREPARE_SCHEMA_V1);
    const producerPrepareDigest = await sha256HexWebCrypto(canonicalBytes, input.crypto);

    return new PreparedEvent({
      hashSchema: PRODUCER_PREPARE_SCHEMA_V1,
      expectedPublicationChannelId,
      eventTypeId,
      eventSchemaVersion,
      businessKey,
      businessEventKey,
      idempotencyKey,
      requestKeySha256,
      contentBytes: ownedContentBytes,
      contentBase64,
      contentSha256,
      producerEventTime,
      deadlineAt,
      optionPresence,
      producerPrepareDigest,
      canonicalCommandJson
    });
  } catch (err) {
    if (err instanceof ProducerValidationError) {
      throw err;
    }
    if (err instanceof DomainError) {
      throw new ProducerValidationError({
        code: err.code,
        message: err.message,
        ...(err.fieldErrors !== undefined ? { fieldErrors: err.fieldErrors } : {})
      });
    }
    throw err;
  }
}
