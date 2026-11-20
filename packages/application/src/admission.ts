import {
  AuthorizationDomainError,
  ConflictDomainError,
  EVENT_MAX_CONTENT_BYTES,
  LimitExceededDomainError,
  NotFoundDomainError,
  ValidationDomainError,
  addMilliseconds,
  compareInstants,
  formatInt64,
  formatUtcTimestamp,
  parseBusinessKey,
  parseCommandReceiptId,
  parseEventId,
  parseEventPayloadId,
  parseEventTypeId,
  parseEventTypeName,
  parseIdempotencyKey,
  parseOutboxId,
  parsePrincipalId,
  parseProducerId,
  parseProjectId,
  parseTenantId,
  parseUtcTimestamp,
  parseWireEnvelopeId,
  type BusinessKey,
  type CanonicalUtcTimestamp,
  type ChannelKind,
  type CommandReceiptId,
  type EventId,
  type EventState,
  type EventTypeId,
  type EventTypeName,
  type IdempotencyKey,
  type OutboxId,
  type PrincipalId,
  type ProducerId,
  type ProducerNamespace,
  type ProjectId,
  type Sha256Hex,
  type TenantId
} from "@relayquill/domain";
import { parsePositiveInt32 } from "@relayquill/contracts";
import {
  EVENT_CONTENT_ENCODING,
  EVENT_CONTENT_MEDIA_TYPE,
  type PositiveInt64String,
  computeBusinessKeySha256,
  computeEffectiveAdmissionFingerprint,
  computeEventAdmissionCommandFingerprint,
  computeOriginalFactsSha256,
  computeRequestKeySha256,
  encodeBase64,
  encodeBrokerNotificationEnvelope,
  encodeUtf8Bytes,
  parseCanonicalUtcTimestamp,
  parsePositiveInt64String,
  serializeWebhookEnvelope,
  sha256Hex
} from "@relayquill/contracts";
import {
  type ProducerCredentialRepository,
  assertHumanWorkflowNamespace,
  authenticateProducerCredential
} from "@relayquill/auth";
import {
  type AdmissionRepositoryPort,
  type ClockPort,
  type IdGeneratorPort,
  type SchemaEvaluatorPort,
  type TelemetryPort,
  type UnitOfWorkPort,
  cryptoIdGeneratorPort,
  noopTelemetryPort,
  systemClockPort
} from "./ports.js";

export const ADMISSION_POLICY_VERSION = "admission_v1" as const;
export const DEFAULT_RETENTION_POLICY_VERSION = "retention_v1" as const;

export type AdmissionActorInput =
  | {
      readonly kind: "producer_credential";
      readonly bearerToken: string;
    }
  | {
      readonly kind: "human_workflow";
      readonly actorPrincipalId: PrincipalId | string;
      readonly publicationChannelId: ProducerId | string;
      readonly producerNamespace: ProducerNamespace | string;
      readonly scopeAuthorized: boolean;
    };

export interface AdmitEventInput {
  readonly tenantId: TenantId | string;
  readonly projectId: ProjectId | string;
  readonly actor: AdmissionActorInput;
  readonly eventTypeId: EventTypeId | string;
  readonly eventTypeName: EventTypeName | string;
  readonly eventSchemaVersion: number;
  readonly businessKey: BusinessKey | string;
  readonly idempotencyKey: IdempotencyKey | string;
  /** Exact lossless UTF-8 JSON bytes (preserved byte-for-byte). */
  readonly contentBytes: Uint8Array | string;
  readonly producerEventTime?: CanonicalUtcTimestamp | string | undefined;
  readonly deadlineAt?: CanonicalUtcTimestamp | string | undefined;
  readonly deliveryWindowMs?: bigint | number | undefined;
  readonly retentionPolicyVersion?: string | undefined;
  readonly traceparent?: string | undefined;
  readonly tracestate?: string | undefined;
}

export interface AdmitEventOutput {
  readonly statusCode: 201 | 200;
  readonly outcome: "accepted" | "idempotent_recovery" | "business_anchor_recovery";
  readonly eventId: EventId;
  readonly receiptId: CommandReceiptId;
  readonly outboxId: OutboxId;
  readonly projectEventSequence: bigint;
  readonly topologyVersion: bigint;
  readonly candidateCount: bigint;
  readonly state: EventState;
  readonly contentSha256: Sha256Hex;
  readonly submittedShapeSha256: Sha256Hex;
  readonly admittedAt: CanonicalUtcTimestamp;
  readonly deliveryDeadlineAt: CanonicalUtcTimestamp;
  readonly appliedDefaults: Readonly<Record<string, unknown>>;
}

export interface ResolvePreparedEventInput {
  readonly tenantId: TenantId | string;
  readonly projectId: ProjectId | string;
  readonly actor: AdmissionActorInput;
  readonly eventTypeId: EventTypeId | string;
  readonly eventSchemaVersion: number;
  readonly businessKey: BusinessKey | string;
  readonly idempotencyKey: IdempotencyKey | string;
  readonly contentBytes: Uint8Array | string;
  readonly producerEventTime?: CanonicalUtcTimestamp | string | undefined;
  readonly deadlineAt?: CanonicalUtcTimestamp | string | undefined;
}

export type ResolvePreparedEventOutput =
  | { readonly found: false }
  | {
      readonly found: true;
      readonly statusCode: 200;
      readonly matchKind: "idempotent_recovery" | "business_anchor_recovery";
      readonly eventId: EventId;
      readonly receiptId: CommandReceiptId;
      readonly outboxId: OutboxId;
      readonly projectEventSequence: bigint;
      readonly topologyVersion: bigint;
      readonly candidateCount: bigint;
      readonly state: EventState;
      readonly admittedAt: CanonicalUtcTimestamp;
      readonly deliveryDeadlineAt: CanonicalUtcTimestamp;
      readonly appliedDefaults: Readonly<Record<string, unknown>>;
    };

export interface AdmissionServiceDeps<TTx> {
  readonly uow: UnitOfWorkPort<TTx>;
  readonly admissionRepo: AdmissionRepositoryPort<TTx>;
  readonly producerCredentialRepo: ProducerCredentialRepository;
  readonly schemaEvaluator: SchemaEvaluatorPort;
  readonly clock?: ClockPort | undefined;
  readonly idGenerator?: IdGeneratorPort | undefined;
  readonly telemetry?: TelemetryPort | undefined;
}

interface ResolvedAdmissionActor {
  readonly channelKind: ChannelKind;
  readonly actorPrincipalId: PrincipalId;
  readonly producerId: ProducerId;
  readonly producerNamespace: ProducerNamespace;
}

function toExactUtf8Bytes(input: Uint8Array | string): Uint8Array {
  if (typeof input === "string") {
    return encodeUtf8Bytes(input, "content");
  }
  const copy = new Uint8Array(input.byteLength);
  copy.set(input);
  return copy;
}

function toPositiveInt64String(value: bigint, fieldName: string): PositiveInt64String {
  return parsePositiveInt64String(formatInt64(value, fieldName), fieldName);
}

async function resolveAndAuthenticateActor(params: {
  readonly actor: AdmissionActorInput;
  readonly tenantId: TenantId;
  readonly projectId: ProjectId;
  readonly eventTypeId: EventTypeId;
  readonly eventSchemaVersion: number;
  readonly installation: Awaited<ReturnType<AdmissionRepositoryPort<unknown>["readAuthorities"]>>["installation"];
  readonly producerCredentialRepo: ProducerCredentialRepository;
  readonly now: ReturnType<ClockPort["nowInstant"]>;
}): Promise<ResolvedAdmissionActor> {
  if (params.actor.kind === "producer_credential") {
    const auth = await authenticateProducerCredential({
      installation: params.installation,
      bearerToken: params.actor.bearerToken,
      repo: params.producerCredentialRepo,
      now: params.now,
      requiredAction: "events.admit",
      requiredEvent: {
        eventTypeId: params.eventTypeId,
        schemaVersion: params.eventSchemaVersion
      }
    });
    if (auth.producer.tenantId !== params.tenantId || auth.producer.projectId !== params.projectId) {
      throw new AuthorizationDomainError({
        code: "FORBIDDEN",
        message: "Producer credential is not bound to the target tenant and project"
      });
    }
    return Object.freeze({
      channelKind: "machine_producer",
      actorPrincipalId: auth.principal.principalId,
      producerId: auth.producer.id,
      producerNamespace: auth.producer.businessNamespace
    });
  }

  if (!params.actor.scopeAuthorized) {
    throw new AuthorizationDomainError({
      code: "FORBIDDEN",
      message: "Human workflow actor is not authorized to admit events in this project"
    });
  }
  const actorPrincipalId = parsePrincipalId(params.actor.actorPrincipalId, "actorPrincipalId");
  const producerId = parseProducerId(params.actor.publicationChannelId, "publicationChannelId");
  const producerNamespace = assertHumanWorkflowNamespace(
    actorPrincipalId,
    params.actor.producerNamespace
  );
  return Object.freeze({
    channelKind: "human_workflow",
    actorPrincipalId,
    producerId,
    producerNamespace
  });
}

export class AdmissionService<TTx> {
  readonly #uow: UnitOfWorkPort<TTx>;
  readonly #admissionRepo: AdmissionRepositoryPort<TTx>;
  readonly #producerCredentialRepo: ProducerCredentialRepository;
  readonly #schemaEvaluator: SchemaEvaluatorPort;
  readonly #clock: ClockPort;
  readonly #ids: IdGeneratorPort;
  readonly #telemetry: TelemetryPort;

  constructor(deps: AdmissionServiceDeps<TTx>) {
    this.#uow = deps.uow;
    this.#admissionRepo = deps.admissionRepo;
    this.#producerCredentialRepo = deps.producerCredentialRepo;
    this.#schemaEvaluator = deps.schemaEvaluator;
    this.#clock = deps.clock ?? systemClockPort;
    this.#ids = deps.idGenerator ?? cryptoIdGeneratorPort;
    this.#telemetry = deps.telemetry ?? noopTelemetryPort;
  }

  /**
   * Resolves a previously submitted admission attempt (lost-response recovery)
   * without running new-write gates while still verifying current actor authority.
   */
  async resolvePreparedEvent(input: ResolvePreparedEventInput): Promise<ResolvePreparedEventOutput> {
    const tenantId = parseTenantId(input.tenantId, "tenantId");
    const projectId = parseProjectId(input.projectId, "projectId");
    const eventTypeId = parseEventTypeId(input.eventTypeId, "eventTypeId");
    const eventSchemaVersion = parsePositiveInt32(input.eventSchemaVersion, "eventSchemaVersion");
    const businessKey = parseBusinessKey(input.businessKey, "businessKey");
    const idempotencyKey = parseIdempotencyKey(input.idempotencyKey, "idempotencyKey");
    const contentBytes = toExactUtf8Bytes(input.contentBytes);
    if (contentBytes.byteLength === 0 || contentBytes.byteLength > EVENT_MAX_CONTENT_BYTES) {
      throw new ValidationDomainError({
        code: contentBytes.byteLength > EVENT_MAX_CONTENT_BYTES ? "PAYLOAD_TOO_LARGE" : "INVALID_VALUE",
        message: `Event content byte length ${contentBytes.byteLength} out of bounds [1, ${EVENT_MAX_CONTENT_BYTES}]`
      });
    }

    const contentSha256 = sha256Hex(contentBytes);
    const businessKeySha256 = computeBusinessKeySha256(businessKey);
    const idempotencyKeySha256 = computeRequestKeySha256(idempotencyKey);
    const producerEventTime =
      input.producerEventTime !== undefined
        ? parseCanonicalUtcTimestamp(input.producerEventTime, "producerEventTime")
        : undefined;
    const requestedDeadlineAt =
      input.deadlineAt !== undefined
        ? parseCanonicalUtcTimestamp(input.deadlineAt, "deadlineAt")
        : undefined;

    const nowInstant = this.#clock.nowInstant();

    return this.#uow.inTransaction(async (tx) => {
      const authorities = await this.#admissionRepo.readAuthorities(tx, tenantId, projectId);
      const actor = await resolveAndAuthenticateActor({
        actor: input.actor,
        tenantId,
        projectId,
        eventTypeId,
        eventSchemaVersion,
        installation: authorities.installation,
        producerCredentialRepo: this.#producerCredentialRepo,
        now: nowInstant
      });

      const submittedShape = computeEventAdmissionCommandFingerprint({
        scope: {
          tenant_id: tenantId,
          project_id: projectId,
          publication_channel_id: actor.producerId,
          channel_kind: actor.channelKind,
          actor_principal_id: actor.actorPrincipalId,
          producer_namespace: actor.producerNamespace
        },
        submission: {
          business_key: businessKey,
          event_type_id: eventTypeId,
          event_schema_version: eventSchemaVersion,
          content_sha256: contentSha256,
          byte_count: contentBytes.byteLength,
          ...(producerEventTime !== undefined ? { producer_event_time: producerEventTime } : {}),
          ...(requestedDeadlineAt !== undefined ? { deadline_at: requestedDeadlineAt } : {})
        }
      });

      const resolved = await this.#admissionRepo.resolveAdmittedEvent(tx, {
        tenantId,
        projectId,
        actorPrincipalId: actor.actorPrincipalId,
        producerNamespace: actor.producerNamespace,
        businessKeySha256,
        idempotencyKeySha256,
        submittedShapeSha256: submittedShape.sha256
      });

      if (!resolved.found) {
        return Object.freeze({ found: false });
      }
      if (resolved.matchKind === "conflict") {
        throw new ConflictDomainError({
          code: resolved.conflictCode,
          message: resolved.message
        });
      }

      return Object.freeze({
        found: true,
        statusCode: 200 as const,
        matchKind: resolved.matchKind,
        eventId: resolved.eventId,
        receiptId: resolved.receiptId,
        outboxId: resolved.outboxId,
        projectEventSequence: resolved.projectEventSequence,
        topologyVersion: resolved.topologyVersion,
        candidateCount: resolved.candidateCount,
        state: resolved.state,
        admittedAt: resolved.admittedAt,
        deliveryDeadlineAt: resolved.deliveryDeadlineAt,
        appliedDefaults: resolved.appliedDefaults
      });
    });
  }

  /**
   * Atomically admits an event with canonical business-key + SHA-256 deduplication,
   * schema validation, conservative fanout/storage reservation checks, lossless JSON
   * storage, and transactional outbox intent creation.
   */
  async admitEvent(input: AdmitEventInput): Promise<AdmitEventOutput> {
    const span = this.#telemetry.startSpan("relayquill.admission.admit_event");
    try {
      const tenantId = parseTenantId(input.tenantId, "tenantId");
      const projectId = parseProjectId(input.projectId, "projectId");
      const eventTypeId = parseEventTypeId(input.eventTypeId, "eventTypeId");
      const eventTypeName = parseEventTypeName(input.eventTypeName, "eventTypeName");
      const eventSchemaVersion = parsePositiveInt32(input.eventSchemaVersion, "eventSchemaVersion");
      const businessKey = parseBusinessKey(input.businessKey, "businessKey");
      const idempotencyKey = parseIdempotencyKey(input.idempotencyKey, "idempotencyKey");
      const contentBytes = toExactUtf8Bytes(input.contentBytes);
      if (contentBytes.byteLength === 0 || contentBytes.byteLength > EVENT_MAX_CONTENT_BYTES) {
        throw new ValidationDomainError({
          code: contentBytes.byteLength > EVENT_MAX_CONTENT_BYTES ? "PAYLOAD_TOO_LARGE" : "INVALID_VALUE",
          message: `Event content byte length ${contentBytes.byteLength} out of bounds [1, ${EVENT_MAX_CONTENT_BYTES}]`,
          fieldErrors: [{ path: "content", code: "PAYLOAD_TOO_LARGE" }]
        });
      }

      const contentSha256 = sha256Hex(contentBytes);
      const businessKeySha256 = computeBusinessKeySha256(businessKey);
      const idempotencyKeySha256 = computeRequestKeySha256(idempotencyKey);
      const producerEventTime =
        input.producerEventTime !== undefined
          ? parseCanonicalUtcTimestamp(input.producerEventTime, "producerEventTime")
          : undefined;
      const requestedDeadlineAt =
        input.deadlineAt !== undefined
          ? parseCanonicalUtcTimestamp(input.deadlineAt, "deadlineAt")
          : undefined;

      const nowInstant = this.#clock.nowInstant();
      const admittedAt = parseCanonicalUtcTimestamp(formatUtcTimestamp(nowInstant), "admittedAt");

      const result = await this.#uow.inTransaction(async (tx) => {
        const authorities = await this.#admissionRepo.readAuthorities(tx, tenantId, projectId);
        const actor = await resolveAndAuthenticateActor({
          actor: input.actor,
          tenantId,
          projectId,
          eventTypeId,
          eventSchemaVersion,
          installation: authorities.installation,
          producerCredentialRepo: this.#producerCredentialRepo,
          now: nowInstant
        });

        const submittedShape = computeEventAdmissionCommandFingerprint({
          scope: {
            tenant_id: tenantId,
            project_id: projectId,
            publication_channel_id: actor.producerId,
            channel_kind: actor.channelKind,
            actor_principal_id: actor.actorPrincipalId,
            producer_namespace: actor.producerNamespace
          },
          submission: {
            business_key: businessKey,
            event_type_id: eventTypeId,
            event_schema_version: eventSchemaVersion,
            content_sha256: contentSha256,
            byte_count: contentBytes.byteLength,
            ...(producerEventTime !== undefined ? { producer_event_time: producerEventTime } : {}),
            ...(requestedDeadlineAt !== undefined ? { deadline_at: requestedDeadlineAt } : {})
          }
        });

        // Step 1: Check accepted-result recovery & identity conflict BEFORE new-write gates.
        const existing = await this.#admissionRepo.resolveAdmittedEvent(tx, {
          tenantId,
          projectId,
          actorPrincipalId: actor.actorPrincipalId,
          producerNamespace: actor.producerNamespace,
          businessKeySha256,
          idempotencyKeySha256,
          submittedShapeSha256: submittedShape.sha256
        });

        if (existing.found) {
          if (existing.matchKind === "conflict") {
            throw new ConflictDomainError({
              code: existing.conflictCode,
              message: existing.message
            });
          }
          return Object.freeze<AdmitEventOutput>({
            statusCode: 200,
            outcome: existing.matchKind,
            eventId: existing.eventId,
            receiptId: existing.receiptId,
            outboxId: existing.outboxId,
            projectEventSequence: existing.projectEventSequence,
            topologyVersion: existing.topologyVersion,
            candidateCount: existing.candidateCount,
            state: existing.state,
            contentSha256,
            submittedShapeSha256: submittedShape.sha256,
            admittedAt: existing.admittedAt,
            deliveryDeadlineAt: existing.deliveryDeadlineAt,
            appliedDefaults: existing.appliedDefaults
          });
        }

        // Step 2: New-write authority gates.
        if (
          authorities.installation.mode === "recovery_quarantine" ||
          !authorities.installation.allowEventAdmission
        ) {
          throw new AuthorizationDomainError({
            code: "FORBIDDEN",
            message: "Installation currently disallows new event admission"
          });
        }
        if (authorities.tenant.state !== "active") {
          throw new AuthorizationDomainError({
            code: "FORBIDDEN",
            message: `Tenant "${tenantId}" is in state "${authorities.tenant.state}"`
          });
        }
        if (
          authorities.project.state !== "active" ||
          authorities.project.admissionPaused === true ||
          authorities.project.recoveryQuarantined === true
        ) {
          throw new AuthorizationDomainError({
            code: "FORBIDDEN",
            message: `Project "${projectId}" is not accepting new event admissions`
          });
        }

        // Step 3: Producer channel scope & payload ceiling checks.
        const producerScope = await this.#admissionRepo.findProducerScope(
          tx,
          tenantId,
          projectId,
          actor.producerId,
          actor.producerNamespace
        );
        if (producerScope === undefined || !producerScope.enabled) {
          throw new AuthorizationDomainError({
            code: "FORBIDDEN",
            message: "Producer scope is missing or disabled"
          });
        }
        if (!producerScope.allowedActions.includes("admit")) {
          throw new AuthorizationDomainError({
            code: "FORBIDDEN",
            message: "Producer scope does not allow event admission"
          });
        }
        if (contentBytes.byteLength > producerScope.maxDecodedContentBytes) {
          throw new ValidationDomainError({
            code: "PAYLOAD_TOO_LARGE",
            message: `Content size ${contentBytes.byteLength} exceeds producer limit ${producerScope.maxDecodedContentBytes}`
          });
        }
        const allowedEvent = producerScope.allowedEventTypeVersions.find(
          (entry) =>
            entry.eventTypeId === eventTypeId &&
            entry.schemaVersions.includes(eventSchemaVersion)
        );
        if (allowedEvent === undefined) {
          throw new AuthorizationDomainError({
            code: "FORBIDDEN",
            message: `Producer scope does not permit (${eventTypeId}, v${eventSchemaVersion})`
          });
        }

        // Step 4: Active schema lookup and lossless schema validation.
        const schemaDef = await this.#admissionRepo.findEventSchema(
          tx,
          tenantId,
          projectId,
          eventTypeId,
          eventSchemaVersion
        );
        if (schemaDef === undefined) {
          throw new NotFoundDomainError({
            code: "NOT_FOUND",
            message: `Event schema (${eventTypeId}, v${eventSchemaVersion}) not found`
          });
        }
        if (schemaDef.state !== "active") {
          throw new ConflictDomainError({
            code: "STATE_TRANSITION_NOT_ALLOWED",
            message: `Event schema (${eventTypeId}, v${eventSchemaVersion}) is "${schemaDef.state}", not active`
          });
        }

        const validation = await this.#schemaEvaluator.validateEvent({
          schemaBytes: schemaDef.schemaBytes,
          profileVersion: schemaDef.profileVersion,
          eventBytes: contentBytes
        });
        if (!validation.valid) {
          throw new ValidationDomainError({
            code: "INVALID_VALUE",
            message: "Event content failed schema validation",
            fieldErrors: validation.diagnostics.map((d) => ({
              path: d.path,
              code: d.code
            }))
          });
        }
        if (validation.sha256 !== contentSha256) {
          throw new ValidationDomainError({
            code: "INVALID_HASH",
            message: "Validated content digest mismatch"
          });
        }

        // Step 5: Resolve delivery window & deadline within project bounds.
        let effectiveWindowMs = authorities.project.defaultDeliveryWindowMs;
        let deliveryDeadlineInstant = addMilliseconds(nowInstant, Number(effectiveWindowMs));
        if (requestedDeadlineAt !== undefined) {
          const parsedDeadline = parseUtcTimestamp(requestedDeadlineAt, "deadlineAt");
          const deltaMs = BigInt(
            Math.trunc(
              parsedDeadline.instant.epochMilliseconds - nowInstant.epochMilliseconds
            )
          );
          if (deltaMs <= 0n || deltaMs > authorities.project.maxDeliveryWindowMs) {
            throw new ValidationDomainError({
              code: "INVALID_TIMESTAMP",
              message: "Requested deadline_at is outside allowed project delivery window bounds",
              fieldErrors: [{ path: "deadline_at", code: "INVALID_TIMESTAMP" }]
            });
          }
          effectiveWindowMs = deltaMs;
          deliveryDeadlineInstant = parsedDeadline.instant;
        } else if (input.deliveryWindowMs !== undefined) {
          const requestedWindow =
            typeof input.deliveryWindowMs === "bigint"
              ? input.deliveryWindowMs
              : BigInt(Math.trunc(input.deliveryWindowMs));
          if (requestedWindow <= 0n || requestedWindow > authorities.project.maxDeliveryWindowMs) {
            throw new ValidationDomainError({
              code: "INVALID_VALUE",
              message: "Requested deliveryWindowMs is outside project bounds",
              fieldErrors: [{ path: "deliveryWindowMs", code: "INVALID_VALUE" }]
            });
          }
          effectiveWindowMs = requestedWindow;
          deliveryDeadlineInstant = addMilliseconds(nowInstant, Number(effectiveWindowMs));
        }

        if (compareInstants(deliveryDeadlineInstant, nowInstant) <= 0) {
          throw new ValidationDomainError({
            code: "INVALID_TIMESTAMP",
            message: "Computed delivery deadline must be in the future"
          });
        }

        const deliveryDeadlineAt = parseCanonicalUtcTimestamp(
          formatUtcTimestamp(deliveryDeadlineInstant),
          "deliveryDeadlineAt"
        );

        // Step 6: Conservative candidate & storage reservation bounds.
        const topologyVersion = authorities.project.topologyVersion;
        const candidateInfo = await this.#admissionRepo.countCandidateSubscriptions(
          tx,
          tenantId,
          projectId,
          eventTypeId,
          eventSchemaVersion,
          topologyVersion
        );

        const eventId = parseEventId(this.#ids.nextUuid(), "eventId");
        const payloadId = parseEventPayloadId(this.#ids.nextUuid(), "payloadId");
        const wireEnvelopeId = parseWireEnvelopeId(this.#ids.nextUuid(), "wireEnvelopeId");
        const outboxId = parseOutboxId(this.#ids.nextUuid(), "outboxId");
        const receiptId = parseCommandReceiptId(this.#ids.nextUuid(), "receiptId");
        const auditId = this.#ids.nextUuid();
        const provisionalSeq = authorities.project.nextEventSequence;

        const wireSerialized = serializeWebhookEnvelope({
          envelope_version: 1,
          representation_version: 1,
          project_id: projectId,
          event_id: eventId,
          project_event_sequence: toPositiveInt64String(provisionalSeq, "project_event_sequence"),
          event_type_id: eventTypeId,
          event_type: eventTypeName,
          event_schema_version: eventSchemaVersion,
          admitted_at: admittedAt,
          producer_event_time: producerEventTime ?? null,
          content: {
            media_type: EVENT_CONTENT_MEDIA_TYPE,
            encoding: EVENT_CONTENT_ENCODING,
            byte_count: contentBytes.byteLength,
            sha256: contentSha256,
            data: encodeBase64(contentBytes)
          }
        });

        const reservedStorageBytes =
          BigInt(contentBytes.byteLength) +
          BigInt(wireSerialized.byte_count) +
          candidateInfo.count * candidateInfo.maxDerivedEnvelopeUpperBoundBytes;

        const maxPendingEvents =
          producerScope.maxPendingEventsOverride !== undefined &&
          producerScope.maxPendingEventsOverride < authorities.quota.maxPendingEvents
            ? producerScope.maxPendingEventsOverride
            : authorities.quota.maxPendingEvents;

        if (authorities.capacity.pendingEvents + 1n > maxPendingEvents) {
          throw new LimitExceededDomainError({
            code: "CAPACITY_EXCEEDED",
            message: "Project pending event quota exceeded",
            retryable: true,
            boundary: "accepted"
          });
        }
        if (
          authorities.capacity.unmaterializedCandidateSlots + candidateInfo.count >
          authorities.quota.maxUnmaterializedCandidateSlots
        ) {
          throw new LimitExceededDomainError({
            code: "CAPACITY_EXCEEDED",
            message: "Project unmaterialized fanout candidate slot quota exceeded",
            retryable: true,
            boundary: "accepted"
          });
        }
        if (
          authorities.capacity.retainedPayloadBytes +
            authorities.capacity.reservedPayloadBytes +
            reservedStorageBytes >
          authorities.quota.maxRetainedPayloadBytes
        ) {
          throw new LimitExceededDomainError({
            code: "CAPACITY_EXCEEDED",
            message: "Project retained and reserved storage budget exceeded",
            retryable: true,
            boundary: "accepted"
          });
        }

        // Step 7: Canonical broker notification envelope (publication generation 1) & effective hash.
        const brokerEncoded = encodeBrokerNotificationEnvelope({
          envelope_version: 1,
          outbox_id: outboxId,
          event_id: eventId,
          project_id: projectId,
          topology_version: topologyVersion,
          publication_generation: 1n,
          content_sha256: contentSha256,
          ...(input.traceparent !== undefined ? { traceparent: input.traceparent } : {}),
          ...(input.tracestate !== undefined ? { tracestate: input.tracestate } : {})
        });

        const retentionPolicyVersion =
          input.retentionPolicyVersion ?? DEFAULT_RETENTION_POLICY_VERSION;
        const effectiveFingerprint = computeEffectiveAdmissionFingerprint({
          submitted_shape_sha256: submittedShape.sha256,
          admitted_at: admittedAt,
          delivery_deadline_at: deliveryDeadlineAt,
          delivery_window_ms: effectiveWindowMs,
          producer_event_time: producerEventTime ?? null,
          option_presence: submittedShape.canonical_object.option_presence,
          topology_version: topologyVersion,
          admission_policy_version: ADMISSION_POLICY_VERSION,
          retention_policy_version: retentionPolicyVersion
        });

        const originalFactsSha256 = computeOriginalFactsSha256({
          project_id: projectId,
          event_id: eventId,
          project_event_sequence: provisionalSeq,
          event_type_id: eventTypeId,
          event_type: eventTypeName,
          event_schema_version: eventSchemaVersion,
          admitted_at: admittedAt,
          producer_event_time: producerEventTime ?? null,
          original_content_sha256: contentSha256
        });

        const appliedDefaults: Readonly<Record<string, unknown>> = Object.freeze({
          delivery_window_ms: effectiveWindowMs.toString(10),
          delivery_deadline_at: deliveryDeadlineAt,
          admitted_at: admittedAt,
          producer_event_time: producerEventTime ?? null,
          topology_version: topologyVersion.toString(10),
          admission_policy_version: ADMISSION_POLICY_VERSION,
          retention_policy_version: retentionPolicyVersion
        });

        const committed = await this.#admissionRepo.admitEvent(tx, {
          tenantId,
          projectId,
          actorPrincipalId: actor.actorPrincipalId,
          producerId: actor.producerId,
          producerNamespace: actor.producerNamespace,
          businessKey,
          businessKeySha256,
          idempotencyKeySha256,
          submittedShapeSha256: submittedShape.sha256,
          effectiveRequestSha256: effectiveFingerprint.sha256,
          originalFactsSha256,
          eventTypeId,
          eventTypeName,
          eventSchemaVersion,
          contentBytes,
          contentSha256,
          wireEnvelopeBytes: wireSerialized.body_bytes,
          wireEnvelopeSha256: wireSerialized.body_sha256,
          brokerEnvelopeBytes: brokerEncoded.bytes,
          brokerEnvelopeSha256: brokerEncoded.envelope_sha256,
          reservedStorageBytes,
          candidateCount: candidateInfo.count,
          producerEventTime: producerEventTime ?? null,
          admittedAt,
          deliveryDeadlineAt,
          appliedDefaults,
          retentionPolicyVersion,
          eventId,
          payloadId,
          wireEnvelopeId,
          outboxId,
          receiptId,
          auditId
        });

        return Object.freeze<AdmitEventOutput>({
          statusCode: committed.outcome === "accepted" ? 201 : 200,
          outcome: committed.outcome,
          eventId: committed.eventId,
          receiptId: committed.receiptId,
          outboxId: committed.outboxId,
          projectEventSequence: committed.projectEventSequence,
          topologyVersion: committed.topologyVersion,
          candidateCount: committed.candidateCount,
          state: committed.state,
          contentSha256,
          submittedShapeSha256: submittedShape.sha256,
          admittedAt: committed.admittedAt,
          deliveryDeadlineAt: committed.deliveryDeadlineAt,
          appliedDefaults: committed.appliedDefaults
        });
      });

      span.end({ code: "OK" });
      return result;
    } catch (err) {
      span.end({ code: "ERROR", message: err instanceof Error ? err.message : "admission_failed" });
      throw err;
    }
  }
}
