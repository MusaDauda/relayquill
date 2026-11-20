import {
  AuthorizationDomainError,
  FANOUT_OUT_OF_ORDER_NAK_MS,
  FANOUT_PAGE_SIZE,
  type PositiveInt64String,
  ValidationDomainError,
  assertContiguousFanoutSequence,
  assertReservationConservation,
  formatInt64,
  formatUtcTimestamp,
  parseBrokerGenerationId,
  parseBrokerInboxId,
  parseControlEpoch,
  parseDeliveryFamilyId,
  parseDeliveryId,
  parseEventId,
  parsePositiveInt64String,
  parseRuntimeInstanceId,
  parseWireEnvelopeId,
  type ControlEpoch,
  type EventId,
  type RuntimeInstanceId,
  type SubscriptionId
} from "@relayquill/domain";
import {
  computeConsumerEventKeySha256,
  computeOrderingKeySha256,
  decodeBrokerNotificationEnvelope,
  encodeBrokerMessageId,
  parseCanonicalUtcTimestamp
} from "@relayquill/contracts";
import {
  PROJECTION_COMPILER_VERSION,
  buildDerivedWebhookEnvelopeV2
} from "@relayquill/event-schema";
import { type BrokerMessage } from "@relayquill/broker";
import {
  type ClockPort,
  type FanoutOutcomeRecord,
  type FanoutRepositoryPort,
  type IdGeneratorPort,
  type SchemaEvaluatorPort,
  type TelemetryPort,
  type UnitOfWorkPort,
  cryptoIdGeneratorPort,
  noopTelemetryPort,
  systemClockPort
} from "./ports.js";

export const DEFAULT_FANOUT_CLAIM_LEASE_MS = 30_000n as const;

export interface ProcessBrokerMessageInput {
  readonly message: BrokerMessage;
  readonly instanceId: RuntimeInstanceId | string;
  readonly controlEpoch: ControlEpoch | string;
  readonly claimLeaseMs?: bigint | undefined;
  readonly pageSize?: number | undefined;
}

export interface ProcessBrokerMessageOutput {
  readonly eventId: EventId;
  readonly disposition:
    | "completed"
    | "already_completed"
    | "out_of_order_naked"
    | "claimed_by_peer";
  readonly projectEventSequence: bigint;
  readonly materializedThroughEventSequence: bigint;
  readonly pagesCommitted: number;
  readonly examinedCount: bigint;
  readonly deliveriesCreated: bigint;
}

export interface MaterializeEventFanoutInput {
  readonly eventId: EventId | string;
  readonly instanceId: RuntimeInstanceId | string;
  readonly controlEpoch: ControlEpoch | string;
  readonly claimLeaseMs?: bigint | undefined;
  readonly pageSize?: number | undefined;
  readonly onPageProgress?: (() => Promise<void>) | undefined;
}

export interface FanoutServiceDeps<TTx> {
  readonly uow: UnitOfWorkPort<TTx>;
  readonly fanoutRepo: FanoutRepositoryPort<TTx>;
  readonly schemaEvaluator: SchemaEvaluatorPort;
  readonly clock?: ClockPort | undefined;
  readonly idGenerator?: IdGeneratorPort | undefined;
  readonly telemetry?: TelemetryPort | undefined;
}

function toPositiveInt64(value: bigint, fieldName: string): PositiveInt64String {
  return parsePositiveInt64String(formatInt64(value, fieldName), fieldName);
}

export class FanoutService<TTx> {
  readonly #uow: UnitOfWorkPort<TTx>;
  readonly #fanoutRepo: FanoutRepositoryPort<TTx>;
  readonly #schemaEvaluator: SchemaEvaluatorPort;
  readonly #clock: ClockPort;
  readonly #ids: IdGeneratorPort;
  readonly #telemetry: TelemetryPort;

  constructor(deps: FanoutServiceDeps<TTx>) {
    this.#uow = deps.uow;
    this.#fanoutRepo = deps.fanoutRepo;
    this.#schemaEvaluator = deps.schemaEvaluator;
    this.#clock = deps.clock ?? systemClockPort;
    this.#ids = deps.idGenerator ?? cryptoIdGeneratorPort;
    this.#telemetry = deps.telemetry ?? noopTelemetryPort;
  }

  /**
   * Processes a single JetStream message:
   * 1. Decodes notification envelope and verifies deterministic `rq:<outboxId>:<gen>` ID.
   * 2. Persists `broker_inbox_events` and checks strict contiguous project sequence watermark.
   * 3. If out-of-order (`projectEventSequence > materializedThroughEventSequence + 1`),
   *    NAKs with `FANOUT_OUT_OF_ORDER_NAK_MS` without materializing.
   * 4. Otherwise materializes subscriptions in deterministic 100-item pages and ACKs
   *    only after the completion page commits.
   */
  async processBrokerMessage(
    input: ProcessBrokerMessageInput
  ): Promise<ProcessBrokerMessageOutput> {
    const span = this.#telemetry.startSpan("relayquill.fanout.process_broker_message");
    try {
      const instanceId = parseRuntimeInstanceId(input.instanceId, "instanceId");
      const controlEpoch = parseControlEpoch(input.controlEpoch, "controlEpoch");
      const decoded = decodeBrokerNotificationEnvelope(input.message.payload);
      const expectedMsgId = encodeBrokerMessageId(
        decoded.outbox_id,
        decoded.publication_generation
      );

      if (input.message.msgId !== undefined && input.message.msgId !== expectedMsgId) {
        await input.message.term("mismatched_broker_message_id");
        throw new ValidationDomainError({
          code: "INVARIANT_VIOLATION",
          message: `Broker message header Nats-Msg-Id "${input.message.msgId}" does not match "${expectedMsgId}"`
        });
      }

      const now = parseCanonicalUtcTimestamp(formatUtcTimestamp(this.#clock.nowInstant()), "now");
      const inboxId = parseBrokerInboxId(this.#ids.nextUuid(), "inboxId");
      const publicationGeneration = BigInt(decoded.publication_generation);
      const topologyVersion = BigInt(decoded.topology_version);
      const brokerGenerationId = parseBrokerGenerationId(
        input.message.brokerGenerationId,
        "brokerGenerationId"
      );

      const accepted = await this.#uow.inTransaction(async (tx) => {
        const installation = await this.#fanoutRepo.readInstallationAuthority(tx);
        if (
          installation.mode === "recovery_quarantine" ||
          !installation.allowFanout ||
          installation.controlEpoch !== controlEpoch
        ) {
          throw new AuthorizationDomainError({
            code: "FORBIDDEN",
            message: "Installation disallows fanout or control epoch is stale"
          });
        }
        return this.#fanoutRepo.acceptBrokerInbox(tx, {
          outboxId: decoded.outbox_id,
          publicationGeneration,
          eventId: decoded.event_id,
          projectId: decoded.project_id,
          topologyVersion,
          envelopeSha256: decoded.envelope_sha256,
          brokerGenerationId,
          streamSequence: BigInt(input.message.seq),
          inboxId,
          instanceId,
          controlEpoch,
          now
        });
      });

      if (accepted.fanoutState === "completed") {
        await input.message.ack();
        span.end({ code: "OK" });
        return Object.freeze({
          eventId: decoded.event_id,
          disposition: "already_completed",
          projectEventSequence: accepted.projectEventSequence,
          materializedThroughEventSequence: accepted.materializedThroughEventSequence,
          pagesCommitted: 0,
          examinedCount: 0n,
          deliveriesCreated: 0n
        });
      }

      if (!accepted.isNextContiguous) {
        await input.message.nak(Number(FANOUT_OUT_OF_ORDER_NAK_MS));
        span.end({ code: "OK" });
        return Object.freeze({
          eventId: decoded.event_id,
          disposition: "out_of_order_naked",
          projectEventSequence: accepted.projectEventSequence,
          materializedThroughEventSequence: accepted.materializedThroughEventSequence,
          pagesCommitted: 0,
          examinedCount: 0n,
          deliveriesCreated: 0n
        });
      }

      assertContiguousFanoutSequence(
        decoded.project_id,
        decoded.event_id,
        accepted.projectEventSequence,
        accepted.materializedThroughEventSequence
      );

      const materialized = await this.materializeEventFanout({
        eventId: decoded.event_id,
        instanceId,
        controlEpoch,
        ...(input.claimLeaseMs !== undefined ? { claimLeaseMs: input.claimLeaseMs } : {}),
        ...(input.pageSize !== undefined ? { pageSize: input.pageSize } : {}),
        onPageProgress: () => input.message.working()
      });

      if (
        materialized.disposition === "completed" ||
        materialized.disposition === "already_completed"
      ) {
        await input.message.ack();
      }

      span.end({ code: "OK" });
      return materialized;
    } catch (err) {
      span.end({ code: "ERROR", message: err instanceof Error ? err.message : "fanout_failed" });
      throw err;
    }
  }

  /**
   * Executes deterministic paginated subscription matching (default 100/page)
   * under a fenced `event_fanout` lease, evaluating filter ASTs, optional ordering
   * key extractors, and lossless derived representations while conserving reservations.
   */
  async materializeEventFanout(
    input: MaterializeEventFanoutInput
  ): Promise<ProcessBrokerMessageOutput> {
    const eventId = parseEventId(input.eventId, "eventId");
    const instanceId = parseRuntimeInstanceId(input.instanceId, "instanceId");
    const controlEpoch = parseControlEpoch(input.controlEpoch, "controlEpoch");
    const claimLeaseMs = input.claimLeaseMs ?? DEFAULT_FANOUT_CLAIM_LEASE_MS;
    const pageSize = Math.min(
      FANOUT_PAGE_SIZE,
      Math.max(1, Math.trunc(input.pageSize ?? FANOUT_PAGE_SIZE))
    );

    const claimNow = parseCanonicalUtcTimestamp(formatUtcTimestamp(this.#clock.nowInstant()), "now");
    const claimed = await this.#uow.inTransaction(async (tx) => {
      const installation = await this.#fanoutRepo.readInstallationAuthority(tx);
      if (
        installation.mode === "recovery_quarantine" ||
        !installation.allowFanout ||
        installation.controlEpoch !== controlEpoch
      ) {
        throw new AuthorizationDomainError({
          code: "FORBIDDEN",
          message: "Installation disallows event fanout"
        });
      }
      return this.#fanoutRepo.claimEventFanout(tx, {
        eventId,
        instanceId,
        controlEpoch,
        claimLeaseMs,
        now: claimNow
      });
    });

    if (claimed.outcome === "already_complete") {
      const eventCtx = await this.#uow.inTransaction((tx) =>
        this.#fanoutRepo.readEventForFanout(tx, eventId)
      );
      return Object.freeze({
        eventId,
        disposition: "already_completed",
        projectEventSequence: eventCtx.projectEventSequence,
        materializedThroughEventSequence: eventCtx.projectEventSequence,
        pagesCommitted: 0,
        examinedCount: 0n,
        deliveriesCreated: 0n
      });
    }

    const eventCtx = await this.#uow.inTransaction((tx) =>
      this.#fanoutRepo.readEventForFanout(tx, eventId)
    );

    let cursor: SubscriptionId | undefined = claimed.subscriptionCursor;
    let totalExamined = claimed.examinedCount;
    let totalDeliveries = 0n;
    let pagesCommitted = 0;
    let materializedWatermark = eventCtx.projectEventSequence - 1n;

    for (;;) {
      const candidates = await this.#uow.inTransaction((tx) =>
        this.#fanoutRepo.listActiveSubscriptionsPage(tx, {
          tenantId: eventCtx.tenantId,
          projectId: eventCtx.projectId,
          eventTypeId: eventCtx.eventTypeId,
          schemaVersion: eventCtx.eventSchemaVersion,
          topologyVersion: claimed.topologyVersion,
          ...(cursor !== undefined ? { afterSubscriptionId: cursor } : {}),
          limit: pageSize
        })
      );

      const outcomes: FanoutOutcomeRecord[] = [];
      let pageDeliveriesCount = 0n;
      let pageSkippedOrBlockedCount = 0n;

      for (const candidate of candidates) {
        const orderingDigestScope =
          candidate.orderingMode === "strict_per_key" && candidate.orderingDomainId !== undefined
            ? {
                orderingDomainId: candidate.orderingDomainId,
                subscriptionId: candidate.subscriptionId,
                consumerContractScope: candidate.consumerContractScope
              }
            : undefined;

        const evaluated = await this.#schemaEvaluator.evaluateFilterAndExtract({
          schemaBytes: eventCtx.schemaBytes,
          schemaProfileVersion: eventCtx.schemaProfileVersion,
          eventBytes: eventCtx.contentBytes,
          filterProfileVersion: candidate.filterProfileVersion,
          filterAst: candidate.filterAst,
          ...(candidate.orderingExtractorSpec !== undefined
            ? { orderingExtractorSpec: candidate.orderingExtractorSpec }
            : {}),
          ...(orderingDigestScope !== undefined ? { orderingDigestScope } : {})
        });

        if (!evaluated.schemaValid) {
          pageSkippedOrBlockedCount += 1n;
          outcomes.push({
            subscriptionId: candidate.subscriptionId,
            subscriptionVersion: candidate.subscriptionVersion,
            outcome: "failed",
            filterProfileVersion: candidate.filterProfileVersion,
            filterSha256: candidate.filterSha256,
            consumerContractScope: candidate.consumerContractScope,
            reservedSlotBytesToRelease: candidate.reservedSlotBytes,
            blockingReason: "SCHEMA_VALIDATION_FAILED_AT_FANOUT"
          });
          continue;
        }

        if (!evaluated.matched) {
          pageSkippedOrBlockedCount += 1n;
          outcomes.push({
            subscriptionId: candidate.subscriptionId,
            subscriptionVersion: candidate.subscriptionVersion,
            outcome: "filtered_out",
            filterProfileVersion: candidate.filterProfileVersion,
            filterSha256: candidate.filterSha256,
            consumerContractScope: candidate.consumerContractScope,
            reservedSlotBytesToRelease: candidate.reservedSlotBytes
          });
          continue;
        }

        if (candidate.orderingMode === "strict_per_key") {
          if (
            candidate.orderingDomainId === undefined ||
            evaluated.ordering === undefined ||
            evaluated.orderingErrorCode !== undefined
          ) {
            pageSkippedOrBlockedCount += 1n;
            outcomes.push({
              subscriptionId: candidate.subscriptionId,
              subscriptionVersion: candidate.subscriptionVersion,
              outcome: "blocked",
              filterProfileVersion: candidate.filterProfileVersion,
              filterSha256: candidate.filterSha256,
              consumerContractScope: candidate.consumerContractScope,
              reservedSlotBytesToRelease: candidate.reservedSlotBytes,
              blockingReason: evaluated.orderingErrorCode ?? "ORDERING_KEY_EXTRACTION_FAILED"
            });
            continue;
          }
        }

        let wireEnvelopeId = eventCtx.wireEnvelopeId;
        let derivedWireEnvelope:
          | NonNullable<FanoutOutcomeRecord["deliverySeed"]>["derivedWireEnvelope"]
          | undefined;
        let reservedSlotBytesToRelease = candidate.reservedSlotBytes;

        if (
          candidate.representationProfileId !== undefined &&
          candidate.representationProfileVersion !== undefined &&
          candidate.representationProfileBytes !== undefined &&
          candidate.representationProfileSha256 !== undefined
        ) {
          const projected = await this.#schemaEvaluator.executeProjection({
            profileBytes: candidate.representationProfileBytes,
            sourceEventBytes: eventCtx.contentBytes,
            sourceSchemaBytes: eventCtx.schemaBytes,
            sourceSchemaProfileVersion: eventCtx.schemaProfileVersion
          });

          const serializedV2 = buildDerivedWebhookEnvelopeV2({
            representation_version: Number(candidate.representationProfileVersion),
            project_id: eventCtx.projectId,
            event_id: eventCtx.eventId,
            project_event_sequence: toPositiveInt64(
              eventCtx.projectEventSequence,
              "project_event_sequence"
            ),
            event_type_id: eventCtx.eventTypeId,
            event_type: eventCtx.eventTypeName,
            event_schema_version: eventCtx.eventSchemaVersion,
            admitted_at: eventCtx.admittedAt,
            producer_event_time: null,
            profile_id: candidate.representationProfileId,
            profile_version: toPositiveInt64(
              candidate.representationProfileVersion,
              "profile_version"
            ),
            profile_sha256: candidate.representationProfileSha256,
            projection: {
              compilerProfileVersion: PROJECTION_COMPILER_VERSION,
              sourceBytes: eventCtx.contentBytes,
              sourceByteCount: eventCtx.contentBytes.byteLength,
              sourceContentSha256: eventCtx.contentSha256,
              derivedJson: projected.derivedJson,
              derivedBytes: projected.derivedBytes,
              derivedByteCount: projected.derivedByteCount,
              derivedContentSha256: projected.derivedContentSha256,
              targetSchemaVersion: projected.targetSchemaVersion,
              provenance: {
                compiler_profile_version: PROJECTION_COMPILER_VERSION,
                source_content_sha256: projected.provenance.source_content_sha256,
                derived_content_sha256: projected.provenance.derived_content_sha256,
                profile_sha256: projected.provenance.profile_sha256,
                source_schema_version: projected.provenance.source_schema_version,
                target_schema_version: projected.provenance.target_schema_version,
                policy_constant_paths: projected.provenance.policy_constant_paths,
                applied_default_paths: projected.provenance.applied_default_paths,
                contains_original_provenance: true,
                is_private_data_redaction: false
              }
            }
          });

          wireEnvelopeId = parseWireEnvelopeId(this.#ids.nextUuid(), "derivedWireEnvelopeId");
          const actualBytes = BigInt(serializedV2.byte_count);
          reservedSlotBytesToRelease =
            candidate.reservedSlotBytes > actualBytes
              ? candidate.reservedSlotBytes - actualBytes
              : 0n;

          derivedWireEnvelope = Object.freeze({
            bodyBytes: serializedV2.body_bytes,
            bodySha256: serializedV2.body_sha256,
            representationProfileId: candidate.representationProfileId,
            representationProfileVersion: candidate.representationProfileVersion,
            provenance: projected.provenance
          });
        }

        const consumerEventKeySha256 = computeConsumerEventKeySha256({
          project_id: eventCtx.projectId,
          event_id: eventCtx.eventId,
          consumer_contract_scope: candidate.consumerContractScope
        });

        const deliveryId = parseDeliveryId(this.#ids.nextUuid(), "deliveryId");
        const familyId = parseDeliveryFamilyId(this.#ids.nextUuid(), "familyId");
        pageDeliveriesCount += 1n;

        let orderingInfo:
          | NonNullable<FanoutOutcomeRecord["deliverySeed"]>["ordering"]
          | undefined;
        if (
          candidate.orderingMode === "strict_per_key" &&
          candidate.orderingDomainId !== undefined &&
          evaluated.ordering !== undefined
        ) {
          const orderingKeySha256 =
            evaluated.ordering.orderingKeySha256 ??
            computeOrderingKeySha256({
              ordering_domain_id: candidate.orderingDomainId,
              subscription_id: candidate.subscriptionId,
              consumer_contract_scope: candidate.consumerContractScope,
              ordering_key: evaluated.ordering.orderingKey
            });

          const orderingDomainId = candidate.orderingDomainId;
          const orderingKey = evaluated.ordering.orderingKey;
          const reservedOrd = await this.#uow.inTransaction((tx) =>
            this.#fanoutRepo.reserveOrderingSequence(tx, {
              tenantId: eventCtx.tenantId,
              projectId: eventCtx.projectId,
              subscriptionId: candidate.subscriptionId,
              orderingDomainId,
              orderingKeySha256,
              consumerContractScope: candidate.consumerContractScope
            })
          );

          orderingInfo = Object.freeze({
            orderingDomainId,
            orderingKey,
            orderingKeySha256,
            orderingSequence: reservedOrd.orderingSequence
          });
        }

        outcomes.push({
          subscriptionId: candidate.subscriptionId,
          subscriptionVersion: candidate.subscriptionVersion,
          outcome: "matched",
          filterProfileVersion: candidate.filterProfileVersion,
          filterSha256: candidate.filterSha256,
          consumerContractScope: candidate.consumerContractScope,
          reservedSlotBytesToRelease,
          deliverySeed: Object.freeze({
            deliveryId,
            familyId,
            endpointId: candidate.endpointId,
            endpointVersion: candidate.endpointVersion,
            wireEnvelopeId,
            ...(derivedWireEnvelope !== undefined ? { derivedWireEnvelope } : {}),
            consumerEventKeySha256,
            maxAttempts: candidate.maxAttempts,
            retryPolicyVersion: candidate.retryPolicyVersion,
            ...(orderingInfo !== undefined ? { ordering: orderingInfo } : {})
          })
        });
      }

      assertReservationConservation({
        reservedCandidateSlots: BigInt(candidates.length),
        unresolvedCandidateSlots: 0n,
        convertedDeliverySlots: pageDeliveriesCount,
        releasedNonmatchSlots: pageSkippedOrBlockedCount
      });

      const lastCandidate = candidates[candidates.length - 1];
      const nextCursor = lastCandidate !== undefined ? lastCandidate.subscriptionId : null;
      const isComplete = candidates.length < pageSize;
      const pageNow = parseCanonicalUtcTimestamp(
        formatUtcTimestamp(this.#clock.nowInstant()),
        "pageNow"
      );

      const committed = await this.#uow.inTransaction((tx) =>
        this.#fanoutRepo.commitFanoutPage(tx, {
          eventId,
          instanceId,
          controlEpoch,
          expectedClaimGeneration: claimed.claimGeneration,
          nextCursor,
          complete: isComplete,
          outcomes,
          now: pageNow
        })
      );

      if (committed.outcome === "already_complete") {
        return Object.freeze({
          eventId,
          disposition: "already_completed",
          projectEventSequence: eventCtx.projectEventSequence,
          materializedThroughEventSequence: eventCtx.projectEventSequence,
          pagesCommitted,
          examinedCount: totalExamined,
          deliveriesCreated: totalDeliveries
        });
      }

      pagesCommitted += 1;
      totalExamined = committed.newExamined;
      totalDeliveries = committed.newDeliveries;
      materializedWatermark = committed.materializedThroughEventSequence;

      if (isComplete || committed.outcome === "completed") {
        return Object.freeze({
          eventId,
          disposition: "completed",
          projectEventSequence: eventCtx.projectEventSequence,
          materializedThroughEventSequence: materializedWatermark,
          pagesCommitted,
          examinedCount: totalExamined,
          deliveriesCreated: totalDeliveries
        });
      }

      cursor = nextCursor ?? undefined;
      if (input.onPageProgress !== undefined) {
        await input.onPageProgress();
      }
    }
  }
}
