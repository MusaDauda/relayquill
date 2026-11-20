import crypto from "node:crypto";
import { type Temporal } from "@js-temporal/polyfill";
import {
  type ActorKind,
  type AttemptState,
  type BrokerGenerationId,
  type BrokerInboxId,
  type BrokerInboxState,
  type CanonicalUtcTimestamp,
  type CircuitState,
  type CommandReceiptId,
  type ControlEpoch,
  type DataGrantAction,
  type DataGrantId,
  type DataGrantProjection,
  type DeliveryFamilyId,
  type DeliveryId,
  type DeliveryOutcomeClass,
  type DeliveryState,
  type EndpointId,
  type EndpointState,
  type EndpointVerificationAttemptId,
  type EndpointVerificationIntentId,
  type EventFanoutState,
  type EventId,
  type EventPayloadId,
  type EventState,
  type EventTypeId,
  type EventTypeName,
  type InstallationMode,
  type KeyId,
  type LateObservationId,
  type OrderingCutoverPlanId,
  type OrderingCutoverPlanState,
  type OrderingDomainId,
  type OrderingMode,
  type OutboxId,
  type OutboxState,
  type PositiveInt64String,
  type PrincipalId,
  type ProducerCredentialId,
  type ProducerId,
  type ProducerNamespace,
  type ProjectId,
  type ProjectState,
  type PublicationObservationId,
  type PublicationRecoveryEpisodeId,
  type ReceiverReceiptObservationId,
  type ReplayProposalId,
  type RepresentationProfileId,
  type RetentionActionId,
  type RetentionActionKind,
  type RetentionActionState,
  type RetentionHoldId,
  type RetentionHoldState,
  type RetryDecisionOutcome,
  type RuntimeInstanceId,
  type SessionId,
  type Sha256Hex,
  type SignatureMode,
  type SigningDeliveryIntentId,
  type SigningKeyVersionId,
  type SubscriptionId,
  type TenantId,
  type TenantState,
  type WatchLeaseId,
  type WatchResourceKind,
  type WireEnvelopeId,
  type AttemptId,
  nowUtcInstant
} from "@relayquill/domain";
import { type BrokerMessageId } from "@relayquill/contracts";
import {
  type AuthChallengeRepository,
  type EnrollmentIntentRepository,
  type GovernanceRepository,
  type HumanSessionRepository,
  type OperationProofRepository,
  type PasskeyRepository,
  type PreauthContextRepository,
  type ProducerCredentialRepository
} from "@relayquill/auth";
import {
  type ExtractedOrderingKeyResult,
  type OrderingDigestScope,
  type ProjectionProvenanceRecord,
  type SchemaDiagnostic
} from "@relayquill/event-schema";
import {
  type EndpointKeyMetadata,
  type EndpointProofVerificationResult,
  type SignedWebhookRequest,
  type SignEndpointVerificationInput,
  type SignWebhookDeliveryInput,
  type VerifyEndpointProofResponseInput,
  type VerifyReceiverReceiptResponseInput,
  type VerifyReceiverReceiptResult
} from "@relayquill/signing";
import {
  type EgressDecision,
  type EgressExecutionResult,
  type ExecutePinnedEgressInput,
  type ResolveEgressOptions
} from "@relayquill/egress";
import {
  type BrokerPublishInput,
  type BrokerPublishResult,
  type BrokerPullOptions,
  type BrokerMessage
} from "@relayquill/broker";

// =============================================================================
// Cross-cutting infrastructure ports
// =============================================================================

export interface ClockPort {
  nowInstant(): Temporal.Instant;
  monotonicNowMs(): number;
  monotonicNowNs(): bigint;
}

export const systemClockPort: ClockPort = Object.freeze({
  nowInstant(): Temporal.Instant {
    return nowUtcInstant();
  },
  monotonicNowMs(): number {
    return Number(process.hrtime.bigint() / 1_000_000n);
  },
  monotonicNowNs(): bigint {
    return process.hrtime.bigint();
  }
});

export interface IdGeneratorPort {
  nextUuid(): string;
  nextRandomBytes(byteLength: number): Uint8Array;
}

export const cryptoIdGeneratorPort: IdGeneratorPort = Object.freeze({
  nextUuid(): string {
    return crypto.randomUUID();
  },
  nextRandomBytes(byteLength: number): Uint8Array {
    return crypto.randomBytes(byteLength);
  }
});

export interface TelemetrySpanHandle {
  readonly traceId?: string | undefined;
  readonly spanId?: string | undefined;
  readonly traceparent?: string | undefined;
  readonly tracestate?: string | undefined;
  end(status?: { readonly code: "OK" | "ERROR"; readonly message?: string | undefined }): void;
}

export interface TelemetryPort {
  startSpan(
    name: string,
    attributes?: Readonly<Record<string, unknown>>
  ): TelemetrySpanHandle;
  createAttemptTrace(options: {
    readonly spanName: string;
    readonly attributes?: Readonly<Record<string, unknown>> | undefined;
    readonly allowedTracestateKeys?: readonly string[] | undefined;
  }): TelemetrySpanHandle;
}

export const noopTelemetryPort: TelemetryPort = Object.freeze({
  startSpan(): TelemetrySpanHandle {
    return {
      end() {
        // Intentional no-op span for isolated unit tests
      }
    };
  },
  createAttemptTrace(): TelemetrySpanHandle {
    return {
      end() {
        // Intentional no-op attempt span for isolated unit tests
      }
    };
  }
});

export interface UnitOfWorkPort<TTx> {
  inTransaction<T>(fn: (tx: TTx) => Promise<T>): Promise<T>;
}

// =============================================================================
// Authority & Quota Records
// =============================================================================

export interface InstallationAuthoritySnapshot {
  readonly controlEpoch: ControlEpoch;
  readonly mode: InstallationMode;
  readonly allowEventAdmission: boolean;
  readonly allowPublication: boolean;
  readonly allowFanout: boolean;
  readonly allowSend: boolean;
  readonly allowEndpointVerification: boolean;
  readonly governanceVersion: bigint;
  readonly updatedAt: CanonicalUtcTimestamp;
  readonly version: bigint;
}

export interface TenantAuthoritySnapshot {
  readonly tenantId: TenantId;
  readonly slug: string;
  readonly displayName: string;
  readonly state: TenantState;
  readonly governanceVersion: bigint;
  readonly version: bigint;
}

export interface ProjectAuthoritySnapshot {
  readonly tenantId: TenantId;
  readonly projectId: ProjectId;
  readonly name: string;
  readonly state: ProjectState;
  readonly admissionPaused?: boolean | undefined;
  readonly admissionPausedReason?: string | undefined;
  readonly recoveryQuarantined?: boolean | undefined;
  readonly topologyVersion: bigint;
  readonly nextEventSequence: bigint;
  readonly materializedThroughEventSequence: bigint;
  readonly governanceVersion: bigint;
  readonly activeOrderingCutoverPlanId?: OrderingCutoverPlanId | undefined;
  readonly defaultDeliveryWindowMs: bigint;
  readonly maxDeliveryWindowMs: bigint;
  readonly version: bigint;
}

export interface ProjectQuotaLimits {
  readonly maxPendingEvents: bigint;
  readonly maxUnmaterializedCandidateSlots: bigint;
  readonly maxPendingDeliveries: bigint;
  readonly maxActiveAttemptSlots: number;
  readonly maxRetainedPayloadBytes: bigint;
}

export interface ProjectCapacitySnapshot {
  readonly projectId: ProjectId;
  readonly tenantId: TenantId;
  readonly pendingEvents: bigint;
  readonly unmaterializedCandidateSlots: bigint;
  readonly pendingDeliveries: bigint;
  readonly activeAttemptSlots: number;
  readonly retainedPayloadBytes: bigint;
  readonly reservedPayloadBytes: bigint;
  readonly version: bigint;
}

export interface ProducerScopeGrantRecord {
  readonly producerId: ProducerId;
  readonly tenantId: TenantId;
  readonly projectId: ProjectId;
  readonly producerNamespace: ProducerNamespace;
  readonly enabled: boolean;
  readonly scopeVersion: bigint;
  readonly allowedActions: readonly ("admit" | "read_status" | "watch")[];
  readonly allowedEventTypeVersions: readonly {
    readonly eventTypeId: EventTypeId;
    readonly eventTypeName: EventTypeName;
    readonly schemaVersions: readonly number[];
  }[];
  readonly maxEncodedBodyBytes: number;
  readonly maxDecodedContentBytes: number;
  readonly maxPendingEventsOverride?: bigint | undefined;
}

export interface EventSchemaDefinitionRecord {
  readonly eventTypeId: EventTypeId;
  readonly eventTypeName: EventTypeName;
  readonly schemaVersion: number;
  readonly tenantId: TenantId;
  readonly projectId: ProjectId;
  readonly state: "draft" | "active" | "deprecated" | "retired";
  readonly profileVersion: string;
  readonly schemaBytes: Uint8Array;
  readonly schemaSha256: Sha256Hex;
}

// =============================================================================
// Admission Port
// =============================================================================

export interface ResolveAdmittedEventQuery {
  readonly tenantId: TenantId;
  readonly projectId: ProjectId;
  readonly actorPrincipalId: PrincipalId;
  readonly producerNamespace: string;
  readonly businessKeySha256: Sha256Hex;
  readonly idempotencyKeySha256: Sha256Hex;
  readonly submittedShapeSha256: Sha256Hex;
}

export type ResolveAdmittedEventOutcome =
  | { readonly found: false }
  | {
      readonly found: true;
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
    }
  | {
      readonly found: true;
      readonly matchKind: "conflict";
      readonly conflictCode:
        | "PUBLICATION_CONTEXT_CHANGED"
        | "BUSINESS_IDENTITY_CONFLICT"
        | "IDEMPOTENCY_CONFLICT";
      readonly message: string;
    };

export interface AdmitEventCommandRecord {
  readonly tenantId: TenantId;
  readonly projectId: ProjectId;
  readonly actorPrincipalId: PrincipalId;
  readonly producerId: ProducerId;
  readonly producerNamespace: ProducerNamespace;
  readonly businessKey: string;
  readonly businessKeySha256: Sha256Hex;
  readonly idempotencyKeySha256: Sha256Hex;
  readonly submittedShapeSha256: Sha256Hex;
  readonly effectiveRequestSha256: Sha256Hex;
  readonly originalFactsSha256: Sha256Hex;
  readonly eventTypeId: EventTypeId;
  readonly eventTypeName: EventTypeName;
  readonly eventSchemaVersion: number;
  readonly contentBytes: Uint8Array;
  readonly contentSha256: Sha256Hex;
  readonly wireEnvelopeBytes: Uint8Array;
  readonly wireEnvelopeSha256: Sha256Hex;
  readonly brokerEnvelopeBytes: Uint8Array;
  readonly brokerEnvelopeSha256: Sha256Hex;
  readonly reservedStorageBytes: bigint;
  readonly candidateCount: bigint;
  readonly producerEventTime?: CanonicalUtcTimestamp | null | undefined;
  readonly admittedAt: CanonicalUtcTimestamp;
  readonly deliveryDeadlineAt: CanonicalUtcTimestamp;
  readonly appliedDefaults: Readonly<Record<string, unknown>>;
  readonly retentionPolicyVersion: string;
  readonly eventId: EventId;
  readonly payloadId: EventPayloadId;
  readonly wireEnvelopeId: WireEnvelopeId;
  readonly outboxId: OutboxId;
  readonly receiptId: CommandReceiptId;
  readonly auditId: string;
}

export interface AdmitEventCommandOutcome {
  readonly outcome: "accepted" | "idempotent_recovery" | "business_anchor_recovery";
  readonly eventId: EventId;
  readonly receiptId: CommandReceiptId;
  readonly outboxId: OutboxId;
  readonly projectEventSequence: bigint;
  readonly topologyVersion: bigint;
  readonly candidateCount: bigint;
  readonly admittedAt: CanonicalUtcTimestamp;
  readonly deliveryDeadlineAt: CanonicalUtcTimestamp;
  readonly state: EventState;
  readonly appliedDefaults: Readonly<Record<string, unknown>>;
}

export interface AdmissionRepositoryPort<TTx> {
  readAuthorities(
    tx: TTx,
    tenantId: TenantId,
    projectId: ProjectId
  ): Promise<{
    readonly installation: InstallationAuthoritySnapshot;
    readonly tenant: TenantAuthoritySnapshot;
    readonly project: ProjectAuthoritySnapshot;
    readonly quota: ProjectQuotaLimits;
    readonly capacity: ProjectCapacitySnapshot;
  }>;
  findProducerScope(
    tx: TTx,
    tenantId: TenantId,
    projectId: ProjectId,
    producerId: ProducerId,
    namespace: ProducerNamespace
  ): Promise<ProducerScopeGrantRecord | undefined>;
  findEventSchema(
    tx: TTx,
    tenantId: TenantId,
    projectId: ProjectId,
    eventTypeId: EventTypeId,
    schemaVersion: number
  ): Promise<EventSchemaDefinitionRecord | undefined>;
  countCandidateSubscriptions(
    tx: TTx,
    tenantId: TenantId,
    projectId: ProjectId,
    eventTypeId: EventTypeId,
    schemaVersion: number,
    topologyVersion: bigint
  ): Promise<{
    readonly count: bigint;
    readonly maxDerivedEnvelopeUpperBoundBytes: bigint;
  }>;
  resolveAdmittedEvent(
    tx: TTx,
    query: ResolveAdmittedEventQuery
  ): Promise<ResolveAdmittedEventOutcome>;
  admitEvent(tx: TTx, record: AdmitEventCommandRecord): Promise<AdmitEventCommandOutcome>;
}

// =============================================================================
// Outbox & Relay Port
// =============================================================================

export interface OutboxRowRecord {
  readonly outboxId: OutboxId;
  readonly eventId: EventId;
  readonly tenantId: TenantId;
  readonly projectId: ProjectId;
  readonly topologyVersion: bigint;
  readonly state: OutboxState;
  readonly currentPublicationGeneration: bigint;
  readonly nextPublishAt: CanonicalUtcTimestamp;
  readonly brokerMessageId: BrokerMessageId;
  readonly claimOwnerInstanceId?: RuntimeInstanceId | undefined;
  readonly claimGeneration: bigint;
  readonly claimExpiresAt?: CanonicalUtcTimestamp | undefined;
  readonly recoveryAttemptCount: number;
  readonly noProgressGenerationCount: number;
  readonly lastSafeErrorCode?: string | undefined;
  readonly version: bigint;
}

export interface ClaimOutboxRecord {
  readonly outboxId: OutboxId;
  readonly eventId: EventId;
  readonly projectId: ProjectId;
  readonly publicationGeneration: bigint;
  readonly claimGeneration: bigint;
  readonly claimExpiresAt: CanonicalUtcTimestamp;
  readonly brokerMessageId: BrokerMessageId;
  readonly envelopeBytes: Uint8Array;
  readonly traceparent?: string | undefined;
  readonly tracestate?: string | undefined;
}

export interface OutboxPublicationRecord {
  readonly publicationGeneration: bigint;
  readonly envelopeSha256: Sha256Hex;
  readonly envelopeBytes: Uint8Array;
  readonly brokerMessageId: BrokerMessageId;
  readonly state: "pending" | "publish_unknown" | "published" | "abandoned";
  readonly streamName?: string | undefined;
  readonly streamSequence?: bigint | undefined;
  readonly firstBrokerGenerationId?: BrokerGenerationId | undefined;
}

export interface RelayRepositoryPort<TTx> {
  readInstallationAuthority(tx: TTx): Promise<InstallationAuthoritySnapshot>;
  listDueOutboxEvents(tx: TTx, now: CanonicalUtcTimestamp, limit: number): Promise<readonly OutboxRowRecord[]>;
  claimOutboxEvent(
    tx: TTx,
    params: {
      readonly outboxId: OutboxId;
      readonly instanceId: RuntimeInstanceId;
      readonly controlEpoch: ControlEpoch;
      readonly claimLeaseMs: bigint;
      readonly now: CanonicalUtcTimestamp;
    }
  ): Promise<ClaimOutboxRecord>;
  observeOutboxPublication(
    tx: TTx,
    params: {
      readonly outboxId: OutboxId;
      readonly publicationGeneration: bigint;
      readonly instanceId: RuntimeInstanceId;
      readonly controlEpoch: ControlEpoch;
      readonly expectedClaimGeneration: bigint;
      readonly outcome: "published" | "publish_unknown" | "retry_pending" | "blocked";
      readonly brokerGenerationId?: BrokerGenerationId | null | undefined;
      readonly streamName?: string | null | undefined;
      readonly streamSequence?: bigint | null | undefined;
      readonly ackDuplicate?: boolean | undefined;
      readonly safeErrorCode?: string | null | undefined;
      readonly nextPublishAt?: CanonicalUtcTimestamp | null | undefined;
      readonly observationId: PublicationObservationId;
      readonly now: CanonicalUtcTimestamp;
    }
  ): Promise<{
    readonly acceptedAsCurrent: boolean;
    readonly outboxState: OutboxState;
    readonly publicationState: string;
  }>;
  listOutboxPublications(tx: TTx, outboxId: OutboxId): Promise<readonly OutboxPublicationRecord[]>;
  allocateOutboxRecoveryGeneration(
    tx: TTx,
    params: {
      readonly outboxId: OutboxId;
      readonly episodeId: PublicationRecoveryEpisodeId;
      readonly instanceId: RuntimeInstanceId;
      readonly controlEpoch: ControlEpoch;
      readonly envelopeBytes: Uint8Array;
      readonly envelopeSha256: Sha256Hex;
      readonly brokerMessageId: BrokerMessageId;
      readonly reasonCode: string;
      readonly now: CanonicalUtcTimestamp;
    }
  ): Promise<{
    readonly outcome: "already_complete" | "review_required" | "allocated";
    readonly episodeId?: PublicationRecoveryEpisodeId | undefined;
    readonly eventId?: EventId | undefined;
    readonly publicationGeneration?: bigint | undefined;
  }>;
}

// =============================================================================
// Broker Inbox & Fanout Port
// =============================================================================

export interface SubscriptionCandidateRecord {
  readonly subscriptionId: SubscriptionId;
  readonly subscriptionVersion: bigint;
  readonly endpointId: EndpointId;
  readonly endpointVersion: bigint;
  readonly eventTypeId: EventTypeId;
  readonly eventTypeName: EventTypeName;
  readonly schemaVersion: number;
  readonly filterProfileVersion: string;
  readonly filterAst: Readonly<Record<string, unknown>>;
  readonly filterSha256: Sha256Hex;
  readonly orderingMode: OrderingMode;
  readonly orderingDomainId?: OrderingDomainId | undefined;
  readonly orderingExtractorVersion?: string | undefined;
  readonly orderingExtractorSpec?: Readonly<Record<string, unknown>> | undefined;
  readonly orderingExtractorSha256?: Sha256Hex | undefined;
  readonly representationProfileId?: RepresentationProfileId | undefined;
  readonly representationProfileVersion?: bigint | undefined;
  readonly representationProfileBytes?: Uint8Array | undefined;
  readonly representationProfileSha256?: Sha256Hex | undefined;
  readonly consumerContractScope: string;
  readonly retryPolicyVersion: string;
  readonly maxAttempts: number;
  readonly reservedSlotBytes: bigint;
}

export interface FanoutEventContextRecord {
  readonly eventId: EventId;
  readonly tenantId: TenantId;
  readonly projectId: ProjectId;
  readonly eventTypeId: EventTypeId;
  readonly eventTypeName: EventTypeName;
  readonly eventSchemaVersion: number;
  readonly schemaProfileVersion: string;
  readonly schemaBytes: Uint8Array;
  readonly originalFactsSha256: Sha256Hex;
  readonly topologyVersion: bigint;
  readonly projectEventSequence: bigint;
  readonly contentBytes: Uint8Array;
  readonly contentSha256: Sha256Hex;
  readonly wireEnvelopeId: WireEnvelopeId;
  readonly wireEnvelopeSha256: Sha256Hex;
  readonly deliveryDeadlineAt: CanonicalUtcTimestamp;
  readonly admittedAt: CanonicalUtcTimestamp;
  readonly traceId?: string | undefined;
}

export interface FanoutOutcomeRecord {
  readonly subscriptionId: SubscriptionId;
  readonly subscriptionVersion: bigint;
  readonly outcome: "matched" | "filtered_out" | "blocked" | "failed";
  readonly filterProfileVersion: string;
  readonly filterSha256: Sha256Hex;
  readonly consumerContractScope: string;
  readonly reservedSlotBytesToRelease: bigint;
  readonly blockingReason?: string | undefined;
  readonly deliverySeed?: {
    readonly deliveryId: DeliveryId;
    readonly familyId: DeliveryFamilyId;
    readonly endpointId: EndpointId;
    readonly endpointVersion: bigint;
    readonly wireEnvelopeId: WireEnvelopeId;
    readonly derivedWireEnvelope?: {
      readonly bodyBytes: Uint8Array;
      readonly bodySha256: Sha256Hex;
      readonly representationProfileId: RepresentationProfileId;
      readonly representationProfileVersion: bigint;
      readonly provenance: ProjectionProvenanceRecord;
    } | undefined;
    readonly consumerEventKeySha256: Sha256Hex;
    readonly maxAttempts: number;
    readonly retryPolicyVersion: string;
    readonly ordering?: {
      readonly orderingDomainId: OrderingDomainId;
      readonly orderingKey: string;
      readonly orderingKeySha256: Sha256Hex;
      readonly orderingSequence: bigint;
    } | undefined;
  } | undefined;
}

export interface FanoutRepositoryPort<TTx> {
  readInstallationAuthority(tx: TTx): Promise<InstallationAuthoritySnapshot>;
  acceptBrokerInbox(
    tx: TTx,
    params: {
      readonly outboxId: OutboxId;
      readonly publicationGeneration: bigint;
      readonly eventId: EventId;
      readonly projectId: ProjectId;
      readonly topologyVersion: bigint;
      readonly envelopeSha256: Sha256Hex;
      readonly brokerGenerationId: BrokerGenerationId;
      readonly streamSequence: bigint;
      readonly inboxId: BrokerInboxId;
      readonly instanceId: RuntimeInstanceId;
      readonly controlEpoch: ControlEpoch;
      readonly now: CanonicalUtcTimestamp;
    }
  ): Promise<{
    readonly inboxId: BrokerInboxId;
    readonly inboxState: BrokerInboxState;
    readonly fanoutState: EventFanoutState;
    readonly projectEventSequence: bigint;
    readonly materializedThroughEventSequence: bigint;
    readonly isNextContiguous: boolean;
  }>;
  claimEventFanout(
    tx: TTx,
    params: {
      readonly eventId: EventId;
      readonly instanceId: RuntimeInstanceId;
      readonly controlEpoch: ControlEpoch;
      readonly claimLeaseMs: bigint;
      readonly now: CanonicalUtcTimestamp;
    }
  ): Promise<
    | { readonly outcome: "already_complete"; readonly eventId: EventId }
    | {
        readonly outcome: "claimed";
        readonly eventId: EventId;
        readonly topologyVersion: bigint;
        readonly subscriptionCursor?: SubscriptionId | undefined;
        readonly claimGeneration: bigint;
        readonly claimExpiresAt: CanonicalUtcTimestamp;
        readonly candidateCount: bigint;
        readonly examinedCount: bigint;
      }
  >;
  readEventForFanout(tx: TTx, eventId: EventId): Promise<FanoutEventContextRecord>;
  listActiveSubscriptionsPage(
    tx: TTx,
    params: {
      readonly tenantId: TenantId;
      readonly projectId: ProjectId;
      readonly eventTypeId: EventTypeId;
      readonly schemaVersion: number;
      readonly topologyVersion: bigint;
      readonly afterSubscriptionId?: SubscriptionId | undefined;
      readonly limit: number;
    }
  ): Promise<readonly SubscriptionCandidateRecord[]>;
  reserveOrderingSequence(
    tx: TTx,
    params: {
      readonly tenantId: TenantId;
      readonly projectId: ProjectId;
      readonly subscriptionId: SubscriptionId;
      readonly orderingDomainId: OrderingDomainId;
      readonly orderingKeySha256: Sha256Hex;
      readonly consumerContractScope: string;
    }
  ): Promise<{ readonly orderingSequence: bigint; readonly blockedHead: boolean }>;
  commitFanoutPage(
    tx: TTx,
    params: {
      readonly eventId: EventId;
      readonly instanceId: RuntimeInstanceId;
      readonly controlEpoch: ControlEpoch;
      readonly expectedClaimGeneration: bigint;
      readonly nextCursor?: SubscriptionId | null | undefined;
      readonly complete: boolean;
      readonly outcomes: readonly FanoutOutcomeRecord[];
      readonly now: CanonicalUtcTimestamp;
    }
  ): Promise<
    | { readonly outcome: "already_complete"; readonly eventId: EventId }
    | {
        readonly outcome: "completed" | "page_committed";
        readonly eventId: EventId;
        readonly newExamined: bigint;
        readonly newDeliveries: bigint;
        readonly materializedThroughEventSequence: bigint;
      }
  >;
}

// =============================================================================
// WDRR Dispatch, Rate Buckets & Circuit Breakers Port
// =============================================================================

export interface DispatchDomainRecord {
  readonly dispatchDomainId: string;
  readonly name: string;
  readonly state: "active" | "draining" | "paused";
  readonly policyKind: "wdrr_hierarchical_v1";
  readonly policyEpoch: bigint;
  readonly version: bigint;
}

export interface WdrrScopeState {
  readonly scopeKind: "tenant" | "project" | "endpoint";
  readonly scopeId: string;
  readonly weight: number;
  readonly deficitUnits: number;
  readonly policyEpoch: bigint;
  readonly lastServedAt?: CanonicalUtcTimestamp | undefined;
  readonly version: bigint;
}

export interface MicrotokenRateBucketRecord {
  readonly scopeKind: "tenant" | "project" | "endpoint";
  readonly scopeId: string;
  readonly policyVersion: bigint;
  readonly tokensMicro: bigint;
  readonly reservedMicro: bigint;
  readonly capacityMicro: bigint;
  readonly refillMicroPerSec: bigint;
  readonly remainderNumerator: bigint;
  readonly lastRefillAtUs: bigint;
  readonly enabled: boolean;
  readonly version: bigint;
}

export interface EndpointCircuitSnapshot {
  readonly endpointId: EndpointId;
  readonly endpointVersion: bigint;
  readonly state: CircuitState;
  readonly circuitGeneration: bigint;
  readonly consecutiveTransientFailures: number;
  readonly consecutivePermanentFailures?: number | undefined;
  readonly reopenCount: number;
  readonly reopenNotBefore?: CanonicalUtcTimestamp | undefined;
  readonly probeGeneration: bigint;
  readonly probeInFlightAttemptId?: AttemptId | null | undefined;
  readonly version: bigint;
}

export interface ReadyDeliveryCandidate {
  readonly deliveryId: DeliveryId;
  readonly familyId: DeliveryFamilyId;
  readonly tenantId: TenantId;
  readonly projectId: ProjectId;
  readonly endpointId: EndpointId;
  readonly endpointVersion: bigint;
  readonly state: DeliveryState;
  readonly attemptCount: number;
  readonly maximumAttempts: number;
  readonly nextEligibleAt?: CanonicalUtcTimestamp | undefined;
  readonly deadlineAt: CanonicalUtcTimestamp;
  readonly orderingSequence?: bigint | undefined;
  readonly orderingBlockedByGap?: boolean | undefined;
  readonly createdAt: CanonicalUtcTimestamp;
}

export interface DispatchClaimRequestRecord {
  readonly requestId: string;
  readonly dispatchDomainId: string;
  readonly workerInstanceId: RuntimeInstanceId;
  readonly controlEpoch: ControlEpoch;
  readonly maximumCount: number;
  readonly requestSha256: Sha256Hex;
  readonly state: "prepared" | "completed" | "failed";
  readonly assignments: readonly {
    readonly attemptId: AttemptId;
    readonly deliveryId: DeliveryId;
    readonly endpointId: EndpointId;
    readonly fencingToken: bigint;
    readonly isCircuitProbe: boolean;
    readonly claimExpiresAt: CanonicalUtcTimestamp;
  }[];
}

export interface PrepareDispatchAttemptInput {
  readonly requestId: string;
  readonly dispatchDomainId: string;
  readonly workerInstanceId: RuntimeInstanceId;
  readonly controlEpoch: ControlEpoch;
  readonly maximumCount: number;
  readonly requestSha256: Sha256Hex;
  readonly selections: readonly {
    readonly deliveryId: DeliveryId;
    readonly attemptId: AttemptId;
    readonly tenantId: TenantId;
    readonly projectId: ProjectId;
    readonly endpointId: EndpointId;
    readonly endpointVersion: bigint;
    readonly isCircuitProbe: boolean;
    readonly expectedCircuitGeneration: bigint;
    readonly expectedProbeGeneration?: bigint | undefined;
    readonly chargeFairnessUnits: number;
    readonly reserveMicrotokens: bigint;
    readonly updatedBuckets: readonly MicrotokenRateBucketRecord[];
  }[];
  readonly updatedDeficits: readonly WdrrScopeState[];
  readonly claimLeaseMs: bigint;
  readonly now: CanonicalUtcTimestamp;
}

export interface DispatchRepositoryPort<TTx> {
  readInstallationAuthority(tx: TTx): Promise<InstallationAuthoritySnapshot>;
  findDispatchClaimRequest(
    tx: TTx,
    requestId: string
  ): Promise<DispatchClaimRequestRecord | undefined>;
  listDispatchDomains(tx: TTx): Promise<readonly DispatchDomainRecord[]>;
  listWdrrTenantStates(
    tx: TTx,
    dispatchDomainId: string,
    limit: number
  ): Promise<readonly (WdrrScopeState & { readonly tenantId: TenantId })[]>;
  listWdrrProjectStates(
    tx: TTx,
    dispatchDomainId: string,
    tenantId: TenantId,
    limit: number
  ): Promise<readonly (WdrrScopeState & { readonly projectId: ProjectId })[]>;
  listWdrrEndpointStates(
    tx: TTx,
    dispatchDomainId: string,
    projectId: ProjectId,
    limit: number
  ): Promise<readonly (WdrrScopeState & { readonly endpointId: EndpointId })[]>;
  listDueDeliveriesForEndpoint(
    tx: TTx,
    projectId: ProjectId,
    endpointId: EndpointId,
    now: CanonicalUtcTimestamp,
    limit: number
  ): Promise<readonly ReadyDeliveryCandidate[]>;
  readRateBuckets(
    tx: TTx,
    scope: {
      readonly tenantId: TenantId;
      readonly projectId: ProjectId;
      readonly endpointId: EndpointId;
    }
  ): Promise<{
    readonly tenantBucket?: MicrotokenRateBucketRecord | undefined;
    readonly projectBucket?: MicrotokenRateBucketRecord | undefined;
    readonly endpointBucket: MicrotokenRateBucketRecord;
  }>;
  readEndpointCircuit(tx: TTx, endpointId: EndpointId): Promise<EndpointCircuitSnapshot>;
  readProjectConcurrencyUsage(
    tx: TTx,
    tenantId: TenantId,
    projectId: ProjectId
  ): Promise<{
    readonly activeAttemptSlots: number;
    readonly maxActiveAttemptSlots: number;
    readonly pendingDeliveries: bigint;
  }>;
  readEndpointConcurrencyUsage(
    tx: TTx,
    endpointId: EndpointId
  ): Promise<{
    readonly activeAttemptSlots: number;
    readonly maxInFlight: number;
    readonly state: EndpointState;
  }>;
  commitDispatchBatch(
    tx: TTx,
    input: PrepareDispatchAttemptInput
  ): Promise<DispatchClaimRequestRecord>;
}

// =============================================================================
// Delivery Execution & Verification Port
// =============================================================================

export interface DeliverySendContextRecord {
  readonly tenantId: TenantId;
  readonly projectId: ProjectId;
  readonly eventId: EventId;
  readonly subscriptionId: SubscriptionId;
  readonly subscriptionVersion: bigint;
  readonly deliveryId: DeliveryId;
  readonly deliveryGeneration: bigint;
  readonly deliveryState: DeliveryState;
  readonly deliveryDeadlineAt: CanonicalUtcTimestamp;
  readonly attemptId: AttemptId;
  readonly attemptNumber: number;
  readonly maximumAttempts: number;
  readonly attemptState: AttemptState;
  readonly fencingToken: bigint;
  readonly isCircuitProbe: boolean;
  readonly circuitGenerationAtPrepare: bigint;
  readonly endpointId: EndpointId;
  readonly endpointVersion: bigint;
  readonly endpointState: EndpointState;
  readonly destinationUrl: string;
  readonly signingPolicyVersion: PositiveInt64String;
  readonly signingKeys: readonly EndpointKeyMetadata[];
  readonly allowOverlapDualSign: boolean;
  readonly wireEnvelopeId: WireEnvelopeId;
  readonly wireBodyBytes: Uint8Array;
  readonly wireBodySha256: Sha256Hex;
  readonly originalFactsSha256: Sha256Hex;
  readonly consumerEventKeySha256: Sha256Hex;
  readonly consumerContractId: string;
  readonly consumerContractVersion: bigint;
  readonly consumerContractScope: string;
  readonly receiptRequired: boolean;
  readonly retryPolicyVersion: string;
  readonly ordering?: {
    readonly orderingDomainId: OrderingDomainId;
    readonly orderingKeySha256: Sha256Hex;
    readonly orderingSequence: PositiveInt64String;
  } | undefined;
  readonly traceparent?: string | undefined;
  readonly tracestate?: string | undefined;
}

export interface VerificationAttemptContextRecord {
  readonly tenantId: TenantId;
  readonly projectId: ProjectId;
  readonly endpointId: EndpointId;
  readonly endpointVersion: bigint;
  readonly endpointState: EndpointState;
  readonly configurationSha256: Sha256Hex;
  readonly destinationUrl: string;
  readonly verificationIntentId: EndpointVerificationIntentId;
  readonly intentExpiresAt: CanonicalUtcTimestamp;
  readonly publicNonce: string;
  readonly keyId: KeyId;
  readonly keyMetadata: EndpointKeyMetadata;
  readonly attemptId: EndpointVerificationAttemptId;
  readonly attemptState: "pending" | "claimed" | "verified" | "failed_transient" | "failed_permanent";
  readonly claimExpiresAt?: CanonicalUtcTimestamp | undefined;
}

export interface DeliveryExecutionRepositoryPort<TTx> {
  loadAttemptSendContext(tx: TTx, attemptId: AttemptId): Promise<DeliverySendContextRecord>;
  startDeliverySend(
    tx: TTx,
    params: {
      readonly attemptId: AttemptId;
      readonly workerInstanceId: RuntimeInstanceId;
      readonly controlEpoch: ControlEpoch;
      readonly expectedFencingToken: bigint;
      readonly networkBudgetMs: bigint;
      readonly now: CanonicalUtcTimestamp;
      readonly spendBuckets: readonly MicrotokenRateBucketRecord[];
    }
  ): Promise<{
    readonly shouldSend: boolean;
    readonly alreadyStarted: boolean;
    readonly abortReason?: string | undefined;
    readonly attemptId: AttemptId;
    readonly requestDeadlineAt: CanonicalUtcTimestamp;
    readonly acceptedAt: CanonicalUtcTimestamp;
  }>;
  deferUnstartedAttempt(
    tx: TTx,
    params: {
      readonly attemptId: AttemptId;
      readonly workerInstanceId: RuntimeInstanceId;
      readonly controlEpoch: ControlEpoch;
      readonly expectedFencingToken: bigint;
      readonly reasonCode: string;
      readonly nextEligibleAt?: CanonicalUtcTimestamp | undefined;
      readonly releaseBuckets: readonly MicrotokenRateBucketRecord[];
      readonly now: CanonicalUtcTimestamp;
    }
  ): Promise<{ readonly deferred: boolean }>;
  recordEgressDecision(
    tx: TTx,
    params: {
      readonly decisionId: string;
      readonly tenantId: TenantId;
      readonly projectId: ProjectId;
      readonly endpointId: EndpointId;
      readonly endpointVersion: bigint;
      readonly deliveryAttemptId?: AttemptId | null | undefined;
      readonly verificationAttemptId?: EndpointVerificationAttemptId | null | undefined;
      readonly runtimeInstanceId: RuntimeInstanceId;
      readonly controlEpoch: ControlEpoch;
      readonly networkPolicyVersion: string;
      readonly registryIpv4Sha256: Sha256Hex;
      readonly registryIpv6Sha256: Sha256Hex;
      readonly authoritySha256: Sha256Hex;
      readonly answerSetSha256?: Sha256Hex | null | undefined;
      readonly selectedAddressSha256?: Sha256Hex | null | undefined;
      readonly selectedFamily?: 4 | 6 | null | undefined;
      readonly peerAddressSha256?: Sha256Hex | null | undefined;
      readonly decision: "allow" | "deny";
      readonly reasonCode: string;
      readonly expiresAt: CanonicalUtcTimestamp;
      readonly now: CanonicalUtcTimestamp;
    }
  ): Promise<void>;
  finalizeDeliveryAttempt(
    tx: TTx,
    params: {
      readonly attemptId: AttemptId;
      readonly workerInstanceId: RuntimeInstanceId;
      readonly controlEpoch: ControlEpoch;
      readonly expectedFencingToken: bigint;
      readonly attemptState: AttemptState;
      readonly outcomeClass: DeliveryOutcomeClass;
      readonly responseStatus?: number | null | undefined;
      readonly responseBodySha256?: Sha256Hex | null | undefined;
      readonly responseByteCount?: number | null | undefined;
      readonly safeErrorCode?: string | null | undefined;
      readonly retryDecision?: RetryDecisionOutcome | null | undefined;
      readonly retryReasonCode?: string | null | undefined;
      readonly retryPolicyVersion?: string | null | undefined;
      readonly selectedDelayMs?: bigint | null | undefined;
      readonly selectedBackoffMs?: bigint | null | undefined;
      readonly retryAfterParseClass?: string | null | undefined;
      readonly retryAfterMs?: bigint | null | undefined;
      readonly nextEligibleAt?: CanonicalUtcTimestamp | null | undefined;
      readonly now: CanonicalUtcTimestamp;
    }
  ): Promise<{
    readonly outcome: "already_finalized" | "finalized";
    readonly attemptId: AttemptId;
    readonly attemptState: AttemptState;
    readonly deliveryState: DeliveryState;
  }>;
  updateEndpointCircuit(
    tx: TTx,
    params: {
      readonly endpointId: EndpointId;
      readonly observedGeneration: bigint;
      readonly isCircuitProbe: boolean;
      readonly attemptId: AttemptId;
      readonly outcomeClass: DeliveryOutcomeClass;
      readonly now: CanonicalUtcTimestamp;
    }
  ): Promise<EndpointCircuitSnapshot>;
  observeReceiverReceipt(
    tx: TTx,
    params: {
      readonly observationId: ReceiverReceiptObservationId;
      readonly deliveryId: DeliveryId;
      readonly attemptId: AttemptId;
      readonly receiptReference: string;
      readonly receiptFactsSha256: Sha256Hex;
      readonly requestWireSha256: Sha256Hex;
      readonly proofSha256: Sha256Hex;
      readonly keyId: KeyId;
      readonly receiverContractId: string;
      readonly receiverContractVersion: bigint;
      readonly receiptFacts: Readonly<Record<string, unknown>>;
      readonly verificationProfileVersion: string;
      readonly sourceKind: string;
      readonly recordedBy: string;
      readonly state: "verified" | "conflicting" | "rejected";
      readonly safeReason?: string | undefined;
      readonly now: CanonicalUtcTimestamp;
    }
  ): Promise<{ readonly recorded: boolean; readonly state: "verified" | "conflicting" | "rejected" }>;
  observeLateDelivery(
    tx: TTx,
    params: {
      readonly observationId: LateObservationId;
      readonly deliveryId: DeliveryId;
      readonly attemptId: AttemptId;
      readonly sourceInstanceId: RuntimeInstanceId;
      readonly observationKeySha256: Sha256Hex;
      readonly factsSha256: Sha256Hex;
      readonly observationKind: string;
      readonly safeFacts: Readonly<Record<string, unknown>>;
      readonly now: CanonicalUtcTimestamp;
    }
  ): Promise<void>;
  loadVerificationAttemptContext(
    tx: TTx,
    attemptId: EndpointVerificationAttemptId
  ): Promise<VerificationAttemptContextRecord>;
  claimVerificationAttempt(
    tx: TTx,
    params: {
      readonly intentId: EndpointVerificationIntentId;
      readonly attemptId: EndpointVerificationAttemptId;
      readonly instanceId: RuntimeInstanceId;
      readonly controlEpoch: ControlEpoch;
      readonly claimLeaseMs: bigint;
      readonly now: CanonicalUtcTimestamp;
    }
  ): Promise<{ readonly claimed: boolean }>;
  finalizeVerificationAttempt(
    tx: TTx,
    params: {
      readonly attemptId: EndpointVerificationAttemptId;
      readonly instanceId: RuntimeInstanceId;
      readonly controlEpoch: ControlEpoch;
      readonly outcome: "verified" | "failed_transient" | "failed_permanent";
      readonly responseStatus?: number | null | undefined;
      readonly proofSha256?: Sha256Hex | null | undefined;
      readonly networkPolicyVersion: string;
      readonly safeReasonCode?: string | null | undefined;
      readonly eventId: string;
      readonly now: CanonicalUtcTimestamp;
    }
  ): Promise<void>;
}

// =============================================================================
// Topology & Config Lifecycle Port
// =============================================================================

export interface EndpointRecord {
  readonly endpointId: EndpointId;
  readonly tenantId: TenantId;
  readonly projectId: ProjectId;
  readonly version: bigint;
  readonly endpointVersion: bigint;
  readonly state: EndpointState;
  readonly destinationUrl: string;
  readonly configurationSha256: Sha256Hex;
  readonly signingPolicyVersion: bigint;
  readonly signatureMode: SignatureMode;
  readonly currentSigningKeyId?: KeyId | undefined;
  readonly previousSigningKeyId?: KeyId | undefined;
  readonly maxInFlight: number;
  readonly rateLimitPerSec: number;
  readonly rateBurst: number;
}

export interface SigningKeyCustodyIntentRecord {
  readonly intentId: SigningDeliveryIntentId;
  readonly endpointId: EndpointId;
  readonly projectId: ProjectId;
  readonly keyId: KeyId;
  readonly keyVersionId: SigningKeyVersionId;
  readonly keyVersion: bigint;
  readonly state: "created" | "delivered_to_custody" | "activated" | "expired" | "revoked";
  readonly custodyKind: string;
  readonly deliveryChannel: string;
  readonly secretSha256: Sha256Hex;
  readonly expiresAt: CanonicalUtcTimestamp;
}

export interface RatePolicyDrainRecord {
  readonly endpointId: EndpointId;
  readonly pendingPolicyVersion: bigint;
  readonly targetCapacityMicro: bigint;
  readonly targetRefillMicroPerSec: bigint;
  readonly drainNotBefore: CanonicalUtcTimestamp;
  readonly state: "pending_drain" | "activated" | "cancelled";
}

export interface TopologyCommandResult<TResource = Record<string, unknown>> {
  readonly outcome: "applied" | "idempotent_recovery";
  readonly resourceId: string;
  readonly version: bigint;
  readonly commandSha256: Sha256Hex;
  readonly effectiveSha256: Sha256Hex;
  readonly receiptId: CommandReceiptId;
  readonly data: TResource;
}

export interface TopologyRepositoryPort<TTx> {
  getTenant(tx: TTx, tenantId: TenantId): Promise<TenantAuthoritySnapshot | undefined>;
  createTenant(
    tx: TTx,
    params: {
      readonly tenantId: TenantId;
      readonly slug: string;
      readonly displayName: string;
      readonly actorPrincipalId: PrincipalId;
      readonly receiptId: CommandReceiptId;
      readonly idempotencyKeySha256: Sha256Hex;
      readonly commandSha256: Sha256Hex;
      readonly effectiveSha256: Sha256Hex;
      readonly now: CanonicalUtcTimestamp;
    }
  ): Promise<TopologyCommandResult<TenantAuthoritySnapshot>>;
  transitionTenantState(
    tx: TTx,
    params: {
      readonly tenantId: TenantId;
      readonly expectedVersion: bigint;
      readonly nextState: TenantState;
      readonly actorPrincipalId: PrincipalId;
      readonly receiptId: CommandReceiptId;
      readonly idempotencyKeySha256: Sha256Hex;
      readonly commandSha256: Sha256Hex;
      readonly effectiveSha256: Sha256Hex;
      readonly now: CanonicalUtcTimestamp;
    }
  ): Promise<TopologyCommandResult<TenantAuthoritySnapshot>>;
  getProject(
    tx: TTx,
    tenantId: TenantId,
    projectId: ProjectId
  ): Promise<ProjectAuthoritySnapshot | undefined>;
  createProject(
    tx: TTx,
    params: {
      readonly tenantId: TenantId;
      readonly projectId: ProjectId;
      readonly name: string;
      readonly defaultDeliveryWindowMs: bigint;
      readonly maxDeliveryWindowMs: bigint;
      readonly actorPrincipalId: PrincipalId;
      readonly receiptId: CommandReceiptId;
      readonly idempotencyKeySha256: Sha256Hex;
      readonly commandSha256: Sha256Hex;
      readonly effectiveSha256: Sha256Hex;
      readonly now: CanonicalUtcTimestamp;
    }
  ): Promise<TopologyCommandResult<ProjectAuthoritySnapshot>>;
  transitionProjectState(
    tx: TTx,
    params: {
      readonly tenantId: TenantId;
      readonly projectId: ProjectId;
      readonly expectedVersion: bigint;
      readonly nextState: ProjectState;
      readonly actorPrincipalId: PrincipalId;
      readonly receiptId: CommandReceiptId;
      readonly idempotencyKeySha256: Sha256Hex;
      readonly commandSha256: Sha256Hex;
      readonly effectiveSha256: Sha256Hex;
      readonly reasonCode?: string | undefined;
      readonly now: CanonicalUtcTimestamp;
    }
  ): Promise<TopologyCommandResult<ProjectAuthoritySnapshot>>;
  getEndpoint(
    tx: TTx,
    tenantId: TenantId,
    projectId: ProjectId,
    endpointId: EndpointId
  ): Promise<EndpointRecord | undefined>;
  registerEndpoint(
    tx: TTx,
    params: {
      readonly tenantId: TenantId;
      readonly projectId: ProjectId;
      readonly endpointId: EndpointId;
      readonly destinationUrl: string;
      readonly configurationSha256: Sha256Hex;
      readonly maxInFlight: number;
      readonly rateLimitPerSec: number;
      readonly rateBurst: number;
      readonly keyId: KeyId;
      readonly keyVersionId: SigningKeyVersionId;
      readonly custodyIntentId: SigningDeliveryIntentId;
      readonly actorPrincipalId: PrincipalId;
      readonly receiptId: CommandReceiptId;
      readonly idempotencyKeySha256: Sha256Hex;
      readonly commandSha256: Sha256Hex;
      readonly effectiveSha256: Sha256Hex;
      readonly now: CanonicalUtcTimestamp;
    }
  ): Promise<TopologyCommandResult<EndpointRecord>>;
  transitionEndpoint(
    tx: TTx,
    params: {
      readonly tenantId: TenantId;
      readonly projectId: ProjectId;
      readonly endpointId: EndpointId;
      readonly expectedVersion: bigint;
      readonly nextState: EndpointState;
      readonly reasonCode?: string | undefined;
      readonly verificationIntentId?: EndpointVerificationIntentId | undefined;
      readonly verificationAttemptId?: EndpointVerificationAttemptId | undefined;
      readonly publicNonce?: string | undefined;
      readonly intentExpiresAt?: CanonicalUtcTimestamp | undefined;
      readonly actorPrincipalId: PrincipalId;
      readonly receiptId: CommandReceiptId;
      readonly idempotencyKeySha256: Sha256Hex;
      readonly commandSha256: Sha256Hex;
      readonly effectiveSha256: Sha256Hex;
      readonly now: CanonicalUtcTimestamp;
    }
  ): Promise<TopologyCommandResult<EndpointRecord>>;
  getSigningKeyCustodyIntent(
    tx: TTx,
    intentId: SigningDeliveryIntentId
  ): Promise<SigningKeyCustodyIntentRecord | undefined>;
  listEndpointSigningKeys(
    tx: TTx,
    endpointId: EndpointId
  ): Promise<readonly EndpointKeyMetadata[]>;
  updateSigningKeyCustodyAndPolicy(
    tx: TTx,
    params: {
      readonly tenantId: TenantId;
      readonly projectId: ProjectId;
      readonly endpointId: EndpointId;
      readonly expectedEndpointVersion: bigint;
      readonly action: "deliver_custody" | "activate_key" | "rotate_key" | "revoke_key";
      readonly intentId?: SigningDeliveryIntentId | undefined;
      readonly newKeyId?: KeyId | undefined;
      readonly newKeyVersionId?: SigningKeyVersionId | undefined;
      readonly signatureMode?: SignatureMode | undefined;
      readonly overlapUntil?: CanonicalUtcTimestamp | undefined;
      readonly verifyUntil?: CanonicalUtcTimestamp | undefined;
      readonly actorPrincipalId: PrincipalId;
      readonly receiptId: CommandReceiptId;
      readonly idempotencyKeySha256: Sha256Hex;
      readonly commandSha256: Sha256Hex;
      readonly effectiveSha256: Sha256Hex;
      readonly now: CanonicalUtcTimestamp;
    }
  ): Promise<TopologyCommandResult<{ readonly signingPolicyVersion: bigint }>>;
  registerEventSchema(
    tx: TTx,
    params: {
      readonly tenantId: TenantId;
      readonly projectId: ProjectId;
      readonly eventTypeId: EventTypeId;
      readonly eventTypeName: EventTypeName;
      readonly schemaVersion: number;
      readonly schemaBytes: Uint8Array;
      readonly schemaSha256: Sha256Hex;
      readonly targetState: "draft" | "active" | "deprecated";
      readonly actorPrincipalId: PrincipalId;
      readonly receiptId: CommandReceiptId;
      readonly idempotencyKeySha256: Sha256Hex;
      readonly commandSha256: Sha256Hex;
      readonly effectiveSha256: Sha256Hex;
      readonly now: CanonicalUtcTimestamp;
    }
  ): Promise<TopologyCommandResult<EventSchemaDefinitionRecord>>;
  upsertSubscriptionWithTopologyBump(
    tx: TTx,
    params: {
      readonly tenantId: TenantId;
      readonly projectId: ProjectId;
      readonly subscriptionId: SubscriptionId;
      readonly expectedVersion?: bigint | undefined;
      readonly endpointId: EndpointId;
      readonly eventTypeId: EventTypeId;
      readonly schemaVersions: readonly number[];
      readonly filterAst: Readonly<Record<string, unknown>>;
      readonly filterSha256: Sha256Hex;
      readonly orderingMode: OrderingMode;
      readonly orderingDomainId?: OrderingDomainId | undefined;
      readonly consumerContractScope: string;
      readonly retryPolicyVersion: string;
      readonly controlAction?: "activate" | "pause" | "resume" | "drain" | "disable" | undefined;
      readonly actorPrincipalId: PrincipalId;
      readonly receiptId: CommandReceiptId;
      readonly idempotencyKeySha256: Sha256Hex;
      readonly commandSha256: Sha256Hex;
      readonly effectiveSha256: Sha256Hex;
      readonly now: CanonicalUtcTimestamp;
    }
  ): Promise<TopologyCommandResult<{ readonly topologyVersion: bigint; readonly subscriptionVersion: bigint }>>;
  registerRepresentationProfile(
    tx: TTx,
    params: {
      readonly tenantId: TenantId;
      readonly projectId: ProjectId;
      readonly profileId: RepresentationProfileId;
      readonly profileVersion: bigint;
      readonly eventTypeId: EventTypeId;
      readonly sourceSchemaVersion: number;
      readonly targetSchemaVersion: number;
      readonly profileBytes: Uint8Array;
      readonly profileSha256: Sha256Hex;
      readonly activate: boolean;
      readonly actorPrincipalId: PrincipalId;
      readonly receiptId: CommandReceiptId;
      readonly idempotencyKeySha256: Sha256Hex;
      readonly commandSha256: Sha256Hex;
      readonly effectiveSha256: Sha256Hex;
      readonly now: CanonicalUtcTimestamp;
    }
  ): Promise<TopologyCommandResult<{ readonly profileId: RepresentationProfileId; readonly profileVersion: bigint }>>;
  scheduleOrActivateRatePolicyDrain(
    tx: TTx,
    params: {
      readonly tenantId: TenantId;
      readonly projectId: ProjectId;
      readonly endpointId: EndpointId;
      readonly pendingPolicyVersion: bigint;
      readonly targetCapacityMicro: bigint;
      readonly targetRefillMicroPerSec: bigint;
      readonly drainNotBefore: CanonicalUtcTimestamp;
      readonly actorPrincipalId: PrincipalId;
      readonly receiptId: CommandReceiptId;
      readonly commandSha256: Sha256Hex;
      readonly effectiveSha256: Sha256Hex;
      readonly now: CanonicalUtcTimestamp;
    }
  ): Promise<TopologyCommandResult<RatePolicyDrainRecord>>;
  bumpDispatchDomainEpoch(
    tx: TTx,
    params: {
      readonly dispatchDomainId: string;
      readonly expectedVersion: bigint;
      readonly actorPrincipalId: PrincipalId;
      readonly receiptId: CommandReceiptId;
      readonly commandSha256: Sha256Hex;
      readonly effectiveSha256: Sha256Hex;
      readonly now: CanonicalUtcTimestamp;
    }
  ): Promise<TopologyCommandResult<DispatchDomainRecord>>;
}

// =============================================================================
// Governance, Replay, Ordering, Maintenance & Evidence Ports
// =============================================================================

export interface AuthRepositoriesBundle {
  readonly producerCredentials: ProducerCredentialRepository;
  readonly humanAuthorization: GovernanceRepository;
  readonly sessions: HumanSessionRepository;
  readonly stepUp: OperationProofRepository;
  readonly enrollment: EnrollmentIntentRepository;
  readonly challenges?: AuthChallengeRepository | undefined;
  readonly preauth?: PreauthContextRepository | undefined;
  readonly passkeys?: PasskeyRepository | undefined;
}

export interface LosslessPayloadViewRecord {
  readonly eventId: EventId;
  readonly payloadId: EventPayloadId;
  readonly retentionState: string;
  readonly contentSha256: Sha256Hex;
  readonly byteCount: number;
  readonly contentBytes?: Uint8Array | undefined;
}

export interface GovernanceRepositoryPort<TTx> {
  listDataGrants(
    tx: TTx,
    tenantId: TenantId,
    projectId: ProjectId,
    principalId: PrincipalId,
    now: CanonicalUtcTimestamp
  ): Promise<readonly DataGrantProjection[]>;
  grantProjectDataAccess(
    tx: TTx,
    params: {
      readonly grantId: DataGrantId;
      readonly tenantId: TenantId;
      readonly projectId: ProjectId;
      readonly granteePrincipalId: PrincipalId;
      readonly grantedByPrincipalId: PrincipalId;
      readonly allowedActions: readonly DataGrantAction[];
      readonly ticketReference: string;
      readonly expiresAt: CanonicalUtcTimestamp;
      readonly now: CanonicalUtcTimestamp;
    }
  ): Promise<DataGrantProjection>;
  readEventContentLossless(
    tx: TTx,
    tenantId: TenantId,
    projectId: ProjectId,
    eventId: EventId
  ): Promise<LosslessPayloadViewRecord | undefined>;
}

export interface ReplayProposalRecord {
  readonly proposalId: ReplayProposalId;
  readonly deliveryId: DeliveryId;
  readonly eventId: EventId;
  readonly tenantId: TenantId;
  readonly projectId: ProjectId;
  readonly proposerPrincipalId: PrincipalId;
  readonly targetSubscriptionVersion: bigint;
  readonly targetEndpointVersion: bigint;
  readonly wireEnvelopeId: WireEnvelopeId;
  readonly strategy: "replay_exact_original" | "replay_with_reviewed_representation";
  readonly orderingStrategy: OrderingMode;
  readonly representationProfileId: string;
  readonly representationProfileVersion: bigint;
  readonly consumerEventKeySha256: Sha256Hex;
  readonly candidateSha256: Sha256Hex;
  readonly state: "proposed" | "approved" | "rejected" | "admitted" | "cancelled";
  readonly reviewId?: string | undefined;
  readonly reviewerPrincipalId?: PrincipalId | undefined;
  readonly reviewerAuthorityVersion?: bigint | undefined;
  readonly version: bigint;
}

export interface ReplayProposalRepositoryPort<TTx> {
  readDeliveryForReplay(
    tx: TTx,
    tenantId: TenantId,
    projectId: ProjectId,
    deliveryId: DeliveryId
  ): Promise<{
    readonly deliveryId: DeliveryId;
    readonly familyId: DeliveryFamilyId;
    readonly eventId: EventId;
    readonly state: DeliveryState;
    readonly deliveryGeneration: bigint;
    readonly subscriptionId: SubscriptionId;
    readonly subscriptionVersion: bigint;
    readonly endpointId: EndpointId;
    readonly endpointVersion: bigint;
    readonly originalWireEnvelopeId: WireEnvelopeId;
    readonly orderingMode: OrderingMode;
    readonly consumerEventKeySha256: Sha256Hex;
    readonly version: bigint;
  }>;
  findProposal(tx: TTx, proposalId: ReplayProposalId): Promise<ReplayProposalRecord | undefined>;
  createReplayProposal(
    tx: TTx,
    params: {
      readonly proposalId: ReplayProposalId;
      readonly deliveryId: DeliveryId;
      readonly proposerPrincipalId: PrincipalId;
      readonly expectedDeliveryVersion: bigint;
      readonly targetSubscriptionVersion: bigint;
      readonly targetEndpointVersion: bigint;
      readonly wireEnvelopeId: WireEnvelopeId;
      readonly strategy: "replay_exact_original" | "replay_with_reviewed_representation";
      readonly orderingStrategy: OrderingMode;
      readonly representationProfileId: string;
      readonly representationProfileVersion: bigint;
      readonly receiverContractId?: string | null | undefined;
      readonly receiverContractVersion?: bigint | null | undefined;
      readonly consumerEventKeySha256: Sha256Hex;
      readonly candidateSha256: Sha256Hex;
      readonly requestedDeadlineAt: CanonicalUtcTimestamp;
      readonly now: CanonicalUtcTimestamp;
    }
  ): Promise<ReplayProposalRecord>;
  reviewReplayProposal(
    tx: TTx,
    params: {
      readonly reviewId: string;
      readonly proposalId: ReplayProposalId;
      readonly expectedProposalVersion: bigint;
      readonly candidateSha256: Sha256Hex;
      readonly reviewerPrincipalId: PrincipalId;
      readonly reviewerAuthorityVersion: bigint;
      readonly decision: "approve" | "reject";
      readonly now: CanonicalUtcTimestamp;
    }
  ): Promise<ReplayProposalRecord>;
  admitReplayProposal(
    tx: TTx,
    params: {
      readonly proposalId: ReplayProposalId;
      readonly expectedProposalVersion: bigint;
      readonly candidateSha256: Sha256Hex;
      readonly reviewId: string;
      readonly actorPrincipalId: PrincipalId;
      readonly newDeliveryId: DeliveryId;
      readonly receiptId: CommandReceiptId;
      readonly idempotencyKeySha256: Sha256Hex;
      readonly now: CanonicalUtcTimestamp;
    }
  ): Promise<{
    readonly newDeliveryId: DeliveryId;
    readonly deliveryGeneration: bigint;
    readonly receiptId: CommandReceiptId;
  }>;
  proposeAndReviewSuppression(
    tx: TTx,
    params: {
      readonly mode: "propose" | "review" | "admit";
      readonly proposalId: string;
      readonly deliveryId: DeliveryId;
      readonly actorPrincipalId: PrincipalId;
      readonly reviewId?: string | undefined;
      readonly decision?: "approve" | "reject" | undefined;
      readonly reasonCode?: string | undefined;
      readonly receiptId?: CommandReceiptId | undefined;
      readonly idempotencyKeySha256?: Sha256Hex | undefined;
      readonly now: CanonicalUtcTimestamp;
    }
  ): Promise<{
    readonly proposalId: string;
    readonly state: string;
    readonly proposerPrincipalId: PrincipalId;
    readonly reviewerPrincipalId?: PrincipalId | undefined;
  }>;
}

export interface OrderingGapRecord {
  readonly tenantId: TenantId;
  readonly projectId: ProjectId;
  readonly orderingDomainId: OrderingDomainId;
  readonly subscriptionId: SubscriptionId;
  readonly orderingKeySha256: Sha256Hex;
  readonly consumerContractScope: string;
  readonly headThroughSequence: bigint;
  readonly blockedSequence: bigint;
  readonly gapReasonCode: string;
}

export interface OrderingCutoverPlanRecord {
  readonly planId: OrderingCutoverPlanId;
  readonly tenantId: TenantId;
  readonly projectId: ProjectId;
  readonly subscriptionId: SubscriptionId;
  readonly fromExtractorVersion: string;
  readonly toExtractorVersion: string;
  readonly state: OrderingCutoverPlanState;
  readonly cutoverTopologyVersion?: bigint | undefined;
  readonly outstandingInFlightBeforeBarrier: number;
  readonly version: bigint;
}

export interface OrderingRepositoryPort<TTx> {
  listOrderingGaps(
    tx: TTx,
    tenantId: TenantId,
    projectId: ProjectId,
    limit: number
  ): Promise<readonly OrderingGapRecord[]>;
  applyOrderSkipDisposition(
    tx: TTx,
    params: {
      readonly proposalId: string;
      readonly reviewId: string;
      readonly actorPrincipalId: PrincipalId;
      readonly dispositionId: string;
      readonly receiptId: CommandReceiptId;
      readonly idempotencyKeySha256: Sha256Hex;
      readonly orderingDomainId: OrderingDomainId;
      readonly orderingKeySha256: Sha256Hex;
      readonly blockedSequence: bigint;
      readonly now: CanonicalUtcTimestamp;
    }
  ): Promise<{
    readonly dispositionId: string;
    readonly newHeadSequence: bigint;
  }>;
  createOrderSkipProposal(
    tx: TTx,
    params: {
      readonly proposalId: string;
      readonly proposerPrincipalId: PrincipalId;
      readonly orderingDomainId: OrderingDomainId;
      readonly orderingKeySha256: Sha256Hex;
      readonly blockedSequence: bigint;
      readonly reasonCode: string;
      readonly now: CanonicalUtcTimestamp;
    }
  ): Promise<{ readonly proposalId: string; readonly state: string; readonly proposerPrincipalId: PrincipalId }>;
  reviewOrderSkipProposal(
    tx: TTx,
    params: {
      readonly proposalId: string;
      readonly reviewId: string;
      readonly reviewerPrincipalId: PrincipalId;
      readonly decision: "approve" | "reject";
      readonly now: CanonicalUtcTimestamp;
    }
  ): Promise<{
    readonly proposalId: string;
    readonly state: string;
    readonly proposerPrincipalId: PrincipalId;
    readonly reviewerPrincipalId: PrincipalId;
  }>;
  appendMissingOrderedDelivery(
    tx: TTx,
    params: {
      readonly tenantId: TenantId;
      readonly projectId: ProjectId;
      readonly orderingDomainId: OrderingDomainId;
      readonly orderingKeySha256: Sha256Hex;
      readonly missingSequence: bigint;
      readonly newDeliveryId: DeliveryId;
      readonly actorPrincipalId: PrincipalId;
      readonly now: CanonicalUtcTimestamp;
    }
  ): Promise<{ readonly appendedDeliveryId: DeliveryId; readonly sequence: bigint }>;
  getCutoverPlan(tx: TTx, planId: OrderingCutoverPlanId): Promise<OrderingCutoverPlanRecord | undefined>;
  saveCutoverPlan(
    tx: TTx,
    plan: OrderingCutoverPlanRecord,
    expectedVersion?: bigint
  ): Promise<OrderingCutoverPlanRecord>;
  countActiveInFlightForSubscription(
    tx: TTx,
    subscriptionId: SubscriptionId,
    throughTopologyVersion: bigint
  ): Promise<number>;
}

export interface WatchLeaseRecord {
  readonly leaseId: WatchLeaseId;
  readonly tenantId: TenantId;
  readonly projectId: ProjectId;
  readonly principalId: PrincipalId;
  readonly actorKind: ActorKind;
  readonly resourceKind: WatchResourceKind;
  readonly resourceId: string;
  readonly state: "active" | "closed" | "expired";
  readonly expiresAt: CanonicalUtcTimestamp;
  readonly streamCutoffAt: CanonicalUtcTimestamp;
}

export interface RetentionHoldRecord {
  readonly id: RetentionHoldId;
  readonly tenantId: TenantId;
  readonly projectId?: ProjectId | undefined;
  readonly targetKind: string;
  readonly targetId: string;
  readonly reasonCode: string;
  readonly state: RetentionHoldState;
  readonly expiresAt?: CanonicalUtcTimestamp | undefined;
  readonly version: bigint;
}

export interface RetentionActionRecord {
  readonly actionId: RetentionActionId;
  readonly tenantId: TenantId;
  readonly projectId?: ProjectId | undefined;
  readonly targetKind: string;
  readonly targetId: string;
  readonly action: RetentionActionKind;
  readonly state: RetentionActionState;
  readonly claimGeneration: bigint;
  readonly nextAttemptAt: CanonicalUtcTimestamp;
  readonly version: bigint;
}

export interface ProjectProjectionDriftReport {
  readonly tenantId: TenantId;
  readonly projectId: ProjectId;
  readonly consistent: boolean;
  readonly stored: {
    readonly totalDeliveries: bigint;
    readonly pendingCount: bigint;
    readonly activeCount: bigint;
    readonly acknowledgedCount: bigint;
    readonly deadLetterCount: bigint;
    readonly suppressedCount: bigint;
    readonly expiredCount: bigint;
  };
  readonly computed: {
    readonly totalDeliveries: bigint;
    readonly pendingCount: bigint;
    readonly activeCount: bigint;
    readonly acknowledgedCount: bigint;
    readonly deadLetterCount: bigint;
    readonly suppressedCount: bigint;
    readonly expiredCount: bigint;
  };
}

export interface MaintenanceRepositoryPort<TTx> {
  promoteDueWork(
    tx: TTx,
    now: CanonicalUtcTimestamp,
    limit: number
  ): Promise<{ readonly promotedDeliveries: number; readonly promotedOutbox: number }>;
  reapExpiredCoordinatorWork(
    tx: TTx,
    params: {
      readonly instanceId: RuntimeInstanceId;
      readonly controlEpoch: ControlEpoch;
      readonly batchLimit: number;
      readonly now: CanonicalUtcTimestamp;
    }
  ): Promise<{
    readonly reapedAttempts: number;
    readonly reapedOutboxClaims: number;
    readonly reapedFanoutClaims: number;
    readonly reapedWatchLeases: number;
  }>;
  listUnknownPublicationOutbox(
    tx: TTx,
    now: CanonicalUtcTimestamp,
    limit: number
  ): Promise<readonly OutboxRowRecord[]>;
  markOutboxReviewRequired(
    tx: TTx,
    params: {
      readonly outboxId: OutboxId;
      readonly episodeId: PublicationRecoveryEpisodeId;
      readonly reasonCode: string;
      readonly now: CanonicalUtcTimestamp;
    }
  ): Promise<void>;
  listActiveRetentionHolds(
    tx: TTx,
    tenantId: TenantId,
    projectId?: ProjectId
  ): Promise<readonly RetentionHoldRecord[]>;
  listDueRetentionActions(tx: TTx, now: CanonicalUtcTimestamp, limit: number): Promise<readonly RetentionActionRecord[]>;
  claimRetentionAction(
    tx: TTx,
    params: {
      readonly actionId: RetentionActionId;
      readonly instanceId: RuntimeInstanceId;
      readonly controlEpoch: ControlEpoch;
      readonly claimLeaseMs: bigint;
      readonly now: CanonicalUtcTimestamp;
    }
  ): Promise<{ readonly claimed: boolean; readonly claimGeneration: bigint }>;
  finalizeRetentionAction(
    tx: TTx,
    params: {
      readonly actionId: RetentionActionId;
      readonly instanceId: RuntimeInstanceId;
      readonly controlEpoch: ControlEpoch;
      readonly claimGeneration: bigint;
      readonly now: CanonicalUtcTimestamp;
    }
  ): Promise<{ readonly outcome: "already_complete" | "completed"; readonly actionId: RetentionActionId }>;
  verifyProjectDeliveryProjection(
    tx: TTx,
    tenantId: TenantId,
    projectId: ProjectId
  ): Promise<ProjectProjectionDriftReport>;
  rebuildProjectDeliveryProjection(
    tx: TTx,
    tenantId: TenantId,
    projectId: ProjectId,
    now: CanonicalUtcTimestamp
  ): Promise<ProjectProjectionDriftReport>;
}

// =============================================================================
// Four Separate Evidence Boundaries Port
// =============================================================================

export interface AdmissionEvidenceRecord {
  readonly eventId: EventId;
  readonly admittedAt: CanonicalUtcTimestamp;
  readonly state: EventState;
  readonly contentSha256: Sha256Hex;
  readonly topologyVersion: bigint;
}

export interface BrokerPublicationEvidenceRecord {
  readonly outboxId: OutboxId;
  readonly publicationGeneration: bigint;
  readonly brokerMessageId: BrokerMessageId;
  readonly state: OutboxState;
  readonly brokerGenerationId?: BrokerGenerationId | undefined;
  readonly streamName?: string | undefined;
  readonly streamSequence?: bigint | undefined;
  readonly publishedAt?: CanonicalUtcTimestamp | undefined;
}

export interface HttpAttemptEvidenceRecord {
  readonly deliveryId: DeliveryId;
  readonly attemptId: AttemptId;
  readonly attemptNumber: number;
  readonly state: AttemptState;
  readonly outcomeClass?: DeliveryOutcomeClass | undefined;
  readonly responseStatus?: number | undefined;
  readonly httpAcknowledged: boolean;
  readonly acknowledgedAt?: CanonicalUtcTimestamp | undefined;
  readonly safeErrorCode?: string | undefined;
}

export interface VerifiedReceiptEvidenceRecord {
  readonly deliveryId: DeliveryId;
  readonly attemptId: AttemptId;
  readonly observationId: ReceiverReceiptObservationId;
  readonly receiptReference: string;
  readonly receiptFactsSha256: Sha256Hex;
  readonly requestWireSha256: Sha256Hex;
  readonly proofSha256: Sha256Hex;
  readonly state: "verified" | "conflicting" | "rejected";
  readonly committedAt?: CanonicalUtcTimestamp | undefined;
  readonly observedAt: CanonicalUtcTimestamp;
}

export interface EvidenceRepositoryPort<TTx> {
  readEventEvidence(
    tx: TTx,
    tenantId: TenantId,
    projectId: ProjectId,
    eventId: EventId
  ): Promise<{
    readonly admission?: AdmissionEvidenceRecord | undefined;
    readonly brokerPublication?: BrokerPublicationEvidenceRecord | undefined;
    readonly httpAttempts: readonly HttpAttemptEvidenceRecord[];
    readonly verifiedReceipts: readonly VerifiedReceiptEvidenceRecord[];
  }>;
  readDeliveryEvidence(
    tx: TTx,
    tenantId: TenantId,
    projectId: ProjectId,
    deliveryId: DeliveryId
  ): Promise<{
    readonly eventId: EventId;
    readonly admission?: AdmissionEvidenceRecord | undefined;
    readonly brokerPublication?: BrokerPublicationEvidenceRecord | undefined;
    readonly httpAttempts: readonly HttpAttemptEvidenceRecord[];
    readonly verifiedReceipts: readonly VerifiedReceiptEvidenceRecord[];
  }>;
}

// =============================================================================
// External Integration Ports (Adapters over @relayquill/* Siblings)
// =============================================================================

export interface BrokerPublishPort {
  readonly brokerGenerationId: BrokerGenerationId;
  readonly streamName: string;
  publish(input: BrokerPublishInput): Promise<BrokerPublishResult>;
}

export interface BrokerConsumePort {
  pullBatch(options?: BrokerPullOptions): Promise<readonly BrokerMessage[]>;
}

export interface SchemaEvaluatorPort {
  validateEvent(input: {
    readonly schemaBytes: Uint8Array;
    readonly profileVersion: string;
    readonly eventBytes: Uint8Array;
  }): Promise<{
    readonly valid: boolean;
    readonly diagnostics: readonly SchemaDiagnostic[];
    readonly byteCount: number;
    readonly sha256: Sha256Hex;
  }>;
  evaluateFilterAndExtract(input: {
    readonly schemaBytes: Uint8Array;
    readonly schemaProfileVersion: string;
    readonly eventBytes: Uint8Array;
    readonly filterProfileVersion: string;
    readonly filterAst: Readonly<Record<string, unknown>>;
    readonly orderingExtractorSpec?: Readonly<Record<string, unknown>> | undefined;
    readonly orderingDigestScope?: OrderingDigestScope | undefined;
  }): Promise<{
    readonly schemaValid: boolean;
    readonly diagnostics: readonly SchemaDiagnostic[];
    readonly matched: boolean;
    readonly ordering?: ExtractedOrderingKeyResult | undefined;
    readonly orderingErrorCode?: string | undefined;
  }>;
  executeProjection(input: {
    readonly profileBytes: Uint8Array;
    readonly sourceEventBytes: Uint8Array;
    readonly sourceSchemaBytes: Uint8Array;
    readonly sourceSchemaProfileVersion: string;
  }): Promise<{
    readonly derivedJson: string;
    readonly derivedBytes: Uint8Array;
    readonly derivedByteCount: number;
    readonly derivedContentSha256: Sha256Hex;
    readonly targetSchemaVersion: number;
    readonly provenance: ProjectionProvenanceRecord;
  }>;
}

export interface EgressResolverPort {
  resolve(url: string, options?: ResolveEgressOptions): Promise<EgressDecision>;
}

export interface EgressExecutorPort {
  execute(input: ExecutePinnedEgressInput): Promise<EgressExecutionResult>;
}

export interface WebhookSignerPort {
  signDelivery(input: SignWebhookDeliveryInput): Promise<SignedWebhookRequest>;
  signEndpointVerification(
    input: SignEndpointVerificationInput
  ): Promise<SignedWebhookRequest & { readonly bodyBytes: Uint8Array }>;
  verifyEndpointProof(input: VerifyEndpointProofResponseInput): EndpointProofVerificationResult;
  verifyReceiverReceipt(
    input: VerifyReceiverReceiptResponseInput
  ): Promise<VerifyReceiverReceiptResult>;
}

export interface WatchLeasePort<TTx> {
  countActiveLeasesForPrincipal(tx: TTx, principalId: PrincipalId): Promise<number>;
  openWatchLease(
    tx: TTx,
    params: {
      readonly leaseId: WatchLeaseId;
      readonly tenantId: TenantId;
      readonly projectId: ProjectId;
      readonly principalId: PrincipalId;
      readonly actorKind: ActorKind;
      readonly sessionId?: SessionId | null | undefined;
      readonly producerCredentialId?: ProducerCredentialId | null | undefined;
      readonly resourceKind: WatchResourceKind;
      readonly resourceId: string;
      readonly runtimeInstanceId: RuntimeInstanceId;
      readonly controlEpoch: ControlEpoch;
      readonly authCutoffAt: CanonicalUtcTimestamp;
      readonly streamCutoffAt: CanonicalUtcTimestamp;
      readonly expiresAt: CanonicalUtcTimestamp;
    }
  ): Promise<WatchLeaseRecord>;
  renewWatchLease(
    tx: TTx,
    leaseId: WatchLeaseId,
    controlEpoch: ControlEpoch,
    authCutoffAt: CanonicalUtcTimestamp,
    newExpiresAt: CanonicalUtcTimestamp
  ): Promise<WatchLeaseRecord>;
  closeWatchLease(tx: TTx, leaseId: WatchLeaseId): Promise<boolean>;
}
