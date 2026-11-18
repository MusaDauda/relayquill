import { ValidationDomainError } from "./errors.js";

declare const brandTag: unique symbol;

export type Brand<T, B extends string> = T & { readonly [brandTag]: B };

export type CanonicalUuid = Brand<string, "CanonicalUuid">;

const CANONICAL_UUID_INPUT_REGEX =
  /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;
const STRICT_LOWER_UUID_REGEX =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

export function isCanonicalUuid(value: unknown): value is CanonicalUuid {
  return typeof value === "string" && STRICT_LOWER_UUID_REGEX.test(value);
}

export function parseCanonicalUuid(value: unknown, fieldPath = "id"): CanonicalUuid {
  if (typeof value !== "string" || !CANONICAL_UUID_INPUT_REGEX.test(value)) {
    throw new ValidationDomainError({
      code: "INVALID_UUID",
      message: `Invalid UUID for ${fieldPath}`,
      fieldErrors: [{ path: fieldPath, code: "INVALID_UUID" }]
    });
  }
  return value.toLowerCase() as CanonicalUuid;
}

export function normalizeCanonicalUuid(value: string, fieldPath = "id"): CanonicalUuid {
  return parseCanonicalUuid(value, fieldPath);
}

interface UuidBrandCodec<T extends CanonicalUuid> {
  readonly parse: (value: unknown, fieldPath?: string) => T;
  readonly is: (value: unknown) => value is T;
}

function createUuidBrandCodec<T extends CanonicalUuid>(
  defaultFieldPath: string
): UuidBrandCodec<T> {
  return {
    parse: (value: unknown, fieldPath = defaultFieldPath): T =>
      parseCanonicalUuid(value, fieldPath) as T,
    is: (value: unknown): value is T => isCanonicalUuid(value)
  };
}

// Tenancy & Access IDs
export type TenantId = Brand<CanonicalUuid, "TenantId">;
export type ProjectId = Brand<CanonicalUuid, "ProjectId">;
export type PrincipalId = Brand<CanonicalUuid, "PrincipalId">;
export type SessionId = Brand<CanonicalUuid, "SessionId">;
export type AuthChallengeId = Brand<CanonicalUuid, "AuthChallengeId">;
export type PreauthContextId = Brand<CanonicalUuid, "PreauthContextId">;
export type EnrollmentIntentId = Brand<CanonicalUuid, "EnrollmentIntentId">;
export type OperationProofId = Brand<CanonicalUuid, "OperationProofId">;
export type TenantMembershipId = Brand<CanonicalUuid, "TenantMembershipId">;
export type ProjectMembershipId = Brand<CanonicalUuid, "ProjectMembershipId">;
export type DataGrantId = Brand<CanonicalUuid, "DataGrantId">;
export type PlatformRoleAssignmentId = Brand<CanonicalUuid, "PlatformRoleAssignmentId">;
export type ProducerId = Brand<CanonicalUuid, "ProducerId">;
export type ProducerCredentialId = Brand<CanonicalUuid, "ProducerCredentialId">;
export type ProducerCredentialIntentId = Brand<CanonicalUuid, "ProducerCredentialIntentId">;
export type ProducerScopeVersionId = Brand<CanonicalUuid, "ProducerScopeVersionId">;
export type RuntimeInstanceId = Brand<CanonicalUuid, "RuntimeInstanceId">;
export type AuditEventId = Brand<CanonicalUuid, "AuditEventId">;
export type LifecycleOperationId = Brand<CanonicalUuid, "LifecycleOperationId">;
export type WatchLeaseId = Brand<CanonicalUuid, "WatchLeaseId">;
export type ControlEpoch = Brand<CanonicalUuid, "ControlEpoch">;

// Events, Outbox & Fanout IDs
export type EventTypeId = Brand<CanonicalUuid, "EventTypeId">;
export type EventId = Brand<CanonicalUuid, "EventId">;
export type EventPayloadId = Brand<CanonicalUuid, "EventPayloadId">;
export type WireEnvelopeId = Brand<CanonicalUuid, "WireEnvelopeId">;
export type CommandReceiptId = Brand<CanonicalUuid, "CommandReceiptId">;
export type OutboxId = Brand<CanonicalUuid, "OutboxId">;
export type BrokerGenerationId = Brand<CanonicalUuid, "BrokerGenerationId">;
export type BrokerStreamGenerationId = Brand<CanonicalUuid, "BrokerStreamGenerationId">;
export type PublicationObservationId = Brand<CanonicalUuid, "PublicationObservationId">;
export type BrokerInboxId = Brand<CanonicalUuid, "BrokerInboxId">;
export type TransportRejectionId = Brand<CanonicalUuid, "TransportRejectionId">;
export type PublicationRecoveryEpisodeId = Brand<CanonicalUuid, "PublicationRecoveryEpisodeId">;

// Endpoints, Signing & Subscriptions IDs
export type EndpointId = Brand<CanonicalUuid, "EndpointId">;
export type EndpointVerificationIntentId = Brand<CanonicalUuid, "EndpointVerificationIntentId">;
export type EndpointVerificationAttemptId = Brand<CanonicalUuid, "EndpointVerificationAttemptId">;
export type EndpointVerificationEventId = Brand<CanonicalUuid, "EndpointVerificationEventId">;
export type EndpointDispatchGrantId = Brand<CanonicalUuid, "EndpointDispatchGrantId">;
export type EndpointCircuitId = Brand<CanonicalUuid, "EndpointCircuitId">;
export type SigningKeyVersionId = Brand<CanonicalUuid, "SigningKeyVersionId">;
export type SigningDeliveryIntentId = Brand<CanonicalUuid, "SigningDeliveryIntentId">;
export type SigningPolicyId = Brand<CanonicalUuid, "SigningPolicyId">;
export type SubscriptionId = Brand<CanonicalUuid, "SubscriptionId">;
export type SubscriptionVersionId = Brand<CanonicalUuid, "SubscriptionVersionId">;
export type SubscriptionControlEventId = Brand<CanonicalUuid, "SubscriptionControlEventId">;
export type SubscriptionTopologyRangeId = Brand<CanonicalUuid, "SubscriptionTopologyRangeId">;
export type RepresentationProfileId = Brand<CanonicalUuid, "RepresentationProfileId">;
export type ReceiverContractId = Brand<CanonicalUuid, "ReceiverContractId">;

// Deliveries, Ordering, Replay & Capacity IDs
export type DeliveryFamilyId = Brand<CanonicalUuid, "DeliveryFamilyId">;
export type DeliveryId = Brand<CanonicalUuid, "DeliveryId">;
export type AttemptId = Brand<CanonicalUuid, "AttemptId">;
export type RetryDecisionId = Brand<CanonicalUuid, "RetryDecisionId">;
export type LateObservationId = Brand<CanonicalUuid, "LateObservationId">;
export type CircuitProbeRequestId = Brand<CanonicalUuid, "CircuitProbeRequestId">;
export type OrderingDomainId = Brand<CanonicalUuid, "OrderingDomainId">;
export type OrderingKeyId = Brand<CanonicalUuid, "OrderingKeyId">;
export type OrderingCutoverPlanId = Brand<CanonicalUuid, "OrderingCutoverPlanId">;
export type OrderSkipProposalId = Brand<CanonicalUuid, "OrderSkipProposalId">;
export type OrderSkipReviewId = Brand<CanonicalUuid, "OrderSkipReviewId">;
export type OrderDispositionId = Brand<CanonicalUuid, "OrderDispositionId">;
export type ReceiverOrderHeadId = Brand<CanonicalUuid, "ReceiverOrderHeadId">;
export type ReceiverOrderAcceptanceId = Brand<CanonicalUuid, "ReceiverOrderAcceptanceId">;
export type ReplayProposalId = Brand<CanonicalUuid, "ReplayProposalId">;
export type ReplayReviewId = Brand<CanonicalUuid, "ReplayReviewId">;
export type SuppressionProposalId = Brand<CanonicalUuid, "SuppressionProposalId">;
export type SuppressionReviewId = Brand<CanonicalUuid, "SuppressionReviewId">;
export type ReceiverReceiptObservationId = Brand<CanonicalUuid, "ReceiverReceiptObservationId">;
export type DispatchDomainId = Brand<CanonicalUuid, "DispatchDomainId">;
export type DispatchClaimRequestId = Brand<CanonicalUuid, "DispatchClaimRequestId">;
export type RatePolicyChangeId = Brand<CanonicalUuid, "RatePolicyChangeId">;

// Retention & Recovery IDs
export type RetentionHoldId = Brand<CanonicalUuid, "RetentionHoldId">;
export type RetentionActionId = Brand<CanonicalUuid, "RetentionActionId">;
export type CoordinatorTaskId = Brand<CanonicalUuid, "CoordinatorTaskId">;
export type RecoveryIncidentId = Brand<CanonicalUuid, "RecoveryIncidentId">;
export type RecoveryOperationId = Brand<CanonicalUuid, "RecoveryOperationId">;
export type RecoveryActionId = Brand<CanonicalUuid, "RecoveryActionId">;
export type RecoveryReviewId = Brand<CanonicalUuid, "RecoveryReviewId">;
export type RecoveryExecutionAttemptId = Brand<CanonicalUuid, "RecoveryExecutionAttemptId">;
export type ExternalOperationId = Brand<CanonicalUuid, "ExternalOperationId">;

const tenantIdCodec = createUuidBrandCodec<TenantId>("tenant_id");
const projectIdCodec = createUuidBrandCodec<ProjectId>("project_id");
const principalIdCodec = createUuidBrandCodec<PrincipalId>("principal_id");
const sessionIdCodec = createUuidBrandCodec<SessionId>("session_id");
const authChallengeIdCodec = createUuidBrandCodec<AuthChallengeId>("auth_challenge_id");
const preauthContextIdCodec = createUuidBrandCodec<PreauthContextId>("preauth_context_id");
const enrollmentIntentIdCodec = createUuidBrandCodec<EnrollmentIntentId>("enrollment_intent_id");
const operationProofIdCodec = createUuidBrandCodec<OperationProofId>("operation_proof_id");
const tenantMembershipIdCodec = createUuidBrandCodec<TenantMembershipId>("tenant_membership_id");
const projectMembershipIdCodec = createUuidBrandCodec<ProjectMembershipId>("project_membership_id");
const dataGrantIdCodec = createUuidBrandCodec<DataGrantId>("data_grant_id");
const platformRoleAssignmentIdCodec = createUuidBrandCodec<PlatformRoleAssignmentId>(
  "platform_role_assignment_id"
);
const producerIdCodec = createUuidBrandCodec<ProducerId>("producer_id");
const producerCredentialIdCodec = createUuidBrandCodec<ProducerCredentialId>(
  "producer_credential_id"
);
const producerCredentialIntentIdCodec = createUuidBrandCodec<ProducerCredentialIntentId>(
  "producer_credential_intent_id"
);
const producerScopeVersionIdCodec = createUuidBrandCodec<ProducerScopeVersionId>(
  "producer_scope_version_id"
);
const runtimeInstanceIdCodec = createUuidBrandCodec<RuntimeInstanceId>("runtime_instance_id");
const auditEventIdCodec = createUuidBrandCodec<AuditEventId>("audit_event_id");
const lifecycleOperationIdCodec = createUuidBrandCodec<LifecycleOperationId>(
  "lifecycle_operation_id"
);
const watchLeaseIdCodec = createUuidBrandCodec<WatchLeaseId>("watch_lease_id");
const controlEpochCodec = createUuidBrandCodec<ControlEpoch>("control_epoch");

const eventTypeIdCodec = createUuidBrandCodec<EventTypeId>("event_type_id");
const eventIdCodec = createUuidBrandCodec<EventId>("event_id");
const eventPayloadIdCodec = createUuidBrandCodec<EventPayloadId>("event_payload_id");
const wireEnvelopeIdCodec = createUuidBrandCodec<WireEnvelopeId>("wire_envelope_id");
const commandReceiptIdCodec = createUuidBrandCodec<CommandReceiptId>("command_receipt_id");
const outboxIdCodec = createUuidBrandCodec<OutboxId>("outbox_id");
const brokerGenerationIdCodec = createUuidBrandCodec<BrokerGenerationId>("broker_generation_id");
const brokerStreamGenerationIdCodec = createUuidBrandCodec<BrokerStreamGenerationId>(
  "broker_stream_generation_id"
);
const publicationObservationIdCodec = createUuidBrandCodec<PublicationObservationId>(
  "publication_observation_id"
);
const brokerInboxIdCodec = createUuidBrandCodec<BrokerInboxId>("broker_inbox_id");
const transportRejectionIdCodec = createUuidBrandCodec<TransportRejectionId>(
  "transport_rejection_id"
);
const publicationRecoveryEpisodeIdCodec = createUuidBrandCodec<PublicationRecoveryEpisodeId>(
  "publication_recovery_episode_id"
);

const endpointIdCodec = createUuidBrandCodec<EndpointId>("endpoint_id");
const endpointVerificationIntentIdCodec = createUuidBrandCodec<EndpointVerificationIntentId>(
  "endpoint_verification_intent_id"
);
const endpointVerificationAttemptIdCodec = createUuidBrandCodec<EndpointVerificationAttemptId>(
  "endpoint_verification_attempt_id"
);
const endpointVerificationEventIdCodec = createUuidBrandCodec<EndpointVerificationEventId>(
  "endpoint_verification_event_id"
);
const endpointDispatchGrantIdCodec = createUuidBrandCodec<EndpointDispatchGrantId>(
  "endpoint_dispatch_grant_id"
);
const endpointCircuitIdCodec = createUuidBrandCodec<EndpointCircuitId>("endpoint_circuit_id");
const signingKeyVersionIdCodec = createUuidBrandCodec<SigningKeyVersionId>(
  "signing_key_version_id"
);
const signingDeliveryIntentIdCodec = createUuidBrandCodec<SigningDeliveryIntentId>(
  "signing_delivery_intent_id"
);
const signingPolicyIdCodec = createUuidBrandCodec<SigningPolicyId>("signing_policy_id");
const subscriptionIdCodec = createUuidBrandCodec<SubscriptionId>("subscription_id");
const subscriptionVersionIdCodec = createUuidBrandCodec<SubscriptionVersionId>(
  "subscription_version_id"
);
const subscriptionControlEventIdCodec = createUuidBrandCodec<SubscriptionControlEventId>(
  "subscription_control_event_id"
);
const subscriptionTopologyRangeIdCodec = createUuidBrandCodec<SubscriptionTopologyRangeId>(
  "subscription_topology_range_id"
);
const representationProfileIdCodec = createUuidBrandCodec<RepresentationProfileId>(
  "representation_profile_id"
);
const receiverContractIdCodec = createUuidBrandCodec<ReceiverContractId>("receiver_contract_id");

const deliveryFamilyIdCodec = createUuidBrandCodec<DeliveryFamilyId>("delivery_family_id");
const deliveryIdCodec = createUuidBrandCodec<DeliveryId>("delivery_id");
const attemptIdCodec = createUuidBrandCodec<AttemptId>("attempt_id");
const retryDecisionIdCodec = createUuidBrandCodec<RetryDecisionId>("retry_decision_id");
const lateObservationIdCodec = createUuidBrandCodec<LateObservationId>("late_observation_id");
const circuitProbeRequestIdCodec = createUuidBrandCodec<CircuitProbeRequestId>(
  "circuit_probe_request_id"
);
const orderingDomainIdCodec = createUuidBrandCodec<OrderingDomainId>("ordering_domain_id");
const orderingKeyIdCodec = createUuidBrandCodec<OrderingKeyId>("ordering_key_id");
const orderingCutoverPlanIdCodec = createUuidBrandCodec<OrderingCutoverPlanId>(
  "ordering_cutover_plan_id"
);
const orderSkipProposalIdCodec = createUuidBrandCodec<OrderSkipProposalId>(
  "order_skip_proposal_id"
);
const orderSkipReviewIdCodec = createUuidBrandCodec<OrderSkipReviewId>("order_skip_review_id");
const orderDispositionIdCodec = createUuidBrandCodec<OrderDispositionId>("order_disposition_id");
const receiverOrderHeadIdCodec = createUuidBrandCodec<ReceiverOrderHeadId>(
  "receiver_order_head_id"
);
const receiverOrderAcceptanceIdCodec = createUuidBrandCodec<ReceiverOrderAcceptanceId>(
  "receiver_order_acceptance_id"
);
const replayProposalIdCodec = createUuidBrandCodec<ReplayProposalId>("replay_proposal_id");
const replayReviewIdCodec = createUuidBrandCodec<ReplayReviewId>("replay_review_id");
const suppressionProposalIdCodec = createUuidBrandCodec<SuppressionProposalId>(
  "suppression_proposal_id"
);
const suppressionReviewIdCodec = createUuidBrandCodec<SuppressionReviewId>(
  "suppression_review_id"
);
const receiverReceiptObservationIdCodec = createUuidBrandCodec<ReceiverReceiptObservationId>(
  "receiver_receipt_observation_id"
);
const dispatchDomainIdCodec = createUuidBrandCodec<DispatchDomainId>("dispatch_domain_id");
const dispatchClaimRequestIdCodec = createUuidBrandCodec<DispatchClaimRequestId>(
  "dispatch_claim_request_id"
);
const ratePolicyChangeIdCodec = createUuidBrandCodec<RatePolicyChangeId>("rate_policy_change_id");

const retentionHoldIdCodec = createUuidBrandCodec<RetentionHoldId>("retention_hold_id");
const retentionActionIdCodec = createUuidBrandCodec<RetentionActionId>("retention_action_id");
const coordinatorTaskIdCodec = createUuidBrandCodec<CoordinatorTaskId>("coordinator_task_id");
const recoveryIncidentIdCodec = createUuidBrandCodec<RecoveryIncidentId>("recovery_incident_id");
const recoveryOperationIdCodec = createUuidBrandCodec<RecoveryOperationId>(
  "recovery_operation_id"
);
const recoveryActionIdCodec = createUuidBrandCodec<RecoveryActionId>("recovery_action_id");
const recoveryReviewIdCodec = createUuidBrandCodec<RecoveryReviewId>("recovery_review_id");
const recoveryExecutionAttemptIdCodec = createUuidBrandCodec<RecoveryExecutionAttemptId>(
  "recovery_execution_attempt_id"
);
const externalOperationIdCodec = createUuidBrandCodec<ExternalOperationId>(
  "external_operation_id"
);

export const parseTenantId = tenantIdCodec.parse;
export const isTenantId = tenantIdCodec.is;
export const parseProjectId = projectIdCodec.parse;
export const isProjectId = projectIdCodec.is;
export const parsePrincipalId = principalIdCodec.parse;
export const isPrincipalId = principalIdCodec.is;
export const parseSessionId = sessionIdCodec.parse;
export const isSessionId = sessionIdCodec.is;
export const parseAuthChallengeId = authChallengeIdCodec.parse;
export const isAuthChallengeId = authChallengeIdCodec.is;
export const parsePreauthContextId = preauthContextIdCodec.parse;
export const isPreauthContextId = preauthContextIdCodec.is;
export const parseEnrollmentIntentId = enrollmentIntentIdCodec.parse;
export const isEnrollmentIntentId = enrollmentIntentIdCodec.is;
export const parseOperationProofId = operationProofIdCodec.parse;
export const isOperationProofId = operationProofIdCodec.is;
export const parseTenantMembershipId = tenantMembershipIdCodec.parse;
export const isTenantMembershipId = tenantMembershipIdCodec.is;
export const parseProjectMembershipId = projectMembershipIdCodec.parse;
export const isProjectMembershipId = projectMembershipIdCodec.is;
export const parseDataGrantId = dataGrantIdCodec.parse;
export const isDataGrantId = dataGrantIdCodec.is;
export const parsePlatformRoleAssignmentId = platformRoleAssignmentIdCodec.parse;
export const isPlatformRoleAssignmentId = platformRoleAssignmentIdCodec.is;
export const parseProducerId = producerIdCodec.parse;
export const isProducerId = producerIdCodec.is;
export const parseProducerCredentialId = producerCredentialIdCodec.parse;
export const isProducerCredentialId = producerCredentialIdCodec.is;
export const parseProducerCredentialIntentId = producerCredentialIntentIdCodec.parse;
export const isProducerCredentialIntentId = producerCredentialIntentIdCodec.is;
export const parseProducerScopeVersionId = producerScopeVersionIdCodec.parse;
export const isProducerScopeVersionId = producerScopeVersionIdCodec.is;
export const parseRuntimeInstanceId = runtimeInstanceIdCodec.parse;
export const isRuntimeInstanceId = runtimeInstanceIdCodec.is;
export const parseAuditEventId = auditEventIdCodec.parse;
export const isAuditEventId = auditEventIdCodec.is;
export const parseLifecycleOperationId = lifecycleOperationIdCodec.parse;
export const isLifecycleOperationId = lifecycleOperationIdCodec.is;
export const parseWatchLeaseId = watchLeaseIdCodec.parse;
export const isWatchLeaseId = watchLeaseIdCodec.is;
export const parseControlEpoch = controlEpochCodec.parse;
export const isControlEpoch = controlEpochCodec.is;

export const parseEventTypeId = eventTypeIdCodec.parse;
export const isEventTypeId = eventTypeIdCodec.is;
export const parseEventId = eventIdCodec.parse;
export const isEventId = eventIdCodec.is;
export const parseEventPayloadId = eventPayloadIdCodec.parse;
export const isEventPayloadId = eventPayloadIdCodec.is;
export const parseWireEnvelopeId = wireEnvelopeIdCodec.parse;
export const isWireEnvelopeId = wireEnvelopeIdCodec.is;
export const parseCommandReceiptId = commandReceiptIdCodec.parse;
export const isCommandReceiptId = commandReceiptIdCodec.is;
export const parseOutboxId = outboxIdCodec.parse;
export const isOutboxId = outboxIdCodec.is;
export const parseBrokerGenerationId = brokerGenerationIdCodec.parse;
export const isBrokerGenerationId = brokerGenerationIdCodec.is;
export const parseBrokerStreamGenerationId = brokerStreamGenerationIdCodec.parse;
export const isBrokerStreamGenerationId = brokerStreamGenerationIdCodec.is;
export const parsePublicationObservationId = publicationObservationIdCodec.parse;
export const isPublicationObservationId = publicationObservationIdCodec.is;
export const parseBrokerInboxId = brokerInboxIdCodec.parse;
export const isBrokerInboxId = brokerInboxIdCodec.is;
export const parseTransportRejectionId = transportRejectionIdCodec.parse;
export const isTransportRejectionId = transportRejectionIdCodec.is;
export const parsePublicationRecoveryEpisodeId = publicationRecoveryEpisodeIdCodec.parse;
export const isPublicationRecoveryEpisodeId = publicationRecoveryEpisodeIdCodec.is;

export const parseEndpointId = endpointIdCodec.parse;
export const isEndpointId = endpointIdCodec.is;
export const parseEndpointVerificationIntentId = endpointVerificationIntentIdCodec.parse;
export const isEndpointVerificationIntentId = endpointVerificationIntentIdCodec.is;
export const parseEndpointVerificationAttemptId = endpointVerificationAttemptIdCodec.parse;
export const isEndpointVerificationAttemptId = endpointVerificationAttemptIdCodec.is;
export const parseEndpointVerificationEventId = endpointVerificationEventIdCodec.parse;
export const isEndpointVerificationEventId = endpointVerificationEventIdCodec.is;
export const parseEndpointDispatchGrantId = endpointDispatchGrantIdCodec.parse;
export const isEndpointDispatchGrantId = endpointDispatchGrantIdCodec.is;
export const parseEndpointCircuitId = endpointCircuitIdCodec.parse;
export const isEndpointCircuitId = endpointCircuitIdCodec.is;
export const parseSigningKeyVersionId = signingKeyVersionIdCodec.parse;
export const isSigningKeyVersionId = signingKeyVersionIdCodec.is;
export const parseSigningDeliveryIntentId = signingDeliveryIntentIdCodec.parse;
export const isSigningDeliveryIntentId = signingDeliveryIntentIdCodec.is;
export const parseSigningPolicyId = signingPolicyIdCodec.parse;
export const isSigningPolicyId = signingPolicyIdCodec.is;
export const parseSubscriptionId = subscriptionIdCodec.parse;
export const isSubscriptionId = subscriptionIdCodec.is;
export const parseSubscriptionVersionId = subscriptionVersionIdCodec.parse;
export const isSubscriptionVersionId = subscriptionVersionIdCodec.is;
export const parseSubscriptionControlEventId = subscriptionControlEventIdCodec.parse;
export const isSubscriptionControlEventId = subscriptionControlEventIdCodec.is;
export const parseSubscriptionTopologyRangeId = subscriptionTopologyRangeIdCodec.parse;
export const isSubscriptionTopologyRangeId = subscriptionTopologyRangeIdCodec.is;
export const parseRepresentationProfileId = representationProfileIdCodec.parse;
export const isRepresentationProfileId = representationProfileIdCodec.is;
export const parseReceiverContractId = receiverContractIdCodec.parse;
export const isReceiverContractId = receiverContractIdCodec.is;

export const parseDeliveryFamilyId = deliveryFamilyIdCodec.parse;
export const isDeliveryFamilyId = deliveryFamilyIdCodec.is;
export const parseDeliveryId = deliveryIdCodec.parse;
export const isDeliveryId = deliveryIdCodec.is;
export const parseAttemptId = attemptIdCodec.parse;
export const isAttemptId = attemptIdCodec.is;
export const parseRetryDecisionId = retryDecisionIdCodec.parse;
export const isRetryDecisionId = retryDecisionIdCodec.is;
export const parseLateObservationId = lateObservationIdCodec.parse;
export const isLateObservationId = lateObservationIdCodec.is;
export const parseCircuitProbeRequestId = circuitProbeRequestIdCodec.parse;
export const isCircuitProbeRequestId = circuitProbeRequestIdCodec.is;
export const parseOrderingDomainId = orderingDomainIdCodec.parse;
export const isOrderingDomainId = orderingDomainIdCodec.is;
export const parseOrderingKeyId = orderingKeyIdCodec.parse;
export const isOrderingKeyId = orderingKeyIdCodec.is;
export const parseOrderingCutoverPlanId = orderingCutoverPlanIdCodec.parse;
export const isOrderingCutoverPlanId = orderingCutoverPlanIdCodec.is;
export const parseOrderSkipProposalId = orderSkipProposalIdCodec.parse;
export const isOrderSkipProposalId = orderSkipProposalIdCodec.is;
export const parseOrderSkipReviewId = orderSkipReviewIdCodec.parse;
export const isOrderSkipReviewId = orderSkipReviewIdCodec.is;
export const parseOrderDispositionId = orderDispositionIdCodec.parse;
export const isOrderDispositionId = orderDispositionIdCodec.is;
export const parseReceiverOrderHeadId = receiverOrderHeadIdCodec.parse;
export const isReceiverOrderHeadId = receiverOrderHeadIdCodec.is;
export const parseReceiverOrderAcceptanceId = receiverOrderAcceptanceIdCodec.parse;
export const isReceiverOrderAcceptanceId = receiverOrderAcceptanceIdCodec.is;
export const parseReplayProposalId = replayProposalIdCodec.parse;
export const isReplayProposalId = replayProposalIdCodec.is;
export const parseReplayReviewId = replayReviewIdCodec.parse;
export const isReplayReviewId = replayReviewIdCodec.is;
export const parseSuppressionProposalId = suppressionProposalIdCodec.parse;
export const isSuppressionProposalId = suppressionProposalIdCodec.is;
export const parseSuppressionReviewId = suppressionReviewIdCodec.parse;
export const isSuppressionReviewId = suppressionReviewIdCodec.is;
export const parseReceiverReceiptObservationId = receiverReceiptObservationIdCodec.parse;
export const isReceiverReceiptObservationId = receiverReceiptObservationIdCodec.is;
export const parseDispatchDomainId = dispatchDomainIdCodec.parse;
export const isDispatchDomainId = dispatchDomainIdCodec.is;
export const parseDispatchClaimRequestId = dispatchClaimRequestIdCodec.parse;
export const isDispatchClaimRequestId = dispatchClaimRequestIdCodec.is;
export const parseRatePolicyChangeId = ratePolicyChangeIdCodec.parse;
export const isRatePolicyChangeId = ratePolicyChangeIdCodec.is;

export const parseRetentionHoldId = retentionHoldIdCodec.parse;
export const isRetentionHoldId = retentionHoldIdCodec.is;
export const parseRetentionActionId = retentionActionIdCodec.parse;
export const isRetentionActionId = retentionActionIdCodec.is;
export const parseCoordinatorTaskId = coordinatorTaskIdCodec.parse;
export const isCoordinatorTaskId = coordinatorTaskIdCodec.is;
export const parseRecoveryIncidentId = recoveryIncidentIdCodec.parse;
export const isRecoveryIncidentId = recoveryIncidentIdCodec.is;
export const parseRecoveryOperationId = recoveryOperationIdCodec.parse;
export const isRecoveryOperationId = recoveryOperationIdCodec.is;
export const parseRecoveryActionId = recoveryActionIdCodec.parse;
export const isRecoveryActionId = recoveryActionIdCodec.is;
export const parseRecoveryReviewId = recoveryReviewIdCodec.parse;
export const isRecoveryReviewId = recoveryReviewIdCodec.is;
export const parseRecoveryExecutionAttemptId = recoveryExecutionAttemptIdCodec.parse;
export const isRecoveryExecutionAttemptId = recoveryExecutionAttemptIdCodec.is;
export const parseExternalOperationId = externalOperationIdCodec.parse;
export const isExternalOperationId = externalOperationIdCodec.is;

// SHA-256 Hex
export type Sha256Hex = Brand<string, "Sha256Hex">;
const SHA256_INPUT_REGEX = /^[0-9a-fA-F]{64}$/;
const SHA256_LOWER_REGEX = /^[0-9a-f]{64}$/;

export function isSha256Hex(value: unknown): value is Sha256Hex {
  return typeof value === "string" && SHA256_LOWER_REGEX.test(value);
}

export function parseSha256Hex(value: unknown, fieldPath = "sha256"): Sha256Hex {
  if (typeof value !== "string" || !SHA256_INPUT_REGEX.test(value)) {
    throw new ValidationDomainError({
      code: "INVALID_HASH",
      message: `Invalid SHA-256 hex digest for ${fieldPath}`,
      fieldErrors: [{ path: fieldPath, code: "INVALID_HASH" }]
    });
  }
  return value.toLowerCase() as Sha256Hex;
}

// Int64 Decimal Strings & BigInt Helpers
export const INT64_MIN = -9223372036854775808n;
export const INT64_MAX = 9223372036854775807n;

export type Int64String = Brand<string, "Int64String">;
export type NonNegativeInt64String = Brand<Int64String, "NonNegativeInt64String">;
export type PositiveInt64String = Brand<NonNegativeInt64String, "PositiveInt64String">;

const CANONICAL_INT64_REGEX = /^(?:0|-?[1-9][0-9]*)$/;

export function parseInt64BigInt(value: unknown, fieldPath = "int64"): bigint {
  if (typeof value === "bigint") {
    if (value < INT64_MIN || value > INT64_MAX) {
      throw new ValidationDomainError({
        code: "INVALID_INT64",
        message: `Integer out of signed 64-bit range for ${fieldPath}`,
        fieldErrors: [{ path: fieldPath, code: "INVALID_INT64" }]
      });
    }
    return value;
  }

  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) {
      throw new ValidationDomainError({
        code: "INVALID_INT64",
        message: `Unsafe or non-integer number for ${fieldPath}`,
        fieldErrors: [{ path: fieldPath, code: "INVALID_INT64" }]
      });
    }
    return BigInt(value);
  }

  if (typeof value !== "string" || !CANONICAL_INT64_REGEX.test(value)) {
    throw new ValidationDomainError({
      code: "INVALID_INT64",
      message: `Invalid canonical int64 string for ${fieldPath}`,
      fieldErrors: [{ path: fieldPath, code: "INVALID_INT64" }]
    });
  }

  const parsed = BigInt(value);
  if (parsed < INT64_MIN || parsed > INT64_MAX) {
    throw new ValidationDomainError({
      code: "INVALID_INT64",
      message: `Integer out of signed 64-bit range for ${fieldPath}`,
      fieldErrors: [{ path: fieldPath, code: "INVALID_INT64" }]
    });
  }
  return parsed;
}

export function parseNonNegativeInt64BigInt(value: unknown, fieldPath = "int64"): bigint {
  const parsed = parseInt64BigInt(value, fieldPath);
  if (parsed < 0n) {
    throw new ValidationDomainError({
      code: "INVALID_INT64",
      message: `Expected non-negative int64 for ${fieldPath}`,
      fieldErrors: [{ path: fieldPath, code: "INVALID_INT64" }]
    });
  }
  return parsed;
}

export function parsePositiveInt64BigInt(value: unknown, fieldPath = "int64"): bigint {
  const parsed = parseInt64BigInt(value, fieldPath);
  if (parsed <= 0n) {
    throw new ValidationDomainError({
      code: "INVALID_INT64",
      message: `Expected positive int64 for ${fieldPath}`,
      fieldErrors: [{ path: fieldPath, code: "INVALID_INT64" }]
    });
  }
  return parsed;
}

export function formatInt64(value: bigint, fieldPath = "int64"): Int64String {
  const checked = parseInt64BigInt(value, fieldPath);
  return checked.toString(10) as Int64String;
}

export function parseInt64String(value: unknown, fieldPath = "int64"): Int64String {
  if (typeof value !== "string" || !CANONICAL_INT64_REGEX.test(value)) {
    throw new ValidationDomainError({
      code: "INVALID_INT64",
      message: `Invalid canonical int64 string for ${fieldPath}`,
      fieldErrors: [{ path: fieldPath, code: "INVALID_INT64" }]
    });
  }
  const parsed = parseInt64BigInt(value, fieldPath);
  return parsed.toString(10) as Int64String;
}

export function parseNonNegativeInt64String(
  value: unknown,
  fieldPath = "int64"
): NonNegativeInt64String {
  if (typeof value !== "string" || !CANONICAL_INT64_REGEX.test(value)) {
    throw new ValidationDomainError({
      code: "INVALID_INT64",
      message: `Invalid non-negative int64 string for ${fieldPath}`,
      fieldErrors: [{ path: fieldPath, code: "INVALID_INT64" }]
    });
  }
  const parsed = parseNonNegativeInt64BigInt(value, fieldPath);
  return parsed.toString(10) as NonNegativeInt64String;
}

export function parsePositiveInt64String(
  value: unknown,
  fieldPath = "int64"
): PositiveInt64String {
  if (typeof value !== "string" || !CANONICAL_INT64_REGEX.test(value)) {
    throw new ValidationDomainError({
      code: "INVALID_INT64",
      message: `Invalid positive int64 string for ${fieldPath}`,
      fieldErrors: [{ path: fieldPath, code: "INVALID_INT64" }]
    });
  }
  const parsed = parsePositiveInt64BigInt(value, fieldPath);
  return parsed.toString(10) as PositiveInt64String;
}

export function isInt64String(value: unknown): value is Int64String {
  if (typeof value !== "string" || !CANONICAL_INT64_REGEX.test(value)) {
    return false;
  }
  const parsed = BigInt(value);
  return parsed >= INT64_MIN && parsed <= INT64_MAX;
}

export function isNonNegativeInt64String(value: unknown): value is NonNegativeInt64String {
  return isInt64String(value) && !value.startsWith("-");
}

export function isPositiveInt64String(value: unknown): value is PositiveInt64String {
  return isNonNegativeInt64String(value) && value !== "0";
}

// Pure ES UTF-8 byte length & lone surrogate detection (works with tsconfig "types": [])
export function hasLoneSurrogate(value: string): boolean {
  for (let i = 0; i < value.length; i += 1) {
    const code = value.charCodeAt(i);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = i + 1 < value.length ? value.charCodeAt(i + 1) : 0;
      if (next < 0xdc00 || next > 0xdfff) {
        return true;
      }
      i += 1;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      return true;
    }
  }
  return false;
}

export function computeUtf8ByteLength(value: string): number {
  let bytes = 0;
  for (let i = 0; i < value.length; i += 1) {
    const code = value.charCodeAt(i);
    if (code <= 0x7f) {
      bytes += 1;
    } else if (code <= 0x7ff) {
      bytes += 2;
    } else if (code >= 0xd800 && code <= 0xdbff) {
      const next = i + 1 < value.length ? value.charCodeAt(i + 1) : 0;
      if (next < 0xdc00 || next > 0xdfff) {
        throw new ValidationDomainError({
          code: "INVALID_VALUE",
          message: "String contains an unpaired UTF-16 high surrogate"
        });
      }
      bytes += 4;
      i += 1;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      throw new ValidationDomainError({
        code: "INVALID_VALUE",
        message: "String contains an unpaired UTF-16 low surrogate"
      });
    } else {
      bytes += 3;
    }
  }
  return bytes;
}

// Producer Namespace
export type ProducerNamespace = Brand<string, "ProducerNamespace">;
const MACHINE_NAMESPACE_REGEX = /^[a-z][a-z0-9._-]{0,63}$/;
const HUMAN_NAMESPACE_PREFIX = "human.";

export function isHumanWorkflowNamespace(value: string): boolean {
  if (!value.startsWith(HUMAN_NAMESPACE_PREFIX)) {
    return false;
  }
  return STRICT_LOWER_UUID_REGEX.test(value.slice(HUMAN_NAMESPACE_PREFIX.length));
}

export function isProducerNamespace(value: unknown): value is ProducerNamespace {
  if (typeof value !== "string") {
    return false;
  }
  if (value.startsWith(HUMAN_NAMESPACE_PREFIX)) {
    return isHumanWorkflowNamespace(value);
  }
  return MACHINE_NAMESPACE_REGEX.test(value);
}

export function parseProducerNamespace(
  value: unknown,
  fieldPath = "producer_namespace"
): ProducerNamespace {
  if (typeof value !== "string") {
    throw new ValidationDomainError({
      code: "INVALID_PRODUCER_NAMESPACE",
      message: `Invalid producer namespace for ${fieldPath}`,
      fieldErrors: [{ path: fieldPath, code: "INVALID_PRODUCER_NAMESPACE" }]
    });
  }
  if (value.startsWith(HUMAN_NAMESPACE_PREFIX)) {
    const rawPrincipal = value.slice(HUMAN_NAMESPACE_PREFIX.length);
    if (!CANONICAL_UUID_INPUT_REGEX.test(rawPrincipal)) {
      throw new ValidationDomainError({
        code: "INVALID_PRODUCER_NAMESPACE",
        message: `Human workflow namespace must end with a canonical UUID for ${fieldPath}`,
        fieldErrors: [{ path: fieldPath, code: "INVALID_PRODUCER_NAMESPACE" }]
      });
    }
    return `${HUMAN_NAMESPACE_PREFIX}${rawPrincipal.toLowerCase()}` as ProducerNamespace;
  }
  if (!MACHINE_NAMESPACE_REGEX.test(value)) {
    throw new ValidationDomainError({
      code: "INVALID_PRODUCER_NAMESPACE",
      message: `Invalid machine producer namespace for ${fieldPath}`,
      fieldErrors: [{ path: fieldPath, code: "INVALID_PRODUCER_NAMESPACE" }]
    });
  }
  return value as ProducerNamespace;
}

// KeyId
export type KeyId = Brand<string, "KeyId">;
const KEY_ID_REGEX = /^[a-z0-9][a-z0-9._-]{0,63}$/;

export function isKeyId(value: unknown): value is KeyId {
  return typeof value === "string" && KEY_ID_REGEX.test(value);
}

export function parseKeyId(value: unknown, fieldPath = "key_id"): KeyId {
  if (!isKeyId(value)) {
    throw new ValidationDomainError({
      code: "INVALID_KEY_ID",
      message: `Invalid key identifier for ${fieldPath}`,
      fieldErrors: [{ path: fieldPath, code: "INVALID_KEY_ID" }]
    });
  }
  return value;
}

// IdempotencyKey (1..128 printable non-whitespace ASCII 0x21..0x7E)
export type IdempotencyKey = Brand<string, "IdempotencyKey">;
const IDEMPOTENCY_KEY_REGEX = /^[\x21-\x7e]{1,128}$/;

export function isIdempotencyKey(value: unknown): value is IdempotencyKey {
  return typeof value === "string" && IDEMPOTENCY_KEY_REGEX.test(value);
}

export function parseIdempotencyKey(
  value: unknown,
  fieldPath = "idempotency_key"
): IdempotencyKey {
  if (!isIdempotencyKey(value)) {
    throw new ValidationDomainError({
      code: "INVALID_IDEMPOTENCY_KEY",
      message: `Invalid idempotency key for ${fieldPath}`,
      fieldErrors: [{ path: fieldPath, code: "INVALID_IDEMPOTENCY_KEY" }]
    });
  }
  return value;
}

// BusinessKey (1..128 UTF-8 bytes, no lone surrogates)
export type BusinessKey = Brand<string, "BusinessKey">;
export const BUSINESS_KEY_MAX_UTF8_BYTES = 128 as const;

export function isBusinessKey(value: unknown): value is BusinessKey {
  if (typeof value !== "string" || value.length === 0 || hasLoneSurrogate(value)) {
    return false;
  }
  const byteLen = computeUtf8ByteLength(value);
  return byteLen >= 1 && byteLen <= BUSINESS_KEY_MAX_UTF8_BYTES;
}

export function parseBusinessKey(value: unknown, fieldPath = "business_key"): BusinessKey {
  if (typeof value !== "string" || value.length === 0 || hasLoneSurrogate(value)) {
    throw new ValidationDomainError({
      code: "INVALID_BUSINESS_KEY",
      message: `Invalid business key for ${fieldPath}`,
      fieldErrors: [{ path: fieldPath, code: "INVALID_BUSINESS_KEY" }]
    });
  }
  const byteLen = computeUtf8ByteLength(value);
  if (byteLen < 1 || byteLen > BUSINESS_KEY_MAX_UTF8_BYTES) {
    throw new ValidationDomainError({
      code: "INVALID_BUSINESS_KEY",
      message: `Business key exceeds ${BUSINESS_KEY_MAX_UTF8_BYTES} UTF-8 bytes for ${fieldPath}`,
      fieldErrors: [{ path: fieldPath, code: "INVALID_BUSINESS_KEY" }]
    });
  }
  return value as BusinessKey;
}

// EventTypeName
export type EventTypeName = Brand<string, "EventTypeName">;
const EVENT_TYPE_NAME_REGEX = /^[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*){0,7}$/;
export const EVENT_TYPE_NAME_MAX_BYTES = 128 as const;

export function isEventTypeName(value: unknown): value is EventTypeName {
  return (
    typeof value === "string" &&
    value.length >= 1 &&
    value.length <= EVENT_TYPE_NAME_MAX_BYTES &&
    EVENT_TYPE_NAME_REGEX.test(value)
  );
}

export function parseEventTypeName(
  value: unknown,
  fieldPath = "event_type_name"
): EventTypeName {
  if (!isEventTypeName(value)) {
    throw new ValidationDomainError({
      code: "INVALID_EVENT_TYPE_NAME",
      message: `Invalid event type name for ${fieldPath}`,
      fieldErrors: [{ path: fieldPath, code: "INVALID_EVENT_TYPE_NAME" }]
    });
  }
  return value;
}

// Opaque Secret Wrapper
const REDACTED_MARKER = "[REDACTED]" as const;

export class OpaqueSecret<T extends string = string> {
  readonly #value: T;

  constructor(value: T) {
    if (typeof value !== "string" || value.length === 0) {
      throw new ValidationDomainError({
        code: "SECRET_CUSTODY_ERROR",
        message: "OpaqueSecret requires a non-empty string value"
      });
    }
    this.#value = value;
    Object.freeze(this);
  }

  expose(): T {
    return this.#value;
  }

  toJSON(): string {
    return REDACTED_MARKER;
  }

  toString(): string {
    return REDACTED_MARKER;
  }

  valueOf(): string {
    return REDACTED_MARKER;
  }

  [Symbol.for("nodejs.util.inspect.custom")](): string {
    return REDACTED_MARKER;
  }
}

// Producer Credential Selector & Token Parsing
export const PRODUCER_CREDENTIAL_PREFIX = "rq_p1" as const;
export type ProducerCredentialSelector = Brand<string, "ProducerCredentialSelector">;

const SELECTOR_REGEX = /^rq_p1\.([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})$/;
const STRICT_SELECTOR_REGEX = /^rq_p1\.([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$/;
const BASE64URL_32B_REGEX = /^[A-Za-z0-9_-]{43}$/;

export function isProducerCredentialSelector(value: unknown): value is ProducerCredentialSelector {
  return typeof value === "string" && STRICT_SELECTOR_REGEX.test(value);
}

export function formatProducerCredentialSelector(
  credentialId: ProducerCredentialId
): ProducerCredentialSelector {
  return `${PRODUCER_CREDENTIAL_PREFIX}.${credentialId}` as ProducerCredentialSelector;
}

export function parseProducerCredentialSelector(
  value: unknown,
  fieldPath = "credential_selector"
): { readonly selector: ProducerCredentialSelector; readonly credentialId: ProducerCredentialId } {
  if (typeof value !== "string") {
    throw new ValidationDomainError({
      code: "INVALID_CREDENTIAL_SELECTOR",
      message: `Invalid producer credential selector for ${fieldPath}`,
      fieldErrors: [{ path: fieldPath, code: "INVALID_CREDENTIAL_SELECTOR" }]
    });
  }
  const match = SELECTOR_REGEX.exec(value);
  if (match === null || match[1] === undefined) {
    throw new ValidationDomainError({
      code: "INVALID_CREDENTIAL_SELECTOR",
      message: `Invalid producer credential selector format for ${fieldPath}`,
      fieldErrors: [{ path: fieldPath, code: "INVALID_CREDENTIAL_SELECTOR" }]
    });
  }
  const credentialId = parseProducerCredentialId(match[1], fieldPath);
  const selector = formatProducerCredentialSelector(credentialId);
  return Object.freeze({ selector, credentialId });
}

export interface ParsedProducerCredentialToken {
  readonly selector: ProducerCredentialSelector;
  readonly credentialId: ProducerCredentialId;
  readonly secret: OpaqueSecret<string>;
}

export function parseProducerCredentialToken(
  token: unknown,
  fieldPath = "authorization"
): ParsedProducerCredentialToken {
  if (typeof token !== "string") {
    throw new ValidationDomainError({
      code: "INVALID_CREDENTIAL_SELECTOR",
      message: `Invalid producer credential token for ${fieldPath}`,
      fieldErrors: [{ path: fieldPath, code: "INVALID_CREDENTIAL_SELECTOR" }]
    });
  }
  const parts = token.split(".");
  if (
    parts.length !== 3 ||
    parts[0] !== PRODUCER_CREDENTIAL_PREFIX ||
    parts[1] === undefined ||
    parts[2] === undefined ||
    !BASE64URL_32B_REGEX.test(parts[2])
  ) {
    throw new ValidationDomainError({
      code: "INVALID_CREDENTIAL_SELECTOR",
      message: `Malformed producer credential token for ${fieldPath}`,
      fieldErrors: [{ path: fieldPath, code: "INVALID_CREDENTIAL_SELECTOR" }]
    });
  }
  const credentialId = parseProducerCredentialId(parts[1], fieldPath);
  const selector = formatProducerCredentialSelector(credentialId);
  return Object.freeze({
    selector,
    credentialId,
    secret: new OpaqueSecret(parts[2])
  });
}
