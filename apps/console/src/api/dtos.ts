import {
  type CircuitProbeRequestState,
  type CircuitState,
  type ContentAvailability,
  type DataGrantAction,
  type DataGrantProjection,
  type DataGrantState,
  type DeliveryPopulation,
  type EndpointState,
  type EndpointVerificationIntentState,
  type EnrollmentIntentKind,
  type EnrollmentIntentState,
  type HumanSessionKind,
  type InstallationMode,
  type MembershipState,
  type OrderingCutoverPlanState,
  type OrderingMemberKind,
  type OrderingMemberState,
  type OrderingMode,
  type OrderingProfile,
  type OverviewStageSummary,
  type PlatformRole,
  type PlatformRoleAssignmentState,
  type ProducerCredentialIntentState,
  type ProducerCredentialState,
  type ProducerScopeAction,
  type ProducerScopeVersionState,
  type ProducerState,
  type ProjectRole,
  type ProjectState,
  type ProposalState,
  type RateBucketOperation,
  type RatePolicyChangeScopeKind,
  type RatePolicyChangeState,
  type ReceiptProfile,
  type ReceiverContractState,
  type RetentionHoldState,
  type RetentionHoldTargetKind,
  type SchemaCompatibilityPolicy,
  type SignatureMode,
  type SigningDeliveryIntentState,
  type SigningKeyVersionState,
  type SubscriptionState,
  type TenantRole,
  type TenantState
} from "@relayquill/domain";
import {
  type AcceptedReceiptDto,
  type CanonicalUtcTimestamp,
  type CanonicalUuid,
  type CapabilityEntryDto,
  type Int64String,
  type NonNegativeInt64String,
  type PositiveInt64String,
  type PrincipalId,
  type ProjectId,
  type Sha256Hex,
  type TenantId,
  assertPlainRecord,
  parseCapabilities
} from "@relayquill/contracts";
import type {
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialRequestOptionsJSON
} from "@simplewebauthn/browser";

export interface WorkspaceProjectOptionDto {
  readonly tenant_id: TenantId;
  readonly tenant_slug: string;
  readonly tenant_display_name: string;
  readonly project_id: ProjectId;
  readonly project_name: string;
  readonly roles: readonly ProjectRole[];
  readonly tenant_roles: readonly TenantRole[];
}

export interface SessionContextDto {
  readonly session_id: CanonicalUuid;
  readonly principal_id: PrincipalId;
  readonly display_name: string;
  readonly purpose: HumanSessionKind;
  readonly authority_epoch: NonNegativeInt64String;
  readonly created_at: CanonicalUtcTimestamp;
  readonly idle_expires_at: CanonicalUtcTimestamp;
  readonly absolute_expires_at: CanonicalUtcTimestamp;
  readonly csrf_token: string;
  readonly platform_roles: readonly PlatformRole[];
  readonly workspaces: readonly WorkspaceProjectOptionDto[];
}

export interface EnrollmentIntentDto {
  readonly intent_id: CanonicalUuid;
  readonly purpose: EnrollmentIntentKind;
  readonly state: EnrollmentIntentState;
  readonly version: Int64String;
  readonly expires_at: CanonicalUtcTimestamp;
  readonly comparison_sha256: Sha256Hex;
  readonly next_step?: string | undefined;
}

export interface EnrollmentPasskeyOptionsDto {
  readonly auth_challenge_id: CanonicalUuid;
  readonly intent_version: Int64String;
  readonly authenticator_label: string;
  readonly public_key: PublicKeyCredentialCreationOptionsJSON;
}

export interface CompletedEnrollmentDto {
  readonly completed: true;
  readonly intent_id: CanonicalUuid;
  readonly purpose: EnrollmentIntentKind;
  readonly principal_id: PrincipalId;
  readonly passkey_id: CanonicalUuid;
  readonly passkey_state: string;
  readonly next_action: "sign_in" | "restricted_recovery_review";
}

export interface SignInOptionsDto {
  readonly auth_challenge_id: CanonicalUuid;
  readonly public_key: PublicKeyCredentialRequestOptionsJSON;
}

export interface SignInCompleteDto {
  readonly session_id: CanonicalUuid;
  readonly principal_id: PrincipalId;
  readonly display_name: string;
  readonly purpose: HumanSessionKind;
  readonly created_at: CanonicalUtcTimestamp;
  readonly idle_expires_at: CanonicalUtcTimestamp;
  readonly absolute_expires_at: CanonicalUtcTimestamp;
}

export interface StepUpOptionsDto {
  readonly auth_challenge_id: CanonicalUuid;
  readonly action: string;
  readonly target_sha256: Sha256Hex;
  readonly expires_at: CanonicalUtcTimestamp;
  readonly public_key: PublicKeyCredentialRequestOptionsJSON;
}

export interface StepUpCompleteDto {
  readonly operation_proof_id: CanonicalUuid;
  readonly action: string;
  readonly target_sha256: Sha256Hex;
  readonly expires_at: CanonicalUtcTimestamp;
}

export interface OverviewStageCardDto {
  readonly stage: OverviewStageSummary;
  readonly label: string;
  readonly count: NonNegativeInt64String | null;
  readonly availability: "current" | "unavailable" | "authorized_empty";
  readonly unit: "events" | "notifications" | "delivery_generations" | "receipt_observations";
  readonly population: DeliveryPopulation | "accepted_events";
  readonly window_label: string;
  readonly observed_at: CanonicalUtcTimestamp;
  readonly note: string;
}

export interface ProjectOverviewDto {
  readonly project_id: ProjectId;
  readonly project_name: string;
  readonly project_state: ProjectState;
  readonly project_version: Int64String;
  readonly topology_version: PositiveInt64String;
  readonly active_cutover_plan_id: CanonicalUuid | null;
  readonly window_label: string;
  readonly observed_at: CanonicalUtcTimestamp;
  readonly stages: readonly OverviewStageCardDto[];
  readonly outbox_pressure: {
    readonly oldest_pending_age_seconds: number | null;
    readonly blocked_outbox_count: NonNegativeInt64String;
    readonly blocked_fanout_predecessor_sequence: PositiveInt64String | null;
    readonly blocked_fanout_reason_code: string | null;
  };
  readonly delivery_pressure: {
    readonly ready_count: NonNegativeInt64String;
    readonly retry_wait_count: NonNegativeInt64String;
    readonly sending_count: NonNegativeInt64String;
    readonly unknown_outcome_count: NonNegativeInt64String;
    readonly open_circuits_count: number;
    readonly half_open_circuits_count: number;
    readonly quarantined_endpoints_count: number;
  };
  readonly budgets: {
    readonly active_send_slots: number;
    readonly approved_send_slots: number;
    readonly held_rate_reservations: number;
    readonly rate_requests_per_second: number;
    readonly rate_burst: number;
    readonly draining_policy_count: number;
  };
  readonly capabilities: readonly CapabilityEntryDto[];
}

export interface InstallationStatusDto {
  readonly mode: InstallationMode;
  readonly control_epoch: CanonicalUuid;
  readonly allow_event_admission: boolean;
  readonly allow_publication: boolean;
  readonly allow_fanout: boolean;
  readonly allow_send: boolean;
  readonly allow_endpoint_verification: boolean;
  readonly governance_version: Int64String;
  readonly version: Int64String;
  readonly updated_at: CanonicalUtcTimestamp;
}

export interface TenantSummaryDto {
  readonly tenant_id: TenantId;
  readonly slug: string;
  readonly display_name: string;
  readonly state: TenantState;
  readonly governance_version: Int64String;
  readonly version: Int64String;
  readonly created_at: CanonicalUtcTimestamp;
  readonly capabilities?: readonly CapabilityEntryDto[] | undefined;
}

export interface PlatformRoleAssignmentDto {
  readonly assignment_id: CanonicalUuid;
  readonly principal_id: PrincipalId;
  readonly display_name: string;
  readonly role: PlatformRole;
  readonly state: PlatformRoleAssignmentState;
  readonly governance_version: Int64String;
  readonly created_at: CanonicalUtcTimestamp;
  readonly version: Int64String;
  readonly capabilities?: readonly CapabilityEntryDto[] | undefined;
}

export interface RecoveryReferenceDto {
  readonly incident_id: CanonicalUuid;
  readonly scope_kind: "installation" | "tenant" | "project";
  readonly state: string;
  readonly summary_code: string;
  readonly created_at: CanonicalUtcTimestamp;
}

export interface AuditEventDto {
  readonly audit_id: CanonicalUuid;
  readonly tenant_id: TenantId | null;
  readonly project_id: ProjectId | null;
  readonly actor_kind: string;
  readonly actor_reference: CanonicalUuid | null;
  readonly operator_reference: string | null;
  readonly action: string;
  readonly target_kind: string;
  readonly target_id: CanonicalUuid;
  readonly prior_version: Int64String | null;
  readonly resulting_version: Int64String | null;
  readonly candidate_sha256: Sha256Hex | null;
  readonly command_receipt_id: CanonicalUuid | null;
  readonly recorded_at: CanonicalUtcTimestamp;
  readonly safe_facts: Readonly<Record<string, unknown>>;
}

export interface EndpointSummaryDto {
  readonly endpoint_id: CanonicalUuid;
  readonly name: string;
  readonly state: EndpointState;
  readonly current_version: PositiveInt64String;
  readonly security_epoch: NonNegativeInt64String;
  readonly destination_url?: string | undefined;
  readonly normalized_host?: string | undefined;
  readonly configuration_sha256: Sha256Hex;
  readonly url_policy_version: string;
  readonly network_policy_version: string;
  readonly request_profile_version: string;
  readonly response_profile_version: string;
  readonly active_signing_policy_version: PositiveInt64String | null;
  readonly active_receiver_contract_id: CanonicalUuid | null;
  readonly active_receiver_contract_version: PositiveInt64String | null;
  readonly verification_state: EndpointVerificationIntentState | "not_started";
  readonly capabilities?: readonly CapabilityEntryDto[] | undefined;
}

export interface SigningKeyIntentDto {
  readonly intent_id: CanonicalUuid;
  readonly endpoint_id: CanonicalUuid;
  readonly endpoint_version: PositiveInt64String;
  readonly key_version_id: CanonicalUuid;
  readonly key_id: string;
  readonly state: SigningDeliveryIntentState;
  readonly sender_custody_destination_id: string;
  readonly receiver_custody_destination_id: string;
  readonly candidate_sha256: Sha256Hex;
  readonly expires_at: CanonicalUtcTimestamp;
  readonly version: Int64String;
}

export interface SigningKeyVersionDto {
  readonly key_version_id: CanonicalUuid;
  readonly key_id: string;
  readonly endpoint_id: CanonicalUuid;
  readonly algorithm: string;
  readonly state: SigningKeyVersionState;
  readonly created_at: CanonicalUtcTimestamp;
  readonly sign_until: CanonicalUtcTimestamp | null;
  readonly verify_until: CanonicalUtcTimestamp | null;
  readonly version: Int64String;
  readonly capabilities?: readonly CapabilityEntryDto[] | undefined;
}

export interface SigningPolicyDto {
  readonly policy_id: CanonicalUuid;
  readonly endpoint_id: CanonicalUuid;
  readonly policy_version: PositiveInt64String;
  readonly signature_mode: SignatureMode;
  readonly primary_key_version_id: CanonicalUuid;
  readonly overlap_key_version_id: CanonicalUuid | null;
  readonly overlap_started_at: CanonicalUtcTimestamp | null;
  readonly overlap_ends_at: CanonicalUtcTimestamp | null;
  readonly old_key_sign_until: CanonicalUtcTimestamp | null;
  readonly old_key_verify_until: CanonicalUtcTimestamp | null;
  readonly policy_sha256: Sha256Hex;
  readonly state: "draft" | "active" | "retired";
  readonly capabilities?: readonly CapabilityEntryDto[] | undefined;
}

export interface EndpointVerificationIntentDto {
  readonly intent_id: CanonicalUuid;
  readonly endpoint_id: CanonicalUuid;
  readonly endpoint_version: PositiveInt64String;
  readonly key_version_id: CanonicalUuid;
  readonly purpose: "verify_destination_and_key" | "verify_rotation_key";
  readonly configuration_sha256: Sha256Hex;
  readonly receiver_contract_id: CanonicalUuid | null;
  readonly receiver_contract_version: PositiveInt64String | null;
  readonly receiver_contract_sha256: Sha256Hex | null;
  readonly state: EndpointVerificationIntentState;
  readonly attempts_used: number;
  readonly max_attempts: number;
  readonly proof_digest_sha256: Sha256Hex | null;
  readonly failure_reason_code: string | null;
  readonly expires_at: CanonicalUtcTimestamp;
  readonly version: Int64String;
}

export interface RetainedDispatchGrantDto {
  readonly grant_id: CanonicalUuid;
  readonly endpoint_id: CanonicalUuid;
  readonly retained_endpoint_version: PositiveInt64String;
  readonly state: "active" | "revoked" | "expired";
  readonly expires_at: CanonicalUtcTimestamp;
  readonly version: Int64String;
  readonly capabilities?: readonly CapabilityEntryDto[] | undefined;
}

export interface EventTypeDto {
  readonly event_type_id: CanonicalUuid;
  readonly type_name: string;
  readonly state: "draft" | "active" | "retired";
  readonly version: Int64String;
  readonly current_schema_version: number | null;
  readonly schema_versions: readonly EventSchemaVersionDto[];
}

export interface EventSchemaVersionDto {
  readonly schema_id: CanonicalUuid;
  readonly event_type_id: CanonicalUuid;
  readonly schema_version: number;
  readonly dialect: string;
  readonly profile_version: string;
  readonly compatibility_policy: SchemaCompatibilityPolicy;
  readonly definition_sha256: Sha256Hex;
  readonly state: "draft" | "published" | "retired";
  readonly version: Int64String;
  readonly capabilities?: readonly CapabilityEntryDto[] | undefined;
}

export interface RepresentationProfileDto {
  readonly profile_id: CanonicalUuid;
  readonly name: string;
  readonly event_type_id: CanonicalUuid;
  readonly current_version: PositiveInt64String | null;
  readonly version: Int64String;
  readonly versions: readonly RepresentationProfileVersionDto[];
}

export interface RepresentationProfileVersionDto {
  readonly version_id: CanonicalUuid;
  readonly profile_id: CanonicalUuid;
  readonly profile_version: PositiveInt64String;
  readonly source_schema_version: number;
  readonly target_schema_version: number;
  readonly compiler_profile_version: string;
  readonly definition_sha256: Sha256Hex;
  readonly proven_output_max_bytes: number;
  readonly state: "draft" | "active" | "retired";
  readonly version: Int64String;
  readonly capabilities?: readonly CapabilityEntryDto[] | undefined;
}

export interface ReceiverContractDto {
  readonly contract_id: CanonicalUuid;
  readonly endpoint_id: CanonicalUuid;
  readonly name: string;
  readonly consumer_contract_scope: string;
  readonly current_version: PositiveInt64String | null;
  readonly versions: readonly ReceiverContractVersionDto[];
}

export interface ReceiverContractVersionDto {
  readonly version_id: CanonicalUuid;
  readonly contract_id: CanonicalUuid;
  readonly contract_version: PositiveInt64String;
  readonly envelope_version: number;
  readonly receipt_profile: ReceiptProfile;
  readonly ordering_profile: OrderingProfile;
  readonly allowed_business_key_ids: readonly string[];
  readonly definition_sha256: Sha256Hex;
  readonly state: ReceiverContractState;
  readonly verified_at: CanonicalUtcTimestamp | null;
  readonly version: Int64String;
  readonly capabilities?: readonly CapabilityEntryDto[] | undefined;
}

export interface SubscriptionSummaryDto {
  readonly subscription_id: CanonicalUuid;
  readonly name: string;
  readonly state: SubscriptionState;
  readonly send_hold: boolean;
  readonly current_version: PositiveInt64String;
  readonly version_id: CanonicalUuid;
  readonly endpoint_id: CanonicalUuid;
  readonly endpoint_version: PositiveInt64String;
  readonly event_type_id: CanonicalUuid;
  readonly selected_schema_versions: readonly number[];
  readonly ordering_mode: OrderingMode;
  readonly ordering_domain_id: CanonicalUuid | null;
  readonly ordering_key_pointer: string | null;
  readonly consumer_contract_scope: string;
  readonly receiver_contract_id: CanonicalUuid;
  readonly receiver_contract_version: PositiveInt64String;
  readonly configuration_sha256: Sha256Hex;
  readonly filter_summary: string;
  readonly topology_from_version: PositiveInt64String | null;
  readonly topology_until_version: PositiveInt64String | null;
  readonly pending_delivery_count: NonNegativeInt64String;
  readonly capabilities?: readonly CapabilityEntryDto[] | undefined;
}

export interface OrderingKeySummaryDto {
  readonly ordering_key_id: CanonicalUuid;
  readonly subscription_id: CanonicalUuid;
  readonly ordering_domain_id: CanonicalUuid;
  readonly consumer_contract_scope: string;
  readonly key_digest_sha256: Sha256Hex;
  readonly extracted_key_value?: string | undefined;
  readonly state: "active" | "blocked";
  readonly next_eligible_sequence: PositiveInt64String;
  readonly next_allocate_sequence: PositiveInt64String;
  readonly blocked_delivery_id: CanonicalUuid | null;
  readonly blocked_reason_code: string | null;
  readonly version: Int64String;
  readonly capabilities?: readonly CapabilityEntryDto[] | undefined;
}

export interface OrderingMemberDto {
  readonly ordering_key_id: CanonicalUuid;
  readonly ordering_sequence: PositiveInt64String;
  readonly member_kind: OrderingMemberKind;
  readonly delivery_id: CanonicalUuid;
  readonly delivery_generation: NonNegativeInt64String;
  readonly state: OrderingMemberState;
  readonly disposition_decision: string | null;
  readonly recorded_at: CanonicalUtcTimestamp;
}

export interface OrderSkipProposalDto {
  readonly proposal_id: CanonicalUuid;
  readonly ordering_key_id: CanonicalUuid;
  readonly delivery_id: CanonicalUuid;
  readonly state: ProposalState;
  readonly version: Int64String;
  readonly candidate_sha256: Sha256Hex;
  readonly prior_sequence: PositiveInt64String;
  readonly resulting_sequence: PositiveInt64String;
  readonly known_outcome_class: string | null;
  readonly proposer_principal_id: PrincipalId;
  readonly created_at: CanonicalUtcTimestamp;
  readonly expires_at: CanonicalUtcTimestamp;
  readonly capabilities?: readonly CapabilityEntryDto[] | undefined;
}

export interface OrderingCutoverPlanDto {
  readonly plan_id: CanonicalUuid;
  readonly subscription_id: CanonicalUuid;
  readonly source_version: PositiveInt64String;
  readonly target_version: PositiveInt64String;
  readonly state: OrderingCutoverPlanState;
  readonly candidate_sha256: Sha256Hex;
  readonly boundary_project_sequence: PositiveInt64String | null;
  readonly materialized_through_event_sequence: NonNegativeInt64String;
  readonly old_heads_remaining: NonNegativeInt64String;
  readonly unknown_attempts_remaining: NonNegativeInt64String;
  readonly expires_at: CanonicalUtcTimestamp;
  readonly version: Int64String;
  readonly capabilities?: readonly CapabilityEntryDto[] | undefined;
}

export interface EndpointCircuitDto {
  readonly circuit_id: CanonicalUuid;
  readonly endpoint_id: CanonicalUuid;
  readonly endpoint_version: PositiveInt64String;
  readonly endpoint_state: EndpointState;
  readonly state: CircuitState;
  readonly circuit_generation: NonNegativeInt64String;
  readonly probe_generation: NonNegativeInt64String;
  readonly consecutive_transient_failures: number;
  readonly reopen_count: number;
  readonly reopen_not_before: CanonicalUtcTimestamp | null;
  readonly probe_attempt_id: CanonicalUuid | null;
  readonly probe_expires_at: CanonicalUtcTimestamp | null;
  readonly window_started_at: CanonicalUtcTimestamp;
  readonly window_success_count: number;
  readonly window_failure_count: number;
  readonly active_probe_request?: {
    readonly request_id: CanonicalUuid;
    readonly state: CircuitProbeRequestState;
    readonly prepared_attempt_id: CanonicalUuid | null;
    readonly expires_at: CanonicalUtcTimestamp;
  } | null | undefined;
  readonly version: Int64String;
  readonly capabilities?: readonly CapabilityEntryDto[] | undefined;
}

export interface ProducerSummaryDto {
  readonly producer_id: CanonicalUuid;
  readonly name: string;
  readonly business_namespace: string;
  readonly state: ProducerState;
  readonly current_scope_version: PositiveInt64String | null;
  readonly authority_epoch: NonNegativeInt64String;
  readonly version: Int64String;
  readonly scopes: readonly ProducerScopeVersionDto[];
  readonly credentials: readonly ProducerCredentialDto[];
  readonly credential_intents: readonly ProducerCredentialIntentDto[];
  readonly capabilities?: readonly CapabilityEntryDto[] | undefined;
}

export interface ProducerScopeVersionDto {
  readonly scope_id: CanonicalUuid;
  readonly scope_version: PositiveInt64String;
  readonly state: ProducerScopeVersionState;
  readonly scope_sha256: Sha256Hex;
  readonly allowed_actions: readonly ProducerScopeAction[];
  readonly allowed_event_count: number;
  readonly version: Int64String;
  readonly capabilities?: readonly CapabilityEntryDto[] | undefined;
}

export interface ProducerCredentialDto {
  readonly credential_id: CanonicalUuid;
  readonly selector_prefix: string;
  readonly state: ProducerCredentialState;
  readonly scope_version: PositiveInt64String;
  readonly created_at: CanonicalUtcTimestamp;
  readonly expires_at: CanonicalUtcTimestamp;
  readonly overlap_ends_at: CanonicalUtcTimestamp | null;
  readonly version: Int64String;
  readonly capabilities?: readonly CapabilityEntryDto[] | undefined;
}

export interface ProducerCredentialIntentDto {
  readonly intent_id: CanonicalUuid;
  readonly scope_version: PositiveInt64String;
  readonly scope_sha256: Sha256Hex;
  readonly custody_destination_id: string;
  readonly state: ProducerCredentialIntentState;
  readonly requested_expires_at: CanonicalUtcTimestamp;
  readonly expires_at: CanonicalUtcTimestamp;
  readonly version: Int64String;
}

export interface RatePolicyChangeDto {
  readonly change_id: CanonicalUuid;
  readonly scope_kind: RatePolicyChangeScopeKind;
  readonly owner_id: CanonicalUuid;
  readonly operation: RateBucketOperation;
  readonly state: RatePolicyChangeState;
  readonly requests_per_second: number;
  readonly burst: number;
  readonly microtokens_per_request: string;
  readonly held_reservation_count: number;
  readonly candidate_sha256: Sha256Hex;
  readonly version: Int64String;
  readonly capabilities?: readonly CapabilityEntryDto[] | undefined;
}

export interface CapacityAndDispatchDto {
  readonly dispatch_domain_id: CanonicalUuid;
  readonly policy_epoch: NonNegativeInt64String;
  readonly eligible_population_label: string;
  readonly project_weight: number;
  readonly active_send_slots: number;
  readonly approved_send_slots: number;
  readonly held_rate_reservations: number;
  readonly rate_requests_per_second: number;
  readonly rate_burst: number;
  readonly microtokens_per_request: string;
  readonly observed_at: CanonicalUtcTimestamp;
}

export interface ProjectMembershipDto {
  readonly membership_id: CanonicalUuid;
  readonly principal_id: PrincipalId;
  readonly display_name: string;
  readonly role: ProjectRole;
  readonly state: MembershipState;
  readonly authority_version: Int64String;
  readonly governance_version: Int64String;
  readonly version: Int64String;
  readonly capabilities?: readonly CapabilityEntryDto[] | undefined;
}

export interface HumanDataGrantDto {
  readonly grant_id: CanonicalUuid;
  readonly membership_id: CanonicalUuid;
  readonly principal_id: PrincipalId;
  readonly action: DataGrantAction;
  readonly projection: DataGrantProjection;
  readonly producer_namespace: string | null;
  readonly state: DataGrantState;
  readonly expires_at: CanonicalUtcTimestamp | null;
  readonly created_at: CanonicalUtcTimestamp;
  readonly version: Int64String;
  readonly capabilities?: readonly CapabilityEntryDto[] | undefined;
}

export interface RetentionHoldDto {
  readonly hold_id: CanonicalUuid;
  readonly target_kind: RetentionHoldTargetKind;
  readonly target_id: CanonicalUuid;
  readonly reason_code: string;
  readonly state: RetentionHoldState;
  readonly review_at: CanonicalUtcTimestamp;
  readonly expires_at: CanonicalUtcTimestamp | null;
  readonly version: Int64String;
  readonly capabilities?: readonly CapabilityEntryDto[] | undefined;
}

export interface DeliveryNetworkDecisionDto {
  readonly decision_id: CanonicalUuid;
  readonly attempt_id: CanonicalUuid;
  readonly policy_sha256: Sha256Hex;
  readonly registry_sha256: Sha256Hex;
  readonly dns_answer_sha256: Sha256Hex;
  readonly pinned_peer_sha256: Sha256Hex;
  readonly ip_family: "ipv4" | "ipv6";
  readonly decision: "allowed" | "denied";
  readonly reason_code: string | null;
  readonly observed_at: CanonicalUtcTimestamp;
}

export interface DeliveryHistoryEntryDto {
  readonly delivery_id: CanonicalUuid;
  readonly history_sequence: PositiveInt64String;
  readonly event_kind: string;
  readonly supported_event_type: boolean;
  readonly recorded_at: CanonicalUtcTimestamp;
  readonly safe_facts: Readonly<Record<string, unknown>>;
}

export interface TraceReferenceDto {
  readonly trace_id: string;
  readonly span_id: string;
  readonly view_url: string | null;
  readonly availability: ContentAvailability;
}

export interface GenericMutationResultDto {
  readonly receipt?: AcceptedReceiptDto | undefined;
  readonly [key: string]: unknown;
}

export type CommercialPlanTierDto = "free" | "pro" | "team" | "enterprise";
export type CommercialBillingIntervalDto = "month" | "year";
export type CommercialBillingProviderDto = "stripe" | "paystack" | "tap";

export interface PublicStatusComponentDto {
  readonly name: string;
  readonly status: "operational" | "degraded" | "maintenance";
  readonly pending_events?: number | undefined;
  readonly success_rate_24h?: number | undefined;
}

export interface PublicStatusDto {
  readonly service: string;
  readonly overall_status: "operational" | "degraded" | "maintenance";
  readonly checked_at: CanonicalUtcTimestamp;
  readonly components: readonly PublicStatusComponentDto[];
}

export interface CommercialSignupResponseDto {
  readonly user_id: CanonicalUuid;
  readonly principal_id: PrincipalId;
  readonly tenant_id: CanonicalUuid;
  readonly tenant_slug: string;
  readonly role: string;
  readonly plan_tier: CommercialPlanTierDto;
  readonly mfa_enrolled: boolean;
  readonly tos_version: string;
  readonly dpa_version: string;
  readonly csrf_token: string;
}

export interface CommercialLoginResponseDto {
  readonly user_id: CanonicalUuid;
  readonly principal_id: PrincipalId;
  readonly tenant_id: CanonicalUuid;
  readonly role: string;
  readonly mfa_enrolled: boolean;
  readonly csrf_token: string;
}

export interface TotpEnrollResponseDto {
  readonly otpauth_uri: string;
  readonly secret_base32: string;
  readonly enrolled: boolean;
}

export interface TotpVerifyResponseDto {
  readonly enrolled: boolean;
}

export interface LegalAcceptResponseDto {
  readonly acceptance_id: CanonicalUuid;
  readonly tenant_id: CanonicalUuid;
  readonly document_kind: "tos" | "privacy" | "dpa";
  readonly doc_version: string;
  readonly accepted_at: CanonicalUtcTimestamp;
}

export interface BillingRegionalRoutingDto {
  readonly provider: CommercialBillingProviderDto;
  readonly countryCode: string;
  readonly currency: string;
  readonly regionLabel: string;
  readonly taxAutomation: boolean;
}

export interface BillingUsageRollupDto {
  readonly metric_code: string;
  readonly total_billable_units: string | number;
  readonly total_free_units: string | number;
  readonly total_cogs_micros?: string | number | undefined;
  readonly alert_70_sent_at?: CanonicalUtcTimestamp | null | undefined;
  readonly alert_85_sent_at?: CanonicalUtcTimestamp | null | undefined;
  readonly alert_95_sent_at?: CanonicalUtcTimestamp | null | undefined;
  readonly spike_alert_sent_at?: CanonicalUtcTimestamp | null | undefined;
}

export interface BillingUsageEventDto {
  readonly usage_event_id: CanonicalUuid;
  readonly idempotency_key: string;
  readonly metric_code: string;
  readonly billable_units: string | number;
  readonly billed_reason: string;
  readonly currency: string;
  readonly unit_price_minor: string | number;
  readonly created_at: CanonicalUtcTimestamp;
}

export interface BillingSubscriptionViewDto {
  readonly org_id: CanonicalUuid;
  readonly period_month: string;
  readonly customer: Readonly<Record<string, unknown>> | null;
  readonly subscription: {
    readonly subscription_id?: CanonicalUuid | undefined;
    readonly stripe_subscription_id?: string | null | undefined;
    readonly plan_tier: CommercialPlanTierDto;
    readonly entitlement_state: string;
    readonly billing_interval: CommercialBillingIntervalDto;
    readonly currency: string;
    readonly unit_amount_minor: number;
    readonly seat_count: number;
    readonly current_period_start?: CanonicalUtcTimestamp | undefined;
    readonly current_period_end?: CanonicalUtcTimestamp | undefined;
    readonly trial_ends_at?: CanonicalUtcTimestamp | null | undefined;
    readonly grace_ends_at?: CanonicalUtcTimestamp | null | undefined;
    readonly cancel_at_period_end: boolean;
  };
  readonly quotas: {
    readonly max_seats: number;
    readonly max_concurrency: number;
    readonly included_units_month: number | string;
    readonly overage_unit_minor: number;
    readonly cap_mode: "hard_cap" | "soft_cap";
    readonly retention_days: number;
    readonly sso_enabled: boolean;
  };
  readonly usage_rollups: readonly BillingUsageRollupDto[];
  readonly regional_routing: BillingRegionalRoutingDto;
  readonly configured_providers: readonly CommercialBillingProviderDto[];
}

export interface BillingUsageViewDto {
  readonly org_id: CanonicalUuid;
  readonly period_month: string;
  readonly rollups: readonly BillingUsageRollupDto[];
  readonly events: readonly BillingUsageEventDto[];
}

export interface BillingCheckoutResponseDto {
  readonly org_id: CanonicalUuid;
  readonly provider: CommercialBillingProviderDto;
  readonly session_id: string;
  readonly checkout_url: string;
  readonly currency: string;
  readonly amount_minor: number;
  readonly tax_automation_enabled: boolean;
  readonly regional_routing: BillingRegionalRoutingDto;
}

export interface BillingPortalResponseDto {
  readonly org_id: CanonicalUuid;
  readonly provider: CommercialBillingProviderDto;
  readonly hosted_portal: boolean;
  readonly portal_url: string;
  readonly self_serve_cancel_endpoint?: string | undefined;
}

export interface BillingCancelResponseDto {
  readonly org_id: CanonicalUuid;
  readonly previous_state: string;
  readonly entitlement_state: string;
  readonly cancel_at_period_end: boolean;
}

export interface CustomerAuditEventDto {
  readonly audit_id: CanonicalUuid;
  readonly actor_kind: string;
  readonly actor_reference: string | null;
  readonly action: string;
  readonly target_kind: string;
  readonly target_id: string;
  readonly metadata: Readonly<Record<string, unknown>>;
  readonly occurred_at: CanonicalUtcTimestamp;
}

export interface BreakGlassSessionSummaryDto {
  readonly break_glass_id: CanonicalUuid;
  readonly operator_id: string;
  readonly reason: string;
  readonly read_only: boolean;
  readonly started_at: CanonicalUtcTimestamp;
  readonly expires_at: CanonicalUtcTimestamp;
  readonly revoked_at: CanonicalUtcTimestamp | null;
}

export interface CustomerSettingsAuditDto {
  readonly tenant_id: CanonicalUuid;
  readonly audit_events: readonly CustomerAuditEventDto[];
  readonly break_glass_sessions: readonly BreakGlassSessionSummaryDto[];
}

export interface BreakGlassCreateResponseDto {
  readonly break_glass_id: CanonicalUuid;
  readonly target_tenant_id: CanonicalUuid;
  readonly read_only: boolean;
  readonly token_once: string;
  readonly started_at: CanonicalUtcTimestamp;
  readonly expires_at: CanonicalUtcTimestamp;
  readonly customer_audit_logged: boolean;
}

export interface BreakGlassRevokeResponseDto {
  readonly break_glass_id: CanonicalUuid;
  readonly target_tenant_id: CanonicalUuid;
  readonly revoked_at: CanonicalUtcTimestamp;
}

export interface GdprErasureRequestDto {
  readonly erasure_request_id: CanonicalUuid;
  readonly org_id: CanonicalUuid;
  readonly state: string;
  readonly tax_records_retained_anonymized_years?: number | undefined;
  readonly receipt_sha256: string | null;
  readonly requested_at: CanonicalUtcTimestamp;
  readonly completed_at?: CanonicalUtcTimestamp | null | undefined;
}

export function parsePlainObjectDto<T extends object>(raw: unknown, fieldPath = "data"): T {
  return assertPlainRecord(raw, fieldPath) as unknown as T;
}

export function parseSessionContextDto(raw: unknown): SessionContextDto {
  const rec = assertPlainRecord(raw, "session_context");
  if (
    typeof rec.session_id !== "string" ||
    typeof rec.principal_id !== "string" ||
    typeof rec.csrf_token !== "string"
  ) {
    throw new Error("Malformed session context payload");
  }
  return rec as unknown as SessionContextDto;
}

export function parseCapabilitiesList(raw: unknown): readonly CapabilityEntryDto[] {
  if (raw === undefined) {
    return [];
  }
  return parseCapabilities(raw, "capabilities");
}
