export const PRINCIPAL_KINDS = ["human", "producer"] as const;
export type PrincipalKind = (typeof PRINCIPAL_KINDS)[number];

export const PRINCIPAL_STATES = ["pending", "active", "suspended", "retired"] as const;
export type PrincipalState = (typeof PRINCIPAL_STATES)[number];

export const PLATFORM_ROLES = ["platform_admin", "platform_auditor"] as const;
export type PlatformRole = (typeof PLATFORM_ROLES)[number];

export const TENANT_ROLES = ["tenant_admin"] as const;
export type TenantRole = (typeof TENANT_ROLES)[number];

export const PROJECT_ROLES = [
  "project_admin",
  "integrator",
  "operator",
  "publisher",
  "observer"
] as const;
export type ProjectRole = (typeof PROJECT_ROLES)[number];

export const MEMBERSHIP_STATES = ["pending", "active", "suspended", "revoked"] as const;
export type MembershipState = (typeof MEMBERSHIP_STATES)[number];

export const PLATFORM_ROLE_ASSIGNMENT_STATES = ["active", "revoked"] as const;
export type PlatformRoleAssignmentState = (typeof PLATFORM_ROLE_ASSIGNMENT_STATES)[number];

export const CHANNEL_KINDS = ["machine_producer", "human_workflow"] as const;
export type ChannelKind = (typeof CHANNEL_KINDS)[number];

export const EVIDENCE_BOUNDARIES = [
  "accepted",
  "published",
  "http_acknowledged",
  "consumer_processed"
] as const;
export type EvidenceBoundary = (typeof EVIDENCE_BOUNDARIES)[number];

export const OVERVIEW_STAGE_SUMMARIES = [
  "accepted_events",
  "broker_stored_notifications",
  "completed_event_fanout",
  "http_acknowledged_delivery_generations",
  "verified_receiver_receipt_observations"
] as const;
export type OverviewStageSummary = (typeof OVERVIEW_STAGE_SUMMARIES)[number];

export const ACCEPTANCE_STATUSES = ["known_rejected", "unknown", "not_applicable"] as const;
export type AcceptanceStatus = (typeof ACCEPTANCE_STATUSES)[number];

export const RECEIPT_VERIFICATION_STATES = [
  "unverified",
  "verified_supported",
  "rejected"
] as const;
export type ReceiptVerificationState = (typeof RECEIPT_VERIFICATION_STATES)[number];

export const RECEIPT_PROFILES = ["http_ack_only", "receiver_local_commit_v1"] as const;
export type ReceiptProfile = (typeof RECEIPT_PROFILES)[number];

export const ORDERING_PROFILES = ["unordered", "receiver_strict_key_v1"] as const;
export type OrderingProfile = (typeof ORDERING_PROFILES)[number];

export const ORDERING_MODES = ["unordered", "strict_per_key"] as const;
export type OrderingMode = (typeof ORDERING_MODES)[number];

export const DELIVERY_POPULATIONS = ["original", "replay", "all"] as const;
export type DeliveryPopulation = (typeof DELIVERY_POPULATIONS)[number];

export const DATA_GRANT_ACTIONS = [
  "events.content.read",
  "deliveries.request.read",
  "receiver_receipts.read"
] as const;
export type DataGrantAction = (typeof DATA_GRANT_ACTIONS)[number];

export const DATA_GRANT_PROJECTIONS = ["own_namespace", "approved_project"] as const;
export type DataGrantProjection = (typeof DATA_GRANT_PROJECTIONS)[number];

export const DATA_GRANT_STATES = ["active", "revoked"] as const;
export type DataGrantState = (typeof DATA_GRANT_STATES)[number];

export const PRODUCER_SCOPE_ACTIONS = [
  "events.admit",
  "events.resolve",
  "events.read_own",
  "events.content.read_own",
  "events.watch_own",
  "deliveries.read_own"
] as const;
export type ProducerScopeAction = (typeof PRODUCER_SCOPE_ACTIONS)[number];

export const CONTENT_AVAILABILITIES = [
  "available",
  "expired",
  "not_generated",
  "unsupported",
  "unavailable"
] as const;
export type ContentAvailability = (typeof CONTENT_AVAILABILITIES)[number];

export const CONTENT_VIEWS = ["original", "derived", "wire"] as const;
export type ContentView = (typeof CONTENT_VIEWS)[number];

export const EXTERNAL_ATTEMPT_OUTCOMES = [
  "not_started",
  "acknowledged",
  "observed_non_success",
  "unknown",
  "unavailable"
] as const;
export type ExternalAttemptOutcome = (typeof EXTERNAL_ATTEMPT_OUTCOMES)[number];

export const COMMAND_RECEIPT_SCOPE_KINDS = ["installation", "tenant", "project"] as const;
export type CommandReceiptScopeKind = (typeof COMMAND_RECEIPT_SCOPE_KINDS)[number];

export const RATE_BUCKET_OPERATIONS = [
  "event_admission",
  "send_start",
  "endpoint_verification",
  "replay_admission"
] as const;
export type RateBucketOperation = (typeof RATE_BUCKET_OPERATIONS)[number];

export const RATE_POLICY_CHANGE_SCOPE_KINDS = [
  "tenant",
  "project",
  "endpoint",
  "producer"
] as const;
export type RatePolicyChangeScopeKind = (typeof RATE_POLICY_CHANGE_SCOPE_KINDS)[number];

export const ACTOR_KINDS = ["human", "producer"] as const;
export type ActorKind = (typeof ACTOR_KINDS)[number];

export const PROCESS_ROLES = [
  "api",
  "relay",
  "fanout",
  "sender",
  "coordinator",
  "protected_admin"
] as const;
export type ProcessRole = (typeof PROCESS_ROLES)[number];

export const WEBHOOK_PURPOSES = ["delivery", "endpoint_verification"] as const;
export type WebhookPurpose = (typeof WEBHOOK_PURPOSES)[number];

export const ENDPOINT_VERIFICATION_PURPOSES = [
  "verify_destination_and_key",
  "verify_rotation_key"
] as const;
export type EndpointVerificationPurpose = (typeof ENDPOINT_VERIFICATION_PURPOSES)[number];

export const SIGNATURE_MODES = ["primary_only", "bounded_dual_signature"] as const;
export type SignatureMode = (typeof SIGNATURE_MODES)[number];

export const REPLAY_STRATEGIES = [
  "replay_exact_original",
  "replay_with_reviewed_representation"
] as const;
export type ReplayStrategy = (typeof REPLAY_STRATEGIES)[number];

export const REPLAY_ORDERING_STRATEGIES = [
  "append_after_current_tail",
  "not_applicable"
] as const;
export type ReplayOrderingStrategy = (typeof REPLAY_ORDERING_STRATEGIES)[number];

export const SCHEMA_COMPATIBILITY_POLICIES = [
  "additive_compatible",
  "new_breaking_version"
] as const;
export type SchemaCompatibilityPolicy = (typeof SCHEMA_COMPATIBILITY_POLICIES)[number];

export const POLICY_KINDS = [
  "admission",
  "response",
  "retry",
  "circuit",
  "url",
  "network",
  "request",
  "retention",
  "rate",
  "dispatch"
] as const;
export type PolicyKind = (typeof POLICY_KINDS)[number];

export const PROJECTION_VERIFICATION_STATUSES = [
  "matched",
  "mismatched",
  "unavailable",
  "unsupported"
] as const;
export type ProjectionVerificationStatus = (typeof PROJECTION_VERIFICATION_STATUSES)[number];

export const ORDER_DISPOSITION_DECISIONS = [
  "reviewed_skip_without_processing_claim"
] as const;
export type OrderDispositionDecision = (typeof ORDER_DISPOSITION_DECISIONS)[number];

export const RECEIVER_ACCEPTANCE_KINDS = [
  "first_business_commit",
  "duplicate_business_anchor"
] as const;
export type ReceiverAcceptanceKind = (typeof RECEIVER_ACCEPTANCE_KINDS)[number];

export function createEnumGuard<T extends string>(values: readonly T[]): (value: unknown) => value is T {
  const allowed = new Set<string>(values);
  return (value: unknown): value is T => typeof value === "string" && allowed.has(value);
}

export const isPrincipalKind = createEnumGuard(PRINCIPAL_KINDS);
export const isPrincipalState = createEnumGuard(PRINCIPAL_STATES);
export const isPlatformRole = createEnumGuard(PLATFORM_ROLES);
export const isTenantRole = createEnumGuard(TENANT_ROLES);
export const isProjectRole = createEnumGuard(PROJECT_ROLES);
export const isMembershipState = createEnumGuard(MEMBERSHIP_STATES);
export const isPlatformRoleAssignmentState = createEnumGuard(PLATFORM_ROLE_ASSIGNMENT_STATES);
export const isChannelKind = createEnumGuard(CHANNEL_KINDS);
export const isEvidenceBoundary = createEnumGuard(EVIDENCE_BOUNDARIES);
export const isOverviewStageSummary = createEnumGuard(OVERVIEW_STAGE_SUMMARIES);
export const isAcceptanceStatus = createEnumGuard(ACCEPTANCE_STATUSES);
export const isReceiptVerificationState = createEnumGuard(RECEIPT_VERIFICATION_STATES);
export const isReceiptProfile = createEnumGuard(RECEIPT_PROFILES);
export const isOrderingProfile = createEnumGuard(ORDERING_PROFILES);
export const isOrderingMode = createEnumGuard(ORDERING_MODES);
export const isDeliveryPopulation = createEnumGuard(DELIVERY_POPULATIONS);
export const isDataGrantAction = createEnumGuard(DATA_GRANT_ACTIONS);
export const isDataGrantProjection = createEnumGuard(DATA_GRANT_PROJECTIONS);
export const isDataGrantState = createEnumGuard(DATA_GRANT_STATES);
export const isProducerScopeAction = createEnumGuard(PRODUCER_SCOPE_ACTIONS);
export const isContentAvailability = createEnumGuard(CONTENT_AVAILABILITIES);
export const isContentView = createEnumGuard(CONTENT_VIEWS);
export const isExternalAttemptOutcome = createEnumGuard(EXTERNAL_ATTEMPT_OUTCOMES);
export const isCommandReceiptScopeKind = createEnumGuard(COMMAND_RECEIPT_SCOPE_KINDS);
export const isRateBucketOperation = createEnumGuard(RATE_BUCKET_OPERATIONS);
export const isRatePolicyChangeScopeKind = createEnumGuard(RATE_POLICY_CHANGE_SCOPE_KINDS);
export const isActorKind = createEnumGuard(ACTOR_KINDS);
export const isProcessRole = createEnumGuard(PROCESS_ROLES);
export const isWebhookPurpose = createEnumGuard(WEBHOOK_PURPOSES);
export const isEndpointVerificationPurpose = createEnumGuard(ENDPOINT_VERIFICATION_PURPOSES);
export const isSignatureMode = createEnumGuard(SIGNATURE_MODES);
export const isReplayStrategy = createEnumGuard(REPLAY_STRATEGIES);
export const isReplayOrderingStrategy = createEnumGuard(REPLAY_ORDERING_STRATEGIES);
export const isSchemaCompatibilityPolicy = createEnumGuard(SCHEMA_COMPATIBILITY_POLICIES);
export const isPolicyKind = createEnumGuard(POLICY_KINDS);
export const isProjectionVerificationStatus = createEnumGuard(PROJECTION_VERIFICATION_STATUSES);
export const isOrderDispositionDecision = createEnumGuard(ORDER_DISPOSITION_DECISIONS);
export const isReceiverAcceptanceKind = createEnumGuard(RECEIVER_ACCEPTANCE_KINDS);
