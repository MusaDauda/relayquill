import { createEnumGuard, ValidationDomainError } from "@relayquill/domain";
import {
  type CanonicalUuid,
  type Int64String,
  assertAllowedKeys,
  assertPlainRecord,
  parseBooleanField,
  parseCanonicalUuid,
  parseInt64String,
  parseSafeReasonCode
} from "./values.js";

export const CAPABILITY_TARGET_KINDS = [
  "installation",
  "tenant",
  "project",
  "membership",
  "data_grant",
  "platform_role_assignment",
  "event_type",
  "event_schema_version",
  "representation_profile",
  "representation_profile_version",
  "receiver_contract",
  "receiver_contract_version",
  "endpoint",
  "endpoint_version",
  "endpoint_circuit",
  "endpoint_verification_intent",
  "retained_dispatch_grant",
  "signing_key_version",
  "signing_delivery_intent",
  "signing_policy",
  "subscription",
  "subscription_version",
  "ordering_key",
  "ordering_cutover_plan",
  "event",
  "delivery",
  "replay_proposal",
  "order_skip_proposal",
  "suppression_proposal",
  "retention_hold",
  "rate_policy_change",
  "dispatch_domain",
  "producer",
  "producer_scope_version",
  "producer_credential",
  "producer_credential_intent"
] as const;

export type CapabilityTargetKind = (typeof CAPABILITY_TARGET_KINDS)[number];
export const isCapabilityTargetKind = createEnumGuard(CAPABILITY_TARGET_KINDS);

export const CAPABILITY_ACTIONS = [
  "events.admit",
  "events.resolve",
  "events.content.read",
  "deliveries.request.read",
  "deliveries.replay.propose",
  "deliveries.suppression.propose",
  "receiver_receipts.read",
  "replay_proposals.review",
  "replay_proposals.admit",
  "replay_proposals.withdraw",
  "order_skip_proposals.propose",
  "order_skip_proposals.review",
  "order_skip_proposals.admit",
  "suppression_proposals.review",
  "suppression_proposals.admit",
  "circuits.request_probe",
  "endpoints.create_version",
  "endpoints.verify",
  "endpoints.activate",
  "endpoints.pause",
  "endpoints.quarantine",
  "endpoints.resume",
  "endpoints.retire",
  "endpoints.retained_dispatch_grant.create",
  "endpoints.retained_dispatch_grant.revoke",
  "signing_key_intents.create",
  "signing_policies.create",
  "signing_policies.activate",
  "signing_keys.revoke",
  "subscriptions.create_version",
  "subscriptions.validate",
  "subscriptions.activate",
  "subscriptions.pause_future",
  "subscriptions.hold_sends",
  "subscriptions.pause_all",
  "subscriptions.resume_future",
  "subscriptions.release_send_hold",
  "subscriptions.retire",
  "ordering_cutovers.propose",
  "ordering_cutovers.begin",
  "ordering_cutovers.activate",
  "ordering_cutovers.abort",
  "event_schema_versions.validate",
  "event_schema_versions.publish",
  "event_schema_versions.retire",
  "representation_profiles.activate",
  "representation_profiles.retire",
  "receiver_contracts.verify",
  "receiver_contracts.activate",
  "publication_context.enable",
  "producers.create",
  "producers.scope_activate",
  "producers.credential_issue",
  "producers.credential_rotate",
  "producers.credential_revoke",
  "producers.suspend",
  "producers.retire",
  "projects.pause_admission",
  "projects.resume_admission",
  "projects.retire",
  "tenants.suspend",
  "tenants.restore",
  "tenants.retire",
  "memberships.change_role",
  "memberships.suspend",
  "memberships.revoke",
  "data_grants.create",
  "data_grants.revoke",
  "retention_holds.create",
  "retention_holds.release",
  "rate_policy_changes.propose",
  "rate_policy_changes.activate",
  "dispatch_policy_changes.apply"
] as const;

export type CapabilityAction = (typeof CAPABILITY_ACTIONS)[number];
export const isCapabilityAction = createEnumGuard(CAPABILITY_ACTIONS);

export interface CapabilityActionDefinition {
  readonly action: CapabilityAction;
  readonly targetKind: CapabilityTargetKind;
  readonly routePattern: string;
  readonly requiresStepUp: boolean;
  readonly requiresDistinctReviewer: boolean;
}

function def(
  action: CapabilityAction,
  targetKind: CapabilityTargetKind,
  routePattern: string,
  requiresStepUp = false,
  requiresDistinctReviewer = false
): CapabilityActionDefinition {
  return Object.freeze({
    action,
    targetKind,
    routePattern,
    requiresStepUp,
    requiresDistinctReviewer
  });
}

export const CAPABILITY_ACTION_REGISTRY: Readonly<
  Record<CapabilityAction, CapabilityActionDefinition>
> = Object.freeze({
  "events.admit": def("events.admit", "project", "POST /events"),
  "events.resolve": def("events.resolve", "project", "POST /events/resolve"),
  "events.content.read": def("events.content.read", "event", "GET /events/{event_id}/content"),
  "deliveries.request.read": def(
    "deliveries.request.read",
    "delivery",
    "GET /deliveries/{delivery_id}/request-content"
  ),
  "deliveries.replay.propose": def(
    "deliveries.replay.propose",
    "delivery",
    "POST /deliveries/{delivery_id}/replay-proposals"
  ),
  "deliveries.suppression.propose": def(
    "deliveries.suppression.propose",
    "delivery",
    "POST /deliveries/{delivery_id}/suppression-proposals"
  ),
  "receiver_receipts.read": def(
    "receiver_receipts.read",
    "delivery",
    "GET /deliveries/{delivery_id}/receiver-receipts"
  ),
  "replay_proposals.review": def(
    "replay_proposals.review",
    "replay_proposal",
    "POST /replay-proposals/{proposal_id}/reviews",
    true,
    true
  ),
  "replay_proposals.admit": def(
    "replay_proposals.admit",
    "replay_proposal",
    "POST /replay-proposals/{proposal_id}/admit",
    true,
    true
  ),
  "replay_proposals.withdraw": def(
    "replay_proposals.withdraw",
    "replay_proposal",
    "POST /replay-proposals/{proposal_id}/withdraw"
  ),
  "order_skip_proposals.propose": def(
    "order_skip_proposals.propose",
    "ordering_key",
    "POST /ordering-keys/{key_id}/skip-proposals"
  ),
  "order_skip_proposals.review": def(
    "order_skip_proposals.review",
    "order_skip_proposal",
    "POST /order-skip-proposals/{proposal_id}/reviews",
    true,
    true
  ),
  "order_skip_proposals.admit": def(
    "order_skip_proposals.admit",
    "order_skip_proposal",
    "POST /order-skip-proposals/{proposal_id}/admit",
    true,
    true
  ),
  "suppression_proposals.review": def(
    "suppression_proposals.review",
    "suppression_proposal",
    "POST /suppression-proposals/{proposal_id}/reviews",
    true,
    true
  ),
  "suppression_proposals.admit": def(
    "suppression_proposals.admit",
    "suppression_proposal",
    "POST /suppression-proposals/{proposal_id}/admit",
    true,
    true
  ),
  "circuits.request_probe": def(
    "circuits.request_probe",
    "endpoint_circuit",
    "POST /endpoints/{endpoint_id}/circuits/request-probe"
  ),
  "endpoints.create_version": def(
    "endpoints.create_version",
    "endpoint",
    "POST /endpoints/{endpoint_id}/versions"
  ),
  "endpoints.verify": def(
    "endpoints.verify",
    "endpoint",
    "POST /endpoints/{endpoint_id}/verification-intents",
    true
  ),
  "endpoints.activate": def(
    "endpoints.activate",
    "endpoint",
    "POST /endpoints/{endpoint_id}/activate",
    true
  ),
  "endpoints.pause": def("endpoints.pause", "endpoint", "POST /endpoints/{endpoint_id}/pause"),
  "endpoints.quarantine": def(
    "endpoints.quarantine",
    "endpoint",
    "POST /endpoints/{endpoint_id}/quarantine",
    true
  ),
  "endpoints.resume": def(
    "endpoints.resume",
    "endpoint",
    "POST /endpoints/{endpoint_id}/resume",
    true
  ),
  "endpoints.retire": def(
    "endpoints.retire",
    "endpoint",
    "POST /endpoints/{endpoint_id}/retire",
    true
  ),
  "endpoints.retained_dispatch_grant.create": def(
    "endpoints.retained_dispatch_grant.create",
    "endpoint",
    "POST /endpoints/{endpoint_id}/retained-dispatch-grants",
    true
  ),
  "endpoints.retained_dispatch_grant.revoke": def(
    "endpoints.retained_dispatch_grant.revoke",
    "retained_dispatch_grant",
    "POST /retained-dispatch-grants/{grant_id}/revoke",
    true
  ),
  "signing_key_intents.create": def(
    "signing_key_intents.create",
    "endpoint",
    "POST /endpoints/{endpoint_id}/signing-key-intents",
    true
  ),
  "signing_policies.create": def(
    "signing_policies.create",
    "endpoint",
    "POST /endpoints/{endpoint_id}/signing-policies",
    true
  ),
  "signing_policies.activate": def(
    "signing_policies.activate",
    "signing_policy",
    "POST /signing-policies/{policy_id}/activate",
    true
  ),
  "signing_keys.revoke": def(
    "signing_keys.revoke",
    "signing_key_version",
    "POST /signing-keys/{key_version_id}/revoke",
    true
  ),
  "subscriptions.create_version": def(
    "subscriptions.create_version",
    "subscription",
    "POST /subscriptions/{subscription_id}/versions"
  ),
  "subscriptions.validate": def(
    "subscriptions.validate",
    "subscription_version",
    "POST /subscription-versions/{version_id}/validate"
  ),
  "subscriptions.activate": def(
    "subscriptions.activate",
    "subscription_version",
    "POST /subscription-versions/{version_id}/activate",
    true
  ),
  "subscriptions.pause_future": def(
    "subscriptions.pause_future",
    "subscription",
    "POST /subscriptions/{subscription_id}/pause-future"
  ),
  "subscriptions.hold_sends": def(
    "subscriptions.hold_sends",
    "subscription",
    "POST /subscriptions/{subscription_id}/hold-sends"
  ),
  "subscriptions.pause_all": def(
    "subscriptions.pause_all",
    "subscription",
    "POST /subscriptions/{subscription_id}/pause-all"
  ),
  "subscriptions.resume_future": def(
    "subscriptions.resume_future",
    "subscription",
    "POST /subscriptions/{subscription_id}/resume-future",
    true
  ),
  "subscriptions.release_send_hold": def(
    "subscriptions.release_send_hold",
    "subscription",
    "POST /subscriptions/{subscription_id}/release-send-hold",
    true
  ),
  "subscriptions.retire": def(
    "subscriptions.retire",
    "subscription",
    "POST /subscriptions/{subscription_id}/retire",
    true
  ),
  "ordering_cutovers.propose": def(
    "ordering_cutovers.propose",
    "subscription",
    "POST /subscriptions/{subscription_id}/ordering-cutovers",
    true
  ),
  "ordering_cutovers.begin": def(
    "ordering_cutovers.begin",
    "ordering_cutover_plan",
    "POST /ordering-cutovers/{plan_id}/begin",
    true
  ),
  "ordering_cutovers.activate": def(
    "ordering_cutovers.activate",
    "ordering_cutover_plan",
    "POST /ordering-cutovers/{plan_id}/activate",
    true
  ),
  "ordering_cutovers.abort": def(
    "ordering_cutovers.abort",
    "ordering_cutover_plan",
    "POST /ordering-cutovers/{plan_id}/abort",
    true
  ),
  "event_schema_versions.validate": def(
    "event_schema_versions.validate",
    "event_schema_version",
    "POST /event-schema-versions/{schema_id}/validate"
  ),
  "event_schema_versions.publish": def(
    "event_schema_versions.publish",
    "event_schema_version",
    "POST /event-schema-versions/{schema_id}/publish",
    true
  ),
  "event_schema_versions.retire": def(
    "event_schema_versions.retire",
    "event_schema_version",
    "POST /event-schema-versions/{schema_id}/retire",
    true
  ),
  "representation_profiles.activate": def(
    "representation_profiles.activate",
    "representation_profile_version",
    "POST /representation-profile-versions/{version_id}/activate",
    true
  ),
  "representation_profiles.retire": def(
    "representation_profiles.retire",
    "representation_profile_version",
    "POST /representation-profile-versions/{version_id}/retire",
    true
  ),
  "receiver_contracts.verify": def(
    "receiver_contracts.verify",
    "receiver_contract_version",
    "POST /receiver-contract-versions/{version_id}/verification-intents",
    true
  ),
  "receiver_contracts.activate": def(
    "receiver_contracts.activate",
    "receiver_contract_version",
    "POST /receiver-contract-versions/{version_id}/activate",
    true
  ),
  "publication_context.enable": def(
    "publication_context.enable",
    "project",
    "POST /publication-context/enable"
  ),
  "producers.create": def("producers.create", "project", "POST /producers", true),
  "producers.scope_activate": def(
    "producers.scope_activate",
    "producer_scope_version",
    "POST /producer-scopes/{scope_id}/activate",
    true
  ),
  "producers.credential_issue": def(
    "producers.credential_issue",
    "producer",
    "POST /producers/{producer_id}/credential-intents",
    true
  ),
  "producers.credential_rotate": def(
    "producers.credential_rotate",
    "producer",
    "POST /producers/{producer_id}/credential-rotations",
    true
  ),
  "producers.credential_revoke": def(
    "producers.credential_revoke",
    "producer_credential",
    "POST /producer-credentials/{credential_id}/revoke",
    true
  ),
  "producers.suspend": def(
    "producers.suspend",
    "producer",
    "POST /producers/{producer_id}/suspend",
    true
  ),
  "producers.retire": def(
    "producers.retire",
    "producer",
    "POST /producers/{producer_id}/retire",
    true
  ),
  "projects.pause_admission": def(
    "projects.pause_admission",
    "project",
    "POST /projects/{project_id}/pause-admission",
    true
  ),
  "projects.resume_admission": def(
    "projects.resume_admission",
    "project",
    "POST /projects/{project_id}/resume-admission",
    true
  ),
  "projects.retire": def("projects.retire", "project", "POST /projects/{project_id}/retire", true),
  "tenants.suspend": def(
    "tenants.suspend",
    "tenant",
    "POST /api/v1/platform/tenants/{tenant_id}/suspend",
    true
  ),
  "tenants.restore": def(
    "tenants.restore",
    "tenant",
    "POST /api/v1/platform/tenants/{tenant_id}/restore",
    true
  ),
  "tenants.retire": def("tenants.retire", "tenant", "POST /tenants/{tenant_id}/retire", true),
  "memberships.change_role": def(
    "memberships.change_role",
    "membership",
    "POST /memberships/{membership_id}/change-role",
    true
  ),
  "memberships.suspend": def(
    "memberships.suspend",
    "membership",
    "POST /memberships/{membership_id}/suspend",
    true
  ),
  "memberships.revoke": def(
    "memberships.revoke",
    "membership",
    "POST /memberships/{membership_id}/revoke",
    true
  ),
  "data_grants.create": def("data_grants.create", "project", "POST /data-grants", true),
  "data_grants.revoke": def(
    "data_grants.revoke",
    "data_grant",
    "POST /data-grants/{grant_id}/revoke",
    true
  ),
  "retention_holds.create": def("retention_holds.create", "project", "POST /retention-holds", true),
  "retention_holds.release": def(
    "retention_holds.release",
    "retention_hold",
    "POST /retention-holds/{hold_id}/release",
    true
  ),
  "rate_policy_changes.propose": def(
    "rate_policy_changes.propose",
    "project",
    "POST /rate-policy-changes",
    true
  ),
  "rate_policy_changes.activate": def(
    "rate_policy_changes.activate",
    "rate_policy_change",
    "POST /rate-policy-changes/{change_id}/activate",
    true
  ),
  "dispatch_policy_changes.apply": def(
    "dispatch_policy_changes.apply",
    "dispatch_domain",
    "POST /dispatch-policy-changes",
    true
  )
});

export interface CapabilityEntryDto {
  readonly action: CapabilityAction;
  readonly target_kind: CapabilityTargetKind;
  readonly target_id: CanonicalUuid;
  readonly expected_version: Int64String | null;
  readonly available: boolean;
  readonly reason_code: string | null;
  readonly requires_step_up: boolean;
  readonly requires_distinct_reviewer: boolean;
}

const CAPABILITY_KEYS = new Set([
  "action",
  "target_kind",
  "target_id",
  "expected_version",
  "available",
  "reason_code",
  "requires_step_up",
  "requires_distinct_reviewer"
]);

export function projectCapability(input: {
  readonly action: CapabilityAction;
  readonly target_id: CanonicalUuid | string;
  readonly target_kind?: CapabilityTargetKind | undefined;
  readonly expected_version: Int64String | bigint | null;
  readonly available: boolean;
  readonly reason_code?: string | null | undefined;
  readonly requires_step_up?: boolean | undefined;
  readonly requires_distinct_reviewer?: boolean | undefined;
}): CapabilityEntryDto {
  const spec = CAPABILITY_ACTION_REGISTRY[input.action];
  const targetKind = input.target_kind ?? spec.targetKind;
  if (targetKind !== spec.targetKind) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Capability "${input.action}" expects target_kind "${spec.targetKind}", got "${targetKind}"`,
      fieldErrors: [{ path: "capability.target_kind", code: "INVALID_VALUE" }]
    });
  }
  const expectedVersion =
    input.expected_version === null
      ? null
      : typeof input.expected_version === "bigint"
        ? parseInt64String(input.expected_version.toString(10), "capability.expected_version")
        : parseInt64String(input.expected_version, "capability.expected_version");

  const reasonCode =
    input.reason_code === undefined || input.reason_code === null
      ? null
      : parseSafeReasonCode(input.reason_code, "capability.reason_code");

  if (!input.available && reasonCode === null) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Unavailable capability "${input.action}" must provide a non-null safe reason_code`,
      fieldErrors: [{ path: "capability.reason_code", code: "INVALID_VALUE" }]
    });
  }

  return Object.freeze({
    action: input.action,
    target_kind: targetKind,
    target_id: parseCanonicalUuid(input.target_id, "capability.target_id"),
    expected_version: expectedVersion,
    available: input.available,
    reason_code: input.available ? null : reasonCode,
    requires_step_up: input.requires_step_up ?? spec.requiresStepUp,
    requires_distinct_reviewer: input.requires_distinct_reviewer ?? spec.requiresDistinctReviewer
  });
}

export function parseCapabilityEntry(
  value: unknown,
  fieldPath = "capability"
): CapabilityEntryDto {
  const rec = assertPlainRecord(value, fieldPath);
  assertAllowedKeys(rec, CAPABILITY_KEYS, fieldPath);

  if (!isCapabilityAction(rec.action)) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Unsupported or forbidden capability action at ${fieldPath}.action`,
      fieldErrors: [{ path: `${fieldPath}.action`, code: "INVALID_VALUE" }]
    });
  }
  if (!isCapabilityTargetKind(rec.target_kind)) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Invalid target_kind at ${fieldPath}.target_kind`,
      fieldErrors: [{ path: `${fieldPath}.target_kind`, code: "INVALID_VALUE" }]
    });
  }
  const spec = CAPABILITY_ACTION_REGISTRY[rec.action];
  if (rec.target_kind !== spec.targetKind) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Capability "${rec.action}" mismatched target_kind "${rec.target_kind}"`,
      fieldErrors: [{ path: `${fieldPath}.target_kind`, code: "INVALID_VALUE" }]
    });
  }

  const targetId = parseCanonicalUuid(rec.target_id, `${fieldPath}.target_id`);
  const expectedVersion =
    rec.expected_version === null
      ? null
      : parseInt64String(rec.expected_version, `${fieldPath}.expected_version`);
  const available = parseBooleanField(rec.available, `${fieldPath}.available`);
  const reasonCode =
    rec.reason_code === null
      ? null
      : parseSafeReasonCode(rec.reason_code, `${fieldPath}.reason_code`);
  const requiresStepUp = parseBooleanField(rec.requires_step_up, `${fieldPath}.requires_step_up`);
  const requiresDistinctReviewer = parseBooleanField(
    rec.requires_distinct_reviewer,
    `${fieldPath}.requires_distinct_reviewer`
  );

  if (spec.requiresStepUp && !requiresStepUp) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Capability "${rec.action}" must declare requires_step_up=true`,
      fieldErrors: [{ path: `${fieldPath}.requires_step_up`, code: "INVALID_VALUE" }]
    });
  }
  if (spec.requiresDistinctReviewer && !requiresDistinctReviewer) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Capability "${rec.action}" must declare requires_distinct_reviewer=true`,
      fieldErrors: [{ path: `${fieldPath}.requires_distinct_reviewer`, code: "INVALID_VALUE" }]
    });
  }
  if (!available && reasonCode === null) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Unavailable capability "${rec.action}" requires reason_code`,
      fieldErrors: [{ path: `${fieldPath}.reason_code`, code: "INVALID_VALUE" }]
    });
  }

  return Object.freeze({
    action: rec.action,
    target_kind: rec.target_kind,
    target_id: targetId,
    expected_version: expectedVersion,
    available,
    reason_code: reasonCode,
    requires_step_up: requiresStepUp,
    requires_distinct_reviewer: requiresDistinctReviewer
  });
}

export function parseCapabilities(
  value: unknown,
  fieldPath = "capabilities"
): readonly CapabilityEntryDto[] {
  if (!Array.isArray(value)) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Expected capabilities array at ${fieldPath}`,
      fieldErrors: [{ path: fieldPath, code: "INVALID_VALUE" }]
    });
  }
  return Object.freeze(
    value.map((entry, index) => parseCapabilityEntry(entry, `${fieldPath}[${index}]`))
  );
}

export function findCapability(
  capabilities: readonly CapabilityEntryDto[],
  action: CapabilityAction
): CapabilityEntryDto | undefined {
  return capabilities.find((entry) => entry.action === action);
}

export function isCapabilityAvailable(
  capabilities: readonly CapabilityEntryDto[],
  action: CapabilityAction
): boolean {
  return findCapability(capabilities, action)?.available === true;
}
