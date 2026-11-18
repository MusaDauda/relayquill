import { type Temporal } from "@js-temporal/polyfill";
import {
  createEnumGuard,
  type ProjectionVerificationStatus
} from "./enums.js";
import {
  AuthorizationDomainError,
  ConflictDomainError,
  InvariantViolationError
} from "./errors.js";
import { type PublicationRecoveryEpisodeState } from "./event.js";
import {
  type ControlEpoch,
  type PrincipalId,
  type RecoveryActionId
} from "./ids.js";
import { type InstallationMode } from "./installation.js";
import { assertTransition, type TransitionMatrix } from "./state-machine.js";

export const RECOVERY_SCOPE_KINDS = ["installation", "tenant", "project"] as const;
export type RecoveryScopeKind = (typeof RECOVERY_SCOPE_KINDS)[number];
export const isRecoveryScopeKind = createEnumGuard(RECOVERY_SCOPE_KINDS);

export const RECOVERY_INCIDENT_STATES = [
  "open",
  "contained",
  "recovering",
  "monitoring",
  "closed"
] as const;
export type RecoveryIncidentState = (typeof RECOVERY_INCIDENT_STATES)[number];
export const isRecoveryIncidentState = createEnumGuard(RECOVERY_INCIDENT_STATES);

export const RECOVERY_OPERATION_STATES = [
  "planned",
  "reviewed",
  "executing",
  "partial",
  "completed",
  "failed",
  "abandoned"
] as const;
export type RecoveryOperationState = (typeof RECOVERY_OPERATION_STATES)[number];
export const isRecoveryOperationState = createEnumGuard(RECOVERY_OPERATION_STATES);

export const EXTERNAL_RECOVERY_PLAN_STATES = [
  "planned",
  "containment_pending",
  "contained",
  "restoring",
  "quarantined",
  "verifying",
  "reconciling",
  "cutover_ready",
  "active",
  "failed"
] as const;
export type ExternalRecoveryPlanState = (typeof EXTERNAL_RECOVERY_PLAN_STATES)[number];
export const isExternalRecoveryPlanState = createEnumGuard(EXTERNAL_RECOVERY_PLAN_STATES);

export const RECOVERY_ACTION_KINDS = [
  "retire_stale_claim",
  "reconcile_reservations",
  "continue_publication_episode",
  "record_receiver_comparison",
  "set_recovery_gate",
  "rebuild_projection",
  "establish_target_epoch"
] as const;
export type RecoveryActionKind = (typeof RECOVERY_ACTION_KINDS)[number];
export const isRecoveryActionKind = createEnumGuard(RECOVERY_ACTION_KINDS);

export const RECOVERY_ACTION_STATES = [
  "planned",
  "reviewed",
  "executing",
  "applied",
  "rejected",
  "unknown"
] as const;
export type RecoveryActionState = (typeof RECOVERY_ACTION_STATES)[number];
export const isRecoveryActionState = createEnumGuard(RECOVERY_ACTION_STATES);

export const RECOVERY_REVIEW_DECISIONS = ["approve", "reject"] as const;
export type RecoveryReviewDecision = (typeof RECOVERY_REVIEW_DECISIONS)[number];
export const isRecoveryReviewDecision = createEnumGuard(RECOVERY_REVIEW_DECISIONS);

export const STALE_CLAIM_KINDS = [
  "publication",
  "fanout",
  "prepared_attempt",
  "coordinator_task"
] as const;
export type StaleClaimKind = (typeof STALE_CLAIM_KINDS)[number];
export const isStaleClaimKind = createEnumGuard(STALE_CLAIM_KINDS);

export const RECEIVER_COMPARISON_OUTCOMES = [
  "matching_committed_anchor",
  "missing_anchor",
  "conflicting_facts",
  "retention_unknown",
  "source_unavailable"
] as const;
export type ReceiverComparisonOutcome = (typeof RECEIVER_COMPARISON_OUTCOMES)[number];
export const isReceiverComparisonOutcome = createEnumGuard(RECEIVER_COMPARISON_OUTCOMES);

export const PROJECTION_KINDS = [
  "project_delivery_totals",
  "event_delivery_totals"
] as const;
export type ProjectionKind = (typeof PROJECTION_KINDS)[number];
export const isProjectionKind = createEnumGuard(PROJECTION_KINDS);

export const COORDINATOR_TASK_KINDS = [
  "publication_recovery",
  "fanout_recovery",
  "eligibility",
  "reaper",
  "retention",
  "projection_verification"
] as const;
export type CoordinatorTaskKind = (typeof COORDINATOR_TASK_KINDS)[number];
export const isCoordinatorTaskKind = createEnumGuard(COORDINATOR_TASK_KINDS);

export const COORDINATOR_TASK_STATES = [
  "ready",
  "claimed",
  "completed",
  "failed_retryable",
  "review_required"
] as const;
export type CoordinatorTaskState = (typeof COORDINATOR_TASK_STATES)[number];
export const isCoordinatorTaskState = createEnumGuard(COORDINATOR_TASK_STATES);

export const BROKER_STREAM_GENERATION_STATES = [
  "prepared",
  "active",
  "quarantined",
  "retired"
] as const;
export type BrokerStreamGenerationState = (typeof BROKER_STREAM_GENERATION_STATES)[number];
export const isBrokerStreamGenerationState = createEnumGuard(BROKER_STREAM_GENERATION_STATES);

export const TRANSPORT_REJECTION_RESOLUTION_STATES = [
  "recorded",
  "review_required",
  "resolved"
] as const;
export type TransportRejectionResolutionState =
  (typeof TRANSPORT_REJECTION_RESOLUTION_STATES)[number];
export const isTransportRejectionResolutionState = createEnumGuard(
  TRANSPORT_REJECTION_RESOLUTION_STATES
);

export const ALLOWED_RECOVERY_INCIDENT_TRANSITIONS: TransitionMatrix<RecoveryIncidentState> =
  Object.freeze({
    open: ["contained", "recovering", "closed"],
    contained: ["recovering", "monitoring", "closed"],
    recovering: ["monitoring", "contained", "closed"],
    monitoring: ["closed", "recovering"],
    closed: []
  });

export const ALLOWED_RECOVERY_OPERATION_TRANSITIONS: TransitionMatrix<RecoveryOperationState> =
  Object.freeze({
    planned: ["reviewed", "abandoned"],
    reviewed: ["executing", "abandoned"],
    executing: ["completed", "partial", "failed"],
    partial: ["executing", "completed", "failed", "abandoned"],
    completed: [],
    failed: [],
    abandoned: []
  });

export const ALLOWED_RECOVERY_ACTION_TRANSITIONS: TransitionMatrix<RecoveryActionState> =
  Object.freeze({
    planned: ["reviewed", "rejected"],
    reviewed: ["executing", "rejected"],
    executing: ["applied", "unknown", "rejected"],
    applied: [],
    rejected: [],
    unknown: ["executing", "applied", "rejected"]
  });

export const ALLOWED_BROKER_STREAM_GENERATION_TRANSITIONS: TransitionMatrix<BrokerStreamGenerationState> =
  Object.freeze({
    prepared: ["active", "quarantined", "retired"],
    active: ["quarantined", "retired"],
    quarantined: ["active", "retired"],
    retired: []
  });

export function requiresDistinctRecoveryReviewer(
  kind: RecoveryActionKind,
  options?: { readonly reopensSends?: boolean | undefined }
): boolean {
  if (
    kind === "reconcile_reservations" ||
    kind === "continue_publication_episode" ||
    kind === "rebuild_projection" ||
    kind === "establish_target_epoch"
  ) {
    return true;
  }
  if (kind === "set_recovery_gate" && options?.reopensSends) {
    return true;
  }
  return false;
}

export function assertRecoveryReviewAllowed(input: {
  readonly actionId: RecoveryActionId;
  readonly kind: RecoveryActionKind;
  readonly requesterPrincipalId: PrincipalId;
  readonly reviewerPrincipalId: PrincipalId;
  readonly reopensSends?: boolean | undefined;
}): void {
  if (
    requiresDistinctRecoveryReviewer(input.kind, { reopensSends: input.reopensSends }) &&
    input.requesterPrincipalId === input.reviewerPrincipalId
  ) {
    throw new AuthorizationDomainError({
      code: "FORBIDDEN",
      message: `Recovery action "${input.kind}" requires a distinct reviewer`,
      resourceRef: { kind: "recovery_action", id: input.actionId }
    });
  }
}

export function assertRetireStaleClaimAllowed(
  claimKind: StaleClaimKind,
  sendStartedAt: Temporal.Instant | null
): void {
  if (claimKind === "prepared_attempt" && sendStartedAt !== null) {
    throw new ConflictDomainError({
      code: "STATE_TRANSITION_NOT_ALLOWED",
      message: "retire_stale_claim cannot retire an attempt that already recorded send_started_at"
    });
  }
}

export function assertContinuePublicationEpisodeAllowed(
  episodeState: PublicationRecoveryEpisodeState
): void {
  if (episodeState !== "review_required") {
    throw new ConflictDomainError({
      code: "STATE_TRANSITION_NOT_ALLOWED",
      message: `continue_publication_episode requires "review_required" episode state, got "${episodeState}"`
    });
  }
}

const RECOVERY_SCOPE_RANK: Readonly<Record<RecoveryScopeKind, number>> = Object.freeze({
  project: 1,
  tenant: 2,
  installation: 3
});

export function assertSetRecoveryGateAllowed(input: {
  readonly planScopeKind: RecoveryScopeKind;
  readonly targetScopeKind: RecoveryScopeKind;
  readonly reopensAllowSend: boolean;
}): void {
  if (
    input.planScopeKind === "project" &&
    input.targetScopeKind === "installation" &&
    input.reopensAllowSend
  ) {
    throw new AuthorizationDomainError({
      code: "FORBIDDEN",
      message: "A project-scoped recovery plan cannot reopen installation-wide allow_send"
    });
  }
  if (RECOVERY_SCOPE_RANK[input.planScopeKind] < RECOVERY_SCOPE_RANK[input.targetScopeKind]) {
    throw new AuthorizationDomainError({
      code: "FORBIDDEN",
      message: `A ${input.planScopeKind}-scoped recovery plan cannot target a ${input.targetScopeKind}-scoped recovery gate`
    });
  }
}

export function assertEstablishTargetEpochAllowed(
  installationMode: InstallationMode,
  sourceEpoch: ControlEpoch,
  targetEpoch: ControlEpoch
): void {
  if (installationMode !== "recovery_quarantine") {
    throw new ConflictDomainError({
      code: "STATE_TRANSITION_NOT_ALLOWED",
      message: `establish_target_epoch requires installation mode "recovery_quarantine", got "${installationMode}"`
    });
  }
  if (sourceEpoch === targetEpoch) {
    throw new InvariantViolationError({
      message: "establish_target_epoch requires targetEpoch to differ from sourceEpoch"
    });
  }
}

export function transitionRecoveryActionState(
  from: RecoveryActionState,
  to: RecoveryActionState,
  actionId: RecoveryActionId
): RecoveryActionState {
  assertTransition("recovery_action", ALLOWED_RECOVERY_ACTION_TRANSITIONS, from, to, {
    kind: "recovery_action",
    id: actionId
  });
  return to;
}

export function isProjectionVerificationHealthy(status: ProjectionVerificationStatus): boolean {
  return status === "matched";
}
