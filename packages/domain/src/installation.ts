import { createEnumGuard } from "./enums.js";
import { ConflictDomainError, InvariantViolationError } from "./errors.js";
import {
  type ControlEpoch,
  type OrderingCutoverPlanId,
  type ProjectId,
  type TenantId
} from "./ids.js";
import { assertTransition, type TransitionMatrix } from "./state-machine.js";

export const INSTALLATION_MODES = [
  "initializing",
  "open",
  "admission_hold",
  "recovery_quarantine",
  "retired"
] as const;
export type InstallationMode = (typeof INSTALLATION_MODES)[number];
export const isInstallationMode = createEnumGuard(INSTALLATION_MODES);

export const TENANT_STATES = ["provisioning", "active", "suspended", "retired"] as const;
export type TenantState = (typeof TENANT_STATES)[number];
export const isTenantState = createEnumGuard(TENANT_STATES);

export const PROJECT_STATES = [
  "provisioning",
  "active",
  "admission_paused",
  "quarantined",
  "retired"
] as const;
export type ProjectState = (typeof PROJECT_STATES)[number];
export const isProjectState = createEnumGuard(PROJECT_STATES);

export const LIFECYCLE_OPERATION_KINDS = [
  "tenant_retirement",
  "project_retirement"
] as const;
export type LifecycleOperationKind = (typeof LIFECYCLE_OPERATION_KINDS)[number];
export const isLifecycleOperationKind = createEnumGuard(LIFECYCLE_OPERATION_KINDS);

export const LIFECYCLE_OPERATION_STATES = [
  "admitted",
  "draining",
  "review_required",
  "completed",
  "revoked",
  "failed_retryable"
] as const;
export type LifecycleOperationState = (typeof LIFECYCLE_OPERATION_STATES)[number];
export const isLifecycleOperationState = createEnumGuard(LIFECYCLE_OPERATION_STATES);

export const ALLOWED_INSTALLATION_MODE_TRANSITIONS: TransitionMatrix<InstallationMode> =
  Object.freeze({
    initializing: ["open", "admission_hold", "recovery_quarantine", "retired"],
    open: ["admission_hold", "recovery_quarantine", "retired"],
    admission_hold: ["open", "recovery_quarantine", "retired"],
    recovery_quarantine: ["admission_hold", "open", "retired"],
    retired: []
  });

export const ALLOWED_TENANT_TRANSITIONS: TransitionMatrix<TenantState> = Object.freeze({
  provisioning: ["active", "suspended", "retired"],
  active: ["suspended", "retired"],
  suspended: ["active", "retired"],
  retired: []
});

export const ALLOWED_PROJECT_TRANSITIONS: TransitionMatrix<ProjectState> = Object.freeze({
  provisioning: ["active", "admission_paused", "quarantined", "retired"],
  active: ["admission_paused", "quarantined", "retired"],
  admission_paused: ["active", "quarantined", "retired"],
  quarantined: ["admission_paused", "active", "retired"],
  retired: []
});

export const ALLOWED_LIFECYCLE_OPERATION_TRANSITIONS: TransitionMatrix<LifecycleOperationState> =
  Object.freeze({
    admitted: ["draining", "review_required", "revoked", "failed_retryable"],
    draining: ["completed", "review_required", "failed_retryable", "revoked"],
    review_required: ["draining", "completed", "revoked"],
    failed_retryable: ["draining", "review_required", "revoked"],
    completed: [],
    revoked: []
  });

export interface InstallationStateSnapshot {
  readonly mode: InstallationMode;
  readonly controlEpoch: ControlEpoch;
  readonly allowEventAdmission: boolean;
  readonly allowPublication: boolean;
  readonly allowFanout: boolean;
  readonly allowSend: boolean;
  readonly allowEndpointVerification: boolean;
  readonly governanceVersion: bigint;
  readonly version: bigint;
}

export function assertInstallationStateInvariants(state: InstallationStateSnapshot): void {
  if (state.mode === "recovery_quarantine") {
    if (
      state.allowEventAdmission ||
      state.allowPublication ||
      state.allowFanout ||
      state.allowSend ||
      state.allowEndpointVerification
    ) {
      throw new InvariantViolationError({
        message: "Installation recovery_quarantine requires all five allow_* flags to be false"
      });
    }
  }
  if (state.mode === "retired") {
    if (
      state.allowEventAdmission ||
      state.allowPublication ||
      state.allowFanout ||
      state.allowSend ||
      state.allowEndpointVerification
    ) {
      throw new InvariantViolationError({
        message: "Retired installation requires all five allow_* flags to be false"
      });
    }
  }
}

export function enterRecoveryQuarantine(
  state: InstallationStateSnapshot,
  newControlEpoch: ControlEpoch
): InstallationStateSnapshot {
  assertTransition(
    "installation_state",
    ALLOWED_INSTALLATION_MODE_TRANSITIONS,
    state.mode,
    "recovery_quarantine"
  );
  if (newControlEpoch === state.controlEpoch) {
    throw new InvariantViolationError({
      message: "Entering recovery_quarantine requires allocating a new control_epoch"
    });
  }
  return Object.freeze({
    ...state,
    mode: "recovery_quarantine",
    controlEpoch: newControlEpoch,
    allowEventAdmission: false,
    allowPublication: false,
    allowFanout: false,
    allowSend: false,
    allowEndpointVerification: false,
    governanceVersion: state.governanceVersion + 1n,
    version: state.version + 1n
  });
}

export function transitionTenantState(
  from: TenantState,
  to: TenantState,
  tenantId: TenantId
): TenantState {
  assertTransition("tenant", ALLOWED_TENANT_TRANSITIONS, from, to, {
    kind: "tenant",
    id: tenantId
  });
  return to;
}

export interface ProjectSnapshot {
  readonly projectId: ProjectId;
  readonly state: ProjectState;
  readonly activeOrderingCutoverPlanId: OrderingCutoverPlanId | null;
  readonly topologyVersion: bigint;
}

export function resumeProjectAdmission(project: ProjectSnapshot): ProjectSnapshot {
  if (project.state !== "admission_paused") {
    throw new ConflictDomainError({
      code: "STATE_TRANSITION_NOT_ALLOWED",
      message: `Cannot resume admission from project state "${project.state}"`,
      resourceRef: { kind: "project", id: project.projectId }
    });
  }
  assertTransition("project", ALLOWED_PROJECT_TRANSITIONS, project.state, "active", {
    kind: "project",
    id: project.projectId
  });
  // Resuming admission preserves activeOrderingCutoverPlanId so an in-flight cutover stays fenced.
  return Object.freeze({
    ...project,
    state: "active"
  });
}
