import crypto from "node:crypto";
import type { Temporal } from "@js-temporal/polyfill";
import {
  AuthorizationDomainError,
  ConflictDomainError,
  type DataGrantAction,
  type DataGrantId,
  type DataGrantProjection,
  type DataGrantState,
  type MembershipState,
  NotFoundDomainError,
  type PlatformRole,
  type PlatformRoleAssignmentId,
  type PlatformRoleAssignmentState,
  type PrincipalId,
  type ProducerNamespace,
  type ProjectId,
  type ProjectMembershipId,
  type ProjectRole,
  type ProposalReviewDecision,
  type ProposalSnapshot,
  type Sha256Hex,
  type TenantId,
  type TenantMembershipId,
  type TenantRole,
  ValidationDomainError,
  compareInstants,
  isDataGrantAction,
  isDataGrantProjection,
  isPlatformRole,
  isProjectRole,
  isTenantRole,
  parseDataGrantId,
  parseProducerNamespace,
  parseProjectId,
  parseTenantId,
  reviewProposal
} from "@relayquill/domain";
import {
  type InstallationAuthoritySnapshot,
  type PrincipalRecord,
  assertInstallationAllowsOrdinaryAccess
} from "./primitives.js";

export interface PlatformRoleAssignmentRecord {
  readonly id: PlatformRoleAssignmentId;
  readonly principalId: PrincipalId;
  readonly role: PlatformRole;
  readonly state: PlatformRoleAssignmentState;
  readonly governanceVersion: bigint;
  readonly createdAt: Temporal.Instant;
  readonly revokedAt: Temporal.Instant | null;
  readonly version: bigint;
}

export interface TenantMembershipRecord {
  readonly id: TenantMembershipId;
  readonly tenantId: TenantId;
  readonly principalId: PrincipalId;
  readonly role: TenantRole;
  readonly state: MembershipState;
  readonly authorityVersion: bigint;
  readonly createdAt: Temporal.Instant;
  readonly updatedAt: Temporal.Instant;
  readonly version: bigint;
}

export interface ProjectMembershipRecord {
  readonly id: ProjectMembershipId;
  readonly tenantId: TenantId;
  readonly projectId: ProjectId;
  readonly principalId: PrincipalId;
  readonly role: ProjectRole;
  readonly state: MembershipState;
  readonly authorityVersion: bigint;
  readonly createdAt: Temporal.Instant;
  readonly updatedAt: Temporal.Instant;
  readonly version: bigint;
}

export interface HumanDataGrantRecord {
  readonly id: DataGrantId;
  readonly membershipId: ProjectMembershipId;
  readonly tenantId: TenantId;
  readonly projectId: ProjectId;
  readonly action: DataGrantAction;
  readonly projection: DataGrantProjection;
  readonly producerNamespace: ProducerNamespace | null;
  readonly state: DataGrantState;
  readonly expiresAt: Temporal.Instant | null;
  readonly createdBy: PrincipalId;
  readonly createdAt: Temporal.Instant;
  readonly version: bigint;
}

export interface ProposalReviewRecord {
  readonly reviewId: string;
  readonly proposalId: string;
  readonly proposalVersion: bigint;
  readonly candidateSha256: Sha256Hex;
  readonly reviewerPrincipalId: PrincipalId;
  readonly decision: ProposalReviewDecision;
  readonly reviewedAt: Temporal.Instant;
}

export interface GovernanceRepository {
  getPrincipal(principalId: PrincipalId): Promise<PrincipalRecord | null>;
  listPlatformRolesForPrincipal(
    principalId: PrincipalId
  ): Promise<readonly PlatformRoleAssignmentRecord[]>;
  countActivePlatformAdmins(excludeAssignmentId?: PlatformRoleAssignmentId): Promise<number>;
  listTenantMembershipsForPrincipal(
    principalId: PrincipalId,
    tenantId: TenantId
  ): Promise<readonly TenantMembershipRecord[]>;
  countActiveTenantAdmins(
    tenantId: TenantId,
    excludeMembershipId?: TenantMembershipId
  ): Promise<number>;
  listProjectMembershipsForPrincipal(
    principalId: PrincipalId,
    tenantId: TenantId,
    projectId: ProjectId
  ): Promise<readonly ProjectMembershipRecord[]>;
  countActiveProjectAdmins(
    projectId: ProjectId,
    excludeMembershipId?: ProjectMembershipId
  ): Promise<number>;
  listDataGrantsForMemberships(
    membershipIds: readonly ProjectMembershipId[],
    action: DataGrantAction
  ): Promise<readonly HumanDataGrantRecord[]>;
  createDataGrant?(input: {
    readonly id: DataGrantId;
    readonly membershipId: ProjectMembershipId;
    readonly tenantId: TenantId;
    readonly projectId: ProjectId;
    readonly action: DataGrantAction;
    readonly projection: DataGrantProjection;
    readonly producerNamespace: ProducerNamespace | null;
    readonly expiresAt: Temporal.Instant | null;
    readonly createdBy: PrincipalId;
    readonly createdAt: Temporal.Instant;
  }): Promise<HumanDataGrantRecord>;
  revokeDataGrant?(input: {
    readonly grantId: DataGrantId;
    readonly expectedVersion: bigint;
  }): Promise<HumanDataGrantRecord>;
  updateTenantMembershipState?(input: {
    readonly membershipId: TenantMembershipId;
    readonly expectedVersion: bigint;
    readonly toState: MembershipState;
    readonly now: Temporal.Instant;
  }): Promise<TenantMembershipRecord>;
  updateProjectMembership?(input: {
    readonly membershipId: ProjectMembershipId;
    readonly expectedVersion: bigint;
    readonly toRole?: ProjectRole | undefined;
    readonly toState?: MembershipState | undefined;
    readonly now: Temporal.Instant;
  }): Promise<ProjectMembershipRecord>;
  revokePlatformRoleAssignment?(input: {
    readonly assignmentId: PlatformRoleAssignmentId;
    readonly expectedVersion: bigint;
    readonly revokedAt: Temporal.Instant;
  }): Promise<PlatformRoleAssignmentRecord>;
}

export class InMemoryGovernanceRepository implements GovernanceRepository {
  readonly #principals = new Map<PrincipalId, PrincipalRecord>();
  readonly #platformRoles = new Map<PlatformRoleAssignmentId, PlatformRoleAssignmentRecord>();
  readonly #tenantMemberships = new Map<TenantMembershipId, TenantMembershipRecord>();
  readonly #projectMemberships = new Map<ProjectMembershipId, ProjectMembershipRecord>();
  readonly #dataGrants = new Map<DataGrantId, HumanDataGrantRecord>();

  putPrincipal(principal: PrincipalRecord): void {
    this.#principals.set(principal.principalId, principal);
  }

  putPlatformRole(assignment: PlatformRoleAssignmentRecord): void {
    this.#platformRoles.set(assignment.id, assignment);
  }

  putTenantMembership(membership: TenantMembershipRecord): void {
    this.#tenantMemberships.set(membership.id, membership);
  }

  putProjectMembership(membership: ProjectMembershipRecord): void {
    this.#projectMemberships.set(membership.id, membership);
  }

  putDataGrant(grant: HumanDataGrantRecord): void {
    this.#dataGrants.set(grant.id, grant);
  }

  getPrincipal(principalId: PrincipalId): Promise<PrincipalRecord | null> {
    return Promise.resolve(this.#principals.get(principalId) ?? null);
  }

  listPlatformRolesForPrincipal(
    principalId: PrincipalId
  ): Promise<readonly PlatformRoleAssignmentRecord[]> {
    const out: PlatformRoleAssignmentRecord[] = [];
    for (const a of this.#platformRoles.values()) {
      if (a.principalId === principalId) {
        out.push(a);
      }
    }
    return Promise.resolve(Object.freeze(out));
  }

  countActivePlatformAdmins(excludeAssignmentId?: PlatformRoleAssignmentId): Promise<number> {
    let count = 0;
    for (const a of this.#platformRoles.values()) {
      if (
        a.id !== excludeAssignmentId &&
        a.role === "platform_admin" &&
        a.state === "active" &&
        this.#principals.get(a.principalId)?.state === "active"
      ) {
        count += 1;
      }
    }
    return Promise.resolve(count);
  }

  listTenantMembershipsForPrincipal(
    principalId: PrincipalId,
    tenantId: TenantId
  ): Promise<readonly TenantMembershipRecord[]> {
    const out: TenantMembershipRecord[] = [];
    for (const m of this.#tenantMemberships.values()) {
      if (m.principalId === principalId && m.tenantId === tenantId) {
        out.push(m);
      }
    }
    return Promise.resolve(Object.freeze(out));
  }

  countActiveTenantAdmins(
    tenantId: TenantId,
    excludeMembershipId?: TenantMembershipId
  ): Promise<number> {
    let count = 0;
    for (const m of this.#tenantMemberships.values()) {
      if (
        m.id !== excludeMembershipId &&
        m.tenantId === tenantId &&
        m.role === "tenant_admin" &&
        m.state === "active" &&
        this.#principals.get(m.principalId)?.state === "active"
      ) {
        count += 1;
      }
    }
    return Promise.resolve(count);
  }

  listProjectMembershipsForPrincipal(
    principalId: PrincipalId,
    tenantId: TenantId,
    projectId: ProjectId
  ): Promise<readonly ProjectMembershipRecord[]> {
    const out: ProjectMembershipRecord[] = [];
    for (const m of this.#projectMemberships.values()) {
      if (
        m.principalId === principalId &&
        m.tenantId === tenantId &&
        m.projectId === projectId
      ) {
        out.push(m);
      }
    }
    return Promise.resolve(Object.freeze(out));
  }

  countActiveProjectAdmins(
    projectId: ProjectId,
    excludeMembershipId?: ProjectMembershipId
  ): Promise<number> {
    let count = 0;
    for (const m of this.#projectMemberships.values()) {
      if (
        m.id !== excludeMembershipId &&
        m.projectId === projectId &&
        m.role === "project_admin" &&
        m.state === "active" &&
        this.#principals.get(m.principalId)?.state === "active"
      ) {
        count += 1;
      }
    }
    return Promise.resolve(count);
  }

  listDataGrantsForMemberships(
    membershipIds: readonly ProjectMembershipId[],
    action: DataGrantAction
  ): Promise<readonly HumanDataGrantRecord[]> {
    const idSet = new Set(membershipIds);
    const out: HumanDataGrantRecord[] = [];
    for (const grant of this.#dataGrants.values()) {
      if (idSet.has(grant.membershipId) && grant.action === action) {
        out.push(grant);
      }
    }
    return Promise.resolve(Object.freeze(out));
  }

  createDataGrant(input: {
    readonly id: DataGrantId;
    readonly membershipId: ProjectMembershipId;
    readonly tenantId: TenantId;
    readonly projectId: ProjectId;
    readonly action: DataGrantAction;
    readonly projection: DataGrantProjection;
    readonly producerNamespace: ProducerNamespace | null;
    readonly expiresAt: Temporal.Instant | null;
    readonly createdBy: PrincipalId;
    readonly createdAt: Temporal.Instant;
  }): Promise<HumanDataGrantRecord> {
    const record: HumanDataGrantRecord = Object.freeze({
      ...input,
      state: "active",
      version: 1n
    });
    this.#dataGrants.set(record.id, record);
    return Promise.resolve(record);
  }

  revokeDataGrant(input: {
    readonly grantId: DataGrantId;
    readonly expectedVersion: bigint;
  }): Promise<HumanDataGrantRecord> {
    const current = this.#dataGrants.get(input.grantId);
    if (current === undefined) {
      return Promise.reject(
        new NotFoundDomainError({ code: "NOT_FOUND", message: "Data grant not found" })
      );
    }
    if (current.version !== input.expectedVersion) {
      return Promise.reject(
        new ConflictDomainError({ code: "VERSION_CONFLICT", message: "Data grant version conflict" })
      );
    }
    const updated: HumanDataGrantRecord = Object.freeze({
      ...current,
      state: "revoked",
      version: current.version + 1n
    });
    this.#dataGrants.set(updated.id, updated);
    return Promise.resolve(updated);
  }

  updateTenantMembershipState(input: {
    readonly membershipId: TenantMembershipId;
    readonly expectedVersion: bigint;
    readonly toState: MembershipState;
    readonly now: Temporal.Instant;
  }): Promise<TenantMembershipRecord> {
    const current = this.#tenantMemberships.get(input.membershipId);
    if (current === undefined) {
      return Promise.reject(
        new NotFoundDomainError({ code: "NOT_FOUND", message: "Tenant membership not found" })
      );
    }
    if (current.version !== input.expectedVersion) {
      return Promise.reject(
        new ConflictDomainError({
          code: "VERSION_CONFLICT",
          message: "Tenant membership version conflict"
        })
      );
    }
    const updated: TenantMembershipRecord = Object.freeze({
      ...current,
      state: input.toState,
      authorityVersion: current.authorityVersion + 1n,
      updatedAt: input.now,
      version: current.version + 1n
    });
    this.#tenantMemberships.set(updated.id, updated);
    return Promise.resolve(updated);
  }

  updateProjectMembership(input: {
    readonly membershipId: ProjectMembershipId;
    readonly expectedVersion: bigint;
    readonly toRole?: ProjectRole | undefined;
    readonly toState?: MembershipState | undefined;
    readonly now: Temporal.Instant;
  }): Promise<ProjectMembershipRecord> {
    const current = this.#projectMemberships.get(input.membershipId);
    if (current === undefined) {
      return Promise.reject(
        new NotFoundDomainError({ code: "NOT_FOUND", message: "Project membership not found" })
      );
    }
    if (current.version !== input.expectedVersion) {
      return Promise.reject(
        new ConflictDomainError({
          code: "VERSION_CONFLICT",
          message: "Project membership version conflict"
        })
      );
    }
    const updated: ProjectMembershipRecord = Object.freeze({
      ...current,
      role: input.toRole ?? current.role,
      state: input.toState ?? current.state,
      authorityVersion: current.authorityVersion + 1n,
      updatedAt: input.now,
      version: current.version + 1n
    });
    this.#projectMemberships.set(updated.id, updated);
    return Promise.resolve(updated);
  }

  revokePlatformRoleAssignment(input: {
    readonly assignmentId: PlatformRoleAssignmentId;
    readonly expectedVersion: bigint;
    readonly revokedAt: Temporal.Instant;
  }): Promise<PlatformRoleAssignmentRecord> {
    const current = this.#platformRoles.get(input.assignmentId);
    if (current === undefined) {
      return Promise.reject(
        new NotFoundDomainError({ code: "NOT_FOUND", message: "Platform role assignment not found" })
      );
    }
    if (current.version !== input.expectedVersion) {
      return Promise.reject(
        new ConflictDomainError({
          code: "VERSION_CONFLICT",
          message: "Platform role assignment version conflict"
        })
      );
    }
    const updated: PlatformRoleAssignmentRecord = Object.freeze({
      ...current,
      state: "revoked",
      revokedAt: input.revokedAt,
      version: current.version + 1n
    });
    this.#platformRoles.set(updated.id, updated);
    return Promise.resolve(updated);
  }
}

export type GovernanceActionScope = "platform" | "tenant" | "project" | "tenant_or_project";

export interface GovernanceActionPolicy {
  readonly scope: GovernanceActionScope;
  readonly platformRoles: readonly PlatformRole[];
  readonly tenantRoles: readonly TenantRole[];
  readonly projectRoles: readonly ProjectRole[];
  readonly requiresStepUp: boolean;
  readonly requiresDistinctReviewer: boolean;
  readonly requiredDataGrantAction?: DataGrantAction | undefined;
  readonly publisherOwnNamespaceOnly?: boolean | undefined;
}

function policy(spec: {
  readonly scope: GovernanceActionScope;
  readonly platformRoles?: readonly PlatformRole[];
  readonly tenantRoles?: readonly TenantRole[];
  readonly projectRoles?: readonly ProjectRole[];
  readonly requiresStepUp?: boolean;
  readonly requiresDistinctReviewer?: boolean;
  readonly requiredDataGrantAction?: DataGrantAction;
  readonly publisherOwnNamespaceOnly?: boolean;
}): GovernanceActionPolicy {
  return Object.freeze({
    scope: spec.scope,
    platformRoles: Object.freeze(spec.platformRoles ?? []),
    tenantRoles: Object.freeze(spec.tenantRoles ?? []),
    projectRoles: Object.freeze(spec.projectRoles ?? []),
    requiresStepUp: spec.requiresStepUp ?? false,
    requiresDistinctReviewer: spec.requiresDistinctReviewer ?? false,
    ...(spec.requiredDataGrantAction !== undefined
      ? { requiredDataGrantAction: spec.requiredDataGrantAction }
      : {}),
    ...(spec.publisherOwnNamespaceOnly !== undefined
      ? { publisherOwnNamespaceOnly: spec.publisherOwnNamespaceOnly }
      : {})
  });
}

export const GOVERNANCE_ACTION_POLICIES: Readonly<Record<string, GovernanceActionPolicy>> =
  Object.freeze({
    // Platform scope
    "tenants.create": policy({ scope: "platform", platformRoles: ["platform_admin"], requiresStepUp: true }),
    "tenants.suspend": policy({ scope: "platform", platformRoles: ["platform_admin"], requiresStepUp: true }),
    "tenants.restore": policy({ scope: "platform", platformRoles: ["platform_admin"], requiresStepUp: true }),
    "tenants.retire": policy({ scope: "platform", platformRoles: ["platform_admin"], requiresStepUp: true }),
    "platform.recovery_controls": policy({ scope: "platform", platformRoles: ["platform_admin"], requiresStepUp: true }),
    "platform.identity_manage": policy({ scope: "platform", platformRoles: ["platform_admin"], requiresStepUp: true }),
    "platform.audit.read": policy({ scope: "platform", platformRoles: ["platform_admin", "platform_auditor"] }),
    "platform.health.read": policy({ scope: "platform", platformRoles: ["platform_admin", "platform_auditor"] }),

    // Tenant scope
    "projects.create": policy({ scope: "tenant", tenantRoles: ["tenant_admin"], requiresStepUp: true }),
    "projects.retire": policy({ scope: "tenant", tenantRoles: ["tenant_admin"], requiresStepUp: true }),
    "tenant.limits.update": policy({ scope: "tenant", tenantRoles: ["tenant_admin"], requiresStepUp: true }),
    "tenant_memberships.grant": policy({ scope: "tenant", tenantRoles: ["tenant_admin"], requiresStepUp: true }),
    "tenant_memberships.change_role": policy({ scope: "tenant", tenantRoles: ["tenant_admin"], requiresStepUp: true }),
    "tenant_memberships.suspend": policy({ scope: "tenant", tenantRoles: ["tenant_admin"], requiresStepUp: true }),
    "tenant_memberships.revoke": policy({ scope: "tenant", tenantRoles: ["tenant_admin"], requiresStepUp: true }),
    "project_admins.assign": policy({ scope: "tenant", tenantRoles: ["tenant_admin"], requiresStepUp: true }),
    "projects.pause_admission": policy({
      scope: "tenant_or_project",
      tenantRoles: ["tenant_admin"],
      projectRoles: ["project_admin"],
      requiresStepUp: true
    }),
    "projects.resume_admission": policy({
      scope: "tenant_or_project",
      tenantRoles: ["tenant_admin"],
      projectRoles: ["project_admin"],
      requiresStepUp: true
    }),

    // Project safe reads & publication
    "publication_context.enable": policy({
      scope: "project",
      projectRoles: ["project_admin", "publisher"],
      publisherOwnNamespaceOnly: true
    }),
    "events.admit": policy({
      scope: "project",
      projectRoles: ["project_admin", "publisher"],
      publisherOwnNamespaceOnly: true
    }),
    "events.resolve": policy({
      scope: "project",
      projectRoles: ["project_admin", "publisher"],
      publisherOwnNamespaceOnly: true
    }),
    "events.read_safe": policy({
      scope: "project",
      projectRoles: ["project_admin", "integrator", "operator", "publisher", "observer"],
      publisherOwnNamespaceOnly: true
    }),
    "deliveries.read_safe": policy({
      scope: "project",
      projectRoles: ["project_admin", "integrator", "operator", "publisher", "observer"],
      publisherOwnNamespaceOnly: true
    }),
    "endpoints.read_safe": policy({
      scope: "project",
      projectRoles: ["project_admin", "integrator", "operator", "observer"]
    }),
    "subscriptions.read_safe": policy({
      scope: "project",
      projectRoles: ["project_admin", "integrator", "operator", "observer"]
    }),
    "producers.read_safe": policy({
      scope: "project",
      projectRoles: ["project_admin", "integrator", "operator", "observer"]
    }),
    "audit.read_safe": policy({
      scope: "project",
      projectRoles: ["project_admin", "integrator", "operator", "observer"]
    }),

    // Sensitive data reads (explicit human_data_grants required!)
    "events.content.read": policy({
      scope: "project",
      projectRoles: ["project_admin", "integrator", "operator", "publisher", "observer"],
      requiredDataGrantAction: "events.content.read",
      publisherOwnNamespaceOnly: true
    }),
    "deliveries.request.read": policy({
      scope: "project",
      projectRoles: ["project_admin", "integrator", "operator", "publisher", "observer"],
      requiredDataGrantAction: "deliveries.request.read",
      publisherOwnNamespaceOnly: true
    }),
    "receiver_receipts.read": policy({
      scope: "project",
      projectRoles: ["project_admin", "integrator", "operator", "publisher", "observer"],
      requiredDataGrantAction: "receiver_receipts.read",
      publisherOwnNamespaceOnly: true
    }),

    // Integrator & operator actions
    "event_schemas.draft": policy({ scope: "project", projectRoles: ["project_admin", "integrator"] }),
    "event_schema_versions.validate": policy({ scope: "project", projectRoles: ["project_admin", "integrator"] }),
    "endpoints.create_version": policy({ scope: "project", projectRoles: ["project_admin", "integrator"] }),
    "subscriptions.create_version": policy({ scope: "project", projectRoles: ["project_admin", "integrator"] }),
    "subscriptions.validate": policy({ scope: "project", projectRoles: ["project_admin", "integrator"] }),

    "endpoints.pause": policy({ scope: "project", projectRoles: ["project_admin", "operator"] }),
    "subscriptions.pause_future": policy({ scope: "project", projectRoles: ["project_admin", "operator"] }),
    "subscriptions.hold_sends": policy({ scope: "project", projectRoles: ["project_admin", "operator"] }),
    "subscriptions.pause_all": policy({ scope: "project", projectRoles: ["project_admin", "operator"] }),
    "deliveries.replay.propose": policy({ scope: "project", projectRoles: ["project_admin", "operator"] }),
    "deliveries.suppression.propose": policy({ scope: "project", projectRoles: ["project_admin", "operator"] }),
    "order_skip_proposals.propose": policy({ scope: "project", projectRoles: ["project_admin", "operator"] }),
    "replay_proposals.withdraw": policy({ scope: "project", projectRoles: ["project_admin", "operator"] }),
    "circuits.request_probe": policy({ scope: "project", projectRoles: ["project_admin", "operator"] }),

    // Two-person reviewed admissions (project_admin + step-up + proposer !== reviewer)
    "replay_proposals.review": policy({
      scope: "project",
      projectRoles: ["project_admin"],
      requiresStepUp: true,
      requiresDistinctReviewer: true
    }),
    "replay_proposals.admit": policy({
      scope: "project",
      projectRoles: ["project_admin"],
      requiresStepUp: true,
      requiresDistinctReviewer: true
    }),
    "order_skip_proposals.review": policy({
      scope: "project",
      projectRoles: ["project_admin"],
      requiresStepUp: true,
      requiresDistinctReviewer: true
    }),
    "order_skip_proposals.admit": policy({
      scope: "project",
      projectRoles: ["project_admin"],
      requiresStepUp: true,
      requiresDistinctReviewer: true
    }),
    "suppression_proposals.review": policy({
      scope: "project",
      projectRoles: ["project_admin"],
      requiresStepUp: true,
      requiresDistinctReviewer: true
    }),
    "suppression_proposals.admit": policy({
      scope: "project",
      projectRoles: ["project_admin"],
      requiresStepUp: true,
      requiresDistinctReviewer: true
    }),

    // Project admin step-up actions
    "endpoints.verify": policy({ scope: "project", projectRoles: ["project_admin"], requiresStepUp: true }),
    "endpoints.activate": policy({ scope: "project", projectRoles: ["project_admin"], requiresStepUp: true }),
    "endpoints.quarantine": policy({ scope: "project", projectRoles: ["project_admin"], requiresStepUp: true }),
    "endpoints.resume": policy({ scope: "project", projectRoles: ["project_admin"], requiresStepUp: true }),
    "endpoints.retire": policy({ scope: "project", projectRoles: ["project_admin"], requiresStepUp: true }),
    "endpoints.retained_dispatch_grant.create": policy({ scope: "project", projectRoles: ["project_admin"], requiresStepUp: true }),
    "endpoints.retained_dispatch_grant.revoke": policy({ scope: "project", projectRoles: ["project_admin"], requiresStepUp: true }),
    "signing_key_intents.create": policy({ scope: "project", projectRoles: ["project_admin"], requiresStepUp: true }),
    "signing_policies.create": policy({ scope: "project", projectRoles: ["project_admin"], requiresStepUp: true }),
    "signing_policies.activate": policy({ scope: "project", projectRoles: ["project_admin"], requiresStepUp: true }),
    "signing_keys.revoke": policy({ scope: "project", projectRoles: ["project_admin"], requiresStepUp: true }),
    "subscriptions.activate": policy({ scope: "project", projectRoles: ["project_admin"], requiresStepUp: true }),
    "subscriptions.resume_future": policy({ scope: "project", projectRoles: ["project_admin"], requiresStepUp: true }),
    "subscriptions.release_send_hold": policy({ scope: "project", projectRoles: ["project_admin"], requiresStepUp: true }),
    "subscriptions.retire": policy({ scope: "project", projectRoles: ["project_admin"], requiresStepUp: true }),
    "ordering_cutovers.propose": policy({ scope: "project", projectRoles: ["project_admin"], requiresStepUp: true }),
    "ordering_cutovers.begin": policy({ scope: "project", projectRoles: ["project_admin"], requiresStepUp: true }),
    "ordering_cutovers.activate": policy({ scope: "project", projectRoles: ["project_admin"], requiresStepUp: true }),
    "ordering_cutovers.abort": policy({ scope: "project", projectRoles: ["project_admin"], requiresStepUp: true }),
    "event_schema_versions.publish": policy({ scope: "project", projectRoles: ["project_admin"], requiresStepUp: true }),
    "event_schema_versions.retire": policy({ scope: "project", projectRoles: ["project_admin"], requiresStepUp: true }),
    "representation_profiles.activate": policy({ scope: "project", projectRoles: ["project_admin"], requiresStepUp: true }),
    "representation_profiles.retire": policy({ scope: "project", projectRoles: ["project_admin"], requiresStepUp: true }),
    "receiver_contracts.verify": policy({ scope: "project", projectRoles: ["project_admin"], requiresStepUp: true }),
    "receiver_contracts.activate": policy({ scope: "project", projectRoles: ["project_admin"], requiresStepUp: true }),
    "producers.create": policy({ scope: "project", projectRoles: ["project_admin"], requiresStepUp: true }),
    "producers.scope_versions.create": policy({ scope: "project", projectRoles: ["project_admin"], requiresStepUp: true }),
    "producers.scope_activate": policy({ scope: "project", projectRoles: ["project_admin"], requiresStepUp: true }),
    "producers.credential_issue": policy({ scope: "project", projectRoles: ["project_admin"], requiresStepUp: true }),
    "producers.credential_rotate": policy({ scope: "project", projectRoles: ["project_admin"], requiresStepUp: true }),
    "producers.credential_revoke": policy({ scope: "project", projectRoles: ["project_admin"], requiresStepUp: true }),
    "producers.suspend": policy({ scope: "project", projectRoles: ["project_admin"], requiresStepUp: true }),
    "producers.retire": policy({ scope: "project", projectRoles: ["project_admin"], requiresStepUp: true }),
    "memberships.change_role": policy({
      scope: "tenant_or_project",
      tenantRoles: ["tenant_admin"],
      projectRoles: ["project_admin"],
      requiresStepUp: true
    }),
    "memberships.suspend": policy({
      scope: "tenant_or_project",
      tenantRoles: ["tenant_admin"],
      projectRoles: ["project_admin"],
      requiresStepUp: true
    }),
    "memberships.revoke": policy({
      scope: "tenant_or_project",
      tenantRoles: ["tenant_admin"],
      projectRoles: ["project_admin"],
      requiresStepUp: true
    }),
    "data_grants.create": policy({ scope: "project", projectRoles: ["project_admin"], requiresStepUp: true }),
    "data_grants.revoke": policy({ scope: "project", projectRoles: ["project_admin"], requiresStepUp: true }),
    "retention_holds.create": policy({ scope: "project", projectRoles: ["project_admin"], requiresStepUp: true }),
    "retention_holds.release": policy({ scope: "project", projectRoles: ["project_admin"], requiresStepUp: true }),
    "rate_policy_changes.propose": policy({ scope: "project", projectRoles: ["project_admin"], requiresStepUp: true }),
    "rate_policy_changes.activate": policy({ scope: "project", projectRoles: ["project_admin"], requiresStepUp: true }),
    "dispatch_policy_changes.apply": policy({ scope: "project", projectRoles: ["project_admin"], requiresStepUp: true })
  });

export function getGovernanceActionPolicy(action: string): GovernanceActionPolicy {
  const entry = GOVERNANCE_ACTION_POLICIES[action];
  if (entry === undefined) {
    throw new AuthorizationDomainError({
      code: "FORBIDDEN",
      message: `Unknown or unmapped governance action "${action}"`
    });
  }
  return entry;
}

export interface AuthorizeHumanActionInput {
  readonly installation: InstallationAuthoritySnapshot;
  readonly principalId: PrincipalId;
  readonly action: string;
  readonly tenantId?: TenantId | string | null | undefined;
  readonly projectId?: ProjectId | string | null | undefined;
  readonly resourceExistsInTargetScope?: boolean | undefined;
  readonly resourceProducerNamespace?: ProducerNamespace | string | null | undefined;
  readonly stepUpVerified?: boolean | undefined;
  readonly repo: GovernanceRepository;
  readonly now: Temporal.Instant;
}

export interface AuthorizedHumanDecision {
  readonly allowed: true;
  readonly action: string;
  readonly matchedScope: "platform" | "tenant" | "project";
  readonly matchedPlatformRoles: readonly PlatformRole[];
  readonly matchedTenantRoles: readonly TenantRole[];
  readonly matchedProjectRoles: readonly ProjectRole[];
  readonly matchedDataGrantId?: DataGrantId | undefined;
}

function isDataGrantEligibleForMembership(input: {
  readonly grant: HumanDataGrantRecord;
  readonly membership: ProjectMembershipRecord;
  readonly action: DataGrantAction;
  readonly principalId: PrincipalId;
  readonly resourceProducerNamespace: ProducerNamespace | null;
  readonly now: Temporal.Instant;
}): boolean {
  const { grant, membership } = input;
  if (
    grant.membershipId !== membership.id ||
    grant.tenantId !== membership.tenantId ||
    grant.projectId !== membership.projectId ||
    grant.action !== input.action ||
    grant.state !== "active"
  ) {
    return false;
  }
  if (grant.expiresAt !== null && compareInstants(input.now, grant.expiresAt) >= 0) {
    return false;
  }

  // publisher role is restricted to own_namespace (human.<principalId>) only.
  if (membership.role === "publisher") {
    if (grant.projection !== "own_namespace") {
      return false;
    }
    const expectedOwn = `human.${input.principalId}`;
    if (grant.producerNamespace !== expectedOwn) {
      return false;
    }
  }

  if (grant.projection === "approved_project") {
    return grant.producerNamespace === null;
  }

  if (grant.producerNamespace === null) {
    return false;
  }
  if (input.resourceProducerNamespace === null) {
    return false;
  }
  return grant.producerNamespace === input.resourceProducerNamespace;
}

function resolveRequiredIds(
  policySpec: GovernanceActionPolicy,
  tenantIdRaw: TenantId | string | null | undefined,
  projectIdRaw: ProjectId | string | null | undefined
): { readonly tenantId: TenantId | null; readonly projectId: ProjectId | null } {
  const tenantId =
    tenantIdRaw !== undefined && tenantIdRaw !== null
      ? parseTenantId(tenantIdRaw, "tenant_id")
      : null;
  const projectId =
    projectIdRaw !== undefined && projectIdRaw !== null
      ? parseProjectId(projectIdRaw, "project_id")
      : null;

  if (policySpec.scope === "tenant" && tenantId === null) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: "Tenant-scoped action requires tenant_id"
    });
  }
  if (
    (policySpec.scope === "project" || policySpec.scope === "tenant_or_project") &&
    (tenantId === null || projectId === null)
  ) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: "Project-scoped action requires both tenant_id and project_id"
    });
  }
  return { tenantId, projectId };
}

export async function authorizeHumanAction(
  input: AuthorizeHumanActionInput
): Promise<AuthorizedHumanDecision> {
  assertInstallationAllowsOrdinaryAccess(input.installation, input.action);
  const policySpec = getGovernanceActionPolicy(input.action);

  const principal = await input.repo.getPrincipal(input.principalId);
  if (principal === null || principal.kind !== "human" || principal.state !== "active") {
    throw new AuthorizationDomainError({
      code: "FORBIDDEN",
      message: "Active human principal required"
    });
  }

  const { tenantId, projectId } = resolveRequiredIds(
    policySpec,
    input.tenantId,
    input.projectId
  );

  const resourceNs =
    input.resourceProducerNamespace !== undefined && input.resourceProducerNamespace !== null
      ? parseProducerNamespace(input.resourceProducerNamespace, "producer_namespace")
      : null;

  if (policySpec.scope === "platform") {
    const assignments = await input.repo.listPlatformRolesForPrincipal(principal.principalId);
    const activeRoles = assignments
      .filter((a) => a.state === "active")
      .map((a) => a.role);
    const matched = activeRoles.filter((r) => policySpec.platformRoles.includes(r));
    if (matched.length === 0) {
      throw new AuthorizationDomainError({
        code: "FORBIDDEN",
        message: `Action "${input.action}" requires platform role`
      });
    }
    if (policySpec.requiresStepUp && input.stepUpVerified !== true) {
      throw new AuthorizationDomainError({
        code: "FORBIDDEN",
        message: `Action "${input.action}" requires verified operation-bound step-up proof`
      });
    }
    return Object.freeze({
      allowed: true,
      action: input.action,
      matchedScope: "platform",
      matchedPlatformRoles: Object.freeze(matched),
      matchedTenantRoles: Object.freeze([]),
      matchedProjectRoles: Object.freeze([])
    });
  }

  if (policySpec.scope === "tenant") {
    if (input.resourceExistsInTargetScope === false) {
      throw new NotFoundDomainError({ code: "NOT_FOUND", message: "Resource not found" });
    }
    const tenantMemberships = await input.repo.listTenantMembershipsForPrincipal(
      principal.principalId,
      tenantId!
    );
    const activeTenantRoles = tenantMemberships
      .filter((m) => m.state === "active")
      .map((m) => m.role);
    if (activeTenantRoles.length === 0) {
      throw new NotFoundDomainError({ code: "NOT_FOUND", message: "Resource not found" });
    }
    const matched = activeTenantRoles.filter((r) => policySpec.tenantRoles.includes(r));
    if (matched.length === 0) {
      throw new AuthorizationDomainError({
        code: "FORBIDDEN",
        message: `Action "${input.action}" is not permitted for current tenant role`
      });
    }
    if (policySpec.requiresStepUp && input.stepUpVerified !== true) {
      throw new AuthorizationDomainError({
        code: "FORBIDDEN",
        message: `Action "${input.action}" requires verified operation-bound step-up proof`
      });
    }
    return Object.freeze({
      allowed: true,
      action: input.action,
      matchedScope: "tenant",
      matchedPlatformRoles: Object.freeze([]),
      matchedTenantRoles: Object.freeze(matched),
      matchedProjectRoles: Object.freeze([])
    });
  }

  // project or tenant_or_project scope
  const activeTenantMemberships = (
    await input.repo.listTenantMembershipsForPrincipal(principal.principalId, tenantId!)
  ).filter((m) => m.state === "active");

  const activeProjectMemberships = (
    await input.repo.listProjectMembershipsForPrincipal(
      principal.principalId,
      tenantId!,
      projectId!
    )
  ).filter((m) => m.state === "active");

  if (policySpec.scope === "tenant_or_project") {
    if (activeTenantMemberships.length === 0 && activeProjectMemberships.length === 0) {
      throw new NotFoundDomainError({ code: "NOT_FOUND", message: "Resource not found" });
    }
    if (input.resourceExistsInTargetScope === false) {
      throw new NotFoundDomainError({ code: "NOT_FOUND", message: "Resource not found" });
    }
    const matchedTenant = activeTenantMemberships
      .map((m) => m.role)
      .filter((r) => policySpec.tenantRoles.includes(r));
    const matchedProject = activeProjectMemberships
      .map((m) => m.role)
      .filter((r) => policySpec.projectRoles.includes(r));
    if (matchedTenant.length === 0 && matchedProject.length === 0) {
      throw new AuthorizationDomainError({
        code: "FORBIDDEN",
        message: `Action "${input.action}" is not permitted`
      });
    }
    if (policySpec.requiresStepUp && input.stepUpVerified !== true) {
      throw new AuthorizationDomainError({
        code: "FORBIDDEN",
        message: `Action "${input.action}" requires verified operation-bound step-up proof`
      });
    }
    return Object.freeze({
      allowed: true,
      action: input.action,
      matchedScope: matchedTenant.length > 0 ? "tenant" : "project",
      matchedPlatformRoles: Object.freeze([]),
      matchedTenantRoles: Object.freeze(matchedTenant),
      matchedProjectRoles: Object.freeze(matchedProject)
    });
  }

  // Strict project-scoped access: out-of-scope actors (even platform_admin or other-tenant members) get 404
  if (activeProjectMemberships.length === 0 || input.resourceExistsInTargetScope === false) {
    throw new NotFoundDomainError({ code: "NOT_FOUND", message: "Resource not found" });
  }

  const eligibleMemberships = activeProjectMemberships.filter((m) =>
    policySpec.projectRoles.includes(m.role)
  );
  if (eligibleMemberships.length === 0) {
    throw new AuthorizationDomainError({
      code: "FORBIDDEN",
      message: `Action "${input.action}" is not permitted for current project role`
    });
  }

  // Check publisher own-namespace boundary if actor has ONLY publisher role among eligible memberships
  const hasNonPublisherEligibleRole = eligibleMemberships.some((m) => m.role !== "publisher");
  if (!hasNonPublisherEligibleRole && policySpec.publisherOwnNamespaceOnly) {
    const ownNamespace = `human.${principal.principalId}`;
    if (resourceNs === null || resourceNs !== ownNamespace) {
      throw new NotFoundDomainError({
        code: "NOT_FOUND",
        message: "Resource not found"
      });
    }
  }

  let matchedDataGrantId: DataGrantId | undefined;
  if (policySpec.requiredDataGrantAction !== undefined) {
    const membershipIds = eligibleMemberships.map((m) => m.id);
    const grants = await input.repo.listDataGrantsForMemberships(
      membershipIds,
      policySpec.requiredDataGrantAction
    );
    const matchedGrant = grants.find((grant) =>
      eligibleMemberships.some((membership) =>
        isDataGrantEligibleForMembership({
          grant,
          membership,
          action: policySpec.requiredDataGrantAction!,
          principalId: principal.principalId,
          resourceProducerNamespace: resourceNs,
          now: input.now
        })
      )
    );
    if (matchedGrant === undefined) {
      throw new AuthorizationDomainError({
        code: "FORBIDDEN",
        message: `Action "${input.action}" requires an explicit active human_data_grant`
      });
    }
    matchedDataGrantId = matchedGrant.id;
  }

  if (policySpec.requiresStepUp && input.stepUpVerified !== true) {
    throw new AuthorizationDomainError({
      code: "FORBIDDEN",
      message: `Action "${input.action}" requires verified operation-bound step-up proof`
    });
  }

  return Object.freeze({
    allowed: true,
    action: input.action,
    matchedScope: "project",
    matchedPlatformRoles: Object.freeze([]),
    matchedTenantRoles: Object.freeze([]),
    matchedProjectRoles: Object.freeze(eligibleMemberships.map((m) => m.role)),
    ...(matchedDataGrantId !== undefined ? { matchedDataGrantId } : {})
  });
}

export async function assertLastPlatformAdminPreserved(input: {
  readonly assignment: PlatformRoleAssignmentRecord;
  readonly nextState: PlatformRoleAssignmentState;
  readonly repo: GovernanceRepository;
}): Promise<void> {
  if (
    input.assignment.role === "platform_admin" &&
    input.assignment.state === "active" &&
    input.nextState !== "active"
  ) {
    const remaining = await input.repo.countActivePlatformAdmins(input.assignment.id);
    if (remaining < 1) {
      throw new ConflictDomainError({
        code: "STATE_TRANSITION_NOT_ALLOWED",
        message: "Cannot revoke the last active platform_admin"
      });
    }
  }
}

export async function assertLastTenantAdminPreserved(input: {
  readonly membership: TenantMembershipRecord;
  readonly nextState: MembershipState;
  readonly repo: GovernanceRepository;
}): Promise<void> {
  if (
    input.membership.role === "tenant_admin" &&
    input.membership.state === "active" &&
    input.nextState !== "active"
  ) {
    const remaining = await input.repo.countActiveTenantAdmins(
      input.membership.tenantId,
      input.membership.id
    );
    if (remaining < 1) {
      throw new ConflictDomainError({
        code: "STATE_TRANSITION_NOT_ALLOWED",
        message: "Cannot suspend or revoke the last active tenant_admin"
      });
    }
  }
}

export async function assertLastProjectAdminPreserved(input: {
  readonly membership: ProjectMembershipRecord;
  readonly nextRole: ProjectRole;
  readonly nextState: MembershipState;
  readonly repo: GovernanceRepository;
}): Promise<void> {
  const wasActiveAdmin =
    input.membership.role === "project_admin" && input.membership.state === "active";
  const staysActiveAdmin = input.nextRole === "project_admin" && input.nextState === "active";
  if (wasActiveAdmin && !staysActiveAdmin) {
    const remaining = await input.repo.countActiveProjectAdmins(
      input.membership.projectId,
      input.membership.id
    );
    if (remaining < 1) {
      throw new ConflictDomainError({
        code: "STATE_TRANSITION_NOT_ALLOWED",
        message: "Cannot demote, suspend, or revoke the last active project_admin"
      });
    }
  }
}

export function assertDistinctGovernanceReviewer(input: {
  readonly proposerPrincipalId: PrincipalId;
  readonly reviewerPrincipalId: PrincipalId;
  readonly actionLabel?: string | undefined;
}): void {
  if (input.proposerPrincipalId === input.reviewerPrincipalId) {
    throw new AuthorizationDomainError({
      code: "FORBIDDEN",
      message: `${input.actionLabel ?? "Two-person governance action"} forbids proposer self-review or self-approval`
    });
  }
}

export async function authorizeProposalReview(input: {
  readonly installation: InstallationAuthoritySnapshot;
  readonly tenantId: TenantId;
  readonly projectId: ProjectId;
  readonly action: "replay_proposals.review" | "order_skip_proposals.review" | "suppression_proposals.review";
  readonly proposal: ProposalSnapshot;
  readonly reviewerPrincipalId: PrincipalId;
  readonly decision: ProposalReviewDecision;
  readonly expectedVersion: bigint;
  readonly expectedCandidateSha256: Sha256Hex;
  readonly stepUpVerified: boolean;
  readonly requiresContentReadGrant?: boolean | undefined;
  readonly repo: GovernanceRepository;
  readonly now: Temporal.Instant;
}): Promise<ProposalSnapshot> {
  await authorizeHumanAction({
    installation: input.installation,
    principalId: input.reviewerPrincipalId,
    action: input.action,
    tenantId: input.tenantId,
    projectId: input.projectId,
    stepUpVerified: input.stepUpVerified,
    repo: input.repo,
    now: input.now
  });

  assertDistinctGovernanceReviewer({
    proposerPrincipalId: input.proposal.proposerPrincipalId,
    reviewerPrincipalId: input.reviewerPrincipalId,
    actionLabel: input.action
  });

  let proposerHasContentRead = true;
  let reviewerHasContentRead = true;
  if (input.requiresContentReadGrant) {
    proposerHasContentRead = await hasActiveProjectDataGrant({
      principalId: input.proposal.proposerPrincipalId,
      tenantId: input.tenantId,
      projectId: input.projectId,
      action: "events.content.read",
      repo: input.repo,
      now: input.now
    });
    reviewerHasContentRead = await hasActiveProjectDataGrant({
      principalId: input.reviewerPrincipalId,
      tenantId: input.tenantId,
      projectId: input.projectId,
      action: "events.content.read",
      repo: input.repo,
      now: input.now
    });
  }

  return reviewProposal(input.proposal, {
    reviewerPrincipalId: input.reviewerPrincipalId,
    reviewerIsCurrentProjectAdmin: true,
    decision: input.decision,
    expectedCandidateSha256: input.expectedCandidateSha256,
    expectedVersion: input.expectedVersion,
    requiresContentReadGrant: input.requiresContentReadGrant,
    proposerHasContentRead,
    reviewerHasContentRead,
    now: input.now
  });
}

export async function authorizeProposalAdmission(input: {
  readonly installation: InstallationAuthoritySnapshot;
  readonly tenantId: TenantId;
  readonly projectId: ProjectId;
  readonly action: "replay_proposals.admit" | "order_skip_proposals.admit" | "suppression_proposals.admit";
  readonly proposal: ProposalSnapshot;
  readonly review: ProposalReviewRecord | null;
  readonly admitterPrincipalId: PrincipalId;
  readonly expectedVersion: bigint;
  readonly expectedCandidateSha256: Sha256Hex;
  readonly stepUpVerified: boolean;
  readonly repo: GovernanceRepository;
  readonly now: Temporal.Instant;
}): Promise<void> {
  await authorizeHumanAction({
    installation: input.installation,
    principalId: input.admitterPrincipalId,
    action: input.action,
    tenantId: input.tenantId,
    projectId: input.projectId,
    stepUpVerified: input.stepUpVerified,
    repo: input.repo,
    now: input.now
  });

  if (compareInstants(input.now, input.proposal.expiresAt) >= 0) {
    throw new ConflictDomainError({
      code: "EXPIRED",
      message: "Proposal has expired before admission"
    });
  }
  if (input.proposal.state !== "approved") {
    throw new ConflictDomainError({
      code: "STATE_TRANSITION_NOT_ALLOWED",
      message: `Proposal must be approved before admission (state="${input.proposal.state}")`
    });
  }
  if (input.proposal.version !== input.expectedVersion) {
    throw new ConflictDomainError({
      code: "VERSION_CONFLICT",
      message: "Proposal version mismatch"
    });
  }
  if (input.proposal.candidateSha256 !== input.expectedCandidateSha256) {
    throw new ConflictDomainError({
      code: "VERSION_CONFLICT",
      message: "Proposal candidate_sha256 mismatch"
    });
  }
  if (
    input.review === null ||
    input.review.decision !== "approve" ||
    input.review.proposalId !== input.proposal.proposalId ||
    input.review.candidateSha256 !== input.proposal.candidateSha256
  ) {
    throw new AuthorizationDomainError({
      code: "FORBIDDEN",
      message: "Proposal admission requires an accepted matching review"
    });
  }

  assertDistinctGovernanceReviewer({
    proposerPrincipalId: input.proposal.proposerPrincipalId,
    reviewerPrincipalId: input.review.reviewerPrincipalId,
    actionLabel: input.action
  });

  // Verify the recorded reviewer still holds active project_admin role at admission time
  const reviewerMemberships = await input.repo.listProjectMembershipsForPrincipal(
    input.review.reviewerPrincipalId,
    input.tenantId,
    input.projectId
  );
  const reviewerPrincipal = await input.repo.getPrincipal(input.review.reviewerPrincipalId);
  const reviewerStillAdmin =
    reviewerPrincipal !== null &&
    reviewerPrincipal.kind === "human" &&
    reviewerPrincipal.state === "active" &&
    reviewerMemberships.some((m) => m.state === "active" && m.role === "project_admin");
  if (!reviewerStillAdmin) {
    throw new AuthorizationDomainError({
      code: "FORBIDDEN",
      message: "Proposal reviewer is no longer an active project_admin"
    });
  }
}

export async function hasActiveProjectDataGrant(input: {
  readonly principalId: PrincipalId;
  readonly tenantId: TenantId;
  readonly projectId: ProjectId;
  readonly action: DataGrantAction;
  readonly resourceProducerNamespace?: ProducerNamespace | string | null | undefined;
  readonly repo: GovernanceRepository;
  readonly now: Temporal.Instant;
}): Promise<boolean> {
  const principal = await input.repo.getPrincipal(input.principalId);
  if (principal === null || principal.kind !== "human" || principal.state !== "active") {
    return false;
  }
  const activeMemberships = (
    await input.repo.listProjectMembershipsForPrincipal(
      input.principalId,
      input.tenantId,
      input.projectId
    )
  ).filter((m) => m.state === "active");
  if (activeMemberships.length === 0) {
    return false;
  }
  const resourceNs =
    input.resourceProducerNamespace !== undefined && input.resourceProducerNamespace !== null
      ? parseProducerNamespace(input.resourceProducerNamespace, "producer_namespace")
      : null;
  const grants = await input.repo.listDataGrantsForMemberships(
    activeMemberships.map((m) => m.id),
    input.action
  );
  return grants.some((grant) =>
    activeMemberships.some((membership) =>
      isDataGrantEligibleForMembership({
        grant,
        membership,
        action: input.action,
        principalId: input.principalId,
        resourceProducerNamespace: resourceNs,
        now: input.now
      })
    )
  );
}

export async function grantProjectDataAccess(input: {
  readonly installation: InstallationAuthoritySnapshot;
  readonly actorPrincipalId: PrincipalId;
  readonly tenantId: TenantId;
  readonly projectId: ProjectId;
  readonly targetMembership: ProjectMembershipRecord;
  readonly action: DataGrantAction;
  readonly projection: DataGrantProjection;
  readonly producerNamespace: ProducerNamespace | string | null;
  readonly expiresAt: Temporal.Instant | null;
  readonly stepUpVerified: boolean;
  readonly repo: GovernanceRepository;
  readonly now: Temporal.Instant;
}): Promise<HumanDataGrantRecord> {
  await authorizeHumanAction({
    installation: input.installation,
    principalId: input.actorPrincipalId,
    action: "data_grants.create",
    tenantId: input.tenantId,
    projectId: input.projectId,
    stepUpVerified: input.stepUpVerified,
    repo: input.repo,
    now: input.now
  });

  if (
    input.targetMembership.tenantId !== input.tenantId ||
    input.targetMembership.projectId !== input.projectId ||
    input.targetMembership.state !== "active"
  ) {
    throw new ConflictDomainError({
      code: "STATE_TRANSITION_NOT_ALLOWED",
      message: "Data grant requires an active membership in the target project"
    });
  }
  if (!isDataGrantAction(input.action) || !isDataGrantProjection(input.projection)) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: "Invalid data grant action or projection"
    });
  }

  let normalizedNs: ProducerNamespace | null = null;
  if (input.projection === "own_namespace") {
    if (input.producerNamespace === null) {
      throw new ValidationDomainError({
        code: "INVALID_VALUE",
        message: "own_namespace data grant requires producer_namespace"
      });
    }
    normalizedNs = parseProducerNamespace(input.producerNamespace, "producer_namespace");
    if (
      input.targetMembership.role === "publisher" &&
      normalizedNs !== `human.${input.targetMembership.principalId}`
    ) {
      throw new AuthorizationDomainError({
        code: "FORBIDDEN",
        message: "publisher data grant must match human.<principal_id> namespace"
      });
    }
  } else {
    if (input.producerNamespace !== null) {
      throw new ValidationDomainError({
        code: "INVALID_VALUE",
        message: "approved_project data grant requires null producer_namespace"
      });
    }
    if (input.targetMembership.role === "publisher") {
      throw new AuthorizationDomainError({
        code: "FORBIDDEN",
        message: "publisher role cannot be granted approved_project data scope"
      });
    }
  }

  if (input.expiresAt !== null && compareInstants(input.expiresAt, input.now) <= 0) {
    throw new ValidationDomainError({
      code: "INVALID_TIMESTAMP",
      message: "Data grant expiresAt must be in the future"
    });
  }
  if (input.repo.createDataGrant === undefined) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: "Governance repository does not implement createDataGrant"
    });
  }

  return input.repo.createDataGrant({
    id: parseDataGrantId(crypto.randomUUID(), "data_grant_id"),
    membershipId: input.targetMembership.id,
    tenantId: input.tenantId,
    projectId: input.projectId,
    action: input.action,
    projection: input.projection,
    producerNamespace: normalizedNs,
    expiresAt: input.expiresAt,
    createdBy: input.actorPrincipalId,
    createdAt: input.now
  });
}

export function assertExactGovernanceRoleString(
  kind: "platform" | "tenant" | "project",
  value: unknown
): PlatformRole | TenantRole | ProjectRole {
  if (kind === "platform" && isPlatformRole(value)) {
    return value;
  }
  if (kind === "tenant" && isTenantRole(value)) {
    return value;
  }
  if (kind === "project" && isProjectRole(value)) {
    return value;
  }
  throw new ValidationDomainError({
    code: "INVALID_VALUE",
    message: `Invalid ${kind} role "${String(value)}"`
  });
}
