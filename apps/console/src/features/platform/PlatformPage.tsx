import { type JSX, useState } from "react";
import { hashCanonicalJson } from "@relayquill/contracts";
import { type PlatformRole } from "@relayquill/domain";
import {
  type PlatformRoleAssignmentDto,
  type RecoveryReferenceDto,
  type TenantSummaryDto
} from "../../api/dtos.js";
import {
  buildPlatformPath,
  type PlatformSection,
  useConsoleRouter
} from "../../app/router.js";
import { useConsoleRuntime } from "../../app/session.js";
import { useScopedQuery } from "../../app/use-scoped-query.js";
import { CopyableId } from "../../components/CopyableId.js";
import { DataTable } from "../../components/DataTable.js";
import { FormField } from "../../components/FormField.js";
import { ConsoleIcon } from "../../components/Icons.js";
import {
  MutationFeedback,
  type MutationFeedbackState
} from "../../components/MutationFeedback.js";
import { ResourceStatePanel } from "../../components/ResourceStatePanel.js";
import { StatusBadge } from "../../components/StatusBadge.js";
import { UtcTimestamp } from "../../components/UtcTimestamp.js";
import { generateIdempotencyKey } from "../../utils/idempotency.js";
import { StepUpModal, type StepUpTargetDescriptor } from "../access/StepUpModal.js";
import { AuditPage } from "../audit/AuditPage.js";

const PLATFORM_ROLES: readonly PlatformRole[] = [
  "platform_admin",
  "platform_auditor"
];

export function PlatformPage({
  section
}: {
  readonly section: PlatformSection;
}): JSX.Element {
  const { navigate } = useConsoleRouter();
  const { api, refreshSession } = useConsoleRuntime();

  // Create Tenant state
  const [tenantSlug, setTenantSlug] = useState("");
  const [tenantName, setTenantName] = useState("");
  const [tenantReason, setTenantReason] = useState("initial_tenant_provisioning");
  const [tenantFeedback, setTenantFeedback] = useState<MutationFeedbackState>({
    kind: "idle"
  });

  // Create Project state
  const [selectedTenantForProject, setSelectedTenantForProject] = useState("");
  const [projectName, setProjectName] = useState("");
  const [projectReason, setProjectReason] = useState("initial_project_provisioning");

  // Assign Platform Role state
  const [rolePrincipalId, setRolePrincipalId] = useState("");
  const [selectedRole, setSelectedRole] = useState<PlatformRole>("platform_auditor");
  const [roleReason, setRoleReason] = useState("platform_governance_assignment");
  const [roleFeedback, setRoleFeedback] = useState<MutationFeedbackState>({
    kind: "idle"
  });

  // Pending Step-Up action
  const [pendingStepUp, setPendingStepUp] = useState<{
    readonly descriptor: StepUpTargetDescriptor;
    readonly execute: (operationProofId: string) => Promise<void>;
  } | null>(null);

  const installationQuery = useScopedQuery({
    resource: "platform.installation",
    enabled: section === "installation" || section === "tenants",
    extractVersion: (d) => d.version,
    fetcher: (signal: AbortSignal) => api.getInstallationStatus(signal)
  });

  const tenantsQuery = useScopedQuery({
    resource: "platform.tenants",
    enabled: section === "tenants",
    isEmpty: (d) => d.items.length === 0,
    fetcher: (signal: AbortSignal) => api.listTenants({ limit: 25 }, signal)
  });

  const rolesQuery = useScopedQuery({
    resource: "platform.roles",
    enabled: section === "roles",
    isEmpty: (d) => d.items.length === 0,
    fetcher: (signal: AbortSignal) => api.listPlatformRoles({ limit: 25 }, signal)
  });

  const recoveryQuery = useScopedQuery({
    resource: "platform.recovery_references",
    enabled: section === "recovery",
    isEmpty: (d) => d.items.length === 0,
    fetcher: (signal: AbortSignal) => api.listRecoveryReferences({ limit: 25 }, signal)
  });

  if (section === "audit") {
    return <AuditPage mode="platform" />;
  }

  const handleCreateTenant = async (): Promise<void> => {
    const draft = {
      schema_version: 1,
      slug: tenantSlug.trim(),
      display_name: tenantName.trim(),
      reason_code: tenantReason.trim() || "initial_tenant_provisioning"
    };
    setTenantFeedback({ kind: "submitting", label: "Provisioning tenant..." });
    const res = await api.createTenant(draft, generateIdempotencyKey("tenant-create"));
    if (!res.ok) {
      setTenantFeedback({ kind: "failed", error: res, preservedDraft: draft });
      return;
    }
    setTenantSlug("");
    setTenantName("");
    setTenantFeedback({
      kind: "succeeded",
      title: "Tenant Created",
      detail: `Provisioned tenant ${draft.display_name} (${draft.slug}).`,
      receiptId: res.data.receipt?.id
    });
    tenantsQuery.reload();
    void refreshSession();
  };

  const handleCreateProject = async (): Promise<void> => {
    const tenantId = selectedTenantForProject.trim();
    const draft = {
      schema_version: 1,
      name: projectName.trim(),
      reason_code: projectReason.trim() || "initial_project_provisioning"
    };
    setTenantFeedback({ kind: "submitting", label: "Provisioning project..." });
    const res = await api.createProject(
      tenantId,
      draft,
      generateIdempotencyKey("project-create")
    );
    if (!res.ok) {
      setTenantFeedback({ kind: "failed", error: res, preservedDraft: draft });
      return;
    }
    setProjectName("");
    setTenantFeedback({
      kind: "succeeded",
      title: "Project Created",
      detail: `Created project ${draft.name} in tenant ${tenantId}.`,
      receiptId: res.data.receipt?.id
    });
    void refreshSession();
  };

  const requestTenantLifecycleMutation = (
    tenant: TenantSummaryDto,
    action: "suspend" | "restore" | "retire"
  ): void => {
    const actionCode = `tenant.${action}`;
    const reasonCode = `platform_operator_${action}`;
    const commandPayload = {
      schema_version: 1,
      tenant_id: tenant.tenant_id,
      expected_version: tenant.version,
      expected_governance_version: tenant.governance_version,
      action,
      reason_code: reasonCode
    };
    const canonical = hashCanonicalJson(commandPayload);

    setPendingStepUp({
      descriptor: {
        action: actionCode,
        actionLabel: `${action.toUpperCase()} Tenant ${tenant.display_name}`,
        scopeKind: "tenant",
        tenantId: tenant.tenant_id,
        projectId: null,
        targetResourceId: tenant.tenant_id,
        targetVersion: tenant.version,
        canonicalCommandSha256: canonical.sha256,
        summary: `Applies ${action} transition to tenant ${tenant.slug} (${tenant.tenant_id}) at version ${tenant.version}.`
      },
      execute: async (operationProofId: string) => {
        setTenantFeedback({
          kind: "submitting",
          label: `Executing tenant ${action}...`
        });
        const body = {
          ...commandPayload,
          operation_proof_id: operationProofId,
          canonical_command_sha256: canonical.sha256
        };
        const res = await api.mutateTenant(
          tenant.tenant_id,
          action,
          body,
          generateIdempotencyKey(`tenant-${action}`)
        );
        if (!res.ok) {
          setTenantFeedback({
            kind: "failed",
            error: res,
            preservedDraft: body,
            currentServerState: tenant
          });
          return;
        }
        setTenantFeedback({
          kind: "succeeded",
          title: `Tenant ${action} accepted`,
          detail: `Tenant ${tenant.display_name} transitioned (${action}).`,
          receiptId: res.data.receipt?.id
        });
        tenantsQuery.reload();
      }
    });
  };

  const requestAssignPlatformRole = (): void => {
    const commandPayload = {
      schema_version: 1,
      principal_id: rolePrincipalId.trim(),
      role: selectedRole,
      reason_code: roleReason.trim() || "platform_governance_assignment"
    };
    const canonical = hashCanonicalJson(commandPayload);
    setPendingStepUp({
      descriptor: {
        action: "platform_roles.grant",
        actionLabel: `Grant Platform Role ${selectedRole}`,
        scopeKind: "installation",
        tenantId: null,
        projectId: null,
        targetResourceId: rolePrincipalId.trim(),
        targetVersion: "1",
        canonicalCommandSha256: canonical.sha256,
        summary: `Grants installation role ${selectedRole} to principal ${rolePrincipalId.trim()}.`
      },
      execute: async (operationProofId: string) => {
        setRoleFeedback({
          kind: "submitting",
          label: "Assigning platform role..."
        });
        const body = {
          ...commandPayload,
          operation_proof_id: operationProofId,
          canonical_command_sha256: canonical.sha256
        };
        const res = await api.assignPlatformRole(
          body,
          generateIdempotencyKey("platform-role-grant")
        );
        if (!res.ok) {
          setRoleFeedback({ kind: "failed", error: res, preservedDraft: body });
          return;
        }
        setRolePrincipalId("");
        setRoleFeedback({
          kind: "succeeded",
          title: "Platform Role Granted",
          detail: `Assigned ${selectedRole} to ${commandPayload.principal_id}.`,
          receiptId: res.data.receipt?.id
        });
        rolesQuery.reload();
      }
    });
  };

  const requestRevokePlatformRole = (assignment: PlatformRoleAssignmentDto): void => {
    const commandPayload = {
      schema_version: 1,
      assignment_id: assignment.assignment_id,
      expected_version: assignment.version,
      expected_governance_version: assignment.governance_version,
      reason_code: "platform_governance_revocation"
    };
    const canonical = hashCanonicalJson(commandPayload);
    setPendingStepUp({
      descriptor: {
        action: "platform_roles.revoke",
        actionLabel: `Revoke ${assignment.role} from ${assignment.display_name}`,
        scopeKind: "installation",
        tenantId: null,
        projectId: null,
        targetResourceId: assignment.assignment_id,
        targetVersion: assignment.version,
        canonicalCommandSha256: canonical.sha256,
        summary: `Revokes platform role assignment ${assignment.assignment_id} (last-admin protection enforced by database).`
      },
      execute: async (operationProofId: string) => {
        setRoleFeedback({
          kind: "submitting",
          label: "Revoking platform role assignment..."
        });
        const body = {
          ...commandPayload,
          operation_proof_id: operationProofId,
          canonical_command_sha256: canonical.sha256
        };
        const res = await api.revokePlatformRole(
          assignment.assignment_id,
          body,
          generateIdempotencyKey("platform-role-revoke")
        );
        if (!res.ok) {
          setRoleFeedback({
            kind: "failed",
            error: res,
            preservedDraft: body,
            currentServerState: assignment
          });
          return;
        }
        setRoleFeedback({
          kind: "succeeded",
          title: "Platform Role Revoked",
          detail: `Revoked ${assignment.role} from ${assignment.display_name}.`,
          receiptId: res.data.receipt?.id
        });
        rolesQuery.reload();
      }
    });
  };

  return (
    <div className="rq-stack">
      <header className="rq-page-header">
        <div>
          <h1 className="rq-page-title">Platform Governance & Installation Scope</h1>
          <p className="rq-page-lead">
            Manage installation-wide operating mode, tenant boundaries, platform administrator
            assignments, and read-only recovery incident references.
          </p>
        </div>
      </header>

      <div className="rq-tabs" role="tablist" aria-label="Platform governance sections">
        <button
          type="button"
          role="tab"
          className="rq-tab"
          aria-selected={section === "tenants"}
          onClick={() => {
            navigate(buildPlatformPath("tenants"));
          }}
        >
          Tenants & Projects
        </button>
        <button
          type="button"
          role="tab"
          className="rq-tab"
          aria-selected={section === "roles"}
          onClick={() => {
            navigate(buildPlatformPath("roles"));
          }}
        >
          Platform Roles
        </button>
        <button
          type="button"
          role="tab"
          className="rq-tab"
          aria-selected={section === "installation"}
          onClick={() => {
            navigate(buildPlatformPath("installation"));
          }}
        >
          Installation Mode
        </button>
        <button
          type="button"
          role="tab"
          className="rq-tab"
          aria-selected={section === "recovery"}
          onClick={() => {
            navigate(buildPlatformPath("recovery"));
          }}
        >
          Protected Recovery References
        </button>
        <button
          type="button"
          role="tab"
          className="rq-tab"
          aria-selected={false}
          onClick={() => {
            navigate(buildPlatformPath("audit"));
          }}
        >
          Platform Audit
        </button>
      </div>

      {section === "installation" ? (
        <ResourceStatePanel
          view={installationQuery.view}
          resourceLabel="Installation status"
          onRetry={installationQuery.reload}
        >
          {(inst) => (
            <section className="rq-card" aria-label="Installation status">
              <div className="rq-card-header">
                <h2 className="rq-section-title">Installation State & Control Epoch</h2>
                <StatusBadge status={inst.mode === "open" ? "active" : "quarantined"} label={inst.mode} />
              </div>
              <p className="rq-meta-text">
                Installation mode transitions into or out of recovery quarantine are restricted to
                the local administrative CLI under two-person review. The browser console presents
                read-only installation gates.
              </p>
              <dl className="rq-kv-grid">
                <dt>Operating Mode</dt>
                <dd className="mono">{inst.mode}</dd>
                <dt>Control Epoch</dt>
                <dd>
                  <CopyableId value={inst.control_epoch} />
                </dd>
                <dt>Governance Version</dt>
                <dd className="mono">{inst.governance_version}</dd>
                <dt>Event Admission Gate</dt>
                <dd>
                  <StatusBadge
                    status={inst.allow_event_admission ? "allowed" : "blocked"}
                    label={inst.allow_event_admission ? "Allowed" : "Blocked"}
                  />
                </dd>
                <dt>Broker Publication Gate</dt>
                <dd>
                  <StatusBadge
                    status={inst.allow_publication ? "allowed" : "blocked"}
                    label={inst.allow_publication ? "Allowed" : "Blocked"}
                  />
                </dd>
                <dt>Ordered Fanout Gate</dt>
                <dd>
                  <StatusBadge
                    status={inst.allow_fanout ? "allowed" : "blocked"}
                    label={inst.allow_fanout ? "Allowed" : "Blocked"}
                  />
                </dd>
                <dt>Outbound HTTP Dispatch Gate</dt>
                <dd>
                  <StatusBadge
                    status={inst.allow_send ? "allowed" : "blocked"}
                    label={inst.allow_send ? "Allowed" : "Blocked"}
                  />
                </dd>
                <dt>Updated At</dt>
                <dd>
                  <UtcTimestamp value={inst.updated_at} />
                </dd>
              </dl>
            </section>
          )}
        </ResourceStatePanel>
      ) : null}

      {section === "tenants" ? (
        <div className="rq-stack">
          <div className="rq-grid-2">
            <section className="rq-card" aria-label="Provision tenant">
              <h2 className="rq-section-title">Provision Tenant</h2>
              <FormField label="Tenant Slug" helpText="Lowercase URL-safe tenant identifier." required>
                {({ inputId, describedBy }) => (
                  <input
                    id={inputId}
                    aria-describedby={describedBy}
                    type="text"
                    className="rq-input mono"
                    value={tenantSlug}
                    onChange={(e) => {
                      setTenantSlug(e.target.value);
                    }}
                  />
                )}
              </FormField>
              <FormField label="Display Name" required>
                {({ inputId }) => (
                  <input
                    id={inputId}
                    type="text"
                    className="rq-input"
                    value={tenantName}
                    onChange={(e) => {
                      setTenantName(e.target.value);
                    }}
                  />
                )}
              </FormField>
              <FormField label="Reason Code" required>
                {({ inputId }) => (
                  <input
                    id={inputId}
                    type="text"
                    className="rq-input mono"
                    value={tenantReason}
                    onChange={(e) => {
                      setTenantReason(e.target.value);
                    }}
                  />
                )}
              </FormField>
              <div>
                <button
                  type="button"
                  className="rq-btn rq-btn-primary"
                  disabled={tenantSlug.trim().length === 0 || tenantName.trim().length === 0}
                  onClick={() => {
                    void handleCreateTenant();
                  }}
                >
                  Create Tenant
                </button>
              </div>
            </section>

            <section className="rq-card" aria-label="Provision project inside tenant">
              <h2 className="rq-section-title">Provision Project</h2>
              <FormField label="Target Tenant ID" helpText="Canonical UUID of the owning tenant." required>
                {({ inputId, describedBy }) => (
                  <input
                    id={inputId}
                    aria-describedby={describedBy}
                    type="text"
                    className="rq-input mono"
                    value={selectedTenantForProject}
                    onChange={(e) => {
                      setSelectedTenantForProject(e.target.value);
                    }}
                  />
                )}
              </FormField>
              <FormField label="Project Name" required>
                {({ inputId }) => (
                  <input
                    id={inputId}
                    type="text"
                    className="rq-input"
                    value={projectName}
                    onChange={(e) => {
                      setProjectName(e.target.value);
                    }}
                  />
                )}
              </FormField>
              <FormField label="Reason Code" required>
                {({ inputId }) => (
                  <input
                    id={inputId}
                    type="text"
                    className="rq-input mono"
                    value={projectReason}
                    onChange={(e) => {
                      setProjectReason(e.target.value);
                    }}
                  />
                )}
              </FormField>
              <div>
                <button
                  type="button"
                  className="rq-btn rq-btn-primary"
                  disabled={
                    selectedTenantForProject.trim().length === 0 ||
                    projectName.trim().length === 0
                  }
                  onClick={() => {
                    void handleCreateProject();
                  }}
                >
                  Create Project
                </button>
              </div>
            </section>
          </div>

          <MutationFeedback
            state={tenantFeedback}
            resourceLabel="Tenant or project mutation"
            onRetry={tenantsQuery.reload}
            onDismiss={() => {
              setTenantFeedback({ kind: "idle" });
            }}
          />

          <ResourceStatePanel
            view={tenantsQuery.view}
            resourceLabel="Tenants"
            emptyTitle="No tenants provisioned"
            onRetry={tenantsQuery.reload}
          >
            {(page) => (
              <section className="rq-card" aria-label="Tenants inventory">
                <div className="rq-card-header">
                  <h2 className="rq-section-title">Tenants</h2>
                  <button type="button" className="rq-btn" onClick={tenantsQuery.reload}>
                    <ConsoleIcon name="refresh" />
                    <span>Refresh</span>
                  </button>
                </div>
                <DataTable<TenantSummaryDto>
                  caption="Platform tenants"
                  rows={page.items}
                  rowKey={(t) => t.tenant_id}
                  columns={[
                    {
                      key: "tenant",
                      header: "Tenant",
                      render: (t) => (
                        <div className="rq-stack-sm">
                          <strong>{t.display_name}</strong>
                          <span className="mono">{t.slug}</span>
                          <CopyableId value={t.tenant_id} compact />
                        </div>
                      )
                    },
                    {
                      key: "state",
                      header: "State",
                      render: (t) => <StatusBadge status={t.state} />
                    },
                    {
                      key: "versions",
                      header: "Version / Governance",
                      render: (t) => (
                        <span className="mono">
                          v{t.version} (gov {t.governance_version})
                        </span>
                      )
                    },
                    {
                      key: "created",
                      header: "Created At",
                      render: (t) => <UtcTimestamp value={t.created_at} />
                    },
                    {
                      key: "actions",
                      header: "Lifecycle Actions (Step-Up)",
                      render: (t) => (
                        <div className="rq-row">
                          <button
                            type="button"
                            className="rq-btn"
                            onClick={() => {
                              setSelectedTenantForProject(t.tenant_id);
                            }}
                          >
                            Select for New Project
                          </button>
                          {t.state === "active" ? (
                            <button
                              type="button"
                              className="rq-btn"
                              onClick={() => {
                                requestTenantLifecycleMutation(t, "suspend");
                              }}
                            >
                              Suspend
                            </button>
                          ) : null}
                          {t.state === "suspended" ? (
                            <button
                              type="button"
                              className="rq-btn"
                              onClick={() => {
                                requestTenantLifecycleMutation(t, "restore");
                              }}
                            >
                              Restore
                            </button>
                          ) : null}
                          {t.state !== "retired" ? (
                            <button
                              type="button"
                              className="rq-btn rq-btn-danger"
                              onClick={() => {
                                requestTenantLifecycleMutation(t, "retire");
                              }}
                            >
                              Retire
                            </button>
                          ) : null}
                        </div>
                      )
                    }
                  ]}
                />
              </section>
            )}
          </ResourceStatePanel>
        </div>
      ) : null}

      {section === "roles" ? (
        <div className="rq-stack">
          <section className="rq-card" aria-label="Grant platform role">
            <h2 className="rq-section-title">Grant Platform Role (Step-Up Required)</h2>
            <div className="rq-grid-3">
              <FormField label="Principal UUID" required>
                {({ inputId }) => (
                  <input
                    id={inputId}
                    type="text"
                    className="rq-input mono"
                    value={rolePrincipalId}
                    onChange={(e) => {
                      setRolePrincipalId(e.target.value);
                    }}
                  />
                )}
              </FormField>
              <FormField label="Platform Role" required>
                {({ inputId }) => (
                  <select
                    id={inputId}
                    className="rq-select"
                    value={selectedRole}
                    onChange={(e) => {
                      setSelectedRole(e.target.value as PlatformRole);
                    }}
                  >
                    {PLATFORM_ROLES.map((r) => (
                      <option key={r} value={r}>
                        {r}
                      </option>
                    ))}
                  </select>
                )}
              </FormField>
              <FormField label="Reason Code" required>
                {({ inputId }) => (
                  <input
                    id={inputId}
                    type="text"
                    className="rq-input mono"
                    value={roleReason}
                    onChange={(e) => {
                      setRoleReason(e.target.value);
                    }}
                  />
                )}
              </FormField>
            </div>
            <div>
              <button
                type="button"
                className="rq-btn rq-btn-primary"
                disabled={rolePrincipalId.trim().length === 0}
                onClick={requestAssignPlatformRole}
              >
                <ConsoleIcon name="key" />
                <span>Grant Platform Role</span>
              </button>
            </div>
          </section>

          <MutationFeedback
            state={roleFeedback}
            resourceLabel="Platform role assignment"
            onRetry={rolesQuery.reload}
            onDismiss={() => {
              setRoleFeedback({ kind: "idle" });
            }}
          />

          <ResourceStatePanel
            view={rolesQuery.view}
            resourceLabel="Platform role assignments"
            onRetry={rolesQuery.reload}
          >
            {(page) => (
              <section className="rq-card" aria-label="Platform role inventory">
                <h2 className="rq-section-title">Active & Historical Platform Roles</h2>
                <DataTable<PlatformRoleAssignmentDto>
                  caption="Platform role assignments"
                  rows={page.items}
                  rowKey={(a) => a.assignment_id}
                  columns={[
                    {
                      key: "principal",
                      header: "Principal",
                      render: (a) => (
                        <div className="rq-stack-sm">
                          <strong>{a.display_name}</strong>
                          <CopyableId value={a.principal_id} compact />
                        </div>
                      )
                    },
                    {
                      key: "role",
                      header: "Role",
                      render: (a) => <span className="mono">{a.role}</span>
                    },
                    {
                      key: "state",
                      header: "State",
                      render: (a) => <StatusBadge status={a.state} />
                    },
                    {
                      key: "version",
                      header: "Version",
                      render: (a) => (
                        <span className="mono">
                          v{a.version} (gov {a.governance_version})
                        </span>
                      )
                    },
                    {
                      key: "actions",
                      header: "Actions",
                      render: (a) =>
                        a.state === "active" ? (
                          <button
                            type="button"
                            className="rq-btn rq-btn-danger"
                            onClick={() => {
                              requestRevokePlatformRole(a);
                            }}
                          >
                            Revoke (Step-Up)
                          </button>
                        ) : (
                          <span className="rq-meta-text">Revoked</span>
                        )
                    }
                  ]}
                />
              </section>
            )}
          </ResourceStatePanel>
        </div>
      ) : null}

      {section === "recovery" ? (
        <ResourceStatePanel
          view={recoveryQuery.view}
          resourceLabel="Protected recovery references"
          emptyTitle="No protected recovery incidents recorded"
          onRetry={recoveryQuery.reload}
        >
          {(page) => (
            <section className="rq-card" aria-label="Protected recovery references">
              <div className="rq-card-header">
                <h2 className="rq-section-title">Read-Only Protected Recovery References</h2>
                <StatusBadge status="verified_supported" label="CLI-Only Execution Boundary" />
              </div>
              <p className="rq-meta-text">
                Protected recovery actions (`rq_recovery.*`) never execute through the browser API.
                This table surfaces safe incident identifiers and state references for audit correlation.
              </p>
              <DataTable<RecoveryReferenceDto>
                caption="Protected recovery references"
                rows={page.items}
                rowKey={(r) => r.incident_id}
                columns={[
                  {
                    key: "id",
                    header: "Incident ID",
                    render: (r) => <CopyableId value={r.incident_id} />
                  },
                  {
                    key: "scope",
                    header: "Scope",
                    render: (r) => <span className="mono">{r.scope_kind}</span>
                  },
                  {
                    key: "state",
                    header: "State",
                    render: (r) => <StatusBadge status={r.state} />
                  },
                  {
                    key: "summary",
                    header: "Summary Code",
                    render: (r) => <span className="mono">{r.summary_code}</span>
                  },
                  {
                    key: "created",
                    header: "Recorded At",
                    render: (r) => <UtcTimestamp value={r.created_at} />
                  }
                ]}
              />
            </section>
          )}
        </ResourceStatePanel>
      ) : null}

      <StepUpModal
        target={pendingStepUp?.descriptor ?? null}
        onCancel={() => {
          setPendingStepUp(null);
        }}
        onVerified={async (proof) => {
          const current = pendingStepUp;
          setPendingStepUp(null);
          if (current !== null) {
            await current.execute(proof.operationProofId);
          }
        }}
      />
    </div>
  );
}
