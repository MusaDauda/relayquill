import { type JSX, useState } from "react";
import { hashCanonicalJson } from "@relayquill/contracts";
import {
  DATA_GRANT_ACTIONS,
  DATA_GRANT_PROJECTIONS,
  type DataGrantAction,
  type DataGrantProjection,
  PROJECT_ROLES,
  type ProjectRole,
  RATE_BUCKET_OPERATIONS,
  RATE_POLICY_CHANGE_SCOPE_KINDS,
  type RateBucketOperation,
  type RatePolicyChangeScopeKind
} from "@relayquill/domain";
import {
  type HumanDataGrantDto,
  type ProjectMembershipDto,
  type RatePolicyChangeDto,
  type RetentionHoldDto
} from "../../api/dtos.js";
import { useActiveScope } from "../../app/scope.js";
import { useConsoleRuntime } from "../../app/session.js";
import { useScopedQuery } from "../../app/use-scoped-query.js";
import { CopyableId } from "../../components/CopyableId.js";
import { DataTable } from "../../components/DataTable.js";
import { FormField } from "../../components/FormField.js";
import {
  MutationFeedback,
  type MutationFeedbackState
} from "../../components/MutationFeedback.js";
import { ResourceStatePanel } from "../../components/ResourceStatePanel.js";
import { StatusBadge } from "../../components/StatusBadge.js";
import { UtcTimestamp } from "../../components/UtcTimestamp.js";
import { generateIdempotencyKey } from "../../utils/idempotency.js";
import { StepUpModal, type StepUpTargetDescriptor } from "../access/StepUpModal.js";

export function LimitsPage(): JSX.Element {
  const { api } = useConsoleRuntime();
  const scope = useActiveScope();

  // Rate policy proposal state
  const [rateScopeKind, setRateScopeKind] = useState<RatePolicyChangeScopeKind>("project");
  const [rateOwnerId, setRateOwnerId] = useState(scope.projectId);
  const [rateOperation, setRateOperation] = useState<RateBucketOperation>("send_start");
  const [rateRps, setRateRps] = useState(50);
  const [rateBurst, setRateBurst] = useState(100);
  const [rateMicrotokens, setRateMicrotokens] = useState("1000000");

  // Membership & Role state
  const [memberPrincipalId, setMemberPrincipalId] = useState("");
  const [memberRole, setMemberRole] = useState<ProjectRole>("operator");

  // Human Data Grant state
  const [grantMembershipId, setGrantMembershipId] = useState("");
  const [grantAction, setGrantAction] = useState<DataGrantAction>("events.content.read");
  const [grantProjection, setGrantProjection] = useState<DataGrantProjection>("approved_project");
  const [grantNamespace, setGrantNamespace] = useState("");
  const [grantExpiresAt, setGrantExpiresAt] = useState(() =>
    new Date(Date.now() + 7 * 24 * 3600 * 1000).toISOString().replace(/\.\d{3}Z$/, "Z")
  );

  // Retention Hold state
  const [holdTargetKind, setHoldTargetKind] = useState("event");
  const [holdTargetId, setHoldTargetId] = useState("");
  const holdReasonCode = "incident_audit_preservation";
  const [holdReviewAt, setHoldReviewAt] = useState(() =>
    new Date(Date.now() + 14 * 24 * 3600 * 1000).toISOString().replace(/\.\d{3}Z$/, "Z")
  );

  const [feedback, setFeedback] = useState<MutationFeedbackState>({ kind: "idle" });
  const [pendingStepUp, setPendingStepUp] = useState<{
    readonly descriptor: StepUpTargetDescriptor;
    readonly execute: (operationProofId: string) => Promise<void>;
  } | null>(null);

  const capacityQuery = useScopedQuery({
    resource: "project.capacity_dispatch",
    fetcher: (signal: AbortSignal) =>
      api.getCapacityAndDispatch(scope.tenantId, scope.projectId, signal)
  });

  const rateChangesQuery = useScopedQuery({
    resource: "project.rate_policy_changes",
    isEmpty: (d) => d.items.length === 0,
    fetcher: (signal: AbortSignal) =>
      api.listRatePolicyChanges(scope.tenantId, scope.projectId, signal)
  });

  const membershipsQuery = useScopedQuery({
    resource: "project.memberships",
    isEmpty: (d) => d.items.length === 0,
    fetcher: (signal: AbortSignal) =>
      api.listMemberships(scope.tenantId, scope.projectId, { limit: 50 }, signal)
  });

  const grantsQuery = useScopedQuery({
    resource: "project.data_grants",
    isEmpty: (d) => d.items.length === 0,
    fetcher: (signal: AbortSignal) =>
      api.listDataGrants(scope.tenantId, scope.projectId, { limit: 50 }, signal)
  });

  const holdsQuery = useScopedQuery({
    resource: "project.retention_holds",
    isEmpty: (d) => d.items.length === 0,
    fetcher: (signal: AbortSignal) =>
      api.listRetentionHolds(scope.tenantId, scope.projectId, signal)
  });

  const handleProposeRatePolicy = async (): Promise<void> => {
    const res = await api.proposeRatePolicyChange(
      scope.tenantId,
      scope.projectId,
      {
        schema_version: 1,
        scope_kind: rateScopeKind,
        owner_id: rateOwnerId.trim(),
        operation: rateOperation,
        requests_per_second: rateRps,
        burst: rateBurst,
        microtokens_per_request: rateMicrotokens.trim()
      },
      generateIdempotencyKey("rate-propose")
    );
    if (!res.ok) {
      setFeedback({ kind: "failed", error: res });
      return;
    }
    setFeedback({
      kind: "succeeded",
      title: "Rate Policy Change Proposed",
      detail: `Change ${res.data.change_id} queued (${res.data.state}); held reservations drain cleanly.`
    });
    rateChangesQuery.reload();
  };

  const openActivateRateChange = (change: RatePolicyChangeDto): void => {
    const body = {
      schema_version: 1,
      expected_version: change.version,
      candidate_sha256: change.candidate_sha256,
      reason_code: "activate_rate_policy_change"
    };
    const canonical = hashCanonicalJson(body);
    setPendingStepUp({
      descriptor: {
        action: "rate_policy_changes.activate",
        actionLabel: `Activate Rate Policy (${change.operation})`,
        scopeKind: "project",
        tenantId: scope.tenantId,
        projectId: scope.projectId,
        targetResourceId: change.change_id,
        targetVersion: change.version,
        canonicalCommandSha256: canonical.sha256,
        summary: `Activates rate change ${change.change_id} (${change.requests_per_second} rps, burst ${change.burst}).`
      },
      execute: async (operationProofId: string) => {
        const res = await api.activateRatePolicyChange(
          scope.tenantId,
          scope.projectId,
          change.change_id,
          { ...body, operation_proof_id: operationProofId },
          generateIdempotencyKey("rate-act")
        );
        if (!res.ok) {
          setFeedback({ kind: "failed", error: res, currentServerState: change });
          return;
        }
        setFeedback({
          kind: "succeeded",
          title: "Rate Policy Change Activated",
          detail: `Rate change ${change.change_id} activated cleanly.`,
          receiptId: res.data.receipt?.id
        });
        rateChangesQuery.reload();
        capacityQuery.reload();
      }
    });
  };

  const openGrantStepUp = (): void => {
    const body = {
      schema_version: 1,
      membership_id: grantMembershipId.trim(),
      action: grantAction,
      projection: grantProjection,
      ...(grantProjection === "own_namespace" && grantNamespace.trim().length > 0
        ? { producer_namespace: grantNamespace.trim() }
        : {}),
      expires_at: grantExpiresAt.trim(),
      reason_code: "scoped_payload_inspection_grant"
    };
    const canonical = hashCanonicalJson(body);
    setPendingStepUp({
      descriptor: {
        action: "data_grants.create",
        actionLabel: `Grant ${grantAction} (${grantProjection})`,
        scopeKind: "project",
        tenantId: scope.tenantId,
        projectId: scope.projectId,
        targetResourceId: grantMembershipId.trim(),
        targetVersion: "1",
        canonicalCommandSha256: canonical.sha256,
        summary: `Issues human data grant "${grantAction}" with projection "${grantProjection}" on membership ${grantMembershipId.trim()}.`
      },
      execute: async (operationProofId: string) => {
        const res = await api.createDataGrant(
          scope.tenantId,
          scope.projectId,
          { ...body, operation_proof_id: operationProofId },
          generateIdempotencyKey("grant-create")
        );
        if (!res.ok) {
          setFeedback({ kind: "failed", error: res });
          return;
        }
        setFeedback({
          kind: "succeeded",
          title: "Human Data Grant Issued",
          detail: `Grant ${res.data.grant_id} (${res.data.action}) is active.`
        });
        grantsQuery.reload();
      }
    });
  };

  const openMemberCreateStepUp = (): void => {
    const body = {
      schema_version: 1,
      principal_id: memberPrincipalId.trim(),
      role: memberRole,
      reason_code: "project_membership_grant"
    };
    const canonical = hashCanonicalJson(body);
    setPendingStepUp({
      descriptor: {
        action: "memberships.change_role",
        actionLabel: `Grant Project Role ${memberRole}`,
        scopeKind: "project",
        tenantId: scope.tenantId,
        projectId: scope.projectId,
        targetResourceId: memberPrincipalId.trim(),
        targetVersion: "1",
        canonicalCommandSha256: canonical.sha256,
        summary: `Assigns project role "${memberRole}" to principal ${memberPrincipalId.trim()}.`
      },
      execute: async (operationProofId: string) => {
        const res = await api.createMembership(
          scope.tenantId,
          scope.projectId,
          { ...body, operation_proof_id: operationProofId },
          generateIdempotencyKey("member-create")
        );
        if (!res.ok) {
          setFeedback({ kind: "failed", error: res });
          return;
        }
        setMemberPrincipalId("");
        setFeedback({
          kind: "succeeded",
          title: "Project Membership Created",
          detail: `Membership ${res.data.membership_id} assigned ${res.data.role}.`
        });
        membershipsQuery.reload();
      }
    });
  };

  return (
    <div className="rq-stack">
      <header className="rq-page-header">
        <div>
          <h1 className="rq-page-title">Limits, Rate Budgets, RBAC & Data Grants</h1>
          <p className="rq-page-lead">
            Monitor send slot occupancy and draining rate policy updates, administer project RBAC
            memberships, issue explicit <span className="kbd-chip">human_data_grants</span>, and
            govern legal/incident retention holds.
          </p>
        </div>
      </header>

      <MutationFeedback state={feedback} resourceLabel="Limits & Access Governance" />

      <section className="rq-card" aria-label="Dispatch capacity and rate budgets">
        <h2 className="rq-section-title">Dispatch Capacity & Send Slot Budgets</h2>
        <ResourceStatePanel
          view={capacityQuery.view}
          resourceLabel="Capacity and dispatch budgets"
          onRetry={capacityQuery.reload}
        >
          {(cap) => (
            <dl className="rq-kv-grid">
              <dt>Dispatch Domain / Policy Epoch</dt>
              <dd className="mono">
                {cap.dispatch_domain_id} (epoch {cap.policy_epoch})
              </dd>
              <dt>Project Dispatch Weight</dt>
              <dd className="mono">{cap.project_weight}</dd>
              <dt>Send Slots (Active / Approved)</dt>
              <dd className="mono">
                {cap.active_send_slots} / {cap.approved_send_slots}
              </dd>
              <dt>Rate Budget & Burst</dt>
              <dd className="mono">
                {cap.rate_requests_per_second} req/s (burst {cap.rate_burst}, held reservations{" "}
                {cap.held_rate_reservations})
              </dd>
              <dt>Microtokens / Request</dt>
              <dd className="mono">{cap.microtokens_per_request}</dd>
            </dl>
          )}
        </ResourceStatePanel>

        <div className="rq-card-inset">
          <strong className="rq-label">Propose Draining Rate Policy Change</strong>
          <div className="rq-grid-3">
            <FormField label="Scope Kind">
              {({ inputId }) => (
                <select
                  id={inputId}
                  className="rq-select"
                  value={rateScopeKind}
                  onChange={(e) => {
                    setRateScopeKind(e.target.value as RatePolicyChangeScopeKind);
                  }}
                >
                  {RATE_POLICY_CHANGE_SCOPE_KINDS.map((k) => (
                    <option key={k} value={k}>
                      {k}
                    </option>
                  ))}
                </select>
              )}
            </FormField>
            <FormField label="Owner UUID">
              {({ inputId }) => (
                <input
                  id={inputId}
                  className="rq-input mono"
                  value={rateOwnerId}
                  onChange={(e) => {
                    setRateOwnerId(e.target.value);
                  }}
                />
              )}
            </FormField>
            <FormField label="Bucket Operation">
              {({ inputId }) => (
                <select
                  id={inputId}
                  className="rq-select"
                  value={rateOperation}
                  onChange={(e) => {
                    setRateOperation(e.target.value as RateBucketOperation);
                  }}
                >
                  {RATE_BUCKET_OPERATIONS.map((op) => (
                    <option key={op} value={op}>
                      {op}
                    </option>
                  ))}
                </select>
              )}
            </FormField>
            <FormField label="Requests / Second">
              {({ inputId }) => (
                <input
                  id={inputId}
                  type="number"
                  min={1}
                  className="rq-input"
                  value={rateRps}
                  onChange={(e) => {
                    setRateRps(Math.max(1, Number(e.target.value) || 1));
                  }}
                />
              )}
            </FormField>
            <FormField label="Burst Capacity">
              {({ inputId }) => (
                <input
                  id={inputId}
                  type="number"
                  min={1}
                  className="rq-input"
                  value={rateBurst}
                  onChange={(e) => {
                    setRateBurst(Math.max(1, Number(e.target.value) || 1));
                  }}
                />
              )}
            </FormField>
            <FormField label="Microtokens / Req">
              {({ inputId }) => (
                <input
                  id={inputId}
                  className="rq-input mono"
                  value={rateMicrotokens}
                  onChange={(e) => {
                    setRateMicrotokens(e.target.value);
                  }}
                />
              )}
            </FormField>
          </div>
          <button
            type="button"
            className="rq-btn rq-btn-primary"
            onClick={() => {
              void handleProposeRatePolicy();
            }}
          >
            Propose Rate Policy Change
          </button>
        </div>

        <ResourceStatePanel
          view={rateChangesQuery.view}
          resourceLabel="Rate policy changes"
          emptyTitle="No pending or recent rate policy changes"
          onRetry={rateChangesQuery.reload}
        >
          {(rcPage) => (
            <DataTable<RatePolicyChangeDto>
              caption="Rate policy changes"
              rows={rcPage.items}
              rowKey={(r) => r.change_id}
              columns={[
                {
                  key: "op",
                  header: "Scope & Operation",
                  render: (r) => (
                    <span className="mono">
                      {r.scope_kind}:{r.operation} ({r.requests_per_second} rps / burst {r.burst})
                    </span>
                  )
                },
                {
                  key: "state",
                  header: "Drain State",
                  render: (r) => (
                    <div className="rq-row">
                      <StatusBadge status={r.state} />
                      <span className="kbd-chip">held: {r.held_reservation_count}</span>
                    </div>
                  )
                },
                {
                  key: "action",
                  header: "Activate",
                  render: (r) =>
                    r.state === "proposed" || r.state === "draining" ? (
                      <button
                        type="button"
                        className="rq-btn rq-btn-primary"
                        onClick={() => {
                          openActivateRateChange(r);
                        }}
                      >
                        Activate (Step-Up)
                      </button>
                    ) : null
                }
              ]}
            />
          )}
        </ResourceStatePanel>
      </section>

      <section className="rq-card" aria-label="Project RBAC memberships">
        <h2 className="rq-section-title">Project RBAC Memberships</h2>
        <div className="rq-grid-3">
          <FormField label="Principal UUID" required>
            {({ inputId }) => (
              <input
                id={inputId}
                className="rq-input mono"
                value={memberPrincipalId}
                onChange={(e) => {
                  setMemberPrincipalId(e.target.value);
                }}
              />
            )}
          </FormField>
          <FormField label="Project Role">
            {({ inputId }) => (
              <select
                id={inputId}
                className="rq-select"
                value={memberRole}
                onChange={(e) => {
                  setMemberRole(e.target.value as ProjectRole);
                }}
              >
                {PROJECT_ROLES.map((role) => (
                  <option key={role} value={role}>
                    {role}
                  </option>
                ))}
              </select>
            )}
          </FormField>
          <div className="rq-row">
            <button
              type="button"
              className="rq-btn rq-btn-primary"
              disabled={memberPrincipalId.trim().length === 0}
              onClick={openMemberCreateStepUp}
            >
              Add / Update Member (Step-Up)
            </button>
          </div>
        </div>

        <ResourceStatePanel
          view={membershipsQuery.view}
          resourceLabel="Project memberships"
          emptyTitle="No project members found"
          onRetry={membershipsQuery.reload}
        >
          {(memPage) => (
            <DataTable<ProjectMembershipDto>
              caption="Project memberships"
              rows={memPage.items}
              rowKey={(m) => m.membership_id}
              columns={[
                {
                  key: "principal",
                  header: "Principal & Membership ID",
                  render: (m) => (
                    <div className="rq-stack-sm">
                      <strong>{m.display_name}</strong>
                      <CopyableId value={m.membership_id} />
                    </div>
                  )
                },
                {
                  key: "role",
                  header: "Role & State",
                  render: (m) => (
                    <div className="rq-row">
                      <span className="kbd-chip">{m.role}</span>
                      <StatusBadge status={m.state} />
                    </div>
                  )
                },
                {
                  key: "actions",
                  header: "Governance",
                  render: (m) => (
                    <div className="rq-row">
                      <button
                        type="button"
                        className="rq-btn"
                        onClick={() => {
                          setGrantMembershipId(m.membership_id);
                        }}
                      >
                        Select for Data Grant
                      </button>
                      {m.state === "active" ? (
                        <button
                          type="button"
                          className="rq-btn rq-btn-danger"
                          onClick={() => {
                            const body = {
                              schema_version: 1,
                              expected_version: m.version,
                              expected_authority_version: m.authority_version,
                              reason_code: "operator_revoke_membership"
                            };
                            const canonical = hashCanonicalJson(body);
                            setPendingStepUp({
                              descriptor: {
                                action: "memberships.revoke",
                                actionLabel: `Revoke Membership (${m.display_name})`,
                                scopeKind: "project",
                                tenantId: scope.tenantId,
                                projectId: scope.projectId,
                                targetResourceId: m.membership_id,
                                targetVersion: m.version,
                                canonicalCommandSha256: canonical.sha256,
                                summary: `Revokes project access for ${m.display_name} (bumps authority epoch).`
                              },
                              execute: async (operationProofId) => {
                                const res = await api.mutateMembership(
                                  scope.tenantId,
                                  scope.projectId,
                                  m.membership_id,
                                  "revoke",
                                  { ...body, operation_proof_id: operationProofId },
                                  generateIdempotencyKey("member-revoke")
                                );
                                if (!res.ok) {
                                  setFeedback({ kind: "failed", error: res });
                                  return;
                                }
                                membershipsQuery.reload();
                              }
                            });
                          }}
                        >
                          Revoke (Step-Up)
                        </button>
                      ) : null}
                    </div>
                  )
                }
              ]}
            />
          )}
        </ResourceStatePanel>
      </section>

      <section className="rq-card" aria-label="Human payload data grants">
        <h2 className="rq-section-title">Human Data Grants (Payload & Receipt Access)</h2>
        <div className="rq-grid-3">
          <FormField label="Membership UUID" required>
            {({ inputId }) => (
              <input
                id={inputId}
                className="rq-input mono"
                value={grantMembershipId}
                onChange={(e) => {
                  setGrantMembershipId(e.target.value);
                }}
              />
            )}
          </FormField>
          <FormField label="Grant Action">
            {({ inputId }) => (
              <select
                id={inputId}
                className="rq-select"
                value={grantAction}
                onChange={(e) => {
                  setGrantAction(e.target.value as DataGrantAction);
                }}
              >
                {DATA_GRANT_ACTIONS.map((a) => (
                  <option key={a} value={a}>
                    {a}
                  </option>
                ))}
              </select>
            )}
          </FormField>
          <FormField label="Projection Boundary">
            {({ inputId }) => (
              <select
                id={inputId}
                className="rq-select"
                value={grantProjection}
                onChange={(e) => {
                  setGrantProjection(e.target.value as DataGrantProjection);
                }}
              >
                {DATA_GRANT_PROJECTIONS.map((p) => (
                  <option key={p} value={p}>
                    {p}
                  </option>
                ))}
              </select>
            )}
          </FormField>
          {grantProjection === "own_namespace" ? (
            <FormField label="Producer Namespace">
              {({ inputId }) => (
                <input
                  id={inputId}
                  className="rq-input mono"
                  value={grantNamespace}
                  onChange={(e) => {
                    setGrantNamespace(e.target.value);
                  }}
                />
              )}
            </FormField>
          ) : null}
          <FormField label="Grant Expiry (UTC)">
            {({ inputId }) => (
              <input
                id={inputId}
                className="rq-input mono"
                value={grantExpiresAt}
                onChange={(e) => {
                  setGrantExpiresAt(e.target.value);
                }}
              />
            )}
          </FormField>
        </div>
        <div className="rq-row">
          <button
            type="button"
            className="rq-btn rq-btn-primary"
            disabled={grantMembershipId.trim().length === 0}
            onClick={openGrantStepUp}
          >
            Issue Human Data Grant (Step-Up)
          </button>
        </div>

        <ResourceStatePanel
          view={grantsQuery.view}
          resourceLabel="Human data grants"
          emptyTitle="No human data grants configured"
          onRetry={grantsQuery.reload}
        >
          {(grantsPage) => (
            <DataTable<HumanDataGrantDto>
              caption="Human data grants"
              rows={grantsPage.items}
              rowKey={(g) => g.grant_id}
              columns={[
                {
                  key: "action",
                  header: "Action & Projection",
                  render: (g) => (
                    <div className="rq-stack-sm">
                      <span className="kbd-chip">{g.action}</span>
                      <span className="mono">
                        {g.projection}
                        {g.producer_namespace !== null ? ` (${g.producer_namespace})` : ""}
                      </span>
                    </div>
                  )
                },
                {
                  key: "state",
                  header: "State & Expiry",
                  render: (g) => (
                    <div className="rq-row">
                      <StatusBadge status={g.state} />
                      {g.expires_at !== null ? (
                        <UtcTimestamp value={g.expires_at} showLocal={false} />
                      ) : null}
                    </div>
                  )
                },
                {
                  key: "revoke",
                  header: "Revoke",
                  render: (g) =>
                    g.state === "active" ? (
                      <button
                        type="button"
                        className="rq-btn rq-btn-danger"
                        onClick={() => {
                          const body = {
                            schema_version: 1,
                            expected_version: g.version,
                            reason_code: "operator_revoke_data_grant"
                          };
                          const canonical = hashCanonicalJson(body);
                          setPendingStepUp({
                            descriptor: {
                              action: "data_grants.revoke",
                              actionLabel: `Revoke Data Grant (${g.action})`,
                              scopeKind: "project",
                              tenantId: scope.tenantId,
                              projectId: scope.projectId,
                              targetResourceId: g.grant_id,
                              targetVersion: g.version,
                              canonicalCommandSha256: canonical.sha256,
                              summary: `Revokes data grant ${g.grant_id} (${g.action}).`
                            },
                            execute: async (operationProofId) => {
                              const res = await api.revokeDataGrant(
                                scope.tenantId,
                                scope.projectId,
                                g.grant_id,
                                { ...body, operation_proof_id: operationProofId },
                                generateIdempotencyKey("grant-revoke")
                              );
                              if (!res.ok) {
                                setFeedback({ kind: "failed", error: res });
                                return;
                              }
                              grantsQuery.reload();
                            }
                          });
                        }}
                      >
                        Revoke (Step-Up)
                      </button>
                    ) : null
                }
              ]}
            />
          )}
        </ResourceStatePanel>
      </section>

      <section className="rq-card" aria-label="Retention holds">
        <h2 className="rq-section-title">Evidence Retention Holds</h2>
        <div className="rq-grid-3">
          <FormField label="Target Kind">
            {({ inputId }) => (
              <select
                id={inputId}
                className="rq-select"
                value={holdTargetKind}
                onChange={(e) => {
                  setHoldTargetKind(e.target.value);
                }}
              >
                <option value="event">event</option>
                <option value="delivery">delivery</option>
                <option value="project">project</option>
              </select>
            )}
          </FormField>
          <FormField label="Target UUID">
            {({ inputId }) => (
              <input
                id={inputId}
                className="rq-input mono"
                value={holdTargetId}
                onChange={(e) => {
                  setHoldTargetId(e.target.value);
                }}
              />
            )}
          </FormField>
          <FormField label="Review At (UTC)">
            {({ inputId }) => (
              <input
                id={inputId}
                className="rq-input mono"
                value={holdReviewAt}
                onChange={(e) => {
                  setHoldReviewAt(e.target.value);
                }}
              />
            )}
          </FormField>
        </div>
        <div className="rq-row">
          <button
            type="button"
            className="rq-btn rq-btn-primary"
            disabled={holdTargetId.trim().length === 0}
            onClick={() => {
              void (async () => {
                const res = await api.createRetentionHold(
                  scope.tenantId,
                  scope.projectId,
                  {
                    schema_version: 1,
                    target_kind: holdTargetKind,
                    target_id: holdTargetId.trim(),
                    reason_code: holdReasonCode,
                    review_at: holdReviewAt.trim()
                  },
                  generateIdempotencyKey("hold-create")
                );
                if (!res.ok) {
                  setFeedback({ kind: "failed", error: res });
                  return;
                }
                holdsQuery.reload();
              })();
            }}
          >
            Place Retention Hold
          </button>
        </div>

        <ResourceStatePanel
          view={holdsQuery.view}
          resourceLabel="Retention holds"
          emptyTitle="No active retention holds"
          onRetry={holdsQuery.reload}
        >
          {(holdsPage) => (
            <DataTable<RetentionHoldDto>
              caption="Retention holds"
              rows={holdsPage.items}
              rowKey={(h) => h.hold_id}
              columns={[
                {
                  key: "target",
                  header: "Target",
                  render: (h) => (
                    <span className="mono">
                      {h.target_kind}:{h.target_id} ({h.reason_code})
                    </span>
                  )
                },
                {
                  key: "state",
                  header: "State & Review",
                  render: (h) => (
                    <div className="rq-row">
                      <StatusBadge status={h.state} />
                      <UtcTimestamp value={h.review_at} showLocal={false} />
                    </div>
                  )
                },
                {
                  key: "release",
                  header: "Release",
                  render: (h) =>
                    h.state === "active" ? (
                      <button
                        type="button"
                        className="rq-btn"
                        onClick={() => {
                          void (async () => {
                            const res = await api.releaseRetentionHold(
                              scope.tenantId,
                              scope.projectId,
                              h.hold_id,
                              {
                                schema_version: 1,
                                expected_version: h.version,
                                reason_code: "retention_hold_review_released"
                              },
                              generateIdempotencyKey("hold-release")
                            );
                            if (!res.ok) {
                              setFeedback({ kind: "failed", error: res });
                              return;
                            }
                            holdsQuery.reload();
                          })();
                        }}
                      >
                        Release Hold
                      </button>
                    ) : null
                }
              ]}
            />
          )}
        </ResourceStatePanel>
      </section>

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
