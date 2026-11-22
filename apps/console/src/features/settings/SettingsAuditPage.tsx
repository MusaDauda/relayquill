import { type JSX, useState } from "react";
import {
  type BreakGlassCreateResponseDto,
  type BreakGlassSessionSummaryDto,
  type CustomerAuditEventDto,
  type GdprErasureRequestDto
} from "../../api/dtos.js";
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

export function SettingsAuditPage(): JSX.Element {
  const { api, session } = useConsoleRuntime();

  const auditQuery = useScopedQuery({
    resource: "commercial.settings_audit",
    enabled: session !== null,
    fetcher: (signal) => api.getSettingsAudit({}, signal)
  });

  // Platform operator break-glass issuance form state (only shown to platform_admin)
  const isPlatformAdmin = session?.platform_roles.includes("platform_admin") ?? false;
  const [targetTenantId, setTargetTenantId] = useState("");
  const [bgReason, setBgReason] = useState("");
  const [bgIssued, setBgIssued] = useState<BreakGlassCreateResponseDto | null>(null);
  const [bgFeedback, setBgFeedback] = useState<MutationFeedbackState>({ kind: "idle" });

  // Never-paywalled GDPR erasure state
  const [confirmPhrase, setConfirmPhrase] = useState("");
  const [erasurePassword, setErasurePassword] = useState("");
  const [erasureTotp, setErasureTotp] = useState("");
  const [erasureRecord, setErasureRecord] = useState<GdprErasureRequestDto | null>(null);
  const [erasureFeedback, setErasureFeedback] = useState<MutationFeedbackState>({ kind: "idle" });

  const handleIssueBreakGlass = async (): Promise<void> => {
    setBgFeedback({ kind: "submitting", label: "Issuing 15-minute read-only break-glass session..." });
    const res = await api.createBreakGlassSession(
      {
        target_tenant_id: targetTenantId.trim(),
        reason: bgReason.trim(),
        ttl_minutes: 15,
        mfa_verified: true
      },
      generateIdempotencyKey("break-glass-create")
    );
    if (!res.ok) {
      setBgFeedback({ kind: "failed", error: res });
      return;
    }
    setBgIssued(res.data);
    setBgFeedback({
      kind: "succeeded",
      title: "Break-Glass Session Issued",
      detail: `Read-only session ${res.data.break_glass_id} expires at ${res.data.expires_at}. Customer notice queued.`
    });
    auditQuery.reload();
  };

  const handleRevokeBreakGlass = async (breakGlassId: string): Promise<void> => {
    setBgFeedback({ kind: "submitting", label: "Revoking support break-glass session..." });
    const res = await api.revokeBreakGlassSession(
      breakGlassId,
      generateIdempotencyKey("break-glass-revoke")
    );
    if (!res.ok) {
      setBgFeedback({ kind: "failed", error: res });
      return;
    }
    setBgFeedback({
      kind: "succeeded",
      title: "Session Revoked",
      detail: `Break-glass session ${res.data.break_glass_id} terminated immediately.`
    });
    auditQuery.reload();
  };

  const handleRequestErasure = async (): Promise<void> => {
    setErasureFeedback({
      kind: "submitting",
      label: "Submitting GDPR organization erasure and generating proof receipt..."
    });
    const res = await api.requestGdprErasure(
      {
        confirm_phrase: "DELETE ORGANIZATION",
        ...(erasurePassword.length > 0 ? { password: erasurePassword } : {}),
        ...(erasureTotp.trim().length > 0 ? { totp_code: erasureTotp.trim() } : {})
      },
      generateIdempotencyKey("gdpr-erasure")
    );
    if (!res.ok) {
      setErasureFeedback({ kind: "failed", error: res });
      return;
    }
    setErasureRecord(res.data);
    setErasurePassword("");
    setErasureTotp("");
    setErasureFeedback({
      kind: "succeeded",
      title: "GDPR Erasure Queued",
      detail: `Request ${res.data.erasure_request_id} in state ${res.data.state}. Cryptographic receipt SHA-256 recorded.`
    });
  };

  const handleRefreshErasure = async (): Promise<void> => {
    if (erasureRecord === null) {
      return;
    }
    const res = await api.getGdprErasureStatus(erasureRecord.erasure_request_id);
    if (res.ok) {
      setErasureRecord(res.data);
    }
  };

  return (
    <div className="rq-stack">
      <header className="rq-page-header">
        <div>
          <h1 className="rq-page-title">Organization Audit &amp; Privacy Controls</h1>
          <p className="rq-page-lead">
            Inspect tenant audit history, read-only 15-minute support break-glass access logs, and
            self-serve GDPR erasure. Never paywalled on any plan.
          </p>
        </div>
        <button type="button" className="rq-btn" onClick={auditQuery.reload}>
          <ConsoleIcon name="refresh" />
          <span>Refresh</span>
        </button>
      </header>

      <ResourceStatePanel
        view={auditQuery.view}
        resourceLabel="Tenant audit and break-glass logs"
        onRetry={auditQuery.reload}
      >
        {(data) => (
          <div className="rq-stack">
            <section className="rq-card" aria-label="Customer audit events">
              <div className="rq-card-header">
                <h2 className="rq-section-title">Tenant Audit Events</h2>
                <StatusBadge status="verified_supported" label={`${data.audit_events.length} events`} />
              </div>
              <DataTable<CustomerAuditEventDto>
                caption="Organization audit log"
                rows={data.audit_events}
                rowKey={(row) => row.audit_id}
                columns={[
                  {
                    key: "occurred_at",
                    header: "Timestamp",
                    render: (row) => <UtcTimestamp value={row.occurred_at} showLocal={false} />
                  },
                  {
                    key: "action",
                    header: "Action",
                    render: (row) => <span className="mono">{row.action}</span>
                  },
                  {
                    key: "actor",
                    header: "Actor",
                    render: (row) => (
                      <span className="mono">
                        {row.actor_kind}:{row.actor_reference ?? "system"}
                      </span>
                    )
                  },
                  {
                    key: "target",
                    header: "Target",
                    render: (row) => (
                      <span className="mono">
                        {row.target_kind}:{row.target_id}
                      </span>
                    )
                  }
                ]}
              />
            </section>

            <section className="rq-card" aria-label="Support break-glass sessions">
              <div className="rq-card-header">
                <h2 className="rq-section-title">15-Minute Support Break-Glass History</h2>
                <StatusBadge status="verified_supported" label="Read-Only Enforced" />
              </div>
              <DataTable<BreakGlassSessionSummaryDto>
                caption="Support break-glass sessions"
                rows={data.break_glass_sessions}
                rowKey={(row) => row.break_glass_id}
                emptyMessage="No support break-glass access has occurred for this tenant."
                columns={[
                  {
                    key: "started_at",
                    header: "Started",
                    render: (row) => <UtcTimestamp value={row.started_at} showLocal={false} />
                  },
                  {
                    key: "reason",
                    header: "Reason",
                    render: (row) => <span>{row.reason}</span>
                  },
                  {
                    key: "operator",
                    header: "Operator",
                    render: (row) => <span className="mono">{row.operator_id}</span>
                  },
                  {
                    key: "status",
                    header: "Status",
                    render: (row) => (
                      <div className="rq-row">
                        <StatusBadge
                          status={row.revoked_at !== null ? "revoked" : "active"}
                          label={row.revoked_at !== null ? "Revoked" : `Expires ${row.expires_at}`}
                        />
                        {isPlatformAdmin && row.revoked_at === null ? (
                          <button
                            type="button"
                            className="rq-btn rq-btn-danger"
                            onClick={() => {
                              void handleRevokeBreakGlass(row.break_glass_id);
                            }}
                          >
                            Revoke
                          </button>
                        ) : null}
                      </div>
                    )
                  }
                ]}
              />
            </section>
          </div>
        )}
      </ResourceStatePanel>

      {isPlatformAdmin ? (
        <section className="rq-card" aria-label="Platform Admin Break-Glass Issuance">
          <h2 className="rq-section-title">Platform Support Break-Glass (15m Read-Only)</h2>
          <div className="rq-grid-2">
            <FormField label="Target Tenant UUID" required>
              {({ inputId, describedBy }) => (
                <input
                  id={inputId}
                  aria-describedby={describedBy}
                  type="text"
                  className="rq-input mono"
                  value={targetTenantId}
                  onChange={(e) => {
                    setTargetTenantId(e.target.value);
                  }}
                />
              )}
            </FormField>
            <FormField label="Incident / Ticket Reason" required>
              {({ inputId, describedBy }) => (
                <input
                  id={inputId}
                  aria-describedby={describedBy}
                  type="text"
                  className="rq-input"
                  value={bgReason}
                  onChange={(e) => {
                    setBgReason(e.target.value);
                  }}
                />
              )}
            </FormField>
          </div>
          <div className="rq-row">
            <button
              type="button"
              className="rq-btn rq-btn-primary"
              disabled={targetTenantId.trim().length === 0 || bgReason.trim().length < 5}
              onClick={() => {
                void handleIssueBreakGlass();
              }}
            >
              Issue 15m Read-Only Break-Glass Token
            </button>
          </div>
          {bgIssued !== null ? (
            <div className="rq-card-inset">
              <CopyableId label="One-Time Break-Glass Token" value={bgIssued.token_once} />
            </div>
          ) : null}
          <MutationFeedback
            state={bgFeedback}
            resourceLabel="Support break-glass"
            onDismiss={() => {
              setBgFeedback({ kind: "idle" });
            }}
          />
        </section>
      ) : null}

      <section className="rq-card" aria-label="Self-Serve GDPR Organization Erasure">
        <div className="rq-card-header">
          <h2 className="rq-section-title">GDPR Organization Erasure (Never Paywalled)</h2>
          <StatusBadge status="unavailable" label="Irreversible PII Purge" />
        </div>
        <p className="rq-meta-text">
          Redacts user credentials, billing emails, and stored event payloads while preserving
          anonymized tax invoices for 7 years and producing a verifiable SHA-256 receipt.
        </p>

        <div className="rq-grid-3">
          <FormField label="Type Confirmation Phrase" helpText='Must match "DELETE ORGANIZATION"' required>
            {({ inputId, describedBy }) => (
              <input
                id={inputId}
                aria-describedby={describedBy}
                type="text"
                className="rq-input mono"
                placeholder="DELETE ORGANIZATION"
                value={confirmPhrase}
                onChange={(e) => {
                  setConfirmPhrase(e.target.value);
                }}
              />
            )}
          </FormField>

          <FormField label="Owner Password (or use TOTP below)">
            {({ inputId, describedBy }) => (
              <input
                id={inputId}
                aria-describedby={describedBy}
                type="password"
                className="rq-input"
                value={erasurePassword}
                onChange={(e) => {
                  setErasurePassword(e.target.value);
                }}
              />
            )}
          </FormField>

          <FormField label="TOTP MFA Code (Optional if Password Given)">
            {({ inputId, describedBy }) => (
              <input
                id={inputId}
                aria-describedby={describedBy}
                type="text"
                className="rq-input mono"
                value={erasureTotp}
                onChange={(e) => {
                  setErasureTotp(e.target.value);
                }}
              />
            )}
          </FormField>
        </div>

        <div className="rq-row">
          <button
            type="button"
            className="rq-btn rq-btn-danger"
            disabled={
              confirmPhrase !== "DELETE ORGANIZATION" ||
              (erasurePassword.length === 0 && erasureTotp.trim().length === 0)
            }
            onClick={() => {
              void handleRequestErasure();
            }}
          >
            Request GDPR Erasure
          </button>
          {erasureRecord !== null ? (
            <button
              type="button"
              className="rq-btn"
              onClick={() => {
                void handleRefreshErasure();
              }}
            >
              Check Erasure State
            </button>
          ) : null}
        </div>

        <MutationFeedback
          state={erasureFeedback}
          resourceLabel="GDPR erasure"
          onDismiss={() => {
            setErasureFeedback({ kind: "idle" });
          }}
        />

        {erasureRecord !== null ? (
          <div className="rq-card-inset">
            <div className="rq-row-between">
              <CopyableId label="Erasure Request ID" value={erasureRecord.erasure_request_id} />
              <StatusBadge status="active" label={erasureRecord.state} />
            </div>
            {erasureRecord.receipt_sha256 !== null ? (
              <CopyableId label="Proof Receipt SHA-256" value={erasureRecord.receipt_sha256} />
            ) : null}
          </div>
        ) : null}
      </section>
    </div>
  );
}
