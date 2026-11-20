import { type JSX, useState } from "react";
import { type AuditEventDto } from "../../api/dtos.js";
import { useActiveScope } from "../../app/scope.js";
import { useConsoleRuntime } from "../../app/session.js";
import { useScopedQuery } from "../../app/use-scoped-query.js";
import { CopyableId } from "../../components/CopyableId.js";
import { DataTable } from "../../components/DataTable.js";
import { FormField } from "../../components/FormField.js";
import { ConsoleIcon } from "../../components/Icons.js";
import { LosslessJsonViewer } from "../../components/LosslessJsonViewer.js";
import { ResourceStatePanel } from "../../components/ResourceStatePanel.js";
import { StatusBadge } from "../../components/StatusBadge.js";
import { UtcTimestamp } from "../../components/UtcTimestamp.js";

export function AuditPage({
  mode
}: {
  readonly mode: "platform" | "project";
}): JSX.Element {
  const { api } = useConsoleRuntime();
  const scope = useActiveScope();

  const [actionFilter, setActionFilter] = useState("");
  const [targetKindFilter, setTargetKindFilter] = useState("");
  const [pageSize, setPageSize] = useState<25 | 100>(25);
  const [cursorStack, setCursorStack] = useState<readonly (string | null)[]>([null]);
  const [selectedEvent, setSelectedEvent] = useState<AuditEventDto | null>(null);

  const currentCursor = cursorStack[cursorStack.length - 1] ?? null;

  const auditQuery = useScopedQuery({
    resource: mode === "platform" ? "platform.audit" : "project.audit",
    filter: {
      action: actionFilter.trim(),
      targetKind: targetKindFilter.trim(),
      pageSize,
      cursor: currentCursor
    },
    isEmpty: (d) => d.items.length === 0,
    fetcher: (signal: AbortSignal) =>
      mode === "platform"
        ? api.listPlatformAudit(
            {
              limit: pageSize,
              cursor: currentCursor,
              ...(actionFilter.trim().length > 0 ? { action: actionFilter.trim() } : {})
            },
            signal
          )
        : api.listProjectAudit(
            scope.tenantId,
            scope.projectId,
            {
              limit: pageSize,
              cursor: currentCursor,
              ...(actionFilter.trim().length > 0 ? { action: actionFilter.trim() } : {}),
              ...(targetKindFilter.trim().length > 0
                ? { target_kind: targetKindFilter.trim() }
                : {})
            },
            signal
          )
  });

  return (
    <div className="rq-stack">
      <header className="rq-page-header">
        <div>
          <h1 className="rq-page-title">
            {mode === "platform" ? "Platform Audit Ledger" : "Project Audit & Governance Ledger"}
          </h1>
          <p className="rq-page-lead">
            Append-only cryptographic command receipts, actor principals, prior and resulting
            resource versions, and secret-free safe facts.
          </p>
        </div>
        <div className="rq-row">
          <StatusBadge status="verified_supported" label="Immutable Audit Trail" />
          <button type="button" className="rq-btn" onClick={auditQuery.reload}>
            <ConsoleIcon name="refresh" />
            <span>Refresh</span>
          </button>
        </div>
      </header>

      <section className="rq-card" aria-label="Audit filters">
        <div className="rq-grid-3">
          <FormField
            label="Filter by Action"
            helpText="Example: endpoints.activate, replay_proposals.review"
          >
            {({ inputId, describedBy }) => (
              <input
                id={inputId}
                aria-describedby={describedBy}
                type="text"
                className="rq-input mono"
                value={actionFilter}
                onChange={(e) => {
                  setActionFilter(e.target.value);
                  setCursorStack([null]);
                }}
              />
            )}
          </FormField>

          {mode === "project" ? (
            <FormField
              label="Filter by Target Kind"
              helpText="Example: endpoint, subscription, replay_proposal"
            >
              {({ inputId, describedBy }) => (
                <input
                  id={inputId}
                  aria-describedby={describedBy}
                  type="text"
                  className="rq-input mono"
                  value={targetKindFilter}
                  onChange={(e) => {
                    setTargetKindFilter(e.target.value);
                    setCursorStack([null]);
                  }}
                />
              )}
            </FormField>
          ) : null}
        </div>
      </section>

      <ResourceStatePanel
        view={auditQuery.view}
        resourceLabel="Audit ledger"
        emptyTitle="No matching audit records"
        onRetry={auditQuery.reload}
      >
        {(page) => (
          <section className="rq-card" aria-label="Audit events table">
            <DataTable<AuditEventDto>
              caption="Audit log entries"
              rows={page.items}
              rowKey={(a) => a.audit_id}
              pagination={{
                pageSize,
                pageIndex: cursorStack.length - 1,
                onPageSizeChange: (nextSize) => {
                  setPageSize(nextSize);
                  setCursorStack([null]);
                },
                hasPrev: cursorStack.length > 1,
                hasNext:
                  (page.page.has_more ?? page.page.next_cursor !== null) &&
                  page.page.next_cursor !== null,
                onPrev: () => {
                  setCursorStack((prev) => (prev.length > 1 ? prev.slice(0, -1) : prev));
                },
                onNext: () => {
                  if (page.page.next_cursor !== null) {
                    const nextCursor = page.page.next_cursor;
                    setCursorStack((prev) => [...prev, nextCursor]);
                  }
                }
              }}
              columns={[
                {
                  key: "recorded_at",
                  header: "Recorded At",
                  render: (a) => <UtcTimestamp value={a.recorded_at} />
                },
                {
                  key: "action",
                  header: "Action & Receipt",
                  render: (a) => (
                    <div className="rq-stack-sm">
                      <strong className="mono">{a.action}</strong>
                      <CopyableId label="Audit ID" value={a.audit_id} compact />
                      {a.command_receipt_id !== null ? (
                        <CopyableId label="Receipt" value={a.command_receipt_id} compact />
                      ) : null}
                    </div>
                  )
                },
                {
                  key: "actor",
                  header: "Actor",
                  render: (a) => (
                    <div className="rq-stack-sm">
                      <span className="mono">{a.actor_kind}</span>
                      {a.actor_reference !== null ? (
                        <CopyableId value={a.actor_reference} compact />
                      ) : null}
                      {a.operator_reference !== null ? (
                        <span className="mono">{a.operator_reference}</span>
                      ) : null}
                    </div>
                  )
                },
                {
                  key: "target",
                  header: "Target Resource & Version Transition",
                  render: (a) => (
                    <div className="rq-stack-sm">
                      <span className="mono">
                        {a.target_kind}: {a.target_id}
                      </span>
                      <span className="rq-meta-text mono">
                        v{a.prior_version ?? "none"} {"->"} v{a.resulting_version ?? "none"}
                      </span>
                    </div>
                  )
                },
                {
                  key: "inspect",
                  header: "Safe Facts",
                  render: (a) => (
                    <button
                      type="button"
                      className="rq-btn"
                      onClick={() => {
                        setSelectedEvent(a);
                      }}
                    >
                      Inspect Facts
                    </button>
                  )
                }
              ]}
            />
          </section>
        )}
      </ResourceStatePanel>

      {selectedEvent !== null ? (
        <section className="rq-card" aria-label="Selected audit event facts">
          <div className="rq-card-header">
            <h2 className="rq-section-title">
              Audit Entry Facts: <span className="mono">{selectedEvent.action}</span>
            </h2>
            <button
              type="button"
              className="rq-btn"
              onClick={() => {
                setSelectedEvent(null);
              }}
            >
              Close Inspector
            </button>
          </div>
          {selectedEvent.candidate_sha256 !== null ? (
            <CopyableId
              label="Candidate SHA-256"
              value={selectedEvent.candidate_sha256}
            />
          ) : null}
          <LosslessJsonViewer
            title="Audit Safe Facts (Redacted of Raw Secrets)"
            jsonText={JSON.stringify(selectedEvent.safe_facts, null, 2)}
          />
        </section>
      ) : null}
    </div>
  );
}
