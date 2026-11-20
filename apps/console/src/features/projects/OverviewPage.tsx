import { type JSX, useState } from "react";
import { hashCanonicalJson, isCapabilityAvailable } from "@relayquill/contracts";
import { type DeliveryPopulation } from "@relayquill/domain";
import { type OverviewStageCardDto, type ProjectOverviewDto } from "../../api/dtos.js";
import { buildProjectPath, useConsoleRouter } from "../../app/router.js";
import { useActiveScope } from "../../app/scope.js";
import { useConsoleRuntime } from "../../app/session.js";
import { useScopedQuery } from "../../app/use-scoped-query.js";
import { CopyableId } from "../../components/CopyableId.js";
import { FormField } from "../../components/FormField.js";
import { ConsoleIcon } from "../../components/Icons.js";
import {
  MutationFeedback,
  type MutationFeedbackState
} from "../../components/MutationFeedback.js";
import { ResourceStatePanel } from "../../components/ResourceStatePanel.js";
import { StatusBadge } from "../../components/StatusBadge.js";
import { UtcTimestamp } from "../../components/UtcTimestamp.js";
import { formatDurationSeconds } from "../../utils/format.js";
import { generateIdempotencyKey } from "../../utils/idempotency.js";
import { StepUpModal, type StepUpTargetDescriptor } from "../access/StepUpModal.js";

const CANONICAL_STAGE_METADATA: readonly {
  readonly stage: OverviewStageCardDto["stage"];
  readonly title: string;
  readonly unitLabel: string;
  readonly explanation: string;
}[] = [
  {
    stage: "accepted_events",
    title: "1. Accepted Events",
    unitLabel: "events",
    explanation: "Committed to the PostgreSQL admission ledger with durable outbox obligations."
  },
  {
    stage: "broker_stored_notifications",
    title: "2. Broker-Stored Notifications",
    unitLabel: "notifications",
    explanation: "Outbox rows observed and acknowledged by the JetStream notification stream."
  },
  {
    stage: "completed_event_fanout",
    title: "3. Completed Event Fanout",
    unitLabel: "events",
    explanation: "Events whose subscription evaluations and delivery generations are materialized."
  },
  {
    stage: "http_acknowledged_delivery_generations",
    title: "4. HTTP-Acknowledged Delivery Generations",
    unitLabel: "delivery_generations",
    explanation: "Outbound webhook delivery generations that received a 2xx HTTP response."
  },
  {
    stage: "verified_receiver_receipt_observations",
    title: "5. Verified Receiver Receipts",
    unitLabel: "receipt_observations",
    explanation: "Cryptographically verified end-to-end receiver receipt observations."
  }
];

function StageSummaryCard({
  meta,
  card,
  windowLabel,
  population
}: {
  readonly meta: (typeof CANONICAL_STAGE_METADATA)[number];
  readonly card: OverviewStageCardDto | undefined;
  readonly windowLabel: string;
  readonly population: string;
}): JSX.Element {
  const unavailable = card === undefined || card.availability === "unavailable" || card.count === null;

  return (
    <article className="rq-card" aria-label={meta.title} data-stage={meta.stage}>
      <div className="rq-row-between">
        <strong className="rq-card-title">{meta.title}</strong>
        <StatusBadge
          status={unavailable ? "unavailable" : card.availability}
          label={unavailable ? "Unavailable" : card.availability === "authorized_empty" ? "Zero Observed" : "Current"}
        />
      </div>

      {unavailable ? (
        <p className="rq-metric-value">Unavailable</p>
      ) : (
        <p className="rq-metric-value">{card.count}</p>
      )}

      <div className="rq-row">
        <span className="kbd-chip">{card?.unit ?? meta.unitLabel}</span>
        <span className="kbd-chip">pop: {card?.population ?? population}</span>
        <span className="kbd-chip">win: {card?.window_label ?? windowLabel}</span>
      </div>

      <p className="rq-meta-text">{card?.note ?? meta.explanation}</p>
    </article>
  );
}

export function OverviewPage(): JSX.Element {
  const { navigate } = useConsoleRouter();
  const { api } = useConsoleRuntime();
  const scope = useActiveScope();

  const [windowFilter, setWindowFilter] = useState("1h");
  const [populationFilter, setPopulationFilter] = useState<DeliveryPopulation>("original");
  const [feedback, setFeedback] = useState<MutationFeedbackState>({ kind: "idle" });
  const [stepUpTarget, setStepUpTarget] = useState<{
    readonly descriptor: StepUpTargetDescriptor;
    readonly action: "pause-admission" | "resume-admission" | "retire";
    readonly commandPayload: Record<string, unknown>;
  } | null>(null);

  const overviewQuery = useScopedQuery({
    resource: "project.overview",
    filter: { window: windowFilter, population: populationFilter },
    extractVersion: (d) => d.project_version,
    fetcher: (signal: AbortSignal) =>
      api.getProjectOverview(
        scope.tenantId,
        scope.projectId,
        { window: windowFilter, population: populationFilter },
        signal
      )
  });

  const openProjectLifecycleStepUp = (
    overview: ProjectOverviewDto,
    action: "pause-admission" | "resume-admission" | "retire"
  ): void => {
    const capabilityAction =
      action === "pause-admission"
        ? "project.pause_admission"
        : action === "resume-admission"
          ? "project.resume_admission"
          : "project.retire";
    const commandPayload = {
      schema_version: 1,
      project_id: overview.project_id,
      expected_version: overview.project_version,
      action,
      reason_code: `operator_${action.replace("-", "_")}`
    };
    const canonical = hashCanonicalJson(commandPayload);

    setStepUpTarget({
      action,
      commandPayload,
      descriptor: {
        action: capabilityAction,
        actionLabel: `${action.replace("-", " ").toUpperCase()} Project ${overview.project_name}`,
        scopeKind: "project",
        tenantId: scope.tenantId,
        projectId: scope.projectId,
        targetResourceId: overview.project_id,
        targetVersion: overview.project_version,
        canonicalCommandSha256: canonical.sha256,
        summary: `Executes ${action} on project ${overview.project_name} (${overview.project_id}) at version ${overview.project_version}.`
      }
    });
  };

  return (
    <div className="rq-stack">
      <header className="rq-page-header">
        <div>
          <h1 className="rq-page-title">Project Operational Overview</h1>
          <p className="rq-page-lead">
            Stage-separated pipeline telemetry across admission, broker publication, ordered fanout,
            outbound HTTP delivery generations, and verified receiver receipts.
          </p>
        </div>
        <div className="rq-row">
          <button type="button" className="rq-btn" onClick={overviewQuery.reload}>
            <ConsoleIcon name="refresh" />
            <span>Refresh Telemetry</span>
          </button>
        </div>
      </header>

      <section className="rq-card" aria-label="Telemetry window and population controls">
        <div className="rq-grid-2">
          <FormField
            label="Observation Time Window"
            helpText="Applies explicit server observation window across all five pipeline stage summaries."
          >
            {({ inputId, describedBy }) => (
              <select
                id={inputId}
                aria-describedby={describedBy}
                className="rq-select"
                value={windowFilter}
                onChange={(e) => {
                  setWindowFilter(e.target.value);
                }}
              >
                <option value="15m">Last 15 Minutes (15m)</option>
                <option value="1h">Last 1 Hour (1h)</option>
                <option value="24h">Last 24 Hours (24h)</option>
                <option value="7d">Last 7 Days (7d)</option>
              </select>
            )}
          </FormField>

          <FormField
            label="Delivery Generation Population"
            helpText="Separates original fanout generations from reviewed replay generations."
          >
            {({ inputId, describedBy }) => (
              <select
                id={inputId}
                aria-describedby={describedBy}
                className="rq-select"
                value={populationFilter}
                onChange={(e) => {
                  setPopulationFilter(e.target.value as DeliveryPopulation);
                }}
              >
                <option value="original">Original Generations Only (original)</option>
                <option value="replay">Replay Generations Only (replay)</option>
                <option value="all">Combined Original + Replay (all)</option>
              </select>
            )}
          </FormField>
        </div>
      </section>

      <MutationFeedback
        state={feedback}
        resourceLabel="Project admission state"
        onRetry={overviewQuery.reload}
        onDismiss={() => {
          setFeedback({ kind: "idle" });
        }}
      />

      <ResourceStatePanel
        view={overviewQuery.view}
        resourceLabel="Project overview"
        onRetry={overviewQuery.reload}
      >
        {(overview) => {
          const canPause = isCapabilityAvailable(
            overview.capabilities,
            "projects.pause_admission"
          );
          const canResume = isCapabilityAvailable(
            overview.capabilities,
            "projects.resume_admission"
          );
          const canRetire = isCapabilityAvailable(overview.capabilities, "projects.retire");

          return (
            <div className="rq-stack">
              <section className="rq-card" aria-label="Project metadata and lifecycle">
                <div className="rq-card-header">
                  <div className="rq-row">
                    <h2 className="rq-section-title">{overview.project_name}</h2>
                    <StatusBadge status={overview.project_state} />
                    <span className="kbd-chip">Topology v{overview.topology_version}</span>
                    <span className="kbd-chip">Project v{overview.project_version}</span>
                  </div>
                  <div className="rq-row">
                    <span className="rq-meta-text">Observed:</span>
                    <UtcTimestamp value={overview.observed_at} showLocal={false} />
                  </div>
                </div>

                <div className="rq-row-between">
                  <CopyableId label="Project ID" value={overview.project_id} />
                  <div className="rq-row">
                    <button
                      type="button"
                      className="rq-btn rq-btn-primary"
                      onClick={() => {
                        navigate(
                          buildProjectPath(scope.tenantId, scope.projectId, "events")
                        );
                      }}
                    >
                      Publish or Inspect Events
                    </button>
                    {overview.project_state === "active" ? (
                      <button
                        type="button"
                        className="rq-btn"
                        disabled={!canPause && overview.capabilities.length > 0}
                        onClick={() => {
                          openProjectLifecycleStepUp(overview, "pause-admission");
                        }}
                      >
                        Pause Admission (Step-Up)
                      </button>
                    ) : null}
                    {overview.project_state === "admission_paused" ? (
                      <button
                        type="button"
                        className="rq-btn"
                        disabled={!canResume && overview.capabilities.length > 0}
                        onClick={() => {
                          openProjectLifecycleStepUp(overview, "resume-admission");
                        }}
                      >
                        Resume Admission (Step-Up)
                      </button>
                    ) : null}
                    {overview.project_state !== "retired" ? (
                      <button
                        type="button"
                        className="rq-btn rq-btn-danger"
                        disabled={!canRetire && overview.capabilities.length > 0}
                        onClick={() => {
                          openProjectLifecycleStepUp(overview, "retire");
                        }}
                      >
                        Retire Project
                      </button>
                    ) : null}
                  </div>
                </div>
              </section>

              <section className="rq-stack-sm" aria-label="Five distinct pipeline stage summaries">
                <div className="rq-row-between">
                  <h2 className="rq-section-title">
                    Pipeline Stage Summaries (Never Collapsed Into One Metric)
                  </h2>
                  <span className="rq-meta-text">
                    Window: <strong className="mono">{overview.window_label}</strong> | Population:{" "}
                    <strong className="mono">{populationFilter}</strong>
                  </span>
                </div>
                <div className="rq-grid-stages">
                  {CANONICAL_STAGE_METADATA.map((meta) => {
                    const card = overview.stages.find((s) => s.stage === meta.stage);
                    return (
                      <StageSummaryCard
                        key={meta.stage}
                        meta={meta}
                        card={card}
                        windowLabel={overview.window_label}
                        population={populationFilter}
                      />
                    );
                  })}
                </div>
              </section>

              <div className="rq-grid-3">
                <section className="rq-card" aria-label="Outbox and ordered fanout pressure">
                  <div className="rq-card-header">
                    <h2 className="rq-card-title">Outbox & Fanout Pressure</h2>
                    <StatusBadge
                      status={
                        overview.outbox_pressure.blocked_fanout_predecessor_sequence !== null ||
                        Number(overview.outbox_pressure.blocked_outbox_count) > 0
                          ? "blocked"
                          : "current"
                      }
                    />
                  </div>
                  <dl className="rq-kv-grid">
                    <dt>Oldest Pending Outbox Age</dt>
                    <dd className="mono">
                      {overview.outbox_pressure.oldest_pending_age_seconds === null
                        ? "None pending"
                        : formatDurationSeconds(
                            overview.outbox_pressure.oldest_pending_age_seconds
                          )}
                    </dd>
                    <dt>Blocked Outbox Obligations</dt>
                    <dd className="mono">{overview.outbox_pressure.blocked_outbox_count}</dd>
                    <dt>Blocked Fanout Predecessor</dt>
                    <dd className="mono">
                      {overview.outbox_pressure.blocked_fanout_predecessor_sequence !== null
                        ? `seq #${overview.outbox_pressure.blocked_fanout_predecessor_sequence}`
                        : "Unblocked"}
                    </dd>
                    <dt>Fanout Block Reason</dt>
                    <dd className="mono">
                      {overview.outbox_pressure.blocked_fanout_reason_code ?? "none"}
                    </dd>
                  </dl>
                  <div>
                    <button
                      type="button"
                      className="rq-btn"
                      onClick={() => {
                        navigate(
                          buildProjectPath(scope.tenantId, scope.projectId, "events")
                        );
                      }}
                    >
                      Inspect Event Fanout Ledger
                    </button>
                  </div>
                </section>

                <section className="rq-card" aria-label="Delivery and circuit pressure">
                  <div className="rq-card-header">
                    <h2 className="rq-card-title">Delivery & Circuit Pressure</h2>
                    <StatusBadge
                      status={
                        overview.delivery_pressure.open_circuits_count > 0 ||
                        Number(overview.delivery_pressure.unknown_outcome_count) > 0
                          ? "unknown"
                          : "current"
                      }
                    />
                  </div>
                  <dl className="rq-kv-grid">
                    <dt>Ready Deliveries</dt>
                    <dd className="mono">{overview.delivery_pressure.ready_count}</dd>
                    <dt>Retry Wait Queue</dt>
                    <dd className="mono">{overview.delivery_pressure.retry_wait_count}</dd>
                    <dt>Active Sending</dt>
                    <dd className="mono">{overview.delivery_pressure.sending_count}</dd>
                    <dt>Unknown Attempt Outcomes</dt>
                    <dd className="mono">{overview.delivery_pressure.unknown_outcome_count}</dd>
                    <dt>Open / Half-Open Circuits</dt>
                    <dd className="mono">
                      {overview.delivery_pressure.open_circuits_count} open /{" "}
                      {overview.delivery_pressure.half_open_circuits_count} half-open
                    </dd>
                    <dt>Quarantined Endpoints</dt>
                    <dd className="mono">
                      {overview.delivery_pressure.quarantined_endpoints_count}
                    </dd>
                  </dl>
                  <div className="rq-row">
                    <button
                      type="button"
                      className="rq-btn"
                      onClick={() => {
                        navigate(
                          buildProjectPath(scope.tenantId, scope.projectId, "deliveries")
                        );
                      }}
                    >
                      Deliveries
                    </button>
                    <button
                      type="button"
                      className="rq-btn"
                      onClick={() => {
                        navigate(
                          buildProjectPath(scope.tenantId, scope.projectId, "ordering")
                        );
                      }}
                    >
                      Ordering & Circuits
                    </button>
                  </div>
                </section>

                <section className="rq-card" aria-label="Active and held rate and concurrency budgets">
                  <div className="rq-card-header">
                    <h2 className="rq-card-title">Rate & Send Slot Budgets</h2>
                    <StatusBadge
                      status={
                        overview.budgets.draining_policy_count > 0 ? "draining" : "active"
                      }
                    />
                  </div>
                  <dl className="rq-kv-grid">
                    <dt>Send Concurrency Slots</dt>
                    <dd className="mono">
                      {overview.budgets.active_send_slots} active /{" "}
                      {overview.budgets.approved_send_slots} approved
                    </dd>
                    <dt>Held Rate Reservations</dt>
                    <dd className="mono">{overview.budgets.held_rate_reservations}</dd>
                    <dt>Approved Rate Budget</dt>
                    <dd className="mono">
                      {overview.budgets.rate_requests_per_second} req/s (burst{" "}
                      {overview.budgets.rate_burst})
                    </dd>
                    <dt>Draining Policy Changes</dt>
                    <dd className="mono">{overview.budgets.draining_policy_count}</dd>
                  </dl>
                  <div>
                    <button
                      type="button"
                      className="rq-btn"
                      onClick={() => {
                        navigate(
                          buildProjectPath(scope.tenantId, scope.projectId, "limits")
                        );
                      }}
                    >
                      Manage Budgets & Access
                    </button>
                  </div>
                </section>
              </div>
            </div>
          );
        }}
      </ResourceStatePanel>

      <StepUpModal
        target={stepUpTarget?.descriptor ?? null}
        onCancel={() => {
          setStepUpTarget(null);
        }}
        onVerified={async (proof) => {
          const current = stepUpTarget;
          setStepUpTarget(null);
          if (current === null) {
            return;
          }
          setFeedback({
            kind: "submitting",
            label: `Executing project ${current.action}...`
          });
          const body = {
            ...current.commandPayload,
            operation_proof_id: proof.operationProofId,
            canonical_command_sha256: proof.canonicalCommandSha256
          };
          const res = await api.mutateProjectAdmission(
            scope.tenantId,
            scope.projectId,
            current.action,
            body,
            generateIdempotencyKey(`project-${current.action}`)
          );
          if (!res.ok) {
            setFeedback({
              kind: "failed",
              error: res,
              preservedDraft: body
            });
            return;
          }
          setFeedback({
            kind: "succeeded",
            title: `Project ${current.action} accepted`,
            detail: `Project transition ${current.action} committed.`,
            receiptId: res.data.receipt?.id
          });
          overviewQuery.reload();
        }}
      />
    </div>
  );
}
