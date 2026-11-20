import { type JSX, useEffect, useState } from "react";
import {
  type AttemptSummaryDto,
  type DeliveryRequestContentDto,
  type DeliverySummaryDto,
  type ReceiverReceiptObservationDto,
  isCapabilityAvailable
} from "@relayquill/contracts";
import {
  DELIVERY_OUTCOME_CLASSES,
  DELIVERY_POPULATIONS,
  DELIVERY_STATES,
  type DeliveryPopulation
} from "@relayquill/domain";
import { type OverviewStageCardDto } from "../../api/dtos.js";
import { buildProjectPath, useConsoleRouter } from "../../app/router.js";
import { useActiveScope } from "../../app/scope.js";
import { useConsoleRuntime } from "../../app/session.js";
import { useScopedQuery } from "../../app/use-scoped-query.js";
import { CopyableId } from "../../components/CopyableId.js";
import { DataTable } from "../../components/DataTable.js";
import { FormField } from "../../components/FormField.js";
import { ConsoleIcon } from "../../components/Icons.js";
import { LiveWatchPanel } from "../../components/LiveWatchPanel.js";
import { LosslessJsonViewer } from "../../components/LosslessJsonViewer.js";
import {
  MutationFeedback,
  type MutationFeedbackState
} from "../../components/MutationFeedback.js";
import { ResourceStatePanel } from "../../components/ResourceStatePanel.js";
import { StatusBadge } from "../../components/StatusBadge.js";
import { UtcTimestamp } from "../../components/UtcTimestamp.js";
import { formatByteSize } from "../../utils/format.js";

const PIPELINE_STAGE_SUMMARIES: readonly {
  readonly stage: OverviewStageCardDto["stage"];
  readonly title: string;
  readonly unit: string;
  readonly description: string;
}[] = [
  {
    stage: "accepted_events",
    title: "1. Event Admission",
    unit: "events",
    description: "Accepted events persisted with immutable business keys and fingerprints."
  },
  {
    stage: "broker_stored_notifications",
    title: "2. Broker Publication",
    unit: "notifications",
    description: "Outbox publication notices confirmed in durable broker stream storage."
  },
  {
    stage: "completed_event_fanout",
    title: "3. Fanout Evaluation",
    unit: "events",
    description: "Events whose subscriptions completed matching and delivery generation."
  },
  {
    stage: "http_acknowledged_delivery_generations",
    title: "4. HTTP Acknowledged Delivery",
    unit: "delivery_generations",
    description: "Delivery generations acknowledged with HTTP 2xx status by endpoints."
  },
  {
    stage: "verified_receiver_receipt_observations",
    title: "5. Receiver Receipt Verified",
    unit: "receipt_observations",
    description: "Cryptographically verified end-to-end consumer receipt observations."
  }
];

export function DeliveriesPage({
  selectedDeliveryId
}: {
  readonly selectedDeliveryId?: string | undefined;
}): JSX.Element {
  const { navigate } = useConsoleRouter();
  const { api } = useConsoleRuntime();
  const scope = useActiveScope();

  const [populationFilter, setPopulationFilter] = useState<DeliveryPopulation>("original");
  const [windowFilter, setWindowFilter] = useState("24h");
  const [eventIdFilter, setEventIdFilter] = useState("");
  const [endpointIdFilter, setEndpointIdFilter] = useState("");
  const [stateFilter, setStateFilter] = useState("");
  const [outcomeFilter, setOutcomeFilter] = useState("");
  const [pageSize, setPageSize] = useState<25 | 100>(25);
  const [cursorStack, setCursorStack] = useState<readonly (string | null)[]>([null]);

  const [wireContent, setWireContent] = useState<DeliveryRequestContentDto | null>(null);
  const [wireFeedback, setWireFeedback] = useState<MutationFeedbackState>({ kind: "idle" });

  const currentCursor = cursorStack[cursorStack.length - 1] ?? null;

  const overviewQuery = useScopedQuery({
    resource: "project.delivery_stage_overview",
    filter: { population: populationFilter, window: windowFilter },
    fetcher: (signal: AbortSignal) =>
      api.getProjectOverview(
        scope.tenantId,
        scope.projectId,
        { population: populationFilter, window: windowFilter },
        signal
      )
  });

  const aggregateSummaryQuery = useScopedQuery({
    resource: "project.delivery_aggregate_summary",
    filter: { population: populationFilter, window: windowFilter },
    fetcher: (signal: AbortSignal) =>
      api.getDeliverySummary(
        scope.tenantId,
        scope.projectId,
        { population: populationFilter, window: windowFilter },
        signal
      )
  });

  const deliveriesQuery = useScopedQuery({
    resource: "project.deliveries",
    filter: {
      populationFilter,
      eventIdFilter,
      endpointIdFilter,
      stateFilter,
      outcomeFilter,
      pageSize,
      cursor: currentCursor
    },
    isEmpty: (d) => d.items.length === 0,
    fetcher: (signal: AbortSignal) =>
      api.listDeliveries(
        scope.tenantId,
        scope.projectId,
        {
          population: populationFilter,
          ...(eventIdFilter.trim().length > 0 ? { event_id: eventIdFilter.trim() } : {}),
          ...(endpointIdFilter.trim().length > 0 ? { endpoint_id: endpointIdFilter.trim() } : {}),
          ...(stateFilter.trim().length > 0 ? { state: stateFilter.trim() } : {}),
          ...(outcomeFilter.trim().length > 0 ? { outcome_class: outcomeFilter.trim() } : {}),
          limit: pageSize,
          cursor: currentCursor
        },
        signal
      )
  });

  const deliveryDetailQuery = useScopedQuery({
    resource: "project.delivery_detail",
    enabled: selectedDeliveryId !== undefined,
    filter: { selectedDeliveryId },
    extractVersion: (d) => d.current_version,
    fetcher: (signal: AbortSignal) =>
      api.getDeliveryDetail(scope.tenantId, scope.projectId, selectedDeliveryId ?? "", signal)
  });

  const attemptsQuery = useScopedQuery({
    resource: "project.delivery_attempts",
    enabled: selectedDeliveryId !== undefined,
    filter: { selectedDeliveryId },
    isEmpty: (d) => d.items.length === 0,
    fetcher: (signal: AbortSignal) =>
      api.listDeliveryAttempts(
        scope.tenantId,
        scope.projectId,
        selectedDeliveryId ?? "",
        { limit: 50 },
        signal
      )
  });

  const receiptsQuery = useScopedQuery({
    resource: "project.delivery_receipts",
    enabled: selectedDeliveryId !== undefined,
    filter: { selectedDeliveryId },
    isEmpty: (d) => d.items.length === 0,
    fetcher: (signal: AbortSignal) =>
      api.listDeliveryReceiverReceipts(
        scope.tenantId,
        scope.projectId,
        selectedDeliveryId ?? "",
        signal
      )
  });

  const networkDecisionsQuery = useScopedQuery({
    resource: "project.delivery_network_decisions",
    enabled: selectedDeliveryId !== undefined,
    filter: { selectedDeliveryId },
    isEmpty: (d) => d.items.length === 0,
    fetcher: (signal: AbortSignal) =>
      api.listDeliveryNetworkDecisions(
        scope.tenantId,
        scope.projectId,
        selectedDeliveryId ?? "",
        signal
      )
  });

  const lateObservationsQuery = useScopedQuery({
    resource: "project.delivery_late_observations",
    enabled: selectedDeliveryId !== undefined,
    filter: { selectedDeliveryId },
    isEmpty: (d) => d.items.length === 0,
    fetcher: (signal: AbortSignal) =>
      api.listDeliveryLateObservations(
        scope.tenantId,
        scope.projectId,
        selectedDeliveryId ?? "",
        signal
      )
  });

  const historyQuery = useScopedQuery({
    resource: "project.delivery_history",
    enabled: selectedDeliveryId !== undefined,
    filter: { selectedDeliveryId },
    isEmpty: (d) => d.items.length === 0,
    fetcher: (signal: AbortSignal) =>
      api.listDeliveryHistory(
        scope.tenantId,
        scope.projectId,
        selectedDeliveryId ?? "",
        { limit: 50 },
        signal
      )
  });

  const traceQuery = useScopedQuery({
    resource: "project.delivery_traces",
    enabled: selectedDeliveryId !== undefined,
    filter: { selectedDeliveryId },
    isEmpty: (d) => d.items.length === 0,
    fetcher: (signal: AbortSignal) =>
      api.listDeliveryTraceReferences(
        scope.tenantId,
        scope.projectId,
        selectedDeliveryId ?? "",
        signal
      )
  });

  useEffect(() => {
    setWireContent(null);
    setWireFeedback({ kind: "idle" });
  }, [selectedDeliveryId]);

  const handleLoadWireRequestContent = async (deliveryId: string): Promise<void> => {
    setWireFeedback({
      kind: "submitting",
      label: "Requesting frozen outbound wire payload (requires deliveries.request.read grant)..."
    });
    const res = await api.getDeliveryRequestContent(scope.tenantId, scope.projectId, deliveryId);
    if (!res.ok) {
      setWireContent(null);
      setWireFeedback({ kind: "failed", error: res });
      return;
    }
    setWireContent(res.data);
    setWireFeedback({
      kind: "succeeded",
      title: "Authorized Wire Content Loaded",
      detail: `SHA-256 ${res.data.sha256} (${formatByteSize(res.data.byte_count)}, rep v${res.data.representation_version}).`
    });
  };

  return (
    <div className="rq-stack">
      <header className="rq-page-header">
        <div>
          <h1 className="rq-page-title">Deliveries & Evidence Boundaries</h1>
          <p className="rq-page-lead">
            Inspect delivery generations independently across all five evidence boundaries:
            admission, broker publication, fanout, HTTP acknowledgement, and verified receiver
            receipts with network peer/policy digests.
          </p>
        </div>
        <div className="rq-row">
          {selectedDeliveryId !== undefined ? (
            <button
              type="button"
              className="rq-btn"
              onClick={() => {
                navigate(buildProjectPath(scope.tenantId, scope.projectId, "deliveries"));
              }}
            >
              Back to Deliveries List
            </button>
          ) : null}
          <FormField label="Population">
            {({ inputId }) => (
              <select
                id={inputId}
                className="rq-select"
                value={populationFilter}
                onChange={(e) => {
                  setPopulationFilter(e.target.value as DeliveryPopulation);
                  setCursorStack([null]);
                }}
              >
                {DELIVERY_POPULATIONS.map((pop) => (
                  <option key={pop} value={pop}>
                    {pop}
                  </option>
                ))}
              </select>
            )}
          </FormField>
          <FormField label="Window">
            {({ inputId }) => (
              <select
                id={inputId}
                className="rq-select"
                value={windowFilter}
                onChange={(e) => {
                  setWindowFilter(e.target.value);
                }}
              >
                <option value="1h">1h</option>
                <option value="24h">24h</option>
                <option value="7d">7d</option>
              </select>
            )}
          </FormField>
        </div>
      </header>

      <ResourceStatePanel
        view={overviewQuery.view}
        resourceLabel="Pipeline stage counters"
        onRetry={overviewQuery.reload}
      >
        {(overview) => (
          <section className="rq-stack" aria-label="Five delivery pipeline stage summaries">
            <div className="rq-grid-stages">
              {PIPELINE_STAGE_SUMMARIES.map((meta) => {
                const card = overview.stages.find((s) => s.stage === meta.stage);
                const unavailable =
                  card === undefined || card.availability === "unavailable" || card.count === null;
                return (
                  <article key={meta.stage} className="rq-card" data-stage={meta.stage}>
                    <div className="rq-row-between">
                      <strong className="rq-card-title">{meta.title}</strong>
                      <StatusBadge
                        status={unavailable ? "unavailable" : card.availability}
                        label={
                          unavailable
                            ? "Unavailable"
                            : card.availability === "authorized_empty"
                              ? "Zero"
                              : "Current"
                        }
                      />
                    </div>
                    <p className="rq-metric-value">{unavailable ? "Unavailable" : card.count}</p>
                    <div className="rq-row">
                      <span className="kbd-chip">{card?.unit ?? meta.unit}</span>
                      <span className="kbd-chip">pop: {card?.population ?? populationFilter}</span>
                    </div>
                    <p className="rq-meta-text">{card?.note ?? meta.description}</p>
                  </article>
                );
              })}
            </div>
          </section>
        )}
      </ResourceStatePanel>

      <ResourceStatePanel
        view={aggregateSummaryQuery.view}
        resourceLabel="Delivery aggregate population summary"
        onRetry={aggregateSummaryQuery.reload}
      >
        {(agg) => (
          <section className="rq-card" aria-label="Delivery generation aggregate totals">
            <div className="rq-card-header">
              <h2 className="rq-section-title">
                Delivery Population Breakdown ({agg.population})
              </h2>
              <UtcTimestamp value={agg.observed_at} />
            </div>
            <div className="rq-row">
              <span className="kbd-chip">pending: {agg.pending_count}</span>
              <span className="kbd-chip">active: {agg.active_count}</span>
              <span className="kbd-chip">acked: {agg.acknowledged_count}</span>
              <span className="kbd-chip">verified receipts: {agg.verified_receipt_count}</span>
              <span className="kbd-chip">dead_letter: {agg.dead_letter_count}</span>
              <span className="kbd-chip">suppressed: {agg.suppressed_count}</span>
              <span className="kbd-chip">expired: {agg.expired_count}</span>
              <span className="kbd-chip">unknown attempts: {agg.unknown_attempt_count}</span>
            </div>
            {agg.distinct_receipt_summary !== undefined ? (
              <p className="rq-meta-text">
                Distinct receipts ({agg.distinct_receipt_summary.grouped_by}):{" "}
                <span className="mono">{agg.distinct_receipt_summary.count}</span> —{" "}
                {agg.distinct_receipt_summary.grouping_note}
              </p>
            ) : null}
          </section>
        )}
      </ResourceStatePanel>

      {selectedDeliveryId !== undefined ? (
        <ResourceStatePanel
          view={deliveryDetailQuery.view}
          resourceLabel="Delivery detail"
          onRetry={deliveryDetailQuery.reload}
        >
          {(delivery) => (
            <div className="rq-stack">
              <section className="rq-card" aria-label="Selected delivery overview">
                <div className="rq-card-header">
                  <div className="rq-row">
                    <h2 className="rq-section-title">
                      Delivery Generation #{delivery.delivery_generation}
                    </h2>
                    <StatusBadge status={delivery.state} />
                    <StatusBadge
                      status={delivery.is_replay ? "replay" : "original"}
                      label={delivery.is_replay ? "Replay Generation" : "Original Generation"}
                    />
                  </div>
                  <CopyableId value={delivery.delivery_id} label="Delivery ID" />
                </div>

                <dl className="rq-kv-grid">
                  <dt>Family ID</dt>
                  <dd>
                    <CopyableId value={delivery.family_id} />
                  </dd>
                  <dt>Event ID</dt>
                  <dd>
                    <div className="rq-row">
                      <CopyableId value={delivery.event_id} />
                      <button
                        type="button"
                        className="rq-btn"
                        onClick={() => {
                          navigate(
                            buildProjectPath(
                              scope.tenantId,
                              scope.projectId,
                              "events",
                              delivery.event_id
                            )
                          );
                        }}
                      >
                        Open Event
                      </button>
                    </div>
                  </dd>
                  <dt>Endpoint & Version</dt>
                  <dd className="mono">
                    {delivery.endpoint_id} (v{delivery.endpoint_version})
                  </dd>
                  <dt>Subscription Original / Dispatch</dt>
                  <dd className="mono">
                    {delivery.subscription_id} (orig v{delivery.original_subscription_version} / disp v
                    {delivery.dispatch_subscription_version})
                  </dd>
                  <dt>Execution Bucket / Blocking Reason</dt>
                  <dd className="mono">
                    {delivery.execution_bucket} / {delivery.blocking_reason ?? "none"}
                  </dd>
                  <dt>Attempts / Fence</dt>
                  <dd className="mono">
                    {delivery.attempt_count} / {delivery.maximum_attempts} (fence{" "}
                    {delivery.current_fence}, prepared {delivery.prepared_attempt_count}, prep
                    failures {delivery.preparation_failure_count})
                  </dd>
                  <dt>Consumer Event Key SHA-256</dt>
                  <dd>
                    <CopyableId value={delivery.consumer_event_key_sha256} />
                  </dd>
                  <dt>Deadline / Next Eligible</dt>
                  <dd>
                    <UtcTimestamp value={delivery.deadline_at} /> /{" "}
                    <UtcTimestamp value={delivery.next_eligible_at} />
                  </dd>
                </dl>

                {delivery.state === "dead_letter" ? (
                  <div className="rq-row">
                    <button
                      type="button"
                      className="rq-btn rq-btn-primary"
                      onClick={() => {
                        navigate(buildProjectPath(scope.tenantId, scope.projectId, "replays"));
                      }}
                    >
                      Propose Two-Person Replay
                    </button>
                  </div>
                ) : null}
              </section>

              <LiveWatchPanel
                streamId={`delivery:${delivery.delivery_id}`}
                path={`/api/v1/tenants/${encodeURIComponent(scope.tenantId)}/projects/${encodeURIComponent(scope.projectId)}/watch/deliveries/${encodeURIComponent(delivery.delivery_id)}`}
                label="Delivery Execution Stream"
                onEvent={() => {
                  deliveryDetailQuery.reload();
                  attemptsQuery.reload();
                  receiptsQuery.reload();
                }}
                onResyncRequired={() => {
                  deliveryDetailQuery.reload();
                  attemptsQuery.reload();
                  receiptsQuery.reload();
                }}
              />

              <section className="rq-card" aria-label="Attempt timeline">
                <h3 className="rq-card-title">Attempt Execution History</h3>
                <ResourceStatePanel
                  view={attemptsQuery.view}
                  resourceLabel="Delivery attempts"
                  emptyTitle="No attempts recorded yet"
                  onRetry={attemptsQuery.reload}
                >
                  {(attemptsPage) => (
                    <ol className="rq-timeline">
                      {attemptsPage.items.map((att: AttemptSummaryDto) => (
                        <li key={att.attempt_id} className="rq-timeline-item">
                          <div className="rq-row-between">
                            <div className="rq-row">
                              <span className="kbd-chip">Attempt #{att.attempt_number}</span>
                              <StatusBadge status={att.state} />
                              <StatusBadge
                                status={att.external_outcome}
                                label={`External: ${att.external_outcome}`}
                              />
                              {att.response_status !== null ? (
                                <span className="kbd-chip">HTTP {att.response_status}</span>
                              ) : null}
                            </div>
                            <CopyableId value={att.attempt_id} />
                          </div>
                          <dl className="rq-kv-grid">
                            <dt>Prepared / Send Started / Finished</dt>
                            <dd>
                              <UtcTimestamp value={att.prepared_at} showLocal={false} /> /{" "}
                              {att.send_started_at !== null ? (
                                <UtcTimestamp value={att.send_started_at} showLocal={false} />
                              ) : (
                                "never"
                              )}{" "}
                              /{" "}
                              {att.finished_at !== null ? (
                                <UtcTimestamp value={att.finished_at} showLocal={false} />
                              ) : (
                                "in-flight"
                              )}
                            </dd>
                            <dt>Outcome / Safe Error Code</dt>
                            <dd className="mono">
                              {att.outcome_class ?? "none"} / {att.safe_error_code ?? "none"}
                            </dd>
                            <dt>Epoch / Fence / Policy</dt>
                            <dd className="mono">
                              epoch {att.control_epoch}, fence {att.fencing_token}, signing policy v
                              {att.signing_policy_version}
                            </dd>
                            <dt>Wire / Response Body SHA-256</dt>
                            <dd className="mono">
                              wire={att.wire_body_sha256.slice(0, 16)}... / resp=
                              {att.response_body_sha256 !== null
                                ? `${att.response_body_sha256.slice(0, 16)}... (${att.response_byte_count ?? 0} B)`
                                : "none"}
                            </dd>
                          </dl>
                        </li>
                      ))}
                    </ol>
                  )}
                </ResourceStatePanel>
              </section>

              <div className="rq-grid-2">
                <section className="rq-card" aria-label="Verified receiver receipt observations">
                  <h3 className="rq-card-title">Receiver Receipts & MAC Verification</h3>
                  <ResourceStatePanel
                    view={receiptsQuery.view}
                    resourceLabel="Receiver receipts"
                    emptyTitle="No receiver receipt observations recorded"
                    emptyDescription="Verified end-to-end receipts require receiver_local_commit_v1 callback or submission."
                    onRetry={receiptsQuery.reload}
                  >
                    {(receiptsPage) => (
                      <ol className="rq-timeline">
                        {receiptsPage.items.map((rec: ReceiverReceiptObservationDto) => (
                          <li key={rec.observation_id} className="rq-timeline-item">
                            <div className="rq-row-between">
                              <div className="rq-row">
                                <StatusBadge status={rec.verification_state} />
                                <span className="kbd-chip">
                                  {rec.verification_profile_version}
                                </span>
                                {rec.key_id !== null ? (
                                  <span className="kbd-chip">key: {rec.key_id}</span>
                                ) : null}
                              </div>
                              <UtcTimestamp value={rec.observed_at} />
                            </div>
                            <dl className="rq-kv-grid">
                              <dt>Receipt Reference</dt>
                              <dd className="mono">{rec.receipt_reference}</dd>
                              <dt>Receipt Facts SHA-256</dt>
                              <dd>
                                <CopyableId value={rec.receipt_facts_sha256} />
                              </dd>
                              <dt>Receiver Contract</dt>
                              <dd className="mono">
                                {rec.receiver_contract_id} v{rec.receiver_contract_version}
                              </dd>
                              {rec.safe_receipt_facts !== undefined ? (
                                <>
                                  <dt>Allowlisted Receipt Facts</dt>
                                  <dd>
                                    <pre className="rq-json-viewer">
                                      {JSON.stringify(rec.safe_receipt_facts, null, 2)}
                                    </pre>
                                  </dd>
                                </>
                              ) : null}
                            </dl>
                          </li>
                        ))}
                      </ol>
                    )}
                  </ResourceStatePanel>
                </section>

                <section className="rq-card" aria-label="Outbound network and DNS peer digests">
                  <h3 className="rq-card-title">Network Egress & Peer Pinned Digests</h3>
                  <ResourceStatePanel
                    view={networkDecisionsQuery.view}
                    resourceLabel="Network decisions"
                    emptyTitle="No network egress decisions recorded"
                    onRetry={networkDecisionsQuery.reload}
                  >
                    {(netPage) => (
                      <ol className="rq-timeline">
                        {netPage.items.map((nd) => (
                          <li key={nd.decision_id} className="rq-timeline-item">
                            <div className="rq-row-between">
                              <div className="rq-row">
                                <StatusBadge
                                  status={nd.decision === "allowed" ? "active" : "rejected"}
                                  label={`Egress ${nd.decision}`}
                                />
                                <span className="kbd-chip">{nd.ip_family}</span>
                                {nd.reason_code !== null ? (
                                  <span className="kbd-chip">{nd.reason_code}</span>
                                ) : null}
                              </div>
                              <UtcTimestamp value={nd.observed_at} />
                            </div>
                            <dl className="rq-kv-grid">
                              <dt>Policy / Registry SHA-256</dt>
                              <dd className="mono">
                                policy={nd.policy_sha256.slice(0, 16)}... / registry=
                                {nd.registry_sha256.slice(0, 16)}...
                              </dd>
                              <dt>DNS / Pinned Peer SHA-256</dt>
                              <dd className="mono">
                                dns={nd.dns_answer_sha256.slice(0, 16)}... / peer=
                                {nd.pinned_peer_sha256.slice(0, 16)}...
                              </dd>
                            </dl>
                          </li>
                        ))}
                      </ol>
                    )}
                  </ResourceStatePanel>
                </section>
              </div>

              <section className="rq-card" aria-label="Authorized outbound wire payload">
                <div className="rq-card-header">
                  <h3 className="rq-card-title">Wire Request Content Inspection</h3>
                  <button
                    type="button"
                    className="rq-btn rq-btn-primary"
                    disabled={
                      !isCapabilityAvailable(
                        delivery.capabilities ?? [],
                        "deliveries.request.read"
                      ) && (delivery.capabilities?.length ?? 0) > 0
                    }
                    onClick={() => {
                      void handleLoadWireRequestContent(delivery.delivery_id);
                    }}
                  >
                    <ConsoleIcon name="info" />
                    <span>Load Authorized Wire Body</span>
                  </button>
                </div>
                <MutationFeedback state={wireFeedback} resourceLabel="Wire request content" />
                {wireContent !== null ? (
                  <LosslessJsonViewer
                    base64Data={wireContent.data}
                    title={`Outbound Wire Envelope (rep v${wireContent.representation_version})`}
                    expectedSha256={wireContent.sha256}
                  />
                ) : null}
              </section>

              <div className="rq-grid-2">
                <section className="rq-card" aria-label="Late delivery observations">
                  <h3 className="rq-card-title">Late Observations</h3>
                  <ResourceStatePanel
                    view={lateObservationsQuery.view}
                    resourceLabel="Late observations"
                    emptyTitle="No late observations"
                    onRetry={lateObservationsQuery.reload}
                  >
                    {(latePage) => (
                      <ol className="rq-timeline">
                        {latePage.items.map((obs) => (
                          <li key={obs.observation_id} className="rq-timeline-item">
                            <div className="rq-row-between">
                              <span className="kbd-chip">{obs.observation_kind}</span>
                              <UtcTimestamp value={obs.recorded_at} />
                            </div>
                            <span className="mono">facts={obs.facts_sha256.slice(0, 20)}...</span>
                          </li>
                        ))}
                      </ol>
                    )}
                  </ResourceStatePanel>
                </section>

                <section className="rq-card" aria-label="Trace references">
                  <h3 className="rq-card-title">Trace References & Delivery History</h3>
                  <ResourceStatePanel
                    view={traceQuery.view}
                    resourceLabel="Trace references"
                    emptyTitle="No external trace references recorded"
                    onRetry={traceQuery.reload}
                  >
                    {(tracesPage) => (
                      <ul className="rq-timeline">
                        {tracesPage.items.map((tr) => (
                          <li key={`${tr.trace_id}:${tr.span_id}`} className="rq-timeline-item">
                            <div className="rq-row-between">
                              <span className="mono">
                                trace={tr.trace_id} / span={tr.span_id}
                              </span>
                              <StatusBadge status={tr.availability} />
                            </div>
                          </li>
                        ))}
                      </ul>
                    )}
                  </ResourceStatePanel>

                  <ResourceStatePanel
                    view={historyQuery.view}
                    resourceLabel="Delivery state transitions"
                    emptyTitle="No state transitions recorded"
                    onRetry={historyQuery.reload}
                  >
                    {(histPage) => (
                      <ol className="rq-timeline">
                        {histPage.items.map((h) => (
                          <li key={h.history_sequence} className="rq-timeline-item">
                            <div className="rq-row-between">
                              <strong>
                                #{h.history_sequence} {h.event_kind}
                              </strong>
                              <UtcTimestamp value={h.recorded_at} />
                            </div>
                          </li>
                        ))}
                      </ol>
                    )}
                  </ResourceStatePanel>
                </section>
              </div>
            </div>
          )}
        </ResourceStatePanel>
      ) : null}

      <section className="rq-card" aria-label="Deliveries filter controls">
        <div className="rq-grid-3">
          <FormField label="Event ID">
            {({ inputId }) => (
              <input
                id={inputId}
                className="rq-input mono"
                placeholder="Canonical UUID"
                value={eventIdFilter}
                onChange={(e) => {
                  setEventIdFilter(e.target.value);
                  setCursorStack([null]);
                }}
              />
            )}
          </FormField>

          <FormField label="Endpoint ID">
            {({ inputId }) => (
              <input
                id={inputId}
                className="rq-input mono"
                placeholder="Canonical UUID"
                value={endpointIdFilter}
                onChange={(e) => {
                  setEndpointIdFilter(e.target.value);
                  setCursorStack([null]);
                }}
              />
            )}
          </FormField>

          <FormField label="Delivery State">
            {({ inputId }) => (
              <select
                id={inputId}
                className="rq-select"
                value={stateFilter}
                onChange={(e) => {
                  setStateFilter(e.target.value);
                  setCursorStack([null]);
                }}
              >
                <option value="">All states</option>
                {DELIVERY_STATES.map((st) => (
                  <option key={st} value={st}>
                    {st}
                  </option>
                ))}
              </select>
            )}
          </FormField>

          <FormField label="Outcome Class">
            {({ inputId }) => (
              <select
                id={inputId}
                className="rq-select"
                value={outcomeFilter}
                onChange={(e) => {
                  setOutcomeFilter(e.target.value);
                  setCursorStack([null]);
                }}
              >
                <option value="">All outcomes</option>
                {DELIVERY_OUTCOME_CLASSES.map((oc) => (
                  <option key={oc} value={oc}>
                    {oc}
                  </option>
                ))}
              </select>
            )}
          </FormField>
        </div>
      </section>

      <ResourceStatePanel
        view={deliveriesQuery.view}
        resourceLabel="Deliveries list"
        emptyTitle="No deliveries match the selected population or filters"
        onRetry={deliveriesQuery.reload}
      >
        {(deliveriesPage) => (
          <section className="rq-card" aria-label="Deliveries table">
            <DataTable<DeliverySummaryDto>
              caption="Project deliveries"
              rows={deliveriesPage.items}
              rowKey={(d) => d.delivery_id}
              pagination={{
                pageSize,
                pageIndex: cursorStack.length - 1,
                onPageSizeChange: (nextSize) => {
                  setPageSize(nextSize);
                  setCursorStack([null]);
                },
                hasPrev: cursorStack.length > 1,
                hasNext:
                  (deliveriesPage.page.has_more ?? deliveriesPage.page.next_cursor !== null) &&
                  deliveriesPage.page.next_cursor !== null,
                onPrev: () => {
                  setCursorStack((prev) => (prev.length > 1 ? prev.slice(0, -1) : prev));
                },
                onNext: () => {
                  if (deliveriesPage.page.next_cursor !== null) {
                    const nextCursor = deliveriesPage.page.next_cursor;
                    setCursorStack((prev) => [...prev, nextCursor]);
                  }
                }
              }}
              columns={[
                {
                  key: "delivery",
                  header: "Delivery / Generation",
                  render: (d) => (
                    <div className="rq-stack-sm">
                      <span className="mono">{d.delivery_id}</span>
                      <div className="rq-row">
                        <span className="kbd-chip">gen #{d.delivery_generation}</span>
                        <span className="kbd-chip">
                          {d.is_replay ? "replay" : "original"}
                        </span>
                      </div>
                    </div>
                  )
                },
                {
                  key: "state",
                  header: "State & Bucket",
                  render: (d) => (
                    <div className="rq-stack-sm">
                      <StatusBadge status={d.state} />
                      <span className="rq-meta-text mono">
                        {d.execution_bucket}
                        {d.blocking_reason !== null ? ` (${d.blocking_reason})` : ""}
                      </span>
                    </div>
                  )
                },
                {
                  key: "attempts",
                  header: "Attempts & Latest Response",
                  render: (d) => (
                    <div className="rq-stack-sm">
                      <span className="mono">
                        {d.attempt_count}/{d.maximum_attempts}
                      </span>
                      {d.latest_response_summary !== null ? (
                        <span className="rq-meta-text mono">
                          HTTP {d.latest_response_summary.response_status ?? "none"} (
                          {d.latest_response_summary.outcome_class})
                        </span>
                      ) : null}
                    </div>
                  )
                },
                {
                  key: "receipt",
                  header: "Latest Receipt",
                  render: (d) =>
                    d.latest_receipt_summary !== null ? (
                      <StatusBadge status={d.latest_receipt_summary.verification_state} />
                    ) : (
                      <span className="rq-meta-text">None</span>
                    )
                },
                {
                  key: "inspect",
                  header: "Inspect",
                  render: (d) => (
                    <button
                      type="button"
                      className="rq-btn"
                      onClick={() => {
                        navigate(
                          buildProjectPath(
                            scope.tenantId,
                            scope.projectId,
                            "deliveries",
                            d.delivery_id
                          )
                        );
                      }}
                    >
                      Investigate
                    </button>
                  )
                }
              ]}
            />
          </section>
        )}
      </ResourceStatePanel>
    </div>
  );
}
