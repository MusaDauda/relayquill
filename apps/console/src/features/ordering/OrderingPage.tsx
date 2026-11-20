import { type JSX, useState } from "react";
import { hashCanonicalJson, isCapabilityAvailable } from "@relayquill/contracts";
import {
  DELIVERY_OUTCOME_CLASSES,
  type DeliveryOutcomeClass,
  type ProposalReviewDecision
} from "@relayquill/domain";
import {
  type OrderSkipProposalDto,
  type OrderingCutoverPlanDto,
  type OrderingKeySummaryDto,
  type OrderingMemberDto
} from "../../api/dtos.js";
import { buildProjectPath, useConsoleRouter } from "../../app/router.js";
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
import { evaluateProposalReviewerEligibility } from "../replays/replay-guards.js";

export function OrderingPage(): JSX.Element {
  const { navigate } = useConsoleRouter();
  const { api, session } = useConsoleRuntime();
  const scope = useActiveScope();

  const [selectedEndpointId, setSelectedEndpointId] = useState("");
  const [keyStateFilter, setKeyStateFilter] = useState("");
  const [subscriptionFilter, setSubscriptionFilter] = useState("");
  const [selectedKey, setSelectedKey] = useState<OrderingKeySummaryDto | null>(null);

  // Order-skip proposal form state
  const [skipDeliveryId, setSkipDeliveryId] = useState("");
  const [skipExpectedDeliveryVersion, setSkipExpectedDeliveryVersion] = useState("1");
  const [skipOutcomeClass, setSkipOutcomeClass] =
    useState<DeliveryOutcomeClass>("permanent_http");
  const [skipReasonCode, setSkipReasonCode] = useState("reviewed_gap_skip_after_triage");
  const [skipEvidence, setSkipEvidence] = useState("ordering-triage-log");
  const [skipReviewId, setSkipReviewId] = useState("");

  // Cutover creation form
  const [cutoverSubId, setCutoverSubId] = useState("");
  const [cutoverTargetVersion, setCutoverTargetVersion] = useState("2");
  const [cutoverReason, setCutoverReason] = useState("extractor_cutover_rollout");

  const [feedback, setFeedback] = useState<MutationFeedbackState>({ kind: "idle" });
  const [pendingStepUp, setPendingStepUp] = useState<{
    readonly descriptor: StepUpTargetDescriptor;
    readonly execute: (operationProofId: string) => Promise<void>;
  } | null>(null);

  const currentPrincipalId = session?.principal_id ?? scope.principalId;

  const endpointsQuery = useScopedQuery({
    resource: "project.ordering_endpoints",
    isEmpty: (d) => d.items.length === 0,
    fetcher: (signal: AbortSignal) =>
      api.listEndpoints(scope.tenantId, scope.projectId, { limit: 100 }, signal)
  });

  const circuitQuery = useScopedQuery({
    resource: "project.endpoint_circuit",
    enabled: selectedEndpointId.trim().length > 0,
    filter: { selectedEndpointId },
    extractVersion: (d) => d.version,
    fetcher: (signal: AbortSignal) =>
      api.getEndpointCircuit(scope.tenantId, scope.projectId, selectedEndpointId.trim(), signal)
  });

  const orderingKeysQuery = useScopedQuery({
    resource: "project.ordering_keys",
    filter: { keyStateFilter, subscriptionFilter },
    isEmpty: (d) => d.items.length === 0,
    fetcher: (signal: AbortSignal) =>
      api.listOrderingKeys(
        scope.tenantId,
        scope.projectId,
        {
          ...(keyStateFilter.trim().length > 0 ? { state: keyStateFilter.trim() } : {}),
          ...(subscriptionFilter.trim().length > 0
            ? { subscription_id: subscriptionFilter.trim() }
            : {}),
          limit: 25
        },
        signal
      )
  });

  const membersQuery = useScopedQuery({
    resource: "project.ordering_members",
    enabled: selectedKey !== null,
    filter: { keyId: selectedKey?.ordering_key_id },
    isEmpty: (d) => d.items.length === 0,
    fetcher: (signal: AbortSignal) =>
      api.listOrderingMembers(
        scope.tenantId,
        scope.projectId,
        selectedKey?.ordering_key_id ?? "",
        { limit: 50 },
        signal
      )
  });

  const skipProposalsQuery = useScopedQuery({
    resource: "project.order_skip_proposals",
    isEmpty: (d) => d.items.length === 0,
    fetcher: (signal: AbortSignal) =>
      api.listOrderSkipProposals(scope.tenantId, scope.projectId, signal)
  });

  const cutoversQuery = useScopedQuery({
    resource: "project.ordering_cutovers",
    isEmpty: (d) => d.items.length === 0,
    fetcher: (signal: AbortSignal) =>
      api.listOrderingCutovers(scope.tenantId, scope.projectId, signal)
  });

  const handleRequestProbe = (endpointId: string, circuitVersion: string): void => {
    const body = {
      schema_version: 1,
      expected_circuit_version: circuitVersion,
      reason_code: "operator_half_open_probe_request"
    };
    const canonical = hashCanonicalJson(body);
    setPendingStepUp({
      descriptor: {
        action: "circuits.request_probe",
        actionLabel: "Request Bounded Half-Open Probe",
        scopeKind: "project",
        tenantId: scope.tenantId,
        projectId: scope.projectId,
        targetResourceId: endpointId,
        targetVersion: circuitVersion,
        canonicalCommandSha256: canonical.sha256,
        summary: `Requests a bounded single-attempt half-open circuit probe on endpoint ${endpointId}.`
      },
      execute: async (operationProofId: string) => {
        setFeedback({ kind: "submitting", label: "Requesting circuit breaker probe..." });
        const res = await api.requestCircuitProbe(
          scope.tenantId,
          scope.projectId,
          endpointId,
          { ...body, operation_proof_id: operationProofId },
          generateIdempotencyKey("circuit-probe")
        );
        if (!res.ok) {
          setFeedback({ kind: "failed", error: res, preservedDraft: body });
          return;
        }
        setFeedback({
          kind: "succeeded",
          title: "Bounded Probe Requested",
          detail: "Circuit breaker recorded bounded probe request.",
          receiptId: res.data.receipt?.id
        });
        circuitQuery.reload();
      }
    });
  };

  const handleProposeGapSkip = async (): Promise<void> => {
    if (selectedKey === null) {
      return;
    }
    const evidenceReferences = skipEvidence
      .split(",")
      .map((s) => s.trim())
      .filter((s) => s.length > 0);
    const body = {
      schema_version: 1,
      ordering_key_id: selectedKey.ordering_key_id,
      delivery_id: skipDeliveryId.trim() || selectedKey.blocked_delivery_id || "",
      expected_key_version: selectedKey.version,
      expected_delivery_version: skipExpectedDeliveryVersion.trim(),
      known_outcome_class: skipOutcomeClass,
      evidence_references:
        evidenceReferences.length > 0 ? evidenceReferences : ["ordering-triage"],
      reason_code: skipReasonCode.trim() || "reviewed_gap_skip_after_triage"
    };
    setFeedback({ kind: "submitting", label: "Submitting reviewed gap_skip proposal..." });
    const res = await api.createOrderSkipProposal(
      scope.tenantId,
      scope.projectId,
      selectedKey.ordering_key_id,
      body,
      generateIdempotencyKey("order-skip-propose")
    );
    if (!res.ok) {
      setFeedback({ kind: "failed", error: res, preservedDraft: body });
      return;
    }
    setFeedback({
      kind: "succeeded",
      title: "Reviewed Gap Skip Proposal Created",
      detail: `Order skip proposal ${res.data.proposal_id} queued for second-person review.`
    });
    skipProposalsQuery.reload();
  };

  const openOrderSkipStepUp = (
    proposal: OrderSkipProposalDto,
    action: "reviews" | "admit",
    decision?: ProposalReviewDecision
  ): void => {
    const body =
      action === "reviews"
        ? {
            schema_version: 1,
            expected_proposal_version: proposal.version,
            candidate_sha256: proposal.candidate_sha256,
            decision: decision ?? "approve",
            evidence_references: ["independent-ordering-review"],
            reason_code: skipReasonCode.trim() || `order_skip_${decision ?? "approve"}`
          }
        : {
            schema_version: 1,
            expected_proposal_version: proposal.version,
            candidate_sha256: proposal.candidate_sha256,
            review_id: skipReviewId.trim(),
            reason_code: skipReasonCode.trim() || "admit_approved_gap_skip"
          };
    const canonical = hashCanonicalJson(body);
    setPendingStepUp({
      descriptor: {
        action:
          action === "reviews" ? "order_skip_proposals.review" : "order_skip_proposals.admit",
        actionLabel:
          action === "reviews"
            ? `${decision === "reject" ? "Reject" : "Approve"} Order Gap Skip`
            : "Admit Approved Order Gap Skip",
        scopeKind: "project",
        tenantId: scope.tenantId,
        projectId: scope.projectId,
        targetResourceId: proposal.proposal_id,
        targetVersion: proposal.version,
        canonicalCommandSha256: canonical.sha256,
        summary: `Executes reviewed gap_skip ${action} advancing strict head seq ${proposal.prior_sequence} -> ${proposal.resulting_sequence}.`
      },
      execute: async (operationProofId: string) => {
        setFeedback({ kind: "submitting", label: `Executing order-skip ${action}...` });
        const res = await api.mutateOrderSkipProposal(
          scope.tenantId,
          scope.projectId,
          proposal.proposal_id,
          action,
          { ...body, operation_proof_id: operationProofId },
          generateIdempotencyKey(`order-skip-${action}`)
        );
        if (!res.ok) {
          setFeedback({ kind: "failed", error: res, currentServerState: proposal });
          return;
        }
        setFeedback({
          kind: "succeeded",
          title: `Order Skip ${action === "reviews" ? "Reviewed" : "Admitted"}`,
          detail: `Order skip proposal ${proposal.proposal_id} updated.`,
          receiptId: res.data.receipt?.id
        });
        skipProposalsQuery.reload();
        orderingKeysQuery.reload();
        membersQuery.reload();
      }
    });
  };

  const handleCreateCutover = async (): Promise<void> => {
    const body = {
      schema_version: 1,
      target_version: cutoverTargetVersion.trim(),
      reason_code: cutoverReason.trim() || "extractor_cutover_rollout"
    };
    setFeedback({ kind: "submitting", label: "Proposing ordering extractor cutover plan..." });
    const res = await api.createOrderingCutover(
      scope.tenantId,
      scope.projectId,
      cutoverSubId.trim(),
      body,
      generateIdempotencyKey("cutover-create")
    );
    if (!res.ok) {
      setFeedback({ kind: "failed", error: res, preservedDraft: body });
      return;
    }
    setFeedback({
      kind: "succeeded",
      title: "Cutover Plan Proposed",
      detail: `Created cutover plan ${res.data.plan_id} (${res.data.source_version} -> ${res.data.target_version}).`
    });
    cutoversQuery.reload();
  };

  const openCutoverMutation = (
    plan: OrderingCutoverPlanDto,
    action: "begin" | "activate" | "abort"
  ): void => {
    const body = {
      schema_version: 1,
      expected_version: plan.version,
      candidate_sha256: plan.candidate_sha256,
      reason_code: cutoverReason.trim() || `cutover_${action}`
    };
    const canonical = hashCanonicalJson(body);
    setPendingStepUp({
      descriptor: {
        action: `ordering_cutovers.${action}`,
        actionLabel: `Extractor Cutover: ${action}`,
        scopeKind: "project",
        tenantId: scope.tenantId,
        projectId: scope.projectId,
        targetResourceId: plan.plan_id,
        targetVersion: plan.version,
        canonicalCommandSha256: canonical.sha256,
        summary: `Transitions extractor cutover ${plan.plan_id} (sub ${plan.subscription_id} v${plan.source_version} -> v${plan.target_version}) with action "${action}".`
      },
      execute: async (operationProofId: string) => {
        setFeedback({ kind: "submitting", label: `Executing cutover ${action}...` });
        const res = await api.mutateOrderingCutover(
          scope.tenantId,
          scope.projectId,
          plan.plan_id,
          action,
          { ...body, operation_proof_id: operationProofId },
          generateIdempotencyKey(`cutover-${action}`)
        );
        if (!res.ok) {
          setFeedback({ kind: "failed", error: res, currentServerState: plan });
          return;
        }
        setFeedback({
          kind: "succeeded",
          title: `Extractor Cutover ${action} Committed`,
          detail: `Cutover plan ${plan.plan_id} transitioned (${action}).`,
          receiptId: res.data.receipt?.id
        });
        cutoversQuery.reload();
      }
    });
  };

  return (
    <div className="rq-stack">
      <header className="rq-page-header">
        <div>
          <h1 className="rq-page-title">Ordering Heads, Circuit Breakers & Cutover Plans</h1>
          <p className="rq-page-lead">
            Inspect endpoint circuit breakers and request bounded half-open probes, diagnose strict
            per-key ordering heads with reviewed <span className="kbd-chip">gap_skip</span> or{" "}
            <span className="kbd-chip">replay_append</span>, and coordinate extractor cutovers.
          </p>
        </div>
      </header>

      <MutationFeedback state={feedback} resourceLabel="Ordering & Circuit governance" />

      <section className="rq-card" aria-label="Endpoint circuit breakers and half-open probes">
        <div className="rq-card-header">
          <h2 className="rq-section-title">Endpoint Circuit Breakers & Half-Open Probes</h2>
        </div>

        <FormField label="Select Endpoint to Inspect Circuit">
          {({ inputId }) => (
            <select
              id={inputId}
              className="rq-select"
              value={selectedEndpointId}
              onChange={(e) => {
                setSelectedEndpointId(e.target.value);
              }}
            >
              <option value="">Choose endpoint...</option>
              {endpointsQuery.view.state === "current"
                ? endpointsQuery.view.data.items.map((ep) => (
                    <option key={ep.endpoint_id} value={ep.endpoint_id}>
                      {ep.name} ({ep.state}) — {ep.endpoint_id}
                    </option>
                  ))
                : null}
            </select>
          )}
        </FormField>

        {selectedEndpointId.trim().length > 0 ? (
          <ResourceStatePanel
            view={circuitQuery.view}
            resourceLabel="Endpoint circuit breaker"
            onRetry={circuitQuery.reload}
          >
            {(circuit) => (
              <div className="rq-card-inset">
                <div className="rq-row-between">
                  <div className="rq-row">
                    <StatusBadge status={circuit.state} />
                    <StatusBadge
                      status={circuit.endpoint_state}
                      label={`Endpoint: ${circuit.endpoint_state}`}
                    />
                  </div>
                  <button
                    type="button"
                    className="rq-btn rq-btn-primary"
                    disabled={
                      !isCapabilityAvailable(
                        circuit.capabilities ?? [],
                        "circuits.request_probe"
                      ) && (circuit.capabilities?.length ?? 0) > 0
                    }
                    onClick={() => {
                      handleRequestProbe(circuit.endpoint_id, circuit.version);
                    }}
                  >
                    Request Bounded Half-Open Probe (Step-Up)
                  </button>
                </div>

                <dl className="rq-kv-grid">
                  <dt>Circuit / Probe Generation</dt>
                  <dd className="mono">
                    circuit gen {circuit.circuit_generation} / probe gen {circuit.probe_generation}
                  </dd>
                  <dt>Failure Window & Reopens</dt>
                  <dd className="mono">
                    consecutive transient failures: {circuit.consecutive_transient_failures}, reopens:{" "}
                    {circuit.reopen_count} (window {circuit.window_success_count} ok /{" "}
                    {circuit.window_failure_count} fail)
                  </dd>
                  <dt>Reopen Not Before</dt>
                  <dd>
                    {circuit.reopen_not_before !== null ? (
                      <UtcTimestamp value={circuit.reopen_not_before} />
                    ) : (
                      "immediate"
                    )}
                  </dd>
                  {circuit.active_probe_request !== null &&
                  circuit.active_probe_request !== undefined ? (
                    <>
                      <dt>Active Probe Request</dt>
                      <dd className="rq-row">
                        <StatusBadge status={circuit.active_probe_request.state} />
                        <CopyableId value={circuit.active_probe_request.request_id} />
                        <UtcTimestamp value={circuit.active_probe_request.expires_at} />
                      </dd>
                    </>
                  ) : null}
                </dl>
              </div>
            )}
          </ResourceStatePanel>
        ) : null}
      </section>

      <section className="rq-card" aria-label="Strict ordered key heads">
        <div className="rq-card-header">
          <h2 className="rq-section-title">Strict Ordered Key Heads & Gap Disposition</h2>
          <button
            type="button"
            className="rq-btn"
            onClick={() => {
              navigate(buildProjectPath(scope.tenantId, scope.projectId, "replays"));
            }}
          >
            Open Replays for replay_append
          </button>
        </div>

        <div className="rq-grid-2">
          <FormField label="Key Head State Filter">
            {({ inputId }) => (
              <select
                id={inputId}
                className="rq-select"
                value={keyStateFilter}
                onChange={(e) => {
                  setKeyStateFilter(e.target.value);
                }}
              >
                <option value="">All key heads</option>
                <option value="blocked">blocked</option>
                <option value="active">active</option>
              </select>
            )}
          </FormField>

          <FormField label="Subscription ID Filter">
            {({ inputId }) => (
              <input
                id={inputId}
                className="rq-input mono"
                placeholder="Canonical subscription UUID"
                value={subscriptionFilter}
                onChange={(e) => {
                  setSubscriptionFilter(e.target.value);
                }}
              />
            )}
          </FormField>
        </div>

        <ResourceStatePanel
          view={orderingKeysQuery.view}
          resourceLabel="Ordering keys"
          emptyTitle="No strict ordering keys found"
          onRetry={orderingKeysQuery.reload}
        >
          {(keysPage) => (
            <DataTable<OrderingKeySummaryDto>
              caption="Strict ordered key heads"
              rows={keysPage.items}
              rowKey={(k) => k.ordering_key_id}
              columns={[
                {
                  key: "key",
                  header: "Ordering Key & Scope",
                  render: (k) => (
                    <div className="rq-stack-sm">
                      <CopyableId value={k.ordering_key_id} />
                      <span className="rq-meta-text mono">
                        {k.extracted_key_value ?? `${k.key_digest_sha256.slice(0, 16)}...`}
                      </span>
                    </div>
                  )
                },
                {
                  key: "seq",
                  header: "Eligible / Allocate Head",
                  render: (k) => (
                    <span className="mono">
                      eligible #{k.next_eligible_sequence} / allocate #{k.next_allocate_sequence}
                    </span>
                  )
                },
                {
                  key: "state",
                  header: "Head State",
                  render: (k) => (
                    <div className="rq-stack-sm">
                      <StatusBadge status={k.state} />
                      {k.blocked_reason_code !== null ? (
                        <span className="rq-meta-text mono">{k.blocked_reason_code}</span>
                      ) : null}
                    </div>
                  )
                },
                {
                  key: "inspect",
                  header: "Inspect Members",
                  render: (k) => (
                    <button
                      type="button"
                      className="rq-btn"
                      onClick={() => {
                        setSelectedKey(k);
                        setSkipDeliveryId(k.blocked_delivery_id ?? "");
                      }}
                    >
                      Inspect Sequence
                    </button>
                  )
                }
              ]}
            />
          )}
        </ResourceStatePanel>

        {selectedKey !== null ? (
          <div className="rq-card-inset">
            <div className="rq-row-between">
              <strong className="rq-label">
                Key {selectedKey.ordering_key_id} Sequence Members (next eligible #
                {selectedKey.next_eligible_sequence})
              </strong>
              <button
                type="button"
                className="rq-btn"
                onClick={() => {
                  setSelectedKey(null);
                }}
              >
                Close Sequence
              </button>
            </div>

            <ResourceStatePanel
              view={membersQuery.view}
              resourceLabel="Ordering sequence members"
              emptyTitle="No sequence members"
              onRetry={membersQuery.reload}
            >
              {(memPage) => (
                <DataTable<OrderingMemberDto>
                  caption="Ordering sequence members"
                  rows={memPage.items}
                  rowKey={(m) => `${m.ordering_key_id}:${m.ordering_sequence}`}
                  columns={[
                    {
                      key: "seq",
                      header: "Sequence & Kind",
                      render: (m) => (
                        <div className="rq-row">
                          <span className="kbd-chip">#{m.ordering_sequence}</span>
                          <span className="kbd-chip">{m.member_kind}</span>
                        </div>
                      )
                    },
                    {
                      key: "delivery",
                      header: "Delivery",
                      render: (m) => (
                        <button
                          type="button"
                          className="rq-btn"
                          onClick={() => {
                            navigate(
                              buildProjectPath(
                                scope.tenantId,
                                scope.projectId,
                                "deliveries",
                                m.delivery_id
                              )
                            );
                          }}
                        >
                          {m.delivery_id.slice(0, 12)}... (gen {m.delivery_generation})
                        </button>
                      )
                    },
                    {
                      key: "state",
                      header: "Member State",
                      render: (m) => (
                        <div className="rq-row">
                          <StatusBadge status={m.state} />
                          {m.disposition_decision !== null ? (
                            <span className="kbd-chip">{m.disposition_decision}</span>
                          ) : null}
                        </div>
                      )
                    }
                  ]}
                />
              )}
            </ResourceStatePanel>

            <div className="rq-grid-3">
              <FormField label="Blocked Delivery ID" required>
                {({ inputId }) => (
                  <input
                    id={inputId}
                    className="rq-input mono"
                    value={skipDeliveryId}
                    onChange={(e) => {
                      setSkipDeliveryId(e.target.value);
                    }}
                  />
                )}
              </FormField>
              <FormField label="Expected Delivery Version" required>
                {({ inputId }) => (
                  <input
                    id={inputId}
                    className="rq-input mono"
                    value={skipExpectedDeliveryVersion}
                    onChange={(e) => {
                      setSkipExpectedDeliveryVersion(e.target.value);
                    }}
                  />
                )}
              </FormField>
              <FormField label="Known Outcome Class" required>
                {({ inputId }) => (
                  <select
                    id={inputId}
                    className="rq-select"
                    value={skipOutcomeClass}
                    onChange={(e) => {
                      setSkipOutcomeClass(e.target.value as DeliveryOutcomeClass);
                    }}
                  >
                    {DELIVERY_OUTCOME_CLASSES.map((oc) => (
                      <option key={oc} value={oc}>
                        {oc}
                      </option>
                    ))}
                  </select>
                )}
              </FormField>
              <FormField label="Evidence References" required>
                {({ inputId }) => (
                  <input
                    id={inputId}
                    className="rq-input mono"
                    value={skipEvidence}
                    onChange={(e) => {
                      setSkipEvidence(e.target.value);
                    }}
                  />
                )}
              </FormField>
              <FormField label="Reason Code" required>
                {({ inputId }) => (
                  <input
                    id={inputId}
                    className="rq-input mono"
                    value={skipReasonCode}
                    onChange={(e) => {
                      setSkipReasonCode(e.target.value);
                    }}
                  />
                )}
              </FormField>
            </div>
            <div className="rq-row">
              <button
                type="button"
                className="rq-btn rq-btn-primary"
                disabled={
                  !isCapabilityAvailable(
                    selectedKey.capabilities ?? [],
                    "order_skip_proposals.propose"
                  ) && (selectedKey.capabilities?.length ?? 0) > 0
                }
                onClick={() => {
                  void handleProposeGapSkip();
                }}
              >
                Propose Reviewed gap_skip
              </button>
            </div>
          </div>
        ) : null}

        <div className="rq-grid-2">
          <FormField
            label="Order-Skip Review ID (for Admitting Approved Skips)"
            helpText="Distinct reviewer approves first with step-up, then operator admits using that review ID."
          >
            {({ inputId }) => (
              <input
                id={inputId}
                className="rq-input mono"
                value={skipReviewId}
                onChange={(e) => {
                  setSkipReviewId(e.target.value);
                }}
              />
            )}
          </FormField>
        </div>

        <ResourceStatePanel
          view={skipProposalsQuery.view}
          resourceLabel="Order skip proposals"
          emptyTitle="No order-skip proposals recorded"
          onRetry={skipProposalsQuery.reload}
        >
          {(skipsPage) => (
            <DataTable<OrderSkipProposalDto>
              caption="Two-person order skip proposals"
              rows={skipsPage.items}
              rowKey={(p) => p.proposal_id}
              columns={[
                {
                  key: "id",
                  header: "Proposal & Head Advance",
                  render: (p) => (
                    <div className="rq-stack-sm">
                      <CopyableId value={p.proposal_id} />
                      <span className="mono">
                        #{p.prior_sequence} -&gt; #{p.resulting_sequence}
                      </span>
                    </div>
                  )
                },
                {
                  key: "state",
                  header: "State & Proposer",
                  render: (p) => (
                    <div className="rq-stack-sm">
                      <StatusBadge status={p.state} />
                      <span className="mono">{p.proposer_principal_id}</span>
                    </div>
                  )
                },
                {
                  key: "actions",
                  header: "Two-Person Actions",
                  render: (p) => {
                    const elig = evaluateProposalReviewerEligibility({
                      proposalState: p.state,
                      proposerPrincipalId: p.proposer_principal_id,
                      currentPrincipalId,
                      capabilities: p.capabilities,
                      reviewAction: "order_skip_proposals.review",
                      admitAction: "order_skip_proposals.admit"
                    });
                    return (
                      <div className="rq-row">
                        <button
                          type="button"
                          className="rq-btn rq-btn-primary"
                          disabled={!elig.canReview}
                          title={elig.blockReason ?? undefined}
                          onClick={() => {
                            openOrderSkipStepUp(p, "reviews", "approve");
                          }}
                        >
                          Approve (Step-Up)
                        </button>
                        <button
                          type="button"
                          className="rq-btn rq-btn-danger"
                          disabled={!elig.canReview}
                          title={elig.blockReason ?? undefined}
                          onClick={() => {
                            openOrderSkipStepUp(p, "reviews", "reject");
                          }}
                        >
                          Reject
                        </button>
                        {elig.canAdmit ? (
                          <button
                            type="button"
                            className="rq-btn rq-btn-primary"
                            disabled={skipReviewId.trim().length === 0}
                            onClick={() => {
                              openOrderSkipStepUp(p, "admit");
                            }}
                          >
                            Admit Skip
                          </button>
                        ) : null}
                      </div>
                    );
                  }
                }
              ]}
            />
          )}
        </ResourceStatePanel>
      </section>

      <section className="rq-card" aria-label="Ordering extractor cutover plans">
        <h2 className="rq-section-title">Extractor Cutover Coordination</h2>
        <div className="rq-grid-3">
          <FormField label="Subscription ID" required>
            {({ inputId }) => (
              <input
                id={inputId}
                className="rq-input mono"
                value={cutoverSubId}
                onChange={(e) => {
                  setCutoverSubId(e.target.value);
                }}
              />
            )}
          </FormField>
          <FormField label="Target Subscription Version" required>
            {({ inputId }) => (
              <input
                id={inputId}
                className="rq-input mono"
                value={cutoverTargetVersion}
                onChange={(e) => {
                  setCutoverTargetVersion(e.target.value);
                }}
              />
            )}
          </FormField>
          <FormField label="Reason Code">
            {({ inputId }) => (
              <input
                id={inputId}
                className="rq-input mono"
                value={cutoverReason}
                onChange={(e) => {
                  setCutoverReason(e.target.value);
                }}
              />
            )}
          </FormField>
        </div>
        <div className="rq-row">
          <button
            type="button"
            className="rq-btn rq-btn-primary"
            disabled={cutoverSubId.trim().length === 0}
            onClick={() => {
              void handleCreateCutover();
            }}
          >
            Propose Extractor Cutover
          </button>
        </div>

        <ResourceStatePanel
          view={cutoversQuery.view}
          resourceLabel="Extractor cutover plans"
          emptyTitle="No extractor cutovers configured"
          onRetry={cutoversQuery.reload}
        >
          {(cutPage) => (
            <DataTable<OrderingCutoverPlanDto>
              caption="Ordering extractor cutover plans"
              rows={cutPage.items}
              rowKey={(c) => c.plan_id}
              columns={[
                {
                  key: "plan",
                  header: "Cutover Plan & Versions",
                  render: (c) => (
                    <div className="rq-stack-sm">
                      <CopyableId value={c.plan_id} />
                      <span className="mono">
                        sub {c.subscription_id} (v{c.source_version} -&gt; v{c.target_version})
                      </span>
                    </div>
                  )
                },
                {
                  key: "state",
                  header: "Drain Status",
                  render: (c) => (
                    <div className="rq-stack-sm">
                      <StatusBadge status={c.state} />
                      <span className="rq-meta-text mono">
                        old heads: {c.old_heads_remaining} / unknown attempts:{" "}
                        {c.unknown_attempts_remaining}
                      </span>
                    </div>
                  )
                },
                {
                  key: "actions",
                  header: "Cutover Transitions",
                  render: (c) => (
                    <div className="rq-row">
                      {c.state === "proposed" ? (
                        <button
                          type="button"
                          className="rq-btn"
                          onClick={() => {
                            openCutoverMutation(c, "begin");
                          }}
                        >
                          Begin Drain
                        </button>
                      ) : null}
                      {c.state === "ready" ? (
                        <button
                          type="button"
                          className="rq-btn rq-btn-primary"
                          onClick={() => {
                            openCutoverMutation(c, "activate");
                          }}
                        >
                          Activate Target (Step-Up)
                        </button>
                      ) : null}
                      {c.state === "proposed" || c.state === "draining" || c.state === "ready" ? (
                        <button
                          type="button"
                          className="rq-btn rq-btn-danger"
                          onClick={() => {
                            openCutoverMutation(c, "abort");
                          }}
                        >
                          Abort
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
