import { type JSX, useMemo, useState } from "react";
import {
  type DeliverySummaryDto,
  type ReplayProposalDto,
  type SuppressionProposalDto,
  hashCanonicalJson,
  isCapabilityAvailable
} from "@relayquill/contracts";
import {
  DELIVERY_OUTCOME_CLASSES,
  DELIVERY_POPULATIONS,
  type DeliveryPopulation,
  PROPOSAL_STATES,
  type ProposalReviewDecision,
  REPLAY_ORDERING_STRATEGIES,
  REPLAY_STRATEGIES,
  type ReplayOrderingStrategy,
  type ReplayStrategy
} from "@relayquill/domain";
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
import {
  buildReplayCandidateDiffRows,
  evaluateProposalReviewerEligibility
} from "./replay-guards.js";

type ReplaysTab = "dead_letter" | "replay_proposals" | "suppressions";

export function ReplaysPage(): JSX.Element {
  const { navigate } = useConsoleRouter();
  const { api, session } = useConsoleRuntime();
  const scope = useActiveScope();

  const [activeTab, setActiveTab] = useState<ReplaysTab>("dead_letter");
  const [endpointFilter, setEndpointFilter] = useState("");
  const [outcomeFilter, setOutcomeFilter] = useState("");
  const [populationFilter, setPopulationFilter] = useState<DeliveryPopulation>("original");
  const [proposalStateFilter, setProposalStateFilter] = useState("");
  const [pageSize, setPageSize] = useState<25 | 100>(25);
  const [cursorStack, setCursorStack] = useState<readonly (string | null)[]>([null]);

  const [selectedDeadLetter, setSelectedDeadLetter] = useState<DeliverySummaryDto | null>(null);
  const [selectedReplayProposal, setSelectedReplayProposal] =
    useState<ReplayProposalDto | null>(null);

  // Proposal creation fields
  const [replayStrategy, setReplayStrategy] =
    useState<ReplayStrategy>("replay_exact_original");
  const [orderingStrategy, setOrderingStrategy] = useState<ReplayOrderingStrategy>(
    "append_after_current_tail"
  );
  const [targetSubscriptionVersion, setTargetSubscriptionVersion] = useState("1");
  const [targetEndpointVersion, setTargetEndpointVersion] = useState("1");
  const [wireEnvelopeId, setWireEnvelopeId] = useState("");
  const [requestedDeadlineAt, setRequestedDeadlineAt] = useState(() =>
    new Date(Date.now() + 24 * 3600 * 1000).toISOString().replace(/\.\d{3}Z$/, "Z")
  );
  const [profileId, setProfileId] = useState("");
  const [profileVersion, setProfileVersion] = useState("");
  const [receiverContractId, setReceiverContractId] = useState("");
  const [receiverContractVersion, setReceiverContractVersion] = useState("");
  const [evidenceInput, setEvidenceInput] = useState("incident-triage-ref");
  const [reasonCode, setReasonCode] = useState("dead_letter_operator_replay");
  const [reviewIdInput, setReviewIdInput] = useState("");
  const [feedback, setFeedback] = useState<MutationFeedbackState>({ kind: "idle" });

  const [pendingStepUp, setPendingStepUp] = useState<{
    readonly descriptor: StepUpTargetDescriptor;
    readonly execute: (operationProofId: string) => Promise<void>;
  } | null>(null);

  const currentCursor = cursorStack[cursorStack.length - 1] ?? null;
  const currentPrincipalId = session?.principal_id ?? scope.principalId;

  const deadLettersQuery = useScopedQuery({
    resource: "project.dead_letter_deliveries",
    enabled: activeTab === "dead_letter" || selectedReplayProposal !== null,
    filter: { endpointFilter, outcomeFilter, populationFilter, pageSize, cursor: currentCursor },
    isEmpty: (d) => d.items.length === 0,
    fetcher: (signal: AbortSignal) =>
      api.listDeliveries(
        scope.tenantId,
        scope.projectId,
        {
          state: "dead_letter",
          population: populationFilter,
          ...(endpointFilter.trim().length > 0 ? { endpoint_id: endpointFilter.trim() } : {}),
          ...(outcomeFilter.trim().length > 0 ? { outcome_class: outcomeFilter.trim() } : {}),
          limit: pageSize,
          cursor: currentCursor
        },
        signal
      )
  });

  const replayProposalsQuery = useScopedQuery({
    resource: "project.replay_proposals",
    enabled: activeTab === "replay_proposals",
    filter: { proposalStateFilter, pageSize, cursor: currentCursor },
    isEmpty: (d) => d.items.length === 0,
    fetcher: (signal: AbortSignal) =>
      api.listReplayProposals(
        scope.tenantId,
        scope.projectId,
        {
          ...(proposalStateFilter.trim().length > 0
            ? { state: proposalStateFilter.trim() }
            : {}),
          limit: pageSize,
          cursor: currentCursor
        },
        signal
      )
  });

  const suppressionsQuery = useScopedQuery({
    resource: "project.suppression_proposals",
    enabled: activeTab === "suppressions",
    filter: { pageSize, cursor: currentCursor },
    isEmpty: (d) => d.items.length === 0,
    fetcher: (signal: AbortSignal) =>
      api.listSuppressionProposals(
        scope.tenantId,
        scope.projectId,
        { limit: pageSize, cursor: currentCursor },
        signal
      )
  });

  const beginReplayComposer = (delivery: DeliverySummaryDto): void => {
    setSelectedDeadLetter(delivery);
    setTargetSubscriptionVersion(delivery.dispatch_subscription_version);
    setTargetEndpointVersion(delivery.endpoint_version);
    setWireEnvelopeId(delivery.wire_envelope_id);
  };

  const handleProposeReplay = async (): Promise<void> => {
    if (selectedDeadLetter === null) {
      return;
    }
    const evidenceReferences = evidenceInput
      .split(",")
      .map((s) => s.trim())
      .filter((s) => s.length > 0);
    const body: Record<string, unknown> = {
      schema_version: 1,
      expected_delivery_version: selectedDeadLetter.current_version,
      target_subscription_version: targetSubscriptionVersion.trim(),
      target_endpoint_version: targetEndpointVersion.trim(),
      wire_envelope_id: wireEnvelopeId.trim() || selectedDeadLetter.wire_envelope_id,
      strategy: replayStrategy,
      ordering_strategy: orderingStrategy,
      requested_deadline_at: requestedDeadlineAt.trim(),
      consumer_event_key_sha256: selectedDeadLetter.consumer_event_key_sha256,
      evidence_references: evidenceReferences.length > 0 ? evidenceReferences : ["console-triage"],
      reason_code: reasonCode.trim() || "dead_letter_operator_replay"
    };
    if (replayStrategy === "replay_with_reviewed_representation") {
      body.representation_profile_id = profileId.trim();
      body.representation_profile_version = profileVersion.trim();
      body.receiver_contract_id = receiverContractId.trim();
      body.receiver_contract_version = receiverContractVersion.trim();
    }

    setFeedback({ kind: "submitting", label: "Submitting two-person replay proposal..." });
    const res = await api.createReplayProposal(
      scope.tenantId,
      scope.projectId,
      selectedDeadLetter.delivery_id,
      body,
      generateIdempotencyKey("replay-propose")
    );
    if (!res.ok) {
      setFeedback({
        kind: "failed",
        error: res,
        preservedDraft: body,
        currentServerState: selectedDeadLetter
      });
      return;
    }
    setFeedback({
      kind: "succeeded",
      title: "Replay Proposal Created",
      detail: `Proposal ${res.data.proposal_id} queued for independent second-operator review.`
    });
    setSelectedReplayProposal(res.data);
    setActiveTab("replay_proposals");
    replayProposalsQuery.reload();
  };

  const handleProposeSuppression = async (delivery: DeliverySummaryDto): Promise<void> => {
    const evidenceReferences = evidenceInput
      .split(",")
      .map((s) => s.trim())
      .filter((s) => s.length > 0);
    const body = {
      schema_version: 1,
      expected_delivery_version: delivery.current_version,
      prior_outcome_class: delivery.last_outcome_class,
      evidence_references: evidenceReferences.length > 0 ? evidenceReferences : ["console-triage"],
      reason_code: reasonCode.trim() || "dead_letter_suppression"
    };
    setFeedback({ kind: "submitting", label: "Submitting suppression proposal..." });
    const res = await api.createSuppressionProposal(
      scope.tenantId,
      scope.projectId,
      delivery.delivery_id,
      body,
      generateIdempotencyKey("suppress-propose")
    );
    if (!res.ok) {
      setFeedback({ kind: "failed", error: res, preservedDraft: body });
      return;
    }
    setFeedback({
      kind: "succeeded",
      title: "Suppression Proposal Created",
      detail: `Suppression proposal ${res.data.proposal_id} awaits distinct-reviewer approval.`
    });
    setActiveTab("suppressions");
    suppressionsQuery.reload();
  };

  const openReplayStepUpAction = (
    proposal: ReplayProposalDto,
    mode: "review_approve" | "review_reject" | "admit" | "withdraw"
  ): void => {
    const evidenceReferences = evidenceInput
      .split(",")
      .map((s) => s.trim())
      .filter((s) => s.length > 0);

    if (mode === "review_approve" || mode === "review_reject") {
      const decision: ProposalReviewDecision = mode === "review_approve" ? "approve" : "reject";
      const payload = {
        schema_version: 1,
        expected_proposal_version: proposal.version,
        candidate_sha256: proposal.candidate_sha256,
        decision,
        evidence_references:
          evidenceReferences.length > 0 ? evidenceReferences : ["independent-console-review"],
        reason_code: reasonCode.trim() || `replay_${decision}`
      };
      const canonical = hashCanonicalJson(payload);
      setPendingStepUp({
        descriptor: {
          action: "replay_proposals.review",
          actionLabel: `${decision === "approve" ? "Approve" : "Reject"} Replay Proposal`,
          scopeKind: "project",
          tenantId: scope.tenantId,
          projectId: scope.projectId,
          targetResourceId: proposal.proposal_id,
          targetVersion: proposal.version,
          canonicalCommandSha256: canonical.sha256,
          summary: `${decision.toUpperCase()} replay proposal ${proposal.proposal_id} for delivery ${proposal.source_delivery_id}. Candidate SHA-256 ${proposal.candidate_sha256.slice(0, 16)}...`
        },
        execute: async (operationProofId: string) => {
          setFeedback({ kind: "submitting", label: `Submitting replay review (${decision})...` });
          const res = await api.reviewReplayProposal(
            scope.tenantId,
            scope.projectId,
            proposal.proposal_id,
            { ...payload, operation_proof_id: operationProofId },
            generateIdempotencyKey("replay-review")
          );
          if (!res.ok) {
            setFeedback({
              kind: "failed",
              error: res,
              preservedDraft: payload,
              currentServerState: proposal
            });
            return;
          }
          setFeedback({
            kind: "succeeded",
            title: `Replay Proposal ${decision === "approve" ? "Approved" : "Rejected"}`,
            detail: `Independent two-person review recorded for ${proposal.proposal_id}.`,
            receiptId: res.data.receipt?.id
          });
          replayProposalsQuery.reload();
        }
      });
      return;
    }

    if (mode === "admit") {
      const payload = {
        schema_version: 1,
        expected_proposal_version: proposal.version,
        candidate_sha256: proposal.candidate_sha256,
        review_id: reviewIdInput.trim(),
        reason_code: reasonCode.trim() || "admit_approved_replay"
      };
      const canonical = hashCanonicalJson(payload);
      setPendingStepUp({
        descriptor: {
          action: "replay_proposals.admit",
          actionLabel: "Admit Approved Replay Generation",
          scopeKind: "project",
          tenantId: scope.tenantId,
          projectId: scope.projectId,
          targetResourceId: proposal.proposal_id,
          targetVersion: proposal.version,
          canonicalCommandSha256: canonical.sha256,
          summary: `Admits new replay delivery generation from approved proposal ${proposal.proposal_id}.`
        },
        execute: async (operationProofId: string) => {
          setFeedback({ kind: "submitting", label: "Admitting replay generation..." });
          const res = await api.admitReplayProposal(
            scope.tenantId,
            scope.projectId,
            proposal.proposal_id,
            { ...payload, operation_proof_id: operationProofId },
            generateIdempotencyKey("replay-admit")
          );
          if (!res.ok) {
            setFeedback({
              kind: "failed",
              error: res,
              preservedDraft: payload,
              currentServerState: proposal
            });
            return;
          }
          setFeedback({
            kind: "succeeded",
            title: "Replay Generation Admitted",
            detail: `Created new replay delivery generation for proposal ${proposal.proposal_id}.`,
            receiptId: res.data.receipt?.id
          });
          replayProposalsQuery.reload();
        }
      });
      return;
    }

    // Withdraw
    const withdrawPayload = {
      schema_version: 1,
      expected_proposal_version: proposal.version,
      reason_code: reasonCode.trim() || "operator_withdraw_replay"
    };
    const canonical = hashCanonicalJson(withdrawPayload);
    setPendingStepUp({
      descriptor: {
        action: "replay_proposals.withdraw",
        actionLabel: "Withdraw Replay Proposal",
        scopeKind: "project",
        tenantId: scope.tenantId,
        projectId: scope.projectId,
        targetResourceId: proposal.proposal_id,
        targetVersion: proposal.version,
        canonicalCommandSha256: canonical.sha256,
        summary: `Withdraws replay proposal ${proposal.proposal_id} before admission.`
      },
      execute: async (operationProofId: string) => {
        setFeedback({ kind: "submitting", label: "Withdrawing replay proposal..." });
        const res = await api.withdrawReplayProposal(
          scope.tenantId,
          scope.projectId,
          proposal.proposal_id,
          { ...withdrawPayload, operation_proof_id: operationProofId },
          generateIdempotencyKey("replay-withdraw")
        );
        if (!res.ok) {
          setFeedback({ kind: "failed", error: res, currentServerState: proposal });
          return;
        }
        setFeedback({
          kind: "succeeded",
          title: "Replay Proposal Withdrawn",
          detail: `Proposal ${proposal.proposal_id} marked revoked.`,
          receiptId: res.data.receipt?.id
        });
        replayProposalsQuery.reload();
      }
    });
  };

  const openSuppressionStepUp = (
    proposal: SuppressionProposalDto,
    action: "reviews" | "admit",
    decision?: ProposalReviewDecision
  ): void => {
    const payload =
      action === "reviews"
        ? {
            schema_version: 1,
            expected_proposal_version: proposal.version,
            candidate_sha256: proposal.candidate_sha256,
            decision: decision ?? "approve",
            evidence_references: ["independent-console-review"],
            reason_code: reasonCode.trim() || `suppression_${decision ?? "approve"}`
          }
        : {
            schema_version: 1,
            expected_proposal_version: proposal.version,
            candidate_sha256: proposal.candidate_sha256,
            review_id: reviewIdInput.trim(),
            reason_code: reasonCode.trim() || "admit_approved_suppression"
          };
    const canonical = hashCanonicalJson(payload);
    setPendingStepUp({
      descriptor: {
        action: action === "reviews" ? "suppression_proposals.review" : "suppression_proposals.admit",
        actionLabel:
          action === "reviews"
            ? `${decision === "reject" ? "Reject" : "Approve"} Suppression Proposal`
            : "Admit Suppression Proposal",
        scopeKind: "project",
        tenantId: scope.tenantId,
        projectId: scope.projectId,
        targetResourceId: proposal.proposal_id,
        targetVersion: proposal.version,
        canonicalCommandSha256: canonical.sha256,
        summary: `Executes ${action} on suppression proposal ${proposal.proposal_id}. Strict ordering heads never advance via suppression.`
      },
      execute: async (operationProofId: string) => {
        setFeedback({ kind: "submitting", label: `Executing suppression ${action}...` });
        const res = await api.reviewOrAdmitSuppressionProposal(
          scope.tenantId,
          scope.projectId,
          proposal.proposal_id,
          action,
          { ...payload, operation_proof_id: operationProofId },
          generateIdempotencyKey(`suppress-${action}`)
        );
        if (!res.ok) {
          setFeedback({ kind: "failed", error: res, currentServerState: proposal });
          return;
        }
        setFeedback({
          kind: "succeeded",
          title: "Suppression Mutation Recorded",
          detail: `Updated suppression proposal ${proposal.proposal_id}.`,
          receiptId: res.data.receipt?.id
        });
        suppressionsQuery.reload();
      }
    });
  };

  const diffRows = useMemo(() => {
    if (selectedReplayProposal === null) {
      return [];
    }
    const matchingDelivery =
      deadLettersQuery.view.state === "current"
        ? deadLettersQuery.view.data.items.find(
            (d) => d.delivery_id === selectedReplayProposal.source_delivery_id
          )
        : undefined;
    return buildReplayCandidateDiffRows({
      sourceDelivery: matchingDelivery,
      targetSubscriptionVersion: selectedReplayProposal.target_subscription_version,
      targetEndpointVersion: selectedReplayProposal.target_endpoint_version,
      wireEnvelopeId: selectedReplayProposal.wire_envelope_id,
      requestedDeadlineAt: selectedReplayProposal.requested_deadline_at,
      strategy: selectedReplayProposal.strategy,
      orderingStrategy: selectedReplayProposal.ordering_strategy,
      candidateSha256: selectedReplayProposal.candidate_sha256
    });
  }, [deadLettersQuery.view, selectedReplayProposal]);

  return (
    <div className="rq-stack">
      <header className="rq-page-header">
        <div>
          <h1 className="rq-page-title">Dead-Letter Triage, Two-Person Replays & Suppressions</h1>
          <p className="rq-page-lead">
            Triage dead-lettered deliveries, inspect candidate configuration diffs, and enforce
            distinct-reviewer (<span className="kbd-chip">proposer !== reviewer</span>) passkey
            step-up approvals before admitting replay generations.
          </p>
        </div>
      </header>

      <MutationFeedback state={feedback} resourceLabel="Replay / Suppression workflow" />

      <div className="rq-tabs" role="tablist" aria-label="Replay workflow views">
        <button
          type="button"
          role="tab"
          aria-selected={activeTab === "dead_letter"}
          className="rq-tab"
          onClick={() => {
            setActiveTab("dead_letter");
            setCursorStack([null]);
          }}
        >
          Dead-Letter Triage & Propose
        </button>
        <button
          type="button"
          role="tab"
          aria-selected={activeTab === "replay_proposals"}
          className="rq-tab"
          onClick={() => {
            setActiveTab("replay_proposals");
            setCursorStack([null]);
          }}
        >
          Replay Proposals & Review Diff
        </button>
        <button
          type="button"
          role="tab"
          aria-selected={activeTab === "suppressions"}
          className="rq-tab"
          onClick={() => {
            setActiveTab("suppressions");
            setCursorStack([null]);
          }}
        >
          Suppression Proposals
        </button>
      </div>

      {activeTab === "dead_letter" ? (
        <div className="rq-stack">
          <section className="rq-card" aria-label="Dead-letter triage filters">
            <div className="rq-grid-3">
              <FormField label="Endpoint ID">
                {({ inputId }) => (
                  <input
                    id={inputId}
                    className="rq-input mono"
                    placeholder="Canonical endpoint UUID"
                    value={endpointFilter}
                    onChange={(e) => {
                      setEndpointFilter(e.target.value);
                      setCursorStack([null]);
                    }}
                  />
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
                    <option value="">All dead-letter outcomes</option>
                    {DELIVERY_OUTCOME_CLASSES.map((oc) => (
                      <option key={oc} value={oc}>
                        {oc}
                      </option>
                    ))}
                  </select>
                )}
              </FormField>

              <FormField label="Delivery Population">
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
                    {DELIVERY_POPULATIONS.map((p) => (
                      <option key={p} value={p}>
                        {p}
                      </option>
                    ))}
                  </select>
                )}
              </FormField>
            </div>
          </section>

          {selectedDeadLetter !== null ? (
            <section className="rq-card" aria-label="Create replay proposal form">
              <div className="rq-card-header">
                <h2 className="rq-section-title">
                  Propose Two-Person Replay for Delivery {selectedDeadLetter.delivery_id}
                </h2>
                <button
                  type="button"
                  className="rq-btn"
                  onClick={() => {
                    setSelectedDeadLetter(null);
                  }}
                >
                  Close Composer
                </button>
              </div>
              <div className="rq-grid-2">
                <FormField label="Replay Strategy" required>
                  {({ inputId }) => (
                    <select
                      id={inputId}
                      className="rq-select"
                      value={replayStrategy}
                      onChange={(e) => {
                        setReplayStrategy(e.target.value as ReplayStrategy);
                      }}
                    >
                      {REPLAY_STRATEGIES.map((st) => (
                        <option key={st} value={st}>
                          {st}
                        </option>
                      ))}
                    </select>
                  )}
                </FormField>
                <FormField label="Ordering Strategy" required>
                  {({ inputId }) => (
                    <select
                      id={inputId}
                      className="rq-select"
                      value={orderingStrategy}
                      onChange={(e) => {
                        setOrderingStrategy(e.target.value as ReplayOrderingStrategy);
                      }}
                    >
                      {REPLAY_ORDERING_STRATEGIES.map((st) => (
                        <option key={st} value={st}>
                          {st}
                        </option>
                      ))}
                    </select>
                  )}
                </FormField>
                <FormField label="Target Subscription Version" required>
                  {({ inputId }) => (
                    <input
                      id={inputId}
                      className="rq-input mono"
                      value={targetSubscriptionVersion}
                      onChange={(e) => {
                        setTargetSubscriptionVersion(e.target.value);
                      }}
                    />
                  )}
                </FormField>
                <FormField label="Target Endpoint Version" required>
                  {({ inputId }) => (
                    <input
                      id={inputId}
                      className="rq-input mono"
                      value={targetEndpointVersion}
                      onChange={(e) => {
                        setTargetEndpointVersion(e.target.value);
                      }}
                    />
                  )}
                </FormField>
                <FormField label="Wire Envelope ID" required>
                  {({ inputId }) => (
                    <input
                      id={inputId}
                      className="rq-input mono"
                      value={wireEnvelopeId}
                      onChange={(e) => {
                        setWireEnvelopeId(e.target.value);
                      }}
                    />
                  )}
                </FormField>
                <FormField label="Requested Replay Deadline (UTC ISO)" required>
                  {({ inputId }) => (
                    <input
                      id={inputId}
                      className="rq-input mono"
                      value={requestedDeadlineAt}
                      onChange={(e) => {
                        setRequestedDeadlineAt(e.target.value);
                      }}
                    />
                  )}
                </FormField>
                <FormField label="Evidence References (comma separated)" required>
                  {({ inputId }) => (
                    <input
                      id={inputId}
                      className="rq-input mono"
                      value={evidenceInput}
                      onChange={(e) => {
                        setEvidenceInput(e.target.value);
                      }}
                    />
                  )}
                </FormField>
                <FormField label="Reason Code" required>
                  {({ inputId }) => (
                    <input
                      id={inputId}
                      className="rq-input mono"
                      value={reasonCode}
                      onChange={(e) => {
                        setReasonCode(e.target.value);
                      }}
                    />
                  )}
                </FormField>
              </div>

              {replayStrategy === "replay_with_reviewed_representation" ? (
                <div className="rq-grid-2">
                  <FormField label="Representation Profile ID" required>
                    {({ inputId }) => (
                      <input
                        id={inputId}
                        className="rq-input mono"
                        value={profileId}
                        onChange={(e) => {
                          setProfileId(e.target.value);
                        }}
                      />
                    )}
                  </FormField>
                  <FormField label="Representation Profile Version" required>
                    {({ inputId }) => (
                      <input
                        id={inputId}
                        className="rq-input mono"
                        value={profileVersion}
                        onChange={(e) => {
                          setProfileVersion(e.target.value);
                        }}
                      />
                    )}
                  </FormField>
                  <FormField label="Receiver Contract ID" required>
                    {({ inputId }) => (
                      <input
                        id={inputId}
                        className="rq-input mono"
                        value={receiverContractId}
                        onChange={(e) => {
                          setReceiverContractId(e.target.value);
                        }}
                      />
                    )}
                  </FormField>
                  <FormField label="Receiver Contract Version" required>
                    {({ inputId }) => (
                      <input
                        id={inputId}
                        className="rq-input mono"
                        value={receiverContractVersion}
                        onChange={(e) => {
                          setReceiverContractVersion(e.target.value);
                        }}
                      />
                    )}
                  </FormField>
                </div>
              ) : null}

              <div className="rq-row">
                <button
                  type="button"
                  className="rq-btn rq-btn-primary"
                  disabled={
                    !isCapabilityAvailable(
                      selectedDeadLetter.capabilities ?? [],
                      "deliveries.replay.propose"
                    ) && (selectedDeadLetter.capabilities?.length ?? 0) > 0
                  }
                  onClick={() => {
                    void handleProposeReplay();
                  }}
                >
                  Create Replay Proposal
                </button>
              </div>
            </section>
          ) : null}

          <ResourceStatePanel
            view={deadLettersQuery.view}
            resourceLabel="Dead-letter deliveries"
            emptyTitle="No dead-lettered deliveries match your triage filters"
            onRetry={deadLettersQuery.reload}
          >
            {(dlPage) => (
              <section className="rq-card" aria-label="Dead-letter queue table">
                <DataTable<DeliverySummaryDto>
                  caption="Dead-lettered deliveries"
                  rows={dlPage.items}
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
                      (dlPage.page.has_more ?? dlPage.page.next_cursor !== null) &&
                      dlPage.page.next_cursor !== null,
                    onPrev: () => {
                      setCursorStack((prev) => (prev.length > 1 ? prev.slice(0, -1) : prev));
                    },
                    onNext: () => {
                      if (dlPage.page.next_cursor !== null) {
                        const c = dlPage.page.next_cursor;
                        setCursorStack((prev) => [...prev, c]);
                      }
                    }
                  }}
                  columns={[
                    {
                      key: "delivery",
                      header: "Delivery & Event",
                      render: (d) => (
                        <div className="rq-stack-sm">
                          <CopyableId value={d.delivery_id} />
                          <span className="rq-meta-text mono">event: {d.event_id}</span>
                        </div>
                      )
                    },
                    {
                      key: "outcome",
                      header: "Outcome & Error",
                      render: (d) => (
                        <div className="rq-stack-sm">
                          <StatusBadge status={d.state} />
                          <span className="mono">
                            {d.last_outcome_class ?? "unknown"} / HTTP{" "}
                            {d.latest_response_summary?.response_status ?? "none"}
                          </span>
                        </div>
                      )
                    },
                    {
                      key: "actions",
                      header: "Triage Actions",
                      render: (d) => (
                        <div className="rq-row">
                          <button
                            type="button"
                            className="rq-btn rq-btn-primary"
                            onClick={() => {
                              beginReplayComposer(d);
                            }}
                          >
                            Propose Replay
                          </button>
                          <button
                            type="button"
                            className="rq-btn"
                            onClick={() => {
                              void handleProposeSuppression(d);
                            }}
                          >
                            Propose Suppression
                          </button>
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
                            Inspect Evidence
                          </button>
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

      {activeTab === "replay_proposals" ? (
        <div className="rq-stack">
          <section className="rq-card" aria-label="Replay proposal filter and approval params">
            <div className="rq-grid-3">
              <FormField label="Proposal State">
                {({ inputId }) => (
                  <select
                    id={inputId}
                    className="rq-select"
                    value={proposalStateFilter}
                    onChange={(e) => {
                      setProposalStateFilter(e.target.value);
                      setCursorStack([null]);
                    }}
                  >
                    <option value="">All proposal states</option>
                    {PROPOSAL_STATES.map((st) => (
                      <option key={st} value={st}>
                        {st}
                      </option>
                    ))}
                  </select>
                )}
              </FormField>

              <FormField
                label="Review ID (for Admitting Approved Proposals)"
                helpText="Required when admitting an already-approved replay proposal."
              >
                {({ inputId }) => (
                  <input
                    id={inputId}
                    className="rq-input mono"
                    placeholder="Approved review UUID"
                    value={reviewIdInput}
                    onChange={(e) => {
                      setReviewIdInput(e.target.value);
                    }}
                  />
                )}
              </FormField>

              <FormField label="Review / Admit Reason Code">
                {({ inputId }) => (
                  <input
                    id={inputId}
                    className="rq-input mono"
                    value={reasonCode}
                    onChange={(e) => {
                      setReasonCode(e.target.value);
                    }}
                  />
                )}
              </FormField>
            </div>
          </section>

          {selectedReplayProposal !== null ? (
            <section className="rq-card" aria-label="Replay candidate comparison diff">
              <div className="rq-card-header">
                <h2 className="rq-section-title">
                  Proposal Diff & Distinct-Reviewer Inspection
                </h2>
                <StatusBadge status={selectedReplayProposal.state} />
              </div>
              <div className="rq-diff-grid">
                <div className="rq-card-inset">
                  <strong className="rq-label">Governance Check</strong>
                  <p className="rq-meta-text">
                    Proposer: <span className="mono">{selectedReplayProposal.proposer_principal_id}</span>
                  </p>
                  <p className="rq-meta-text">
                    Current Reviewer: <span className="mono">{currentPrincipalId}</span>
                  </p>
                  {(() => {
                    const eligibility = evaluateProposalReviewerEligibility({
                      proposalState: selectedReplayProposal.state,
                      proposerPrincipalId: selectedReplayProposal.proposer_principal_id,
                      currentPrincipalId,
                      capabilities: selectedReplayProposal.capabilities,
                      reviewAction: "replay_proposals.review",
                      admitAction: "replay_proposals.admit",
                      withdrawAction: "replay_proposals.withdraw"
                    });
                    return (
                      <div className="rq-stack-sm">
                        <StatusBadge
                          status={eligibility.distinctReviewerSatisfied ? "active" : "blocked"}
                          label={
                            eligibility.distinctReviewerSatisfied
                              ? "Distinct Reviewer Satisfied"
                              : "Same Principal Blocked (proposer === reviewer)"
                          }
                        />
                        {eligibility.blockReason !== null ? (
                          <p className="rq-field-error" role="status">
                            {eligibility.blockReason}
                          </p>
                        ) : null}
                      </div>
                    );
                  })()}
                </div>

                <div className="rq-card-inset">
                  <strong className="rq-label">Candidate Snapshot Comparison</strong>
                  <ul className="rq-timeline">
                    {diffRows.map((row) => (
                      <li key={row.field} className="rq-timeline-item">
                        <div className="rq-row-between">
                          <strong>{row.field}</strong>
                          <StatusBadge
                            status={row.changed ? "pending" : "active"}
                            label={row.changed ? "Changed" : "Unchanged"}
                          />
                        </div>
                        <span className="mono">Source: {row.sourceValue}</span>
                        <span className="mono">Proposed: {row.proposedValue}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              </div>
            </section>
          ) : null}

          <ResourceStatePanel
            view={replayProposalsQuery.view}
            resourceLabel="Replay proposals"
            emptyTitle="No replay proposals in this filter"
            onRetry={replayProposalsQuery.reload}
          >
            {(rpPage) => (
              <section className="rq-card" aria-label="Replay proposals table">
                <DataTable<ReplayProposalDto>
                  caption="Replay proposals"
                  rows={rpPage.items}
                  rowKey={(p) => p.proposal_id}
                  columns={[
                    {
                      key: "proposal",
                      header: "Proposal & Strategy",
                      render: (p) => (
                        <div className="rq-stack-sm">
                          <CopyableId value={p.proposal_id} />
                          <span className="rq-meta-text mono">
                            {p.strategy} ({p.ordering_strategy})
                          </span>
                        </div>
                      )
                    },
                    {
                      key: "proposer",
                      header: "Proposer & Candidate SHA-256",
                      render: (p) => (
                        <div className="rq-stack-sm">
                          <span className="mono">{p.proposer_principal_id}</span>
                          <span className="rq-meta-text mono">
                            sha={p.candidate_sha256.slice(0, 16)}...
                          </span>
                        </div>
                      )
                    },
                    {
                      key: "state",
                      header: "State & Expiry",
                      render: (p) => (
                        <div className="rq-stack-sm">
                          <StatusBadge status={p.state} />
                          <UtcTimestamp value={p.expires_at} showLocal={false} />
                        </div>
                      )
                    },
                    {
                      key: "actions",
                      header: "Two-Person Actions",
                      render: (p) => {
                        const eligibility = evaluateProposalReviewerEligibility({
                          proposalState: p.state,
                          proposerPrincipalId: p.proposer_principal_id,
                          currentPrincipalId,
                          capabilities: p.capabilities,
                          reviewAction: "replay_proposals.review",
                          admitAction: "replay_proposals.admit",
                          withdrawAction: "replay_proposals.withdraw"
                        });
                        return (
                          <div className="rq-row">
                            <button
                              type="button"
                              className="rq-btn"
                              onClick={() => {
                                setSelectedReplayProposal(p);
                              }}
                            >
                              Inspect Diff
                            </button>
                            <button
                              type="button"
                              className="rq-btn rq-btn-primary"
                              disabled={!eligibility.canReview}
                              title={eligibility.blockReason ?? undefined}
                              onClick={() => {
                                openReplayStepUpAction(p, "review_approve");
                              }}
                            >
                              Approve (Step-Up)
                            </button>
                            <button
                              type="button"
                              className="rq-btn rq-btn-danger"
                              disabled={!eligibility.canReview}
                              title={eligibility.blockReason ?? undefined}
                              onClick={() => {
                                openReplayStepUpAction(p, "review_reject");
                              }}
                            >
                              Reject (Step-Up)
                            </button>
                            {eligibility.canAdmit ? (
                              <button
                                type="button"
                                className="rq-btn rq-btn-primary"
                                disabled={reviewIdInput.trim().length === 0}
                                onClick={() => {
                                  openReplayStepUpAction(p, "admit");
                                }}
                              >
                                Admit Replay
                              </button>
                            ) : null}
                            {eligibility.canWithdraw ? (
                              <button
                                type="button"
                                className="rq-btn"
                                onClick={() => {
                                  openReplayStepUpAction(p, "withdraw");
                                }}
                              >
                                Withdraw
                              </button>
                            ) : null}
                          </div>
                        );
                      }
                    }
                  ]}
                />
              </section>
            )}
          </ResourceStatePanel>
        </div>
      ) : null}

      {activeTab === "suppressions" ? (
        <div className="rq-stack">
          <section className="rq-card-inset" role="note">
            <strong className="rq-label">Ordering Safety Guarantee</strong>
            <p className="rq-meta-text">
              Suppressing a delivery marks it permanently terminal without claiming consumer
              commit. Strict ordering heads never advance via suppression; ordered gaps require a
              separate reviewed <span className="kbd-chip">gap_skip</span> or{" "}
              <span className="kbd-chip">replay_append</span> decision.
            </p>
          </section>

          <ResourceStatePanel
            view={suppressionsQuery.view}
            resourceLabel="Suppression proposals"
            emptyTitle="No suppression proposals recorded"
            onRetry={suppressionsQuery.reload}
          >
            {(supPage) => (
              <section className="rq-card" aria-label="Suppression proposals table">
                <DataTable<SuppressionProposalDto>
                  caption="Suppression proposals"
                  rows={supPage.items}
                  rowKey={(s) => s.proposal_id}
                  columns={[
                    {
                      key: "id",
                      header: "Proposal & Delivery",
                      render: (s) => (
                        <div className="rq-stack-sm">
                          <CopyableId value={s.proposal_id} />
                          <span className="mono">delivery: {s.delivery_id}</span>
                        </div>
                      )
                    },
                    {
                      key: "proposer",
                      header: "Proposer & State",
                      render: (s) => (
                        <div className="rq-stack-sm">
                          <StatusBadge status={s.state} />
                          <span className="mono">{s.proposer_principal_id}</span>
                        </div>
                      )
                    },
                    {
                      key: "actions",
                      header: "Actions",
                      render: (s) => {
                        const eligibility = evaluateProposalReviewerEligibility({
                          proposalState: s.state,
                          proposerPrincipalId: s.proposer_principal_id,
                          currentPrincipalId,
                          capabilities: s.capabilities,
                          reviewAction: "suppression_proposals.review",
                          admitAction: "suppression_proposals.admit"
                        });
                        return (
                          <div className="rq-row">
                            <button
                              type="button"
                              className="rq-btn rq-btn-primary"
                              disabled={!eligibility.canReview}
                              title={eligibility.blockReason ?? undefined}
                              onClick={() => {
                                openSuppressionStepUp(s, "reviews", "approve");
                              }}
                            >
                              Approve (Step-Up)
                            </button>
                            <button
                              type="button"
                              className="rq-btn rq-btn-danger"
                              disabled={!eligibility.canReview}
                              title={eligibility.blockReason ?? undefined}
                              onClick={() => {
                                openSuppressionStepUp(s, "reviews", "reject");
                              }}
                            >
                              Reject (Step-Up)
                            </button>
                            {eligibility.canAdmit ? (
                              <button
                                type="button"
                                className="rq-btn rq-btn-primary"
                                disabled={reviewIdInput.trim().length === 0}
                                onClick={() => {
                                  openSuppressionStepUp(s, "admit");
                                }}
                              >
                                Admit Suppression
                              </button>
                            ) : null}
                          </div>
                        );
                      }
                    }
                  ]}
                />
              </section>
            )}
          </ResourceStatePanel>
        </div>
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
