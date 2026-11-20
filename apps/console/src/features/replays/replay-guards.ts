import {
  type CapabilityAction,
  type CapabilityEntryDto,
  type DeliverySummaryDto,
  isCapabilityAvailable
} from "@relayquill/contracts";
import { type ProposalState } from "@relayquill/domain";

export interface ReviewerEligibilityInput {
  readonly proposalState: ProposalState;
  readonly proposerPrincipalId: string;
  readonly currentPrincipalId: string;
  readonly capabilities?: readonly CapabilityEntryDto[] | undefined;
  readonly reviewAction: CapabilityAction;
  readonly admitAction: CapabilityAction;
  readonly withdrawAction?: CapabilityAction | undefined;
}

export interface ReviewerEligibilityResult {
  readonly distinctReviewerSatisfied: boolean;
  readonly canReview: boolean;
  readonly canAdmit: boolean;
  readonly canWithdraw: boolean;
  readonly blockReason: string | null;
}

/**
 * Enforces two-person governance in browser controls before offering review mutations:
 * a proposal's creator cannot approve or reject their own proposal (`proposer !== reviewer`).
 */
export function evaluateProposalReviewerEligibility(
  input: ReviewerEligibilityInput
): ReviewerEligibilityResult {
  const proposer = input.proposerPrincipalId.trim();
  const current = input.currentPrincipalId.trim();
  const distinctReviewerSatisfied =
    proposer.length > 0 && current.length > 0 && proposer !== current;

  const hasCapList = input.capabilities !== undefined && input.capabilities.length > 0;
  const reviewCapAllowed =
    !hasCapList || isCapabilityAvailable(input.capabilities, input.reviewAction);
  const admitCapAllowed =
    !hasCapList || isCapabilityAvailable(input.capabilities, input.admitAction);
  const withdrawCapAllowed =
    input.withdrawAction !== undefined &&
    (!hasCapList || isCapabilityAvailable(input.capabilities, input.withdrawAction));

  const canReview =
    input.proposalState === "proposed" && distinctReviewerSatisfied && reviewCapAllowed;
  const canAdmit = input.proposalState === "approved" && admitCapAllowed;
  const canWithdraw =
    (input.proposalState === "proposed" || input.proposalState === "approved") &&
    withdrawCapAllowed;

  let blockReason: string | null = null;
  if (input.proposalState === "proposed" && !distinctReviewerSatisfied) {
    blockReason =
      "Two-person governance requires a distinct reviewer (proposer !== current operator).";
  } else if (input.proposalState === "proposed" && !reviewCapAllowed) {
    blockReason = "Current project role does not hold review capability for this proposal.";
  } else if (input.proposalState === "approved" && !admitCapAllowed) {
    blockReason = "Current project role does not hold admission capability for this proposal.";
  }

  return {
    distinctReviewerSatisfied,
    canReview,
    canAdmit,
    canWithdraw,
    blockReason
  };
}

export interface ReplayCandidateDiffRow {
  readonly field: string;
  readonly sourceValue: string;
  readonly proposedValue: string;
  readonly changed: boolean;
}

export function buildReplayCandidateDiffRows(input: {
  readonly sourceDelivery?: DeliverySummaryDto | undefined;
  readonly targetSubscriptionVersion: string;
  readonly targetEndpointVersion: string;
  readonly wireEnvelopeId: string;
  readonly requestedDeadlineAt: string;
  readonly strategy: string;
  readonly orderingStrategy: string;
  readonly candidateSha256: string;
}): readonly ReplayCandidateDiffRow[] {
  const src = input.sourceDelivery;
  const srcSub = src?.dispatch_subscription_version ?? "unknown";
  const srcEnd = src?.endpoint_version ?? "unknown";
  const srcWire = src?.wire_envelope_id ?? "unknown";
  const srcDeadline = src?.deadline_at ?? "unknown";

  return [
    {
      field: "Subscription Version",
      sourceValue: `v${srcSub}`,
      proposedValue: `v${input.targetSubscriptionVersion}`,
      changed: src !== undefined && srcSub !== input.targetSubscriptionVersion
    },
    {
      field: "Endpoint Version",
      sourceValue: `v${srcEnd}`,
      proposedValue: `v${input.targetEndpointVersion}`,
      changed: src !== undefined && srcEnd !== input.targetEndpointVersion
    },
    {
      field: "Wire Envelope ID",
      sourceValue: srcWire,
      proposedValue: input.wireEnvelopeId,
      changed: src !== undefined && srcWire !== input.wireEnvelopeId
    },
    {
      field: "Delivery Deadline",
      sourceValue: srcDeadline,
      proposedValue: input.requestedDeadlineAt,
      changed: src !== undefined && srcDeadline !== input.requestedDeadlineAt
    },
    {
      field: "Replay Strategy",
      sourceValue: src !== undefined ? (src.is_replay ? "replay" : "original") : "original",
      proposedValue: input.strategy,
      changed: true
    },
    {
      field: "Ordering Strategy",
      sourceValue: "original_slot",
      proposedValue: input.orderingStrategy,
      changed: true
    },
    {
      field: "Candidate SHA-256",
      sourceValue: src?.consumer_event_key_sha256 ?? "n/a",
      proposedValue: input.candidateSha256,
      changed: true
    }
  ];
}
