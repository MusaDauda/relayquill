import { type Temporal } from "@js-temporal/polyfill";
import { type DeliveryState, isTerminalDeliveryState } from "./delivery.js";
import {
  createEnumGuard,
  type ReplayOrderingStrategy,
  type ReplayStrategy
} from "./enums.js";
import {
  AuthorizationDomainError,
  ConflictDomainError,
  ExpiredDomainError
} from "./errors.js";
import {
  type AttemptId,
  type DeliveryId,
  type PrincipalId,
  type Sha256Hex
} from "./ids.js";
import { assertTransition, type TransitionMatrix } from "./state-machine.js";
import { addMilliseconds, compareInstants } from "./time.js";

export const PROPOSAL_STATES = [
  "proposed",
  "approved",
  "admitted",
  "rejected",
  "expired",
  "revoked"
] as const;
export type ProposalState = (typeof PROPOSAL_STATES)[number];
export const isProposalState = createEnumGuard(PROPOSAL_STATES);

export const PROPOSAL_REVIEW_DECISIONS = ["approve", "reject"] as const;
export type ProposalReviewDecision = (typeof PROPOSAL_REVIEW_DECISIONS)[number];
export const isProposalReviewDecision = createEnumGuard(PROPOSAL_REVIEW_DECISIONS);

export const SUPPRESSION_ADMIT_OUTCOMES = ["suppressed", "already_terminal"] as const;
export type SuppressionAdmitOutcome = (typeof SUPPRESSION_ADMIT_OUTCOMES)[number];

export const PROPOSAL_TTL_MS = 900_000n;

export const ALLOWED_PROPOSAL_TRANSITIONS: TransitionMatrix<ProposalState> = Object.freeze({
  proposed: ["approved", "rejected", "expired", "revoked"],
  approved: ["admitted", "expired", "revoked"],
  admitted: [],
  rejected: [],
  expired: [],
  revoked: []
});

export function isTerminalProposalState(state: ProposalState): boolean {
  return (
    state === "admitted" ||
    state === "rejected" ||
    state === "expired" ||
    state === "revoked"
  );
}

export function computeProposalExpiresAt(createdAt: Temporal.Instant): Temporal.Instant {
  return addMilliseconds(createdAt, PROPOSAL_TTL_MS, "proposal_expires_at");
}

export interface ProposalSnapshot {
  readonly proposalId: string;
  readonly state: ProposalState;
  readonly proposerPrincipalId: PrincipalId;
  readonly candidateSha256: Sha256Hex;
  readonly version: bigint;
  readonly expiresAt: Temporal.Instant;
}

export interface ProposalReviewInput {
  readonly reviewerPrincipalId: PrincipalId;
  readonly reviewerIsCurrentProjectAdmin: boolean;
  readonly decision: ProposalReviewDecision;
  readonly expectedCandidateSha256: Sha256Hex;
  readonly expectedVersion: bigint;
  readonly requiresContentReadGrant?: boolean | undefined;
  readonly proposerHasContentRead?: boolean | undefined;
  readonly reviewerHasContentRead?: boolean | undefined;
  readonly now: Temporal.Instant;
}

export function reviewProposal(
  proposal: ProposalSnapshot,
  input: ProposalReviewInput
): ProposalSnapshot {
  if (compareInstants(input.now, proposal.expiresAt) >= 0) {
    throw new ExpiredDomainError({
      code: "EXPIRED",
      message: "Proposal review window (15m) has expired",
      resourceRef: { kind: "proposal", id: proposal.proposalId }
    });
  }
  if (!input.reviewerIsCurrentProjectAdmin) {
    throw new AuthorizationDomainError({
      code: "FORBIDDEN",
      message: "Proposal reviewer must currently hold project_admin role",
      resourceRef: { kind: "proposal", id: proposal.proposalId }
    });
  }
  if (input.reviewerPrincipalId === proposal.proposerPrincipalId) {
    throw new AuthorizationDomainError({
      code: "FORBIDDEN",
      message: "Two-person review forbids self-approval or self-review by proposer",
      resourceRef: { kind: "proposal", id: proposal.proposalId }
    });
  }
  if (input.expectedCandidateSha256 !== proposal.candidateSha256) {
    throw new ConflictDomainError({
      code: "VERSION_CONFLICT",
      message: "Proposal candidate_sha256 mismatch",
      resourceRef: { kind: "proposal", id: proposal.proposalId }
    });
  }
  if (input.expectedVersion !== proposal.version) {
    throw new ConflictDomainError({
      code: "VERSION_CONFLICT",
      message: "Proposal version mismatch",
      resourceRef: { kind: "proposal", id: proposal.proposalId }
    });
  }
  if (input.requiresContentReadGrant) {
    if (!input.proposerHasContentRead || !input.reviewerHasContentRead) {
      throw new AuthorizationDomainError({
        code: "FORBIDDEN",
        message: "Both proposer and reviewer require active events.content.read grant",
        resourceRef: { kind: "proposal", id: proposal.proposalId }
      });
    }
  }

  const targetState: ProposalState = input.decision === "approve" ? "approved" : "rejected";
  assertTransition("proposal", ALLOWED_PROPOSAL_TRANSITIONS, proposal.state, targetState, {
    kind: "proposal",
    id: proposal.proposalId
  });

  return Object.freeze({
    ...proposal,
    state: targetState,
    version: proposal.version + 1n
  });
}

export interface ReplayProposalAdmissionInput {
  readonly proposal: ProposalSnapshot;
  readonly strategy: ReplayStrategy;
  readonly orderingStrategy: ReplayOrderingStrategy;
  readonly destinationChanged: boolean;
  readonly strictPerKeyOrdering: boolean;
  readonly proposerHasContentRead: boolean;
  readonly reviewerHasContentRead: boolean;
  readonly expectedCandidateSha256: Sha256Hex;
  readonly expectedVersion: bigint;
  readonly now: Temporal.Instant;
}

export function admitReplayProposal(input: ReplayProposalAdmissionInput): ProposalSnapshot {
  if (compareInstants(input.now, input.proposal.expiresAt) >= 0) {
    throw new ExpiredDomainError({
      code: "EXPIRED",
      message: "Replay proposal has expired before admission",
      resourceRef: { kind: "replay_proposal", id: input.proposal.proposalId }
    });
  }
  if (input.expectedCandidateSha256 !== input.proposal.candidateSha256) {
    throw new ConflictDomainError({
      code: "VERSION_CONFLICT",
      message: "Replay proposal candidate_sha256 mismatch",
      resourceRef: { kind: "replay_proposal", id: input.proposal.proposalId }
    });
  }
  if (input.expectedVersion !== input.proposal.version) {
    throw new ConflictDomainError({
      code: "VERSION_CONFLICT",
      message: "Replay proposal version mismatch",
      resourceRef: { kind: "replay_proposal", id: input.proposal.proposalId }
    });
  }
  if (
    input.destinationChanged ||
    input.strategy === "replay_with_reviewed_representation"
  ) {
    if (!input.proposerHasContentRead || !input.reviewerHasContentRead) {
      throw new AuthorizationDomainError({
        code: "FORBIDDEN",
        message: "Changed destination or reviewed representation replay requires events.content.read on both proposer and reviewer",
        resourceRef: { kind: "replay_proposal", id: input.proposal.proposalId }
      });
    }
  }
  if (input.strictPerKeyOrdering && input.orderingStrategy !== "append_after_current_tail") {
    throw new ConflictDomainError({
      code: "STATE_TRANSITION_NOT_ALLOWED",
      message: "Strict per-key replay must use append_after_current_tail",
      resourceRef: { kind: "replay_proposal", id: input.proposal.proposalId }
    });
  }
  assertTransition(
    "replay_proposal",
    ALLOWED_PROPOSAL_TRANSITIONS,
    input.proposal.state,
    "admitted",
    { kind: "replay_proposal", id: input.proposal.proposalId }
  );
  return Object.freeze({
    ...input.proposal,
    state: "admitted",
    version: input.proposal.version + 1n
  });
}

export interface SuppressionDeliveryTarget {
  readonly deliveryId: DeliveryId;
  readonly state: DeliveryState;
  readonly currentAttemptId: AttemptId | null;
}

export interface SuppressionAdmissionResult {
  readonly outcome: SuppressionAdmitOutcome;
  readonly proposal: ProposalSnapshot;
  readonly nextDeliveryState: DeliveryState;
  readonly advancesStrictOrderingHead: false;
}

export function admitSuppressionProposal(
  proposal: ProposalSnapshot,
  delivery: SuppressionDeliveryTarget,
  input: {
    readonly expectedCandidateSha256: Sha256Hex;
    readonly expectedVersion: bigint;
    readonly now: Temporal.Instant;
  }
): SuppressionAdmissionResult {
  if (compareInstants(input.now, proposal.expiresAt) >= 0) {
    throw new ExpiredDomainError({
      code: "EXPIRED",
      message: "Suppression proposal has expired before admission",
      resourceRef: { kind: "suppression_proposal", id: proposal.proposalId }
    });
  }
  if (input.expectedCandidateSha256 !== proposal.candidateSha256) {
    throw new ConflictDomainError({
      code: "VERSION_CONFLICT",
      message: "Suppression proposal candidate_sha256 mismatch",
      resourceRef: { kind: "suppression_proposal", id: proposal.proposalId }
    });
  }
  if (input.expectedVersion !== proposal.version) {
    throw new ConflictDomainError({
      code: "VERSION_CONFLICT",
      message: "Suppression proposal version mismatch",
      resourceRef: { kind: "suppression_proposal", id: proposal.proposalId }
    });
  }

  assertTransition(
    "suppression_proposal",
    ALLOWED_PROPOSAL_TRANSITIONS,
    proposal.state,
    "admitted",
    { kind: "suppression_proposal", id: proposal.proposalId }
  );

  if (isTerminalDeliveryState(delivery.state)) {
    return Object.freeze({
      outcome: "already_terminal",
      proposal: Object.freeze({
        ...proposal,
        state: "admitted",
        version: proposal.version + 1n
      }),
      nextDeliveryState: delivery.state,
      advancesStrictOrderingHead: false
    });
  }

  if (
    (delivery.state !== "pending" &&
      delivery.state !== "ready" &&
      delivery.state !== "retry_wait") ||
    delivery.currentAttemptId !== null
  ) {
    throw new ConflictDomainError({
      code: "STATE_TRANSITION_NOT_ALLOWED",
      message: "Suppression requires pending, ready, or retry_wait delivery with no active attempt",
      resourceRef: { kind: "delivery", id: delivery.deliveryId }
    });
  }

  return Object.freeze({
    outcome: "suppressed",
    proposal: Object.freeze({
      ...proposal,
      state: "admitted",
      version: proposal.version + 1n
    }),
    nextDeliveryState: "suppressed",
    advancesStrictOrderingHead: false
  });
}
