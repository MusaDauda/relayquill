import test from "node:test";
import assert from "node:assert/strict";
import {
  ALLOWED_ORDERING_CUTOVER_TRANSITIONS,
  ALLOWED_SUBSCRIPTION_TRANSITIONS,
  AuthorizationDomainError,
  ConflictDomainError,
  ExpiredDomainError,
  InvariantViolationError,
  LimitExceededDomainError,
  RateLimitDomainError,
  UnsupportedStateTransitionError,
  ValidationDomainError,
  activateOrderingCutover,
  addMilliseconds,
  addSeconds,
  admitReplayProposal,
  admitSuppressionProposal,
  applySubscriptionControlAction,
  assertCanBeginVerificationAttempt,
  assertCanConsumeAuthChallenge,
  assertCanPrepareOrderedDelivery,
  assertCanSkipOrderingMember,
  assertContinuePublicationEpisodeAllowed,
  assertEstablishTargetEpochAllowed,
  assertInstallationStateInvariants,
  assertProducerChannelBinding,
  assertProducerCredentialTiming,
  assertProducerScopeBounds,
  assertRecoveryReviewAllowed,
  assertRetentionClaimBatchSize,
  assertRetireStaleClaimAllowed,
  assertSetRecoveryGateAllowed,
  assertSigningPolicyInvariants,
  assertStrictOrderingConfiguration,
  assertSubscriptionSchemaVersions,
  assertValidSubscriptionTopologyRange,
  assertWatchQuotaAvailable,
  beginOrderingCutover,
  canTransition,
  closeWatchLease,
  computeProposalExpiresAt,
  computeWatchLeaseExpiry,
  computeWatchStreamCutoff,
  enterRecoveryQuarantine,
  evaluateContentExpirationEligibility,
  evaluateReceiverOrderAcceptance,
  isHistoryRetirementEligible,
  isHumanSessionExpired,
  isTopologyVersionInRange,
  markOrderingCutoverReady,
  parseControlEpoch,
  parseDeliveryId,
  parseEndpointId,
  parseEndpointVerificationIntentId,
  parseOrderingCutoverPlanId,
  parseOrderingDomainId,
  parseOrderingKeyId,
  parsePrincipalId,
  parseProducerCredentialId,
  parseProducerNamespace,
  parseProjectId,
  parseRecoveryActionId,
  parseRetentionHoldId,
  parseSha256Hex,
  parseSigningKeyVersionId,
  parseSubscriptionId,
  parseUtcTimestamp,
  parseWatchLeaseId,
  quarantineEndpoint,
  renewWatchLease,
  resumeProjectAdmission,
  reviewProposal,
  validateExtractedOrderingKey
} from "@relayquill/domain";

const T0 = parseUtcTimestamp("2026-11-01T12:00:00.000000Z").instant;
const PROJECT_ID = parseProjectId("00000000-0000-4000-8000-000000000001");
const ORDERING_DOMAIN_ID = parseOrderingDomainId("00000000-0000-4000-8000-000000000002");
const ORDERING_KEY_ID = parseOrderingKeyId("00000000-0000-4000-8000-000000000003");
const CUTOVER_ID = parseOrderingCutoverPlanId("00000000-0000-4000-8000-000000000004");
const PROPOSER_ID = parsePrincipalId("00000000-0000-4000-8000-000000000005");
const REVIEWER_ID = parsePrincipalId("00000000-0000-4000-8000-000000000006");
const DELIVERY_ID = parseDeliveryId("00000000-0000-4000-8000-000000000007");
const HOLD_ID = parseRetentionHoldId("00000000-0000-4000-8000-000000000008");
const RECOVERY_ACTION_ID = parseRecoveryActionId("00000000-0000-4000-8000-000000000009");
const EPOCH_1 = parseControlEpoch("00000000-0000-4000-8000-000000000010");
const EPOCH_2 = parseControlEpoch("00000000-0000-4000-8000-000000000011");
const KEY_V1 = parseSigningKeyVersionId("00000000-0000-4000-8000-000000000012");
const KEY_V2 = parseSigningKeyVersionId("00000000-0000-4000-8000-000000000013");
const ENDPOINT_ID = parseEndpointId("00000000-0000-4000-8000-000000000014");
const VERIFY_INTENT_ID = parseEndpointVerificationIntentId("00000000-0000-4000-8000-000000000015");
const SUB_ID = parseSubscriptionId("00000000-0000-4000-8000-000000000016");
const CRED_ID = parseProducerCredentialId("00000000-0000-4000-8000-000000000017");
const WATCH_ID = parseWatchLeaseId("00000000-0000-4000-8000-000000000018");
const SHA_A = parseSha256Hex("c".repeat(64));
const SHA_B = parseSha256Hex("d".repeat(64));

test("Ordering guards enforce 128B key cap, head-only prep, skip rejection on send_started, and cutover barriers", () => {
  assert.equal(validateExtractedOrderingKey("k".repeat(128)), "k".repeat(128));
  assert.throws(() => validateExtractedOrderingKey("k".repeat(129)), ValidationDomainError);
  assertStrictOrderingConfiguration("strict_per_key", ORDERING_DOMAIN_ID, true);
  assert.throws(() => assertStrictOrderingConfiguration("strict_per_key", null, true), InvariantViolationError);

  assertCanPrepareOrderedDelivery({
    orderingKeyId: ORDERING_KEY_ID,
    orderingSequence: 2n,
    nextEligibleSequence: 2n,
    memberState: "eligible"
  });
  assert.throws(
    () =>
      assertCanPrepareOrderedDelivery({
        orderingKeyId: ORDERING_KEY_ID,
        orderingSequence: 3n,
        nextEligibleSequence: 2n,
        memberState: "waiting"
      }),
    ConflictDomainError
  );

  assert.throws(
    () =>
      assertCanSkipOrderingMember({
        orderingKeyId: ORDERING_KEY_ID,
        orderingSequence: 2n,
        nextEligibleSequence: 2n,
        memberState: "blocked",
        deliveryState: "sending",
        hasActiveSendStartedAttempt: true
      }),
    ConflictDomainError
  );

  const skip = assertCanSkipOrderingMember({
    orderingKeyId: ORDERING_KEY_ID,
    orderingSequence: 2n,
    nextEligibleSequence: 2n,
    memberState: "blocked",
    deliveryState: "dead_letter",
    hasActiveSendStartedAttempt: false
  });
  assert.equal(skip.decision, "reviewed_skip_without_processing_claim");
  assert.equal(skip.nextEligibleSequence, 3n);

  const plan = {
    planId: CUTOVER_ID,
    projectId: PROJECT_ID,
    state: "proposed",
    sourceConsumerScope: "orders.v1",
    targetConsumerScope: "orders.v1",
    boundaryProjectSequence: null,
    expiresAt: addSeconds(T0, 900)
  };
  const draining = beginOrderingCutover(plan, {
    activeProjectCutoverPlanId: null,
    currentProjectSequence: 10n,
    now: T0
  });
  assert.throws(
    () =>
      markOrderingCutoverReady(draining, {
        materializedThroughEventSequence: 9n,
        oldHeadsDrained: true,
        now: addSeconds(T0, 10)
      }),
    ConflictDomainError
  );
  assert.throws(
    () =>
      markOrderingCutoverReady(draining, {
        materializedThroughEventSequence: 10n,
        oldHeadsDrained: true,
        now: addSeconds(T0, 900)
      }),
    ExpiredDomainError
  );
  const ready = markOrderingCutoverReady(draining, {
    materializedThroughEventSequence: 10n,
    oldHeadsDrained: true,
    now: addSeconds(T0, 10)
  });
  assert.throws(
    () => activateOrderingCutover(ready, { now: addSeconds(T0, 900) }),
    ExpiredDomainError
  );
  assert.equal(canTransition(ALLOWED_ORDERING_CUTOVER_TRANSITIONS, "draining", "expired"), true);
  assert.equal(canTransition(ALLOWED_ORDERING_CUTOVER_TRANSITIONS, "ready", "expired"), true);
  const activated = activateOrderingCutover(ready, { now: addSeconds(T0, 20) });
  assert.equal(activated.state, "activated");

  const firstCommit = evaluateReceiverOrderAcceptance({
    headState: "active",
    nextExpectedSequence: 1n,
    incomingSequence: 1n,
    alreadyCommittedAtSequence: false,
    incomingMatchesCommittedAnchor: false
  });
  assert.equal(firstCommit.acceptanceKind, "first_business_commit");
  assert.equal(firstCommit.mutatesBusinessCounter, true);

  const dupCommit = evaluateReceiverOrderAcceptance({
    headState: "active",
    nextExpectedSequence: 2n,
    incomingSequence: 1n,
    alreadyCommittedAtSequence: true,
    incomingMatchesCommittedAnchor: true
  });
  assert.equal(dupCommit.acceptanceKind, "duplicate_business_anchor");
  assert.equal(dupCommit.mutatesBusinessCounter, false);

  assert.throws(
    () =>
      evaluateReceiverOrderAcceptance({
        headState: "active",
        nextExpectedSequence: 2n,
        incomingSequence: 4n,
        alreadyCommittedAtSequence: false,
        incomingMatchesCommittedAnchor: false
      }),
    ConflictDomainError
  );
});

test("Proposals enforce 15m TTL, two-person review, exact hash/version, content.read, and suppression rules", () => {
  const proposal = {
    proposalId: "00000000-0000-4000-8000-000000000050",
    state: "proposed",
    proposerPrincipalId: PROPOSER_ID,
    candidateSha256: SHA_A,
    version: 1n,
    expiresAt: computeProposalExpiresAt(T0)
  };

  // Self-review rejected
  assert.throws(
    () =>
      reviewProposal(proposal, {
        reviewerPrincipalId: PROPOSER_ID,
        reviewerIsCurrentProjectAdmin: true,
        decision: "approve",
        expectedCandidateSha256: SHA_A,
        expectedVersion: 1n,
        now: addSeconds(T0, 10)
      }),
    AuthorizationDomainError
  );

  // Stale hash rejected
  assert.throws(
    () =>
      reviewProposal(proposal, {
        reviewerPrincipalId: REVIEWER_ID,
        reviewerIsCurrentProjectAdmin: true,
        decision: "approve",
        expectedCandidateSha256: SHA_B,
        expectedVersion: 1n,
        now: addSeconds(T0, 10)
      }),
    ConflictDomainError
  );

  // Expired at 15m
  assert.throws(
    () =>
      reviewProposal(proposal, {
        reviewerPrincipalId: REVIEWER_ID,
        reviewerIsCurrentProjectAdmin: true,
        decision: "approve",
        expectedCandidateSha256: SHA_A,
        expectedVersion: 1n,
        now: addSeconds(T0, 900)
      }),
    ExpiredDomainError
  );

  const approved = reviewProposal(proposal, {
    reviewerPrincipalId: REVIEWER_ID,
    reviewerIsCurrentProjectAdmin: true,
    decision: "approve",
    expectedCandidateSha256: SHA_A,
    expectedVersion: 1n,
    now: addSeconds(T0, 10)
  });
  assert.equal(approved.state, "approved");

  assert.throws(
    () =>
      admitReplayProposal({
        proposal: approved,
        strategy: "replay_with_reviewed_representation",
        orderingStrategy: "append_after_current_tail",
        destinationChanged: true,
        strictPerKeyOrdering: true,
        proposerHasContentRead: true,
        reviewerHasContentRead: false,
        expectedCandidateSha256: SHA_A,
        expectedVersion: 2n,
        now: addSeconds(T0, 20)
      }),
    AuthorizationDomainError
  );

  const terminalSuppression = admitSuppressionProposal(
    approved,
    { deliveryId: DELIVERY_ID, state: "acknowledged", currentAttemptId: null },
    { expectedCandidateSha256: SHA_A, expectedVersion: 2n, now: addSeconds(T0, 20) }
  );
  assert.equal(terminalSuppression.outcome, "already_terminal");
  assert.equal(terminalSuppression.nextDeliveryState, "acknowledged");
  assert.equal(terminalSuppression.advancesStrictOrderingHead, false);
});

test("Retention enforces 30d post-terminal window, dependency barrier over expired holds, 90d history, and 100 batch cap", () => {
  const after30d = addMilliseconds(T0, 2_592_000_000n);
  const expiredHold = {
    holdId: HOLD_ID,
    targetKind: "event",
    state: "active",
    expiresAt: addSeconds(T0, 60)
  };

  // Optional hold expiry NEVER bypasses mandatory dependencies
  const blockedByDeps = evaluateContentExpirationEligibility({
    currentState: "required",
    allObligationsTerminal: true,
    allObligationsTerminalAt: T0,
    hasLiveMandatoryDependencies: true,
    holds: [expiredHold],
    now: after30d
  });
  assert.equal(blockedByDeps.eligible, false);
  assert.equal(blockedByDeps.blockingReason, "live_mandatory_dependency");

  const eligible = evaluateContentExpirationEligibility({
    currentState: "required",
    allObligationsTerminal: true,
    allObligationsTerminalAt: T0,
    hasLiveMandatoryDependencies: false,
    holds: [expiredHold],
    now: after30d
  });
  assert.equal(eligible.eligible, true);
  assert.equal(eligible.recommendedState, "release_eligible");

  assert.equal(
    isHistoryRetirementEligible(T0, false, [], addMilliseconds(T0, 7_776_000_000n)),
    true
  );
  assert.equal(assertRetentionClaimBatchSize(100), 100);
  assert.throws(() => assertRetentionClaimBatchSize(101), LimitExceededDomainError);
});

test("Recovery, Installation, Topology, Access, and Watch enforce all governance invariants", () => {
  assert.throws(
    () => assertRetireStaleClaimAllowed("prepared_attempt", T0),
    ConflictDomainError
  );
  assert.throws(() => assertContinuePublicationEpisodeAllowed("active"), ConflictDomainError);
  assertContinuePublicationEpisodeAllowed("review_required");
  assert.throws(
    () =>
      assertSetRecoveryGateAllowed({
        planScopeKind: "project",
        targetScopeKind: "installation",
        reopensAllowSend: true
      }),
    AuthorizationDomainError
  );
  assert.throws(
    () =>
      assertSetRecoveryGateAllowed({
        planScopeKind: "project",
        targetScopeKind: "installation",
        reopensAllowSend: false
      }),
    AuthorizationDomainError
  );
  assert.throws(
    () =>
      assertSetRecoveryGateAllowed({
        planScopeKind: "project",
        targetScopeKind: "tenant",
        reopensAllowSend: false
      }),
    AuthorizationDomainError
  );
  assert.throws(
    () =>
      assertSetRecoveryGateAllowed({
        planScopeKind: "tenant",
        targetScopeKind: "installation",
        reopensAllowSend: true
      }),
    AuthorizationDomainError
  );
  assert.throws(
    () =>
      assertSetRecoveryGateAllowed({
        planScopeKind: "tenant",
        targetScopeKind: "installation",
        reopensAllowSend: false
      }),
    AuthorizationDomainError
  );
  assertSetRecoveryGateAllowed({
    planScopeKind: "tenant",
    targetScopeKind: "project",
    reopensAllowSend: true
  });
  assertSetRecoveryGateAllowed({
    planScopeKind: "installation",
    targetScopeKind: "installation",
    reopensAllowSend: true
  });
  assert.throws(
    () => assertEstablishTargetEpochAllowed("open", EPOCH_1, EPOCH_2),
    ConflictDomainError
  );
  assert.throws(
    () =>
      assertRecoveryReviewAllowed({
        actionId: RECOVERY_ACTION_ID,
        kind: "rebuild_projection",
        requesterPrincipalId: PROPOSER_ID,
        reviewerPrincipalId: PROPOSER_ID
      }),
    AuthorizationDomainError
  );

  // Installation quarantine forces all 5 allow_* false and new control_epoch
  const quarantined = enterRecoveryQuarantine(
    {
      mode: "open",
      controlEpoch: EPOCH_1,
      allowEventAdmission: true,
      allowPublication: true,
      allowFanout: true,
      allowSend: true,
      allowEndpointVerification: true,
      governanceVersion: 1n,
      version: 1n
    },
    EPOCH_2
  );
  assertInstallationStateInvariants(quarantined);
  assert.equal(quarantined.allowSend, false);

  const resumedProject = resumeProjectAdmission({
    projectId: PROJECT_ID,
    state: "admission_paused",
    activeOrderingCutoverPlanId: CUTOVER_ID,
    topologyVersion: 3n
  });
  assert.equal(resumedProject.activeOrderingCutoverPlanId, CUTOVER_ID);

  // Topology, signing, verification
  assertValidSubscriptionTopologyRange({ fromTopologyVersion: 1n, untilTopologyVersion: 3n });
  assert.equal(isTopologyVersionInRange({ fromTopologyVersion: 1n, untilTopologyVersion: 3n }, 3n), false);
  assertSubscriptionSchemaVersions([1, 2, 3]);
  assert.throws(() => assertSubscriptionSchemaVersions(Array.from({ length: 17 }, (_, i) => i + 1)), LimitExceededDomainError);

  assertSigningPolicyInvariants({
    signatureMode: "primary_only",
    primaryKeyVersionId: KEY_V2,
    overlapKeyVersionId: null,
    overlapStartedAt: null,
    overlapEndsAt: null,
    oldKeySignUntil: null,
    oldKeyVerifyUntil: null
  });
  assert.throws(
    () =>
      assertSigningPolicyInvariants({
        signatureMode: "primary_only",
        primaryKeyVersionId: KEY_V2,
        overlapKeyVersionId: null,
        overlapStartedAt: T0,
        overlapEndsAt: null,
        oldKeySignUntil: null,
        oldKeyVerifyUntil: null
      }),
    InvariantViolationError
  );
  assertSigningPolicyInvariants({
    signatureMode: "bounded_dual_signature",
    primaryKeyVersionId: KEY_V2,
    overlapKeyVersionId: KEY_V1,
    overlapStartedAt: T0,
    overlapEndsAt: addSeconds(T0, 900),
    oldKeySignUntil: addSeconds(T0, 600),
    oldKeyVerifyUntil: addSeconds(T0, 900)
  });
  assert.throws(
    () =>
      assertSigningPolicyInvariants({
        signatureMode: "bounded_dual_signature",
        primaryKeyVersionId: KEY_V2,
        overlapKeyVersionId: KEY_V1,
        overlapStartedAt: T0,
        overlapEndsAt: addSeconds(T0, 900),
        oldKeySignUntil: addSeconds(T0, 700),
        oldKeyVerifyUntil: addSeconds(T0, 900)
      }),
    InvariantViolationError
  );
  assert.throws(
    () =>
      assertSigningPolicyInvariants({
        signatureMode: "bounded_dual_signature",
        primaryKeyVersionId: KEY_V2,
        overlapKeyVersionId: KEY_V1,
        overlapStartedAt: T0,
        overlapEndsAt: addSeconds(T0, 900),
        oldKeySignUntil: addSeconds(T0, 600),
        oldKeyVerifyUntil: addSeconds(T0, 901)
      }),
    InvariantViolationError
  );
  assert.throws(
    () =>
      assertSigningPolicyInvariants({
        signatureMode: "bounded_dual_signature",
        primaryKeyVersionId: KEY_V2,
        overlapKeyVersionId: KEY_V1,
        overlapStartedAt: T0,
        overlapEndsAt: addSeconds(T0, 900),
        oldKeySignUntil: addSeconds(T0, -1),
        oldKeyVerifyUntil: addSeconds(T0, 600)
      }),
    InvariantViolationError
  );

  assert.throws(
    () =>
      assertCanBeginVerificationAttempt(
        {
          intentId: VERIFY_INTENT_ID,
          endpointId: ENDPOINT_ID,
          state: "approved",
          attemptsUsed: 3,
          expiresAt: addSeconds(T0, 60)
        },
        T0
      ),
    LimitExceededDomainError
  );

  const subUpdated = applySubscriptionControlAction(
    { subscriptionId: SUB_ID, state: "active", sendHold: false, controlSequence: 1n },
    "hold_sends"
  );
  assert.equal(subUpdated.state, "active");
  assert.equal(subUpdated.sendHold, true);

  // Security quarantine on subscription cannot be cleared by ordinary control actions
  assert.equal(canTransition(ALLOWED_SUBSCRIPTION_TRANSITIONS, "quarantined", "active"), false);
  const subQuarantined = applySubscriptionControlAction(subUpdated, "quarantine");
  assert.equal(subQuarantined.state, "quarantined");
  assert.equal(subQuarantined.sendHold, true);
  assert.throws(
    () => applySubscriptionControlAction(subQuarantined, "activate"),
    UnsupportedStateTransitionError
  );
  assert.throws(
    () => applySubscriptionControlAction(subQuarantined, "resume_future"),
    UnsupportedStateTransitionError
  );
  assert.throws(
    () => applySubscriptionControlAction(subQuarantined, "cutover_activate"),
    ConflictDomainError
  );
  assert.throws(
    () => applySubscriptionControlAction(subQuarantined, "release_send_hold"),
    ConflictDomainError
  );

  const endpointQuarantined = quarantineEndpoint("active", 3n, ENDPOINT_ID);
  assert.equal(endpointQuarantined.state, "quarantined");
  assert.equal(endpointQuarantined.securityEpoch, 4n);

  // Access & Watch
  const machineNs = parseProducerNamespace("orders.api");
  const humanNs = parseProducerNamespace(`human.${PROPOSER_ID}`);
  assertProducerChannelBinding("machine_producer", "producer", machineNs);
  assertProducerChannelBinding("human_workflow", "human", humanNs);
  assert.throws(
    () => assertProducerChannelBinding("machine_producer", "human", machineNs),
    InvariantViolationError
  );
  assertProducerScopeBounds(64, 16);
  assert.throws(() => assertProducerScopeBounds(65, 1), LimitExceededDomainError);
  assertProducerCredentialTiming({
    credentialId: CRED_ID,
    issuedAt: T0,
    expiresAt: addMilliseconds(T0, 2_592_000_000n),
    overlapStartedAt: T0,
    overlapEndsAt: addSeconds(T0, 900)
  });
  assert.throws(
    () =>
      assertProducerCredentialTiming({
        credentialId: CRED_ID,
        issuedAt: T0,
        expiresAt: addMilliseconds(T0, 2_592_000_000n),
        overlapStartedAt: T0,
        overlapEndsAt: null
      }),
    ValidationDomainError
  );
  assert.throws(
    () =>
      assertProducerCredentialTiming({
        credentialId: CRED_ID,
        issuedAt: T0,
        expiresAt: addMilliseconds(T0, 2_592_000_000n),
        overlapStartedAt: null,
        overlapEndsAt: addSeconds(T0, 900)
      }),
    ValidationDomainError
  );

  assert.equal(
    isHumanSessionExpired({
      state: "active",
      absoluteExpiresAt: addSeconds(T0, 3600),
      idleExpiresAt: addSeconds(T0, 1800),
      now: addSeconds(T0, 60)
    }),
    false
  );
  assert.equal(
    isHumanSessionExpired({
      state: "active",
      absoluteExpiresAt: addSeconds(T0, 3600),
      idleExpiresAt: addSeconds(T0, 1800),
      now: addSeconds(T0, 1800)
    }),
    true
  );
  assert.equal(
    isHumanSessionExpired({
      state: "revoked",
      absoluteExpiresAt: addSeconds(T0, 3600),
      idleExpiresAt: addSeconds(T0, 1800),
      now: addSeconds(T0, 60)
    }),
    true
  );

  assert.throws(
    () =>
      assertCanConsumeAuthChallenge({
        state: "pending",
        failureCount: 5,
        expiresAt: addSeconds(T0, 60),
        now: T0
      }),
    LimitExceededDomainError
  );

  assertWatchQuotaAvailable({ actorActiveCount: 1, projectActiveCount: 9, tenantActiveCount: 19 });
  assert.throws(
    () => assertWatchQuotaAvailable({ actorActiveCount: 2, projectActiveCount: 0, tenantActiveCount: 0 }),
    LimitExceededDomainError
  );

  const streamCutoff = computeWatchStreamCutoff(T0);
  const authCutoff = addSeconds(T0, 1800);
  const lease = {
    leaseId: WATCH_ID,
    state: "open",
    slotState: "held",
    openedAt: T0,
    lastRenewedAt: T0,
    leaseExpiresAt: computeWatchLeaseExpiry(T0, authCutoff, streamCutoff),
    streamCutoffAt: streamCutoff
  };
  assert.throws(() => renewWatchLease(lease, addMilliseconds(T0, 500), authCutoff), RateLimitDomainError);
  const renewed = renewWatchLease(lease, addSeconds(T0, 2), authCutoff);
  assert.equal(renewed.leaseExpiresAt.equals(addSeconds(T0, 7)), true);
  const closedLease = closeWatchLease(renewed);
  assert.equal(closedLease.state, "closed");
  assert.equal(closedLease.slotState, "released");
});
