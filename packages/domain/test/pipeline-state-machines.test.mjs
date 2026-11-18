import test from "node:test";
import assert from "node:assert/strict";
import {
  ALLOWED_ATTEMPT_TRANSITIONS,
  ALLOWED_BROKER_INBOX_TRANSITIONS,
  ALLOWED_CIRCUIT_TRANSITIONS,
  ALLOWED_DELIVERY_TRANSITIONS,
  ALLOWED_EVENT_FANOUT_TRANSITIONS,
  ALLOWED_EVENT_TRANSITIONS,
  ALLOWED_LOCAL_INVOCATION_TRANSITIONS,
  ALLOWED_OUTBOX_TRANSITIONS,
  ALLOWED_PUBLICATION_TRANSITIONS,
  ATTEMPT_STATES,
  BROKER_EVENT_STREAM_NAME,
  BROKER_INBOX_STATES,
  CIRCUIT_STATES,
  ConflictDomainError,
  DELIVERY_EXECUTION_BUCKETS,
  DELIVERY_STATES,
  EVENT_FANOUT_STATES,
  EVENT_STATES,
  InvariantViolationError,
  LOCAL_INVOCATION_STATES,
  OUTBOX_STATES,
  PUBLICATION_STATES,
  RETRY_V1_POLICY,
  RateLimitDomainError,
  UnsupportedStateTransitionError,
  ValidationDomainError,
  acknowledgeOutboxPublication,
  addMilliseconds,
  addSeconds,
  allocateOutboxRecoveryGeneration,
  applyCircuitObservation,
  assertContiguousFanoutSequence,
  assertDeliveryTransition,
  assertReservationConservation,
  attachLateObservationToTerminalDelivery,
  canCompleteEventFanout,
  canPrepareDelivery,
  canTransition,
  claimCircuitProbe,
  claimOutboxRow,
  classifyHttpOutcome,
  computeBackoffCeilingMs,
  computeCircuitOpenDelayMs,
  computeEventDeliveryDeadline,
  computeLocalInvocationCutoff,
  computeRetryDecision,
  createReplayDeliverySeed,
  deferUnstartedCircuitProbe,
  enterLocalInvocation,
  finalizeDeliveryAttempt,
  finishLocalInvocation,
  formatBrokerMessageId,
  isTerminalAttemptState,
  isTerminalDeliveryState,
  isValidHttpStatus,
  parseAttemptId,
  parseBrokerGenerationId,
  parseControlEpoch,
  parseDeliveryFamilyId,
  parseDeliveryId,
  parseEndpointCircuitId,
  parseEndpointId,
  parseEventId,
  parseLateObservationId,
  parseOutboxId,
  parseProjectId,
  parsePublicationObservationId,
  parsePublicationRecoveryEpisodeId,
  parseRuntimeInstanceId,
  parseSha256Hex,
  parseSubscriptionId,
  parseUtcTimestamp,
  recordRecoveryEpisodeProgress,
  releaseOutboxClaimToPending,
  resolveLocalInvocationPermission,
  startDeliveryPreparation,
  toDeliveryExecutionBucket,
  transitionAttemptState,
  transitionEventFanoutState,
  transitionEventState
} from "@relayquill/domain";

const T0 = parseUtcTimestamp("2026-11-01T12:00:00.000000Z").instant;
const PROJECT_ID = parseProjectId("00000000-0000-4000-8000-000000000001");
const EVENT_ID = parseEventId("00000000-0000-4000-8000-000000000002");
const OUTBOX_ID = parseOutboxId("00000000-0000-4000-8000-000000000003");
const INSTANCE_ID = parseRuntimeInstanceId("00000000-0000-4000-8000-000000000004");
const EPOCH = parseControlEpoch("00000000-0000-4000-8000-000000000005");
const BROKER_GEN_ID = parseBrokerGenerationId("00000000-0000-4000-8000-000000000006");
const PUB_OBS_ID = parsePublicationObservationId("00000000-0000-4000-8000-000000000007");
const EPISODE_ID = parsePublicationRecoveryEpisodeId("00000000-0000-4000-8000-000000000008");
const DELIVERY_ID = parseDeliveryId("00000000-0000-4000-8000-000000000009");
const FAMILY_ID = parseDeliveryFamilyId("00000000-0000-4000-8000-000000000010");
const SUB_ID = parseSubscriptionId("00000000-0000-4000-8000-000000000011");
const ENDPOINT_ID = parseEndpointId("00000000-0000-4000-8000-000000000012");
const ATTEMPT_ID = parseAttemptId("00000000-0000-4000-8000-000000000013");
const CIRCUIT_ID = parseEndpointCircuitId("00000000-0000-4000-8000-000000000014");
const LATE_OBS_ID = parseLateObservationId("00000000-0000-4000-8000-000000000015");
const HASH = parseSha256Hex("b".repeat(64));

test("All pipeline transition matrices reject terminal exits and illegal jumps", () => {
  for (const from of EVENT_STATES) {
    for (const to of EVENT_STATES) {
      if (from === "retired") {
        assert.equal(canTransition(ALLOWED_EVENT_TRANSITIONS, from, to), false);
      }
    }
  }
  for (const from of OUTBOX_STATES) {
    if (from === "retired") {
      for (const to of OUTBOX_STATES) {
        assert.equal(canTransition(ALLOWED_OUTBOX_TRANSITIONS, from, to), false);
      }
    }
  }
  for (const to of PUBLICATION_STATES) {
    assert.equal(canTransition(ALLOWED_PUBLICATION_TRANSITIONS, "recovery_superseded", to), false);
  }
  for (const to of BROKER_INBOX_STATES) {
    assert.equal(canTransition(ALLOWED_BROKER_INBOX_TRANSITIONS, "completed", to), false);
  }
  for (const to of EVENT_FANOUT_STATES) {
    assert.equal(canTransition(ALLOWED_EVENT_FANOUT_TRANSITIONS, "completed", to), false);
  }
  for (const from of DELIVERY_STATES) {
    if (isTerminalDeliveryState(from)) {
      for (const to of DELIVERY_STATES) {
        assert.equal(canTransition(ALLOWED_DELIVERY_TRANSITIONS, from, to), false);
      }
    }
  }
  assert.equal(canTransition(ALLOWED_DELIVERY_TRANSITIONS, "pending", "acknowledged"), false);
  assert.equal(canTransition(ALLOWED_DELIVERY_TRANSITIONS, "retry_wait", "acknowledged"), false);

  for (const from of ATTEMPT_STATES) {
    if (isTerminalAttemptState(from)) {
      for (const to of ATTEMPT_STATES) {
        assert.equal(canTransition(ALLOWED_ATTEMPT_TRANSITIONS, from, to), false);
      }
    }
  }
  assert.equal(canTransition(ALLOWED_ATTEMPT_TRANSITIONS, "send_started", "deferred_before_send"), false);
  assert.equal(canTransition(ALLOWED_ATTEMPT_TRANSITIONS, "send_started", "failed_before_send"), false);

  assert.equal(canTransition(ALLOWED_LOCAL_INVOCATION_TRANSITIONS, "invoking", "permission_accepted"), false);
  for (const to of LOCAL_INVOCATION_STATES) {
    assert.equal(canTransition(ALLOWED_LOCAL_INVOCATION_TRANSITIONS, "finished", to), false);
    assert.equal(canTransition(ALLOWED_LOCAL_INVOCATION_TRANSITIONS, "aborted", to), false);
    assert.equal(canTransition(ALLOWED_LOCAL_INVOCATION_TRANSITIONS, "unusable", to), false);
  }
  assert.equal(CIRCUIT_STATES.length, 3);
  assert.equal(canTransition(ALLOWED_CIRCUIT_TRANSITIONS, "open", "closed"), false);
  assert.throws(
    () => assertDeliveryTransition("pending", "acknowledged", DELIVERY_ID),
    UnsupportedStateTransitionError
  );
});

test("Event, Outbox, Publication, and Recovery Episode enforce fencing and recovery bounds", () => {
  const defaultDeadline = computeEventDeliveryDeadline(T0);
  assert.equal(defaultDeadline.equals(addMilliseconds(T0, 86_400_000n)), true);
  assert.throws(() => computeEventDeliveryDeadline(T0, 604_800_001n), ValidationDomainError);

  assert.equal(
    formatBrokerMessageId(OUTBOX_ID, 1n),
    "rq:00000000-0000-4000-8000-000000000003:1"
  );

  const event0 = { eventId: EVENT_ID, state: "accepted", blockingReason: null, retiredAt: null };
  assert.throws(
    () => transitionEventState(event0, "fanout_blocked", { blockingReason: "   " }),
    ValidationDomainError
  );
  const blocked = transitionEventState(event0, "fanout_blocked", { blockingReason: "missing_schema" });
  const complete = transitionEventState(blocked, "fanout_complete");
  const retired = transitionEventState(complete, "retired", { retiredAt: addSeconds(T0, 10) });
  assert.throws(() => transitionEventState(retired, "accepted"), UnsupportedStateTransitionError);

  const outbox0 = {
    outboxId: OUTBOX_ID,
    state: "pending",
    currentPublicationGeneration: 1n,
    claimGeneration: 0n,
    claimOwnerInstanceId: null,
    claimControlEpoch: null,
    claimExpiresAt: null,
    nextPublishAt: T0,
    lastSafeErrorCode: null
  };
  let pub = {
    outboxId: OUTBOX_ID,
    publicationGeneration: 1n,
    state: "prepared",
    brokerMessageId: formatBrokerMessageId(OUTBOX_ID, 1n),
    sendCount: 0,
    firstBrokerGenerationId: null,
    firstObservationId: null,
    streamSequence: null,
    ackObservedAt: null
  };

  const claimed = claimOutboxRow(outbox0, {
    ownerInstanceId: INSTANCE_ID,
    controlEpoch: EPOCH,
    now: T0
  });
  assert.equal(claimed.claimGeneration, 1n);

  // Stale claim fence rejected
  assert.throws(
    () =>
      acknowledgeOutboxPublication(claimed, pub, {
        ownerInstanceId: INSTANCE_ID,
        controlEpoch: EPOCH,
        expectedClaimGeneration: 99n,
        streamName: BROKER_EVENT_STREAM_NAME,
        streamSequence: 1,
        brokerGenerationId: BROKER_GEN_ID,
        observationId: PUB_OBS_ID,
        ackObservedAt: T0
      }),
    ConflictDomainError
  );

  // Uncertain retry preserves currentPublicationGeneration
  const released = releaseOutboxClaimToPending(claimed, pub, {
    nextPublishAt: addSeconds(T0, 2),
    markPublishUnknown: true,
    lastSafeErrorCode: "BROKER_TIMEOUT"
  });
  assert.equal(released.outbox.currentPublicationGeneration, 1n);
  assert.equal(released.publication.state, "publish_unknown");

  const reclaimed = claimOutboxRow(released.outbox, {
    ownerInstanceId: INSTANCE_ID,
    controlEpoch: EPOCH,
    now: addSeconds(T0, 2)
  });
  const acked = acknowledgeOutboxPublication(reclaimed, released.publication, {
    ownerInstanceId: INSTANCE_ID,
    controlEpoch: EPOCH,
    expectedClaimGeneration: 2n,
    streamName: BROKER_EVENT_STREAM_NAME,
    streamSequence: 42,
    brokerGenerationId: BROKER_GEN_ID,
    observationId: PUB_OBS_ID,
    ackObservedAt: addSeconds(T0, 3)
  });
  assert.equal(acked.outbox.state, "published");
  assert.equal(acked.publication.state, "ack_observed");
  assert.equal(acked.publication.sendCount, 2);

  // Recovery episode: 60s spacing and 5 no-progress generations -> review_required
  let outbox = acked.outbox;
  pub = acked.publication;
  let episode = {
    episodeId: EPISODE_ID,
    outboxId: OUTBOX_ID,
    state: "active",
    successiveNoProgressGenerations: 0,
    lastGenerationIssuedAt: null
  };
  let cursorTime = addSeconds(T0, 10);
  for (let i = 0; i < 4; i += 1) {
    const rec = allocateOutboxRecoveryGeneration(outbox, pub, episode, cursorTime);
    outbox = rec.outbox;
    pub = rec.nextPublication;
    episode = rec.episode;
    assert.equal(episode.state, "active");
    if (i === 0) {
      assert.throws(
        () => allocateOutboxRecoveryGeneration(outbox, pub, episode, addSeconds(cursorTime, 30)),
        RateLimitDomainError
      );
    }
    cursorTime = addSeconds(cursorTime, 60);
  }
  const fifth = allocateOutboxRecoveryGeneration(outbox, pub, episode, cursorTime);
  assert.equal(fifth.episode.state, "review_required");
  assert.equal(fifth.outbox.state, "blocked");
  assert.throws(
    () =>
      allocateOutboxRecoveryGeneration(
        { ...outbox, state: "retired" },
        pub,
        { ...episode, state: "active" },
        addSeconds(cursorTime, 60)
      ),
    UnsupportedStateTransitionError
  );

  const resetEpisode = recordRecoveryEpisodeProgress(
    { ...fifth.episode, state: "active" },
    true
  );
  assert.equal(resetEpisode.state, "completed");
  assert.equal(resetEpisode.successiveNoProgressGenerations, 0);
});

test("Fanout enforces contiguous watermark and reservation conservation", () => {
  assertContiguousFanoutSequence(PROJECT_ID, EVENT_ID, 5n, 4n);
  assert.throws(() => assertContiguousFanoutSequence(PROJECT_ID, EVENT_ID, 6n, 4n), ConflictDomainError);

  assertReservationConservation({
    reservedCandidateSlots: 10n,
    unresolvedCandidateSlots: 2n,
    convertedDeliverySlots: 5n,
    releasedNonmatchSlots: 3n
  });
  assert.throws(
    () =>
      assertReservationConservation({
        reservedCandidateSlots: 10n,
        unresolvedCandidateSlots: 2n,
        convertedDeliverySlots: 5n,
        releasedNonmatchSlots: 2n
      }),
    InvariantViolationError
  );

  const fanout = {
    eventId: EVENT_ID,
    projectId: PROJECT_ID,
    projectEventSequence: 1n,
    state: "materializing",
    candidateCount: 3,
    examinedCount: 3
  };
  assert.equal(
    canCompleteEventFanout(fanout, {
      reservedCandidateSlots: 3n,
      unresolvedCandidateSlots: 1n,
      convertedDeliverySlots: 2n,
      releasedNonmatchSlots: 0n
    }),
    false
  );
  const completed = transitionEventFanoutState(fanout, "completed", {
    materializedThroughEventSequence: 0n,
    reservation: {
      reservedCandidateSlots: 3n,
      unresolvedCandidateSlots: 0n,
      convertedDeliverySlots: 2n,
      releasedNonmatchSlots: 1n
    }
  });
  assert.equal(completed.state, "completed");
});

test("Delivery buckets, Attempt counters, Late observations, and Replay seed invariants", () => {
  const buckets = new Set(DELIVERY_STATES.map((s) => toDeliveryExecutionBucket(s)));
  assert.deepEqual([...buckets].sort(), [...DELIVERY_EXECUTION_BUCKETS].sort());
  assert.equal(isValidHttpStatus(202), true);
  assert.equal(isValidHttpStatus(0), false);
  assert.equal(isValidHttpStatus(600), false);

  const baseDelivery = {
    deliveryId: DELIVERY_ID,
    familyId: FAMILY_ID,
    eventId: EVENT_ID,
    subscriptionId: SUB_ID,
    endpointId: ENDPOINT_ID,
    deliveryGeneration: 0n,
    state: "ready",
    attemptCount: 0,
    maximumAttempts: 12,
    preparedAttemptCount: 0,
    preparationFailureCount: 0,
    nextAttemptNumber: 1,
    currentFence: 0n,
    currentAttemptId: null,
    nextEligibleAt: T0,
    deadlineAt: addSeconds(T0, 3600),
    acknowledgedAt: null,
    terminalAt: null,
    consumerEventKeySha256: HASH
  };

  const prereqs = {
    endpointActive: true,
    hasValidDispatchGrant: true,
    subscriptionActive: true,
    subscriptionSendHold: false,
    circuitAllowsAttempt: true,
    orderingAllowsAttempt: true
  };
  assert.equal(canPrepareDelivery(baseDelivery, prereqs, T0), true);

  const sending = startDeliveryPreparation(baseDelivery, prereqs, ATTEMPT_ID, T0);
  assert.equal(sending.preparedAttemptCount, 1);
  assert.equal(sending.attemptCount, 0);

  const preparedAttempt = {
    attemptId: ATTEMPT_ID,
    deliveryId: DELIVERY_ID,
    attemptNumber: 1,
    state: "prepared",
    fencingToken: 1n,
    ownerInstanceId: INSTANCE_ID,
    controlEpoch: EPOCH,
    claimExpiresAt: addSeconds(T0, 30),
    requestDeadlineAt: null,
    responseStatus: null
  };

  // Deferred before send preserves attemptCount and preparationFailureCount
  const deferredAttempt = transitionAttemptState(preparedAttempt, "deferred_before_send", {
    expectedFencingToken: 1n,
    ownerInstanceId: INSTANCE_ID,
    controlEpoch: EPOCH
  });
  assert.equal(deferredAttempt.counterDeltas.attemptCountDelta, 0);
  assert.equal(deferredAttempt.counterDeltas.preparationFailureDelta, 0);

  const backToReady = finalizeDeliveryAttempt(sending, {
    attemptId: ATTEMPT_ID,
    expectedFence: 1n,
    attemptState: deferredAttempt.attempt.state,
    targetState: "ready",
    decidedAt: addSeconds(T0, 1)
  });
  assert.equal(backToReady.attemptCount, 0);

  // Send started increments attemptCount and transitions to acknowledged
  const sending2 = startDeliveryPreparation(backToReady, prereqs, ATTEMPT_ID, addSeconds(T0, 2));
  const startedAttempt = transitionAttemptState(
    { ...preparedAttempt, fencingToken: sending2.currentFence },
    "send_started",
    {
      expectedFencingToken: sending2.currentFence,
      requestDeadlineAt: addSeconds(T0, 12)
    }
  );
  assert.equal(startedAttempt.counterDeltas.attemptCountDelta, 1);
  const observedAttempt = transitionAttemptState(startedAttempt.attempt, "response_observed", {
    expectedFencingToken: sending2.currentFence,
    responseStatus: 202
  });
  const ackTime = addSeconds(T0, 3);
  const ackedDelivery = finalizeDeliveryAttempt(sending2, {
    attemptId: ATTEMPT_ID,
    expectedFence: sending2.currentFence,
    attemptState: observedAttempt.attempt.state,
    targetState: "acknowledged",
    decidedAt: ackTime
  });
  assert.equal(ackedDelivery.state, "acknowledged");
  assert.equal(ackedDelivery.attemptCount, 1);

  // Late receipt observation does not transition acknowledged delivery
  const lateAttachment = attachLateObservationToTerminalDelivery(ackedDelivery, {
    observationId: LATE_OBS_ID,
    kind: "reviewed_receiver_receipt_reference",
    observedAt: addSeconds(T0, 50),
    receiptVerificationState: "verified_supported"
  });
  assert.equal(lateAttachment.preservedState, "acknowledged");
  assert.equal(lateAttachment.preservedAcknowledgedAt?.equals(ackTime), true);

  // Replay creates new generation >= 1 without modifying original delivery
  const replay = createReplayDeliverySeed(
    {
      familyId: FAMILY_ID,
      eventId: EVENT_ID,
      subscriptionId: SUB_ID,
      nextGeneration: 1n,
      consumerEventKeySha256: HASH
    },
    parseDeliveryId("00000000-0000-4000-8000-000000000099"),
    ENDPOINT_ID,
    { now: addSeconds(T0, 60), deadlineAt: addSeconds(T0, 3600) }
  );
  assert.equal(replay.newDelivery.deliveryGeneration, 1n);
  assert.equal(replay.newDelivery.state, "pending");
  assert.equal(replay.nextFamily.nextGeneration, 2n);
});

test("LocalInvocation enforces monotonic continuity, cutoff math, and terminal exceptions", () => {
  const owner = {
    workerInstanceId: INSTANCE_ID,
    attemptId: ATTEMPT_ID,
    fencingToken: 1n,
    controlEpoch: EPOCH
  };
  const inv0 = { owner, state: "permission_pending", m0Ns: 1_000_000_000n, localCutoffNs: null };

  // Negative monotonic jump -> unusable
  const badClock = resolveLocalInvocationPermission(inv0, {
    owner,
    m0Ns: 1_000_000_000n,
    m1Ns: 999_000_000n,
    requestDeadlineAt: addSeconds(T0, 10),
    acceptanceDbClock: T0
  });
  assert.equal(badClock.state, "unusable");

  // Conservative cutoff: min(10s - elapsed, (requestDeadline - acceptanceClock) - elapsed)
  const cutoff = computeLocalInvocationCutoff({
    m0Ns: 1_000_000_000n,
    m1Ns: 1_500_000_000n,
    requestDeadlineAt: addSeconds(T0, 6),
    acceptanceDbClock: T0
  });
  assert.equal(cutoff.usable, true);
  if (cutoff.usable) {
    assert.equal(cutoff.elapsedNs, 500_000_000n);
    assert.equal(cutoff.remainingBudgetNs, 5_500_000_000n);
    assert.equal(cutoff.localCutoffNs, 7_000_000_000n);
  }

  const accepted = resolveLocalInvocationPermission(inv0, {
    owner,
    m0Ns: 1_000_000_000n,
    m1Ns: 1_500_000_000n,
    requestDeadlineAt: addSeconds(T0, 6),
    acceptanceDbClock: T0
  });
  assert.equal(accepted.state, "permission_accepted");

  const invoking = enterLocalInvocation(accepted, owner, 2_000_000_000n, true);
  assert.equal(invoking.state, "invoking");

  assert.throws(
    () => finishLocalInvocation(invoking, "permission_accepted"),
    UnsupportedStateTransitionError
  );
  const finished = finishLocalInvocation(invoking, "finished");
  assert.equal(finished.state, "finished");
});

test("retry_v1 computes exact backoff ceilings, Retry-After, and NO_RETRY_WITHIN_WINDOW", () => {
  assert.equal(classifyHttpOutcome(202).outcomeClass, "acknowledged");
  assert.equal(classifyHttpOutcome(302).outcomeClass, "permanent_redirect");
  assert.equal(classifyHttpOutcome(429).outcomeClass, "transient_http");
  assert.equal(classifyHttpOutcome(503).outcomeClass, "transient_http");
  assert.equal(classifyHttpOutcome(501).outcomeClass, "permanent_http");
  assert.equal(classifyHttpOutcome(505).outcomeClass, "permanent_http");
  assert.equal(classifyHttpOutcome(400).outcomeClass, "permanent_http");
  assert.throws(() => classifyHttpOutcome(0), ValidationDomainError);

  assert.deepEqual(
    [1, 2, 3, 4, 5].map((o) => computeBackoffCeilingMs(o, RETRY_V1_POLICY)),
    [1_000n, 2_000n, 4_000n, 8_000n, 16_000n]
  );
  assert.equal(computeBackoffCeilingMs(1000, RETRY_V1_POLICY), 1_800_000n);

  // Worked deadline fit: 12:00:00 + 3s = 12:00:03; +10s min window = 12:00:13
  const fit = computeRetryDecision({
    outcomeClass: "transient_http",
    attemptCount: 3,
    decidedAt: T0,
    deadlineAt: addSeconds(T0, 20),
    drawUniformBigIntInclusive: () => 3_000n
  });
  assert.equal(fit.decision, "retry_wait");
  assert.equal(fit.nextEligibleAt?.equals(addSeconds(T0, 3)), true);

  const noFit = computeRetryDecision({
    outcomeClass: "transient_http",
    attemptCount: 3,
    decidedAt: T0,
    deadlineAt: addSeconds(T0, 10),
    drawUniformBigIntInclusive: () => 3_000n
  });
  assert.equal(noFit.decision, "dead_letter");
  assert.equal(noFit.reasonCode, "NO_RETRY_WITHIN_WINDOW");

  // Retry-After capped at 1800s and max(jitter, cappedRetryAfter)
  const retryAfterRes = computeRetryDecision({
    outcomeClass: "transient_http",
    attemptCount: 1,
    decidedAt: T0,
    deadlineAt: addSeconds(T0, 3600),
    retryAfterMs: 5_000_000n,
    retryAfterParseClass: "delay_seconds",
    drawUniformBigIntInclusive: () => 500n
  });
  assert.equal(retryAfterRes.decision, "retry_wait");
  assert.equal(retryAfterRes.cappedRetryAfterMs, 1_800_000n);
  assert.equal(retryAfterRes.selectedDelayMs, 1_800_000n);

  // Permanent HTTP with Retry-After still dead-letters
  const perm = computeRetryDecision({
    outcomeClass: "permanent_http",
    attemptCount: 1,
    decidedAt: T0,
    deadlineAt: addSeconds(T0, 3600),
    retryAfterMs: 60_000n,
    drawUniformBigIntInclusive: () => 0n
  });
  assert.equal(perm.decision, "dead_letter");

  // Expired at decidedAt >= deadlineAt
  const expired = computeRetryDecision({
    outcomeClass: "transient_http",
    attemptCount: 1,
    decidedAt: T0,
    deadlineAt: T0,
    drawUniformBigIntInclusive: () => 0n
  });
  assert.equal(expired.decision, "expired");

  // Exhausted 12 send_starts
  const exhausted = computeRetryDecision({
    outcomeClass: "transient_http",
    attemptCount: 12,
    decidedAt: T0,
    deadlineAt: addSeconds(T0, 3600),
    drawUniformBigIntInclusive: () => 0n
  });
  assert.equal(exhausted.decision, "dead_letter");
  assert.equal(exhausted.reasonCode, "RETRY_BUDGET_EXHAUSTED");
});

test("Circuit enforces 5-failure threshold, generation fencing, probe backoff, and quarantine separation", () => {
  assert.deepEqual(
    [0, 1, 2, 3, 4, 5].map((n) => computeCircuitOpenDelayMs(n)),
    [60_000n, 120_000n, 240_000n, 480_000n, 900_000n, 900_000n]
  );

  let circuit = {
    circuitId: CIRCUIT_ID,
    endpointId: ENDPOINT_ID,
    endpointVersion: 1n,
    state: "closed",
    circuitGeneration: 1n,
    probeGeneration: 0n,
    consecutiveTransientFailures: 0,
    reopenCount: 0,
    reopenNotBefore: null,
    probeAttemptId: null,
    probeOwnerInstanceId: null,
    probeControlEpoch: null,
    probeExpiresAt: null,
    windowStartedAt: T0,
    windowSuccessCount: 0,
    windowFailureCount: 0
  };

  for (let i = 0; i < 3; i += 1) {
    circuit = applyCircuitObservation(circuit, {
      circuitGenerationAtStart: 1n,
      attemptId: ATTEMPT_ID,
      decidedAt: addSeconds(T0, i + 1),
      outcomeClass: "transient_http"
    }).circuit;
  }
  assert.equal(circuit.consecutiveTransientFailures, 3);

  // Permanent HTTP resets consecutive transient failures
  circuit = applyCircuitObservation(circuit, {
    circuitGenerationAtStart: 1n,
    attemptId: ATTEMPT_ID,
    decidedAt: addSeconds(T0, 4),
    outcomeClass: "permanent_http"
  }).circuit;
  assert.equal(circuit.consecutiveTransientFailures, 0);

  // 5 consecutive transient failures open the circuit for 60s
  for (let i = 0; i < 5; i += 1) {
    circuit = applyCircuitObservation(circuit, {
      circuitGenerationAtStart: 1n,
      attemptId: ATTEMPT_ID,
      decidedAt: addSeconds(T0, 10 + i),
      outcomeClass: i === 4 ? "transport_unknown" : "transient_http"
    }).circuit;
  }
  assert.equal(circuit.state, "open");
  assert.equal(circuit.circuitGeneration, 2n);
  assert.equal(circuit.reopenNotBefore?.equals(addSeconds(T0, 74)), true);

  // Stale generation observation is ignored
  const staleRes = applyCircuitObservation(circuit, {
    circuitGenerationAtStart: 1n,
    attemptId: ATTEMPT_ID,
    decidedAt: addSeconds(T0, 15),
    outcomeClass: "acknowledged"
  });
  assert.equal(staleRes.applied, false);

  // Claim probe -> defer unstarted -> reopenCount preserved with >= 1s delay
  const halfOpen = claimCircuitProbe(circuit, {
    probeAttemptId: ATTEMPT_ID,
    probeOwnerInstanceId: INSTANCE_ID,
    probeControlEpoch: EPOCH,
    claimExpiresAt: addSeconds(T0, 104),
    deliveryDeadlineAt: addSeconds(T0, 3600),
    now: addSeconds(T0, 74)
  });
  assert.equal(halfOpen.state, "half_open");
  assert.equal(halfOpen.probeGeneration, 1n);

  const deferredOpen = deferUnstartedCircuitProbe(halfOpen, {
    expectedCircuitGeneration: 2n,
    expectedProbeGeneration: 1n,
    probeAttemptId: ATTEMPT_ID,
    decidedAt: addSeconds(T0, 75)
  });
  assert.equal(deferredOpen.state, "open");
  assert.equal(deferredOpen.reopenCount, 0);
  assert.equal(deferredOpen.reopenNotBefore?.equals(addSeconds(T0, 76)), true);

  // Permanent HTTP in half_open conservatively reopens circuit (120s)
  const halfOpen2 = claimCircuitProbe(deferredOpen, {
    probeAttemptId: ATTEMPT_ID,
    probeOwnerInstanceId: INSTANCE_ID,
    probeControlEpoch: EPOCH,
    claimExpiresAt: addSeconds(T0, 106),
    deliveryDeadlineAt: addSeconds(T0, 3600),
    now: addSeconds(T0, 76)
  });
  const reopened = applyCircuitObservation(halfOpen2, {
    circuitGenerationAtStart: 2n,
    probeGenerationAtStart: 2n,
    attemptId: ATTEMPT_ID,
    decidedAt: addSeconds(T0, 77),
    outcomeClass: "permanent_http"
  });
  assert.equal(reopened.circuit.state, "open");
  assert.equal(reopened.circuit.reopenCount, 1);
  assert.equal(reopened.circuit.reopenNotBefore?.equals(addSeconds(T0, 197)), true);

  // Recovery to closed never clears endpoint security quarantine
  const halfOpen3 = claimCircuitProbe(reopened.circuit, {
    probeAttemptId: ATTEMPT_ID,
    probeOwnerInstanceId: INSTANCE_ID,
    probeControlEpoch: EPOCH,
    claimExpiresAt: addSeconds(T0, 227),
    deliveryDeadlineAt: addSeconds(T0, 3600),
    now: addSeconds(T0, 197)
  });
  const closedAgain = applyCircuitObservation(halfOpen3, {
    circuitGenerationAtStart: halfOpen3.circuitGeneration,
    probeGenerationAtStart: halfOpen3.probeGeneration,
    attemptId: ATTEMPT_ID,
    decidedAt: addSeconds(T0, 198),
    outcomeClass: "acknowledged"
  });
  assert.equal(closedAgain.circuit.state, "closed");
  assert.equal(closedAgain.clearsSecurityQuarantine, false);
});
