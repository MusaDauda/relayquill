import test from "node:test";
import assert from "node:assert/strict";
import {
  CONSOLE_RESOURCE_STATES,
  CONSOLE_RESOURCE_STATE_META,
  getConsoleResourceStateDescriptor,
  isAcceptanceStatus,
  isChannelKind,
  isConsoleResourceState,
  isContentAvailability,
  isContentView,
  isDataGrantAction,
  isDeliveryPopulation,
  isEndpointVerificationPurpose,
  isEvidenceBoundary,
  isOrderingMode,
  isOverviewStageSummary,
  isPlatformRole,
  isPrincipalKind,
  isProcessRole,
  isProducerScopeAction,
  isProjectRole,
  isReceiptProfile,
  isReceiptVerificationState,
  isReplayOrderingStrategy,
  isReplayStrategy,
  isSignatureMode,
  mapHttpStatusToConsoleState
} from "@relayquill/domain";

test("Console resource states include all 12 canonical states and descriptors", () => {
  assert.equal(CONSOLE_RESOURCE_STATES.length, 12);
  assert.deepEqual(
    [...CONSOLE_RESOURCE_STATES],
    [
      "loading",
      "authorized_empty",
      "current",
      "refreshing",
      "stale",
      "unknown",
      "forbidden",
      "not_found",
      "conflict",
      "pressure",
      "unavailable",
      "expired_content"
    ]
  );

  for (const state of CONSOLE_RESOURCE_STATES) {
    assert.equal(isConsoleResourceState(state), true);
    const meta = getConsoleResourceStateDescriptor(state);
    assert.equal(meta, CONSOLE_RESOURCE_STATE_META[state]);
    assert.ok(meta.label.length > 0);
    assert.ok(meta.nonColorIndicator.length > 0);
  }
  assert.equal(isConsoleResourceState("bogus"), false);
  assert.equal(getConsoleResourceStateDescriptor("stale").allowsStaleData, true);
  assert.equal(getConsoleResourceStateDescriptor("stale").disablesMutations, true);
  assert.equal(getConsoleResourceStateDescriptor("loading").forbidsSyntheticZero, true);
  assert.equal(getConsoleResourceStateDescriptor("unavailable").forbidsSyntheticZero, true);
});

test("mapHttpStatusToConsoleState maps HTTP status and acceptance accurately", () => {
  assert.equal(mapHttpStatusToConsoleState(200), "current");
  assert.equal(mapHttpStatusToConsoleState(401), "forbidden");
  assert.equal(mapHttpStatusToConsoleState(403), "forbidden");
  assert.equal(mapHttpStatusToConsoleState(404), "not_found");
  assert.equal(mapHttpStatusToConsoleState(409), "conflict");
  assert.equal(mapHttpStatusToConsoleState(410), "expired_content");
  assert.equal(mapHttpStatusToConsoleState(429), "pressure");
  assert.equal(mapHttpStatusToConsoleState(503, "unknown"), "unknown");
  assert.equal(mapHttpStatusToConsoleState(503, "known_rejected"), "unavailable");
  assert.equal(mapHttpStatusToConsoleState(500), "unavailable");
});

test("Core domain enum guards accept canonical values and reject unknown ones", () => {
  assert.equal(isPrincipalKind("human"), true);
  assert.equal(isPrincipalKind("bot"), false);
  assert.equal(isPlatformRole("platform_admin"), true);
  assert.equal(isProjectRole("project_admin"), true);
  assert.equal(isChannelKind("human_workflow"), true);
  assert.equal(isEvidenceBoundary("consumer_processed"), true);
  assert.equal(isOverviewStageSummary("verified_receiver_receipt_observations"), true);
  assert.equal(isAcceptanceStatus("known_rejected"), true);
  assert.equal(isReceiptVerificationState("verified_supported"), true);
  assert.equal(isReceiptProfile("receiver_local_commit_v1"), true);
  assert.equal(isOrderingMode("strict_per_key"), true);
  assert.equal(isDeliveryPopulation("replay"), true);
  assert.equal(isDataGrantAction("events.content.read"), true);
  assert.equal(isProducerScopeAction("events.admit"), true);
  assert.equal(isContentAvailability("not_generated"), true);
  assert.equal(isContentView("wire"), true);
  assert.equal(isProcessRole("protected_admin"), true);
  assert.equal(isEndpointVerificationPurpose("verify_rotation_key"), true);
  assert.equal(isSignatureMode("bounded_dual_signature"), true);
  assert.equal(isReplayStrategy("replay_with_reviewed_representation"), true);
  assert.equal(isReplayOrderingStrategy("append_after_current_tail"), true);
  assert.equal(isEvidenceBoundary("unknown_future_value"), false);
});
