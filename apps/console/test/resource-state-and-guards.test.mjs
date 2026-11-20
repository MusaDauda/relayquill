import test from "node:test";
import assert from "node:assert/strict";
import { CONSOLE_RESOURCE_STATES } from "@relayquill/domain";
import {
  buildScopedQueryKey,
  ScopedQueryCache
} from "../src/app/query-cache.js";
import { parseConsolePathname } from "../src/app/router.js";
import {
  buildScopePartitionKey,
  prepareEventAdmissionCommand,
  PreparedCommandMemoryStore
} from "../src/api/prepared-commands.js";
import {
  getResourceStateDescriptor,
  resourceStateFromApiError
} from "../src/features/resource-state/model.js";
import { evaluateProposalReviewerEligibility } from "../src/features/replays/replay-guards.js";

test("all 12 explicit resource states resolve descriptors cleanly and map HTTP failures accurately", () => {
  assert.equal(CONSOLE_RESOURCE_STATES.length, 12);
  for (const state of CONSOLE_RESOURCE_STATES) {
    const desc = getResourceStateDescriptor(state);
    assert.ok(desc.label.length > 0, `Missing label for ${state}`);
    assert.ok(desc.nonColorIndicator.length > 0, `Missing indicator for ${state}`);
    assert.ok(["loading", "healthy", "degraded", "error"].includes(desc.category));
    assert.ok(["status", "alert"].includes(desc.accessibilityRole));
  }

  const conflictView = resourceStateFromApiError({
    status: 409,
    code: "VERSION_CONFLICT",
    message: "Expected version 4, server has 5.",
    acceptance: "known_rejected",
    retryable: false,
    resourceRef: { kind: "endpoint", id: "00000000-0000-4000-8000-000000000099" },
    preservedDraft: { name: "preserved-draft" },
    currentServerState: { version: "5" }
  });
  assert.equal(conflictView.state, "conflict");
  if (conflictView.state === "conflict") {
    assert.deepEqual(conflictView.preservedDraft, { name: "preserved-draft" });
  }

  const unknownView = resourceStateFromApiError({
    status: 504,
    code: "GATEWAY_TIMEOUT",
    message: "Admission write outcome uncertain.",
    acceptance: "unknown",
    retryable: true
  });
  assert.equal(unknownView.state, "unknown");

  const authView = resourceStateFromApiError({
    status: 403,
    code: "FORBIDDEN",
    message: "Missing data grant.",
    acceptance: "known_rejected",
    retryable: false
  });
  assert.equal(authView.state, "forbidden");
});

test("ScopedQueryCache and PreparedCommandMemoryStore isolate per principal and scope", () => {
  const cache = new ScopedQueryCache();
  const keyA = buildScopedQueryKey({
    principalId: "00000000-0000-4000-8000-000000000001",
    tenantId: "00000000-0000-4000-8000-000000000010",
    projectId: "00000000-0000-4000-8000-000000000020",
    resource: "events",
    filter: "{}",
    projectionEligibility: "approved_project"
  });
  const keyB = buildScopedQueryKey({
    principalId: "00000000-0000-4000-8000-000000000001",
    tenantId: "00000000-0000-4000-8000-000000000011",
    projectId: "00000000-0000-4000-8000-000000000020",
    resource: "events",
    filter: "{}",
    projectionEligibility: "approved_project"
  });
  assert.notEqual(keyA, keyB);

  const ac = new AbortController();
  const scopeKeyA = "00000000-0000-4000-8000-000000000001:00000000-0000-4000-8000-000000000010:00000000-0000-4000-8000-000000000020";
  const scopeKeyB = "00000000-0000-4000-8000-000000000001:00000000-0000-4000-8000-000000000011:00000000-0000-4000-8000-000000000020";
  cache.setActiveScope(scopeKeyA);
  cache.registerController(scopeKeyA, ac);
  cache.setActiveScope(scopeKeyB);
  assert.equal(ac.signal.aborted, true);

  const store = new PreparedCommandMemoryStore();
  const principalA = "00000000-0000-4000-8000-000000000001";
  const principalB = "00000000-0000-4000-8000-000000000002";
  const tenantId = "00000000-0000-4000-8000-000000000010";
  const projectId = "00000000-0000-4000-8000-000000000020";
  const channelId = "00000000-0000-4000-8000-000000000030";
  const eventTypeId = "00000000-0000-4000-8000-000000000040";

  const cmdA = prepareEventAdmissionCommand({
    scope: {
      tenantId,
      projectId,
      publicationChannelId: channelId,
      channelKind: "human_workflow",
      actorPrincipalId: principalA,
      namespace: `human.${principalA}`
    },
    eventTypeId,
    eventSchemaVersion: 1,
    businessKey: "bk-1",
    idempotencyKey: "idem-key-1234567890",
    rawJsonText: '{"amount":9223372036854775807}'
  });
  const cmdB = prepareEventAdmissionCommand({
    scope: {
      tenantId,
      projectId,
      publicationChannelId: channelId,
      channelKind: "human_workflow",
      actorPrincipalId: principalB,
      namespace: `human.${principalB}`
    },
    eventTypeId,
    eventSchemaVersion: 1,
    businessKey: "bk-2",
    idempotencyKey: "idem-key-0987654321",
    rawJsonText: '{"amount":10}'
  });

  store.save(cmdA);
  store.save(cmdB);
  store.updateStatus(buildScopePartitionKey(principalA, tenantId, projectId), cmdA.idempotencyKey, {
    status: "acceptance_unknown"
  });
  assert.equal(store.listForScope(cmdA.scopeKey)[0]?.status, "acceptance_unknown");
  store.clearForPrincipal(principalA);
  assert.equal(store.listForScope(cmdA.scopeKey).length, 0);
  assert.equal(store.listForScope(cmdB.scopeKey).length, 1);
});

test("two-person proposal guard strictly enforces proposer !== reviewer", () => {
  const sameActor = evaluateProposalReviewerEligibility({
    proposalState: "proposed",
    proposerPrincipalId: "00000000-0000-4000-8000-000000000001",
    currentPrincipalId: "00000000-0000-4000-8000-000000000001",
    reviewAction: "replay_proposals.review",
    admitAction: "replay_proposals.admit",
    withdrawAction: "replay_proposals.withdraw"
  });
  assert.equal(sameActor.distinctReviewerSatisfied, false);
  assert.equal(sameActor.canReview, false);
  assert.match(sameActor.blockReason ?? "", /proposer !== current operator/i);

  const distinctReviewer = evaluateProposalReviewerEligibility({
    proposalState: "proposed",
    proposerPrincipalId: "00000000-0000-4000-8000-000000000001",
    currentPrincipalId: "00000000-0000-4000-8000-000000000002",
    capabilities: [
      { action: "replay_proposals.review", target_kind: "replay_proposal", available: true },
      { action: "replay_proposals.admit", target_kind: "replay_proposal", available: true }
    ],
    reviewAction: "replay_proposals.review",
    admitAction: "replay_proposals.admit"
  });
  assert.equal(distinctReviewer.distinctReviewerSatisfied, true);
  assert.equal(distinctReviewer.canReview, true);
  assert.equal(distinctReviewer.canAdmit, false);
});

test("parseConsolePathname validates canonical scope UUIDs and supports representations route", () => {
  const validRep = parseConsolePathname(
    "/t/00000000-0000-4000-8000-000000000010/p/00000000-0000-4000-8000-000000000020/representations"
  );
  assert.equal(validRep.kind, "project");
  if (validRep.kind === "project") {
    assert.equal(validRep.section, "representations");
  }

  const badUuid = parseConsolePathname("/t/not-a-uuid/p/00000000-0000-4000-8000-000000000020/events");
  assert.equal(badUuid.kind, "invalid_scope");

  const unknown = parseConsolePathname("/unknown-path");
  assert.equal(unknown.kind, "not_found");
});
