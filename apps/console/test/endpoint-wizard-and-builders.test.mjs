import test from "node:test";
import assert from "node:assert/strict";
import {
  createInitialEndpointWizardState,
  getEndpointWizardStepEligibility,
  transitionEndpointWizardStep,
  updateEndpointWizardDraft,
  validateCustodyReferenceId,
  validateNormalizedHttpsUrl
} from "../src/features/endpoints/endpoint-wizard.js";
import {
  evaluateFilterOnLosslessJson,
  FILTER_PROFILE_VERSION,
  validateFilterDefinition
} from "../src/features/subscriptions/filter-ast.js";
import {
  applyLosslessProjectionSpec,
  PROJECTION_PROFILE_VERSION,
  validateProjectionSpec
} from "../src/features/schemas/projection-mapper.js";

test("6-step endpoint onboarding wizard enforces validation, step ordering, and downstream invalidation", () => {
  assert.equal(validateNormalizedHttpsUrl("http://example.com/hook").valid, false);
  assert.equal(validateNormalizedHttpsUrl("https://127.0.0.1/hook").valid, false);
  assert.equal(validateNormalizedHttpsUrl("https://user:pass@partner.example/hook").valid, false);
  const okUrl = validateNormalizedHttpsUrl("https://webhooks.partner.example/v1/relayquill");
  assert.equal(okUrl.valid, true);
  assert.equal(okUrl.normalizedHost, "webhooks.partner.example");

  assert.notEqual(
    validateCustodyReferenceId("rq_p1.00000000-0000-4000-8000-000000000001.secret123", "Sender ref"),
    null
  );
  assert.equal(validateCustodyReferenceId("custody-sender-prod-01", "Sender ref"), null);

  let state = createInitialEndpointWizardState();
  state = updateEndpointWizardDraft(state, {
    name: "Partner Webhook",
    destinationUrl: "https://webhooks.partner.example/hook"
  });
  assert.equal(getEndpointWizardStepEligibility(state, 2).allowed, false);

  // Simulate steps 1 -> 5 completed
  state = {
    ...state,
    endpointId: "ep-1",
    endpointVersion: "1",
    configurationSha256: "a".repeat(64),
    keyVersionId: "kv-1",
    draft: { ...state.draft, receiverReadinessAck: true },
    signingPolicyId: "sp-1",
    verificationIntentId: "vi-1",
    verificationPassed: true,
    verificationProofSha256: "b".repeat(64),
    currentStep: 5
  };
  assert.equal(getEndpointWizardStepEligibility(state, 6).allowed, true);
  state = transitionEndpointWizardStep(state, 6);
  assert.equal(state.currentStep, 6);

  // Changing policy invalidates verification proof and jumps back to step 3
  const afterPolicyEdit = updateEndpointWizardDraft(state, {
    signatureMode: "bounded_dual_signature"
  });
  assert.equal(afterPolicyEdit.signingPolicyId, null);
  assert.equal(afterPolicyEdit.verificationPassed, false);
  assert.equal(afterPolicyEdit.currentStep, 3);

  // Changing destination URL invalidates everything back to step 1
  const afterUrlEdit = updateEndpointWizardDraft(state, {
    destinationUrl: "https://webhooks2.partner.example/hook"
  });
  assert.equal(afterUrlEdit.endpointId, null);
  assert.equal(afterUrlEdit.keyVersionId, null);
  assert.equal(afterUrlEdit.currentStep, 1);
});

test("relayquill.filter.v1 AST builder validates bounds and evaluates lossless integers", () => {
  const filterDef = {
    version: FILTER_PROFILE_VERSION,
    root: {
      op: "and",
      children: [
        { op: "eq", pointer: "/currency", value: "USD" },
        { op: "in", pointer: "/tier", values: ["gold", "enterprise"] },
        { op: "exists", pointer: "/seq", value: true }
      ]
    }
  };
  assert.deepEqual(validateFilterDefinition(filterDef), []);

  const matchRes = evaluateFilterOnLosslessJson(
    filterDef,
    '{"currency":"USD","tier":"enterprise","seq":9223372036854775807}'
  );
  assert.equal(matchRes.matched, true);

  const deepErrors = validateFilterDefinition({
    version: FILTER_PROFILE_VERSION,
    root: {
      op: "not",
      child: {
        op: "not",
        child: {
          op: "not",
          child: {
            op: "not",
            child: {
              op: "not",
              child: { op: "exists", pointer: "/x", value: true }
            }
          }
        }
      }
    }
  });
  assert.ok(deepErrors.some((e) => /depth exceeds/i.test(e)));
});

test("relayquill.lossless-projection.v1 preserves 64-bit ints and trailing-zero decimals", () => {
  const spec = {
    profile_version: PROJECTION_PROFILE_VERSION,
    mappings: [
      { op: "copy", sourcePointer: "/seq", targetPointer: "/ledger/seq" },
      { op: "copy", sourcePointer: "/rate", targetPointer: "/ledger/rate" },
      { op: "copy_or_default", sourcePointer: "/missing", targetPointer: "/region", defaultValue: "us" },
      { op: "constant", targetPointer: "/version", value: "v2" }
    ]
  };
  assert.deepEqual(validateProjectionSpec(spec), []);

  const applied = applyLosslessProjectionSpec(
    spec,
    '{"seq":9223372036854775807,"rate":0.0825000}'
  );
  assert.equal(applied.ok, true);
  assert.match(applied.outputJsonText ?? "", /9223372036854775807/);
  assert.match(applied.outputJsonText ?? "", /0\.0825000/);
  assert.match(applied.outputJsonText ?? "", /"region": "us"/);

  const overlapErrors = validateProjectionSpec({
    profile_version: PROJECTION_PROFILE_VERSION,
    mappings: [
      { op: "constant", targetPointer: "/a", value: "1" },
      { op: "constant", targetPointer: "/a/b", value: "2" }
    ]
  });
  assert.ok(overlapErrors.some((e) => /overlapping/i.test(e)));
});
