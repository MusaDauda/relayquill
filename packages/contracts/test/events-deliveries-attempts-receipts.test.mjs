import test from "node:test";
import assert from "node:assert/strict";
import { ValidationDomainError } from "@relayquill/domain";
import {
  deriveExternalAttemptOutcome,
  encodeBase64,
  encodeUtf8Bytes,
  parseAdmitEventRequest,
  parseAdmitEventResult,
  parseAttemptSummary,
  parseCreateReplayProposalRequest,
  parseDeliverySummary,
  parseEventDetail,
  parseReceiverReceiptObservation,
  parseResolveEventRequest,
  sha256Hex
} from "@relayquill/contracts";

const TENANT_ID = "00000000-0000-4000-8000-000000000101";
const PROJECT_ID = "00000000-0000-4000-8000-000000000105";
const EVENT_ID = "00000000-0000-4000-8000-000000000205";
const EVENT_TYPE_ID = "00000000-0000-4000-8000-000000000305";
const CHANNEL_ID = "00000000-0000-4000-8000-000000000405";
const OUTBOX_ID = "00000000-0000-4000-8000-000000000605";
const FAMILY_ID = "00000000-0000-4000-8000-000000000f05";
const DELIVERY_ID = "00000000-0000-4000-8000-000000001005";
const SUB_ID = "00000000-0000-4000-8000-000000000805";
const ENDPOINT_ID = "00000000-0000-4000-8000-000000000a05";
const WIRE_ID = "00000000-0000-4000-8000-000000000e05";
const ATTEMPT_ID = "00000000-0000-4000-8000-000000000c05";
const RECEIPT_ID = "00000000-0000-4000-8000-000000000d05";
const CONTRACT_ID = "00000000-0000-4000-8000-000000001105";
const EPOCH_ID = "00000000-0000-4000-8000-000000001205";
const OBS_ID = "00000000-0000-4000-8000-000000001305";

test("event admission, resolve, and event detail DTOs enforce option presence and observation separation", () => {
  const bytes = encodeUtf8Bytes('{"message":"hello"}');
  const b64 = encodeBase64(bytes);
  const digest = sha256Hex(bytes);

  const req = parseAdmitEventRequest({
    schema_version: 1,
    expected_publication_channel_id: CHANNEL_ID,
    event_type_id: EVENT_TYPE_ID,
    event_schema_version: 1,
    business_key: "sample-echo-001",
    content: {
      media_type: "application/json",
      encoding: "base64",
      data: b64
    }
  });
  assert.equal(req.content.sha256, digest);
  assert.equal(req.producer_event_time, undefined);

  // Explicit null for optional timestamps is invalid
  assert.throws(
    () =>
      parseAdmitEventRequest({
        schema_version: 1,
        expected_publication_channel_id: CHANNEL_ID,
        event_type_id: EVENT_TYPE_ID,
        event_schema_version: 1,
        business_key: "sample-echo-001",
        content: { media_type: "application/json", encoding: "base64", data: b64 },
        producer_event_time: null
      }),
    ValidationDomainError
  );

  const resolveReq = parseResolveEventRequest({
    schema_version: 1,
    business_key: "sample-echo-001",
    submitted_shape_sha256: digest
  });
  assert.equal(resolveReq.submitted_shape_sha256, digest);

  const acceptedEvent = {
    event_id: EVENT_ID,
    event_type_id: EVENT_TYPE_ID,
    event_type: "demo.echoed",
    event_schema_version: 1,
    publication_channel_id: CHANNEL_ID,
    namespace: "demo.machine",
    business_key: "sample-echo-001",
    accepted_at: "2026-11-01T12:00:00.000000Z",
    project_event_sequence: "1",
    topology_version: "1",
    original_content_sha256: digest,
    original_content_byte_count: 19,
    deadline_at: "2026-11-02T12:00:00.000000Z",
    state_at_acceptance: "accepted",
    producer_event_time: null,
    submitted_shape_sha256: digest,
    effective_request_sha256: digest,
    hash_schema_version: 1
  };

  const admitResult = parseAdmitEventResult({
    receipt: {
      id: RECEIPT_ID,
      accepted_at: "2026-11-01T12:00:00.000000Z",
      resource_kind: "event",
      resource_id: EVENT_ID,
      accepted_version: "1"
    },
    event: acceptedEvent,
    applied_defaults: {
      delivery_window_ms: "86400000",
      deadline_at: "2026-11-02T12:00:00.000000Z",
      producer_event_time_present: false,
      deadline_at_present: false
    },
    matched_existing: false
  });
  assert.equal(admitResult.matched_existing, false);

  const emptyCounts = (population) => ({
    unit: "delivery_generation",
    population,
    total_deliveries: "0",
    pending_count: "0",
    sending_count: "0",
    http_acknowledged_count: "0",
    dead_letter_count: "0",
    suppressed_count: "0",
    expired_count: "0",
    verified_receipt_count: "0"
  });

  const detail = parseEventDetail({
    ...acceptedEvent,
    accepted_version: "1",
    current_version: "2",
    current_state: "fanout_complete",
    observed_at: "2026-11-01T12:00:02.000000Z",
    fanout: {
      event_id: EVENT_ID,
      state: "completed",
      project_event_sequence: "1",
      topology_version: "1",
      examined_count: "1",
      matched_count: "1",
      delivery_count: "1",
      candidate_count: "1",
      last_progress_at: "2026-11-01T12:00:01.000000Z",
      completed_at: "2026-11-01T12:00:01.000000Z",
      project_materialized_through_event_sequence: "1"
    },
    publication: {
      outbox_id: OUTBOX_ID,
      current_publication_generation: "1",
      state: "published",
      next_publish_at: null,
      observation_state: "not_observed",
      first_observation: null,
      latest_observation: null,
      last_safe_error_code: null
    },
    delivery_counts: {
      original: emptyCounts("original"),
      replay: emptyCounts("replay"),
      all: emptyCounts("all")
    },
    content_availability: {
      view: "original",
      availability: "available",
      media_type: "application/json",
      byte_count: 19,
      sha256: digest
    },
    capabilities: []
  });
  assert.equal(detail.publication.observation_state, "not_observed");
});

test("delivery, replay proposal, attempt uncertainty, and receipt observation contracts", () => {
  const sha = "a".repeat(64);
  const delivery = parseDeliverySummary({
    delivery_id: DELIVERY_ID,
    family_id: FAMILY_ID,
    event_id: EVENT_ID,
    delivery_generation: "0",
    is_replay: false,
    replay_proposal_id: null,
    subscription_id: SUB_ID,
    original_subscription_version: "1",
    dispatch_subscription_version: "1",
    endpoint_id: ENDPOINT_ID,
    endpoint_version: "1",
    wire_envelope_id: WIRE_ID,
    representation_version: 1,
    consumer_event_key_sha256: sha,
    state: "retry_wait",
    execution_bucket: "pending",
    blocking_reason: null,
    last_outcome_class: "transport_unknown",
    attempt_count: 1,
    maximum_attempts: 12,
    prepared_attempt_count: 1,
    preparation_failure_count: 0,
    next_attempt_number: 2,
    deadline_at: "2026-11-02T12:00:00.000000Z",
    next_eligible_at: "2026-11-01T12:01:00.000000Z",
    acknowledged_at: null,
    terminal_at: null,
    current_version: "3",
    current_fence: "1",
    current_attempt_id: null,
    latest_response_summary: null,
    latest_receipt_summary: null
  });
  assert.equal(delivery.delivery_generation, "0");

  // Replay exact original cannot attach representation_profile_id
  assert.throws(
    () =>
      parseCreateReplayProposalRequest({
        schema_version: 1,
        expected_delivery_version: "3",
        target_subscription_version: "1",
        target_endpoint_version: "1",
        wire_envelope_id: WIRE_ID,
        strategy: "replay_exact_original",
        ordering_strategy: "not_applicable",
        requested_deadline_at: "2026-11-02T12:00:00.000000Z",
        consumer_event_key_sha256: sha,
        representation_profile_id: TENANT_ID,
        evidence_references: ["incident-1"],
        reason_code: "MANUAL_RETRY"
      }),
    ValidationDomainError
  );

  // Attempt external outcome derivation and validation
  assert.equal(
    deriveExternalAttemptOutcome({
      state: "deferred_before_send",
      send_started_at: null,
      response_status: null
    }),
    "not_started"
  );
  assert.equal(
    deriveExternalAttemptOutcome({
      state: "transport_unknown",
      send_started_at: "2026-11-01T12:00:02.000000Z",
      response_status: null
    }),
    "unknown"
  );
  assert.equal(
    deriveExternalAttemptOutcome({
      state: "response_observed",
      send_started_at: "2026-11-01T12:00:02.000000Z",
      response_status: 200
    }),
    "acknowledged"
  );

  const attempt = parseAttemptSummary({
    attempt_id: ATTEMPT_ID,
    delivery_id: DELIVERY_ID,
    attempt_number: 1,
    prepared_at: "2026-11-01T12:00:01.000000Z",
    send_started_at: "2026-11-01T12:00:02.000000Z",
    finished_at: "2026-11-01T12:00:12.000000Z",
    claim_expires_at: "2026-11-01T12:00:31.000000Z",
    request_deadline_at: "2026-11-01T12:00:12.000000Z",
    state: "transport_unknown",
    control_epoch: EPOCH_ID,
    fencing_token: "1",
    external_outcome: "unknown",
    response_status: null,
    outcome_class: "transport_unknown",
    safe_error_code: "DEPENDENCY_UNAVAILABLE",
    endpoint_id: ENDPOINT_ID,
    endpoint_version: "1",
    signing_policy_version: "1",
    wire_body_sha256: sha,
    response_body_sha256: null,
    response_byte_count: null
  });
  assert.equal(attempt.response_status, null);

  // Fabricated status 0 or acknowledged without 2xx status must reject
  assert.throws(
    () =>
      parseAttemptSummary({
        ...attempt,
        state: "response_observed",
        external_outcome: "acknowledged",
        response_status: 0
      }),
    ValidationDomainError
  );

  // Receiver receipt observation preserves committed_at=null and rejects secret/MAC fields
  const unverifiedReceipt = parseReceiverReceiptObservation({
    observation_id: OBS_ID,
    delivery_id: DELIVERY_ID,
    attempt_id: ATTEMPT_ID,
    receipt_reference: "http-ack-only",
    verification_state: "unverified",
    verification_profile_version: "http_ack_only",
    receiver_contract_id: CONTRACT_ID,
    receiver_contract_version: "1",
    receipt_facts_sha256: sha,
    observed_at: "2026-11-01T12:00:03.000000Z",
    committed_at: null,
    key_id: null
  });
  assert.equal(unverifiedReceipt.committed_at, null);

  assert.throws(
    () =>
      parseReceiverReceiptObservation({
        ...unverifiedReceipt,
        safe_receipt_facts: {
          receipt_version: 1,
          project_id: PROJECT_ID,
          event_id: EVENT_ID,
          consumer_event_key: sha,
          original_facts_sha256: sha,
          receipt_id: RECEIPT_ID,
          business_status: "committed",
          committed_at: "2026-11-01T12:00:03.000000Z",
          delivery_attempt_id: ATTEMPT_ID,
          key_id: "k1.primary",
          mac: "A".repeat(43)
        }
      }),
    ValidationDomainError
  );
});
