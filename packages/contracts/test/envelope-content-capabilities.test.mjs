import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  DOMAIN_ERROR_CODES,
  DependencyUnavailableDomainError,
  InvariantViolationError,
  ValidationDomainError
} from "@relayquill/domain";
import {
  CAPABILITY_ACTIONS,
  RESPONSE_SCHEMA_VERSION,
  classifyResponseEnvelope,
  createErrorEnvelope,
  createPaginatedData,
  createSuccessEnvelope,
  encodeBase64,
  encodeUtf8Bytes,
  findCapability,
  isCapabilityAvailable,
  mapDomainErrorCodeToHttpStatus,
  parseCapabilities,
  parseCapabilityEntry,
  parseContentAvailabilityMetadata,
  parseDeliveryRequestContentDto,
  parseErrorEnvelope,
  parseEventContentDto,
  parseEventContentInput,
  parseEventRepresentationSummary,
  parsePaginatedData,
  parseSuccessEnvelope,
  projectCapability,
  sha256Hex
} from "@relayquill/contracts";

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");
const COMPAT_VECTORS = JSON.parse(
  fs.readFileSync(path.join(REPO_ROOT, "contracts/compatibility/vectors.json"), "utf8")
);

const PROJECT_ID = "00000000-0000-4000-8000-000000000105";
const EVENT_ID = "00000000-0000-4000-8000-000000000205";
const WIRE_ID = "00000000-0000-4000-8000-000000000e05";
const PROFILE_ID = "00000000-0000-4000-8000-000000000705";

test("success, paginated, and error/acceptance envelopes conform to compatibility vectors", () => {
  const success = createSuccessEnvelope(
    createPaginatedData({
      items: [{ id: EVENT_ID }],
      next_cursor: null,
      limit: 25
    }),
    {
      request_id: "req-env-001",
      observed_at: "2026-11-01T12:00:00.123456Z"
    }
  );
  assert.equal(success.meta.response_schema_version, RESPONSE_SCHEMA_VERSION);
  assert.equal(success.data.page.next_cursor, null);
  assert.equal("total" in success.data.page, false);

  const parsedSuccess = parseSuccessEnvelope(success, (raw) =>
    parsePaginatedData(raw, (item) => item)
  );
  assert.equal(parsedSuccess.data.items.length, 1);

  for (const vec of COMPAT_VECTORS.error_acceptance_vectors) {
    const parsedErr = parseErrorEnvelope(vec);
    assert.equal(parsedErr.error.acceptance, vec.error.acceptance);
  }

  const depErr = new DependencyUnavailableDomainError({
    message: "Broker reply timed out",
    boundary: "published"
  });
  const errEnv = createErrorEnvelope(depErr, {
    request_id: "req-dep-001",
    observed_at: "2026-11-01T12:00:01.000000Z"
  });
  assert.equal(errEnv.error.acceptance, "unknown");
  assert.equal(errEnv.error.retryable, true);
  assert.equal(errEnv.error.boundary, "published");

  const invErr = new InvariantViolationError({ message: "bad transition" });
  assert.equal(invErr.acceptance, "not_applicable");

  // Unknown future response_schema_version must surface explicit unsupported classification
  const futureClassified = classifyResponseEnvelope(
    COMPAT_VECTORS.unsupported_future_response_vector,
    (x) => x
  );
  assert.deepEqual(futureClassified, {
    supported: false,
    reason: "unsupported_response_schema_version",
    response_schema_version: 99
  });

  // Every domain error code has an explicit HTTP status mapping
  for (const code of DOMAIN_ERROR_CODES) {
    const status = mapDomainErrorCodeToHttpStatus(code);
    assert.ok(status >= 400 && status <= 599);
  }
});

test("content input, views, availability states, and representations enforce invariants", () => {
  const bytes = encodeUtf8Bytes('{"message":"hello"}');
  const b64 = encodeBase64(bytes);
  const digest = sha256Hex(bytes);

  const parsedInput = parseEventContentInput({
    media_type: "application/json",
    encoding: "base64",
    data: b64,
    sha256: digest
  });
  assert.equal(parsedInput.byte_count, 19);
  assert.equal(parsedInput.sha256, digest);

  // Mismatched declared SHA-256 or empty payload rejects
  assert.throws(
    () =>
      parseEventContentInput({
        media_type: "application/json",
        encoding: "base64",
        data: b64,
        sha256: "0".repeat(64)
      }),
    ValidationDomainError
  );
  assert.throws(
    () =>
      parseEventContentInput({
        media_type: "application/json",
        encoding: "base64",
        data: ""
      }),
    ValidationDomainError
  );

  // Explicit availability states
  for (const availability of ["available", "expired", "not_generated", "unsupported", "unavailable"]) {
    const meta = parseContentAvailabilityMetadata({
      view: availability === "not_generated" ? "derived" : "original",
      representation_version: availability === "not_generated" ? 2 : 1,
      availability,
      media_type: "application/json",
      byte_count: availability === "available" || availability === "expired" ? 19 : null,
      sha256: availability === "available" || availability === "expired" ? digest : null
    });
    assert.equal(meta.availability, availability);
  }

  // derived view is invalid for representation_version 1
  assert.throws(
    () =>
      parseEventContentDto({
        view: "derived",
        availability: "available",
        representation_version: 1,
        media_type: "application/json",
        encoding: "base64",
        byte_count: 19,
        sha256: digest,
        data: b64
      }),
    ValidationDomainError
  );

  const wireContent = parseDeliveryRequestContentDto({
    representation_version: 1,
    wire_envelope_id: WIRE_ID,
    media_type: "application/json",
    encoding: "base64",
    byte_count: 19,
    sha256: digest,
    data: b64,
    availability: "available"
  });
  assert.equal(wireContent.wire_envelope_id, WIRE_ID);

  const repSummary = parseEventRepresentationSummary({
    wire_envelope_id: WIRE_ID,
    representation_version: 2,
    profile_id: PROFILE_ID,
    profile_version: "1",
    target_schema_version: 1,
    source_content_sha256: digest,
    derived_content_sha256: digest,
    body_sha256: digest,
    byte_count: 19,
    availability: "available",
    retention_state: "required",
    created_at: "2026-11-01T12:00:00.000000Z"
  });
  assert.equal(repSummary.representation_version, 2);
});

test("capability projections enforce step-up, distinct reviewer, and disallow protected repair", () => {
  const reviewCap = projectCapability({
    action: "replay_proposals.review",
    target_id: PROJECT_ID,
    expected_version: 1n,
    available: true
  });
  assert.equal(reviewCap.requires_step_up, true);
  assert.equal(reviewCap.requires_distinct_reviewer, true);
  assert.equal(reviewCap.reason_code, null);

  const blockedCap = projectCapability({
    action: "events.content.read",
    target_id: EVENT_ID,
    expected_version: null,
    available: false,
    reason_code: "DATA_GRANT_REQUIRED"
  });

  const list = parseCapabilities([reviewCap, blockedCap]);
  assert.equal(isCapabilityAvailable(list, "replay_proposals.review"), true);
  assert.equal(isCapabilityAvailable(list, "events.content.read"), false);
  assert.equal(findCapability(list, "events.content.read")?.reason_code, "DATA_GRANT_REQUIRED");

  // Unavailable capability without reason_code must reject
  assert.throws(
    () =>
      projectCapability({
        action: "events.content.read",
        target_id: EVENT_ID,
        expected_version: null,
        available: false
      }),
    ValidationDomainError
  );

  // Protected repair / cloud recovery actions are never in CAPABILITY_ACTIONS
  assert.equal(CAPABILITY_ACTIONS.includes("repair.establish_target_epoch"), false);
  assert.throws(
    () =>
      parseCapabilityEntry({
        action: "repair.establish_target_epoch",
        target_kind: "installation",
        target_id: PROJECT_ID,
        expected_version: "1",
        available: true,
        reason_code: null,
        requires_step_up: true,
        requires_distinct_reviewer: false
      }),
    ValidationDomainError
  );

  // Step-up downgrade attempt rejects
  assert.throws(
    () =>
      parseCapabilityEntry({
        ...reviewCap,
        requires_step_up: false
      }),
    ValidationDomainError
  );
});
