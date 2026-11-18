import test from "node:test";
import assert from "node:assert/strict";
import { ExpiredDomainError, ValidationDomainError } from "@relayquill/domain";
import {
  CURSOR_MAX_DECODED_BYTES,
  RESPONSE_SCHEMA_VERSION,
  WATCH_MAX_FRAME_BYTES,
  computeCursorFilterSha256,
  createSseChunkDecoder,
  decodeBase64UrlStrict,
  decodeCursor,
  encodeBase64Url,
  encodeCursor,
  encodeUtf8Bytes,
  formatSseFrame,
  formatSseHeartbeatFrame
} from "@relayquill/contracts";

const TENANT_ID = "00000000-0000-4000-8000-000000000101";
const PROJECT_ID = "00000000-0000-4000-8000-000000000105";
const OTHER_PROJECT_ID = "00000000-0000-4000-8000-000000000109";
const EVENT_ID = "00000000-0000-4000-8000-000000000205";

test("signed and validated cursors enforce <=1024B ceiling, scope/filter binding, and expiry", () => {
  const filterHash = computeCursorFilterSha256({ state: "accepted", limit: 25 });
  const signingKey = new Uint8Array(32).fill(0x2a);

  const expectedContext = {
    resource: "events",
    tenant_id: TENANT_ID,
    project_id: PROJECT_ID,
    order: "project_event_sequence_desc",
    filter_sha256: filterHash
  };

  const cursor = encodeCursor(
    {
      resource: "events",
      tenant_id: TENANT_ID,
      project_id: PROJECT_ID,
      parent_id: null,
      order: "project_event_sequence_desc",
      filter_sha256: filterHash,
      boundary: {
        sequence: "42",
        id: EVENT_ID,
        timestamp: "2026-11-01T12:00:00.000000Z"
      }
    },
    { signingKey }
  );

  const decodedBytes = decodeBase64UrlStrict(cursor);
  assert.ok(decodedBytes.length <= CURSOR_MAX_DECODED_BYTES);

  const decoded = decodeCursor(cursor, expectedContext, { signingKey });
  assert.equal(decoded.boundary.sequence, "42");
  assert.equal(decoded.boundary.id, EVENT_ID);

  // Wrong project, wrong filter, wrong signature, tampered payload all yield INVALID_CURSOR
  assert.throws(
    () => decodeCursor(cursor, { ...expectedContext, project_id: OTHER_PROJECT_ID }, { signingKey }),
    (err) => err instanceof ValidationDomainError && err.code === "INVALID_CURSOR"
  );
  assert.throws(
    () =>
      decodeCursor(
        cursor,
        { ...expectedContext, filter_sha256: computeCursorFilterSha256({ state: "retired" }) },
        { signingKey }
      ),
    (err) => err instanceof ValidationDomainError && err.code === "INVALID_CURSOR"
  );
  assert.throws(
    () => decodeCursor(cursor, expectedContext, { signingKey: new Uint8Array(32).fill(0x2b) }),
    (err) => err instanceof ValidationDomainError && err.code === "INVALID_CURSOR"
  );

  // Oversized (>1024B decoded) cursor is rejected
  const oversized = encodeBase64Url(new Uint8Array(CURSOR_MAX_DECODED_BYTES + 1).fill(0x7b));
  assert.throws(
    () => decodeCursor(oversized, expectedContext),
    (err) => err instanceof ValidationDomainError && err.code === "INVALID_CURSOR"
  );

  // Retained floor expiration yields CURSOR_EXPIRED
  assert.throws(
    () =>
      decodeCursor(cursor, expectedContext, {
        signingKey,
        retainedFloor: { min_sequence: 100n }
      }),
    (err) => err instanceof ExpiredDomainError && err.code === "CURSOR_EXPIRED"
  );
});

test("SSE watch formatter and chunked parser handle arbitrary splits, 8KiB ceiling, and unknown types", () => {
  const snapshotFrame = formatSseFrame({
    id: "cur-snap-1",
    payload: {
      response_schema_version: RESPONSE_SCHEMA_VERSION,
      frame_type: "snapshot",
      resource_kind: "event",
      resource_id: EVENT_ID,
      cursor: "cur-snap-1",
      high_water_sequence: "5",
      observed_at: "2026-11-01T12:00:00.123456Z",
      state: "fanout_in_progress",
      current_version: "2",
      summary: { note: "line1\nline2\u2028safe" }
    }
  });
  const heartbeat = formatSseHeartbeatFrame("ping");
  const eventFrame = formatSseFrame({
    id: "cur-evt-6",
    payload: {
      response_schema_version: RESPONSE_SCHEMA_VERSION,
      frame_type: "event",
      resource_kind: "event",
      resource_id: EVENT_ID,
      event_id: EVENT_ID,
      event_sequence: "6",
      event_type: "delivery.acknowledged",
      event_schema_version: 1,
      recorded_at: "2026-11-01T12:00:01.000000Z",
      safe_details: { delivery_generation: "0" }
    }
  });
  const futureAdditiveEvent = formatSseFrame({
    id: "cur-evt-7",
    payload: {
      response_schema_version: RESPONSE_SCHEMA_VERSION,
      frame_type: "event",
      resource_kind: "event",
      resource_id: EVENT_ID,
      event_id: EVENT_ID,
      event_sequence: "7",
      event_type: "future.additive_notice",
      event_schema_version: 1,
      recorded_at: "2026-11-01T12:00:02.000000Z",
      safe_details: {}
    }
  });
  const resyncFrame = formatSseFrame({
    payload: {
      response_schema_version: RESPONSE_SCHEMA_VERSION,
      frame_type: "resync_required",
      reason_code: "HISTORY_GAP",
      snapshot_path: `/api/v1/tenants/${TENANT_ID}/projects/${PROJECT_ID}/events/${EVENT_ID}`,
      recorded_at: "2026-11-01T12:00:03.000000Z"
    }
  });

  // Non-snapshot/event frame must reject id
  assert.throws(
    () =>
      formatSseFrame({
        id: "illegal-id",
        payload: {
          response_schema_version: RESPONSE_SCHEMA_VERSION,
          frame_type: "authorization_lost",
          reason_code: "SESSION_REVOKED",
          recorded_at: "2026-11-01T12:00:03.000000Z"
        }
      }),
    ValidationDomainError
  );

  // Oversized frame > 8192 bytes rejects
  assert.throws(
    () =>
      formatSseFrame({
        id: "cur-big",
        payload: {
          response_schema_version: RESPONSE_SCHEMA_VERSION,
          frame_type: "snapshot",
          resource_kind: "event",
          resource_id: EVENT_ID,
          cursor: "cur-big",
          high_water_sequence: "1",
          observed_at: "2026-11-01T12:00:00.000000Z",
          state: "accepted",
          current_version: "1",
          summary: { huge: "x".repeat(WATCH_MAX_FRAME_BYTES) }
        }
      }),
    ValidationDomainError
  );

  // Stream split across 7-byte chunks
  const fullStream = encodeUtf8Bytes(
    snapshotFrame +
      heartbeat +
      eventFrame +
      futureAdditiveEvent +
      resyncFrame +
      'event: snapshot\nid: cur-v99\ndata: {"response_schema_version":99,"frame_type":"snapshot"}\n\n'
  );
  const decoder = createSseChunkDecoder();
  const received = [];
  for (let i = 0; i < fullStream.length; i += 7) {
    received.push(...decoder.push(fullStream.subarray(i, i + 7)));
  }
  received.push(...decoder.finish());

  assert.equal(received.length, 6);
  assert.equal(received[0]?.supported, true);
  assert.equal(received[0]?.frame_type, "snapshot");
  assert.equal(received[1]?.frame_type, "heartbeat");
  assert.equal(received[2]?.frame_type, "event");
  if (received[2]?.supported && received[2].frame_type === "event") {
    assert.equal(received[2].data.supported_event_type, true);
  }
  assert.equal(received[3]?.supported, true);
  if (received[3]?.supported && received[3].frame_type === "event") {
    assert.equal(received[3].data.supported_event_type, false);
  }
  assert.equal(received[4]?.frame_type, "resync_required");
  assert.deepEqual(received[5], {
    supported: false,
    reason: "unsupported_response_schema_version",
    response_schema_version: 99,
    frame_type: "snapshot"
  });
});
