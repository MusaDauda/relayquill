import { describe, it } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  ProducerAcceptanceUnknownError,
  ProducerAuthError,
  ProducerConflictError,
  ProducerContextChangedError,
  ProducerValidationError,
  RelayquillProducerClient,
  createProducerClient,
  getEvent,
  getOriginalContent,
  getPublicationContext,
  listDeliveries,
  prepareEvent,
  resolvePreparedEvent,
  submitEvent,
  watchEvents
} from "../dist/index.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SRC_DIR = path.resolve(__dirname, "..", "src");

const TENANT_ID = "11111111-1111-4111-8111-111111111111";
const PROJECT_ID = "22222222-2222-4222-8222-222222222222";
const PRODUCER_ID = "33333333-3333-4333-8333-333333333333";
const PRINCIPAL_ID = "44444444-4444-4444-8444-444444444444";
const EVENT_TYPE_ID = "55555555-5555-4555-8555-555555555555";
const EVENT_ID = "66666666-6666-4666-8666-666666666666";
const RECEIPT_ID = "77777777-7777-4777-8777-777777777777";
const OUTBOX_ID = "88888888-8888-4888-8888-888888888888";
const SUBSCRIPTION_ID = "99999999-9999-4999-8999-999999999999";
const ENDPOINT_ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const DELIVERY_ID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";

function makeBearerToken() {
  return `rq_p1.${PRODUCER_ID}.${"A".repeat(43)}`;
}

function makePublicationContext(overrides = {}) {
  return {
    actor_kind: "producer",
    channel_enabled: true,
    channel_kind: "machine_producer",
    publication_channel_id: PRODUCER_ID,
    namespace: "billing",
    scope_version: "1",
    authority_epoch: "1",
    allowed_actions: ["events.admit", "events.resolve", "events.read_own", "events.content.read_own", "events.watch_own", "deliveries.read_own"],
    allowed_events: [
      {
        event_type_id: EVENT_TYPE_ID,
        event_type_name: "order.created",
        allowed_schema_versions: [1]
      }
    ],
    budgets: {
      max_encoded_body_bytes: 524288,
      max_decoded_content_bytes: 262144,
      default_delivery_window_ms: "3600000",
      max_delivery_window_ms: "86400000"
    },
    ...overrides
  };
}

function jsonResponse(status, bodyObj, headers = {}) {
  return {
    ok: status >= 200 && status <= 299,
    status,
    headers: new Headers({ "content-type": "application/json", ...headers }),
    async text() {
      return JSON.stringify(bodyObj);
    }
  };
}

function successEnvelope(data) {
  return {
    data,
    meta: {
      response_schema_version: 1,
      request_id: "01010101-0101-4101-8101-010101010101",
      observed_at: "2026-11-20T10:00:00.000000Z"
    }
  };
}

function errorEnvelope(code, message, extra = {}) {
  return {
    error: {
      code,
      message,
      retryable: extra.retryable ?? false,
      acceptance: extra.acceptance ?? "known_rejected",
      ...extra
    },
    meta: {
      response_schema_version: 1,
      request_id: "02020202-0202-4202-8202-020202020202",
      observed_at: "2026-11-20T10:00:00.000000Z"
    }
  };
}

describe("@relayquill/producer-sdk portability & prepareEvent", () => {
  it("uses zero node:* built-ins in source modules", () => {
    const files = fs.readdirSync(SRC_DIR).filter((f) => f.endsWith(".ts"));
    assert.ok(files.length > 0);
    for (const file of files) {
      const content = fs.readFileSync(path.join(SRC_DIR, file), "utf8");
      assert.equal(/["']node:/.test(content), false, `Found forbidden node:* import in ${file}`);
    }
  });

  it("prepares deterministic digests via Web Crypto and preserves exact lossless bytes", async () => {
    const rawText = '{"orderId":"ord-1","amount":  4200 }';
    const rawBytes = new TextEncoder().encode(rawText);

    const prepared = await prepareEvent({
      expectedPublicationChannelId: PRODUCER_ID,
      eventTypeId: EVENT_TYPE_ID,
      eventSchemaVersion: 1,
      businessKey: "ord-1",
      idempotencyKey: "idem-1",
      content: rawBytes,
      scope: {
        tenantId: TENANT_ID,
        projectId: PROJECT_ID,
        actorPrincipalId: PRINCIPAL_ID,
        channelKind: "machine_producer",
        producerNamespace: "billing"
      }
    });

    assert.equal(prepared.byteCount, rawBytes.byteLength);
    assert.match(prepared.contentSha256, /^[0-9a-f]{64}$/);
    assert.match(prepared.submittedShapeSha256 ?? "", /^[0-9a-f]{64}$/);
    assert.equal(prepared.producerPrepareDigest, prepared.submittedShapeSha256);

    // Mutate input buffer and returned copy -> internal bytes stay immutable
    rawBytes[0] = 0x20;
    const copy = prepared.getContentBytesCopy();
    assert.equal(new TextDecoder().decode(copy), rawText);
    copy[0] = 0x20;
    assert.equal(new TextDecoder().decode(prepared.getContentBytesCopy()), rawText);

    // Also validates no-scope prepare path
    const preparedNoScope = await prepareEvent({
      expectedPublicationChannelId: PRODUCER_ID,
      eventTypeId: EVENT_TYPE_ID,
      eventSchemaVersion: 1,
      businessKey: "ord-1",
      content: { kind: "json", value: { ok: true } }
    });
    assert.match(preparedNoScope.producerPrepareDigest, /^[0-9a-f]{64}$/);
    assert.equal(preparedNoScope.submittedShapeSha256, undefined);
  });
});

describe("@relayquill/producer-sdk HTTP lifecycle & typed errors", () => {
  it("executes submitEvent (201/200 with retry), resolvePreparedEvent, getEvent, getOriginalContent, listDeliveries, and getPublicationContext", async () => {
    const calls = [];
    let submitCount = 0;
    const contentRaw = '{"orderId":"ord-7"}';

    const shaZero = "0".repeat(64);
    const makeAcceptedEvent = () => ({
      event_id: EVENT_ID,
      event_type_id: EVENT_TYPE_ID,
      event_type: "order.created",
      event_schema_version: 1,
      publication_channel_id: PRODUCER_ID,
      namespace: "billing",
      business_key: "ord-7",
      accepted_at: "2026-11-20T10:00:00.000000Z",
      project_event_sequence: "1",
      topology_version: "1",
      original_content_sha256: shaZero,
      original_content_byte_count: 19,
      deadline_at: "2026-11-20T11:00:00.000000Z",
      state_at_acceptance: "accepted",
      producer_event_time: null,
      submitted_shape_sha256: shaZero,
      effective_request_sha256: shaZero,
      hash_schema_version: 1
    });
    const makeDefaults = () => ({
      delivery_window_ms: "3600000",
      deadline_at: "2026-11-20T11:00:00.000000Z",
      producer_event_time_present: false,
      deadline_at_present: false
    });
    const makeReceipt = () => ({
      id: RECEIPT_ID,
      accepted_at: "2026-11-20T10:00:00.000000Z",
      resource_kind: "event",
      resource_id: EVENT_ID,
      accepted_version: "1"
    });
    const makeCounts = (population) => ({
      unit: "delivery_generation",
      population,
      total_deliveries: "1",
      pending_count: "0",
      sending_count: "0",
      http_acknowledged_count: "1",
      dead_letter_count: "0",
      suppressed_count: "0",
      expired_count: "0",
      verified_receipt_count: "0"
    });

    const mockFetch = async (url, init) => {
      calls.push({ url, method: init?.method ?? "GET", headers: init?.headers ?? {}, body: init?.body });
      if (url.endsWith("/publication-context")) {
        return jsonResponse(200, successEnvelope(makePublicationContext()));
      }
      if (url.endsWith("/events") && init?.method === "POST") {
        submitCount += 1;
        if (submitCount === 1) {
          return jsonResponse(503, errorEnvelope("DEPENDENCY_UNAVAILABLE", "Try again", { retryable: true, acceptance: "unknown" }));
        }
        const status = submitCount === 2 ? 201 : 200;
        return jsonResponse(status, successEnvelope({
          receipt: makeReceipt(),
          event: makeAcceptedEvent(),
          applied_defaults: makeDefaults(),
          matched_existing: status === 200
        }));
      }
      if (url.endsWith("/events/resolve") && init?.method === "POST") {
        const parsed = JSON.parse(init.body);
        if (parsed.business_key === "missing") {
          return jsonResponse(404, errorEnvelope("NOT_FOUND", "Not found"));
        }
        return jsonResponse(200, successEnvelope({
          receipt: makeReceipt(),
          event: makeAcceptedEvent(),
          applied_defaults: makeDefaults(),
          fingerprint_verified: true,
          content_availability: {
            view: "original",
            availability: "available",
            media_type: "application/json",
            byte_count: 19,
            sha256: shaZero
          },
          current_observation: {
            current_version: "1",
            current_state: "accepted",
            observed_at: "2026-11-20T10:00:00.000000Z"
          }
        }));
      }
      if (url.endsWith(`/events/${EVENT_ID}`)) {
        return jsonResponse(200, successEnvelope({
          ...makeAcceptedEvent(),
          accepted_version: "1",
          current_version: "1",
          current_state: "accepted",
          observed_at: "2026-11-20T10:00:00.000000Z",
          fanout: {
            event_id: EVENT_ID,
            state: "completed",
            project_event_sequence: "1",
            topology_version: "1",
            examined_count: "1",
            matched_count: "1",
            delivery_count: "1",
            candidate_count: "1",
            last_progress_at: "2026-11-20T10:00:00.000000Z",
            completed_at: "2026-11-20T10:00:00.000000Z",
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
            original: makeCounts("original"),
            replay: makeCounts("replay"),
            all: makeCounts("all")
          },
          content_availability: {
            view: "original",
            availability: "available",
            media_type: "application/json",
            byte_count: 19,
            sha256: shaZero
          },
          capabilities: []
        }));
      }
      if (url.endsWith(`/events/${EVENT_ID}/content`)) {
        const bytes = new TextEncoder().encode(contentRaw);
        const contentSha = crypto.createHash("sha256").update(bytes).digest("hex");
        let bin = "";
        for (const b of bytes) bin += String.fromCharCode(b);
        return jsonResponse(200, successEnvelope({
          availability: "available",
          view: "original",
          media_type: "application/json",
          encoding: "base64",
          byte_count: bytes.byteLength,
          sha256: contentSha,
          data: btoa(bin)
        }));
      }
      if (url.includes("/deliveries")) {
        return jsonResponse(200, successEnvelope({
          items: [
            {
              delivery_id: DELIVERY_ID,
              family_id: OUTBOX_ID,
              event_id: EVENT_ID,
              delivery_generation: "1",
              is_replay: false,
              replay_proposal_id: null,
              subscription_id: SUBSCRIPTION_ID,
              original_subscription_version: "1",
              dispatch_subscription_version: "1",
              endpoint_id: ENDPOINT_ID,
              endpoint_version: "1",
              wire_envelope_id: OUTBOX_ID,
              representation_version: 1,
              consumer_event_key_sha256: shaZero,
              state: "acknowledged",
              execution_bucket: "acknowledged",
              blocking_reason: null,
              last_outcome_class: "acknowledged",
              attempt_count: 1,
              maximum_attempts: 12,
              prepared_attempt_count: 1,
              preparation_failure_count: 0,
              next_attempt_number: 2,
              deadline_at: "2026-11-20T11:00:00.000000Z",
              next_eligible_at: "2026-11-20T10:00:00.000000Z",
              acknowledged_at: "2026-11-20T10:00:01.000000Z",
              terminal_at: "2026-11-20T10:00:01.000000Z",
              current_version: "2",
              current_fence: "0",
              current_attempt_id: null,
              latest_response_summary: null,
              latest_receipt_summary: null
            }
          ],
          page: { limit: 20, has_more: false, next_cursor: null }
        }));
      }
      throw new Error(`Unexpected URL ${url}`);
    };

    const client = createProducerClient({
      baseUrl: "https://api.relayquill.example.com",
      tenantId: TENANT_ID,
      projectId: PROJECT_ID,
      getCredential: () => makeBearerToken(),
      fetch: mockFetch,
      retry: { maxAttempts: 3, baseDelayMs: 1, maxDelayMs: 5, totalBudgetMs: 2000 }
    });
    assert.ok(client instanceof RelayquillProducerClient);

    const ctx = await getPublicationContext(client);
    assert.equal(ctx.data.namespace, "billing");

    const prepared = await prepareEvent({
      publicationContext: ctx.data,
      eventTypeId: EVENT_TYPE_ID,
      eventSchemaVersion: 1,
      businessKey: "ord-7",
      idempotencyKey: "idem-7",
      content: contentRaw
    });

    // Submit retried cleanly on 503 then succeeded 201 with identical Idempotency-Key
    const submitted201 = await submitEvent(client, prepared, { verifyPublicationContext: true });
    assert.equal(submitted201.status, 201);
    assert.equal(submitted201.attempts, 2);

    const submitted200 = await submitEvent(client, prepared);
    assert.equal(submitted200.status, 200);
    assert.equal(submitted200.outcome, "replayed");

    // Resolve found + missing 404
    const resolvedOk = await resolvePreparedEvent(client, prepared);
    assert.equal(resolvedOk.found, true);

    const resolvedMissing = await resolvePreparedEvent(client, { businessKey: "missing" });
    assert.equal(resolvedMissing.found, false);
    assert.equal(resolvedMissing.status, 404);

    // Read operations
    const ev = await getEvent(client, EVENT_ID);
    assert.equal(ev.data.event_id, EVENT_ID);

    const orig = await getOriginalContent(client, EVENT_ID);
    assert.equal(new TextDecoder().decode(orig.bytes), contentRaw);

    const list = await listDeliveries(client, { eventId: EVENT_ID, limit: 20 });
    assert.equal(list.data.items.length, 1);

    // Mismatched publication channel throws ProducerContextChangedError
    const badPrepared = await prepareEvent({
      expectedPublicationChannelId: EVENT_ID,
      eventTypeId: EVENT_TYPE_ID,
      eventSchemaVersion: 1,
      businessKey: "ord-8",
      content: contentRaw
    });
    await assert.rejects(
      () => submitEvent(client, badPrepared, { verifyPublicationContext: true }),
      (err) => err instanceof ProducerContextChangedError
    );
  });

  it("maps HTTP/transport failures to typed errors and streams SSE frames via watchEvents", async () => {
    const authClient = createProducerClient({
      baseUrl: "https://api.relayquill.example.com",
      tenantId: TENANT_ID,
      projectId: PROJECT_ID,
      getCredential: () => makeBearerToken(),
      fetch: async () => jsonResponse(401, errorEnvelope("UNAUTHENTICATED", "Bad token")),
      retry: { maxAttempts: 1 }
    });
    await assert.rejects(
      () => authClient.getEvent(EVENT_ID),
      (err) => err instanceof ProducerAuthError
    );

    const conflictClient = createProducerClient({
      baseUrl: "https://api.relayquill.example.com",
      tenantId: TENANT_ID,
      projectId: PROJECT_ID,
      getCredential: () => makeBearerToken(),
      fetch: async () => jsonResponse(409, errorEnvelope("IDEMPOTENCY_CONFLICT", "Conflict")),
      retry: { maxAttempts: 1 }
    });
    const prepared = await prepareEvent({
      expectedPublicationChannelId: PRODUCER_ID,
      eventTypeId: EVENT_TYPE_ID,
      eventSchemaVersion: 1,
      businessKey: "ord-c",
      content: "{}"
    });
    await assert.rejects(
      () => conflictClient.submitEvent(prepared),
      (err) => err instanceof ProducerConflictError
    );

    const unknownClient = createProducerClient({
      baseUrl: "https://api.relayquill.example.com",
      tenantId: TENANT_ID,
      projectId: PROJECT_ID,
      getCredential: () => makeBearerToken(),
      fetch: async () => {
        throw new Error("socket hang up");
      },
      retry: { maxAttempts: 1 }
    });
    await assert.rejects(
      () => unknownClient.submitEvent(prepared),
      (err) => err instanceof ProducerAcceptanceUnknownError
    );

    // Validation error on invalid URL scheme
    assert.throws(
      () =>
        createProducerClient({
          baseUrl: "ftp://api.external.example.com",
          tenantId: TENANT_ID,
          projectId: PROJECT_ID,
          getCredential: () => makeBearerToken()
        }),
      (err) => err instanceof ProducerValidationError
    );

    // Watch SSE frame streaming
    const ssePayload = [
      `event: snapshot\nid: cur-1\ndata: ${JSON.stringify({ response_schema_version: 1, frame_type: "snapshot", resource_kind: "event", resource_id: EVENT_ID, cursor: "cur-1", high_water_sequence: "1", observed_at: "2026-11-20T10:00:00.000000Z", state: "accepted", current_version: "1", summary: {} })}\n\n`,
      `event: event\nid: cur-2\ndata: ${JSON.stringify({ response_schema_version: 1, frame_type: "event", resource_kind: "event", resource_id: EVENT_ID, event_id: EVENT_ID, event_sequence: "2", event_type: "delivery.acknowledged", event_schema_version: 1, recorded_at: "2026-11-20T10:00:01.000000Z", safe_details: {} })}\n\n`
    ].join("");

    const watchClient = createProducerClient({
      baseUrl: "https://api.relayquill.example.com",
      tenantId: TENANT_ID,
      projectId: PROJECT_ID,
      getCredential: () => makeBearerToken(),
      fetch: async () => ({
        ok: true,
        status: 200,
        headers: new Headers({ "content-type": "text/event-stream" }),
        body: new ReadableStream({
          start(controller) {
            controller.enqueue(new TextEncoder().encode(ssePayload));
            controller.close();
          }
        })
      })
    });

    const frames = [];
    const stream = watchEvents(watchClient, { eventId: EVENT_ID });
    for await (const frame of stream) {
      frames.push(frame);
    }
    assert.equal(frames.length, 2);
    assert.equal(frames[0].frameType, "snapshot");
    assert.equal(frames[1].frameType, "event");
    assert.equal(stream.getLastHandledCursor(), "cur-2");
  });
});
