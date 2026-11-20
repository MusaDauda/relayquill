import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";
import {
  ClosedConnectionError,
  NoRespondersError,
  PermissionViolationError,
  TimeoutError,
  headers
} from "@nats-io/transport-node";
import { JetStreamApiError } from "@nats-io/jetstream";
import {
  ValidationDomainError,
  parseBrokerGenerationId,
  parseEventId,
  parseOutboxId,
  parseProjectId
} from "@relayquill/domain";
import {
  decodeBrokerNotificationEnvelope,
  encodeBrokerMessageId,
  encodeBrokerNotificationEnvelope,
  sha256Hex
} from "@relayquill/contracts";
import {
  BROKER_EVENT_MAX_PAYLOAD_BYTES,
  BROKER_EVENT_STREAM_NAME,
  BrokerCapacityError,
  BrokerPublishError,
  BrokerUnavailableError,
  DEFAULT_DEV_BROKER_TOPOLOGY,
  FANOUT_CONSUMER_NAME,
  InMemoryJetStreamBroker,
  NatsBrokerConnection,
  NatsBrokerConsumer,
  NatsBrokerPublisher,
  NatsJetStreamBrokerAdapter,
  classifyPublishError,
  createBrokerAdapter,
  extractTraceHeadersFromRecord,
  natsHeadersToRecord,
  sanitizeTraceHeadersForPublish,
  validateBrokerConnectionOptions,
  validatePubAckMetadata
} from "../dist/index.js";

const DEFAULT_PROJECT_ID = parseProjectId("00000000-0000-4000-8000-000000000001");
const VALID_TRACEPARENT = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
const VALID_TRACESTATE = "rq=tenant-a,vendor=skip-me";

function createTestEnvelope({
  outboxId = "10000000-0000-4000-8000-000000000001",
  eventId = "20000000-0000-4000-8000-000000000001",
  projectId = DEFAULT_PROJECT_ID,
  publicationGeneration = "1",
  traceparent = undefined,
  tracestate = undefined
} = {}) {
  const encoded = encodeBrokerNotificationEnvelope({
    outbox_id: parseOutboxId(outboxId),
    event_id: parseEventId(eventId),
    project_id: parseProjectId(projectId),
    topology_version: "1",
    publication_generation: publicationGeneration,
    content_sha256: sha256Hex(Buffer.from(`${outboxId}:${eventId}:${publicationGeneration}`, "utf8")),
    ...(traceparent !== undefined ? { traceparent } : {}),
    ...(tracestate !== undefined ? { tracestate } : {})
  });
  return {
    outboxId: encoded.envelope.outbox_id,
    projectId: encoded.envelope.project_id,
    publicationGeneration: encoded.envelope.publication_generation,
    envelopeBytes: encoded.bytes,
    msgId: encoded.broker_message_id,
    subject: encoded.subject
  };
}

function sha256BytesHex(bytes) {
  return crypto.createHash("sha256").update(bytes).digest("hex");
}

test("InMemoryJetStreamBroker enforces deterministic Nats-Msg-Id dedup within 120s window and allows post-window publish", async () => {
  let clockMs = 1_700_000_000_000;
  const broker = new InMemoryJetStreamBroker({ nowMs: () => clockMs });
  const env = createTestEnvelope();

  const first = await broker.publish({
    outboxId: env.outboxId,
    projectId: env.projectId,
    publicationGeneration: env.publicationGeneration,
    envelopeBytes: env.envelopeBytes
  });
  assert.equal(first.stream, BROKER_EVENT_STREAM_NAME);
  assert.equal(first.seq, 1);
  assert.equal(first.duplicate, false);
  assert.equal(first.msgId, encodeBrokerMessageId(env.outboxId, env.publicationGeneration));

  clockMs += 30_000;
  const dup = await broker.publish({
    outboxId: env.outboxId,
    projectId: env.projectId,
    publicationGeneration: env.publicationGeneration,
    envelopeBytes: env.envelopeBytes
  });
  assert.equal(dup.seq, 1);
  assert.equal(dup.duplicate, true);
  assert.equal(broker.getStreamStats()?.messages, 1);

  clockMs += 90_001;
  const afterWindow = await broker.publish({
    outboxId: env.outboxId,
    projectId: env.projectId,
    publicationGeneration: env.publicationGeneration,
    envelopeBytes: env.envelopeBytes
  });
  assert.equal(afterWindow.seq, 2);
  assert.equal(afterWindow.duplicate, false);
  assert.equal(broker.getStreamStats()?.messages, 2);

  await broker.close();
});

test("lost PubAck returns ACCEPTANCE_UNKNOWN and retry with same generation deduplicates cleanly", async () => {
  let clockMs = 1_700_000_000_000;
  const broker = new InMemoryJetStreamBroker({ nowMs: () => clockMs });
  const env = createTestEnvelope({
    outboxId: "10000000-0000-4000-8000-000000000010",
    eventId: "20000000-0000-4000-8000-000000000010",
    publicationGeneration: "1"
  });

  broker.dropNextPubAckAfterStore(1);

  await assert.rejects(
    async () =>
      broker.publish({
        outboxId: env.outboxId,
        projectId: env.projectId,
        publicationGeneration: env.publicationGeneration,
        envelopeBytes: env.envelopeBytes
      }),
    (err) =>
      err instanceof BrokerPublishError &&
      err.code === "ACCEPTANCE_UNKNOWN" &&
      err.acceptance === "unknown" &&
      err.classification === "publish_unknown"
  );

  assert.equal(broker.getStreamStats()?.messages, 1);

  clockMs += 2_000;
  const retry = await broker.publish({
    outboxId: env.outboxId,
    projectId: env.projectId,
    publicationGeneration: env.publicationGeneration,
    envelopeBytes: env.envelopeBytes
  });
  assert.equal(retry.seq, 1);
  assert.equal(retry.duplicate, true);

  const delivered = await broker.pullBatch({ maxBatch: 10, maxBytes: 65536, expiresMs: 1000 });
  assert.equal(delivered.length, 1);
  assert.equal(delivered[0]?.seq, 1);
  await delivered[0]?.ack();

  await broker.close();
});

test("InMemoryJetStreamBroker enforces DiscardNew capacity limits and max payload size", async () => {
  const broker = new InMemoryJetStreamBroker({
    maxMsgs: 2,
    maxBytes: 1024
  });

  const e1 = createTestEnvelope({
    outboxId: "10000000-0000-4000-8000-000000000021",
    eventId: "20000000-0000-4000-8000-000000000021"
  });
  const e2 = createTestEnvelope({
    outboxId: "10000000-0000-4000-8000-000000000022",
    eventId: "20000000-0000-4000-8000-000000000022"
  });
  const e3 = createTestEnvelope({
    outboxId: "10000000-0000-4000-8000-000000000023",
    eventId: "20000000-0000-4000-8000-000000000023"
  });

  await broker.publish({
    outboxId: e1.outboxId,
    projectId: e1.projectId,
    publicationGeneration: e1.publicationGeneration,
    envelopeBytes: e1.envelopeBytes
  });
  await broker.publish({
    outboxId: e2.outboxId,
    projectId: e2.projectId,
    publicationGeneration: e2.publicationGeneration,
    envelopeBytes: e2.envelopeBytes
  });

  await assert.rejects(
    async () =>
      broker.publish({
        outboxId: e3.outboxId,
        projectId: e3.projectId,
        publicationGeneration: e3.publicationGeneration,
        envelopeBytes: e3.envelopeBytes
      }),
    (err) =>
      err instanceof BrokerCapacityError &&
      err.code === "CAPACITY_EXCEEDED" &&
      err.acceptance === "known_rejected" &&
      err.classification === "capacity_exceeded"
  );

  const e1Gen2 = createTestEnvelope({
    outboxId: "10000000-0000-4000-8000-000000000021",
    eventId: "20000000-0000-4000-8000-000000000021",
    publicationGeneration: "2"
  });
  broker.forceStreamFull(true);
  await assert.rejects(
    async () =>
      broker.publish({
        outboxId: e1Gen2.outboxId,
        projectId: e1Gen2.projectId,
        publicationGeneration: e1Gen2.publicationGeneration,
        envelopeBytes: e1Gen2.envelopeBytes
      }),
    BrokerCapacityError
  );
  broker.forceStreamFull(false);

  const rawBroker = new InMemoryJetStreamBroker({ validateEnvelopePayload: false });
  const oversized = new Uint8Array(BROKER_EVENT_MAX_PAYLOAD_BYTES + 1);
  await assert.rejects(
    async () =>
      rawBroker.publish({
        outboxId: e1.outboxId,
        projectId: e1.projectId,
        publicationGeneration: "1",
        envelopeBytes: oversized
      }),
    (err) => err instanceof ValidationDomainError && err.code === "PAYLOAD_TOO_LARGE"
  );

  await broker.close();
  await rawBroker.close();
});

test("InMemoryJetStreamBroker consumer handles AckWait redelivery, working(), nak(delayMs), ackAck, term(), MaxDeliver, and MaxAckPending", async () => {
  let clockMs = 1_700_000_000_000;
  const broker = new InMemoryJetStreamBroker({
    nowMs: () => clockMs,
    ackWaitNs: 30_000_000_000,
    maxDeliver: 3,
    maxAckPending: 2,
    maxBatch: 8
  });

  const e1 = createTestEnvelope({
    outboxId: "10000000-0000-4000-8000-000000000031",
    eventId: "20000000-0000-4000-8000-000000000031"
  });
  const e2 = createTestEnvelope({
    outboxId: "10000000-0000-4000-8000-000000000032",
    eventId: "20000000-0000-4000-8000-000000000032"
  });
  const e3 = createTestEnvelope({
    outboxId: "10000000-0000-4000-8000-000000000033",
    eventId: "20000000-0000-4000-8000-000000000033"
  });

  for (const e of [e1, e2, e3]) {
    await broker.publish({
      outboxId: e.outboxId,
      projectId: e.projectId,
      publicationGeneration: e.publicationGeneration,
      envelopeBytes: e.envelopeBytes
    });
  }

  // MaxAckPending = 2 stops the 3rd message from delivering until pending shrinks
  const batch1 = await broker.pullBatch({ maxBatch: 8, maxBytes: 65536, expiresMs: 1000 });
  assert.equal(batch1.length, 2);
  assert.equal(batch1[0]?.deliveryCount, 1);
  assert.equal(batch1[0]?.redelivered, false);

  const emptyWhileFull = await broker.pullBatch({ maxBatch: 8, maxBytes: 65536, expiresMs: 1000 });
  assert.equal(emptyWhileFull.length, 0);

  // working() extends msg[0] AckWait deadline by another 30s
  clockMs += 20_000;
  await batch1[0]?.working();

  // At +30s total, msg[1] expired AckWait while msg[0] was extended to +50s
  clockMs += 10_000;
  await batch1[0]?.ack(); // ack seq 1 -> frees slot and settles seq 1

  const batch2 = await broker.pullBatch({ maxBatch: 8, maxBytes: 65536, expiresMs: 1000 });
  assert.equal(batch2.length, 2);
  // msg[1] (seq 2) redelivered due to AckWait expiry, msg[2] (seq 3) delivered first time
  const redeliveredMsg = batch2.find((m) => m.seq === 2);
  const freshMsg = batch2.find((m) => m.seq === 3);
  assert.ok(redeliveredMsg);
  assert.ok(freshMsg);
  assert.equal(redeliveredMsg.deliveryCount, 2);
  assert.equal(redeliveredMsg.redelivered, true);

  // term() on seq 3 stops redelivery immediately
  await freshMsg.term("poison_message");

  // nak(5000) schedules delayed redelivery for seq 2
  await redeliveredMsg.nak(5_000);
  const tooEarly = await broker.pullBatch({ maxBatch: 8, maxBytes: 65536, expiresMs: 1000 });
  assert.equal(tooEarly.length, 0);

  clockMs += 5_000;
  const batch3 = await broker.pullBatch({ maxBatch: 8, maxBytes: 65536, expiresMs: 1000 });
  assert.equal(batch3.length, 1);
  assert.equal(batch3[0]?.seq, 2);
  assert.equal(batch3[0]?.deliveryCount, 3); // equal to maxDeliver (3)

  // Drop ackAck once to verify ACK_CONFIRM_TIMEOUT rejects cleanly; after AckWait, MaxDeliver=3 exhausts
  broker.dropNextAck(1);
  await assert.rejects(
    async () => batch3[0]?.ackAck(),
    (err) => err instanceof BrokerUnavailableError && err.reasonCode === "ACK_CONFIRM_TIMEOUT"
  );

  clockMs += 30_000;
  const afterMaxDeliver = await broker.pullBatch({ maxBatch: 8, maxBytes: 65536, expiresMs: 1000 });
  assert.equal(afterMaxDeliver.length, 0);

  const stats = broker.getConsumerStats();
  assert.equal(stats?.acked, 1);
  assert.equal(stats?.terminated, 1);
  assert.equal(stats?.maxDeliverExceeded, 1);
  assert.equal(stats?.pending, 0);

  await broker.close();
});

test("trace header injection never mutates immutable envelope bytes and consumer safely extracts/strips baggage", async () => {
  const broker = new InMemoryJetStreamBroker({ allowedTracestateKeys: ["rq"] });
  const env = createTestEnvelope();
  const originalHash = sha256BytesHex(env.envelopeBytes);

  const defaultSanitized = sanitizeTraceHeadersForPublish({
    traceparent: VALID_TRACEPARENT,
    tracestate: VALID_TRACESTATE
  });
  assert.equal(defaultSanitized.traceparent, VALID_TRACEPARENT);
  assert.equal(defaultSanitized.tracestate, undefined);

  const sanitized = sanitizeTraceHeadersForPublish(
    {
      traceparent: VALID_TRACEPARENT,
      tracestate: VALID_TRACESTATE
    },
    { allowedVendorKeys: ["rq"] }
  );
  assert.equal(sanitized.traceparent, VALID_TRACEPARENT);
  assert.equal(sanitized.tracestate, "rq=tenant-a");

  await broker.publish({
    outboxId: env.outboxId,
    projectId: env.projectId,
    publicationGeneration: env.publicationGeneration,
    envelopeBytes: env.envelopeBytes,
    traceContext: {
      traceparent: VALID_TRACEPARENT,
      tracestate: VALID_TRACESTATE
    }
  });

  // Verify immutable bytes did not gain trace fields
  assert.equal(sha256BytesHex(env.envelopeBytes), originalHash);
  const decodedStored = decodeBrokerNotificationEnvelope(env.envelopeBytes);
  assert.equal(decodedStored.traceparent, undefined);

  const pulled = await broker.pullBatch({ maxBatch: 1, maxBytes: 65536, expiresMs: 1000 });
  assert.equal(pulled.length, 1);
  assert.equal(sha256BytesHex(pulled[0].payload), originalHash);
  assert.equal(pulled[0].headers.traceparent?.[0], VALID_TRACEPARENT);
  assert.equal(pulled[0].headers.tracestate?.[0], "rq=tenant-a");
  assert.equal(pulled[0].trace.suppliedValidTraceparent, true);
  assert.equal(pulled[0].trace.traceparent?.traceId, "4bf92f3577b34da6a3ce929d0e0e4736");
  assert.equal(pulled[0].trace.tracestate, "rq=tenant-a");
  await pulled[0].ack();

  // Direct extractTraceHeadersFromRecord strips baggage and safely rejects invalid/all-zero traceparent
  const extractedBad = extractTraceHeadersFromRecord({
    traceparent: ["00-00000000000000000000000000000000-00f067aa0ba902b7-01"],
    tracestate: ["rq=ok,bad=ignored"],
    baggage: ["secret=must-strip"]
  });
  assert.equal(extractedBad.suppliedValidTraceparent, false);
  assert.equal(extractedBad.baggageDropped, true);
  assert.ok(extractedBad.invalidReason !== undefined);

  const hdrs = headers();
  hdrs.append("TraceParent", VALID_TRACEPARENT);
  hdrs.append("Baggage", "secret=drop");
  const headerMap = natsHeadersToRecord(hdrs);
  const extractedGood = extractTraceHeadersFromRecord(headerMap);
  assert.equal(extractedGood.suppliedValidTraceparent, true);
  assert.equal(extractedGood.baggageDropped, true);

  await broker.close();
});

test("recovery stream recreation advances brokerGenerationId and consume() yields under AbortSignal + slot limits", async () => {
  const gen1 = parseBrokerGenerationId("11111111-1111-4111-8111-111111111111");
  const gen2 = parseBrokerGenerationId("22222222-2222-4222-8222-222222222222");
  const broker = await createBrokerAdapter({
    mode: "in_memory_test",
    brokerGenerationId: gen1
  });

  const env1 = createTestEnvelope({
    outboxId: "10000000-0000-4000-8000-000000000041",
    eventId: "20000000-0000-4000-8000-000000000041",
    publicationGeneration: "1"
  });
  const pub1 = await broker.publish({
    outboxId: env1.outboxId,
    projectId: env1.projectId,
    publicationGeneration: env1.publicationGeneration,
    envelopeBytes: env1.envelopeBytes,
    expectedBrokerGenerationId: gen1
  });
  assert.equal(pub1.brokerGenerationId, gen1);

  assert.equal(broker instanceof InMemoryJetStreamBroker, true);
  if (broker instanceof InMemoryJetStreamBroker) {
    const newGen = broker.recreateStreamForRecoveryTest(gen2);
    assert.equal(newGen, gen2);
    assert.equal(broker.brokerGenerationId, gen2);
  }

  await assert.rejects(
    async () =>
      broker.publish({
        outboxId: env1.outboxId,
        projectId: env1.projectId,
        publicationGeneration: "1",
        envelopeBytes: env1.envelopeBytes,
        expectedBrokerGenerationId: gen1
      }),
    (err) => err instanceof BrokerUnavailableError && err.reasonCode === "BROKER_GENERATION_MISMATCH"
  );

  // Re-emit under incremented publication_generation 2 on new broker stream generation
  const env2 = createTestEnvelope({
    outboxId: "10000000-0000-4000-8000-000000000041",
    eventId: "20000000-0000-4000-8000-000000000041",
    publicationGeneration: "2"
  });
  const pub2 = await broker.publish({
    outboxId: env2.outboxId,
    projectId: env2.projectId,
    publicationGeneration: env2.publicationGeneration,
    envelopeBytes: env2.envelopeBytes,
    expectedBrokerGenerationId: gen2
  });
  assert.equal(pub2.seq, 1);
  assert.equal(pub2.brokerGenerationId, gen2);

  let available = 1;
  const ac = new AbortController();
  const received = [];
  for await (const msg of broker.consume({
    maxBatch: 4,
    maxBytes: 65536,
    expiresMs: 1000,
    availableSlots: () => available,
    slotWaitMs: 5,
    idlePollDelayMs: 5,
    signal: ac.signal
  })) {
    received.push(msg);
    available = 0;
    await msg.ack();
    ac.abort();
  }
  assert.equal(received.length, 1);
  assert.equal(received[0]?.brokerGenerationId, gen2);
  assert.equal(received[0]?.msgId, encodeBrokerMessageId(env2.outboxId, "2"));

  const health = await broker.getHealth();
  assert.equal(health.healthy, true);
  assert.equal(health.brokerGenerationId, gen2);

  await broker.close();
});

test("NatsBrokerPublisher and NatsBrokerConsumer interact cleanly with JetStream mocks and classify errors", async () => {
  const genId = parseBrokerGenerationId("33333333-3333-4333-8333-333333333333");
  const env = createTestEnvelope();
  let publishedCall;

  const mockJs = {
    publish: async (subject, payload, opts) => {
      publishedCall = { subject, payload, opts };
      return {
        stream: BROKER_EVENT_STREAM_NAME,
        seq: 42,
        duplicate: false,
        domain: undefined
      };
    },
    consumers: {
      get: async (_stream, _consumer) => ({
        fetch: async (_pullOpts) => ({
          close: async () => undefined,
          async *[Symbol.asyncIterator]() {
            const msgHdrs = headers();
            msgHdrs.set("Nats-Msg-Id", env.msgId);
            msgHdrs.set("traceparent", VALID_TRACEPARENT);
            msgHdrs.set("baggage", "drop=me");
            yield {
              subject: env.subject,
              seq: 42,
              redelivered: false,
              data: env.envelopeBytes,
              headers: msgHdrs,
              info: {
                stream: BROKER_EVENT_STREAM_NAME,
                consumer: FANOUT_CONSUMER_NAME,
                deliveryCount: 1,
                deliverySequence: 7,
                pending: 0,
                timestampNanos: 1_700_000_000_000_000_000
              },
              ack: () => undefined,
              ackAck: async () => true,
              nak: () => undefined,
              working: () => undefined,
              term: () => undefined
            };
          }
        })
      })
    }
  };

  const publisher = new NatsBrokerPublisher({
    js: mockJs,
    brokerGenerationId: genId,
    subjectPrefix: "rq.prod.",
    allowedTracestateKeys: ["rq"]
  });
  const pubRes = await publisher.publish({
    outboxId: env.outboxId,
    projectId: env.projectId,
    publicationGeneration: env.publicationGeneration,
    envelopeBytes: env.envelopeBytes,
    traceContext: {
      traceparent: VALID_TRACEPARENT,
      tracestate: "rq=v1,other=ignore"
    }
  });
  assert.equal(pubRes.seq, 42);
  assert.equal(pubRes.duplicate, false);
  assert.equal(publishedCall.subject, `rq.prod.rq.events.${env.projectId}.accepted`);
  assert.equal(publishedCall.opts?.msgID, env.msgId);
  assert.equal(publishedCall.opts?.headers?.get("traceparent"), VALID_TRACEPARENT);
  assert.equal(publishedCall.opts?.headers?.get("tracestate"), "rq=v1");

  const consumer = new NatsBrokerConsumer({
    js: mockJs,
    brokerGenerationId: genId
  });
  const pulled = await consumer.pullBatch({ maxBatch: 8, maxBytes: 32768, expiresMs: 1000 });
  assert.equal(pulled.length, 1);
  assert.equal(pulled[0]?.seq, 42);
  assert.equal(pulled[0]?.deliverySequence, 7);
  assert.equal(pulled[0]?.trace.suppliedValidTraceparent, true);
  assert.equal(pulled[0]?.trace.baggageDropped, true);
  assert.equal(await pulled[0]?.ackAck(), true);

  // Error classifications and PubAck validation
  assert.throws(
    () => validatePubAckMetadata({ stream: "WRONG_STREAM", seq: 1, duplicate: false }, BROKER_EVENT_STREAM_NAME, env.msgId),
    (err) => err instanceof BrokerUnavailableError && err.reasonCode === "STREAM_NAME_MISMATCH"
  );
  assert.throws(
    () => validatePubAckMetadata({ stream: BROKER_EVENT_STREAM_NAME, seq: 0, duplicate: false }, BROKER_EVENT_STREAM_NAME, env.msgId),
    (err) => err instanceof ValidationDomainError && err.code === "INVALID_INT64"
  );

  assert.equal(
    classifyPublishError(new TimeoutError(), { stream: BROKER_EVENT_STREAM_NAME, subject: env.subject, msgId: env.msgId }) instanceof BrokerPublishError,
    true
  );
  assert.equal(
    classifyPublishError(new JetStreamApiError({ code: 500, err_code: 10077, description: "maximum messages exceeded" }), { stream: BROKER_EVENT_STREAM_NAME, subject: env.subject, msgId: env.msgId }) instanceof BrokerCapacityError,
    true
  );
  assert.equal(
    classifyPublishError(new NoRespondersError(), { stream: BROKER_EVENT_STREAM_NAME, subject: env.subject, msgId: env.msgId }) instanceof BrokerUnavailableError,
    true
  );
  assert.equal(
    classifyPublishError(new ClosedConnectionError("closed"), { stream: BROKER_EVENT_STREAM_NAME, subject: env.subject, msgId: env.msgId }) instanceof BrokerPublishError,
    true
  );
  assert.equal(
    classifyPublishError(new PermissionViolationError("denied"), { stream: BROKER_EVENT_STREAM_NAME, subject: env.subject, msgId: env.msgId }) instanceof BrokerUnavailableError,
    true
  );

  await consumer.close();
  await publisher.close();
});

test("NatsJetStreamBrokerAdapter exposes unified publish, pullBatch, getHealth, and drain-on-close lifecycle", async () => {
  const genId = parseBrokerGenerationId("44444444-4444-4444-8444-444444444444");
  const env = createTestEnvelope();
  let drained = false;
  let closed = false;

  const mockNc = {
    options: { inboxPrefix: "_INBOX" },
    info: { jetstream: true, tls_required: false, max_payload: 65536 },
    isClosed: () => closed,
    isDraining: () => drained,
    getServer: () => "nats://127.0.0.1:4222",
    status: () => ({
      async *[Symbol.asyncIterator]() {
        // empty
      }
    }),
    drain: async () => {
      drained = true;
      closed = true;
    },
    close: async () => {
      closed = true;
    }
  };

  const mockJs = {
    publish: async () => ({ stream: BROKER_EVENT_STREAM_NAME, seq: 9, duplicate: false }),
    consumers: {
      get: async () => ({
        fetch: async () => ({
          close: async () => undefined,
          async *[Symbol.asyncIterator]() {
            yield {
              subject: env.subject,
              seq: 9,
              redelivered: false,
              data: env.envelopeBytes,
              headers: headers(),
              info: {
                stream: BROKER_EVENT_STREAM_NAME,
                consumer: FANOUT_CONSUMER_NAME,
                deliveryCount: 1,
                deliverySequence: 1,
                pending: 0,
                timestampNanos: 1_700_000_000_000_000_000
              },
              ack: () => undefined,
              ackAck: async () => true,
              nak: () => undefined,
              working: () => undefined,
              term: () => undefined
            };
          }
        })
      })
    }
  };

  const spec = validateBrokerConnectionOptions({
    mode: "development_loopback",
    servers: ["nats://127.0.0.1:4222"],
    authMode: "none_fixture"
  });
  const connection = new NatsBrokerConnection({
    nc: mockNc,
    js: mockJs,
    spec,
    brokerGenerationId: genId
  });
  const adapter = new NatsJetStreamBrokerAdapter({
    connection,
    publisher: new NatsBrokerPublisher({ js: mockJs, brokerGenerationId: genId }),
    consumer: new NatsBrokerConsumer({ js: mockJs, brokerGenerationId: genId }),
    topologyContract: DEFAULT_DEV_BROKER_TOPOLOGY
  });

  const healthBefore = await adapter.getHealth();
  assert.equal(healthBefore.healthy, true);
  assert.equal(healthBefore.mode, "development_loopback");
  assert.equal(healthBefore.encrypted, false);
  assert.deepEqual(healthBefore.connectedServers, ["nats://127.0.0.1:4222"]);
  assert.equal(healthBefore.brokerGenerationId, genId);

  const pub = await adapter.publish({
    outboxId: env.outboxId,
    projectId: env.projectId,
    publicationGeneration: env.publicationGeneration,
    envelopeBytes: env.envelopeBytes
  });
  assert.equal(pub.seq, 9);

  const msgs = await adapter.pullBatch({ maxBatch: 4, maxBytes: 32768, expiresMs: 1000 });
  assert.equal(msgs.length, 1);
  assert.equal(msgs[0]?.seq, 9);
  await msgs[0]?.ack();

  await adapter.close();
  assert.equal(drained, true);
  assert.equal(connection.isClosed, true);
});
