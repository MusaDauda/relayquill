import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  nowUtcInstant,
  parseBrokerGenerationId,
  parseCommandReceiptId,
  parseEndpointId,
  parseEventId,
  parseEventPayloadId,
  parseEventTypeId,
  parseOutboxId,
  parsePrincipalId,
  parseProducerId,
  parseProjectId,
  parsePublicationRecoveryEpisodeId,
  parseRuntimeInstanceId,
  parseSha256Hex,
  parseSubscriptionId,
  parseTenantId,
  parseWireEnvelopeId
} from "@relayquill/domain";
import { encodeBrokerNotificationEnvelope } from "@relayquill/contracts";
import { InMemoryJetStreamBroker } from "@relayquill/broker";
import {
  admitEvent,
  createPGliteAdapter,
  readInstallationStatus
} from "@relayquill/postgres";
import {
  createRelayHealthServer,
  createRelayWorker,
  parseRelayCliArgs
} from "../dist/index.js";

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");

function shaHex(data) {
  return parseSha256Hex(crypto.createHash("sha256").update(data).digest("hex"));
}

function shaBytes(data) {
  return crypto.createHash("sha256").update(data).digest();
}

async function applyMigrations(db) {
  const dir = path.join(REPO_ROOT, "migrations");
  const files = fs
    .readdirSync(dir)
    .filter((f) => f.endsWith(".sql"))
    .sort();
  for (const file of files) {
    await db.exec(fs.readFileSync(path.join(dir, file), "utf8"));
  }
}

async function seedFixtureBase(db, brokerGenerationId) {
  await db.exec(`
    UPDATE rq.installation_state
       SET mode = 'open',
           allow_event_admission = true,
           allow_publication = true,
           allow_fanout = true,
           allow_send = true,
           allow_endpoint_verification = true,
           version = version + 1
     WHERE id = 1;
  `);

  const status = await db.withTransaction("rq_api", (tx) => readInstallationStatus(tx));
  const ids = {
    controlEpoch: status.controlEpoch,
    tenantId: parseTenantId("10000000-0000-4000-8000-000000000001"),
    projectId: parseProjectId("20000000-0000-4000-8000-000000000001"),
    actorPrincipalId: parsePrincipalId("30000000-0000-4000-8000-000000000001"),
    producerPrincipalId: parsePrincipalId("30000000-0000-4000-8000-000000000002"),
    producerId: parseProducerId("40000000-0000-4000-8000-000000000001"),
    eventTypeId: parseEventTypeId("50000000-0000-4000-8000-000000000001"),
    endpointId: parseEndpointId("60000000-0000-4000-8000-000000000001"),
    subscriptionId: parseSubscriptionId("70000000-0000-4000-8000-000000000001")
  };

  await db.withTransaction("rq_migrator", async (tx) => {
    await tx.query(
      `INSERT INTO rq.principals (id, kind, state) VALUES ($1::uuid, 'human', 'active'), ($2::uuid, 'producer', 'active')`,
      [ids.actorPrincipalId, ids.producerPrincipalId]
    );
    await tx.query(
      `INSERT INTO rq.humans (principal_id, principal_kind, display_name, webauthn_user_id)
       VALUES ($1::uuid, 'human', 'Relay Ops', $2::bytea)`,
      [ids.actorPrincipalId, shaBytes("webauthn")]
    );
    await tx.query(
      `INSERT INTO rq.tenants (id, slug, display_name, state) VALUES ($1::uuid, 'acme', 'Acme', 'active')`,
      [ids.tenantId]
    );
    await tx.query(
      `INSERT INTO rq.projects (id, tenant_id, name, state, topology_version)
       VALUES ($1::uuid, $2::uuid, 'core', 'active', 1)`,
      [ids.projectId, ids.tenantId]
    );
    await tx.query(
      `INSERT INTO rq.tenant_capacity (tenant_id, limit_profile_version, max_pending_events, max_downstream_obligations, max_active_attempt_slots, max_retained_payload_bytes)
       VALUES ($1::uuid, 'default', 1000, 10000, 100, 100000000)`,
      [ids.tenantId]
    );
    await tx.query(
      `INSERT INTO rq.project_capacity (project_id, tenant_id, limit_profile_version, max_pending_events, max_downstream_obligations, max_active_attempt_slots, max_retained_payload_bytes)
       VALUES ($1::uuid, $2::uuid, 'default', 1000, 10000, 100, 100000000)`,
      [ids.projectId, ids.tenantId]
    );
    await tx.query(
      `INSERT INTO rq.producers (id, tenant_id, project_id, principal_id, principal_kind, channel_kind, name, business_namespace, state, current_scope_version)
       VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid, 'producer', 'machine_producer', 'orders-prod', 'orders', 'active', 1)`,
      [ids.producerId, ids.tenantId, ids.projectId, ids.producerPrincipalId]
    );
    await tx.query(
      `INSERT INTO rq.event_types (id, tenant_id, project_id, type_name, state, current_schema_version)
       VALUES ($1::uuid, $2::uuid, $3::uuid, 'order.created', 'active', 1)`,
      [ids.eventTypeId, ids.tenantId, ids.projectId]
    );
    await tx.query(
      `INSERT INTO rq.event_schema_versions (event_type_id, schema_version, tenant_id, project_id, dialect, profile_version, definition_bytes, definition_sha256, normalized_profile, compatibility_policy, state, created_by, published_by, published_at)
       VALUES ($1::uuid, 1, $2::uuid, $3::uuid, 'https://json-schema.org/draft/2020-12/schema', 'relayquill.event-schema.v1', $4::bytea, $5::bytea, '{"type":"object"}'::jsonb, 'additive_compatible', 'published', $6::uuid, $6::uuid, pg_catalog.clock_timestamp())`,
      [ids.eventTypeId, ids.tenantId, ids.projectId, Buffer.from("{}"), shaBytes("schema"), ids.actorPrincipalId]
    );
    await tx.query(
      `INSERT INTO rq.broker_stream_generations (id, deployment_reference, cluster_reference, stream_name, observed_stream_created_at, configuration_sha256, state, created_by_operator_reference)
       VALUES ($1::uuid, 'dep', 'cls', 'RELAYQUILL_EVENTS_V1', pg_catalog.clock_timestamp(), $2::bytea, 'active', 'ops')`,
      [brokerGenerationId, shaBytes("streamcfg")]
    );
    for (const op of ["event_admission", "send_start"]) {
      await tx.query(
        `INSERT INTO rq.tenant_rate_buckets (tenant_id, operation, tokens_micro, reserved_micro, capacity_micro, refill_micro_per_second, refill_remainder_numerator, last_refill_at, policy_version)
         VALUES ($1::uuid, $2::text, 100000000, 0, 100000000, 10000000, 0, pg_catalog.clock_timestamp(), 1)`,
        [ids.tenantId, op]
      );
      await tx.query(
        `INSERT INTO rq.project_rate_buckets (project_id, tenant_id, operation, tokens_micro, reserved_micro, capacity_micro, refill_micro_per_second, refill_remainder_numerator, last_refill_at, policy_version)
         VALUES ($1::uuid, $2::uuid, $3::text, 100000000, 0, 100000000, 10000000, 0, pg_catalog.clock_timestamp(), 1)`,
        [ids.projectId, ids.tenantId, op]
      );
    }
    await tx.query(
      `INSERT INTO rq.producer_rate_buckets (producer_id, tenant_id, project_id, operation, tokens_micro, reserved_micro, capacity_micro, refill_micro_per_second, refill_remainder_numerator, last_refill_at, policy_version)
       VALUES ($1::uuid, $2::uuid, $3::uuid, 'event_admission', 100000000, 0, 100000000, 10000000, 0, pg_catalog.clock_timestamp(), 1)`,
      [ids.producerId, ids.tenantId, ids.projectId]
    );
  });

  return ids;
}

async function seedOutboxEvent(db, ids, suffix) {
  const eventId = parseEventId(`a0000000-0000-4000-8000-${suffix}`);
  const payloadId = parseEventPayloadId(`a1000000-0000-4000-8000-${suffix}`);
  const wireEnvelopeId = parseWireEnvelopeId(`a2000000-0000-4000-8000-${suffix}`);
  const outboxId = parseOutboxId(`a3000000-0000-4000-8000-${suffix}`);
  const receiptId = parseCommandReceiptId(`a4000000-0000-4000-8000-${suffix}`);
  const auditId = `a5000000-0000-4000-8000-${suffix}`;

  const contentBytes = Buffer.from(JSON.stringify({ order_id: `ord-${suffix}` }));
  const contentSha256 = shaHex(contentBytes);
  const wireBytes = Buffer.from(JSON.stringify({ id: `ord-${suffix}`, type: "order.created" }));
  const encodedEnv = encodeBrokerNotificationEnvelope({
    envelope_version: 1,
    outbox_id: outboxId,
    event_id: eventId,
    project_id: ids.projectId,
    topology_version: 1n,
    publication_generation: 1n,
    content_sha256: contentSha256
  });

  await db.withTransaction("rq_api", (tx) =>
    admitEvent(tx, {
      tenantId: ids.tenantId,
      projectId: ids.projectId,
      actorPrincipalId: ids.actorPrincipalId,
      producerId: ids.producerId,
      producerNamespace: "orders",
      businessKey: `ord-${suffix}`,
      businessKeySha256: shaHex(`bk:${suffix}`),
      idempotencyKeySha256: shaHex(`idem:${suffix}`),
      submittedShapeSha256: shaHex(`shape:${suffix}`),
      effectiveRequestSha256: shaHex(`eff:${suffix}`),
      eventTypeId: ids.eventTypeId,
      eventSchemaVersion: 1,
      content: contentBytes,
      contentSha256,
      wireEnvelopeBytes: wireBytes,
      wireEnvelopeSha256: shaHex(wireBytes),
      brokerEnvelopeBytes: encodedEnv.bytes,
      brokerEnvelopeSha256: encodedEnv.envelope_sha256,
      producerEventTime: nowUtcInstant(),
      deliveryDeadlineAt: nowUtcInstant().add({ seconds: 1800 }),
      appliedDefaults: { ttl_seconds: 1800 },
      retentionPolicyVersion: "retention_v1",
      eventId,
      payloadId,
      wireEnvelopeId,
      outboxId,
      receiptId,
      auditId
    })
  );

  return { outboxId, eventId, brokerMessageId: encodedEnv.broker_message_id };
}

test("RelayWorker publishes pending outbox events with deterministic Nats-Msg-Id, transitions dropped PubAck to publish_unknown, and deduplicates recovery", async (t) => {
  const db = await createPGliteAdapter({ schema: "rq", isolation: "shared_database_schemas" });
  const brokerGenId = parseBrokerGenerationId("81000000-0000-4000-8000-000000000001");
  const broker = new InMemoryJetStreamBroker({ brokerGenerationId: brokerGenId });
  t.after(async () => {
    await broker.close();
    await db.close();
  });

  await applyMigrations(db);
  const ids = await seedFixtureBase(db, brokerGenId);
  const worker = createRelayWorker({
    pgAdapter: db,
    broker,
    instanceId: parseRuntimeInstanceId("90000000-0000-4000-8000-000000000002"),
    controlEpoch: ids.controlEpoch,
    settings: {
      poll_interval_ms: 25,
      batch_size: 16,
      claim_lease_ms: 15_000,
      publish_concurrency: 2,
      publish_timeout_ms: 1_000
    }
  });

  // 1. Normal publish
  const normal = await seedOutboxEvent(db, ids, "000000000001");
  const tick1 = await worker.runOnce();
  assert.equal(tick1.scannedCount, 1);
  assert.equal(tick1.publishedCount, 1);
  assert.equal(tick1.outcomes[0]?.brokerMessageId, `rq:${normal.outboxId}:1`);
  assert.equal(tick1.outcomes[0]?.streamSequence, 1n);

  const normalMsg = broker.getStoredMessage(1);
  assert.ok(normalMsg !== null);
  assert.equal(normalMsg.msgId, `rq:${normal.outboxId}:1`);

  const normalDb = await db.withTransaction("rq_relay", (tx) =>
    tx.query(
      `SELECT o.state AS outbox_state, op.state AS pub_state, op.stream_sequence
         FROM rq.outbox_events o
         JOIN rq.outbox_publications op
           ON op.outbox_id = o.id AND op.publication_generation = o.current_publication_generation
        WHERE o.id = $1::uuid`,
      [normal.outboxId]
    )
  );
  assert.equal(normalDb.rows[0]?.outbox_state, "published");
  assert.equal(normalDb.rows[0]?.pub_state, "ack_observed");
  assert.equal(normalDb.rows[0]?.stream_sequence, "1");

  // 2. Lost PubAck -> fenced publish_unknown without dropping identity
  const lostAck = await seedOutboxEvent(db, ids, "000000000002");
  broker.dropNextPubAckAfterStore(1);

  const tick2 = await worker.runOnce();
  assert.equal(tick2.scannedCount, 1);
  assert.equal(tick2.publishUnknownCount, 1);
  assert.equal(tick2.outcomes[0]?.outcome, "publish_unknown");
  assert.equal(tick2.outcomes[0]?.brokerMessageId, `rq:${lostAck.outboxId}:1`);

  const storedBeforeDedup = broker.getStoredMessage(2);
  assert.ok(storedBeforeDedup !== null);
  assert.equal(storedBeforeDedup.msgId, `rq:${lostAck.outboxId}:1`);
  assert.equal(broker.getStoredMessage(3), null);

  const unknownDb = await db.withTransaction("rq_relay", (tx) =>
    tx.query(
      `SELECT o.state AS outbox_state, o.current_publication_generation,
              op.state AS pub_state, op.broker_message_id
         FROM rq.outbox_events o
         JOIN rq.outbox_publications op
           ON op.outbox_id = o.id AND op.publication_generation = o.current_publication_generation
        WHERE o.id = $1::uuid`,
      [lostAck.outboxId]
    )
  );
  assert.equal(unknownDb.rows[0]?.outbox_state, "pending");
  assert.equal(unknownDb.rows[0]?.current_publication_generation, "1");
  assert.equal(unknownDb.rows[0]?.pub_state, "publish_unknown");
  assert.equal(unknownDb.rows[0]?.broker_message_id, `rq:${lostAck.outboxId}:1`);

  // 3. Recovery after backoff elapses within JetStream dedup window republishes exact same rq:<outboxId>:1
  await db.withTransaction("rq_migrator", (tx) =>
    tx.query(
      `UPDATE rq.outbox_events
          SET next_publish_at = pg_catalog.clock_timestamp() - interval '1 second'
        WHERE id = $1::uuid`,
      [lostAck.outboxId]
    )
  );

  const recovered = await worker.service.recoverUnknownPublication({
    outboxId: lostAck.outboxId,
    episodeId: parsePublicationRecoveryEpisodeId("b1000000-0000-4000-8000-000000000001"),
    instanceId: worker.instanceId,
    controlEpoch: ids.controlEpoch,
    noProgressGenerationCount: 0
  });
  assert.equal(recovered.action, "republished_same_generation");
  assert.equal(recovered.publicationGeneration, 1n);
  assert.equal(recovered.brokerMessageId, `rq:${lostAck.outboxId}:1`);
  assert.equal(recovered.outboxState, "published");
  // JetStream deduplicated seq 2 and did NOT append a duplicate seq 3
  assert.equal(broker.getStoredMessage(3), null);

  const afterRecoveryDb = await db.withTransaction("rq_relay", (tx) =>
    tx.query(
      `SELECT o.state AS outbox_state, op.state AS pub_state, op.stream_sequence
         FROM rq.outbox_events o
         JOIN rq.outbox_publications op
           ON op.outbox_id = o.id AND op.publication_generation = o.current_publication_generation
        WHERE o.id = $1::uuid`,
      [lostAck.outboxId]
    )
  );
  assert.equal(afterRecoveryDb.rows[0]?.outbox_state, "published");
  assert.equal(afterRecoveryDb.rows[0]?.pub_state, "ack_observed");
  assert.equal(afterRecoveryDb.rows[0]?.stream_sequence, "2");
});

test("RelayWorker lifecycle start/stop and node:http health probes work and CLI parses flags", async (t) => {
  const parsed = parseRelayCliArgs(["--config", "./config/development.relay.json", "--once", "--health-port", "0"]);
  assert.equal(parsed.configPath, "./config/development.relay.json");
  assert.equal(parsed.once, true);
  assert.equal(parsed.healthPort, 0);

  const db = await createPGliteAdapter({ schema: "rq", isolation: "shared_database_schemas" });
  const brokerGenId = parseBrokerGenerationId("81000000-0000-4000-8000-000000000002");
  const broker = new InMemoryJetStreamBroker({ brokerGenerationId: brokerGenId });
  await applyMigrations(db);
  const ids = await seedFixtureBase(db, brokerGenId);

  const worker = createRelayWorker({
    pgAdapter: db,
    broker,
    instanceId: parseRuntimeInstanceId("90000000-0000-4000-8000-000000000003"),
    controlEpoch: ids.controlEpoch,
    settings: { poll_interval_ms: 50 }
  });

  const health = createRelayHealthServer({ probe: worker, port: 0 });
  const addr = await health.start();
  t.after(async () => {
    await worker.stop();
    await health.stop();
    await broker.close();
    await db.close();
  });

  await worker.start();
  const liveRes = await fetch(`http://${addr.host}:${addr.port}/health/live`);
  assert.equal(liveRes.status, 200);
  const readyRes = await fetch(`http://${addr.host}:${addr.port}/health/ready`);
  assert.equal(readyRes.status, 200);

  await worker.stop("test_done");
  const afterStopReady = await fetch(`http://${addr.host}:${addr.port}/health/ready`);
  assert.equal(afterStopReady.status, 503);
});
