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
  parseDeliveryFamilyId,
  parseDeliveryId,
  parseEndpointId,
  parseEventId,
  parseEventPayloadId,
  parseEventTypeId,
  parseOutboxId,
  parsePrincipalId,
  parseProducerId,
  parseProjectId,
  parseRuntimeInstanceId,
  parseSha256Hex,
  parseSubscriptionId,
  parseTenantId,
  parseWireEnvelopeId
} from "@relayquill/domain";
import {
  computeConsumerEventKeySha256,
  encodeBrokerNotificationEnvelope,
  hashCanonicalJson
} from "@relayquill/contracts";
import { InMemoryJetStreamBroker, deriveAcceptedEventSubject } from "@relayquill/broker";
import {
  admitEvent,
  claimEventFanout,
  commitFanoutPage,
  createPGliteAdapter,
  readInstallationStatus,
  registerRuntimeInstance
} from "@relayquill/postgres";
import {
  createFanoutHealthServer,
  createFanoutWorker,
  parseFanoutCliArgs
} from "../dist/index.js";

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");

function shaHex(data) {
  return parseSha256Hex(crypto.createHash("sha256").update(data).digest("hex"));
}

function shaBytes(data) {
  return crypto.createHash("sha256").update(data).digest();
}

function suffixUuid(prefix, index) {
  return `${prefix}-${String(index).padStart(12, "0")}`;
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

async function seedFanoutFixture(db, brokerGenerationId, totalSubscriptions) {
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
    signingKeyId: "61000000-0000-4000-8000-000000000001",
    subscriptionIds: []
  };

  const eventSchemaBytes = Buffer.from(
    JSON.stringify({
      $schema: "https://json-schema.org/draft/2020-12/schema",
      type: "object",
      required: ["order_id", "tier"],
      additionalProperties: false,
      properties: {
        order_id: { type: "string", maxLength: 64 },
        tier: { type: "string", maxLength: 32 }
      }
    }),
    "utf8"
  );
  const eventSchemaShaBytes = crypto.createHash("sha256").update(eventSchemaBytes).digest();

  const matchFilterAst = {
    operation: "eq",
    path: "/tier",
    value: "gold"
  };
  const matchFilterShaBytes = Buffer.from(
    hashCanonicalJson(matchFilterAst, "match_filter").sha256,
    "hex"
  );

  const nonMatchFilterAst = {
    operation: "eq",
    path: "/tier",
    value: "platinum"
  };
  const nonMatchFilterShaBytes = Buffer.from(
    hashCanonicalJson(nonMatchFilterAst, "nonmatch_filter").sha256,
    "hex"
  );

  await db.withTransaction("rq_migrator", async (tx) => {
    await tx.query(
      `INSERT INTO rq.principals (id, kind, state) VALUES ($1::uuid, 'human', 'active'), ($2::uuid, 'producer', 'active')`,
      [ids.actorPrincipalId, ids.producerPrincipalId]
    );
    await tx.query(
      `INSERT INTO rq.humans (principal_id, principal_kind, display_name, webauthn_user_id)
       VALUES ($1::uuid, 'human', 'Fanout Ops', $2::bytea)`,
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
       VALUES ($1::uuid, 'default', 1000, 100000, 100, 100000000)`,
      [ids.tenantId]
    );
    await tx.query(
      `INSERT INTO rq.project_capacity (project_id, tenant_id, limit_profile_version, max_pending_events, max_downstream_obligations, max_active_attempt_slots, max_retained_payload_bytes)
       VALUES ($1::uuid, $2::uuid, 'default', 1000, 100000, 100, 100000000)`,
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
      [ids.eventTypeId, ids.tenantId, ids.projectId, eventSchemaBytes, eventSchemaShaBytes, ids.actorPrincipalId]
    );
    await tx.query(
      `INSERT INTO rq.endpoints (id, tenant_id, project_id, name, state, current_version, security_epoch, current_signing_policy_version, created_by)
       VALUES ($1::uuid, $2::uuid, $3::uuid, 'hook-fanout', 'active', 1, 1, 1, $4::uuid)`,
      [ids.endpointId, ids.tenantId, ids.projectId, ids.actorPrincipalId]
    );
    await tx.query(
      `INSERT INTO rq.endpoint_versions (endpoint_id, endpoint_version, tenant_id, project_id, destination_url, normalized_hostname, port, path_and_query_sha256, url_policy_version, network_policy_version, request_profile_version, response_profile_version, configuration_sha256, created_by)
       VALUES ($1::uuid, 1, $2::uuid, $3::uuid, 'https://receiver.example.test/webhook', 'receiver.example.test', 443, $4::bytea, 'url_v1', 'network_v1', 'request_v1', 'response_v1', $5::bytea, $6::uuid)`,
      [ids.endpointId, ids.tenantId, ids.projectId, shaBytes("path"), shaBytes("epcfg"), ids.actorPrincipalId]
    );
    const receiverContractId = "63000000-0000-4000-8000-000000000001";
    await tx.query(
      `INSERT INTO rq.receiver_contracts (id, tenant_id, project_id, endpoint_id, name, state, current_version, created_by)
       VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid, 'rc-fanout', 'active', 1, $5::uuid)`,
      [receiverContractId, ids.tenantId, ids.projectId, ids.endpointId, ids.actorPrincipalId]
    );
    await tx.query(
      `INSERT INTO rq.receiver_contract_versions (contract_id, contract_version, tenant_id, project_id, endpoint_id, consumer_contract_scope, definition_bytes, definition_sha256, receipt_profile, ordering_profile, minimum_inbox_retention_seconds, verified_at, published_by)
       VALUES ($1::uuid, 1, $2::uuid, $3::uuid, $4::uuid, 'default', $5::bytea, $6::bytea, 'http_ack_only', 'unordered', 7776000, pg_catalog.clock_timestamp(), $7::uuid)`,
      [receiverContractId, ids.tenantId, ids.projectId, ids.endpointId, Buffer.from("{}"), shaBytes("rcdef"), ids.actorPrincipalId]
    );

    for (let i = 1; i <= totalSubscriptions; i += 1) {
      const subId = parseSubscriptionId(suffixUuid("70000000-0000-4000-8000", i));
      const setupReceiptId = suffixUuid("64000000-0000-4000-8000", i);
      const activationEventId = suffixUuid("65000000-0000-4000-8000", i);
      const isMatching = i <= 150;
      const filterJson = JSON.stringify(isMatching ? matchFilterAst : nonMatchFilterAst);
      const filterSha = isMatching ? matchFilterShaBytes : nonMatchFilterShaBytes;
      const scope = `scope_${i}`;

      await tx.query(
        `INSERT INTO rq.subscriptions (id, tenant_id, project_id, name, state, current_version, control_sequence, send_hold, created_by)
         VALUES ($1::uuid, $2::uuid, $3::uuid, $4::text, 'active', 1, 1, false, $5::uuid)`,
        [subId, ids.tenantId, ids.projectId, `sub-${i}`, ids.actorPrincipalId]
      );
      await tx.query(
        `INSERT INTO rq.subscription_versions (subscription_id, subscription_version, tenant_id, project_id, endpoint_id, endpoint_version, event_type_id, filter_profile_version, filter_ast, filter_sha256, ordering_mode, retry_policy_version, response_policy_kind, response_policy_version, consumer_contract_scope, receiver_contract_id, receiver_contract_version, configuration_sha256, created_by)
         VALUES ($1::uuid, 1, $2::uuid, $3::uuid, $4::uuid, 1, $5::uuid, 'relayquill.filter.v1', $6::jsonb, $7::bytea, 'unordered', 'retry_v1', 'response', 'response_v1', $8::text, $9::uuid, 1, $10::bytea, $11::uuid)`,
        [
          subId,
          ids.tenantId,
          ids.projectId,
          ids.endpointId,
          ids.eventTypeId,
          filterJson,
          filterSha,
          scope,
          receiverContractId,
          shaBytes(`subcfg-${i}`),
          ids.actorPrincipalId
        ]
      );
      await tx.query(
        `INSERT INTO rq.subscription_schema_versions (subscription_id, subscription_version, tenant_id, project_id, event_type_id, event_schema_version)
         VALUES ($1::uuid, 1, $2::uuid, $3::uuid, $4::uuid, 1)`,
        [subId, ids.tenantId, ids.projectId, ids.eventTypeId]
      );
      await tx.query(
        `INSERT INTO rq.command_receipts (id, scope_kind, tenant_id, project_id, actor_principal_id, command_family, key_sha256, submitted_shape_sha256, effective_request_sha256, resource_kind, resource_id, accepted_version)
         VALUES ($1::uuid, 'project', $2::uuid, $3::uuid, $4::uuid, 'subscription.control', $5::bytea, $6::bytea, $7::bytea, 'subscription', $8::uuid, 1)`,
        [
          setupReceiptId,
          ids.tenantId,
          ids.projectId,
          ids.actorPrincipalId,
          shaBytes(`key-${i}`),
          shaBytes(`shape-${i}`),
          shaBytes(`eff-${i}`),
          subId
        ]
      );
      await tx.query(
        `INSERT INTO rq.subscription_control_events (id, subscription_id, tenant_id, project_id, control_sequence, action, prior_version, resulting_version, topology_version, actor_principal_id, command_receipt_id, safe_reason_code)
         VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid, 1, 'activate', NULL, 1, 1, $5::uuid, $6::uuid, 'initial_activate')`,
        [activationEventId, subId, ids.tenantId, ids.projectId, ids.actorPrincipalId, setupReceiptId]
      );
      await tx.query(
        `INSERT INTO rq.subscription_topology_ranges (project_id, tenant_id, subscription_id, subscription_version, from_topology_version, activation_event_id)
         VALUES ($1::uuid, $2::uuid, $3::uuid, 1, 1, $4::uuid)`,
        [ids.projectId, ids.tenantId, subId, activationEventId]
      );
      ids.subscriptionIds.push(subId);
    }

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

async function admitAndPrepareBrokerPublish(db, ids, index, candidateCount) {
  const eventId = parseEventId(suffixUuid("a0000000-0000-4000-8000", index));
  const payloadId = parseEventPayloadId(suffixUuid("a1000000-0000-4000-8000", index));
  const wireEnvelopeId = parseWireEnvelopeId(suffixUuid("a2000000-0000-4000-8000", index));
  const outboxId = parseOutboxId(suffixUuid("a3000000-0000-4000-8000", index));
  const receiptId = parseCommandReceiptId(suffixUuid("a4000000-0000-4000-8000", index));
  const auditId = suffixUuid("a5000000-0000-4000-8000", index);

  const contentBytes = Buffer.from(JSON.stringify({ order_id: `ord-${index}`, tier: "gold" }));
  const contentSha256 = shaHex(contentBytes);
  const wireBytes = Buffer.from(JSON.stringify({ id: `ord-${index}`, type: "order.created" }));
  const encodedEnv = encodeBrokerNotificationEnvelope({
    envelope_version: 1,
    outbox_id: outboxId,
    event_id: eventId,
    project_id: ids.projectId,
    topology_version: 1n,
    publication_generation: 1n,
    content_sha256: contentSha256
  });

  const admitRes = await db.withTransaction("rq_api", (tx) =>
    admitEvent(tx, {
      tenantId: ids.tenantId,
      projectId: ids.projectId,
      actorPrincipalId: ids.actorPrincipalId,
      producerId: ids.producerId,
      producerNamespace: "orders",
      businessKey: `ord-${index}`,
      businessKeySha256: shaHex(`bk:${index}`),
      idempotencyKeySha256: shaHex(`idem:${index}`),
      submittedShapeSha256: shaHex(`shape:${index}`),
      effectiveRequestSha256: shaHex(`eff:${index}`),
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
      candidateCount: BigInt(candidateCount),
      eventId,
      payloadId,
      wireEnvelopeId,
      outboxId,
      receiptId,
      auditId
    })
  );

  return {
    eventId,
    outboxId,
    wireEnvelopeId,
    projectEventSequence: admitRes.projectEventSequence,
    encodedEnv
  };
}

async function publishToBroker(broker, projectId, outboxId, encodedEnv) {
  return broker.publish({
    outboxId,
    projectId,
    publicationGeneration: 1n,
    envelopeBytes: encodedEnv.bytes,
    subject: deriveAcceptedEventSubject(projectId, broker.subjectPrefix),
    msgId: encodedEnv.broker_message_id
  });
}

test("FanoutWorker executes multi-page fanout (100/page), resumes crash safely, and NAKs out-of-order project sequence gaps", async (t) => {
  let brokerNowMs = Date.now();
  const db = await createPGliteAdapter({ schema: "rq", isolation: "shared_database_schemas" });
  const brokerGenId = parseBrokerGenerationId("81000000-0000-4000-8000-000000000001");
  const broker = new InMemoryJetStreamBroker({
    brokerGenerationId: brokerGenId,
    nowMs: () => brokerNowMs
  });
  const worker = createFanoutWorker({
    pgAdapter: db,
    broker,
    instanceId: parseRuntimeInstanceId("90000000-0000-4000-8000-000000000003"),
    settings: {
      ack_wait_ms: 30_000,
      max_deliver: 10,
      max_ack_pending: 100,
      max_batch: 10,
      max_bytes: 262_144,
      max_expires_ms: 50
    }
  });

  t.after(async () => {
    await worker.stop();
    await broker.close();
    await db.close();
  });

  await applyMigrations(db);
  const totalSubs = 205;
  const ids = await seedFanoutFixture(db, brokerGenId, totalSubs);
  const peerInstanceId = parseRuntimeInstanceId("90000000-0000-4000-8000-000000000099");
  await db.withTransaction("rq_fanout", (tx) =>
    registerRuntimeInstance(tx, {
      instanceId: peerInstanceId,
      processRole: "fanout",
      databaseRole: "rq_fanout",
      controlEpoch: ids.controlEpoch,
      buildReference: "peer-crash",
      leaseMs: 30_000n
    })
  );

  // 1. Multi-page fanout (205 subs -> 3 pages: 100, 100, 5; 150 matched, 55 filtered_out)
  const ev1 = await admitAndPrepareBrokerPublish(db, ids, 1, totalSubs);
  assert.equal(ev1.projectEventSequence, 1n);
  await publishToBroker(broker, ids.projectId, ev1.outboxId, ev1.encodedEnv);

  const tick1 = await worker.runOnce();
  assert.equal(tick1.pulledCount, 1);
  assert.equal(tick1.completedCount, 1);
  assert.equal(tick1.deliveriesCreatedCount, 150);
  assert.equal(tick1.results[0]?.pagesCommitted, 3);
  assert.equal(tick1.results[0]?.examinedCount, 205n);
  assert.equal(tick1.results[0]?.materializedThroughEventSequence, 1n);

  const ev1State = await db.withTransaction("rq_fanout", (tx) =>
    tx.query(
      `SELECT ef.state AS fanout_state, ef.examined_count, ef.delivery_count,
              bi.state AS inbox_state, pfs.materialized_through_event_sequence
         FROM rq.event_fanout ef
         JOIN rq.broker_inbox bi ON bi.event_id = ef.event_id
         JOIN rq.project_fanout_state pfs ON pfs.project_id = ef.project_id
        WHERE ef.event_id = $1::uuid`,
      [ev1.eventId]
    )
  );
  assert.equal(ev1State.rows[0]?.fanout_state, "completed");
  assert.equal(ev1State.rows[0]?.examined_count, "205");
  assert.equal(ev1State.rows[0]?.delivery_count, "150");
  assert.equal(ev1State.rows[0]?.inbox_state, "completed");
  assert.equal(ev1State.rows[0]?.materialized_through_event_sequence, "1");

  // 2. Crash / resume idempotency after page 1 already committed under an expired claim
  const ev2 = await admitAndPrepareBrokerPublish(db, ids, 2, totalSubs);
  assert.equal(ev2.projectEventSequence, 2n);
  const pub2 = await publishToBroker(broker, ids.projectId, ev2.outboxId, ev2.encodedEnv);

  // Pre-commit page 1 (first 100 subscriptions) as if peer crashed mid-fanout
  await db.withTransaction("rq_fanout", async (tx) => {
    const claim = await claimEventFanout(tx, {
      eventId: ev2.eventId,
      instanceId: peerInstanceId,
      controlEpoch: ids.controlEpoch,
      claimLeaseMs: 1_000n
    });
    assert.equal(claim.outcome, "claimed");

    const filterHash = hashCanonicalJson({ operation: "eq", path: "/tier", value: "gold" }, "f").sha256;
    const firstPageOutcomes = ids.subscriptionIds.slice(0, 100).map((subId, i) => ({
      subscription_id: subId,
      subscription_version: "1",
      outcome: "matched",
      filter_profile_version: "relayquill.filter.v1",
      filter_sha256: filterHash,
      delivery_id: parseDeliveryId(suffixUuid("d1000000-0000-4000-8000", i + 1)),
      family_id: parseDeliveryFamilyId(suffixUuid("f1000000-0000-4000-8000", i + 1)),
      endpoint_id: ids.endpointId,
      endpoint_version: "1",
      wire_envelope_id: ev2.wireEnvelopeId,
      consumer_contract_scope: `scope_${i + 1}`,
      consumer_event_key_sha256: computeConsumerEventKeySha256({
        project_id: ids.projectId,
        event_id: ev2.eventId,
        consumer_contract_scope: `scope_${i + 1}`
      })
    }));

    const committedPage1 = await commitFanoutPage(tx, {
      eventId: ev2.eventId,
      instanceId: peerInstanceId,
      controlEpoch: ids.controlEpoch,
      expectedClaimGeneration: claim.claimGeneration,
      nextCursor: ids.subscriptionIds[99],
      complete: false,
      outcomes: firstPageOutcomes
    });
    assert.equal(committedPage1.outcome, "page_committed");

    // Force peer claim expiry so FanoutWorker can take over immediately
    await tx.query(
      `UPDATE rq.event_fanout
          SET claim_expires_at = pg_catalog.clock_timestamp() - interval '10 seconds'
        WHERE event_id = $1::uuid`,
      [ev2.eventId]
    );
  });

  const tick2 = await worker.runOnce();
  assert.equal(tick2.completedCount, 1);
  // Resumed from cursor 100 -> committed remaining 2 pages (100 + 5), reaching all 150 deliveries without duplicating page 1
  assert.equal(tick2.results[0]?.pagesCommitted, 2);
  assert.equal(tick2.results[0]?.examinedCount, 205n);
  assert.equal(tick2.deliveriesCreatedCount, 150);

  const ev2Totals = await db.withTransaction("rq_fanout", (tx) =>
    tx.query(
      `SELECT count(*)::int AS delivery_rows
         FROM rq.deliveries
        WHERE event_id = $1::uuid`,
      [ev2.eventId]
    )
  );
  assert.equal(ev2Totals.rows[0]?.delivery_rows, 150);

  // 3. Out-of-order project sequence gap NAK + ordered completion once predecessor lands
  const ev3 = await admitAndPrepareBrokerPublish(db, ids, 3, totalSubs);
  const ev4 = await admitAndPrepareBrokerPublish(db, ids, 4, totalSubs);
  assert.equal(ev3.projectEventSequence, 3n);
  assert.equal(ev4.projectEventSequence, 4n);

  // Publish seq 4 out-of-order BEFORE seq 3
  await publishToBroker(broker, ids.projectId, ev4.outboxId, ev4.encodedEnv);

  const tickGap = await worker.runOnce();
  assert.equal(tickGap.pulledCount, 1);
  assert.equal(tickGap.nakedOutOfOrderCount, 1);
  assert.equal(tickGap.completedCount, 0);
  assert.equal(tickGap.results[0]?.disposition, "out_of_order_naked");

  // Publish seq 3 now and let tick process seq 3
  await publishToBroker(broker, ids.projectId, ev3.outboxId, ev3.encodedEnv);
  const tickSeq3 = await worker.runOnce();
  assert.equal(tickSeq3.completedCount, 1);
  assert.equal(tickSeq3.results[0]?.projectEventSequence, 3n);

  // Advance broker simulated clock past NAK delay so seq 4 redelivers cleanly
  brokerNowMs += 10_000;
  const tickSeq4 = await worker.runOnce();
  assert.equal(tickSeq4.completedCount, 1);
  assert.equal(tickSeq4.results[0]?.projectEventSequence, 4n);
  assert.equal(tickSeq4.results[0]?.materializedThroughEventSequence, 4n);
  void pub2;
});

test("FanoutWorker lifecycle start/stop and node:http health probes work and CLI parses flags", async (t) => {
  const parsed = parseFanoutCliArgs(["--config", "./config/development.fanout.json", "--page-size", "100", "--once"]);
  assert.equal(parsed.configPath, "./config/development.fanout.json");
  assert.equal(parsed.pageSize, 100);
  assert.equal(parsed.once, true);

  const db = await createPGliteAdapter({ schema: "rq", isolation: "shared_database_schemas" });
  const brokerGenId = parseBrokerGenerationId("81000000-0000-4000-8000-000000000002");
  const broker = new InMemoryJetStreamBroker({ brokerGenerationId: brokerGenId });
  await applyMigrations(db);
  const ids = await seedFanoutFixture(db, brokerGenId, 1);

  const worker = createFanoutWorker({
    pgAdapter: db,
    broker,
    instanceId: parseRuntimeInstanceId("90000000-0000-4000-8000-000000000004"),
    controlEpoch: ids.controlEpoch,
    pollIntervalMs: 50
  });
  const health = createFanoutHealthServer({ probe: worker, port: 0 });
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
