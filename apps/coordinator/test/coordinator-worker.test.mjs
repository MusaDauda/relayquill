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
  parseRuntimeInstanceId,
  parseSessionId,
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
  openWatchLease,
  readProjectDeliveryTotals,
  readInstallationStatus
} from "@relayquill/postgres";
import {
  createCoordinatorHealthServer,
  createCoordinatorWorker,
  parseCoordinatorCliArgs
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
    watchSessionId: parseSessionId("ad000000-0000-4000-8000-000000000001"),
    eventTypeId: parseEventTypeId("50000000-0000-4000-8000-000000000001"),
    endpointId: parseEndpointId("60000000-0000-4000-8000-000000000001"),
    signingKeyId: "61000000-0000-4000-8000-000000000001",
    dispatchGrantId: "62000000-0000-4000-8000-000000000001",
    subscriptionId: parseSubscriptionId("70000000-0000-4000-8000-000000000001"),
    senderInstanceId: parseRuntimeInstanceId("91000000-0000-4000-8000-000000000001"),
    fanoutInstanceId: parseRuntimeInstanceId("92000000-0000-4000-8000-000000000001"),
    relayInstanceId: parseRuntimeInstanceId("93000000-0000-4000-8000-000000000001"),
    apiInstanceId: parseRuntimeInstanceId("94000000-0000-4000-8000-000000000001")
  };

  await db.withTransaction("rq_migrator", async (tx) => {
    await tx.query(
      `INSERT INTO rq.principals (id, kind, state) VALUES ($1::uuid, 'human', 'active'), ($2::uuid, 'producer', 'active')`,
      [ids.actorPrincipalId, ids.producerPrincipalId]
    );
    await tx.query(
      `INSERT INTO rq.humans (principal_id, principal_kind, display_name, webauthn_user_id)
       VALUES ($1::uuid, 'human', 'Coord Ops', $2::bytea)`,
      [ids.actorPrincipalId, shaBytes("webauthn")]
    );
    await tx.query(
      `INSERT INTO rq.human_sessions (id, principal_id, control_epoch, token_digest, csrf_digest, principal_authority_epoch, purpose, state, idle_expires_at, absolute_expires_at)
       VALUES ($1::uuid, $2::uuid, $3::uuid, pg_catalog.sha256('sess-tok'::bytea), pg_catalog.sha256('sess-csrf'::bytea), 1, 'ordinary', 'active', pg_catalog.clock_timestamp() + interval '30 minutes', pg_catalog.clock_timestamp() + interval '60 minutes')`,
      [ids.watchSessionId, ids.actorPrincipalId, ids.controlEpoch]
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
      `INSERT INTO rq.endpoints (id, tenant_id, project_id, name, state, current_version, security_epoch, current_signing_policy_version, created_by)
       VALUES ($1::uuid, $2::uuid, $3::uuid, 'orders-hook', 'active', 1, 1, 1, $4::uuid)`,
      [ids.endpointId, ids.tenantId, ids.projectId, ids.actorPrincipalId]
    );
    await tx.query(
      `INSERT INTO rq.endpoint_versions (endpoint_id, endpoint_version, tenant_id, project_id, destination_url, normalized_hostname, port, path_and_query_sha256, url_policy_version, network_policy_version, request_profile_version, response_profile_version, configuration_sha256, created_by)
       VALUES ($1::uuid, 1, $2::uuid, $3::uuid, 'https://receiver.example.test/webhook', 'receiver.example.test', 443, $4::bytea, 'url_v1', 'network_v1', 'request_v1', 'response_v1', $5::bytea, $6::uuid)`,
      [ids.endpointId, ids.tenantId, ids.projectId, shaBytes("path"), shaBytes("epcfg"), ids.actorPrincipalId]
    );
    await tx.query(
      `INSERT INTO rq.endpoint_dispatch_grants (id, tenant_id, project_id, endpoint_id, endpoint_version, security_epoch, grant_class, state, approved_by, approved_configuration_sha256)
       VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid, 1, 1, 'current_destination', 'active', $5::uuid, $6::bytea)`,
      [ids.dispatchGrantId, ids.tenantId, ids.projectId, ids.endpointId, ids.actorPrincipalId, shaBytes("epcfg")]
    );
    await tx.query(
      `INSERT INTO rq.signing_key_versions (id, tenant_id, project_id, endpoint_id, key_version, key_id, algorithm, custody_reference, custody_version_reference, state)
       VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid, 1, 'k1', 'hmac-sha256-v1', 'custody://k1', 'v1', 'active')`,
      [ids.signingKeyId, ids.tenantId, ids.projectId, ids.endpointId]
    );
    await tx.query(
      `INSERT INTO rq.signing_policies (endpoint_id, policy_version, tenant_id, project_id, primary_key_version_id, signature_mode, policy_sha256, created_by)
       VALUES ($1::uuid, 1, $2::uuid, $3::uuid, $4::uuid, 'primary_only', $5::bytea, $6::uuid)`,
      [ids.endpointId, ids.tenantId, ids.projectId, ids.signingKeyId, shaBytes("spol"), ids.actorPrincipalId]
    );
    const receiverContractId = "63000000-0000-4000-8000-000000000001";
    await tx.query(
      `INSERT INTO rq.receiver_contracts (id, tenant_id, project_id, endpoint_id, name, state, current_version, created_by)
       VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid, 'rc-a', 'active', 1, $5::uuid)`,
      [receiverContractId, ids.tenantId, ids.projectId, ids.endpointId, ids.actorPrincipalId]
    );
    await tx.query(
      `INSERT INTO rq.receiver_contract_versions (contract_id, contract_version, tenant_id, project_id, endpoint_id, consumer_contract_scope, definition_bytes, definition_sha256, receipt_profile, ordering_profile, minimum_inbox_retention_seconds, verified_at, published_by)
       VALUES ($1::uuid, 1, $2::uuid, $3::uuid, $4::uuid, 'default', $5::bytea, $6::bytea, 'http_ack_only', 'unordered', 7776000, pg_catalog.clock_timestamp(), $7::uuid)`,
      [receiverContractId, ids.tenantId, ids.projectId, ids.endpointId, Buffer.from("{}"), shaBytes("rcdef"), ids.actorPrincipalId]
    );
    await tx.query(
      `INSERT INTO rq.endpoint_capacity (endpoint_id, tenant_id, project_id, approved_active_slots, held_slots)
       VALUES ($1::uuid, $2::uuid, $3::uuid, 16, 0)`,
      [ids.endpointId, ids.tenantId, ids.projectId]
    );
    await tx.query(
      `INSERT INTO rq.subscriptions (id, tenant_id, project_id, name, state, current_version, control_sequence, send_hold, created_by)
       VALUES ($1::uuid, $2::uuid, $3::uuid, 'orders-sub', 'active', 1, 1, false, $4::uuid)`,
      [ids.subscriptionId, ids.tenantId, ids.projectId, ids.actorPrincipalId]
    );
    await tx.query(
      `INSERT INTO rq.subscription_versions (subscription_id, subscription_version, tenant_id, project_id, endpoint_id, endpoint_version, event_type_id, filter_profile_version, filter_ast, filter_sha256, ordering_mode, retry_policy_version, response_policy_kind, response_policy_version, consumer_contract_scope, receiver_contract_id, receiver_contract_version, configuration_sha256, created_by)
       VALUES ($1::uuid, 1, $2::uuid, $3::uuid, $4::uuid, 1, $5::uuid, 'relayquill.filter.v1', '{"all":[]}'::jsonb, $6::bytea, 'unordered', 'retry_v1', 'response', 'response_v1', 'default', $7::uuid, 1, $8::bytea, $9::uuid)`,
      [ids.subscriptionId, ids.tenantId, ids.projectId, ids.endpointId, ids.eventTypeId, shaBytes("flt"), receiverContractId, shaBytes("subcfg"), ids.actorPrincipalId]
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
      `INSERT INTO rq.endpoint_rate_buckets (endpoint_id, tenant_id, project_id, operation, tokens_micro, reserved_micro, capacity_micro, refill_micro_per_second, refill_remainder_numerator, last_refill_at, policy_version)
       VALUES ($1::uuid, $2::uuid, $3::uuid, 'send_start', 100000000, 0, 100000000, 10000000, 0, pg_catalog.clock_timestamp(), 1)`,
      [ids.endpointId, ids.tenantId, ids.projectId]
    );
    await tx.query(
      `INSERT INTO rq.producer_rate_buckets (producer_id, tenant_id, project_id, operation, tokens_micro, reserved_micro, capacity_micro, refill_micro_per_second, refill_remainder_numerator, last_refill_at, policy_version)
       VALUES ($1::uuid, $2::uuid, $3::uuid, 'event_admission', 100000000, 0, 100000000, 10000000, 0, pg_catalog.clock_timestamp(), 1)`,
      [ids.producerId, ids.tenantId, ids.projectId]
    );

    const regInstances = [
      [ids.senderInstanceId, "sender", "rq_sender"],
      [ids.fanoutInstanceId, "fanout", "rq_fanout"],
      [ids.relayInstanceId, "relay", "rq_relay"],
      [ids.apiInstanceId, "api", "rq_api"]
    ];
    for (const [instId, pRole, dbRole] of regInstances) {
      await tx.query(
        `INSERT INTO rq.runtime_instances (id, process_role, database_role, control_epoch, build_reference, state, expires_at)
         VALUES ($1::uuid, $2::text, $3::text, $4::uuid, 'test-peer', 'active', pg_catalog.clock_timestamp() + interval '1 hour')`,
        [instId, pRole, dbRole, ids.controlEpoch]
      );
    }
    await tx.query(
      `INSERT INTO rq.sender_instances (id, process_nonce_digest, build_reference, control_epoch, state, approved_slots, expires_at)
       VALUES ($1::uuid, $2::bytea, 'test-sender', $3::uuid, 'active', 32, pg_catalog.clock_timestamp() + interval '1 hour')`,
      [ids.senderInstanceId, shaBytes("nonce"), ids.controlEpoch]
    );
    await tx.query(
      `INSERT INTO rq.sender_capacity (instance_id, approved_slots, held_slots) VALUES ($1::uuid, 32, 0)`,
      [ids.senderInstanceId]
    );
  });

  return ids;
}

async function seedAdmittedEvent(db, ids, suffix) {
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
      receiptId,
      eventId,
      payloadId,
      wireEnvelopeId,
      outboxId,
      auditId
    })
  );

  return {
    eventId,
    payloadId,
    wireEnvelopeId,
    outboxId,
    encodedEnv
  };
}

test("CoordinatorWorker executes all 5 maintenance flows on PGlite + InMemoryJetStreamBroker", async (t) => {
  const db = await createPGliteAdapter({ schema: "rq", isolation: "shared_database_schemas" });
  const brokerGenId = parseBrokerGenerationId("81000000-0000-4000-8000-000000000001");
  const broker = new InMemoryJetStreamBroker({ brokerGenerationId: brokerGenId });
  await applyMigrations(db);
  const ids = await seedFixtureBase(db, brokerGenId);

  const worker = createCoordinatorWorker({
    pgAdapter: db,
    broker,
    instanceId: parseRuntimeInstanceId("90000000-0000-4000-8000-000000000001"),
    controlEpoch: ids.controlEpoch,
    publicationRecoveryBatchSize: 10
  });

  t.after(async () => {
    await worker.stop("test_done");
    await broker.close();
    await db.close();
  });

  // Flow 1 + Flow 2 + Flow 5 setup: admit events, create deliveries, expired claims & watch leases
  const evPromoted = await seedAdmittedEvent(db, ids, "000000000001");
  const evReap = await seedAdmittedEvent(db, ids, "000000000002");
  const evExtra = await seedAdmittedEvent(db, ids, "000000000099");

  const dueDeliveryId = "d1000000-0000-4000-8000-000000000001";
  const futureDeliveryId = "d1000000-0000-4000-8000-000000000002";
  const expiredDeliveryId = "d1000000-0000-4000-8000-000000000003";
  const expiredAttemptId = "d2000000-0000-4000-8000-000000000003";
  const expiredWatchLeaseId = "d3000000-0000-4000-8000-000000000001";

  // Clean setup for the 3 deliveries across 3 families (all delivery_generation = 0)
  await db.withTransaction("rq_migrator", async (tx) => {
    await tx.query(
      `INSERT INTO rq.delivery_families (id, event_id, tenant_id, project_id, subscription_id, original_subscription_version, consumer_contract_scope, consumer_event_key_sha256)
       VALUES ('f1000000-0000-4000-8000-000000000001', $1::uuid, $4::uuid, $5::uuid, $6::uuid, 1, 'default', $7::bytea),
              ('f1000000-0000-4000-8000-000000000002', $2::uuid, $4::uuid, $5::uuid, $6::uuid, 1, 'default', $8::bytea),
              ('f1000000-0000-4000-8000-000000000003', $3::uuid, $4::uuid, $5::uuid, $6::uuid, 1, 'default', $9::bytea)`,
      [
        evPromoted.eventId,
        evReap.eventId,
        evExtra.eventId,
        ids.tenantId,
        ids.projectId,
        ids.subscriptionId,
        shaBytes("ck1"),
        shaBytes("ck2"),
        shaBytes("ck3")
      ]
    );
    await tx.query(
      `INSERT INTO rq.deliveries (
         id, family_id, event_id, tenant_id, project_id, subscription_id,
         original_subscription_version, dispatch_subscription_version, endpoint_id, endpoint_version,
         wire_envelope_id, delivery_generation, current_attempt_id, current_fence, state, deadline_at, next_eligible_at, control_epoch
       ) VALUES
       ($1::uuid, 'f1000000-0000-4000-8000-000000000001', $4::uuid, $7::uuid, $8::uuid, $9::uuid,
        1, 1, $10::uuid, 1, $11::uuid, 0, NULL, 0, 'pending',
        pg_catalog.clock_timestamp() + interval '1 hour', pg_catalog.clock_timestamp() - interval '10 seconds', $14::uuid),
       ($2::uuid, 'f1000000-0000-4000-8000-000000000002', $5::uuid, $7::uuid, $8::uuid, $9::uuid,
        1, 1, $10::uuid, 1, $12::uuid, 0, NULL, 0, 'retry_wait',
        pg_catalog.clock_timestamp() + interval '1 hour', pg_catalog.clock_timestamp() + interval '10 minutes', $14::uuid),
       ($3::uuid, 'f1000000-0000-4000-8000-000000000003', $6::uuid, $7::uuid, $8::uuid, $9::uuid,
        1, 1, $10::uuid, 1, $13::uuid, 0, $15::uuid, 1, 'sending',
        pg_catalog.clock_timestamp() + interval '1 hour', pg_catalog.clock_timestamp() - interval '10 seconds', $14::uuid)`,
      [
        dueDeliveryId,
        futureDeliveryId,
        expiredDeliveryId,
        evPromoted.eventId,
        evReap.eventId,
        evExtra.eventId,
        ids.tenantId,
        ids.projectId,
        ids.subscriptionId,
        ids.endpointId,
        evPromoted.wireEnvelopeId,
        evReap.wireEnvelopeId,
        evExtra.wireEnvelopeId,
        ids.controlEpoch,
        expiredAttemptId
      ]
    );

    // Delayed outbox promotion candidate
    await tx.query(
      `UPDATE rq.outbox_events
          SET next_publish_at = pg_catalog.clock_timestamp() - interval '5 seconds',
              last_safe_error_code = 'TRANSIENT_DELAY'
        WHERE id = $1::uuid`,
      [evPromoted.outboxId]
    );

    // Expired outbox claim candidate
    await tx.query(
      `UPDATE rq.outbox_events
          SET state = 'claimed',
              claim_owner_instance_id = $2::uuid,
              claim_control_epoch = $3::uuid,
              claim_generation = claim_generation + 1,
              claim_expires_at = pg_catalog.clock_timestamp() - interval '10 seconds'
        WHERE id = $1::uuid`,
      [evReap.outboxId, ids.relayInstanceId, ids.controlEpoch]
    );

    // Expired event_fanout claim candidate
    await tx.query(
      `UPDATE rq.event_fanout
          SET state = 'materializing',
              candidate_count = 1,
              claim_owner_instance_id = $2::uuid,
              claim_control_epoch = $3::uuid,
              claim_generation = 1,
              claim_expires_at = pg_catalog.clock_timestamp() - interval '10 seconds'
        WHERE event_id = $1::uuid`,
      [evReap.eventId, ids.fanoutInstanceId, ids.controlEpoch]
    );

    // Expired delivery_attempt + held capacity rows for rq.cmd_coordinator_reap_expired
    await tx.query(
      `INSERT INTO rq.delivery_attempts (
         id, delivery_id, tenant_id, project_id, attempt_number, worker_instance_id, control_epoch,
         fencing_token, state, prepared_at, send_started_at, request_deadline_at, claim_expires_at,
         endpoint_id, endpoint_version, endpoint_security_epoch, dispatch_grant_id, signing_policy_version,
         wire_body_sha256, request_profile_version, network_policy_version, response_profile_version,
         circuit_generation_at_preparation, circuit_generation_at_start
       ) VALUES (
         $1::uuid, $2::uuid, $3::uuid, $4::uuid, 1, $5::uuid, $6::uuid,
         1, 'send_started', pg_catalog.clock_timestamp() - interval '30 seconds',
         pg_catalog.clock_timestamp() - interval '20 seconds',
         pg_catalog.clock_timestamp() + interval '30 seconds',
         pg_catalog.clock_timestamp() - interval '5 seconds',
         $7::uuid, 1, 1, $8::uuid, 1, $9::bytea, 'req_v1', 'net_v1', 'resp_v1', 0, 0
       )`,
      [
        expiredAttemptId,
        expiredDeliveryId,
        ids.tenantId,
        ids.projectId,
        ids.senderInstanceId,
        ids.controlEpoch,
        ids.endpointId,
        ids.dispatchGrantId,
        shaBytes("wire")
      ]
    );
    await tx.query(
      `INSERT INTO rq.attempt_slots (attempt_id, delivery_id, tenant_id, project_id, endpoint_id, worker_instance_id, state)
       VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid, $5::uuid, $6::uuid, 'held')`,
      [expiredAttemptId, expiredDeliveryId, ids.tenantId, ids.projectId, ids.endpointId, ids.senderInstanceId]
    );
    await tx.query(
      `INSERT INTO rq.delivery_capacity_positions (delivery_id, tenant_id, project_id, endpoint_id, position, current_attempt_id)
       VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid, 'active', $5::uuid)`,
      [expiredDeliveryId, ids.tenantId, ids.projectId, ids.endpointId, expiredAttemptId]
    );
    await tx.query(
      `UPDATE rq.sender_capacity SET held_slots = 1 WHERE instance_id = $1::uuid`,
      [ids.senderInstanceId]
    );
    await tx.query(
      `UPDATE rq.endpoint_capacity SET held_slots = 1 WHERE endpoint_id = $1::uuid`,
      [ids.endpointId]
    );
    await tx.query(
      `UPDATE rq.tenant_capacity SET active_attempt_slots = 1, pending_deliveries = 3 WHERE tenant_id = $1::uuid`,
      [ids.tenantId]
    );
    await tx.query(
      `UPDATE rq.project_capacity SET active_attempt_slots = 1, pending_deliveries = 3 WHERE project_id = $1::uuid`,
      [ids.projectId]
    );

    // Base projection totals matching the 3 initial deliveries (2 pending-bucket, 1 active)
    await tx.query(
      `INSERT INTO rq.project_delivery_totals (project_id, tenant_id, total_deliveries, pending_count, active_count)
       VALUES ($1::uuid, $2::uuid, 3, 2, 1)`,
      [ids.projectId, ids.tenantId]
    );

    // Watch capacity rows for watch_lease reaping
    await tx.query(
      `INSERT INTO rq.actor_watch_capacity (principal_id, held_count, approved_count) VALUES ($1::uuid, 0, 5)`,
      [ids.actorPrincipalId]
    );
    await tx.query(
      `INSERT INTO rq.tenant_watch_capacity (tenant_id, held_count, approved_count) VALUES ($1::uuid, 0, 10)`,
      [ids.tenantId]
    );
    await tx.query(
      `INSERT INTO rq.project_watch_capacity (project_id, tenant_id, held_count, approved_count) VALUES ($1::uuid, $2::uuid, 0, 10)`,
      [ids.projectId, ids.tenantId]
    );
  });

  await db.withTransaction("rq_api", (tx) =>
    openWatchLease(tx, {
      leaseId: expiredWatchLeaseId,
      tenantId: ids.tenantId,
      projectId: ids.projectId,
      principalId: ids.actorPrincipalId,
      actorKind: "human",
      sessionId: ids.watchSessionId,
      resourceKind: "event",
      resourceId: evPromoted.eventId,
      runtimeInstanceId: ids.apiInstanceId,
      controlEpoch: ids.controlEpoch,
      authCutoffAt: nowUtcInstant().add({ minutes: 5 }),
      streamCutoffAt: nowUtcInstant().add({ minutes: 10 })
    })
  );
  await db.withTransaction("rq_migrator", (tx) =>
    tx.query(
      `UPDATE rq.watch_leases
          SET opened_at = pg_catalog.clock_timestamp() - interval '10 minutes',
              expires_at = pg_catalog.clock_timestamp() - interval '5 seconds'
        WHERE id = $1::uuid`,
      [expiredWatchLeaseId]
    )
  );

  // Flow 3 setup: unknown publication cases (same-gen dedup, >=5 -> review_required)
  const evRecoverSameGen = await seedAdmittedEvent(db, ids, "000000000004");
  const evThreshold5 = await seedAdmittedEvent(db, ids, "000000000006");

  // Publish evRecoverSameGen directly to JetStream so retry deduplicates cleanly via broker_message_id
  await broker.publish({
    outboxId: evRecoverSameGen.outboxId,
    projectId: ids.projectId,
    publicationGeneration: 1n,
    envelopeBytes: evRecoverSameGen.encodedEnv.bytes,
    timeoutMs: 1000,
    expectedBrokerGenerationId: brokerGenId
  });
  const storedSeq1 = broker.getStoredMessage(1);
  assert.ok(storedSeq1 !== null);
  assert.equal(broker.getStoredMessage(2), null);

  await db.withTransaction("rq_migrator", async (tx) => {
    for (const ev of [evRecoverSameGen, evThreshold5]) {
      await tx.query(
        `UPDATE rq.outbox_publications
            SET state = 'publish_unknown', send_count = 1
          WHERE outbox_id = $1::uuid AND publication_generation = 1`,
        [ev.outboxId]
      );
      await tx.query(
        `UPDATE rq.outbox_events
            SET next_publish_at = pg_catalog.clock_timestamp() - interval '5 seconds'
          WHERE id = $1::uuid`,
        [ev.outboxId]
      );
    }

    // Active recovery episode at 5 no-progress generations for evThreshold5 -> review_required
    await tx.query(
      `INSERT INTO rq.publication_recovery_episodes (
         id, outbox_id, event_id, control_epoch, state, starting_fanout_version,
         last_progress_boundary_sha256, successive_no_progress_generations, last_generation_at
       ) VALUES (
         'e1000000-0000-4000-8000-000000000002', $1::uuid, $2::uuid, $3::uuid, 'active', 1,
         $4::bytea, 5, pg_catalog.clock_timestamp() - interval '2 minutes'
       )`,
      [evThreshold5.outboxId, evThreshold5.eventId, ids.controlEpoch, shaBytes("b2")]
    );
  });

  // Flow 4 setup: retention actions (one held by active hold on event, one unheld with expired hold)
  const evHeld = await seedAdmittedEvent(db, ids, "000000000007");
  const evExpire = await seedAdmittedEvent(db, ids, "000000000008");
  const actionHeldId = "c1000000-0000-4000-8000-000000000001";
  const actionExpireId = "c1000000-0000-4000-8000-000000000002";

  await db.withTransaction("rq_migrator", async (tx) => {
    await tx.query(
      `INSERT INTO rq.retention_holds (
         id, tenant_id, project_id, target_kind, target_id, reason_code, state, created_by, review_at, expires_at
       ) VALUES
       ('c2000000-0000-4000-8000-000000000001', $1::uuid, $2::uuid, 'event', $3::uuid, 'LEGAL_HOLD', 'active', $5::uuid, pg_catalog.clock_timestamp() + interval '1 day', pg_catalog.clock_timestamp() + interval '7 days'),
       ('c2000000-0000-4000-8000-000000000002', $1::uuid, $2::uuid, 'delivery_family', $4::uuid, 'OLD_HOLD', 'released', $5::uuid, pg_catalog.clock_timestamp(), pg_catalog.clock_timestamp() + interval '1 day')`,
      [ids.tenantId, ids.projectId, evHeld.payloadId, evExpire.wireEnvelopeId, ids.actorPrincipalId]
    );

    await tx.query(
      `INSERT INTO rq.retention_actions (
         id, tenant_id, project_id, target_kind, target_id, action, state, source_boundary_sha256, next_attempt_at
       ) VALUES
       ($1::uuid, $3::uuid, $4::uuid, 'event', $5::uuid, 'expire_payload', 'ready', $7::bytea, pg_catalog.clock_timestamp() - interval '5 seconds'),
       ($2::uuid, $3::uuid, $4::uuid, 'delivery_family', $6::uuid, 'expire_wire', 'ready', $8::bytea, pg_catalog.clock_timestamp() - interval '5 seconds')`,
      [
        actionHeldId,
        actionExpireId,
        ids.tenantId,
        ids.projectId,
        evHeld.payloadId,
        evExpire.wireEnvelopeId,
        shaBytes("rb1"),
        shaBytes("rb2")
      ]
    );
  });

  // Execute coordinator tick 1 (republish same-gen + threshold=5 quarantine + promote + reap + retention + projection check)
  const tick1 = await worker.runOnce({ forceNewGeneration: false });

  // Verify Flow 1: eligibility promotion
  assert.equal(tick1.promotion.promotedDeliveries, 1);
  assert.ok(tick1.promotion.promotedOutbox >= 1);
  const deliveriesRes = await db.query(
    `SELECT id, state FROM rq.deliveries WHERE id IN ($1::uuid, $2::uuid) ORDER BY id ASC`,
    [dueDeliveryId, futureDeliveryId]
  );
  assert.equal(deliveriesRes.rows[0]?.state, "ready");
  assert.equal(deliveriesRes.rows[1]?.state, "retry_wait");

  // Verify Flow 2: expired claims & watch leases reaped
  assert.equal(tick1.reaper.reapedAttempts, 1);
  assert.equal(tick1.reaper.reapedWatchLeases, 1);
  assert.ok(tick1.reaper.reapedOutboxClaims >= 1);
  assert.equal(tick1.reaper.reapedFanoutClaims, 1);

  const leaseCheck = await db.query(
    `SELECT state, slot_state, closed_at IS NOT NULL AS has_closed FROM rq.watch_leases WHERE id = $1::uuid`,
    [expiredWatchLeaseId]
  );
  assert.equal(leaseCheck.rows[0]?.state, "closed");
  assert.equal(leaseCheck.rows[0]?.slot_state, "released");
  assert.equal(leaseCheck.rows[0]?.has_closed, true);

  const outboxReapCheck = await db.query(
    `SELECT state, claim_owner_instance_id FROM rq.outbox_events WHERE id = $1::uuid`,
    [evReap.outboxId]
  );
  assert.equal(outboxReapCheck.rows[0]?.state, "pending");
  assert.equal(outboxReapCheck.rows[0]?.claim_owner_instance_id, null);

  const fanoutReapCheck = await db.query(
    `SELECT claim_owner_instance_id, safe_error_code FROM rq.event_fanout WHERE event_id = $1::uuid`,
    [evReap.eventId]
  );
  assert.equal(fanoutReapCheck.rows[0]?.claim_owner_instance_id, null);
  assert.equal(fanoutReapCheck.rows[0]?.safe_error_code, "FANOUT_CLAIM_EXPIRED");

  // Verify Flow 3: publication_recovery (threshold >= 5 -> review_required, same-gen dedup -> published)
  assert.equal(tick1.publicationRecovery.reviewRequiredCount, 1);
  assert.ok(tick1.publicationRecovery.quarantinedOutboxIds.includes(evThreshold5.outboxId));
  assert.ok(tick1.publicationRecovery.republishedCount >= 1);
  // JetStream deduplicated evRecoverSameGen (still only 1 stored message at seq 1)
  assert.equal(broker.getStoredMessage(2), null);

  const thresholdDb = await db.query(
    `SELECT o.state AS outbox_state, pre.state AS ep_state
       FROM rq.outbox_events o
       JOIN rq.publication_recovery_episodes pre ON pre.outbox_id = o.id
      WHERE o.id = $1::uuid`,
    [evThreshold5.outboxId]
  );
  assert.equal(thresholdDb.rows[0]?.outbox_state, "blocked");
  assert.equal(thresholdDb.rows[0]?.ep_state, "review_required");

  // Verify 1/min rate limit enforcement during forceNewGeneration sweep + max-5 generation ceiling
  const evRateLimited = await seedAdmittedEvent(db, ids, "000000000005");
  const evNewGenQuota = await seedAdmittedEvent(db, ids, "000000000009");
  await db.withTransaction("rq_migrator", async (tx) => {
    for (const ev of [evRateLimited, evNewGenQuota]) {
      await tx.query(
        `UPDATE rq.outbox_publications SET state = 'publish_unknown' WHERE outbox_id = $1::uuid`,
        [ev.outboxId]
      );
      await tx.query(
        `UPDATE rq.outbox_events SET next_publish_at = pg_catalog.clock_timestamp() - interval '5 seconds' WHERE id = $1::uuid`,
        [ev.outboxId]
      );
    }
    // Active recovery episode within 60s window for evRateLimited (rate limit 53400 guard)
    await tx.query(
      `INSERT INTO rq.publication_recovery_episodes (
         id, outbox_id, event_id, control_epoch, state, starting_fanout_version,
         last_progress_boundary_sha256, successive_no_progress_generations, last_generation_at
       ) VALUES (
         'e1000000-0000-4000-8000-000000000001', $1::uuid, $2::uuid, $3::uuid, 'active', 1,
         $4::bytea, 1, pg_catalog.clock_timestamp()
       )`,
      [evRateLimited.outboxId, evRateLimited.eventId, ids.controlEpoch, shaBytes("b1")]
    );
    // Simulate episode at count 4 older than 2 minutes -> 5th generation hits SQL ceiling -> review_required
    await tx.query(
      `INSERT INTO rq.publication_recovery_episodes (
         id, outbox_id, event_id, control_epoch, state, starting_fanout_version,
         last_progress_boundary_sha256, successive_no_progress_generations, last_generation_at
       ) VALUES (
         'e1000000-0000-4000-8000-000000000003', $1::uuid, $2::uuid, $3::uuid, 'active', 1,
         $4::bytea, 4, pg_catalog.clock_timestamp() - interval '2 minutes'
       )`,
      [evNewGenQuota.outboxId, evNewGenQuota.eventId, ids.controlEpoch, shaBytes("b3")]
    );
  });

  const tickRate = await worker.runOnce({ forceNewGeneration: true });
  assert.ok(tickRate.publicationRecovery.stillUnknownCount >= 1);
  const rateLimitedRow = await db.query(
    `SELECT current_publication_generation, state FROM rq.outbox_events WHERE id = $1::uuid`,
    [evRateLimited.outboxId]
  );
  assert.equal(rateLimitedRow.rows[0]?.current_publication_generation, "1");
  assert.equal(rateLimitedRow.rows[0]?.state, "pending");
  assert.ok(tickRate.publicationRecovery.quarantinedOutboxIds.includes(evNewGenQuota.outboxId));
  const newGenCheck = await db.query(
    `SELECT state FROM rq.outbox_events WHERE id = $1::uuid`,
    [evNewGenQuota.outboxId]
  );
  assert.equal(newGenCheck.rows[0]?.state, "blocked");

  // Verify Flow 4: retention holds respected, unheld wire envelope tombstoned
  assert.equal(tick1.retention.skippedHeldCount, 1);
  assert.equal(tick1.retention.completedCount, 1);
  const heldPayloadRes = await db.query(
    `SELECT content IS NOT NULL AS has_content, retention_state FROM rq.event_payloads WHERE id = $1::uuid`,
    [evHeld.payloadId]
  );
  assert.equal(heldPayloadRes.rows[0]?.has_content, true);
  assert.equal(heldPayloadRes.rows[0]?.retention_state, "required");
  const expiredWireRes = await db.query(
    `SELECT body_bytes IS NOT NULL AS has_body, retention_state FROM rq.event_wire_envelopes WHERE id = $1::uuid`,
    [evExpire.wireEnvelopeId]
  );
  assert.equal(expiredWireRes.rows[0]?.has_body, false);
  assert.equal(expiredWireRes.rows[0]?.retention_state, "expired");

  // Verify Flow 5: 16-shard delta compaction + drift verification/rebuild
  await db.withTransaction("rq_migrator", async (tx) => {
    for (const shard of [0, 5, 11, 15]) {
      await tx.query(
        `INSERT INTO rq.project_delivery_total_deltas (
           project_id, shard_id, tenant_id, total_deliveries_delta, pending_delta, active_delta, acknowledged_delta
         ) VALUES ($1::uuid, $2::smallint, $3::uuid, 2, 1, 0, 1)`,
        [ids.projectId, shard, ids.tenantId]
      );
      await tx.query(
        `INSERT INTO rq.event_delivery_totals (event_id, tenant_id, project_id, total_deliveries, terminal_deliveries, acknowledged_deliveries)
         VALUES ($1::uuid, $3::uuid, $2::uuid, 0, 0, 0)
         ON CONFLICT (event_id) DO NOTHING`,
        [evPromoted.eventId, ids.projectId, ids.tenantId]
      );
      await tx.query(
        `INSERT INTO rq.event_delivery_total_deltas (
           event_id, shard_id, tenant_id, project_id, total_deliveries_delta, terminal_deliveries_delta, acknowledged_deliveries_delta
         ) VALUES ($1::uuid, $2::smallint, $3::uuid, $4::uuid, 1, 1, 1)`,
        [evPromoted.eventId, shard, ids.tenantId, ids.projectId]
      );
    }
  });

  const tickCompact = await worker.runOnce({ forceNewGeneration: false });
  assert.equal(tickCompact.projections.compactedProjects, 1);
  assert.equal(tickCompact.projections.compactedEvents, 1);
  assert.equal(tickCompact.projections.driftedProjects, 1);
  assert.equal(tickCompact.projections.rebuiltProjects, 1);

  const remainingDeltas = await db.query(
    `SELECT (SELECT COUNT(*) FROM rq.project_delivery_total_deltas)::int AS p_cnt,
            (SELECT COUNT(*) FROM rq.event_delivery_total_deltas)::int AS e_cnt`
  );
  assert.equal(remainingDeltas.rows[0]?.p_cnt, 0);
  assert.equal(remainingDeltas.rows[0]?.e_cnt, 0);

  const totalsAfterRebuild = await db.withTransaction("rq_coordinator", (tx) =>
    readProjectDeliveryTotals(tx, ids.tenantId, ids.projectId)
  );
  assert.equal(totalsAfterRebuild.totalDeliveries, 3n);
  assert.equal(totalsAfterRebuild.pendingCount, 3n);
  assert.equal(totalsAfterRebuild.activeCount, 0n);

  const verifyClean = await worker.service.verifyProjectProjection({
    tenantId: ids.tenantId,
    projectId: ids.projectId
  });
  assert.equal(verifyClean.consistent, true);
});

test("CoordinatorWorker lifecycle start/stop, node:http health probes, and CLI parsing work", async (t) => {
  const parsed = parseCoordinatorCliArgs([
    "--config",
    "./config/portable.coordinator.json",
    "--once",
    "--health-port",
    "0"
  ]);
  assert.equal(parsed.configPath, "./config/portable.coordinator.json");
  assert.equal(parsed.once, true);
  assert.equal(parsed.healthPort, 0);

  const db = await createPGliteAdapter({ schema: "rq", isolation: "shared_database_schemas" });
  const brokerGenId = parseBrokerGenerationId("81000000-0000-4000-8000-000000000002");
  await applyMigrations(db);
  const ids = await seedFixtureBase(db, brokerGenId);

  const worker = createCoordinatorWorker({
    pgAdapter: db,
    instanceId: parseRuntimeInstanceId("90000000-0000-4000-8000-000000000002"),
    controlEpoch: ids.controlEpoch,
    settings: { loop_interval_ms: 50 }
  });
  const health = createCoordinatorHealthServer({ probe: worker, port: 0 });
  const addr = await health.start();

  t.after(async () => {
    await worker.stop();
    await health.stop();
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
  const snapshot = worker.getHealth();
  assert.equal(snapshot.live, false);
  assert.equal(snapshot.ready, false);
});
