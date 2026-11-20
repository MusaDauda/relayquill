import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { Temporal } from "@js-temporal/polyfill";
import {
  nowUtcInstant,
  parseAttemptId,
  parseBrokerGenerationId,
  parseBrokerInboxId,
  parseCommandReceiptId,
  parseControlEpoch,
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
  parsePublicationObservationId,
  parseRecoveryActionId,
  parseRecoveryIncidentId,
  parseRecoveryOperationId,
  parseRuntimeInstanceId,
  parseSessionId,
  parseSha256Hex,
  parseSubscriptionId,
  parseTenantId,
  parseWatchLeaseId,
  parseWireEnvelopeId
} from "@relayquill/domain";
import {
  PostgresRuntimeRegistryStore,
  acceptBrokerInbox,
  acquireProjectMaintenance,
  admitEvent,
  claimEventFanout,
  claimOutboxEvent,
  closeRecoveryIncident,
  closeWatchLease,
  commitFanoutPage,
  compactDeliveryTotalDeltas,
  createPGliteAdapter,
  createRecoveryOperation,
  executeEstablishTargetEpoch,
  executeRebuildProjection,
  finalizeDeliveryAttempt,
  lockDeliveryDispatchAuthoritiesShare,
  observeOutboxPublication,
  openRecoveryIncident,
  openWatchLease,
  planRecoveryAction,
  prepareDispatchDelivery,
  readClaimInventory,
  readDeliverySafe,
  readEventCausalChain,
  readEventDeliveryDeltaShards,
  readEventDeliveryTotals,
  readEventPayloadBytes,
  readEventSafe,
  readInstallationStatus,
  readObligationInventory,
  readProjectDeliveryDeltaShards,
  readProjectDeliveryTotals,
  readProjectQueueHealth,
  readProjectionSourceCounts,
  readRecoveryOperationResult,
  readSchemaMigrations,
  readWireEnvelopeBytes,
  reapExpiredCoordinatorWork,
  registerRuntimeInstance,
  releaseProjectMaintenance,
  renewWatchLease,
  resolveAdmittedEvent,
  reviewRecoveryAction,
  startDeliverySend
} from "@relayquill/postgres";

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");

function shaHex(text) {
  return parseSha256Hex(crypto.createHash("sha256").update(text).digest("hex"));
}

function shaBytes(text) {
  return crypto.createHash("sha256").update(text).digest();
}

async function applyCoreMigrations(db) {
  const dir = path.join(REPO_ROOT, "migrations");
  const files = fs.readdirSync(dir).filter((f) => f.endsWith(".sql")).sort();
  for (const file of files) {
    await db.exec(fs.readFileSync(path.join(dir, file), "utf8"));
  }
}

test("Typed PostgreSQL repositories run full event -> outbox -> inbox -> fanout -> dispatch -> send -> finalize -> sharded projections -> recovery roundtrip on PGlite", async (t) => {
  const db = await createPGliteAdapter({ schema: "rq", isolation: "shared_database_schemas" });
  t.after(() => db.close());
  await applyCoreMigrations(db);

  const ids = {
    tenantId: parseTenantId("10000000-0000-4000-8000-000000000001"),
    projectId: parseProjectId("20000000-0000-4000-8000-000000000001"),
    actorPrincipalId: parsePrincipalId("30000000-0000-4000-8000-000000000001"),
    producerPrincipalId: parsePrincipalId("30000000-0000-4000-8000-000000000002"),
    producerId: parseProducerId("40000000-0000-4000-8000-000000000001"),
    eventTypeId: parseEventTypeId("50000000-0000-4000-8000-000000000001"),
    endpointId: parseEndpointId("60000000-0000-4000-8000-000000000001"),
    signingKeyId: "61000000-0000-4000-8000-000000000001",
    subscriptionId: parseSubscriptionId("70000000-0000-4000-8000-000000000001"),
    dispatchDomainId: "80000000-0000-4000-8000-000000000001",
    brokerGenId: parseBrokerGenerationId("81000000-0000-4000-8000-000000000001"),
    apiInstanceId: parseRuntimeInstanceId("90000000-0000-4000-8000-000000000001"),
    relayInstanceId: parseRuntimeInstanceId("90000000-0000-4000-8000-000000000002"),
    fanoutInstanceId: parseRuntimeInstanceId("90000000-0000-4000-8000-000000000003"),
    senderInstanceId: parseRuntimeInstanceId("90000000-0000-4000-8000-000000000004"),
    coordInstanceId: parseRuntimeInstanceId("90000000-0000-4000-8000-000000000005"),
    eventId: parseEventId("a0000000-0000-4000-8000-000000000001"),
    payloadId: parseEventPayloadId("a1000000-0000-4000-8000-000000000001"),
    wireEnvelopeId: parseWireEnvelopeId("a2000000-0000-4000-8000-000000000001"),
    outboxId: parseOutboxId("a3000000-0000-4000-8000-000000000001"),
    receiptId: parseCommandReceiptId("a4000000-0000-4000-8000-000000000001"),
    auditId: "a5000000-0000-4000-8000-000000000001",
    obsId: parsePublicationObservationId("a6000000-0000-4000-8000-000000000001"),
    inboxId: parseBrokerInboxId("a7000000-0000-4000-8000-000000000001"),
    deliveryId: parseDeliveryId("a8000000-0000-4000-8000-000000000001"),
    familyId: parseDeliveryFamilyId("a9000000-0000-4000-8000-000000000001"),
    prepReqId: "aa000000-0000-4000-8000-000000000001",
    attemptId: parseAttemptId("ab000000-0000-4000-8000-000000000001"),
    leaseId: parseWatchLeaseId("ac000000-0000-4000-8000-000000000001")
  };

  const initStatus = await db.withTransaction("rq_api", (tx) => readInstallationStatus(tx));
  assert.equal(initStatus.mode, "initializing");
  assert.equal(initStatus.allowEventAdmission, false);

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

  const installStatus = await db.withTransaction("rq_api", (tx) => readInstallationStatus(tx));
  assert.equal(installStatus.mode, "open");
  assert.equal(installStatus.allowEventAdmission, true);
  const controlEpoch = installStatus.controlEpoch;

  await db.withTransaction("rq_migrator", async (tx) => {
    const migrations = await readSchemaMigrations(tx);
    assert.ok(Array.isArray(migrations));

    await tx.query(
      `INSERT INTO rq.principals (id, kind, state) VALUES ($1::uuid, 'human', 'active'), ($2::uuid, 'producer', 'active')`,
      [ids.actorPrincipalId, ids.producerPrincipalId]
    );
    await tx.query(
      `INSERT INTO rq.humans (principal_id, principal_kind, display_name, webauthn_user_id)
       VALUES ($1::uuid, 'human', 'Alice Ops', $2::bytea)`,
      [ids.actorPrincipalId, shaBytes("actor-webauthn")]
    );
    await tx.query(
      `INSERT INTO rq.tenants (id, slug, display_name, state) VALUES ($1::uuid, 'acme', 'Acme', 'active')`,
      [ids.tenantId]
    );
    await tx.query(
      `INSERT INTO rq.projects (id, tenant_id, name, state, topology_version) VALUES ($1::uuid, $2::uuid, 'core', 'active', 1)`,
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
       VALUES ($1::uuid, $2::uuid, $3::uuid, 'hook-a', 'active', 1, 1, 1, $4::uuid)`,
      [ids.endpointId, ids.tenantId, ids.projectId, ids.actorPrincipalId]
    );
    await tx.query(
      `INSERT INTO rq.endpoint_versions (endpoint_id, endpoint_version, tenant_id, project_id, destination_url, normalized_hostname, port, path_and_query_sha256, url_policy_version, network_policy_version, request_profile_version, response_profile_version, configuration_sha256, created_by)
       VALUES ($1::uuid, 1, $2::uuid, $3::uuid, 'https://receiver.example.test/webhook', 'receiver.example.test', 443, $4::bytea, 'url_v1', 'network_v1', 'request_v1', 'response_v1', $5::bytea, $6::uuid)`,
      [ids.endpointId, ids.tenantId, ids.projectId, shaBytes("path"), shaBytes("epcfg"), ids.actorPrincipalId]
    );
    await tx.query(
      `INSERT INTO rq.endpoint_capacity (endpoint_id, tenant_id, project_id, approved_active_slots, held_slots)
       VALUES ($1::uuid, $2::uuid, $3::uuid, 32, 0)`,
      [ids.endpointId, ids.tenantId, ids.projectId]
    );
    await tx.query(
      `INSERT INTO rq.endpoint_dispatch_grants (id, tenant_id, project_id, endpoint_id, endpoint_version, security_epoch, grant_class, state, approved_by, approved_configuration_sha256)
       VALUES ('62000000-0000-4000-8000-000000000001'::uuid, $1::uuid, $2::uuid, $3::uuid, 1, 1, 'current_destination', 'active', $4::uuid, $5::bytea)`,
      [ids.tenantId, ids.projectId, ids.endpointId, ids.actorPrincipalId, shaBytes("epcfg")]
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
    await tx.query(
      `INSERT INTO rq.endpoint_circuits (endpoint_id, endpoint_version, tenant_id, project_id, state, circuit_generation, policy_kind, policy_version)
       VALUES ($1::uuid, 1, $2::uuid, $3::uuid, 'closed', 1, 'circuit', 'circuit_v1')`,
      [ids.endpointId, ids.tenantId, ids.projectId]
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
      `INSERT INTO rq.subscriptions (id, tenant_id, project_id, name, state, current_version, control_sequence, send_hold, created_by)
       VALUES ($1::uuid, $2::uuid, $3::uuid, 'sub-a', 'active', 1, 1, false, $4::uuid)`,
      [ids.subscriptionId, ids.tenantId, ids.projectId, ids.actorPrincipalId]
    );
    await tx.query(
      `INSERT INTO rq.subscription_versions (subscription_id, subscription_version, tenant_id, project_id, endpoint_id, endpoint_version, event_type_id, filter_profile_version, filter_ast, filter_sha256, ordering_mode, retry_policy_version, response_policy_kind, response_policy_version, consumer_contract_scope, receiver_contract_id, receiver_contract_version, configuration_sha256, created_by)
       VALUES ($1::uuid, 1, $2::uuid, $3::uuid, $4::uuid, 1, $5::uuid, 'relayquill.filter.v1', '{"all":[]}'::jsonb, $6::bytea, 'unordered', 'retry_v1', 'response', 'response_v1', 'default', $7::uuid, 1, $8::bytea, $9::uuid)`,
      [ids.subscriptionId, ids.tenantId, ids.projectId, ids.endpointId, ids.eventTypeId, shaBytes("filter"), receiverContractId, shaBytes("subcfg"), ids.actorPrincipalId]
    );
    await tx.query(
      `INSERT INTO rq.subscription_schema_versions (subscription_id, subscription_version, tenant_id, project_id, event_type_id, event_schema_version)
       VALUES ($1::uuid, 1, $2::uuid, $3::uuid, $4::uuid, 1)`,
      [ids.subscriptionId, ids.tenantId, ids.projectId, ids.eventTypeId]
    );
    const setupReceiptId = "64000000-0000-4000-8000-000000000001";
    const activationEventId = "65000000-0000-4000-8000-000000000001";
    await tx.query(
      `INSERT INTO rq.command_receipts (id, scope_kind, tenant_id, project_id, actor_principal_id, command_family, key_sha256, submitted_shape_sha256, effective_request_sha256, resource_kind, resource_id, accepted_version)
       VALUES ($1::uuid, 'project', $2::uuid, $3::uuid, $4::uuid, 'subscription.control', $5::bytea, $6::bytea, $7::bytea, 'subscription', $8::uuid, 1)`,
      [setupReceiptId, ids.tenantId, ids.projectId, ids.actorPrincipalId, shaBytes("subkey"), shaBytes("subshape"), shaBytes("subeff"), ids.subscriptionId]
    );
    await tx.query(
      `INSERT INTO rq.subscription_control_events (id, subscription_id, tenant_id, project_id, control_sequence, action, prior_version, resulting_version, topology_version, actor_principal_id, command_receipt_id, safe_reason_code)
       VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid, 1, 'activate', NULL, 1, 1, $5::uuid, $6::uuid, 'initial_activate')`,
      [activationEventId, ids.subscriptionId, ids.tenantId, ids.projectId, ids.actorPrincipalId, setupReceiptId]
    );
    await tx.query(
      `INSERT INTO rq.subscription_topology_ranges (project_id, tenant_id, subscription_id, subscription_version, from_topology_version, activation_event_id)
       VALUES ($1::uuid, $2::uuid, $3::uuid, 1, 1, $4::uuid)`,
      [ids.projectId, ids.tenantId, ids.subscriptionId, activationEventId]
    );
    await tx.query(
      `INSERT INTO rq.broker_stream_generations (id, deployment_reference, cluster_reference, stream_name, observed_stream_created_at, configuration_sha256, state, created_by_operator_reference)
       VALUES ($1::uuid, 'dep', 'cls', 'RELAYQUILL_EVENTS_V1', pg_catalog.clock_timestamp(), $2::bytea, 'active', 'op')`,
      [ids.brokerGenId, shaBytes("stream")]
    );
    await tx.query(
      `INSERT INTO rq.dispatch_domains (id, name, state, policy_kind, policy_version, policy_sha256)
       VALUES ($1::uuid, 'default', 'active', 'dispatch', 'dispatch_v1', $2::bytea)`,
      [ids.dispatchDomainId, shaBytes("wdrr")]
    );
    await tx.query(
      `INSERT INTO rq.dispatch_state (dispatch_domain_id, policy_epoch, round_number) VALUES ($1::uuid, 1, 1)`,
      [ids.dispatchDomainId]
    );
    await tx.query(
      `INSERT INTO rq.project_dispatch_memberships (project_id, tenant_id, dispatch_domain_id, state, policy_version)
       VALUES ($1::uuid, $2::uuid, $3::uuid, 'active', 'dispatch_v1')`,
      [ids.projectId, ids.tenantId, ids.dispatchDomainId]
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
    await tx.query(
      `INSERT INTO rq.endpoint_rate_buckets (endpoint_id, tenant_id, project_id, operation, tokens_micro, reserved_micro, capacity_micro, refill_micro_per_second, refill_remainder_numerator, last_refill_at, policy_version)
       VALUES ($1::uuid, $2::uuid, $3::uuid, 'send_start', 100000000, 0, 100000000, 10000000, 0, pg_catalog.clock_timestamp(), 1)`,
      [ids.endpointId, ids.tenantId, ids.projectId]
    );
  });

  // RuntimeRegistryStore & role registrations
  const registry = new PostgresRuntimeRegistryStore(db, "rq_api");
  const apiReg = await registry.registerInstance({
    instanceId: ids.apiInstanceId,
    processRole: "api",
    databaseRole: "rq_api",
    controlEpoch,
    buildReference: "test-build",
    leaseMs: 60_000n,
    now: nowUtcInstant()
  });
  assert.equal(apiReg.state, "active");
  const beat = await registry.heartbeatInstance({
    instanceId: ids.apiInstanceId,
    controlEpoch,
    expectedVersion: apiReg.version,
    leaseMs: 60_000n,
    now: nowUtcInstant()
  });
  assert.equal(beat.version, 2n);

  for (const [instanceId, processRole, databaseRole] of [
    [ids.relayInstanceId, "relay", "rq_relay"],
    [ids.fanoutInstanceId, "fanout", "rq_fanout"],
    [ids.senderInstanceId, "sender", "rq_sender"],
    [ids.coordInstanceId, "coordinator", "rq_coordinator"]
  ]) {
    await db.withTransaction(databaseRole, (tx) =>
      registerRuntimeInstance(tx, {
        instanceId,
        processRole,
        databaseRole,
        controlEpoch,
        buildReference: "test-build",
        leaseMs: 60_000n,
        approvedSlots: 16
      })
    );
  }

  // Event admission + idempotency + resolution + safe read + restricted byte read
  const contentBytes = Buffer.from('{"order_id":"ord-1"}');
  const wireBytes = Buffer.from('{"id":"ord-1","type":"order.created"}');
  const brokerBytes = Buffer.from('{"outbox":"1"}');
  const deadline = nowUtcInstant().add({ seconds: 1800 });

  const admitRes = await db.withTransaction("rq_api", (tx) =>
    admitEvent(tx, {
      tenantId: ids.tenantId,
      projectId: ids.projectId,
      actorPrincipalId: ids.actorPrincipalId,
      producerId: ids.producerId,
      producerNamespace: "orders",
      businessKey: "ord-1",
      businessKeySha256: shaHex("bk:ord-1"),
      idempotencyKeySha256: shaHex("idem:ord-1"),
      submittedShapeSha256: shaHex("shape:ord-1"),
      effectiveRequestSha256: shaHex("eff:ord-1"),
      eventTypeId: ids.eventTypeId,
      eventSchemaVersion: 1,
      content: contentBytes,
      contentSha256: shaHex(contentBytes),
      wireEnvelopeBytes: wireBytes,
      wireEnvelopeSha256: shaHex(wireBytes),
      brokerEnvelopeBytes: brokerBytes,
      brokerEnvelopeSha256: shaHex(brokerBytes),
      producerEventTime: nowUtcInstant(),
      deliveryDeadlineAt: deadline,
      appliedDefaults: { ttl_seconds: 1800 },
      retentionPolicyVersion: "ret.v1",
      eventId: ids.eventId,
      payloadId: ids.payloadId,
      wireEnvelopeId: ids.wireEnvelopeId,
      outboxId: ids.outboxId,
      receiptId: ids.receiptId,
      auditId: ids.auditId
    })
  );
  assert.equal(admitRes.outcome, "accepted");
  assert.equal(admitRes.projectEventSequence, 1n);

  const resolved = await db.withTransaction("rq_api", (tx) =>
    resolveAdmittedEvent(tx, {
      tenantId: ids.tenantId,
      projectId: ids.projectId,
      actorPrincipalId: ids.actorPrincipalId,
      producerNamespace: "orders",
      businessKeySha256: shaHex("bk:ord-1"),
      idempotencyKeySha256: shaHex("idem:ord-1"),
      submittedShapeSha256: shaHex("shape:ord-1")
    })
  );
  assert.equal(resolved.found, true);
  assert.equal(resolved.eventId, ids.eventId);

  const safeEv = await db.withTransaction("rq_reporter", (tx) =>
    readEventSafe(tx, ids.tenantId, ids.projectId, ids.eventId)
  );
  assert.equal(safeEv?.state, "accepted");

  const payloadRes = await db.withTransaction("rq_api", (tx) =>
    readEventPayloadBytes(tx, ids.tenantId, ids.projectId, ids.eventId)
  );
  assert.deepEqual(payloadRes?.content, contentBytes);

  const wireRes = await db.withTransaction("rq_sender", (tx) =>
    readWireEnvelopeBytes(tx, ids.tenantId, ids.projectId, ids.wireEnvelopeId)
  );
  assert.deepEqual(wireRes?.bodyBytes, wireBytes);

  // Outbox claim + observe
  const claimed = await db.withTransaction("rq_relay", (tx) =>
    claimOutboxEvent(tx, {
      outboxId: ids.outboxId,
      instanceId: ids.relayInstanceId,
      controlEpoch,
      claimLeaseMs: 15_000n
    })
  );
  assert.deepEqual(claimed.envelopeBytes, brokerBytes);

  const observed = await db.withTransaction("rq_relay", (tx) =>
    observeOutboxPublication(tx, {
      outboxId: ids.outboxId,
      publicationGeneration: claimed.publicationGeneration,
      instanceId: ids.relayInstanceId,
      controlEpoch,
      expectedClaimGeneration: claimed.claimGeneration,
      outcome: "published",
      brokerGenerationId: ids.brokerGenId,
      streamName: "RELAYQUILL_EVENTS_V1",
      streamSequence: 1n,
      observationId: ids.obsId
    })
  );
  assert.equal(observed.acceptedAsCurrent, true);
  assert.equal(observed.outboxState, "published");

  // Inbox accept -> fanout claim -> fanout page
  const inboxRes = await db.withTransaction("rq_fanout", (tx) =>
    acceptBrokerInbox(tx, {
      outboxId: ids.outboxId,
      publicationGeneration: claimed.publicationGeneration,
      eventId: ids.eventId,
      projectId: ids.projectId,
      topologyVersion: 1n,
      envelopeSha256: shaHex(brokerBytes),
      brokerGenerationId: ids.brokerGenId,
      streamSequence: 1n,
      inboxId: ids.inboxId,
      instanceId: ids.fanoutInstanceId,
      controlEpoch
    })
  );
  assert.equal(inboxRes.isNextContiguous, true);

  const fanoutClaim = await db.withTransaction("rq_fanout", (tx) =>
    claimEventFanout(tx, {
      eventId: ids.eventId,
      instanceId: ids.fanoutInstanceId,
      controlEpoch,
      claimLeaseMs: 15_000n
    })
  );
  assert.equal(fanoutClaim.outcome, "claimed");

  const fanoutPage = await db.withTransaction("rq_fanout", (tx) =>
    commitFanoutPage(tx, {
      eventId: ids.eventId,
      instanceId: ids.fanoutInstanceId,
      controlEpoch,
      expectedClaimGeneration: fanoutClaim.claimGeneration,
      complete: true,
      outcomes: [
        {
          subscription_id: ids.subscriptionId,
          subscription_version: "1",
          outcome: "matched",
          filter_profile_version: "filter.v1",
          filter_sha256: shaHex("filter"),
          delivery_id: ids.deliveryId,
          family_id: ids.familyId,
          endpoint_id: ids.endpointId,
          endpoint_version: "1",
          wire_envelope_id: ids.wireEnvelopeId,
          consumer_contract_scope: "default",
          consumer_event_key_sha256: shaHex("cek:ord-1")
        }
      ]
    })
  );
  assert.equal(fanoutPage.outcome, "completed");
  assert.equal(fanoutPage.newDeliveries, 1n);

  // Dispatch authorities FOR SHARE -> prepare -> send_start -> finalize
  const shareLock = await db.withTransaction("rq_sender", (tx) =>
    lockDeliveryDispatchAuthoritiesShare(tx, ids.tenantId, ids.projectId)
  );
  assert.equal(shareLock.project.id, ids.projectId);

  const prep = await db.withTransaction("rq_sender", (tx) =>
    prepareDispatchDelivery(tx, {
      requestId: ids.prepReqId,
      dispatchDomainId: ids.dispatchDomainId,
      workerInstanceId: ids.senderInstanceId,
      controlEpoch,
      requestSha256: shaHex("prep-req-1"),
      deliveryId: ids.deliveryId,
      attemptId: ids.attemptId,
      claimLeaseMs: 30_000n
    })
  );
  assert.equal(prep.outcome, "prepared");

  const started = await db.withTransaction("rq_sender", (tx) =>
    startDeliverySend(tx, {
      attemptId: ids.attemptId,
      workerInstanceId: ids.senderInstanceId,
      controlEpoch,
      expectedFencingToken: prep.fencingToken,
      networkBudgetMs: 10_000n
    })
  );
  assert.equal(started.shouldSend, true);

  const fin = await db.withTransaction("rq_sender", (tx) =>
    finalizeDeliveryAttempt(tx, {
      attemptId: ids.attemptId,
      workerInstanceId: ids.senderInstanceId,
      controlEpoch,
      expectedFencingToken: prep.fencingToken,
      attemptState: "response_observed",
      outcomeClass: "acknowledged",
      responseStatus: 204,
      responseBodySha256: shaHex(""),
      responseByteCount: 0,
      retryDecision: "acknowledged"
    })
  );
  assert.equal(fin.outcome, "finalized");
  assert.equal(fin.deliveryState, "acknowledged");

  const safeDel = await db.withTransaction("rq_reporter", (tx) =>
    readDeliverySafe(tx, ids.tenantId, ids.projectId, ids.deliveryId)
  );
  assert.equal(safeDel?.state, "acknowledged");

  // Sharded deltas + compaction + diagnostics
  const evDeltas = await db.withTransaction("rq_reporter", (tx) =>
    readEventDeliveryDeltaShards(tx, ids.tenantId, ids.projectId, ids.eventId)
  );
  assert.equal(evDeltas.aggregated.acknowledgedDeliveriesDelta, 1n);

  const projDeltas = await db.withTransaction("rq_reporter", (tx) =>
    readProjectDeliveryDeltaShards(tx, ids.tenantId, ids.projectId)
  );
  assert.equal(projDeltas.aggregated.acknowledgedDelta, 1n);

  await db.withTransaction("rq_coordinator", (tx) =>
    compactDeliveryTotalDeltas(tx, {
      tenantId: ids.tenantId,
      projectId: ids.projectId,
      eventId: ids.eventId
    })
  );

  const projTotals = await db.withTransaction("rq_reporter", (tx) =>
    readProjectDeliveryTotals(tx, ids.tenantId, ids.projectId)
  );
  assert.equal(projTotals.totalDeliveries, 1n);
  assert.equal(projTotals.acknowledgedCount, 1n);

  const evTotals = await db.withTransaction("rq_reporter", (tx) =>
    readEventDeliveryTotals(tx, ids.tenantId, ids.projectId, ids.eventId)
  );
  assert.equal(evTotals.acknowledgedDeliveries, 1n);

  const chain = await db.withTransaction("rq_reporter", (tx) =>
    readEventCausalChain(tx, ids.tenantId, ids.projectId, ids.eventId)
  );
  assert.equal(chain.deliveries.length, 1);
  assert.equal(chain.attemptsByDeliveryId.get(ids.deliveryId)?.length, 1);

  const health = await db.withTransaction("rq_reporter", (tx) =>
    readProjectQueueHealth(tx, ids.tenantId, ids.projectId)
  );
  assert.equal(health.pendingOutboxCount, 0n);

  // Watch lease & reaper
  const watchSessionId = parseSessionId("ad000000-0000-4000-8000-000000000001");
  await db.exec(
    `INSERT INTO rq.human_sessions (id, principal_id, control_epoch, token_digest, csrf_digest, principal_authority_epoch, purpose, state, idle_expires_at, absolute_expires_at)
     VALUES ('${watchSessionId}', '${ids.actorPrincipalId}', '${controlEpoch}', pg_catalog.sha256('sess-tok'::bytea), pg_catalog.sha256('sess-csrf'::bytea), 1, 'ordinary', 'active', pg_catalog.clock_timestamp() + interval '30 minutes', pg_catalog.clock_timestamp() + interval '60 minutes')`
  );
  const openedWatch = await db.withTransaction("rq_api", (tx) =>
    openWatchLease(tx, {
      leaseId: ids.leaseId,
      tenantId: ids.tenantId,
      projectId: ids.projectId,
      principalId: ids.actorPrincipalId,
      actorKind: "human",
      sessionId: watchSessionId,
      resourceKind: "event",
      resourceId: ids.eventId,
      runtimeInstanceId: ids.apiInstanceId,
      controlEpoch,
      authCutoffAt: nowUtcInstant().add({ minutes: 10 }),
      streamCutoffAt: nowUtcInstant().add({ seconds: 60 })
    })
  );
  assert.equal(openedWatch.leaseId, ids.leaseId);
  await assert.rejects(
    () =>
      db.withTransaction("rq_api", (tx) =>
        renewWatchLease(tx, {
          leaseId: ids.leaseId,
          controlEpoch,
          authCutoffAt: nowUtcInstant().add({ minutes: 10 })
        })
      ),
    (err) => err.code === "RATE_LIMITED"
  );
  await new Promise((resolve) => setTimeout(resolve, 1050));
  await db.withTransaction("rq_api", (tx) =>
    renewWatchLease(tx, {
      leaseId: ids.leaseId,
      controlEpoch,
      authCutoffAt: nowUtcInstant().add({ minutes: 10 })
    })
  );
  const closedWatch = await db.withTransaction("rq_api", (tx) => closeWatchLease(tx, ids.leaseId));
  assert.equal(closedWatch.outcome, "closed");
  const reaped = await db.withTransaction("rq_coordinator", (tx) =>
    reapExpiredCoordinatorWork(tx, {
      instanceId: ids.coordInstanceId,
      controlEpoch,
      batchLimit: 10
    })
  );
  assert.equal(typeof reaped.reapedAttempts, "number");

  // Protected rq_recovery incident -> operation -> plan -> review -> execute -> read_operation_result -> close
  const dbIdRes = await db.query(
    "SELECT pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(pg_catalog.current_database(), 'UTF8')), 'hex') AS db_sha"
  );
  const dbDigest = parseSha256Hex(dbIdRes.rows[0].db_sha);
  const targetEpoch = parseControlEpoch("f1000000-0000-4000-8000-000000000001");
  const incId = parseRecoveryIncidentId("f2000000-0000-4000-8000-000000000001");
  const opId = parseRecoveryOperationId("f3000000-0000-4000-8000-000000000001");
  const actEpochId = parseRecoveryActionId("f4000000-0000-4000-8000-000000000001");
  const actRebuildId = parseRecoveryActionId("f4000000-0000-4000-8000-000000000002");

  await db.withTransaction("rq_recovery", async (tx) => {
    const inc = await openRecoveryIncident(tx, {
      incidentId: incId,
      externalOperationId: "f5000000-0000-4000-8000-000000000001",
      incidentReference: "INC-PG-1",
      scopeKind: "installation"
    });
    assert.equal(inc.outcome, "opened");

    const op = await createRecoveryOperation(tx, {
      operationId: opId,
      incidentId: incId,
      externalOperationId: "f5000000-0000-4000-8000-000000000002",
      sourceEpoch: controlEpoch,
      targetEpoch,
      targetDatabaseIdentityDigest: dbDigest,
      planSha256: shaHex("plan-1"),
      requesterReference: "op-alice"
    });
    assert.equal(op.outcome, "planned");

    const expFactsSha = shaHex("exp-epoch");
    const propFactsSha = shaHex("prop-epoch");
    await planRecoveryAction(tx, {
      actionId: actEpochId,
      operationId: opId,
      ordinal: 1,
      kind: "establish_target_epoch",
      scopeKind: "installation",
      expectedTargetVersion: installStatus.version,
      expectedControlEpoch: controlEpoch,
      expectedFactsSha256: expFactsSha,
      proposedFactsSha256: propFactsSha,
      requesterReference: "op-alice",
      reasonCode: "epoch_rotate",
      evidenceReference: "ev-1",
      typedPlan: {
        source_epoch: controlEpoch,
        target_epoch: targetEpoch,
        expected_installation_version: Number(installStatus.version),
        target_database_identity_digest_hex: dbDigest,
        containment_evidence_reference: "containment-1",
        broker_generation_evidence_reference: "broker-1",
        proposed_mode: "admission_hold"
      }
    });

    await reviewRecoveryAction(tx, {
      reviewId: "f6000000-0000-4000-8000-000000000001",
      actionId: actEpochId,
      planSha256: shaHex("plan-1"),
      targetEpoch,
      expectedFactsSha256: expFactsSha,
      proposedFactsSha256: propFactsSha,
      reviewerReference: "op-bob",
      decision: "approve",
      expiresAt: Temporal.Instant.from(nowUtcInstant()).add({ minutes: 10 }),
      authorityEvidenceDigest: shaHex("auth-bob")
    });

    const execRes = await executeEstablishTargetEpoch(tx, {
      actionId: actEpochId,
      operatorReference: "op-charlie",
      executionNonceDigest: shaHex("nonce-1"),
      targetDatabaseIdentityDigest: dbDigest
    });
    assert.equal(execRes.outcome, "applied");

    const storedRes = await readRecoveryOperationResult(tx, actEpochId);
    assert.equal(storedRes["outcome"], "applied");

    const claims = await readClaimInventory(tx, ids.tenantId, ids.projectId);
    assert.ok(Array.isArray(claims));
    const obligations = await readObligationInventory(tx, ids.tenantId, ids.projectId);
    assert.equal(obligations.length, 1);
    const srcCounts = await readProjectionSourceCounts(tx, ids.tenantId, ids.projectId, ids.eventId);
    assert.equal(srcCounts["total_deliveries"], 1);

    const maint = await acquireProjectMaintenance(tx, {
      operationId: opId,
      tenantId: ids.tenantId,
      projectId: ids.projectId,
      expectedVersion: 2n, // admitEvent incremented project version from 1 to 2
      operatorReference: "op-charlie"
    });
    assert.equal(maint.outcome, "acquired");

    await planRecoveryAction(tx, {
      actionId: actRebuildId,
      operationId: opId,
      ordinal: 2,
      kind: "rebuild_projection",
      scopeKind: "project",
      tenantId: ids.tenantId,
      projectId: ids.projectId,
      targetId: ids.eventId,
      expectedTargetVersion: evTotals.version,
      expectedControlEpoch: targetEpoch,
      expectedFactsSha256: shaHex("exp-reb"),
      proposedFactsSha256: shaHex("prop-reb"),
      requesterReference: "op-alice",
      reasonCode: "rebuild_verify",
      evidenceReference: "ev-2",
      typedPlan: {
        projection_kind: "event_delivery_totals",
        event_id: ids.eventId,
        population_definition_version: "delivery_population.v1",
        expected_projection_version: Number(evTotals.version),
        expected_source_boundary_sha256_hex: shaHex("boundary"),
        max_source_rows: 1000,
        proposed_total_deliveries: 1,
        proposed_acknowledged_count: 1,
        proposed_terminal_deliveries: 1,
        diagnostic_mismatch_sha256_hex: shaHex("diag")
      }
    });

    await reviewRecoveryAction(tx, {
      reviewId: "f6000000-0000-4000-8000-000000000002",
      actionId: actRebuildId,
      planSha256: shaHex("plan-1"),
      targetEpoch,
      expectedFactsSha256: shaHex("exp-reb"),
      proposedFactsSha256: shaHex("prop-reb"),
      reviewerReference: "op-bob",
      decision: "approve",
      expiresAt: Temporal.Instant.from(nowUtcInstant()).add({ minutes: 10 }),
      authorityEvidenceDigest: shaHex("auth-bob-2")
    });

    const rebRes = await executeRebuildProjection(tx, {
      actionId: actRebuildId,
      operatorReference: "op-charlie",
      executionNonceDigest: shaHex("nonce-2"),
      targetDatabaseIdentityDigest: dbDigest
    });
    assert.equal(rebRes.outcome, "applied");

    const rel = await releaseProjectMaintenance(tx, {
      operationId: opId,
      tenantId: ids.tenantId,
      projectId: ids.projectId,
      expectedVersion: maint.maintenanceVersion,
      operatorReference: "op-charlie"
    });
    assert.equal(rel.outcome, "released");

    const closed = await closeRecoveryIncident(tx, {
      incidentId: incId,
      expectedVersion: inc.version,
      remainingRiskDecisionCode: "risk_none",
      operatorReference: "op-charlie"
    });
    assert.equal(closed.outcome, "closed");
  });
});
