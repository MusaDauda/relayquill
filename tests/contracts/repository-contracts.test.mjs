import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  DomainError,
  nowUtcInstant,
  parseAttemptId,
  parseBrokerGenerationId,
  parseBrokerInboxId,
  parseCommandReceiptId,
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
  parseRuntimeInstanceId,
  parseSha256Hex,
  parseSubscriptionId,
  parseTenantId,
  parseWireEnvelopeId
} from "@relayquill/domain";
import {
  DELIVERY_DELTA_SHARD_COUNT,
  PG_OID_INT8,
  PG_OID_TIMESTAMP,
  PG_OID_TIMESTAMPTZ,
  RELAYQUILL_PGLITE_PARSERS,
  acceptBrokerInbox,
  admitEvent,
  claimEventFanout,
  claimOutboxEvent,
  commitFanoutPage,
  compactDeliveryTotalDeltas,
  createPGliteAdapter,
  createScopedPgTypes,
  finalizeDeliveryAttempt,
  lockDeliveryDispatchAuthoritiesShare,
  observeOutboxPublication,
  prepareDispatchDelivery,
  readEventDeliveryDeltaShards,
  readEventDeliveryTotals,
  readInstallationStatus,
  readProjectDeliveryDeltaShards,
  readProjectDeliveryTotals,
  registerRuntimeInstance,
  startDeliverySend
} from "@relayquill/postgres";

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");

function normalizePgTypeToken(pgType) {
  const lower = pgType.trim().toLowerCase();
  if (lower === "timestamp with time zone") return "timestamptz";
  return lower;
}

function parseIdentityArgs(identityArgs) {
  const trimmed = String(identityArgs ?? "").trim();
  if (trimmed.length === 0) {
    return [];
  }
  return trimmed.split(",").map((part) => {
    const tokens = part.trim().split(/\s+/);
    const name = tokens[0];
    const type = normalizePgTypeToken(tokens.slice(1).join(" "));
    return { name, type };
  });
}

function shaHex(text) {
  return parseSha256Hex(crypto.createHash("sha256").update(text).digest("hex"));
}

function shaBytes(text) {
  return crypto.createHash("sha256").update(text).digest();
}

function makeUuid(prefix, n) {
  return `${prefix}000000-0000-4000-8000-${String(n).padStart(12, "0")}`;
}

test("TypeScript repository call sites align 1-to-1 with privilege-manifest.json signatures and cast types", () => {
  const manifest = JSON.parse(
    fs.readFileSync(path.join(REPO_ROOT, "migrations/privilege-manifest.json"), "utf8")
  );
  const byQualifiedName = new Map(manifest.functions.map((f) => [f.qualified_name, f]));

  const repoDir = path.join(REPO_ROOT, "packages/postgres/src/repositories");
  const repoFiles = fs.readdirSync(repoDir).filter((f) => f.endsWith(".ts") && f !== "index.ts" && f !== "_sql.ts");

  const invokedFunctions = new Set();

  // Extract callJsonbFunction / callOptionalJsonbFunction / executeRecoveryEntrypoint / direct SELECT rq* calls
  const callRegex =
    /(?:call(?:Optional)?JsonbFunction\(\s*tx,\s*"((?:rq|rq_recovery)\.[a-z0-9_]+)",\s*\[([^\]]*)\]|executeRecoveryEntrypoint\(\s*tx,\s*"(rq_recovery\.[a-z0-9_]+)"|(?:FROM|SELECT\s+[^;]*)\s+((?:rq|rq_recovery)\.[a-z0-9_]+)\()/gms;

  for (const file of repoFiles) {
    const src = fs.readFileSync(path.join(repoDir, file), "utf8");
    for (const match of src.matchAll(callRegex)) {
      if (match[1]) {
        const fnName = match[1];
        const castsRaw = match[2];
        const tsCasts = [...castsRaw.matchAll(/"([a-z]+)"/g)].map((m) => m[1]);
        const spec = byQualifiedName.get(fnName);
        assert.ok(spec, `TS calls unknown SQL function ${fnName} in ${file}`);
        invokedFunctions.add(fnName);
        const manifestArgs = parseIdentityArgs(spec.identity_args);
        assert.equal(
          tsCasts.length,
          manifestArgs.length,
          `Parameter count mismatch for ${fnName} in ${file}: TS=${tsCasts.length} vs manifest=${manifestArgs.length}`
        );
        for (let i = 0; i < manifestArgs.length; i += 1) {
          assert.equal(
            tsCasts[i],
            manifestArgs[i].type,
            `Parameter #${i + 1} (${manifestArgs[i].name}) type mismatch for ${fnName} in ${file}`
          );
        }
      } else if (match[3]) {
        const fnName = match[3];
        const spec = byQualifiedName.get(fnName);
        assert.ok(spec, `TS calls unknown recovery function ${fnName} in ${file}`);
        invokedFunctions.add(fnName);
        const manifestArgs = parseIdentityArgs(spec.identity_args);
        assert.deepEqual(
          manifestArgs.map((a) => a.type),
          ["uuid", "text", "bytea", "bytea"],
          `Recovery entrypoint signature mismatch for ${fnName}`
        );
      } else if (match[4]) {
        const fnName = match[4];
        const spec = byQualifiedName.get(fnName);
        assert.ok(spec, `TS queries unknown SQL table-function ${fnName} in ${file}`);
        invokedFunctions.add(fnName);
      }
    }
  }

  // Assert every public function in manifest.functions (58/58) is covered by typed repositories
  assert.equal(
    invokedFunctions.size,
    manifest.functions.length,
    `Missing repository wrappers for: ${manifest.functions
      .map((f) => f.qualified_name)
      .filter((n) => !invokedFunctions.has(n))
      .join(", ")}`
  );

  // Verify ordinary delivery paths never issue FOR UPDATE on installation_state, projects, or events
  for (const deliveryFile of ["dispatch.ts", "deliveries.ts", "projections.ts"]) {
    const content = fs.readFileSync(path.join(repoDir, deliveryFile), "utf8");
    assert.equal(
      /FROM\s+rq\.(?:installation_state|projects|events)\b[\s\S]{0,160}\bFOR\s+UPDATE\b/i.test(content),
      false,
      `${deliveryFile} must never use FOR UPDATE on installation_state, projects, or events`
    );
  }
});

test("16-shard delivery delta fan-in aggregates accurately across shards 0..15, compacts cleanly, and uses FOR SHARE locks", async (t) => {
  const db = await createPGliteAdapter({ schema: "rq", isolation: "shared_database_schemas" });
  t.after(() => db.close());

  const migrationsDir = path.join(REPO_ROOT, "migrations");
  for (const file of fs.readdirSync(migrationsDir).filter((f) => f.endsWith(".sql")).sort()) {
    await db.exec(fs.readFileSync(path.join(migrationsDir, file), "utf8"));
  }

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
  const install = await db.withTransaction("rq_api", (tx) => readInstallationStatus(tx));
  const tenantId = parseTenantId(makeUuid("10", 1));
  const projectId = parseProjectId(makeUuid("20", 1));
  const actorId = parsePrincipalId(makeUuid("30", 1));
  const prodPrinId = parsePrincipalId(makeUuid("30", 2));
  const producerId = parseProducerId(makeUuid("40", 1));
  const eventTypeId = parseEventTypeId(makeUuid("50", 1));
  const endpointId = parseEndpointId(makeUuid("60", 1));
  const dispatchDomainId = makeUuid("80", 1);
  const brokerGenId = parseBrokerGenerationId(makeUuid("81", 1));
  const relayId = parseRuntimeInstanceId(makeUuid("90", 2));
  const fanoutId = parseRuntimeInstanceId(makeUuid("90", 3));
  const senderId = parseRuntimeInstanceId(makeUuid("90", 4));
  const eventId = parseEventId(makeUuid("a0", 1));
  const payloadId = parseEventPayloadId(makeUuid("a1", 1));
  const wireId = parseWireEnvelopeId(makeUuid("a2", 1));
  const outboxId = parseOutboxId(makeUuid("a3", 1));
  const receiptId = parseCommandReceiptId(makeUuid("a4", 1));

  await db.withTransaction("rq_migrator", async (tx) => {
    await tx.query("INSERT INTO rq.principals (id, kind, state) VALUES ($1::uuid, 'human', 'active'), ($2::uuid, 'producer', 'active')", [actorId, prodPrinId]);
    await tx.query("INSERT INTO rq.humans (principal_id, principal_kind, display_name, webauthn_user_id) VALUES ($1::uuid, 'human', 'Alice Ops', $2::bytea)", [actorId, shaBytes("actor-webauthn")]);
    await tx.query("INSERT INTO rq.tenants (id, slug, display_name, state) VALUES ($1::uuid, 'shard-t', 'Shard Tenant', 'active')", [tenantId]);
    await tx.query("INSERT INTO rq.projects (id, tenant_id, name, state, topology_version) VALUES ($1::uuid, $2::uuid, 'shard-p', 'active', 1)", [projectId, tenantId]);
    await tx.query("INSERT INTO rq.tenant_capacity (tenant_id, limit_profile_version, max_pending_events, max_downstream_obligations, max_active_attempt_slots, max_retained_payload_bytes) VALUES ($1::uuid, 'default', 1000, 10000, 100, 100000000)", [tenantId]);
    await tx.query("INSERT INTO rq.project_capacity (project_id, tenant_id, limit_profile_version, max_pending_events, max_downstream_obligations, max_active_attempt_slots, max_retained_payload_bytes) VALUES ($1::uuid, $2::uuid, 'default', 1000, 10000, 100, 100000000)", [projectId, tenantId]);
    await tx.query("INSERT INTO rq.producers (id, tenant_id, project_id, principal_id, principal_kind, channel_kind, name, business_namespace, state, current_scope_version) VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid, 'producer', 'machine_producer', 'shard-prod', 'shard', 'active', 1)", [producerId, tenantId, projectId, prodPrinId]);
    await tx.query("INSERT INTO rq.event_types (id, tenant_id, project_id, type_name, state, current_schema_version) VALUES ($1::uuid, $2::uuid, $3::uuid, 'shard.ev', 'active', 1)", [eventTypeId, tenantId, projectId]);
    await tx.query("INSERT INTO rq.event_schema_versions (event_type_id, schema_version, tenant_id, project_id, dialect, profile_version, definition_bytes, definition_sha256, normalized_profile, compatibility_policy, state, created_by, published_by, published_at) VALUES ($1::uuid, 1, $2::uuid, $3::uuid, 'https://json-schema.org/draft/2020-12/schema', 'relayquill.event-schema.v1', $4::bytea, $5::bytea, '{\"type\":\"object\"}'::jsonb, 'additive_compatible', 'published', $6::uuid, $6::uuid, pg_catalog.clock_timestamp())", [eventTypeId, tenantId, projectId, Buffer.from("{}"), shaBytes("schema"), actorId]);
    await tx.query("INSERT INTO rq.endpoints (id, tenant_id, project_id, name, state, current_version, security_epoch, current_signing_policy_version, created_by) VALUES ($1::uuid, $2::uuid, $3::uuid, 'ep', 'active', 1, 1, 1, $4::uuid)", [endpointId, tenantId, projectId, actorId]);
    await tx.query("INSERT INTO rq.endpoint_versions (endpoint_id, endpoint_version, tenant_id, project_id, destination_url, normalized_hostname, port, path_and_query_sha256, url_policy_version, network_policy_version, request_profile_version, response_profile_version, configuration_sha256, created_by) VALUES ($1::uuid, 1, $2::uuid, $3::uuid, 'https://hook.test/x', 'hook.test', 443, $4::bytea, 'url_v1', 'network_v1', 'request_v1', 'response_v1', $4::bytea, $5::uuid)", [endpointId, tenantId, projectId, shaBytes("ep"), actorId]);
    await tx.query("INSERT INTO rq.endpoint_capacity (endpoint_id, tenant_id, project_id, approved_active_slots, held_slots) VALUES ($1::uuid, $2::uuid, $3::uuid, 64, 0)", [endpointId, tenantId, projectId]);
    await tx.query("INSERT INTO rq.endpoint_dispatch_grants (id, tenant_id, project_id, endpoint_id, endpoint_version, security_epoch, grant_class, state, approved_by, approved_configuration_sha256) VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid, 1, 1, 'current_destination', 'active', $5::uuid, $6::bytea)", [makeUuid("62", 1), tenantId, projectId, endpointId, actorId, shaBytes("ep")]);
    await tx.query("INSERT INTO rq.signing_key_versions (id, tenant_id, project_id, endpoint_id, key_version, key_id, algorithm, custody_reference, custody_version_reference, state) VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid, 1, 'k1', 'hmac-sha256-v1', 'c://k1', 'v1', 'active')", [makeUuid("61", 1), tenantId, projectId, endpointId]);
    await tx.query("INSERT INTO rq.signing_policies (endpoint_id, policy_version, tenant_id, project_id, primary_key_version_id, signature_mode, policy_sha256, created_by) VALUES ($1::uuid, 1, $2::uuid, $3::uuid, $4::uuid, 'primary_only', $5::bytea, $6::uuid)", [endpointId, tenantId, projectId, makeUuid("61", 1), shaBytes("sp"), actorId]);
    await tx.query("INSERT INTO rq.endpoint_circuits (endpoint_id, endpoint_version, tenant_id, project_id, state, circuit_generation, policy_kind, policy_version) VALUES ($1::uuid, 1, $2::uuid, $3::uuid, 'closed', 1, 'circuit', 'circuit_v1')", [endpointId, tenantId, projectId]);
    const receiverContractId = makeUuid("63", 1);
    await tx.query("INSERT INTO rq.receiver_contracts (id, tenant_id, project_id, endpoint_id, name, state, current_version, created_by) VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid, 'rc-shard', 'active', 1, $5::uuid)", [receiverContractId, tenantId, projectId, endpointId, actorId]);
    await tx.query("INSERT INTO rq.receiver_contract_versions (contract_id, contract_version, tenant_id, project_id, endpoint_id, consumer_contract_scope, definition_bytes, definition_sha256, receipt_profile, ordering_profile, minimum_inbox_retention_seconds, verified_at, published_by) VALUES ($1::uuid, 1, $2::uuid, $3::uuid, $4::uuid, 'default', $5::bytea, $6::bytea, 'http_ack_only', 'unordered', 7776000, pg_catalog.clock_timestamp(), $7::uuid)", [receiverContractId, tenantId, projectId, endpointId, Buffer.from("{}"), shaBytes("rcdef"), actorId]);
    await tx.query("INSERT INTO rq.broker_stream_generations (id, deployment_reference, cluster_reference, stream_name, observed_stream_created_at, configuration_sha256, state, created_by_operator_reference) VALUES ($1::uuid, 'd', 'c', 'RELAYQUILL_EVENTS_V1', pg_catalog.clock_timestamp(), $2::bytea, 'active', 'op')", [brokerGenId, shaBytes("bs")]);
    await tx.query("INSERT INTO rq.dispatch_domains (id, name, state, policy_kind, policy_version, policy_sha256) VALUES ($1::uuid, 'default', 'active', 'dispatch', 'dispatch_v1', $2::bytea)", [dispatchDomainId, shaBytes("wd")]);
    await tx.query("INSERT INTO rq.dispatch_state (dispatch_domain_id, policy_epoch, round_number) VALUES ($1::uuid, 1, 1)", [dispatchDomainId]);
    await tx.query("INSERT INTO rq.project_dispatch_memberships (project_id, tenant_id, dispatch_domain_id, state, policy_version) VALUES ($1::uuid, $2::uuid, $3::uuid, 'active', 'dispatch_v1')", [projectId, tenantId, dispatchDomainId]);
    for (const op of ["event_admission", "send_start"]) {
      await tx.query("INSERT INTO rq.tenant_rate_buckets (tenant_id, operation, tokens_micro, reserved_micro, capacity_micro, refill_micro_per_second, refill_remainder_numerator, last_refill_at, policy_version) VALUES ($1::uuid, $2::text, 1000000000, 0, 1000000000, 10000000, 0, pg_catalog.clock_timestamp(), 1)", [tenantId, op]);
      await tx.query("INSERT INTO rq.project_rate_buckets (project_id, tenant_id, operation, tokens_micro, reserved_micro, capacity_micro, refill_micro_per_second, refill_remainder_numerator, last_refill_at, policy_version) VALUES ($1::uuid, $2::uuid, $3::text, 1000000000, 0, 1000000000, 10000000, 0, pg_catalog.clock_timestamp(), 1)", [projectId, tenantId, op]);
    }
    await tx.query("INSERT INTO rq.producer_rate_buckets (producer_id, tenant_id, project_id, operation, tokens_micro, reserved_micro, capacity_micro, refill_micro_per_second, refill_remainder_numerator, last_refill_at, policy_version) VALUES ($1::uuid, $2::uuid, $3::uuid, 'event_admission', 1000000000, 0, 1000000000, 10000000, 0, pg_catalog.clock_timestamp(), 1)", [producerId, tenantId, projectId]);
    await tx.query("INSERT INTO rq.endpoint_rate_buckets (endpoint_id, tenant_id, project_id, operation, tokens_micro, reserved_micro, capacity_micro, refill_micro_per_second, refill_remainder_numerator, last_refill_at, policy_version) VALUES ($1::uuid, $2::uuid, $3::uuid, 'send_start', 1000000000, 0, 1000000000, 10000000, 0, pg_catalog.clock_timestamp(), 1)", [endpointId, tenantId, projectId]);

    const setupReceiptId = makeUuid("64", 1);
    await tx.query("INSERT INTO rq.command_receipts (id, scope_kind, tenant_id, project_id, actor_principal_id, command_family, key_sha256, submitted_shape_sha256, effective_request_sha256, resource_kind, resource_id, accepted_version) VALUES ($1::uuid, 'project', $2::uuid, $3::uuid, $4::uuid, 'subscription.control', $5::bytea, $6::bytea, $7::bytea, 'subscription', $8::uuid, 1)", [setupReceiptId, tenantId, projectId, actorId, shaBytes("subkey"), shaBytes("subshape"), shaBytes("subeff"), makeUuid("70", 1)]);

    // 20 matched subscriptions for one event so deliveries hash across distinct 16 shards
    for (let i = 1; i <= 20; i += 1) {
      const subId = parseSubscriptionId(makeUuid("70", i));
      const activationEventId = makeUuid("65", i);
      await tx.query("INSERT INTO rq.subscriptions (id, tenant_id, project_id, name, state, current_version, control_sequence, send_hold, created_by) VALUES ($1::uuid, $2::uuid, $3::uuid, $4::text, 'active', 1, 1, false, $5::uuid)", [subId, tenantId, projectId, `sub-${i}`, actorId]);
      await tx.query("INSERT INTO rq.subscription_versions (subscription_id, subscription_version, tenant_id, project_id, endpoint_id, endpoint_version, event_type_id, filter_profile_version, filter_ast, filter_sha256, ordering_mode, retry_policy_version, response_policy_kind, response_policy_version, consumer_contract_scope, receiver_contract_id, receiver_contract_version, configuration_sha256, created_by) VALUES ($1::uuid, 1, $2::uuid, $3::uuid, $4::uuid, 1, $5::uuid, 'relayquill.filter.v1', '{}'::jsonb, $6::bytea, 'unordered', 'retry_v1', 'response', 'response_v1', 'default', $7::uuid, 1, $6::bytea, $8::uuid)", [subId, tenantId, projectId, endpointId, eventTypeId, shaBytes(`sub-${i}`), receiverContractId, actorId]);
      await tx.query("INSERT INTO rq.subscription_schema_versions (subscription_id, subscription_version, tenant_id, project_id, event_type_id, event_schema_version) VALUES ($1::uuid, 1, $2::uuid, $3::uuid, $4::uuid, 1)", [subId, tenantId, projectId, eventTypeId]);
      await tx.query("INSERT INTO rq.subscription_control_events (id, subscription_id, tenant_id, project_id, control_sequence, action, prior_version, resulting_version, topology_version, actor_principal_id, command_receipt_id, safe_reason_code) VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid, 1, 'activate', NULL, 1, 1, $5::uuid, $6::uuid, 'initial_activate')", [activationEventId, subId, tenantId, projectId, actorId, setupReceiptId]);
      await tx.query("INSERT INTO rq.subscription_topology_ranges (project_id, tenant_id, subscription_id, subscription_version, from_topology_version, activation_event_id) VALUES ($1::uuid, $2::uuid, $3::uuid, 1, 1, $4::uuid)", [projectId, tenantId, subId, activationEventId]);
    }
  });

  await db.withTransaction("rq_relay", (tx) =>
    registerRuntimeInstance(tx, { instanceId: relayId, processRole: "relay", databaseRole: "rq_relay", controlEpoch: install.controlEpoch, buildReference: "t", leaseMs: 60_000n })
  );
  await db.withTransaction("rq_fanout", (tx) =>
    registerRuntimeInstance(tx, { instanceId: fanoutId, processRole: "fanout", databaseRole: "rq_fanout", controlEpoch: install.controlEpoch, buildReference: "t", leaseMs: 60_000n })
  );
  await db.withTransaction("rq_sender", (tx) =>
    registerRuntimeInstance(tx, { instanceId: senderId, processRole: "sender", databaseRole: "rq_sender", controlEpoch: install.controlEpoch, buildReference: "t", leaseMs: 60_000n, approvedSlots: 32 })
  );

  // Verify FOR SHARE lock acquisition holds only AccessShareLock/RowShareLock (never RowExclusiveLock)
  const lockModes = await db.withTransaction("rq_sender", async (tx) => {
    await lockDeliveryDispatchAuthoritiesShare(tx, tenantId, projectId);
    const locks = await tx.query(`
      SELECT c.relname, l.mode
        FROM pg_catalog.pg_locks l
        JOIN pg_catalog.pg_class c ON c.oid = l.relation
        JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
       WHERE n.nspname = 'rq' AND c.relname IN ('installation_state', 'projects') AND l.granted
    `);
    return locks.rows;
  });
  assert.ok(lockModes.length > 0);
  for (const row of lockModes) {
    assert.notEqual(row.mode, "RowExclusiveLock");
    assert.notEqual(row.mode, "ExclusiveLock");
  }

  const brokerBytes = Buffer.from('{"k":1}');
  await db.withTransaction("rq_api", (tx) =>
    admitEvent(tx, {
      tenantId,
      projectId,
      actorPrincipalId: actorId,
      producerId,
      producerNamespace: "shard",
      businessKey: "bk-shard",
      businessKeySha256: shaHex("bk-shard"),
      idempotencyKeySha256: shaHex("idem-shard"),
      submittedShapeSha256: shaHex("shape-shard"),
      effectiveRequestSha256: shaHex("eff-shard"),
      eventTypeId,
      eventSchemaVersion: 1,
      content: Buffer.from("{}"),
      contentSha256: shaHex("{}"),
      wireEnvelopeBytes: Buffer.from("{}"),
      wireEnvelopeSha256: shaHex("{}"),
      brokerEnvelopeBytes: brokerBytes,
      brokerEnvelopeSha256: shaHex(brokerBytes),
      deliveryDeadlineAt: nowUtcInstant().add({ minutes: 30 }),
      appliedDefaults: {},
      retentionPolicyVersion: "r1",
      eventId,
      payloadId,
      wireEnvelopeId: wireId,
      outboxId,
      receiptId,
      auditId: makeUuid("a5", 1)
    })
  );

  const claimed = await db.withTransaction("rq_relay", (tx) =>
    claimOutboxEvent(tx, { outboxId, instanceId: relayId, controlEpoch: install.controlEpoch, claimLeaseMs: 10_000n })
  );
  await db.withTransaction("rq_relay", (tx) =>
    observeOutboxPublication(tx, {
      outboxId,
      publicationGeneration: claimed.publicationGeneration,
      instanceId: relayId,
      controlEpoch: install.controlEpoch,
      expectedClaimGeneration: claimed.claimGeneration,
      outcome: "published",
      brokerGenerationId: brokerGenId,
      streamName: "RELAYQUILL_EVENTS_V1",
      streamSequence: 1n,
      observationId: parsePublicationObservationId(makeUuid("a6", 1))
    })
  );

  await db.withTransaction("rq_fanout", (tx) =>
    acceptBrokerInbox(tx, {
      outboxId,
      publicationGeneration: claimed.publicationGeneration,
      eventId,
      projectId,
      topologyVersion: 1n,
      envelopeSha256: shaHex(brokerBytes),
      brokerGenerationId: brokerGenId,
      streamSequence: 1n,
      inboxId: parseBrokerInboxId(makeUuid("a7", 1)),
      instanceId: fanoutId,
      controlEpoch: install.controlEpoch
    })
  );

  const fClaim = await db.withTransaction("rq_fanout", (tx) =>
    claimEventFanout(tx, { eventId, instanceId: fanoutId, controlEpoch: install.controlEpoch, claimLeaseMs: 10_000n })
  );
  assert.equal(fClaim.outcome, "claimed");

  const outcomes = Array.from({ length: 20 }, (_, idx) => {
    const i = idx + 1;
    return {
      subscription_id: parseSubscriptionId(makeUuid("70", i)),
      subscription_version: "1",
      outcome: "matched",
      filter_profile_version: "filter.v1",
      filter_sha256: shaHex(`sub-${i}`),
      delivery_id: makeUuid("a8", i),
      family_id: makeUuid("a9", i),
      endpoint_id: endpointId,
      endpoint_version: "1",
      wire_envelope_id: wireId,
      consumer_contract_scope: "default",
      consumer_event_key_sha256: shaHex(`cek-${i}`)
    };
  });
  await db.withTransaction("rq_fanout", (tx) =>
    commitFanoutPage(tx, {
      eventId,
      instanceId: fanoutId,
      controlEpoch: install.controlEpoch,
      expectedClaimGeneration: fClaim.claimGeneration,
      complete: true,
      outcomes
    })
  );

  for (let i = 1; i <= 20; i += 1) {
    const deliveryId = parseDeliveryId(makeUuid("a8", i));
    const attemptId = parseAttemptId(makeUuid("ab", i));
    const prep = await db.withTransaction("rq_sender", (tx) =>
      prepareDispatchDelivery(tx, {
        requestId: makeUuid("aa", i),
        dispatchDomainId,
        workerInstanceId: senderId,
        controlEpoch: install.controlEpoch,
        requestSha256: shaHex(`req-${i}`),
        deliveryId,
        attemptId,
        claimLeaseMs: 10_000n
      })
    );
    await db.withTransaction("rq_sender", (tx) =>
      startDeliverySend(tx, {
        attemptId,
        workerInstanceId: senderId,
        controlEpoch: install.controlEpoch,
        expectedFencingToken: prep.fencingToken,
        networkBudgetMs: 10_000n
      })
    );
    const ack = i <= 15;
    await db.withTransaction("rq_sender", (tx) =>
      finalizeDeliveryAttempt(tx, {
        attemptId,
        workerInstanceId: senderId,
        controlEpoch: install.controlEpoch,
        expectedFencingToken: prep.fencingToken,
        attemptState: "response_observed",
        outcomeClass: ack ? "acknowledged" : "permanent_http",
        retryDecision: ack ? "acknowledged" : "dead_letter",
        retryReasonCode: ack ? null : "permanent_4xx",
        responseStatus: ack ? 204 : 400
      })
    );
  }

  // Verify multiple distinct shards among 0..15 were written cleanly and aggregate identically
  const evShards = await db.withTransaction("rq_reporter", (tx) =>
    readEventDeliveryDeltaShards(tx, tenantId, projectId, eventId)
  );
  assert.ok(evShards.shards.length > 1 && evShards.shards.length <= DELIVERY_DELTA_SHARD_COUNT);
  for (const s of evShards.shards) {
    assert.ok(s.shardId >= 0 && s.shardId < DELIVERY_DELTA_SHARD_COUNT);
  }
  assert.equal(evShards.aggregated.totalDeliveriesDelta, 20n);
  assert.equal(evShards.aggregated.terminalDeliveriesDelta, 20n);
  assert.equal(evShards.aggregated.acknowledgedDeliveriesDelta, 15n);

  const projShards = await db.withTransaction("rq_reporter", (tx) =>
    readProjectDeliveryDeltaShards(tx, tenantId, projectId)
  );
  assert.equal(projShards.aggregated.acknowledgedDelta, 15n);
  assert.equal(projShards.aggregated.deadLetterDelta, 5n);

  const preCompProj = await db.withTransaction("rq_reporter", (tx) =>
    readProjectDeliveryTotals(tx, tenantId, projectId)
  );
  assert.equal(preCompProj.totalDeliveries, 20n);
  assert.equal(preCompProj.acknowledgedCount, 15n);
  assert.equal(preCompProj.deadLetterCount, 5n);

  await db.withTransaction("rq_coordinator", (tx) =>
    compactDeliveryTotalDeltas(tx, { tenantId, projectId, eventId })
  );

  const postCompShards = await db.withTransaction("rq_reporter", (tx) =>
    readEventDeliveryDeltaShards(tx, tenantId, projectId, eventId)
  );
  assert.equal(postCompShards.shards.length, 0);

  const postCompEv = await db.withTransaction("rq_reporter", (tx) =>
    readEventDeliveryTotals(tx, tenantId, projectId, eventId)
  );
  assert.equal(postCompEv.totalDeliveries, 20n);
  assert.equal(postCompEv.terminalDeliveries, 20n);
  assert.equal(postCompEv.acknowledgedDeliveries, 15n);

  // Jittered contention retry and OID parity contract
  const pgTypes = createScopedPgTypes();
  assert.equal(
    pgTypes.getTypeParser(PG_OID_TIMESTAMPTZ, "text")("2026-11-18 10:20:30.12+00"),
    RELAYQUILL_PGLITE_PARSERS[PG_OID_TIMESTAMPTZ]("2026-11-18 10:20:30.12+00")
  );
  assert.equal(
    pgTypes.getTypeParser(PG_OID_TIMESTAMP, "text")("2026-11-18 10:20:30"),
    RELAYQUILL_PGLITE_PARSERS[PG_OID_TIMESTAMP]("2026-11-18 10:20:30")
  );
  assert.equal(
    pgTypes.getTypeParser(PG_OID_INT8, "text")("9223372036854775807"),
    RELAYQUILL_PGLITE_PARSERS[PG_OID_INT8]("9223372036854775807")
  );

  let contentionAttempts = 0;
  const delays = [];
  await assert.rejects(
    () =>
      db.withTransaction(
        "rq_sender",
        async () => {
          contentionAttempts += 1;
          const e = new Error("lock timeout");
          e.code = "55P03";
          throw e;
        },
        {
          retryOnContention: true,
          maxAttempts: 3,
          baseBackoffMs: 4,
          maxBackoffMs: 16,
          deadlineMs: 2000,
          random: () => 0.75,
          onRetry: (evt) => delays.push(evt.delayMs)
        }
      ),
    (err) => err instanceof DomainError && err.code === "LOCK_CONTENTION"
  );
  assert.equal(contentionAttempts, 3);
  assert.deepEqual(delays, [3, 6]);
});
