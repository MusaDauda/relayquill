import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import https from "node:https";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  nowUtcInstant,
  parseCommandReceiptId,
  parseDeliveryFamilyId,
  parseDeliveryId,
  parseEndpointId,
  parseEndpointVerificationIntentId,
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
  encodeBase64,
  EVENT_CONTENT_ENCODING,
  EVENT_CONTENT_MEDIA_TYPE,
  parseCanonicalUtcTimestamp,
  serializeWebhookEnvelope
} from "@relayquill/contracts";
import {
  admitEvent,
  claimOutboxEvent,
  createPGliteAdapter,
  observeOutboxPublication,
  acceptBrokerInbox,
  claimEventFanout,
  commitFanoutPage,
  readInstallationStatus,
  registerRuntimeInstance
} from "@relayquill/postgres";
import {
  createMemorySigningKeyHandle,
  signEndpointProof,
  signReceiverLocalCommitReceipt,
  verifyWebhookRequest
} from "@relayquill/signing";
import { generateSelfSignedCert } from "../../../tests/e2e/harness/https-double.mjs";
import {
  createSenderHealthServer,
  createSenderWorker,
  parseSenderCliArgs
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

async function readIncomingBody(req) {
  const chunks = [];
  for await (const chunk of req) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  }
  return Buffer.concat(chunks);
}

test("SenderWorker signs 25-field webhooks, persists verified receiver_local_commit_v1 MAC, blocks SSRF with send_started=false, and executes 204 endpoint proof verification", async (t) => {
  const cert = generateSelfSignedCert({
    commonName: "receiver.fixture.test",
    dnsNames: ["receiver.fixture.test"],
    ipAddresses: []
  });

  const ids = {
    tenantId: parseTenantId("10000000-0000-4000-8000-000000000001"),
    projectId: parseProjectId("20000000-0000-4000-8000-000000000001"),
    actorPrincipalId: parsePrincipalId("30000000-0000-4000-8000-000000000001"),
    producerPrincipalId: parsePrincipalId("30000000-0000-4000-8000-000000000002"),
    producerId: parseProducerId("40000000-0000-4000-8000-000000000001"),
    eventTypeId: parseEventTypeId("50000000-0000-4000-8000-000000000001"),
    validEndpointId: parseEndpointId("60000000-0000-4000-8000-000000000001"),
    ssrfEndpointId: parseEndpointId("60000000-0000-4000-8000-000000000002"),
    validSigningKeyId: "61000000-0000-4000-8000-000000000001",
    ssrfSigningKeyId: "61000000-0000-4000-8000-000000000002",
    validSubscriptionId: parseSubscriptionId("70000000-0000-4000-8000-000000000001"),
    ssrfSubscriptionId: parseSubscriptionId("70000000-0000-4000-8000-000000000002"),
    dispatchDomainId: "80000000-0000-4000-8000-000000000001",
    brokerGenId: "81000000-0000-4000-8000-000000000001",
    relayInstanceId: parseRuntimeInstanceId("90000000-0000-4000-8000-000000000002"),
    fanoutInstanceId: parseRuntimeInstanceId("90000000-0000-4000-8000-000000000003"),
    senderInstanceId: parseRuntimeInstanceId("90000000-0000-4000-8000-000000000004"),
    verificationIntentId: parseEndpointVerificationIntentId("c1000000-0000-4000-8000-000000000001"),
    validDeliveryId: parseDeliveryId("a8000000-0000-4000-8000-000000000001"),
    ssrfDeliveryId: parseDeliveryId("a8000000-0000-4000-8000-000000000002"),
    validFamilyId: parseDeliveryFamilyId("a9000000-0000-4000-8000-000000000001"),
    ssrfFamilyId: parseDeliveryFamilyId("a9000000-0000-4000-8000-000000000002")
  };

  const hmacSecretBytes = Buffer.from("0123456789abcdef0123456789abcdef", "utf8");
  const receivedDeliveries = [];
  const receivedVerifications = [];

  const server = https.createServer(
    { key: cert.keyPem, cert: cert.certPem },
    async (req, res) => {
      try {
        const rawBody = await readIncomingBody(req);
        const addr = server.address();
        const port = typeof addr === "object" && addr !== null ? addr.port : 0;
        const authority = `receiver.fixture.test:${port}`;

        const verification = await verifyWebhookRequest({
          method: req.method ?? "POST",
          rawHeaders: req.rawHeaders,
          rawBodyBytes: rawBody,
          expectedTarget: {
            externalAuthority: authority,
            requestTarget: "/hooks/relayquill"
          },
          expectedContext: {
            projectId: ids.projectId,
            endpointId: ids.validEndpointId
          },
          authorityValidation: {
            allowFixtureAuthority: true,
            expectedFixtureAuthority: authority
          },
          keyProvider: () => ({
            handle: createMemorySigningKeyHandle(hmacSecretBytes, { id: "k1" }),
            metadata: {
              keyId: "k1",
              keyVersionId: ids.validSigningKeyId,
              endpointId: ids.validEndpointId,
              projectId: ids.projectId,
              keyVersion: 1n,
              state: "active",
              activateNotBefore: null,
              signUntil: null,
              verifyUntil: null,
              revokedAt: null
            },
            releaseAfterUse: true
          })
        });

        assert.equal(verification.ok, true, `Receiver webhook verification failed: ${JSON.stringify(verification)}`);

        if (verification.purpose === "endpoint_verification") {
          receivedVerifications.push(verification);
          const proof = signEndpointProof({
            verificationIntentId: verification.verificationBody.verification_id,
            endpointId: verification.verificationBody.endpoint_id,
            endpointVersion: verification.verificationBody.endpoint_version,
            configurationSha256: verification.verificationBody.configuration_sha256,
            keyId: verification.verifiedKeyId,
            publicNonce: verification.verificationBody.public_nonce,
            verificationAttemptId: verification.headers.attempt_id,
            requestTimestampSeconds: String(verification.headers.timestamp_seconds),
            requestWireBodySha256: verification.bodySha256,
            keyHandle: createMemorySigningKeyHandle(hmacSecretBytes, { id: "k1" })
          });
          res.writeHead(204, { [proof.headerName]: proof.headerValue });
          res.end();
          return;
        }

        receivedDeliveries.push(verification);
        const receipt = signReceiverLocalCommitReceipt({
          keyId: verification.verifiedKeyId,
          projectId: verification.decodedEnvelope.envelope.project_id,
          eventId: verification.decodedEnvelope.envelope.event_id,
          consumerEventKey: verification.headers.consumer_key,
          originalFactsSha256: verification.decodedEnvelope.original_facts_sha256,
          receiptId: "d1000000-0000-4000-8000-000000000001",
          committedAt: parseCanonicalUtcTimestamp(nowUtcInstant().toString(), "committed_at"),
          deliveryAttemptId: verification.headers.attempt_id,
          requestWireBodySha256: verification.bodySha256,
          keyHandle: createMemorySigningKeyHandle(hmacSecretBytes, { id: "k1" })
        });
        res.writeHead(200, {
          "content-type": "application/json; charset=utf-8",
          "content-length": String(receipt.bodyBytes.byteLength)
        });
        res.end(receipt.bodyBytes);
      } catch (err) {
        res.writeHead(500);
        res.end(String(err));
      }
    }
  );

  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const serverPort = server.address().port;
  const validAuthority = `receiver.fixture.test:${serverPort}`;
  const validUrl = `https://${validAuthority}/hooks/relayquill`;
  const ssrfUrl = "https://169.254.169.254/latest/meta-data";

  const db = await createPGliteAdapter({ schema: "rq", isolation: "shared_database_schemas" });
  t.after(async () => {
    await db.close();
    await new Promise((resolve) => server.close(resolve));
  });

  await applyMigrations(db);
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
  const controlEpoch = status.controlEpoch;
  const nonceBytes = crypto.randomBytes(32);

  await db.withTransaction("rq_migrator", async (tx) => {
    await tx.query(
      `INSERT INTO rq.principals (id, kind, state) VALUES ($1::uuid, 'human', 'active'), ($2::uuid, 'producer', 'active')`,
      [ids.actorPrincipalId, ids.producerPrincipalId]
    );
    await tx.query(
      `INSERT INTO rq.humans (principal_id, principal_kind, display_name, webauthn_user_id)
       VALUES ($1::uuid, 'human', 'Sender Ops', $2::bytea)`,
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

    const endpointsCfg = [
      {
        endpointId: ids.validEndpointId,
        name: "hook-valid",
        url: validUrl,
        host: "receiver.fixture.test",
        port: serverPort,
        signingKeyId: ids.validSigningKeyId,
        keyId: "k1",
        receiptProfile: "receiver_local_commit_v1",
        grantId: "62000000-0000-4000-8000-000000000001",
        rcId: "63000000-0000-4000-8000-000000000001",
        subId: ids.validSubscriptionId,
        subName: "sub-valid",
        recId: "64000000-0000-4000-8000-000000000001",
        actId: "65000000-0000-4000-8000-000000000001",
        scope: "valid_scope"
      },
      {
        endpointId: ids.ssrfEndpointId,
        name: "hook-ssrf",
        url: ssrfUrl,
        host: "169.254.169.254",
        port: 443,
        signingKeyId: ids.ssrfSigningKeyId,
        keyId: "k2",
        receiptProfile: "http_ack_only",
        grantId: "62000000-0000-4000-8000-000000000002",
        rcId: "63000000-0000-4000-8000-000000000002",
        subId: ids.ssrfSubscriptionId,
        subName: "sub-ssrf",
        recId: "64000000-0000-4000-8000-000000000002",
        actId: "65000000-0000-4000-8000-000000000002",
        scope: "ssrf_scope"
      }
    ];

    for (const ep of endpointsCfg) {
      const cfgSha = shaBytes(`epcfg:${ep.endpointId}`);
      await tx.query(
        `INSERT INTO rq.endpoints (id, tenant_id, project_id, name, state, current_version, security_epoch, current_signing_policy_version, created_by)
         VALUES ($1::uuid, $2::uuid, $3::uuid, $4::text, 'active', 1, 1, 1, $5::uuid)`,
        [ep.endpointId, ids.tenantId, ids.projectId, ep.name, ids.actorPrincipalId]
      );
      await tx.query(
        `INSERT INTO rq.endpoint_versions (endpoint_id, endpoint_version, tenant_id, project_id, destination_url, normalized_hostname, port, path_and_query_sha256, url_policy_version, network_policy_version, request_profile_version, response_profile_version, configuration_sha256, created_by)
         VALUES ($1::uuid, 1, $2::uuid, $3::uuid, $4::text, $5::text, $6::integer, $7::bytea, 'url_v1', 'network_v1', 'request_v1', 'response_v1', $8::bytea, $9::uuid)`,
        [ep.endpointId, ids.tenantId, ids.projectId, ep.url, ep.host, ep.port, shaBytes(`path:${ep.name}`), cfgSha, ids.actorPrincipalId]
      );
      await tx.query(
        `INSERT INTO rq.endpoint_capacity (endpoint_id, tenant_id, project_id, approved_active_slots, held_slots)
         VALUES ($1::uuid, $2::uuid, $3::uuid, 32, 0)`,
        [ep.endpointId, ids.tenantId, ids.projectId]
      );
      await tx.query(
        `INSERT INTO rq.endpoint_dispatch_grants (id, tenant_id, project_id, endpoint_id, endpoint_version, security_epoch, grant_class, state, approved_by, approved_configuration_sha256)
         VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid, 1, 1, 'current_destination', 'active', $5::uuid, $6::bytea)`,
        [ep.grantId, ids.tenantId, ids.projectId, ep.endpointId, ids.actorPrincipalId, cfgSha]
      );
      await tx.query(
        `INSERT INTO rq.signing_key_versions (id, tenant_id, project_id, endpoint_id, key_version, key_id, algorithm, custody_reference, custody_version_reference, state)
         VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid, 1, $5::text, 'hmac-sha256-v1', 'custody://k1', 'v1', 'active')`,
        [ep.signingKeyId, ids.tenantId, ids.projectId, ep.endpointId, ep.keyId]
      );
      await tx.query(
        `INSERT INTO rq.signing_policies (endpoint_id, policy_version, tenant_id, project_id, primary_key_version_id, signature_mode, policy_sha256, created_by)
         VALUES ($1::uuid, 1, $2::uuid, $3::uuid, $4::uuid, 'primary_only', $5::bytea, $6::uuid)`,
        [ep.endpointId, ids.tenantId, ids.projectId, ep.signingKeyId, shaBytes(`spol:${ep.name}`), ids.actorPrincipalId]
      );
      await tx.query(
        `INSERT INTO rq.endpoint_circuits (endpoint_id, endpoint_version, tenant_id, project_id, state, circuit_generation, policy_kind, policy_version)
         VALUES ($1::uuid, 1, $2::uuid, $3::uuid, 'closed', 1, 'circuit', 'circuit_v1')`,
        [ep.endpointId, ids.tenantId, ids.projectId]
      );
      await tx.query(
        `INSERT INTO rq.receiver_contracts (id, tenant_id, project_id, endpoint_id, name, state, current_version, created_by)
         VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid, $5::text, 'active', 1, $6::uuid)`,
        [ep.rcId, ids.tenantId, ids.projectId, ep.endpointId, `rc-${ep.name}`, ids.actorPrincipalId]
      );
      await tx.query(
        `INSERT INTO rq.receiver_contract_versions (contract_id, contract_version, tenant_id, project_id, endpoint_id, consumer_contract_scope, definition_bytes, definition_sha256, receipt_profile, ordering_profile, minimum_inbox_retention_seconds, verified_at, published_by)
         VALUES ($1::uuid, 1, $2::uuid, $3::uuid, $4::uuid, $5::text, $6::bytea, $7::bytea, $8::text, 'unordered', 7776000, pg_catalog.clock_timestamp(), $9::uuid)`,
        [ep.rcId, ids.tenantId, ids.projectId, ep.endpointId, ep.scope, Buffer.from("{}"), shaBytes(`rcdef:${ep.name}`), ep.receiptProfile, ids.actorPrincipalId]
      );
      await tx.query(
        `INSERT INTO rq.subscriptions (id, tenant_id, project_id, name, state, current_version, control_sequence, send_hold, created_by)
         VALUES ($1::uuid, $2::uuid, $3::uuid, $4::text, 'active', 1, 1, false, $5::uuid)`,
        [ep.subId, ids.tenantId, ids.projectId, ep.subName, ids.actorPrincipalId]
      );
      await tx.query(
        `INSERT INTO rq.subscription_versions (subscription_id, subscription_version, tenant_id, project_id, endpoint_id, endpoint_version, event_type_id, filter_profile_version, filter_ast, filter_sha256, ordering_mode, retry_policy_version, response_policy_kind, response_policy_version, consumer_contract_scope, receiver_contract_id, receiver_contract_version, configuration_sha256, created_by)
         VALUES ($1::uuid, 1, $2::uuid, $3::uuid, $4::uuid, 1, $5::uuid, 'relayquill.filter.v1', '{"all":[]}'::jsonb, $6::bytea, 'unordered', 'retry_v1', 'response', 'response_v1', $7::text, $8::uuid, 1, $9::bytea, $10::uuid)`,
        [ep.subId, ids.tenantId, ids.projectId, ep.endpointId, ids.eventTypeId, shaBytes(`filter:${ep.name}`), ep.scope, ep.rcId, shaBytes(`subcfg:${ep.name}`), ids.actorPrincipalId]
      );
      await tx.query(
        `INSERT INTO rq.subscription_schema_versions (subscription_id, subscription_version, tenant_id, project_id, event_type_id, event_schema_version)
         VALUES ($1::uuid, 1, $2::uuid, $3::uuid, $4::uuid, 1)`,
        [ep.subId, ids.tenantId, ids.projectId, ids.eventTypeId]
      );
      await tx.query(
        `INSERT INTO rq.command_receipts (id, scope_kind, tenant_id, project_id, actor_principal_id, command_family, key_sha256, submitted_shape_sha256, effective_request_sha256, resource_kind, resource_id, accepted_version)
         VALUES ($1::uuid, 'project', $2::uuid, $3::uuid, $4::uuid, 'subscription.control', $5::bytea, $6::bytea, $7::bytea, 'subscription', $8::uuid, 1)`,
        [ep.recId, ids.tenantId, ids.projectId, ids.actorPrincipalId, shaBytes(`sk:${ep.name}`), shaBytes(`ss:${ep.name}`), shaBytes(`se:${ep.name}`), ep.subId]
      );
      await tx.query(
        `INSERT INTO rq.subscription_control_events (id, subscription_id, tenant_id, project_id, control_sequence, action, prior_version, resulting_version, topology_version, actor_principal_id, command_receipt_id, safe_reason_code)
         VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid, 1, 'activate', NULL, 1, 1, $5::uuid, $6::uuid, 'initial_activate')`,
        [ep.actId, ep.subId, ids.tenantId, ids.projectId, ids.actorPrincipalId, ep.recId]
      );
      await tx.query(
        `INSERT INTO rq.subscription_topology_ranges (project_id, tenant_id, subscription_id, subscription_version, from_topology_version, activation_event_id)
         VALUES ($1::uuid, $2::uuid, $3::uuid, 1, 1, $4::uuid)`,
        [ids.projectId, ids.tenantId, ep.subId, ep.actId]
      );
      await tx.query(
        `INSERT INTO rq.endpoint_rate_buckets (endpoint_id, tenant_id, project_id, operation, tokens_micro, reserved_micro, capacity_micro, refill_micro_per_second, refill_remainder_numerator, last_refill_at, policy_version)
         VALUES ($1::uuid, $2::uuid, $3::uuid, 'send_start', 100000000, 0, 100000000, 10000000, 0, pg_catalog.clock_timestamp(), 1)`,
        [ep.endpointId, ids.tenantId, ids.projectId]
      );
    }

    await tx.query(
      `INSERT INTO rq.endpoint_verification_intents (id, tenant_id, project_id, endpoint_id, endpoint_version, security_epoch, configuration_sha256, signing_key_version_id, purpose, public_nonce, state, attempt_count, created_by, expires_at)
       VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid, 1, 1, $5::bytea, $6::uuid, 'verify_destination_and_key', $7::bytea, 'approved', 0, $8::uuid, pg_catalog.clock_timestamp() + interval '10 minutes')`,
      [
        ids.verificationIntentId,
        ids.tenantId,
        ids.projectId,
        ids.validEndpointId,
        shaBytes(`epcfg:${ids.validEndpointId}`),
        ids.validSigningKeyId,
        nonceBytes,
        ids.actorPrincipalId
      ]
    );

    await tx.query(
      `INSERT INTO rq.broker_stream_generations (id, deployment_reference, cluster_reference, stream_name, observed_stream_created_at, configuration_sha256, state, created_by_operator_reference)
       VALUES ($1::uuid, 'dep', 'cls', 'RELAYQUILL_EVENTS_V1', pg_catalog.clock_timestamp(), $2::bytea, 'active', 'ops')`,
      [ids.brokerGenId, shaBytes("streamcfg")]
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
  });

  await db.withTransaction("rq_relay", (tx) =>
    registerRuntimeInstance(tx, {
      instanceId: ids.relayInstanceId,
      processRole: "relay",
      databaseRole: "rq_relay",
      controlEpoch,
      buildReference: "test",
      leaseMs: 60_000n
    })
  );
  await db.withTransaction("rq_fanout", (tx) =>
    registerRuntimeInstance(tx, {
      instanceId: ids.fanoutInstanceId,
      processRole: "fanout",
      databaseRole: "rq_fanout",
      controlEpoch,
      buildReference: "test",
      leaseMs: 60_000n
    })
  );

  // Admit event and fan out into 2 deliveries (valid HTTPS endpoint + SSRF-blocked endpoint)
  const eventId = parseEventId("a0000000-0000-4000-8000-000000000001");
  const payloadId = parseEventPayloadId("a1000000-0000-4000-8000-000000000001");
  const wireEnvelopeId = parseWireEnvelopeId("a2000000-0000-4000-8000-000000000001");
  const outboxId = parseOutboxId("a3000000-0000-4000-8000-000000000001");
  const receiptId = parseCommandReceiptId("a4000000-0000-4000-8000-000000000001");

  const contentJson = { order_id: "ord-send-1" };
  const contentBytes = Buffer.from(JSON.stringify(contentJson), "utf8");
  const contentSha256 = shaHex(contentBytes);
  const admittedAt = parseCanonicalUtcTimestamp(nowUtcInstant().toString(), "admitted_at");
  const producerEventTime = admittedAt;
  const wireSerialized = serializeWebhookEnvelope({
    envelope_version: 1,
    representation_version: 1,
    project_id: ids.projectId,
    event_id: eventId,
    project_event_sequence: "1",
    event_type_id: ids.eventTypeId,
    event_type: "order.created",
    event_schema_version: 1,
    admitted_at: admittedAt,
    producer_event_time: producerEventTime,
    content: {
      media_type: EVENT_CONTENT_MEDIA_TYPE,
      encoding: EVENT_CONTENT_ENCODING,
      byte_count: contentBytes.byteLength,
      sha256: contentSha256,
      data: encodeBase64(contentBytes)
    }
  });
  const wireBytes = Buffer.from(wireSerialized.body_bytes);
  const brokerBytes = Buffer.from('{"outbox":"sender-test"}');

  await db.withTransaction("rq_api", (tx) =>
    admitEvent(tx, {
      tenantId: ids.tenantId,
      projectId: ids.projectId,
      actorPrincipalId: ids.actorPrincipalId,
      producerId: ids.producerId,
      producerNamespace: "orders",
      businessKey: "ord-send-1",
      businessKeySha256: shaHex("bk:ord-send-1"),
      idempotencyKeySha256: shaHex("idem:ord-send-1"),
      submittedShapeSha256: shaHex("shape:ord-send-1"),
      effectiveRequestSha256: shaHex("eff:ord-send-1"),
      eventTypeId: ids.eventTypeId,
      eventSchemaVersion: 1,
      content: contentBytes,
      contentSha256,
      wireEnvelopeBytes: wireBytes,
      wireEnvelopeSha256: shaHex(wireBytes),
      brokerEnvelopeBytes: brokerBytes,
      brokerEnvelopeSha256: shaHex(brokerBytes),
      producerEventTime: parseCanonicalUtcTimestamp(producerEventTime, "producerEventTime"),
      deliveryDeadlineAt: nowUtcInstant().add({ seconds: 1800 }),
      appliedDefaults: { ttl_seconds: 1800 },
      retentionPolicyVersion: "retention_v1",
      eventId,
      payloadId,
      wireEnvelopeId,
      outboxId,
      receiptId,
      auditId: "a5000000-0000-4000-8000-000000000001"
    })
  );

  const claimOut = await db.withTransaction("rq_relay", (tx) =>
    claimOutboxEvent(tx, {
      outboxId,
      instanceId: ids.relayInstanceId,
      controlEpoch,
      claimLeaseMs: 15_000n
    })
  );
  await db.withTransaction("rq_relay", (tx) =>
    observeOutboxPublication(tx, {
      outboxId,
      publicationGeneration: claimOut.publicationGeneration,
      instanceId: ids.relayInstanceId,
      controlEpoch,
      expectedClaimGeneration: claimOut.claimGeneration,
      outcome: "published",
      brokerGenerationId: ids.brokerGenId,
      streamName: "RELAYQUILL_EVENTS_V1",
      streamSequence: 1n,
      observationId: "a6000000-0000-4000-8000-000000000001"
    })
  );
  await db.withTransaction("rq_fanout", (tx) =>
    acceptBrokerInbox(tx, {
      outboxId,
      publicationGeneration: claimOut.publicationGeneration,
      eventId,
      projectId: ids.projectId,
      topologyVersion: 1n,
      envelopeSha256: shaHex(brokerBytes),
      brokerGenerationId: ids.brokerGenId,
      streamSequence: 1n,
      inboxId: "a7000000-0000-4000-8000-000000000001",
      instanceId: ids.fanoutInstanceId,
      controlEpoch
    })
  );
  const fClaim = await db.withTransaction("rq_fanout", (tx) =>
    claimEventFanout(tx, {
      eventId,
      instanceId: ids.fanoutInstanceId,
      controlEpoch,
      claimLeaseMs: 15_000n
    })
  );
  await db.withTransaction("rq_fanout", (tx) =>
    commitFanoutPage(tx, {
      eventId,
      instanceId: ids.fanoutInstanceId,
      controlEpoch,
      expectedClaimGeneration: fClaim.claimGeneration,
      complete: true,
      outcomes: [
        {
          subscription_id: ids.validSubscriptionId,
          subscription_version: "1",
          outcome: "matched",
          filter_profile_version: "relayquill.filter.v1",
          filter_sha256: shaHex("filter:hook-valid"),
          delivery_id: ids.validDeliveryId,
          family_id: ids.validFamilyId,
          endpoint_id: ids.validEndpointId,
          endpoint_version: "1",
          wire_envelope_id: wireEnvelopeId,
          consumer_contract_scope: "valid_scope",
          consumer_event_key_sha256: computeConsumerEventKeySha256({
            project_id: ids.projectId,
            event_id: eventId,
            consumer_contract_scope: "valid_scope"
          })
        },
        {
          subscription_id: ids.ssrfSubscriptionId,
          subscription_version: "1",
          outcome: "matched",
          filter_profile_version: "relayquill.filter.v1",
          filter_sha256: shaHex("filter:hook-ssrf"),
          delivery_id: ids.ssrfDeliveryId,
          family_id: ids.ssrfFamilyId,
          endpoint_id: ids.ssrfEndpointId,
          endpoint_version: "1",
          wire_envelope_id: wireEnvelopeId,
          consumer_contract_scope: "ssrf_scope",
          consumer_event_key_sha256: computeConsumerEventKeySha256({
            project_id: ids.projectId,
            event_id: eventId,
            consumer_contract_scope: "ssrf_scope"
          })
        }
      ]
    })
  );

  // Create SenderWorker wired to custody secret provider + trusted_local_fixture egress + TLS CA
  const worker = createSenderWorker({
    pgAdapter: db,
    instanceId: ids.senderInstanceId,
    controlEpoch,
    profile: "development_trusted_local",
    egressConfig: {
      mode: "trusted_local_fixture",
      allow_fixture_receiver: true,
      fixture_receiver_authority: validAuthority,
      fixture_receiver_path: "/hooks/relayquill",
      fixture_resolve_ip: "127.0.0.1"
    },
    ca: cert.certPem,
    secretProviderConfig: { mode: "in_memory_test" },
    initialInMemorySecrets: {
      "custody://k1": hmacSecretBytes
    },
    settings: {
      dispatch_domain: "default",
      approved_slots: 8,
      poll_interval_ms: 50,
      request_timeout_ms: 5_000,
      max_response_bytes: 65_536
    }
  });

  const tick = await worker.runOnce();

  // 1. Verify endpoint verification flow (204 rq.endpoint-proof.v1\0)
  assert.equal(tick.verificationOutcomes.length, 1);
  assert.equal(tick.verificationOutcomes[0]?.outcome, "verified");
  assert.equal(tick.verificationOutcomes[0]?.responseStatus, 204);
  assert.equal(receivedVerifications.length, 1);

  const intentDb = await db.withTransaction("rq_sender", (tx) =>
    tx.query(
      `SELECT ivi.state AS intent_state, eva.state AS attempt_state, eva.response_status
         FROM rq.endpoint_verification_intents ivi
         JOIN rq.endpoint_verification_attempts eva ON eva.intent_id = ivi.id
        WHERE ivi.id = $1::uuid`,
      [ids.verificationIntentId]
    )
  );
  assert.equal(intentDb.rows[0]?.intent_state, "verified");
  assert.equal(intentDb.rows[0]?.attempt_state, "verified");
  assert.equal(intentDb.rows[0]?.response_status, 204);

  // 2. Verify signed delivery + receiver_local_commit_v1 receipt persistence + SSRF block
  assert.equal(tick.claimedDeliveriesCount, 2);
  assert.equal(tick.deliveryOutcomes.length, 2);

  const validOutcome = tick.deliveryOutcomes.find((o) => o.deliveryId === ids.validDeliveryId);
  assert.equal(validOutcome?.disposition, "acknowledged");
  assert.equal(validOutcome?.receiptState, "verified");
  assert.equal(receivedDeliveries.length, 1);

  const ssrfOutcome = tick.deliveryOutcomes.find((o) => o.deliveryId === ids.ssrfDeliveryId);
  assert.equal(ssrfOutcome?.disposition, "failed_before_send");
  assert.equal(ssrfOutcome?.attemptState, "failed_before_send");
  assert.equal(ssrfOutcome?.deliveryState, "dead_letter");

  const validDb = await db.withTransaction("rq_reporter", (tx) =>
    tx.query(
      `SELECT d.state AS delivery_state, da.state AS attempt_state, da.send_started_at,
              rro.state AS receipt_state, rro.source_kind
         FROM rq.deliveries d
         JOIN rq.delivery_attempts da ON da.delivery_id = d.id
         JOIN rq.receiver_receipt_observations rro ON rro.delivery_id = d.id
        WHERE d.id = $1::uuid`,
      [ids.validDeliveryId]
    )
  );
  assert.equal(validDb.rows[0]?.delivery_state, "acknowledged");
  assert.equal(validDb.rows[0]?.attempt_state, "response_observed");
  assert.ok(validDb.rows[0]?.send_started_at !== null);
  assert.equal(validDb.rows[0]?.receipt_state, "verified_supported");
  assert.equal(validDb.rows[0]?.source_kind, "direct_response");

  const ssrfDb = await db.withTransaction("rq_reporter", (tx) =>
    tx.query(
      `SELECT d.state AS delivery_state, da.state AS attempt_state, da.send_started_at,
              da.safe_error_code, ed.decision, ed.reason_code
         FROM rq.deliveries d
         JOIN rq.delivery_attempts da ON da.delivery_id = d.id
         JOIN rq.egress_decisions ed ON ed.delivery_attempt_id = da.id
        WHERE d.id = $1::uuid`,
      [ids.ssrfDeliveryId]
    )
  );
  assert.equal(ssrfDb.rows[0]?.delivery_state, "dead_letter");
  assert.equal(ssrfDb.rows[0]?.attempt_state, "failed_before_send");
  assert.equal(ssrfDb.rows[0]?.send_started_at, null);
  assert.equal(ssrfDb.rows[0]?.decision, "denied");
});

test("SenderWorker lifecycle start/stop and node:http health probes work and CLI parses flags", async (t) => {
  const parsed = parseSenderCliArgs(["--config", "./config/development.sender.json", "--once"]);
  assert.equal(parsed.configPath, "./config/development.sender.json");
  assert.equal(parsed.once, true);

  const db = await createPGliteAdapter({ schema: "rq", isolation: "shared_database_schemas" });
  await applyMigrations(db);
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

  const worker = createSenderWorker({
    pgAdapter: db,
    secretProviderConfig: { mode: "in_memory_test" }
  });
  const health = createSenderHealthServer({ probe: worker, port: 0 });
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
});
