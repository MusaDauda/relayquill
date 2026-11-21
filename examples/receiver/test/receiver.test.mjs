import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { PGlite } from "@electric-sql/pglite";
import {
  EVENT_CONTENT_MEDIA_TYPE,
  WEBHOOK_HEADER_NAMES,
  WEBHOOK_PROTOCOL_VERSION,
  WEBHOOK_RECEIPT_MAX_BODY_BYTES,
  buildEndpointProofPreimage,
  buildReceiverReceiptPreimage,
  buildWebhookSignaturePreimage,
  computeConsumerEventKeySha256,
  computeOrderingKeySha256,
  encodeBase64Url,
  formatWebhookSignaturesHeader,
  parseCanonicalUuid,
  parseEndpointId,
  parseEndpointVerificationIntentId,
  parseEventId,
  parseEventTypeId,
  parseEventTypeName,
  parseOrderingDomainId,
  parseProjectId,
  parseSha256Hex,
  parseSubscriptionId,
  serializeEndpointVerificationBody,
  serializeWebhookEnvelope
} from "@relayquill/contracts";
import {
  InMemoryReceiverKeyProvider,
  createReceiverKeyHandle
} from "@relayquill/receiver-sdk";
import { sendIpcFrame } from "@relayquill/runtime";
import {
  createReceiverDbClient,
  createReceiverServer,
  parseReceiverCliArgs
} from "../dist/index.js";

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");

function sha256Hex(data) {
  return parseSha256Hex(crypto.createHash("sha256").update(data).digest("hex"));
}

function sha256Bytes(data) {
  return crypto.createHash("sha256").update(data).digest();
}

function hmacSha256Bytes(secretBytes, preimage) {
  return crypto.createHmac("sha256", secretBytes).update(preimage).digest();
}

async function applyReceiverMigrations(pglite) {
  const dir = path.join(REPO_ROOT, "examples/receiver/migrations");
  const files = fs
    .readdirSync(dir)
    .filter((f) => f.endsWith(".sql"))
    .sort();
  for (const file of files) {
    await pglite.exec(fs.readFileSync(path.join(dir, file), "utf8"));
  }
}

async function seedReceiverIntegration(pglite, options) {
  const {
    integrationId,
    demoCounterId,
    projectId,
    endpointId,
    contractId,
    keyId,
    custodyRef,
    expectedAuthority,
    requestTarget
  } = options;

  await pglite.transaction(async (tx) => {
    await tx.query(
      `INSERT INTO rc.integrations (
         id, relay_project_id, endpoint_id, consumer_contract_scope,
         expected_external_authority, expected_request_target,
         configuration_version, receiver_contract_id, receiver_contract_version,
         contract_sha256, state, demo_counter_id
       ) VALUES (
         $1::uuid, $2::uuid, $3::uuid, 'default',
         $4::text, $5::text,
         1, $6::uuid, 1,
         $7::bytea, 'active', $8::uuid
       )`,
      [
        integrationId,
        projectId,
        endpointId,
        expectedAuthority,
        requestTarget,
        contractId,
        sha256Bytes("contract"),
        demoCounterId
      ]
    );
    await tx.query(
      `INSERT INTO rc.demo_counters (id, integration_id, label, value)
       VALUES ($1::uuid, $2::uuid, 'orders_processed', 0)`,
      [demoCounterId, integrationId]
    );
    await tx.query(
      `INSERT INTO rc.allowed_endpoint_versions (integration_id, endpoint_version, state)
       VALUES ($1::uuid, 1, 'active')`,
      [integrationId]
    );
    await tx.query(
      `INSERT INTO rc.key_metadata (integration_id, key_id, custody_reference, custody_version_reference, state)
       VALUES ($1::uuid, $2::text, $3::text, 'v1', 'active')`,
      [integrationId, keyId, custodyRef]
    );
    await tx.query(
      `INSERT INTO rc.allowed_representations (id, integration_id, envelope_version, state)
       VALUES ($1::uuid, $2::uuid, 1, 'active')`,
      [crypto.randomUUID(), integrationId]
    );
  });
}

function postRawHttp({ port, pathName, authority, headers, bodyBytes }) {
  return new Promise((resolve, reject) => {
    const req = http.request(
      {
        host: "127.0.0.1",
        port,
        method: "POST",
        path: pathName,
        headers: {
          Host: authority,
          "Content-Length": String(bodyBytes.byteLength),
          ...headers
        }
      },
      (res) => {
        const chunks = [];
        res.on("data", (chunk) => chunks.push(chunk));
        res.on("end", () => {
          resolve({
            statusCode: res.statusCode ?? 0,
            headers: res.headers,
            rawHeaders: res.rawHeaders,
            bodyBytes: Buffer.concat(chunks)
          });
        });
      }
    );
    req.on("error", (err) => reject(err));
    req.write(Buffer.from(bodyBytes));
    req.end();
  });
}

function buildSignedVerificationRequest({
  authority,
  requestTarget,
  projectId,
  endpointId,
  endpointVersion = "1",
  keyId,
  secretBytes,
  verificationId,
  attemptId,
  configSha256,
  publicNonce,
  timestampSeconds
}) {
  const serialized = serializeEndpointVerificationBody({
    envelope_version: 1,
    verification_id: verificationId,
    endpoint_id: endpointId,
    endpoint_version: endpointVersion,
    key_id: keyId,
    purpose: "verify_destination_and_key",
    public_nonce: publicNonce,
    configuration_sha256: configSha256
  });

  const preimage = buildWebhookSignaturePreimage({
    version: WEBHOOK_PROTOCOL_VERSION,
    purpose: "endpoint_verification",
    key_id: keyId,
    method: "POST",
    external_authority: authority,
    request_target: requestTarget,
    project_id: projectId,
    endpoint_id: endpointId,
    endpoint_version: endpointVersion,
    signing_policy_version: "0",
    attempt_id: attemptId,
    verification_id: verificationId,
    timestamp_seconds: timestampSeconds,
    wire_body_sha256: serialized.body_sha256,
    raw_wire_body_bytes: serialized.body_bytes
  });
  const macBytes = hmacSha256Bytes(secretBytes, preimage);
  const sigHeader = formatWebhookSignaturesHeader([
    { version: "v1", kid: keyId, mac: encodeBase64Url(macBytes) }
  ]);

  return {
    bodyBytes: serialized.body_bytes,
    bodySha256: serialized.body_sha256,
    headers: {
      "Content-Type": EVENT_CONTENT_MEDIA_TYPE,
      [WEBHOOK_HEADER_NAMES.version]: WEBHOOK_PROTOCOL_VERSION,
      [WEBHOOK_HEADER_NAMES.purpose]: "endpoint_verification",
      [WEBHOOK_HEADER_NAMES.verificationId]: verificationId,
      [WEBHOOK_HEADER_NAMES.projectId]: projectId,
      [WEBHOOK_HEADER_NAMES.endpointId]: endpointId,
      [WEBHOOK_HEADER_NAMES.endpointVersion]: endpointVersion,
      [WEBHOOK_HEADER_NAMES.attemptId]: attemptId,
      [WEBHOOK_HEADER_NAMES.signingPolicy]: "0",
      [WEBHOOK_HEADER_NAMES.timestamp]: timestampSeconds,
      [WEBHOOK_HEADER_NAMES.bodySha256]: serialized.body_sha256,
      [WEBHOOK_HEADER_NAMES.signatures]: sigHeader
    }
  };
}

function buildSignedDeliveryRequest({
  authority,
  requestTarget,
  projectId,
  endpointId,
  endpointVersion = "1",
  subscriptionId,
  eventId,
  eventTypeId,
  deliveryId,
  deliveryGeneration = "0",
  attemptId,
  keyId,
  secretBytes,
  timestampSeconds,
  admittedAt = "2026-11-21T00:00:00.000Z",
  producerEventTime = "2026-11-21T00:00:00.000Z",
  payloadObj,
  ordering
}) {
  const rawContentJson = JSON.stringify(payloadObj);
  const rawContentBytes = Buffer.from(rawContentJson, "utf8");
  const consumerKey = computeConsumerEventKeySha256({
    project_id: projectId,
    event_id: eventId,
    consumer_contract_scope: "default"
  });
  const serialized = serializeWebhookEnvelope({
    envelope_version: 1,
    representation_version: 1,
    project_id: projectId,
    event_id: eventId,
    project_event_sequence: "1",
    event_type_id: eventTypeId,
    event_type: parseEventTypeName("order.created"),
    event_schema_version: 1,
    admitted_at: admittedAt,
    producer_event_time: producerEventTime,
    content: {
      media_type: EVENT_CONTENT_MEDIA_TYPE,
      encoding: "base64",
      byte_count: rawContentBytes.byteLength,
      sha256: sha256Hex(rawContentBytes),
      data: rawContentBytes.toString("base64")
    }
  });

  const preimage = buildWebhookSignaturePreimage({
    version: WEBHOOK_PROTOCOL_VERSION,
    purpose: "delivery",
    key_id: keyId,
    method: "POST",
    external_authority: authority,
    request_target: requestTarget,
    project_id: projectId,
    event_id: eventId,
    subscription_id: subscriptionId,
    endpoint_id: endpointId,
    endpoint_version: endpointVersion,
    signing_policy_version: "1",
    delivery_id: deliveryId,
    delivery_generation: deliveryGeneration,
    attempt_id: attemptId,
    timestamp_seconds: timestampSeconds,
    consumer_event_key: consumerKey,
    ...(ordering !== undefined
      ? {
          ordering_domain_id: ordering.domainId,
          ordering_key_sha256: ordering.keySha256,
          ordering_sequence: ordering.sequence
        }
      : {}),
    wire_body_sha256: serialized.body_sha256,
    raw_wire_body_bytes: serialized.body_bytes
  });
  const macBytes = hmacSha256Bytes(secretBytes, preimage);
  const sigHeader = formatWebhookSignaturesHeader([
    { version: "v1", kid: keyId, mac: encodeBase64Url(macBytes) }
  ]);

  return {
    consumerKey,
    originalFactsSha256: serialized.original_facts_sha256,
    bodyBytes: serialized.body_bytes,
    bodySha256: serialized.body_sha256,
    headers: {
      "Content-Type": EVENT_CONTENT_MEDIA_TYPE,
      [WEBHOOK_HEADER_NAMES.version]: WEBHOOK_PROTOCOL_VERSION,
      [WEBHOOK_HEADER_NAMES.purpose]: "delivery",
      [WEBHOOK_HEADER_NAMES.projectId]: projectId,
      [WEBHOOK_HEADER_NAMES.eventId]: eventId,
      [WEBHOOK_HEADER_NAMES.subscriptionId]: subscriptionId,
      [WEBHOOK_HEADER_NAMES.endpointId]: endpointId,
      [WEBHOOK_HEADER_NAMES.endpointVersion]: endpointVersion,
      [WEBHOOK_HEADER_NAMES.deliveryId]: deliveryId,
      [WEBHOOK_HEADER_NAMES.deliveryGeneration]: deliveryGeneration,
      [WEBHOOK_HEADER_NAMES.attemptId]: attemptId,
      [WEBHOOK_HEADER_NAMES.signingPolicy]: "1",
      [WEBHOOK_HEADER_NAMES.timestamp]: timestampSeconds,
      [WEBHOOK_HEADER_NAMES.consumerKey]: consumerKey,
      [WEBHOOK_HEADER_NAMES.bodySha256]: serialized.body_sha256,
      [WEBHOOK_HEADER_NAMES.signatures]: sigHeader,
      ...(ordering !== undefined
        ? {
            [WEBHOOK_HEADER_NAMES.orderingDomain]: ordering.domainId,
            [WEBHOOK_HEADER_NAMES.orderingKey]: ordering.keySha256,
            [WEBHOOK_HEADER_NAMES.orderingSequence]: ordering.sequence
          }
        : {})
    }
  };
}

test("Receiver server handles 204 proof, signed receipts, commit_drop_response idempotency, replay_append without double count, and IPC fault controls", async (t) => {
  const cliParsed = parseReceiverCliArgs([
    "--config",
    "./config/portable.receiver.json",
    "--host",
    "127.0.0.1",
    "--port",
    "19095"
  ]);
  assert.equal(cliParsed.port, 19095);
  assert.equal(cliParsed.host, "127.0.0.1");

  const pglite = await PGlite.create({ dataDir: "memory://" });
  await applyReceiverMigrations(pglite);

  const projectId = parseProjectId("20000000-0000-4000-8000-000000000001");
  const endpointId = parseEndpointId("60000000-0000-4000-8000-000000000001");
  const subscriptionId = parseSubscriptionId("70000000-0000-4000-8000-000000000001");
  const eventTypeId = parseEventTypeId("50000000-0000-4000-8000-000000000001");
  const integrationId = parseCanonicalUuid("10000000-0000-4000-8000-000000000010");
  const demoCounterId = parseCanonicalUuid("10000000-0000-4000-8000-000000000011");
  const contractId = parseCanonicalUuid("63000000-0000-4000-8000-000000000001");
  const keyId = "k1";
  const secretBytes = Buffer.from("0123456789abcdef0123456789abcdef");
  const expectedAuthority = "receiver.example.test:443";
  const requestTarget = "/webhook";

  await seedReceiverIntegration(pglite, {
    integrationId,
    demoCounterId,
    projectId,
    endpointId,
    contractId,
    keyId,
    custodyRef: "env:TEST_KEY",
    expectedAuthority,
    requestTarget
  });

  const keyProvider = new InMemoryReceiverKeyProvider();
  keyProvider.registerKey({
    projectId,
    endpointId,
    secretBytes,
    metadata: {
      keyId,
      state: "active"
    }
  });
  void createReceiverKeyHandle(secretBytes);

  const db = await createReceiverDbClient({
    pglite,
    ownsClient: false,
    schema: "rc"
  });
  const tmpRuntimeDir = fs.mkdtempSync(path.join(os.tmpdir(), "rq-rc-ipc-"));

  const server = await createReceiverServer({
    db,
    host: "127.0.0.1",
    port: 0,
    routePath: requestTarget,
    keyProvider,
    controlChannel: {
      env_name: "test",
      channel: `receiver-ctrl-${process.pid}-${Date.now()}`
    },
    runtimeDir: tmpRuntimeDir
  });
  const started = await server.start();

  t.after(async () => {
    await server.stop();
    await db.close();
    await pglite.close();
    keyProvider.destroy();
    fs.rmSync(tmpRuntimeDir, { recursive: true, force: true });
  });

  assert.ok(started.ipcEndpoint !== undefined);

  // Health endpoints
  const liveRes = await fetch(`http://127.0.0.1:${started.port}/health/live`);
  assert.equal(liveRes.status, 200);
  const readyRes = await fetch(`http://127.0.0.1:${started.port}/health/ready`);
  assert.equal(readyRes.status, 200);

  const nowSec = String(Math.floor(Date.now() / 1000));

  // 1. 204 Endpoint proof challenge
  const verificationId = parseEndpointVerificationIntentId("e1000000-0000-4000-8000-000000000001");
  const verAttemptId = "e2000000-0000-4000-8000-000000000001";
  const publicNonce = encodeBase64Url(crypto.randomBytes(32));
  const configSha256 = sha256Hex("ep-config-v1");
  const probeReq = buildSignedVerificationRequest({
    authority: expectedAuthority,
    requestTarget,
    projectId,
    endpointId,
    keyId,
    secretBytes,
    verificationId,
    attemptId: verAttemptId,
    configSha256,
    publicNonce,
    timestampSeconds: nowSec
  });
  const probeResp = await postRawHttp({
    port: started.port,
    pathName: requestTarget,
    authority: expectedAuthority,
    headers: probeReq.headers,
    bodyBytes: probeReq.bodyBytes
  });
  assert.equal(probeResp.statusCode, 204);
  assert.equal(probeResp.bodyBytes.byteLength, 0);
  const proofHeader = probeResp.headers[WEBHOOK_HEADER_NAMES.endpointProof.toLowerCase()];
  assert.equal(typeof proofHeader, "string");
  const expectedProofPreimage = buildEndpointProofPreimage({
    verification_intent_id: verificationId,
    endpoint_id: endpointId,
    endpoint_version: "1",
    configuration_sha256: configSha256,
    key_id: keyId,
    public_nonce: publicNonce,
    verification_attempt_id: verAttemptId,
    request_timestamp_seconds: nowSec,
    request_wire_body_sha256: probeReq.bodySha256
  });
  assert.equal(
    proofHeader,
    encodeBase64Url(hmacSha256Bytes(secretBytes, expectedProofPreimage))
  );

  // 2. commit_drop_response via protected IPC -> DB commits once, HTTP drops, retry returns valid signed receipt <= 4096B with still 1 business mutation
  const armDrop = await sendIpcFrame(started.ipcEndpoint, {
    op: "commit_drop_response",
    count: 1
  });
  assert.equal(armDrop.ok, true);
  assert.equal(armDrop.faults.commitDropRemaining, 1);

  const event1Id = parseEventId("a0000000-0000-4000-8000-000000000001");
  const delivery1Id = "d0000000-0000-4000-8000-000000000001";
  const delReq1Attempt1 = buildSignedDeliveryRequest({
    authority: expectedAuthority,
    requestTarget,
    projectId,
    endpointId,
    subscriptionId,
    eventId: event1Id,
    eventTypeId,
    deliveryId: delivery1Id,
    attemptId: "b0000000-0000-4000-8000-000000000001",
    keyId,
    secretBytes,
    timestampSeconds: nowSec,
    payloadObj: { order_id: "ord-1", amount: 100 }
  });
  await assert.rejects(() =>
    postRawHttp({
      port: started.port,
      pathName: requestTarget,
      authority: expectedAuthority,
      headers: delReq1Attempt1.headers,
      bodyBytes: delReq1Attempt1.bodyBytes
    })
  );

  const afterDropInspect = await sendIpcFrame(started.ipcEndpoint, { op: "inspect_state" });
  assert.equal(afterDropInspect.ok, true);
  assert.equal(afterDropInspect.state.integrations[0]?.counterValue, "1");
  assert.equal(afterDropInspect.state.businessMutationCount, 1);
  assert.equal(afterDropInspect.state.inboxCount, 1);

  // Retry after dropped response (new attempt_id, same event/consumerKey/facts)
  const retryAttemptId = "b0000000-0000-4000-8000-000000000002";
  const delReq1Retry = buildSignedDeliveryRequest({
    authority: expectedAuthority,
    requestTarget,
    projectId,
    endpointId,
    subscriptionId,
    eventId: event1Id,
    eventTypeId,
    deliveryId: delivery1Id,
    attemptId: retryAttemptId,
    keyId,
    secretBytes,
    timestampSeconds: nowSec,
    payloadObj: { order_id: "ord-1", amount: 100 }
  });
  const retryResp = await postRawHttp({
    port: started.port,
    pathName: requestTarget,
    authority: expectedAuthority,
    headers: delReq1Retry.headers,
    bodyBytes: delReq1Retry.bodyBytes
  });
  assert.equal(retryResp.statusCode, 200);
  assert.ok(retryResp.bodyBytes.byteLength <= WEBHOOK_RECEIPT_MAX_BODY_BYTES);
  const receipt1 = JSON.parse(retryResp.bodyBytes.toString("utf8"));
  assert.equal(receipt1.business_status, "committed");
  assert.equal(receipt1.event_id, event1Id);
  assert.equal(receipt1.delivery_attempt_id, retryAttemptId);

  const expectedReceipt1Preimage = buildReceiverReceiptPreimage({
    key_id: receipt1.key_id,
    project_id: receipt1.project_id,
    event_id: receipt1.event_id,
    consumer_event_key: receipt1.consumer_event_key,
    original_facts_sha256: receipt1.original_facts_sha256,
    receipt_id: receipt1.receipt_id,
    business_status: "committed",
    committed_at: receipt1.committed_at,
    delivery_attempt_id: receipt1.delivery_attempt_id,
    request_wire_body_sha256: delReq1Retry.bodySha256
  });
  assert.equal(
    receipt1.mac,
    encodeBase64Url(hmacSha256Bytes(secretBytes, expectedReceipt1Preimage))
  );

  // Counter & mutations MUST remain 1 after retry!
  const afterRetryState = await server.inspectState();
  assert.equal(afterRetryState.integrations[0]?.counterValue, "1");
  assert.equal(afterRetryState.businessMutationCount, 1);

  // Conflicting facts for same consumer_key -> 409 conflict
  const conflictReq = buildSignedDeliveryRequest({
    authority: expectedAuthority,
    requestTarget,
    projectId,
    endpointId,
    subscriptionId,
    eventId: event1Id,
    eventTypeId,
    deliveryId: delivery1Id,
    attemptId: "b0000000-0000-4000-8000-000000000003",
    keyId,
    secretBytes,
    timestampSeconds: nowSec,
    payloadObj: { order_id: "ord-1", amount: 999 }
  });
  const conflictResp = await postRawHttp({
    port: started.port,
    pathName: requestTarget,
    authority: expectedAuthority,
    headers: conflictReq.headers,
    bodyBytes: conflictReq.bodyBytes
  });
  assert.equal(conflictResp.statusCode, 409);

  // 3. Strict ordering + gap rejection + replay_append advancing sequence head WITHOUT double-incrementing counter
  const orderingDomainId = parseOrderingDomainId("c0000000-0000-4000-8000-000000000001");
  const orderingKeySha256 = computeOrderingKeySha256({
    ordering_domain_id: orderingDomainId,
    subscription_id: subscriptionId,
    consumer_contract_scope: "default",
    ordering_key: "customer:cust-42"
  });
  const event2Id = parseEventId("a0000000-0000-4000-8000-000000000002");

  const seq1Req = buildSignedDeliveryRequest({
    authority: expectedAuthority,
    requestTarget,
    projectId,
    endpointId,
    subscriptionId,
    eventId: event2Id,
    eventTypeId,
    deliveryId: "d0000000-0000-4000-8000-000000000002",
    attemptId: "b0000000-0000-4000-8000-000000000010",
    keyId,
    secretBytes,
    timestampSeconds: nowSec,
    payloadObj: { order_id: "ord-2", step: "created" },
    ordering: { domainId: orderingDomainId, keySha256: orderingKeySha256, sequence: "1" }
  });
  const seq1Resp = await postRawHttp({
    port: started.port,
    pathName: requestTarget,
    authority: expectedAuthority,
    headers: seq1Req.headers,
    bodyBytes: seq1Req.bodyBytes
  });
  assert.equal(seq1Resp.statusCode, 200);
  const afterSeq1State = await server.inspectState();
  assert.equal(afterSeq1State.integrations[0]?.counterValue, "2");
  assert.equal(afterSeq1State.businessMutationCount, 2);
  assert.equal(afterSeq1State.orderHeads[0]?.nextExpectedSequence, "2");

  // Sequence gap (sequence 3 when next_expected_sequence = 2) -> 409
  const gapReq = buildSignedDeliveryRequest({
    authority: expectedAuthority,
    requestTarget,
    projectId,
    endpointId,
    subscriptionId,
    eventId: parseEventId("a0000000-0000-4000-8000-000000000003"),
    eventTypeId,
    deliveryId: "d0000000-0000-4000-8000-000000000003",
    attemptId: "b0000000-0000-4000-8000-000000000011",
    keyId,
    secretBytes,
    timestampSeconds: nowSec,
    payloadObj: { order_id: "ord-3", step: "created" },
    ordering: { domainId: orderingDomainId, keySha256: orderingKeySha256, sequence: "3" }
  });
  const gapResp = await postRawHttp({
    port: started.port,
    pathName: requestTarget,
    authority: expectedAuthority,
    headers: gapReq.headers,
    bodyBytes: gapReq.bodyBytes
  });
  assert.equal(gapResp.statusCode, 409);

  // replay_append of event2 at ordering_sequence = 2 advances head to 3 WITHOUT incrementing counter or business_mutations!
  const replayAppendReq = buildSignedDeliveryRequest({
    authority: expectedAuthority,
    requestTarget,
    projectId,
    endpointId,
    subscriptionId,
    eventId: event2Id,
    eventTypeId,
    deliveryId: "d0000000-0000-4000-8000-000000000004",
    deliveryGeneration: "1",
    attemptId: "b0000000-0000-4000-8000-000000000012",
    keyId,
    secretBytes,
    timestampSeconds: nowSec,
    payloadObj: { order_id: "ord-2", step: "created" },
    ordering: { domainId: orderingDomainId, keySha256: orderingKeySha256, sequence: "2" }
  });
  const replayAppendResp = await postRawHttp({
    port: started.port,
    pathName: requestTarget,
    authority: expectedAuthority,
    headers: replayAppendReq.headers,
    bodyBytes: replayAppendReq.bodyBytes
  });
  assert.equal(replayAppendResp.statusCode, 200);
  const replayReceipt = JSON.parse(replayAppendResp.bodyBytes.toString("utf8"));
  assert.equal(replayReceipt.event_id, event2Id);

  const afterReplayAppendState = await server.inspectState();
  assert.equal(afterReplayAppendState.integrations[0]?.counterValue, "2");
  assert.equal(afterReplayAppendState.businessMutationCount, 2);
  assert.equal(afterReplayAppendState.orderHeads[0]?.nextExpectedSequence, "3");
  assert.equal(afterReplayAppendState.orderAcceptancesCount, 2);

  // 4. Remaining IPC fault commands: oversized_receipt_response, invalid_receipt_mac, commit_delay_response, reset_faults
  await sendIpcFrame(started.ipcEndpoint, { op: "oversized_receipt_response", count: 1 });
  const oversizedResp = await postRawHttp({
    port: started.port,
    pathName: requestTarget,
    authority: expectedAuthority,
    headers: delReq1Retry.headers,
    bodyBytes: delReq1Retry.bodyBytes
  });
  assert.equal(oversizedResp.statusCode, 200);
  assert.ok(oversizedResp.bodyBytes.byteLength > WEBHOOK_RECEIPT_MAX_BODY_BYTES);

  await sendIpcFrame(started.ipcEndpoint, { op: "invalid_receipt_mac", count: 1 });
  const badMacResp = await postRawHttp({
    port: started.port,
    pathName: requestTarget,
    authority: expectedAuthority,
    headers: delReq1Retry.headers,
    bodyBytes: delReq1Retry.bodyBytes
  });
  assert.equal(badMacResp.statusCode, 200);
  const badMacReceipt = JSON.parse(badMacResp.bodyBytes.toString("utf8"));
  assert.notEqual(
    badMacReceipt.mac,
    encodeBase64Url(
      hmacSha256Bytes(
        secretBytes,
        buildReceiverReceiptPreimage({
          key_id: badMacReceipt.key_id,
          project_id: badMacReceipt.project_id,
          event_id: badMacReceipt.event_id,
          consumer_event_key: badMacReceipt.consumer_event_key,
          original_facts_sha256: badMacReceipt.original_facts_sha256,
          receipt_id: badMacReceipt.receipt_id,
          business_status: "committed",
          committed_at: badMacReceipt.committed_at,
          delivery_attempt_id: badMacReceipt.delivery_attempt_id,
          request_wire_body_sha256: delReq1Retry.bodySha256
        })
      )
    )
  );

  await sendIpcFrame(started.ipcEndpoint, { op: "commit_delay_response", delay_ms: 80, count: 1 });
  const delayStart = Date.now();
  const delayedResp = await postRawHttp({
    port: started.port,
    pathName: requestTarget,
    authority: expectedAuthority,
    headers: delReq1Retry.headers,
    bodyBytes: delReq1Retry.bodyBytes
  });
  assert.equal(delayedResp.statusCode, 200);
  assert.ok(Date.now() - delayStart >= 60);

  await sendIpcFrame(started.ipcEndpoint, { op: "commit_drop_response", count: 5 });
  const resetReply = await sendIpcFrame(started.ipcEndpoint, { op: "reset_faults" });
  assert.equal(resetReply.ok, true);
  assert.equal(resetReply.faults.commitDropRemaining, 0);

  const cleanAfterReset = await postRawHttp({
    port: started.port,
    pathName: requestTarget,
    authority: expectedAuthority,
    headers: delReq1Retry.headers,
    bodyBytes: delReq1Retry.bodyBytes
  });
  assert.equal(cleanAfterReset.statusCode, 200);
  assert.ok(cleanAfterReset.bodyBytes.byteLength <= WEBHOOK_RECEIPT_MAX_BODY_BYTES);
});
