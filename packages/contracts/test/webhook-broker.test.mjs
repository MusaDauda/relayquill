import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { ValidationDomainError } from "@relayquill/domain";
import {
  BROKER_EVENT_MAX_PAYLOAD_BYTES,
  BROKER_EVENT_STREAM_NAME,
  FANOUT_CONSUMER_NAME,
  WEBHOOK_HEADER_NAMES,
  buildEndpointProofPreimage,
  buildReceiverReceiptPreimage,
  buildWebhookSignaturePreimage,
  decodeBrokerMessageId,
  decodeBrokerNotificationEnvelope,
  decodeEndpointVerificationBodyBytes,
  decodeReceiverLocalCommitReceiptBytes,
  decodeWebhookEnvelopeBytes,
  encodeBase64Url,
  encodeBrokerMessageId,
  encodeBrokerNotificationEnvelope,
  encodeUtf8Bytes,
  formatWebhookSignaturesHeader,
  hmacSha256Digest,
  isWebhookTimestampFresh,
  parseBrokerEventSubject,
  parseW3CTraceparent,
  parseW3CTracestate,
  parseWebhookRawHeaders,
  parseWebhookSignaturesHeader,
  serializeEndpointVerificationBody,
  serializeReceiverLocalCommitReceipt,
  serializeWebhookEnvelope
} from "@relayquill/contracts";

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");
const WEBHOOK_VECTORS = JSON.parse(
  fs.readFileSync(path.join(REPO_ROOT, "contracts/webhook-v1/vectors.json"), "utf8")
);
const BROKER_VECTORS = JSON.parse(
  fs.readFileSync(path.join(REPO_ROOT, "contracts/broker-v1/vectors.json"), "utf8")
);

test("webhook envelope v1 produces exact 552-byte canonical JSON and SHA-256 vector", () => {
  const vec = WEBHOOK_VECTORS.envelope_v1_echo_vector;
  const serialized = serializeWebhookEnvelope(vec.envelope);

  assert.equal(serialized.byte_count, 552);
  assert.equal(serialized.byte_count, vec.canonical_byte_count);
  assert.equal(serialized.body_json, vec.canonical_json);
  assert.equal(
    serialized.body_sha256,
    "c37a5e1841419d414e907071fda86dc1b66f96e943083a6e503c10e61e227b1b"
  );
  assert.equal(serialized.body_sha256, vec.canonical_sha256);
  assert.equal(serialized.original_facts_sha256, vec.original_facts_sha256);

  const decoded = decodeWebhookEnvelopeBytes(serialized.body_bytes);
  assert.equal(decoded.envelope.envelope_version, 1);
  assert.equal(decoded.original_facts_sha256, vec.original_facts_sha256);
  assert.equal(
    new TextDecoder().decode(decoded.original_content_bytes),
    vec.raw_content_utf8
  );
});

test("webhook envelope v2 preserves original_facts_sha256 and validates derived bytes", () => {
  const vec = WEBHOOK_VECTORS.envelope_v2_derived_vector;
  const serialized = serializeWebhookEnvelope(vec.envelope);

  assert.equal(serialized.byte_count, vec.canonical_byte_count);
  assert.equal(serialized.body_json, vec.canonical_json);
  assert.equal(serialized.body_sha256, vec.canonical_sha256);
  assert.equal(serialized.original_facts_sha256, vec.original_facts_sha256);

  const decoded = decodeWebhookEnvelopeBytes(serialized.body_bytes);
  assert.equal(decoded.envelope.envelope_version, 2);
  assert.equal(new TextDecoder().decode(decoded.derived_content_bytes), vec.raw_derived_utf8);

  // Unknown top-level field or wrong content hash in raw body bytes rejects
  const tampered = encodeUtf8Bytes(
    serialized.body_json.replace('"event_type":"demo.echoed"', '"event_type":"demo.echoed","extra":1')
  );
  assert.throws(() => decodeWebhookEnvelopeBytes(tampered), ValidationDomainError);
});

test("webhook headers, signature grammar, verification body, receipt DTO, and preimages", () => {
  const vec = WEBHOOK_VECTORS.envelope_v1_echo_vector;
  const serialized = serializeWebhookEnvelope(vec.envelope);
  const ephemeralKey = new Uint8Array(32).map((_, i) => (i + 1) & 0xff);

  const subscriptionId = "00000000-0000-4000-8000-000000000805";
  const endpointId = "00000000-0000-4000-8000-000000000a05";
  const deliveryId = "00000000-0000-4000-8000-000000001005";
  const attemptId = "00000000-0000-4000-8000-000000000c05";
  const consumerKey = "f".repeat(64);
  const orderingDomainId = "00000000-0000-4000-8000-000000000905";
  const orderingKeyHash = "e".repeat(64);
  const timestampSec = "1762000000";

  const preimage = buildWebhookSignaturePreimage({
    purpose: "delivery",
    key_id: "k1.primary",
    external_authority: "receiver.example:443",
    request_target: "/hooks/relayquill",
    project_id: vec.envelope.project_id,
    event_id: vec.envelope.event_id,
    subscription_id: subscriptionId,
    endpoint_id: endpointId,
    endpoint_version: "1",
    signing_policy_version: "1",
    delivery_id: deliveryId,
    delivery_generation: "0",
    attempt_id: attemptId,
    timestamp_seconds: timestampSec,
    consumer_event_key: consumerKey,
    ordering_domain_id: orderingDomainId,
    ordering_key_sha256: orderingKeyHash,
    ordering_sequence: "1",
    traceparent: "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
    tracestate: "rq=v1",
    wire_body_sha256: serialized.body_sha256,
    raw_wire_body_bytes: serialized.body_bytes
  });

  const macBytes = hmacSha256Digest(ephemeralKey, preimage);
  const expectedNodeMac = new Uint8Array(
    crypto.createHmac("sha256", ephemeralKey).update(preimage).digest()
  );
  assert.deepEqual(macBytes, expectedNodeMac);

  const macStr = encodeBase64Url(macBytes);
  const sigHeader = formatWebhookSignaturesHeader([{ kid: "k1.primary", mac: macStr }]);

  const rawHeaders = [
    ["Content-Type", "application/json; charset=utf-8"],
    [WEBHOOK_HEADER_NAMES.version, "1"],
    [WEBHOOK_HEADER_NAMES.purpose, "delivery"],
    [WEBHOOK_HEADER_NAMES.projectId, vec.envelope.project_id],
    [WEBHOOK_HEADER_NAMES.eventId, vec.envelope.event_id],
    [WEBHOOK_HEADER_NAMES.subscriptionId, subscriptionId],
    [WEBHOOK_HEADER_NAMES.endpointId, endpointId],
    [WEBHOOK_HEADER_NAMES.endpointVersion, "1"],
    [WEBHOOK_HEADER_NAMES.deliveryId, deliveryId],
    [WEBHOOK_HEADER_NAMES.deliveryGeneration, "0"],
    [WEBHOOK_HEADER_NAMES.attemptId, attemptId],
    [WEBHOOK_HEADER_NAMES.signingPolicy, "1"],
    [WEBHOOK_HEADER_NAMES.timestamp, timestampSec],
    [WEBHOOK_HEADER_NAMES.consumerKey, consumerKey],
    [WEBHOOK_HEADER_NAMES.bodySha256, serialized.body_sha256],
    [WEBHOOK_HEADER_NAMES.signatures, sigHeader],
    [WEBHOOK_HEADER_NAMES.orderingDomain, orderingDomainId],
    [WEBHOOK_HEADER_NAMES.orderingKey, orderingKeyHash],
    [WEBHOOK_HEADER_NAMES.orderingSequence, "1"],
    ["traceparent", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"],
    ["tracestate", "rq=v1"]
  ];

  const parsedHeaders = parseWebhookRawHeaders(rawHeaders);
  assert.equal(parsedHeaders.purpose, "delivery");
  if (parsedHeaders.purpose === "delivery") {
    assert.equal(parsedHeaders.ordering?.ordering_sequence, "1");
  }

  // Freshness window: [-300s, +30s]
  assert.equal(isWebhookTimestampFresh(timestampSec, 1762000300n), true);
  assert.equal(isWebhookTimestampFresh(timestampSec, 1762000301n), false);
  assert.equal(isWebhookTimestampFresh(timestampSec, 1761999970n), true);
  assert.equal(isWebhookTimestampFresh(timestampSec, 1761999969n), false);

  // Duplicate protected header, Content-Encoding, partial ordering tuple, duplicate kid must reject
  assert.throws(
    () => parseWebhookRawHeaders([...rawHeaders, ["relayquill-timestamp", timestampSec]]),
    ValidationDomainError
  );
  assert.throws(
    () => parseWebhookRawHeaders([...rawHeaders, ["Content-Encoding", "gzip"]]),
    ValidationDomainError
  );
  assert.throws(
    () =>
      parseWebhookRawHeaders(
        rawHeaders.filter(([name]) => name !== WEBHOOK_HEADER_NAMES.orderingSequence)
      ),
    ValidationDomainError
  );
  assert.throws(
    () => parseWebhookSignaturesHeader(`v1;kid=k1;mac=${macStr},v1;kid=k1;mac=${macStr}`),
    ValidationDomainError
  );

  // Endpoint verification body & endpoint proof preimage
  const evVec = WEBHOOK_VECTORS.endpoint_verification_vector;
  const serializedEv = serializeEndpointVerificationBody(evVec.body);
  assert.equal(serializedEv.body_json, evVec.canonical_json);
  assert.equal(serializedEv.body_sha256, evVec.canonical_sha256);
  assert.equal(decodeEndpointVerificationBodyBytes(serializedEv.body_bytes).key_id, "k1.primary");

  const proofPreimage = buildEndpointProofPreimage({
    verification_intent_id: evVec.body.verification_id,
    endpoint_id: evVec.body.endpoint_id,
    endpoint_version: evVec.body.endpoint_version,
    configuration_sha256: evVec.body.configuration_sha256,
    key_id: evVec.body.key_id,
    public_nonce: evVec.body.public_nonce,
    verification_attempt_id: attemptId,
    request_timestamp_seconds: timestampSec,
    request_wire_body_sha256: serializedEv.body_sha256
  });
  assert.ok(proofPreimage.length > 0);

  // Receiver local commit v1 receipt DTO & preimage
  const receiptId = "00000000-0000-4000-8000-000000000d05";
  const receiptPreimage = buildReceiverReceiptPreimage({
    key_id: "k1.primary",
    project_id: vec.envelope.project_id,
    event_id: vec.envelope.event_id,
    consumer_event_key: consumerKey,
    original_facts_sha256: vec.original_facts_sha256,
    receipt_id: receiptId,
    business_status: "committed",
    committed_at: "2026-11-01T12:00:05.123456Z",
    delivery_attempt_id: attemptId,
    request_wire_body_sha256: serialized.body_sha256
  });
  const receiptMac = encodeBase64Url(hmacSha256Digest(ephemeralKey, receiptPreimage));
  const serializedReceipt = serializeReceiverLocalCommitReceipt({
    receipt_version: 1,
    project_id: vec.envelope.project_id,
    event_id: vec.envelope.event_id,
    consumer_event_key: consumerKey,
    original_facts_sha256: vec.original_facts_sha256,
    receipt_id: receiptId,
    business_status: "committed",
    committed_at: "2026-11-01T12:00:05.123456Z",
    delivery_attempt_id: attemptId,
    key_id: "k1.primary",
    mac: receiptMac
  });
  assert.ok(serializedReceipt.body_bytes.length <= 4096);
  assert.equal(
    decodeReceiverLocalCommitReceiptBytes(serializedReceipt.body_bytes).mac,
    receiptMac
  );
});

test("broker notification envelope <=4KiB, deterministic broker_message_id, and W3C trace checks", () => {
  assert.equal(BROKER_EVENT_STREAM_NAME, "RELAYQUILL_EVENTS_V1");
  assert.equal(FANOUT_CONSUMER_NAME, "RELAYQUILL_FANOUT_V1");
  assert.equal(BROKER_EVENT_MAX_PAYLOAD_BYTES, 4096);

  for (const vec of BROKER_VECTORS.vectors) {
    const encoded = encodeBrokerNotificationEnvelope(vec.input);
    assert.equal(encoded.subject, vec.expected_subject);
    assert.equal(encoded.broker_message_id, vec.expected_broker_message_id);
    assert.equal(encoded.json, vec.expected_json);
    assert.equal(encoded.byte_count, vec.expected_byte_count);
    assert.ok(encoded.byte_count <= BROKER_EVENT_MAX_PAYLOAD_BYTES);
    assert.equal(encoded.envelope_sha256, vec.expected_envelope_sha256);

    const decoded = decodeBrokerNotificationEnvelope(encoded.bytes);
    assert.equal(decoded.broker_message_id, vec.expected_broker_message_id);
    assert.equal(decoded.envelope_sha256, vec.expected_envelope_sha256);
  }

  const msgId = encodeBrokerMessageId("00000000-0000-4000-8000-000000000605", 3n);
  assert.equal(msgId, "rq:00000000-0000-4000-8000-000000000605:3");
  assert.deepEqual(decodeBrokerMessageId(msgId), {
    message_id: msgId,
    outbox_id: "00000000-0000-4000-8000-000000000605",
    publication_generation: "3"
  });
  assert.throws(() => decodeBrokerMessageId("rq:bad:0"), ValidationDomainError);

  const parsedSubj = parseBrokerEventSubject(
    "rq.events.00000000-0000-4000-8000-000000000105.accepted"
  );
  assert.equal(parsedSubj.project_id, "00000000-0000-4000-8000-000000000105");
  assert.throws(() => parseBrokerEventSubject("rq.events.not-a-uuid.accepted"), ValidationDomainError);

  // Rejects private payload/unknown fields and invalid traceparent/tracestate
  assert.throws(
    () =>
      decodeBrokerNotificationEnvelope(
        JSON.stringify({
          ...BROKER_VECTORS.vectors[0].input,
          raw_payload: "forbidden"
        })
      ),
    ValidationDomainError
  );
  assert.throws(
    () => parseW3CTraceparent("00-00000000000000000000000000000000-00f067aa0ba902b7-01"),
    ValidationDomainError
  );
  assert.throws(
    () => parseW3CTraceparent("00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01"),
    ValidationDomainError
  );
  assert.throws(
    () => parseW3CTracestate("k1=1,k2=2,k3=3,k4=4,k5=5,k6=6,k7=7,k8=8,k9=9"),
    ValidationDomainError
  );
});

test("all released JSON Schema definitions under contracts/ are valid Draft 2020-12 JSON documents", () => {
  const schemaPaths = [
    "contracts/webhook-v1/webhook-envelope.schema.json",
    "contracts/webhook-v1/endpoint-verification.schema.json",
    "contracts/webhook-v1/receiver-local-commit-receipt.schema.json",
    "contracts/broker-v1/broker-notification.schema.json",
    "contracts/canonical-command-v1/canonical-command.schema.json",
    "contracts/compatibility/http-envelope-and-states.schema.json"
  ];
  for (const rel of schemaPaths) {
    const schema = JSON.parse(fs.readFileSync(path.join(REPO_ROOT, rel), "utf8"));
    assert.equal(schema.$schema, "https://json-schema.org/draft/2020-12/schema", rel);
    assert.ok(typeof schema.$id === "string" && schema.$id.startsWith("https://"), rel);
    assert.ok(typeof schema.title === "string" && schema.title.length > 0, rel);
  }
});
