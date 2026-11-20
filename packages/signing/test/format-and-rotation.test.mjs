import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { Temporal } from "@js-temporal/polyfill";
import { ValidationDomainError } from "@relayquill/domain";
import {
  WEBHOOK_HEADER_NAMES,
  encodeBase64Url,
  encodeUtf8Bytes,
  serializeWebhookEnvelope
} from "@relayquill/contracts";
import {
  ALLOWED_KEY_LIFECYCLE_TRANSITIONS,
  SIGNING_OVERLAP_MAX_MS,
  SIGNING_VERIFY_BUFFER_MS,
  assertKeyLifecycleTransition,
  checkKeySigningEligibility,
  checkKeyVerificationEligibility,
  encodeWebhookSignaturePreimage,
  formatSignaturesHeader,
  parseSignaturesHeader,
  resolveSigningPlan,
  toKeyLifecycleState,
  validateRawEndpointProofResponseHeaders,
  validateRawWebhookHeaders
} from "../dist/index.js";

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");
const WEBHOOK_VECTORS = JSON.parse(
  fs.readFileSync(path.join(REPO_ROOT, "contracts/webhook-v1/vectors.json"), "utf8")
);

function buildSampleDeliveryRawHeaders(overrides = {}) {
  const vec = WEBHOOK_VECTORS.envelope_v1_echo_vector;
  const serialized = serializeWebhookEnvelope(vec.envelope);
  const macB64 = encodeBase64Url(new Uint8Array(32).fill(0xab));
  const map = new Map([
    ["Content-Type", "application/json; charset=utf-8"],
    [WEBHOOK_HEADER_NAMES.version, "1"],
    [WEBHOOK_HEADER_NAMES.purpose, "delivery"],
    [WEBHOOK_HEADER_NAMES.projectId, vec.envelope.project_id],
    [WEBHOOK_HEADER_NAMES.eventId, vec.envelope.event_id],
    [WEBHOOK_HEADER_NAMES.subscriptionId, "00000000-0000-4000-8000-000000000805"],
    [WEBHOOK_HEADER_NAMES.endpointId, "00000000-0000-4000-8000-000000000a05"],
    [WEBHOOK_HEADER_NAMES.endpointVersion, "1"],
    [WEBHOOK_HEADER_NAMES.deliveryId, "00000000-0000-4000-8000-000000001005"],
    [WEBHOOK_HEADER_NAMES.deliveryGeneration, "0"],
    [WEBHOOK_HEADER_NAMES.attemptId, "00000000-0000-4000-8000-000000000c05"],
    [WEBHOOK_HEADER_NAMES.signingPolicy, "1"],
    [WEBHOOK_HEADER_NAMES.timestamp, "1762000000"],
    [WEBHOOK_HEADER_NAMES.consumerKey, "a".repeat(64)],
    [WEBHOOK_HEADER_NAMES.bodySha256, serialized.body_sha256],
    [WEBHOOK_HEADER_NAMES.signatures, `v1;kid=k1.primary;mac=${macB64}`]
  ]);
  for (const [k, v] of Object.entries(overrides)) {
    if (v === undefined) {
      map.delete(k);
    } else {
      map.set(k, v);
    }
  }
  return Array.from(map.entries());
}

test("Relayquill-Signatures grammar enforces strict v1 entries, distinct kids, and 32-byte unpadded MACs", () => {
  const mac1 = encodeBase64Url(new Uint8Array(32).fill(0x11));
  const mac2 = encodeBase64Url(new Uint8Array(32).fill(0x22));

  const single = parseSignaturesHeader(`v1;kid=k1.primary;mac=${mac1}`);
  assert.equal(single.length, 1);
  assert.equal(single[0].kid, "k1.primary");
  assert.equal(single[0].mac_bytes.byteLength, 32);

  const dual = parseSignaturesHeader(`v1;kid=k2_next-1;mac=${mac2},v1;kid=k1.primary;mac=${mac1}`);
  assert.equal(dual.length, 2);
  assert.equal(
    formatSignaturesHeader([
      { kid: "k2_next-1", mac: mac2 },
      { kid: "k1.primary", mac: mac1 }
    ]),
    `v1;kid=k2_next-1;mac=${mac2},v1;kid=k1.primary;mac=${mac1}`
  );

  // Rejects whitespace, unknown versions, extra params, invalid kids, padding, duplicate kids, >2 entries
  const badHeaders = [
    "",
    `v2;kid=k1;mac=${mac1}`,
    `v1;kid=k1;mac=${mac1};extra=1`,
    `v1;kid=K1;mac=${mac1}`,
    `v1;kid=.k1;mac=${mac1}`,
    `v1;kid=${"a".repeat(65)};mac=${mac1}`,
    `v1;kid=k1;mac=${mac1}=`,
    `v1;kid=k1;mac=${encodeBase64Url(new Uint8Array(31).fill(1))}`,
    `v1;kid=k1;mac=${mac1}, v1;kid=k2;mac=${mac2}`,
    `v1;kid=k1;mac=${mac1},v1;kid=k1;mac=${mac2}`,
    `v1;kid=k1;mac=${mac1},v1;kid=k2;mac=${mac2},v1;kid=k3;mac=${mac1}`
  ];
  for (const raw of badHeaders) {
    assert.throws(() => parseSignaturesHeader(raw), ValidationDomainError, `expected reject: ${raw}`);
  }
});

test("raw single-occurrence header validator rejects duplicate, coalesced, and oversized security headers", () => {
  const basePairs = buildSampleDeliveryRawHeaders();
  const parsed = validateRawWebhookHeaders(basePairs);
  assert.equal(parsed.purpose, "delivery");

  // Flat Node IncomingMessage.rawHeaders format works too
  const flatHeaders = basePairs.flatMap(([k, v]) => [k, v]);
  assert.equal(validateRawWebhookHeaders(flatHeaders).purpose, "delivery");

  // Odd-length flat rawHeaders rejects
  assert.throws(() => validateRawWebhookHeaders([...flatHeaders, "X-Dangling"]), ValidationDomainError);

  // Duplicate protected header (case-insensitive) rejects rather than last-value-wins
  assert.throws(
    () => validateRawWebhookHeaders([...basePairs, ["relayquill-timestamp", "1762000001"]]),
    ValidationDomainError
  );
  assert.throws(
    () => validateRawWebhookHeaders([...basePairs, ["Relayquill-Signatures", basePairs[15][1]]]),
    ValidationDomainError
  );
  assert.throws(
    () => validateRawWebhookHeaders([...basePairs, ["Content-Type", "application/json"]]),
    ValidationDomainError
  );

  // Coalesced values in single-valued security headers reject
  assert.throws(
    () =>
      validateRawWebhookHeaders(
        buildSampleDeliveryRawHeaders({ "Content-Type": "application/json, text/plain" })
      ),
    ValidationDomainError
  );
  assert.throws(
    () =>
      validateRawWebhookHeaders(
        buildSampleDeliveryRawHeaders({ [WEBHOOK_HEADER_NAMES.version]: "1, 1" })
      ),
    ValidationDomainError
  );
  assert.throws(
    () =>
      validateRawWebhookHeaders(
        buildSampleDeliveryRawHeaders({ "Content-Encoding": "gzip" })
      ),
    ValidationDomainError
  );
  assert.throws(
    () => validateRawWebhookHeaders(buildSampleDeliveryRawHeaders({ "Content-Type": undefined })),
    ValidationDomainError
  );

  // Header budget > 8 KiB rejects with PAYLOAD_TOO_LARGE
  assert.throws(
    () => validateRawWebhookHeaders([...basePairs, ["X-Large-Filler", "a".repeat(8200)]]),
    (err) => err instanceof ValidationDomainError && err.code === "PAYLOAD_TOO_LARGE"
  );

  // Endpoint proof response header rejects duplicates and non-zero Content-Length
  const proofB64 = encodeBase64Url(crypto.randomBytes(32));
  assert.equal(
    validateRawEndpointProofResponseHeaders([[WEBHOOK_HEADER_NAMES.endpointProof, proofB64]])
      .proofBytes.byteLength,
    32
  );
  assert.throws(
    () =>
      validateRawEndpointProofResponseHeaders([
        [WEBHOOK_HEADER_NAMES.endpointProof, proofB64],
        [WEBHOOK_HEADER_NAMES.endpointProof, proofB64]
      ]),
    ValidationDomainError
  );
  assert.throws(
    () =>
      validateRawEndpointProofResponseHeaders([
        [WEBHOOK_HEADER_NAMES.endpointProof, proofB64],
        ["Content-Length", "10"]
      ]),
    ValidationDomainError
  );
});

test("exact 25-field length-prefixed preimage encoding matches golden canonical vector layout", () => {
  const vec = WEBHOOK_VECTORS.envelope_v1_echo_vector;
  const serialized = serializeWebhookEnvelope(vec.envelope);
  assert.equal(serialized.byte_count, 552);
  assert.equal(
    serialized.body_sha256,
    "c37a5e1841419d414e907071fda86dc1b66f96e943083a6e503c10e61e227b1b"
  );

  const preimage = encodeWebhookSignaturePreimage({
    purpose: "delivery",
    key_id: "k1.primary",
    external_authority: "hooks.merchant.com:443",
    request_target: "/hooks/relayquill",
    project_id: vec.envelope.project_id,
    event_id: vec.envelope.event_id,
    subscription_id: "00000000-0000-4000-8000-000000000805",
    endpoint_id: "00000000-0000-4000-8000-000000000a05",
    endpoint_version: "1",
    signing_policy_version: "1",
    delivery_id: "00000000-0000-4000-8000-000000001005",
    delivery_generation: "0",
    attempt_id: "00000000-0000-4000-8000-000000000c05",
    timestamp_seconds: "1762000000",
    consumer_event_key: "f".repeat(64),
    wire_body_sha256: serialized.body_sha256,
    raw_wire_body_bytes: serialized.body_bytes
  });

  // Verify exact domain prefix rq.webhook-signature.v1\0 and 25 uint32be-prefixed fields
  const prefixBytes = encodeUtf8Bytes("rq.webhook-signature.v1");
  assert.deepEqual(preimage.subarray(0, prefixBytes.length), prefixBytes);
  assert.equal(preimage[prefixBytes.length], 0x00);

  const view = new DataView(preimage.buffer, preimage.byteOffset, preimage.byteLength);
  let offset = prefixBytes.length + 1;
  const decodedFields = [];
  while (offset < preimage.byteLength) {
    const len = view.getUint32(offset, false);
    offset += 4;
    decodedFields.push(preimage.subarray(offset, offset + len));
    offset += len;
  }
  assert.equal(offset, preimage.byteLength);
  assert.equal(decodedFields.length, 25);
  assert.equal(new TextDecoder().decode(decodedFields[0]), "1");
  assert.equal(new TextDecoder().decode(decodedFields[1]), "delivery");
  assert.equal(new TextDecoder().decode(decodedFields[2]), "k1.primary");
  assert.equal(new TextDecoder().decode(decodedFields[3]), "POST");
  assert.equal(new TextDecoder().decode(decodedFields[4]), "hooks.merchant.com:443");
  assert.equal(new TextDecoder().decode(decodedFields[5]), "/hooks/relayquill");
  assert.equal(decodedFields[15].byteLength, 0); // verification_id absent
  assert.equal(decodedFields[18].byteLength, 0); // ordering_domain_id absent
  assert.equal(decodedFields[21].byteLength, 0); // traceparent absent
  assert.equal(decodedFields[22].byteLength, 0); // tracestate absent
  assert.equal(new TextDecoder().decode(decodedFields[23]), serialized.body_sha256);
  assert.deepEqual(decodedFields[24], serialized.body_bytes);
});

test("key lifecycle states, pending-key rules, bounded dual-signing, and verify cutoffs", () => {
  assert.equal(toKeyLifecycleState("prepared"), "pending");
  assert.equal(toKeyLifecycleState("receiver_verified"), "pending");
  assert.equal(toKeyLifecycleState("overlap"), "overlap");
  assert.deepEqual(ALLOWED_KEY_LIFECYCLE_TRANSITIONS.pending, ["active", "revoked"]);
  assertKeyLifecycleTransition("pending", "active", "k2");
  assertKeyLifecycleTransition("active", "overlap", "k1");
  assert.throws(() => assertKeyLifecycleTransition("retired", "active", "k1"), Error);

  const t0 = Temporal.Instant.from("2026-11-01T12:00:00Z");
  const overlapSignUntil = t0.add({ milliseconds: Number(SIGNING_OVERLAP_MAX_MS - SIGNING_VERIFY_BUFFER_MS) });
  const overlapEndsAt = t0.add({ milliseconds: Number(SIGNING_OVERLAP_MAX_MS) });

  const pendingKey = { keyId: "k2.pending", state: "pending" };
  const activeKey = { keyId: "k2.active", state: "active" };
  const overlapKey = {
    keyId: "k1.old",
    state: "overlap",
    signUntil: overlapSignUntil,
    verifyUntil: overlapEndsAt
  };

  // Pending keys are valid ONLY for endpoint_verification, never for delivery
  assert.equal(checkKeySigningEligibility(pendingKey, "endpoint_verification", t0).eligible, true);
  assert.equal(checkKeyVerificationEligibility(pendingKey, "endpoint_verification", t0).eligible, true);
  assert.equal(checkKeySigningEligibility(pendingKey, "delivery", t0).eligible, false);
  assert.equal(
    checkKeyVerificationEligibility(pendingKey, "delivery", t0).reason,
    "pending_key_forbidden_for_delivery"
  );

  // Bounded dual signing: dual before old.sign_until, single between sign_until and verify_until
  const dualPolicy = {
    signatureMode: "bounded_dual_signature",
    primaryKey: activeKey,
    overlapKey,
    overlapStartedAt: t0,
    overlapEndsAt,
    oldKeySignUntil: overlapSignUntil,
    oldKeyVerifyUntil: overlapEndsAt
  };
  const planAtStart = resolveSigningPlan(dualPolicy, t0);
  assert.equal(planAtStart.dualSigningActive, true);
  assert.deepEqual(planAtStart.signingKeys.map((k) => k.keyId), ["k2.active", "k1.old"]);

  const planInVerifyTail = resolveSigningPlan(dualPolicy, overlapSignUntil.add({ seconds: 1 }));
  assert.equal(planInVerifyTail.dualSigningActive, false);
  assert.deepEqual(planInVerifyTail.signingKeys.map((k) => k.keyId), ["k2.active"]);

  // Verify cutoff: overlap key accepted up to verifyUntil, rejected immediately after
  assert.equal(checkKeyVerificationEligibility(overlapKey, "delivery", overlapEndsAt).eligible, true);
  assert.equal(
    checkKeyVerificationEligibility(overlapKey, "delivery", overlapEndsAt.add({ seconds: 1 })).eligible,
    false
  );

  // Snapshot expiration rejects stale cached key authority
  const expiredSnapshotKey = {
    keyId: "k2.active",
    state: "active",
    snapshotObservedAt: t0,
    snapshotExpiresAt: t0.add({ seconds: 60 })
  };
  assert.equal(
    checkKeyVerificationEligibility(expiredSnapshotKey, "delivery", t0.add({ seconds: 60 })).reason,
    "key_snapshot_expired"
  );
});
