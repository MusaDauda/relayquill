import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import util from "node:util";
import { fileURLToPath } from "node:url";
import { Temporal } from "@js-temporal/polyfill";
import {
  DependencyUnavailableDomainError,
  ValidationDomainError
} from "@relayquill/domain";
import {
  WEBHOOK_HEADER_NAMES,
  computeConsumerEventKeySha256,
  serializeWebhookEnvelope
} from "@relayquill/contracts";
import {
  InMemoryWebhookKeyProvider,
  createMemorySigningKeyHandle,
  encodeWebhookSignaturePreimage,
  serializeEndpointVerificationHeaders,
  serializeWebhookDeliveryHeaders,
  signEndpointProof,
  signEndpointVerificationRequest,
  signReceiverLocalCommitReceipt,
  signWebhookDelivery,
  verifyEndpointProofResponse,
  verifyReceiverLocalCommitReceiptResponse,
  verifyWebhookRequest
} from "../dist/index.js";

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");
const WEBHOOK_VECTORS = JSON.parse(
  fs.readFileSync(path.join(REPO_ROOT, "contracts/webhook-v1/vectors.json"), "utf8")
);

const IDS = Object.freeze({
  projectId: "00000000-0000-4000-8000-000000000105",
  eventId: "00000000-0000-4000-8000-000000000205",
  subscriptionId: "00000000-0000-4000-8000-000000000805",
  endpointId: "00000000-0000-4000-8000-000000000a05",
  deliveryId: "00000000-0000-4000-8000-000000001005",
  attemptId: "00000000-0000-4000-8000-000000000c05",
  verificationId: "00000000-0000-4000-8000-000000000b05",
  receiptId: "00000000-0000-4000-8000-000000000d05",
  orderingDomainId: "00000000-0000-4000-8000-000000000905"
});

test("non-serializing memory key handle redacts inspect/JSON and zeroes on destroy", () => {
  const raw = crypto.randomBytes(32);
  const handle = createMemorySigningKeyHandle(raw, { id: "k1.primary" });
  assert.equal(JSON.stringify(handle), '"[REDACTED]"');
  assert.equal(String(handle), "[REDACTED]");
  assert.ok(!util.inspect(handle).includes(raw.toString("hex")));
  assert.equal(handle.useBytes((buf) => buf.equals(raw)), true);
  handle.destroy();
  assert.equal(handle.isDestroyed, true);
  assert.throws(() => handle.useBytes(() => true), DependencyUnavailableDomainError);
});

test("delivery sign + verify succeeds and rejects changed byte, method, path, header, freshness, and pending key", async () => {
  const vec = WEBHOOK_VECTORS.envelope_v1_echo_vector;
  const serialized = serializeWebhookEnvelope(vec.envelope);
  const now = Temporal.Instant.from("2026-11-01T12:00:00Z");
  const consumerScope = "orders.v1";
  const consumerKey = computeConsumerEventKeySha256({
    project_id: IDS.projectId,
    event_id: IDS.eventId,
    consumer_contract_scope: consumerScope
  });

  const provider = new InMemoryWebhookKeyProvider();
  const activeKeyBytes = crypto.randomBytes(32);
  const pendingKeyBytes = crypto.randomBytes(32);
  const retiredKeyBytes = crypto.randomBytes(32);

  provider.registerKey({
    projectId: IDS.projectId,
    endpointId: IDS.endpointId,
    metadata: { keyId: "k1.active", state: "active" },
    secretBytes: activeKeyBytes
  });
  provider.registerKey({
    projectId: IDS.projectId,
    endpointId: IDS.endpointId,
    metadata: { keyId: "k2.pending", state: "pending" },
    secretBytes: pendingKeyBytes
  });
  provider.registerKey({
    projectId: IDS.projectId,
    endpointId: IDS.endpointId,
    metadata: { keyId: "k0.retired", state: "retired" },
    secretBytes: retiredKeyBytes
  });

  const signed = await signWebhookDelivery({
    externalAuthority: "hooks.merchant.com:443",
    requestTarget: "/hooks/relayquill",
    projectId: IDS.projectId,
    eventId: IDS.eventId,
    subscriptionId: IDS.subscriptionId,
    endpointId: IDS.endpointId,
    endpointVersion: "1",
    signingPolicyVersion: "1",
    deliveryId: IDS.deliveryId,
    deliveryGeneration: "0",
    attemptId: IDS.attemptId,
    consumerEventKey: consumerKey,
    rawWireBodyBytes: serialized.body_bytes,
    now,
    signingKeys: [{ keyId: "k1.active", state: "active" }],
    getKeyMaterial: provider.asResolver()
  });

  const baseVerifyInput = {
    method: "POST",
    rawHeaders: signed.rawHeaderPairs,
    rawBodyBytes: serialized.body_bytes,
    expectedTarget: {
      externalAuthority: "hooks.merchant.com:443",
      requestTarget: "/hooks/relayquill",
      observedRequestTarget: "/hooks/relayquill"
    },
    expectedContext: {
      projectId: IDS.projectId,
      endpointId: IDS.endpointId,
      consumerContractScope: consumerScope
    },
    keyProvider: (q) => provider.resolveKey(q),
    now
  };

  const okRes = await verifyWebhookRequest(baseVerifyInput);
  assert.equal(okRes.ok, true);
  assert.equal(okRes.verifiedKeyId, "k1.active");

  // 1. Changed byte in raw body
  const tamperedBody = new Uint8Array(serialized.body_bytes);
  tamperedBody[tamperedBody.length - 5] ^= 0x01;
  const changedByteRes = await verifyWebhookRequest({ ...baseVerifyInput, rawBodyBytes: tamperedBody });
  assert.equal(changedByteRes.ok, false);
  assert.equal(changedByteRes.safeReason, "body_hash_mismatch");

  // 2. Method mismatch
  const badMethodRes = await verifyWebhookRequest({ ...baseVerifyInput, method: "PUT" });
  assert.equal(badMethodRes.ok, false);
  assert.equal(badMethodRes.safeReason, "invalid_method");

  // 3. Target path & authority mismatch
  const badPathRes = await verifyWebhookRequest({
    ...baseVerifyInput,
    expectedTarget: {
      externalAuthority: "hooks.merchant.com:443",
      requestTarget: "/hooks/other"
    }
  });
  assert.equal(badPathRes.ok, false);
  assert.equal(badPathRes.safeReason, "mac_mismatch");

  const badObservedRouteRes = await verifyWebhookRequest({
    ...baseVerifyInput,
    expectedTarget: {
      externalAuthority: "hooks.merchant.com:443",
      requestTarget: "/hooks/relayquill",
      observedRequestTarget: "/hooks/relayquill/../admin"
    }
  });
  assert.equal(badObservedRouteRes.ok, false);
  assert.equal(badObservedRouteRes.safeReason, "target_mismatch");

  // 4. Duplicate header
  const dupHeaderRes = await verifyWebhookRequest({
    ...baseVerifyInput,
    rawHeaders: [...signed.rawHeaderPairs, [WEBHOOK_HEADER_NAMES.signatures, signed.signaturesHeader]]
  });
  assert.equal(dupHeaderRes.ok, false);
  assert.equal(dupHeaderRes.safeReason, "invalid_headers_or_duplicate");

  // 5. Freshness bounds (-300s <= ts <= +30s)
  assert.equal(
    (await verifyWebhookRequest({ ...baseVerifyInput, now: now.add({ seconds: 300 }) })).ok,
    true
  );
  assert.equal(
    (await verifyWebhookRequest({ ...baseVerifyInput, now: now.add({ seconds: 301 }) })).safeReason,
    "timestamp_stale_or_future"
  );
  assert.equal(
    (await verifyWebhookRequest({ ...baseVerifyInput, now: now.subtract({ seconds: 30 }) })).ok,
    true
  );
  assert.equal(
    (await verifyWebhookRequest({ ...baseVerifyInput, now: now.subtract({ seconds: 31 }) })).safeReason,
    "timestamp_stale_or_future"
  );

  // 6. Consumer key mismatch (different scope)
  const wrongScopeRes = await verifyWebhookRequest({
    ...baseVerifyInput,
    expectedContext: {
      projectId: IDS.projectId,
      endpointId: IDS.endpointId,
      consumerContractScope: "billing.v1"
    }
  });
  assert.equal(wrongScopeRes.ok, false);
  assert.equal(wrongScopeRes.safeReason, "consumer_key_mismatch");

  // 7. Pending key cannot sign ordinary delivery, and even a valid mathematical MAC under a pending key is rejected!
  await assert.rejects(
    () =>
      signWebhookDelivery({
        externalAuthority: "hooks.merchant.com:443",
        requestTarget: "/hooks/relayquill",
        projectId: IDS.projectId,
        eventId: IDS.eventId,
        subscriptionId: IDS.subscriptionId,
        endpointId: IDS.endpointId,
        endpointVersion: "1",
        signingPolicyVersion: "1",
        deliveryId: IDS.deliveryId,
        deliveryGeneration: "0",
        attemptId: IDS.attemptId,
        consumerEventKey: consumerKey,
        rawWireBodyBytes: serialized.body_bytes,
        now,
        signingKeys: [{ keyId: "k2.pending", state: "pending" }],
        getKeyMaterial: provider.asResolver()
      }),
    Error
  );

  // Craft a mathematically valid signature using k2.pending key material (as if active on sender, pending on receiver)
  const senderSpoofedProvider = new InMemoryWebhookKeyProvider();
  senderSpoofedProvider.registerKey({
    projectId: IDS.projectId,
    endpointId: IDS.endpointId,
    metadata: { keyId: "k2.pending", state: "active" },
    secretBytes: pendingKeyBytes
  });
  const pendingSigned = await signWebhookDelivery({
    externalAuthority: "hooks.merchant.com:443",
    requestTarget: "/hooks/relayquill",
    projectId: IDS.projectId,
    eventId: IDS.eventId,
    subscriptionId: IDS.subscriptionId,
    endpointId: IDS.endpointId,
    endpointVersion: "1",
    signingPolicyVersion: "1",
    deliveryId: IDS.deliveryId,
    deliveryGeneration: "0",
    attemptId: IDS.attemptId,
    consumerEventKey: consumerKey,
    rawWireBodyBytes: serialized.body_bytes,
    now,
    signingKeys: [{ keyId: "k2.pending", state: "active" }],
    getKeyMaterial: senderSpoofedProvider.asResolver()
  });
  const pendingDeliveryVerify = await verifyWebhookRequest({
    ...baseVerifyInput,
    rawHeaders: pendingSigned.rawHeaderPairs
  });
  assert.equal(pendingDeliveryVerify.ok, false);
  assert.equal(pendingDeliveryVerify.safeReason, "pending_key_forbidden_for_delivery");

  // 8. Retired key mathematically valid MAC still rejects
  const retiredSpoofedProvider = new InMemoryWebhookKeyProvider();
  retiredSpoofedProvider.registerKey({
    projectId: IDS.projectId,
    endpointId: IDS.endpointId,
    metadata: { keyId: "k0.retired", state: "active" },
    secretBytes: retiredKeyBytes
  });
  const retiredSigned = await signWebhookDelivery({
    externalAuthority: "hooks.merchant.com:443",
    requestTarget: "/hooks/relayquill",
    projectId: IDS.projectId,
    eventId: IDS.eventId,
    subscriptionId: IDS.subscriptionId,
    endpointId: IDS.endpointId,
    endpointVersion: "1",
    signingPolicyVersion: "1",
    deliveryId: IDS.deliveryId,
    deliveryGeneration: "0",
    attemptId: IDS.attemptId,
    consumerEventKey: consumerKey,
    rawWireBodyBytes: serialized.body_bytes,
    now,
    signingKeys: [{ keyId: "k0.retired", state: "active" }],
    getKeyMaterial: retiredSpoofedProvider.asResolver()
  });
  const retiredVerify = await verifyWebhookRequest({
    ...baseVerifyInput,
    rawHeaders: retiredSigned.rawHeaderPairs
  });
  assert.equal(retiredVerify.ok, false);
  assert.equal(retiredVerify.safeReason, "key_retired_or_expired");

  provider.destroy();
  senderSpoofedProvider.destroy();
  retiredSpoofedProvider.destroy();
});

test("endpoint verification request, 204 Endpoint-Proof, and receiver_local_commit_v1 receipt MAC", async () => {
  const now = Temporal.Instant.from("2026-11-01T12:00:00Z");
  const pendingMeta = { keyId: "k2.pending", state: "pending" };
  const activeMeta = { keyId: "k1.active", state: "active" };
  const provider = new InMemoryWebhookKeyProvider();
  provider.registerKey({
    projectId: IDS.projectId,
    endpointId: IDS.endpointId,
    metadata: pendingMeta,
    secretBytes: crypto.randomBytes(32)
  });
  provider.registerKey({
    projectId: IDS.projectId,
    endpointId: IDS.endpointId,
    metadata: activeMeta,
    secretBytes: crypto.randomBytes(32)
  });

  const evVec = WEBHOOK_VECTORS.endpoint_verification_vector;
  const evBody = { ...evVec.body, key_id: "k2.pending" };

  const signedEv = await signEndpointVerificationRequest({
    externalAuthority: "hooks.merchant.com:443",
    requestTarget: "/hooks/relayquill",
    projectId: IDS.projectId,
    endpointId: IDS.endpointId,
    endpointVersion: "1",
    attemptId: IDS.attemptId,
    verificationId: evBody.verification_id,
    body: evBody,
    signingKey: pendingMeta,
    now,
    getKeyMaterial: provider.asResolver()
  });
  assert.equal(signedEv.headers[WEBHOOK_HEADER_NAMES.signingPolicy], "0");

  const verifiedEv = await verifyWebhookRequest({
    method: "POST",
    rawHeaders: signedEv.rawHeaderPairs,
    rawBodyBytes: signedEv.bodyBytes,
    expectedTarget: {
      externalAuthority: "hooks.merchant.com:443",
      requestTarget: "/hooks/relayquill"
    },
    expectedContext: {
      projectId: IDS.projectId,
      endpointId: IDS.endpointId
    },
    keyProvider: (q) => provider.resolveKey(q),
    now
  });
  assert.equal(verifiedEv.ok, true);
  assert.equal(verifiedEv.purpose, "endpoint_verification");

  // Receiver signs 204 Relayquill-Endpoint-Proof with pending key
  const proofHandle = provider.resolveKey({
    projectId: IDS.projectId,
    endpointId: IDS.endpointId,
    keyId: "k2.pending"
  }).handle;
  const signedProof = signEndpointProof({
    verificationIntentId: evBody.verification_id,
    endpointId: IDS.endpointId,
    endpointVersion: "1",
    configurationSha256: evBody.configuration_sha256,
    keyId: "k2.pending",
    publicNonce: evBody.public_nonce,
    verificationAttemptId: IDS.attemptId,
    requestTimestampSeconds: signedEv.timestampSeconds,
    requestWireBodySha256: signedEv.bodySha256,
    keyHandle: proofHandle,
    keyMetadata: pendingMeta,
    now
  });

  const proofOk = verifyEndpointProofResponse({
    statusCode: 204,
    rawHeaders: [[signedProof.headerName, signedProof.headerValue]],
    rawBodyBytes: new Uint8Array(0),
    expected: {
      verificationIntentId: evBody.verification_id,
      endpointId: IDS.endpointId,
      endpointVersion: "1",
      configurationSha256: evBody.configuration_sha256,
      keyId: "k2.pending",
      publicNonce: evBody.public_nonce,
      verificationAttemptId: IDS.attemptId,
      requestTimestampSeconds: signedEv.timestampSeconds,
      requestWireBodySha256: signedEv.bodySha256,
      intentExpiresAt: now.add({ minutes: 2 })
    },
    keyHandle: proofHandle,
    keyMetadata: pendingMeta,
    now
  });
  assert.equal(proofOk.ok, true);
  assert.equal(proofOk.proofSha256, signedProof.proofSha256);

  // Proof cannot be replayed against a different attemptId or non-204 status
  const proofReplay = verifyEndpointProofResponse({
    statusCode: 204,
    rawHeaders: [[signedProof.headerName, signedProof.headerValue]],
    expected: {
      verificationIntentId: evBody.verification_id,
      endpointId: IDS.endpointId,
      endpointVersion: "1",
      configurationSha256: evBody.configuration_sha256,
      keyId: "k2.pending",
      publicNonce: evBody.public_nonce,
      verificationAttemptId: "00000000-0000-4000-8000-000000000c99",
      requestTimestampSeconds: signedEv.timestampSeconds,
      requestWireBodySha256: signedEv.bodySha256,
      intentExpiresAt: now.add({ minutes: 2 })
    },
    keyHandle: proofHandle,
    keyMetadata: pendingMeta,
    now
  });
  assert.equal(proofReplay.ok, false);
  assert.equal(proofReplay.safeReason, "proof_mac_mismatch");
  proofHandle.destroy();

  // Receiver local commit v1 receipt MAC sign + verify
  const vec = WEBHOOK_VECTORS.envelope_v1_echo_vector;
  const serialized = serializeWebhookEnvelope(vec.envelope);
  const consumerKey = computeConsumerEventKeySha256({
    project_id: IDS.projectId,
    event_id: IDS.eventId,
    consumer_contract_scope: "orders.v1"
  });
  const activeHandle = provider.resolveKey({
    projectId: IDS.projectId,
    endpointId: IDS.endpointId,
    keyId: "k1.active"
  }).handle;

  const signedReceipt = signReceiverLocalCommitReceipt({
    keyId: "k1.active",
    projectId: IDS.projectId,
    eventId: IDS.eventId,
    consumerEventKey: consumerKey,
    originalFactsSha256: vec.original_facts_sha256,
    receiptId: IDS.receiptId,
    committedAt: "2026-11-01T12:00:02.123456Z",
    deliveryAttemptId: IDS.attemptId,
    requestWireBodySha256: serialized.body_sha256,
    keyHandle: activeHandle,
    keyMetadata: activeMeta,
    now
  });

  const receiptOk = await verifyReceiverLocalCommitReceiptResponse({
    statusCode: 200,
    rawHeaders: [["Content-Type", "application/json"]],
    rawBodyBytes: signedReceipt.bodyBytes,
    receiptProfile: "receiver_local_commit_v1",
    expected: {
      projectId: IDS.projectId,
      eventId: IDS.eventId,
      consumerEventKey: consumerKey,
      originalFactsSha256: vec.original_facts_sha256,
      deliveryAttemptId: IDS.attemptId,
      requestWireBodySha256: serialized.body_sha256,
      allowedKeyIds: new Set(["k1.active"])
    },
    resolveVerificationKey: (kid) => provider.resolveKey({
      projectId: IDS.projectId,
      endpointId: IDS.endpointId,
      keyId: kid
    }),
    now
  });
  assert.equal(receiptOk.ok, true);
  assert.equal(receiptOk.verificationState, "verified_supported");
  assert.equal("mac" in receiptOk.safeReceiptFacts, false);

  // Rejects receipt bound to wrong attempt or disallowed keyId
  const wrongKeyReceipt = await verifyReceiverLocalCommitReceiptResponse({
    statusCode: 200,
    rawHeaders: [["Content-Type", "application/json"]],
    rawBodyBytes: signedReceipt.bodyBytes,
    receiptProfile: "receiver_local_commit_v1",
    expected: {
      projectId: IDS.projectId,
      eventId: IDS.eventId,
      consumerEventKey: consumerKey,
      originalFactsSha256: vec.original_facts_sha256,
      deliveryAttemptId: IDS.attemptId,
      requestWireBodySha256: serialized.body_sha256,
      allowedKeyIds: new Set(["k9.other"])
    },
    resolveVerificationKey: (kid) => provider.resolveKey({
      projectId: IDS.projectId,
      endpointId: IDS.endpointId,
      keyId: kid
    }),
    now
  });
  assert.equal(wrongKeyReceipt.ok, false);
  assert.equal(wrongKeyReceipt.safeReason, "key_not_permitted_for_request");

  activeHandle.destroy();
  provider.destroy();
});

test("traceparent and tracestate normalization enforces signing and header serialization parity", async () => {
  const vec = WEBHOOK_VECTORS.envelope_v1_echo_vector;
  const serialized = serializeWebhookEnvelope(vec.envelope);
  const now = Temporal.Instant.from("2026-11-01T12:00:00Z");
  const consumerScope = "orders.v1";
  const consumerKey = computeConsumerEventKeySha256({
    project_id: IDS.projectId,
    event_id: IDS.eventId,
    consumer_contract_scope: consumerScope
  });

  const provider = new InMemoryWebhookKeyProvider();
  provider.registerKey({
    projectId: IDS.projectId,
    endpointId: IDS.endpointId,
    metadata: { keyId: "k1.active", state: "active" },
    secretBytes: crypto.randomBytes(32)
  });

  const validTraceparent = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
  const validTracestate = "vendor=1,relay=ok";

  const baseSignInput = {
    externalAuthority: "hooks.example.org:443",
    requestTarget: "/v1/relayquill",
    projectId: IDS.projectId,
    eventId: IDS.eventId,
    subscriptionId: IDS.subscriptionId,
    endpointId: IDS.endpointId,
    endpointVersion: "1",
    signingPolicyVersion: "1",
    deliveryId: IDS.deliveryId,
    deliveryGeneration: "1",
    attemptId: IDS.attemptId,
    consumerEventKey: consumerKey,
    rawWireBodyBytes: serialized.body_bytes,
    signingKeys: [{ keyId: "k1.active", state: "active" }],
    now,
    getKeyMaterial: (req) => provider.resolveKey(req)
  };

  // 1. Both traceparent and tracestate present -> both emitted and verified
  const signedWithBoth = await signWebhookDelivery({
    ...baseSignInput,
    traceparent: validTraceparent,
    tracestate: validTracestate
  });
  assert.equal(signedWithBoth.headers[WEBHOOK_HEADER_NAMES.traceparent], validTraceparent);
  assert.equal(signedWithBoth.headers[WEBHOOK_HEADER_NAMES.tracestate], validTracestate);
  const verifiedBoth = await verifyWebhookRequest({
    method: "POST",
    rawHeaders: signedWithBoth.rawHeaderPairs,
    rawBodyBytes: serialized.body_bytes,
    expectedTarget: {
      externalAuthority: "hooks.example.org:443",
      requestTarget: "/v1/relayquill"
    },
    expectedContext: {
      projectId: IDS.projectId,
      endpointId: IDS.endpointId,
      consumerContractScope: consumerScope
    },
    keyProvider: (req) => provider.resolveKey(req),
    now
  });
  assert.equal(verifiedBoth.ok, true);

  // 2. Empty tracestate ("") with valid traceparent is normalized to undefined (no throw, verifies cleanly)
  const signedEmptyState = await signWebhookDelivery({
    ...baseSignInput,
    traceparent: validTraceparent,
    tracestate: ""
  });
  assert.equal(signedEmptyState.headers[WEBHOOK_HEADER_NAMES.traceparent], validTraceparent);
  assert.equal(WEBHOOK_HEADER_NAMES.tracestate in signedEmptyState.headers, false);
  const verifiedEmptyState = await verifyWebhookRequest({
    method: "POST",
    rawHeaders: signedEmptyState.rawHeaderPairs,
    rawBodyBytes: serialized.body_bytes,
    expectedTarget: {
      externalAuthority: "hooks.example.org:443",
      requestTarget: "/v1/relayquill"
    },
    expectedContext: {
      projectId: IDS.projectId,
      endpointId: IDS.endpointId,
      consumerContractScope: consumerScope
    },
    keyProvider: (req) => provider.resolveKey(req),
    now
  });
  assert.equal(verifiedEmptyState.ok, true);

  // 3. tracestate without traceparent is rejected identically in signing and header serialization
  await assert.rejects(
    () =>
      signWebhookDelivery({
        ...baseSignInput,
        traceparent: undefined,
        tracestate: validTracestate
      }),
    ValidationDomainError
  );
  await assert.rejects(
    () =>
      signWebhookDelivery({
        ...baseSignInput,
        traceparent: "",
        tracestate: validTracestate
      }),
    ValidationDomainError
  );
  assert.throws(
    () =>
      serializeWebhookDeliveryHeaders({
        projectId: IDS.projectId,
        eventId: IDS.eventId,
        subscriptionId: IDS.subscriptionId,
        endpointId: IDS.endpointId,
        endpointVersion: "1",
        deliveryId: IDS.deliveryId,
        deliveryGeneration: "1",
        attemptId: IDS.attemptId,
        signingPolicyVersion: "1",
        timestampSeconds: "1793534400",
        consumerEventKey: consumerKey,
        bodySha256: serialized.body_sha256,
        signaturesHeader: signedWithBoth.signaturesHeader,
        traceparent: undefined,
        tracestate: validTracestate
      }),
    ValidationDomainError
  );

  // 4. Endpoint verification request also enforces traceparent/tracestate parity
  const verificationBody = {
    ...WEBHOOK_VECTORS.endpoint_verification_vector.body,
    key_id: "k1.active"
  };
  const signedVerifyEmptyState = await signEndpointVerificationRequest({
    externalAuthority: "hooks.example.org:443",
    requestTarget: "/v1/relayquill",
    projectId: IDS.projectId,
    endpointId: IDS.endpointId,
    endpointVersion: "1",
    attemptId: IDS.attemptId,
    verificationId: verificationBody.verification_id,
    body: verificationBody,
    signingKey: { keyId: "k1.active", state: "active" },
    traceparent: validTraceparent,
    tracestate: "",
    now,
    getKeyMaterial: (req) => provider.resolveKey(req)
  });
  assert.equal(signedVerifyEmptyState.headers[WEBHOOK_HEADER_NAMES.traceparent], validTraceparent);
  assert.equal(WEBHOOK_HEADER_NAMES.tracestate in signedVerifyEmptyState.headers, false);
  const verifiedEndpointEmptyState = await verifyWebhookRequest({
    method: "POST",
    rawHeaders: signedVerifyEmptyState.rawHeaderPairs,
    rawBodyBytes: signedVerifyEmptyState.bodyBytes,
    expectedTarget: {
      externalAuthority: "hooks.example.org:443",
      requestTarget: "/v1/relayquill"
    },
    expectedContext: {
      projectId: IDS.projectId,
      endpointId: IDS.endpointId
    },
    keyProvider: (req) => provider.resolveKey(req),
    now
  });
  assert.equal(verifiedEndpointEmptyState.ok, true);

  await assert.rejects(
    () =>
      signEndpointVerificationRequest({
        externalAuthority: "hooks.example.org:443",
        requestTarget: "/v1/relayquill",
        projectId: IDS.projectId,
        endpointId: IDS.endpointId,
        endpointVersion: "1",
        attemptId: IDS.attemptId,
        verificationId: verificationBody.verification_id,
        body: verificationBody,
        signingKey: { keyId: "k1.active", state: "active" },
        traceparent: undefined,
        tracestate: validTracestate,
        now,
        getKeyMaterial: (req) => provider.resolveKey(req)
      }),
    ValidationDomainError
  );
  assert.throws(
    () =>
      serializeEndpointVerificationHeaders({
        verificationId: verificationBody.verification_id,
        projectId: IDS.projectId,
        endpointId: IDS.endpointId,
        endpointVersion: "1",
        attemptId: IDS.attemptId,
        timestampSeconds: "1793534400",
        bodySha256: serialized.body_sha256,
        signaturesHeader: signedVerifyEmptyState.signaturesHeader,
        traceparent: undefined,
        tracestate: validTracestate
      }),
    ValidationDomainError
  );

  // 5. encodeWebhookSignaturePreimage and verifyWebhookRequest also enforce traceparent/tracestate parity
  const basePreimageInput = {
    purpose: "delivery",
    key_id: "k1.active",
    external_authority: "hooks.example.org:443",
    request_target: "/v1/relayquill",
    project_id: IDS.projectId,
    event_id: IDS.eventId,
    subscription_id: IDS.subscriptionId,
    endpoint_id: IDS.endpointId,
    endpoint_version: "1",
    signing_policy_version: "1",
    delivery_id: IDS.deliveryId,
    delivery_generation: "1",
    attempt_id: IDS.attemptId,
    timestamp_seconds: "1793534400",
    consumer_event_key: consumerKey,
    wire_body_sha256: serialized.body_sha256,
    raw_wire_body_bytes: serialized.body_bytes
  };
  assert.deepEqual(
    encodeWebhookSignaturePreimage({
      ...basePreimageInput,
      traceparent: validTraceparent,
      tracestate: ""
    }),
    encodeWebhookSignaturePreimage({
      ...basePreimageInput,
      traceparent: validTraceparent
    })
  );
  assert.throws(
    () =>
      encodeWebhookSignaturePreimage({
        ...basePreimageInput,
        traceparent: undefined,
        tracestate: validTracestate
      }),
    ValidationDomainError
  );
  assert.throws(
    () =>
      encodeWebhookSignaturePreimage({
        ...basePreimageInput,
        traceparent: "",
        tracestate: validTracestate
      }),
    ValidationDomainError
  );

  const rawWithoutTraceparent = [
    ...signedEmptyState.rawHeaderPairs.filter(
      ([name]) => name.toLowerCase() !== WEBHOOK_HEADER_NAMES.traceparent
    ),
    [WEBHOOK_HEADER_NAMES.tracestate, validTracestate]
  ];
  const rejectedVerifyNoParent = await verifyWebhookRequest({
    method: "POST",
    rawHeaders: rawWithoutTraceparent,
    rawBodyBytes: serialized.body_bytes,
    expectedTarget: {
      externalAuthority: "hooks.example.org:443",
      requestTarget: "/v1/relayquill"
    },
    expectedContext: {
      projectId: IDS.projectId,
      endpointId: IDS.endpointId,
      consumerContractScope: consumerScope
    },
    keyProvider: (req) => provider.resolveKey(req),
    now
  });
  assert.equal(rejectedVerifyNoParent.ok, false);
  assert.equal(rejectedVerifyNoParent.httpStatus, 400);
  assert.equal(rejectedVerifyNoParent.safeReason, "invalid_headers_or_duplicate");

  provider.destroy();
});
