import { describe, it } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { Readable } from "node:stream";
import { Temporal } from "@js-temporal/polyfill";
import {
  WEBHOOK_HEADER_NAMES,
  WEBHOOK_RECEIPT_MAX_BODY_BYTES,
  computeConsumerEventKeySha256,
  encodeBase64,
  encodeBase64Url,
  serializeEndpointVerificationBody,
  serializeWebhookEnvelope
} from "@relayquill/contracts";
import {
  signEndpointVerificationRequest,
  signWebhookDelivery,
  verifyEndpointProofResponse,
  verifyReceiverLocalCommitReceiptResponse
} from "@relayquill/signing";
import {
  InMemoryReceiverInboxAdapter,
  InMemoryReceiverKeyProvider,
  ReceiverAuthError,
  ReceiverConflictError,
  ReceiverExpiredError,
  ReceiverValidationError,
  assertWebhookRequestVerified,
  createReceiverKeyHandle,
  createSignedDeliveryReceipt,
  executeIdempotentDelivery,
  handleEndpointProofChallenge,
  readBoundedRawWebhookRequest,
  verifyWebhookRequest
} from "../dist/index.js";

const PROJECT_ID = "11111111-1111-4111-8111-111111111111";
const ENDPOINT_ID = "22222222-2222-4222-8222-222222222222";
const SUBSCRIPTION_ID = "33333333-3333-4333-8333-333333333333";
const EVENT_TYPE_ID = "44444444-4444-4444-8444-444444444444";
const ORDERING_DOMAIN_ID = "55555555-5555-4555-8555-555555555555";
const KEY_ID = "k_primary_1";
const AUTHORITY = "hooks.receiver.example.com:443";
const REQUEST_TARGET = "/webhooks/relayquill";
const SECRET_BYTES = crypto.createHash("sha256").update("relayquill-test-secret-v1").digest();
const NOW = Temporal.Instant.from("2026-11-20T12:00:00.000000Z");

function setupProvider(secret = SECRET_BYTES, keyId = KEY_ID) {
  const provider = new InMemoryReceiverKeyProvider();
  const metadata = {
    keyId,
    state: "active",
    projectId: PROJECT_ID,
    endpointId: ENDPOINT_ID
  };
  provider.registerKey({
    projectId: PROJECT_ID,
    endpointId: ENDPOINT_ID,
    metadata,
    secretBytes: secret
  });
  return { provider, metadata };
}

function buildDeliveryFixture({
  eventId = "66666666-6666-4666-8666-666666666666",
  deliveryId = "77777777-7777-4777-8777-777777777777",
  attemptId = "88888888-8888-4888-8888-888888888888",
  deliveryGeneration = "0",
  rawContentText = '{"orderId":"ord-42","total":   1200}',
  ordering = undefined,
  now = NOW
} = {}) {
  const contentBytes = new TextEncoder().encode(rawContentText);
  const contentSha256 = crypto.createHash("sha256").update(contentBytes).digest("hex");
  const serialized = serializeWebhookEnvelope({
    envelope_version: 1,
    representation_version: 1,
    project_id: PROJECT_ID,
    event_id: eventId,
    project_event_sequence: "1",
    event_type_id: EVENT_TYPE_ID,
    event_type: "order.created",
    event_schema_version: 1,
    admitted_at: "2026-11-20T11:59:59.000000Z",
    producer_event_time: null,
    content: {
      media_type: "application/json",
      encoding: "base64",
      byte_count: contentBytes.byteLength,
      sha256: contentSha256,
      data: encodeBase64(contentBytes)
    }
  });
  const consumerEventKey = computeConsumerEventKeySha256({
    project_id: PROJECT_ID,
    event_id: eventId,
    consumer_contract_scope: "default"
  });

  return {
    eventId,
    deliveryId,
    attemptId,
    deliveryGeneration,
    consumerEventKey,
    serialized,
    ordering,
    now
  };
}

describe("@relayquill/receiver-sdk raw stream & signature verification", () => {
  it("reads bounded raw webhook requests without altering body bytes or coercing duplicate headers", async () => {
    const rawBodyText = '{ "preserved":  true, "whitespace":   [1, 2] }';
    const rawBodyBytes = new TextEncoder().encode(rawBodyText);
    const req = Readable.from([rawBodyBytes.subarray(0, 12), rawBodyBytes.subarray(12)]);
    Object.assign(req, {
      method: "POST",
      url: REQUEST_TARGET,
      rawHeaders: [
        "Content-Type",
        "application/json",
        "X-Custom",
        "alpha",
        "x-custom",
        "beta"
      ]
    });

    const bounded = await readBoundedRawWebhookRequest(req);
    assert.equal(bounded.method, "POST");
    assert.equal(bounded.rawUrl, REQUEST_TARGET);
    assert.equal(bounded.rawHeaders.length, 3);
    assert.equal(new TextDecoder().decode(bounded.rawBodyBytes), rawBodyText);
    assert.equal(
      bounded.bodySha256,
      crypto.createHash("sha256").update(rawBodyBytes).digest("hex")
    );

    // Oversized header rejection before buffering body
    let bodyPulled = false;
    const hugeHeadersReq = {
      method: "POST",
      rawHeaders: [["X-Huge", "A".repeat(200)]],
      body: {
        async *[Symbol.asyncIterator]() {
          bodyPulled = true;
          yield Buffer.from("{}");
        }
      }
    };
    await assert.rejects(
      () => readBoundedRawWebhookRequest(hugeHeadersReq, { maxHeaderBytes: 64 }),
      (err) => err instanceof ReceiverValidationError && err.httpStatus === 413 && err.code === "PAYLOAD_TOO_LARGE"
    );
    assert.equal(bodyPulled, false);

    // Oversized streaming body rejection destroys stream early
    let destroyed = false;
    const oversizedStream = new Readable({
      read() {
        this.push(Buffer.alloc(128, 0x61));
      },
      destroy(err, cb) {
        destroyed = true;
        cb(err);
      }
    });
    await assert.rejects(
      () =>
        readBoundedRawWebhookRequest(
          { method: "POST", rawHeaders: [["Content-Type", "application/json"]], body: oversizedStream },
          { maxBodyBytes: 100 }
        ),
      (err) => err instanceof ReceiverValidationError && err.httpStatus === 413 && err.code === "PAYLOAD_TOO_LARGE"
    );
    assert.equal(destroyed, true);

    // Empty body rejection
    await assert.rejects(
      () => readBoundedRawWebhookRequest({ method: "POST", rawHeaders: [], body: new Uint8Array(0) }),
      (err) => err instanceof ReceiverValidationError && err.httpStatus === 400
    );
  });

  it("verifies signed webhook deliveries and maps failures to typed errors", async () => {
    const { provider, metadata } = setupProvider();
    const fixture = buildDeliveryFixture();
    const signed = await signWebhookDelivery({
      externalAuthority: AUTHORITY,
      requestTarget: REQUEST_TARGET,
      projectId: PROJECT_ID,
      eventId: fixture.eventId,
      subscriptionId: SUBSCRIPTION_ID,
      endpointId: ENDPOINT_ID,
      endpointVersion: "1",
      signingPolicyVersion: "1",
      deliveryId: fixture.deliveryId,
      deliveryGeneration: fixture.deliveryGeneration,
      attemptId: fixture.attemptId,
      consumerEventKey: fixture.consumerEventKey,
      rawWireBodyBytes: fixture.serialized.body_bytes,
      now: NOW,
      signingKeys: [metadata],
      getKeyMaterial: provider.asSigningKeyResolver()
    });

    const rawReq = await readBoundedRawWebhookRequest({
      method: "POST",
      url: REQUEST_TARGET,
      rawHeaders: signed.rawHeaderPairs,
      body: fixture.serialized.body_bytes
    });

    const verified = await assertWebhookRequestVerified({
      request: rawReq,
      expectedTarget: {
        externalAuthority: AUTHORITY,
        requestTarget: REQUEST_TARGET,
        observedAuthority: AUTHORITY,
        observedRequestTarget: REQUEST_TARGET
      },
      expectedContext: {
        projectId: PROJECT_ID,
        endpointId: ENDPOINT_ID,
        subscriptionId: SUBSCRIPTION_ID,
        consumerContractScope: "default"
      },
      keyProvider: provider,
      now: NOW
    });
    assert.equal(verified.ok, true);
    assert.equal(verified.purpose, "delivery");
    assert.equal(verified.verifiedKeyId, KEY_ID);

    // Tampered body -> ReceiverAuthError
    const tamperedBytes = Uint8Array.from(fixture.serialized.body_bytes);
    tamperedBytes[tamperedBytes.length - 2] = 0x20;
    await assert.rejects(
      () =>
        assertWebhookRequestVerified({
          method: "POST",
          rawHeaders: signed.rawHeaderPairs,
          rawBodyBytes: tamperedBytes,
          expectedTarget: { externalAuthority: AUTHORITY, requestTarget: REQUEST_TARGET },
          expectedContext: { projectId: PROJECT_ID, endpointId: ENDPOINT_ID },
          keyProvider: provider,
          now: NOW
        }),
      (err) => err instanceof ReceiverAuthError && err.httpStatus === 401
    );

    // Stale timestamp -> ReceiverAuthError (timestamp_stale_or_future)
    await assert.rejects(
      () =>
        assertWebhookRequestVerified({
          request: rawReq,
          expectedTarget: { externalAuthority: AUTHORITY, requestTarget: REQUEST_TARGET },
          expectedContext: { projectId: PROJECT_ID, endpointId: ENDPOINT_ID },
          keyProvider: provider,
          now: Temporal.Instant.fromEpochMilliseconds(NOW.epochMilliseconds + 600_000)
        }),
      (err) => err instanceof ReceiverAuthError && err.httpStatus === 401 && err.safeReason === "timestamp_stale_or_future"
    );

    // Expired key snapshot -> ReceiverExpiredError (EXPIRED)
    provider.updateKeyMetadata({
      projectId: PROJECT_ID,
      endpointId: ENDPOINT_ID,
      metadata: {
        ...metadata,
        snapshotExpiresAt: Temporal.Instant.fromEpochMilliseconds(NOW.epochMilliseconds - 1_000)
      }
    });
    await assert.rejects(
      () =>
        assertWebhookRequestVerified({
          request: rawReq,
          expectedTarget: { externalAuthority: AUTHORITY, requestTarget: REQUEST_TARGET },
          expectedContext: { projectId: PROJECT_ID, endpointId: ENDPOINT_ID },
          keyProvider: provider,
          now: NOW
        }),
      (err) => err instanceof ReceiverExpiredError && err.httpStatus === 401 && err.code === "EXPIRED"
    );
    provider.updateKeyMetadata({ projectId: PROJECT_ID, endpointId: ENDPOINT_ID, metadata });

    // Duplicate protected header -> verifyWebhookRequest returns failure & assert throws ReceiverValidationError
    const dupHeaders = [
      ...signed.rawHeaderPairs,
      [WEBHOOK_HEADER_NAMES.eventId, fixture.eventId]
    ];
    const dupRes = await verifyWebhookRequest({
      method: "POST",
      rawHeaders: dupHeaders,
      rawBodyBytes: fixture.serialized.body_bytes,
      expectedTarget: { externalAuthority: AUTHORITY, requestTarget: REQUEST_TARGET },
      expectedContext: { projectId: PROJECT_ID, endpointId: ENDPOINT_ID },
      keyProvider: provider,
      now: NOW
    });
    assert.equal(dupRes.ok, false);
    if (!dupRes.ok) {
      assert.equal(dupRes.safeReason, "invalid_headers_or_duplicate");
    }
    await assert.rejects(
      () =>
        assertWebhookRequestVerified({
          method: "POST",
          rawHeaders: dupHeaders,
          rawBodyBytes: fixture.serialized.body_bytes,
          expectedTarget: { externalAuthority: AUTHORITY, requestTarget: REQUEST_TARGET },
          expectedContext: { projectId: PROJECT_ID, endpointId: ENDPOINT_ID },
          keyProvider: provider,
          now: NOW
        }),
      (err) => err instanceof ReceiverValidationError && err.httpStatus === 400
    );

    provider.destroy();
  });
});

describe("@relayquill/receiver-sdk endpoint proof, delivery receipt & idempotent inbox", () => {
  it("handles 204 endpoint proof challenges and signs <=4096B receiver receipts verified by @relayquill/signing", async () => {
    const { provider, metadata } = setupProvider();
    const verificationId = "99999999-9999-4999-8999-999999999999";
    const verificationAttemptId = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
    const configSha = "a".repeat(64);
    const nonce = encodeBase64Url(crypto.randomBytes(32));
    const serializedBody = serializeEndpointVerificationBody({
      envelope_version: 1,
      verification_id: verificationId,
      endpoint_id: ENDPOINT_ID,
      endpoint_version: "1",
      key_id: KEY_ID,
      purpose: "verify_destination_and_key",
      public_nonce: nonce,
      configuration_sha256: configSha
    });

    const signedVerify = await signEndpointVerificationRequest({
      externalAuthority: AUTHORITY,
      requestTarget: REQUEST_TARGET,
      projectId: PROJECT_ID,
      endpointId: ENDPOINT_ID,
      endpointVersion: "1",
      attemptId: verificationAttemptId,
      verificationId,
      body: serializedBody.body,
      rawWireBodyBytes: serializedBody.body_bytes,
      signingKey: metadata,
      now: NOW,
      getKeyMaterial: provider.asSigningKeyResolver()
    });

    const verifiedChallenge = await assertWebhookRequestVerified({
      method: "POST",
      rawHeaders: signedVerify.rawHeaderPairs,
      rawBodyBytes: signedVerify.bodyBytes,
      expectedTarget: { externalAuthority: AUTHORITY, requestTarget: REQUEST_TARGET },
      expectedContext: { projectId: PROJECT_ID, endpointId: ENDPOINT_ID },
      keyProvider: provider,
      now: NOW
    });
    assert.equal(verifiedChallenge.purpose, "endpoint_verification");

    const writtenHeaders = {};
    let ended = false;
    const mockRes = {
      statusCode: 0,
      setHeader(name, value) {
        writtenHeaders[name] = value;
      },
      end() {
        ended = true;
      }
    };

    const keyHandle = createReceiverKeyHandle(SECRET_BYTES, { id: KEY_ID });
    const proofResp = await handleEndpointProofChallenge({
      verifiedRequest: verifiedChallenge,
      keyHandle,
      keyMetadata: metadata,
      now: NOW,
      response: mockRes
    });
    assert.equal(proofResp.statusCode, 204);
    assert.equal(proofResp.body.byteLength, 0);
    assert.equal(mockRes.statusCode, 204);
    assert.equal(ended, true);
    assert.equal(writtenHeaders[WEBHOOK_HEADER_NAMES.endpointProof], proofResp.headerValue);

    const proofCheck = verifyEndpointProofResponse({
      statusCode: proofResp.statusCode,
      rawHeaders: Object.entries(proofResp.headers),
      rawBodyBytes: proofResp.body,
      expected: {
        verificationIntentId: verificationId,
        endpointId: ENDPOINT_ID,
        endpointVersion: "1",
        configurationSha256: configSha,
        keyId: KEY_ID,
        publicNonce: nonce,
        verificationAttemptId,
        requestTimestampSeconds: verifiedChallenge.headers.timestamp_seconds,
        requestWireBodySha256: verifiedChallenge.bodySha256,
        intentExpiresAt: Temporal.Instant.fromEpochMilliseconds(NOW.epochMilliseconds + 300_000)
      },
      keyHandle,
      keyMetadata: metadata,
      now: NOW
    });
    assert.equal(proofCheck.ok, true);

    // Also test standalone createSignedDeliveryReceipt
    const deliveryFixture = buildDeliveryFixture();
    const signedDel = await signWebhookDelivery({
      externalAuthority: AUTHORITY,
      requestTarget: REQUEST_TARGET,
      projectId: PROJECT_ID,
      eventId: deliveryFixture.eventId,
      subscriptionId: SUBSCRIPTION_ID,
      endpointId: ENDPOINT_ID,
      endpointVersion: "1",
      signingPolicyVersion: "1",
      deliveryId: deliveryFixture.deliveryId,
      deliveryGeneration: "0",
      attemptId: deliveryFixture.attemptId,
      consumerEventKey: deliveryFixture.consumerEventKey,
      rawWireBodyBytes: deliveryFixture.serialized.body_bytes,
      now: NOW,
      signingKeys: [metadata],
      getKeyMaterial: provider.asSigningKeyResolver()
    });
    const verifiedDel = await assertWebhookRequestVerified({
      method: "POST",
      rawHeaders: signedDel.rawHeaderPairs,
      rawBodyBytes: deliveryFixture.serialized.body_bytes,
      expectedTarget: { externalAuthority: AUTHORITY, requestTarget: REQUEST_TARGET },
      expectedContext: { projectId: PROJECT_ID, endpointId: ENDPOINT_ID },
      keyProvider: provider,
      now: NOW
    });
    assert.equal(verifiedDel.purpose, "delivery");

    const receiptResp = await createSignedDeliveryReceipt({
      verifiedDelivery: verifiedDel,
      keyProvider: provider,
      now: NOW
    });
    assert.equal(receiptResp.statusCode, 200);
    assert.ok(receiptResp.bodyBytes.byteLength <= WEBHOOK_RECEIPT_MAX_BODY_BYTES);

    const receiptCheck = await verifyReceiverLocalCommitReceiptResponse({
      statusCode: receiptResp.statusCode,
      rawHeaders: Object.entries(receiptResp.headers),
      rawBodyBytes: receiptResp.bodyBytes,
      receiptProfile: "receiver_local_commit_v1",
      expected: {
        projectId: PROJECT_ID,
        eventId: deliveryFixture.eventId,
        consumerEventKey: deliveryFixture.consumerEventKey,
        originalFactsSha256: deliveryFixture.serialized.original_facts_sha256,
        deliveryAttemptId: deliveryFixture.attemptId,
        requestWireBodySha256: verifiedDel.bodySha256,
        allowedKeyIds: new Set([KEY_ID])
      },
      resolveVerificationKey: () => ({ handle: keyHandle, metadata }),
      now: NOW
    });
    assert.equal(receiptCheck.ok, true);

    keyHandle.destroy?.();
    provider.destroy();
  });

  it("executes idempotent deliveries across accepted, already_committed, replay_append, gap, and conflict", async () => {
    const { provider, metadata } = setupProvider();
    const inbox = new InMemoryReceiverInboxAdapter();
    let businessSideEffects = 0;

    async function verifyOrderedAttempt({
      eventId,
      deliveryId,
      attemptId,
      deliveryGeneration = "0",
      rawContentText,
      orderingDomainId = ORDERING_DOMAIN_ID,
      orderingSequence
    }) {
      const fixture = buildDeliveryFixture({
        eventId,
        deliveryId,
        attemptId,
        deliveryGeneration,
        rawContentText
      });
      const orderingKeySha256 = crypto.createHash("sha256").update("customer-99").digest("hex");
      const ordering =
        orderingSequence !== undefined
          ? {
              orderingDomainId,
              orderingKeySha256,
              orderingSequence
            }
          : undefined;
      const signed = await signWebhookDelivery({
        externalAuthority: AUTHORITY,
        requestTarget: REQUEST_TARGET,
        projectId: PROJECT_ID,
        eventId: fixture.eventId,
        subscriptionId: SUBSCRIPTION_ID,
        endpointId: ENDPOINT_ID,
        endpointVersion: "1",
        signingPolicyVersion: "1",
        deliveryId: fixture.deliveryId,
        deliveryGeneration,
        attemptId: fixture.attemptId,
        consumerEventKey: fixture.consumerEventKey,
        rawWireBodyBytes: fixture.serialized.body_bytes,
        ordering,
        now: NOW,
        signingKeys: [metadata],
        getKeyMaterial: provider.asSigningKeyResolver()
      });
      const verified = await assertWebhookRequestVerified({
        method: "POST",
        rawHeaders: signed.rawHeaderPairs,
        rawBodyBytes: fixture.serialized.body_bytes,
        expectedTarget: { externalAuthority: AUTHORITY, requestTarget: REQUEST_TARGET },
        expectedContext: { projectId: PROJECT_ID, endpointId: ENDPOINT_ID },
        keyProvider: provider,
        now: NOW
      });
      assert.equal(verified.purpose, "delivery");
      return { verified, orderingKeySha256 };
    }

    const ev1Id = "66666666-6666-4666-8666-666666666601";
    const ev2Id = "66666666-6666-4666-8666-666666666602";

    // 1. Sequence 1 accepted -> runs business mutation once, head advances to 2
    const seq1 = await verifyOrderedAttempt({
      eventId: ev1Id,
      deliveryId: "77777777-7777-4777-8777-777777777701",
      attemptId: "88888888-8888-4888-8888-888888888801",
      rawContentText: '{"seq":1}',
      orderingSequence: "1"
    });
    const res1 = await executeIdempotentDelivery({
      verifiedDelivery: seq1.verified,
      inbox,
      keyProvider: provider,
      now: NOW,
      onBusinessMutation: () => {
        businessSideEffects += 1;
      }
    });
    assert.equal(res1.outcome, "accepted");
    assert.equal(res1.mutatedBusinessState, true);
    assert.equal(res1.advancedOrderingHead, true);
    assert.equal(res1.nextExpectedSequence, 2n);
    assert.equal(res1.receipt?.statusCode, 200);
    assert.equal(businessSideEffects, 1);

    // 2. Duplicate retry of sequence 1 -> already_committed WITHOUT re-running business mutation
    const seq1Retry = await verifyOrderedAttempt({
      eventId: ev1Id,
      deliveryId: "77777777-7777-4777-8777-777777777701",
      attemptId: "88888888-8888-4888-8888-888888888802",
      rawContentText: '{"seq":1}',
      orderingSequence: "1"
    });
    const res1Retry = await executeIdempotentDelivery({
      verifiedDelivery: seq1Retry.verified,
      inbox,
      keyProvider: provider,
      now: Temporal.Instant.fromEpochMilliseconds(NOW.epochMilliseconds + 5_000),
      onBusinessMutation: () => {
        businessSideEffects += 1;
      }
    });
    assert.equal(res1Retry.outcome, "already_committed");
    assert.equal(res1Retry.mutatedBusinessState, false);
    assert.equal(res1Retry.advancedOrderingHead, false);
    assert.equal(res1Retry.committedAt, res1.committedAt);
    assert.equal(businessSideEffects, 1);

    // 3. Gap (sequence 3 while head expects 2) -> CONSUMER_ORDER_GAP conflict
    const seq3Gap = await verifyOrderedAttempt({
      eventId: ev2Id,
      deliveryId: "77777777-7777-4777-8777-777777777703",
      attemptId: "88888888-8888-4888-8888-888888888803",
      rawContentText: '{"seq":3}',
      orderingSequence: "3"
    });
    await assert.rejects(
      () =>
        executeIdempotentDelivery({
          verifiedDelivery: seq3Gap.verified,
          inbox,
          onBusinessMutation: () => {
            businessSideEffects += 1;
          }
        }),
      (err) => err instanceof ReceiverConflictError && err.code === "CONSUMER_ORDER_GAP"
    );
    assert.equal(businessSideEffects, 1);

    // 4. replay_append for already-committed ev1 at next expected sequence 2 -> advances head WITHOUT mutating business state
    const seq2ReplayAppend = await verifyOrderedAttempt({
      eventId: ev1Id,
      deliveryId: "77777777-7777-4777-8777-777777777704",
      attemptId: "88888888-8888-4888-8888-888888888804",
      deliveryGeneration: "1",
      rawContentText: '{"seq":1}',
      orderingSequence: "2"
    });
    const resReplayAppend = await executeIdempotentDelivery({
      verifiedDelivery: seq2ReplayAppend.verified,
      inbox,
      keyProvider: provider,
      now: Temporal.Instant.fromEpochMilliseconds(NOW.epochMilliseconds + 10_000),
      onBusinessMutation: () => {
        businessSideEffects += 1;
      }
    });
    assert.equal(resReplayAppend.outcome, "replay_append");
    assert.equal(resReplayAppend.mutatedBusinessState, false);
    assert.equal(resReplayAppend.advancedOrderingHead, true);
    assert.equal(resReplayAppend.nextExpectedSequence, 3n);
    assert.equal(resReplayAppend.committedAt, res1.committedAt);
    assert.equal(businessSideEffects, 1);

    // 5. Conflicting event at sequence 1 -> CONSUMER_ORDER_POSITION_CONFLICT
    const conflictSeq1 = await verifyOrderedAttempt({
      eventId: ev2Id,
      deliveryId: "77777777-7777-4777-8777-777777777705",
      attemptId: "88888888-8888-4888-8888-888888888805",
      rawContentText: '{"seq":2}',
      orderingSequence: "1"
    });
    await assert.rejects(
      () =>
        executeIdempotentDelivery({
          verifiedDelivery: conflictSeq1.verified,
          inbox,
          onBusinessMutation: () => {
            businessSideEffects += 1;
          }
        }),
      (err) => err instanceof ReceiverConflictError && err.code === "CONSUMER_ORDER_POSITION_CONFLICT"
    );

    // 6. Unordered facts conflict on same consumer_event_key -> IDEMPOTENCY_CONFLICT
    const unorderedConflict = await verifyOrderedAttempt({
      eventId: ev1Id,
      deliveryId: "77777777-7777-4777-8777-777777777706",
      attemptId: "88888888-8888-4888-8888-888888888806",
      rawContentText: '{"seq":"TAMPERED_FACTS"}'
    });
    await assert.rejects(
      () =>
        executeIdempotentDelivery({
          verifiedDelivery: unorderedConflict.verified,
          inbox,
          onBusinessMutation: () => {
            businessSideEffects += 1;
          }
        }),
      (err) => err instanceof ReceiverConflictError && err.code === "IDEMPOTENCY_CONFLICT"
    );

    // 7. Held order head rejects sequence 3 cleanly
    inbox.setOrderHeadState(PROJECT_ID, ORDERING_DOMAIN_ID, seq1.orderingKeySha256, "held");
    const seq3WhileHeld = await verifyOrderedAttempt({
      eventId: ev2Id,
      deliveryId: "77777777-7777-4777-8777-777777777707",
      attemptId: "88888888-8888-4888-8888-888888888807",
      rawContentText: '{"seq":3}',
      orderingSequence: "3"
    });
    await assert.rejects(
      () =>
        executeIdempotentDelivery({
          verifiedDelivery: seq3WhileHeld.verified,
          inbox,
          onBusinessMutation: () => {
            businessSideEffects += 1;
          }
        }),
      (err) => err instanceof ReceiverConflictError && err.code === "STATE_TRANSITION_NOT_ALLOWED"
    );
    assert.equal(businessSideEffects, 1);

    provider.destroy();
  });
});
