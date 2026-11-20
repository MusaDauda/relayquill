import { type Temporal } from "@js-temporal/polyfill";
import {
  type AllowlistedReceiptFactsDto,
  type AttemptId,
  type Base64UrlString,
  type CanonicalJsonValue,
  type CanonicalUtcTimestamp,
  type EndpointId,
  type EventId,
  type EndpointVerificationIntentId,
  type KeyId,
  type NonNegativeInt64String,
  type PositiveInt64String,
  type ProjectId,
  type ReceiverLocalCommitReceiptV1,
  type Sha256Hex,
  WEBHOOK_HEADER_NAMES,
  WEBHOOK_RECEIPT_MAX_BODY_BYTES,
  buildEndpointProofPreimage,
  buildReceiverReceiptPreimage,
  canonicalizeJson,
  decodeBase64UrlStrict,
  decodeReceiverLocalCommitReceiptBytes,
  encodeBase64Url,
  encodeUtf8Bytes,
  parseAllowlistedReceiptFacts,
  parseAttemptId,
  parseCanonicalUtcTimestamp,
  parseCanonicalUuid,
  parseEndpointId,
  parseEndpointVerificationIntentId,
  parseEventId,
  parseKeyId,
  parseNonNegativeInt64String,
  parsePositiveInt64String,
  parseProjectId,
  parseSha256Hex,
  serializeReceiverLocalCommitReceipt
} from "@relayquill/contracts";
import {
  ValidationDomainError,
  compareInstants,
  nowUtcInstant,
  type ReceiptProfile,
  type ReceiptVerificationState
} from "@relayquill/domain";
import {
  type RawHeaderInput,
  validateRawEndpointProofResponseHeaders,
  validateRawReceiptResponseHeaders
} from "./format.js";
import {
  type EndpointKeyMetadata,
  checkKeySigningEligibility,
  checkKeyVerificationEligibility
} from "./rotation.js";
import {
  type SigningKeyHandle,
  computeHmacSha256,
  sha256HexNode
} from "./signer.js";
import { constantTimeEqualBytes } from "./verifier.js";

export interface SignEndpointProofInput {
  readonly verificationIntentId: EndpointVerificationIntentId | string;
  readonly endpointId: EndpointId | string;
  readonly endpointVersion: PositiveInt64String | string;
  readonly configurationSha256: Sha256Hex | string;
  readonly keyId: KeyId | string;
  readonly publicNonce: Base64UrlString | string;
  readonly verificationAttemptId: AttemptId | string;
  readonly requestTimestampSeconds: NonNegativeInt64String | string;
  readonly requestWireBodySha256: Sha256Hex | string;
  readonly keyHandle: SigningKeyHandle;
  readonly keyMetadata?: EndpointKeyMetadata | undefined;
  readonly now?: Temporal.Instant | undefined;
}

export interface SignedEndpointProof {
  readonly headerName: typeof WEBHOOK_HEADER_NAMES.endpointProof;
  readonly headerValue: Base64UrlString;
  readonly proofSha256: Sha256Hex;
}

export function signEndpointProof(input: SignEndpointProofInput): SignedEndpointProof {
  const now = input.now ?? nowUtcInstant();
  if (input.keyMetadata !== undefined) {
    const eligibility = checkKeySigningEligibility(
      input.keyMetadata,
      "endpoint_verification",
      now
    );
    if (!eligibility.eligible) {
      throw new ValidationDomainError({
        code: "STATE_TRANSITION_NOT_ALLOWED",
        message: `Key "${input.keyId}" is ineligible to sign endpoint proof (${eligibility.reason})`
      });
    }
  }

  const preimage = buildEndpointProofPreimage({
    verification_intent_id: input.verificationIntentId,
    endpoint_id: input.endpointId,
    endpoint_version: input.endpointVersion,
    configuration_sha256: input.configurationSha256,
    key_id: input.keyId,
    public_nonce: input.publicNonce,
    verification_attempt_id: input.verificationAttemptId,
    request_timestamp_seconds: input.requestTimestampSeconds,
    request_wire_body_sha256: input.requestWireBodySha256
  });

  const proofBytes = computeHmacSha256(input.keyHandle, preimage);
  const headerValue = encodeBase64Url(proofBytes);
  const proofSha256 = sha256HexNode(proofBytes);

  return Object.freeze({
    headerName: WEBHOOK_HEADER_NAMES.endpointProof,
    headerValue,
    proofSha256
  });
}

export interface VerifyEndpointProofResponseInput {
  readonly statusCode: number;
  readonly rawHeaders: RawHeaderInput;
  readonly rawBodyBytes?: Uint8Array | undefined;
  readonly expected: {
    readonly verificationIntentId: EndpointVerificationIntentId | string;
    readonly endpointId: EndpointId | string;
    readonly endpointVersion: PositiveInt64String | string;
    readonly configurationSha256: Sha256Hex | string;
    readonly keyId: KeyId | string;
    readonly publicNonce: Base64UrlString | string;
    readonly verificationAttemptId: AttemptId | string;
    readonly requestTimestampSeconds: NonNegativeInt64String | string;
    readonly requestWireBodySha256: Sha256Hex | string;
    readonly intentExpiresAt: Temporal.Instant;
  };
  readonly keyHandle: SigningKeyHandle;
  readonly keyMetadata?: EndpointKeyMetadata | undefined;
  readonly now?: Temporal.Instant | undefined;
}

export type EndpointProofVerificationResult =
  | { readonly ok: true; readonly proofSha256: Sha256Hex }
  | {
      readonly ok: false;
      readonly safeReason:
        | "unexpected_status"
        | "non_empty_body"
        | "invalid_proof_headers"
        | "intent_expired"
        | "key_ineligible"
        | "proof_mac_mismatch";
    };

export function verifyEndpointProofResponse(
  input: VerifyEndpointProofResponseInput
): EndpointProofVerificationResult {
  if (input.statusCode !== 204) {
    return Object.freeze({ ok: false, safeReason: "unexpected_status" });
  }
  if (input.rawBodyBytes !== undefined && input.rawBodyBytes.byteLength !== 0) {
    return Object.freeze({ ok: false, safeReason: "non_empty_body" });
  }

  let proofBytes: Uint8Array;
  try {
    proofBytes = validateRawEndpointProofResponseHeaders(input.rawHeaders).proofBytes;
  } catch {
    return Object.freeze({ ok: false, safeReason: "invalid_proof_headers" });
  }

  const now = input.now ?? nowUtcInstant();
  if (compareInstants(now, input.expected.intentExpiresAt) >= 0) {
    return Object.freeze({ ok: false, safeReason: "intent_expired" });
  }

  if (input.keyMetadata !== undefined) {
    const eligibility = checkKeyVerificationEligibility(
      input.keyMetadata,
      "endpoint_verification",
      now
    );
    if (!eligibility.eligible) {
      return Object.freeze({ ok: false, safeReason: "key_ineligible" });
    }
  }

  const preimage = buildEndpointProofPreimage({
    verification_intent_id: parseEndpointVerificationIntentId(
      input.expected.verificationIntentId,
      "verificationIntentId"
    ),
    endpoint_id: parseEndpointId(input.expected.endpointId, "endpointId"),
    endpoint_version: parsePositiveInt64String(
      input.expected.endpointVersion,
      "endpointVersion"
    ),
    configuration_sha256: parseSha256Hex(
      input.expected.configurationSha256,
      "configurationSha256"
    ),
    key_id: parseKeyId(input.expected.keyId, "keyId"),
    public_nonce: input.expected.publicNonce,
    verification_attempt_id: parseAttemptId(
      input.expected.verificationAttemptId,
      "verificationAttemptId"
    ),
    request_timestamp_seconds: parseNonNegativeInt64String(
      input.expected.requestTimestampSeconds,
      "requestTimestampSeconds"
    ),
    request_wire_body_sha256: parseSha256Hex(
      input.expected.requestWireBodySha256,
      "requestWireBodySha256"
    )
  });

  const expectedProof = computeHmacSha256(input.keyHandle, preimage);
  if (!constantTimeEqualBytes(expectedProof, proofBytes)) {
    return Object.freeze({ ok: false, safeReason: "proof_mac_mismatch" });
  }

  return Object.freeze({
    ok: true,
    proofSha256: sha256HexNode(proofBytes)
  });
}

export interface SignReceiverReceiptInput {
  readonly keyId: KeyId | string;
  readonly projectId: ProjectId | string;
  readonly eventId: EventId | string;
  readonly consumerEventKey: Sha256Hex | string;
  readonly originalFactsSha256: Sha256Hex | string;
  readonly receiptId: string;
  readonly committedAt: CanonicalUtcTimestamp | string;
  readonly deliveryAttemptId: AttemptId | string;
  readonly requestWireBodySha256: Sha256Hex | string;
  readonly keyHandle: SigningKeyHandle;
  readonly keyMetadata?: EndpointKeyMetadata | undefined;
  readonly now?: Temporal.Instant | undefined;
}

export interface SignedReceiverReceipt {
  readonly receipt: ReceiverLocalCommitReceiptV1;
  readonly bodyJson: string;
  readonly bodyBytes: Uint8Array;
}

export function signReceiverLocalCommitReceipt(
  input: SignReceiverReceiptInput
): SignedReceiverReceipt {
  const now = input.now ?? nowUtcInstant();
  if (input.keyMetadata !== undefined) {
    const eligibility = checkKeySigningEligibility(input.keyMetadata, "delivery", now);
    if (!eligibility.eligible) {
      throw new ValidationDomainError({
        code: "STATE_TRANSITION_NOT_ALLOWED",
        message: `Key "${input.keyId}" is ineligible to sign receiver receipt (${eligibility.reason})`
      });
    }
  }

  const keyId = parseKeyId(input.keyId, "keyId");
  const projectId = parseProjectId(input.projectId, "projectId");
  const eventId = parseEventId(input.eventId, "eventId");
  const consumerEventKey = parseSha256Hex(input.consumerEventKey, "consumerEventKey");
  const originalFactsSha256 = parseSha256Hex(input.originalFactsSha256, "originalFactsSha256");
  const receiptId = parseCanonicalUuid(input.receiptId, "receiptId");
  const committedAt = parseCanonicalUtcTimestamp(input.committedAt, "committedAt");
  const deliveryAttemptId = parseAttemptId(input.deliveryAttemptId, "deliveryAttemptId");
  const requestWireBodySha256 = parseSha256Hex(
    input.requestWireBodySha256,
    "requestWireBodySha256"
  );

  const preimage = buildReceiverReceiptPreimage({
    key_id: keyId,
    project_id: projectId,
    event_id: eventId,
    consumer_event_key: consumerEventKey,
    original_facts_sha256: originalFactsSha256,
    receipt_id: receiptId,
    business_status: "committed",
    committed_at: committedAt,
    delivery_attempt_id: deliveryAttemptId,
    request_wire_body_sha256: requestWireBodySha256
  });

  const macBytes = computeHmacSha256(input.keyHandle, preimage);
  const mac = encodeBase64Url(macBytes);

  const serialized = serializeReceiverLocalCommitReceipt({
    receipt_version: 1,
    project_id: projectId,
    event_id: eventId,
    consumer_event_key: consumerEventKey,
    original_facts_sha256: originalFactsSha256,
    receipt_id: receiptId,
    business_status: "committed",
    committed_at: committedAt,
    delivery_attempt_id: deliveryAttemptId,
    key_id: keyId,
    mac
  });

  return Object.freeze({
    receipt: serialized.receipt,
    bodyJson: serialized.body_json,
    bodyBytes: serialized.body_bytes
  });
}

export interface VerifyReceiverReceiptResponseInput {
  readonly statusCode: number;
  readonly rawHeaders: RawHeaderInput;
  readonly rawBodyBytes: Uint8Array;
  readonly bodyOversizedOrIncomplete?: boolean | undefined;
  readonly receiptProfile: ReceiptProfile;
  readonly expected: {
    readonly projectId: ProjectId | string;
    readonly eventId: EventId | string;
    readonly consumerEventKey: Sha256Hex | string;
    readonly originalFactsSha256: Sha256Hex | string;
    readonly deliveryAttemptId: AttemptId | string;
    readonly requestWireBodySha256: Sha256Hex | string;
    readonly allowedKeyIds: ReadonlySet<KeyId>;
  };
  readonly resolveVerificationKey: (keyId: KeyId) => Promise<{
    readonly handle: SigningKeyHandle;
    readonly metadata?: EndpointKeyMetadata | undefined;
    readonly releaseAfterUse?: boolean | undefined;
  } | null> | {
    readonly handle: SigningKeyHandle;
    readonly metadata?: EndpointKeyMetadata | undefined;
    readonly releaseAfterUse?: boolean | undefined;
  } | null;
  readonly now?: Temporal.Instant | undefined;
}

export type ReceiverReceiptSafeRejectionReason =
  | "unsupported_receipt_profile"
  | "non_200_status"
  | "invalid_or_compressed_headers"
  | "oversized_or_incomplete_body"
  | "malformed_receipt_json"
  | "receipt_scope_mismatch"
  | "key_not_permitted_for_request"
  | "key_ineligible"
  | "receipt_mac_mismatch";

export type VerifyReceiverReceiptResult =
  | {
      readonly ok: true;
      readonly verificationState: Extract<ReceiptVerificationState, "verified_supported">;
      readonly safeReceiptFacts: AllowlistedReceiptFactsDto;
      readonly receiptFactsSha256: Sha256Hex;
      readonly proofSha256: Sha256Hex;
    }
  | {
      readonly ok: false;
      readonly verificationState: Exclude<ReceiptVerificationState, "verified_supported">;
      readonly safeReason: ReceiverReceiptSafeRejectionReason;
    };

export async function verifyReceiverLocalCommitReceiptResponse(
  input: VerifyReceiverReceiptResponseInput
): Promise<VerifyReceiverReceiptResult> {
  if (input.receiptProfile !== "receiver_local_commit_v1") {
    return Object.freeze({
      ok: false,
      verificationState: "unverified",
      safeReason: "unsupported_receipt_profile"
    });
  }
  if (input.statusCode !== 200) {
    return Object.freeze({
      ok: false,
      verificationState: "unverified",
      safeReason: "non_200_status"
    });
  }

  try {
    validateRawReceiptResponseHeaders(input.rawHeaders);
  } catch {
    return Object.freeze({
      ok: false,
      verificationState: "rejected",
      safeReason: "invalid_or_compressed_headers"
    });
  }

  if (
    input.bodyOversizedOrIncomplete === true ||
    !(input.rawBodyBytes instanceof Uint8Array) ||
    input.rawBodyBytes.byteLength === 0 ||
    input.rawBodyBytes.byteLength > WEBHOOK_RECEIPT_MAX_BODY_BYTES
  ) {
    return Object.freeze({
      ok: false,
      verificationState: "unverified",
      safeReason: "oversized_or_incomplete_body"
    });
  }

  let receipt: ReceiverLocalCommitReceiptV1;
  try {
    receipt = decodeReceiverLocalCommitReceiptBytes(input.rawBodyBytes);
  } catch {
    return Object.freeze({
      ok: false,
      verificationState: "rejected",
      safeReason: "malformed_receipt_json"
    });
  }

  const expectedProjectId = parseProjectId(input.expected.projectId, "expected.projectId");
  const expectedEventId = parseEventId(input.expected.eventId, "expected.eventId");
  const expectedConsumerKey = parseSha256Hex(
    input.expected.consumerEventKey,
    "expected.consumerEventKey"
  );
  const expectedFactsHash = parseSha256Hex(
    input.expected.originalFactsSha256,
    "expected.originalFactsSha256"
  );
  const expectedAttemptId = parseAttemptId(
    input.expected.deliveryAttemptId,
    "expected.deliveryAttemptId"
  );
  const expectedWireBodySha = parseSha256Hex(
    input.expected.requestWireBodySha256,
    "expected.requestWireBodySha256"
  );

  if (
    receipt.project_id !== expectedProjectId ||
    receipt.event_id !== expectedEventId ||
    receipt.consumer_event_key !== expectedConsumerKey ||
    receipt.original_facts_sha256 !== expectedFactsHash ||
    receipt.delivery_attempt_id !== expectedAttemptId ||
    receipt.business_status !== "committed"
  ) {
    return Object.freeze({
      ok: false,
      verificationState: "rejected",
      safeReason: "receipt_scope_mismatch"
    });
  }

  if (!input.expected.allowedKeyIds.has(receipt.key_id)) {
    return Object.freeze({
      ok: false,
      verificationState: "rejected",
      safeReason: "key_not_permitted_for_request"
    });
  }

  const resolvedKey = await input.resolveVerificationKey(receipt.key_id);
  if (resolvedKey === null) {
    return Object.freeze({
      ok: false,
      verificationState: "rejected",
      safeReason: "key_ineligible"
    });
  }

  const now = input.now ?? nowUtcInstant();
  try {
    if (resolvedKey.metadata !== undefined) {
      const eligibility = checkKeyVerificationEligibility(resolvedKey.metadata, "delivery", now);
      if (!eligibility.eligible) {
        return Object.freeze({
          ok: false,
          verificationState: "rejected",
          safeReason: "key_ineligible"
        });
      }
    }

    const receiptMacBytes = decodeBase64UrlStrict(receipt.mac, "receipt.mac", {
      exactByteLength: 32
    });
    const preimage = buildReceiverReceiptPreimage({
      key_id: receipt.key_id,
      project_id: receipt.project_id,
      event_id: receipt.event_id,
      consumer_event_key: receipt.consumer_event_key,
      original_facts_sha256: receipt.original_facts_sha256,
      receipt_id: receipt.receipt_id,
      business_status: "committed",
      committed_at: receipt.committed_at,
      delivery_attempt_id: receipt.delivery_attempt_id,
      request_wire_body_sha256: expectedWireBodySha
    });

    const expectedMac = computeHmacSha256(resolvedKey.handle, preimage);
    if (!constantTimeEqualBytes(expectedMac, receiptMacBytes)) {
      return Object.freeze({
        ok: false,
        verificationState: "rejected",
        safeReason: "receipt_mac_mismatch"
      });
    }

    const safeReceiptFacts = parseAllowlistedReceiptFacts({
      receipt_version: 1,
      project_id: receipt.project_id,
      event_id: receipt.event_id,
      consumer_event_key: receipt.consumer_event_key,
      original_facts_sha256: receipt.original_facts_sha256,
      receipt_id: receipt.receipt_id,
      business_status: "committed",
      committed_at: receipt.committed_at,
      delivery_attempt_id: receipt.delivery_attempt_id,
      key_id: receipt.key_id
    });
    const receiptFactsSha256 = sha256HexNode(
      encodeUtf8Bytes(
        canonicalizeJson(safeReceiptFacts as unknown as CanonicalJsonValue, "safe_receipt_facts")
      )
    );
    const proofSha256 = sha256HexNode(receiptMacBytes);

    return Object.freeze({
      ok: true,
      verificationState: "verified_supported",
      safeReceiptFacts,
      receiptFactsSha256,
      proofSha256
    });
  } finally {
    if (resolvedKey.releaseAfterUse === true) {
      resolvedKey.handle.destroy?.();
    }
  }
}
