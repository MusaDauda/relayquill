import crypto from "node:crypto";
import { Temporal } from "@js-temporal/polyfill";
import {
  EVENT_CONTENT_MEDIA_TYPE,
  type ReceiverLocalCommitReceiptV1,
  WEBHOOK_RECEIPT_MAX_BODY_BYTES,
  parseCanonicalUtcTimestamp
} from "@relayquill/contracts";
import {
  type CanonicalUtcTimestamp,
  formatUtcTimestamp,
  nowUtcInstant
} from "@relayquill/domain";
import {
  type EndpointKeyMetadata,
  type SigningKeyHandle,
  type VerifyDeliverySuccess,
  signReceiverLocalCommitReceipt
} from "@relayquill/signing";
import { ReceiverValidationError, toReceiverSdkError } from "./errors.js";
import {
  type ReceiverKeyResolverInput,
  withResolvedSigningMaterial
} from "./keys.js";

export interface CreateSignedDeliveryReceiptInput {
  readonly verifiedDelivery: VerifyDeliverySuccess;
  readonly committedAt?: CanonicalUtcTimestamp | Temporal.Instant | string | undefined;
  readonly receiptId?: string | undefined;
  readonly keyHandle?: SigningKeyHandle | undefined;
  readonly keyMetadata?: EndpointKeyMetadata | undefined;
  readonly keyProvider?: ReceiverKeyResolverInput | undefined;
  readonly now?: Temporal.Instant | undefined;
}

export interface SignedDeliveryReceiptResponse {
  readonly statusCode: 200;
  readonly contentType: typeof EVENT_CONTENT_MEDIA_TYPE;
  readonly headers: Readonly<Record<string, string>>;
  readonly receipt: ReceiverLocalCommitReceiptV1;
  readonly bodyJson: string;
  readonly bodyBytes: Uint8Array;
}

function resolveCommittedAt(
  committedAt: CanonicalUtcTimestamp | Temporal.Instant | string | undefined,
  now?: Temporal.Instant
): CanonicalUtcTimestamp {
  try {
    if (committedAt === undefined) {
      return formatUtcTimestamp(now ?? nowUtcInstant());
    }
    if (committedAt instanceof Temporal.Instant) {
      return formatUtcTimestamp(committedAt);
    }
    return parseCanonicalUtcTimestamp(committedAt, "committedAt");
  } catch (err) {
    throw toReceiverSdkError(err);
  }
}

export async function createSignedDeliveryReceipt(
  input: CreateSignedDeliveryReceiptInput
): Promise<SignedDeliveryReceiptResponse> {
  const { verifiedDelivery } = input;
  const { headers, decodedEnvelope, verifiedKeyId, bodySha256 } = verifiedDelivery;
  const committedAt = resolveCommittedAt(input.committedAt, input.now);
  const receiptId = input.receiptId ?? crypto.randomUUID();

  const signed = await withResolvedSigningMaterial(
    {
      keyHandle: input.keyHandle,
      keyMetadata: input.keyMetadata,
      keyProvider: input.keyProvider,
      projectId: headers.project_id,
      endpointId: headers.endpoint_id,
      keyId: verifiedKeyId,
      purpose: "delivery"
    },
    (material) => {
      try {
        return signReceiverLocalCommitReceipt({
          keyId: verifiedKeyId,
          projectId: headers.project_id,
          eventId: headers.event_id,
          consumerEventKey: headers.consumer_key,
          originalFactsSha256: decodedEnvelope.original_facts_sha256,
          receiptId,
          committedAt,
          deliveryAttemptId: headers.attempt_id,
          requestWireBodySha256: bodySha256,
          keyHandle: material.handle,
          keyMetadata: material.metadata,
          now: input.now
        });
      } catch (err) {
        throw toReceiverSdkError(err);
      }
    }
  );

  if (signed.bodyBytes.byteLength > WEBHOOK_RECEIPT_MAX_BODY_BYTES) {
    throw new ReceiverValidationError({
      code: "PAYLOAD_TOO_LARGE",
      httpStatus: 413,
      message: `Receiver commit receipt exceeds maximum size of ${WEBHOOK_RECEIPT_MAX_BODY_BYTES} bytes`
    });
  }

  return Object.freeze({
    statusCode: 200,
    contentType: EVENT_CONTENT_MEDIA_TYPE,
    headers: Object.freeze({
      "Content-Type": EVENT_CONTENT_MEDIA_TYPE
    }),
    receipt: signed.receipt,
    bodyJson: signed.bodyJson,
    bodyBytes: signed.bodyBytes
  });
}
