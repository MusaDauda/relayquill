export const RECEIVER_SDK_PACKAGE_VERSION = "0.1.0" as const;

export {
  WEBHOOK_HEADER_NAMES,
  WEBHOOK_MAX_BODY_BYTES,
  WEBHOOK_MAX_HEADER_BYTES,
  WEBHOOK_PROTOCOL_VERSION,
  WEBHOOK_RECEIPT_MAX_BODY_BYTES,
  type AttemptId,
  type Base64UrlString,
  type CanonicalUtcTimestamp,
  type DecodedWebhookEnvelope,
  type DeliveryId,
  type EndpointId,
  type EndpointVerificationBodyV1,
  type EndpointVerificationIntentId,
  type EventId,
  type KeyId,
  type NonNegativeInt64String,
  type OrderingDomainId,
  type ParsedWebhookDeliveryHeaders,
  type ParsedWebhookVerificationHeaders,
  type PositiveInt64String,
  type ProjectId,
  type ReceiverLocalCommitReceiptV1,
  type Sha256Hex,
  type SubscriptionId,
  type WebhookSignatureEntry
} from "@relayquill/contracts";

export {
  type DomainErrorCode,
  type ReceiverOrderHeadState,
  type WebhookPurpose
} from "@relayquill/domain";

export {
  type EndpointKeyMetadata,
  type ExpectedWebhookContext,
  type ExpectedWebhookTarget,
  type KeyLifecycleState,
  type RawHeaderInput,
  type ResolvedSigningKeyMaterial,
  type SafeVerificationFailureReason,
  type SignedAuthorityValidationOptions,
  type SigningKeyHandle,
  type VerificationKeyRecord,
  type VerifyDeliverySuccess,
  type VerifyEndpointVerificationSuccess,
  type VerifyWebhookFailure,
  type VerifyWebhookResult,
  type WebhookKeyMaterialResolver,
  type WebhookVerificationKeyProvider
} from "@relayquill/signing";

export {
  ReceiverAuthError,
  ReceiverConfigError,
  ReceiverConflictError,
  ReceiverExpiredError,
  ReceiverSdkError,
  type ReceiverSdkErrorCode,
  type ReceiverSdkErrorOptions,
  ReceiverValidationError
} from "./errors.js";

export {
  type CreateReceiverKeyHandleOptions,
  InMemoryReceiverKeyProvider,
  type ReceiverKeyHandle,
  type ReceiverKeyMetadata,
  type ReceiverKeyResolverInput,
  type RegisterReceiverKeyInput,
  type ResolveReceiverKeyQuery,
  createReceiverKeyHandle
} from "./keys.js";

export {
  type BoundedRawWebhookRequest,
  type ReadBoundedRawWebhookRequestInput,
  type ReadBoundedRawWebhookRequestOptions,
  type WebhookHttpRequestLike,
  readBoundedRawWebhookRequest
} from "./raw-request.js";

export {
  type VerifyReceiverBoundedRequestInput,
  type VerifyReceiverRawFieldsInput,
  type VerifyReceiverWebhookCommonInput,
  type VerifyReceiverWebhookInput,
  assertWebhookRequestVerified,
  verifyWebhookRequest
} from "./verify.js";

export {
  type EndpointProofHttpResponse,
  type EndpointProofResponseWriter,
  type HandleEndpointProofChallengeInput,
  handleEndpointProofChallenge
} from "./endpoint-proof.js";

export {
  type CreateSignedDeliveryReceiptInput,
  type SignedDeliveryReceiptResponse,
  createSignedDeliveryReceipt
} from "./receipt.js";

export {
  type ExecuteIdempotentDeliveryInput,
  type ExecuteIdempotentDeliveryResult,
  type IdempotentDeliveryOutcome,
  InMemoryReceiverInboxAdapter,
  type ReceiverBusinessCommitAnchor,
  type ReceiverDeliveryMutationContext,
  type ReceiverInboxAdapter,
  type ReceiverInboxTransactionContext,
  type ReceiverOrderHeadRecord,
  type ReceiverOrderPositionAnchor,
  executeIdempotentDelivery
} from "./inbox.js";
