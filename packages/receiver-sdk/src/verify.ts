import { type Temporal } from "@js-temporal/polyfill";
import {
  type ExpectedWebhookContext,
  type ExpectedWebhookTarget,
  type RawHeaderInput,
  type SignedAuthorityValidationOptions,
  type VerifyDeliverySuccess,
  type VerifyEndpointVerificationSuccess,
  type VerifyWebhookFailure,
  type VerifyWebhookRequestInput,
  type VerifyWebhookResult,
  verifyWebhookRequest as verifySignedWebhookRequest
} from "@relayquill/signing";
import {
  ReceiverAuthError,
  ReceiverExpiredError,
  ReceiverValidationError
} from "./errors.js";
import {
  type ReceiverKeyResolverInput,
  normalizeVerificationKeyProvider
} from "./keys.js";
import { type BoundedRawWebhookRequest } from "./raw-request.js";

export interface VerifyReceiverWebhookCommonInput {
  readonly expectedTarget: ExpectedWebhookTarget;
  readonly expectedContext: ExpectedWebhookContext;
  readonly keyProvider: ReceiverKeyResolverInput;
  readonly now?: Temporal.Instant | undefined;
  readonly nowUnixSeconds?: bigint | undefined;
  readonly freshnessWindow?: {
    readonly pastSeconds?: bigint | undefined;
    readonly futureSeconds?: bigint | undefined;
  } | undefined;
  readonly authorityValidation?: SignedAuthorityValidationOptions | undefined;
}

export interface VerifyReceiverRawFieldsInput extends VerifyReceiverWebhookCommonInput {
  readonly method: string;
  readonly rawHeaders: RawHeaderInput;
  readonly rawBodyBytes: Uint8Array;
  readonly request?: undefined;
}

export interface VerifyReceiverBoundedRequestInput extends VerifyReceiverWebhookCommonInput {
  readonly request: BoundedRawWebhookRequest;
  readonly method?: undefined;
  readonly rawHeaders?: undefined;
  readonly rawBodyBytes?: undefined;
}

export type VerifyReceiverWebhookInput =
  | VerifyReceiverRawFieldsInput
  | VerifyReceiverBoundedRequestInput;

function toSigningVerifyInput(input: VerifyReceiverWebhookInput): VerifyWebhookRequestInput {
  const keyProvider = normalizeVerificationKeyProvider(input.keyProvider);
  const method = input.request !== undefined ? input.request.method : input.method;
  const rawHeaders = input.request !== undefined ? input.request.rawHeaders : input.rawHeaders;
  const rawBodyBytes = input.request !== undefined ? input.request.rawBodyBytes : input.rawBodyBytes;

  return {
    method,
    rawHeaders,
    rawBodyBytes,
    expectedTarget: input.expectedTarget,
    expectedContext: input.expectedContext,
    keyProvider,
    ...(input.now !== undefined ? { now: input.now } : {}),
    ...(input.nowUnixSeconds !== undefined ? { nowUnixSeconds: input.nowUnixSeconds } : {}),
    ...(input.freshnessWindow !== undefined ? { freshnessWindow: input.freshnessWindow } : {}),
    ...(input.authorityValidation !== undefined
      ? { authorityValidation: input.authorityValidation }
      : {})
  };
}

export async function verifyWebhookRequest(
  input: VerifyReceiverWebhookInput
): Promise<VerifyWebhookResult> {
  return verifySignedWebhookRequest(toSigningVerifyInput(input));
}

function throwVerifiedFailure(failure: VerifyWebhookFailure): never {
  if (failure.errorCode === "EXPIRED") {
    throw new ReceiverExpiredError({
      code: failure.errorCode,
      message: `Webhook verification rejected (${failure.safeReason})`,
      safeReason: failure.safeReason
    });
  }
  if (
    failure.errorCode === "INVALID_VALUE" ||
    failure.errorCode === "PAYLOAD_TOO_LARGE" ||
    failure.errorCode === "UNSUPPORTED_SCHEMA_VERSION"
  ) {
    const httpStatus: 400 | 413 | 422 =
      failure.httpStatus === 413
        ? 413
        : failure.httpStatus === 422
          ? 422
          : 400;
    throw new ReceiverValidationError({
      code: failure.errorCode,
      message: `Webhook request rejected (${failure.safeReason})`,
      httpStatus,
      safeReason: failure.safeReason
    });
  }
  const authStatus: 401 | 403 = failure.httpStatus === 403 ? 403 : 401;
  throw new ReceiverAuthError({
    code: failure.errorCode,
    message: `Webhook signature verification failed (${failure.safeReason})`,
    httpStatus: authStatus,
    safeReason: failure.safeReason
  });
}

export async function assertWebhookRequestVerified(
  input: VerifyReceiverWebhookInput
): Promise<VerifyDeliverySuccess | VerifyEndpointVerificationSuccess> {
  const result = await verifyWebhookRequest(input);
  if (result.ok) {
    return result;
  }
  return throwVerifiedFailure(result);
}
