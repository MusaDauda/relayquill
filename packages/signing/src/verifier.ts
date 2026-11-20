import crypto from "node:crypto";
import { type Temporal } from "@js-temporal/polyfill";
import {
  type DecodedWebhookEnvelope,
  type EndpointVerificationBodyV1,
  type KeyId,
  type ParsedWebhookDeliveryHeaders,
  type ParsedWebhookHeaders,
  type ParsedWebhookVerificationHeaders,
  type PositiveInt64String,
  type ProjectId,
  type EndpointId,
  type SubscriptionId,
  type Sha256Hex,
  WEBHOOK_FRESHNESS_FUTURE_SECONDS,
  WEBHOOK_FRESHNESS_PAST_SECONDS,
  WEBHOOK_MAX_BODY_BYTES,
  WEBHOOK_PROTOCOL_VERSION,
  computeConsumerEventKeySha256,
  decodeEndpointVerificationBodyBytes,
  decodeWebhookEnvelopeBytes,
  parseEndpointId,
  parseKeyId,
  parseNonNegativeInt64BigInt,
  parseProjectId,
  parseSubscriptionId
} from "@relayquill/contracts";
import {
  AuthenticationDomainError,
  DomainError,
  ExpiredDomainError,
  ValidationDomainError,
  nowUtcInstant,
  type DomainErrorCode,
  type WebhookPurpose
} from "@relayquill/domain";
import {
  type RawHeaderInput,
  type SignedAuthorityValidationOptions,
  encodeWebhookSignaturePreimage,
  validateRawWebhookHeaders,
  validateSignedExternalAuthority,
  validateSignedRequestTarget
} from "./format.js";
import {
  type EndpointKeyMetadata,
  checkKeyVerificationEligibility
} from "./rotation.js";
import {
  type ResolvedSigningKeyMaterial,
  type SigningKeyHandle,
  computeHmacSha256,
  normalizeResolvedKeyMaterial,
  sha256HexNode
} from "./signer.js";

export function constantTimeEqualBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.byteLength !== b.byteLength) {
    return false;
  }
  return crypto.timingSafeEqual(a, b);
}

export interface VerificationKeyRecord {
  readonly metadata: EndpointKeyMetadata;
  readonly handle: SigningKeyHandle;
  readonly releaseAfterUse?: boolean | undefined;
}

export type WebhookVerificationKeyProvider = (query: {
  readonly projectId: ProjectId;
  readonly endpointId: EndpointId;
  readonly keyId: KeyId;
  readonly purpose: WebhookPurpose;
}) =>
  | Promise<VerificationKeyRecord | ResolvedSigningKeyMaterial | null>
  | VerificationKeyRecord
  | ResolvedSigningKeyMaterial
  | null;

export interface ExpectedWebhookTarget {
  readonly externalAuthority: string;
  readonly requestTarget: string;
  readonly observedAuthority?: string | undefined;
  readonly observedRequestTarget?: string | undefined;
}

export interface ExpectedWebhookContext {
  readonly projectId: ProjectId | string;
  readonly endpointId: EndpointId | string;
  readonly subscriptionId?: SubscriptionId | string | undefined;
  readonly allowedEndpointVersions?: ReadonlySet<PositiveInt64String> | undefined;
  readonly consumerContractScope?: string | undefined;
  readonly expectedConsumerEventKey?: Sha256Hex | string | undefined;
}

export interface VerifyWebhookRequestInput {
  readonly method: string;
  readonly rawHeaders: RawHeaderInput;
  readonly rawBodyBytes: Uint8Array;
  readonly expectedTarget: ExpectedWebhookTarget;
  readonly expectedContext: ExpectedWebhookContext;
  readonly keyProvider: WebhookVerificationKeyProvider;
  readonly now?: Temporal.Instant | undefined;
  readonly nowUnixSeconds?: bigint | undefined;
  readonly freshnessWindow?: {
    readonly pastSeconds?: bigint | undefined;
    readonly futureSeconds?: bigint | undefined;
  } | undefined;
  readonly authorityValidation?: SignedAuthorityValidationOptions | undefined;
}

export type SafeVerificationFailureReason =
  | "invalid_method"
  | "invalid_body_framing"
  | "invalid_headers_or_duplicate"
  | "target_mismatch"
  | "context_scope_mismatch"
  | "timestamp_stale_or_future"
  | "body_hash_mismatch"
  | "unknown_key"
  | "pending_key_forbidden_for_delivery"
  | "key_retired_or_expired"
  | "key_revoked"
  | "key_snapshot_expired"
  | "key_ineligible"
  | "mac_mismatch"
  | "invalid_envelope_payload"
  | "envelope_identity_mismatch"
  | "consumer_key_mismatch"
  | "verification_body_mismatch";

export interface VerifyWebhookFailure {
  readonly ok: false;
  readonly errorCode: DomainErrorCode;
  readonly httpStatus: 400 | 401 | 403 | 413 | 422;
  readonly safeReason: SafeVerificationFailureReason;
}

export interface VerifyDeliverySuccess {
  readonly ok: true;
  readonly purpose: "delivery";
  readonly verifiedKeyId: KeyId;
  readonly headers: ParsedWebhookDeliveryHeaders;
  readonly bodySha256: Sha256Hex;
  readonly decodedEnvelope: DecodedWebhookEnvelope;
}

export interface VerifyEndpointVerificationSuccess {
  readonly ok: true;
  readonly purpose: "endpoint_verification";
  readonly verifiedKeyId: KeyId;
  readonly headers: ParsedWebhookVerificationHeaders;
  readonly bodySha256: Sha256Hex;
  readonly verificationBody: EndpointVerificationBodyV1;
}

export type VerifyWebhookResult =
  | VerifyDeliverySuccess
  | VerifyEndpointVerificationSuccess
  | VerifyWebhookFailure;

function failResult(
  safeReason: SafeVerificationFailureReason,
  errorCode: DomainErrorCode,
  httpStatus: 400 | 401 | 403 | 413 | 422
): VerifyWebhookFailure {
  return Object.freeze({
    ok: false,
    errorCode,
    httpStatus,
    safeReason
  });
}

function mapKeyRejectionReason(reason: string): {
  readonly safeReason: SafeVerificationFailureReason;
  readonly errorCode: DomainErrorCode;
} {
  if (reason === "pending_key_forbidden_for_delivery") {
    return { safeReason: "pending_key_forbidden_for_delivery", errorCode: "SIGNATURE_VERIFICATION_FAILED" };
  }
  if (reason === "key_revoked") {
    return { safeReason: "key_revoked", errorCode: "SIGNATURE_VERIFICATION_FAILED" };
  }
  if (reason === "key_snapshot_expired") {
    return { safeReason: "key_snapshot_expired", errorCode: "EXPIRED" };
  }
  if (reason === "key_retired" || reason === "key_verify_cutoff_exceeded") {
    return { safeReason: "key_retired_or_expired", errorCode: "SIGNATURE_VERIFICATION_FAILED" };
  }
  return { safeReason: "key_ineligible", errorCode: "SIGNATURE_VERIFICATION_FAILED" };
}

export async function verifyWebhookRequest(
  input: VerifyWebhookRequestInput
): Promise<VerifyWebhookResult> {
  // 1. Method & body framing before expensive parsing
  if (input.method !== "POST") {
    return failResult("invalid_method", "INVALID_VALUE", 400);
  }
  if (!(input.rawBodyBytes instanceof Uint8Array)) {
    return failResult("invalid_body_framing", "INVALID_VALUE", 400);
  }
  if (input.rawBodyBytes.length === 0) {
    return failResult("invalid_body_framing", "INVALID_VALUE", 400);
  }
  if (input.rawBodyBytes.length > WEBHOOK_MAX_BODY_BYTES) {
    return failResult("invalid_body_framing", "PAYLOAD_TOO_LARGE", 413);
  }

  // 2. Single-occurrence raw header & framing validation
  let parsedHeaders: ParsedWebhookHeaders;
  try {
    parsedHeaders = validateRawWebhookHeaders(input.rawHeaders, { requireContentType: true });
  } catch (err) {
    if (err instanceof DomainError && err.code === "PAYLOAD_TOO_LARGE") {
      return failResult("invalid_headers_or_duplicate", "PAYLOAD_TOO_LARGE", 413);
    }
    return failResult("invalid_headers_or_duplicate", "INVALID_VALUE", 400);
  }

  // 3. Explicit configured external target validation & observed route binding
  let expectedAuthority: string;
  let expectedRequestTarget: string;
  try {
    expectedAuthority = validateSignedExternalAuthority(
      input.expectedTarget.externalAuthority,
      input.authorityValidation
    );
    expectedRequestTarget = validateSignedRequestTarget(input.expectedTarget.requestTarget);
  } catch {
    return failResult("target_mismatch", "INVALID_VALUE", 400);
  }

  if (
    input.expectedTarget.observedAuthority !== undefined &&
    input.expectedTarget.observedAuthority !== expectedAuthority
  ) {
    return failResult("target_mismatch", "SIGNATURE_VERIFICATION_FAILED", 401);
  }
  if (
    input.expectedTarget.observedRequestTarget !== undefined &&
    input.expectedTarget.observedRequestTarget !== expectedRequestTarget
  ) {
    return failResult("target_mismatch", "SIGNATURE_VERIFICATION_FAILED", 401);
  }

  // 4. Context scope match before MAC evaluation
  const expectedProjectId = parseProjectId(input.expectedContext.projectId, "expectedContext.projectId");
  const expectedEndpointId = parseEndpointId(
    input.expectedContext.endpointId,
    "expectedContext.endpointId"
  );
  if (parsedHeaders.project_id !== expectedProjectId || parsedHeaders.endpoint_id !== expectedEndpointId) {
    return failResult("context_scope_mismatch", "SIGNATURE_VERIFICATION_FAILED", 401);
  }
  if (
    input.expectedContext.allowedEndpointVersions !== undefined &&
    !input.expectedContext.allowedEndpointVersions.has(parsedHeaders.endpoint_version)
  ) {
    return failResult("context_scope_mismatch", "SIGNATURE_VERIFICATION_FAILED", 401);
  }
  if (input.expectedContext.subscriptionId !== undefined && parsedHeaders.purpose === "delivery") {
    const expectedSubId = parseSubscriptionId(
      input.expectedContext.subscriptionId,
      "expectedContext.subscriptionId"
    );
    if (parsedHeaders.subscription_id !== expectedSubId) {
      return failResult("context_scope_mismatch", "SIGNATURE_VERIFICATION_FAILED", 401);
    }
  }

  // 5. Freshness window check: -300s <= ts <= +30s
  const nowInstant = input.now ?? nowUtcInstant();
  const nowUnixSeconds = input.nowUnixSeconds ?? nowInstant.epochNanoseconds / 1_000_000_000n;
  const pastSeconds = input.freshnessWindow?.pastSeconds ?? WEBHOOK_FRESHNESS_PAST_SECONDS;
  const futureSeconds = input.freshnessWindow?.futureSeconds ?? WEBHOOK_FRESHNESS_FUTURE_SECONDS;
  const signedTs = parseNonNegativeInt64BigInt(parsedHeaders.timestamp_seconds, "timestamp_seconds");
  if (signedTs < nowUnixSeconds - pastSeconds || signedTs > nowUnixSeconds + futureSeconds) {
    return failResult("timestamp_stale_or_future", "SIGNATURE_VERIFICATION_FAILED", 401);
  }

  // 6. Wire body SHA-256 verification before HMAC
  const actualBodySha256 = sha256HexNode(input.rawBodyBytes);
  if (actualBodySha256 !== parsedHeaders.body_sha256) {
    return failResult("body_hash_mismatch", "SIGNATURE_VERIFICATION_FAILED", 401);
  }

  // 7. Key resolution, key lifecycle check, 25-field preimage, and constant-time MAC check
  let matchedKeyId: KeyId | null = null;
  let lastRejection: { safeReason: SafeVerificationFailureReason; errorCode: DomainErrorCode } = {
    safeReason: "mac_mismatch",
    errorCode: "SIGNATURE_VERIFICATION_FAILED"
  };

  for (const sigEntry of parsedHeaders.signatures) {
    const kid = parseKeyId(sigEntry.kid, "signatures.kid");
    const rawKeyResult = await input.keyProvider({
      projectId: expectedProjectId,
      endpointId: expectedEndpointId,
      keyId: kid,
      purpose: parsedHeaders.purpose
    });

    if (rawKeyResult === null) {
      if (matchedKeyId === null && lastRejection.safeReason === "mac_mismatch") {
        lastRejection = { safeReason: "unknown_key", errorCode: "SIGNATURE_VERIFICATION_FAILED" };
      }
      continue;
    }

    const resolved = normalizeResolvedKeyMaterial(rawKeyResult);
    try {
      if (resolved.metadata === undefined) {
        lastRejection = { safeReason: "key_ineligible", errorCode: "SIGNATURE_VERIFICATION_FAILED" };
        continue;
      }

      if (
        (resolved.metadata.projectId !== undefined && resolved.metadata.projectId !== expectedProjectId) ||
        (resolved.metadata.endpointId !== undefined && resolved.metadata.endpointId !== expectedEndpointId) ||
        resolved.metadata.keyId !== kid
      ) {
        lastRejection = { safeReason: "context_scope_mismatch", errorCode: "SIGNATURE_VERIFICATION_FAILED" };
        continue;
      }

      const eligibility = checkKeyVerificationEligibility(
        resolved.metadata,
        parsedHeaders.purpose,
        nowInstant
      );
      if (!eligibility.eligible) {
        lastRejection = mapKeyRejectionReason(eligibility.reason);
        continue;
      }

      const preimage = encodeWebhookSignaturePreimage(
        parsedHeaders.purpose === "delivery"
          ? {
              version: WEBHOOK_PROTOCOL_VERSION,
              purpose: "delivery",
              key_id: kid,
              method: "POST",
              external_authority: expectedAuthority,
              request_target: expectedRequestTarget,
              project_id: parsedHeaders.project_id,
              event_id: parsedHeaders.event_id,
              subscription_id: parsedHeaders.subscription_id,
              endpoint_id: parsedHeaders.endpoint_id,
              endpoint_version: parsedHeaders.endpoint_version,
              signing_policy_version: parsedHeaders.signing_policy_version,
              delivery_id: parsedHeaders.delivery_id,
              delivery_generation: parsedHeaders.delivery_generation,
              attempt_id: parsedHeaders.attempt_id,
              timestamp_seconds: parsedHeaders.timestamp_seconds,
              consumer_event_key: parsedHeaders.consumer_key,
              ordering_domain_id: parsedHeaders.ordering?.ordering_domain_id,
              ordering_key_sha256: parsedHeaders.ordering?.ordering_key_sha256,
              ordering_sequence: parsedHeaders.ordering?.ordering_sequence,
              traceparent: parsedHeaders.traceparent,
              tracestate: parsedHeaders.tracestate,
              wire_body_sha256: actualBodySha256,
              raw_wire_body_bytes: input.rawBodyBytes
            }
          : {
              version: WEBHOOK_PROTOCOL_VERSION,
              purpose: "endpoint_verification",
              key_id: kid,
              method: "POST",
              external_authority: expectedAuthority,
              request_target: expectedRequestTarget,
              project_id: parsedHeaders.project_id,
              endpoint_id: parsedHeaders.endpoint_id,
              endpoint_version: parsedHeaders.endpoint_version,
              signing_policy_version: "0",
              attempt_id: parsedHeaders.attempt_id,
              verification_id: parsedHeaders.verification_id,
              timestamp_seconds: parsedHeaders.timestamp_seconds,
              traceparent: parsedHeaders.traceparent,
              tracestate: parsedHeaders.tracestate,
              wire_body_sha256: actualBodySha256,
              raw_wire_body_bytes: input.rawBodyBytes
            },
        input.authorityValidation
      );

      const expectedMac = computeHmacSha256(resolved.handle, preimage);
      if (constantTimeEqualBytes(expectedMac, sigEntry.mac_bytes)) {
        matchedKeyId = kid;
        break;
      }
      lastRejection = { safeReason: "mac_mismatch", errorCode: "SIGNATURE_VERIFICATION_FAILED" };
    } finally {
      if (resolved.releaseAfterUse === true) {
        resolved.handle.destroy?.();
      }
    }
  }

  if (matchedKeyId === null) {
    return failResult(lastRejection.safeReason, lastRejection.errorCode, 401);
  }

  // 8. Post-MAC strict envelope parsing & scope identity checks
  if (parsedHeaders.purpose === "endpoint_verification") {
    let verificationBody: EndpointVerificationBodyV1;
    try {
      verificationBody = decodeEndpointVerificationBodyBytes(input.rawBodyBytes);
    } catch {
      return failResult("invalid_envelope_payload", "INVALID_VALUE", 400);
    }
    if (
      verificationBody.verification_id !== parsedHeaders.verification_id ||
      verificationBody.endpoint_id !== parsedHeaders.endpoint_id ||
      verificationBody.endpoint_version !== parsedHeaders.endpoint_version ||
      verificationBody.key_id !== matchedKeyId
    ) {
      return failResult("verification_body_mismatch", "SIGNATURE_VERIFICATION_FAILED", 401);
    }

    return Object.freeze({
      ok: true,
      purpose: "endpoint_verification",
      verifiedKeyId: matchedKeyId,
      headers: parsedHeaders,
      bodySha256: actualBodySha256,
      verificationBody
    });
  }

  let decodedEnvelope: DecodedWebhookEnvelope;
  try {
    decodedEnvelope = decodeWebhookEnvelopeBytes(input.rawBodyBytes);
  } catch (err) {
    if (err instanceof DomainError && err.code === "UNSUPPORTED_SCHEMA_VERSION") {
      return failResult("invalid_envelope_payload", "UNSUPPORTED_SCHEMA_VERSION", 422);
    }
    return failResult("invalid_envelope_payload", "INVALID_VALUE", 400);
  }

  if (
    decodedEnvelope.envelope.project_id !== parsedHeaders.project_id ||
    decodedEnvelope.envelope.event_id !== parsedHeaders.event_id
  ) {
    return failResult("envelope_identity_mismatch", "SIGNATURE_VERIFICATION_FAILED", 401);
  }

  if (input.expectedContext.consumerContractScope !== undefined) {
    const recomputedConsumerKey = computeConsumerEventKeySha256({
      project_id: expectedProjectId,
      event_id: parsedHeaders.event_id,
      consumer_contract_scope: input.expectedContext.consumerContractScope
    });
    if (recomputedConsumerKey !== parsedHeaders.consumer_key) {
      return failResult("consumer_key_mismatch", "SIGNATURE_VERIFICATION_FAILED", 401);
    }
  }

  if (input.expectedContext.expectedConsumerEventKey !== undefined) {
    if (input.expectedContext.expectedConsumerEventKey !== parsedHeaders.consumer_key) {
      return failResult("consumer_key_mismatch", "SIGNATURE_VERIFICATION_FAILED", 401);
    }
  }

  return Object.freeze({
    ok: true,
    purpose: "delivery",
    verifiedKeyId: matchedKeyId,
    headers: parsedHeaders,
    bodySha256: actualBodySha256,
    decodedEnvelope
  });
}

export async function assertWebhookRequestVerified(
  input: VerifyWebhookRequestInput
): Promise<VerifyDeliverySuccess | VerifyEndpointVerificationSuccess> {
  const result = await verifyWebhookRequest(input);
  if (result.ok) {
    return result;
  }
  if (result.errorCode === "EXPIRED") {
    throw new ExpiredDomainError({
      code: "EXPIRED",
      message: `Webhook verification rejected (${result.safeReason})`
    });
  }
  if (result.errorCode === "INVALID_VALUE" || result.errorCode === "PAYLOAD_TOO_LARGE" || result.errorCode === "UNSUPPORTED_SCHEMA_VERSION") {
    throw new ValidationDomainError({
      code: result.errorCode,
      message: `Webhook request rejected (${result.safeReason})`
    });
  }
  throw new AuthenticationDomainError({
    code: result.errorCode,
    message: `Webhook signature verification failed (${result.safeReason})`
  });
}
