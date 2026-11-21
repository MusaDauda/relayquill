import crypto from "node:crypto";
import Stripe from "stripe";
import { parseCanonicalUtcTimestamp, canonicalizeJson, sha256Hex, type CanonicalJsonValue } from "@relayquill/contracts";
import { type AccountMode, type ProviderBindingRecord, type ProviderKind } from "./db.js";

const PAYSTACK_SIGNATURE_HEX_REGEX = /^[0-9a-f]{128}$/;

export class ProviderVerificationError extends Error {
  readonly code: string;
  readonly httpStatus: number;

  constructor(options: {
    readonly code: string;
    readonly httpStatus: number;
    readonly message: string;
    readonly cause?: unknown;
  }) {
    super(options.message, options.cause !== undefined ? { cause: options.cause } : undefined);
    this.name = new.target.name;
    this.code = options.code;
    this.httpStatus = options.httpStatus;
  }
}

export interface NormalizedProviderCallback {
  readonly provider: ProviderKind;
  readonly accountMode: AccountMode;
  readonly payloadProfile: string;
  readonly providerEventId: string | null;
  readonly eventType: string;
  readonly objectReference: string | null;
  readonly providerBusinessTime: string | null;
  readonly rawBodySha256Hex: string;
  readonly identityProfile: string;
  readonly semanticKeySha256Hex: string;
  readonly normalizedFacts: Readonly<Record<string, unknown>>;
  readonly normalizedFactsSha256Hex: string;
  readonly businessKey: string;
  readonly requestKey: string;
}

const stripeVerifierClient = new Stripe("rk_test_webhook_signature_verifier_only");

export async function verifyStripeWebhookCallback(params: {
  readonly rawBodyBytes: Uint8Array;
  readonly signatureHeader: string | undefined;
  readonly webhookSecret: string;
  readonly toleranceSeconds?: number | undefined;
  readonly receivedAtSeconds?: number | undefined;
}): Promise<Stripe.Event> {
  if (params.signatureHeader === undefined || params.signatureHeader.trim().length === 0) {
    throw new ProviderVerificationError({
      code: "MISSING_STRIPE_SIGNATURE",
      httpStatus: 401,
      message: "Missing Stripe-Signature header"
    });
  }
  const tolerance = params.toleranceSeconds ?? 300;
  try {
    return await stripeVerifierClient.webhooks.constructEventAsync(
      Buffer.from(params.rawBodyBytes),
      params.signatureHeader,
      params.webhookSecret,
      tolerance,
      undefined,
      params.receivedAtSeconds
    );
  } catch (err) {
    throw new ProviderVerificationError({
      code: "STRIPE_SIGNATURE_VERIFICATION_FAILED",
      httpStatus: 401,
      message: err instanceof Error ? err.message : "Stripe signature verification failed",
      cause: err
    });
  }
}

export function verifyPaystackWebhookCallback(params: {
  readonly rawBodyBytes: Uint8Array;
  readonly signatureHeader: string | undefined;
  readonly webhookSecret: string;
}): Readonly<Record<string, unknown>> {
  if (params.signatureHeader === undefined || params.signatureHeader.trim().length === 0) {
    throw new ProviderVerificationError({
      code: "MISSING_PAYSTACK_SIGNATURE",
      httpStatus: 401,
      message: "Missing x-paystack-signature header"
    });
  }
  const sig = params.signatureHeader.trim();
  if (!PAYSTACK_SIGNATURE_HEX_REGEX.test(sig)) {
    throw new ProviderVerificationError({
      code: "INVALID_PAYSTACK_SIGNATURE_FORMAT",
      httpStatus: 401,
      message: "x-paystack-signature must be 128 lowercase hex characters"
    });
  }

  const expectedDigest = crypto
    .createHmac("sha512", params.webhookSecret)
    .update(params.rawBodyBytes)
    .digest();
  const actualDigest = Buffer.from(sig, "hex");
  if (
    expectedDigest.byteLength !== actualDigest.byteLength ||
    !crypto.timingSafeEqual(expectedDigest, actualDigest)
  ) {
    throw new ProviderVerificationError({
      code: "PAYSTACK_SIGNATURE_VERIFICATION_FAILED",
      httpStatus: 401,
      message: "Paystack HMAC-SHA512 verification failed"
    });
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(Buffer.from(params.rawBodyBytes).toString("utf8"));
  } catch (err) {
    throw new ProviderVerificationError({
      code: "INVALID_PAYSTACK_JSON",
      httpStatus: 400,
      message: "Invalid Paystack JSON payload",
      cause: err
    });
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new ProviderVerificationError({
      code: "INVALID_PAYSTACK_OBJECT",
      httpStatus: 400,
      message: "Paystack webhook payload must be a JSON object"
    });
  }
  return parsed as Readonly<Record<string, unknown>>;
}

function readOptionalNonEmptyString(val: unknown): string | null {
  if (typeof val === "string" && val.trim().length > 0) {
    return val.trim();
  }
  if (typeof val === "number" && Number.isFinite(val)) {
    return String(val);
  }
  return null;
}

function normalizeIsoTimestamp(val: unknown): string | null {
  if (typeof val === "number" && Number.isFinite(val) && val >= 0) {
    return parseCanonicalUtcTimestamp(new Date(val * 1000).toISOString(), "provider_business_time");
  }
  if (typeof val === "string" && val.trim().length > 0) {
    try {
      return parseCanonicalUtcTimestamp(val.trim(), "provider_business_time");
    } catch {
      const parsedMs = Date.parse(val.trim());
      if (Number.isFinite(parsedMs)) {
        return parseCanonicalUtcTimestamp(new Date(parsedMs).toISOString(), "provider_business_time");
      }
    }
  }
  return null;
}

function normalizeSafeBusinessKey(raw: string): string {
  const sanitized = raw.replace(/[^a-zA-Z0-9:._-]/g, "_").slice(0, 200);
  return sanitized.length > 0 ? sanitized : "provider_event";
}

function normalizeSafeRequestKey(raw: string): string {
  const sanitized = raw.replace(/[^a-zA-Z0-9:._-]/g, "_");
  if (sanitized.length === 0) {
    return "pi_request";
  }
  if (sanitized.length <= 128) {
    return sanitized;
  }
  const digest = crypto.createHash("sha256").update(sanitized, "utf8").digest("hex").slice(0, 48);
  return `${sanitized.slice(0, 79)}_${digest}`;
}

export function normalizeStripeCallback(params: {
  readonly binding: ProviderBindingRecord;
  readonly event: Stripe.Event;
  readonly rawBodyBytes: Uint8Array;
}): NormalizedProviderCallback {
  const rawBodySha256Hex = sha256Hex(params.rawBodyBytes);
  const providerEventId = readOptionalNonEmptyString(params.event.id);
  const eventType = readOptionalNonEmptyString(params.event.type) ?? "stripe.unknown";
  const dataObj = params.event.data?.object as unknown as Readonly<Record<string, unknown>> | undefined;
  const objectReference =
    dataObj !== undefined ? readOptionalNonEmptyString(dataObj["id"]) : null;
  const providerBusinessTime = normalizeIsoTimestamp(params.event.created);
  const expectedMode: AccountMode = params.event.livemode ? "live" : "test";
  if (expectedMode !== params.binding.accountMode) {
    throw new ProviderVerificationError({
      code: "ACCOUNT_MODE_MISMATCH",
      httpStatus: 401,
      message: `Stripe livemode=${String(params.event.livemode)} does not match binding mode "${params.binding.accountMode}"`
    });
  }

  const identityProfile = "stripe.event.v1";
  const semanticSeed =
    providerEventId !== null
      ? `stripe:${params.binding.id}:${providerEventId}`
      : `stripe:${params.binding.id}:raw:${rawBodySha256Hex}`;
  const semanticKeySha256Hex = crypto.createHash("sha256").update(semanticSeed, "utf8").digest("hex");

  const normalizedFacts: Record<string, unknown> = {
    schema_version: 1,
    provider: "stripe",
    account_mode: params.binding.accountMode,
    payload_profile: params.binding.payloadProfile,
    provider_event_id: providerEventId,
    event_type: eventType,
    object_reference: objectReference,
    provider_business_time: providerBusinessTime,
    api_version: params.event.api_version ?? null,
    data_object: dataObj ?? null
  };
  const canonicalFacts = canonicalizeJson(
    normalizedFacts as unknown as CanonicalJsonValue,
    "normalized_facts"
  );
  const normalizedFactsSha256Hex = sha256Hex(Buffer.from(canonicalFacts, "utf8"));
  const businessKey = normalizeSafeBusinessKey(
    providerEventId !== null
      ? `stripe:${params.binding.id}:${providerEventId}`
      : `stripe:${params.binding.id}:${rawBodySha256Hex}`
  );
  const requestKey = normalizeSafeRequestKey(`pi:${businessKey}`);

  return {
    provider: "stripe",
    accountMode: params.binding.accountMode,
    payloadProfile: params.binding.payloadProfile,
    providerEventId,
    eventType,
    objectReference,
    providerBusinessTime,
    rawBodySha256Hex,
    identityProfile,
    semanticKeySha256Hex,
    normalizedFacts,
    normalizedFactsSha256Hex,
    businessKey,
    requestKey
  };
}

export function normalizePaystackCallback(params: {
  readonly binding: ProviderBindingRecord;
  readonly payload: Readonly<Record<string, unknown>>;
  readonly rawBodyBytes: Uint8Array;
}): NormalizedProviderCallback {
  const rawBodySha256Hex = sha256Hex(params.rawBodyBytes);
  const eventType = readOptionalNonEmptyString(params.payload["event"]) ?? "paystack.unknown";
  const rawData =
    typeof params.payload["data"] === "object" &&
    params.payload["data"] !== null &&
    !Array.isArray(params.payload["data"])
      ? (params.payload["data"] as Readonly<Record<string, unknown>>)
      : undefined;

  const dataId = rawData !== undefined ? readOptionalNonEmptyString(rawData["id"]) : null;
  const topId = readOptionalNonEmptyString(params.payload["id"]);
  const providerEventId = topId ?? dataId;
  const objectReference =
    (rawData !== undefined ? readOptionalNonEmptyString(rawData["reference"]) : null) ?? dataId;
  const providerBusinessTime =
    normalizeIsoTimestamp(rawData?.["paid_at"]) ??
    normalizeIsoTimestamp(rawData?.["created_at"]) ??
    normalizeIsoTimestamp(rawData?.["createdAt"]);

  if (rawData !== undefined && typeof rawData["domain"] === "string") {
    const payloadDomain = rawData["domain"];
    if (payloadDomain === "live" || payloadDomain === "test") {
      if (payloadDomain !== params.binding.accountMode) {
        throw new ProviderVerificationError({
          code: "ACCOUNT_MODE_MISMATCH",
          httpStatus: 401,
          message: `Paystack domain="${payloadDomain}" does not match binding mode "${params.binding.accountMode}"`
        });
      }
    }
  }

  const identityProfile = "paystack.event.v1";
  const semanticAnchor = providerEventId ?? objectReference ?? rawBodySha256Hex;
  const semanticSeed = `paystack:${params.binding.id}:${eventType}:${semanticAnchor}`;
  const semanticKeySha256Hex = crypto.createHash("sha256").update(semanticSeed, "utf8").digest("hex");

  const normalizedFacts: Record<string, unknown> = {
    schema_version: 1,
    provider: "paystack",
    account_mode: params.binding.accountMode,
    payload_profile: params.binding.payloadProfile,
    provider_event_id: providerEventId,
    event_type: eventType,
    object_reference: objectReference,
    provider_business_time: providerBusinessTime,
    data: rawData ?? null
  };
  const canonicalFacts = canonicalizeJson(
    normalizedFacts as unknown as CanonicalJsonValue,
    "normalized_facts"
  );
  const normalizedFactsSha256Hex = sha256Hex(Buffer.from(canonicalFacts, "utf8"));
  const businessKey = normalizeSafeBusinessKey(
    `paystack:${params.binding.id}:${eventType}:${semanticAnchor}`
  );
  const requestKey = normalizeSafeRequestKey(`pi:${businessKey}`);

  return {
    provider: "paystack",
    accountMode: params.binding.accountMode,
    payloadProfile: params.binding.payloadProfile,
    providerEventId,
    eventType,
    objectReference,
    providerBusinessTime,
    rawBodySha256Hex,
    identityProfile,
    semanticKeySha256Hex,
    normalizedFacts,
    normalizedFactsSha256Hex,
    businessKey,
    requestKey
  };
}
