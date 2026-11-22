import crypto from "node:crypto";
import {
  AuthenticationDomainError,
  DependencyUnavailableDomainError,
  parseTenantId,
  ValidationDomainError,
  type BillingInterval,
  type PlanTier
} from "@relayquill/domain";
import {
  computePlanTotalMinor,
  type BillingCheckoutInput,
  type BillingCheckoutResult,
  type BillingProviderAdapter,
  type NormalizedBillingEvent
} from "./regional-router.js";

export interface PaystackProviderOptions {
  readonly secretKey: string;
  readonly apiBaseUrl?: string | undefined;
  readonly planCodes?: Readonly<Partial<Record<`${Exclude<PlanTier, "free">}_${BillingInterval}`, string>>> | undefined;
  readonly fetchImpl?: typeof fetch | undefined;
}

function timingSafeHexEquals(expectedHex: string, actualHex: string): boolean {
  const cleanExpected = expectedHex.trim().toLowerCase();
  const cleanActual = actualHex.trim().toLowerCase();
  if (
    cleanExpected.length === 0 ||
    cleanExpected.length !== cleanActual.length ||
    !/^[0-9a-f]+$/.test(cleanActual)
  ) {
    return false;
  }
  return crypto.timingSafeEqual(Buffer.from(cleanExpected, "hex"), Buffer.from(cleanActual, "hex"));
}

function asObject(val: unknown): Record<string, unknown> {
  return val !== null && typeof val === "object" && !Array.isArray(val)
    ? (val as Record<string, unknown>)
    : {};
}

function optStr(obj: Record<string, unknown>, key: string): string | undefined {
  const v = obj[key];
  return typeof v === "string" && v.trim().length > 0 ? v.trim() : undefined;
}

function parseOptionalPlanTier(raw: string | undefined): PlanTier | undefined {
  return raw === "free" || raw === "pro" || raw === "team" || raw === "enterprise"
    ? raw
    : undefined;
}

function parseOptionalInterval(raw: string | undefined): BillingInterval | undefined {
  return raw === "month" || raw === "year" ? raw : undefined;
}

/**
 * Paystack billing adapter serving Nigeria, Ghana, Kenya, South Africa, and Côte d'Ivoire rails.
 */
export function createPaystackBillingAdapter(
  options: PaystackProviderOptions
): BillingProviderAdapter {
  const secretKey = options.secretKey.trim();
  if (secretKey.length === 0) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: "Paystack secretKey must be non-empty"
    });
  }
  const apiBaseUrl = (options.apiBaseUrl ?? "https://api.paystack.co").replace(/\/+$/, "");
  const fetchImpl = options.fetchImpl ?? globalThis.fetch;

  return Object.freeze({
    provider: "paystack",

    async createCheckoutSession(input: BillingCheckoutInput): Promise<BillingCheckoutResult> {
      const currency = (input.currency ?? "NGN").trim().toUpperCase();
      const amountMinor = computePlanTotalMinor({
        planTier: input.planTier,
        billingInterval: input.billingInterval,
        seatCount: input.seatCount,
        currency
      });
      const planCode = options.planCodes?.[`${input.planTier}_${input.billingInterval}`];

      const payload: Record<string, unknown> = {
        email: input.customerEmail,
        amount: String(amountMinor),
        currency,
        callback_url: input.successUrl,
        metadata: {
          org_id: input.orgId,
          plan_tier: input.planTier,
          billing_interval: input.billingInterval,
          seat_count: input.seatCount,
          cancel_action: input.cancelUrl
        }
      };
      if (planCode !== undefined && planCode.trim().length > 0) {
        payload["plan"] = planCode.trim();
      }

      const res = await fetchImpl(`${apiBaseUrl}/transaction/initialize`, {
        method: "POST",
        headers: {
          authorization: `Bearer ${secretKey}`,
          "content-type": "application/json"
        },
        body: JSON.stringify(payload)
      });

      const bodyJson = asObject(await res.json().catch(() => ({})));
      if (!res.ok || bodyJson["status"] !== true) {
        throw new DependencyUnavailableDomainError({
          code: "DEPENDENCY_UNAVAILABLE",
          message: `Paystack initialize failed (${res.status}): ${optStr(bodyJson, "message") ?? "unknown error"}`
        });
      }
      const data = asObject(bodyJson["data"]);
      const checkoutUrl = optStr(data, "authorization_url");
      const reference = optStr(data, "reference") ?? optStr(data, "access_code");
      if (checkoutUrl === undefined || reference === undefined) {
        throw new DependencyUnavailableDomainError({
          code: "DEPENDENCY_UNAVAILABLE",
          message: "Paystack initialize response lacked authorization_url or reference"
        });
      }

      return Object.freeze({
        provider: "paystack",
        sessionId: reference,
        checkoutUrl,
        currency,
        amountMinor,
        taxAutomationEnabled: false
      });
    },

    verifyAndParseWebhook(
      rawBody: Buffer,
      signatureHeader: string | undefined,
      nowMs: number
    ): NormalizedBillingEvent {
      if (signatureHeader === undefined || signatureHeader.trim().length === 0) {
        throw new AuthenticationDomainError({
          code: "SIGNATURE_VERIFICATION_FAILED",
          message: "Missing x-paystack-signature header"
        });
      }
      const expectedHex = crypto.createHmac("sha512", secretKey).update(rawBody).digest("hex");
      if (!timingSafeHexEquals(expectedHex, signatureHeader)) {
        throw new AuthenticationDomainError({
          code: "SIGNATURE_VERIFICATION_FAILED",
          message: "Invalid Paystack webhook HMAC-SHA512 signature"
        });
      }

      const parsed = asObject(JSON.parse(rawBody.toString("utf8")));
      const rawEventType = optStr(parsed, "event") ?? "unknown";
      const data = asObject(parsed["data"]);
      const metadata = asObject(data["metadata"]);
      const customer = asObject(data["customer"]);
      const plan = asObject(data["plan"]);
      const payloadSha256 = crypto.createHash("sha256").update(rawBody).digest("hex");

      const dataId =
        optStr(data, "reference") ??
        (typeof data["id"] === "string" || typeof data["id"] === "number"
          ? String(data["id"])
          : payloadSha256.slice(0, 16));
      const externalEventId = `paystack:${rawEventType}:${dataId}`;
      const rawCreatedAt =
        optStr(data, "paid_at") ?? optStr(data, "created_at") ?? new Date(nowMs).toISOString();
      const createdAt = Number.isNaN(Date.parse(rawCreatedAt))
        ? new Date(nowMs)
        : new Date(rawCreatedAt);

      const rawOrgId = optStr(metadata, "org_id");
      const orgId = rawOrgId !== undefined ? parseTenantId(rawOrgId, "metadata.org_id") : undefined;
      const customerId = optStr(customer, "customer_code") ?? optStr(customer, "email");
      const subscriptionId =
        optStr(data, "subscription_code") ??
        optStr(asObject(data["subscription"]), "subscription_code");

      let billingEventKind: NormalizedBillingEvent["billingEventKind"] = "ignored";
      if (rawEventType === "charge.success") {
        billingEventKind = "checkout_completed_paid";
      } else if (rawEventType === "subscription.create" || rawEventType === "invoice.update") {
        billingEventKind = "invoice_paid";
      } else if (rawEventType === "invoice.payment_failed") {
        billingEventKind = "invoice_payment_failed";
      } else if (rawEventType === "subscription.not_renew") {
        billingEventKind = "cancel_scheduled";
      } else if (rawEventType === "subscription.disable") {
        billingEventKind = "subscription_deleted";
      } else if (rawEventType === "charge.dispute.create") {
        billingEventKind = "dispute_created";
      } else if (rawEventType === "charge.dispute.resolve") {
        const status = optStr(data, "status");
        billingEventKind = status === "won" ? "dispute_won" : "dispute_lost";
      }

      const periodEndRaw = optStr(data, "next_payment_date");
      const currentPeriodEnd =
        periodEndRaw !== undefined && !Number.isNaN(Date.parse(periodEndRaw))
          ? new Date(periodEndRaw)
          : new Date(createdAt.getTime() + 30 * 24 * 60 * 60 * 1000);

      return Object.freeze({
        provider: "paystack",
        externalEventId,
        rawEventType,
        createdAt,
        payloadSha256,
        billingEventKind,
        orgId,
        customerId,
        subscriptionId,
        planTier: parseOptionalPlanTier(optStr(metadata, "plan_tier")),
        billingInterval:
          parseOptionalInterval(optStr(metadata, "billing_interval")) ??
          parseOptionalInterval(optStr(plan, "interval")),
        currency: (optStr(data, "currency") ?? "NGN").toUpperCase(),
        unitAmountMinor:
          typeof data["amount"] === "number" ? Math.max(0, Math.trunc(data["amount"])) : undefined,
        seatCount:
          typeof metadata["seat_count"] === "number"
            ? Math.max(1, Math.trunc(metadata["seat_count"]))
            : 1,
        currentPeriodStart: createdAt,
        currentPeriodEnd,
        cancelAtPeriodEnd: rawEventType === "subscription.not_renew",
        billingEmail: optStr(customer, "email")
      });
    }
  });
}
