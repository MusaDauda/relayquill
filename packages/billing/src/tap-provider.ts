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

export interface TapProviderOptions {
  readonly secretKey: string;
  readonly apiBaseUrl?: string | undefined;
  readonly fetchImpl?: typeof fetch | undefined;
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

/**
 * Tap Payments regional adapter serving MENA markets (mada, KNET, BenefitPay, Fawry, local cards).
 */
export function createTapBillingAdapter(options: TapProviderOptions): BillingProviderAdapter {
  const secretKey = options.secretKey.trim();
  if (secretKey.length === 0) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: "Tap secretKey must be non-empty"
    });
  }
  const apiBaseUrl = (options.apiBaseUrl ?? "https://api.tap.company").replace(/\/+$/, "");
  const fetchImpl = options.fetchImpl ?? globalThis.fetch;

  return Object.freeze({
    provider: "tap",

    async createCheckoutSession(input: BillingCheckoutInput): Promise<BillingCheckoutResult> {
      const currency = (input.currency ?? "SAR").trim().toUpperCase();
      const amountMinor = computePlanTotalMinor({
        planTier: input.planTier,
        billingInterval: input.billingInterval,
        seatCount: input.seatCount,
        currency
      });
      // Tap API expects major currency decimal for most currencies (or minor-adjusted major units)
      const amountMajor = Number((amountMinor / 100).toFixed(2));

      const res = await fetchImpl(`${apiBaseUrl}/v2/charges`, {
        method: "POST",
        headers: {
          authorization: `Bearer ${secretKey}`,
          "content-type": "application/json"
        },
        body: JSON.stringify({
          amount: amountMajor,
          currency,
          threeDSecure: true,
          customer: {
            email: input.customerEmail
          },
          source: { id: "src_all" },
          redirect: { url: input.successUrl },
          metadata: {
            org_id: input.orgId,
            plan_tier: input.planTier,
            billing_interval: input.billingInterval,
            seat_count: String(input.seatCount)
          }
        })
      });

      const json = asObject(await res.json().catch(() => ({})));
      const tx = asObject(json["transaction"]);
      const chargeId = optStr(json, "id");
      const checkoutUrl = optStr(tx, "url");
      if (!res.ok || chargeId === undefined || checkoutUrl === undefined) {
        throw new DependencyUnavailableDomainError({
          code: "DEPENDENCY_UNAVAILABLE",
          message: `Tap charge initialization failed (${res.status})`
        });
      }

      return Object.freeze({
        provider: "tap",
        sessionId: chargeId,
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
          message: "Missing Tap webhook signature header"
        });
      }

      const rawDigest = crypto.createHmac("sha256", secretKey).update(rawBody).digest("hex");
      const parsed = asObject(JSON.parse(rawBody.toString("utf8")));
      const chargeId = optStr(parsed, "id") ?? "unknown";
      const currency = (optStr(parsed, "currency") ?? "SAR").toUpperCase();
      const reference = asObject(parsed["reference"]);
      const tx = asObject(parsed["transaction"]);
      const amountStr =
        typeof parsed["amount"] === "number" || typeof parsed["amount"] === "string"
          ? String(parsed["amount"])
          : "";
      const canonicalConcat = [
        `x_id${chargeId}`,
        `x_amount${amountStr}`,
        `x_currency${currency}`,
        `x_gateway_reference${optStr(reference, "gateway") ?? ""}`,
        `x_payment_reference${optStr(reference, "payment") ?? ""}`,
        `x_status${optStr(parsed, "status") ?? ""}`,
        `x_created${optStr(tx, "created") ?? ""}`
      ].join("");
      const canonicalDigest = crypto
        .createHmac("sha256", secretKey)
        .update(canonicalConcat)
        .digest("hex");

      if (
        !timingSafeHexEquals(rawDigest, signatureHeader) &&
        !timingSafeHexEquals(canonicalDigest, signatureHeader)
      ) {
        throw new AuthenticationDomainError({
          code: "SIGNATURE_VERIFICATION_FAILED",
          message: "Invalid Tap webhook HMAC-SHA256 signature"
        });
      }

      const payloadSha256 = crypto.createHash("sha256").update(rawBody).digest("hex");
      const status = (optStr(parsed, "status") ?? "UNKNOWN").toUpperCase();
      const metadata = asObject(parsed["metadata"]);
      const customer = asObject(parsed["customer"]);
      const rawOrgId = optStr(metadata, "org_id");
      const orgId = rawOrgId !== undefined ? parseTenantId(rawOrgId, "metadata.org_id") : undefined;

      let billingEventKind: NormalizedBillingEvent["billingEventKind"] = "ignored";
      if (status === "CAPTURED" || status === "AUTHORIZED") {
        billingEventKind = "checkout_completed_paid";
      } else if (status === "FAILED" || status === "DECLINED" || status === "TIMEDOUT") {
        billingEventKind = "invoice_payment_failed";
      } else if (status === "CANCELLED" || status === "VOID") {
        billingEventKind = "subscription_deleted";
      } else if (status === "DISPUTE_OPEN") {
        billingEventKind = "dispute_created";
      }

      const rawPlan = optStr(metadata, "plan_tier");
      const planTier: PlanTier | undefined =
        rawPlan === "free" || rawPlan === "pro" || rawPlan === "team" || rawPlan === "enterprise"
          ? rawPlan
          : undefined;
      const rawInterval = optStr(metadata, "billing_interval");
      const billingInterval: BillingInterval | undefined =
        rawInterval === "month" || rawInterval === "year" ? rawInterval : undefined;

      const createdMs = Number(tx["created"] ?? nowMs);
      const createdAt = Number.isFinite(createdMs) && createdMs > 0 ? new Date(createdMs) : new Date(nowMs);
      const amountNum = Number(parsed["amount"] ?? 0);

      return Object.freeze({
        provider: "tap",
        externalEventId: `tap:${status}:${chargeId}`,
        rawEventType: `tap.charge.${status.toLowerCase()}`,
        createdAt,
        payloadSha256,
        billingEventKind,
        orgId,
        customerId: optStr(customer, "id") ?? optStr(customer, "email"),
        subscriptionId: chargeId,
        planTier,
        billingInterval,
        currency,
        unitAmountMinor: Number.isFinite(amountNum) ? Math.max(0, Math.round(amountNum * 100)) : undefined,
        seatCount: Number(metadata["seat_count"] ?? 1) || 1,
        currentPeriodStart: createdAt,
        currentPeriodEnd: new Date(createdAt.getTime() + 30 * 24 * 60 * 60 * 1000),
        billingEmail: optStr(customer, "email")
      });
    }
  });
}
