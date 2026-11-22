import {
  PLAN_CATALOG,
  type BillingEventKind,
  type BillingInterval,
  type PlanTier,
  type TenantId
} from "@relayquill/domain";

export const BILLING_PROVIDER_IDS = ["stripe", "paystack", "tap"] as const;
export type BillingProviderId = (typeof BILLING_PROVIDER_IDS)[number];

export interface RegionRoutingDecision {
  readonly provider: BillingProviderId;
  readonly countryCode: string;
  readonly currency: string;
  readonly regionGroup: "africa_paystack" | "mena_tap" | "global_stripe";
  readonly paymentRails: readonly string[];
  readonly supportsTaxAutomation: boolean;
  readonly supportsHostedPortal: boolean;
}

export interface BillingCheckoutInput {
  readonly orgId: TenantId;
  readonly customerEmail: string;
  readonly customerId?: string | undefined;
  readonly planTier: Exclude<PlanTier, "free">;
  readonly billingInterval: BillingInterval;
  readonly seatCount: number;
  readonly countryCode?: string | undefined;
  readonly currency?: string | undefined;
  readonly successUrl: string;
  readonly cancelUrl: string;
  readonly trialDays?: number | undefined;
}

export interface BillingCheckoutResult {
  readonly provider: BillingProviderId;
  readonly sessionId: string;
  readonly checkoutUrl: string;
  readonly currency: string;
  readonly amountMinor: number;
  readonly taxAutomationEnabled: boolean;
}

export interface BillingPortalInput {
  readonly orgId: TenantId;
  readonly customerId: string;
  readonly returnUrl: string;
}

export interface BillingPortalResult {
  readonly provider: BillingProviderId;
  readonly portalUrl: string;
  readonly hostedPortal: boolean;
}

export interface NormalizedBillingEvent {
  readonly provider: BillingProviderId;
  readonly externalEventId: string;
  readonly rawEventType: string;
  readonly createdAt: Date;
  readonly payloadSha256: string;
  readonly billingEventKind: BillingEventKind | "ignored";
  readonly orgId?: TenantId | undefined;
  readonly customerId?: string | undefined;
  readonly subscriptionId?: string | undefined;
  readonly planTier?: PlanTier | undefined;
  readonly billingInterval?: BillingInterval | undefined;
  readonly currency?: string | undefined;
  readonly unitAmountMinor?: number | undefined;
  readonly seatCount?: number | undefined;
  readonly currentPeriodStart?: Date | undefined;
  readonly currentPeriodEnd?: Date | undefined;
  readonly trialEndsAt?: Date | null | undefined;
  readonly cancelAtPeriodEnd?: boolean | undefined;
  readonly billingEmail?: string | undefined;
  readonly billingCountry?: string | undefined;
}

export interface BillingProviderAdapter {
  readonly provider: BillingProviderId;
  createCheckoutSession(input: BillingCheckoutInput): Promise<BillingCheckoutResult>;
  createPortalSession?(input: BillingPortalInput): Promise<BillingPortalResult>;
  verifyAndParseWebhook(
    rawBody: Buffer,
    signatureHeader: string | undefined,
    nowMs: number
  ): NormalizedBillingEvent;
}

const PAYSTACK_COUNTRY_DEFAULTS: Readonly<
  Record<string, { readonly currency: string; readonly rails: readonly string[] }>
> = Object.freeze({
  NG: { currency: "NGN", rails: ["Pay with Bank", "Transfer", "USSD", "Cards"] },
  GH: { currency: "GHS", rails: ["Mobile Money (MTN/Vodafone)", "Cards"] },
  KE: { currency: "KES", rails: ["M-Pesa", "Cards"] },
  ZA: { currency: "ZAR", rails: ["Instant EFT", "SnapScan", "Cards"] },
  CI: { currency: "XOF", rails: ["Orange / Wave Mobile Money", "Cards"] }
});

const TAP_MENA_COUNTRY_DEFAULTS: Readonly<
  Record<string, { readonly currency: string; readonly rails: readonly string[] }>
> = Object.freeze({
  SA: { currency: "SAR", rails: ["mada", "Apple Pay", "STC Pay", "Cards"] },
  KW: { currency: "KWD", rails: ["KNET", "Apple Pay", "Cards"] },
  BH: { currency: "BHD", rails: ["BenefitPay", "Apple Pay", "Cards"] },
  QA: { currency: "QAR", rails: ["NAPS", "Apple Pay", "Cards"] },
  OM: { currency: "OMR", rails: ["OmanNet", "Cards"] },
  EG: { currency: "EGP", rails: ["Fawry", "Meeza", "Cards"] }
});

const FX_MINOR_MULTIPLIERS_FROM_USD: Readonly<Record<string, number>> = Object.freeze({
  USD: 1,
  EUR: 0.92,
  GBP: 0.79,
  AED: 3.67,
  NGN: 1600,
  GHS: 15.5,
  KES: 129,
  ZAR: 18,
  XOF: 605,
  SAR: 3.75,
  KWD: 0.31,
  BHD: 0.38,
  QAR: 3.64,
  OMR: 0.39,
  EGP: 49.5
});

/**
 * Selects the optimal payment processor and default currency rails for an organization's ISO country code.
 */
export function resolveBillingProviderForCountry(
  rawCountry?: string,
  preferredCurrency?: string
): RegionRoutingDecision {
  const countryCode = (rawCountry ?? "US").trim().toUpperCase().slice(0, 2) || "US";
  const requestedCurrency = preferredCurrency?.trim().toUpperCase();

  const paystackCfg = PAYSTACK_COUNTRY_DEFAULTS[countryCode];
  if (paystackCfg !== undefined) {
    return Object.freeze({
      provider: "paystack",
      countryCode,
      currency: requestedCurrency && requestedCurrency.length === 3 ? requestedCurrency : paystackCfg.currency,
      regionGroup: "africa_paystack",
      paymentRails: paystackCfg.rails,
      supportsTaxAutomation: false,
      supportsHostedPortal: false
    });
  }

  const tapCfg = TAP_MENA_COUNTRY_DEFAULTS[countryCode];
  if (tapCfg !== undefined) {
    return Object.freeze({
      provider: "tap",
      countryCode,
      currency: requestedCurrency && requestedCurrency.length === 3 ? requestedCurrency : tapCfg.currency,
      regionGroup: "mena_tap",
      paymentRails: tapCfg.rails,
      supportsTaxAutomation: false,
      supportsHostedPortal: false
    });
  }

  const stripeDefaultCurrency =
    countryCode === "GB"
      ? "GBP"
      : countryCode === "AE"
        ? "AED"
        : ["DE", "FR", "NL", "ES", "IT", "IE", "BE", "AT", "FI", "PT"].includes(countryCode)
          ? "EUR"
          : "USD";

  return Object.freeze({
    provider: "stripe",
    countryCode,
    currency:
      requestedCurrency && requestedCurrency.length === 3 ? requestedCurrency : stripeDefaultCurrency,
    regionGroup: "global_stripe",
    paymentRails: ["Cards", "Apple Pay", "Google Pay", "Link", "SEPA / ACH"],
    supportsTaxAutomation: true,
    supportsHostedPortal: true
  });
}

/**
 * Computes plan + seat total in integer minor units (converted cleanly for regional gateways when USD is not forced).
 */
export function computePlanTotalMinor(input: {
  readonly planTier: PlanTier;
  readonly billingInterval: BillingInterval;
  readonly seatCount: number;
  readonly currency?: string | undefined;
}): number {
  const spec = PLAN_CATALOG[input.planTier];
  const baseUsdMinor =
    input.billingInterval === "year" && spec.annualPriceMinor !== null
      ? spec.annualPriceMinor
      : input.planTier === "enterprise" && input.billingInterval === "year"
        ? spec.monthlyPriceMinor * 10
        : spec.monthlyPriceMinor;

  const extraSeats = Math.max(0, Math.trunc(input.seatCount) - spec.maxSeats);
  const addonMultiplier = input.billingInterval === "year" ? 10 : 1;
  const totalUsdMinor = baseUsdMinor + extraSeats * spec.seatAddonMinor * addonMultiplier;

  const cur = (input.currency ?? "USD").trim().toUpperCase();
  const rate = FX_MINOR_MULTIPLIERS_FROM_USD[cur] ?? 1;
  return Math.max(0, Math.round(totalUsdMinor * rate));
}
