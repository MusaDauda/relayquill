import crypto from "node:crypto";
import Stripe from "stripe";
import {
  AuthenticationDomainError,
  DEFAULT_SAAS_TAX_CODE,
  parseTenantId,
  PLAN_CATALOG,
  ValidationDomainError,
  type BillingInterval,
  type PlanTier
} from "@relayquill/domain";
import {
  computePlanTotalMinor,
  type BillingCheckoutInput,
  type BillingCheckoutResult,
  type BillingPortalInput,
  type BillingPortalResult,
  type BillingProviderAdapter,
  type NormalizedBillingEvent
} from "./regional-router.js";

export const STRIPE_PINNED_API_VERSION = "2026-10-28.endive" as const;

export interface CreatePinnedStripeClientOptions {
  readonly apiKey: string;
  readonly host?: string | undefined;
  readonly port?: number | undefined;
  readonly protocol?: "http" | "https" | undefined;
  readonly allowNonRestrictedKeyForLocalMock?: boolean | undefined;
}

export interface StripeBillingProviderOptions {
  readonly client: Stripe;
  readonly webhookSecret: string;
  readonly webhookToleranceSeconds?: number | undefined;
  readonly enableAutomaticTax?: boolean | undefined;
  readonly collectTaxIds?: boolean | undefined;
  readonly priceIds?: Readonly<
    Partial<Record<`${Exclude<PlanTier, "free">}_${BillingInterval}`, string>>
  > | undefined;
  readonly productIds?: Readonly<Partial<Record<Exclude<PlanTier, "free">, string>>> | undefined;
}

function isLoopbackHost(host: string | undefined): boolean {
  if (host === undefined) {
    return false;
  }
  const clean = host.trim().toLowerCase();
  return clean === "127.0.0.1" || clean === "localhost" || clean === "::1";
}

/**
 * Instantiates an isolated `Stripe` SDK client pinned to `2026-10-28.endive` with `rk_` key enforcement.
 */
export function createPinnedStripeClient(options: CreatePinnedStripeClientOptions): Stripe {
  const apiKey = options.apiKey.trim();
  if (apiKey.length === 0) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: "Stripe API key must be non-empty"
    });
  }
  const allowMock =
    options.allowNonRestrictedKeyForLocalMock === true && isLoopbackHost(options.host);
  if (!apiKey.startsWith("rk_") && !allowMock) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: "Production Stripe runtime requires a least-privilege Restricted API Key (rk_*)"
    });
  }

  return new Stripe(apiKey, {
    apiVersion: STRIPE_PINNED_API_VERSION,
    maxNetworkRetries: 1,
    timeout: 10_000,
    ...(options.host !== undefined ? { host: options.host } : {}),
    ...(options.port !== undefined ? { port: options.port } : {}),
    ...(options.protocol !== undefined ? { protocol: options.protocol } : {})
  });
}

function refId(val: string | { readonly id: string } | null | undefined): string | undefined {
  if (typeof val === "string" && val.length > 0) {
    return val;
  }
  if (val !== null && typeof val === "object" && typeof val.id === "string") {
    return val.id;
  }
  return undefined;
}

function parsePlanTierMeta(meta: Stripe.Metadata | null | undefined): PlanTier | undefined {
  const raw = meta?.["plan_tier"];
  return raw === "free" || raw === "pro" || raw === "team" || raw === "enterprise"
    ? raw
    : undefined;
}

function parseIntervalMeta(
  meta: Stripe.Metadata | null | undefined
): BillingInterval | undefined {
  const raw = meta?.["billing_interval"];
  return raw === "month" || raw === "year" ? raw : undefined;
}

function parseOrgIdFromMetadata(meta: Stripe.Metadata | null | undefined, clientRef?: string | null) {
  const candidate = meta?.["org_id"] ?? clientRef ?? undefined;
  if (typeof candidate !== "string" || candidate.trim().length === 0) {
    return undefined;
  }
  return parseTenantId(candidate.trim(), "org_id");
}

/**
 * Stripe billing adapter supporting Checkout Sessions, Dynamic Payment Methods, Stripe Tax, Customer Portal, and signed webhooks.
 */
export function createStripeBillingAdapter(
  options: StripeBillingProviderOptions
): BillingProviderAdapter {
  const webhookSecret = options.webhookSecret.trim();
  if (webhookSecret.length === 0) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: "Stripe webhookSecret must be non-empty"
    });
  }
  const toleranceSeconds = Math.max(0, options.webhookToleranceSeconds ?? 300);
  const enableAutomaticTax = options.enableAutomaticTax !== false;
  const collectTaxIds = options.collectTaxIds !== false;

  return Object.freeze({
    provider: "stripe",

    async createCheckoutSession(input: BillingCheckoutInput): Promise<BillingCheckoutResult> {
      const currency = (input.currency ?? "USD").trim().toLowerCase();
      const amountMinor = computePlanTotalMinor({
        planTier: input.planTier,
        billingInterval: input.billingInterval,
        seatCount: input.seatCount,
        currency: currency.toUpperCase()
      });
      const priceKey = `${input.planTier}_${input.billingInterval}` as const;
      const configuredPriceId = options.priceIds?.[priceKey];
      const configuredProductId = options.productIds?.[input.planTier];
      const spec = PLAN_CATALOG[input.planTier];

      const lineItem: Stripe.Checkout.SessionCreateParams.LineItem =
        configuredPriceId !== undefined && configuredPriceId.trim().length > 0
          ? { price: configuredPriceId.trim(), quantity: 1 }
          : {
              quantity: 1,
              price_data: {
                currency,
                unit_amount: amountMinor,
                tax_behavior: "exclusive",
                recurring: {
                  interval: input.billingInterval
                },
                ...(configuredProductId !== undefined
                  ? { product: configuredProductId }
                  : {
                      product_data: {
                        name: `Relayquill ${input.planTier.toUpperCase()} Plan`,
                        tax_code: DEFAULT_SAAS_TAX_CODE
                      }
                    })
              }
            };

      const suffix = crypto.randomBytes(4).toString("hex");
      // Intentionally omit `payment_method_types` so Stripe dynamically renders eligible global/local rails.
      const params: Stripe.Checkout.SessionCreateParams = {
        mode: "subscription",
        client_reference_id: input.orgId,
        ...(input.customerId !== undefined && !input.customerId.startsWith("cus_local_")
          ? { customer: input.customerId }
          : { customer_email: input.customerEmail }),
        line_items: [lineItem],
        automatic_tax: { enabled: enableAutomaticTax },
        tax_id_collection: { enabled: collectTaxIds },
        billing_address_collection: "auto",
        integration_identifier: `relayquill_sub_${suffix}`,
        metadata: {
          org_id: input.orgId,
          plan_tier: input.planTier,
          billing_interval: input.billingInterval,
          seat_count: String(Math.max(spec.maxSeats, input.seatCount))
        },
        subscription_data: {
          ...(input.trialDays !== undefined && input.trialDays > 0
            ? { trial_period_days: input.trialDays }
            : {}),
          metadata: {
            org_id: input.orgId,
            plan_tier: input.planTier,
            billing_interval: input.billingInterval,
            seat_count: String(Math.max(spec.maxSeats, input.seatCount))
          }
        },
        success_url: input.successUrl,
        cancel_url: input.cancelUrl
      };

      const session = await options.client.checkout.sessions.create(params);
      if (typeof session.url !== "string" || session.url.length === 0) {
        throw new ValidationDomainError({
          code: "INVALID_VALUE",
          message: "Stripe Checkout Session returned without hosted redirect URL"
        });
      }

      return Object.freeze({
        provider: "stripe",
        sessionId: session.id,
        checkoutUrl: session.url,
        currency: currency.toUpperCase(),
        amountMinor,
        taxAutomationEnabled: enableAutomaticTax
      });
    },

    async createPortalSession(input: BillingPortalInput): Promise<BillingPortalResult> {
      const portal = await options.client.billingPortal.sessions.create({
        customer: input.customerId,
        return_url: input.returnUrl
      });
      return Object.freeze({
        provider: "stripe",
        portalUrl: portal.url,
        hostedPortal: true
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
          message: "Missing stripe-signature webhook header"
        });
      }

      let event: Stripe.Event;
      try {
        event = options.client.webhooks.constructEvent(
          rawBody,
          signatureHeader,
          webhookSecret,
          toleranceSeconds,
          undefined,
          nowMs
        );
      } catch (err) {
        throw new AuthenticationDomainError({
          code: "SIGNATURE_VERIFICATION_FAILED",
          message: err instanceof Error ? err.message : "Stripe signature verification failed"
        });
      }

      const payloadSha256 = crypto.createHash("sha256").update(rawBody).digest("hex");
      const createdAt = new Date(event.created * 1000);

      switch (event.type) {
        case "checkout.session.completed":
        case "checkout.session.async_payment_succeeded": {
          const session = event.data.object;
          const unpaid = session.payment_status === "unpaid";
          return Object.freeze({
            provider: "stripe",
            externalEventId: event.id,
            rawEventType: event.type,
            createdAt,
            payloadSha256,
            billingEventKind: unpaid ? "ignored" : "checkout_completed_paid",
            orgId: parseOrgIdFromMetadata(session.metadata, session.client_reference_id),
            customerId: refId(session.customer),
            subscriptionId: refId(session.subscription),
            planTier: parsePlanTierMeta(session.metadata),
            billingInterval: parseIntervalMeta(session.metadata),
            currency: session.currency?.toUpperCase(),
            unitAmountMinor: session.amount_total ?? undefined,
            seatCount: Number(session.metadata?.["seat_count"] ?? 1) || 1,
            billingEmail: session.customer_details?.email ?? session.customer_email ?? undefined,
            billingCountry: session.customer_details?.address?.country ?? undefined
          });
        }

        case "checkout.session.async_payment_failed": {
          const session = event.data.object;
          return Object.freeze({
            provider: "stripe",
            externalEventId: event.id,
            rawEventType: event.type,
            createdAt,
            payloadSha256,
            billingEventKind: "invoice_payment_failed",
            orgId: parseOrgIdFromMetadata(session.metadata, session.client_reference_id),
            customerId: refId(session.customer),
            subscriptionId: refId(session.subscription)
          });
        }

        case "invoice.paid":
        case "invoice.payment_failed": {
          const invoice = event.data.object;
          const subDetails = invoice.parent?.subscription_details;
          const subId = refId(subDetails?.subscription);
          const subMeta = subDetails?.metadata ?? invoice.metadata;
          return Object.freeze({
            provider: "stripe",
            externalEventId: event.id,
            rawEventType: event.type,
            createdAt,
            payloadSha256,
            billingEventKind:
              event.type === "invoice.paid" ? "invoice_paid" : "invoice_payment_failed",
            orgId: parseOrgIdFromMetadata(subMeta),
            customerId: refId(invoice.customer),
            subscriptionId: subId,
            planTier: parsePlanTierMeta(subMeta),
            billingInterval: parseIntervalMeta(subMeta),
            currency: invoice.currency.toUpperCase(),
            unitAmountMinor: invoice.amount_paid || invoice.amount_due,
            currentPeriodStart: new Date(invoice.period_start * 1000),
            currentPeriodEnd: new Date(invoice.period_end * 1000),
            billingEmail: invoice.customer_email ?? undefined
          });
        }

        case "customer.subscription.created":
        case "customer.subscription.updated":
        case "customer.subscription.deleted": {
          const sub = event.data.object;
          const primaryItem = sub.items?.data?.[0];
          const itemInterval = primaryItem?.price?.recurring?.interval;
          const interval: BillingInterval | undefined =
            itemInterval === "month"
              ? "month"
              : itemInterval === "year"
                ? "year"
                : parseIntervalMeta(sub.metadata);

          let kind: NormalizedBillingEvent["billingEventKind"] = "invoice_paid";
          if (event.type === "customer.subscription.deleted" || sub.status === "canceled") {
            kind = "subscription_deleted";
          } else if (sub.cancel_at_period_end) {
            kind = "cancel_scheduled";
          } else if (sub.status === "trialing") {
            kind = "trial_started";
          } else if (sub.status === "past_due" || sub.status === "unpaid") {
            kind = "invoice_payment_failed";
          }

          return Object.freeze({
            provider: "stripe",
            externalEventId: event.id,
            rawEventType: event.type,
            createdAt,
            payloadSha256,
            billingEventKind: kind,
            orgId: parseOrgIdFromMetadata(sub.metadata),
            customerId: refId(sub.customer),
            subscriptionId: sub.id,
            planTier: parsePlanTierMeta(sub.metadata),
            billingInterval: interval,
            currency: sub.currency.toUpperCase(),
            unitAmountMinor: primaryItem?.price?.unit_amount ?? undefined,
            seatCount: Math.max(1, Number(sub.metadata?.["seat_count"] ?? 1) || 1),
            currentPeriodStart:
              primaryItem?.current_period_start !== undefined
                ? new Date(primaryItem.current_period_start * 1000)
                : undefined,
            currentPeriodEnd:
              primaryItem?.current_period_end !== undefined
                ? new Date(primaryItem.current_period_end * 1000)
                : undefined,
            trialEndsAt: sub.trial_end !== null ? new Date(sub.trial_end * 1000) : null,
            cancelAtPeriodEnd: sub.cancel_at_period_end
          });
        }

        case "charge.dispute.created":
        case "charge.dispute.closed": {
          const dispute = event.data.object;
          const chargeObj =
            typeof dispute.charge === "object" && dispute.charge !== null
              ? dispute.charge
              : null;
          const kind: NormalizedBillingEvent["billingEventKind"] =
            event.type === "charge.dispute.created"
              ? "dispute_created"
              : dispute.status === "won"
                ? "dispute_won"
                : "dispute_lost";
          return Object.freeze({
            provider: "stripe",
            externalEventId: event.id,
            rawEventType: event.type,
            createdAt,
            payloadSha256,
            billingEventKind: kind,
            orgId: parseOrgIdFromMetadata(dispute.metadata),
            customerId: refId(chargeObj?.customer)
          });
        }

        case "radar.early_fraud_warning.created": {
          const warning = event.data.object;
          const chargeObj =
            typeof warning.charge === "object" && warning.charge !== null
              ? warning.charge
              : null;
          return Object.freeze({
            provider: "stripe",
            externalEventId: event.id,
            rawEventType: event.type,
            createdAt,
            payloadSha256,
            billingEventKind: "dispute_created",
            customerId: refId(chargeObj?.customer)
          });
        }

        default:
          return Object.freeze({
            provider: "stripe",
            externalEventId: event.id,
            rawEventType: event.type,
            createdAt,
            payloadSha256,
            billingEventKind: "ignored"
          });
      }
    }
  });
}
