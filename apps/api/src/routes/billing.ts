import crypto from "node:crypto";
import {
  BILLING_PROVIDER_IDS,
  processNormalizedBillingWebhook,
  resolveBillingProviderForCountry,
  type BillingProviderId
} from "@relayquill/billing";
import {
  DependencyUnavailableDomainError,
  isBillingInterval,
  isPlanTier,
  PLAN_CATALOG,
  reduceEntitlementState,
  ValidationDomainError,
  formatUtcTimestamp,
  type EntitlementState
} from "@relayquill/domain";
import { withTenantRlsTransaction } from "@relayquill/postgres";
import { type FastifyInstance } from "fastify";
import {
  type ApiContext,
  authenticateHumanMutation,
  authenticateHumanRead,
  getRawRequestHeaderMap,
  getRequestJsonBody,
  readInstallationSnapshot
} from "../context.js";
import { sendSuccessEnvelope } from "../http/errors.js";
import { extractSingleRawHeader } from "../http/headers.js";
import { getRequestRawBodyBuffer } from "../server.js";
import { asText } from "../repos/sql-helpers.js";
import { resolveActorCommercialTenantId } from "./commercial-auth-and-ops.js";

function getPeriodMonthUtc(nowMs: number): string {
  const d = new Date(nowMs);
  return `${d.getUTCFullYear()}-${String(d.getUTCMonth() + 1).padStart(2, "0")}`;
}

/**
 * Registers commercial multi-provider billing (Stripe, Paystack Africa, Tap MENA), usage readouts,
 * never-paywalled portal/cancel endpoints, and raw-body verified webhook receivers.
 */
export function registerBillingRoutes(app: FastifyInstance, ctx: ApiContext): void {
  // Current subscription, entitlement quota, monthly usage rollup, and regional routing preview
  app.get("/api/v1/billing/subscription", async (request, reply) => {
    const inst = await ctx.pgAdapter.withTransaction(
      ctx.pgAdapter.configuredRole,
      (tx) => readInstallationSnapshot(ctx, tx),
      { readOnly: true }
    );
    const { auth } = await authenticateHumanRead(ctx, request, inst);

    try {
      const instant = ctx.clock.nowInstant();
      const nowIso = formatUtcTimestamp(instant);
      const periodMonth = getPeriodMonthUtc(instant.epochMilliseconds);
      const queryObj = (request.query ?? {}) as Record<string, unknown>;

      const data = await ctx.pgAdapter.withTransaction(
        ctx.pgAdapter.configuredRole,
        async (tx) => {
          const resolved = await resolveActorCommercialTenantId(
            tx,
            auth.principal.principalId,
            queryObj["tenant_id"]
          );
          const cusRes = await tx.query<Record<string, unknown>>(
            `SELECT org_id, stripe_customer_id, billing_email, billing_country, currency,
                    tax_exempt_status, default_txcd
               FROM rq.billing_customers WHERE org_id = $1::uuid LIMIT 1`,
            [resolved.tenantId]
          );
          const subRes = await tx.query<Record<string, unknown>>(
            `SELECT subscription_id, stripe_subscription_id, plan_tier, entitlement_state,
                    billing_interval, currency, unit_amount_minor, seat_count,
                    current_period_start, current_period_end, trial_ends_at, grace_ends_at,
                    cancel_at_period_end, version
               FROM rq.billing_subscriptions WHERE org_id = $1::uuid LIMIT 1`,
            [resolved.tenantId]
          );
          const quotaRes = await tx.query<Record<string, unknown>>(
            `SELECT max_seats, max_concurrency, included_units_month, overage_unit_minor,
                    cap_mode, retention_days, sso_enabled
               FROM rq.entitlement_quotas WHERE org_id = $1::uuid LIMIT 1`,
            [resolved.tenantId]
          );
          const rollupRes = await tx.query<Record<string, unknown>>(
            `SELECT metric_code, total_billable_units, total_free_units, total_cogs_micros
               FROM rq.usage_rollups
              WHERE org_id = $1::uuid AND period_month = $2::char(7)`,
            [resolved.tenantId, periodMonth]
          );

          const country =
            typeof queryObj["country"] === "string"
              ? queryObj["country"]
              : typeof cusRes.rows[0]?.["billing_country"] === "string"
                ? cusRes.rows[0]["billing_country"]
                : "US";
          const preferredCurrency =
            typeof queryObj["currency"] === "string"
              ? queryObj["currency"]
              : typeof queryObj["country"] === "string"
                ? undefined
                : typeof cusRes.rows[0]?.["currency"] === "string"
                  ? cusRes.rows[0]["currency"]
                  : undefined;

          return {
            org_id: resolved.tenantId,
            period_month: periodMonth,
            customer: cusRes.rows[0] ?? null,
            subscription: subRes.rows[0] ?? {
              plan_tier: "free",
              entitlement_state: "FREE",
              billing_interval: "month",
              currency: "USD",
              unit_amount_minor: 0,
              seat_count: 1,
              cancel_at_period_end: false
            },
            quotas: quotaRes.rows[0] ?? {
              max_seats: PLAN_CATALOG.free.maxSeats,
              max_concurrency: PLAN_CATALOG.free.maxConcurrency,
              included_units_month: PLAN_CATALOG.free.includedUnitsMonth,
              overage_unit_minor: PLAN_CATALOG.free.overagePer10kMinor,
              cap_mode: PLAN_CATALOG.free.capMode,
              retention_days: PLAN_CATALOG.free.retentionDays,
              sso_enabled: PLAN_CATALOG.free.ssoEnabled
            },
            usage_rollups: rollupRes.rows,
            regional_routing: resolveBillingProviderForCountry(country, preferredCurrency),
            configured_providers: Object.keys(ctx.billingAdapters),
            plan_catalog: PLAN_CATALOG
          };
        },
        { readOnly: true }
      );

      return sendSuccessEnvelope(reply, 200, data, { requestId: request.id, observedAt: nowIso });
    } finally {
      auth.destroySecrets();
    }
  });

  // Monthly usage rollup + bounded recent usage events with zero-charge transparency
  app.get("/api/v1/billing/usage", async (request, reply) => {
    const inst = await ctx.pgAdapter.withTransaction(
      ctx.pgAdapter.configuredRole,
      (tx) => readInstallationSnapshot(ctx, tx),
      { readOnly: true }
    );
    const { auth } = await authenticateHumanRead(ctx, request, inst);

    try {
      const instant = ctx.clock.nowInstant();
      const nowIso = formatUtcTimestamp(instant);
      const queryObj = (request.query ?? {}) as Record<string, unknown>;
      const periodMonth =
        typeof queryObj["period_month"] === "string" && /^\d{4}-\d{2}$/.test(queryObj["period_month"])
          ? queryObj["period_month"]
          : getPeriodMonthUtc(instant.epochMilliseconds);

      const data = await ctx.pgAdapter.withTransaction(
        ctx.pgAdapter.configuredRole,
        async (tx) => {
          const resolved = await resolveActorCommercialTenantId(
            tx,
            auth.principal.principalId,
            queryObj["tenant_id"]
          );
          const rollups = await tx.query<Record<string, unknown>>(
            `SELECT metric_code, total_billable_units, total_free_units, total_cogs_micros,
                    alert_70_sent_at, alert_85_sent_at, alert_95_sent_at, spike_alert_sent_at
               FROM rq.usage_rollups
              WHERE org_id = $1::uuid AND period_month = $2::char(7)`,
            [resolved.tenantId, periodMonth]
          );
          const events = await tx.query<Record<string, unknown>>(
            `SELECT usage_event_id, idempotency_key, metric_code, billable_units,
                    billed_reason, currency, unit_price_minor, created_at
               FROM rq.usage_events
              WHERE org_id = $1::uuid AND period_month = $2::char(7)
              ORDER BY created_at DESC
              LIMIT 100`,
            [resolved.tenantId, periodMonth]
          );
          return {
            org_id: resolved.tenantId,
            period_month: periodMonth,
            rollups: rollups.rows,
            events: events.rows
          };
        },
        { readOnly: true }
      );

      return sendSuccessEnvelope(reply, 200, data, { requestId: request.id, observedAt: nowIso });
    } finally {
      auth.destroySecrets();
    }
  });

  // Regional checkout session initiation (Stripe / Paystack Africa / Tap MENA)
  app.post("/api/v1/billing/checkout", async (request, reply) => {
    const inst = await ctx.pgAdapter.withTransaction(
      ctx.pgAdapter.configuredRole,
      (tx) => readInstallationSnapshot(ctx, tx),
      { readOnly: true }
    );
    const { auth } = await authenticateHumanMutation(ctx, request, inst);

    try {
      const body = getRequestJsonBody(request);
      const rawTier = asText(body["plan_tier"]).trim().toLowerCase();
      if (!isPlanTier(rawTier) || rawTier === "free") {
        throw new ValidationDomainError({
          code: "INVALID_VALUE",
          message: "plan_tier must be one of pro, team, or enterprise",
          fieldErrors: [{ path: "plan_tier", code: "INVALID_VALUE" }]
        });
      }
      const rawInterval = asText(body["billing_interval"], "month").trim().toLowerCase();
      if (!isBillingInterval(rawInterval)) {
        throw new ValidationDomainError({
          code: "INVALID_VALUE",
          message: "billing_interval must be month or year",
          fieldErrors: [{ path: "billing_interval", code: "INVALID_VALUE" }]
        });
      }
      const seatCount =
        typeof body["seat_count"] === "number" && Number.isSafeInteger(body["seat_count"])
          ? Math.max(1, body["seat_count"])
          : PLAN_CATALOG[rawTier].maxSeats;
      const countryCode =
        typeof body["country_code"] === "string" ? body["country_code"].trim().toUpperCase() : "US";
      const currency =
        typeof body["currency"] === "string" ? body["currency"].trim().toUpperCase() : undefined;
      const routing = resolveBillingProviderForCountry(countryCode, currency);

      const requestedProvider =
        typeof body["provider"] === "string" ? body["provider"].trim().toLowerCase() : undefined;
      let provider: BillingProviderId = routing.provider;
      if (requestedProvider !== undefined) {
        if (!BILLING_PROVIDER_IDS.includes(requestedProvider as BillingProviderId)) {
          throw new ValidationDomainError({
            code: "INVALID_VALUE",
            message: "provider must be stripe, paystack, or tap"
          });
        }
        provider = requestedProvider as BillingProviderId;
      }

      const adapter = ctx.billingAdapters[provider];
      if (adapter === undefined) {
        throw new DependencyUnavailableDomainError({
          code: "DEPENDENCY_UNAVAILABLE",
          message: `Billing provider adapter "${provider}" is not configured in this environment`
        });
      }

      const successUrl = asText(
        body["success_url"],
        "http://localhost:5205/billing?checkout=success"
      );
      const cancelUrl = asText(body["cancel_url"], "http://localhost:5205/billing?checkout=canceled");
      const trialDays =
        typeof body["trial_days"] === "number" && Number.isSafeInteger(body["trial_days"])
          ? Math.max(0, Math.min(30, body["trial_days"]))
          : undefined;

      const nowIso = formatUtcTimestamp(ctx.clock.nowInstant());
      const resolved = await ctx.pgAdapter.withTransaction(
        ctx.pgAdapter.configuredRole,
        (tx) => resolveActorCommercialTenantId(tx, auth.principal.principalId, body["tenant_id"]),
        { readOnly: true }
      );

      const cusInfo = await withTenantRlsTransaction(
        ctx.pgAdapter,
        ctx.pgAdapter.configuredRole,
        resolved.tenantId,
        async (tx) => {
          const userEmailRes = await tx.query<{ email: string }>(
            `SELECT email FROM rq.users WHERE tenant_id = $1::uuid LIMIT 1`,
            [resolved.tenantId]
          );
          const fallbackEmail =
            userEmailRes.rows[0]?.email ?? `billing-${resolved.tenantId.slice(0, 8)}@relayquill.local`;
          const cusRes = await tx.query<{ stripe_customer_id: string; billing_email: string }>(
            `SELECT stripe_customer_id, billing_email
               FROM rq.billing_customers WHERE org_id = $1::uuid LIMIT 1`,
            [resolved.tenantId]
          );
          if (cusRes.rows[0] === undefined) {
            const placeholder = `cus_local_${resolved.tenantId.replace(/-/g, "").slice(0, 16)}`;
            await tx.query(
              `INSERT INTO rq.billing_customers (
                 org_id, stripe_customer_id, billing_email, billing_country, currency
               ) VALUES ($1::uuid, $2::text, $3::text, $4::char(2), $5::char(3))`,
              [resolved.tenantId, placeholder, fallbackEmail, routing.countryCode, routing.currency]
            );
            return { customerId: placeholder, billingEmail: fallbackEmail };
          }
          await tx.query(
            `UPDATE rq.billing_customers
                SET billing_country = $2::char(2),
                    currency = $3::char(3),
                    updated_at = $4::timestamptz
              WHERE org_id = $1::uuid`,
            [resolved.tenantId, routing.countryCode, routing.currency, nowIso]
          );
          return {
            customerId: cusRes.rows[0].stripe_customer_id,
            billingEmail: cusRes.rows[0].billing_email
          };
        }
      );

      const checkout = await adapter.createCheckoutSession({
        orgId: resolved.tenantId,
        customerEmail: cusInfo.billingEmail,
        customerId: cusInfo.customerId,
        planTier: rawTier,
        billingInterval: rawInterval,
        seatCount,
        countryCode: routing.countryCode,
        currency: routing.currency,
        successUrl,
        cancelUrl,
        trialDays
      });

      await withTenantRlsTransaction(
        ctx.pgAdapter,
        ctx.pgAdapter.configuredRole,
        resolved.tenantId,
        async (tx) => {
          await tx.query(
            `INSERT INTO rq.audit_events (
               id, tenant_id, project_id, actor_kind, actor_reference, action,
               target_kind, target_id, recorded_at, safe_facts
             ) VALUES (
               $1::uuid, $2::uuid, NULL, 'human', $3::uuid, 'billing.checkout.started',
               'tenant', $2::uuid, $4::timestamptz, $5::jsonb
             )`,
            [
              crypto.randomUUID(),
              resolved.tenantId,
              auth.principal.principalId,
              nowIso,
              JSON.stringify({
                provider: checkout.provider,
                plan_tier: rawTier,
                billing_interval: rawInterval,
                currency: checkout.currency
              })
            ]
          );
        }
      );

      return sendSuccessEnvelope(
        reply,
        201,
        {
          org_id: resolved.tenantId,
          provider: checkout.provider,
          session_id: checkout.sessionId,
          checkout_url: checkout.checkoutUrl,
          currency: checkout.currency,
          amount_minor: checkout.amountMinor,
          tax_automation_enabled: checkout.taxAutomationEnabled,
          regional_routing: routing
        },
        { requestId: request.id, observedAt: nowIso }
      );
    } finally {
      auth.destroySecrets();
    }
  });

  // Never-paywalled billing portal session endpoint
  app.post("/api/v1/billing/portal", async (request, reply) => {
    const inst = await ctx.pgAdapter.withTransaction(
      ctx.pgAdapter.configuredRole,
      (tx) => readInstallationSnapshot(ctx, tx),
      { readOnly: true }
    );
    const { auth } = await authenticateHumanMutation(ctx, request, inst);

    try {
      const body = getRequestJsonBody(request);
      const returnUrl = asText(body["return_url"], "http://localhost:5205/billing");
      const nowIso = formatUtcTimestamp(ctx.clock.nowInstant());
      const resolved = await ctx.pgAdapter.withTransaction(
        ctx.pgAdapter.configuredRole,
        (tx) => resolveActorCommercialTenantId(tx, auth.principal.principalId, body["tenant_id"]),
        { readOnly: true }
      );

      const cus = await withTenantRlsTransaction(
        ctx.pgAdapter,
        ctx.pgAdapter.configuredRole,
        resolved.tenantId,
        async (tx) => {
          const res = await tx.query<{ stripe_customer_id: string; billing_country: string | null }>(
            `SELECT stripe_customer_id, billing_country
               FROM rq.billing_customers WHERE org_id = $1::uuid LIMIT 1`,
            [resolved.tenantId]
          );
          return res.rows[0];
        },
        { readOnly: true }
      );

      const routing = resolveBillingProviderForCountry(cus?.billing_country ?? undefined);
      const adapter = ctx.billingAdapters[routing.provider];
      if (
        adapter?.createPortalSession !== undefined &&
        cus?.stripe_customer_id !== undefined &&
        !cus.stripe_customer_id.startsWith("cus_local_")
      ) {
        const portal = await adapter.createPortalSession({
          orgId: resolved.tenantId,
          customerId: cus.stripe_customer_id,
          returnUrl
        });
        return sendSuccessEnvelope(
          reply,
          200,
          {
            org_id: resolved.tenantId,
            provider: portal.provider,
            hosted_portal: portal.hostedPortal,
            portal_url: portal.portalUrl
          },
          { requestId: request.id, observedAt: nowIso }
        );
      }

      return sendSuccessEnvelope(
        reply,
        200,
        {
          org_id: resolved.tenantId,
          provider: routing.provider,
          hosted_portal: false,
          portal_url: returnUrl,
          self_serve_cancel_endpoint: "/api/v1/billing/cancel"
        },
        { requestId: request.id, observedAt: nowIso }
      );
    } finally {
      auth.destroySecrets();
    }
  });

  // Never-paywalled self-serve subscription cancellation at period end
  app.post("/api/v1/billing/cancel", async (request, reply) => {
    const inst = await ctx.pgAdapter.withTransaction(
      ctx.pgAdapter.configuredRole,
      (tx) => readInstallationSnapshot(ctx, tx),
      { readOnly: true }
    );
    const { auth } = await authenticateHumanMutation(ctx, request, inst);

    try {
      const body = getRequestJsonBody(request);
      const instant = ctx.clock.nowInstant();
      const now = new Date(instant.epochMilliseconds);
      const nowIso = formatUtcTimestamp(instant);
      const resolved = await ctx.pgAdapter.withTransaction(
        ctx.pgAdapter.configuredRole,
        (tx) => resolveActorCommercialTenantId(tx, auth.principal.principalId, body["tenant_id"]),
        { readOnly: true }
      );

      const result = await withTenantRlsTransaction(
        ctx.pgAdapter,
        ctx.pgAdapter.configuredRole,
        resolved.tenantId,
        async (tx) => {
          const subRes = await tx.query<{
            subscription_id: string;
            entitlement_state: EntitlementState;
          }>(
            `SELECT subscription_id, entitlement_state
               FROM rq.billing_subscriptions WHERE org_id = $1::uuid LIMIT 1`,
            [resolved.tenantId]
          );
          const row = subRes.rows[0];
          const prevState: EntitlementState = row?.entitlement_state ?? "FREE";
          const transition = reduceEntitlementState(prevState, "cancel_scheduled", now);
          if (row !== undefined) {
            await tx.query(
              `UPDATE rq.billing_subscriptions
                  SET cancel_at_period_end = true,
                      entitlement_state = $2::text,
                      version = version + 1,
                      updated_at = $3::timestamptz
                WHERE subscription_id = $1::uuid`,
              [row.subscription_id, transition.nextState, nowIso]
            );
          }
          await tx.query(
            `INSERT INTO rq.audit_events (
               id, tenant_id, project_id, actor_kind, actor_reference, action,
               target_kind, target_id, recorded_at, safe_facts
             ) VALUES (
               $1::uuid, $2::uuid, NULL, 'human', $3::uuid, 'billing.subscription.cancel_scheduled',
               'tenant', $2::uuid, $4::timestamptz, $5::jsonb
             )`,
            [
              crypto.randomUUID(),
              resolved.tenantId,
              auth.principal.principalId,
              nowIso,
              JSON.stringify({ previous_state: prevState, next_state: transition.nextState })
            ]
          );
          return {
            org_id: resolved.tenantId,
            previous_state: prevState,
            entitlement_state: transition.nextState,
            cancel_at_period_end: true
          };
        }
      );

      return sendSuccessEnvelope(reply, 200, result, { requestId: request.id, observedAt: nowIso });
    } finally {
      auth.destroySecrets();
    }
  });

  // Public provider webhook receivers with raw-body cryptographic signature verification
  const webhookRoutes: ReadonlyArray<{
    readonly provider: BillingProviderId;
    readonly path: string;
    readonly signatureHeaders: readonly string[];
  }> = [
    { provider: "stripe", path: "/api/v1/webhooks/stripe", signatureHeaders: ["stripe-signature"] },
    {
      provider: "paystack",
      path: "/api/v1/webhooks/paystack",
      signatureHeaders: ["x-paystack-signature"]
    },
    {
      provider: "tap",
      path: "/api/v1/webhooks/tap",
      signatureHeaders: ["hashstring", "x-tap-signature"]
    }
  ];

  for (const spec of webhookRoutes) {
    app.post(spec.path, async (request, reply) => {
      const adapter = ctx.billingAdapters[spec.provider];
      if (adapter === undefined) {
        throw new DependencyUnavailableDomainError({
          code: "DEPENDENCY_UNAVAILABLE",
          message: `Webhook handler for provider "${spec.provider}" is not configured`
        });
      }
      const rawBuf = getRequestRawBodyBuffer(request);
      if (rawBuf === undefined || rawBuf.byteLength === 0) {
        throw new ValidationDomainError({
          code: "INVALID_VALUE",
          message: "Missing raw HTTP body bytes for webhook signature verification"
        });
      }

      const headerMap = getRawRequestHeaderMap(request);
      let sigHeader: string | undefined;
      for (const h of spec.signatureHeaders) {
        const val = extractSingleRawHeader(headerMap, h);
        if (val !== undefined && val.length > 0) {
          sigHeader = val;
          break;
        }
      }

      const normalized = adapter.verifyAndParseWebhook(
        rawBuf,
        sigHeader,
        ctx.clock.nowInstant().epochMilliseconds
      );
      const outcome = await processNormalizedBillingWebhook({
        pgAdapter: ctx.pgAdapter,
        event: normalized
      });

      const nowIso = formatUtcTimestamp(ctx.clock.nowInstant());
      return sendSuccessEnvelope(
        reply,
        200,
        {
          provider: spec.provider,
          event_id: outcome.externalEventId,
          outcome: outcome.outcome,
          org_id: outcome.orgId,
          next_state: outcome.nextState ?? null
        },
        { requestId: request.id, observedAt: nowIso }
      );
    });
  }
}
