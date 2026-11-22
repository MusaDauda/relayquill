import crypto from "node:crypto";
import {
  PLAN_CATALOG,
  reduceEntitlementState,
  type BillingEventKind,
  type BillingInterval,
  type EntitlementState,
  type PlanTier,
  type TenantId
} from "@relayquill/domain";
import { bindTenantRlsScope, type PgAdapter, type PgTransactionClient } from "@relayquill/postgres";
import { type NormalizedBillingEvent } from "./regional-router.js";

export type WebhookProcessingOutcome =
  | "APPLIED"
  | "IGNORED_STALE"
  | "IGNORED_DUPLICATE"
  | "FAILED";

export interface ProcessBillingWebhookInput {
  readonly pgAdapter: PgAdapter;
  readonly event: NormalizedBillingEvent;
  readonly explicitOrgId?: TenantId | undefined;
}

export interface ProcessBillingWebhookResult {
  readonly externalEventId: string;
  readonly outcome: WebhookProcessingOutcome;
  readonly orgId: TenantId | null;
  readonly previousState?: EntitlementState | undefined;
  readonly nextState?: EntitlementState | undefined;
  readonly dunningQueued?: boolean | undefined;
}

async function resolveOrgIdForEvent(
  tx: PgTransactionClient,
  event: NormalizedBillingEvent,
  explicitOrgId?: TenantId
): Promise<TenantId | null> {
  if (explicitOrgId !== undefined) {
    return explicitOrgId;
  }
  if (event.orgId !== undefined) {
    return event.orgId;
  }
  if (event.subscriptionId !== undefined) {
    const subRes = await tx.query<{ org_id: string }>(
      `SELECT org_id FROM rq.billing_subscriptions WHERE stripe_subscription_id = $1::text LIMIT 1`,
      [event.subscriptionId]
    );
    if (subRes.rows[0]?.org_id !== undefined) {
      return subRes.rows[0].org_id as TenantId;
    }
  }
  if (event.customerId !== undefined) {
    const cusRes = await tx.query<{ org_id: string }>(
      `SELECT org_id FROM rq.billing_customers WHERE stripe_customer_id = $1::text LIMIT 1`,
      [event.customerId]
    );
    if (cusRes.rows[0]?.org_id !== undefined) {
      return cusRes.rows[0].org_id as TenantId;
    }
  }
  return null;
}

function resolveTargetPlanTier(
  requested: PlanTier | undefined,
  current: PlanTier,
  eventKind: BillingEventKind
): PlanTier {
  if (requested !== undefined) {
    return requested;
  }
  if (eventKind === "grace_window_elapsed" || eventKind === "subscription_deleted") {
    return "free";
  }
  return current;
}

/**
 * Persists commercial billing webhooks idempotently, rejects stale timestamps, and updates PG entitlements inside RLS scope.
 */
export async function processNormalizedBillingWebhook(
  input: ProcessBillingWebhookInput
): Promise<ProcessBillingWebhookResult> {
  const { event, pgAdapter } = input;
  const eventTsIso = event.createdAt.toISOString();

  return pgAdapter.withTransaction(pgAdapter.configuredRole, async (tx) => {
    const existingEvent = await tx.query<{ outcome: string }>(
      `SELECT outcome FROM rq.billing_webhook_events WHERE stripe_event_id = $1::text LIMIT 1`,
      [event.externalEventId]
    );
    if (existingEvent.rows[0] !== undefined) {
      return {
        externalEventId: event.externalEventId,
        outcome: "IGNORED_DUPLICATE",
        orgId: input.explicitOrgId ?? event.orgId ?? null
      };
    }

    if (event.billingEventKind === "ignored") {
      await tx.query(
        `INSERT INTO rq.billing_webhook_events (
           stripe_event_id, event_type, stripe_created_at, payload_sha256, outcome, error_detail
         ) VALUES ($1::text, $2::text, $3::timestamptz, $4::char(64), 'APPLIED', 'non_actionable_event')`,
        [event.externalEventId, event.rawEventType, eventTsIso, event.payloadSha256]
      );
      return {
        externalEventId: event.externalEventId,
        outcome: "APPLIED",
        orgId: input.explicitOrgId ?? event.orgId ?? null
      };
    }

    const orgId = await resolveOrgIdForEvent(tx, event, input.explicitOrgId);
    if (orgId === null) {
      await tx.query(
        `INSERT INTO rq.billing_webhook_events (
           stripe_event_id, event_type, stripe_created_at, payload_sha256, outcome, error_detail
         ) VALUES ($1::text, $2::text, $3::timestamptz, $4::char(64), 'FAILED', 'org_id_unresolvable')`,
        [event.externalEventId, event.rawEventType, eventTsIso, event.payloadSha256]
      );
      return {
        externalEventId: event.externalEventId,
        outcome: "FAILED",
        orgId: null
      };
    }

    await bindTenantRlsScope(tx, orgId);

    const customerRes = await tx.query<{
      stripe_customer_id: string;
      billing_email: string;
      last_stripe_event_ts: Date | string;
    }>(
      `SELECT stripe_customer_id, billing_email, last_stripe_event_ts
         FROM rq.billing_customers
        WHERE org_id = $1::uuid
        LIMIT 1`,
      [orgId]
    );

    const subRes = await tx.query<{
      subscription_id: string;
      stripe_subscription_id: string | null;
      plan_tier: PlanTier;
      entitlement_state: EntitlementState;
      billing_interval: BillingInterval;
      currency: string;
      unit_amount_minor: string | number;
      seat_count: number;
      last_stripe_event_ts: Date | string;
    }>(
      `SELECT subscription_id, stripe_subscription_id, plan_tier, entitlement_state,
              billing_interval, currency, unit_amount_minor, seat_count, last_stripe_event_ts
         FROM rq.billing_subscriptions
        WHERE org_id = $1::uuid
        LIMIT 1`,
      [orgId]
    );

    const currentSub = subRes.rows[0];
    const lastTsRaw = currentSub?.last_stripe_event_ts ?? customerRes.rows[0]?.last_stripe_event_ts;
    const lastTsMs = lastTsRaw !== undefined ? new Date(lastTsRaw).getTime() : 0;
    if (Number.isFinite(lastTsMs) && event.createdAt.getTime() < lastTsMs) {
      await tx.query(
        `INSERT INTO rq.billing_webhook_events (
           stripe_event_id, event_type, stripe_created_at, payload_sha256, outcome, error_detail
         ) VALUES ($1::text, $2::text, $3::timestamptz, $4::char(64), 'IGNORED_STALE', 'stale_event_timestamp')`,
        [event.externalEventId, event.rawEventType, eventTsIso, event.payloadSha256]
      );
      return {
        externalEventId: event.externalEventId,
        outcome: "IGNORED_STALE",
        orgId,
        previousState: currentSub?.entitlement_state ?? "FREE",
        nextState: currentSub?.entitlement_state ?? "FREE"
      };
    }

    const previousState: EntitlementState = currentSub?.entitlement_state ?? "FREE";
    const transition = reduceEntitlementState(previousState, event.billingEventKind, event.createdAt);
    const nextPlanTier = resolveTargetPlanTier(
      event.planTier,
      currentSub?.plan_tier ?? "pro",
      event.billingEventKind
    );
    const catalog = PLAN_CATALOG[nextPlanTier];
    const nextInterval: BillingInterval =
      event.billingInterval ?? currentSub?.billing_interval ?? "month";
    const nextCurrency = (event.currency ?? currentSub?.currency ?? "USD").toUpperCase();
    const nextSeatCount = Math.max(1, event.seatCount ?? currentSub?.seat_count ?? 1);
    const nextUnitAmount =
      event.unitAmountMinor !== undefined
        ? event.unitAmountMinor
        : Number(currentSub?.unit_amount_minor ?? catalog.monthlyPriceMinor);
    const nextCustomerId =
      event.customerId ??
      customerRes.rows[0]?.stripe_customer_id ??
      `${event.provider}_cus_${orgId.replace(/-/g, "").slice(0, 16)}`;
    const nextEmail = event.billingEmail ?? customerRes.rows[0]?.billing_email ?? "billing@relayquill.local";

    if (customerRes.rows[0] === undefined) {
      await tx.query(
        `INSERT INTO rq.billing_customers (
           org_id, stripe_customer_id, billing_email, billing_country, currency, last_stripe_event_ts
         ) VALUES ($1::uuid, $2::text, $3::text, $4::char(2), $5::char(3), $6::timestamptz)`,
        [orgId, nextCustomerId, nextEmail, event.billingCountry ?? null, nextCurrency, eventTsIso]
      );
    } else {
      await tx.query(
        `UPDATE rq.billing_customers
            SET stripe_customer_id = $2::text,
                billing_email = $3::text,
                billing_country = COALESCE($4::char(2), billing_country),
                currency = $5::char(3),
                last_stripe_event_ts = $6::timestamptz,
                updated_at = pg_catalog.clock_timestamp()
          WHERE org_id = $1::uuid`,
        [orgId, nextCustomerId, nextEmail, event.billingCountry ?? null, nextCurrency, eventTsIso]
      );
    }

    const periodStart = (event.currentPeriodStart ?? event.createdAt).toISOString();
    const periodEnd = (
      event.currentPeriodEnd ?? new Date(event.createdAt.getTime() + 30 * 24 * 60 * 60 * 1000)
    ).toISOString();
    const cancelAtPeriodEnd =
      event.cancelAtPeriodEnd ?? transition.nextState === "CANCELED_END_OF_PERIOD";
    const graceEndsAt = transition.graceEndsAt !== null ? transition.graceEndsAt.toISOString() : null;
    const trialEndsAt = event.trialEndsAt !== undefined && event.trialEndsAt !== null ? event.trialEndsAt.toISOString() : null;
    const nextExtSubId = event.subscriptionId ?? currentSub?.stripe_subscription_id ?? null;

    if (currentSub === undefined) {
      await tx.query(
        `INSERT INTO rq.billing_subscriptions (
           subscription_id, org_id, stripe_subscription_id, plan_tier, entitlement_state,
           billing_interval, currency, unit_amount_minor, seat_count,
           current_period_start, current_period_end, trial_ends_at, grace_ends_at,
           cancel_at_period_end, last_stripe_event_ts, version
         ) VALUES (
           $1::uuid, $2::uuid, $3::text, $4::text, $5::text,
           $6::text, $7::char(3), $8::bigint, $9::int,
           $10::timestamptz, $11::timestamptz, $12::timestamptz, $13::timestamptz,
           $14::boolean, $15::timestamptz, 1
         )`,
        [
          crypto.randomUUID(),
          orgId,
          nextExtSubId,
          nextPlanTier,
          transition.nextState,
          nextInterval,
          nextCurrency,
          nextUnitAmount,
          nextSeatCount,
          periodStart,
          periodEnd,
          trialEndsAt,
          graceEndsAt,
          cancelAtPeriodEnd,
          eventTsIso
        ]
      );
    } else {
      await tx.query(
        `UPDATE rq.billing_subscriptions
            SET stripe_subscription_id = COALESCE($2::text, stripe_subscription_id),
                plan_tier = $3::text,
                entitlement_state = $4::text,
                billing_interval = $5::text,
                currency = $6::char(3),
                unit_amount_minor = $7::bigint,
                seat_count = $8::int,
                current_period_start = $9::timestamptz,
                current_period_end = $10::timestamptz,
                trial_ends_at = COALESCE($11::timestamptz, trial_ends_at),
                grace_ends_at = $12::timestamptz,
                cancel_at_period_end = $13::boolean,
                last_stripe_event_ts = $14::timestamptz,
                version = version + 1,
                updated_at = pg_catalog.clock_timestamp()
          WHERE org_id = $1::uuid`,
        [
          orgId,
          nextExtSubId,
          nextPlanTier,
          transition.nextState,
          nextInterval,
          nextCurrency,
          nextUnitAmount,
          nextSeatCount,
          periodStart,
          periodEnd,
          trialEndsAt,
          graceEndsAt,
          cancelAtPeriodEnd,
          eventTsIso
        ]
      );
    }

    const effectiveMaxSeats = Math.max(catalog.maxSeats, nextSeatCount);
    await tx.query(
      `INSERT INTO rq.entitlement_quotas (
         org_id, max_seats, max_concurrency, included_units_month, overage_unit_minor,
         cap_mode, soft_cap_minor, retention_days, sso_enabled
       ) VALUES ($1::uuid, $2::int, $3::int, $4::bigint, $5::bigint, $6::text, NULL, $7::int, $8::boolean)
       ON CONFLICT (org_id) DO UPDATE
         SET max_seats = EXCLUDED.max_seats,
             max_concurrency = EXCLUDED.max_concurrency,
             included_units_month = EXCLUDED.included_units_month,
             overage_unit_minor = EXCLUDED.overage_unit_minor,
             cap_mode = EXCLUDED.cap_mode,
             retention_days = EXCLUDED.retention_days,
             sso_enabled = EXCLUDED.sso_enabled,
             updated_at = pg_catalog.clock_timestamp()`,
      [
        orgId,
        effectiveMaxSeats,
        catalog.maxConcurrency,
        catalog.includedUnitsMonth,
        catalog.overagePer10kMinor,
        catalog.capMode,
        catalog.retentionDays,
        catalog.ssoEnabled
      ]
    );

    let dunningQueued = false;
    if (event.billingEventKind === "invoice_payment_failed") {
      const inserted = await tx.query(
        `INSERT INTO rq.email_outbox (
           id, tenant_id, idempotency_key, template_code, recipient_email, template_vars, state, attempt_count
         ) VALUES (
           $1::uuid, $2::uuid, $3::text, 'dunning_notice_1', $4::text, $5::jsonb, 'pending', 0
         ) ON CONFLICT (idempotency_key) DO NOTHING
         RETURNING id`,
        [
          crypto.randomUUID(),
          orgId,
          `dunning:1:${orgId}:${event.externalEventId}`,
          nextEmail,
          JSON.stringify({
            provider: event.provider,
            grace_ends_at: graceEndsAt,
            event_id: event.externalEventId
          })
        ]
      );
      dunningQueued = inserted.rows.length > 0;
    }

    await tx.query(
      `INSERT INTO rq.billing_webhook_events (
         stripe_event_id, event_type, stripe_created_at, payload_sha256, outcome
       ) VALUES ($1::text, $2::text, $3::timestamptz, $4::char(64), 'APPLIED')`,
      [event.externalEventId, event.rawEventType, eventTsIso, event.payloadSha256]
    );

    return {
      externalEventId: event.externalEventId,
      outcome: "APPLIED",
      orgId,
      previousState,
      nextState: transition.nextState,
      dunningQueued
    };
  });
}
