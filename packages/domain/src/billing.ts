import { createEnumGuard } from "./enums.js";

export const PLAN_TIERS = ["free", "pro", "team", "enterprise"] as const;
export type PlanTier = (typeof PLAN_TIERS)[number];
export const isPlanTier = createEnumGuard(PLAN_TIERS);

export const BILLING_INTERVALS = ["month", "year"] as const;
export type BillingInterval = (typeof BILLING_INTERVALS)[number];
export const isBillingInterval = createEnumGuard(BILLING_INTERVALS);

export const CAP_MODES = ["hard_cap", "soft_cap"] as const;
export type CapMode = (typeof CAP_MODES)[number];
export const isCapMode = createEnumGuard(CAP_MODES);

export const ENTITLEMENT_STATES = [
  "FREE",
  "TRIALING",
  "ACTIVE",
  "PAST_DUE_GRACE",
  "RESTRICTED_DOWNGRADED",
  "DISPUTE_HOLD",
  "CANCELED_END_OF_PERIOD",
  "CANCELED_TERMINATED",
  "UNKNOWN_RECONCILING"
] as const;
export type EntitlementState = (typeof ENTITLEMENT_STATES)[number];
export const isEntitlementState = createEnumGuard(ENTITLEMENT_STATES);

export const BILLING_EVENT_KINDS = [
  "checkout_completed_paid",
  "trial_started",
  "invoice_paid",
  "invoice_payment_failed",
  "grace_window_elapsed",
  "dispute_created",
  "dispute_won",
  "dispute_lost",
  "cancel_scheduled",
  "subscription_deleted",
  "reconcile_timeout",
  "reconcile_confirmed_active"
] as const;
export type BillingEventKind = (typeof BILLING_EVENT_KINDS)[number];
export const isBillingEventKind = createEnumGuard(BILLING_EVENT_KINDS);

export const BILLED_REASONS = [
  "metered_usage",
  "included_allowance",
  "idempotent_replay_free",
  "cancelled_free",
  "cached_free",
  "system_error_free"
] as const;
export type BilledReason = (typeof BILLED_REASONS)[number];
export const isBilledReason = createEnumGuard(BILLED_REASONS);

export const ZERO_CHARGE_REASONS = [
  "idempotent_replay_free",
  "cancelled_free",
  "cached_free",
  "system_error_free"
] as const;
export type ZeroChargeReason = (typeof ZERO_CHARGE_REASONS)[number];

const ZERO_CHARGE_REASON_SET: ReadonlySet<string> = new Set<string>(ZERO_CHARGE_REASONS);

/**
 * Returns true when a usage classification carries zero billable customer units.
 */
export function isZeroChargeReason(reason: BilledReason): reason is ZeroChargeReason {
  return ZERO_CHARGE_REASON_SET.has(reason);
}

export const NEVER_PAYWALL_ACTIONS = [
  "auth.mfa.manage",
  "signing_keys.rotate",
  "audit_logs.read",
  "audit_logs.export",
  "deliveries.export",
  "dlq.export",
  "billing.portal",
  "billing.cancel",
  "billing.invoices.read",
  "org.erasure.request"
] as const;
export type NeverPaywallAction = (typeof NEVER_PAYWALL_ACTIONS)[number];

const NEVER_PAYWALL_ACTION_SET: ReadonlySet<string> = new Set<string>(NEVER_PAYWALL_ACTIONS);

/**
 * Security, portability, self-cancellation, and GDPR erasure actions that remain accessible even under quota hard caps or dunning.
 */
export function isNeverPaywallAction(action: string): action is NeverPaywallAction {
  return NEVER_PAYWALL_ACTION_SET.has(action);
}

export const EMAIL_OUTBOX_TEMPLATES = [
  "verify_email",
  "quota_alert_70",
  "quota_alert_85",
  "quota_alert_95",
  "quota_spike_3x",
  "dunning_notice_1",
  "dunning_notice_3",
  "dunning_notice_5",
  "dunning_notice_7",
  "break_glass_notice",
  "gdpr_erasure_receipt"
] as const;
export type EmailOutboxTemplateCode = (typeof EMAIL_OUTBOX_TEMPLATES)[number];
export const isEmailOutboxTemplateCode = createEnumGuard(EMAIL_OUTBOX_TEMPLATES);

export const GDPR_ERASURE_STATES = [
  "queued",
  "redis_revoked",
  "pg_purged",
  "storage_purged",
  "completed",
  "failed"
] as const;
export type GdprErasureState = (typeof GDPR_ERASURE_STATES)[number];
export const isGdprErasureState = createEnumGuard(GDPR_ERASURE_STATES);

export const LEGAL_DOCUMENT_KINDS = ["tos", "privacy", "dpa"] as const;
export type LegalDocumentKind = (typeof LEGAL_DOCUMENT_KINDS)[number];
export const isLegalDocumentKind = createEnumGuard(LEGAL_DOCUMENT_KINDS);

export const CONSOLE_VIEW_STATES = [
  "loading",
  "empty",
  "ready",
  "partial",
  "error",
  "unauthorized",
  "rate_limited",
  "quota_exceeded"
] as const;
export type ConsoleViewState = (typeof CONSOLE_VIEW_STATES)[number];
export const isConsoleViewState = createEnumGuard(CONSOLE_VIEW_STATES);

export const DEFAULT_SAAS_TAX_CODE = "txcd_10103001" as const;
export const GRACE_PERIOD_MS = 7 * 24 * 60 * 60 * 1000;

export interface PlanEntitlementDefaults {
  readonly planTier: PlanTier;
  readonly monthlyPriceMinor: number;
  readonly annualPriceMinor: number | null;
  readonly seatAddonMinor: number;
  readonly maxSeats: number;
  readonly maxConcurrency: number;
  readonly maxEndpoints: number;
  readonly includedUnitsMonth: number;
  readonly overagePer10kMinor: number;
  readonly capMode: CapMode;
  readonly retentionDays: number;
  readonly ssoEnabled: boolean;
}

export const PLAN_CATALOG: Readonly<Record<PlanTier, PlanEntitlementDefaults>> = Object.freeze({
  free: Object.freeze({
    planTier: "free",
    monthlyPriceMinor: 0,
    annualPriceMinor: 0,
    seatAddonMinor: 0,
    maxSeats: 1,
    maxConcurrency: 1,
    maxEndpoints: 2,
    includedUnitsMonth: 25_000,
    overagePer10kMinor: 0,
    capMode: "hard_cap",
    retentionDays: 3,
    ssoEnabled: false
  }),
  pro: Object.freeze({
    planTier: "pro",
    monthlyPriceMinor: 3900,
    annualPriceMinor: 37200,
    seatAddonMinor: 0,
    maxSeats: 3,
    maxConcurrency: 10,
    maxEndpoints: 25,
    includedUnitsMonth: 500_000,
    overagePer10kMinor: 8,
    capMode: "hard_cap",
    retentionDays: 30,
    ssoEnabled: false
  }),
  team: Object.freeze({
    planTier: "team",
    monthlyPriceMinor: 14900,
    annualPriceMinor: 142800,
    seatAddonMinor: 1900,
    maxSeats: 5,
    maxConcurrency: 50,
    maxEndpoints: 200,
    includedUnitsMonth: 3_000_000,
    overagePer10kMinor: 5,
    capMode: "soft_cap",
    retentionDays: 90,
    ssoEnabled: true
  }),
  enterprise: Object.freeze({
    planTier: "enterprise",
    monthlyPriceMinor: 99900,
    annualPriceMinor: null,
    seatAddonMinor: 0,
    maxSeats: 50,
    maxConcurrency: 250,
    maxEndpoints: 2000,
    includedUnitsMonth: 25_000_000,
    overagePer10kMinor: 3,
    capMode: "soft_cap",
    retentionDays: 365,
    ssoEnabled: true
  })
});

export interface EntitlementTransitionResult {
  readonly nextState: EntitlementState;
  readonly graceEndsAt: Date | null;
  readonly freezeExpansion: boolean;
}

/**
 * Pure reducer governing commercial SaaS subscription and dunning entitlement transitions.
 */
export function reduceEntitlementState(
  current: EntitlementState,
  event: BillingEventKind,
  now: Date
): EntitlementTransitionResult {
  switch (event) {
    case "trial_started":
      return { nextState: "TRIALING", graceEndsAt: null, freezeExpansion: false };
    case "checkout_completed_paid":
    case "invoice_paid":
    case "reconcile_confirmed_active":
      return { nextState: "ACTIVE", graceEndsAt: null, freezeExpansion: false };
    case "invoice_payment_failed":
      return {
        nextState: "PAST_DUE_GRACE",
        graceEndsAt: new Date(now.getTime() + GRACE_PERIOD_MS),
        freezeExpansion: false
      };
    case "grace_window_elapsed":
      return { nextState: "RESTRICTED_DOWNGRADED", graceEndsAt: null, freezeExpansion: true };
    case "dispute_created":
      return { nextState: "DISPUTE_HOLD", graceEndsAt: null, freezeExpansion: true };
    case "dispute_won":
      return { nextState: "ACTIVE", graceEndsAt: null, freezeExpansion: false };
    case "dispute_lost":
    case "subscription_deleted":
      return { nextState: "CANCELED_TERMINATED", graceEndsAt: null, freezeExpansion: true };
    case "cancel_scheduled":
      return { nextState: "CANCELED_END_OF_PERIOD", graceEndsAt: null, freezeExpansion: false };
    case "reconcile_timeout":
      return { nextState: "UNKNOWN_RECONCILING", graceEndsAt: null, freezeExpansion: true };
    default: {
      const exhaustive: never = event;
      void exhaustive;
      return { nextState: current, graceEndsAt: null, freezeExpansion: false };
    }
  }
}

/**
 * Returns true while paid delivery tier capacity remains active (including during 7-day dunning grace).
 */
export function isPaidDeliveryAllowed(state: EntitlementState): boolean {
  return (
    state === "TRIALING" ||
    state === "ACTIVE" ||
    state === "PAST_DUE_GRACE" ||
    state === "CANCELED_END_OF_PERIOD"
  );
}

export const DISPOSABLE_EMAIL_DOMAINS: ReadonlySet<string> = new Set([
  "mailinator.com",
  "guerrillamail.com",
  "10minutemail.com",
  "tempmail.com",
  "yopmail.com",
  "trashmail.com"
]);

export interface SignupSybilCheckResult {
  readonly allowed: boolean;
  readonly reason?: "INVALID_EMAIL_FORMAT" | "DISPOSABLE_EMAIL_DOMAIN_REJECTED";
}

/**
 * Blocks malformed addresses and known disposable domains on free/self-serve signup.
 */
export function validateSignupSybilHygiene(email: string): SignupSybilCheckResult {
  const trimmed = email.trim().toLowerCase();
  const atIndex = trimmed.indexOf("@");
  if (atIndex <= 0 || atIndex !== trimmed.lastIndexOf("@")) {
    return { allowed: false, reason: "INVALID_EMAIL_FORMAT" };
  }
  const domain = trimmed.slice(atIndex + 1);
  if (domain.length === 0 || !domain.includes(".") || /\s/.test(trimmed)) {
    return { allowed: false, reason: "INVALID_EMAIL_FORMAT" };
  }
  if (DISPOSABLE_EMAIL_DOMAINS.has(domain)) {
    return { allowed: false, reason: "DISPOSABLE_EMAIL_DOMAIN_REJECTED" };
  }
  return { allowed: true };
}

/**
 * Formats an integer minor-unit currency amount (for example cents) with `Intl.NumberFormat`.
 */
export function formatMinorCurrency(
  amountMinor: number,
  currency = "USD",
  locale = "en-US"
): string {
  const safeMinor = Number.isFinite(amountMinor) ? Math.trunc(amountMinor) : 0;
  return new Intl.NumberFormat(locale, {
    style: "currency",
    currency: currency.trim().toUpperCase() || "USD",
    minimumFractionDigits: 2,
    maximumFractionDigits: 2
  }).format(safeMinor / 100);
}
