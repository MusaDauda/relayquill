import test from "node:test";
import assert from "node:assert/strict";
import {
  BILLING_EVENT_KINDS,
  BILLED_REASONS,
  CONSOLE_VIEW_STATES,
  DEFAULT_SAAS_TAX_CODE,
  ENTITLEMENT_STATES,
  GRACE_PERIOD_MS,
  NEVER_PAYWALL_ACTIONS,
  PLAN_CATALOG,
  PLAN_TIERS,
  ZERO_CHARGE_REASONS,
  formatMinorCurrency,
  isBilledReason,
  isConsoleViewState,
  isEntitlementState,
  isNeverPaywallAction,
  isPaidDeliveryAllowed,
  isPlanTier,
  isZeroChargeReason,
  reduceEntitlementState,
  validateSignupSybilHygiene
} from "@relayquill/domain";

test("PLAN_CATALOG defines four commercial tiers with integer minor units and hard/soft caps", () => {
  assert.deepEqual([...PLAN_TIERS], ["free", "pro", "team", "enterprise"]);
  assert.equal(DEFAULT_SAAS_TAX_CODE, "txcd_10103001");

  for (const tier of PLAN_TIERS) {
    assert.equal(isPlanTier(tier), true);
    const plan = PLAN_CATALOG[tier];
    assert.equal(plan.planTier, tier);
    assert.equal(Number.isInteger(plan.monthlyPriceMinor), true);
    assert.equal(Number.isInteger(plan.includedUnitsMonth), true);
    assert.equal(Number.isInteger(plan.maxConcurrency), true);
    assert.equal(Number.isInteger(plan.maxSeats), true);
  }

  assert.equal(PLAN_CATALOG.free.monthlyPriceMinor, 0);
  assert.equal(PLAN_CATALOG.free.includedUnitsMonth, 25_000);
  assert.equal(PLAN_CATALOG.free.capMode, "hard_cap");
  assert.equal(PLAN_CATALOG.free.ssoEnabled, false);

  assert.equal(PLAN_CATALOG.pro.monthlyPriceMinor, 3900);
  assert.equal(PLAN_CATALOG.pro.annualPriceMinor, 37200);
  assert.equal(PLAN_CATALOG.pro.includedUnitsMonth, 500_000);
  assert.equal(PLAN_CATALOG.pro.capMode, "hard_cap");

  assert.equal(PLAN_CATALOG.team.monthlyPriceMinor, 14900);
  assert.equal(PLAN_CATALOG.team.annualPriceMinor, 142800);
  assert.equal(PLAN_CATALOG.team.seatAddonMinor, 1900);
  assert.equal(PLAN_CATALOG.team.includedUnitsMonth, 3_000_000);
  assert.equal(PLAN_CATALOG.team.capMode, "soft_cap");
  assert.equal(PLAN_CATALOG.team.ssoEnabled, true);

  assert.equal(PLAN_CATALOG.enterprise.monthlyPriceMinor, 99900);
  assert.equal(PLAN_CATALOG.enterprise.includedUnitsMonth, 25_000_000);
  assert.equal(PLAN_CATALOG.enterprise.ssoEnabled, true);
});

test("reduceEntitlementState enforces all 9 sovereign states and 7-day dunning grace", () => {
  assert.equal(ENTITLEMENT_STATES.length, 9);
  assert.equal(BILLING_EVENT_KINDS.length, 12);
  for (const state of ENTITLEMENT_STATES) {
    assert.equal(isEntitlementState(state), true);
  }

  const now = new Date("2026-11-22T12:00:00.000Z");

  const trial = reduceEntitlementState("FREE", "trial_started", now);
  assert.equal(trial.nextState, "TRIALING");
  assert.equal(isPaidDeliveryAllowed(trial.nextState), true);

  const active = reduceEntitlementState("TRIALING", "invoice_paid", now);
  assert.equal(active.nextState, "ACTIVE");
  assert.equal(active.freezeExpansion, false);
  assert.equal(isPaidDeliveryAllowed(active.nextState), true);

  const pastDue = reduceEntitlementState("ACTIVE", "invoice_payment_failed", now);
  assert.equal(pastDue.nextState, "PAST_DUE_GRACE");
  assert.equal(pastDue.graceEndsAt?.getTime(), now.getTime() + GRACE_PERIOD_MS);
  assert.equal(pastDue.freezeExpansion, false);
  assert.equal(isPaidDeliveryAllowed(pastDue.nextState), true);

  const restricted = reduceEntitlementState("PAST_DUE_GRACE", "grace_window_elapsed", now);
  assert.equal(restricted.nextState, "RESTRICTED_DOWNGRADED");
  assert.equal(restricted.freezeExpansion, true);
  assert.equal(isPaidDeliveryAllowed(restricted.nextState), false);

  const disputed = reduceEntitlementState("ACTIVE", "dispute_created", now);
  assert.equal(disputed.nextState, "DISPUTE_HOLD");
  assert.equal(disputed.freezeExpansion, true);
  assert.equal(isPaidDeliveryAllowed(disputed.nextState), false);

  const disputeWon = reduceEntitlementState("DISPUTE_HOLD", "dispute_won", now);
  assert.equal(disputeWon.nextState, "ACTIVE");

  const disputeLost = reduceEntitlementState("DISPUTE_HOLD", "dispute_lost", now);
  assert.equal(disputeLost.nextState, "CANCELED_TERMINATED");
  assert.equal(isPaidDeliveryAllowed(disputeLost.nextState), false);

  const cancelScheduled = reduceEntitlementState("ACTIVE", "cancel_scheduled", now);
  assert.equal(cancelScheduled.nextState, "CANCELED_END_OF_PERIOD");
  assert.equal(isPaidDeliveryAllowed(cancelScheduled.nextState), true);

  const reconciling = reduceEntitlementState("ACTIVE", "reconcile_timeout", now);
  assert.equal(reconciling.nextState, "UNKNOWN_RECONCILING");
  assert.equal(reconciling.freezeExpansion, true);
  assert.equal(isPaidDeliveryAllowed(reconciling.nextState), false);

  const reconciled = reduceEntitlementState("UNKNOWN_RECONCILING", "reconcile_confirmed_active", now);
  assert.equal(reconciled.nextState, "ACTIVE");
});

test("zero-charge reasons, never-paywall actions, console view states, Sybil checks, and currency formatting behave strictly", () => {
  assert.equal(BILLED_REASONS.length, 6);
  assert.equal(ZERO_CHARGE_REASONS.length, 4);
  for (const r of BILLED_REASONS) {
    assert.equal(isBilledReason(r), true);
  }
  assert.equal(isZeroChargeReason("metered_usage"), false);
  assert.equal(isZeroChargeReason("included_allowance"), false);
  for (const r of ZERO_CHARGE_REASONS) {
    assert.equal(isZeroChargeReason(r), true);
  }

  for (const action of NEVER_PAYWALL_ACTIONS) {
    assert.equal(isNeverPaywallAction(action), true);
  }
  assert.equal(isNeverPaywallAction("org.erasure.request"), true);
  assert.equal(isNeverPaywallAction("events.admit"), false);

  assert.equal(CONSOLE_VIEW_STATES.length, 8);
  for (const viewState of CONSOLE_VIEW_STATES) {
    assert.equal(isConsoleViewState(viewState), true);
  }

  assert.deepEqual(validateSignupSybilHygiene("alice@company.example"), { allowed: true });
  assert.deepEqual(validateSignupSybilHygiene("bob@mailinator.com"), {
    allowed: false,
    reason: "DISPOSABLE_EMAIL_DOMAIN_REJECTED"
  });
  assert.deepEqual(validateSignupSybilHygiene("bad-email"), {
    allowed: false,
    reason: "INVALID_EMAIL_FORMAT"
  });

  assert.equal(formatMinorCurrency(3900, "USD", "en-US"), "$39.00");
  assert.equal(formatMinorCurrency(14900, "USD", "en-US"), "$149.00");
});
