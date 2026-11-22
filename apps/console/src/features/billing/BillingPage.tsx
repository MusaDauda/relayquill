import { type JSX, useState } from "react";
import {
  PLAN_CATALOG,
  type PlanTier,
  formatMinorCurrency,
  isZeroChargeReason
} from "@relayquill/domain";
import {
  type BillingCheckoutResponseDto,
  type BillingSubscriptionViewDto,
  type BillingUsageEventDto,
  type CommercialBillingIntervalDto,
  type CommercialBillingProviderDto
} from "../../api/dtos.js";
import { buildSettingsAuditPath, useConsoleRouter } from "../../app/router.js";
import { useConsoleRuntime } from "../../app/session.js";
import { useScopedQuery } from "../../app/use-scoped-query.js";
import { CommercialStateBanner } from "../../components/CommercialStateBanner.js";
import { DataTable } from "../../components/DataTable.js";
import { FormField } from "../../components/FormField.js";
import { ConsoleIcon } from "../../components/Icons.js";
import {
  MutationFeedback,
  type MutationFeedbackState
} from "../../components/MutationFeedback.js";
import { ResourceStatePanel } from "../../components/ResourceStatePanel.js";
import { StatusBadge } from "../../components/StatusBadge.js";
import { UtcTimestamp } from "../../components/UtcTimestamp.js";
import { generateIdempotencyKey } from "../../utils/idempotency.js";
import { consoleTelemetry } from "../../utils/telemetry.js";

const COUNTRY_OPTIONS: readonly { readonly code: string; readonly label: string }[] = [
  { code: "US", label: "United States (Stripe / USD)" },
  { code: "GB", label: "United Kingdom (Stripe / GBP)" },
  { code: "DE", label: "European Union — Germany (Stripe / EUR)" },
  { code: "NG", label: "Nigeria (Paystack Africa / NGN)" },
  { code: "GH", label: "Ghana (Paystack Africa / GHS)" },
  { code: "KE", label: "Kenya (Paystack Africa / KES)" },
  { code: "ZA", label: "South Africa (Paystack Africa / ZAR)" },
  { code: "AE", label: "United Arab Emirates (Tap MENA / AED)" },
  { code: "SA", label: "Saudi Arabia (Tap MENA / SAR)" },
  { code: "KW", label: "Kuwait (Tap MENA / KWD)" }
];

const UPGRADE_TIERS: readonly Exclude<PlanTier, "free">[] = ["pro", "team", "enterprise"];

function toNumericCount(val: string | number | undefined): number {
  if (typeof val === "number") {
    return Number.isFinite(val) ? val : 0;
  }
  if (typeof val === "string") {
    const parsed = Number(val);
    return Number.isFinite(parsed) ? parsed : 0;
  }
  return 0;
}

export function BillingPage(): JSX.Element {
  const { api, session } = useConsoleRuntime();
  const { navigate } = useConsoleRouter();

  const [countryCode, setCountryCode] = useState("US");
  const [providerOverride, setProviderOverride] = useState<"auto" | CommercialBillingProviderDto>("auto");
  const [billingInterval, setBillingInterval] = useState<CommercialBillingIntervalDto>("month");
  const [checkoutResult, setCheckoutResult] = useState<BillingCheckoutResponseDto | null>(null);
  const [mutationFeedback, setMutationFeedback] = useState<MutationFeedbackState>({ kind: "idle" });

  const subQuery = useScopedQuery({
    resource: "billing.subscription",
    enabled: session !== null,
    filter: { countryCode },
    fetcher: (signal) => api.getBillingSubscription({ country: countryCode }, signal)
  });

  const usageQuery = useScopedQuery({
    resource: "billing.usage",
    enabled: session !== null,
    fetcher: (signal) => api.getBillingUsage({}, signal)
  });

  const handleStartCheckout = async (planTier: Exclude<PlanTier, "free">): Promise<void> => {
    setMutationFeedback({
      kind: "submitting",
      label: `Creating ${planTier} checkout session...`
    });
    const res = await api.createBillingCheckout(
      {
        plan_tier: planTier,
        billing_interval: billingInterval,
        country_code: countryCode,
        ...(providerOverride !== "auto" ? { provider: providerOverride } : {})
      },
      generateIdempotencyKey("billing-checkout")
    );
    if (!res.ok) {
      setMutationFeedback({ kind: "failed", error: res });
      return;
    }
    setCheckoutResult(res.data);
    consoleTelemetry.captureEvent("billing.checkout_initiated", {
      plan_tier: planTier,
      interval: billingInterval,
      provider: res.data.provider
    });
    setMutationFeedback({
      kind: "succeeded",
      title: "Checkout Session Ready",
      detail: `${res.data.provider.toUpperCase()} session ${res.data.session_id} prepared for ${formatMinorCurrency(res.data.amount_minor, res.data.currency)}.`
    });
    subQuery.reload();
  };

  const handleOpenPortal = async (): Promise<void> => {
    setMutationFeedback({
      kind: "submitting",
      label: "Opening never-paywalled billing portal..."
    });
    const res = await api.createBillingPortal({}, generateIdempotencyKey("billing-portal"));
    if (!res.ok) {
      setMutationFeedback({ kind: "failed", error: res });
      return;
    }
    setMutationFeedback({
      kind: "succeeded",
      title: "Billing Portal Ready",
      detail: `${res.data.provider.toUpperCase()} portal URL: ${res.data.portal_url}`
    });
  };

  const handleCancelSubscription = async (): Promise<void> => {
    setMutationFeedback({
      kind: "submitting",
      label: "Scheduling end-of-period subscription cancellation..."
    });
    const res = await api.cancelBillingSubscription({}, generateIdempotencyKey("billing-cancel"));
    if (!res.ok) {
      setMutationFeedback({ kind: "failed", error: res });
      return;
    }
    setMutationFeedback({
      kind: "succeeded",
      title: "Cancellation Scheduled",
      detail: `Subscription transitioned from ${res.data.previous_state} to ${res.data.entitlement_state} (cancel_at_period_end=${String(res.data.cancel_at_period_end)}).`
    });
    subQuery.reload();
  };

  const renderSubscriptionContent = (subData: BillingSubscriptionViewDto): JSX.Element => {
    const rollup = subData.usage_rollups[0];
    const billableUnits = toNumericCount(rollup?.total_billable_units);
    const freeUnits = toNumericCount(rollup?.total_free_units);
    const includedUnits = Math.max(1, toNumericCount(subData.quotas.included_units_month));
    const usagePct = Math.min(100, Math.round((billableUnits / includedUnits) * 100));
    const quotaBannerState =
      billableUnits >= includedUnits && subData.quotas.cap_mode === "hard_cap"
        ? "quota_exceeded"
        : usagePct >= 70
          ? "partial"
          : "ready";

    return (
      <div className="rq-stack">
        {quotaBannerState !== "ready" ? (
          <CommercialStateBanner
            state={quotaBannerState}
            detail={
              quotaBannerState === "quota_exceeded"
                ? `Monthly allowance reached (${billableUnits.toLocaleString()} / ${includedUnits.toLocaleString()} deliveries). Portal, self-serve cancel, audit logs, and GDPR erasure stay accessible.`
                : `Monthly usage reached ${usagePct}% of included plan allowance.`
            }
          />
        ) : null}

        <div className="rq-grid-2">
          <section className="rq-card" aria-label="Current entitlement and usage meter">
            <div className="rq-card-header">
              <h2 className="rq-card-title">Current Subscription &amp; Quota</h2>
              <StatusBadge
                status={
                  subData.subscription.entitlement_state === "ACTIVE" ||
                  subData.subscription.entitlement_state === "FREE"
                    ? "active"
                    : "pressure"
                }
                label={`${subData.subscription.plan_tier.toUpperCase()} (${subData.subscription.entitlement_state})`}
              />
            </div>

            <dl className="rq-kv-grid">
              <dt>Billing Period</dt>
              <dd className="mono rq-tabular">{subData.period_month}</dd>
              <dt>Cap Policy</dt>
              <dd className="mono">
                {subData.quotas.cap_mode} ({includedUnits.toLocaleString()} included / month)
              </dd>
              <dt>Billable Deliveries</dt>
              <dd className="mono rq-tabular">{billableUnits.toLocaleString()}</dd>
              <dt>Zero-Charge Replays &amp; Exempt</dt>
              <dd className="mono rq-tabular">{freeUnits.toLocaleString()}</dd>
              <dt>Seats / Concurrency / Retention</dt>
              <dd className="mono rq-tabular">
                {subData.quotas.max_seats} seats | {subData.quotas.max_concurrency} concurrent |{" "}
                {subData.quotas.retention_days}d retention
              </dd>
            </dl>

            <div className="rq-stack-sm">
              <div className="rq-row-between">
                <span className="rq-meta-text">Included Monthly Allowance</span>
                <span className="mono rq-tabular">{usagePct}%</span>
              </div>
              <div
                className="rq-meter-track"
                role="progressbar"
                aria-valuenow={usagePct}
                aria-valuemin={0}
                aria-valuemax={100}
                aria-label="Monthly included delivery usage"
              >
                <div
                  className="rq-meter-fill"
                  data-tone={quotaBannerState === "quota_exceeded" ? "error" : "ok"}
                  style={{ width: `${usagePct}%` }}
                />
              </div>
            </div>
          </section>

          <section className="rq-card" aria-label="Regional gateway selector and portal">
            <div className="rq-card-header">
              <h2 className="rq-card-title">Regional Payment Routing</h2>
              <StatusBadge status="verified_supported" label={subData.regional_routing.provider.toUpperCase()} />
            </div>

            <div className="rq-grid-2">
              <FormField label="Billing Country / Region">
                {({ inputId, describedBy }) => (
                  <select
                    id={inputId}
                    aria-describedby={describedBy}
                    className="rq-select"
                    value={countryCode}
                    onChange={(e) => {
                      setCountryCode(e.target.value);
                    }}
                  >
                    {COUNTRY_OPTIONS.map((opt) => (
                      <option key={opt.code} value={opt.code}>
                        {opt.label}
                      </option>
                    ))}
                  </select>
                )}
              </FormField>

              <FormField label="Gateway Selection">
                {({ inputId, describedBy }) => (
                  <select
                    id={inputId}
                    aria-describedby={describedBy}
                    className="rq-select"
                    value={providerOverride}
                    onChange={(e) => {
                      const val = e.target.value;
                      setProviderOverride(
                        val === "stripe" || val === "paystack" || val === "tap" ? val : "auto"
                      );
                    }}
                  >
                    <option value="auto">
                      Auto Regional ({subData.regional_routing.provider.toUpperCase()})
                    </option>
                    <option value="stripe">Stripe (Global &amp; Stripe Tax)</option>
                    <option value="paystack">Paystack (Africa — NGN/GHS/KES/ZAR)</option>
                    <option value="tap">Tap Payments (MENA — AED/SAR/KWD)</option>
                  </select>
                )}
              </FormField>
            </div>

            <dl className="rq-kv-grid">
              <dt>Selected Gateway</dt>
              <dd className="mono">
                {subData.regional_routing.regionLabel} ({subData.regional_routing.currency})
              </dd>
              <dt>Tax Automation</dt>
              <dd>{subData.regional_routing.taxAutomation ? "Automatic VAT / Sales Tax enabled" : "Local regional checkout tax rules"}</dd>
              <dt>Configured Server Adapters</dt>
              <dd className="mono">
                {subData.configured_providers.length > 0
                  ? subData.configured_providers.join(", ")
                  : "No live gateway keys configured in dev"}
              </dd>
            </dl>

            <div className="rq-row">
              <button
                type="button"
                className="rq-btn"
                onClick={() => {
                  void handleOpenPortal();
                }}
              >
                Open Billing Portal (Never Paywalled)
              </button>
              <button
                type="button"
                className="rq-btn rq-btn-danger"
                onClick={() => {
                  void handleCancelSubscription();
                }}
              >
                Cancel at Period End
              </button>
              <button
                type="button"
                className="rq-btn"
                onClick={() => {
                  navigate(buildSettingsAuditPath());
                }}
              >
                Audit &amp; GDPR Settings
              </button>
            </div>
          </section>
        </div>

        <section className="rq-card" aria-label="Commercial plans">
          <div className="rq-row-between">
            <div>
              <h2 className="rq-section-title">Commercial Plans</h2>
              <p className="rq-meta-text">
                SSO SAML/OIDC is included from Team and above without a standalone SSO surcharge.
              </p>
            </div>
            <div className="rq-tabs" role="tablist" aria-label="Billing interval">
              <button
                type="button"
                role="tab"
                className="rq-tab"
                aria-selected={billingInterval === "month"}
                onClick={() => {
                  setBillingInterval("month");
                }}
              >
                Monthly
              </button>
              <button
                type="button"
                role="tab"
                className="rq-tab"
                aria-selected={billingInterval === "year"}
                onClick={() => {
                  setBillingInterval("year");
                }}
              >
                Annual
              </button>
            </div>
          </div>

          <div className="rq-grid-3">
            {UPGRADE_TIERS.map((tier) => {
              const spec = PLAN_CATALOG[tier];
              const priceMinor =
                billingInterval === "year" && spec.annualPriceMinor !== null
                  ? spec.annualPriceMinor
                  : spec.monthlyPriceMinor;
              const isCurrent = subData.subscription.plan_tier === tier;
              return (
                <article
                  key={tier}
                  className="rq-plan-card"
                  data-current={isCurrent ? "true" : "false"}
                >
                  <div className="rq-row-between">
                    <strong className="rq-card-title">{tier.toUpperCase()}</strong>
                    {isCurrent ? <StatusBadge status="active" label="Current" /> : null}
                  </div>
                  <p className="rq-metric-value rq-tabular">
                    {formatMinorCurrency(priceMinor, "USD")}
                    <span className="rq-meta-text">/{billingInterval}</span>
                  </p>
                  <p className="rq-meta-text mono rq-tabular">
                    {spec.includedUnitsMonth.toLocaleString()} deliveries/mo | {spec.maxSeats} seats |{" "}
                    {spec.retentionDays}d retention | SSO: {spec.ssoEnabled ? "Included" : "No"}
                  </p>
                  <button
                    type="button"
                    className="rq-btn rq-btn-primary"
                    onClick={() => {
                      void handleStartCheckout(tier);
                    }}
                  >
                    Checkout ({providerOverride === "auto" ? subData.regional_routing.provider : providerOverride})
                  </button>
                </article>
              );
            })}
          </div>

          <MutationFeedback
            state={mutationFeedback}
            resourceLabel="Billing mutation"
            onDismiss={() => {
              setMutationFeedback({ kind: "idle" });
            }}
          />

          {checkoutResult !== null ? (
            <div className="rq-card-inset">
              <strong className="rq-label">Checkout Redirect URL</strong>
              <a
                href={checkoutResult.checkout_url}
                className="mono"
                target="_blank"
                rel="noreferrer"
              >
                {checkoutResult.checkout_url}
              </a>
            </div>
          ) : null}
        </section>
      </div>
    );
  };

  return (
    <div className="rq-stack">
      <header className="rq-page-header">
        <div>
          <h1 className="rq-page-title">Billing, Regional Gateways &amp; Usage</h1>
          <p className="rq-page-lead">
            Multi-provider checkout routing across Stripe Global, Paystack Africa, and Tap MENA,
            plus transparent zero-charge replay accounting.
          </p>
        </div>
        <button
          type="button"
          className="rq-btn"
          onClick={() => {
            subQuery.reload();
            usageQuery.reload();
          }}
        >
          <ConsoleIcon name="refresh" />
          <span>Refresh</span>
        </button>
      </header>

      <ResourceStatePanel
        view={subQuery.view}
        resourceLabel="Subscription and quota summary"
        onRetry={subQuery.reload}
      >
        {(subData) => renderSubscriptionContent(subData)}
      </ResourceStatePanel>

      <section className="rq-card" aria-label="Usage events ledger">
        <h2 className="rq-section-title">Metered &amp; Zero-Charge Usage Ledger</h2>
        <p className="rq-meta-text">
          Idempotent replays, DLQ exemptions, cancelled events, and health probes remain visibly
          marked zero-charge.
        </p>
        <ResourceStatePanel
          view={usageQuery.view}
          resourceLabel="Usage event ledger"
          emptyTitle="No usage events recorded yet"
          emptyDescription="Admit or deliver events to inspect metered billable units vs. zero-charge exemptions."
          onRetry={usageQuery.reload}
        >
          {(usageData) => (
            <DataTable<BillingUsageEventDto>
              caption="Recent metered and zero-charge billing events"
              rows={usageData.events}
              rowKey={(row) => row.usage_event_id}
              columns={[
                {
                  key: "created_at",
                  header: "Timestamp",
                  render: (row) => <UtcTimestamp value={row.created_at} showLocal={false} />
                },
                {
                  key: "metric",
                  header: "Metric",
                  render: (row) => <span className="mono">{row.metric_code}</span>
                },
                {
                  key: "units",
                  header: "Units",
                  render: (row) => (
                    <span className="mono rq-tabular">
                      {toNumericCount(row.billable_units).toLocaleString()}
                    </span>
                  )
                },
                {
                  key: "reason",
                  header: "Classification",
                  render: (row) => {
                    const zeroCharge = isZeroChargeReason(
                      row.billed_reason as Parameters<typeof isZeroChargeReason>[0]
                    );
                    return (
                      <StatusBadge
                        status={zeroCharge ? "verified_supported" : "active"}
                        label={zeroCharge ? `${row.billed_reason} ($0)` : row.billed_reason}
                      />
                    );
                  }
                },
                {
                  key: "idempotency_key",
                  header: "Idempotency Key",
                  render: (row) => <span className="mono">{row.idempotency_key}</span>
                }
              ]}
            />
          )}
        </ResourceStatePanel>
      </section>
    </div>
  );
}
