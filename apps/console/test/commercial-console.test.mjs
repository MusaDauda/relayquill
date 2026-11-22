import test from "node:test";
import assert from "node:assert/strict";
import { CONSOLE_VIEW_STATES } from "@relayquill/domain";
import {
  buildBillingPath,
  buildOnboardingPath,
  buildSettingsAuditPath,
  buildStatusPath,
  parseConsolePathname
} from "../src/app/router.js";
import { createCommercialConsoleApiMethods } from "../src/api/commercial-api.js";
import { describeCommercialViewState } from "../src/components/CommercialStateBanner.js";
import {
  createConsoleTelemetry,
  readConsoleTelemetryConfig,
  scrubBrowserRoute,
  scrubTelemetryProps
} from "../src/utils/telemetry.js";

test("commercial router parses /status, /onboarding, /billing, and /settings/audit cleanly", () => {
  assert.deepEqual(parseConsolePathname(buildStatusPath()), { kind: "status" });
  assert.deepEqual(parseConsolePathname(buildOnboardingPath()), { kind: "onboarding" });
  assert.deepEqual(parseConsolePathname(buildBillingPath()), { kind: "billing" });
  assert.deepEqual(parseConsolePathname(buildSettingsAuditPath()), { kind: "settings_audit" });
});

test("describeCommercialViewState covers all 8 CONSOLE_VIEW_STATES cleanly", () => {
  assert.equal(CONSOLE_VIEW_STATES.length, 8);
  for (const state of CONSOLE_VIEW_STATES) {
    const desc = describeCommercialViewState(state);
    assert.equal(desc.state, state);
    assert.ok(desc.label.length > 0);
    assert.ok(desc.summary.length > 0);
    assert.ok(["status", "alert"].includes(desc.role));
  }
  assert.equal(describeCommercialViewState("quota_exceeded").tone, "warn");
  assert.equal(describeCommercialViewState("quota_exceeded").role, "alert");
});

test("console telemetry is env-gated and scrubs sensitive routes and fields", () => {
  const disabledCfg = readConsoleTelemetryConfig({});
  assert.equal(disabledCfg.sentryDsn, null);
  assert.equal(disabledCfg.posthogKey, null);

  let called = 0;
  const noopClient = createConsoleTelemetry(disabledCfg, {
    fetch: () => {
      called += 1;
      return Promise.resolve(new Response(null, { status: 200 }));
    }
  });
  assert.equal(noopClient.captureException(new Error("boom"), { route: "/billing?token=abc" }), false);
  assert.equal(noopClient.captureEvent("billing.checkout_initiated", { api_key: "secret" }), false);
  assert.equal(called, 0);

  assert.equal(scrubBrowserRoute("/billing?session_id=cs_live_secret#frag"), "/billing");
  const scrubbed = scrubTelemetryProps({
    plan_tier: "pro",
    api_key: "rk_live_secret",
    password: "123",
    email: "alice@example.com"
  });
  assert.equal(scrubbed["plan_tier"], "pro");
  assert.equal(scrubbed["api_key"], "[REDACTED]");
  assert.equal(scrubbed["password"], "[REDACTED]");
  assert.equal(scrubbed["email"], "[REDACTED]");

  const requests = [];
  const enabledClient = createConsoleTelemetry(
    {
      sentryDsn: "https://public@o1.ingest.sentry.io/42",
      posthogKey: "phc_test_key",
      posthogHost: "https://eu.posthog.com"
    },
    {
      fetch: (url, init) => {
        requests.push({ url: String(url), body: String(init?.body ?? "") });
        return Promise.resolve(new Response(null, { status: 200 }));
      }
    }
  );
  assert.equal(enabledClient.captureException(new Error("db failed"), { route: "/billing?token=123" }), true);
  assert.equal(enabledClient.captureEvent("checkout.started", { plan_tier: "team", secret: "x" }), true);
  assert.equal(requests.length, 2);
  assert.ok(!requests[0].body.includes("token=123"));
  assert.ok(!requests[1].body.includes('"x"'));
});

test("createCommercialConsoleApiMethods dispatches commercial billing, status, auth, and GDPR requests", async () => {
  const seen = [];
  const api = createCommercialConsoleApiMethods({
    async request(opts) {
      seen.push({ method: opts.method, path: opts.path, bodyObj: opts.bodyObj });
      return {
        ok: true,
        status: 200,
        data: opts.parseData({
          service: "relayquill",
          overall_status: "operational",
          checked_at: "2026-11-22T00:00:00.000000Z",
          components: []
        }),
        meta: { request_id: "req-1", observed_at: "2026-11-22T00:00:00.000000Z" }
      };
    }
  });

  const statusRes = await api.getPublicStatus();
  assert.equal(statusRes.ok, true);
  await api.getBillingSubscription({ country: "NG" });
  await api.getBillingUsage({ period_month: "2026-11" });
  await api.createBillingCheckout(
    { plan_tier: "pro", billing_interval: "month", country_code: "NG" },
    "idem-1"
  );
  await api.createBillingPortal({}, "idem-2");
  await api.cancelBillingSubscription({}, "idem-3");
  await api.getSettingsAudit();
  await api.requestGdprErasure({ confirm_phrase: "DELETE ORGANIZATION", password: "pw" }, "idem-4");

  assert.deepEqual(
    seen.map((s) => `${s.method} ${s.path}`),
    [
      "GET /api/v1/status",
      "GET /api/v1/billing/subscription?country=NG",
      "GET /api/v1/billing/usage?period_month=2026-11",
      "POST /api/v1/billing/checkout",
      "POST /api/v1/billing/portal",
      "POST /api/v1/billing/cancel",
      "GET /api/v1/settings/audit",
      "POST /api/v1/orgs/me/erasure-request"
    ]
  );
});
