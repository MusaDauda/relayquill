import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import Stripe from "stripe";
import {
  createPaystackBillingAdapter,
  createPinnedStripeClient,
  createStripeBillingAdapter,
  createTapBillingAdapter,
  InMemoryQuotaRedisClient
} from "@relayquill/billing";
import { parseUtcTimestamp } from "@relayquill/domain";
import { createPGliteAdapter } from "@relayquill/postgres";
import { createAllowlistedLogger, createApiServer } from "../dist/index.js";

const TEST_DIR = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(TEST_DIR, "../../..");
const MIGRATIONS_DIR = path.join(REPO_ROOT, "migrations");
const CONSOLE_ORIGIN = "http://localhost:5205";

async function applyMigrations(pg) {
  const files = fs.readdirSync(MIGRATIONS_DIR).filter((f) => f.endsWith(".sql")).sort();
  for (const f of files) {
    await pg.exec(fs.readFileSync(path.join(MIGRATIONS_DIR, f), "utf8"));
  }
}

function extractCookiePair(setCookieHeader, cookieName) {
  const headers = Array.isArray(setCookieHeader) ? setCookieHeader : [setCookieHeader];
  for (const h of headers) {
    if (typeof h === "string" && h.startsWith(`${cookieName}=`)) {
      return h.split(";")[0];
    }
  }
  return null;
}

test("Multi-provider regional billing (Stripe/Paystack/Tap), raw-body webhooks, 402 QuotaGuard, idempotent free replay, never-paywalled portal, and Sentry 5xx capture", async (t) => {
  const pg = await createPGliteAdapter({
    schema: "rq",
    supportSchema: "rq_support",
    isolation: "shared_database_schemas",
    configuredRole: "rq_api"
  });
  t.after(() => pg.close());
  await applyMigrations(pg);

  await pg.exec(`
    UPDATE rq.installation_state
       SET mode = 'open',
           allow_event_admission = true,
           allow_publication = true,
           allow_fanout = true,
           allow_send = true,
           allow_endpoint_verification = true,
           version = version + 1
     WHERE id = 1;
  `);

  const mockStripeServer = http.createServer((req, res) => {
    req.on("data", () => {});
    req.on("end", () => {
      res.writeHead(200, { "content-type": "application/json" });
      if (req.url?.includes("/checkout/sessions")) {
        res.end(
          JSON.stringify({
            id: "cs_api_mock_1",
            url: "https://checkout.stripe.test/session/cs_api_mock_1"
          })
        );
      } else {
        res.end(
          JSON.stringify({
            id: "bps_api_mock_1",
            url: "https://billing.stripe.test/portal/bps_api_mock_1"
          })
        );
      }
    });
  });
  await new Promise((resolve) => mockStripeServer.listen(0, "127.0.0.1", resolve));
  t.after(() => mockStripeServer.close());
  const stripeMockPort = mockStripeServer.address().port;

  const stripeSecret = "whsec_api_integration_secret";
  const paystackSecret = "psk_api_integration_secret";
  const tapSecret = "tap_api_integration_secret";

  const stripeClient = createPinnedStripeClient({
    apiKey: "rk_test_api_mock",
    host: "127.0.0.1",
    port: stripeMockPort,
    protocol: "http"
  });
  const billingAdapters = {
    stripe: createStripeBillingAdapter({ client: stripeClient, webhookSecret: stripeSecret }),
    paystack: createPaystackBillingAdapter({
      secretKey: paystackSecret,
      fetchImpl: async () =>
        new Response(
          JSON.stringify({
            status: true,
            data: { authorization_url: "https://checkout.paystack.test/ng_1", reference: "ps_ref_1" }
          }),
          { status: 200 }
        )
    }),
    tap: createTapBillingAdapter({
      secretKey: tapSecret,
      fetchImpl: async () =>
        new Response(
          JSON.stringify({
            id: "chg_tap_1",
            transaction: { url: "https://tap.company.test/chg_tap_1" }
          }),
          { status: 200 }
        )
    })
  };

  let fixedMs = Date.UTC(2026, 10, 22, 16, 0, 0);
  const fixedClock = {
    nowMs: () => fixedMs,
    nowInstant: () => parseUtcTimestamp(new Date(fixedMs).toISOString()).instant,
    nowTimestamp: () => new Date(fixedMs).toISOString()
  };

  const quotaRedis = new InMemoryQuotaRedisClient();
  const capturedErrors = [];
  const server = createApiServer({
    pgAdapter: pg,
    profile: "development_trusted_local",
    allowDevBootstrapRoute: true,
    clock: fixedClock,
    quotaRedis,
    billingAdapters,
    errorReporter: {
      enabled: true,
      provider: "sentry",
      projectId: "42",
      async captureException(err, context) {
        capturedErrors.push({ err, context });
        return Promise.resolve({
          sent: true,
          reason: "dispatched",
          eventId: "e".repeat(32),
          scrubbedMessage: err instanceof Error ? err.message : String(err)
        });
      }
    },
    logger: createAllowlistedLogger({ level: "silent" })
  });
  t.after(() => server.close());
  const { app } = server;
  app.get("/api/v1/test-sentry-5xx", () => {
    throw new Error("Simulated internal explosion with sk_live_secretXYZ");
  });

  // 1. Signup -> Free tier + verify regional checkout selection (US -> Stripe, NG -> Paystack, SA -> Tap)
  const signupRes = await app.inject({
    method: "POST",
    url: "/api/v1/auth/signup",
    headers: { "content-type": "application/json" },
    payload: JSON.stringify({
      email: "cto@lagos-fintech.example",
      password: "ExamplePassphrase!ChangeBeforeUse",
      org_name: "Lagos Fintech",
      accept_legal: true
    })
  });
  assert.equal(signupRes.statusCode, 201, signupRes.body);
  const { tenant_id: tenantId, principal_id: principalId, csrf_token: csrf } = signupRes.json().data;
  const sessionCookie = extractCookiePair(signupRes.headers["set-cookie"], "rq_session_dev");
  assert.ok(sessionCookie);

  const sub0 = await app.inject({
    method: "GET",
    url: "/api/v1/billing/subscription?country=NG",
    headers: { cookie: sessionCookie }
  });
  assert.equal(sub0.statusCode, 200, sub0.body);
  assert.equal(sub0.json().data.subscription.entitlement_state, "FREE");
  assert.equal(sub0.json().data.regional_routing.provider, "paystack");
  assert.equal(sub0.json().data.regional_routing.currency, "NGN");

  const ngCheckoutRes = await app.inject({
    method: "POST",
    url: "/api/v1/billing/checkout",
    headers: {
      "content-type": "application/json",
      cookie: sessionCookie,
      origin: CONSOLE_ORIGIN,
      "x-relayquill-csrf": csrf,
      "idempotency-key": "chk-ng-1"
    },
    payload: JSON.stringify({
      plan_tier: "pro",
      billing_interval: "month",
      seat_count: 1,
      country_code: "NG"
    })
  });
  assert.equal(ngCheckoutRes.statusCode, 201, ngCheckoutRes.body);
  assert.equal(ngCheckoutRes.json().data.provider, "paystack");
  assert.equal(ngCheckoutRes.json().data.currency, "NGN");

  const saCheckoutRes = await app.inject({
    method: "POST",
    url: "/api/v1/billing/checkout",
    headers: {
      "content-type": "application/json",
      cookie: sessionCookie,
      origin: CONSOLE_ORIGIN,
      "x-relayquill-csrf": csrf,
      "idempotency-key": "chk-sa-1"
    },
    payload: JSON.stringify({
      plan_tier: "team",
      billing_interval: "month",
      country_code: "SA"
    })
  });
  assert.equal(saCheckoutRes.statusCode, 201, saCheckoutRes.body);
  assert.equal(saCheckoutRes.json().data.provider, "tap");
  assert.equal(saCheckoutRes.json().data.currency, "SAR");

  const usCheckoutRes = await app.inject({
    method: "POST",
    url: "/api/v1/billing/checkout",
    headers: {
      "content-type": "application/json",
      cookie: sessionCookie,
      origin: CONSOLE_ORIGIN,
      "x-relayquill-csrf": csrf,
      "idempotency-key": "chk-us-1"
    },
    payload: JSON.stringify({
      plan_tier: "pro",
      billing_interval: "month",
      country_code: "US"
    })
  });
  assert.equal(usCheckoutRes.statusCode, 201, usCheckoutRes.body);
  assert.equal(usCheckoutRes.json().data.provider, "stripe");
  assert.equal(usCheckoutRes.json().data.tax_automation_enabled, true);

  // 2. Webhook raw-body HMAC checks: bad sig -> 401, valid Paystack -> ACTIVE Pro, valid Stripe -> ACTIVE Team
  const badStripeHook = await app.inject({
    method: "POST",
    url: "/api/v1/webhooks/stripe",
    headers: { "content-type": "application/json", "stripe-signature": "t=1,v1=invalid" },
    payload: JSON.stringify({ id: "evt_bad", type: "checkout.session.completed", data: { object: {} } })
  });
  assert.equal(badStripeHook.statusCode, 401);

  const psRawBody = JSON.stringify({
    event: "charge.success",
    data: {
      reference: "ps_ref_1",
      amount: 6240000,
      currency: "NGN",
      paid_at: new Date(fixedMs).toISOString(),
      customer: { customer_code: "CUS_ng_1", email: "cto@lagos-fintech.example" },
      metadata: { org_id: tenantId, plan_tier: "pro", billing_interval: "month", seat_count: 1 }
    }
  });
  const psSig = crypto.createHmac("sha512", paystackSecret).update(psRawBody, "utf8").digest("hex");
  const psHookRes = await app.inject({
    method: "POST",
    url: "/api/v1/webhooks/paystack",
    headers: { "content-type": "application/json", "x-paystack-signature": psSig },
    payload: psRawBody
  });
  assert.equal(psHookRes.statusCode, 200, psHookRes.body);
  assert.equal(psHookRes.json().data.outcome, "APPLIED");
  assert.equal(psHookRes.json().data.next_state, "ACTIVE");

  // Re-deliver duplicate -> IGNORED_DUPLICATE
  const psDupRes = await app.inject({
    method: "POST",
    url: "/api/v1/webhooks/paystack",
    headers: { "content-type": "application/json", "x-paystack-signature": psSig },
    payload: psRawBody
  });
  assert.equal(psDupRes.statusCode, 200);
  assert.equal(psDupRes.json().data.outcome, "IGNORED_DUPLICATE");

  // Stripe upgrade checkout.session.completed webhook
  fixedMs += 5000;
  const stripeRaw = JSON.stringify({
    id: "evt_stripe_upgrade_1",
    object: "event",
    type: "checkout.session.completed",
    created: Math.floor(fixedMs / 1000),
    data: {
      object: {
        id: "cs_api_mock_1",
        object: "checkout.session",
        payment_status: "paid",
        client_reference_id: tenantId,
        customer: "cus_stripe_live_9",
        subscription: "sub_stripe_live_9",
        currency: "usd",
        amount_total: 3900,
        metadata: { org_id: tenantId, plan_tier: "pro", billing_interval: "month", seat_count: "3" }
      }
    }
  });
  const stripeSig = Stripe.webhooks.generateTestHeaderString({
    payload: stripeRaw,
    secret: stripeSecret,
    timestamp: Math.floor(fixedMs / 1000)
  });
  const stripeHookRes = await app.inject({
    method: "POST",
    url: "/api/v1/webhooks/stripe",
    headers: { "content-type": "application/json", "stripe-signature": stripeSig },
    payload: stripeRaw
  });
  assert.equal(stripeHookRes.statusCode, 200, stripeHookRes.body);
  assert.equal(stripeHookRes.json().data.next_state, "ACTIVE");

  // Tap webhook test with hashstring HMAC-SHA256
  fixedMs += 5000;
  const tapRaw = JSON.stringify({
    id: "chg_tap_1",
    status: "CAPTURED",
    amount: 558.75,
    currency: "SAR",
    customer: { id: "cus_tap_9", email: "cto@lagos-fintech.example" },
    transaction: { created: fixedMs },
    metadata: { org_id: tenantId, plan_tier: "pro", billing_interval: "month", seat_count: "3" }
  });
  const tapSig = crypto.createHmac("sha256", tapSecret).update(tapRaw, "utf8").digest("hex");
  const tapHookRes = await app.inject({
    method: "POST",
    url: "/api/v1/webhooks/tap",
    headers: { "content-type": "application/json", hashstring: tapSig },
    payload: tapRaw
  });
  assert.equal(tapHookRes.statusCode, 200, tapHookRes.body);
  assert.equal(tapHookRes.json().data.outcome, "APPLIED");

  // 3. Seed project + published event schema + human workflow channel, then verify Pre-Enqueue QuotaGuard 402
  const projectId = crypto.randomUUID();
  await pg.exec(`
    INSERT INTO rq.projects (id, tenant_id, name, state, topology_version, next_event_sequence, governance_version)
    VALUES ('${projectId}'::uuid, '${tenantId}'::uuid, 'payments-prod', 'active', 1, 1, 1);
    INSERT INTO rq.project_memberships (id, tenant_id, project_id, principal_id, role, state, authority_version)
    VALUES ('${crypto.randomUUID()}'::uuid, '${tenantId}'::uuid, '${projectId}'::uuid, '${principalId}'::uuid, 'project_admin', 'active', 1);
  `);

  const etRes = await app.inject({
    method: "POST",
    url: `/api/v1/tenants/${tenantId}/projects/${projectId}/event-types`,
    headers: {
      "content-type": "application/json",
      cookie: sessionCookie,
      origin: CONSOLE_ORIGIN,
      "x-relayquill-csrf": csrf,
      "idempotency-key": "et-bill-1"
    },
    payload: JSON.stringify({ schema_version: 1, type_name: "invoice.paid" })
  });
  assert.equal(etRes.statusCode, 201, etRes.body);
  const eventTypeId = etRes.json().data.event_type_id;

  const svRes = await app.inject({
    method: "POST",
    url: `/api/v1/tenants/${tenantId}/projects/${projectId}/event-types/${eventTypeId}/schema-versions`,
    headers: {
      "content-type": "application/json",
      cookie: sessionCookie,
      origin: CONSOLE_ORIGIN,
      "x-relayquill-csrf": csrf,
      "idempotency-key": "sv-bill-1"
    },
    payload: JSON.stringify({
      schema_version: 1,
      compatibility_policy: "additive_compatible",
      definition: {
        $schema: "https://json-schema.org/draft/2020-12/schema",
        type: "object",
        additionalProperties: false,
        required: ["order_id"],
        properties: { order_id: { type: "string", maxLength: 128 } }
      }
    })
  });
  assert.equal(svRes.statusCode, 201, svRes.body);
  await pg.exec(`
    UPDATE rq.event_schema_versions SET state = 'published', published_by = '${principalId}'::uuid
     WHERE event_type_id = '${eventTypeId}'::uuid;
    UPDATE rq.event_types SET state = 'active', current_schema_version = 1
     WHERE id = '${eventTypeId}'::uuid;
  `);

  const pubEnable = await app.inject({
    method: "POST",
    url: `/api/v1/tenants/${tenantId}/projects/${projectId}/publication-context/enable`,
    headers: {
      "content-type": "application/json",
      cookie: sessionCookie,
      origin: CONSOLE_ORIGIN,
      "x-relayquill-csrf": csrf,
      "idempotency-key": "pub-en-1"
    },
    payload: JSON.stringify({ schema_version: 1 })
  });
  assert.ok(pubEnable.statusCode === 200 || pubEnable.statusCode === 201, pubEnable.body);
  const pubChannelId = pubEnable.json().data.publication_channel_id;

  const rawPayload = Buffer.from('{"order_id":"ord_1"}', "utf8");
  const admitReqBody = {
    schema_version: 1,
    expected_publication_channel_id: pubChannelId,
    event_type_id: eventTypeId,
    event_schema_version: 1,
    business_key: "ord_1",
    content: {
      media_type: "application/json",
      encoding: "base64",
      data: rawPayload.toString("base64"),
      sha256: crypto.createHash("sha256").update(rawPayload).digest("hex")
    }
  };

  // Seed Redis usage counter at Pro cap - 1 (499,999) for 2026-11
  quotaRedis.seedUsage(`rq:quota:${tenantId}:2026-11`, 499_999);

  // First event hits 500,000 -> 201 admitted
  const evOk = await app.inject({
    method: "POST",
    url: `/api/v1/tenants/${tenantId}/projects/${projectId}/events`,
    headers: {
      "content-type": "application/json",
      cookie: sessionCookie,
      origin: CONSOLE_ORIGIN,
      "x-relayquill-csrf": csrf,
      "idempotency-key": "ev-cap-500k"
    },
    payload: JSON.stringify(admitReqBody)
  });
  assert.equal(evOk.statusCode, 201, evOk.body);

  // Malformed Bearer token returns 400 INVALID_CREDENTIAL_SELECTOR (never leaks 402 quota oracle)
  const malformedBearer = await app.inject({
    method: "POST",
    url: `/api/v1/tenants/${tenantId}/projects/${projectId}/events`,
    headers: {
      "content-type": "application/json",
      authorization: "Bearer rq_invalid_token_xyz",
      "idempotency-key": "ev-unauth-1"
    },
    payload: JSON.stringify({ ...admitReqBody, business_key: "ord_unauth" })
  });
  assert.equal(malformedBearer.statusCode, 400, malformedBearer.body);
  assert.equal(malformedBearer.json().error.code, "INVALID_CREDENTIAL_SELECTOR");

  // Request with no session cookie or Authorization returns 401 UNAUTHENTICATED (never leaks 402 oracle)
  const noCreds = await app.inject({
    method: "POST",
    url: `/api/v1/tenants/${tenantId}/projects/${projectId}/events`,
    headers: {
      origin: CONSOLE_ORIGIN,
      "content-type": "application/json",
      "idempotency-key": "ev-unauth-2"
    },
    payload: JSON.stringify({ ...admitReqBody, business_key: "ord_unauth_2" })
  });
  assert.equal(noCreds.statusCode, 401, noCreds.body);
  assert.equal(noCreds.json().error.code, "UNAUTHENTICATED");

  // Second unique event exceeds 500k hard cap -> 402 QUOTA_HARD_CAP_REACHED
  const rawPayload2 = Buffer.from('{"order_id":"ord_2"}', "utf8");
  const evBlocked = await app.inject({
    method: "POST",
    url: `/api/v1/tenants/${tenantId}/projects/${projectId}/events`,
    headers: {
      "content-type": "application/json",
      cookie: sessionCookie,
      origin: CONSOLE_ORIGIN,
      "x-relayquill-csrf": csrf,
      "idempotency-key": "ev-cap-over"
    },
    payload: JSON.stringify({
      ...admitReqBody,
      business_key: "ord_2",
      content: {
        media_type: "application/json",
        encoding: "base64",
        data: rawPayload2.toString("base64"),
        sha256: crypto.createHash("sha256").update(rawPayload2).digest("hex")
      }
    })
  });
  assert.equal(evBlocked.statusCode, 402, evBlocked.body);
  assert.equal(evBlocked.json().error.code, "QUOTA_HARD_CAP_REACHED");

  // Idempotent replay of ev-cap-500k succeeds 200 with 0 billable units even at cap
  const evReplay = await app.inject({
    method: "POST",
    url: `/api/v1/tenants/${tenantId}/projects/${projectId}/events`,
    headers: {
      "content-type": "application/json",
      cookie: sessionCookie,
      origin: CONSOLE_ORIGIN,
      "x-relayquill-csrf": csrf,
      "idempotency-key": "ev-cap-500k"
    },
    payload: JSON.stringify(admitReqBody)
  });
  assert.equal(evReplay.statusCode, 200, evReplay.body);

  const usageRes = await app.inject({
    method: "GET",
    url: "/api/v1/billing/usage?period_month=2026-11",
    headers: { cookie: sessionCookie }
  });
  assert.equal(usageRes.statusCode, 200, usageRes.body);
  assert.ok(
    usageRes.json().data.events.some((e) => e.billed_reason === "idempotent_replay_free"),
    "Expected zero-charge idempotent_replay_free record in billing usage"
  );

  // Never-paywalled portal & cancel remain accessible even after 402 hard cap
  const portalRes = await app.inject({
    method: "POST",
    url: "/api/v1/billing/portal",
    headers: {
      "content-type": "application/json",
      cookie: sessionCookie,
      origin: CONSOLE_ORIGIN,
      "x-relayquill-csrf": csrf,
      "idempotency-key": "portal-after-cap"
    }
  });
  assert.equal(portalRes.statusCode, 200, portalRes.body);

  const cancelRes = await app.inject({
    method: "POST",
    url: "/api/v1/billing/cancel",
    headers: {
      "content-type": "application/json",
      cookie: sessionCookie,
      origin: CONSOLE_ORIGIN,
      "x-relayquill-csrf": csrf,
      "idempotency-key": "cancel-after-cap"
    }
  });
  assert.equal(cancelRes.statusCode, 200, cancelRes.body);
  assert.equal(cancelRes.json().data.cancel_at_period_end, true);
  assert.equal(cancelRes.json().data.entitlement_state, "CANCELED_END_OF_PERIOD");

  // 4. Verify env-gated Sentry errorReporter triggers on unexpected 5xx route failure
  const boomRes = await app.inject({ method: "GET", url: "/api/v1/test-sentry-5xx" });
  assert.equal(boomRes.statusCode, 500);
  assert.equal(capturedErrors.length, 1);
  assert.equal(capturedErrors[0].context.statusCode, 500);
});
