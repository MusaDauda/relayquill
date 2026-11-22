import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import net from "node:net";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import Stripe from "stripe";
import { mapDomainErrorCodeToHttpStatus } from "@relayquill/contracts";
import { LimitExceededDomainError, parseTenantId } from "@relayquill/domain";
import { createPGliteAdapter, withTenantRlsTransaction } from "@relayquill/postgres";
import {
  computePlanTotalMinor,
  createAwsSesEmailAdapter,
  createInMemoryEmailAdapter,
  createMailpitSmtpEmailAdapter,
  createPaystackBillingAdapter,
  createPinnedStripeClient,
  createPostmarkEmailAdapter,
  createResendEmailAdapter,
  createStripeBillingAdapter,
  createTapBillingAdapter,
  drainPendingEmailOutboxBatch,
  evaluateQuotaGuard,
  InMemoryQuotaRedisClient,
  processNormalizedBillingWebhook,
  resolveBillingProviderForCountry,
  selectTransactionalEmailAdapterFromEnv,
  TcpRespQuotaRedisClient
} from "@relayquill/billing";

const TEST_DIR = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(TEST_DIR, "../../..");
const MIGRATIONS_DIR = path.join(REPO_ROOT, "migrations");

async function setupSeededTenant(t, pg, orgId, billingEmail = "owner@acme.example") {
  const files = fs.readdirSync(MIGRATIONS_DIR).filter((f) => f.endsWith(".sql")).sort();
  for (const f of files) {
    await pg.exec(fs.readFileSync(path.join(MIGRATIONS_DIR, f), "utf8"));
  }
  await pg.exec(`
    INSERT INTO rq.tenants (id, slug, display_name, state, governance_version)
    VALUES ('${orgId}'::uuid, 'acme-${orgId.slice(0, 6)}', 'Acme Corp', 'active', 1);
  `);
  await withTenantRlsTransaction(pg, pg.configuredRole, orgId, async (tx) => {
    await tx.query(
      `INSERT INTO rq.billing_customers (org_id, stripe_customer_id, billing_email)
       VALUES ($1::uuid, $2::text, $3::text)`,
      [orgId, `cus_test_${orgId.slice(0, 8)}`, billingEmail]
    );
    await tx.query(
      `INSERT INTO rq.billing_subscriptions (
         subscription_id, org_id, plan_tier, entitlement_state, billing_interval,
         currency, unit_amount_minor, seat_count, current_period_start, current_period_end
       ) VALUES (
         $1::uuid, $2::uuid, 'free', 'FREE', 'month',
         'USD', 0, 1, '2026-11-01T00:00:00Z', '2026-12-01T00:00:00Z'
       )`,
      [crypto.randomUUID(), orgId]
    );
    await tx.query(
      `INSERT INTO rq.entitlement_quotas (
         org_id, max_seats, max_concurrency, included_units_month, overage_unit_minor,
         cap_mode, retention_days, sso_enabled
       ) VALUES ($1::uuid, 1, 1, 25000, 0, 'hard_cap', 3, false)`,
      [orgId]
    );
  });
  void t;
}

test("regional payment router selects Stripe, Paystack (Africa), and Tap (MENA) cleanly", () => {
  const ng = resolveBillingProviderForCountry("ng");
  assert.equal(ng.provider, "paystack");
  assert.equal(ng.currency, "NGN");
  assert.equal(ng.supportsHostedPortal, false);

  const sa = resolveBillingProviderForCountry("SA");
  assert.equal(sa.provider, "tap");
  assert.equal(sa.currency, "SAR");
  assert.ok(sa.paymentRails.includes("mada"));

  const ae = resolveBillingProviderForCountry("AE");
  assert.equal(ae.provider, "stripe");
  assert.equal(ae.currency, "AED");
  assert.equal(ae.supportsTaxAutomation, true);

  const usOverride = resolveBillingProviderForCountry("NG", "USD");
  assert.equal(usOverride.provider, "paystack");
  assert.equal(usOverride.currency, "USD");

  assert.equal(
    computePlanTotalMinor({ planTier: "pro", billingInterval: "month", seatCount: 1, currency: "USD" }),
    3900
  );
  assert.equal(
    computePlanTotalMinor({ planTier: "team", billingInterval: "month", seatCount: 7, currency: "USD" }),
    14900 + 2 * 1900
  );
});

test("Stripe provider pins rk_ key, omits payment_method_types, enables automatic_tax, and verifies signatures", async (t) => {
  assert.throws(
    () => createPinnedStripeClient({ apiKey: "sk_test_not_restricted" }),
    /Restricted API Key/
  );

  const capturedForms = [];
  const mockServer = http.createServer((req, res) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      capturedForms.push({
        path: req.url,
        body: Buffer.concat(chunks).toString("utf8")
      });
      res.writeHead(200, { "content-type": "application/json" });
      if (req.url?.includes("/checkout/sessions")) {
        res.end(JSON.stringify({ id: "cs_test_123", url: "https://checkout.stripe.test/cs_test_123" }));
      } else {
        res.end(JSON.stringify({ id: "bps_123", url: "https://billing.stripe.test/portal" }));
      }
    });
  });
  await new Promise((resolve) => mockServer.listen(0, "127.0.0.1", resolve));
  t.after(() => mockServer.close());
  const port = mockServer.address().port;

  const client = createPinnedStripeClient({
    apiKey: "rk_test_mock_key_value",
    host: "127.0.0.1",
    port,
    protocol: "http"
  });
  const stripeAdapter = createStripeBillingAdapter({
    client,
    webhookSecret: "whsec_test_secret_value"
  });

  const orgId = parseTenantId(crypto.randomUUID(), "orgId");
  const checkout = await stripeAdapter.createCheckoutSession({
    orgId,
    customerEmail: "billing@acme.example",
    planTier: "pro",
    billingInterval: "month",
    seatCount: 2,
    successUrl: "http://127.0.0.1:5205/billing?success=1",
    cancelUrl: "http://127.0.0.1:5205/billing?canceled=1"
  });
  assert.equal(checkout.provider, "stripe");
  assert.equal(checkout.sessionId, "cs_test_123");
  assert.equal(checkout.taxAutomationEnabled, true);
  assert.equal(capturedForms[0].body.includes("payment_method_types"), false);
  assert.equal(capturedForms[0].body.includes("automatic_tax"), true);
  assert.equal(capturedForms[0].body.includes("integration_identifier"), true);

  const nowMs = Date.UTC(2026, 10, 22, 14, 0, 0);
  const webhookPayload = JSON.stringify({
    id: "evt_sub_updated_1",
    object: "event",
    type: "customer.subscription.updated",
    created: Math.floor(nowMs / 1000),
    data: {
      object: {
        id: "sub_live_1",
        object: "subscription",
        status: "active",
        cancel_at_period_end: false,
        currency: "usd",
        customer: "cus_123",
        trial_end: null,
        metadata: { org_id: orgId, plan_tier: "team", billing_interval: "month", seat_count: "6" },
        items: {
          data: [
            {
              current_period_start: Math.floor(nowMs / 1000),
              current_period_end: Math.floor(nowMs / 1000) + 2592000,
              price: { unit_amount: 14900, recurring: { interval: "month" } }
            }
          ]
        }
      }
    }
  });
  const sig = Stripe.webhooks.generateTestHeaderString({
    payload: webhookPayload,
    secret: "whsec_test_secret_value",
    timestamp: Math.floor(nowMs / 1000)
  });

  const parsed = stripeAdapter.verifyAndParseWebhook(Buffer.from(webhookPayload, "utf8"), sig, nowMs);
  assert.equal(parsed.externalEventId, "evt_sub_updated_1");
  assert.equal(parsed.billingEventKind, "invoice_paid");
  assert.equal(parsed.planTier, "team");
  assert.equal(parsed.seatCount, 6);

  assert.throws(
    () => stripeAdapter.verifyAndParseWebhook(Buffer.from(webhookPayload, "utf8"), "t=1,v1=bad", nowMs),
    /No signatures found/
  );
});

test("Paystack (Nigeria/Africa) & Tap (MENA) adapters create checkouts and verify HMAC webhooks", async () => {
  const paystack = createPaystackBillingAdapter({
    secretKey: "psk_test_secret",
    fetchImpl: async () =>
      new Response(
        JSON.stringify({
          status: true,
          data: { authorization_url: "https://checkout.paystack.com/xyz", reference: "ref_ng_1" }
        }),
        { status: 200 }
      )
  });
  const orgId = parseTenantId(crypto.randomUUID(), "orgId");
  const ngCheckout = await paystack.createCheckoutSession({
    orgId,
    customerEmail: "founder@lagos.ng",
    planTier: "pro",
    billingInterval: "month",
    seatCount: 1,
    countryCode: "NG",
    currency: "NGN",
    successUrl: "https://console.example/billing?ok=1",
    cancelUrl: "https://console.example/billing"
  });
  assert.equal(ngCheckout.provider, "paystack");
  assert.equal(ngCheckout.currency, "NGN");

  const psRaw = Buffer.from(
    JSON.stringify({
      event: "charge.success",
      data: {
        reference: "ref_ng_1",
        amount: ngCheckout.amountMinor,
        currency: "NGN",
        paid_at: "2026-11-22T15:00:00Z",
        customer: { customer_code: "CUS_ng_1", email: "founder@lagos.ng" },
        metadata: { org_id: orgId, plan_tier: "pro", billing_interval: "month", seat_count: 1 }
      }
    }),
    "utf8"
  );
  const psSig = crypto.createHmac("sha512", "psk_test_secret").update(psRaw).digest("hex");
  const psEvt = paystack.verifyAndParseWebhook(psRaw, psSig, Date.now());
  assert.equal(psEvt.billingEventKind, "checkout_completed_paid");
  assert.equal(psEvt.planTier, "pro");

  const tap = createTapBillingAdapter({
    secretKey: "tap_test_secret",
    fetchImpl: async () =>
      new Response(
        JSON.stringify({ id: "chg_sa_1", transaction: { url: "https://tap.company/pay/chg_sa_1" } }),
        { status: 200 }
      )
  });
  const saCheckout = await tap.createCheckoutSession({
    orgId,
    customerEmail: "ops@riyadh.sa",
    planTier: "team",
    billingInterval: "month",
    seatCount: 5,
    countryCode: "SA",
    currency: "SAR",
    successUrl: "https://console.example/billing?ok=1",
    cancelUrl: "https://console.example/billing"
  });
  assert.equal(saCheckout.provider, "tap");
  assert.equal(saCheckout.currency, "SAR");

  const tapRaw = Buffer.from(
    JSON.stringify({
      id: "chg_sa_1",
      status: "CAPTURED",
      amount: 558.75,
      currency: "SAR",
      customer: { id: "cus_sa_1", email: "ops@riyadh.sa" },
      metadata: { org_id: orgId, plan_tier: "team", billing_interval: "month" }
    }),
    "utf8"
  );
  const tapSig = crypto.createHmac("sha256", "tap_test_secret").update(tapRaw).digest("hex");
  const tapEvt = tap.verifyAndParseWebhook(tapRaw, tapSig, Date.now());
  assert.equal(tapEvt.billingEventKind, "checkout_completed_paid");
});

test("processNormalizedBillingWebhook handles upgrades, duplicates, stale timestamps, dunning grace & QuotaGuard 402", async (t) => {
  const pg = await createPGliteAdapter({
    schema: "rq",
    supportSchema: "rq_support",
    isolation: "shared_database_schemas",
    configuredRole: "rq_api"
  });
  t.after(() => pg.close());

  const orgId = parseTenantId(crypto.randomUUID(), "orgId");
  await setupSeededTenant(t, pg, orgId);

  const t1 = new Date("2026-11-22T12:00:00Z");
  const upgradeRes = await processNormalizedBillingWebhook({
    pgAdapter: pg,
    event: {
      provider: "stripe",
      externalEventId: "evt_up_1",
      rawEventType: "checkout.session.completed",
      createdAt: t1,
      payloadSha256: "a".repeat(64),
      billingEventKind: "checkout_completed_paid",
      orgId,
      customerId: "cus_stripe_1",
      subscriptionId: "sub_stripe_1",
      planTier: "pro",
      billingInterval: "month",
      currency: "USD",
      unitAmountMinor: 3900,
      seatCount: 2
    }
  });
  assert.equal(upgradeRes.outcome, "APPLIED");
  assert.equal(upgradeRes.nextState, "ACTIVE");

  // Duplicate event ignored idempotently
  const dupRes = await processNormalizedBillingWebhook({
    pgAdapter: pg,
    event: {
      provider: "stripe",
      externalEventId: "evt_up_1",
      rawEventType: "checkout.session.completed",
      createdAt: t1,
      payloadSha256: "a".repeat(64),
      billingEventKind: "checkout_completed_paid",
      orgId
    }
  });
  assert.equal(dupRes.outcome, "IGNORED_DUPLICATE");

  // Older out-of-order event rejected as stale without clobbering ACTIVE state
  const staleRes = await processNormalizedBillingWebhook({
    pgAdapter: pg,
    event: {
      provider: "stripe",
      externalEventId: "evt_old_stale",
      rawEventType: "customer.subscription.deleted",
      createdAt: new Date("2026-11-22T11:00:00Z"),
      payloadSha256: "b".repeat(64),
      billingEventKind: "subscription_deleted",
      orgId,
      subscriptionId: "sub_stripe_1"
    }
  });
  assert.equal(staleRes.outcome, "IGNORED_STALE");
  assert.equal(staleRes.nextState, "ACTIVE");

  // Newer invoice failure opens 7-day PAST_DUE_GRACE & queues dunning_notice_1
  const failRes = await processNormalizedBillingWebhook({
    pgAdapter: pg,
    event: {
      provider: "stripe",
      externalEventId: "evt_fail_1",
      rawEventType: "invoice.payment_failed",
      createdAt: new Date("2026-11-22T13:00:00Z"),
      payloadSha256: "c".repeat(64),
      billingEventKind: "invoice_payment_failed",
      orgId,
      subscriptionId: "sub_stripe_1"
    }
  });
  assert.equal(failRes.outcome, "APPLIED");
  assert.equal(failRes.nextState, "PAST_DUE_GRACE");
  assert.equal(failRes.dunningQueued, true);

  // QuotaGuard triggers 95% alert at 475k, allows up to 500k Pro hard cap, records idempotent replay free, and maps 402
  const redis = new InMemoryQuotaRedisClient();
  redis.seedUsage(`rq:quota:${orgId}:2026-11`, 474_999);
  const alert95Guard = await evaluateQuotaGuard({
    pgAdapter: pg,
    redis,
    orgId,
    idempotencyKey: "ev-475k",
    now: new Date("2026-11-22T13:04:00Z")
  });
  assert.equal(alert95Guard.usedUnitsMonth, 475_000);
  assert.ok(alert95Guard.alertsQueued.includes("quota_alert_95"));

  redis.seedUsage(`rq:quota:${orgId}:2026-11`, 499_999);
  const okGuard = await evaluateQuotaGuard({
    pgAdapter: pg,
    redis,
    orgId,
    idempotencyKey: "ev-500k",
    now: new Date("2026-11-22T13:05:00Z")
  });
  assert.equal(okGuard.allowed, true);
  assert.equal(okGuard.usedUnitsMonth, 500_000);

  // Next unique event hits hard cap -> 402 QUOTA_HARD_CAP_REACHED
  let caughtErr;
  try {
    await evaluateQuotaGuard({
      pgAdapter: pg,
      redis,
      orgId,
      idempotencyKey: "ev-500k-plus-1",
      now: new Date("2026-11-22T13:06:00Z")
    });
  } catch (err) {
    caughtErr = err;
  }
  assert.ok(caughtErr instanceof LimitExceededDomainError);
  assert.equal(caughtErr.code, "QUOTA_HARD_CAP_REACHED");
  assert.equal(mapDomainErrorCodeToHttpStatus(caughtErr.code), 402);

  // Idempotent replay succeeds with 0 billable units even at cap
  const replayGuard = await evaluateQuotaGuard({
    pgAdapter: pg,
    redis,
    orgId,
    idempotencyKey: "ev-500k",
    isIdempotentReplay: true,
    now: new Date("2026-11-22T13:06:00Z")
  });
  assert.equal(replayGuard.billableUnits, 0);
  assert.equal(replayGuard.billedReason, "idempotent_replay_free");

  // Email outbox drains pending notifications cleanly
  const memMail = createInMemoryEmailAdapter();
  const drainSummary = await withTenantRlsTransaction(pg, pg.configuredRole, orgId, (tx) =>
    drainPendingEmailOutboxBatch(tx, memMail)
  );
  assert.ok(drainSummary.dispatched >= 2);
  assert.ok(memMail.sent.some((m) => m.templateCode === "dunning_notice_1"));
});

test("TcpRespQuotaRedisClient, Resend, Postmark, AWS SES SigV4, and Mailpit SMTP adapters work end-to-end", async (t) => {
  // Mock minimal RESP2 server
  const respServer = net.createServer((sock) => {
    sock.on("data", (chunk) => {
      if (chunk.toString("utf8").includes("EVAL")) {
        sock.write("*4\r\n:1\r\n:42\r\n:41\r\n:5\r\n");
      }
    });
  });
  await new Promise((resolve) => respServer.listen(0, "127.0.0.1", resolve));
  t.after(() => respServer.close());
  const redisClient = new TcpRespQuotaRedisClient(`redis://127.0.0.1:${respServer.address().port}`);
  t.after(() => redisClient.close());

  const evalRes = await redisClient.evalQuotaCheck({
    quotaKey: "rq:quota:abc:2026-11",
    spikeKey: "rq:spike:abc:2026112214",
    requestedUnits: 1,
    limitUnits: 25000,
    enforceHardCap: true,
    quotaTtlSeconds: 3600,
    spikeTtlSeconds: 3600
  });
  assert.equal(evalRes.allowed, true);
  assert.equal(evalRes.usedUnits, 42);

  // Mock Mailpit SMTP server
  const smtpCommands = [];
  const smtpServer = net.createServer((sock) => {
    sock.write("220 mailpit.local ESMTP\r\n");
    sock.on("data", (buf) => {
      const txt = buf.toString("utf8");
      smtpCommands.push(txt.trim());
      if (txt.startsWith("DATA")) {
        sock.write("354 Start mail input\r\n");
      } else if (txt.startsWith("QUIT")) {
        sock.write("221 Bye\r\n");
        sock.end();
      } else {
        sock.write("250 OK\r\n");
      }
    });
  });
  await new Promise((resolve) => smtpServer.listen(0, "127.0.0.1", resolve));
  t.after(() => smtpServer.close());
  const mailpit = createMailpitSmtpEmailAdapter({
    host: "127.0.0.1",
    port: smtpServer.address().port,
    fromEmail: "alerts@relayquill.local"
  });
  const smtpRes = await mailpit.send({
    to: "dev@acme.example",
    subject: "Test",
    text: "Hello",
    html: "<p>Hello</p>",
    idempotencyKey: "k1",
    templateCode: "verify_email"
  });
  assert.equal(smtpRes.provider, "mailpit");
  assert.ok(smtpCommands.some((c) => c.startsWith("MAIL FROM:<alerts@relayquill.local>")));

  // HTTP Email providers
  const resend = createResendEmailAdapter({
    apiKey: "re_test_123",
    fromEmail: "no-reply@relayquill.example",
    fetchImpl: async () => new Response(JSON.stringify({ id: "re_msg_1" }), { status: 200 })
  });
  assert.equal(
    (
      await resend.send({
        to: "a@b.example",
        subject: "S",
        text: "T",
        html: "<p>T</p>",
        idempotencyKey: "r1",
        templateCode: "verify_email"
      })
    ).messageId,
    "re_msg_1"
  );

  const postmark = createPostmarkEmailAdapter({
    serverToken: "pm_test_123",
    fromEmail: "no-reply@relayquill.example",
    fetchImpl: async () => new Response(JSON.stringify({ MessageID: "pm_msg_1" }), { status: 200 })
  });
  assert.equal(
    (
      await postmark.send({
        to: "a@b.example",
        subject: "S",
        text: "T",
        html: "<p>T</p>",
        idempotencyKey: "p1",
        templateCode: "verify_email"
      })
    ).messageId,
    "pm_msg_1"
  );

  let sesAuthHeader = "";
  const ses = createAwsSesEmailAdapter({
    accessKeyId: "AKIAIOSFODNN7EXAMPLE",
    secretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    region: "us-east-1",
    fromEmail: "no-reply@relayquill.example",
    fetchImpl: async (_url, init) => {
      sesAuthHeader = String((init?.headers)?.["authorization"] ?? "");
      return new Response(JSON.stringify({ MessageId: "ses_msg_1" }), { status: 200 });
    }
  });
  assert.equal(
    (
      await ses.send({
        to: "a@b.example",
        subject: "S",
        text: "T",
        html: "<p>T</p>",
        idempotencyKey: "s1",
        templateCode: "verify_email"
      })
    ).messageId,
    "ses_msg_1"
  );
  assert.ok(sesAuthHeader.startsWith("AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/"));

  assert.equal(selectTransactionalEmailAdapterFromEnv({}).provider, "memory");
  assert.equal(
    selectTransactionalEmailAdapterFromEnv({ RESEND_API_KEY: "re_env_1" }).provider,
    "resend"
  );
});
