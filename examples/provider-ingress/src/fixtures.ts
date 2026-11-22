import crypto from "node:crypto";
import Stripe from "stripe";

const stripeFixtureClient = new Stripe("rk_test_provider_ingress_fixture_only");

export interface GeneratedWebhookFixture {
  readonly provider: "stripe" | "paystack" | "github";
  readonly eventId: string;
  readonly payloadText: string;
  readonly payloadBytes: Buffer;
  readonly headers: Readonly<Record<string, string>>;
}

export async function generateStripeWebhookFixture(params: {
  readonly secret: string;
  readonly eventId?: string | undefined;
  readonly eventType?: string | undefined;
  readonly objectId?: string | undefined;
  readonly amountCents?: number | undefined;
  readonly currency?: string | undefined;
  readonly livemode?: boolean | undefined;
  readonly createdSeconds?: number | undefined;
  readonly timestampSeconds?: number | undefined;
  readonly reorderKeys?: boolean | undefined;
}): Promise<GeneratedWebhookFixture> {
  const eventId = params.eventId ?? `evt_stripe_${crypto.randomBytes(8).toString("hex")}`;
  const eventType = params.eventType ?? "payment_intent.succeeded";
  const created = params.createdSeconds ?? Math.floor(Date.now() / 1000);
  const dataObject = {
    id: params.objectId ?? `pi_${crypto.randomBytes(6).toString("hex")}`,
    object: "payment_intent",
    amount: params.amountCents ?? 2500,
    currency: params.currency ?? "usd",
    status: "succeeded"
  };
  const payloadObj = params.reorderKeys === true
    ? {
        type: eventType,
        livemode: params.livemode ?? false,
        id: eventId,
        created,
        api_version: "2026-01-28.acacia",
        data: { object: dataObject },
        object: "event"
      }
    : {
        id: eventId,
        object: "event",
        api_version: "2026-01-28.acacia",
        created,
        data: { object: dataObject },
        livemode: params.livemode ?? false,
        type: eventType
      };
  const payloadText = JSON.stringify(payloadObj);
  const sigHeader = await stripeFixtureClient.webhooks.generateTestHeaderStringAsync({
    payload: payloadText,
    secret: params.secret,
    ...(params.timestampSeconds !== undefined ? { timestamp: params.timestampSeconds } : {})
  });

  return {
    provider: "stripe",
    eventId,
    payloadText,
    payloadBytes: Buffer.from(payloadText, "utf8"),
    headers: Object.freeze({
      "content-type": "application/json",
      "stripe-signature": sigHeader
    })
  };
}

export function generatePaystackWebhookFixture(params: {
  readonly secret: string;
  readonly eventId?: string | undefined;
  readonly eventType?: string | undefined;
  readonly reference?: string | undefined;
  readonly amountKobo?: number | undefined;
  readonly currency?: string | undefined;
  readonly domain?: "test" | "live" | undefined;
  readonly paidAt?: string | undefined;
  readonly reorderKeys?: boolean | undefined;
}): GeneratedWebhookFixture {
  const eventId = params.eventId ?? `evt_paystack_${crypto.randomBytes(8).toString("hex")}`;
  const eventType = params.eventType ?? "charge.success";
  const reference = params.reference ?? `ref_${crypto.randomBytes(6).toString("hex")}`;
  const domain = params.domain ?? "test";
  const paidAt = params.paidAt ?? "2026-06-01T12:00:00.000Z";
  const dataObj = params.reorderKeys === true
    ? {
        status: "success",
        reference,
        paid_at: paidAt,
        id: 10042,
        domain,
        currency: params.currency ?? "NGN",
        amount: params.amountKobo ?? 50_000
      }
    : {
        id: 10042,
        domain,
        status: "success",
        reference,
        amount: params.amountKobo ?? 50_000,
        currency: params.currency ?? "NGN",
        paid_at: paidAt
      };
  const payloadObj = params.reorderKeys === true
    ? {
        data: dataObj,
        id: eventId,
        event: eventType
      }
    : {
        event: eventType,
        id: eventId,
        data: dataObj
      };
  const payloadText = params.reorderKeys === true
    ? JSON.stringify(payloadObj, null, 2)
    : JSON.stringify(payloadObj);
  const payloadBytes = Buffer.from(payloadText, "utf8");
  const signature = crypto
    .createHmac("sha512", params.secret)
    .update(payloadBytes)
    .digest("hex");

  return {
    provider: "paystack",
    eventId,
    payloadText,
    payloadBytes,
    headers: Object.freeze({
      "content-type": "application/json",
      "x-paystack-signature": signature
    })
  };
}

export function generateGithubPushWebhookFixture(params: {
  readonly secret: string;
  readonly deliveryId?: string | undefined;
  readonly repository?: string | undefined;
  readonly ref?: string | undefined;
  readonly beforeSha?: string | undefined;
  readonly afterSha?: string | undefined;
  readonly commitId?: string | undefined;
  readonly timestamp?: string | undefined;
  readonly reorderKeys?: boolean | undefined;
}): GeneratedWebhookFixture {
  const deliveryId = params.deliveryId ?? crypto.randomUUID();
  const repositoryFullName = params.repository ?? "relayquill/webhooks";
  const gitRef = params.ref ?? "refs/heads/main";
  const beforeSha = params.beforeSha ?? "1111111111111111111111111111111111111111";
  const afterSha = params.afterSha ?? "2222222222222222222222222222222222222222";
  const commitId = params.commitId ?? afterSha;
  const timestamp = params.timestamp ?? "2026-06-01T12:00:00Z";

  const headCommit =
    params.reorderKeys === true
      ? { timestamp, id: commitId, message: "feat: webhook conformance push" }
      : { id: commitId, message: "feat: webhook conformance push", timestamp };
  const repository =
    params.reorderKeys === true
      ? { id: 987654, full_name: repositoryFullName }
      : { full_name: repositoryFullName, id: 987654 };
  const payloadObj =
    params.reorderKeys === true
      ? {
          head_commit: headCommit,
          commits: [headCommit],
          after: afterSha,
          before: beforeSha,
          ref: gitRef,
          repository
        }
      : {
          ref: gitRef,
          before: beforeSha,
          after: afterSha,
          repository,
          head_commit: headCommit,
          commits: [headCommit]
        };
  const payloadText =
    params.reorderKeys === true
      ? JSON.stringify(payloadObj, null, 2)
      : JSON.stringify(payloadObj);
  const payloadBytes = Buffer.from(payloadText, "utf8");
  const digest = crypto.createHmac("sha256", params.secret).update(payloadBytes).digest("hex");

  return {
    provider: "github",
    eventId: deliveryId,
    payloadText,
    payloadBytes,
    headers: Object.freeze({
      "content-type": "application/json",
      "x-github-event": "push",
      "x-github-delivery": deliveryId,
      "x-hub-signature-256": `sha256=${digest}`
    })
  };
}

export interface FixtureCheckResult {
  readonly name: string;
  readonly status: number;
  readonly expectedStatus: number;
  readonly passed: boolean;
  readonly body: unknown;
}

export interface ProviderIngressFixtureSuiteResult {
  readonly passed: boolean;
  readonly checks: readonly FixtureCheckResult[];
}

export async function runProviderIngressFixtures(params: {
  readonly baseUrl: string;
  readonly stripePath?: string | undefined;
  readonly paystackPath?: string | undefined;
  readonly githubPath?: string | undefined;
  readonly stripeSecret: string;
  readonly paystackSecret: string;
  readonly githubSecret?: string | undefined;
  readonly stripeBindingId?: string | undefined;
  readonly paystackBindingId?: string | undefined;
  readonly githubBindingId?: string | undefined;
}): Promise<ProviderIngressFixtureSuiteResult> {
  const baseUrl = params.baseUrl.replace(/\/+$/, "");
  const stripePath = params.stripePath ?? "/webhooks/stripe";
  const paystackPath = params.paystackPath ?? "/webhooks/paystack";
  const githubPath = params.githubPath ?? "/webhooks/github";

  const stripeSuffix =
    params.stripeBindingId !== undefined
      ? `?binding_id=${encodeURIComponent(params.stripeBindingId)}`
      : "";
  const paystackSuffix =
    params.paystackBindingId !== undefined
      ? `?binding_id=${encodeURIComponent(params.paystackBindingId)}`
      : "";
  const githubSuffix =
    params.githubBindingId !== undefined
      ? `?binding_id=${encodeURIComponent(params.githubBindingId)}`
      : "";

  const sendPost = async (
    routePath: string,
    payloadBytes: Buffer,
    headers: Readonly<Record<string, string>>
  ): Promise<{ readonly status: number; readonly body: unknown }> => {
    const res = await fetch(`${baseUrl}${routePath}`, {
      method: "POST",
      headers,
      body: new Uint8Array(payloadBytes)
    });
    const text = await res.text();
    let body: unknown = text;
    try {
      body = JSON.parse(text);
    } catch {
      body = text;
    }
    return { status: res.status, body };
  };

  const checks: FixtureCheckResult[] = [];
  const pushCheck = (name: string, status: number, expectedStatus: number, body: unknown, okExtra = true): void => {
    checks.push({
      name,
      status,
      expectedStatus,
      passed: status === expectedStatus && okExtra,
      body
    });
  };

  const stripeAccepted = await generateStripeWebhookFixture({
    secret: params.stripeSecret
  });
  const s1 = await sendPost(`${stripePath}${stripeSuffix}`, stripeAccepted.payloadBytes, stripeAccepted.headers);
  pushCheck(
    "stripe.accepted",
    s1.status,
    202,
    s1.body,
    (s1.body as Record<string, unknown> | undefined)?.["outcome"] === "accepted"
  );

  const s2 = await sendPost(`${stripePath}${stripeSuffix}`, stripeAccepted.payloadBytes, stripeAccepted.headers);
  pushCheck(
    "stripe.transport_dedup",
    s2.status,
    200,
    s2.body,
    (s2.body as Record<string, unknown> | undefined)?.["outcome"] === "already_accepted_transport"
  );

  const sBad = await sendPost(`${stripePath}${stripeSuffix}`, stripeAccepted.payloadBytes, {
    "content-type": "application/json",
    "stripe-signature": "t=1700000000,v1=0000000000000000000000000000000000000000000000000000000000000000"
  });
  pushCheck("stripe.invalid_signature", sBad.status, 401, sBad.body);

  const paystackBaseEventId = `evt_paystack_conf_${crypto.randomBytes(6).toString("hex")}`;
  const paystackRef = `ref_conf_${crypto.randomBytes(6).toString("hex")}`;
  const p1Fixture = generatePaystackWebhookFixture({
    secret: params.paystackSecret,
    eventId: paystackBaseEventId,
    reference: paystackRef,
    amountKobo: 75_000
  });
  const p1 = await sendPost(`${paystackPath}${paystackSuffix}`, p1Fixture.payloadBytes, p1Fixture.headers);
  pushCheck(
    "paystack.accepted",
    p1.status,
    202,
    p1.body,
    (p1.body as Record<string, unknown> | undefined)?.["outcome"] === "accepted"
  );

  const p2Fixture = generatePaystackWebhookFixture({
    secret: params.paystackSecret,
    eventId: paystackBaseEventId,
    reference: paystackRef,
    amountKobo: 75_000,
    reorderKeys: true
  });
  const p2 = await sendPost(`${paystackPath}${paystackSuffix}`, p2Fixture.payloadBytes, p2Fixture.headers);
  pushCheck(
    "paystack.semantic_dedup",
    p2.status,
    200,
    p2.body,
    (p2.body as Record<string, unknown> | undefined)?.["outcome"] === "already_accepted_semantic"
  );

  const pConflictFixture = generatePaystackWebhookFixture({
    secret: params.paystackSecret,
    eventId: paystackBaseEventId,
    reference: paystackRef,
    amountKobo: 99_900
  });
  const pConflict = await sendPost(
    `${paystackPath}${paystackSuffix}`,
    pConflictFixture.payloadBytes,
    pConflictFixture.headers
  );
  pushCheck("paystack.semantic_conflict", pConflict.status, 409, pConflict.body);

  const pBadSig = await sendPost(`${paystackPath}${paystackSuffix}`, p1Fixture.payloadBytes, {
    "content-type": "application/json",
    "x-paystack-signature": "a".repeat(128)
  });
  pushCheck("paystack.invalid_signature", pBadSig.status, 401, pBadSig.body);

  if (params.githubSecret !== undefined) {
    const ghFixture = generateGithubPushWebhookFixture({
      secret: params.githubSecret
    });
    const g1 = await sendPost(`${githubPath}${githubSuffix}`, ghFixture.payloadBytes, ghFixture.headers);
    pushCheck(
      "github.accepted",
      g1.status,
      202,
      g1.body,
      (g1.body as Record<string, unknown> | undefined)?.["outcome"] === "accepted"
    );

    const g2 = await sendPost(`${githubPath}${githubSuffix}`, ghFixture.payloadBytes, ghFixture.headers);
    pushCheck(
      "github.transport_dedup",
      g2.status,
      200,
      g2.body,
      (g2.body as Record<string, unknown> | undefined)?.["outcome"] === "already_accepted_transport"
    );

    const gBadSig = await sendPost(`${githubPath}${githubSuffix}`, ghFixture.payloadBytes, {
      "content-type": "application/json",
      "x-github-event": "push",
      "x-github-delivery": ghFixture.eventId,
      "x-hub-signature-256": `sha256=${"0".repeat(64)}`
    });
    pushCheck("github.invalid_signature", gBadSig.status, 401, gBadSig.body);
  }

  return {
    passed: checks.every((c) => c.passed),
    checks
  };
}
