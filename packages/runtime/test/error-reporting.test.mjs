import assert from "node:assert/strict";
import test from "node:test";
import {
  createEnvGatedErrorReporter,
  parseSentryDsn,
  scrubErrorPayload
} from "@relayquill/runtime";

test("parseSentryDsn stays disabled when unset and rejects malformed or remote http DSNs", () => {
  assert.deepEqual(parseSentryDsn(undefined), { enabled: false });
  assert.deepEqual(parseSentryDsn("   "), { enabled: false });

  assert.throws(() => parseSentryDsn("not-a-url"), /valid URL/);
  assert.throws(() => parseSentryDsn("http://pub@sentry.example.com/123"), /https:\/\//);
  assert.throws(() => parseSentryDsn("https://sentry.example.com/123"), /public key/);
  assert.throws(() => parseSentryDsn("https://pub@sentry.example.com/non-numeric"), /numeric project ID/);

  const parsed = parseSentryDsn("https://pubKey123@o42.ingest.sentry.io/450001");
  assert.equal(parsed.enabled, true);
  if (parsed.enabled) {
    assert.equal(parsed.projectId, "450001");
    assert.equal(parsed.envelopeUrl, "https://o42.ingest.sentry.io/api/450001/envelope/");
  }
});

test("scrubErrorPayload strips secret keys, URLs query tokens, emails, and sensitive extra fields", () => {
  const err = new Error(
    "Webhook dispatch failed for https://hooks.example.com/cb?token=secret123&sig=abc with sk_live_secretValue123 and whsec_987654"
  );
  const scrubbed = scrubErrorPayload(err, {
    service: "api",
    route: "/api/v1/events?secret=foo",
    method: "post",
    statusCode: 500,
    extra: {
      authorization: "Bearer eyJabcdef",
      email: "user@example.com",
      safe_count: 3
    }
  });

  assert.equal(scrubbed.message.includes("secret123"), false);
  assert.equal(scrubbed.message.includes("sk_live_"), false);
  assert.equal(scrubbed.message.includes("whsec_"), false);
  assert.equal(scrubbed.tags["route"], "/api/v1/events");
  assert.equal(scrubbed.extra["authorization"], "[REDACTED]");
  assert.equal(scrubbed.extra["email"], "[REDACTED]");
  assert.equal(scrubbed.extra["safe_count"], 3);
});

test("createEnvGatedErrorReporter is no-op without DSN and dispatches scrubbed envelope when DSN set", async () => {
  const noopReporter = createEnvGatedErrorReporter({ dsn: "" });
  assert.equal(noopReporter.enabled, false);
  assert.equal(noopReporter.provider, "noop");
  const noopRes = await noopReporter.captureException(new Error("boom"), { service: "api" });
  assert.equal(noopRes.sent, false);
  assert.equal(noopRes.reason, "dsn_unset");

  const capturedRequests = [];
  const liveReporter = createEnvGatedErrorReporter({
    dsn: "https://pubABC@o9.ingest.sentry.io/9001",
    environment: "production",
    fetchImpl: async (url, init) => {
      capturedRequests.push({ url: String(url), init });
      return new Response("{}", { status: 200 });
    }
  });
  assert.equal(liveReporter.enabled, true);
  assert.equal(liveReporter.provider, "sentry");

  const sent = await liveReporter.captureException(
    new Error("Failure calling https://api.stripe.com/v1/checkout?api_key=rk_test_abc999"),
    {
      service: "api",
      statusCode: 500,
      requestId: "req-1",
      extra: { cookie: "rq_session=abc" }
    }
  );
  assert.equal(sent.sent, true);
  assert.equal(sent.reason, "dispatched");
  assert.equal(capturedRequests.length, 1);
  assert.equal(capturedRequests[0].url, "https://o9.ingest.sentry.io/api/9001/envelope/");
  const body = String(capturedRequests[0].init.body);
  assert.equal(body.includes("rk_test_abc999"), false);
  assert.equal(body.includes("rq_session"), false);
});
