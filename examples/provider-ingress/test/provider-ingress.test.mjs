import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { PGlite } from "@electric-sql/pglite";
import {
  createErrorEnvelope,
  createSuccessEnvelope,
  parseCanonicalUtcTimestamp
} from "@relayquill/contracts";
import { NotFoundDomainError, formatUtcTimestamp, nowUtcInstant } from "@relayquill/domain";
import { createProducerClient } from "@relayquill/producer-sdk";
import { InMemorySecretProvider, sendIpcFrame } from "@relayquill/runtime";
import {
  createProviderIngressDbClient,
  createProviderIngressServer,
  generatePaystackWebhookFixture,
  generateStripeWebhookFixture,
  parseProviderIngressCliArgs,
  runProviderIngressFixtures,
  sha256HexToBuffer
} from "../dist/index.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const MIGRATIONS_DIR = path.resolve(__dirname, "../migrations");

async function createMigratedPiDb() {
  const pglite = await PGlite.create({ dataDir: "memory://" });
  const files = fs
    .readdirSync(MIGRATIONS_DIR)
    .filter((f) => f.endsWith(".sql"))
    .sort();
  for (const file of files) {
    await pglite.exec(fs.readFileSync(path.join(MIGRATIONS_DIR, file), "utf8"));
  }
  const db = await createProviderIngressDbClient({
    pglite,
    ownsClient: true,
    schema: "pi",
    role: "provider_runtime",
    applySetLocalRole: true
  });
  return { pglite, db };
}

async function seedAndActivateBinding(pglite, db, params) {
  const configObj = {
    provider: params.provider,
    account_reference: params.accountReference,
    account_mode: params.accountMode,
    payload_profile: params.payloadProfile,
    secret_custody_reference: params.secretCustodyReference,
    secret_version_reference: params.secretVersionReference,
    relay_tenant_id: params.tenantId,
    relay_project_id: params.projectId,
    publication_channel_id: params.publicationChannelId,
    normalized_event_type_id: params.eventTypeId,
    normalized_schema_version: params.schemaVersion
  };
  const configShaHex = crypto.createHash("sha256").update(JSON.stringify(configObj), "utf8").digest("hex");
  const configShaBuf = sha256HexToBuffer(configShaHex);

  await pglite.transaction(async (tx) => {
    await tx.query(
      `INSERT INTO pi.bindings (
         id, provider, account_reference, account_mode, payload_profile,
         secret_custody_reference, secret_version_reference, state,
         relay_tenant_id, relay_project_id, publication_channel_id,
         normalized_event_type_id, normalized_schema_version,
         configuration_sha256, current_binding_version, version
       ) VALUES (
         $1::uuid, $2::text, $3::text, $4::text, $5::text,
         $6::text, $7::text, 'draft',
         $8::uuid, $9::uuid, $10::uuid, $11::uuid, $12::integer,
         $13::bytea, NULL, 1
       )`,
      [
        params.bindingId,
        params.provider,
        params.accountReference,
        params.accountMode,
        params.payloadProfile,
        params.secretCustodyReference,
        params.secretVersionReference,
        params.tenantId,
        params.projectId,
        params.publicationChannelId,
        params.eventTypeId,
        params.schemaVersion,
        configShaBuf
      ]
    );
    await tx.query(
      `INSERT INTO pi.binding_versions (
         binding_id, binding_version, provider, account_reference, account_mode, payload_profile,
         secret_custody_reference, secret_version_reference,
         relay_tenant_id, relay_project_id, publication_channel_id,
         normalized_event_type_id, normalized_schema_version,
         configuration_sha256, state
       ) VALUES (
         $1::uuid, 1, $2::text, $3::text, $4::text, $5::text,
         $6::text, $7::text,
         $8::uuid, $9::uuid, $10::uuid, $11::uuid, $12::integer,
         $13::bytea, 'draft'
       )`,
      [
        params.bindingId,
        params.provider,
        params.accountReference,
        params.accountMode,
        params.payloadProfile,
        params.secretCustodyReference,
        params.secretVersionReference,
        params.tenantId,
        params.projectId,
        params.publicationChannelId,
        params.eventTypeId,
        params.schemaVersion,
        configShaBuf
      ]
    );
  });

  await db.inTransaction(async (tx) => {
    await tx.query(
      `SELECT pi.cmd_binding_activate($1::uuid, 1, 1, $2::bytea, 'test_operator')`,
      [params.bindingId, configShaBuf]
    );
  });
}

async function startAdmissionApiDouble(scope) {
  const admittedByBizKey = new Map();
  let nextSeq = 1;
  let postEventsCalls = 0;
  let resolveCalls = 0;
  let dropAfterCommitCount = 0;

  const readJson = (req) =>
    new Promise((resolve, reject) => {
      const chunks = [];
      req.on("data", (c) => chunks.push(c));
      req.on("end", () => {
        try {
          resolve(JSON.parse(Buffer.concat(chunks).toString("utf8")));
        } catch (err) {
          reject(err);
        }
      });
      req.on("error", reject);
    });

  const server = http.createServer(async (req, res) => {
    const now = formatUtcTimestamp(nowUtcInstant());
    const url = new URL(req.url ?? "/", "http://127.0.0.1");
    const prefix = `/api/v1/tenants/${scope.tenantId}/projects/${scope.projectId}`;

    if (req.method === "POST" && url.pathname === `${prefix}/events`) {
      postEventsCalls += 1;
      const body = await readJson(req);
      const businessKey = String(body.business_key);
      let record = admittedByBizKey.get(businessKey);
      let status = 200;
      if (record === undefined) {
        status = 201;
        const eventId = crypto.randomUUID();
        const receiptId = crypto.randomUUID();
        const rawBytes = Buffer.from(String(body.content.data), "base64");
        const contentSha = crypto.createHash("sha256").update(rawBytes).digest("hex");
        const submittedShapeSha = crypto
          .createHash("sha256")
          .update(JSON.stringify(body), "utf8")
          .digest("hex");
        const effectiveRequestSha = crypto
          .createHash("sha256")
          .update(`${businessKey}:${String(req.headers["idempotency-key"] ?? "")}`, "utf8")
          .digest("hex");
        record = {
          receipt: {
            id: receiptId,
            accepted_at: now,
            resource_kind: "event",
            resource_id: eventId,
            accepted_version: "1"
          },
          event: {
            event_id: eventId,
            event_type_id: body.event_type_id,
            event_type: "billing.provider.callback",
            event_schema_version: body.event_schema_version,
            publication_channel_id: body.expected_publication_channel_id,
            namespace: scope.namespace,
            business_key: businessKey,
            accepted_at: now,
            project_event_sequence: String(nextSeq),
            topology_version: "1",
            original_content_sha256: contentSha,
            original_content_byte_count: rawBytes.byteLength,
            deadline_at: parseCanonicalUtcTimestamp("2026-12-31T23:59:59.000000Z", "deadline_at"),
            state_at_acceptance: "accepted",
            producer_event_time: body.producer_event_time ?? null,
            submitted_shape_sha256: submittedShapeSha,
            effective_request_sha256: effectiveRequestSha,
            hash_schema_version: 1
          },
          applied_defaults: {
            delivery_window_ms: "86400000",
            deadline_at: parseCanonicalUtcTimestamp("2026-12-31T23:59:59.000000Z", "deadline_at"),
            producer_event_time_present: body.producer_event_time !== undefined,
            deadline_at_present: body.deadline_at !== undefined
          },
          matched_existing: false,
          current_observation: {
            current_version: "1",
            current_state: "accepted",
            observed_at: now
          }
        };
        nextSeq += 1;
        admittedByBizKey.set(businessKey, record);
      }

      if (dropAfterCommitCount > 0) {
        dropAfterCommitCount -= 1;
        req.socket.destroy();
        return;
      }

      const payload = {
        ...record,
        matched_existing: status === 200
      };
      const envelope = createSuccessEnvelope(payload, {
        request_id: `req_post_${postEventsCalls}`,
        observed_at: now
      });
      res.writeHead(status, { "content-type": "application/json" });
      res.end(JSON.stringify(envelope));
      return;
    }

    if (req.method === "POST" && url.pathname === `${prefix}/events/resolve`) {
      resolveCalls += 1;
      const body = await readJson(req);
      const existing = admittedByBizKey.get(String(body.business_key));
      if (existing === undefined) {
        const errEnv = createErrorEnvelope(
          new NotFoundDomainError({
            code: "NOT_FOUND",
            message: "No committed event observed"
          }),
          { request_id: `req_res_${resolveCalls}`, observed_at: now }
        );
        res.writeHead(404, { "content-type": "application/json" });
        res.end(JSON.stringify(errEnv));
        return;
      }
      const resPayload = {
        receipt: existing.receipt,
        event: existing.event,
        applied_defaults: existing.applied_defaults,
        fingerprint_verified: body.submitted_shape_sha256 !== undefined,
        content_availability: {
          view: "original",
          availability: "available",
          media_type: "application/json",
          byte_count: existing.event.original_content_byte_count,
          sha256: existing.event.original_content_sha256
        },
        current_observation: existing.current_observation
      };
      const envelope = createSuccessEnvelope(resPayload, {
        request_id: `req_res_${resolveCalls}`,
        observed_at: now
      });
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify(envelope));
      return;
    }

    res.writeHead(404, { "content-type": "application/json" });
    res.end(JSON.stringify({ ok: false }));
  });

  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const addr = server.address();
  assert.ok(addr && typeof addr === "object");

  return {
    baseUrl: `http://127.0.0.1:${addr.port}`,
    armDropAfterCommitOnce() {
      dropAfterCommitCount += 1;
    },
    getMetrics() {
      return {
        postEventsCalls,
        resolveCalls,
        admittedCount: admittedByBizKey.size
      };
    },
    admittedByBizKey,
    close: () => new Promise((resolve, reject) => server.close((e) => (e ? reject(e) : resolve())))
  };
}

test("Provider ingress verifies Stripe/Paystack webhooks, enforces dedup/conflict, and recovers acceptance_unknown", async () => {
  const { pglite, db } = await createMigratedPiDb();
  const tenantId = crypto.randomUUID();
  const projectId = crypto.randomUUID();
  const channelId = crypto.randomUUID();
  const eventTypeId = crypto.randomUUID();
  const stripeBindingId = crypto.randomUUID();
  const paystackBindingId = crypto.randomUUID();

  const stripeSecret = "whsec_test_relayquill_stripe_secret";
  const paystackSecret = "sk_test_relayquill_paystack_secret";
  const secretProvider = new InMemorySecretProvider({
    initialSecrets: {
      "custody:stripe/test": stripeSecret,
      "custody:paystack/test": paystackSecret
    }
  });

  const apiDouble = await startAdmissionApiDouble({
    tenantId,
    projectId,
    namespace: "billing.webhooks"
  });

  const producerToken = `rq_p1.${crypto.randomUUID()}.${crypto.randomBytes(32).toString("base64url")}`;
  const producerClient = createProducerClient({
    baseUrl: apiDouble.baseUrl,
    getCredential: () => producerToken,
    retry: { maxAttempts: 1 }
  });

  let ipcTempDir = null;
  const ipcEndpoint =
    process.platform === "win32"
      ? `\\\\.\\pipe\\rq-pi-test-${crypto.randomBytes(6).toString("hex")}`
      : (() => {
          ipcTempDir = fs.mkdtempSync(path.join(os.tmpdir(), "rq-pi-"));
          fs.chmodSync(ipcTempDir, 0o700);
          return path.join(ipcTempDir, "control.sock");
        })();

  const server = await createProviderIngressServer({
    db,
    host: "127.0.0.1",
    port: 0,
    secretProvider,
    producerClient,
    startForwarder: false,
    forwarderOptions: {
      baseBackoffMs: 25,
      maxBackoffMs: 100
    },
    controlChannelEndpoint: ipcEndpoint
  });

  try {
    await seedAndActivateBinding(pglite, db, {
      bindingId: stripeBindingId,
      provider: "stripe",
      accountReference: "acct_stripe_test",
      accountMode: "test",
      payloadProfile: "stripe.snapshot.v1",
      secretCustodyReference: "custody:stripe/test",
      secretVersionReference: "v1",
      tenantId,
      projectId,
      publicationChannelId: channelId,
      eventTypeId,
      schemaVersion: 1
    });

    await seedAndActivateBinding(pglite, db, {
      bindingId: paystackBindingId,
      provider: "paystack",
      accountReference: "acct_paystack_test",
      accountMode: "test",
      payloadProfile: "paystack.webhook.v1",
      secretCustodyReference: "custody:paystack/test",
      secretVersionReference: "v1",
      tenantId,
      projectId,
      publicationChannelId: channelId,
      eventTypeId,
      schemaVersion: 1
    });

    const started = await server.start();
    const baseUrl = `http://${started.host}:${started.port}`;

    const liveRes = await fetch(`${baseUrl}/health/live`);
    assert.equal(liveRes.status, 200);
    const readyRes = await fetch(`${baseUrl}/health/ready`);
    assert.equal(readyRes.status, 200);

    const suiteResult = await runProviderIngressFixtures({
      baseUrl,
      stripeSecret,
      paystackSecret,
      stripeBindingId,
      paystackBindingId
    });
    assert.equal(suiteResult.passed, true, JSON.stringify(suiteResult.checks, null, 2));
    assert.equal(suiteResult.checks.length, 7);

    // Verify stale Stripe timestamp (> 300s) is rejected
    const staleStripe = await generateStripeWebhookFixture({
      secret: stripeSecret,
      timestampSeconds: Math.floor(Date.now() / 1000) - 900
    });
    const staleRes = await fetch(`${baseUrl}/webhooks/stripe`, {
      method: "POST",
      headers: staleStripe.headers,
      body: new Uint8Array(staleStripe.payloadBytes)
    });
    assert.equal(staleRes.status, 401);

    // Verify Stripe livemode mismatch against test binding is rejected
    const liveModeStripe = await generateStripeWebhookFixture({
      secret: stripeSecret,
      livemode: true
    });
    const modeRes = await fetch(`${baseUrl}/webhooks/stripe`, {
      method: "POST",
      headers: liveModeStripe.headers,
      body: new Uint8Array(liveModeStripe.payloadBytes)
    });
    assert.equal(modeRes.status, 401);

    // Verify Paystack uppercase hex signature is rejected
    const upperPaystack = generatePaystackWebhookFixture({
      secret: paystackSecret,
      reference: "ref_upper_check"
    });
    const upperRes = await fetch(`${baseUrl}/webhooks/paystack`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-paystack-signature": upperPaystack.headers["x-paystack-signature"].toUpperCase()
      },
      body: new Uint8Array(upperPaystack.payloadBytes)
    });
    assert.equal(upperRes.status, 401);

    // Inspect DB before forwarding: 2 accepted observations (1 stripe, 1 paystack)
    const preForwardState = await server.inspectState();
    assert.equal(preForwardState.observationsCount, 2);
    assert.equal(preForwardState.forwardIntents.length, 2);
    assert.ok(preForwardState.forwardIntents.every((f) => f.state === "ready"));

    // Arm post-commit socket drop for the first forwarded intent -> triggers acceptance_unknown
    apiDouble.armDropAfterCommitOnce();
    const cycle1 = await server.forwarder.runOnce();
    assert.equal(cycle1.dueCount, 2);
    assert.equal(cycle1.acceptanceUnknownCount, 1);
    assert.equal(cycle1.acceptedCount, 1);
    assert.equal(apiDouble.getMetrics().admittedCount, 2);
    assert.equal(apiDouble.getMetrics().postEventsCalls, 2);
    assert.equal(apiDouble.getMetrics().resolveCalls, 0);

    const midState = await server.inspectState();
    assert.equal(
      midState.forwardIntents.filter((f) => f.state === "acceptance_unknown").length,
      1
    );
    assert.equal(
      midState.forwardIntents.filter((f) => f.state === "accepted").length,
      1
    );

    // Wait past short backoff (25ms), then invoke IPC run_forwarder_once -> recovers via /events/resolve
    await new Promise((resolve) => setTimeout(resolve, 60));
    const ipcRun = await sendIpcFrame(ipcEndpoint, { op: "run_forwarder_once" });
    assert.equal(ipcRun.ok, true);
    assert.equal(ipcRun.summary.dueCount, 1);
    assert.equal(ipcRun.summary.acceptedCount, 1);
    assert.equal(apiDouble.getMetrics().postEventsCalls, 2, "must not re-POST on acceptance_unknown resolve");
    assert.equal(apiDouble.getMetrics().resolveCalls, 1);

    const postState = await server.inspectState();
    assert.ok(postState.forwardIntents.every((f) => f.state === "accepted" && typeof f.relayEventId === "string"));

    const ipcInspect = await sendIpcFrame(ipcEndpoint, { op: "inspect_state" });
    assert.equal(ipcInspect.ok, true);
    assert.equal(ipcInspect.state.observationsCount, 2);

    const obsRows = await pglite.query(`SELECT state FROM pi.observations ORDER BY received_at ASC`);
    assert.deepEqual(
      obsRows.rows.map((r) => r.state),
      ["forwarded", "forwarded"]
    );
  } finally {
    await server.stop();
    await apiDouble.close();
    await secretProvider.close();
    await db.close();
    if (ipcTempDir !== null) {
      fs.rmSync(ipcTempDir, { recursive: true, force: true });
    }
  }
});

test("parseProviderIngressCliArgs parses config and rejects invalid flags", () => {
  const parsed = parseProviderIngressCliArgs([
    "--config",
    "config/portable.provider-ingress.json",
    "--host",
    "0.0.0.0",
    "--port",
    "19096"
  ], {});
  assert.equal(parsed.configPath, "config/portable.provider-ingress.json");
  assert.equal(parsed.host, "0.0.0.0");
  assert.equal(parsed.port, 19096);
  assert.equal(parsed.help, false);

  const helpParsed = parseProviderIngressCliArgs(["--help"], {});
  assert.equal(helpParsed.help, true);

  assert.throws(() => parseProviderIngressCliArgs(["--unknown"], {}), /Unknown CLI argument/);
  assert.throws(() => parseProviderIngressCliArgs([], {}), /Missing required --config/);
});
