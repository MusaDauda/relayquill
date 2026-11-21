import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import {
  createErrorEnvelope,
  createSuccessEnvelope,
  formatSseFrame,
  parseCanonicalUtcTimestamp
} from "@relayquill/contracts";
import { NotFoundDomainError, formatUtcTimestamp, nowUtcInstant } from "@relayquill/domain";
import { parseProducerCliArgs, runProducerCli } from "../dist/index.js";

function createStringBufferWriter() {
  let buf = "";
  return {
    write(chunk) {
      buf += String(chunk);
      return true;
    },
    read() {
      return buf;
    },
    clear() {
      buf = "";
    }
  };
}

async function startIpcSecretDouble(secrets) {
  const endpoint =
    process.platform === "win32"
      ? `\\\\.\\pipe\\rq-prod-sec-${crypto.randomBytes(6).toString("hex")}`
      : path.join(os.tmpdir(), `rq-prod-sec-${crypto.randomBytes(6).toString("hex")}.sock`);

  const sockets = new Set();
  const server = net.createServer((socket) => {
    sockets.add(socket);
    socket.on("close", () => sockets.delete(socket));
    let pending = Buffer.alloc(0);
    socket.on("data", (chunk) => {
      pending = Buffer.concat([pending, Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)]);
      const idx = pending.indexOf(0x0a);
      if (idx === -1) {
        return;
      }
      const line = pending.subarray(0, idx).toString("utf8").trim();
      pending = pending.subarray(idx + 1);
      const req = JSON.parse(line);
      if (req.op === "get" && typeof req.ref === "string") {
        const val = secrets[req.ref];
        if (val === undefined) {
          socket.write(`${JSON.stringify({ ok: false, errorCode: "NOT_FOUND", message: "Not found" })}\n`);
          return;
        }
        socket.write(
          `${JSON.stringify({
            ok: true,
            op: "get",
            valueBase64: Buffer.from(val, "utf8").toString("base64")
          })}\n`
        );
      } else {
        socket.write(`${JSON.stringify({ ok: false, errorCode: "INVALID_REQUEST", message: "Unsupported" })}\n`);
      }
    });
  });

  await new Promise((resolve) => server.listen(endpoint, resolve));
  return {
    endpoint,
    async close() {
      for (const s of sockets) {
        s.destroy();
      }
      await new Promise((resolve) => server.close(() => resolve()));
      if (process.platform !== "win32" && fs.existsSync(endpoint)) {
        fs.unlinkSync(endpoint);
      }
    }
  };
}

async function startProducerApiDouble(scope) {
  const eventsByBizKey = new Map();
  const eventsById = new Map();
  const deliveriesByEventId = new Map();
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

  const zeroCounts = (population) => ({
    unit: "delivery_generation",
    population,
    total_deliveries: "0",
    pending_count: "0",
    sending_count: "0",
    http_acknowledged_count: "0",
    dead_letter_count: "0",
    suppressed_count: "0",
    expired_count: "0",
    verified_receipt_count: "0"
  });

  const server = http.createServer(async (req, res) => {
    const auth = req.headers.authorization ?? "";
    if (auth !== `Bearer ${scope.expectedToken}`) {
      res.writeHead(401, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: { code: "UNAUTHENTICATED", message: "Bad token" } }));
      return;
    }

    const now = formatUtcTimestamp(nowUtcInstant());
    const url = new URL(req.url ?? "/", "http://127.0.0.1");
    const prefix = `/api/v1/tenants/${scope.tenantId}/projects/${scope.projectId}`;

    if (req.method === "GET" && url.pathname === `${prefix}/publication-context`) {
      const ctxPayload = {
        actor_kind: "producer",
        channel_enabled: true,
        channel_kind: "machine_producer",
        publication_channel_id: scope.channelId,
        namespace: scope.namespace,
        scope_version: "1",
        authority_epoch: "1",
        allowed_actions: [
          "events.admit",
          "events.resolve",
          "events.read_own",
          "events.watch_own",
          "deliveries.read_own"
        ],
        allowed_events: [
          {
            event_type_id: scope.eventTypeId,
            event_type_name: "orders.payment.settled",
            allowed_schema_versions: [1]
          }
        ],
        budgets: {
          max_encoded_body_bytes: 262_144,
          max_decoded_content_bytes: 131_072,
          default_delivery_window_ms: "86400000",
          max_delivery_window_ms: "604800000"
        },
        capabilities: []
      };
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify(createSuccessEnvelope(ctxPayload, { request_id: "req_ctx", observed_at: now })));
      return;
    }

    if (req.method === "POST" && url.pathname === `${prefix}/events`) {
      postEventsCalls += 1;
      const body = await readJson(req);
      const businessKey = String(body.business_key);
      let entry = eventsByBizKey.get(businessKey);
      let status = 200;
      if (entry === undefined) {
        status = 201;
        const eventId = crypto.randomUUID();
        const receiptId = crypto.randomUUID();
        const deliveryId = crypto.randomUUID();
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

        const projection = {
          event_id: eventId,
          event_type_id: body.event_type_id,
          event_type: "orders.payment.settled",
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
        };

        const receipt = {
          id: receiptId,
          accepted_at: now,
          resource_kind: "event",
          resource_id: eventId,
          accepted_version: "1"
        };

        const applied_defaults = {
          delivery_window_ms: "86400000",
          deadline_at: parseCanonicalUtcTimestamp("2026-12-31T23:59:59.000000Z", "deadline_at"),
          producer_event_time_present: body.producer_event_time !== undefined,
          deadline_at_present: body.deadline_at !== undefined
        };

        entry = {
          receipt,
          event: projection,
          applied_defaults,
          matched_existing: false,
          current_observation: {
            current_version: "1",
            current_state: "accepted",
            observed_at: now
          }
        };

        const deliverySummary = {
          delivery_id: deliveryId,
          family_id: crypto.randomUUID(),
          event_id: eventId,
          delivery_generation: "0",
          is_replay: false,
          replay_proposal_id: null,
          subscription_id: crypto.randomUUID(),
          original_subscription_version: "1",
          dispatch_subscription_version: "1",
          endpoint_id: crypto.randomUUID(),
          endpoint_version: "1",
          wire_envelope_id: crypto.randomUUID(),
          representation_version: 1,
          consumer_event_key_sha256: crypto.createHash("sha256").update(businessKey, "utf8").digest("hex"),
          state: "acknowledged",
          execution_bucket: "acknowledged",
          blocking_reason: null,
          last_outcome_class: "acknowledged",
          attempt_count: 1,
          maximum_attempts: 5,
          prepared_attempt_count: 1,
          preparation_failure_count: 0,
          next_attempt_number: 2,
          deadline_at: parseCanonicalUtcTimestamp("2026-12-31T23:59:59.000000Z", "deadline_at"),
          next_eligible_at: now,
          acknowledged_at: now,
          terminal_at: now,
          current_version: "2",
          current_fence: "1",
          current_attempt_id: crypto.randomUUID(),
          latest_response_summary: null,
          latest_receipt_summary: null,
          capabilities: []
        };

        eventsByBizKey.set(businessKey, entry);
        eventsById.set(eventId, entry);
        deliveriesByEventId.set(eventId, [deliverySummary]);
        nextSeq += 1;
      }

      if (dropAfterCommitCount > 0) {
        dropAfterCommitCount -= 1;
        req.socket.destroy();
        return;
      }

      res.writeHead(status, { "content-type": "application/json" });
      res.end(
        JSON.stringify(
          createSuccessEnvelope(
            { ...entry, matched_existing: status === 200 },
            { request_id: `req_admit_${postEventsCalls}`, observed_at: now }
          )
        )
      );
      return;
    }

    if (req.method === "POST" && url.pathname === `${prefix}/events/resolve`) {
      resolveCalls += 1;
      const body = await readJson(req);
      const entry = eventsByBizKey.get(String(body.business_key));
      if (entry === undefined) {
        res.writeHead(404, { "content-type": "application/json" });
        res.end(
          JSON.stringify(
            createErrorEnvelope(
              new NotFoundDomainError({ code: "NOT_FOUND", message: "Not committed" }),
              { request_id: `req_res_${resolveCalls}`, observed_at: now }
            )
          )
        );
        return;
      }
      res.writeHead(200, { "content-type": "application/json" });
      res.end(
        JSON.stringify(
          createSuccessEnvelope(
            {
              receipt: entry.receipt,
              event: entry.event,
              applied_defaults: entry.applied_defaults,
              fingerprint_verified: body.submitted_shape_sha256 !== undefined,
              content_availability: {
                view: "original",
                availability: "available",
                media_type: "application/json",
                byte_count: entry.event.original_content_byte_count,
                sha256: entry.event.original_content_sha256
              },
              current_observation: entry.current_observation
            },
            { request_id: `req_res_${resolveCalls}`, observed_at: now }
          )
        )
      );
      return;
    }

    const evWatchMatch = /^\/events\/([0-9a-f-]+)\/watch$/.exec(url.pathname.slice(prefix.length));
    if (req.method === "GET" && evWatchMatch?.[1] !== undefined) {
      const eventId = evWatchMatch[1];
      const entry = eventsById.get(eventId);
      if (entry === undefined) {
        res.writeHead(404, { "content-type": "application/json" });
        res.end(JSON.stringify({ ok: false }));
        return;
      }
      res.writeHead(200, {
        "content-type": "text/event-stream",
        "cache-control": "no-store"
      });
      res.write(
        formatSseFrame({
          id: "cur_1",
          payload: {
            response_schema_version: 1,
            frame_type: "snapshot",
            resource_kind: "event",
            resource_id: eventId,
            cursor: "cur_1",
            high_water_sequence: "1",
            observed_at: now,
            state: "fanout_complete",
            current_version: "2",
            summary: { event_id: eventId }
          }
        })
      );
      res.write(
        formatSseFrame({
          id: "cur_2",
          payload: {
            response_schema_version: 1,
            frame_type: "event",
            resource_kind: "event",
            resource_id: eventId,
            event_id: eventId,
            event_sequence: "2",
            event_type: "delivery.acknowledged",
            event_schema_version: 1,
            recorded_at: now,
            safe_details: { delivery_generation: "0" }
          }
        })
      );
      res.end();
      return;
    }

    const evGetMatch = /^\/events\/([0-9a-f-]+)$/.exec(url.pathname.slice(prefix.length));
    if (req.method === "GET" && evGetMatch?.[1] !== undefined) {
      const eventId = evGetMatch[1];
      const entry = eventsById.get(eventId);
      if (entry === undefined) {
        res.writeHead(404, { "content-type": "application/json" });
        res.end(JSON.stringify({ ok: false }));
        return;
      }
      const detail = {
        ...entry.event,
        accepted_version: "1",
        current_version: "2",
        current_state: "fanout_complete",
        observed_at: now,
        fanout: {
          event_id: eventId,
          state: "completed",
          project_event_sequence: entry.event.project_event_sequence,
          topology_version: "1",
          examined_count: "1",
          matched_count: "1",
          delivery_count: "1",
          candidate_count: "1",
          last_progress_at: now,
          completed_at: now,
          project_materialized_through_event_sequence: entry.event.project_event_sequence
        },
        publication: {
          outbox_id: crypto.randomUUID(),
          current_publication_generation: "1",
          state: "published",
          next_publish_at: null,
          observation_state: "not_observed",
          first_observation: null,
          latest_observation: null,
          last_safe_error_code: null
        },
        delivery_counts: {
          original: { ...zeroCounts("original"), total_deliveries: "1", verified_receipt_count: "1" },
          replay: zeroCounts("replay"),
          all: { ...zeroCounts("all"), total_deliveries: "1", verified_receipt_count: "1" }
        },
        content_availability: {
          view: "original",
          availability: "available",
          media_type: "application/json",
          byte_count: entry.event.original_content_byte_count,
          sha256: entry.event.original_content_sha256
        },
        capabilities: []
      };
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify(createSuccessEnvelope(detail, { request_id: "req_ev", observed_at: now })));
      return;
    }

    if (req.method === "GET" && url.pathname === `${prefix}/deliveries`) {
      const eventId = url.searchParams.get("event_id") ?? "";
      const items = deliveriesByEventId.get(eventId) ?? [];
      res.writeHead(200, { "content-type": "application/json" });
      res.end(
        JSON.stringify(
          createSuccessEnvelope(
            {
              items,
              page: {
                next_cursor: null,
                limit: 50,
                has_more: false
              }
            },
            { request_id: "req_del", observed_at: now }
          )
        )
      );
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
    setDropAfterCommitCount(count) {
      dropAfterCommitCount = count;
    },
    getMetrics() {
      return { postEventsCalls, resolveCalls, totalEvents: eventsById.size };
    },
    close: () => new Promise((resolve, reject) => server.close((e) => (e ? reject(e) : resolve())))
  };
}

test("parseProducerCliArgs renders help and blocks secret flags or literals", () => {
  const help = parseProducerCliArgs(["--help"], {});
  assert.equal(help.help, true);

  const sampleSecret = `rq_p1.${crypto.randomUUID()}.${crypto.randomBytes(32).toString("base64url")}`;
  assert.throws(() => parseProducerCliArgs(["submit", "--token", "abc"], {}), /Forbidden secret CLI flag/);
  assert.throws(() => parseProducerCliArgs(["submit", "--secret=abc"], {}), /Forbidden secret CLI flag/);
  assert.throws(() => parseProducerCliArgs(["submit", "--password", "pw"], {}), /Forbidden secret CLI flag/);
  assert.throws(() => parseProducerCliArgs(["submit", "--business-key", sampleSecret], {}), /Secret literal detected/);
});

test("Producer CLI executes prepare, submit, acceptance_unknown recovery via retry-original, resolve, status, and watch", async () => {
  const tenantId = crypto.randomUUID();
  const projectId = crypto.randomUUID();
  const channelId = crypto.randomUUID();
  const eventTypeId = crypto.randomUUID();
  const token = `rq_p1.${crypto.randomUUID()}.${crypto.randomBytes(32).toString("base64url")}`;

  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "rq-producer-test-"));
  const runsDir = path.join(tmpRoot, "runs");
  const secretFile = path.join(tmpRoot, "cred.secret");
  fs.writeFileSync(secretFile, token, "utf8");

  const ipcCustody = await startIpcSecretDouble({
    "custody:producer-example/credential": token
  });

  const apiDouble = await startProducerApiDouble({
    tenantId,
    projectId,
    channelId,
    eventTypeId,
    namespace: "orders.billing",
    expectedToken: token
  });

  const configPath = path.join(tmpRoot, "producer.config.json");
  fs.writeFileSync(
    configPath,
    JSON.stringify({
      schema_version: 1,
      profile: "development_trusted_local",
      process_role: "producer_example",
      api_target: {
        origin: apiDouble.baseUrl,
        tenant_id: tenantId,
        project_id: projectId,
        credential_secret_ref: "custody:producer-example/credential"
      },
      secret_provider: {
        mode: "local_ipc_provider",
        ipc_endpoint: ipcCustody.endpoint
      },
      runs_dir: runsDir,
      project_scope: {
        project_slug: "billing-events",
        producer_credential_ref: "custody:producer-example/credential"
      }
    }),
    "utf8"
  );

  const stdout = createStringBufferWriter();
  const stderr = createStringBufferWriter();

  try {
    // 1. Help
    const helpExit = await runProducerCli(["--help"], { stdout, stderr });
    assert.equal(helpExit, 0);
    assert.match(stdout.read(), /Relayquill Reference Producer CLI/);
    stdout.clear();

    // 2. Prepare using config + IPC custody secret ref (fetches publication-context automatically)
    const prepExit = await runProducerCli(
      [
        "prepare",
        "--config",
        configPath,
        "--run-id",
        "order-101",
        "--event-type-id",
        eventTypeId,
        "--schema-version",
        "1",
        "--business-key",
        "order:101:settled",
        "--content",
        JSON.stringify({ order_id: "ord_101", amount_cents: 4200, currency: "USD" })
      ],
      { stdout, stderr }
    );
    assert.equal(prepExit, 0);
    const prepOut = JSON.parse(stdout.read());
    assert.equal(prepOut.ok, true);
    assert.equal(prepOut.command, "prepare");
    assert.equal(prepOut.run_id, "order-101");

    // Verify no secret leaked in stored run artifact
    const storedText = fs.readFileSync(prepOut.run_file, "utf8");
    assert.equal(storedText.includes(token), false);
    stdout.clear();

    // 3. Submit with post-commit socket drops across retries -> exit code 2 (acceptance_unknown)
    apiDouble.setDropAfterCommitCount(10);
    const submitUnknownExit = await runProducerCli(
      ["submit", "--config", configPath, "--run-id", "order-101"],
      { stdout, stderr }
    );
    apiDouble.setDropAfterCommitCount(0);
    assert.equal(submitUnknownExit, 2);
    const errOut = JSON.parse(stderr.read());
    assert.equal(errOut.acceptance, "unknown");
    stderr.clear();

    // 4. Retry original resolves existing admitted event without re-POSTing
    const preRetryPostCalls = apiDouble.getMetrics().postEventsCalls;
    const retryExit = await runProducerCli(
      ["retry-original", "--config", configPath, "--run-id", "order-101"],
      { stdout, stderr }
    );
    assert.equal(retryExit, 0);
    const retryOut = JSON.parse(stdout.read());
    assert.equal(retryOut.recovery_path, "resolved");
    assert.ok(typeof retryOut.event_id === "string");
    assert.equal(apiDouble.getMetrics().postEventsCalls, preRetryPostCalls);
    assert.equal(apiDouble.getMetrics().resolveCalls, 1);
    stdout.clear();

    // 5. Status inspects EventDetailDto + DeliverySummaryDto[]
    const statusExit = await runProducerCli(
      ["status", "--config", configPath, "--run-id", "order-101"],
      { stdout, stderr }
    );
    assert.equal(statusExit, 0);
    const statusOut = JSON.parse(stdout.read());
    assert.equal(statusOut.event.event_id, retryOut.event_id);
    assert.equal(statusOut.deliveries.items.length, 1);
    stdout.clear();

    // 6. Watch streams snapshot + event SSE frames cleanly
    const watchExit = await runProducerCli(
      ["watch", "--config", configPath, "--run-id", "order-101", "--max-frames", "2", "--timeout-ms", "2000"],
      { stdout, stderr }
    );
    assert.equal(watchExit, 0);
    const watchOut = JSON.parse(stdout.read());
    assert.equal(watchOut.frame_count, 2);
    assert.equal(watchOut.frames[0].frameType, "snapshot");
    assert.equal(watchOut.frames[1].frameType, "event");
    stdout.clear();

    // 7. Standalone submit via env:<VAR> + file:<PATH> credential refs + resolve 404
    const submitDirectExit = await runProducerCli(
      [
        "submit",
        "--origin",
        apiDouble.baseUrl,
        "--tenant-id",
        tenantId,
        "--project-id",
        projectId,
        "--credential-ref",
        "env:TEST_PRODUCER_BEARER",
        "--runs-dir",
        runsDir,
        "--run-id",
        "order-102",
        "--channel-id",
        channelId,
        "--event-type-id",
        eventTypeId,
        "--business-key",
        "order:102:settled",
        "--content",
        "{\"order_id\":\"ord_102\"}"
      ],
      {
        env: { TEST_PRODUCER_BEARER: token },
        stdout,
        stderr
      }
    );
    assert.equal(submitDirectExit, 0);
    const subDirectOut = JSON.parse(stdout.read());
    assert.equal(subDirectOut.outcome, "created");
    stdout.clear();

    const resolveMissingExit = await runProducerCli(
      [
        "resolve",
        "--origin",
        apiDouble.baseUrl,
        "--tenant-id",
        tenantId,
        "--project-id",
        projectId,
        "--credential-ref",
        `file:${secretFile}`,
        "--business-key",
        "order:missing"
      ],
      { stdout, stderr }
    );
    assert.equal(resolveMissingExit, 0);
    const missingOut = JSON.parse(stdout.read());
    assert.equal(missingOut.found, false);
    assert.equal(missingOut.acceptance, "unknown");
  } finally {
    await apiDouble.close();
    await ipcCustody.close();
    fs.rmSync(tmpRoot, { recursive: true, force: true });
  }
});
