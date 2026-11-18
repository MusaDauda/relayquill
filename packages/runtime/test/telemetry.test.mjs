import test from "node:test";
import assert from "node:assert/strict";
import { ExportResultCode } from "@opentelemetry/core";
import {
  MAX_TRACESTATE_BYTES,
  MAX_TRACESTATE_ENTRIES,
  TELEMETRY_MAX_EXPORT_BATCH_SIZE,
  TELEMETRY_MAX_QUEUE_SIZE,
  buildSafeTraceViewUrl,
  createSecretHandle,
  createTraceparent,
  formatTraceparent,
  initTelemetry,
  parseTraceparent,
  redactTelemetryText,
  sanitizeIncomingTraceHeaders,
  sanitizeTelemetryAttributes,
  sanitizeTracestate
} from "@relayquill/runtime";

test("W3C traceparent parser rejects all-zero IDs, bad length, uppercase, and unsupported versions", () => {
  const valid = createTraceparent(1);
  assert.equal(valid.length, 55);
  const parsed = parseTraceparent(valid);
  assert.equal(parsed.valid, true);
  if (parsed.valid) {
    assert.equal(parsed.canonical, valid);
    assert.equal(parsed.sampled, true);
    assert.equal(
      formatTraceparent({
        traceId: parsed.traceId,
        spanId: parsed.spanId,
        traceFlags: parsed.traceFlags
      }),
      valid
    );
  }

  assert.equal(
    parseTraceparent("00-00000000000000000000000000000000-1111111111111111-01").valid,
    false
  );
  assert.equal(
    parseTraceparent("00-11111111111111111111111111111111-0000000000000000-01").valid,
    false
  );
  assert.equal(
    parseTraceparent("01-11111111111111111111111111111111-2222222222222222-01").valid,
    false
  );
  assert.equal(
    parseTraceparent("00-1111111111111111111111111111111A-2222222222222222-01").valid,
    false
  );
  assert.equal(parseTraceparent("short").valid, false);
});

test("W3C tracestate sanitizer enforces <= 8 entries, <= 256 bytes, allowlist, and strips baggage", () => {
  const tp = createTraceparent(1);
  const rawState = Array.from({ length: 12 }, (_, idx) => `v${idx}=val${idx}`).join(",");

  // Default external propagation without allowlist returns empty tracestate and strips baggage.
  const inboundDefault = sanitizeIncomingTraceHeaders({
    traceparent: tp,
    tracestate: rawState,
    baggage: "userId=alice,secret=xyz"
  });
  assert.equal(inboundDefault.suppliedValidTraceparent, true);
  assert.equal(inboundDefault.tracestate, "");
  assert.equal(inboundDefault.baggageDropped, true);

  // With allowAnyValidVendorKey, bounded to <= 8 entries and <= 256 ASCII bytes
  const truncatedEntries = sanitizeTracestate(rawState, { allowAnyValidVendorKey: true });
  const parts = truncatedEntries.split(",");
  assert.equal(parts.length, MAX_TRACESTATE_ENTRIES);
  assert.ok(Buffer.byteLength(truncatedEntries, "ascii") <= MAX_TRACESTATE_BYTES);

  // Byte limit check (each entry ~65 bytes -> at most 3 entries fit <= 256B)
  const longRaw = Array.from({ length: 6 }, (_, idx) => `vendor${idx}=${"a".repeat(58)}`).join(",");
  const byteBounded = sanitizeTracestate(longRaw, { allowAnyValidVendorKey: true });
  assert.ok(Buffer.byteLength(byteBounded, "ascii") <= MAX_TRACESTATE_BYTES);
  assert.equal(byteBounded.split(",").length, 3);

  // Explicit allowlist keeps only approved vendor keys
  const allowlisted = sanitizeTracestate("rq=ok,evil=bad,other=nope,rq=dup", {
    allowedVendorKeys: ["rq"]
  });
  assert.equal(allowlisted, "rq=ok");
});

test("attribute and log sanitization removes secrets, SecretHandles, and credentials", () => {
  const handle = createSecretHandle("top-secret-key", { id: "k1" });
  const clean = sanitizeTelemetryAttributes({
    "relayquill.role": "sender",
    "relayquill.attempt": 3,
    password: "should-be-dropped",
    authorization: "Bearer abc123",
    raw_body: '{"sensitive":"data"}',
    credential_handle: handle,
    error_summary: "failed connecting postgres://user:pass123@db.internal:5432/rq with rq_p1.secret99"
  });

  assert.equal(clean["relayquill.role"], "sender");
  assert.equal(clean["relayquill.attempt"], 3);
  assert.equal("password" in clean, false);
  assert.equal("authorization" in clean, false);
  assert.equal("raw_body" in clean, false);
  assert.equal("credential_handle" in clean, false);
  assert.equal(String(clean.error_summary).includes("pass123"), false);
  assert.equal(String(clean.error_summary).includes("rq_p1.secret99"), false);
  assert.equal(redactTelemetryText("Bearer secret_tok_123").includes("secret_tok_123"), false);
  handle.destroy();

  assert.equal(
    buildSafeTraceViewUrl("https://traces.relayquill.example", "11111111111111111111111111111111"),
    "https://traces.relayquill.example/trace/11111111111111111111111111111111"
  );
  assert.equal(
    buildSafeTraceViewUrl("http://evil.example", "11111111111111111111111111111111"),
    undefined
  );
  assert.equal(
    buildSafeTraceViewUrl("https://traces.relayquill.example", "00000000000000000000000000000000"),
    undefined
  );
});

test("OpenTelemetry NodeSDK telemetry enforces queue bounds and exports scrubbed manual attempt spans", async () => {
  assert.equal(TELEMETRY_MAX_QUEUE_SIZE, 2048);
  assert.equal(TELEMETRY_MAX_EXPORT_BATCH_SIZE, 256);

  assert.throws(
    () =>
      initTelemetry({
        serviceName: "bad-queue",
        maxQueueSize: 4096,
        registerGlobalSdk: false
      }),
    /maxQueueSize/
  );

  const exportedSpans = [];
  const memoryExporter = {
    export(spans, resultCallback) {
      exportedSpans.push(...spans);
      resultCallback({ code: ExportResultCode.SUCCESS });
    },
    shutdown() {
      return Promise.resolve();
    }
  };

  const telemetry = initTelemetry({
    serviceName: "relayquill-sender-test",
    spanExporter: memoryExporter,
    maxQueueSize: TELEMETRY_MAX_QUEUE_SIZE,
    maxExportBatchSize: TELEMETRY_MAX_EXPORT_BATCH_SIZE
  });

  try {
    const inboundTp = createTraceparent(1);
    const extracted = telemetry.extractInboundContext({
      traceparent: inboundTp,
      tracestate: "vendor=123",
      baggage: "token=secret"
    });
    assert.equal(extracted.baggageDropped, true);
    assert.ok(extracted.link !== undefined);

    const attemptHandle = telemetry.createAttemptSpanContext({
      links: extracted.link !== undefined ? [extracted.link] : undefined,
      attributes: {
        "relayquill.delivery_id": "del-1",
        signing_key: "must-never-appear",
        note: "Bearer leak_token_abc"
      }
    });

    assert.equal(attemptHandle.traceparent.length, 55);
    assert.equal(parseTraceparent(attemptHandle.traceparent).valid, true);
    assert.equal(attemptHandle.tracestate, "");
    attemptHandle.end({ code: "OK" });
  } finally {
    await telemetry.shutdown();
  }

  assert.equal(exportedSpans.length, 1);
  const span = exportedSpans[0];
  assert.equal(span.attributes["relayquill.delivery_id"], "del-1");
  assert.equal("signing_key" in span.attributes, false);
  assert.equal(String(span.attributes.note).includes("leak_token_abc"), false);
  assert.equal(telemetry.getStats().exportedSpans, 1);
});

test("failing telemetry exporter tracks drops safely without throwing", async () => {
  const failingExporter = {
    export(_spans, resultCallback) {
      resultCallback({
        code: ExportResultCode.FAILED,
        error: new Error("collector offline")
      });
    },
    shutdown() {
      return Promise.resolve();
    }
  };

  const telemetry = initTelemetry({
    serviceName: "relayquill-fail-test",
    spanExporter: failingExporter
  });

  try {
    const span = telemetry.createAttemptSpanContext();
    span.end({ code: "ERROR", message: "failed with rq_p1.mysecret" });
  } finally {
    await telemetry.shutdown();
  }

  const stats = telemetry.getStats();
  assert.ok(stats.exportFailures >= 1);
  assert.ok(stats.droppedSpans >= 1);
});
