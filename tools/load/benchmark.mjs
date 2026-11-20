import crypto from "node:crypto";
import fs from "node:fs";
import { monitorEventLoopDelay } from "node:perf_hooks";
import path from "node:path";
import {
  CliError,
  findRawSecretsInObject,
  parseCliFlags,
  readStrictJsonFile,
  redactSensitiveData,
  runCliMain
} from "../release/lib/cli.mjs";

const HELP_TEXT = `Usage: node tools/load/benchmark.mjs [options]

Execute a bounded synthetic load benchmark (or target HTTP endpoint probe) measuring
offered vs accepted request rate, monotonic p50/p95/p99 latency including failures,
Node monitorEventLoopDelay histograms, and separate backlog drain projections.

Options:
  --mode <mode>                  Benchmark mode: synthetic | http (default: synthetic)
  --target-url <url>             Owned local/staging HTTP target URL when --mode http
  --profile <path>               Optional strict JSON load profile file
  --backlog-snapshot <path>      Optional sanitized backlog snapshot JSON
  --duration-seconds <sec>       Measured interval duration in seconds (1..300, default: 1)
  --warmup-seconds <sec>         Warmup interval duration in seconds (0..60, default: 0)
  --concurrency <n>              Bounded worker concurrency (1..128, default: 4)
  --max-requests <n>             Hard cap on generated requests (1..100000, default: 200)
  --offered-rate <rps>           Target offered requests/sec in synthetic mode (1..10000, default: 100)
  --body-bytes <bytes>           Synthetic payload byte size (64..65536, default: 1024)
  --seed <int>                   Deterministic PRNG seed (default: 42)
  --initial-backlog <count>      Override backlog count for separate drain estimation
  --drain-rate-per-sec <rps>     Sustainable completed-obligation rate S for drain projection
  --incoming-rate-per-sec <rps>  Incoming delivery rate D for drain projection
  --timeout-ms <ms>              Per-request HTTP timeout in ms (50..30000, default: 2000)
  --out <path>                   Write sanitized benchmark report JSON
  --json                         Emit structured JSON output
  -h, --help                     Show help without reading secrets or mutating state
`;

const BLOCKED_EXTERNAL_PROVIDER_HOSTS = [
  "api.stripe.com",
  "stripe.com",
  "api.paystack.co",
  "paystack.co"
];

const ALLOWED_PROFILE_KEYS = new Set([
  "profile_version",
  "run_id",
  "seed",
  "duration_seconds",
  "warmup_seconds",
  "concurrency",
  "max_requests",
  "offered_rate_per_sec",
  "body_bytes",
  "timeout_ms",
  "fixture_scope"
]);

function roundMs(value) {
  return Math.round(value * 1000) / 1000;
}

function nsToMs(ns) {
  const num = typeof ns === "bigint" ? Number(ns) : Number(ns);
  if (!Number.isFinite(num) || num < 0) {
    return 0;
  }
  return roundMs(num / 1_000_000);
}

export function computeLatencyPercentiles(samplesMs) {
  if (!Array.isArray(samplesMs) || samplesMs.length === 0) {
    return {
      count: 0,
      min_ms: 0,
      p50_ms: 0,
      p95_ms: 0,
      p99_ms: 0,
      max_ms: 0,
      mean_ms: 0
    };
  }
  const sorted = [...samplesMs].sort((a, b) => a - b);
  const count = sorted.length;
  const pick = (q) => {
    const idx = Math.min(count - 1, Math.max(0, Math.ceil(q * count) - 1));
    return roundMs(sorted[idx]);
  };
  const sum = sorted.reduce((acc, v) => acc + v, 0);
  return {
    count,
    min_ms: roundMs(sorted[0]),
    p50_ms: pick(0.5),
    p95_ms: pick(0.95),
    p99_ms: pick(0.99),
    max_ms: roundMs(sorted[count - 1]),
    mean_ms: roundMs(sum / count)
  };
}

export function computeBacklogDrainProjection(input) {
  const outboxPending = Math.max(0, Number(input.outbox_pending_count ?? 0));
  const deliveryPending = Math.max(0, Number(input.delivery_pending_count ?? input.initial_backlog ?? 0));
  const strictOrderHeld = Math.max(0, Number(input.strict_order_held_count ?? 0));
  const unknownOutcomeCount = Math.max(0, Number(input.unknown_outcome_count ?? 0));
  const oldestPendingAgeSec =
    input.oldest_pending_age_seconds === null || input.oldest_pending_age_seconds === undefined
      ? null
      : Math.max(0, Number(input.oldest_pending_age_seconds));

  const incomingRate = Math.max(0, Number(input.incoming_rate_per_sec ?? 0));
  const sustainableRate = Math.max(0, Number(input.sustainable_drain_rate_per_sec ?? 0));
  const eligibleBacklog = outboxPending + deliveryPending;

  let drainStatus = "idle";
  let netDrainPerSec = roundMs(sustainableRate - incomingRate);
  let estimatedDrainSeconds = 0;

  if (eligibleBacklog === 0 && strictOrderHeld === 0) {
    drainStatus = "idle";
    estimatedDrainSeconds = 0;
  } else if (eligibleBacklog === 0 && strictOrderHeld > 0) {
    drainStatus = "held_blocked";
    estimatedDrainSeconds = null;
  } else if (sustainableRate <= incomingRate) {
    drainStatus = "growing";
    estimatedDrainSeconds = null;
  } else {
    drainStatus = "draining";
    estimatedDrainSeconds = Math.ceil(eligibleBacklog / (sustainableRate - incomingRate));
  }

  return {
    measurement_separated_from_target_rate: true,
    outbox_pending_count: outboxPending,
    delivery_pending_count: deliveryPending,
    eligible_backlog_total: eligibleBacklog,
    strict_order_held_count: strictOrderHeld,
    unknown_outcome_count: unknownOutcomeCount,
    oldest_pending_age_seconds: oldestPendingAgeSec,
    incoming_rate_per_sec: roundMs(incomingRate),
    sustainable_drain_rate_per_sec: roundMs(sustainableRate),
    net_drain_rate_per_sec: netDrainPerSec,
    estimated_drain_seconds: estimatedDrainSeconds,
    drain_status: drainStatus,
    note:
      strictOrderHeld > 0
        ? "Strict-order held keys remain blocked independently and cannot drain at global throughput."
        : "Eligible backlog drain estimate assumes steady completion rate without new holds."
  };
}

function validateTargetUrl(rawUrl) {
  let parsed;
  try {
    parsed = new URL(rawUrl);
  } catch {
    throw new CliError(`Invalid --target-url: "${rawUrl}"`, 1);
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new CliError(`Unsupported target URL protocol "${parsed.protocol}"`, 1);
  }
  const host = parsed.hostname.toLowerCase();
  if (BLOCKED_EXTERNAL_PROVIDER_HOSTS.some((b) => host === b || host.endsWith(`.${b}`))) {
    throw new CliError(
      `Refusing load test against public payment provider domain "${host}"; use owned local/fixture receiver`,
      1
    );
  }
  return parsed.toString();
}

function loadAndValidateProfile(profilePath) {
  const raw = readStrictJsonFile(profilePath);
  const secretFindings = findRawSecretsInObject(raw, "$");
  if (secretFindings.length > 0) {
    throw new CliError(`Refusing load profile containing secrets:\n- ${secretFindings.join("\n- ")}`, 1);
  }
  for (const key of Object.keys(raw)) {
    if (!ALLOWED_PROFILE_KEYS.has(key)) {
      throw new CliError(`Unknown load profile field "${key}"`, 1);
    }
  }
  if (raw.duration_seconds !== undefined && (raw.duration_seconds < 1 || raw.duration_seconds > 300)) {
    throw new CliError("Profile duration_seconds must be within 1..300", 1);
  }
  if (raw.max_requests !== undefined && (raw.max_requests < 1 || raw.max_requests > 100000)) {
    throw new CliError("Profile max_requests must be within 1..100000", 1);
  }
  if (raw.concurrency !== undefined && (raw.concurrency < 1 || raw.concurrency > 128)) {
    throw new CliError("Profile concurrency must be within 1..128", 1);
  }
  return raw;
}

function buildDeterministicPayload(seed, seq, targetBytes) {
  const prefix = JSON.stringify({
    seed,
    sequence: seq,
    business_key: `bench-${seed}-${seq}`
  });
  const padLen = Math.max(0, targetBytes - Buffer.byteLength(prefix, "utf8") - 14);
  return JSON.stringify({
    seed,
    sequence: seq,
    business_key: `bench-${seed}-${seq}`,
    pad: "x".repeat(padLen)
  });
}

async function executeSingleSyntheticOp(seq, seed, bodyBytes) {
  const payload = buildDeterministicPayload(seed, seq, bodyBytes);
  const digest = crypto.createHash("sha256").update(payload).digest("hex");
  return {
    accepted: digest.length === 64,
    status: 201,
    rejected: false,
    error: false,
    bytes: Buffer.byteLength(payload, "utf8")
  };
}

async function executeSingleHttpOp(targetUrl, seq, seed, bodyBytes, timeoutMs) {
  const payload = buildDeterministicPayload(seed, seq, bodyBytes);
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(targetUrl, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "idempotency-key": `bench-${seed}-${seq}`
      },
      body: payload,
      signal: controller.signal
    });
    await res.arrayBuffer();
    const ok = res.status >= 200 && res.status < 300;
    return {
      accepted: ok,
      status: res.status,
      rejected: !ok,
      error: false,
      bytes: Buffer.byteLength(payload, "utf8")
    };
  } catch {
    return {
      accepted: false,
      status: null,
      rejected: false,
      error: true,
      bytes: Buffer.byteLength(payload, "utf8")
    };
  } finally {
    clearTimeout(timer);
  }
}

export async function runLoadBenchmark(options = {}) {
  const profile = options.profilePath ? loadAndValidateProfile(options.profilePath) : {};
  const mode = options.targetUrl ? "http" : (options.mode ?? "synthetic");
  if (mode === "http" && !options.targetUrl) {
    throw new CliError("--mode http requires --target-url <url>", 1);
  }
  const targetUrl = options.targetUrl ? validateTargetUrl(options.targetUrl) : null;

  const durationSeconds = options.durationSeconds ?? profile.duration_seconds ?? 1;
  const warmupSeconds = options.warmupSeconds ?? profile.warmup_seconds ?? 0;
  const concurrency = options.concurrency ?? profile.concurrency ?? 4;
  const maxRequests = options.maxRequests ?? profile.max_requests ?? 200;
  const offeredRatePerSec = options.offeredRate ?? profile.offered_rate_per_sec ?? 100;
  const bodyBytes = options.bodyBytes ?? profile.body_bytes ?? 1024;
  const seed = options.seed ?? profile.seed ?? 42;
  const timeoutMs = options.timeoutMs ?? profile.timeout_ms ?? 2000;

  const backlogSnapshot = options.backlogSnapshotPath
    ? readStrictJsonFile(options.backlogSnapshotPath)
    : {};
  if (options.backlogSnapshotPath) {
    const secretFindings = findRawSecretsInObject(backlogSnapshot, "$");
    if (secretFindings.length > 0) {
      throw new CliError(`Refusing backlog snapshot with raw secrets:\n- ${secretFindings.join("\n- ")}`, 1);
    }
  }

  const loopHistogram = monitorEventLoopDelay({ resolution: 10 });
  loopHistogram.enable();

  const warmupCount = warmupSeconds > 0 ? Math.min(maxRequests, Math.max(1, concurrency)) : 0;
  const measuredCap = Math.min(maxRequests, Math.max(1, Math.round(durationSeconds * offeredRatePerSec)));

  let warmupCompleted = 0;
  const latenciesMs = [];
  let offeredCount = 0;
  let acceptedCount = 0;
  let rejectedCount = 0;
  let errorCount = 0;
  let totalPayloadBytes = 0;

  const warmupStartNs = process.hrtime.bigint();
  for (let w = 0; w < warmupCount; w += 1) {
    if (mode === "http") {
      await executeSingleHttpOp(targetUrl, -1 - w, seed, bodyBytes, timeoutMs);
    } else {
      await executeSingleSyntheticOp(-1 - w, seed, bodyBytes);
    }
    warmupCompleted += 1;
  }
  const warmupDurationMs = nsToMs(process.hrtime.bigint() - warmupStartNs);

  const measuredStartIso = new Date().toISOString();
  const measuredStartNs = process.hrtime.bigint();
  const deadlineNs = measuredStartNs + BigInt(Math.round(durationSeconds * 1_000_000_000));
  let nextSeq = 0;

  try {
    const workers = Array.from({ length: concurrency }, async () => {
      while (true) {
        if (nextSeq >= measuredCap) {
          break;
        }
        const nowNs = process.hrtime.bigint();
        if (nowNs >= deadlineNs && offeredCount > 0) {
          break;
        }
        const seq = nextSeq;
        nextSeq += 1;
        offeredCount += 1;
        const opStartNs = process.hrtime.bigint();
        const res =
          mode === "http"
            ? await executeSingleHttpOp(targetUrl, seq, seed, bodyBytes, timeoutMs)
            : await executeSingleSyntheticOp(seq, seed, bodyBytes);
        const opMs = nsToMs(process.hrtime.bigint() - opStartNs);
        latenciesMs.push(opMs);
        totalPayloadBytes += res.bytes;
        if (res.accepted) {
          acceptedCount += 1;
        } else if (res.error) {
          errorCount += 1;
        } else if (res.rejected) {
          rejectedCount += 1;
        }
        if (mode === "synthetic" && seq % concurrency === 0) {
          await new Promise((resolve) => setTimeout(resolve, 1));
        }
      }
    });
    await Promise.all(workers);
  } finally {
    loopHistogram.disable();
  }

  const measuredDurationMs = Math.max(1, nsToMs(process.hrtime.bigint() - measuredStartNs));
  const measuredEndIso = new Date().toISOString();
  const measuredDurationSec = measuredDurationMs / 1000;

  const observedIncomingRate =
    options.incomingRatePerSec !== undefined
      ? options.incomingRatePerSec
      : offeredCount / measuredDurationSec;
  const observedDrainRate =
    options.drainRatePerSec !== undefined
      ? options.drainRatePerSec
      : acceptedCount / measuredDurationSec;

  const backlogProjection = computeBacklogDrainProjection({
    ...backlogSnapshot,
    initial_backlog: options.initialBacklog ?? backlogSnapshot.delivery_pending_count ?? 0,
    incoming_rate_per_sec: observedIncomingRate,
    sustainable_drain_rate_per_sec: observedDrainRate
  });

  const report = redactSensitiveData({
    ok: true,
    run_id: profile.run_id ?? crypto.randomUUID(),
    mode,
    target_scope: targetUrl ? "owned_http_target" : "in_process_synthetic",
    seed,
    warmup: {
      requests_completed: warmupCompleted,
      duration_ms: warmupDurationMs
    },
    measured_window: {
      started_at: measuredStartIso,
      ended_at: measuredEndIso,
      duration_ms: roundMs(measuredDurationMs),
      concurrency,
      body_bytes: bodyBytes
    },
    workload_rates: {
      offered_count: offeredCount,
      accepted_count: acceptedCount,
      rejected_count: rejectedCount,
      error_count: errorCount,
      total_payload_bytes: totalPayloadBytes,
      offered_requests_per_sec: roundMs(offeredCount / measuredDurationSec),
      accepted_requests_per_sec: roundMs(acceptedCount / measuredDurationSec),
      rejected_requests_per_sec: roundMs(rejectedCount / measuredDurationSec),
      errors_per_sec: roundMs(errorCount / measuredDurationSec)
    },
    latency_distribution_ms: computeLatencyPercentiles(latenciesMs),
    event_loop_delay_ms: {
      resolution_ms: 10,
      min: nsToMs(loopHistogram.min),
      mean: nsToMs(loopHistogram.mean),
      p50: nsToMs(loopHistogram.percentile(50)),
      p95: nsToMs(loopHistogram.percentile(95)),
      p99: nsToMs(loopHistogram.percentile(99)),
      max: nsToMs(loopHistogram.max)
    },
    backlog_drain: backlogProjection,
    limitations:
      mode === "synthetic"
        ? "In-process synthetic benchmark does not prove downstream PostgreSQL, broker, or durable receiver capacity."
        : "Measured HTTP benchmark reflects the targeted endpoint only; separate receiver inbox mutations remain distinct."
  });

  if (options.outPath) {
    const resolvedOut = path.resolve(options.outPath);
    fs.mkdirSync(path.dirname(resolvedOut), { recursive: true });
    fs.writeFileSync(resolvedOut, `${JSON.stringify(report, null, 2)}\n`, "utf8");
  }

  return report;
}

runCliMain(import.meta.url, HELP_TEXT, async (argv) => {
  const parsed = parseCliFlags(argv, {
    options: {
      "--mode": { type: "string", enum: ["synthetic", "http"], default: "synthetic" },
      "--target-url": { type: "string" },
      "--profile": { type: "string" },
      "--backlog-snapshot": { type: "string" },
      "--duration-seconds": { type: "integer", min: 1, max: 300 },
      "--warmup-seconds": { type: "integer", min: 0, max: 60 },
      "--concurrency": { type: "integer", min: 1, max: 128 },
      "--max-requests": { type: "integer", min: 1, max: 100000 },
      "--offered-rate": { type: "integer", min: 1, max: 10000 },
      "--body-bytes": { type: "integer", min: 64, max: 65536 },
      "--seed": { type: "integer", min: 0, max: 2147483647 },
      "--initial-backlog": { type: "integer", min: 0, max: 100000000 },
      "--drain-rate-per-sec": { type: "number", min: 0, max: 1000000 },
      "--incoming-rate-per-sec": { type: "number", min: 0, max: 1000000 },
      "--timeout-ms": { type: "integer", min: 50, max: 30000 },
      "--out": { type: "string" },
      "--json": { type: "boolean", default: false }
    }
  });
  if (parsed.help) {
    return { help: true };
  }
  const report = await runLoadBenchmark({
    mode: parsed.options["--mode"],
    targetUrl: parsed.options["--target-url"],
    profilePath: parsed.options["--profile"],
    backlogSnapshotPath: parsed.options["--backlog-snapshot"],
    durationSeconds: parsed.options["--duration-seconds"],
    warmupSeconds: parsed.options["--warmup-seconds"],
    concurrency: parsed.options["--concurrency"],
    maxRequests: parsed.options["--max-requests"],
    offeredRate: parsed.options["--offered-rate"],
    bodyBytes: parsed.options["--body-bytes"],
    seed: parsed.options["--seed"],
    initialBacklog: parsed.options["--initial-backlog"],
    drainRatePerSec: parsed.options["--drain-rate-per-sec"],
    incomingRatePerSec: parsed.options["--incoming-rate-per-sec"],
    timeoutMs: parsed.options["--timeout-ms"],
    outPath: parsed.options["--out"]
  });

  if (parsed.options["--json"]) {
    return { exitCode: 0, output: report };
  }
  return {
    exitCode: 0,
    output: `[benchmark] mode=${report.mode} offered=${report.workload_rates.offered_count} rps=${report.workload_rates.offered_requests_per_sec} p50=${report.latency_distribution_ms.p50_ms}ms p95=${report.latency_distribution_ms.p95_ms}ms p99=${report.latency_distribution_ms.p99_ms}ms el_p99=${report.event_loop_delay_ms.p99}ms drain=${report.backlog_drain.drain_status}`
  };
});
