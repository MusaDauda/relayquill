import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  CliError,
  parseCliFlags,
  readStrictJsonFile,
  redactSensitiveData,
  runCliMain
} from "./lib/cli.mjs";
import { validateDeploymentProfileFile } from "./lib/schema.mjs";

const DEFAULT_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");

const HELP_TEXT = `Usage: node tools/release/probe.mjs --config <profile.json> [options]

Execute sanitized release probes (pre-activation, post-activation, negative)
without mutating traffic gates or converting failed checks into warnings.

Options:
  --config <path>          Deployment profile JSON (required)
  --suite <name>           Probe suite: pre-activation | post-activation | negative (default: pre-activation)
  --snapshot <path>        Sanitized probe observation snapshot JSON (offline verification)
  --live                   Run bounded live HTTP health checks against configured/target endpoints
  --api-url <url>          Override API base URL for bounded --live probe
  --console-url <url>      Override console base URL for bounded --live probe
  --timeout-ms <ms>        Per-probe HTTP timeout in ms (100..30000, default 5000)
  --provider-source <src>  Payment callback source label: local_simulation | provider_sandbox
  --out <path>             Write sanitized probe report JSON
  --root <dir>             Repository root directory
  --json                   Emit structured JSON output
  -h, --help               Show help without reading secrets or mutating state
`;

async function probeHttpUrl(url, timeoutMs) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  const started = Date.now();
  try {
    const res = await fetch(url, {
      method: "GET",
      redirect: "manual",
      signal: controller.signal
    });
    return {
      ok: res.status >= 200 && res.status < 300,
      status: res.status,
      duration_ms: Date.now() - started,
      headers: {
        x_content_type_options: res.headers.get("x-content-type-options"),
        cache_control: res.headers.get("cache-control")
      }
    };
  } catch (err) {
    return {
      ok: false,
      status: null,
      duration_ms: Date.now() - started,
      error: err instanceof Error ? err.message : String(err)
    };
  } finally {
    clearTimeout(timer);
  }
}

function evaluateSnapshotChecks(suite, snapshot) {
  const checks = [];
  const roles = snapshot.roles ?? {};
  const neg = snapshot.negative ?? {};

  if (suite === "pre-activation" || suite === "post-activation") {
    for (const roleName of ["api", "relay", "fanout", "sender", "coordinator"]) {
      const state = roles[roleName];
      const passed = Boolean(state && state.ready === true && state.live !== false);
      checks.push({
        id: `role_ready:${roleName}`,
        category: "readiness",
        passed,
        detail: passed ? "ready" : `role ${roleName} not ready`
      });
    }
    const healthyBrokers = Number(snapshot.broker?.healthy_nodes ?? 0);
    const totalBrokers = Number(snapshot.broker?.total_nodes ?? 3);
    const quorumOk = healthyBrokers >= Math.floor(totalBrokers / 2) + 1 && totalBrokers >= 3;
    checks.push({
      id: "broker_quorum",
      category: "broker",
      passed: quorumOk,
      detail: `${healthyBrokers}/${totalBrokers} healthy broker nodes`
    });
    const dbTlsOk = snapshot.database?.tls_verified === true && snapshot.database?.schema_revision_matched === true;
    checks.push({
      id: "database_tls_and_schema",
      category: "database",
      passed: dbTlsOk,
      detail: dbTlsOk ? "TLS verified and schema matched" : "database TLS or schema revision check failed"
    });
  }

  if (suite === "post-activation") {
    const publicCheck = snapshot.public_endpoints ?? {};
    checks.push({
      id: "public_https_api",
      category: "public_surface",
      passed: publicCheck.api_https_ok === true,
      detail: publicCheck.api_https_ok === true ? "external HTTPS API verified" : "external HTTPS API probe failed"
    });
    checks.push({
      id: "public_https_console",
      category: "public_surface",
      passed: publicCheck.console_https_ok === true,
      detail:
        publicCheck.console_https_ok === true
          ? "external HTTPS console verified"
          : "external HTTPS console probe failed"
    });
    const synthetic = snapshot.synthetic_walkthrough ?? {};
    checks.push({
      id: "synthetic_event_and_receiver",
      category: "end_to_end",
      passed:
        synthetic.admitted === true &&
        synthetic.delivered === true &&
        synthetic.receiver_unique_mutations === 1,
      detail: `admitted=${Boolean(synthetic.admitted)} delivered=${Boolean(synthetic.delivered)} rc_mutations=${synthetic.receiver_unique_mutations ?? 0}`
    });
  }

  if (suite === "negative" || suite === "pre-activation" || suite === "post-activation") {
    checks.push({
      id: "negative_unauthenticated_denied",
      category: "negative",
      passed: neg.unauthenticated_rejected === true,
      detail: neg.unauthenticated_rejected === true ? "denied as expected" : "missing unauthenticated denial proof"
    });
    checks.push({
      id: "negative_ssrf_private_ip_denied",
      category: "negative",
      passed: neg.ssrf_private_denied === true,
      detail: neg.ssrf_private_denied === true ? "SSRF private address denied" : "missing SSRF denial proof"
    });
    checks.push({
      id: "negative_plaintext_broker_denied",
      category: "negative",
      passed: neg.plaintext_broker_denied === true,
      detail:
        neg.plaintext_broker_denied === true
          ? "plaintext broker connection rejected"
          : "missing plaintext broker denial proof"
    });
    if (suite === "negative") {
      checks.push({
        id: "negative_stale_epoch_denied",
        category: "negative",
        passed: neg.stale_epoch_denied === true,
        detail:
          neg.stale_epoch_denied === true
            ? "stale epoch rejected"
            : "missing stale epoch rejection proof"
      });
    }
  }

  return checks;
}

export async function runReleaseProbes(options) {
  const repoRoot = path.resolve(options.rootDir ?? DEFAULT_ROOT);
  const profileRes = validateDeploymentProfileFile(options.configPath, { repoRoot });
  if (!profileRes.ok) {
    throw new CliError(`Invalid profile:\n- ${profileRes.errors.join("\n- ")}`, 1);
  }
  const profile = profileRes.profile;
  const suite = options.suite ?? "pre-activation";
  const timeoutMs = options.timeoutMs ?? 5000;
  const providerSource = options.providerSource ?? "local_simulation";

  let checks = [];
  let probeStatus = "executed";

  if (options.snapshotPath) {
    const snapshot = readStrictJsonFile(options.snapshotPath);
    checks = evaluateSnapshotChecks(suite, snapshot);
  } else if (options.live) {
    const apiBase = (options.apiUrl ?? profile.dns_names.api_origin).replace(/\/+$/, "");
    const consoleBase = (options.consoleUrl ?? profile.dns_names.console_origin).replace(/\/+$/, "");
    const apiReady = await probeHttpUrl(`${apiBase}/api/v1/health/ready`, timeoutMs);
    const consoleHealth = await probeHttpUrl(`${consoleBase}/healthz`, timeoutMs);
    checks = [
      {
        id: "live_api_ready",
        category: "readiness",
        passed: apiReady.ok,
        status: apiReady.status,
        duration_ms: apiReady.duration_ms,
        detail: apiReady.ok ? "HTTP 2xx" : apiReady.error ?? `HTTP ${apiReady.status}`
      },
      {
        id: "live_console_healthz",
        category: "readiness",
        passed: consoleHealth.ok,
        status: consoleHealth.status,
        duration_ms: consoleHealth.duration_ms,
        detail: consoleHealth.ok ? "HTTP 2xx" : consoleHealth.error ?? `HTTP ${consoleHealth.status}`
      }
    ];
  } else {
    probeStatus = "not_run";
    checks = [
      {
        id: "probe_execution_missing",
        category: "control",
        passed: false,
        detail: "Provide --snapshot <path> or --live to execute release probes (never auto-passes unrun checks)"
      }
    ];
  }

  const failedChecks = checks.filter((c) => !c.passed);
  const report = redactSensitiveData({
    ok: failedChecks.length === 0 && probeStatus === "executed",
    suite,
    probe_status: probeStatus,
    deployment_name: profile.deployment_name,
    deployment_mode: profileRes.deploymentMode,
    activates_traffic: false,
    provider_ingress_evidence_source: providerSource,
    live_funds_processed: false,
    observed_at: new Date().toISOString(),
    passed_count: checks.length - failedChecks.length,
    failed_count: failedChecks.length,
    checks
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
      "--config": { type: "string", required: true },
      "--suite": {
        type: "string",
        enum: ["pre-activation", "post-activation", "negative"],
        default: "pre-activation"
      },
      "--snapshot": { type: "string" },
      "--live": { type: "boolean", default: false },
      "--api-url": { type: "string" },
      "--console-url": { type: "string" },
      "--timeout-ms": { type: "integer", min: 100, max: 30000, default: 5000 },
      "--provider-source": {
        type: "string",
        enum: ["local_simulation", "provider_sandbox"],
        default: "local_simulation"
      },
      "--out": { type: "string" },
      "--root": { type: "string" },
      "--json": { type: "boolean", default: false }
    }
  });
  if (parsed.help) {
    return { help: true };
  }
  const report = await runReleaseProbes({
    configPath: parsed.options["--config"],
    suite: parsed.options["--suite"],
    snapshotPath: parsed.options["--snapshot"],
    live: parsed.options["--live"],
    apiUrl: parsed.options["--api-url"],
    consoleUrl: parsed.options["--console-url"],
    timeoutMs: parsed.options["--timeout-ms"],
    providerSource: parsed.options["--provider-source"],
    outPath: parsed.options["--out"],
    rootDir: parsed.options["--root"]
  });

  const exitCode = report.ok ? 0 : 1;
  if (parsed.options["--json"]) {
    return { exitCode, output: report };
  }
  return {
    exitCode,
    output: `[probe] suite=${report.suite} ok=${report.ok} passed=${report.passed_count} failed=${report.failed_count}`
  };
});
