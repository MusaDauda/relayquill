import { spawn, spawnSync } from "node:child_process";
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");

const ALL_TOOL_SCRIPTS = [
  "tools/release/validate-profile.mjs",
  "tools/release/check-identity.mjs",
  "tools/release/inspect-plan.mjs",
  "tools/release/build-manifest.mjs",
  "tools/release/verify-manifest.mjs",
  "tools/release/rollout.mjs",
  "tools/release/inspect-rollout.mjs",
  "tools/release/probe.mjs",
  "tools/release/teardown-inventory.mjs",
  "tools/cluster/check-context.mjs",
  "tools/cluster/validate-rendered.mjs",
  "tools/cluster/failure-run.mjs",
  "tools/recovery/isolated-restore-audit.mjs",
  "tools/recovery/repair-runner.mjs",
  "tools/load/benchmark.mjs",
  "tools/load/cost-model.mjs",
  "tools/operations/diagnose.mjs"
];

function runTool(relScript, args, options = {}) {
  const scriptPath = path.join(REPO_ROOT, relScript);
  return spawnSync(process.execPath, [scriptPath, ...args], {
    cwd: options.cwd ?? REPO_ROOT,
    encoding: "utf8",
    shell: false,
    maxBuffer: 32 * 1024 * 1024
  });
}

function runToolAsync(relScript, args, options = {}) {
  const scriptPath = path.join(REPO_ROOT, relScript);
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [scriptPath, ...args], {
      cwd: options.cwd ?? REPO_ROOT,
      shell: false,
      stdio: ["ignore", "pipe", "pipe"]
    });
    let stdout = "";
    let stderr = "";
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk) => {
      stdout += chunk;
    });
    child.stderr.on("data", (chunk) => {
      stderr += chunk;
    });
    child.on("error", reject);
    child.on("close", (status) => {
      resolve({ status, stdout, stderr });
    });
  });
}

function makeTempDir(t, prefix = "rq-ops-test-") {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  return dir;
}

function writeJson(filePath, obj) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, `${JSON.stringify(obj, null, 2)}\n`, "utf8");
  return filePath;
}

test("all ops/release/cluster/recovery/load CLIs support --help cleanly", () => {
  for (const script of ALL_TOOL_SCRIPTS) {
    const res = runTool(script, ["--help"]);
    assert.equal(res.status, 0, `${script} --help exited ${res.status}: ${res.stderr}`);
    assert.match(res.stdout, /Usage:/i, `${script} --help missing Usage text`);
  }
});

test("all ops CLIs reject unknown flags and secret-bearing CLI arguments", () => {
  for (const script of ALL_TOOL_SCRIPTS) {
    const unknownRes = runTool(script, ["--nonexistent-flag-xyz"]);
    assert.notEqual(unknownRes.status, 0, `${script} accepted unknown flag`);
    assert.match(unknownRes.stderr, /Unknown CLI flag/i);

    const secretFlagRes = runTool(script, ["--password", "super-secret-value"]);
    assert.notEqual(secretFlagRes.status, 0, `${script} accepted --password flag`);
    assert.match(secretFlagRes.stderr, /secret-bearing CLI argument/i);

    const credValueRes = runTool(script, ["--config", "rq_p1.00000000-0000-4000-8000-000000000001.secretbytes12345"]);
    assert.notEqual(credValueRes.status, 0, `${script} accepted raw rq_p1 credential literal`);
    assert.match(credValueRes.stderr, /secret-like literal/i);
  }
});

test("inspect-plan.mjs handles exit 0, exit 2, exit 1 and enforces security guards", (t) => {
  const tmpDir = makeTempDir(t, "rq-plan-");
  const configPath = path.join(REPO_ROOT, "config", "release.deployment.json");

  // 1. No-op plan -> exit 0
  const noopPlanPath = writeJson(path.join(tmpDir, "noop.plan.json"), {
    resource_changes: [
      {
        address: "aws_db_instance.primary",
        type: "aws_db_instance",
        change: { actions: ["no-op"], before: {}, after: {} }
      }
    ]
  });
  const noopRes = runTool("tools/release/inspect-plan.mjs", [
    "--config",
    configPath,
    "--plan-json",
    noopPlanPath,
    "--json"
  ]);
  assert.equal(noopRes.status, 0, `Expected exit 0 for no-op plan, got ${noopRes.status}: ${noopRes.stderr}`);
  const noopDoc = JSON.parse(noopRes.stdout);
  assert.equal(noopDoc.detailed_exitcode, 0);
  assert.equal(noopDoc.has_changes, false);

  // 2. Clean create/update plan -> exit 2
  const cleanChangePath = writeJson(path.join(tmpDir, "change.plan.json"), {
    resource_changes: [
      {
        address: "aws_db_instance.primary",
        type: "aws_db_instance",
        change: {
          actions: ["update"],
          before: { publicly_accessible: false },
          after: {
            publicly_accessible: false,
            tags_all: {
              Application: "relayquill",
              Environment: "production",
              ManagedBy: "terraform"
            }
          }
        }
      }
    ]
  });
  const outRecordPath = path.join(tmpDir, "plan-record.json");
  const changeRes = runTool("tools/release/inspect-plan.mjs", [
    "--config",
    configPath,
    "--plan-json",
    cleanChangePath,
    "--out",
    outRecordPath,
    "--json"
  ]);
  assert.equal(changeRes.status, 2, `Expected exit 2 for valid change plan, got ${changeRes.status}: ${changeRes.stderr}`);
  const changeDoc = JSON.parse(changeRes.stdout);
  assert.equal(changeDoc.detailed_exitcode, 2);
  assert.equal(changeDoc.has_changes, true);
  assert.ok(fs.existsSync(outRecordPath));

  // 3. Explicit --detailed-exitcode 1 -> exit 1
  const errPlanRes = runTool("tools/release/inspect-plan.mjs", [
    "--config",
    configPath,
    "--plan-json",
    noopPlanPath,
    "--detailed-exitcode",
    "1"
  ]);
  assert.equal(errPlanRes.status, 1);

  // 4. Security rejections: public DB, 0.0.0.0/0 on 5432, secret resource, unexpected DB deletion
  const insecurePlans = [
    {
      name: "public_db",
      plan: {
        resource_changes: [
          {
            address: "aws_db_instance.exposed",
            type: "aws_db_instance",
            change: {
              actions: ["create"],
              before: null,
              after: {
                publicly_accessible: true,
                tags_all: { Application: "relayquill", Environment: "production", ManagedBy: "terraform" }
              }
            }
          }
        ]
      },
      pattern: /Public database prohibited/i
    },
    {
      name: "public_sg_5432",
      plan: {
        resource_changes: [
          {
            address: "aws_security_group_rule.pg",
            type: "aws_security_group_rule",
            change: {
              actions: ["create"],
              before: null,
              after: {
                type: "ingress",
                from_port: 5432,
                to_port: 5432,
                cidr_blocks: ["0.0.0.0/0"],
                tags_all: { Application: "relayquill", Environment: "production", ManagedBy: "terraform" }
              }
            }
          }
        ]
      },
      pattern: /Public 0\.0\.0\.0\/0.*5432/i
    },
    {
      name: "forbidden_random_password",
      plan: {
        resource_changes: [
          {
            address: "random_password.db",
            type: "random_password",
            change: { actions: ["create"], before: null, after: {} }
          }
        ]
      },
      pattern: /random_password/i
    },
    {
      name: "protected_db_delete",
      plan: {
        resource_changes: [
          {
            address: "aws_db_instance.primary",
            type: "aws_db_instance",
            change: { actions: ["delete"], before: {}, after: null }
          }
        ]
      },
      pattern: /Unexpected deletion of protected stateful resource/i
    }
  ];

  for (const item of insecurePlans) {
    const p = writeJson(path.join(tmpDir, `${item.name}.json`), item.plan);
    const r = runTool("tools/release/inspect-plan.mjs", [
      "--config",
      configPath,
      "--plan-json",
      p
    ]);
    assert.equal(r.status, 1, `Expected security rejection exit 1 for ${item.name}`);
    assert.match(r.stderr, item.pattern, `Unexpected message for ${item.name}: ${r.stderr}`);
  }
});

test("validate-rendered.mjs passes on repo kubernetes manifests and rejects :latest, root, and Secret violations", (t) => {
  for (const overlay of ["base", "selfhosted", "eks"]) {
    const res = runTool("tools/cluster/validate-rendered.mjs", ["--overlay", overlay, "--json"]);
    assert.equal(res.status, 0, `validate-rendered failed on ${overlay}: ${res.stderr}`);
    const parsed = JSON.parse(res.stdout);
    assert.equal(parsed.ok, true, `Expected ok=true on ${overlay}`);
    assert.deepEqual(parsed.violations, []);
  }

  const tmpDir = makeTempDir(t, "rq-k8s-bad-");

  const badLatestYaml = path.join(tmpDir, "bad-latest.yaml");
  fs.writeFileSync(
    badLatestYaml,
    `apiVersion: apps/v1
kind: Deployment
metadata:
  name: bad-api
  namespace: relayquill-app
spec:
  template:
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 10001
        seccompProfile:
          type: RuntimeDefault
      containers:
        - name: api
          image: 000000000000.dkr.ecr.us-east-1.amazonaws.com/relayquill/services:latest
          securityContext:
            runAsNonRoot: true
            runAsUser: 10001
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop: ["ALL"]
`,
    "utf8"
  );
  const latestRes = runTool("tools/cluster/validate-rendered.mjs", ["--rendered", badLatestYaml]);
  assert.equal(latestRes.status, 1);
  assert.match(latestRes.stderr, /:latest/i);

  const badRootYaml = path.join(tmpDir, "bad-root.yaml");
  fs.writeFileSync(
    badRootYaml,
    `apiVersion: apps/v1
kind: Deployment
metadata:
  name: bad-root
  namespace: relayquill-app
spec:
  template:
    spec:
      containers:
        - name: sender
          image: 000000000000.dkr.ecr.us-east-1.amazonaws.com/relayquill/services@sha256:0000000000000000000000000000000000000000000000000000000000000001
          securityContext:
            runAsNonRoot: false
            runAsUser: 0
            allowPrivilegeEscalation: true
            readOnlyRootFilesystem: false
`,
    "utf8"
  );
  const rootRes = runTool("tools/cluster/validate-rendered.mjs", ["--rendered", badRootYaml]);
  assert.equal(rootRes.status, 1);
  assert.match(rootRes.stderr, /runAsNonRoot=true/i);
  assert.match(rootRes.stderr, /readOnlyRootFilesystem=true/i);
  assert.match(rootRes.stderr, /capabilities\.drop/i);

  const badSecretYaml = path.join(tmpDir, "bad-secret.yaml");
  fs.writeFileSync(
    badSecretYaml,
    `apiVersion: v1
kind: Secret
metadata:
  name: leaked-secret
  namespace: relayquill-app
stringData:
  db_token: topsecret123
`,
    "utf8"
  );
  const secretRes = runTool("tools/cluster/validate-rendered.mjs", ["--rendered", badSecretYaml]);
  assert.equal(secretRes.status, 1);
  assert.match(secretRes.stderr, /Secret manifest/i);
});

test("isolated-restore-audit.mjs classifies A/B/C divergence and verifies authority containment", (t) => {
  const tmpDir = makeTempDir(t, "rq-restore-");

  const validBundle = {
    restore_point: "2026-11-20T07:00:00.000000Z",
    rpo_lag_seconds: 120,
    authorities: {
      source_rq_database: "pg-source-rq",
      restored_rq_database: "pg-restored-isolated-rq",
      current_rc_database: "pg-live-rc",
      current_pi_database: "pg-live-pi",
      restored_colocated_rc_database: "pg-restored-stale-rc",
      restored_colocated_pi_database: "pg-restored-stale-pi",
      restored_publicly_accessible: false,
      restored_tls_mode: "verify_full"
    },
    old_writer_containment: {
      active_old_worker_processes: 0,
      autoscaling_disabled: true,
      active_old_db_sessions: 0,
      active_old_broker_connections: 0,
      network_contained: true
    },
    quarantine_state: {
      mode: "recovery_quarantine",
      allow_event_admission: false,
      allow_publication: false,
      allow_fanout: false,
      allow_send: false,
      allow_endpoint_verification: false,
      source_control_epoch: "00000000-0000-4000-8000-0000000000e1",
      target_control_epoch: "00000000-0000-4000-8000-0000000000e2",
      old_epoch_credentials_denied: true
    },
    restored_rq_events: [
      {
        event_id: "evt-A",
        delivery_state: "acknowledged",
        original_facts_sha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      },
      {
        event_id: "evt-B-match",
        delivery_state: "pending",
        attempt_state: "prepared",
        attempt_id: "att-b-1",
        send_started_at: null,
        original_facts_sha256: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
      },
      {
        event_id: "evt-B-conflict",
        delivery_state: "pending",
        attempt_state: "send_started",
        attempt_id: "att-b-2",
        send_started_at: "2026-11-20T06:59:00.000000Z",
        original_facts_sha256: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
      }
    ],
    live_rc_anchors: [
      {
        event_id: "evt-A",
        committed: true,
        original_facts_sha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        mutation_count: 1
      },
      {
        event_id: "evt-B-match",
        committed: true,
        original_facts_sha256: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        receipt_id: "rcpt-b-1",
        mutation_count: 1
      },
      {
        event_id: "evt-B-conflict",
        committed: true,
        original_facts_sha256: "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
        mutation_count: 1
      }
    ],
    external_accepted_receipts: [
      {
        event_id: "evt-C-missing",
        accepted_at: "2026-11-20T07:01:00.000000Z",
        receipt_id: "rcpt-c-1",
        retained_original_payload_verified: true
      }
    ],
    broker_notifications: [
      { event_id: "evt-C-missing", stream_seq: "42" }
    ]
  };

  const bundlePath = writeJson(path.join(tmpDir, "bundle.json"), validBundle);
  const res = runTool("tools/recovery/isolated-restore-audit.mjs", ["--input", bundlePath, "--json"]);
  assert.equal(res.status, 0, `isolated-restore-audit failed: ${res.stderr}`);
  const report = JSON.parse(res.stdout);
  assert.equal(report.ok, true);
  assert.equal(report.counts.class_A_consistent, 1);
  assert.equal(report.counts.class_B_receiver_ahead, 2);
  assert.equal(report.counts.class_C_missing_accepted, 1);
  assert.equal(report.counts.orphaned_broker_notifications, 1);
  assert.equal(report.classifications.attempt_dispositions.length, 2);

  // --fail-on-holds must exit 1 because of Class B conflict and Class C missing
  const holdRes = runTool("tools/recovery/isolated-restore-audit.mjs", [
    "--input",
    bundlePath,
    "--fail-on-holds"
  ]);
  assert.equal(holdRes.status, 1);

  // Co-located receiver repointing to restored DB must fail boundary isolation
  const badColocated = structuredClone(validBundle);
  badColocated.authorities.current_rc_database = "pg-restored-stale-rc";
  const badPath = writeJson(path.join(tmpDir, "bad-colocated.json"), badColocated);
  const colocatedRes = runTool("tools/recovery/isolated-restore-audit.mjs", ["--input", badPath]);
  assert.equal(colocatedRes.status, 1);
  assert.match(colocatedRes.stderr, /Independent receiver \(rc\) authority/i);
});

test("repair-runner.mjs enforces distinct reviewer, send_started rejection, and idempotent replay", (t) => {
  const tmpDir = makeTempDir(t, "rq-repair-");
  const ledgerPath = path.join(tmpDir, "ledger.json");

  const validRequest = {
    action_id: "00000000-0000-4000-8000-000000000701",
    operation_id: "00000000-0000-4000-8000-000000000700",
    kind: "reconcile_reservations",
    requester_reference: "operator-alice",
    expected_target_version: "5",
    typed_plan: {
      expected_stored_value: "10",
      derived_obligation_value: "4",
      proposed_value: "4",
      capacity_bound: "16",
      gates_held: true
    },
    review: {
      decision: "approve",
      reviewer_reference: "operator-bob",
      authority_evidence_digest: "e".repeat(64)
    }
  };
  const reqPath = writeJson(path.join(tmpDir, "req.json"), validRequest);

  const firstRes = runTool("tools/recovery/repair-runner.mjs", [
    "--request",
    reqPath,
    "--ledger",
    ledgerPath,
    "--json"
  ]);
  assert.equal(firstRes.status, 0, `repair-runner failed: ${firstRes.stderr}`);
  const firstDoc = JSON.parse(firstRes.stdout);
  assert.equal(firstDoc.idempotent_replay, false);
  assert.equal(firstDoc.result_version, "6");

  // Repeat identical action_id -> idempotent replay
  const secondRes = runTool("tools/recovery/repair-runner.mjs", [
    "--request",
    reqPath,
    "--ledger",
    ledgerPath,
    "--json"
  ]);
  assert.equal(secondRes.status, 0);
  assert.equal(JSON.parse(secondRes.stdout).idempotent_replay, true);

  // Self-approval -> exit 3
  const selfReview = structuredClone(validRequest);
  selfReview.action_id = "00000000-0000-4000-8000-000000000702";
  selfReview.review.reviewer_reference = "operator-alice";
  const selfPath = writeJson(path.join(tmpDir, "self.json"), selfReview);
  const selfRes = runTool("tools/recovery/repair-runner.mjs", ["--request", selfPath]);
  assert.equal(selfRes.status, 3);
  assert.match(selfRes.stderr, /distinct requester and reviewer/i);

  // retire_stale_claim on send_started attempt -> exit 4
  const badRetirePath = writeJson(path.join(tmpDir, "retire-started.json"), {
    action_id: "00000000-0000-4000-8000-000000000703",
    operation_id: "00000000-0000-4000-8000-000000000700",
    kind: "retire_stale_claim",
    requester_reference: "operator-alice",
    typed_plan: {
      claim_kind: "prepared_attempt",
      send_started_at: "2026-11-20T07:05:00.000000Z"
    },
    review: {
      decision: "approve",
      reviewer_reference: "operator-bob",
      authority_evidence_digest: "f".repeat(64)
    }
  });
  const retireRes = runTool("tools/recovery/repair-runner.mjs", ["--request", badRetirePath]);
  assert.equal(retireRes.status, 4);
});

test("cost-model.mjs emits dated self-hosted and cloud worksheets in JSON and CSV", (t) => {
  const tmpDir = makeTempDir(t, "rq-cost-");
  const csvOut = path.join(tmpDir, "cost.csv");

  const jsonRes = runTool("tools/load/cost-model.mjs", [
    "--price-date",
    "2026-02-01",
    "--region",
    "eu-west-1",
    "--json"
  ]);
  assert.equal(jsonRes.status, 0, `cost-model failed: ${jsonRes.stderr}`);
  const worksheet = JSON.parse(jsonRes.stdout);
  assert.equal(worksheet.ok, true);
  assert.equal(worksheet.scenarios_kept_independent, true);
  assert.equal(worksheet.price_date, "2026-02-01");
  const scenarioNames = worksheet.scenarios.map((s) => s.scenario_name).sort();
  assert.deepEqual(scenarioNames, ["cloud_ec2", "cloud_eks", "self_hosted"]);
  for (const s of worksheet.scenarios) {
    assert.ok(s.monthly_steady_total > 0);
    assert.ok(s.one_off_experiment_total > 0);
  }

  const csvRes = runTool("tools/load/cost-model.mjs", [
    "--profile",
    "self_hosted",
    "--format",
    "csv",
    "--out",
    csvOut
  ]);
  assert.equal(csvRes.status, 0);
  const csvText = fs.readFileSync(csvOut, "utf8");
  assert.match(csvText, /^scenario_name,profile_kind,resource,region,unit,quantity,unit_price,currency,price_date,source_url,subtotal/);
  assert.match(csvText, /self_hosted,self_hosted,/);
});

test("diagnose.mjs pinpoints first failing causal boundary and blocks secrets", (t) => {
  const tmpDir = makeTempDir(t, "rq-diag-");

  const pubFailSnap = writeJson(path.join(tmpDir, "pub-fail.json"), {
    incident_ref: "inc-pub-1",
    installation: { mode: "normal", allow_event_admission: true, allow_publication: true, allow_fanout: true, allow_send: true },
    admission: { accepted: true, content_integrity_ok: true },
    publication: { state: "pending", observation_state: "not_observed", current_publication_generation: "2", last_safe_error_code: "BROKER_UNREACHABLE" },
    fanout: { state: "pending" },
    delivery: { state: "pending" }
  });
  const pubRes = runTool("tools/operations/diagnose.mjs", [
    "--input",
    pubFailSnap,
    "--fail-on-finding",
    "--json"
  ]);
  assert.equal(pubRes.status, 1);
  const pubDiag = JSON.parse(pubRes.stdout);
  assert.equal(pubDiag.first_failing_boundary.boundary, "outbox_publication");
  assert.equal(pubDiag.first_failing_boundary.reason_code, "BROKER_UNREACHABLE");
  const fanAssessment = pubDiag.boundary_assessments.find((b) => b.boundary === "ordered_fanout");
  assert.equal(fanAssessment.status, "blocked_upstream");

  const egressFailSnap = writeJson(path.join(tmpDir, "egress-fail.json"), {
    installation: { mode: "normal", allow_event_admission: true, allow_publication: true, allow_fanout: true, allow_send: true },
    admission: { accepted: true, content_integrity_ok: true },
    publication: { state: "published", observation_state: "observed" },
    fanout: { state: "completed" },
    delivery: { state: "retry_wait" },
    network_decision: { decision: "denied", ip_family: "ipv4", reason_code: "PRIVATE_OR_RESERVED_ADDRESS" }
  });
  const egressRes = runTool("tools/operations/diagnose.mjs", ["--input", egressFailSnap, "--json"]);
  assert.equal(egressRes.status, 0);
  const egressDiag = JSON.parse(egressRes.stdout);
  assert.equal(egressDiag.first_failing_boundary.boundary, "outbound_egress");
  assert.equal(egressDiag.first_failing_boundary.reason_code, "PRIVATE_OR_RESERVED_ADDRESS");

  const secretSnap = writeJson(path.join(tmpDir, "secret-snap.json"), {
    admission: { accepted: true, signing_key: "topsecret" }
  });
  const secretDiagRes = runTool("tools/operations/diagnose.mjs", ["--input", secretSnap]);
  assert.equal(secretDiagRes.status, 1);
  assert.match(secretDiagRes.stderr, /raw secrets/i);
});

test("benchmark.mjs measures synthetic and HTTP load, event loop delay, and separate backlog drain", async (t) => {
  const tmpDir = makeTempDir(t, "rq-bench-");

  const benchRes = runTool("tools/load/benchmark.mjs", [
    "--mode",
    "synthetic",
    "--duration-seconds",
    "1",
    "--max-requests",
    "40",
    "--concurrency",
    "4",
    "--initial-backlog",
    "1200",
    "--drain-rate-per-sec",
    "100",
    "--incoming-rate-per-sec",
    "60",
    "--json"
  ]);
  assert.equal(benchRes.status, 0, `benchmark failed: ${benchRes.stderr}`);
  const report = JSON.parse(benchRes.stdout);
  assert.equal(report.ok, true);
  assert.equal(report.workload_rates.offered_count, 40);
  assert.equal(report.latency_distribution_ms.count, 40);
  assert.ok(report.latency_distribution_ms.p99_ms >= report.latency_distribution_ms.p50_ms);
  assert.equal(typeof report.event_loop_delay_ms.p99, "number");
  assert.equal(report.backlog_drain.measurement_separated_from_target_rate, true);
  assert.equal(report.backlog_drain.drain_status, "draining");
  assert.equal(report.backlog_drain.estimated_drain_seconds, 30);

  // Also verify HTTP benchmark against a local ephemeral HTTP server
  const server = http.createServer((_req, res) => {
    res.writeHead(201, { "content-type": "application/json" });
    res.end("{\"ok\":true}");
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const addr = server.address();
  const outPath = path.join(tmpDir, "http-bench.json");

  const httpRes = await runToolAsync("tools/load/benchmark.mjs", [
    "--mode",
    "http",
    "--target-url",
    `http://127.0.0.1:${addr.port}/events`,
    "--duration-seconds",
    "1",
    "--max-requests",
    "12",
    "--concurrency",
    "2",
    "--out",
    outPath,
    "--json"
  ]);
  assert.equal(httpRes.status, 0, `http benchmark failed: ${httpRes.stderr}`);
  const httpReport = JSON.parse(httpRes.stdout);
  assert.equal(httpReport.workload_rates.accepted_count, 12);
  assert.ok(fs.existsSync(outPath));
});

test("failure-run.mjs exposes all 15 scenarios and runs synthetic/dry-run with cleanup", (t) => {
  const tmpDir = makeTempDir(t, "rq-failure-");

  const listRes = runTool("tools/cluster/failure-run.mjs", ["--list", "--json"]);
  assert.equal(listRes.status, 0);
  const listed = JSON.parse(listRes.stdout);
  assert.equal(listed.scenario_count, 15);

  const runRes = runTool("tools/cluster/failure-run.mjs", [
    "--scenario",
    "paused-stale-sender-resumes",
    "--dry-run",
    "--records-dir",
    tmpDir,
    "--json"
  ]);
  assert.equal(runRes.status, 0, `failure-run failed: ${runRes.stderr}`);
  const runDoc = JSON.parse(runRes.stdout);
  assert.equal(runDoc.ok, true);
  assert.equal(runDoc.execution_mode, "dry-run");
  assert.equal(runDoc.cleanup_verified, true);
  assert.equal(runDoc.cleanup.reservations_conserved, true);

  const nonSynthetic = runTool("tools/cluster/failure-run.mjs", [
    "--scenario",
    "relay-loses-puback",
    "--project",
    "prod-customer-billing",
    "--records-dir",
    tmpDir
  ]);
  assert.equal(nonSynthetic.status, 1);
  assert.match(nonSynthetic.stderr, /non-synthetic project/i);
});
