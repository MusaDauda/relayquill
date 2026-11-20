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

const HELP_TEXT = `Usage: node tools/release/teardown-inventory.mjs --config <profile.json> [options]

Inventory deployment-owned resources before/after teardown, verify drain prerequisites,
account for retained billable artifacts, and block deletion of shared or independent authorities.

Options:
  --config <path>       Deployment profile JSON (required)
  --inventory <path>    Observed resource inventory JSON
  --stage <stage>       Evaluation stage: pre-teardown | post-teardown (default: pre-teardown)
  --out <path>          Write sanitized teardown inventory JSON
  --root <dir>          Repository root directory
  --json                Emit structured JSON output
  -h, --help            Show help without reading secrets or mutating state
`;

const PROTECTED_SHARED_TYPES = new Set([
  "aws_route53_zone_shared",
  "terraform_state_bucket",
  "terraform_lock_table",
  "independent_receiver_db",
  "independent_provider_ingress_db",
  "shared_ecr_repository"
]);

const RETAINED_COST_TYPES = new Set([
  "aws_db_snapshot",
  "aws_ebs_snapshot",
  "aws_cloudwatch_log_group",
  "aws_secretsmanager_secret",
  "aws_kms_key",
  "aws_ecr_repository",
  "pvc_retained_volume",
  "pg_backup_archive"
]);

const COMPUTE_TYPES = new Set([
  "aws_instance",
  "aws_lb",
  "aws_nat_gateway",
  "aws_eks_node_group",
  "aws_eks_cluster",
  "k8s_deployment",
  "compose_service"
]);

function classifyResource(resource, deploymentName) {
  const type = String(resource.type ?? "unknown");
  const id = String(resource.id ?? resource.name ?? "unnamed");
  const tags = resource.tags ?? {};
  const belongsToDeployment =
    resource.deployment_name === deploymentName ||
    tags.Deployment === deploymentName ||
    tags.deployment === deploymentName ||
    id.startsWith(deploymentName);

  if (
    resource.shared === true ||
    resource.authority === "rc" ||
    resource.authority === "pi" ||
    PROTECTED_SHARED_TYPES.has(type) ||
    !belongsToDeployment
  ) {
    return "protected_shared_do_not_delete";
  }
  if (resource.retain === true || RETAINED_COST_TYPES.has(type)) {
    return "retained_with_cost";
  }
  if (resource.requires_drain === true || type === "active_gate" || type === "unknown_sender_attempts") {
    return "requires_drain_first";
  }
  if (COMPUTE_TYPES.has(type) || resource.category === "compute") {
    return "safe_to_remove_compute";
  }
  return "retained_with_cost";
}

export function buildTeardownInventory(options) {
  const repoRoot = path.resolve(options.rootDir ?? DEFAULT_ROOT);
  const profileRes = validateDeploymentProfileFile(options.configPath, { repoRoot });
  if (!profileRes.ok) {
    throw new CliError(`Invalid profile:\n- ${profileRes.errors.join("\n- ")}`, 1);
  }
  const profile = profileRes.profile;
  const stage = options.stage ?? "pre-teardown";
  const input = options.inventoryPath
    ? readStrictJsonFile(options.inventoryPath)
    : { resources: [], gates_closed: false, unknown_externally_started_attempts: 0 };

  const resources = Array.isArray(input) ? input : Array.isArray(input.resources) ? input.resources : [];
  const buckets = {
    requires_drain_first: [],
    safe_to_remove_compute: [],
    retained_with_cost: [],
    protected_shared_do_not_delete: []
  };

  const blockers = [];
  for (const res of resources) {
    const cls = classifyResource(res, profile.deployment_name);
    const entry = {
      id: String(res.id ?? res.name ?? "unnamed"),
      type: String(res.type ?? "unknown"),
      authority: res.authority ?? "rq",
      marked_for_delete: Boolean(res.marked_for_delete),
      monthly_cost_note: res.monthly_cost_note ?? null
    };
    buckets[cls].push(entry);

    if (cls === "protected_shared_do_not_delete" && entry.marked_for_delete) {
      blockers.push(
        `Refusing deletion of shared, unrelated, or independent resource "${entry.id}" (${entry.type})`
      );
    }
  }

  const gatesClosed = input.gates_closed === true;
  const unknownAttempts = Number(input.unknown_externally_started_attempts ?? 0);

  if (stage === "pre-teardown") {
    if (!gatesClosed) {
      blockers.push("Admission and send gates must be closed before teardown");
    }
    if (buckets.requires_drain_first.length > 0) {
      blockers.push(
        `${buckets.requires_drain_first.length} resource(s) require drain/inventory completion before teardown`
      );
    }
  }

  if (stage === "post-teardown") {
    if (buckets.safe_to_remove_compute.length > 0) {
      blockers.push(
        `Post-teardown verification incomplete: ${buckets.safe_to_remove_compute.length} compute resource(s) still present`
      );
    }
  }

  const report = redactSensitiveData({
    ok: blockers.length === 0,
    stage,
    deployment_name: profile.deployment_name,
    deployment_mode: profileRes.deploymentMode,
    gates_closed: gatesClosed,
    unknown_externally_started_attempts: unknownAttempts,
    teardown_complete: stage === "post-teardown" && blockers.length === 0,
    counts: {
      requires_drain_first: buckets.requires_drain_first.length,
      safe_to_remove_compute: buckets.safe_to_remove_compute.length,
      retained_with_cost: buckets.retained_with_cost.length,
      protected_shared_do_not_delete: buckets.protected_shared_do_not_delete.length
    },
    buckets,
    blockers
  });

  if (options.outPath) {
    const resolvedOut = path.resolve(options.outPath);
    fs.mkdirSync(path.dirname(resolvedOut), { recursive: true });
    fs.writeFileSync(resolvedOut, `${JSON.stringify(report, null, 2)}\n`, "utf8");
  }

  return report;
}

runCliMain(import.meta.url, HELP_TEXT, (argv) => {
  const parsed = parseCliFlags(argv, {
    options: {
      "--config": { type: "string", required: true },
      "--inventory": { type: "string" },
      "--stage": { type: "string", enum: ["pre-teardown", "post-teardown"], default: "pre-teardown" },
      "--out": { type: "string" },
      "--root": { type: "string" },
      "--json": { type: "boolean", default: false }
    }
  });
  if (parsed.help) {
    return { help: true };
  }
  const report = buildTeardownInventory({
    configPath: parsed.options["--config"],
    inventoryPath: parsed.options["--inventory"],
    stage: parsed.options["--stage"],
    outPath: parsed.options["--out"],
    rootDir: parsed.options["--root"]
  });
  const exitCode = report.ok ? 0 : 1;
  if (parsed.options["--json"]) {
    return { exitCode, output: report };
  }
  return {
    exitCode,
    output: `[teardown-inventory] stage=${report.stage} ok=${report.ok} compute=${report.counts.safe_to_remove_compute} retained=${report.counts.retained_with_cost} protected=${report.counts.protected_shared_do_not_delete} blockers=${report.blockers.length}`
  };
});
