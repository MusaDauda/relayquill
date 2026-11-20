import { spawnSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  CliError,
  canonicalizeJson,
  hasForbiddenRawSecretValue,
  isSensitiveFieldName,
  parseCliFlags,
  readStrictJsonFile,
  redactSensitiveData,
  runCliMain,
  sha256Hex
} from "./lib/cli.mjs";
import { validateDeploymentProfileFile } from "./lib/schema.mjs";

const DEFAULT_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");

const HELP_TEXT = `Usage: node tools/release/inspect-plan.mjs --config <profile.json> [options]

Inspect Terraform saved plan (-detailed-exitcode 0/1/2) or self-hosted diff in memory,
bind plan/source/lock/profile digests, and enforce security and destruction guards.

Exit Codes:
  0  No changes and all security/policy guards passed
  1  Error, invalid arguments, Terraform failure, or security/policy guard failure
  2  Reviewable change plan passed all security/policy guards

Options:
  --config <path>              Path to deployment profile JSON (required)
  --root <dir>                 Repository root directory
  --plan-json <path>           Pre-captured Terraform show -json output (offline mode)
  --plan-binary <path>         Saved Terraform plan binary path for digest binding
  --lock-file <path>           Override .terraform.lock.hcl path for digest binding
  --var-file <path>            Terraform -var-file path when running live terraform plan
  --save-plan <path>           Saved plan output path when running terraform plan
  --terraform-bin <path>       Terraform binary (or .mjs test shim)
  --detailed-exitcode <0|1|2>  Explicit terraform plan exit code when using --plan-json
  --out <path>                 Write nonsecret operation/plan binding record JSON
  --allow-replacement          Allow stateful resource replacement
  --allow-deletion             Allow stateful resource deletion
  --fail-on-replace            Fail on any resource replacement
  --json                       Emit structured JSON output
  -h, --help                   Show help without reading secrets or mutating state
`;

const FORBIDDEN_SECRET_RESOURCES = new Set([
  "random_password",
  "tls_private_key",
  "aws_secretsmanager_secret_version"
]);

const PROTECTED_STATEFUL_TYPES = new Set([
  "aws_db_instance",
  "aws_kms_key",
  "aws_ebs_volume",
  "aws_secretsmanager_secret",
  "aws_route53_zone",
  "aws_vpc",
  "aws_subnet"
]);

const BILL_DRIVER_TYPES = new Set([
  "aws_db_instance",
  "aws_nat_gateway",
  "aws_lb",
  "aws_instance",
  "aws_ebs_volume",
  "aws_vpc_endpoint",
  "aws_secretsmanager_secret",
  "aws_kms_key",
  "aws_eks_cluster"
]);

const PROTECTED_INTERNAL_PORTS = [5432, 4222, 6222, 8222, 22];

function runToolExecutable(binPath, args, cwd) {
  if (binPath.endsWith(".mjs") || binPath.endsWith(".js")) {
    return spawnSync(process.execPath, [binPath, ...args], {
      cwd,
      encoding: "utf8",
      shell: false,
      maxBuffer: 64 * 1024 * 1024
    });
  }
  return spawnSync(binPath, args, {
    cwd,
    encoding: "utf8",
    shell: false,
    maxBuffer: 64 * 1024 * 1024
  });
}

function readGitMetadata(repoRoot) {
  const head = spawnSync("git", ["rev-parse", "HEAD"], { cwd: repoRoot, encoding: "utf8", shell: false });
  const status = spawnSync("git", ["status", "--porcelain"], { cwd: repoRoot, encoding: "utf8", shell: false });
  return {
    source_commit: head.status === 0 ? head.stdout.trim() : "unknown",
    source_dirty: status.status === 0 ? status.stdout.trim().length > 0 : null
  };
}

function portRangeOverlapsProtected(fromPort, toPort) {
  const from = typeof fromPort === "number" ? fromPort : -1;
  const to = typeof toPort === "number" ? toPort : -1;
  if (from === 0 && to === 0) {
    return true;
  }
  if (from === -1 || to === -1) {
    return true;
  }
  return PROTECTED_INTERNAL_PORTS.some((p) => p >= from && p <= to);
}

function scanPlanObjectForSecrets(value, jsonPath, violations) {
  if (typeof value === "string") {
    if (hasForbiddenRawSecretValue(value)) {
      violations.push(`Secret literal present in Terraform plan at ${jsonPath}`);
    }
    return;
  }
  if (Array.isArray(value)) {
    for (let i = 0; i < value.length; i += 1) {
      scanPlanObjectForSecrets(value[i], `${jsonPath}[${i}]`, violations);
    }
    return;
  }
  if (value && typeof value === "object") {
    for (const [key, nested] of Object.entries(value)) {
      if (isSensitiveFieldName(key) && typeof nested === "string" && nested.length > 0) {
        violations.push(`Non-empty secret attribute "${key}" exposed in Terraform plan at ${jsonPath}.${key}`);
      } else {
        scanPlanObjectForSecrets(nested, `${jsonPath}.${key}`, violations);
      }
    }
  }
}

function classifyChangeActions(actions) {
  if (!Array.isArray(actions) || actions.length === 0) {
    return "no-op";
  }
  const joined = actions.join(",");
  if (joined === "no-op" || joined === "read") {
    return "no-op";
  }
  if (joined === "create") {
    return "create";
  }
  if (joined === "update") {
    return "update";
  }
  if (joined === "delete") {
    return "delete";
  }
  if (
    (actions.includes("create") && actions.includes("delete")) ||
    joined === "replace"
  ) {
    return "replace";
  }
  return "update";
}

function hasPublicCidr(list) {
  return Array.isArray(list) && list.some((c) => c === "0.0.0.0/0" || c === "::/0");
}

function validateSecurityGroupChanges(type, after, address, violations) {
  if (!after || typeof after !== "object") {
    return;
  }
  if (type === "aws_security_group" && Array.isArray(after.ingress)) {
    for (const rule of after.ingress) {
      const publicV4 = hasPublicCidr(rule?.cidr_blocks);
      const publicV6 = hasPublicCidr(rule?.ipv6_cidr_blocks);
      if ((publicV4 || publicV6) && portRangeOverlapsProtected(rule?.from_port, rule?.to_port)) {
        violations.push(
          `Public 0.0.0.0/0 or ::/0 ingress on protected port (${rule?.from_port}-${rule?.to_port}) in ${address}`
        );
      }
    }
  }
  if (type === "aws_security_group_rule" && after.type === "ingress") {
    const publicV4 = hasPublicCidr(after.cidr_blocks);
    const publicV6 = hasPublicCidr(after.ipv6_cidr_blocks);
    if ((publicV4 || publicV6) && portRangeOverlapsProtected(after.from_port, after.to_port)) {
      violations.push(
        `Public 0.0.0.0/0 or ::/0 ingress rule on protected port (${after.from_port}-${after.to_port}) in ${address}`
      );
    }
  }
  if (type === "aws_vpc_security_group_ingress_rule") {
    const isPublic = after.cidr_ipv4 === "0.0.0.0/0" || after.cidr_ipv6 === "::/0";
    if (isPublic && portRangeOverlapsProtected(after.from_port, after.to_port)) {
      violations.push(
        `Public 0.0.0.0/0 or ::/0 VPC ingress rule on protected port (${after.from_port}-${after.to_port}) in ${address}`
      );
    }
  }
}

export function analyzePlanDocument(planDoc, profile, options = {}) {
  const resourceChanges = Array.isArray(planDoc?.resource_changes) ? planDoc.resource_changes : [];
  const violations = [];

  const summary = {
    creates: [],
    updates: [],
    replacements: [],
    deletions: [],
    no_op_count: 0,
    public_exposure: [],
    identity_changes: [],
    expected_bill_drivers: []
  };

  const requiredTagKeys = Object.keys(profile?.resource_tags ?? {});

  for (const rc of resourceChanges) {
    const address = String(rc?.address ?? "unknown");
    const type = String(rc?.type ?? "unknown");
    const actions = rc?.change?.actions ?? ["no-op"];
    const actionKind = classifyChangeActions(actions);
    const after = rc?.change?.after ?? null;
    const before = rc?.change?.before ?? null;

    if (FORBIDDEN_SECRET_RESOURCES.has(type)) {
      violations.push(`Forbidden secret-generating Terraform resource type "${type}" at ${address}`);
    }

    scanPlanObjectForSecrets(before, `${address}.before`, violations);
    scanPlanObjectForSecrets(after, `${address}.after`, violations);

    if (actionKind === "no-op") {
      summary.no_op_count += 1;
      continue;
    }

    if (actionKind === "create") {
      summary.creates.push(address);
    } else if (actionKind === "update") {
      summary.updates.push(address);
    } else if (actionKind === "replace") {
      summary.replacements.push(address);
      if (options.failOnReplace) {
        violations.push(`Resource replacement disallowed by --fail-on-replace: ${address}`);
      } else if (PROTECTED_STATEFUL_TYPES.has(type) && !options.allowReplacement) {
        violations.push(`Unexpected replacement of protected stateful resource ${address} (${type})`);
      }
    } else if (actionKind === "delete") {
      summary.deletions.push(address);
      if (PROTECTED_STATEFUL_TYPES.has(type) && !options.allowDeletion) {
        violations.push(`Unexpected deletion of protected stateful resource ${address} (${type})`);
      }
    }

    if (type === "aws_db_instance" && after?.publicly_accessible === true) {
      violations.push(`Public database prohibited: ${address} sets publicly_accessible=true`);
    }

    if (
      type === "aws_instance" &&
      (address.includes("broker") || String(after?.tags?.Role ?? "").toLowerCase() === "broker") &&
      after?.associate_public_ip_address === true
    ) {
      violations.push(`Public broker host prohibited: ${address} sets associate_public_ip_address=true`);
    }

    validateSecurityGroupChanges(type, after, address, violations);

    if (
      actionKind !== "delete" &&
      after &&
      typeof after === "object" &&
      requiredTagKeys.length > 0 &&
      type.startsWith("aws_")
    ) {
      const concreteTags =
        after.tags_all && typeof after.tags_all === "object"
          ? after.tags_all
          : after.tags && typeof after.tags === "object"
            ? after.tags
            : null;
      if (concreteTags !== null) {
        const afterUnknownTags = rc?.change?.after_unknown?.tags_all === true || rc?.change?.after_unknown?.tags === true;
        if (!afterUnknownTags) {
          for (const reqKey of requiredTagKeys) {
            if (!Object.prototype.hasOwnProperty.call(concreteTags, reqKey)) {
              violations.push(`Missing required tag "${reqKey}" on ${address}`);
            }
          }
        }
      }
    }

    if (
      type === "aws_lb" ||
      type === "aws_lb_listener" ||
      type === "aws_route53_record" ||
      (type === "aws_db_instance" && after?.publicly_accessible === true)
    ) {
      summary.public_exposure.push({
        address,
        type,
        action: actionKind,
        internal: after?.internal ?? null
      });
    }

    if (
      type.startsWith("aws_iam_") ||
      type === "aws_eks_pod_identity_association"
    ) {
      summary.identity_changes.push({ address, type, action: actionKind });
    }

    if (BILL_DRIVER_TYPES.has(type)) {
      summary.expected_bill_drivers.push({ address, type, action: actionKind });
    }
  }

  return { summary, violations };
}

export function inspectPlan(options) {
  const repoRoot = path.resolve(options.rootDir ?? DEFAULT_ROOT);
  const profileRes = validateDeploymentProfileFile(options.configPath, { repoRoot });
  if (!profileRes.ok) {
    throw new CliError(`Invalid profile:\n- ${profileRes.errors.join("\n- ")}`, 1);
  }
  const profile = profileRes.profile;
  const infraRoot = path.resolve(repoRoot, profile.infrastructure_root);

  let planDoc = null;
  let terraformExitCode = options.detailedExitcode;
  let savedPlanPath = options.planBinaryPath ? path.resolve(options.planBinaryPath) : null;
  let tempDirToClean = null;

  try {
    if (options.planJsonPath) {
      planDoc = readStrictJsonFile(options.planJsonPath, { maxBytes: 16 * 1024 * 1024 });
      if (terraformExitCode === undefined) {
        const changes = Array.isArray(planDoc?.resource_changes) ? planDoc.resource_changes : [];
        const hasChanges = changes.some((rc) => classifyChangeActions(rc?.change?.actions) !== "no-op");
        terraformExitCode = hasChanges ? 2 : 0;
      }
    } else if (profileRes.deploymentMode === "self_hosted" && !options.terraformBin) {
      planDoc = { resource_changes: [] };
      terraformExitCode = terraformExitCode ?? 0;
    } else {
      const terraformBin = options.terraformBin ?? "terraform";
      if (!savedPlanPath) {
        if (options.savePlanPath) {
          savedPlanPath = path.resolve(options.savePlanPath);
          fs.mkdirSync(path.dirname(savedPlanPath), { recursive: true });
        } else {
          tempDirToClean = fs.mkdtempSync(path.join(os.tmpdir(), "rq-tfplan-"));
          savedPlanPath = path.join(tempDirToClean, "tfplan.bin");
        }
      }
      const planArgs = [
        `-chdir=${infraRoot}`,
        "plan",
        "-detailed-exitcode",
        "-input=false",
        `-out=${savedPlanPath}`
      ];
      if (options.varFilePath) {
        planArgs.push(`-var-file=${path.resolve(options.varFilePath)}`);
      }
      const planRun = runToolExecutable(terraformBin, planArgs, repoRoot);
      if (planRun.error) {
        throw new CliError(`Failed to run terraform plan: ${planRun.error.message}`, 1);
      }
      terraformExitCode = planRun.status ?? 1;
      if (terraformExitCode !== 0 && terraformExitCode !== 2) {
        throw new CliError(
          `terraform plan failed with exit code ${terraformExitCode}: ${redactSensitiveData((planRun.stderr ?? "").trim())}`,
          1
        );
      }

      const showRun = runToolExecutable(
        terraformBin,
        [`-chdir=${infraRoot}`, "show", "-json", savedPlanPath],
        repoRoot
      );
      if (showRun.error || showRun.status !== 0) {
        throw new CliError(
          `terraform show -json failed (exit ${showRun.status ?? 1}): ${redactSensitiveData((showRun.stderr ?? "").trim())}`,
          1
        );
      }
      planDoc = JSON.parse(showRun.stdout);
    }

    if (terraformExitCode === 1) {
      throw new CliError("Plan execution reported exit code 1 (failure)", 1);
    }
    if (terraformExitCode !== 0 && terraformExitCode !== 2) {
      throw new CliError(`Unsupported terraform -detailed-exitcode value: ${terraformExitCode}`, 1);
    }

    const { summary, violations } = analyzePlanDocument(planDoc, profile, {
      allowReplacement: options.allowReplacement,
      allowDeletion: options.allowDeletion,
      failOnReplace: options.failOnReplace
    });

    if (violations.length > 0) {
      throw new CliError(
        `Plan security/policy validation failed (${violations.length} violation(s)):\n- ${violations.join("\n- ")}`,
        1
      );
    }

    const lockPath = options.lockFilePath
      ? path.resolve(options.lockFilePath)
      : path.join(infraRoot, ".terraform.lock.hcl");
    const providerLockSha256 = fs.existsSync(lockPath)
      ? sha256Hex(fs.readFileSync(lockPath))
      : null;

    const savedPlanSha256 =
      savedPlanPath && fs.existsSync(savedPlanPath)
        ? sha256Hex(fs.readFileSync(savedPlanPath))
        : sha256Hex(canonicalizeJson(planDoc));

    const planJsonSha256 = sha256Hex(canonicalizeJson(planDoc));
    const gitMeta = readGitMetadata(repoRoot);

    const hasActualChanges =
      summary.creates.length > 0 ||
      summary.updates.length > 0 ||
      summary.replacements.length > 0 ||
      summary.deletions.length > 0;

    const finalExitCode = terraformExitCode === 2 || hasActualChanges ? 2 : 0;

    const operationRecord = redactSensitiveData({
      record_version: 1,
      operation_id: crypto.randomUUID(),
      created_at: new Date().toISOString(),
      deployment_name: profile.deployment_name,
      deployment_mode: profileRes.deploymentMode,
      expected_identity_reference: profile.expected_identity_reference,
      detailed_exitcode: finalExitCode,
      has_changes: finalExitCode === 2,
      bindings: {
        profile_sha256: profileRes.profileSha256,
        saved_plan_sha256: savedPlanSha256,
        plan_json_sha256: planJsonSha256,
        provider_lock_sha256: providerLockSha256,
        source_commit: gitMeta.source_commit,
        source_dirty: gitMeta.source_dirty
      },
      summary
    });

    if (options.outPath) {
      const resolvedOut = path.resolve(options.outPath);
      fs.mkdirSync(path.dirname(resolvedOut), { recursive: true });
      fs.writeFileSync(resolvedOut, `${JSON.stringify(operationRecord, null, 2)}\n`, "utf8");
    }

    return { exitCode: finalExitCode, record: operationRecord };
  } finally {
    if (tempDirToClean) {
      fs.rmSync(tempDirToClean, { recursive: true, force: true });
    }
  }
}

runCliMain(
  import.meta.url,
  HELP_TEXT,
  (argv) => {
    const parsed = parseCliFlags(argv, {
      errorExitCode: 1,
      options: {
        "--config": { type: "string", required: true },
        "--root": { type: "string" },
        "--plan-json": { type: "string" },
        "--plan-binary": { type: "string" },
        "--lock-file": { type: "string" },
        "--var-file": { type: "string" },
        "--save-plan": { type: "string" },
        "--terraform-bin": { type: "string" },
        "--detailed-exitcode": { type: "integer", min: 0, max: 2 },
        "--out": { type: "string" },
        "--allow-replacement": { type: "boolean", default: false },
        "--allow-deletion": { type: "boolean", default: false },
        "--fail-on-replace": { type: "boolean", default: false },
        "--json": { type: "boolean", default: false }
      }
    });
    if (parsed.help) {
      return { help: true };
    }

    const res = inspectPlan({
      configPath: parsed.options["--config"],
      rootDir: parsed.options["--root"],
      planJsonPath: parsed.options["--plan-json"],
      planBinaryPath: parsed.options["--plan-binary"],
      lockFilePath: parsed.options["--lock-file"],
      varFilePath: parsed.options["--var-file"],
      savePlanPath: parsed.options["--save-plan"],
      terraformBin: parsed.options["--terraform-bin"],
      detailedExitcode: parsed.options["--detailed-exitcode"],
      outPath: parsed.options["--out"],
      allowReplacement: parsed.options["--allow-replacement"],
      allowDeletion: parsed.options["--allow-deletion"],
      failOnReplace: parsed.options["--fail-on-replace"]
    });

    if (parsed.options["--json"]) {
      return { exitCode: res.exitCode, output: res.record };
    }
    const s = res.record.summary;
    return {
      exitCode: res.exitCode,
      output: `[inspect-plan] exit=${res.exitCode} creates=${s.creates.length} updates=${s.updates.length} replacements=${s.replacements.length} deletions=${s.deletions.length} plan_sha256=${res.record.bindings.saved_plan_sha256.slice(0, 12)}`
    };
  },
  { errorExitCode: 1 }
);
