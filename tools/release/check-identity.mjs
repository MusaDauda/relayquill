import { spawnSync } from "node:child_process";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  CliError,
  parseCliFlags,
  readStrictJsonFile,
  redactAwsAccountInString,
  redactSensitiveData,
  runCliMain
} from "./lib/cli.mjs";
import { validateDeploymentProfileFile } from "./lib/schema.mjs";

const DEFAULT_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");

const HELP_TEXT = `Usage: node tools/release/check-identity.mjs --config <profile.json> [options]

Verify expected deployment identity (AWS role/account/region or self-hosted operator)
with redacted nonsecret output.

Options:
  --config <path>           Path to deployment profile JSON (required)
  --root <dir>              Repository root directory
  --identity-json <path>    Observed identity JSON file (STS or operator payload)
  --observed-arn <arn>      Observed AWS caller ARN (offline verification)
  --observed-region <reg>   Observed AWS region
  --observed-user <name>    Observed self-hosted operator identity
  --live                    Invoke live identity check (aws sts / local OS principal)
  --policy-only             Verify expected_identity_reference policy without live probe
  --json                    Emit structured JSON output
  -h, --help                Show help without reading secrets or mutating state
`;

function parseIamRoleRef(ref) {
  const match = /^arn:aws[a-z-]*:iam::(\d{12}):role\/(.+)$/.exec(ref);
  if (!match) {
    return null;
  }
  return { accountId: match[1], roleName: match[2] };
}

function parseAssumedOrRoleArn(arn) {
  const roleMatch = /^arn:aws[a-z-]*:iam::(\d{12}):role\/(.+)$/.exec(arn);
  if (roleMatch) {
    return { kind: "role", accountId: roleMatch[1], roleName: roleMatch[2] };
  }
  const stsMatch = /^arn:aws[a-z-]*:sts::(\d{12}):assumed-role\/([^/]+)\/(.+)$/.exec(arn);
  if (stsMatch) {
    return { kind: "assumed_role", accountId: stsMatch[1], roleName: stsMatch[2], sessionName: stsMatch[3] };
  }
  if (/^arn:aws[a-z-]*:iam::\d{12}:root$/i.test(arn)) {
    return { kind: "root" };
  }
  if (/^arn:aws[a-z-]*:iam::\d{12}:user\//i.test(arn)) {
    return { kind: "static_user" };
  }
  return { kind: "unknown" };
}

function resolveLiveAwsIdentity(region) {
  const res = spawnSync("aws", ["sts", "get-caller-identity", "--output", "json"], {
    encoding: "utf8",
    shell: false,
    env: { ...process.env, ...(region ? { AWS_REGION: region, AWS_DEFAULT_REGION: region } : {}) }
  });
  if (res.error) {
    throw new CliError(`Failed to execute aws CLI for --live check: ${res.error.message}`, 1);
  }
  if (res.status !== 0) {
    throw new CliError(`aws sts get-caller-identity failed (exit ${res.status}): ${(res.stderr ?? "").trim()}`, 1);
  }
  try {
    return JSON.parse(res.stdout);
  } catch {
    throw new CliError("aws sts get-caller-identity returned non-JSON output", 1);
  }
}

export function checkIdentity(options) {
  const repoRoot = path.resolve(options.rootDir ?? DEFAULT_ROOT);
  const profileRes = validateDeploymentProfileFile(options.configPath, { repoRoot });
  if (!profileRes.ok) {
    throw new CliError(`Invalid profile before identity check:\n- ${profileRes.errors.join("\n- ")}`, 1);
  }

  const profile = profileRes.profile;
  const expectedRef = profile.expected_identity_reference;
  const mode = profileRes.deploymentMode;

  let observed = null;
  if (options.identityJsonPath) {
    observed = readStrictJsonFile(options.identityJsonPath);
  } else if (options.observedArn || options.observedUser || options.observedRegion) {
    observed = {
      Arn: options.observedArn,
      region: options.observedRegion,
      operator: options.observedUser
    };
  } else if (options.live) {
    if (mode === "aws_release") {
      observed = resolveLiveAwsIdentity(profile.region);
      observed.region = observed.region ?? process.env.AWS_REGION ?? process.env.AWS_DEFAULT_REGION ?? profile.region;
    } else {
      const uid = typeof process.getuid === "function" ? process.getuid() : null;
      const username = os.userInfo().username;
      observed = {
        operator: `selfhosted:${username}`,
        uid,
        is_root: uid === 0
      };
    }
  }

  if (mode === "self_hosted") {
    if (observed) {
      const actualOp = String(observed.operator ?? observed.Arn ?? observed.identity ?? "");
      if (observed.is_root === true || observed.uid === 0 || /^root$/i.test(actualOp)) {
        throw new CliError("Refusing root identity for self-hosted deployment operation", 1);
      }
      if (expectedRef && actualOp && actualOp !== expectedRef) {
        throw new CliError(
          `Identity mismatch: expected "${expectedRef}", observed "${actualOp}"`,
          1
        );
      }
    }
    return redactSensitiveData({
      ok: true,
      deployment_mode: "self_hosted",
      deployment_name: profile.deployment_name,
      expected_identity_reference: expectedRef,
      probe_status: observed ? "verified" : "not_run",
      observed_identity: observed ? String(observed.operator ?? observed.identity ?? expectedRef) : null
    });
  }

  const expectedRole = parseIamRoleRef(expectedRef);
  if (!expectedRole) {
    throw new CliError(
      `Invalid expected_identity_reference "${redactAwsAccountInString(expectedRef)}"; expected IAM role ARN`,
      1
    );
  }

  if (!observed) {
    return redactSensitiveData({
      ok: true,
      deployment_mode: "aws_release",
      deployment_name: profile.deployment_name,
      region: profile.region,
      expected_identity_reference: expectedRef,
      probe_status: "not_run",
      live_identity_verified: false
    });
  }

  const observedArn = String(observed.Arn ?? observed.arn ?? "");
  const parsedObserved = parseAssumedOrRoleArn(observedArn);
  if (parsedObserved.kind === "root" || parsedObserved.kind === "static_user") {
    throw new CliError(
      `Forbidden caller identity kind (${parsedObserved.kind}); federated/assumed role is required`,
      1
    );
  }
  if (parsedObserved.kind !== "role" && parsedObserved.kind !== "assumed_role") {
    throw new CliError(
      `Unrecognized observed AWS ARN: ${redactAwsAccountInString(observedArn)}`,
      1
    );
  }
  if (parsedObserved.accountId !== expectedRole.accountId) {
    throw new CliError(
      `AWS account mismatch: expected ${redactAwsAccountInString(expectedRef)}, got ${redactAwsAccountInString(observedArn)}`,
      1
    );
  }
  if (parsedObserved.roleName !== expectedRole.roleName) {
    throw new CliError(
      `AWS role mismatch: expected role "${expectedRole.roleName}", got "${parsedObserved.roleName}"`,
      1
    );
  }
  const observedRegion = observed.region ?? observed.Region;
  if (observedRegion && observedRegion !== profile.region) {
    throw new CliError(
      `AWS region mismatch: expected "${profile.region}", got "${observedRegion}"`,
      1
    );
  }

  return redactSensitiveData({
    ok: true,
    deployment_mode: "aws_release",
    deployment_name: profile.deployment_name,
    region: profile.region,
    expected_identity_reference: expectedRef,
    observed_arn: observedArn,
    probe_status: "verified",
    live_identity_verified: Boolean(options.live)
  });
}

runCliMain(import.meta.url, HELP_TEXT, (argv) => {
  const parsed = parseCliFlags(argv, {
    options: {
      "--config": { type: "string", required: true },
      "--root": { type: "string" },
      "--identity-json": { type: "string" },
      "--observed-arn": { type: "string" },
      "--observed-region": { type: "string" },
      "--observed-user": { type: "string" },
      "--live": { type: "boolean", default: false },
      "--policy-only": { type: "boolean", default: false },
      "--json": { type: "boolean", default: false }
    }
  });
  if (parsed.help) {
    return { help: true };
  }
  const report = checkIdentity({
    configPath: parsed.options["--config"],
    rootDir: parsed.options["--root"],
    identityJsonPath: parsed.options["--identity-json"],
    observedArn: parsed.options["--observed-arn"],
    observedRegion: parsed.options["--observed-region"],
    observedUser: parsed.options["--observed-user"],
    live: parsed.options["--live"] && !parsed.options["--policy-only"]
  });

  if (parsed.options["--json"]) {
    return { exitCode: 0, output: report };
  }
  return {
    exitCode: 0,
    output: `[check-identity] ok mode=${report.deployment_mode} probe=${report.probe_status} ref=${report.expected_identity_reference}`
  };
});
