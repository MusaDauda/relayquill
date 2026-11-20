import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  CliError,
  parseCliFlags,
  readStrictJsonFile,
  runCliMain
} from "./lib/cli.mjs";
import {
  validateDeploymentProfileFile,
  validateRoleConfigObject
} from "./lib/schema.mjs";

const DEFAULT_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");

const HELP_TEXT = `Usage: node tools/release/validate-profile.mjs --config <profile.json> [options]
       node tools/release/validate-profile.mjs --role-config <role.json> [options]

Validate nonsecret deployment profiles (self-hosted or AWS release) and role configs.

Options:
  --config <path>       Path to deployment profile JSON
  --role-config <path>  Path to single role configuration JSON
  --root <dir>          Repository root directory (defaults to workspace root)
  --production          Require release or self_hosted profile when validating --role-config
  --json                Emit structured JSON output
  -h, --help            Show help without reading secrets or mutating state
`;

export function validateProfile(options) {
  const repoRoot = path.resolve(options.rootDir ?? DEFAULT_ROOT);
  if (options.roleConfigPath) {
    const resolved = path.resolve(options.roleConfigPath);
    const roleCfg = readStrictJsonFile(resolved);
    const errors = validateRoleConfigObject(roleCfg, {
      repoRoot,
      requireProductionProfile: Boolean(options.requireProduction)
    });
    return {
      ok: errors.length === 0,
      kind: "role_config",
      path: resolved,
      profile: roleCfg.profile,
      process_role: roleCfg.process_role,
      errors
    };
  }

  if (!options.configPath) {
    throw new CliError("Missing required --config <profile.json> or --role-config <role.json>", 1);
  }

  const res = validateDeploymentProfileFile(options.configPath, { repoRoot });
  return {
    ok: res.ok,
    kind: "deployment_profile",
    deployment_mode: res.deploymentMode,
    deployment_name: res.profile.deployment_name,
    region: res.profile.region ?? "self-hosted",
    cpu_platform: res.profile.cpu_platform,
    profile_sha256: res.profileSha256,
    role_config_digests: res.roleConfigDigests,
    errors: res.errors
  };
}

runCliMain(import.meta.url, HELP_TEXT, (argv) => {
  const parsed = parseCliFlags(argv, {
    options: {
      "--config": { type: "string" },
      "--role-config": { type: "string" },
      "--root": { type: "string" },
      "--production": { type: "boolean", default: false },
      "--json": { type: "boolean", default: false }
    }
  });
  if (parsed.help) {
    return { help: true };
  }

  const report = validateProfile({
    configPath: parsed.options["--config"],
    roleConfigPath: parsed.options["--role-config"],
    rootDir: parsed.options["--root"],
    requireProduction: parsed.options["--production"]
  });

  if (!report.ok) {
    throw new CliError(
      `Profile validation failed (${report.errors.length} error(s)):\n- ${report.errors.join("\n- ")}`,
      1
    );
  }

  if (parsed.options["--json"]) {
    return { exitCode: 0, output: report };
  }
  return {
    exitCode: 0,
    output:
      report.kind === "role_config"
        ? `[validate-profile] ok role=${report.process_role} profile=${report.profile}`
        : `[validate-profile] ok deployment=${report.deployment_name} mode=${report.deployment_mode} sha256=${report.profile_sha256.slice(0, 12)}`
  };
});
