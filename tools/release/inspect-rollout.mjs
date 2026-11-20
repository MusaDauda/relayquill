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

const HELP_TEXT = `Usage: node tools/release/inspect-rollout.mjs --config <profile.json> [options]

Read-only rollout observer and resume inspector after lost mutation replies.
Never mutates remote state or starts a new rollout operation.

Options:
  --config <path>          Deployment profile JSON (required)
  --operation-id <uuid>    Specific release operation UUID to inspect
  --observed-state <path>  Optional observed runtime/resource snapshot JSON to reconcile unknown steps
  --root <dir>             Repository root directory
  --json                   Emit structured JSON output
  -h, --help               Show help without reading secrets or mutating state
`;

export function inspectRollout(options) {
  const repoRoot = path.resolve(options.rootDir ?? DEFAULT_ROOT);
  const profileRes = validateDeploymentProfileFile(options.configPath, { repoRoot });
  if (!profileRes.ok) {
    throw new CliError(`Invalid profile:\n- ${profileRes.errors.join("\n- ")}`, 1);
  }
  const profile = profileRes.profile;
  const baseDir = path.resolve(repoRoot, profile.release_record_directory);
  const opsDir = path.join(baseDir, "operations");
  const lockPath = path.join(baseDir, "lock.json");
  const activePath = path.join(baseDir, "active-release.json");

  const lock = fs.existsSync(lockPath) ? readStrictJsonFile(lockPath) : null;
  const activeRelease = fs.existsSync(activePath) ? readStrictJsonFile(activePath) : null;
  const observedSnapshot = options.observedStatePath ? readStrictJsonFile(options.observedStatePath) : null;

  let operations = [];
  if (fs.existsSync(opsDir)) {
    const files = fs.readdirSync(opsDir).filter((f) => f.endsWith(".json")).sort();
    for (const file of files) {
      if (options.operationId && file !== `${options.operationId}.json`) {
        continue;
      }
      operations.push(readStrictJsonFile(path.join(opsDir, file)));
    }
  }

  if (options.operationId && operations.length === 0) {
    throw new CliError(`Operation record not found: ${options.operationId}`, 1);
  }

  const summaries = operations.map((op) => {
    const unknownSteps = (op.steps ?? []).filter((s) => s.outcome === "unknown");
    const reconciliations = unknownSteps.map((step) => {
      const observedOutcome = observedSnapshot?.roles?.[step.target]?.digest
        ? observedSnapshot.roles[step.target].digest === step.parameters?.manifest_digest
          ? "observed_applied"
          : "observed_not_applied"
        : "still_unknown";
      return {
        step_key: step.step_key,
        target: step.target,
        reconciled_status: observedOutcome
      };
    });
    return {
      operation_id: op.operation_id,
      state: op.state,
      release_id: op.release_id,
      manifest_sha256: op.manifest_sha256,
      step_count: (op.steps ?? []).length,
      unknown_step_count: unknownSteps.length,
      unknown_reconciliations: reconciliations,
      gates: op.gates,
      updated_at: op.updated_at
    };
  });

  return redactSensitiveData({
    ok: true,
    read_only: true,
    deployment_name: profile.deployment_name,
    deployment_mode: profileRes.deploymentMode,
    lock,
    active_release: activeRelease
      ? { release_id: activeRelease.release_id, manifest_sha256: activeRelease.manifest_sha256 }
      : null,
    operations: summaries
  });
}

runCliMain(import.meta.url, HELP_TEXT, (argv) => {
  const parsed = parseCliFlags(argv, {
    options: {
      "--config": { type: "string", required: true },
      "--operation-id": { type: "string" },
      "--observed-state": { type: "string" },
      "--root": { type: "string" },
      "--json": { type: "boolean", default: false }
    }
  });
  if (parsed.help) {
    return { help: true };
  }
  const report = inspectRollout({
    configPath: parsed.options["--config"],
    operationId: parsed.options["--operation-id"],
    observedStatePath: parsed.options["--observed-state"],
    rootDir: parsed.options["--root"]
  });
  if (parsed.options["--json"]) {
    return { exitCode: 0, output: report };
  }
  const latest = report.operations[report.operations.length - 1];
  return {
    exitCode: 0,
    output: latest
      ? `[inspect-rollout] ops=${report.operations.length} latest=${latest.operation_id} state=${latest.state} unknown=${latest.unknown_step_count}`
      : `[inspect-rollout] ops=0 active=${report.active_release?.release_id ?? "none"}`
  };
});
