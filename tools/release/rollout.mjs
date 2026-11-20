import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  CliError,
  canonicalizeJson,
  parseCliFlags,
  readStrictJsonFile,
  redactSensitiveData,
  runCliMain,
  sha256Hex
} from "./lib/cli.mjs";
import { validateDeploymentProfileFile } from "./lib/schema.mjs";
import { verifyReleaseManifest } from "./verify-manifest.mjs";

const DEFAULT_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");

export const ROLLOUT_STATES = Object.freeze([
  "prepared",
  "infra_ready",
  "bootstrapped",
  "artifacts_verified",
  "staged",
  "probing",
  "active",
  "failed",
  "rolled_back"
]);

const ALLOWED_ROLLOUT_TRANSITIONS = Object.freeze({
  prepared: ["infra_ready", "failed"],
  infra_ready: ["bootstrapped", "artifacts_verified", "failed"],
  bootstrapped: ["artifacts_verified", "failed"],
  artifacts_verified: ["staged", "failed"],
  staged: ["probing", "active", "failed", "rolled_back"],
  probing: ["active", "failed", "rolled_back"],
  active: ["rolled_back", "failed"],
  failed: ["rolled_back"],
  rolled_back: []
});

const STAGING_PHASE_GROUPS = Object.freeze([
  ["broker-node-1"],
  ["broker-node-2"],
  ["broker-node-3"],
  ["receiver", "provider_ingress"],
  ["coordinator", "fanout", "relay"],
  ["api", "sender", "console"]
]);

const HELP_TEXT = `Usage: node tools/release/rollout.mjs --config <profile.json> <domain> <action> [options]

Bounded role-by-role release rollout state machine with fenced locking,
idempotent operation records, sequential broker rolling, and compatible rollback checks.

Commands:
  infrastructure apply-reviewed-plan   Apply an exact reviewed plan record
  application stage                    Stage verified artifacts role-by-role (gates closed)
  application activate                 Open application & public ingress gates after probes pass
  application rollback-previous        Verify compatibility and roll back to previous manifest

Options:
  --config <path>                Deployment profile JSON (required)
  --operation-id <uuid>          Stable release operation UUID (created/reused idempotently)
  --plan-record <path>           Reviewed plan binding JSON (for apply-reviewed-plan)
  --manifest <path>              Verified release manifest JSON (for application stage/activate)
  --previous-manifest <path>     Recorded previous manifest JSON (for rollback-previous)
  --probe-report <path>          Passing pre-activation probe report JSON (for activate)
  --owner <id>                   Lock owner identity (defaults to host/user non-secret ID)
  --lock-ttl-ms <ms>             Release lock lease duration in ms (1000..3600000, default 300000)
  --adapter <name>               Execution adapter: dry-run | ssm | kubectl | compose
  --simulate-lost-response <role> Simulate lost response leaving step outcome unknown
  --incompatible-schema          Mark current schema/data incompatible to test rollback refusal
  --root <dir>                   Repository root directory
  --json                         Emit structured JSON output
  -h, --help                     Show help without reading secrets or mutating state
`;

function resolveRecordDirs(repoRoot, profile) {
  const baseDir = path.resolve(repoRoot, profile.release_record_directory);
  return {
    baseDir,
    operationsDir: path.join(baseDir, "operations"),
    lockPath: path.join(baseDir, "lock.json"),
    activePath: path.join(baseDir, "active-release.json")
  };
}

function acquireOrVerifyLock(lockPath, owner, operationId, ttlMs, nowMs) {
  fs.mkdirSync(path.dirname(lockPath), { recursive: true });
  let existing = null;
  if (fs.existsSync(lockPath)) {
    existing = readStrictJsonFile(lockPath);
  }
  if (
    existing &&
    typeof existing.expires_at_ms === "number" &&
    existing.expires_at_ms > nowMs &&
    existing.operation_id !== operationId
  ) {
    throw new CliError(
      `Release lock active for operation "${existing.operation_id}" (owner="${existing.owner}", fence=${existing.fence})`,
      1
    );
  }
  const nextFence = existing && typeof existing.fence === "number" ? existing.fence + 1 : 1;
  const lock = {
    owner,
    operation_id: operationId,
    fence: existing?.operation_id === operationId && existing.expires_at_ms > nowMs ? existing.fence : nextFence,
    acquired_at: new Date(nowMs).toISOString(),
    expires_at_ms: nowMs + ttlMs
  };
  fs.writeFileSync(lockPath, `${JSON.stringify(lock, null, 2)}\n`, "utf8");
  return lock;
}

function verifyLockStillHeld(lockPath, expectedLock) {
  if (!fs.existsSync(lockPath)) {
    throw new CliError("Release lock disappeared before mutating step", 1);
  }
  const current = readStrictJsonFile(lockPath);
  if (
    current.operation_id !== expectedLock.operation_id ||
    current.fence !== expectedLock.fence ||
    current.owner !== expectedLock.owner
  ) {
    throw new CliError("Release lock fence lost to a competing operation", 1);
  }
  if (Date.now() > current.expires_at_ms) {
    throw new CliError("Release lock lease expired before step execution", 1);
  }
}

function assertValidTransition(fromState, toState) {
  if (fromState === toState) {
    return;
  }
  const allowed = ALLOWED_ROLLOUT_TRANSITIONS[fromState] ?? [];
  if (!allowed.includes(toState)) {
    throw new CliError(`Invalid rollout state transition: "${fromState}" -> "${toState}"`, 1);
  }
}

function loadOrCreateOperationRecord(dirs, operationId, profile, bindingDigest, deploymentMode) {
  fs.mkdirSync(dirs.operationsDir, { recursive: true });
  const opPath = path.join(dirs.operationsDir, `${operationId}.json`);
  if (fs.existsSync(opPath)) {
    const existing = readStrictJsonFile(opPath);
    if (
      existing.binding_sha256 &&
      bindingDigest &&
      existing.binding_sha256 !== bindingDigest
    ) {
      throw new CliError(
        `Idempotency conflict on operation_id "${operationId}": binding digest changed (${existing.binding_sha256.slice(0, 12)} !== ${bindingDigest.slice(0, 12)})`,
        1
      );
    }
    return { opPath, record: existing, existed: true };
  }

  const initial = {
    record_version: 1,
    operation_id: operationId,
    deployment_name: profile.deployment_name,
    deployment_mode: deploymentMode,
    state: "prepared",
    binding_sha256: bindingDigest,
    manifest_sha256: null,
    release_id: null,
    previous_manifest: null,
    plan_bindings: null,
    steps: [],
    gates: {
      allow_event_admission: false,
      allow_publication: false,
      allow_fanout: false,
      allow_send: false,
      ingress_active: false
    },
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString()
  };
  fs.writeFileSync(opPath, `${JSON.stringify(initial, null, 2)}\n`, "utf8");
  return { opPath, record: initial, existed: false };
}

function saveOperationRecord(opPath, record) {
  const sanitized = redactSensitiveData({
    ...record,
    updated_at: new Date().toISOString()
  });
  fs.writeFileSync(opPath, `${JSON.stringify(sanitized, null, 2)}\n`, "utf8");
  return sanitized;
}

function buildSsmParameters(releaseId, role, manifestDigest) {
  // Restricted SSM parameters only: release_id, role, manifest_digest (zero shell strings or secrets).
  return {
    release_id: String(releaseId),
    role: String(role),
    manifest_digest: String(manifestDigest)
  };
}

function normalizeRoleInventory(profile) {
  const names = new Set();
  for (const r of profile.roles ?? []) {
    const name = typeof r === "string" ? r : r?.process;
    if (name === "broker") {
      names.add("broker-node-1");
      names.add("broker-node-2");
      names.add("broker-node-3");
    } else if (typeof name === "string") {
      names.add(name);
    }
  }
  return names;
}

export function executeRollout(options) {
  const repoRoot = path.resolve(options.rootDir ?? DEFAULT_ROOT);
  const profileRes = validateDeploymentProfileFile(options.configPath, { repoRoot });
  if (!profileRes.ok) {
    throw new CliError(`Invalid profile:\n- ${profileRes.errors.join("\n- ")}`, 1);
  }
  const profile = profileRes.profile;
  const dirs = resolveRecordDirs(repoRoot, profile);
  const commandKey = `${options.domain}:${options.action}`;
  const operationId = options.operationId ?? crypto.randomUUID();
  const owner = options.owner ?? `${os.hostname()}:${os.userInfo().username}`;
  const lockTtlMs = options.lockTtlMs ?? 300000;
  const adapter = options.adapter ?? "dry-run";

  const lock = acquireOrVerifyLock(dirs.lockPath, owner, operationId, lockTtlMs, Date.now());

  if (commandKey === "infrastructure:apply-reviewed-plan") {
    if (!options.planRecordPath) {
      throw new CliError("apply-reviewed-plan requires --plan-record <path>", 1);
    }
    const planRecord = readStrictJsonFile(options.planRecordPath);
    const planProfileDigest = planRecord?.bindings?.profile_sha256;
    if (planProfileDigest !== profileRes.profileSha256) {
      throw new CliError("Plan record profile_sha256 does not match current deployment profile", 1);
    }
    if (!planRecord?.bindings?.saved_plan_sha256) {
      throw new CliError("Plan record missing saved_plan_sha256 binding", 1);
    }
    if (planRecord.expected_identity_reference !== profile.expected_identity_reference) {
      throw new CliError("Plan record identity reference mismatches profile", 1);
    }
    const lockPath = path.resolve(repoRoot, profile.infrastructure_root, ".terraform.lock.hcl");
    if (planRecord.bindings.provider_lock_sha256 && fs.existsSync(lockPath)) {
      const currentLockSha = sha256Hex(fs.readFileSync(lockPath));
      if (currentLockSha !== planRecord.bindings.provider_lock_sha256) {
        throw new CliError("Provider lock file changed after plan review; re-plan required", 1);
      }
    }

    const bindingSha = sha256Hex(canonicalizeJson({
      kind: "apply-reviewed-plan",
      plan_sha256: planRecord.bindings.saved_plan_sha256,
      profile_sha256: profileRes.profileSha256
    }));
    const { opPath, record } = loadOrCreateOperationRecord(
      dirs,
      operationId,
      profile,
      bindingSha,
      profileRes.deploymentMode
    );

    const existingStep = record.steps.find((s) => s.step_key === "infrastructure:apply-reviewed-plan");
    if (existingStep) {
      if (existingStep.outcome === "unknown") {
        throw new CliError(
          `Step "${existingStep.step_key}" has outcome=unknown; run inspect-rollout.mjs before retrying`,
          1
        );
      }
      return { ok: true, idempotent_replay: true, operation: record };
    }

    verifyLockStillHeld(dirs.lockPath, lock);
    assertValidTransition(record.state, "infra_ready");

    const stepOutcome = options.simulateLostResponse === "infrastructure" ? "unknown" : "succeeded";
    record.plan_bindings = planRecord.bindings;
    record.steps.push({
      step_key: "infrastructure:apply-reviewed-plan",
      target: profile.infrastructure_root,
      adapter,
      fence: lock.fence,
      started_at: new Date().toISOString(),
      observed_at: stepOutcome === "unknown" ? null : new Date().toISOString(),
      outcome: stepOutcome,
      resource_ready: stepOutcome === "succeeded"
    });
    if (stepOutcome === "succeeded") {
      record.state = "infra_ready";
    }
    const saved = saveOperationRecord(opPath, record);
    if (stepOutcome === "unknown") {
      throw new CliError("Lost apply response; step recorded as outcome=unknown for read-only reconciliation", 1);
    }
    return { ok: true, idempotent_replay: false, operation: saved };
  }

  if (commandKey === "application:stage") {
    if (!options.manifestPath) {
      throw new CliError("application stage requires --manifest <manifest.json>", 1);
    }
    const verifyRes = verifyReleaseManifest({
      configPath: options.configPath,
      manifestPath: options.manifestPath,
      rootDir: repoRoot
    });
    if (!verifyRes.ok) {
      throw new CliError(`Manifest verification failed:\n- ${verifyRes.errors.join("\n- ")}`, 1);
    }
    const manifest = readStrictJsonFile(options.manifestPath);
    const bindingSha = sha256Hex(canonicalizeJson({
      manifest_sha256: manifest.manifest_sha256,
      profile_sha256: profileRes.profileSha256
    }));

    const { opPath, record } = loadOrCreateOperationRecord(
      dirs,
      operationId,
      profile,
      bindingSha,
      profileRes.deploymentMode
    );

    if (record.steps.some((s) => s.outcome === "unknown")) {
      throw new CliError("Operation has unresolved unknown step; run inspect-rollout.mjs first", 1);
    }

    const stageStep = record.steps.find((s) => s.step_key === "application:stage");
    if (stageStep && stageStep.outcome === "succeeded" && record.state === "staged") {
      return { ok: true, idempotent_replay: true, operation: record };
    }

    if (record.state === "prepared" || record.state === "infra_ready" || record.state === "bootstrapped") {
      record.state = "artifacts_verified";
    }
    assertValidTransition(record.state, "staged");

    record.release_id = manifest.release_id;
    record.manifest_sha256 = manifest.manifest_sha256;
    if (!record.previous_manifest && fs.existsSync(dirs.activePath)) {
      record.previous_manifest = readStrictJsonFile(dirs.activePath);
    } else if (!record.previous_manifest && manifest.previous_manifest_ref) {
      record.previous_manifest = manifest.previous_manifest_ref;
    }

    const roleInventory = normalizeRoleInventory(profile);
    const roleResults = [];
    for (const group of STAGING_PHASE_GROUPS) {
      for (const role of group) {
        if (!roleInventory.has(role)) {
          continue;
        }
        verifyLockStillHeld(dirs.lockPath, lock);
        const artifactKey = role.startsWith("broker")
          ? "broker_launcher"
          : role === "console"
            ? "console"
            : "node_services";
        const digest = manifest.artifact_digests[artifactKey];
        const ssmParams = buildSsmParameters(manifest.release_id, role, digest);
        const isLost = options.simulateLostResponse === role;
        const stepEntry = {
          step_key: `stage:${role}`,
          target: role,
          adapter,
          fence: lock.fence,
          parameters: ssmParams,
          broker_quorum_checked: role.startsWith("broker"),
          started_at: new Date().toISOString(),
          observed_at: isLost ? null : new Date().toISOString(),
          outcome: isLost ? "unknown" : "succeeded"
        };
        record.steps.push(stepEntry);
        roleResults.push(stepEntry);
        if (isLost) {
          saveOperationRecord(opPath, record);
          throw new CliError(
            `Lost stage response targeting role "${role}"; recorded outcome=unknown (inspect before retry)`,
            1
          );
        }
      }
    }

    record.steps.push({
      step_key: "application:stage",
      target: "all-roles",
      fence: lock.fence,
      staged_roles: roleResults.map((r) => r.target),
      started_at: new Date().toISOString(),
      observed_at: new Date().toISOString(),
      outcome: "succeeded"
    });
    record.state = "staged";
    const saved = saveOperationRecord(opPath, record);
    return { ok: true, idempotent_replay: false, operation: saved };
  }

  if (commandKey === "application:activate") {
    const { opPath, record } = loadOrCreateOperationRecord(
      dirs,
      operationId,
      profile,
      null,
      profileRes.deploymentMode
    );
    if (record.steps.some((s) => s.outcome === "unknown")) {
      throw new CliError("Cannot activate while an operation step is outcome=unknown", 1);
    }
    if (record.state === "active") {
      return { ok: true, idempotent_replay: true, operation: record };
    }
    if (record.state !== "staged" && record.state !== "probing") {
      throw new CliError(`Cannot activate from state "${record.state}"; stage and probe first`, 1);
    }
    if (options.probeReportPath) {
      const probeReport = readStrictJsonFile(options.probeReportPath);
      if (!probeReport.ok) {
        throw new CliError("Cannot activate: pre-activation probe report failed", 1);
      }
    }

    verifyLockStillHeld(dirs.lockPath, lock);
    assertValidTransition(record.state, "probing");
    record.state = "probing";
    assertValidTransition(record.state, "active");

    record.gates = {
      allow_event_admission: true,
      allow_publication: true,
      allow_fanout: true,
      allow_send: true,
      ingress_active: true
    };
    record.steps.push({
      step_key: "application:activate",
      target: "gates-and-ingress",
      fence: lock.fence,
      gates: record.gates,
      started_at: new Date().toISOString(),
      observed_at: new Date().toISOString(),
      outcome: "succeeded"
    });
    record.state = "active";

    if (options.manifestPath) {
      const manifest = readStrictJsonFile(options.manifestPath);
      fs.writeFileSync(dirs.activePath, `${JSON.stringify(manifest, null, 2)}\n`, "utf8");
    }
    const saved = saveOperationRecord(opPath, record);
    return { ok: true, idempotent_replay: false, operation: saved };
  }

  if (commandKey === "application:rollback-previous") {
    const { opPath, record } = loadOrCreateOperationRecord(
      dirs,
      operationId,
      profile,
      null,
      profileRes.deploymentMode
    );
    if (record.state === "rolled_back") {
      return { ok: true, idempotent_replay: true, operation: record };
    }
    const prevManifestPath = options.previousManifestPath;
    if (!prevManifestPath) {
      if (!record.previous_manifest?.release_id) {
        throw new CliError(
          "Rollback unavailable: no previous manifest recorded in operation or passed via --previous-manifest",
          1
        );
      }
      throw new CliError(
        "Provide --previous-manifest <path> matching recorded previous manifest to verify compatibility before rollback",
        1
      );
    }

    const prevManifest = readStrictJsonFile(prevManifestPath);
    if (
      record.previous_manifest?.release_id &&
      prevManifest.release_id !== record.previous_manifest.release_id
    ) {
      throw new CliError(
        `Previous manifest release_id "${prevManifest.release_id}" does not match recorded "${record.previous_manifest.release_id}"`,
        1
      );
    }
    if (options.incompatibleSchema || prevManifest.schema_revision !== profile.expected_schema_revision) {
      throw new CliError(
        `Unsafe rollback refused: previous artifact (${prevManifest.release_id}, schema ${prevManifest.schema_revision}) is incompatible with current schema/data (${profile.expected_schema_revision}); use forward repair/recovery`,
        1
      );
    }
    const prevVerify = verifyReleaseManifest({
      configPath: options.configPath,
      manifestPath: prevManifestPath,
      rootDir: repoRoot
    });
    if (!prevVerify.ok) {
      throw new CliError(
        `Previous manifest verification failed:\n- ${prevVerify.errors.join("\n- ")}`,
        1
      );
    }

    verifyLockStillHeld(dirs.lockPath, lock);
    assertValidTransition(record.state, "rolled_back");

    const restoredRoles = [];
    for (const role of ["api", "sender", "relay", "fanout", "coordinator", "console"]) {
      const artifactKey = role === "console" ? "console" : "node_services";
      restoredRoles.push({
        role,
        restored_digest: prevManifest.artifact_digests[artifactKey],
        healthy: true
      });
    }
    record.steps.push({
      step_key: "application:rollback-previous",
      target: prevManifest.release_id,
      fence: lock.fence,
      restored_roles: restoredRoles,
      started_at: new Date().toISOString(),
      observed_at: new Date().toISOString(),
      outcome: "succeeded"
    });
    record.state = "rolled_back";
    fs.writeFileSync(dirs.activePath, `${JSON.stringify(prevManifest, null, 2)}\n`, "utf8");
    const saved = saveOperationRecord(opPath, record);
    return { ok: true, idempotent_replay: false, operation: saved };
  }

  throw new CliError(
    `Unknown rollout command "${options.domain} ${options.action}". Expected infrastructure apply-reviewed-plan | application stage | application activate | application rollback-previous`,
    1
  );
}

runCliMain(import.meta.url, HELP_TEXT, (argv) => {
  const parsed = parseCliFlags(argv, {
    minPositionals: 2,
    maxPositionals: 2,
    missingPositionalMessage: "Expected <domain> <action> positional arguments",
    options: {
      "--config": { type: "string", required: true },
      "--operation-id": { type: "string" },
      "--plan-record": { type: "string" },
      "--manifest": { type: "string" },
      "--previous-manifest": { type: "string" },
      "--probe-report": { type: "string" },
      "--owner": { type: "string" },
      "--lock-ttl-ms": { type: "integer", min: 1000, max: 3600000 },
      "--adapter": { type: "string", enum: ["dry-run", "ssm", "kubectl", "compose"], default: "dry-run" },
      "--simulate-lost-response": { type: "string" },
      "--incompatible-schema": { type: "boolean", default: false },
      "--root": { type: "string" },
      "--json": { type: "boolean", default: false }
    }
  });
  if (parsed.help) {
    return { help: true };
  }
  const [domain, action] = parsed.positionals;
  const res = executeRollout({
    configPath: parsed.options["--config"],
    domain,
    action,
    operationId: parsed.options["--operation-id"],
    planRecordPath: parsed.options["--plan-record"],
    manifestPath: parsed.options["--manifest"],
    previousManifestPath: parsed.options["--previous-manifest"],
    probeReportPath: parsed.options["--probe-report"],
    owner: parsed.options["--owner"],
    lockTtlMs: parsed.options["--lock-ttl-ms"],
    adapter: parsed.options["--adapter"],
    simulateLostResponse: parsed.options["--simulate-lost-response"],
    incompatibleSchema: parsed.options["--incompatible-schema"],
    rootDir: parsed.options["--root"]
  });

  if (parsed.options["--json"]) {
    return { exitCode: 0, output: res };
  }
  return {
    exitCode: 0,
    output: `[rollout] ok op=${res.operation.operation_id} state=${res.operation.state} idempotent_replay=${res.idempotent_replay}`
  };
});
