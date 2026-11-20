import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  CliError,
  canonicalizeJson,
  findRawSecretsInObject,
  parseCliFlags,
  readStrictJsonFile,
  runCliMain,
  sha256Hex
} from "./lib/cli.mjs";
import { validateDeploymentProfileFile } from "./lib/schema.mjs";
import { validatePinnedImageReference } from "./build-manifest.mjs";

const DEFAULT_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");

const HELP_TEXT = `Usage: node tools/release/verify-manifest.mjs --config <profile.json> --manifest <manifest.json> [options]

Verify release manifest integrity, digest pinning, config digest compatibility,
schema revision match, and optional previous-release rollback compatibility.

Options:
  --config <path>             Deployment profile JSON (required)
  --manifest <path>           Release manifest JSON to verify (required)
  --previous-manifest <path>  Optional previous deployed manifest for rollback check
  --root <dir>                Repository root directory
  --json                      Emit structured JSON output
  -h, --help                  Show help without reading secrets or mutating state
`;

export function verifyReleaseManifest(options) {
  const repoRoot = path.resolve(options.rootDir ?? DEFAULT_ROOT);
  const profileRes = validateDeploymentProfileFile(options.configPath, { repoRoot });
  if (!profileRes.ok) {
    throw new CliError(`Invalid profile:\n- ${profileRes.errors.join("\n- ")}`, 1);
  }
  const profile = profileRes.profile;
  const manifest = readStrictJsonFile(options.manifestPath);
  const errors = [];

  errors.push(...findRawSecretsInObject(manifest, "$"));

  if (manifest.manifest_version !== 1) {
    errors.push(`$.manifest_version: expected 1, got ${manifest.manifest_version}`);
  }
  if (typeof manifest.release_id !== "string" || manifest.release_id.length === 0) {
    errors.push("$.release_id: missing");
  }
  if (manifest.deployment_name !== profile.deployment_name) {
    errors.push(
      `$.deployment_name: mismatch ("${manifest.deployment_name}" !== "${profile.deployment_name}")`
    );
  }
  if (manifest.cpu_platform !== profile.cpu_platform) {
    errors.push(`$.cpu_platform: mismatch ("${manifest.cpu_platform}" !== "${profile.cpu_platform}")`);
  }
  if (manifest.profile_sha256 !== profileRes.profileSha256) {
    errors.push("$.profile_sha256: manifest does not match current deployment profile digest");
  }
  if (manifest.schema_revision !== profile.expected_schema_revision) {
    errors.push(
      `$.schema_revision: expected "${profile.expected_schema_revision}", got "${manifest.schema_revision}"`
    );
  }

  const { manifest_sha256: declaredDigest, ...bodyWithoutDigest } = manifest;
  const computedDigest = sha256Hex(canonicalizeJson(bodyWithoutDigest));
  if (declaredDigest !== computedDigest) {
    errors.push(
      `$.manifest_sha256: integrity mismatch (declared=${declaredDigest}, computed=${computedDigest})`
    );
  }

  for (const artifactKey of ["node_services", "console", "broker_launcher"]) {
    const ref = manifest.artifact_digests?.[artifactKey];
    const expectedRepo = profile.artifact_repositories?.[artifactKey];
    try {
      validatePinnedImageReference(ref, expectedRepo, artifactKey);
    } catch (err) {
      errors.push(err instanceof Error ? err.message : String(err));
    }
  }

  for (const [roleName, expectedCfgDigest] of Object.entries(profileRes.roleConfigDigests)) {
    const actualCfgDigest = manifest.config_digests?.[roleName];
    if (actualCfgDigest !== expectedCfgDigest) {
      errors.push(
        `$.config_digests.${roleName}: manifest digest differs from config file on disk`
      );
    }
  }

  const proto = manifest.protocol_compatibility ?? {};
  if (
    proto.http_schema_version !== 1 ||
    proto.broker_envelope_version !== 1 ||
    proto.webhook_signature_version !== 1
  ) {
    errors.push("$.protocol_compatibility: incompatible protocol version(s)");
  }

  let rollbackCompatible = null;
  if (options.previousManifestPath) {
    const prev = readStrictJsonFile(options.previousManifestPath);
    const prevProto = prev.protocol_compatibility ?? {};
    const listedCompatible =
      Array.isArray(manifest.compatible_previous_releases) &&
      manifest.compatible_previous_releases.includes(prev.release_id);
    const sameSchema = prev.schema_revision === manifest.schema_revision;
    const sameProto =
      prevProto.http_schema_version === proto.http_schema_version &&
      prevProto.broker_envelope_version === proto.broker_envelope_version &&
      prevProto.webhook_signature_version === proto.webhook_signature_version;

    rollbackCompatible = listedCompatible && sameProto && sameSchema;
    if (!rollbackCompatible) {
      errors.push(
        `Previous release "${prev.release_id}" is not declared rollback-compatible with "${manifest.release_id}"`
      );
    }
  }

  return {
    ok: errors.length === 0,
    release_id: manifest.release_id,
    manifest_sha256: declaredDigest,
    rollback_compatible: rollbackCompatible,
    errors
  };
}

runCliMain(import.meta.url, HELP_TEXT, (argv) => {
  const parsed = parseCliFlags(argv, {
    options: {
      "--config": { type: "string", required: true },
      "--manifest": { type: "string", required: true },
      "--previous-manifest": { type: "string" },
      "--root": { type: "string" },
      "--json": { type: "boolean", default: false }
    }
  });
  if (parsed.help) {
    return { help: true };
  }
  const report = verifyReleaseManifest({
    configPath: parsed.options["--config"],
    manifestPath: parsed.options["--manifest"],
    previousManifestPath: parsed.options["--previous-manifest"],
    rootDir: parsed.options["--root"]
  });
  if (!report.ok) {
    throw new CliError(
      `Manifest verification failed (${report.errors.length} error(s)):\n- ${report.errors.join("\n- ")}`,
      1
    );
  }
  if (parsed.options["--json"]) {
    return { exitCode: 0, output: report };
  }
  return {
    exitCode: 0,
    output: `[verify-manifest] ok release_id=${report.release_id} sha256=${report.manifest_sha256.slice(0, 12)}`
  };
});
