import { spawnSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
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

const DEFAULT_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");

const HELP_TEXT = `Usage: node tools/release/build-manifest.mjs --config <profile.json> [options]

Build an immutable, digest-pinned release manifest binding source commit,
resolved container image digests (@sha256:...), role config digests, and schema compatibility.

Options:
  --config <path>                Deployment profile JSON (required)
  --images <path>                JSON file mapping node_services, console, broker_launcher to repo@sha256:...
  --image <name=ref>             Explicit artifact digest override (repeatable)
  --previous-manifest <path>     Previous deployed manifest JSON for explicit lineage
  --compatible-previous <id>     Compatible previous release_id (repeatable)
  --out <path>                   Output manifest JSON path
  --root <dir>                   Repository root directory
  --allow-dirty                  Allow dirty git working tree (for synthetic verification only)
  --resolve-remote               Resolve image tags via AWS ECR / Docker inspect when tag is given
  --tag <tag>                    Git commit or build tag to resolve with --resolve-remote
  --json                         Emit structured JSON output
  -h, --help                     Show help without reading secrets or mutating state
`;

const PINNED_DIGEST_REF_REGEX =
  /^[a-z0-9][a-z0-9._/-]*(?::[0-9]{1,5})?(?:\/[a-z0-9._-]+)+(?::[A-Za-z0-9_.-]+)?@sha256:[0-9a-f]{64}$/;

export function validatePinnedImageReference(ref, expectedRepoPrefix, label) {
  if (typeof ref !== "string" || ref.length === 0) {
    throw new CliError(`Missing pinned image digest for artifact "${label}"`, 1);
  }
  if (/:latest(?:@|$)/i.test(ref)) {
    throw new CliError(`Mutable :latest tag prohibited for artifact "${label}": ${ref}`, 1);
  }
  if (!PINNED_DIGEST_REF_REGEX.test(ref)) {
    throw new CliError(
      `Artifact "${label}" must be an immutable registry digest reference (<repo>@sha256:<64-hex>), got: ${ref}`,
      1
    );
  }
  if (expectedRepoPrefix) {
    const repoPart = ref.split("@")[0].replace(/:[^/]+$/, "");
    if (repoPart !== expectedRepoPrefix) {
      throw new CliError(
        `Artifact "${label}" repository mismatch: expected "${expectedRepoPrefix}", got "${repoPart}"`,
        1
      );
    }
  }
}

function readGitState(repoRoot) {
  const commitRes = spawnSync("git", ["rev-parse", "HEAD"], {
    cwd: repoRoot,
    encoding: "utf8",
    shell: false
  });
  const dirtyRes = spawnSync("git", ["status", "--porcelain"], {
    cwd: repoRoot,
    encoding: "utf8",
    shell: false
  });
  return {
    sourceCommit: commitRes.status === 0 ? commitRes.stdout.trim() : null,
    sourceDirty: dirtyRes.status === 0 ? dirtyRes.stdout.trim().length > 0 : true
  };
}

function resolveRemoteEcrDigest(repoUri, tag, region) {
  const match = /^(\d{12})\.dkr\.ecr\.([a-z0-9-]+)\.amazonaws\.com\/(.+)$/.exec(repoUri);
  if (!match) {
    return null;
  }
  const [, registryId, ecrRegion, repoName] = match;
  if (region && ecrRegion !== region) {
    throw new CliError(`ECR repository region "${ecrRegion}" mismatches profile region "${region}"`, 1);
  }
  const res = spawnSync(
    "aws",
    [
      "ecr",
      "describe-images",
      "--registry-id",
      registryId,
      "--repository-name",
      repoName,
      "--image-ids",
      `imageTag=${tag}`,
      "--region",
      ecrRegion,
      "--output",
      "json"
    ],
    { encoding: "utf8", shell: false }
  );
  if (res.error || res.status !== 0) {
    throw new CliError(
      `Failed to resolve ECR digest for ${repoUri}:${tag}: ${(res.stderr ?? res.error?.message ?? "").trim()}`,
      1
    );
  }
  const parsed = JSON.parse(res.stdout);
  const digest = parsed?.imageDetails?.[0]?.imageDigest;
  if (typeof digest !== "string" || !/^sha256:[0-9a-f]{64}$/.test(digest)) {
    throw new CliError(`ECR returned invalid digest for ${repoUri}:${tag}`, 1);
  }
  return `${repoUri}@${digest}`;
}

export function buildReleaseManifest(options) {
  const repoRoot = path.resolve(options.rootDir ?? DEFAULT_ROOT);
  const profileRes = validateDeploymentProfileFile(options.configPath, { repoRoot });
  if (!profileRes.ok) {
    throw new CliError(`Invalid profile:\n- ${profileRes.errors.join("\n- ")}`, 1);
  }
  const profile = profileRes.profile;
  const gitState = readGitState(repoRoot);
  if (!gitState.sourceCommit) {
    throw new CliError("Unable to resolve git source_commit (HEAD)", 1);
  }
  if (gitState.sourceDirty && !options.allowDirty) {
    throw new CliError(
      "Refusing to build release manifest from dirty working tree (commit changes or pass --allow-dirty for synthetic testing)",
      1
    );
  }

  const imageMap = {};
  if (options.imagesPath) {
    Object.assign(imageMap, readStrictJsonFile(options.imagesPath));
  }
  for (const item of options.imageOverrides ?? []) {
    const eqIdx = item.indexOf("=");
    if (eqIdx <= 0) {
      throw new CliError(`Invalid --image format "${item}"; expected <artifact>=<repo>@sha256:<hex>`, 1);
    }
    const name = item.slice(0, eqIdx).trim();
    const ref = item.slice(eqIdx + 1).trim();
    imageMap[name] = ref;
  }

  const artifactKeys = ["node_services", "console", "broker_launcher"];
  const artifactDigests = {};
  const tagToResolve = options.tag ?? gitState.sourceCommit;
  for (const key of artifactKeys) {
    const expectedRepo = profile.artifact_repositories?.[key];
    let resolvedRef = imageMap[key];
    if (!resolvedRef && options.resolveRemote && expectedRepo) {
      resolvedRef = resolveRemoteEcrDigest(expectedRepo, tagToResolve, profile.region);
    }
    validatePinnedImageReference(resolvedRef, expectedRepo, key);
    artifactDigests[key] = resolvedRef;
  }

  let previousManifestRef = null;
  const compatiblePrev = new Set(options.compatiblePrevious ?? []);
  if (options.previousManifestPath) {
    const prev = readStrictJsonFile(options.previousManifestPath);
    if (typeof prev.release_id !== "string" || typeof prev.manifest_sha256 !== "string") {
      throw new CliError("Previous manifest missing release_id or manifest_sha256", 1);
    }
    previousManifestRef = {
      release_id: prev.release_id,
      manifest_sha256: prev.manifest_sha256
    };
    compatiblePrev.add(prev.release_id);
  }

  const topologyPath = path.join(repoRoot, "infra", "broker", "public-topology.json");
  const brokerTopologyDigest = fs.existsSync(topologyPath)
    ? sha256Hex(fs.readFileSync(topologyPath))
    : profileRes.roleConfigDigests.relay ?? null;

  const firstRoleCfg = Object.values(profileRes.roleConfigs)[0] ?? {};
  const protocol = firstRoleCfg.protocol ?? {
    http_schema_version: 1,
    broker_envelope_version: 1,
    webhook_signature_version: 1
  };

  const releaseId = options.releaseId ?? `rel-${gitState.sourceCommit.slice(0, 12)}-${crypto.randomUUID().slice(0, 8)}`;
  const body = {
    manifest_version: 1,
    release_id: releaseId,
    created_at: new Date().toISOString(),
    deployment_name: profile.deployment_name,
    deployment_mode: profileRes.deploymentMode,
    region: profile.region ?? "self-hosted",
    cpu_platform: profile.cpu_platform,
    source_commit: gitState.sourceCommit,
    source_dirty: Boolean(gitState.sourceDirty),
    profile_sha256: profileRes.profileSha256,
    artifact_digests: artifactDigests,
    config_digests: profileRes.roleConfigDigests,
    schema_revision: profile.expected_schema_revision,
    broker_config_digest: brokerTopologyDigest,
    sdk_contract_revision: 1,
    protocol_compatibility: {
      http_schema_version: protocol.http_schema_version,
      broker_envelope_version: protocol.broker_envelope_version,
      webhook_signature_version: protocol.webhook_signature_version
    },
    compatible_previous_releases: Array.from(compatiblePrev).sort(),
    previous_manifest_ref: previousManifestRef
  };

  const manifest = redactSensitiveData({
    ...body,
    manifest_sha256: sha256Hex(canonicalizeJson(body))
  });

  const outPath = options.outPath
    ? path.resolve(options.outPath)
    : path.resolve(repoRoot, profile.release_record_directory, `manifest-${releaseId}.json`);
  fs.mkdirSync(path.dirname(outPath), { recursive: true });
  fs.writeFileSync(outPath, `${JSON.stringify(manifest, null, 2)}\n`, "utf8");

  return { ok: true, outPath, manifest };
}

runCliMain(import.meta.url, HELP_TEXT, (argv) => {
  const parsed = parseCliFlags(argv, {
    options: {
      "--config": { type: "string", required: true },
      "--images": { type: "string" },
      "--image": { type: "string", multiple: true },
      "--previous-manifest": { type: "string" },
      "--compatible-previous": { type: "string", multiple: true },
      "--out": { type: "string" },
      "--root": { type: "string" },
      "--allow-dirty": { type: "boolean", default: false },
      "--resolve-remote": { type: "boolean", default: false },
      "--tag": { type: "string" },
      "--json": { type: "boolean", default: false }
    }
  });
  if (parsed.help) {
    return { help: true };
  }
  const res = buildReleaseManifest({
    configPath: parsed.options["--config"],
    imagesPath: parsed.options["--images"],
    imageOverrides: parsed.options["--image"],
    previousManifestPath: parsed.options["--previous-manifest"],
    compatiblePrevious: parsed.options["--compatible-previous"],
    outPath: parsed.options["--out"],
    rootDir: parsed.options["--root"],
    allowDirty: parsed.options["--allow-dirty"],
    resolveRemote: parsed.options["--resolve-remote"],
    tag: parsed.options["--tag"]
  });
  if (parsed.options["--json"]) {
    return { exitCode: 0, output: res.manifest };
  }
  return {
    exitCode: 0,
    output: `[build-manifest] ok release_id=${res.manifest.release_id} sha256=${res.manifest.manifest_sha256.slice(0, 12)} out=${res.outPath}`
  };
});
