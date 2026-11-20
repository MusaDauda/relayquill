import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  CliError,
  findRawSecretsInObject,
  hasForbiddenRawSecretValue,
  parseCliFlags,
  parseStrictJson,
  redactSensitiveData,
  runCliMain
} from "../release/lib/cli.mjs";
import { loadConfigSchemas, validateRoleConfigObject } from "../release/lib/schema.mjs";
import { loadKustomizeDirectory, parseYamlDocuments } from "./lib/yaml.mjs";

const DEFAULT_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");

const HELP_TEXT = `Usage: node tools/cluster/validate-rendered.mjs [options]

Parse rendered Kustomize YAML or infra/kubernetes/ manifests (base, overlays/selfhosted,
overlays/eks, jobs) and enforce container security, non-root execution, read-only rootfs,
dropped capabilities, no embedded Secret values, no dev trust settings, and image digest rules.

Options:
  --rendered <path>           Validate a rendered multi-document YAML file (enforces no :latest)
  --target <dir-or-file>      Validate specific directory or YAML manifest (repeatable)
  --overlay <name>            Validate named overlay: base | selfhosted | eks | jobs | all
  --config <path>             Optional deployment profile JSON
  --require-digests           Require @sha256:<64-hex> digest on every container image
  --allow-template-images     Allow unpinned template tags when scanning synthetic directory templates
  --root <dir>                Repository root directory
  --json                      Emit structured JSON output
  -h, --help                  Show help without reading secrets or mutating state
`;

const WORKLOAD_KINDS = new Set(["Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob", "Pod"]);
const INTERNAL_ONLY_SERVICES = new Set([
  "relayquill-relay-health",
  "relayquill-fanout-health",
  "relayquill-sender-health",
  "relayquill-coordinator-health",
  "relayquill-postgres",
  "relayquill-postgres-headless",
  "relayquill-broker",
  "relayquill-broker-headless"
]);

const FORBIDDEN_DEV_PROFILES = new Set(["portable_pglite", "development_trusted_local"]);
const FORBIDDEN_DEV_DB_MODES = new Set(["portable_pglite", "development_trusted_local"]);
const FORBIDDEN_DEV_BROKER_MODES = new Set(["in_memory_test", "development_loopback", "embedded_go_tls"]);

function extractPodSpec(doc) {
  if (doc.kind === "Pod") {
    return doc.spec;
  }
  if (doc.kind === "CronJob") {
    return doc.spec?.jobTemplate?.spec?.template?.spec;
  }
  return doc.spec?.template?.spec;
}

function checkImageReference(image, label, options, violations, unpinnedImages) {
  if (typeof image !== "string" || image.trim().length === 0) {
    violations.push(`${label}: missing container image`);
    return;
  }
  const hasLatest = /:latest(?:@|$)/i.test(image) || (!image.includes(":") && !image.includes("@sha256:"));
  const hasDigest = /@sha256:[0-9a-f]{64}$/.test(image);

  if (!hasDigest) {
    unpinnedImages.push({ location: label, image });
  }

  if (options.rejectLatest && hasLatest) {
    violations.push(`${label}: mutable or :latest image tag is prohibited (${image})`);
  } else if (options.requireDigests && !hasDigest) {
    violations.push(`${label}: immutable @sha256:<64-hex> image digest required (${image})`);
  }
}

function validateWorkloadSecurity(doc, docId, options, violations, unpinnedImages) {
  const podSpec = extractPodSpec(doc);
  if (!podSpec || typeof podSpec !== "object") {
    violations.push(`${docId}: missing pod template spec`);
    return;
  }

  if (podSpec.hostNetwork === true) {
    violations.push(`${docId}: hostNetwork=true is forbidden`);
  }
  if (podSpec.hostPID === true) {
    violations.push(`${docId}: hostPID=true is forbidden`);
  }
  if (podSpec.hostIPC === true) {
    violations.push(`${docId}: hostIPC=true is forbidden`);
  }

  const podSec = podSpec.securityContext ?? {};
  const podRunAsNonRoot = podSec.runAsNonRoot === true;
  const podRunAsUser = podSec.runAsUser;
  const podRunAsGroup = podSec.runAsGroup;
  const podSeccomp = podSec.seccompProfile?.type;

  if (podSec.runAsNonRoot === false) {
    violations.push(`${docId}: pod securityContext.runAsNonRoot=false is forbidden`);
  }
  if (typeof podRunAsUser === "number" && podRunAsUser <= 0) {
    violations.push(`${docId}: pod securityContext.runAsUser must be non-root (> 0), got ${podRunAsUser}`);
  }
  if (typeof podRunAsGroup === "number" && podRunAsGroup <= 0) {
    violations.push(`${docId}: pod securityContext.runAsGroup must be non-root (> 0), got ${podRunAsGroup}`);
  }

  for (const vol of podSpec.volumes ?? []) {
    if (vol?.hostPath?.path) {
      const hp = String(vol.hostPath.path);
      if (hp.includes("docker.sock") || hp === "/" || hp.startsWith("/etc") || hp.startsWith("/var/run")) {
        violations.push(`${docId}: forbidden hostPath mount "${hp}" on volume "${vol.name}"`);
      }
    }
  }

  const allContainers = [
    ...(Array.isArray(podSpec.initContainers) ? podSpec.initContainers : []),
    ...(Array.isArray(podSpec.containers) ? podSpec.containers : [])
  ];
  if (allContainers.length === 0) {
    violations.push(`${docId}: workload defines zero containers`);
    return;
  }

  for (const container of allContainers) {
    const cName = String(container?.name ?? "unnamed");
    const cLabel = `${docId}/container:${cName}`;
    const cSec = container?.securityContext ?? {};

    checkImageReference(container?.image, cLabel, options, violations, unpinnedImages);

    const effectiveNonRoot = cSec.runAsNonRoot === true || (cSec.runAsNonRoot !== false && podRunAsNonRoot);
    if (!effectiveNonRoot) {
      violations.push(`${cLabel}: runAsNonRoot=true required on pod or container`);
    }

    const effectiveUser = cSec.runAsUser ?? podRunAsUser;
    if (typeof effectiveUser !== "number" || effectiveUser <= 0) {
      violations.push(`${cLabel}: explicit non-root runAsUser (> 0) required, got ${effectiveUser}`);
    }

    const effectiveSeccomp = cSec.seccompProfile?.type ?? podSeccomp;
    if (effectiveSeccomp !== "RuntimeDefault") {
      violations.push(`${cLabel}: seccompProfile.type="RuntimeDefault" required`);
    }

    if (cSec.privileged === true) {
      violations.push(`${cLabel}: privileged=true is forbidden`);
    }
    if (cSec.allowPrivilegeEscalation !== false) {
      violations.push(`${cLabel}: allowPrivilegeEscalation=false is required`);
    }
    if (cSec.readOnlyRootFilesystem !== true) {
      violations.push(`${cLabel}: readOnlyRootFilesystem=true is required`);
    }

    const dropped = Array.isArray(cSec.capabilities?.drop)
      ? cSec.capabilities.drop.map((x) => String(x).toUpperCase())
      : [];
    if (!dropped.includes("ALL")) {
      violations.push(`${cLabel}: securityContext.capabilities.drop must include "ALL"`);
    }
    const added = Array.isArray(cSec.capabilities?.add) ? cSec.capabilities.add : [];
    if (added.length > 0) {
      violations.push(`${cLabel}: securityContext.capabilities.add is forbidden (${added.join(",")})`);
    }

    for (const envEntry of container?.env ?? []) {
      const envName = String(envEntry?.name ?? "");
      const envVal = envEntry?.value;
      if (envName === "RELAYQUILL_ENV" && typeof envVal === "string") {
        if (/^(?:dev|development|test|local)$/i.test(envVal)) {
          violations.push(`${cLabel}: forbidden development RELAYQUILL_ENV="${envVal}"`);
        }
      }
      if (typeof envVal === "string" && hasForbiddenRawSecretValue(envVal)) {
        violations.push(`${cLabel}: raw secret literal in env "${envName}"`);
      }
      if (
        /(?:PASSWORD|SECRET|PRIVATE_KEY|NKEY_SEED|TOKEN|SESSION_HMAC)$/i.test(envName) &&
        !/_(?:FILE|REF|DIR|PATH)$/i.test(envName) &&
        typeof envVal === "string" &&
        envVal.length > 0
      ) {
        violations.push(`${cLabel}: inline secret value in env "${envName}" is forbidden`);
      }
    }
  }
}

function validateConfigMapData(doc, docId, repoRoot, schemas, violations) {
  const data = doc.data ?? {};
  for (const [key, rawVal] of Object.entries(data)) {
    if (typeof rawVal !== "string") {
      continue;
    }
    if (hasForbiddenRawSecretValue(rawVal)) {
      violations.push(`${docId} data[${key}]: contains forbidden raw secret literal`);
    }
    if (key.endsWith(".json")) {
      let parsed;
      try {
        parsed = parseStrictJson(rawVal, `${docId}:${key}`);
      } catch (err) {
        violations.push(`${docId} data[${key}]: ${err instanceof Error ? err.message : String(err)}`);
        continue;
      }
      for (const f of findRawSecretsInObject(parsed, `${docId}:${key}`)) {
        violations.push(f);
      }

      if (parsed.process_role && parsed.profile) {
        if (FORBIDDEN_DEV_PROFILES.has(parsed.profile)) {
          violations.push(`${docId} data[${key}]: forbidden development profile "${parsed.profile}"`);
        }
        if (FORBIDDEN_DEV_DB_MODES.has(parsed.database?.mode)) {
          violations.push(`${docId} data[${key}]: forbidden development database.mode "${parsed.database?.mode}"`);
        }
        if (
          parsed.database?.authentication === "trusted_local_only" ||
          parsed.database?.authentication === "in_process_pglite"
        ) {
          violations.push(
            `${docId} data[${key}]: forbidden development database.authentication "${parsed.database.authentication}"`
          );
        }
        if (parsed.database?.tls_mode && parsed.database.tls_mode !== "verify_full") {
          violations.push(`${docId} data[${key}]: database.tls_mode must be "verify_full"`);
        }
        if (FORBIDDEN_DEV_BROKER_MODES.has(parsed.broker?.mode)) {
          violations.push(`${docId} data[${key}]: forbidden development broker.mode "${parsed.broker?.mode}"`);
        }
        if (parsed.broker?.auth_mode === "none_fixture") {
          violations.push(`${docId} data[${key}]: forbidden broker.auth_mode="none_fixture"`);
        }
        if (parsed.egress?.allow_fixture_receiver === true || parsed.egress?.mode === "trusted_local_fixture") {
          violations.push(`${docId} data[${key}]: fixture receiver egress is forbidden in cluster manifests`);
        }
        if (parsed.auth?.cookie_profile === "development_only") {
          violations.push(`${docId} data[${key}]: auth.cookie_profile="development_only" is forbidden`);
        }
        const roleErrs = validateRoleConfigObject(parsed, {
          repoRoot,
          schemas,
          requireProductionProfile: true
        });
        for (const e of roleErrs) {
          violations.push(`${docId} data[${key}]: ${e}`);
        }
      }
    }
  }
}

export function validateManifestDocuments(documents, options = {}) {
  const repoRoot = path.resolve(options.repoRoot ?? DEFAULT_ROOT);
  const schemas = options.schemas ?? loadConfigSchemas(repoRoot);
  const violations = [];
  const unpinnedImages = [];
  let workloadsChecked = 0;
  let configMapsChecked = 0;
  let networkPoliciesChecked = 0;

  for (const rule of options.imageRules ?? []) {
    if (rule?.newTag === "latest" || /:latest$/i.test(String(rule?.newName ?? ""))) {
      violations.push(`Kustomization images override explicitly sets mutable :latest tag for "${rule.name}"`);
    }
  }

  for (const doc of documents) {
    if (!doc || typeof doc !== "object") {
      continue;
    }
    const kind = String(doc.kind ?? "Unknown");
    const ns = doc.metadata?.namespace ? `${doc.metadata.namespace}/` : "";
    const name = String(doc.metadata?.name ?? "unnamed");
    const docId = `${kind}:${ns}${name}`;

    if (kind === "Secret") {
      const hasData =
        (doc.data && Object.keys(doc.data).length > 0) ||
        (doc.stringData && Object.keys(doc.stringData).length > 0);
      violations.push(
        hasData
          ? `${docId}: embedded Secret manifest with secret data is forbidden in repository/rendered output`
          : `${docId}: Secret manifest is forbidden in rendered output; provision secrets out-of-band`
      );
      continue;
    }

    if (WORKLOAD_KINDS.has(kind)) {
      workloadsChecked += 1;
      validateWorkloadSecurity(doc, docId, options, violations, unpinnedImages);
      continue;
    }

    if (kind === "ConfigMap") {
      configMapsChecked += 1;
      validateConfigMapData(doc, docId, repoRoot, schemas, violations);
      continue;
    }

    if (kind === "Service") {
      const svcType = String(doc.spec?.type ?? "ClusterIP");
      if (INTERNAL_ONLY_SERVICES.has(name) && (svcType === "LoadBalancer" || svcType === "NodePort")) {
        violations.push(`${docId}: internal service "${name}" must not be exposed as ${svcType}`);
      }
      continue;
    }

    if (kind === "NetworkPolicy") {
      networkPoliciesChecked += 1;
    }
  }

  if (options.requireOverlayTopology) {
    if (networkPoliciesChecked === 0) {
      violations.push("Overlay is missing NetworkPolicy definitions");
    }
  }

  return {
    ok: violations.length === 0,
    documents_checked: documents.length,
    workloads_checked: workloadsChecked,
    config_maps_checked: configMapsChecked,
    network_policies_checked: networkPoliciesChecked,
    unpinned_image_count: unpinnedImages.length,
    unpinned_images: unpinnedImages,
    violations
  };
}

function isInsideRepoKubernetesTree(repoRoot, targetPath) {
  const k8sRoot = path.join(path.resolve(repoRoot), "infra", "kubernetes");
  const resolvedTarget = path.resolve(targetPath);
  const rel = path.relative(k8sRoot, resolvedTarget);
  return rel === "" || (!rel.startsWith("..") && !path.isAbsolute(rel));
}

export function validateRenderedOrOverlays(options = {}) {
  const repoRoot = path.resolve(options.rootDir ?? DEFAULT_ROOT);
  const schemas = loadConfigSchemas(repoRoot);
  const targetResults = [];
  const allViolations = [];

  if (options.renderedPath) {
    const resolved = path.resolve(options.renderedPath);
    if (!fs.existsSync(resolved)) {
      throw new CliError(`Rendered YAML file not found: ${resolved}`, 1);
    }
    const docs = parseYamlDocuments(fs.readFileSync(resolved, "utf8"), resolved);
    const res = validateManifestDocuments(docs, {
      repoRoot,
      schemas,
      rejectLatest: !options.allowTemplateImages,
      requireDigests: Boolean(options.requireDigests || options.configPath),
      requireOverlayTopology: false
    });
    targetResults.push({ target: resolved, mode: "rendered", ...res });
    allViolations.push(...res.violations.map((v) => `[${resolved}] ${v}`));
  } else {
    let targets = [];
    if (Array.isArray(options.targets) && options.targets.length > 0) {
      targets = options.targets.map((t) => path.resolve(t));
    } else {
      const overlayChoice = options.overlay ?? "all";
      const k8sDir = path.join(repoRoot, "infra", "kubernetes");
      if (overlayChoice === "base") {
        targets = [path.join(k8sDir, "base")];
      } else if (overlayChoice === "selfhosted") {
        targets = [path.join(k8sDir, "overlays", "selfhosted")];
      } else if (overlayChoice === "eks") {
        targets = [path.join(k8sDir, "overlays", "eks")];
      } else if (overlayChoice === "jobs") {
        targets = [path.join(k8sDir, "jobs")];
      } else {
        targets = [
          path.join(k8sDir, "base"),
          path.join(k8sDir, "overlays", "selfhosted"),
          path.join(k8sDir, "overlays", "eks"),
          path.join(k8sDir, "jobs")
        ];
      }
    }

    for (const targetPath of targets) {
      if (!fs.existsSync(targetPath)) {
        throw new CliError(`Manifest target path not found: ${targetPath}`, 1);
      }
      const stat = fs.statSync(targetPath);
      const isRepoTemplate = isInsideRepoKubernetesTree(repoRoot, targetPath);
      const loaded = stat.isDirectory()
        ? loadKustomizeDirectory(targetPath)
        : {
            documents: parseYamlDocuments(fs.readFileSync(targetPath, "utf8"), targetPath),
            imageRules: []
          };

      // Reject :latest automatically on rendered/synthetic targets or when --require-digests is set;
      // allow pre-pinning repo template directories unless --require-digests is passed.
      const rejectLatest =
        Boolean(options.requireDigests) ||
        (!isRepoTemplate && !options.allowTemplateImages);

      const res = validateManifestDocuments(loaded.documents, {
        repoRoot,
        schemas,
        imageRules: loaded.imageRules,
        rejectLatest,
        requireDigests: Boolean(options.requireDigests),
        requireOverlayTopology: stat.isDirectory() && !targetPath.endsWith("jobs")
      });

      const relLabel = path.relative(repoRoot, targetPath).replace(/\\/g, "/") || targetPath;
      targetResults.push({
        target: relLabel,
        mode: isRepoTemplate && !options.requireDigests ? "template" : "strict",
        ...res
      });
      allViolations.push(...res.violations.map((v) => `[${relLabel}] ${v}`));
    }
  }

  return redactSensitiveData({
    ok: allViolations.length === 0,
    targets_checked: targetResults.length,
    targets: targetResults,
    violations: allViolations
  });
}

runCliMain(import.meta.url, HELP_TEXT, (argv) => {
  const parsed = parseCliFlags(argv, {
    options: {
      "--rendered": { type: "string" },
      "--target": { type: "string", multiple: true },
      "--overlay": {
        type: "string",
        enum: ["base", "selfhosted", "eks", "jobs", "all"]
      },
      "--config": { type: "string" },
      "--require-digests": { type: "boolean", default: false },
      "--allow-template-images": { type: "boolean", default: false },
      "--root": { type: "string" },
      "--json": { type: "boolean", default: false }
    }
  });
  if (parsed.help) {
    return { help: true };
  }

  const report = validateRenderedOrOverlays({
    renderedPath: parsed.options["--rendered"],
    targets: parsed.options["--target"],
    overlay: parsed.options["--overlay"],
    configPath: parsed.options["--config"],
    requireDigests: parsed.options["--require-digests"],
    allowTemplateImages: parsed.options["--allow-template-images"],
    rootDir: parsed.options["--root"]
  });

  if (!report.ok) {
    throw new CliError(
      `Manifest validation failed (${report.violations.length} violation(s)):\n- ${report.violations.join("\n- ")}`,
      1
    );
  }
  if (parsed.options["--json"]) {
    return { exitCode: 0, output: report };
  }
  const summaryParts = report.targets.map(
    (t) => `${t.target}(docs=${t.documents_checked},workloads=${t.workloads_checked},mode=${t.mode})`
  );
  return {
    exitCode: 0,
    output: `[validate-rendered] ok ${summaryParts.join(" ")}`
  };
});
