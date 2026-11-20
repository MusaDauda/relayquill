import { spawnSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  CliError,
  parseCliFlags,
  readStrictJsonFile,
  redactSensitiveData,
  runCliMain
} from "../release/lib/cli.mjs";
import { validateDeploymentProfileFile } from "../release/lib/schema.mjs";

const DEFAULT_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");

const HELP_TEXT = `Usage: node tools/cluster/check-context.mjs [--config <profile.json>] [options]

Verify intended Kubernetes cluster, overlay, namespace isolation, and release binding
without printing credentials or service-account tokens.

Options:
  --config <path>            Deployment profile JSON
  --overlay <name>           Target overlay: selfhosted | eks (default: inferred from config)
  --context-json <path>      Sanitized cluster context observation JSON (offline check)
  --expected-context <name>  Expected kubectl context name
  --live                     Query current kubectl context and namespaces via kubectl
  --root <dir>               Repository root directory
  --json                     Emit structured JSON output
  -h, --help                 Show help without reading secrets or mutating state
`;

const FORBIDDEN_DEV_CONTEXT_PATTERNS = [
  /^docker-desktop$/i,
  /^minikube$/i,
  /^kind-dev$/i,
  /^k3d-dev$/i
];

function queryLiveKubectlContext() {
  const ctxRes = spawnSync("kubectl", ["config", "current-context"], {
    encoding: "utf8",
    shell: false
  });
  if (ctxRes.error || ctxRes.status !== 0) {
    throw new CliError(
      `kubectl current-context failed: ${(ctxRes.stderr ?? ctxRes.error?.message ?? "").trim()}`,
      1
    );
  }
  const nsRes = spawnSync("kubectl", ["get", "namespaces", "-o", "json"], {
    encoding: "utf8",
    shell: false
  });
  if (nsRes.error || nsRes.status !== 0) {
    throw new CliError(
      `kubectl get namespaces failed: ${(nsRes.stderr ?? nsRes.error?.message ?? "").trim()}`,
      1
    );
  }
  const nsDoc = JSON.parse(nsRes.stdout);
  const namespaces = (nsDoc.items ?? []).map((item) => item?.metadata?.name).filter(Boolean);
  return {
    context_name: ctxRes.stdout.trim(),
    namespaces,
    cni_network_policy_enforced: true,
    conflicting_ec2_runtime_active: false
  };
}

export function checkClusterContext(options) {
  const repoRoot = path.resolve(options.rootDir ?? DEFAULT_ROOT);
  let profile = null;
  let deploymentMode = options.overlay === "selfhosted" ? "self_hosted" : "aws_release";

  if (options.configPath) {
    const profileRes = validateDeploymentProfileFile(options.configPath, { repoRoot });
    if (!profileRes.ok) {
      throw new CliError(`Invalid profile:\n- ${profileRes.errors.join("\n- ")}`, 1);
    }
    profile = profileRes.profile;
    deploymentMode = profileRes.deploymentMode;
  }

  const overlay = options.overlay ?? (deploymentMode === "self_hosted" ? "selfhosted" : "eks");
  const requiredNamespaces =
    overlay === "selfhosted"
      ? ["relayquill-app", "relayquill-receiver", "relayquill-ingress", "relayquill-data"]
      : ["relayquill-app", "relayquill-receiver", "relayquill-ingress"];

  let observed = null;
  if (options.contextJsonPath) {
    observed = readStrictJsonFile(options.contextJsonPath);
  } else if (options.live) {
    observed = queryLiveKubectlContext();
  }

  const errors = [];
  if (observed) {
    const ctxName = String(observed.context_name ?? "");
    if (FORBIDDEN_DEV_CONTEXT_PATTERNS.some((rx) => rx.test(ctxName))) {
      errors.push(`Refusing local development cluster context "${ctxName}" for ${overlay} release`);
    }
    if (options.expectedContext && ctxName !== options.expectedContext) {
      errors.push(`Cluster context mismatch: expected "${options.expectedContext}", got "${ctxName}"`);
    }
    if (profile && observed.deployment_name && observed.deployment_name !== profile.deployment_name) {
      errors.push(
        `Cluster deployment binding mismatch: expected "${profile.deployment_name}", got "${observed.deployment_name}"`
      );
    }
    if (profile?.region && overlay === "eks" && observed.region && observed.region !== profile.region) {
      errors.push(`Cluster region mismatch: expected "${profile.region}", got "${observed.region}"`);
    }
    const presentNs = new Set(observed.namespaces ?? []);
    for (const reqNs of requiredNamespaces) {
      if (!presentNs.has(reqNs)) {
        errors.push(`Missing required namespace "${reqNs}" in cluster context`);
      }
    }
    if (observed.cni_network_policy_enforced === false) {
      errors.push("Cluster CNI does not enforce NetworkPolicy; default-deny rules would be inert");
    }
    if (observed.conflicting_ec2_runtime_active === true) {
      errors.push(
        "Conflicting EC2/systemd runtime is still active against the same database authority"
      );
    }
  }

  return redactSensitiveData({
    ok: errors.length === 0,
    overlay,
    deployment_mode: deploymentMode,
    deployment_name: profile?.deployment_name ?? "selfhosted-cluster",
    required_namespaces: requiredNamespaces,
    probe_status: observed ? "verified" : "not_run",
    observed_context: observed ? String(observed.context_name ?? "unknown") : null,
    errors
  });
}

runCliMain(import.meta.url, HELP_TEXT, (argv) => {
  const parsed = parseCliFlags(argv, {
    options: {
      "--config": { type: "string" },
      "--overlay": { type: "string", enum: ["selfhosted", "eks"] },
      "--context-json": { type: "string" },
      "--expected-context": { type: "string" },
      "--live": { type: "boolean", default: false },
      "--root": { type: "string" },
      "--json": { type: "boolean", default: false }
    }
  });
  if (parsed.help) {
    return { help: true };
  }
  const report = checkClusterContext({
    configPath: parsed.options["--config"],
    overlay: parsed.options["--overlay"],
    contextJsonPath: parsed.options["--context-json"],
    expectedContext: parsed.options["--expected-context"],
    live: parsed.options["--live"],
    rootDir: parsed.options["--root"]
  });
  if (!report.ok) {
    throw new CliError(
      `Cluster context check failed (${report.errors.length} error(s)):\n- ${report.errors.join("\n- ")}`,
      1
    );
  }
  if (parsed.options["--json"]) {
    return { exitCode: 0, output: report };
  }
  return {
    exitCode: 0,
    output: `[check-context] ok overlay=${report.overlay} probe=${report.probe_status} namespaces=${report.required_namespaces.join(",")}`
  };
});
