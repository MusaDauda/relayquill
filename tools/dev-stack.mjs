import { spawn, spawnSync } from "node:child_process";
import fs from "node:fs";
import net from "node:net";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";
import { isMainModule } from "./lib/workspaces.mjs";

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

export const DEV_STACK_PROFILES = Object.freeze(["full", "core", "api-only", "examples"]);

export const DEV_STACK_HELP_TEXT = `Relayquill Local Development Stack Coordinator

Usage:
  node tools/dev-stack.mjs [options]

Options:
  --profile <name>         Startup profile: full | core | api-only | examples (default: full)
  --env-file <path>        Path to .env file (default: .env if present, fallback .env.example)
  --dry-run                Validate paths/env/ports and print resolved startup plan without spawning
  --no-broker              Do not launch local NATS JetStream broker process
  --no-console             Do not launch Vite console dev server
  --no-examples            Exclude examples/receiver and examples/provider-ingress
  --with-examples          Include examples/receiver and examples/provider-ingress
  --postgres-check <mode>  Check local PostgreSQL TCP port: auto | require | skip (default: auto)
  --stop-timeout-ms <ms>   Graceful SIGTERM timeout per process in ms (default: 5000)
  -h, --help               Show this help message
`;

const SECRET_KEY_PATTERN = /(SECRET|PASSWORD|PASS|TOKEN|NKEY|SEED|KEY_PEM|CRED)/i;

/**
 * Redacts userinfo credentials in connection URLs and suppresses secret-bearing env values.
 */
export function redactDisplayValue(key, value) {
  if (value === undefined || value === null || value === "") {
    return "(unset)";
  }
  const str = String(value);
  if (/^postgres(?:ql)?:\/\//i.test(str) || /^nats(?:s|tls)?:\/\//i.test(str)) {
    return str.replace(/:\/\/([^/:@\s]+):([^/@\s]+)@/g, "://$1:[REDACTED]@");
  }
  if (SECRET_KEY_PATTERN.test(key)) {
    return `[REDACTED:${str.length}ch]`;
  }
  return str;
}

/**
 * Parses a standard .env file without mutating existing parent process overrides.
 */
export function parseDotEnvText(text) {
  const result = {};
  const lines = text.split(/\r?\n/);
  for (const rawLine of lines) {
    const trimmed = rawLine.trim();
    if (trimmed.length === 0 || trimmed.startsWith("#")) {
      continue;
    }
    const withoutExport = trimmed.startsWith("export ") ? trimmed.slice(7).trim() : trimmed;
    const eqIdx = withoutExport.indexOf("=");
    if (eqIdx <= 0) {
      continue;
    }
    const key = withoutExport.slice(0, eqIdx).trim();
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(key)) {
      continue;
    }
    let val = withoutExport.slice(eqIdx + 1).trim();
    if (
      (val.startsWith('"') && val.endsWith('"') && val.length >= 2) ||
      (val.startsWith("'") && val.endsWith("'") && val.length >= 2)
    ) {
      val = val.slice(1, -1);
    } else {
      const commentIdx = val.indexOf(" #");
      if (commentIdx >= 0) {
        val = val.slice(0, commentIdx).trim();
      }
    }
    result[key] = val;
  }
  return result;
}

export function loadStackEnv(envFilePath, baseEnv = process.env) {
  const explicitPath =
    typeof envFilePath === "string" && envFilePath.trim().length > 0
      ? path.resolve(REPO_ROOT, envFilePath.trim())
      : null;
  const dotEnvPath = path.join(REPO_ROOT, ".env");
  const exampleEnvPath = path.join(REPO_ROOT, ".env.example");

  let selectedEnvFile = null;
  if (explicitPath !== null) {
    if (!fs.existsSync(explicitPath)) {
      throw new Error(`Specified --env-file not found: ${explicitPath}`);
    }
    selectedEnvFile = explicitPath;
  } else if (fs.existsSync(dotEnvPath)) {
    selectedEnvFile = dotEnvPath;
  } else if (fs.existsSync(exampleEnvPath)) {
    selectedEnvFile = exampleEnvPath;
  }

  const fileVars =
    selectedEnvFile !== null ? parseDotEnvText(fs.readFileSync(selectedEnvFile, "utf8")) : {};

  const merged = {
    ...fileVars,
    RELAYQUILL_ENV: baseEnv["RELAYQUILL_ENV"] ?? fileVars["RELAYQUILL_ENV"] ?? "development",
    DATABASE_URL:
      baseEnv["DATABASE_URL"] ??
      fileVars["DATABASE_URL"] ??
      "postgres://rq_api@127.0.0.1:55005/relayquill",
    DIRECT_DATABASE_URL:
      baseEnv["DIRECT_DATABASE_URL"] ??
      fileVars["DIRECT_DATABASE_URL"] ??
      "postgres://rq_migrator@127.0.0.1:55005/relayquill",
    RECEIVER_DATABASE_URL:
      baseEnv["RECEIVER_DATABASE_URL"] ??
      fileVars["RECEIVER_DATABASE_URL"] ??
      "postgres://receiver_runtime@127.0.0.1:55005/relayquill_receiver",
    PROVIDER_INGRESS_DATABASE_URL:
      baseEnv["PROVIDER_INGRESS_DATABASE_URL"] ??
      fileVars["PROVIDER_INGRESS_DATABASE_URL"] ??
      "postgres://provider_runtime@127.0.0.1:55005/relayquill_provider",
    NATS_URL: baseEnv["NATS_URL"] ?? fileVars["NATS_URL"] ?? "nats://127.0.0.1:14225",
    PUBLIC_CONSOLE_ORIGIN:
      baseEnv["PUBLIC_CONSOLE_ORIGIN"] ??
      fileVars["PUBLIC_CONSOLE_ORIGIN"] ??
      "http://localhost:5205",
    PUBLIC_API_ORIGIN:
      baseEnv["PUBLIC_API_ORIGIN"] ?? fileVars["PUBLIC_API_ORIGIN"] ?? "http://localhost:8005",
    WEBAUTHN_RP_ID: baseEnv["WEBAUTHN_RP_ID"] ?? fileVars["WEBAUTHN_RP_ID"] ?? "localhost"
  };

  for (const [k, v] of Object.entries(baseEnv)) {
    if (v !== undefined) {
      merged[k] = v;
    }
  }

  return { selectedEnvFile, env: merged };
}

export function parseDevStackArgs(argv) {
  let profile = "full";
  let envFilePath;
  let dryRun = false;
  let help = false;
  let includeBroker = true;
  let includeConsole;
  let includeExamples;
  let postgresCheck = "auto";
  let stopTimeoutMs = 5000;

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === undefined) {
      continue;
    }
    if (arg === "--help" || arg === "-h") {
      help = true;
      continue;
    }
    if (arg === "--dry-run") {
      dryRun = true;
      continue;
    }
    if (arg === "--no-broker") {
      includeBroker = false;
      continue;
    }
    if (arg === "--no-console") {
      includeConsole = false;
      continue;
    }
    if (arg === "--no-examples") {
      includeExamples = false;
      continue;
    }
    if (arg === "--with-examples") {
      includeExamples = true;
      continue;
    }
    if (arg === "--profile") {
      profile = argv[i + 1] ?? "";
      i += 1;
      continue;
    }
    if (arg === "--env-file") {
      envFilePath = argv[i + 1] ?? "";
      i += 1;
      continue;
    }
    if (arg === "--postgres-check") {
      postgresCheck = argv[i + 1] ?? "auto";
      i += 1;
      continue;
    }
    if (arg === "--stop-timeout-ms") {
      stopTimeoutMs = Number(argv[i + 1] ?? "5000");
      i += 1;
      continue;
    }
    throw new Error(`Unknown CLI argument: ${arg}`);
  }

  if (!DEV_STACK_PROFILES.includes(profile)) {
    throw new Error(
      `Invalid --profile "${profile}". Expected one of: ${DEV_STACK_PROFILES.join(", ")}`
    );
  }
  if (!["auto", "require", "skip"].includes(postgresCheck)) {
    throw new Error(`Invalid --postgres-check "${postgresCheck}". Expected auto, require, or skip`);
  }
  if (!Number.isFinite(stopTimeoutMs) || stopTimeoutMs < 500 || stopTimeoutMs > 60000) {
    throw new Error(`Invalid --stop-timeout-ms "${String(stopTimeoutMs)}" (expected 500..60000)`);
  }

  const effectiveConsole = includeConsole ?? (profile === "full" || profile === "examples");
  const effectiveExamples = includeExamples ?? (profile === "full" || profile === "examples");
  const effectiveBroker = includeBroker && profile !== "api-only";

  return {
    profile,
    envFilePath,
    dryRun,
    help,
    includeBroker: effectiveBroker,
    includeConsole: effectiveConsole,
    includeExamples: effectiveExamples,
    postgresCheck,
    stopTimeoutMs
  };
}

function parseHostPortFromUrl(rawUrl, defaultHost, defaultPort) {
  try {
    const u = new URL(rawUrl);
    return {
      host: u.hostname || defaultHost,
      port: u.port ? Number(u.port) : defaultPort
    };
  } catch {
    return { host: defaultHost, port: defaultPort };
  }
}

export function checkTcpPortOpen(host, port, timeoutMs = 800) {
  return new Promise((resolve) => {
    const socket = net.createConnection({ host, port });
    let done = false;
    const finish = (ok) => {
      if (!done) {
        done = true;
        socket.destroy();
        resolve(ok);
      }
    };
    socket.setTimeout(timeoutMs);
    socket.once("connect", () => finish(true));
    socket.once("timeout", () => finish(false));
    socket.once("error", () => finish(false));
  });
}

function detectBrokerLauncherSpec() {
  const exeSuffix = process.platform === "win32" ? ".exe" : "";
  const prebuilt = path.join(REPO_ROOT, "tools", "broker-launcher", `relayquill-broker${exeSuffix}`);
  const topologyPath = path.join(REPO_ROOT, "infra", "broker", "public-topology.json");
  if (fs.existsSync(prebuilt)) {
    return {
      mode: "binary",
      command: prebuilt,
      args: ["serve", "--topology", topologyPath],
      cwd: path.join(REPO_ROOT, "tools", "broker-launcher")
    };
  }
  const goCheck = spawnSync("go", ["version"], { encoding: "utf8", shell: false });
  if (goCheck.status === 0) {
    return {
      mode: "go-run",
      command: "go",
      args: ["run", "./cmd/relayquill-broker", "serve", "--topology", topologyPath],
      cwd: path.join(REPO_ROOT, "tools", "broker-launcher")
    };
  }
  return null;
}

export function buildProcessSpecs(options, env) {
  const specs = [];
  const brokerDir = path.join(REPO_ROOT, "tools", "broker-launcher");
  const viteBin = path.join(REPO_ROOT, "node_modules", "vite", "bin", "vite.js");
  const npmBin = process.platform === "win32" ? "npm.cmd" : "npm";
  const natsEndpoint = parseHostPortFromUrl(env["NATS_URL"] ?? "", "127.0.0.1", 14225);

  if (options.includeBroker) {
    const detected = detectBrokerLauncherSpec();
    specs.push({
      id: "broker",
      kind: "broker",
      requiredBuildArtifact: path.join(brokerDir, "cmd", "relayquill-broker", "main.go"),
      command: detected?.command ?? "go",
      args: detected?.args ?? [
        "run",
        "./cmd/relayquill-broker",
        "serve",
        "--topology",
        path.join(REPO_ROOT, "infra", "broker", "public-topology.json"),
        "--host",
        natsEndpoint.host,
        "--client-port",
        String(natsEndpoint.port)
      ],
      cwd: brokerDir,
      available: detected !== null,
      startupNote:
        detected === null
          ? "Go toolchain/binary unavailable; run docker compose -f infra/compose.dev.yaml up -d broker"
          : `Using ${detected.mode}`
    });
  }

  specs.push({
    id: "admin-provider",
    kind: "node",
    command: process.execPath,
    args: [
      "--enable-source-maps",
      path.join(REPO_ROOT, "apps", "admin", "dist", "main.js"),
      "provider",
      "serve",
      "--config",
      path.join(REPO_ROOT, "config", "development.provider.json"),
      "--seed-dev"
    ],
    requiredBuildArtifact: path.join(REPO_ROOT, "apps", "admin", "dist", "main.js"),
    cwd: REPO_ROOT,
    available: true
  });

  if (options.profile !== "api-only") {
    for (const [id, pkgDir, cfgName] of [
      ["coordinator", "apps/coordinator", "development.coordinator.json"],
      ["relay", "apps/relay", "development.relay.json"],
      ["fanout", "apps/fanout", "development.fanout.json"],
      ["sender", "apps/sender", "development.sender.json"]
    ]) {
      const entry = path.join(REPO_ROOT, pkgDir, "dist", "main.js");
      specs.push({
        id,
        kind: "node",
        command: process.execPath,
        args: ["--enable-source-maps", entry, "--config", path.join(REPO_ROOT, "config", cfgName)],
        requiredBuildArtifact: entry,
        cwd: REPO_ROOT,
        available: true
      });
    }
  }

  const apiEntry = path.join(REPO_ROOT, "apps", "api", "dist", "main.js");
  specs.push({
    id: "api",
    kind: "node",
    command: process.execPath,
    args: [
      "--enable-source-maps",
      apiEntry,
      "--config",
      path.join(REPO_ROOT, "config", "development.api.json"),
      "--allow-dev-bootstrap"
    ],
    requiredBuildArtifact: apiEntry,
    cwd: REPO_ROOT,
    available: true
  });

  if (options.includeExamples) {
    for (const [id, exDir, cfgName] of [
      ["example-receiver", "examples/receiver", "development.receiver.json"],
      ["example-provider-ingress", "examples/provider-ingress", "development.provider-ingress.json"]
    ]) {
      const entry = path.join(REPO_ROOT, exDir, "dist", "main.js");
      specs.push({
        id,
        kind: "node",
        command: process.execPath,
        args: ["--enable-source-maps", entry, "--config", path.join(REPO_ROOT, "config", cfgName)],
        requiredBuildArtifact: entry,
        cwd: REPO_ROOT,
        available: true
      });
    }
  }

  if (options.includeConsole) {
    const consoleDir = path.join(REPO_ROOT, "apps", "console");
    specs.push({
      id: "console",
      kind: "console",
      command: fs.existsSync(viteBin) ? process.execPath : npmBin,
      args: fs.existsSync(viteBin)
        ? [viteBin, "--host", "localhost", "--port", "5205"]
        : ["run", "dev", "--workspace", "@relayquill/console", "--", "--port", "5205"],
      requiredBuildArtifact: path.join(consoleDir, "package.json"),
      cwd: consoleDir,
      available: true
    });
  }

  return specs;
}

function summarizePlan(options, envResult, specs, pgReachable) {
  const pgTarget = parseHostPortFromUrl(envResult.env["DATABASE_URL"] ?? "", "127.0.0.1", 55005);
  return {
    ok: true,
    profile: options.profile,
    dry_run: options.dryRun,
    env_file: envResult.selectedEnvFile
      ? path.relative(REPO_ROOT, envResult.selectedEnvFile)
      : null,
    postgres: {
      target: `${pgTarget.host}:${pgTarget.port}`,
      url: redactDisplayValue("DATABASE_URL", envResult.env["DATABASE_URL"]),
      check_mode: options.postgresCheck,
      reachable: pgReachable
    },
    broker_url: redactDisplayValue("NATS_URL", envResult.env["NATS_URL"]),
    public_console_origin: envResult.env["PUBLIC_CONSOLE_ORIGIN"],
    public_api_origin: envResult.env["PUBLIC_API_ORIGIN"],
    processes: specs.map((s) => ({
      id: s.id,
      kind: s.kind,
      ready_artifact_exists: fs.existsSync(s.requiredBuildArtifact),
      available: s.available,
      ...(s.startupNote ? { note: s.startupNote } : {}),
      args_count: s.args.length
    }))
  };
}

function terminateChild(child, timeoutMs) {
  return new Promise((resolve) => {
    if (child.exitCode !== null || child.signalCode !== null || child.killed) {
      resolve();
      return;
    }
    let settled = false;
    const finish = () => {
      if (!settled) {
        settled = true;
        clearTimeout(killTimer);
        resolve();
      }
    };
    child.once("exit", finish);
    const killTimer = setTimeout(() => {
      try {
        child.kill("SIGKILL");
      } catch {
        // Ignore already-exited child process
      }
      finish();
    }, timeoutMs);

    try {
      child.kill("SIGTERM");
    } catch {
      finish();
    }
  });
}

export async function runDevStack(argv = process.argv.slice(2)) {
  const options = parseDevStackArgs(argv);
  if (options.help) {
    process.stdout.write(DEV_STACK_HELP_TEXT);
    return 0;
  }

  const envResult = loadStackEnv(options.envFilePath);
  const pgTarget = parseHostPortFromUrl(envResult.env["DATABASE_URL"] ?? "", "127.0.0.1", 55005);
  const pgReachable =
    options.postgresCheck === "skip"
      ? null
      : await checkTcpPortOpen(pgTarget.host, pgTarget.port, 700);

  const specs = buildProcessSpecs(options, envResult.env);
  const plan = summarizePlan(options, envResult, specs, pgReachable);

  if (options.dryRun) {
    process.stdout.write(`${JSON.stringify(plan, null, 2)}\n`);
    return 0;
  }

  if (options.postgresCheck === "require" && pgReachable === false) {
    throw new Error(
      `PostgreSQL not reachable at ${pgTarget.host}:${pgTarget.port}. Start postgres via docker compose -f infra/compose.dev.yaml up -d db`
    );
  }

  const missingArtifacts = specs.filter((s) => s.available && !fs.existsSync(s.requiredBuildArtifact));
  if (missingArtifacts.length > 0) {
    throw new Error(
      `Missing built artifacts for: ${missingArtifacts.map((s) => s.id).join(", ")}. Run npm run build first.`
    );
  }

  const launchableSpecs = specs.filter((s) => {
    if (!s.available) {
      process.stderr.write(`[dev-stack] skipping ${s.id}: ${s.startupNote ?? "unavailable"}\n`);
      return false;
    }
    return true;
  });

  const children = [];
  let shuttingDown = false;

  const stopAll = async (reason) => {
    if (shuttingDown) {
      return;
    }
    shuttingDown = true;
    process.stdout.write(`[dev-stack] shutting down (${reason})...\n`);
    for (let i = children.length - 1; i >= 0; i -= 1) {
      const entry = children[i];
      if (!entry) {
        continue;
      }
      process.stdout.write(`[dev-stack] stopping ${entry.id}...\n`);
      await terminateChild(entry.child, options.stopTimeoutMs);
    }
  };

  for (const spec of launchableSpecs) {
    process.stdout.write(`[dev-stack] starting ${spec.id}...\n`);
    const child = spawn(spec.command, spec.args, {
      cwd: spec.cwd,
      env: envResult.env,
      shell: false,
      stdio: ["ignore", "pipe", "pipe"]
    });
    child.stdout?.on("data", (chunk) => {
      for (const line of chunk.toString("utf8").split(/\r?\n/)) {
        if (line.length > 0) {
          process.stdout.write(`[${spec.id}] ${redactDisplayValue(spec.id, line)}\n`);
        }
      }
    });
    child.stderr?.on("data", (chunk) => {
      for (const line of chunk.toString("utf8").split(/\r?\n/)) {
        if (line.length > 0) {
          process.stderr.write(`[${spec.id}:err] ${redactDisplayValue(spec.id, line)}\n`);
        }
      }
    });
    child.once("exit", (code, signal) => {
      if (!shuttingDown) {
        process.stderr.write(
          `[dev-stack] process "${spec.id}" exited unexpectedly (code=${String(code)}, signal=${String(signal)})\n`
        );
        void stopAll(`child_exit:${spec.id}`).then(() => {
          process.exitCode = code && code !== 0 ? code : 1;
        });
      }
    });
    children.push({ id: spec.id, child });
  }

  await new Promise((resolve) => {
    const onSignal = (sig) => {
      process.off("SIGINT", onSigint);
      process.off("SIGTERM", onSigterm);
      void stopAll(sig).finally(() => resolve());
    };
    const onSigint = () => onSignal("SIGINT");
    const onSigterm = () => onSignal("SIGTERM");
    process.on("SIGINT", onSigint);
    process.on("SIGTERM", onSigterm);
  });

  return 0;
}

if (isMainModule(import.meta.url)) {
  runDevStack().then(
    (code) => {
      process.exitCode = code;
    },
    (err) => {
      const msg = err instanceof Error ? err.message : String(err);
      process.stderr.write(`dev-stack error: ${msg}\n`);
      process.exitCode = 1;
    }
  );
}
