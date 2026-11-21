import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";
import {
  createSecretProvider,
  loadRoleConfig,
  resolveRuntimeEnvironment,
  type ReceiverRoleConfig,
  type SecretProvider
} from "@relayquill/runtime";
import {
  createReceiverDbClient,
  type PGliteCompatibleClient,
  type ReceiverDbClient
} from "./db.js";
import { createReceiverServer } from "./server.js";

export interface ReceiverCliOptions {
  readonly configPath: string;
  readonly host?: string | undefined;
  readonly port?: number | undefined;
  readonly help: boolean;
}

const HELP_TEXT = `Relayquill Reference Receiver Server

Usage:
  relayquill-receiver --config <path> [options]

Options:
  -c, --config <path>   Path to receiver role JSON configuration (or RELAYQUILL_CONFIG)
      --host <host>     Override bind host (default: config http.host or 127.0.0.1)
      --port <port>     Override bind port (default: config http.port or 19095)
  -h, --help            Show this help message
`;

export function parseReceiverCliArgs(
  argv: readonly string[],
  env: Readonly<Record<string, string | undefined>> = process.env
): ReceiverCliOptions {
  let configPath = env["RELAYQUILL_CONFIG"] ?? env["CONFIG_PATH"] ?? "";
  let host = env["HTTP_HOST"];
  let port: number | undefined =
    env["HTTP_PORT"] !== undefined && env["HTTP_PORT"] !== ""
      ? Number(env["HTTP_PORT"])
      : undefined;
  let help = false;

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === undefined) {
      continue;
    }
    if (arg === "--help" || arg === "-h") {
      help = true;
      continue;
    }
    if (arg === "--config" || arg === "-c") {
      configPath = argv[i + 1] ?? "";
      i += 1;
      continue;
    }
    if (arg === "--host") {
      host = argv[i + 1];
      i += 1;
      continue;
    }
    if (arg === "--port") {
      const raw = argv[i + 1];
      port = raw !== undefined ? Number(raw) : undefined;
      i += 1;
      continue;
    }
    throw new Error(`Unknown CLI argument: ${arg}`);
  }

  if (!help && configPath.trim().length === 0) {
    throw new Error("Missing required --config <path> option");
  }
  if (port !== undefined && (!Number.isInteger(port) || port < 0 || port > 65535)) {
    throw new Error(`Invalid --port value: ${String(port)}`);
  }

  return {
    configPath: configPath.trim(),
    ...(host !== undefined && host.length > 0 ? { host } : {}),
    ...(port !== undefined ? { port } : {}),
    help
  };
}

function assertReceiverConfig(config: ReturnType<typeof loadRoleConfig>): ReceiverRoleConfig {
  if (config.process_role !== "receiver") {
    throw new Error(`Expected process_role="receiver", got "${config.process_role}"`);
  }
  return config;
}

async function createConfiguredDb(config: ReceiverRoleConfig): Promise<ReceiverDbClient> {
  const resolved = resolveRuntimeEnvironment(config);
  const envDb = resolved.database;
  const baseDb = config.database;
  const mode = envDb?.mode ?? baseDb.mode;
  const schema = envDb?.schema ?? baseDb.schema;
  const role = envDb?.configuredRole ?? baseDb.role;

  if (mode === "portable_pglite") {
    const pgliteMod = (await import("@electric-sql/pglite")) as {
      readonly PGlite: {
        create(options?: { readonly dataDir?: string | undefined }): Promise<PGliteCompatibleClient>;
      };
    };
    const pglite = await pgliteMod.PGlite.create({
      dataDir: "memory://"
    });
    const migrationsDir = path.resolve(
      path.dirname(fileURLToPath(import.meta.url)),
      "../migrations"
    );
    if (fs.existsSync(migrationsDir) && typeof pglite.exec === "function") {
      const files = fs
        .readdirSync(migrationsDir)
        .filter((f) => f.endsWith(".sql"))
        .sort();
      for (const file of files) {
        await pglite.exec(fs.readFileSync(path.join(migrationsDir, file), "utf8"));
      }
    }
    return createReceiverDbClient({
      pglite,
      ownsClient: true,
      schema,
      role
    });
  }

  const password = envDb?.passwordHandle?.readUtf8();
  const tlsMode = envDb?.tlsMode ?? baseDb.tls_mode;
  const caFile = envDb?.tlsCaFile ?? baseDb.tls_ca_file;
  const ssl =
    tlsMode === "verify_full"
      ? {
          rejectUnauthorized: true as const,
          ...(caFile !== undefined ? { ca: fs.readFileSync(caFile, "utf8") } : {})
        }
      : undefined;

  return createReceiverDbClient({
    poolConfig: {
      host: envDb?.host ?? baseDb.host,
      port: envDb?.port ?? baseDb.port,
      database: envDb?.name ?? baseDb.name,
      user: envDb?.user ?? baseDb.role,
      ...(password !== undefined ? { password } : {}),
      ...(ssl !== undefined ? { ssl } : {}),
      max: baseDb.maximum_connections,
      connectionTimeoutMillis: baseDb.connection_timeout_ms
    },
    ownsClient: true,
    schema,
    role
  });
}

export async function runReceiverCli(
  argv: readonly string[] = process.argv.slice(2)
): Promise<number> {
  const opts = parseReceiverCliArgs(argv);
  if (opts.help) {
    process.stdout.write(HELP_TEXT);
    return 0;
  }

  const config = assertReceiverConfig(loadRoleConfig(opts.configPath));
  const resolved = resolveRuntimeEnvironment(config);
  const secretProvider: SecretProvider = createSecretProvider(config.secret_provider, {
    env: process.env,
    allowDirectEnvAndFileRefs: true
  });
  const db = await createConfiguredDb(config);

  const server = await createReceiverServer({
    db,
    host: opts.host ?? config.http.host ?? "127.0.0.1",
    port: opts.port ?? config.http.port ?? 19095,
    secretProvider,
    ...(resolved.controlEndpoint !== undefined
      ? { controlChannelEndpoint: resolved.controlEndpoint }
      : {}),
    controlChannel: config.control_channel
  });

  try {
    await server.start();

    await new Promise<void>((resolve) => {
      let shuttingDown = false;
      const handleSignal = (): void => {
        if (shuttingDown) {
          return;
        }
        shuttingDown = true;
        process.off("SIGINT", handleSignal);
        process.off("SIGTERM", handleSignal);
        void server.stop().finally(() => resolve());
      };
      process.on("SIGINT", handleSignal);
      process.on("SIGTERM", handleSignal);
    });

    return 0;
  } finally {
    await server.stop().catch(() => undefined);
    await db.close().catch(() => undefined);
    await secretProvider.close?.().catch(() => undefined);
  }
}

const isDirectExecution =
  process.argv[1] !== undefined &&
  (import.meta.url.endsWith(process.argv[1].replace(/\\/g, "/")) ||
    process.argv[1].endsWith("main.js") ||
    process.argv[1].endsWith("main.ts"));

if (isDirectExecution) {
  runReceiverCli()
    .then((code) => {
      process.exitCode = code;
    })
    .catch((err) => {
      const msg = err instanceof Error ? err.stack ?? err.message : String(err);
      process.stderr.write(`${msg}\n`);
      process.exitCode = 1;
    });
}
