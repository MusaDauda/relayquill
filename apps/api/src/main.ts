import process from "node:process";
import { type TelemetryPort } from "@relayquill/application";
import { ValidationDomainError, parseRuntimeInstanceId } from "@relayquill/domain";
import { createPgAdapterFromConfig, type PgAdapter } from "@relayquill/postgres";
import {
  type ApiRoleConfig,
  type RelayquillTelemetry,
  type SecretProvider,
  createSecretProvider,
  initTelemetry,
  isProductionProfile,
  loadRoleConfig,
  resolveRuntimeEnvironment
} from "@relayquill/runtime";
import { API_APP_VERSION, createApiServer } from "./index.js";

export interface ApiCliOptions {
  readonly configPath: string;
  readonly envFilePath?: string | undefined;
  readonly host?: string | undefined;
  readonly port?: number | undefined;
  readonly instanceId?: string | undefined;
  readonly allowDevBootstrap?: boolean | undefined;
  readonly help: boolean;
}

export const API_HELP_TEXT = `Relayquill Control & Ingestion HTTP API Server

Usage:
  relayquill-api --config <path> [options]

Options:
  -c, --config <path>        Path to api role JSON configuration (or RELAYQUILL_CONFIG)
      --env-file <path>      Optional .env file override passed to runtime env resolver
      --host <host>          Override HTTP bind host
      --port <port>          Override HTTP bind port
      --instance-id <uuid>   Override runtime instance UUID
      --allow-dev-bootstrap  Allow development enrollment bootstrap approval endpoint
  -h, --help                 Show this help message
`;

export function parseApiCliArgs(
  argv: readonly string[],
  env: Readonly<Record<string, string | undefined>> = process.env
): ApiCliOptions {
  let configPath = env["RELAYQUILL_CONFIG"] ?? env["CONFIG_PATH"] ?? "";
  let envFilePath = env["RELAYQUILL_ENV_FILE"];
  let host = env["API_HOST"];
  let port: number | undefined =
    env["API_PORT"] !== undefined && env["API_PORT"] !== ""
      ? Number(env["API_PORT"])
      : undefined;
  let instanceId = env["RELAYQUILL_INSTANCE_ID"];
  let allowDevBootstrap =
    env["RELAYQUILL_DEV_BOOTSTRAP"] === "1" || env["RELAYQUILL_DEV_BOOTSTRAP"] === "true";
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
    if (arg === "--env-file") {
      envFilePath = argv[i + 1];
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
    if (arg === "--instance-id") {
      instanceId = argv[i + 1];
      i += 1;
      continue;
    }
    if (arg === "--allow-dev-bootstrap") {
      allowDevBootstrap = true;
      continue;
    }
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Unknown CLI argument: ${arg}`
    });
  }

  if (!help && configPath.trim().length === 0) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: "Missing required --config <path> option"
    });
  }
  if (port !== undefined && (!Number.isInteger(port) || port < 0 || port > 65535)) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Invalid --port value: ${String(port)}`
    });
  }

  return {
    configPath: configPath.trim(),
    ...(envFilePath !== undefined && envFilePath.length > 0 ? { envFilePath } : {}),
    ...(host !== undefined && host.length > 0 ? { host } : {}),
    ...(port !== undefined ? { port } : {}),
    ...(instanceId !== undefined && instanceId.length > 0
      ? { instanceId: parseRuntimeInstanceId(instanceId, "instance_id") }
      : {}),
    allowDevBootstrap,
    help
  };
}

function assertApiConfig(config: ReturnType<typeof loadRoleConfig>): ApiRoleConfig {
  if (config.process_role !== "api") {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Expected process_role="api", got "${config.process_role}"`
    });
  }
  return config;
}

function createApiTelemetryPort(telemetry: RelayquillTelemetry): TelemetryPort {
  return {
    startSpan(name, attributes) {
      const handle = telemetry.createAttemptSpanContext({
        spanName: name,
        attributes
      });
      return {
        traceId: handle.traceId,
        spanId: handle.spanId,
        traceparent: handle.traceparent,
        tracestate: handle.tracestate,
        end(status) {
          handle.end(status);
        }
      };
    },
    createAttemptTrace(options) {
      const handle = telemetry.createAttemptSpanContext({
        spanName: options.spanName,
        attributes: options.attributes,
        allowedTracestateKeys: options.allowedTracestateKeys
      });
      return {
        traceId: handle.traceId,
        spanId: handle.spanId,
        traceparent: handle.traceparent,
        tracestate: handle.tracestate,
        end(status) {
          handle.end(status);
        }
      };
    }
  };
}

export async function runApiCli(argv: readonly string[] = process.argv.slice(2)): Promise<number> {
  const opts = parseApiCliArgs(argv);
  if (opts.help) {
    process.stdout.write(API_HELP_TEXT);
    return 0;
  }

  const roleConfig = assertApiConfig(loadRoleConfig(opts.configPath));
  const resolvedEnv = resolveRuntimeEnvironment(roleConfig, {
    ...(opts.envFilePath !== undefined ? { envFilePath: opts.envFilePath } : {})
  });
  const telemetry = roleConfig.telemetry
    ? initTelemetry({
        serviceName: roleConfig.telemetry.service_name,
        enabled: roleConfig.telemetry.enabled,
        ...(roleConfig.telemetry.otlp_endpoint !== undefined
          ? { otlpEndpoint: roleConfig.telemetry.otlp_endpoint }
          : {}),
        maxQueueSize: roleConfig.telemetry.max_queue_size,
        maxExportBatchSize: roleConfig.telemetry.max_export_batch_size,
        ...(roleConfig.telemetry.trace_view_origin !== undefined
          ? { traceViewOrigin: roleConfig.telemetry.trace_view_origin }
          : {})
      })
    : undefined;

  let pgAdapter: PgAdapter | undefined;
  let secretProvider: SecretProvider | undefined;

  try {
    pgAdapter = await createPgAdapterFromConfig(resolvedEnv.database ?? roleConfig.database);
    secretProvider = createSecretProvider(roleConfig.secret_provider);
    const allowDevBootstrapRoute =
      !isProductionProfile(roleConfig.profile) &&
      (opts.allowDevBootstrap === true || roleConfig.profile === "development_trusted_local");

    const allowedOrigins = new Set(roleConfig.auth.allowed_origins);
    if (resolvedEnv.publicConsoleOrigin !== undefined) {
      allowedOrigins.add(resolvedEnv.publicConsoleOrigin);
    }

    const server = createApiServer({
      pgAdapter,
      authConfig: {
        rp_id: resolvedEnv.webauthnRpId ?? roleConfig.auth.rp_id,
        allowed_origins: Array.from(allowedOrigins),
        cookie_profile: roleConfig.auth.cookie_profile
      },
      profile: roleConfig.profile,
      allowDevBootstrapRoute,
      secretProvider,
      ...(telemetry !== undefined ? { telemetry: createApiTelemetryPort(telemetry) } : {}),
      ...(opts.instanceId !== undefined ? { runtimeInstanceId: opts.instanceId } : {}),
      buildReference: `relayquill-api/${API_APP_VERSION}`,
      sseHeartbeatMs: roleConfig.http.sse_heartbeat_ms,
      sseMaxLifetimeMs: roleConfig.http.sse_max_lifetime_ms
    });

    const bound = await server.start({
      host: opts.host ?? roleConfig.http.host,
      port: opts.port ?? roleConfig.http.port
    });

    process.stdout.write(
      `${JSON.stringify({
        ok: true,
        event: "api.listening",
        url: bound.url,
        profile: roleConfig.profile,
        instance_id: server.ctx.runtimeInstanceId
      })}\n`
    );

    await new Promise<void>((resolve) => {
      let draining = false;
      const onSignal = (signal: NodeJS.Signals): void => {
        if (draining) {
          return;
        }
        draining = true;
        process.off("SIGINT", onSigint);
        process.off("SIGTERM", onSigterm);
        server.ctx.logger.info(
          { event: "api.draining", component: "api", route: signal },
          `draining API server (${signal})`
        );
        void server
          .close()
          .catch(() => undefined)
          .finally(() => {
            resolve();
          });
      };
      const onSigint = (): void => onSignal("SIGINT");
      const onSigterm = (): void => onSignal("SIGTERM");
      process.on("SIGINT", onSigint);
      process.on("SIGTERM", onSigterm);
    });

    return 0;
  } finally {
    if (secretProvider?.close !== undefined) {
      await secretProvider.close().catch(() => undefined);
    }
    if (pgAdapter !== undefined) {
      await pgAdapter.close().catch(() => undefined);
    }
    if (telemetry !== undefined) {
      await telemetry.shutdown().catch(() => undefined);
    }
  }
}

const isDirectExecution =
  process.argv[1] !== undefined &&
  (import.meta.url.endsWith(process.argv[1].replace(/\\/g, "/")) ||
    process.argv[1].endsWith("main.js") ||
    process.argv[1].endsWith("main.ts"));

if (isDirectExecution) {
  runApiCli()
    .then((code) => {
      process.exitCode = code;
    })
    .catch((err: unknown) => {
      const msg = err instanceof Error ? err.stack ?? err.message : String(err);
      process.stderr.write(`${msg}\n`);
      process.exitCode = 1;
    });
}
