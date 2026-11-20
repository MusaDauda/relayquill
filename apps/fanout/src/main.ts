import process from "node:process";
import { FANOUT_PAGE_SIZE, parseControlEpoch, parseRuntimeInstanceId } from "@relayquill/domain";
import { type TelemetryPort } from "@relayquill/application";
import { type BrokerAdapter, createBrokerAdapter } from "@relayquill/broker";
import { SchemaWorkerPool } from "@relayquill/event-schema";
import { createPgAdapterFromConfig, type PgAdapter } from "@relayquill/postgres";
import {
  type FanoutRoleConfig,
  initTelemetry,
  loadRoleConfig,
  type RelayquillTelemetry,
  resolveRuntimeEnvironment
} from "@relayquill/runtime";
import { createFanoutHealthServer, type FanoutHealthServer } from "./health.js";
import { createFanoutWorker } from "./worker.js";

export interface FanoutCliOptions {
  readonly configPath: string;
  readonly controlEpoch?: string | undefined;
  readonly instanceId?: string | undefined;
  readonly healthHost?: string | undefined;
  readonly healthPort?: number | undefined;
  readonly pageSize: number;
  readonly once: boolean;
  readonly help: boolean;
}

const HELP_TEXT = `Relayquill Event Fanout Worker

Usage:
  relayquill-fanout --config <path> [options]

Options:
  -c, --config <path>          Path to fanout role JSON configuration (or RELAYQUILL_CONFIG)
      --control-epoch <uuid>   Override control epoch UUID (default: read installation_state)
      --instance-id <uuid>     Override runtime instance UUID
      --page-size <count>      Fanout subscription page size (default: ${FANOUT_PAGE_SIZE})
      --health-host <host>     Optional HTTP health probe host (default: 127.0.0.1 when port set)
      --health-port <port>     Optional node:http /health/live & /health/ready port
      --once                   Execute one broker pull/fanout tick and exit cleanly
  -h, --help                   Show this help message
`;

export function parseFanoutCliArgs(
  argv: readonly string[],
  env: Readonly<Record<string, string | undefined>> = process.env
): FanoutCliOptions {
  let configPath = env["RELAYQUILL_CONFIG"] ?? env["CONFIG_PATH"] ?? "";
  let controlEpoch = env["RELAYQUILL_CONTROL_EPOCH"];
  let instanceId = env["RELAYQUILL_INSTANCE_ID"];
  let healthHost = env["HEALTH_HOST"];
  let healthPort: number | undefined =
    env["HEALTH_PORT"] !== undefined && env["HEALTH_PORT"] !== ""
      ? Number(env["HEALTH_PORT"])
      : undefined;
  let pageSize: number = FANOUT_PAGE_SIZE;
  let once = false;
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
    if (arg === "--once") {
      once = true;
      continue;
    }
    if (arg === "--config" || arg === "-c") {
      configPath = argv[i + 1] ?? "";
      i += 1;
      continue;
    }
    if (arg === "--control-epoch") {
      controlEpoch = argv[i + 1];
      i += 1;
      continue;
    }
    if (arg === "--instance-id") {
      instanceId = argv[i + 1];
      i += 1;
      continue;
    }
    if (arg === "--page-size") {
      const raw = argv[i + 1];
      pageSize = raw !== undefined ? Number(raw) : FANOUT_PAGE_SIZE;
      i += 1;
      continue;
    }
    if (arg === "--health-host") {
      healthHost = argv[i + 1];
      i += 1;
      continue;
    }
    if (arg === "--health-port") {
      const raw = argv[i + 1];
      healthPort = raw !== undefined ? Number(raw) : undefined;
      i += 1;
      continue;
    }
    throw new Error(`Unknown CLI argument: ${arg}`);
  }

  if (!help && configPath.trim().length === 0) {
    throw new Error("Missing required --config <path> option");
  }
  if (!Number.isInteger(pageSize) || pageSize < 1 || pageSize > 500) {
    throw new Error(`Invalid --page-size value: ${String(pageSize)}`);
  }
  if (healthPort !== undefined && (!Number.isInteger(healthPort) || healthPort < 0 || healthPort > 65535)) {
    throw new Error(`Invalid --health-port value: ${String(healthPort)}`);
  }

  return {
    configPath: configPath.trim(),
    ...(controlEpoch !== undefined && controlEpoch.length > 0
      ? { controlEpoch: parseControlEpoch(controlEpoch, "control_epoch") }
      : {}),
    ...(instanceId !== undefined && instanceId.length > 0
      ? { instanceId: parseRuntimeInstanceId(instanceId, "instance_id") }
      : {}),
    ...(healthHost !== undefined && healthHost.length > 0 ? { healthHost } : {}),
    ...(healthPort !== undefined ? { healthPort } : {}),
    pageSize,
    once,
    help
  };
}

function assertFanoutConfig(config: ReturnType<typeof loadRoleConfig>): FanoutRoleConfig {
  if (config.process_role !== "fanout") {
    throw new Error(`Expected process_role="fanout", got "${config.process_role}"`);
  }
  return config;
}

function createWorkerTelemetryPort(telemetry: RelayquillTelemetry): TelemetryPort {
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

export async function runFanoutCli(argv: readonly string[] = process.argv.slice(2)): Promise<number> {
  const opts = parseFanoutCliArgs(argv);
  if (opts.help) {
    process.stdout.write(HELP_TEXT);
    return 0;
  }

  const roleConfig = assertFanoutConfig(loadRoleConfig(opts.configPath));
  const resolvedEnv = resolveRuntimeEnvironment(roleConfig);
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
  let broker: BrokerAdapter | undefined;
  let schemaPool: SchemaWorkerPool | undefined;
  let healthServer: FanoutHealthServer | undefined;

  try {
    pgAdapter = await createPgAdapterFromConfig(resolvedEnv.database ?? roleConfig.database);
    const brokerConfig = resolvedEnv.broker;
    const brokerSecretRef = brokerConfig?.secretRef ?? roleConfig.broker.secret_ref;
    const inboxPrefix = brokerConfig?.inboxPrefix ?? roleConfig.broker.inbox_prefix;
    broker = await createBrokerAdapter({
      mode: brokerConfig?.mode ?? roleConfig.broker.mode,
      servers: [...(brokerConfig?.servers ?? roleConfig.broker.servers)],
      authMode: brokerConfig?.authMode ?? roleConfig.broker.auth_mode,
      ...(brokerSecretRef !== undefined ? { secretRef: brokerSecretRef } : {}),
      ...(roleConfig.broker.tls !== undefined ? { tls: roleConfig.broker.tls } : {}),
      streamName: roleConfig.broker.stream_name,
      subjectPrefix: roleConfig.broker.subject_prefix,
      consumerName: roleConfig.broker.consumer_name,
      replicas: roleConfig.broker.replicas,
      ...(inboxPrefix !== undefined ? { inboxPrefix } : {}),
      fanoutSettings: roleConfig.fanout
    });

    schemaPool = new SchemaWorkerPool();
    await schemaPool.warmup();

    const worker = createFanoutWorker({
      pgAdapter,
      broker,
      schemaPool,
      databaseRole: roleConfig.database.role,
      instanceId: opts.instanceId,
      controlEpoch: opts.controlEpoch,
      settings: roleConfig.fanout,
      pageSize: opts.pageSize,
      ...(telemetry !== undefined ? { telemetry: createWorkerTelemetryPort(telemetry) } : {}),
      onError: (err) => {
        const msg = err instanceof Error ? err.message : String(err);
        process.stderr.write(`fanout tick error: ${msg}\n`);
      }
    });

    if (opts.once) {
      await worker.runOnce();
      await worker.stop("cli_once");
      return 0;
    }

    if (opts.healthPort !== undefined) {
      healthServer = createFanoutHealthServer({
        host: opts.healthHost,
        port: opts.healthPort,
        probe: worker
      });
      await healthServer.start();
    }

    await worker.start();

    await new Promise<void>((resolve) => {
      let shuttingDown = false;
      const handleSignal = (signal: NodeJS.Signals): void => {
        if (shuttingDown) {
          return;
        }
        shuttingDown = true;
        process.off("SIGINT", onSigint);
        process.off("SIGTERM", onSigterm);
        void worker
          .stop(`signal:${signal}`)
          .finally(() => {
            resolve();
          });
      };
      const onSigint = (): void => handleSignal("SIGINT");
      const onSigterm = (): void => handleSignal("SIGTERM");
      process.on("SIGINT", onSigint);
      process.on("SIGTERM", onSigterm);
    });

    return 0;
  } finally {
    if (healthServer !== undefined) {
      await healthServer.stop().catch(() => undefined);
    }
    if (schemaPool !== undefined) {
      await schemaPool.close().catch(() => undefined);
    }
    if (broker !== undefined) {
      await broker.close().catch(() => undefined);
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
  runFanoutCli()
    .then((code) => {
      process.exitCode = code;
    })
    .catch((err) => {
      const msg = err instanceof Error ? err.stack ?? err.message : String(err);
      process.stderr.write(`${msg}\n`);
      process.exitCode = 1;
    });
}
