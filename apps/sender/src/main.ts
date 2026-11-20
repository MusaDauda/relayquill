import fs from "node:fs";
import process from "node:process";
import { parseControlEpoch, parseRuntimeInstanceId } from "@relayquill/domain";
import { type TelemetryPort } from "@relayquill/application";
import { createPgAdapterFromConfig, type PgAdapter } from "@relayquill/postgres";
import {
  initTelemetry,
  loadRoleConfig,
  type RelayquillTelemetry,
  resolveRuntimeEnvironment,
  type SenderRoleConfig
} from "@relayquill/runtime";
import { createSenderHealthServer, type SenderHealthServer } from "./health.js";
import { createSenderWorker } from "./worker.js";

export interface SenderCliOptions {
  readonly configPath: string;
  readonly controlEpoch?: string | undefined;
  readonly instanceId?: string | undefined;
  readonly healthHost?: string | undefined;
  readonly healthPort?: number | undefined;
  readonly caFile?: string | undefined;
  readonly once: boolean;
  readonly help: boolean;
}

const HELP_TEXT = `Relayquill Webhook Delivery Sender Worker

Usage:
  relayquill-sender --config <path> [options]

Options:
  -c, --config <path>          Path to sender role JSON configuration (or RELAYQUILL_CONFIG)
      --control-epoch <uuid>   Override control epoch UUID (default: read installation_state)
      --instance-id <uuid>     Override runtime instance UUID
      --ca-file <path>         Optional extra CA PEM file for pinned HTTPS verification
      --health-host <host>     Optional HTTP health probe host (default: 127.0.0.1 when port set)
      --health-port <port>     Optional node:http /health/live & /health/ready port
      --once                   Execute one dispatch + send batch and exit cleanly
  -h, --help                   Show this help message
`;

export function parseSenderCliArgs(
  argv: readonly string[],
  env: Readonly<Record<string, string | undefined>> = process.env
): SenderCliOptions {
  let configPath = env["RELAYQUILL_CONFIG"] ?? env["CONFIG_PATH"] ?? "";
  let controlEpoch = env["RELAYQUILL_CONTROL_EPOCH"];
  let instanceId = env["RELAYQUILL_INSTANCE_ID"];
  let healthHost = env["HEALTH_HOST"];
  let healthPort: number | undefined =
    env["HEALTH_PORT"] !== undefined && env["HEALTH_PORT"] !== ""
      ? Number(env["HEALTH_PORT"])
      : undefined;
  let caFile = env["RELAYQUILL_EGRESS_CA_FILE"];
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
    if (arg === "--ca-file") {
      caFile = argv[i + 1];
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
    ...(caFile !== undefined && caFile.length > 0 ? { caFile } : {}),
    ...(healthHost !== undefined && healthHost.length > 0 ? { healthHost } : {}),
    ...(healthPort !== undefined ? { healthPort } : {}),
    once,
    help
  };
}

function assertSenderConfig(config: ReturnType<typeof loadRoleConfig>): SenderRoleConfig {
  if (config.process_role !== "sender") {
    throw new Error(`Expected process_role="sender", got "${config.process_role}"`);
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

export async function runSenderCli(argv: readonly string[] = process.argv.slice(2)): Promise<number> {
  const opts = parseSenderCliArgs(argv);
  if (opts.help) {
    process.stdout.write(HELP_TEXT);
    return 0;
  }

  const roleConfig = assertSenderConfig(loadRoleConfig(opts.configPath));
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
  let healthServer: SenderHealthServer | undefined;

  try {
    pgAdapter = await createPgAdapterFromConfig(resolvedEnv.database ?? roleConfig.database);
    const caPem = opts.caFile !== undefined ? fs.readFileSync(opts.caFile, "utf8") : undefined;

    const worker = createSenderWorker({
      pgAdapter,
      databaseRole: roleConfig.database.role,
      instanceId: opts.instanceId,
      controlEpoch: opts.controlEpoch,
      profile: roleConfig.profile,
      egressConfig: roleConfig.egress,
      ...(caPem !== undefined ? { ca: caPem } : {}),
      secretProviderConfig: roleConfig.secret_provider,
      settings: roleConfig.sender,
      ...(telemetry !== undefined ? { telemetry: createWorkerTelemetryPort(telemetry) } : {}),
      onError: (err) => {
        const msg = err instanceof Error ? err.message : String(err);
        process.stderr.write(`sender tick error: ${msg}\n`);
      }
    });

    if (opts.once) {
      await worker.runOnce();
      return 0;
    }

    if (opts.healthPort !== undefined) {
      healthServer = createSenderHealthServer({
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
  runSenderCli()
    .then((code) => {
      process.exitCode = code;
    })
    .catch((err) => {
      const msg = err instanceof Error ? err.stack ?? err.message : String(err);
      process.stderr.write(`${msg}\n`);
      process.exitCode = 1;
    });
}
