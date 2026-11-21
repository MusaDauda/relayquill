import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { parseCanonicalUtcTimestamp, parseSha256Hex } from "@relayquill/contracts";
import { parseCanonicalUuid } from "@relayquill/domain";
import {
  ProducerAcceptanceUnknownError,
  ProducerSdkError,
  createProducerClient,
  prepareEvent,
  type PrepareEventInput,
  type ProducerClientOptions,
  type ProducerCredentialProvider,
  type WatchFrame
} from "@relayquill/producer-sdk";
import {
  resolveProducerCredentialFromRef,
  type ProducerSecretProviderSettings
} from "./credentials.js";
import {
  PRODUCER_RUN_SCHEMA_VERSION,
  loadProducerRun,
  reconstructPreparedEventFromRun,
  resolveRunFilePath,
  saveProducerRun,
  validateRunId,
  type StoredProducerRun
} from "./store.js";

export const EXAMPLE_PRODUCER_VERSION = "0.1.0" as const;

export const PRODUCER_COMMANDS = [
  "prepare",
  "submit",
  "resolve",
  "retry-original",
  "status",
  "watch"
] as const;

export type ProducerCliCommand = (typeof PRODUCER_COMMANDS)[number];

const SECRET_FLAG_NAMES = new Set([
  "--token",
  "--secret",
  "--password",
  "--credential",
  "--api-key",
  "--signing-key",
  "--private-key",
  "--bearer",
  "--nkey-seed",
  "--auth",
  "--authorization"
]);

const SECRET_LITERAL_PATTERN =
  /(^rq_p1\.[^.\s]+\.[^.\s]+|-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----|^(?:password|secret|token|api[_-]?key)\s*=)/i;

const VALUE_FLAGS = new Set([
  "-c",
  "--config",
  "--origin",
  "--tenant-id",
  "--project-id",
  "--credential-ref",
  "--runs-dir",
  "--run-id",
  "--run-file",
  "--channel-id",
  "--publication-channel-id",
  "--event-type-id",
  "--schema-version",
  "--business-key",
  "--idempotency-key",
  "--content",
  "--content-file",
  "--producer-event-time",
  "--deadline-at",
  "--submitted-shape-sha256",
  "--event-id",
  "--delivery-id",
  "--cursor",
  "--max-frames",
  "--timeout-ms"
]);

const HELP_TEXT = `Relayquill Reference Producer CLI

Usage:
  relayquill-producer <command> [options]

Commands:
  prepare         Fetch/use publication context, build PreparedEvent, persist safe run state
  submit          Prepare (or load run) and submit event idempotently via producer-sdk
  resolve         Resolve uncertain acceptance state via POST /events/resolve
  retry-original  Safely recover a prepared run by resolving first then submitting original
  status          Inspect admitted event details and delivery summaries
  watch           Stream event or delivery SSE updates until completion or max frames

Options:
  -c, --config <path>              Producer example config JSON
      --origin <url>               Relayquill API origin URL
      --tenant-id <uuid>           Tenant UUID (required with --project-id for tenant-scoped routes)
      --project-id <uuid>          Project UUID
      --credential-ref <ref>       Secret reference only: env:<VAR>, file:<PATH>, custody:<KEY>
      --runs-dir <dir>             Directory for safe prepared/admitted run JSON artifacts
      --run-id <id>                Safe run artifact identifier
      --run-file <path>            Explicit path to a run artifact JSON file
      --channel-id <uuid>          Expected publication channel UUID
      --event-type-id <uuid>       Event type UUID
      --schema-version <int>       Event schema version integer >= 1
      --business-key <key>         Idempotent domain business key
      --idempotency-key <key>      Optional explicit Idempotency-Key
      --content <json>             Inline JSON payload string
      --content-file <path>        Path to UTF-8 JSON payload file
      --producer-event-time <ts>   Optional canonical UTC timestamp
      --deadline-at <ts>           Optional canonical UTC deadline timestamp
      --submitted-shape-sha256     Optional fingerprint for standalone resolve
      --event-id <uuid>            Event UUID for status / watch
      --delivery-id <uuid>         Delivery UUID for watch
      --cursor <cursor>            Watch resume cursor
      --max-frames <n>             Max watch SSE frames before stopping cleanly (default: 10)
      --timeout-ms <ms>            Watch abort timeout milliseconds (default: 5000)
  -h, --help                       Show this help message

Security:
  Raw tokens, passwords, and secrets on CLI flags or argv are strictly rejected.
  Supply credentials strictly via --credential-ref (env:, file:, custody:).
`;

export interface ParsedProducerCliArgs {
  readonly help: boolean;
  readonly command?: ProducerCliCommand | undefined;
  readonly configPath?: string | undefined;
  readonly flags: ReadonlyMap<string, string>;
}

interface LoadedProducerConfigFile {
  readonly origin?: string | undefined;
  readonly tenantId?: string | undefined;
  readonly projectId?: string | undefined;
  readonly credentialRef?: string | undefined;
  readonly runsDir?: string | undefined;
  readonly secretProvider?: ProducerSecretProviderSettings | undefined;
}

export interface ProducerCliRuntime {
  readonly env?: Readonly<Record<string, string | undefined>> | undefined;
  readonly stdout?: { write(chunk: string): unknown } | undefined;
  readonly stderr?: { write(chunk: string): unknown } | undefined;
  readonly getCredential?: ProducerCredentialProvider | undefined;
  readonly fetch?: ProducerClientOptions["fetch"] | undefined;
}

function assertNoSecretCliArg(arg: string): void {
  const eqIdx = arg.indexOf("=");
  const flagName = eqIdx !== -1 ? arg.slice(0, eqIdx) : arg;
  if (SECRET_FLAG_NAMES.has(flagName)) {
    throw new Error(
      `Forbidden secret CLI flag "${flagName}". Pass --credential-ref <env:|file:|custody:> instead.`
    );
  }
  if (SECRET_LITERAL_PATTERN.test(arg)) {
    throw new Error(
      "Secret literal detected on CLI arguments; use --credential-ref <env:|file:|custody:> instead."
    );
  }
}

export function parseProducerCliArgs(
  argv: readonly string[],
  env: Readonly<Record<string, string | undefined>> = process.env
): ParsedProducerCliArgs {
  const flags = new Map<string, string>();
  let command: ProducerCliCommand | undefined;
  let help = false;

  for (let i = 0; i < argv.length; i += 1) {
    const raw = argv[i];
    if (raw === undefined) {
      continue;
    }
    assertNoSecretCliArg(raw);

    if (raw === "--help" || raw === "-h") {
      help = true;
      continue;
    }

    if (raw.startsWith("-")) {
      const eqIdx = raw.indexOf("=");
      const flag = eqIdx !== -1 ? raw.slice(0, eqIdx) : raw;
      const canonicalFlag =
        flag === "-c"
          ? "--config"
          : flag === "--publication-channel-id"
            ? "--channel-id"
            : flag;
      if (!VALUE_FLAGS.has(flag)) {
        throw new Error(`Unknown CLI flag: ${flag}`);
      }
      const value = eqIdx !== -1 ? raw.slice(eqIdx + 1) : argv[i + 1];
      if (value === undefined) {
        throw new Error(`Missing value for CLI flag ${flag}`);
      }
      assertNoSecretCliArg(value);
      if (eqIdx === -1) {
        i += 1;
      }
      flags.set(canonicalFlag, value);
      continue;
    }

    if (command === undefined) {
      const matched = (PRODUCER_COMMANDS as readonly string[]).find((c) => c === raw);
      if (matched === undefined) {
        throw new Error(
          `Unknown producer command "${raw}". Expected one of: ${PRODUCER_COMMANDS.join(", ")}`
        );
      }
      command = matched as ProducerCliCommand;
      continue;
    }

    throw new Error(`Unexpected positional argument "${raw}"`);
  }

  const envConfig = env["RELAYQUILL_CONFIG"] ?? env["CONFIG_PATH"];
  const configPath = flags.get("--config") ?? (envConfig !== undefined && envConfig !== "" ? envConfig : undefined);

  if (!help && command === undefined) {
    throw new Error(
      `Missing command (${PRODUCER_COMMANDS.join(", ")}). Pass --help for usage.`
    );
  }

  return {
    help,
    ...(command !== undefined ? { command } : {}),
    ...(configPath !== undefined ? { configPath } : {}),
    flags
  };
}

function readOptRecordString(rec: Record<string, unknown>, key: string): string | undefined {
  const val = rec[key];
  return typeof val === "string" && val.trim().length > 0 ? val.trim() : undefined;
}

function loadProducerConfigFile(configPath: string): LoadedProducerConfigFile {
  const resolved = path.resolve(configPath);
  const raw = JSON.parse(fs.readFileSync(resolved, "utf8")) as unknown;
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
    throw new Error(`Producer config at "${resolved}" must be a JSON object`);
  }
  const rec = raw as Record<string, unknown>;
  const apiTarget = rec["api_target"] as Record<string, unknown> | undefined;
  const projectScope = rec["project_scope"] as Record<string, unknown> | undefined;
  const secProviderRaw = rec["secret_provider"] as Record<string, unknown> | undefined;
  const ipcRaw = secProviderRaw?.["ipc"] as Record<string, unknown> | undefined;

  let secretProvider: ProducerSecretProviderSettings | undefined;
  if (secProviderRaw !== undefined && typeof secProviderRaw["mode"] === "string") {
    const ipcEnvName = ipcRaw !== undefined ? readOptRecordString(ipcRaw, "env_name") : undefined;
    const ipcChannel = ipcRaw !== undefined ? readOptRecordString(ipcRaw, "channel") : undefined;
    const ipcRuntimeEnv =
      ipcRaw !== undefined ? readOptRecordString(ipcRaw, "runtime_dir_env") : undefined;
    const ipcEndpoint = readOptRecordString(secProviderRaw, "ipc_endpoint");
    secretProvider = {
      mode: secProviderRaw["mode"],
      ...(ipcEndpoint !== undefined ? { ipc_endpoint: ipcEndpoint } : {}),
      ...(ipcEnvName !== undefined && ipcChannel !== undefined
        ? {
            ipc: {
              env_name: ipcEnvName,
              channel: ipcChannel,
              ...(ipcRuntimeEnv !== undefined ? { runtime_dir_env: ipcRuntimeEnv } : {})
            }
          }
        : {})
    };
  }

  const origin =
    apiTarget !== undefined ? readOptRecordString(apiTarget, "origin") : readOptRecordString(rec, "origin");
  const tenantId =
    apiTarget !== undefined ? readOptRecordString(apiTarget, "tenant_id") : readOptRecordString(rec, "tenant_id");
  const projectId =
    apiTarget !== undefined ? readOptRecordString(apiTarget, "project_id") : readOptRecordString(rec, "project_id");
  const credentialRef =
    (apiTarget !== undefined ? readOptRecordString(apiTarget, "credential_secret_ref") : undefined) ??
    (projectScope !== undefined ? readOptRecordString(projectScope, "producer_credential_ref") : undefined);
  const runsDir = readOptRecordString(rec, "runs_dir");

  return {
    ...(origin !== undefined ? { origin } : {}),
    ...(tenantId !== undefined ? { tenantId } : {}),
    ...(projectId !== undefined ? { projectId } : {}),
    ...(credentialRef !== undefined ? { credentialRef } : {}),
    ...(runsDir !== undefined ? { runsDir } : {}),
    ...(secretProvider !== undefined ? { secretProvider } : {})
  };
}

function readEventContentInput(flags: ReadonlyMap<string, string>): string {
  const inline = flags.get("--content");
  if (inline !== undefined && inline.length > 0) {
    return inline;
  }
  const contentFile = flags.get("--content-file");
  if (contentFile !== undefined && contentFile.length > 0) {
    return fs.readFileSync(path.resolve(contentFile), "utf8");
  }
  throw new Error("Either --content <json> or --content-file <path> is required");
}

function requireFlag(flags: ReadonlyMap<string, string>, name: string): string {
  const val = flags.get(name);
  if (val === undefined || val.trim().length === 0) {
    throw new Error(`Missing required CLI option ${name}`);
  }
  return val.trim();
}

function writeJsonLine(out: { write(chunk: string): unknown }, payload: unknown): void {
  out.write(`${JSON.stringify(payload, null, 2)}\n`);
}

function isoNowUtc(): string {
  return parseCanonicalUtcTimestamp(new Date().toISOString(), "now");
}

export async function runProducerCli(
  argv: readonly string[] = process.argv.slice(2),
  runtime: ProducerCliRuntime = {}
): Promise<number> {
  const env = runtime.env ?? process.env;
  const stdout = runtime.stdout ?? process.stdout;
  const stderr = runtime.stderr ?? process.stderr;

  const parsed = parseProducerCliArgs(argv, env);
  if (parsed.help) {
    stdout.write(HELP_TEXT);
    return 0;
  }

  const command = parsed.command;
  if (command === undefined) {
    throw new Error("No producer CLI command specified");
  }

  const fileCfg =
    parsed.configPath !== undefined ? loadProducerConfigFile(parsed.configPath) : {};

  const runsDir = parsed.flags.get("--runs-dir") ?? fileCfg.runsDir ?? path.resolve("runs");

  const existingRunFile =
    parsed.flags.has("--run-file") || parsed.flags.has("--run-id")
      ? resolveRunFilePath({
          runsDir,
          runId: parsed.flags.get("--run-id"),
          runFile: parsed.flags.get("--run-file")
        })
      : undefined;

  const existingRun =
    existingRunFile !== undefined &&
    command !== "prepare" &&
    (command !== "submit" || !parsed.flags.has("--event-type-id")) &&
    fs.existsSync(existingRunFile)
      ? loadProducerRun(existingRunFile)
      : undefined;

  const origin =
    parsed.flags.get("--origin") ??
    env["RELAYQUILL_API_ORIGIN"] ??
    existingRun?.origin ??
    fileCfg.origin;
  if (origin === undefined || origin.length === 0) {
    throw new Error("Missing API origin: supply --origin <url>, RELAYQUILL_API_ORIGIN, or --config");
  }

  const rawTenantId =
    parsed.flags.get("--tenant-id") ?? env["RELAYQUILL_TENANT_ID"] ?? existingRun?.tenant_id ?? fileCfg.tenantId;
  const rawProjectId =
    parsed.flags.get("--project-id") ?? env["RELAYQUILL_PROJECT_ID"] ?? existingRun?.project_id ?? fileCfg.projectId;
  const tenantId = rawTenantId !== undefined ? parseCanonicalUuid(rawTenantId, "tenant_id") : undefined;
  const projectId = rawProjectId !== undefined ? parseCanonicalUuid(rawProjectId, "project_id") : undefined;

  const credentialRef =
    parsed.flags.get("--credential-ref") ??
    env["RELAYQUILL_PRODUCER_CREDENTIAL_REF"] ??
    existingRun?.credential_ref ??
    fileCfg.credentialRef;

  const getCredential: ProducerCredentialProvider =
    runtime.getCredential ??
    (async () => {
      if (credentialRef === undefined || credentialRef.length === 0) {
        throw new Error(
          "Missing credential reference: supply --credential-ref <env:|file:|custody:> or --config"
        );
      }
      return resolveProducerCredentialFromRef({
        secretRef: credentialRef,
        env,
        ...(fileCfg.secretProvider !== undefined ? { secretProvider: fileCfg.secretProvider } : {})
      });
    });

  const client = createProducerClient({
    baseUrl: origin,
    ...(tenantId !== undefined && projectId !== undefined ? { tenantId, projectId } : {}),
    getCredential,
    ...(runtime.fetch !== undefined ? { fetch: runtime.fetch } : {})
  });

  const buildAndPersistRun = async (): Promise<{
    readonly run: StoredProducerRun;
    readonly runFile: string;
    readonly prepared: Awaited<ReturnType<typeof prepareEvent>>;
  }> => {
    const runId = validateRunId(
      parsed.flags.get("--run-id") ?? `run-${crypto.randomBytes(6).toString("hex")}`
    );
    const targetFile =
      existingRunFile ??
      resolveRunFilePath({
        runsDir,
        runId
      });

    const eventTypeId = parseCanonicalUuid(requireFlag(parsed.flags, "--event-type-id"), "event_type_id");
    const schemaVerRaw = Number(parsed.flags.get("--schema-version") ?? "1");
    if (!Number.isInteger(schemaVerRaw) || schemaVerRaw < 1) {
      throw new Error(`Invalid --schema-version: ${String(parsed.flags.get("--schema-version"))}`);
    }
    const businessKey = requireFlag(parsed.flags, "--business-key");
    const contentJson = readEventContentInput(parsed.flags);
    const explicitChannelId = parsed.flags.get("--channel-id");
    const idempotencyKey = parsed.flags.get("--idempotency-key");
    const producerEventTime = parsed.flags.get("--producer-event-time");
    const deadlineAt = parsed.flags.get("--deadline-at");

    const prepareInput: PrepareEventInput = {
      ...(explicitChannelId !== undefined
        ? { expectedPublicationChannelId: explicitChannelId }
        : { publicationContext: (await client.getPublicationContext()).data }),
      eventTypeId,
      eventSchemaVersion: schemaVerRaw,
      businessKey,
      content: contentJson,
      ...(idempotencyKey !== undefined ? { idempotencyKey } : {}),
      ...(producerEventTime !== undefined ? { producerEventTime } : {}),
      ...(deadlineAt !== undefined ? { deadlineAt } : {})
    };

    const prepared = await prepareEvent(prepareInput);
    const now = isoNowUtc();
    const run: StoredProducerRun = {
      schema_version: PRODUCER_RUN_SCHEMA_VERSION,
      run_id: runId,
      created_at: now,
      updated_at: now,
      origin,
      ...(tenantId !== undefined ? { tenant_id: tenantId } : {}),
      ...(projectId !== undefined ? { project_id: projectId } : {}),
      ...(credentialRef !== undefined ? { credential_ref: credentialRef } : {}),
      prepare_input: {
        expected_publication_channel_id: prepared.expectedPublicationChannelId,
        event_type_id: prepared.eventTypeId,
        event_schema_version: prepared.eventSchemaVersion,
        business_key: prepared.businessKey,
        idempotency_key: prepared.idempotencyKey,
        content_json: Buffer.from(prepared.getContentBytesCopy()).toString("utf8"),
        ...(prepared.producerEventTime !== undefined
          ? { producer_event_time: prepared.producerEventTime }
          : {}),
        ...(prepared.deadlineAt !== undefined ? { deadline_at: prepared.deadlineAt } : {})
      },
      safe_metadata: prepared.toSafeMetadata()
    };
    saveProducerRun(targetFile, run);
    return { run, runFile: targetFile, prepared };
  };

  switch (command) {
    case "prepare": {
      const { run, runFile } = await buildAndPersistRun();
      writeJsonLine(stdout, {
        ok: true,
        command: "prepare",
        run_id: run.run_id,
        run_file: runFile,
        safe_metadata: run.safe_metadata
      });
      return 0;
    }

    case "submit": {
      const preparedBundle =
        existingRun !== undefined && existingRunFile !== undefined
          ? {
              run: existingRun,
              runFile: existingRunFile,
              prepared: await reconstructPreparedEventFromRun(existingRun)
            }
          : await buildAndPersistRun();

      try {
        const res = await client.submitEvent(preparedBundle.prepared);
        const updated: StoredProducerRun = {
          ...preparedBundle.run,
          updated_at: isoNowUtc(),
          event_id: res.data.event.event_id,
          receipt_id: res.data.receipt.id,
          last_outcome: res.outcome
        };
        saveProducerRun(preparedBundle.runFile, updated);
        writeJsonLine(stdout, {
          ok: true,
          command: "submit",
          run_id: updated.run_id,
          run_file: preparedBundle.runFile,
          status: res.status,
          outcome: res.outcome,
          matched_existing: res.matchedExisting,
          attempts: res.attempts,
          event_id: res.data.event.event_id,
          receipt_id: res.data.receipt.id
        });
        return 0;
      } catch (err) {
        if (
          err instanceof ProducerAcceptanceUnknownError ||
          (err instanceof ProducerSdkError && err.acceptance === "unknown")
        ) {
          const updated: StoredProducerRun = {
            ...preparedBundle.run,
            updated_at: isoNowUtc(),
            last_outcome: "acceptance_unknown"
          };
          saveProducerRun(preparedBundle.runFile, updated);
          stderr.write(
            `${JSON.stringify({
              ok: false,
              command: "submit",
              acceptance: "unknown",
              code: err.code,
              run_id: updated.run_id,
              run_file: preparedBundle.runFile,
              message: err.message
            })}\n`
          );
          return 2;
        }
        throw err;
      }
    }

    case "resolve": {
      if (existingRun !== undefined && existingRunFile !== undefined) {
        const prepared = await reconstructPreparedEventFromRun(existingRun);
        const res = await client.resolvePreparedEvent(prepared);
        if (res.found) {
          const updated: StoredProducerRun = {
            ...existingRun,
            updated_at: isoNowUtc(),
            event_id: res.data.event.event_id,
            receipt_id: res.data.receipt.id,
            last_outcome: "resolved_committed"
          };
          saveProducerRun(existingRunFile, updated);
        }
        writeJsonLine(stdout, {
          ok: true,
          command: "resolve",
          run_id: existingRun.run_id,
          ...res
        });
        return 0;
      }

      const businessKey = requireFlag(parsed.flags, "--business-key");
      const rawShape = parsed.flags.get("--submitted-shape-sha256");
      const idemKey = parsed.flags.get("--idempotency-key");
      const res = await client.resolvePreparedEvent({
        businessKey,
        ...(rawShape !== undefined ? { submittedShapeSha256: parseSha256Hex(rawShape, "submitted_shape_sha256") } : {}),
        ...(idemKey !== undefined ? { idempotencyKey: idemKey } : {})
      });
      writeJsonLine(stdout, {
        ok: true,
        command: "resolve",
        ...res
      });
      return 0;
    }

    case "retry-original": {
      if (existingRun === undefined || existingRunFile === undefined) {
        throw new Error("retry-original requires --run-id <id> or --run-file <path> pointing to a saved run");
      }
      const prepared = await reconstructPreparedEventFromRun(existingRun);
      const resolved = await client.resolvePreparedEvent(prepared);
      if (resolved.found) {
        const updated: StoredProducerRun = {
          ...existingRun,
          updated_at: isoNowUtc(),
          event_id: resolved.data.event.event_id,
          receipt_id: resolved.data.receipt.id,
          last_outcome: "resolved_existing"
        };
        saveProducerRun(existingRunFile, updated);
        writeJsonLine(stdout, {
          ok: true,
          command: "retry-original",
          recovery_path: "resolved",
          run_id: updated.run_id,
          run_file: existingRunFile,
          event_id: resolved.data.event.event_id,
          receipt_id: resolved.data.receipt.id
        });
        return 0;
      }

      const submitted = await client.submitEvent(prepared);
      const updated: StoredProducerRun = {
        ...existingRun,
        updated_at: isoNowUtc(),
        event_id: submitted.data.event.event_id,
        receipt_id: submitted.data.receipt.id,
        last_outcome: submitted.outcome
      };
      saveProducerRun(existingRunFile, updated);
      writeJsonLine(stdout, {
        ok: true,
        command: "retry-original",
        recovery_path: "resubmitted",
        run_id: updated.run_id,
        run_file: existingRunFile,
        status: submitted.status,
        outcome: submitted.outcome,
        event_id: submitted.data.event.event_id,
        receipt_id: submitted.data.receipt.id
      });
      return 0;
    }

    case "status": {
      const eventIdRaw = parsed.flags.get("--event-id") ?? existingRun?.event_id;
      if (eventIdRaw === undefined) {
        throw new Error("status requires --event-id <uuid> or a run artifact with recorded event_id");
      }
      const eventId = parseCanonicalUuid(eventIdRaw, "event_id");
      const [eventRes, deliveriesRes] = await Promise.all([
        client.getEvent(eventId),
        client.listDeliveries({ eventId })
      ]);
      writeJsonLine(stdout, {
        ok: true,
        command: "status",
        event: eventRes.data,
        deliveries: deliveriesRes.data
      });
      return 0;
    }

    case "watch": {
      const deliveryIdRaw = parsed.flags.get("--delivery-id");
      const eventIdRaw = parsed.flags.get("--event-id") ?? existingRun?.event_id;
      if (deliveryIdRaw === undefined && eventIdRaw === undefined) {
        throw new Error(
          "watch requires --event-id <uuid>, --delivery-id <uuid>, or a run artifact with recorded event_id"
        );
      }
      const cursor = parsed.flags.get("--cursor");
      const maxFrames = Number(parsed.flags.get("--max-frames") ?? "10");
      const timeoutMs = Number(parsed.flags.get("--timeout-ms") ?? "5000");
      if (!Number.isInteger(maxFrames) || maxFrames < 1) {
        throw new Error(`Invalid --max-frames value: ${String(maxFrames)}`);
      }
      if (!Number.isInteger(timeoutMs) || timeoutMs < 1) {
        throw new Error(`Invalid --timeout-ms value: ${String(timeoutMs)}`);
      }

      const abortController = new AbortController();
      const timeoutHandle = setTimeout(() => {
        abortController.abort();
      }, timeoutMs);

      const stream =
        deliveryIdRaw !== undefined
          ? client.watchDelivery(parseCanonicalUuid(deliveryIdRaw, "delivery_id"), {
              ...(cursor !== undefined ? { cursor } : {}),
              signal: abortController.signal
            })
          : client.watchEvent(parseCanonicalUuid(eventIdRaw, "event_id"), {
              ...(cursor !== undefined ? { cursor } : {}),
              signal: abortController.signal
            });

      const frames: WatchFrame[] = [];
      try {
        for await (const frame of stream) {
          frames.push(frame);
          if (frames.length >= maxFrames) {
            abortController.abort();
            break;
          }
          if (
            frame.supported &&
            (frame.frameType === "authorization_lost" || frame.frameType === "resync_required")
          ) {
            break;
          }
        }
      } catch (err) {
        if (!abortController.signal.aborted) {
          throw err;
        }
      } finally {
        clearTimeout(timeoutHandle);
      }

      writeJsonLine(stdout, {
        ok: true,
        command: "watch",
        frame_count: frames.length,
        frames
      });
      return 0;
    }
  }
}

export {
  PRODUCER_RUN_SCHEMA_VERSION,
  loadProducerRun,
  reconstructPreparedEventFromRun,
  resolveRunFilePath,
  saveProducerRun,
  validateRunId,
  type StoredProducerPrepareInput,
  type StoredProducerRun
} from "./store.js";
export {
  resolveCustodyIpcEndpoint,
  resolveProducerCredentialFromRef,
  type ProducerIpcRef,
  type ProducerSecretProviderSettings
} from "./credentials.js";
