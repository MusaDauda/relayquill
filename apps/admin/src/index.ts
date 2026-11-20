import { type Temporal } from "@js-temporal/polyfill";
import { type BrokerTopologyManager, type InMemoryJetStreamBroker } from "@relayquill/broker";
import { ValidationDomainError } from "@relayquill/domain";
import { type PgAdapter, createPgAdapterFromConfig } from "@relayquill/postgres";
import {
  type BrokerConfig,
  type ResolvedBrokerEnvConfig,
  type RoleConfig,
  type SecretProvider,
  createSecretProvider,
  loadRoleConfig,
  resolveIpcChannelEndpoint,
  resolveRuntimeEnvironment
} from "@relayquill/runtime";
import { runApproveEnrollmentCommand, type OperatorChannelClient } from "./access.js";
import { runBrokerCommand } from "./broker.js";
import {
  ADMIN_HELP_TEXT,
  type ParsedAdminCliArgs,
  getRequiredStringFlag,
  getStringFlag,
  parseAdminCliArgs
} from "./cli.js";
import { runDbMigrate, runDbStatus, runDbVerify } from "./db.js";
import { type DiagnosticsSubcommand, runDiagnosticsCommand } from "./diagnostics.js";
import {
  type AdminIpcServerHandle,
  type ProviderSeedEntry,
  type StartAdminIpcServerOptions,
  startAdminIpcServer
} from "./local-provider.js";
import { runRecoveryCommand } from "./recovery.js";
import { runSigningDeliver } from "./signing.js";

export const ADMIN_APP_VERSION = "0.1.0" as const;

export * from "./access.js";
export * from "./broker.js";
export * from "./cli.js";
export * from "./db.js";
export * from "./diagnostics.js";
export * from "./local-provider.js";
export * from "./recovery.js";
export * from "./signing.js";

export interface AdminAppOptions {
  readonly config?: RoleConfig | undefined;
  readonly configPath?: string | undefined;
  readonly envFilePath?: string | undefined;
  readonly env?: Readonly<Record<string, string | undefined>> | undefined;
  readonly pgAdapter?: PgAdapter | undefined;
  readonly ownsPgAdapter?: boolean | undefined;
  readonly topologyManager?: BrokerTopologyManager | undefined;
  readonly inMemoryBroker?: InMemoryJetStreamBroker | undefined;
  readonly secretProvider?: SecretProvider | undefined;
  readonly operatorClient?: OperatorChannelClient | undefined;
  readonly operatorEndpoint?: string | undefined;
  readonly migrationsDir?: string | undefined;
  readonly now?: Temporal.Instant | undefined;
  readonly initialProviderEntries?: readonly ProviderSeedEntry[] | undefined;
  readonly providerOptions?: StartAdminIpcServerOptions | undefined;
}

export interface AdminApp {
  readonly config?: RoleConfig | undefined;
  readonly helpText: string;
  run(argv: readonly string[]): Promise<Record<string, unknown>>;
  startProviderServer(overrides?: StartAdminIpcServerOptions): Promise<AdminIpcServerHandle>;
  close(): Promise<void>;
}

function serializeBigInts(value: unknown): unknown {
  if (typeof value === "bigint") {
    return value.toString(10);
  }
  if (Array.isArray(value)) {
    return value.map(serializeBigInts);
  }
  if (value !== null && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value)) {
      if (v !== undefined) {
        out[k] = serializeBigInts(v);
      }
    }
    return out;
  }
  return value;
}

export function formatAdminJsonOutput(value: unknown): string {
  return JSON.stringify(serializeBigInts(value), null, 2);
}

export function createAdminApp(options: AdminAppOptions = {}): AdminApp {
  let activeConfig: RoleConfig | undefined = options.config;
  let ownedPgAdapter: PgAdapter | undefined;
  let activeProviderHandle: AdminIpcServerHandle | undefined;

  const resolveConfig = (parsed: ParsedAdminCliArgs): RoleConfig | undefined => {
    if (activeConfig !== undefined) {
      return activeConfig;
    }
    const cfgPath = parsed.configPath ?? options.configPath;
    if (cfgPath === undefined) {
      return undefined;
    }
    activeConfig = loadRoleConfig(cfgPath);
    return activeConfig;
  };

  const getPgAdapter = async (
    config: RoleConfig | undefined,
    envFilePath: string | undefined
  ): Promise<PgAdapter> => {
    if (options.pgAdapter !== undefined) {
      return options.pgAdapter;
    }
    if (ownedPgAdapter !== undefined) {
      return ownedPgAdapter;
    }
    if (config === undefined || !("database" in config) || config.database === undefined) {
      throw new ValidationDomainError({
        code: "INVALID_VALUE",
        message: "This command requires a configuration with database settings or an injected pgAdapter"
      });
    }
    const resolvedEnv = resolveRuntimeEnvironment(config, {
      env: options.env,
      envFilePath: envFilePath ?? options.envFilePath
    });
    const dbConfig = resolvedEnv.database ?? config.database;
    ownedPgAdapter = await createPgAdapterFromConfig(dbConfig);
    return ownedPgAdapter;
  };

  const getSecretProvider = (config: RoleConfig | undefined): SecretProvider => {
    if (options.secretProvider !== undefined) {
      return options.secretProvider;
    }
    if (config !== undefined && "secret_provider" in config && config.secret_provider !== undefined) {
      return createSecretProvider(config.secret_provider, { env: options.env });
    }
    return createSecretProvider({ mode: "in_memory_test" }, { env: options.env });
  };

  const resolveMigrationsDir = (
    parsed: ParsedAdminCliArgs,
    config: RoleConfig | undefined
  ): string => {
    const flagDir = getStringFlag(parsed.flags, "--migrations-dir");
    if (flagDir !== undefined) {
      return flagDir;
    }
    if (options.migrationsDir !== undefined) {
      return options.migrationsDir;
    }
    if (config !== undefined && "migrations_dir" in config && typeof config.migrations_dir === "string") {
      return config.migrations_dir;
    }
    return "migrations";
  };

  const startProviderServer = async (
    overrides: StartAdminIpcServerOptions = {}
  ): Promise<AdminIpcServerHandle> => {
    const cfg = activeConfig ?? options.config;
    const ipcRef =
      cfg !== undefined && "ipc" in cfg ? cfg.ipc : { env_name: "dev", channel: "provider" };
    const providerSettings =
      cfg !== undefined && "provider" in cfg ? cfg.provider : undefined;

    const handle = await startAdminIpcServer({
      ipc: ipcRef,
      env: options.env,
      providerSettings,
      ...(options.initialProviderEntries !== undefined
        ? { initialEntries: options.initialProviderEntries }
        : {}),
      ...options.providerOptions,
      ...overrides
    });
    activeProviderHandle = handle;
    return handle;
  };

  return {
    get config(): RoleConfig | undefined {
      return activeConfig;
    },
    helpText: ADMIN_HELP_TEXT,
    startProviderServer,
    async run(argv: readonly string[]): Promise<Record<string, unknown>> {
      const parsed = parseAdminCliArgs(argv);
      if (parsed.help) {
        return { ok: true, help: ADMIN_HELP_TEXT };
      }

      const [group, subcommand] = parsed.positionals;
      if (group === undefined) {
        throw new ValidationDomainError({
          code: "INVALID_VALUE",
          message: "Missing admin command group. Pass --help for usage."
        });
      }

      const cfg = resolveConfig(parsed);
      const envFilePath = parsed.envFilePath ?? options.envFilePath;

      switch (group) {
        case "db": {
          if (subcommand !== "status" && subcommand !== "migrate" && subcommand !== "verify") {
            throw new ValidationDomainError({
              code: "INVALID_VALUE",
              message: `Unknown db subcommand "${String(subcommand)}"; expected status|migrate|verify`
            });
          }
          const pgAdapter = await getPgAdapter(cfg, envFilePath);
          const migrationsDir = resolveMigrationsDir(parsed, cfg);
          if (subcommand === "status") {
            return (await runDbStatus(pgAdapter, migrationsDir)) as unknown as Record<string, unknown>;
          }
          if (subcommand === "migrate") {
            return (await runDbMigrate(pgAdapter, migrationsDir)) as unknown as Record<string, unknown>;
          }
          return (await runDbVerify(pgAdapter, migrationsDir)) as unknown as Record<string, unknown>;
        }

        case "broker": {
          if (subcommand !== "inspect" && subcommand !== "ensure" && subcommand !== "verify") {
            throw new ValidationDomainError({
              code: "INVALID_VALUE",
              message: `Unknown broker subcommand "${String(subcommand)}"; expected inspect|ensure|verify`
            });
          }
          let brokerConfig: BrokerConfig | ResolvedBrokerEnvConfig | undefined =
            cfg !== undefined && "broker" in cfg ? cfg.broker : undefined;
          if (cfg !== undefined && "broker" in cfg && cfg.broker !== undefined) {
            const resolvedEnv = resolveRuntimeEnvironment(cfg, {
              env: options.env,
              envFilePath
            });
            brokerConfig = resolvedEnv.broker ?? cfg.broker;
          }
          return (await runBrokerCommand({
            subcommand,
            brokerConfig,
            topologyManager: options.topologyManager,
            inMemoryBroker: options.inMemoryBroker,
            secretProvider: options.secretProvider
          })) as unknown as Record<string, unknown>;
        }

        case "provider": {
          if (subcommand !== "serve") {
            throw new ValidationDomainError({
              code: "INVALID_VALUE",
              message: `Unknown provider subcommand "${String(subcommand)}"; expected serve`
            });
          }
          const noSeed = parsed.flags.get("--no-seed") === true;
          const seedDev = parsed.flags.get("--seed-dev") === true || !noSeed;
          const allowAdmins = parsed.flags.get("--allow-admins") === true;
          const handle = await startProviderServer({
            seedDefaults: seedDev,
            allowBuiltInAdmins: allowAdmins
          });
          if (parsed.flags.get("--reseed") === true) {
            await handle.reseed();
          }
          return {
            ok: true,
            mode: "provider_serving",
            ...handle.status()
          };
        }

        case "access": {
          if (subcommand !== "approve-enrollment") {
            throw new ValidationDomainError({
              code: "INVALID_VALUE",
              message: `Unknown access subcommand "${String(subcommand)}"; expected approve-enrollment`
            });
          }
          const intentId = getRequiredStringFlag(parsed.flags, "--intent-id");
          const version = getRequiredStringFlag(parsed.flags, "--version");
          const comparisonSha256 = getRequiredStringFlag(parsed.flags, "--comparison-sha256");
          const operatorRef = getRequiredStringFlag(parsed.flags, "--operator-ref");
          const note = getStringFlag(parsed.flags, "--note");

          const operatorEndpoint =
            options.operatorEndpoint ??
            (cfg !== undefined && "operator_channel" in cfg && cfg.operator_channel !== undefined
              ? resolveIpcChannelEndpoint(cfg.operator_channel, options.env)
              : undefined);

          const pgAdapter =
            operatorEndpoint === undefined && options.operatorClient === undefined
              ? await getPgAdapter(cfg, envFilePath)
              : options.pgAdapter;

          return (await runApproveEnrollmentCommand(
            {
              intentId,
              version,
              comparisonSha256,
              operatorRef,
              ...(note !== undefined ? { note } : {})
            },
            {
              operatorEndpoint,
              operatorClient: options.operatorClient,
              pgAdapter,
              now: options.now
            }
          )) as unknown as Record<string, unknown>;
        }

        case "signing": {
          if (subcommand !== "deliver") {
            throw new ValidationDomainError({
              code: "INVALID_VALUE",
              message: `Unknown signing subcommand "${String(subcommand)}"; expected deliver`
            });
          }
          const pgAdapter = await getPgAdapter(cfg, envFilePath);
          const secretProvider = getSecretProvider(cfg);
          const intentId = getStringFlag(parsed.flags, "--intent-id");
          const kind = getStringFlag(parsed.flags, "--kind") as
            | "signing_key"
            | "producer_credential"
            | undefined;
          return (await runSigningDeliver({
            pgAdapter,
            secretProvider,
            intentId,
            kind,
            now: options.now
          })) as unknown as Record<string, unknown>;
        }

        case "recovery": {
          if (
            subcommand !== "inspect" &&
            subcommand !== "plan" &&
            subcommand !== "review" &&
            subcommand !== "execute"
          ) {
            throw new ValidationDomainError({
              code: "INVALID_VALUE",
              message: `Unknown recovery subcommand "${String(subcommand)}"; expected inspect|plan|review|execute`
            });
          }
          const pgAdapter = await getPgAdapter(cfg, envFilePath);
          const decisionRaw = getStringFlag(parsed.flags, "--decision");
          return runRecoveryCommand({
            subcommand,
            pgAdapter,
            planFile: getStringFlag(parsed.flags, "--plan-file"),
            tenantId: getStringFlag(parsed.flags, "--tenant-id"),
            projectId: getStringFlag(parsed.flags, "--project-id"),
            actionId: getStringFlag(parsed.flags, "--action-id"),
            operationId: getStringFlag(parsed.flags, "--operation-id"),
            incidentId: getStringFlag(parsed.flags, "--incident-id"),
            operatorRef: getStringFlag(parsed.flags, "--operator-ref"),
            reviewerRef: getStringFlag(parsed.flags, "--reviewer-ref"),
            decision:
              decisionRaw === "approve" || decisionRaw === "reject" ? decisionRaw : undefined,
            reasonCode: getStringFlag(parsed.flags, "--reason-code"),
            evidenceRef: getStringFlag(parsed.flags, "--evidence-ref")
          });
        }

        case "diagnostics": {
          const diagSub = (subcommand ?? "summary") as DiagnosticsSubcommand;
          if (diagSub !== "summary" && diagSub !== "project" && diagSub !== "event") {
            throw new ValidationDomainError({
              code: "INVALID_VALUE",
              message: `Unknown diagnostics subcommand "${String(subcommand)}"; expected summary|project|event`
            });
          }
          const operatorEndpoint =
            options.operatorEndpoint ??
            (cfg !== undefined && "operator_channel" in cfg && cfg.operator_channel !== undefined
              ? resolveIpcChannelEndpoint(cfg.operator_channel, options.env)
              : undefined);
          const pgAdapter =
            operatorEndpoint === undefined && options.operatorClient === undefined
              ? await getPgAdapter(cfg, envFilePath)
              : options.pgAdapter;
          const limitStr = getStringFlag(parsed.flags, "--limit");
          const limit = limitStr !== undefined ? Number.parseInt(limitStr, 10) : undefined;
          return runDiagnosticsCommand({
            subcommand: diagSub,
            pgAdapter,
            operatorEndpoint,
            operatorClient: options.operatorClient,
            tenantId: getStringFlag(parsed.flags, "--tenant-id"),
            projectId: getStringFlag(parsed.flags, "--project-id"),
            eventId: getStringFlag(parsed.flags, "--event-id"),
            limit
          });
        }

        default:
          throw new ValidationDomainError({
            code: "INVALID_VALUE",
            message: `Unknown admin command "${group}". Pass --help for usage.`
          });
      }
    },
    async close(): Promise<void> {
      if (activeProviderHandle !== undefined) {
        const handle = activeProviderHandle;
        activeProviderHandle = undefined;
        await handle.close();
      }
      if (ownedPgAdapter !== undefined) {
        const pg = ownedPgAdapter;
        ownedPgAdapter = undefined;
        await pg.close();
      } else if (options.ownsPgAdapter === true && options.pgAdapter !== undefined) {
        await options.pgAdapter.close();
      }
    }
  };
}

export async function runAdminCommand(
  argv: readonly string[],
  options: AdminAppOptions = {}
): Promise<Record<string, unknown>> {
  const app = createAdminApp(options);
  try {
    return await app.run(argv);
  } finally {
    await app.close();
  }
}
