import fs from "node:fs";
import pg from "pg";
import {
  AuthorizationDomainError,
  DependencyUnavailableDomainError,
  ValidationDomainError,
  type CanonicalUtcTimestamp
} from "@relayquill/domain";
import {
  type DatabaseAuthMode,
  type DatabaseConfig,
  type DatabaseMode,
  type DatabasePoolMode,
  type DatabaseTlsMode,
  type ResolvedDatabaseEnvConfig,
  type SecretHandle
} from "@relayquill/runtime";
import { isConnectionDiscardRequired, mapPostgresError } from "./errors.js";
import { readRequiredString } from "./mappers.js";
import { createScopedPgTypes } from "./parsers.js";
import {
  assertSafeSqlIdentifier,
  buildSearchPathSql,
  buildTransactionGuardStatements,
  queryClockTimestamp,
  runBoundedTransaction,
  type TransactionBackendHandle,
  type TransactionSessionContext
} from "./transaction.js";
import {
  type DatabaseAuthoritySchema,
  type DatabaseRole,
  type PgAdapter,
  type PgIsolationMode,
  type PgQueryOptions,
  type PgQueryResult,
  type PgSessionIdentity,
  type PgSupportSchema,
  type PgTransactionClient,
  type StandardPgAdapterOptions,
  type TransactionOptions
} from "./types.js";

const LOOPBACK_HOSTS = new Set(["localhost", "127.0.0.1", "::1", "[::1]"]);

export interface NormalizedStandardPgConfig {
  readonly mode: DatabaseMode;
  readonly isolation: PgIsolationMode;
  readonly host: string;
  readonly port: number;
  readonly name: string;
  readonly schema: DatabaseAuthoritySchema;
  readonly supportSchema: PgSupportSchema;
  readonly configuredRole: string;
  readonly user: string;
  readonly authentication: DatabaseAuthMode;
  readonly tlsMode: DatabaseTlsMode;
  readonly tlsCaFile?: string | undefined;
  readonly poolMode: DatabasePoolMode;
  readonly maximumConnections: number;
  readonly connectionTimeoutMs: number;
  readonly statementTimeoutMs: number;
  readonly lockTimeoutMs: number;
  readonly passwordHandle?: SecretHandle | undefined;
}

function isResolvedEnvConfig(
  config: DatabaseConfig | ResolvedDatabaseEnvConfig
): config is ResolvedDatabaseEnvConfig {
  return "configuredRole" in config;
}

export function normalizeStandardPgConfig(
  config: DatabaseConfig | ResolvedDatabaseEnvConfig,
  options: StandardPgAdapterOptions = {}
): NormalizedStandardPgConfig {
  if (isResolvedEnvConfig(config)) {
    return {
      mode: config.mode,
      isolation: "shared_database_schemas",
      host: config.host,
      port: config.port,
      name: config.name,
      schema: config.schema,
      supportSchema: config.supportSchema,
      configuredRole: config.configuredRole,
      user: config.user,
      authentication: config.authentication,
      tlsMode: config.tlsMode,
      tlsCaFile: config.tlsCaFile,
      poolMode: config.poolMode,
      maximumConnections: options.maxConnections ?? 16,
      connectionTimeoutMs: options.connectionTimeoutMs ?? 5000,
      statementTimeoutMs: 5000,
      lockTimeoutMs: 2000,
      passwordHandle: config.passwordHandle
    };
  }

  return {
    mode: config.mode,
    isolation: config.isolation,
    host: config.host,
    port: config.port,
    name: config.name,
    schema: config.schema,
    supportSchema: config.support_schema,
    configuredRole: config.role,
    user: config.role,
    authentication: config.authentication,
    tlsMode: config.tls_mode,
    tlsCaFile: config.tls_ca_file,
    poolMode: config.pool_mode,
    maximumConnections: options.maxConnections ?? config.maximum_connections,
    connectionTimeoutMs: options.connectionTimeoutMs ?? config.connection_timeout_ms,
    statementTimeoutMs: config.statement_timeout_ms,
    lockTimeoutMs: config.lock_timeout_ms
  };
}

function resolveSslConfig(
  normalized: NormalizedStandardPgConfig,
  options: StandardPgAdapterOptions
): pg.PoolConfig["ssl"] {
  const requiresVerifyFull =
    normalized.mode === "standard_tls" ||
    normalized.mode === "hosted_neon" ||
    normalized.mode === "hosted_supabase" ||
    normalized.mode === "release_rds_iam";

  if (requiresVerifyFull && normalized.tlsMode !== "verify_full") {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Database mode "${normalized.mode}" requires tls_mode="verify_full" (got "${normalized.tlsMode}")`,
      fieldErrors: [{ path: "database.tls_mode", code: "INVALID_VALUE" }]
    });
  }

  if (normalized.tlsMode === "disabled_fixture") {
    const isLocal = LOOPBACK_HOSTS.has(normalized.host.trim().toLowerCase());
    if (
      normalized.mode !== "development_trusted_local" ||
      (!isLocal && options.allowInsecureLocalhost !== true)
    ) {
      throw new ValidationDomainError({
        code: "INVALID_VALUE",
        message: `Unencrypted PostgreSQL disabled_fixture mode is forbidden for host "${normalized.host}" and mode "${normalized.mode}"`,
        fieldErrors: [{ path: "database.tls_mode", code: "INVALID_VALUE" }]
      });
    }
    return false;
  }

  if (normalized.tlsMode !== "verify_full") {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Invalid TLS mode "${normalized.tlsMode}" for standard PostgreSQL pool`,
      fieldErrors: [{ path: "database.tls_mode", code: "INVALID_VALUE" }]
    });
  }

  let ca: string | undefined = options.tlsCaPem;
  if (ca === undefined && normalized.tlsCaFile !== undefined) {
    try {
      ca = fs.readFileSync(normalized.tlsCaFile, "utf8");
    } catch (err) {
      throw new DependencyUnavailableDomainError({
        code: "SECRET_CUSTODY_ERROR",
        message: `Unable to load database TLS CA file "${normalized.tlsCaFile}": ${
          err instanceof Error ? err.message : String(err)
        }`,
        retryable: false,
        acceptance: "known_rejected"
      });
    }
  }

  return {
    rejectUnauthorized: true,
    servername: normalized.host,
    ...(ca !== undefined ? { ca } : {})
  };
}

function unwrapSecretValue(secret: string | SecretHandle): string {
  if (typeof secret === "string") {
    if (secret.length === 0) {
      throw new ValidationDomainError({
        code: "SECRET_CUSTODY_ERROR",
        message: "Database credential supplier returned an empty string"
      });
    }
    return secret;
  }
  return secret.useUtf8((value) => {
    if (value.length === 0) {
      throw new ValidationDomainError({
        code: "SECRET_CUSTODY_ERROR",
        message: `SecretHandle "${secret.id}" is empty`
      });
    }
    return value;
  });
}

function resolvePasswordProvider(
  normalized: NormalizedStandardPgConfig,
  options: StandardPgAdapterOptions
): pg.PoolConfig["password"] {
  if (normalized.authentication === "aws_rds_iam_token") {
    const provider = options.iamTokenProvider;
    if (provider === undefined) {
      throw new ValidationDomainError({
        code: "SECRET_CUSTODY_ERROR",
        message: "Database authentication mode aws_rds_iam_token requires an iamTokenProvider"
      });
    }
    return async (): Promise<string> => {
      const issued = await provider({
        host: normalized.host,
        port: normalized.port,
        user: normalized.user,
        database: normalized.name
      });
      return unwrapSecretValue(issued);
    };
  }

  if (normalized.authentication === "trusted_local_only") {
    if (normalized.mode !== "development_trusted_local") {
      throw new ValidationDomainError({
        code: "INVALID_VALUE",
        message: `trusted_local_only authentication is forbidden in mode "${normalized.mode}"`
      });
    }
    return undefined;
  }

  if (
    normalized.authentication === "secret_provider_password" ||
    normalized.authentication === "scram_sha_256"
  ) {
    if (options.passwordProvider !== undefined) {
      const provider = options.passwordProvider;
      return async (): Promise<string> => unwrapSecretValue(await provider());
    }
    if (normalized.passwordHandle !== undefined) {
      const handle = normalized.passwordHandle;
      return (): string => unwrapSecretValue(handle);
    }
    throw new ValidationDomainError({
      code: "SECRET_CUSTODY_ERROR",
      message: `Database authentication mode "${normalized.authentication}" requires a passwordProvider or passwordHandle`
    });
  }

  throw new ValidationDomainError({
    code: "INVALID_VALUE",
    message: `Unsupported authentication mode "${normalized.authentication}" for standard pg adapter`
  });
}

/**
 * Builds a strict `pg.PoolConfig` using only standard PostgreSQL (`pg`) wire configuration:
 * zero proprietary vendor DB SDKs, strict `verify_full` TLS outside local fixtures, fresh
 * dynamic RDS IAM token callback support, and custom OID type overrides matching `PGlite`.
 */
export function buildPgPoolConfig(
  config: DatabaseConfig | ResolvedDatabaseEnvConfig,
  options: StandardPgAdapterOptions = {}
): pg.PoolConfig {
  const normalized = normalizeStandardPgConfig(config, options);
  if (normalized.mode === "portable_pglite") {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: 'Use createPGliteAdapter for mode="portable_pglite", not standard pg Pool'
    });
  }

  const ssl = resolveSslConfig(normalized, options);
  const password = resolvePasswordProvider(normalized, options);
  const poolConfig: pg.PoolConfig = {
    host: normalized.host,
    port: normalized.port,
    database: normalized.name,
    user: normalized.user,
    ...(password !== undefined ? { password } : {}),
    ssl,
    max: Math.max(1, normalized.maximumConnections),
    connectionTimeoutMillis: Math.max(100, normalized.connectionTimeoutMs),
    idleTimeoutMillis: options.idleTimeoutMs ?? 30_000,
    allowExitOnIdle: false,
    statement_timeout: false,
    types: createScopedPgTypes(),
    application_name:
      options.applicationName ?? `relayquill-${normalized.configuredRole}`
  };

  if (normalized.poolMode !== "transaction_pooler") {
    poolConfig.idle_in_transaction_session_timeout = Math.max(
      5_000,
      normalized.statementTimeoutMs * 2
    );
  }

  return poolConfig;
}

function mapRawPgResult<TRow extends Record<string, unknown>>(
  raw: pg.QueryResult<TRow>
): PgQueryResult<TRow> {
  return {
    rows: raw.rows,
    rowCount: raw.rowCount ?? raw.rows.length,
    command: raw.command,
    fields: raw.fields.map((field) => ({
      name: field.name,
      dataTypeID: field.dataTypeID
    }))
  };
}

async function readSessionIdentity(
  client: Pick<pg.PoolClient, "query">
): Promise<PgSessionIdentity> {
  const res = await client.query<{
    database: unknown;
    current_user: unknown;
    session_user: unknown;
    search_path: unknown;
  }>(
    "SELECT pg_catalog.current_database() AS database, current_user AS current_user, pg_catalog.session_user AS session_user, pg_catalog.current_setting('search_path') AS search_path"
  );
  const row = res.rows[0];
  if (row === undefined) {
    throw new DependencyUnavailableDomainError({
      code: "DEPENDENCY_UNAVAILABLE",
      message: "Session identity query returned no row",
      retryable: true,
      acceptance: "unknown"
    });
  }
  return {
    database: readRequiredString(row, "database", "current_database"),
    currentUser: readRequiredString(row, "current_user", "current_user"),
    sessionUser: readRequiredString(row, "session_user", "session_user"),
    searchPath: readRequiredString(row, "search_path", "search_path")
  };
}

function assertSessionIdentityMatches(
  identity: PgSessionIdentity,
  expectedDatabase: string,
  expectedUser: string
): void {
  if (identity.database !== expectedDatabase) {
    throw new AuthorizationDomainError({
      code: "FORBIDDEN",
      message: `Connected database "${identity.database}" does not match configured database "${expectedDatabase}"`
    });
  }
  if (identity.sessionUser !== expectedUser && identity.currentUser !== expectedUser) {
    throw new AuthorizationDomainError({
      code: "FORBIDDEN",
      message: `Connected session user "${identity.sessionUser}" (current_user "${identity.currentUser}") does not match expected role "${expectedUser}"`
    });
  }
}

export class StandardPgAdapter implements PgAdapter {
  readonly backend = "pg" as const;
  readonly mode: DatabaseMode;
  readonly isolation: PgIsolationMode;
  readonly schema: DatabaseAuthoritySchema;
  readonly supportSchema: PgSupportSchema;
  readonly configuredRole: string;

  readonly #pool: pg.Pool;
  readonly #expectedDatabase: string;
  readonly #expectedUser: string;
  readonly #verifyOnConnect: boolean;
  readonly #defaultStatementTimeoutMs: number;
  readonly #defaultLockTimeoutMs: number;
  readonly #nowMs?: (() => number) | undefined;
  readonly #verifiedClients = new WeakSet<pg.PoolClient>();
  #closed = false;

  constructor(
    config: DatabaseConfig | ResolvedDatabaseEnvConfig,
    options: StandardPgAdapterOptions = {},
    poolOverride?: pg.Pool
  ) {
    const normalized = normalizeStandardPgConfig(config, options);
    const poolConfig = buildPgPoolConfig(config, options);
    this.mode = normalized.mode;
    this.isolation = normalized.isolation;
    this.schema = normalized.schema;
    this.supportSchema = normalized.supportSchema;
    this.configuredRole = normalized.configuredRole;
    this.#expectedDatabase = normalized.name;
    this.#expectedUser = normalized.user;
    this.#verifyOnConnect = options.verifyOnConnect ?? true;
    this.#defaultStatementTimeoutMs = Math.min(5000, Math.max(1, normalized.statementTimeoutMs));
    this.#defaultLockTimeoutMs = Math.min(2000, Math.max(1, normalized.lockTimeoutMs));
    this.#nowMs = options.nowMs;

    this.#pool = poolOverride ?? new pg.Pool(poolConfig);
    this.#pool.on("error", (err) => {
      options.onPoolError?.(mapPostgresError(err, { operation: "pg.Pool" }));
    });
  }

  get pool(): pg.Pool {
    return this.#pool;
  }

  async verifySessionIdentity(expectedUser?: string): Promise<PgSessionIdentity> {
    this.#assertOpen();
    const client = await this.#pool.connect();
    let discard = false;
    try {
      const identity = await readSessionIdentity(client);
      assertSessionIdentityMatches(
        identity,
        this.#expectedDatabase,
        expectedUser ?? this.#expectedUser
      );
      this.#verifiedClients.add(client);
      return identity;
    } catch (err) {
      discard = true;
      throw mapPostgresError(err, { operation: "verifySessionIdentity" });
    } finally {
      client.release(discard);
    }
  }

  async query<TRow extends Record<string, unknown> = Record<string, unknown>>(
    sql: string,
    params: readonly unknown[] = [],
    options?: PgQueryOptions
  ): Promise<PgQueryResult<TRow>> {
    this.#assertOpen();
    const role = options?.role ?? this.configuredRole;
    const schema = options?.schema ?? this.schema;
    const statementTimeoutMs = Math.min(
      5000,
      Math.max(1, options?.statementTimeoutMs ?? this.#defaultStatementTimeoutMs)
    );
    const backend = this.#createBackendHandle(schema, undefined);
    return runBoundedTransaction({
      backend,
      role,
      schema,
      supportSchema: this.supportSchema,
      isolation: this.isolation,
      options: {
        deadlineMs: statementTimeoutMs,
        statementTimeoutMs,
        lockTimeoutMs: this.#defaultLockTimeoutMs,
        signal: options?.signal,
        nowMs: this.#nowMs,
        retryOnContention: false
      },
      fn: async (tx) => tx.query<TRow>(sql, params)
    });
  }

  async exec(sql: string, options?: PgQueryOptions): Promise<void> {
    await this.query(sql, [], options);
  }

  async withTransaction<T>(
    role: DatabaseRole,
    fn: (tx: PgTransactionClient) => Promise<T>,
    options?: TransactionOptions
  ): Promise<T> {
    this.#assertOpen();
    const backend = this.#createBackendHandle(this.schema, options);
    return runBoundedTransaction({
      backend,
      role,
      schema: this.schema,
      supportSchema: this.supportSchema,
      isolation: this.isolation,
      fn,
      options: {
        lockTimeoutMs: options?.lockTimeoutMs ?? this.#defaultLockTimeoutMs,
        statementTimeoutMs: options?.statementTimeoutMs ?? this.#defaultStatementTimeoutMs,
        deadlineMs: options?.deadlineMs ?? this.#defaultStatementTimeoutMs,
        retryOnContention: options?.retryOnContention,
        maxAttempts: options?.maxAttempts,
        baseBackoffMs: options?.baseBackoffMs,
        maxBackoffMs: options?.maxBackoffMs,
        random: options?.random,
        signal: options?.signal,
        nowMs: options?.nowMs ?? this.#nowMs,
        onRetry: options?.onRetry,
        readOnly: options?.readOnly,
        deferrable: options?.deferrable
      }
    });
  }

  async close(): Promise<void> {
    if (this.#closed) {
      return;
    }
    this.#closed = true;
    await this.#pool.end();
  }

  #assertOpen(): void {
    if (this.#closed) {
      throw new DependencyUnavailableDomainError({
        code: "DEPENDENCY_UNAVAILABLE",
        message: "StandardPgAdapter pool has already been closed",
        retryable: false,
        acceptance: "known_rejected"
      });
    }
  }

  #createBackendHandle(
    schema: DatabaseAuthoritySchema,
    txOptions?: TransactionOptions
  ): TransactionBackendHandle {
    return {
      executeAttempt: async <T>(
        context: TransactionSessionContext,
        runner: (helpers: {
          query: <TRow extends Record<string, unknown> = Record<string, unknown>>(
            sql: string,
            params?: readonly unknown[]
          ) => Promise<PgQueryResult<TRow>>;
          exec: (sql: string) => Promise<void>;
          readClockTimestamp: () => Promise<CanonicalUtcTimestamp>;
        }) => Promise<{ readonly value: T; readonly markDiscard?: boolean | undefined }>
      ): Promise<T> => {
        let client: pg.PoolClient;
        try {
          client = await this.#pool.connect();
        } catch (err) {
          throw mapPostgresError(err, { operation: "pool.connect" });
        }

        let begun = false;
        let discard = false;
        let abortListener: (() => void) | undefined;

        const onAbortSignal = (): void => {
          discard = true;
        };

        if (context.signal !== undefined) {
          if (context.signal.aborted) {
            client.release(true);
            throw new DOMException("Transaction aborted immediately after acquire", "AbortError");
          }
          abortListener = onAbortSignal;
          context.signal.addEventListener("abort", abortListener, { once: true });
        }

        try {
          if (this.#verifyOnConnect && !this.#verifiedClients.has(client)) {
            const identity = await readSessionIdentity(client);
            assertSessionIdentityMatches(identity, this.#expectedDatabase, this.#expectedUser);
            this.#verifiedClients.add(client);
          }

          assertSafeSqlIdentifier(context.role, "role");
          await client.query("BEGIN");
          begun = true;

          const guardStatements = buildTransactionGuardStatements({
            schema,
            supportSchema: context.supportSchema,
            isolation: context.isolation,
            lockTimeoutMs: context.lockTimeoutMs,
            statementTimeoutMs: context.statementTimeoutMs,
            readOnly: txOptions?.readOnly,
            deferrable: txOptions?.deferrable
          });
          for (const stmt of guardStatements) {
            await client.query(stmt);
          }

          const queryFn = async <TRow extends Record<string, unknown> = Record<string, unknown>>(
            sql: string,
            queryParams: readonly unknown[] = []
          ): Promise<PgQueryResult<TRow>> => {
            if (context.signal?.aborted === true) {
              discard = true;
              throw new DOMException("Query aborted by signal", "AbortError");
            }
            const res = await client.query<TRow>({
              text: sql,
              values: [...queryParams]
            });
            return mapRawPgResult(res);
          };

          const execFn = async (sql: string): Promise<void> => {
            await queryFn(sql);
          };

          const outcome = await runner({
            query: queryFn,
            exec: execFn,
            readClockTimestamp: () => queryClockTimestamp(queryFn)
          });

          if (outcome.markDiscard === true || context.signal?.aborted === true) {
            discard = true;
            await client.query("ROLLBACK").catch(() => {
              discard = true;
            });
            throw new DOMException("Transaction aborted before commit", "AbortError");
          }

          await client.query("COMMIT");
          return outcome.value;
        } catch (err) {
          if (isConnectionDiscardRequired(err) || context.signal?.aborted === true) {
            discard = true;
          }
          if (begun && !discard) {
            try {
              await client.query("ROLLBACK");
            } catch {
              discard = true;
            }
          }
          throw err;
        } finally {
          if (context.signal !== undefined && abortListener !== undefined) {
            context.signal.removeEventListener("abort", abortListener);
          }
          client.release(discard);
        }
      }
    };
  }
}

export function createStandardPgAdapter(
  config: DatabaseConfig | ResolvedDatabaseEnvConfig,
  options: StandardPgAdapterOptions = {}
): StandardPgAdapter {
  void buildSearchPathSql;
  return new StandardPgAdapter(config, options);
}
