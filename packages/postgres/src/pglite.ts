import { DependencyUnavailableDomainError, ValidationDomainError, type CanonicalUtcTimestamp } from "@relayquill/domain";
import { type DatabaseConfig, type ResolvedDatabaseEnvConfig } from "@relayquill/runtime";
import { isConnectionDiscardRequired, mapPostgresError } from "./errors.js";
import { readRequiredString } from "./mappers.js";
import { RELAYQUILL_PGLITE_PARSERS } from "./parsers.js";
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
  type PGliteAdapterOptions,
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

export interface PGliteQueryFieldLike {
  readonly name: string;
  readonly dataTypeID: number;
}

export interface PGliteResultsLike<TRow = Record<string, unknown>> {
  readonly rows: TRow[];
  readonly affectedRows?: number | undefined;
  readonly command?: string | undefined;
  readonly rowCount?: number | undefined;
  readonly fields: PGliteQueryFieldLike[];
}

export interface PGliteTxLike {
  query<T = Record<string, unknown>>(
    query: string,
    params?: unknown[]
  ): Promise<PGliteResultsLike<T>>;
  exec(query: string): Promise<Array<PGliteResultsLike>>;
  rollback(): Promise<void>;
  readonly closed: boolean;
}

export interface PGliteDbLike {
  readonly closed: boolean;
  query<T = Record<string, unknown>>(
    query: string,
    params?: unknown[]
  ): Promise<PGliteResultsLike<T>>;
  exec(query: string): Promise<Array<PGliteResultsLike>>;
  transaction<T>(callback: (tx: PGliteTxLike) => Promise<T>): Promise<T>;
  close(): Promise<void>;
}

interface PGliteModuleLike {
  readonly PGlite: {
    create(options: {
      readonly dataDir?: string | undefined;
      readonly extensions?: Readonly<Record<string, unknown>> | undefined;
      readonly parsers?: Readonly<Record<number, (value: string) => unknown>> | undefined;
    }): Promise<PGliteDbLike>;
  };
}

interface BtreeGistModuleLike {
  readonly btree_gist: unknown;
}

const PGLITE_MODULE_ID = "@electric-sql/pglite";
const PGLITE_BTREE_GIST_MODULE_ID = "@electric-sql/pglite/contrib/btree_gist";

async function createRawPGliteInstance(dataDir: string): Promise<PGliteDbLike> {
  const pgliteMod = (await import(PGLITE_MODULE_ID)) as PGliteModuleLike;
  const btreeMod = (await import(PGLITE_BTREE_GIST_MODULE_ID)) as BtreeGistModuleLike;
  return pgliteMod.PGlite.create({
    dataDir,
    extensions: { btree_gist: btreeMod.btree_gist },
    parsers: RELAYQUILL_PGLITE_PARSERS
  });
}

function mapPGliteResult<TRow extends Record<string, unknown>>(
  raw: PGliteResultsLike<TRow>
): PgQueryResult<TRow> {
  return {
    rows: raw.rows,
    rowCount: raw.affectedRows ?? raw.rowCount ?? raw.rows.length,
    command: raw.command ?? "",
    fields: raw.fields.map((field) => ({
      name: field.name,
      dataTypeID: field.dataTypeID
    }))
  };
}

export class PGliteAdapter implements PgAdapter {
  readonly backend = "pglite" as const;
  readonly mode = "portable_pglite" as const;
  readonly isolation: PgIsolationMode;
  readonly schema: DatabaseAuthoritySchema;
  readonly supportSchema: PgSupportSchema;
  readonly configuredRole: string;

  readonly #db: PGliteDbLike;
  readonly #ownsDb: boolean;
  readonly #applySetLocalRole: boolean;
  readonly #nowMs?: (() => number) | undefined;
  #closed = false;

  constructor(
    db: PGliteDbLike,
    options: PGliteAdapterOptions & { readonly ownsDb?: boolean | undefined } = {}
  ) {
    this.#db = db;
    this.#ownsDb = options.ownsDb ?? true;
    this.schema = options.schema ?? "rq";
    this.supportSchema = options.supportSchema ?? "rq_support";
    this.isolation = options.isolation ?? "shared_database_schemas";
    this.configuredRole = options.configuredRole ?? "postgres";
    this.#applySetLocalRole = options.applySetLocalRole ?? false;
    this.#nowMs = options.nowMs;
  }

  get raw(): PGliteDbLike {
    return this.#db;
  }

  async verifySessionIdentity(expectedUser?: string): Promise<PgSessionIdentity> {
    this.#assertOpen();
    const res = await this.#db.query<{
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
        message: "PGlite session identity check returned no row",
        retryable: false,
        acceptance: "unknown"
      });
    }
    const identity: PgSessionIdentity = {
      database: readRequiredString(row, "database", "current_database"),
      currentUser: readRequiredString(row, "current_user", "current_user"),
      sessionUser: readRequiredString(row, "session_user", "session_user"),
      searchPath: readRequiredString(row, "search_path", "search_path")
    };
    if (
      expectedUser !== undefined &&
      identity.currentUser !== expectedUser &&
      identity.sessionUser !== expectedUser
    ) {
      throw new ValidationDomainError({
        code: "FORBIDDEN",
        message: `PGlite session user "${identity.currentUser}" does not match expected "${expectedUser}"`
      });
    }
    return identity;
  }

  async query<TRow extends Record<string, unknown> = Record<string, unknown>>(
    sql: string,
    params: readonly unknown[] = [],
    options?: PgQueryOptions
  ): Promise<PgQueryResult<TRow>> {
    this.#assertOpen();
    const schema = options?.schema ?? this.schema;
    const role = options?.role ?? this.configuredRole;
    const statementTimeoutMs = Math.min(5000, Math.max(1, options?.statementTimeoutMs ?? 5000));
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
        lockTimeoutMs: 2000,
        signal: options?.signal,
        nowMs: this.#nowMs,
        retryOnContention: false
      },
      fn: async (tx) => tx.query<TRow>(sql, params)
    });
  }

  /**
   * Executes multi-statement SQL (such as migration scripts) directly in PGlite.
   * For `shared_database_schemas`, applies session search_path before execution.
   */
  async exec(sql: string, options?: PgQueryOptions): Promise<void> {
    this.#assertOpen();
    const schema = options?.schema ?? this.schema;
    try {
      await this.#db.exec("SET TIME ZONE 'UTC'");
      if (this.isolation === "shared_database_schemas") {
        await this.#db.exec(
          buildSearchPathSql(schema, this.supportSchema, this.isolation).replace(
            "SET LOCAL ",
            "SET "
          )
        );
      }
      await this.#db.exec(sql);
    } catch (err) {
      throw mapPostgresError(err, { operation: "pglite.exec" });
    }
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
        ...options,
        nowMs: options?.nowMs ?? this.#nowMs
      }
    });
  }

  async close(): Promise<void> {
    if (this.#closed) {
      return;
    }
    this.#closed = true;
    if (this.#ownsDb && !this.#db.closed) {
      await this.#db.close();
    }
  }

  #assertOpen(): void {
    if (this.#closed || this.#db.closed) {
      throw new DependencyUnavailableDomainError({
        code: "DEPENDENCY_UNAVAILABLE",
        message: "PGliteAdapter instance is already closed",
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
        return this.#db.transaction(async (rawTx) => {
          const safeRole = assertSafeSqlIdentifier(context.role, "role");
          const applyRole =
            this.#applySetLocalRole && safeRole !== "postgres" ? safeRole : undefined;

          const guardStatements = buildTransactionGuardStatements({
            schema,
            supportSchema: context.supportSchema,
            isolation: context.isolation,
            lockTimeoutMs: context.lockTimeoutMs,
            statementTimeoutMs: context.statementTimeoutMs,
            applyRole,
            readOnly: txOptions?.readOnly,
            deferrable: txOptions?.deferrable
          });
          for (const stmt of guardStatements) {
            await rawTx.exec(stmt);
          }

          const queryFn = async <TRow extends Record<string, unknown> = Record<string, unknown>>(
            sql: string,
            queryParams: readonly unknown[] = []
          ): Promise<PgQueryResult<TRow>> => {
            if (context.signal?.aborted === true) {
              throw new DOMException("PGlite query aborted by signal", "AbortError");
            }
            const res = await rawTx.query<TRow>(sql, [...queryParams]);
            return mapPGliteResult(res);
          };

          const execFn = async (sql: string): Promise<void> => {
            if (context.signal?.aborted === true) {
              throw new DOMException("PGlite exec aborted by signal", "AbortError");
            }
            await rawTx.exec(sql);
          };

          try {
            const outcome = await runner({
              query: queryFn,
              exec: execFn,
              readClockTimestamp: () => queryClockTimestamp(queryFn)
            });
            if (outcome.markDiscard === true || context.signal?.aborted === true) {
              await rawTx.rollback();
              throw new DOMException("PGlite transaction aborted before commit", "AbortError");
            }
            return outcome.value;
          } catch (err) {
            if (isConnectionDiscardRequired(err) && !rawTx.closed) {
              await rawTx.rollback().catch(() => {});
            }
            throw err;
          }
        });
      }
    };
  }
}

export async function createPGliteAdapter(
  options: PGliteAdapterOptions = {}
): Promise<PGliteAdapter> {
  const schema = options.schema ?? "rq";
  const supportSchema = options.supportSchema ?? "rq_support";
  const isolation = options.isolation ?? "shared_database_schemas";
  const db = await createRawPGliteInstance(options.dataDir ?? "memory://");

  try {
    await db.exec("SET TIME ZONE 'UTC';");
    await db.exec("CREATE EXTENSION IF NOT EXISTS btree_gist;");
    if (options.createSchemaIfMissing === true) {
      await db.exec(`CREATE SCHEMA IF NOT EXISTS ${assertSafeSqlIdentifier(schema, "schema")};`);
      await db.exec(
        `CREATE SCHEMA IF NOT EXISTS ${assertSafeSqlIdentifier(supportSchema, "support_schema")};`
      );
    }
  } catch (err) {
    await db.close().catch(() => {});
    throw mapPostgresError(err, { operation: "createPGliteAdapter" });
  }

  return new PGliteAdapter(db, {
    ...options,
    schema,
    supportSchema,
    isolation,
    ownsDb: true
  });
}

export interface PGliteAuthorityCluster {
  readonly isolation: PgIsolationMode;
  readonly rq: PGliteAdapter;
  readonly rc: PGliteAdapter;
  readonly pi: PGliteAdapter;
  close(): Promise<void>;
}

/**
 * Creates a full three-authority PGlite test cluster (`rq`, `rc`, `pi`) in either
 * `separate_databases` mode (three isolated PGlite instances) or `shared_database_schemas`
 * mode (one shared PGlite instance with separate schemas).
 */
export async function createPGliteAuthorityCluster(params?: {
  readonly isolation?: PgIsolationMode | undefined;
  readonly applySetLocalRole?: boolean | undefined;
}): Promise<PGliteAuthorityCluster> {
  const isolation = params?.isolation ?? "shared_database_schemas";
  const applySetLocalRole = params?.applySetLocalRole ?? false;

  if (isolation === "separate_databases") {
    const rq = await createPGliteAdapter({
      schema: "rq",
      supportSchema: "rq_support",
      isolation,
      configuredRole: "rq_migrator",
      applySetLocalRole
    });
    try {
      const rc = await createPGliteAdapter({
        schema: "rc",
        supportSchema: "rq_support",
        isolation,
        configuredRole: "receiver_migrator",
        applySetLocalRole
      });
      try {
        const pi = await createPGliteAdapter({
          schema: "pi",
          supportSchema: "rq_support",
          isolation,
          configuredRole: "provider_migrator",
          applySetLocalRole
        });
        return {
          isolation,
          rq,
          rc,
          pi,
          async close(): Promise<void> {
            await Promise.all([rq.close(), rc.close(), pi.close()]);
          }
        };
      } catch (err) {
        await rc.close().catch(() => {});
        throw err;
      }
    } catch (err) {
      await rq.close().catch(() => {});
      throw err;
    }
  }

  const sharedDb = await createRawPGliteInstance("memory://");

  try {
    await sharedDb.exec("SET TIME ZONE 'UTC'; CREATE EXTENSION IF NOT EXISTS btree_gist;");
    const rq = new PGliteAdapter(sharedDb, {
      schema: "rq",
      supportSchema: "rq_support",
      isolation,
      configuredRole: "rq_migrator",
      applySetLocalRole,
      ownsDb: true
    });
    const rc = new PGliteAdapter(sharedDb, {
      schema: "rc",
      supportSchema: "rq_support",
      isolation,
      configuredRole: "receiver_migrator",
      applySetLocalRole,
      ownsDb: false
    });
    const pi = new PGliteAdapter(sharedDb, {
      schema: "pi",
      supportSchema: "rq_support",
      isolation,
      configuredRole: "provider_migrator",
      applySetLocalRole,
      ownsDb: false
    });
    return {
      isolation,
      rq,
      rc,
      pi,
      async close(): Promise<void> {
        await rq.close();
      }
    };
  } catch (err) {
    if (!sharedDb.closed) {
      await sharedDb.close().catch(() => {});
    }
    throw mapPostgresError(err, { operation: "createPGliteAuthorityCluster" });
  }
}

export async function createPgAdapterFromConfig(
  config: DatabaseConfig | ResolvedDatabaseEnvConfig,
  options?: {
    readonly pglite?: PGliteAdapterOptions | undefined;
    readonly pg?: StandardPgAdapterOptions | undefined;
  }
): Promise<PgAdapter> {
  if (config.mode === "portable_pglite") {
    const schema = config.schema;
    const supportSchema =
      "supportSchema" in config ? config.supportSchema : config.support_schema;
    const configuredRole = "configuredRole" in config ? config.configuredRole : config.role;
    const isolation = "isolation" in config ? config.isolation : "shared_database_schemas";
    return createPGliteAdapter({
      schema,
      supportSchema,
      isolation,
      configuredRole,
      ...options?.pglite
    });
  }

  const { createStandardPgAdapter } = await import("./pool.js");
  return createStandardPgAdapter(config, options?.pg);
}
