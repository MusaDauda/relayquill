import {
  DependencyUnavailableDomainError,
  type CanonicalUtcTimestamp
} from "@relayquill/domain";
import {
  extractSqlState,
  isRetryableContentionError,
  mapPostgresError
} from "./errors.js";
import { readRequiredUtcTimestamp } from "./mappers.js";
import {
  type DatabaseAuthoritySchema,
  type PgIsolationMode,
  type PgQueryResult,
  type PgSupportSchema,
  type TransactionOptions
} from "./types.js";

export const DEFAULT_LOCK_TIMEOUT_MS = 2000 as const;
export const MAX_LOCK_TIMEOUT_MS = 2000 as const;
export const MAX_STATEMENT_TIMEOUT_MS = 5000 as const;
export const DEFAULT_DEADLINE_MS = 5000 as const;
export const DEFAULT_MAX_CONTENTION_ATTEMPTS = 3 as const;
export const MAX_CONTENTION_ATTEMPTS = 3 as const;
export const DEFAULT_BASE_BACKOFF_MS = 10 as const;
export const DEFAULT_MAX_BACKOFF_MS = 250 as const;

export interface TransactionSessionContext {
  readonly role: string;
  readonly schema: DatabaseAuthoritySchema;
  readonly supportSchema: PgSupportSchema;
  readonly isolation: PgIsolationMode;
  readonly attemptNumber: number;
  readonly deadlineMs: number;
  readonly signal?: AbortSignal | undefined;
  readonly lockTimeoutMs: number;
  readonly statementTimeoutMs: number;
  remainingBudgetMs(): number;
}

export interface TransactionBackendHandle {
  executeAttempt<T>(
    context: TransactionSessionContext,
    runner: (helpers: {
      query: <TRow extends Record<string, unknown> = Record<string, unknown>>(
        sql: string,
        params?: readonly unknown[]
      ) => Promise<PgQueryResult<TRow>>;
      exec: (sql: string) => Promise<void>;
      readClockTimestamp: () => Promise<CanonicalUtcTimestamp>;
    }) => Promise<{ readonly value: T; readonly markDiscard?: boolean | undefined }>
  ): Promise<T>;
}

const SAFE_IDENTIFIER_REGEX = /^[a-z_][a-z0-9_]*$/;

export function assertSafeSqlIdentifier(identifier: string, label = "identifier"): string {
  if (!SAFE_IDENTIFIER_REGEX.test(identifier)) {
    throw new DependencyUnavailableDomainError({
      code: "INVARIANT_VIOLATION",
      message: `Unsafe PostgreSQL ${label}: ${identifier}`,
      retryable: false,
      acceptance: "known_rejected"
    });
  }
  return identifier;
}

export function buildSearchPathSql(
  schema: DatabaseAuthoritySchema,
  supportSchema: PgSupportSchema,
  isolation: PgIsolationMode
): string {
  const safeSchema = assertSafeSqlIdentifier(schema, "schema");
  const safeSupport = assertSafeSqlIdentifier(supportSchema, "support_schema");
  if (isolation === "separate_databases") {
    return `SET LOCAL search_path TO ${safeSchema}, ${safeSupport}, public`;
  }
  return `SET LOCAL search_path TO ${safeSchema}, ${safeSupport}`;
}

export function buildTransactionGuardStatements(params: {
  readonly schema: DatabaseAuthoritySchema;
  readonly supportSchema: PgSupportSchema;
  readonly isolation: PgIsolationMode;
  readonly lockTimeoutMs: number;
  readonly statementTimeoutMs: number;
  readonly applyRole?: string | undefined;
  readonly readOnly?: boolean | undefined;
  readonly deferrable?: boolean | undefined;
}): string[] {
  const statements: string[] = [
    params.readOnly === true
      ? params.deferrable === true
        ? "SET TRANSACTION ISOLATION LEVEL READ COMMITTED READ ONLY DEFERRABLE"
        : "SET TRANSACTION ISOLATION LEVEL READ COMMITTED READ ONLY"
      : "SET TRANSACTION ISOLATION LEVEL READ COMMITTED",
    "SET LOCAL TIME ZONE 'UTC'",
    `SET LOCAL lock_timeout = '${Math.trunc(params.lockTimeoutMs)}ms'`,
    `SET LOCAL statement_timeout = '${Math.trunc(params.statementTimeoutMs)}ms'`,
    buildSearchPathSql(params.schema, params.supportSchema, params.isolation)
  ];
  if (params.applyRole !== undefined) {
    const safeRole = assertSafeSqlIdentifier(params.applyRole, "role");
    statements.push(`SET LOCAL ROLE ${safeRole}`);
  }
  return statements;
}

export async function queryClockTimestamp(
  queryFn: <TRow extends Record<string, unknown>>(
    sql: string,
    params?: readonly unknown[]
  ) => Promise<PgQueryResult<TRow>>
): Promise<CanonicalUtcTimestamp> {
  const res = await queryFn<{ clock_timestamp: unknown }>(
    "SELECT pg_catalog.clock_timestamp() AS clock_timestamp"
  );
  const first = res.rows[0];
  if (first === undefined) {
    throw new DependencyUnavailableDomainError({
      code: "DEPENDENCY_UNAVAILABLE",
      message: "PostgreSQL clock_timestamp() returned no row",
      retryable: false,
      acceptance: "unknown"
    });
  }
  return readRequiredUtcTimestamp(first, "clock_timestamp", "pg_catalog.clock_timestamp");
}

function clampPositiveInt(value: number | undefined, fallback: number, max: number): number {
  if (value === undefined || !Number.isFinite(value)) {
    return fallback;
  }
  const truncated = Math.trunc(value);
  if (truncated < 1) {
    return 1;
  }
  return truncated > max ? max : truncated;
}

function sleepWithAbort(delayMs: number, signal?: AbortSignal): Promise<void> {
  if (signal?.aborted === true) {
    return Promise.reject(new DOMException("Aborted during retry backoff", "AbortError"));
  }
  if (delayMs <= 0) {
    return Promise.resolve();
  }
  return new Promise<void>((resolve, reject) => {
    const timer = setTimeout(() => {
      cleanup();
      resolve();
    }, delayMs);

    const onAbort = (): void => {
      clearTimeout(timer);
      cleanup();
      reject(new DOMException("Aborted during retry backoff", "AbortError"));
    };

    const cleanup = (): void => {
      if (signal !== undefined) {
        signal.removeEventListener("abort", onAbort);
      }
    };

    if (signal !== undefined) {
      signal.addEventListener("abort", onAbort, { once: true });
    }
  });
}

function computeFullJitterBackoffMs(params: {
  readonly attempt: number;
  readonly baseBackoffMs: number;
  readonly maxBackoffMs: number;
  readonly remainingBudgetMs: number;
  readonly random: () => number;
}): number {
  const exponentialCap = Math.min(
    params.maxBackoffMs,
    params.baseBackoffMs * 2 ** (params.attempt - 1)
  );
  const sample = Math.min(1, Math.max(0, params.random()));
  const rawJitter = Math.max(1, Math.floor(sample * exponentialCap));
  return Math.min(params.remainingBudgetMs, rawJitter);
}

/**
 * Executes a bounded `READ COMMITTED` PostgreSQL transaction enforcing:
 * - `lock_timeout <= 2000ms`
 * - `statement_timeout <= Math.min(5000, remaining_budget_ms)`
 * - post-setup `clock_timestamp()` helper and budget enforcement
 * - bounded exponential backoff + full jitter retries (up to 3 attempts) on SQLSTATEs
 *   `55P03` (`lock_not_available`), `40P01` (`deadlock_detected`), and `40001` (`serialization_failure`)
 * - clean connection discard on aborted/cancelled/dirty failures (`isConnectionDiscardRequired`)
 */
export async function runBoundedTransaction<T>(params: {
  readonly backend: TransactionBackendHandle;
  readonly role: string;
  readonly schema: DatabaseAuthoritySchema;
  readonly supportSchema: PgSupportSchema;
  readonly isolation: PgIsolationMode;
  readonly fn: (tx: {
    readonly role: string;
    readonly schema: DatabaseAuthoritySchema;
    readonly supportSchema: PgSupportSchema;
    readonly isolation: PgIsolationMode;
    readonly attemptNumber: number;
    readonly deadlineMs: number;
    readonly signal?: AbortSignal | undefined;
    remainingBudgetMs(): number;
    readClockTimestamp(): Promise<CanonicalUtcTimestamp>;
    query<TRow extends Record<string, unknown> = Record<string, unknown>>(
      sql: string,
      params?: readonly unknown[]
    ): Promise<PgQueryResult<TRow>>;
    exec(sql: string): Promise<void>;
  }) => Promise<T>;
  readonly options?: TransactionOptions | undefined;
}): Promise<T> {
  const opts = params.options;
  const nowMs = opts?.nowMs ?? (() => performance.now());
  const deadlineMs = clampPositiveInt(opts?.deadlineMs, DEFAULT_DEADLINE_MS, 60_000);
  const lockTimeoutMs = clampPositiveInt(
    opts?.lockTimeoutMs,
    DEFAULT_LOCK_TIMEOUT_MS,
    MAX_LOCK_TIMEOUT_MS
  );
  const requestedStatementMax = clampPositiveInt(
    opts?.statementTimeoutMs,
    MAX_STATEMENT_TIMEOUT_MS,
    MAX_STATEMENT_TIMEOUT_MS
  );
  const retryEnabled = opts?.retryOnContention === true;
  const maxAttempts = retryEnabled
    ? clampPositiveInt(opts?.maxAttempts, DEFAULT_MAX_CONTENTION_ATTEMPTS, MAX_CONTENTION_ATTEMPTS)
    : 1;
  const baseBackoffMs = clampPositiveInt(opts?.baseBackoffMs, DEFAULT_BASE_BACKOFF_MS, 5_000);
  const maxBackoffMs = clampPositiveInt(opts?.maxBackoffMs, DEFAULT_MAX_BACKOFF_MS, 5_000);
  const random = opts?.random ?? Math.random;
  const signal = opts?.signal;
  const isAborted = (): boolean => signal?.aborted === true;
  const startedAtMs = nowMs();

  const remainingBudgetMs = (): number => Math.max(0, Math.floor(deadlineMs - (nowMs() - startedAtMs)));

  for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
    if (isAborted()) {
      throw new DependencyUnavailableDomainError({
        code: "ACCEPTANCE_UNKNOWN",
        message: "Transaction aborted before attempt started",
        retryable: false,
        acceptance: "unknown"
      });
    }

    const budgetBeforeAcquire = remainingBudgetMs();
    if (budgetBeforeAcquire <= 0) {
      throw new DependencyUnavailableDomainError({
        code: "EXPIRED",
        message: `Transaction deadline budget (${deadlineMs}ms) exhausted before attempt ${attempt}`,
        retryable: false,
        acceptance: "known_rejected"
      });
    }

    const effectiveStatementTimeoutMs = Math.max(
      1,
      Math.min(requestedStatementMax, budgetBeforeAcquire)
    );
    const effectiveLockTimeoutMs = Math.max(1, Math.min(lockTimeoutMs, effectiveStatementTimeoutMs));

    const sessionCtx: TransactionSessionContext = {
      role: params.role,
      schema: params.schema,
      supportSchema: params.supportSchema,
      isolation: params.isolation,
      attemptNumber: attempt,
      deadlineMs,
      signal,
      lockTimeoutMs: effectiveLockTimeoutMs,
      statementTimeoutMs: effectiveStatementTimeoutMs,
      remainingBudgetMs
    };

    try {
      return await params.backend.executeAttempt(sessionCtx, async (helpers) => {
        if (isAborted()) {
          return {
            value: await Promise.reject<T>(
              new DOMException("Transaction aborted after connection acquisition", "AbortError")
            ),
            markDiscard: true
          };
        }

        const budgetAfterConnect = remainingBudgetMs();
        if (budgetAfterConnect <= 0) {
          throw new DependencyUnavailableDomainError({
            code: "EXPIRED",
            message: `Transaction deadline budget (${deadlineMs}ms) exhausted waiting for connection`,
            retryable: false,
            acceptance: "known_rejected"
          });
        }

        const tx = {
          role: params.role,
          schema: params.schema,
          supportSchema: params.supportSchema,
          isolation: params.isolation,
          attemptNumber: attempt,
          deadlineMs,
          signal,
          remainingBudgetMs,
          readClockTimestamp: helpers.readClockTimestamp,
          query: async <TRow extends Record<string, unknown> = Record<string, unknown>>(
            sql: string,
            queryParams?: readonly unknown[]
          ): Promise<PgQueryResult<TRow>> => {
            if (isAborted()) {
              throw new DOMException("Transaction aborted before query execution", "AbortError");
            }
            if (remainingBudgetMs() <= 0) {
              throw new DependencyUnavailableDomainError({
                code: "ACCEPTANCE_UNKNOWN",
                message: `Transaction deadline budget (${deadlineMs}ms) exhausted before query`,
                retryable: false,
                acceptance: "unknown"
              });
            }
            return helpers.query<TRow>(sql, queryParams);
          },
          exec: async (sql: string): Promise<void> => {
            if (isAborted()) {
              throw new DOMException("Transaction aborted before exec", "AbortError");
            }
            if (remainingBudgetMs() <= 0) {
              throw new DependencyUnavailableDomainError({
                code: "ACCEPTANCE_UNKNOWN",
                message: `Transaction deadline budget (${deadlineMs}ms) exhausted before exec`,
                retryable: false,
                acceptance: "unknown"
              });
            }
            await helpers.exec(sql);
          }
        };

        const value = await params.fn(tx);
        return { value, markDiscard: isAborted() };
      });
    } catch (err) {
      const canRetry =
        retryEnabled &&
        isRetryableContentionError(err) &&
        attempt < maxAttempts &&
        !isAborted();

      const sqlState = extractSqlState(err) ?? "unknown";

      if (canRetry) {
        const remainingForRetry = remainingBudgetMs();
        if (remainingForRetry > 0) {
          const delayMs = computeFullJitterBackoffMs({
            attempt,
            baseBackoffMs,
            maxBackoffMs,
            remainingBudgetMs: remainingForRetry,
            random
          });
          if (delayMs > 0 && remainingBudgetMs() > delayMs) {
            opts?.onRetry?.({
              attempt,
              maxAttempts,
              sqlState,
              delayMs,
              remainingBudgetMs: remainingForRetry
            });
            try {
              await sleepWithAbort(delayMs, signal);
              continue;
            } catch (abortErr) {
              throw mapPostgresError(abortErr, { operation: `withTransaction(${params.role})` });
            }
          }
        }
      }

      throw mapPostgresError(err, { operation: `withTransaction(${params.role})` });
    }
  }

  throw new DependencyUnavailableDomainError({
    code: "LOCK_CONTENTION",
    message: `Transaction retry budget exhausted after ${maxAttempts} attempts`,
    retryable: false,
    acceptance: "known_rejected"
  });
}
