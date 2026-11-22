import { AsyncLocalStorage } from "node:async_hooks";
import type { Temporal } from "@js-temporal/polyfill";
import {
  type CanonicalUtcTimestamp,
  ValidationDomainError,
  formatUtcTimestamp,
  parseUtcTimestamp
} from "@relayquill/domain";
import {
  type DatabaseRole,
  type PgAdapter,
  type PgQueryOptions,
  type PgQueryResult,
  type PgTransactionClient,
  type TransactionOptions
} from "@relayquill/postgres";

const activeTxStorage = new AsyncLocalStorage<PgTransactionClient>();

/**
 * Wraps a `PgAdapter` so nested `withTransaction` / `query` / `exec` calls within
 * the same async call chain and database role reuse the active transaction instead
 * of deadlocking single-connection adapters such as PGlite.
 */
export function createReentrantPgAdapter(pgAdapter: PgAdapter): PgAdapter {
  return {
    get backend() {
      return pgAdapter.backend;
    },
    get mode() {
      return pgAdapter.mode;
    },
    get isolation() {
      return pgAdapter.isolation;
    },
    get schema() {
      return pgAdapter.schema;
    },
    get supportSchema() {
      return pgAdapter.supportSchema;
    },
    get configuredRole() {
      return pgAdapter.configuredRole;
    },
    verifySessionIdentity(expectedUser?: string) {
      return pgAdapter.verifySessionIdentity(expectedUser);
    },
    query<TRow extends Record<string, unknown> = Record<string, unknown>>(
      sql: string,
      params?: readonly unknown[],
      options?: PgQueryOptions
    ): Promise<PgQueryResult<TRow>> {
      const activeTx = activeTxStorage.getStore();
      if (
        activeTx !== undefined &&
        (options?.role === undefined || activeTx.role === options.role)
      ) {
        return activeTx.query<TRow>(sql, params);
      }
      return pgAdapter.query<TRow>(sql, params, options);
    },
    exec(sql: string, options?: PgQueryOptions): Promise<void> {
      const activeTx = activeTxStorage.getStore();
      if (
        activeTx !== undefined &&
        (options?.role === undefined || activeTx.role === options.role)
      ) {
        return activeTx.exec(sql);
      }
      return pgAdapter.exec(sql, options);
    },
    withTransaction<T>(
      role: DatabaseRole,
      fn: (tx: PgTransactionClient) => Promise<T>,
      options?: TransactionOptions
    ): Promise<T> {
      const activeTx = activeTxStorage.getStore();
      if (activeTx !== undefined && activeTx.role === role) {
        return fn(activeTx);
      }
      return pgAdapter.withTransaction(
        role,
        (tx) => activeTxStorage.run(tx, () => fn(tx)),
        options
      );
    },
    close() {
      return pgAdapter.close();
    }
  };
}

export interface PgExecutor {
  query<TRow extends Record<string, unknown> = Record<string, unknown>>(
    sql: string,
    params?: readonly unknown[]
  ): Promise<{ readonly rows: readonly TRow[] }>;
  inTx<T>(fn: (tx: PgTransactionClient) => Promise<T>): Promise<T>;
}

export function createAdapterExecutor(
  pgAdapter: PgAdapter,
  role = pgAdapter.configuredRole
): PgExecutor {
  return {
    query(sql, params = []) {
      return pgAdapter.withTransaction(role, (tx) => tx.query(sql, params));
    },
    inTx(fn) {
      return pgAdapter.withTransaction(role, fn, { retryOnContention: true });
    }
  };
}

export function createTxExecutor(tx: PgTransactionClient): PgExecutor {
  return {
    query(sql, params = []) {
      return tx.query(sql, params);
    },
    inTx(fn) {
      return fn(tx);
    }
  };
}

export function readByteaBuffer(val: unknown, field: string): Buffer {
  if (Buffer.isBuffer(val)) {
    return val;
  }
  if (val instanceof Uint8Array) {
    return Buffer.from(val);
  }
  if (typeof val === "string" && val.startsWith("\\x")) {
    return Buffer.from(val.slice(2), "hex");
  }
  throw new ValidationDomainError({
    code: "INVALID_VALUE",
    message: `Expected bytea buffer for "${field}"`
  });
}

export function readByteaUint8(val: unknown, field: string): Uint8Array {
  return new Uint8Array(readByteaBuffer(val, field));
}

export function toParamBuffer(bytes: Uint8Array | Buffer): Buffer {
  return Buffer.from(bytes.buffer, bytes.byteOffset, bytes.byteLength);
}

export function readInstant(val: unknown, field: string): Temporal.Instant {
  return parseUtcTimestamp(val, field).instant;
}

export function readOptionalInstant(val: unknown, field: string): Temporal.Instant | null {
  if (val === null || val === undefined) {
    return null;
  }
  return parseUtcTimestamp(val, field).instant;
}

export function toUtcParam(instant: Temporal.Instant): CanonicalUtcTimestamp {
  return formatUtcTimestamp(instant);
}

export function toBigIntSafe(val: unknown, field: string): bigint {
  if (typeof val === "bigint") {
    return val;
  }
  if (typeof val === "number" && Number.isSafeInteger(val)) {
    return BigInt(val);
  }
  if (typeof val === "string" && /^-?\d+$/.test(val.trim())) {
    return BigInt(val.trim());
  }
  throw new ValidationDomainError({
    code: "INVALID_INT64",
    message: `Expected int64 for "${field}"`
  });
}

export function asText(val: unknown, fallback = ""): string {
  if (typeof val === "string") {
    return val;
  }
  if (typeof val === "number" || typeof val === "bigint" || typeof val === "boolean") {
    return String(val);
  }
  return fallback;
}

export function asOptionalText(val: unknown): string | null {
  if (val === null || val === undefined) {
    return null;
  }
  if (typeof val === "string") {
    return val;
  }
  if (typeof val === "number" || typeof val === "bigint" || typeof val === "boolean") {
    return String(val);
  }
  return null;
}

export function toIntSafe(val: unknown, field: string): number {
  if (typeof val === "number" && Number.isSafeInteger(val)) {
    return val;
  }
  if (typeof val === "bigint") {
    return Number(val);
  }
  if (typeof val === "string" && /^-?\d+$/.test(val.trim())) {
    return Number.parseInt(val.trim(), 10);
  }
  throw new ValidationDomainError({
    code: "INVALID_VALUE",
    message: `Expected safe integer for "${field}"`
  });
}
