import { PGlite, TransactionAbortedError } from '@electric-sql/pglite';
import { btree_gist } from '@electric-sql/pglite/contrib/btree_gist';

export const EXACT_PG_PARSERS = Object.freeze({
  1184: (value) => value, // timestamptz -> exact PG string (microseconds preserved)
  1114: (value) => value, // timestamp -> exact PG string (no local TZ shift)
  20: (value) => value // int8 -> exact decimal string (>53-bit safe)
});

export const RETRYABLE_SQLSTATES = new Set(['55P03', '40P01', '40001']);

const AUTHORITY_NAMES = ['rq', 'rc', 'pi'];
const SAFE_IDENT_REGEX = /^[a-z_][a-z0-9_]*$/;

function assertSafeIdentifier(ident) {
  if (!SAFE_IDENT_REGEX.test(ident)) {
    throw new Error(`Unsafe SQL identifier: ${ident}`);
  }
  return ident;
}

export function createBarrier(parties) {
  if (!Number.isInteger(parties) || parties < 1) {
    throw new Error(`Barrier parties must be a positive integer, received ${parties}`);
  }
  let waiting = [];
  let arrived = 0;

  return {
    get count() {
      return arrived;
    },
    async arrive() {
      arrived += 1;
      if (arrived >= parties) {
        const waiters = waiting;
        waiting = [];
        for (const resolve of waiters) {
          resolve();
        }
        return;
      }
      await new Promise((resolve) => {
        waiting.push(resolve);
      });
    },
    reset() {
      arrived = 0;
      waiting = [];
    }
  };
}

export function createSqlStateError(sqlState, message) {
  const err = new Error(message ?? `Simulated PostgreSQL SQLSTATE ${sqlState}`);
  err.code = sqlState;
  err.sqlstate = sqlState;
  return err;
}

export function createContentionFaultInjector(rules = []) {
  const queue = [...rules];
  let injectedCount = 0;

  return {
    get injectedCount() {
      return injectedCount;
    },
    enqueue(sqlState, message) {
      queue.push({ sqlState, message });
    },
    maybeFail() {
      if (queue.length === 0) {
        return;
      }
      const next = queue.shift();
      injectedCount += 1;
      throw createSqlStateError(next.sqlState, next.message);
    }
  };
}

function sleep(ms) {
  return new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
}

export async function withRetryOnContention(fn, options = {}) {
  const maxAttempts = options.maxAttempts ?? 6;
  const baseDelayMs = options.baseDelayMs ?? 5;
  const maxDelayMs = options.maxDelayMs ?? 80;
  const deadlineMs = options.deadlineMs ?? 5_000;
  const random = options.random ?? Math.random;
  const onRetry = options.onRetry;

  const startedAt = Date.now();

  for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
    try {
      return await fn(attempt);
    } catch (err) {
      const code = err?.code ?? err?.sqlstate;
      const isRetryable = typeof code === 'string' && RETRYABLE_SQLSTATES.has(code);
      if (!isRetryable || attempt >= maxAttempts) {
        throw err;
      }

      const elapsedMs = Date.now() - startedAt;
      const remainingMs = deadlineMs - elapsedMs;
      if (remainingMs <= 0) {
        throw err;
      }

      const capMs = Math.min(maxDelayMs, baseDelayMs * (2 ** (attempt - 1)));
      const jitteredMs = Math.min(remainingMs, Math.max(1, Math.floor(random() * capMs)));
      if (typeof onRetry === 'function') {
        onRetry({ attempt, code, delayMs: jitteredMs, remainingMs });
      }
      await sleep(jitteredMs);
    }
  }

  throw new Error('Exhausted retry loop unexpectedly');
}

function wrapPgliteAuthority(db, schemaName) {
  const schemaPrefix = schemaName ? `SET LOCAL search_path TO ${assertSafeIdentifier(schemaName)}, public;` : '';

  return {
    kind: 'pglite',
    schema: schemaName ?? 'public',
    raw: db,
    async query(sql, params = []) {
      if (!schemaName) {
        return db.query(sql, params);
      }
      return db.transaction(async (tx) => {
        await tx.exec(schemaPrefix);
        return tx.query(sql, params);
      });
    },
    async exec(sql) {
      if (!schemaName) {
        return db.exec(sql);
      }
      return db.transaction(async (tx) => {
        await tx.exec(schemaPrefix);
        return tx.exec(sql);
      });
    },
    async withTransaction(fn, opts = {}) {
      const executeTx = () => db.transaction(async (tx) => {
        if (schemaName) {
          await tx.exec(schemaPrefix);
        }
        return fn(tx);
      });
      if (opts.retryOnContention) {
        return withRetryOnContention(executeTx, opts);
      }
      return executeTx();
    }
  };
}

async function createLivePgHarness(pgUrl, options) {
  const authorities = options.authorities ?? AUTHORITY_NAMES;
  const mode = options.mode ?? 'shared_database_schemas';
  if (mode !== 'separate_databases' && mode !== 'shared_database_schemas') {
    throw new Error(`Unsupported pg-pglite mode: ${mode}`);
  }

  const safeAuthorities = authorities.map((name) => ({
    name,
    safeName: assertSafeIdentifier(name)
  }));

  const pgUrls = options.pgUrls ?? null;
  if (mode === 'separate_databases') {
    const missing = safeAuthorities
      .map(({ name }) => name)
      .filter((name) => !pgUrls?.[name] || !String(pgUrls[name]).trim());
    if (missing.length > 0) {
      throw new Error(
        `Live PostgreSQL separate_databases mode requires per-authority pgUrls for [${missing.join(', ')}] to avoid public schema collision`
      );
    }
  } else if (!pgUrl) {
    throw new Error('Live PostgreSQL shared_database_schemas mode requires a non-empty pgUrl');
  }

  let pgMod;
  try {
    pgMod = await import('pg');
  } catch (err) {
    throw new Error(
      'RELAYQUILL_TEST_PG_URL is set, but the "pg" package is not installed in node_modules.',
      { cause: err }
    );
  }

  const Pool = pgMod.Pool ?? pgMod.default?.Pool;
  const types = pgMod.types ?? pgMod.default?.types;
  if (!Pool || !types) {
    throw new Error('Loaded "pg" module does not expose Pool and types');
  }

  types.setTypeParser(1184, EXACT_PG_PARSERS[1184]);
  types.setTypeParser(1114, EXACT_PG_PARSERS[1114]);
  types.setTypeParser(20, EXACT_PG_PARSERS[20]);

  const basePoolConfig = {
    ...(options.poolOptions ?? {}),
    ...(options.connectionTimeoutMillis !== undefined
      ? { connectionTimeoutMillis: options.connectionTimeoutMillis }
      : {})
  };

  const pools = [];
  const closePoolsBestEffort = async () => {
    for (const pool of pools) {
      await pool.end().catch(() => {});
    }
  };

  const dbs = {};
  try {
    const sharedPool = mode === 'shared_database_schemas'
      ? new Pool({ ...basePoolConfig, connectionString: pgUrl })
      : null;
    if (sharedPool) {
      sharedPool.on('error', () => {});
      pools.push(sharedPool);
      await sharedPool.query('CREATE EXTENSION IF NOT EXISTS btree_gist;');
    }

    for (const { name, safeName } of safeAuthorities) {
      let authorityPool = sharedPool;
      if (mode === 'separate_databases') {
        authorityPool = new Pool({
          ...basePoolConfig,
          connectionString: String(pgUrls[name]).trim()
        });
        authorityPool.on('error', () => {});
        pools.push(authorityPool);
        await authorityPool.query('CREATE EXTENSION IF NOT EXISTS btree_gist;');
      } else {
        await authorityPool.query(`CREATE SCHEMA IF NOT EXISTS ${safeName};`);
      }

      dbs[name] = {
        kind: 'pg',
        schema: mode === 'shared_database_schemas' ? safeName : 'public',
        raw: authorityPool,
        async query(sql, params = []) {
          const client = await authorityPool.connect();
          try {
            await client.query('BEGIN');
            if (mode === 'shared_database_schemas') {
              await client.query(`SET LOCAL search_path TO ${safeName}, public`);
            }
            const result = await client.query(sql, params);
            await client.query('COMMIT');
            return result;
          } catch (err) {
            try {
              await client.query('ROLLBACK');
            } catch {
              // Ignore rollback errors after failed statement.
            }
            throw err;
          } finally {
            client.release();
          }
        },
        async exec(sql) {
          return this.query(sql);
        },
        async withTransaction(fn, opts = {}) {
          const executeTx = async () => {
            const client = await authorityPool.connect();
            try {
              await client.query('BEGIN');
              if (mode === 'shared_database_schemas') {
                await client.query(`SET LOCAL search_path TO ${safeName}, public`);
              }
              const res = await fn(client);
              await client.query('COMMIT');
              return res;
            } catch (err) {
              try {
                await client.query('ROLLBACK');
              } catch {
                // Ignore rollback errors after failed statement.
              }
              throw err;
            } finally {
              client.release();
            }
          };
          if (opts.retryOnContention) {
            return withRetryOnContention(executeTx, opts);
          }
          return executeTx();
        }
      };
    }
  } catch (err) {
    await closePoolsBestEffort();
    throw err;
  }

  let cleanedUp = false;

  return {
    mode,
    backend: 'pg',
    dbs,
    TransactionAbortedError,
    createBarrier,
    createContentionFaultInjector,
    withRetryOnContention,
    async cleanup() {
      if (cleanedUp) {
        return;
      }
      cleanedUp = true;
      const errors = [];
      for (const pool of pools) {
        try {
          await pool.end();
        } catch (err) {
          errors.push(err);
        }
      }
      if (errors.length > 0) {
        throw new AggregateError(errors, 'Failed to close PostgreSQL pools cleanly');
      }
    }
  };
}

export async function createPgHarness(options = {}) {
  const pgUrl = (options.pgUrl ?? process.env.RELAYQUILL_TEST_PG_URL ?? '').trim();
  if (pgUrl || options.pgUrls) {
    return createLivePgHarness(pgUrl, options);
  }

  const mode = options.mode ?? 'separate_databases';
  if (mode !== 'separate_databases' && mode !== 'shared_database_schemas') {
    throw new Error(`Unsupported pg-pglite mode: ${mode}`);
  }

  const authorities = options.authorities ?? AUTHORITY_NAMES;
  const safeAuthorities = authorities.map((name) => ({
    name,
    safeName: assertSafeIdentifier(name)
  }));
  const instances = [];
  const dbs = {};

  try {
    if (mode === 'separate_databases') {
      for (const { name } of safeAuthorities) {
        const db = await PGlite.create({
          dataDir: 'memory://',
          extensions: { btree_gist },
          parsers: EXACT_PG_PARSERS
        });
        instances.push(db);
        await db.exec('CREATE EXTENSION IF NOT EXISTS btree_gist;');
        dbs[name] = wrapPgliteAuthority(db, null);
      }
    } else {
      const sharedDb = await PGlite.create({
        dataDir: 'memory://',
        extensions: { btree_gist },
        parsers: EXACT_PG_PARSERS
      });
      instances.push(sharedDb);
      await sharedDb.exec('CREATE EXTENSION IF NOT EXISTS btree_gist;');

      for (const { name, safeName } of safeAuthorities) {
        await sharedDb.exec(`CREATE SCHEMA IF NOT EXISTS ${safeName};`);
        dbs[name] = wrapPgliteAuthority(sharedDb, safeName);
      }
    }
  } catch (err) {
    for (const db of instances) {
      if (!db.closed) {
        await db.close().catch(() => {});
      }
    }
    throw err;
  }

  return {
    mode,
    backend: 'pglite',
    dbs,
    TransactionAbortedError,
    createBarrier,
    createContentionFaultInjector,
    withRetryOnContention,
    async cleanup() {
      const errors = [];
      for (const db of instances) {
        try {
          if (!db.closed) {
            await db.close();
          }
        } catch (err) {
          errors.push(err);
        }
      }
      if (errors.length > 0) {
        throw new AggregateError(errors, 'Failed to close PGlite instances cleanly');
      }
    }
  };
}
