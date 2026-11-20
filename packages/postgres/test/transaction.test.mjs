import test from "node:test";
import assert from "node:assert/strict";
import { DomainError, isCanonicalUtcTimestamp } from "@relayquill/domain";
import { createPGliteAdapter } from "@relayquill/postgres";

function makeSqlStateError(sqlState, message) {
  const err = new Error(message);
  err.code = sqlState;
  err.sqlstate = sqlState;
  return err;
}

test("withTransaction enforces READ COMMITTED, lock_timeout <= 2000ms, statement_timeout <= min(5000, budget), UTC, and clock_timestamp", async (t) => {
  const db = await createPGliteAdapter({ schema: "rq", isolation: "shared_database_schemas" });
  t.after(() => db.close());

  const observed = await db.withTransaction(
    "rq_api",
    async (tx) => {
      const iso = await tx.query("SHOW transaction_isolation");
      const lock = await tx.query("SHOW lock_timeout");
      const stmt = await tx.query("SHOW statement_timeout");
      const tz = await tx.query("SHOW TimeZone");
      const clk = await tx.readClockTimestamp();
      return {
        isolation: iso.rows[0].transaction_isolation,
        lockTimeout: lock.rows[0].lock_timeout,
        statementTimeout: stmt.rows[0].statement_timeout,
        timeZone: tz.rows[0].TimeZone,
        clockTimestamp: clk,
        remainingMs: tx.remainingBudgetMs()
      };
    },
    { deadlineMs: 1200, lockTimeoutMs: 4000, statementTimeoutMs: 9000 }
  );

  assert.equal(observed.isolation, "read committed");
  assert.equal(observed.timeZone, "UTC");
  // PGlite renders <= 1200ms (e.g. "1200ms" or "1199ms") and lock_timeout clipped to statement_timeout <= 1200ms
  assert.match(observed.statementTimeout, /^\d+ms$/);
  const stmtMs = Number.parseInt(observed.statementTimeout, 10);
  const lockMs = Number.parseInt(observed.lockTimeout, 10);
  assert.ok(stmtMs >= 1 && stmtMs <= 1200);
  assert.ok(lockMs >= 1 && lockMs <= 1200);
  assert.equal(isCanonicalUtcTimestamp(observed.clockTimestamp), true);
  assert.ok(observed.remainingMs <= 1200);
});

test("withTransaction retries SQLSTATE 55P03, 40P01, and 40001 with bounded full jitter up to 3 attempts", async (t) => {
  const db = await createPGliteAdapter({ createSchemaIfMissing: true });
  t.after(() => db.close());

  await db.exec("CREATE TABLE IF NOT EXISTS retry_probe (id integer PRIMARY KEY, note text);");

  const codes = ["55P03", "40P01"];
  const retryEvents = [];
  let attempts = 0;

  const committed = await db.withTransaction(
    "rq_sender",
    async (tx) => {
      attempts += 1;
      await tx.query("INSERT INTO retry_probe (id, note) VALUES ($1::integer, $2::text)", [
        attempts,
        `attempt-${attempts}`
      ]);
      if (codes.length > 0) {
        const nextCode = codes.shift();
        throw makeSqlStateError(nextCode, `transient contention ${nextCode}`);
      }
      return attempts;
    },
    {
      retryOnContention: true,
      maxAttempts: 5, // must clamp at 3
      baseBackoffMs: 20,
      maxBackoffMs: 100,
      deadlineMs: 4000,
      random: () => 0.5,
      onRetry: (evt) => retryEvents.push(evt)
    }
  );

  assert.equal(committed, 3);
  assert.equal(attempts, 3);
  assert.equal(retryEvents.length, 2);
  assert.deepEqual(
    retryEvents.map((e) => ({ attempt: e.attempt, maxAttempts: e.maxAttempts, sqlState: e.sqlState, delayMs: e.delayMs })),
    [
      { attempt: 1, maxAttempts: 3, sqlState: "55P03", delayMs: 10 },
      { attempt: 2, maxAttempts: 3, sqlState: "40P01", delayMs: 20 }
    ]
  );

  // Earlier failed attempts rolled back cleanly, only attempt 3 row exists
  const rows = await db.query("SELECT id, note FROM retry_probe ORDER BY id");
  assert.deepEqual(rows.rows, [{ id: 3, note: "attempt-3" }]);

  // Serialization failure 40001 exhausting 3 attempts throws retryable LOCK_CONTENTION
  let exhaustedAttempts = 0;
  await assert.rejects(
    () =>
      db.withTransaction(
        "rq_sender",
        async () => {
          exhaustedAttempts += 1;
          throw makeSqlStateError("40001", "could not serialize access");
        },
        {
          retryOnContention: true,
          baseBackoffMs: 2,
          deadlineMs: 2000,
          random: () => 0.5
        }
      ),
    (err) => err instanceof DomainError && err.code === "LOCK_CONTENTION" && err.retryable === true
  );
  assert.equal(exhaustedAttempts, 3);

  // Non-retryable error fails on attempt 1 immediately
  let nonRetryAttempts = 0;
  await assert.rejects(
    () =>
      db.withTransaction(
        "rq_sender",
        async () => {
          nonRetryAttempts += 1;
          throw makeSqlStateError("23505", "duplicate key value");
        },
        { retryOnContention: true }
      ),
    (err) => err instanceof DomainError && err.code === "VERSION_CONFLICT" && err.retryable === false
  );
  assert.equal(nonRetryAttempts, 1);
});

test("withTransaction halts immediately when AbortSignal fires before or mid-transaction", async (t) => {
  const db = await createPGliteAdapter();
  t.after(() => db.close());

  const preAborted = new AbortController();
  preAborted.abort();

  await assert.rejects(
    () =>
      db.withTransaction(
        "rq_api",
        async () => "unreachable",
        { signal: preAborted.signal, retryOnContention: true }
      ),
    (err) => err instanceof DomainError && err.code === "ACCEPTANCE_UNKNOWN" && err.acceptance === "unknown"
  );

  const midController = new AbortController();
  await assert.rejects(
    () =>
      db.withTransaction(
        "rq_api",
        async (tx) => {
          midController.abort();
          return tx.query("SELECT 1");
        },
        { signal: midController.signal }
      ),
    (err) => err instanceof DomainError && err.code === "ACCEPTANCE_UNKNOWN" && err.acceptance === "unknown"
  );
});
