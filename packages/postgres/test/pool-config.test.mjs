import test from "node:test";
import assert from "node:assert/strict";
import EventEmitter from "node:events";
import { DomainError } from "@relayquill/domain";
import { createSecretHandle } from "@relayquill/runtime";
import {
  PG_OID_INT8,
  PG_OID_TIMESTAMPTZ,
  StandardPgAdapter,
  buildPgPoolConfig
} from "@relayquill/postgres";

function makeBaseDbConfig(overrides = {}) {
  return {
    mode: "standard_tls",
    isolation: "shared_database_schemas",
    host: "pg.internal.example",
    port: 5432,
    name: "relayquill",
    schema: "rq",
    support_schema: "rq_support",
    role: "rq_api",
    authentication: "scram_sha_256",
    tls_mode: "verify_full",
    pool_mode: "direct",
    maximum_connections: 8,
    connection_timeout_ms: 3000,
    statement_timeout_ms: 5000,
    lock_timeout_ms: 2000,
    ...overrides
  };
}

test("buildPgPoolConfig supports standard_tls, hosted_neon, hosted_supabase, release_rds_iam, and development_trusted_local", async () => {
  const passwordHandle = createSecretHandle("super-secret-pass", {
    id: "db_pw",
    source: "memory"
  });

  const stdCfg = buildPgPoolConfig(makeBaseDbConfig(), {
    tlsCaPem: "-----BEGIN CERTIFICATE-----\nFAKECA\n-----END CERTIFICATE-----\n",
    passwordProvider: async () => passwordHandle
  });
  assert.equal(stdCfg.host, "pg.internal.example");
  assert.equal(stdCfg.user, "rq_api");
  assert.equal(stdCfg.database, "relayquill");
  assert.equal(stdCfg.statement_timeout, false);
  assert.deepEqual(stdCfg.ssl, {
    rejectUnauthorized: true,
    servername: "pg.internal.example",
    ca: "-----BEGIN CERTIFICATE-----\nFAKECA\n-----END CERTIFICATE-----\n"
  });
  assert.equal(typeof stdCfg.password, "function");
  assert.equal(await stdCfg.password(), "super-secret-pass");
  assert.equal(stdCfg.types.getTypeParser(PG_OID_TIMESTAMPTZ, "text")("2026-11-18 07:00:00+00"), "2026-11-18T07:00:00.000000Z");
  assert.equal(stdCfg.types.getTypeParser(PG_OID_INT8, "text")("9007199254740993"), "9007199254740993");

  const neonCfg = buildPgPoolConfig(
    makeBaseDbConfig({
      mode: "hosted_neon",
      host: "ep-cool-pine.us-east-2.aws.neon.tech",
      pool_mode: "transaction_pooler"
    }),
    { passwordProvider: async () => "neon-pw" }
  );
  assert.equal(neonCfg.ssl.rejectUnauthorized, true);
  assert.equal(neonCfg.idle_in_transaction_session_timeout, undefined);

  const supaCfg = buildPgPoolConfig(
    makeBaseDbConfig({
      mode: "hosted_supabase",
      host: "db.abcdefgh.supabase.co",
      pool_mode: "session_pooler"
    }),
    { passwordProvider: async () => "supa-pw" }
  );
  assert.equal(supaCfg.ssl.servername, "db.abcdefgh.supabase.co");

  let iamCalls = 0;
  const rdsCfg = buildPgPoolConfig(
    makeBaseDbConfig({
      mode: "release_rds_iam",
      authentication: "aws_rds_iam_token",
      host: "rq-prod.cluster-xyz.us-east-1.rds.amazonaws.com"
    }),
    {
      iamTokenProvider: async ({ host, port, user, database }) => {
        iamCalls += 1;
        return `rds-iam-token-${iamCalls}-${host}:${port}/${database}/${user}`;
      }
    }
  );
  assert.equal(typeof rdsCfg.password, "function");
  assert.match(await rdsCfg.password(), /^rds-iam-token-1-/);
  assert.match(await rdsCfg.password(), /^rds-iam-token-2-/);
  assert.equal(iamCalls, 2);

  const localCfg = buildPgPoolConfig(
    makeBaseDbConfig({
      mode: "development_trusted_local",
      host: "127.0.0.1",
      authentication: "trusted_local_only",
      tls_mode: "disabled_fixture"
    })
  );
  assert.equal(localCfg.ssl, false);
  assert.equal(localCfg.password, undefined);
});

test("buildPgPoolConfig fails closed on insecure TLS or missing IAM token provider", () => {
  assert.throws(
    () =>
      buildPgPoolConfig(
        makeBaseDbConfig({
          mode: "standard_tls",
          tls_mode: "disabled_fixture"
        }),
        { passwordProvider: async () => "pw" }
      ),
    /requires tls_mode="verify_full"/
  );

  assert.throws(
    () =>
      buildPgPoolConfig(
        makeBaseDbConfig({
          mode: "development_trusted_local",
          host: "remote.db.example",
          authentication: "trusted_local_only",
          tls_mode: "disabled_fixture"
        })
      ),
    /disabled_fixture mode is forbidden/
  );

  assert.throws(
    () =>
      buildPgPoolConfig(
        makeBaseDbConfig({
          mode: "release_rds_iam",
          authentication: "aws_rds_iam_token"
        })
      ),
    /requires an iamTokenProvider/
  );
});

test("StandardPgAdapter verifies session identity on connect and discards cancelled/broken connections", async () => {
  const executedSql = [];
  const releaseCalls = [];
  let simulateMismatch = false;
  let simulateCancelOnQuery = false;

  class MockPool extends EventEmitter {
    async connect() {
      const client = {
        async query(arg) {
          const text = typeof arg === "string" ? arg : arg.text;
          executedSql.push(text);
          if (text.includes("current_database()")) {
            return {
              rows: [
                {
                  database: simulateMismatch ? "wrong_db" : "relayquill",
                  current_user: "rq_api",
                  session_user: "rq_api",
                  search_path: "rq, rq_support"
                }
              ],
              rowCount: 1,
              command: "SELECT",
              fields: []
            };
          }
          if (text === "SELECT 1" && simulateCancelOnQuery) {
            const err = new Error("canceling statement due to user request");
            err.code = "57014";
            throw err;
          }
          if (text.includes("clock_timestamp")) {
            return {
              rows: [{ clock_timestamp: "2026-11-18T08:00:00.000000Z" }],
              rowCount: 1,
              command: "SELECT",
              fields: []
            };
          }
          return { rows: [{ ok: true }], rowCount: 1, command: "SELECT", fields: [] };
        },
        release(destroy) {
          releaseCalls.push(Boolean(destroy));
        }
      };
      return client;
    }

    async end() {
      return undefined;
    }
  }

  const adapter = new StandardPgAdapter(
    makeBaseDbConfig({
      mode: "development_trusted_local",
      host: "127.0.0.1",
      authentication: "trusted_local_only",
      tls_mode: "disabled_fixture"
    }),
    {},
    new MockPool()
  );

  const identity = await adapter.verifySessionIdentity("rq_api");
  assert.equal(identity.database, "relayquill");
  assert.equal(identity.currentUser, "rq_api");
  assert.equal(releaseCalls.pop(), false);

  const ok = await adapter.withTransaction("rq_api", async (tx) => {
    const res = await tx.query("SELECT 1");
    return res.rows[0].ok;
  });
  assert.equal(ok, true);
  assert.equal(releaseCalls.pop(), false);
  assert.ok(executedSql.includes("SET LOCAL lock_timeout = '2000ms'"));
  assert.ok(executedSql.includes("SET LOCAL TIME ZONE 'UTC'"));

  // Cancelled query -> discard=true and acceptance="unknown"
  simulateCancelOnQuery = true;
  await assert.rejects(
    () =>
      adapter.withTransaction("rq_api", async (tx) => {
        await tx.query("SELECT 1");
      }),
    (err) => err instanceof DomainError && err.code === "ACCEPTANCE_UNKNOWN" && err.acceptance === "unknown"
  );
  assert.equal(releaseCalls.pop(), true);
  simulateCancelOnQuery = false;

  // Database mismatch on connect -> FORBIDDEN and discard=true
  simulateMismatch = true;
  await assert.rejects(
    () => adapter.verifySessionIdentity("rq_api"),
    (err) => err instanceof DomainError && err.code === "FORBIDDEN"
  );
  assert.equal(releaseCalls.pop(), true);

  await adapter.close();
});
