import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { AuthorizationDomainError, ConflictDomainError } from "@relayquill/domain";
import { createPGliteAuthorityCluster, withTenantRlsTransaction } from "@relayquill/postgres";

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");

const COMMERCIAL_TABLES = [
  "users",
  "oidc_connections",
  "support_break_glass_sessions",
  "billing_customers",
  "billing_subscriptions",
  "entitlement_quotas",
  "usage_events",
  "usage_rollups",
  "billing_webhook_events",
  "email_outbox",
  "gdpr_erasure_requests",
  "legal_acceptances"
];

const TENANT_RLS_TABLES = COMMERCIAL_TABLES.filter((name) => name !== "billing_webhook_events");

function listSqlFiles(relDir) {
  const dir = path.join(REPO_ROOT, relDir);
  return fs
    .readdirSync(dir)
    .filter((f) => f.endsWith(".sql"))
    .sort()
    .map((f) => ({
      name: f,
      sql: fs.readFileSync(path.join(dir, f), "utf8")
    }));
}

async function applyRqMigrations(rq) {
  for (const file of listSqlFiles("migrations")) {
    await rq.exec(file.sql);
  }
}

test("Migration 0010 creates commercial tables owned by rq_owner with FORCE ROW LEVEL SECURITY", async (t) => {
  const cluster = await createPGliteAuthorityCluster({
    isolation: "shared_database_schemas",
    applySetLocalRole: true
  });
  t.after(() => cluster.close());
  await applyRqMigrations(cluster.rq);

  const relRes = await cluster.rq.query(
    `SELECT c.relname,
            pg_catalog.pg_get_userbyid(c.relowner) AS owner,
            c.relrowsecurity,
            c.relforcerowsecurity
       FROM pg_catalog.pg_class c
       JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
      WHERE n.nspname = 'rq'
        AND c.relname = ANY($1::text[])
      ORDER BY c.relname`,
    [COMMERCIAL_TABLES]
  );

  assert.equal(relRes.rows.length, COMMERCIAL_TABLES.length);
  const byName = new Map(relRes.rows.map((row) => [row.relname, row]));

  for (const table of COMMERCIAL_TABLES) {
    const row = byName.get(table);
    assert.ok(row, `Missing table rq.${table}`);
    assert.equal(row.owner, "rq_owner", `Expected rq_owner on rq.${table}`);
  }

  for (const rlsTable of TENANT_RLS_TABLES) {
    const row = byName.get(rlsTable);
    assert.equal(row.relrowsecurity, true, `Expected ENABLE ROW LEVEL SECURITY on rq.${rlsTable}`);
    assert.equal(row.relforcerowsecurity, true, `Expected FORCE ROW LEVEL SECURITY on rq.${rlsTable}`);
  }
});

test("FORCE ROW LEVEL SECURITY isolates tenants under rq_billing and rq_audit_ro and enforces 15m break-glass constraints", async (t) => {
  const cluster = await createPGliteAuthorityCluster({
    isolation: "shared_database_schemas",
    applySetLocalRole: true
  });
  t.after(() => cluster.close());
  await applyRqMigrations(cluster.rq);

  const tenantA = "10000000-0000-4000-8000-00000000000a";
  const tenantB = "10000000-0000-4000-8000-00000000000b";
  const principalA = "20000000-0000-4000-8000-00000000000a";
  const principalB = "20000000-0000-4000-8000-00000000000b";
  const operatorId = "30000000-0000-4000-8000-0000000000op".replace("0000000000op", "000000000099");
  const userA = "40000000-0000-4000-8000-00000000000a";
  const userB = "40000000-0000-4000-8000-00000000000b";
  const subA = "50000000-0000-4000-8000-00000000000a";
  const subB = "50000000-0000-4000-8000-00000000000b";
  const bgA = "60000000-0000-4000-8000-00000000000a";
  const bgB = "60000000-0000-4000-8000-00000000000b";
  const tokenHashA = crypto.createHash("sha256").update("bg-token-a").digest();
  const tokenHashB = crypto.createHash("sha256").update("bg-token-b").digest();

  await cluster.rq.withTransaction("postgres", async (tx) => {
    await tx.query(
      "INSERT INTO rq.principals (id, kind, state) VALUES ($1::uuid, 'human', 'active'), ($2::uuid, 'human', 'active'), ($3::uuid, 'human', 'active')",
      [principalA, principalB, operatorId]
    );
    await tx.query(
      "INSERT INTO rq.tenants (id, slug, display_name, state, tos_version, tos_accepted_at) VALUES ($1::uuid, 'tenant-alpha', 'Tenant Alpha', 'active', '2026-11-01', pg_catalog.clock_timestamp()), ($2::uuid, 'tenant-beta', 'Tenant Beta', 'active', '2026-11-01', pg_catalog.clock_timestamp())",
      [tenantA, tenantB]
    );
    await tx.query(
      "INSERT INTO rq.users (id, principal_id, tenant_id, email, password_hash, role) VALUES ($1::uuid, $2::uuid, $3::uuid, 'alpha@alpha.test', '$argon2id$v=19$m=65536,t=3,p=1$stub$hashvalue', 'owner'), ($4::uuid, $5::uuid, $6::uuid, 'beta@beta.test', '$argon2id$v=19$m=65536,t=3,p=1$stub$hashvalue', 'owner')",
      [userA, principalA, tenantA, userB, principalB, tenantB]
    );
    await tx.query(
      "INSERT INTO rq.billing_customers (org_id, stripe_customer_id, billing_email) VALUES ($1::uuid, 'cus_alpha', 'billing@alpha.test'), ($2::uuid, 'cus_beta', 'billing@beta.test')",
      [tenantA, tenantB]
    );
    await tx.query(
      "INSERT INTO rq.billing_subscriptions (subscription_id, org_id, stripe_subscription_id, plan_tier, entitlement_state, billing_interval, unit_amount_minor, current_period_start, current_period_end) VALUES ($1::uuid, $2::uuid, 'sub_alpha', 'pro', 'ACTIVE', 'month', 3900, '2026-11-01T00:00:00Z'::timestamptz, '2026-12-01T00:00:00Z'::timestamptz), ($3::uuid, $4::uuid, 'sub_beta', 'team', 'ACTIVE', 'month', 14900, '2026-11-01T00:00:00Z'::timestamptz, '2026-12-01T00:00:00Z'::timestamptz)",
      [subA, tenantA, subB, tenantB]
    );
    await tx.query(
      "INSERT INTO rq.support_break_glass_sessions (id, tenant_id, operator_id, reason, mfa_verified_at, token_sha256, started_at, expires_at) VALUES ($1::uuid, $2::uuid, $3::uuid, 'Investigate delivery timeout for tenant alpha', '2026-11-22T10:00:00Z'::timestamptz, $4::bytea, '2026-11-22T10:01:00Z'::timestamptz, '2026-11-22T10:15:00Z'::timestamptz), ($5::uuid, $6::uuid, $3::uuid, 'Investigate delivery timeout for tenant beta', '2026-11-22T10:00:00Z'::timestamptz, $7::bytea, '2026-11-22T10:01:00Z'::timestamptz, '2026-11-22T10:15:00Z'::timestamptz)",
      [bgA, tenantA, operatorId, tokenHashA, bgB, tenantB, tokenHashB]
    );
  });

  // 1. Unbound rq_billing session must see 0 rows due to FORCE ROW LEVEL SECURITY
  const unboundBilling = await cluster.rq.withTransaction("rq_billing", async (tx) => {
    const res = await tx.query("SELECT org_id FROM rq.billing_subscriptions");
    return res.rows;
  });
  assert.equal(unboundBilling.length, 0);

  // 2. Tenant-bound rq_billing session must see strictly Tenant A's subscription and never Tenant B
  const tenantABilling = await withTenantRlsTransaction(cluster.rq, "rq_billing", tenantA, async (tx) => {
    const res = await tx.query("SELECT org_id, plan_tier FROM rq.billing_subscriptions");
    return res.rows;
  });
  assert.deepEqual(tenantABilling, [{ org_id: tenantA, plan_tier: "pro" }]);

  // 3. rq_billing must be denied access to event_payloads, signing_key_versions, and users
  for (const table of ["rq.event_payloads", "rq.signing_key_versions", "rq.users"]) {
    await assert.rejects(
      () => cluster.rq.withTransaction("rq_billing", (tx) => tx.query(`SELECT count(*) FROM ${table}`)),
      (err) => err instanceof AuthorizationDomainError && err.code === "FORBIDDEN"
    );
  }

  // 4. rq_audit_ro sees 0 unbound break-glass rows, only Tenant A when bound, and cannot DELETE or read payloads
  const unboundAudit = await cluster.rq.withTransaction("rq_audit_ro", async (tx) => {
    const res = await tx.query("SELECT id FROM rq.support_break_glass_sessions");
    return res.rows;
  });
  assert.equal(unboundAudit.length, 0);

  const tenantAAudit = await withTenantRlsTransaction(cluster.rq, "rq_audit_ro", tenantA, async (tx) => {
    const res = await tx.query("SELECT id, tenant_id FROM rq.support_break_glass_sessions");
    return res.rows;
  });
  assert.deepEqual(tenantAAudit, [{ id: bgA, tenant_id: tenantA }]);

  await assert.rejects(
    () => cluster.rq.withTransaction("rq_audit_ro", (tx) => tx.query("DELETE FROM rq.audit_events")),
    (err) => err instanceof AuthorizationDomainError && err.code === "FORBIDDEN"
  );
  await assert.rejects(
    () => cluster.rq.withTransaction("rq_audit_ro", (tx) => tx.query("SELECT count(*) FROM rq.event_payloads")),
    (err) => err instanceof AuthorizationDomainError && err.code === "FORBIDDEN"
  );

  // 5. Break-glass table constraints reject short reason, read_only = false, and TTL > 15m
  await assert.rejects(
    () =>
      cluster.rq.withTransaction("postgres", (tx) =>
        tx.query(
          "INSERT INTO rq.support_break_glass_sessions (id, tenant_id, operator_id, reason, mfa_verified_at, token_sha256, started_at, expires_at) VALUES ($1::uuid, $2::uuid, $3::uuid, 'too short', '2026-11-22T10:00:00Z'::timestamptz, $4::bytea, '2026-11-22T10:01:00Z'::timestamptz, '2026-11-22T10:15:00Z'::timestamptz)",
          [
            "60000000-0000-4000-8000-00000000000c",
            tenantA,
            operatorId,
            crypto.createHash("sha256").update("short-reason").digest()
          ]
        )
      ),
    (err) => err instanceof ConflictDomainError && err.code === "STATE_TRANSITION_NOT_ALLOWED"
  );

  await assert.rejects(
    () =>
      cluster.rq.withTransaction("postgres", (tx) =>
        tx.query(
          "INSERT INTO rq.support_break_glass_sessions (id, tenant_id, operator_id, reason, mfa_verified_at, read_only, token_sha256, started_at, expires_at) VALUES ($1::uuid, $2::uuid, $3::uuid, 'Valid justification length', '2026-11-22T10:00:00Z'::timestamptz, false, $4::bytea, '2026-11-22T10:01:00Z'::timestamptz, '2026-11-22T10:15:00Z'::timestamptz)",
          [
            "60000000-0000-4000-8000-00000000000d",
            tenantA,
            operatorId,
            crypto.createHash("sha256").update("not-readonly").digest()
          ]
        )
      ),
    (err) => err instanceof ConflictDomainError && err.code === "STATE_TRANSITION_NOT_ALLOWED"
  );

  await assert.rejects(
    () =>
      cluster.rq.withTransaction("postgres", (tx) =>
        tx.query(
          "INSERT INTO rq.support_break_glass_sessions (id, tenant_id, operator_id, reason, mfa_verified_at, token_sha256, started_at, expires_at) VALUES ($1::uuid, $2::uuid, $3::uuid, 'Valid justification length', '2026-11-22T10:00:00Z'::timestamptz, $4::bytea, '2026-11-22T10:00:00Z'::timestamptz, '2026-11-22T10:16:00Z'::timestamptz)",
          [
            "60000000-0000-4000-8000-00000000000e",
            tenantA,
            operatorId,
            crypto.createHash("sha256").update("ttl-over-15m").digest()
          ]
        )
      ),
    (err) => err instanceof ConflictDomainError && err.code === "STATE_TRANSITION_NOT_ALLOWED"
  );
});
