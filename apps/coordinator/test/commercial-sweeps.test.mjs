import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { createInMemoryEmailAdapter } from "@relayquill/billing";
import { createPGliteAdapter, withTenantRlsTransaction } from "@relayquill/postgres";
import {
  runBillingGraceExpirySweep,
  runEmailOutboxSweep,
  runGdprErasureCompletionSweep
} from "../dist/index.js";

const TEST_DIR = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(TEST_DIR, "../../..");
const MIGRATIONS_DIR = path.join(REPO_ROOT, "migrations");

async function setupDb(t) {
  const pg = await createPGliteAdapter({
    schema: "rq",
    supportSchema: "rq_support",
    isolation: "shared_database_schemas",
    configuredRole: "rq_coordinator"
  });
  t.after(() => pg.close());
  const files = fs.readdirSync(MIGRATIONS_DIR).filter((f) => f.endsWith(".sql")).sort();
  for (const f of files) {
    await pg.exec(fs.readFileSync(path.join(MIGRATIONS_DIR, f), "utf8"));
  }
  return pg;
}

test("Coordinator sweeps handle dunning grace expiry, email outbox draining, and GDPR erasure completion", async (t) => {
  const pg = await setupDb(t);

  const tenantId = crypto.randomUUID();
  const principalId = crypto.randomUUID();
  const userId = crypto.randomUUID();
  const erasureId = crypto.randomUUID();
  const graceEndsAt = new Date("2026-11-29T12:00:00Z");

  await pg.exec(`
    INSERT INTO rq.principals (id, kind, state, authority_epoch)
    VALUES ('${principalId}'::uuid, 'human', 'active', 1);
    INSERT INTO rq.tenants (id, slug, display_name, state, governance_version)
    VALUES ('${tenantId}'::uuid, 'sweep-org', 'Sweep Org', 'active', 1);
  `);

  await withTenantRlsTransaction(pg, pg.configuredRole, tenantId, async (tx) => {
    await tx.query(
      `INSERT INTO rq.users (id, principal_id, tenant_id, email, password_hash, role, mfa_enrolled)
       VALUES ($1::uuid, $2::uuid, $3::uuid, 'alice@sweep.example', '$argon2id$hash_placeholder', 'owner', true)`,
      [userId, principalId, tenantId]
    );
    await tx.query(
      `INSERT INTO rq.billing_customers (org_id, stripe_customer_id, billing_email)
       VALUES ($1::uuid, 'cus_sweep_1', 'alice@sweep.example')`,
      [tenantId]
    );
    await tx.query(
      `INSERT INTO rq.billing_subscriptions (
         subscription_id, org_id, plan_tier, entitlement_state, billing_interval,
         currency, unit_amount_minor, seat_count, current_period_start, current_period_end, grace_ends_at
       ) VALUES (
         $1::uuid, $2::uuid, 'pro', 'PAST_DUE_GRACE', 'month',
         'USD', 3900, 1, '2026-11-01T00:00:00Z', '2026-12-01T00:00:00Z', $3::timestamptz
       )`,
      [crypto.randomUUID(), tenantId, graceEndsAt.toISOString()]
    );
    await tx.query(
      `INSERT INTO rq.entitlement_quotas (
         org_id, max_seats, max_concurrency, included_units_month, overage_unit_minor, cap_mode, retention_days, sso_enabled
       ) VALUES ($1::uuid, 3, 10, 500000, 8, 'hard_cap', 30, false)`,
      [tenantId]
    );
    await tx.query(
      `INSERT INTO rq.gdpr_erasure_requests (id, org_id, requested_by, state)
       VALUES ($1::uuid, $2::uuid, $3::uuid, 'queued')`,
      [erasureId, tenantId, principalId]
    );
  });

  // Mid-grace run (~5 days elapsed since 2026-11-22) queues notice 3 & 5 without downgrading yet
  const midGrace = await runBillingGraceExpirySweep(pg, {
    now: new Date("2026-11-27T12:00:00Z")
  });
  assert.equal(midGrace.dunningRemindersQueued, 2);
  assert.equal(midGrace.downgradedCount, 0);

  // Email sweep delivers both notices via TransactionalEmailAdapter
  const memMail = createInMemoryEmailAdapter();
  const mailRes = await runEmailOutboxSweep(pg, memMail);
  assert.equal(mailRes.dispatched, 2);

  // Post-grace expiry downgrades to RESTRICTED_DOWNGRADED & Free cap, plus queues notice 7
  const postGrace = await runBillingGraceExpirySweep(pg, {
    now: new Date("2026-11-30T00:00:00Z")
  });
  assert.equal(postGrace.downgradedCount, 1);
  assert.equal(postGrace.dunningRemindersQueued, 1);

  const subCheck = await withTenantRlsTransaction(pg, pg.configuredRole, tenantId, (tx) =>
    tx.query(
      `SELECT s.plan_tier, s.entitlement_state, q.included_units_month
         FROM rq.billing_subscriptions s
         JOIN rq.entitlement_quotas q ON q.org_id = s.org_id
        WHERE s.org_id = $1::uuid`,
      [tenantId]
    )
  );
  assert.equal(subCheck.rows[0].entitlement_state, "RESTRICTED_DOWNGRADED");
  assert.equal(subCheck.rows[0].plan_tier, "free");
  assert.equal(Number(subCheck.rows[0].included_units_month), 25000);

  // GDPR erasure sweep anonymizes PII and completes erasure request
  const revokedOrgs = [];
  const gdprRes = await runGdprErasureCompletionSweep(pg, {
    revokeEphemeralKeys: async (id) => {
      revokedOrgs.push(id);
    }
  });
  assert.equal(gdprRes.completedCount, 1);
  assert.deepEqual(revokedOrgs, [tenantId]);

  const verifyGdpr = await withTenantRlsTransaction(pg, pg.configuredRole, tenantId, async (tx) => {
    const u = await tx.query(`SELECT email, totp_secret_enc FROM rq.users WHERE id = $1::uuid`, [
      userId
    ]);
    const r = await tx.query(`SELECT state, receipt_sha256 FROM rq.gdpr_erasure_requests WHERE id = $1::uuid`, [
      erasureId
    ]);
    return { u: u.rows[0], r: r.rows[0] };
  });
  assert.ok(verifyGdpr.u.email.endsWith("@redacted.invalid"));
  assert.equal(verifyGdpr.u.totp_secret_enc, null);
  assert.equal(verifyGdpr.r.state, "completed");
  assert.ok(verifyGdpr.r.receipt_sha256 !== null);
});
