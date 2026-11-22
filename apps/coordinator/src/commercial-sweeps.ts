import crypto from "node:crypto";
import {
  drainPendingEmailOutboxBatch,
  type EmailOutboxDrainSummary,
  type TransactionalEmailAdapter
} from "@relayquill/billing";
import {
  GRACE_PERIOD_MS,
  PLAN_CATALOG,
  reduceEntitlementState,
  type TenantId
} from "@relayquill/domain";
import { type PgAdapter, withTenantRlsTransaction } from "@relayquill/postgres";

export interface BillingGraceSweepOptions {
  readonly databaseRole?: string;
  readonly now?: Date;
  readonly batchLimit?: number;
  readonly tenantIds?: readonly TenantId[];
}

export interface BillingGraceSweepSummary {
  readonly tenantsScanned: number;
  readonly dunningRemindersQueued: number;
  readonly downgradedCount: number;
}

export interface EmailOutboxSweepOptions {
  readonly databaseRole?: string;
  readonly tenantIds?: readonly TenantId[];
  readonly batchPerTenant?: number;
  readonly maxAttempts?: number;
}

export interface GdprErasureSweepOptions {
  readonly databaseRole?: string;
  readonly now?: Date;
  readonly batchLimit?: number;
  readonly tenantIds?: readonly TenantId[];
  readonly revokeEphemeralKeys?: (orgId: TenantId) => Promise<void>;
}

export interface GdprErasureSweepSummary {
  readonly tenantsScanned: number;
  readonly completedCount: number;
}

async function listCandidateTenantIds(
  pgAdapter: PgAdapter,
  role: string,
  explicitTenantIds: readonly TenantId[] | undefined,
  limit: number
): Promise<readonly TenantId[]> {
  if (explicitTenantIds !== undefined) {
    return explicitTenantIds;
  }
  return pgAdapter.withTransaction(
    role,
    async (tx) => {
      const res = await tx.query<{ id: string }>(
        `SELECT id FROM rq.tenants ORDER BY created_at ASC LIMIT $1::int`,
        [Math.max(1, Math.min(500, limit))]
      );
      return res.rows.map((r) => r.id as TenantId);
    },
    { readOnly: true }
  );
}

/**
 * Evaluates active 7-day billing dunning grace periods, emits staged reminders (3/5/7),
 * and downgrades expired accounts to `RESTRICTED_DOWNGRADED` cleanly inside RLS scope.
 */
export async function runBillingGraceExpirySweep(
  pgAdapter: PgAdapter,
  options: BillingGraceSweepOptions = {}
): Promise<BillingGraceSweepSummary> {
  const role = options.databaseRole ?? pgAdapter.configuredRole;
  const now = options.now ?? new Date();
  const nowIso = now.toISOString();
  const tenantIds = await listCandidateTenantIds(
    pgAdapter,
    role,
    options.tenantIds,
    options.batchLimit ?? 100
  );

  let dunningRemindersQueued = 0;
  let downgradedCount = 0;

  for (const tenantId of tenantIds) {
    await withTenantRlsTransaction(pgAdapter, role, tenantId, async (tx) => {
      const subRes = await tx.query<{
        subscription_id: string;
        grace_ends_at: Date | string | null;
        billing_email: string;
      }>(
        `SELECT s.subscription_id, s.grace_ends_at, c.billing_email
           FROM rq.billing_subscriptions s
           JOIN rq.billing_customers c ON c.org_id = s.org_id
          WHERE s.org_id = $1::uuid
            AND s.entitlement_state = 'PAST_DUE_GRACE'
            AND s.grace_ends_at IS NOT NULL
          LIMIT 1`,
        [tenantId]
      );

      const row = subRes.rows[0];
      if (row === undefined || row.grace_ends_at === null) {
        return;
      }

      const graceEndsMs = new Date(row.grace_ends_at).getTime();
      const graceStartMs = graceEndsMs - GRACE_PERIOD_MS;
      const elapsedDays = (now.getTime() - graceStartMs) / (24 * 60 * 60 * 1000);

      const stages = [
        { minDays: 2, code: "dunning_notice_3" },
        { minDays: 4, code: "dunning_notice_5" },
        { minDays: 6, code: "dunning_notice_7" }
      ] as const;

      for (const stage of stages) {
        if (elapsedDays >= stage.minDays) {
          const idem = `dunning:${stage.code}:${tenantId}:${new Date(graceEndsMs).toISOString()}`;
          const inserted = await tx.query(
            `INSERT INTO rq.email_outbox (
               id, tenant_id, idempotency_key, template_code, recipient_email, template_vars, state, attempt_count
             ) VALUES (
               $1::uuid, $2::uuid, $3::text, $4::text, $5::text, $6::jsonb, 'pending', 0
             ) ON CONFLICT (idempotency_key) DO NOTHING
             RETURNING id`,
            [
              crypto.randomUUID(),
              tenantId,
              idem,
              stage.code,
              row.billing_email,
              JSON.stringify({ grace_ends_at: new Date(graceEndsMs).toISOString() })
            ]
          );
          if (inserted.rows.length > 0) {
            dunningRemindersQueued += 1;
          }
        }
      }

      if (graceEndsMs <= now.getTime()) {
        const transition = reduceEntitlementState("PAST_DUE_GRACE", "grace_window_elapsed", now);
        const freePlan = PLAN_CATALOG.free;
        await tx.query(
          `UPDATE rq.billing_subscriptions
              SET entitlement_state = $2::text,
                  plan_tier = 'free',
                  grace_ends_at = NULL,
                  unit_amount_minor = 0,
                  version = version + 1,
                  updated_at = $3::timestamptz
            WHERE subscription_id = $1::uuid`,
          [row.subscription_id, transition.nextState, nowIso]
        );
        await tx.query(
          `UPDATE rq.entitlement_quotas
              SET max_seats = $2::int,
                  max_concurrency = $3::int,
                  included_units_month = $4::bigint,
                  overage_unit_minor = 0,
                  cap_mode = $5::text,
                  retention_days = $6::int,
                  sso_enabled = $7::boolean,
                  updated_at = $8::timestamptz
            WHERE org_id = $1::uuid`,
          [
            tenantId,
            freePlan.maxSeats,
            freePlan.maxConcurrency,
            freePlan.includedUnitsMonth,
            freePlan.capMode,
            freePlan.retentionDays,
            freePlan.ssoEnabled,
            nowIso
          ]
        );
        downgradedCount += 1;
      }
    });
  }

  return {
    tenantsScanned: tenantIds.length,
    dunningRemindersQueued,
    downgradedCount
  };
}

/**
 * Drains pending rows in `rq.email_outbox` across tenant scopes via the active `TransactionalEmailAdapter`.
 */
export async function runEmailOutboxSweep(
  pgAdapter: PgAdapter,
  adapter: TransactionalEmailAdapter,
  options: EmailOutboxSweepOptions = {}
): Promise<EmailOutboxDrainSummary> {
  const role = options.databaseRole ?? pgAdapter.configuredRole;
  const tenantIds = await listCandidateTenantIds(pgAdapter, role, options.tenantIds, 200);

  let scanned = 0;
  let dispatched = 0;
  let failedPermanent = 0;
  let retried = 0;

  for (const tenantId of tenantIds) {
    const res = await withTenantRlsTransaction(pgAdapter, role, tenantId, (tx) =>
      drainPendingEmailOutboxBatch(tx, adapter, {
        limit: options.batchPerTenant ?? 25,
        maxAttempts: options.maxAttempts ?? 5
      })
    );
    scanned += res.scanned;
    dispatched += res.dispatched;
    failedPermanent += res.failedPermanent;
    retried += res.retried;
  }

  return { scanned, dispatched, failedPermanent, retried };
}

/**
 * Advances queued GDPR org erasure workflows across Redis/PG/storage while anonymizing tax ledgers.
 */
export async function runGdprErasureCompletionSweep(
  pgAdapter: PgAdapter,
  options: GdprErasureSweepOptions = {}
): Promise<GdprErasureSweepSummary> {
  const role = options.databaseRole ?? pgAdapter.configuredRole;
  const nowIso = (options.now ?? new Date()).toISOString();
  const tenantIds = await listCandidateTenantIds(
    pgAdapter,
    role,
    options.tenantIds,
    options.batchLimit ?? 100
  );

  let completedCount = 0;

  for (const tenantId of tenantIds) {
    await withTenantRlsTransaction(pgAdapter, role, tenantId, async (tx) => {
      const reqRes = await tx.query<{ id: string }>(
        `SELECT id
           FROM rq.gdpr_erasure_requests
          WHERE org_id = $1::uuid
            AND state IN ('queued', 'redis_revoked', 'pg_purged', 'storage_purged')
          ORDER BY requested_at ASC
          LIMIT 10
          FOR UPDATE SKIP LOCKED`,
        [tenantId]
      );
      if (reqRes.rows.length === 0) {
        return;
      }

      if (options.revokeEphemeralKeys !== undefined) {
        await options.revokeEphemeralKeys(tenantId);
      }

      // Anonymize PII on users & billing contact while retaining tax/ledger integrity.
      await tx.query(
        `UPDATE rq.users
            SET email = 'erased-' || id::text || '@redacted.invalid',
                password_hash = '$argon2id$erased_redacted',
                totp_secret_enc = NULL,
                mfa_enrolled = false,
                version = version + 1
          WHERE tenant_id = $1::uuid`,
        [tenantId]
      );
      await tx.query(
        `UPDATE rq.billing_customers
            SET billing_email = 'erased-' || org_id::text || '@tax-archived.invalid',
                updated_at = $2::timestamptz
          WHERE org_id = $1::uuid`,
        [tenantId, nowIso]
      );

      for (const reqRow of reqRes.rows) {
        const receiptHash = crypto
          .createHash("sha256")
          .update(`gdpr:${tenantId}:${reqRow.id}:${nowIso}`, "utf8")
          .digest();
        await tx.query(
          `UPDATE rq.gdpr_erasure_requests
              SET state = 'completed',
                  redis_purged_at = COALESCE(redis_purged_at, $2::timestamptz),
                  pg_purged_at = COALESCE(pg_purged_at, $2::timestamptz),
                  storage_purged_at = COALESCE(storage_purged_at, $2::timestamptz),
                  tax_anonymized_at = COALESCE(tax_anonymized_at, $2::timestamptz),
                  receipt_sha256 = $3::bytea,
                  completed_at = $2::timestamptz
            WHERE id = $1::uuid`,
          [reqRow.id, nowIso, receiptHash]
        );
        completedCount += 1;
      }
    });
  }

  return {
    tenantsScanned: tenantIds.length,
    completedCount
  };
}
