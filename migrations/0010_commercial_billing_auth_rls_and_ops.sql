-- Migration 0010: Commercial billing entitlements, user/OIDC identity, 15m break-glass,
-- transactional email outbox, legal acceptances, GDPR erasure tracking, and strict FORCE RLS.

DO $$
DECLARE
  v_can_create_role boolean := false;
  v_role text;
  v_missing_roles text[] := ARRAY[]::text[];
  v_ext_schema text;
BEGIN
  SELECT (r.rolsuper OR r.rolcreaterole)
    INTO v_can_create_role
    FROM pg_catalog.pg_roles r
   WHERE r.rolname = current_user;

  FOREACH v_role IN ARRAY ARRAY[
    'rq_billing',
    'rq_audit_ro',
    'rq_worker'
  ] LOOP
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = v_role) THEN
      v_missing_roles := pg_catalog.array_append(v_missing_roles, v_role);
    END IF;
  END LOOP;

  IF COALESCE(pg_catalog.array_length(v_missing_roles, 1), 0) > 0 THEN
    IF NOT v_can_create_role THEN
      RAISE EXCEPTION 'Required commercial/audit database roles missing (%) and current user "%" lacks CREATEROLE privilege',
        pg_catalog.array_to_string(v_missing_roles, ', '),
        current_user;
    END IF;

    FOREACH v_role IN ARRAY v_missing_roles LOOP
      EXECUTE pg_catalog.format(
        'CREATE ROLE %I LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS',
        v_role
      );
    END LOOP;
  END IF;

  EXECUTE 'GRANT USAGE ON SCHEMA rq, rq_support TO rq_billing, rq_audit_ro, rq_worker';

  SELECT n.nspname
    INTO v_ext_schema
    FROM pg_catalog.pg_extension e
    JOIN pg_catalog.pg_namespace n ON n.oid = e.extnamespace
   WHERE e.extname = 'btree_gist';

  IF v_ext_schema IS NOT NULL THEN
    EXECUTE pg_catalog.format(
      'GRANT USAGE ON SCHEMA %I TO rq_billing, rq_audit_ro, rq_worker',
      v_ext_schema
    );
  END IF;
END
$$;

ALTER TABLE rq.tenants
  ADD COLUMN IF NOT EXISTS tos_version text NULL,
  ADD COLUMN IF NOT EXISTS tos_accepted_at timestamptz NULL,
  ADD COLUMN IF NOT EXISTS dpa_version text NULL,
  ADD COLUMN IF NOT EXISTS dpa_accepted_at timestamptz NULL;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
      FROM pg_catalog.pg_constraint c
      JOIN pg_catalog.pg_class t ON t.oid = c.conrelid
      JOIN pg_catalog.pg_namespace n ON n.oid = t.relnamespace
     WHERE n.nspname = 'rq'
       AND t.relname = 'tenants'
       AND c.conname = 'chk_tenants_tos_version_len'
  ) THEN
    ALTER TABLE rq.tenants
      ADD CONSTRAINT chk_tenants_tos_version_len
      CHECK (tos_version IS NULL OR pg_catalog.length(tos_version) BETWEEN 1 AND 64);
  END IF;

  IF NOT EXISTS (
    SELECT 1
      FROM pg_catalog.pg_constraint c
      JOIN pg_catalog.pg_class t ON t.oid = c.conrelid
      JOIN pg_catalog.pg_namespace n ON n.oid = t.relnamespace
     WHERE n.nspname = 'rq'
       AND t.relname = 'tenants'
       AND c.conname = 'chk_tenants_dpa_version_len'
  ) THEN
    ALTER TABLE rq.tenants
      ADD CONSTRAINT chk_tenants_dpa_version_len
      CHECK (dpa_version IS NULL OR pg_catalog.length(dpa_version) BETWEEN 1 AND 64);
  END IF;
END
$$;

CREATE TABLE IF NOT EXISTS rq.users (
  id uuid PRIMARY KEY,
  principal_id uuid UNIQUE NOT NULL REFERENCES rq.principals(id),
  tenant_id uuid NOT NULL REFERENCES rq.tenants(id),
  email text UNIQUE NOT NULL CHECK (pg_catalog.length(email) BETWEEN 3 AND 320),
  email_verified_at timestamptz NULL,
  password_hash text NOT NULL CHECK (pg_catalog.length(password_hash) >= 8),
  role text NOT NULL CHECK (role IN ('owner', 'admin', 'developer', 'auditor', 'viewer')),
  mfa_enrolled boolean NOT NULL DEFAULT false,
  totp_secret_enc bytea NULL,
  oidc_subject text NULL,
  last_login_at timestamptz NULL,
  created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  version bigint NOT NULL DEFAULT 1 CHECK (version >= 1)
);

CREATE INDEX IF NOT EXISTS idx_rq_users_tenant_created
  ON rq.users (tenant_id, created_at DESC);

CREATE TABLE IF NOT EXISTS rq.oidc_connections (
  id uuid PRIMARY KEY,
  tenant_id uuid UNIQUE NOT NULL REFERENCES rq.tenants(id),
  issuer_url text NOT NULL CHECK (issuer_url ~ '^https://'),
  client_id text NOT NULL CHECK (pg_catalog.length(client_id) >= 1),
  client_secret_ref text NOT NULL CHECK (pg_catalog.length(client_secret_ref) >= 1),
  role_mapping jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (pg_catalog.jsonb_typeof(role_mapping) = 'object'),
  enabled boolean NOT NULL DEFAULT false,
  created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp()
);

CREATE TABLE IF NOT EXISTS rq.support_break_glass_sessions (
  id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL REFERENCES rq.tenants(id),
  operator_id uuid NOT NULL REFERENCES rq.principals(id),
  reason text NOT NULL CHECK (pg_catalog.length(pg_catalog.btrim(reason)) >= 12),
  mfa_verified_at timestamptz NOT NULL,
  read_only boolean NOT NULL DEFAULT true CHECK (read_only = true),
  token_sha256 bytea UNIQUE NOT NULL CHECK (pg_catalog.octet_length(token_sha256) = 32),
  started_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  expires_at timestamptz NOT NULL,
  revoked_at timestamptz NULL,
  CHECK (expires_at > started_at AND expires_at <= started_at + interval '15 minutes')
);

CREATE INDEX IF NOT EXISTS idx_rq_support_break_glass_tenant_started
  ON rq.support_break_glass_sessions (tenant_id, started_at DESC);

CREATE TABLE IF NOT EXISTS rq.billing_customers (
  org_id uuid PRIMARY KEY REFERENCES rq.tenants(id),
  stripe_customer_id text UNIQUE NOT NULL CHECK (pg_catalog.length(stripe_customer_id) >= 1),
  billing_email text NOT NULL CHECK (pg_catalog.length(billing_email) BETWEEN 3 AND 320),
  billing_country char(2) NULL,
  currency char(3) NOT NULL DEFAULT 'USD',
  tax_exempt_status text NOT NULL DEFAULT 'none' CHECK (tax_exempt_status IN ('none', 'exempt', 'reverse')),
  tax_id_type text NULL,
  tax_id_value text NULL,
  tax_id_verified boolean NOT NULL DEFAULT false,
  default_txcd text NOT NULL DEFAULT 'txcd_10103001',
  last_stripe_event_ts timestamptz NOT NULL DEFAULT '1970-01-01T00:00:00Z'::timestamptz,
  created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp()
);

CREATE TABLE IF NOT EXISTS rq.billing_subscriptions (
  subscription_id uuid PRIMARY KEY,
  org_id uuid UNIQUE NOT NULL REFERENCES rq.billing_customers(org_id) ON DELETE CASCADE,
  stripe_subscription_id text UNIQUE NULL,
  plan_tier text NOT NULL CHECK (plan_tier IN ('free', 'pro', 'team', 'enterprise')),
  entitlement_state text NOT NULL CHECK (entitlement_state IN (
    'FREE',
    'TRIALING',
    'ACTIVE',
    'PAST_DUE_GRACE',
    'RESTRICTED_DOWNGRADED',
    'DISPUTE_HOLD',
    'CANCELED_END_OF_PERIOD',
    'CANCELED_TERMINATED',
    'UNKNOWN_RECONCILING'
  )),
  billing_interval text NOT NULL CHECK (billing_interval IN ('month', 'year')),
  currency char(3) NOT NULL DEFAULT 'USD',
  unit_amount_minor bigint NOT NULL DEFAULT 0 CHECK (unit_amount_minor >= 0),
  seat_count integer NOT NULL DEFAULT 1 CHECK (seat_count >= 1),
  current_period_start timestamptz NOT NULL,
  current_period_end timestamptz NOT NULL,
  trial_ends_at timestamptz NULL,
  grace_ends_at timestamptz NULL,
  cancel_at_period_end boolean NOT NULL DEFAULT false,
  last_stripe_event_ts timestamptz NOT NULL DEFAULT '1970-01-01T00:00:00Z'::timestamptz,
  version integer NOT NULL DEFAULT 1 CHECK (version >= 1),
  updated_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp()
);

CREATE INDEX IF NOT EXISTS idx_rq_billing_subs_state_grace
  ON rq.billing_subscriptions (entitlement_state, grace_ends_at);

CREATE TABLE IF NOT EXISTS rq.entitlement_quotas (
  org_id uuid PRIMARY KEY REFERENCES rq.billing_customers(org_id) ON DELETE CASCADE,
  max_seats integer NOT NULL CHECK (max_seats >= 1),
  max_concurrency integer NOT NULL CHECK (max_concurrency >= 1),
  included_units_month bigint NOT NULL CHECK (included_units_month >= 0),
  overage_unit_minor bigint NOT NULL DEFAULT 0 CHECK (overage_unit_minor >= 0),
  cap_mode text NOT NULL CHECK (cap_mode IN ('hard_cap', 'soft_cap')),
  soft_cap_minor bigint NULL CHECK (soft_cap_minor IS NULL OR soft_cap_minor >= 0),
  retention_days integer NOT NULL CHECK (retention_days >= 1),
  sso_enabled boolean NOT NULL DEFAULT false,
  updated_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp()
);

CREATE TABLE IF NOT EXISTS rq.usage_events (
  usage_event_id uuid PRIMARY KEY,
  org_id uuid NOT NULL REFERENCES rq.billing_customers(org_id),
  idempotency_key text NOT NULL CHECK (pg_catalog.length(idempotency_key) >= 1),
  metric_code text NOT NULL CHECK (metric_code IN ('outbound_deliveries', 'replay_deliveries')),
  period_month char(7) NOT NULL,
  billable_units bigint NOT NULL CHECK (billable_units >= 0),
  billed_reason text NOT NULL CHECK (billed_reason IN (
    'metered_usage',
    'included_allowance',
    'idempotent_replay_free',
    'cancelled_free',
    'cached_free',
    'system_error_free'
  )),
  cogs_micros bigint NOT NULL DEFAULT 0 CHECK (cogs_micros >= 0),
  currency char(3) NOT NULL DEFAULT 'USD',
  unit_price_minor bigint NOT NULL DEFAULT 0 CHECK (unit_price_minor >= 0),
  stripe_meter_event_id text NULL,
  created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  UNIQUE (org_id, metric_code, idempotency_key)
);

CREATE INDEX IF NOT EXISTS idx_rq_usage_org_month
  ON rq.usage_events (org_id, metric_code, period_month);

CREATE TABLE IF NOT EXISTS rq.usage_rollups (
  org_id uuid NOT NULL REFERENCES rq.billing_customers(org_id),
  metric_code text NOT NULL,
  period_month char(7) NOT NULL,
  total_billable_units bigint NOT NULL DEFAULT 0 CHECK (total_billable_units >= 0),
  total_free_units bigint NOT NULL DEFAULT 0 CHECK (total_free_units >= 0),
  total_cogs_micros bigint NOT NULL DEFAULT 0 CHECK (total_cogs_micros >= 0),
  alert_70_sent_at timestamptz NULL,
  alert_85_sent_at timestamptz NULL,
  alert_95_sent_at timestamptz NULL,
  spike_alert_sent_at timestamptz NULL,
  updated_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  PRIMARY KEY (org_id, metric_code, period_month)
);

CREATE TABLE IF NOT EXISTS rq.billing_webhook_events (
  stripe_event_id text PRIMARY KEY,
  event_type text NOT NULL,
  stripe_created_at timestamptz NOT NULL,
  payload_sha256 char(64) NOT NULL,
  outcome text NOT NULL CHECK (outcome IN ('APPLIED', 'IGNORED_STALE', 'IGNORED_DUPLICATE', 'FAILED')),
  error_detail text NULL,
  processed_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp()
);

CREATE TABLE IF NOT EXISTS rq.email_outbox (
  id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL REFERENCES rq.tenants(id),
  idempotency_key text UNIQUE NOT NULL,
  template_code text NOT NULL CHECK (template_code IN (
    'verify_email',
    'quota_alert_70',
    'quota_alert_85',
    'quota_alert_95',
    'quota_spike_3x',
    'dunning_notice_1',
    'dunning_notice_3',
    'dunning_notice_5',
    'dunning_notice_7',
    'break_glass_notice',
    'gdpr_erasure_receipt'
  )),
  recipient_email text NOT NULL CHECK (pg_catalog.length(recipient_email) BETWEEN 3 AND 320),
  template_vars jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (pg_catalog.jsonb_typeof(template_vars) = 'object'),
  state text NOT NULL CHECK (state IN ('pending', 'dispatched', 'failed_permanent')),
  provider_msg_id text NULL,
  attempt_count integer NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
  created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  dispatched_at timestamptz NULL
);

CREATE INDEX IF NOT EXISTS idx_rq_email_outbox_pending
  ON rq.email_outbox (created_at ASC)
  WHERE state = 'pending';

CREATE TABLE IF NOT EXISTS rq.gdpr_erasure_requests (
  id uuid PRIMARY KEY,
  org_id uuid NOT NULL REFERENCES rq.tenants(id),
  requested_by uuid NOT NULL,
  state text NOT NULL CHECK (state IN ('queued', 'redis_revoked', 'pg_purged', 'storage_purged', 'completed', 'failed')),
  redis_purged_at timestamptz NULL,
  pg_purged_at timestamptz NULL,
  storage_purged_at timestamptz NULL,
  tax_anonymized_at timestamptz NULL,
  receipt_sha256 bytea NULL CHECK (receipt_sha256 IS NULL OR pg_catalog.octet_length(receipt_sha256) = 32),
  requested_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  completed_at timestamptz NULL
);

CREATE INDEX IF NOT EXISTS idx_rq_gdpr_erasure_org_requested
  ON rq.gdpr_erasure_requests (org_id, requested_at DESC);

CREATE TABLE IF NOT EXISTS rq.legal_acceptances (
  id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL REFERENCES rq.tenants(id),
  user_id uuid NOT NULL,
  document_kind text NOT NULL CHECK (document_kind IN ('tos', 'privacy', 'dpa')),
  doc_version text NOT NULL CHECK (pg_catalog.length(doc_version) BETWEEN 1 AND 64),
  ip_sha256 bytea NOT NULL CHECK (pg_catalog.octet_length(ip_sha256) = 32),
  accepted_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp()
);

CREATE INDEX IF NOT EXISTS idx_rq_legal_acceptances_tenant_time
  ON rq.legal_acceptances (tenant_id, accepted_at DESC);

-- Enforce strict transaction-bound tenant RLS on all tenant/org-scoped tables added here
ALTER TABLE rq.users                        ENABLE ROW LEVEL SECURITY;
ALTER TABLE rq.users                        FORCE ROW LEVEL SECURITY;
ALTER TABLE rq.oidc_connections             ENABLE ROW LEVEL SECURITY;
ALTER TABLE rq.oidc_connections             FORCE ROW LEVEL SECURITY;
ALTER TABLE rq.support_break_glass_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE rq.support_break_glass_sessions FORCE ROW LEVEL SECURITY;
ALTER TABLE rq.billing_customers            ENABLE ROW LEVEL SECURITY;
ALTER TABLE rq.billing_customers            FORCE ROW LEVEL SECURITY;
ALTER TABLE rq.billing_subscriptions        ENABLE ROW LEVEL SECURITY;
ALTER TABLE rq.billing_subscriptions        FORCE ROW LEVEL SECURITY;
ALTER TABLE rq.entitlement_quotas           ENABLE ROW LEVEL SECURITY;
ALTER TABLE rq.entitlement_quotas           FORCE ROW LEVEL SECURITY;
ALTER TABLE rq.usage_events                 ENABLE ROW LEVEL SECURITY;
ALTER TABLE rq.usage_events                 FORCE ROW LEVEL SECURITY;
ALTER TABLE rq.usage_rollups                ENABLE ROW LEVEL SECURITY;
ALTER TABLE rq.usage_rollups                FORCE ROW LEVEL SECURITY;
ALTER TABLE rq.email_outbox                 ENABLE ROW LEVEL SECURITY;
ALTER TABLE rq.email_outbox                 FORCE ROW LEVEL SECURITY;
ALTER TABLE rq.gdpr_erasure_requests        ENABLE ROW LEVEL SECURITY;
ALTER TABLE rq.gdpr_erasure_requests        FORCE ROW LEVEL SECURITY;
ALTER TABLE rq.legal_acceptances            ENABLE ROW LEVEL SECURITY;
ALTER TABLE rq.legal_acceptances            FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_iso_users ON rq.users;
CREATE POLICY tenant_iso_users ON rq.users
  USING (tenant_id = NULLIF(pg_catalog.current_setting('app.current_tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(pg_catalog.current_setting('app.current_tenant_id', true), '')::uuid);

DROP POLICY IF EXISTS tenant_iso_oidc_connections ON rq.oidc_connections;
CREATE POLICY tenant_iso_oidc_connections ON rq.oidc_connections
  USING (tenant_id = NULLIF(pg_catalog.current_setting('app.current_tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(pg_catalog.current_setting('app.current_tenant_id', true), '')::uuid);

DROP POLICY IF EXISTS tenant_visible_break_glass ON rq.support_break_glass_sessions;
CREATE POLICY tenant_visible_break_glass ON rq.support_break_glass_sessions
  USING (tenant_id = NULLIF(pg_catalog.current_setting('app.current_tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(pg_catalog.current_setting('app.current_tenant_id', true), '')::uuid);

DROP POLICY IF EXISTS tenant_iso_billing_customers ON rq.billing_customers;
CREATE POLICY tenant_iso_billing_customers ON rq.billing_customers
  USING (org_id = NULLIF(pg_catalog.current_setting('app.current_tenant_id', true), '')::uuid)
  WITH CHECK (org_id = NULLIF(pg_catalog.current_setting('app.current_tenant_id', true), '')::uuid);

DROP POLICY IF EXISTS tenant_iso_billing_subscriptions ON rq.billing_subscriptions;
CREATE POLICY tenant_iso_billing_subscriptions ON rq.billing_subscriptions
  USING (org_id = NULLIF(pg_catalog.current_setting('app.current_tenant_id', true), '')::uuid)
  WITH CHECK (org_id = NULLIF(pg_catalog.current_setting('app.current_tenant_id', true), '')::uuid);

DROP POLICY IF EXISTS tenant_iso_entitlement_quotas ON rq.entitlement_quotas;
CREATE POLICY tenant_iso_entitlement_quotas ON rq.entitlement_quotas
  USING (org_id = NULLIF(pg_catalog.current_setting('app.current_tenant_id', true), '')::uuid)
  WITH CHECK (org_id = NULLIF(pg_catalog.current_setting('app.current_tenant_id', true), '')::uuid);

DROP POLICY IF EXISTS tenant_iso_usage_events ON rq.usage_events;
CREATE POLICY tenant_iso_usage_events ON rq.usage_events
  USING (org_id = NULLIF(pg_catalog.current_setting('app.current_tenant_id', true), '')::uuid)
  WITH CHECK (org_id = NULLIF(pg_catalog.current_setting('app.current_tenant_id', true), '')::uuid);

DROP POLICY IF EXISTS tenant_iso_usage_rollups ON rq.usage_rollups;
CREATE POLICY tenant_iso_usage_rollups ON rq.usage_rollups
  USING (org_id = NULLIF(pg_catalog.current_setting('app.current_tenant_id', true), '')::uuid)
  WITH CHECK (org_id = NULLIF(pg_catalog.current_setting('app.current_tenant_id', true), '')::uuid);

DROP POLICY IF EXISTS tenant_iso_email_outbox ON rq.email_outbox;
CREATE POLICY tenant_iso_email_outbox ON rq.email_outbox
  USING (tenant_id = NULLIF(pg_catalog.current_setting('app.current_tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(pg_catalog.current_setting('app.current_tenant_id', true), '')::uuid);

DROP POLICY IF EXISTS tenant_iso_gdpr_erasure_requests ON rq.gdpr_erasure_requests;
CREATE POLICY tenant_iso_gdpr_erasure_requests ON rq.gdpr_erasure_requests
  USING (org_id = NULLIF(pg_catalog.current_setting('app.current_tenant_id', true), '')::uuid)
  WITH CHECK (org_id = NULLIF(pg_catalog.current_setting('app.current_tenant_id', true), '')::uuid);

DROP POLICY IF EXISTS tenant_iso_legal_acceptances ON rq.legal_acceptances;
CREATE POLICY tenant_iso_legal_acceptances ON rq.legal_acceptances
  USING (tenant_id = NULLIF(pg_catalog.current_setting('app.current_tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(pg_catalog.current_setting('app.current_tenant_id', true), '')::uuid);

-- Transfer ownership of all new schema relations to rq_owner
DO $$
DECLARE
  v_can_own boolean := false;
  v_rec record;
BEGIN
  SELECT (r.rolsuper OR pg_catalog.pg_has_role(current_user, 'rq_owner', 'MEMBER'))
    INTO v_can_own
    FROM pg_catalog.pg_roles r
   WHERE r.rolname = current_user;

  IF v_can_own THEN
    FOR v_rec IN
      SELECT c.relkind, n.nspname, c.relname
        FROM pg_catalog.pg_class c
        JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
       WHERE n.nspname = 'rq'
         AND c.relkind IN ('r', 'p', 'v', 'S')
         AND pg_catalog.pg_get_userbyid(c.relowner) <> 'rq_owner'
    LOOP
      IF v_rec.relkind = 'S' THEN
        EXECUTE pg_catalog.format('ALTER SEQUENCE %I.%I OWNER TO rq_owner', v_rec.nspname, v_rec.relname);
      ELSIF v_rec.relkind = 'v' THEN
        EXECUTE pg_catalog.format('ALTER VIEW %I.%I OWNER TO rq_owner', v_rec.nspname, v_rec.relname);
      ELSE
        EXECUTE pg_catalog.format('ALTER TABLE %I.%I OWNER TO rq_owner', v_rec.nspname, v_rec.relname);
      END IF;
    END LOOP;
  END IF;
END
$$;

-- Revoke PUBLIC and strip direct DML privileges before granting least-privilege SELECT access
REVOKE ALL ON TABLE
  rq.users,
  rq.oidc_connections,
  rq.support_break_glass_sessions,
  rq.billing_customers,
  rq.billing_subscriptions,
  rq.entitlement_quotas,
  rq.usage_events,
  rq.usage_rollups,
  rq.billing_webhook_events,
  rq.email_outbox,
  rq.gdpr_erasure_requests,
  rq.legal_acceptances
FROM PUBLIC, rq_api, rq_relay, rq_fanout, rq_sender, rq_coordinator, rq_reporter, rq_signing_issuer, rq_migrator, rq_recovery, rq_billing, rq_audit_ro, rq_worker;

REVOKE ALL ON TABLE rq.audit_events FROM PUBLIC, rq_billing, rq_audit_ro, rq_worker;

GRANT SELECT ON
  rq.billing_customers,
  rq.billing_subscriptions,
  rq.entitlement_quotas,
  rq.usage_events,
  rq.usage_rollups,
  rq.billing_webhook_events
TO rq_billing;

GRANT SELECT ON
  rq.audit_events,
  rq.support_break_glass_sessions,
  rq.gdpr_erasure_requests,
  rq.legal_acceptances
TO rq_audit_ro;

GRANT SELECT ON
  rq.users,
  rq.oidc_connections,
  rq.support_break_glass_sessions,
  rq.billing_customers,
  rq.billing_subscriptions,
  rq.entitlement_quotas,
  rq.usage_events,
  rq.usage_rollups,
  rq.email_outbox,
  rq.gdpr_erasure_requests,
  rq.legal_acceptances
TO rq_api;

GRANT SELECT ON
  rq.billing_customers,
  rq.billing_subscriptions,
  rq.entitlement_quotas,
  rq.usage_rollups,
  rq.email_outbox,
  rq.gdpr_erasure_requests
TO rq_coordinator;

GRANT SELECT ON
  rq.email_outbox,
  rq.outbox_events,
  rq.broker_inbox,
  rq.deliveries,
  rq.delivery_attempts
TO rq_worker;
