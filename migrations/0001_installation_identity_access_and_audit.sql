-- Migration 0001: Installation gate, principals, native authentication, runtime instances, and audit log.

DO $$
DECLARE
  v_can_create_role boolean := false;
  v_role text;
  v_owner_is_member boolean := false;
  v_missing_roles text[] := ARRAY[]::text[];
BEGIN
  SELECT (r.rolsuper OR r.rolcreaterole)
    INTO v_can_create_role
    FROM pg_catalog.pg_roles r
   WHERE r.rolname = current_user;

  FOREACH v_role IN ARRAY ARRAY[
    'rq_owner',
    'rq_api',
    'rq_relay',
    'rq_fanout',
    'rq_sender',
    'rq_coordinator',
    'rq_reporter',
    'rq_signing_issuer',
    'rq_migrator',
    'rq_recovery'
  ] LOOP
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = v_role) THEN
      v_missing_roles := pg_catalog.array_append(v_missing_roles, v_role);
    END IF;
  END LOOP;

  IF COALESCE(pg_catalog.array_length(v_missing_roles, 1), 0) > 0 THEN
    IF NOT v_can_create_role THEN
      RAISE EXCEPTION 'Required Relayquill database roles missing (%) and current user "%" lacks CREATEROLE privilege',
        pg_catalog.array_to_string(v_missing_roles, ', '),
        current_user;
    END IF;

    FOREACH v_role IN ARRAY v_missing_roles LOOP
      IF v_role = 'rq_owner' THEN
        EXECUTE pg_catalog.format(
          'CREATE ROLE %I NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS',
          v_role
        );
      ELSE
        EXECUTE pg_catalog.format(
          'CREATE ROLE %I LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS',
          v_role
        );
      END IF;
    END LOOP;
  END IF;

  IF v_can_create_role THEN
    SELECT pg_catalog.pg_has_role('rq_migrator', 'rq_owner', 'MEMBER') INTO v_owner_is_member;
    IF NOT v_owner_is_member THEN
      EXECUTE 'GRANT rq_owner TO rq_migrator';
    END IF;
  END IF;
END
$$;

CREATE SCHEMA IF NOT EXISTS rq;
CREATE SCHEMA IF NOT EXISTS rq_support;
CREATE SCHEMA IF NOT EXISTS rq_recovery;

DO $$
DECLARE
  v_is_super boolean := false;
  v_schema text;
  v_ext_schema text;
BEGIN
  SELECT r.rolsuper INTO v_is_super
    FROM pg_catalog.pg_roles r
   WHERE r.rolname = current_user;

  IF v_is_super THEN
    FOREACH v_schema IN ARRAY ARRAY['rq', 'rq_support', 'rq_recovery'] LOOP
      EXECUTE pg_catalog.format('ALTER SCHEMA %I OWNER TO rq_owner', v_schema);
    END LOOP;
    BEGIN
      EXECUTE 'REVOKE CREATE ON SCHEMA public FROM PUBLIC';
    EXCEPTION WHEN insufficient_privilege THEN
      NULL;
    END;
  END IF;

  SELECT n.nspname
    INTO v_ext_schema
    FROM pg_catalog.pg_extension e
    JOIN pg_catalog.pg_namespace n ON n.oid = e.extnamespace
   WHERE e.extname = 'btree_gist';

  IF v_ext_schema IS NULL THEN
    EXECUTE 'CREATE EXTENSION IF NOT EXISTS btree_gist WITH SCHEMA rq_support';
    v_ext_schema := 'rq_support';
  END IF;

  IF v_ext_schema IS NOT NULL THEN
    EXECUTE pg_catalog.format('GRANT USAGE ON SCHEMA %I TO rq_owner', v_ext_schema);
  END IF;
END
$$;

CREATE TABLE IF NOT EXISTS rq.schema_migrations (
  migration_id text PRIMARY KEY CHECK (pg_catalog.length(migration_id) BETWEEN 1 AND 128),
  checksum bytea NOT NULL CHECK (pg_catalog.octet_length(checksum) = 32),
  applied_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  source_reference text NOT NULL CHECK (pg_catalog.length(source_reference) BETWEEN 1 AND 256),
  runner_version text NOT NULL CHECK (pg_catalog.length(runner_version) BETWEEN 1 AND 128)
);

CREATE TABLE IF NOT EXISTS rq.installation_state (
  id smallint PRIMARY KEY CHECK (id = 1),
  control_epoch uuid NOT NULL,
  mode text NOT NULL CHECK (mode IN ('initializing', 'open', 'admission_hold', 'recovery_quarantine', 'retired')),
  allow_event_admission boolean NOT NULL,
  allow_publication boolean NOT NULL,
  allow_fanout boolean NOT NULL,
  allow_send boolean NOT NULL,
  allow_endpoint_verification boolean NOT NULL,
  governance_version bigint NOT NULL DEFAULT 1 CHECK (governance_version >= 1),
  updated_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  version bigint NOT NULL DEFAULT 1 CHECK (version >= 1),
  CONSTRAINT chk_installation_quarantine_or_retired_flags CHECK (
    mode NOT IN ('recovery_quarantine', 'retired')
    OR (
      NOT allow_event_admission
      AND NOT allow_publication
      AND NOT allow_fanout
      AND NOT allow_send
      AND NOT allow_endpoint_verification
    )
  )
);

INSERT INTO rq.installation_state (
  id,
  control_epoch,
  mode,
  allow_event_admission,
  allow_publication,
  allow_fanout,
  allow_send,
  allow_endpoint_verification,
  governance_version,
  updated_at,
  version
)
VALUES (
  1,
  pg_catalog.gen_random_uuid(),
  'initializing',
  false,
  false,
  false,
  false,
  false,
  1,
  pg_catalog.clock_timestamp(),
  1
)
ON CONFLICT (id) DO NOTHING;

CREATE TABLE IF NOT EXISTS rq.principals (
  id uuid PRIMARY KEY,
  kind text NOT NULL CHECK (kind IN ('human', 'producer')),
  state text NOT NULL CHECK (state IN ('pending', 'active', 'suspended', 'retired')),
  authority_epoch bigint NOT NULL DEFAULT 1 CHECK (authority_epoch >= 1),
  created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  version bigint NOT NULL DEFAULT 1 CHECK (version >= 1),
  UNIQUE (id, kind)
);

CREATE TABLE IF NOT EXISTS rq.humans (
  principal_id uuid PRIMARY KEY,
  principal_kind text NOT NULL DEFAULT 'human' CHECK (principal_kind = 'human'),
  display_name text NOT NULL CHECK (pg_catalog.octet_length(display_name) BETWEEN 1 AND 256),
  webauthn_user_id bytea NOT NULL UNIQUE CHECK (pg_catalog.octet_length(webauthn_user_id) BETWEEN 16 AND 64),
  created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  version bigint NOT NULL DEFAULT 1 CHECK (version >= 1),
  FOREIGN KEY (principal_id, principal_kind) REFERENCES rq.principals(id, kind),
  UNIQUE (principal_id, webauthn_user_id)
);

CREATE TABLE IF NOT EXISTS rq.passkeys (
  id uuid PRIMARY KEY,
  human_principal_id uuid NOT NULL,
  credential_id bytea NOT NULL UNIQUE CHECK (pg_catalog.octet_length(credential_id) BETWEEN 16 AND 1024),
  public_key bytea NOT NULL CHECK (pg_catalog.octet_length(public_key) BETWEEN 32 AND 4096),
  webauthn_user_id bytea NOT NULL,
  sign_count bigint NOT NULL DEFAULT 0 CHECK (sign_count >= 0),
  device_type text NOT NULL CHECK (pg_catalog.length(device_type) BETWEEN 1 AND 64),
  backed_up boolean NOT NULL,
  transports jsonb NOT NULL DEFAULT '[]'::jsonb,
  state text NOT NULL CHECK (state IN ('active', 'revoked', 'recovery_pending')),
  enrolled_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  last_used_at timestamptz NULL,
  revoked_at timestamptz NULL,
  version bigint NOT NULL DEFAULT 1 CHECK (version >= 1),
  FOREIGN KEY (human_principal_id, webauthn_user_id) REFERENCES rq.humans(principal_id, webauthn_user_id),
  CONSTRAINT chk_passkeys_transports_array CHECK (pg_catalog.jsonb_typeof(transports) = 'array')
);

CREATE TABLE IF NOT EXISTS rq.preauth_contexts (
  id uuid PRIMARY KEY,
  proof_digest bytea NOT NULL UNIQUE CHECK (pg_catalog.octet_length(proof_digest) = 32),
  state text NOT NULL CHECK (state IN ('active', 'revoked', 'expired')),
  created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  expires_at timestamptz NOT NULL,
  version bigint NOT NULL DEFAULT 1 CHECK (version >= 1),
  CHECK (expires_at > created_at)
);

CREATE TABLE IF NOT EXISTS rq.human_sessions (
  id uuid PRIMARY KEY,
  principal_id uuid NOT NULL REFERENCES rq.humans(principal_id),
  control_epoch uuid NOT NULL,
  token_digest bytea NOT NULL UNIQUE CHECK (pg_catalog.octet_length(token_digest) = 32),
  csrf_digest bytea NOT NULL CHECK (pg_catalog.octet_length(csrf_digest) = 32),
  principal_authority_epoch bigint NOT NULL CHECK (principal_authority_epoch >= 1),
  purpose text NOT NULL CHECK (purpose IN ('ordinary', 'recovery_restricted')),
  state text NOT NULL CHECK (state IN ('active', 'revoked', 'expired')),
  created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  last_seen_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  idle_expires_at timestamptz NOT NULL,
  absolute_expires_at timestamptz NOT NULL,
  revoked_at timestamptz NULL,
  version bigint NOT NULL DEFAULT 1 CHECK (version >= 1),
  UNIQUE (id, principal_id),
  CHECK (idle_expires_at > created_at AND absolute_expires_at >= idle_expires_at)
);

CREATE TABLE IF NOT EXISTS rq.auth_challenges (
  id uuid PRIMARY KEY,
  control_epoch uuid NOT NULL,
  human_principal_id uuid NULL REFERENCES rq.humans(principal_id),
  purpose text NOT NULL CHECK (purpose IN ('enroll_passkey', 'sign_in', 'step_up', 'restricted_recovery')),
  challenge_bytes bytea NOT NULL CHECK (pg_catalog.octet_length(challenge_bytes) BETWEEN 16 AND 128),
  browser_proof_digest bytea NOT NULL CHECK (pg_catalog.octet_length(browser_proof_digest) = 32),
  preauth_context_id uuid NULL REFERENCES rq.preauth_contexts(id),
  session_id uuid NULL REFERENCES rq.human_sessions(id),
  action text NULL CHECK (action IS NULL OR pg_catalog.length(action) BETWEEN 1 AND 128),
  target_sha256 bytea NULL CHECK (target_sha256 IS NULL OR pg_catalog.octet_length(target_sha256) = 32),
  state text NOT NULL CHECK (state IN ('pending', 'consumed', 'denied', 'expired', 'revoked')),
  failure_count integer NOT NULL DEFAULT 0 CHECK (failure_count BETWEEN 0 AND 5),
  created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  expires_at timestamptz NOT NULL,
  version bigint NOT NULL DEFAULT 1 CHECK (version >= 1),
  CHECK (expires_at > created_at),
  CONSTRAINT chk_auth_challenges_purpose_binding CHECK (
    (
      purpose = 'step_up'
      AND session_id IS NOT NULL
      AND preauth_context_id IS NULL
      AND human_principal_id IS NOT NULL
      AND action IS NOT NULL
      AND target_sha256 IS NOT NULL
    )
    OR (
      purpose <> 'step_up'
      AND preauth_context_id IS NOT NULL
      AND session_id IS NULL
    )
  )
);

CREATE TABLE IF NOT EXISTS rq.enrollment_intents (
  id uuid PRIMARY KEY,
  control_epoch uuid NOT NULL,
  purpose text NOT NULL CHECK (purpose IN ('first_platform_admin', 'invited_human', 'restricted_factor_recovery')),
  target_principal_id uuid NULL REFERENCES rq.humans(principal_id),
  tenant_id uuid NULL,
  project_id uuid NULL,
  browser_proof_digest bytea NOT NULL CHECK (pg_catalog.octet_length(browser_proof_digest) = 32),
  preauth_context_id uuid NOT NULL REFERENCES rq.preauth_contexts(id),
  comparison_sha256 bytea NOT NULL CHECK (pg_catalog.octet_length(comparison_sha256) = 32),
  state text NOT NULL CHECK (state IN ('requested', 'approved', 'enrolling', 'completed', 'rejected', 'expired', 'revoked')),
  approved_by uuid NULL REFERENCES rq.humans(principal_id),
  operator_event_reference text NULL CHECK (operator_event_reference IS NULL OR pg_catalog.octet_length(operator_event_reference) BETWEEN 1 AND 256),
  created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  expires_at timestamptz NOT NULL,
  version bigint NOT NULL DEFAULT 1 CHECK (version >= 1),
  CHECK (expires_at > created_at),
  CHECK (project_id IS NULL OR tenant_id IS NOT NULL)
);

CREATE TABLE IF NOT EXISTS rq.platform_role_assignments (
  id uuid PRIMARY KEY,
  principal_id uuid NOT NULL REFERENCES rq.humans(principal_id),
  role text NOT NULL CHECK (role IN ('platform_admin', 'platform_auditor')),
  state text NOT NULL CHECK (state IN ('active', 'revoked')),
  governance_version bigint NOT NULL CHECK (governance_version >= 1),
  created_by uuid NULL REFERENCES rq.humans(principal_id),
  created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  revoked_at timestamptz NULL,
  version bigint NOT NULL DEFAULT 1 CHECK (version >= 1),
  CHECK ((state = 'revoked' AND revoked_at IS NOT NULL) OR (state = 'active' AND revoked_at IS NULL))
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_platform_role_assignments_active
  ON rq.platform_role_assignments (principal_id, role)
  WHERE state = 'active';

CREATE TABLE IF NOT EXISTS rq.operation_proofs (
  id uuid PRIMARY KEY,
  session_id uuid NOT NULL,
  principal_id uuid NOT NULL,
  control_epoch uuid NOT NULL,
  action text NOT NULL CHECK (pg_catalog.length(action) BETWEEN 1 AND 128),
  target_sha256 bytea NOT NULL CHECK (pg_catalog.octet_length(target_sha256) = 32),
  challenge_id uuid NOT NULL UNIQUE REFERENCES rq.auth_challenges(id),
  verified_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  expires_at timestamptz NOT NULL,
  state text NOT NULL CHECK (state IN ('active', 'consumed', 'revoked')),
  accepted_receipt_id uuid NULL,
  version bigint NOT NULL DEFAULT 1 CHECK (version >= 1),
  FOREIGN KEY (session_id, principal_id) REFERENCES rq.human_sessions(id, principal_id),
  CHECK (expires_at > verified_at)
);

CREATE TABLE IF NOT EXISTS rq.runtime_instances (
  id uuid PRIMARY KEY,
  process_role text NOT NULL CHECK (process_role IN ('api', 'relay', 'fanout', 'sender', 'coordinator', 'protected_admin')),
  database_role text NOT NULL CHECK (database_role IN ('rq_api', 'rq_relay', 'rq_fanout', 'rq_sender', 'rq_coordinator', 'rq_reporter', 'rq_signing_issuer', 'rq_migrator', 'rq_recovery')),
  control_epoch uuid NOT NULL,
  build_reference text NOT NULL CHECK (pg_catalog.octet_length(build_reference) BETWEEN 1 AND 256),
  state text NOT NULL CHECK (state IN ('active', 'draining', 'quarantined', 'ended')),
  started_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  last_seen_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  expires_at timestamptz NOT NULL,
  version bigint NOT NULL DEFAULT 1 CHECK (version >= 1),
  UNIQUE (id, process_role),
  CHECK (expires_at >= started_at)
);

CREATE TABLE IF NOT EXISTS rq.audit_events (
  id uuid PRIMARY KEY,
  tenant_id uuid NULL,
  project_id uuid NULL,
  actor_kind text NOT NULL CHECK (actor_kind IN ('human', 'producer', 'runtime_instance', 'operator', 'system')),
  actor_reference uuid NULL,
  operator_reference text NULL CHECK (operator_reference IS NULL OR pg_catalog.octet_length(operator_reference) BETWEEN 1 AND 256),
  action text NOT NULL CHECK (pg_catalog.length(action) BETWEEN 1 AND 128),
  target_kind text NOT NULL CHECK (pg_catalog.length(target_kind) BETWEEN 1 AND 128),
  target_id uuid NOT NULL,
  prior_version bigint NULL CHECK (prior_version IS NULL OR prior_version >= 0),
  resulting_version bigint NULL CHECK (resulting_version IS NULL OR resulting_version >= 0),
  candidate_sha256 bytea NULL CHECK (candidate_sha256 IS NULL OR pg_catalog.octet_length(candidate_sha256) = 32),
  command_receipt_id uuid NULL,
  recorded_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  safe_facts jsonb NOT NULL DEFAULT '{}'::jsonb,
  CHECK (project_id IS NULL OR tenant_id IS NOT NULL),
  CHECK (
    (actor_kind IN ('human', 'producer', 'runtime_instance') AND actor_reference IS NOT NULL)
    OR actor_kind IN ('operator', 'system')
  ),
  CHECK (pg_catalog.jsonb_typeof(safe_facts) = 'object')
);
