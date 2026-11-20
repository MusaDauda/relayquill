-- Receiver Migration 0001: Independent receiver roles, rc schema, configuration, inbox, synthetic counter, receipts, and strict order heads.

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

  FOREACH v_role IN ARRAY ARRAY['receiver_owner', 'receiver_migrator', 'receiver_runtime'] LOOP
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = v_role) THEN
      v_missing_roles := pg_catalog.array_append(v_missing_roles, v_role);
    END IF;
  END LOOP;

  IF COALESCE(pg_catalog.array_length(v_missing_roles, 1), 0) > 0 THEN
    IF NOT v_can_create_role THEN
      RAISE EXCEPTION 'Required receiver database roles missing (%) and current user "%" lacks CREATEROLE privilege',
        pg_catalog.array_to_string(v_missing_roles, ', '),
        current_user;
    END IF;

    FOREACH v_role IN ARRAY v_missing_roles LOOP
      IF v_role = 'receiver_owner' THEN
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
    SELECT pg_catalog.pg_has_role('receiver_migrator', 'receiver_owner', 'MEMBER') INTO v_owner_is_member;
    IF NOT v_owner_is_member THEN
      EXECUTE 'GRANT receiver_owner TO receiver_migrator';
    END IF;
  END IF;
END
$$;

CREATE SCHEMA IF NOT EXISTS rc;

DO $$
DECLARE
  v_is_super boolean := false;
BEGIN
  SELECT r.rolsuper INTO v_is_super FROM pg_catalog.pg_roles r WHERE r.rolname = current_user;
  IF v_is_super THEN
    EXECUTE 'ALTER SCHEMA rc OWNER TO receiver_owner';
  END IF;
END
$$;

CREATE TABLE IF NOT EXISTS rc.schema_migrations (
  migration_id text PRIMARY KEY CHECK (pg_catalog.length(migration_id) BETWEEN 1 AND 128),
  checksum bytea NOT NULL CHECK (pg_catalog.octet_length(checksum) = 32),
  applied_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  source_reference text NOT NULL CHECK (pg_catalog.length(source_reference) BETWEEN 1 AND 256),
  runner_version text NOT NULL CHECK (pg_catalog.length(runner_version) BETWEEN 1 AND 128)
);

CREATE TABLE IF NOT EXISTS rc.integrations (
  id uuid PRIMARY KEY,
  relay_project_id uuid NOT NULL,
  endpoint_id uuid NOT NULL,
  consumer_contract_scope text NOT NULL CHECK (pg_catalog.octet_length(consumer_contract_scope) BETWEEN 1 AND 128),
  expected_external_authority text NOT NULL CHECK (pg_catalog.octet_length(expected_external_authority) BETWEEN 1 AND 256),
  expected_request_target text NOT NULL CHECK (pg_catalog.octet_length(expected_request_target) BETWEEN 1 AND 512),
  configuration_version bigint NOT NULL DEFAULT 1 CHECK (configuration_version >= 1),
  receiver_contract_id uuid NOT NULL,
  receiver_contract_version bigint NOT NULL CHECK (receiver_contract_version >= 1),
  contract_sha256 bytea NOT NULL CHECK (pg_catalog.octet_length(contract_sha256) = 32),
  state text NOT NULL CHECK (state IN ('active', 'paused', 'retired')),
  demo_counter_id uuid NOT NULL,
  created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  version bigint NOT NULL DEFAULT 1 CHECK (version >= 1),
  UNIQUE (relay_project_id, endpoint_id, consumer_contract_scope),
  UNIQUE (id, relay_project_id)
);

CREATE TABLE IF NOT EXISTS rc.allowed_endpoint_versions (
  integration_id uuid NOT NULL REFERENCES rc.integrations(id),
  endpoint_version bigint NOT NULL CHECK (endpoint_version >= 1),
  state text NOT NULL CHECK (state IN ('pending', 'active', 'retired', 'revoked')),
  verify_until timestamptz NULL,
  version bigint NOT NULL DEFAULT 1 CHECK (version >= 1),
  PRIMARY KEY (integration_id, endpoint_version)
);

CREATE TABLE IF NOT EXISTS rc.key_metadata (
  integration_id uuid NOT NULL REFERENCES rc.integrations(id),
  key_id text NOT NULL CHECK (key_id ~ '^[a-z0-9][a-z0-9._-]{0,63}$'),
  custody_reference text NOT NULL CHECK (pg_catalog.octet_length(custody_reference) BETWEEN 1 AND 256),
  custody_version_reference text NOT NULL CHECK (pg_catalog.octet_length(custody_version_reference) BETWEEN 1 AND 256),
  state text NOT NULL CHECK (state IN ('pending', 'active', 'overlap', 'retired', 'revoked')),
  verify_until timestamptz NULL,
  configuration_version bigint NOT NULL DEFAULT 1 CHECK (configuration_version >= 1),
  version bigint NOT NULL DEFAULT 1 CHECK (version >= 1),
  PRIMARY KEY (integration_id, key_id)
);

CREATE TABLE IF NOT EXISTS rc.key_configuration_events (
  id uuid PRIMARY KEY,
  integration_id uuid NOT NULL REFERENCES rc.integrations(id),
  key_id text NOT NULL,
  action text NOT NULL CHECK (action IN ('install_pending', 'promote_active', 'rotate_overlap', 'retire', 'revoke', 'bind_contract')),
  prior_version bigint NOT NULL CHECK (prior_version >= 0),
  resulting_version bigint NOT NULL CHECK (resulting_version >= 1),
  contract_sha256 bytea NOT NULL CHECK (pg_catalog.octet_length(contract_sha256) = 32),
  operator_reference text NOT NULL CHECK (pg_catalog.octet_length(operator_reference) BETWEEN 1 AND 256),
  accepted_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp()
);

CREATE TABLE IF NOT EXISTS rc.allowed_representations (
  id uuid PRIMARY KEY,
  integration_id uuid NOT NULL REFERENCES rc.integrations(id),
  envelope_version integer NOT NULL CHECK (envelope_version IN (1, 2)),
  profile_id uuid NULL,
  profile_version bigint NULL CHECK (profile_version IS NULL OR profile_version >= 1),
  target_schema_version integer NULL CHECK (target_schema_version IS NULL OR target_schema_version >= 1),
  state text NOT NULL CHECK (state IN ('active', 'retired')),
  version bigint NOT NULL DEFAULT 1 CHECK (version >= 1),
  CONSTRAINT chk_rc_allowed_representations_envelope CHECK (
    (envelope_version = 1 AND profile_id IS NULL AND profile_version IS NULL AND target_schema_version IS NULL)
    OR (envelope_version = 2 AND profile_id IS NOT NULL AND profile_version IS NOT NULL AND target_schema_version IS NOT NULL)
  )
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_rc_allowed_representations_v1
  ON rc.allowed_representations (integration_id, envelope_version)
  WHERE envelope_version = 1;

CREATE UNIQUE INDEX IF NOT EXISTS uq_rc_allowed_representations_v2
  ON rc.allowed_representations (integration_id, envelope_version, profile_id, profile_version, target_schema_version)
  WHERE envelope_version = 2;

CREATE TABLE IF NOT EXISTS rc.demo_counters (
  id uuid PRIMARY KEY,
  integration_id uuid NOT NULL REFERENCES rc.integrations(id),
  label text NOT NULL CHECK (pg_catalog.octet_length(label) BETWEEN 1 AND 128),
  value bigint NOT NULL DEFAULT 0 CHECK (value >= 0),
  version bigint NOT NULL DEFAULT 1 CHECK (version >= 1),
  UNIQUE (id, integration_id)
);

CREATE TABLE IF NOT EXISTS rc.inbox (
  integration_id uuid NOT NULL,
  consumer_event_key_sha256 bytea NOT NULL CHECK (pg_catalog.octet_length(consumer_event_key_sha256) = 32),
  relay_project_id uuid NOT NULL,
  event_id uuid NOT NULL,
  original_facts_sha256 bytea NOT NULL CHECK (pg_catalog.octet_length(original_facts_sha256) = 32),
  original_content_sha256 bytea NOT NULL CHECK (pg_catalog.octet_length(original_content_sha256) = 32),
  source_event_type_id uuid NOT NULL,
  source_schema_version integer NOT NULL CHECK (source_schema_version >= 1),
  first_representation_version integer NOT NULL CHECK (first_representation_version >= 1),
  first_wire_sha256 bytea NOT NULL CHECK (pg_catalog.octet_length(first_wire_sha256) = 32),
  state text NOT NULL CHECK (state = 'processed'),
  first_attempt_id uuid NOT NULL,
  processed_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  receipt_id uuid NOT NULL,
  version bigint NOT NULL DEFAULT 1 CHECK (version >= 1),
  PRIMARY KEY (integration_id, consumer_event_key_sha256),
  UNIQUE (integration_id, consumer_event_key_sha256, original_facts_sha256),
  FOREIGN KEY (integration_id, relay_project_id) REFERENCES rc.integrations(id, relay_project_id)
);

CREATE TABLE IF NOT EXISTS rc.business_mutations (
  id uuid PRIMARY KEY,
  integration_id uuid NOT NULL,
  consumer_event_key_sha256 bytea NOT NULL CHECK (pg_catalog.octet_length(consumer_event_key_sha256) = 32),
  counter_id uuid NOT NULL,
  applied_increment integer NOT NULL DEFAULT 1 CHECK (applied_increment = 1),
  original_facts_sha256 bytea NOT NULL CHECK (pg_catalog.octet_length(original_facts_sha256) = 32),
  recorded_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  version bigint NOT NULL DEFAULT 1 CHECK (version >= 1),
  UNIQUE (integration_id, consumer_event_key_sha256),
  FOREIGN KEY (integration_id, consumer_event_key_sha256, original_facts_sha256)
    REFERENCES rc.inbox(integration_id, consumer_event_key_sha256, original_facts_sha256),
  FOREIGN KEY (counter_id, integration_id) REFERENCES rc.demo_counters(id, integration_id)
);

CREATE TABLE IF NOT EXISTS rc.receipts (
  id uuid PRIMARY KEY,
  integration_id uuid NOT NULL,
  consumer_event_key_sha256 bytea NOT NULL CHECK (pg_catalog.octet_length(consumer_event_key_sha256) = 32),
  original_facts_sha256 bytea NOT NULL CHECK (pg_catalog.octet_length(original_facts_sha256) = 32),
  business_status text NOT NULL CHECK (business_status = 'committed'),
  committed_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  version bigint NOT NULL DEFAULT 1 CHECK (version >= 1),
  UNIQUE (integration_id, consumer_event_key_sha256),
  UNIQUE (id, integration_id, consumer_event_key_sha256, original_facts_sha256),
  FOREIGN KEY (integration_id, consumer_event_key_sha256, original_facts_sha256)
    REFERENCES rc.inbox(integration_id, consumer_event_key_sha256, original_facts_sha256)
);

CREATE TABLE IF NOT EXISTS rc.order_heads (
  integration_id uuid NOT NULL REFERENCES rc.integrations(id),
  ordering_domain_id uuid NOT NULL,
  ordering_key_sha256 bytea NOT NULL CHECK (pg_catalog.octet_length(ordering_key_sha256) = 32),
  next_expected_sequence bigint NOT NULL DEFAULT 1 CHECK (next_expected_sequence >= 1),
  state text NOT NULL DEFAULT 'active' CHECK (state IN ('active', 'held')),
  version bigint NOT NULL DEFAULT 1 CHECK (version >= 1),
  PRIMARY KEY (integration_id, ordering_domain_id, ordering_key_sha256)
);

CREATE TABLE IF NOT EXISTS rc.order_acceptances (
  integration_id uuid NOT NULL,
  ordering_domain_id uuid NOT NULL,
  ordering_key_sha256 bytea NOT NULL CHECK (pg_catalog.octet_length(ordering_key_sha256) = 32),
  ordering_sequence bigint NOT NULL CHECK (ordering_sequence >= 1),
  consumer_event_key_sha256 bytea NOT NULL CHECK (pg_catalog.octet_length(consumer_event_key_sha256) = 32),
  original_facts_sha256 bytea NOT NULL CHECK (pg_catalog.octet_length(original_facts_sha256) = 32),
  receipt_id uuid NOT NULL,
  first_attempt_id uuid NOT NULL,
  acceptance_kind text NOT NULL CHECK (acceptance_kind IN ('first_business_commit', 'duplicate_business_anchor')),
  accepted_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  version bigint NOT NULL DEFAULT 1 CHECK (version >= 1),
  PRIMARY KEY (integration_id, ordering_domain_id, ordering_key_sha256, ordering_sequence),
  FOREIGN KEY (integration_id, ordering_domain_id, ordering_key_sha256)
    REFERENCES rc.order_heads(integration_id, ordering_domain_id, ordering_key_sha256),
  FOREIGN KEY (integration_id, consumer_event_key_sha256, original_facts_sha256)
    REFERENCES rc.inbox(integration_id, consumer_event_key_sha256, original_facts_sha256),
  FOREIGN KEY (receipt_id, integration_id, consumer_event_key_sha256, original_facts_sha256)
    REFERENCES rc.receipts(id, integration_id, consumer_event_key_sha256, original_facts_sha256)
);

CREATE TABLE IF NOT EXISTS rc.order_dispositions (
  id uuid PRIMARY KEY,
  integration_id uuid NOT NULL,
  ordering_domain_id uuid NOT NULL,
  ordering_key_sha256 bytea NOT NULL CHECK (pg_catalog.octet_length(ordering_key_sha256) = 32),
  prior_sequence bigint NOT NULL CHECK (prior_sequence >= 1),
  resulting_sequence bigint NOT NULL CHECK (resulting_sequence = prior_sequence + 1),
  source_sender_disposition_id uuid NULL,
  reason_code text NOT NULL CHECK (pg_catalog.length(reason_code) BETWEEN 1 AND 128),
  operator_reference text NOT NULL CHECK (pg_catalog.octet_length(operator_reference) BETWEEN 1 AND 256),
  accepted_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  version bigint NOT NULL DEFAULT 1 CHECK (version >= 1),
  FOREIGN KEY (integration_id, ordering_domain_id, ordering_key_sha256)
    REFERENCES rc.order_heads(integration_id, ordering_domain_id, ordering_key_sha256)
);

CREATE TABLE IF NOT EXISTS rc.trace_references (
  id uuid PRIMARY KEY,
  integration_id uuid NOT NULL REFERENCES rc.integrations(id),
  resource_kind text NOT NULL CHECK (resource_kind IN ('inbox', 'business_mutation', 'receipt', 'order_acceptance', 'order_disposition')),
  resource_id uuid NOT NULL,
  trace_id text NOT NULL CHECK (trace_id ~ '^[0-9a-f]{32}$' AND trace_id <> '00000000000000000000000000000000'),
  span_id text NOT NULL CHECK (span_id ~ '^[0-9a-f]{16}$' AND span_id <> '0000000000000000'),
  trace_flags integer NOT NULL CHECK (trace_flags BETWEEN 0 AND 255),
  tracestate text NULL CHECK (tracestate IS NULL OR pg_catalog.octet_length(tracestate) <= 256),
  recorded_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp()
);
