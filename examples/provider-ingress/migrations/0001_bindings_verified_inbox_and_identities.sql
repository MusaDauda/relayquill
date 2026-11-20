-- Provider Ingress Migration 0001: Independent provider roles, pi schema, bindings, binding versions, observations, and deduplication identities.

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

  FOREACH v_role IN ARRAY ARRAY['provider_owner', 'provider_migrator', 'provider_runtime'] LOOP
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = v_role) THEN
      v_missing_roles := pg_catalog.array_append(v_missing_roles, v_role);
    END IF;
  END LOOP;

  IF COALESCE(pg_catalog.array_length(v_missing_roles, 1), 0) > 0 THEN
    IF NOT v_can_create_role THEN
      RAISE EXCEPTION 'Required provider-ingress database roles missing (%) and current user "%" lacks CREATEROLE privilege',
        pg_catalog.array_to_string(v_missing_roles, ', '),
        current_user;
    END IF;

    FOREACH v_role IN ARRAY v_missing_roles LOOP
      IF v_role = 'provider_owner' THEN
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
    SELECT pg_catalog.pg_has_role('provider_migrator', 'provider_owner', 'MEMBER') INTO v_owner_is_member;
    IF NOT v_owner_is_member THEN
      EXECUTE 'GRANT provider_owner TO provider_migrator';
    END IF;
  END IF;
END
$$;

CREATE SCHEMA IF NOT EXISTS pi;

DO $$
DECLARE
  v_is_super boolean := false;
BEGIN
  SELECT r.rolsuper INTO v_is_super FROM pg_catalog.pg_roles r WHERE r.rolname = current_user;
  IF v_is_super THEN
    EXECUTE 'ALTER SCHEMA pi OWNER TO provider_owner';
  END IF;
END
$$;

CREATE TABLE IF NOT EXISTS pi.schema_migrations (
  migration_id text PRIMARY KEY CHECK (pg_catalog.length(migration_id) BETWEEN 1 AND 128),
  checksum bytea NOT NULL CHECK (pg_catalog.octet_length(checksum) = 32),
  applied_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  source_reference text NOT NULL CHECK (pg_catalog.length(source_reference) BETWEEN 1 AND 256),
  runner_version text NOT NULL CHECK (pg_catalog.length(runner_version) BETWEEN 1 AND 128)
);

CREATE TABLE IF NOT EXISTS pi.bindings (
  id uuid PRIMARY KEY,
  provider text NOT NULL CHECK (provider IN ('stripe', 'paystack')),
  account_reference text NOT NULL CHECK (pg_catalog.octet_length(account_reference) BETWEEN 1 AND 256),
  account_mode text NOT NULL CHECK (account_mode IN ('test', 'live')),
  payload_profile text NOT NULL CHECK (pg_catalog.length(payload_profile) BETWEEN 1 AND 128),
  secret_custody_reference text NOT NULL CHECK (pg_catalog.octet_length(secret_custody_reference) BETWEEN 1 AND 256),
  secret_version_reference text NOT NULL CHECK (pg_catalog.octet_length(secret_version_reference) BETWEEN 1 AND 256),
  state text NOT NULL CHECK (state IN ('draft', 'active', 'paused', 'retired', 'revoked')),
  relay_tenant_id uuid NOT NULL,
  relay_project_id uuid NOT NULL,
  publication_channel_id uuid NOT NULL,
  normalized_event_type_id uuid NOT NULL,
  normalized_schema_version integer NOT NULL CHECK (normalized_schema_version >= 1),
  configuration_sha256 bytea NOT NULL CHECK (pg_catalog.octet_length(configuration_sha256) = 32),
  current_binding_version bigint NULL CHECK (current_binding_version IS NULL OR current_binding_version >= 1),
  created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  version bigint NOT NULL DEFAULT 1 CHECK (version >= 1)
);

CREATE TABLE IF NOT EXISTS pi.binding_versions (
  binding_id uuid NOT NULL REFERENCES pi.bindings(id),
  binding_version bigint NOT NULL CHECK (binding_version >= 1),
  provider text NOT NULL CHECK (provider IN ('stripe', 'paystack')),
  account_reference text NOT NULL CHECK (pg_catalog.octet_length(account_reference) BETWEEN 1 AND 256),
  account_mode text NOT NULL CHECK (account_mode IN ('test', 'live')),
  payload_profile text NOT NULL CHECK (pg_catalog.length(payload_profile) BETWEEN 1 AND 128),
  secret_custody_reference text NOT NULL CHECK (pg_catalog.octet_length(secret_custody_reference) BETWEEN 1 AND 256),
  secret_version_reference text NOT NULL CHECK (pg_catalog.octet_length(secret_version_reference) BETWEEN 1 AND 256),
  relay_tenant_id uuid NOT NULL,
  relay_project_id uuid NOT NULL,
  publication_channel_id uuid NOT NULL,
  normalized_event_type_id uuid NOT NULL,
  normalized_schema_version integer NOT NULL CHECK (normalized_schema_version >= 1),
  configuration_sha256 bytea NOT NULL CHECK (pg_catalog.octet_length(configuration_sha256) = 32),
  created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  state text NOT NULL CHECK (state IN ('draft', 'active', 'retired', 'revoked')),
  PRIMARY KEY (binding_id, binding_version),
  UNIQUE (binding_id, binding_version, provider, account_mode, payload_profile)
);

CREATE TABLE IF NOT EXISTS pi.observations (
  id uuid PRIMARY KEY,
  binding_id uuid NOT NULL,
  binding_version bigint NOT NULL CHECK (binding_version >= 1),
  provider text NOT NULL CHECK (provider IN ('stripe', 'paystack')),
  account_mode text NOT NULL CHECK (account_mode IN ('test', 'live')),
  payload_profile text NOT NULL CHECK (pg_catalog.length(payload_profile) BETWEEN 1 AND 128),
  provider_event_id text NULL CHECK (provider_event_id IS NULL OR pg_catalog.octet_length(provider_event_id) BETWEEN 1 AND 256),
  event_type text NOT NULL CHECK (pg_catalog.length(event_type) BETWEEN 1 AND 128),
  object_reference text NULL CHECK (object_reference IS NULL OR pg_catalog.octet_length(object_reference) BETWEEN 1 AND 256),
  provider_business_time timestamptz NULL,
  raw_body_sha256 bytea NOT NULL CHECK (pg_catalog.octet_length(raw_body_sha256) = 32),
  normalized_facts jsonb NOT NULL,
  normalized_facts_sha256 bytea NOT NULL CHECK (pg_catalog.octet_length(normalized_facts_sha256) = 32),
  state text NOT NULL CHECK (state IN ('accepted', 'forward_pending', 'forwarded', 'quarantined', 'retired')),
  received_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  version bigint NOT NULL DEFAULT 1 CHECK (version >= 1),
  UNIQUE (id, binding_id, binding_version),
  FOREIGN KEY (binding_id, binding_version, provider, account_mode, payload_profile)
    REFERENCES pi.binding_versions(binding_id, binding_version, provider, account_mode, payload_profile),
  CHECK (pg_catalog.jsonb_typeof(normalized_facts) = 'object')
);

CREATE TABLE IF NOT EXISTS pi.transport_receipts (
  binding_id uuid NOT NULL REFERENCES pi.bindings(id),
  raw_body_sha256 bytea NOT NULL CHECK (pg_catalog.octet_length(raw_body_sha256) = 32),
  observation_id uuid NOT NULL REFERENCES pi.observations(id),
  first_received_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  last_received_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  receive_count bigint NOT NULL DEFAULT 1 CHECK (receive_count >= 1),
  version bigint NOT NULL DEFAULT 1 CHECK (version >= 1),
  PRIMARY KEY (binding_id, raw_body_sha256)
);

CREATE TABLE IF NOT EXISTS pi.semantic_identities (
  binding_id uuid NOT NULL REFERENCES pi.bindings(id),
  identity_profile text NOT NULL CHECK (pg_catalog.length(identity_profile) BETWEEN 1 AND 128),
  semantic_key_sha256 bytea NOT NULL CHECK (pg_catalog.octet_length(semantic_key_sha256) = 32),
  normalized_facts_sha256 bytea NOT NULL CHECK (pg_catalog.octet_length(normalized_facts_sha256) = 32),
  observation_id uuid NOT NULL REFERENCES pi.observations(id),
  created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  version bigint NOT NULL DEFAULT 1 CHECK (version >= 1),
  PRIMARY KEY (binding_id, identity_profile, semantic_key_sha256)
);
