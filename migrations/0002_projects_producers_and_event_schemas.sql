-- Migration 0002: Tenants, projects, memberships, raw-data grants, producers, event types, schemas, and policy registry.

CREATE TABLE IF NOT EXISTS rq.tenants (
  id uuid PRIMARY KEY,
  slug text NOT NULL UNIQUE CHECK (pg_catalog.octet_length(slug) BETWEEN 3 AND 64 AND slug ~ '^[a-z][a-z0-9-]{1,62}[a-z0-9]$'),
  display_name text NOT NULL CHECK (pg_catalog.octet_length(display_name) BETWEEN 1 AND 256),
  state text NOT NULL CHECK (state IN ('provisioning', 'active', 'suspended', 'retired')),
  governance_version bigint NOT NULL DEFAULT 1 CHECK (governance_version >= 1),
  created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  version bigint NOT NULL DEFAULT 1 CHECK (version >= 1)
);

CREATE TABLE IF NOT EXISTS rq.projects (
  id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL REFERENCES rq.tenants(id),
  name text NOT NULL CHECK (pg_catalog.octet_length(name) BETWEEN 1 AND 128),
  state text NOT NULL CHECK (state IN ('provisioning', 'active', 'admission_paused', 'quarantined', 'retired')),
  topology_version bigint NOT NULL DEFAULT 1 CHECK (topology_version >= 1),
  next_event_sequence bigint NOT NULL DEFAULT 1 CHECK (next_event_sequence >= 1),
  governance_version bigint NOT NULL DEFAULT 1 CHECK (governance_version >= 1),
  active_ordering_cutover_plan_id uuid NULL,
  projection_maintenance_operation_id uuid NULL,
  projection_maintenance_version bigint NOT NULL DEFAULT 0 CHECK (projection_maintenance_version >= 0),
  created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  version bigint NOT NULL DEFAULT 1 CHECK (version >= 1),
  UNIQUE (id, tenant_id),
  UNIQUE (tenant_id, name)
);

CREATE TABLE IF NOT EXISTS rq.tenant_memberships (
  id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL REFERENCES rq.tenants(id),
  principal_id uuid NOT NULL REFERENCES rq.humans(principal_id),
  role text NOT NULL CHECK (role IN ('tenant_admin')),
  state text NOT NULL CHECK (state IN ('pending', 'active', 'suspended', 'revoked')),
  authority_version bigint NOT NULL DEFAULT 1 CHECK (authority_version >= 1),
  created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  version bigint NOT NULL DEFAULT 1 CHECK (version >= 1)
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_tenant_memberships_active
  ON rq.tenant_memberships (tenant_id, principal_id, role)
  WHERE state = 'active';

CREATE TABLE IF NOT EXISTS rq.project_memberships (
  id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL,
  project_id uuid NOT NULL,
  principal_id uuid NOT NULL REFERENCES rq.humans(principal_id),
  role text NOT NULL CHECK (role IN ('project_admin', 'integrator', 'operator', 'publisher', 'observer')),
  state text NOT NULL CHECK (state IN ('pending', 'active', 'suspended', 'revoked')),
  authority_version bigint NOT NULL DEFAULT 1 CHECK (authority_version >= 1),
  created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  version bigint NOT NULL DEFAULT 1 CHECK (version >= 1),
  FOREIGN KEY (project_id, tenant_id) REFERENCES rq.projects(id, tenant_id),
  UNIQUE (id, project_id, tenant_id)
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_project_memberships_active
  ON rq.project_memberships (project_id, principal_id, role)
  WHERE state = 'active';

CREATE TABLE IF NOT EXISTS rq.human_data_grants (
  id uuid PRIMARY KEY,
  membership_id uuid NOT NULL,
  tenant_id uuid NOT NULL,
  project_id uuid NOT NULL,
  action text NOT NULL CHECK (action IN ('events.content.read', 'deliveries.request.read', 'receiver_receipts.read')),
  projection text NOT NULL CHECK (projection IN ('own_namespace', 'approved_project')),
  producer_namespace text NULL CHECK (producer_namespace IS NULL OR pg_catalog.octet_length(producer_namespace) BETWEEN 1 AND 128),
  state text NOT NULL CHECK (state IN ('active', 'revoked')),
  expires_at timestamptz NULL,
  created_by uuid NOT NULL REFERENCES rq.humans(principal_id),
  created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  version bigint NOT NULL DEFAULT 1 CHECK (version >= 1),
  FOREIGN KEY (membership_id, project_id, tenant_id) REFERENCES rq.project_memberships(id, project_id, tenant_id),
  CONSTRAINT chk_human_data_grants_projection CHECK (
    (projection = 'own_namespace' AND producer_namespace IS NOT NULL)
    OR (projection = 'approved_project' AND producer_namespace IS NULL)
  )
);

CREATE TABLE IF NOT EXISTS rq.producers (
  id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL,
  project_id uuid NOT NULL,
  principal_id uuid NOT NULL,
  principal_kind text NOT NULL CHECK (principal_kind IN ('producer', 'human')),
  channel_kind text NOT NULL CHECK (channel_kind IN ('machine_producer', 'human_workflow')),
  name text NOT NULL CHECK (pg_catalog.octet_length(name) BETWEEN 1 AND 128),
  business_namespace text NOT NULL CHECK (pg_catalog.octet_length(business_namespace) BETWEEN 1 AND 128),
  state text NOT NULL CHECK (state IN ('pending', 'active', 'suspended', 'retired')),
  current_scope_version bigint NULL CHECK (current_scope_version IS NULL OR current_scope_version >= 1),
  authority_epoch bigint NOT NULL DEFAULT 1 CHECK (authority_epoch >= 1),
  created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  version bigint NOT NULL DEFAULT 1 CHECK (version >= 1),
  FOREIGN KEY (project_id, tenant_id) REFERENCES rq.projects(id, tenant_id),
  FOREIGN KEY (principal_id, principal_kind) REFERENCES rq.principals(id, kind),
  UNIQUE (id, project_id, tenant_id),
  UNIQUE (id, project_id, tenant_id, channel_kind),
  UNIQUE (id, project_id, tenant_id, principal_id, channel_kind),
  UNIQUE (id, project_id, tenant_id, business_namespace),
  UNIQUE (project_id, business_namespace),
  UNIQUE (project_id, channel_kind, principal_id),
  CONSTRAINT chk_producers_channel_principal_namespace CHECK (
    (
      channel_kind = 'machine_producer'
      AND principal_kind = 'producer'
      AND business_namespace ~ '^[a-z][a-z0-9._-]{0,63}$'
      AND business_namespace NOT LIKE 'human.%'
    )
    OR (
      channel_kind = 'human_workflow'
      AND principal_kind = 'human'
      AND business_namespace = ('human.' || principal_id::text)
    )
  )
);

CREATE TABLE IF NOT EXISTS rq.producer_scope_versions (
  producer_id uuid NOT NULL,
  scope_version bigint NOT NULL CHECK (scope_version >= 1),
  tenant_id uuid NOT NULL,
  project_id uuid NOT NULL,
  scope_definition jsonb NOT NULL,
  scope_sha256 bytea NOT NULL CHECK (pg_catalog.octet_length(scope_sha256) = 32),
  state text NOT NULL CHECK (state IN ('draft', 'approved', 'active', 'retired')),
  published_by uuid NULL REFERENCES rq.humans(principal_id),
  created_by uuid NOT NULL REFERENCES rq.humans(principal_id),
  created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  activated_at timestamptz NULL,
  PRIMARY KEY (producer_id, scope_version),
  UNIQUE (producer_id, scope_version, project_id, tenant_id, scope_sha256),
  FOREIGN KEY (producer_id, project_id, tenant_id) REFERENCES rq.producers(id, project_id, tenant_id),
  CHECK (pg_catalog.jsonb_typeof(scope_definition) = 'object')
);

CREATE TABLE IF NOT EXISTS rq.producer_credential_intents (
  id uuid PRIMARY KEY,
  producer_id uuid NOT NULL,
  tenant_id uuid NOT NULL,
  project_id uuid NOT NULL,
  channel_kind text NOT NULL DEFAULT 'machine_producer' CHECK (channel_kind = 'machine_producer'),
  control_epoch uuid NOT NULL,
  scope_version bigint NOT NULL CHECK (scope_version >= 1),
  scope_sha256 bytea NOT NULL CHECK (pg_catalog.octet_length(scope_sha256) = 32),
  requested_expiry timestamptz NOT NULL,
  custody_destination_reference text NOT NULL CHECK (pg_catalog.octet_length(custody_destination_reference) BETWEEN 1 AND 256),
  state text NOT NULL CHECK (state IN ('requested', 'approved', 'delivering', 'delivery_unknown', 'delivered', 'activated', 'revoked', 'expired', 'failed_reissue_required')),
  credential_id uuid NULL,
  issuer_principal_id uuid NOT NULL REFERENCES rq.humans(principal_id),
  created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  expires_at timestamptz NOT NULL,
  version bigint NOT NULL DEFAULT 1 CHECK (version >= 1),
  FOREIGN KEY (producer_id, project_id, tenant_id, channel_kind) REFERENCES rq.producers(id, project_id, tenant_id, channel_kind),
  FOREIGN KEY (producer_id, scope_version, project_id, tenant_id, scope_sha256) REFERENCES rq.producer_scope_versions(producer_id, scope_version, project_id, tenant_id, scope_sha256),
  CHECK (expires_at > created_at AND requested_expiry > created_at)
);

CREATE TABLE IF NOT EXISTS rq.producer_credentials (
  id uuid PRIMARY KEY,
  producer_id uuid NOT NULL,
  tenant_id uuid NOT NULL,
  project_id uuid NOT NULL,
  principal_id uuid NOT NULL,
  channel_kind text NOT NULL DEFAULT 'machine_producer' CHECK (channel_kind = 'machine_producer'),
  control_epoch uuid NOT NULL,
  secret_digest bytea NOT NULL CHECK (pg_catalog.octet_length(secret_digest) = 32),
  state text NOT NULL CHECK (state IN ('pending_activation', 'active', 'overlap', 'revoked', 'expired')),
  scope_version bigint NOT NULL CHECK (scope_version >= 1),
  owner_authority_epoch bigint NOT NULL CHECK (owner_authority_epoch >= 1),
  issued_by uuid NOT NULL REFERENCES rq.humans(principal_id),
  intent_id uuid NOT NULL UNIQUE REFERENCES rq.producer_credential_intents(id),
  created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  expires_at timestamptz NOT NULL,
  activated_at timestamptz NULL,
  revoked_at timestamptz NULL,
  version bigint NOT NULL DEFAULT 1 CHECK (version >= 1),
  FOREIGN KEY (producer_id, project_id, tenant_id, principal_id, channel_kind) REFERENCES rq.producers(id, project_id, tenant_id, principal_id, channel_kind),
  FOREIGN KEY (producer_id, scope_version) REFERENCES rq.producer_scope_versions(producer_id, scope_version),
  CHECK (expires_at > created_at AND expires_at <= created_at + interval '30 days')
);

CREATE TABLE IF NOT EXISTS rq.event_types (
  id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL,
  project_id uuid NOT NULL,
  type_name text NOT NULL CHECK (
    pg_catalog.octet_length(type_name) <= 128
    AND type_name ~ '^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*){0,7}$'
  ),
  state text NOT NULL CHECK (state IN ('draft', 'active', 'retired')),
  current_schema_version integer NULL CHECK (current_schema_version IS NULL OR current_schema_version >= 1),
  created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  version bigint NOT NULL DEFAULT 1 CHECK (version >= 1),
  FOREIGN KEY (project_id, tenant_id) REFERENCES rq.projects(id, tenant_id),
  UNIQUE (id, project_id, tenant_id),
  UNIQUE (project_id, type_name)
);

CREATE TABLE IF NOT EXISTS rq.event_schema_versions (
  event_type_id uuid NOT NULL,
  schema_version integer NOT NULL CHECK (schema_version >= 1),
  tenant_id uuid NOT NULL,
  project_id uuid NOT NULL,
  dialect text NOT NULL CHECK (dialect = 'https://json-schema.org/draft/2020-12/schema'),
  profile_version text NOT NULL CHECK (profile_version = 'relayquill.event-schema.v1'),
  definition_bytes bytea NOT NULL CHECK (pg_catalog.octet_length(definition_bytes) BETWEEN 2 AND 65536),
  definition_sha256 bytea NOT NULL CHECK (pg_catalog.octet_length(definition_sha256) = 32),
  normalized_profile jsonb NOT NULL,
  compatibility_policy text NOT NULL CHECK (compatibility_policy IN ('additive_compatible', 'new_breaking_version')),
  state text NOT NULL CHECK (state IN ('draft', 'published', 'retired')),
  created_by uuid NOT NULL REFERENCES rq.humans(principal_id),
  published_by uuid NULL REFERENCES rq.humans(principal_id),
  created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  published_at timestamptz NULL,
  PRIMARY KEY (event_type_id, schema_version),
  UNIQUE (event_type_id, schema_version, project_id, tenant_id),
  FOREIGN KEY (event_type_id, project_id, tenant_id) REFERENCES rq.event_types(id, project_id, tenant_id),
  CHECK (pg_catalog.jsonb_typeof(normalized_profile) = 'object')
);

CREATE TABLE IF NOT EXISTS rq.policy_versions (
  policy_kind text NOT NULL CHECK (policy_kind IN ('admission', 'response', 'retry', 'circuit', 'url', 'network', 'request', 'retention', 'rate', 'dispatch')),
  policy_version text NOT NULL CHECK (pg_catalog.length(policy_version) BETWEEN 1 AND 128),
  definition_bytes bytea NOT NULL CHECK (pg_catalog.octet_length(definition_bytes) BETWEEN 2 AND 65536),
  definition_sha256 bytea NOT NULL CHECK (pg_catalog.octet_length(definition_sha256) = 32),
  normalized_definition jsonb NOT NULL,
  state text NOT NULL CHECK (state IN ('draft', 'active', 'retired')),
  created_by uuid NULL REFERENCES rq.humans(principal_id),
  created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  activated_at timestamptz NULL,
  PRIMARY KEY (policy_kind, policy_version),
  UNIQUE (policy_kind, policy_version, definition_sha256),
  CHECK (pg_catalog.jsonb_typeof(normalized_definition) = 'object')
);
