-- Migration 0004: Accepted event payloads, immutable events, wire envelopes, business anchors, command receipts, outbox, and event history.

CREATE SEQUENCE IF NOT EXISTS rq.event_history_seq
  AS bigint
  START WITH 1
  INCREMENT BY 1
  NO CYCLE;

CREATE TABLE IF NOT EXISTS rq.event_payloads (
  id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL,
  project_id uuid NOT NULL,
  content bytea NULL,
  content_sha256 bytea NOT NULL CHECK (pg_catalog.octet_length(content_sha256) = 32),
  byte_count integer NOT NULL CHECK (byte_count BETWEEN 1 AND 262144),
  media_type text NOT NULL DEFAULT 'application/json' CHECK (media_type = 'application/json'),
  created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  retention_state text NOT NULL CHECK (retention_state IN ('required', 'release_eligible', 'expired', 'held')),
  retention_expires_at timestamptz NULL,
  expired_at timestamptz NULL,
  retention_action_id uuid NULL,
  FOREIGN KEY (project_id, tenant_id) REFERENCES rq.projects(id, tenant_id),
  UNIQUE (id, project_id, tenant_id),
  UNIQUE (id, project_id, tenant_id, content_sha256, byte_count),
  CONSTRAINT chk_event_payloads_retention_tombstone CHECK (
    (
      retention_state = 'expired'
      AND content IS NULL
      AND expired_at IS NOT NULL
      AND retention_action_id IS NOT NULL
    )
    OR (
      retention_state IN ('required', 'release_eligible', 'held')
      AND content IS NOT NULL
      AND pg_catalog.octet_length(content) = byte_count
      AND expired_at IS NULL
    )
  )
);

CREATE TABLE IF NOT EXISTS rq.events (
  id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL,
  project_id uuid NOT NULL,
  producer_id uuid NOT NULL,
  producer_namespace text NOT NULL,
  business_key text NOT NULL CHECK (pg_catalog.octet_length(business_key) BETWEEN 1 AND 128),
  event_type_id uuid NOT NULL,
  event_schema_version integer NOT NULL CHECK (event_schema_version >= 1),
  submitted_shape_sha256 bytea NOT NULL CHECK (pg_catalog.octet_length(submitted_shape_sha256) = 32),
  effective_request_sha256 bytea NOT NULL CHECK (pg_catalog.octet_length(effective_request_sha256) = 32),
  hash_schema_version integer NOT NULL DEFAULT 1 CHECK (hash_schema_version = 1),
  content_sha256 bytea NOT NULL CHECK (pg_catalog.octet_length(content_sha256) = 32),
  content_byte_count integer NOT NULL CHECK (content_byte_count BETWEEN 1 AND 262144),
  content_payload_id uuid NOT NULL,
  topology_version bigint NOT NULL CHECK (topology_version >= 1),
  project_event_sequence bigint NOT NULL CHECK (project_event_sequence >= 1),
  state text NOT NULL CHECK (state IN ('accepted', 'fanout_in_progress', 'fanout_complete', 'fanout_blocked', 'retired')),
  blocking_reason text NULL,
  producer_event_time timestamptz NULL,
  admitted_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  delivery_deadline_at timestamptz NOT NULL,
  retired_at timestamptz NULL,
  next_history_sequence bigint NOT NULL DEFAULT 0 CHECK (next_history_sequence >= 0),
  version bigint NOT NULL DEFAULT 1 CHECK (version >= 1),
  FOREIGN KEY (project_id, tenant_id) REFERENCES rq.projects(id, tenant_id),
  FOREIGN KEY (producer_id, project_id, tenant_id, producer_namespace)
    REFERENCES rq.producers(id, project_id, tenant_id, business_namespace),
  FOREIGN KEY (event_type_id, event_schema_version, project_id, tenant_id)
    REFERENCES rq.event_schema_versions(event_type_id, schema_version, project_id, tenant_id),
  FOREIGN KEY (content_payload_id, project_id, tenant_id, content_sha256, content_byte_count)
    REFERENCES rq.event_payloads(id, project_id, tenant_id, content_sha256, byte_count),
  UNIQUE (id, project_id, tenant_id),
  UNIQUE (id, project_id, tenant_id, topology_version),
  UNIQUE (id, project_id, tenant_id, topology_version, project_event_sequence),
  UNIQUE (id, project_id, tenant_id, content_sha256),
  UNIQUE (project_id, producer_namespace, business_key),
  UNIQUE (project_id, project_event_sequence),
  CHECK (delivery_deadline_at > admitted_at AND delivery_deadline_at <= admitted_at + interval '7 days'),
  CHECK ((state = 'fanout_blocked' AND blocking_reason IS NOT NULL) OR state <> 'fanout_blocked'),
  CHECK ((state = 'retired' AND retired_at IS NOT NULL) OR (state <> 'retired' AND retired_at IS NULL))
);

CREATE TABLE IF NOT EXISTS rq.event_wire_envelopes (
  id uuid PRIMARY KEY,
  event_id uuid NOT NULL,
  tenant_id uuid NOT NULL,
  project_id uuid NOT NULL,
  representation_version integer NOT NULL CHECK (representation_version >= 1),
  profile_id uuid NULL,
  profile_version bigint NULL CHECK (profile_version IS NULL OR profile_version >= 1),
  target_schema_version integer NULL CHECK (target_schema_version IS NULL OR target_schema_version >= 1),
  source_content_sha256 bytea NOT NULL CHECK (pg_catalog.octet_length(source_content_sha256) = 32),
  body_bytes bytea NULL,
  body_sha256 bytea NOT NULL CHECK (pg_catalog.octet_length(body_sha256) = 32),
  byte_count integer NOT NULL CHECK (byte_count BETWEEN 1 AND 524288),
  created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  retention_state text NOT NULL CHECK (retention_state IN ('required', 'release_eligible', 'expired', 'held')),
  expired_at timestamptz NULL,
  retention_action_id uuid NULL,
  FOREIGN KEY (event_id, project_id, tenant_id, source_content_sha256)
    REFERENCES rq.events(id, project_id, tenant_id, content_sha256),
  UNIQUE (event_id, representation_version),
  UNIQUE (id, project_id, tenant_id),
  UNIQUE (id, event_id, project_id, tenant_id),
  CONSTRAINT chk_event_wire_envelopes_representation CHECK (
    (representation_version = 1 AND profile_id IS NULL AND profile_version IS NULL AND target_schema_version IS NULL)
    OR (representation_version >= 2 AND profile_id IS NOT NULL AND profile_version IS NOT NULL AND target_schema_version IS NOT NULL)
  ),
  CONSTRAINT chk_event_wire_envelopes_retention CHECK (
    (
      retention_state = 'expired'
      AND body_bytes IS NULL
      AND expired_at IS NOT NULL
      AND retention_action_id IS NOT NULL
    )
    OR (
      retention_state IN ('required', 'release_eligible', 'held')
      AND body_bytes IS NOT NULL
      AND pg_catalog.octet_length(body_bytes) = byte_count
      AND expired_at IS NULL
    )
  )
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_event_wire_envelopes_derived_profile
  ON rq.event_wire_envelopes (event_id, profile_id, profile_version)
  WHERE profile_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS rq.business_event_anchors (
  project_id uuid NOT NULL,
  producer_namespace text NOT NULL CHECK (pg_catalog.octet_length(producer_namespace) BETWEEN 1 AND 128),
  business_key_sha256 bytea NOT NULL CHECK (pg_catalog.octet_length(business_key_sha256) = 32),
  event_id uuid NOT NULL UNIQUE,
  tenant_id uuid NOT NULL,
  event_type_id uuid NOT NULL,
  event_schema_version integer NOT NULL CHECK (event_schema_version >= 1),
  submitted_shape_sha256 bytea NOT NULL CHECK (pg_catalog.octet_length(submitted_shape_sha256) = 32),
  effective_request_sha256 bytea NOT NULL CHECK (pg_catalog.octet_length(effective_request_sha256) = 32),
  hash_schema_version integer NOT NULL DEFAULT 1 CHECK (hash_schema_version = 1),
  applied_defaults jsonb NOT NULL DEFAULT '{}'::jsonb,
  original_project_sequence bigint NOT NULL CHECK (original_project_sequence >= 1),
  accepted_at timestamptz NOT NULL,
  retention_policy_version text NOT NULL CHECK (pg_catalog.length(retention_policy_version) BETWEEN 1 AND 128),
  PRIMARY KEY (project_id, producer_namespace, business_key_sha256),
  FOREIGN KEY (project_id, tenant_id) REFERENCES rq.projects(id, tenant_id),
  CHECK (pg_catalog.jsonb_typeof(applied_defaults) = 'object')
);

CREATE TABLE IF NOT EXISTS rq.command_receipts (
  id uuid PRIMARY KEY,
  scope_kind text NOT NULL CHECK (scope_kind IN ('installation', 'tenant', 'project')),
  tenant_id uuid NULL REFERENCES rq.tenants(id),
  project_id uuid NULL,
  actor_principal_id uuid NOT NULL REFERENCES rq.principals(id),
  command_family text NOT NULL CHECK (pg_catalog.length(command_family) BETWEEN 1 AND 128),
  key_sha256 bytea NOT NULL CHECK (pg_catalog.octet_length(key_sha256) = 32),
  submitted_shape_sha256 bytea NOT NULL CHECK (pg_catalog.octet_length(submitted_shape_sha256) = 32),
  effective_request_sha256 bytea NOT NULL CHECK (pg_catalog.octet_length(effective_request_sha256) = 32),
  resource_kind text NOT NULL CHECK (pg_catalog.length(resource_kind) BETWEEN 1 AND 64),
  resource_id uuid NOT NULL,
  accepted_version bigint NULL CHECK (accepted_version IS NULL OR accepted_version >= 0),
  applied_defaults jsonb NOT NULL DEFAULT '{}'::jsonb,
  accepted_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  hash_schema_version integer NOT NULL DEFAULT 1 CHECK (hash_schema_version = 1),
  FOREIGN KEY (project_id, tenant_id) REFERENCES rq.projects(id, tenant_id),
  CONSTRAINT chk_command_receipts_scope_ancestry CHECK (
    (scope_kind = 'installation' AND tenant_id IS NULL AND project_id IS NULL)
    OR (scope_kind = 'tenant' AND tenant_id IS NOT NULL AND project_id IS NULL)
    OR (scope_kind = 'project' AND tenant_id IS NOT NULL AND project_id IS NOT NULL)
  ),
  CHECK (pg_catalog.jsonb_typeof(applied_defaults) = 'object')
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_command_receipts_installation
  ON rq.command_receipts (actor_principal_id, command_family, key_sha256)
  WHERE scope_kind = 'installation';

CREATE UNIQUE INDEX IF NOT EXISTS uq_command_receipts_tenant
  ON rq.command_receipts (tenant_id, actor_principal_id, command_family, key_sha256)
  WHERE scope_kind = 'tenant';

CREATE UNIQUE INDEX IF NOT EXISTS uq_command_receipts_project
  ON rq.command_receipts (project_id, actor_principal_id, command_family, key_sha256)
  WHERE scope_kind = 'project';

CREATE TABLE IF NOT EXISTS rq.outbox_events (
  id uuid PRIMARY KEY,
  event_id uuid NOT NULL UNIQUE,
  tenant_id uuid NOT NULL,
  project_id uuid NOT NULL,
  topology_version bigint NOT NULL CHECK (topology_version >= 1),
  state text NOT NULL CHECK (state IN ('pending', 'claimed', 'published', 'blocked', 'retired')),
  current_publication_generation bigint NOT NULL DEFAULT 1 CHECK (current_publication_generation >= 1),
  next_publish_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  claim_owner_instance_id uuid NULL REFERENCES rq.runtime_instances(id),
  claim_control_epoch uuid NULL,
  claim_generation bigint NOT NULL DEFAULT 0 CHECK (claim_generation >= 0),
  claim_expires_at timestamptz NULL,
  last_safe_error_code text NULL,
  created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  version bigint NOT NULL DEFAULT 1 CHECK (version >= 1),
  FOREIGN KEY (event_id, project_id, tenant_id, topology_version)
    REFERENCES rq.events(id, project_id, tenant_id, topology_version),
  UNIQUE (id, project_id, tenant_id),
  UNIQUE (id, event_id, project_id, tenant_id),
  CONSTRAINT chk_outbox_events_claim_state CHECK (
    (
      state = 'claimed'
      AND claim_owner_instance_id IS NOT NULL
      AND claim_control_epoch IS NOT NULL
      AND claim_expires_at IS NOT NULL
      AND claim_generation >= 1
    )
    OR (
      state <> 'claimed'
      AND claim_owner_instance_id IS NULL
      AND claim_control_epoch IS NULL
      AND claim_expires_at IS NULL
    )
  )
);

CREATE TABLE IF NOT EXISTS rq.outbox_publications (
  outbox_id uuid NOT NULL,
  publication_generation bigint NOT NULL CHECK (publication_generation >= 1),
  tenant_id uuid NOT NULL,
  project_id uuid NOT NULL,
  envelope_version integer NOT NULL DEFAULT 1 CHECK (envelope_version = 1),
  envelope_bytes bytea NOT NULL CHECK (pg_catalog.octet_length(envelope_bytes) BETWEEN 1 AND 4096),
  envelope_sha256 bytea NOT NULL CHECK (pg_catalog.octet_length(envelope_sha256) = 32),
  broker_message_id text NOT NULL UNIQUE CHECK (pg_catalog.length(broker_message_id) BETWEEN 1 AND 128),
  state text NOT NULL CHECK (state IN ('prepared', 'publish_unknown', 'ack_observed', 'recovery_superseded')),
  send_count integer NOT NULL DEFAULT 0 CHECK (send_count >= 0),
  created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  last_send_at timestamptz NULL,
  ack_observed_at timestamptz NULL,
  stream_name text NULL,
  stream_sequence bigint NULL CHECK (stream_sequence IS NULL OR stream_sequence >= 1),
  first_broker_generation_id uuid NULL,
  first_observation_id uuid NULL,
  safe_error_code text NULL,
  PRIMARY KEY (outbox_id, publication_generation),
  UNIQUE (outbox_id, publication_generation, project_id, tenant_id, envelope_sha256),
  FOREIGN KEY (outbox_id, project_id, tenant_id) REFERENCES rq.outbox_events(id, project_id, tenant_id)
);

CREATE TABLE IF NOT EXISTS rq.event_history (
  event_id uuid NOT NULL,
  event_sequence bigint NOT NULL DEFAULT pg_catalog.nextval('rq.event_history_seq') CHECK (event_sequence >= 1),
  tenant_id uuid NOT NULL,
  project_id uuid NOT NULL,
  event_kind text NOT NULL CHECK (pg_catalog.length(event_kind) BETWEEN 1 AND 128),
  event_schema_version integer NOT NULL CHECK (event_schema_version >= 1),
  recorded_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  safe_facts jsonb NOT NULL DEFAULT '{}'::jsonb,
  causing_command_id uuid NULL REFERENCES rq.command_receipts(id),
  source_instance_id uuid NULL REFERENCES rq.runtime_instances(id),
  PRIMARY KEY (event_id, event_sequence),
  FOREIGN KEY (event_id, project_id, tenant_id) REFERENCES rq.events(id, project_id, tenant_id),
  CHECK (pg_catalog.jsonb_typeof(safe_facts) = 'object')
);
