-- Migration 0005: Broker stream generations, publication observations, transport rejections, broker inbox, canonical fanout, and recovery episodes.

CREATE TABLE IF NOT EXISTS rq.broker_stream_generations (
  id uuid PRIMARY KEY,
  deployment_reference text NOT NULL CHECK (pg_catalog.octet_length(deployment_reference) BETWEEN 1 AND 256),
  cluster_reference text NOT NULL CHECK (pg_catalog.octet_length(cluster_reference) BETWEEN 1 AND 256),
  stream_name text NOT NULL CHECK (stream_name = 'RELAYQUILL_EVENTS_V1'),
  observed_stream_created_at timestamptz NOT NULL,
  configuration_sha256 bytea NOT NULL CHECK (pg_catalog.octet_length(configuration_sha256) = 32),
  state text NOT NULL CHECK (state IN ('prepared', 'active', 'quarantined', 'retired')),
  created_by_operator_reference text NOT NULL CHECK (pg_catalog.octet_length(created_by_operator_reference) BETWEEN 1 AND 256),
  recorded_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  version bigint NOT NULL DEFAULT 1 CHECK (version >= 1)
);

CREATE TABLE IF NOT EXISTS rq.publication_observations (
  id uuid PRIMARY KEY,
  outbox_id uuid NOT NULL,
  publication_generation bigint NOT NULL CHECK (publication_generation >= 1),
  broker_generation_id uuid NOT NULL REFERENCES rq.broker_stream_generations(id),
  stream_name text NOT NULL CHECK (stream_name = 'RELAYQUILL_EVENTS_V1'),
  stream_sequence bigint NOT NULL CHECK (stream_sequence >= 1),
  ack_duplicate boolean NOT NULL,
  observed_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  source_instance_id uuid NOT NULL REFERENCES rq.runtime_instances(id),
  local_claim_generation bigint NOT NULL CHECK (local_claim_generation >= 1),
  accepted_as_current boolean NOT NULL,
  FOREIGN KEY (outbox_id, publication_generation) REFERENCES rq.outbox_publications(outbox_id, publication_generation)
);

CREATE TABLE IF NOT EXISTS rq.transport_rejections (
  id uuid PRIMARY KEY,
  broker_generation_id uuid NOT NULL REFERENCES rq.broker_stream_generations(id),
  stream_sequence bigint NOT NULL CHECK (stream_sequence >= 1),
  envelope_sha256 bytea NOT NULL CHECK (pg_catalog.octet_length(envelope_sha256) = 32),
  reason_code text NOT NULL CHECK (pg_catalog.length(reason_code) BETWEEN 1 AND 128),
  observed_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  source_instance_id uuid NOT NULL REFERENCES rq.runtime_instances(id),
  resolution_state text NOT NULL CHECK (resolution_state IN ('recorded', 'review_required', 'resolved')),
  UNIQUE (broker_generation_id, stream_sequence, envelope_sha256, reason_code)
);

CREATE TABLE IF NOT EXISTS rq.broker_inbox (
  id uuid PRIMARY KEY,
  outbox_id uuid NOT NULL,
  publication_generation bigint NOT NULL CHECK (publication_generation >= 1),
  event_id uuid NOT NULL,
  tenant_id uuid NOT NULL,
  project_id uuid NOT NULL,
  envelope_sha256 bytea NOT NULL CHECK (pg_catalog.octet_length(envelope_sha256) = 32),
  first_broker_generation_id uuid NOT NULL REFERENCES rq.broker_stream_generations(id),
  first_stream_sequence bigint NOT NULL CHECK (first_stream_sequence >= 1),
  last_broker_generation_id uuid NOT NULL REFERENCES rq.broker_stream_generations(id),
  last_stream_sequence bigint NOT NULL CHECK (last_stream_sequence >= 1),
  receive_count bigint NOT NULL DEFAULT 1 CHECK (receive_count >= 1),
  state text NOT NULL CHECK (state IN ('received', 'materializing', 'completed', 'blocked')),
  first_received_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  last_received_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  completed_at timestamptz NULL,
  version bigint NOT NULL DEFAULT 1 CHECK (version >= 1),
  UNIQUE (outbox_id, publication_generation),
  FOREIGN KEY (outbox_id, event_id, project_id, tenant_id)
    REFERENCES rq.outbox_events(id, event_id, project_id, tenant_id),
  FOREIGN KEY (outbox_id, publication_generation, project_id, tenant_id, envelope_sha256)
    REFERENCES rq.outbox_publications(outbox_id, publication_generation, project_id, tenant_id, envelope_sha256),
  CHECK ((state = 'completed' AND completed_at IS NOT NULL) OR state <> 'completed')
);

CREATE TABLE IF NOT EXISTS rq.event_fanout (
  event_id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL,
  project_id uuid NOT NULL,
  topology_version bigint NOT NULL CHECK (topology_version >= 1),
  project_event_sequence bigint NOT NULL CHECK (project_event_sequence >= 1),
  state text NOT NULL CHECK (state IN ('pending', 'materializing', 'completed', 'blocked')),
  candidate_count bigint NOT NULL DEFAULT 0 CHECK (candidate_count >= 0),
  last_progress_at timestamptz NULL,
  subscription_cursor uuid NULL,
  examined_count bigint NOT NULL DEFAULT 0 CHECK (examined_count >= 0 AND examined_count <= candidate_count),
  matched_count bigint NOT NULL DEFAULT 0 CHECK (matched_count >= 0 AND matched_count <= examined_count),
  delivery_count bigint NOT NULL DEFAULT 0 CHECK (delivery_count >= 0 AND delivery_count <= matched_count),
  claim_owner_instance_id uuid NULL REFERENCES rq.runtime_instances(id),
  claim_control_epoch uuid NULL,
  claim_generation bigint NOT NULL DEFAULT 0 CHECK (claim_generation >= 0),
  claim_expires_at timestamptz NULL,
  completed_at timestamptz NULL,
  safe_error_code text NULL,
  version bigint NOT NULL DEFAULT 1 CHECK (version >= 1),
  UNIQUE (event_id, topology_version),
  FOREIGN KEY (event_id, project_id, tenant_id, topology_version, project_event_sequence)
    REFERENCES rq.events(id, project_id, tenant_id, topology_version, project_event_sequence),
  CHECK ((state = 'completed' AND examined_count = candidate_count AND completed_at IS NOT NULL) OR state <> 'completed'),
  CONSTRAINT chk_event_fanout_claim_state CHECK (
    (
      claim_owner_instance_id IS NOT NULL
      AND claim_control_epoch IS NOT NULL
      AND claim_expires_at IS NOT NULL
      AND claim_generation >= 1
    )
    OR (
      claim_owner_instance_id IS NULL
      AND claim_control_epoch IS NULL
      AND claim_expires_at IS NULL
    )
  )
);

CREATE TABLE IF NOT EXISTS rq.project_fanout_state (
  project_id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL,
  materialized_through_event_sequence bigint NOT NULL DEFAULT 0 CHECK (materialized_through_event_sequence >= 0),
  active_event_id uuid NULL REFERENCES rq.event_fanout(event_id),
  last_progress_at timestamptz NULL,
  version bigint NOT NULL DEFAULT 1 CHECK (version >= 1),
  FOREIGN KEY (project_id, tenant_id) REFERENCES rq.projects(id, tenant_id)
);

CREATE TABLE IF NOT EXISTS rq.fanout_outcomes (
  event_id uuid NOT NULL,
  subscription_id uuid NOT NULL,
  subscription_version bigint NOT NULL CHECK (subscription_version >= 1),
  tenant_id uuid NOT NULL,
  project_id uuid NOT NULL,
  outcome text NOT NULL CHECK (outcome IN ('matched', 'filtered_out', 'schema_not_selected', 'explicitly_suppressed')),
  filter_profile_version text NOT NULL DEFAULT 'relayquill.filter.v1' CHECK (filter_profile_version = 'relayquill.filter.v1'),
  filter_sha256 bytea NULL CHECK (filter_sha256 IS NULL OR pg_catalog.octet_length(filter_sha256) = 32),
  delivery_id uuid NULL,
  recorded_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  safe_reason_code text NULL,
  PRIMARY KEY (event_id, subscription_id, subscription_version),
  FOREIGN KEY (event_id, project_id, tenant_id) REFERENCES rq.events(id, project_id, tenant_id),
  FOREIGN KEY (subscription_id, subscription_version, project_id, tenant_id)
    REFERENCES rq.subscription_versions(subscription_id, subscription_version, project_id, tenant_id),
  CHECK ((outcome = 'matched' AND delivery_id IS NOT NULL) OR (outcome <> 'matched' AND delivery_id IS NULL))
);

CREATE TABLE IF NOT EXISTS rq.publication_recovery_episodes (
  id uuid PRIMARY KEY,
  outbox_id uuid NOT NULL REFERENCES rq.outbox_events(id),
  event_id uuid NOT NULL REFERENCES rq.events(id),
  control_epoch uuid NOT NULL,
  state text NOT NULL CHECK (state IN ('active', 'completed', 'review_required', 'revoked')),
  starting_fanout_version bigint NOT NULL CHECK (starting_fanout_version >= 1),
  last_progress_boundary_sha256 bytea NOT NULL CHECK (pg_catalog.octet_length(last_progress_boundary_sha256) = 32),
  successive_no_progress_generations integer NOT NULL DEFAULT 0 CHECK (successive_no_progress_generations BETWEEN 0 AND 100),
  last_generation_at timestamptz NULL,
  review_reference uuid NULL,
  created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  version bigint NOT NULL DEFAULT 1 CHECK (version >= 1)
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_publication_recovery_episodes_active
  ON rq.publication_recovery_episodes (outbox_id)
  WHERE state = 'active';
