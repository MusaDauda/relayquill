-- Migration 0007: WDRR dispatch state, rate/ordering controls, representations, receiver contracts, replay/suppression, watch leases, retention, coordinator tasks, and sharded projection deltas.

CREATE TABLE IF NOT EXISTS rq.dispatch_domains (
  id uuid PRIMARY KEY,
  name text NOT NULL UNIQUE CHECK (pg_catalog.octet_length(name) BETWEEN 1 AND 128),
  state text NOT NULL CHECK (state IN ('active', 'draining', 'retired')),
  policy_kind text NOT NULL DEFAULT 'dispatch' CHECK (policy_kind = 'dispatch'),
  policy_version text NOT NULL DEFAULT 'dispatch_v1',
  policy_sha256 bytea NOT NULL CHECK (pg_catalog.octet_length(policy_sha256) = 32),
  created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  version bigint NOT NULL DEFAULT 1 CHECK (version >= 1),
  FOREIGN KEY (policy_kind, policy_version) REFERENCES rq.policy_versions(policy_kind, policy_version)
);

CREATE TABLE IF NOT EXISTS rq.project_dispatch_memberships (
  project_id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL,
  dispatch_domain_id uuid NOT NULL REFERENCES rq.dispatch_domains(id),
  state text NOT NULL CHECK (state IN ('active', 'draining', 'removed')),
  policy_version text NOT NULL DEFAULT 'dispatch_v1' CHECK (pg_catalog.length(policy_version) BETWEEN 1 AND 128),
  created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  version bigint NOT NULL DEFAULT 1 CHECK (version >= 1),
  FOREIGN KEY (project_id, tenant_id) REFERENCES rq.projects(id, tenant_id),
  UNIQUE (dispatch_domain_id, project_id, tenant_id)
);

CREATE TABLE IF NOT EXISTS rq.dispatch_state (
  dispatch_domain_id uuid PRIMARY KEY REFERENCES rq.dispatch_domains(id),
  policy_epoch bigint NOT NULL DEFAULT 1 CHECK (policy_epoch >= 1),
  round_number bigint NOT NULL DEFAULT 1 CHECK (round_number >= 1),
  tenant_cursor uuid NULL,
  last_progress_at timestamptz NULL,
  scan_cursor uuid NULL,
  version bigint NOT NULL DEFAULT 1 CHECK (version >= 1)
);

CREATE TABLE IF NOT EXISTS rq.tenant_dispatch_state (
  dispatch_domain_id uuid NOT NULL REFERENCES rq.dispatch_domains(id),
  tenant_id uuid NOT NULL REFERENCES rq.tenants(id),
  weight integer NOT NULL DEFAULT 1 CHECK (weight BETWEEN 1 AND 100),
  deficit_units integer NOT NULL DEFAULT 0 CHECK (deficit_units BETWEEN 0 AND 1000),
  last_credited_policy_epoch bigint NOT NULL DEFAULT 0 CHECK (last_credited_policy_epoch >= 0),
  last_credited_round bigint NOT NULL DEFAULT 0 CHECK (last_credited_round >= 0),
  project_cursor uuid NULL,
  project_round bigint NOT NULL DEFAULT 1 CHECK (project_round >= 1),
  project_scan_after_id uuid NULL,
  project_round_start_id uuid NULL,
  last_served_at timestamptz NULL,
  version bigint NOT NULL DEFAULT 1 CHECK (version >= 1),
  PRIMARY KEY (dispatch_domain_id, tenant_id)
);

CREATE TABLE IF NOT EXISTS rq.project_dispatch_state (
  dispatch_domain_id uuid NOT NULL,
  project_id uuid NOT NULL,
  tenant_id uuid NOT NULL,
  weight integer NOT NULL DEFAULT 1 CHECK (weight BETWEEN 1 AND 100),
  deficit_units integer NOT NULL DEFAULT 0 CHECK (deficit_units BETWEEN 0 AND 1000),
  last_credited_policy_epoch bigint NOT NULL DEFAULT 0 CHECK (last_credited_policy_epoch >= 0),
  last_credited_round bigint NOT NULL DEFAULT 0 CHECK (last_credited_round >= 0),
  endpoint_cursor uuid NULL,
  endpoint_round bigint NOT NULL DEFAULT 1 CHECK (endpoint_round >= 1),
  endpoint_scan_after_id uuid NULL,
  endpoint_round_start_id uuid NULL,
  last_served_at timestamptz NULL,
  version bigint NOT NULL DEFAULT 1 CHECK (version >= 1),
  PRIMARY KEY (dispatch_domain_id, project_id),
  FOREIGN KEY (dispatch_domain_id, project_id, tenant_id)
    REFERENCES rq.project_dispatch_memberships(dispatch_domain_id, project_id, tenant_id),
  FOREIGN KEY (dispatch_domain_id, tenant_id)
    REFERENCES rq.tenant_dispatch_state(dispatch_domain_id, tenant_id)
);

CREATE TABLE IF NOT EXISTS rq.endpoint_dispatch_state (
  dispatch_domain_id uuid NOT NULL,
  endpoint_id uuid NOT NULL,
  tenant_id uuid NOT NULL,
  project_id uuid NOT NULL,
  weight integer NOT NULL DEFAULT 1 CHECK (weight BETWEEN 1 AND 10),
  deficit_units integer NOT NULL DEFAULT 0 CHECK (deficit_units BETWEEN 0 AND 100),
  last_credited_policy_epoch bigint NOT NULL DEFAULT 0 CHECK (last_credited_policy_epoch >= 0),
  last_credited_round bigint NOT NULL DEFAULT 0 CHECK (last_credited_round >= 0),
  candidate_seek_created_at timestamptz NULL,
  candidate_seek_delivery_id uuid NULL,
  candidate_seek_upper_created_at timestamptz NULL,
  candidate_seek_upper_delivery_id uuid NULL,
  last_served_at timestamptz NULL,
  version bigint NOT NULL DEFAULT 1 CHECK (version >= 1),
  PRIMARY KEY (dispatch_domain_id, endpoint_id),
  FOREIGN KEY (dispatch_domain_id, project_id)
    REFERENCES rq.project_dispatch_state(dispatch_domain_id, project_id),
  FOREIGN KEY (endpoint_id, project_id, tenant_id)
    REFERENCES rq.endpoints(id, project_id, tenant_id)
);

CREATE TABLE IF NOT EXISTS rq.dispatch_claim_requests (
  id uuid PRIMARY KEY,
  runtime_instance_id uuid NOT NULL REFERENCES rq.sender_instances(id),
  dispatch_domain_id uuid NOT NULL REFERENCES rq.dispatch_domains(id),
  control_epoch uuid NOT NULL,
  request_sha256 bytea NOT NULL CHECK (pg_catalog.octet_length(request_sha256) = 32),
  maximum_count integer NOT NULL CHECK (maximum_count BETWEEN 1 AND 8),
  state text NOT NULL CHECK (state IN ('pending', 'accepted', 'empty', 'rejected')),
  created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  accepted_at timestamptz NULL,
  version bigint NOT NULL DEFAULT 1 CHECK (version >= 1)
);

CREATE TABLE IF NOT EXISTS rq.dispatch_claim_assignments (
  request_id uuid NOT NULL REFERENCES rq.dispatch_claim_requests(id),
  assignment_index integer NOT NULL CHECK (assignment_index >= 0),
  attempt_id uuid NOT NULL,
  delivery_id uuid NOT NULL,
  tenant_id uuid NOT NULL,
  project_id uuid NOT NULL,
  fencing_token bigint NOT NULL CHECK (fencing_token >= 1),
  control_epoch uuid NOT NULL,
  accepted_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  PRIMARY KEY (request_id, assignment_index),
  UNIQUE (request_id, attempt_id),
  FOREIGN KEY (attempt_id, delivery_id, project_id, tenant_id)
    REFERENCES rq.delivery_attempts(id, delivery_id, project_id, tenant_id)
);

CREATE TABLE IF NOT EXISTS rq.rate_policy_changes (
  id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL REFERENCES rq.tenants(id),
  project_id uuid NULL,
  endpoint_id uuid NULL,
  producer_id uuid NULL,
  scope_kind text NOT NULL CHECK (scope_kind IN ('tenant', 'project', 'endpoint', 'producer')),
  operation text NOT NULL CHECK (operation IN ('event_admission', 'send_start', 'endpoint_verification', 'replay_admission')),
  candidate_sha256 bytea NOT NULL CHECK (pg_catalog.octet_length(candidate_sha256) = 32),
  candidate_definition jsonb NOT NULL,
  state text NOT NULL CHECK (state IN ('proposed', 'draining', 'activated', 'rejected', 'expired', 'revoked')),
  expected_policy_version bigint NOT NULL CHECK (expected_policy_version >= 1),
  created_by uuid NOT NULL REFERENCES rq.humans(principal_id),
  created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  expires_at timestamptz NOT NULL,
  version bigint NOT NULL DEFAULT 1 CHECK (version >= 1),
  FOREIGN KEY (project_id, tenant_id) REFERENCES rq.projects(id, tenant_id),
  FOREIGN KEY (endpoint_id, project_id, tenant_id) REFERENCES rq.endpoints(id, project_id, tenant_id),
  FOREIGN KEY (producer_id, project_id, tenant_id) REFERENCES rq.producers(id, project_id, tenant_id),
  CHECK (pg_catalog.jsonb_typeof(candidate_definition) = 'object'),
  CHECK (expires_at > created_at),
  CONSTRAINT chk_rate_policy_changes_scope_ancestry CHECK (
    (scope_kind = 'tenant' AND project_id IS NULL AND endpoint_id IS NULL AND producer_id IS NULL)
    OR (scope_kind = 'project' AND project_id IS NOT NULL AND endpoint_id IS NULL AND producer_id IS NULL)
    OR (scope_kind = 'endpoint' AND project_id IS NOT NULL AND endpoint_id IS NOT NULL AND producer_id IS NULL)
    OR (scope_kind = 'producer' AND project_id IS NOT NULL AND endpoint_id IS NULL AND producer_id IS NOT NULL)
  )
);

CREATE TABLE IF NOT EXISTS rq.ordering_domains (
  id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL,
  project_id uuid NOT NULL,
  subscription_id uuid NOT NULL,
  domain_generation bigint NOT NULL CHECK (domain_generation >= 1),
  consumer_contract_scope text NOT NULL CHECK (pg_catalog.octet_length(consumer_contract_scope) BETWEEN 1 AND 128),
  extractor_sha256 bytea NOT NULL CHECK (pg_catalog.octet_length(extractor_sha256) = 32),
  state text NOT NULL CHECK (state IN ('prepared', 'active', 'draining', 'retired')),
  created_by uuid NOT NULL REFERENCES rq.humans(principal_id),
  created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  version bigint NOT NULL DEFAULT 1 CHECK (version >= 1),
  UNIQUE (subscription_id, domain_generation),
  UNIQUE (id, project_id, tenant_id, subscription_id, consumer_contract_scope),
  FOREIGN KEY (subscription_id, project_id, tenant_id) REFERENCES rq.subscriptions(id, project_id, tenant_id)
);

CREATE TABLE IF NOT EXISTS rq.ordering_cutover_plans (
  id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL,
  project_id uuid NOT NULL,
  subscription_id uuid NOT NULL,
  source_version bigint NOT NULL CHECK (source_version >= 1),
  target_version bigint NOT NULL CHECK (target_version >= 1),
  source_extractor_sha256 bytea NOT NULL CHECK (pg_catalog.octet_length(source_extractor_sha256) = 32),
  target_extractor_sha256 bytea NOT NULL CHECK (pg_catalog.octet_length(target_extractor_sha256) = 32),
  source_consumer_scope text NOT NULL CHECK (pg_catalog.octet_length(source_consumer_scope) BETWEEN 1 AND 128),
  target_consumer_scope text NOT NULL CHECK (pg_catalog.octet_length(target_consumer_scope) BETWEEN 1 AND 128),
  state text NOT NULL CHECK (state IN ('proposed', 'draining', 'ready', 'activated', 'rejected', 'expired', 'revoked')),
  boundary_project_sequence bigint NOT NULL DEFAULT 0 CHECK (boundary_project_sequence >= 0),
  candidate_sha256 bytea NOT NULL CHECK (pg_catalog.octet_length(candidate_sha256) = 32),
  created_by uuid NOT NULL REFERENCES rq.humans(principal_id),
  review_id uuid NULL,
  created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  expires_at timestamptz NOT NULL,
  version bigint NOT NULL DEFAULT 1 CHECK (version >= 1),
  FOREIGN KEY (subscription_id, source_version, project_id, tenant_id)
    REFERENCES rq.subscription_versions(subscription_id, subscription_version, project_id, tenant_id),
  FOREIGN KEY (subscription_id, target_version, project_id, tenant_id)
    REFERENCES rq.subscription_versions(subscription_id, subscription_version, project_id, tenant_id),
  CHECK (source_consumer_scope = target_consumer_scope),
  CHECK (expires_at > created_at)
);

CREATE TABLE IF NOT EXISTS rq.order_skip_proposals (
  id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL,
  project_id uuid NOT NULL,
  ordering_key_id uuid NOT NULL,
  delivery_id uuid NOT NULL,
  expected_key_version bigint NOT NULL CHECK (expected_key_version >= 1),
  expected_delivery_version bigint NOT NULL CHECK (expected_delivery_version >= 1),
  consumer_scope text NOT NULL CHECK (pg_catalog.octet_length(consumer_scope) BETWEEN 1 AND 128),
  known_outcome_class text NOT NULL CHECK (pg_catalog.length(known_outcome_class) BETWEEN 1 AND 128),
  evidence_sha256 bytea NOT NULL CHECK (pg_catalog.octet_length(evidence_sha256) = 32),
  candidate_sha256 bytea NOT NULL CHECK (pg_catalog.octet_length(candidate_sha256) = 32),
  proposer_principal_id uuid NOT NULL REFERENCES rq.humans(principal_id),
  state text NOT NULL CHECK (state IN ('proposed', 'approved', 'admitted', 'rejected', 'expired', 'revoked')),
  created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  expires_at timestamptz NOT NULL,
  accepted_disposition_id uuid NULL,
  version bigint NOT NULL DEFAULT 1 CHECK (version >= 1),
  FOREIGN KEY (ordering_key_id, project_id, tenant_id) REFERENCES rq.ordering_keys(id, project_id, tenant_id),
  FOREIGN KEY (delivery_id, project_id, tenant_id) REFERENCES rq.deliveries(id, project_id, tenant_id),
  UNIQUE (id, project_id, tenant_id, candidate_sha256),
  CHECK (expires_at > created_at)
);

CREATE TABLE IF NOT EXISTS rq.order_skip_reviews (
  id uuid PRIMARY KEY,
  proposal_id uuid NOT NULL,
  tenant_id uuid NOT NULL,
  project_id uuid NOT NULL,
  proposal_version bigint NOT NULL CHECK (proposal_version >= 1),
  candidate_sha256 bytea NOT NULL CHECK (pg_catalog.octet_length(candidate_sha256) = 32),
  reviewer_principal_id uuid NOT NULL REFERENCES rq.humans(principal_id),
  reviewer_authority_version bigint NOT NULL CHECK (reviewer_authority_version >= 1),
  decision text NOT NULL CHECK (decision IN ('approve', 'reject')),
  state text NOT NULL CHECK (state IN ('active', 'consumed', 'revoked', 'expired')),
  created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  expires_at timestamptz NOT NULL,
  FOREIGN KEY (proposal_id, project_id, tenant_id, candidate_sha256)
    REFERENCES rq.order_skip_proposals(id, project_id, tenant_id, candidate_sha256),
  CHECK (expires_at > created_at)
);

CREATE TABLE IF NOT EXISTS rq.order_dispositions (
  id uuid PRIMARY KEY,
  proposal_id uuid NOT NULL UNIQUE REFERENCES rq.order_skip_proposals(id),
  ordering_key_id uuid NOT NULL REFERENCES rq.ordering_keys(id),
  delivery_id uuid NOT NULL REFERENCES rq.deliveries(id),
  prior_sequence bigint NOT NULL CHECK (prior_sequence >= 1),
  resulting_sequence bigint NOT NULL CHECK (resulting_sequence = prior_sequence + 1),
  decision text NOT NULL CHECK (decision = 'reviewed_skip_without_processing_claim'),
  actor_principal_id uuid NOT NULL REFERENCES rq.humans(principal_id),
  reviewer_principal_id uuid NOT NULL REFERENCES rq.humans(principal_id),
  candidate_sha256 bytea NOT NULL CHECK (pg_catalog.octet_length(candidate_sha256) = 32),
  accepted_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  command_receipt_id uuid NOT NULL REFERENCES rq.command_receipts(id),
  CHECK (actor_principal_id <> reviewer_principal_id)
);

CREATE TABLE IF NOT EXISTS rq.representation_profiles (
  id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL,
  project_id uuid NOT NULL,
  event_type_id uuid NOT NULL,
  name text NOT NULL CHECK (pg_catalog.octet_length(name) BETWEEN 1 AND 128),
  state text NOT NULL CHECK (state IN ('draft', 'active', 'retired')),
  current_version bigint NULL CHECK (current_version IS NULL OR current_version >= 1),
  created_by uuid NOT NULL REFERENCES rq.humans(principal_id),
  created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  version bigint NOT NULL DEFAULT 1 CHECK (version >= 1),
  FOREIGN KEY (event_type_id, project_id, tenant_id) REFERENCES rq.event_types(id, project_id, tenant_id),
  UNIQUE (id, project_id, tenant_id, event_type_id),
  UNIQUE (project_id, name)
);

CREATE TABLE IF NOT EXISTS rq.representation_profile_versions (
  profile_id uuid NOT NULL,
  profile_version bigint NOT NULL CHECK (profile_version >= 1),
  tenant_id uuid NOT NULL,
  project_id uuid NOT NULL,
  event_type_id uuid NOT NULL,
  source_schema_version integer NOT NULL CHECK (source_schema_version >= 1),
  target_schema_version integer NOT NULL CHECK (target_schema_version >= 1),
  definition_bytes bytea NOT NULL CHECK (pg_catalog.octet_length(definition_bytes) BETWEEN 2 AND 65536),
  definition_sha256 bytea NOT NULL CHECK (pg_catalog.octet_length(definition_sha256) = 32),
  normalized_mapping jsonb NOT NULL,
  compiler_profile_version text NOT NULL CHECK (compiler_profile_version = 'relayquill.lossless-projection.v1'),
  proven_output_max_bytes integer NOT NULL CHECK (proven_output_max_bytes BETWEEN 1 AND 98304),
  created_by uuid NOT NULL REFERENCES rq.humans(principal_id),
  published_by uuid NULL REFERENCES rq.humans(principal_id),
  created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  published_at timestamptz NULL,
  PRIMARY KEY (profile_id, profile_version),
  UNIQUE (profile_id, profile_version, project_id, tenant_id),
  UNIQUE (profile_id, profile_version, project_id, tenant_id, source_schema_version, target_schema_version),
  FOREIGN KEY (profile_id, project_id, tenant_id, event_type_id)
    REFERENCES rq.representation_profiles(id, project_id, tenant_id, event_type_id),
  FOREIGN KEY (event_type_id, source_schema_version, project_id, tenant_id)
    REFERENCES rq.event_schema_versions(event_type_id, schema_version, project_id, tenant_id),
  FOREIGN KEY (event_type_id, target_schema_version, project_id, tenant_id)
    REFERENCES rq.event_schema_versions(event_type_id, schema_version, project_id, tenant_id),
  CHECK (pg_catalog.jsonb_typeof(normalized_mapping) = 'object')
);

CREATE TABLE IF NOT EXISTS rq.receiver_contracts (
  id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL,
  project_id uuid NOT NULL,
  endpoint_id uuid NOT NULL,
  name text NOT NULL CHECK (pg_catalog.octet_length(name) BETWEEN 1 AND 128),
  state text NOT NULL CHECK (state IN ('draft', 'verified', 'active', 'retired')),
  current_version bigint NULL CHECK (current_version IS NULL OR current_version >= 1),
  created_by uuid NOT NULL REFERENCES rq.humans(principal_id),
  created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  version bigint NOT NULL DEFAULT 1 CHECK (version >= 1),
  FOREIGN KEY (endpoint_id, project_id, tenant_id) REFERENCES rq.endpoints(id, project_id, tenant_id),
  UNIQUE (id, project_id, tenant_id, endpoint_id),
  UNIQUE (endpoint_id, name)
);

CREATE TABLE IF NOT EXISTS rq.receiver_contract_versions (
  contract_id uuid NOT NULL,
  contract_version bigint NOT NULL CHECK (contract_version >= 1),
  tenant_id uuid NOT NULL,
  project_id uuid NOT NULL,
  endpoint_id uuid NOT NULL,
  consumer_contract_scope text NOT NULL CHECK (pg_catalog.octet_length(consumer_contract_scope) BETWEEN 1 AND 128),
  definition_bytes bytea NOT NULL CHECK (pg_catalog.octet_length(definition_bytes) BETWEEN 2 AND 65536),
  definition_sha256 bytea NOT NULL CHECK (pg_catalog.octet_length(definition_sha256) = 32),
  receipt_profile text NOT NULL CHECK (receipt_profile IN ('http_ack_only', 'receiver_local_commit_v1')),
  ordering_profile text NOT NULL CHECK (ordering_profile IN ('unordered', 'receiver_strict_key_v1')),
  minimum_inbox_retention_seconds bigint NOT NULL CHECK (minimum_inbox_retention_seconds >= 7776000),
  created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  verified_at timestamptz NULL,
  published_by uuid NOT NULL REFERENCES rq.humans(principal_id),
  PRIMARY KEY (contract_id, contract_version),
  UNIQUE (contract_id, contract_version, project_id, tenant_id),
  UNIQUE (contract_id, contract_version, project_id, tenant_id, definition_sha256),
  FOREIGN KEY (contract_id, project_id, tenant_id, endpoint_id)
    REFERENCES rq.receiver_contracts(id, project_id, tenant_id, endpoint_id)
);

CREATE TABLE IF NOT EXISTS rq.subscription_representation_bindings (
  subscription_id uuid NOT NULL,
  subscription_version bigint NOT NULL CHECK (subscription_version >= 1),
  source_schema_version integer NOT NULL CHECK (source_schema_version >= 1),
  tenant_id uuid NOT NULL,
  project_id uuid NOT NULL,
  profile_id uuid NOT NULL,
  profile_version bigint NOT NULL CHECK (profile_version >= 1),
  receiver_contract_id uuid NOT NULL,
  receiver_contract_version bigint NOT NULL CHECK (receiver_contract_version >= 1),
  created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  PRIMARY KEY (subscription_id, subscription_version, source_schema_version),
  FOREIGN KEY (subscription_id, subscription_version, source_schema_version)
    REFERENCES rq.subscription_schema_versions(subscription_id, subscription_version, event_schema_version),
  FOREIGN KEY (profile_id, profile_version, project_id, tenant_id)
    REFERENCES rq.representation_profile_versions(profile_id, profile_version, project_id, tenant_id),
  FOREIGN KEY (receiver_contract_id, receiver_contract_version, project_id, tenant_id)
    REFERENCES rq.receiver_contract_versions(contract_id, contract_version, project_id, tenant_id)
);

CREATE TABLE IF NOT EXISTS rq.event_representation_counters (
  event_id uuid PRIMARY KEY REFERENCES rq.events(id),
  next_representation_version integer NOT NULL DEFAULT 2 CHECK (next_representation_version >= 2),
  version bigint NOT NULL DEFAULT 1 CHECK (version >= 1)
);

CREATE TABLE IF NOT EXISTS rq.event_representation_reservations (
  event_id uuid NOT NULL,
  profile_id uuid NOT NULL,
  profile_version bigint NOT NULL CHECK (profile_version >= 1),
  tenant_id uuid NOT NULL,
  project_id uuid NOT NULL,
  reserved_wire_bytes bigint NOT NULL CHECK (reserved_wire_bytes BETWEEN 1 AND 524288),
  actual_wire_bytes bigint NULL CHECK (actual_wire_bytes IS NULL OR actual_wire_bytes BETWEEN 1 AND reserved_wire_bytes),
  state text NOT NULL CHECK (state IN ('held', 'converted', 'released')),
  version bigint NOT NULL DEFAULT 1 CHECK (version >= 1),
  PRIMARY KEY (event_id, profile_id, profile_version),
  FOREIGN KEY (event_id, project_id, tenant_id) REFERENCES rq.events(id, project_id, tenant_id),
  FOREIGN KEY (profile_id, profile_version, project_id, tenant_id)
    REFERENCES rq.representation_profile_versions(profile_id, profile_version, project_id, tenant_id),
  CHECK ((state = 'converted' AND actual_wire_bytes IS NOT NULL) OR (state <> 'converted'))
);

CREATE TABLE IF NOT EXISTS rq.representation_provenance (
  wire_envelope_id uuid PRIMARY KEY,
  event_id uuid NOT NULL,
  tenant_id uuid NOT NULL,
  project_id uuid NOT NULL,
  source_content_sha256 bytea NOT NULL CHECK (pg_catalog.octet_length(source_content_sha256) = 32),
  profile_id uuid NOT NULL,
  profile_version bigint NOT NULL CHECK (profile_version >= 1),
  profile_sha256 bytea NOT NULL CHECK (pg_catalog.octet_length(profile_sha256) = 32),
  target_schema_version integer NOT NULL CHECK (target_schema_version >= 1),
  derived_content_sha256 bytea NOT NULL CHECK (pg_catalog.octet_length(derived_content_sha256) = 32),
  compiler_profile_version text NOT NULL CHECK (compiler_profile_version = 'relayquill.lossless-projection.v1'),
  created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  FOREIGN KEY (wire_envelope_id, event_id, project_id, tenant_id)
    REFERENCES rq.event_wire_envelopes(id, event_id, project_id, tenant_id),
  FOREIGN KEY (profile_id, profile_version, project_id, tenant_id)
    REFERENCES rq.representation_profile_versions(profile_id, profile_version, project_id, tenant_id)
);

CREATE TABLE IF NOT EXISTS rq.receiver_receipt_observations (
  id uuid PRIMARY KEY,
  delivery_id uuid NOT NULL,
  event_id uuid NOT NULL,
  tenant_id uuid NOT NULL,
  project_id uuid NOT NULL,
  attempt_id uuid NULL,
  consumer_contract_scope text NOT NULL CHECK (pg_catalog.octet_length(consumer_contract_scope) BETWEEN 1 AND 128),
  receipt_reference text NOT NULL CHECK (pg_catalog.octet_length(receipt_reference) BETWEEN 1 AND 256),
  receipt_facts_sha256 bytea NOT NULL CHECK (pg_catalog.octet_length(receipt_facts_sha256) = 32),
  request_wire_sha256 bytea NOT NULL CHECK (pg_catalog.octet_length(request_wire_sha256) = 32),
  proof_sha256 bytea NOT NULL CHECK (pg_catalog.octet_length(proof_sha256) = 32),
  key_id text NOT NULL CHECK (key_id ~ '^[a-z0-9][a-z0-9._-]{0,63}$'),
  receiver_contract_id uuid NOT NULL,
  receiver_contract_version bigint NOT NULL CHECK (receiver_contract_version >= 1),
  receipt_facts jsonb NOT NULL DEFAULT '{}'::jsonb,
  verification_profile_version text NOT NULL CHECK (pg_catalog.length(verification_profile_version) BETWEEN 1 AND 128),
  source_kind text NOT NULL CHECK (source_kind IN ('direct_response', 'operator_verified_intake')),
  observed_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  recorded_by uuid NOT NULL REFERENCES rq.principals(id),
  state text NOT NULL CHECK (state IN ('unverified', 'verified_supported', 'rejected')),
  UNIQUE (delivery_id, receipt_reference, receipt_facts_sha256, verification_profile_version),
  FOREIGN KEY (delivery_id, event_id, project_id, tenant_id)
    REFERENCES rq.deliveries(id, event_id, project_id, tenant_id),
  FOREIGN KEY (attempt_id, delivery_id, project_id, tenant_id)
    REFERENCES rq.delivery_attempts(id, delivery_id, project_id, tenant_id),
  FOREIGN KEY (receiver_contract_id, receiver_contract_version, project_id, tenant_id)
    REFERENCES rq.receiver_contract_versions(contract_id, contract_version, project_id, tenant_id),
  CHECK (pg_catalog.jsonb_typeof(receipt_facts) = 'object')
);

CREATE TABLE IF NOT EXISTS rq.signing_delivery_intents (
  id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL,
  project_id uuid NOT NULL,
  endpoint_id uuid NOT NULL,
  endpoint_version bigint NOT NULL CHECK (endpoint_version >= 1),
  key_version_id uuid NOT NULL,
  control_epoch uuid NOT NULL,
  sender_destination_reference text NOT NULL CHECK (pg_catalog.octet_length(sender_destination_reference) BETWEEN 1 AND 256),
  receiver_destination_reference text NOT NULL CHECK (pg_catalog.octet_length(receiver_destination_reference) BETWEEN 1 AND 256),
  candidate_sha256 bytea NOT NULL CHECK (pg_catalog.octet_length(candidate_sha256) = 32),
  state text NOT NULL CHECK (state IN ('requested', 'approved', 'delivering', 'delivery_unknown', 'delivered', 'failed_reissue_required', 'revoked', 'expired')),
  created_by uuid NOT NULL REFERENCES rq.humans(principal_id),
  created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  expires_at timestamptz NOT NULL,
  version bigint NOT NULL DEFAULT 1 CHECK (version >= 1),
  FOREIGN KEY (endpoint_id, endpoint_version, project_id, tenant_id)
    REFERENCES rq.endpoint_versions(endpoint_id, endpoint_version, project_id, tenant_id),
  FOREIGN KEY (key_version_id, endpoint_id, project_id, tenant_id)
    REFERENCES rq.signing_key_versions(id, endpoint_id, project_id, tenant_id),
  CHECK (expires_at > created_at)
);

CREATE TABLE IF NOT EXISTS rq.replay_proposals (
  id uuid PRIMARY KEY,
  family_id uuid NOT NULL,
  source_delivery_id uuid NOT NULL,
  event_id uuid NOT NULL,
  tenant_id uuid NOT NULL,
  project_id uuid NOT NULL,
  proposer_principal_id uuid NOT NULL REFERENCES rq.humans(principal_id),
  source_delivery_version bigint NOT NULL CHECK (source_delivery_version >= 1),
  target_subscription_version bigint NOT NULL CHECK (target_subscription_version >= 1),
  target_endpoint_version bigint NOT NULL CHECK (target_endpoint_version >= 1),
  wire_envelope_id uuid NOT NULL,
  strategy text NOT NULL CHECK (strategy IN ('replay_exact_original', 'replay_with_reviewed_representation')),
  ordering_strategy text NOT NULL CHECK (ordering_strategy IN ('append_after_current_tail', 'not_applicable')),
  representation_profile_id uuid NULL,
  representation_profile_version bigint NULL CHECK (representation_profile_version IS NULL OR representation_profile_version >= 1),
  receiver_contract_id uuid NULL,
  receiver_contract_version bigint NULL CHECK (receiver_contract_version IS NULL OR receiver_contract_version >= 1),
  consumer_event_key_sha256 bytea NOT NULL CHECK (pg_catalog.octet_length(consumer_event_key_sha256) = 32),
  candidate_sha256 bytea NOT NULL CHECK (pg_catalog.octet_length(candidate_sha256) = 32),
  state text NOT NULL CHECK (state IN ('proposed', 'approved', 'admitted', 'rejected', 'expired', 'revoked')),
  requested_deadline_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  expires_at timestamptz NOT NULL,
  accepted_delivery_id uuid NULL REFERENCES rq.deliveries(id),
  version bigint NOT NULL DEFAULT 1 CHECK (version >= 1),
  FOREIGN KEY (family_id) REFERENCES rq.delivery_families(id),
  FOREIGN KEY (source_delivery_id, event_id, project_id, tenant_id)
    REFERENCES rq.deliveries(id, event_id, project_id, tenant_id),
  FOREIGN KEY (wire_envelope_id, event_id, project_id, tenant_id)
    REFERENCES rq.event_wire_envelopes(id, event_id, project_id, tenant_id),
  UNIQUE (id, project_id, tenant_id, candidate_sha256),
  CHECK (expires_at > created_at AND requested_deadline_at > created_at)
);

CREATE TABLE IF NOT EXISTS rq.replay_reviews (
  id uuid PRIMARY KEY,
  proposal_id uuid NOT NULL,
  tenant_id uuid NOT NULL,
  project_id uuid NOT NULL,
  proposal_version bigint NOT NULL CHECK (proposal_version >= 1),
  candidate_sha256 bytea NOT NULL CHECK (pg_catalog.octet_length(candidate_sha256) = 32),
  reviewer_principal_id uuid NOT NULL REFERENCES rq.humans(principal_id),
  reviewer_authority_version bigint NOT NULL CHECK (reviewer_authority_version >= 1),
  decision text NOT NULL CHECK (decision IN ('approve', 'reject')),
  state text NOT NULL CHECK (state IN ('active', 'consumed', 'revoked', 'expired')),
  created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  expires_at timestamptz NOT NULL,
  FOREIGN KEY (proposal_id, project_id, tenant_id, candidate_sha256)
    REFERENCES rq.replay_proposals(id, project_id, tenant_id, candidate_sha256),
  CHECK (expires_at > created_at)
);

CREATE TABLE IF NOT EXISTS rq.suppression_proposals (
  id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL,
  project_id uuid NOT NULL,
  delivery_id uuid NOT NULL,
  expected_delivery_version bigint NOT NULL CHECK (expected_delivery_version >= 1),
  prior_outcome_class text NOT NULL CHECK (pg_catalog.length(prior_outcome_class) BETWEEN 1 AND 128),
  candidate_sha256 bytea NOT NULL CHECK (pg_catalog.octet_length(candidate_sha256) = 32),
  proposer_principal_id uuid NOT NULL REFERENCES rq.humans(principal_id),
  state text NOT NULL CHECK (state IN ('proposed', 'approved', 'admitted', 'rejected', 'expired', 'revoked')),
  created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  expires_at timestamptz NOT NULL,
  accepted_receipt_id uuid NULL REFERENCES rq.command_receipts(id),
  version bigint NOT NULL DEFAULT 1 CHECK (version >= 1),
  FOREIGN KEY (delivery_id, project_id, tenant_id) REFERENCES rq.deliveries(id, project_id, tenant_id),
  UNIQUE (id, project_id, tenant_id, candidate_sha256),
  CHECK (expires_at > created_at)
);

CREATE TABLE IF NOT EXISTS rq.suppression_reviews (
  id uuid PRIMARY KEY,
  proposal_id uuid NOT NULL,
  proposal_version bigint NOT NULL CHECK (proposal_version >= 1),
  tenant_id uuid NOT NULL,
  project_id uuid NOT NULL,
  candidate_sha256 bytea NOT NULL CHECK (pg_catalog.octet_length(candidate_sha256) = 32),
  reviewer_principal_id uuid NOT NULL REFERENCES rq.humans(principal_id),
  reviewer_authority_version bigint NOT NULL CHECK (reviewer_authority_version >= 1),
  decision text NOT NULL CHECK (decision IN ('approve', 'reject')),
  state text NOT NULL CHECK (state IN ('active', 'consumed', 'revoked', 'expired')),
  created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  expires_at timestamptz NOT NULL,
  FOREIGN KEY (proposal_id, project_id, tenant_id, candidate_sha256)
    REFERENCES rq.suppression_proposals(id, project_id, tenant_id, candidate_sha256),
  CHECK (expires_at > created_at)
);

CREATE TABLE IF NOT EXISTS rq.circuit_probe_requests (
  id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL,
  project_id uuid NOT NULL,
  endpoint_id uuid NOT NULL,
  endpoint_version bigint NOT NULL CHECK (endpoint_version >= 1),
  expected_circuit_generation bigint NOT NULL CHECK (expected_circuit_generation >= 0),
  requested_by uuid NOT NULL REFERENCES rq.humans(principal_id),
  requested_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  expires_at timestamptz NOT NULL,
  state text NOT NULL CHECK (state IN ('pending', 'prepared', 'obsolete', 'expired')),
  prepared_attempt_id uuid NULL,
  command_receipt_id uuid NOT NULL REFERENCES rq.command_receipts(id),
  version bigint NOT NULL DEFAULT 1 CHECK (version >= 1),
  FOREIGN KEY (endpoint_id, endpoint_version) REFERENCES rq.endpoint_circuits(endpoint_id, endpoint_version),
  FOREIGN KEY (prepared_attempt_id, project_id, tenant_id, endpoint_id, endpoint_version)
    REFERENCES rq.delivery_attempts(id, project_id, tenant_id, endpoint_id, endpoint_version),
  CHECK (expires_at > requested_at)
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_circuit_probe_requests_pending
  ON rq.circuit_probe_requests (endpoint_id, endpoint_version, expected_circuit_generation)
  WHERE state = 'pending';

CREATE TABLE IF NOT EXISTS rq.trace_references (
  id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL,
  project_id uuid NOT NULL,
  resource_kind text NOT NULL CHECK (resource_kind IN ('event', 'outbox_publication', 'fanout', 'delivery', 'attempt', 'verification', 'receiver_receipt')),
  resource_id uuid NOT NULL,
  context_kind text NOT NULL CHECK (context_kind IN ('enqueue', 'publish_observation', 'materialization', 'delivery_creation', 'send_observation', 'verified_receiver_observation')),
  trace_id text NOT NULL CHECK (trace_id ~ '^[0-9a-f]{32}$' AND trace_id <> '00000000000000000000000000000000'),
  span_id text NOT NULL CHECK (span_id ~ '^[0-9a-f]{16}$' AND span_id <> '0000000000000000'),
  trace_flags integer NOT NULL CHECK (trace_flags BETWEEN 0 AND 255),
  tracestate text NULL CHECK (tracestate IS NULL OR pg_catalog.octet_length(tracestate) <= 256),
  source_instance_id uuid NULL REFERENCES rq.runtime_instances(id),
  recorded_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  observation_profile_version text NOT NULL DEFAULT 'trace_v1' CHECK (pg_catalog.length(observation_profile_version) BETWEEN 1 AND 64),
  FOREIGN KEY (project_id, tenant_id) REFERENCES rq.projects(id, tenant_id)
);

CREATE TABLE IF NOT EXISTS rq.lifecycle_operations (
  id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL REFERENCES rq.tenants(id),
  project_id uuid NULL,
  kind text NOT NULL CHECK (kind IN ('tenant_retirement', 'project_retirement')),
  target_version bigint NOT NULL CHECK (target_version >= 1),
  candidate_sha256 bytea NOT NULL CHECK (pg_catalog.octet_length(candidate_sha256) = 32),
  state text NOT NULL CHECK (state IN ('admitted', 'draining', 'review_required', 'completed', 'revoked', 'failed_retryable')),
  created_by uuid NOT NULL REFERENCES rq.humans(principal_id),
  created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  last_progress_at timestamptz NULL,
  safe_reason_code text NULL,
  version bigint NOT NULL DEFAULT 1 CHECK (version >= 1),
  FOREIGN KEY (project_id, tenant_id) REFERENCES rq.projects(id, tenant_id),
  CHECK ((kind = 'tenant_retirement' AND project_id IS NULL) OR (kind = 'project_retirement' AND project_id IS NOT NULL))
);

CREATE TABLE IF NOT EXISTS rq.watch_leases (
  id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL,
  project_id uuid NOT NULL,
  principal_id uuid NOT NULL REFERENCES rq.principals(id),
  actor_kind text NOT NULL CHECK (actor_kind IN ('human', 'producer')),
  session_id uuid NULL,
  producer_credential_id uuid NULL REFERENCES rq.producer_credentials(id),
  resource_kind text NOT NULL CHECK (resource_kind IN ('event', 'delivery')),
  resource_id uuid NOT NULL,
  runtime_instance_id uuid NOT NULL REFERENCES rq.runtime_instances(id),
  control_epoch uuid NOT NULL,
  state text NOT NULL CHECK (state IN ('open', 'closed')),
  slot_state text NOT NULL CHECK (slot_state IN ('held', 'released')),
  opened_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  last_renewed_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  expires_at timestamptz NOT NULL,
  stream_cutoff_at timestamptz NOT NULL,
  closed_at timestamptz NULL,
  version bigint NOT NULL DEFAULT 1 CHECK (version >= 1),
  FOREIGN KEY (project_id, tenant_id) REFERENCES rq.projects(id, tenant_id),
  FOREIGN KEY (session_id, principal_id) REFERENCES rq.human_sessions(id, principal_id),
  CONSTRAINT chk_watch_leases_actor_ref CHECK (
    (actor_kind = 'human' AND session_id IS NOT NULL AND producer_credential_id IS NULL)
    OR (actor_kind = 'producer' AND producer_credential_id IS NOT NULL AND session_id IS NULL)
  ),
  CONSTRAINT chk_watch_leases_state CHECK (
    (state = 'open' AND slot_state = 'held' AND closed_at IS NULL)
    OR (state = 'closed' AND slot_state = 'released' AND closed_at IS NOT NULL)
  ),
  CHECK (expires_at > opened_at AND stream_cutoff_at >= expires_at)
);

CREATE TABLE IF NOT EXISTS rq.actor_watch_capacity (
  principal_id uuid PRIMARY KEY REFERENCES rq.principals(id),
  held_count integer NOT NULL DEFAULT 0 CHECK (held_count >= 0),
  approved_count integer NOT NULL DEFAULT 2 CHECK (approved_count >= 1),
  updated_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  version bigint NOT NULL DEFAULT 1 CHECK (version >= 1)
);

CREATE TABLE IF NOT EXISTS rq.tenant_watch_capacity (
  tenant_id uuid PRIMARY KEY REFERENCES rq.tenants(id),
  held_count integer NOT NULL DEFAULT 0 CHECK (held_count >= 0),
  approved_count integer NOT NULL DEFAULT 20 CHECK (approved_count >= 1),
  updated_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  version bigint NOT NULL DEFAULT 1 CHECK (version >= 1)
);

CREATE TABLE IF NOT EXISTS rq.project_watch_capacity (
  project_id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL,
  held_count integer NOT NULL DEFAULT 0 CHECK (held_count >= 0),
  approved_count integer NOT NULL DEFAULT 10 CHECK (approved_count >= 1),
  updated_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  version bigint NOT NULL DEFAULT 1 CHECK (version >= 1),
  FOREIGN KEY (project_id, tenant_id) REFERENCES rq.projects(id, tenant_id)
);

CREATE TABLE IF NOT EXISTS rq.retention_holds (
  id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL,
  project_id uuid NOT NULL,
  target_kind text NOT NULL CHECK (target_kind IN ('event', 'delivery_family', 'endpoint_version', 'signing_metadata', 'project')),
  target_id uuid NOT NULL,
  reason_code text NOT NULL CHECK (pg_catalog.length(reason_code) BETWEEN 1 AND 128),
  state text NOT NULL CHECK (state IN ('active', 'released', 'expired')),
  created_by uuid NOT NULL REFERENCES rq.humans(principal_id),
  created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  review_at timestamptz NOT NULL,
  expires_at timestamptz NULL,
  version bigint NOT NULL DEFAULT 1 CHECK (version >= 1),
  FOREIGN KEY (project_id, tenant_id) REFERENCES rq.projects(id, tenant_id),
  CHECK (expires_at IS NULL OR expires_at > created_at)
);

CREATE TABLE IF NOT EXISTS rq.retention_actions (
  id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL,
  project_id uuid NOT NULL,
  target_kind text NOT NULL CHECK (target_kind IN ('event', 'delivery_family', 'endpoint_version', 'signing_metadata', 'project')),
  target_id uuid NOT NULL,
  action text NOT NULL CHECK (action IN ('expire_payload', 'expire_wire', 'retire_history', 'retire_metadata')),
  state text NOT NULL CHECK (state IN ('ready', 'claimed', 'completed', 'failed_retryable', 'review_required')),
  owner_instance_id uuid NULL REFERENCES rq.runtime_instances(id),
  claim_control_epoch uuid NULL,
  claim_generation bigint NOT NULL DEFAULT 0 CHECK (claim_generation >= 0),
  claim_expires_at timestamptz NULL,
  source_boundary_sha256 bytea NOT NULL CHECK (pg_catalog.octet_length(source_boundary_sha256) = 32),
  created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  next_attempt_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  version bigint NOT NULL DEFAULT 1 CHECK (version >= 1),
  FOREIGN KEY (project_id, tenant_id) REFERENCES rq.projects(id, tenant_id),
  CONSTRAINT chk_retention_actions_claim_state CHECK (
    (state = 'claimed' AND owner_instance_id IS NOT NULL AND claim_control_epoch IS NOT NULL AND claim_expires_at IS NOT NULL AND claim_generation >= 1)
    OR (state <> 'claimed' AND owner_instance_id IS NULL AND claim_control_epoch IS NULL AND claim_expires_at IS NULL)
  )
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_retention_actions_active
  ON rq.retention_actions (target_kind, target_id, action)
  WHERE state IN ('ready', 'claimed', 'failed_retryable', 'review_required');

CREATE TABLE IF NOT EXISTS rq.coordinator_tasks (
  id uuid PRIMARY KEY,
  task_kind text NOT NULL CHECK (task_kind IN ('publication_recovery', 'fanout_recovery', 'eligibility', 'reaper', 'retention', 'projection_verification')),
  tenant_id uuid NULL REFERENCES rq.tenants(id),
  project_id uuid NULL,
  target_id uuid NOT NULL,
  state text NOT NULL CHECK (state IN ('ready', 'claimed', 'completed', 'failed_retryable', 'review_required')),
  owner_instance_id uuid NULL REFERENCES rq.runtime_instances(id),
  control_epoch uuid NOT NULL,
  claim_generation bigint NOT NULL DEFAULT 0 CHECK (claim_generation >= 0),
  claim_expires_at timestamptz NULL,
  not_before timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  attempt_count integer NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
  safe_error_code text NULL,
  version bigint NOT NULL DEFAULT 1 CHECK (version >= 1),
  FOREIGN KEY (project_id, tenant_id) REFERENCES rq.projects(id, tenant_id),
  CHECK (project_id IS NULL OR tenant_id IS NOT NULL),
  CONSTRAINT chk_coordinator_tasks_claim_state CHECK (
    (state = 'claimed' AND owner_instance_id IS NOT NULL AND claim_expires_at IS NOT NULL AND claim_generation >= 1)
    OR (state <> 'claimed' AND owner_instance_id IS NULL AND claim_expires_at IS NULL)
  )
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_coordinator_tasks_active
  ON rq.coordinator_tasks (task_kind, target_id)
  WHERE state IN ('ready', 'claimed', 'failed_retryable', 'review_required');

CREATE TABLE IF NOT EXISTS rq.project_delivery_totals (
  project_id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL,
  total_deliveries bigint NOT NULL DEFAULT 0 CHECK (total_deliveries >= 0),
  pending_count bigint NOT NULL DEFAULT 0 CHECK (pending_count >= 0),
  active_count bigint NOT NULL DEFAULT 0 CHECK (active_count >= 0),
  acknowledged_count bigint NOT NULL DEFAULT 0 CHECK (acknowledged_count >= 0),
  dead_letter_count bigint NOT NULL DEFAULT 0 CHECK (dead_letter_count >= 0),
  suppressed_count bigint NOT NULL DEFAULT 0 CHECK (suppressed_count >= 0),
  expired_count bigint NOT NULL DEFAULT 0 CHECK (expired_count >= 0),
  unknown_attempt_observations bigint NOT NULL DEFAULT 0 CHECK (unknown_attempt_observations >= 0),
  source_boundary_sha256 bytea NULL CHECK (source_boundary_sha256 IS NULL OR pg_catalog.octet_length(source_boundary_sha256) = 32),
  updated_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  version bigint NOT NULL DEFAULT 1 CHECK (version >= 1),
  FOREIGN KEY (project_id, tenant_id) REFERENCES rq.projects(id, tenant_id),
  CONSTRAINT chk_project_delivery_totals_disjoint_sum CHECK (
    total_deliveries = pending_count + active_count + acknowledged_count + dead_letter_count + suppressed_count + expired_count
  )
);

CREATE TABLE IF NOT EXISTS rq.project_delivery_total_deltas (
  project_id uuid NOT NULL,
  shard_id smallint NOT NULL CHECK (shard_id BETWEEN 0 AND 15),
  tenant_id uuid NOT NULL,
  total_deliveries_delta bigint NOT NULL DEFAULT 0,
  pending_delta bigint NOT NULL DEFAULT 0,
  active_delta bigint NOT NULL DEFAULT 0,
  acknowledged_delta bigint NOT NULL DEFAULT 0,
  dead_letter_delta bigint NOT NULL DEFAULT 0,
  suppressed_delta bigint NOT NULL DEFAULT 0,
  expired_delta bigint NOT NULL DEFAULT 0,
  unknown_attempt_observations_delta bigint NOT NULL DEFAULT 0,
  updated_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  version bigint NOT NULL DEFAULT 1 CHECK (version >= 1),
  PRIMARY KEY (project_id, shard_id),
  FOREIGN KEY (project_id, tenant_id) REFERENCES rq.projects(id, tenant_id)
);

CREATE TABLE IF NOT EXISTS rq.event_delivery_totals (
  event_id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL,
  project_id uuid NOT NULL,
  total_deliveries bigint NOT NULL DEFAULT 0 CHECK (total_deliveries >= 0),
  terminal_deliveries bigint NOT NULL DEFAULT 0 CHECK (terminal_deliveries >= 0 AND terminal_deliveries <= total_deliveries),
  acknowledged_deliveries bigint NOT NULL DEFAULT 0 CHECK (acknowledged_deliveries >= 0 AND acknowledged_deliveries <= terminal_deliveries),
  last_outcome_at timestamptz NULL,
  updated_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  version bigint NOT NULL DEFAULT 1 CHECK (version >= 1),
  FOREIGN KEY (event_id, project_id, tenant_id) REFERENCES rq.events(id, project_id, tenant_id)
);

-- 16-shard delta table eliminates hot-row FOR UPDATE contention on parent rq.events during concurrent delivery transitions.
CREATE TABLE IF NOT EXISTS rq.event_delivery_total_deltas (
  event_id uuid NOT NULL,
  shard_id smallint NOT NULL CHECK (shard_id BETWEEN 0 AND 15),
  tenant_id uuid NOT NULL,
  project_id uuid NOT NULL,
  total_deliveries_delta bigint NOT NULL DEFAULT 0,
  terminal_deliveries_delta bigint NOT NULL DEFAULT 0,
  acknowledged_deliveries_delta bigint NOT NULL DEFAULT 0,
  last_outcome_at timestamptz NULL,
  updated_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  version bigint NOT NULL DEFAULT 1 CHECK (version >= 1),
  PRIMARY KEY (event_id, shard_id),
  FOREIGN KEY (event_id, project_id, tenant_id) REFERENCES rq.events(id, project_id, tenant_id)
);
