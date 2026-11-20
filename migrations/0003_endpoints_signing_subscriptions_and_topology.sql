-- Migration 0003: Endpoints, signing keys and policies, verification intents/attempts/events, dispatch grants, subscriptions, and topology ranges.

CREATE TABLE IF NOT EXISTS rq.endpoints (
  id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL,
  project_id uuid NOT NULL,
  name text NOT NULL CHECK (pg_catalog.octet_length(name) BETWEEN 1 AND 128),
  state text NOT NULL CHECK (state IN ('draft', 'verification_pending', 'active', 'paused', 'quarantined', 'retired')),
  current_version bigint NULL CHECK (current_version IS NULL OR current_version >= 1),
  security_epoch bigint NOT NULL DEFAULT 1 CHECK (security_epoch >= 1),
  current_signing_policy_version bigint NULL CHECK (current_signing_policy_version IS NULL OR current_signing_policy_version >= 1),
  created_by uuid NOT NULL REFERENCES rq.humans(principal_id),
  created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  version bigint NOT NULL DEFAULT 1 CHECK (version >= 1),
  FOREIGN KEY (project_id, tenant_id) REFERENCES rq.projects(id, tenant_id),
  UNIQUE (id, project_id, tenant_id),
  UNIQUE (project_id, name)
);

CREATE TABLE IF NOT EXISTS rq.endpoint_versions (
  endpoint_id uuid NOT NULL,
  endpoint_version bigint NOT NULL CHECK (endpoint_version >= 1),
  tenant_id uuid NOT NULL,
  project_id uuid NOT NULL,
  destination_url text NOT NULL CHECK (pg_catalog.octet_length(destination_url) BETWEEN 1 AND 2048),
  normalized_hostname text NOT NULL CHECK (pg_catalog.octet_length(normalized_hostname) BETWEEN 1 AND 255),
  port integer NOT NULL CHECK (port BETWEEN 1 AND 65535),
  path_and_query_sha256 bytea NOT NULL CHECK (pg_catalog.octet_length(path_and_query_sha256) = 32),
  url_policy_version text NOT NULL CHECK (pg_catalog.length(url_policy_version) BETWEEN 1 AND 128),
  network_policy_version text NOT NULL CHECK (pg_catalog.length(network_policy_version) BETWEEN 1 AND 128),
  request_profile_version text NOT NULL CHECK (pg_catalog.length(request_profile_version) BETWEEN 1 AND 128),
  response_profile_version text NOT NULL CHECK (pg_catalog.length(response_profile_version) BETWEEN 1 AND 128),
  configuration_sha256 bytea NOT NULL CHECK (pg_catalog.octet_length(configuration_sha256) = 32),
  created_by uuid NOT NULL REFERENCES rq.humans(principal_id),
  created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  verified_at timestamptz NULL,
  activated_at timestamptz NULL,
  PRIMARY KEY (endpoint_id, endpoint_version),
  UNIQUE (endpoint_id, endpoint_version, project_id, tenant_id),
  UNIQUE (endpoint_id, endpoint_version, project_id, tenant_id, configuration_sha256),
  FOREIGN KEY (endpoint_id, project_id, tenant_id) REFERENCES rq.endpoints(id, project_id, tenant_id)
);

CREATE TABLE IF NOT EXISTS rq.signing_key_versions (
  id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL,
  project_id uuid NOT NULL,
  endpoint_id uuid NOT NULL,
  key_version bigint NOT NULL CHECK (key_version >= 1),
  key_id text NOT NULL CHECK (key_id ~ '^[a-z0-9][a-z0-9._-]{0,63}$'),
  algorithm text NOT NULL CHECK (algorithm = 'hmac-sha256-v1'),
  custody_reference text NOT NULL CHECK (pg_catalog.octet_length(custody_reference) BETWEEN 1 AND 256),
  custody_version_reference text NOT NULL CHECK (pg_catalog.octet_length(custody_version_reference) BETWEEN 1 AND 256),
  state text NOT NULL CHECK (state IN ('prepared', 'receiver_verified', 'active', 'overlap', 'retired', 'revoked')),
  created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  receiver_verified_at timestamptz NULL,
  activate_not_before timestamptz NULL,
  sign_until timestamptz NULL,
  verify_until timestamptz NULL,
  revoked_at timestamptz NULL,
  version bigint NOT NULL DEFAULT 1 CHECK (version >= 1),
  FOREIGN KEY (endpoint_id, project_id, tenant_id) REFERENCES rq.endpoints(id, project_id, tenant_id),
  UNIQUE (endpoint_id, key_version),
  UNIQUE (endpoint_id, key_id),
  UNIQUE (id, endpoint_id, project_id, tenant_id),
  CHECK (sign_until IS NULL OR verify_until IS NULL OR sign_until <= verify_until)
);

CREATE TABLE IF NOT EXISTS rq.signing_policies (
  endpoint_id uuid NOT NULL,
  policy_version bigint NOT NULL CHECK (policy_version >= 1),
  tenant_id uuid NOT NULL,
  project_id uuid NOT NULL,
  primary_key_version_id uuid NOT NULL,
  overlap_key_version_id uuid NULL,
  signature_mode text NOT NULL CHECK (signature_mode IN ('primary_only', 'bounded_dual_signature')),
  overlap_until timestamptz NULL,
  policy_sha256 bytea NOT NULL CHECK (pg_catalog.octet_length(policy_sha256) = 32),
  created_by uuid NOT NULL REFERENCES rq.humans(principal_id),
  created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  activated_at timestamptz NULL,
  PRIMARY KEY (endpoint_id, policy_version),
  FOREIGN KEY (endpoint_id, project_id, tenant_id) REFERENCES rq.endpoints(id, project_id, tenant_id),
  FOREIGN KEY (primary_key_version_id, endpoint_id, project_id, tenant_id) REFERENCES rq.signing_key_versions(id, endpoint_id, project_id, tenant_id),
  FOREIGN KEY (overlap_key_version_id, endpoint_id, project_id, tenant_id) REFERENCES rq.signing_key_versions(id, endpoint_id, project_id, tenant_id),
  CONSTRAINT chk_signing_policies_mode CHECK (
    (
      signature_mode = 'primary_only'
      AND overlap_key_version_id IS NULL
      AND overlap_until IS NULL
    )
    OR (
      signature_mode = 'bounded_dual_signature'
      AND overlap_key_version_id IS NOT NULL
      AND overlap_key_version_id <> primary_key_version_id
      AND overlap_until IS NOT NULL
    )
  )
);

CREATE TABLE IF NOT EXISTS rq.endpoint_verification_intents (
  id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL,
  project_id uuid NOT NULL,
  endpoint_id uuid NOT NULL,
  endpoint_version bigint NOT NULL CHECK (endpoint_version >= 1),
  security_epoch bigint NOT NULL CHECK (security_epoch >= 1),
  configuration_sha256 bytea NOT NULL CHECK (pg_catalog.octet_length(configuration_sha256) = 32),
  signing_key_version_id uuid NOT NULL,
  receiver_contract_id uuid NULL,
  receiver_contract_version bigint NULL CHECK (receiver_contract_version IS NULL OR receiver_contract_version >= 1),
  receiver_contract_sha256 bytea NULL CHECK (receiver_contract_sha256 IS NULL OR pg_catalog.octet_length(receiver_contract_sha256) = 32),
  purpose text NOT NULL CHECK (purpose IN ('verify_destination_and_key', 'verify_rotation_key')),
  public_nonce bytea NOT NULL CHECK (pg_catalog.octet_length(public_nonce) = 32),
  state text NOT NULL CHECK (state IN ('requested', 'approved', 'probing', 'verified', 'failed', 'expired', 'revoked')),
  attempt_count integer NOT NULL DEFAULT 0 CHECK (attempt_count BETWEEN 0 AND 3),
  created_by uuid NOT NULL REFERENCES rq.humans(principal_id),
  created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  expires_at timestamptz NOT NULL,
  verified_at timestamptz NULL,
  safe_error_code text NULL,
  version bigint NOT NULL DEFAULT 1 CHECK (version >= 1),
  FOREIGN KEY (endpoint_id, endpoint_version, project_id, tenant_id, configuration_sha256)
    REFERENCES rq.endpoint_versions(endpoint_id, endpoint_version, project_id, tenant_id, configuration_sha256),
  FOREIGN KEY (signing_key_version_id, endpoint_id, project_id, tenant_id)
    REFERENCES rq.signing_key_versions(id, endpoint_id, project_id, tenant_id),
  UNIQUE (id, project_id, tenant_id, endpoint_id, endpoint_version, signing_key_version_id),
  CHECK (expires_at > created_at),
  CONSTRAINT chk_endpoint_verification_contract_tuple CHECK (
    (receiver_contract_id IS NULL AND receiver_contract_version IS NULL AND receiver_contract_sha256 IS NULL)
    OR (receiver_contract_id IS NOT NULL AND receiver_contract_version IS NOT NULL AND receiver_contract_sha256 IS NOT NULL)
  )
);

CREATE TABLE IF NOT EXISTS rq.endpoint_verification_attempts (
  id uuid PRIMARY KEY,
  intent_id uuid NOT NULL,
  tenant_id uuid NOT NULL,
  project_id uuid NOT NULL,
  endpoint_id uuid NOT NULL,
  endpoint_version bigint NOT NULL CHECK (endpoint_version >= 1),
  signing_key_version_id uuid NOT NULL,
  runtime_instance_id uuid NOT NULL REFERENCES rq.runtime_instances(id),
  control_epoch uuid NOT NULL,
  claim_generation bigint NOT NULL CHECK (claim_generation >= 1),
  state text NOT NULL CHECK (state IN ('prepared', 'send_started', 'verified', 'failed', 'expired', 'abandoned')),
  prepared_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  send_started_at timestamptz NULL,
  claim_expires_at timestamptz NOT NULL,
  request_deadline_at timestamptz NOT NULL,
  response_status integer NULL CHECK (response_status IS NULL OR response_status BETWEEN 100 AND 599),
  proof_sha256 bytea NULL CHECK (proof_sha256 IS NULL OR pg_catalog.octet_length(proof_sha256) = 32),
  safe_error_code text NULL,
  finished_at timestamptz NULL,
  version bigint NOT NULL DEFAULT 1 CHECK (version >= 1),
  FOREIGN KEY (intent_id, project_id, tenant_id, endpoint_id, endpoint_version, signing_key_version_id)
    REFERENCES rq.endpoint_verification_intents(id, project_id, tenant_id, endpoint_id, endpoint_version, signing_key_version_id),
  UNIQUE (id, project_id, tenant_id, endpoint_id, endpoint_version),
  CHECK (claim_expires_at >= prepared_at AND request_deadline_at <= claim_expires_at)
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_endpoint_verification_attempts_active_intent
  ON rq.endpoint_verification_attempts (intent_id)
  WHERE state IN ('prepared', 'send_started');

CREATE TABLE IF NOT EXISTS rq.endpoint_verification_events (
  id uuid PRIMARY KEY,
  intent_id uuid NOT NULL,
  tenant_id uuid NOT NULL,
  project_id uuid NOT NULL,
  endpoint_id uuid NOT NULL,
  endpoint_version bigint NOT NULL CHECK (endpoint_version >= 1),
  key_version_id uuid NOT NULL,
  security_epoch bigint NOT NULL CHECK (security_epoch >= 1),
  outcome text NOT NULL CHECK (outcome IN ('verified', 'denied', 'unavailable', 'expired')),
  proof_sha256 bytea NULL CHECK (proof_sha256 IS NULL OR pg_catalog.octet_length(proof_sha256) = 32),
  network_policy_version text NOT NULL CHECK (pg_catalog.length(network_policy_version) BETWEEN 1 AND 128),
  observed_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  safe_reason_code text NOT NULL CHECK (pg_catalog.length(safe_reason_code) BETWEEN 1 AND 128),
  FOREIGN KEY (intent_id, project_id, tenant_id, endpoint_id, endpoint_version, key_version_id)
    REFERENCES rq.endpoint_verification_intents(id, project_id, tenant_id, endpoint_id, endpoint_version, signing_key_version_id),
  UNIQUE (id, project_id, tenant_id, endpoint_id, endpoint_version)
);

CREATE TABLE IF NOT EXISTS rq.endpoint_dispatch_grants (
  id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL,
  project_id uuid NOT NULL,
  endpoint_id uuid NOT NULL,
  endpoint_version bigint NOT NULL CHECK (endpoint_version >= 1),
  security_epoch bigint NOT NULL CHECK (security_epoch >= 1),
  grant_class text NOT NULL CHECK (grant_class IN ('current_destination', 'retained_destination_dispatch')),
  state text NOT NULL CHECK (state IN ('active', 'revoked', 'expired')),
  approved_by uuid NOT NULL REFERENCES rq.humans(principal_id),
  approved_configuration_sha256 bytea NOT NULL CHECK (pg_catalog.octet_length(approved_configuration_sha256) = 32),
  created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  expires_at timestamptz NULL,
  version bigint NOT NULL DEFAULT 1 CHECK (version >= 1),
  FOREIGN KEY (endpoint_id, endpoint_version, project_id, tenant_id, approved_configuration_sha256)
    REFERENCES rq.endpoint_versions(endpoint_id, endpoint_version, project_id, tenant_id, configuration_sha256),
  CHECK (expires_at IS NULL OR expires_at > created_at)
);

CREATE TABLE IF NOT EXISTS rq.subscriptions (
  id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL,
  project_id uuid NOT NULL,
  name text NOT NULL CHECK (pg_catalog.octet_length(name) BETWEEN 1 AND 128),
  state text NOT NULL CHECK (state IN ('draft', 'active', 'paused', 'retired', 'quarantined')),
  current_version bigint NULL CHECK (current_version IS NULL OR current_version >= 1),
  control_sequence bigint NOT NULL DEFAULT 1 CHECK (control_sequence >= 1),
  send_hold boolean NOT NULL DEFAULT false,
  created_by uuid NOT NULL REFERENCES rq.humans(principal_id),
  created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  version bigint NOT NULL DEFAULT 1 CHECK (version >= 1),
  FOREIGN KEY (project_id, tenant_id) REFERENCES rq.projects(id, tenant_id),
  UNIQUE (id, project_id, tenant_id),
  UNIQUE (project_id, name)
);

CREATE TABLE IF NOT EXISTS rq.subscription_versions (
  subscription_id uuid NOT NULL,
  subscription_version bigint NOT NULL CHECK (subscription_version >= 1),
  tenant_id uuid NOT NULL,
  project_id uuid NOT NULL,
  endpoint_id uuid NOT NULL,
  endpoint_version bigint NOT NULL CHECK (endpoint_version >= 1),
  event_type_id uuid NOT NULL,
  filter_profile_version text NOT NULL DEFAULT 'relayquill.filter.v1' CHECK (filter_profile_version = 'relayquill.filter.v1'),
  filter_ast jsonb NULL,
  filter_sha256 bytea NULL CHECK (filter_sha256 IS NULL OR pg_catalog.octet_length(filter_sha256) = 32),
  ordering_mode text NOT NULL CHECK (ordering_mode IN ('unordered', 'strict_per_key')),
  ordering_domain_id uuid NULL,
  ordering_extractor jsonb NULL,
  ordering_extractor_sha256 bytea NULL CHECK (ordering_extractor_sha256 IS NULL OR pg_catalog.octet_length(ordering_extractor_sha256) = 32),
  retry_policy_version text NOT NULL CHECK (pg_catalog.length(retry_policy_version) BETWEEN 1 AND 128),
  response_policy_kind text NOT NULL DEFAULT 'response' CHECK (response_policy_kind = 'response'),
  response_policy_version text NOT NULL CHECK (pg_catalog.length(response_policy_version) BETWEEN 1 AND 128),
  consumer_contract_scope text NOT NULL CHECK (pg_catalog.octet_length(consumer_contract_scope) BETWEEN 1 AND 128),
  receiver_contract_id uuid NOT NULL,
  receiver_contract_version bigint NOT NULL CHECK (receiver_contract_version >= 1),
  configuration_sha256 bytea NOT NULL CHECK (pg_catalog.octet_length(configuration_sha256) = 32),
  created_by uuid NOT NULL REFERENCES rq.humans(principal_id),
  created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  activated_at timestamptz NULL,
  PRIMARY KEY (subscription_id, subscription_version),
  UNIQUE (subscription_id, subscription_version, project_id, tenant_id),
  UNIQUE (subscription_id, subscription_version, project_id, tenant_id, event_type_id),
  FOREIGN KEY (subscription_id, project_id, tenant_id) REFERENCES rq.subscriptions(id, project_id, tenant_id),
  FOREIGN KEY (endpoint_id, endpoint_version, project_id, tenant_id) REFERENCES rq.endpoint_versions(endpoint_id, endpoint_version, project_id, tenant_id),
  FOREIGN KEY (event_type_id, project_id, tenant_id) REFERENCES rq.event_types(id, project_id, tenant_id),
  FOREIGN KEY (response_policy_kind, response_policy_version) REFERENCES rq.policy_versions(policy_kind, policy_version),
  CONSTRAINT chk_subscription_versions_filter_pair CHECK (
    (filter_ast IS NULL AND filter_sha256 IS NULL)
    OR (filter_ast IS NOT NULL AND filter_sha256 IS NOT NULL AND pg_catalog.jsonb_typeof(filter_ast) = 'object')
  ),
  CONSTRAINT chk_subscription_versions_ordering_mode CHECK (
    (
      ordering_mode = 'strict_per_key'
      AND ordering_domain_id IS NOT NULL
      AND ordering_extractor IS NOT NULL
      AND ordering_extractor_sha256 IS NOT NULL
    )
    OR (
      ordering_mode = 'unordered'
      AND ordering_domain_id IS NULL
      AND ordering_extractor IS NULL
      AND ordering_extractor_sha256 IS NULL
    )
  )
);

CREATE TABLE IF NOT EXISTS rq.subscription_schema_versions (
  subscription_id uuid NOT NULL,
  subscription_version bigint NOT NULL CHECK (subscription_version >= 1),
  tenant_id uuid NOT NULL,
  project_id uuid NOT NULL,
  event_type_id uuid NOT NULL,
  event_schema_version integer NOT NULL CHECK (event_schema_version >= 1),
  PRIMARY KEY (subscription_id, subscription_version, event_schema_version),
  FOREIGN KEY (subscription_id, subscription_version, project_id, tenant_id, event_type_id)
    REFERENCES rq.subscription_versions(subscription_id, subscription_version, project_id, tenant_id, event_type_id),
  FOREIGN KEY (event_type_id, event_schema_version, project_id, tenant_id)
    REFERENCES rq.event_schema_versions(event_type_id, schema_version, project_id, tenant_id)
);

CREATE TABLE IF NOT EXISTS rq.subscription_control_events (
  id uuid PRIMARY KEY,
  subscription_id uuid NOT NULL,
  tenant_id uuid NOT NULL,
  project_id uuid NOT NULL,
  control_sequence bigint NOT NULL CHECK (control_sequence >= 1),
  action text NOT NULL CHECK (action IN ('activate', 'pause_future', 'hold_sends', 'pause_all', 'resume_future', 'release_send_hold', 'retire', 'quarantine', 'cutover_activate')),
  prior_version bigint NULL CHECK (prior_version IS NULL OR prior_version >= 1),
  resulting_version bigint NULL CHECK (resulting_version IS NULL OR resulting_version >= 1),
  topology_version bigint NULL CHECK (topology_version IS NULL OR topology_version >= 1),
  actor_principal_id uuid NOT NULL REFERENCES rq.principals(id),
  command_receipt_id uuid NOT NULL,
  configuration_sha256 bytea NULL CHECK (configuration_sha256 IS NULL OR pg_catalog.octet_length(configuration_sha256) = 32),
  recorded_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  safe_reason_code text NOT NULL CHECK (pg_catalog.length(safe_reason_code) BETWEEN 1 AND 128),
  UNIQUE (subscription_id, control_sequence),
  UNIQUE (id, project_id, tenant_id),
  FOREIGN KEY (subscription_id, project_id, tenant_id) REFERENCES rq.subscriptions(id, project_id, tenant_id)
);

CREATE TABLE IF NOT EXISTS rq.subscription_topology_ranges (
  project_id uuid NOT NULL,
  tenant_id uuid NOT NULL,
  subscription_id uuid NOT NULL,
  subscription_version bigint NOT NULL CHECK (subscription_version >= 1),
  from_topology_version bigint NOT NULL CHECK (from_topology_version >= 1),
  until_topology_version bigint NULL,
  activation_event_id uuid NOT NULL,
  created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  PRIMARY KEY (subscription_id, subscription_version, from_topology_version),
  FOREIGN KEY (subscription_id, subscription_version, project_id, tenant_id)
    REFERENCES rq.subscription_versions(subscription_id, subscription_version, project_id, tenant_id),
  FOREIGN KEY (activation_event_id, project_id, tenant_id)
    REFERENCES rq.subscription_control_events(id, project_id, tenant_id),
  CHECK (until_topology_version IS NULL OR until_topology_version > from_topology_version),
  EXCLUDE USING gist (
    subscription_id WITH =,
    pg_catalog.int8range(from_topology_version, until_topology_version, '[)') WITH &&
  )
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_subscription_topology_ranges_open
  ON rq.subscription_topology_ranges (subscription_id)
  WHERE until_topology_version IS NULL;
