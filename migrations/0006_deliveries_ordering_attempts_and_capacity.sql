-- Migration 0006: Delivery families, deliveries, attempts, egress decisions, retry policies/decisions, circuits, ordering, capacity, slots, and token buckets.

INSERT INTO rq.policy_versions (
  policy_kind,
  policy_version,
  definition_bytes,
  definition_sha256,
  normalized_definition,
  state,
  created_by,
  activated_at
)
SELECT
  v.policy_kind,
  v.policy_version,
  pg_catalog.convert_to(v.def_json, 'UTF8'),
  pg_catalog.sha256(pg_catalog.convert_to(v.def_json, 'UTF8')),
  v.def_json::jsonb,
  'active',
  NULL,
  pg_catalog.clock_timestamp()
FROM (
  VALUES
    ('admission', 'admission_v1', '{"max_content_bytes":262144,"max_envelope_bytes":524288,"default_window_ms":86400000,"max_window_ms":604800000}'),
    ('response', 'response_v1', '{"acknowledged_range":[200,299],"redirect_permanent":[300,399],"transient_4xx":[408,425,429],"permanent_5xx":[501,505]}'),
    ('retry', 'retry_v1', '{"base_delay_ms":1000,"multiplier":2,"max_delay_ms":1800000,"retry_after_cap_ms":1800000,"minimum_next_window_ms":10000,"maximum_send_starts":12}'),
    ('circuit', 'circuit_v1', '{"failure_threshold":5,"initial_open_delay_ms":60000,"max_open_delay_ms":900000,"diagnostic_window_ms":60000}'),
    ('url', 'url_v1', '{"scheme":"https","port":443,"allow_query":false,"max_url_bytes":2048,"max_path_bytes":1024}'),
    ('network', 'network_v1', '{"max_cname_depth":8,"max_resolved_addresses":16,"dns_timeout_ms":2000,"connect_timeout_ms":2000,"tls_timeout_ms":2000,"header_timeout_ms":3000}'),
    ('request', 'request_v1', '{"method":"POST","content_type":"application/json","allow_compression":false,"max_body_bytes":524288}'),
    ('retention', 'retention_v1', '{"post_terminal_content_ms":2592000000,"history_min_ms":7776000000}'),
    ('rate', 'rate_v1', '{"unit_micro":1000000,"tenant_admit_rps":50,"tenant_admit_burst":100,"project_admit_rps":20,"project_admit_burst":40,"producer_admit_rps":10,"producer_admit_burst":20,"tenant_send_rps":50,"tenant_send_burst":100,"project_send_rps":20,"project_send_burst":40,"endpoint_send_rps":5,"endpoint_send_burst":10}'),
    ('dispatch', 'dispatch_v1', '{"max_tenants_per_pass":64,"max_candidates_per_pass":256,"max_claim_batch":8,"tenant_deficit_cap":1000,"project_deficit_cap":1000,"endpoint_deficit_cap":100}')
) AS v(policy_kind, policy_version, def_json)
ON CONFLICT (policy_kind, policy_version) DO NOTHING;

CREATE TABLE IF NOT EXISTS rq.retry_policy_versions (
  policy_version text PRIMARY KEY,
  policy_kind text NOT NULL DEFAULT 'retry' CHECK (policy_kind = 'retry'),
  definition_sha256 bytea NOT NULL CHECK (pg_catalog.octet_length(definition_sha256) = 32),
  base_delay_ms bigint NOT NULL CHECK (base_delay_ms >= 100),
  multiplier integer NOT NULL CHECK (multiplier BETWEEN 1 AND 16),
  max_delay_ms bigint NOT NULL CHECK (max_delay_ms >= base_delay_ms),
  retry_after_cap_ms bigint NOT NULL CHECK (retry_after_cap_ms >= 0),
  minimum_next_window_ms bigint NOT NULL CHECK (minimum_next_window_ms >= 1000),
  maximum_send_starts integer NOT NULL CHECK (maximum_send_starts BETWEEN 1 AND 100),
  created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  state text NOT NULL CHECK (state IN ('draft', 'published', 'retired')),
  FOREIGN KEY (policy_kind, policy_version, definition_sha256)
    REFERENCES rq.policy_versions(policy_kind, policy_version, definition_sha256)
);

INSERT INTO rq.retry_policy_versions (
  policy_version,
  policy_kind,
  definition_sha256,
  base_delay_ms,
  multiplier,
  max_delay_ms,
  retry_after_cap_ms,
  minimum_next_window_ms,
  maximum_send_starts,
  state
)
SELECT
  pv.policy_version,
  pv.policy_kind,
  pv.definition_sha256,
  1000,
  2,
  1800000,
  1800000,
  10000,
  12,
  'published'
FROM rq.policy_versions pv
WHERE pv.policy_kind = 'retry' AND pv.policy_version = 'retry_v1'
ON CONFLICT (policy_version) DO NOTHING;

CREATE TABLE IF NOT EXISTS rq.delivery_families (
  id uuid PRIMARY KEY,
  event_id uuid NOT NULL,
  tenant_id uuid NOT NULL,
  project_id uuid NOT NULL,
  subscription_id uuid NOT NULL,
  original_subscription_version bigint NOT NULL CHECK (original_subscription_version >= 1),
  consumer_contract_scope text NOT NULL CHECK (pg_catalog.octet_length(consumer_contract_scope) BETWEEN 1 AND 128),
  consumer_event_key_sha256 bytea NOT NULL CHECK (pg_catalog.octet_length(consumer_event_key_sha256) = 32),
  original_delivery_id uuid NULL,
  next_generation bigint NOT NULL DEFAULT 1 CHECK (next_generation >= 1),
  created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  version bigint NOT NULL DEFAULT 1 CHECK (version >= 1),
  UNIQUE (event_id, subscription_id, original_subscription_version),
  UNIQUE (id, event_id, project_id, tenant_id, subscription_id),
  FOREIGN KEY (event_id, project_id, tenant_id) REFERENCES rq.events(id, project_id, tenant_id),
  FOREIGN KEY (subscription_id, original_subscription_version, project_id, tenant_id)
    REFERENCES rq.subscription_versions(subscription_id, subscription_version, project_id, tenant_id)
);

CREATE TABLE IF NOT EXISTS rq.deliveries (
  id uuid PRIMARY KEY,
  family_id uuid NOT NULL,
  event_id uuid NOT NULL,
  tenant_id uuid NOT NULL,
  project_id uuid NOT NULL,
  subscription_id uuid NOT NULL,
  original_subscription_version bigint NOT NULL CHECK (original_subscription_version >= 1),
  dispatch_subscription_version bigint NOT NULL CHECK (dispatch_subscription_version >= 1),
  endpoint_id uuid NOT NULL,
  endpoint_version bigint NOT NULL CHECK (endpoint_version >= 1),
  wire_envelope_id uuid NOT NULL,
  delivery_generation bigint NOT NULL CHECK (delivery_generation >= 0),
  replay_proposal_id uuid NULL,
  state text NOT NULL CHECK (state IN ('pending', 'ready', 'sending', 'retry_wait', 'acknowledged', 'dead_letter', 'suppressed', 'expired')),
  blocking_reason text NULL,
  ordering_key_sha256 bytea NULL CHECK (ordering_key_sha256 IS NULL OR pg_catalog.octet_length(ordering_key_sha256) = 32),
  ordering_sequence bigint NULL CHECK (ordering_sequence IS NULL OR ordering_sequence >= 1),
  attempt_count integer NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
  next_attempt_number integer NOT NULL DEFAULT 1 CHECK (next_attempt_number >= 1),
  prepared_attempt_count integer NOT NULL DEFAULT 0 CHECK (prepared_attempt_count >= 0),
  preparation_failure_count integer NOT NULL DEFAULT 0 CHECK (preparation_failure_count >= 0),
  maximum_attempts integer NOT NULL DEFAULT 12 CHECK (maximum_attempts BETWEEN 1 AND 100),
  deadline_at timestamptz NOT NULL,
  next_eligible_at timestamptz NOT NULL,
  current_attempt_id uuid NULL,
  current_fence bigint NOT NULL DEFAULT 0 CHECK (current_fence >= 0),
  control_epoch uuid NOT NULL,
  acknowledged_at timestamptz NULL,
  terminal_at timestamptz NULL,
  last_outcome_class text NULL CHECK (
    last_outcome_class IS NULL
    OR last_outcome_class IN ('acknowledged', 'transient_http', 'permanent_http', 'permanent_redirect', 'transport_unknown', 'permanent_policy_or_security')
  ),
  next_history_sequence bigint NOT NULL DEFAULT 0 CHECK (next_history_sequence >= 0),
  created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  version bigint NOT NULL DEFAULT 1 CHECK (version >= 1),
  UNIQUE (family_id, delivery_generation),
  UNIQUE (id, project_id, tenant_id),
  UNIQUE (id, project_id, tenant_id, endpoint_id),
  UNIQUE (id, event_id, project_id, tenant_id),
  FOREIGN KEY (family_id, event_id, project_id, tenant_id, subscription_id)
    REFERENCES rq.delivery_families(id, event_id, project_id, tenant_id, subscription_id),
  FOREIGN KEY (subscription_id, dispatch_subscription_version, project_id, tenant_id)
    REFERENCES rq.subscription_versions(subscription_id, subscription_version, project_id, tenant_id),
  FOREIGN KEY (endpoint_id, endpoint_version, project_id, tenant_id)
    REFERENCES rq.endpoint_versions(endpoint_id, endpoint_version, project_id, tenant_id),
  FOREIGN KEY (wire_envelope_id, event_id, project_id, tenant_id)
    REFERENCES rq.event_wire_envelopes(id, event_id, project_id, tenant_id),
  CONSTRAINT chk_deliveries_generation_replay CHECK (
    (delivery_generation = 0 AND dispatch_subscription_version = original_subscription_version AND replay_proposal_id IS NULL)
    OR (delivery_generation >= 1 AND replay_proposal_id IS NOT NULL)
  ),
  CONSTRAINT chk_deliveries_current_attempt CHECK (
    (state = 'sending' AND current_attempt_id IS NOT NULL)
    OR (state <> 'sending' AND current_attempt_id IS NULL)
  ),
  CONSTRAINT chk_deliveries_terminal_timestamps CHECK (
    (state = 'acknowledged' AND acknowledged_at IS NOT NULL AND terminal_at IS NOT NULL)
    OR (state IN ('dead_letter', 'suppressed', 'expired') AND acknowledged_at IS NULL AND terminal_at IS NOT NULL)
    OR (state IN ('pending', 'ready', 'sending', 'retry_wait') AND acknowledged_at IS NULL AND terminal_at IS NULL)
  )
);

CREATE TABLE IF NOT EXISTS rq.delivery_attempts (
  id uuid PRIMARY KEY,
  delivery_id uuid NOT NULL,
  tenant_id uuid NOT NULL,
  project_id uuid NOT NULL,
  attempt_number integer NOT NULL CHECK (attempt_number >= 1),
  worker_instance_id uuid NOT NULL REFERENCES rq.runtime_instances(id),
  control_epoch uuid NOT NULL,
  fencing_token bigint NOT NULL CHECK (fencing_token >= 1),
  state text NOT NULL CHECK (state IN ('prepared', 'send_started', 'response_observed', 'failed_before_send', 'deferred_before_send', 'transport_unknown', 'abandoned')),
  prepared_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  send_started_at timestamptz NULL,
  request_deadline_at timestamptz NOT NULL,
  claim_expires_at timestamptz NOT NULL,
  endpoint_id uuid NOT NULL,
  endpoint_version bigint NOT NULL CHECK (endpoint_version >= 1),
  endpoint_security_epoch bigint NOT NULL CHECK (endpoint_security_epoch >= 1),
  dispatch_grant_id uuid NOT NULL REFERENCES rq.endpoint_dispatch_grants(id),
  signing_policy_version bigint NOT NULL CHECK (signing_policy_version >= 1),
  wire_body_sha256 bytea NOT NULL CHECK (pg_catalog.octet_length(wire_body_sha256) = 32),
  request_profile_version text NOT NULL CHECK (pg_catalog.length(request_profile_version) BETWEEN 1 AND 128),
  network_policy_version text NOT NULL CHECK (pg_catalog.length(network_policy_version) BETWEEN 1 AND 128),
  response_profile_version text NOT NULL CHECK (pg_catalog.length(response_profile_version) BETWEEN 1 AND 128),
  circuit_generation_at_preparation bigint NOT NULL CHECK (circuit_generation_at_preparation >= 0),
  circuit_generation_at_start bigint NULL CHECK (circuit_generation_at_start IS NULL OR circuit_generation_at_start >= 0),
  probe_generation_at_start bigint NULL CHECK (probe_generation_at_start IS NULL OR probe_generation_at_start >= 1),
  response_status integer NULL CHECK (response_status IS NULL OR response_status BETWEEN 100 AND 599),
  response_body_sha256 bytea NULL CHECK (response_body_sha256 IS NULL OR pg_catalog.octet_length(response_body_sha256) = 32),
  response_byte_count integer NULL CHECK (response_byte_count IS NULL OR response_byte_count >= 0),
  outcome_class text NULL CHECK (
    outcome_class IS NULL
    OR outcome_class IN ('acknowledged', 'transient_http', 'permanent_http', 'permanent_redirect', 'transport_unknown', 'permanent_policy_or_security')
  ),
  safe_error_code text NULL,
  finished_at timestamptz NULL,
  version bigint NOT NULL DEFAULT 1 CHECK (version >= 1),
  UNIQUE (delivery_id, attempt_number),
  UNIQUE (id, delivery_id, project_id, tenant_id),
  UNIQUE (id, project_id, tenant_id, endpoint_id, endpoint_version),
  FOREIGN KEY (delivery_id, project_id, tenant_id, endpoint_id)
    REFERENCES rq.deliveries(id, project_id, tenant_id, endpoint_id),
  FOREIGN KEY (endpoint_id, signing_policy_version)
    REFERENCES rq.signing_policies(endpoint_id, policy_version),
  CHECK (claim_expires_at >= prepared_at),
  CHECK ((state = 'response_observed' AND response_status IS NOT NULL) OR state <> 'response_observed'),
  CONSTRAINT chk_delivery_attempts_start_bindings CHECK (
    (state IN ('prepared', 'failed_before_send', 'deferred_before_send') AND send_started_at IS NULL AND circuit_generation_at_start IS NULL)
    OR (state IN ('send_started', 'response_observed', 'transport_unknown') AND send_started_at IS NOT NULL AND circuit_generation_at_start IS NOT NULL)
    OR state = 'abandoned'
  )
);

CREATE TABLE IF NOT EXISTS rq.egress_decisions (
  id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL,
  project_id uuid NOT NULL,
  endpoint_id uuid NOT NULL,
  endpoint_version bigint NOT NULL CHECK (endpoint_version >= 1),
  delivery_attempt_id uuid NULL,
  verification_attempt_id uuid NULL,
  runtime_instance_id uuid NOT NULL REFERENCES rq.runtime_instances(id),
  control_epoch uuid NOT NULL,
  network_policy_version text NOT NULL CHECK (pg_catalog.length(network_policy_version) BETWEEN 1 AND 128),
  registry_ipv4_sha256 bytea NOT NULL CHECK (pg_catalog.octet_length(registry_ipv4_sha256) = 32),
  registry_ipv6_sha256 bytea NOT NULL CHECK (pg_catalog.octet_length(registry_ipv6_sha256) = 32),
  authority_sha256 bytea NOT NULL CHECK (pg_catalog.octet_length(authority_sha256) = 32),
  answer_set_sha256 bytea NOT NULL CHECK (pg_catalog.octet_length(answer_set_sha256) = 32),
  selected_address_sha256 bytea NULL CHECK (selected_address_sha256 IS NULL OR pg_catalog.octet_length(selected_address_sha256) = 32),
  selected_family integer NULL CHECK (selected_family IS NULL OR selected_family IN (4, 6)),
  peer_address_sha256 bytea NULL CHECK (peer_address_sha256 IS NULL OR pg_catalog.octet_length(peer_address_sha256) = 32),
  decision text NOT NULL CHECK (decision IN ('allowed', 'denied', 'unavailable', 'expired')),
  reason_code text NOT NULL CHECK (pg_catalog.length(reason_code) BETWEEN 1 AND 128),
  observed_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  expires_at timestamptz NOT NULL,
  version bigint NOT NULL DEFAULT 1 CHECK (version >= 1),
  FOREIGN KEY (endpoint_id, endpoint_version, project_id, tenant_id)
    REFERENCES rq.endpoint_versions(endpoint_id, endpoint_version, project_id, tenant_id),
  FOREIGN KEY (delivery_attempt_id, project_id, tenant_id, endpoint_id, endpoint_version)
    REFERENCES rq.delivery_attempts(id, project_id, tenant_id, endpoint_id, endpoint_version),
  FOREIGN KEY (verification_attempt_id, project_id, tenant_id, endpoint_id, endpoint_version)
    REFERENCES rq.endpoint_verification_attempts(id, project_id, tenant_id, endpoint_id, endpoint_version),
  CONSTRAINT chk_egress_decisions_attempt_xor CHECK (
    (delivery_attempt_id IS NOT NULL AND verification_attempt_id IS NULL)
    OR (delivery_attempt_id IS NULL AND verification_attempt_id IS NOT NULL)
  )
);

CREATE TABLE IF NOT EXISTS rq.delivery_retry_decisions (
  id uuid PRIMARY KEY,
  delivery_id uuid NOT NULL,
  attempt_id uuid NOT NULL UNIQUE,
  tenant_id uuid NOT NULL,
  project_id uuid NOT NULL,
  outcome_class text NOT NULL CHECK (outcome_class IN ('acknowledged', 'transient_http', 'permanent_http', 'permanent_redirect', 'transport_unknown', 'permanent_policy_or_security')),
  retry_policy_version text NOT NULL REFERENCES rq.retry_policy_versions(policy_version),
  selected_delay_milliseconds bigint NULL CHECK (selected_delay_milliseconds IS NULL OR selected_delay_milliseconds >= 0),
  selected_backoff_milliseconds bigint NULL CHECK (selected_backoff_milliseconds IS NULL OR selected_backoff_milliseconds >= 0),
  retry_after_parse_class text NOT NULL CHECK (retry_after_parse_class IN ('none', 'delay_seconds', 'http_date', 'past_date', 'invalid', 'oversized', 'conflicting')),
  retry_after_milliseconds bigint NULL CHECK (retry_after_milliseconds IS NULL OR retry_after_milliseconds >= 0),
  next_eligible_at timestamptz NULL,
  decision text NOT NULL CHECK (decision IN ('retry_wait', 'acknowledged', 'dead_letter', 'suppressed', 'expired')),
  reason_code text NULL,
  decided_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  version bigint NOT NULL DEFAULT 1 CHECK (version >= 1),
  FOREIGN KEY (attempt_id, delivery_id, project_id, tenant_id)
    REFERENCES rq.delivery_attempts(id, delivery_id, project_id, tenant_id)
);

CREATE TABLE IF NOT EXISTS rq.late_delivery_observations (
  id uuid PRIMARY KEY,
  delivery_id uuid NOT NULL,
  attempt_id uuid NOT NULL,
  tenant_id uuid NOT NULL,
  project_id uuid NOT NULL,
  source_instance_id uuid NOT NULL REFERENCES rq.runtime_instances(id),
  observation_key_sha256 bytea NOT NULL CHECK (pg_catalog.octet_length(observation_key_sha256) = 32),
  facts_sha256 bytea NOT NULL CHECK (pg_catalog.octet_length(facts_sha256) = 32),
  observation_kind text NOT NULL CHECK (observation_kind IN ('late_http_response', 'late_transport_report', 'reviewed_receiver_receipt_reference')),
  safe_facts jsonb NOT NULL DEFAULT '{}'::jsonb,
  recorded_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  version bigint NOT NULL DEFAULT 1 CHECK (version >= 1),
  UNIQUE (attempt_id, source_instance_id, observation_key_sha256),
  FOREIGN KEY (attempt_id, delivery_id, project_id, tenant_id)
    REFERENCES rq.delivery_attempts(id, delivery_id, project_id, tenant_id),
  CHECK (pg_catalog.jsonb_typeof(safe_facts) = 'object')
);

CREATE TABLE IF NOT EXISTS rq.endpoint_circuits (
  endpoint_id uuid NOT NULL,
  endpoint_version bigint NOT NULL CHECK (endpoint_version >= 1),
  tenant_id uuid NOT NULL,
  project_id uuid NOT NULL,
  state text NOT NULL CHECK (state IN ('closed', 'open', 'half_open')),
  circuit_generation bigint NOT NULL DEFAULT 0 CHECK (circuit_generation >= 0),
  consecutive_transient_failures integer NOT NULL DEFAULT 0 CHECK (consecutive_transient_failures >= 0),
  reopen_count integer NOT NULL DEFAULT 0 CHECK (reopen_count >= 0),
  window_failure_count bigint NOT NULL DEFAULT 0 CHECK (window_failure_count >= 0),
  window_success_count bigint NOT NULL DEFAULT 0 CHECK (window_success_count >= 0),
  window_started_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  reopen_not_before timestamptz NULL,
  probe_attempt_id uuid NULL,
  probe_generation bigint NOT NULL DEFAULT 0 CHECK (probe_generation >= 0),
  probe_owner_instance_id uuid NULL REFERENCES rq.runtime_instances(id),
  probe_control_epoch uuid NULL,
  probe_expires_at timestamptz NULL,
  policy_kind text NOT NULL DEFAULT 'circuit' CHECK (policy_kind = 'circuit'),
  policy_version text NOT NULL DEFAULT 'circuit_v1',
  updated_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  version bigint NOT NULL DEFAULT 1 CHECK (version >= 1),
  PRIMARY KEY (endpoint_id, endpoint_version),
  FOREIGN KEY (endpoint_id, endpoint_version, project_id, tenant_id)
    REFERENCES rq.endpoint_versions(endpoint_id, endpoint_version, project_id, tenant_id),
  FOREIGN KEY (policy_kind, policy_version) REFERENCES rq.policy_versions(policy_kind, policy_version),
  FOREIGN KEY (probe_attempt_id, project_id, tenant_id, endpoint_id, endpoint_version)
    REFERENCES rq.delivery_attempts(id, project_id, tenant_id, endpoint_id, endpoint_version),
  CONSTRAINT chk_endpoint_circuits_probe_binding CHECK (
    (
      state = 'half_open'
      AND probe_attempt_id IS NOT NULL
      AND probe_owner_instance_id IS NOT NULL
      AND probe_control_epoch IS NOT NULL
      AND probe_expires_at IS NOT NULL
      AND probe_generation >= 1
    )
    OR (
      state IN ('closed', 'open')
      AND probe_attempt_id IS NULL
      AND probe_owner_instance_id IS NULL
      AND probe_control_epoch IS NULL
      AND probe_expires_at IS NULL
    )
  )
);

CREATE TABLE IF NOT EXISTS rq.ordering_keys (
  id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL,
  project_id uuid NOT NULL,
  subscription_id uuid NOT NULL,
  ordering_domain_id uuid NOT NULL,
  consumer_contract_scope text NOT NULL CHECK (pg_catalog.octet_length(consumer_contract_scope) BETWEEN 1 AND 128),
  ordering_key_sha256 bytea NOT NULL CHECK (pg_catalog.octet_length(ordering_key_sha256) = 32),
  next_allocate_sequence bigint NOT NULL DEFAULT 1 CHECK (next_allocate_sequence >= 1),
  next_eligible_sequence bigint NOT NULL DEFAULT 1 CHECK (next_eligible_sequence >= 1 AND next_eligible_sequence <= next_allocate_sequence),
  blocked_delivery_id uuid NULL,
  version bigint NOT NULL DEFAULT 1 CHECK (version >= 1),
  updated_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  UNIQUE (subscription_id, consumer_contract_scope, ordering_domain_id, ordering_key_sha256),
  UNIQUE (id, project_id, tenant_id),
  FOREIGN KEY (subscription_id, project_id, tenant_id) REFERENCES rq.subscriptions(id, project_id, tenant_id)
);

CREATE TABLE IF NOT EXISTS rq.ordering_members (
  ordering_key_id uuid NOT NULL,
  ordering_sequence bigint NOT NULL CHECK (ordering_sequence >= 1),
  delivery_id uuid NOT NULL UNIQUE,
  tenant_id uuid NOT NULL,
  project_id uuid NOT NULL,
  member_kind text NOT NULL CHECK (member_kind IN ('original', 'replay_append')),
  admitted_project_event_sequence bigint NOT NULL CHECK (admitted_project_event_sequence >= 1),
  state text NOT NULL CHECK (state IN ('waiting', 'eligible', 'acknowledged', 'reviewed_skip', 'blocked')),
  disposition_event_id uuid NULL,
  version bigint NOT NULL DEFAULT 1 CHECK (version >= 1),
  PRIMARY KEY (ordering_key_id, ordering_sequence),
  FOREIGN KEY (ordering_key_id, project_id, tenant_id) REFERENCES rq.ordering_keys(id, project_id, tenant_id),
  FOREIGN KEY (delivery_id, project_id, tenant_id) REFERENCES rq.deliveries(id, project_id, tenant_id)
);

CREATE TABLE IF NOT EXISTS rq.tenant_capacity (
  tenant_id uuid PRIMARY KEY REFERENCES rq.tenants(id),
  limit_profile_version text NOT NULL DEFAULT 'limits_v1' CHECK (pg_catalog.length(limit_profile_version) BETWEEN 1 AND 128),
  pending_events bigint NOT NULL DEFAULT 0 CHECK (pending_events >= 0),
  unmaterialized_candidate_slots bigint NOT NULL DEFAULT 0 CHECK (unmaterialized_candidate_slots >= 0),
  pending_deliveries bigint NOT NULL DEFAULT 0 CHECK (pending_deliveries >= 0),
  active_attempt_slots integer NOT NULL DEFAULT 0 CHECK (active_attempt_slots >= 0),
  retained_payload_bytes bigint NOT NULL DEFAULT 0 CHECK (retained_payload_bytes >= 0),
  reserved_payload_bytes bigint NOT NULL DEFAULT 0 CHECK (reserved_payload_bytes >= 0),
  max_pending_events bigint NOT NULL DEFAULT 10000 CHECK (max_pending_events >= 1),
  max_downstream_obligations bigint NOT NULL DEFAULT 100000 CHECK (max_downstream_obligations >= 1),
  max_active_attempt_slots integer NOT NULL DEFAULT 32 CHECK (max_active_attempt_slots >= 1),
  max_retained_payload_bytes bigint NOT NULL DEFAULT 2147483648 CHECK (max_retained_payload_bytes >= 1),
  updated_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  version bigint NOT NULL DEFAULT 1 CHECK (version >= 1)
);

CREATE TABLE IF NOT EXISTS rq.project_capacity (
  project_id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL,
  limit_profile_version text NOT NULL DEFAULT 'limits_v1' CHECK (pg_catalog.length(limit_profile_version) BETWEEN 1 AND 128),
  pending_events bigint NOT NULL DEFAULT 0 CHECK (pending_events >= 0),
  unmaterialized_candidate_slots bigint NOT NULL DEFAULT 0 CHECK (unmaterialized_candidate_slots >= 0),
  pending_deliveries bigint NOT NULL DEFAULT 0 CHECK (pending_deliveries >= 0),
  active_attempt_slots integer NOT NULL DEFAULT 0 CHECK (active_attempt_slots >= 0),
  retained_payload_bytes bigint NOT NULL DEFAULT 0 CHECK (retained_payload_bytes >= 0),
  reserved_payload_bytes bigint NOT NULL DEFAULT 0 CHECK (reserved_payload_bytes >= 0),
  max_pending_events bigint NOT NULL DEFAULT 1000 CHECK (max_pending_events >= 1),
  max_downstream_obligations bigint NOT NULL DEFAULT 10000 CHECK (max_downstream_obligations >= 1),
  max_active_attempt_slots integer NOT NULL DEFAULT 16 CHECK (max_active_attempt_slots >= 1),
  max_retained_payload_bytes bigint NOT NULL DEFAULT 536870912 CHECK (max_retained_payload_bytes >= 1),
  updated_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  version bigint NOT NULL DEFAULT 1 CHECK (version >= 1),
  FOREIGN KEY (project_id, tenant_id) REFERENCES rq.projects(id, tenant_id)
);

CREATE TABLE IF NOT EXISTS rq.event_fanout_reservations (
  event_id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL,
  project_id uuid NOT NULL,
  reserved_candidate_slots bigint NOT NULL CHECK (reserved_candidate_slots >= 0),
  unresolved_candidate_slots bigint NOT NULL CHECK (unresolved_candidate_slots >= 0),
  converted_delivery_slots bigint NOT NULL CHECK (converted_delivery_slots >= 0),
  released_nonmatch_slots bigint NOT NULL CHECK (released_nonmatch_slots >= 0),
  state text NOT NULL CHECK (state IN ('held', 'partially_converted', 'completed')),
  version bigint NOT NULL DEFAULT 1 CHECK (version >= 1),
  FOREIGN KEY (event_id, project_id, tenant_id) REFERENCES rq.events(id, project_id, tenant_id),
  CONSTRAINT chk_event_fanout_reservations_conservation CHECK (
    reserved_candidate_slots = unresolved_candidate_slots + converted_delivery_slots + released_nonmatch_slots
  ),
  CONSTRAINT chk_event_fanout_reservations_state CHECK (
    (state = 'completed' AND unresolved_candidate_slots = 0)
    OR (state IN ('held', 'partially_converted') AND unresolved_candidate_slots > 0)
  )
);

CREATE TABLE IF NOT EXISTS rq.sender_instances (
  id uuid PRIMARY KEY REFERENCES rq.runtime_instances(id),
  process_nonce_digest bytea NOT NULL CHECK (pg_catalog.octet_length(process_nonce_digest) = 32),
  build_reference text NOT NULL CHECK (pg_catalog.octet_length(build_reference) BETWEEN 1 AND 256),
  control_epoch uuid NOT NULL,
  state text NOT NULL CHECK (state IN ('active', 'draining', 'quarantined', 'ended')),
  approved_slots integer NOT NULL DEFAULT 8 CHECK (approved_slots >= 1),
  started_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  last_seen_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  expires_at timestamptz NOT NULL,
  version bigint NOT NULL DEFAULT 1 CHECK (version >= 1),
  CHECK (expires_at >= started_at)
);

CREATE TABLE IF NOT EXISTS rq.sender_capacity (
  instance_id uuid PRIMARY KEY REFERENCES rq.sender_instances(id),
  approved_slots integer NOT NULL DEFAULT 8 CHECK (approved_slots >= 1),
  held_slots integer NOT NULL DEFAULT 0 CHECK (held_slots >= 0 AND held_slots <= approved_slots),
  updated_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  version bigint NOT NULL DEFAULT 1 CHECK (version >= 1)
);

CREATE TABLE IF NOT EXISTS rq.endpoint_capacity (
  endpoint_id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL,
  project_id uuid NOT NULL,
  approved_active_slots integer NOT NULL DEFAULT 4 CHECK (approved_active_slots >= 1),
  held_slots integer NOT NULL DEFAULT 0 CHECK (held_slots >= 0),
  updated_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  version bigint NOT NULL DEFAULT 1 CHECK (version >= 1),
  FOREIGN KEY (endpoint_id, project_id, tenant_id) REFERENCES rq.endpoints(id, project_id, tenant_id)
);

CREATE TABLE IF NOT EXISTS rq.delivery_capacity_positions (
  delivery_id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL,
  project_id uuid NOT NULL,
  endpoint_id uuid NOT NULL,
  position text NOT NULL CHECK (position IN ('pending', 'active', 'released')),
  current_attempt_id uuid NULL,
  released_at timestamptz NULL,
  version bigint NOT NULL DEFAULT 1 CHECK (version >= 1),
  updated_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  FOREIGN KEY (delivery_id, project_id, tenant_id, endpoint_id)
    REFERENCES rq.deliveries(id, project_id, tenant_id, endpoint_id),
  FOREIGN KEY (current_attempt_id, delivery_id, project_id, tenant_id)
    REFERENCES rq.delivery_attempts(id, delivery_id, project_id, tenant_id),
  CONSTRAINT chk_delivery_capacity_positions_state CHECK (
    (position = 'active' AND current_attempt_id IS NOT NULL AND released_at IS NULL)
    OR (position = 'pending' AND current_attempt_id IS NULL AND released_at IS NULL)
    OR (position = 'released' AND current_attempt_id IS NULL AND released_at IS NOT NULL)
  )
);

CREATE TABLE IF NOT EXISTS rq.attempt_slots (
  attempt_id uuid PRIMARY KEY,
  delivery_id uuid NOT NULL,
  tenant_id uuid NOT NULL,
  project_id uuid NOT NULL,
  endpoint_id uuid NOT NULL,
  worker_instance_id uuid NOT NULL REFERENCES rq.sender_instances(id),
  state text NOT NULL CHECK (state IN ('held', 'released')),
  held_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  released_at timestamptz NULL,
  release_reason text NULL,
  version bigint NOT NULL DEFAULT 1 CHECK (version >= 1),
  FOREIGN KEY (attempt_id, delivery_id, project_id, tenant_id)
    REFERENCES rq.delivery_attempts(id, delivery_id, project_id, tenant_id),
  FOREIGN KEY (delivery_id, project_id, tenant_id, endpoint_id)
    REFERENCES rq.deliveries(id, project_id, tenant_id, endpoint_id),
  CHECK ((state = 'held' AND released_at IS NULL) OR (state = 'released' AND released_at IS NOT NULL))
);

CREATE TABLE IF NOT EXISTS rq.tenant_rate_buckets (
  tenant_id uuid NOT NULL REFERENCES rq.tenants(id),
  operation text NOT NULL CHECK (operation IN ('event_admission', 'send_start', 'endpoint_verification', 'replay_admission')),
  tokens_micro bigint NOT NULL,
  reserved_micro bigint NOT NULL DEFAULT 0,
  capacity_micro bigint NOT NULL,
  refill_micro_per_second bigint NOT NULL,
  refill_remainder_numerator bigint NOT NULL DEFAULT 0,
  rate_change_gate_id uuid NULL,
  last_refill_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  policy_version bigint NOT NULL DEFAULT 1 CHECK (policy_version >= 1),
  updated_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  version bigint NOT NULL DEFAULT 1 CHECK (version >= 1),
  PRIMARY KEY (tenant_id, operation),
  CONSTRAINT chk_tenant_rate_buckets_conservation CHECK (
    reserved_micro >= 0
    AND tokens_micro >= reserved_micro
    AND tokens_micro <= capacity_micro
    AND capacity_micro >= 1000000
    AND refill_micro_per_second >= 1
    AND refill_remainder_numerator >= 0
    AND refill_remainder_numerator < 1000000
  )
);

CREATE TABLE IF NOT EXISTS rq.project_rate_buckets (
  project_id uuid NOT NULL,
  tenant_id uuid NOT NULL,
  operation text NOT NULL CHECK (operation IN ('event_admission', 'send_start', 'endpoint_verification', 'replay_admission')),
  tokens_micro bigint NOT NULL,
  reserved_micro bigint NOT NULL DEFAULT 0,
  capacity_micro bigint NOT NULL,
  refill_micro_per_second bigint NOT NULL,
  refill_remainder_numerator bigint NOT NULL DEFAULT 0,
  rate_change_gate_id uuid NULL,
  last_refill_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  policy_version bigint NOT NULL DEFAULT 1 CHECK (policy_version >= 1),
  updated_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  version bigint NOT NULL DEFAULT 1 CHECK (version >= 1),
  PRIMARY KEY (project_id, operation),
  FOREIGN KEY (project_id, tenant_id) REFERENCES rq.projects(id, tenant_id),
  CONSTRAINT chk_project_rate_buckets_conservation CHECK (
    reserved_micro >= 0
    AND tokens_micro >= reserved_micro
    AND tokens_micro <= capacity_micro
    AND capacity_micro >= 1000000
    AND refill_micro_per_second >= 1
    AND refill_remainder_numerator >= 0
    AND refill_remainder_numerator < 1000000
  )
);

CREATE TABLE IF NOT EXISTS rq.endpoint_rate_buckets (
  endpoint_id uuid NOT NULL,
  tenant_id uuid NOT NULL,
  project_id uuid NOT NULL,
  operation text NOT NULL CHECK (operation IN ('event_admission', 'send_start', 'endpoint_verification', 'replay_admission')),
  tokens_micro bigint NOT NULL,
  reserved_micro bigint NOT NULL DEFAULT 0,
  capacity_micro bigint NOT NULL,
  refill_micro_per_second bigint NOT NULL,
  refill_remainder_numerator bigint NOT NULL DEFAULT 0,
  rate_change_gate_id uuid NULL,
  last_refill_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  policy_version bigint NOT NULL DEFAULT 1 CHECK (policy_version >= 1),
  updated_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  version bigint NOT NULL DEFAULT 1 CHECK (version >= 1),
  PRIMARY KEY (endpoint_id, operation),
  FOREIGN KEY (endpoint_id, project_id, tenant_id) REFERENCES rq.endpoints(id, project_id, tenant_id),
  CONSTRAINT chk_endpoint_rate_buckets_conservation CHECK (
    reserved_micro >= 0
    AND tokens_micro >= reserved_micro
    AND tokens_micro <= capacity_micro
    AND capacity_micro >= 1000000
    AND refill_micro_per_second >= 1
    AND refill_remainder_numerator >= 0
    AND refill_remainder_numerator < 1000000
  )
);

CREATE TABLE IF NOT EXISTS rq.producer_rate_buckets (
  producer_id uuid NOT NULL,
  tenant_id uuid NOT NULL,
  project_id uuid NOT NULL,
  operation text NOT NULL CHECK (operation IN ('event_admission', 'send_start', 'endpoint_verification', 'replay_admission')),
  tokens_micro bigint NOT NULL,
  reserved_micro bigint NOT NULL DEFAULT 0,
  capacity_micro bigint NOT NULL,
  refill_micro_per_second bigint NOT NULL,
  refill_remainder_numerator bigint NOT NULL DEFAULT 0,
  rate_change_gate_id uuid NULL,
  last_refill_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  policy_version bigint NOT NULL DEFAULT 1 CHECK (policy_version >= 1),
  updated_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  version bigint NOT NULL DEFAULT 1 CHECK (version >= 1),
  PRIMARY KEY (producer_id, operation),
  FOREIGN KEY (producer_id, project_id, tenant_id) REFERENCES rq.producers(id, project_id, tenant_id),
  CONSTRAINT chk_producer_rate_buckets_conservation CHECK (
    reserved_micro >= 0
    AND tokens_micro >= reserved_micro
    AND tokens_micro <= capacity_micro
    AND capacity_micro >= 1000000
    AND refill_micro_per_second >= 1
    AND refill_remainder_numerator >= 0
    AND refill_remainder_numerator < 1000000
  )
);

CREATE OR REPLACE VIEW rq.rate_buckets AS
  SELECT
    'tenant'::text AS scope_kind,
    tenant_id AS scope_id,
    tenant_id,
    NULL::uuid AS project_id,
    operation,
    tokens_micro,
    reserved_micro,
    capacity_micro,
    refill_micro_per_second,
    refill_remainder_numerator,
    rate_change_gate_id,
    last_refill_at,
    policy_version,
    updated_at,
    version
  FROM rq.tenant_rate_buckets
  UNION ALL
  SELECT
    'project'::text AS scope_kind,
    project_id AS scope_id,
    tenant_id,
    project_id,
    operation,
    tokens_micro,
    reserved_micro,
    capacity_micro,
    refill_micro_per_second,
    refill_remainder_numerator,
    rate_change_gate_id,
    last_refill_at,
    policy_version,
    updated_at,
    version
  FROM rq.project_rate_buckets
  UNION ALL
  SELECT
    'endpoint'::text AS scope_kind,
    endpoint_id AS scope_id,
    tenant_id,
    project_id,
    operation,
    tokens_micro,
    reserved_micro,
    capacity_micro,
    refill_micro_per_second,
    refill_remainder_numerator,
    rate_change_gate_id,
    last_refill_at,
    policy_version,
    updated_at,
    version
  FROM rq.endpoint_rate_buckets
  UNION ALL
  SELECT
    'producer'::text AS scope_kind,
    producer_id AS scope_id,
    tenant_id,
    project_id,
    operation,
    tokens_micro,
    reserved_micro,
    capacity_micro,
    refill_micro_per_second,
    refill_remainder_numerator,
    rate_change_gate_id,
    last_refill_at,
    policy_version,
    updated_at,
    version
  FROM rq.producer_rate_buckets;

CREATE TABLE IF NOT EXISTS rq.tenant_send_reservations (
  attempt_id uuid NOT NULL REFERENCES rq.delivery_attempts(id),
  tenant_id uuid NOT NULL,
  operation text NOT NULL DEFAULT 'send_start' CHECK (operation = 'send_start'),
  reserved_micro bigint NOT NULL DEFAULT 1000000 CHECK (reserved_micro = 1000000),
  state text NOT NULL CHECK (state IN ('held', 'consumed', 'released')),
  held_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  released_at timestamptz NULL,
  version bigint NOT NULL DEFAULT 1 CHECK (version >= 1),
  PRIMARY KEY (attempt_id, tenant_id),
  FOREIGN KEY (tenant_id, operation) REFERENCES rq.tenant_rate_buckets(tenant_id, operation)
);

CREATE TABLE IF NOT EXISTS rq.project_send_reservations (
  attempt_id uuid NOT NULL REFERENCES rq.delivery_attempts(id),
  project_id uuid NOT NULL,
  operation text NOT NULL DEFAULT 'send_start' CHECK (operation = 'send_start'),
  reserved_micro bigint NOT NULL DEFAULT 1000000 CHECK (reserved_micro = 1000000),
  state text NOT NULL CHECK (state IN ('held', 'consumed', 'released')),
  held_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  released_at timestamptz NULL,
  version bigint NOT NULL DEFAULT 1 CHECK (version >= 1),
  PRIMARY KEY (attempt_id, project_id),
  FOREIGN KEY (project_id, operation) REFERENCES rq.project_rate_buckets(project_id, operation)
);

CREATE TABLE IF NOT EXISTS rq.endpoint_send_reservations (
  attempt_id uuid NOT NULL REFERENCES rq.delivery_attempts(id),
  endpoint_id uuid NOT NULL,
  operation text NOT NULL DEFAULT 'send_start' CHECK (operation = 'send_start'),
  reserved_micro bigint NOT NULL DEFAULT 1000000 CHECK (reserved_micro = 1000000),
  state text NOT NULL CHECK (state IN ('held', 'consumed', 'released')),
  held_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  released_at timestamptz NULL,
  version bigint NOT NULL DEFAULT 1 CHECK (version >= 1),
  PRIMARY KEY (attempt_id, endpoint_id),
  FOREIGN KEY (endpoint_id, operation) REFERENCES rq.endpoint_rate_buckets(endpoint_id, operation)
);

CREATE TABLE IF NOT EXISTS rq.delivery_history (
  delivery_id uuid NOT NULL,
  history_sequence bigint NOT NULL CHECK (history_sequence >= 1),
  tenant_id uuid NOT NULL,
  project_id uuid NOT NULL,
  kind text NOT NULL CHECK (pg_catalog.length(kind) BETWEEN 1 AND 128),
  recorded_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  attempt_id uuid NULL,
  command_receipt_id uuid NULL REFERENCES rq.command_receipts(id),
  safe_facts jsonb NOT NULL DEFAULT '{}'::jsonb,
  event_schema_version integer NOT NULL CHECK (event_schema_version >= 1),
  PRIMARY KEY (delivery_id, history_sequence),
  FOREIGN KEY (delivery_id, project_id, tenant_id) REFERENCES rq.deliveries(id, project_id, tenant_id),
  FOREIGN KEY (attempt_id, delivery_id, project_id, tenant_id) REFERENCES rq.delivery_attempts(id, delivery_id, project_id, tenant_id),
  CHECK (pg_catalog.jsonb_typeof(safe_facts) = 'object')
);
