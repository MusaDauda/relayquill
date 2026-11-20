-- Migration 0008: Late/deferred scoped FKs, immutability guards, operational indexes, SECURITY DEFINER command/read boundary, and strict per-role privilege lockdown.

-- 1. Late and deferred circular scoped foreign keys
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_constraint WHERE conname = 'fk_enrollment_intents_tenant') THEN
    ALTER TABLE rq.enrollment_intents
      ADD CONSTRAINT fk_enrollment_intents_tenant FOREIGN KEY (tenant_id) REFERENCES rq.tenants(id),
      ADD CONSTRAINT fk_enrollment_intents_project FOREIGN KEY (project_id, tenant_id) REFERENCES rq.projects(id, tenant_id);
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_constraint WHERE conname = 'fk_audit_events_tenant') THEN
    ALTER TABLE rq.audit_events
      ADD CONSTRAINT fk_audit_events_tenant FOREIGN KEY (tenant_id) REFERENCES rq.tenants(id),
      ADD CONSTRAINT fk_audit_events_project FOREIGN KEY (project_id, tenant_id) REFERENCES rq.projects(id, tenant_id),
      ADD CONSTRAINT fk_audit_events_command_receipt FOREIGN KEY (command_receipt_id) REFERENCES rq.command_receipts(id);
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_constraint WHERE conname = 'fk_operation_proofs_accepted_receipt') THEN
    ALTER TABLE rq.operation_proofs
      ADD CONSTRAINT fk_operation_proofs_accepted_receipt FOREIGN KEY (accepted_receipt_id) REFERENCES rq.command_receipts(id);
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_constraint WHERE conname = 'fk_producer_credential_intents_credential') THEN
    ALTER TABLE rq.producer_credential_intents
      ADD CONSTRAINT fk_producer_credential_intents_credential FOREIGN KEY (credential_id) REFERENCES rq.producer_credentials(id);
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_constraint WHERE conname = 'fk_projects_active_ordering_cutover') THEN
    ALTER TABLE rq.projects
      ADD CONSTRAINT fk_projects_active_ordering_cutover FOREIGN KEY (active_ordering_cutover_plan_id) REFERENCES rq.ordering_cutover_plans(id);
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_constraint WHERE conname = 'fk_endpoint_verification_intents_receiver_contract') THEN
    ALTER TABLE rq.endpoint_verification_intents
      ADD CONSTRAINT fk_endpoint_verification_intents_receiver_contract
      FOREIGN KEY (receiver_contract_id, receiver_contract_version, project_id, tenant_id, receiver_contract_sha256)
      REFERENCES rq.receiver_contract_versions(contract_id, contract_version, project_id, tenant_id, definition_sha256);
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_constraint WHERE conname = 'fk_subscription_versions_ordering_domain') THEN
    ALTER TABLE rq.subscription_versions
      ADD CONSTRAINT fk_subscription_versions_ordering_domain
      FOREIGN KEY (ordering_domain_id, project_id, tenant_id, subscription_id, consumer_contract_scope)
      REFERENCES rq.ordering_domains(id, project_id, tenant_id, subscription_id, consumer_contract_scope),
      ADD CONSTRAINT fk_subscription_versions_retry_policy
      FOREIGN KEY (retry_policy_version) REFERENCES rq.retry_policy_versions(policy_version),
      ADD CONSTRAINT fk_subscription_versions_receiver_contract
      FOREIGN KEY (receiver_contract_id, receiver_contract_version, project_id, tenant_id)
      REFERENCES rq.receiver_contract_versions(contract_id, contract_version, project_id, tenant_id);
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_constraint WHERE conname = 'fk_subscription_control_events_receipt') THEN
    ALTER TABLE rq.subscription_control_events
      ADD CONSTRAINT fk_subscription_control_events_receipt FOREIGN KEY (command_receipt_id) REFERENCES rq.command_receipts(id);
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_constraint WHERE conname = 'fk_event_payloads_retention_action') THEN
    ALTER TABLE rq.event_payloads
      ADD CONSTRAINT fk_event_payloads_retention_action FOREIGN KEY (retention_action_id) REFERENCES rq.retention_actions(id);
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_constraint WHERE conname = 'fk_event_wire_envelopes_retention_action') THEN
    ALTER TABLE rq.event_wire_envelopes
      ADD CONSTRAINT fk_event_wire_envelopes_retention_action FOREIGN KEY (retention_action_id) REFERENCES rq.retention_actions(id),
      ADD CONSTRAINT fk_event_wire_envelopes_profile_version
      FOREIGN KEY (profile_id, profile_version, project_id, tenant_id)
      REFERENCES rq.representation_profile_versions(profile_id, profile_version, project_id, tenant_id);
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_constraint WHERE conname = 'fk_outbox_publications_first_generation') THEN
    ALTER TABLE rq.outbox_publications
      ADD CONSTRAINT fk_outbox_publications_first_generation FOREIGN KEY (first_broker_generation_id) REFERENCES rq.broker_stream_generations(id),
      ADD CONSTRAINT fk_outbox_publications_first_observation FOREIGN KEY (first_observation_id) REFERENCES rq.publication_observations(id);
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_constraint WHERE conname = 'fk_fanout_outcomes_delivery') THEN
    ALTER TABLE rq.fanout_outcomes
      ADD CONSTRAINT fk_fanout_outcomes_delivery FOREIGN KEY (delivery_id, project_id, tenant_id) REFERENCES rq.deliveries(id, project_id, tenant_id);
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_constraint WHERE conname = 'fk_delivery_families_original_delivery') THEN
    ALTER TABLE rq.delivery_families
      ADD CONSTRAINT fk_delivery_families_original_delivery
      FOREIGN KEY (original_delivery_id) REFERENCES rq.deliveries(id) DEFERRABLE INITIALLY DEFERRED;
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_constraint WHERE conname = 'fk_deliveries_current_attempt') THEN
    ALTER TABLE rq.deliveries
      ADD CONSTRAINT fk_deliveries_current_attempt
      FOREIGN KEY (current_attempt_id) REFERENCES rq.delivery_attempts(id) DEFERRABLE INITIALLY DEFERRED,
      ADD CONSTRAINT fk_deliveries_replay_proposal
      FOREIGN KEY (replay_proposal_id) REFERENCES rq.replay_proposals(id);
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_constraint WHERE conname = 'fk_ordering_keys_domain') THEN
    ALTER TABLE rq.ordering_keys
      ADD CONSTRAINT fk_ordering_keys_domain
      FOREIGN KEY (ordering_domain_id, project_id, tenant_id, subscription_id, consumer_contract_scope)
      REFERENCES rq.ordering_domains(id, project_id, tenant_id, subscription_id, consumer_contract_scope),
      ADD CONSTRAINT fk_ordering_keys_blocked_delivery
      FOREIGN KEY (blocked_delivery_id) REFERENCES rq.deliveries(id);
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_constraint WHERE conname = 'fk_ordering_members_disposition') THEN
    ALTER TABLE rq.ordering_members
      ADD CONSTRAINT fk_ordering_members_disposition FOREIGN KEY (disposition_event_id) REFERENCES rq.order_dispositions(id);
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_constraint WHERE conname = 'fk_tenant_rate_buckets_gate') THEN
    ALTER TABLE rq.tenant_rate_buckets
      ADD CONSTRAINT fk_tenant_rate_buckets_gate FOREIGN KEY (rate_change_gate_id) REFERENCES rq.rate_policy_changes(id);
    ALTER TABLE rq.project_rate_buckets
      ADD CONSTRAINT fk_project_rate_buckets_gate FOREIGN KEY (rate_change_gate_id) REFERENCES rq.rate_policy_changes(id);
    ALTER TABLE rq.endpoint_rate_buckets
      ADD CONSTRAINT fk_endpoint_rate_buckets_gate FOREIGN KEY (rate_change_gate_id) REFERENCES rq.rate_policy_changes(id);
    ALTER TABLE rq.producer_rate_buckets
      ADD CONSTRAINT fk_producer_rate_buckets_gate FOREIGN KEY (rate_change_gate_id) REFERENCES rq.rate_policy_changes(id);
  END IF;
END
$$;

-- 2. Operational indexes
CREATE INDEX IF NOT EXISTS idx_events_project_seq_desc
  ON rq.events (project_id, project_event_sequence DESC);
CREATE INDEX IF NOT EXISTS idx_events_project_state_admitted
  ON rq.events (project_id, state, admitted_at DESC);
CREATE INDEX IF NOT EXISTS idx_events_project_type_admitted
  ON rq.events (project_id, event_type_id, admitted_at DESC);

CREATE INDEX IF NOT EXISTS idx_outbox_events_due_pending
  ON rq.outbox_events (state, next_publish_at, id)
  WHERE state IN ('pending', 'blocked');
CREATE INDEX IF NOT EXISTS idx_outbox_events_claimed_expiry
  ON rq.outbox_events (claim_expires_at)
  WHERE state = 'claimed';
CREATE INDEX IF NOT EXISTS idx_outbox_events_project_state
  ON rq.outbox_events (project_id, state);

CREATE INDEX IF NOT EXISTS idx_broker_inbox_project_state
  ON rq.broker_inbox (project_id, state, last_received_at);

CREATE INDEX IF NOT EXISTS idx_event_fanout_project_seq
  ON rq.event_fanout (project_id, project_event_sequence);
CREATE INDEX IF NOT EXISTS idx_event_fanout_claim_expiry
  ON rq.event_fanout (claim_expires_at)
  WHERE state = 'materializing';

CREATE INDEX IF NOT EXISTS idx_sub_topo_ranges_project_bounds
  ON rq.subscription_topology_ranges (project_id, from_topology_version, until_topology_version);

CREATE INDEX IF NOT EXISTS idx_deliveries_endpoint_eligible
  ON rq.deliveries (endpoint_id, state, next_eligible_at, created_at, id);
CREATE INDEX IF NOT EXISTS idx_deliveries_project_state_eligible
  ON rq.deliveries (project_id, state, next_eligible_at);
CREATE INDEX IF NOT EXISTS idx_deliveries_project_created_desc
  ON rq.deliveries (project_id, created_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_deliveries_nonterminal_deadline
  ON rq.deliveries (deadline_at)
  WHERE state IN ('pending', 'ready', 'sending', 'retry_wait');
CREATE INDEX IF NOT EXISTS idx_deliveries_event_generation
  ON rq.deliveries (event_id, delivery_generation);

CREATE INDEX IF NOT EXISTS idx_delivery_attempts_active_expiry
  ON rq.delivery_attempts (claim_expires_at)
  WHERE state IN ('prepared', 'send_started');
CREATE INDEX IF NOT EXISTS idx_delivery_attempts_delivery_num_desc
  ON rq.delivery_attempts (delivery_id, attempt_number DESC);
CREATE INDEX IF NOT EXISTS idx_delivery_attempts_worker_state
  ON rq.delivery_attempts (worker_instance_id, state);

CREATE INDEX IF NOT EXISTS idx_ordering_members_key_state_seq
  ON rq.ordering_members (ordering_key_id, state, ordering_sequence);

CREATE INDEX IF NOT EXISTS idx_endpoint_circuits_reopen
  ON rq.endpoint_circuits (state, reopen_not_before)
  WHERE state IN ('open', 'half_open');

CREATE INDEX IF NOT EXISTS idx_human_sessions_principal_state
  ON rq.human_sessions (principal_id, state, absolute_expires_at);
CREATE INDEX IF NOT EXISTS idx_producer_credentials_producer_state
  ON rq.producer_credentials (producer_id, state, expires_at);
CREATE INDEX IF NOT EXISTS idx_auth_challenges_pending_expiry
  ON rq.auth_challenges (expires_at)
  WHERE state = 'pending';
CREATE INDEX IF NOT EXISTS idx_enrollment_intents_preauth
  ON rq.enrollment_intents (preauth_context_id, state, expires_at);

CREATE INDEX IF NOT EXISTS idx_retention_actions_due
  ON rq.retention_actions (state, next_attempt_at)
  WHERE state IN ('ready', 'failed_retryable');
CREATE INDEX IF NOT EXISTS idx_retention_actions_claim_expiry
  ON rq.retention_actions (claim_expires_at)
  WHERE state = 'claimed';

CREATE INDEX IF NOT EXISTS idx_coordinator_tasks_due
  ON rq.coordinator_tasks (task_kind, state, not_before)
  WHERE state IN ('ready', 'failed_retryable');
CREATE INDEX IF NOT EXISTS idx_coordinator_tasks_claim_expiry
  ON rq.coordinator_tasks (claim_expires_at)
  WHERE state = 'claimed';

CREATE INDEX IF NOT EXISTS idx_watch_leases_open_expiry
  ON rq.watch_leases (expires_at)
  WHERE state = 'open';
CREATE INDEX IF NOT EXISTS idx_watch_leases_resource
  ON rq.watch_leases (resource_kind, resource_id, state);

CREATE INDEX IF NOT EXISTS idx_audit_events_scope_time
  ON rq.audit_events (tenant_id, project_id, recorded_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_events_target_time
  ON rq.audit_events (target_kind, target_id, recorded_at DESC);

CREATE INDEX IF NOT EXISTS idx_trace_references_resource
  ON rq.trace_references (project_id, resource_kind, resource_id, recorded_at DESC);

-- 3. Immutability trigger guards (owned by rq_owner, search_path = pg_catalog)
CREATE OR REPLACE FUNCTION rq._trg_immutable_row()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
  RAISE EXCEPTION 'Immutable record in %.% cannot be updated or deleted', TG_TABLE_SCHEMA, TG_TABLE_NAME
    USING ERRCODE = '55000';
END;
$$;

CREATE OR REPLACE FUNCTION rq._trg_events_immutable()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'Accepted rows in rq.events cannot be deleted' USING ERRCODE = '55000';
  END IF;
  IF NEW.id IS DISTINCT FROM OLD.id
     OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
     OR NEW.project_id IS DISTINCT FROM OLD.project_id
     OR NEW.producer_id IS DISTINCT FROM OLD.producer_id
     OR NEW.producer_namespace IS DISTINCT FROM OLD.producer_namespace
     OR NEW.business_key IS DISTINCT FROM OLD.business_key
     OR NEW.event_type_id IS DISTINCT FROM OLD.event_type_id
     OR NEW.event_schema_version IS DISTINCT FROM OLD.event_schema_version
     OR NEW.submitted_shape_sha256 IS DISTINCT FROM OLD.submitted_shape_sha256
     OR NEW.effective_request_sha256 IS DISTINCT FROM OLD.effective_request_sha256
     OR NEW.hash_schema_version IS DISTINCT FROM OLD.hash_schema_version
     OR NEW.content_sha256 IS DISTINCT FROM OLD.content_sha256
     OR NEW.content_byte_count IS DISTINCT FROM OLD.content_byte_count
     OR NEW.content_payload_id IS DISTINCT FROM OLD.content_payload_id
     OR NEW.topology_version IS DISTINCT FROM OLD.topology_version
     OR NEW.project_event_sequence IS DISTINCT FROM OLD.project_event_sequence
     OR NEW.producer_event_time IS DISTINCT FROM OLD.producer_event_time
     OR NEW.admitted_at IS DISTINCT FROM OLD.admitted_at
     OR NEW.delivery_deadline_at IS DISTINCT FROM OLD.delivery_deadline_at THEN
    RAISE EXCEPTION 'Immutable admission facts on rq.events cannot be modified' USING ERRCODE = '55000';
  END IF;
  RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION rq._trg_event_payloads_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'Rows in rq.event_payloads cannot be deleted' USING ERRCODE = '55000';
  END IF;
  IF NEW.id IS DISTINCT FROM OLD.id
     OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
     OR NEW.project_id IS DISTINCT FROM OLD.project_id
     OR NEW.content_sha256 IS DISTINCT FROM OLD.content_sha256
     OR NEW.byte_count IS DISTINCT FROM OLD.byte_count
     OR NEW.media_type IS DISTINCT FROM OLD.media_type
     OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
    RAISE EXCEPTION 'Immutable payload identity/hash/size cannot be modified' USING ERRCODE = '55000';
  END IF;
  IF OLD.retention_state = 'expired' THEN
    RAISE EXCEPTION 'Expired payload tombstone cannot be reopened or modified' USING ERRCODE = '55000';
  END IF;
  IF NEW.content IS DISTINCT FROM OLD.content AND NEW.retention_state <> 'expired' THEN
    RAISE EXCEPTION 'Payload bytes cannot be mutated outside retention expiry' USING ERRCODE = '55000';
  END IF;
  RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION rq._trg_event_wire_envelopes_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'Rows in rq.event_wire_envelopes cannot be deleted' USING ERRCODE = '55000';
  END IF;
  IF NEW.id IS DISTINCT FROM OLD.id
     OR NEW.event_id IS DISTINCT FROM OLD.event_id
     OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
     OR NEW.project_id IS DISTINCT FROM OLD.project_id
     OR NEW.representation_version IS DISTINCT FROM OLD.representation_version
     OR NEW.profile_id IS DISTINCT FROM OLD.profile_id
     OR NEW.profile_version IS DISTINCT FROM OLD.profile_version
     OR NEW.target_schema_version IS DISTINCT FROM OLD.target_schema_version
     OR NEW.source_content_sha256 IS DISTINCT FROM OLD.source_content_sha256
     OR NEW.body_sha256 IS DISTINCT FROM OLD.body_sha256
     OR NEW.byte_count IS DISTINCT FROM OLD.byte_count
     OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
    RAISE EXCEPTION 'Immutable wire envelope facts cannot be modified' USING ERRCODE = '55000';
  END IF;
  IF OLD.retention_state = 'expired' THEN
    RAISE EXCEPTION 'Expired wire envelope tombstone cannot be modified' USING ERRCODE = '55000';
  END IF;
  IF NEW.body_bytes IS DISTINCT FROM OLD.body_bytes AND NEW.retention_state <> 'expired' THEN
    RAISE EXCEPTION 'Wire bytes cannot be mutated outside retention expiry' USING ERRCODE = '55000';
  END IF;
  RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION rq._trg_event_schema_versions_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'Schema versions cannot be deleted' USING ERRCODE = '55000';
  END IF;
  IF OLD.state <> 'draft' THEN
    IF NEW.definition_bytes IS DISTINCT FROM OLD.definition_bytes
       OR NEW.definition_sha256 IS DISTINCT FROM OLD.definition_sha256
       OR NEW.normalized_profile IS DISTINCT FROM OLD.normalized_profile
       OR NEW.dialect IS DISTINCT FROM OLD.dialect
       OR NEW.profile_version IS DISTINCT FROM OLD.profile_version
       OR NEW.compatibility_policy IS DISTINCT FROM OLD.compatibility_policy
       OR NEW.published_at IS DISTINCT FROM OLD.published_at
       OR NEW.published_by IS DISTINCT FROM OLD.published_by
       OR (OLD.state = 'retired' AND NEW.state <> 'retired') THEN
      RAISE EXCEPTION 'Published/retired schema version definition is immutable' USING ERRCODE = '55000';
    END IF;
  END IF;
  RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION rq._trg_policy_versions_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'Policy versions cannot be deleted' USING ERRCODE = '55000';
  END IF;
  IF OLD.state <> 'draft' THEN
    IF NEW.definition_bytes IS DISTINCT FROM OLD.definition_bytes
       OR NEW.definition_sha256 IS DISTINCT FROM OLD.definition_sha256
       OR NEW.normalized_definition IS DISTINCT FROM OLD.normalized_definition
       OR NEW.activated_at IS DISTINCT FROM OLD.activated_at
       OR (OLD.state = 'retired' AND NEW.state <> 'retired') THEN
      RAISE EXCEPTION 'Published policy definition is immutable' USING ERRCODE = '55000';
    END IF;
  END IF;
  RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION rq._trg_endpoint_versions_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'Endpoint versions cannot be deleted' USING ERRCODE = '55000';
  END IF;
  IF OLD.activated_at IS NOT NULL OR OLD.verified_at IS NOT NULL THEN
    IF NEW.destination_url IS DISTINCT FROM OLD.destination_url
       OR NEW.normalized_hostname IS DISTINCT FROM OLD.normalized_hostname
       OR NEW.port IS DISTINCT FROM OLD.port
       OR NEW.path_and_query_sha256 IS DISTINCT FROM OLD.path_and_query_sha256
       OR NEW.url_policy_version IS DISTINCT FROM OLD.url_policy_version
       OR NEW.network_policy_version IS DISTINCT FROM OLD.network_policy_version
       OR NEW.request_profile_version IS DISTINCT FROM OLD.request_profile_version
       OR NEW.response_profile_version IS DISTINCT FROM OLD.response_profile_version
       OR NEW.configuration_sha256 IS DISTINCT FROM OLD.configuration_sha256 THEN
      RAISE EXCEPTION 'Verified/activated endpoint version configuration is immutable' USING ERRCODE = '55000';
    END IF;
  END IF;
  RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION rq._trg_subscription_versions_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'Subscription versions cannot be deleted' USING ERRCODE = '55000';
  END IF;
  IF OLD.activated_at IS NOT NULL THEN
    IF NEW.endpoint_id IS DISTINCT FROM OLD.endpoint_id
       OR NEW.endpoint_version IS DISTINCT FROM OLD.endpoint_version
       OR NEW.event_type_id IS DISTINCT FROM OLD.event_type_id
       OR NEW.filter_ast IS DISTINCT FROM OLD.filter_ast
       OR NEW.filter_sha256 IS DISTINCT FROM OLD.filter_sha256
       OR NEW.ordering_mode IS DISTINCT FROM OLD.ordering_mode
       OR NEW.ordering_domain_id IS DISTINCT FROM OLD.ordering_domain_id
       OR NEW.ordering_extractor IS DISTINCT FROM OLD.ordering_extractor
       OR NEW.ordering_extractor_sha256 IS DISTINCT FROM OLD.ordering_extractor_sha256
       OR NEW.retry_policy_version IS DISTINCT FROM OLD.retry_policy_version
       OR NEW.response_policy_version IS DISTINCT FROM OLD.response_policy_version
       OR NEW.consumer_contract_scope IS DISTINCT FROM OLD.consumer_contract_scope
       OR NEW.receiver_contract_id IS DISTINCT FROM OLD.receiver_contract_id
       OR NEW.receiver_contract_version IS DISTINCT FROM OLD.receiver_contract_version
       OR NEW.configuration_sha256 IS DISTINCT FROM OLD.configuration_sha256 THEN
      RAISE EXCEPTION 'Activated subscription version configuration is immutable' USING ERRCODE = '55000';
    END IF;
  END IF;
  RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION rq._trg_producer_scope_versions_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'Producer scope versions cannot be deleted' USING ERRCODE = '55000';
  END IF;
  IF OLD.state <> 'draft' THEN
    IF NEW.scope_definition IS DISTINCT FROM OLD.scope_definition
       OR NEW.scope_sha256 IS DISTINCT FROM OLD.scope_sha256
       OR NEW.published_by IS DISTINCT FROM OLD.published_by THEN
      RAISE EXCEPTION 'Approved/active producer scope definition is immutable' USING ERRCODE = '55000';
    END IF;
  END IF;
  RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION rq._trg_representation_profile_versions_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'Representation profile versions cannot be deleted' USING ERRCODE = '55000';
  END IF;
  IF OLD.published_at IS NOT NULL THEN
    IF NEW.definition_bytes IS DISTINCT FROM OLD.definition_bytes
       OR NEW.definition_sha256 IS DISTINCT FROM OLD.definition_sha256
       OR NEW.normalized_mapping IS DISTINCT FROM OLD.normalized_mapping
       OR NEW.source_schema_version IS DISTINCT FROM OLD.source_schema_version
       OR NEW.target_schema_version IS DISTINCT FROM OLD.target_schema_version
       OR NEW.proven_output_max_bytes IS DISTINCT FROM OLD.proven_output_max_bytes THEN
      RAISE EXCEPTION 'Published representation profile version is immutable' USING ERRCODE = '55000';
    END IF;
  END IF;
  RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION rq._trg_receiver_contract_versions_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'Receiver contract versions cannot be deleted' USING ERRCODE = '55000';
  END IF;
  IF OLD.verified_at IS NOT NULL THEN
    IF NEW.definition_bytes IS DISTINCT FROM OLD.definition_bytes
       OR NEW.definition_sha256 IS DISTINCT FROM OLD.definition_sha256
       OR NEW.receipt_profile IS DISTINCT FROM OLD.receipt_profile
       OR NEW.ordering_profile IS DISTINCT FROM OLD.ordering_profile
       OR NEW.minimum_inbox_retention_seconds IS DISTINCT FROM OLD.minimum_inbox_retention_seconds THEN
      RAISE EXCEPTION 'Verified receiver contract version is immutable' USING ERRCODE = '55000';
    END IF;
  END IF;
  RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION rq._trg_signing_policies_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'Signing policies cannot be deleted' USING ERRCODE = '55000';
  END IF;
  IF OLD.activated_at IS NOT NULL THEN
    IF NEW.primary_key_version_id IS DISTINCT FROM OLD.primary_key_version_id
       OR NEW.overlap_key_version_id IS DISTINCT FROM OLD.overlap_key_version_id
       OR NEW.signature_mode IS DISTINCT FROM OLD.signature_mode
       OR NEW.overlap_until IS DISTINCT FROM OLD.overlap_until
       OR NEW.policy_sha256 IS DISTINCT FROM OLD.policy_sha256 THEN
      RAISE EXCEPTION 'Activated signing policy is immutable' USING ERRCODE = '55000';
    END IF;
  END IF;
  RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION rq._trg_outbox_publications_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'Outbox publications cannot be deleted' USING ERRCODE = '55000';
  END IF;
  IF NEW.envelope_version IS DISTINCT FROM OLD.envelope_version
     OR NEW.envelope_bytes IS DISTINCT FROM OLD.envelope_bytes
     OR NEW.envelope_sha256 IS DISTINCT FROM OLD.envelope_sha256
     OR NEW.broker_message_id IS DISTINCT FROM OLD.broker_message_id THEN
    RAISE EXCEPTION 'Outbox publication envelope/message identity is immutable' USING ERRCODE = '55000';
  END IF;
  IF OLD.first_observation_id IS NOT NULL THEN
    IF NEW.first_broker_generation_id IS DISTINCT FROM OLD.first_broker_generation_id
       OR NEW.first_observation_id IS DISTINCT FROM OLD.first_observation_id
       OR NEW.stream_name IS DISTINCT FROM OLD.stream_name
       OR NEW.stream_sequence IS DISTINCT FROM OLD.stream_sequence
       OR NEW.ack_observed_at IS DISTINCT FROM OLD.ack_observed_at THEN
      RAISE EXCEPTION 'First observed broker publication identity cannot be overwritten' USING ERRCODE = '55000';
    END IF;
  END IF;
  RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION rq._trg_subscription_topology_ranges_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'Subscription topology ranges cannot be deleted' USING ERRCODE = '55000';
  END IF;
  IF NEW.project_id IS DISTINCT FROM OLD.project_id
     OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
     OR NEW.subscription_id IS DISTINCT FROM OLD.subscription_id
     OR NEW.subscription_version IS DISTINCT FROM OLD.subscription_version
     OR NEW.from_topology_version IS DISTINCT FROM OLD.from_topology_version
     OR NEW.activation_event_id IS DISTINCT FROM OLD.activation_event_id
     OR OLD.until_topology_version IS NOT NULL THEN
    RAISE EXCEPTION 'Closed or immutable topology range fields cannot be modified' USING ERRCODE = '55000';
  END IF;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_events_immutable ON rq.events;
CREATE TRIGGER trg_events_immutable BEFORE UPDATE OR DELETE ON rq.events
  FOR EACH ROW EXECUTE FUNCTION rq._trg_events_immutable();

DROP TRIGGER IF EXISTS trg_event_payloads_guard ON rq.event_payloads;
CREATE TRIGGER trg_event_payloads_guard BEFORE UPDATE OR DELETE ON rq.event_payloads
  FOR EACH ROW EXECUTE FUNCTION rq._trg_event_payloads_guard();

DROP TRIGGER IF EXISTS trg_event_wire_envelopes_guard ON rq.event_wire_envelopes;
CREATE TRIGGER trg_event_wire_envelopes_guard BEFORE UPDATE OR DELETE ON rq.event_wire_envelopes
  FOR EACH ROW EXECUTE FUNCTION rq._trg_event_wire_envelopes_guard();

DROP TRIGGER IF EXISTS trg_event_schema_versions_guard ON rq.event_schema_versions;
CREATE TRIGGER trg_event_schema_versions_guard BEFORE UPDATE OR DELETE ON rq.event_schema_versions
  FOR EACH ROW EXECUTE FUNCTION rq._trg_event_schema_versions_guard();

DROP TRIGGER IF EXISTS trg_policy_versions_guard ON rq.policy_versions;
CREATE TRIGGER trg_policy_versions_guard BEFORE UPDATE OR DELETE ON rq.policy_versions
  FOR EACH ROW EXECUTE FUNCTION rq._trg_policy_versions_guard();

DROP TRIGGER IF EXISTS trg_endpoint_versions_guard ON rq.endpoint_versions;
CREATE TRIGGER trg_endpoint_versions_guard BEFORE UPDATE OR DELETE ON rq.endpoint_versions
  FOR EACH ROW EXECUTE FUNCTION rq._trg_endpoint_versions_guard();

DROP TRIGGER IF EXISTS trg_subscription_versions_guard ON rq.subscription_versions;
CREATE TRIGGER trg_subscription_versions_guard BEFORE UPDATE OR DELETE ON rq.subscription_versions
  FOR EACH ROW EXECUTE FUNCTION rq._trg_subscription_versions_guard();

DROP TRIGGER IF EXISTS trg_producer_scope_versions_guard ON rq.producer_scope_versions;
CREATE TRIGGER trg_producer_scope_versions_guard BEFORE UPDATE OR DELETE ON rq.producer_scope_versions
  FOR EACH ROW EXECUTE FUNCTION rq._trg_producer_scope_versions_guard();

DROP TRIGGER IF EXISTS trg_representation_profile_versions_guard ON rq.representation_profile_versions;
CREATE TRIGGER trg_representation_profile_versions_guard BEFORE UPDATE OR DELETE ON rq.representation_profile_versions
  FOR EACH ROW EXECUTE FUNCTION rq._trg_representation_profile_versions_guard();

DROP TRIGGER IF EXISTS trg_receiver_contract_versions_guard ON rq.receiver_contract_versions;
CREATE TRIGGER trg_receiver_contract_versions_guard BEFORE UPDATE OR DELETE ON rq.receiver_contract_versions
  FOR EACH ROW EXECUTE FUNCTION rq._trg_receiver_contract_versions_guard();

DROP TRIGGER IF EXISTS trg_signing_policies_guard ON rq.signing_policies;
CREATE TRIGGER trg_signing_policies_guard BEFORE UPDATE OR DELETE ON rq.signing_policies
  FOR EACH ROW EXECUTE FUNCTION rq._trg_signing_policies_guard();

DROP TRIGGER IF EXISTS trg_outbox_publications_guard ON rq.outbox_publications;
CREATE TRIGGER trg_outbox_publications_guard BEFORE UPDATE OR DELETE ON rq.outbox_publications
  FOR EACH ROW EXECUTE FUNCTION rq._trg_outbox_publications_guard();

DROP TRIGGER IF EXISTS trg_subscription_topology_ranges_guard ON rq.subscription_topology_ranges;
CREATE TRIGGER trg_subscription_topology_ranges_guard BEFORE UPDATE OR DELETE ON rq.subscription_topology_ranges
  FOR EACH ROW EXECUTE FUNCTION rq._trg_subscription_topology_ranges_guard();

-- Strictly append-only tables
DO $$
DECLARE
  v_tbl text;
BEGIN
  FOREACH v_tbl IN ARRAY ARRAY[
    'business_event_anchors',
    'command_receipts',
    'event_history',
    'delivery_history',
    'audit_events',
    'publication_observations',
    'endpoint_verification_events',
    'fanout_outcomes',
    'late_delivery_observations',
    'delivery_retry_decisions',
    'order_dispositions',
    'representation_provenance',
    'subscription_control_events'
  ] LOOP
    EXECUTE pg_catalog.format('DROP TRIGGER IF EXISTS trg_%I_append_only ON rq.%I', v_tbl, v_tbl);
    EXECUTE pg_catalog.format(
      'CREATE TRIGGER trg_%I_append_only BEFORE UPDATE OR DELETE ON rq.%I FOR EACH ROW EXECUTE FUNCTION rq._trg_immutable_row()',
      v_tbl,
      v_tbl
    );
  END LOOP;
END
$$;

-- 4. Private internal helpers (no runtime EXECUTE)
CREATE OR REPLACE FUNCTION rq._assert_session_role(p_allowed_roles text[])
RETURNS void
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
DECLARE
  v_is_super boolean := false;
BEGIN
  IF session_user::text = ANY (p_allowed_roles) THEN
    RETURN;
  END IF;

  SELECT r.rolsuper
    INTO v_is_super
    FROM pg_catalog.pg_roles r
   WHERE r.rolname = session_user::text;

  IF COALESCE(v_is_super, false) THEN
    RETURN;
  END IF;

  RAISE EXCEPTION 'Session identity "%" is not authorized for this command', session_user
    USING ERRCODE = '42501';
END;
$$;

CREATE OR REPLACE FUNCTION rq._delivery_shard(p_delivery_id uuid)
RETURNS smallint
LANGUAGE sql
IMMUTABLE
STRICT
SET search_path = pg_catalog
AS $$
  SELECT ((pg_catalog.get_byte(pg_catalog.uuid_send(p_delivery_id), 15)) & 15)::smallint;
$$;

CREATE OR REPLACE FUNCTION rq._refill_micro_tokens(
  p_tokens_micro bigint,
  p_capacity_micro bigint,
  p_refill_micro_per_sec bigint,
  p_remainder_num bigint,
  p_last_refill_at timestamptz,
  p_now timestamptz
)
RETURNS TABLE (
  new_tokens_micro bigint,
  new_remainder_num bigint,
  new_last_refill_at timestamptz
)
LANGUAGE plpgsql
IMMUTABLE
STRICT
SET search_path = pg_catalog
AS $$
DECLARE
  v_elapsed_us numeric(38, 0);
  v_numerator numeric(38, 0);
  v_added bigint;
  v_rem bigint;
  v_tokens bigint;
BEGIN
  IF p_now <= p_last_refill_at THEN
    new_tokens_micro := LEAST(p_capacity_micro, p_tokens_micro);
    new_remainder_num := CASE WHEN new_tokens_micro >= p_capacity_micro THEN 0 ELSE p_remainder_num END;
    new_last_refill_at := p_last_refill_at;
    RETURN NEXT;
    RETURN;
  END IF;

  v_elapsed_us := pg_catalog.trunc(EXTRACT(EPOCH FROM (p_now - p_last_refill_at)) * 1000000::numeric);
  IF v_elapsed_us < 0 THEN
    v_elapsed_us := 0;
  END IF;

  v_numerator := v_elapsed_us * p_refill_micro_per_sec::numeric + p_remainder_num::numeric;
  v_added := LEAST(
    p_capacity_micro::numeric,
    pg_catalog.floor(v_numerator / 1000000::numeric)
  )::bigint;
  v_rem := pg_catalog.mod(v_numerator, 1000000::numeric)::bigint;

  IF p_tokens_micro + v_added >= p_capacity_micro THEN
    new_tokens_micro := p_capacity_micro;
    new_remainder_num := 0;
  ELSE
    new_tokens_micro := p_tokens_micro + v_added;
    new_remainder_num := v_rem;
  END IF;
  new_last_refill_at := p_now;
  RETURN NEXT;
END;
$$;

-- 5. SECURITY DEFINER runtime command functions (owned by rq_owner, search_path = pg_catalog)
CREATE OR REPLACE FUNCTION rq.cmd_runtime_register(
  p_instance_id uuid,
  p_process_role text,
  p_database_role text,
  p_control_epoch uuid,
  p_build_reference text,
  p_lease_ms bigint,
  p_approved_slots integer DEFAULT 8
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  v_gate rq.installation_state%ROWTYPE;
  v_now timestamptz;
  v_expires_at timestamptz;
  v_is_super boolean := false;
BEGIN
  PERFORM rq._assert_session_role(ARRAY['rq_api', 'rq_relay', 'rq_fanout', 'rq_sender', 'rq_coordinator', 'rq_signing_issuer', 'rq_recovery']);

  SELECT r.rolsuper INTO v_is_super
    FROM pg_catalog.pg_roles r
   WHERE r.rolname = session_user::text;

  IF NOT COALESCE(v_is_super, false) AND p_database_role <> session_user::text THEN
    RAISE EXCEPTION 'Database role "%" does not match authenticated session "%"', p_database_role, session_user
      USING ERRCODE = '42501';
  END IF;

  SELECT * INTO v_gate FROM rq.installation_state WHERE id = 1 FOR SHARE;
  IF NOT FOUND OR v_gate.control_epoch <> p_control_epoch THEN
    RAISE EXCEPTION 'Control epoch mismatch during runtime registration' USING ERRCODE = '55000';
  END IF;

  v_now := pg_catalog.clock_timestamp();
  v_expires_at := v_now + (GREATEST(1000::bigint, p_lease_ms)::text || ' milliseconds')::interval;

  INSERT INTO rq.runtime_instances (
    id, process_role, database_role, control_epoch, build_reference, state, started_at, last_seen_at, expires_at, version
  ) VALUES (
    p_instance_id, p_process_role, p_database_role, p_control_epoch, p_build_reference, 'active', v_now, v_now, v_expires_at, 1
  )
  ON CONFLICT (id) DO NOTHING;

  IF p_process_role = 'sender' THEN
    INSERT INTO rq.sender_instances (
      id, process_nonce_digest, build_reference, control_epoch, state, approved_slots, started_at, last_seen_at, expires_at, version
    ) VALUES (
      p_instance_id, pg_catalog.sha256(pg_catalog.uuid_send(p_instance_id)), p_build_reference, p_control_epoch, 'active', p_approved_slots, v_now, v_now, v_expires_at, 1
    )
    ON CONFLICT (id) DO NOTHING;

    INSERT INTO rq.sender_capacity (instance_id, approved_slots, held_slots, updated_at, version)
    VALUES (p_instance_id, p_approved_slots, 0, v_now, 1)
    ON CONFLICT (instance_id) DO NOTHING;
  END IF;

  RETURN pg_catalog.jsonb_build_object(
    'instance_id', p_instance_id,
    'process_role', p_process_role,
    'control_epoch', p_control_epoch,
    'expires_at', v_expires_at
  );
END;
$$;

CREATE OR REPLACE FUNCTION rq.cmd_runtime_heartbeat(
  p_instance_id uuid,
  p_control_epoch uuid,
  p_lease_ms bigint
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  v_gate rq.installation_state%ROWTYPE;
  v_inst rq.runtime_instances%ROWTYPE;
  v_now timestamptz;
  v_expires_at timestamptz;
BEGIN
  PERFORM rq._assert_session_role(ARRAY['rq_api', 'rq_relay', 'rq_fanout', 'rq_sender', 'rq_coordinator', 'rq_signing_issuer', 'rq_recovery']);

  SELECT * INTO v_gate FROM rq.installation_state WHERE id = 1 FOR SHARE;
  SELECT * INTO v_inst FROM rq.runtime_instances WHERE id = p_instance_id FOR UPDATE;
  IF NOT FOUND OR v_gate.control_epoch <> p_control_epoch OR v_inst.control_epoch <> p_control_epoch OR v_inst.state IN ('quarantined', 'ended') THEN
    RAISE EXCEPTION 'Runtime instance cannot renew lease in current epoch or state' USING ERRCODE = '55000';
  END IF;

  v_now := pg_catalog.clock_timestamp();
  v_expires_at := v_now + (GREATEST(1000::bigint, p_lease_ms)::text || ' milliseconds')::interval;

  UPDATE rq.runtime_instances
     SET last_seen_at = v_now,
         expires_at = v_expires_at,
         version = version + 1
   WHERE id = p_instance_id;

  IF v_inst.process_role = 'sender' THEN
    UPDATE rq.sender_instances
       SET last_seen_at = v_now,
           expires_at = v_expires_at,
           version = version + 1
     WHERE id = p_instance_id AND state IN ('active', 'draining');
  END IF;

  RETURN pg_catalog.jsonb_build_object(
    'instance_id', p_instance_id,
    'state', v_inst.state,
    'expires_at', v_expires_at,
    'version', v_inst.version + 1
  );
END;
$$;

CREATE OR REPLACE FUNCTION rq.cmd_event_admit(
  p_tenant_id uuid,
  p_project_id uuid,
  p_actor_principal_id uuid,
  p_producer_id uuid,
  p_producer_namespace text,
  p_business_key text,
  p_business_key_sha256 bytea,
  p_idempotency_key_sha256 bytea,
  p_submitted_shape_sha256 bytea,
  p_effective_request_sha256 bytea,
  p_event_type_id uuid,
  p_event_schema_version integer,
  p_content bytea,
  p_content_sha256 bytea,
  p_wire_envelope_bytes bytea,
  p_wire_envelope_sha256 bytea,
  p_broker_envelope_bytes bytea,
  p_broker_envelope_sha256 bytea,
  p_producer_event_time timestamptz,
  p_delivery_deadline_at timestamptz,
  p_applied_defaults jsonb,
  p_retention_policy_version text,
  p_event_id uuid,
  p_payload_id uuid,
  p_wire_envelope_id uuid,
  p_outbox_id uuid,
  p_receipt_id uuid,
  p_audit_id uuid
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  v_gate rq.installation_state%ROWTYPE;
  v_tenant rq.tenants%ROWTYPE;
  v_project rq.projects%ROWTYPE;
  v_existing_receipt rq.command_receipts%ROWTYPE;
  v_existing_anchor rq.business_event_anchors%ROWTYPE;
  v_existing_event rq.events%ROWTYPE;
  v_tcap rq.tenant_capacity%ROWTYPE;
  v_pcap rq.project_capacity%ROWTYPE;
  v_tbucket rq.tenant_rate_buckets%ROWTYPE;
  v_pbucket rq.project_rate_buckets%ROWTYPE;
  v_prbucket rq.producer_rate_buckets%ROWTYPE;
  v_refill record;
  v_now timestamptz;
  v_candidate_count bigint := 0;
  v_seq bigint;
  v_total_bytes bigint;
  v_guard_hash bytea;
  v_guard_key bigint;
BEGIN
  PERFORM rq._assert_session_role(ARRAY['rq_api']);

  -- Rank 1: Installation gate (FOR SHARE)
  SELECT * INTO v_gate FROM rq.installation_state WHERE id = 1 FOR SHARE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'Installation gate missing' USING ERRCODE = '55000';
  END IF;

  -- Rank 4: Tenant (FOR SHARE) and Project (FOR UPDATE for sequence/control serialization)
  SELECT * INTO v_tenant FROM rq.tenants WHERE id = p_tenant_id FOR SHARE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'Tenant not found' USING ERRCODE = 'P0002';
  END IF;

  SELECT * INTO v_project FROM rq.projects WHERE id = p_project_id AND tenant_id = p_tenant_id FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'Project not found' USING ERRCODE = 'P0002';
  END IF;

  -- Rank 6: Scoped command guard
  v_guard_hash := pg_catalog.sha256(
    pg_catalog.convert_to('events.admit:' || p_project_id::text || ':' || p_actor_principal_id::text, 'UTF8') || p_idempotency_key_sha256
  );
  v_guard_key := (
    (pg_catalog.get_byte(v_guard_hash, 0)::bigint << 56)
    | (pg_catalog.get_byte(v_guard_hash, 1)::bigint << 48)
    | (pg_catalog.get_byte(v_guard_hash, 2)::bigint << 40)
    | (pg_catalog.get_byte(v_guard_hash, 3)::bigint << 32)
    | (pg_catalog.get_byte(v_guard_hash, 4)::bigint << 24)
    | (pg_catalog.get_byte(v_guard_hash, 5)::bigint << 16)
    | (pg_catalog.get_byte(v_guard_hash, 6)::bigint << 8)
    | pg_catalog.get_byte(v_guard_hash, 7)::bigint
  );
  PERFORM pg_catalog.pg_advisory_xact_lock(v_guard_key);

  -- Preflight accepted-result recovery before new-write gates
  SELECT * INTO v_existing_receipt
    FROM rq.command_receipts
   WHERE scope_kind = 'project'
     AND project_id = p_project_id
     AND actor_principal_id = p_actor_principal_id
     AND command_family = 'events.admit'
     AND key_sha256 = p_idempotency_key_sha256;

  IF FOUND THEN
    IF v_existing_receipt.submitted_shape_sha256 <> p_submitted_shape_sha256 THEN
      RAISE EXCEPTION 'Idempotency key reused with conflicting request shape' USING ERRCODE = '23505';
    END IF;
    SELECT * INTO v_existing_event FROM rq.events WHERE id = v_existing_receipt.resource_id;
    RETURN pg_catalog.jsonb_build_object(
      'outcome', 'idempotent_recovery',
      'event_id', v_existing_event.id,
      'receipt_id', v_existing_receipt.id,
      'project_event_sequence', v_existing_event.project_event_sequence,
      'topology_version', v_existing_event.topology_version,
      'admitted_at', v_existing_event.admitted_at,
      'delivery_deadline_at', v_existing_event.delivery_deadline_at,
      'state', v_existing_event.state,
      'applied_defaults', v_existing_receipt.applied_defaults
    );
  END IF;

  SELECT * INTO v_existing_anchor
    FROM rq.business_event_anchors
   WHERE project_id = p_project_id
     AND producer_namespace = p_producer_namespace
     AND business_key_sha256 = p_business_key_sha256;

  IF FOUND THEN
    IF v_existing_anchor.submitted_shape_sha256 <> p_submitted_shape_sha256 THEN
      RAISE EXCEPTION 'Business key conflict with changed submission' USING ERRCODE = '23505';
    END IF;
    SELECT * INTO v_existing_event FROM rq.events WHERE id = v_existing_anchor.event_id;
    RETURN pg_catalog.jsonb_build_object(
      'outcome', 'business_anchor_recovery',
      'event_id', v_existing_anchor.event_id,
      'receipt_id', NULL,
      'project_event_sequence', v_existing_anchor.original_project_sequence,
      'topology_version', v_existing_event.topology_version,
      'admitted_at', v_existing_anchor.accepted_at,
      'delivery_deadline_at', v_existing_event.delivery_deadline_at,
      'state', v_existing_event.state,
      'applied_defaults', v_existing_anchor.applied_defaults
    );
  END IF;

  -- New-write gates checked after locks
  IF v_gate.mode <> 'open' OR NOT v_gate.allow_event_admission THEN
    RAISE EXCEPTION 'Installation event admission is closed' USING ERRCODE = '55000';
  END IF;
  IF v_tenant.state <> 'active' OR v_project.state <> 'active' THEN
    RAISE EXCEPTION 'Tenant or project is not active for admission' USING ERRCODE = '55000';
  END IF;
  IF v_project.active_ordering_cutover_plan_id IS NOT NULL OR v_project.projection_maintenance_operation_id IS NOT NULL THEN
    RAISE EXCEPTION 'Project admission fenced by cutover or projection maintenance' USING ERRCODE = '55000';
  END IF;

  -- Count historical candidates at captured topology version
  SELECT pg_catalog.count(*)
    INTO v_candidate_count
    FROM rq.subscription_topology_ranges str
    JOIN rq.subscription_versions sv
      ON sv.subscription_id = str.subscription_id
     AND sv.subscription_version = str.subscription_version
     AND sv.project_id = str.project_id
     AND sv.tenant_id = str.tenant_id
   WHERE str.project_id = p_project_id
     AND str.tenant_id = p_tenant_id
     AND sv.event_type_id = p_event_type_id
     AND str.from_topology_version <= v_project.topology_version
     AND (str.until_topology_version IS NULL OR v_project.topology_version < str.until_topology_version);

  -- Capacity & rate bucket ranks (tenant -> project -> producer)
  SELECT * INTO v_tcap FROM rq.tenant_capacity WHERE tenant_id = p_tenant_id FOR UPDATE;
  SELECT * INTO v_pcap FROM rq.project_capacity WHERE project_id = p_project_id FOR UPDATE;
  SELECT * INTO v_tbucket FROM rq.tenant_rate_buckets WHERE tenant_id = p_tenant_id AND operation = 'event_admission' FOR UPDATE;
  SELECT * INTO v_pbucket FROM rq.project_rate_buckets WHERE project_id = p_project_id AND operation = 'event_admission' FOR UPDATE;
  SELECT * INTO v_prbucket FROM rq.producer_rate_buckets WHERE producer_id = p_producer_id AND operation = 'event_admission' FOR UPDATE;

  v_now := pg_catalog.clock_timestamp();
  v_total_bytes := pg_catalog.octet_length(p_content)::bigint + pg_catalog.octet_length(p_wire_envelope_bytes)::bigint;

  IF v_tcap.pending_events + 1 > v_tcap.max_pending_events
     OR v_tcap.unmaterialized_candidate_slots + v_tcap.pending_deliveries + v_candidate_count > v_tcap.max_downstream_obligations
     OR v_tcap.retained_payload_bytes + v_tcap.reserved_payload_bytes + v_total_bytes > v_tcap.max_retained_payload_bytes THEN
    RAISE EXCEPTION 'Tenant capacity limit exceeded' USING ERRCODE = '53400';
  END IF;

  IF v_pcap.pending_events + 1 > v_pcap.max_pending_events
     OR v_pcap.unmaterialized_candidate_slots + v_pcap.pending_deliveries + v_candidate_count > v_pcap.max_downstream_obligations
     OR v_pcap.retained_payload_bytes + v_pcap.reserved_payload_bytes + v_total_bytes > v_pcap.max_retained_payload_bytes THEN
    RAISE EXCEPTION 'Project capacity limit exceeded' USING ERRCODE = '53400';
  END IF;

  IF v_tbucket.rate_change_gate_id IS NOT NULL OR v_pbucket.rate_change_gate_id IS NOT NULL OR v_prbucket.rate_change_gate_id IS NOT NULL THEN
    RAISE EXCEPTION 'Admission bucket gated by pending rate change' USING ERRCODE = '55000';
  END IF;

  SELECT * INTO v_refill FROM rq._refill_micro_tokens(
    v_tbucket.tokens_micro, v_tbucket.capacity_micro, v_tbucket.refill_micro_per_second, v_tbucket.refill_remainder_numerator, v_tbucket.last_refill_at, v_now
  );
  IF v_refill.new_tokens_micro - v_tbucket.reserved_micro < 1000000 THEN
    RAISE EXCEPTION 'Tenant admission rate limit exceeded' USING ERRCODE = '53400';
  END IF;
  UPDATE rq.tenant_rate_buckets
     SET tokens_micro = v_refill.new_tokens_micro - 1000000,
         refill_remainder_numerator = v_refill.new_remainder_num,
         last_refill_at = v_refill.new_last_refill_at,
         updated_at = v_now,
         version = version + 1
   WHERE tenant_id = p_tenant_id AND operation = 'event_admission';

  SELECT * INTO v_refill FROM rq._refill_micro_tokens(
    v_pbucket.tokens_micro, v_pbucket.capacity_micro, v_pbucket.refill_micro_per_second, v_pbucket.refill_remainder_numerator, v_pbucket.last_refill_at, v_now
  );
  IF v_refill.new_tokens_micro - v_pbucket.reserved_micro < 1000000 THEN
    RAISE EXCEPTION 'Project admission rate limit exceeded' USING ERRCODE = '53400';
  END IF;
  UPDATE rq.project_rate_buckets
     SET tokens_micro = v_refill.new_tokens_micro - 1000000,
         refill_remainder_numerator = v_refill.new_remainder_num,
         last_refill_at = v_refill.new_last_refill_at,
         updated_at = v_now,
         version = version + 1
   WHERE project_id = p_project_id AND operation = 'event_admission';

  SELECT * INTO v_refill FROM rq._refill_micro_tokens(
    v_prbucket.tokens_micro, v_prbucket.capacity_micro, v_prbucket.refill_micro_per_second, v_prbucket.refill_remainder_numerator, v_prbucket.last_refill_at, v_now
  );
  IF v_refill.new_tokens_micro - v_prbucket.reserved_micro < 1000000 THEN
    RAISE EXCEPTION 'Producer admission rate limit exceeded' USING ERRCODE = '53400';
  END IF;
  UPDATE rq.producer_rate_buckets
     SET tokens_micro = v_refill.new_tokens_micro - 1000000,
         refill_remainder_numerator = v_refill.new_remainder_num,
         last_refill_at = v_refill.new_last_refill_at,
         updated_at = v_now,
         version = version + 1
   WHERE producer_id = p_producer_id AND operation = 'event_admission';

  v_seq := v_project.next_event_sequence;

  UPDATE rq.projects
     SET next_event_sequence = next_event_sequence + 1,
         updated_at = v_now,
         version = version + 1
   WHERE id = p_project_id;

  INSERT INTO rq.event_payloads (
    id, tenant_id, project_id, content, content_sha256, byte_count, media_type, created_at, retention_state
  ) VALUES (
    p_payload_id, p_tenant_id, p_project_id, p_content, p_content_sha256, pg_catalog.octet_length(p_content), 'application/json', v_now, 'required'
  );

  INSERT INTO rq.events (
    id, tenant_id, project_id, producer_id, producer_namespace, business_key, event_type_id, event_schema_version,
    submitted_shape_sha256, effective_request_sha256, hash_schema_version, content_sha256, content_byte_count,
    content_payload_id, topology_version, project_event_sequence, state, producer_event_time, admitted_at,
    delivery_deadline_at, next_history_sequence, version
  ) VALUES (
    p_event_id, p_tenant_id, p_project_id, p_producer_id, p_producer_namespace, p_business_key, p_event_type_id, p_event_schema_version,
    p_submitted_shape_sha256, p_effective_request_sha256, 1, p_content_sha256, pg_catalog.octet_length(p_content),
    p_payload_id, v_project.topology_version, v_seq, 'accepted', p_producer_event_time, v_now,
    p_delivery_deadline_at, 1, 1
  );

  INSERT INTO rq.event_wire_envelopes (
    id, event_id, tenant_id, project_id, representation_version, source_content_sha256, body_bytes, body_sha256, byte_count, created_at, retention_state
  ) VALUES (
    p_wire_envelope_id, p_event_id, p_tenant_id, p_project_id, 1, p_content_sha256, p_wire_envelope_bytes, p_wire_envelope_sha256, pg_catalog.octet_length(p_wire_envelope_bytes), v_now, 'required'
  );

  INSERT INTO rq.business_event_anchors (
    project_id, producer_namespace, business_key_sha256, event_id, tenant_id, event_type_id, event_schema_version,
    submitted_shape_sha256, effective_request_sha256, hash_schema_version, applied_defaults, original_project_sequence,
    accepted_at, retention_policy_version
  ) VALUES (
    p_project_id, p_producer_namespace, p_business_key_sha256, p_event_id, p_tenant_id, p_event_type_id, p_event_schema_version,
    p_submitted_shape_sha256, p_effective_request_sha256, 1, p_applied_defaults, v_seq, v_now, p_retention_policy_version
  );

  INSERT INTO rq.command_receipts (
    id, scope_kind, tenant_id, project_id, actor_principal_id, command_family, key_sha256, submitted_shape_sha256,
    effective_request_sha256, resource_kind, resource_id, accepted_version, applied_defaults, accepted_at, hash_schema_version
  ) VALUES (
    p_receipt_id, 'project', p_tenant_id, p_project_id, p_actor_principal_id, 'events.admit', p_idempotency_key_sha256,
    p_submitted_shape_sha256, p_effective_request_sha256, 'event', p_event_id, 1, p_applied_defaults, v_now, 1
  );

  INSERT INTO rq.outbox_events (
    id, event_id, tenant_id, project_id, topology_version, state, current_publication_generation, next_publish_at, created_at, updated_at, version
  ) VALUES (
    p_outbox_id, p_event_id, p_tenant_id, p_project_id, v_project.topology_version, 'pending', 1, v_now, v_now, v_now, 1
  );

  INSERT INTO rq.outbox_publications (
    outbox_id, publication_generation, tenant_id, project_id, envelope_version, envelope_bytes, envelope_sha256, broker_message_id, state, send_count, created_at
  ) VALUES (
    p_outbox_id, 1, p_tenant_id, p_project_id, 1, p_broker_envelope_bytes, p_broker_envelope_sha256,
    'rq:' || p_outbox_id::text || ':1', 'prepared', 0, v_now
  );

  INSERT INTO rq.event_fanout (
    event_id, tenant_id, project_id, topology_version, project_event_sequence, state, candidate_count,
    examined_count, matched_count, delivery_count, claim_generation, version
  ) VALUES (
    p_event_id, p_tenant_id, p_project_id, v_project.topology_version, v_seq, 'pending', v_candidate_count,
    0, 0, 0, 0, 1
  );

  INSERT INTO rq.event_fanout_reservations (
    event_id, tenant_id, project_id, reserved_candidate_slots, unresolved_candidate_slots, converted_delivery_slots, released_nonmatch_slots, state, version
  ) VALUES (
    p_event_id, p_tenant_id, p_project_id, v_candidate_count, v_candidate_count, 0, 0,
    CASE WHEN v_candidate_count = 0 THEN 'completed' ELSE 'held' END,
    1
  );

  INSERT INTO rq.event_delivery_totals (
    event_id, tenant_id, project_id, total_deliveries, terminal_deliveries, acknowledged_deliveries, updated_at, version
  ) VALUES (
    p_event_id, p_tenant_id, p_project_id, 0, 0, 0, v_now, 1
  );

  INSERT INTO rq.event_history (
    event_id, event_sequence, tenant_id, project_id, event_kind, event_schema_version, recorded_at, safe_facts, causing_command_id
  ) VALUES (
    p_event_id, pg_catalog.nextval('rq.event_history_seq'), p_tenant_id, p_project_id, 'event.accepted', 1, v_now,
    pg_catalog.jsonb_build_object('project_event_sequence', v_seq::text, 'topology_version', v_project.topology_version::text, 'candidate_count', v_candidate_count),
    p_receipt_id
  );

  UPDATE rq.tenant_capacity
     SET pending_events = pending_events + 1,
         unmaterialized_candidate_slots = unmaterialized_candidate_slots + v_candidate_count,
         retained_payload_bytes = retained_payload_bytes + v_total_bytes,
         updated_at = v_now,
         version = version + 1
   WHERE tenant_id = p_tenant_id;

  UPDATE rq.project_capacity
     SET pending_events = pending_events + 1,
         unmaterialized_candidate_slots = unmaterialized_candidate_slots + v_candidate_count,
         retained_payload_bytes = retained_payload_bytes + v_total_bytes,
         updated_at = v_now,
         version = version + 1
   WHERE project_id = p_project_id;

  INSERT INTO rq.audit_events (
    id, tenant_id, project_id, actor_kind, actor_reference, action, target_kind, target_id,
    prior_version, resulting_version, candidate_sha256, command_receipt_id, recorded_at, safe_facts
  ) VALUES (
    p_audit_id, p_tenant_id, p_project_id, 'producer', p_actor_principal_id, 'events.admit', 'event', p_event_id,
    NULL, 1, p_effective_request_sha256, p_receipt_id, v_now,
    pg_catalog.jsonb_build_object('project_event_sequence', v_seq::text, 'topology_version', v_project.topology_version::text)
  );

  RETURN pg_catalog.jsonb_build_object(
    'outcome', 'accepted',
    'event_id', p_event_id,
    'receipt_id', p_receipt_id,
    'outbox_id', p_outbox_id,
    'project_event_sequence', v_seq,
    'topology_version', v_project.topology_version,
    'candidate_count', v_candidate_count,
    'admitted_at', v_now,
    'delivery_deadline_at', p_delivery_deadline_at,
    'state', 'accepted',
    'applied_defaults', p_applied_defaults
  );
END;
$$;

CREATE OR REPLACE FUNCTION rq.cmd_event_resolve(
  p_tenant_id uuid,
  p_project_id uuid,
  p_actor_principal_id uuid,
  p_producer_namespace text,
  p_business_key_sha256 bytea,
  p_idempotency_key_sha256 bytea,
  p_submitted_shape_sha256 bytea
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  v_receipt rq.command_receipts%ROWTYPE;
  v_anchor rq.business_event_anchors%ROWTYPE;
  v_event rq.events%ROWTYPE;
BEGIN
  PERFORM rq._assert_session_role(ARRAY['rq_api']);

  IF p_idempotency_key_sha256 IS NOT NULL THEN
    SELECT * INTO v_receipt
      FROM rq.command_receipts
     WHERE scope_kind = 'project'
       AND project_id = p_project_id
       AND actor_principal_id = p_actor_principal_id
       AND command_family = 'events.admit'
       AND key_sha256 = p_idempotency_key_sha256;
    IF FOUND THEN
      IF p_submitted_shape_sha256 IS NOT NULL AND v_receipt.submitted_shape_sha256 <> p_submitted_shape_sha256 THEN
        RAISE EXCEPTION 'Submitted fingerprint conflicts with retained receipt' USING ERRCODE = '23505';
      END IF;
      SELECT * INTO v_event FROM rq.events WHERE id = v_receipt.resource_id AND tenant_id = p_tenant_id;
      RETURN pg_catalog.jsonb_build_object(
        'found', true,
        'event_id', v_event.id,
        'receipt_id', v_receipt.id,
        'project_event_sequence', v_event.project_event_sequence,
        'state', v_event.state,
        'admitted_at', v_event.admitted_at,
        'delivery_deadline_at', v_event.delivery_deadline_at
      );
    END IF;
  END IF;

  SELECT * INTO v_anchor
    FROM rq.business_event_anchors
   WHERE project_id = p_project_id
     AND tenant_id = p_tenant_id
     AND producer_namespace = p_producer_namespace
     AND business_key_sha256 = p_business_key_sha256;

  IF NOT FOUND THEN
    RETURN pg_catalog.jsonb_build_object('found', false);
  END IF;

  IF p_submitted_shape_sha256 IS NOT NULL AND v_anchor.submitted_shape_sha256 <> p_submitted_shape_sha256 THEN
    RAISE EXCEPTION 'Submitted fingerprint conflicts with retained business anchor' USING ERRCODE = '23505';
  END IF;

  SELECT * INTO v_event FROM rq.events WHERE id = v_anchor.event_id;
  RETURN pg_catalog.jsonb_build_object(
    'found', true,
    'event_id', v_anchor.event_id,
    'receipt_id', NULL,
    'project_event_sequence', v_anchor.original_project_sequence,
    'state', v_event.state,
    'admitted_at', v_anchor.accepted_at,
    'delivery_deadline_at', v_event.delivery_deadline_at
  );
END;
$$;

CREATE OR REPLACE FUNCTION rq.cmd_outbox_claim(
  p_outbox_id uuid,
  p_instance_id uuid,
  p_control_epoch uuid,
  p_claim_lease_ms bigint
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  v_gate rq.installation_state%ROWTYPE;
  v_inst rq.runtime_instances%ROWTYPE;
  v_project rq.projects%ROWTYPE;
  v_outbox rq.outbox_events%ROWTYPE;
  v_pub rq.outbox_publications%ROWTYPE;
  v_now timestamptz;
  v_claim_expires timestamptz;
BEGIN
  PERFORM rq._assert_session_role(ARRAY['rq_relay']);

  SELECT * INTO v_gate FROM rq.installation_state WHERE id = 1 FOR SHARE;
  SELECT * INTO v_inst FROM rq.runtime_instances WHERE id = p_instance_id FOR SHARE;
  IF NOT FOUND OR v_gate.control_epoch <> p_control_epoch OR NOT v_gate.allow_publication
     OR v_inst.state <> 'active' OR v_inst.control_epoch <> p_control_epoch THEN
    RAISE EXCEPTION 'Publication claim denied by installation or runtime authority' USING ERRCODE = '55000';
  END IF;

  SELECT * INTO v_outbox FROM rq.outbox_events WHERE id = p_outbox_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'Outbox row not found' USING ERRCODE = 'P0002';
  END IF;

  SELECT * INTO v_project FROM rq.projects WHERE id = v_outbox.project_id AND tenant_id = v_outbox.tenant_id FOR SHARE;
  SELECT * INTO v_outbox FROM rq.outbox_events WHERE id = p_outbox_id FOR UPDATE;
  SELECT * INTO v_pub FROM rq.outbox_publications WHERE outbox_id = p_outbox_id AND publication_generation = v_outbox.current_publication_generation FOR SHARE;

  v_now := pg_catalog.clock_timestamp();
  IF v_inst.expires_at <= v_now THEN
    RAISE EXCEPTION 'Relay runtime lease expired' USING ERRCODE = '55000';
  END IF;

  IF v_outbox.state = 'claimed' AND v_outbox.claim_expires_at > v_now THEN
    RAISE EXCEPTION 'Outbox row holds active unexpired claim' USING ERRCODE = '55P03';
  END IF;
  IF v_outbox.state NOT IN ('pending', 'claimed') OR v_outbox.next_publish_at > v_now THEN
    RAISE EXCEPTION 'Outbox row not eligible for publish claim' USING ERRCODE = '55000';
  END IF;

  v_claim_expires := v_now + (GREATEST(1000::bigint, p_claim_lease_ms)::text || ' milliseconds')::interval;

  UPDATE rq.outbox_events
     SET state = 'claimed',
         claim_owner_instance_id = p_instance_id,
         claim_control_epoch = p_control_epoch,
         claim_generation = claim_generation + 1,
         claim_expires_at = v_claim_expires,
         updated_at = v_now,
         version = version + 1
   WHERE id = p_outbox_id
   RETURNING * INTO v_outbox;

  RETURN pg_catalog.jsonb_build_object(
    'outbox_id', v_outbox.id,
    'event_id', v_outbox.event_id,
    'project_id', v_outbox.project_id,
    'publication_generation', v_outbox.current_publication_generation,
    'claim_generation', v_outbox.claim_generation,
    'claim_expires_at', v_outbox.claim_expires_at,
    'broker_message_id', v_pub.broker_message_id,
    'envelope_bytes_b64', pg_catalog.encode(v_pub.envelope_bytes, 'base64')
  );
END;
$$;

CREATE OR REPLACE FUNCTION rq.cmd_outbox_observe(
  p_outbox_id uuid,
  p_publication_generation bigint,
  p_instance_id uuid,
  p_control_epoch uuid,
  p_expected_claim_generation bigint,
  p_outcome text,
  p_broker_generation_id uuid,
  p_stream_name text,
  p_stream_sequence bigint,
  p_ack_duplicate boolean,
  p_safe_error_code text,
  p_next_publish_at timestamptz,
  p_observation_id uuid
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  v_gate rq.installation_state%ROWTYPE;
  v_inst rq.runtime_instances%ROWTYPE;
  v_project rq.projects%ROWTYPE;
  v_outbox rq.outbox_events%ROWTYPE;
  v_pub rq.outbox_publications%ROWTYPE;
  v_now timestamptz;
  v_is_current boolean := false;
BEGIN
  PERFORM rq._assert_session_role(ARRAY['rq_relay']);

  SELECT * INTO v_gate FROM rq.installation_state WHERE id = 1 FOR SHARE;
  SELECT * INTO v_inst FROM rq.runtime_instances WHERE id = p_instance_id FOR SHARE;
  IF NOT FOUND OR v_gate.control_epoch <> p_control_epoch OR v_inst.control_epoch <> p_control_epoch THEN
    RAISE EXCEPTION 'Publication observation denied by control epoch' USING ERRCODE = '55000';
  END IF;

  SELECT * INTO v_outbox FROM rq.outbox_events WHERE id = p_outbox_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'Outbox row not found' USING ERRCODE = 'P0002';
  END IF;
  SELECT * INTO v_project FROM rq.projects WHERE id = v_outbox.project_id AND tenant_id = v_outbox.tenant_id FOR SHARE;
  SELECT * INTO v_outbox FROM rq.outbox_events WHERE id = p_outbox_id FOR UPDATE;
  SELECT * INTO v_pub FROM rq.outbox_publications WHERE outbox_id = p_outbox_id AND publication_generation = p_publication_generation FOR UPDATE;

  v_now := pg_catalog.clock_timestamp();
  v_is_current := (
    v_outbox.state = 'claimed'
    AND v_outbox.current_publication_generation = p_publication_generation
    AND v_outbox.claim_owner_instance_id = p_instance_id
    AND v_outbox.claim_control_epoch = p_control_epoch
    AND v_outbox.claim_generation = p_expected_claim_generation
  );

  IF p_outcome = 'ack_observed' THEN
    INSERT INTO rq.publication_observations (
      id, outbox_id, publication_generation, broker_generation_id, stream_name, stream_sequence,
      ack_duplicate, observed_at, source_instance_id, local_claim_generation, accepted_as_current
    ) VALUES (
      p_observation_id, p_outbox_id, p_publication_generation, p_broker_generation_id, p_stream_name, p_stream_sequence,
      COALESCE(p_ack_duplicate, false), v_now, p_instance_id, p_expected_claim_generation, v_is_current
    );
  END IF;

  IF NOT v_is_current THEN
    RETURN pg_catalog.jsonb_build_object(
      'accepted_as_current', false,
      'outbox_state', v_outbox.state,
      'publication_state', v_pub.state
    );
  END IF;

  IF p_outcome = 'ack_observed' THEN
    UPDATE rq.outbox_publications
       SET state = 'ack_observed',
           send_count = send_count + 1,
           last_send_at = v_now,
           ack_observed_at = COALESCE(ack_observed_at, v_now),
           stream_name = COALESCE(stream_name, p_stream_name),
           stream_sequence = COALESCE(stream_sequence, p_stream_sequence),
           first_broker_generation_id = COALESCE(first_broker_generation_id, p_broker_generation_id),
           first_observation_id = COALESCE(first_observation_id, p_observation_id),
           safe_error_code = NULL
     WHERE outbox_id = p_outbox_id AND publication_generation = p_publication_generation;

    UPDATE rq.outbox_events
       SET state = 'published',
           claim_owner_instance_id = NULL,
           claim_control_epoch = NULL,
           claim_expires_at = NULL,
           last_safe_error_code = NULL,
           updated_at = v_now,
           version = version + 1
     WHERE id = p_outbox_id;

    RETURN pg_catalog.jsonb_build_object('accepted_as_current', true, 'outbox_state', 'published');
  ELSIF p_outcome = 'publish_unknown' THEN
    UPDATE rq.outbox_publications
       SET state = CASE WHEN state = 'prepared' THEN 'publish_unknown' ELSE state END,
           send_count = send_count + 1,
           last_send_at = v_now,
           safe_error_code = p_safe_error_code
     WHERE outbox_id = p_outbox_id AND publication_generation = p_publication_generation;

    UPDATE rq.outbox_events
       SET state = 'pending',
           claim_owner_instance_id = NULL,
           claim_control_epoch = NULL,
           claim_expires_at = NULL,
           next_publish_at = COALESCE(p_next_publish_at, v_now + interval '2 seconds'),
           last_safe_error_code = p_safe_error_code,
           updated_at = v_now,
           version = version + 1
     WHERE id = p_outbox_id;

    RETURN pg_catalog.jsonb_build_object('accepted_as_current', true, 'outbox_state', 'pending');
  ELSE
    UPDATE rq.outbox_events
       SET state = 'blocked',
           claim_owner_instance_id = NULL,
           claim_control_epoch = NULL,
           claim_expires_at = NULL,
           last_safe_error_code = p_safe_error_code,
           updated_at = v_now,
           version = version + 1
     WHERE id = p_outbox_id;

    RETURN pg_catalog.jsonb_build_object('accepted_as_current', true, 'outbox_state', 'blocked');
  END IF;
END;
$$;

CREATE OR REPLACE FUNCTION rq.cmd_inbox_accept(
  p_outbox_id uuid,
  p_publication_generation bigint,
  p_event_id uuid,
  p_project_id uuid,
  p_topology_version bigint,
  p_envelope_sha256 bytea,
  p_broker_generation_id uuid,
  p_stream_sequence bigint,
  p_inbox_id uuid,
  p_instance_id uuid,
  p_control_epoch uuid
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  v_gate rq.installation_state%ROWTYPE;
  v_inst rq.runtime_instances%ROWTYPE;
  v_project rq.projects%ROWTYPE;
  v_event rq.events%ROWTYPE;
  v_fanout rq.event_fanout%ROWTYPE;
  v_pfs rq.project_fanout_state%ROWTYPE;
  v_inbox rq.broker_inbox%ROWTYPE;
  v_now timestamptz;
BEGIN
  PERFORM rq._assert_session_role(ARRAY['rq_fanout']);

  SELECT * INTO v_gate FROM rq.installation_state WHERE id = 1 FOR SHARE;
  SELECT * INTO v_inst FROM rq.runtime_instances WHERE id = p_instance_id FOR SHARE;
  IF NOT FOUND OR v_gate.control_epoch <> p_control_epoch OR v_inst.control_epoch <> p_control_epoch OR v_inst.state <> 'active' THEN
    RAISE EXCEPTION 'Inbox acceptance denied by control epoch or runtime state' USING ERRCODE = '55000';
  END IF;

  SELECT * INTO v_project FROM rq.projects WHERE id = p_project_id FOR SHARE;
  SELECT * INTO v_event FROM rq.events WHERE id = p_event_id AND project_id = p_project_id AND topology_version = p_topology_version FOR SHARE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'Authoritative event/topology not found for broker envelope' USING ERRCODE = 'P0002';
  END IF;

  v_now := pg_catalog.clock_timestamp();

  INSERT INTO rq.broker_inbox (
    id, outbox_id, publication_generation, event_id, tenant_id, project_id, envelope_sha256,
    first_broker_generation_id, first_stream_sequence, last_broker_generation_id, last_stream_sequence,
    receive_count, state, first_received_at, last_received_at, version
  ) VALUES (
    p_inbox_id, p_outbox_id, p_publication_generation, p_event_id, v_event.tenant_id, p_project_id, p_envelope_sha256,
    p_broker_generation_id, p_stream_sequence, p_broker_generation_id, p_stream_sequence,
    1, 'received', v_now, v_now, 1
  )
  ON CONFLICT (outbox_id, publication_generation) DO UPDATE
    SET last_broker_generation_id = EXCLUDED.last_broker_generation_id,
        last_stream_sequence = EXCLUDED.last_stream_sequence,
        receive_count = rq.broker_inbox.receive_count + 1,
        last_received_at = v_now,
        version = rq.broker_inbox.version + 1
  RETURNING * INTO v_inbox;

  SELECT * INTO v_fanout FROM rq.event_fanout WHERE event_id = p_event_id;
  SELECT * INTO v_pfs FROM rq.project_fanout_state WHERE project_id = p_project_id;

  IF v_fanout.state = 'completed' AND v_inbox.state <> 'completed' THEN
    UPDATE rq.broker_inbox
       SET state = 'completed',
           completed_at = v_now,
           version = version + 1
     WHERE id = v_inbox.id
     RETURNING * INTO v_inbox;
  END IF;

  RETURN pg_catalog.jsonb_build_object(
    'inbox_id', v_inbox.id,
    'inbox_state', v_inbox.state,
    'fanout_state', v_fanout.state,
    'project_event_sequence', v_event.project_event_sequence,
    'materialized_through_event_sequence', COALESCE(v_pfs.materialized_through_event_sequence, 0),
    'is_next_contiguous', (v_event.project_event_sequence = COALESCE(v_pfs.materialized_through_event_sequence, 0) + 1)
  );
END;
$$;

CREATE OR REPLACE FUNCTION rq.cmd_fanout_claim(
  p_event_id uuid,
  p_instance_id uuid,
  p_control_epoch uuid,
  p_claim_lease_ms bigint
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  v_gate rq.installation_state%ROWTYPE;
  v_inst rq.runtime_instances%ROWTYPE;
  v_project rq.projects%ROWTYPE;
  v_fanout rq.event_fanout%ROWTYPE;
  v_pfs rq.project_fanout_state%ROWTYPE;
  v_now timestamptz;
  v_claim_expires timestamptz;
BEGIN
  PERFORM rq._assert_session_role(ARRAY['rq_fanout']);

  SELECT * INTO v_gate FROM rq.installation_state WHERE id = 1 FOR SHARE;
  SELECT * INTO v_inst FROM rq.runtime_instances WHERE id = p_instance_id FOR SHARE;
  IF NOT FOUND OR v_gate.control_epoch <> p_control_epoch OR NOT v_gate.allow_fanout
     OR v_inst.state <> 'active' OR v_inst.control_epoch <> p_control_epoch THEN
    RAISE EXCEPTION 'Fanout claim denied by installation or runtime authority' USING ERRCODE = '55000';
  END IF;

  SELECT * INTO v_fanout FROM rq.event_fanout WHERE event_id = p_event_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'Canonical fanout record not found' USING ERRCODE = 'P0002';
  END IF;

  SELECT * INTO v_project FROM rq.projects WHERE id = v_fanout.project_id AND tenant_id = v_fanout.tenant_id FOR SHARE;
  IF v_project.projection_maintenance_operation_id IS NOT NULL THEN
    RAISE EXCEPTION 'Project under projection maintenance hold' USING ERRCODE = '55000';
  END IF;

  INSERT INTO rq.project_fanout_state (project_id, tenant_id, materialized_through_event_sequence, version)
  VALUES (v_fanout.project_id, v_fanout.tenant_id, 0, 1)
  ON CONFLICT (project_id) DO NOTHING;

  SELECT * INTO v_pfs FROM rq.project_fanout_state WHERE project_id = v_fanout.project_id FOR UPDATE;
  SELECT * INTO v_fanout FROM rq.event_fanout WHERE event_id = p_event_id FOR UPDATE;

  IF v_fanout.state = 'completed' THEN
    RETURN pg_catalog.jsonb_build_object('outcome', 'already_complete', 'event_id', p_event_id);
  END IF;

  IF v_fanout.project_event_sequence <> v_pfs.materialized_through_event_sequence + 1 THEN
    RAISE EXCEPTION 'Predecessor project event not yet materialized' USING ERRCODE = '55000';
  END IF;

  v_now := pg_catalog.clock_timestamp();
  IF v_fanout.claim_owner_instance_id IS NOT NULL AND v_fanout.claim_expires_at > v_now THEN
    RAISE EXCEPTION 'Canonical fanout holds active unexpired claim' USING ERRCODE = '55P03';
  END IF;

  v_claim_expires := v_now + (GREATEST(1000::bigint, p_claim_lease_ms)::text || ' milliseconds')::interval;

  UPDATE rq.project_fanout_state
     SET active_event_id = p_event_id,
         version = version + 1
   WHERE project_id = v_fanout.project_id;

  UPDATE rq.event_fanout
     SET state = 'materializing',
         claim_owner_instance_id = p_instance_id,
         claim_control_epoch = p_control_epoch,
         claim_generation = claim_generation + 1,
         claim_expires_at = v_claim_expires,
         version = version + 1
   WHERE event_id = p_event_id
   RETURNING * INTO v_fanout;

  RETURN pg_catalog.jsonb_build_object(
    'outcome', 'claimed',
    'event_id', v_fanout.event_id,
    'topology_version', v_fanout.topology_version,
    'subscription_cursor', v_fanout.subscription_cursor,
    'claim_generation', v_fanout.claim_generation,
    'claim_expires_at', v_fanout.claim_expires_at,
    'candidate_count', v_fanout.candidate_count,
    'examined_count', v_fanout.examined_count
  );
END;
$$;

CREATE OR REPLACE FUNCTION rq.cmd_fanout_page(
  p_event_id uuid,
  p_instance_id uuid,
  p_control_epoch uuid,
  p_expected_claim_generation bigint,
  p_next_cursor uuid,
  p_complete boolean,
  p_outcomes jsonb
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  v_gate rq.installation_state%ROWTYPE;
  v_inst rq.runtime_instances%ROWTYPE;
  v_project rq.projects%ROWTYPE;
  v_event rq.events%ROWTYPE;
  v_tcap rq.tenant_capacity%ROWTYPE;
  v_pcap rq.project_capacity%ROWTYPE;
  v_pfs rq.project_fanout_state%ROWTYPE;
  v_fanout rq.event_fanout%ROWTYPE;
  v_res rq.event_fanout_reservations%ROWTYPE;
  v_now timestamptz;
  v_item jsonb;
  v_outcome text;
  v_sub_id uuid;
  v_sub_ver bigint;
  v_new_examined bigint := 0;
  v_new_matched bigint := 0;
  v_new_deliveries bigint := 0;
  v_new_nonmatch bigint := 0;
  v_order_key_id uuid;
  v_order_seq bigint;
  v_shard smallint;
  v_delivery_id uuid;
  v_family_id uuid;
  v_fam_orig_del uuid;
  v_inserted_outcome boolean;
BEGIN
  PERFORM rq._assert_session_role(ARRAY['rq_fanout']);

  SELECT * INTO v_gate FROM rq.installation_state WHERE id = 1 FOR SHARE;
  SELECT * INTO v_inst FROM rq.runtime_instances WHERE id = p_instance_id FOR SHARE;
  IF NOT FOUND OR v_gate.control_epoch <> p_control_epoch OR NOT v_gate.allow_fanout
     OR v_inst.state <> 'active' OR v_inst.control_epoch <> p_control_epoch THEN
    RAISE EXCEPTION 'Fanout page denied by authority gate' USING ERRCODE = '55000';
  END IF;

  SELECT * INTO v_event FROM rq.events WHERE id = p_event_id FOR SHARE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'Event not found' USING ERRCODE = 'P0002';
  END IF;

  SELECT * INTO v_project FROM rq.projects WHERE id = v_event.project_id AND tenant_id = v_event.tenant_id FOR SHARE;
  IF v_project.projection_maintenance_operation_id IS NOT NULL THEN
    RAISE EXCEPTION 'Project under projection maintenance hold' USING ERRCODE = '55000';
  END IF;

  SELECT * INTO v_tcap FROM rq.tenant_capacity WHERE tenant_id = v_event.tenant_id FOR UPDATE;
  SELECT * INTO v_pcap FROM rq.project_capacity WHERE project_id = v_event.project_id FOR UPDATE;
  SELECT * INTO v_pfs FROM rq.project_fanout_state WHERE project_id = v_event.project_id FOR UPDATE;
  SELECT * INTO v_fanout FROM rq.event_fanout WHERE event_id = p_event_id FOR UPDATE;
  SELECT * INTO v_res FROM rq.event_fanout_reservations WHERE event_id = p_event_id FOR UPDATE;

  IF v_fanout.state = 'completed' THEN
    RETURN pg_catalog.jsonb_build_object('outcome', 'already_complete', 'event_id', p_event_id);
  END IF;

  v_now := pg_catalog.clock_timestamp();
  IF v_fanout.claim_owner_instance_id IS DISTINCT FROM p_instance_id
     OR v_fanout.claim_control_epoch IS DISTINCT FROM p_control_epoch
     OR v_fanout.claim_generation IS DISTINCT FROM p_expected_claim_generation
     OR v_fanout.claim_expires_at <= v_now THEN
    RAISE EXCEPTION 'Stale or expired canonical fanout claim' USING ERRCODE = '55P03';
  END IF;

  IF v_event.project_event_sequence <> v_pfs.materialized_through_event_sequence + 1 THEN
    RAISE EXCEPTION 'Out-of-order project sequence materialization' USING ERRCODE = '55000';
  END IF;

  FOR v_item IN SELECT value FROM pg_catalog.jsonb_array_elements(COALESCE(p_outcomes, '[]'::jsonb)) LOOP
    v_sub_id := (v_item->>'subscription_id')::uuid;
    v_sub_ver := (v_item->>'subscription_version')::bigint;
    v_outcome := v_item->>'outcome';

    IF EXISTS (
      SELECT 1 FROM rq.fanout_outcomes
       WHERE event_id = p_event_id AND subscription_id = v_sub_id AND subscription_version = v_sub_ver
    ) THEN
      CONTINUE;
    END IF;

    v_new_examined := v_new_examined + 1;

    IF v_outcome = 'matched' THEN
      v_delivery_id := (v_item->>'delivery_id')::uuid;
      v_family_id := (v_item->>'family_id')::uuid;
      v_new_matched := v_new_matched + 1;

      INSERT INTO rq.delivery_families (
        id, event_id, tenant_id, project_id, subscription_id, original_subscription_version,
        consumer_contract_scope, consumer_event_key_sha256, original_delivery_id, next_generation, created_at, version
      ) VALUES (
        v_family_id, p_event_id, v_event.tenant_id, v_event.project_id, v_sub_id, v_sub_ver,
        v_item->>'consumer_contract_scope', pg_catalog.decode(v_item->>'consumer_event_key_sha256', 'hex'),
        v_delivery_id, 1, v_now, 1
      )
      ON CONFLICT (event_id, subscription_id, original_subscription_version) DO NOTHING;

      SELECT id, original_delivery_id
        INTO v_family_id, v_fam_orig_del
        FROM rq.delivery_families
       WHERE event_id = p_event_id AND subscription_id = v_sub_id AND original_subscription_version = v_sub_ver;

      v_order_key_id := NULL;
      v_order_seq := NULL;
      IF (v_item->>'ordering_domain_id') IS NOT NULL THEN
        v_order_key_id := (v_item->>'ordering_key_id')::uuid;
        INSERT INTO rq.ordering_keys (
          id, tenant_id, project_id, subscription_id, ordering_domain_id, consumer_contract_scope,
          ordering_key_sha256, next_allocate_sequence, next_eligible_sequence, version, updated_at
        ) VALUES (
          v_order_key_id, v_event.tenant_id, v_event.project_id, v_sub_id, (v_item->>'ordering_domain_id')::uuid,
          v_item->>'consumer_contract_scope', pg_catalog.decode(v_item->>'ordering_key_sha256', 'hex'),
          1, 1, 1, v_now
        )
        ON CONFLICT (subscription_id, consumer_contract_scope, ordering_domain_id, ordering_key_sha256) DO NOTHING;

        SELECT id, next_allocate_sequence
          INTO v_order_key_id, v_order_seq
          FROM rq.ordering_keys
         WHERE subscription_id = v_sub_id
           AND consumer_contract_scope = v_item->>'consumer_contract_scope'
           AND ordering_domain_id = (v_item->>'ordering_domain_id')::uuid
           AND ordering_key_sha256 = pg_catalog.decode(v_item->>'ordering_key_sha256', 'hex')
           FOR UPDATE;

        UPDATE rq.ordering_keys
           SET next_allocate_sequence = next_allocate_sequence + 1,
               updated_at = v_now,
               version = version + 1
         WHERE id = v_order_key_id;
      END IF;

      INSERT INTO rq.deliveries (
        id, family_id, event_id, tenant_id, project_id, subscription_id, original_subscription_version,
        dispatch_subscription_version, endpoint_id, endpoint_version, wire_envelope_id, delivery_generation,
        state, ordering_key_sha256, ordering_sequence, maximum_attempts, deadline_at, next_eligible_at,
        control_epoch, created_at, updated_at, version
      ) VALUES (
        v_delivery_id, v_family_id, p_event_id, v_event.tenant_id, v_event.project_id, v_sub_id, v_sub_ver,
        v_sub_ver, (v_item->>'endpoint_id')::uuid, (v_item->>'endpoint_version')::bigint,
        (v_item->>'wire_envelope_id')::uuid, 0,
        'ready',
        CASE WHEN v_order_key_id IS NOT NULL THEN pg_catalog.decode(v_item->>'ordering_key_sha256', 'hex') ELSE NULL END,
        v_order_seq,
        COALESCE((v_item->>'maximum_attempts')::integer, 12),
        v_event.delivery_deadline_at,
        v_now,
        p_control_epoch,
        v_now,
        v_now,
        1
      )
      ON CONFLICT (family_id, delivery_generation) DO NOTHING;

      IF FOUND THEN
        v_new_deliveries := v_new_deliveries + 1;

        INSERT INTO rq.delivery_capacity_positions (
          delivery_id, tenant_id, project_id, endpoint_id, position, version, updated_at
        ) VALUES (
          v_delivery_id, v_event.tenant_id, v_event.project_id, (v_item->>'endpoint_id')::uuid, 'pending', 1, v_now
        );

        IF v_order_key_id IS NOT NULL THEN
          INSERT INTO rq.ordering_members (
            ordering_key_id, ordering_sequence, delivery_id, tenant_id, project_id, member_kind,
            admitted_project_event_sequence, state, version
          ) VALUES (
            v_order_key_id, v_order_seq, v_delivery_id, v_event.tenant_id, v_event.project_id, 'original',
            v_event.project_event_sequence,
            CASE WHEN v_order_seq = 1 THEN 'eligible' ELSE 'waiting' END,
            1
          );
        END IF;

        v_shard := rq._delivery_shard(v_delivery_id);
        INSERT INTO rq.event_delivery_total_deltas (
          event_id, shard_id, tenant_id, project_id, total_deliveries_delta, terminal_deliveries_delta, acknowledged_deliveries_delta, updated_at, version
        ) VALUES (
          p_event_id, v_shard, v_event.tenant_id, v_event.project_id, 1, 0, 0, v_now, 1
        )
        ON CONFLICT (event_id, shard_id) DO UPDATE
          SET total_deliveries_delta = rq.event_delivery_total_deltas.total_deliveries_delta + 1,
              updated_at = v_now,
              version = rq.event_delivery_total_deltas.version + 1;

        INSERT INTO rq.project_delivery_total_deltas (
          project_id, shard_id, tenant_id, total_deliveries_delta, pending_delta, updated_at, version
        ) VALUES (
          v_event.project_id, v_shard, v_event.tenant_id, 1, 1, v_now, 1
        )
        ON CONFLICT (project_id, shard_id) DO UPDATE
          SET total_deliveries_delta = rq.project_delivery_total_deltas.total_deliveries_delta + 1,
              pending_delta = rq.project_delivery_total_deltas.pending_delta + 1,
              updated_at = v_now,
              version = rq.project_delivery_total_deltas.version + 1;
      END IF;

      INSERT INTO rq.fanout_outcomes (
        event_id, subscription_id, subscription_version, tenant_id, project_id, outcome,
        filter_profile_version, filter_sha256, delivery_id, recorded_at, safe_reason_code
      ) VALUES (
        p_event_id, v_sub_id, v_sub_ver, v_event.tenant_id, v_event.project_id, 'matched',
        'relayquill.filter.v1',
        CASE WHEN (v_item->>'filter_sha256') IS NOT NULL THEN pg_catalog.decode(v_item->>'filter_sha256', 'hex') ELSE NULL END,
        v_delivery_id, v_now, v_item->>'safe_reason_code'
      );
    ELSE
      v_new_nonmatch := v_new_nonmatch + 1;
      INSERT INTO rq.fanout_outcomes (
        event_id, subscription_id, subscription_version, tenant_id, project_id, outcome,
        filter_profile_version, filter_sha256, delivery_id, recorded_at, safe_reason_code
      ) VALUES (
        p_event_id, v_sub_id, v_sub_ver, v_event.tenant_id, v_event.project_id, v_outcome,
        'relayquill.filter.v1',
        CASE WHEN (v_item->>'filter_sha256') IS NOT NULL THEN pg_catalog.decode(v_item->>'filter_sha256', 'hex') ELSE NULL END,
        NULL, v_now, v_item->>'safe_reason_code'
      );
    END IF;
  END LOOP;

  IF v_new_examined > 0 THEN
    UPDATE rq.event_fanout_reservations
       SET unresolved_candidate_slots = unresolved_candidate_slots - v_new_examined,
           converted_delivery_slots = converted_delivery_slots + v_new_deliveries,
           released_nonmatch_slots = released_nonmatch_slots + v_new_nonmatch,
           state = CASE WHEN unresolved_candidate_slots - v_new_examined = 0 THEN 'completed' ELSE 'partially_converted' END,
           version = version + 1
     WHERE event_id = p_event_id;

    UPDATE rq.tenant_capacity
       SET unmaterialized_candidate_slots = unmaterialized_candidate_slots - v_new_examined,
           pending_deliveries = pending_deliveries + v_new_deliveries,
           updated_at = v_now,
           version = version + 1
     WHERE tenant_id = v_event.tenant_id;

    UPDATE rq.project_capacity
       SET unmaterialized_candidate_slots = unmaterialized_candidate_slots - v_new_examined,
           pending_deliveries = pending_deliveries + v_new_deliveries,
           updated_at = v_now,
           version = version + 1
     WHERE project_id = v_event.project_id;
  END IF;

  IF p_complete THEN
    IF v_fanout.examined_count + v_new_examined <> v_fanout.candidate_count THEN
      RAISE EXCEPTION 'Cannot complete fanout with unexamined candidates' USING ERRCODE = '55000';
    END IF;

    UPDATE rq.event_fanout
       SET state = 'completed',
           subscription_cursor = p_next_cursor,
           examined_count = examined_count + v_new_examined,
           matched_count = matched_count + v_new_matched,
           delivery_count = delivery_count + v_new_deliveries,
           last_progress_at = v_now,
           completed_at = v_now,
           claim_owner_instance_id = NULL,
           claim_control_epoch = NULL,
           claim_expires_at = NULL,
           version = version + 1
     WHERE event_id = p_event_id;

    UPDATE rq.events
       SET state = 'fanout_complete',
           version = version + 1
     WHERE id = p_event_id;

    UPDATE rq.project_fanout_state
       SET materialized_through_event_sequence = v_event.project_event_sequence,
           active_event_id = NULL,
           last_progress_at = v_now,
           version = version + 1
     WHERE project_id = v_event.project_id;

    UPDATE rq.broker_inbox
       SET state = 'completed',
           completed_at = v_now,
           version = version + 1
     WHERE event_id = p_event_id AND state <> 'completed';

    UPDATE rq.tenant_capacity
       SET pending_events = pending_events - 1,
           updated_at = v_now,
           version = version + 1
     WHERE tenant_id = v_event.tenant_id;

    UPDATE rq.project_capacity
       SET pending_events = pending_events - 1,
           updated_at = v_now,
           version = version + 1
     WHERE project_id = v_event.project_id;

    INSERT INTO rq.event_history (
      event_id, event_sequence, tenant_id, project_id, event_kind, event_schema_version, recorded_at, safe_facts, source_instance_id
    ) VALUES (
      p_event_id, pg_catalog.nextval('rq.event_history_seq'), v_event.tenant_id, v_event.project_id,
      'fanout.progress', 1, v_now,
      pg_catalog.jsonb_build_object('completed', true, 'examined', v_fanout.examined_count + v_new_examined, 'deliveries', v_fanout.delivery_count + v_new_deliveries),
      p_instance_id
    );
  ELSE
    UPDATE rq.event_fanout
       SET subscription_cursor = p_next_cursor,
           examined_count = examined_count + v_new_examined,
           matched_count = matched_count + v_new_matched,
           delivery_count = delivery_count + v_new_deliveries,
           last_progress_at = v_now,
           version = version + 1
     WHERE event_id = p_event_id;
  END IF;

  RETURN pg_catalog.jsonb_build_object(
    'outcome', CASE WHEN p_complete THEN 'completed' ELSE 'page_committed' END,
    'event_id', p_event_id,
    'new_examined', v_new_examined,
    'new_deliveries', v_new_deliveries
  );
END;
$$;

CREATE OR REPLACE FUNCTION rq.cmd_dispatch_prepare(
  p_request_id uuid,
  p_dispatch_domain_id uuid,
  p_worker_instance_id uuid,
  p_control_epoch uuid,
  p_request_sha256 bytea,
  p_delivery_id uuid,
  p_attempt_id uuid,
  p_claim_lease_ms bigint
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  v_gate rq.installation_state%ROWTYPE;
  v_sender rq.sender_instances%ROWTYPE;
  v_req rq.dispatch_claim_requests%ROWTYPE;
  v_delivery rq.deliveries%ROWTYPE;
  v_tenant rq.tenants%ROWTYPE;
  v_project rq.projects%ROWTYPE;
  v_endpoint rq.endpoints%ROWTYPE;
  v_grant rq.endpoint_dispatch_grants%ROWTYPE;
  v_sub rq.subscriptions%ROWTYPE;
  v_spol rq.signing_policies%ROWTYPE;
  v_ep_ver rq.endpoint_versions%ROWTYPE;
  v_wire rq.event_wire_envelopes%ROWTYPE;
  v_sc rq.sender_capacity%ROWTYPE;
  v_tc rq.tenant_capacity%ROWTYPE;
  v_pc rq.project_capacity%ROWTYPE;
  v_ec rq.endpoint_capacity%ROWTYPE;
  v_tb rq.tenant_rate_buckets%ROWTYPE;
  v_pb rq.project_rate_buckets%ROWTYPE;
  v_eb rq.endpoint_rate_buckets%ROWTYPE;
  v_circuit rq.endpoint_circuits%ROWTYPE;
  v_okey rq.ordering_keys%ROWTYPE;
  v_omem rq.ordering_members%ROWTYPE;
  v_refill record;
  v_now timestamptz;
  v_claim_expires timestamptz;
  v_new_fence bigint;
  v_attempt_num integer;
  v_shard smallint;
BEGIN
  PERFORM rq._assert_session_role(ARRAY['rq_sender']);

  -- Ordinary delivery path locks installation_state and projects FOR SHARE only (never FOR UPDATE)
  SELECT * INTO v_gate FROM rq.installation_state WHERE id = 1 FOR SHARE;
  IF NOT FOUND OR v_gate.control_epoch <> p_control_epoch OR NOT v_gate.allow_send THEN
    RAISE EXCEPTION 'Send preparation denied by installation gate' USING ERRCODE = '55000';
  END IF;

  SELECT * INTO v_sender FROM rq.sender_instances WHERE id = p_worker_instance_id FOR SHARE;
  IF NOT FOUND OR v_sender.state <> 'active' OR v_sender.control_epoch <> p_control_epoch THEN
    RAISE EXCEPTION 'Sender instance not active in current control epoch' USING ERRCODE = '55000';
  END IF;

  -- Recover idempotent claim request if already persisted
  SELECT * INTO v_req FROM rq.dispatch_claim_requests WHERE id = p_request_id FOR SHARE;
  IF FOUND THEN
    IF v_req.request_sha256 <> p_request_sha256 THEN
      RAISE EXCEPTION 'Dispatch claim request ID reused with conflicting payload' USING ERRCODE = '23505';
    END IF;
    RETURN pg_catalog.jsonb_build_object(
      'outcome', 'idempotent_recovery',
      'request_id', v_req.id,
      'state', v_req.state,
      'assignments', COALESCE((
        SELECT pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(
          'attempt_id', a.attempt_id, 'delivery_id', a.delivery_id, 'fencing_token', a.fencing_token::text
        ) ORDER BY a.assignment_index)
        FROM rq.dispatch_claim_assignments a WHERE a.request_id = v_req.id
      ), '[]'::jsonb)
    );
  END IF;

  -- Resolve target scope before acquiring ranked locks
  SELECT * INTO v_delivery FROM rq.deliveries WHERE id = p_delivery_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'Delivery not found' USING ERRCODE = 'P0002';
  END IF;

  SELECT * INTO v_tenant FROM rq.tenants WHERE id = v_delivery.tenant_id FOR SHARE;
  SELECT * INTO v_project FROM rq.projects WHERE id = v_delivery.project_id AND tenant_id = v_delivery.tenant_id FOR SHARE;
  IF v_tenant.state <> 'active' OR v_project.state <> 'active' OR v_project.projection_maintenance_operation_id IS NOT NULL THEN
    RAISE EXCEPTION 'Tenant or project gate forbids send preparation' USING ERRCODE = '55000';
  END IF;

  SELECT * INTO v_endpoint FROM rq.endpoints WHERE id = v_delivery.endpoint_id FOR SHARE;
  IF v_endpoint.state <> 'active' THEN
    RAISE EXCEPTION 'Endpoint is not active' USING ERRCODE = '55000';
  END IF;

  SELECT * INTO v_ep_ver FROM rq.endpoint_versions
   WHERE endpoint_id = v_delivery.endpoint_id AND endpoint_version = v_delivery.endpoint_version FOR SHARE;

  v_now := pg_catalog.clock_timestamp();

  SELECT * INTO v_grant
    FROM rq.endpoint_dispatch_grants
   WHERE endpoint_id = v_delivery.endpoint_id
     AND endpoint_version = v_delivery.endpoint_version
     AND security_epoch = v_endpoint.security_epoch
     AND state = 'active'
     AND (expires_at IS NULL OR expires_at > v_now)
     AND (
       (grant_class = 'current_destination' AND v_endpoint.current_version = v_delivery.endpoint_version)
       OR grant_class = 'retained_destination_dispatch'
     )
   ORDER BY created_at DESC
   LIMIT 1
   FOR SHARE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'No active dispatch grant for pinned endpoint version' USING ERRCODE = '55000';
  END IF;

  SELECT * INTO v_sub FROM rq.subscriptions WHERE id = v_delivery.subscription_id FOR SHARE;
  IF v_sub.state <> 'active' OR v_sub.send_hold THEN
    RAISE EXCEPTION 'Subscription is paused or send-held' USING ERRCODE = '55000';
  END IF;

  IF v_endpoint.current_signing_policy_version IS NULL THEN
    RAISE EXCEPTION 'Endpoint lacks an active signing policy' USING ERRCODE = '55000';
  END IF;
  SELECT * INTO v_spol FROM rq.signing_policies
   WHERE endpoint_id = v_delivery.endpoint_id AND policy_version = v_endpoint.current_signing_policy_version FOR SHARE;

  SELECT * INTO v_wire FROM rq.event_wire_envelopes WHERE id = v_delivery.wire_envelope_id FOR SHARE;
  IF v_wire.retention_state = 'expired' OR v_wire.body_bytes IS NULL THEN
    RAISE EXCEPTION 'Wire envelope bytes expired' USING ERRCODE = '55000';
  END IF;

  -- Capacity & rate reservations
  SELECT * INTO v_sc FROM rq.sender_capacity WHERE instance_id = p_worker_instance_id FOR UPDATE;
  SELECT * INTO v_tc FROM rq.tenant_capacity WHERE tenant_id = v_delivery.tenant_id FOR UPDATE;
  SELECT * INTO v_pc FROM rq.project_capacity WHERE project_id = v_delivery.project_id FOR UPDATE;
  SELECT * INTO v_ec FROM rq.endpoint_capacity WHERE endpoint_id = v_delivery.endpoint_id FOR UPDATE;

  IF v_sc.held_slots >= v_sc.approved_slots OR v_tc.active_attempt_slots >= v_tc.max_active_attempt_slots
     OR v_pc.active_attempt_slots >= v_pc.max_active_attempt_slots OR v_ec.held_slots >= v_ec.approved_active_slots THEN
    RAISE EXCEPTION 'Sender, tenant, project, or endpoint active slot budget exhausted' USING ERRCODE = '53400';
  END IF;

  SELECT * INTO v_tb FROM rq.tenant_rate_buckets WHERE tenant_id = v_delivery.tenant_id AND operation = 'send_start' FOR UPDATE;
  SELECT * INTO v_pb FROM rq.project_rate_buckets WHERE project_id = v_delivery.project_id AND operation = 'send_start' FOR UPDATE;
  SELECT * INTO v_eb FROM rq.endpoint_rate_buckets WHERE endpoint_id = v_delivery.endpoint_id AND operation = 'send_start' FOR UPDATE;

  IF v_tb.rate_change_gate_id IS NOT NULL OR v_pb.rate_change_gate_id IS NOT NULL OR v_eb.rate_change_gate_id IS NOT NULL THEN
    RAISE EXCEPTION 'Send rate bucket gated by pending rate change' USING ERRCODE = '55000';
  END IF;

  SELECT * INTO v_refill FROM rq._refill_micro_tokens(v_tb.tokens_micro, v_tb.capacity_micro, v_tb.refill_micro_per_second, v_tb.refill_remainder_numerator, v_tb.last_refill_at, v_now);
  IF v_refill.new_tokens_micro - v_tb.reserved_micro < 1000000 THEN
    RAISE EXCEPTION 'Tenant send rate exhausted' USING ERRCODE = '53400';
  END IF;
  UPDATE rq.tenant_rate_buckets
     SET tokens_micro = v_refill.new_tokens_micro,
         reserved_micro = reserved_micro + 1000000,
         refill_remainder_numerator = v_refill.new_remainder_num,
         last_refill_at = v_refill.new_last_refill_at,
         updated_at = v_now,
         version = version + 1
   WHERE tenant_id = v_delivery.tenant_id AND operation = 'send_start';

  SELECT * INTO v_refill FROM rq._refill_micro_tokens(v_pb.tokens_micro, v_pb.capacity_micro, v_pb.refill_micro_per_second, v_pb.refill_remainder_numerator, v_pb.last_refill_at, v_now);
  IF v_refill.new_tokens_micro - v_pb.reserved_micro < 1000000 THEN
    RAISE EXCEPTION 'Project send rate exhausted' USING ERRCODE = '53400';
  END IF;
  UPDATE rq.project_rate_buckets
     SET tokens_micro = v_refill.new_tokens_micro,
         reserved_micro = reserved_micro + 1000000,
         refill_remainder_numerator = v_refill.new_remainder_num,
         last_refill_at = v_refill.new_last_refill_at,
         updated_at = v_now,
         version = version + 1
   WHERE project_id = v_delivery.project_id AND operation = 'send_start';

  SELECT * INTO v_refill FROM rq._refill_micro_tokens(v_eb.tokens_micro, v_eb.capacity_micro, v_eb.refill_micro_per_second, v_eb.refill_remainder_numerator, v_eb.last_refill_at, v_now);
  IF v_refill.new_tokens_micro - v_eb.reserved_micro < 1000000 THEN
    RAISE EXCEPTION 'Endpoint send rate exhausted' USING ERRCODE = '53400';
  END IF;
  UPDATE rq.endpoint_rate_buckets
     SET tokens_micro = v_refill.new_tokens_micro,
         reserved_micro = reserved_micro + 1000000,
         refill_remainder_numerator = v_refill.new_remainder_num,
         last_refill_at = v_refill.new_last_refill_at,
         updated_at = v_now,
         version = version + 1
   WHERE endpoint_id = v_delivery.endpoint_id AND operation = 'send_start';

  -- Circuit check (open -> half_open probe claim if cooldown elapsed)
  SELECT * INTO v_circuit FROM rq.endpoint_circuits
   WHERE endpoint_id = v_delivery.endpoint_id AND endpoint_version = v_delivery.endpoint_version FOR UPDATE;
  IF v_circuit.state = 'half_open' THEN
    RAISE EXCEPTION 'Endpoint circuit probe already active' USING ERRCODE = '55P03';
  ELSIF v_circuit.state = 'open' THEN
    IF v_circuit.reopen_not_before IS NOT NULL AND v_now < v_circuit.reopen_not_before THEN
      RAISE EXCEPTION 'Endpoint circuit is open until reopen_not_before' USING ERRCODE = '55000';
    END IF;
  END IF;

  -- Strict ordering head check
  IF v_delivery.ordering_key_sha256 IS NOT NULL THEN
    SELECT * INTO v_omem FROM rq.ordering_members WHERE delivery_id = p_delivery_id FOR SHARE;
    SELECT * INTO v_okey FROM rq.ordering_keys WHERE id = v_omem.ordering_key_id FOR SHARE;
    IF v_omem.ordering_sequence <> v_okey.next_eligible_sequence OR v_omem.state <> 'eligible' THEN
      RAISE EXCEPTION 'Delivery is not at strict ordering head' USING ERRCODE = '55000';
    END IF;
  END IF;

  -- Lock delivery + position
  SELECT * INTO v_delivery FROM rq.deliveries WHERE id = p_delivery_id FOR UPDATE;
  PERFORM 1 FROM rq.delivery_capacity_positions WHERE delivery_id = p_delivery_id FOR UPDATE;

  IF v_delivery.state NOT IN ('ready', 'retry_wait')
     OR v_delivery.current_attempt_id IS NOT NULL
     OR v_delivery.next_eligible_at > v_now
     OR v_delivery.deadline_at <= v_now
     OR v_delivery.attempt_count >= v_delivery.maximum_attempts
     OR v_delivery.preparation_failure_count >= 24 THEN
    RAISE EXCEPTION 'Delivery not eligible for preparation' USING ERRCODE = '55000';
  END IF;

  v_claim_expires := LEAST(
    v_now + (GREATEST(1000::bigint, p_claim_lease_ms)::text || ' milliseconds')::interval,
    v_delivery.deadline_at
  );
  v_new_fence := v_delivery.current_fence + 1;
  v_attempt_num := v_delivery.next_attempt_number;

  INSERT INTO rq.delivery_attempts (
    id, delivery_id, tenant_id, project_id, attempt_number, worker_instance_id, control_epoch, fencing_token,
    state, prepared_at, request_deadline_at, claim_expires_at, endpoint_id, endpoint_version, endpoint_security_epoch,
    dispatch_grant_id, signing_policy_version, wire_body_sha256, request_profile_version, network_policy_version,
    response_profile_version, circuit_generation_at_preparation, version
  ) VALUES (
    p_attempt_id, p_delivery_id, v_delivery.tenant_id, v_delivery.project_id, v_attempt_num, p_worker_instance_id, p_control_epoch, v_new_fence,
    'prepared', v_now, v_claim_expires, v_claim_expires, v_delivery.endpoint_id, v_delivery.endpoint_version, v_endpoint.security_epoch,
    v_grant.id, v_spol.policy_version, v_wire.body_sha256, v_ep_ver.request_profile_version, v_ep_ver.network_policy_version,
    v_ep_ver.response_profile_version, v_circuit.circuit_generation, 1
  );

  IF v_circuit.state = 'open' THEN
    UPDATE rq.endpoint_circuits
       SET state = 'half_open',
           probe_generation = probe_generation + 1,
           probe_attempt_id = p_attempt_id,
           probe_owner_instance_id = p_worker_instance_id,
           probe_control_epoch = p_control_epoch,
           probe_expires_at = v_claim_expires,
           updated_at = v_now,
           version = version + 1
     WHERE endpoint_id = v_delivery.endpoint_id AND endpoint_version = v_delivery.endpoint_version;
  END IF;

  UPDATE rq.deliveries
     SET state = 'sending',
         current_attempt_id = p_attempt_id,
         current_fence = v_new_fence,
         prepared_attempt_count = prepared_attempt_count + 1,
         next_attempt_number = next_attempt_number + 1,
         next_history_sequence = next_history_sequence + 1,
         updated_at = v_now,
         version = version + 1
   WHERE id = p_delivery_id;

  INSERT INTO rq.attempt_slots (
    attempt_id, delivery_id, tenant_id, project_id, endpoint_id, worker_instance_id, state, held_at, version
  ) VALUES (
    p_attempt_id, p_delivery_id, v_delivery.tenant_id, v_delivery.project_id, v_delivery.endpoint_id, p_worker_instance_id, 'held', v_now, 1
  );

  UPDATE rq.delivery_capacity_positions
     SET position = 'active',
         current_attempt_id = p_attempt_id,
         updated_at = v_now,
         version = version + 1
   WHERE delivery_id = p_delivery_id;

  INSERT INTO rq.tenant_send_reservations (attempt_id, tenant_id, operation, reserved_micro, state, held_at, version)
  VALUES (p_attempt_id, v_delivery.tenant_id, 'send_start', 1000000, 'held', v_now, 1);
  INSERT INTO rq.project_send_reservations (attempt_id, project_id, operation, reserved_micro, state, held_at, version)
  VALUES (p_attempt_id, v_delivery.project_id, 'send_start', 1000000, 'held', v_now, 1);
  INSERT INTO rq.endpoint_send_reservations (attempt_id, endpoint_id, operation, reserved_micro, state, held_at, version)
  VALUES (p_attempt_id, v_delivery.endpoint_id, 'send_start', 1000000, 'held', v_now, 1);

  UPDATE rq.sender_capacity SET held_slots = held_slots + 1, updated_at = v_now, version = version + 1 WHERE instance_id = p_worker_instance_id;
  UPDATE rq.tenant_capacity SET active_attempt_slots = active_attempt_slots + 1, updated_at = v_now, version = version + 1 WHERE tenant_id = v_delivery.tenant_id;
  UPDATE rq.project_capacity SET active_attempt_slots = active_attempt_slots + 1, updated_at = v_now, version = version + 1 WHERE project_id = v_delivery.project_id;
  UPDATE rq.endpoint_capacity SET held_slots = held_slots + 1, updated_at = v_now, version = version + 1 WHERE endpoint_id = v_delivery.endpoint_id;

  v_shard := rq._delivery_shard(p_delivery_id);
  INSERT INTO rq.project_delivery_total_deltas (
    project_id, shard_id, tenant_id, pending_delta, active_delta, updated_at, version
  ) VALUES (
    v_delivery.project_id, v_shard, v_delivery.tenant_id, -1, 1, v_now, 1
  )
  ON CONFLICT (project_id, shard_id) DO UPDATE
    SET pending_delta = rq.project_delivery_total_deltas.pending_delta - 1,
        active_delta = rq.project_delivery_total_deltas.active_delta + 1,
        updated_at = v_now,
        version = rq.project_delivery_total_deltas.version + 1;

  INSERT INTO rq.dispatch_claim_requests (
    id, runtime_instance_id, dispatch_domain_id, control_epoch, request_sha256, maximum_count, state, created_at, accepted_at, version
  ) VALUES (
    p_request_id, p_worker_instance_id, p_dispatch_domain_id, p_control_epoch, p_request_sha256, 1, 'accepted', v_now, v_now, 1
  );

  INSERT INTO rq.dispatch_claim_assignments (
    request_id, assignment_index, attempt_id, delivery_id, tenant_id, project_id, fencing_token, control_epoch, accepted_at
  ) VALUES (
    p_request_id, 0, p_attempt_id, p_delivery_id, v_delivery.tenant_id, v_delivery.project_id, v_new_fence, p_control_epoch, v_now
  );

  INSERT INTO rq.delivery_history (
    delivery_id, history_sequence, tenant_id, project_id, kind, recorded_at, attempt_id, safe_facts, event_schema_version
  ) VALUES (
    p_delivery_id, v_delivery.next_history_sequence + 1, v_delivery.tenant_id, v_delivery.project_id,
    'delivery.prepared', v_now, p_attempt_id,
    pg_catalog.jsonb_build_object('attempt_number', v_attempt_num, 'fencing_token', v_new_fence::text, 'claim_expires_at', v_claim_expires),
    1
  );

  RETURN pg_catalog.jsonb_build_object(
    'outcome', 'prepared',
    'attempt_id', p_attempt_id,
    'delivery_id', p_delivery_id,
    'attempt_number', v_attempt_num,
    'fencing_token', v_new_fence::text,
    'claim_expires_at', v_claim_expires
  );
END;
$$;

CREATE OR REPLACE FUNCTION rq.cmd_send_start(
  p_attempt_id uuid,
  p_worker_instance_id uuid,
  p_control_epoch uuid,
  p_expected_fencing_token bigint,
  p_network_budget_ms bigint DEFAULT 10000
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  v_gate rq.installation_state%ROWTYPE;
  v_sender rq.sender_instances%ROWTYPE;
  v_attempt rq.delivery_attempts%ROWTYPE;
  v_delivery rq.deliveries%ROWTYPE;
  v_tenant rq.tenants%ROWTYPE;
  v_project rq.projects%ROWTYPE;
  v_endpoint rq.endpoints%ROWTYPE;
  v_sub rq.subscriptions%ROWTYPE;
  v_circuit rq.endpoint_circuits%ROWTYPE;
  v_tb rq.tenant_rate_buckets%ROWTYPE;
  v_pb rq.project_rate_buckets%ROWTYPE;
  v_eb rq.endpoint_rate_buckets%ROWTYPE;
  v_refill record;
  v_now timestamptz;
  v_req_deadline timestamptz;
  v_probe_gen bigint := NULL;
BEGIN
  PERFORM rq._assert_session_role(ARRAY['rq_sender']);

  -- Ordinary delivery path locks installation_state and projects FOR SHARE only
  SELECT * INTO v_gate FROM rq.installation_state WHERE id = 1 FOR SHARE;
  IF NOT FOUND OR v_gate.control_epoch <> p_control_epoch OR NOT v_gate.allow_send THEN
    RAISE EXCEPTION 'send_start denied by installation gate' USING ERRCODE = '55000';
  END IF;

  SELECT * INTO v_sender FROM rq.sender_instances WHERE id = p_worker_instance_id FOR SHARE;
  IF NOT FOUND OR v_sender.state <> 'active' OR v_sender.control_epoch <> p_control_epoch THEN
    RAISE EXCEPTION 'Sender instance not active for send_start' USING ERRCODE = '55000';
  END IF;

  SELECT * INTO v_attempt FROM rq.delivery_attempts WHERE id = p_attempt_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'Attempt not found' USING ERRCODE = 'P0002';
  END IF;

  SELECT * INTO v_tenant FROM rq.tenants WHERE id = v_attempt.tenant_id FOR SHARE;
  SELECT * INTO v_project FROM rq.projects WHERE id = v_attempt.project_id AND tenant_id = v_attempt.tenant_id FOR SHARE;
  IF v_tenant.state <> 'active' OR v_project.state <> 'active' OR v_project.projection_maintenance_operation_id IS NOT NULL THEN
    RAISE EXCEPTION 'Tenant or project gate forbids send_start' USING ERRCODE = '55000';
  END IF;

  SELECT * INTO v_delivery FROM rq.deliveries WHERE id = v_attempt.delivery_id;
  SELECT * INTO v_endpoint FROM rq.endpoints WHERE id = v_attempt.endpoint_id FOR SHARE;
  SELECT * INTO v_sub FROM rq.subscriptions WHERE id = v_delivery.subscription_id FOR SHARE;

  v_now := pg_catalog.clock_timestamp();

  IF v_endpoint.state <> 'active' OR v_endpoint.security_epoch <> v_attempt.endpoint_security_epoch
     OR v_sub.state <> 'active' OR v_sub.send_hold THEN
    RAISE EXCEPTION 'Endpoint security or subscription hold changed before send_start' USING ERRCODE = '55000';
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM rq.endpoint_dispatch_grants g
     WHERE g.id = v_attempt.dispatch_grant_id
       AND g.state = 'active'
       AND g.security_epoch = v_endpoint.security_epoch
       AND (g.expires_at IS NULL OR g.expires_at > v_now)
  ) THEN
    RAISE EXCEPTION 'Dispatch grant revoked or expired before send_start' USING ERRCODE = '55000';
  END IF;

  SELECT * INTO v_tb FROM rq.tenant_rate_buckets WHERE tenant_id = v_attempt.tenant_id AND operation = 'send_start' FOR UPDATE;
  SELECT * INTO v_pb FROM rq.project_rate_buckets WHERE project_id = v_attempt.project_id AND operation = 'send_start' FOR UPDATE;
  SELECT * INTO v_eb FROM rq.endpoint_rate_buckets WHERE endpoint_id = v_attempt.endpoint_id AND operation = 'send_start' FOR UPDATE;

  IF v_tb.rate_change_gate_id IS NOT NULL OR v_pb.rate_change_gate_id IS NOT NULL OR v_eb.rate_change_gate_id IS NOT NULL THEN
    RAISE EXCEPTION 'Rate policy drain gate active' USING ERRCODE = '55000';
  END IF;

  PERFORM 1 FROM rq.tenant_send_reservations WHERE attempt_id = p_attempt_id AND tenant_id = v_attempt.tenant_id AND state = 'held' FOR UPDATE;
  PERFORM 1 FROM rq.project_send_reservations WHERE attempt_id = p_attempt_id AND project_id = v_attempt.project_id AND state = 'held' FOR UPDATE;
  PERFORM 1 FROM rq.endpoint_send_reservations WHERE attempt_id = p_attempt_id AND endpoint_id = v_attempt.endpoint_id AND state = 'held' FOR UPDATE;

  SELECT * INTO v_circuit FROM rq.endpoint_circuits
   WHERE endpoint_id = v_attempt.endpoint_id AND endpoint_version = v_attempt.endpoint_version FOR UPDATE;

  IF v_circuit.probe_attempt_id = p_attempt_id THEN
    IF v_circuit.state <> 'half_open'
       OR v_circuit.probe_owner_instance_id <> p_worker_instance_id
       OR v_circuit.probe_control_epoch <> p_control_epoch
       OR v_circuit.probe_expires_at <= v_now THEN
      RAISE EXCEPTION 'Circuit probe authorization changed before send_start' USING ERRCODE = '55000';
    END IF;
    v_probe_gen := v_circuit.probe_generation;
  ELSIF v_circuit.state <> 'closed' OR v_circuit.circuit_generation <> v_attempt.circuit_generation_at_preparation THEN
    RAISE EXCEPTION 'Endpoint circuit opened after preparation' USING ERRCODE = '55000';
  END IF;

  SELECT * INTO v_delivery FROM rq.deliveries WHERE id = v_attempt.delivery_id FOR UPDATE;
  SELECT * INTO v_attempt FROM rq.delivery_attempts WHERE id = p_attempt_id FOR UPDATE;

  IF v_attempt.state = 'send_started'
     AND v_attempt.worker_instance_id = p_worker_instance_id
     AND v_attempt.control_epoch = p_control_epoch
     AND v_attempt.fencing_token = p_expected_fencing_token THEN
    RETURN pg_catalog.jsonb_build_object(
      'should_send', true,
      'already_started', true,
      'attempt_id', v_attempt.id,
      'request_deadline_at', v_attempt.request_deadline_at,
      'accepted_at', v_attempt.send_started_at
    );
  END IF;

  IF v_attempt.state <> 'prepared'
     OR v_attempt.worker_instance_id <> p_worker_instance_id
     OR v_attempt.control_epoch <> p_control_epoch
     OR v_attempt.fencing_token <> p_expected_fencing_token
     OR v_delivery.current_attempt_id IS DISTINCT FROM p_attempt_id
     OR v_attempt.claim_expires_at <= v_now
     OR v_delivery.deadline_at <= v_now
     OR v_delivery.attempt_count >= v_delivery.maximum_attempts THEN
    RAISE EXCEPTION 'Attempt cannot transition to send_started' USING ERRCODE = '55P03';
  END IF;

  -- Refill and consume held send-start rate reservations
  SELECT * INTO v_refill FROM rq._refill_micro_tokens(v_tb.tokens_micro, v_tb.capacity_micro, v_tb.refill_micro_per_second, v_tb.refill_remainder_numerator, v_tb.last_refill_at, v_now);
  UPDATE rq.tenant_rate_buckets
     SET tokens_micro = v_refill.new_tokens_micro - 1000000,
         reserved_micro = reserved_micro - 1000000,
         refill_remainder_numerator = v_refill.new_remainder_num,
         last_refill_at = v_refill.new_last_refill_at,
         updated_at = v_now,
         version = version + 1
   WHERE tenant_id = v_attempt.tenant_id AND operation = 'send_start';

  SELECT * INTO v_refill FROM rq._refill_micro_tokens(v_pb.tokens_micro, v_pb.capacity_micro, v_pb.refill_micro_per_second, v_pb.refill_remainder_numerator, v_pb.last_refill_at, v_now);
  UPDATE rq.project_rate_buckets
     SET tokens_micro = v_refill.new_tokens_micro - 1000000,
         reserved_micro = reserved_micro - 1000000,
         refill_remainder_numerator = v_refill.new_remainder_num,
         last_refill_at = v_refill.new_last_refill_at,
         updated_at = v_now,
         version = version + 1
   WHERE project_id = v_attempt.project_id AND operation = 'send_start';

  SELECT * INTO v_refill FROM rq._refill_micro_tokens(v_eb.tokens_micro, v_eb.capacity_micro, v_eb.refill_micro_per_second, v_eb.refill_remainder_numerator, v_eb.last_refill_at, v_now);
  UPDATE rq.endpoint_rate_buckets
     SET tokens_micro = v_refill.new_tokens_micro - 1000000,
         reserved_micro = reserved_micro - 1000000,
         refill_remainder_numerator = v_refill.new_remainder_num,
         last_refill_at = v_refill.new_last_refill_at,
         updated_at = v_now,
         version = version + 1
   WHERE endpoint_id = v_attempt.endpoint_id AND operation = 'send_start';

  UPDATE rq.tenant_send_reservations SET state = 'consumed', released_at = v_now, version = version + 1 WHERE attempt_id = p_attempt_id;
  UPDATE rq.project_send_reservations SET state = 'consumed', released_at = v_now, version = version + 1 WHERE attempt_id = p_attempt_id;
  UPDATE rq.endpoint_send_reservations SET state = 'consumed', released_at = v_now, version = version + 1 WHERE attempt_id = p_attempt_id;

  v_req_deadline := LEAST(
    v_now + (GREATEST(1::bigint, LEAST(10000::bigint, p_network_budget_ms))::text || ' milliseconds')::interval,
    v_attempt.claim_expires_at,
    v_delivery.deadline_at
  );

  UPDATE rq.deliveries
     SET attempt_count = attempt_count + 1,
         next_history_sequence = next_history_sequence + 1,
         updated_at = v_now,
         version = version + 1
   WHERE id = v_delivery.id;

  UPDATE rq.delivery_attempts
     SET state = 'send_started',
         send_started_at = v_now,
         request_deadline_at = v_req_deadline,
         circuit_generation_at_start = v_circuit.circuit_generation,
         probe_generation_at_start = v_probe_gen,
         version = version + 1
   WHERE id = p_attempt_id;

  INSERT INTO rq.delivery_history (
    delivery_id, history_sequence, tenant_id, project_id, kind, recorded_at, attempt_id, safe_facts, event_schema_version
  ) VALUES (
    v_delivery.id, v_delivery.next_history_sequence + 1, v_delivery.tenant_id, v_delivery.project_id,
    'send.started', v_now, p_attempt_id,
    pg_catalog.jsonb_build_object('request_deadline_at', v_req_deadline, 'circuit_generation', v_circuit.circuit_generation::text),
    1
  );

  RETURN pg_catalog.jsonb_build_object(
    'should_send', true,
    'already_started', false,
    'attempt_id', p_attempt_id,
    'request_deadline_at', v_req_deadline,
    'accepted_at', v_now
  );
END;
$$;

CREATE OR REPLACE FUNCTION rq.cmd_attempt_finalize(
  p_attempt_id uuid,
  p_worker_instance_id uuid,
  p_control_epoch uuid,
  p_expected_fencing_token bigint,
  p_attempt_state text,
  p_outcome_class text,
  p_response_status integer,
  p_response_body_sha256 bytea,
  p_response_byte_count integer,
  p_safe_error_code text,
  p_retry_decision text,
  p_retry_reason_code text,
  p_retry_policy_version text,
  p_selected_delay_ms bigint,
  p_selected_backoff_ms bigint,
  p_retry_after_parse_class text,
  p_retry_after_ms bigint,
  p_next_eligible_at timestamptz
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  v_gate rq.installation_state%ROWTYPE;
  v_attempt rq.delivery_attempts%ROWTYPE;
  v_delivery rq.deliveries%ROWTYPE;
  v_project rq.projects%ROWTYPE;
  v_event rq.events%ROWTYPE;
  v_circuit rq.endpoint_circuits%ROWTYPE;
  v_omem rq.ordering_members%ROWTYPE;
  v_okey rq.ordering_keys%ROWTYPE;
  v_now timestamptz;
  v_shard smallint;
  v_target_del_state text;
  v_is_unstarted boolean;
  v_is_terminal boolean;
  v_term_delta bigint := 0;
  v_ack_delta bigint := 0;
  v_pend_delta bigint := 0;
  v_dlq_delta bigint := 0;
  v_sup_delta bigint := 0;
  v_exp_delta bigint := 0;
  v_unk_delta bigint := 0;
  v_hist_kind text;
  v_delay_ms bigint;
  v_next_reopen integer;
BEGIN
  PERFORM rq._assert_session_role(ARRAY['rq_sender']);

  -- Ordinary delivery finalization uses FOR SHARE on installation_state, projects, and parent events
  SELECT * INTO v_gate FROM rq.installation_state WHERE id = 1 FOR SHARE;
  IF NOT FOUND OR v_gate.control_epoch <> p_control_epoch OR v_gate.mode IN ('recovery_quarantine', 'retired') THEN
    RAISE EXCEPTION 'Attempt finalization denied by installation gate or control epoch' USING ERRCODE = '55000';
  END IF;

  SELECT * INTO v_attempt FROM rq.delivery_attempts WHERE id = p_attempt_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'Delivery attempt not found' USING ERRCODE = 'P0002';
  END IF;

  SELECT * INTO v_delivery FROM rq.deliveries WHERE id = v_attempt.delivery_id;
  SELECT * INTO v_project FROM rq.projects WHERE id = v_attempt.project_id AND tenant_id = v_attempt.tenant_id FOR SHARE;
  IF v_project.projection_maintenance_operation_id IS NOT NULL THEN
    RAISE EXCEPTION 'Project under projection maintenance hold' USING ERRCODE = '55000';
  END IF;

  -- Parent event locked FOR SHARE (never FOR UPDATE) to avoid hot-row serialization
  SELECT * INTO v_event FROM rq.events WHERE id = v_delivery.event_id AND project_id = v_delivery.project_id AND tenant_id = v_delivery.tenant_id FOR SHARE;

  -- Check capacity & unstarted reservations first in rank order
  PERFORM 1 FROM rq.sender_capacity WHERE instance_id = v_attempt.worker_instance_id FOR UPDATE;
  PERFORM 1 FROM rq.tenant_capacity WHERE tenant_id = v_attempt.tenant_id FOR UPDATE;
  PERFORM 1 FROM rq.project_capacity WHERE project_id = v_attempt.project_id FOR UPDATE;
  PERFORM 1 FROM rq.endpoint_capacity WHERE endpoint_id = v_attempt.endpoint_id FOR UPDATE;

  v_is_unstarted := p_attempt_state IN ('deferred_before_send', 'failed_before_send');
  IF v_is_unstarted THEN
    PERFORM 1 FROM rq.tenant_rate_buckets WHERE tenant_id = v_attempt.tenant_id AND operation = 'send_start' FOR UPDATE;
    PERFORM 1 FROM rq.project_rate_buckets WHERE project_id = v_attempt.project_id AND operation = 'send_start' FOR UPDATE;
    PERFORM 1 FROM rq.endpoint_rate_buckets WHERE endpoint_id = v_attempt.endpoint_id AND operation = 'send_start' FOR UPDATE;
  END IF;

  SELECT * INTO v_circuit FROM rq.endpoint_circuits
   WHERE endpoint_id = v_attempt.endpoint_id AND endpoint_version = v_attempt.endpoint_version FOR UPDATE;

  IF v_delivery.ordering_key_sha256 IS NOT NULL THEN
    SELECT * INTO v_omem FROM rq.ordering_members WHERE delivery_id = v_delivery.id FOR UPDATE;
    SELECT * INTO v_okey FROM rq.ordering_keys WHERE id = v_omem.ordering_key_id FOR UPDATE;
  END IF;

  SELECT * INTO v_delivery FROM rq.deliveries WHERE id = v_attempt.delivery_id FOR UPDATE;
  SELECT * INTO v_attempt FROM rq.delivery_attempts WHERE id = p_attempt_id FOR UPDATE;

  -- Idempotent return if this attempt is already finalized
  IF v_attempt.state IN ('response_observed', 'failed_before_send', 'deferred_before_send', 'transport_unknown', 'abandoned') THEN
    RETURN pg_catalog.jsonb_build_object(
      'outcome', 'already_finalized',
      'attempt_id', v_attempt.id,
      'attempt_state', v_attempt.state,
      'delivery_state', v_delivery.state
    );
  END IF;

  IF v_attempt.worker_instance_id <> p_worker_instance_id
     OR v_attempt.control_epoch <> p_control_epoch
     OR v_attempt.fencing_token <> p_expected_fencing_token
     OR v_delivery.current_attempt_id IS DISTINCT FROM p_attempt_id
     OR v_delivery.current_fence <> p_expected_fencing_token THEN
    RAISE EXCEPTION 'Stale attempt owner or fencing token' USING ERRCODE = '55P03';
  END IF;

  v_now := pg_catalog.clock_timestamp();

  IF v_is_unstarted THEN
    IF v_attempt.state <> 'prepared' THEN
      RAISE EXCEPTION 'Started attempt cannot finalize as unstarted' USING ERRCODE = '55000';
    END IF;
    UPDATE rq.tenant_rate_buckets
       SET reserved_micro = reserved_micro - 1000000, updated_at = v_now, version = version + 1
     WHERE tenant_id = v_attempt.tenant_id AND operation = 'send_start'
       AND EXISTS (SELECT 1 FROM rq.tenant_send_reservations r WHERE r.attempt_id = p_attempt_id AND r.state = 'held');
    UPDATE rq.project_rate_buckets
       SET reserved_micro = reserved_micro - 1000000, updated_at = v_now, version = version + 1
     WHERE project_id = v_attempt.project_id AND operation = 'send_start'
       AND EXISTS (SELECT 1 FROM rq.project_send_reservations r WHERE r.attempt_id = p_attempt_id AND r.state = 'held');
    UPDATE rq.endpoint_rate_buckets
       SET reserved_micro = reserved_micro - 1000000, updated_at = v_now, version = version + 1
     WHERE endpoint_id = v_attempt.endpoint_id AND operation = 'send_start'
       AND EXISTS (SELECT 1 FROM rq.endpoint_send_reservations r WHERE r.attempt_id = p_attempt_id AND r.state = 'held');

    UPDATE rq.tenant_send_reservations SET state = 'released', released_at = v_now, version = version + 1 WHERE attempt_id = p_attempt_id AND state = 'held';
    UPDATE rq.project_send_reservations SET state = 'released', released_at = v_now, version = version + 1 WHERE attempt_id = p_attempt_id AND state = 'held';
    UPDATE rq.endpoint_send_reservations SET state = 'released', released_at = v_now, version = version + 1 WHERE attempt_id = p_attempt_id AND state = 'held';
  END IF;

  IF p_attempt_state = 'deferred_before_send' AND v_circuit.state = 'half_open' AND v_circuit.probe_attempt_id = p_attempt_id THEN
    UPDATE rq.endpoint_circuits
       SET state = 'open',
           reopen_not_before = v_now + interval '1 second',
           probe_attempt_id = NULL,
           probe_owner_instance_id = NULL,
           probe_control_epoch = NULL,
           probe_expires_at = NULL,
           updated_at = v_now,
           version = version + 1
     WHERE endpoint_id = v_attempt.endpoint_id AND endpoint_version = v_attempt.endpoint_version;
  ELSIF NOT v_is_unstarted THEN
    IF v_circuit.state = 'half_open'
       AND v_circuit.probe_attempt_id = p_attempt_id
       AND v_attempt.circuit_generation_at_start = v_circuit.circuit_generation
       AND v_attempt.probe_generation_at_start = v_circuit.probe_generation THEN
      IF p_outcome_class = 'acknowledged' THEN
        UPDATE rq.endpoint_circuits
           SET state = 'closed',
               circuit_generation = circuit_generation + 1,
               consecutive_transient_failures = 0,
               reopen_count = 0,
               reopen_not_before = NULL,
               probe_attempt_id = NULL,
               probe_owner_instance_id = NULL,
               probe_control_epoch = NULL,
               probe_expires_at = NULL,
               window_started_at = v_now,
               window_success_count = 0,
               window_failure_count = 0,
               updated_at = v_now,
               version = version + 1
         WHERE endpoint_id = v_attempt.endpoint_id AND endpoint_version = v_attempt.endpoint_version;
      ELSE
        v_next_reopen := v_circuit.reopen_count + 1;
        v_delay_ms := LEAST(900000::bigint, (60000::bigint * pg_catalog.power(2::numeric, LEAST(v_next_reopen, 6)))::bigint);
        UPDATE rq.endpoint_circuits
           SET state = 'open',
               circuit_generation = circuit_generation + 1,
               reopen_count = v_next_reopen,
               reopen_not_before = v_now + (v_delay_ms::text || ' milliseconds')::interval,
               probe_attempt_id = NULL,
               probe_owner_instance_id = NULL,
               probe_control_epoch = NULL,
               probe_expires_at = NULL,
               window_started_at = v_now,
               window_success_count = 0,
               window_failure_count = 0,
               updated_at = v_now,
               version = version + 1
         WHERE endpoint_id = v_attempt.endpoint_id AND endpoint_version = v_attempt.endpoint_version;
      END IF;
    ELSIF v_circuit.state = 'closed' AND v_attempt.circuit_generation_at_start = v_circuit.circuit_generation THEN
      IF p_outcome_class IN ('acknowledged', 'permanent_http', 'permanent_redirect') THEN
        UPDATE rq.endpoint_circuits
           SET consecutive_transient_failures = 0,
               window_success_count = CASE WHEN p_outcome_class = 'acknowledged' THEN window_success_count + 1 ELSE window_success_count END,
               window_failure_count = CASE WHEN p_outcome_class <> 'acknowledged' THEN window_failure_count + 1 ELSE window_failure_count END,
               updated_at = v_now,
               version = version + 1
         WHERE endpoint_id = v_attempt.endpoint_id AND endpoint_version = v_attempt.endpoint_version;
      ELSIF p_outcome_class IN ('transient_http', 'transport_unknown') THEN
        IF v_circuit.consecutive_transient_failures + 1 >= 5 THEN
          UPDATE rq.endpoint_circuits
             SET state = 'open',
                 circuit_generation = circuit_generation + 1,
                 consecutive_transient_failures = 5,
                 reopen_count = 0,
                 reopen_not_before = v_now + interval '60 seconds',
                 window_started_at = v_now,
                 window_success_count = 0,
                 window_failure_count = 0,
                 updated_at = v_now,
                 version = version + 1
           WHERE endpoint_id = v_attempt.endpoint_id AND endpoint_version = v_attempt.endpoint_version;
        ELSE
          UPDATE rq.endpoint_circuits
             SET consecutive_transient_failures = consecutive_transient_failures + 1,
                 window_failure_count = window_failure_count + 1,
                 updated_at = v_now,
                 version = version + 1
           WHERE endpoint_id = v_attempt.endpoint_id AND endpoint_version = v_attempt.endpoint_version;
        END IF;
      END IF;
    END IF;
  END IF;

  IF p_attempt_state = 'deferred_before_send' THEN
    v_target_del_state := CASE
      WHEN v_now >= v_delivery.deadline_at THEN 'expired'
      ELSE 'retry_wait'
    END;
  ELSIF p_attempt_state = 'failed_before_send' THEN
    IF v_now >= v_delivery.deadline_at THEN
      v_target_del_state := 'expired';
    ELSIF v_delivery.preparation_failure_count + 1 >= 24 THEN
      v_target_del_state := 'dead_letter';
    ELSE
      v_target_del_state := 'retry_wait';
    END IF;
  ELSE
    v_target_del_state := p_retry_decision;
  END IF;

  v_is_terminal := v_target_del_state IN ('acknowledged', 'dead_letter', 'suppressed', 'expired');

  UPDATE rq.delivery_attempts
     SET state = p_attempt_state,
         response_status = p_response_status,
         response_body_sha256 = p_response_body_sha256,
         response_byte_count = p_response_byte_count,
         outcome_class = p_outcome_class,
         safe_error_code = p_safe_error_code,
         finished_at = v_now,
         version = version + 1
   WHERE id = p_attempt_id;

  IF NOT v_is_unstarted THEN
    INSERT INTO rq.delivery_retry_decisions (
      id, delivery_id, attempt_id, tenant_id, project_id, outcome_class, retry_policy_version,
      selected_delay_milliseconds, selected_backoff_milliseconds, retry_after_parse_class,
      retry_after_milliseconds, next_eligible_at, decision, reason_code, decided_at, version
    ) VALUES (
      pg_catalog.gen_random_uuid(), v_delivery.id, p_attempt_id, v_delivery.tenant_id, v_delivery.project_id,
      p_outcome_class, COALESCE(p_retry_policy_version, 'retry_v1'),
      p_selected_delay_ms, p_selected_backoff_ms, COALESCE(p_retry_after_parse_class, 'none'),
      p_retry_after_ms, CASE WHEN v_target_del_state = 'retry_wait' THEN p_next_eligible_at ELSE NULL END,
      v_target_del_state, p_retry_reason_code, v_now, 1
    )
    ON CONFLICT (attempt_id) DO NOTHING;
  END IF;

  UPDATE rq.deliveries
     SET state = v_target_del_state,
         current_attempt_id = NULL,
         preparation_failure_count = preparation_failure_count + CASE WHEN p_attempt_state = 'failed_before_send' THEN 1 ELSE 0 END,
         next_eligible_at = CASE WHEN v_target_del_state = 'retry_wait' THEN COALESCE(p_next_eligible_at, v_now + interval '1 second') ELSE next_eligible_at END,
         acknowledged_at = CASE WHEN v_target_del_state = 'acknowledged' THEN v_now ELSE NULL END,
         terminal_at = CASE WHEN v_is_terminal THEN v_now ELSE NULL END,
         last_outcome_class = COALESCE(p_outcome_class, last_outcome_class),
         blocking_reason = CASE WHEN v_target_del_state IN ('dead_letter', 'expired') THEN p_retry_reason_code ELSE NULL END,
         next_history_sequence = next_history_sequence + 1,
         updated_at = v_now,
         version = version + 1
   WHERE id = v_delivery.id;

  IF v_delivery.ordering_key_sha256 IS NOT NULL THEN
    IF v_target_del_state = 'acknowledged' THEN
      UPDATE rq.ordering_members SET state = 'acknowledged', version = version + 1 WHERE delivery_id = v_delivery.id;
      UPDATE rq.ordering_keys
         SET next_eligible_sequence = next_eligible_sequence + 1,
             blocked_delivery_id = NULL,
             updated_at = v_now,
             version = version + 1
       WHERE id = v_okey.id;
      UPDATE rq.ordering_members
         SET state = 'eligible', version = version + 1
       WHERE ordering_key_id = v_okey.id
         AND ordering_sequence = v_okey.next_eligible_sequence + 1
         AND state = 'waiting';
    ELSIF v_target_del_state IN ('dead_letter', 'expired') THEN
      UPDATE rq.ordering_members SET state = 'blocked', version = version + 1 WHERE delivery_id = v_delivery.id;
      UPDATE rq.ordering_keys SET blocked_delivery_id = v_delivery.id, updated_at = v_now, version = version + 1 WHERE id = v_okey.id;
    END IF;
  END IF;

  UPDATE rq.attempt_slots
     SET state = 'released', released_at = v_now, release_reason = p_attempt_state, version = version + 1
   WHERE attempt_id = p_attempt_id AND state = 'held';

  UPDATE rq.sender_capacity SET held_slots = held_slots - 1, updated_at = v_now, version = version + 1 WHERE instance_id = v_attempt.worker_instance_id;
  UPDATE rq.tenant_capacity
     SET active_attempt_slots = active_attempt_slots - 1,
         pending_deliveries = pending_deliveries - CASE WHEN v_is_terminal THEN 1 ELSE 0 END,
         updated_at = v_now,
         version = version + 1
   WHERE tenant_id = v_attempt.tenant_id;
  UPDATE rq.project_capacity
     SET active_attempt_slots = active_attempt_slots - 1,
         pending_deliveries = pending_deliveries - CASE WHEN v_is_terminal THEN 1 ELSE 0 END,
         updated_at = v_now,
         version = version + 1
   WHERE project_id = v_attempt.project_id;
  UPDATE rq.endpoint_capacity SET held_slots = held_slots - 1, updated_at = v_now, version = version + 1 WHERE endpoint_id = v_attempt.endpoint_id;

  UPDATE rq.delivery_capacity_positions
     SET position = CASE WHEN v_is_terminal THEN 'released' ELSE 'pending' END,
         current_attempt_id = NULL,
         released_at = CASE WHEN v_is_terminal THEN v_now ELSE NULL END,
         updated_at = v_now,
         version = version + 1
   WHERE delivery_id = v_delivery.id;

  -- Sharded delta projection updates (zero hot-row contention on rq.events / rq.event_delivery_totals / rq.project_delivery_totals)
  v_shard := rq._delivery_shard(v_delivery.id);
  IF v_target_del_state = 'acknowledged' THEN
    v_term_delta := 1; v_ack_delta := 1; v_hist_kind := 'delivery.acknowledged';
  ELSIF v_target_del_state = 'dead_letter' THEN
    v_term_delta := 1; v_dlq_delta := 1; v_hist_kind := 'delivery.dead_lettered';
  ELSIF v_target_del_state = 'suppressed' THEN
    v_term_delta := 1; v_sup_delta := 1; v_hist_kind := 'delivery.suppressed';
  ELSIF v_target_del_state = 'expired' THEN
    v_term_delta := 1; v_exp_delta := 1; v_hist_kind := 'delivery.expired';
  ELSE
    v_pend_delta := 1; v_hist_kind := 'delivery.retry_scheduled';
  END IF;

  IF p_attempt_state IN ('transport_unknown', 'abandoned') THEN
    v_unk_delta := 1;
  END IF;

  INSERT INTO rq.event_delivery_total_deltas (
    event_id, shard_id, tenant_id, project_id, total_deliveries_delta, terminal_deliveries_delta,
    acknowledged_deliveries_delta, last_outcome_at, updated_at, version
  ) VALUES (
    v_delivery.event_id, v_shard, v_delivery.tenant_id, v_delivery.project_id, 0, v_term_delta,
    v_ack_delta, v_now, v_now, 1
  )
  ON CONFLICT (event_id, shard_id) DO UPDATE
    SET terminal_deliveries_delta = rq.event_delivery_total_deltas.terminal_deliveries_delta + v_term_delta,
        acknowledged_deliveries_delta = rq.event_delivery_total_deltas.acknowledged_deliveries_delta + v_ack_delta,
        last_outcome_at = v_now,
        updated_at = v_now,
        version = rq.event_delivery_total_deltas.version + 1;

  INSERT INTO rq.project_delivery_total_deltas (
    project_id, shard_id, tenant_id, pending_delta, active_delta, acknowledged_delta, dead_letter_delta,
    suppressed_delta, expired_delta, unknown_attempt_observations_delta, updated_at, version
  ) VALUES (
    v_delivery.project_id, v_shard, v_delivery.tenant_id, v_pend_delta, -1, v_ack_delta, v_dlq_delta,
    v_sup_delta, v_exp_delta, v_unk_delta, v_now, 1
  )
  ON CONFLICT (project_id, shard_id) DO UPDATE
    SET pending_delta = rq.project_delivery_total_deltas.pending_delta + v_pend_delta,
        active_delta = rq.project_delivery_total_deltas.active_delta - 1,
        acknowledged_delta = rq.project_delivery_total_deltas.acknowledged_delta + v_ack_delta,
        dead_letter_delta = rq.project_delivery_total_deltas.dead_letter_delta + v_dlq_delta,
        suppressed_delta = rq.project_delivery_total_deltas.suppressed_delta + v_sup_delta,
        expired_delta = rq.project_delivery_total_deltas.expired_delta + v_exp_delta,
        unknown_attempt_observations_delta = rq.project_delivery_total_deltas.unknown_attempt_observations_delta + v_unk_delta,
        updated_at = v_now,
        version = rq.project_delivery_total_deltas.version + 1;

  INSERT INTO rq.delivery_history (
    delivery_id, history_sequence, tenant_id, project_id, kind, recorded_at, attempt_id, safe_facts, event_schema_version
  ) VALUES (
    v_delivery.id, v_delivery.next_history_sequence + 1, v_delivery.tenant_id, v_delivery.project_id,
    v_hist_kind, v_now, p_attempt_id,
    pg_catalog.jsonb_build_object('attempt_state', p_attempt_state, 'delivery_state', v_target_del_state, 'outcome_class', p_outcome_class, 'shard_id', v_shard),
    1
  );

  INSERT INTO rq.event_history (
    event_id, event_sequence, tenant_id, project_id, event_kind, event_schema_version, recorded_at, safe_facts, source_instance_id
  ) VALUES (
    v_delivery.event_id, pg_catalog.nextval('rq.event_history_seq'), v_delivery.tenant_id, v_delivery.project_id,
    'event.delivery_aggregate_changed', 1, v_now,
    pg_catalog.jsonb_build_object('delivery_id', v_delivery.id, 'shard_id', v_shard, 'delivery_state', v_target_del_state),
    p_worker_instance_id
  );

  RETURN pg_catalog.jsonb_build_object(
    'outcome', 'finalized',
    'attempt_id', p_attempt_id,
    'attempt_state', p_attempt_state,
    'delivery_state', v_target_del_state,
    'shard_id', v_shard
  );
END;
$$;

CREATE OR REPLACE FUNCTION rq.cmd_late_delivery_observe(
  p_observation_id uuid,
  p_delivery_id uuid,
  p_attempt_id uuid,
  p_source_instance_id uuid,
  p_observation_key_sha256 bytea,
  p_facts_sha256 bytea,
  p_observation_kind text,
  p_safe_facts jsonb
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  v_attempt rq.delivery_attempts%ROWTYPE;
  v_now timestamptz;
BEGIN
  PERFORM rq._assert_session_role(ARRAY['rq_sender', 'rq_coordinator']);
  SELECT * INTO v_attempt FROM rq.delivery_attempts WHERE id = p_attempt_id AND delivery_id = p_delivery_id FOR SHARE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'Attempt/delivery mismatch' USING ERRCODE = 'P0002';
  END IF;
  v_now := pg_catalog.clock_timestamp();
  INSERT INTO rq.late_delivery_observations (
    id, delivery_id, attempt_id, tenant_id, project_id, source_instance_id, observation_key_sha256,
    facts_sha256, observation_kind, safe_facts, recorded_at, version
  ) VALUES (
    p_observation_id, p_delivery_id, p_attempt_id, v_attempt.tenant_id, v_attempt.project_id,
    p_source_instance_id, p_observation_key_sha256, p_facts_sha256, p_observation_kind, p_safe_facts, v_now, 1
  )
  ON CONFLICT (attempt_id, source_instance_id, observation_key_sha256) DO NOTHING;

  RETURN pg_catalog.jsonb_build_object('observation_id', p_observation_id, 'attempt_id', p_attempt_id);
END;
$$;

CREATE OR REPLACE FUNCTION rq.cmd_egress_decision_record(
  p_decision_id uuid,
  p_tenant_id uuid,
  p_project_id uuid,
  p_endpoint_id uuid,
  p_endpoint_version bigint,
  p_delivery_attempt_id uuid,
  p_verification_attempt_id uuid,
  p_runtime_instance_id uuid,
  p_control_epoch uuid,
  p_network_policy_version text,
  p_registry_ipv4_sha256 bytea,
  p_registry_ipv6_sha256 bytea,
  p_authority_sha256 bytea,
  p_answer_set_sha256 bytea,
  p_selected_address_sha256 bytea,
  p_selected_family integer,
  p_peer_address_sha256 bytea,
  p_decision text,
  p_reason_code text,
  p_expires_at timestamptz
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  v_now timestamptz := pg_catalog.clock_timestamp();
BEGIN
  PERFORM rq._assert_session_role(ARRAY['rq_sender']);
  INSERT INTO rq.egress_decisions (
    id, tenant_id, project_id, endpoint_id, endpoint_version, delivery_attempt_id, verification_attempt_id,
    runtime_instance_id, control_epoch, network_policy_version, registry_ipv4_sha256, registry_ipv6_sha256,
    authority_sha256, answer_set_sha256, selected_address_sha256, selected_family, peer_address_sha256,
    decision, reason_code, observed_at, expires_at, version
  ) VALUES (
    p_decision_id, p_tenant_id, p_project_id, p_endpoint_id, p_endpoint_version, p_delivery_attempt_id, p_verification_attempt_id,
    p_runtime_instance_id, p_control_epoch, p_network_policy_version, p_registry_ipv4_sha256, p_registry_ipv6_sha256,
    p_authority_sha256, p_answer_set_sha256, p_selected_address_sha256, p_selected_family, p_peer_address_sha256,
    p_decision, p_reason_code, v_now, p_expires_at, 1
  )
  ON CONFLICT (id) DO NOTHING;

  RETURN pg_catalog.jsonb_build_object('egress_decision_id', p_decision_id, 'decision', p_decision);
END;
$$;

CREATE OR REPLACE FUNCTION rq.cmd_verification_attempt_claim(
  p_intent_id uuid,
  p_attempt_id uuid,
  p_instance_id uuid,
  p_control_epoch uuid,
  p_claim_lease_ms bigint
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  v_gate rq.installation_state%ROWTYPE;
  v_intent rq.endpoint_verification_intents%ROWTYPE;
  v_now timestamptz := pg_catalog.clock_timestamp();
  v_claim_expires timestamptz;
BEGIN
  PERFORM rq._assert_session_role(ARRAY['rq_sender']);
  SELECT * INTO v_gate FROM rq.installation_state WHERE id = 1 FOR SHARE;
  IF NOT v_gate.allow_endpoint_verification OR v_gate.control_epoch <> p_control_epoch THEN
    RAISE EXCEPTION 'Endpoint verification closed by installation gate' USING ERRCODE = '55000';
  END IF;
  SELECT * INTO v_intent FROM rq.endpoint_verification_intents WHERE id = p_intent_id FOR UPDATE;
  IF NOT FOUND OR v_intent.state NOT IN ('approved', 'probing') OR v_intent.expires_at <= v_now OR v_intent.attempt_count >= 3 THEN
    RAISE EXCEPTION 'Endpoint verification intent not eligible' USING ERRCODE = '55000';
  END IF;

  v_claim_expires := LEAST(v_now + (p_claim_lease_ms::text || ' milliseconds')::interval, v_intent.expires_at);
  UPDATE rq.endpoint_verification_intents
     SET state = 'probing', attempt_count = attempt_count + 1, version = version + 1
   WHERE id = p_intent_id;

  INSERT INTO rq.endpoint_verification_attempts (
    id, intent_id, tenant_id, project_id, endpoint_id, endpoint_version, signing_key_version_id,
    runtime_instance_id, control_epoch, claim_generation, state, prepared_at, claim_expires_at, request_deadline_at, version
  ) VALUES (
    p_attempt_id, p_intent_id, v_intent.tenant_id, v_intent.project_id, v_intent.endpoint_id, v_intent.endpoint_version,
    v_intent.signing_key_version_id, p_instance_id, p_control_epoch, v_intent.attempt_count + 1,
    'prepared', v_now, v_claim_expires, v_claim_expires, 1
  );

  RETURN pg_catalog.jsonb_build_object('attempt_id', p_attempt_id, 'intent_id', p_intent_id, 'claim_expires_at', v_claim_expires);
END;
$$;

CREATE OR REPLACE FUNCTION rq.cmd_verification_attempt_finalize(
  p_attempt_id uuid,
  p_instance_id uuid,
  p_control_epoch uuid,
  p_outcome text,
  p_response_status integer,
  p_proof_sha256 bytea,
  p_network_policy_version text,
  p_safe_reason_code text,
  p_event_id uuid
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  v_attempt rq.endpoint_verification_attempts%ROWTYPE;
  v_intent rq.endpoint_verification_intents%ROWTYPE;
  v_now timestamptz := pg_catalog.clock_timestamp();
  v_new_intent_state text;
BEGIN
  PERFORM rq._assert_session_role(ARRAY['rq_sender']);
  SELECT * INTO v_attempt FROM rq.endpoint_verification_attempts WHERE id = p_attempt_id FOR UPDATE;
  IF NOT FOUND OR v_attempt.runtime_instance_id <> p_instance_id OR v_attempt.control_epoch <> p_control_epoch THEN
    RAISE EXCEPTION 'Verification attempt claim mismatch' USING ERRCODE = '55P03';
  END IF;
  SELECT * INTO v_intent FROM rq.endpoint_verification_intents WHERE id = v_attempt.intent_id FOR UPDATE;

  UPDATE rq.endpoint_verification_attempts
     SET state = CASE WHEN p_outcome = 'verified' THEN 'verified' ELSE 'failed' END,
         response_status = p_response_status,
         proof_sha256 = p_proof_sha256,
         safe_error_code = CASE WHEN p_outcome = 'verified' THEN NULL ELSE p_safe_reason_code END,
         finished_at = v_now,
         version = version + 1
   WHERE id = p_attempt_id;

  v_new_intent_state := CASE
    WHEN p_outcome = 'verified' AND v_intent.expires_at > v_now THEN 'verified'
    WHEN v_intent.expires_at <= v_now THEN 'expired'
    WHEN v_intent.attempt_count >= 3 THEN 'failed'
    ELSE 'approved'
  END;

  UPDATE rq.endpoint_verification_intents
     SET state = v_new_intent_state,
         verified_at = CASE WHEN v_new_intent_state = 'verified' THEN v_now ELSE verified_at END,
         safe_error_code = CASE WHEN v_new_intent_state = 'verified' THEN NULL ELSE p_safe_reason_code END,
         version = version + 1
   WHERE id = v_intent.id;

  INSERT INTO rq.endpoint_verification_events (
    id, intent_id, tenant_id, project_id, endpoint_id, endpoint_version, key_version_id, security_epoch,
    outcome, proof_sha256, network_policy_version, observed_at, safe_reason_code
  ) VALUES (
    p_event_id, v_intent.id, v_intent.tenant_id, v_intent.project_id, v_intent.endpoint_id, v_intent.endpoint_version,
    v_intent.signing_key_version_id, v_intent.security_epoch, p_outcome, p_proof_sha256,
    COALESCE(p_network_policy_version, 'network_v1'), v_now, p_safe_reason_code
  );

  RETURN pg_catalog.jsonb_build_object('intent_id', v_intent.id, 'intent_state', v_new_intent_state);
END;
$$;

CREATE OR REPLACE FUNCTION rq.cmd_receiver_receipt_observe(
  p_observation_id uuid,
  p_delivery_id uuid,
  p_attempt_id uuid,
  p_receipt_reference text,
  p_receipt_facts_sha256 bytea,
  p_request_wire_sha256 bytea,
  p_proof_sha256 bytea,
  p_key_id text,
  p_receiver_contract_id uuid,
  p_receiver_contract_version bigint,
  p_receipt_facts jsonb,
  p_verification_profile_version text,
  p_source_kind text,
  p_recorded_by uuid,
  p_state text
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  v_del rq.deliveries%ROWTYPE;
  v_fam rq.delivery_families%ROWTYPE;
  v_now timestamptz := pg_catalog.clock_timestamp();
BEGIN
  PERFORM rq._assert_session_role(ARRAY['rq_sender']);
  SELECT * INTO v_del FROM rq.deliveries WHERE id = p_delivery_id FOR SHARE;
  SELECT * INTO v_fam FROM rq.delivery_families WHERE id = v_del.family_id FOR SHARE;

  INSERT INTO rq.receiver_receipt_observations (
    id, delivery_id, event_id, tenant_id, project_id, attempt_id, consumer_contract_scope,
    receipt_reference, receipt_facts_sha256, request_wire_sha256, proof_sha256, key_id,
    receiver_contract_id, receiver_contract_version, receipt_facts, verification_profile_version,
    source_kind, observed_at, recorded_by, state
  ) VALUES (
    p_observation_id, p_delivery_id, v_del.event_id, v_del.tenant_id, v_del.project_id, p_attempt_id,
    v_fam.consumer_contract_scope, p_receipt_reference, p_receipt_facts_sha256, p_request_wire_sha256,
    p_proof_sha256, p_key_id, p_receiver_contract_id, p_receiver_contract_version, p_receipt_facts,
    p_verification_profile_version, p_source_kind, v_now, p_recorded_by, p_state
  )
  ON CONFLICT (delivery_id, receipt_reference, receipt_facts_sha256, verification_profile_version) DO NOTHING;

  RETURN pg_catalog.jsonb_build_object('observation_id', p_observation_id, 'state', p_state);
END;
$$;

CREATE OR REPLACE FUNCTION rq.cmd_circuit_probe_request(
  p_request_id uuid,
  p_tenant_id uuid,
  p_project_id uuid,
  p_endpoint_id uuid,
  p_endpoint_version bigint,
  p_expected_circuit_generation bigint,
  p_requested_by uuid,
  p_receipt_id uuid,
  p_key_sha256 bytea,
  p_submitted_shape_sha256 bytea
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  v_gate rq.installation_state%ROWTYPE;
  v_circuit rq.endpoint_circuits%ROWTYPE;
  v_now timestamptz := pg_catalog.clock_timestamp();
BEGIN
  PERFORM rq._assert_session_role(ARRAY['rq_api']);
  SELECT * INTO v_gate FROM rq.installation_state WHERE id = 1 FOR SHARE;
  SELECT * INTO v_circuit FROM rq.endpoint_circuits
   WHERE endpoint_id = p_endpoint_id AND endpoint_version = p_endpoint_version AND project_id = p_project_id AND tenant_id = p_tenant_id
   FOR SHARE;
  IF NOT FOUND OR v_circuit.circuit_generation <> p_expected_circuit_generation THEN
    RAISE EXCEPTION 'Circuit generation mismatch' USING ERRCODE = '23505';
  END IF;

  INSERT INTO rq.command_receipts (
    id, scope_kind, tenant_id, project_id, actor_principal_id, command_family, key_sha256,
    submitted_shape_sha256, effective_request_sha256, resource_kind, resource_id, accepted_version, accepted_at, hash_schema_version
  ) VALUES (
    p_receipt_id, 'project', p_tenant_id, p_project_id, p_requested_by, 'circuit.request_probe',
    p_key_sha256, p_submitted_shape_sha256, p_submitted_shape_sha256, 'circuit_probe_request', p_request_id, 1, v_now, 1
  );

  INSERT INTO rq.circuit_probe_requests (
    id, tenant_id, project_id, endpoint_id, endpoint_version, expected_circuit_generation,
    requested_by, requested_at, expires_at, state, command_receipt_id, version
  ) VALUES (
    p_request_id, p_tenant_id, p_project_id, p_endpoint_id, p_endpoint_version, p_expected_circuit_generation,
    p_requested_by, v_now, v_now + interval '5 minutes', 'pending', p_receipt_id, 1
  );

  RETURN pg_catalog.jsonb_build_object('request_id', p_request_id, 'receipt_id', p_receipt_id, 'state', 'pending');
END;
$$;

CREATE OR REPLACE FUNCTION rq.cmd_replay_propose(
  p_proposal_id uuid,
  p_delivery_id uuid,
  p_proposer_principal_id uuid,
  p_expected_delivery_version bigint,
  p_target_subscription_version bigint,
  p_target_endpoint_version bigint,
  p_wire_envelope_id uuid,
  p_strategy text,
  p_ordering_strategy text,
  p_representation_profile_id uuid,
  p_representation_profile_version bigint,
  p_receiver_contract_id uuid,
  p_receiver_contract_version bigint,
  p_consumer_event_key_sha256 bytea,
  p_candidate_sha256 bytea,
  p_requested_deadline_at timestamptz
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  v_del rq.deliveries%ROWTYPE;
  v_now timestamptz := pg_catalog.clock_timestamp();
BEGIN
  PERFORM rq._assert_session_role(ARRAY['rq_api']);
  SELECT * INTO v_del FROM rq.deliveries WHERE id = p_delivery_id FOR SHARE;
  IF NOT FOUND OR v_del.version <> p_expected_delivery_version THEN
    RAISE EXCEPTION 'Source delivery version mismatch' USING ERRCODE = '23505';
  END IF;

  INSERT INTO rq.replay_proposals (
    id, family_id, source_delivery_id, event_id, tenant_id, project_id, proposer_principal_id,
    source_delivery_version, target_subscription_version, target_endpoint_version, wire_envelope_id,
    strategy, ordering_strategy, representation_profile_id, representation_profile_version,
    receiver_contract_id, receiver_contract_version, consumer_event_key_sha256, candidate_sha256,
    state, requested_deadline_at, created_at, expires_at, version
  ) VALUES (
    p_proposal_id, v_del.family_id, p_delivery_id, v_del.event_id, v_del.tenant_id, v_del.project_id, p_proposer_principal_id,
    p_expected_delivery_version, p_target_subscription_version, p_target_endpoint_version, p_wire_envelope_id,
    p_strategy, p_ordering_strategy, p_representation_profile_id, p_representation_profile_version,
    p_receiver_contract_id, p_receiver_contract_version, p_consumer_event_key_sha256, p_candidate_sha256,
    'proposed', p_requested_deadline_at, v_now, v_now + interval '15 minutes', 1
  );

  RETURN pg_catalog.jsonb_build_object('proposal_id', p_proposal_id, 'state', 'proposed', 'expires_at', v_now + interval '15 minutes');
END;
$$;

CREATE OR REPLACE FUNCTION rq.cmd_replay_review(
  p_review_id uuid,
  p_proposal_id uuid,
  p_expected_proposal_version bigint,
  p_candidate_sha256 bytea,
  p_reviewer_principal_id uuid,
  p_reviewer_authority_version bigint,
  p_decision text
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  v_prop rq.replay_proposals%ROWTYPE;
  v_now timestamptz := pg_catalog.clock_timestamp();
BEGIN
  PERFORM rq._assert_session_role(ARRAY['rq_api']);
  SELECT * INTO v_prop FROM rq.replay_proposals WHERE id = p_proposal_id FOR UPDATE;
  IF NOT FOUND OR v_prop.state <> 'proposed' OR v_prop.version <> p_expected_proposal_version
     OR v_prop.candidate_sha256 <> p_candidate_sha256 OR v_prop.expires_at <= v_now THEN
    RAISE EXCEPTION 'Replay proposal cannot be reviewed in current state/version' USING ERRCODE = '23505';
  END IF;
  IF v_prop.proposer_principal_id = p_reviewer_principal_id THEN
    RAISE EXCEPTION 'Self-review of replay proposal is forbidden' USING ERRCODE = '42501';
  END IF;

  INSERT INTO rq.replay_reviews (
    id, proposal_id, tenant_id, project_id, proposal_version, candidate_sha256,
    reviewer_principal_id, reviewer_authority_version, decision, state, created_at, expires_at
  ) VALUES (
    p_review_id, p_proposal_id, v_prop.tenant_id, v_prop.project_id, p_expected_proposal_version, p_candidate_sha256,
    p_reviewer_principal_id, p_reviewer_authority_version, p_decision, 'active', v_now, v_prop.expires_at
  );

  UPDATE rq.replay_proposals
     SET state = CASE WHEN p_decision = 'approve' THEN 'approved' ELSE 'rejected' END,
         version = version + 1
   WHERE id = p_proposal_id;

  RETURN pg_catalog.jsonb_build_object('review_id', p_review_id, 'proposal_id', p_proposal_id, 'state', CASE WHEN p_decision = 'approve' THEN 'approved' ELSE 'rejected' END);
END;
$$;

CREATE OR REPLACE FUNCTION rq.cmd_replay_admit(
  p_proposal_id uuid,
  p_expected_proposal_version bigint,
  p_candidate_sha256 bytea,
  p_review_id uuid,
  p_actor_principal_id uuid,
  p_new_delivery_id uuid,
  p_receipt_id uuid,
  p_idempotency_key_sha256 bytea
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  v_gate rq.installation_state%ROWTYPE;
  v_prop rq.replay_proposals%ROWTYPE;
  v_rev rq.replay_reviews%ROWTYPE;
  v_fam rq.delivery_families%ROWTYPE;
  v_src rq.deliveries%ROWTYPE;
  v_project rq.projects%ROWTYPE;
  v_now timestamptz := pg_catalog.clock_timestamp();
  v_gen bigint;
  v_shard smallint;
BEGIN
  PERFORM rq._assert_session_role(ARRAY['rq_api']);
  SELECT * INTO v_gate FROM rq.installation_state WHERE id = 1 FOR SHARE;
  SELECT * INTO v_prop FROM rq.replay_proposals WHERE id = p_proposal_id FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'Replay proposal not found' USING ERRCODE = 'P0002';
  END IF;

  IF v_prop.state = 'admitted' AND v_prop.accepted_delivery_id IS NOT NULL THEN
    RETURN pg_catalog.jsonb_build_object('outcome', 'idempotent_recovery', 'delivery_id', v_prop.accepted_delivery_id, 'proposal_id', v_prop.id);
  END IF;

  SELECT * INTO v_project FROM rq.projects WHERE id = v_prop.project_id AND tenant_id = v_prop.tenant_id FOR SHARE;
  IF v_project.projection_maintenance_operation_id IS NOT NULL THEN
    RAISE EXCEPTION 'Project under projection maintenance hold' USING ERRCODE = '55000';
  END IF;

  SELECT * INTO v_rev FROM rq.replay_reviews WHERE id = p_review_id AND proposal_id = p_proposal_id FOR UPDATE;
  IF NOT FOUND OR v_rev.decision <> 'approve' OR v_rev.state <> 'active' OR v_rev.expires_at <= v_now THEN
    RAISE EXCEPTION 'Valid active replay approval review required' USING ERRCODE = '55000';
  END IF;

  IF v_prop.state <> 'approved' OR v_prop.version <> p_expected_proposal_version
     OR v_prop.candidate_sha256 <> p_candidate_sha256 OR v_prop.expires_at <= v_now THEN
    RAISE EXCEPTION 'Replay proposal state/version/expiry conflict' USING ERRCODE = '23505';
  END IF;

  PERFORM 1 FROM rq.tenant_capacity WHERE tenant_id = v_prop.tenant_id FOR UPDATE;
  PERFORM 1 FROM rq.project_capacity WHERE project_id = v_prop.project_id FOR UPDATE;
  SELECT * INTO v_fam FROM rq.delivery_families WHERE id = v_prop.family_id FOR UPDATE;
  SELECT * INTO v_src FROM rq.deliveries WHERE id = v_prop.source_delivery_id FOR SHARE;

  v_gen := v_fam.next_generation;
  UPDATE rq.delivery_families SET next_generation = next_generation + 1, version = version + 1 WHERE id = v_fam.id;

  INSERT INTO rq.deliveries (
    id, family_id, event_id, tenant_id, project_id, subscription_id, original_subscription_version,
    dispatch_subscription_version, endpoint_id, endpoint_version, wire_envelope_id, delivery_generation,
    replay_proposal_id, state, maximum_attempts, deadline_at, next_eligible_at, control_epoch, created_at, updated_at, version
  ) VALUES (
    p_new_delivery_id, v_fam.id, v_prop.event_id, v_prop.tenant_id, v_prop.project_id, v_fam.subscription_id,
    v_fam.original_subscription_version, v_prop.target_subscription_version, v_src.endpoint_id, v_prop.target_endpoint_version,
    v_prop.wire_envelope_id, v_gen, p_proposal_id, 'ready', v_src.maximum_attempts, v_prop.requested_deadline_at,
    v_now, v_gate.control_epoch, v_now, v_now, 1
  );

  INSERT INTO rq.delivery_capacity_positions (
    delivery_id, tenant_id, project_id, endpoint_id, position, version, updated_at
  ) VALUES (
    p_new_delivery_id, v_prop.tenant_id, v_prop.project_id, v_src.endpoint_id, 'pending', 1, v_now
  );

  INSERT INTO rq.command_receipts (
    id, scope_kind, tenant_id, project_id, actor_principal_id, command_family, key_sha256,
    submitted_shape_sha256, effective_request_sha256, resource_kind, resource_id, accepted_version, accepted_at, hash_schema_version
  ) VALUES (
    p_receipt_id, 'project', v_prop.tenant_id, v_prop.project_id, p_actor_principal_id, 'replay.admit',
    p_idempotency_key_sha256, p_candidate_sha256, p_candidate_sha256, 'delivery', p_new_delivery_id, 1, v_now, 1
  );

  UPDATE rq.replay_reviews SET state = 'consumed' WHERE id = v_rev.id;
  UPDATE rq.replay_proposals SET state = 'admitted', accepted_delivery_id = p_new_delivery_id, version = version + 1 WHERE id = p_proposal_id;

  UPDATE rq.tenant_capacity SET pending_deliveries = pending_deliveries + 1, updated_at = v_now, version = version + 1 WHERE tenant_id = v_prop.tenant_id;
  UPDATE rq.project_capacity SET pending_deliveries = pending_deliveries + 1, updated_at = v_now, version = version + 1 WHERE project_id = v_prop.project_id;

  v_shard := rq._delivery_shard(p_new_delivery_id);
  INSERT INTO rq.event_delivery_total_deltas (
    event_id, shard_id, tenant_id, project_id, total_deliveries_delta, updated_at, version
  ) VALUES (
    v_prop.event_id, v_shard, v_prop.tenant_id, v_prop.project_id, 1, v_now, 1
  )
  ON CONFLICT (event_id, shard_id) DO UPDATE
    SET total_deliveries_delta = rq.event_delivery_total_deltas.total_deliveries_delta + 1,
        updated_at = v_now,
        version = rq.event_delivery_total_deltas.version + 1;

  INSERT INTO rq.project_delivery_total_deltas (
    project_id, shard_id, tenant_id, total_deliveries_delta, pending_delta, updated_at, version
  ) VALUES (
    v_prop.project_id, v_shard, v_prop.tenant_id, 1, 1, v_now, 1
  )
  ON CONFLICT (project_id, shard_id) DO UPDATE
    SET total_deliveries_delta = rq.project_delivery_total_deltas.total_deliveries_delta + 1,
        pending_delta = rq.project_delivery_total_deltas.pending_delta + 1,
        updated_at = v_now,
        version = rq.project_delivery_total_deltas.version + 1;

  RETURN pg_catalog.jsonb_build_object(
    'outcome', 'admitted',
    'delivery_id', p_new_delivery_id,
    'delivery_generation', v_gen,
    'receipt_id', p_receipt_id
  );
END;
$$;

CREATE OR REPLACE FUNCTION rq.cmd_order_skip_admit(
  p_proposal_id uuid,
  p_review_id uuid,
  p_actor_principal_id uuid,
  p_disposition_id uuid,
  p_receipt_id uuid,
  p_idempotency_key_sha256 bytea
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  v_prop rq.order_skip_proposals%ROWTYPE;
  v_rev rq.order_skip_reviews%ROWTYPE;
  v_okey rq.ordering_keys%ROWTYPE;
  v_omem rq.ordering_members%ROWTYPE;
  v_del rq.deliveries%ROWTYPE;
  v_now timestamptz := pg_catalog.clock_timestamp();
BEGIN
  PERFORM rq._assert_session_role(ARRAY['rq_api']);
  SELECT * INTO v_prop FROM rq.order_skip_proposals WHERE id = p_proposal_id FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'Order skip proposal not found' USING ERRCODE = 'P0002';
  END IF;
  IF v_prop.state = 'admitted' AND v_prop.accepted_disposition_id IS NOT NULL THEN
    RETURN pg_catalog.jsonb_build_object('outcome', 'idempotent_recovery', 'disposition_id', v_prop.accepted_disposition_id);
  END IF;

  SELECT * INTO v_rev FROM rq.order_skip_reviews WHERE id = p_review_id AND proposal_id = p_proposal_id FOR UPDATE;
  IF NOT FOUND OR v_rev.decision <> 'approve' OR v_rev.state <> 'active' OR v_rev.expires_at <= v_now
     OR v_rev.reviewer_principal_id = v_prop.proposer_principal_id THEN
    RAISE EXCEPTION 'Valid distinct order skip approval required' USING ERRCODE = '42501';
  END IF;

  SELECT * INTO v_okey FROM rq.ordering_keys WHERE id = v_prop.ordering_key_id FOR UPDATE;
  SELECT * INTO v_omem FROM rq.ordering_members WHERE delivery_id = v_prop.delivery_id FOR UPDATE;
  SELECT * INTO v_del FROM rq.deliveries WHERE id = v_prop.delivery_id FOR UPDATE;

  IF v_omem.ordering_sequence <> v_okey.next_eligible_sequence OR v_del.state = 'sending' OR v_del.state = 'acknowledged' THEN
    RAISE EXCEPTION 'Ordering head cannot be skipped in current state' USING ERRCODE = '55000';
  END IF;

  INSERT INTO rq.command_receipts (
    id, scope_kind, tenant_id, project_id, actor_principal_id, command_family, key_sha256,
    submitted_shape_sha256, effective_request_sha256, resource_kind, resource_id, accepted_version, accepted_at, hash_schema_version
  ) VALUES (
    p_receipt_id, 'project', v_prop.tenant_id, v_prop.project_id, p_actor_principal_id, 'order.skip_admit',
    p_idempotency_key_sha256, v_prop.candidate_sha256, v_prop.candidate_sha256, 'order_disposition', p_disposition_id, 1, v_now, 1
  );

  INSERT INTO rq.order_dispositions (
    id, proposal_id, ordering_key_id, delivery_id, prior_sequence, resulting_sequence,
    decision, actor_principal_id, reviewer_principal_id, candidate_sha256, accepted_at, command_receipt_id
  ) VALUES (
    p_disposition_id, p_proposal_id, v_okey.id, v_del.id, v_okey.next_eligible_sequence, v_okey.next_eligible_sequence + 1,
    'reviewed_skip_without_processing_claim', p_actor_principal_id, v_rev.reviewer_principal_id, v_prop.candidate_sha256, v_now, p_receipt_id
  );

  UPDATE rq.ordering_members
     SET state = 'reviewed_skip', disposition_event_id = p_disposition_id, version = version + 1
   WHERE delivery_id = v_del.id;

  UPDATE rq.ordering_keys
     SET next_eligible_sequence = next_eligible_sequence + 1, blocked_delivery_id = NULL, updated_at = v_now, version = version + 1
   WHERE id = v_okey.id;

  UPDATE rq.ordering_members
     SET state = 'eligible', version = version + 1
   WHERE ordering_key_id = v_okey.id AND ordering_sequence = v_okey.next_eligible_sequence + 1 AND state = 'waiting';

  UPDATE rq.order_skip_reviews SET state = 'consumed' WHERE id = v_rev.id;
  UPDATE rq.order_skip_proposals SET state = 'admitted', accepted_disposition_id = p_disposition_id, version = version + 1 WHERE id = p_proposal_id;

  RETURN pg_catalog.jsonb_build_object('outcome', 'admitted', 'disposition_id', p_disposition_id, 'resulting_sequence', v_okey.next_eligible_sequence + 1);
END;
$$;

CREATE OR REPLACE FUNCTION rq.cmd_suppression_admit(
  p_proposal_id uuid,
  p_review_id uuid,
  p_actor_principal_id uuid,
  p_receipt_id uuid,
  p_idempotency_key_sha256 bytea
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  v_prop rq.suppression_proposals%ROWTYPE;
  v_rev rq.suppression_reviews%ROWTYPE;
  v_del rq.deliveries%ROWTYPE;
  v_project rq.projects%ROWTYPE;
  v_now timestamptz := pg_catalog.clock_timestamp();
  v_shard smallint;
BEGIN
  PERFORM rq._assert_session_role(ARRAY['rq_api']);
  SELECT * INTO v_prop FROM rq.suppression_proposals WHERE id = p_proposal_id FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'Suppression proposal not found' USING ERRCODE = 'P0002';
  END IF;
  IF v_prop.state = 'admitted' AND v_prop.accepted_receipt_id IS NOT NULL THEN
    RETURN pg_catalog.jsonb_build_object('outcome', 'idempotent_recovery', 'receipt_id', v_prop.accepted_receipt_id);
  END IF;

  SELECT * INTO v_project FROM rq.projects WHERE id = v_prop.project_id AND tenant_id = v_prop.tenant_id FOR SHARE;
  IF v_project.projection_maintenance_operation_id IS NOT NULL THEN
    RAISE EXCEPTION 'Project under projection maintenance hold' USING ERRCODE = '55000';
  END IF;

  SELECT * INTO v_rev FROM rq.suppression_reviews WHERE id = p_review_id AND proposal_id = p_proposal_id FOR UPDATE;
  IF NOT FOUND OR v_rev.decision <> 'approve' OR v_rev.state <> 'active' OR v_rev.expires_at <= v_now
     OR v_rev.reviewer_principal_id = v_prop.proposer_principal_id THEN
    RAISE EXCEPTION 'Valid distinct suppression approval required' USING ERRCODE = '42501';
  END IF;

  SELECT * INTO v_del FROM rq.deliveries WHERE id = v_prop.delivery_id FOR UPDATE;

  INSERT INTO rq.command_receipts (
    id, scope_kind, tenant_id, project_id, actor_principal_id, command_family, key_sha256,
    submitted_shape_sha256, effective_request_sha256, resource_kind, resource_id, accepted_version, accepted_at, hash_schema_version
  ) VALUES (
    p_receipt_id, 'project', v_prop.tenant_id, v_prop.project_id, p_actor_principal_id, 'delivery.suppress_admit',
    p_idempotency_key_sha256, v_prop.candidate_sha256, v_prop.candidate_sha256, 'delivery', v_del.id, v_del.version, v_now, 1
  );

  UPDATE rq.suppression_reviews SET state = 'consumed' WHERE id = v_rev.id;
  UPDATE rq.suppression_proposals SET state = 'admitted', accepted_receipt_id = p_receipt_id, version = version + 1 WHERE id = p_proposal_id;

  IF v_del.state IN ('acknowledged', 'dead_letter', 'suppressed', 'expired') THEN
    RETURN pg_catalog.jsonb_build_object('outcome', 'already_terminal', 'delivery_state', v_del.state, 'receipt_id', p_receipt_id);
  END IF;

  IF v_del.state NOT IN ('pending', 'ready', 'retry_wait') OR v_del.current_attempt_id IS NOT NULL THEN
    RAISE EXCEPTION 'Delivery cannot be suppressed while active' USING ERRCODE = '55000';
  END IF;

  UPDATE rq.deliveries
     SET state = 'suppressed', terminal_at = v_now, updated_at = v_now, version = version + 1
   WHERE id = v_del.id;

  UPDATE rq.delivery_capacity_positions
     SET position = 'released', released_at = v_now, updated_at = v_now, version = version + 1
   WHERE delivery_id = v_del.id;

  UPDATE rq.tenant_capacity SET pending_deliveries = pending_deliveries - 1, updated_at = v_now, version = version + 1 WHERE tenant_id = v_del.tenant_id;
  UPDATE rq.project_capacity SET pending_deliveries = pending_deliveries - 1, updated_at = v_now, version = version + 1 WHERE project_id = v_del.project_id;

  v_shard := rq._delivery_shard(v_del.id);
  INSERT INTO rq.event_delivery_total_deltas (
    event_id, shard_id, tenant_id, project_id, terminal_deliveries_delta, last_outcome_at, updated_at, version
  ) VALUES (
    v_del.event_id, v_shard, v_del.tenant_id, v_del.project_id, 1, v_now, v_now, 1
  )
  ON CONFLICT (event_id, shard_id) DO UPDATE
    SET terminal_deliveries_delta = rq.event_delivery_total_deltas.terminal_deliveries_delta + 1,
        last_outcome_at = v_now,
        updated_at = v_now,
        version = rq.event_delivery_total_deltas.version + 1;

  INSERT INTO rq.project_delivery_total_deltas (
    project_id, shard_id, tenant_id, pending_delta, suppressed_delta, updated_at, version
  ) VALUES (
    v_del.project_id, v_shard, v_del.tenant_id, -1, 1, v_now, 1
  )
  ON CONFLICT (project_id, shard_id) DO UPDATE
    SET pending_delta = rq.project_delivery_total_deltas.pending_delta - 1,
        suppressed_delta = rq.project_delivery_total_deltas.suppressed_delta + 1,
        updated_at = v_now,
        version = rq.project_delivery_total_deltas.version + 1;

  RETURN pg_catalog.jsonb_build_object('outcome', 'suppressed', 'delivery_id', v_del.id, 'receipt_id', p_receipt_id);
END;
$$;

CREATE OR REPLACE FUNCTION rq.cmd_watch_lease_open(
  p_lease_id uuid,
  p_tenant_id uuid,
  p_project_id uuid,
  p_principal_id uuid,
  p_actor_kind text,
  p_session_id uuid,
  p_producer_credential_id uuid,
  p_resource_kind text,
  p_resource_id uuid,
  p_runtime_instance_id uuid,
  p_control_epoch uuid,
  p_auth_cutoff_at timestamptz,
  p_stream_cutoff_at timestamptz
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  v_gate rq.installation_state%ROWTYPE;
  v_ac rq.actor_watch_capacity%ROWTYPE;
  v_tc rq.tenant_watch_capacity%ROWTYPE;
  v_pc rq.project_watch_capacity%ROWTYPE;
  v_now timestamptz := pg_catalog.clock_timestamp();
  v_expires_at timestamptz;
BEGIN
  PERFORM rq._assert_session_role(ARRAY['rq_api']);
  SELECT * INTO v_gate FROM rq.installation_state WHERE id = 1 FOR SHARE;
  IF v_gate.control_epoch <> p_control_epoch OR v_gate.mode IN ('recovery_quarantine', 'retired') THEN
    RAISE EXCEPTION 'Watch admission closed by installation gate' USING ERRCODE = '55000';
  END IF;

  INSERT INTO rq.actor_watch_capacity (principal_id) VALUES (p_principal_id) ON CONFLICT (principal_id) DO NOTHING;
  INSERT INTO rq.tenant_watch_capacity (tenant_id) VALUES (p_tenant_id) ON CONFLICT (tenant_id) DO NOTHING;
  INSERT INTO rq.project_watch_capacity (project_id, tenant_id) VALUES (p_project_id, p_tenant_id) ON CONFLICT (project_id) DO NOTHING;

  SELECT * INTO v_ac FROM rq.actor_watch_capacity WHERE principal_id = p_principal_id FOR UPDATE;
  SELECT * INTO v_tc FROM rq.tenant_watch_capacity WHERE tenant_id = p_tenant_id FOR UPDATE;
  SELECT * INTO v_pc FROM rq.project_watch_capacity WHERE project_id = p_project_id FOR UPDATE;

  IF v_ac.held_count >= v_ac.approved_count OR v_tc.held_count >= v_tc.approved_count OR v_pc.held_count >= v_pc.approved_count THEN
    RAISE EXCEPTION 'Watch stream quota exceeded' USING ERRCODE = '53400';
  END IF;

  v_expires_at := LEAST(v_now + interval '5 seconds', p_auth_cutoff_at, p_stream_cutoff_at);
  INSERT INTO rq.watch_leases (
    id, tenant_id, project_id, principal_id, actor_kind, session_id, producer_credential_id,
    resource_kind, resource_id, runtime_instance_id, control_epoch, state, slot_state,
    opened_at, last_renewed_at, expires_at, stream_cutoff_at, version
  ) VALUES (
    p_lease_id, p_tenant_id, p_project_id, p_principal_id, p_actor_kind, p_session_id, p_producer_credential_id,
    p_resource_kind, p_resource_id, p_runtime_instance_id, p_control_epoch, 'open', 'held',
    v_now, v_now, v_expires_at, p_stream_cutoff_at, 1
  );

  UPDATE rq.actor_watch_capacity SET held_count = held_count + 1, updated_at = v_now, version = version + 1 WHERE principal_id = p_principal_id;
  UPDATE rq.tenant_watch_capacity SET held_count = held_count + 1, updated_at = v_now, version = version + 1 WHERE tenant_id = p_tenant_id;
  UPDATE rq.project_watch_capacity SET held_count = held_count + 1, updated_at = v_now, version = version + 1 WHERE project_id = p_project_id;

  RETURN pg_catalog.jsonb_build_object('lease_id', p_lease_id, 'expires_at', v_expires_at, 'stream_cutoff_at', p_stream_cutoff_at);
END;
$$;

CREATE OR REPLACE FUNCTION rq.cmd_watch_lease_renew(
  p_lease_id uuid,
  p_control_epoch uuid,
  p_auth_cutoff_at timestamptz
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  v_lease rq.watch_leases%ROWTYPE;
  v_now timestamptz := pg_catalog.clock_timestamp();
  v_expires_at timestamptz;
BEGIN
  PERFORM rq._assert_session_role(ARRAY['rq_api']);
  SELECT * INTO v_lease FROM rq.watch_leases WHERE id = p_lease_id FOR UPDATE;
  IF NOT FOUND OR v_lease.state <> 'open' OR v_lease.control_epoch <> p_control_epoch OR v_now >= v_lease.stream_cutoff_at THEN
    RAISE EXCEPTION 'Watch lease cannot be renewed' USING ERRCODE = '55000';
  END IF;
  IF v_now < v_lease.last_renewed_at + interval '1 second' THEN
    RAISE EXCEPTION 'Watch lease renewal rate limit (1/s)' USING ERRCODE = '53400';
  END IF;

  v_expires_at := LEAST(v_now + interval '5 seconds', p_auth_cutoff_at, v_lease.stream_cutoff_at);
  UPDATE rq.watch_leases
     SET last_renewed_at = v_now, expires_at = v_expires_at, version = version + 1
   WHERE id = p_lease_id;

  RETURN pg_catalog.jsonb_build_object('lease_id', p_lease_id, 'expires_at', v_expires_at);
END;
$$;

CREATE OR REPLACE FUNCTION rq.cmd_watch_lease_close(p_lease_id uuid)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  v_lease rq.watch_leases%ROWTYPE;
  v_now timestamptz := pg_catalog.clock_timestamp();
BEGIN
  PERFORM rq._assert_session_role(ARRAY['rq_api', 'rq_coordinator']);
  SELECT * INTO v_lease FROM rq.watch_leases WHERE id = p_lease_id;
  IF NOT FOUND THEN
    RETURN pg_catalog.jsonb_build_object('outcome', 'not_found');
  END IF;

  PERFORM 1 FROM rq.actor_watch_capacity WHERE principal_id = v_lease.principal_id FOR UPDATE;
  PERFORM 1 FROM rq.tenant_watch_capacity WHERE tenant_id = v_lease.tenant_id FOR UPDATE;
  PERFORM 1 FROM rq.project_watch_capacity WHERE project_id = v_lease.project_id FOR UPDATE;
  SELECT * INTO v_lease FROM rq.watch_leases WHERE id = p_lease_id FOR UPDATE;

  IF v_lease.state = 'closed' THEN
    RETURN pg_catalog.jsonb_build_object('outcome', 'already_closed', 'lease_id', p_lease_id);
  END IF;

  UPDATE rq.watch_leases
     SET state = 'closed', slot_state = 'released', closed_at = v_now, version = version + 1
   WHERE id = p_lease_id;

  UPDATE rq.actor_watch_capacity SET held_count = GREATEST(0, held_count - 1), updated_at = v_now, version = version + 1 WHERE principal_id = v_lease.principal_id;
  UPDATE rq.tenant_watch_capacity SET held_count = GREATEST(0, held_count - 1), updated_at = v_now, version = version + 1 WHERE tenant_id = v_lease.tenant_id;
  UPDATE rq.project_watch_capacity SET held_count = GREATEST(0, held_count - 1), updated_at = v_now, version = version + 1 WHERE project_id = v_lease.project_id;

  RETURN pg_catalog.jsonb_build_object('outcome', 'closed', 'lease_id', p_lease_id);
END;
$$;

CREATE OR REPLACE FUNCTION rq.cmd_signing_delivery_finalize(
  p_intent_id uuid,
  p_control_epoch uuid,
  p_next_state text
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  v_gate rq.installation_state%ROWTYPE;
  v_intent rq.signing_delivery_intents%ROWTYPE;
BEGIN
  PERFORM rq._assert_session_role(ARRAY['rq_signing_issuer']);
  SELECT * INTO v_gate FROM rq.installation_state WHERE id = 1 FOR SHARE;
  SELECT * INTO v_intent FROM rq.signing_delivery_intents WHERE id = p_intent_id FOR UPDATE;
  IF NOT FOUND OR v_gate.control_epoch <> p_control_epoch OR v_intent.control_epoch <> p_control_epoch THEN
    RAISE EXCEPTION 'Signing delivery intent epoch mismatch' USING ERRCODE = '55000';
  END IF;
  UPDATE rq.signing_delivery_intents SET state = p_next_state, version = version + 1 WHERE id = p_intent_id;
  RETURN pg_catalog.jsonb_build_object('intent_id', p_intent_id, 'state', p_next_state);
END;
$$;

CREATE OR REPLACE FUNCTION rq.cmd_producer_credential_intent_finalize(
  p_intent_id uuid,
  p_control_epoch uuid,
  p_next_state text,
  p_credential_id uuid,
  p_secret_digest bytea,
  p_expires_at timestamptz
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  v_gate rq.installation_state%ROWTYPE;
  v_intent rq.producer_credential_intents%ROWTYPE;
  v_prod rq.producers%ROWTYPE;
  v_now timestamptz := pg_catalog.clock_timestamp();
BEGIN
  PERFORM rq._assert_session_role(ARRAY['rq_signing_issuer']);
  SELECT * INTO v_gate FROM rq.installation_state WHERE id = 1 FOR SHARE;
  SELECT * INTO v_intent FROM rq.producer_credential_intents WHERE id = p_intent_id FOR UPDATE;
  IF NOT FOUND OR v_gate.control_epoch <> p_control_epoch OR v_intent.control_epoch <> p_control_epoch THEN
    RAISE EXCEPTION 'Producer credential intent epoch mismatch' USING ERRCODE = '55000';
  END IF;
  SELECT * INTO v_prod FROM rq.producers WHERE id = v_intent.producer_id FOR SHARE;

  IF p_next_state = 'delivered' AND p_credential_id IS NOT NULL AND p_secret_digest IS NOT NULL THEN
    INSERT INTO rq.producer_credentials (
      id, producer_id, tenant_id, project_id, principal_id, channel_kind, control_epoch, secret_digest,
      state, scope_version, owner_authority_epoch, issued_by, intent_id, created_at, expires_at, version
    ) VALUES (
      p_credential_id, v_intent.producer_id, v_intent.tenant_id, v_intent.project_id, v_prod.principal_id,
      'machine_producer', p_control_epoch, p_secret_digest, 'pending_activation', v_intent.scope_version,
      v_prod.authority_epoch, v_intent.issuer_principal_id, p_intent_id, v_now, p_expires_at, 1
    )
    ON CONFLICT (intent_id) DO NOTHING;
  END IF;

  UPDATE rq.producer_credential_intents
     SET state = p_next_state,
         credential_id = COALESCE(p_credential_id, credential_id),
         version = version + 1
   WHERE id = p_intent_id;

  RETURN pg_catalog.jsonb_build_object('intent_id', p_intent_id, 'state', p_next_state, 'credential_id', p_credential_id);
END;
$$;

CREATE OR REPLACE FUNCTION rq.cmd_outbox_recovery_generation(
  p_outbox_id uuid,
  p_episode_id uuid,
  p_instance_id uuid,
  p_control_epoch uuid,
  p_envelope_bytes bytea,
  p_envelope_sha256 bytea,
  p_broker_message_id text,
  p_reason_code text
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  v_gate rq.installation_state%ROWTYPE;
  v_outbox rq.outbox_events%ROWTYPE;
  v_fanout rq.event_fanout%ROWTYPE;
  v_ep rq.publication_recovery_episodes%ROWTYPE;
  v_now timestamptz := pg_catalog.clock_timestamp();
  v_next_gen bigint;
  v_next_count integer;
  v_req_review boolean;
BEGIN
  PERFORM rq._assert_session_role(ARRAY['rq_coordinator']);
  SELECT * INTO v_gate FROM rq.installation_state WHERE id = 1 FOR SHARE;
  IF v_gate.control_epoch <> p_control_epoch OR NOT v_gate.allow_publication THEN
    RAISE EXCEPTION 'Recovery generation denied by gate' USING ERRCODE = '55000';
  END IF;

  SELECT * INTO v_outbox FROM rq.outbox_events WHERE id = p_outbox_id FOR UPDATE;
  SELECT * INTO v_fanout FROM rq.event_fanout WHERE event_id = v_outbox.event_id FOR SHARE;
  IF v_fanout.state = 'completed' THEN
    RETURN pg_catalog.jsonb_build_object('outcome', 'already_complete', 'event_id', v_fanout.event_id);
  END IF;

  SELECT * INTO v_ep FROM rq.publication_recovery_episodes WHERE outbox_id = p_outbox_id AND state = 'active' FOR UPDATE;
  IF NOT FOUND THEN
    INSERT INTO rq.publication_recovery_episodes (
      id, outbox_id, event_id, control_epoch, state, starting_fanout_version,
      last_progress_boundary_sha256, successive_no_progress_generations, created_at, version
    ) VALUES (
      p_episode_id, p_outbox_id, v_outbox.event_id, p_control_epoch, 'active', v_fanout.version,
      pg_catalog.sha256(pg_catalog.convert_to(v_fanout.version::text, 'UTF8')), 0, v_now, 1
    )
    RETURNING * INTO v_ep;
  END IF;

  IF v_ep.last_generation_at IS NOT NULL AND v_now < v_ep.last_generation_at + interval '60 seconds' THEN
    RAISE EXCEPTION 'Recovery generation rate limit (1/minute) active' USING ERRCODE = '53400';
  END IF;

  v_next_count := v_ep.successive_no_progress_generations + 1;
  v_req_review := v_next_count >= 5;

  UPDATE rq.outbox_publications
     SET state = 'recovery_superseded'
   WHERE outbox_id = p_outbox_id AND publication_generation = v_outbox.current_publication_generation;

  IF v_req_review THEN
    UPDATE rq.publication_recovery_episodes
       SET state = 'review_required',
           successive_no_progress_generations = v_next_count,
           last_generation_at = v_now,
           version = version + 1
     WHERE id = v_ep.id;

    UPDATE rq.outbox_events
       SET state = 'blocked',
           last_safe_error_code = 'RECOVERY_NO_PROGRESS_THRESHOLD',
           updated_at = v_now,
           version = version + 1
     WHERE id = p_outbox_id;

    RETURN pg_catalog.jsonb_build_object('outcome', 'review_required', 'episode_id', v_ep.id);
  END IF;

  v_next_gen := v_outbox.current_publication_generation + 1;
  INSERT INTO rq.outbox_publications (
    outbox_id, publication_generation, tenant_id, project_id, envelope_version, envelope_bytes,
    envelope_sha256, broker_message_id, state, send_count, created_at
  ) VALUES (
    p_outbox_id, v_next_gen, v_outbox.tenant_id, v_outbox.project_id, 1, p_envelope_bytes,
    p_envelope_sha256, p_broker_message_id, 'prepared', 0, v_now
  );

  UPDATE rq.outbox_events
     SET state = 'pending',
         current_publication_generation = v_next_gen,
         claim_owner_instance_id = NULL,
         claim_control_epoch = NULL,
         claim_expires_at = NULL,
         next_publish_at = v_now,
         last_safe_error_code = p_reason_code,
         updated_at = v_now,
         version = version + 1
   WHERE id = p_outbox_id;

  UPDATE rq.publication_recovery_episodes
     SET successive_no_progress_generations = v_next_count,
         last_generation_at = v_now,
         version = version + 1
   WHERE id = v_ep.id;

  RETURN pg_catalog.jsonb_build_object('outcome', 'allocated', 'publication_generation', v_next_gen, 'episode_id', v_ep.id);
END;
$$;

CREATE OR REPLACE FUNCTION rq.cmd_coordinator_reap_expired(
  p_instance_id uuid,
  p_control_epoch uuid,
  p_batch_limit integer DEFAULT 50
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  v_gate rq.installation_state%ROWTYPE;
  v_now timestamptz := pg_catalog.clock_timestamp();
  v_att rq.delivery_attempts%ROWTYPE;
  v_del rq.deliveries%ROWTYPE;
  v_lease_id uuid;
  v_reaped_attempts integer := 0;
  v_reaped_leases integer := 0;
  v_shard smallint;
BEGIN
  PERFORM rq._assert_session_role(ARRAY['rq_coordinator']);
  SELECT * INTO v_gate FROM rq.installation_state WHERE id = 1 FOR SHARE;
  IF v_gate.control_epoch <> p_control_epoch OR v_gate.mode IN ('recovery_quarantine', 'retired') THEN
    RAISE EXCEPTION 'Coordinator reaper blocked by installation gate' USING ERRCODE = '55000';
  END IF;

  FOR v_att IN
    SELECT a.*
      FROM rq.delivery_attempts a
      JOIN rq.projects p ON p.id = a.project_id AND p.tenant_id = a.tenant_id
     WHERE a.state IN ('prepared', 'send_started')
       AND a.claim_expires_at <= v_now
       AND p.projection_maintenance_operation_id IS NULL
     ORDER BY a.claim_expires_at ASC
     LIMIT GREATEST(1, LEAST(100, p_batch_limit))
  LOOP
    PERFORM 1 FROM rq.projects WHERE id = v_att.project_id FOR SHARE;
    SELECT * INTO v_del FROM rq.deliveries WHERE id = v_att.delivery_id;
    PERFORM 1 FROM rq.events WHERE id = v_del.event_id FOR SHARE;
    PERFORM 1 FROM rq.sender_capacity WHERE instance_id = v_att.worker_instance_id FOR UPDATE;
    PERFORM 1 FROM rq.tenant_capacity WHERE tenant_id = v_att.tenant_id FOR UPDATE;
    PERFORM 1 FROM rq.project_capacity WHERE project_id = v_att.project_id FOR UPDATE;
    PERFORM 1 FROM rq.endpoint_capacity WHERE endpoint_id = v_att.endpoint_id FOR UPDATE;
    SELECT * INTO v_del FROM rq.deliveries WHERE id = v_att.delivery_id FOR UPDATE;
    SELECT * INTO v_att FROM rq.delivery_attempts WHERE id = v_att.id FOR UPDATE;

    IF v_att.state NOT IN ('prepared', 'send_started') OR v_att.claim_expires_at > v_now THEN
      CONTINUE;
    END IF;

    IF v_att.state = 'prepared' THEN
      UPDATE rq.tenant_rate_buckets
         SET reserved_micro = reserved_micro - 1000000, updated_at = v_now, version = version + 1
       WHERE tenant_id = v_att.tenant_id AND operation = 'send_start'
         AND EXISTS (SELECT 1 FROM rq.tenant_send_reservations r WHERE r.attempt_id = v_att.id AND r.state = 'held');
      UPDATE rq.project_rate_buckets
         SET reserved_micro = reserved_micro - 1000000, updated_at = v_now, version = version + 1
       WHERE project_id = v_att.project_id AND operation = 'send_start'
         AND EXISTS (SELECT 1 FROM rq.project_send_reservations r WHERE r.attempt_id = v_att.id AND r.state = 'held');
      UPDATE rq.endpoint_rate_buckets
         SET reserved_micro = reserved_micro - 1000000, updated_at = v_now, version = version + 1
       WHERE endpoint_id = v_att.endpoint_id AND operation = 'send_start'
         AND EXISTS (SELECT 1 FROM rq.endpoint_send_reservations r WHERE r.attempt_id = v_att.id AND r.state = 'held');
      UPDATE rq.tenant_send_reservations SET state = 'released', released_at = v_now, version = version + 1 WHERE attempt_id = v_att.id AND state = 'held';
      UPDATE rq.project_send_reservations SET state = 'released', released_at = v_now, version = version + 1 WHERE attempt_id = v_att.id AND state = 'held';
      UPDATE rq.endpoint_send_reservations SET state = 'released', released_at = v_now, version = version + 1 WHERE attempt_id = v_att.id AND state = 'held';
    END IF;

    UPDATE rq.delivery_attempts
       SET state = 'abandoned',
           outcome_class = CASE WHEN v_att.state = 'send_started' THEN 'transport_unknown' ELSE NULL END,
           safe_error_code = 'LEASE_EXPIRED',
           finished_at = v_now,
           version = version + 1
     WHERE id = v_att.id;

    UPDATE rq.deliveries
       SET state = CASE WHEN v_now >= deadline_at THEN 'expired' ELSE 'retry_wait' END,
           current_attempt_id = NULL,
           next_eligible_at = CASE WHEN v_now < deadline_at THEN v_now + interval '1 second' ELSE next_eligible_at END,
           terminal_at = CASE WHEN v_now >= deadline_at THEN v_now ELSE NULL END,
           last_outcome_class = CASE WHEN v_att.state = 'send_started' THEN 'transport_unknown' ELSE last_outcome_class END,
           updated_at = v_now,
           version = version + 1
     WHERE id = v_del.id AND current_attempt_id = v_att.id;

    UPDATE rq.attempt_slots SET state = 'released', released_at = v_now, release_reason = 'abandoned', version = version + 1 WHERE attempt_id = v_att.id AND state = 'held';
    UPDATE rq.sender_capacity SET held_slots = held_slots - 1, updated_at = v_now, version = version + 1 WHERE instance_id = v_att.worker_instance_id;
    UPDATE rq.tenant_capacity
       SET active_attempt_slots = active_attempt_slots - 1,
           pending_deliveries = pending_deliveries - CASE WHEN v_now >= v_del.deadline_at THEN 1 ELSE 0 END,
           updated_at = v_now, version = version + 1
     WHERE tenant_id = v_att.tenant_id;
    UPDATE rq.project_capacity
       SET active_attempt_slots = active_attempt_slots - 1,
           pending_deliveries = pending_deliveries - CASE WHEN v_now >= v_del.deadline_at THEN 1 ELSE 0 END,
           updated_at = v_now, version = version + 1
     WHERE project_id = v_att.project_id;
    UPDATE rq.endpoint_capacity SET held_slots = held_slots - 1, updated_at = v_now, version = version + 1 WHERE endpoint_id = v_att.endpoint_id;
    UPDATE rq.delivery_capacity_positions
       SET position = CASE WHEN v_now >= v_del.deadline_at THEN 'released' ELSE 'pending' END,
           current_attempt_id = NULL,
           released_at = CASE WHEN v_now >= v_del.deadline_at THEN v_now ELSE NULL END,
           updated_at = v_now, version = version + 1
     WHERE delivery_id = v_del.id;

    v_shard := rq._delivery_shard(v_del.id);
    INSERT INTO rq.project_delivery_total_deltas (
      project_id, shard_id, tenant_id, pending_delta, active_delta, expired_delta, unknown_attempt_observations_delta, updated_at, version
    ) VALUES (
      v_del.project_id, v_shard, v_del.tenant_id,
      CASE WHEN v_now >= v_del.deadline_at THEN 0 ELSE 1 END, -1,
      CASE WHEN v_now >= v_del.deadline_at THEN 1 ELSE 0 END,
      CASE WHEN v_att.state = 'send_started' THEN 1 ELSE 0 END,
      v_now, 1
    )
    ON CONFLICT (project_id, shard_id) DO UPDATE
      SET pending_delta = rq.project_delivery_total_deltas.pending_delta + CASE WHEN v_now >= v_del.deadline_at THEN 0 ELSE 1 END,
          active_delta = rq.project_delivery_total_deltas.active_delta - 1,
          expired_delta = rq.project_delivery_total_deltas.expired_delta + CASE WHEN v_now >= v_del.deadline_at THEN 1 ELSE 0 END,
          unknown_attempt_observations_delta = rq.project_delivery_total_deltas.unknown_attempt_observations_delta + CASE WHEN v_att.state = 'send_started' THEN 1 ELSE 0 END,
          updated_at = v_now, version = rq.project_delivery_total_deltas.version + 1;

    v_reaped_attempts := v_reaped_attempts + 1;
  END LOOP;

  FOR v_lease_id IN
    SELECT id FROM rq.watch_leases WHERE state = 'open' AND expires_at <= v_now ORDER BY expires_at ASC LIMIT 100
  LOOP
    PERFORM rq.cmd_watch_lease_close(v_lease_id);
    v_reaped_leases := v_reaped_leases + 1;
  END LOOP;

  RETURN pg_catalog.jsonb_build_object('reaped_attempts', v_reaped_attempts, 'reaped_watch_leases', v_reaped_leases);
END;
$$;

CREATE OR REPLACE FUNCTION rq.cmd_retention_finalize(
  p_action_id uuid,
  p_instance_id uuid,
  p_control_epoch uuid,
  p_claim_generation bigint
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  v_gate rq.installation_state%ROWTYPE;
  v_act rq.retention_actions%ROWTYPE;
  v_now timestamptz := pg_catalog.clock_timestamp();
BEGIN
  PERFORM rq._assert_session_role(ARRAY['rq_coordinator']);
  SELECT * INTO v_gate FROM rq.installation_state WHERE id = 1 FOR SHARE;
  SELECT * INTO v_act FROM rq.retention_actions WHERE id = p_action_id FOR UPDATE;
  IF NOT FOUND OR v_gate.control_epoch <> p_control_epoch THEN
    RAISE EXCEPTION 'Retention action or epoch invalid' USING ERRCODE = '55000';
  END IF;
  IF v_act.state = 'completed' THEN
    RETURN pg_catalog.jsonb_build_object('outcome', 'already_complete', 'action_id', p_action_id);
  END IF;
  IF v_act.state <> 'claimed' OR v_act.owner_instance_id <> p_instance_id
     OR v_act.claim_control_epoch <> p_control_epoch OR v_act.claim_generation <> p_claim_generation THEN
    RAISE EXCEPTION 'Retention action claim mismatch' USING ERRCODE = '55P03';
  END IF;

  IF v_act.action = 'expire_payload' THEN
    UPDATE rq.event_payloads
       SET content = NULL, retention_state = 'expired', expired_at = v_now, retention_action_id = p_action_id
     WHERE id = v_act.target_id AND project_id = v_act.project_id AND tenant_id = v_act.tenant_id AND retention_state <> 'expired';
  ELSIF v_act.action = 'expire_wire' THEN
    UPDATE rq.event_wire_envelopes
       SET body_bytes = NULL, retention_state = 'expired', expired_at = v_now, retention_action_id = p_action_id
     WHERE id = v_act.target_id AND project_id = v_act.project_id AND tenant_id = v_act.tenant_id AND retention_state <> 'expired';
  END IF;

  UPDATE rq.retention_actions
     SET state = 'completed', owner_instance_id = NULL, claim_control_epoch = NULL, claim_expires_at = NULL, version = version + 1
   WHERE id = p_action_id;

  RETURN pg_catalog.jsonb_build_object('outcome', 'completed', 'action_id', p_action_id, 'action', v_act.action);
END;
$$;

CREATE OR REPLACE FUNCTION rq.cmd_compact_delivery_total_deltas(
  p_tenant_id uuid,
  p_project_id uuid,
  p_event_id uuid DEFAULT NULL
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  v_now timestamptz := pg_catalog.clock_timestamp();
  v_tot bigint := 0;
  v_term bigint := 0;
  v_ack bigint := 0;
  v_last timestamptz;
  v_ptot bigint := 0;
  v_ppend bigint := 0;
  v_pact bigint := 0;
  v_pack bigint := 0;
  v_pdlq bigint := 0;
  v_psup bigint := 0;
  v_pexp bigint := 0;
  v_punk bigint := 0;
BEGIN
  PERFORM rq._assert_session_role(ARRAY['rq_coordinator', 'rq_recovery']);

  IF p_event_id IS NOT NULL THEN
    SELECT
      COALESCE(pg_catalog.sum(total_deliveries_delta), 0)::bigint,
      COALESCE(pg_catalog.sum(terminal_deliveries_delta), 0)::bigint,
      COALESCE(pg_catalog.sum(acknowledged_deliveries_delta), 0)::bigint,
      pg_catalog.max(last_outcome_at)
      INTO v_tot, v_term, v_ack, v_last
      FROM rq.event_delivery_total_deltas
     WHERE event_id = p_event_id AND project_id = p_project_id AND tenant_id = p_tenant_id;

    UPDATE rq.event_delivery_totals
       SET total_deliveries = total_deliveries + v_tot,
           terminal_deliveries = terminal_deliveries + v_term,
           acknowledged_deliveries = acknowledged_deliveries + v_ack,
           last_outcome_at = GREATEST(last_outcome_at, v_last),
           updated_at = v_now,
           version = version + 1
     WHERE event_id = p_event_id AND project_id = p_project_id AND tenant_id = p_tenant_id;

    DELETE FROM rq.event_delivery_total_deltas
     WHERE event_id = p_event_id AND project_id = p_project_id AND tenant_id = p_tenant_id;
  END IF;

  SELECT
    COALESCE(pg_catalog.sum(total_deliveries_delta), 0)::bigint,
    COALESCE(pg_catalog.sum(pending_delta), 0)::bigint,
    COALESCE(pg_catalog.sum(active_delta), 0)::bigint,
    COALESCE(pg_catalog.sum(acknowledged_delta), 0)::bigint,
    COALESCE(pg_catalog.sum(dead_letter_delta), 0)::bigint,
    COALESCE(pg_catalog.sum(suppressed_delta), 0)::bigint,
    COALESCE(pg_catalog.sum(expired_delta), 0)::bigint,
    COALESCE(pg_catalog.sum(unknown_attempt_observations_delta), 0)::bigint
    INTO v_ptot, v_ppend, v_pact, v_pack, v_pdlq, v_psup, v_pexp, v_punk
    FROM rq.project_delivery_total_deltas
   WHERE project_id = p_project_id AND tenant_id = p_tenant_id;

  INSERT INTO rq.project_delivery_totals (
    project_id, tenant_id, total_deliveries, pending_count, active_count, acknowledged_count,
    dead_letter_count, suppressed_count, expired_count, unknown_attempt_observations, updated_at, version
  ) VALUES (
    p_project_id, p_tenant_id, v_ptot, v_ppend, v_pact, v_pack, v_pdlq, v_psup, v_pexp, v_punk, v_now, 1
  )
  ON CONFLICT (project_id) DO UPDATE
    SET total_deliveries = rq.project_delivery_totals.total_deliveries + v_ptot,
        pending_count = rq.project_delivery_totals.pending_count + v_ppend,
        active_count = rq.project_delivery_totals.active_count + v_pact,
        acknowledged_count = rq.project_delivery_totals.acknowledged_count + v_pack,
        dead_letter_count = rq.project_delivery_totals.dead_letter_count + v_pdlq,
        suppressed_count = rq.project_delivery_totals.suppressed_count + v_psup,
        expired_count = rq.project_delivery_totals.expired_count + v_pexp,
        unknown_attempt_observations = rq.project_delivery_totals.unknown_attempt_observations + v_punk,
        updated_at = v_now,
        version = rq.project_delivery_totals.version + 1;

  DELETE FROM rq.project_delivery_total_deltas
   WHERE project_id = p_project_id AND tenant_id = p_tenant_id;

  RETURN pg_catalog.jsonb_build_object('compacted_at', v_now, 'project_id', p_project_id, 'event_id', p_event_id);
END;
$$;

-- 6. Safe and role-specific SECURITY DEFINER read functions
CREATE OR REPLACE FUNCTION rq.read_installation_status()
RETURNS jsonb
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
  SELECT pg_catalog.jsonb_build_object(
    'control_epoch', control_epoch,
    'mode', mode,
    'allow_event_admission', allow_event_admission,
    'allow_publication', allow_publication,
    'allow_fanout', allow_fanout,
    'allow_send', allow_send,
    'allow_endpoint_verification', allow_endpoint_verification,
    'governance_version', governance_version::text,
    'updated_at', updated_at,
    'version', version::text
  )
  FROM rq.installation_state
  WHERE id = 1;
$$;

CREATE OR REPLACE FUNCTION rq.read_schema_migrations()
RETURNS TABLE (
  migration_id text,
  checksum bytea,
  applied_at timestamptz,
  source_reference text,
  runner_version text
)
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
  SELECT migration_id, checksum, applied_at, source_reference, runner_version
    FROM rq.schema_migrations
   ORDER BY migration_id ASC;
$$;

CREATE OR REPLACE FUNCTION rq.read_project_delivery_totals(
  p_tenant_id uuid,
  p_project_id uuid
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  v_base rq.project_delivery_totals%ROWTYPE;
  v_d record;
BEGIN
  PERFORM rq._assert_session_role(ARRAY['rq_api', 'rq_reporter', 'rq_coordinator', 'rq_recovery']);

  SELECT * INTO v_base FROM rq.project_delivery_totals WHERE project_id = p_project_id AND tenant_id = p_tenant_id;
  SELECT
    COALESCE(pg_catalog.sum(total_deliveries_delta), 0)::bigint AS tot,
    COALESCE(pg_catalog.sum(pending_delta), 0)::bigint AS pend,
    COALESCE(pg_catalog.sum(active_delta), 0)::bigint AS act,
    COALESCE(pg_catalog.sum(acknowledged_delta), 0)::bigint AS ack,
    COALESCE(pg_catalog.sum(dead_letter_delta), 0)::bigint AS dlq,
    COALESCE(pg_catalog.sum(suppressed_delta), 0)::bigint AS sup,
    COALESCE(pg_catalog.sum(expired_delta), 0)::bigint AS exp,
    COALESCE(pg_catalog.sum(unknown_attempt_observations_delta), 0)::bigint AS unk
    INTO v_d
    FROM rq.project_delivery_total_deltas
   WHERE project_id = p_project_id AND tenant_id = p_tenant_id;

  RETURN pg_catalog.jsonb_build_object(
    'project_id', p_project_id,
    'tenant_id', p_tenant_id,
    'total_deliveries', (COALESCE(v_base.total_deliveries, 0) + v_d.tot)::text,
    'pending_count', (COALESCE(v_base.pending_count, 0) + v_d.pend)::text,
    'active_count', (COALESCE(v_base.active_count, 0) + v_d.act)::text,
    'acknowledged_count', (COALESCE(v_base.acknowledged_count, 0) + v_d.ack)::text,
    'dead_letter_count', (COALESCE(v_base.dead_letter_count, 0) + v_d.dlq)::text,
    'suppressed_count', (COALESCE(v_base.suppressed_count, 0) + v_d.sup)::text,
    'expired_count', (COALESCE(v_base.expired_count, 0) + v_d.exp)::text,
    'unknown_attempt_observations', (COALESCE(v_base.unknown_attempt_observations, 0) + v_d.unk)::text,
    'version', COALESCE(v_base.version, 0)::text
  );
END;
$$;

CREATE OR REPLACE FUNCTION rq.read_event_delivery_totals(
  p_tenant_id uuid,
  p_project_id uuid,
  p_event_id uuid
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  v_base rq.event_delivery_totals%ROWTYPE;
  v_d record;
BEGIN
  PERFORM rq._assert_session_role(ARRAY['rq_api', 'rq_reporter', 'rq_coordinator', 'rq_recovery']);

  SELECT * INTO v_base FROM rq.event_delivery_totals WHERE event_id = p_event_id AND project_id = p_project_id AND tenant_id = p_tenant_id;
  SELECT
    COALESCE(pg_catalog.sum(total_deliveries_delta), 0)::bigint AS tot,
    COALESCE(pg_catalog.sum(terminal_deliveries_delta), 0)::bigint AS term,
    COALESCE(pg_catalog.sum(acknowledged_deliveries_delta), 0)::bigint AS ack,
    pg_catalog.max(last_outcome_at) AS last_at
    INTO v_d
    FROM rq.event_delivery_total_deltas
   WHERE event_id = p_event_id AND project_id = p_project_id AND tenant_id = p_tenant_id;

  RETURN pg_catalog.jsonb_build_object(
    'event_id', p_event_id,
    'project_id', p_project_id,
    'tenant_id', p_tenant_id,
    'total_deliveries', (COALESCE(v_base.total_deliveries, 0) + v_d.tot)::text,
    'terminal_deliveries', (COALESCE(v_base.terminal_deliveries, 0) + v_d.term)::text,
    'acknowledged_deliveries', (COALESCE(v_base.acknowledged_deliveries, 0) + v_d.ack)::text,
    'last_outcome_at', GREATEST(v_base.last_outcome_at, v_d.last_at),
    'version', COALESCE(v_base.version, 0)::text
  );
END;
$$;

CREATE OR REPLACE FUNCTION rq.read_event_safe(
  p_tenant_id uuid,
  p_project_id uuid,
  p_event_id uuid
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  v_ev rq.events%ROWTYPE;
BEGIN
  PERFORM rq._assert_session_role(ARRAY['rq_api', 'rq_reporter', 'rq_coordinator']);
  SELECT * INTO v_ev FROM rq.events WHERE id = p_event_id AND project_id = p_project_id AND tenant_id = p_tenant_id;
  IF NOT FOUND THEN
    RETURN NULL;
  END IF;
  RETURN pg_catalog.jsonb_build_object(
    'event_id', v_ev.id,
    'tenant_id', v_ev.tenant_id,
    'project_id', v_ev.project_id,
    'producer_namespace', v_ev.producer_namespace,
    'event_type_id', v_ev.event_type_id,
    'event_schema_version', v_ev.event_schema_version,
    'content_sha256', pg_catalog.encode(v_ev.content_sha256, 'hex'),
    'content_byte_count', v_ev.content_byte_count,
    'topology_version', v_ev.topology_version::text,
    'project_event_sequence', v_ev.project_event_sequence::text,
    'state', v_ev.state,
    'admitted_at', v_ev.admitted_at,
    'delivery_deadline_at', v_ev.delivery_deadline_at
  );
END;
$$;

CREATE OR REPLACE FUNCTION rq.read_delivery_safe(
  p_tenant_id uuid,
  p_project_id uuid,
  p_delivery_id uuid
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  v_del rq.deliveries%ROWTYPE;
BEGIN
  PERFORM rq._assert_session_role(ARRAY['rq_api', 'rq_reporter', 'rq_coordinator']);
  SELECT * INTO v_del FROM rq.deliveries WHERE id = p_delivery_id AND project_id = p_project_id AND tenant_id = p_tenant_id;
  IF NOT FOUND THEN
    RETURN NULL;
  END IF;
  RETURN pg_catalog.jsonb_build_object(
    'delivery_id', v_del.id,
    'family_id', v_del.family_id,
    'event_id', v_del.event_id,
    'project_id', v_del.project_id,
    'endpoint_id', v_del.endpoint_id,
    'endpoint_version', v_del.endpoint_version::text,
    'delivery_generation', v_del.delivery_generation::text,
    'state', v_del.state,
    'blocking_reason', v_del.blocking_reason,
    'attempt_count', v_del.attempt_count,
    'maximum_attempts', v_del.maximum_attempts,
    'deadline_at', v_del.deadline_at,
    'next_eligible_at', v_del.next_eligible_at,
    'last_outcome_class', v_del.last_outcome_class,
    'acknowledged_at', v_del.acknowledged_at,
    'terminal_at', v_del.terminal_at
  );
END;
$$;

CREATE OR REPLACE FUNCTION rq.read_event_payload_bytes(
  p_tenant_id uuid,
  p_project_id uuid,
  p_event_id uuid
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  v_ev rq.events%ROWTYPE;
  v_pl rq.event_payloads%ROWTYPE;
BEGIN
  PERFORM rq._assert_session_role(ARRAY['rq_api', 'rq_fanout']);
  SELECT * INTO v_ev FROM rq.events WHERE id = p_event_id AND project_id = p_project_id AND tenant_id = p_tenant_id;
  IF NOT FOUND THEN
    RETURN NULL;
  END IF;
  SELECT * INTO v_pl FROM rq.event_payloads WHERE id = v_ev.content_payload_id;
  RETURN pg_catalog.jsonb_build_object(
    'event_id', v_ev.id,
    'payload_id', v_pl.id,
    'retention_state', v_pl.retention_state,
    'content_sha256', pg_catalog.encode(v_pl.content_sha256, 'hex'),
    'byte_count', v_pl.byte_count,
    'content_b64', CASE WHEN v_pl.content IS NOT NULL THEN pg_catalog.encode(v_pl.content, 'base64') ELSE NULL END
  );
END;
$$;

CREATE OR REPLACE FUNCTION rq.read_wire_envelope_bytes(
  p_tenant_id uuid,
  p_project_id uuid,
  p_wire_envelope_id uuid
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  v_wire rq.event_wire_envelopes%ROWTYPE;
BEGIN
  PERFORM rq._assert_session_role(ARRAY['rq_api', 'rq_fanout', 'rq_sender']);
  SELECT * INTO v_wire FROM rq.event_wire_envelopes
   WHERE id = p_wire_envelope_id AND project_id = p_project_id AND tenant_id = p_tenant_id;
  IF NOT FOUND THEN
    RETURN NULL;
  END IF;
  RETURN pg_catalog.jsonb_build_object(
    'wire_envelope_id', v_wire.id,
    'event_id', v_wire.event_id,
    'representation_version', v_wire.representation_version,
    'retention_state', v_wire.retention_state,
    'body_sha256', pg_catalog.encode(v_wire.body_sha256, 'hex'),
    'byte_count', v_wire.byte_count,
    'body_b64', CASE WHEN v_wire.body_bytes IS NOT NULL THEN pg_catalog.encode(v_wire.body_bytes, 'base64') ELSE NULL END
  );
END;
$$;

-- Safe reporter views (never expose raw payload bytes, verifiers, keys, or destination URLs)
CREATE OR REPLACE VIEW rq.v_safe_events AS
  SELECT
    id, tenant_id, project_id, producer_id, producer_namespace, event_type_id,
    event_schema_version, content_sha256, content_byte_count, topology_version,
    project_event_sequence, state, blocking_reason, producer_event_time, admitted_at,
    delivery_deadline_at, retired_at, version
  FROM rq.events;

CREATE OR REPLACE VIEW rq.v_safe_deliveries AS
  SELECT
    id, family_id, event_id, tenant_id, project_id, subscription_id,
    original_subscription_version, dispatch_subscription_version, endpoint_id,
    endpoint_version, wire_envelope_id, delivery_generation, replay_proposal_id,
    state, blocking_reason, attempt_count, maximum_attempts, deadline_at,
    next_eligible_at, acknowledged_at, terminal_at, last_outcome_class,
    created_at, updated_at, version
  FROM rq.deliveries;

-- 7. Ownership transfer, default privileges, and strict per-role grants
DO $$
DECLARE
  v_prev_role text := current_user;
  v_switched boolean := false;
  v_can_own boolean := false;
  v_rec record;
  v_ext_schema text;
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

    FOR v_rec IN
      SELECT p.proname, pg_catalog.pg_get_function_identity_arguments(p.oid) AS args
        FROM pg_catalog.pg_proc p
        JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
       WHERE n.nspname = 'rq'
         AND pg_catalog.pg_get_userbyid(p.proowner) <> 'rq_owner'
    LOOP
      EXECUTE pg_catalog.format('ALTER FUNCTION rq.%I(%s) OWNER TO rq_owner', v_rec.proname, v_rec.args);
    END LOOP;

    IF current_user <> 'rq_owner' AND pg_catalog.pg_has_role(current_user, 'rq_owner', 'MEMBER') THEN
      EXECUTE 'SET ROLE rq_owner';
      v_switched := true;
    END IF;

    EXECUTE 'ALTER DEFAULT PRIVILEGES FOR ROLE rq_owner IN SCHEMA rq REVOKE ALL ON TABLES FROM PUBLIC';
    EXECUTE 'ALTER DEFAULT PRIVILEGES FOR ROLE rq_owner IN SCHEMA rq REVOKE ALL ON SEQUENCES FROM PUBLIC';
    EXECUTE 'ALTER DEFAULT PRIVILEGES FOR ROLE rq_owner IN SCHEMA rq REVOKE ALL ON FUNCTIONS FROM PUBLIC';

    IF v_switched THEN
      EXECUTE pg_catalog.format('SET ROLE %I', v_prev_role);
    END IF;
  END IF;

  SELECT n.nspname
    INTO v_ext_schema
    FROM pg_catalog.pg_extension e
    JOIN pg_catalog.pg_namespace n ON n.oid = e.extnamespace
   WHERE e.extname = 'btree_gist';

  IF v_ext_schema IS NOT NULL THEN
    EXECUTE pg_catalog.format(
      'GRANT USAGE ON SCHEMA %I TO rq_api, rq_relay, rq_fanout, rq_sender, rq_coordinator, rq_reporter, rq_signing_issuer, rq_migrator, rq_recovery',
      v_ext_schema
    );
  END IF;
END
$$;

REVOKE ALL ON SCHEMA rq FROM PUBLIC;
REVOKE ALL ON SCHEMA rq_support FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA rq FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA rq FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA rq FROM PUBLIC;

REVOKE ALL ON ALL TABLES IN SCHEMA rq FROM rq_api, rq_relay, rq_fanout, rq_sender, rq_coordinator, rq_reporter, rq_signing_issuer;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA rq FROM rq_api, rq_relay, rq_fanout, rq_sender, rq_coordinator, rq_reporter, rq_signing_issuer;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA rq FROM rq_api, rq_relay, rq_fanout, rq_sender, rq_coordinator, rq_reporter, rq_signing_issuer, rq_migrator, rq_recovery;

GRANT USAGE ON SCHEMA rq TO rq_api, rq_relay, rq_fanout, rq_sender, rq_coordinator, rq_reporter, rq_signing_issuer, rq_migrator, rq_recovery;
GRANT USAGE ON SCHEMA rq_support TO rq_api, rq_relay, rq_fanout, rq_sender, rq_coordinator, rq_reporter, rq_signing_issuer, rq_migrator, rq_recovery;

-- Safe read-only SELECT grants (never direct INSERT/UPDATE/DELETE, and never raw payloads/verifiers/keys)
GRANT SELECT ON
  rq.schema_migrations,
  rq.installation_state,
  rq.tenants,
  rq.projects,
  rq.policy_versions,
  rq.retry_policy_versions,
  rq.dispatch_domains,
  rq.project_dispatch_memberships,
  rq.v_safe_events,
  rq.v_safe_deliveries,
  rq.project_delivery_totals,
  rq.event_delivery_totals,
  rq.event_delivery_total_deltas,
  rq.project_delivery_total_deltas
TO rq_api, rq_relay, rq_fanout, rq_sender, rq_coordinator, rq_reporter, rq_signing_issuer, rq_recovery;

GRANT SELECT ON
  rq.principals, rq.humans, rq.tenant_memberships, rq.project_memberships, rq.human_data_grants,
  rq.platform_role_assignments, rq.producers, rq.producer_scope_versions, rq.event_types, rq.event_schema_versions,
  rq.endpoints, rq.endpoint_versions, rq.endpoint_verification_intents, rq.endpoint_verification_attempts,
  rq.endpoint_verification_events, rq.endpoint_dispatch_grants, rq.signing_key_versions, rq.signing_policies,
  rq.subscriptions, rq.subscription_versions, rq.subscription_schema_versions, rq.subscription_control_events,
  rq.subscription_topology_ranges, rq.events, rq.business_event_anchors, rq.command_receipts, rq.outbox_events,
  rq.outbox_publications, rq.event_history, rq.broker_stream_generations, rq.broker_inbox, rq.event_fanout,
  rq.project_fanout_state, rq.fanout_outcomes, rq.publication_recovery_episodes, rq.delivery_families,
  rq.deliveries, rq.delivery_attempts, rq.delivery_retry_decisions, rq.late_delivery_observations,
  rq.endpoint_circuits, rq.ordering_domains, rq.ordering_keys, rq.ordering_members, rq.tenant_capacity,
  rq.project_capacity, rq.event_fanout_reservations, rq.sender_instances, rq.sender_capacity, rq.endpoint_capacity,
  rq.delivery_capacity_positions, rq.attempt_slots, rq.tenant_rate_buckets, rq.project_rate_buckets,
  rq.endpoint_rate_buckets, rq.producer_rate_buckets, rq.rate_buckets, rq.delivery_history,
  rq.replay_proposals, rq.replay_reviews, rq.order_skip_proposals, rq.order_skip_reviews, rq.order_dispositions,
  rq.suppression_proposals, rq.suppression_reviews, rq.circuit_probe_requests, rq.representation_profiles,
  rq.representation_profile_versions, rq.subscription_representation_bindings, rq.receiver_contracts,
  rq.receiver_contract_versions, rq.receiver_receipt_observations, rq.trace_references, rq.watch_leases,
  rq.actor_watch_capacity, rq.tenant_watch_capacity, rq.project_watch_capacity, rq.retention_holds,
  rq.retention_actions, rq.coordinator_tasks, rq.audit_events, rq.lifecycle_operations
TO rq_api, rq_coordinator, rq_recovery;

GRANT SELECT ON rq.outbox_events, rq.outbox_publications, rq.broker_stream_generations, rq.publication_observations
  TO rq_relay;

GRANT SELECT ON rq.events, rq.event_types, rq.event_schema_versions, rq.subscriptions, rq.subscription_versions,
  rq.subscription_schema_versions, rq.subscription_topology_ranges, rq.broker_stream_generations, rq.broker_inbox,
  rq.event_fanout, rq.project_fanout_state, rq.fanout_outcomes, rq.event_fanout_reservations,
  rq.representation_profiles, rq.representation_profile_versions, rq.subscription_representation_bindings
  TO rq_fanout;

GRANT SELECT ON rq.endpoints, rq.endpoint_versions, rq.endpoint_dispatch_grants, rq.signing_key_versions,
  rq.signing_policies, rq.subscriptions, rq.subscription_versions, rq.deliveries, rq.delivery_families,
  rq.delivery_attempts, rq.endpoint_circuits, rq.circuit_probe_requests, rq.ordering_keys, rq.ordering_members,
  rq.sender_instances, rq.sender_capacity, rq.endpoint_capacity, rq.tenant_capacity, rq.project_capacity,
  rq.tenant_rate_buckets, rq.project_rate_buckets, rq.endpoint_rate_buckets, rq.dispatch_state,
  rq.tenant_dispatch_state, rq.project_dispatch_state, rq.endpoint_dispatch_state, rq.dispatch_claim_requests,
  rq.dispatch_claim_assignments, rq.receiver_contracts, rq.receiver_contract_versions, rq.endpoint_verification_intents,
  rq.endpoint_verification_attempts
  TO rq_sender;

GRANT SELECT ON rq.signing_delivery_intents, rq.signing_key_versions, rq.producer_credential_intents, rq.producers
  TO rq_signing_issuer;

-- Exact per-role EXECUTE grants (every signature matches privilege-manifest.json)
GRANT EXECUTE ON FUNCTION rq.cmd_runtime_register(uuid, text, text, uuid, text, bigint, integer)
  TO rq_api, rq_relay, rq_fanout, rq_sender, rq_coordinator, rq_signing_issuer, rq_recovery;
GRANT EXECUTE ON FUNCTION rq.cmd_runtime_heartbeat(uuid, uuid, bigint)
  TO rq_api, rq_relay, rq_fanout, rq_sender, rq_coordinator, rq_signing_issuer, rq_recovery;

GRANT EXECUTE ON FUNCTION rq.cmd_event_admit(
  uuid, uuid, uuid, uuid, text, text, bytea, bytea, bytea, bytea, uuid, integer, bytea, bytea, bytea, bytea,
  bytea, bytea, timestamptz, timestamptz, jsonb, text, uuid, uuid, uuid, uuid, uuid, uuid
) TO rq_api;
GRANT EXECUTE ON FUNCTION rq.cmd_event_resolve(uuid, uuid, uuid, text, bytea, bytea, bytea) TO rq_api;
GRANT EXECUTE ON FUNCTION rq.cmd_circuit_probe_request(uuid, uuid, uuid, uuid, bigint, bigint, uuid, uuid, bytea, bytea) TO rq_api;
GRANT EXECUTE ON FUNCTION rq.cmd_replay_propose(uuid, uuid, uuid, bigint, bigint, bigint, uuid, text, text, uuid, bigint, uuid, bigint, bytea, bytea, timestamptz) TO rq_api;
GRANT EXECUTE ON FUNCTION rq.cmd_replay_review(uuid, uuid, bigint, bytea, uuid, bigint, text) TO rq_api;
GRANT EXECUTE ON FUNCTION rq.cmd_replay_admit(uuid, bigint, bytea, uuid, uuid, uuid, uuid, bytea) TO rq_api;
GRANT EXECUTE ON FUNCTION rq.cmd_order_skip_admit(uuid, uuid, uuid, uuid, uuid, bytea) TO rq_api;
GRANT EXECUTE ON FUNCTION rq.cmd_suppression_admit(uuid, uuid, uuid, uuid, bytea) TO rq_api;
GRANT EXECUTE ON FUNCTION rq.cmd_watch_lease_open(uuid, uuid, uuid, uuid, text, uuid, uuid, text, uuid, uuid, uuid, timestamptz, timestamptz) TO rq_api;
GRANT EXECUTE ON FUNCTION rq.cmd_watch_lease_renew(uuid, uuid, timestamptz) TO rq_api;
GRANT EXECUTE ON FUNCTION rq.cmd_watch_lease_close(uuid) TO rq_api, rq_coordinator;

GRANT EXECUTE ON FUNCTION rq.cmd_outbox_claim(uuid, uuid, uuid, bigint) TO rq_relay;
GRANT EXECUTE ON FUNCTION rq.cmd_outbox_observe(uuid, bigint, uuid, uuid, bigint, text, uuid, text, bigint, boolean, text, timestamptz, uuid) TO rq_relay;

GRANT EXECUTE ON FUNCTION rq.cmd_inbox_accept(uuid, bigint, uuid, uuid, bigint, bytea, uuid, bigint, uuid, uuid, uuid) TO rq_fanout;
GRANT EXECUTE ON FUNCTION rq.cmd_fanout_claim(uuid, uuid, uuid, bigint) TO rq_fanout;
GRANT EXECUTE ON FUNCTION rq.cmd_fanout_page(uuid, uuid, uuid, bigint, uuid, boolean, jsonb) TO rq_fanout;

GRANT EXECUTE ON FUNCTION rq.cmd_dispatch_prepare(uuid, uuid, uuid, uuid, bytea, uuid, uuid, bigint) TO rq_sender;
GRANT EXECUTE ON FUNCTION rq.cmd_send_start(uuid, uuid, uuid, bigint, bigint) TO rq_sender;
GRANT EXECUTE ON FUNCTION rq.cmd_attempt_finalize(uuid, uuid, uuid, bigint, text, text, integer, bytea, integer, text, text, text, text, bigint, bigint, text, bigint, timestamptz) TO rq_sender;
GRANT EXECUTE ON FUNCTION rq.cmd_late_delivery_observe(uuid, uuid, uuid, uuid, bytea, bytea, text, jsonb) TO rq_sender, rq_coordinator;
GRANT EXECUTE ON FUNCTION rq.cmd_egress_decision_record(uuid, uuid, uuid, uuid, bigint, uuid, uuid, uuid, uuid, text, bytea, bytea, bytea, bytea, bytea, integer, bytea, text, text, timestamptz) TO rq_sender;
GRANT EXECUTE ON FUNCTION rq.cmd_verification_attempt_claim(uuid, uuid, uuid, uuid, bigint) TO rq_sender;
GRANT EXECUTE ON FUNCTION rq.cmd_verification_attempt_finalize(uuid, uuid, uuid, text, integer, bytea, text, text, uuid) TO rq_sender;
GRANT EXECUTE ON FUNCTION rq.cmd_receiver_receipt_observe(uuid, uuid, uuid, text, bytea, bytea, bytea, text, uuid, bigint, jsonb, text, text, uuid, text) TO rq_sender;

GRANT EXECUTE ON FUNCTION rq.cmd_signing_delivery_finalize(uuid, uuid, text) TO rq_signing_issuer;
GRANT EXECUTE ON FUNCTION rq.cmd_producer_credential_intent_finalize(uuid, uuid, text, uuid, bytea, timestamptz) TO rq_signing_issuer;

GRANT EXECUTE ON FUNCTION rq.cmd_outbox_recovery_generation(uuid, uuid, uuid, uuid, bytea, bytea, text, text) TO rq_coordinator;
GRANT EXECUTE ON FUNCTION rq.cmd_coordinator_reap_expired(uuid, uuid, integer) TO rq_coordinator;
GRANT EXECUTE ON FUNCTION rq.cmd_retention_finalize(uuid, uuid, uuid, bigint) TO rq_coordinator;
GRANT EXECUTE ON FUNCTION rq.cmd_compact_delivery_total_deltas(uuid, uuid, uuid) TO rq_coordinator, rq_recovery;

-- Safe read functions
GRANT EXECUTE ON FUNCTION rq.read_installation_status()
  TO rq_api, rq_relay, rq_fanout, rq_sender, rq_coordinator, rq_reporter, rq_signing_issuer, rq_recovery;
GRANT EXECUTE ON FUNCTION rq.read_schema_migrations()
  TO rq_api, rq_relay, rq_fanout, rq_sender, rq_coordinator, rq_reporter, rq_signing_issuer, rq_migrator, rq_recovery;
GRANT EXECUTE ON FUNCTION rq.read_project_delivery_totals(uuid, uuid)
  TO rq_api, rq_reporter, rq_coordinator, rq_recovery;
GRANT EXECUTE ON FUNCTION rq.read_event_delivery_totals(uuid, uuid, uuid)
  TO rq_api, rq_reporter, rq_coordinator, rq_recovery;
GRANT EXECUTE ON FUNCTION rq.read_event_safe(uuid, uuid, uuid)
  TO rq_api, rq_reporter, rq_coordinator;
GRANT EXECUTE ON FUNCTION rq.read_delivery_safe(uuid, uuid, uuid)
  TO rq_api, rq_reporter, rq_coordinator;

-- Restricted private-byte read functions (explicitly denied to rq_reporter, rq_relay, rq_signing_issuer)
GRANT EXECUTE ON FUNCTION rq.read_event_payload_bytes(uuid, uuid, uuid)
  TO rq_api, rq_fanout;
GRANT EXECUTE ON FUNCTION rq.read_wire_envelope_bytes(uuid, uuid, uuid)
  TO rq_api, rq_fanout, rq_sender;
