-- Migration 0009: Protected recovery operations schema, typed repair records, review/execution separation, projection maintenance gate closure, and rq_recovery role boundaries.

-- 1. Incidents, operations, and action plan headers
CREATE TABLE IF NOT EXISTS rq_recovery.incidents (
  id uuid PRIMARY KEY,
  external_operation_id uuid NOT NULL UNIQUE,
  incident_reference text NOT NULL CHECK (pg_catalog.octet_length(incident_reference) BETWEEN 1 AND 256),
  scope_kind text NOT NULL CHECK (scope_kind IN ('installation', 'tenant', 'project')),
  tenant_id uuid NULL REFERENCES rq.tenants(id),
  project_id uuid NULL,
  state text NOT NULL CHECK (state IN ('open', 'contained', 'recovering', 'monitoring', 'closed')),
  remaining_risk_decision_code text NULL CHECK (
    remaining_risk_decision_code IS NULL OR pg_catalog.length(remaining_risk_decision_code) BETWEEN 1 AND 128
  ),
  opened_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  closed_at timestamptz NULL,
  version bigint NOT NULL DEFAULT 1 CHECK (version >= 1),
  FOREIGN KEY (project_id, tenant_id) REFERENCES rq.projects(id, tenant_id),
  CONSTRAINT chk_recovery_incidents_scope_ancestry CHECK (
    (scope_kind = 'installation' AND tenant_id IS NULL AND project_id IS NULL)
    OR (scope_kind = 'tenant' AND tenant_id IS NOT NULL AND project_id IS NULL)
    OR (scope_kind = 'project' AND tenant_id IS NOT NULL AND project_id IS NOT NULL)
  ),
  CONSTRAINT chk_recovery_incidents_closed_state CHECK (
    (state = 'closed' AND closed_at IS NOT NULL AND remaining_risk_decision_code IS NOT NULL)
    OR (state <> 'closed' AND closed_at IS NULL)
  )
);

CREATE TABLE IF NOT EXISTS rq_recovery.operations (
  id uuid PRIMARY KEY,
  incident_id uuid NOT NULL REFERENCES rq_recovery.incidents(id),
  external_operation_id uuid NOT NULL UNIQUE,
  source_epoch uuid NOT NULL,
  target_epoch uuid NOT NULL,
  target_database_identity_digest bytea NOT NULL CHECK (pg_catalog.octet_length(target_database_identity_digest) = 32),
  plan_sha256 bytea NOT NULL CHECK (pg_catalog.octet_length(plan_sha256) = 32),
  state text NOT NULL CHECK (state IN ('planned', 'reviewed', 'executing', 'partial', 'completed', 'failed', 'abandoned')),
  requester_reference text NOT NULL CHECK (pg_catalog.octet_length(requester_reference) BETWEEN 1 AND 256),
  created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  version bigint NOT NULL DEFAULT 1 CHECK (version >= 1),
  UNIQUE (id, plan_sha256),
  UNIQUE (id, target_epoch, plan_sha256)
);

CREATE TABLE IF NOT EXISTS rq_recovery.actions (
  id uuid PRIMARY KEY,
  operation_id uuid NOT NULL,
  ordinal integer NOT NULL CHECK (ordinal >= 1),
  kind text NOT NULL CHECK (
    kind IN (
      'retire_stale_claim',
      'reconcile_reservations',
      'continue_publication_episode',
      'record_receiver_comparison',
      'set_recovery_gate',
      'rebuild_projection',
      'establish_target_epoch'
    )
  ),
  scope_kind text NOT NULL CHECK (scope_kind IN ('installation', 'tenant', 'project')),
  tenant_id uuid NULL REFERENCES rq.tenants(id),
  project_id uuid NULL,
  target_id uuid NULL,
  expected_target_version bigint NULL CHECK (expected_target_version IS NULL OR expected_target_version >= 0),
  expected_control_epoch uuid NOT NULL,
  plan_sha256 bytea NOT NULL CHECK (pg_catalog.octet_length(plan_sha256) = 32),
  expected_facts_sha256 bytea NOT NULL CHECK (pg_catalog.octet_length(expected_facts_sha256) = 32),
  proposed_facts_sha256 bytea NOT NULL CHECK (pg_catalog.octet_length(proposed_facts_sha256) = 32),
  state text NOT NULL CHECK (state IN ('planned', 'reviewed', 'executing', 'applied', 'rejected', 'unknown')),
  requester_reference text NOT NULL CHECK (pg_catalog.octet_length(requester_reference) BETWEEN 1 AND 256),
  reason_code text NOT NULL CHECK (pg_catalog.length(reason_code) BETWEEN 1 AND 128),
  evidence_reference text NOT NULL CHECK (pg_catalog.octet_length(evidence_reference) BETWEEN 1 AND 256),
  created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  version bigint NOT NULL DEFAULT 1 CHECK (version >= 1),
  UNIQUE (operation_id, ordinal),
  UNIQUE (id, kind),
  UNIQUE (id, expected_facts_sha256, proposed_facts_sha256),
  FOREIGN KEY (operation_id, plan_sha256) REFERENCES rq_recovery.operations(id, plan_sha256),
  FOREIGN KEY (project_id, tenant_id) REFERENCES rq.projects(id, tenant_id),
  CONSTRAINT chk_recovery_actions_scope_ancestry CHECK (
    (scope_kind = 'installation' AND tenant_id IS NULL AND project_id IS NULL)
    OR (scope_kind = 'tenant' AND tenant_id IS NOT NULL AND project_id IS NULL)
    OR (scope_kind = 'project' AND tenant_id IS NOT NULL AND project_id IS NOT NULL)
  )
);

-- 2. Separately typed action plan child records (one-to-one with rq_recovery.actions)
CREATE TABLE IF NOT EXISTS rq_recovery.action_establish_target_epochs (
  action_id uuid PRIMARY KEY,
  action_kind text NOT NULL DEFAULT 'establish_target_epoch' CHECK (action_kind = 'establish_target_epoch'),
  source_epoch uuid NOT NULL,
  target_epoch uuid NOT NULL,
  expected_installation_version bigint NOT NULL CHECK (expected_installation_version >= 1),
  target_database_identity_digest bytea NOT NULL CHECK (pg_catalog.octet_length(target_database_identity_digest) = 32),
  containment_evidence_reference text NOT NULL CHECK (pg_catalog.octet_length(containment_evidence_reference) BETWEEN 1 AND 256),
  broker_generation_evidence_reference text NOT NULL CHECK (pg_catalog.octet_length(broker_generation_evidence_reference) BETWEEN 1 AND 256),
  proposed_mode text NOT NULL CHECK (proposed_mode IN ('admission_hold', 'recovery_quarantine')),
  FOREIGN KEY (action_id, action_kind) REFERENCES rq_recovery.actions(id, kind),
  CHECK (source_epoch <> target_epoch)
);

CREATE TABLE IF NOT EXISTS rq_recovery.action_retire_stale_claims (
  action_id uuid PRIMARY KEY,
  action_kind text NOT NULL DEFAULT 'retire_stale_claim' CHECK (action_kind = 'retire_stale_claim'),
  claim_kind text NOT NULL CHECK (claim_kind IN ('publication', 'fanout', 'prepared_attempt', 'coordinator_task')),
  scope_kind text NOT NULL CHECK (scope_kind IN ('installation', 'tenant', 'project')),
  tenant_id uuid NULL REFERENCES rq.tenants(id),
  project_id uuid NULL,
  outbox_id uuid NULL REFERENCES rq.outbox_events(id),
  event_id uuid NULL REFERENCES rq.event_fanout(event_id),
  attempt_id uuid NULL REFERENCES rq.delivery_attempts(id),
  coordinator_task_id uuid NULL REFERENCES rq.coordinator_tasks(id),
  expected_owner_instance_id uuid NOT NULL REFERENCES rq.runtime_instances(id),
  expected_claim_generation bigint NOT NULL CHECK (expected_claim_generation >= 1),
  expected_claim_control_epoch uuid NOT NULL,
  expected_claim_expires_at timestamptz NOT NULL,
  expected_resource_version bigint NOT NULL CHECK (expected_resource_version >= 1),
  old_writer_containment_reference text NOT NULL CHECK (pg_catalog.octet_length(old_writer_containment_reference) BETWEEN 1 AND 256),
  timeline_mode text NOT NULL CHECK (timeline_mode IN ('stale_timeline_contained', 'live_expired_reap')),
  FOREIGN KEY (action_id, action_kind) REFERENCES rq_recovery.actions(id, kind),
  FOREIGN KEY (project_id, tenant_id) REFERENCES rq.projects(id, tenant_id),
  CONSTRAINT chk_action_retire_claims_scope CHECK (
    (scope_kind = 'installation' AND tenant_id IS NULL AND project_id IS NULL)
    OR (scope_kind = 'tenant' AND tenant_id IS NOT NULL AND project_id IS NULL)
    OR (scope_kind = 'project' AND tenant_id IS NOT NULL AND project_id IS NOT NULL)
  ),
  CONSTRAINT chk_action_retire_claims_target_xor CHECK (
    (claim_kind = 'publication' AND outbox_id IS NOT NULL AND event_id IS NULL AND attempt_id IS NULL AND coordinator_task_id IS NULL)
    OR (claim_kind = 'fanout' AND event_id IS NOT NULL AND outbox_id IS NULL AND attempt_id IS NULL AND coordinator_task_id IS NULL)
    OR (claim_kind = 'prepared_attempt' AND attempt_id IS NOT NULL AND outbox_id IS NULL AND event_id IS NULL AND coordinator_task_id IS NULL)
    OR (claim_kind = 'coordinator_task' AND coordinator_task_id IS NOT NULL AND outbox_id IS NULL AND event_id IS NULL AND attempt_id IS NULL)
  )
);

CREATE TABLE IF NOT EXISTS rq_recovery.action_reconcile_reservations (
  action_id uuid PRIMARY KEY,
  action_kind text NOT NULL DEFAULT 'reconcile_reservations' CHECK (action_kind = 'reconcile_reservations'),
  reservation_kind text NOT NULL CHECK (
    reservation_kind IN (
      'tenant_fanout_slot',
      'project_fanout_slot',
      'sender_send_slot',
      'endpoint_send_slot',
      'tenant_send_slot',
      'project_send_slot',
      'tenant_rate_bucket',
      'project_rate_bucket',
      'endpoint_rate_bucket',
      'producer_rate_bucket'
    )
  ),
  scope_kind text NOT NULL CHECK (scope_kind IN ('tenant', 'project', 'endpoint', 'producer', 'sender')),
  tenant_id uuid NULL REFERENCES rq.tenants(id),
  project_id uuid NULL,
  endpoint_id uuid NULL,
  producer_id uuid NULL,
  sender_instance_id uuid NULL REFERENCES rq.sender_instances(id),
  bucket_operation text NULL CHECK (
    bucket_operation IS NULL OR bucket_operation IN ('event_admission', 'send_start', 'endpoint_verification', 'replay_admission')
  ),
  expected_resource_version bigint NOT NULL CHECK (expected_resource_version >= 1),
  expected_stored_value bigint NOT NULL CHECK (expected_stored_value >= 0),
  derived_obligation_value bigint NOT NULL CHECK (derived_obligation_value >= 0),
  proposed_value bigint NOT NULL CHECK (proposed_value >= 0),
  capacity_bound bigint NOT NULL CHECK (capacity_bound >= 0 AND proposed_value <= capacity_bound),
  conservative_policy text NOT NULL CHECK (conservative_policy IN ('canonical_exact', 'restored_timeline_conservative_hold')),
  affected_window_start timestamptz NULL,
  affected_window_end timestamptz NULL,
  obligation_inventory_digest bytea NOT NULL CHECK (pg_catalog.octet_length(obligation_inventory_digest) = 32),
  FOREIGN KEY (action_id, action_kind) REFERENCES rq_recovery.actions(id, kind),
  FOREIGN KEY (project_id, tenant_id) REFERENCES rq.projects(id, tenant_id),
  FOREIGN KEY (endpoint_id, project_id, tenant_id) REFERENCES rq.endpoints(id, project_id, tenant_id),
  FOREIGN KEY (producer_id, project_id, tenant_id) REFERENCES rq.producers(id, project_id, tenant_id),
  CONSTRAINT chk_action_reconcile_res_target CHECK (
    (reservation_kind IN ('tenant_fanout_slot', 'tenant_send_slot') AND scope_kind = 'tenant' AND tenant_id IS NOT NULL AND bucket_operation IS NULL)
    OR (reservation_kind IN ('project_fanout_slot', 'project_send_slot') AND scope_kind = 'project' AND tenant_id IS NOT NULL AND project_id IS NOT NULL AND bucket_operation IS NULL)
    OR (reservation_kind = 'endpoint_send_slot' AND scope_kind = 'endpoint' AND tenant_id IS NOT NULL AND project_id IS NOT NULL AND endpoint_id IS NOT NULL AND bucket_operation IS NULL)
    OR (reservation_kind = 'sender_send_slot' AND scope_kind = 'sender' AND sender_instance_id IS NOT NULL AND bucket_operation IS NULL)
    OR (reservation_kind = 'tenant_rate_bucket' AND scope_kind = 'tenant' AND tenant_id IS NOT NULL AND bucket_operation IS NOT NULL)
    OR (reservation_kind = 'project_rate_bucket' AND scope_kind = 'project' AND tenant_id IS NOT NULL AND project_id IS NOT NULL AND bucket_operation IS NOT NULL)
    OR (reservation_kind = 'endpoint_rate_bucket' AND scope_kind = 'endpoint' AND tenant_id IS NOT NULL AND project_id IS NOT NULL AND endpoint_id IS NOT NULL AND bucket_operation IS NOT NULL)
    OR (reservation_kind = 'producer_rate_bucket' AND scope_kind = 'producer' AND tenant_id IS NOT NULL AND project_id IS NOT NULL AND producer_id IS NOT NULL AND bucket_operation IS NOT NULL)
  )
);

CREATE TABLE IF NOT EXISTS rq_recovery.action_continue_publication_episodes (
  action_id uuid PRIMARY KEY,
  action_kind text NOT NULL DEFAULT 'continue_publication_episode' CHECK (action_kind = 'continue_publication_episode'),
  tenant_id uuid NOT NULL,
  project_id uuid NOT NULL,
  outbox_id uuid NOT NULL,
  event_id uuid NOT NULL,
  episode_id uuid NOT NULL REFERENCES rq.publication_recovery_episodes(id),
  expected_episode_version bigint NOT NULL CHECK (expected_episode_version >= 1),
  expected_outbox_version bigint NOT NULL CHECK (expected_outbox_version >= 1),
  expected_publication_generation bigint NOT NULL CHECK (expected_publication_generation >= 1),
  no_progress_boundary_sha256 bytea NOT NULL CHECK (pg_catalog.octet_length(no_progress_boundary_sha256) = 32),
  cause_resolution_evidence_reference text NOT NULL CHECK (pg_catalog.octet_length(cause_resolution_evidence_reference) BETWEEN 1 AND 256),
  schedule_next_notification boolean NOT NULL,
  FOREIGN KEY (action_id, action_kind) REFERENCES rq_recovery.actions(id, kind),
  FOREIGN KEY (outbox_id, event_id, project_id, tenant_id) REFERENCES rq.outbox_events(id, event_id, project_id, tenant_id)
);

CREATE TABLE IF NOT EXISTS rq_recovery.action_record_receiver_comparisons (
  action_id uuid PRIMARY KEY,
  action_kind text NOT NULL DEFAULT 'record_receiver_comparison' CHECK (action_kind = 'record_receiver_comparison'),
  tenant_id uuid NOT NULL,
  project_id uuid NOT NULL,
  delivery_id uuid NOT NULL,
  event_id uuid NOT NULL,
  consumer_contract_scope text NOT NULL CHECK (pg_catalog.octet_length(consumer_contract_scope) BETWEEN 1 AND 128),
  consumer_event_key_sha256 bytea NOT NULL CHECK (pg_catalog.octet_length(consumer_event_key_sha256) = 32),
  original_facts_sha256 bytea NOT NULL CHECK (pg_catalog.octet_length(original_facts_sha256) = 32),
  comparison_outcome text NOT NULL CHECK (
    comparison_outcome IN ('matching_committed_anchor', 'missing_anchor', 'conflicting_facts', 'retention_unknown', 'source_unavailable')
  ),
  source_kind text NOT NULL CHECK (
    source_kind IN ('protected_receiver_inventory', 'independent_audit_export', 'operator_source_snapshot')
  ),
  source_reference text NOT NULL CHECK (pg_catalog.octet_length(source_reference) BETWEEN 1 AND 256),
  observed_at timestamptz NOT NULL,
  diagnostic_evidence_digest bytea NOT NULL CHECK (pg_catalog.octet_length(diagnostic_evidence_digest) = 32),
  receiver_facts_sha256 bytea NULL CHECK (receiver_facts_sha256 IS NULL OR pg_catalog.octet_length(receiver_facts_sha256) = 32),
  requires_hold_investigation boolean NOT NULL,
  FOREIGN KEY (action_id, action_kind) REFERENCES rq_recovery.actions(id, kind),
  FOREIGN KEY (delivery_id, event_id, project_id, tenant_id) REFERENCES rq.deliveries(id, event_id, project_id, tenant_id),
  CHECK (comparison_outcome <> 'conflicting_facts' OR requires_hold_investigation)
);

CREATE TABLE IF NOT EXISTS rq_recovery.action_set_recovery_gates (
  action_id uuid PRIMARY KEY,
  action_kind text NOT NULL DEFAULT 'set_recovery_gate' CHECK (action_kind = 'set_recovery_gate'),
  target_scope_kind text NOT NULL CHECK (target_scope_kind IN ('installation', 'tenant', 'project')),
  tenant_id uuid NULL REFERENCES rq.tenants(id),
  project_id uuid NULL,
  expected_target_version bigint NOT NULL CHECK (expected_target_version >= 1),
  proposed_installation_mode text NULL CHECK (
    proposed_installation_mode IS NULL OR proposed_installation_mode IN ('open', 'admission_hold', 'recovery_quarantine')
  ),
  proposed_allow_event_admission boolean NULL,
  proposed_allow_publication boolean NULL,
  proposed_allow_fanout boolean NULL,
  proposed_allow_send boolean NULL,
  proposed_allow_endpoint_verification boolean NULL,
  proposed_tenant_state text NULL CHECK (proposed_tenant_state IS NULL OR proposed_tenant_state IN ('active', 'suspended')),
  proposed_project_state text NULL CHECK (proposed_project_state IS NULL OR proposed_project_state IN ('active', 'admission_paused', 'quarantined')),
  containment_evidence_reference text NOT NULL CHECK (pg_catalog.octet_length(containment_evidence_reference) BETWEEN 1 AND 256),
  integrity_evidence_reference text NOT NULL CHECK (pg_catalog.octet_length(integrity_evidence_reference) BETWEEN 1 AND 256),
  broker_evidence_reference text NOT NULL CHECK (pg_catalog.octet_length(broker_evidence_reference) BETWEEN 1 AND 256),
  receiver_evidence_reference text NOT NULL CHECK (pg_catalog.octet_length(receiver_evidence_reference) BETWEEN 1 AND 256),
  capacity_evidence_reference text NOT NULL CHECK (pg_catalog.octet_length(capacity_evidence_reference) BETWEEN 1 AND 256),
  retained_hold_refs jsonb NOT NULL DEFAULT '[]'::jsonb,
  FOREIGN KEY (action_id, action_kind) REFERENCES rq_recovery.actions(id, kind),
  FOREIGN KEY (project_id, tenant_id) REFERENCES rq.projects(id, tenant_id),
  CHECK (pg_catalog.jsonb_typeof(retained_hold_refs) = 'array'),
  CONSTRAINT chk_action_set_gate_scope CHECK (
    (
      target_scope_kind = 'installation'
      AND tenant_id IS NULL
      AND project_id IS NULL
      AND proposed_tenant_state IS NULL
      AND proposed_project_state IS NULL
      AND (
        proposed_installation_mode IS NOT NULL
        OR proposed_allow_event_admission IS NOT NULL
        OR proposed_allow_publication IS NOT NULL
        OR proposed_allow_fanout IS NOT NULL
        OR proposed_allow_send IS NOT NULL
        OR proposed_allow_endpoint_verification IS NOT NULL
      )
    )
    OR (
      target_scope_kind = 'tenant'
      AND tenant_id IS NOT NULL
      AND project_id IS NULL
      AND proposed_tenant_state IS NOT NULL
      AND proposed_installation_mode IS NULL
      AND proposed_project_state IS NULL
      AND proposed_allow_event_admission IS NULL
      AND proposed_allow_publication IS NULL
      AND proposed_allow_fanout IS NULL
      AND proposed_allow_send IS NULL
      AND proposed_allow_endpoint_verification IS NULL
    )
    OR (
      target_scope_kind = 'project'
      AND tenant_id IS NOT NULL
      AND project_id IS NOT NULL
      AND proposed_project_state IS NOT NULL
      AND proposed_installation_mode IS NULL
      AND proposed_tenant_state IS NULL
      AND proposed_allow_event_admission IS NULL
      AND proposed_allow_publication IS NULL
      AND proposed_allow_fanout IS NULL
      AND proposed_allow_send IS NULL
      AND proposed_allow_endpoint_verification IS NULL
    )
  )
);

CREATE TABLE IF NOT EXISTS rq_recovery.action_rebuild_projections (
  action_id uuid PRIMARY KEY,
  action_kind text NOT NULL DEFAULT 'rebuild_projection' CHECK (action_kind = 'rebuild_projection'),
  projection_kind text NOT NULL CHECK (projection_kind IN ('project_delivery_totals', 'event_delivery_totals')),
  tenant_id uuid NOT NULL,
  project_id uuid NOT NULL,
  event_id uuid NULL,
  population_definition_version text NOT NULL CHECK (population_definition_version = 'delivery_population.v1'),
  expected_projection_version bigint NOT NULL CHECK (expected_projection_version >= 1),
  expected_source_boundary_sha256 bytea NOT NULL CHECK (pg_catalog.octet_length(expected_source_boundary_sha256) = 32),
  max_source_rows bigint NOT NULL DEFAULT 10000 CHECK (max_source_rows BETWEEN 1 AND 100000),
  proposed_total_deliveries bigint NOT NULL CHECK (proposed_total_deliveries >= 0),
  proposed_pending_count bigint NULL CHECK (proposed_pending_count IS NULL OR proposed_pending_count >= 0),
  proposed_active_count bigint NULL CHECK (proposed_active_count IS NULL OR proposed_active_count >= 0),
  proposed_acknowledged_count bigint NOT NULL CHECK (proposed_acknowledged_count >= 0),
  proposed_dead_letter_count bigint NULL CHECK (proposed_dead_letter_count IS NULL OR proposed_dead_letter_count >= 0),
  proposed_suppressed_count bigint NULL CHECK (proposed_suppressed_count IS NULL OR proposed_suppressed_count >= 0),
  proposed_expired_count bigint NULL CHECK (proposed_expired_count IS NULL OR proposed_expired_count >= 0),
  proposed_terminal_deliveries bigint NULL CHECK (proposed_terminal_deliveries IS NULL OR proposed_terminal_deliveries >= 0),
  proposed_unknown_attempt_observations bigint NULL CHECK (proposed_unknown_attempt_observations IS NULL OR proposed_unknown_attempt_observations >= 0),
  diagnostic_mismatch_sha256 bytea NOT NULL CHECK (pg_catalog.octet_length(diagnostic_mismatch_sha256) = 32),
  FOREIGN KEY (action_id, action_kind) REFERENCES rq_recovery.actions(id, kind),
  FOREIGN KEY (project_id, tenant_id) REFERENCES rq.projects(id, tenant_id),
  FOREIGN KEY (event_id, project_id, tenant_id) REFERENCES rq.events(id, project_id, tenant_id),
  CONSTRAINT chk_action_rebuild_proj_kind_fields CHECK (
    (
      projection_kind = 'event_delivery_totals'
      AND event_id IS NOT NULL
      AND proposed_terminal_deliveries IS NOT NULL
      AND proposed_terminal_deliveries <= proposed_total_deliveries
      AND proposed_acknowledged_count <= proposed_terminal_deliveries
      AND proposed_pending_count IS NULL
      AND proposed_active_count IS NULL
      AND proposed_dead_letter_count IS NULL
      AND proposed_suppressed_count IS NULL
      AND proposed_expired_count IS NULL
      AND proposed_unknown_attempt_observations IS NULL
    )
    OR (
      projection_kind = 'project_delivery_totals'
      AND event_id IS NULL
      AND proposed_terminal_deliveries IS NULL
      AND proposed_pending_count IS NOT NULL
      AND proposed_active_count IS NOT NULL
      AND proposed_dead_letter_count IS NOT NULL
      AND proposed_suppressed_count IS NOT NULL
      AND proposed_expired_count IS NOT NULL
      AND proposed_unknown_attempt_observations IS NOT NULL
      AND proposed_total_deliveries = (
        proposed_pending_count
        + proposed_active_count
        + proposed_acknowledged_count
        + proposed_dead_letter_count
        + proposed_suppressed_count
        + proposed_expired_count
      )
    )
  )
);

-- 3. Reviews, execution attempts, immutable action results, and receiver comparison provenance
CREATE TABLE IF NOT EXISTS rq_recovery.reviews (
  id uuid PRIMARY KEY,
  action_id uuid NOT NULL REFERENCES rq_recovery.actions(id),
  operation_id uuid NOT NULL,
  plan_sha256 bytea NOT NULL CHECK (pg_catalog.octet_length(plan_sha256) = 32),
  target_epoch uuid NOT NULL,
  expected_facts_sha256 bytea NOT NULL CHECK (pg_catalog.octet_length(expected_facts_sha256) = 32),
  proposed_facts_sha256 bytea NOT NULL CHECK (pg_catalog.octet_length(proposed_facts_sha256) = 32),
  reviewer_reference text NOT NULL CHECK (pg_catalog.octet_length(reviewer_reference) BETWEEN 1 AND 256),
  reviewed_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  expires_at timestamptz NOT NULL,
  decision text NOT NULL CHECK (decision IN ('approve', 'reject')),
  reject_reason_code text NULL CHECK (
    reject_reason_code IS NULL OR pg_catalog.length(reject_reason_code) BETWEEN 1 AND 128
  ),
  authority_evidence_digest bytea NOT NULL CHECK (pg_catalog.octet_length(authority_evidence_digest) = 32),
  state text NOT NULL DEFAULT 'active' CHECK (state IN ('active', 'consumed', 'revoked', 'expired')),
  FOREIGN KEY (operation_id, plan_sha256) REFERENCES rq_recovery.operations(id, plan_sha256),
  FOREIGN KEY (action_id, expected_facts_sha256, proposed_facts_sha256)
    REFERENCES rq_recovery.actions(id, expected_facts_sha256, proposed_facts_sha256),
  CHECK (expires_at > reviewed_at),
  CHECK ((decision = 'reject' AND reject_reason_code IS NOT NULL) OR (decision = 'approve' AND reject_reason_code IS NULL))
);

CREATE TABLE IF NOT EXISTS rq_recovery.execution_attempts (
  id uuid PRIMARY KEY,
  action_id uuid NOT NULL REFERENCES rq_recovery.actions(id),
  operator_reference text NOT NULL CHECK (pg_catalog.octet_length(operator_reference) BETWEEN 1 AND 256),
  execution_nonce_digest bytea NOT NULL CHECK (pg_catalog.octet_length(execution_nonce_digest) = 32),
  started_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  finished_at timestamptz NULL,
  outcome text NOT NULL CHECK (outcome IN ('started', 'applied', 'already_complete', 'rejected', 'conflict', 'failed_retryable', 'unknown')),
  safe_error_code text NULL,
  version bigint NOT NULL DEFAULT 1 CHECK (version >= 1)
);

CREATE TABLE IF NOT EXISTS rq_recovery.action_results (
  action_id uuid PRIMARY KEY REFERENCES rq_recovery.actions(id),
  operation_id uuid NOT NULL REFERENCES rq_recovery.operations(id),
  execution_attempt_id uuid NOT NULL REFERENCES rq_recovery.execution_attempts(id),
  outcome text NOT NULL CHECK (outcome IN ('applied', 'already_complete')),
  proposed_facts_sha256 bytea NOT NULL CHECK (pg_catalog.octet_length(proposed_facts_sha256) = 32),
  resulting_facts_sha256 bytea NOT NULL CHECK (pg_catalog.octet_length(resulting_facts_sha256) = 32),
  new_target_version bigint NOT NULL CHECK (new_target_version >= 0),
  safe_result_facts jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (pg_catalog.jsonb_typeof(safe_result_facts) = 'object'),
  recorded_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp()
);

CREATE TABLE IF NOT EXISTS rq_recovery.receiver_comparison_records (
  id uuid PRIMARY KEY,
  action_id uuid NOT NULL UNIQUE REFERENCES rq_recovery.actions(id),
  tenant_id uuid NOT NULL,
  project_id uuid NOT NULL,
  delivery_id uuid NOT NULL,
  event_id uuid NOT NULL,
  consumer_contract_scope text NOT NULL CHECK (pg_catalog.octet_length(consumer_contract_scope) BETWEEN 1 AND 128),
  consumer_event_key_sha256 bytea NOT NULL CHECK (pg_catalog.octet_length(consumer_event_key_sha256) = 32),
  original_facts_sha256 bytea NOT NULL CHECK (pg_catalog.octet_length(original_facts_sha256) = 32),
  comparison_outcome text NOT NULL CHECK (
    comparison_outcome IN ('matching_committed_anchor', 'missing_anchor', 'conflicting_facts', 'retention_unknown', 'source_unavailable')
  ),
  source_kind text NOT NULL CHECK (
    source_kind IN ('protected_receiver_inventory', 'independent_audit_export', 'operator_source_snapshot')
  ),
  source_reference text NOT NULL CHECK (pg_catalog.octet_length(source_reference) BETWEEN 1 AND 256),
  observed_at timestamptz NOT NULL,
  diagnostic_evidence_digest bytea NOT NULL CHECK (pg_catalog.octet_length(diagnostic_evidence_digest) = 32),
  receiver_facts_sha256 bytea NULL CHECK (receiver_facts_sha256 IS NULL OR pg_catalog.octet_length(receiver_facts_sha256) = 32),
  requires_hold_investigation boolean NOT NULL,
  recorded_by_operator_reference text NOT NULL CHECK (pg_catalog.octet_length(recorded_by_operator_reference) BETWEEN 1 AND 256),
  recorded_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  FOREIGN KEY (delivery_id, event_id, project_id, tenant_id) REFERENCES rq.deliveries(id, event_id, project_id, tenant_id)
);

-- 4. Late FK closure for rq.projects.projection_maintenance_operation_id
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_constraint WHERE conname = 'fk_projects_projection_maintenance_operation') THEN
    ALTER TABLE rq.projects
      ADD CONSTRAINT fk_projects_projection_maintenance_operation
      FOREIGN KEY (projection_maintenance_operation_id) REFERENCES rq_recovery.operations(id);
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_constraint WHERE conname = 'chk_projects_projection_maintenance_version') THEN
    ALTER TABLE rq.projects
      ADD CONSTRAINT chk_projects_projection_maintenance_version
      CHECK (
        projection_maintenance_operation_id IS NULL
        OR (projection_maintenance_operation_id IS NOT NULL AND projection_maintenance_version >= 1)
      );
  END IF;
END
$$;

-- 5. Indexes and immutability guards
CREATE INDEX IF NOT EXISTS idx_recovery_operations_incident_created
  ON rq_recovery.operations (incident_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_recovery_actions_op_ordinal
  ON rq_recovery.actions (operation_id, ordinal);
CREATE INDEX IF NOT EXISTS idx_recovery_reviews_action_state
  ON rq_recovery.reviews (action_id, state, expires_at DESC);
CREATE INDEX IF NOT EXISTS idx_recovery_exec_attempts_action_started
  ON rq_recovery.execution_attempts (action_id, started_at DESC);
CREATE INDEX IF NOT EXISTS idx_recovery_cmp_records_delivery_obs
  ON rq_recovery.receiver_comparison_records (delivery_id, observed_at DESC);

CREATE OR REPLACE FUNCTION rq_recovery._trg_completed_operation_immutable()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'Recovery operation records cannot be deleted' USING ERRCODE = '55000';
  END IF;
  IF OLD.state = 'completed' AND (
    NEW.plan_sha256 IS DISTINCT FROM OLD.plan_sha256
    OR NEW.source_epoch IS DISTINCT FROM OLD.source_epoch
    OR NEW.target_epoch IS DISTINCT FROM OLD.target_epoch
    OR NEW.target_database_identity_digest IS DISTINCT FROM OLD.target_database_identity_digest
    OR NEW.external_operation_id IS DISTINCT FROM OLD.external_operation_id
  ) THEN
    RAISE EXCEPTION 'Completed recovery operation identity and digest are immutable' USING ERRCODE = '55000';
  END IF;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_recovery_operations_immutable ON rq_recovery.operations;
CREATE TRIGGER trg_recovery_operations_immutable
  BEFORE UPDATE OR DELETE ON rq_recovery.operations
  FOR EACH ROW EXECUTE FUNCTION rq_recovery._trg_completed_operation_immutable();

DROP TRIGGER IF EXISTS trg_recovery_action_results_append_only ON rq_recovery.action_results;
CREATE TRIGGER trg_recovery_action_results_append_only
  BEFORE UPDATE OR DELETE ON rq_recovery.action_results
  FOR EACH ROW EXECUTE FUNCTION rq._trg_immutable_row();

DROP TRIGGER IF EXISTS trg_recovery_comparison_records_append_only ON rq_recovery.receiver_comparison_records;
CREATE TRIGGER trg_recovery_comparison_records_append_only
  BEFORE UPDATE OR DELETE ON rq_recovery.receiver_comparison_records
  FOR EACH ROW EXECUTE FUNCTION rq._trg_immutable_row();

CREATE OR REPLACE FUNCTION rq_recovery._trg_review_immutable()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'Recovery reviews cannot be deleted' USING ERRCODE = '55000';
  END IF;
  IF NEW.id <> OLD.id OR NEW.action_id <> OLD.action_id OR NEW.operation_id <> OLD.operation_id
     OR NEW.plan_sha256 <> OLD.plan_sha256 OR NEW.target_epoch <> OLD.target_epoch
     OR NEW.expected_facts_sha256 <> OLD.expected_facts_sha256
     OR NEW.proposed_facts_sha256 <> OLD.proposed_facts_sha256
     OR NEW.reviewer_reference <> OLD.reviewer_reference
     OR NEW.decision <> OLD.decision
     OR OLD.state <> 'active' THEN
    RAISE EXCEPTION 'Recovery review fields are immutable after recording' USING ERRCODE = '55000';
  END IF;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_recovery_reviews_immutable ON rq_recovery.reviews;
CREATE TRIGGER trg_recovery_reviews_immutable
  BEFORE UPDATE OR DELETE ON rq_recovery.reviews
  FOR EACH ROW EXECUTE FUNCTION rq_recovery._trg_review_immutable();

-- 6. SECURITY DEFINER entry points for rq_recovery (never general SQL execution)
CREATE OR REPLACE FUNCTION rq_recovery._verify_review_and_record_attempt(
  p_action_id uuid,
  p_expected_kind text,
  p_operator_reference text,
  p_execution_nonce_digest bytea,
  p_target_database_identity_digest bytea,
  OUT out_already_done boolean,
  OUT out_existing_result jsonb,
  OUT out_action rq_recovery.actions,
  OUT out_op rq_recovery.operations,
  OUT out_review rq_recovery.reviews,
  OUT out_exec_attempt_id uuid
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  v_now timestamptz := pg_catalog.clock_timestamp();
  v_existing rq_recovery.action_results%ROWTYPE;
BEGIN
  out_already_done := false;
  out_existing_result := NULL;

  SELECT * INTO out_action FROM rq_recovery.actions WHERE id = p_action_id FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'Recovery action not found' USING ERRCODE = 'P0002';
  END IF;

  IF out_action.kind <> p_expected_kind THEN
    RAISE EXCEPTION 'Recovery entry point does not own action kind %', out_action.kind USING ERRCODE = '22023';
  END IF;

  SELECT * INTO out_op FROM rq_recovery.operations WHERE id = out_action.operation_id FOR UPDATE;
  IF out_op.target_database_identity_digest IS DISTINCT FROM p_target_database_identity_digest THEN
    RAISE EXCEPTION 'Target database identity digest mismatch' USING ERRCODE = '55000';
  END IF;
  IF out_op.state = 'abandoned' THEN
    RAISE EXCEPTION 'Recovery operation has been abandoned' USING ERRCODE = '55000';
  END IF;

  -- Idempotent result recovery if action already completed cleanly
  SELECT * INTO v_existing FROM rq_recovery.action_results WHERE action_id = p_action_id;
  IF FOUND THEN
    IF v_existing.proposed_facts_sha256 <> out_action.proposed_facts_sha256 THEN
      RAISE EXCEPTION 'Idempotency conflict on previously executed recovery action' USING ERRCODE = '23505';
    END IF;
    out_already_done := true;
    out_existing_result := pg_catalog.jsonb_build_object(
      'outcome', v_existing.outcome,
      'operation_id', v_existing.operation_id,
      'action_id', v_existing.action_id,
      'new_target_version', v_existing.new_target_version,
      'resulting_facts_sha256', pg_catalog.encode(v_existing.resulting_facts_sha256, 'hex'),
      'safe_result_facts', v_existing.safe_result_facts,
      'recorded_at', v_existing.recorded_at
    );
    RETURN;
  END IF;

  IF out_action.state = 'rejected' THEN
    RAISE EXCEPTION 'Recovery action has been rejected' USING ERRCODE = '55000';
  END IF;

  SELECT r.*
    INTO out_review
    FROM rq_recovery.reviews r
   WHERE r.action_id = out_action.id
     AND r.operation_id = out_op.id
     AND r.plan_sha256 = out_op.plan_sha256
     AND r.expected_facts_sha256 = out_action.expected_facts_sha256
     AND r.proposed_facts_sha256 = out_action.proposed_facts_sha256
     AND r.decision = 'approve'
     AND r.state = 'active'
     AND r.expires_at > v_now
     AND (
       (out_action.kind = 'establish_target_epoch' AND r.target_epoch = out_op.target_epoch)
       OR (out_action.kind <> 'establish_target_epoch' AND r.target_epoch = out_action.expected_control_epoch AND r.target_epoch = out_op.target_epoch)
     )
   ORDER BY r.reviewed_at DESC
   LIMIT 1
   FOR UPDATE;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'Missing, expired, rejected, or stale recovery review' USING ERRCODE = '42501';
  END IF;

  IF out_review.reviewer_reference = out_action.requester_reference
     OR out_review.reviewer_reference = p_operator_reference THEN
    RAISE EXCEPTION 'Recovery separation requires distinct reviewer and requester/operator identities' USING ERRCODE = '42501';
  END IF;

  out_exec_attempt_id := pg_catalog.gen_random_uuid();
  INSERT INTO rq_recovery.execution_attempts (
    id, action_id, operator_reference, execution_nonce_digest, started_at, outcome, version
  ) VALUES (
    out_exec_attempt_id, p_action_id, p_operator_reference, p_execution_nonce_digest, v_now, 'started', 1
  );
END;
$$;

CREATE OR REPLACE FUNCTION rq_recovery.cmd_incident_open(
  p_incident_id uuid,
  p_external_operation_id uuid,
  p_incident_reference text,
  p_scope_kind text,
  p_tenant_id uuid DEFAULT NULL,
  p_project_id uuid DEFAULT NULL
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  v_existing rq_recovery.incidents%ROWTYPE;
  v_now timestamptz := pg_catalog.clock_timestamp();
BEGIN
  PERFORM rq._assert_session_role(ARRAY['rq_recovery']);

  SELECT * INTO v_existing FROM rq_recovery.incidents WHERE external_operation_id = p_external_operation_id FOR UPDATE;
  IF FOUND THEN
    IF v_existing.id <> p_incident_id OR v_existing.incident_reference <> p_incident_reference THEN
      RAISE EXCEPTION 'Incident external operation conflict' USING ERRCODE = '23505';
    END IF;
    RETURN pg_catalog.jsonb_build_object('outcome', 'idempotent', 'incident_id', v_existing.id, 'state', v_existing.state, 'version', v_existing.version);
  END IF;

  INSERT INTO rq_recovery.incidents (
    id, external_operation_id, incident_reference, scope_kind, tenant_id, project_id, state, opened_at, version
  ) VALUES (
    p_incident_id, p_external_operation_id, p_incident_reference, p_scope_kind, p_tenant_id, p_project_id, 'open', v_now, 1
  );

  RETURN pg_catalog.jsonb_build_object('outcome', 'opened', 'incident_id', p_incident_id, 'state', 'open', 'version', 1);
END;
$$;

CREATE OR REPLACE FUNCTION rq_recovery.cmd_incident_close(
  p_incident_id uuid,
  p_expected_version bigint,
  p_remaining_risk_decision_code text,
  p_operator_reference text
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  v_inc rq_recovery.incidents%ROWTYPE;
  v_now timestamptz := pg_catalog.clock_timestamp();
BEGIN
  PERFORM rq._assert_session_role(ARRAY['rq_recovery']);

  SELECT * INTO v_inc FROM rq_recovery.incidents WHERE id = p_incident_id FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'Recovery incident not found' USING ERRCODE = 'P0002';
  END IF;

  IF v_inc.state = 'closed' THEN
    IF v_inc.remaining_risk_decision_code = p_remaining_risk_decision_code THEN
      RETURN pg_catalog.jsonb_build_object('outcome', 'idempotent', 'incident_id', v_inc.id, 'state', v_inc.state, 'version', v_inc.version);
    END IF;
    RAISE EXCEPTION 'Closed incident cannot change remaining-risk decision' USING ERRCODE = '55000';
  END IF;

  IF v_inc.version <> p_expected_version THEN
    RAISE EXCEPTION 'Incident version precondition conflict' USING ERRCODE = '40001';
  END IF;

  UPDATE rq_recovery.incidents
     SET state = 'closed',
         remaining_risk_decision_code = p_remaining_risk_decision_code,
         closed_at = v_now,
         version = version + 1
   WHERE id = p_incident_id
   RETURNING * INTO v_inc;

  INSERT INTO rq.audit_events (
    id, tenant_id, project_id, actor_kind, operator_reference, action, target_kind, target_id,
    prior_version, resulting_version, recorded_at, safe_facts
  ) VALUES (
    pg_catalog.gen_random_uuid(), v_inc.tenant_id, v_inc.project_id, 'operator', p_operator_reference,
    'recovery.incident.close', 'recovery_incident', v_inc.id, p_expected_version, v_inc.version, v_now,
    pg_catalog.jsonb_build_object('remaining_risk_decision_code', p_remaining_risk_decision_code)
  );

  RETURN pg_catalog.jsonb_build_object('outcome', 'closed', 'incident_id', v_inc.id, 'state', v_inc.state, 'version', v_inc.version);
END;
$$;

CREATE OR REPLACE FUNCTION rq_recovery.cmd_operation_create(
  p_operation_id uuid,
  p_incident_id uuid,
  p_external_operation_id uuid,
  p_source_epoch uuid,
  p_target_epoch uuid,
  p_target_database_identity_digest bytea,
  p_plan_sha256 bytea,
  p_requester_reference text
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  v_existing rq_recovery.operations%ROWTYPE;
  v_now timestamptz := pg_catalog.clock_timestamp();
BEGIN
  PERFORM rq._assert_session_role(ARRAY['rq_recovery']);

  SELECT * INTO v_existing FROM rq_recovery.operations WHERE external_operation_id = p_external_operation_id FOR UPDATE;
  IF FOUND THEN
    IF v_existing.id <> p_operation_id OR v_existing.plan_sha256 <> p_plan_sha256 OR v_existing.target_epoch <> p_target_epoch THEN
      RAISE EXCEPTION 'Recovery operation external ID reused with conflicting plan' USING ERRCODE = '23505';
    END IF;
    RETURN pg_catalog.jsonb_build_object('outcome', 'idempotent', 'operation_id', v_existing.id, 'state', v_existing.state, 'version', v_existing.version);
  END IF;

  INSERT INTO rq_recovery.operations (
    id, incident_id, external_operation_id, source_epoch, target_epoch, target_database_identity_digest,
    plan_sha256, state, requester_reference, created_at, updated_at, version
  ) VALUES (
    p_operation_id, p_incident_id, p_external_operation_id, p_source_epoch, p_target_epoch, p_target_database_identity_digest,
    p_plan_sha256, 'planned', p_requester_reference, v_now, v_now, 1
  );

  RETURN pg_catalog.jsonb_build_object('outcome', 'planned', 'operation_id', p_operation_id, 'state', 'planned', 'version', 1);
END;
$$;

CREATE OR REPLACE FUNCTION rq_recovery.cmd_action_plan(
  p_action_id uuid,
  p_operation_id uuid,
  p_ordinal integer,
  p_kind text,
  p_scope_kind text,
  p_tenant_id uuid,
  p_project_id uuid,
  p_target_id uuid,
  p_expected_target_version bigint,
  p_expected_control_epoch uuid,
  p_expected_facts_sha256 bytea,
  p_proposed_facts_sha256 bytea,
  p_requester_reference text,
  p_reason_code text,
  p_evidence_reference text,
  p_typed_plan jsonb
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  v_op rq_recovery.operations%ROWTYPE;
  v_existing rq_recovery.actions%ROWTYPE;
  v_now timestamptz := pg_catalog.clock_timestamp();
BEGIN
  PERFORM rq._assert_session_role(ARRAY['rq_recovery']);

  IF pg_catalog.jsonb_typeof(p_typed_plan) <> 'object' THEN
    RAISE EXCEPTION 'Typed recovery plan must be a JSON object' USING ERRCODE = '22023';
  END IF;

  SELECT * INTO v_op FROM rq_recovery.operations WHERE id = p_operation_id FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'Recovery operation not found' USING ERRCODE = 'P0002';
  END IF;
  IF v_op.state IN ('completed', 'abandoned') THEN
    RAISE EXCEPTION 'Cannot add action to closed operation' USING ERRCODE = '55000';
  END IF;

  IF p_kind = 'establish_target_epoch' AND p_expected_control_epoch <> v_op.source_epoch THEN
    RAISE EXCEPTION 'establish_target_epoch expected_control_epoch must match operation source_epoch' USING ERRCODE = '22023';
  ELSIF p_kind <> 'establish_target_epoch' AND p_expected_control_epoch <> v_op.target_epoch THEN
    RAISE EXCEPTION 'Recovery action expected_control_epoch must match operation target_epoch' USING ERRCODE = '22023';
  END IF;

  SELECT * INTO v_existing FROM rq_recovery.actions WHERE id = p_action_id;
  IF FOUND THEN
    IF v_existing.kind <> p_kind OR v_existing.expected_facts_sha256 <> p_expected_facts_sha256 OR v_existing.proposed_facts_sha256 <> p_proposed_facts_sha256 THEN
      RAISE EXCEPTION 'Recovery action ID conflict' USING ERRCODE = '23505';
    END IF;
    RETURN pg_catalog.jsonb_build_object('outcome', 'idempotent', 'action_id', v_existing.id, 'kind', v_existing.kind, 'state', v_existing.state);
  END IF;

  INSERT INTO rq_recovery.actions (
    id, operation_id, ordinal, kind, scope_kind, tenant_id, project_id, target_id,
    expected_target_version, expected_control_epoch, plan_sha256,
    expected_facts_sha256, proposed_facts_sha256, state, requester_reference,
    reason_code, evidence_reference, created_at, updated_at, version
  ) VALUES (
    p_action_id, p_operation_id, p_ordinal, p_kind, p_scope_kind, p_tenant_id, p_project_id, p_target_id,
    p_expected_target_version, p_expected_control_epoch, v_op.plan_sha256,
    p_expected_facts_sha256, p_proposed_facts_sha256, 'planned', p_requester_reference,
    p_reason_code, p_evidence_reference, v_now, v_now, 1
  );

  IF p_kind = 'establish_target_epoch' THEN
    INSERT INTO rq_recovery.action_establish_target_epochs (
      action_id, source_epoch, target_epoch, expected_installation_version,
      target_database_identity_digest, containment_evidence_reference,
      broker_generation_evidence_reference, proposed_mode
    ) VALUES (
      p_action_id, v_op.source_epoch, v_op.target_epoch, p_expected_target_version,
      v_op.target_database_identity_digest,
      p_typed_plan->>'containment_evidence_reference',
      p_typed_plan->>'broker_generation_evidence_reference',
      p_typed_plan->>'proposed_mode'
    );
  ELSIF p_kind = 'retire_stale_claim' THEN
    INSERT INTO rq_recovery.action_retire_stale_claims (
      action_id, claim_kind, scope_kind, tenant_id, project_id,
      outbox_id, event_id, attempt_id, coordinator_task_id,
      expected_owner_instance_id, expected_claim_generation, expected_claim_control_epoch,
      expected_claim_expires_at, expected_resource_version, old_writer_containment_reference, timeline_mode
    ) VALUES (
      p_action_id,
      p_typed_plan->>'claim_kind',
      p_scope_kind, p_tenant_id, p_project_id,
      (p_typed_plan->>'outbox_id')::uuid,
      (p_typed_plan->>'event_id')::uuid,
      (p_typed_plan->>'attempt_id')::uuid,
      (p_typed_plan->>'coordinator_task_id')::uuid,
      (p_typed_plan->>'expected_owner_instance_id')::uuid,
      (p_typed_plan->>'expected_claim_generation')::bigint,
      (p_typed_plan->>'expected_claim_control_epoch')::uuid,
      (p_typed_plan->>'expected_claim_expires_at')::timestamptz,
      p_expected_target_version,
      p_typed_plan->>'old_writer_containment_reference',
      p_typed_plan->>'timeline_mode'
    );
  ELSIF p_kind = 'reconcile_reservations' THEN
    INSERT INTO rq_recovery.action_reconcile_reservations (
      action_id, reservation_kind, scope_kind, tenant_id, project_id,
      endpoint_id, producer_id, sender_instance_id, bucket_operation,
      expected_resource_version, expected_stored_value, derived_obligation_value,
      proposed_value, capacity_bound, conservative_policy, affected_window_start,
      affected_window_end, obligation_inventory_digest
    ) VALUES (
      p_action_id,
      p_typed_plan->>'reservation_kind',
      p_typed_plan->>'target_scope_kind',
      p_tenant_id, p_project_id,
      (p_typed_plan->>'endpoint_id')::uuid,
      (p_typed_plan->>'producer_id')::uuid,
      (p_typed_plan->>'sender_instance_id')::uuid,
      p_typed_plan->>'bucket_operation',
      p_expected_target_version,
      (p_typed_plan->>'expected_stored_value')::bigint,
      (p_typed_plan->>'derived_obligation_value')::bigint,
      (p_typed_plan->>'proposed_value')::bigint,
      (p_typed_plan->>'capacity_bound')::bigint,
      p_typed_plan->>'conservative_policy',
      (p_typed_plan->>'affected_window_start')::timestamptz,
      (p_typed_plan->>'affected_window_end')::timestamptz,
      pg_catalog.decode(p_typed_plan->>'obligation_inventory_digest_hex', 'hex')
    );
  ELSIF p_kind = 'continue_publication_episode' THEN
    INSERT INTO rq_recovery.action_continue_publication_episodes (
      action_id, tenant_id, project_id, outbox_id, event_id, episode_id,
      expected_episode_version, expected_outbox_version, expected_publication_generation,
      no_progress_boundary_sha256, cause_resolution_evidence_reference, schedule_next_notification
    ) VALUES (
      p_action_id, p_tenant_id, p_project_id,
      (p_typed_plan->>'outbox_id')::uuid,
      (p_typed_plan->>'event_id')::uuid,
      (p_typed_plan->>'episode_id')::uuid,
      (p_typed_plan->>'expected_episode_version')::bigint,
      (p_typed_plan->>'expected_outbox_version')::bigint,
      (p_typed_plan->>'expected_publication_generation')::bigint,
      pg_catalog.decode(p_typed_plan->>'no_progress_boundary_sha256_hex', 'hex'),
      p_typed_plan->>'cause_resolution_evidence_reference',
      (p_typed_plan->>'schedule_next_notification')::boolean
    );
  ELSIF p_kind = 'record_receiver_comparison' THEN
    INSERT INTO rq_recovery.action_record_receiver_comparisons (
      action_id, tenant_id, project_id, delivery_id, event_id,
      consumer_contract_scope, consumer_event_key_sha256, original_facts_sha256,
      comparison_outcome, source_kind, source_reference, observed_at,
      diagnostic_evidence_digest, receiver_facts_sha256, requires_hold_investigation
    ) VALUES (
      p_action_id, p_tenant_id, p_project_id,
      (p_typed_plan->>'delivery_id')::uuid,
      (p_typed_plan->>'event_id')::uuid,
      p_typed_plan->>'consumer_contract_scope',
      pg_catalog.decode(p_typed_plan->>'consumer_event_key_sha256_hex', 'hex'),
      pg_catalog.decode(p_typed_plan->>'original_facts_sha256_hex', 'hex'),
      p_typed_plan->>'comparison_outcome',
      p_typed_plan->>'source_kind',
      p_typed_plan->>'source_reference',
      (p_typed_plan->>'observed_at')::timestamptz,
      pg_catalog.decode(p_typed_plan->>'diagnostic_evidence_digest_hex', 'hex'),
      CASE WHEN p_typed_plan->>'receiver_facts_sha256_hex' IS NULL THEN NULL ELSE pg_catalog.decode(p_typed_plan->>'receiver_facts_sha256_hex', 'hex') END,
      (p_typed_plan->>'requires_hold_investigation')::boolean
    );
  ELSIF p_kind = 'set_recovery_gate' THEN
    INSERT INTO rq_recovery.action_set_recovery_gates (
      action_id, target_scope_kind, tenant_id, project_id, expected_target_version,
      proposed_installation_mode, proposed_allow_event_admission, proposed_allow_publication,
      proposed_allow_fanout, proposed_allow_send, proposed_allow_endpoint_verification,
      proposed_tenant_state, proposed_project_state,
      containment_evidence_reference, integrity_evidence_reference, broker_evidence_reference,
      receiver_evidence_reference, capacity_evidence_reference, retained_hold_refs
    ) VALUES (
      p_action_id, p_scope_kind, p_tenant_id, p_project_id, p_expected_target_version,
      p_typed_plan->>'proposed_installation_mode',
      (p_typed_plan->>'proposed_allow_event_admission')::boolean,
      (p_typed_plan->>'proposed_allow_publication')::boolean,
      (p_typed_plan->>'proposed_allow_fanout')::boolean,
      (p_typed_plan->>'proposed_allow_send')::boolean,
      (p_typed_plan->>'proposed_allow_endpoint_verification')::boolean,
      p_typed_plan->>'proposed_tenant_state',
      p_typed_plan->>'proposed_project_state',
      p_typed_plan->>'containment_evidence_reference',
      p_typed_plan->>'integrity_evidence_reference',
      p_typed_plan->>'broker_evidence_reference',
      p_typed_plan->>'receiver_evidence_reference',
      p_typed_plan->>'capacity_evidence_reference',
      COALESCE(p_typed_plan->'retained_hold_refs', '[]'::jsonb)
    );
  ELSIF p_kind = 'rebuild_projection' THEN
    INSERT INTO rq_recovery.action_rebuild_projections (
      action_id, projection_kind, tenant_id, project_id, event_id,
      population_definition_version, expected_projection_version,
      expected_source_boundary_sha256, max_source_rows,
      proposed_total_deliveries, proposed_pending_count, proposed_active_count,
      proposed_acknowledged_count, proposed_dead_letter_count, proposed_suppressed_count,
      proposed_expired_count, proposed_terminal_deliveries,
      proposed_unknown_attempt_observations, diagnostic_mismatch_sha256
    ) VALUES (
      p_action_id,
      p_typed_plan->>'projection_kind',
      p_tenant_id, p_project_id,
      (p_typed_plan->>'event_id')::uuid,
      COALESCE(p_typed_plan->>'population_definition_version', 'delivery_population.v1'),
      p_expected_target_version,
      pg_catalog.decode(p_typed_plan->>'expected_source_boundary_sha256_hex', 'hex'),
      COALESCE((p_typed_plan->>'max_source_rows')::bigint, 10000),
      (p_typed_plan->>'proposed_total_deliveries')::bigint,
      (p_typed_plan->>'proposed_pending_count')::bigint,
      (p_typed_plan->>'proposed_active_count')::bigint,
      (p_typed_plan->>'proposed_acknowledged_count')::bigint,
      (p_typed_plan->>'proposed_dead_letter_count')::bigint,
      (p_typed_plan->>'proposed_suppressed_count')::bigint,
      (p_typed_plan->>'proposed_expired_count')::bigint,
      (p_typed_plan->>'proposed_terminal_deliveries')::bigint,
      (p_typed_plan->>'proposed_unknown_attempt_observations')::bigint,
      pg_catalog.decode(p_typed_plan->>'diagnostic_mismatch_sha256_hex', 'hex')
    );
  ELSE
    RAISE EXCEPTION 'Unsupported recovery action kind %', p_kind USING ERRCODE = '22023';
  END IF;

  RETURN pg_catalog.jsonb_build_object(
    'outcome', 'planned',
    'action_id', p_action_id,
    'operation_id', p_operation_id,
    'ordinal', p_ordinal,
    'kind', p_kind
  );
END;
$$;

CREATE OR REPLACE FUNCTION rq_recovery.cmd_action_review(
  p_review_id uuid,
  p_action_id uuid,
  p_plan_sha256 bytea,
  p_target_epoch uuid,
  p_expected_facts_sha256 bytea,
  p_proposed_facts_sha256 bytea,
  p_reviewer_reference text,
  p_decision text,
  p_reject_reason_code text,
  p_expires_at timestamptz,
  p_authority_evidence_digest bytea
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  v_action rq_recovery.actions%ROWTYPE;
  v_op rq_recovery.operations%ROWTYPE;
  v_now timestamptz := pg_catalog.clock_timestamp();
BEGIN
  PERFORM rq._assert_session_role(ARRAY['rq_recovery']);

  SELECT * INTO v_action FROM rq_recovery.actions WHERE id = p_action_id FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'Recovery action not found' USING ERRCODE = 'P0002';
  END IF;
  SELECT * INTO v_op FROM rq_recovery.operations WHERE id = v_action.operation_id FOR UPDATE;

  IF v_op.plan_sha256 <> p_plan_sha256
     OR v_op.target_epoch <> p_target_epoch
     OR v_action.expected_facts_sha256 <> p_expected_facts_sha256
     OR v_action.proposed_facts_sha256 <> p_proposed_facts_sha256 THEN
    RAISE EXCEPTION 'Review target epoch, plan digest, or facts digest mismatch' USING ERRCODE = '40001';
  END IF;

  IF p_reviewer_reference = v_action.requester_reference OR p_reviewer_reference = v_op.requester_reference THEN
    RAISE EXCEPTION 'Requester cannot self-approve a recovery action' USING ERRCODE = '42501';
  END IF;

  UPDATE rq_recovery.reviews
     SET state = 'revoked'
   WHERE action_id = p_action_id AND state = 'active';

  INSERT INTO rq_recovery.reviews (
    id, action_id, operation_id, plan_sha256, target_epoch, expected_facts_sha256,
    proposed_facts_sha256, reviewer_reference, reviewed_at, expires_at,
    decision, reject_reason_code, authority_evidence_digest, state
  ) VALUES (
    p_review_id, p_action_id, v_op.id, p_plan_sha256, p_target_epoch, p_expected_facts_sha256,
    p_proposed_facts_sha256, p_reviewer_reference, v_now, p_expires_at,
    p_decision, p_reject_reason_code, p_authority_evidence_digest, 'active'
  );

  UPDATE rq_recovery.actions
     SET state = CASE WHEN p_decision = 'approve' THEN 'reviewed' ELSE 'rejected' END,
         updated_at = v_now,
         version = version + 1
   WHERE id = p_action_id AND state IN ('planned', 'reviewed');

  IF p_decision = 'approve' AND v_op.state = 'planned' THEN
    UPDATE rq_recovery.operations
       SET state = 'reviewed', updated_at = v_now, version = version + 1
     WHERE id = v_op.id;
  END IF;

  RETURN pg_catalog.jsonb_build_object(
    'outcome', 'recorded',
    'review_id', p_review_id,
    'action_id', p_action_id,
    'decision', p_decision
  );
END;
$$;

CREATE OR REPLACE FUNCTION rq_recovery.cmd_establish_target_epoch(
  p_action_id uuid,
  p_operator_reference text,
  p_execution_nonce_digest bytea,
  p_target_database_identity_digest bytea
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  v_ctx record;
  v_plan rq_recovery.action_establish_target_epochs%ROWTYPE;
  v_inst rq.installation_state%ROWTYPE;
  v_now timestamptz := pg_catalog.clock_timestamp();
  v_res_facts jsonb;
  v_res_sha bytea;
BEGIN
  PERFORM rq._assert_session_role(ARRAY['rq_recovery']);

  SELECT * INTO v_ctx FROM rq_recovery._verify_review_and_record_attempt(
    p_action_id, 'establish_target_epoch', p_operator_reference, p_execution_nonce_digest, p_target_database_identity_digest
  );
  IF v_ctx.out_already_done THEN
    RETURN v_ctx.out_existing_result;
  END IF;

  SELECT * INTO v_plan FROM rq_recovery.action_establish_target_epochs WHERE action_id = p_action_id FOR SHARE;
  SELECT * INTO v_inst FROM rq.installation_state WHERE id = 1 FOR UPDATE;

  IF v_inst.control_epoch <> v_plan.source_epoch OR v_inst.version <> v_plan.expected_installation_version THEN
    UPDATE rq_recovery.execution_attempts
       SET outcome = 'conflict', finished_at = v_now, safe_error_code = 'EPOCH_OR_VERSION_CONFLICT', version = version + 1
     WHERE id = v_ctx.out_exec_attempt_id;
    RAISE EXCEPTION 'Installation epoch or version precondition conflict' USING ERRCODE = '40001';
  END IF;

  UPDATE rq.installation_state
     SET control_epoch = v_plan.target_epoch,
         mode = v_plan.proposed_mode,
         allow_event_admission = false,
         allow_publication = false,
         allow_fanout = false,
         allow_send = false,
         allow_endpoint_verification = false,
         governance_version = governance_version + 1,
         updated_at = v_now,
         version = version + 1
   WHERE id = 1
   RETURNING * INTO v_inst;

  UPDATE rq_recovery.reviews SET state = 'consumed' WHERE id = (v_ctx.out_review).id;
  UPDATE rq_recovery.actions SET state = 'applied', updated_at = v_now, version = version + 1 WHERE id = p_action_id;
  UPDATE rq_recovery.execution_attempts SET outcome = 'applied', finished_at = v_now, version = version + 1 WHERE id = v_ctx.out_exec_attempt_id;

  v_res_facts := pg_catalog.jsonb_build_object(
    'action_kind', 'establish_target_epoch',
    'control_epoch', v_inst.control_epoch,
    'mode', v_inst.mode,
    'version', v_inst.version
  );
  v_res_sha := pg_catalog.sha256(pg_catalog.convert_to(v_res_facts::text, 'UTF8'));

  INSERT INTO rq_recovery.action_results (
    action_id, operation_id, execution_attempt_id, outcome,
    proposed_facts_sha256, resulting_facts_sha256, new_target_version, safe_result_facts, recorded_at
  ) VALUES (
    p_action_id, (v_ctx.out_op).id, v_ctx.out_exec_attempt_id, 'applied',
    (v_ctx.out_action).proposed_facts_sha256, v_res_sha, v_inst.version, v_res_facts, v_now
  );

  INSERT INTO rq.audit_events (
    id, actor_kind, operator_reference, action, target_kind, target_id,
    prior_version, resulting_version, candidate_sha256, recorded_at, safe_facts
  ) VALUES (
    pg_catalog.gen_random_uuid(), 'operator', p_operator_reference, 'recovery.establish_target_epoch',
    'installation_state', v_inst.control_epoch, v_plan.expected_installation_version, v_inst.version, v_res_sha, v_now, v_res_facts
  );

  RETURN pg_catalog.jsonb_build_object(
    'outcome', 'applied',
    'operation_id', (v_ctx.out_op).id,
    'action_id', p_action_id,
    'new_target_version', v_inst.version,
    'resulting_facts_sha256', pg_catalog.encode(v_res_sha, 'hex'),
    'safe_result_facts', v_res_facts
  );
END;
$$;

CREATE OR REPLACE FUNCTION rq_recovery.cmd_retire_stale_claim(
  p_action_id uuid,
  p_operator_reference text,
  p_execution_nonce_digest bytea,
  p_target_database_identity_digest bytea
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  v_ctx record;
  v_plan rq_recovery.action_retire_stale_claims%ROWTYPE;
  v_inst rq.installation_state%ROWTYPE;
  v_outbox rq.outbox_events%ROWTYPE;
  v_fanout rq.event_fanout%ROWTYPE;
  v_attempt rq.delivery_attempts%ROWTYPE;
  v_delivery rq.deliveries%ROWTYPE;
  v_circuit rq.endpoint_circuits%ROWTYPE;
  v_task rq.coordinator_tasks%ROWTYPE;
  v_now timestamptz := pg_catalog.clock_timestamp();
  v_new_version bigint;
  v_target_id uuid;
  v_shard smallint;
  v_res_facts jsonb;
  v_res_sha bytea;
BEGIN
  PERFORM rq._assert_session_role(ARRAY['rq_recovery']);

  SELECT * INTO v_ctx FROM rq_recovery._verify_review_and_record_attempt(
    p_action_id, 'retire_stale_claim', p_operator_reference, p_execution_nonce_digest, p_target_database_identity_digest
  );
  IF v_ctx.out_already_done THEN
    RETURN v_ctx.out_existing_result;
  END IF;

  SELECT * INTO v_plan FROM rq_recovery.action_retire_stale_claims WHERE action_id = p_action_id FOR SHARE;
  SELECT * INTO v_inst FROM rq.installation_state WHERE id = 1 FOR SHARE;

  IF v_inst.control_epoch <> (v_ctx.out_action).expected_control_epoch THEN
    RAISE EXCEPTION 'Target epoch precondition mismatch' USING ERRCODE = '40001';
  END IF;

  IF v_plan.claim_kind = 'publication' THEN
    SELECT * INTO v_outbox FROM rq.outbox_events WHERE id = v_plan.outbox_id FOR UPDATE;
    IF NOT FOUND
       OR v_outbox.version <> v_plan.expected_resource_version
       OR v_outbox.claim_owner_instance_id IS DISTINCT FROM v_plan.expected_owner_instance_id
       OR v_outbox.claim_generation <> v_plan.expected_claim_generation
       OR v_outbox.claim_control_epoch IS DISTINCT FROM v_plan.expected_claim_control_epoch THEN
      RAISE EXCEPTION 'Publication claim precondition mismatch' USING ERRCODE = '40001';
    END IF;
    IF v_plan.timeline_mode = 'live_expired_reap' AND v_outbox.claim_expires_at > v_now THEN
      RAISE EXCEPTION 'Cannot retire healthy non-expired live publication claim' USING ERRCODE = '55000';
    END IF;

    UPDATE rq.outbox_events
       SET state = 'pending',
           claim_owner_instance_id = NULL,
           claim_control_epoch = NULL,
           claim_expires_at = NULL,
           last_safe_error_code = 'RECOVERY_RETIRED_STALE_CLAIM',
           updated_at = v_now,
           version = version + 1
     WHERE id = v_outbox.id
     RETURNING version INTO v_new_version;
    v_target_id := v_outbox.id;

  ELSIF v_plan.claim_kind = 'fanout' THEN
    SELECT * INTO v_fanout FROM rq.event_fanout WHERE event_id = v_plan.event_id FOR UPDATE;
    IF NOT FOUND
       OR v_fanout.version <> v_plan.expected_resource_version
       OR v_fanout.claim_owner_instance_id IS DISTINCT FROM v_plan.expected_owner_instance_id
       OR v_fanout.claim_generation <> v_plan.expected_claim_generation
       OR v_fanout.claim_control_epoch IS DISTINCT FROM v_plan.expected_claim_control_epoch THEN
      RAISE EXCEPTION 'Fanout claim precondition mismatch' USING ERRCODE = '40001';
    END IF;
    IF v_plan.timeline_mode = 'live_expired_reap' AND v_fanout.claim_expires_at > v_now THEN
      RAISE EXCEPTION 'Cannot retire healthy non-expired live fanout claim' USING ERRCODE = '55000';
    END IF;

    UPDATE rq.event_fanout
       SET state = CASE WHEN examined_count > 0 THEN 'materializing' ELSE 'pending' END,
           claim_owner_instance_id = NULL,
           claim_control_epoch = NULL,
           claim_expires_at = NULL,
           safe_error_code = 'RECOVERY_RETIRED_STALE_CLAIM',
           version = version + 1
     WHERE event_id = v_fanout.event_id
     RETURNING version INTO v_new_version;
    v_target_id := v_fanout.event_id;

  ELSIF v_plan.claim_kind = 'prepared_attempt' THEN
    SELECT * INTO v_attempt FROM rq.delivery_attempts WHERE id = v_plan.attempt_id FOR UPDATE;
    IF NOT FOUND
       OR v_attempt.version <> v_plan.expected_resource_version
       OR v_attempt.worker_instance_id <> v_plan.expected_owner_instance_id
       OR v_attempt.fencing_token <> v_plan.expected_claim_generation
       OR v_attempt.control_epoch <> v_plan.expected_claim_control_epoch THEN
      RAISE EXCEPTION 'Prepared attempt precondition mismatch' USING ERRCODE = '40001';
    END IF;
    IF v_attempt.state <> 'prepared' OR v_attempt.send_started_at IS NOT NULL THEN
      RAISE EXCEPTION 'Cannot retire send_started or finalized delivery attempt via stale claim retirement' USING ERRCODE = '55000';
    END IF;
    IF v_plan.timeline_mode = 'live_expired_reap' AND v_attempt.claim_expires_at > v_now THEN
      RAISE EXCEPTION 'Cannot retire healthy non-expired prepared attempt' USING ERRCODE = '55000';
    END IF;

    SELECT * INTO v_delivery FROM rq.deliveries WHERE id = v_attempt.delivery_id FOR UPDATE;

    -- Release unstarted send rate reservations and active capacity slots in the same conservation transaction
    UPDATE rq.tenant_rate_buckets
       SET reserved_micro = reserved_micro - 1000000, updated_at = v_now, version = version + 1
     WHERE tenant_id = v_attempt.tenant_id AND operation = 'send_start'
       AND EXISTS (SELECT 1 FROM rq.tenant_send_reservations r WHERE r.attempt_id = v_attempt.id AND r.state = 'held');
    UPDATE rq.project_rate_buckets
       SET reserved_micro = reserved_micro - 1000000, updated_at = v_now, version = version + 1
     WHERE project_id = v_attempt.project_id AND operation = 'send_start'
       AND EXISTS (SELECT 1 FROM rq.project_send_reservations r WHERE r.attempt_id = v_attempt.id AND r.state = 'held');
    UPDATE rq.endpoint_rate_buckets
       SET reserved_micro = reserved_micro - 1000000, updated_at = v_now, version = version + 1
     WHERE endpoint_id = v_attempt.endpoint_id AND operation = 'send_start'
       AND EXISTS (SELECT 1 FROM rq.endpoint_send_reservations r WHERE r.attempt_id = v_attempt.id AND r.state = 'held');

    UPDATE rq.tenant_send_reservations SET state = 'released', released_at = v_now, version = version + 1 WHERE attempt_id = v_attempt.id AND state = 'held';
    UPDATE rq.project_send_reservations SET state = 'released', released_at = v_now, version = version + 1 WHERE attempt_id = v_attempt.id AND state = 'held';
    UPDATE rq.endpoint_send_reservations SET state = 'released', released_at = v_now, version = version + 1 WHERE attempt_id = v_attempt.id AND state = 'held';

    UPDATE rq.attempt_slots
       SET state = 'released', released_at = v_now, release_reason = 'recovery_retire_stale_claim', version = version + 1
     WHERE attempt_id = v_attempt.id AND state = 'held';

    UPDATE rq.sender_capacity SET held_slots = held_slots - 1, updated_at = v_now, version = version + 1 WHERE instance_id = v_attempt.worker_instance_id;
    UPDATE rq.tenant_capacity SET active_attempt_slots = active_attempt_slots - 1, updated_at = v_now, version = version + 1 WHERE tenant_id = v_attempt.tenant_id;
    UPDATE rq.project_capacity SET active_attempt_slots = active_attempt_slots - 1, updated_at = v_now, version = version + 1 WHERE project_id = v_attempt.project_id;
    UPDATE rq.endpoint_capacity SET held_slots = held_slots - 1, updated_at = v_now, version = version + 1 WHERE endpoint_id = v_attempt.endpoint_id;

    UPDATE rq.delivery_capacity_positions
       SET position = 'pending', current_attempt_id = NULL, updated_at = v_now, version = version + 1
     WHERE delivery_id = v_delivery.id;

    SELECT * INTO v_circuit FROM rq.endpoint_circuits
     WHERE endpoint_id = v_attempt.endpoint_id AND endpoint_version = v_attempt.endpoint_version FOR UPDATE;
    IF v_circuit.state = 'half_open' AND v_circuit.probe_attempt_id = v_attempt.id THEN
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
    END IF;

    UPDATE rq.delivery_attempts
       SET state = 'failed_before_send',
           safe_error_code = 'RECOVERY_RETIRED_STALE_CLAIM',
           finished_at = v_now,
           version = version + 1
     WHERE id = v_attempt.id
     RETURNING version INTO v_new_version;

    UPDATE rq.deliveries
       SET state = 'retry_wait',
           current_attempt_id = NULL,
           blocking_reason = 'stale_claim_retired',
           next_eligible_at = GREATEST(next_eligible_at, v_now),
           next_history_sequence = next_history_sequence + 1,
           updated_at = v_now,
           version = version + 1
     WHERE id = v_delivery.id;

    v_shard := rq._delivery_shard(v_delivery.id);
    INSERT INTO rq.project_delivery_total_deltas (
      project_id, shard_id, tenant_id, pending_delta, active_delta, updated_at, version
    ) VALUES (
      v_delivery.project_id, v_shard, v_delivery.tenant_id, 1, -1, v_now, 1
    )
    ON CONFLICT (project_id, shard_id) DO UPDATE
      SET pending_delta = rq.project_delivery_total_deltas.pending_delta + 1,
          active_delta = rq.project_delivery_total_deltas.active_delta - 1,
          updated_at = v_now,
          version = rq.project_delivery_total_deltas.version + 1;

    INSERT INTO rq.delivery_history (
      delivery_id, history_sequence, tenant_id, project_id, kind, recorded_at, attempt_id, safe_facts, event_schema_version
    ) VALUES (
      v_delivery.id, v_delivery.next_history_sequence + 1, v_delivery.tenant_id, v_delivery.project_id,
      'delivery.stale_claim_retired', v_now, v_attempt.id,
      pg_catalog.jsonb_build_object('action_id', p_action_id, 'timeline_mode', v_plan.timeline_mode), 1
    );

    v_target_id := v_attempt.id;

  ELSIF v_plan.claim_kind = 'coordinator_task' THEN
    SELECT * INTO v_task FROM rq.coordinator_tasks WHERE id = v_plan.coordinator_task_id FOR UPDATE;
    IF NOT FOUND
       OR v_task.version <> v_plan.expected_resource_version
       OR v_task.owner_instance_id IS DISTINCT FROM v_plan.expected_owner_instance_id
       OR v_task.claim_generation <> v_plan.expected_claim_generation
       OR v_task.control_epoch <> v_plan.expected_claim_control_epoch THEN
      RAISE EXCEPTION 'Coordinator task claim precondition mismatch' USING ERRCODE = '40001';
    END IF;
    IF v_plan.timeline_mode = 'live_expired_reap' AND v_task.claim_expires_at > v_now THEN
      RAISE EXCEPTION 'Cannot retire healthy non-expired live coordinator claim' USING ERRCODE = '55000';
    END IF;

    UPDATE rq.coordinator_tasks
       SET state = 'ready',
           owner_instance_id = NULL,
           claim_expires_at = NULL,
           safe_error_code = 'RECOVERY_RETIRED_STALE_CLAIM',
           version = version + 1
     WHERE id = v_task.id
     RETURNING version INTO v_new_version;
    v_target_id := v_task.id;
  END IF;

  UPDATE rq_recovery.reviews SET state = 'consumed' WHERE id = (v_ctx.out_review).id;
  UPDATE rq_recovery.actions SET state = 'applied', updated_at = v_now, version = version + 1 WHERE id = p_action_id;
  UPDATE rq_recovery.execution_attempts SET outcome = 'applied', finished_at = v_now, version = version + 1 WHERE id = v_ctx.out_exec_attempt_id;

  v_res_facts := pg_catalog.jsonb_build_object(
    'action_kind', 'retire_stale_claim',
    'claim_kind', v_plan.claim_kind,
    'target_id', v_target_id,
    'new_target_version', v_new_version
  );
  v_res_sha := pg_catalog.sha256(pg_catalog.convert_to(v_res_facts::text, 'UTF8'));

  INSERT INTO rq_recovery.action_results (
    action_id, operation_id, execution_attempt_id, outcome,
    proposed_facts_sha256, resulting_facts_sha256, new_target_version, safe_result_facts, recorded_at
  ) VALUES (
    p_action_id, (v_ctx.out_op).id, v_ctx.out_exec_attempt_id, 'applied',
    (v_ctx.out_action).proposed_facts_sha256, v_res_sha, v_new_version, v_res_facts, v_now
  );

  INSERT INTO rq.audit_events (
    id, tenant_id, project_id, actor_kind, operator_reference, action, target_kind, target_id,
    prior_version, resulting_version, candidate_sha256, recorded_at, safe_facts
  ) VALUES (
    pg_catalog.gen_random_uuid(), v_plan.tenant_id, v_plan.project_id, 'operator', p_operator_reference,
    'recovery.retire_stale_claim', v_plan.claim_kind, v_target_id,
    v_plan.expected_resource_version, v_new_version, v_res_sha, v_now, v_res_facts
  );

  RETURN pg_catalog.jsonb_build_object(
    'outcome', 'applied',
    'operation_id', (v_ctx.out_op).id,
    'action_id', p_action_id,
    'new_target_version', v_new_version,
    'resulting_facts_sha256', pg_catalog.encode(v_res_sha, 'hex'),
    'safe_result_facts', v_res_facts
  );
END;
$$;

CREATE OR REPLACE FUNCTION rq_recovery.cmd_reconcile_reservations(
  p_action_id uuid,
  p_operator_reference text,
  p_execution_nonce_digest bytea,
  p_target_database_identity_digest bytea
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  v_ctx record;
  v_plan rq_recovery.action_reconcile_reservations%ROWTYPE;
  v_inst rq.installation_state%ROWTYPE;
  v_now timestamptz := pg_catalog.clock_timestamp();
  v_cur_ver bigint;
  v_cur_val bigint;
  v_new_ver bigint;
  v_target_id uuid;
  v_res_facts jsonb;
  v_res_sha bytea;
BEGIN
  PERFORM rq._assert_session_role(ARRAY['rq_recovery']);

  SELECT * INTO v_ctx FROM rq_recovery._verify_review_and_record_attempt(
    p_action_id, 'reconcile_reservations', p_operator_reference, p_execution_nonce_digest, p_target_database_identity_digest
  );
  IF v_ctx.out_already_done THEN
    RETURN v_ctx.out_existing_result;
  END IF;

  SELECT * INTO v_plan FROM rq_recovery.action_reconcile_reservations WHERE action_id = p_action_id FOR SHARE;
  SELECT * INTO v_inst FROM rq.installation_state WHERE id = 1 FOR SHARE;

  IF v_inst.control_epoch <> (v_ctx.out_action).expected_control_epoch THEN
    RAISE EXCEPTION 'Target epoch precondition mismatch' USING ERRCODE = '40001';
  END IF;

  IF v_plan.reservation_kind = 'tenant_fanout_slot' THEN
    SELECT version, unmaterialized_candidate_slots INTO v_cur_ver, v_cur_val
      FROM rq.tenant_capacity WHERE tenant_id = v_plan.tenant_id FOR UPDATE;
    IF v_cur_ver <> v_plan.expected_resource_version OR v_cur_val <> v_plan.expected_stored_value THEN
      RAISE EXCEPTION 'Reservation stored value or version conflict' USING ERRCODE = '40001';
    END IF;
    UPDATE rq.tenant_capacity SET unmaterialized_candidate_slots = v_plan.proposed_value, updated_at = v_now, version = version + 1
     WHERE tenant_id = v_plan.tenant_id RETURNING version INTO v_new_ver;
    v_target_id := v_plan.tenant_id;

  ELSIF v_plan.reservation_kind = 'project_fanout_slot' THEN
    SELECT version, unmaterialized_candidate_slots INTO v_cur_ver, v_cur_val
      FROM rq.project_capacity WHERE project_id = v_plan.project_id FOR UPDATE;
    IF v_cur_ver <> v_plan.expected_resource_version OR v_cur_val <> v_plan.expected_stored_value THEN
      RAISE EXCEPTION 'Reservation stored value or version conflict' USING ERRCODE = '40001';
    END IF;
    UPDATE rq.project_capacity SET unmaterialized_candidate_slots = v_plan.proposed_value, updated_at = v_now, version = version + 1
     WHERE project_id = v_plan.project_id RETURNING version INTO v_new_ver;
    v_target_id := v_plan.project_id;

  ELSIF v_plan.reservation_kind = 'tenant_send_slot' THEN
    SELECT version, active_attempt_slots INTO v_cur_ver, v_cur_val
      FROM rq.tenant_capacity WHERE tenant_id = v_plan.tenant_id FOR UPDATE;
    IF v_cur_ver <> v_plan.expected_resource_version OR v_cur_val <> v_plan.expected_stored_value THEN
      RAISE EXCEPTION 'Reservation stored value or version conflict' USING ERRCODE = '40001';
    END IF;
    UPDATE rq.tenant_capacity SET active_attempt_slots = v_plan.proposed_value::integer, updated_at = v_now, version = version + 1
     WHERE tenant_id = v_plan.tenant_id RETURNING version INTO v_new_ver;
    v_target_id := v_plan.tenant_id;

  ELSIF v_plan.reservation_kind = 'project_send_slot' THEN
    SELECT version, active_attempt_slots INTO v_cur_ver, v_cur_val
      FROM rq.project_capacity WHERE project_id = v_plan.project_id FOR UPDATE;
    IF v_cur_ver <> v_plan.expected_resource_version OR v_cur_val <> v_plan.expected_stored_value THEN
      RAISE EXCEPTION 'Reservation stored value or version conflict' USING ERRCODE = '40001';
    END IF;
    UPDATE rq.project_capacity SET active_attempt_slots = v_plan.proposed_value::integer, updated_at = v_now, version = version + 1
     WHERE project_id = v_plan.project_id RETURNING version INTO v_new_ver;
    v_target_id := v_plan.project_id;

  ELSIF v_plan.reservation_kind = 'endpoint_send_slot' THEN
    SELECT version, held_slots INTO v_cur_ver, v_cur_val
      FROM rq.endpoint_capacity WHERE endpoint_id = v_plan.endpoint_id FOR UPDATE;
    IF v_cur_ver <> v_plan.expected_resource_version OR v_cur_val <> v_plan.expected_stored_value THEN
      RAISE EXCEPTION 'Reservation stored value or version conflict' USING ERRCODE = '40001';
    END IF;
    UPDATE rq.endpoint_capacity SET held_slots = v_plan.proposed_value::integer, updated_at = v_now, version = version + 1
     WHERE endpoint_id = v_plan.endpoint_id RETURNING version INTO v_new_ver;
    v_target_id := v_plan.endpoint_id;

  ELSIF v_plan.reservation_kind = 'sender_send_slot' THEN
    SELECT version, held_slots INTO v_cur_ver, v_cur_val
      FROM rq.sender_capacity WHERE instance_id = v_plan.sender_instance_id FOR UPDATE;
    IF v_cur_ver <> v_plan.expected_resource_version OR v_cur_val <> v_plan.expected_stored_value THEN
      RAISE EXCEPTION 'Reservation stored value or version conflict' USING ERRCODE = '40001';
    END IF;
    UPDATE rq.sender_capacity SET held_slots = v_plan.proposed_value::integer, updated_at = v_now, version = version + 1
     WHERE instance_id = v_plan.sender_instance_id RETURNING version INTO v_new_ver;
    v_target_id := v_plan.sender_instance_id;

  ELSIF v_plan.reservation_kind = 'tenant_rate_bucket' THEN
    SELECT version, reserved_micro INTO v_cur_ver, v_cur_val
      FROM rq.tenant_rate_buckets WHERE tenant_id = v_plan.tenant_id AND operation = v_plan.bucket_operation FOR UPDATE;
    IF v_cur_ver <> v_plan.expected_resource_version OR v_cur_val <> v_plan.expected_stored_value THEN
      RAISE EXCEPTION 'Rate bucket stored reservation conflict' USING ERRCODE = '40001';
    END IF;
    UPDATE rq.tenant_rate_buckets SET reserved_micro = v_plan.proposed_value, updated_at = v_now, version = version + 1
     WHERE tenant_id = v_plan.tenant_id AND operation = v_plan.bucket_operation RETURNING version INTO v_new_ver;
    v_target_id := v_plan.tenant_id;

  ELSIF v_plan.reservation_kind = 'project_rate_bucket' THEN
    SELECT version, reserved_micro INTO v_cur_ver, v_cur_val
      FROM rq.project_rate_buckets WHERE project_id = v_plan.project_id AND operation = v_plan.bucket_operation FOR UPDATE;
    IF v_cur_ver <> v_plan.expected_resource_version OR v_cur_val <> v_plan.expected_stored_value THEN
      RAISE EXCEPTION 'Rate bucket stored reservation conflict' USING ERRCODE = '40001';
    END IF;
    UPDATE rq.project_rate_buckets SET reserved_micro = v_plan.proposed_value, updated_at = v_now, version = version + 1
     WHERE project_id = v_plan.project_id AND operation = v_plan.bucket_operation RETURNING version INTO v_new_ver;
    v_target_id := v_plan.project_id;

  ELSIF v_plan.reservation_kind = 'endpoint_rate_bucket' THEN
    SELECT version, reserved_micro INTO v_cur_ver, v_cur_val
      FROM rq.endpoint_rate_buckets WHERE endpoint_id = v_plan.endpoint_id AND operation = v_plan.bucket_operation FOR UPDATE;
    IF v_cur_ver <> v_plan.expected_resource_version OR v_cur_val <> v_plan.expected_stored_value THEN
      RAISE EXCEPTION 'Rate bucket stored reservation conflict' USING ERRCODE = '40001';
    END IF;
    UPDATE rq.endpoint_rate_buckets SET reserved_micro = v_plan.proposed_value, updated_at = v_now, version = version + 1
     WHERE endpoint_id = v_plan.endpoint_id AND operation = v_plan.bucket_operation RETURNING version INTO v_new_ver;
    v_target_id := v_plan.endpoint_id;

  ELSIF v_plan.reservation_kind = 'producer_rate_bucket' THEN
    SELECT version, reserved_micro INTO v_cur_ver, v_cur_val
      FROM rq.producer_rate_buckets WHERE producer_id = v_plan.producer_id AND operation = v_plan.bucket_operation FOR UPDATE;
    IF v_cur_ver <> v_plan.expected_resource_version OR v_cur_val <> v_plan.expected_stored_value THEN
      RAISE EXCEPTION 'Rate bucket stored reservation conflict' USING ERRCODE = '40001';
    END IF;
    UPDATE rq.producer_rate_buckets SET reserved_micro = v_plan.proposed_value, updated_at = v_now, version = version + 1
     WHERE producer_id = v_plan.producer_id AND operation = v_plan.bucket_operation RETURNING version INTO v_new_ver;
    v_target_id := v_plan.producer_id;
  END IF;

  UPDATE rq_recovery.reviews SET state = 'consumed' WHERE id = (v_ctx.out_review).id;
  UPDATE rq_recovery.actions SET state = 'applied', updated_at = v_now, version = version + 1 WHERE id = p_action_id;
  UPDATE rq_recovery.execution_attempts SET outcome = 'applied', finished_at = v_now, version = version + 1 WHERE id = v_ctx.out_exec_attempt_id;

  v_res_facts := pg_catalog.jsonb_build_object(
    'action_kind', 'reconcile_reservations',
    'reservation_kind', v_plan.reservation_kind,
    'target_id', v_target_id,
    'prior_value', v_plan.expected_stored_value,
    'proposed_value', v_plan.proposed_value,
    'conservative_policy', v_plan.conservative_policy,
    'new_target_version', v_new_ver
  );
  v_res_sha := pg_catalog.sha256(pg_catalog.convert_to(v_res_facts::text, 'UTF8'));

  INSERT INTO rq_recovery.action_results (
    action_id, operation_id, execution_attempt_id, outcome,
    proposed_facts_sha256, resulting_facts_sha256, new_target_version, safe_result_facts, recorded_at
  ) VALUES (
    p_action_id, (v_ctx.out_op).id, v_ctx.out_exec_attempt_id, 'applied',
    (v_ctx.out_action).proposed_facts_sha256, v_res_sha, v_new_ver, v_res_facts, v_now
  );

  INSERT INTO rq.audit_events (
    id, tenant_id, project_id, actor_kind, operator_reference, action, target_kind, target_id,
    prior_version, resulting_version, candidate_sha256, recorded_at, safe_facts
  ) VALUES (
    pg_catalog.gen_random_uuid(), v_plan.tenant_id, v_plan.project_id, 'operator', p_operator_reference,
    'recovery.reconcile_reservations', v_plan.reservation_kind, v_target_id,
    v_plan.expected_resource_version, v_new_ver, v_res_sha, v_now, v_res_facts
  );

  RETURN pg_catalog.jsonb_build_object(
    'outcome', 'applied',
    'operation_id', (v_ctx.out_op).id,
    'action_id', p_action_id,
    'new_target_version', v_new_ver,
    'resulting_facts_sha256', pg_catalog.encode(v_res_sha, 'hex'),
    'safe_result_facts', v_res_facts
  );
END;
$$;

CREATE OR REPLACE FUNCTION rq_recovery.cmd_continue_publication_episode(
  p_action_id uuid,
  p_operator_reference text,
  p_execution_nonce_digest bytea,
  p_target_database_identity_digest bytea
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  v_ctx record;
  v_plan rq_recovery.action_continue_publication_episodes%ROWTYPE;
  v_inst rq.installation_state%ROWTYPE;
  v_ep rq.publication_recovery_episodes%ROWTYPE;
  v_outbox rq.outbox_events%ROWTYPE;
  v_fanout rq.event_fanout%ROWTYPE;
  v_now timestamptz := pg_catalog.clock_timestamp();
  v_new_ep_id uuid;
  v_outcome text := 'applied';
  v_next_pub_at timestamptz;
  v_res_facts jsonb;
  v_res_sha bytea;
BEGIN
  PERFORM rq._assert_session_role(ARRAY['rq_recovery']);

  SELECT * INTO v_ctx FROM rq_recovery._verify_review_and_record_attempt(
    p_action_id, 'continue_publication_episode', p_operator_reference, p_execution_nonce_digest, p_target_database_identity_digest
  );
  IF v_ctx.out_already_done THEN
    RETURN v_ctx.out_existing_result;
  END IF;

  SELECT * INTO v_plan FROM rq_recovery.action_continue_publication_episodes WHERE action_id = p_action_id FOR SHARE;
  SELECT * INTO v_inst FROM rq.installation_state WHERE id = 1 FOR SHARE;

  IF v_inst.control_epoch <> (v_ctx.out_action).expected_control_epoch THEN
    RAISE EXCEPTION 'Target epoch precondition mismatch' USING ERRCODE = '40001';
  END IF;

  SELECT * INTO v_ep FROM rq.publication_recovery_episodes WHERE id = v_plan.episode_id FOR UPDATE;
  SELECT * INTO v_outbox FROM rq.outbox_events WHERE id = v_plan.outbox_id FOR UPDATE;
  SELECT * INTO v_fanout FROM rq.event_fanout WHERE event_id = v_plan.event_id FOR UPDATE;

  IF v_fanout.state = 'completed' THEN
    -- Nonmutating already_complete when canonical fanout completed after planning
    v_outcome := 'already_complete';
    UPDATE rq_recovery.reviews SET state = 'consumed' WHERE id = (v_ctx.out_review).id;
    UPDATE rq_recovery.actions SET state = 'applied', updated_at = v_now, version = version + 1 WHERE id = p_action_id;
    UPDATE rq_recovery.execution_attempts SET outcome = 'already_complete', finished_at = v_now, version = version + 1 WHERE id = v_ctx.out_exec_attempt_id;

    v_res_facts := pg_catalog.jsonb_build_object(
      'action_kind', 'continue_publication_episode',
      'event_id', v_plan.event_id,
      'outbox_id', v_plan.outbox_id,
      'fanout_state', 'completed',
      'new_episode_id', NULL
    );
    v_res_sha := pg_catalog.sha256(pg_catalog.convert_to(v_res_facts::text, 'UTF8'));

    INSERT INTO rq_recovery.action_results (
      action_id, operation_id, execution_attempt_id, outcome,
      proposed_facts_sha256, resulting_facts_sha256, new_target_version, safe_result_facts, recorded_at
    ) VALUES (
      p_action_id, (v_ctx.out_op).id, v_ctx.out_exec_attempt_id, 'already_complete',
      (v_ctx.out_action).proposed_facts_sha256, v_res_sha, v_outbox.version, v_res_facts, v_now
    );

    RETURN pg_catalog.jsonb_build_object(
      'outcome', 'already_complete',
      'operation_id', (v_ctx.out_op).id,
      'action_id', p_action_id,
      'new_target_version', v_outbox.version,
      'resulting_facts_sha256', pg_catalog.encode(v_res_sha, 'hex'),
      'safe_result_facts', v_res_facts
    );
  END IF;

  IF v_ep.state <> 'review_required'
     OR v_ep.version <> v_plan.expected_episode_version
     OR v_outbox.version <> v_plan.expected_outbox_version
     OR v_outbox.current_publication_generation <> v_plan.expected_publication_generation THEN
    RAISE EXCEPTION 'Publication episode or outbox version precondition mismatch' USING ERRCODE = '40001';
  END IF;

  IF v_fanout.claim_owner_instance_id IS NOT NULL AND v_fanout.claim_expires_at > v_now THEN
    RAISE EXCEPTION 'Cannot continue episode while valid active fanout claim is progressing' USING ERRCODE = '55000';
  END IF;

  -- Close/revoke reviewed old episode while retaining all history
  UPDATE rq.publication_recovery_episodes
     SET state = 'revoked',
         review_reference = p_action_id,
         version = version + 1
   WHERE id = v_ep.id;

  v_new_ep_id := pg_catalog.gen_random_uuid();
  INSERT INTO rq.publication_recovery_episodes (
    id, outbox_id, event_id, control_epoch, state, starting_fanout_version,
    last_progress_boundary_sha256, successive_no_progress_generations,
    last_generation_at, review_reference, created_at, version
  ) VALUES (
    v_new_ep_id, v_outbox.id, v_outbox.event_id, v_inst.control_epoch, 'active',
    v_fanout.version, v_plan.no_progress_boundary_sha256, 0,
    NULL, p_action_id, v_now, 1
  );

  v_next_pub_at := CASE
    WHEN v_ep.last_generation_at IS NOT NULL THEN GREATEST(v_now, v_ep.last_generation_at + interval '60 seconds')
    ELSE v_now
  END;

  IF v_plan.schedule_next_notification THEN
    UPDATE rq.outbox_events
       SET state = 'pending',
           claim_owner_instance_id = NULL,
           claim_control_epoch = NULL,
           claim_expires_at = NULL,
           next_publish_at = v_next_pub_at,
           last_safe_error_code = NULL,
           updated_at = v_now,
           version = version + 1
     WHERE id = v_outbox.id
     RETURNING * INTO v_outbox;
  END IF;

  UPDATE rq_recovery.reviews SET state = 'consumed' WHERE id = (v_ctx.out_review).id;
  UPDATE rq_recovery.actions SET state = 'applied', updated_at = v_now, version = version + 1 WHERE id = p_action_id;
  UPDATE rq_recovery.execution_attempts SET outcome = 'applied', finished_at = v_now, version = version + 1 WHERE id = v_ctx.out_exec_attempt_id;

  v_res_facts := pg_catalog.jsonb_build_object(
    'action_kind', 'continue_publication_episode',
    'revoked_episode_id', v_ep.id,
    'new_episode_id', v_new_ep_id,
    'outbox_id', v_outbox.id,
    'publication_generation', v_outbox.current_publication_generation,
    'next_publish_at', v_outbox.next_publish_at
  );
  v_res_sha := pg_catalog.sha256(pg_catalog.convert_to(v_res_facts::text, 'UTF8'));

  INSERT INTO rq_recovery.action_results (
    action_id, operation_id, execution_attempt_id, outcome,
    proposed_facts_sha256, resulting_facts_sha256, new_target_version, safe_result_facts, recorded_at
  ) VALUES (
    p_action_id, (v_ctx.out_op).id, v_ctx.out_exec_attempt_id, 'applied',
    (v_ctx.out_action).proposed_facts_sha256, v_res_sha, v_outbox.version, v_res_facts, v_now
  );

  INSERT INTO rq.audit_events (
    id, tenant_id, project_id, actor_kind, operator_reference, action, target_kind, target_id,
    prior_version, resulting_version, candidate_sha256, recorded_at, safe_facts
  ) VALUES (
    pg_catalog.gen_random_uuid(), v_plan.tenant_id, v_plan.project_id, 'operator', p_operator_reference,
    'recovery.continue_publication_episode', 'publication_recovery_episode', v_new_ep_id,
    v_plan.expected_outbox_version, v_outbox.version, v_res_sha, v_now, v_res_facts
  );

  RETURN pg_catalog.jsonb_build_object(
    'outcome', 'applied',
    'operation_id', (v_ctx.out_op).id,
    'action_id', p_action_id,
    'new_target_version', v_outbox.version,
    'resulting_facts_sha256', pg_catalog.encode(v_res_sha, 'hex'),
    'safe_result_facts', v_res_facts
  );
END;
$$;

CREATE OR REPLACE FUNCTION rq_recovery.cmd_record_receiver_comparison(
  p_action_id uuid,
  p_operator_reference text,
  p_execution_nonce_digest bytea,
  p_target_database_identity_digest bytea
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  v_ctx record;
  v_plan rq_recovery.action_record_receiver_comparisons%ROWTYPE;
  v_inst rq.installation_state%ROWTYPE;
  v_del rq.deliveries%ROWTYPE;
  v_now timestamptz := pg_catalog.clock_timestamp();
  v_rec_id uuid;
  v_res_facts jsonb;
  v_res_sha bytea;
BEGIN
  PERFORM rq._assert_session_role(ARRAY['rq_recovery']);

  SELECT * INTO v_ctx FROM rq_recovery._verify_review_and_record_attempt(
    p_action_id, 'record_receiver_comparison', p_operator_reference, p_execution_nonce_digest, p_target_database_identity_digest
  );
  IF v_ctx.out_already_done THEN
    RETURN v_ctx.out_existing_result;
  END IF;

  SELECT * INTO v_plan FROM rq_recovery.action_record_receiver_comparisons WHERE action_id = p_action_id FOR SHARE;
  SELECT * INTO v_inst FROM rq.installation_state WHERE id = 1 FOR SHARE;

  IF v_inst.control_epoch <> (v_ctx.out_action).expected_control_epoch THEN
    RAISE EXCEPTION 'Target epoch precondition mismatch' USING ERRCODE = '40001';
  END IF;

  SELECT * INTO v_del FROM rq.deliveries WHERE id = v_plan.delivery_id FOR SHARE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'Delivery not found for comparison' USING ERRCODE = 'P0002';
  END IF;

  v_rec_id := pg_catalog.gen_random_uuid();
  INSERT INTO rq_recovery.receiver_comparison_records (
    id, action_id, tenant_id, project_id, delivery_id, event_id,
    consumer_contract_scope, consumer_event_key_sha256, original_facts_sha256,
    comparison_outcome, source_kind, source_reference, observed_at,
    diagnostic_evidence_digest, receiver_facts_sha256, requires_hold_investigation,
    recorded_by_operator_reference, recorded_at
  ) VALUES (
    v_rec_id, p_action_id, v_plan.tenant_id, v_plan.project_id, v_plan.delivery_id, v_plan.event_id,
    v_plan.consumer_contract_scope, v_plan.consumer_event_key_sha256, v_plan.original_facts_sha256,
    v_plan.comparison_outcome, v_plan.source_kind, v_plan.source_reference, v_plan.observed_at,
    v_plan.diagnostic_evidence_digest, v_plan.receiver_facts_sha256, v_plan.requires_hold_investigation,
    p_operator_reference, v_now
  );

  -- Append provenance only; never fabricate HTTP acknowledgement or modify canonical delivery state
  UPDATE rq_recovery.reviews SET state = 'consumed' WHERE id = (v_ctx.out_review).id;
  UPDATE rq_recovery.actions SET state = 'applied', updated_at = v_now, version = version + 1 WHERE id = p_action_id;
  UPDATE rq_recovery.execution_attempts SET outcome = 'applied', finished_at = v_now, version = version + 1 WHERE id = v_ctx.out_exec_attempt_id;

  v_res_facts := pg_catalog.jsonb_build_object(
    'action_kind', 'record_receiver_comparison',
    'comparison_record_id', v_rec_id,
    'delivery_id', v_plan.delivery_id,
    'comparison_outcome', v_plan.comparison_outcome,
    'source_kind', v_plan.source_kind,
    'requires_hold_investigation', v_plan.requires_hold_investigation
  );
  v_res_sha := pg_catalog.sha256(pg_catalog.convert_to(v_res_facts::text, 'UTF8'));

  INSERT INTO rq_recovery.action_results (
    action_id, operation_id, execution_attempt_id, outcome,
    proposed_facts_sha256, resulting_facts_sha256, new_target_version, safe_result_facts, recorded_at
  ) VALUES (
    p_action_id, (v_ctx.out_op).id, v_ctx.out_exec_attempt_id, 'applied',
    (v_ctx.out_action).proposed_facts_sha256, v_res_sha, v_del.version, v_res_facts, v_now
  );

  INSERT INTO rq.audit_events (
    id, tenant_id, project_id, actor_kind, operator_reference, action, target_kind, target_id,
    prior_version, resulting_version, candidate_sha256, recorded_at, safe_facts
  ) VALUES (
    pg_catalog.gen_random_uuid(), v_plan.tenant_id, v_plan.project_id, 'operator', p_operator_reference,
    'recovery.record_receiver_comparison', 'receiver_comparison_record', v_rec_id,
    v_del.version, v_del.version, v_res_sha, v_now, v_res_facts
  );

  RETURN pg_catalog.jsonb_build_object(
    'outcome', 'applied',
    'operation_id', (v_ctx.out_op).id,
    'action_id', p_action_id,
    'new_target_version', v_del.version,
    'resulting_facts_sha256', pg_catalog.encode(v_res_sha, 'hex'),
    'safe_result_facts', v_res_facts
  );
END;
$$;

CREATE OR REPLACE FUNCTION rq_recovery.cmd_set_recovery_gate(
  p_action_id uuid,
  p_operator_reference text,
  p_execution_nonce_digest bytea,
  p_target_database_identity_digest bytea
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  v_ctx record;
  v_plan rq_recovery.action_set_recovery_gates%ROWTYPE;
  v_inst rq.installation_state%ROWTYPE;
  v_tenant rq.tenants%ROWTYPE;
  v_project rq.projects%ROWTYPE;
  v_now timestamptz := pg_catalog.clock_timestamp();
  v_new_ver bigint;
  v_target_id uuid;
  v_res_facts jsonb;
  v_res_sha bytea;
BEGIN
  PERFORM rq._assert_session_role(ARRAY['rq_recovery']);

  SELECT * INTO v_ctx FROM rq_recovery._verify_review_and_record_attempt(
    p_action_id, 'set_recovery_gate', p_operator_reference, p_execution_nonce_digest, p_target_database_identity_digest
  );
  IF v_ctx.out_already_done THEN
    RETURN v_ctx.out_existing_result;
  END IF;

  SELECT * INTO v_plan FROM rq_recovery.action_set_recovery_gates WHERE action_id = p_action_id FOR SHARE;
  SELECT * INTO v_inst FROM rq.installation_state WHERE id = 1 FOR UPDATE;

  IF v_inst.control_epoch <> (v_ctx.out_action).expected_control_epoch THEN
    RAISE EXCEPTION 'Target epoch precondition mismatch' USING ERRCODE = '40001';
  END IF;

  IF v_plan.target_scope_kind = 'installation' THEN
    IF v_inst.version <> v_plan.expected_target_version THEN
      RAISE EXCEPTION 'Installation version precondition conflict' USING ERRCODE = '40001';
    END IF;
    UPDATE rq.installation_state
       SET mode = COALESCE(v_plan.proposed_installation_mode, mode),
           allow_event_admission = COALESCE(v_plan.proposed_allow_event_admission, allow_event_admission),
           allow_publication = COALESCE(v_plan.proposed_allow_publication, allow_publication),
           allow_fanout = COALESCE(v_plan.proposed_allow_fanout, allow_fanout),
           allow_send = COALESCE(v_plan.proposed_allow_send, allow_send),
           allow_endpoint_verification = COALESCE(v_plan.proposed_allow_endpoint_verification, allow_endpoint_verification),
           governance_version = governance_version + 1,
           updated_at = v_now,
           version = version + 1
     WHERE id = 1
     RETURNING * INTO v_inst;
    v_new_ver := v_inst.version;
    v_target_id := v_inst.control_epoch;

  ELSIF v_plan.target_scope_kind = 'tenant' THEN
    SELECT * INTO v_tenant FROM rq.tenants WHERE id = v_plan.tenant_id FOR UPDATE;
    IF v_tenant.version <> v_plan.expected_target_version THEN
      RAISE EXCEPTION 'Tenant version precondition conflict' USING ERRCODE = '40001';
    END IF;
    UPDATE rq.tenants
       SET state = v_plan.proposed_tenant_state,
           governance_version = governance_version + 1,
           updated_at = v_now,
           version = version + 1
     WHERE id = v_plan.tenant_id
     RETURNING version INTO v_new_ver;
    v_target_id := v_plan.tenant_id;

  ELSIF v_plan.target_scope_kind = 'project' THEN
    SELECT * INTO v_project FROM rq.projects WHERE id = v_plan.project_id AND tenant_id = v_plan.tenant_id FOR UPDATE;
    IF v_project.version <> v_plan.expected_target_version THEN
      RAISE EXCEPTION 'Project version precondition conflict' USING ERRCODE = '40001';
    END IF;
    UPDATE rq.projects
       SET state = v_plan.proposed_project_state,
           governance_version = governance_version + 1,
           updated_at = v_now,
           version = version + 1
     WHERE id = v_plan.project_id AND tenant_id = v_plan.tenant_id
     RETURNING version INTO v_new_ver;
    v_target_id := v_plan.project_id;
  END IF;

  UPDATE rq_recovery.reviews SET state = 'consumed' WHERE id = (v_ctx.out_review).id;
  UPDATE rq_recovery.actions SET state = 'applied', updated_at = v_now, version = version + 1 WHERE id = p_action_id;
  UPDATE rq_recovery.execution_attempts SET outcome = 'applied', finished_at = v_now, version = version + 1 WHERE id = v_ctx.out_exec_attempt_id;

  v_res_facts := pg_catalog.jsonb_build_object(
    'action_kind', 'set_recovery_gate',
    'target_scope_kind', v_plan.target_scope_kind,
    'target_id', v_target_id,
    'new_target_version', v_new_ver,
    'retained_hold_refs', v_plan.retained_hold_refs
  );
  v_res_sha := pg_catalog.sha256(pg_catalog.convert_to(v_res_facts::text, 'UTF8'));

  INSERT INTO rq_recovery.action_results (
    action_id, operation_id, execution_attempt_id, outcome,
    proposed_facts_sha256, resulting_facts_sha256, new_target_version, safe_result_facts, recorded_at
  ) VALUES (
    p_action_id, (v_ctx.out_op).id, v_ctx.out_exec_attempt_id, 'applied',
    (v_ctx.out_action).proposed_facts_sha256, v_res_sha, v_new_ver, v_res_facts, v_now
  );

  INSERT INTO rq.audit_events (
    id, tenant_id, project_id, actor_kind, operator_reference, action, target_kind, target_id,
    prior_version, resulting_version, candidate_sha256, recorded_at, safe_facts
  ) VALUES (
    pg_catalog.gen_random_uuid(), v_plan.tenant_id, v_plan.project_id, 'operator', p_operator_reference,
    'recovery.set_recovery_gate', v_plan.target_scope_kind, v_target_id,
    v_plan.expected_target_version, v_new_ver, v_res_sha, v_now, v_res_facts
  );

  RETURN pg_catalog.jsonb_build_object(
    'outcome', 'applied',
    'operation_id', (v_ctx.out_op).id,
    'action_id', p_action_id,
    'new_target_version', v_new_ver,
    'resulting_facts_sha256', pg_catalog.encode(v_res_sha, 'hex'),
    'safe_result_facts', v_res_facts
  );
END;
$$;

CREATE OR REPLACE FUNCTION rq_recovery.cmd_project_maintenance_acquire(
  p_operation_id uuid,
  p_tenant_id uuid,
  p_project_id uuid,
  p_expected_project_version bigint,
  p_operator_reference text
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  v_project rq.projects%ROWTYPE;
  v_now timestamptz := pg_catalog.clock_timestamp();
BEGIN
  PERFORM rq._assert_session_role(ARRAY['rq_recovery']);

  PERFORM 1 FROM rq_recovery.operations WHERE id = p_operation_id FOR SHARE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'Maintenance operation not found' USING ERRCODE = 'P0002';
  END IF;

  SELECT * INTO v_project FROM rq.projects WHERE id = p_project_id AND tenant_id = p_tenant_id FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'Project not found' USING ERRCODE = 'P0002';
  END IF;

  IF v_project.projection_maintenance_operation_id = p_operation_id THEN
    RETURN pg_catalog.jsonb_build_object(
      'outcome', 'idempotent',
      'project_id', v_project.id,
      'maintenance_version', v_project.projection_maintenance_version,
      'project_version', v_project.version
    );
  END IF;

  IF v_project.projection_maintenance_operation_id IS NOT NULL OR v_project.version <> p_expected_project_version THEN
    RAISE EXCEPTION 'Project already held by another maintenance operation or version mismatch' USING ERRCODE = '40001';
  END IF;

  UPDATE rq.projects
     SET projection_maintenance_operation_id = p_operation_id,
         projection_maintenance_version = projection_maintenance_version + 1,
         updated_at = v_now,
         version = version + 1
   WHERE id = p_project_id AND tenant_id = p_tenant_id
   RETURNING * INTO v_project;

  INSERT INTO rq.audit_events (
    id, tenant_id, project_id, actor_kind, operator_reference, action, target_kind, target_id,
    prior_version, resulting_version, recorded_at, safe_facts
  ) VALUES (
    pg_catalog.gen_random_uuid(), p_tenant_id, p_project_id, 'operator', p_operator_reference,
    'recovery.project_maintenance.acquire', 'project', p_project_id,
    p_expected_project_version, v_project.version, v_now,
    pg_catalog.jsonb_build_object('operation_id', p_operation_id, 'maintenance_version', v_project.projection_maintenance_version)
  );

  RETURN pg_catalog.jsonb_build_object(
    'outcome', 'acquired',
    'project_id', v_project.id,
    'maintenance_version', v_project.projection_maintenance_version,
    'project_version', v_project.version
  );
END;
$$;

CREATE OR REPLACE FUNCTION rq_recovery.cmd_project_maintenance_release(
  p_operation_id uuid,
  p_tenant_id uuid,
  p_project_id uuid,
  p_expected_maintenance_version bigint,
  p_operator_reference text
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  v_project rq.projects%ROWTYPE;
  v_now timestamptz := pg_catalog.clock_timestamp();
BEGIN
  PERFORM rq._assert_session_role(ARRAY['rq_recovery']);

  SELECT * INTO v_project FROM rq.projects WHERE id = p_project_id AND tenant_id = p_tenant_id FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'Project not found' USING ERRCODE = 'P0002';
  END IF;

  IF v_project.projection_maintenance_operation_id IS NULL THEN
    RETURN pg_catalog.jsonb_build_object(
      'outcome', 'already_released',
      'project_id', v_project.id,
      'maintenance_version', v_project.projection_maintenance_version,
      'project_version', v_project.version
    );
  END IF;

  IF v_project.projection_maintenance_operation_id IS DISTINCT FROM p_operation_id
     OR v_project.projection_maintenance_version <> p_expected_maintenance_version THEN
    RAISE EXCEPTION 'Only the owning maintenance operation and expected version may release the gate' USING ERRCODE = '40001';
  END IF;

  UPDATE rq.projects
     SET projection_maintenance_operation_id = NULL,
         projection_maintenance_version = projection_maintenance_version + 1,
         updated_at = v_now,
         version = version + 1
   WHERE id = p_project_id AND tenant_id = p_tenant_id
   RETURNING * INTO v_project;

  INSERT INTO rq.audit_events (
    id, tenant_id, project_id, actor_kind, operator_reference, action, target_kind, target_id,
    prior_version, resulting_version, recorded_at, safe_facts
  ) VALUES (
    pg_catalog.gen_random_uuid(), p_tenant_id, p_project_id, 'operator', p_operator_reference,
    'recovery.project_maintenance.release', 'project', p_project_id,
    v_project.version - 1, v_project.version, v_now,
    pg_catalog.jsonb_build_object('operation_id', p_operation_id, 'maintenance_version', v_project.projection_maintenance_version)
  );

  RETURN pg_catalog.jsonb_build_object(
    'outcome', 'released',
    'project_id', v_project.id,
    'maintenance_version', v_project.projection_maintenance_version,
    'project_version', v_project.version
  );
END;
$$;

CREATE OR REPLACE FUNCTION rq_recovery.cmd_rebuild_projection(
  p_action_id uuid,
  p_operator_reference text,
  p_execution_nonce_digest bytea,
  p_target_database_identity_digest bytea
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  v_ctx record;
  v_plan rq_recovery.action_rebuild_projections%ROWTYPE;
  v_inst rq.installation_state%ROWTYPE;
  v_project rq.projects%ROWTYPE;
  v_event rq.events%ROWTYPE;
  v_edtot rq.event_delivery_totals%ROWTYPE;
  v_pdtot rq.project_delivery_totals%ROWTYPE;
  v_now timestamptz := pg_catalog.clock_timestamp();
  v_src_total bigint;
  v_src_pending bigint;
  v_src_active bigint;
  v_src_ack bigint;
  v_src_dlq bigint;
  v_src_sup bigint;
  v_src_exp bigint;
  v_src_term bigint;
  v_src_unk bigint;
  v_new_ver bigint;
  v_res_facts jsonb;
  v_res_sha bytea;
BEGIN
  PERFORM rq._assert_session_role(ARRAY['rq_recovery']);

  SELECT * INTO v_ctx FROM rq_recovery._verify_review_and_record_attempt(
    p_action_id, 'rebuild_projection', p_operator_reference, p_execution_nonce_digest, p_target_database_identity_digest
  );
  IF v_ctx.out_already_done THEN
    RETURN v_ctx.out_existing_result;
  END IF;

  SELECT * INTO v_plan FROM rq_recovery.action_rebuild_projections WHERE action_id = p_action_id FOR SHARE;
  SELECT * INTO v_inst FROM rq.installation_state WHERE id = 1 FOR SHARE;

  IF v_inst.control_epoch <> (v_ctx.out_action).expected_control_epoch THEN
    RAISE EXCEPTION 'Target epoch precondition mismatch' USING ERRCODE = '40001';
  END IF;

  IF v_plan.projection_kind = 'event_delivery_totals' THEN
    SELECT * INTO v_project FROM rq.projects WHERE id = v_plan.project_id AND tenant_id = v_plan.tenant_id FOR SHARE;
    SELECT * INTO v_event FROM rq.events WHERE id = v_plan.event_id AND project_id = v_plan.project_id AND tenant_id = v_plan.tenant_id FOR UPDATE;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'Target event not found for projection rebuild' USING ERRCODE = 'P0002';
    END IF;

    SELECT * INTO v_edtot FROM rq.event_delivery_totals WHERE event_id = v_plan.event_id FOR UPDATE;
    IF NOT FOUND OR v_edtot.version <> v_plan.expected_projection_version THEN
      RAISE EXCEPTION 'Event projection version precondition conflict' USING ERRCODE = '40001';
    END IF;

    PERFORM 1 FROM rq.event_delivery_total_deltas WHERE event_id = v_plan.event_id FOR UPDATE;

    SELECT
      pg_catalog.count(*)::bigint,
      pg_catalog.count(*) FILTER (WHERE d.state IN ('acknowledged', 'dead_letter', 'suppressed', 'expired'))::bigint,
      pg_catalog.count(*) FILTER (WHERE d.state = 'acknowledged')::bigint
      INTO v_src_total, v_src_term, v_src_ack
      FROM rq.deliveries d
     WHERE d.event_id = v_plan.event_id
       AND d.project_id = v_plan.project_id
       AND d.tenant_id = v_plan.tenant_id;

    IF v_src_total > v_plan.max_source_rows THEN
      RAISE EXCEPTION 'Rebuild source count exceeds bounded baseline limit' USING ERRCODE = '54000';
    END IF;
    IF v_src_total <> v_plan.proposed_total_deliveries
       OR v_src_term <> v_plan.proposed_terminal_deliveries
       OR v_src_ack <> v_plan.proposed_acknowledged_count THEN
      RAISE EXCEPTION 'Event rebuild proposed counts do not match canonical deliveries snapshot' USING ERRCODE = '40001';
    END IF;

    UPDATE rq.event_delivery_total_deltas
       SET total_deliveries_delta = 0,
           terminal_deliveries_delta = 0,
           acknowledged_deliveries_delta = 0,
           updated_at = v_now,
           version = version + 1
     WHERE event_id = v_plan.event_id;

    UPDATE rq.event_delivery_totals
       SET total_deliveries = v_src_total,
           terminal_deliveries = v_src_term,
           acknowledged_deliveries = v_src_ack,
           updated_at = v_now,
           version = version + 1
     WHERE event_id = v_plan.event_id
     RETURNING version INTO v_new_ver;

    INSERT INTO rq.event_history (
      event_id, event_sequence, tenant_id, project_id, event_kind, event_schema_version, recorded_at, safe_facts
    ) VALUES (
      v_plan.event_id, pg_catalog.nextval('rq.event_history_seq'), v_plan.tenant_id, v_plan.project_id,
      'event.delivery_aggregate_changed', 1, v_now,
      pg_catalog.jsonb_build_object(
        'repaired_by_action_id', p_action_id,
        'projection_version', v_new_ver,
        'total_deliveries', v_src_total,
        'terminal_deliveries', v_src_term,
        'acknowledged_deliveries', v_src_ack
      )
    );

  ELSE
    -- project_delivery_totals rebuild requires active project maintenance gate owned by this operation
    SELECT * INTO v_project FROM rq.projects WHERE id = v_plan.project_id AND tenant_id = v_plan.tenant_id FOR UPDATE;
    IF NOT FOUND OR v_project.projection_maintenance_operation_id IS DISTINCT FROM (v_ctx.out_op).id THEN
      RAISE EXCEPTION 'Project projection rebuild requires matching active projection maintenance gate' USING ERRCODE = '55000';
    END IF;

    SELECT * INTO v_pdtot FROM rq.project_delivery_totals WHERE project_id = v_plan.project_id FOR UPDATE;
    IF NOT FOUND OR v_pdtot.version <> v_plan.expected_projection_version THEN
      RAISE EXCEPTION 'Project projection version precondition conflict' USING ERRCODE = '40001';
    END IF;

    PERFORM 1 FROM rq.project_delivery_total_deltas WHERE project_id = v_plan.project_id FOR UPDATE;

    SELECT
      pg_catalog.count(*)::bigint,
      pg_catalog.count(*) FILTER (WHERE d.state IN ('pending', 'ready', 'retry_wait'))::bigint,
      pg_catalog.count(*) FILTER (WHERE d.state = 'sending')::bigint,
      pg_catalog.count(*) FILTER (WHERE d.state = 'acknowledged')::bigint,
      pg_catalog.count(*) FILTER (WHERE d.state = 'dead_letter')::bigint,
      pg_catalog.count(*) FILTER (WHERE d.state = 'suppressed')::bigint,
      pg_catalog.count(*) FILTER (WHERE d.state = 'expired')::bigint
      INTO v_src_total, v_src_pending, v_src_active, v_src_ack, v_src_dlq, v_src_sup, v_src_exp
      FROM rq.deliveries d
     WHERE d.project_id = v_plan.project_id
       AND d.tenant_id = v_plan.tenant_id;

    SELECT pg_catalog.count(*)::bigint
      INTO v_src_unk
      FROM rq.delivery_attempts a
     WHERE a.project_id = v_plan.project_id
       AND a.tenant_id = v_plan.tenant_id
       AND a.state IN ('transport_unknown', 'abandoned');

    IF v_src_total > v_plan.max_source_rows THEN
      RAISE EXCEPTION 'Rebuild source count exceeds bounded baseline limit' USING ERRCODE = '54000';
    END IF;
    IF v_src_total <> v_plan.proposed_total_deliveries
       OR v_src_pending <> v_plan.proposed_pending_count
       OR v_src_active <> v_plan.proposed_active_count
       OR v_src_ack <> v_plan.proposed_acknowledged_count
       OR v_src_dlq <> v_plan.proposed_dead_letter_count
       OR v_src_sup <> v_plan.proposed_suppressed_count
       OR v_src_exp <> v_plan.proposed_expired_count
       OR v_src_unk <> v_plan.proposed_unknown_attempt_observations THEN
      RAISE EXCEPTION 'Project rebuild proposed counts do not match canonical deliveries snapshot' USING ERRCODE = '40001';
    END IF;

    UPDATE rq.project_delivery_total_deltas
       SET total_deliveries_delta = 0,
           pending_delta = 0,
           active_delta = 0,
           acknowledged_delta = 0,
           dead_letter_delta = 0,
           suppressed_delta = 0,
           expired_delta = 0,
           unknown_attempt_observations_delta = 0,
           updated_at = v_now,
           version = version + 1
     WHERE project_id = v_plan.project_id;

    UPDATE rq.project_delivery_totals
       SET total_deliveries = v_src_total,
           pending_count = v_src_pending,
           active_count = v_src_active,
           acknowledged_count = v_src_ack,
           dead_letter_count = v_src_dlq,
           suppressed_count = v_src_sup,
           expired_count = v_src_exp,
           unknown_attempt_observations = v_src_unk,
           source_boundary_sha256 = v_plan.expected_source_boundary_sha256,
           updated_at = v_now,
           version = version + 1
     WHERE project_id = v_plan.project_id
     RETURNING version INTO v_new_ver;
  END IF;

  UPDATE rq_recovery.reviews SET state = 'consumed' WHERE id = (v_ctx.out_review).id;
  UPDATE rq_recovery.actions SET state = 'applied', updated_at = v_now, version = version + 1 WHERE id = p_action_id;
  UPDATE rq_recovery.execution_attempts SET outcome = 'applied', finished_at = v_now, version = version + 1 WHERE id = v_ctx.out_exec_attempt_id;

  v_res_facts := pg_catalog.jsonb_build_object(
    'action_kind', 'rebuild_projection',
    'projection_kind', v_plan.projection_kind,
    'project_id', v_plan.project_id,
    'event_id', v_plan.event_id,
    'new_target_version', v_new_ver,
    'total_deliveries', v_src_total,
    'acknowledged_count', v_src_ack
  );
  v_res_sha := pg_catalog.sha256(pg_catalog.convert_to(v_res_facts::text, 'UTF8'));

  INSERT INTO rq_recovery.action_results (
    action_id, operation_id, execution_attempt_id, outcome,
    proposed_facts_sha256, resulting_facts_sha256, new_target_version, safe_result_facts, recorded_at
  ) VALUES (
    p_action_id, (v_ctx.out_op).id, v_ctx.out_exec_attempt_id, 'applied',
    (v_ctx.out_action).proposed_facts_sha256, v_res_sha, v_new_ver, v_res_facts, v_now
  );

  INSERT INTO rq.audit_events (
    id, tenant_id, project_id, actor_kind, operator_reference, action, target_kind, target_id,
    prior_version, resulting_version, candidate_sha256, recorded_at, safe_facts
  ) VALUES (
    pg_catalog.gen_random_uuid(), v_plan.tenant_id, v_plan.project_id, 'operator', p_operator_reference,
    'recovery.rebuild_projection', v_plan.projection_kind, COALESCE(v_plan.event_id, v_plan.project_id),
    v_plan.expected_projection_version, v_new_ver, v_res_sha, v_now, v_res_facts
  );

  RETURN pg_catalog.jsonb_build_object(
    'outcome', 'applied',
    'operation_id', (v_ctx.out_op).id,
    'action_id', p_action_id,
    'new_target_version', v_new_ver,
    'resulting_facts_sha256', pg_catalog.encode(v_res_sha, 'hex'),
    'safe_result_facts', v_res_facts
  );
END;
$$;

-- 7. Bounded read-only recovery inspections
CREATE OR REPLACE FUNCTION rq_recovery.read_operation_result(p_action_id uuid)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  v_action rq_recovery.actions%ROWTYPE;
  v_res rq_recovery.action_results%ROWTYPE;
  v_last_exec rq_recovery.execution_attempts%ROWTYPE;
BEGIN
  PERFORM rq._assert_session_role(ARRAY['rq_recovery']);

  SELECT * INTO v_action FROM rq_recovery.actions WHERE id = p_action_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'Recovery action not found' USING ERRCODE = 'P0002';
  END IF;

  SELECT * INTO v_res FROM rq_recovery.action_results WHERE action_id = p_action_id;
  IF FOUND THEN
    RETURN pg_catalog.jsonb_build_object(
      'status', 'completed',
      'outcome', v_res.outcome,
      'operation_id', v_res.operation_id,
      'action_id', v_res.action_id,
      'new_target_version', v_res.new_target_version,
      'resulting_facts_sha256', pg_catalog.encode(v_res.resulting_facts_sha256, 'hex'),
      'safe_result_facts', v_res.safe_result_facts,
      'recorded_at', v_res.recorded_at
    );
  END IF;

  SELECT * INTO v_last_exec
    FROM rq_recovery.execution_attempts
   WHERE action_id = p_action_id
   ORDER BY started_at DESC
   LIMIT 1;

  RETURN pg_catalog.jsonb_build_object(
    'status', v_action.state,
    'operation_id', v_action.operation_id,
    'action_id', v_action.id,
    'last_attempt_outcome', v_last_exec.outcome,
    'last_safe_error_code', v_last_exec.safe_error_code
  );
END;
$$;

CREATE OR REPLACE FUNCTION rq_recovery.read_claim_inventory(
  p_tenant_id uuid DEFAULT NULL,
  p_project_id uuid DEFAULT NULL
)
RETURNS TABLE (
  claim_kind text,
  resource_id uuid,
  tenant_id uuid,
  project_id uuid,
  owner_instance_id uuid,
  control_epoch uuid,
  claim_generation bigint,
  claim_expires_at timestamptz,
  state text,
  version bigint
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
BEGIN
  PERFORM rq._assert_session_role(ARRAY['rq_recovery']);

  RETURN QUERY
  SELECT 'publication'::text, o.id, o.tenant_id, o.project_id, o.claim_owner_instance_id,
         o.claim_control_epoch, o.claim_generation, o.claim_expires_at, o.state, o.version
    FROM rq.outbox_events o
   WHERE o.claim_owner_instance_id IS NOT NULL
     AND (p_tenant_id IS NULL OR o.tenant_id = p_tenant_id)
     AND (p_project_id IS NULL OR o.project_id = p_project_id)
  UNION ALL
  SELECT 'fanout'::text, f.event_id, f.tenant_id, f.project_id, f.claim_owner_instance_id,
         f.claim_control_epoch, f.claim_generation, f.claim_expires_at, f.state, f.version
    FROM rq.event_fanout f
   WHERE f.claim_owner_instance_id IS NOT NULL
     AND (p_tenant_id IS NULL OR f.tenant_id = p_tenant_id)
     AND (p_project_id IS NULL OR f.project_id = p_project_id)
  UNION ALL
  SELECT 'prepared_attempt'::text, a.id, a.tenant_id, a.project_id, a.worker_instance_id,
         a.control_epoch, a.fencing_token, a.claim_expires_at, a.state, a.version
    FROM rq.delivery_attempts a
   WHERE a.state IN ('prepared', 'send_started')
     AND (p_tenant_id IS NULL OR a.tenant_id = p_tenant_id)
     AND (p_project_id IS NULL OR a.project_id = p_project_id)
  UNION ALL
  SELECT 'coordinator_task'::text, c.id, c.tenant_id, c.project_id, c.owner_instance_id,
         c.control_epoch, c.claim_generation, c.claim_expires_at, c.state, c.version
    FROM rq.coordinator_tasks c
   WHERE c.owner_instance_id IS NOT NULL
     AND (p_tenant_id IS NULL OR c.tenant_id = p_tenant_id)
     AND (p_project_id IS NULL OR c.project_id = p_project_id);
END;
$$;

CREATE OR REPLACE FUNCTION rq_recovery.read_obligation_inventory(
  p_tenant_id uuid,
  p_project_id uuid DEFAULT NULL
)
RETURNS TABLE (
  project_id uuid,
  stored_pending_events bigint,
  derived_pending_events bigint,
  stored_active_slots integer,
  derived_held_slots bigint,
  stored_unmaterialized_slots bigint,
  derived_unresolved_slots bigint
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
BEGIN
  PERFORM rq._assert_session_role(ARRAY['rq_recovery']);

  RETURN QUERY
  SELECT
    pc.project_id,
    pc.pending_events,
    (SELECT pg_catalog.count(*)::bigint FROM rq.events e WHERE e.project_id = pc.project_id AND e.state IN ('accepted', 'fanout_in_progress')),
    pc.active_attempt_slots,
    (SELECT pg_catalog.count(*)::bigint FROM rq.attempt_slots s WHERE s.project_id = pc.project_id AND s.state = 'held'),
    pc.unmaterialized_candidate_slots,
    COALESCE((SELECT pg_catalog.sum(r.unresolved_candidate_slots)::bigint FROM rq.event_fanout_reservations r WHERE r.project_id = pc.project_id), 0::bigint)
  FROM rq.project_capacity pc
  WHERE pc.tenant_id = p_tenant_id
    AND (p_project_id IS NULL OR pc.project_id = p_project_id)
  ORDER BY pc.project_id;
END;
$$;

CREATE OR REPLACE FUNCTION rq_recovery.read_projection_source_counts(
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
  v_total bigint;
  v_pending bigint;
  v_active bigint;
  v_ack bigint;
  v_dlq bigint;
  v_sup bigint;
  v_exp bigint;
  v_term bigint;
  v_unk bigint;
BEGIN
  PERFORM rq._assert_session_role(ARRAY['rq_recovery']);

  IF p_event_id IS NOT NULL THEN
    SELECT
      pg_catalog.count(*)::bigint,
      pg_catalog.count(*) FILTER (WHERE state IN ('acknowledged', 'dead_letter', 'suppressed', 'expired'))::bigint,
      pg_catalog.count(*) FILTER (WHERE state = 'acknowledged')::bigint
      INTO v_total, v_term, v_ack
      FROM rq.deliveries
     WHERE tenant_id = p_tenant_id AND project_id = p_project_id AND event_id = p_event_id;

    RETURN pg_catalog.jsonb_build_object(
      'population_definition_version', 'delivery_population.v1',
      'event_id', p_event_id,
      'total_deliveries', v_total,
      'terminal_deliveries', v_term,
      'acknowledged_deliveries', v_ack
    );
  END IF;

  SELECT
    pg_catalog.count(*)::bigint,
    pg_catalog.count(*) FILTER (WHERE state IN ('pending', 'ready', 'retry_wait'))::bigint,
    pg_catalog.count(*) FILTER (WHERE state = 'sending')::bigint,
    pg_catalog.count(*) FILTER (WHERE state = 'acknowledged')::bigint,
    pg_catalog.count(*) FILTER (WHERE state = 'dead_letter')::bigint,
    pg_catalog.count(*) FILTER (WHERE state = 'suppressed')::bigint,
    pg_catalog.count(*) FILTER (WHERE state = 'expired')::bigint
    INTO v_total, v_pending, v_active, v_ack, v_dlq, v_sup, v_exp
    FROM rq.deliveries
   WHERE tenant_id = p_tenant_id AND project_id = p_project_id;

  SELECT pg_catalog.count(*)::bigint
    INTO v_unk
    FROM rq.delivery_attempts
   WHERE tenant_id = p_tenant_id AND project_id = p_project_id AND state IN ('transport_unknown', 'abandoned');

  RETURN pg_catalog.jsonb_build_object(
    'population_definition_version', 'delivery_population.v1',
    'project_id', p_project_id,
    'total_deliveries', v_total,
    'pending_count', v_pending,
    'active_count', v_active,
    'acknowledged_count', v_ack,
    'dead_letter_count', v_dlq,
    'suppressed_count', v_sup,
    'expired_count', v_exp,
    'unknown_attempt_observations', v_unk
  );
END;
$$;

-- 8. Transfer rq_recovery ownership to rq_owner and enforce strict least-privilege grants
DO $$
DECLARE
  v_is_super boolean := false;
  v_prev_role text := current_user;
  v_switched boolean := false;
  v_rec record;
BEGIN
  SELECT r.rolsuper INTO v_is_super FROM pg_catalog.pg_roles r WHERE r.rolname = current_user;
  IF v_is_super OR pg_catalog.pg_has_role(current_user, 'rq_owner', 'MEMBER') THEN
    FOR v_rec IN
      SELECT n.nspname, c.relname, c.relkind
        FROM pg_catalog.pg_class c
        JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
       WHERE n.nspname = 'rq_recovery'
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
       WHERE n.nspname = 'rq_recovery'
         AND pg_catalog.pg_get_userbyid(p.proowner) <> 'rq_owner'
    LOOP
      EXECUTE pg_catalog.format('ALTER FUNCTION rq_recovery.%I(%s) OWNER TO rq_owner', v_rec.proname, v_rec.args);
    END LOOP;

    IF current_user <> 'rq_owner' AND pg_catalog.pg_has_role(current_user, 'rq_owner', 'MEMBER') THEN
      EXECUTE 'SET ROLE rq_owner';
      v_switched := true;
    END IF;

    EXECUTE 'ALTER DEFAULT PRIVILEGES FOR ROLE rq_owner IN SCHEMA rq_recovery REVOKE ALL ON TABLES FROM PUBLIC';
    EXECUTE 'ALTER DEFAULT PRIVILEGES FOR ROLE rq_owner IN SCHEMA rq_recovery REVOKE ALL ON SEQUENCES FROM PUBLIC';
    EXECUTE 'ALTER DEFAULT PRIVILEGES FOR ROLE rq_owner IN SCHEMA rq_recovery REVOKE ALL ON FUNCTIONS FROM PUBLIC';

    IF v_switched THEN
      EXECUTE pg_catalog.format('SET ROLE %I', v_prev_role);
    END IF;
  END IF;
END
$$;

REVOKE ALL ON SCHEMA rq_recovery FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA rq_recovery FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA rq_recovery FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA rq_recovery FROM PUBLIC;

REVOKE ALL ON SCHEMA rq_recovery FROM rq_api, rq_relay, rq_fanout, rq_sender, rq_coordinator, rq_reporter, rq_signing_issuer;
REVOKE ALL ON ALL TABLES IN SCHEMA rq_recovery FROM rq_api, rq_relay, rq_fanout, rq_sender, rq_coordinator, rq_reporter, rq_signing_issuer;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA rq_recovery FROM rq_api, rq_relay, rq_fanout, rq_sender, rq_coordinator, rq_reporter, rq_signing_issuer, rq_migrator, rq_recovery;

GRANT USAGE ON SCHEMA rq_recovery TO rq_migrator, rq_recovery;

-- Bounded read-only inspection SELECT for rq_recovery; mutations happen exclusively via named entry points
GRANT SELECT ON
  rq_recovery.incidents,
  rq_recovery.operations,
  rq_recovery.actions,
  rq_recovery.action_establish_target_epochs,
  rq_recovery.action_retire_stale_claims,
  rq_recovery.action_reconcile_reservations,
  rq_recovery.action_continue_publication_episodes,
  rq_recovery.action_record_receiver_comparisons,
  rq_recovery.action_set_recovery_gates,
  rq_recovery.action_rebuild_projections,
  rq_recovery.reviews,
  rq_recovery.execution_attempts,
  rq_recovery.action_results,
  rq_recovery.receiver_comparison_records
TO rq_recovery;

GRANT EXECUTE ON FUNCTION rq_recovery.cmd_incident_open(uuid, uuid, text, text, uuid, uuid) TO rq_recovery;
GRANT EXECUTE ON FUNCTION rq_recovery.cmd_incident_close(uuid, bigint, text, text) TO rq_recovery;
GRANT EXECUTE ON FUNCTION rq_recovery.cmd_operation_create(uuid, uuid, uuid, uuid, uuid, bytea, bytea, text) TO rq_recovery;
GRANT EXECUTE ON FUNCTION rq_recovery.cmd_action_plan(uuid, uuid, integer, text, text, uuid, uuid, uuid, bigint, uuid, bytea, bytea, text, text, text, jsonb) TO rq_recovery;
GRANT EXECUTE ON FUNCTION rq_recovery.cmd_action_review(uuid, uuid, bytea, uuid, bytea, bytea, text, text, text, timestamptz, bytea) TO rq_recovery;
GRANT EXECUTE ON FUNCTION rq_recovery.cmd_establish_target_epoch(uuid, text, bytea, bytea) TO rq_recovery;
GRANT EXECUTE ON FUNCTION rq_recovery.cmd_retire_stale_claim(uuid, text, bytea, bytea) TO rq_recovery;
GRANT EXECUTE ON FUNCTION rq_recovery.cmd_reconcile_reservations(uuid, text, bytea, bytea) TO rq_recovery;
GRANT EXECUTE ON FUNCTION rq_recovery.cmd_continue_publication_episode(uuid, text, bytea, bytea) TO rq_recovery;
GRANT EXECUTE ON FUNCTION rq_recovery.cmd_record_receiver_comparison(uuid, text, bytea, bytea) TO rq_recovery;
GRANT EXECUTE ON FUNCTION rq_recovery.cmd_set_recovery_gate(uuid, text, bytea, bytea) TO rq_recovery;
GRANT EXECUTE ON FUNCTION rq_recovery.cmd_project_maintenance_acquire(uuid, uuid, uuid, bigint, text) TO rq_recovery;
GRANT EXECUTE ON FUNCTION rq_recovery.cmd_project_maintenance_release(uuid, uuid, uuid, bigint, text) TO rq_recovery;
GRANT EXECUTE ON FUNCTION rq_recovery.cmd_rebuild_projection(uuid, text, bytea, bytea) TO rq_recovery;
GRANT EXECUTE ON FUNCTION rq_recovery.read_operation_result(uuid) TO rq_recovery;
GRANT EXECUTE ON FUNCTION rq_recovery.read_claim_inventory(uuid, uuid) TO rq_recovery;
GRANT EXECUTE ON FUNCTION rq_recovery.read_obligation_inventory(uuid, uuid) TO rq_recovery;
GRANT EXECUTE ON FUNCTION rq_recovery.read_projection_source_counts(uuid, uuid, uuid) TO rq_recovery;
