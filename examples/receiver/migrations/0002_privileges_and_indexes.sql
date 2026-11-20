-- Receiver Migration 0002: Deferred FKs, immutability guards, operational indexes, transactional functions, and receiver role privileges.

-- 1. Deferred circular FKs
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_constraint WHERE conname = 'fk_rc_integrations_demo_counter') THEN
    ALTER TABLE rc.integrations
      ADD CONSTRAINT fk_rc_integrations_demo_counter
      FOREIGN KEY (demo_counter_id, id) REFERENCES rc.demo_counters(id, integration_id)
      DEFERRABLE INITIALLY DEFERRED;
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_constraint WHERE conname = 'fk_rc_inbox_receipt') THEN
    ALTER TABLE rc.inbox
      ADD CONSTRAINT fk_rc_inbox_receipt
      FOREIGN KEY (receipt_id, integration_id, consumer_event_key_sha256, original_facts_sha256)
      REFERENCES rc.receipts(id, integration_id, consumer_event_key_sha256, original_facts_sha256)
      DEFERRABLE INITIALLY DEFERRED;
  END IF;
END
$$;

-- 2. Operational indexes
CREATE INDEX IF NOT EXISTS idx_rc_inbox_integration_processed
  ON rc.inbox (integration_id, processed_at DESC);
CREATE INDEX IF NOT EXISTS idx_rc_inbox_event_id
  ON rc.inbox (event_id);
CREATE INDEX IF NOT EXISTS idx_rc_key_cfg_events_int_accepted
  ON rc.key_configuration_events (integration_id, accepted_at DESC);
CREATE INDEX IF NOT EXISTS idx_rc_order_acceptances_receipt
  ON rc.order_acceptances (receipt_id);
CREATE INDEX IF NOT EXISTS idx_rc_trace_references_resource
  ON rc.trace_references (integration_id, resource_kind, resource_id, recorded_at DESC);

-- 3. Immutability guards
CREATE OR REPLACE FUNCTION rc._trg_immutable_row()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
  RAISE EXCEPTION 'Immutable receiver record in %.% cannot be modified or deleted', TG_TABLE_SCHEMA, TG_TABLE_NAME
    USING ERRCODE = '55000';
END;
$$;

CREATE OR REPLACE FUNCTION rc._trg_inbox_immutable()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'Committed receiver inbox anchors cannot be deleted' USING ERRCODE = '55000';
  END IF;
  IF NEW.integration_id <> OLD.integration_id
     OR NEW.consumer_event_key_sha256 <> OLD.consumer_event_key_sha256
     OR NEW.relay_project_id <> OLD.relay_project_id
     OR NEW.event_id <> OLD.event_id
     OR NEW.original_facts_sha256 <> OLD.original_facts_sha256
     OR NEW.original_content_sha256 <> OLD.original_content_sha256
     OR NEW.source_event_type_id <> OLD.source_event_type_id
     OR NEW.source_schema_version <> OLD.source_schema_version
     OR NEW.first_attempt_id <> OLD.first_attempt_id
     OR NEW.processed_at <> OLD.processed_at
     OR NEW.receipt_id <> OLD.receipt_id THEN
    RAISE EXCEPTION 'Committed receiver inbox semantic anchor fields are immutable' USING ERRCODE = '55000';
  END IF;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_rc_key_cfg_events_immutable ON rc.key_configuration_events;
CREATE TRIGGER trg_rc_key_cfg_events_immutable
  BEFORE UPDATE OR DELETE ON rc.key_configuration_events
  FOR EACH ROW EXECUTE FUNCTION rc._trg_immutable_row();

DROP TRIGGER IF EXISTS trg_rc_business_mutations_immutable ON rc.business_mutations;
CREATE TRIGGER trg_rc_business_mutations_immutable
  BEFORE UPDATE OR DELETE ON rc.business_mutations
  FOR EACH ROW EXECUTE FUNCTION rc._trg_immutable_row();

DROP TRIGGER IF EXISTS trg_rc_receipts_immutable ON rc.receipts;
CREATE TRIGGER trg_rc_receipts_immutable
  BEFORE UPDATE OR DELETE ON rc.receipts
  FOR EACH ROW EXECUTE FUNCTION rc._trg_immutable_row();

DROP TRIGGER IF EXISTS trg_rc_order_acceptances_immutable ON rc.order_acceptances;
CREATE TRIGGER trg_rc_order_acceptances_immutable
  BEFORE UPDATE OR DELETE ON rc.order_acceptances
  FOR EACH ROW EXECUTE FUNCTION rc._trg_immutable_row();

DROP TRIGGER IF EXISTS trg_rc_order_dispositions_immutable ON rc.order_dispositions;
CREATE TRIGGER trg_rc_order_dispositions_immutable
  BEFORE UPDATE OR DELETE ON rc.order_dispositions
  FOR EACH ROW EXECUTE FUNCTION rc._trg_immutable_row();

DROP TRIGGER IF EXISTS trg_rc_trace_references_immutable ON rc.trace_references;
CREATE TRIGGER trg_rc_trace_references_immutable
  BEFORE UPDATE OR DELETE ON rc.trace_references
  FOR EACH ROW EXECUTE FUNCTION rc._trg_immutable_row();

DROP TRIGGER IF EXISTS trg_rc_inbox_immutable ON rc.inbox;
CREATE TRIGGER trg_rc_inbox_immutable
  BEFORE UPDATE OR DELETE ON rc.inbox
  FOR EACH ROW EXECUTE FUNCTION rc._trg_inbox_immutable();

-- 4. Private session assertion helper and SECURITY DEFINER command/read functions
CREATE OR REPLACE FUNCTION rc._assert_session_role(p_allowed_roles text[])
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  v_is_super boolean := false;
BEGIN
  IF session_user = ANY(p_allowed_roles) THEN
    RETURN;
  END IF;

  SELECT r.rolsuper INTO v_is_super FROM pg_catalog.pg_roles r WHERE r.rolname = session_user;
  IF COALESCE(v_is_super, false) THEN
    RETURN;
  END IF;

  RAISE EXCEPTION 'Session role "%" is not authorized for this receiver database operation', session_user
    USING ERRCODE = '42501';
END;
$$;

CREATE OR REPLACE FUNCTION rc.cmd_process_unordered_delivery(
  p_integration_id uuid,
  p_consumer_event_key_sha256 bytea,
  p_relay_project_id uuid,
  p_event_id uuid,
  p_original_facts_sha256 bytea,
  p_original_content_sha256 bytea,
  p_source_event_type_id uuid,
  p_source_schema_version integer,
  p_representation_version integer,
  p_wire_sha256 bytea,
  p_attempt_id uuid,
  p_endpoint_version bigint,
  p_key_id text,
  p_profile_id uuid DEFAULT NULL,
  p_profile_version bigint DEFAULT NULL,
  p_target_schema_version integer DEFAULT NULL,
  p_new_receipt_id uuid DEFAULT NULL,
  p_new_mutation_id uuid DEFAULT NULL
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  v_int rc.integrations%ROWTYPE;
  v_ep rc.allowed_endpoint_versions%ROWTYPE;
  v_key rc.key_metadata%ROWTYPE;
  v_inbox rc.inbox%ROWTYPE;
  v_receipt rc.receipts%ROWTYPE;
  v_counter rc.demo_counters%ROWTYPE;
  v_now timestamptz := pg_catalog.clock_timestamp();
  v_receipt_id uuid;
  v_mutation_id uuid;
BEGIN
  PERFORM rc._assert_session_role(ARRAY['receiver_runtime']);

  SELECT * INTO v_int FROM rc.integrations WHERE id = p_integration_id FOR SHARE;
  IF NOT FOUND OR v_int.state <> 'active' OR v_int.relay_project_id <> p_relay_project_id THEN
    RAISE EXCEPTION 'Receiver integration inactive or mismatched' USING ERRCODE = '55000';
  END IF;

  SELECT * INTO v_ep
    FROM rc.allowed_endpoint_versions
   WHERE integration_id = p_integration_id AND endpoint_version = p_endpoint_version
   FOR SHARE;
  IF NOT FOUND OR v_ep.state NOT IN ('active', 'pending') OR (v_ep.verify_until IS NOT NULL AND v_ep.verify_until <= v_now) THEN
    RAISE EXCEPTION 'Endpoint version not accepted by receiver integration' USING ERRCODE = '42501';
  END IF;

  SELECT * INTO v_key
    FROM rc.key_metadata
   WHERE integration_id = p_integration_id AND key_id = p_key_id
   FOR SHARE;
  IF NOT FOUND OR v_key.state NOT IN ('active', 'overlap') THEN
    RAISE EXCEPTION 'Receiver key inactive for business delivery' USING ERRCODE = '42501';
  END IF;

  IF p_representation_version = 1 THEN
    IF NOT EXISTS (
      SELECT 1 FROM rc.allowed_representations ar
       WHERE ar.integration_id = p_integration_id AND ar.envelope_version = 1 AND ar.state = 'active'
    ) THEN
      RAISE EXCEPTION 'Envelope v1 representation not enabled' USING ERRCODE = '22023';
    END IF;
  ELSIF p_representation_version = 2 THEN
    IF NOT EXISTS (
      SELECT 1 FROM rc.allowed_representations ar
       WHERE ar.integration_id = p_integration_id
         AND ar.envelope_version = 2
         AND ar.profile_id = p_profile_id
         AND ar.profile_version = p_profile_version
         AND ar.target_schema_version = p_target_schema_version
         AND ar.state = 'active'
    ) THEN
      RAISE EXCEPTION 'Envelope v2 profile/target representation not approved' USING ERRCODE = '22023';
    END IF;
  ELSE
    RAISE EXCEPTION 'Unsupported representation version %', p_representation_version USING ERRCODE = '22023';
  END IF;

  PERFORM pg_catalog.pg_advisory_xact_lock(
    pg_catalog.hashtext(p_integration_id::text),
    pg_catalog.hashtext(pg_catalog.encode(p_consumer_event_key_sha256, 'hex'))
  );

  SELECT * INTO v_inbox
    FROM rc.inbox
   WHERE integration_id = p_integration_id AND consumer_event_key_sha256 = p_consumer_event_key_sha256
   FOR UPDATE;

  IF FOUND THEN
    IF v_inbox.original_facts_sha256 <> p_original_facts_sha256 THEN
      RAISE EXCEPTION 'ORIGINAL_EVENT_CONFLICT' USING ERRCODE = '23505';
    END IF;
    SELECT * INTO v_receipt FROM rc.receipts WHERE id = v_inbox.receipt_id;
    SELECT * INTO v_counter FROM rc.demo_counters WHERE id = v_int.demo_counter_id;
    RETURN pg_catalog.jsonb_build_object(
      'outcome', 'already_processed',
      'receipt_id', v_receipt.id,
      'business_status', v_receipt.business_status,
      'committed_at', v_receipt.committed_at,
      'counter_value', v_counter.value
    );
  END IF;

  SELECT * INTO v_counter FROM rc.demo_counters WHERE id = v_int.demo_counter_id FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'Configured demo counter missing' USING ERRCODE = 'P0002';
  END IF;
  IF v_counter.value >= 9223372036854775807 THEN
    RAISE EXCEPTION 'Demo counter bigint overflow' USING ERRCODE = '22003';
  END IF;

  UPDATE rc.demo_counters
     SET value = value + 1, version = version + 1
   WHERE id = v_counter.id
   RETURNING * INTO v_counter;

  v_receipt_id := COALESCE(p_new_receipt_id, pg_catalog.gen_random_uuid());
  v_mutation_id := COALESCE(p_new_mutation_id, pg_catalog.gen_random_uuid());

  INSERT INTO rc.inbox (
    integration_id, consumer_event_key_sha256, relay_project_id, event_id,
    original_facts_sha256, original_content_sha256, source_event_type_id,
    source_schema_version, first_representation_version, first_wire_sha256,
    state, first_attempt_id, processed_at, receipt_id, version
  ) VALUES (
    p_integration_id, p_consumer_event_key_sha256, p_relay_project_id, p_event_id,
    p_original_facts_sha256, p_original_content_sha256, p_source_event_type_id,
    p_source_schema_version, p_representation_version, p_wire_sha256,
    'processed', p_attempt_id, v_now, v_receipt_id, 1
  );

  INSERT INTO rc.receipts (
    id, integration_id, consumer_event_key_sha256, original_facts_sha256,
    business_status, committed_at, version
  ) VALUES (
    v_receipt_id, p_integration_id, p_consumer_event_key_sha256, p_original_facts_sha256,
    'committed', v_now, 1
  );

  INSERT INTO rc.business_mutations (
    id, integration_id, consumer_event_key_sha256, counter_id,
    applied_increment, original_facts_sha256, recorded_at, version
  ) VALUES (
    v_mutation_id, p_integration_id, p_consumer_event_key_sha256, v_counter.id,
    1, p_original_facts_sha256, v_now, 1
  );

  RETURN pg_catalog.jsonb_build_object(
    'outcome', 'committed',
    'receipt_id', v_receipt_id,
    'business_status', 'committed',
    'committed_at', v_now,
    'counter_value', v_counter.value
  );
END;
$$;

CREATE OR REPLACE FUNCTION rc.cmd_process_strict_ordered_delivery(
  p_integration_id uuid,
  p_ordering_domain_id uuid,
  p_ordering_key_sha256 bytea,
  p_ordering_sequence bigint,
  p_consumer_event_key_sha256 bytea,
  p_relay_project_id uuid,
  p_event_id uuid,
  p_original_facts_sha256 bytea,
  p_original_content_sha256 bytea,
  p_source_event_type_id uuid,
  p_source_schema_version integer,
  p_representation_version integer,
  p_wire_sha256 bytea,
  p_attempt_id uuid,
  p_endpoint_version bigint,
  p_key_id text,
  p_profile_id uuid DEFAULT NULL,
  p_profile_version bigint DEFAULT NULL,
  p_target_schema_version integer DEFAULT NULL,
  p_new_receipt_id uuid DEFAULT NULL,
  p_new_mutation_id uuid DEFAULT NULL
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  v_int rc.integrations%ROWTYPE;
  v_ep rc.allowed_endpoint_versions%ROWTYPE;
  v_key rc.key_metadata%ROWTYPE;
  v_head rc.order_heads%ROWTYPE;
  v_acc rc.order_acceptances%ROWTYPE;
  v_inbox rc.inbox%ROWTYPE;
  v_receipt rc.receipts%ROWTYPE;
  v_counter rc.demo_counters%ROWTYPE;
  v_now timestamptz := pg_catalog.clock_timestamp();
  v_receipt_id uuid;
  v_mutation_id uuid;
BEGIN
  PERFORM rc._assert_session_role(ARRAY['receiver_runtime']);

  SELECT * INTO v_int FROM rc.integrations WHERE id = p_integration_id FOR SHARE;
  IF NOT FOUND OR v_int.state <> 'active' OR v_int.relay_project_id <> p_relay_project_id THEN
    RAISE EXCEPTION 'Receiver integration inactive or mismatched' USING ERRCODE = '55000';
  END IF;

  SELECT * INTO v_ep FROM rc.allowed_endpoint_versions
   WHERE integration_id = p_integration_id AND endpoint_version = p_endpoint_version FOR SHARE;
  IF NOT FOUND OR v_ep.state NOT IN ('active', 'pending') OR (v_ep.verify_until IS NOT NULL AND v_ep.verify_until <= v_now) THEN
    RAISE EXCEPTION 'Endpoint version not accepted by receiver integration' USING ERRCODE = '42501';
  END IF;

  SELECT * INTO v_key FROM rc.key_metadata
   WHERE integration_id = p_integration_id AND key_id = p_key_id FOR SHARE;
  IF NOT FOUND OR v_key.state NOT IN ('active', 'overlap') THEN
    RAISE EXCEPTION 'Receiver key inactive for business delivery' USING ERRCODE = '42501';
  END IF;

  IF p_representation_version = 1 THEN
    IF NOT EXISTS (
      SELECT 1 FROM rc.allowed_representations ar
       WHERE ar.integration_id = p_integration_id AND ar.envelope_version = 1 AND ar.state = 'active'
    ) THEN
      RAISE EXCEPTION 'Envelope v1 representation not enabled' USING ERRCODE = '22023';
    END IF;
  ELSIF p_representation_version = 2 THEN
    IF NOT EXISTS (
      SELECT 1 FROM rc.allowed_representations ar
       WHERE ar.integration_id = p_integration_id
         AND ar.envelope_version = 2
         AND ar.profile_id = p_profile_id
         AND ar.profile_version = p_profile_version
         AND ar.target_schema_version = p_target_schema_version
         AND ar.state = 'active'
    ) THEN
      RAISE EXCEPTION 'Envelope v2 profile/target representation not approved' USING ERRCODE = '22023';
    END IF;
  ELSE
    RAISE EXCEPTION 'Unsupported representation version %', p_representation_version USING ERRCODE = '22023';
  END IF;

  PERFORM pg_catalog.pg_advisory_xact_lock(
    pg_catalog.hashtext(p_integration_id::text),
    pg_catalog.hashtext(pg_catalog.encode(p_consumer_event_key_sha256, 'hex'))
  );

  INSERT INTO rc.order_heads (
    integration_id, ordering_domain_id, ordering_key_sha256, next_expected_sequence, state, version
  ) VALUES (
    p_integration_id, p_ordering_domain_id, p_ordering_key_sha256, 1, 'active', 1
  )
  ON CONFLICT (integration_id, ordering_domain_id, ordering_key_sha256) DO NOTHING;

  SELECT * INTO v_head
    FROM rc.order_heads
   WHERE integration_id = p_integration_id
     AND ordering_domain_id = p_ordering_domain_id
     AND ordering_key_sha256 = p_ordering_key_sha256
   FOR UPDATE;

  IF v_head.state <> 'active' THEN
    RAISE EXCEPTION 'Receiver order head is held' USING ERRCODE = '55000';
  END IF;

  IF p_ordering_sequence < v_head.next_expected_sequence THEN
    SELECT * INTO v_acc
      FROM rc.order_acceptances
     WHERE integration_id = p_integration_id
       AND ordering_domain_id = p_ordering_domain_id
       AND ordering_key_sha256 = p_ordering_key_sha256
       AND ordering_sequence = p_ordering_sequence;

    IF NOT FOUND
       OR v_acc.consumer_event_key_sha256 <> p_consumer_event_key_sha256
       OR v_acc.original_facts_sha256 <> p_original_facts_sha256 THEN
      RAISE EXCEPTION 'CONSUMER_ORDER_POSITION_CONFLICT' USING ERRCODE = '23505';
    END IF;

    SELECT * INTO v_receipt FROM rc.receipts WHERE id = v_acc.receipt_id;
    SELECT * INTO v_counter FROM rc.demo_counters WHERE id = v_int.demo_counter_id;
    RETURN pg_catalog.jsonb_build_object(
      'outcome', 'already_processed',
      'receipt_id', v_receipt.id,
      'business_status', v_receipt.business_status,
      'committed_at', v_receipt.committed_at,
      'counter_value', v_counter.value,
      'next_expected_sequence', v_head.next_expected_sequence
    );
  ELSIF p_ordering_sequence > v_head.next_expected_sequence THEN
    RAISE EXCEPTION 'CONSUMER_ORDER_GAP' USING ERRCODE = '55000';
  END IF;

  -- p_ordering_sequence = v_head.next_expected_sequence
  SELECT * INTO v_inbox
    FROM rc.inbox
   WHERE integration_id = p_integration_id AND consumer_event_key_sha256 = p_consumer_event_key_sha256
   FOR UPDATE;

  IF FOUND THEN
    IF v_inbox.original_facts_sha256 <> p_original_facts_sha256 THEN
      RAISE EXCEPTION 'ORIGINAL_EVENT_CONFLICT' USING ERRCODE = '23505';
    END IF;
    SELECT * INTO v_receipt FROM rc.receipts WHERE id = v_inbox.receipt_id;
    INSERT INTO rc.order_acceptances (
      integration_id, ordering_domain_id, ordering_key_sha256, ordering_sequence,
      consumer_event_key_sha256, original_facts_sha256, receipt_id, first_attempt_id,
      acceptance_kind, accepted_at, version
    ) VALUES (
      p_integration_id, p_ordering_domain_id, p_ordering_key_sha256, p_ordering_sequence,
      p_consumer_event_key_sha256, p_original_facts_sha256, v_receipt.id, p_attempt_id,
      'duplicate_business_anchor', v_now, 1
    );
    UPDATE rc.order_heads
       SET next_expected_sequence = next_expected_sequence + 1, version = version + 1
     WHERE integration_id = p_integration_id
       AND ordering_domain_id = p_ordering_domain_id
       AND ordering_key_sha256 = p_ordering_key_sha256
     RETURNING * INTO v_head;
    SELECT * INTO v_counter FROM rc.demo_counters WHERE id = v_int.demo_counter_id;
    RETURN pg_catalog.jsonb_build_object(
      'outcome', 'already_processed_order_advanced',
      'receipt_id', v_receipt.id,
      'business_status', v_receipt.business_status,
      'committed_at', v_receipt.committed_at,
      'counter_value', v_counter.value,
      'next_expected_sequence', v_head.next_expected_sequence
    );
  END IF;

  SELECT * INTO v_counter FROM rc.demo_counters WHERE id = v_int.demo_counter_id FOR UPDATE;
  IF v_counter.value >= 9223372036854775807 THEN
    RAISE EXCEPTION 'Demo counter bigint overflow' USING ERRCODE = '22003';
  END IF;

  UPDATE rc.demo_counters SET value = value + 1, version = version + 1 WHERE id = v_counter.id RETURNING * INTO v_counter;

  v_receipt_id := COALESCE(p_new_receipt_id, pg_catalog.gen_random_uuid());
  v_mutation_id := COALESCE(p_new_mutation_id, pg_catalog.gen_random_uuid());

  INSERT INTO rc.inbox (
    integration_id, consumer_event_key_sha256, relay_project_id, event_id,
    original_facts_sha256, original_content_sha256, source_event_type_id,
    source_schema_version, first_representation_version, first_wire_sha256,
    state, first_attempt_id, processed_at, receipt_id, version
  ) VALUES (
    p_integration_id, p_consumer_event_key_sha256, p_relay_project_id, p_event_id,
    p_original_facts_sha256, p_original_content_sha256, p_source_event_type_id,
    p_source_schema_version, p_representation_version, p_wire_sha256,
    'processed', p_attempt_id, v_now, v_receipt_id, 1
  );

  INSERT INTO rc.receipts (
    id, integration_id, consumer_event_key_sha256, original_facts_sha256,
    business_status, committed_at, version
  ) VALUES (
    v_receipt_id, p_integration_id, p_consumer_event_key_sha256, p_original_facts_sha256,
    'committed', v_now, 1
  );

  INSERT INTO rc.business_mutations (
    id, integration_id, consumer_event_key_sha256, counter_id,
    applied_increment, original_facts_sha256, recorded_at, version
  ) VALUES (
    v_mutation_id, p_integration_id, p_consumer_event_key_sha256, v_counter.id,
    1, p_original_facts_sha256, v_now, 1
  );

  INSERT INTO rc.order_acceptances (
    integration_id, ordering_domain_id, ordering_key_sha256, ordering_sequence,
    consumer_event_key_sha256, original_facts_sha256, receipt_id, first_attempt_id,
    acceptance_kind, accepted_at, version
  ) VALUES (
    p_integration_id, p_ordering_domain_id, p_ordering_key_sha256, p_ordering_sequence,
    p_consumer_event_key_sha256, p_original_facts_sha256, v_receipt_id, p_attempt_id,
    'first_business_commit', v_now, 1
  );

  UPDATE rc.order_heads
     SET next_expected_sequence = next_expected_sequence + 1, version = version + 1
   WHERE integration_id = p_integration_id
     AND ordering_domain_id = p_ordering_domain_id
     AND ordering_key_sha256 = p_ordering_key_sha256
   RETURNING * INTO v_head;

  RETURN pg_catalog.jsonb_build_object(
    'outcome', 'committed',
    'receipt_id', v_receipt_id,
    'business_status', 'committed',
    'committed_at', v_now,
    'counter_value', v_counter.value,
    'next_expected_sequence', v_head.next_expected_sequence
  );
END;
$$;

CREATE OR REPLACE FUNCTION rc.cmd_apply_order_skip_disposition(
  p_disposition_id uuid,
  p_integration_id uuid,
  p_ordering_domain_id uuid,
  p_ordering_key_sha256 bytea,
  p_expected_prior_sequence bigint,
  p_source_sender_disposition_id uuid,
  p_reason_code text,
  p_operator_reference text
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  v_head rc.order_heads%ROWTYPE;
  v_now timestamptz := pg_catalog.clock_timestamp();
BEGIN
  PERFORM rc._assert_session_role(ARRAY['receiver_runtime']);

  SELECT * INTO v_head
    FROM rc.order_heads
   WHERE integration_id = p_integration_id
     AND ordering_domain_id = p_ordering_domain_id
     AND ordering_key_sha256 = p_ordering_key_sha256
   FOR UPDATE;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'Receiver order head not found' USING ERRCODE = 'P0002';
  END IF;
  IF v_head.next_expected_sequence <> p_expected_prior_sequence THEN
    RAISE EXCEPTION 'Receiver order head precondition conflict' USING ERRCODE = '40001';
  END IF;

  INSERT INTO rc.order_dispositions (
    id, integration_id, ordering_domain_id, ordering_key_sha256,
    prior_sequence, resulting_sequence, source_sender_disposition_id,
    reason_code, operator_reference, accepted_at, version
  ) VALUES (
    p_disposition_id, p_integration_id, p_ordering_domain_id, p_ordering_key_sha256,
    p_expected_prior_sequence, p_expected_prior_sequence + 1, p_source_sender_disposition_id,
    p_reason_code, p_operator_reference, v_now, 1
  );

  UPDATE rc.order_heads
     SET next_expected_sequence = p_expected_prior_sequence + 1,
         version = version + 1
   WHERE integration_id = p_integration_id
     AND ordering_domain_id = p_ordering_domain_id
     AND ordering_key_sha256 = p_ordering_key_sha256
   RETURNING * INTO v_head;

  RETURN pg_catalog.jsonb_build_object(
    'outcome', 'skipped',
    'disposition_id', p_disposition_id,
    'next_expected_sequence', v_head.next_expected_sequence
  );
END;
$$;

CREATE OR REPLACE FUNCTION rc.cmd_key_configure(
  p_event_id uuid,
  p_integration_id uuid,
  p_key_id text,
  p_action text,
  p_custody_reference text,
  p_custody_version_reference text,
  p_verify_until timestamptz,
  p_contract_sha256 bytea,
  p_operator_reference text
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  v_int rc.integrations%ROWTYPE;
  v_key rc.key_metadata%ROWTYPE;
  v_prior_ver bigint := 0;
  v_next_ver bigint := 1;
  v_new_state text;
  v_now timestamptz := pg_catalog.clock_timestamp();
BEGIN
  PERFORM rc._assert_session_role(ARRAY['receiver_runtime']);

  SELECT * INTO v_int FROM rc.integrations WHERE id = p_integration_id FOR UPDATE;
  IF NOT FOUND OR v_int.contract_sha256 <> p_contract_sha256 THEN
    RAISE EXCEPTION 'Integration not found or contract digest mismatch' USING ERRCODE = '40001';
  END IF;

  SELECT * INTO v_key FROM rc.key_metadata WHERE integration_id = p_integration_id AND key_id = p_key_id FOR UPDATE;
  IF FOUND THEN
    v_prior_ver := v_key.version;
    v_next_ver := v_key.version + 1;
  END IF;

  v_new_state := CASE p_action
    WHEN 'install_pending' THEN 'pending'
    WHEN 'promote_active' THEN 'active'
    WHEN 'rotate_overlap' THEN 'overlap'
    WHEN 'retire' THEN 'retired'
    WHEN 'revoke' THEN 'revoked'
    ELSE v_key.state
  END;

  INSERT INTO rc.key_metadata (
    integration_id, key_id, custody_reference, custody_version_reference, state, verify_until, configuration_version, version
  ) VALUES (
    p_integration_id, p_key_id, p_custody_reference, p_custody_version_reference, v_new_state, p_verify_until, v_int.configuration_version + 1, 1
  )
  ON CONFLICT (integration_id, key_id) DO UPDATE
    SET custody_reference = EXCLUDED.custody_reference,
        custody_version_reference = EXCLUDED.custody_version_reference,
        state = EXCLUDED.state,
        verify_until = EXCLUDED.verify_until,
        configuration_version = v_int.configuration_version + 1,
        version = rc.key_metadata.version + 1;

  UPDATE rc.integrations
     SET configuration_version = configuration_version + 1, version = version + 1
   WHERE id = p_integration_id;

  INSERT INTO rc.key_configuration_events (
    id, integration_id, key_id, action, prior_version, resulting_version, contract_sha256, operator_reference, accepted_at
  ) VALUES (
    p_event_id, p_integration_id, p_key_id, p_action, v_prior_ver, v_next_ver, p_contract_sha256, p_operator_reference, v_now
  );

  RETURN pg_catalog.jsonb_build_object(
    'outcome', 'configured',
    'integration_id', p_integration_id,
    'key_id', p_key_id,
    'state', v_new_state,
    'version', v_next_ver
  );
END;
$$;

CREATE OR REPLACE FUNCTION rc.read_schema_migrations()
RETURNS TABLE (
  migration_id text,
  checksum bytea,
  applied_at timestamptz,
  source_reference text,
  runner_version text
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
BEGIN
  PERFORM rc._assert_session_role(ARRAY['receiver_runtime', 'receiver_migrator']);
  RETURN QUERY
  SELECT m.migration_id, m.checksum, m.applied_at, m.source_reference, m.runner_version
    FROM rc.schema_migrations m
   ORDER BY m.migration_id;
END;
$$;

-- 5. Ownership transfer and least-privilege grants
DO $$
DECLARE
  v_is_super boolean := false;
  v_prev_role text := current_user;
  v_switched boolean := false;
  v_rec record;
BEGIN
  SELECT r.rolsuper INTO v_is_super FROM pg_catalog.pg_roles r WHERE r.rolname = current_user;
  IF v_is_super OR pg_catalog.pg_has_role(current_user, 'receiver_owner', 'MEMBER') THEN
    FOR v_rec IN
      SELECT n.nspname, c.relname, c.relkind
        FROM pg_catalog.pg_class c
        JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
       WHERE n.nspname = 'rc'
         AND c.relkind IN ('r', 'p', 'v', 'S')
         AND pg_catalog.pg_get_userbyid(c.relowner) <> 'receiver_owner'
    LOOP
      IF v_rec.relkind = 'S' THEN
        EXECUTE pg_catalog.format('ALTER SEQUENCE %I.%I OWNER TO receiver_owner', v_rec.nspname, v_rec.relname);
      ELSIF v_rec.relkind = 'v' THEN
        EXECUTE pg_catalog.format('ALTER VIEW %I.%I OWNER TO receiver_owner', v_rec.nspname, v_rec.relname);
      ELSE
        EXECUTE pg_catalog.format('ALTER TABLE %I.%I OWNER TO receiver_owner', v_rec.nspname, v_rec.relname);
      END IF;
    END LOOP;

    FOR v_rec IN
      SELECT p.proname, pg_catalog.pg_get_function_identity_arguments(p.oid) AS args
        FROM pg_catalog.pg_proc p
        JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
       WHERE n.nspname = 'rc'
         AND pg_catalog.pg_get_userbyid(p.proowner) <> 'receiver_owner'
    LOOP
      EXECUTE pg_catalog.format('ALTER FUNCTION rc.%I(%s) OWNER TO receiver_owner', v_rec.proname, v_rec.args);
    END LOOP;

    IF current_user <> 'receiver_owner' AND pg_catalog.pg_has_role(current_user, 'receiver_owner', 'MEMBER') THEN
      EXECUTE 'SET ROLE receiver_owner';
      v_switched := true;
    END IF;

    EXECUTE 'ALTER DEFAULT PRIVILEGES FOR ROLE receiver_owner IN SCHEMA rc REVOKE ALL ON TABLES FROM PUBLIC';
    EXECUTE 'ALTER DEFAULT PRIVILEGES FOR ROLE receiver_owner IN SCHEMA rc REVOKE ALL ON SEQUENCES FROM PUBLIC';
    EXECUTE 'ALTER DEFAULT PRIVILEGES FOR ROLE receiver_owner IN SCHEMA rc REVOKE ALL ON FUNCTIONS FROM PUBLIC';

    IF v_switched THEN
      EXECUTE pg_catalog.format('SET ROLE %I', v_prev_role);
    END IF;
  END IF;
END
$$;

REVOKE ALL ON SCHEMA rc FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA rc FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA rc FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA rc FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA rc FROM receiver_runtime, receiver_migrator;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA rc FROM receiver_runtime, receiver_migrator;

GRANT USAGE ON SCHEMA rc TO receiver_runtime, receiver_migrator;

-- Safe SELECT-only inspection for receiver_runtime (no direct INSERT/UPDATE/DELETE)
GRANT SELECT ON
  rc.schema_migrations,
  rc.integrations,
  rc.allowed_endpoint_versions,
  rc.key_metadata,
  rc.key_configuration_events,
  rc.allowed_representations,
  rc.demo_counters,
  rc.inbox,
  rc.business_mutations,
  rc.receipts,
  rc.order_heads,
  rc.order_acceptances,
  rc.order_dispositions,
  rc.trace_references
TO receiver_runtime;

GRANT EXECUTE ON FUNCTION rc.cmd_process_unordered_delivery(
  uuid, bytea, uuid, uuid, bytea, bytea, uuid, integer, integer, bytea, uuid, bigint, text, uuid, bigint, integer, uuid, uuid
) TO receiver_runtime;
GRANT EXECUTE ON FUNCTION rc.cmd_process_strict_ordered_delivery(
  uuid, uuid, bytea, bigint, bytea, uuid, uuid, bytea, bytea, uuid, integer, integer, bytea, uuid, bigint, text, uuid, bigint, integer, uuid, uuid
) TO receiver_runtime;
GRANT EXECUTE ON FUNCTION rc.cmd_apply_order_skip_disposition(uuid, uuid, uuid, bytea, bigint, uuid, text, text) TO receiver_runtime;
GRANT EXECUTE ON FUNCTION rc.cmd_key_configure(uuid, uuid, text, text, text, text, timestamptz, bytea, text) TO receiver_runtime;
GRANT EXECUTE ON FUNCTION rc.read_schema_migrations() TO receiver_runtime, receiver_migrator;
