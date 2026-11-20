-- Provider Ingress Migration 0003: Immutability triggers, operational indexes, transactional functions, and provider_runtime grants.

-- 1. Late FK from bindings.current_binding_version -> binding_versions
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_constraint WHERE conname = 'fk_pi_bindings_current_version') THEN
    ALTER TABLE pi.bindings
      ADD CONSTRAINT fk_pi_bindings_current_version
      FOREIGN KEY (id, current_binding_version) REFERENCES pi.binding_versions(binding_id, binding_version)
      DEFERRABLE INITIALLY DEFERRED;
  END IF;
END
$$;

-- 2. Operational indexes
CREATE INDEX IF NOT EXISTS idx_pi_observations_binding_received
  ON pi.observations (binding_id, received_at DESC);
CREATE INDEX IF NOT EXISTS idx_pi_forward_intents_due
  ON pi.forward_intents (state, next_attempt_at, id)
  WHERE state IN ('ready', 'acceptance_unknown');
CREATE INDEX IF NOT EXISTS idx_pi_forward_intents_claimed_expiry
  ON pi.forward_intents (claim_expires_at)
  WHERE state = 'claimed';
CREATE INDEX IF NOT EXISTS idx_pi_audit_events_binding_recorded
  ON pi.audit_events (binding_id, recorded_at DESC);

-- 3. Immutability guards
CREATE OR REPLACE FUNCTION pi._trg_immutable_row()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
  RAISE EXCEPTION 'Immutable provider-ingress record in %.% cannot be updated or deleted', TG_TABLE_SCHEMA, TG_TABLE_NAME
    USING ERRCODE = '55000';
END;
$$;

CREATE OR REPLACE FUNCTION pi._trg_binding_versions_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'Binding version history cannot be deleted' USING ERRCODE = '55000';
  END IF;
  IF OLD.state <> 'draft' THEN
    IF NEW.binding_id <> OLD.binding_id OR NEW.binding_version <> OLD.binding_version
       OR NEW.provider <> OLD.provider OR NEW.account_reference <> OLD.account_reference
       OR NEW.account_mode <> OLD.account_mode OR NEW.payload_profile <> OLD.payload_profile
       OR NEW.secret_custody_reference <> OLD.secret_custody_reference
       OR NEW.secret_version_reference <> OLD.secret_version_reference
       OR NEW.relay_tenant_id <> OLD.relay_tenant_id OR NEW.relay_project_id <> OLD.relay_project_id
       OR NEW.publication_channel_id <> OLD.publication_channel_id
       OR NEW.normalized_event_type_id <> OLD.normalized_event_type_id
       OR NEW.normalized_schema_version <> OLD.normalized_schema_version
       OR NEW.configuration_sha256 <> OLD.configuration_sha256 THEN
      RAISE EXCEPTION 'Non-draft provider binding version configuration fields are immutable' USING ERRCODE = '55000';
    END IF;
    IF NOT ((OLD.state = 'active' AND NEW.state IN ('active', 'retired', 'revoked'))
            OR (OLD.state = 'retired' AND NEW.state = 'retired')
            OR (OLD.state = 'revoked' AND NEW.state = 'revoked')) THEN
      RAISE EXCEPTION 'Invalid provider binding version transition % -> %', OLD.state, NEW.state USING ERRCODE = '55000';
    END IF;
  END IF;
  RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION pi._trg_bindings_identity_guard()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'Provider bindings cannot be deleted' USING ERRCODE = '55000';
  END IF;
  IF OLD.current_binding_version IS NOT NULL AND (
    NEW.provider <> OLD.provider
    OR NEW.account_reference <> OLD.account_reference
    OR NEW.account_mode <> OLD.account_mode
    OR NEW.payload_profile <> OLD.payload_profile
    OR NEW.relay_tenant_id <> OLD.relay_tenant_id
    OR NEW.relay_project_id <> OLD.relay_project_id
    OR NEW.publication_channel_id <> OLD.publication_channel_id
    OR NEW.normalized_event_type_id <> OLD.normalized_event_type_id
    OR NEW.normalized_schema_version <> OLD.normalized_schema_version
  ) THEN
    RAISE EXCEPTION 'Activated provider binding scope identity cannot change across versions' USING ERRCODE = '55000';
  END IF;
  RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION pi._trg_observations_immutable()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog
AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'Accepted provider observations cannot be deleted' USING ERRCODE = '55000';
  END IF;
  IF NEW.id <> OLD.id OR NEW.binding_id <> OLD.binding_id OR NEW.binding_version <> OLD.binding_version
     OR NEW.provider <> OLD.provider OR NEW.account_mode <> OLD.account_mode
     OR NEW.payload_profile <> OLD.payload_profile
     OR NEW.provider_event_id IS DISTINCT FROM OLD.provider_event_id
     OR NEW.event_type <> OLD.event_type
     OR NEW.raw_body_sha256 <> OLD.raw_body_sha256
     OR NEW.normalized_facts <> OLD.normalized_facts
     OR NEW.normalized_facts_sha256 <> OLD.normalized_facts_sha256 THEN
    RAISE EXCEPTION 'Accepted provider observation core identity and facts are immutable' USING ERRCODE = '55000';
  END IF;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_pi_audit_events_immutable ON pi.audit_events;
CREATE TRIGGER trg_pi_audit_events_immutable
  BEFORE UPDATE OR DELETE ON pi.audit_events
  FOR EACH ROW EXECUTE FUNCTION pi._trg_immutable_row();

DROP TRIGGER IF EXISTS trg_pi_semantic_identities_immutable ON pi.semantic_identities;
CREATE TRIGGER trg_pi_semantic_identities_immutable
  BEFORE UPDATE OR DELETE ON pi.semantic_identities
  FOR EACH ROW EXECUTE FUNCTION pi._trg_immutable_row();

DROP TRIGGER IF EXISTS trg_pi_binding_versions_guard ON pi.binding_versions;
CREATE TRIGGER trg_pi_binding_versions_guard
  BEFORE UPDATE OR DELETE ON pi.binding_versions
  FOR EACH ROW EXECUTE FUNCTION pi._trg_binding_versions_guard();

DROP TRIGGER IF EXISTS trg_pi_bindings_identity_guard ON pi.bindings;
CREATE TRIGGER trg_pi_bindings_identity_guard
  BEFORE UPDATE OR DELETE ON pi.bindings
  FOR EACH ROW EXECUTE FUNCTION pi._trg_bindings_identity_guard();

DROP TRIGGER IF EXISTS trg_pi_observations_immutable ON pi.observations;
CREATE TRIGGER trg_pi_observations_immutable
  BEFORE UPDATE OR DELETE ON pi.observations
  FOR EACH ROW EXECUTE FUNCTION pi._trg_observations_immutable();

-- 4. Private role assertion helper and SECURITY DEFINER command/read functions
CREATE OR REPLACE FUNCTION pi._assert_session_role(p_allowed_roles text[])
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

  RAISE EXCEPTION 'Session role "%" is not authorized for this provider-ingress operation', session_user
    USING ERRCODE = '42501';
END;
$$;

CREATE OR REPLACE FUNCTION pi.cmd_binding_activate(
  p_binding_id uuid,
  p_binding_version bigint,
  p_expected_binding_version bigint,
  p_configuration_sha256 bytea,
  p_operator_reference text
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  v_root pi.bindings%ROWTYPE;
  v_ver pi.binding_versions%ROWTYPE;
  v_now timestamptz := pg_catalog.clock_timestamp();
BEGIN
  PERFORM pi._assert_session_role(ARRAY['provider_runtime']);

  SELECT * INTO v_root FROM pi.bindings WHERE id = p_binding_id FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'Provider binding not found' USING ERRCODE = 'P0002';
  END IF;
  IF v_root.version <> p_expected_binding_version THEN
    RAISE EXCEPTION 'Provider binding version precondition conflict' USING ERRCODE = '40001';
  END IF;

  SELECT * INTO v_ver
    FROM pi.binding_versions
   WHERE binding_id = p_binding_id AND binding_version = p_binding_version
   FOR UPDATE;
  IF NOT FOUND OR v_ver.configuration_sha256 <> p_configuration_sha256 THEN
    RAISE EXCEPTION 'Provider binding version or configuration digest mismatch' USING ERRCODE = '40001';
  END IF;

  IF v_ver.state NOT IN ('draft', 'active') THEN
    RAISE EXCEPTION 'Retired or revoked binding version cannot be activated' USING ERRCODE = '55000';
  END IF;

  IF v_ver.state = 'draft' THEN
    UPDATE pi.binding_versions
       SET state = 'active'
     WHERE binding_id = p_binding_id AND binding_version = p_binding_version;
  END IF;

  UPDATE pi.bindings
     SET provider = v_ver.provider,
         account_reference = v_ver.account_reference,
         account_mode = v_ver.account_mode,
         payload_profile = v_ver.payload_profile,
         secret_custody_reference = v_ver.secret_custody_reference,
         secret_version_reference = v_ver.secret_version_reference,
         state = 'active',
         relay_tenant_id = v_ver.relay_tenant_id,
         relay_project_id = v_ver.relay_project_id,
         publication_channel_id = v_ver.publication_channel_id,
         normalized_event_type_id = v_ver.normalized_event_type_id,
         normalized_schema_version = v_ver.normalized_schema_version,
         configuration_sha256 = v_ver.configuration_sha256,
         current_binding_version = p_binding_version,
         version = version + 1
   WHERE id = p_binding_id
   RETURNING * INTO v_root;

  INSERT INTO pi.audit_events (
    id, binding_id, action, actor_kind, actor_reference, prior_version, resulting_version, candidate_sha256, recorded_at, safe_facts
  ) VALUES (
    pg_catalog.gen_random_uuid(), p_binding_id, 'binding.activate', 'operator', p_operator_reference,
    p_expected_binding_version, v_root.version, p_configuration_sha256, v_now,
    pg_catalog.jsonb_build_object('binding_version', p_binding_version, 'provider', v_root.provider, 'account_mode', v_root.account_mode)
  );

  RETURN pg_catalog.jsonb_build_object(
    'outcome', 'activated',
    'binding_id', p_binding_id,
    'binding_version', p_binding_version,
    'root_version', v_root.version
  );
END;
$$;

CREATE OR REPLACE FUNCTION pi.cmd_receive_verified_callback(
  p_observation_id uuid,
  p_forward_intent_id uuid,
  p_binding_id uuid,
  p_binding_version bigint,
  p_provider text,
  p_account_mode text,
  p_payload_profile text,
  p_provider_event_id text,
  p_event_type text,
  p_object_reference text,
  p_provider_business_time timestamptz,
  p_raw_body_sha256 bytea,
  p_identity_profile text,
  p_semantic_key_sha256 bytea,
  p_normalized_facts jsonb,
  p_normalized_facts_sha256 bytea,
  p_business_key text,
  p_request_key text,
  p_prepared_bytes bytea,
  p_submission_sha256 bytea
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  v_bind pi.bindings%ROWTYPE;
  v_bver pi.binding_versions%ROWTYPE;
  v_trec pi.transport_receipts%ROWTYPE;
  v_sem pi.semantic_identities%ROWTYPE;
  v_now timestamptz := pg_catalog.clock_timestamp();
BEGIN
  PERFORM pi._assert_session_role(ARRAY['provider_runtime']);

  SELECT * INTO v_bind FROM pi.bindings WHERE id = p_binding_id FOR SHARE;
  IF NOT FOUND OR v_bind.state <> 'active' OR v_bind.current_binding_version IS DISTINCT FROM p_binding_version THEN
    RAISE EXCEPTION 'Provider binding inactive or superseded' USING ERRCODE = '55000';
  END IF;

  SELECT * INTO v_bver
    FROM pi.binding_versions
   WHERE binding_id = p_binding_id AND binding_version = p_binding_version
   FOR SHARE;
  IF NOT FOUND OR v_bver.state <> 'active'
     OR v_bver.provider <> p_provider
     OR v_bver.account_mode <> p_account_mode
     OR v_bver.payload_profile <> p_payload_profile THEN
    RAISE EXCEPTION 'Verified binding version mismatch' USING ERRCODE = '42501';
  END IF;

  PERFORM pg_catalog.pg_advisory_xact_lock(
    pg_catalog.hashtext(p_binding_id::text),
    pg_catalog.hashtext(pg_catalog.encode(p_raw_body_sha256, 'hex'))
  );
  PERFORM pg_catalog.pg_advisory_xact_lock(
    pg_catalog.hashtext(p_binding_id::text),
    pg_catalog.hashtext(p_identity_profile || ':' || pg_catalog.encode(p_semantic_key_sha256, 'hex'))
  );

  SELECT * INTO v_trec
    FROM pi.transport_receipts
   WHERE binding_id = p_binding_id AND raw_body_sha256 = p_raw_body_sha256
   FOR UPDATE;

  IF FOUND THEN
    UPDATE pi.transport_receipts
       SET receive_count = receive_count + 1,
           last_received_at = v_now,
           version = version + 1
     WHERE binding_id = p_binding_id AND raw_body_sha256 = p_raw_body_sha256;

    RETURN pg_catalog.jsonb_build_object(
      'outcome', 'already_accepted_transport',
      'observation_id', v_trec.observation_id,
      'binding_id', p_binding_id,
      'binding_version', p_binding_version
    );
  END IF;

  SELECT * INTO v_sem
    FROM pi.semantic_identities
   WHERE binding_id = p_binding_id
     AND identity_profile = p_identity_profile
     AND semantic_key_sha256 = p_semantic_key_sha256
   FOR UPDATE;

  IF FOUND THEN
    IF v_sem.normalized_facts_sha256 <> p_normalized_facts_sha256 THEN
      RAISE EXCEPTION 'SEMANTIC_IDENTITY_CONFLICT' USING ERRCODE = '23505';
    END IF;
    INSERT INTO pi.transport_receipts (
      binding_id, raw_body_sha256, observation_id, first_received_at, last_received_at, receive_count, version
    ) VALUES (
      p_binding_id, p_raw_body_sha256, v_sem.observation_id, v_now, v_now, 1, 1
    );
    RETURN pg_catalog.jsonb_build_object(
      'outcome', 'already_accepted_semantic',
      'observation_id', v_sem.observation_id,
      'binding_id', p_binding_id,
      'binding_version', p_binding_version
    );
  END IF;

  INSERT INTO pi.observations (
    id, binding_id, binding_version, provider, account_mode, payload_profile,
    provider_event_id, event_type, object_reference, provider_business_time,
    raw_body_sha256, normalized_facts, normalized_facts_sha256, state, received_at, version
  ) VALUES (
    p_observation_id, p_binding_id, p_binding_version, p_provider, p_account_mode, p_payload_profile,
    p_provider_event_id, p_event_type, p_object_reference, p_provider_business_time,
    p_raw_body_sha256, p_normalized_facts, p_normalized_facts_sha256, 'forward_pending', v_now, 1
  );

  INSERT INTO pi.transport_receipts (
    binding_id, raw_body_sha256, observation_id, first_received_at, last_received_at, receive_count, version
  ) VALUES (
    p_binding_id, p_raw_body_sha256, p_observation_id, v_now, v_now, 1, 1
  );

  INSERT INTO pi.semantic_identities (
    binding_id, identity_profile, semantic_key_sha256, normalized_facts_sha256, observation_id, created_at, version
  ) VALUES (
    p_binding_id, p_identity_profile, p_semantic_key_sha256, p_normalized_facts_sha256, p_observation_id, v_now, 1
  );

  INSERT INTO pi.forward_intents (
    id, observation_id, binding_id, binding_version, event_type_id, schema_version,
    business_key, request_key, prepared_bytes, submission_sha256, state, next_attempt_at, version
  ) VALUES (
    p_forward_intent_id, p_observation_id, p_binding_id, p_binding_version,
    v_bver.normalized_event_type_id, v_bver.normalized_schema_version,
    p_business_key, p_request_key, p_prepared_bytes, p_submission_sha256,
    'ready', v_now, 1
  );

  INSERT INTO pi.audit_events (
    id, binding_id, observation_id, action, actor_kind, actor_reference,
    prior_version, resulting_version, candidate_sha256, recorded_at, safe_facts
  ) VALUES (
    pg_catalog.gen_random_uuid(), p_binding_id, p_observation_id,
    'ingress.observation_accepted', 'runtime', p_binding_id::text,
    0, 1, p_normalized_facts_sha256, v_now,
    pg_catalog.jsonb_build_object('provider', p_provider, 'event_type', p_event_type, 'binding_version', p_binding_version)
  );

  RETURN pg_catalog.jsonb_build_object(
    'outcome', 'accepted',
    'observation_id', p_observation_id,
    'forward_intent_id', p_forward_intent_id,
    'binding_id', p_binding_id,
    'binding_version', p_binding_version
  );
END;
$$;

CREATE OR REPLACE FUNCTION pi.cmd_forward_claim(
  p_intent_id uuid,
  p_owner_instance_id uuid,
  p_lease_ms bigint DEFAULT 30000
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  v_int pi.forward_intents%ROWTYPE;
  v_now timestamptz := pg_catalog.clock_timestamp();
  v_expires timestamptz := v_now + (p_lease_ms::text || ' milliseconds')::interval;
BEGIN
  PERFORM pi._assert_session_role(ARRAY['provider_runtime']);

  SELECT * INTO v_int FROM pi.forward_intents WHERE id = p_intent_id FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'Forward intent not found' USING ERRCODE = 'P0002';
  END IF;

  IF v_int.state = 'accepted' THEN
    RETURN pg_catalog.jsonb_build_object(
      'outcome', 'already_accepted',
      'intent_id', v_int.id,
      'relay_event_id', v_int.relay_event_id,
      'relay_receipt_id', v_int.relay_receipt_id
    );
  END IF;

  IF v_int.state IN ('blocked', 'retired') THEN
    RETURN pg_catalog.jsonb_build_object('outcome', 'not_eligible', 'state', v_int.state);
  END IF;

  IF v_int.state = 'claimed' AND v_int.claim_expires_at > v_now THEN
    RETURN pg_catalog.jsonb_build_object('outcome', 'already_claimed');
  END IF;

  IF v_int.state IN ('ready', 'acceptance_unknown') AND v_int.next_attempt_at > v_now THEN
    RETURN pg_catalog.jsonb_build_object('outcome', 'not_due', 'next_attempt_at', v_int.next_attempt_at);
  END IF;

  UPDATE pi.forward_intents
     SET state = 'claimed',
         owner_instance_id = p_owner_instance_id,
         claim_generation = claim_generation + 1,
         claim_expires_at = v_expires,
         version = version + 1
   WHERE id = p_intent_id
   RETURNING * INTO v_int;

  RETURN pg_catalog.jsonb_build_object(
    'outcome', 'claimed',
    'intent_id', v_int.id,
    'observation_id', v_int.observation_id,
    'binding_id', v_int.binding_id,
    'binding_version', v_int.binding_version,
    'claim_generation', v_int.claim_generation,
    'claim_expires_at', v_int.claim_expires_at,
    'business_key', v_int.business_key,
    'request_key', v_int.request_key,
    'prepared_bytes_base64', pg_catalog.encode(v_int.prepared_bytes, 'base64')
  );
END;
$$;

CREATE OR REPLACE FUNCTION pi.cmd_forward_finalize(
  p_intent_id uuid,
  p_owner_instance_id uuid,
  p_expected_claim_generation bigint,
  p_outcome text,
  p_relay_event_id uuid DEFAULT NULL,
  p_relay_receipt_id uuid DEFAULT NULL,
  p_safe_error_code text DEFAULT NULL,
  p_next_attempt_at timestamptz DEFAULT NULL
)
RETURNS jsonb
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
  v_int pi.forward_intents%ROWTYPE;
  v_now timestamptz := pg_catalog.clock_timestamp();
BEGIN
  PERFORM pi._assert_session_role(ARRAY['provider_runtime']);

  SELECT * INTO v_int FROM pi.forward_intents WHERE id = p_intent_id FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'Forward intent not found' USING ERRCODE = 'P0002';
  END IF;

  IF v_int.state = 'accepted' THEN
    RETURN pg_catalog.jsonb_build_object(
      'outcome', 'already_accepted',
      'intent_id', v_int.id,
      'relay_event_id', v_int.relay_event_id,
      'relay_receipt_id', v_int.relay_receipt_id
    );
  END IF;

  IF v_int.state <> 'claimed'
     OR v_int.owner_instance_id IS DISTINCT FROM p_owner_instance_id
     OR v_int.claim_generation <> p_expected_claim_generation THEN
    RAISE EXCEPTION 'Stale forward claim owner or generation' USING ERRCODE = '55P03';
  END IF;

  IF p_outcome = 'accepted' THEN
    UPDATE pi.forward_intents
       SET state = 'accepted',
           owner_instance_id = NULL,
           claim_expires_at = NULL,
           relay_event_id = p_relay_event_id,
           relay_receipt_id = p_relay_receipt_id,
           safe_error_code = NULL,
           version = version + 1
     WHERE id = p_intent_id
     RETURNING * INTO v_int;

    UPDATE pi.observations
       SET state = 'forwarded', version = version + 1
     WHERE id = v_int.observation_id AND state IN ('accepted', 'forward_pending');

  ELSIF p_outcome = 'acceptance_unknown' THEN
    UPDATE pi.forward_intents
       SET state = 'acceptance_unknown',
           owner_instance_id = NULL,
           claim_expires_at = NULL,
           safe_error_code = p_safe_error_code,
           next_attempt_at = COALESCE(p_next_attempt_at, v_now + interval '5 seconds'),
           version = version + 1
     WHERE id = p_intent_id
     RETURNING * INTO v_int;

  ELSIF p_outcome = 'blocked' THEN
    UPDATE pi.forward_intents
       SET state = 'blocked',
           owner_instance_id = NULL,
           claim_expires_at = NULL,
           safe_error_code = COALESCE(p_safe_error_code, 'PUBLICATION_CONTEXT_CHANGED'),
           version = version + 1
     WHERE id = p_intent_id
     RETURNING * INTO v_int;

    UPDATE pi.observations
       SET state = 'quarantined', version = version + 1
     WHERE id = v_int.observation_id;
  ELSE
    UPDATE pi.forward_intents
       SET state = 'ready',
           owner_instance_id = NULL,
           claim_expires_at = NULL,
           safe_error_code = p_safe_error_code,
           next_attempt_at = COALESCE(p_next_attempt_at, v_now + interval '5 seconds'),
           version = version + 1
     WHERE id = p_intent_id
     RETURNING * INTO v_int;
  END IF;

  RETURN pg_catalog.jsonb_build_object(
    'outcome', p_outcome,
    'intent_id', v_int.id,
    'state', v_int.state,
    'relay_event_id', v_int.relay_event_id,
    'relay_receipt_id', v_int.relay_receipt_id
  );
END;
$$;

CREATE OR REPLACE FUNCTION pi.read_schema_migrations()
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
  PERFORM pi._assert_session_role(ARRAY['provider_runtime', 'provider_migrator']);
  RETURN QUERY
  SELECT m.migration_id, m.checksum, m.applied_at, m.source_reference, m.runner_version
    FROM pi.schema_migrations m
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
  IF v_is_super OR pg_catalog.pg_has_role(current_user, 'provider_owner', 'MEMBER') THEN
    FOR v_rec IN
      SELECT n.nspname, c.relname, c.relkind
        FROM pg_catalog.pg_class c
        JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
       WHERE n.nspname = 'pi'
         AND c.relkind IN ('r', 'p', 'v', 'S')
         AND pg_catalog.pg_get_userbyid(c.relowner) <> 'provider_owner'
    LOOP
      IF v_rec.relkind = 'S' THEN
        EXECUTE pg_catalog.format('ALTER SEQUENCE %I.%I OWNER TO provider_owner', v_rec.nspname, v_rec.relname);
      ELSIF v_rec.relkind = 'v' THEN
        EXECUTE pg_catalog.format('ALTER VIEW %I.%I OWNER TO provider_owner', v_rec.nspname, v_rec.relname);
      ELSE
        EXECUTE pg_catalog.format('ALTER TABLE %I.%I OWNER TO provider_owner', v_rec.nspname, v_rec.relname);
      END IF;
    END LOOP;

    FOR v_rec IN
      SELECT p.proname, pg_catalog.pg_get_function_identity_arguments(p.oid) AS args
        FROM pg_catalog.pg_proc p
        JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
       WHERE n.nspname = 'pi'
         AND pg_catalog.pg_get_userbyid(p.proowner) <> 'provider_owner'
    LOOP
      EXECUTE pg_catalog.format('ALTER FUNCTION pi.%I(%s) OWNER TO provider_owner', v_rec.proname, v_rec.args);
    END LOOP;

    IF current_user <> 'provider_owner' AND pg_catalog.pg_has_role(current_user, 'provider_owner', 'MEMBER') THEN
      EXECUTE 'SET ROLE provider_owner';
      v_switched := true;
    END IF;

    EXECUTE 'ALTER DEFAULT PRIVILEGES FOR ROLE provider_owner IN SCHEMA pi REVOKE ALL ON TABLES FROM PUBLIC';
    EXECUTE 'ALTER DEFAULT PRIVILEGES FOR ROLE provider_owner IN SCHEMA pi REVOKE ALL ON SEQUENCES FROM PUBLIC';
    EXECUTE 'ALTER DEFAULT PRIVILEGES FOR ROLE provider_owner IN SCHEMA pi REVOKE ALL ON FUNCTIONS FROM PUBLIC';

    IF v_switched THEN
      EXECUTE pg_catalog.format('SET ROLE %I', v_prev_role);
    END IF;
  END IF;
END
$$;

REVOKE ALL ON SCHEMA pi FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA pi FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA pi FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA pi FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA pi FROM provider_runtime, provider_migrator;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA pi FROM provider_runtime, provider_migrator;

GRANT USAGE ON SCHEMA pi TO provider_runtime, provider_migrator;

GRANT SELECT ON
  pi.schema_migrations,
  pi.bindings,
  pi.binding_versions,
  pi.observations,
  pi.transport_receipts,
  pi.semantic_identities,
  pi.forward_intents,
  pi.audit_events
TO provider_runtime;

GRANT EXECUTE ON FUNCTION pi.cmd_binding_activate(uuid, bigint, bigint, bytea, text) TO provider_runtime;
GRANT EXECUTE ON FUNCTION pi.cmd_receive_verified_callback(
  uuid, uuid, uuid, bigint, text, text, text, text, text, text, timestamptz, bytea, text, bytea, jsonb, bytea, text, text, bytea, bytea
) TO provider_runtime;
GRANT EXECUTE ON FUNCTION pi.cmd_forward_claim(uuid, uuid, bigint) TO provider_runtime;
GRANT EXECUTE ON FUNCTION pi.cmd_forward_finalize(uuid, uuid, bigint, text, uuid, uuid, text, timestamptz) TO provider_runtime;
GRANT EXECUTE ON FUNCTION pi.read_schema_migrations() TO provider_runtime, provider_migrator;
