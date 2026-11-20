-- Provider Ingress Migration 0002: Outbox forward intents and safe operational audit log.

CREATE TABLE IF NOT EXISTS pi.forward_intents (
  id uuid PRIMARY KEY,
  observation_id uuid NOT NULL UNIQUE,
  binding_id uuid NOT NULL,
  binding_version bigint NOT NULL CHECK (binding_version >= 1),
  event_type_id uuid NOT NULL,
  schema_version integer NOT NULL CHECK (schema_version >= 1),
  business_key text NOT NULL CHECK (pg_catalog.octet_length(business_key) BETWEEN 1 AND 256),
  request_key text NOT NULL CHECK (pg_catalog.octet_length(request_key) BETWEEN 1 AND 256),
  prepared_bytes bytea NOT NULL CHECK (pg_catalog.octet_length(prepared_bytes) BETWEEN 2 AND 131072),
  submission_sha256 bytea NOT NULL CHECK (pg_catalog.octet_length(submission_sha256) = 32),
  state text NOT NULL CHECK (state IN ('ready', 'claimed', 'acceptance_unknown', 'accepted', 'blocked', 'retired')),
  owner_instance_id uuid NULL,
  claim_generation bigint NOT NULL DEFAULT 0 CHECK (claim_generation >= 0),
  claim_expires_at timestamptz NULL,
  relay_event_id uuid NULL,
  relay_receipt_id uuid NULL,
  safe_error_code text NULL,
  next_attempt_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  version bigint NOT NULL DEFAULT 1 CHECK (version >= 1),
  FOREIGN KEY (observation_id, binding_id, binding_version)
    REFERENCES pi.observations(id, binding_id, binding_version),
  CONSTRAINT chk_pi_forward_intents_claim_state CHECK (
    (state = 'claimed' AND owner_instance_id IS NOT NULL AND claim_expires_at IS NOT NULL AND claim_generation >= 1)
    OR (state <> 'claimed' AND owner_instance_id IS NULL AND claim_expires_at IS NULL)
  )
);

CREATE TABLE IF NOT EXISTS pi.audit_events (
  id uuid PRIMARY KEY,
  binding_id uuid NULL REFERENCES pi.bindings(id),
  observation_id uuid NULL REFERENCES pi.observations(id),
  action text NOT NULL CHECK (pg_catalog.length(action) BETWEEN 1 AND 128),
  actor_kind text NOT NULL CHECK (actor_kind IN ('operator', 'runtime', 'system')),
  actor_reference text NOT NULL CHECK (pg_catalog.octet_length(actor_reference) BETWEEN 1 AND 256),
  prior_version bigint NULL CHECK (prior_version IS NULL OR prior_version >= 0),
  resulting_version bigint NULL CHECK (resulting_version IS NULL OR resulting_version >= 0),
  candidate_sha256 bytea NULL CHECK (candidate_sha256 IS NULL OR pg_catalog.octet_length(candidate_sha256) = 32),
  recorded_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  safe_facts jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (pg_catalog.jsonb_typeof(safe_facts) = 'object')
);
