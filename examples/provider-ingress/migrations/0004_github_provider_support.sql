-- Provider Ingress Migration 0004: Expand allowed providers to include GitHub webhook ingress (github.push.v1).

ALTER TABLE pi.bindings
  DROP CONSTRAINT IF EXISTS bindings_provider_check,
  ADD CONSTRAINT bindings_provider_check CHECK (provider IN ('stripe', 'paystack', 'github'));

ALTER TABLE pi.binding_versions
  DROP CONSTRAINT IF EXISTS binding_versions_provider_check,
  ADD CONSTRAINT binding_versions_provider_check CHECK (provider IN ('stripe', 'paystack', 'github'));

ALTER TABLE pi.observations
  DROP CONSTRAINT IF EXISTS observations_provider_check,
  ADD CONSTRAINT observations_provider_check CHECK (provider IN ('stripe', 'paystack', 'github'));
