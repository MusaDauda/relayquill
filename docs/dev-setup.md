# Local Development Setup

Relayquill supports three local development workflows, ordered from zero external daemons to optional remote hosted development endpoints:

1. **Zero-Daemon Mode (`portable_pglite`)**: Uses `@electric-sql/pglite` (in-memory PostgreSQL with `btree_gist`) and the in-memory JetStream harness. Ideal for unit, contract, migration, and E2E verification without Docker.
2. **Containerized Local Stack (`development_trusted_local`)**: Runs standard PostgreSQL 18, NATS JetStream, and an OpenTelemetry collector locally via `infra/compose.dev.yaml` bound strictly to `127.0.0.1`.
3. **Optional Remote Dev Endpoints (`.env`)**: Connects local processes to hosted Neon, Supabase, or Synadia Cloud developer instances solely for zero-install remote testing. **(Never used in production; see [self-hosted-production.md](./self-hosted-production.md).)**

---

## 1. Prerequisites

- **Node.js**: `>= 24.16.0 < 27` (pinned in `.node-version` as `24.16.0`)
- **npm**: `11.13.0` (workspaces enabled)
- **Go**: `1.27.1` (only required for building or testing `tools/broker-launcher`)
- **Docker & Docker Compose v2+**: optional, required only for `infra/compose.dev.yaml` or building container images

Install dependencies and verify workspace boundaries, types, lint, and hygiene:

```bash
npm ci
npm run boundaries
npm run typecheck
npm run lint
npm run build
npm run hygiene
```

---

## 2. Zero-Daemon Mode (`portable_pglite`)

No Docker daemon, external PostgreSQL server, or NATS server is required to run the workspace test suites or E2E harness:

```bash
npm test
node tests/e2e/harness/harness.smoke.test.mjs
```

`tests/e2e/harness/stack.mjs` provisions isolated in-memory `PGlite` databases (`rq`, `rc`, `pi`), the deterministic `InMemoryJetStreamBroker`, local HTTP/TLS receiver doubles, and platform-native protected IPC probes (Win32 Named Pipes with `SetSecurityInfo` DACL on Windows; `0700`/`0600` Unix domain sockets on Linux/macOS).

Role configurations for this mode live in `config/portable.*.json` and strictly avoid external network credentials.

---

## 3. Containerized Trusted-Local Dev Stack (`infra/compose.dev.yaml`)

When developing against real TCP PostgreSQL 18, real NATS JetStream, and local OpenTelemetry traces:

### Start Backing Services

```bash
docker compose -f infra/compose.dev.yaml config --quiet
docker compose -f infra/compose.dev.yaml up -d db broker
# Optional: include OTel collector on 127.0.0.1:14317 (gRPC) / 14318 (HTTP)
docker compose -f infra/compose.dev.yaml up -d otel-collector
```

Bound loopback endpoints:
- **PostgreSQL 18 (`postgres:18-bookworm`)**: `127.0.0.1:55005` (`POSTGRES_HOST_AUTH_METHOD: trust`, fixture-only)
- **NATS JetStream (`nats:2-alpine`)**: `127.0.0.1:14225` (client), `127.0.0.1:18225` (HTTP monitoring `/healthz`)
- **OTel Collector**: `127.0.0.1:14317` (OTLP gRPC), `127.0.0.1:14318` (OTLP HTTP)

### Bootstrap Scoped Roles & Databases (Trusted Local)

Create the isolated `rq`, `rc`, and `pi` databases and non-superuser roles without reusing `postgres` for application traffic:

```bash
docker compose -f infra/compose.dev.yaml exec -T db psql -U postgres -d postgres -v ON_ERROR_STOP=1 <<'SQL'
DO $$
DECLARE role_name text;
BEGIN
  FOREACH role_name IN ARRAY ARRAY['rq_owner', 'receiver_owner', 'provider_owner'] LOOP
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = role_name) THEN
      EXECUTE format('CREATE ROLE %I NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS', role_name);
    END IF;
  END LOOP;
  FOREACH role_name IN ARRAY ARRAY[
    'rq_api', 'rq_relay', 'rq_fanout', 'rq_sender', 'rq_coordinator',
    'rq_reporter', 'rq_signing_issuer', 'rq_migrator', 'rq_recovery',
    'receiver_migrator', 'receiver_runtime',
    'provider_migrator', 'provider_runtime'
  ] LOOP
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = role_name) THEN
      EXECUTE format('CREATE ROLE %I LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS', role_name);
    END IF;
  END LOOP;
END
$$;

GRANT rq_owner TO rq_migrator;
GRANT receiver_owner TO receiver_migrator;
GRANT provider_owner TO provider_migrator;

ALTER DATABASE relayquill OWNER TO rq_owner;
SELECT format('CREATE DATABASE %I OWNER %I', 'relayquill_receiver', 'receiver_owner')
WHERE NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = 'relayquill_receiver') \gexec
SELECT format('CREATE DATABASE %I OWNER %I', 'relayquill_provider', 'provider_owner')
WHERE NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = 'relayquill_provider') \gexec

REVOKE ALL ON DATABASE relayquill FROM PUBLIC;
REVOKE ALL ON DATABASE relayquill_receiver FROM PUBLIC;
REVOKE ALL ON DATABASE relayquill_provider FROM PUBLIC;

GRANT CONNECT ON DATABASE relayquill TO rq_api, rq_relay, rq_fanout, rq_sender, rq_coordinator, rq_reporter, rq_signing_issuer, rq_migrator, rq_recovery;
GRANT CONNECT ON DATABASE relayquill_receiver TO receiver_migrator, receiver_runtime;
GRANT CONNECT ON DATABASE relayquill_provider TO provider_migrator, provider_runtime;
SQL

docker compose -f infra/compose.dev.yaml exec -T db psql -U postgres -d relayquill -v ON_ERROR_STOP=1 -c \
  "REVOKE CREATE ON SCHEMA public FROM PUBLIC; CREATE SCHEMA IF NOT EXISTS rq AUTHORIZATION rq_owner; CREATE SCHEMA IF NOT EXISTS rq_support AUTHORIZATION rq_owner; CREATE SCHEMA IF NOT EXISTS rq_recovery AUTHORIZATION rq_owner; CREATE EXTENSION IF NOT EXISTS btree_gist WITH SCHEMA rq_support;"

docker compose -f infra/compose.dev.yaml exec -T db psql -U postgres -d relayquill_receiver -v ON_ERROR_STOP=1 -c \
  "REVOKE CREATE ON SCHEMA public FROM PUBLIC; CREATE SCHEMA IF NOT EXISTS rc AUTHORIZATION receiver_owner;"

docker compose -f infra/compose.dev.yaml exec -T db psql -U postgres -d relayquill_provider -v ON_ERROR_STOP=1 -c \
  "REVOKE CREATE ON SCHEMA public FROM PUBLIC; CREATE SCHEMA IF NOT EXISTS pi AUTHORIZATION provider_owner;"
```

### Run Migrations, Broker Ensure & Dev Processes

Run migrations, start the local fixture secret provider, ensure JetStream streams, and start each role in its own terminal (using `config/development.*.json`):

```bash
# 1. Start local protected IPC secret provider
npm run start --workspace @relayquill/admin -- --config config/development.provider.json provider serve

# 2. Apply migrations (rq, rc, pi) and ensure JetStream stream/consumer
npm run start --workspace @relayquill/admin -- --config config/development.admin.json db migrate
npm run start --workspace @relayquill/admin -- --config config/development.admin.json broker ensure
npm run start --workspace @relayquill/example-receiver -- --config config/development.receiver-migrator.json db migrate
npm run start --workspace @relayquill/example-provider-ingress -- --config config/development.provider-ingress-migrator.json db migrate

# 3. Start application workers + console (each in its own terminal)
npm run start --workspace @relayquill/api -- --config config/development.api.json
npm run start --workspace @relayquill/relay -- --config config/development.relay.json
npm run start --workspace @relayquill/fanout -- --config config/development.fanout.json
npm run start --workspace @relayquill/sender -- --config config/development.sender.json
npm run start --workspace @relayquill/coordinator -- --config config/development.coordinator.json
npm run start --workspace @relayquill/example-receiver -- --config config/development.receiver.json serve
npm run start --workspace @relayquill/example-provider-ingress -- --config config/development.provider-ingress.json serve
npm run dev --workspace @relayquill/console -- --host localhost --port 5205 --strictPort
```

> **Note on Console Origin & Passkeys:** Always open the console at `http://localhost:5205` (not `127.0.0.1:5205`) so WebAuthn RP ID (`localhost`), allowed origin, and Vite's `/api` proxy to `http://127.0.0.1:8005` align.

When stopping the local backing containers, preserve durable volumes with `stop` (avoid `down -v` unless intentionally resetting):

```bash
docker compose -f infra/compose.dev.yaml stop db broker otel-collector
```

---

## 4. Optional Remote Dev Endpoints (`.env`)

For contributors who prefer not to run local PostgreSQL or NATS containers during development, Relayquill provides optional `.env`-configured templates for remote developer databases and brokers. These templates use standard `pg` and `@nats-io/transport-node` drivers—no proprietary vendor SDKs are installed.

Copy `.env.example` to `.env` (never commit `.env` to Git) and configure one of the optional dev profiles:

- **Neon Remote Dev (`config/hosted.neon.*.json`)**:
  - Set role passwords referenced by `password_secret_ref` (`env:RELAYQUILL_NEON_PASSWORD_RQ_API`, etc.) or `DATABASE_URL` / `DIRECT_DATABASE_URL` in `.env` (`sslmode=verify-full`).
  - Use direct connections (`pool_mode: direct`) for `migrator` and `coordinator`, and pooler endpoints (`connection_timeout_ms >= 10000` for cold-start wakeups) for `api`/`sender`.
- **Supabase Remote Dev (`config/hosted.supabase.*.json`)**:
  - Uses `isolation: "shared_database_schemas"` (`database: "postgres"`, schemas `rq`, `rc`, `pi`, and `support_schema: "extensions"`).
  - Set `RELAYQUILL_SUPABASE_PASSWORD_*` variables in `.env` and ensure the Supabase CA root is available at `certs/supabase-prod-ca-2021.crt`.
- **Synadia Cloud NGS Remote Dev (`config/hosted.synadia.*.json`)**:
  - Set `NATS_CREDS_FILE` / `RELAYQUILL_NATS_CREDS_*` in `.env` pointing to your developer `.creds` JWT file (`handshake_first: false`, `tls://connect.ngs.global`).

> **Production Policy:** Neon, Supabase, and Synadia Cloud are documented **strictly for remote developer convenience**. Production deployments must run 100% self-hosted infrastructure (`infra/compose.prod.yaml` or `infra/kubernetes/overlays/selfhosted/`) with zero managed-service dependencies.

---

## 5. Stripe & Paystack Test-Mode Callbacks

To exercise `examples/provider-ingress` locally:

1. Configure test-only secrets in `.env` (or inject via the local IPC fixture provider — never commit real or sandbox credentials):
   - `STRIPE_WEBHOOK_SECRET` (from `stripe listen --print-secret` or local test fixture)
   - `PAYSTACK_TEST_SECRET_KEY` (Paystack test-mode secret key for `x-paystack-signature` HMAC-SHA512 verification)
2. Ensure `account_mode` in `pi.bindings` is set strictly to `test`.
3. Note that Stripe (`Stripe-Signature` with 300s timestamp tolerance) and Paystack (`x-paystack-signature` raw-body SHA-512 HMAC without transport timestamp) are strictly separated from Relayquill's outbound `rq.webhook-signature.v1` contract.
