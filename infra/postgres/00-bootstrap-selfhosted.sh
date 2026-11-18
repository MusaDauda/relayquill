#!/bin/sh
set -eu

# Bootstrap isolated Relayquill authorities (rq, rc, pi) and scoped SCRAM-SHA-256 roles.
# Reads role credentials from mounted secret files under /run/secrets/pg_password_<role>.

read_secret_or_fail() {
  role_name="$1"
  secret_file="/run/secrets/pg_password_${role_name}"
  if [ ! -r "$secret_file" ]; then
    echo "Missing readable secret file for PostgreSQL role ${role_name}: ${secret_file}" >&2
    exit 1
  fi
  tr -d '\r\n' < "$secret_file"
}

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname postgres <<'SQL'
DO $$
DECLARE r text;
BEGIN
  FOREACH r IN ARRAY ARRAY['rq_owner', 'receiver_owner', 'provider_owner'] LOOP
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r) THEN
      EXECUTE format('CREATE ROLE %I NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS', r);
    END IF;
  END LOOP;
  FOREACH r IN ARRAY ARRAY[
    'rq_api', 'rq_relay', 'rq_fanout', 'rq_sender', 'rq_coordinator',
    'rq_reporter', 'rq_signing_issuer', 'rq_migrator', 'rq_recovery',
    'receiver_migrator', 'receiver_runtime',
    'provider_migrator', 'provider_runtime'
  ] LOOP
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r) THEN
      EXECUTE format('CREATE ROLE %I LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS', r);
    END IF;
  END LOOP;
END
$$;

GRANT rq_owner TO rq_migrator;
GRANT receiver_owner TO receiver_migrator;
GRANT provider_owner TO provider_migrator;
SQL

for role_name in \
  rq_api rq_relay rq_fanout rq_sender rq_coordinator \
  rq_reporter rq_signing_issuer rq_migrator rq_recovery \
  receiver_migrator receiver_runtime \
  provider_migrator provider_runtime
do
  pw="$(read_secret_or_fail "$role_name")"
  psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname postgres \
    -v target_role="$role_name" -v target_pw="$pw" <<'SQL'
SELECT format('ALTER ROLE %I WITH PASSWORD %L', :'target_role', :'target_pw') \gexec
SQL
done

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname postgres <<'SQL'
SELECT format('CREATE DATABASE %I OWNER %I', 'relayquill', 'rq_owner')
WHERE NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = 'relayquill') \gexec
ALTER DATABASE relayquill OWNER TO rq_owner;

SELECT format('CREATE DATABASE %I OWNER %I', 'relayquill_receiver', 'receiver_owner')
WHERE NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = 'relayquill_receiver') \gexec

SELECT format('CREATE DATABASE %I OWNER %I', 'relayquill_provider', 'provider_owner')
WHERE NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = 'relayquill_provider') \gexec

REVOKE ALL ON DATABASE relayquill FROM PUBLIC;
REVOKE ALL ON DATABASE relayquill_receiver FROM PUBLIC;
REVOKE ALL ON DATABASE relayquill_provider FROM PUBLIC;

GRANT CONNECT ON DATABASE relayquill TO
  rq_api, rq_relay, rq_fanout, rq_sender, rq_coordinator,
  rq_reporter, rq_signing_issuer, rq_migrator, rq_recovery;
GRANT CONNECT ON DATABASE relayquill_receiver TO receiver_migrator, receiver_runtime;
GRANT CONNECT ON DATABASE relayquill_provider TO provider_migrator, provider_runtime;
SQL

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname relayquill <<'SQL'
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
CREATE SCHEMA IF NOT EXISTS rq AUTHORIZATION rq_owner;
CREATE SCHEMA IF NOT EXISTS rq_support AUTHORIZATION rq_owner;
CREATE SCHEMA IF NOT EXISTS rq_recovery AUTHORIZATION rq_owner;
CREATE EXTENSION IF NOT EXISTS btree_gist WITH SCHEMA rq_support;
SQL

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname relayquill_receiver <<'SQL'
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
CREATE SCHEMA IF NOT EXISTS rc AUTHORIZATION receiver_owner;
SQL

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname relayquill_provider <<'SQL'
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
CREATE SCHEMA IF NOT EXISTS pi AUTHORIZATION provider_owner;
SQL
