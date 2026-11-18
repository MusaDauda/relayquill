# Self-Hosted Production Deployment Guide

Relayquill is engineered for **100% self-hostable production operation** on standard open-source infrastructure with **zero reliance on managed databases, proprietary message brokers, or cloud-only locking services**.

Core production components:
- **PostgreSQL 18** (`postgres:18-bookworm` or native OS install) with native TLS (`ssl=on`), `SCRAM-SHA-256`, and scoped non-superuser roles
- **3-Node NATS JetStream Quorum** (`tools/broker-launcher` / `relayquill-broker`) with native client TLS, cluster route mTLS, and Ed25519 NKey principal ACLs
- **Node 24 LTS Workers** (`api`, `relay`, `fanout`, `sender`, `coordinator`, `admin`) running non-root (`uid 10001`) with read-only root filesystems
- **Static Console Reverse Proxy** (non-root Nginx `uid 101`) serving the React console and proxying `/api/` on the same origin

---

## 1. Prerequisites & Security Model

- **No committed secrets**: All passwords, TLS private keys, NKey seeds, and signing keys reside outside Git in untracked secret mounts (`/run/secrets/...` or Kubernetes Secrets) and never inside JSON configs or container images.
- **No automatic migration on startup**: Database migrations (`migrations/0001..0009`) and JetStream stream/consumer provisioning (`broker ensure`) are invoked explicitly via the `admin` role (`rq_migrator` + `broker_admin`).
- **HTTPS Origin Required**: WebAuthn passkeys and `__Host-rq_session` cookies require an HTTPS reverse proxy (e.g., Nginx, Caddy, or Traefik) terminating TLS 1.2/1.3 in front of `console:8080` on your chosen public domain (`console.relayquill.example`).

---

## 2. Generate TLS Certificates & NKey Identities

### Step A — Generate PostgreSQL & Broker PKI

Use `infra/scripts/generate-selfhosted-certs.sh` on a secure operator workstation to create separate root CAs for PostgreSQL (`postgres-ca.pem`), Broker Client TLS (`broker-ca.pem`), and Broker Cluster Route mTLS (`broker-cluster-ca.pem`), plus SAN-verified server/peer certificates:

```bash
./infra/scripts/generate-selfhosted-certs.sh ./infra/secrets/certs
```

Set restrictive ownership on private keys matching container UIDs:
- `postgres-server.key`: owner `999:999`, mode `0600`
- `broker-{1,2,3}-server.key` and `broker-{1,2,3}-route.key`: owner `65532:65532`, mode `0400`

### Step B — Generate NKey Identities (`nk`)

Generate distinct Ed25519 NKey pairs (`-gen user`) for `relay`, `fanout`, and `broker_admin`. Keep private seeds (`SU...`) strictly in secret storage and store only public keys (`U...`) for the broker topology:

```bash
mkdir -p ./infra/secrets/broker-keys
chmod 700 ./infra/secrets/broker-keys

for principal in relay fanout admin; do
  nk -gen user -pubout > "./infra/secrets/broker-keys/${principal}.keypair"
  grep '^SU' "./infra/secrets/broker-keys/${principal}.keypair" > "./infra/secrets/nats_rq_${principal}_nkey.seed"
  grep '^U'  "./infra/secrets/broker-keys/${principal}.keypair" > "./infra/secrets/broker-keys/${principal}.pub"
  rm -f "./infra/secrets/broker-keys/${principal}.keypair"
  chmod 0440 "./infra/secrets/nats_rq_${principal}_nkey.seed"
  chmod 0444 "./infra/secrets/broker-keys/${principal}.pub"
done
```

### Step C — Generate Scoped Database Passwords & Runtime Secrets

Create high-entropy random secrets (`openssl rand -base64 32 | tr -d '\n'`) with mode `0440` under `./infra/secrets/` for each isolated PostgreSQL role and runtime secret:
- `pg_superuser_password`
- `pg_password_rq_{api,relay,fanout,sender,coordinator,reporter,signing_issuer,migrator,recovery}`
- `pg_password_receiver_{migrator,runtime}`
- `pg_password_provider_{migrator,runtime}`
- `auth_session_hmac`
- `endpoint_signing_keys`

For Docker Compose on Linux, ensure `pg_password_*` files mounted into `postgres` are readable by `uid 999` (`0440` or `0400` owned by `999`) and files mounted into `application` containers are readable by `uid 10001`.

---

## 3. Option A — Self-Hosted Docker Compose (`infra/compose.prod.yaml`)

1. **Validate Compose & Build Local Images**:
   ```bash
   docker compose -f infra/compose.prod.yaml config --quiet
   docker compose -f infra/compose.prod.yaml build
   ```
   Verify built images run non-root (`10001`, `101`, `65532`):
   ```bash
   docker image inspect relayquill-app:local --format '{{.Config.User}}'
   docker image inspect relayquill-console:local --format '{{.Config.User}}'
   docker image inspect relayquill-broker:local --format '{{.Config.User}}'
   ```

2. **Start Data & Quorum Backing Services**:
   ```bash
   docker compose -f infra/compose.prod.yaml up -d postgres broker-1 broker-2 broker-3
   docker compose -f infra/compose.prod.yaml ps
   ```
   Confirm `postgres` is healthy and all three broker nodes pass `/healthz` (`8222`).

3. **Run One-Shot Schema Migrations & Broker Stream Setup**:
   ```bash
   docker compose -f infra/compose.prod.yaml --profile ops run --rm migrate-db
   docker compose -f infra/compose.prod.yaml --profile ops run --rm ensure-broker
   ```

4. **Start Application Workers & Console Proxy**:
   ```bash
   docker compose -f infra/compose.prod.yaml up -d api relay fanout sender coordinator console
   ```

5. **Configure Public HTTPS TLS Termination**:
   Point your reverse proxy (Caddy/Nginx/HAProxy on the host) from `https://console.relayquill.example` to `http://127.0.0.1:8080`, preserving `Host`, `X-Forwarded-Proto: https`, `X-Forwarded-For`, and a `120s` idle/read timeout with response buffering disabled for SSE (`/api/v1/events/watch`). Update `public_origin`, `rp_id`, and `allowed_origins` in `config/selfhosted.api.json` to match your domain.

---

## 4. Option B — Self-Hosted Kubernetes (`infra/kubernetes/overlays/selfhosted/`)

This overlay runs on any conformant self-hosted Kubernetes cluster (kubeadm, k3s, Talos, bare-metal, or any cloud Kubernetes) with zero AWS/EKS dependencies.

### Prerequisites
- A CNI plugin enforcing `NetworkPolicy` (e.g., Cilium or Calico)
- A `StorageClass` supporting `ReadWriteOnce` persistent volumes (`pgdata` + 3× `jetstream-data`)
- `ingress-nginx` (or equivalent Ingress controller labeled `relayquill.example/ingress-controller: "true"` on its namespace)

### Deployment Steps

1. **Create Namespaces First**:
   ```bash
   kubectl apply -f infra/kubernetes/base/namespaces.yaml
   kubectl apply -f infra/kubernetes/overlays/selfhosted/namespace-data.yaml
   ```

2. **Provision Non-Committed Secrets & Public CA ConfigMaps Out-of-Band**:
   Create the scoped Kubernetes `Secret` and `ConfigMap` objects directly from your generated `./infra/secrets/` directory (never commit Secret YAML into Git):
   - In `relayquill-data`:
     - `Secret` `relayquill-pg-tls` (`tls.crt`, `tls.key`, `ca.crt`)
     - `Secret` `relayquill-pg-passwords` (`pg_superuser_password`, `pg_password_*`)
     - `Secret` `relayquill-broker-server-tls` (`tls.crt`, `tls.key`, `ca.crt`)
     - `Secret` `relayquill-broker-route-tls` (`tls.crt`, `tls.key`, `ca.crt`)
     - `Secret` `relayquill-broker-private-keys` (`server.key`, `route.key`)
     - `ConfigMap` `relayquill-broker-public-nkeys` (`relay.pub`, `fanout.pub`, `admin.pub`)
   - In `relayquill-app`:
     - `ConfigMap` `relayquill-ca-bundles` (`postgres-ca.pem`, `broker-ca.pem`)
     - Scoped role secrets: `relayquill-api-secrets`, `relayquill-relay-secrets`, `relayquill-fanout-secrets`, `relayquill-sender-secrets`, `relayquill-coordinator-secrets`, `relayquill-migrator-secrets`, `relayquill-recovery-secrets`
     - `Secret` `relayquill-public-tls` (Ingress HTTPS cert/key)
   - In `relayquill-receiver` & `relayquill-ingress`:
     - `ConfigMap` `relayquill-receiver-ca-bundles` & `relayquill-ingress-ca-bundles`
     - `Secret` `relayquill-receiver-secrets`, `relayquill-receiver-migrator-secrets`, `relayquill-ingress-secrets`, `relayquill-ingress-migrator-secrets`

3. **Review & Apply Rendered Manifests**:
   Update image references in `infra/kubernetes/overlays/selfhosted/kustomization.yaml` (or via `kustomize edit set image`) to pinned registry digests (`@sha256:...`), then preview and apply:
   ```bash
   kubectl kustomize infra/kubernetes/overlays/selfhosted > /tmp/relayquill-rendered.yaml
   kubectl apply -k infra/kubernetes/overlays/selfhosted
   ```

4. **Wait for Data & Quorum StatefulSets, Then Run Migration Jobs**:
   ```bash
   kubectl rollout status statefulset/relayquill-postgres -n relayquill-data --timeout=180s
   kubectl rollout status statefulset/relayquill-broker -n relayquill-data --timeout=180s
   kubectl apply -f infra/kubernetes/jobs/migrate.yaml
   kubectl wait --for=condition=complete job/relayquill-migrate-rq -n relayquill-app --timeout=120s
   kubectl wait --for=condition=complete job/relayquill-broker-ensure -n relayquill-app --timeout=120s
   ```

5. **Verify Workloads & Rolling Upgrades**:
   ```bash
   kubectl rollout status deployment/relayquill-api -n relayquill-app --timeout=180s
   kubectl rollout status deployment/relayquill-relay -n relayquill-app --timeout=180s
   kubectl rollout status deployment/relayquill-fanout -n relayquill-app --timeout=180s
   kubectl rollout status deployment/relayquill-sender -n relayquill-app --timeout=180s
   kubectl rollout status deployment/relayquill-coordinator -n relayquill-app --timeout=180s
   kubectl rollout status deployment/relayquill-console -n relayquill-app --timeout=180s
   ```
   When upgrading the broker quorum, roll `relayquill-broker` pods one ordinal at a time and verify `2/3` Raft quorum health between restarts (`PodDisruptionBudget` enforces `minAvailable: 2`).

---

## 5. Production Negative Verification Checklist

Before enabling external admission or webhook dispatch in production, verify these controls fail closed:
- **Database TLS & Role Isolation**: Plaintext Postgres connections reject (`host ... reject` in `pg_hba.conf`); `rq_api` cannot read `rq_recovery` tables or connect to `relayquill_receiver` (`rc`) or `relayquill_provider` (`pi`).
- **Broker TLS & Principal ACLs**: Plaintext NATS connections and untrusted CA certs fail; `relay` cannot subscribe to `_INBOX.rq.fanout.>` or pull JetStream consumers; `fanout` cannot publish to `rq.events.*.accepted`.
- **Egress Pinning**: `sender` rejects `https://127.0.0.1`, `https://169.254.169.254`, `http://receiver.fixture.test:19095`, and any hostname returning a private/reserved DNS record before opening a socket.
- **No Raw Secrets in Logs or Configs**: Run `npm run hygiene` and confirm zero secret keys or credentials appear in `config/`, `infra/`, or container logs.
