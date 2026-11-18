#!/usr/bin/env bash
set -euo pipefail

# Generates local self-hosted TLS certificates (PostgreSQL CA/server, Broker Client CA/servers,
# Broker Cluster Route mTLS CA/certs) into an operator-owned untracked output directory.
# Requires openssl >= 1.1.1. Never commit generated keys or certs to Git.

OUT_DIR="${1:-./infra/secrets/certs}"
DAYS="${DAYS:-365}"

mkdir -p "$OUT_DIR"
chmod 700 "$OUT_DIR"

create_ca() {
  local name="$1"
  local cn="$2"
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "${OUT_DIR}/${name}.key"
  chmod 600 "${OUT_DIR}/${name}.key"
  openssl req -x509 -new -nodes -key "${OUT_DIR}/${name}.key" -sha256 -days "$DAYS" \
    -subj "/CN=${cn}" -out "${OUT_DIR}/${name}.pem"
}

sign_cert() {
  local ca_name="$1"
  local cert_name="$2"
  local cn="$3"
  local san="$4"
  local eku="$5"

  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "${OUT_DIR}/${cert_name}.key"
  chmod 600 "${OUT_DIR}/${cert_name}.key"
  openssl req -new -key "${OUT_DIR}/${cert_name}.key" -subj "/CN=${cn}" -out "${OUT_DIR}/${cert_name}.csr"

  cat > "${OUT_DIR}/${cert_name}.ext" <<EOF
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=${eku}
subjectAltName=${san}
EOF

  openssl x509 -req -in "${OUT_DIR}/${cert_name}.csr" \
    -CA "${OUT_DIR}/${ca_name}.pem" -CAkey "${OUT_DIR}/${ca_name}.key" -CAcreateserial \
    -out "${OUT_DIR}/${cert_name}.crt" -days "$DAYS" -sha256 -extfile "${OUT_DIR}/${cert_name}.ext"

  rm -f "${OUT_DIR}/${cert_name}.csr" "${OUT_DIR}/${cert_name}.ext"
}

# 1. PostgreSQL TLS CA & server cert (covers internal Compose & Kubernetes DNS SANs)
create_ca "postgres-ca" "Relayquill PostgreSQL Root CA"
sign_cert "postgres-ca" "postgres-server" "postgres.internal.relayquill.example" \
  "DNS:postgres,DNS:postgres.internal.relayquill.example,DNS:postgres-rc.internal.relayquill.example,DNS:postgres-pi.internal.relayquill.example,DNS:relayquill-postgres,DNS:relayquill-postgres.relayquill-data.svc.cluster.local" \
  "serverAuth"

# 2. Broker Client TLS CA & per-node server certs
create_ca "broker-ca" "Relayquill Broker Client Root CA"
for idx in 1 2 3; do
  k8s_idx=$((idx - 1))
  sign_cert "broker-ca" "broker-${idx}-server" "broker-${idx}.internal.relayquill.example" \
    "DNS:broker-${idx},DNS:broker-${idx}.internal.relayquill.example,DNS:relayquill-broker-${k8s_idx}.relayquill-broker-headless.relayquill-data.svc.cluster.local,DNS:relayquill-broker.relayquill-data.svc.cluster.local" \
    "serverAuth"
done

# 3. Broker Cluster Route mTLS CA & per-node peer certs
create_ca "broker-cluster-ca" "Relayquill Broker Route mTLS CA"
for idx in 1 2 3; do
  k8s_idx=$((idx - 1))
  sign_cert "broker-cluster-ca" "broker-${idx}-route" "broker-${idx}.internal.relayquill.example" \
    "DNS:broker-${idx},DNS:broker-${idx}.internal.relayquill.example,DNS:relayquill-broker-${k8s_idx}.relayquill-broker-headless.relayquill-data.svc.cluster.local" \
    "serverAuth,clientAuth"
done

echo "Generated self-hosted TLS certificates in ${OUT_DIR}"
echo "Restrict private key ownership for container UIDs before starting services:"
echo "  postgres-server.key -> UID 999 (0600)"
echo "  broker-*-{server,route}.key -> UID 65532 (0400)"
