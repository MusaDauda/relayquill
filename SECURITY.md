# Security Policy

Relayquill is designed around explicit trust boundaries, least-privilege custody, and verifiable cryptographic invariants across admission, broker transport, outbound webhook delivery, operator authentication, and database persistence.

---

## 1. Cryptographic Custody & Trust Boundaries

### 1.1 Human Access, WebAuthn Passkeys & Session Custody (`@relayquill/auth`)

- **Passkey-First Authentication**: Human operator authentication uses WebAuthn (`@simplewebauthn/server` / `@simplewebauthn/browser`) with required User Verification (`UV`), strict configured `rpID` and `expectedOrigin` verification (never trusting `Host` or forwarded headers), synced-passkey counter handling, and human-readable account labels paired with opaque 32-byte `webauthn_user_id` values.
- **Preauth Challenges & Enrollment Intents**: Enrollment flows (`first_platform_admin`, `invited_human`, `restricted_factor_recovery`) bind a preauth context cookie (`__Host-rq_pre` in HTTPS profiles; `rq.browser-proof.v1\0` SHA-256 digest) to a 3-minute challenge (max 5 failed attempts) and a 5-minute enrollment intent verified via `comparison_sha256` (capped at 5 live intents per browser and 1,000 pending installation intents).
- **Native Sessions & Derived CSRF**: Authenticated sessions issue 32-byte tokens stored only as `rq.session.v1\0` SHA-256 verifiers inside `__Host-rq_session` cookies (`Secure`, `HttpOnly`, `Path=/`, `SameSite=Lax`, no `Domain`), enforcing an 8-hour absolute lifetime and 30-minute rate-bounded idle expiry alongside `control_epoch` and principal-state checks on every call. State-changing browser requests require a refresh-safe derived CSRF token (`HMAC-SHA256(raw_session_bytes, "rq.csrf.v1")` / `rq.csrf-digest.v1\0`) verified in constant time alongside an exact `Origin` check. Zero session tokens or CSRF secrets are written to `localStorage` or URL query parameters.
- **Operation-Bound Step-Up Verification**: Sensitive control-plane mutations (endpoint activation, signing key/policy changes, two-person replay/skip/suppression approvals, membership/data-grant changes, tenant/project holds) require a 5-minute WebAuthn step-up proof (`rq.session-browser-proof.v1\0` / `rq.step-up-target.v1\0`) bound to the exact `action`, scope (`tenant_id`/`project_id`), `target_resource_id`, `target_version`, and RFC 8785 `canonical_command_sha256`, consumed atomically with the accepted mutation.
- **Explicit Data Grants & Two-Person Approvals**: Reading raw payloads (`events.content.read`), wire delivery requests (`deliveries.request.read`), or receiver receipts (`receiver_receipts.read`) requires an explicit, active, non-expired `human_data_grants` record. Replay, strict-order skip, and suppression approvals strictly enforce `proposer !== reviewer`.

### 1.2 Machine Producer Credentials (`rq_p1`)

- Machine producer credentials use the non-recoverable format `rq_p1.<canonical-uuid>.<unpadded-base64url-32B>`, persisted solely as a length-prefixed `rq.producer-credential.v1\0` SHA-256 digest.
- Credentials are capped at a 30-day lifetime, support bounded same-scope rotation overlap (`<= 15 minutes`), reject stale scope pointers immediately (`PUBLICATION_CONTEXT_CHANGED`), and strictly isolate `machine_producer` credentials from `human_workflow` (`human.<uuid>`) publication namespaces.

### 1.3 PostgreSQL `SECURITY DEFINER` Role Separation (`migrations/`)

- **Isolated Data Authorities**: Core delivery (`relayquill`, schemas `rq`, `rq_support`, `rq_recovery`), independent receiver (`relayquill_receiver`, schema `rc`), and provider ingress (`relayquill_provider`, schema `pi`) run under separate databases/schemas and separate `NOLOGIN` owner roles (`rq_owner`, `receiver_owner`, `provider_owner`) with `PUBLIC` privileges revoked on databases, schemas, tables, sequences, and functions.
- **Zero Direct Runtime Table DML**: Runtime login roles (`rq_api`, `rq_relay`, `rq_fanout`, `rq_sender`, `rq_coordinator`, `rq_reporter`, `rq_signing_issuer`, `rq_migrator`, `rq_recovery`) do not hold direct `INSERT`/`UPDATE`/`DELETE` rights on base tables. All ordinary mutations run through `rq_owner`-owned `SECURITY DEFINER` stored procedures locked to `SET search_path = pg_catalog`, verifying `session_user` against an explicit per-function allowlist and enforcing `installation_state.control_epoch`.
- **Mechanically Audited Privilege Manifest**: `migrations/privilege-manifest.json` enumerates every public procedure, private helper, owner, `SECURITY DEFINER` flag, `search_path`, and allowed/denied role; `tests/contracts/migrations-and-manifest.test.mjs` verifies 1-to-1 parity against PostgreSQL `pg_proc` on every CI run.
- **Sensitive Table Isolation**: Credential, session, passkey, proof, signing-key metadata, and payload tables are isolated from read-only diagnostic (`rq_reporter`) and cross-role access.

### 1.4 25-Field Outbound Webhook Signing (`@relayquill/signing`)

- Every outbound delivery and endpoint verification request is authenticated with per-attempt HMAC-SHA256 over a length-prefixed binary preimage prefixed by `rq.webhook-signature.v1\0` and 25 ordered canonical fields:
  1. `version` (`1`), `purpose` (`delivery` | `endpoint_verification`), `key_id`, uppercase HTTP `method` (`POST`), normalized `external_authority` (`host:port`), normalized ASCII `request_target` (no query/fragment), `project_id`, `event_id`, `subscription_id`, `endpoint_id`, `endpoint_version`, `signing_policy_version`, `delivery_id`, `delivery_generation`, `attempt_id`, `verification_id`, `timestamp_seconds`, `consumer_event_key`, `ordering_domain_id`, `ordering_key_sha256`, `ordering_sequence`, `traceparent`, `tracestate`, `wire_body_sha256`, and `raw_wire_body_bytes` (preimage capped at `532,480` bytes).
- **Single-Occurrence Header Enforcement**: Receivers parse raw header arrays (`rawHeaders`) and fail closed on duplicate or proxy-coalesced `Relayquill-*`, `Content-Type`, `Content-Encoding`, `traceparent`, or `tracestate` headers (protected headers capped at `8,192` bytes).
- **Freshness, Constant-Time MACs & Bounded Key Rotation**: Verifiers enforce a `[-300s, +30s]` timestamp freshness window, verify `Relayquill-Body-SHA256` before MAC calculation, compare 32-byte MACs using `crypto.timingSafeEqual`, and allow at most 2 distinct-`kid` signatures (`v1;kid=<id>;mac=<base64url>`) during `bounded_dual_signature` overlap windows. Keys in `pending` state are rejected for business deliveries and permitted only for `endpoint_verification`.
- **Endpoint Proof & Signed Delivery Receipts**: Endpoint ownership verification requires a `204 No Content` response carrying `Relayquill-Endpoint-Proof` signed under `rq.endpoint-proof.v1\0`. Endpoints opting into `receiver_local_commit_v1` return a bounded (`<= 4,096` bytes) JSON receipt authenticated under `rq.receiver-receipt.v1\0`.

### 1.5 SSRF Defense & DNS-Pinned Outbound Egress (`@relayquill/egress`)

- **Strict URL Normalization (`url_v1`)**: Production profiles (`self_hosted`, `release`) allow only `https://` URLs up to `2,048` UTF-8 bytes on port `443` (or omitted) and reject IP literals (including decimal/hex/octal obfuscation), userinfo, query strings, fragments, dot-segments, repeated slashes, double-encoded `%25`, trailing dots, single-label hostnames, and reserved suffixes (`.localhost`, `.local`, `.internal`, `.home.arpa`, `.test`, `.invalid`, `.example`, `.localdomain`). The local `receiver.fixture.test:19095` fixture override is schema-forbidden and code-rejected in `self_hosted` and `release` profiles.
- **Content-Addressed IANA CIDR Deny Policy**: `packages/egress/artifacts/iana-special-purpose.v1.json` is evaluated via `ipaddr.js` to deny RFC 1918 private space, loopback (`127.0.0.0/8`), CGNAT (`100.64.0.0/10`), link-local and cloud metadata (`169.254.0.0/16`, `168.63.129.16/32`), documentation/benchmark/multicast/reserved ranges, non-`2000::/3` IPv6, ULA (`fc00::/7`), and IPv4-mapped/NAT64/6to4/Teredo representations (never unwrapping mapped IPv4 to allow).
- **Whole-Answer Isolated DNS Resolution & Pinned Socket Verification**: Each outbound attempt uses an isolated cancellable `dns.promises.Resolver` (`2s` DNS budget within `5s` preflight, max `8` CNAME hops with cycle detection, max `16` answers). If **any** returned A or AAAA record is denied, the entire decision fails closed. The connector disables pooling (`agent: false`), ignores `HTTP_PROXY`, pins `lookup` to the validated IP/family while preserving SNI (`servername`) and `rejectUnauthorized: true`, verifies `socket.remoteAddress` matches the pinned IP **before** writing HTTP headers or body bytes, refuses HTTP redirects, enforces bounded network budgets (`2s` TCP, `2s` TLS, `3s` header, `10s` total), caps response headers (`8 KiB`) and body (`64 KiB`), and disables automatic decompression (`Accept-Encoding: identity`).

### 1.6 Dual-Platform Protected IPC & Secret Custody (`@relayquill/runtime`)

- **Windows (`win32`)**: Local control and fixture secret-provider channels use Named Pipes (`\\.\pipe\relayquill-<env>-<channel>`) hardened via Win32 `advapi32.dll` `SetSecurityInfo` with `PROTECTED_DACL_SECURITY_INFORMATION` and SDDL `D:P(A;;GA;;;<USER_SID>)(A;;GA;;;SY)` (owning user SID and `LocalSystem` only; inherited ACEs stripped; `WD`/`AN`/`AU`/`BA` rejected) and verified on both server and client via `GetSecurityInfo`.
- **Linux / POSIX**: Local IPC uses Unix domain sockets under a verified owner-only `0700` directory with `0600` socket permissions, `lstat` symlink rejection, and UID ownership verification.
- **Wire & Memory Hygiene**: IPC frames are newline-delimited JSON capped at `64 KiB`. In-memory secret handles (`SecretHandle`) are non-serializing (`toJSON`/`util.inspect` redact values) and support explicit byte zeroing after use. Broker private keys and NKey seeds live strictly in untracked secret mounts (`/run/secrets/...`) and never in `public-topology.json` or Git-tracked `config/*.json` files.

### 1.7 Authenticated Self-Hosted Broker Quorum (`tools/broker-launcher`)

- The Go `relayquill-broker` launcher embeds `nats-server/v2` with mandatory client TLS (`handshake_first: true`, TLS 1.2+), cluster route mTLS with explicit peer SAN allowlists (`VerifyConnection`), Ed25519 NKey principal ACLs separating `relay`, `fanout`, and `broker_admin`, `sync_interval: always`, and `<= 4 KiB` metadata-only envelopes (zero raw event payloads stored in JetStream).

---

## 2. Security Non-Goals

To keep trust boundaries honest and auditable, Relayquill explicitly treats the following as **out of scope / non-goals**:

- **End-to-End Payload Encryption Against the Platform Operator**: Relayquill stores lossless event bytes in PostgreSQL (`rq.event_payloads`) to validate schemas, evaluate filter ASTs, compute projections, and sign outbound deliveries. Operators with host/database owner control or explicit `human_data_grants` are within the platform custody boundary; tenants requiring opaque payload confidentiality must encrypt sensitive fields at the application layer prior to admission.
- **Derived Representations as Privacy Redaction**: Derived representations (`envelope_version: 2`, `relayquill.lossless-projection.v1`) are structural payload projections for consumer schema compatibility—not PII redaction or secret scrubbing (`is_private_data_redaction: false`).
- **Compromised Host Kernel or Root Compromise**: Protected IPC (Win32 DACLs / POSIX `0600`), non-root containers (`uid 10001` / `101` / `65532`), and read-only root filesystems limit lateral movement, but cannot protect against a compromised host kernel or root/SYSTEM attacker with arbitrary memory inspection rights.
- **Transport-Only Business Confirmation**: Under `http_ack_only`, a `2xx` HTTP response proves only peer HTTP acknowledgement—not receiver business commit. End-to-end consumer commit proof requires explicit opt-in to `receiver_local_commit_v1`.
- **Untrusted Local Development Fixtures in Production**: `development_trusted_local` (`POSTGRES_HOST_AUTH_METHOD=trust`, loopback HTTP, `receiver.fixture.test:19095`) is strictly for local testing and is rejected in `self_hosted` and `release` profiles.

---

## 3. Supported Versions

| Version | Supported |
|---|---|
| `0.1.x` | Yes |

---

## 4. Responsible Vulnerability Reporting

**Do not open public GitHub issues or pull requests for suspected security vulnerabilities.**

### How to Report

1. Use **GitHub Private Vulnerability Reporting** (Security Advisories) on this repository if enabled, or contact the maintainers privately via the security contact published in the repository metadata (`security@relayquill.example` for self-hosted/enterprise mirrors—replace with your organization's monitored security inbox when deploying internally).
2. Include in your report:
   - Affected component(s) and exact file paths or protocol boundary (e.g., `@relayquill/signing`, `@relayquill/egress`, `@relayquill/auth`, `migrations/`, `tools/broker-launcher`).
   - Clear reproduction steps, minimal proof-of-concept request/payload, and observed vs. expected security invariant.
   - Deployment profile (`self_hosted`, `release`, or `development_trusted_local`) and runtime versions (Node.js, Go, PostgreSQL).
   - Impact assessment (confidentiality, integrity, availability, privilege boundary crossed).

### Response Commitments

- **Acknowledgement**: Within **48 hours** of receipt.
- **Initial Triage & Severity Assessment**: Within **5 business days**, confirming reproduction, affected versions, and remediation tracking.
- **Coordinated Disclosure**: We work with reporters to validate a fix, add regression tests covering the violated invariant, and publish a security advisory and patch release before public disclosure. Please allow a standard **90-day** coordinated disclosure window unless an active exploit requires accelerated mitigation guidance.
