# Relayquill Architecture

Relayquill is a self-hostable event publication and signed webhook delivery platform built on **Node 24 LTS TypeScript**, **PostgreSQL 18**, **NATS JetStream** (embedded via the Go `relayquill-broker` launcher), and **React / Nginx**.

Production deployments require **zero managed cloud services**: the entire stack runs on standard open-source PostgreSQL 18, a 3-node native-TLS JetStream quorum, static Nginx reverse proxy, and isolated Node worker processes. Managed services (Neon, Supabase, Synadia Cloud) are supported strictly as optional remote development targets, and AWS Terraform (`infra/aws/`) is an optional deployment target.

---

## 1. Process Topology & Authority Boundaries

Relayquill separates control plane, transport, delivery egress, independent receiver state, and provider ingress into distinct processes and database authorities:

```
  [Browser / Operator] ──HTTPS──> [Console (Nginx uid 101)] ──/api/──> [API (Fastify)]
                                                                             │
  [External Provider]  ──HTTPS──> [Provider Ingress (pi)] ──Producer SDK─────┤
                                                                             ▼
                                                                   [PostgreSQL 18 (rq)]
                                                                    ▲     ▲      ▲
                        ┌───────────────────────────────────────────┘     │      │
                        │                                                 │      │
                  [Outbox Relay] ──mTLS/TLS+NKey──> [3-Node JetStream]    │      │
                                                          │               │      │
                                                     Pull Consumer        │      │
                                                          ▼               │      │
                                                    [Fanout Worker] ──────┘      │
                                                                                 │
  [External Receiver] <──Pinned HTTPS + HMAC── [Sender Worker] ──────────────────┤
  (Independent rc)                                                               │
                                               [Coordinator Worker] ─────────────┘
```

### Separate Data Authorities (`rq`, `rc`, `pi`, JetStream)

| Authority | Database / Store | Owner Role | Runtime Roles | Trust Boundary |
|---|---|---|---|---|
| **Core Delivery (`rq`)** | `relayquill` (schemas `rq`, `rq_support`, `rq_recovery`) | `rq_owner` (`NOLOGIN`) | `rq_api`, `rq_relay`, `rq_fanout`, `rq_sender`, `rq_coordinator`, `rq_reporter`, `rq_signing_issuer`, `rq_migrator`, `rq_recovery` | Authoritative event intent, outbox, canonical fanout, delivery attempts, ordering, rate buckets, audit, and recovery operations. |
| **Independent Receiver (`rc`)** | `relayquill_receiver` (schema `rc`) | `receiver_owner` (`NOLOGIN`) | `receiver_runtime`, `receiver_migrator` | Models an external customer webhook consumer. Zero `CONNECT` privilege to `rq` or `pi`; proves end-to-end idempotency, signature verification, and divergence reconciliation. |
| **Provider Ingress (`pi`)** | `relayquill_provider` (schema `pi`) | `provider_owner` (`NOLOGIN`) | `provider_runtime`, `provider_migrator` | Verifies inbound Stripe/Paystack raw callbacks, stores minimized observations/inbox anchors, and forwards normalized events solely via `@relayquill/producer-sdk`. |
| **JetStream Broker** | 3-node persistent Raft quorum (`RELAYQUILL_EVENTS_V1`) | `broker_admin` (NKey) | `relay` (publish `rq.events.*.accepted`), `fanout` (pull/ack `RELAYQUILL_FANOUT_V1`) | Ephemeral-to-bounded transport notification store (`<= 4 KiB` metadata-only envelopes; zero raw event payload bytes, zero secrets). |

Every ordinary runtime database role executes mutations via `rq_owner`-owned `SECURITY DEFINER` stored procedures (`SET search_path = pg_catalog`) checking `session_user` and `control_epoch`, with `PUBLIC` execution revoked. Only `rq_migrator` assumes `rq_owner`; runtime workers never hold DDL or cross-role permissions.

---

## 2. Four Evidence Stages

Relayquill never collapses asynchronous event delivery into a single misleading "delivered" flag. Each boundary produces independent, verifiable evidence:

1. **`accepted`**: PostgreSQL (`rq`) atomically commits the immutable event, raw payload bytes, canonical wire envelope (`552`-byte golden profile), business idempotency anchor, command receipt, outbox root (generation `1`), and initial `event_fanout` reservation inside one `READ COMMITTED` transaction before returning HTTP `201`.
2. **`published`**: The outbox relay claims due outbox roots via short leased transactions, publishes the `<= 4 KiB` notification envelope to JetStream with a deterministic `Nats-Msg-Id`, and records `PubAck` stream/sequence metadata after receiving durable broker confirmation (`sync_interval: always`, quorum `replicas: 3`).
3. **`http_acknowledged`**: The sender worker executes a pinned HTTPS POST outside any DB transaction and observes an allowable `2xx` HTTP response before the request deadline. HTTP `202` or generic `2xx` confirms transport acceptance by the peer HTTP stack—not business completion.
4. **`consumer_processed`**: Recorded **only** when the endpoint explicitly opts into `receiver_local_commit_v1` and returns a signed bounded receipt matching the exact request binding, active key policy, and `original_facts_sha256` (`verified_supported`). Under `http_ack_only`, processing remains honestly classified as `unverified`.

---

## 3. Lock Ranking & Sharded Delta Contention Design

### Deterministic `READ COMMITTED` Lock Order

All mutating database transactions execute with bounded lock timeouts (`2s` default) and statement timeouts (`5s` default), reading `clock_timestamp()` after lock waits before checking credentials, proofs, or deadlines. Transactions acquire locks strictly in descending rank order and never acquire a higher-ranked lock after a lower one:

1. **Installation Gate (`rq.installation_state`, `id = 1`)**:
   - Ordinary admission, publication, fanout, and delivery mutations take **`SELECT ... FOR SHARE`** on `id = 1`—allowing concurrent workers to proceed in parallel while blocking atomically against exclusive `FOR UPDATE` transitions (`admission_hold`, `recovery_quarantine`, or `control_epoch` rotation).
2. **Principal / Session / Proof / Runtime Authority**: sorted IDs within fixed class order.
3. **Dispatch Domain State**: cursor and domain weight configuration.
4. **Tenant & Project Envelopes (`rq.tenants`, `rq.projects`)**:
   - Ordinary non-counter reads take `FOR SHARE` on `rq.projects`; projection-counted writes verify `projection_maintenance_operation_id` and lock sorted tenant/project IDs.
5. **Scoped Authority & Configuration**: memberships, producer scopes/credentials, endpoints/versions/grants, subscriptions/versions, signing policies/keys, and data grants.
6. **Scoped Command Idempotency Guard**: `pg_advisory_xact_lock` over 64-bit big-endian SHA-256 prefix of `(scope, actor, command_family, idempotency_key_digest)`.
7. **Capacity & Rate Buckets**: actor-watch -> tenant -> project -> endpoint -> producer (`refill_remainder_numerator` integer token math).
8. **Claims & Cursors**: `project_fanout_state` -> `event_fanout` -> outbox / coordinator task claims.
9. **Circuits & Ordering Keys**: `endpoint_circuits` -> sorted `ordering_heads` / `ordering_members`.
10. **Events, Delivery Families, Deliveries, Positions**: sorted by ID.
11. **Attempts, Slots, Retry Decisions, Reviews**.
12. **Immutable Append-Only Logs**: history, audit events, publication observations, and receipts.

### 16-Shard `event_delivery_total_deltas`

Updating an event's aggregate delivery counters directly on `rq.events` with `SELECT ... FOR UPDATE` creates a single-row serialization bottleneck whenever multiple sender workers finalize deliveries for the same event concurrently. To eliminate that hot-row lock contention:

- `migrations/0007_dispatch_replay_retention_and_projections.sql` defines `rq.event_delivery_total_deltas` keyed by `(event_id, shard_id)` with 16 deterministic shards (`shard_id` in `0..15`, derived from the delivery/attempt identity).
- Concurrent attempt finalizations, delivery transitions, and receipt observations update only their assigned shard delta row instead of taking `FOR UPDATE` on `rq.events`.
- Read projections and coordinator compaction aggregate `(event_delivery_totals + SUM(deltas))` cleanly without blocking active senders.

---

## 4. Dual-Platform Protected IPC (`packages/runtime/src/ipc.ts`)

Operator commands, local fixture secret providers, and independent receiver/ingress control planes communicate over local IPC (`env_name`, `channel`), never unauthenticated loopback TCP:

- **Windows (`win32`)**: Named Pipes `\\.\pipe\relayquill-<env>-<channel>` hardened via Win32 `advapi32.dll` `SetSecurityInfo` with `PROTECTED_DACL_SECURITY_INFORMATION` and SDDL `D:P(A;;GA;;;<USER_SID>)(A;;GA;;;SY)` (granting full access solely to the owning user SID and `LocalSystem`, stripping inherited ACEs and rejecting `WD`/`AN`/`AU`/`BA`). Both server and client verify ownership and DACL protection with `GetSecurityInfo`.
- **Linux / POSIX**: Unix domain sockets inside a verified owner-only `0700` runtime directory with `0600` socket file permissions, `lstat` symlink rejection, and UID ownership verification (`process.getuid()`).
- **Wire Framing**: Newline-delimited JSON frames capped at `64 KiB`, rejecting embedded `\r`/`\n` in raw frame inputs.

---

## 5. Egress Pinning (`packages/egress`)

Endpoint ownership verification never makes an internal, loopback, link-local, or cloud metadata address safe for outbound delivery. The sender enforces defense-in-depth at both the application connector and network policy layers:

1. **Strict URL & Target Normalization**: Accepts only `https://` URLs up to `2048` UTF-8 bytes with no control characters, whitespace, backslashes, embedded userinfo, query strings, fragments, non-443 ports, IP literals (including decimal/hex/octal obfuscation), trailing dots, single-label hostnames, or reserved suffixes (`.localhost`, `.local`, `.internal`, `.home.arpa`, `.test`, `.invalid`, `.example`). The local `receiver.fixture.test:19095` override is restricted solely to non-production trusted fixture profiles and is schema-rejected in release and self-hosted configurations.
2. **Content-Addressed CIDR Policy**: Ships pinned IANA IPv4 and IPv6 special-purpose prefix registries evaluated via `ipaddr.js`, unconditionally blocking RFC1918, loopback, link-local (`169.254.0.0/16`, including cloud metadata `169.254.169.254/32` and `168.63.129.16/32`), CGNAT (`100.64.0.0/10`), documentation ranges, multicast, IPv4-mapped IPv6 (`::ffff:0:0/96`), NAT64, 6to4, Teredo, and ULA (`fc00::/7`).
3. **Isolated DNS Resolution**: Each attempt allocates a dedicated `dns.promises.Resolver` (`2s` DNS sub-budget within a `5s` preflight budget, max `8` CNAME hops, max `16` addresses). If **any** A or AAAA record resolves to a denied range, the entire connection decision fails before dialing.
4. **One-Use Pinned Socket & Post-Connect Verification**: Uses `https.request` with `agent: false` (no cross-request socket pooling), a custom `lookup` callback returning only the single selected IP/family, original hostname preserved as TLS `servername` (SNI) with `rejectUnauthorized: true`, and `socket.remoteAddress` equality verification **before** writing HTTP headers or body bytes. Redirects are disabled, response headers are capped at `8 KiB`, and retained response bodies are capped at `64 KiB`.
5. **Network-Level Complement**: Compose segments `sender` onto a dedicated `egress` bridge while keeping `postgres`, `broker`, `api`, `relay`, `fanout`, and `coordinator` isolated; Kubernetes `NetworkPolicy` denies private IPv4 ranges from `sender`.

---

## 6. Webhook Signing, Verification & Replay

### Canonical Wire Envelope & Preimage

- Events are serialized once at admission into `rq.event_wire_envelopes` using RFC 8785 deterministic sorted-key JSON with no trailing newline (`envelope_version: 1`, `representation_version: 1`). The reference `{"message":"hello"}` fixture yields an exact `552`-byte body with SHA-256 `c37a5e1841419d414e907071fda86dc1b66f96e943083a6e503c10e61e227b1b`.
- Outbound requests include `Relayquill-Version: 1`, `Relayquill-Purpose`, scoped IDs, `Relayquill-Consumer-Key` (64-hex SHA-256 of project/event/consumer scope), `Relayquill-Body-SHA256`, `Relayquill-Timestamp` (canonical integer Unix seconds), and `Relayquill-Signatures`.
- The HMAC-SHA256 preimage starts with UTF-8 `rq.webhook-signature.v1\0` followed by 25 unsigned 32-bit big-endian length-prefixed canonical fields ending with raw wire body bytes (`<= 520 KiB`).
- `Relayquill-Signatures` carries 1 entry (`v1;kid=<key-id>;mac=<base64url>`) or 2 entries separated by `,` during `bounded_dual_signature` key rotation overlap. Receivers inspect raw duplicate headers (rejecting coalescing ambiguity), enforce freshness (`[now - 300s, now + 30s]`), compare MACs in constant time after preimage reconstruction, and verify `rq.endpoint-proof.v1` challenges (`204` + `Relayquill-Endpoint-Proof`) before endpoint activation.

### Ordering & Reviewed Replay

- **Unordered vs Strict-Per-Key**: Subscriptions default to `unordered`. `strict_per_key` assigns monotonic per-key sequences (`ordering_heads` / `ordering_members`); an unresolved predecessor holds later messages until acknowledged or resolved via an explicit `reviewed_skip_without_processing_claim`.
- **Two-Person Reviewed Replay**: Operators propose a replay (`replay_exact_original` or `replay_with_reviewed_representation`); a **distinct** `project_admin` reviewer must approve the exact proposal hash, current endpoint URL/key version, and prior response classification (`known_rejected` / `unknown` / `not_applicable`). Replays allocate a new delivery generation while preserving the immutable `Relayquill-Consumer-Key` and using `append_after_current_tail` ordering—never mutating past attempt records.
