# Incident Response & Causal Troubleshooting Runbook

This runbook defines structured incident containment and boundary-by-boundary diagnosis for Relayquill.

> **Core Invariant:** Never resolve a dashboard alert by deleting `outbox_events`, resetting delivery counters, skipping predecessor checks, disabling TLS/egress pinning, or fabricating successful delivery states. Find the first unsupported boundary while preserving accepted obligations.

---

## 1. Establish Scope & Contain Before Restarting

1. **Record Incident Metadata**: Incident ID, first observed UTC timestamp, deployment profile (`compose-prod` vs `k8s-selfhosted`), active `control_epoch`, and current container image digests.
2. **Inspect Installation State First** (read-only):
   ```bash
   node apps/admin/dist/main.js --config config/diagnostics.operator.json diagnostics installation
   ```
   Confirm `mode` (`open`, `admission_hold`, `recovery_quarantine`), `governance_version`, `control_epoch`, and schema revision (`0009`).
3. **Contain If Risky**:
   - If new writes worsen backlog or a destination/key may be compromised, place the affected tenant, project, endpoint, or installation into **`admission_hold`** or endpoint/subscription **`hold_sends`** via the audited control plane.
   - Do **not** bulk-kill or restart every worker process first: restarts discard in-memory timing context and widen `transport_unknown` windows.
4. **Separate Populations**:
   - Distinguish single-event, single-endpoint, single-tenant, and installation-wide scope.
   - Keep `started` / `transport_unknown` attempts classified separately from future work stopped by a hold.

---

## 2. Diagnostic Read-Only Commands

Use the dedicated `rq_reporter` identity (`config/diagnostics.operator.json` + bounded `config/diagnostics.request.json`) over the protected operator channel. Diagnostics never mutate state or expose raw event payloads, HMAC keys, or credentials:

```bash
node apps/admin/dist/main.js --config config/diagnostics.operator.json diagnostics event-chain --request config/diagnostics.request.json
node apps/admin/dist/main.js --config config/diagnostics.operator.json diagnostics queues      --request config/diagnostics.request.json
node apps/admin/dist/main.js --config config/diagnostics.operator.json diagnostics claims      --request config/diagnostics.request.json
node apps/admin/dist/main.js --config config/diagnostics.operator.json diagnostics capacity    --request config/diagnostics.request.json
```

---

## 3. Causal Troubleshooting by Boundary

### A. Producer Timeout or Connection Loss at Admission
- **Check**: Whether the producer retained its exact prepared request bytes, publication channel ID, `business_key`, and explicit timestamp options (`producer_event_time` / `deadline_at`).
- **Action**: Call `resolvePrepared` or resubmit the **exact** same prepared payload and idempotency key.
- **Forbidden**: Do not generate a fresh idempotency key or fresh 24-hour deadline to force a `201`; a genuine prior commit recovers the original event ID and command receipt deterministically.

### B. Event `accepted` in `rq`, Missing `published` in JetStream
- **Check**: `outbox_events` state, `publication_generation`, `claim_owner_instance_id`, `claim_expires_at`, and relay readiness (`/health/ready`).
- **Common Causes**:
  - JetStream stream `RELAYQUILL_EVENTS_V1` hit `max_msgs` / `max_bytes` under `DiscardNew`: hold new admissions via capacity policy while draining backlog.
  - Relay NKey/TLS auth failure or broker quorum loss (fewer than 2 of 3 broker nodes reachable).
  - Lost `PubAck` after broker store: relay retries using the **exact same** `Nats-Msg-Id` so JetStream deduplicates within `duplicate_window_ns` (`120s`).
- **Forbidden**: Never switch stream discard policy to `DiscardOld` or hand-publish guessed payloads.

### C. `published` Observed, Fanout Stalled
- **Check**: `broker_inbox`, `event_fanout` (`cursor`, `last_progress_at`), `project_fanout_state.materialized_through_event_sequence`, and `publication_recovery_episodes`.
- **Common Causes**:
  - **Missing Predecessor**: Project strict sequence `materialized_through_event_sequence + 1` has not yet arrived; later notifications correctly NAK/defer rather than skipping an earlier event.
  - **5-No-Progress Review Threshold**: Five recovery generations passed without advancing the canonical cursor (`state = 'review_required'`).
  - **Fanout Consumer ACL / Timeout**: Verify `fanout` NKey can pull `$JS.API.CONSUMER.MSG.NEXT.RELAYQUILL_EVENTS_V1.RELAYQUILL_FANOUT_V1` and ACK `$JS.ACK.RELAYQUILL_EVENTS_V1.RELAYQUILL_FANOUT_V1.>`.
- **Forbidden**: Never ACK/delete a stuck broker notification solely to clear pending stream metrics.

### D. Delivery Pending Without Outbound Traffic
- **Check**: `deliveries` state, `next_eligible_at`, `endpoint_circuits`, `ordering_heads`/`members`, `send_hold`, and rate buckets (`rate_buckets`).
- **Common Causes**:
  - Endpoint circuit is `open` or rate bucket tokens are exhausted (`refill_remainder_numerator`).
  - `strict_per_key` ordering: an earlier sequence for the same `(ordering_domain_id, ordering_key_sha256)` is still unresolved (`blocked` or retrying). Unblock only via predecessor completion, reviewed replay, or `reviewed_skip_without_processing_claim`.
  - Signing secret or dispatch grant unavailable: sender defers cleanly (`deferred_before_send`) and never transmits unsigned webhooks.
  - Approved `sender` slot saturation: inspect active `runtime_instances` leases rather than multiplying slot budgets by pod replicas.

### E. Send Starts (`send_started`), Fails or Times Out
- **Check**: `rq.egress_decisions` (`decision`, `reason_code`, `authority_sha256`, `answer_set_sha256`, `selected_address_sha256`, `peer_address_sha256`) and `delivery_attempts.state`.
- **Common Causes**:
  - **DNS / CIDR Policy Denial (`decision = 'denied'`)**: Destination resolved to an RFC1918, loopback, link-local, metadata, or special-purpose IP (or mixed public + private answer set). Treated as a policy block, not a transient network error.
  - **Peer Mismatch**: Connected socket remote IP did not match pinned decision; socket was destroyed before sending bytes.
  - **Timeout / Reset After Write**: Recorded honestly as `transport_unknown`; later attempts carry a new `attempt_id` and timestamp while preserving `Relayquill-Consumer-Key`.

### F. HTTP `2xx` Observed, Processing Unverified or Signature Rejected
- **Check**: Endpoint `receipt_profile` (`http_ack_only` vs `receiver_local_commit_v1`), `receipt_observations`, and `signing_key_versions` overlap state.
- **Rules**:
  - Generic `2xx` under `http_ack_only` keeps `consumer_processed` unverified—do **not** resend acknowledged business deliveries just to chase a receipt badge.
  - For receiver signature rejections, verify `Relayquill-Timestamp` skew (`[now - 300s, now + 30s]`), duplicate-header rejections at reverse proxies, exact normalized external authority/path (`:443` host + path), and key overlap window (`bounded_dual_signature`). Never log raw HMAC keys or signed request secrets during triage.

### G. Console / SSE Watch Lag vs History Disagreement
- **Check**: Projection checkpoint lag, `watch_leases`, actor/tenant/project stream limits, and SSE `resync_required` frames.
- **Rules**: Heartbeats (`10s`) do not advance resume cursors; auth/grant revocation intentionally closes active SSE connections. Use bounded projection verification/rebuild under `rq_recovery` if `project_delivery_totals` or `event_delivery_total_deltas` mismatch canonical source counts.

### H. Provider Ingress (`pi`) Callback Failure
- **Check**: `pi.observations`, `pi.transport_receipts`, `pi.semantic_identities`, and `pi.forward_intents`.
- **Rules**: Confirm raw request bytes reach `provider-ingress` before JSON parsing. Remember Stripe checks `Stripe-Signature` with a 300s tolerance whereas Paystack checks `x-paystack-signature` SHA-512 HMAC without a transport timestamp. If forwarding fails with `PUBLICATION_CONTEXT_CHANGED`, resolve producer credential/channel state rather than silently re-encoding payloads.

---

## 4. Incident Closure Gate

Before closing an incident and lifting holds:
1. Verify `diagnostics capacity` shows conserved reservations (`pending` + `held` slots match canonical deliveries/attempts).
2. Re-run a synthetic delivery + independent receiver check in the affected environment.
3. Document confirmed root cause, affected time window, any unresolved `transport_unknown` attempts, and explicit risk sign-off.
