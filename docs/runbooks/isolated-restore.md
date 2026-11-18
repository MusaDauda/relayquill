# Isolated Restore & Independent Receiver Reconciliation Runbook

This runbook specifies the controlled database restoration, old-writer containment, quarantine epoch establishment, and independent receiver reconciliation procedure for self-hosted PostgreSQL 18 deployments.

> **Core Invariant:** Restoring `rq` from a backup or PITR target **never** rewinds the independent external receiver (`rc`) or provider ingress (`pi`). Any gap between the restored `rq` snapshot and live external authorities must be quarantined, inventoried, and reconciled explicitly before reopening traffic.

---

## 1. Recovery Objectives & Backup Inventory

- **Engineering Targets**: Recovery Point Objective (RPO) `<= 5 minutes` (via encrypted WAL archiving / pgBackRest / basebackup); synthetic Recovery Time Objective (RTO) `<= 60 minutes` measured from incident declaration to verified safe service reopening (reported separately as DB restore time, integrity verification time, and reopening time).
- **Backup Scope Separation**:
  - **`rq` (`relayquill`)**: Base backups + continuous WAL archives encrypted at rest. Restored into a **new isolated PostgreSQL 18 instance**—never overwritten in place on a shared server hosting live `rc` or `pi`.
  - **`rc` (`relayquill_receiver`) & `pi` (`relayquill_provider`)**: Backed up and operated independently. Remain untouched during an `rq` recovery so receiver deduplication anchors and counters remain authoritative.
  - **JetStream (`RELAYQUILL_EVENTS_V1`)**: 3-node Raft store holds bounded `<= 4 KiB` metadata notifications only—it cannot reconstruct lost event payloads by itself.
  - **Secret Custody**: Signed endpoint keys, NKey seeds, and producer verifiers live outside the DB backup; restoring a stale DB snapshot never restores revoked secret custody.

---

## 2. Phase 1 — Create Recovery Plan & Contain Original Deployment

Before mutating any infrastructure or database:

1. **Allocate an External Operation Record**: Generate a unique `external_operation_id` UUID and non-secret recovery plan binding:
   - `source_database_reference`, exact `restore_point` (LSN or UTC timestamp), `target_database_reference`
   - `source_control_epoch` and newly allocated `proposed_new_control_epoch`
   - Exact unaffected `rc` and `pi` database references
2. **Contain Old Writers Completely**:
   - Close installation/project gates if reachable (`admission_hold` / `recovery_quarantine`).
   - Stop all old `api`, `relay`, `fanout`, `sender`, and `coordinator` processes (`docker compose stop` or `kubectl scale deployment --replicas=0` across `api`, `relay`, `fanout`, `sender`, `coordinator`).
   - Disable autoscaling/restarts and revoke old DB connection credentials or firewall ingress to the old DB.
   - Terminate remaining backend sessions on the source DB (`pg_terminate_backend`) and wait through the bounded outbound HTTP deadline (`10s` network window).
   - **Critical Check:** Rotating `control_epoch` in the restored DB does **not** stop an old sender process holding keys in memory against an uncontained network path. Verify zero active old worker pods/containers and zero old NATS client connections before proceeding.

---

## 3. Phase 2 — Restore `rq` into an Isolated Target Instance

1. Provision a **fresh isolated PostgreSQL 18 instance** on a recovery-only network segment (`no` ordinary app traffic permitted).
2. Restore the base backup and replay WAL up to the exact chosen `restore_point` (`recovery_target_time` or `recovery_target_lsn`, `recovery_target_action = 'pause'` or `'promote'` into isolated mode).
3. Enforce TLS (`ssl = on`, `password_encryption = scram-sha-256`, `pg_hba.conf` `hostssl`) and restrict `CONNECT` solely to `rq_recovery` and `rq_migrator` until verification completes; drop or lock any stale colocated copies of `rc` or `pi` present in the physical cluster snapshot so nothing ever connects to them.

---

## 4. Phase 3 — Immediate Quarantine & Epoch Rotation

Before allowing any ordinary worker (`api`, `relay`, `fanout`, `sender`, `coordinator`) to connect:

1. Connect strictly as **`rq_recovery`**.
2. Lock `rq.installation_state` (`id = 1`) `FOR UPDATE`, verify the restored `control_epoch` matches `source_control_epoch`, and commit:
   - `mode = 'recovery_quarantine'`
   - `allow_event_admission = false`, `allow_publication = false`, `allow_fanout = false`, `allow_send = false`, `allow_endpoint_verification = false`
   - `control_epoch = <new_control_epoch>`
   - Increment `governance_version` and `version`, appending an immutable `rq.audit_events` + `rq_recovery.operations` record.
3. Verify that all old human sessions, operation proofs, auth challenges, and pending credential intents referencing the previous `control_epoch` are rejected automatically by epoch mismatch. Do **not** rewrite old producer credential epochs to make leaked secrets valid again—reissue credentials under reviewed current scope.

---

## 5. Phase 4 — Integrity, Obligations & Broker Reconciliation

Run bounded read-only inspection under `rq_recovery`:

```bash
node apps/admin/dist/main.js --config config/recovery.target.json recovery inspect
node apps/admin/dist/main.js --config config/recovery.target.json recovery verify-integrity
```

Verify every boundary before planning any repair (`migrations/0009_protected_recovery_operations.sql`):

1. **Schema & Hash Integrity**: Verify schema revision `0009`, `event_payloads` byte-count/SHA-256 integrity, one `event_fanout` per event, and contiguous `materialized_through_event_sequence`.
2. **In-Flight Attempt Classification**:
   - **`prepared` attempts (no `send_started_at`)**: Safe to retire via two-person reviewed `rq_recovery` action `retire_stale_claim` once old-writer containment is confirmed, releasing held slot/rate reservations atomically.
   - **`send_started` attempts**: **Never** eligible for `retire_stale_claim`. Must remain preserved as externally uncertain until compared against independent receiver records.
3. **Capacity & Rate Bucket Reconciliation**:
   - Never reset rate buckets to full during recovery (post-snapshot sends may have spent tokens). Apply a conservative hold/drain and record any counter repairs through `reconcile_reservations` with exact before/after facts digests.
4. **Broker Stream Strategy (`retain` vs `new_generation`)**:
   - If retaining the JetStream cluster, verify all old relay/fanout clients are disconnected and check for notifications whose `event_id` does not exist in the restored `rq` database (post-snapshot events). Quarantine orphaned notifications rather than fabricating events from `<= 4 KiB` metadata.
   - If initializing a clean JetStream stream, register a new `rq.broker_generations` record via `rq_migrator`/`broker_admin` and reconcile incomplete outbox roots through generation re-emission (`<= 1/min/root`, `5`-no-progress review boundary).

---

## 6. Phase 5 — Independent Receiver Reconciliation & Post-Snapshot Loss

For every delivery whose attempt was `send_started` around the restore window or held in the restored snapshot while potentially sent later:

1. **Query Independent Receiver (`rc`) Safely**:
   - Inspect `rc.inbox`, `rc.business_mutations`, `rc.receipts`, and `rc.order_heads` via the receiver's own read-only administrative interface (never by mutating `rc` or forging a `verified_supported` receipt).
   - Record findings in `rq_recovery` via `record_receiver_comparison` (`matching_committed_anchor`, `missing_anchor`, `conflicting_facts`, `retention_unknown`, or `source_unavailable`).
   - If `matching_committed_anchor` exists, an ordinary subsequent retry preserves the same `Relayquill-Consumer-Key` and resolves idempotently at the receiver without duplicating business mutations.
   - If `conflicting_facts` is observed, keep the scope held for manual investigation.
2. **Account for Accepted Events Missing from Restored Snapshot**:
   - Compare retained external producer receipts / `pi.forward_intents` against restored `rq.events`.
   - Any event admitted after the `restore_point` (`201` returned earlier, absent in restored `rq`) must be classified explicitly as **`accepted_after_restore_point_missing`**.
   - Reconstruct only from verified retained producer payloads via an explicit reviewed recovery record linking original receipt ID, new admission, and receiver state—never invent silent empty events.

---

## 7. Phase 6 — Two-Person Review & Controlled Reopening

All state-mutating repairs (`retire_stale_claim`, `reconcile_reservations`, `continue_publication_episode`, `record_receiver_comparison`, `set_recovery_gate`) require distinct requester (`recovery_operator`) and reviewer (`recovery_reviewer`) approval bound to the exact `plan_sha256`, `target_epoch`, and row versions:

```bash
# 1. Plan exact typed action (operator)
node apps/admin/dist/main.js --config config/recovery.target.json recovery plan --request config/recovery.action-request.json

# 2. Distinct reviewer approval
node apps/admin/dist/main.js --config config/recovery.reviewer.json recovery review

# 3. Execute exact reviewed action ID and inspect result
node apps/admin/dist/main.js --config config/recovery.target.json recovery apply
node apps/admin/dist/main.js --config config/recovery.target.json recovery result
```

Before executing `set_recovery_gate` to transition `installation_state.mode` back to `open`:
- Re-verify active endpoint URLs, signing key versions, and dispatch grants against current custody (snapshots can resurrect previously revoked endpoints or rotated keys).
- Keep unresolved scopes under narrow project/endpoint holds while reopening verified healthy scopes.
- Run a bounded synthetic walkthrough event end-to-end and verify `diagnostics capacity` conservation.
