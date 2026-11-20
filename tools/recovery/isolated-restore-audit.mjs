import fs from "node:fs";
import path from "node:path";
import {
  CliError,
  findRawSecretsInObject,
  parseCliFlags,
  readStrictJsonFile,
  redactSensitiveData,
  runCliMain
} from "../release/lib/cli.mjs";

const HELP_TEXT = `Usage: node tools/recovery/isolated-restore-audit.mjs --input <bundle.json> [options]

Audit isolated PostgreSQL restore authority separation (restored rq vs live independent
rc and pi authorities), verify old-writer containment and recovery_quarantine epoch rotation,
and classify event/delivery obligations into A / B / C divergence categories.

Options:
  --input <path>            Sanitized recovery audit input JSON (required)
  --config <path>           Optional recovery operator config JSON
  --target <path>           Optional recovery target config JSON
  --fail-on-holds           Exit non-zero if any B conflict, C missing, or reverse-divergence hold exists
  --out <path>              Write sanitized audit report JSON
  --json                    Emit structured JSON output
  -h, --help                Show help without reading secrets or mutating state
`;

function verifyAuthoritiesAndContainment(bundle) {
  const violations = [];
  const auth = bundle.authorities ?? {};
  const sourceRq = String(auth.source_rq_database ?? "");
  const restoredRq = String(auth.restored_rq_database ?? "");
  const currentRc = String(auth.current_rc_database ?? "");
  const currentPi = String(auth.current_pi_database ?? "");
  const staleColocatedRc = String(auth.restored_colocated_rc_database ?? "");
  const staleColocatedPi = String(auth.restored_colocated_pi_database ?? "");

  if (!sourceRq || !restoredRq || !currentRc || !currentPi) {
    violations.push("Missing required database authority references (source_rq, restored_rq, current_rc, current_pi)");
  }
  if (sourceRq && restoredRq && sourceRq === restoredRq) {
    violations.push(
      `Restored rq database ("${restoredRq}") must be a new isolated instance, never an in-place overwrite of source_rq`
    );
  }
  if (currentRc && (currentRc === restoredRq || (staleColocatedRc && currentRc === staleColocatedRc))) {
    violations.push(
      `Independent receiver (rc) authority ("${currentRc}") must remain on live current rc and never repoint to restored stale snapshot`
    );
  }
  if (currentPi && (currentPi === restoredRq || (staleColocatedPi && currentPi === staleColocatedPi))) {
    violations.push(
      `Independent provider-ingress (pi) authority ("${currentPi}") must remain on live current pi and never repoint to restored stale snapshot`
    );
  }
  if (auth.restored_publicly_accessible === true) {
    violations.push("Restored target database has publicly_accessible=true; isolated private network required");
  }
  if (auth.restored_tls_mode && auth.restored_tls_mode !== "verify_full") {
    violations.push(`Restored target database tls_mode must be "verify_full", got "${auth.restored_tls_mode}"`);
  }

  const containment = bundle.old_writer_containment ?? {};
  if (Number(containment.active_old_worker_processes ?? 0) !== 0) {
    violations.push(
      `Old writer containment failed: ${containment.active_old_worker_processes} old worker process(es) still active`
    );
  }
  if (containment.autoscaling_disabled !== true) {
    violations.push("Old writer containment failed: autoscaling/restart on old deployment is not disabled");
  }
  if (Number(containment.active_old_db_sessions ?? 0) !== 0) {
    violations.push(
      `Old writer containment failed: ${containment.active_old_db_sessions} old rq database session(s) remain connected`
    );
  }
  if (Number(containment.active_old_broker_connections ?? 0) !== 0) {
    violations.push(
      `Old writer containment failed: ${containment.active_old_broker_connections} old broker client connection(s) remain active`
    );
  }
  if (containment.network_contained !== true) {
    violations.push(
      "Old writer containment failed: network/egress containment not verified (epoch rotation alone does not stop in-RAM sender keys)"
    );
  }

  const quarantine = bundle.quarantine_state ?? {};
  if (quarantine.mode !== "recovery_quarantine") {
    violations.push(
      `Restored target installation_state.mode must be "recovery_quarantine", got "${quarantine.mode}"`
    );
  }
  for (const flag of [
    "allow_event_admission",
    "allow_publication",
    "allow_fanout",
    "allow_send",
    "allow_endpoint_verification"
  ]) {
    if (quarantine[flag] !== false) {
      violations.push(`Quarantine invariant violated: installation_state.${flag} must be false`);
    }
  }
  if (!quarantine.source_control_epoch || !quarantine.target_control_epoch) {
    violations.push("Quarantine state must declare both source_control_epoch and target_control_epoch");
  } else if (quarantine.source_control_epoch === quarantine.target_control_epoch) {
    violations.push("Quarantine state must allocate a new target_control_epoch distinct from source_control_epoch");
  }
  if (quarantine.old_epoch_credentials_denied !== true) {
    violations.push("Quarantine verification must confirm old sessions/credentials/claims are denied by new control_epoch");
  }

  return violations;
}

export function auditIsolatedRestore(bundle, options = {}) {
  const secretFindings = findRawSecretsInObject(bundle, "$");
  if (secretFindings.length > 0) {
    throw new CliError(`Refusing recovery bundle containing raw secrets:\n- ${secretFindings.join("\n- ")}`, 1);
  }

  const boundaryViolations = verifyAuthoritiesAndContainment(bundle);
  const restoredEvents = Array.isArray(bundle.restored_rq_events) ? bundle.restored_rq_events : [];
  const rcInbox = Array.isArray(bundle.live_rc_anchors) ? bundle.live_rc_anchors : [];
  const externalAccepted = Array.isArray(bundle.external_accepted_receipts)
    ? bundle.external_accepted_receipts
    : [];
  const brokerNotifications = Array.isArray(bundle.broker_notifications)
    ? bundle.broker_notifications
    : [];

  const rqByEventId = new Map(restoredEvents.map((e) => [String(e.event_id), e]));
  const rcByEventId = new Map(rcInbox.map((r) => [String(r.event_id), r]));

  const classA = [];
  const classB = [];
  const classC = [];
  const reverseDivergence = [];
  const attemptActions = [];
  const holds = [];

  for (const rqEvent of restoredEvents) {
    const eventId = String(rqEvent.event_id);
    const rcAnchor = rcByEventId.get(eventId);
    const rqCommittedBeforeRestore =
      rqEvent.delivery_state === "succeeded" ||
      rqEvent.delivery_state === "acknowledged" ||
      rqEvent.acknowledged_before_restore === true;

    if (rqEvent.attempt_state === "prepared" && !rqEvent.send_started_at) {
      attemptActions.push({
        event_id: eventId,
        attempt_id: rqEvent.attempt_id ?? null,
        classification: "prepared_unstarted_retire_eligible",
        allowed_repair_action: "retire_stale_claim"
      });
    } else if (rqEvent.attempt_state === "send_started" || rqEvent.send_started_at) {
      attemptActions.push({
        event_id: eventId,
        attempt_id: rqEvent.attempt_id ?? null,
        classification: "send_started_externally_uncertain",
        allowed_repair_action: "record_receiver_comparison"
      });
    }

    if (rqCommittedBeforeRestore) {
      if (rcAnchor && rcAnchor.committed === true) {
        if (
          rcAnchor.original_facts_sha256 &&
          rqEvent.original_facts_sha256 &&
          rcAnchor.original_facts_sha256 !== rqEvent.original_facts_sha256
        ) {
          const item = {
            event_id: eventId,
            classification: "B_conflicting_facts_hold",
            comparison_outcome: "conflicting_facts",
            requires_hold: true
          };
          classB.push(item);
          holds.push(`Event ${eventId}: original_facts_sha256 mismatch between restored rq and live rc`);
        } else {
          classA.push({
            event_id: eventId,
            classification: "A_consistent_committed",
            comparison_outcome: "matching_committed_anchor",
            receiver_mutation_count: Number(rcAnchor.mutation_count ?? 1),
            requires_hold: false
          });
        }
      } else {
        reverseDivergence.push({
          event_id: eventId,
          classification: "reverse_divergence_receiver_missing_committed_anchor",
          comparison_outcome: "missing_anchor",
          requires_hold: true
        });
        holds.push(
          `Event ${eventId}: restored rq shows acknowledged delivery but live rc lacks anchor (reverse divergence hold)`
        );
      }
      continue;
    }

    // Event exists in restored rq but was not yet acknowledged in the restored snapshot
    if (rcAnchor && rcAnchor.committed === true) {
      const factsMatch =
        !rcAnchor.original_facts_sha256 ||
        !rqEvent.original_facts_sha256 ||
        rcAnchor.original_facts_sha256 === rqEvent.original_facts_sha256;

      if (!factsMatch) {
        classB.push({
          event_id: eventId,
          classification: "B_conflicting_facts_hold",
          comparison_outcome: "conflicting_facts",
          consumer_key: rcAnchor.consumer_key ?? rqEvent.consumer_key ?? null,
          requires_hold: true
        });
        holds.push(`Event ${eventId}: Class B facts hash conflict with live rc anchor`);
      } else {
        classB.push({
          event_id: eventId,
          classification: "B_matching_committed_anchor",
          comparison_outcome: "matching_committed_anchor",
          consumer_key: rcAnchor.consumer_key ?? rqEvent.consumer_key ?? null,
          stable_receipt_id: rcAnchor.receipt_id ?? null,
          receiver_mutation_count: Number(rcAnchor.mutation_count ?? 1),
          deduplicates_on_authorized_retry: true,
          requires_hold: false
        });
      }
    }
  }

  for (const ext of externalAccepted) {
    const eventId = String(ext.event_id);
    if (!rqByEventId.has(eventId)) {
      const hasVerifiedPayload = ext.retained_original_payload_verified === true;
      const rcAnchor = rcByEventId.get(eventId);
      const item = {
        event_id: eventId,
        classification: "C_accepted_after_restore_point_missing",
        accepted_at: ext.accepted_at ?? null,
        producer_receipt_id: ext.receipt_id ?? null,
        receiver_committed: Boolean(rcAnchor?.committed),
        reconstruction_status: hasVerifiedPayload
          ? "verified_producer_payload_available_for_reviewed_reconstruction"
          : "irrecoverable_accepted_work_hold",
        requires_hold: true
      };
      classC.push(item);
      holds.push(
        `Event ${eventId}: accepted after restore point (201) and missing from restored rq (${item.reconstruction_status})`
      );
    }
  }

  const orphanedNotifications = [];
  for (const notif of brokerNotifications) {
    const eventId = String(notif.event_id);
    if (!rqByEventId.has(eventId)) {
      orphanedNotifications.push({
        event_id: eventId,
        broker_stream_seq: notif.stream_seq ?? null,
        classification: "orphaned_post_snapshot_notification_quarantined",
        can_reconstruct_payload_from_metadata: false
      });
    }
  }

  const boundaryOk = boundaryViolations.length === 0;
  const holdsOk = !options.failOnHolds || holds.length === 0;

  return redactSensitiveData({
    ok: boundaryOk && holdsOk,
    boundary_isolation_ok: boundaryOk,
    old_writer_quarantine_verified: boundaryOk,
    restore_point: bundle.restore_point ?? null,
    rpo_lag_seconds: bundle.rpo_lag_seconds ?? null,
    counts: {
      class_A_consistent: classA.length,
      class_B_receiver_ahead: classB.length,
      class_C_missing_accepted: classC.length,
      reverse_divergence: reverseDivergence.length,
      orphaned_broker_notifications: orphanedNotifications.length,
      holds: holds.length
    },
    classifications: {
      A: classA,
      B: classB,
      C: classC,
      reverse_divergence: reverseDivergence,
      attempt_dispositions: attemptActions,
      orphaned_broker_notifications: orphanedNotifications
    },
    holds,
    violations: boundaryViolations
  });
}

runCliMain(import.meta.url, HELP_TEXT, (argv) => {
  const parsed = parseCliFlags(argv, {
    options: {
      "--input": { type: "string", required: true },
      "--config": { type: "string" },
      "--target": { type: "string" },
      "--fail-on-holds": { type: "boolean", default: false },
      "--out": { type: "string" },
      "--json": { type: "boolean", default: false }
    }
  });
  if (parsed.help) {
    return { help: true };
  }
  const bundle = readStrictJsonFile(parsed.options["--input"]);
  const report = auditIsolatedRestore(bundle, {
    failOnHolds: parsed.options["--fail-on-holds"]
  });

  if (parsed.options["--out"]) {
    const outPath = path.resolve(parsed.options["--out"]);
    fs.mkdirSync(path.dirname(outPath), { recursive: true });
    fs.writeFileSync(outPath, `${JSON.stringify(report, null, 2)}\n`, "utf8");
  }

  if (!report.ok) {
    const reasons = [...report.violations, ...(parsed.options["--fail-on-holds"] ? report.holds : [])];
    throw new CliError(`Isolated restore audit failed:\n- ${reasons.join("\n- ")}`, 1);
  }
  if (parsed.options["--json"]) {
    return { exitCode: 0, output: report };
  }
  return {
    exitCode: 0,
    output: `[isolated-restore-audit] ok A=${report.counts.class_A_consistent} B=${report.counts.class_B_receiver_ahead} C=${report.counts.class_C_missing_accepted} holds=${report.counts.holds}`
  };
});
