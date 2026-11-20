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

const HELP_TEXT = `Usage: node tools/operations/diagnose.mjs --input <snapshot.json> [options]

Analyze a sanitized nonsecret Relayquill incident snapshot in strict causal order
to pinpoint the first failing (unsupported) boundary without falsifying downstream
state or deleting accepted obligations.

Causal Boundary Order:
  1. installation_gate
  2. producer_admission
  3. outbox_publication
  4. ordered_fanout
  5. dispatch_eligibility
  6. outbound_egress
  7. receiver_verification
  8. projection_consistency

Options:
  --input <path>        Sanitized nonsecret diagnostic snapshot JSON (required)
  --fail-on-finding     Exit 1 if any failing or uncertain causal boundary is detected
  --out <path>          Write sanitized causal diagnosis report JSON
  --json                Emit structured JSON output
  -h, --help            Show help without reading secrets or mutating state
`;

const CAUSAL_BOUNDARIES = Object.freeze([
  "installation_gate",
  "producer_admission",
  "outbox_publication",
  "ordered_fanout",
  "dispatch_eligibility",
  "outbound_egress",
  "receiver_verification",
  "projection_consistency"
]);

function assessInstallationGate(snapshot) {
  const inst = snapshot.installation ?? null;
  if (!inst) {
    return { status: "not_observed", severity: "info", reason_code: null, summary: "No installation gate block provided." };
  }
  if (inst.mode === "recovery_quarantine") {
    return {
      status: "failing",
      severity: "critical",
      reason_code: "INSTALLATION_RECOVERY_QUARANTINE",
      summary: `Installation is in mode="recovery_quarantine" (control_epoch=${inst.control_epoch ?? "unknown"}).`,
      runbook_action: "Inspect isolated restore/containment state and reopen only reviewed scopes via protected recovery cutover."
    };
  }
  const closedGates = ["allow_event_admission", "allow_publication", "allow_fanout", "allow_send"]
    .filter((k) => inst[k] === false);
  if (closedGates.length > 0) {
    return {
      status: "failing",
      severity: "warn",
      reason_code: "INSTALLATION_GATE_CLOSED",
      summary: `Installation gate(s) closed: ${closedGates.join(", ")}.`,
      runbook_action: "Verify active release/recovery holds before reopening gates; preserve existing obligations."
    };
  }
  if (inst.epoch_mismatch === true) {
    return {
      status: "failing",
      severity: "critical",
      reason_code: "CONTROL_EPOCH_MISMATCH",
      summary: "Worker/process runtime epoch disagrees with current installation control_epoch.",
      runbook_action: "Restart stale role processes against current configuration and verify old writers are contained."
    };
  }
  return { status: "healthy", severity: "info", reason_code: null, summary: "Installation gates and control epoch match." };
}

function assessProducerAdmission(snapshot) {
  const adm = snapshot.admission ?? snapshot.event ?? null;
  if (!adm) {
    return { status: "not_observed", severity: "info", reason_code: null, summary: "No admission record in snapshot." };
  }
  if (adm.missing === true || adm.accepted === false) {
    return {
      status: "failing",
      severity: "critical",
      reason_code: adm.reason_code ?? "EVENT_ADMISSION_ABSENT",
      summary: "Canonical accepted event row is absent or rejected at admission boundary.",
      runbook_action: "Use resolvePrepared with the producer's exact frozen request; never invent a new business key."
    };
  }
  if (adm.response_lost_unknown === true) {
    return {
      status: "failing",
      severity: "warn",
      reason_code: "ADMISSION_RESPONSE_UNKNOWN",
      summary: "Producer response was lost; resolve using original frozen body/idempotency key.",
      runbook_action: "Query POST /events/resolve with exact business_key and submitted_shape_sha256."
    };
  }
  if (adm.content_integrity_ok === false) {
    return {
      status: "failing",
      severity: "critical",
      reason_code: "CONTENT_INTEGRITY_MISMATCH",
      summary: "Stored event content digest or byte count failed verification.",
      runbook_action: "Hold affected scope and run isolated integrity verification before releasing deliveries."
    };
  }
  return { status: "healthy", severity: "info", reason_code: null, summary: "Canonical event admission verified." };
}

function assessOutboxPublication(snapshot) {
  const pub = snapshot.publication ?? snapshot.outbox ?? null;
  if (!pub) {
    return { status: "not_observed", severity: "info", reason_code: null, summary: "No outbox publication block in snapshot." };
  }
  if (pub.broker_quorum_lost === true) {
    return {
      status: "failing",
      severity: "critical",
      reason_code: "BROKER_QUORUM_LOST",
      summary: "JetStream broker cluster lost quorum; PubAck unavailable while DB outbox work remains retained.",
      runbook_action: "Restore broker 2-of-3 quorum; do not clear outbox rows or switch to DiscardOld."
    };
  }
  if (pub.stream_discard_new_full === true || pub.last_safe_error_code === "STREAM_FULL_DISCARD_NEW") {
    return {
      status: "failing",
      severity: "warn",
      reason_code: "STREAM_FULL_DISCARD_NEW",
      summary: "JetStream stream reached DiscardNew byte/message cap and is rejecting new publications.",
      runbook_action: "Pause new event admission under capacity policy while draining existing backlog; never purge stream messages."
    };
  }
  if (pub.observation_state === "not_observed" || pub.state === "pending" || pub.state === "retry_wait") {
    return {
      status: "failing",
      severity: "warn",
      reason_code: pub.last_safe_error_code ?? "OUTBOX_PUBLICATION_ABSENT",
      summary: `Event accepted in DB outbox (generation=${pub.current_publication_generation ?? 1}), but broker observation is ${pub.observation_state ?? pub.state}.`,
      runbook_action: "Check relay readiness, broker TLS/NKey scope, and claim lease before considering recovery generation."
    };
  }
  return { status: "healthy", severity: "info", reason_code: null, summary: "Broker publication observed." };
}

function assessOrderedFanout(snapshot) {
  const fan = snapshot.fanout ?? null;
  if (!fan) {
    return { status: "not_observed", severity: "info", reason_code: null, summary: "No fanout block in snapshot." };
  }
  if (fan.blocked_predecessor && fan.blocked_predecessor.project_event_sequence !== undefined) {
    return {
      status: "failing",
      severity: "warn",
      reason_code: fan.blocked_predecessor.reason_code ?? "FANOUT_PREDECESSOR_BLOCKED",
      summary: `Fanout blocked behind predecessor project_event_sequence #${fan.blocked_predecessor.project_event_sequence}.`,
      runbook_action: "Investigate the exact blocked predecessor event and fanout claim; never skip a predecessor watermark."
    };
  }
  if (Number(fan.no_progress_recovery_generations ?? 0) >= 5 || fan.episode_state === "review_required") {
    return {
      status: "failing",
      severity: "critical",
      reason_code: "FANOUT_EPISODE_REVIEW_REQUIRED",
      summary: "Fanout episode halted after repeated no-progress recovery generations.",
      runbook_action: "Inspect consumer permissions and topology state, then run reviewed continue_publication_episode."
    };
  }
  if (fan.state && fan.state !== "completed") {
    return {
      status: "failing",
      severity: "warn",
      reason_code: "FANOUT_INCOMPLETE",
      summary: `Canonical event_fanout state is "${fan.state}" (examined=${fan.examined_count ?? "?"}, matched=${fan.matched_count ?? "?"}).`,
      runbook_action: "Inspect fanout worker claim and consumer lag without acknowledging stuck JetStream deliveries."
    };
  }
  return { status: "healthy", severity: "info", reason_code: null, summary: "Ordered fanout materialized." };
}

function assessDispatchEligibility(snapshot) {
  const deliv = snapshot.delivery ?? null;
  const endpoint = snapshot.endpoint ?? null;
  const circuit = snapshot.circuit ?? null;
  const ordering = snapshot.ordering ?? null;
  const capacity = snapshot.capacity ?? null;

  if (!deliv && !endpoint && !circuit && !ordering && !capacity) {
    return { status: "not_observed", severity: "info", reason_code: null, summary: "No dispatch eligibility block in snapshot." };
  }
  if (endpoint?.state === "quarantined") {
    return {
      status: "failing",
      severity: "critical",
      reason_code: "ENDPOINT_QUARANTINED",
      summary: `Endpoint ${endpoint.endpoint_id ?? ""} is in security state="quarantined".`,
      runbook_action: "Resolve security cause, advance verification/signing prerequisites, and resume via step-up."
    };
  }
  if (endpoint?.state === "paused" || deliv?.blocking_reason === "SEND_HOLD") {
    return {
      status: "failing",
      severity: "warn",
      reason_code: deliv?.blocking_reason ?? "ENDPOINT_OR_SUBSCRIPTION_HELD",
      summary: "Dispatch is paused by explicit endpoint pause or subscription send_hold.",
      runbook_action: "Inspect hold provenance before releasing; retained accepted obligations remain queued."
    };
  }
  if (circuit?.state === "open") {
    return {
      status: "failing",
      severity: "warn",
      reason_code: "CIRCUIT_OPEN",
      summary: `Endpoint circuit generation ${circuit.circuit_generation ?? "?"} is open (reopen_not_before=${circuit.reopen_not_before ?? "unknown"}).`,
      runbook_action: "Wait for reopen window and request one bounded half-open probe; never force-clear failures."
    };
  }
  if (ordering?.state === "blocked" || ordering?.blocked_delivery_id) {
    return {
      status: "failing",
      severity: "warn",
      reason_code: ordering.blocked_reason_code ?? "STRICT_ORDER_HEAD_BLOCKED",
      summary: `Strict ordering key blocked at delivery ${ordering.blocked_delivery_id ?? "unknown"} (seq #${ordering.next_eligible_sequence ?? "?"}).`,
      runbook_action: "Resolve or propose reviewed skip/replay for the blocked head delivery; inspect independent receiver head."
    };
  }
  if (capacity?.secret_retrieval_denied === true || deliv?.blocking_reason === "SECRET_CUSTODY_ERROR") {
    return {
      status: "failing",
      severity: "critical",
      reason_code: "SECRET_CUSTODY_DENIED",
      summary: "Sender cannot retrieve signing secret from custody provider; unstarted sends deferred.",
      runbook_action: "Restore scoped workload secret access; never transmit unsigned webhooks or fallback to static keys."
    };
  }
  if (deliv?.state === "dead_letter") {
    return {
      status: "failing",
      severity: "warn",
      reason_code: deliv.blocking_reason ?? "DELIVERY_DEAD_LETTER",
      summary: `Delivery ${deliv.delivery_id ?? ""} reached dead_letter after ${deliv.attempt_count ?? "?"} attempts.`,
      runbook_action: "Inspect prior attempt outcomes and receiver inbox state, then submit a two-person replay proposal."
    };
  }
  return { status: "healthy", severity: "info", reason_code: null, summary: "Dispatch eligibility gates open." };
}

function assessOutboundEgress(snapshot) {
  const net = snapshot.network_decision ?? null;
  const att = snapshot.latest_attempt ?? null;
  if (!net && !att) {
    return { status: "not_observed", severity: "info", reason_code: null, summary: "No outbound egress attempt in snapshot." };
  }
  if (net?.decision === "denied") {
    return {
      status: "failing",
      severity: "critical",
      reason_code: net.reason_code ?? "EGRESS_POLICY_DENIED",
      summary: `Outbound connection denied prior to HTTP transmit (${net.reason_code ?? "policy_denied"}, family=${net.ip_family ?? "?"}).`,
      runbook_action: "Fix destination DNS/egress policy; never bypass RFC1918/private CIDR or redirect restrictions."
    };
  }
  if (att?.external_outcome === "unknown" || att?.state === "transport_unknown" || att?.state === "send_started") {
    return {
      status: "failing",
      severity: "warn",
      reason_code: att.safe_error_code ?? "EXTERNAL_ATTEMPT_OUTCOME_UNKNOWN",
      summary: `Attempt ${att.attempt_id ?? ""} started send with external_outcome="unknown" (fence=${att.fencing_token ?? "?"}).`,
      runbook_action: "Inspect independent receiver inbox via consumer key/original_facts_sha256 before retrying or replaying."
    };
  }
  if (att?.external_outcome === "observed_non_success") {
    return {
      status: "failing",
      severity: "warn",
      reason_code: att.safe_error_code ?? `HTTP_${att.response_status ?? "ERROR"}`,
      summary: `Receiver returned non-success HTTP status ${att.response_status ?? "unknown"} (${att.outcome_class ?? "error"}).`,
      runbook_action: "Inspect receiver signature/freshness configuration and retry schedule."
    };
  }
  return { status: "healthy", severity: "info", reason_code: null, summary: "Outbound HTTP delivery acknowledged." };
}

function assessReceiverVerification(snapshot) {
  const rc = snapshot.receiver_receipt ?? snapshot.receiver ?? null;
  if (!rc) {
    return { status: "not_observed", severity: "info", reason_code: null, summary: "No receiver verification block in snapshot." };
  }
  if (rc.original_facts_mismatch === true || rc.verification_state === "rejected") {
    return {
      status: "failing",
      severity: "critical",
      reason_code: rc.reason_code ?? "RECEIVER_RECEIPT_REJECTED",
      summary: "Receiver receipt rejected or original_facts_sha256 mismatched independent receiver anchor.",
      runbook_action: "Place affected integration on hold; compare original_facts_sha256 across sender and receiver authorities."
    };
  }
  if (rc.receipt_profile === "http_ack_only" || rc.verification_state === "unverified") {
    return {
      status: "failing",
      severity: "info",
      reason_code: "PROCESSING_UNVERIFIED_HTTP_ACK_ONLY",
      summary: "HTTP 2xx observed, but end-to-end business processing remains unverified (http_ack_only or unverified receipt).",
      runbook_action: "Upgrade contract to receiver_local_commit_v1 if cryptographic processing proof is required; do not re-send acknowledged deliveries just for a badge."
    };
  }
  return { status: "healthy", severity: "info", reason_code: null, summary: "Verified receiver receipt matches contract." };
}

function assessProjectionConsistency(snapshot) {
  const proj = snapshot.projection ?? null;
  if (!proj) {
    return { status: "not_observed", severity: "info", reason_code: null, summary: "No projection consistency block in snapshot." };
  }
  if (proj.status === "mismatched" || (proj.lag_sequences !== undefined && Number(proj.lag_sequences) > 0)) {
    return {
      status: "failing",
      severity: "warn",
      reason_code: proj.status === "mismatched" ? "PROJECTION_MISMATCHED" : "PROJECTION_LAGGING",
      summary: `Read projection status=${proj.status ?? "lagging"} (lag=${proj.lag_sequences ?? "unknown"}).`,
      runbook_action: "Run bounded projection rebuild from canonical source tables; do not trust stale dashboard counters."
    };
  }
  return { status: "healthy", severity: "info", reason_code: null, summary: "Projection matches canonical source state." };
}

const ASSESSORS = Object.freeze({
  installation_gate: assessInstallationGate,
  producer_admission: assessProducerAdmission,
  outbox_publication: assessOutboxPublication,
  ordered_fanout: assessOrderedFanout,
  dispatch_eligibility: assessDispatchEligibility,
  outbound_egress: assessOutboundEgress,
  receiver_verification: assessReceiverVerification,
  projection_consistency: assessProjectionConsistency
});

export function diagnoseSnapshot(snapshot) {
  if (!snapshot || typeof snapshot !== "object" || Array.isArray(snapshot)) {
    throw new CliError("Diagnostic snapshot must be a plain JSON object", 1);
  }
  const secretFindings = findRawSecretsInObject(snapshot, "$");
  if (secretFindings.length > 0) {
    throw new CliError(
      `Refusing diagnostic snapshot containing raw secrets:\n- ${secretFindings.join("\n- ")}`,
      1
    );
  }

  let firstFailure = null;
  const assessments = [];
  const confirmedFacts = [];
  const uncertainOutcomes = [];

  for (const boundary of CAUSAL_BOUNDARIES) {
    const raw = ASSESSORS[boundary](snapshot);
    if (firstFailure !== null) {
      assessments.push({
        boundary,
        status: raw.status === "healthy" ? "healthy" : "blocked_upstream",
        severity: "info",
        reason_code: raw.reason_code,
        summary:
          raw.status === "healthy"
            ? raw.summary
            : `Blocked or downstream of first failing boundary "${firstFailure.boundary}".`
      });
      continue;
    }

    assessments.push({
      boundary,
      status: raw.status,
      severity: raw.severity,
      reason_code: raw.reason_code,
      summary: raw.summary
    });

    if (raw.status === "healthy") {
      confirmedFacts.push(`${boundary}: ${raw.summary}`);
    } else if (raw.status === "failing") {
      firstFailure = {
        boundary,
        severity: raw.severity,
        reason_code: raw.reason_code,
        evidence_summary: raw.summary,
        runbook_action: raw.runbook_action,
        preserves_obligations: true
      };
      if (raw.reason_code === "EXTERNAL_ATTEMPT_OUTCOME_UNKNOWN" || raw.reason_code === "ADMISSION_RESPONSE_UNKNOWN") {
        uncertainOutcomes.push(raw.summary);
      }
    }
  }

  const overallStatus =
    firstFailure === null
      ? "healthy"
      : uncertainOutcomes.length > 0
        ? "uncertain_external_outcome"
        : firstFailure.boundary === "installation_gate"
          ? "held_or_quarantined"
          : "degraded_with_causal_boundary";

  return redactSensitiveData({
    ok: firstFailure === null,
    status: overallStatus,
    incident_ref: snapshot.incident_ref ?? null,
    scope: snapshot.scope ?? null,
    first_failing_boundary: firstFailure,
    boundary_assessments: assessments,
    confirmed_facts: confirmedFacts,
    uncertain_external_outcomes: uncertainOutcomes,
    recommended_next_checks: firstFailure
      ? [
          firstFailure.runbook_action,
          "Preserve all accepted outbox, delivery, and attempt history; never delete rows or mutate business keys."
        ]
      : ["All observed boundaries are healthy."]
  });
}

runCliMain(import.meta.url, HELP_TEXT, (argv) => {
  const parsed = parseCliFlags(argv, {
    options: {
      "--input": { type: "string", required: true },
      "--fail-on-finding": { type: "boolean", default: false },
      "--out": { type: "string" },
      "--json": { type: "boolean", default: false }
    }
  });
  if (parsed.help) {
    return { help: true };
  }
  const snapshot = readStrictJsonFile(parsed.options["--input"]);
  const report = diagnoseSnapshot(snapshot);

  if (parsed.options["--out"]) {
    const resolvedOut = path.resolve(parsed.options["--out"]);
    fs.mkdirSync(path.dirname(resolvedOut), { recursive: true });
    fs.writeFileSync(resolvedOut, `${JSON.stringify(report, null, 2)}\n`, "utf8");
  }

  const exitCode = parsed.options["--fail-on-finding"] && !report.ok ? 1 : 0;
  if (parsed.options["--json"]) {
    return { exitCode, output: report };
  }
  const first = report.first_failing_boundary;
  return {
    exitCode,
    output: first
      ? `[diagnose] status=${report.status} first_failing_boundary=${first.boundary} reason=${first.reason_code}`
      : `[diagnose] status=${report.status} first_failing_boundary=none`
  };
});
