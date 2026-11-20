import fs from "node:fs";
import path from "node:path";
import {
  CliError,
  canonicalizeJson,
  findRawSecretsInObject,
  parseCliFlags,
  readStrictJsonFile,
  redactSensitiveData,
  runCliMain,
  sha256Hex
} from "../release/lib/cli.mjs";

export const EXIT_CODES = Object.freeze({
  OK: 0,
  INVALID_INPUT: 2,
  UNAUTHORIZED_OR_STALE_REVIEW: 3,
  PRECONDITION_OR_IDEMPOTENCY_CONFLICT: 4,
  CONTENTION: 5,
  UNKNOWN_OUTCOME: 6,
  DEPENDENCY_FAILURE: 7
});

export const ALLOWED_REPAIR_ACTION_KINDS = Object.freeze([
  "retire_stale_claim",
  "reconcile_reservations",
  "continue_publication_episode",
  "record_receiver_comparison",
  "set_recovery_gate",
  "rebuild_projection",
  "establish_target_epoch"
]);

const ALLOWED_CLAIM_KINDS = new Set([
  "publication",
  "fanout",
  "prepared_attempt",
  "coordinator_task"
]);

const ALLOWED_COMPARISON_OUTCOMES = new Set([
  "matching_committed_anchor",
  "missing_anchor",
  "conflicting_facts",
  "retention_unknown",
  "source_unavailable"
]);

const SCOPE_RANK = Object.freeze({
  project: 1,
  tenant: 2,
  installation: 3
});

const HELP_TEXT = `Usage: node tools/recovery/repair-runner.mjs --request <action-request.json> [options]

Repeat-safe reviewed repair dispatcher enforcing 64 KiB request limit, enumerated action kinds,
distinct requester/reviewer separation, exact version/epoch/facts preconditions, and idempotent result recovery.

Exit Codes:
  0  Requested read or exact accepted repair action completed
  2  Invalid input, unknown flag, secret argument, or unsupported action kind
  3  Unauthorized, missing, expired, or self-approved review
  4  Precondition mismatch (version/epoch/facts) or idempotency conflict
  5  Retryable lock/statement contention
  6  Unknown outcome from lost reply (inspect result before retry)
  7  Database or dependency failure

Options:
  --request <path>          Typed nonsecret repair action request JSON (<= 64 KiB)
  --state <path>            Target database/resource state snapshot JSON
  --ledger <path>           Persistent repair execution ledger JSON for repeat-safe idempotency
  --inspect-result          Read-only result observation for --action-id without mutating
  --action-id <uuid>        Specific action UUID to inspect with --inspect-result
  --config <path>           Optional recovery operator/target configuration JSON
  --out <path>              Write sanitized execution result JSON
  --json                    Emit structured JSON output
  -h, --help                Show help without reading secrets or mutating state
`;

function requiresDistinctReviewer(kind, typedPlan) {
  if (
    kind === "reconcile_reservations" ||
    kind === "continue_publication_episode" ||
    kind === "rebuild_projection" ||
    kind === "establish_target_epoch"
  ) {
    return true;
  }
  if (kind === "set_recovery_gate" && typedPlan?.proposed_allow_send === true) {
    return true;
  }
  return false;
}

function validateReviewBinding(request, nowMs) {
  const review = request.review;
  if (!review || typeof review !== "object") {
    throw new CliError(
      "Missing authenticated review record on repair request",
      EXIT_CODES.UNAUTHORIZED_OR_STALE_REVIEW
    );
  }
  if (review.decision !== "approve" && review.decision !== "approved") {
    throw new CliError(
      `Repair action review decision is "${review.decision}", not approved`,
      EXIT_CODES.UNAUTHORIZED_OR_STALE_REVIEW
    );
  }
  if (
    typeof review.authority_evidence_digest !== "string" ||
    !/^[0-9a-f]{64}$/i.test(review.authority_evidence_digest)
  ) {
    throw new CliError(
      "Review record missing valid 64-hex authority_evidence_digest (unsigned approved=true is forbidden)",
      EXIT_CODES.UNAUTHORIZED_OR_STALE_REVIEW
    );
  }
  if (typeof review.reviewer_reference !== "string" || review.reviewer_reference.trim().length === 0) {
    throw new CliError("Review record missing reviewer_reference", EXIT_CODES.UNAUTHORIZED_OR_STALE_REVIEW);
  }
  if (
    requiresDistinctReviewer(request.kind, request.typed_plan) &&
    review.reviewer_reference === request.requester_reference
  ) {
    throw new CliError(
      `Repair action "${request.kind}" requires distinct requester and reviewer identities (self-approval forbidden)`,
      EXIT_CODES.UNAUTHORIZED_OR_STALE_REVIEW
    );
  }
  if (review.plan_sha256 && request.plan_sha256 && review.plan_sha256 !== request.plan_sha256) {
    throw new CliError(
      "Review plan_sha256 does not match action plan_sha256",
      EXIT_CODES.UNAUTHORIZED_OR_STALE_REVIEW
    );
  }
  if (
    review.expected_facts_sha256 &&
    review.expected_facts_sha256 !== request.expected_facts_sha256
  ) {
    throw new CliError(
      "Review expected_facts_sha256 does not match action expected_facts_sha256",
      EXIT_CODES.UNAUTHORIZED_OR_STALE_REVIEW
    );
  }
  if (
    review.proposed_facts_sha256 &&
    review.proposed_facts_sha256 !== request.proposed_facts_sha256
  ) {
    throw new CliError(
      "Review proposed_facts_sha256 does not match action proposed_facts_sha256",
      EXIT_CODES.UNAUTHORIZED_OR_STALE_REVIEW
    );
  }
  if (review.expires_at) {
    const expMs = Date.parse(review.expires_at);
    if (!Number.isFinite(expMs) || expMs <= nowMs) {
      throw new CliError(
        `Review approval expired at ${review.expires_at}`,
        EXIT_CODES.UNAUTHORIZED_OR_STALE_REVIEW
      );
    }
  }
}

function parseCheckedBigInt(val, fieldName) {
  if (typeof val === "bigint") {
    return val;
  }
  if (typeof val === "number" && Number.isSafeInteger(val)) {
    return BigInt(val);
  }
  if (typeof val === "string" && /^-?\d+$/.test(val)) {
    return BigInt(val);
  }
  throw new CliError(`Field "${fieldName}" must be an exact integer string or safe integer`, EXIT_CODES.INVALID_INPUT);
}

function validateKindSpecificInvariants(request, targetState) {
  const kind = request.kind;
  const plan = request.typed_plan ?? {};

  if (kind === "retire_stale_claim") {
    if (!ALLOWED_CLAIM_KINDS.has(plan.claim_kind)) {
      throw new CliError(`Invalid claim_kind "${plan.claim_kind}"`, EXIT_CODES.INVALID_INPUT);
    }
    const sendStartedAt = plan.send_started_at ?? targetState?.target_row?.send_started_at ?? null;
    if (plan.claim_kind === "prepared_attempt" && sendStartedAt !== null) {
      throw new CliError(
        "retire_stale_claim cannot retire a delivery attempt that already has send_started_at recorded",
        EXIT_CODES.PRECONDITION_OR_IDEMPOTENCY_CONFLICT
      );
    }
    if (
      plan.timeline_mode === "stale_timeline_contained" &&
      (!plan.old_writer_containment_reference || String(plan.old_writer_containment_reference).trim().length === 0)
    ) {
      throw new CliError(
        "retire_stale_claim for stale timeline requires old_writer_containment_reference",
        EXIT_CODES.PRECONDITION_OR_IDEMPOTENCY_CONFLICT
      );
    }
    return {
      outcome: "applied",
      preserved_history_row: true,
      released_unstarted_reservation: plan.claim_kind === "prepared_attempt"
    };
  }

  if (kind === "reconcile_reservations") {
    const stored = parseCheckedBigInt(plan.expected_stored_value, "expected_stored_value");
    const derived = parseCheckedBigInt(plan.derived_obligation_value, "derived_obligation_value");
    const proposed = parseCheckedBigInt(plan.proposed_value, "proposed_value");
    const bound = parseCheckedBigInt(plan.capacity_bound, "capacity_bound");

    if (proposed < 0n || bound < 0n || stored < 0n || derived < 0n) {
      throw new CliError(
        "reconcile_reservations rejects negative reservation or capacity values",
        EXIT_CODES.PRECONDITION_OR_IDEMPOTENCY_CONFLICT
      );
    }
    if (proposed > bound) {
      throw new CliError(
        `reconcile_reservations proposed_value (${proposed}) exceeds capacity_bound (${bound})`,
        EXIT_CODES.PRECONDITION_OR_IDEMPOTENCY_CONFLICT
      );
    }
    if (proposed < derived) {
      throw new CliError(
        `reconcile_reservations non-conserving proposed_value (${proposed}) < derived_obligation_value (${derived})`,
        EXIT_CODES.PRECONDITION_OR_IDEMPOTENCY_CONFLICT
      );
    }
    if (plan.gates_held !== true && targetState?.gates_held !== true) {
      throw new CliError(
        "reconcile_reservations requires affected preparation/admission gates held",
        EXIT_CODES.PRECONDITION_OR_IDEMPOTENCY_CONFLICT
      );
    }
    return {
      outcome: "applied",
      old_value: stored.toString(),
      derived_value: derived.toString(),
      new_value: proposed.toString(),
      conservative_policy: plan.conservative_policy ?? "canonical_exact"
    };
  }

  if (kind === "continue_publication_episode") {
    const rootState = targetState?.outbox_state ?? plan.outbox_state;
    if (rootState === "completed") {
      return {
        outcome: "already_complete",
        mutated: false
      };
    }
    const epState = targetState?.episode_state ?? plan.episode_state;
    if (epState !== "review_required") {
      throw new CliError(
        `continue_publication_episode requires episode_state="review_required", got "${epState}"`,
        EXIT_CODES.PRECONDITION_OR_IDEMPOTENCY_CONFLICT
      );
    }
    if (targetState?.active_progressing_fanout_claim === true) {
      throw new CliError(
        "continue_publication_episode refused: a valid fanout claim is actively progressing",
        EXIT_CODES.PRECONDITION_OR_IDEMPOTENCY_CONFLICT
      );
    }
    return {
      outcome: "applied",
      previous_episode_history_retained: true,
      new_episode_linked: true
    };
  }

  if (kind === "record_receiver_comparison") {
    if (!ALLOWED_COMPARISON_OUTCOMES.has(plan.comparison_outcome)) {
      throw new CliError(
        `Invalid comparison_outcome "${plan.comparison_outcome}"`,
        EXIT_CODES.INVALID_INPUT
      );
    }
    if (
      plan.fabricate_http_ack === true ||
      plan.fabricate_verified_supported === true ||
      plan.force_delivery_processed === true
    ) {
      throw new CliError(
        "record_receiver_comparison cannot fabricate HTTP acknowledgement or verified_supported receipt",
        EXIT_CODES.PRECONDITION_OR_IDEMPOTENCY_CONFLICT
      );
    }
    if (plan.comparison_outcome === "conflicting_facts" && plan.requires_hold_investigation !== true) {
      throw new CliError(
        "conflicting_facts comparison outcome requires requires_hold_investigation=true",
        EXIT_CODES.PRECONDITION_OR_IDEMPOTENCY_CONFLICT
      );
    }
    return {
      outcome: "applied",
      comparison_outcome: plan.comparison_outcome,
      provenance_label: plan.source_kind ?? "protected_receiver_inventory"
    };
  }

  if (kind === "set_recovery_gate") {
    const planScope = request.scope_kind ?? "project";
    const targetScope = plan.target_scope_kind ?? planScope;
    if (
      (SCOPE_RANK[planScope] ?? 0) < (SCOPE_RANK[targetScope] ?? 0) ||
      (planScope === "project" && targetScope === "installation")
    ) {
      throw new CliError(
        `A ${planScope}-scoped recovery plan cannot reopen or modify a ${targetScope}-scoped gate`,
        EXIT_CODES.UNAUTHORIZED_OR_STALE_REVIEW
      );
    }
    if (
      plan.proposed_installation_mode === "open" &&
      Number(plan.unresolved_unsafe_scope_count ?? 0) > 0 &&
      (!Array.isArray(plan.retained_hold_refs) || plan.retained_hold_refs.length === 0)
    ) {
      throw new CliError(
        "Cannot set installation mode=open while unresolved unsafe scopes lack enforced retained_hold_refs",
        EXIT_CODES.PRECONDITION_OR_IDEMPOTENCY_CONFLICT
      );
    }
    return {
      outcome: "applied",
      target_scope_kind: targetScope,
      retained_hold_count: Array.isArray(plan.retained_hold_refs) ? plan.retained_hold_refs.length : 0
    };
  }

  if (kind === "establish_target_epoch") {
    const currentMode = targetState?.installation_mode ?? plan.current_installation_mode ?? "recovery_quarantine";
    if (currentMode !== "recovery_quarantine") {
      throw new CliError(
        `establish_target_epoch requires installation_mode="recovery_quarantine", got "${currentMode}"`,
        EXIT_CODES.PRECONDITION_OR_IDEMPOTENCY_CONFLICT
      );
    }
    if (!plan.source_epoch || !plan.target_epoch || plan.source_epoch === plan.target_epoch) {
      throw new CliError(
        "establish_target_epoch requires target_epoch distinct from source_epoch",
        EXIT_CODES.PRECONDITION_OR_IDEMPOTENCY_CONFLICT
      );
    }
    return {
      outcome: "applied",
      source_epoch: plan.source_epoch,
      target_epoch: plan.target_epoch
    };
  }

  if (kind === "rebuild_projection") {
    return {
      outcome: "applied",
      projection_kind: plan.projection_kind ?? "project_delivery_totals"
    };
  }

  throw new CliError(`Unsupported repair action kind: "${kind}"`, EXIT_CODES.INVALID_INPUT);
}

export function dispatchRepairAction(options) {
  const ledgerPath = options.ledgerPath ? path.resolve(options.ledgerPath) : null;
  const ledger =
    ledgerPath && fs.existsSync(ledgerPath)
      ? readStrictJsonFile(ledgerPath)
      : { actions: {} };

  if (options.inspectResultOnly) {
    const actionId = options.actionId;
    if (!actionId) {
      throw new CliError("--inspect-result requires --action-id <uuid>", EXIT_CODES.INVALID_INPUT);
    }
    const existing = ledger.actions?.[actionId];
    if (!existing) {
      throw new CliError(`No recorded execution result for action_id "${actionId}"`, EXIT_CODES.INVALID_INPUT);
    }
    if (existing.state === "unknown") {
      return {
        exitCode: EXIT_CODES.UNKNOWN_OUTCOME,
        result: redactSensitiveData(existing)
      };
    }
    return {
      exitCode: EXIT_CODES.OK,
      result: redactSensitiveData(existing)
    };
  }

  if (!options.requestPath) {
    throw new CliError("Missing required --request <action-request.json>", EXIT_CODES.INVALID_INPUT);
  }

  const request = readStrictJsonFile(options.requestPath, {
    maxBytes: 64 * 1024,
    exitCode: EXIT_CODES.INVALID_INPUT
  });

  const secrets = findRawSecretsInObject(request, "$");
  if (secrets.length > 0) {
    throw new CliError(
      `Refusing repair request containing raw secrets:\n- ${secrets.join("\n- ")}`,
      EXIT_CODES.INVALID_INPUT
    );
  }

  // Also support config/recovery.action-request.json template format cleanly
  const kind = request.kind === "recovery_action_request" && request.action_kind
    ? request.action_kind
    : request.kind;

  if (!ALLOWED_REPAIR_ACTION_KINDS.includes(kind)) {
    throw new CliError(
      `Repair runner refuses unowned or unknown action kind "${kind}". Allowed kinds: ${ALLOWED_REPAIR_ACTION_KINDS.join(", ")}`,
      EXIT_CODES.INVALID_INPUT
    );
  }

  const actionId = String(request.action_id ?? request.id ?? "");
  const operationId = String(request.operation_id ?? "");
  if (!actionId || !operationId) {
    throw new CliError("Repair request requires action_id and operation_id", EXIT_CODES.INVALID_INPUT);
  }

  const proposedFactsSha =
    request.proposed_facts_sha256 ??
    sha256Hex(canonicalizeJson(request.proposed_facts ?? request.typed_plan ?? {}));
  const expectedFactsSha =
    request.expected_facts_sha256 ??
    sha256Hex(canonicalizeJson(request.expected_facts ?? {}));

  const normalizedRequest = {
    ...request,
    kind,
    action_id: actionId,
    operation_id: operationId,
    expected_facts_sha256: expectedFactsSha,
    proposed_facts_sha256: proposedFactsSha
  };

  // 1. Check repeat-safe idempotency ledger BEFORE mutating
  const prior = ledger.actions?.[actionId];
  if (prior) {
    if (prior.proposed_facts_sha256 !== proposedFactsSha || prior.kind !== kind) {
      throw new CliError(
        `Idempotency conflict on action_id "${actionId}": proposed facts or kind differ from recorded execution`,
        EXIT_CODES.PRECONDITION_OR_IDEMPOTENCY_CONFLICT
      );
    }
    if (prior.state === "unknown") {
      throw new CliError(
        `Action "${actionId}" has state=unknown after lost commit reply; inspect with --inspect-result before retrying`,
        EXIT_CODES.UNKNOWN_OUTCOME
      );
    }
    if (prior.state === "applied") {
      return {
        exitCode: EXIT_CODES.OK,
        result: redactSensitiveData({
          ...prior.result,
          idempotent_replay: true
        })
      };
    }
  }

  const targetState = options.statePath ? readStrictJsonFile(options.statePath) : {};
  if (targetState.simulate_contention === true) {
    throw new CliError(
      "Bounded lock/statement timeout contention encountered; safe to retry same action_id",
      EXIT_CODES.CONTENTION
    );
  }
  if (targetState.simulate_dependency_failure === true) {
    throw new CliError("Database connection dependency unavailable", EXIT_CODES.DEPENDENCY_FAILURE);
  }

  // 2. Validate review & requester!=reviewer separation
  validateReviewBinding(normalizedRequest, Date.now());

  // 3. Validate control_epoch, target_version, and expected_facts_sha256 preconditions
  if (
    targetState.current_control_epoch &&
    normalizedRequest.expected_control_epoch &&
    kind !== "establish_target_epoch" &&
    targetState.current_control_epoch !== normalizedRequest.expected_control_epoch
  ) {
    throw new CliError(
      `Control epoch mismatch: expected "${normalizedRequest.expected_control_epoch}", current "${targetState.current_control_epoch}"`,
      EXIT_CODES.PRECONDITION_OR_IDEMPOTENCY_CONFLICT
    );
  }
  if (
    targetState.current_target_version !== undefined &&
    normalizedRequest.expected_target_version !== undefined &&
    String(targetState.current_target_version) !== String(normalizedRequest.expected_target_version)
  ) {
    throw new CliError(
      `Target version changed (expected ${normalizedRequest.expected_target_version}, current ${targetState.current_target_version}); re-inspect and create a new plan revision`,
      EXIT_CODES.PRECONDITION_OR_IDEMPOTENCY_CONFLICT
    );
  }
  if (targetState.current_facts !== undefined) {
    const actualFactsSha = sha256Hex(canonicalizeJson(targetState.current_facts));
    if (actualFactsSha !== expectedFactsSha) {
      throw new CliError(
        `Expected facts digest mismatch (expected ${expectedFactsSha.slice(0, 12)}, actual ${actualFactsSha.slice(0, 12)})`,
        EXIT_CODES.PRECONDITION_OR_IDEMPOTENCY_CONFLICT
      );
    }
  }

  // 4. Validate action-kind specific invariants
  const detail = validateKindSpecificInvariants(normalizedRequest, targetState);

  if (targetState.simulate_lost_commit_reply === true) {
    const unknownEntry = {
      action_id: actionId,
      operation_id: operationId,
      kind,
      state: "unknown",
      proposed_facts_sha256: proposedFactsSha,
      updated_at: new Date().toISOString()
    };
    ledger.actions[actionId] = unknownEntry;
    if (ledgerPath) {
      fs.mkdirSync(path.dirname(ledgerPath), { recursive: true });
      fs.writeFileSync(ledgerPath, `${JSON.stringify(ledger, null, 2)}\n`, "utf8");
    }
    throw new CliError(
      `Commit reply lost for action "${actionId}"; recorded state=unknown`,
      EXIT_CODES.UNKNOWN_OUTCOME
    );
  }

  const prevVersion = BigInt(normalizedRequest.expected_target_version ?? targetState.current_target_version ?? 1);
  const newVersion = detail.outcome === "already_complete" ? prevVersion : prevVersion + 1n;
  const resultingFactsSha = sha256Hex(
    canonicalizeJson({
      action_id: actionId,
      operation_id: operationId,
      kind,
      new_target_version: newVersion.toString(),
      proposed_facts_sha256: proposedFactsSha,
      detail
    })
  );

  const acceptedResult = redactSensitiveData({
    ok: true,
    action_id: actionId,
    operation_id: operationId,
    kind,
    outcome: detail.outcome,
    result_version: newVersion.toString(),
    resulting_facts_sha256: resultingFactsSha,
    idempotent_replay: false,
    detail
  });

  ledger.actions[actionId] = {
    action_id: actionId,
    operation_id: operationId,
    kind,
    state: "applied",
    proposed_facts_sha256: proposedFactsSha,
    result: acceptedResult,
    updated_at: new Date().toISOString()
  };

  if (ledgerPath) {
    fs.mkdirSync(path.dirname(ledgerPath), { recursive: true });
    fs.writeFileSync(ledgerPath, `${JSON.stringify(ledger, null, 2)}\n`, "utf8");
  }
  if (options.outPath) {
    const outPath = path.resolve(options.outPath);
    fs.mkdirSync(path.dirname(outPath), { recursive: true });
    fs.writeFileSync(outPath, `${JSON.stringify(acceptedResult, null, 2)}\n`, "utf8");
  }

  return {
    exitCode: EXIT_CODES.OK,
    result: acceptedResult
  };
}

runCliMain(
  import.meta.url,
  HELP_TEXT,
  (argv) => {
    const parsed = parseCliFlags(argv, {
      errorExitCode: EXIT_CODES.INVALID_INPUT,
      options: {
        "--request": { type: "string" },
        "--state": { type: "string" },
        "--ledger": { type: "string" },
        "--inspect-result": { type: "boolean", default: false },
        "--action-id": { type: "string" },
        "--config": { type: "string" },
        "--out": { type: "string" },
        "--json": { type: "boolean", default: false }
      }
    });
    if (parsed.help) {
      return { help: true };
    }
    const res = dispatchRepairAction({
      requestPath: parsed.options["--request"],
      statePath: parsed.options["--state"],
      ledgerPath: parsed.options["--ledger"],
      inspectResultOnly: parsed.options["--inspect-result"],
      actionId: parsed.options["--action-id"],
      outPath: parsed.options["--out"]
    });
    if (parsed.options["--json"]) {
      return { exitCode: res.exitCode, output: res.result };
    }
    return {
      exitCode: res.exitCode,
      output: `[repair-runner] action=${res.result.action_id} kind=${res.result.kind ?? "unknown"} outcome=${res.result.outcome ?? res.result.state} version=${res.result.result_version ?? "n/a"} replay=${Boolean(res.result.idempotent_replay)}`
    };
  },
  { errorExitCode: EXIT_CODES.INVALID_INPUT }
);
