import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import {
  ConflictDomainError,
  RECOVERY_ACTION_KINDS,
  ValidationDomainError,
  parseControlEpoch,
  parseProjectId,
  parseRecoveryActionId,
  parseRecoveryIncidentId,
  parseRecoveryOperationId,
  parseSha256Hex,
  parseTenantId,
  formatUtcTimestamp,
  nowUtcInstant
} from "@relayquill/domain";
import { canonicalizeJson, sha256Utf8Hex } from "@relayquill/contracts";
import {
  type PgAdapter,
  createRecoveryOperation,
  executeContinuePublicationEpisode,
  executeEstablishTargetEpoch,
  executeRebuildProjection,
  executeReconcileReservations,
  executeRecordReceiverComparison,
  executeRetireStaleClaim,
  executeSetRecoveryGate,
  openRecoveryIncident,
  planRecoveryAction,
  readClaimInventory,
  readInstallationStatus,
  readObligationInventory,
  readProjectionSourceCounts,
  reviewRecoveryAction
} from "@relayquill/postgres";

export type RecoverySubcommand = "inspect" | "plan" | "review" | "execute";

export interface RunRecoveryCommandOptions {
  readonly subcommand: RecoverySubcommand;
  readonly pgAdapter: PgAdapter;
  readonly planFile?: string | undefined;
  readonly tenantId?: string | undefined;
  readonly projectId?: string | undefined;
  readonly actionId?: string | undefined;
  readonly operationId?: string | undefined;
  readonly incidentId?: string | undefined;
  readonly operatorRef?: string | undefined;
  readonly reviewerRef?: string | undefined;
  readonly decision?: "approve" | "reject" | undefined;
  readonly reasonCode?: string | undefined;
  readonly evidenceRef?: string | undefined;
}

export async function runRecoveryCommand(
  options: RunRecoveryCommandOptions
): Promise<Record<string, unknown>> {
  if (options.subcommand === "inspect") {
    return options.pgAdapter.withTransaction("rq_recovery", async (tx) => {
      const installation = await readInstallationStatus(tx);
      const claims = await readClaimInventory(
        tx,
        options.tenantId !== undefined ? parseTenantId(options.tenantId, "tenant_id") : null,
        options.projectId !== undefined ? parseProjectId(options.projectId, "project_id") : null
      );
      const obligations =
        options.tenantId !== undefined
          ? await readObligationInventory(
              tx,
              parseTenantId(options.tenantId, "tenant_id"),
              options.projectId !== undefined ? parseProjectId(options.projectId, "project_id") : null
            )
          : [];
      const projectCounts =
        options.tenantId !== undefined && options.projectId !== undefined
          ? await readProjectionSourceCounts(
              tx,
              parseTenantId(options.tenantId, "tenant_id"),
              parseProjectId(options.projectId, "project_id")
            )
          : undefined;
      return {
        ok: true,
        subcommand: "inspect",
        installation,
        claimsCount: claims.length,
        claims: claims.slice(0, 25),
        obligationsCount: obligations.length,
        obligations: obligations.slice(0, 25),
        ...(projectCounts !== undefined ? { projectProjectionSourceCounts: projectCounts } : {})
      };
    }, { readOnly: true });
  }

  if (options.subcommand === "plan") {
    if (options.planFile === undefined) {
      throw new ValidationDomainError({
        code: "INVALID_VALUE",
        message: "recovery plan requires --plan-file <path>"
      });
    }
    const raw = JSON.parse(fs.readFileSync(path.resolve(options.planFile), "utf8")) as Record<
      string,
      unknown
    >;
    const incidentId = parseRecoveryIncidentId(
      raw["incident_id"] ?? options.incidentId ?? crypto.randomUUID(),
      "incident_id"
    );
    const operationId = parseRecoveryOperationId(
      raw["operation_id"] ?? options.operationId ?? crypto.randomUUID(),
      "operation_id"
    );
    const actionId = parseRecoveryActionId(
      raw["action_id"] ?? options.actionId ?? crypto.randomUUID(),
      "action_id"
    );
    const rawKind = raw["action_kind"];
    const kind = typeof rawKind === "string" ? rawKind : "";
    if (!(RECOVERY_ACTION_KINDS as readonly string[]).includes(kind)) {
      throw new ValidationDomainError({
        code: "INVALID_VALUE",
        message: `Invalid recovery action_kind "${kind}"`
      });
    }
    const requesterRef =
      typeof raw["requester_reference"] === "string"
        ? raw["requester_reference"]
        : (options.operatorRef ?? "recovery-operator");
    const reasonCode =
      typeof raw["reason_code"] === "string"
        ? raw["reason_code"]
        : (options.reasonCode ?? "OPERATOR_RECOVERY");
    const evidenceRef =
      typeof raw["evidence_reference"] === "string"
        ? raw["evidence_reference"]
        : (options.evidenceRef ?? "recovery-plan");
    const typedPlan = (raw["typed_plan"] ?? {}) as Record<string, unknown>;
    const scopeKind = (raw["scope_kind"] ?? "installation") as "installation" | "tenant" | "project";
    const planSha256 = sha256Utf8Hex(canonicalizeJson(typedPlan as never));
    const expectedFactsSha256 = parseSha256Hex(
      raw["expected_facts_sha256"] ?? planSha256,
      "expected_facts_sha256"
    );
    const proposedFactsSha256 = parseSha256Hex(
      raw["proposed_facts_sha256"] ?? planSha256,
      "proposed_facts_sha256"
    );

    return options.pgAdapter.withTransaction("rq_recovery", async (tx) => {
      const inst = await readInstallationStatus(tx);
      const externalOpId =
        typeof raw["external_operation_id"] === "string"
          ? raw["external_operation_id"]
          : operationId;
      const targetEpoch = parseControlEpoch(raw["target_epoch"] ?? inst.controlEpoch, "target_epoch");
      const dbDigest = parseSha256Hex(
        raw["target_database_identity_digest"] ?? planSha256,
        "target_database_identity_digest"
      );

      await openRecoveryIncident(tx, {
        incidentId,
        externalOperationId: `${externalOpId}-inc`,
        incidentReference:
          typeof raw["incident_reference"] === "string"
            ? raw["incident_reference"]
            : incidentId,
        scopeKind,
        tenantId: typeof raw["tenant_id"] === "string" ? parseTenantId(raw["tenant_id"]) : null,
        projectId: typeof raw["project_id"] === "string" ? parseProjectId(raw["project_id"]) : null
      });
      await createRecoveryOperation(tx, {
        operationId,
        incidentId,
        externalOperationId: externalOpId,
        sourceEpoch: inst.controlEpoch,
        targetEpoch,
        targetDatabaseIdentityDigest: dbDigest,
        planSha256,
        requesterReference: requesterRef
      });
      await planRecoveryAction(tx, {
        actionId,
        operationId,
        ordinal: typeof raw["ordinal"] === "number" ? raw["ordinal"] : 1,
        kind: kind as (typeof RECOVERY_ACTION_KINDS)[number],
        scopeKind,
        tenantId: typeof raw["tenant_id"] === "string" ? parseTenantId(raw["tenant_id"]) : null,
        projectId: typeof raw["project_id"] === "string" ? parseProjectId(raw["project_id"]) : null,
        targetId: typeof raw["target_id"] === "string" ? raw["target_id"] : null,
        expectedFactsSha256,
        proposedFactsSha256,
        requesterReference: requesterRef,
        reasonCode,
        evidenceReference: evidenceRef,
        typedPlan
      });
      return {
        ok: true,
        subcommand: "plan",
        incidentId,
        operationId,
        actionId,
        planSha256
      };
    });
  }

  if (options.subcommand === "review") {
    const actionId = parseRecoveryActionId(options.actionId, "action_id");
    const reviewerRef = options.reviewerRef ?? options.operatorRef;
    if (reviewerRef === undefined || reviewerRef.trim().length === 0) {
      throw new ValidationDomainError({
        code: "INVALID_VALUE",
        message: "recovery review requires --reviewer-ref <operator-id>"
      });
    }
    const decision = options.decision ?? "approve";

    return options.pgAdapter.withTransaction("rq_recovery", async (tx) => {
      const actionRes = await tx.query<Record<string, unknown>>(
        `SELECT a.id, a.operation_id, a.expected_facts_sha256, a.proposed_facts_sha256,
                a.requester_reference, o.plan_sha256, o.target_epoch
           FROM rq_recovery.actions a
           JOIN rq_recovery.operations o ON o.id = a.operation_id
          WHERE a.id = $1::uuid`,
        [actionId]
      );
      const row = actionRes.rows[0];
      if (row === undefined) {
        throw new ConflictDomainError({
          code: "NOT_FOUND",
          message: `Recovery action ${actionId} not found`
        });
      }
      if (String(row["requester_reference"]) === reviewerRef.trim()) {
        throw new ConflictDomainError({
          code: "STATE_TRANSITION_NOT_ALLOWED",
          message: "Recovery reviewer cannot be identical to requester"
        });
      }
      const toHex = (val: unknown): string =>
        Buffer.isBuffer(val)
          ? val.toString("hex")
          : val instanceof Uint8Array
            ? Buffer.from(val).toString("hex")
            : String(val).replace(/^\\x/, "");

      const reviewId = crypto.randomUUID();
      const reviewExpiresAt = formatUtcTimestamp(nowUtcInstant().add({ minutes: 30 }));
      const authorityEvidenceDigest = parseSha256Hex(
        crypto.createHash("sha256").update(`${actionId}:${reviewerRef.trim()}`, "utf8").digest("hex"),
        "authorityEvidenceDigest"
      );
      await reviewRecoveryAction(tx, {
        reviewId,
        actionId,
        planSha256: parseSha256Hex(toHex(row["plan_sha256"])),
        targetEpoch: parseControlEpoch(row["target_epoch"]),
        expectedFactsSha256: parseSha256Hex(toHex(row["expected_facts_sha256"])),
        proposedFactsSha256: parseSha256Hex(toHex(row["proposed_facts_sha256"])),
        reviewerReference: reviewerRef.trim(),
        decision,
        expiresAt: reviewExpiresAt,
        authorityEvidenceDigest
      });
      return {
        ok: true,
        subcommand: "review",
        actionId,
        reviewId,
        decision
      };
    });
  }

  // Execute
  const actionId = parseRecoveryActionId(options.actionId, "action_id");
  return options.pgAdapter.withTransaction("rq_recovery", async (tx) => {
    const actionRes = await tx.query<Record<string, unknown>>(
      `SELECT a.kind, o.plan_sha256, o.target_epoch
         FROM rq_recovery.actions a
         JOIN rq_recovery.operations o ON o.id = a.operation_id
        WHERE a.id = $1::uuid`,
      [actionId]
    );
    const row = actionRes.rows[0];
    if (row === undefined) {
      throw new ConflictDomainError({
        code: "NOT_FOUND",
        message: `Recovery action ${actionId} not found`
      });
    }
    const kind = String(row["kind"]);
    const rawDigest = row["plan_sha256"];
    const planSha256 = parseSha256Hex(
      Buffer.isBuffer(rawDigest)
        ? rawDigest.toString("hex")
        : rawDigest instanceof Uint8Array
          ? Buffer.from(rawDigest).toString("hex")
          : String(rawDigest).replace(/^\\x/, "")
    );
    const operatorRef = options.operatorRef ?? "recovery-operator";
    const executionNonceDigest = parseSha256Hex(
      crypto.createHash("sha256").update(`${actionId}:${crypto.randomUUID()}`, "utf8").digest("hex"),
      "executionNonceDigest"
    );
    const execParams = {
      actionId,
      operatorReference: operatorRef,
      executionNonceDigest,
      targetDatabaseIdentityDigest: planSha256
    };

    let result;
    switch (kind) {
      case "establish_target_epoch":
        result = await executeEstablishTargetEpoch(tx, execParams);
        break;
      case "retire_stale_claim":
        result = await executeRetireStaleClaim(tx, execParams);
        break;
      case "reconcile_reservations":
        result = await executeReconcileReservations(tx, execParams);
        break;
      case "continue_publication_episode":
        result = await executeContinuePublicationEpisode(tx, execParams);
        break;
      case "record_receiver_comparison":
        result = await executeRecordReceiverComparison(tx, execParams);
        break;
      case "set_recovery_gate":
        result = await executeSetRecoveryGate(tx, execParams);
        break;
      case "rebuild_projections":
        result = await executeRebuildProjection(tx, execParams);
        break;
      default:
        throw new ValidationDomainError({
          code: "INVALID_VALUE",
          message: `Unsupported recovery action kind "${kind}"`
        });
    }
    return {
      ok: true,
      subcommand: "execute",
      actionId,
      kind,
      result
    };
  });
}
