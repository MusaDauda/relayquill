import crypto from "node:crypto";
import type { Temporal } from "@js-temporal/polyfill";
import {
  type ApproveEnrollmentIntentRecordInput,
  type CompleteEnrollmentAtomicInput,
  type CreateEnrollmentIntentRecordInput,
  type EnrollmentIntentRecord,
  type EnrollmentIntentRepository,
  type HumanRecord,
  type PasskeyRecord,
  type PrincipalRecord,
  approveEnrollmentIntent
} from "@relayquill/auth";
import {
  ConflictDomainError,
  type EnrollmentIntentId,
  type EnrollmentIntentState,
  type PrincipalId,
  ValidationDomainError,
  formatUtcTimestamp,
  nowUtcInstant,
  parseControlEpoch,
  parseEnrollmentIntentId,
  parseInt64BigInt,
  parsePrincipalId,
  parseProjectId,
  parseSha256Hex,
  parseTenantId,
  parseUtcTimestamp
} from "@relayquill/domain";
import { parseBoundedString } from "@relayquill/contracts";
import { type PgAdapter, type PgTransactionClient, readInstallationStatus } from "@relayquill/postgres";
import { sendIpcFrame } from "@relayquill/runtime";

export interface ApproveEnrollmentCommandInput {
  readonly intentId: string;
  readonly version: string;
  readonly comparisonSha256: string;
  readonly operatorRef: string;
  readonly note?: string | undefined;
}

export interface ApproveEnrollmentCommandResult {
  readonly ok: true;
  readonly intent_id: EnrollmentIntentId;
  readonly state: EnrollmentIntentState;
  readonly version: string;
  readonly target_principal_id: PrincipalId | null;
  readonly operator_reference: string | null;
}

export interface OperatorChannelClient {
  send<TResponse = unknown>(request: unknown): Promise<TResponse>;
}

function toBuffer(val: unknown): Buffer {
  if (Buffer.isBuffer(val)) {
    return val;
  }
  if (val instanceof Uint8Array) {
    return Buffer.from(val);
  }
  if (typeof val === "string" && val.startsWith("\\x")) {
    return Buffer.from(val.slice(2), "hex");
  }
  throw new ValidationDomainError({
    code: "INVALID_VALUE",
    message: "Expected bytea buffer value"
  });
}

function mapEnrollmentRow(row: Record<string, unknown>): EnrollmentIntentRecord {
  const referenceTag =
    typeof row["operator_event_reference"] === "string"
      ? row["operator_event_reference"]
      : "enrollment";
  return {
    id: parseEnrollmentIntentId(row["id"], "id"),
    controlEpoch: parseControlEpoch(row["control_epoch"], "control_epoch"),
    purpose: String(row["purpose"]) as EnrollmentIntentRecord["purpose"],
    targetPrincipalId:
      row["target_principal_id"] === null || row["target_principal_id"] === undefined
        ? null
        : parsePrincipalId(row["target_principal_id"], "target_principal_id"),
    tenantId:
      row["tenant_id"] === null || row["tenant_id"] === undefined
        ? null
        : parseTenantId(row["tenant_id"], "tenant_id"),
    projectId:
      row["project_id"] === null || row["project_id"] === undefined
        ? null
        : parseProjectId(row["project_id"], "project_id"),
    browserProofDigest: toBuffer(row["browser_proof_digest"]),
    preauthContextId: String(row["preauth_context_id"]) as EnrollmentIntentRecord["preauthContextId"],
    comparisonSha256: toBuffer(row["comparison_sha256"]),
    referenceTag,
    state: String(row["state"]) as EnrollmentIntentState,
    approvedBy:
      row["approved_by"] === null || row["approved_by"] === undefined
        ? null
        : parsePrincipalId(row["approved_by"], "approved_by"),
    operatorEventReference:
      typeof row["operator_event_reference"] === "string"
        ? row["operator_event_reference"]
        : null,
    createdAt: parseUtcTimestamp(row["created_at"], "created_at").instant,
    expiresAt: parseUtcTimestamp(row["expires_at"], "expires_at").instant,
    version: parseInt64BigInt(row["version"], "version")
  };
}

function buildPgEnrollmentRepo(tx: PgTransactionClient): EnrollmentIntentRepository {
  return {
    async findIntentById(id: EnrollmentIntentId): Promise<EnrollmentIntentRecord | null> {
      const res = await tx.query<Record<string, unknown>>(
        `SELECT id, control_epoch, purpose, target_principal_id, tenant_id, project_id,
                browser_proof_digest, preauth_context_id, comparison_sha256, state,
                approved_by, operator_event_reference, created_at, expires_at, version
           FROM rq.enrollment_intents
          WHERE id = $1::uuid
          FOR UPDATE`,
        [id]
      );
      const row = res.rows[0];
      return row === undefined ? null : mapEnrollmentRow(row);
    },
    createIntent(_input: CreateEnrollmentIntentRecordInput): Promise<EnrollmentIntentRecord> {
      return Promise.reject(
        new ConflictDomainError({
          code: "STATE_TRANSITION_NOT_ALLOWED",
          message: "createIntent is not supported inside approve-enrollment"
        })
      );
    },
    countLiveIntentsForPreauth(
      _preauthContextId: EnrollmentIntentRecord["preauthContextId"]
    ): Promise<number> {
      return Promise.resolve(0);
    },
    countLiveInstallationIntents(): Promise<number> {
      return Promise.resolve(0);
    },
    async hasActivePlatformAdmin(): Promise<boolean> {
      const res = await tx.query<{ present: boolean }>(
        `SELECT EXISTS (
           SELECT 1
             FROM rq.platform_role_assignments
            WHERE role = 'platform_admin' AND state = 'active'
         ) AS present`
      );
      return res.rows[0]?.present === true;
    },
    async getPrincipalAndHuman(principalId: PrincipalId): Promise<{
      readonly principal: PrincipalRecord;
      readonly human: HumanRecord | null;
    } | null> {
      const res = await tx.query<Record<string, unknown>>(
        `SELECT p.id, p.kind, p.state, p.authority_epoch, p.version,
                h.display_name, h.webauthn_user_id, h.version AS human_version
           FROM rq.principals p
           LEFT JOIN rq.humans h ON h.principal_id = p.id
          WHERE p.id = $1::uuid`,
        [principalId]
      );
      const row = res.rows[0];
      if (row === undefined) {
        return null;
      }
      const resolvedPrincipalId = parsePrincipalId(row["id"], "id");
      const principal: PrincipalRecord = {
        principalId: resolvedPrincipalId,
        kind: String(row["kind"]) as "human" | "producer",
        state: String(row["state"]) as PrincipalRecord["state"],
        authorityEpoch: parseInt64BigInt(row["authority_epoch"], "authority_epoch"),
        version: parseInt64BigInt(row["version"], "version")
      };
      const human: HumanRecord | null =
        typeof row["display_name"] === "string" && row["webauthn_user_id"] !== null
          ? {
              principalId: resolvedPrincipalId,
              displayName: row["display_name"],
              webauthnUserId: toBuffer(row["webauthn_user_id"]),
              version: parseInt64BigInt(row["human_version"] ?? "1", "human_version")
            }
          : null;
      return { principal, human };
    },
    async approveIntent(input: ApproveEnrollmentIntentRecordInput): Promise<EnrollmentIntentRecord> {
      if (input.provisionHuman !== undefined) {
        await tx.query(
          `INSERT INTO rq.principals (id, kind, state, authority_epoch, created_at, updated_at, version)
           VALUES ($1::uuid, 'human', 'pending', 1, $2::timestamptz, $2::timestamptz, 1)
           ON CONFLICT (id) DO NOTHING`,
          [input.provisionHuman.principalId, formatUtcTimestamp(input.provisionHuman.now)]
        );
        await tx.query(
          `INSERT INTO rq.humans (principal_id, principal_kind, display_name, webauthn_user_id, created_at, updated_at, version)
           VALUES ($1::uuid, 'human', $2::text, $3::bytea, $4::timestamptz, $4::timestamptz, 1)
           ON CONFLICT (principal_id) DO NOTHING`,
          [
            input.provisionHuman.principalId,
            input.provisionHuman.displayName,
            Buffer.from(input.provisionHuman.webauthnUserId),
            formatUtcTimestamp(input.provisionHuman.now)
          ]
        );
      }

      const upd = await tx.query<Record<string, unknown>>(
        `UPDATE rq.enrollment_intents
            SET state = 'approved',
                target_principal_id = $3::uuid,
                approved_by = $4::uuid,
                operator_event_reference = COALESCE($5::text, operator_event_reference),
                version = version + 1
          WHERE id = $1::uuid
            AND version = $2::bigint
            AND state = 'requested'
          RETURNING id, control_epoch, purpose, target_principal_id, tenant_id, project_id,
                    browser_proof_digest, preauth_context_id, comparison_sha256, state,
                    approved_by, operator_event_reference, created_at, expires_at, version`,
        [
          input.intentId,
          input.expectedVersion.toString(10),
          input.targetPrincipalId,
          input.approvedBy,
          input.operatorEventReference
        ]
      );
      const row = upd.rows[0];
      if (row === undefined) {
        throw new ConflictDomainError({
          code: "VERSION_CONFLICT",
          message: "Enrollment intent version or state changed concurrently"
        });
      }
      return mapEnrollmentRow(row);
    },
    markEnrolling(): Promise<EnrollmentIntentRecord> {
      return Promise.reject(
        new ConflictDomainError({
          code: "STATE_TRANSITION_NOT_ALLOWED",
          message: "markEnrolling is not supported inside approve-enrollment"
        })
      );
    },
    rejectOrRevokeIntent(): Promise<EnrollmentIntentRecord> {
      return Promise.reject(
        new ConflictDomainError({
          code: "STATE_TRANSITION_NOT_ALLOWED",
          message: "rejectOrRevokeIntent is not supported inside approve-enrollment"
        })
      );
    },
    completeEnrollmentAtomic(
      _input: CompleteEnrollmentAtomicInput
    ): Promise<{ readonly intent: EnrollmentIntentRecord; readonly passkey: PasskeyRecord }> {
      return Promise.reject(
        new ConflictDomainError({
          code: "STATE_TRANSITION_NOT_ALLOWED",
          message: "completeEnrollmentAtomic is not supported inside approve-enrollment"
        })
      );
    }
  };
}

export async function runApproveEnrollmentCommand(
  input: ApproveEnrollmentCommandInput,
  deps: {
    readonly operatorEndpoint?: string | undefined;
    readonly operatorClient?: OperatorChannelClient | undefined;
    readonly pgAdapter?: PgAdapter | undefined;
    readonly now?: Temporal.Instant | undefined;
  }
): Promise<ApproveEnrollmentCommandResult> {
  const intentId = parseEnrollmentIntentId(input.intentId, "intent_id");
  const expectedVersion = parseInt64BigInt(input.version, "version");
  if (expectedVersion < 1n) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: "version must be >= 1",
      fieldErrors: [{ path: "version", code: "INVALID_VALUE" }]
    });
  }
  const comparisonSha256 = parseSha256Hex(input.comparisonSha256, "comparison_sha256");
  const operatorRef = parseBoundedString(input.operatorRef, {
    fieldPath: "operator_ref",
    minUtf8Bytes: 1,
    maxUtf8Bytes: 256
  });

  if (deps.operatorClient !== undefined || deps.operatorEndpoint !== undefined) {
    const reqPayload = {
      op: "access.approve_enrollment",
      intent_id: intentId,
      expected_version: expectedVersion.toString(10),
      comparison_sha256: comparisonSha256,
      operator_reference: operatorRef,
      ...(input.note !== undefined ? { note: input.note } : {})
    };
    const reply =
      deps.operatorClient !== undefined
        ? await deps.operatorClient.send<Record<string, unknown>>(reqPayload)
        : await sendIpcFrame<Record<string, unknown>>(deps.operatorEndpoint!, reqPayload, {
            verifySecurity: true
          });

    if (reply["ok"] !== true) {
      throw new ConflictDomainError({
        code: "STATE_TRANSITION_NOT_ALLOWED",
        message:
          typeof reply["message"] === "string"
            ? reply["message"]
            : "Operator channel rejected enrollment approval"
      });
    }
    return {
      ok: true,
      intent_id: intentId,
      state: (typeof reply["state"] === "string" ? reply["state"] : "approved") as EnrollmentIntentState,
      version: typeof reply["version"] === "string" ? reply["version"] : (expectedVersion + 1n).toString(10),
      target_principal_id:
        typeof reply["target_principal_id"] === "string"
          ? parsePrincipalId(reply["target_principal_id"], "target_principal_id")
          : null,
      operator_reference: operatorRef
    };
  }

  if (deps.pgAdapter === undefined) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: "approve-enrollment requires either operator_channel config or database connection"
    });
  }

  return deps.pgAdapter.withTransaction(deps.pgAdapter.configuredRole, async (tx) => {
    const inst = await readInstallationStatus(tx);
    const repo = buildPgEnrollmentRepo(tx);
    const updated = await approveEnrollmentIntent({
      installation: {
        controlEpoch: inst.controlEpoch,
        mode: inst.mode,
        allowEventAdmission: inst.allowEventAdmission,
        allowPublication: inst.allowPublication,
        allowFanout: inst.allowFanout,
        allowSend: inst.allowSend,
        allowEndpointVerification: inst.allowEndpointVerification,
        governanceVersion: inst.governanceVersion,
        version: inst.version
      },
      intentId,
      expectedVersion,
      expectedComparisonSha256: comparisonSha256,
      operatorEventReference: operatorRef,
      enrollmentRepo: repo,
      now: deps.now ?? nowUtcInstant()
    });

    await tx.query(
      `INSERT INTO rq.audit_events (
         id, tenant_id, project_id, actor_kind, operator_reference, action,
         target_kind, target_id, prior_version, resulting_version, safe_facts
       ) VALUES ($1::uuid, $2::uuid, $3::uuid, 'operator', $4::text, 'access.enrollment.approve',
                 'enrollment_intent', $5::uuid, $6::bigint, $7::bigint, $8::jsonb)`,
      [
        crypto.randomUUID(),
        updated.tenantId,
        updated.projectId,
        operatorRef,
        updated.id,
        expectedVersion.toString(10),
        updated.version.toString(10),
        JSON.stringify({
          purpose: updated.purpose,
          comparison_sha256: comparisonSha256
        })
      ]
    );

    return {
      ok: true,
      intent_id: updated.id,
      state: updated.state,
      version: updated.version.toString(10),
      target_principal_id: updated.targetPrincipalId,
      operator_reference: updated.operatorEventReference
    };
  });
}
