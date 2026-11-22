import crypto from "node:crypto";
import type { Temporal } from "@js-temporal/polyfill";
import {
  type AllowedPasskeyTransport,
  type ApproveEnrollmentIntentRecordInput,
  type AuthChallengeRecord,
  type AuthChallengeRepository,
  type CompleteEnrollmentAtomicInput,
  type CompleteSignInAtomicInput,
  type CompleteStepUpAtomicInput,
  type ConsumeAuthChallengeInput,
  type ConsumeOperationProofInput,
  type CreateAuthChallengeInput,
  type CreateEnrollmentIntentRecordInput,
  type CreateHumanSessionInput,
  type CreatePasskeyInput,
  type CreatePreauthContextInput,
  type EnrollmentIntentRecord,
  type EnrollmentIntentRepository,
  type GovernanceRepository,
  type HumanDataGrantRecord,
  type HumanRecord,
  type HumanSessionPrincipalLookup,
  type HumanSessionRecord,
  type HumanSessionRepository,
  type OperationProofRecord,
  type OperationProofRepository,
  type PasskeyRecord,
  type PasskeyRepository,
  type PlatformRoleAssignmentRecord,
  type PreauthContextRecord,
  type PreauthContextRepository,
  type PrincipalRecord,
  type ProducerCredentialIntentRecord,
  type ProducerCredentialRecord,
  type ProducerCredentialRepository,
  type ProducerRecord,
  type ProducerScopeDefinition,
  type ProducerScopeVersionRecord,
  type ProjectMembershipRecord,
  type RecordAuthChallengeFailureInput,
  type RecordPasskeyUseInput,
  type TenantMembershipRecord,
  type TouchHumanSessionIdleInput,
  type UpdatePasskeyStateInput
} from "@relayquill/auth";
import { type AuthRepositoriesBundle } from "@relayquill/application";
import {
  type AuthChallengeId,
  type AuthChallengeKind,
  type AuthChallengeState,
  ConflictDomainError,
  type DataGrantAction,
  type DataGrantProjection,
  type DataGrantState,
  type EnrollmentIntentId,
  type EnrollmentIntentKind,
  type EnrollmentIntentState,
  type HumanSessionKind,
  type HumanSessionState,
  type MembershipState,
  NotFoundDomainError,
  type OperationProofId,
  type OperationProofState,
  type PasskeyState,
  type PlatformRole,
  type PlatformRoleAssignmentId,
  type PlatformRoleAssignmentState,
  type PreauthContextId,
  type PreauthContextState,
  type PrincipalId,
  type PrincipalKind,
  type PrincipalState,
  type ProducerCredentialId,
  type ProducerCredentialIntentId,
  type ProducerCredentialIntentState,
  type ProducerCredentialState,
  type ProducerId,
  type ProducerScopeVersionState,
  type ProducerState,
  type ProjectId,
  type ProjectMembershipId,
  type ProjectRole,
  type SessionId,
  type TenantId,
  type TenantMembershipId,
  type TenantRole,
  parseAuthChallengeId,
  parseCommandReceiptId,
  parseControlEpoch,
  parseDataGrantId,
  parseEnrollmentIntentId,
  parseEventTypeId,
  parseOperationProofId,
  parsePreauthContextId,
  parsePrincipalId,
  parseProducerCredentialId,
  parseProducerCredentialIntentId,
  parseProducerId,
  parseProducerNamespace,
  parseProjectId,
  parseSessionId,
  parseTenantId,
  parseCanonicalUuid
} from "@relayquill/domain";
import { type PgTransactionClient } from "@relayquill/postgres";
import {
  type PgExecutor,
  readByteaUint8,
  readInstant,
  readOptionalInstant,
  toBigIntSafe,
  toIntSafe,
  toParamBuffer,
  toUtcParam
} from "./sql-helpers.js";

function mapPreauthRow(row: Record<string, unknown>): PreauthContextRecord {
  return {
    id: parsePreauthContextId(row["id"], "preauth.id"),
    proofDigest: readByteaUint8(row["proof_digest"], "proof_digest"),
    state: String(row["state"]) as PreauthContextState,
    createdAt: readInstant(row["created_at"], "created_at"),
    expiresAt: readInstant(row["expires_at"], "expires_at"),
    version: toBigIntSafe(row["version"], "version")
  };
}

function mapChallengeRow(row: Record<string, unknown>): AuthChallengeRecord {
  return {
    id: parseAuthChallengeId(row["id"], "challenge.id"),
    controlEpoch: parseControlEpoch(row["control_epoch"], "control_epoch"),
    humanPrincipalId:
      row["human_principal_id"] === null || row["human_principal_id"] === undefined
        ? null
        : parsePrincipalId(row["human_principal_id"], "human_principal_id"),
    purpose: String(row["purpose"]) as AuthChallengeKind,
    challengeBytes: readByteaUint8(row["challenge_bytes"], "challenge_bytes"),
    browserProofDigest: readByteaUint8(row["browser_proof_digest"], "browser_proof_digest"),
    preauthContextId:
      row["preauth_context_id"] === null || row["preauth_context_id"] === undefined
        ? null
        : parsePreauthContextId(row["preauth_context_id"], "preauth_context_id"),
    sessionId:
      row["session_id"] === null || row["session_id"] === undefined
        ? null
        : parseSessionId(row["session_id"], "session_id"),
    action: typeof row["action"] === "string" ? row["action"] : null,
    targetSha256:
      row["target_sha256"] === null || row["target_sha256"] === undefined
        ? null
        : readByteaUint8(row["target_sha256"], "target_sha256"),
    state: String(row["state"]) as AuthChallengeState,
    failureCount: toIntSafe(row["failure_count"], "failure_count"),
    createdAt: readInstant(row["created_at"], "created_at"),
    expiresAt: readInstant(row["expires_at"], "expires_at"),
    version: toBigIntSafe(row["version"], "version")
  };
}

function mapPasskeyRow(row: Record<string, unknown>): PasskeyRecord {
  const transportsRaw = row["transports"];
  const transports: AllowedPasskeyTransport[] = Array.isArray(transportsRaw)
    ? transportsRaw.map((t) => String(t) as AllowedPasskeyTransport)
    : [];
  return {
    id: parseCanonicalUuid(row["id"], "passkey.id"),
    humanPrincipalId: parsePrincipalId(row["human_principal_id"], "human_principal_id"),
    credentialId: readByteaUint8(row["credential_id"], "credential_id"),
    publicKey: readByteaUint8(row["public_key"], "public_key"),
    webauthnUserId: readByteaUint8(row["webauthn_user_id"], "webauthn_user_id"),
    signCount: toBigIntSafe(row["sign_count"], "sign_count"),
    deviceType: String(row["device_type"]) as PasskeyRecord["deviceType"],
    backedUp: Boolean(row["backed_up"]),
    transports,
    state: String(row["state"]) as PasskeyState,
    enrolledAt: readInstant(row["enrolled_at"], "enrolled_at"),
    lastUsedAt: readOptionalInstant(row["last_used_at"], "last_used_at"),
    revokedAt: readOptionalInstant(row["revoked_at"], "revoked_at"),
    version: toBigIntSafe(row["version"], "version")
  };
}

function mapEnrollmentRow(row: Record<string, unknown>): EnrollmentIntentRecord {
  const referenceTag =
    typeof row["operator_event_reference"] === "string"
      ? row["operator_event_reference"]
      : "enrollment";
  return {
    id: parseEnrollmentIntentId(row["id"], "enrollment.id"),
    controlEpoch: parseControlEpoch(row["control_epoch"], "control_epoch"),
    purpose: String(row["purpose"]) as EnrollmentIntentKind,
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
    browserProofDigest: readByteaUint8(row["browser_proof_digest"], "browser_proof_digest"),
    preauthContextId: parsePreauthContextId(row["preauth_context_id"], "preauth_context_id"),
    comparisonSha256: readByteaUint8(row["comparison_sha256"], "comparison_sha256"),
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
    createdAt: readInstant(row["created_at"], "created_at"),
    expiresAt: readInstant(row["expires_at"], "expires_at"),
    version: toBigIntSafe(row["version"], "version")
  };
}

function mapSessionRow(row: Record<string, unknown>): HumanSessionRecord {
  return {
    id: parseSessionId(row["id"], "session.id"),
    principalId: parsePrincipalId(row["principal_id"], "principal_id"),
    controlEpoch: parseControlEpoch(row["control_epoch"], "control_epoch"),
    tokenDigest: readByteaUint8(row["token_digest"], "token_digest"),
    csrfDigest: readByteaUint8(row["csrf_digest"], "csrf_digest"),
    principalAuthorityEpoch: toBigIntSafe(
      row["principal_authority_epoch"],
      "principal_authority_epoch"
    ),
    purpose: String(row["purpose"]) as HumanSessionKind,
    state: String(row["state"]) as HumanSessionState,
    createdAt: readInstant(row["created_at"], "created_at"),
    lastSeenAt: readInstant(row["last_seen_at"], "last_seen_at"),
    idleExpiresAt: readInstant(row["idle_expires_at"], "idle_expires_at"),
    absoluteExpiresAt: readInstant(row["absolute_expires_at"], "absolute_expires_at"),
    revokedAt: readOptionalInstant(row["revoked_at"], "revoked_at"),
    version: toBigIntSafe(row["version"], "version")
  };
}

function mapPrincipalRow(row: Record<string, unknown>, idCol = "id"): PrincipalRecord {
  return {
    principalId: parsePrincipalId(row[idCol], idCol),
    kind: String(row["kind"]) as PrincipalKind,
    state: String(row["state"]) as PrincipalState,
    authorityEpoch: toBigIntSafe(row["authority_epoch"], "authority_epoch"),
    version: toBigIntSafe(row["version"], "version")
  };
}

function mapOperationProofRow(row: Record<string, unknown>): OperationProofRecord {
  return {
    id: parseOperationProofId(row["id"], "proof.id"),
    sessionId: parseSessionId(row["session_id"], "session_id"),
    principalId: parsePrincipalId(row["principal_id"], "principal_id"),
    controlEpoch: parseControlEpoch(row["control_epoch"], "control_epoch"),
    action: String(row["action"]),
    targetSha256: readByteaUint8(row["target_sha256"], "target_sha256"),
    challengeId: parseAuthChallengeId(row["challenge_id"], "challenge_id"),
    verifiedAt: readInstant(row["verified_at"], "verified_at"),
    expiresAt: readInstant(row["expires_at"], "expires_at"),
    state: String(row["state"]) as OperationProofState,
    acceptedReceiptId:
      row["accepted_receipt_id"] === null || row["accepted_receipt_id"] === undefined
        ? null
        : parseCommandReceiptId(row["accepted_receipt_id"], "accepted_receipt_id"),
    version: toBigIntSafe(row["version"], "version")
  };
}

export function createPgPreauthRepo(exec: PgExecutor): PreauthContextRepository {
  return {
    async findPreauthContextByProofDigest(proofDigest: Uint8Array): Promise<PreauthContextRecord | null> {
      const res = await exec.query<Record<string, unknown>>(
        `SELECT id, proof_digest, state, created_at, expires_at, version
           FROM rq.preauth_contexts
          WHERE proof_digest = $1::bytea`,
        [toParamBuffer(proofDigest)]
      );
      return res.rows[0] ? mapPreauthRow(res.rows[0]) : null;
    },
    async findPreauthContextById(id: PreauthContextId): Promise<PreauthContextRecord | null> {
      const res = await exec.query<Record<string, unknown>>(
        `SELECT id, proof_digest, state, created_at, expires_at, version
           FROM rq.preauth_contexts
          WHERE id = $1::uuid`,
        [id]
      );
      return res.rows[0] ? mapPreauthRow(res.rows[0]) : null;
    },
    async createPreauthContext(input: CreatePreauthContextInput): Promise<PreauthContextRecord> {
      const res = await exec.query<Record<string, unknown>>(
        `INSERT INTO rq.preauth_contexts (id, proof_digest, state, created_at, expires_at, version)
         VALUES ($1::uuid, $2::bytea, 'active', $3::timestamptz, $4::timestamptz, 1)
         RETURNING id, proof_digest, state, created_at, expires_at, version`,
        [
          input.id,
          toParamBuffer(input.proofDigest),
          toUtcParam(input.createdAt),
          toUtcParam(input.expiresAt)
        ]
      );
      return mapPreauthRow(res.rows[0]!);
    },
    async revokePreauthContext(id: PreauthContextId, expectedVersion: bigint): Promise<PreauthContextRecord> {
      const res = await exec.query<Record<string, unknown>>(
        `UPDATE rq.preauth_contexts
            SET state = 'revoked', version = version + 1
          WHERE id = $1::uuid AND version = $2::bigint
          RETURNING id, proof_digest, state, created_at, expires_at, version`,
        [id, expectedVersion.toString(10)]
      );
      if (res.rows[0] === undefined) {
        throw new ConflictDomainError({
          code: "VERSION_CONFLICT",
          message: "Preauthentication context version mismatch"
        });
      }
      return mapPreauthRow(res.rows[0]);
    }
  };
}

export function createPgAuthChallengeRepo(exec: PgExecutor): AuthChallengeRepository {
  return {
    async findChallengeById(id: AuthChallengeId): Promise<AuthChallengeRecord | null> {
      const res = await exec.query<Record<string, unknown>>(
        `SELECT id, control_epoch, human_principal_id, purpose, challenge_bytes,
                browser_proof_digest, preauth_context_id, session_id, action, target_sha256,
                state, failure_count, created_at, expires_at, version
           FROM rq.auth_challenges
          WHERE id = $1::uuid`,
        [id]
      );
      return res.rows[0] ? mapChallengeRow(res.rows[0]) : null;
    },
    async createChallenge(input: CreateAuthChallengeInput): Promise<AuthChallengeRecord> {
      const res = await exec.query<Record<string, unknown>>(
        `INSERT INTO rq.auth_challenges (
           id, control_epoch, human_principal_id, purpose, challenge_bytes,
           browser_proof_digest, preauth_context_id, session_id, action, target_sha256,
           state, failure_count, created_at, expires_at, version
         ) VALUES (
           $1::uuid, $2::uuid, $3::uuid, $4::text, $5::bytea,
           $6::bytea, $7::uuid, $8::uuid, $9::text, $10::bytea,
           'pending', 0, $11::timestamptz, $12::timestamptz, 1
         )
         RETURNING id, control_epoch, human_principal_id, purpose, challenge_bytes,
                   browser_proof_digest, preauth_context_id, session_id, action, target_sha256,
                   state, failure_count, created_at, expires_at, version`,
        [
          input.id,
          input.controlEpoch,
          input.humanPrincipalId,
          input.purpose,
          toParamBuffer(input.challengeBytes),
          toParamBuffer(input.browserProofDigest),
          input.preauthContextId,
          input.sessionId,
          input.action,
          input.targetSha256 !== null ? toParamBuffer(input.targetSha256) : null,
          toUtcParam(input.createdAt),
          toUtcParam(input.expiresAt)
        ]
      );
      return mapChallengeRow(res.rows[0]!);
    },
    async recordChallengeFailure(input: RecordAuthChallengeFailureInput): Promise<AuthChallengeRecord> {
      const res = await exec.query<Record<string, unknown>>(
        `UPDATE rq.auth_challenges
            SET failure_count = LEAST(5, failure_count + 1),
                state = CASE WHEN failure_count + 1 >= 5 THEN 'denied' ELSE state END,
                version = version + 1
          WHERE id = $1::uuid AND version = $2::bigint AND state = 'pending'
          RETURNING id, control_epoch, human_principal_id, purpose, challenge_bytes,
                    browser_proof_digest, preauth_context_id, session_id, action, target_sha256,
                    state, failure_count, created_at, expires_at, version`,
        [input.challengeId, input.expectedVersion.toString(10)]
      );
      if (res.rows[0] === undefined) {
        throw new ConflictDomainError({
          code: "VERSION_CONFLICT",
          message: "Auth challenge state or version conflict"
        });
      }
      return mapChallengeRow(res.rows[0]);
    },
    async consumeChallenge(input: ConsumeAuthChallengeInput): Promise<AuthChallengeRecord> {
      const res = await exec.query<Record<string, unknown>>(
        `UPDATE rq.auth_challenges
            SET state = 'consumed', version = version + 1
          WHERE id = $1::uuid
            AND version = $2::bigint
            AND control_epoch = $3::uuid
            AND state = 'pending'
          RETURNING id, control_epoch, human_principal_id, purpose, challenge_bytes,
                    browser_proof_digest, preauth_context_id, session_id, action, target_sha256,
                    state, failure_count, created_at, expires_at, version`,
        [input.challengeId, input.expectedVersion.toString(10), input.expectedControlEpoch]
      );
      if (res.rows[0] === undefined) {
        throw new ConflictDomainError({
          code: "VERSION_CONFLICT",
          message: "Auth challenge already consumed or expired"
        });
      }
      return mapChallengeRow(res.rows[0]);
    },
    async revokeChallenge(id: AuthChallengeId, expectedVersion: bigint): Promise<AuthChallengeRecord> {
      const res = await exec.query<Record<string, unknown>>(
        `UPDATE rq.auth_challenges
            SET state = 'revoked', version = version + 1
          WHERE id = $1::uuid AND version = $2::bigint
          RETURNING id, control_epoch, human_principal_id, purpose, challenge_bytes,
                    browser_proof_digest, preauth_context_id, session_id, action, target_sha256,
                    state, failure_count, created_at, expires_at, version`,
        [id, expectedVersion.toString(10)]
      );
      if (res.rows[0] === undefined) {
        throw new ConflictDomainError({
          code: "VERSION_CONFLICT",
          message: "Auth challenge version conflict"
        });
      }
      return mapChallengeRow(res.rows[0]);
    }
  };
}

export function createPgPasskeyRepo(exec: PgExecutor): PasskeyRepository {
  return {
    async findPasskeyByCredentialId(credentialId: Uint8Array): Promise<PasskeyRecord | null> {
      const res = await exec.query<Record<string, unknown>>(
        `SELECT id, human_principal_id, credential_id, public_key, webauthn_user_id,
                sign_count, device_type, backed_up, transports, state, enrolled_at,
                last_used_at, revoked_at, version
           FROM rq.passkeys
          WHERE credential_id = $1::bytea`,
        [toParamBuffer(credentialId)]
      );
      return res.rows[0] ? mapPasskeyRow(res.rows[0]) : null;
    },
    async listPasskeysForHuman(humanPrincipalId: PrincipalId): Promise<readonly PasskeyRecord[]> {
      const res = await exec.query<Record<string, unknown>>(
        `SELECT id, human_principal_id, credential_id, public_key, webauthn_user_id,
                sign_count, device_type, backed_up, transports, state, enrolled_at,
                last_used_at, revoked_at, version
           FROM rq.passkeys
          WHERE human_principal_id = $1::uuid
          ORDER BY enrolled_at ASC`,
        [humanPrincipalId]
      );
      return res.rows.map(mapPasskeyRow);
    },
    async createPasskey(input: CreatePasskeyInput): Promise<PasskeyRecord> {
      const res = await exec.query<Record<string, unknown>>(
        `INSERT INTO rq.passkeys (
           id, human_principal_id, credential_id, public_key, webauthn_user_id,
           sign_count, device_type, backed_up, transports, state, enrolled_at, version
         ) VALUES (
           $1::uuid, $2::uuid, $3::bytea, $4::bytea, $5::bytea,
           $6::bigint, $7::text, $8::boolean, $9::jsonb, $10::text, $11::timestamptz, 1
         )
         RETURNING id, human_principal_id, credential_id, public_key, webauthn_user_id,
                   sign_count, device_type, backed_up, transports, state, enrolled_at,
                   last_used_at, revoked_at, version`,
        [
          input.id,
          input.humanPrincipalId,
          toParamBuffer(input.credentialId),
          toParamBuffer(input.publicKey),
          toParamBuffer(input.webauthnUserId),
          input.signCount.toString(10),
          input.deviceType,
          input.backedUp,
          JSON.stringify(input.transports),
          input.state,
          toUtcParam(input.enrolledAt)
        ]
      );
      return mapPasskeyRow(res.rows[0]!);
    },
    async recordPasskeyUse(input: RecordPasskeyUseInput): Promise<PasskeyRecord> {
      const res = await exec.query<Record<string, unknown>>(
        `UPDATE rq.passkeys
            SET sign_count = $3::bigint,
                device_type = $4::text,
                backed_up = $5::boolean,
                last_used_at = $6::timestamptz,
                version = version + 1
          WHERE id = $1::uuid AND version = $2::bigint
          RETURNING id, human_principal_id, credential_id, public_key, webauthn_user_id,
                    sign_count, device_type, backed_up, transports, state, enrolled_at,
                    last_used_at, revoked_at, version`,
        [
          input.passkeyId,
          input.expectedVersion.toString(10),
          input.newSignCount.toString(10),
          input.deviceType,
          input.backedUp,
          toUtcParam(input.usedAt)
        ]
      );
      if (res.rows[0] === undefined) {
        throw new ConflictDomainError({
          code: "VERSION_CONFLICT",
          message: "Passkey version conflict"
        });
      }
      return mapPasskeyRow(res.rows[0]);
    },
    async updatePasskeyState(input: UpdatePasskeyStateInput): Promise<PasskeyRecord> {
      const res = await exec.query<Record<string, unknown>>(
        `UPDATE rq.passkeys
            SET state = $3::text,
                revoked_at = $4::timestamptz,
                version = version + 1
          WHERE id = $1::uuid AND version = $2::bigint
          RETURNING id, human_principal_id, credential_id, public_key, webauthn_user_id,
                    sign_count, device_type, backed_up, transports, state, enrolled_at,
                    last_used_at, revoked_at, version`,
        [
          input.passkeyId,
          input.expectedVersion.toString(10),
          input.toState,
          input.revokedAt !== undefined && input.revokedAt !== null
            ? toUtcParam(input.revokedAt)
            : null
        ]
      );
      if (res.rows[0] === undefined) {
        throw new ConflictDomainError({
          code: "VERSION_CONFLICT",
          message: "Passkey version conflict"
        });
      }
      return mapPasskeyRow(res.rows[0]);
    }
  };
}

export function createPgEnrollmentRepo(exec: PgExecutor): EnrollmentIntentRepository {
  return {
    async hasActivePlatformAdmin(): Promise<boolean> {
      const res = await exec.query<{ present: boolean }>(
        `SELECT EXISTS (
           SELECT 1 FROM rq.platform_role_assignments
            WHERE role = 'platform_admin' AND state = 'active'
         ) AS present`
      );
      return res.rows[0]?.present === true;
    },
    async getPrincipalAndHuman(principalId: PrincipalId): Promise<{
      readonly principal: PrincipalRecord;
      readonly human: HumanRecord | null;
    } | null> {
      const res = await exec.query<Record<string, unknown>>(
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
      const principal = mapPrincipalRow(row, "id");
      const human: HumanRecord | null =
        typeof row["display_name"] === "string" && row["webauthn_user_id"] !== null
          ? {
              principalId: principal.principalId,
              displayName: row["display_name"],
              webauthnUserId: readByteaUint8(row["webauthn_user_id"], "webauthn_user_id"),
              version: toBigIntSafe(row["human_version"] ?? "1", "human_version")
            }
          : null;
      return { principal, human };
    },
    async findIntentById(id: EnrollmentIntentId): Promise<EnrollmentIntentRecord | null> {
      const res = await exec.query<Record<string, unknown>>(
        `SELECT id, control_epoch, purpose, target_principal_id, tenant_id, project_id,
                browser_proof_digest, preauth_context_id, comparison_sha256, state,
                approved_by, operator_event_reference, created_at, expires_at, version
           FROM rq.enrollment_intents
          WHERE id = $1::uuid`,
        [id]
      );
      return res.rows[0] ? mapEnrollmentRow(res.rows[0]) : null;
    },
    async countLiveIntentsForPreauth(
      preauthContextId: PreauthContextId,
      now: Temporal.Instant
    ): Promise<number> {
      const res = await exec.query<{ cnt: number }>(
        `SELECT count(*)::integer AS cnt
           FROM rq.enrollment_intents
          WHERE preauth_context_id = $1::uuid
            AND state IN ('requested', 'approved', 'enrolling')
            AND expires_at > $2::timestamptz`,
        [preauthContextId, toUtcParam(now)]
      );
      return res.rows[0]?.cnt ?? 0;
    },
    async countLiveInstallationIntents(now: Temporal.Instant): Promise<number> {
      const res = await exec.query<{ cnt: number }>(
        `SELECT count(*)::integer AS cnt
           FROM rq.enrollment_intents
          WHERE state IN ('requested', 'approved', 'enrolling')
            AND expires_at > $1::timestamptz`,
        [toUtcParam(now)]
      );
      return res.rows[0]?.cnt ?? 0;
    },
    async createIntent(input: CreateEnrollmentIntentRecordInput): Promise<EnrollmentIntentRecord> {
      const res = await exec.query<Record<string, unknown>>(
        `INSERT INTO rq.enrollment_intents (
           id, control_epoch, purpose, target_principal_id, tenant_id, project_id,
           browser_proof_digest, preauth_context_id, comparison_sha256, state,
           operator_event_reference, created_at, expires_at, version
         ) VALUES (
           $1::uuid, $2::uuid, $3::text, $4::uuid, $5::uuid, $6::uuid,
           $7::bytea, $8::uuid, $9::bytea, 'requested',
           $10::text, $11::timestamptz, $12::timestamptz, 1
         )
         RETURNING id, control_epoch, purpose, target_principal_id, tenant_id, project_id,
                   browser_proof_digest, preauth_context_id, comparison_sha256, state,
                   approved_by, operator_event_reference, created_at, expires_at, version`,
        [
          input.id,
          input.controlEpoch,
          input.purpose,
          input.targetPrincipalId,
          input.tenantId,
          input.projectId,
          toParamBuffer(input.browserProofDigest),
          input.preauthContextId,
          toParamBuffer(input.comparisonSha256),
          input.referenceTag,
          toUtcParam(input.createdAt),
          toUtcParam(input.expiresAt)
        ]
      );
      return mapEnrollmentRow(res.rows[0]!);
    },
    approveIntent(input: ApproveEnrollmentIntentRecordInput): Promise<EnrollmentIntentRecord> {
      return exec.inTx(async (tx) => {
        if (input.provisionHuman !== undefined) {
          await tx.query(
            `INSERT INTO rq.principals (id, kind, state, authority_epoch, created_at, updated_at, version)
             VALUES ($1::uuid, 'human', 'pending', 1, $2::timestamptz, $2::timestamptz, 1)
             ON CONFLICT (id) DO NOTHING`,
            [input.provisionHuman.principalId, toUtcParam(input.provisionHuman.now)]
          );
          await tx.query(
            `INSERT INTO rq.humans (principal_id, principal_kind, display_name, webauthn_user_id, created_at, updated_at, version)
             VALUES ($1::uuid, 'human', $2::text, $3::bytea, $4::timestamptz, $4::timestamptz, 1)
             ON CONFLICT (principal_id) DO NOTHING`,
            [
              input.provisionHuman.principalId,
              input.provisionHuman.displayName,
              toParamBuffer(input.provisionHuman.webauthnUserId),
              toUtcParam(input.provisionHuman.now)
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
            WHERE id = $1::uuid AND version = $2::bigint AND state = 'requested'
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
        if (upd.rows[0] === undefined) {
          throw new ConflictDomainError({
            code: "VERSION_CONFLICT",
            message: "Enrollment intent version or state changed concurrently"
          });
        }
        return mapEnrollmentRow(upd.rows[0]);
      });
    },
    async markEnrolling(
      intentId: EnrollmentIntentId,
      expectedVersion: bigint
    ): Promise<EnrollmentIntentRecord> {
      const res = await exec.query<Record<string, unknown>>(
        `UPDATE rq.enrollment_intents
            SET state = 'enrolling', version = version + 1
          WHERE id = $1::uuid AND version = $2::bigint AND state IN ('approved', 'enrolling')
          RETURNING id, control_epoch, purpose, target_principal_id, tenant_id, project_id,
                    browser_proof_digest, preauth_context_id, comparison_sha256, state,
                    approved_by, operator_event_reference, created_at, expires_at, version`,
        [intentId, expectedVersion.toString(10)]
      );
      if (res.rows[0] === undefined) {
        throw new ConflictDomainError({
          code: "VERSION_CONFLICT",
          message: "Enrollment intent could not transition to enrolling"
        });
      }
      return mapEnrollmentRow(res.rows[0]);
    },
    async rejectOrRevokeIntent(
      intentId: EnrollmentIntentId,
      expectedVersion: bigint,
      toState: "rejected" | "revoked"
    ): Promise<EnrollmentIntentRecord> {
      const res = await exec.query<Record<string, unknown>>(
        `UPDATE rq.enrollment_intents
            SET state = $3::text, version = version + 1
          WHERE id = $1::uuid AND version = $2::bigint
          RETURNING id, control_epoch, purpose, target_principal_id, tenant_id, project_id,
                    browser_proof_digest, preauth_context_id, comparison_sha256, state,
                    approved_by, operator_event_reference, created_at, expires_at, version`,
        [intentId, expectedVersion.toString(10), toState]
      );
      if (res.rows[0] === undefined) {
        throw new ConflictDomainError({
          code: "VERSION_CONFLICT",
          message: "Enrollment intent version conflict"
        });
      }
      return mapEnrollmentRow(res.rows[0]);
    },
    completeEnrollmentAtomic(input: CompleteEnrollmentAtomicInput): Promise<{
      readonly intent: EnrollmentIntentRecord;
      readonly passkey: PasskeyRecord;
    }> {
      return exec.inTx(async (tx) => {
        const chUpd = await tx.query<Record<string, unknown>>(
          `UPDATE rq.auth_challenges
              SET state = 'consumed', version = version + 1
            WHERE id = $1::uuid AND version = $2::bigint AND control_epoch = $3::uuid AND state = 'pending'
            RETURNING id`,
          [
            input.challengeId,
            input.expectedChallengeVersion.toString(10),
            input.expectedControlEpoch
          ]
        );
        if (chUpd.rows[0] === undefined) {
          throw new ConflictDomainError({
            code: "VERSION_CONFLICT",
            message: "Enrollment challenge already consumed or expired"
          });
        }

        if (input.activateHumanPrincipal) {
          await tx.query(
            `UPDATE rq.principals
                SET state = 'active', updated_at = $2::timestamptz, version = version + 1
              WHERE id = $1::uuid AND state IN ('pending', 'active')`,
            [input.principalId, toUtcParam(input.now)]
          );
        }

        if (input.grantPlatformAdmin) {
          await tx.query(
            `INSERT INTO rq.platform_role_assignments (
               id, principal_id, role, state, governance_version, created_at, version
             ) VALUES ($1::uuid, $2::uuid, 'platform_admin', 'active', 1, $3::timestamptz, 1)
             ON CONFLICT (principal_id, role) WHERE state = 'active' DO NOTHING`,
            [crypto.randomUUID(), input.principalId, toUtcParam(input.now)]
          );
        }

        const pkRes = await tx.query<Record<string, unknown>>(
          `INSERT INTO rq.passkeys (
             id, human_principal_id, credential_id, public_key, webauthn_user_id,
             sign_count, device_type, backed_up, transports, state, enrolled_at, version
           ) VALUES (
             $1::uuid, $2::uuid, $3::bytea, $4::bytea, $5::bytea,
             $6::bigint, $7::text, $8::boolean, $9::jsonb, $10::text, $11::timestamptz, 1
           )
           RETURNING id, human_principal_id, credential_id, public_key, webauthn_user_id,
                     sign_count, device_type, backed_up, transports, state, enrolled_at,
                     last_used_at, revoked_at, version`,
          [
            input.passkeyId,
            input.principalId,
            toParamBuffer(input.verifiedPasskey.credentialId),
            toParamBuffer(input.verifiedPasskey.publicKey),
            toParamBuffer(input.webauthnUserId),
            input.verifiedPasskey.signCount.toString(10),
            input.verifiedPasskey.deviceType,
            input.verifiedPasskey.backedUp,
            JSON.stringify(input.verifiedPasskey.transports),
            input.passkeyState,
            toUtcParam(input.now)
          ]
        );

        const intUpd = await tx.query<Record<string, unknown>>(
          `UPDATE rq.enrollment_intents
              SET state = 'completed', version = version + 1
            WHERE id = $1::uuid AND version = $2::bigint AND state = 'enrolling'
            RETURNING id, control_epoch, purpose, target_principal_id, tenant_id, project_id,
                      browser_proof_digest, preauth_context_id, comparison_sha256, state,
                      approved_by, operator_event_reference, created_at, expires_at, version`,
          [input.intentId, input.expectedIntentVersion.toString(10)]
        );
        if (intUpd.rows[0] === undefined) {
          throw new ConflictDomainError({
            code: "VERSION_CONFLICT",
            message: "Enrollment intent version conflict during completion"
          });
        }

        return {
          intent: mapEnrollmentRow(intUpd.rows[0]),
          passkey: mapPasskeyRow(pkRes.rows[0]!)
        };
      });
    }
  };
}

export function createPgSessionRepo(exec: PgExecutor): HumanSessionRepository {
  const lookupHuman = async (
    principalId: PrincipalId,
    tx?: PgTransactionClient
  ): Promise<HumanSessionPrincipalLookup | null> => {
    const queryFn = tx ? tx.query.bind(tx) : exec.query.bind(exec);
    const res = await queryFn<Record<string, unknown>>(
      `SELECT p.id, p.kind, p.state, p.authority_epoch, p.version,
              h.display_name, h.webauthn_user_id, h.version AS human_version
         FROM rq.principals p
         JOIN rq.humans h ON h.principal_id = p.id
        WHERE p.id = $1::uuid`,
      [principalId]
    );
    const row = res.rows[0];
    if (row === undefined) {
      return null;
    }
    const principal = mapPrincipalRow(row, "id");
    const human: HumanRecord = {
      principalId: principal.principalId,
      displayName: String(row["display_name"]),
      webauthnUserId: readByteaUint8(row["webauthn_user_id"], "webauthn_user_id"),
      version: toBigIntSafe(row["human_version"], "human_version")
    };
    return { principal, human };
  };

  return {
    async findSessionByTokenDigest(tokenDigest: Uint8Array): Promise<HumanSessionRecord | null> {
      const res = await exec.query<Record<string, unknown>>(
        `SELECT id, principal_id, control_epoch, token_digest, csrf_digest,
                principal_authority_epoch, purpose, state, created_at, last_seen_at,
                idle_expires_at, absolute_expires_at, revoked_at, version
           FROM rq.human_sessions
          WHERE token_digest = $1::bytea`,
        [toParamBuffer(tokenDigest)]
      );
      return res.rows[0] ? mapSessionRow(res.rows[0]) : null;
    },
    async findSessionById(sessionId: SessionId): Promise<HumanSessionRecord | null> {
      const res = await exec.query<Record<string, unknown>>(
        `SELECT id, principal_id, control_epoch, token_digest, csrf_digest,
                principal_authority_epoch, purpose, state, created_at, last_seen_at,
                idle_expires_at, absolute_expires_at, revoked_at, version
           FROM rq.human_sessions
          WHERE id = $1::uuid`,
        [sessionId]
      );
      return res.rows[0] ? mapSessionRow(res.rows[0]) : null;
    },
    getPrincipalAndHumanForSession(principalId: PrincipalId): Promise<HumanSessionPrincipalLookup | null> {
      return lookupHuman(principalId);
    },
    getPrincipalAndHumanByPasskey(principalId: PrincipalId): Promise<HumanSessionPrincipalLookup | null> {
      return lookupHuman(principalId);
    },
    async createSession(input: CreateHumanSessionInput): Promise<HumanSessionRecord> {
      const res = await exec.query<Record<string, unknown>>(
        `INSERT INTO rq.human_sessions (
           id, principal_id, control_epoch, token_digest, csrf_digest,
           principal_authority_epoch, purpose, state, created_at, last_seen_at,
           idle_expires_at, absolute_expires_at, version
         ) VALUES (
           $1::uuid, $2::uuid, $3::uuid, $4::bytea, $5::bytea,
           $6::bigint, $7::text, 'active', $8::timestamptz, $8::timestamptz,
           $9::timestamptz, $10::timestamptz, 1
         )
         RETURNING id, principal_id, control_epoch, token_digest, csrf_digest,
                   principal_authority_epoch, purpose, state, created_at, last_seen_at,
                   idle_expires_at, absolute_expires_at, revoked_at, version`,
        [
          input.id,
          input.principalId,
          input.controlEpoch,
          toParamBuffer(input.tokenDigest),
          toParamBuffer(input.csrfDigest),
          input.principalAuthorityEpoch.toString(10),
          input.purpose,
          toUtcParam(input.createdAt),
          toUtcParam(input.idleExpiresAt),
          toUtcParam(input.absoluteExpiresAt)
        ]
      );
      return mapSessionRow(res.rows[0]!);
    },
    completeSignInAtomic(input: CompleteSignInAtomicInput): Promise<HumanSessionRecord> {
      return exec.inTx(async (tx) => {
        const ch = await tx.query<Record<string, unknown>>(
          `UPDATE rq.auth_challenges
              SET state = 'consumed', version = version + 1
            WHERE id = $1::uuid AND version = $2::bigint AND control_epoch = $3::uuid AND state = 'pending'
            RETURNING id`,
          [
            input.challengeId,
            input.expectedChallengeVersion.toString(10),
            input.expectedControlEpoch
          ]
        );
        if (ch.rows[0] === undefined) {
          throw new ConflictDomainError({
            code: "VERSION_CONFLICT",
            message: "Sign-in challenge already consumed or expired"
          });
        }

        const pk = await tx.query<Record<string, unknown>>(
          `UPDATE rq.passkeys
              SET sign_count = $3::bigint,
                  device_type = $4::text,
                  backed_up = $5::boolean,
                  last_used_at = $6::timestamptz,
                  version = version + 1
            WHERE id = $1::uuid AND version = $2::bigint
            RETURNING id`,
          [
            input.passkeyId,
            input.expectedPasskeyVersion.toString(10),
            input.verifiedPasskey.newSignCount.toString(10),
            input.verifiedPasskey.deviceType,
            input.verifiedPasskey.backedUp,
            toUtcParam(input.now)
          ]
        );
        if (pk.rows[0] === undefined) {
          throw new ConflictDomainError({
            code: "VERSION_CONFLICT",
            message: "Passkey version conflict during sign-in"
          });
        }

        const sess = await tx.query<Record<string, unknown>>(
          `INSERT INTO rq.human_sessions (
             id, principal_id, control_epoch, token_digest, csrf_digest,
             principal_authority_epoch, purpose, state, created_at, last_seen_at,
             idle_expires_at, absolute_expires_at, version
           ) VALUES (
             $1::uuid, $2::uuid, $3::uuid, $4::bytea, $5::bytea,
             $6::bigint, $7::text, 'active', $8::timestamptz, $8::timestamptz,
             $9::timestamptz, $10::timestamptz, 1
           )
           RETURNING id, principal_id, control_epoch, token_digest, csrf_digest,
                     principal_authority_epoch, purpose, state, created_at, last_seen_at,
                     idle_expires_at, absolute_expires_at, revoked_at, version`,
          [
            input.session.id,
            input.session.principalId,
            input.session.controlEpoch,
            toParamBuffer(input.session.tokenDigest),
            toParamBuffer(input.session.csrfDigest),
            input.session.principalAuthorityEpoch.toString(10),
            input.session.purpose,
            toUtcParam(input.session.createdAt),
            toUtcParam(input.session.idleExpiresAt),
            toUtcParam(input.session.absoluteExpiresAt)
          ]
        );
        return mapSessionRow(sess.rows[0]!);
      });
    },
    async touchSessionIdle(input: TouchHumanSessionIdleInput): Promise<HumanSessionRecord> {
      const res = await exec.query<Record<string, unknown>>(
        `UPDATE rq.human_sessions
            SET last_seen_at = $3::timestamptz,
                idle_expires_at = $4::timestamptz,
                version = version + 1
          WHERE id = $1::uuid AND version = $2::bigint AND state = 'active'
          RETURNING id, principal_id, control_epoch, token_digest, csrf_digest,
                    principal_authority_epoch, purpose, state, created_at, last_seen_at,
                    idle_expires_at, absolute_expires_at, revoked_at, version`,
        [
          input.sessionId,
          input.expectedVersion.toString(10),
          toUtcParam(input.lastSeenAt),
          toUtcParam(input.idleExpiresAt)
        ]
      );
      if (res.rows[0] === undefined) {
        throw new ConflictDomainError({
          code: "VERSION_CONFLICT",
          message: "Human session version conflict"
        });
      }
      return mapSessionRow(res.rows[0]);
    },
    async revokeSession(input: {
      readonly sessionId: SessionId;
      readonly expectedVersion: bigint;
      readonly revokedAt: Temporal.Instant;
    }): Promise<HumanSessionRecord> {
      const res = await exec.query<Record<string, unknown>>(
        `UPDATE rq.human_sessions
            SET state = 'revoked', revoked_at = $3::timestamptz, version = version + 1
          WHERE id = $1::uuid AND version = $2::bigint
          RETURNING id, principal_id, control_epoch, token_digest, csrf_digest,
                    principal_authority_epoch, purpose, state, created_at, last_seen_at,
                    idle_expires_at, absolute_expires_at, revoked_at, version`,
        [input.sessionId, input.expectedVersion.toString(10), toUtcParam(input.revokedAt)]
      );
      if (res.rows[0] === undefined) {
        throw new ConflictDomainError({
          code: "VERSION_CONFLICT",
          message: "Human session version conflict during revoke"
        });
      }
      return mapSessionRow(res.rows[0]);
    },
    async revokeOtherSessionsForPrincipal(input: {
      readonly principalId: PrincipalId;
      readonly keepSessionId: SessionId;
      readonly revokedAt: Temporal.Instant;
    }): Promise<number> {
      const res = await exec.query<Record<string, unknown>>(
        `UPDATE rq.human_sessions
            SET state = 'revoked', revoked_at = $3::timestamptz, version = version + 1
          WHERE principal_id = $1::uuid AND id <> $2::uuid AND state = 'active'
          RETURNING id`,
        [input.principalId, input.keepSessionId, toUtcParam(input.revokedAt)]
      );
      return res.rows.length;
    }
  };
}

export function createPgStepUpRepo(exec: PgExecutor): OperationProofRepository {
  return {
    async findProofById(id: OperationProofId): Promise<OperationProofRecord | null> {
      const res = await exec.query<Record<string, unknown>>(
        `SELECT id, session_id, principal_id, control_epoch, action, target_sha256,
                challenge_id, verified_at, expires_at, state, accepted_receipt_id, version
           FROM rq.operation_proofs
          WHERE id = $1::uuid`,
        [id]
      );
      return res.rows[0] ? mapOperationProofRow(res.rows[0]) : null;
    },
    completeStepUpAtomic(input: CompleteStepUpAtomicInput): Promise<OperationProofRecord> {
      return exec.inTx(async (tx) => {
        const ch = await tx.query<Record<string, unknown>>(
          `UPDATE rq.auth_challenges
              SET state = 'consumed', version = version + 1
            WHERE id = $1::uuid AND version = $2::bigint AND control_epoch = $3::uuid AND state = 'pending'
            RETURNING id`,
          [
            input.challengeId,
            input.expectedChallengeVersion.toString(10),
            input.expectedControlEpoch
          ]
        );
        if (ch.rows[0] === undefined) {
          throw new ConflictDomainError({
            code: "VERSION_CONFLICT",
            message: "Step-up challenge already consumed or expired"
          });
        }
        const pk = await tx.query<Record<string, unknown>>(
          `UPDATE rq.passkeys
              SET sign_count = $3::bigint,
                  device_type = $4::text,
                  backed_up = $5::boolean,
                  last_used_at = $6::timestamptz,
                  version = version + 1
            WHERE id = $1::uuid AND version = $2::bigint
            RETURNING id`,
          [
            input.passkeyId,
            input.expectedPasskeyVersion.toString(10),
            input.verifiedPasskey.newSignCount.toString(10),
            input.verifiedPasskey.deviceType,
            input.verifiedPasskey.backedUp,
            toUtcParam(input.verifiedAt)
          ]
        );
        if (pk.rows[0] === undefined) {
          throw new ConflictDomainError({
            code: "VERSION_CONFLICT",
            message: "Passkey version conflict during step-up"
          });
        }
        const proof = await tx.query<Record<string, unknown>>(
          `INSERT INTO rq.operation_proofs (
             id, session_id, principal_id, control_epoch, action, target_sha256,
             challenge_id, verified_at, expires_at, state, version
           ) VALUES (
             $1::uuid, $2::uuid, $3::uuid, $4::uuid, $5::text, $6::bytea,
             $7::uuid, $8::timestamptz, $9::timestamptz, 'active', 1
           )
           RETURNING id, session_id, principal_id, control_epoch, action, target_sha256,
                     challenge_id, verified_at, expires_at, state, accepted_receipt_id, version`,
          [
            input.proofId,
            input.sessionId,
            input.principalId,
            input.expectedControlEpoch,
            input.action,
            toParamBuffer(input.targetSha256),
            input.challengeId,
            toUtcParam(input.verifiedAt),
            toUtcParam(input.expiresAt)
          ]
        );
        return mapOperationProofRow(proof.rows[0]!);
      });
    },
    async consumeOperationProof(input: ConsumeOperationProofInput): Promise<OperationProofRecord> {
      const res = await exec.query<Record<string, unknown>>(
        `UPDATE rq.operation_proofs
            SET state = 'consumed',
                accepted_receipt_id = (SELECT id FROM rq.command_receipts WHERE id = $8::uuid),
                version = version + 1
          WHERE id = $1::uuid
            AND version = $2::bigint
            AND session_id = $3::uuid
            AND principal_id = $4::uuid
            AND control_epoch = $5::uuid
            AND action = $6::text
            AND target_sha256 = $7::bytea
            AND state = 'active'
            AND expires_at > $9::timestamptz
          RETURNING id, session_id, principal_id, control_epoch, action, target_sha256,
                    challenge_id, verified_at, expires_at, state, accepted_receipt_id, version`,
        [
          input.proofId,
          input.expectedVersion.toString(10),
          input.expectedSessionId,
          input.expectedPrincipalId,
          input.expectedControlEpoch,
          input.expectedAction,
          toParamBuffer(input.expectedTargetSha256),
          input.acceptedReceiptId,
          toUtcParam(input.now)
        ]
      );
      if (res.rows[0] === undefined) {
        throw new ConflictDomainError({
          code: "VERSION_CONFLICT",
          message: "Operation proof was already consumed, expired, or mismatched"
        });
      }
      return mapOperationProofRow(res.rows[0]);
    },
    async revokeOperationProof(id: OperationProofId, expectedVersion: bigint): Promise<OperationProofRecord> {
      const res = await exec.query<Record<string, unknown>>(
        `UPDATE rq.operation_proofs
            SET state = 'revoked', version = version + 1
          WHERE id = $1::uuid AND version = $2::bigint
          RETURNING id, session_id, principal_id, control_epoch, action, target_sha256,
                    challenge_id, verified_at, expires_at, state, accepted_receipt_id, version`,
        [id, expectedVersion.toString(10)]
      );
      if (res.rows[0] === undefined) {
        throw new ConflictDomainError({
          code: "VERSION_CONFLICT",
          message: "Operation proof version conflict"
        });
      }
      return mapOperationProofRow(res.rows[0]);
    }
  };
}

export function createPgProducerCredentialRepo(exec: PgExecutor): ProducerCredentialRepository {
  const mapProducer = (row: Record<string, unknown>): ProducerRecord => ({
    id: parseProducerId(row["id"], "producer.id"),
    tenantId: parseTenantId(row["tenant_id"], "tenant_id"),
    projectId: parseProjectId(row["project_id"], "project_id"),
    principalId: parsePrincipalId(row["principal_id"], "principal_id"),
    principalKind: String(row["principal_kind"]) as "producer" | "human",
    channelKind: String(row["channel_kind"]) as ProducerRecord["channelKind"],
    name: String(row["name"]),
    businessNamespace: parseProducerNamespace(row["business_namespace"], "business_namespace"),
    state: String(row["state"]) as ProducerState,
    currentScopeVersion:
      row["current_scope_version"] === null || row["current_scope_version"] === undefined
        ? null
        : toBigIntSafe(row["current_scope_version"], "current_scope_version"),
    authorityEpoch: toBigIntSafe(row["authority_epoch"], "authority_epoch"),
    version: toBigIntSafe(row["version"], "version")
  });

  const mapScope = (row: Record<string, unknown>): ProducerScopeVersionRecord => {
    const rawDef = (row["scope_definition"] ?? {}) as Record<string, unknown>;
    const rawEvents = Array.isArray(rawDef["allowed_events"])
      ? rawDef["allowed_events"]
      : Array.isArray(rawDef["allowedEvents"])
        ? rawDef["allowedEvents"]
        : [];
    const allowedEvents = rawEvents.map((ev) => {
      const item = ev as Record<string, unknown>;
      const rawVers = Array.isArray(item["allowed_schema_versions"])
        ? item["allowed_schema_versions"]
        : Array.isArray(item["schemaVersions"])
          ? item["schemaVersions"]
          : [];
      return {
        eventTypeId: parseEventTypeId(item["event_type_id"] ?? item["eventTypeId"], "event_type_id"),
        schemaVersions: rawVers.map((v) => toIntSafe(v, "schema_version"))
      };
    });
    const rawActions = Array.isArray(rawDef["allowed_actions"])
      ? rawDef["allowed_actions"]
      : Array.isArray(rawDef["actions"])
        ? rawDef["actions"]
        : ["admit", "read_status", "watch"];
    const scopeDefinition: ProducerScopeDefinition = {
      allowedEvents,
      actions: rawActions.map((a) => String(a) as ProducerScopeDefinition["actions"][number])
    };
    return {
      producerId: parseProducerId(row["producer_id"], "producer_id"),
      scopeVersion: toBigIntSafe(row["scope_version"], "scope_version"),
      tenantId: parseTenantId(row["tenant_id"], "tenant_id"),
      projectId: parseProjectId(row["project_id"], "project_id"),
      scopeDefinition,
      scopeSha256: readByteaUint8(row["scope_sha256"], "scope_sha256"),
      state: String(row["state"]) as ProducerScopeVersionState
    };
  };

  const mapIntent = (row: Record<string, unknown>): ProducerCredentialIntentRecord => ({
    id: parseProducerCredentialIntentId(row["id"], "intent.id"),
    producerId: parseProducerId(row["producer_id"], "producer_id"),
    tenantId: parseTenantId(row["tenant_id"], "tenant_id"),
    projectId: parseProjectId(row["project_id"], "project_id"),
    channelKind: "machine_producer",
    controlEpoch: parseControlEpoch(row["control_epoch"], "control_epoch"),
    scopeVersion: toBigIntSafe(row["scope_version"], "scope_version"),
    scopeSha256: readByteaUint8(row["scope_sha256"], "scope_sha256"),
    requestedExpiry: readInstant(row["requested_expiry"], "requested_expiry"),
    custodyDestinationReference: String(row["custody_destination_reference"]),
    state: String(row["state"]) as ProducerCredentialIntentState,
    credentialId:
      row["credential_id"] === null || row["credential_id"] === undefined
        ? null
        : parseProducerCredentialId(row["credential_id"], "credential_id"),
    issuerPrincipalId: parsePrincipalId(row["issuer_principal_id"], "issuer_principal_id"),
    createdAt: readInstant(row["created_at"], "created_at"),
    expiresAt: readInstant(row["expires_at"], "expires_at"),
    version: toBigIntSafe(row["version"], "version")
  });

  const mapCredential = (row: Record<string, unknown>): ProducerCredentialRecord => ({
    id: parseProducerCredentialId(row["id"], "credential.id"),
    producerId: parseProducerId(row["producer_id"], "producer_id"),
    tenantId: parseTenantId(row["tenant_id"], "tenant_id"),
    projectId: parseProjectId(row["project_id"], "project_id"),
    principalId: parsePrincipalId(row["principal_id"], "principal_id"),
    channelKind: "machine_producer",
    controlEpoch: parseControlEpoch(row["control_epoch"], "control_epoch"),
    secretDigest: readByteaUint8(row["secret_digest"], "secret_digest"),
    state: String(row["state"]) as ProducerCredentialState,
    scopeVersion: toBigIntSafe(row["scope_version"], "scope_version"),
    ownerAuthorityEpoch: toBigIntSafe(row["owner_authority_epoch"], "owner_authority_epoch"),
    issuedBy: parsePrincipalId(row["issued_by"], "issued_by"),
    intentId: parseProducerCredentialIntentId(row["intent_id"], "intent_id"),
    createdAt: readInstant(row["created_at"], "created_at"),
    expiresAt: readInstant(row["expires_at"], "expires_at"),
    activatedAt: readOptionalInstant(row["activated_at"], "activated_at"),
    overlapStartedAt: null,
    overlapEndsAt: null,
    revokedAt: readOptionalInstant(row["revoked_at"], "revoked_at"),
    version: toBigIntSafe(row["version"], "version")
  });

  return {
    async findProducerById(producerId: ProducerId): Promise<ProducerRecord | null> {
      const res = await exec.query<Record<string, unknown>>(
        `SELECT id, tenant_id, project_id, principal_id, principal_kind, channel_kind,
                name, business_namespace, state, current_scope_version, authority_epoch, version
           FROM rq.producers
          WHERE id = $1::uuid`,
        [producerId]
      );
      return res.rows[0] ? mapProducer(res.rows[0]) : null;
    },
    async findPrincipalById(principalId: PrincipalId): Promise<PrincipalRecord | null> {
      const res = await exec.query<Record<string, unknown>>(
        `SELECT id, kind, state, authority_epoch, version
           FROM rq.principals
          WHERE id = $1::uuid`,
        [principalId]
      );
      return res.rows[0] ? mapPrincipalRow(res.rows[0]) : null;
    },
    async findScopeVersion(
      producerId: ProducerId,
      scopeVersion: bigint
    ): Promise<ProducerScopeVersionRecord | null> {
      const res = await exec.query<Record<string, unknown>>(
        `SELECT producer_id, scope_version, tenant_id, project_id, scope_definition, scope_sha256, state
           FROM rq.producer_scope_versions
          WHERE producer_id = $1::uuid AND scope_version = $2::bigint`,
        [producerId, scopeVersion.toString(10)]
      );
      return res.rows[0] ? mapScope(res.rows[0]) : null;
    },
    async findCredentialIntentById(
      intentId: ProducerCredentialIntentId
    ): Promise<ProducerCredentialIntentRecord | null> {
      const res = await exec.query<Record<string, unknown>>(
        `SELECT id, producer_id, tenant_id, project_id, control_epoch, scope_version, scope_sha256,
                requested_expiry, custody_destination_reference, state, credential_id,
                issuer_principal_id, created_at, expires_at, version
           FROM rq.producer_credential_intents
          WHERE id = $1::uuid`,
        [intentId]
      );
      return res.rows[0] ? mapIntent(res.rows[0]) : null;
    },
    async findCredentialById(
      credentialId: ProducerCredentialId
    ): Promise<ProducerCredentialRecord | null> {
      const res = await exec.query<Record<string, unknown>>(
        `SELECT id, producer_id, tenant_id, project_id, principal_id, control_epoch, secret_digest,
                state, scope_version, owner_authority_epoch, issued_by, intent_id,
                created_at, expires_at, activated_at, revoked_at, version
           FROM rq.producer_credentials
          WHERE id = $1::uuid`,
        [credentialId]
      );
      return res.rows[0] ? mapCredential(res.rows[0]) : null;
    },
    async createCredentialIntent(input): Promise<ProducerCredentialIntentRecord> {
      const res = await exec.query<Record<string, unknown>>(
        `INSERT INTO rq.producer_credential_intents (
           id, producer_id, tenant_id, project_id, channel_kind, control_epoch,
           scope_version, scope_sha256, requested_expiry, custody_destination_reference,
           state, issuer_principal_id, created_at, expires_at, version
         ) VALUES (
           $1::uuid, $2::uuid, $3::uuid, $4::uuid, 'machine_producer', $5::uuid,
           $6::bigint, $7::bytea, $8::timestamptz, $9::text,
           'requested', $10::uuid, $11::timestamptz, $12::timestamptz, 1
         )
         RETURNING id, producer_id, tenant_id, project_id, control_epoch, scope_version, scope_sha256,
                   requested_expiry, custody_destination_reference, state, credential_id,
                   issuer_principal_id, created_at, expires_at, version`,
        [
          input.id,
          input.producerId,
          input.tenantId,
          input.projectId,
          input.controlEpoch,
          input.scopeVersion.toString(10),
          toParamBuffer(input.scopeSha256),
          toUtcParam(input.requestedExpiry),
          input.custodyDestinationReference,
          input.issuerPrincipalId,
          toUtcParam(input.createdAt),
          toUtcParam(input.expiresAt)
        ]
      );
      return mapIntent(res.rows[0]!);
    },
    recordDeliveredCredential(input): Promise<{
      readonly intent: ProducerCredentialIntentRecord;
      readonly credential: ProducerCredentialRecord;
    }> {
      return exec.inTx(async (tx) => {
        const curIntent = await tx.query<Record<string, unknown>>(
          `SELECT id, producer_id, tenant_id, project_id, control_epoch, scope_version, scope_sha256,
                  requested_expiry, custody_destination_reference, state, credential_id,
                  issuer_principal_id, created_at, expires_at, version
             FROM rq.producer_credential_intents
            WHERE id = $1::uuid AND version = $2::bigint
            FOR UPDATE`,
          [input.intentId, input.expectedIntentVersion.toString(10)]
        );
        const intentRow = curIntent.rows[0];
        if (intentRow === undefined) {
          throw new ConflictDomainError({
            code: "VERSION_CONFLICT",
            message: "Credential intent version conflict"
          });
        }
        const prodRes = await tx.query<Record<string, unknown>>(
          `SELECT principal_id, authority_epoch FROM rq.producers WHERE id = $1::uuid FOR SHARE`,
          [intentRow["producer_id"]]
        );
        const prodRow = prodRes.rows[0];
        if (prodRow === undefined) {
          throw new NotFoundDomainError({
            code: "NOT_FOUND",
            message: "Producer not found"
          });
        }

        const credRes = await tx.query<Record<string, unknown>>(
          `INSERT INTO rq.producer_credentials (
             id, producer_id, tenant_id, project_id, principal_id, channel_kind,
             control_epoch, secret_digest, state, scope_version, owner_authority_epoch,
             issued_by, intent_id, created_at, expires_at, version
           ) VALUES (
             $1::uuid, $2::uuid, $3::uuid, $4::uuid, $5::uuid, 'machine_producer',
             $6::uuid, $7::bytea, 'pending_activation', $8::bigint, $9::bigint,
             $10::uuid, $11::uuid, $12::timestamptz, $13::timestamptz, 1
           )
           RETURNING id, producer_id, tenant_id, project_id, principal_id, control_epoch, secret_digest,
                     state, scope_version, owner_authority_epoch, issued_by, intent_id,
                     created_at, expires_at, activated_at, revoked_at, version`,
          [
            input.credentialId,
            intentRow["producer_id"],
            intentRow["tenant_id"],
            intentRow["project_id"],
            prodRow["principal_id"],
            intentRow["control_epoch"],
            toParamBuffer(input.secretDigest),
            intentRow["scope_version"],
            prodRow["authority_epoch"],
            intentRow["issuer_principal_id"],
            input.intentId,
            toUtcParam(input.now),
            toUtcParam(input.expiresAt)
          ]
        );
        const updIntent = await tx.query<Record<string, unknown>>(
          `UPDATE rq.producer_credential_intents
              SET state = 'delivered', credential_id = $3::uuid, version = version + 1
            WHERE id = $1::uuid AND version = $2::bigint
            RETURNING id, producer_id, tenant_id, project_id, control_epoch, scope_version, scope_sha256,
                      requested_expiry, custody_destination_reference, state, credential_id,
                      issuer_principal_id, created_at, expires_at, version`,
          [input.intentId, input.expectedIntentVersion.toString(10), input.credentialId]
        );
        return {
          intent: mapIntent(updIntent.rows[0]!),
          credential: mapCredential(credRes.rows[0]!)
        };
      });
    },
    activateCredentialAtomic(input): Promise<{
      readonly intent: ProducerCredentialIntentRecord;
      readonly credential: ProducerCredentialRecord;
    }> {
      return exec.inTx(async (tx) => {
        const cred = await tx.query<Record<string, unknown>>(
          `UPDATE rq.producer_credentials
              SET state = 'active', activated_at = $3::timestamptz, version = version + 1
            WHERE id = $1::uuid AND version = $2::bigint AND state = 'pending_activation'
            RETURNING id, producer_id, tenant_id, project_id, principal_id, control_epoch, secret_digest,
                      state, scope_version, owner_authority_epoch, issued_by, intent_id,
                      created_at, expires_at, activated_at, revoked_at, version`,
          [input.credentialId, input.expectedCredentialVersion.toString(10), toUtcParam(input.now)]
        );
        if (cred.rows[0] === undefined) {
          throw new ConflictDomainError({
            code: "VERSION_CONFLICT",
            message: "Credential activation version or state conflict"
          });
        }
        const intent = await tx.query<Record<string, unknown>>(
          `UPDATE rq.producer_credential_intents
              SET state = 'activated', version = version + 1
            WHERE id = $1::uuid AND version = $2::bigint
            RETURNING id, producer_id, tenant_id, project_id, control_epoch, scope_version, scope_sha256,
                      requested_expiry, custody_destination_reference, state, credential_id,
                      issuer_principal_id, created_at, expires_at, version`,
          [input.intentId, input.expectedIntentVersion.toString(10)]
        );
        if (intent.rows[0] === undefined) {
          throw new ConflictDomainError({
            code: "VERSION_CONFLICT",
            message: "Credential intent version conflict"
          });
        }
        return {
          intent: mapIntent(intent.rows[0]),
          credential: mapCredential(cred.rows[0])
        };
      });
    },
    rotateCredentialOverlapAtomic(input): Promise<{
      readonly oldCredential: ProducerCredentialRecord;
      readonly newCredential: ProducerCredentialRecord;
    }> {
      return exec.inTx(async (tx) => {
        const oldCred = await tx.query<Record<string, unknown>>(
          `UPDATE rq.producer_credentials
              SET state = 'overlap', version = version + 1
            WHERE id = $1::uuid AND version = $2::bigint
            RETURNING id, producer_id, tenant_id, project_id, principal_id, control_epoch, secret_digest,
                      state, scope_version, owner_authority_epoch, issued_by, intent_id,
                      created_at, expires_at, activated_at, revoked_at, version`,
          [input.oldCredentialId, input.expectedOldVersion.toString(10)]
        );
        const newCred = await tx.query<Record<string, unknown>>(
          `UPDATE rq.producer_credentials
              SET state = 'active', activated_at = $3::timestamptz, version = version + 1
            WHERE id = $1::uuid AND version = $2::bigint
            RETURNING id, producer_id, tenant_id, project_id, principal_id, control_epoch, secret_digest,
                      state, scope_version, owner_authority_epoch, issued_by, intent_id,
                      created_at, expires_at, activated_at, revoked_at, version`,
          [input.newCredentialId, input.expectedNewVersion.toString(10), toUtcParam(input.now)]
        );
        if (oldCred.rows[0] === undefined || newCred.rows[0] === undefined) {
          throw new ConflictDomainError({
            code: "VERSION_CONFLICT",
            message: "Credential rotation version conflict"
          });
        }
        return {
          oldCredential: mapCredential(oldCred.rows[0]),
          newCredential: mapCredential(newCred.rows[0])
        };
      });
    },
    async revokeCredential(input): Promise<ProducerCredentialRecord> {
      const res = await exec.query<Record<string, unknown>>(
        `UPDATE rq.producer_credentials
            SET state = 'revoked', revoked_at = $3::timestamptz, version = version + 1
          WHERE id = $1::uuid AND version = $2::bigint
          RETURNING id, producer_id, tenant_id, project_id, principal_id, control_epoch, secret_digest,
                    state, scope_version, owner_authority_epoch, issued_by, intent_id,
                    created_at, expires_at, activated_at, revoked_at, version`,
        [input.credentialId, input.expectedVersion.toString(10), toUtcParam(input.revokedAt)]
      );
      if (res.rows[0] === undefined) {
        throw new ConflictDomainError({
          code: "VERSION_CONFLICT",
          message: "Credential version conflict"
        });
      }
      return mapCredential(res.rows[0]);
    }
  };
}

export function createPgGovernanceRepo(exec: PgExecutor): GovernanceRepository {
  return {
    async getPrincipal(principalId: PrincipalId): Promise<PrincipalRecord | null> {
      const res = await exec.query<Record<string, unknown>>(
        `SELECT id, kind, state, authority_epoch, version
           FROM rq.principals
          WHERE id = $1::uuid`,
        [principalId]
      );
      return res.rows[0] ? mapPrincipalRow(res.rows[0]) : null;
    },
    async listPlatformRolesForPrincipal(
      principalId: PrincipalId
    ): Promise<readonly PlatformRoleAssignmentRecord[]> {
      const res = await exec.query<Record<string, unknown>>(
        `SELECT id, principal_id, role, state, governance_version, created_at, revoked_at, version
           FROM rq.platform_role_assignments
          WHERE principal_id = $1::uuid`,
        [principalId]
      );
      return res.rows.map((row) => ({
        id: parseCanonicalUuid(row["id"], "assignment.id") as PlatformRoleAssignmentId,
        principalId: parsePrincipalId(row["principal_id"], "principal_id"),
        role: String(row["role"]) as PlatformRole,
        state: String(row["state"]) as PlatformRoleAssignmentState,
        governanceVersion: toBigIntSafe(row["governance_version"], "governance_version"),
        createdAt: readInstant(row["created_at"], "created_at"),
        revokedAt: readOptionalInstant(row["revoked_at"], "revoked_at"),
        version: toBigIntSafe(row["version"], "version")
      }));
    },
    async countActivePlatformAdmins(excludeAssignmentId?: PlatformRoleAssignmentId): Promise<number> {
      const res = await exec.query<{ cnt: number }>(
        `SELECT count(*)::integer AS cnt
           FROM rq.platform_role_assignments
          WHERE role = 'platform_admin'
            AND state = 'active'
            AND ($1::uuid IS NULL OR id <> $1::uuid)`,
        [excludeAssignmentId ?? null]
      );
      return res.rows[0]?.cnt ?? 0;
    },
    async listTenantMembershipsForPrincipal(
      principalId: PrincipalId,
      tenantId: TenantId
    ): Promise<readonly TenantMembershipRecord[]> {
      const res = await exec.query<Record<string, unknown>>(
        `SELECT id, tenant_id, principal_id, role, state, authority_version, created_at, updated_at, version
           FROM rq.tenant_memberships
          WHERE principal_id = $1::uuid AND tenant_id = $2::uuid`,
        [principalId, tenantId]
      );
      return res.rows.map((row) => ({
        id: parseCanonicalUuid(row["id"], "membership.id") as TenantMembershipId,
        tenantId: parseTenantId(row["tenant_id"], "tenant_id"),
        principalId: parsePrincipalId(row["principal_id"], "principal_id"),
        role: String(row["role"]) as TenantRole,
        state: String(row["state"]) as MembershipState,
        authorityVersion: toBigIntSafe(row["authority_version"], "authority_version"),
        createdAt: readInstant(row["created_at"], "created_at"),
        updatedAt: readInstant(row["updated_at"], "updated_at"),
        version: toBigIntSafe(row["version"], "version")
      }));
    },
    async countActiveTenantAdmins(
      tenantId: TenantId,
      excludeMembershipId?: TenantMembershipId
    ): Promise<number> {
      const res = await exec.query<{ cnt: number }>(
        `SELECT count(*)::integer AS cnt
           FROM rq.tenant_memberships
          WHERE tenant_id = $1::uuid AND role = 'tenant_admin' AND state = 'active'
            AND ($2::uuid IS NULL OR id <> $2::uuid)`,
        [tenantId, excludeMembershipId ?? null]
      );
      return res.rows[0]?.cnt ?? 0;
    },
    async listProjectMembershipsForPrincipal(
      principalId: PrincipalId,
      tenantId: TenantId,
      projectId: ProjectId
    ): Promise<readonly ProjectMembershipRecord[]> {
      const res = await exec.query<Record<string, unknown>>(
        `SELECT id, tenant_id, project_id, principal_id, role, state, authority_version,
                created_at, updated_at, version
           FROM rq.project_memberships
          WHERE principal_id = $1::uuid AND tenant_id = $2::uuid AND project_id = $3::uuid`,
        [principalId, tenantId, projectId]
      );
      return res.rows.map((row) => ({
        id: parseCanonicalUuid(row["id"], "membership.id") as ProjectMembershipId,
        tenantId: parseTenantId(row["tenant_id"], "tenant_id"),
        projectId: parseProjectId(row["project_id"], "project_id"),
        principalId: parsePrincipalId(row["principal_id"], "principal_id"),
        role: String(row["role"]) as ProjectRole,
        state: String(row["state"]) as MembershipState,
        authorityVersion: toBigIntSafe(row["authority_version"], "authority_version"),
        createdAt: readInstant(row["created_at"], "created_at"),
        updatedAt: readInstant(row["updated_at"], "updated_at"),
        version: toBigIntSafe(row["version"], "version")
      }));
    },
    async countActiveProjectAdmins(
      projectId: ProjectId,
      excludeMembershipId?: ProjectMembershipId
    ): Promise<number> {
      const res = await exec.query<{ cnt: number }>(
        `SELECT count(*)::integer AS cnt
           FROM rq.project_memberships
          WHERE project_id = $1::uuid AND role = 'project_admin' AND state = 'active'
            AND ($2::uuid IS NULL OR id <> $2::uuid)`,
        [projectId, excludeMembershipId ?? null]
      );
      return res.rows[0]?.cnt ?? 0;
    },
    async listDataGrantsForMemberships(
      membershipIds: readonly ProjectMembershipId[],
      action: DataGrantAction
    ): Promise<readonly HumanDataGrantRecord[]> {
      if (membershipIds.length === 0) {
        return [];
      }
      const res = await exec.query<Record<string, unknown>>(
        `SELECT id, membership_id, tenant_id, project_id, action, projection,
                producer_namespace, state, expires_at, created_by, created_at, version
           FROM rq.human_data_grants
          WHERE membership_id = ANY($1::uuid[]) AND action = $2::text`,
        [membershipIds, action]
      );
      return res.rows.map((row) => ({
        id: parseDataGrantId(row["id"], "grant.id"),
        membershipId: parseCanonicalUuid(row["membership_id"], "membership_id") as ProjectMembershipId,
        tenantId: parseTenantId(row["tenant_id"], "tenant_id"),
        projectId: parseProjectId(row["project_id"], "project_id"),
        action: String(row["action"]) as DataGrantAction,
        projection: String(row["projection"]) as DataGrantProjection,
        producerNamespace:
          row["producer_namespace"] === null || row["producer_namespace"] === undefined
            ? null
            : parseProducerNamespace(row["producer_namespace"], "producer_namespace"),
        state: String(row["state"]) as DataGrantState,
        expiresAt: readOptionalInstant(row["expires_at"], "expires_at"),
        createdBy: parsePrincipalId(row["created_by"], "created_by"),
        createdAt: readInstant(row["created_at"], "created_at"),
        version: toBigIntSafe(row["version"], "version")
      }));
    }
  };
}

export function createPgAuthRepositories(exec: PgExecutor): AuthRepositoriesBundle {
  return {
    preauth: createPgPreauthRepo(exec),
    challenges: createPgAuthChallengeRepo(exec),
    passkeys: createPgPasskeyRepo(exec),
    enrollment: createPgEnrollmentRepo(exec),
    sessions: createPgSessionRepo(exec),
    stepUp: createPgStepUpRepo(exec),
    producerCredentials: createPgProducerCredentialRepo(exec),
    humanAuthorization: createPgGovernanceRepo(exec)
  };
}
