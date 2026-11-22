import type { Pool, PoolClient, PoolConfig } from "pg";
import {
  formatUtcTimestamp,
  nowUtcInstant,
  parseCanonicalUuid,
  parseSha256Hex
} from "@relayquill/domain";
import { parseCanonicalUtcTimestamp } from "@relayquill/contracts";

export type ProviderKind = "stripe" | "paystack" | "github";
export type AccountMode = "test" | "live";

export interface ProviderIngressQueryResult<
  TRow extends Record<string, unknown> = Record<string, unknown>
> {
  readonly rows: readonly TRow[];
  readonly rowCount?: number | null | undefined;
}

export interface ProviderIngressSqlTxClient {
  query<TRow extends Record<string, unknown> = Record<string, unknown>>(
    sql: string,
    params?: readonly unknown[]
  ): Promise<ProviderIngressQueryResult<TRow>>;
}

export interface PGliteCompatibleClient {
  readonly closed?: boolean | undefined;
  query<TRow = Record<string, unknown>>(
    sql: string,
    params?: unknown[]
  ): Promise<{
    readonly rows: TRow[];
    readonly rowCount?: number | undefined;
    readonly affectedRows?: number | undefined;
  }>;
  exec?(sql: string): Promise<unknown>;
  transaction<T>(callback: (tx: ProviderIngressSqlTxClient) => Promise<T>): Promise<T>;
  close?(): Promise<void>;
}

export interface ProviderIngressDbClient {
  readonly backend: "pg" | "pglite";
  inTransaction<T>(fn: (tx: ProviderIngressSqlTxClient) => Promise<T>): Promise<T>;
  query<TRow extends Record<string, unknown> = Record<string, unknown>>(
    sql: string,
    params?: readonly unknown[]
  ): Promise<ProviderIngressQueryResult<TRow>>;
  exec(sql: string): Promise<void>;
  close(): Promise<void>;
}

export interface CreateProviderIngressDbOptions {
  readonly pool?: Pool | undefined;
  readonly poolConfig?: PoolConfig | undefined;
  readonly pglite?: PGliteCompatibleClient | undefined;
  readonly ownsClient?: boolean | undefined;
  readonly schema?: string | undefined;
  readonly role?: string | undefined;
  readonly applySetLocalRole?: boolean | undefined;
}

export class ProviderIngressDbError extends Error {
  readonly code: string;
  readonly httpStatus: number;

  constructor(options: {
    readonly code: string;
    readonly httpStatus: number;
    readonly message: string;
    readonly cause?: unknown;
  }) {
    super(options.message, options.cause !== undefined ? { cause: options.cause } : undefined);
    this.name = new.target.name;
    this.code = options.code;
    this.httpStatus = options.httpStatus;
  }
}

export interface ProviderBindingRecord {
  readonly id: string;
  readonly provider: ProviderKind;
  readonly accountReference: string;
  readonly accountMode: AccountMode;
  readonly payloadProfile: string;
  readonly secretCustodyReference: string;
  readonly secretVersionReference: string;
  readonly state: string;
  readonly relayTenantId: string;
  readonly relayProjectId: string;
  readonly publicationChannelId: string;
  readonly normalizedEventTypeId: string;
  readonly normalizedSchemaVersion: number;
  readonly currentBindingVersion: bigint;
}

export interface ReceiveVerifiedCallbackParams {
  readonly observationId: string;
  readonly forwardIntentId: string;
  readonly bindingId: string;
  readonly bindingVersion: bigint;
  readonly provider: ProviderKind;
  readonly accountMode: AccountMode;
  readonly payloadProfile: string;
  readonly providerEventId: string | null;
  readonly eventType: string;
  readonly objectReference: string | null;
  readonly providerBusinessTime: string | null;
  readonly rawBodySha256Hex: string;
  readonly identityProfile: string;
  readonly semanticKeySha256Hex: string;
  readonly normalizedFacts: Readonly<Record<string, unknown>>;
  readonly normalizedFactsSha256Hex: string;
  readonly businessKey: string;
  readonly requestKey: string;
  readonly preparedBytes: Buffer;
  readonly submissionSha256Hex: string;
}

export interface ReceiveVerifiedCallbackResult {
  readonly outcome: "accepted" | "already_accepted_transport" | "already_accepted_semantic";
  readonly observationId: string;
  readonly forwardIntentId?: string | undefined;
  readonly bindingId: string;
  readonly bindingVersion: bigint;
}

export interface DueForwardIntentRecord {
  readonly intentId: string;
  readonly state: "ready" | "claimed" | "acceptance_unknown";
  readonly bindingId: string;
  readonly nextAttemptAt: string;
}

export type ClaimForwardIntentResult =
  | {
      readonly outcome: "already_accepted";
      readonly intentId: string;
      readonly relayEventId?: string | undefined;
      readonly relayReceiptId?: string | undefined;
    }
  | {
      readonly outcome: "not_eligible" | "already_claimed" | "not_due";
      readonly state?: string | undefined;
    }
  | {
      readonly outcome: "claimed";
      readonly intentId: string;
      readonly observationId: string;
      readonly bindingId: string;
      readonly bindingVersion: bigint;
      readonly claimGeneration: bigint;
      readonly claimExpiresAt: string;
      readonly businessKey: string;
      readonly requestKey: string;
      readonly preparedBytes: Buffer;
      readonly priorState: "ready" | "claimed" | "acceptance_unknown";
    };

export type ForwardFinalizeOutcome =
  | "accepted"
  | "acceptance_unknown"
  | "blocked"
  | "retry";

export interface FinalizeForwardIntentResult {
  readonly outcome: string;
  readonly intentId: string;
  readonly state?: string | undefined;
  readonly relayEventId?: string | undefined;
  readonly relayReceiptId?: string | undefined;
}

export interface ProviderIngressStateSnapshot {
  readonly bindings: readonly {
    readonly id: string;
    readonly provider: ProviderKind;
    readonly accountReference: string;
    readonly accountMode: AccountMode;
    readonly state: string;
    readonly currentBindingVersion: string;
  }[];
  readonly observationsCount: number;
  readonly transportReceiptsCount: number;
  readonly semanticIdentitiesCount: number;
  readonly forwardIntents: readonly {
    readonly id: string;
    readonly observationId: string;
    readonly state: string;
    readonly businessKey: string;
    readonly relayEventId?: string | undefined;
    readonly safeErrorCode?: string | undefined;
  }[];
  readonly auditEventsCount: number;
}

const SAFE_IDENT_REGEX = /^[a-z_][a-z0-9_]*$/;

function assertSafeIdent(ident: string, label: string): string {
  if (!SAFE_IDENT_REGEX.test(ident)) {
    throw new ProviderIngressDbError({
      code: "INVALID_VALUE",
      httpStatus: 400,
      message: `Unsafe SQL ${label}: "${ident}"`
    });
  }
  return ident;
}

export function sha256HexToBuffer(hex: string, label = "sha256"): Buffer {
  return Buffer.from(parseSha256Hex(hex, label), "hex");
}

function readReqString(row: Record<string, unknown>, col: string): string {
  const val = row[col];
  if (typeof val !== "string" || val.length === 0) {
    throw new ProviderIngressDbError({
      code: "INTERNAL_ERROR",
      httpStatus: 500,
      message: `Missing required string column "${col}"`
    });
  }
  return val;
}

function readOptString(row: Record<string, unknown>, col: string): string | undefined {
  const val = row[col];
  if (val === null || val === undefined) {
    return undefined;
  }
  if (typeof val === "string" && val.length > 0) {
    return val;
  }
  return undefined;
}

function readReqBigInt(row: Record<string, unknown>, col: string): bigint {
  const val = row[col];
  if (typeof val === "bigint") {
    return val;
  }
  if (typeof val === "number") {
    return BigInt(Math.trunc(val));
  }
  if (typeof val === "string" && /^-?\d+$/.test(val.trim())) {
    return BigInt(val.trim());
  }
  throw new ProviderIngressDbError({
    code: "INTERNAL_ERROR",
    httpStatus: 500,
    message: `Missing required integer column "${col}"`
  });
}

function readReqTimestamp(row: Record<string, unknown>, col: string): string {
  const val = row[col];
  if (val instanceof Date) {
    return parseCanonicalUtcTimestamp(val.toISOString(), col);
  }
  if (typeof val === "string" && val.length > 0) {
    return parseCanonicalUtcTimestamp(val, col);
  }
  return formatUtcTimestamp(nowUtcInstant());
}

function mapPiSqlError(err: unknown): Error {
  if (err instanceof ProviderIngressDbError) {
    return err;
  }
  const rec = err as { readonly message?: unknown; readonly code?: unknown } | undefined;
  const msg = typeof rec?.message === "string" ? rec.message : String(err);
  const sqlstate = typeof rec?.code === "string" ? rec.code : undefined;

  if (msg.includes("SEMANTIC_IDENTITY_CONFLICT") || sqlstate === "23505") {
    return new ProviderIngressDbError({
      code: "SEMANTIC_IDENTITY_CONFLICT",
      httpStatus: 409,
      message: msg,
      cause: err
    });
  }
  if (sqlstate === "P0002") {
    return new ProviderIngressDbError({
      code: "NOT_FOUND",
      httpStatus: 404,
      message: msg,
      cause: err
    });
  }
  if (sqlstate === "42501") {
    return new ProviderIngressDbError({
      code: "FORBIDDEN",
      httpStatus: 403,
      message: msg,
      cause: err
    });
  }
  return new ProviderIngressDbError({
    code: "INTERNAL_ERROR",
    httpStatus: 500,
    message: msg,
    cause: err
  });
}

export async function createProviderIngressDbClient(
  options: CreateProviderIngressDbOptions
): Promise<ProviderIngressDbClient> {
  const schema = assertSafeIdent(options.schema ?? "pi", "schema");
  const role =
    options.role !== undefined && options.role.length > 0
      ? assertSafeIdent(options.role, "role")
      : undefined;
  const applyRole = options.applySetLocalRole === true && role !== undefined;

  if (options.pglite !== undefined) {
    const pglite = options.pglite;
    const owns = options.ownsClient ?? false;
    return {
      backend: "pglite",
      async inTransaction<T>(fn: (tx: ProviderIngressSqlTxClient) => Promise<T>): Promise<T> {
        try {
          return await pglite.transaction(async (rawTx) => {
            await rawTx.query("SET LOCAL TIME ZONE 'UTC'");
            await rawTx.query(`SET LOCAL search_path TO ${schema}, public`);
            if (applyRole && role !== undefined) {
              await rawTx.query(`SET LOCAL ROLE ${role}`);
            }
            return fn(rawTx);
          });
        } catch (err) {
          throw mapPiSqlError(err);
        }
      },
      async query<TRow extends Record<string, unknown> = Record<string, unknown>>(
        sql: string,
        params: readonly unknown[] = []
      ): Promise<ProviderIngressQueryResult<TRow>> {
        try {
          return await pglite.query<TRow>(sql, [...params]);
        } catch (err) {
          throw mapPiSqlError(err);
        }
      },
      async exec(sql: string): Promise<void> {
        if (typeof pglite.exec === "function") {
          await pglite.exec(sql);
          return;
        }
        await pglite.query(sql);
      },
      async close(): Promise<void> {
        if (owns && typeof pglite.close === "function" && pglite.closed !== true) {
          await pglite.close();
        }
      }
    };
  }

  let pool: Pool;
  let ownsPool = options.ownsClient ?? false;
  if (options.pool !== undefined) {
    pool = options.pool;
  } else if (options.poolConfig !== undefined) {
    const pgMod = await import("pg");
    pool = new pgMod.Pool(options.poolConfig);
    ownsPool = true;
  } else {
    throw new ProviderIngressDbError({
      code: "INVALID_VALUE",
      httpStatus: 400,
      message: "Either pglite, pool, or poolConfig must be provided to createProviderIngressDbClient"
    });
  }

  const runOnClient = async <T>(
    client: PoolClient,
    fn: (tx: ProviderIngressSqlTxClient) => Promise<T>
  ): Promise<T> => {
    await client.query("BEGIN");
    try {
      await client.query("SET LOCAL TIME ZONE 'UTC'");
      await client.query(`SET LOCAL search_path TO ${schema}, public`);
      if (applyRole && role !== undefined) {
        await client.query(`SET LOCAL ROLE ${role}`);
      }
      const res = await fn({
        query: async <TRow extends Record<string, unknown> = Record<string, unknown>>(
          sql: string,
          params: readonly unknown[] = []
        ) => client.query<TRow>(sql, [...params])
      });
      await client.query("COMMIT");
      return res;
    } catch (err) {
      await client.query("ROLLBACK").catch(() => undefined);
      throw mapPiSqlError(err);
    }
  };

  return {
    backend: "pg",
    async inTransaction<T>(fn: (tx: ProviderIngressSqlTxClient) => Promise<T>): Promise<T> {
      const client = await pool.connect();
      try {
        return await runOnClient(client, fn);
      } finally {
        client.release();
      }
    },
    async query<TRow extends Record<string, unknown> = Record<string, unknown>>(
      sql: string,
      params: readonly unknown[] = []
    ): Promise<ProviderIngressQueryResult<TRow>> {
      try {
        return await pool.query<TRow>(sql, [...params]);
      } catch (err) {
        throw mapPiSqlError(err);
      }
    },
    async exec(sql: string): Promise<void> {
      await pool.query(sql);
    },
    async close(): Promise<void> {
      if (ownsPool) {
        await pool.end();
      }
    }
  };
}

function mapBindingRow(row: Record<string, unknown>): ProviderBindingRecord {
  const provider = readReqString(row, "provider");
  const mode = readReqString(row, "account_mode");
  if (
    (provider !== "stripe" && provider !== "paystack" && provider !== "github") ||
    (mode !== "test" && mode !== "live")
  ) {
    throw new ProviderIngressDbError({
      code: "INTERNAL_ERROR",
      httpStatus: 500,
      message: `Invalid binding provider/mode in database: ${provider}/${mode}`
    });
  }
  return {
    id: parseCanonicalUuid(readReqString(row, "id"), "binding_id"),
    provider,
    accountReference: readReqString(row, "account_reference"),
    accountMode: mode,
    payloadProfile: readReqString(row, "payload_profile"),
    secretCustodyReference: readReqString(row, "secret_custody_reference"),
    secretVersionReference: readReqString(row, "secret_version_reference"),
    state: readReqString(row, "state"),
    relayTenantId: parseCanonicalUuid(readReqString(row, "relay_tenant_id"), "relay_tenant_id"),
    relayProjectId: parseCanonicalUuid(readReqString(row, "relay_project_id"), "relay_project_id"),
    publicationChannelId: parseCanonicalUuid(
      readReqString(row, "publication_channel_id"),
      "publication_channel_id"
    ),
    normalizedEventTypeId: parseCanonicalUuid(
      readReqString(row, "normalized_event_type_id"),
      "normalized_event_type_id"
    ),
    normalizedSchemaVersion: Number(readReqBigInt(row, "normalized_schema_version")),
    currentBindingVersion: readReqBigInt(row, "current_binding_version")
  };
}

export class ProviderIngressRepository {
  async findActiveBindingsByProvider(
    tx: ProviderIngressSqlTxClient,
    provider: ProviderKind,
    bindingId?: string
  ): Promise<readonly ProviderBindingRecord[]> {
    if (bindingId !== undefined) {
      const exact = await tx.query<Record<string, unknown>>(
        `SELECT id, provider, account_reference, account_mode, payload_profile,
                secret_custody_reference, secret_version_reference, state,
                relay_tenant_id, relay_project_id, publication_channel_id,
                normalized_event_type_id, normalized_schema_version, current_binding_version
           FROM pi.bindings
          WHERE id = $1::uuid
            AND provider = $2::text
            AND state = 'active'
            AND current_binding_version IS NOT NULL`,
        [parseCanonicalUuid(bindingId, "binding_id"), provider]
      );
      return exact.rows.map((r) => mapBindingRow(r));
    }

    const res = await tx.query<Record<string, unknown>>(
      `SELECT id, provider, account_reference, account_mode, payload_profile,
              secret_custody_reference, secret_version_reference, state,
              relay_tenant_id, relay_project_id, publication_channel_id,
              normalized_event_type_id, normalized_schema_version, current_binding_version
         FROM pi.bindings
        WHERE provider = $1::text
          AND state = 'active'
          AND current_binding_version IS NOT NULL
        ORDER BY created_at ASC`,
      [provider]
    );
    return res.rows.map((r) => mapBindingRow(r));
  }

  async receiveVerifiedCallback(
    tx: ProviderIngressSqlTxClient,
    params: ReceiveVerifiedCallbackParams
  ): Promise<ReceiveVerifiedCallbackResult> {
    const res = await tx.query<Record<string, unknown>>(
      `SELECT pi.cmd_receive_verified_callback(
         $1::uuid, $2::uuid, $3::uuid, $4::bigint,
         $5::text, $6::text, $7::text, $8::text, $9::text, $10::text, $11::timestamptz,
         $12::bytea, $13::text, $14::bytea, $15::jsonb, $16::bytea,
         $17::text, $18::text, $19::bytea, $20::bytea
       ) AS result`,
      [
        params.observationId,
        params.forwardIntentId,
        params.bindingId,
        params.bindingVersion.toString(10),
        params.provider,
        params.accountMode,
        params.payloadProfile,
        params.providerEventId,
        params.eventType,
        params.objectReference,
        params.providerBusinessTime,
        sha256HexToBuffer(params.rawBodySha256Hex, "raw_body_sha256"),
        params.identityProfile,
        sha256HexToBuffer(params.semanticKeySha256Hex, "semantic_key_sha256"),
        JSON.stringify(params.normalizedFacts),
        sha256HexToBuffer(params.normalizedFactsSha256Hex, "normalized_facts_sha256"),
        params.businessKey,
        params.requestKey,
        params.preparedBytes,
        sha256HexToBuffer(params.submissionSha256Hex, "submission_sha256")
      ]
    );
    const data = res.rows[0]?.["result"] as Record<string, unknown> | undefined;
    if (data === undefined) {
      throw new ProviderIngressDbError({
        code: "INTERNAL_ERROR",
        httpStatus: 500,
        message: "pi.cmd_receive_verified_callback returned no result"
      });
    }
    const rawOutcome = readReqString(data, "outcome");
    if (
      rawOutcome !== "accepted" &&
      rawOutcome !== "already_accepted_transport" &&
      rawOutcome !== "already_accepted_semantic"
    ) {
      throw new ProviderIngressDbError({
        code: "INTERNAL_ERROR",
        httpStatus: 500,
        message: `Unexpected callback receive outcome "${rawOutcome}"`
      });
    }
    const fwdId = readOptString(data, "forward_intent_id");
    return {
      outcome: rawOutcome,
      observationId: parseCanonicalUuid(readReqString(data, "observation_id"), "observation_id"),
      ...(fwdId !== undefined ? { forwardIntentId: parseCanonicalUuid(fwdId, "forward_intent_id") } : {}),
      bindingId: parseCanonicalUuid(readReqString(data, "binding_id"), "binding_id"),
      bindingVersion: readReqBigInt(data, "binding_version")
    };
  }

  async listDueForwardIntents(
    tx: ProviderIngressSqlTxClient,
    limit = 32
  ): Promise<readonly DueForwardIntentRecord[]> {
    const clamped = Math.max(1, Math.min(200, Math.trunc(limit)));
    const res = await tx.query<Record<string, unknown>>(
      `SELECT id, state, binding_id, next_attempt_at
         FROM pi.forward_intents
        WHERE (
          state IN ('ready', 'acceptance_unknown')
          AND next_attempt_at <= pg_catalog.clock_timestamp()
        ) OR (
          state = 'claimed'
          AND claim_expires_at <= pg_catalog.clock_timestamp()
        )
        ORDER BY next_attempt_at ASC, id ASC
        LIMIT $1::integer`,
      [clamped]
    );
    return res.rows.map((r) => {
      const state = readReqString(r, "state");
      return {
        intentId: parseCanonicalUuid(readReqString(r, "id"), "intent_id"),
        state:
          state === "acceptance_unknown"
            ? "acceptance_unknown"
            : state === "claimed"
              ? "claimed"
              : "ready",
        bindingId: parseCanonicalUuid(readReqString(r, "binding_id"), "binding_id"),
        nextAttemptAt: readReqTimestamp(r, "next_attempt_at")
      };
    });
  }

  async claimForwardIntent(
    tx: ProviderIngressSqlTxClient,
    params: {
      readonly intentId: string;
      readonly ownerInstanceId: string;
      readonly leaseMs?: bigint | undefined;
      readonly expectedPriorState?: "ready" | "claimed" | "acceptance_unknown" | undefined;
    }
  ): Promise<ClaimForwardIntentResult> {
    const priorRes = await tx.query<Record<string, unknown>>(
      `SELECT state FROM pi.forward_intents WHERE id = $1::uuid`,
      [params.intentId]
    );
    const priorRaw = priorRes.rows[0]?.["state"];
    const priorState: "ready" | "claimed" | "acceptance_unknown" =
      priorRaw === "acceptance_unknown"
        ? "acceptance_unknown"
        : priorRaw === "claimed"
          ? "claimed"
          : params.expectedPriorState ?? "ready";

    const leaseMs = (params.leaseMs ?? 30_000n).toString(10);
    const res = await tx.query<Record<string, unknown>>(
      `SELECT pi.cmd_forward_claim($1::uuid, $2::uuid, $3::bigint) AS result`,
      [params.intentId, params.ownerInstanceId, leaseMs]
    );
    const data = res.rows[0]?.["result"] as Record<string, unknown> | undefined;
    if (data === undefined) {
      throw new ProviderIngressDbError({
        code: "INTERNAL_ERROR",
        httpStatus: 500,
        message: "pi.cmd_forward_claim returned no result"
      });
    }
    const outcome = readReqString(data, "outcome");
    if (outcome === "already_accepted") {
      const ev = readOptString(data, "relay_event_id");
      const rc = readOptString(data, "relay_receipt_id");
      return {
        outcome: "already_accepted",
        intentId: parseCanonicalUuid(readReqString(data, "intent_id"), "intent_id"),
        ...(ev !== undefined ? { relayEventId: parseCanonicalUuid(ev, "relay_event_id") } : {}),
        ...(rc !== undefined ? { relayReceiptId: parseCanonicalUuid(rc, "relay_receipt_id") } : {})
      };
    }
    if (outcome === "not_eligible" || outcome === "already_claimed" || outcome === "not_due") {
      const st = readOptString(data, "state");
      return {
        outcome,
        ...(st !== undefined ? { state: st } : {})
      };
    }
    const b64 = readReqString(data, "prepared_bytes_base64");
    return {
      outcome: "claimed",
      intentId: parseCanonicalUuid(readReqString(data, "intent_id"), "intent_id"),
      observationId: parseCanonicalUuid(readReqString(data, "observation_id"), "observation_id"),
      bindingId: parseCanonicalUuid(readReqString(data, "binding_id"), "binding_id"),
      bindingVersion: readReqBigInt(data, "binding_version"),
      claimGeneration: readReqBigInt(data, "claim_generation"),
      claimExpiresAt: readReqTimestamp(data, "claim_expires_at"),
      businessKey: readReqString(data, "business_key"),
      requestKey: readReqString(data, "request_key"),
      preparedBytes: Buffer.from(b64, "base64"),
      priorState
    };
  }

  async finalizeForwardIntent(
    tx: ProviderIngressSqlTxClient,
    params: {
      readonly intentId: string;
      readonly ownerInstanceId: string;
      readonly expectedClaimGeneration: bigint;
      readonly outcome: ForwardFinalizeOutcome;
      readonly relayEventId?: string | null | undefined;
      readonly relayReceiptId?: string | null | undefined;
      readonly safeErrorCode?: string | null | undefined;
      readonly nextAttemptAt?: string | null | undefined;
    }
  ): Promise<FinalizeForwardIntentResult> {
    const res = await tx.query<Record<string, unknown>>(
      `SELECT pi.cmd_forward_finalize(
         $1::uuid, $2::uuid, $3::bigint, $4::text,
         $5::uuid, $6::uuid, $7::text, $8::timestamptz
       ) AS result`,
      [
        params.intentId,
        params.ownerInstanceId,
        params.expectedClaimGeneration.toString(10),
        params.outcome,
        params.relayEventId ?? null,
        params.relayReceiptId ?? null,
        params.safeErrorCode ?? null,
        params.nextAttemptAt ?? null
      ]
    );
    const data = res.rows[0]?.["result"] as Record<string, unknown> | undefined;
    if (data === undefined) {
      throw new ProviderIngressDbError({
        code: "INTERNAL_ERROR",
        httpStatus: 500,
        message: "pi.cmd_forward_finalize returned no result"
      });
    }
    const state = readOptString(data, "state");
    const ev = readOptString(data, "relay_event_id");
    const rc = readOptString(data, "relay_receipt_id");
    return {
      outcome: readReqString(data, "outcome"),
      intentId: parseCanonicalUuid(readReqString(data, "intent_id"), "intent_id"),
      ...(state !== undefined ? { state } : {}),
      ...(ev !== undefined ? { relayEventId: parseCanonicalUuid(ev, "relay_event_id") } : {}),
      ...(rc !== undefined ? { relayReceiptId: parseCanonicalUuid(rc, "relay_receipt_id") } : {})
    };
  }

  async inspectState(tx: ProviderIngressSqlTxClient): Promise<ProviderIngressStateSnapshot> {
    const bRes = await tx.query<Record<string, unknown>>(
      `SELECT id, provider, account_reference, account_mode, state, current_binding_version
         FROM pi.bindings
        ORDER BY created_at ASC`
    );
    const countsRes = await tx.query<Record<string, unknown>>(
      `SELECT
         (SELECT COUNT(*)::bigint FROM pi.observations) AS obs_cnt,
         (SELECT COUNT(*)::bigint FROM pi.transport_receipts) AS tr_cnt,
         (SELECT COUNT(*)::bigint FROM pi.semantic_identities) AS sem_cnt,
         (SELECT COUNT(*)::bigint FROM pi.audit_events) AS audit_cnt`
    );
    const fwdRes = await tx.query<Record<string, unknown>>(
      `SELECT id, observation_id, state, business_key, relay_event_id, safe_error_code
         FROM pi.forward_intents
        ORDER BY next_attempt_at ASC, id ASC`
    );
    const c = countsRes.rows[0] ?? {};
    return {
      bindings: bRes.rows.map((r) => ({
        id: readReqString(r, "id"),
        provider: readReqString(r, "provider") as ProviderKind,
        accountReference: readReqString(r, "account_reference"),
        accountMode: readReqString(r, "account_mode") as AccountMode,
        state: readReqString(r, "state"),
        currentBindingVersion:
          r["current_binding_version"] !== null && r["current_binding_version"] !== undefined
            ? readReqBigInt(r, "current_binding_version").toString(10)
            : "0"
      })),
      observationsCount: Number(readReqBigInt(c, "obs_cnt")),
      transportReceiptsCount: Number(readReqBigInt(c, "tr_cnt")),
      semanticIdentitiesCount: Number(readReqBigInt(c, "sem_cnt")),
      forwardIntents: fwdRes.rows.map((f) => {
        const relayEventId = readOptString(f, "relay_event_id");
        const safeErrorCode = readOptString(f, "safe_error_code");
        return {
          id: readReqString(f, "id"),
          observationId: readReqString(f, "observation_id"),
          state: readReqString(f, "state"),
          businessKey: readReqString(f, "business_key"),
          ...(relayEventId !== undefined ? { relayEventId } : {}),
          ...(safeErrorCode !== undefined ? { safeErrorCode } : {})
        };
      }),
      auditEventsCount: Number(readReqBigInt(c, "audit_cnt"))
    };
  }
}
