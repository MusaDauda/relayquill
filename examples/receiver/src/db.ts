import crypto from "node:crypto";
import type { Pool, PoolClient, PoolConfig } from "pg";
import {
  formatUtcTimestamp,
  nowUtcInstant,
  parseCanonicalUuid,
  parseEndpointId,
  parseEventId,
  parseKeyId,
  parseProjectId,
  parseSha256Hex
} from "@relayquill/domain";
import { parseCanonicalUtcTimestamp } from "@relayquill/contracts";
import {
  ReceiverConflictError,
  ReceiverSdkError,
  ReceiverValidationError,
  type CanonicalUtcTimestamp,
  type EndpointId,
  type EventId,
  type KeyId,
  type OrderingDomainId,
  type ProjectId,
  type ReceiverBusinessCommitAnchor,
  type ReceiverInboxAdapter,
  type ReceiverInboxTransactionContext,
  type ReceiverOrderHeadRecord,
  type ReceiverOrderPositionAnchor,
  type Sha256Hex,
  type VerifyDeliverySuccess
} from "@relayquill/receiver-sdk";

function createInternalError(message: string, cause?: unknown): ReceiverSdkError {
  return new ReceiverSdkError({
    code: "INTERNAL_ERROR",
    httpStatus: 500,
    retryable: false,
    message,
    ...(cause !== undefined ? { cause } : {})
  });
}

function toSdkProjectId(raw: string): ProjectId {
  const validated: string = parseProjectId(raw, "project_id");
  return validated as ProjectId;
}

function toSdkEndpointId(raw: string): EndpointId {
  const validated: string = parseEndpointId(raw, "endpoint_id");
  return validated as EndpointId;
}

function toSdkEventId(raw: string): EventId {
  const validated: string = parseEventId(raw, "event_id");
  return validated as EventId;
}

function toSdkKeyId(raw: string): KeyId {
  const validated: string = parseKeyId(raw, "key_id");
  return validated as KeyId;
}

function toSdkSha256Hex(raw: string, label = "sha256"): Sha256Hex {
  const validated: string = parseSha256Hex(raw, label);
  return validated as Sha256Hex;
}

function toSdkTimestamp(raw: string, label = "timestamp"): CanonicalUtcTimestamp {
  const validated: string = parseCanonicalUtcTimestamp(raw, label);
  return validated as CanonicalUtcTimestamp;
}

export interface ReceiverQueryResult<TRow extends Record<string, unknown> = Record<string, unknown>> {
  readonly rows: readonly TRow[];
  readonly rowCount?: number | null | undefined;
}

export interface ReceiverSqlTxClient {
  query<TRow extends Record<string, unknown> = Record<string, unknown>>(
    sql: string,
    params?: readonly unknown[]
  ): Promise<ReceiverQueryResult<TRow>>;
}

export interface PGliteCompatibleClient {
  readonly closed?: boolean | undefined;
  query<TRow = Record<string, unknown>>(
    sql: string,
    params?: unknown[]
  ): Promise<{ readonly rows: TRow[]; readonly rowCount?: number | undefined; readonly affectedRows?: number | undefined }>;
  exec?(sql: string): Promise<unknown>;
  transaction<T>(callback: (tx: ReceiverSqlTxClient) => Promise<T>): Promise<T>;
  close?(): Promise<void>;
}

export interface ReceiverDbClient {
  readonly backend: "pg" | "pglite";
  inTransaction<T>(fn: (tx: ReceiverSqlTxClient) => Promise<T>): Promise<T>;
  query<TRow extends Record<string, unknown> = Record<string, unknown>>(
    sql: string,
    params?: readonly unknown[]
  ): Promise<ReceiverQueryResult<TRow>>;
  exec(sql: string): Promise<void>;
  close(): Promise<void>;
}

export interface CreateReceiverDbOptions {
  readonly pool?: Pool | undefined;
  readonly poolConfig?: PoolConfig | undefined;
  readonly pglite?: PGliteCompatibleClient | undefined;
  readonly ownsClient?: boolean | undefined;
  readonly schema?: string | undefined;
  readonly role?: string | undefined;
  readonly applySetLocalRole?: boolean | undefined;
}

export interface ReceiverIntegrationRecord {
  readonly id: string;
  readonly relayProjectId: ProjectId;
  readonly endpointId: EndpointId;
  readonly consumerContractScope: string;
  readonly expectedExternalAuthority: string;
  readonly expectedRequestTarget: string;
  readonly configurationVersion: bigint;
  readonly receiverContractId: string;
  readonly receiverContractVersion: bigint;
  readonly state: string;
  readonly demoCounterId: string;
}

export interface ReceiverKeyMetadataRecord {
  readonly integrationId: string;
  readonly projectId: ProjectId;
  readonly endpointId: EndpointId;
  readonly keyId: KeyId;
  readonly custodyReference: string;
  readonly custodyVersionReference: string;
  readonly state: "pending" | "active" | "overlap" | "retired" | "revoked";
  readonly verifyUntil?: CanonicalUtcTimestamp | undefined;
}

export interface ReceiverStateSnapshot {
  readonly integrations: readonly {
    readonly id: string;
    readonly relayProjectId: string;
    readonly endpointId: string;
    readonly consumerContractScope: string;
    readonly expectedRequestTarget: string;
    readonly state: string;
    readonly counterValue: string;
  }[];
  readonly inboxCount: number;
  readonly businessMutationCount: number;
  readonly receiptCount: number;
  readonly orderHeads: readonly {
    readonly integrationId: string;
    readonly orderingDomainId: string;
    readonly orderingKeySha256: string;
    readonly nextExpectedSequence: string;
    readonly state: string;
  }[];
  readonly orderAcceptancesCount: number;
}

const SAFE_IDENT_REGEX = /^[a-z_][a-z0-9_]*$/;

function assertSafeIdent(ident: string, label: string): string {
  if (!SAFE_IDENT_REGEX.test(ident)) {
    throw new ReceiverValidationError({
      code: "INVALID_VALUE",
      message: `Unsafe SQL ${label}: "${ident}"`
    });
  }
  return ident;
}

export function sha256HexToBuffer(hex: Sha256Hex | string, label = "sha256"): Buffer {
  const normalized = parseSha256Hex(hex, label);
  return Buffer.from(normalized, "hex");
}

export function rawToSha256Hex(value: unknown, label = "sha256"): Sha256Hex {
  if (value instanceof Uint8Array) {
    return toSdkSha256Hex(Buffer.from(value).toString("hex"), label);
  }
  if (typeof value === "string") {
    const cleaned = value.startsWith("\\x") || value.startsWith("0x") ? value.slice(2) : value;
    return toSdkSha256Hex(cleaned, label);
  }
  throw createInternalError(`Expected bytea/hex at ${label}`);
}

function readReqString(row: Record<string, unknown>, col: string): string {
  const val = row[col];
  if (typeof val !== "string" || val.length === 0) {
    throw createInternalError(`Missing required string column "${col}"`);
  }
  return val;
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
  throw createInternalError(`Missing required integer column "${col}"`);
}

function readReqTimestamp(row: Record<string, unknown>, col: string): CanonicalUtcTimestamp {
  const val = row[col];
  if (val instanceof Date) {
    return toSdkTimestamp(val.toISOString(), col);
  }
  if (typeof val === "string") {
    return toSdkTimestamp(val, col);
  }
  return toSdkTimestamp(formatUtcTimestamp(nowUtcInstant()), col);
}

function readOptTimestamp(
  row: Record<string, unknown>,
  col: string
): CanonicalUtcTimestamp | undefined {
  const val = row[col];
  if (val === null || val === undefined) {
    return undefined;
  }
  if (val instanceof Date) {
    return toSdkTimestamp(val.toISOString(), col);
  }
  if (typeof val === "string" && val.length > 0) {
    return toSdkTimestamp(val, col);
  }
  return undefined;
}

function mapRcSqlError(err: unknown): Error {
  if (err instanceof ReceiverSdkError) {
    return err;
  }
  const rec = err as { readonly message?: unknown; readonly code?: unknown } | undefined;
  const msg = typeof rec?.message === "string" ? rec.message : String(err);
  const sqlstate = typeof rec?.code === "string" ? rec.code : undefined;

  if (msg.includes("CONSUMER_ORDER_GAP")) {
    return new ReceiverConflictError({
      code: "CONSUMER_ORDER_GAP",
      retryable: true,
      message: msg,
      cause: err
    });
  }
  if (msg.includes("ORIGINAL_EVENT_CONFLICT")) {
    return new ReceiverConflictError({
      code: "ORIGINAL_EVENT_CONFLICT",
      message: msg,
      cause: err
    });
  }
  if (msg.includes("CONSUMER_ORDER_POSITION_CONFLICT")) {
    return new ReceiverConflictError({
      code: "CONSUMER_ORDER_POSITION_CONFLICT",
      message: msg,
      cause: err
    });
  }
  if (sqlstate === "23505") {
    return new ReceiverConflictError({
      code: "IDEMPOTENCY_CONFLICT",
      message: msg,
      cause: err
    });
  }
  return createInternalError(msg, err);
}

export async function createReceiverDbClient(
  options: CreateReceiverDbOptions
): Promise<ReceiverDbClient> {
  const schema = assertSafeIdent(options.schema ?? "rc", "schema");
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
      async inTransaction<T>(fn: (tx: ReceiverSqlTxClient) => Promise<T>): Promise<T> {
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
          throw mapRcSqlError(err);
        }
      },
      async query<TRow extends Record<string, unknown> = Record<string, unknown>>(
        sql: string,
        params: readonly unknown[] = []
      ): Promise<ReceiverQueryResult<TRow>> {
        try {
          return await pglite.query<TRow>(sql, [...params]);
        } catch (err) {
          throw mapRcSqlError(err);
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
    throw new ReceiverValidationError({
      code: "INVALID_VALUE",
      message: "Either pglite, pool, or poolConfig must be provided to createReceiverDbClient"
    });
  }

  const runOnClient = async <T>(
    client: PoolClient,
    fn: (tx: ReceiverSqlTxClient) => Promise<T>
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
      throw mapRcSqlError(err);
    }
  };

  return {
    backend: "pg",
    async inTransaction<T>(fn: (tx: ReceiverSqlTxClient) => Promise<T>): Promise<T> {
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
    ): Promise<ReceiverQueryResult<TRow>> {
      try {
        return await pool.query<TRow>(sql, [...params]);
      } catch (err) {
        throw mapRcSqlError(err);
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

function mapIntegrationRow(row: Record<string, unknown>): ReceiverIntegrationRecord {
  return {
    id: parseCanonicalUuid(readReqString(row, "id"), "integration_id"),
    relayProjectId: toSdkProjectId(readReqString(row, "relay_project_id")),
    endpointId: toSdkEndpointId(readReqString(row, "endpoint_id")),
    consumerContractScope: readReqString(row, "consumer_contract_scope"),
    expectedExternalAuthority: readReqString(row, "expected_external_authority"),
    expectedRequestTarget: readReqString(row, "expected_request_target"),
    configurationVersion: readReqBigInt(row, "configuration_version"),
    receiverContractId: parseCanonicalUuid(
      readReqString(row, "receiver_contract_id"),
      "receiver_contract_id"
    ),
    receiverContractVersion: readReqBigInt(row, "receiver_contract_version"),
    state: readReqString(row, "state"),
    demoCounterId: parseCanonicalUuid(readReqString(row, "demo_counter_id"), "demo_counter_id")
  };
}

export class ReceiverRepository {
  async findIntegrationByRequest(
    tx: ReceiverSqlTxClient,
    params: {
      readonly requestTarget: string;
      readonly projectId?: ProjectId | undefined;
      readonly endpointId?: EndpointId | undefined;
      readonly consumerContractScope?: string | undefined;
    }
  ): Promise<ReceiverIntegrationRecord | undefined> {
    if (
      params.projectId !== undefined &&
      params.endpointId !== undefined &&
      params.consumerContractScope !== undefined
    ) {
      const exactRes = await tx.query<Record<string, unknown>>(
        `SELECT id, relay_project_id, endpoint_id, consumer_contract_scope,
                expected_external_authority, expected_request_target, configuration_version,
                receiver_contract_id, receiver_contract_version, state, demo_counter_id
           FROM rc.integrations
          WHERE relay_project_id = $1::uuid
            AND endpoint_id = $2::uuid
            AND consumer_contract_scope = $3::text
            AND state = 'active'
          LIMIT 1`,
        [params.projectId, params.endpointId, params.consumerContractScope]
      );
      if (exactRes.rows[0] !== undefined) {
        return mapIntegrationRow(exactRes.rows[0]);
      }
    }

    const res = await tx.query<Record<string, unknown>>(
      `SELECT id, relay_project_id, endpoint_id, consumer_contract_scope,
              expected_external_authority, expected_request_target, configuration_version,
              receiver_contract_id, receiver_contract_version, state, demo_counter_id
         FROM rc.integrations
        WHERE state = 'active'
          AND expected_request_target = $1::text
        ORDER BY created_at ASC
        LIMIT 1`,
      [params.requestTarget]
    );
    const row = res.rows[0];
    return row !== undefined ? mapIntegrationRow(row) : undefined;
  }

  async findAllowedEndpointVersions(
    tx: ReceiverSqlTxClient,
    integrationId: string
  ): Promise<ReadonlySet<string>> {
    const res = await tx.query<Record<string, unknown>>(
      `SELECT endpoint_version::text AS ep_ver
         FROM rc.allowed_endpoint_versions
        WHERE integration_id = $1::uuid
          AND state IN ('active', 'pending')
          AND (verify_until IS NULL OR verify_until > pg_catalog.clock_timestamp())`,
      [integrationId]
    );
    const out = new Set<string>();
    for (const row of res.rows) {
      out.add(readReqString(row, "ep_ver"));
    }
    return out;
  }

  async findKeyMetadata(
    tx: ReceiverSqlTxClient,
    params: {
      readonly projectId: ProjectId;
      readonly endpointId: EndpointId;
      readonly keyId: KeyId;
    }
  ): Promise<ReceiverKeyMetadataRecord | undefined> {
    const res = await tx.query<Record<string, unknown>>(
      `SELECT km.integration_id, i.relay_project_id, i.endpoint_id, km.key_id,
              km.custody_reference, km.custody_version_reference, km.state, km.verify_until
         FROM rc.key_metadata km
         JOIN rc.integrations i ON i.id = km.integration_id
        WHERE i.relay_project_id = $1::uuid
          AND i.endpoint_id = $2::uuid
          AND km.key_id = $3::text
          AND i.state = 'active'
        LIMIT 1`,
      [params.projectId, params.endpointId, params.keyId]
    );
    const row = res.rows[0];
    if (row === undefined) {
      return undefined;
    }
    const rawState = readReqString(row, "state");
    if (
      rawState !== "pending" &&
      rawState !== "active" &&
      rawState !== "overlap" &&
      rawState !== "retired" &&
      rawState !== "revoked"
    ) {
      return undefined;
    }
    const verifyUntil = readOptTimestamp(row, "verify_until");
    return {
      integrationId: parseCanonicalUuid(readReqString(row, "integration_id"), "integration_id"),
      projectId: toSdkProjectId(readReqString(row, "relay_project_id")),
      endpointId: toSdkEndpointId(readReqString(row, "endpoint_id")),
      keyId: toSdkKeyId(readReqString(row, "key_id")),
      custodyReference: readReqString(row, "custody_reference"),
      custodyVersionReference: readReqString(row, "custody_version_reference"),
      state: rawState,
      ...(verifyUntil !== undefined ? { verifyUntil } : {})
    };
  }

  async getInboxBusinessAnchor(
    tx: ReceiverSqlTxClient,
    integrationId: string,
    projectId: ProjectId,
    consumerEventKey: Sha256Hex
  ): Promise<{ readonly anchor: ReceiverBusinessCommitAnchor; readonly receiptId: string } | null> {
    const res = await tx.query<Record<string, unknown>>(
      `SELECT i.event_id, i.original_facts_sha256, i.receipt_id, r.committed_at
         FROM rc.inbox i
         JOIN rc.receipts r ON r.id = i.receipt_id
        WHERE i.integration_id = $1::uuid
          AND i.consumer_event_key_sha256 = $2::bytea
        LIMIT 1`,
      [integrationId, sha256HexToBuffer(consumerEventKey, "consumer_event_key")]
    );
    const row = res.rows[0];
    if (row === undefined) {
      return null;
    }
    const receiptId = parseCanonicalUuid(readReqString(row, "receipt_id"), "receipt_id");
    return {
      receiptId,
      anchor: {
        projectId,
        consumerEventKey,
        eventId: toSdkEventId(readReqString(row, "event_id")),
        originalFactsSha256: rawToSha256Hex(row["original_facts_sha256"], "original_facts_sha256"),
        committedAt: readReqTimestamp(row, "committed_at")
      }
    };
  }

  async getOrderHead(
    tx: ReceiverSqlTxClient,
    integrationId: string,
    orderingDomainId: OrderingDomainId,
    orderingKeySha256: Sha256Hex
  ): Promise<ReceiverOrderHeadRecord | null> {
    const res = await tx.query<Record<string, unknown>>(
      `SELECT next_expected_sequence, state
         FROM rc.order_heads
        WHERE integration_id = $1::uuid
          AND ordering_domain_id = $2::uuid
          AND ordering_key_sha256 = $3::bytea
        LIMIT 1`,
      [integrationId, orderingDomainId, sha256HexToBuffer(orderingKeySha256, "ordering_key")]
    );
    const row = res.rows[0];
    if (row === undefined) {
      return null;
    }
    const state = readReqString(row, "state");
    return {
      headState: state === "held" ? "held" : "active",
      nextExpectedSequence: readReqBigInt(row, "next_expected_sequence")
    };
  }

  async getOrderPositionAnchor(
    tx: ReceiverSqlTxClient,
    integrationId: string,
    orderingDomainId: OrderingDomainId,
    orderingKeySha256: Sha256Hex,
    sequence: bigint
  ): Promise<{ readonly anchor: ReceiverOrderPositionAnchor; readonly receiptId: string } | null> {
    const res = await tx.query<Record<string, unknown>>(
      `SELECT consumer_event_key_sha256, original_facts_sha256, accepted_at, receipt_id
         FROM rc.order_acceptances
        WHERE integration_id = $1::uuid
          AND ordering_domain_id = $2::uuid
          AND ordering_key_sha256 = $3::bytea
          AND ordering_sequence = $4::bigint
        LIMIT 1`,
      [
        integrationId,
        orderingDomainId,
        sha256HexToBuffer(orderingKeySha256, "ordering_key"),
        sequence.toString(10)
      ]
    );
    const row = res.rows[0];
    if (row === undefined) {
      return null;
    }
    return {
      receiptId: parseCanonicalUuid(readReqString(row, "receipt_id"), "receipt_id"),
      anchor: {
        consumerEventKey: rawToSha256Hex(row["consumer_event_key_sha256"], "consumer_key"),
        originalFactsSha256: rawToSha256Hex(row["original_facts_sha256"], "original_facts"),
        committedAt: readReqTimestamp(row, "accepted_at")
      }
    };
  }

  async callProcessDeliveryProc(
    tx: ReceiverSqlTxClient,
    params: {
      readonly integrationId: string;
      readonly delivery: VerifyDeliverySuccess;
      readonly receiptId: string;
      readonly mutationId: string;
    }
  ): Promise<{
    readonly outcome: string;
    readonly receiptId: string;
    readonly committedAt: CanonicalUtcTimestamp;
    readonly counterValue: bigint;
    readonly nextExpectedSequence?: bigint | undefined;
  }> {
    const { delivery } = params;
    const { headers, decodedEnvelope, bodySha256, verifiedKeyId } = delivery;
    const env = decodedEnvelope.envelope;
    const repVersion = env.representation_version;
    const derived = env.envelope_version === 2 ? env.derived : undefined;
    const profileId = derived !== undefined ? derived.profile_id : null;
    const profileVersion = derived !== undefined ? derived.profile_version : null;
    const targetSchemaVersion =
      derived !== undefined ? derived.target_event_schema_version : null;

    if (headers.ordering === undefined) {
      const res = await tx.query<Record<string, unknown>>(
        `SELECT rc.cmd_process_unordered_delivery(
           $1::uuid, $2::bytea, $3::uuid, $4::uuid, $5::bytea, $6::bytea,
           $7::uuid, $8::integer, $9::integer, $10::bytea, $11::uuid, $12::bigint,
           $13::text, $14::uuid, $15::bigint, $16::integer, $17::uuid, $18::uuid
         ) AS result`,
        [
          params.integrationId,
          sha256HexToBuffer(headers.consumer_key, "consumer_key"),
          headers.project_id,
          headers.event_id,
          sha256HexToBuffer(decodedEnvelope.original_facts_sha256, "original_facts"),
          sha256HexToBuffer(env.content.sha256, "content_sha256"),
          env.event_type_id,
          env.event_schema_version,
          repVersion,
          sha256HexToBuffer(bodySha256, "wire_sha256"),
          headers.attempt_id,
          headers.endpoint_version,
          verifiedKeyId,
          profileId,
          profileVersion,
          targetSchemaVersion,
          params.receiptId,
          params.mutationId
        ]
      );
      const data = res.rows[0]?.["result"] as Record<string, unknown> | undefined;
      if (data === undefined) {
        throw createInternalError("rc.cmd_process_unordered_delivery returned no result");
      }
      return {
        outcome: readReqString(data, "outcome"),
        receiptId: parseCanonicalUuid(readReqString(data, "receipt_id"), "receipt_id"),
        committedAt: readReqTimestamp(data, "committed_at"),
        counterValue: readReqBigInt(data, "counter_value")
      };
    }

    const res = await tx.query<Record<string, unknown>>(
      `SELECT rc.cmd_process_strict_ordered_delivery(
         $1::uuid, $2::uuid, $3::bytea, $4::bigint,
         $5::bytea, $6::uuid, $7::uuid, $8::bytea, $9::bytea,
         $10::uuid, $11::integer, $12::integer, $13::bytea, $14::uuid, $15::bigint,
         $16::text, $17::uuid, $18::bigint, $19::integer, $20::uuid, $21::uuid
       ) AS result`,
      [
        params.integrationId,
        headers.ordering.ordering_domain_id,
        sha256HexToBuffer(headers.ordering.ordering_key_sha256, "ordering_key"),
        headers.ordering.ordering_sequence,
        sha256HexToBuffer(headers.consumer_key, "consumer_key"),
        headers.project_id,
        headers.event_id,
        sha256HexToBuffer(decodedEnvelope.original_facts_sha256, "original_facts"),
        sha256HexToBuffer(env.content.sha256, "content_sha256"),
        env.event_type_id,
        env.event_schema_version,
        repVersion,
        sha256HexToBuffer(bodySha256, "wire_sha256"),
        headers.attempt_id,
        headers.endpoint_version,
        verifiedKeyId,
        profileId,
        profileVersion,
        targetSchemaVersion,
        params.receiptId,
        params.mutationId
      ]
    );
    const data = res.rows[0]?.["result"] as Record<string, unknown> | undefined;
    if (data === undefined) {
      throw createInternalError("rc.cmd_process_strict_ordered_delivery returned no result");
    }
    return {
      outcome: readReqString(data, "outcome"),
      receiptId: parseCanonicalUuid(readReqString(data, "receipt_id"), "receipt_id"),
      committedAt: readReqTimestamp(data, "committed_at"),
      counterValue: readReqBigInt(data, "counter_value"),
      ...(data["next_expected_sequence"] !== undefined && data["next_expected_sequence"] !== null
        ? { nextExpectedSequence: readReqBigInt(data, "next_expected_sequence") }
        : {})
    };
  }

  async inspectState(tx: ReceiverSqlTxClient): Promise<ReceiverStateSnapshot> {
    const intRes = await tx.query<Record<string, unknown>>(
      `SELECT i.id, i.relay_project_id, i.endpoint_id, i.consumer_contract_scope,
              i.expected_request_target, i.state, dc.value AS counter_value
         FROM rc.integrations i
         JOIN rc.demo_counters dc ON dc.id = i.demo_counter_id
        ORDER BY i.created_at ASC`
    );
    const countsRes = await tx.query<Record<string, unknown>>(
      `SELECT
         (SELECT COUNT(*)::bigint FROM rc.inbox) AS inbox_count,
         (SELECT COUNT(*)::bigint FROM rc.business_mutations) AS business_mutation_count,
         (SELECT COUNT(*)::bigint FROM rc.receipts) AS receipt_count,
         (SELECT COUNT(*)::bigint FROM rc.order_acceptances) AS order_acceptances_count`
    );
    const headsRes = await tx.query<Record<string, unknown>>(
      `SELECT integration_id, ordering_domain_id, ordering_key_sha256, next_expected_sequence, state
         FROM rc.order_heads
        ORDER BY integration_id ASC, ordering_domain_id ASC`
    );

    const counts = countsRes.rows[0] ?? {};
    return {
      integrations: intRes.rows.map((r) => ({
        id: readReqString(r, "id"),
        relayProjectId: readReqString(r, "relay_project_id"),
        endpointId: readReqString(r, "endpoint_id"),
        consumerContractScope: readReqString(r, "consumer_contract_scope"),
        expectedRequestTarget: readReqString(r, "expected_request_target"),
        state: readReqString(r, "state"),
        counterValue: readReqBigInt(r, "counter_value").toString(10)
      })),
      inboxCount: Number(readReqBigInt(counts, "inbox_count")),
      businessMutationCount: Number(readReqBigInt(counts, "business_mutation_count")),
      receiptCount: Number(readReqBigInt(counts, "receipt_count")),
      orderHeads: headsRes.rows.map((h) => ({
        integrationId: readReqString(h, "integration_id"),
        orderingDomainId: readReqString(h, "ordering_domain_id"),
        orderingKeySha256: rawToSha256Hex(h["ordering_key_sha256"], "ordering_key_sha256"),
        nextExpectedSequence: readReqBigInt(h, "next_expected_sequence").toString(10),
        state: readReqString(h, "state")
      })),
      orderAcceptancesCount: Number(readReqBigInt(counts, "order_acceptances_count"))
    };
  }
}

export interface BoundDeliveryCommitInfo {
  readonly receiptId: string;
  readonly committedAt: CanonicalUtcTimestamp;
  readonly counterValue?: bigint | undefined;
  readonly outcome?: string | undefined;
}

/**
 * Bridges `@relayquill/receiver-sdk`'s `ReceiverInboxAdapter` with the independent
 * `rc.*` PostgreSQL stored procedures (`cmd_process_unordered_delivery` and
 * `cmd_process_strict_ordered_delivery`) inside a single ACID transaction.
 */
export function createPgDeliveryExecutionScope(params: {
  readonly db: ReceiverDbClient;
  readonly repo: ReceiverRepository;
  readonly integrationId: string;
  readonly verifiedDelivery: VerifyDeliverySuccess;
}): {
  readonly inbox: ReceiverInboxAdapter;
  readonly onBusinessMutation: () => Promise<void>;
  readonly getCommitInfo: () => BoundDeliveryCommitInfo;
} {
  let activeTx: ReceiverSqlTxClient | undefined;
  let procExecuted = false;
  let commitInfo: BoundDeliveryCommitInfo = {
    receiptId: crypto.randomUUID(),
    committedAt: toSdkTimestamp(formatUtcTimestamp(nowUtcInstant()), "committedAt")
  };

  const executeProc = async (tx: ReceiverSqlTxClient): Promise<void> => {
    const out = await params.repo.callProcessDeliveryProc(tx, {
      integrationId: params.integrationId,
      delivery: params.verifiedDelivery,
      receiptId: commitInfo.receiptId,
      mutationId: crypto.randomUUID()
    });
    procExecuted = true;
    commitInfo = {
      receiptId: out.receiptId,
      committedAt: out.committedAt,
      counterValue: out.counterValue,
      outcome: out.outcome
    };
  };

  const inbox: ReceiverInboxAdapter = {
    async runInTransaction<T>(fn: (tx: ReceiverInboxTransactionContext) => Promise<T>): Promise<T> {
      return params.db.inTransaction(async (tx) => {
        activeTx = tx;
        try {
          const ctx: ReceiverInboxTransactionContext = {
            async getBusinessAnchor(projectId, consumerEventKey) {
              const found = await params.repo.getInboxBusinessAnchor(
                tx,
                params.integrationId,
                projectId,
                consumerEventKey
              );
              if (found !== null) {
                commitInfo = {
                  receiptId: found.receiptId,
                  committedAt: found.anchor.committedAt
                };
                return found.anchor;
              }
              return null;
            },
            async saveBusinessAnchor() {
              // Persisted atomically in onBusinessMutation via rc.cmd_process_*.
            },
            async getOrderHead(_projectId, orderingDomainId, orderingKeySha256) {
              return params.repo.getOrderHead(
                tx,
                params.integrationId,
                orderingDomainId,
                orderingKeySha256
              );
            },
            async saveOrderHead() {
              // Persisted atomically via rc.cmd_process_strict_ordered_delivery.
            },
            async getOrderPositionAnchor(_projectId, orderingDomainId, orderingKeySha256, sequence) {
              const found = await params.repo.getOrderPositionAnchor(
                tx,
                params.integrationId,
                orderingDomainId,
                orderingKeySha256,
                sequence
              );
              if (found !== null) {
                commitInfo = {
                  receiptId: found.receiptId,
                  committedAt: found.anchor.committedAt
                };
                return found.anchor;
              }
              return null;
            },
            async saveOrderPositionAnchor() {
              // On replay_append, executeIdempotentDelivery skips onBusinessMutation and calls
              // saveOrderPositionAnchor; execute the strict-ordered proc now so order_heads
              // and order_acceptances advance atomically without re-incrementing demo_counters.
              if (!procExecuted) {
                await executeProc(tx);
              }
            }
          };

          return await fn(ctx);
        } finally {
          activeTx = undefined;
        }
      });
    }
  };

  return {
    inbox,
    async onBusinessMutation(): Promise<void> {
      if (activeTx === undefined) {
        throw createInternalError("onBusinessMutation invoked outside active receiver transaction");
      }
      await executeProc(activeTx);
    },
    getCommitInfo(): BoundDeliveryCommitInfo {
      return commitInfo;
    }
  };
}
