import crypto from "node:crypto";
import net from "node:net";
import tls from "node:tls";
import {
  isPaidDeliveryAllowed,
  LimitExceededDomainError,
  PLAN_CATALOG,
  type BilledReason,
  type CapMode,
  type EntitlementState,
  type PlanTier,
  type TenantId
} from "@relayquill/domain";
import { withTenantRlsTransaction, type PgAdapter, type PgTransactionClient } from "@relayquill/postgres";

export interface QuotaRedisClient {
  evalQuotaCheck(input: {
    readonly quotaKey: string;
    readonly spikeKey: string;
    readonly requestedUnits: number;
    readonly limitUnits: number;
    readonly enforceHardCap: boolean;
    readonly quotaTtlSeconds: number;
    readonly spikeTtlSeconds: number;
  }): Promise<{
    readonly allowed: boolean;
    readonly usedUnits: number;
    readonly priorUsedUnits: number;
    readonly hourlyUnits: number;
  }>;
  close(): Promise<void>;
}

const QUOTA_CHECK_LUA = `
local current = tonumber(redis.call("GET", KEYS[1]) or "0")
local req = tonumber(ARGV[1])
local limit = tonumber(ARGV[2])
local enforce = tonumber(ARGV[3])
local quota_ttl = tonumber(ARGV[4])
local spike_ttl = tonumber(ARGV[5])
local next_used = current + req
if enforce == 1 and next_used > limit then
  return {0, current, current, tonumber(redis.call("GET", KEYS[2]) or "0")}
end
redis.call("INCRBY", KEYS[1], req)
if redis.call("TTL", KEYS[1]) < 0 then
  redis.call("EXPIRE", KEYS[1], quota_ttl)
end
local hourly = redis.call("INCRBY", KEYS[2], req)
if redis.call("TTL", KEYS[2]) < 0 then
  redis.call("EXPIRE", KEYS[2], spike_ttl)
end
return {1, next_used, current, hourly}
`.trim();

/**
 * Deterministic in-memory quota counter mirroring the exact atomic Redis Lua contract for tests & dev mode.
 */
export class InMemoryQuotaRedisClient implements QuotaRedisClient {
  readonly #counters = new Map<string, number>();

  evalQuotaCheck(input: {
    readonly quotaKey: string;
    readonly spikeKey: string;
    readonly requestedUnits: number;
    readonly limitUnits: number;
    readonly enforceHardCap: boolean;
    readonly quotaTtlSeconds: number;
    readonly spikeTtlSeconds: number;
  }): Promise<{
    readonly allowed: boolean;
    readonly usedUnits: number;
    readonly priorUsedUnits: number;
    readonly hourlyUnits: number;
  }> {
    void input.quotaTtlSeconds;
    void input.spikeTtlSeconds;
    const prior = this.#counters.get(input.quotaKey) ?? 0;
    const nextUsed = prior + input.requestedUnits;
    const currentHourly = this.#counters.get(input.spikeKey) ?? 0;
    if (input.enforceHardCap && nextUsed > input.limitUnits) {
      return Promise.resolve({
        allowed: false,
        usedUnits: prior,
        priorUsedUnits: prior,
        hourlyUnits: currentHourly
      });
    }
    this.#counters.set(input.quotaKey, nextUsed);
    const nextHourly = currentHourly + input.requestedUnits;
    this.#counters.set(input.spikeKey, nextHourly);
    return Promise.resolve({
      allowed: true,
      usedUnits: nextUsed,
      priorUsedUnits: prior,
      hourlyUnits: nextHourly
    });
  }

  seedUsage(quotaKey: string, units: number): void {
    this.#counters.set(quotaKey, Math.max(0, Math.trunc(units)));
  }

  close(): Promise<void> {
    this.#counters.clear();
    return Promise.resolve();
  }
}

interface RespPendingCall {
  readonly resolve: (val: unknown) => void;
  readonly reject: (err: Error) => void;
  readonly timer: ReturnType<typeof setTimeout>;
}

function encodeRespCommand(parts: readonly (string | number)[]): Buffer {
  const chunks: Buffer[] = [Buffer.from(`*${parts.length}\r\n`, "utf8")];
  for (const part of parts) {
    const buf = Buffer.from(String(part), "utf8");
    chunks.push(Buffer.from(`$${buf.byteLength}\r\n`, "utf8"), buf, Buffer.from("\r\n", "utf8"));
  }
  return Buffer.concat(chunks);
}

function tryDecodeResp(
  buffer: Buffer,
  offset = 0
): { readonly value: unknown; readonly nextOffset: number } | null {
  if (offset >= buffer.byteLength) {
    return null;
  }
  const crlf = buffer.indexOf("\r\n", offset);
  if (crlf === -1) {
    return null;
  }
  const prefix = String.fromCharCode(buffer[offset]!);
  const line = buffer.subarray(offset + 1, crlf).toString("utf8");

  if (prefix === "+" || prefix === ":") {
    return { value: prefix === ":" ? Number(line) : line, nextOffset: crlf + 2 };
  }
  if (prefix === "-") {
    return { value: new Error(line), nextOffset: crlf + 2 };
  }
  if (prefix === "$") {
    const len = Number.parseInt(line, 10);
    if (len === -1) {
      return { value: null, nextOffset: crlf + 2 };
    }
    const endIdx = crlf + 2 + len;
    if (buffer.byteLength < endIdx + 2) {
      return null;
    }
    return { value: buffer.subarray(crlf + 2, endIdx).toString("utf8"), nextOffset: endIdx + 2 };
  }
  if (prefix === "*") {
    const count = Number.parseInt(line, 10);
    if (count === -1) {
      return { value: null, nextOffset: crlf + 2 };
    }
    const arr: unknown[] = [];
    let cursor = crlf + 2;
    for (let i = 0; i < count; i += 1) {
      const item = tryDecodeResp(buffer, cursor);
      if (item === null) {
        return null;
      }
      arr.push(item.value);
      cursor = item.nextOffset;
    }
    return { value: arr, nextOffset: cursor };
  }
  return null;
}

/**
 * Multiplexed RESP2 Redis client using one persistent socket with command timeouts (no connect-per-request).
 */
export class TcpRespQuotaRedisClient implements QuotaRedisClient {
  readonly #url: URL;
  readonly #timeoutMs: number;
  #socket: net.Socket | tls.TLSSocket | null = null;
  #connecting: Promise<net.Socket | tls.TLSSocket> | null = null;
  #recvBuf: Buffer = Buffer.alloc(0);
  readonly #pending: RespPendingCall[] = [];
  #closed = false;

  constructor(redisUrl: string, timeoutMs = 1500) {
    this.#url = new URL(redisUrl);
    this.#timeoutMs = Math.max(250, timeoutMs);
  }

  async evalQuotaCheck(input: {
    readonly quotaKey: string;
    readonly spikeKey: string;
    readonly requestedUnits: number;
    readonly limitUnits: number;
    readonly enforceHardCap: boolean;
    readonly quotaTtlSeconds: number;
    readonly spikeTtlSeconds: number;
  }) {
    const result = await this.#send([
      "EVAL",
      QUOTA_CHECK_LUA,
      2,
      input.quotaKey,
      input.spikeKey,
      input.requestedUnits,
      input.limitUnits,
      input.enforceHardCap ? 1 : 0,
      input.quotaTtlSeconds,
      input.spikeTtlSeconds
    ]);
    const tuple = Array.isArray(result) ? result : [];
    return {
      allowed: Number(tuple[0] ?? 0) === 1,
      usedUnits: Number(tuple[1] ?? 0),
      priorUsedUnits: Number(tuple[2] ?? 0),
      hourlyUnits: Number(tuple[3] ?? 0)
    };
  }

  async close(): Promise<void> {
    this.#closed = true;
    const sock = this.#socket;
    this.#socket = null;
    while (this.#pending.length > 0) {
      const p = this.#pending.shift()!;
      clearTimeout(p.timer);
      p.reject(new Error("Redis client closed"));
    }
    if (sock !== null) {
      sock.destroy();
    }
    await Promise.resolve();
  }

  async #ensureConnected(): Promise<net.Socket | tls.TLSSocket> {
    if (this.#closed) {
      throw new Error("Redis client is closed");
    }
    if (this.#socket !== null && !this.#socket.destroyed) {
      return this.#socket;
    }
    if (this.#connecting !== null) {
      return this.#connecting;
    }
    this.#connecting = new Promise((resolve, reject) => {
      const host = this.#url.hostname || "127.0.0.1";
      const port = Number(this.#url.port || (this.#url.protocol === "rediss:" ? 6380 : 6379));
      const sock =
        this.#url.protocol === "rediss:"
          ? tls.connect({ host, port, rejectUnauthorized: true })
          : net.createConnection({ host, port });

      const onError = (err: Error): void => {
        sock.destroy();
        this.#connecting = null;
        reject(err);
      };
      sock.once("error", onError);
      sock.once("connect", () => {
        sock.off("error", onError);
        sock.setNoDelay(true);
        sock.on("data", (chunk: Buffer) => this.#onData(chunk));
        sock.on("close", () => this.#onClose());
        sock.on("error", () => this.#onClose());
        this.#socket = sock;
        this.#connecting = null;
        const password = decodeURIComponent(this.#url.password || "");
        const username = decodeURIComponent(this.#url.username || "");
        if (password.length > 0) {
          const authArgs = username.length > 0 ? ["AUTH", username, password] : ["AUTH", password];
          void this.#writeRaw(sock, authArgs)
            .then(() => resolve(sock))
            .catch(reject);
        } else {
          resolve(sock);
        }
      });
    });
    return this.#connecting;
  }

  #onData(chunk: Buffer): void {
    this.#recvBuf = Buffer.concat([this.#recvBuf, chunk]);
    while (this.#pending.length > 0) {
      const decoded = tryDecodeResp(this.#recvBuf, 0);
      if (decoded === null) {
        break;
      }
      this.#recvBuf = this.#recvBuf.subarray(decoded.nextOffset);
      const call = this.#pending.shift()!;
      clearTimeout(call.timer);
      if (decoded.value instanceof Error) {
        call.reject(decoded.value);
      } else {
        call.resolve(decoded.value);
      }
    }
  }

  #onClose(): void {
    this.#socket = null;
    this.#recvBuf = Buffer.alloc(0);
    while (this.#pending.length > 0) {
      const p = this.#pending.shift()!;
      clearTimeout(p.timer);
      p.reject(new Error("Redis connection closed"));
    }
  }

  async #send(args: readonly (string | number)[]): Promise<unknown> {
    const sock = await this.#ensureConnected();
    return this.#writeRaw(sock, args);
  }

  #writeRaw(sock: net.Socket | tls.TLSSocket, args: readonly (string | number)[]): Promise<unknown> {
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        const idx = this.#pending.findIndex((p) => p.resolve === resolve);
        if (idx !== -1) {
          this.#pending.splice(idx, 1);
        }
        reject(new Error("Redis command timeout"));
      }, this.#timeoutMs);
      this.#pending.push({ resolve, reject, timer });
      sock.write(encodeRespCommand(args));
    });
  }
}

export interface EvaluateQuotaGuardInput {
  readonly pgAdapter: PgAdapter;
  readonly redis: QuotaRedisClient;
  readonly orgId: TenantId;
  readonly idempotencyKey: string;
  readonly metricCode?: "outbound_deliveries" | "replay_deliveries" | undefined;
  readonly requestedUnits?: number | undefined;
  readonly isIdempotentReplay?: boolean | undefined;
  readonly now?: Date | undefined;
  readonly cogsMicros?: number | undefined;
}

export interface EvaluateQuotaGuardResult {
  readonly allowed: boolean;
  readonly planTier: PlanTier;
  readonly entitlementState: EntitlementState;
  readonly capMode: CapMode;
  readonly usedUnitsMonth: number;
  readonly includedUnitsMonth: number;
  readonly billableUnits: number;
  readonly billedReason: BilledReason;
  readonly alertsQueued: readonly string[];
  readonly redisDegradedFallback: boolean;
}

function formatYearMonth(date: Date): string {
  return `${date.getUTCFullYear()}-${String(date.getUTCMonth() + 1).padStart(2, "0")}`;
}

function formatHourBucket(date: Date): string {
  return `${date.getUTCFullYear()}${String(date.getUTCMonth() + 1).padStart(2, "0")}${String(date.getUTCDate()).padStart(2, "0")}${String(date.getUTCHours()).padStart(2, "0")}`;
}

async function queueThresholdEmailIfNeeded(
  tx: PgTransactionClient,
  input: {
    readonly orgId: TenantId;
    readonly metricCode: string;
    readonly periodMonth: string;
    readonly hourBucket: string;
    readonly priorUsed: number;
    readonly nextUsed: number;
    readonly includedUnits: number;
    readonly hourlyUnits: number;
  }
): Promise<readonly string[]> {
  if (input.includedUnits <= 0) {
    return [];
  }
  const queued: string[] = [];
  const recipientRes = await tx.query<{ billing_email: unknown }>(
    `SELECT billing_email FROM rq.billing_customers WHERE org_id = $1::uuid`,
    [input.orgId]
  );
  const recipientEmail =
    typeof recipientRes.rows[0]?.billing_email === "string"
      ? recipientRes.rows[0].billing_email
      : null;
  if (recipientEmail === null) {
    return [];
  }

  const thresholds = [
    { pct: 0.7, code: "quota_alert_70", col: "alert_70_sent_at" },
    { pct: 0.85, code: "quota_alert_85", col: "alert_85_sent_at" },
    { pct: 0.95, code: "quota_alert_95", col: "alert_95_sent_at" }
  ] as const;

  for (const t of thresholds) {
    const thresholdUnits = Math.ceil(input.includedUnits * t.pct);
    if (input.priorUsed < thresholdUnits && input.nextUsed >= thresholdUnits) {
      const idem = `quota:${t.code}:${input.orgId}:${input.periodMonth}`;
      const inserted = await tx.query(
        `INSERT INTO rq.email_outbox (
           id, tenant_id, idempotency_key, template_code, recipient_email, template_vars, state, attempt_count
         ) VALUES ($1::uuid, $2::uuid, $3::text, $4::text, $5::text, $6::jsonb, 'pending', 0)
         ON CONFLICT (idempotency_key) DO NOTHING
         RETURNING id`,
        [
          crypto.randomUUID(),
          input.orgId,
          idem,
          t.code,
          recipientEmail,
          JSON.stringify({
            period_month: input.periodMonth,
            used_units: input.nextUsed,
            included_units: input.includedUnits
          })
        ]
      );
      if (inserted.rows.length > 0) {
        queued.push(t.code);
        await tx.query(
          `UPDATE rq.usage_rollups SET ${t.col} = pg_catalog.clock_timestamp()
            WHERE org_id = $1::uuid AND metric_code = $2::text AND period_month = $3::char(7)
              AND ${t.col} IS NULL`,
          [input.orgId, input.metricCode, input.periodMonth]
        );
      }
    }
  }

  // Spike threshold: >3x average hourly pace of included monthly allocation (minimum guard 500 units/hour)
  const expectedHourlyPace = Math.max(500, Math.ceil((input.includedUnits / 720) * 3));
  if (input.hourlyUnits > expectedHourlyPace) {
    const spikeIdem = `quota:quota_spike_3x:${input.orgId}:${input.hourBucket}`;
    const inserted = await tx.query(
      `INSERT INTO rq.email_outbox (
         id, tenant_id, idempotency_key, template_code, recipient_email, template_vars, state, attempt_count
       ) VALUES ($1::uuid, $2::uuid, $3::text, 'quota_spike_3x', $4::text, $5::jsonb, 'pending', 0)
       ON CONFLICT (idempotency_key) DO NOTHING
       RETURNING id`,
      [
        crypto.randomUUID(),
        input.orgId,
        spikeIdem,
        recipientEmail,
        JSON.stringify({
          hour_bucket: input.hourBucket,
          hourly_units: input.hourlyUnits,
          threshold_units: expectedHourlyPace
        })
      ]
    );
    if (inserted.rows.length > 0) {
      queued.push("quota_spike_3x");
      await tx.query(
        `UPDATE rq.usage_rollups SET spike_alert_sent_at = pg_catalog.clock_timestamp()
          WHERE org_id = $1::uuid AND metric_code = $2::text AND period_month = $3::char(7)`,
        [input.orgId, input.metricCode, input.periodMonth]
      );
    }
  }

  return queued;
}

/**
 * Evaluates pre-enqueue commercial entitlements and records zero/metered usage safely inside RLS scope.
 */
export async function evaluateQuotaGuard(
  input: EvaluateQuotaGuardInput
): Promise<EvaluateQuotaGuardResult> {
  const now = input.now ?? new Date();
  const metricCode = input.metricCode ?? "outbound_deliveries";
  const requestedUnits = Math.max(1, Math.trunc(input.requestedUnits ?? 1));
  const periodMonth = formatYearMonth(now);
  const hourBucket = formatHourBucket(now);

  // Load commercial entitlement snapshot strictly within tenant RLS context
  const entitlement = await withTenantRlsTransaction(
    input.pgAdapter,
    input.pgAdapter.configuredRole,
    input.orgId,
    async (tx) => {
      const subRes = await tx.query<{
        plan_tier: PlanTier;
        entitlement_state: EntitlementState;
        currency: string;
      }>(
        `SELECT plan_tier, entitlement_state, currency
           FROM rq.billing_subscriptions
          WHERE org_id = $1::uuid
          LIMIT 1`,
        [input.orgId]
      );
      const qRes = await tx.query<{
        included_units_month: string | number;
        overage_unit_minor: string | number;
        cap_mode: CapMode;
      }>(
        `SELECT included_units_month, overage_unit_minor, cap_mode
           FROM rq.entitlement_quotas
          WHERE org_id = $1::uuid
          LIMIT 1`,
        [input.orgId]
      );
      const cusRes = await tx.query<{ org_id: string }>(
        `SELECT org_id FROM rq.billing_customers WHERE org_id = $1::uuid LIMIT 1`,
        [input.orgId]
      );
      const rollupRes = await tx.query<{ total_billable_units: string | number }>(
        `SELECT total_billable_units
           FROM rq.usage_rollups
          WHERE org_id = $1::uuid AND metric_code = $2::text AND period_month = $3::char(7)
          LIMIT 1`,
        [input.orgId, metricCode, periodMonth]
      );

      const hasBillingCustomer = cusRes.rows[0] !== undefined;
      const planTier: PlanTier = subRes.rows[0]?.plan_tier ?? "free";
      const entitlementState: EntitlementState = subRes.rows[0]?.entitlement_state ?? "FREE";
      const currency = String(subRes.rows[0]?.currency ?? "USD");
      const catalog = PLAN_CATALOG[planTier];
      const includedUnits = Number(
        qRes.rows[0]?.included_units_month ?? catalog.includedUnitsMonth
      );
      const overageUnitMinor = Number(
        qRes.rows[0]?.overage_unit_minor ?? catalog.overagePer10kMinor
      );
      const capMode: CapMode = qRes.rows[0]?.cap_mode ?? catalog.capMode;
      const pgUsedUnits = Number(rollupRes.rows[0]?.total_billable_units ?? 0);

      return {
        hasBillingCustomer,
        planTier,
        entitlementState,
        currency,
        includedUnits,
        overageUnitMinor,
        capMode,
        pgUsedUnits
      };
    },
    { readOnly: true }
  );

  if (input.isIdempotentReplay) {
    if (entitlement.hasBillingCustomer) {
      await withTenantRlsTransaction(
        input.pgAdapter,
        input.pgAdapter.configuredRole,
        input.orgId,
        async (tx) => {
          await tx.query(
            `INSERT INTO rq.usage_events (
               usage_event_id, org_id, idempotency_key, metric_code, period_month,
               billable_units, billed_reason, cogs_micros, currency, unit_price_minor
             ) VALUES (
               $1::uuid, $2::uuid, $3::text, $4::text, $5::char(7),
               0, 'idempotent_replay_free', 0, $6::char(3), 0
             ) ON CONFLICT (org_id, metric_code, idempotency_key) DO NOTHING`,
            [
              crypto.randomUUID(),
              input.orgId,
              `${input.idempotencyKey}:replay`,
              metricCode,
              periodMonth,
              entitlement.currency
            ]
          );
        }
      );
    }
    return {
      allowed: true,
      planTier: entitlement.planTier,
      entitlementState: entitlement.entitlementState,
      capMode: entitlement.capMode,
      usedUnitsMonth: entitlement.pgUsedUnits,
      includedUnitsMonth: entitlement.includedUnits,
      billableUnits: 0,
      billedReason: "idempotent_replay_free",
      alertsQueued: [],
      redisDegradedFallback: false
    };
  }

  const paidAllowed = isPaidDeliveryAllowed(entitlement.entitlementState);
  const effectiveCapMode: CapMode = paidAllowed ? entitlement.capMode : "hard_cap";
  const effectiveLimitUnits =
    entitlement.entitlementState === "DISPUTE_HOLD"
      ? 0
      : paidAllowed
        ? entitlement.includedUnits
        : Math.min(entitlement.includedUnits, PLAN_CATALOG.free.includedUnitsMonth);
  const enforceHardCap = effectiveCapMode === "hard_cap";

  const quotaKey = `rq:quota:${input.orgId}:${periodMonth}`;
  const spikeKey = `rq:spike:${input.orgId}:${hourBucket}`;

  let redisResult: {
    readonly allowed: boolean;
    readonly usedUnits: number;
    readonly priorUsedUnits: number;
    readonly hourlyUnits: number;
  };
  let redisDegradedFallback = false;

  try {
    redisResult = await input.redis.evalQuotaCheck({
      quotaKey,
      spikeKey,
      requestedUnits,
      limitUnits: effectiveLimitUnits,
      enforceHardCap,
      quotaTtlSeconds: 40 * 24 * 60 * 60,
      spikeTtlSeconds: 2 * 60 * 60
    });
  } catch {
    redisDegradedFallback = true;
    const prior = entitlement.pgUsedUnits;
    const nextUsed = prior + requestedUnits;
    redisResult = {
      allowed: !(enforceHardCap && nextUsed > effectiveLimitUnits),
      usedUnits: enforceHardCap && nextUsed > effectiveLimitUnits ? prior : nextUsed,
      priorUsedUnits: prior,
      hourlyUnits: requestedUnits
    };
  }

  if (!redisResult.allowed) {
    throw new LimitExceededDomainError({
      code: "QUOTA_HARD_CAP_REACHED",
      message:
        entitlement.entitlementState === "DISPUTE_HOLD"
          ? "Organization billing is on dispute hold; upgrade or resolve payment dispute to resume admissions"
          : `Monthly hard quota cap of ${effectiveLimitUnits} ${metricCode} units reached on ${entitlement.planTier} plan`,
      resourceRef: { kind: "billing_subscription", id: input.orgId }
    });
  }

  const billedReason: BilledReason =
    redisResult.usedUnits > entitlement.includedUnits ? "metered_usage" : "included_allowance";

  const alertsQueued = entitlement.hasBillingCustomer
    ? await withTenantRlsTransaction(
        input.pgAdapter,
        input.pgAdapter.configuredRole,
        input.orgId,
        async (tx) => {
          const insertedEvent = await tx.query(
            `INSERT INTO rq.usage_events (
               usage_event_id, org_id, idempotency_key, metric_code, period_month,
               billable_units, billed_reason, cogs_micros, currency, unit_price_minor
             ) VALUES (
               $1::uuid, $2::uuid, $3::text, $4::text, $5::char(7),
               $6::bigint, $7::text, $8::bigint, $9::char(3), $10::bigint
             )
             ON CONFLICT (org_id, metric_code, idempotency_key) DO NOTHING
             RETURNING usage_event_id`,
            [
              crypto.randomUUID(),
              input.orgId,
              input.idempotencyKey,
              metricCode,
              periodMonth,
              requestedUnits,
              billedReason,
              Math.max(0, Math.trunc(input.cogsMicros ?? 0)),
              entitlement.currency,
              entitlement.overageUnitMinor
            ]
          );

          if (insertedEvent.rows.length > 0) {
            await tx.query(
              `INSERT INTO rq.usage_rollups (
                 org_id, metric_code, period_month, total_billable_units, total_free_units, total_cogs_micros
               ) VALUES ($1::uuid, $2::text, $3::char(7), $4::bigint, 0, $5::bigint)
               ON CONFLICT (org_id, metric_code, period_month) DO UPDATE
                 SET total_billable_units = rq.usage_rollups.total_billable_units + EXCLUDED.total_billable_units,
                     total_cogs_micros = rq.usage_rollups.total_cogs_micros + EXCLUDED.total_cogs_micros,
                     updated_at = pg_catalog.clock_timestamp()`,
              [
                input.orgId,
                metricCode,
                periodMonth,
                requestedUnits,
                Math.max(0, Math.trunc(input.cogsMicros ?? 0))
              ]
            );
          }

          return queueThresholdEmailIfNeeded(tx, {
            orgId: input.orgId,
            metricCode,
            periodMonth,
            hourBucket,
            priorUsed: redisResult.priorUsedUnits,
            nextUsed: redisResult.usedUnits,
            includedUnits: effectiveLimitUnits,
            hourlyUnits: redisResult.hourlyUnits
          });
        }
      )
    : [];

  return {
    allowed: true,
    planTier: entitlement.planTier,
    entitlementState: entitlement.entitlementState,
    capMode: effectiveCapMode,
    usedUnitsMonth: redisResult.usedUnits,
    includedUnitsMonth: effectiveLimitUnits,
    billableUnits: requestedUnits,
    billedReason,
    alertsQueued,
    redisDegradedFallback
  };
}
