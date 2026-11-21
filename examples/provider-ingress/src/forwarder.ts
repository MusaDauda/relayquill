import crypto from "node:crypto";
import {
  canonicalizeJson,
  parseCanonicalUtcTimestamp,
  parseCanonicalUuid,
  parseSha256Hex,
  type CanonicalJsonValue
} from "@relayquill/contracts";
import {
  ProducerAbortedError,
  ProducerAcceptanceUnknownError,
  ProducerContextChangedError,
  ProducerSdkError,
  ProducerValidationError,
  ProducerConflictError,
  prepareEvent,
  type PreparedEvent,
  type RelayquillProducerClient
} from "@relayquill/producer-sdk";
import {
  ProviderIngressDbError,
  ProviderIngressRepository,
  type ForwardFinalizeOutcome,
  type ProviderBindingRecord,
  type ProviderIngressDbClient
} from "./db.js";
import { type NormalizedProviderCallback } from "./verify.js";

export const PREPARED_SUBMISSION_SCHEMA_VERSION = 1 as const;
const MAX_PREPARED_BYTES = 131_072;

export interface PreparedForwardPayload {
  readonly schema_version: typeof PREPARED_SUBMISSION_SCHEMA_VERSION;
  readonly relay_tenant_id: string;
  readonly relay_project_id: string;
  readonly prepare_input: {
    readonly expected_publication_channel_id: string;
    readonly event_type_id: string;
    readonly event_schema_version: number;
    readonly business_key: string;
    readonly idempotency_key: string;
    readonly content_json: string;
    readonly producer_event_time?: string | undefined;
  };
}

export interface PreparedCallbackSubmission {
  readonly prepared: PreparedEvent;
  readonly preparedBytes: Buffer;
  readonly submissionSha256Hex: string;
}

export async function prepareNormalizedCallbackSubmission(params: {
  readonly binding: ProviderBindingRecord;
  readonly normalized: NormalizedProviderCallback;
}): Promise<PreparedCallbackSubmission> {
  const contentJson = canonicalizeJson(
    params.normalized.normalizedFacts as unknown as CanonicalJsonValue,
    "normalized_facts"
  );

  const prepared = await prepareEvent({
    expectedPublicationChannelId: params.binding.publicationChannelId,
    eventTypeId: params.binding.normalizedEventTypeId,
    eventSchemaVersion: params.binding.normalizedSchemaVersion,
    businessKey: params.normalized.businessKey,
    idempotencyKey: params.normalized.requestKey,
    content: contentJson,
    ...(params.normalized.providerBusinessTime !== null
      ? { producerEventTime: params.normalized.providerBusinessTime }
      : {})
  });

  const payload: PreparedForwardPayload = {
    schema_version: PREPARED_SUBMISSION_SCHEMA_VERSION,
    relay_tenant_id: params.binding.relayTenantId,
    relay_project_id: params.binding.relayProjectId,
    prepare_input: {
      expected_publication_channel_id: prepared.expectedPublicationChannelId,
      event_type_id: prepared.eventTypeId,
      event_schema_version: prepared.eventSchemaVersion,
      business_key: prepared.businessKey,
      idempotency_key: prepared.idempotencyKey,
      content_json: contentJson,
      ...(prepared.producerEventTime !== undefined
        ? { producer_event_time: prepared.producerEventTime }
        : {})
    }
  };

  const preparedBytes = Buffer.from(JSON.stringify(payload), "utf8");
  if (preparedBytes.byteLength < 2 || preparedBytes.byteLength > MAX_PREPARED_BYTES) {
    throw new ProviderIngressDbError({
      code: "PAYLOAD_TOO_LARGE",
      httpStatus: 413,
      message: `Prepared forward payload byte length ${preparedBytes.byteLength} outside [2, ${MAX_PREPARED_BYTES}]`
    });
  }

  const rawDigest = prepared.submittedShapeSha256 ?? prepared.producerPrepareDigest;
  const submissionSha256Hex = parseSha256Hex(rawDigest, "submission_sha256");

  return {
    prepared,
    preparedBytes,
    submissionSha256Hex
  };
}

function readStringField(rec: Record<string, unknown>, key: string): string {
  const val = rec[key];
  if (typeof val !== "string" || val.length === 0) {
    throw new ProviderIngressDbError({
      code: "INVALID_PREPARED_BYTES",
      httpStatus: 500,
      message: `Invalid or missing prepared_bytes field "${key}"`
    });
  }
  return val;
}

export async function reconstructPreparedForwardPayload(preparedBytes: Buffer): Promise<{
  readonly relayTenantId: string;
  readonly relayProjectId: string;
  readonly prepared: PreparedEvent;
}> {
  let raw: unknown;
  try {
    raw = JSON.parse(preparedBytes.toString("utf8"));
  } catch (err) {
    throw new ProviderIngressDbError({
      code: "INVALID_PREPARED_BYTES",
      httpStatus: 500,
      message: "Corrupt prepared_bytes JSON in forward intent",
      cause: err
    });
  }
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
    throw new ProviderIngressDbError({
      code: "INVALID_PREPARED_BYTES",
      httpStatus: 500,
      message: "prepared_bytes must decode to a JSON object"
    });
  }

  const rec = raw as Record<string, unknown>;
  if (rec["schema_version"] !== PREPARED_SUBMISSION_SCHEMA_VERSION) {
    throw new ProviderIngressDbError({
      code: "INVALID_PREPARED_BYTES",
      httpStatus: 500,
      message: `Unsupported prepared_bytes schema_version: ${String(rec["schema_version"])}`
    });
  }

  const relayTenantId = parseCanonicalUuid(readStringField(rec, "relay_tenant_id"), "relay_tenant_id");
  const relayProjectId = parseCanonicalUuid(readStringField(rec, "relay_project_id"), "relay_project_id");
  const prepRaw = rec["prepare_input"];
  if (typeof prepRaw !== "object" || prepRaw === null || Array.isArray(prepRaw)) {
    throw new ProviderIngressDbError({
      code: "INVALID_PREPARED_BYTES",
      httpStatus: 500,
      message: "prepared_bytes missing prepare_input object"
    });
  }

  const prep = prepRaw as Record<string, unknown>;
  const eventSchemaVersion = prep["event_schema_version"];
  if (typeof eventSchemaVersion !== "number" || !Number.isInteger(eventSchemaVersion) || eventSchemaVersion < 1) {
    throw new ProviderIngressDbError({
      code: "INVALID_PREPARED_BYTES",
      httpStatus: 500,
      message: "prepared_bytes invalid event_schema_version"
    });
  }

  const producerEventTimeRaw = prep["producer_event_time"];
  const producerEventTime =
    typeof producerEventTimeRaw === "string" && producerEventTimeRaw.length > 0
      ? parseCanonicalUtcTimestamp(producerEventTimeRaw, "producer_event_time")
      : undefined;

  const prepared = await prepareEvent({
    expectedPublicationChannelId: readStringField(prep, "expected_publication_channel_id"),
    eventTypeId: readStringField(prep, "event_type_id"),
    eventSchemaVersion,
    businessKey: readStringField(prep, "business_key"),
    idempotencyKey: readStringField(prep, "idempotency_key"),
    content: readStringField(prep, "content_json"),
    ...(producerEventTime !== undefined ? { producerEventTime } : {})
  });

  return {
    relayTenantId,
    relayProjectId,
    prepared
  };
}

export interface ProviderForwarderOptions {
  readonly db: ProviderIngressDbClient;
  readonly repository?: ProviderIngressRepository | undefined;
  readonly producerClient: RelayquillProducerClient;
  readonly ownerInstanceId?: string | undefined;
  readonly pollIntervalMs?: number | undefined;
  readonly batchSize?: number | undefined;
  readonly claimLeaseMs?: bigint | undefined;
  readonly baseBackoffMs?: number | undefined;
  readonly maxBackoffMs?: number | undefined;
  readonly nowMs?: (() => number) | undefined;
}

export type ForwardIntentProcessOutcome =
  | {
      readonly outcome: "accepted" | "already_accepted";
      readonly intentId: string;
      readonly relayEventId?: string | undefined;
      readonly relayReceiptId?: string | undefined;
    }
  | {
      readonly outcome: "acceptance_unknown" | "blocked" | "retry";
      readonly intentId: string;
      readonly safeErrorCode: string;
    }
  | {
      readonly outcome: "skipped";
      readonly intentId: string;
      readonly reason: string;
    };

export interface ForwardCycleSummary {
  readonly dueCount: number;
  readonly claimedCount: number;
  readonly acceptedCount: number;
  readonly alreadyAcceptedCount: number;
  readonly acceptanceUnknownCount: number;
  readonly blockedCount: number;
  readonly retryScheduledCount: number;
  readonly skippedCount: number;
}

function sanitizeSafeErrorCode(raw: string): string {
  const cleaned = raw.replace(/[^A-Za-z0-9_.-]/g, "_").slice(0, 64);
  return cleaned.length > 0 ? cleaned : "FORWARD_ERROR";
}

function classifyForwardError(err: unknown): {
  readonly outcome: Extract<ForwardFinalizeOutcome, "acceptance_unknown" | "blocked" | "retry">;
  readonly safeErrorCode: string;
} {
  if (err instanceof ProducerAcceptanceUnknownError) {
    return {
      outcome: "acceptance_unknown",
      safeErrorCode: sanitizeSafeErrorCode(err.code)
    };
  }
  if (err instanceof ProducerAbortedError) {
    return {
      outcome: err.acceptance === "unknown" ? "acceptance_unknown" : "retry",
      safeErrorCode: sanitizeSafeErrorCode(err.code)
    };
  }
  if (
    err instanceof ProducerContextChangedError ||
    err instanceof ProducerValidationError ||
    err instanceof ProducerConflictError
  ) {
    return {
      outcome: "blocked",
      safeErrorCode: sanitizeSafeErrorCode(err.code)
    };
  }
  if (err instanceof ProducerSdkError) {
    if (err.acceptance === "unknown") {
      return {
        outcome: "acceptance_unknown",
        safeErrorCode: sanitizeSafeErrorCode(err.code)
      };
    }
    if (err.retryable) {
      return {
        outcome: "retry",
        safeErrorCode: sanitizeSafeErrorCode(err.code)
      };
    }
    if (err.httpStatus !== undefined && err.httpStatus >= 400 && err.httpStatus < 500 && err.httpStatus !== 429) {
      return {
        outcome: "blocked",
        safeErrorCode: sanitizeSafeErrorCode(err.code)
      };
    }
    return {
      outcome: "retry",
      safeErrorCode: sanitizeSafeErrorCode(err.code)
    };
  }
  return {
    outcome: "retry",
    safeErrorCode: "FORWARD_UNEXPECTED_ERROR"
  };
}

export class ProviderOutboxForwarder {
  readonly #db: ProviderIngressDbClient;
  readonly #repo: ProviderIngressRepository;
  readonly #client: RelayquillProducerClient;
  readonly #ownerInstanceId: string;
  readonly #pollIntervalMs: number;
  readonly #batchSize: number;
  readonly #claimLeaseMs: bigint;
  readonly #baseBackoffMs: number;
  readonly #maxBackoffMs: number;
  readonly #nowMs: () => number;

  #running = false;
  #stopRequested = false;
  #timer: ReturnType<typeof setTimeout> | null = null;
  #inFlight: Promise<ForwardCycleSummary> | null = null;

  constructor(options: ProviderForwarderOptions) {
    this.#db = options.db;
    this.#repo = options.repository ?? new ProviderIngressRepository();
    this.#client = options.producerClient;
    this.#ownerInstanceId =
      options.ownerInstanceId !== undefined
        ? parseCanonicalUuid(options.ownerInstanceId, "ownerInstanceId")
        : crypto.randomUUID();
    this.#pollIntervalMs = Math.max(25, Math.trunc(options.pollIntervalMs ?? 500));
    this.#batchSize = Math.max(1, Math.min(200, Math.trunc(options.batchSize ?? 16)));
    this.#claimLeaseMs = options.claimLeaseMs ?? 30_000n;
    this.#baseBackoffMs = Math.max(50, Math.trunc(options.baseBackoffMs ?? 500));
    this.#maxBackoffMs = Math.max(this.#baseBackoffMs, Math.trunc(options.maxBackoffMs ?? 30_000));
    this.#nowMs = options.nowMs ?? (() => Date.now());
  }

  get ownerInstanceId(): string {
    return this.#ownerInstanceId;
  }

  get isRunning(): boolean {
    return this.#running;
  }

  async processIntent(
    intentId: string,
    expectedPriorState?: "ready" | "claimed" | "acceptance_unknown"
  ): Promise<ForwardIntentProcessOutcome> {
    const claimed = await this.#db.inTransaction((tx) =>
      this.#repo.claimForwardIntent(tx, {
        intentId,
        ownerInstanceId: this.#ownerInstanceId,
        leaseMs: this.#claimLeaseMs,
        ...(expectedPriorState !== undefined ? { expectedPriorState } : {})
      })
    );

    if (claimed.outcome === "already_accepted") {
      return {
        outcome: "already_accepted",
        intentId: claimed.intentId,
        ...(claimed.relayEventId !== undefined ? { relayEventId: claimed.relayEventId } : {}),
        ...(claimed.relayReceiptId !== undefined ? { relayReceiptId: claimed.relayReceiptId } : {})
      };
    }

    if (claimed.outcome !== "claimed") {
      return {
        outcome: "skipped",
        intentId,
        reason: claimed.outcome
      };
    }

    let decoded: Awaited<ReturnType<typeof reconstructPreparedForwardPayload>>;
    try {
      decoded = await reconstructPreparedForwardPayload(claimed.preparedBytes);
    } catch (err) {
      const safeCode =
        err instanceof ProviderIngressDbError ? sanitizeSafeErrorCode(err.code) : "INVALID_PREPARED_BYTES";
      await this.#db.inTransaction((tx) =>
        this.#repo.finalizeForwardIntent(tx, {
          intentId: claimed.intentId,
          ownerInstanceId: this.#ownerInstanceId,
          expectedClaimGeneration: claimed.claimGeneration,
          outcome: "blocked",
          safeErrorCode: safeCode
        })
      );
      return {
        outcome: "blocked",
        intentId: claimed.intentId,
        safeErrorCode: safeCode
      };
    }

    const callScope = {
      tenantId: decoded.relayTenantId,
      projectId: decoded.relayProjectId
    };

    try {
      if (claimed.priorState === "acceptance_unknown") {
        const resolved = await this.#client.resolvePreparedEvent(decoded.prepared, callScope);
        if (resolved.found) {
          await this.#db.inTransaction((tx) =>
            this.#repo.finalizeForwardIntent(tx, {
              intentId: claimed.intentId,
              ownerInstanceId: this.#ownerInstanceId,
              expectedClaimGeneration: claimed.claimGeneration,
              outcome: "accepted",
              relayEventId: resolved.data.event.event_id,
              relayReceiptId: resolved.data.receipt.id
            })
          );
          return {
            outcome: "accepted",
            intentId: claimed.intentId,
            relayEventId: resolved.data.event.event_id,
            relayReceiptId: resolved.data.receipt.id
          };
        }
      }

      const submitted = await this.#client.submitEvent(decoded.prepared, callScope);
      await this.#db.inTransaction((tx) =>
        this.#repo.finalizeForwardIntent(tx, {
          intentId: claimed.intentId,
          ownerInstanceId: this.#ownerInstanceId,
          expectedClaimGeneration: claimed.claimGeneration,
          outcome: "accepted",
          relayEventId: submitted.data.event.event_id,
          relayReceiptId: submitted.data.receipt.id
        })
      );
      return {
        outcome: "accepted",
        intentId: claimed.intentId,
        relayEventId: submitted.data.event.event_id,
        relayReceiptId: submitted.data.receipt.id
      };
    } catch (err) {
      const classified = classifyForwardError(err);
      const backoffMs = Math.min(
        this.#maxBackoffMs,
        this.#baseBackoffMs * Math.pow(2, Math.min(6, Number(claimed.claimGeneration - 1n)))
      );
      const nextAttemptAt = new Date(this.#nowMs() + backoffMs).toISOString();

      await this.#db.inTransaction((tx) =>
        this.#repo.finalizeForwardIntent(tx, {
          intentId: claimed.intentId,
          ownerInstanceId: this.#ownerInstanceId,
          expectedClaimGeneration: claimed.claimGeneration,
          outcome: classified.outcome,
          safeErrorCode: classified.safeErrorCode,
          ...(classified.outcome === "blocked" ? {} : { nextAttemptAt })
        })
      );
      return {
        outcome: classified.outcome,
        intentId: claimed.intentId,
        safeErrorCode: classified.safeErrorCode
      };
    }
  }

  async runOnce(): Promise<ForwardCycleSummary> {
    if (this.#inFlight !== null) {
      return this.#inFlight;
    }
    const exec = async (): Promise<ForwardCycleSummary> => {
      const due = await this.#db.inTransaction((tx) =>
        this.#repo.listDueForwardIntents(tx, this.#batchSize)
      );
      let claimedCount = 0;
      let acceptedCount = 0;
      let alreadyAcceptedCount = 0;
      let acceptanceUnknownCount = 0;
      let blockedCount = 0;
      let retryScheduledCount = 0;
      let skippedCount = 0;

      for (const item of due) {
        if (this.#stopRequested) {
          break;
        }
        const res = await this.processIntent(item.intentId, item.state);
        switch (res.outcome) {
          case "accepted":
            claimedCount += 1;
            acceptedCount += 1;
            break;
          case "already_accepted":
            alreadyAcceptedCount += 1;
            break;
          case "acceptance_unknown":
            claimedCount += 1;
            acceptanceUnknownCount += 1;
            break;
          case "blocked":
            claimedCount += 1;
            blockedCount += 1;
            break;
          case "retry":
            claimedCount += 1;
            retryScheduledCount += 1;
            break;
          case "skipped":
            skippedCount += 1;
            break;
        }
      }

      return {
        dueCount: due.length,
        claimedCount,
        acceptedCount,
        alreadyAcceptedCount,
        acceptanceUnknownCount,
        blockedCount,
        retryScheduledCount,
        skippedCount
      };
    };

    this.#inFlight = exec().finally(() => {
      this.#inFlight = null;
    });
    return this.#inFlight;
  }

  async start(): Promise<void> {
    if (this.#running) {
      return;
    }
    this.#running = true;
    this.#stopRequested = false;

    const scheduleNext = (): void => {
      if (this.#stopRequested) {
        return;
      }
      this.#timer = setTimeout(() => {
        void this.runOnce()
          .catch(() => undefined)
          .finally(() => {
            scheduleNext();
          });
      }, this.#pollIntervalMs);
      this.#timer.unref?.();
    };

    await this.runOnce().catch(() => undefined);
    scheduleNext();
  }

  async stop(): Promise<void> {
    this.#stopRequested = true;
    this.#running = false;
    if (this.#timer !== null) {
      clearTimeout(this.#timer);
      this.#timer = null;
    }
    if (this.#inFlight !== null) {
      await this.#inFlight.catch(() => undefined);
    }
  }
}
