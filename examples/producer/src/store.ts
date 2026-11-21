import fs from "node:fs";
import path from "node:path";
import {
  prepareEvent,
  type PreparedEvent,
  type SafePreparedEventMetadata
} from "@relayquill/producer-sdk";

export const PRODUCER_RUN_SCHEMA_VERSION = 1 as const;
const SAFE_RUN_ID_REGEX = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;

export interface StoredProducerPrepareInput {
  readonly expected_publication_channel_id: string;
  readonly event_type_id: string;
  readonly event_schema_version: number;
  readonly business_key: string;
  readonly idempotency_key: string;
  readonly content_json: string;
  readonly producer_event_time?: string | undefined;
  readonly deadline_at?: string | undefined;
}

export interface StoredProducerRun {
  readonly schema_version: typeof PRODUCER_RUN_SCHEMA_VERSION;
  readonly run_id: string;
  readonly created_at: string;
  readonly updated_at: string;
  readonly origin: string;
  readonly tenant_id?: string | undefined;
  readonly project_id?: string | undefined;
  readonly credential_ref?: string | undefined;
  readonly prepare_input: StoredProducerPrepareInput;
  readonly safe_metadata: SafePreparedEventMetadata;
  readonly event_id?: string | undefined;
  readonly receipt_id?: string | undefined;
  readonly last_outcome?: string | undefined;
}

export function validateRunId(raw: string): string {
  const trimmed = raw.trim();
  if (!SAFE_RUN_ID_REGEX.test(trimmed) || trimmed.includes("..")) {
    throw new Error(`Invalid run identifier "${raw}"`);
  }
  return trimmed;
}

export function resolveRunFilePath(params: {
  readonly runsDir: string;
  readonly runId?: string | undefined;
  readonly runFile?: string | undefined;
}): string {
  if (params.runFile !== undefined && params.runFile.trim().length > 0) {
    return path.resolve(params.runFile.trim());
  }
  if (params.runId !== undefined && params.runId.trim().length > 0) {
    const safeId = validateRunId(params.runId);
    const resolvedDir = path.resolve(params.runsDir);
    const candidate = path.resolve(resolvedDir, `${safeId}.json`);
    if (!candidate.startsWith(`${resolvedDir}${path.sep}`)) {
      throw new Error(`Resolved run file escaped runsDir: ${candidate}`);
    }
    return candidate;
  }
  throw new Error("Either --run-id or --run-file must be provided");
}

export function saveProducerRun(filePath: string, run: StoredProducerRun): void {
  const resolved = path.resolve(filePath);
  const dir = path.dirname(resolved);
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  const tmpPath = `${resolved}.${process.pid}.tmp`;
  fs.writeFileSync(tmpPath, `${JSON.stringify(run, null, 2)}\n`, {
    encoding: "utf8",
    mode: 0o600
  });
  fs.renameSync(tmpPath, resolved);
}

function readReqStr(rec: Record<string, unknown>, key: string): string {
  const val = rec[key];
  if (typeof val !== "string" || val.length === 0) {
    throw new Error(`Run artifact missing required string field "${key}"`);
  }
  return val;
}

function readOptStr(rec: Record<string, unknown>, key: string): string | undefined {
  const val = rec[key];
  return typeof val === "string" && val.length > 0 ? val : undefined;
}

export function loadProducerRun(filePath: string): StoredProducerRun {
  const resolved = path.resolve(filePath);
  const rawText = fs.readFileSync(resolved, "utf8");
  const parsed: unknown = JSON.parse(rawText);
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new Error(`Run artifact at "${resolved}" must be a JSON object`);
  }
  const rec = parsed as Record<string, unknown>;
  if (rec["schema_version"] !== PRODUCER_RUN_SCHEMA_VERSION) {
    throw new Error(`Unsupported run artifact schema_version: ${String(rec["schema_version"])}`);
  }
  const prepRaw = rec["prepare_input"];
  if (typeof prepRaw !== "object" || prepRaw === null || Array.isArray(prepRaw)) {
    throw new Error(`Run artifact at "${resolved}" missing prepare_input object`);
  }
  const prep = prepRaw as Record<string, unknown>;
  const schemaVer = prep["event_schema_version"];
  if (typeof schemaVer !== "number" || !Number.isInteger(schemaVer) || schemaVer < 1) {
    throw new Error("Run artifact prepare_input.event_schema_version must be a positive integer");
  }

  const producerEventTime = readOptStr(prep, "producer_event_time");
  const deadlineAt = readOptStr(prep, "deadline_at");
  const tenantId = readOptStr(rec, "tenant_id");
  const projectId = readOptStr(rec, "project_id");
  const credentialRef = readOptStr(rec, "credential_ref");
  const eventId = readOptStr(rec, "event_id");
  const receiptId = readOptStr(rec, "receipt_id");
  const lastOutcome = readOptStr(rec, "last_outcome");

  return {
    schema_version: PRODUCER_RUN_SCHEMA_VERSION,
    run_id: validateRunId(readReqStr(rec, "run_id")),
    created_at: readReqStr(rec, "created_at"),
    updated_at: readReqStr(rec, "updated_at"),
    origin: readReqStr(rec, "origin"),
    ...(tenantId !== undefined ? { tenant_id: tenantId } : {}),
    ...(projectId !== undefined ? { project_id: projectId } : {}),
    ...(credentialRef !== undefined ? { credential_ref: credentialRef } : {}),
    prepare_input: {
      expected_publication_channel_id: readReqStr(prep, "expected_publication_channel_id"),
      event_type_id: readReqStr(prep, "event_type_id"),
      event_schema_version: schemaVer,
      business_key: readReqStr(prep, "business_key"),
      idempotency_key: readReqStr(prep, "idempotency_key"),
      content_json: readReqStr(prep, "content_json"),
      ...(producerEventTime !== undefined ? { producer_event_time: producerEventTime } : {}),
      ...(deadlineAt !== undefined ? { deadline_at: deadlineAt } : {})
    },
    safe_metadata: rec["safe_metadata"] as SafePreparedEventMetadata,
    ...(eventId !== undefined ? { event_id: eventId } : {}),
    ...(receiptId !== undefined ? { receipt_id: receiptId } : {}),
    ...(lastOutcome !== undefined ? { last_outcome: lastOutcome } : {})
  };
}

export async function reconstructPreparedEventFromRun(
  run: StoredProducerRun
): Promise<PreparedEvent> {
  return prepareEvent({
    expectedPublicationChannelId: run.prepare_input.expected_publication_channel_id,
    eventTypeId: run.prepare_input.event_type_id,
    eventSchemaVersion: run.prepare_input.event_schema_version,
    businessKey: run.prepare_input.business_key,
    idempotencyKey: run.prepare_input.idempotency_key,
    content: run.prepare_input.content_json,
    ...(run.prepare_input.producer_event_time !== undefined
      ? { producerEventTime: run.prepare_input.producer_event_time }
      : {}),
    ...(run.prepare_input.deadline_at !== undefined
      ? { deadlineAt: run.prepare_input.deadline_at }
      : {})
  });
}
