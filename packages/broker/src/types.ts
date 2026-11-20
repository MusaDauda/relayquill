import {
  BROKER_DEDUP_WINDOW_MS,
  BROKER_EVENT_MAX_PAYLOAD_BYTES,
  BROKER_EVENT_STREAM_NAME,
  type BrokerGenerationId,
  DependencyUnavailableDomainError,
  type EvidenceBoundary,
  FANOUT_ACK_WAIT_MS,
  FANOUT_CONSUMER_NAME,
  FANOUT_MAX_ACK_PENDING,
  FANOUT_MAX_DELIVER,
  FANOUT_OUT_OF_ORDER_NAK_MS,
  FANOUT_PULL_MAX_BATCH,
  FANOUT_PULL_MAX_BYTES,
  InvariantViolationError,
  LimitExceededDomainError,
  OUTBOX_PUBLISH_TIMEOUT_MS,
  type OutboxId,
  type ProjectId,
  RELAY_MAX_IN_FLIGHT,
  type Sha256Hex,
  ValidationDomainError,
  formatBrokerEventSubject,
  parseProjectId
} from "@relayquill/domain";
import {
  type BrokerMessageId,
  type PositiveInt64String
} from "@relayquill/contracts";
import {
  type BrokerMode,
  type ParsedTraceparent,
  type SanitizeTracestateOptions,
  parseTraceparent,
  sanitizeIncomingTraceHeaders,
  sanitizeTracestate
} from "@relayquill/runtime";
import { type MsgHdrs } from "@nats-io/transport-node";
import { type ConsumerInfo, type StreamInfo } from "@nats-io/jetstream";

export {
  BROKER_DEDUP_WINDOW_MS,
  BROKER_EVENT_MAX_PAYLOAD_BYTES,
  BROKER_EVENT_STREAM_NAME,
  FANOUT_ACK_WAIT_MS,
  FANOUT_CONSUMER_NAME,
  FANOUT_MAX_ACK_PENDING,
  FANOUT_MAX_DELIVER,
  FANOUT_OUT_OF_ORDER_NAK_MS,
  FANOUT_PULL_MAX_BATCH,
  FANOUT_PULL_MAX_BYTES,
  OUTBOX_PUBLISH_TIMEOUT_MS,
  RELAY_MAX_IN_FLIGHT
};

export const BROKER_DEFAULT_MAX_MSGS = 100_000 as const;
export const BROKER_DEFAULT_MAX_BYTES = 268_435_456 as const;
export const BROKER_DEFAULT_MAX_AGE_SECONDS = 3_600 as const;
export const BROKER_DEFAULT_MAX_AGE_NS = 3_600_000_000_000 as const;
export const BROKER_DEFAULT_DUPLICATE_WINDOW_SECONDS = 120 as const;
export const BROKER_DEFAULT_DUPLICATE_WINDOW_NS = 120_000_000_000 as const;
export const BROKER_DEFAULT_ACK_WAIT_SECONDS = 30 as const;
export const BROKER_DEFAULT_ACK_WAIT_NS = 30_000_000_000 as const;
export const BROKER_DEFAULT_PULL_MAX_EXPIRES_MS = 5_000 as const;
export const BROKER_DEFAULT_PULL_MAX_EXPIRES_NS = 5_000_000_000 as const;
export const BROKER_MIN_PULL_EXPIRES_MS = 1_000 as const;
export const BROKER_DEFAULT_REPLICAS = 1 as const;
export const BROKER_EVENT_SUBJECT_SUFFIX = "rq.events.*.accepted" as const;
export const BROKER_MAX_NAK_DELAY_MS = 300_000 as const;

const SUBJECT_PREFIX_REGEX = /^([a-z0-9_-]+\.)*$/;
const SUBJECT_PREFIX_MAX_LEN = 64;

export type BrokerPublishClassification =
  | "publish_unknown"
  | "capacity_exceeded"
  | "unavailable"
  | "rejected";

export interface BrokerErrorMetadata {
  readonly classification: BrokerPublishClassification;
  readonly stream?: string | undefined;
  readonly subject?: string | undefined;
  readonly msgId?: BrokerMessageId | string | undefined;
  readonly reasonCode?: string | undefined;
}

export class BrokerPublishError extends DependencyUnavailableDomainError {
  readonly classification: BrokerPublishClassification;
  readonly stream: string | undefined;
  readonly subject: string | undefined;
  readonly msgId: string | undefined;
  readonly reasonCode: string | undefined;

  constructor(
    options: {
      readonly message: string;
      readonly classification?: BrokerPublishClassification | undefined;
      readonly retryable?: boolean | undefined;
      readonly acceptance?: "known_rejected" | "unknown" | "not_applicable" | undefined;
      readonly boundary?: EvidenceBoundary | undefined;
      readonly stream?: string | undefined;
      readonly subject?: string | undefined;
      readonly msgId?: BrokerMessageId | string | undefined;
      readonly reasonCode?: string | undefined;
    },
    cause?: unknown
  ) {
    super({
      code: "ACCEPTANCE_UNKNOWN",
      message: options.message,
      retryable: options.retryable ?? true,
      acceptance: options.acceptance ?? "unknown",
      boundary: options.boundary ?? "published"
    });
    if (cause !== undefined) {
      this.cause = cause;
    }
    this.classification = options.classification ?? "publish_unknown";
    this.stream = options.stream;
    this.subject = options.subject;
    this.msgId = options.msgId;
    this.reasonCode = options.reasonCode;
  }
}

export class BrokerCapacityError extends LimitExceededDomainError {
  readonly classification = "capacity_exceeded" as const;
  readonly stream: string | undefined;
  readonly subject: string | undefined;
  readonly msgId: string | undefined;
  readonly reasonCode: string | undefined;

  constructor(
    options: {
      readonly message: string;
      readonly stream?: string | undefined;
      readonly subject?: string | undefined;
      readonly msgId?: BrokerMessageId | string | undefined;
      readonly reasonCode?: string | undefined;
    },
    cause?: unknown
  ) {
    super({
      code: "CAPACITY_EXCEEDED",
      message: options.message,
      retryable: true,
      acceptance: "known_rejected",
      boundary: "published"
    });
    if (cause !== undefined) {
      this.cause = cause;
    }
    this.stream = options.stream;
    this.subject = options.subject;
    this.msgId = options.msgId;
    this.reasonCode = options.reasonCode;
  }
}

export class BrokerUnavailableError extends DependencyUnavailableDomainError {
  readonly classification = "unavailable" as const;
  readonly stream: string | undefined;
  readonly subject: string | undefined;
  readonly msgId: string | undefined;
  readonly reasonCode: string | undefined;

  constructor(
    options: {
      readonly message: string;
      readonly retryable?: boolean | undefined;
      readonly acceptance?: "known_rejected" | "unknown" | "not_applicable" | undefined;
      readonly stream?: string | undefined;
      readonly subject?: string | undefined;
      readonly msgId?: BrokerMessageId | string | undefined;
      readonly reasonCode?: string | undefined;
    },
    cause?: unknown
  ) {
    super({
      code: "DEPENDENCY_UNAVAILABLE",
      message: options.message,
      retryable: options.retryable ?? true,
      acceptance: options.acceptance ?? "known_rejected",
      boundary: "published"
    });
    if (cause !== undefined) {
      this.cause = cause;
    }
    this.stream = options.stream;
    this.subject = options.subject;
    this.msgId = options.msgId;
    this.reasonCode = options.reasonCode;
  }
}

export interface BrokerTopologyMismatch {
  readonly resource: "stream" | "consumer";
  readonly field: string;
  readonly expected: string;
  readonly actual: string;
}

export class BrokerTopologyMismatchError extends InvariantViolationError {
  readonly mismatches: readonly BrokerTopologyMismatch[];

  constructor(
    message: string,
    mismatches: readonly BrokerTopologyMismatch[],
    cause?: unknown
  ) {
    super({
      code: "INVARIANT_VIOLATION",
      message,
      boundary: "published"
    });
    if (cause !== undefined) {
      this.cause = cause;
    }
    this.mismatches = Object.freeze(mismatches.map((m) => Object.freeze({ ...m })));
  }
}

export interface BrokerTraceHeaders {
  readonly traceparent?: string | undefined;
  readonly tracestate?: string | undefined;
}

export interface BrokerExtractedTransportTrace {
  readonly suppliedValidTraceparent: boolean;
  readonly traceparent?: ParsedTraceparent | undefined;
  readonly tracestate: string;
  readonly invalidReason?: string | undefined;
  readonly baggageDropped: boolean;
}

export interface BrokerPublishInput {
  readonly outboxId: OutboxId | string;
  readonly projectId: ProjectId | string;
  readonly publicationGeneration: PositiveInt64String | bigint | number;
  readonly envelopeBytes: Uint8Array;
  readonly subject?: string | undefined;
  readonly traceContext?: BrokerTraceHeaders | undefined;
  readonly timeoutMs?: number | undefined;
  readonly expectedBrokerGenerationId?: BrokerGenerationId | string | undefined;
  readonly signal?: AbortSignal | undefined;
}

export interface BrokerPublishResult {
  readonly stream: string;
  readonly seq: number;
  readonly duplicate: boolean;
  readonly brokerGenerationId: BrokerGenerationId;
  readonly msgId: BrokerMessageId;
  readonly subject: string;
  readonly domain?: string | undefined;
}

export interface BrokerMessage {
  readonly stream: string;
  readonly consumer: string;
  readonly subject: string;
  readonly seq: number;
  readonly deliveryCount: number;
  readonly deliverySequence: number;
  readonly redelivered: boolean;
  readonly pending: number;
  readonly timestampNanos: bigint;
  readonly payload: Uint8Array;
  readonly headers: Readonly<Record<string, readonly string[]>>;
  readonly msgId?: string | undefined;
  readonly trace: BrokerExtractedTransportTrace;
  readonly brokerGenerationId: BrokerGenerationId;
  ack(): Promise<void>;
  ackAck(timeoutMs?: number): Promise<boolean>;
  nak(delayMs?: number): Promise<void>;
  working(): Promise<void>;
  term(reason?: string): Promise<void>;
}

export interface BrokerPullOptions {
  readonly maxBatch?: number | undefined;
  readonly maxBytes?: number | undefined;
  readonly expiresMs?: number | undefined;
  readonly bind?: boolean | undefined;
  readonly signal?: AbortSignal | undefined;
  readonly allowedTracestateKeys?: readonly string[] | undefined;
  readonly allowAnyValidTracestateKey?: boolean | undefined;
}

export interface BrokerConsumeOptions extends BrokerPullOptions {
  readonly availableSlots?: (() => number) | undefined;
  readonly slotWaitMs?: number | undefined;
  readonly idlePollDelayMs?: number | undefined;
}

export interface BrokerStreamContract {
  readonly name: string;
  readonly subject_prefix: string;
  readonly subjects: readonly [string];
  readonly storage: "file";
  readonly retention: "limits";
  readonly discard: "new";
  readonly discard_new_per_subject: false;
  readonly max_msgs: number;
  readonly max_bytes: number;
  readonly max_msg_size: 4096;
  readonly max_age_ns: number;
  readonly duplicate_window_ns: 120000000000;
  readonly replicas: 1 | 3;
}

export interface BrokerConsumerContract {
  readonly stream_name: string;
  readonly durable_name: string;
  readonly deliver_policy: "all";
  readonly ack_policy: "explicit";
  readonly replay_policy: "instant";
  readonly ack_wait_ns: number;
  readonly max_deliver: number;
  readonly max_ack_pending: number;
  readonly max_batch: number;
  readonly max_bytes: number;
  readonly max_expires_ns: number;
}

export interface BrokerTopologyContract {
  readonly stream: BrokerStreamContract;
  readonly consumer: BrokerConsumerContract;
  readonly configuration_sha256: Sha256Hex;
}

export interface BrokerTopologyInspection {
  readonly streamInfo: StreamInfo;
  readonly consumerInfo?: ConsumerInfo | undefined;
  readonly observedStreamCreatedAt: string;
  readonly configurationSha256: Sha256Hex;
}

export interface InspectBrokerTopologyOptions {
  readonly verifyConsumer?: boolean | undefined;
  readonly expectedStreamCreatedAt?: string | undefined;
  readonly expectedConfigurationSha256?: Sha256Hex | undefined;
}

export interface BrokerHealthStatus {
  readonly healthy: boolean;
  readonly mode: BrokerMode;
  readonly encrypted: boolean;
  readonly connectedServers: readonly string[];
  readonly streamName: string;
  readonly consumerName: string;
  readonly brokerGenerationId: BrokerGenerationId;
  readonly lastError?: string | undefined;
}

export interface BrokerTopologyManager {
  readonly streams: {
    info(stream: string): Promise<StreamInfo>;
    add(cfg: Partial<StreamInfo["config"]> & { name: string }): Promise<StreamInfo>;
  };
  readonly consumers: {
    info(stream: string, consumer: string): Promise<ConsumerInfo>;
    add(stream: string, cfg: Partial<ConsumerInfo["config"]>): Promise<ConsumerInfo>;
  };
}

export interface BrokerAdapter {
  readonly mode: BrokerMode;
  readonly brokerGenerationId: BrokerGenerationId;
  readonly streamName: string;
  readonly consumerName: string;
  readonly subjectPrefix: string;
  publish(input: BrokerPublishInput): Promise<BrokerPublishResult>;
  pullBatch(options?: BrokerPullOptions): Promise<readonly BrokerMessage[]>;
  consume(options?: BrokerConsumeOptions): AsyncIterable<BrokerMessage>;
  inspectTopology?(options?: InspectBrokerTopologyOptions): Promise<BrokerTopologyInspection>;
  getHealth(): Promise<BrokerHealthStatus>;
  close(): Promise<void>;
}

export function normalizeSubjectPrefix(subjectPrefix: string | undefined): string {
  const prefix = subjectPrefix ?? "";
  if (
    typeof prefix !== "string" ||
    prefix.length > SUBJECT_PREFIX_MAX_LEN ||
    !SUBJECT_PREFIX_REGEX.test(prefix)
  ) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Invalid broker subject_prefix "${String(subjectPrefix)}"`,
      fieldErrors: [{ path: "subject_prefix", code: "INVALID_VALUE" }]
    });
  }
  return prefix;
}

export function formatStreamSubjectPattern(subjectPrefix = ""): string {
  const normalized = normalizeSubjectPrefix(subjectPrefix);
  return `${normalized}${BROKER_EVENT_SUBJECT_SUFFIX}`;
}

export function deriveAcceptedEventSubject(
  projectId: ProjectId | string,
  subjectPrefix = ""
): string {
  const validProjectId = parseProjectId(projectId, "project_id");
  const normalized = normalizeSubjectPrefix(subjectPrefix);
  return `${normalized}${formatBrokerEventSubject(validProjectId)}`;
}

export function sanitizeTraceHeadersForPublish(
  traceContext: BrokerTraceHeaders | undefined,
  options: SanitizeTracestateOptions = {}
): BrokerTraceHeaders {
  if (traceContext === undefined || traceContext.traceparent === undefined) {
    return Object.freeze({});
  }
  const parsed = parseTraceparent(traceContext.traceparent);
  if (!parsed.valid) {
    return Object.freeze({});
  }
  const cleanState =
    traceContext.tracestate !== undefined
      ? sanitizeTracestate(traceContext.tracestate, {
          allowedVendorKeys: options.allowedVendorKeys,
          allowAnyValidVendorKey:
            options.allowAnyValidVendorKey ??
            (options.allowedVendorKeys !== undefined ? undefined : false),
          maxEntries: options.maxEntries,
          maxBytes: options.maxBytes
        })
      : "";
  return Object.freeze({
    traceparent: parsed.canonical,
    ...(cleanState.length > 0 ? { tracestate: cleanState } : {})
  });
}

export function extractTraceHeadersFromRecord(
  rawHeaders: Readonly<Record<string, string | readonly string[] | undefined>>,
  options: SanitizeTracestateOptions = {}
): BrokerExtractedTransportTrace {
  return sanitizeIncomingTraceHeaders(rawHeaders, options);
}

export function natsHeadersToRecord(
  hdrs: MsgHdrs | undefined
): Readonly<Record<string, readonly string[]>> {
  const record: Record<string, readonly string[]> = Object.create(null) as Record<
    string,
    readonly string[]
  >;
  if (hdrs === undefined) {
    return Object.freeze(record);
  }
  for (const [key, values] of hdrs) {
    if (key === "__proto__" || key === "constructor" || key === "prototype") {
      continue;
    }
    record[key] = Object.freeze([...values]);
  }
  return Object.freeze(record);
}

export function readHeaderFirstValue(
  rawHeaders: Readonly<Record<string, readonly string[] | undefined>>,
  headerName: string
): string | undefined {
  const exact = rawHeaders[headerName];
  if (exact !== undefined && exact.length > 0) {
    return exact[0];
  }
  const targetLower = headerName.toLowerCase();
  for (const [key, values] of Object.entries(rawHeaders)) {
    if (key.toLowerCase() === targetLower && values !== undefined && values.length > 0) {
      return values[0];
    }
  }
  return undefined;
}
