import crypto from "node:crypto";
import {
  type BrokerGenerationId,
  ValidationDomainError,
  parseBrokerGenerationId,
  parseOutboxId,
  parsePositiveInt64String,
  parseProjectId
} from "@relayquill/domain";
import {
  decodeBrokerNotificationEnvelope,
  encodeBrokerMessageId
} from "@relayquill/contracts";
import {
  AckPolicy,
  type ConsumerConfig,
  type ConsumerInfo,
  DeliverPolicy,
  DiscardPolicy,
  JetStreamApiCodes,
  JetStreamApiError,
  ReplayPolicy,
  RetentionPolicy,
  StorageType,
  type StreamConfig,
  type StreamInfo
} from "@nats-io/jetstream";
import {
  BROKER_DEFAULT_ACK_WAIT_NS,
  BROKER_DEFAULT_DUPLICATE_WINDOW_NS,
  BROKER_DEFAULT_MAX_AGE_NS,
  BROKER_DEFAULT_MAX_BYTES,
  BROKER_DEFAULT_MAX_MSGS,
  BROKER_DEFAULT_PULL_MAX_EXPIRES_NS,
  BROKER_DEFAULT_REPLICAS,
  BROKER_EVENT_MAX_PAYLOAD_BYTES,
  BROKER_EVENT_STREAM_NAME,
  BrokerCapacityError,
  BrokerPublishError,
  BrokerUnavailableError,
  FANOUT_CONSUMER_NAME,
  FANOUT_MAX_ACK_PENDING,
  FANOUT_MAX_DELIVER,
  FANOUT_PULL_MAX_BATCH,
  FANOUT_PULL_MAX_BYTES,
  type BrokerAdapter,
  type BrokerConsumeOptions,
  type BrokerHealthStatus,
  type BrokerMessage,
  type BrokerPublishInput,
  type BrokerPublishResult,
  type BrokerPullOptions,
  type BrokerTopologyInspection,
  type BrokerTopologyManager,
  type InspectBrokerTopologyOptions,
  deriveAcceptedEventSubject,
  extractTraceHeadersFromRecord,
  formatStreamSubjectPattern,
  normalizeSubjectPrefix,
  sanitizeTraceHeadersForPublish
} from "./types.js";
import { validateNakDelayMs, validatePullBounds } from "./consumer.js";
import { buildBrokerTopologyContract, inspectBrokerTopology } from "./stream-contract.js";

const NS_PER_MS = 1_000_000;

export function matchNatsSubject(pattern: string, subject: string): boolean {
  const patTokens = pattern.split(".");
  const subTokens = subject.split(".");

  for (let i = 0; i < patTokens.length; i += 1) {
    const pat = patTokens[i];
    if (pat === ">") {
      return i < subTokens.length;
    }
    if (i >= subTokens.length) {
      return false;
    }
    if (pat !== "*" && pat !== subTokens[i]) {
      return false;
    }
  }

  return patTokens.length === subTokens.length;
}

export interface InMemoryStreamRecord {
  readonly stream: string;
  readonly seq: number;
  readonly subject: string;
  readonly payload: Uint8Array;
  readonly headers: Readonly<Record<string, readonly string[]>>;
  readonly msgId?: string | undefined;
  readonly storedAtMs: number;
}

interface PendingDeliveryState {
  deliveredCount: number;
  firstDeliveredAtMs: number;
  deadlineAtMs: number;
  availableAtMs: number;
  inFlight: boolean;
}

interface InMemoryStreamState {
  name: string;
  brokerGenerationId: BrokerGenerationId;
  created: string;
  subjects: string[];
  storage: StorageType;
  retention: RetentionPolicy;
  discard: DiscardPolicy;
  discardNewPerSubject: boolean;
  maxMsgs: number;
  maxBytes: number;
  maxMsgSize: number;
  maxAgeNs: number;
  duplicateWindowNs: number;
  replicas: number;
  nextSeq: number;
  deletedSeqs: number[];
  messages: InMemoryStreamRecord[];
  totalBytes: number;
  dedupIndex: Map<string, { readonly seq: number; readonly storedAtMs: number }>;
  consumers: Map<string, InMemoryConsumerState>;
}

interface InMemoryConsumerState {
  streamName: string;
  durableName: string;
  created: string;
  deliverPolicy: DeliverPolicy;
  ackPolicy: AckPolicy;
  replayPolicy: ReplayPolicy;
  ackWaitNs: number;
  maxDeliver: number;
  maxAckPending: number;
  maxBatch: number;
  maxBytes: number;
  maxExpiresNs: number;
  nextCursorSeq: number;
  lastDeliveredStreamSeq: number;
  lastDeliveredConsumerSeq: number;
  lastDeliveredAtNs: number;
  ackFloorStreamSeq: number;
  ackFloorConsumerSeq: number;
  lastAckedAtNs: number;
  totalRedelivered: number;
  pending: Map<number, PendingDeliveryState>;
  acked: Set<number>;
  terminated: Map<number, string | undefined>;
  maxDeliverExceeded: Set<number>;
}

export interface InMemoryStreamStats {
  readonly name: string;
  readonly brokerGenerationId: BrokerGenerationId;
  readonly created: string;
  readonly messages: number;
  readonly bytes: number;
  readonly firstSeq: number;
  readonly lastSeq: number;
  readonly dedupEntries: number;
}

export interface InMemoryConsumerStats {
  readonly durableName: string;
  readonly pending: number;
  readonly inFlight: number;
  readonly acked: number;
  readonly terminated: number;
  readonly maxDeliverExceeded: number;
  readonly totalRedelivered: number;
}

export interface InMemoryJetStreamBrokerOptions {
  readonly nowMs?: (() => number) | undefined;
  readonly streamName?: string | undefined;
  readonly consumerName?: string | undefined;
  readonly subjectPrefix?: string | undefined;
  readonly replicas?: 1 | 3 | undefined;
  readonly maxMsgs?: number | undefined;
  readonly maxBytes?: number | undefined;
  readonly maxAgeNs?: number | undefined;
  readonly duplicateWindowNs?: number | undefined;
  readonly ackWaitNs?: number | undefined;
  readonly maxDeliver?: number | undefined;
  readonly maxAckPending?: number | undefined;
  readonly maxBatch?: number | undefined;
  readonly pullMaxBytes?: number | undefined;
  readonly maxExpiresNs?: number | undefined;
  readonly autoCreateTopology?: boolean | undefined;
  readonly brokerGenerationId?: BrokerGenerationId | string | undefined;
  readonly validateEnvelopePayload?: boolean | undefined;
  readonly allowedTracestateKeys?: readonly string[] | undefined;
  readonly allowAnyValidTracestateKey?: boolean | undefined;
}

export type InMemoryFaultSpec =
  | {
      readonly kind: "commit_drop_puback";
      readonly count?: number | undefined;
      readonly predicate?: ((input: BrokerPublishInput) => boolean) | undefined;
    }
  | {
      readonly kind: "stream_full";
      readonly enabled: boolean;
    }
  | {
      readonly kind: "unavailable";
      readonly enabled: boolean;
    }
  | {
      readonly kind: "drop_ack";
      readonly count?: number | undefined;
    };

export class InMemoryJetStreamBroker implements BrokerAdapter {
  readonly mode = "in_memory_test" as const;
  readonly streamName: string;
  readonly consumerName: string;
  readonly subjectPrefix: string;
  readonly manager: BrokerTopologyManager;

  readonly #nowMs: () => number;
  readonly #streams = new Map<string, InMemoryStreamState>();
  readonly #validateEnvelopePayload: boolean;
  readonly #allowedTracestateKeys: readonly string[] | undefined;
  readonly #allowAnyValidTracestateKey: boolean | undefined;
  readonly #wakeWaiters = new Set<() => void>();

  #forceStreamFull = false;
  #forceUnavailable = false;
  #dropPubAckCount = 0;
  #dropPubAckPredicate: ((input: BrokerPublishInput) => boolean) | undefined;
  #dropAckCount = 0;
  #closed = false;
  #lastGenerationId: BrokerGenerationId;
  #defaultReplicas: 1 | 3;
  #defaultMaxMsgs: number;
  #defaultMaxBytes: number;
  #defaultMaxAgeNs: number;
  #defaultDuplicateWindowNs: number;
  #defaultAckWaitNs: number;
  #defaultMaxDeliver: number;
  #defaultMaxAckPending: number;
  #defaultMaxBatch: number;
  #defaultPullMaxBytes: number;
  #defaultMaxExpiresNs: number;

  constructor(options: InMemoryJetStreamBrokerOptions = {}) {
    this.#nowMs = options.nowMs ?? (() => Date.now());
    this.streamName = options.streamName ?? BROKER_EVENT_STREAM_NAME;
    this.consumerName = options.consumerName ?? FANOUT_CONSUMER_NAME;
    this.subjectPrefix = normalizeSubjectPrefix(options.subjectPrefix);
    this.#validateEnvelopePayload = options.validateEnvelopePayload ?? true;
    this.#allowedTracestateKeys = options.allowedTracestateKeys;
    this.#allowAnyValidTracestateKey = options.allowAnyValidTracestateKey;

    this.#defaultReplicas = options.replicas ?? BROKER_DEFAULT_REPLICAS;
    this.#defaultMaxMsgs = options.maxMsgs ?? BROKER_DEFAULT_MAX_MSGS;
    this.#defaultMaxBytes = options.maxBytes ?? BROKER_DEFAULT_MAX_BYTES;
    this.#defaultMaxAgeNs = options.maxAgeNs ?? BROKER_DEFAULT_MAX_AGE_NS;
    this.#defaultDuplicateWindowNs = options.duplicateWindowNs ?? BROKER_DEFAULT_DUPLICATE_WINDOW_NS;
    this.#defaultAckWaitNs = options.ackWaitNs ?? BROKER_DEFAULT_ACK_WAIT_NS;
    this.#defaultMaxDeliver = options.maxDeliver ?? FANOUT_MAX_DELIVER;
    this.#defaultMaxAckPending = options.maxAckPending ?? FANOUT_MAX_ACK_PENDING;
    this.#defaultMaxBatch = options.maxBatch ?? FANOUT_PULL_MAX_BATCH;
    this.#defaultPullMaxBytes = options.pullMaxBytes ?? FANOUT_PULL_MAX_BYTES;
    this.#defaultMaxExpiresNs = options.maxExpiresNs ?? BROKER_DEFAULT_PULL_MAX_EXPIRES_NS;

    this.#lastGenerationId = parseBrokerGenerationId(
      options.brokerGenerationId ?? crypto.randomUUID(),
      "brokerGenerationId"
    );

    this.manager = Object.freeze({
      streams: {
        info: (name: string) => Promise.resolve(this.#getStreamInfo(name)),
        add: (cfg: Partial<StreamConfig> & { name: string }) =>
          Promise.resolve(this.#addStream(cfg))
      },
      consumers: {
        info: (stream: string, consumer: string) =>
          Promise.resolve(this.#getConsumerInfo(stream, consumer)),
        add: (stream: string, cfg: Partial<ConsumerConfig>) =>
          Promise.resolve(this.#addConsumer(stream, cfg))
      }
    });

    if (options.autoCreateTopology !== false) {
      const stream = this.#createStreamInternal({
        name: this.streamName,
        subjects: [formatStreamSubjectPattern(this.subjectPrefix)],
        storage: StorageType.File,
        retention: RetentionPolicy.Limits,
        discard: DiscardPolicy.New,
        discard_new_per_subject: false,
        max_msgs: this.#defaultMaxMsgs,
        max_bytes: this.#defaultMaxBytes,
        max_msg_size: BROKER_EVENT_MAX_PAYLOAD_BYTES,
        max_age: this.#defaultMaxAgeNs,
        duplicate_window: this.#defaultDuplicateWindowNs,
        num_replicas: this.#defaultReplicas
      }, this.#lastGenerationId);
      this.#createConsumerInternal(stream, {
        durable_name: this.consumerName,
        deliver_policy: DeliverPolicy.All,
        ack_policy: AckPolicy.Explicit,
        replay_policy: ReplayPolicy.Instant,
        ack_wait: this.#defaultAckWaitNs,
        max_deliver: this.#defaultMaxDeliver,
        max_ack_pending: this.#defaultMaxAckPending,
        max_batch: this.#defaultMaxBatch,
        max_bytes: this.#defaultPullMaxBytes,
        max_expires: this.#defaultMaxExpiresNs
      });
    }
  }

  get brokerGenerationId(): BrokerGenerationId {
    const stream = this.#streams.get(this.streamName);
    return stream !== undefined ? stream.brokerGenerationId : this.#lastGenerationId;
  }

  #assertOpen(): void {
    if (this.#closed) {
      throw new BrokerUnavailableError({
        message: "InMemoryJetStreamBroker is closed",
        retryable: false,
        acceptance: "known_rejected",
        stream: this.streamName,
        reasonCode: "BROKER_CLOSED"
      });
    }
  }

  #notifyWaiters(): void {
    for (const wake of this.#wakeWaiters) {
      wake();
    }
  }

  #createStreamInternal(
    cfg: Partial<StreamConfig> & { name: string },
    generationId: BrokerGenerationId = parseBrokerGenerationId(crypto.randomUUID(), "generation")
  ): InMemoryStreamState {
    if (this.#streams.has(cfg.name)) {
      throw new JetStreamApiError({
        code: 400,
        err_code: 10058,
        description: `stream name "${cfg.name}" already in use`
      });
    }
    const nowIso = new Date(this.#nowMs()).toISOString();
    const state: InMemoryStreamState = {
      name: cfg.name,
      brokerGenerationId: generationId,
      created: nowIso,
      subjects: [...(cfg.subjects ?? [formatStreamSubjectPattern(this.subjectPrefix)])],
      storage: cfg.storage ?? StorageType.File,
      retention: cfg.retention ?? RetentionPolicy.Limits,
      discard: cfg.discard ?? DiscardPolicy.New,
      discardNewPerSubject: cfg.discard_new_per_subject ?? false,
      maxMsgs: cfg.max_msgs ?? this.#defaultMaxMsgs,
      maxBytes: cfg.max_bytes ?? this.#defaultMaxBytes,
      maxMsgSize: cfg.max_msg_size ?? BROKER_EVENT_MAX_PAYLOAD_BYTES,
      maxAgeNs: cfg.max_age ?? this.#defaultMaxAgeNs,
      duplicateWindowNs: cfg.duplicate_window ?? this.#defaultDuplicateWindowNs,
      replicas: cfg.num_replicas ?? this.#defaultReplicas,
      nextSeq: 1,
      deletedSeqs: [],
      messages: [],
      totalBytes: 0,
      dedupIndex: new Map(),
      consumers: new Map()
    };
    this.#streams.set(cfg.name, state);
    if (cfg.name === this.streamName) {
      this.#lastGenerationId = generationId;
    }
    return state;
  }

  #createConsumerInternal(
    stream: InMemoryStreamState,
    cfg: Partial<ConsumerConfig>
  ): InMemoryConsumerState {
    const durableName = cfg.durable_name ?? cfg.name;
    if (!durableName) {
      throw new ValidationDomainError({
        code: "INVALID_VALUE",
        message: "Consumer durable_name is required"
      });
    }
    if (stream.consumers.has(durableName)) {
      throw new JetStreamApiError({
        code: 400,
        err_code: 10013,
        description: `consumer "${durableName}" already exists`
      });
    }
    const nowMs = this.#nowMs();
    const consumer: InMemoryConsumerState = {
      streamName: stream.name,
      durableName,
      created: new Date(nowMs).toISOString(),
      deliverPolicy: cfg.deliver_policy ?? DeliverPolicy.All,
      ackPolicy: cfg.ack_policy ?? AckPolicy.Explicit,
      replayPolicy: cfg.replay_policy ?? ReplayPolicy.Instant,
      ackWaitNs: cfg.ack_wait ?? this.#defaultAckWaitNs,
      maxDeliver: cfg.max_deliver ?? this.#defaultMaxDeliver,
      maxAckPending: cfg.max_ack_pending ?? this.#defaultMaxAckPending,
      maxBatch: cfg.max_batch ?? this.#defaultMaxBatch,
      maxBytes: cfg.max_bytes ?? this.#defaultPullMaxBytes,
      maxExpiresNs: cfg.max_expires ?? this.#defaultMaxExpiresNs,
      nextCursorSeq: 1,
      lastDeliveredStreamSeq: 0,
      lastDeliveredConsumerSeq: 0,
      lastDeliveredAtNs: 0,
      ackFloorStreamSeq: 0,
      ackFloorConsumerSeq: 0,
      lastAckedAtNs: 0,
      totalRedelivered: 0,
      pending: new Map(),
      acked: new Set(),
      terminated: new Map(),
      maxDeliverExceeded: new Set()
    };
    stream.consumers.set(durableName, consumer);
    return consumer;
  }

  #toStreamInfo(stream: InMemoryStreamState): StreamInfo {
    const nowMs = this.#nowMs();
    this.#pruneStreamExpired(stream, nowMs);

    const firstMsg = stream.messages[0];
    const lastMsg = stream.messages[stream.messages.length - 1];

    return {
      total: 0,
      offset: 0,
      limit: 0,
      created: stream.created,
      config: {
        name: stream.name,
        subjects: [...stream.subjects],
        retention: stream.retention,
        storage: stream.storage,
        discard: stream.discard,
        discard_new_per_subject: stream.discardNewPerSubject,
        max_consumers: -1,
        max_msgs_per_subject: -1,
        max_msgs: stream.maxMsgs,
        max_age: stream.maxAgeNs,
        max_bytes: stream.maxBytes,
        max_msg_size: stream.maxMsgSize,
        duplicate_window: stream.duplicateWindowNs,
        allow_rollup_hdrs: false,
        num_replicas: stream.replicas,
        deny_delete: false,
        deny_purge: false,
        allow_direct: false,
        mirror_direct: false,
        sealed: false,
        first_seq: 1,
        allow_msg_counter: false,
        persist_mode: "default"
      },
      state: {
        messages: stream.messages.length,
        bytes: stream.totalBytes,
        first_seq: firstMsg?.seq ?? 0,
        first_ts: firstMsg !== undefined ? new Date(firstMsg.storedAtMs).toISOString() : new Date(0).toISOString(),
        last_seq: lastMsg?.seq ?? 0,
        last_ts: lastMsg !== undefined ? new Date(lastMsg.storedAtMs).toISOString() : new Date(0).toISOString(),
        num_deleted: stream.deletedSeqs.length,
        deleted: [...stream.deletedSeqs],
        lost: { msgs: null, bytes: 0 },
        consumer_count: stream.consumers.size
      }
    };
  }

  #toConsumerInfo(stream: InMemoryStreamState, consumer: InMemoryConsumerState): ConsumerInfo {
    const nowMs = this.#nowMs();
    this.#reconcileConsumerPending(stream, consumer, nowMs);

    const pendingTotal = stream.messages.filter((m) => m.seq >= consumer.nextCursorSeq).length;

    return {
      stream_name: consumer.streamName,
      name: consumer.durableName,
      created: consumer.created,
      config: {
        durable_name: consumer.durableName,
        name: consumer.durableName,
        deliver_policy: consumer.deliverPolicy,
        ack_policy: consumer.ackPolicy,
        replay_policy: consumer.replayPolicy,
        ack_wait: consumer.ackWaitNs,
        max_deliver: consumer.maxDeliver,
        max_ack_pending: consumer.maxAckPending,
        max_batch: consumer.maxBatch,
        max_bytes: consumer.maxBytes,
        max_expires: consumer.maxExpiresNs
      },
      delivered: {
        consumer_seq: consumer.lastDeliveredConsumerSeq,
        stream_seq: consumer.lastDeliveredStreamSeq,
        last_active: consumer.lastDeliveredAtNs
      },
      ack_floor: {
        consumer_seq: consumer.ackFloorConsumerSeq,
        stream_seq: consumer.ackFloorStreamSeq,
        last_active: consumer.lastAckedAtNs
      },
      num_ack_pending: consumer.pending.size,
      num_redelivered: consumer.totalRedelivered,
      num_waiting: 0,
      num_pending: pendingTotal,
      push_bound: false,
      pause_remaining: 0
    };
  }

  #getStreamInfo(name: string): StreamInfo {
    this.#assertOpen();
    if (this.#forceUnavailable) {
      throw new BrokerUnavailableError({
        message: "Broker unavailable (injected fault)",
        retryable: true,
        acceptance: "known_rejected",
        stream: name,
        reasonCode: "FORCED_UNAVAILABLE"
      });
    }
    const stream = this.#streams.get(name);
    if (stream === undefined) {
      throw new JetStreamApiError({
        code: 404,
        err_code: JetStreamApiCodes.StreamNotFound,
        description: `stream not found: ${name}`
      });
    }
    return this.#toStreamInfo(stream);
  }

  #addStream(cfg: Partial<StreamConfig> & { name: string }): StreamInfo {
    this.#assertOpen();
    const stream = this.#createStreamInternal(cfg);
    return this.#toStreamInfo(stream);
  }

  #getConsumerInfo(streamName: string, consumerName: string): ConsumerInfo {
    this.#assertOpen();
    if (this.#forceUnavailable) {
      throw new BrokerUnavailableError({
        message: "Broker unavailable (injected fault)",
        retryable: true,
        acceptance: "known_rejected",
        stream: streamName,
        reasonCode: "FORCED_UNAVAILABLE"
      });
    }
    const stream = this.#streams.get(streamName);
    if (stream === undefined) {
      throw new JetStreamApiError({
        code: 404,
        err_code: JetStreamApiCodes.StreamNotFound,
        description: `stream not found: ${streamName}`
      });
    }
    const consumer = stream.consumers.get(consumerName);
    if (consumer === undefined) {
      throw new JetStreamApiError({
        code: 404,
        err_code: JetStreamApiCodes.ConsumerNotFound,
        description: `consumer not found: ${consumerName}`
      });
    }
    return this.#toConsumerInfo(stream, consumer);
  }

  #addConsumer(streamName: string, cfg: Partial<ConsumerConfig>): ConsumerInfo {
    this.#assertOpen();
    const stream = this.#streams.get(streamName);
    if (stream === undefined) {
      throw new JetStreamApiError({
        code: 404,
        err_code: JetStreamApiCodes.StreamNotFound,
        description: `stream not found: ${streamName}`
      });
    }
    const consumer = this.#createConsumerInternal(stream, cfg);
    return this.#toConsumerInfo(stream, consumer);
  }

  #findStreamForSubject(subject: string): InMemoryStreamState | undefined {
    for (const stream of this.#streams.values()) {
      if (stream.subjects.some((pat) => matchNatsSubject(pat, subject))) {
        return stream;
      }
    }
    return undefined;
  }

  #pruneStreamExpired(stream: InMemoryStreamState, nowMs: number): number {
    if (!Number.isFinite(stream.maxAgeNs) || stream.maxAgeNs <= 0) {
      return 0;
    }
    const maxAgeMs = stream.maxAgeNs / NS_PER_MS;
    let removed = 0;
    const kept: InMemoryStreamRecord[] = [];
    for (const msg of stream.messages) {
      if (nowMs - msg.storedAtMs >= maxAgeMs) {
        stream.totalBytes -= msg.payload.byteLength;
        stream.deletedSeqs.push(msg.seq);
        removed += 1;
      } else {
        kept.push(msg);
      }
    }
    stream.messages = kept;
    return removed;
  }

  #pruneDedupWindow(stream: InMemoryStreamState, nowMs: number): void {
    const windowMs = stream.duplicateWindowNs / NS_PER_MS;
    for (const [msgId, entry] of stream.dedupIndex.entries()) {
      if (nowMs - entry.storedAtMs >= windowMs) {
        stream.dedupIndex.delete(msgId);
      }
    }
  }

  #advanceAckFloor(consumer: InMemoryConsumerState, ackedSeq: number): void {
    if (ackedSeq <= consumer.ackFloorStreamSeq) {
      return;
    }
    let next = consumer.ackFloorStreamSeq + 1;
    while (consumer.acked.has(next) || consumer.terminated.has(next) || consumer.maxDeliverExceeded.has(next)) {
      consumer.ackFloorStreamSeq = next;
      consumer.ackFloorConsumerSeq += 1;
      next += 1;
    }
  }

  #reconcileConsumerPending(
    stream: InMemoryStreamState,
    consumer: InMemoryConsumerState,
    nowMs: number
  ): {
    activeInFlight: number;
    redeliverCandidates: Array<{ seq: number; record: InMemoryStreamRecord; state: PendingDeliveryState }>;
  } {
    const msgBySeq = new Map(stream.messages.map((m) => [m.seq, m]));
    let activeInFlight = 0;
    const redeliverCandidates: Array<{
      seq: number;
      record: InMemoryStreamRecord;
      state: PendingDeliveryState;
    }> = [];

    for (const [seq, state] of consumer.pending.entries()) {
      const record = msgBySeq.get(seq);
      if (record === undefined) {
        consumer.pending.delete(seq);
        continue;
      }
      if (state.inFlight && nowMs >= state.deadlineAtMs) {
        state.inFlight = false;
        state.availableAtMs = nowMs;
      }
      if (state.inFlight) {
        activeInFlight += 1;
      } else if (nowMs >= state.availableAtMs) {
        if (state.deliveredCount >= consumer.maxDeliver) {
          consumer.pending.delete(seq);
          consumer.maxDeliverExceeded.add(seq);
        } else {
          redeliverCandidates.push({ seq, record, state });
        }
      }
    }

    return { activeInFlight, redeliverCandidates };
  }

  #buildMessageHandle(
    stream: InMemoryStreamState,
    consumer: InMemoryConsumerState,
    record: InMemoryStreamRecord,
    deliveryCount: number,
    deliverySequence: number,
    pendingEstimate: number,
    pullOpts: BrokerPullOptions
  ): BrokerMessage {
    const state = consumer.pending.get(record.seq);
    const expectedDeliveryCount = deliveryCount;
    let settled = false;

    const isCurrentAttempt = (): boolean => {
      if (this.#closed) {
        return false;
      }
      const current = consumer.pending.get(record.seq);
      return (
        current === state &&
        state !== undefined &&
        state.inFlight &&
        state.deliveredCount === expectedDeliveryCount
      );
    };

    const trace = extractTraceHeadersFromRecord(record.headers, {
      allowedVendorKeys: pullOpts.allowedTracestateKeys ?? this.#allowedTracestateKeys,
      allowAnyValidVendorKey: pullOpts.allowAnyValidTracestateKey ?? this.#allowAnyValidTracestateKey
    });

    const settleAck = (requireConfirm: boolean): boolean => {
      if (settled || !isCurrentAttempt()) {
        return false;
      }
      settled = true;
      if (this.#dropAckCount > 0) {
        this.#dropAckCount -= 1;
        if (requireConfirm) {
          throw new BrokerUnavailableError({
            message: `ACK confirmation lost for ${stream.name}#${record.seq}`,
            retryable: true,
            acceptance: "unknown",
            stream: stream.name,
            reasonCode: "ACK_CONFIRM_TIMEOUT"
          });
        }
        return false;
      }
      consumer.pending.delete(record.seq);
      consumer.acked.add(record.seq);
      consumer.lastAckedAtNs = this.#nowMs() * NS_PER_MS;
      this.#advanceAckFloor(consumer, record.seq);
      this.#notifyWaiters();
      return true;
    };

    return Object.freeze({
      stream: stream.name,
      consumer: consumer.durableName,
      subject: record.subject,
      seq: record.seq,
      deliveryCount,
      deliverySequence,
      redelivered: deliveryCount > 1,
      pending: pendingEstimate,
      timestampNanos: BigInt(record.storedAtMs) * BigInt(NS_PER_MS),
      payload: new Uint8Array(record.payload),
      headers: record.headers,
      ...(record.msgId !== undefined ? { msgId: record.msgId } : {}),
      trace,
      brokerGenerationId: stream.brokerGenerationId,
      ack: () => {
        settleAck(false);
        return Promise.resolve();
      },
      ackAck: () => {
        return Promise.resolve(settleAck(true));
      },
      nak: (delayMs?: number) => {
        const validatedDelay = validateNakDelayMs(delayMs) ?? 0;
        if (settled || !isCurrentAttempt() || state === undefined) {
          return Promise.resolve();
        }
        settled = true;
        const nowMs = this.#nowMs();
        state.inFlight = false;
        state.availableAtMs = nowMs + validatedDelay;
        state.deadlineAtMs = Number.POSITIVE_INFINITY;
        this.#notifyWaiters();
        return Promise.resolve();
      },
      working: () => {
        if (settled || !isCurrentAttempt() || state === undefined) {
          return Promise.resolve();
        }
        const nowMs = this.#nowMs();
        state.deadlineAtMs = nowMs + consumer.ackWaitNs / NS_PER_MS;
        return Promise.resolve();
      },
      term: (reason?: string) => {
        if (settled || !isCurrentAttempt()) {
          return Promise.resolve();
        }
        settled = true;
        consumer.pending.delete(record.seq);
        consumer.terminated.set(record.seq, reason);
        this.#advanceAckFloor(consumer, record.seq);
        this.#notifyWaiters();
        return Promise.resolve();
      }
    });
  }

  async publish(input: BrokerPublishInput): Promise<BrokerPublishResult> {
    this.#assertOpen();
    if (this.#forceUnavailable) {
      throw new BrokerUnavailableError({
        message: "InMemoryJetStreamBroker is unavailable (injected fault)",
        retryable: true,
        acceptance: "known_rejected",
        stream: this.streamName,
        reasonCode: "FORCED_UNAVAILABLE"
      });
    }

    const outboxId = parseOutboxId(input.outboxId, "outboxId");
    const projectId = parseProjectId(input.projectId, "projectId");
    const publicationGeneration = parsePositiveInt64String(
      typeof input.publicationGeneration === "bigint"
        ? input.publicationGeneration.toString(10)
        : input.publicationGeneration,
      "publicationGeneration"
    );
    const subject = deriveAcceptedEventSubject(projectId, this.subjectPrefix);
    if (input.subject !== undefined && input.subject !== subject) {
      throw new ValidationDomainError({
        code: "INVALID_VALUE",
        message: `Publish subject "${input.subject}" does not match derived subject "${subject}"`,
        acceptance: "known_rejected",
        boundary: "published"
      });
    }

    if (!(input.envelopeBytes instanceof Uint8Array)) {
      throw new ValidationDomainError({
        code: "INVALID_VALUE",
        message: "envelopeBytes must be a Uint8Array",
        acceptance: "known_rejected",
        boundary: "published"
      });
    }

    const stream = this.#findStreamForSubject(subject);
    if (stream === undefined) {
      throw new BrokerUnavailableError({
        message: `No JetStream stream matches subject "${subject}"`,
        retryable: true,
        acceptance: "known_rejected",
        stream: this.streamName,
        subject,
        reasonCode: "STREAM_NOT_FOUND"
      });
    }

    if (
      input.expectedBrokerGenerationId !== undefined &&
      parseBrokerGenerationId(input.expectedBrokerGenerationId, "expectedBrokerGenerationId") !==
        stream.brokerGenerationId
    ) {
      throw new BrokerUnavailableError({
        message: "Broker generation ID changed unexpectedly; refusing unverified publication",
        retryable: false,
        acceptance: "known_rejected",
        stream: stream.name,
        subject,
        reasonCode: "BROKER_GENERATION_MISMATCH"
      });
    }

    if (input.envelopeBytes.byteLength === 0 || input.envelopeBytes.byteLength > stream.maxMsgSize) {
      throw new ValidationDomainError({
        code: input.envelopeBytes.byteLength > stream.maxMsgSize ? "PAYLOAD_TOO_LARGE" : "INVALID_VALUE",
        message: `Broker envelope size ${input.envelopeBytes.byteLength} out of bounds [1, ${stream.maxMsgSize}]`,
        acceptance: "known_rejected",
        boundary: "published"
      });
    }

    if (this.#validateEnvelopePayload) {
      const decoded = decodeBrokerNotificationEnvelope(input.envelopeBytes);
      if (
        decoded.outbox_id !== outboxId ||
        decoded.project_id !== projectId ||
        decoded.publication_generation !== publicationGeneration
      ) {
        throw new ValidationDomainError({
          code: "INVALID_VALUE",
          message: "Broker envelope metadata does not match publish outbox/project/generation identity",
          acceptance: "known_rejected",
          boundary: "published"
        });
      }
    }

    const msgId = encodeBrokerMessageId(outboxId, publicationGeneration);
    const nowMs = this.#nowMs();
    this.#pruneStreamExpired(stream, nowMs);
    this.#pruneDedupWindow(stream, nowMs);

    const existingDedup = stream.dedupIndex.get(msgId);
    if (existingDedup !== undefined) {
      return Promise.resolve(
        Object.freeze({
          stream: stream.name,
          seq: existingDedup.seq,
          duplicate: true,
          brokerGenerationId: stream.brokerGenerationId,
          msgId,
          subject
        })
      );
    }

    const immutableCopy = new Uint8Array(input.envelopeBytes);

    if (this.#forceStreamFull) {
      throw new BrokerCapacityError({
        message: `Stream "${stream.name}" is full (injected fault)`,
        stream: stream.name,
        subject,
        msgId,
        reasonCode: "FORCED_STREAM_FULL"
      });
    }

    if (stream.retention === RetentionPolicy.Limits && stream.discard === DiscardPolicy.New) {
      if (stream.messages.length >= stream.maxMsgs) {
        throw new BrokerCapacityError({
          message: `Stream "${stream.name}" exceeded max_msgs (${stream.maxMsgs})`,
          stream: stream.name,
          subject,
          msgId,
          reasonCode: "MAX_MSGS_EXCEEDED"
        });
      }
      if (stream.totalBytes + immutableCopy.byteLength > stream.maxBytes) {
        throw new BrokerCapacityError({
          message: `Stream "${stream.name}" exceeded max_bytes (${stream.maxBytes})`,
          stream: stream.name,
          subject,
          msgId,
          reasonCode: "MAX_BYTES_EXCEEDED"
        });
      }
    }

    const safeTrace = sanitizeTraceHeadersForPublish(input.traceContext, {
      allowedVendorKeys: this.#allowedTracestateKeys,
      allowAnyValidVendorKey: this.#allowAnyValidTracestateKey
    });
    const headerRecord: Record<string, readonly string[]> = Object.create(null) as Record<
      string,
      readonly string[]
    >;
    headerRecord["Nats-Msg-Id"] = Object.freeze([msgId]);
    if (safeTrace.traceparent !== undefined) {
      headerRecord.traceparent = Object.freeze([safeTrace.traceparent]);
    }
    if (safeTrace.tracestate !== undefined) {
      headerRecord.tracestate = Object.freeze([safeTrace.tracestate]);
    }

    const seq = stream.nextSeq;
    stream.nextSeq += 1;

    const record: InMemoryStreamRecord = Object.freeze({
      stream: stream.name,
      seq,
      subject,
      payload: immutableCopy,
      headers: Object.freeze(headerRecord),
      msgId,
      storedAtMs: nowMs
    });

    stream.messages.push(record);
    stream.totalBytes += immutableCopy.byteLength;
    stream.dedupIndex.set(msgId, { seq, storedAtMs: nowMs });
    this.#notifyWaiters();

    const shouldDropPubAck =
      this.#dropPubAckCount > 0 &&
      (this.#dropPubAckPredicate === undefined || this.#dropPubAckPredicate(input));
    if (shouldDropPubAck) {
      this.#dropPubAckCount -= 1;
      if (this.#dropPubAckCount === 0) {
        this.#dropPubAckPredicate = undefined;
      }
      throw new BrokerPublishError({
        message: `PubAck lost after storing ${stream.name}#${seq} for ${msgId}`,
        classification: "publish_unknown",
        retryable: true,
        acceptance: "unknown",
        stream: stream.name,
        subject,
        msgId,
        reasonCode: "PUBACK_LOST"
      });
    }

    return Promise.resolve(
      Object.freeze({
        stream: stream.name,
        seq,
        duplicate: false,
        brokerGenerationId: stream.brokerGenerationId,
        msgId,
        subject
      })
    );
  }

  pullBatch(options: BrokerPullOptions = {}): Promise<readonly BrokerMessage[]> {
    this.#assertOpen();
    if (this.#forceUnavailable) {
      throw new BrokerUnavailableError({
        message: "InMemoryJetStreamBroker is unavailable (injected fault)",
        retryable: true,
        acceptance: "known_rejected",
        stream: this.streamName,
        reasonCode: "FORCED_UNAVAILABLE"
      });
    }
    if (options.signal?.aborted) {
      return Promise.resolve([]);
    }

    const stream = this.#streams.get(this.streamName);
    if (stream === undefined) {
      throw new BrokerUnavailableError({
        message: `Stream not found: ${this.streamName}`,
        retryable: true,
        acceptance: "known_rejected",
        stream: this.streamName,
        reasonCode: "STREAM_NOT_FOUND"
      });
    }
    const consumer = stream.consumers.get(this.consumerName);
    if (consumer === undefined) {
      throw new BrokerUnavailableError({
        message: `Consumer not found: ${this.consumerName} on stream ${this.streamName}`,
        retryable: true,
        acceptance: "known_rejected",
        stream: this.streamName,
        reasonCode: "CONSUMER_NOT_FOUND"
      });
    }

    const { maxBatch, maxBytes } = validatePullBounds(options, {
      maxBatchLimit: consumer.maxBatch,
      maxBytesLimit: consumer.maxBytes,
      maxExpiresMsLimit: Math.floor(consumer.maxExpiresNs / NS_PER_MS),
      minExpiresMs: 1
    });

    const nowMs = this.#nowMs();
    this.#pruneStreamExpired(stream, nowMs);

    const { activeInFlight: initialInFlight, redeliverCandidates } =
      this.#reconcileConsumerPending(stream, consumer, nowMs);
    let activeInFlight = initialInFlight;

    const delivered: BrokerMessage[] = [];
    let deliveredBytes = 0;

    const canAcceptMore = (nextRecord: InMemoryStreamRecord): boolean => {
      if (delivered.length >= maxBatch) {
        return false;
      }
      if (activeInFlight >= consumer.maxAckPending) {
        return false;
      }
      if (delivered.length > 0 && deliveredBytes + nextRecord.payload.byteLength > maxBytes) {
        return false;
      }
      if (nextRecord.payload.byteLength > maxBytes) {
        return false;
      }
      return true;
    };

    const ackWaitMs = consumer.ackWaitNs / NS_PER_MS;

    redeliverCandidates.sort((a, b) => a.seq - b.seq);
    for (const candidate of redeliverCandidates) {
      if (!canAcceptMore(candidate.record)) {
        break;
      }
      candidate.state.deliveredCount += 1;
      candidate.state.inFlight = true;
      candidate.state.deadlineAtMs = nowMs + ackWaitMs;
      consumer.totalRedelivered += 1;
      consumer.lastDeliveredConsumerSeq += 1;
      consumer.lastDeliveredStreamSeq = Math.max(
        consumer.lastDeliveredStreamSeq,
        candidate.record.seq
      );
      consumer.lastDeliveredAtNs = nowMs * NS_PER_MS;
      activeInFlight += 1;
      deliveredBytes += candidate.record.payload.byteLength;
      const pendingRemaining = Math.max(
        0,
        stream.messages.filter((m) => m.seq >= consumer.nextCursorSeq).length
      );
      delivered.push(
        this.#buildMessageHandle(
          stream,
          consumer,
          candidate.record,
          candidate.state.deliveredCount,
          consumer.lastDeliveredConsumerSeq,
          pendingRemaining,
          options
        )
      );
    }

    for (const record of stream.messages) {
      if (record.seq < consumer.nextCursorSeq) {
        continue;
      }
      consumer.nextCursorSeq = record.seq + 1;
      if (!canAcceptMore(record)) {
        consumer.nextCursorSeq = record.seq;
        break;
      }
      consumer.pending.set(record.seq, {
        deliveredCount: 1,
        firstDeliveredAtMs: nowMs,
        deadlineAtMs: nowMs + ackWaitMs,
        availableAtMs: nowMs,
        inFlight: true
      });
      consumer.lastDeliveredConsumerSeq += 1;
      consumer.lastDeliveredStreamSeq = Math.max(consumer.lastDeliveredStreamSeq, record.seq);
      consumer.lastDeliveredAtNs = nowMs * NS_PER_MS;
      activeInFlight += 1;
      deliveredBytes += record.payload.byteLength;
      const pendingRemaining = Math.max(
        0,
        stream.messages.filter((m) => m.seq >= consumer.nextCursorSeq).length
      );
      delivered.push(
        this.#buildMessageHandle(
          stream,
          consumer,
          record,
          1,
          consumer.lastDeliveredConsumerSeq,
          pendingRemaining,
          options
        )
      );
    }

    return Promise.resolve(Object.freeze(delivered));
  }

  async *consume(options: BrokerConsumeOptions = {}): AsyncIterable<BrokerMessage> {
    const slotWaitMs = options.slotWaitMs ?? 25;
    const idleWaitMs = options.idlePollDelayMs ?? 25;

    while (!this.#closed && !options.signal?.aborted) {
      let batchLimit = options.maxBatch ?? FANOUT_PULL_MAX_BATCH;
      if (options.availableSlots !== undefined) {
        const freeSlots = options.availableSlots();
        if (freeSlots <= 0) {
          await this.#waitForWakeupOrTimeout(slotWaitMs, options.signal);
          continue;
        }
        batchLimit = Math.min(batchLimit, freeSlots);
      }

      const batch = await this.pullBatch({
        ...options,
        maxBatch: batchLimit
      });

      if (batch.length === 0) {
        if (this.#closed || options.signal?.aborted) {
          break;
        }
        await this.#waitForWakeupOrTimeout(idleWaitMs, options.signal);
        continue;
      }

      for (const msg of batch) {
        if (this.#closed || options.signal?.aborted) {
          return;
        }
        yield msg;
      }
    }
  }

  #waitForWakeupOrTimeout(ms: number, signal?: AbortSignal): Promise<void> {
    if (this.#closed || signal?.aborted) {
      return Promise.resolve();
    }
    return new Promise<void>((resolve) => {
      let done = false;
      const finish = (): void => {
        if (done) {
          return;
        }
        done = true;
        clearTimeout(timer);
        this.#wakeWaiters.delete(finish);
        signal?.removeEventListener("abort", finish);
        resolve();
      };

      const timer = setTimeout(finish, Math.max(1, ms));
      timer.unref();
      this.#wakeWaiters.add(finish);
      signal?.addEventListener("abort", finish, { once: true });
    });
  }

  inspectTopology(options: InspectBrokerTopologyOptions = {}): Promise<BrokerTopologyInspection> {
    const contract = buildBrokerTopologyContract({
      streamName: this.streamName,
      consumerName: this.consumerName,
      subjectPrefix: this.subjectPrefix,
      replicas: this.#defaultReplicas,
      maxMsgs: this.#defaultMaxMsgs,
      maxBytes: this.#defaultMaxBytes,
      maxAgeNs: this.#defaultMaxAgeNs,
      ackWaitMs: Math.floor(this.#defaultAckWaitNs / NS_PER_MS),
      maxDeliver: this.#defaultMaxDeliver,
      maxAckPending: this.#defaultMaxAckPending,
      maxBatch: this.#defaultMaxBatch,
      pullMaxBytes: this.#defaultPullMaxBytes,
      maxExpiresMs: Math.floor(this.#defaultMaxExpiresNs / NS_PER_MS)
    });
    return inspectBrokerTopology(this.manager, contract, options);
  }

  getHealth(): Promise<BrokerHealthStatus> {
    const healthy = !this.#closed && !this.#forceUnavailable && this.#streams.has(this.streamName);
    return Promise.resolve(
      Object.freeze({
        healthy,
        mode: this.mode,
        encrypted: false,
        connectedServers: Object.freeze(["in-memory"]),
        streamName: this.streamName,
        consumerName: this.consumerName,
        brokerGenerationId: this.brokerGenerationId,
        ...(this.#forceUnavailable ? { lastError: "forced_unavailable" } : {})
      })
    );
  }

  getStreamStats(streamName = this.streamName): InMemoryStreamStats | null {
    const stream = this.#streams.get(streamName);
    if (stream === undefined) {
      return null;
    }
    const nowMs = this.#nowMs();
    this.#pruneStreamExpired(stream, nowMs);
    this.#pruneDedupWindow(stream, nowMs);
    return Object.freeze({
      name: stream.name,
      brokerGenerationId: stream.brokerGenerationId,
      created: stream.created,
      messages: stream.messages.length,
      bytes: stream.totalBytes,
      firstSeq: stream.messages[0]?.seq ?? 0,
      lastSeq: stream.nextSeq - 1,
      dedupEntries: stream.dedupIndex.size
    });
  }

  getConsumerStats(
    streamName = this.streamName,
    durableName = this.consumerName
  ): InMemoryConsumerStats | null {
    const stream = this.#streams.get(streamName);
    const consumer = stream?.consumers.get(durableName);
    if (stream === undefined || consumer === undefined) {
      return null;
    }
    this.#reconcileConsumerPending(stream, consumer, this.#nowMs());
    let inFlight = 0;
    for (const state of consumer.pending.values()) {
      if (state.inFlight) {
        inFlight += 1;
      }
    }
    return Object.freeze({
      durableName: consumer.durableName,
      pending: consumer.pending.size,
      inFlight,
      acked: consumer.acked.size,
      terminated: consumer.terminated.size,
      maxDeliverExceeded: consumer.maxDeliverExceeded.size,
      totalRedelivered: consumer.totalRedelivered
    });
  }

  getStoredMessage(seq: number, streamName = this.streamName): InMemoryStreamRecord | null {
    const stream = this.#streams.get(streamName);
    if (stream === undefined) {
      return null;
    }
    return stream.messages.find((m) => m.seq === seq) ?? null;
  }

  injectFault(fault: InMemoryFaultSpec): void {
    switch (fault.kind) {
      case "commit_drop_puback":
        this.#dropPubAckCount = fault.count ?? 1;
        this.#dropPubAckPredicate = fault.predicate;
        break;
      case "stream_full":
        this.#forceStreamFull = fault.enabled;
        break;
      case "unavailable":
        this.#forceUnavailable = fault.enabled;
        break;
      case "drop_ack":
        this.#dropAckCount = fault.count ?? 1;
        break;
    }
  }

  dropNextPubAckAfterStore(
    count = 1,
    predicate?: (input: BrokerPublishInput) => boolean
  ): void {
    this.injectFault({ kind: "commit_drop_puback", count, predicate });
  }

  forceStreamFull(enabled = true): void {
    this.injectFault({ kind: "stream_full", enabled });
  }

  forceUnavailable(enabled = true): void {
    this.injectFault({ kind: "unavailable", enabled });
  }

  dropNextAck(count = 1): void {
    this.injectFault({ kind: "drop_ack", count });
  }

  expireMessages(maxAgeMs = 0, streamName?: string): number {
    let totalExpired = 0;
    const nowMs = this.#nowMs();
    for (const stream of this.#streams.values()) {
      if (streamName !== undefined && stream.name !== streamName) {
        continue;
      }
      const kept: InMemoryStreamRecord[] = [];
      for (const msg of stream.messages) {
        if (nowMs - msg.storedAtMs >= maxAgeMs) {
          stream.totalBytes -= msg.payload.byteLength;
          stream.deletedSeqs.push(msg.seq);
          totalExpired += 1;
        } else {
          kept.push(msg);
        }
      }
      stream.messages = kept;
    }
    return totalExpired;
  }

  recreateStreamForRecoveryTest(nextBrokerGenerationId?: BrokerGenerationId | string): BrokerGenerationId {
    const oldStream = this.#streams.get(this.streamName);
    const generationId = parseBrokerGenerationId(
      nextBrokerGenerationId ?? crypto.randomUUID(),
      "nextBrokerGenerationId"
    );
    this.#streams.delete(this.streamName);
    const created = this.#createStreamInternal(
      {
        name: this.streamName,
        subjects: oldStream ? [...oldStream.subjects] : [formatStreamSubjectPattern(this.subjectPrefix)],
        storage: StorageType.File,
        retention: RetentionPolicy.Limits,
        discard: DiscardPolicy.New,
        discard_new_per_subject: false,
        max_msgs: oldStream?.maxMsgs ?? this.#defaultMaxMsgs,
        max_bytes: oldStream?.maxBytes ?? this.#defaultMaxBytes,
        max_msg_size: oldStream?.maxMsgSize ?? BROKER_EVENT_MAX_PAYLOAD_BYTES,
        max_age: oldStream?.maxAgeNs ?? this.#defaultMaxAgeNs,
        duplicate_window: oldStream?.duplicateWindowNs ?? this.#defaultDuplicateWindowNs,
        num_replicas: oldStream?.replicas ?? this.#defaultReplicas
      },
      generationId
    );
    this.#createConsumerInternal(created, {
      durable_name: this.consumerName,
      deliver_policy: DeliverPolicy.All,
      ack_policy: AckPolicy.Explicit,
      replay_policy: ReplayPolicy.Instant,
      ack_wait: this.#defaultAckWaitNs,
      max_deliver: this.#defaultMaxDeliver,
      max_ack_pending: this.#defaultMaxAckPending,
      max_batch: this.#defaultMaxBatch,
      max_bytes: this.#defaultPullMaxBytes,
      max_expires: this.#defaultMaxExpiresNs
    });
    return generationId;
  }

  close(): Promise<void> {
    this.#closed = true;
    this.#notifyWaiters();
    this.#streams.clear();
    return Promise.resolve();
  }
}
