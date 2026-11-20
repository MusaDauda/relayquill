import {
  type BrokerGenerationId,
  ValidationDomainError,
  parseBrokerGenerationId
} from "@relayquill/domain";
import { abortableDelay } from "@relayquill/runtime";
import {
  type Consumer,
  type ConsumerMessages,
  type JetStreamClient,
  JetStreamError,
  type JsMsg
} from "@nats-io/jetstream";
import {
  BROKER_DEFAULT_PULL_MAX_EXPIRES_MS,
  BROKER_EVENT_MAX_PAYLOAD_BYTES,
  BROKER_EVENT_STREAM_NAME,
  BROKER_MAX_NAK_DELAY_MS,
  BROKER_MIN_PULL_EXPIRES_MS,
  BrokerUnavailableError,
  FANOUT_CONSUMER_NAME,
  FANOUT_PULL_MAX_BATCH,
  FANOUT_PULL_MAX_BYTES,
  type BrokerConsumeOptions,
  type BrokerMessage,
  type BrokerPullOptions,
  extractTraceHeadersFromRecord,
  natsHeadersToRecord,
  readHeaderFirstValue
} from "./types.js";

export interface NatsBrokerConsumerOptions {
  readonly js: JetStreamClient;
  readonly streamName?: string | undefined;
  readonly consumerName?: string | undefined;
  readonly brokerGenerationId: BrokerGenerationId | string;
  readonly maxBatchLimit?: number | undefined;
  readonly maxBytesLimit?: number | undefined;
  readonly maxExpiresMsLimit?: number | undefined;
  readonly allowedTracestateKeys?: readonly string[] | undefined;
  readonly allowAnyValidTracestateKey?: boolean | undefined;
  readonly ackAckTimeoutMs?: number | undefined;
}

export function validatePullBounds(
  options: BrokerPullOptions | undefined,
  limits: {
    readonly maxBatchLimit: number;
    readonly maxBytesLimit: number;
    readonly maxExpiresMsLimit: number;
    readonly minExpiresMs?: number | undefined;
  }
): {
  readonly maxBatch: number;
  readonly maxBytes: number;
  readonly expiresMs: number;
} {
  const maxBatch = options?.maxBatch ?? limits.maxBatchLimit;
  const maxBytes = options?.maxBytes ?? limits.maxBytesLimit;
  const expiresMs = options?.expiresMs ?? limits.maxExpiresMsLimit;
  const minExpiresMs = limits.minExpiresMs ?? BROKER_MIN_PULL_EXPIRES_MS;

  if (!Number.isInteger(maxBatch) || maxBatch < 1 || maxBatch > limits.maxBatchLimit) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Consumer maxBatch must be within [1, ${limits.maxBatchLimit}], got ${String(maxBatch)}`
    });
  }
  if (
    !Number.isInteger(maxBytes) ||
    maxBytes < BROKER_EVENT_MAX_PAYLOAD_BYTES ||
    maxBytes > limits.maxBytesLimit
  ) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Consumer maxBytes must be within [${BROKER_EVENT_MAX_PAYLOAD_BYTES}, ${limits.maxBytesLimit}], got ${String(maxBytes)}`
    });
  }
  if (!Number.isInteger(expiresMs) || expiresMs < minExpiresMs || expiresMs > limits.maxExpiresMsLimit) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Consumer expiresMs must be within [${minExpiresMs}, ${limits.maxExpiresMsLimit}], got ${String(expiresMs)}`
    });
  }

  return { maxBatch, maxBytes, expiresMs };
}

export function validateNakDelayMs(delayMs: number | undefined): number | undefined {
  if (delayMs === undefined) {
    return undefined;
  }
  if (!Number.isFinite(delayMs) || delayMs < 0 || delayMs > BROKER_MAX_NAK_DELAY_MS) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `NAK delayMs must be within [0, ${BROKER_MAX_NAK_DELAY_MS}], got ${String(delayMs)}`
    });
  }
  return Math.trunc(delayMs);
}

export function wrapJsMsg(
  msg: JsMsg,
  options: {
    readonly brokerGenerationId: BrokerGenerationId;
    readonly allowedTracestateKeys?: readonly string[] | undefined;
    readonly allowAnyValidTracestateKey?: boolean | undefined;
    readonly ackAckTimeoutMs?: number | undefined;
  }
): BrokerMessage {
  if (!Number.isSafeInteger(msg.seq) || msg.seq <= 0) {
    throw new ValidationDomainError({
      code: "INVALID_INT64",
      message: `Delivered JetStream message seq is not a positive safe integer: ${String(msg.seq)}`
    });
  }

  const headerRecord = natsHeadersToRecord(msg.headers);
  const msgId = readHeaderFirstValue(headerRecord, "Nats-Msg-Id");
  const trace = extractTraceHeadersFromRecord(headerRecord, {
    allowedVendorKeys: options.allowedTracestateKeys,
    allowAnyValidVendorKey: options.allowAnyValidTracestateKey
  });
  const payloadCopy = new Uint8Array(msg.data);
  const defaultAckTimeout = options.ackAckTimeoutMs ?? 5_000;

  return Object.freeze({
    stream: msg.info.stream,
    consumer: msg.info.consumer,
    subject: msg.subject,
    seq: msg.seq,
    deliveryCount: msg.info.deliveryCount,
    deliverySequence: msg.info.deliverySequence,
    redelivered: msg.redelivered,
    pending: msg.info.pending,
    timestampNanos: msg.timestampNanos,
    payload: payloadCopy,
    headers: headerRecord,
    ...(msgId !== undefined ? { msgId } : {}),
    trace,
    brokerGenerationId: options.brokerGenerationId,
    ack: () => Promise.resolve().then(() => msg.ack()),
    ackAck: (timeoutMs?: number) => msg.ackAck({ timeout: timeoutMs ?? defaultAckTimeout }),
    nak: (delayMs?: number) => {
      const checked = validateNakDelayMs(delayMs);
      return Promise.resolve().then(() => msg.nak(checked));
    },
    working: () => Promise.resolve().then(() => msg.working()),
    term: (reason?: string) => Promise.resolve().then(() => msg.term(reason))
  });
}

export class NatsBrokerConsumer {
  readonly streamName: string;
  readonly consumerName: string;
  readonly brokerGenerationId: BrokerGenerationId;
  readonly maxBatchLimit: number;
  readonly maxBytesLimit: number;
  readonly maxExpiresMsLimit: number;
  readonly #js: JetStreamClient;
  readonly #allowedTracestateKeys: readonly string[] | undefined;
  readonly #allowAnyValidTracestateKey: boolean | undefined;
  readonly #ackAckTimeoutMs: number;
  #cachedConsumer: Consumer | null = null;
  #closed = false;

  constructor(options: NatsBrokerConsumerOptions) {
    this.#js = options.js;
    this.streamName = options.streamName ?? BROKER_EVENT_STREAM_NAME;
    this.consumerName = options.consumerName ?? FANOUT_CONSUMER_NAME;
    this.brokerGenerationId = parseBrokerGenerationId(
      options.brokerGenerationId,
      "brokerGenerationId"
    );
    this.maxBatchLimit = options.maxBatchLimit ?? FANOUT_PULL_MAX_BATCH;
    this.maxBytesLimit = options.maxBytesLimit ?? FANOUT_PULL_MAX_BYTES;
    this.maxExpiresMsLimit = options.maxExpiresMsLimit ?? BROKER_DEFAULT_PULL_MAX_EXPIRES_MS;
    this.#allowedTracestateKeys = options.allowedTracestateKeys;
    this.#allowAnyValidTracestateKey = options.allowAnyValidTracestateKey;
    this.#ackAckTimeoutMs = options.ackAckTimeoutMs ?? 5_000;
  }

  close(): void {
    this.#closed = true;
    this.#cachedConsumer = null;
  }

  async #getConsumer(): Promise<Consumer> {
    if (this.#cachedConsumer !== null) {
      return this.#cachedConsumer;
    }
    try {
      const consumer = await this.#js.consumers.get(this.streamName, this.consumerName);
      this.#cachedConsumer = consumer;
      return consumer;
    } catch (err) {
      throw new BrokerUnavailableError(
        {
          message: `Failed to resolve JetStream consumer "${this.consumerName}" on "${this.streamName}": ${err instanceof Error ? err.message : String(err)}`,
          retryable: true,
          acceptance: "known_rejected",
          stream: this.streamName,
          reasonCode: "CONSUMER_UNAVAILABLE"
        },
        err
      );
    }
  }

  async pullBatch(options: BrokerPullOptions = {}): Promise<readonly BrokerMessage[]> {
    if (this.#closed || options.signal?.aborted) {
      return [];
    }

    const { maxBatch, maxBytes, expiresMs } = validatePullBounds(options, {
      maxBatchLimit: this.maxBatchLimit,
      maxBytesLimit: this.maxBytesLimit,
      maxExpiresMsLimit: this.maxExpiresMsLimit
    });

    // @nats-io/jetstream fetch treats max_messages and max_bytes as mutually exclusive;
    // cap message count by maxBytes / max_msg_size so both batch and byte ceilings hold.
    const effectiveBatch = Math.min(
      maxBatch,
      Math.max(1, Math.floor(maxBytes / BROKER_EVENT_MAX_PAYLOAD_BYTES))
    );

    const consumer = await this.#getConsumer();
    const idleHeartbeatMs = Math.max(500, Math.min(2_500, Math.floor(expiresMs / 2)));

    let iter: ConsumerMessages;
    try {
      iter = await consumer.fetch({
        max_messages: effectiveBatch,
        expires: expiresMs,
        idle_heartbeat: idleHeartbeatMs,
        bind: options.bind ?? true
      });
    } catch (err) {
      this.#cachedConsumer = null;
      throw new BrokerUnavailableError(
        {
          message: `Failed to initiate JetStream pull fetch: ${err instanceof Error ? err.message : String(err)}`,
          retryable: true,
          acceptance: "known_rejected",
          stream: this.streamName,
          reasonCode: "PULL_FETCH_FAILED"
        },
        err
      );
    }

    const onAbort = (): void => {
      void iter.close();
    };
    options.signal?.addEventListener("abort", onAbort, { once: true });

    const out: BrokerMessage[] = [];
    try {
      for await (const rawMsg of iter) {
        out.push(
          wrapJsMsg(rawMsg, {
            brokerGenerationId: this.brokerGenerationId,
            allowedTracestateKeys: options.allowedTracestateKeys ?? this.#allowedTracestateKeys,
            allowAnyValidTracestateKey:
              options.allowAnyValidTracestateKey ?? this.#allowAnyValidTracestateKey,
            ackAckTimeoutMs: this.#ackAckTimeoutMs
          })
        );
        if (options.signal?.aborted || this.#closed) {
          break;
        }
      }
      return Object.freeze(out);
    } catch (err) {
      if (options.signal?.aborted || this.#closed) {
        return Object.freeze(out);
      }
      this.#cachedConsumer = null;
      const jsStatusCode = getJetStreamStatusCode(err);
      if (jsStatusCode === 408) {
        return Object.freeze(out);
      }
      throw new BrokerUnavailableError(
        {
          message: `JetStream pull stream interrupted: ${err instanceof Error ? err.message : String(err)}`,
          retryable: true,
          acceptance: "known_rejected",
          stream: this.streamName,
          reasonCode: jsStatusCode !== undefined ? `JS_STATUS_${String(jsStatusCode)}` : "PULL_STREAM_ERROR"
        },
        err
      );
    } finally {
      options.signal?.removeEventListener("abort", onAbort);
      await iter.close().catch(() => undefined);
    }
  }

  async *consume(options: BrokerConsumeOptions = {}): AsyncIterable<BrokerMessage> {
    const slotWaitMs = options.slotWaitMs ?? 50;
    const idlePollDelayMs = options.idlePollDelayMs ?? 10;

    while (!this.#closed && !options.signal?.aborted) {
      let batchLimit = options.maxBatch ?? this.maxBatchLimit;
      if (options.availableSlots !== undefined) {
        const freeSlots = options.availableSlots();
        if (freeSlots <= 0) {
          if (options.signal !== undefined) {
            await abortableDelay(slotWaitMs, options.signal);
          } else {
            await delayUnref(slotWaitMs);
          }
          continue;
        }
        batchLimit = Math.min(batchLimit, freeSlots);
      }

      const batch = await this.pullBatch({
        ...options,
        maxBatch: batchLimit
      });

      if (batch.length === 0) {
        if (options.signal?.aborted || this.#closed) {
          break;
        }
        if (idlePollDelayMs > 0) {
          if (options.signal !== undefined) {
            await abortableDelay(idlePollDelayMs, options.signal);
          } else {
            await delayUnref(idlePollDelayMs);
          }
        }
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
}

function delayUnref(ms: number): Promise<void> {
  return new Promise((resolve) => {
    const timer = setTimeout(resolve, Math.max(0, ms));
    timer.unref();
  });
}

function getJetStreamStatusCode(err: unknown): number | undefined {
  if (err instanceof JetStreamError && "code" in err && typeof err.code === "number") {
    return err.code;
  }
  return undefined;
}
