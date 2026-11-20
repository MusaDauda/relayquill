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
  encodeBrokerMessageId,
  type BrokerMessageId
} from "@relayquill/contracts";
import {
  AuthorizationError,
  ClosedConnectionError,
  ConnectionError,
  DrainingConnectionError,
  InvalidArgumentError,
  InvalidSubjectError,
  NoRespondersError,
  PermissionViolationError,
  RequestError,
  TimeoutError,
  UserAuthenticationExpiredError,
  headers,
  type NatsConnection
} from "@nats-io/transport-node";
import {
  JetStreamApiCodes,
  JetStreamApiError,
  JetStreamError,
  type JetStreamClient,
  type PubAck
} from "@nats-io/jetstream";
import {
  BROKER_EVENT_MAX_PAYLOAD_BYTES,
  BROKER_EVENT_STREAM_NAME,
  BrokerCapacityError,
  BrokerPublishError,
  BrokerUnavailableError,
  OUTBOX_PUBLISH_TIMEOUT_MS,
  RELAY_MAX_IN_FLIGHT,
  type BrokerPublishInput,
  type BrokerPublishResult,
  deriveAcceptedEventSubject,
  normalizeSubjectPrefix,
  sanitizeTraceHeadersForPublish
} from "./types.js";

const CAPACITY_ERROR_REGEX =
  /maximum\s+(?:messages|bytes)|max.*(?:msgs|bytes)|discard|stream.*full|resource\s+limit/i;
const PAYLOAD_SIZE_ERROR_REGEX = /maximum\s+payload|message\s+size/i;

export interface NatsBrokerPublisherOptions {
  readonly js: JetStreamClient;
  readonly nc?: NatsConnection | undefined;
  readonly streamName?: string | undefined;
  readonly subjectPrefix?: string | undefined;
  readonly brokerGenerationId: BrokerGenerationId | string;
  readonly timeoutMs?: number | undefined;
  readonly maxInFlight?: number | undefined;
  readonly allowedTracestateKeys?: readonly string[] | undefined;
  readonly allowAnyValidTracestateKey?: boolean | undefined;
  readonly validateEnvelopePayload?: boolean | undefined;
}

class ConcurrencyGate {
  readonly #limit: number;
  #inFlight = 0;
  readonly #waiters: Array<{
    readonly resolve: () => void;
    readonly reject: (err: Error) => void;
    readonly cleanup: () => void;
  }> = [];

  constructor(limit: number) {
    this.#limit = limit;
  }

  get activeCount(): number {
    return this.#inFlight;
  }

  async acquire(signal?: AbortSignal): Promise<void> {
    if (signal?.aborted) {
      throw new BrokerUnavailableError({
        message: "Broker publish aborted while waiting for concurrency slot",
        retryable: true,
        acceptance: "known_rejected",
        reasonCode: "PUBLISH_ABORTED"
      });
    }
    if (this.#inFlight < this.#limit) {
      this.#inFlight += 1;
      return;
    }

    await new Promise<void>((resolve, reject) => {
      const entry = {
        resolve: () => {
          entry.cleanup();
          resolve();
        },
        reject: (err: Error) => {
          entry.cleanup();
          reject(err);
        },
        cleanup: () => {
          if (signal !== undefined) {
            signal.removeEventListener("abort", onAbort);
          }
        }
      };

      const onAbort = (): void => {
        const idx = this.#waiters.indexOf(entry);
        if (idx !== -1) {
          this.#waiters.splice(idx, 1);
        }
        entry.reject(
          new BrokerUnavailableError({
            message: "Broker publish aborted while waiting for concurrency slot",
            retryable: true,
            acceptance: "known_rejected",
            reasonCode: "PUBLISH_ABORTED"
          })
        );
      };

      if (signal !== undefined) {
        signal.addEventListener("abort", onAbort, { once: true });
      }
      this.#waiters.push(entry);
    });
  }

  release(): void {
    const next = this.#waiters.shift();
    if (next !== undefined) {
      next.resolve();
      return;
    }
    if (this.#inFlight > 0) {
      this.#inFlight -= 1;
    }
  }
}

function isTimeoutCause(err: unknown): boolean {
  if (err instanceof TimeoutError) {
    return true;
  }
  if (err instanceof RequestError && err.cause instanceof TimeoutError) {
    return true;
  }
  if (err instanceof Error && err.name === "TimeoutError") {
    return true;
  }
  return false;
}

function isNoRespondersError(err: unknown): boolean {
  if (err instanceof NoRespondersError) {
    return true;
  }
  if (err instanceof RequestError && err.isNoResponders()) {
    return true;
  }
  if (err instanceof Error && err.name === "JetStreamNotEnabled") {
    return true;
  }
  return false;
}

function isAuthOrPermError(err: unknown): boolean {
  return (
    err instanceof AuthorizationError ||
    err instanceof PermissionViolationError ||
    err instanceof UserAuthenticationExpiredError ||
    (err instanceof RequestError &&
      (err.cause instanceof AuthorizationError ||
        err.cause instanceof PermissionViolationError ||
        err.cause instanceof UserAuthenticationExpiredError))
  );
}

function isConnectionLostInFlightError(err: unknown): boolean {
  return (
    err instanceof ConnectionError ||
    err instanceof ClosedConnectionError ||
    err instanceof DrainingConnectionError ||
    (err instanceof RequestError &&
      (err.cause instanceof ConnectionError ||
        err.cause instanceof ClosedConnectionError ||
        err.cause instanceof DrainingConnectionError))
  );
}

export function classifyPublishError(
  err: unknown,
  context: {
    readonly stream: string;
    readonly subject: string;
    readonly msgId: BrokerMessageId;
  }
): Error {
  if (
    err instanceof ValidationDomainError ||
    err instanceof BrokerPublishError ||
    err instanceof BrokerCapacityError ||
    err instanceof BrokerUnavailableError
  ) {
    return err;
  }

  if (err instanceof JetStreamApiError) {
    const msg = err.message || "JetStream API error";
    if (PAYLOAD_SIZE_ERROR_REGEX.test(msg)) {
      return new ValidationDomainError({
        code: "PAYLOAD_TOO_LARGE",
        message: `Broker rejected message size: ${msg}`,
        acceptance: "known_rejected",
        boundary: "published"
      });
    }
    if (
      err.code === 10077 ||
      err.code === 10047 ||
      err.code === 10048 ||
      err.code === 10054 ||
      CAPACITY_ERROR_REGEX.test(msg)
    ) {
      return new BrokerCapacityError(
        {
          message: `Broker stream "${context.stream}" capacity reached (DiscardNew): ${msg}`,
          stream: context.stream,
          subject: context.subject,
          msgId: context.msgId,
          reasonCode: `JS_API_${err.code}`
        },
        err
      );
    }
    if (
      err.code === JetStreamApiCodes.StreamNotFound ||
      err.code === JetStreamApiCodes.JetStreamNotEnabledForAccount
    ) {
      return new BrokerUnavailableError(
        {
          message: `Broker stream "${context.stream}" unavailable: ${msg}`,
          retryable: true,
          acceptance: "known_rejected",
          stream: context.stream,
          subject: context.subject,
          msgId: context.msgId,
          reasonCode: `JS_API_${err.code}`
        },
        err
      );
    }
    return new BrokerUnavailableError(
      {
        message: `JetStream publish rejected (${err.code}): ${msg}`,
        retryable: err.status >= 500,
        acceptance: "known_rejected",
        stream: context.stream,
        subject: context.subject,
        msgId: context.msgId,
        reasonCode: `JS_API_${err.code}`
      },
      err
    );
  }

  if (isTimeoutCause(err)) {
    return new BrokerPublishError(
      {
        message: `Timed out awaiting PubAck for ${context.msgId} on "${context.subject}"`,
        classification: "publish_unknown",
        retryable: true,
        acceptance: "unknown",
        stream: context.stream,
        subject: context.subject,
        msgId: context.msgId,
        reasonCode: "PUBACK_TIMEOUT"
      },
      err
    );
  }

  if (isNoRespondersError(err)) {
    return new BrokerUnavailableError(
      {
        message: `No JetStream responders for "${context.subject}"`,
        retryable: true,
        acceptance: "known_rejected",
        stream: context.stream,
        subject: context.subject,
        msgId: context.msgId,
        reasonCode: "NO_RESPONDERS"
      },
      err
    );
  }

  if (isAuthOrPermError(err)) {
    return new BrokerUnavailableError(
      {
        message: `Broker authorization/permission error publishing ${context.msgId}: ${err instanceof Error ? err.message : String(err)}`,
        retryable: false,
        acceptance: "known_rejected",
        stream: context.stream,
        subject: context.subject,
        msgId: context.msgId,
        reasonCode: "PERMISSION_DENIED"
      },
      err
    );
  }

  if (isConnectionLostInFlightError(err)) {
    return new BrokerPublishError(
      {
        message: `Broker connection interrupted while awaiting PubAck for ${context.msgId}`,
        classification: "publish_unknown",
        retryable: true,
        acceptance: "unknown",
        stream: context.stream,
        subject: context.subject,
        msgId: context.msgId,
        reasonCode: "CONNECTION_LOST_IN_FLIGHT"
      },
      err
    );
  }

  if (err instanceof InvalidSubjectError || err instanceof InvalidArgumentError) {
    return new ValidationDomainError({
      code: "INVALID_VALUE",
      message: err.message,
      acceptance: "known_rejected",
      boundary: "published"
    });
  }

  if (err instanceof JetStreamError) {
    return new BrokerPublishError(
      {
        message: `Uncertain JetStream publish outcome for ${context.msgId}: ${err.message}`,
        classification: "publish_unknown",
        retryable: true,
        acceptance: "unknown",
        stream: context.stream,
        subject: context.subject,
        msgId: context.msgId,
        reasonCode: "JETSTREAM_PUBLISH_ERROR"
      },
      err
    );
  }

  return new BrokerPublishError(
    {
      message: `Unknown broker publish failure for ${context.msgId}: ${err instanceof Error ? err.message : String(err)}`,
      classification: "publish_unknown",
      retryable: true,
      acceptance: "unknown",
      stream: context.stream,
      subject: context.subject,
      msgId: context.msgId,
      reasonCode: "PUBLISH_UNKNOWN"
    },
    err
  );
}

export function validatePubAckMetadata(
  ack: PubAck,
  expectedStreamName: string,
  msgId: BrokerMessageId
): void {
  if (ack.stream !== expectedStreamName) {
    throw new BrokerUnavailableError({
      message: `PubAck stream mismatch for ${msgId}: expected "${expectedStreamName}", got "${ack.stream}"`,
      retryable: false,
      acceptance: "unknown",
      stream: ack.stream,
      msgId,
      reasonCode: "STREAM_NAME_MISMATCH"
    });
  }
  if (!Number.isSafeInteger(ack.seq) || ack.seq <= 0) {
    throw new ValidationDomainError({
      code: "INVALID_INT64",
      message: `PubAck sequence for ${msgId} is not a positive safe integer: ${String(ack.seq)}`,
      acceptance: "unknown",
      boundary: "published"
    });
  }
}

export class NatsBrokerPublisher {
  readonly streamName: string;
  readonly subjectPrefix: string;
  readonly brokerGenerationId: BrokerGenerationId;
  readonly #js: JetStreamClient;
  readonly #nc: NatsConnection | undefined;
  readonly #defaultTimeoutMs: number;
  readonly #gate: ConcurrencyGate;
  readonly #allowedTracestateKeys: readonly string[] | undefined;
  readonly #allowAnyValidTracestateKey: boolean | undefined;
  readonly #validateEnvelopePayload: boolean;
  #closed = false;

  constructor(options: NatsBrokerPublisherOptions) {
    this.#js = options.js;
    this.#nc = options.nc;
    this.streamName = options.streamName ?? BROKER_EVENT_STREAM_NAME;
    this.subjectPrefix = normalizeSubjectPrefix(options.subjectPrefix);
    this.brokerGenerationId = parseBrokerGenerationId(
      options.brokerGenerationId,
      "brokerGenerationId"
    );
    const timeoutMs = options.timeoutMs ?? Number(OUTBOX_PUBLISH_TIMEOUT_MS);
    if (!Number.isInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 60_000) {
      throw new ValidationDomainError({
        code: "INVALID_VALUE",
        message: `Publisher timeoutMs must be within [100, 60000], got ${String(timeoutMs)}`
      });
    }
    this.#defaultTimeoutMs = timeoutMs;
    const maxInFlight = options.maxInFlight ?? RELAY_MAX_IN_FLIGHT;
    if (!Number.isInteger(maxInFlight) || maxInFlight < 1 || maxInFlight > 128) {
      throw new ValidationDomainError({
        code: "INVALID_VALUE",
        message: `Publisher maxInFlight must be within [1, 128], got ${String(maxInFlight)}`
      });
    }
    this.#gate = new ConcurrencyGate(maxInFlight);
    this.#allowedTracestateKeys = options.allowedTracestateKeys;
    this.#allowAnyValidTracestateKey = options.allowAnyValidTracestateKey;
    this.#validateEnvelopePayload = options.validateEnvelopePayload ?? true;
  }

  get inFlightCount(): number {
    return this.#gate.activeCount;
  }

  close(): void {
    this.#closed = true;
  }

  async publish(input: BrokerPublishInput): Promise<BrokerPublishResult> {
    if (this.#closed || this.#nc?.isClosed() || this.#nc?.isDraining()) {
      throw new BrokerUnavailableError({
        message: "Broker publisher connection is closed or draining",
        retryable: true,
        acceptance: "known_rejected",
        stream: this.streamName,
        reasonCode: "CONNECTION_UNAVAILABLE"
      });
    }

    if (
      input.expectedBrokerGenerationId !== undefined &&
      parseBrokerGenerationId(input.expectedBrokerGenerationId, "expectedBrokerGenerationId") !==
        this.brokerGenerationId
    ) {
      throw new BrokerUnavailableError({
        message: "Broker generation ID changed unexpectedly; refusing unverified publication",
        retryable: false,
        acceptance: "known_rejected",
        stream: this.streamName,
        reasonCode: "BROKER_GENERATION_MISMATCH"
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
    if (
      input.envelopeBytes.byteLength === 0 ||
      input.envelopeBytes.byteLength > BROKER_EVENT_MAX_PAYLOAD_BYTES
    ) {
      throw new ValidationDomainError({
        code: input.envelopeBytes.byteLength > BROKER_EVENT_MAX_PAYLOAD_BYTES ? "PAYLOAD_TOO_LARGE" : "INVALID_VALUE",
        message: `Broker envelope byte length ${input.envelopeBytes.byteLength} out of bounds [1, ${BROKER_EVENT_MAX_PAYLOAD_BYTES}]`,
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
    const timeoutMs = input.timeoutMs ?? this.#defaultTimeoutMs;
    if (!Number.isInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 60_000) {
      throw new ValidationDomainError({
        code: "INVALID_VALUE",
        message: `Publish timeoutMs must be within [100, 60000], got ${String(timeoutMs)}`,
        acceptance: "known_rejected",
        boundary: "published"
      });
    }

    const safeTrace = sanitizeTraceHeadersForPublish(input.traceContext, {
      allowedVendorKeys: this.#allowedTracestateKeys,
      allowAnyValidVendorKey: this.#allowAnyValidTracestateKey
    });
    const natsHeaders = headers();
    if (safeTrace.traceparent !== undefined) {
      natsHeaders.set("traceparent", safeTrace.traceparent);
    }
    if (safeTrace.tracestate !== undefined) {
      natsHeaders.set("tracestate", safeTrace.tracestate);
    }

    // Copy bytes so neither NATS transport nor callers can mutate the caller's envelope buffer.
    const immutablePayloadCopy = new Uint8Array(input.envelopeBytes);

    await this.#gate.acquire(input.signal);
    try {
      if (this.#closed || this.#nc?.isClosed() || this.#nc?.isDraining()) {
        throw new BrokerUnavailableError({
          message: "Broker connection closed before publish transmission",
          retryable: true,
          acceptance: "known_rejected",
          stream: this.streamName,
          subject,
          msgId,
          reasonCode: "CONNECTION_UNAVAILABLE"
        });
      }

      const ack = await this.#js.publish(subject, immutablePayloadCopy, {
        msgID: msgId,
        headers: natsHeaders,
        timeout: timeoutMs
      });

      validatePubAckMetadata(ack, this.streamName, msgId);

      return Object.freeze({
        stream: ack.stream,
        seq: ack.seq,
        duplicate: Boolean(ack.duplicate),
        brokerGenerationId: this.brokerGenerationId,
        msgId,
        subject,
        ...(ack.domain !== undefined && ack.domain.length > 0 ? { domain: ack.domain } : {})
      });
    } catch (err) {
      throw classifyPublishError(err, {
        stream: this.streamName,
        subject,
        msgId
      });
    } finally {
      this.#gate.release();
    }
  }
}
