import {
  type CanonicalUuid,
  type DeliveryId,
  type EventId,
  type ParsedSseFrame,
  WATCH_MAX_FRAME_BYTES,
  type WatchAuthorizationLostFrameData,
  type WatchEventFrameData,
  type WatchResyncRequiredFrameData,
  type WatchSnapshotFrameData,
  type WatchUnavailableFrameData,
  classifyResponseEnvelope,
  createSseChunkDecoder,
  parseBoundedString,
  parseDeliveryId,
  parseEventId,
  parseStrictJsonObject
} from "@relayquill/contracts";
import { DomainError, type WatchResourceKind } from "@relayquill/domain";
import {
  type ProducerAuthConfig,
  resolveRequestAuth
} from "./context.js";
import {
  ProducerAbortedError,
  ProducerAuthError,
  ProducerPressureError,
  ProducerProtocolError,
  ProducerSdkError,
  ProducerValidationError
} from "./errors.js";
import { parseRetryAfterHeader } from "./retry.js";

export {
  type ParsedSseFrame,
  WATCH_MAX_FRAME_BYTES,
  type WatchAuthorizationLostFrameData,
  type WatchEventFrameData,
  type WatchResyncRequiredFrameData,
  type WatchResourceKind,
  type WatchSnapshotFrameData,
  type WatchUnavailableFrameData
};

export interface FetchHeadersLike {
  get(name: string): string | null;
}

export interface FetchReadableStreamReaderLike {
  read(): Promise<{ readonly done: boolean; readonly value?: Uint8Array | undefined }>;
  cancel(reason?: unknown): Promise<unknown>;
  releaseLock?(): void;
}

export interface FetchReadableStreamLike {
  getReader(): FetchReadableStreamReaderLike;
}

export interface FetchResponseLike {
  readonly status: number;
  readonly ok: boolean;
  readonly headers: FetchHeadersLike;
  readonly body: FetchReadableStreamLike | null;
  text(): Promise<string>;
}

export interface FetchRequestInitLike {
  readonly method?: string | undefined;
  readonly headers?: Readonly<Record<string, string>> | undefined;
  readonly body?: string | undefined;
  readonly signal?: AbortSignal | null | undefined;
  readonly credentials?: "omit" | "same-origin" | "include" | undefined;
}

export type FetchLike = (
  input: string,
  init?: FetchRequestInitLike
) => Promise<FetchResponseLike>;

export interface WatchEventsInput {
  readonly eventId?: EventId | string | undefined;
  readonly deliveryId?: DeliveryId | string | undefined;
  readonly resourceKind?: WatchResourceKind | undefined;
  readonly resourceId?: CanonicalUuid | string | undefined;
  readonly lastEventId?: string | undefined;
  readonly cursor?: string | undefined;
  readonly signal?: AbortSignal | undefined;
}

export type WatchFrame =
  | {
      readonly supported: true;
      readonly frameType: "snapshot";
      readonly cursor: string;
      readonly data: WatchSnapshotFrameData;
    }
  | {
      readonly supported: true;
      readonly frameType: "event";
      readonly cursor: string;
      readonly data: WatchEventFrameData;
    }
  | {
      readonly supported: true;
      readonly frameType: "heartbeat";
      readonly comment: string;
    }
  | {
      readonly supported: true;
      readonly frameType: "resync_required";
      readonly data: WatchResyncRequiredFrameData;
    }
  | {
      readonly supported: true;
      readonly frameType: "authorization_lost";
      readonly data: WatchAuthorizationLostFrameData;
    }
  | {
      readonly supported: true;
      readonly frameType: "unavailable";
      readonly data: WatchUnavailableFrameData;
    }
  | {
      readonly supported: false;
      readonly frameType: "unsupported";
      readonly reason:
        | "unsupported_response_schema_version"
        | "unsupported_frame_type"
        | "malformed_frame";
      readonly responseSchemaVersion?: number | undefined;
      readonly rawFrameType?: string | undefined;
    };

export interface WatchTransportContext {
  readonly buildWatchUrl: (resourceKind: WatchResourceKind, resourceId: CanonicalUuid) => string;
  readonly auth: ProducerAuthConfig;
  readonly fetchFn: FetchLike;
}

function mapParsedSseFrame(frame: ParsedSseFrame): WatchFrame {
  if (!frame.supported) {
    return Object.freeze({
      supported: false,
      frameType: "unsupported",
      reason: frame.reason,
      ...(frame.response_schema_version !== undefined
        ? { responseSchemaVersion: frame.response_schema_version }
        : {}),
      ...(frame.frame_type !== undefined ? { rawFrameType: frame.frame_type } : {})
    });
  }
  switch (frame.frame_type) {
    case "heartbeat":
      return Object.freeze({
        supported: true,
        frameType: "heartbeat",
        comment: frame.comment
      });
    case "snapshot":
      return Object.freeze({
        supported: true,
        frameType: "snapshot",
        cursor: frame.id,
        data: frame.data
      });
    case "event":
      return Object.freeze({
        supported: true,
        frameType: "event",
        cursor: frame.id,
        data: frame.data
      });
    case "resync_required":
      return Object.freeze({
        supported: true,
        frameType: "resync_required",
        data: frame.data
      });
    case "authorization_lost":
      return Object.freeze({
        supported: true,
        frameType: "authorization_lost",
        data: frame.data
      });
    case "unavailable":
      return Object.freeze({
        supported: true,
        frameType: "unavailable",
        data: frame.data
      });
  }
}

function resolveWatchTarget(input: WatchEventsInput): {
  readonly resourceKind: WatchResourceKind;
  readonly resourceId: CanonicalUuid;
} {
  if (input.eventId !== undefined && input.deliveryId !== undefined) {
    throw new ProducerValidationError({
      message: "Specify either eventId or deliveryId for watchEvents, not both"
    });
  }
  if (input.eventId !== undefined) {
    return {
      resourceKind: "event",
      resourceId: parseEventId(input.eventId, "eventId")
    };
  }
  if (input.deliveryId !== undefined) {
    return {
      resourceKind: "delivery",
      resourceId: parseDeliveryId(input.deliveryId, "deliveryId")
    };
  }
  if (input.resourceKind !== undefined && input.resourceId !== undefined) {
    if (input.resourceKind === "event") {
      return {
        resourceKind: "event",
        resourceId: parseEventId(input.resourceId, "resourceId")
      };
    }
    if (input.resourceKind === "delivery") {
      return {
        resourceKind: "delivery",
        resourceId: parseDeliveryId(input.resourceId, "resourceId")
      };
    }
  }
  throw new ProducerValidationError({
    message: "watchEvents requires eventId or deliveryId"
  });
}

function validateWatchResumeCursor(rawCursor: string, fieldPath: string): string {
  try {
    return parseBoundedString(rawCursor, {
      fieldPath,
      minUtf8Bytes: 1,
      maxUtf8Bytes: 1400,
      rejectControlChars: true
    });
  } catch (err) {
    throw new ProducerValidationError({
      code: "INVALID_CURSOR",
      message: err instanceof DomainError ? err.message : `Invalid watch cursor for ${fieldPath}`,
      fieldErrors: [{ path: fieldPath, code: "INVALID_CURSOR" }]
    });
  }
}

async function throwWatchHttpError(response: FetchResponseLike): Promise<never> {
  const retryAfterMs = parseRetryAfterHeader(response.headers.get("retry-after"));
  let rawText = "";
  try {
    rawText = await response.text();
  } catch {
    rawText = "";
  }

  if (rawText.trim().length > 0) {
    try {
      const parsedObj = parseStrictJsonObject(rawText, {
        fieldPath: "watch_error_response",
        maxDepth: 12,
        maxNodes: 512
      });
      const classified = classifyResponseEnvelope(parsedObj, (d) => d);
      if (classified.supported && classified.kind === "error") {
        const { error, meta } = classified.envelope;
        if (response.status === 401 || response.status === 403) {
          throw new ProducerAuthError({
            code: error.code === "FORBIDDEN" ? "FORBIDDEN" : "UNAUTHENTICATED",
            message: error.message,
            httpStatus: response.status,
            requestId: meta.request_id,
            observedAt: meta.observed_at
          });
        }
        if (response.status === 429) {
          throw new ProducerPressureError({
            code: error.code === "CAPACITY_EXCEEDED" ? "CAPACITY_EXCEEDED" : "RATE_LIMITED",
            message: error.message,
            httpStatus: 429,
            retryable: error.retryable,
            requestId: meta.request_id,
            observedAt: meta.observed_at,
            ...(retryAfterMs !== null ? { retryAfterMs } : {})
          });
        }
        throw new ProducerSdkError({
          code: error.code as ProducerSdkError["code"],
          message: error.message,
          httpStatus: response.status,
          retryable: error.retryable,
          acceptance: error.acceptance,
          requestId: meta.request_id,
          observedAt: meta.observed_at,
          ...(error.field_errors !== undefined ? { fieldErrors: error.field_errors } : {}),
          ...(error.resource_ref !== undefined ? { resourceRef: error.resource_ref } : {})
        });
      }
    } catch (inner) {
      if (inner instanceof ProducerSdkError) {
        throw inner;
      }
    }
  }

  if (response.status === 401 || response.status === 403) {
    throw new ProducerAuthError({
      code: response.status === 403 ? "FORBIDDEN" : "UNAUTHENTICATED",
      message: `Watch stream rejected with HTTP ${String(response.status)}`,
      httpStatus: response.status
    });
  }
  if (response.status === 410) {
    throw new ProducerSdkError({
      code: "CURSOR_EXPIRED",
      message: "Watch resume cursor has expired",
      httpStatus: 410,
      retryable: false,
      acceptance: "known_rejected"
    });
  }
  if (response.status === 429) {
    throw new ProducerPressureError({
      code: "RATE_LIMITED",
      message: "Watch stream rate or quota limited (HTTP 429)",
      httpStatus: 429,
      ...(retryAfterMs !== null ? { retryAfterMs } : {})
    });
  }
  throw new ProducerSdkError({
    code: response.status >= 500 ? "DEPENDENCY_UNAVAILABLE" : "INVALID_VALUE",
    message: `Watch stream request failed with HTTP ${String(response.status)}`,
    httpStatus: response.status,
    retryable: response.status >= 500,
    acceptance: "not_applicable"
  });
}

export class WatchStream implements AsyncIterable<WatchFrame> {
  readonly #transport: WatchTransportContext;
  readonly #target: { readonly resourceKind: WatchResourceKind; readonly resourceId: CanonicalUuid };
  readonly #resumeCursor: string | undefined;
  readonly #externalSignal: AbortSignal | undefined;
  readonly #internalAbortController = new AbortController();
  readonly #seenEventSequences = new Set<string>();
  #lastHandledCursor: string | null = null;
  #closed = false;

  constructor(transport: WatchTransportContext, input: WatchEventsInput) {
    this.#transport = transport;
    this.#target = resolveWatchTarget(input);

    const rawResume = input.lastEventId ?? input.cursor;
    this.#resumeCursor =
      rawResume !== undefined ? validateWatchResumeCursor(rawResume, "lastEventId") : undefined;
    this.#externalSignal = input.signal;

    if (this.#externalSignal !== undefined) {
      if (this.#externalSignal.aborted) {
        this.#internalAbortController.abort(this.#externalSignal.reason);
      } else {
        this.#externalSignal.addEventListener(
          "abort",
          () => {
            this.#internalAbortController.abort(this.#externalSignal?.reason);
          },
          { once: true }
        );
      }
    }
  }

  get resourceKind(): WatchResourceKind {
    return this.#target.resourceKind;
  }

  get resourceId(): CanonicalUuid {
    return this.#target.resourceId;
  }

  get isClosed(): boolean {
    return this.#closed;
  }

  /**
   * Returns the cursor of the last snapshot or event frame whose iteration step
   * completed in the consumer loop.
   */
  getLastHandledCursor(): string | null {
    return this.#lastHandledCursor;
  }

  close(): void {
    this.#closed = true;
    if (!this.#internalAbortController.signal.aborted) {
      this.#internalAbortController.abort();
    }
  }

  async *[Symbol.asyncIterator](): AsyncGenerator<WatchFrame, void, undefined> {
    if (this.#externalSignal?.aborted === true) {
      throw new ProducerAbortedError({
        message: "Watch stream aborted before connection",
        acceptance: "not_applicable"
      });
    }
    if (this.#closed) {
      return;
    }

    const auth = await resolveRequestAuth(this.#transport.auth, {
      isMutation: this.#transport.auth.mode === "browser_session"
    });
    const url = this.#transport.buildWatchUrl(this.#target.resourceKind, this.#target.resourceId);

    const headers: Record<string, string> = {
      Accept: "text/event-stream",
      "Cache-Control": "no-store",
      ...auth.headers
    };
    const effectiveResume = this.#lastHandledCursor ?? this.#resumeCursor;
    if (effectiveResume !== undefined) {
      headers["Last-Event-ID"] = effectiveResume;
    }

    let response: FetchResponseLike;
    try {
      response = await this.#transport.fetchFn(url, {
        method: "GET",
        headers,
        signal: this.#internalAbortController.signal,
        ...(auth.credentials !== undefined ? { credentials: auth.credentials } : {})
      });
    } catch (err) {
      if (Boolean(this.#externalSignal?.aborted) || this.#internalAbortController.signal.aborted) {
        if (this.#closed && !Boolean(this.#externalSignal?.aborted)) {
          return;
        }
        throw new ProducerAbortedError({
          message: "Watch stream aborted by AbortSignal",
          acceptance: "not_applicable"
        });
      }
      throw new ProducerSdkError({
        code: "TRANSPORT_FAILURE",
        message:
          err instanceof Error
            ? `Watch stream transport failure: ${err.message}`
            : "Watch stream transport failure",
        retryable: true,
        acceptance: "not_applicable"
      });
    }

    if (!response.ok || response.status !== 200) {
      await throwWatchHttpError(response);
    }

    const contentType = response.headers.get("content-type")?.toLowerCase() ?? "";
    if (!contentType.includes("text/event-stream")) {
      throw new ProducerProtocolError({
        code: "PROTOCOL_ERROR",
        message: `Expected text/event-stream Content-Type on watch response, got "${contentType}"`,
        httpStatus: response.status,
        acceptance: "not_applicable"
      });
    }

    if (response.body === null) {
      throw new ProducerProtocolError({
        code: "PROTOCOL_ERROR",
        message: "Watch response is missing a readable body stream",
        httpStatus: response.status,
        acceptance: "not_applicable"
      });
    }

    const reader = response.body.getReader();
    const decoder = createSseChunkDecoder();

    try {
      while (!this.#closed) {
        let readResult: { readonly done: boolean; readonly value?: Uint8Array | undefined };
        try {
          readResult = await reader.read();
        } catch (err) {
          if (this.#closed && !Boolean(this.#externalSignal?.aborted)) {
            return;
          }
          if (
            Boolean(this.#externalSignal?.aborted) ||
            this.#internalAbortController.signal.aborted
          ) {
            throw new ProducerAbortedError({
              message: "Watch stream cancelled via AbortSignal",
              acceptance: "not_applicable"
            });
          }
          throw new ProducerSdkError({
            code: "TRANSPORT_FAILURE",
            message:
              err instanceof Error ? `Watch stream read failed: ${err.message}` : "Watch stream read failed",
            retryable: true,
            acceptance: "not_applicable"
          });
        }

        let parsedFrames: readonly ParsedSseFrame[];
        try {
          parsedFrames = readResult.done
            ? decoder.finish()
            : decoder.push(readResult.value ?? new Uint8Array(0));
        } catch (err) {
          if (err instanceof DomainError && err.code === "PAYLOAD_TOO_LARGE") {
            throw new ProducerValidationError({
              code: "PAYLOAD_TOO_LARGE",
              httpStatus: 413,
              message: err.message
            });
          }
          throw new ProducerProtocolError({
            code: "PROTOCOL_ERROR",
            message: err instanceof Error ? err.message : "Invalid SSE frame stream",
            acceptance: "not_applicable"
          });
        }

        for (const rawFrame of parsedFrames) {
          const mapped = mapParsedSseFrame(rawFrame);

          if (mapped.supported && mapped.frameType === "event") {
            const dedupKey = `${mapped.data.resource_kind}:${mapped.data.resource_id}:${mapped.data.event_sequence}`;
            if (this.#seenEventSequences.has(dedupKey)) {
              this.#lastHandledCursor = mapped.cursor;
              continue;
            }
            this.#seenEventSequences.add(dedupKey);
          }

          yield mapped;

          // Advance last_handled_cursor ONLY AFTER caller handles the yielded frame
          if (
            mapped.supported &&
            (mapped.frameType === "snapshot" || mapped.frameType === "event")
          ) {
            this.#lastHandledCursor = mapped.cursor;
          }

          if (
            mapped.supported &&
            (mapped.frameType === "resync_required" ||
              mapped.frameType === "authorization_lost" ||
              mapped.frameType === "unavailable")
          ) {
            this.#closed = true;
            return;
          }
        }

        if (readResult.done) {
          this.#closed = true;
          return;
        }
      }
    } finally {
      this.#closed = true;
      try {
        await reader.cancel();
      } catch {
        // Ignore stream cancellation cleanup errors
      }
      reader.releaseLock?.();
    }
  }
}
