import { WEBHOOK_MAX_BODY_BYTES, WEBHOOK_MAX_HEADER_BYTES } from "@relayquill/contracts";
import type { Sha256Hex } from "@relayquill/domain";
import { type RawHeaderInput, sha256HexNode } from "@relayquill/signing";
import { ReceiverValidationError } from "./errors.js";

export interface WebhookHttpRequestLike {
  readonly method?: string | undefined;
  readonly url?: string | undefined;
  readonly rawHeaders?: RawHeaderInput | undefined;
  readonly headers?: Readonly<Record<string, string | readonly string[] | undefined>> | undefined;
  readonly body?: Uint8Array | AsyncIterable<Uint8Array | Buffer | string> | undefined;
}

export type ReadBoundedRawWebhookRequestInput =
  | (WebhookHttpRequestLike & AsyncIterable<Uint8Array | Buffer | string>)
  | WebhookHttpRequestLike;

export interface ReadBoundedRawWebhookRequestOptions {
  readonly maxHeaderBytes?: number | undefined;
  readonly maxBodyBytes?: number | undefined;
  readonly allowEmptyBody?: boolean | undefined;
  readonly signal?: AbortSignal | undefined;
}

export interface BoundedRawWebhookRequest {
  readonly method: string;
  readonly rawUrl: string | undefined;
  readonly rawHeaders: ReadonlyArray<readonly [string, string]>;
  readonly rawBodyBytes: Uint8Array;
  readonly bodySha256: Sha256Hex;
}

function normalizePositiveLimit(value: number | undefined, fallback: number, name: string): number {
  const limit = value ?? fallback;
  if (!Number.isSafeInteger(limit) || limit <= 0) {
    throw new ReceiverValidationError({
      code: "INVALID_VALUE",
      message: `${name} must be a positive integer`
    });
  }
  return limit;
}

function normalizeRawHeadersToPairs(
  request: WebhookHttpRequestLike,
  maxHeaderBytes: number
): ReadonlyArray<readonly [string, string]> {
  const pairs: Array<readonly [string, string]> = [];
  let totalBytes = 0;

  const pushPair = (name: string, value: string): void => {
    totalBytes += Buffer.byteLength(name, "utf8") + Buffer.byteLength(value, "utf8") + 4;
    if (totalBytes > maxHeaderBytes) {
      throw new ReceiverValidationError({
        code: "PAYLOAD_TOO_LARGE",
        httpStatus: 413,
        message: `Webhook request headers exceed limit of ${maxHeaderBytes} bytes`,
        safeReason: "invalid_headers_or_duplicate"
      });
    }
    pairs.push(Object.freeze([name, value] as const));
  };

  if (request.rawHeaders !== undefined) {
    if (request.rawHeaders.length === 0) {
      return Object.freeze(pairs);
    }
    const first = request.rawHeaders[0];
    if (typeof first === "string") {
      const flat = request.rawHeaders as readonly string[];
      if (flat.length % 2 !== 0) {
        throw new ReceiverValidationError({
          code: "INVALID_VALUE",
          message: "rawHeaders alternating name/value list must have even length",
          safeReason: "invalid_headers_or_duplicate"
        });
      }
      for (let i = 0; i < flat.length; i += 2) {
        const name = flat[i];
        const value = flat[i + 1];
        if (typeof name !== "string" || typeof value !== "string") {
          throw new ReceiverValidationError({
            code: "INVALID_VALUE",
            message: "Invalid non-string raw header entry",
            safeReason: "invalid_headers_or_duplicate"
          });
        }
        pushPair(name, value);
      }
      return Object.freeze(pairs);
    }

    for (const entry of request.rawHeaders as ReadonlyArray<readonly [string, string]>) {
      if (!Array.isArray(entry) || entry.length !== 2 || typeof entry[0] !== "string" || typeof entry[1] !== "string") {
        throw new ReceiverValidationError({
          code: "INVALID_VALUE",
          message: "Invalid raw header tuple entry",
          safeReason: "invalid_headers_or_duplicate"
        });
      }
      pushPair(entry[0], entry[1]);
    }
    return Object.freeze(pairs);
  }

  if (request.headers !== undefined) {
    for (const [name, rawValue] of Object.entries(request.headers)) {
      if (rawValue === undefined) {
        continue;
      }
      if (typeof rawValue === "string") {
        pushPair(name, rawValue);
      } else if (Array.isArray(rawValue)) {
        for (const item of rawValue) {
          if (typeof item === "string") {
            pushPair(name, item);
          }
        }
      }
    }
  }

  return Object.freeze(pairs);
}

function isAsyncIterable(value: unknown): value is AsyncIterable<Uint8Array | Buffer | string> {
  return (
    value !== null &&
    typeof value === "object" &&
    Symbol.asyncIterator in value &&
    typeof (value as { readonly [Symbol.asyncIterator]?: unknown })[Symbol.asyncIterator] === "function"
  );
}

function destroyStreamIfSupported(stream: unknown): void {
  if (
    stream !== null &&
    typeof stream === "object" &&
    "destroy" in stream &&
    typeof (stream as { readonly destroy?: unknown }).destroy === "function"
  ) {
    try {
      (stream as { destroy(): void }).destroy();
    } catch {
      // ignore stream cleanup failure
    }
  }
}

export async function readBoundedRawWebhookRequest(
  request: ReadBoundedRawWebhookRequestInput,
  options: ReadBoundedRawWebhookRequestOptions = {}
): Promise<BoundedRawWebhookRequest> {
  const signal = options.signal;
  if (signal?.aborted) {
    throw new ReceiverValidationError({
      code: "INVALID_VALUE",
      message: "Request reading aborted"
    });
  }

  const maxHeaderBytes = normalizePositiveLimit(
    options.maxHeaderBytes,
    WEBHOOK_MAX_HEADER_BYTES,
    "maxHeaderBytes"
  );
  const maxBodyBytes = normalizePositiveLimit(
    options.maxBodyBytes,
    WEBHOOK_MAX_BODY_BYTES,
    "maxBodyBytes"
  );

  const method = request.method ?? "POST";
  const rawUrl = request.url;
  const rawHeaders = normalizeRawHeadersToPairs(request, maxHeaderBytes);

  let rawBodyBytes: Uint8Array;
  const bodyCandidate = isAsyncIterable(request) ? request : request.body;

  if (bodyCandidate instanceof Uint8Array) {
    if (bodyCandidate.byteLength > maxBodyBytes) {
      throw new ReceiverValidationError({
        code: "PAYLOAD_TOO_LARGE",
        httpStatus: 413,
        message: `Webhook body exceeds limit of ${maxBodyBytes} bytes`,
        safeReason: "invalid_body_framing"
      });
    }
    rawBodyBytes = Uint8Array.from(bodyCandidate);
  } else if (isAsyncIterable(bodyCandidate)) {
    const chunks: Uint8Array[] = [];
    let totalBytes = 0;

    for await (const chunk of bodyCandidate) {
      if (Boolean(signal?.aborted)) {
        destroyStreamIfSupported(bodyCandidate);
        throw new ReceiverValidationError({
          code: "INVALID_VALUE",
          message: "Request reading aborted"
        });
      }
      const chunkBytes =
        chunk instanceof Uint8Array
          ? chunk
          : Buffer.from(chunk, "utf8");
      if (totalBytes + chunkBytes.byteLength > maxBodyBytes) {
        destroyStreamIfSupported(bodyCandidate);
        throw new ReceiverValidationError({
          code: "PAYLOAD_TOO_LARGE",
          httpStatus: 413,
          message: `Webhook body exceeds limit of ${maxBodyBytes} bytes`,
          safeReason: "invalid_body_framing"
        });
      }
      if (chunkBytes.byteLength > 0) {
        chunks.push(Uint8Array.from(chunkBytes));
        totalBytes += chunkBytes.byteLength;
      }
    }

    const merged = new Uint8Array(totalBytes);
    let offset = 0;
    for (const chunk of chunks) {
      merged.set(chunk, offset);
      offset += chunk.byteLength;
    }
    rawBodyBytes = merged;
  } else if (bodyCandidate === undefined) {
    rawBodyBytes = new Uint8Array(0);
  } else {
    throw new ReceiverValidationError({
      code: "INVALID_VALUE",
      message: "Request body must be Uint8Array or AsyncIterable",
      safeReason: "invalid_body_framing"
    });
  }

  if (!options.allowEmptyBody && rawBodyBytes.byteLength === 0) {
    throw new ReceiverValidationError({
      code: "INVALID_VALUE",
      message: "Webhook request body must be non-empty",
      safeReason: "invalid_body_framing"
    });
  }

  return Object.freeze({
    method,
    rawUrl,
    rawHeaders,
    rawBodyBytes,
    bodySha256: sha256HexNode(rawBodyBytes)
  });
}
