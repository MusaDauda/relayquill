import crypto from "node:crypto";
import type http from "node:http";
import { type Sha256Hex } from "@relayquill/contracts";
import {
  type DeliveryOutcomeClass,
  classifyHttpOutcome,
  isValidHttpStatus
} from "@relayquill/domain";

export const MAX_RESPONSE_HEADER_BYTES = 8_192 as const;
export const MAX_RESPONSE_BODY_BYTES = 65_536 as const;
export const RECEIPT_BODY_MAX_BYTES = 4_096 as const;

export type ResponseBodyDisposition =
  | "complete"
  | "empty"
  | "oversized"
  | "unsupported_encoding"
  | "truncated_or_lost"
  | "redirect_not_followed";

export interface BoundedResponseResult {
  readonly status: number;
  readonly outcomeClass: DeliveryOutcomeClass;
  readonly httpAcknowledged: boolean;
  readonly retryable: boolean;
  readonly safeErrorCode: string | null;
  readonly rawHeaders: ReadonlyArray<readonly [string, string]>;
  readonly rawHeaderBytes: number;
  readonly contentType: string | null;
  readonly contentEncoding: string | null;
  readonly bodyDisposition: ResponseBodyDisposition;
  readonly bodyBytes: Uint8Array;
  readonly bodyByteCount: number;
  readonly bodySha256: Sha256Hex | null;
  readonly receiptEligible: boolean;
}

export interface InspectResponseHeadersResult {
  readonly ok: boolean;
  readonly rawHeaderPairs: ReadonlyArray<readonly [string, string]>;
  readonly rawHeaderBytes: number;
  readonly contentType: string | null;
  readonly contentEncoding: string | null;
  readonly isCompressed: boolean;
  readonly reasonCode?: string | undefined;
}

export function inspectResponseHeaders(
  rawHeadersInput: readonly string[],
  maxHeaderBytes: number = MAX_RESPONSE_HEADER_BYTES
): InspectResponseHeadersResult {
  const pairs: Array<readonly [string, string]> = [];
  let totalBytes = 0;
  let contentType: string | null = null;
  let contentEncoding: string | null = null;

  for (let i = 0; i < rawHeadersInput.length; i += 2) {
    const name = rawHeadersInput[i] ?? "";
    const value = rawHeadersInput[i + 1] ?? "";
    totalBytes += Buffer.byteLength(name, "utf8") + Buffer.byteLength(value, "utf8") + 4;
    if (totalBytes > maxHeaderBytes) {
      return Object.freeze({
        ok: false,
        rawHeaderPairs: Object.freeze(pairs),
        rawHeaderBytes: totalBytes,
        contentType,
        contentEncoding,
        isCompressed: false,
        reasonCode: "RESPONSE_HEADERS_TOO_LARGE"
      });
    }
    const lower = name.toLowerCase();
    if (lower === "content-type") {
      contentType = contentType === null ? value : `${contentType}, ${value}`;
    } else if (lower === "content-encoding") {
      contentEncoding = contentEncoding === null ? value : `${contentEncoding}, ${value}`;
    }
    pairs.push(Object.freeze([name, value] as const));
  }

  const normalizedEncoding = contentEncoding?.trim().toLowerCase() ?? "";
  const isCompressed = normalizedEncoding.length > 0 && normalizedEncoding !== "identity";

  return Object.freeze({
    ok: true,
    rawHeaderPairs: Object.freeze(pairs),
    rawHeaderBytes: totalBytes,
    contentType,
    contentEncoding,
    isCompressed
  });
}

export interface ReadBoundedResponseOptions {
  readonly maxHeaderBytes?: number | undefined;
  readonly maxBodyBytes?: number | undefined;
  readonly signal?: AbortSignal | undefined;
}

function isJsonMediaType(contentType: string | null): boolean {
  if (contentType === null || contentType.includes(",")) {
    return false;
  }
  const media = contentType.split(";")[0]?.trim().toLowerCase();
  return media === "application/json";
}

export async function readBoundedResponse(
  res: http.IncomingMessage,
  options: ReadBoundedResponseOptions = {}
): Promise<BoundedResponseResult> {
  const maxHeaderBytes = options.maxHeaderBytes ?? MAX_RESPONSE_HEADER_BYTES;
  const maxBodyBytes = options.maxBodyBytes ?? MAX_RESPONSE_BODY_BYTES;
  const status = res.statusCode ?? 0;

  if (!isValidHttpStatus(status)) {
    res.destroy();
    throw Object.assign(new Error("Invalid HTTP response status code"), {
      safeErrorCode: "INVALID_RESPONSE_STATUS",
      headersObserved: false
    });
  }

  const headerInfo = inspectResponseHeaders(res.rawHeaders, maxHeaderBytes);
  if (!headerInfo.ok) {
    res.destroy();
    throw Object.assign(new Error("Response headers exceed allowed budget"), {
      safeErrorCode: headerInfo.reasonCode ?? "RESPONSE_HEADERS_TOO_LARGE",
      headersObserved: false
    });
  }

  // Never follow 3xx redirects; destroy response immediately.
  if (status >= 300 && status <= 399) {
    res.destroy();
    const classified = classifyHttpOutcome(status);
    return Object.freeze({
      status,
      outcomeClass: classified.outcomeClass,
      httpAcknowledged: false,
      retryable: classified.retryable,
      safeErrorCode: classified.safeErrorCode,
      rawHeaders: headerInfo.rawHeaderPairs,
      rawHeaderBytes: headerInfo.rawHeaderBytes,
      contentType: headerInfo.contentType,
      contentEncoding: headerInfo.contentEncoding,
      bodyDisposition: "redirect_not_followed",
      bodyBytes: new Uint8Array(0),
      bodyByteCount: 0,
      bodySha256: null,
      receiptEligible: false
    });
  }

  const classified = classifyHttpOutcome(status);
  const httpAcknowledged = status >= 200 && status <= 299;

  // Compression is unsupported: destroy without decompressing while keeping 2xx HTTP acknowledgement.
  if (headerInfo.isCompressed) {
    res.destroy();
    return Object.freeze({
      status,
      outcomeClass: classified.outcomeClass,
      httpAcknowledged,
      retryable: classified.retryable,
      safeErrorCode: classified.safeErrorCode,
      rawHeaders: headerInfo.rawHeaderPairs,
      rawHeaderBytes: headerInfo.rawHeaderBytes,
      contentType: headerInfo.contentType,
      contentEncoding: headerInfo.contentEncoding,
      bodyDisposition: "unsupported_encoding",
      bodyBytes: new Uint8Array(0),
      bodyByteCount: 0,
      bodySha256: null,
      receiptEligible: false
    });
  }

  const chunks: Buffer[] = [];
  let totalBytes = 0;

  const disposition = await new Promise<ResponseBodyDisposition>((resolve) => {
    let settled = false;
    const finish = (nextDisposition: ResponseBodyDisposition): void => {
      if (settled) {
        return;
      }
      settled = true;
      cleanup();
      resolve(nextDisposition);
    };

    const onData = (chunk: Buffer | string): void => {
      const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      if (totalBytes + buf.byteLength > maxBodyBytes) {
        res.destroy();
        finish("oversized");
        return;
      }
      totalBytes += buf.byteLength;
      chunks.push(buf);
    };

    const onEnd = (): void => {
      if (res.complete === false) {
        finish("truncated_or_lost");
      } else {
        finish(totalBytes === 0 ? "empty" : "complete");
      }
    };

    const onClose = (): void => {
      if (!settled) {
        finish(res.complete ? (totalBytes === 0 ? "empty" : "complete") : "truncated_or_lost");
      }
    };

    const onError = (): void => {
      finish("truncated_or_lost");
    };

    const onAbort = (): void => {
      res.destroy();
      finish("truncated_or_lost");
    };

    const cleanup = (): void => {
      res.off("data", onData);
      res.off("end", onEnd);
      res.off("close", onClose);
      res.off("error", onError);
      options.signal?.removeEventListener("abort", onAbort);
    };

    if (options.signal?.aborted) {
      onAbort();
      return;
    }

    res.on("data", onData);
    res.on("end", onEnd);
    res.on("close", onClose);
    res.on("error", onError);
    options.signal?.addEventListener("abort", onAbort, { once: true });
  });

  if (disposition === "oversized" || disposition === "truncated_or_lost") {
    return Object.freeze({
      status,
      outcomeClass: classified.outcomeClass,
      httpAcknowledged,
      retryable: classified.retryable,
      safeErrorCode: classified.safeErrorCode,
      rawHeaders: headerInfo.rawHeaderPairs,
      rawHeaderBytes: headerInfo.rawHeaderBytes,
      contentType: headerInfo.contentType,
      contentEncoding: headerInfo.contentEncoding,
      bodyDisposition: disposition,
      bodyBytes: new Uint8Array(0),
      bodyByteCount: 0,
      bodySha256: null,
      receiptEligible: false
    });
  }

  const combined = totalBytes === 0 ? Buffer.alloc(0) : Buffer.concat(chunks, totalBytes);
  const bodyBytes = new Uint8Array(combined.buffer, combined.byteOffset, combined.byteLength);
  const bodySha256 = crypto.createHash("sha256").update(bodyBytes).digest("hex") as Sha256Hex;
  const receiptEligible =
    httpAcknowledged &&
    disposition === "complete" &&
    bodyBytes.byteLength > 0 &&
    bodyBytes.byteLength <= RECEIPT_BODY_MAX_BYTES &&
    isJsonMediaType(headerInfo.contentType);

  return Object.freeze({
    status,
    outcomeClass: classified.outcomeClass,
    httpAcknowledged,
    retryable: classified.retryable,
    safeErrorCode: classified.safeErrorCode,
    rawHeaders: headerInfo.rawHeaderPairs,
    rawHeaderBytes: headerInfo.rawHeaderBytes,
    contentType: headerInfo.contentType,
    contentEncoding: headerInfo.contentEncoding,
    bodyDisposition: disposition,
    bodyBytes,
    bodyByteCount: bodyBytes.byteLength,
    bodySha256,
    receiptEligible
  });
}
