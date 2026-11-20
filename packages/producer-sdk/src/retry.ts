import {
  ProducerAbortedError,
  ProducerPressureError,
  ProducerValidationError
} from "./errors.js";
import { type WebCryptoLike, requireWebCrypto } from "./values.js";

export const DEFAULT_MAX_RETRY_ATTEMPTS = 3 as const;
export const DEFAULT_TOTAL_RETRY_BUDGET_MS = 20_000 as const;
export const DEFAULT_MIN_JITTER_MS = 100 as const;
export const DEFAULT_MAX_JITTER_MS = 2_000 as const;

export const DEFAULT_MAX_CONCURRENT_REQUESTS = 4 as const;
export const DEFAULT_MAX_QUEUED_OPERATIONS = 16 as const;
export const DEFAULT_MAX_QUEUED_BYTES = 8_388_608 as const;

export interface ProducerRetryPolicy {
  readonly maxAttempts?: number | undefined;
  readonly totalBudgetMs?: number | undefined;
  readonly minJitterMs?: number | undefined;
  readonly maxJitterMs?: number | undefined;
  readonly sleep?: ((delayMs: number, signal?: AbortSignal) => Promise<void>) | undefined;
  readonly nowMs?: (() => number) | undefined;
  readonly randomUint32?: (() => number) | undefined;
  readonly crypto?: WebCryptoLike | undefined;
}

export function drawUniformUint32WebCrypto(customCrypto?: WebCryptoLike): number {
  const webCrypto = requireWebCrypto(customCrypto);
  const buf = new Uint32Array(1);
  webCrypto.getRandomValues(new Uint8Array(buf.buffer));
  return buf[0] ?? 0;
}

export function computeBoundedJitterMs(
  minMs: number = DEFAULT_MIN_JITTER_MS,
  maxMs: number = DEFAULT_MAX_JITTER_MS,
  randomUint32?: () => number,
  customCrypto?: WebCryptoLike
): number {
  if (!Number.isInteger(minMs) || !Number.isInteger(maxMs) || minMs < 0 || maxMs < minMs) {
    throw new ProducerValidationError({
      message: `Invalid jitter range [${String(minMs)}, ${String(maxMs)}]`
    });
  }
  if (minMs === maxMs) {
    return minMs;
  }
  const span = maxMs - minMs + 1;
  const draw = randomUint32 !== undefined ? randomUint32() >>> 0 : drawUniformUint32WebCrypto(customCrypto);
  return minMs + (draw % span);
}

const DELAY_SECONDS_REGEX = /^(?:0|[1-9][0-9]{0,8})$/;

export function parseRetryAfterHeader(
  headerValue: string | null | undefined,
  nowMs: number = Date.now()
): number | null {
  if (headerValue === undefined || headerValue === null) {
    return null;
  }
  const trimmed = headerValue.trim();
  if (trimmed.length === 0 || trimmed.length > 128) {
    return null;
  }
  if (DELAY_SECONDS_REGEX.test(trimmed)) {
    const seconds = Number.parseInt(trimmed, 10);
    if (!Number.isSafeInteger(seconds) || seconds < 0) {
      return null;
    }
    return seconds * 1_000;
  }
  const parsedDateMs = Date.parse(trimmed);
  if (Number.isNaN(parsedDateMs)) {
    return null;
  }
  const deltaMs = parsedDateMs - nowMs;
  return deltaMs <= 0 ? 0 : Math.ceil(deltaMs);
}

export function isRetryableHttpStatus(status: number): boolean {
  if (status === 408 || status === 425 || status === 429) {
    return true;
  }
  if (status >= 500 && status <= 599) {
    return status !== 501 && status !== 505;
  }
  return false;
}

export async function defaultSleepWithAbort(
  delayMs: number,
  signal?: AbortSignal,
  wasDispatched = false
): Promise<void> {
  if (signal?.aborted === true) {
    throw new ProducerAbortedError({
      acceptance: wasDispatched ? "unknown" : "known_rejected"
    });
  }
  if (delayMs <= 0) {
    return;
  }
  await new Promise<void>((resolve, reject) => {
    const onAbort = (): void => {
      clearTimeout(timer);
      reject(
        new ProducerAbortedError({
          acceptance: wasDispatched ? "unknown" : "known_rejected"
        })
      );
    };
    const timer = setTimeout(() => {
      signal?.removeEventListener("abort", onAbort);
      resolve();
    }, delayMs);
    signal?.addEventListener("abort", onAbort, { once: true });
  });
}

interface QueuedWaiter {
  readonly byteCost: number;
  readonly grant: () => void;
}

export class ClientPressureLimiter {
  readonly #maxConcurrent: number;
  readonly #maxQueuedOps: number;
  readonly #maxQueuedBytes: number;
  #activeCount = 0;
  #queuedBytes = 0;
  readonly #queue: QueuedWaiter[] = [];

  constructor(options?: {
    readonly maxConcurrentRequests?: number | undefined;
    readonly maxQueuedOperations?: number | undefined;
    readonly maxQueuedBytes?: number | undefined;
  }) {
    const maxConcurrent = options?.maxConcurrentRequests ?? DEFAULT_MAX_CONCURRENT_REQUESTS;
    const maxQueuedOps = options?.maxQueuedOperations ?? DEFAULT_MAX_QUEUED_OPERATIONS;
    const maxQueuedBytes = options?.maxQueuedBytes ?? DEFAULT_MAX_QUEUED_BYTES;

    if (
      !Number.isInteger(maxConcurrent) ||
      maxConcurrent < 1 ||
      !Number.isInteger(maxQueuedOps) ||
      maxQueuedOps < 0 ||
      !Number.isInteger(maxQueuedBytes) ||
      maxQueuedBytes < 1
    ) {
      throw new ProducerValidationError({
        message: "Invalid client pressure limiter bounds"
      });
    }
    this.#maxConcurrent = maxConcurrent;
    this.#maxQueuedOps = maxQueuedOps;
    this.#maxQueuedBytes = maxQueuedBytes;
  }

  get activeCount(): number {
    return this.#activeCount;
  }

  get queuedCount(): number {
    return this.#queue.length;
  }

  get queuedBytes(): number {
    return this.#queuedBytes;
  }

  async run<T>(byteCost: number, fn: () => Promise<T>): Promise<T> {
    const normalizedBytes = Math.max(0, byteCost);
    await this.#acquire(normalizedBytes);
    try {
      return await fn();
    } finally {
      this.#release();
    }
  }

  async #acquire(byteCost: number): Promise<void> {
    if (this.#activeCount < this.#maxConcurrent && this.#queue.length === 0) {
      this.#activeCount += 1;
      return;
    }
    if (this.#queue.length >= this.#maxQueuedOps) {
      throw new ProducerPressureError({
        code: "CAPACITY_EXCEEDED",
        httpStatus: 429,
        message: `Local producer client operation queue limit (${this.#maxQueuedOps}) exceeded`,
        retryable: true,
        acceptance: "known_rejected"
      });
    }
    if (this.#queuedBytes + byteCost > this.#maxQueuedBytes) {
      throw new ProducerPressureError({
        code: "CAPACITY_EXCEEDED",
        httpStatus: 429,
        message: `Local producer client queued payload byte budget (${this.#maxQueuedBytes} bytes) exceeded`,
        retryable: true,
        acceptance: "known_rejected"
      });
    }

    this.#queuedBytes += byteCost;
    await new Promise<void>((resolve) => {
      this.#queue.push({
        byteCost,
        grant: () => {
          this.#queuedBytes -= byteCost;
          resolve();
        }
      });
    });
  }

  #release(): void {
    const next = this.#queue.shift();
    if (next !== undefined) {
      next.grant();
      return;
    }
    this.#activeCount = Math.max(0, this.#activeCount - 1);
  }
}
