import { type AcceptanceStatus, type SafeResourceRef } from "@relayquill/domain";
import {
  type CanonicalUtcTimestamp,
  type HttpFieldError,
  type ResponseMeta,
  classifyResponseEnvelope,
  parseIdempotencyKey
} from "@relayquill/contracts";

export interface HttpApiSuccess<T> {
  readonly ok: true;
  readonly status: number;
  readonly data: T;
  readonly meta: ResponseMeta;
}

export interface HttpApiFailure {
  readonly ok: false;
  readonly status: number;
  readonly code: string;
  readonly message: string;
  readonly acceptance: AcceptanceStatus;
  readonly retryable: boolean;
  readonly fieldErrors: readonly HttpFieldError[];
  readonly resourceRef?: SafeResourceRef | undefined;
  readonly retryAfterSeconds?: number | undefined;
  readonly meta?: ResponseMeta | undefined;
  readonly unsupportedProtocol?: boolean | undefined;
  readonly aborted?: boolean | undefined;
}

export type HttpApiResult<T> = HttpApiSuccess<T> | HttpApiFailure;

export interface HttpClientRequestOptions<T> {
  readonly method: "GET" | "POST";
  readonly path: string;
  readonly parseData: (raw: unknown) => T;
  readonly bodyJson?: string | undefined;
  readonly bodyObj?: unknown;
  readonly idempotencyKey?: string | undefined;
  readonly csrfToken?: string | null | undefined;
  readonly signal?: AbortSignal | undefined;
  readonly timeoutMs?: number | undefined;
  readonly isMutation?: boolean | undefined;
}

export function parseRetryAfterSeconds(headerValue: string | null, nowMs = Date.now()): number | undefined {
  if (headerValue === null) {
    return undefined;
  }
  const trimmed = headerValue.trim();
  if (trimmed.length === 0) {
    return undefined;
  }
  if (/^\d+$/.test(trimmed)) {
    const secs = Number.parseInt(trimmed, 10);
    return Number.isSafeInteger(secs) && secs >= 0 ? Math.min(secs, 3600) : undefined;
  }
  const parsedDate = Date.parse(trimmed);
  if (!Number.isNaN(parsedDate)) {
    const deltaSecs = Math.ceil((parsedDate - nowMs) / 1000);
    return deltaSecs > 0 ? Math.min(deltaSecs, 3600) : 0;
  }
  return undefined;
}

export interface HttpTransport {
  fetchImpl?: typeof fetch | undefined;
  getCsrfToken: () => string | null;
  onUnauthorized?: (() => void) | undefined;
  basePath?: string | undefined;
}

export function createConsoleHttpClient(transport: HttpTransport) {
  const fetchFn = transport.fetchImpl ?? ((input: RequestInfo | URL, init?: RequestInit) => fetch(input, init));
  const basePath = transport.basePath ?? "";

  async function request<T>(opts: HttpClientRequestOptions<T>): Promise<HttpApiResult<T>> {
    const isMutation = opts.isMutation ?? opts.method !== "GET";
    const headers: Record<string, string> = {
      Accept: "application/json"
    };

    let bodyStr: string | undefined = opts.bodyJson;
    if (bodyStr === undefined && opts.bodyObj !== undefined) {
      bodyStr = JSON.stringify(opts.bodyObj);
    }
    if (bodyStr !== undefined) {
      headers["Content-Type"] = "application/json";
    }

    if (opts.idempotencyKey !== undefined) {
      const validKey = parseIdempotencyKey(opts.idempotencyKey, "Idempotency-Key");
      headers["Idempotency-Key"] = validKey;
    }

    const csrfToken = opts.csrfToken !== undefined ? opts.csrfToken : transport.getCsrfToken();
    if (isMutation && csrfToken !== null && csrfToken.length > 0) {
      headers["X-CSRF-Token"] = csrfToken;
    }

    const controller = new AbortController();
    const timeoutMs = opts.timeoutMs ?? 10_000;
    let timedOut = false;
    const timeoutId = globalThis.setTimeout(() => {
      timedOut = true;
      controller.abort();
    }, timeoutMs);

    const onExternalAbort = (): void => {
      controller.abort();
    };
    if (opts.signal !== undefined) {
      if (opts.signal.aborted) {
        globalThis.clearTimeout(timeoutId);
        return {
          ok: false,
          status: 0,
          code: isMutation ? "ACCEPTANCE_UNKNOWN" : "REQUEST_ABORTED",
          message: isMutation
            ? "Request was aborted after dispatch; server commit state is unknown."
            : "Request cancelled due to scope change or navigation.",
          acceptance: isMutation ? "unknown" : "not_applicable",
          retryable: isMutation,
          fieldErrors: [],
          aborted: true
        };
      }
      opts.signal.addEventListener("abort", onExternalAbort, { once: true });
    }

    let response: Response;
    try {
      response = await fetchFn(`${basePath}${opts.path}`, {
        method: opts.method,
        credentials: "same-origin",
        cache: "no-store",
        headers,
        ...(bodyStr !== undefined ? { body: bodyStr } : {}),
        signal: controller.signal
      });
    } catch {
      globalThis.clearTimeout(timeoutId);
      opts.signal?.removeEventListener("abort", onExternalAbort);
      const isExternalAbort = opts.signal?.aborted === true && !timedOut;
      if (isExternalAbort && !isMutation) {
        return {
          ok: false,
          status: 0,
          code: "REQUEST_ABORTED",
          message: "Read request cancelled after scope change.",
          acceptance: "not_applicable",
          retryable: true,
          fieldErrors: [],
          aborted: true
        };
      }
      return {
        ok: false,
        status: 503,
        code: isMutation ? "ACCEPTANCE_UNKNOWN" : "DEPENDENCY_UNAVAILABLE",
        message: timedOut
          ? isMutation
            ? "Request timed out before response; durable server acceptance is unknown."
            : "Request timed out waiting for API response."
          : isMutation
            ? "Network error interrupted mutation response; server acceptance is unknown."
            : "Network error reaching API server.",
        acceptance: isMutation ? "unknown" : "not_applicable",
        retryable: true,
        fieldErrors: [],
        aborted: isExternalAbort
      };
    }

    globalThis.clearTimeout(timeoutId);
    opts.signal?.removeEventListener("abort", onExternalAbort);

    const retryAfterSeconds = parseRetryAfterSeconds(response.headers.get("retry-after"));

    if (response.status === 204) {
      let parsedNoBody: T;
      try {
        parsedNoBody = opts.parseData(undefined);
      } catch {
        return {
          ok: false,
          status: 502,
          code: "UNSUPPORTED_RESPONSE_PROTOCOL",
          message: "Unexpected 204 No Content response for route requiring body.",
          acceptance: isMutation ? "unknown" : "not_applicable",
          retryable: false,
          fieldErrors: [],
          unsupportedProtocol: true
        };
      }
      const nowIso = new Date().toISOString().replace("Z", "000Z") as CanonicalUtcTimestamp;
      return {
        ok: true,
        status: 204,
        data: parsedNoBody,
        meta: {
          request_id: response.headers.get("x-request-id") ?? "no-content-204",
          response_schema_version: 1,
          observed_at: nowIso
        }
      };
    }

    let rawJson: unknown;
    try {
      rawJson = await response.json();
    } catch {
      if (response.status === 401) {
        transport.onUnauthorized?.();
      }
      return {
        ok: false,
        status: response.status,
        code: response.status >= 200 && response.status < 300 ? "ACCEPTANCE_UNKNOWN" : "DEPENDENCY_UNAVAILABLE",
        message:
          response.status >= 200 && response.status < 300
            ? "Committed HTTP 2xx reply could not be parsed as JSON; outcome requires resolution."
            : `API returned non-JSON HTTP ${response.status} response.`,
        acceptance: isMutation && (response.status >= 500 || response.status < 300) ? "unknown" : "known_rejected",
        retryable: response.status >= 500 || response.status === 429,
        fieldErrors: [],
        ...(retryAfterSeconds !== undefined ? { retryAfterSeconds } : {}),
        unsupportedProtocol: true
      };
    }

    const classified = classifyResponseEnvelope(rawJson, opts.parseData);
    if (!classified.supported) {
      return {
        ok: false,
        status: response.status,
        code: "UNSUPPORTED_SCHEMA_VERSION",
        message:
          classified.reason === "unsupported_response_schema_version"
            ? `Unsupported response_schema_version (${String(classified.response_schema_version)}).`
            : isMutation && response.status >= 200 && response.status < 300
              ? "Response envelope failed schema validation; original mutation outcome is unknown."
              : "Response envelope failed contract validation.",
        acceptance:
          isMutation && (response.status < 300 || response.status >= 500)
            ? "unknown"
            : "known_rejected",
        retryable: false,
        fieldErrors: [],
        ...(retryAfterSeconds !== undefined ? { retryAfterSeconds } : {}),
        unsupportedProtocol: true
      };
    }

    if (classified.kind === "success") {
      if (response.status < 200 || response.status >= 300) {
        return {
          ok: false,
          status: response.status,
          code: "UNSUPPORTED_RESPONSE_PROTOCOL",
          message: `HTTP ${response.status} unexpectedly carried a success envelope.`,
          acceptance: "unknown",
          retryable: false,
          fieldErrors: [],
          unsupportedProtocol: true
        };
      }
      return {
        ok: true,
        status: response.status,
        data: classified.envelope.data,
        meta: classified.envelope.meta
      };
    }

    const errEnv = classified.envelope;
    if (response.status === 401) {
      transport.onUnauthorized?.();
    }

    return {
      ok: false,
      status: response.status,
      code: errEnv.error.code,
      message: errEnv.error.message,
      acceptance: errEnv.error.acceptance,
      retryable: errEnv.error.retryable,
      fieldErrors: errEnv.error.field_errors ?? [],
      ...(errEnv.error.resource_ref !== undefined ? { resourceRef: errEnv.error.resource_ref } : {}),
      ...(retryAfterSeconds !== undefined ? { retryAfterSeconds } : {}),
      meta: errEnv.meta
    };
  }

  return { request };
}

export type ConsoleHttpClient = ReturnType<typeof createConsoleHttpClient>;
