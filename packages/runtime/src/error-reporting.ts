import crypto from "node:crypto";
import { ValidationDomainError } from "@relayquill/domain";
import { redactTelemetryText } from "./trace-context.js";

export interface ParsedSentryDsn {
  readonly enabled: true;
  readonly origin: string;
  readonly publicKey: string;
  readonly projectId: string;
  readonly envelopeUrl: string;
}

export interface DisabledSentryDsn {
  readonly enabled: false;
}

export type SentryDsnConfig = ParsedSentryDsn | DisabledSentryDsn;

export interface ParseSentryDsnOptions {
  readonly allowInsecureLocalhost?: boolean | undefined;
}

export interface CapturedErrorEvent {
  readonly sent: boolean;
  readonly reason: "dispatched" | "dsn_unset" | "transport_error" | "http_rejected";
  readonly eventId: string;
  readonly statusCode?: number;
  readonly scrubbedMessage: string;
}

export interface ErrorCaptureContext {
  readonly service: string;
  readonly environment?: string | undefined;
  readonly release?: string | undefined;
  readonly route?: string | undefined;
  readonly method?: string | undefined;
  readonly statusCode?: number | undefined;
  readonly requestId?: string | undefined;
  readonly tenantId?: string | undefined;
  readonly tags?: Readonly<Record<string, string>> | undefined;
  readonly extra?: Readonly<Record<string, unknown>> | undefined;
}

export interface ErrorReporter {
  readonly enabled: boolean;
  readonly provider: "sentry" | "noop";
  readonly projectId?: string | undefined;
  captureException(
    error: unknown,
    context: ErrorCaptureContext
  ): Promise<CapturedErrorEvent>;
}

export interface CreateEnvGatedErrorReporterOptions {
  readonly dsn?: string | undefined;
  readonly environment?: string | undefined;
  readonly release?: string | undefined;
  readonly service?: string | undefined;
  readonly allowInsecureLocalhost?: boolean | undefined;
  readonly fetchImpl?: typeof fetch | undefined;
  readonly timeoutMs?: number | undefined;
}

const SENSITIVE_KEY_PATTERN =
  /^(authorization|cookie|set-cookie|password|passwd|secret|token|api[_-]?key|signing[_-]?secret|client[_-]?secret|x-relayquill-.*|totp|email|payload|body|raw_body)$/i;
const MAX_MESSAGE_LEN = 512;
const MAX_STACK_FRAMES = 12;

/**
 * Parses an optional Sentry DSN while blocking plaintext remote HTTP endpoints.
 */
export function parseSentryDsn(
  rawDsn: string | undefined,
  options: ParseSentryDsnOptions = {}
): SentryDsnConfig {
  const trimmed = rawDsn?.trim() ?? "";
  if (trimmed.length === 0) {
    return Object.freeze({ enabled: false });
  }

  let parsed: URL;
  try {
    parsed = new URL(trimmed);
  } catch {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: "SENTRY_DSN must be a valid URL"
    });
  }

  const isLocalHost =
    parsed.hostname === "localhost" ||
    parsed.hostname === "127.0.0.1" ||
    parsed.hostname === "::1";
  const allowHttp = options.allowInsecureLocalhost === true && isLocalHost;
  if (parsed.protocol !== "https:" && !(allowHttp && parsed.protocol === "http:")) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: "SENTRY_DSN must use https:// (or http:// on localhost when explicitly allowed)"
    });
  }

  const publicKey = parsed.username.trim();
  const projectId = parsed.pathname.replace(/^\/+|\/+$/g, "");
  if (publicKey.length === 0 || !/^\d+$/.test(projectId)) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: "SENTRY_DSN must include a public key and numeric project ID"
    });
  }

  const basePath = `${parsed.protocol}//${parsed.host}`;
  return Object.freeze({
    enabled: true,
    origin: basePath,
    publicKey,
    projectId,
    envelopeUrl: `${basePath}/api/${projectId}/envelope/`
  });
}

function scrubStringValue(value: string): string {
  const withoutUrlsQuery = value.replace(
    /\bhttps?:\/\/[^\s"'<>]+/gi,
    (matched) => {
      try {
        const u = new URL(matched);
        return `${u.protocol}//${u.host}${u.pathname}`;
      } catch {
        return "[REDACTED_URL]";
      }
    }
  );
  const redacted = redactTelemetryText(withoutUrlsQuery)
    .replace(/\bwhsec_[A-Za-z0-9_-]+/g, "[REDACTED_WEBHOOK_SECRET]")
    .replace(/\brk_(?:live|test)_[A-Za-z0-9]+/g, "[REDACTED_STRIPE_KEY]")
    .replace(/\bsk_(?:live|test)_[A-Za-z0-9]+/g, "[REDACTED_SECRET_KEY]")
    .replace(/\bpk_(?:live|test)_[A-Za-z0-9]+/g, "[REDACTED_PUBLIC_KEY]");
  return redacted.slice(0, MAX_MESSAGE_LEN);
}

function scrubRecord(
  input: Readonly<Record<string, unknown>> | undefined,
  depth = 0
): Readonly<Record<string, unknown>> {
  if (input === undefined || depth > 3) {
    return Object.freeze({});
  }
  const out: Record<string, unknown> = {};
  for (const [key, val] of Object.entries(input).slice(0, 24)) {
    if (SENSITIVE_KEY_PATTERN.test(key)) {
      out[key] = "[REDACTED]";
      continue;
    }
    if (typeof val === "string") {
      out[key] = scrubStringValue(val);
    } else if (typeof val === "number" || typeof val === "boolean" || val === null) {
      out[key] = val;
    } else if (Array.isArray(val)) {
      out[key] = val
        .slice(0, 12)
        .map((item) => (typeof item === "string" ? scrubStringValue(item) : String(item)));
    } else if (typeof val === "object") {
      out[key] = scrubRecord(val as Readonly<Record<string, unknown>>, depth + 1);
    }
  }
  return Object.freeze(out);
}

export interface ScrubbedErrorPayload {
  readonly eventId: string;
  readonly name: string;
  readonly message: string;
  readonly stackSummary: readonly string[];
  readonly tags: Readonly<Record<string, string>>;
  readonly extra: Readonly<Record<string, unknown>>;
}

/**
 * Scrubs secret tokens, email addresses, headers, and query strings prior to external error reporting.
 */
export function scrubErrorPayload(
  error: unknown,
  context: ErrorCaptureContext
): ScrubbedErrorPayload {
  const eventId = crypto.randomBytes(16).toString("hex");
  const rawName = error instanceof Error ? error.name : "NonErrorException";
  const rawMsg =
    error instanceof Error
      ? error.message
      : typeof error === "string"
        ? error
        : "Unhandled non-error rejection";
  const rawStack =
    error instanceof Error && typeof error.stack === "string"
      ? error.stack
          .split("\n")
          .slice(1, 1 + MAX_STACK_FRAMES)
          .map((line) => scrubStringValue(line.trim()))
      : [];

  const tags: Record<string, string> = {
    service: context.service
  };
  if (context.route !== undefined) {
    const cleanRoute = context.route.split("?")[0] ?? context.route;
    tags["route"] = scrubStringValue(cleanRoute);
  }
  if (context.method !== undefined) {
    tags["http.method"] = context.method.toUpperCase();
  }
  if (context.statusCode !== undefined) {
    tags["http.status_code"] = String(context.statusCode);
  }
  if (context.requestId !== undefined) {
    tags["request_id"] = context.requestId;
  }
  if (context.tenantId !== undefined) {
    tags["tenant_id"] = context.tenantId;
  }
  if (context.tags !== undefined) {
    for (const [k, v] of Object.entries(context.tags)) {
      if (!SENSITIVE_KEY_PATTERN.test(k)) {
        tags[k] = scrubStringValue(v);
      }
    }
  }

  return Object.freeze({
    eventId,
    name: scrubStringValue(rawName),
    message: scrubStringValue(rawMsg),
    stackSummary: Object.freeze(rawStack),
    tags: Object.freeze(tags),
    extra: scrubRecord(context.extra)
  });
}

/**
 * Creates an env-gated Sentry error reporter (no-op whenever `SENTRY_DSN` is absent or blank).
 */
export function createEnvGatedErrorReporter(
  options: CreateEnvGatedErrorReporterOptions = {}
): ErrorReporter {
  const rawDsn = options.dsn ?? process.env["SENTRY_DSN"];
  const parsed = parseSentryDsn(rawDsn, {
    allowInsecureLocalhost: options.allowInsecureLocalhost
  });

  if (!parsed.enabled) {
    return Object.freeze({
      enabled: false,
      provider: "noop",
      captureException(
        error: unknown,
        context: ErrorCaptureContext
      ): Promise<CapturedErrorEvent> {
        const scrubbed = scrubErrorPayload(error, context);
        return Promise.resolve({
          sent: false,
          reason: "dsn_unset",
          eventId: scrubbed.eventId,
          scrubbedMessage: scrubbed.message
        });
      }
    });
  }

  const fetchImpl = options.fetchImpl ?? globalThis.fetch;
  const timeoutMs = Math.max(250, Math.min(10_000, options.timeoutMs ?? 2_000));
  const defaultEnv = options.environment ?? process.env["NODE_ENV"] ?? "development";
  const defaultRelease = options.release ?? process.env["RELAYQUILL_RELEASE"] ?? "0.1.0";

  return Object.freeze({
    enabled: true,
    provider: "sentry",
    projectId: parsed.projectId,
    async captureException(
      error: unknown,
      context: ErrorCaptureContext
    ): Promise<CapturedErrorEvent> {
      const scrubbed = scrubErrorPayload(error, {
        ...context,
        service: context.service || options.service || "relayquill"
      });
      const envelopeHeader = JSON.stringify({
        event_id: scrubbed.eventId,
        sent_at: new Date().toISOString()
      });
      const itemPayload = JSON.stringify({
        event_id: scrubbed.eventId,
        timestamp: Math.floor(Date.now() / 1000),
        platform: "node",
        level: "error",
        environment: context.environment ?? defaultEnv,
        release: context.release ?? defaultRelease,
        exception: {
          values: [
            {
              type: scrubbed.name,
              value: scrubbed.message
            }
          ]
        },
        tags: scrubbed.tags,
        extra: {
          ...scrubbed.extra,
          stack_summary: scrubbed.stackSummary
        }
      });
      const itemHeader = JSON.stringify({
        type: "event",
        length: Buffer.byteLength(itemPayload, "utf8")
      });
      const body = `${envelopeHeader}\n${itemHeader}\n${itemPayload}\n`;

      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeoutMs);
      try {
        const res = await fetchImpl(parsed.envelopeUrl, {
          method: "POST",
          headers: {
            "content-type": "application/x-sentry-envelope",
            "x-sentry-auth": `Sentry sentry_version=7, sentry_key=${parsed.publicKey}, sentry_client=relayquill/0.1.0`
          },
          body,
          signal: controller.signal
        });
        return {
          sent: res.ok,
          reason: res.ok ? "dispatched" : "http_rejected",
          eventId: scrubbed.eventId,
          statusCode: res.status,
          scrubbedMessage: scrubbed.message
        };
      } catch {
        return {
          sent: false,
          reason: "transport_error",
          eventId: scrubbed.eventId,
          scrubbedMessage: scrubbed.message
        };
      } finally {
        clearTimeout(timer);
      }
    }
  });
}
