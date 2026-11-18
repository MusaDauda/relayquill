import {
  ROOT_CONTEXT,
  SpanKind,
  SpanStatusCode,
  context,
  createTraceState,
  propagation,
  trace,
  type Context,
  type Link,
  type Span,
  type SpanContext,
  type Tracer
} from "@opentelemetry/api";
import { ExportResultCode, W3CTraceContextPropagator, type ExportResult } from "@opentelemetry/core";
import { OTLPTraceExporter } from "@opentelemetry/exporter-trace-otlp-http";
import { NodeSDK, type NodeSDKConfiguration } from "@opentelemetry/sdk-node";
import { ValidationDomainError } from "@relayquill/domain";
import { type TelemetryConfig } from "./config.js";
import {
  MAX_TELEMETRY_ATTRIBUTES,
  MAX_TELEMETRY_ATTRIBUTE_LENGTH,
  TELEMETRY_MAX_EXPORT_BATCH_SIZE,
  TELEMETRY_MAX_QUEUE_SIZE,
  formatTraceparent,
  generateSpanId,
  generateTraceId,
  isValidSpanId,
  isValidTraceId,
  redactTelemetryText,
  sanitizeIncomingTraceHeaders,
  sanitizeTelemetryAttributes,
  sanitizeTracestate,
  type ParsedTraceparent,
  type SanitizeTracestateOptions
} from "./trace-context.js";

export * from "./trace-context.js";

export type TelemetrySpanExporter = NonNullable<NodeSDKConfiguration["traceExporter"]>;
export type TelemetryReadableSpan = Parameters<TelemetrySpanExporter["export"]>[0][number];

export interface TelemetryExporterStats {
  readonly exportedSpans: number;
  readonly droppedSpans: number;
  readonly exportFailures: number;
}

class NoopSpanExporter implements TelemetrySpanExporter {
  export(
    _spans: TelemetryReadableSpan[],
    resultCallback: (result: ExportResult) => void
  ): void {
    resultCallback({ code: ExportResultCode.SUCCESS });
  }

  shutdown(): Promise<void> {
    return Promise.resolve();
  }
}

function sanitizeReadableSpan(span: TelemetryReadableSpan): TelemetryReadableSpan {
  const cleanAttributes = sanitizeTelemetryAttributes(span.attributes);
  const cleanEvents = span.events.map((ev) => ({
    ...ev,
    name: redactTelemetryText(ev.name),
    attributes:
      ev.attributes !== undefined
        ? sanitizeTelemetryAttributes(ev.attributes)
        : undefined
  }));
  const cleanStatus =
    span.status.message !== undefined
      ? { ...span.status, message: redactTelemetryText(span.status.message) }
      : span.status;

  // Preserve ReadableSpan prototype/getters without mutating original span or passing raw secrets.
  return Object.create(span, {
    attributes: { value: cleanAttributes, enumerable: true },
    events: { value: cleanEvents, enumerable: true },
    status: { value: cleanStatus, enumerable: true }
  }) as TelemetryReadableSpan;
}

export class SanitizingSpanExporter implements TelemetrySpanExporter {
  readonly #delegate: TelemetrySpanExporter;
  readonly #maxBatchSize: number;
  #exportedSpans = 0;
  #droppedSpans = 0;
  #exportFailures = 0;

  constructor(
    delegate: TelemetrySpanExporter,
    maxBatchSize: number = TELEMETRY_MAX_EXPORT_BATCH_SIZE
  ) {
    this.#delegate = delegate;
    this.#maxBatchSize = Math.min(TELEMETRY_MAX_EXPORT_BATCH_SIZE, Math.max(1, maxBatchSize));
  }

  getStats(): TelemetryExporterStats {
    return Object.freeze({
      exportedSpans: this.#exportedSpans,
      droppedSpans: this.#droppedSpans,
      exportFailures: this.#exportFailures
    });
  }

  export(
    spans: TelemetryReadableSpan[],
    resultCallback: (result: ExportResult) => void
  ): void {
    if (spans.length === 0) {
      resultCallback({ code: ExportResultCode.SUCCESS });
      return;
    }

    const sanitized = spans.map(sanitizeReadableSpan);
    const boundedBatch =
      sanitized.length > this.#maxBatchSize
        ? sanitized.slice(0, this.#maxBatchSize)
        : sanitized;
    const overflowCount = sanitized.length - boundedBatch.length;
    if (overflowCount > 0) {
      this.#droppedSpans += overflowCount;
    }

    try {
      this.#delegate.export(boundedBatch, (result) => {
        if (result.code === ExportResultCode.SUCCESS) {
          this.#exportedSpans += boundedBatch.length;
        } else {
          this.#exportFailures += 1;
          this.#droppedSpans += boundedBatch.length;
        }
        resultCallback(result);
      });
    } catch (err) {
      this.#exportFailures += 1;
      this.#droppedSpans += boundedBatch.length;
      resultCallback({
        code: ExportResultCode.FAILED,
        error: err instanceof Error ? err : new Error(String(err))
      });
    }
  }

  shutdown(): Promise<void> {
    return Promise.resolve(this.#delegate.shutdown()).catch(() => undefined);
  }

  forceFlush(): Promise<void> {
    if (typeof this.#delegate.forceFlush === "function") {
      return Promise.resolve(this.#delegate.forceFlush()).catch(() => undefined);
    }
    return Promise.resolve();
  }
}

export interface InitTelemetryOptions {
  readonly serviceName: string;
  readonly enabled?: boolean | undefined;
  readonly otlpEndpoint?: string | undefined;
  readonly otlpHeaders?: Readonly<Record<string, string>> | undefined;
  readonly otlpTimeoutMs?: number | undefined;
  readonly maxQueueSize?: number | undefined;
  readonly maxExportBatchSize?: number | undefined;
  readonly traceViewOrigin?: string | undefined;
  readonly spanExporter?: TelemetrySpanExporter | undefined;
  readonly allowedTracestateKeys?: readonly string[] | undefined;
  readonly registerGlobalSdk?: boolean | undefined;
}

export interface ExtractedParentTrace {
  readonly context: Context;
  readonly link?: Link | undefined;
  readonly parsed?: ParsedTraceparent | undefined;
  readonly invalidReason?: string | undefined;
  readonly baggageDropped: boolean;
}

export interface AttemptSpanHandle {
  readonly span: Span;
  readonly traceId: string;
  readonly spanId: string;
  readonly traceFlags: number;
  readonly traceparent: string;
  readonly tracestate: string;
  end(status?: { readonly code: "OK" | "ERROR"; readonly message?: string | undefined }): void;
}

export interface StartManualSpanOptions {
  readonly kind?: SpanKind | undefined;
  readonly parentContext?: Context | undefined;
  readonly links?: readonly Link[] | undefined;
  readonly attributes?: Readonly<Record<string, unknown>> | undefined;
}

export class RelayquillTelemetry {
  readonly enabled: boolean;
  readonly serviceName: string;
  readonly maxQueueSize: number;
  readonly maxExportBatchSize: number;
  readonly traceViewOrigin: string | undefined;
  readonly #allowedTracestateKeys: readonly string[] | undefined;
  readonly #sdk: NodeSDK | null;
  readonly #exporter: SanitizingSpanExporter;
  readonly #registerGlobalSdk: boolean;
  #started = false;
  #shutdownDone = false;

  constructor(options: InitTelemetryOptions) {
    if (typeof options.serviceName !== "string" || options.serviceName.trim().length === 0) {
      throw new ValidationDomainError({
        code: "INVALID_VALUE",
        message: "Telemetry serviceName must be a non-empty string"
      });
    }
    const maxQueueSize = options.maxQueueSize ?? TELEMETRY_MAX_QUEUE_SIZE;
    const maxExportBatchSize = options.maxExportBatchSize ?? TELEMETRY_MAX_EXPORT_BATCH_SIZE;
    if (
      !Number.isInteger(maxQueueSize) ||
      maxQueueSize < 1 ||
      maxQueueSize > TELEMETRY_MAX_QUEUE_SIZE
    ) {
      throw new ValidationDomainError({
        code: "INVALID_VALUE",
        message: `Telemetry maxQueueSize must be within [1, ${TELEMETRY_MAX_QUEUE_SIZE}]`
      });
    }
    if (
      !Number.isInteger(maxExportBatchSize) ||
      maxExportBatchSize < 1 ||
      maxExportBatchSize > TELEMETRY_MAX_EXPORT_BATCH_SIZE
    ) {
      throw new ValidationDomainError({
        code: "INVALID_VALUE",
        message: `Telemetry maxExportBatchSize must be within [1, ${TELEMETRY_MAX_EXPORT_BATCH_SIZE}]`
      });
    }

    this.enabled = options.enabled ?? true;
    this.serviceName = options.serviceName.trim();
    this.maxQueueSize = maxQueueSize;
    this.maxExportBatchSize = maxExportBatchSize;
    this.traceViewOrigin = options.traceViewOrigin;
    this.#allowedTracestateKeys = options.allowedTracestateKeys;
    this.#registerGlobalSdk = options.registerGlobalSdk ?? true;

    const baseExporter: TelemetrySpanExporter =
      options.spanExporter !== undefined
        ? options.spanExporter
        : this.enabled && options.otlpEndpoint !== undefined
          ? new OTLPTraceExporter({
              url: options.otlpEndpoint,
              ...(options.otlpHeaders !== undefined ? { headers: { ...options.otlpHeaders } } : {}),
              ...(options.otlpTimeoutMs !== undefined
                ? { timeoutMillis: options.otlpTimeoutMs }
                : {})
            })
          : new NoopSpanExporter();

    this.#exporter = new SanitizingSpanExporter(baseExporter, this.maxExportBatchSize);

    if (!this.enabled || !this.#registerGlobalSdk) {
      this.#sdk = null;
      return;
    }

    this.#sdk = new NodeSDK({
      serviceName: this.serviceName,
      autoDetectResources: false,
      textMapPropagator: new W3CTraceContextPropagator(),
      instrumentations: [],
      logRecordProcessors: [],
      metricReaders: [],
      traceExporter: this.#exporter,
      spanLimits: {
        attributeCountLimit: MAX_TELEMETRY_ATTRIBUTES,
        attributeValueLengthLimit: MAX_TELEMETRY_ATTRIBUTE_LENGTH,
        eventCountLimit: 32,
        linkCountLimit: 16
      }
    });
  }

  static fromTelemetryConfig(
    config: TelemetryConfig | undefined,
    fallbackServiceName: string,
    overrides: Omit<Partial<InitTelemetryOptions>, "serviceName"> = {}
  ): RelayquillTelemetry {
    return new RelayquillTelemetry({
      serviceName: config?.service_name ?? fallbackServiceName,
      enabled: overrides.enabled ?? config?.enabled ?? false,
      otlpEndpoint: overrides.otlpEndpoint ?? config?.otlp_endpoint,
      otlpHeaders: overrides.otlpHeaders,
      otlpTimeoutMs: overrides.otlpTimeoutMs,
      maxQueueSize: overrides.maxQueueSize ?? config?.max_queue_size ?? TELEMETRY_MAX_QUEUE_SIZE,
      maxExportBatchSize:
        overrides.maxExportBatchSize ??
        config?.max_export_batch_size ??
        TELEMETRY_MAX_EXPORT_BATCH_SIZE,
      traceViewOrigin: overrides.traceViewOrigin ?? config?.trace_view_origin,
      spanExporter: overrides.spanExporter,
      allowedTracestateKeys: overrides.allowedTracestateKeys,
      registerGlobalSdk: overrides.registerGlobalSdk
    });
  }

  start(): void {
    if (this.#started || this.#shutdownDone || this.#sdk === null) {
      return;
    }
    this.#started = true;

    // Configure BatchSpanProcessor queue/batch ceilings strictly to product limits during start().
    const prevQueue = process.env.OTEL_BSP_MAX_QUEUE_SIZE;
    const prevBatch = process.env.OTEL_BSP_MAX_EXPORT_BATCH_SIZE;
    process.env.OTEL_BSP_MAX_QUEUE_SIZE = String(this.maxQueueSize);
    process.env.OTEL_BSP_MAX_EXPORT_BATCH_SIZE = String(this.maxExportBatchSize);
    try {
      this.#sdk.start();
    } finally {
      if (prevQueue === undefined) {
        delete process.env.OTEL_BSP_MAX_QUEUE_SIZE;
      } else {
        process.env.OTEL_BSP_MAX_QUEUE_SIZE = prevQueue;
      }
      if (prevBatch === undefined) {
        delete process.env.OTEL_BSP_MAX_EXPORT_BATCH_SIZE;
      } else {
        process.env.OTEL_BSP_MAX_EXPORT_BATCH_SIZE = prevBatch;
      }
    }
  }

  getTracer(name = this.serviceName, version = "0.1.0"): Tracer {
    return trace.getTracer(name, version);
  }

  getStats(): TelemetryExporterStats {
    return this.#exporter.getStats();
  }

  extractInboundContext(
    headers: Readonly<Record<string, string | readonly string[] | undefined>>,
    options: SanitizeTracestateOptions & { readonly continueApprovedParent?: boolean | undefined } = {}
  ): ExtractedParentTrace {
    const sanitized = sanitizeIncomingTraceHeaders(headers, {
      allowedVendorKeys: options.allowedVendorKeys ?? this.#allowedTracestateKeys,
      allowAnyValidVendorKey: options.allowAnyValidVendorKey,
      maxEntries: options.maxEntries,
      maxBytes: options.maxBytes
    });

    if (!sanitized.suppliedValidTraceparent || sanitized.traceparent === undefined) {
      return Object.freeze<ExtractedParentTrace>({
        context: ROOT_CONTEXT,
        invalidReason: sanitized.invalidReason,
        baggageDropped: sanitized.baggageDropped
      });
    }

    const remoteSpanContext: SpanContext = {
      traceId: sanitized.traceparent.traceId,
      spanId: sanitized.traceparent.spanId,
      traceFlags: sanitized.traceparent.traceFlags,
      isRemote: true,
      ...(sanitized.tracestate.length > 0
        ? { traceState: createTraceState(sanitized.tracestate) }
        : {})
    };

    const link: Link = Object.freeze({
      context: remoteSpanContext,
      attributes: Object.freeze({
        "relayquill.trace_source": "inbound_validated"
      })
    });

    const parentContext =
      options.continueApprovedParent === true
        ? trace.setSpanContext(ROOT_CONTEXT, remoteSpanContext)
        : ROOT_CONTEXT;

    return Object.freeze<ExtractedParentTrace>({
      context: parentContext,
      link,
      parsed: sanitized.traceparent,
      baggageDropped: sanitized.baggageDropped
    });
  }

  startManualSpan(name: string, options: StartManualSpanOptions = {}): Span {
    const tracer = this.getTracer();
    const safeAttrs = sanitizeTelemetryAttributes(options.attributes);
    return tracer.startSpan(
      name,
      {
        kind: options.kind ?? SpanKind.INTERNAL,
        attributes: safeAttrs,
        ...(options.links !== undefined ? { links: [...options.links] } : {})
      },
      options.parentContext ?? context.active()
    );
  }

  createAttemptSpanContext(options: {
    readonly spanName?: string | undefined;
    readonly parentContext?: Context | undefined;
    readonly links?: readonly Link[] | undefined;
    readonly attributes?: Readonly<Record<string, unknown>> | undefined;
    readonly allowedTracestateKeys?: readonly string[] | undefined;
  } = {}): AttemptSpanHandle {
    const span = this.startManualSpan(options.spanName ?? "relayquill.sender.attempt", {
      kind: SpanKind.CLIENT,
      parentContext: options.parentContext,
      links: options.links,
      attributes: options.attributes
    });

    const rawCtx = span.spanContext();
    const traceId = isValidTraceId(rawCtx.traceId) ? rawCtx.traceId : generateTraceId();
    const spanId = isValidSpanId(rawCtx.spanId) ? rawCtx.spanId : generateSpanId();
    const traceFlags = Number.isInteger(rawCtx.traceFlags) ? rawCtx.traceFlags & 0xff : 1;
    const traceparent = formatTraceparent({ traceId, spanId, traceFlags });

    const rawState = rawCtx.traceState?.serialize() ?? "";
    const tracestate = sanitizeTracestate(rawState, {
      allowedVendorKeys: options.allowedTracestateKeys ?? this.#allowedTracestateKeys
    });

    return Object.freeze<AttemptSpanHandle>({
      span,
      traceId,
      spanId,
      traceFlags,
      traceparent,
      tracestate,
      end(status) {
        if (status !== undefined) {
          span.setStatus({
            code: status.code === "ERROR" ? SpanStatusCode.ERROR : SpanStatusCode.OK,
            ...(status.message !== undefined
              ? { message: redactTelemetryText(status.message) }
              : {})
          });
        }
        span.end();
      }
    });
  }

  async shutdown(): Promise<void> {
    if (this.#shutdownDone) {
      return;
    }
    this.#shutdownDone = true;
    if (this.#sdk !== null) {
      try {
        await this.#sdk.shutdown();
      } catch {
        // Export shutdown failures are best-effort and must never abort process drain
      }
      if (this.#registerGlobalSdk) {
        trace.disable();
        propagation.disable();
        context.disable();
      }
    } else {
      await this.#exporter.shutdown();
    }
  }
}

export function initTelemetry(options: InitTelemetryOptions): RelayquillTelemetry {
  const instance = new RelayquillTelemetry(options);
  instance.start();
  return instance;
}
