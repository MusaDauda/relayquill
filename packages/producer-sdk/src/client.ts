import {
  type AdmitEventResultDto,
  type BusinessKey,
  type CanonicalUtcTimestamp,
  type DeliveryId,
  type DeliverySummaryDto,
  EVENT_CONTENT_MEDIA_TYPE,
  type EndpointId,
  type EventContentDto,
  type EventDetailDto,
  type EventId,
  type IdempotencyKey,
  type NonNegativeInt64String,
  type PaginatedData,
  type ProjectId,
  type PublicationContextDto,
  type ResolveEventRequestDto,
  type ResolveEventResultDto,
  type ResponseMeta,
  type Sha256Hex,
  type SubscriptionId,
  type TenantId,
  assertAllowedKeys,
  assertPlainRecord,
  classifyResponseEnvelope,
  decodeBase64Strict,
  parseAcceptedEventProjection,
  parseAcceptedReceipt,
  parseAdmitEventResult,
  parseAppliedAdmissionDefaults,
  parseBooleanField,
  parseBusinessKey,
  parseCanonicalUtcTimestamp,
  parseContentAvailabilityMetadata,
  parseDeliverySummary,
  parseEventContentDto,
  parseEventDetail,
  parseEventId,
  parseIdempotencyKey,
  parseInt64String,
  parsePageLimit,
  parsePaginatedData,
  parseProjectId,
  parseSha256Hex,
  parseStrictJsonObject,
  parseTenantId
} from "@relayquill/contracts";
import {
  type DeliveryOutcomeClass,
  type DeliveryPopulation,
  type DeliveryState,
  DomainError,
  isEventState
} from "@relayquill/domain";
import {
  type ProducerAuthConfig,
  type ProducerCredentialProvider,
  PublicationContextCache,
  assertPublicationContextMatchesPrepared,
  parsePublicationContextDto,
  resolveRequestAuth
} from "./context.js";
import {
  ProducerAbortedError,
  ProducerAcceptanceUnknownError,
  ProducerAuthError,
  ProducerConflictError,
  ProducerContextChangedError,
  ProducerPressureError,
  ProducerProtocolError,
  ProducerSdkError,
  ProducerValidationError
} from "./errors.js";
import {
  type PrepareEventInput,
  PreparedEvent,
  prepareEvent
} from "./prepared.js";
import {
  ClientPressureLimiter,
  DEFAULT_MAX_JITTER_MS,
  DEFAULT_MAX_RETRY_ATTEMPTS,
  DEFAULT_MIN_JITTER_MS,
  DEFAULT_TOTAL_RETRY_BUDGET_MS,
  type ProducerRetryPolicy,
  computeBoundedJitterMs,
  defaultSleepWithAbort,
  isRetryableHttpStatus,
  parseRetryAfterHeader
} from "./retry.js";
import {
  type FetchLike,
  type FetchResponseLike,
  type WatchEventsInput,
  WatchStream
} from "./watch.js";

export interface ProducerClientOptions {
  readonly baseUrl: string;
  readonly tenantId?: TenantId | string | undefined;
  readonly projectId?: ProjectId | string | undefined;
  readonly getCredential?: ProducerCredentialProvider | undefined;
  readonly auth?: ProducerAuthConfig | undefined;
  readonly fetch?: FetchLike | undefined;
  readonly retry?: ProducerRetryPolicy | undefined;
  readonly maxConcurrentRequests?: number | undefined;
  readonly maxQueuedOperations?: number | undefined;
  readonly maxQueuedBytes?: number | undefined;
  readonly contextCacheTtlMs?: number | undefined;
  readonly verifyContextOnNewSelector?: boolean | undefined;
}

export interface RequestCallOptions {
  readonly signal?: AbortSignal | undefined;
  readonly retry?: ProducerRetryPolicy | undefined;
  readonly tenantId?: TenantId | string | undefined;
  readonly projectId?: ProjectId | string | undefined;
}

export interface SubmitEventOptions extends RequestCallOptions {
  readonly verifyPublicationContext?: boolean | undefined;
}

export interface SubmitEventResult {
  readonly status: 200 | 201;
  readonly outcome: "created" | "replayed";
  readonly matchedExisting: boolean;
  readonly data: AdmitEventResultDto;
  readonly meta: ResponseMeta;
  readonly attempts: number;
}

export interface ResolvePreparedEventInput {
  readonly businessKey: BusinessKey | string;
  readonly submittedShapeSha256?: Sha256Hex | string | undefined;
  readonly producerPrepareDigest?: Sha256Hex | string | undefined;
  readonly idempotencyKey?: IdempotencyKey | string | undefined;
}

export type ResolvePreparedEventResult =
  | {
      readonly found: true;
      readonly status: 200;
      readonly data: ResolveEventResultDto;
      readonly meta: ResponseMeta;
    }
  | {
      readonly found: false;
      readonly status: 404;
      readonly acceptance: "unknown";
      readonly meta?: ResponseMeta | undefined;
    };

export interface GetEventResult {
  readonly status: 200;
  readonly data: EventDetailDto;
  readonly meta: ResponseMeta;
}

export interface GetOriginalContentResult {
  readonly status: 200;
  readonly data: EventContentDto;
  readonly bytes: Uint8Array;
  readonly meta: ResponseMeta;
}

export interface ListDeliveriesQuery {
  readonly eventId?: EventId | string | undefined;
  readonly subscriptionId?: SubscriptionId | string | undefined;
  readonly endpointId?: EndpointId | string | undefined;
  readonly state?: DeliveryState | undefined;
  readonly deliveryGeneration?: NonNegativeInt64String | string | undefined;
  readonly outcomeClass?: DeliveryOutcomeClass | undefined;
  readonly population?: DeliveryPopulation | undefined;
  readonly cursor?: string | undefined;
  readonly limit?: number | undefined;
}

export interface ListDeliveriesResult {
  readonly status: 200;
  readonly data: PaginatedData<DeliverySummaryDto>;
  readonly meta: ResponseMeta;
}

function validateBaseUrlOrigin(rawBaseUrl: string): string {
  if (typeof rawBaseUrl !== "string" || rawBaseUrl.trim().length === 0) {
    throw new ProducerValidationError({
      message: "ProducerClient baseUrl must be a non-empty HTTP/HTTPS URL"
    });
  }
  let parsed: URL;
  try {
    parsed = new URL(rawBaseUrl);
  } catch {
    throw new ProducerValidationError({
      message: `Invalid ProducerClient baseUrl "${rawBaseUrl}"`
    });
  }
  if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
    throw new ProducerValidationError({
      message: `Unsupported ProducerClient protocol "${parsed.protocol}"; expected https: or http:`
    });
  }
  if (parsed.username.length > 0 || parsed.password.length > 0) {
    throw new ProducerValidationError({
      message: "ProducerClient baseUrl must not embed userinfo credentials"
    });
  }
  if (parsed.search.length > 0 || parsed.hash.length > 0) {
    throw new ProducerValidationError({
      message: "ProducerClient baseUrl must not contain query parameters or fragments"
    });
  }
  const cleanPath = parsed.pathname.replace(/\/+$/, "");
  return `${parsed.origin}${cleanPath}`;
}

function resolveDefaultFetch(customFetch?: FetchLike): FetchLike {
  if (customFetch !== undefined) {
    return customFetch;
  }
  const globalFetch = globalThis.fetch as FetchLike | undefined;
  if (typeof globalFetch !== "function") {
    throw new ProducerSdkError({
      code: "DEPENDENCY_UNAVAILABLE",
      message: "Global fetch API is unavailable; pass a fetch implementation in ProducerClientOptions",
      retryable: false,
      acceptance: "not_applicable"
    });
  }
  return (input, init) => globalFetch(input, init);
}

const RESOLVE_RESULT_KEYS = new Set([
  "receipt",
  "event",
  "applied_defaults",
  "fingerprint_verified",
  "content_availability",
  "current_observation"
]);

const CURRENT_OBS_KEYS = new Set(["current_version", "current_state", "observed_at"]);

export function parseResolveEventResult(
  value: unknown,
  fieldPath = "data"
): ResolveEventResultDto {
  const rec = assertPlainRecord(value, fieldPath);
  assertAllowedKeys(rec, RESOLVE_RESULT_KEYS, fieldPath);

  const obsRec = assertPlainRecord(rec.current_observation, `${fieldPath}.current_observation`);
  assertAllowedKeys(obsRec, CURRENT_OBS_KEYS, `${fieldPath}.current_observation`);
  if (!isEventState(obsRec.current_state)) {
    throw new ProducerValidationError({
      message: `Invalid current_state in ${fieldPath}.current_observation`,
      fieldErrors: [{ path: `${fieldPath}.current_observation.current_state`, code: "INVALID_VALUE" }]
    });
  }

  return Object.freeze({
    receipt: parseAcceptedReceipt(rec.receipt, "event", `${fieldPath}.receipt`),
    event: parseAcceptedEventProjection(rec.event, `${fieldPath}.event`),
    applied_defaults: parseAppliedAdmissionDefaults(
      rec.applied_defaults,
      `${fieldPath}.applied_defaults`
    ),
    fingerprint_verified: parseBooleanField(
      rec.fingerprint_verified,
      `${fieldPath}.fingerprint_verified`
    ),
    content_availability: parseContentAvailabilityMetadata(
      rec.content_availability,
      `${fieldPath}.content_availability`
    ),
    current_observation: Object.freeze({
      current_version: parseInt64String(
        obsRec.current_version,
        `${fieldPath}.current_observation.current_version`
      ),
      current_state: obsRec.current_state,
      observed_at: parseCanonicalUtcTimestamp(
        obsRec.observed_at,
        `${fieldPath}.current_observation.observed_at`
      )
    })
  });
}

export class RelayquillProducerClient {
  readonly #baseUrl: string;
  readonly #tenantId: TenantId | undefined;
  readonly #projectId: ProjectId | undefined;
  readonly #auth: ProducerAuthConfig;
  readonly #fetch: FetchLike;
  readonly #retryPolicy: ProducerRetryPolicy;
  readonly #limiter: ClientPressureLimiter;
  readonly #contextCache: PublicationContextCache;
  readonly #verifyContextOnNewSelector: boolean;

  constructor(options: ProducerClientOptions) {
    this.#baseUrl = validateBaseUrlOrigin(options.baseUrl);
    this.#tenantId =
      options.tenantId !== undefined ? parseTenantId(options.tenantId, "tenantId") : undefined;
    this.#projectId =
      options.projectId !== undefined ? parseProjectId(options.projectId, "projectId") : undefined;

    if ((this.#tenantId !== undefined) !== (this.#projectId !== undefined)) {
      throw new ProducerValidationError({
        message: "ProducerClientOptions requires both tenantId and projectId when scoped"
      });
    }

    if (options.auth !== undefined) {
      this.#auth = options.auth;
    } else if (options.getCredential !== undefined) {
      this.#auth = { mode: "bearer", getCredential: options.getCredential };
    } else {
      throw new ProducerValidationError({
        message: "ProducerClientOptions requires getCredential callback or auth configuration"
      });
    }

    this.#fetch = resolveDefaultFetch(options.fetch);
    this.#retryPolicy = options.retry ?? {};
    this.#limiter = new ClientPressureLimiter({
      maxConcurrentRequests: options.maxConcurrentRequests,
      maxQueuedOperations: options.maxQueuedOperations,
      maxQueuedBytes: options.maxQueuedBytes
    });
    this.#contextCache = new PublicationContextCache({
      ttlMs: options.contextCacheTtlMs,
      nowMs: options.retry?.nowMs
    });
    this.#verifyContextOnNewSelector = options.verifyContextOnNewSelector ?? false;
  }

  get baseUrl(): string {
    return this.#baseUrl;
  }

  get tenantId(): TenantId | undefined {
    return this.#tenantId;
  }

  get projectId(): ProjectId | undefined {
    return this.#projectId;
  }

  get activeRequestCount(): number {
    return this.#limiter.activeCount;
  }

  get queuedOperationCount(): number {
    return this.#limiter.queuedCount;
  }

  #buildProjectRoute(
    subpath: string,
    override?: { readonly tenantId?: TenantId | string | undefined; readonly projectId?: ProjectId | string | undefined }
  ): string {
    const tenantId =
      override?.tenantId !== undefined
        ? parseTenantId(override.tenantId, "tenantId")
        : this.#tenantId;
    const projectId =
      override?.projectId !== undefined
        ? parseProjectId(override.projectId, "projectId")
        : this.#projectId;

    const normalizedSubpath = subpath.startsWith("/") ? subpath : `/${subpath}`;
    if (this.#baseUrl.endsWith("/api/v1")) {
      if (tenantId !== undefined && projectId !== undefined) {
        return `${this.#baseUrl}/tenants/${tenantId}/projects/${projectId}${normalizedSubpath}`;
      }
      return `${this.#baseUrl}${normalizedSubpath}`;
    }
    if (tenantId !== undefined && projectId !== undefined) {
      return `${this.#baseUrl}/api/v1/tenants/${tenantId}/projects/${projectId}${normalizedSubpath}`;
    }
    return `${this.#baseUrl}/api/v1${normalizedSubpath}`;
  }

  async getPublicationContext(
    options?: RequestCallOptions & { readonly forceRefresh?: boolean | undefined }
  ): Promise<{ readonly data: PublicationContextDto; readonly meta: ResponseMeta }> {
    const resolvedAuth = await resolveRequestAuth(this.#auth, { isMutation: false });
    if (options?.forceRefresh !== true) {
      const cached = this.#contextCache.get(resolvedAuth.selector);
      if (cached !== null) {
        return Object.freeze({
          data: cached,
          meta: Object.freeze({
            request_id: "cached_publication_context",
            response_schema_version: 1,
            observed_at: "2026-01-01T00:00:00.000000Z" as CanonicalUtcTimestamp
          })
        });
      }
    }

    const url = this.#buildProjectRoute("/publication-context", options);
    const result = await this.#executeWithRetry<PublicationContextDto>({
      url,
      method: "GET",
      byteCost: 0,
      isMutation: false,
      parseData: (raw) => parsePublicationContextDto(raw),
      signal: options?.signal,
      retry: options?.retry
    });

    this.#contextCache.set(resolvedAuth.selector, result.data);
    return Object.freeze({
      data: result.data,
      meta: result.meta
    });
  }

  async prepareEvent(input: PrepareEventInput): Promise<PreparedEvent> {
    if (
      input.expectedPublicationChannelId === undefined &&
      input.publicationContext === undefined
    ) {
      const ctx = await this.getPublicationContext();
      return prepareEvent({
        ...input,
        publicationContext: ctx.data
      });
    }
    return prepareEvent(input);
  }

  async submitEvent(
    prepared: PreparedEvent,
    options?: SubmitEventOptions
  ): Promise<SubmitEventResult> {
    if (!(prepared instanceof PreparedEvent)) {
      throw new ProducerValidationError({
        message: "submitEvent requires a PreparedEvent instance created by prepareEvent"
      });
    }

    // Check cached/rotated publication context if applicable
    const shouldVerifyContext =
      options?.verifyPublicationContext ??
      (this.#verifyContextOnNewSelector || this.#contextCache.hasAnyCachedContext());

    if (shouldVerifyContext) {
      const auth = await resolveRequestAuth(this.#auth, { isMutation: true });
      let ctx = this.#contextCache.get(auth.selector);
      if (ctx === null) {
        const fetched = await this.getPublicationContext({
          signal: options?.signal,
          retry: options?.retry,
          tenantId: options?.tenantId,
          projectId: options?.projectId,
          forceRefresh: true
        });
        ctx = fetched.data;
      }
      assertPublicationContextMatchesPrepared(ctx, prepared);
    }

    const dto = prepared.toAdmitRequestDto();
    const bodyJson = JSON.stringify(dto);
    const url = this.#buildProjectRoute("/events", options);

    const res = await this.#executeWithRetry<AdmitEventResultDto>({
      url,
      method: "POST",
      headers: {
        "Content-Type": EVENT_CONTENT_MEDIA_TYPE,
        "Idempotency-Key": prepared.idempotencyKey
      },
      body: bodyJson,
      byteCost: prepared.byteCount,
      isMutation: true,
      preparedContext: prepared,
      parseData: (raw) => parseAdmitEventResult(raw),
      signal: options?.signal,
      retry: options?.retry
    });

    if (res.status !== 200 && res.status !== 201) {
      throw new ProducerProtocolError({
        code: "PROTOCOL_ERROR",
        message: `Unexpected HTTP status ${String(res.status)} on event admission`,
        httpStatus: res.status,
        acceptance: "unknown",
        requestId: res.meta.request_id
      });
    }

    const isReplay = res.status === 200 || res.data.matched_existing;
    return Object.freeze({
      status: res.status,
      outcome: isReplay ? "replayed" : "created",
      matchedExisting: isReplay,
      data: res.data,
      meta: res.meta,
      attempts: res.attempts
    });
  }

  async submitPrepared(
    prepared: PreparedEvent,
    options?: SubmitEventOptions
  ): Promise<SubmitEventResult> {
    return this.submitEvent(prepared, options);
  }

  async resolvePreparedEvent(
    input: PreparedEvent | ResolvePreparedEventInput,
    options?: RequestCallOptions
  ): Promise<ResolvePreparedEventResult> {
    let businessKey: BusinessKey;
    let submittedShapeSha256: Sha256Hex | undefined;
    let idempotencyKey: IdempotencyKey | undefined;

    try {
      if (input instanceof PreparedEvent) {
        businessKey = input.businessKey;
        submittedShapeSha256 = input.submittedShapeSha256 ?? input.producerPrepareDigest;
        idempotencyKey = input.idempotencyKey;
      } else {
        businessKey = parseBusinessKey(input.businessKey, "businessKey");
        const rawDigest = input.submittedShapeSha256 ?? input.producerPrepareDigest;
        submittedShapeSha256 =
          rawDigest !== undefined ? parseSha256Hex(rawDigest, "submittedShapeSha256") : undefined;
        idempotencyKey =
          input.idempotencyKey !== undefined
            ? parseIdempotencyKey(input.idempotencyKey, "idempotencyKey")
            : undefined;
      }
    } catch (err) {
      throw new ProducerValidationError({
        code: err instanceof DomainError ? err.code : "INVALID_VALUE",
        message: err instanceof Error ? err.message : "Invalid resolvePreparedEvent input"
      });
    }

    const reqDto: ResolveEventRequestDto = Object.freeze({
      schema_version: 1,
      business_key: businessKey,
      ...(submittedShapeSha256 !== undefined
        ? { submitted_shape_sha256: submittedShapeSha256 }
        : {})
    });

    const url = this.#buildProjectRoute("/events/resolve", options);
    const headers: Record<string, string> = {
      "Content-Type": EVENT_CONTENT_MEDIA_TYPE
    };
    if (idempotencyKey !== undefined) {
      headers["Idempotency-Key"] = idempotencyKey;
    }

    try {
      const res = await this.#executeWithRetry<ResolveEventResultDto>({
        url,
        method: "POST",
        headers,
        body: JSON.stringify(reqDto),
        byteCost: 256,
        isMutation: true,
        parseData: (raw) => parseResolveEventResult(raw),
        signal: options?.signal,
        retry: options?.retry
      });

      return Object.freeze({
        found: true,
        status: 200,
        data: res.data,
        meta: res.meta
      });
    } catch (err) {
      if (err instanceof ProducerSdkError && err.httpStatus === 404 && err.code === "NOT_FOUND") {
        // 404 on /events/resolve means no committed event was observed at this read boundary;
        // it does NOT prove an earlier delayed request can never commit.
        return Object.freeze({
          found: false,
          status: 404,
          acceptance: "unknown",
          ...(err.requestId !== undefined && err.observedAt !== undefined
            ? {
                meta: Object.freeze({
                  request_id: err.requestId,
                  response_schema_version: 1 as const,
                  observed_at: err.observedAt
                })
              }
            : {})
        });
      }
      throw err;
    }
  }

  async resolvePrepared(
    input: PreparedEvent | ResolvePreparedEventInput,
    options?: RequestCallOptions
  ): Promise<ResolvePreparedEventResult> {
    return this.resolvePreparedEvent(input, options);
  }

  async getEvent(
    eventId: EventId | string,
    options?: RequestCallOptions
  ): Promise<GetEventResult> {
    let parsedId: EventId;
    try {
      parsedId = parseEventId(eventId, "eventId");
    } catch (err) {
      throw new ProducerValidationError({
        code: "INVALID_UUID",
        message: err instanceof Error ? err.message : "Invalid eventId UUID"
      });
    }

    const url = this.#buildProjectRoute(`/events/${parsedId}`, options);
    const res = await this.#executeWithRetry<EventDetailDto>({
      url,
      method: "GET",
      byteCost: 0,
      isMutation: false,
      parseData: (raw) => parseEventDetail(raw),
      signal: options?.signal,
      retry: options?.retry
    });

    return Object.freeze({
      status: 200,
      data: res.data,
      meta: res.meta
    });
  }

  async getOriginalContent(
    eventId: EventId | string,
    options?: RequestCallOptions
  ): Promise<GetOriginalContentResult> {
    let parsedId: EventId;
    try {
      parsedId = parseEventId(eventId, "eventId");
    } catch (err) {
      throw new ProducerValidationError({
        code: "INVALID_UUID",
        message: err instanceof Error ? err.message : "Invalid eventId UUID"
      });
    }

    const url = this.#buildProjectRoute(`/events/${parsedId}/content`, options);
    const res = await this.#executeWithRetry<EventContentDto>({
      url,
      method: "GET",
      byteCost: 0,
      isMutation: false,
      parseData: (raw) => parseEventContentDto(raw),
      signal: options?.signal,
      retry: options?.retry
    });

    const decodedBytes = decodeBase64Strict(res.data.data, "content.data");
    return Object.freeze({
      status: 200,
      data: res.data,
      bytes: decodedBytes,
      meta: res.meta
    });
  }

  async listDeliveries(
    query?: ListDeliveriesQuery,
    options?: RequestCallOptions
  ): Promise<ListDeliveriesResult> {
    const params = new URLSearchParams();
    if (query?.eventId !== undefined) {
      params.set("event_id", parseEventId(query.eventId, "eventId"));
    }
    if (query?.subscriptionId !== undefined) {
      params.set("subscription_id", String(query.subscriptionId));
    }
    if (query?.endpointId !== undefined) {
      params.set("endpoint_id", String(query.endpointId));
    }
    if (query?.state !== undefined) {
      params.set("state", query.state);
    }
    if (query?.deliveryGeneration !== undefined) {
      params.set("delivery_generation", String(query.deliveryGeneration));
    }
    if (query?.outcomeClass !== undefined) {
      params.set("outcome_class", query.outcomeClass);
    }
    if (query?.population !== undefined) {
      params.set("population", query.population);
    }
    if (query?.cursor !== undefined) {
      params.set("cursor", query.cursor);
    }
    if (query?.limit !== undefined) {
      params.set("limit", String(parsePageLimit(query.limit, "limit")));
    }

    const qs = params.toString();
    const subpath = qs.length > 0 ? `/deliveries?${qs}` : "/deliveries";
    const url = this.#buildProjectRoute(subpath, options);

    const res = await this.#executeWithRetry<PaginatedData<DeliverySummaryDto>>({
      url,
      method: "GET",
      byteCost: 0,
      isMutation: false,
      parseData: (raw) => parsePaginatedData(raw, (item, idx) => parseDeliverySummary(item, `items[${idx}]`)),
      signal: options?.signal,
      retry: options?.retry
    });

    return Object.freeze({
      status: 200,
      data: res.data,
      meta: res.meta
    });
  }

  watchEvents(input: WatchEventsInput): WatchStream {
    return new WatchStream(
      {
        buildWatchUrl: (resourceKind, resourceId) => {
          const collection = resourceKind === "event" ? "events" : "deliveries";
          return this.#buildProjectRoute(`/${collection}/${resourceId}/watch`);
        },
        auth: this.#auth,
        fetchFn: this.#fetch
      },
      input
    );
  }

  watchEvent(
    eventId: EventId | string,
    options?: Omit<WatchEventsInput, "eventId" | "deliveryId">
  ): WatchStream {
    return this.watchEvents({
      ...options,
      eventId
    });
  }

  watchDelivery(
    deliveryId: DeliveryId | string,
    options?: Omit<WatchEventsInput, "eventId" | "deliveryId">
  ): WatchStream {
    return this.watchEvents({
      ...options,
      deliveryId
    });
  }

  async #executeWithRetry<TData>(req: {
    readonly url: string;
    readonly method: "GET" | "POST";
    readonly headers?: Readonly<Record<string, string>> | undefined;
    readonly body?: string | undefined;
    readonly byteCost: number;
    readonly isMutation: boolean;
    readonly preparedContext?: PreparedEvent | undefined;
    readonly parseData: (raw: unknown) => TData;
    readonly signal?: AbortSignal | undefined;
    readonly retry?: ProducerRetryPolicy | undefined;
  }): Promise<{
    readonly status: number;
    readonly data: TData;
    readonly meta: ResponseMeta;
    readonly attempts: number;
  }> {
    return this.#limiter.run(req.byteCost, async () => {
      const policy: ProducerRetryPolicy = {
        ...this.#retryPolicy,
        ...req.retry
      };
      const maxAttempts = policy.maxAttempts ?? DEFAULT_MAX_RETRY_ATTEMPTS;
      const totalBudgetMs = policy.totalBudgetMs ?? DEFAULT_TOTAL_RETRY_BUDGET_MS;
      const minJitterMs = policy.minJitterMs ?? DEFAULT_MIN_JITTER_MS;
      const maxJitterMs = policy.maxJitterMs ?? DEFAULT_MAX_JITTER_MS;
      const nowMs = policy.nowMs ?? (() => Date.now());
      const sleepFn =
        policy.sleep ??
        ((delayMs: number, sig?: AbortSignal) =>
          defaultSleepWithAbort(delayMs, sig, hasDispatchedAttempt));

      if (!Number.isInteger(maxAttempts) || maxAttempts < 1) {
        throw new ProducerValidationError({
          message: `Invalid retry maxAttempts ${String(maxAttempts)}`
        });
      }
      if (!Number.isInteger(totalBudgetMs) || totalBudgetMs < 1) {
        throw new ProducerValidationError({
          message: `Invalid retry totalBudgetMs ${String(totalBudgetMs)}`
        });
      }

      const startMs = nowMs();
      const deadlineMs = startMs + totalBudgetMs;
      let hasDispatchedAttempt = false;
      let lastUnknownError: ProducerSdkError | null = null;

      for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
        if (req.signal?.aborted === true) {
          throw new ProducerAbortedError({
            acceptance: hasDispatchedAttempt && req.isMutation ? "unknown" : "known_rejected",
            businessKey: req.preparedContext?.businessKey,
            idempotencyKey: req.preparedContext?.idempotencyKey,
            producerPrepareDigest: req.preparedContext?.producerPrepareDigest
          });
        }

        const resolvedAuth = await resolveRequestAuth(this.#auth, {
          isMutation: req.isMutation
        });

        const mergedHeaders: Record<string, string> = {
          Accept: EVENT_CONTENT_MEDIA_TYPE,
          "Cache-Control": "no-store",
          ...req.headers,
          ...resolvedAuth.headers
        };

        hasDispatchedAttempt = true;
        let response: FetchResponseLike;
        try {
          response = await this.#fetch(req.url, {
            method: req.method,
            headers: mergedHeaders,
            ...(req.body !== undefined ? { body: req.body } : {}),
            ...(req.signal !== undefined ? { signal: req.signal } : {}),
            ...(resolvedAuth.credentials !== undefined
              ? { credentials: resolvedAuth.credentials }
              : {})
          });
        } catch (err) {
          if (Boolean(req.signal?.aborted)) {
            throw new ProducerAbortedError({
              acceptance: req.isMutation ? "unknown" : "known_rejected",
              businessKey: req.preparedContext?.businessKey,
              idempotencyKey: req.preparedContext?.idempotencyKey,
              producerPrepareDigest: req.preparedContext?.producerPrepareDigest
            });
          }

          lastUnknownError = req.isMutation
            ? new ProducerAcceptanceUnknownError({
                code: "TRANSPORT_FAILURE",
                message:
                  err instanceof Error
                    ? `Transport failure during event request: ${err.message}`
                    : "Transport failure during event request",
                retryable: true,
                businessKey: req.preparedContext?.businessKey,
                idempotencyKey: req.preparedContext?.idempotencyKey,
                producerPrepareDigest: req.preparedContext?.producerPrepareDigest,
                submittedShapeSha256: req.preparedContext?.submittedShapeSha256,
                expectedPublicationChannelId: req.preparedContext?.expectedPublicationChannelId
              })
            : new ProducerSdkError({
                code: "TRANSPORT_FAILURE",
                message:
                  err instanceof Error
                    ? `Transport failure: ${err.message}`
                    : "Transport failure",
                retryable: true,
                acceptance: "not_applicable"
              });

          if (attempt >= maxAttempts) {
            throw lastUnknownError;
          }

          const remainingMs = deadlineMs - nowMs();
          const jitterMs = computeBoundedJitterMs(
            minJitterMs,
            maxJitterMs,
            policy.randomUint32,
            policy.crypto
          );
          if (remainingMs <= 0 || jitterMs > remainingMs) {
            throw lastUnknownError;
          }
          await sleepFn(jitterMs, req.signal);
          continue;
        }

        const retryAfterMs = parseRetryAfterHeader(
          response.headers.get("retry-after"),
          nowMs()
        );
        const rawText = await response.text();

        let parsedJson: Record<string, unknown>;
        try {
          parsedJson = parseStrictJsonObject(rawText, {
            fieldPath: "response",
            maxDepth: 24,
            maxNodes: 16_384
          });
        } catch {
          if (isRetryableHttpStatus(response.status) && attempt < maxAttempts) {
            const remainingMs = deadlineMs - nowMs();
            const delayMs =
              retryAfterMs ??
              computeBoundedJitterMs(
                minJitterMs,
                maxJitterMs,
                policy.randomUint32,
                policy.crypto
              );
            if (retryAfterMs !== null && retryAfterMs > remainingMs) {
              throw new ProducerPressureError({
                code: "RATE_LIMITED",
                httpStatus: response.status,
                message: `Server Retry-After (${String(retryAfterMs)}ms) exceeds remaining caller budget (${String(Math.max(0, remainingMs))}ms)`,
                retryAfterMs,
                acceptance: req.isMutation && response.status >= 500 ? "unknown" : "known_rejected"
              });
            }
            if (remainingMs > 0 && delayMs <= remainingMs) {
              await sleepFn(delayMs, req.signal);
              continue;
            }
          }
          if (req.isMutation && (response.ok || response.status >= 500)) {
            throw new ProducerAcceptanceUnknownError({
              code: "ACCEPTANCE_UNKNOWN",
              httpStatus: response.status,
              message: `Malformed JSON response body from HTTP ${String(response.status)}; commit outcome is uncertain`,
              businessKey: req.preparedContext?.businessKey,
              idempotencyKey: req.preparedContext?.idempotencyKey,
              producerPrepareDigest: req.preparedContext?.producerPrepareDigest,
              submittedShapeSha256: req.preparedContext?.submittedShapeSha256,
              expectedPublicationChannelId: req.preparedContext?.expectedPublicationChannelId
            });
          }
          throw new ProducerProtocolError({
            code: "PROTOCOL_ERROR",
            httpStatus: response.status,
            message: `Malformed JSON response envelope (HTTP ${String(response.status)})`,
            acceptance: req.isMutation ? "unknown" : "not_applicable"
          });
        }

        const classified = classifyResponseEnvelope(parsedJson, req.parseData);
        if (!classified.supported) {
          if (classified.reason === "unsupported_response_schema_version") {
            throw new ProducerProtocolError({
              code: "UNSUPPORTED_RESPONSE_SCHEMA",
              httpStatus: response.status,
              message: `Unsupported response_schema_version ${String(classified.response_schema_version)}`,
              responseSchemaVersion: classified.response_schema_version,
              acceptance: req.isMutation && response.ok ? "unknown" : "not_applicable"
            });
          }
          throw new ProducerProtocolError({
            code: "PROTOCOL_ERROR",
            httpStatus: response.status,
            message: "Response body did not match supported Relayquill envelope contract",
            acceptance: req.isMutation && response.ok ? "unknown" : "not_applicable"
          });
        }

        if (classified.kind === "success" && response.ok) {
          return Object.freeze({
            status: response.status,
            data: classified.envelope.data,
            meta: classified.envelope.meta,
            attempts: attempt
          });
        }

        if (classified.kind !== "error") {
          throw new ProducerProtocolError({
            code: "PROTOCOL_ERROR",
            httpStatus: response.status,
            message: `HTTP ${String(response.status)} returned unexpected success envelope`,
            acceptance: req.isMutation ? "unknown" : "not_applicable"
          });
        }

        const { error, meta } = classified.envelope;
        const mappedError = this.#mapHttpErrorToSdkError(
          response.status,
          error,
          meta,
          retryAfterMs,
          req.preparedContext
        );

        const shouldRetry =
          attempt < maxAttempts &&
          (error.retryable || isRetryableHttpStatus(response.status)) &&
          response.status !== 400 &&
          response.status !== 401 &&
          response.status !== 403 &&
          response.status !== 404 &&
          response.status !== 409 &&
          response.status !== 410 &&
          response.status !== 413 &&
          response.status !== 415 &&
          response.status !== 422;

        if (!shouldRetry) {
          throw mappedError;
        }

        const remainingMs = deadlineMs - nowMs();
        if (retryAfterMs !== null && retryAfterMs > remainingMs) {
          throw new ProducerPressureError({
            code: error.code === "CAPACITY_EXCEEDED" ? "CAPACITY_EXCEEDED" : "RATE_LIMITED",
            httpStatus: response.status,
            message: `Server Retry-After (${String(retryAfterMs)}ms) exceeds remaining caller budget (${String(Math.max(0, remainingMs))}ms)`,
            retryable: true,
            acceptance: error.acceptance,
            requestId: meta.request_id,
            observedAt: meta.observed_at,
            retryAfterMs
          });
        }

        const jitterMs = computeBoundedJitterMs(
          minJitterMs,
          maxJitterMs,
          policy.randomUint32,
          policy.crypto
        );
        const delayMs = retryAfterMs !== null ? Math.max(retryAfterMs, jitterMs) : jitterMs;

        if (remainingMs <= 0 || delayMs > remainingMs) {
          throw mappedError;
        }

        await sleepFn(delayMs, req.signal);
      }

      throw (
        lastUnknownError ??
        new ProducerAcceptanceUnknownError({
          code: "ACCEPTANCE_UNKNOWN",
          message: "Retry budget exhausted without definitive outcome",
          businessKey: req.preparedContext?.businessKey,
          idempotencyKey: req.preparedContext?.idempotencyKey,
          producerPrepareDigest: req.preparedContext?.producerPrepareDigest,
          submittedShapeSha256: req.preparedContext?.submittedShapeSha256,
          expectedPublicationChannelId: req.preparedContext?.expectedPublicationChannelId
        })
      );
    });
  }

  #mapHttpErrorToSdkError(
    httpStatus: number,
    error: {
      readonly code: string;
      readonly message: string;
      readonly retryable: boolean;
      readonly acceptance: "known_rejected" | "unknown" | "not_applicable";
      readonly boundary?: "accepted" | "published" | "http_acknowledged" | "consumer_processed" | undefined;
      readonly field_errors?: readonly { readonly path: string; readonly code: string }[] | undefined;
      readonly resource_ref?: { readonly kind: string; readonly id: string } | undefined;
    },
    meta: ResponseMeta,
    retryAfterMs: number | null,
    prepared?: PreparedEvent
  ): ProducerSdkError {
    if (error.code === "PUBLICATION_CONTEXT_CHANGED") {
      return new ProducerContextChangedError({
        message: error.message,
        httpStatus,
        requestId: meta.request_id,
        observedAt: meta.observed_at,
        expectedPublicationChannelId: prepared?.expectedPublicationChannelId,
        businessKey: prepared?.businessKey,
        idempotencyKey: prepared?.idempotencyKey,
        producerPrepareDigest: prepared?.producerPrepareDigest
      });
    }

    if (
      httpStatus === 409 ||
      error.code === "BUSINESS_IDENTITY_CONFLICT" ||
      error.code === "IDEMPOTENCY_CONFLICT" ||
      error.code === "VERSION_CONFLICT" ||
      error.code === "STATE_TRANSITION_NOT_ALLOWED"
    ) {
      return new ProducerConflictError({
        code:
          error.code === "IDEMPOTENCY_CONFLICT" ||
          error.code === "VERSION_CONFLICT" ||
          error.code === "STATE_TRANSITION_NOT_ALLOWED"
            ? error.code
            : "BUSINESS_IDENTITY_CONFLICT",
        message: error.message,
        httpStatus,
        requestId: meta.request_id,
        observedAt: meta.observed_at,
        businessKey: prepared?.businessKey,
        idempotencyKey: prepared?.idempotencyKey,
        producerPrepareDigest: prepared?.producerPrepareDigest,
        ...(error.field_errors !== undefined ? { fieldErrors: error.field_errors } : {}),
        ...(error.resource_ref !== undefined ? { resourceRef: error.resource_ref } : {})
      });
    }

    if (httpStatus === 401 || httpStatus === 403 || error.code === "UNAUTHENTICATED" || error.code === "FORBIDDEN") {
      return new ProducerAuthError({
        code: httpStatus === 403 || error.code === "FORBIDDEN" ? "FORBIDDEN" : "UNAUTHENTICATED",
        message: error.message,
        httpStatus,
        requestId: meta.request_id,
        observedAt: meta.observed_at,
        ...(error.resource_ref !== undefined ? { resourceRef: error.resource_ref } : {})
      });
    }

    if (httpStatus === 429 || error.code === "RATE_LIMITED" || error.code === "CAPACITY_EXCEEDED") {
      return new ProducerPressureError({
        code: error.code === "CAPACITY_EXCEEDED" ? "CAPACITY_EXCEEDED" : "RATE_LIMITED",
        message: error.message,
        httpStatus,
        retryable: error.retryable,
        acceptance: error.acceptance,
        requestId: meta.request_id,
        observedAt: meta.observed_at,
        ...(retryAfterMs !== null ? { retryAfterMs } : {}),
        ...(error.resource_ref !== undefined ? { resourceRef: error.resource_ref } : {})
      });
    }

    if (error.acceptance === "unknown" || error.code === "ACCEPTANCE_UNKNOWN") {
      return new ProducerAcceptanceUnknownError({
        code: error.code === "DEPENDENCY_UNAVAILABLE" ? "DEPENDENCY_UNAVAILABLE" : "ACCEPTANCE_UNKNOWN",
        message: error.message,
        httpStatus,
        retryable: error.retryable,
        requestId: meta.request_id,
        observedAt: meta.observed_at,
        businessKey: prepared?.businessKey,
        idempotencyKey: prepared?.idempotencyKey,
        producerPrepareDigest: prepared?.producerPrepareDigest,
        submittedShapeSha256: prepared?.submittedShapeSha256,
        expectedPublicationChannelId: prepared?.expectedPublicationChannelId,
        ...(error.resource_ref !== undefined ? { resourceRef: error.resource_ref } : {})
      });
    }

    if (httpStatus === 400 || httpStatus === 413 || httpStatus === 415 || httpStatus === 422) {
      return new ProducerValidationError({
        code: error.code as ProducerSdkError["code"],
        message: error.message,
        httpStatus,
        acceptance: error.acceptance,
        requestId: meta.request_id,
        observedAt: meta.observed_at,
        ...(error.field_errors !== undefined ? { fieldErrors: error.field_errors } : {}),
        ...(error.resource_ref !== undefined ? { resourceRef: error.resource_ref } : {})
      });
    }

    return new ProducerSdkError({
      code: error.code as ProducerSdkError["code"],
      message: error.message,
      httpStatus,
      retryable: error.retryable,
      acceptance: error.acceptance,
      boundary: error.boundary,
      requestId: meta.request_id,
      observedAt: meta.observed_at,
      ...(retryAfterMs !== null ? { retryAfterMs } : {}),
      ...(error.field_errors !== undefined ? { fieldErrors: error.field_errors } : {}),
      ...(error.resource_ref !== undefined ? { resourceRef: error.resource_ref } : {})
    });
  }
}

export function createProducerClient(options: ProducerClientOptions): RelayquillProducerClient {
  return new RelayquillProducerClient(options);
}

function resolveClient(
  clientOrOptions: RelayquillProducerClient | ProducerClientOptions
): RelayquillProducerClient {
  return clientOrOptions instanceof RelayquillProducerClient
    ? clientOrOptions
    : new RelayquillProducerClient(clientOrOptions);
}

export async function submitEvent(
  clientOrOptions: RelayquillProducerClient | ProducerClientOptions,
  prepared: PreparedEvent,
  options?: SubmitEventOptions
): Promise<SubmitEventResult> {
  return resolveClient(clientOrOptions).submitEvent(prepared, options);
}

export async function submitPrepared(
  clientOrOptions: RelayquillProducerClient | ProducerClientOptions,
  prepared: PreparedEvent,
  options?: SubmitEventOptions
): Promise<SubmitEventResult> {
  return resolveClient(clientOrOptions).submitEvent(prepared, options);
}

export async function resolvePreparedEvent(
  clientOrOptions: RelayquillProducerClient | ProducerClientOptions,
  input: PreparedEvent | ResolvePreparedEventInput,
  options?: RequestCallOptions
): Promise<ResolvePreparedEventResult> {
  return resolveClient(clientOrOptions).resolvePreparedEvent(input, options);
}

export async function resolvePrepared(
  clientOrOptions: RelayquillProducerClient | ProducerClientOptions,
  input: PreparedEvent | ResolvePreparedEventInput,
  options?: RequestCallOptions
): Promise<ResolvePreparedEventResult> {
  return resolveClient(clientOrOptions).resolvePreparedEvent(input, options);
}

export async function getEvent(
  clientOrOptions: RelayquillProducerClient | ProducerClientOptions,
  eventId: EventId | string,
  options?: RequestCallOptions
): Promise<GetEventResult> {
  return resolveClient(clientOrOptions).getEvent(eventId, options);
}

export async function getOriginalContent(
  clientOrOptions: RelayquillProducerClient | ProducerClientOptions,
  eventId: EventId | string,
  options?: RequestCallOptions
): Promise<GetOriginalContentResult> {
  return resolveClient(clientOrOptions).getOriginalContent(eventId, options);
}

export async function listDeliveries(
  clientOrOptions: RelayquillProducerClient | ProducerClientOptions,
  query?: ListDeliveriesQuery,
  options?: RequestCallOptions
): Promise<ListDeliveriesResult> {
  return resolveClient(clientOrOptions).listDeliveries(query, options);
}

export async function getPublicationContext(
  clientOrOptions: RelayquillProducerClient | ProducerClientOptions,
  options?: RequestCallOptions & { readonly forceRefresh?: boolean | undefined }
): Promise<{ readonly data: PublicationContextDto; readonly meta: ResponseMeta }> {
  return resolveClient(clientOrOptions).getPublicationContext(options);
}

export function watchEvents(
  clientOrOptions: RelayquillProducerClient | ProducerClientOptions,
  input: WatchEventsInput
): WatchStream {
  return resolveClient(clientOrOptions).watchEvents(input);
}

export function watchEvent(
  clientOrOptions: RelayquillProducerClient | ProducerClientOptions,
  eventId: EventId | string,
  options?: Omit<WatchEventsInput, "eventId" | "deliveryId">
): WatchStream {
  return resolveClient(clientOrOptions).watchEvent(eventId, options);
}

export function watchDelivery(
  clientOrOptions: RelayquillProducerClient | ProducerClientOptions,
  deliveryId: DeliveryId | string,
  options?: Omit<WatchEventsInput, "eventId" | "deliveryId">
): WatchStream {
  return resolveClient(clientOrOptions).watchDelivery(deliveryId, options);
}
