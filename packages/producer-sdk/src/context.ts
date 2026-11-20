import {
  type CapabilityEntryDto,
  type NonNegativeInt64String,
  type PositiveInt64String,
  type ProducerId,
  type ProducerNamespace,
  type PublicationAllowedEventDto,
  type PublicationBudgetsDto,
  type PublicationContextDto,
  assertAllowedKeys,
  assertPlainRecord,
  parseBooleanField,
  parseBoundedInteger,
  parseCapabilities,
  parseEventTypeId,
  parseEventTypeName,
  parseNonNegativeInt64String,
  parsePositiveInt32,
  parsePositiveInt64String,
  parseProducerId,
  parseProducerNamespace
} from "@relayquill/contracts";
import {
  DomainError,
  EVENT_MAX_CONTENT_BYTES,
  EVENT_MAX_ENVELOPE_BYTES,
  type ParsedProducerCredentialToken,
  type ProducerCredentialSelector,
  type ProducerScopeAction,
  isActorKind,
  isChannelKind,
  isProducerScopeAction,
  parseProducerCredentialToken
} from "@relayquill/domain";
import {
  ProducerAuthError,
  ProducerContextChangedError,
  ProducerValidationError
} from "./errors.js";
import { type PreparedEvent } from "./prepared.js";

export type ProducerCredentialProvider = () => Promise<string> | string;

export interface BrowserSessionAuthConfig {
  readonly mode: "browser_session";
  readonly getCsrfToken?: (() => Promise<string> | string) | undefined;
  readonly credentials?: "same-origin" | "include" | undefined;
}

export interface BearerProducerAuthConfig {
  readonly mode?: "bearer" | undefined;
  readonly getCredential: ProducerCredentialProvider;
}

export type ProducerAuthConfig = BearerProducerAuthConfig | BrowserSessionAuthConfig;

export interface ResolvedRequestAuth {
  readonly mode: "bearer" | "browser_session";
  readonly selector: ProducerCredentialSelector | "browser_session";
  readonly headers: Readonly<Record<string, string>>;
  readonly credentials?: "same-origin" | "include" | undefined;
}

export async function resolveRequestAuth(
  auth: ProducerAuthConfig,
  options: { readonly isMutation: boolean }
): Promise<ResolvedRequestAuth> {
  if (auth.mode === "browser_session") {
    const headers: Record<string, string> = {};
    if (options.isMutation && auth.getCsrfToken !== undefined) {
      const rawCsrf = await auth.getCsrfToken();
      if (typeof rawCsrf !== "string" || rawCsrf.trim().length === 0) {
        throw new ProducerAuthError({
          code: "UNAUTHENTICATED",
          message: "Browser session mutation requires a non-empty X-CSRF-Token"
        });
      }
      headers["X-CSRF-Token"] = rawCsrf.trim();
    }
    return Object.freeze({
      mode: "browser_session",
      selector: "browser_session",
      headers: Object.freeze(headers),
      credentials: auth.credentials ?? "same-origin"
    });
  }

  let rawToken: unknown;
  try {
    rawToken = await auth.getCredential();
  } catch {
    throw new ProducerAuthError({
      code: "UNAUTHENTICATED",
      message: "Credential provider callback failed to supply a valid producer token"
    });
  }

  let parsed: ParsedProducerCredentialToken;
  try {
    parsed = parseProducerCredentialToken(rawToken, "authorization");
  } catch (err) {
    throw new ProducerAuthError({
      code: "INVALID_CREDENTIAL_SELECTOR",
      message:
        err instanceof DomainError
          ? err.message
          : "Malformed producer credential token; expected rq_p1.<uuid>.<secret>"
    });
  }

  const bearerValue = `Bearer ${parsed.selector}.${parsed.secret.expose()}`;
  return Object.freeze({
    mode: "bearer",
    selector: parsed.selector,
    headers: Object.freeze({
      Authorization: bearerValue
    })
  });
}

const PUBLICATION_CONTEXT_KEYS = new Set([
  "actor_kind",
  "channel_enabled",
  "channel_kind",
  "publication_channel_id",
  "namespace",
  "scope_version",
  "authority_epoch",
  "allowed_actions",
  "allowed_events",
  "budgets",
  "capabilities"
]);

const ALLOWED_EVENT_KEYS = new Set([
  "event_type_id",
  "event_type_name",
  "allowed_schema_versions"
]);

const BUDGETS_KEYS = new Set([
  "max_encoded_body_bytes",
  "max_decoded_content_bytes",
  "default_delivery_window_ms",
  "max_delivery_window_ms"
]);

export function parsePublicationContextDto(
  value: unknown,
  fieldPath = "publication_context"
): PublicationContextDto {
  try {
    const rec = assertPlainRecord(value, fieldPath);
    assertAllowedKeys(rec, PUBLICATION_CONTEXT_KEYS, fieldPath);

    if (!isActorKind(rec.actor_kind)) {
      throw new ProducerValidationError({
        message: `Invalid actor_kind in ${fieldPath}`,
        fieldErrors: [{ path: `${fieldPath}.actor_kind`, code: "INVALID_VALUE" }]
      });
    }
    const channelEnabled = parseBooleanField(rec.channel_enabled, `${fieldPath}.channel_enabled`);
    if (!isChannelKind(rec.channel_kind)) {
      throw new ProducerValidationError({
        message: `Invalid channel_kind in ${fieldPath}`,
        fieldErrors: [{ path: `${fieldPath}.channel_kind`, code: "INVALID_VALUE" }]
      });
    }

    const publicationChannelId: ProducerId | null =
      rec.publication_channel_id === null
        ? null
        : parseProducerId(rec.publication_channel_id, `${fieldPath}.publication_channel_id`);
    const namespace: ProducerNamespace | null =
      rec.namespace === null
        ? null
        : parseProducerNamespace(rec.namespace, `${fieldPath}.namespace`);
    const scopeVersion: PositiveInt64String | null =
      rec.scope_version === null
        ? null
        : parsePositiveInt64String(rec.scope_version, `${fieldPath}.scope_version`);
    const authorityEpoch: NonNegativeInt64String = parseNonNegativeInt64String(
      rec.authority_epoch,
      `${fieldPath}.authority_epoch`
    );

    if (!Array.isArray(rec.allowed_actions)) {
      throw new ProducerValidationError({
        message: `Expected array for ${fieldPath}.allowed_actions`,
        fieldErrors: [{ path: `${fieldPath}.allowed_actions`, code: "INVALID_VALUE" }]
      });
    }
    const allowedActions: ProducerScopeAction[] = [];
    for (let i = 0; i < rec.allowed_actions.length; i += 1) {
      const act: unknown = rec.allowed_actions[i];
      if (!isProducerScopeAction(act)) {
        throw new ProducerValidationError({
          message: `Invalid producer scope action at ${fieldPath}.allowed_actions[${i}]`,
          fieldErrors: [{ path: `${fieldPath}.allowed_actions[${i}]`, code: "INVALID_VALUE" }]
        });
      }
      allowedActions.push(act);
    }

    if (!Array.isArray(rec.allowed_events)) {
      throw new ProducerValidationError({
        message: `Expected array for ${fieldPath}.allowed_events`,
        fieldErrors: [{ path: `${fieldPath}.allowed_events`, code: "INVALID_VALUE" }]
      });
    }
    const allowedEvents: PublicationAllowedEventDto[] = rec.allowed_events.map(
      (entry: unknown, idx: number) => {
        const entryRec = assertPlainRecord(entry, `${fieldPath}.allowed_events[${idx}]`);
        assertAllowedKeys(entryRec, ALLOWED_EVENT_KEYS, `${fieldPath}.allowed_events[${idx}]`);
        if (
          !Array.isArray(entryRec.allowed_schema_versions) ||
          entryRec.allowed_schema_versions.length === 0
        ) {
          throw new ProducerValidationError({
            message: `Expected non-empty array for ${fieldPath}.allowed_events[${idx}].allowed_schema_versions`
          });
        }
        const versions = entryRec.allowed_schema_versions.map((ver: unknown, vIdx: number) =>
          parsePositiveInt32(
            ver,
            `${fieldPath}.allowed_events[${idx}].allowed_schema_versions[${vIdx}]`
          )
        );
        return Object.freeze({
          event_type_id: parseEventTypeId(
            entryRec.event_type_id,
            `${fieldPath}.allowed_events[${idx}].event_type_id`
          ),
          event_type_name: parseEventTypeName(
            entryRec.event_type_name,
            `${fieldPath}.allowed_events[${idx}].event_type_name`
          ),
          allowed_schema_versions: Object.freeze(versions)
        });
      }
    );

    const budgetsRec = assertPlainRecord(rec.budgets, `${fieldPath}.budgets`);
    assertAllowedKeys(budgetsRec, BUDGETS_KEYS, `${fieldPath}.budgets`);
    const budgets: PublicationBudgetsDto = Object.freeze({
      max_encoded_body_bytes: parseBoundedInteger(budgetsRec.max_encoded_body_bytes, {
        fieldPath: `${fieldPath}.budgets.max_encoded_body_bytes`,
        min: 1,
        max: EVENT_MAX_ENVELOPE_BYTES
      }),
      max_decoded_content_bytes: parseBoundedInteger(budgetsRec.max_decoded_content_bytes, {
        fieldPath: `${fieldPath}.budgets.max_decoded_content_bytes`,
        min: 1,
        max: EVENT_MAX_CONTENT_BYTES
      }),
      default_delivery_window_ms: parsePositiveInt64String(
        budgetsRec.default_delivery_window_ms,
        `${fieldPath}.budgets.default_delivery_window_ms`
      ),
      max_delivery_window_ms: parsePositiveInt64String(
        budgetsRec.max_delivery_window_ms,
        `${fieldPath}.budgets.max_delivery_window_ms`
      )
    });

    const capabilities: readonly CapabilityEntryDto[] | undefined =
      rec.capabilities !== undefined
        ? parseCapabilities(rec.capabilities, `${fieldPath}.capabilities`)
        : undefined;

    return Object.freeze({
      actor_kind: rec.actor_kind,
      channel_enabled: channelEnabled,
      channel_kind: rec.channel_kind,
      publication_channel_id: publicationChannelId,
      namespace,
      scope_version: scopeVersion,
      authority_epoch: authorityEpoch,
      allowed_actions: Object.freeze(allowedActions),
      allowed_events: Object.freeze(allowedEvents),
      budgets,
      ...(capabilities !== undefined ? { capabilities } : {})
    });
  } catch (err) {
    if (err instanceof ProducerValidationError) {
      throw err;
    }
    if (err instanceof DomainError) {
      throw new ProducerValidationError({
        code: err.code,
        message: err.message,
        ...(err.fieldErrors !== undefined ? { fieldErrors: err.fieldErrors } : {})
      });
    }
    throw err;
  }
}

export function assertPublicationContextMatchesPrepared(
  context: PublicationContextDto,
  prepared: PreparedEvent
): void {
  if (!context.channel_enabled || context.publication_channel_id === null) {
    throw new ProducerContextChangedError({
      message: "Authenticated publication context has no enabled publication channel",
      expectedPublicationChannelId: prepared.expectedPublicationChannelId,
      actualPublicationChannelId: context.publication_channel_id,
      businessKey: prepared.businessKey,
      idempotencyKey: prepared.idempotencyKey,
      producerPrepareDigest: prepared.producerPrepareDigest
    });
  }
  if (context.publication_channel_id !== prepared.expectedPublicationChannelId) {
    throw new ProducerContextChangedError({
      message: `Authenticated publication channel "${context.publication_channel_id}" does not match prepared expected_publication_channel_id "${prepared.expectedPublicationChannelId}"`,
      expectedPublicationChannelId: prepared.expectedPublicationChannelId,
      actualPublicationChannelId: context.publication_channel_id,
      businessKey: prepared.businessKey,
      idempotencyKey: prepared.idempotencyKey,
      producerPrepareDigest: prepared.producerPrepareDigest
    });
  }
}

export interface CachedPublicationContextEntry {
  readonly selector: ProducerCredentialSelector | "browser_session";
  readonly context: PublicationContextDto;
  readonly cachedAtMs: number;
  readonly expiresAtMs: number;
}

export const DEFAULT_CONTEXT_CACHE_TTL_MS = 60_000 as const;
export const MAX_CACHED_SELECTORS = 16 as const;

export class PublicationContextCache {
  readonly #entries = new Map<string, CachedPublicationContextEntry>();
  readonly #ttlMs: number;
  readonly #nowMs: () => number;

  constructor(options?: {
    readonly ttlMs?: number | undefined;
    readonly nowMs?: (() => number) | undefined;
  }) {
    this.#ttlMs = options?.ttlMs ?? DEFAULT_CONTEXT_CACHE_TTL_MS;
    this.#nowMs = options?.nowMs ?? (() => Date.now());
  }

  get(selector: ProducerCredentialSelector | "browser_session"): PublicationContextDto | null {
    const entry = this.#entries.get(selector);
    if (entry === undefined) {
      return null;
    }
    if (this.#nowMs() >= entry.expiresAtMs) {
      this.#entries.delete(selector);
      return null;
    }
    return entry.context;
  }

  hasAnyCachedContext(): boolean {
    return this.#entries.size > 0;
  }

  set(
    selector: ProducerCredentialSelector | "browser_session",
    context: PublicationContextDto,
    ttlMs?: number
  ): void {
    const now = this.#nowMs();
    if (this.#entries.size >= MAX_CACHED_SELECTORS && !this.#entries.has(selector)) {
      const oldestKey = this.#entries.keys().next().value;
      if (oldestKey !== undefined) {
        this.#entries.delete(oldestKey);
      }
    }
    this.#entries.set(
      selector,
      Object.freeze({
        selector,
        context,
        cachedAtMs: now,
        expiresAtMs: now + (ttlMs ?? this.#ttlMs)
      })
    );
  }

  clear(): void {
    this.#entries.clear();
  }
}
