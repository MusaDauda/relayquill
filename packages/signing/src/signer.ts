import crypto from "node:crypto";
import { type Temporal } from "@js-temporal/polyfill";
import {
  type AttemptId,
  type DeliveryId,
  type EndpointId,
  type EndpointVerificationBodyV1,
  type EndpointVerificationIntentId,
  type EventId,
  type KeyId,
  type NonNegativeInt64String,
  type OrderingDomainId,
  type PositiveInt64String,
  type ProjectId,
  type Sha256Hex,
  type SubscriptionId,
  WEBHOOK_HEADER_NAMES,
  WEBHOOK_MAX_BODY_BYTES,
  WEBHOOK_PROTOCOL_VERSION,
  encodeBase64Url,
  parseAttemptId,
  parseEndpointId,
  parseEndpointVerificationIntentId,
  parseKeyId,
  parseNonNegativeInt64String,
  parsePositiveInt64String,
  parseProjectId,
  parseSha256Hex,
  serializeEndpointVerificationBody
} from "@relayquill/contracts";
import {
  DependencyUnavailableDomainError,
  ValidationDomainError,
  nowUtcInstant,
  type WebhookPurpose
} from "@relayquill/domain";
import {
  type SignedAuthorityValidationOptions,
  encodeWebhookSignaturePreimage,
  formatSignaturesHeader,
  normalizeOptionalTraceContext,
  serializeEndpointVerificationHeaders,
  serializeWebhookDeliveryHeaders,
  validateSignedExternalAuthority,
  validateSignedRequestTarget
} from "./format.js";
import {
  type EndpointKeyMetadata,
  type EndpointSigningPolicyConfig,
  checkKeySigningEligibility,
  resolveSigningPlan
} from "./rotation.js";

export const WEBHOOK_HMAC_KEY_BYTES = 32 as const;

export interface SigningKeyHandle {
  readonly id: string;
  readonly byteLength: number;
  readonly isDestroyed: boolean;
  useBytes<T>(fn: (bytes: Buffer) => T): T;
  destroy?(): void;
  toJSON(): string;
  toString(): string;
  valueOf(): string;
}

export interface ResolvedSigningKeyMaterial {
  readonly metadata?: EndpointKeyMetadata | undefined;
  readonly handle: SigningKeyHandle;
  readonly releaseAfterUse?: boolean | undefined;
}

export type WebhookKeyMaterialResolver = (query: {
  readonly projectId: ProjectId;
  readonly endpointId: EndpointId;
  readonly keyId: KeyId;
  readonly purpose: WebhookPurpose;
}) => Promise<ResolvedSigningKeyMaterial | SigningKeyHandle> | ResolvedSigningKeyMaterial | SigningKeyHandle;

class MemorySigningKeyHandle implements SigningKeyHandle {
  readonly id: string;
  readonly byteLength: number;
  #secretBytes: Buffer | null;
  #destroyed = false;

  constructor(secretBytes: Uint8Array, id: string) {
    const copy = Buffer.allocUnsafe(secretBytes.byteLength);
    copy.set(secretBytes);
    this.#secretBytes = copy;
    this.byteLength = copy.byteLength;
    this.id = id;
  }

  get isDestroyed(): boolean {
    return this.#destroyed;
  }

  useBytes<T>(fn: (bytes: Buffer) => T): T {
    if (this.#destroyed || this.#secretBytes === null) {
      throw new DependencyUnavailableDomainError({
        code: "SECRET_CUSTODY_ERROR",
        message: `Signing key handle "${this.id}" has already been destroyed`,
        retryable: false
      });
    }
    const scratch = Buffer.allocUnsafe(this.#secretBytes.byteLength);
    this.#secretBytes.copy(scratch);
    try {
      return fn(scratch);
    } finally {
      scratch.fill(0);
    }
  }

  destroy(): void {
    if (this.#secretBytes !== null) {
      this.#secretBytes.fill(0);
      this.#secretBytes = null;
    }
    this.#destroyed = true;
  }

  toJSON(): string {
    return "[REDACTED]";
  }

  toString(): string {
    return "[REDACTED]";
  }

  valueOf(): string {
    return "[REDACTED]";
  }

  [Symbol.for("nodejs.util.inspect.custom")](): string {
    return `[SigningKeyHandle:${this.id} REDACTED]`;
  }
}

export function isSigningKeyHandle(value: unknown): value is SigningKeyHandle {
  if (typeof value !== "object" || value === null) {
    return false;
  }
  const candidate = value as Partial<SigningKeyHandle>;
  return (
    typeof candidate.id === "string" &&
    typeof candidate.byteLength === "number" &&
    typeof candidate.isDestroyed === "boolean" &&
    typeof candidate.useBytes === "function"
  );
}

export function createMemorySigningKeyHandle(
  secretBytes: Uint8Array | Buffer,
  options: { readonly id?: string | undefined; readonly require32Bytes?: boolean | undefined } = {}
): SigningKeyHandle {
  if (!(secretBytes instanceof Uint8Array)) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: "Signing key material must be Uint8Array or Buffer bytes"
    });
  }
  const require32 = options.require32Bytes ?? true;
  if (require32 && secretBytes.byteLength !== WEBHOOK_HMAC_KEY_BYTES) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Webhook signing key must be exactly ${WEBHOOK_HMAC_KEY_BYTES} raw bytes`
    });
  }
  if (secretBytes.byteLength === 0) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: "Signing key bytes must be non-empty"
    });
  }
  return new MemorySigningKeyHandle(secretBytes, options.id ?? "endpoint-hmac-key");
}

export function sha256HexNode(bytes: Uint8Array): Sha256Hex {
  return crypto.createHash("sha256").update(bytes).digest("hex") as Sha256Hex;
}

export function computeHmacSha256(
  keyHandle: SigningKeyHandle,
  preimage: Uint8Array,
  options: { readonly require32Bytes?: boolean | undefined } = {}
): Uint8Array {
  if (!isSigningKeyHandle(keyHandle)) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: "Expected non-serializing SigningKeyHandle"
    });
  }
  const require32 = options.require32Bytes ?? true;
  if (require32 && keyHandle.byteLength !== WEBHOOK_HMAC_KEY_BYTES) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Webhook HMAC key must be ${WEBHOOK_HMAC_KEY_BYTES} raw bytes`
    });
  }
  return keyHandle.useBytes((keyBytes) => {
    const digest = crypto.createHmac("sha256", keyBytes).update(preimage).digest();
    return new Uint8Array(digest.buffer, digest.byteOffset, digest.byteLength);
  });
}

export function normalizeResolvedKeyMaterial(
  resolved: ResolvedSigningKeyMaterial | SigningKeyHandle
): ResolvedSigningKeyMaterial {
  if (isSigningKeyHandle(resolved)) {
    return { handle: resolved, releaseAfterUse: false };
  }
  return resolved;
}

export function instantToUnixSecondsString(instant: Temporal.Instant): NonNegativeInt64String {
  const secs = instant.epochNanoseconds / 1_000_000_000n;
  return parseNonNegativeInt64String(secs.toString(10), "timestamp_seconds");
}

export interface InMemoryKeyEntry {
  readonly metadata: EndpointKeyMetadata;
  readonly secretBytes: Uint8Array;
}

interface StoredMemoryKey {
  readonly metadata: EndpointKeyMetadata;
  readonly secretBytes: Buffer;
}

export class InMemoryWebhookKeyProvider {
  readonly #entries = new Map<string, StoredMemoryKey>();

  static #scopeKey(projectId: ProjectId, endpointId: EndpointId, keyId: KeyId): string {
    return `${projectId}:${endpointId}:${keyId}`;
  }

  registerKey(input: {
    readonly projectId: ProjectId | string;
    readonly endpointId: EndpointId | string;
    readonly metadata: EndpointKeyMetadata;
    readonly secretBytes: Uint8Array;
  }): void {
    if (!(input.secretBytes instanceof Uint8Array) || input.secretBytes.byteLength !== WEBHOOK_HMAC_KEY_BYTES) {
      throw new ValidationDomainError({
        code: "INVALID_VALUE",
        message: `In-memory endpoint key must be ${WEBHOOK_HMAC_KEY_BYTES} bytes`
      });
    }
    const projectId = parseProjectId(input.projectId, "projectId");
    const endpointId = parseEndpointId(input.endpointId, "endpointId");
    const keyId = parseKeyId(input.metadata.keyId, "keyId");
    const scopeKey = InMemoryWebhookKeyProvider.#scopeKey(projectId, endpointId, keyId);
    const existing = this.#entries.get(scopeKey);
    if (existing !== undefined) {
      existing.secretBytes.fill(0);
    }
    const copy = Buffer.allocUnsafe(WEBHOOK_HMAC_KEY_BYTES);
    copy.set(input.secretBytes);
    this.#entries.set(scopeKey, {
      metadata: Object.freeze({
        ...input.metadata,
        keyId,
        projectId,
        endpointId
      }),
      secretBytes: copy
    });
  }

  updateKeyMetadata(input: {
    readonly projectId: ProjectId | string;
    readonly endpointId: EndpointId | string;
    readonly metadata: EndpointKeyMetadata;
  }): void {
    const projectId = parseProjectId(input.projectId, "projectId");
    const endpointId = parseEndpointId(input.endpointId, "endpointId");
    const keyId = parseKeyId(input.metadata.keyId, "keyId");
    const scopeKey = InMemoryWebhookKeyProvider.#scopeKey(projectId, endpointId, keyId);
    const existing = this.#entries.get(scopeKey);
    if (existing === undefined) {
      throw new DependencyUnavailableDomainError({
        code: "SECRET_CUSTODY_ERROR",
        message: `Unknown key "${keyId}" for endpoint "${endpointId}"`,
        retryable: false
      });
    }
    this.#entries.set(scopeKey, {
      metadata: Object.freeze({
        ...input.metadata,
        keyId,
        projectId,
        endpointId
      }),
      secretBytes: existing.secretBytes
    });
  }

  resolveKey(query: {
    readonly projectId: ProjectId;
    readonly endpointId: EndpointId;
    readonly keyId: KeyId;
  }): ResolvedSigningKeyMaterial | null {
    const scopeKey = InMemoryWebhookKeyProvider.#scopeKey(
      parseProjectId(query.projectId, "projectId"),
      parseEndpointId(query.endpointId, "endpointId"),
      parseKeyId(query.keyId, "keyId")
    );
    const entry = this.#entries.get(scopeKey);
    if (entry === undefined) {
      return null;
    }
    return {
      metadata: entry.metadata,
      handle: createMemorySigningKeyHandle(entry.secretBytes, {
        id: `${entry.metadata.endpointId ?? "endpoint"}:${entry.metadata.keyId}`
      }),
      releaseAfterUse: true
    };
  }

  asResolver(): WebhookKeyMaterialResolver {
    return (query) => {
      const resolved = this.resolveKey(query);
      if (resolved === null) {
        throw new DependencyUnavailableDomainError({
          code: "SECRET_CUSTODY_ERROR",
          message: `Signing key "${query.keyId}" is unavailable for endpoint "${query.endpointId}"`,
          retryable: false
        });
      }
      return resolved;
    };
  }

  destroy(): void {
    for (const entry of this.#entries.values()) {
      entry.secretBytes.fill(0);
    }
    this.#entries.clear();
  }
}

export interface SignWebhookDeliveryInput {
  readonly method?: "POST" | undefined;
  readonly externalAuthority: string;
  readonly requestTarget: string;
  readonly projectId: ProjectId | string;
  readonly eventId: EventId | string;
  readonly subscriptionId: SubscriptionId | string;
  readonly endpointId: EndpointId | string;
  readonly endpointVersion: PositiveInt64String | string;
  readonly signingPolicyVersion: PositiveInt64String | string;
  readonly deliveryId: DeliveryId | string;
  readonly deliveryGeneration: NonNegativeInt64String | string;
  readonly attemptId: AttemptId | string;
  readonly consumerEventKey: Sha256Hex | string;
  readonly rawWireBodyBytes: Uint8Array;
  readonly expectedBodySha256?: Sha256Hex | string | undefined;
  readonly ordering?: {
    readonly orderingDomainId: OrderingDomainId | string;
    readonly orderingKeySha256: Sha256Hex | string;
    readonly orderingSequence: PositiveInt64String | string;
  } | undefined;
  readonly traceparent?: string | undefined;
  readonly tracestate?: string | undefined;
  readonly timestampSeconds?: NonNegativeInt64String | string | undefined;
  readonly now?: Temporal.Instant | undefined;
  readonly signingPolicy?: EndpointSigningPolicyConfig | undefined;
  readonly signingKeys?: readonly EndpointKeyMetadata[] | undefined;
  readonly getKeyMaterial: WebhookKeyMaterialResolver;
  readonly authorityValidation?: SignedAuthorityValidationOptions | undefined;
}

export interface SignedWebhookRequest {
  readonly purpose: WebhookPurpose;
  readonly method: "POST";
  readonly externalAuthority: string;
  readonly requestTarget: string;
  readonly timestampSeconds: NonNegativeInt64String;
  readonly bodySha256: Sha256Hex;
  readonly signaturesHeader: string;
  readonly signedKeyIds: readonly KeyId[];
  readonly headers: Readonly<Record<string, string>>;
  readonly rawHeaderPairs: ReadonlyArray<readonly [string, string]>;
}

export async function signWebhookDelivery(
  input: SignWebhookDeliveryInput
): Promise<SignedWebhookRequest> {
  const method = input.method ?? "POST";
  if (method !== "POST") {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Webhook signing requires POST method, got "${String(method)}"`
    });
  }
  if (!(input.rawWireBodyBytes instanceof Uint8Array)) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: "rawWireBodyBytes must be Uint8Array"
    });
  }
  if (input.rawWireBodyBytes.length === 0 || input.rawWireBodyBytes.length > WEBHOOK_MAX_BODY_BYTES) {
    throw new ValidationDomainError({
      code: input.rawWireBodyBytes.length > WEBHOOK_MAX_BODY_BYTES ? "PAYLOAD_TOO_LARGE" : "INVALID_VALUE",
      message: `Webhook wire body length ${input.rawWireBodyBytes.length} out of bounds [1, ${WEBHOOK_MAX_BODY_BYTES}]`
    });
  }

  const externalAuthority = validateSignedExternalAuthority(
    input.externalAuthority,
    input.authorityValidation
  );
  const requestTarget = validateSignedRequestTarget(input.requestTarget);
  const projectId = parseProjectId(input.projectId, "projectId");
  const endpointId = parseEndpointId(input.endpointId, "endpointId");
  const signingPolicyVersion = parsePositiveInt64String(
    input.signingPolicyVersion,
    "signingPolicyVersion"
  );
  const now = input.now ?? nowUtcInstant();
  const timestampSeconds =
    input.timestampSeconds !== undefined
      ? parseNonNegativeInt64String(input.timestampSeconds, "timestampSeconds")
      : instantToUnixSecondsString(now);

  const bodySha256 = sha256HexNode(input.rawWireBodyBytes);
  if (input.expectedBodySha256 !== undefined) {
    const expected = parseSha256Hex(input.expectedBodySha256, "expectedBodySha256");
    if (expected !== bodySha256) {
      throw new ValidationDomainError({
        code: "INVALID_HASH",
        message: "rawWireBodyBytes SHA-256 does not match expectedBodySha256"
      });
    }
  }

  const traceContext = normalizeOptionalTraceContext(input.traceparent, input.tracestate);

  let selectedKeys: readonly EndpointKeyMetadata[];
  if (input.signingPolicy !== undefined) {
    selectedKeys = resolveSigningPlan(input.signingPolicy, now).signingKeys;
  } else if (input.signingKeys !== undefined) {
    if (input.signingKeys.length < 1 || input.signingKeys.length > 2) {
      throw new ValidationDomainError({
        code: "INVALID_VALUE",
        message: "Delivery signing requires 1 or 2 signing keys"
      });
    }
    selectedKeys = input.signingKeys;
  } else {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: "Either signingPolicy or signingKeys must be supplied"
    });
  }

  const seenKids = new Set<KeyId>();
  const signatureEntries: Array<{ readonly kid: KeyId; readonly mac: string }> = [];

  for (const keyMeta of selectedKeys) {
    const kid = parseKeyId(keyMeta.keyId, "signingKey.keyId");
    if (seenKids.has(kid)) {
      throw new ValidationDomainError({
        code: "INVALID_VALUE",
        message: `Duplicate signing key ID "${kid}"`
      });
    }
    seenKids.add(kid);

    const metaCheck = checkKeySigningEligibility(keyMeta, "delivery", now);
    if (!metaCheck.eligible) {
      throw new ValidationDomainError({
        code: "STATE_TRANSITION_NOT_ALLOWED",
        message: `Signing key "${kid}" is ineligible for delivery (${metaCheck.reason})`
      });
    }

    const resolved = normalizeResolvedKeyMaterial(
      await input.getKeyMaterial({
        projectId,
        endpointId,
        keyId: kid,
        purpose: "delivery"
      })
    );

    try {
      if (resolved.metadata !== undefined) {
        const providerCheck = checkKeySigningEligibility(resolved.metadata, "delivery", now);
        if (!providerCheck.eligible) {
          throw new ValidationDomainError({
            code: "STATE_TRANSITION_NOT_ALLOWED",
            message: `Provider key "${kid}" is ineligible for delivery (${providerCheck.reason})`
          });
        }
      }

      const preimage = encodeWebhookSignaturePreimage(
        {
          version: WEBHOOK_PROTOCOL_VERSION,
          purpose: "delivery",
          key_id: kid,
          method: "POST",
          external_authority: externalAuthority,
          request_target: requestTarget,
          project_id: projectId,
          event_id: input.eventId,
          subscription_id: input.subscriptionId,
          endpoint_id: endpointId,
          endpoint_version: input.endpointVersion,
          signing_policy_version: signingPolicyVersion,
          delivery_id: input.deliveryId,
          delivery_generation: input.deliveryGeneration,
          attempt_id: input.attemptId,
          timestamp_seconds: timestampSeconds,
          consumer_event_key: input.consumerEventKey,
          ordering_domain_id: input.ordering?.orderingDomainId,
          ordering_key_sha256: input.ordering?.orderingKeySha256,
          ordering_sequence: input.ordering?.orderingSequence,
          traceparent: traceContext.traceparent,
          tracestate: traceContext.tracestate,
          wire_body_sha256: bodySha256,
          raw_wire_body_bytes: input.rawWireBodyBytes
        },
        input.authorityValidation
      );

      const macBytes = computeHmacSha256(resolved.handle, preimage);
      signatureEntries.push({
        kid,
        mac: encodeBase64Url(macBytes)
      });
    } finally {
      if (resolved.releaseAfterUse === true) {
        resolved.handle.destroy?.();
      }
    }
  }

  const signaturesHeader = formatSignaturesHeader(signatureEntries);
  const serialized = serializeWebhookDeliveryHeaders({
    projectId,
    eventId: input.eventId,
    subscriptionId: input.subscriptionId,
    endpointId,
    endpointVersion: input.endpointVersion,
    deliveryId: input.deliveryId,
    deliveryGeneration: input.deliveryGeneration,
    attemptId: input.attemptId,
    signingPolicyVersion,
    timestampSeconds,
    consumerEventKey: input.consumerEventKey,
    bodySha256,
    signaturesHeader,
    ordering: input.ordering,
    traceparent: traceContext.traceparent,
    tracestate: traceContext.tracestate
  });

  return Object.freeze({
    purpose: "delivery",
    method: "POST",
    externalAuthority,
    requestTarget,
    timestampSeconds,
    bodySha256,
    signaturesHeader,
    signedKeyIds: Object.freeze(signatureEntries.map((entry) => entry.kid)),
    headers: serialized.headers,
    rawHeaderPairs: serialized.rawHeaderPairs
  });
}

export interface SignEndpointVerificationInput {
  readonly method?: "POST" | undefined;
  readonly externalAuthority: string;
  readonly requestTarget: string;
  readonly projectId: ProjectId | string;
  readonly endpointId: EndpointId | string;
  readonly endpointVersion: PositiveInt64String | string;
  readonly attemptId: AttemptId | string;
  readonly verificationId: EndpointVerificationIntentId | string;
  readonly body: EndpointVerificationBodyV1;
  readonly rawWireBodyBytes?: Uint8Array | undefined;
  readonly signingKey: EndpointKeyMetadata;
  readonly timestampSeconds?: NonNegativeInt64String | string | undefined;
  readonly now?: Temporal.Instant | undefined;
  readonly traceparent?: string | undefined;
  readonly tracestate?: string | undefined;
  readonly getKeyMaterial: WebhookKeyMaterialResolver;
  readonly authorityValidation?: SignedAuthorityValidationOptions | undefined;
}

export async function signEndpointVerificationRequest(
  input: SignEndpointVerificationInput
): Promise<SignedWebhookRequest & { readonly bodyBytes: Uint8Array }> {
  const method = input.method ?? "POST";
  if (method !== "POST") {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Endpoint verification signing requires POST method, got "${String(method)}"`
    });
  }

  const externalAuthority = validateSignedExternalAuthority(
    input.externalAuthority,
    input.authorityValidation
  );
  const requestTarget = validateSignedRequestTarget(input.requestTarget);
  const projectId = parseProjectId(input.projectId, "projectId");
  const endpointId = parseEndpointId(input.endpointId, "endpointId");
  const endpointVersion = parsePositiveInt64String(input.endpointVersion, "endpointVersion");
  const verificationId = parseEndpointVerificationIntentId(input.verificationId, "verificationId");
  const attemptId = parseAttemptId(input.attemptId, "attemptId");
  const kid = parseKeyId(input.signingKey.keyId, "signingKey.keyId");

  const serializedBody = serializeEndpointVerificationBody(input.body);
  if (
    serializedBody.body.verification_id !== verificationId ||
    serializedBody.body.endpoint_id !== endpointId ||
    serializedBody.body.endpoint_version !== endpointVersion ||
    serializedBody.body.key_id !== kid
  ) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: "Endpoint verification body fields do not match signed header context"
    });
  }

  const wireBytes = input.rawWireBodyBytes ?? serializedBody.body_bytes;
  const bodySha256 = sha256HexNode(wireBytes);
  if (input.rawWireBodyBytes !== undefined && bodySha256 !== serializedBody.body_sha256) {
    throw new ValidationDomainError({
      code: "INVALID_HASH",
      message: "Provided rawWireBodyBytes does not match canonical endpoint verification body"
    });
  }

  const now = input.now ?? nowUtcInstant();
  const timestampSeconds =
    input.timestampSeconds !== undefined
      ? parseNonNegativeInt64String(input.timestampSeconds, "timestampSeconds")
      : instantToUnixSecondsString(now);

  const traceContext = normalizeOptionalTraceContext(input.traceparent, input.tracestate);

  const metaCheck = checkKeySigningEligibility(input.signingKey, "endpoint_verification", now);
  if (!metaCheck.eligible) {
    throw new ValidationDomainError({
      code: "STATE_TRANSITION_NOT_ALLOWED",
      message: `Key "${kid}" is ineligible for endpoint_verification (${metaCheck.reason})`
    });
  }

  const resolved = normalizeResolvedKeyMaterial(
    await input.getKeyMaterial({
      projectId,
      endpointId,
      keyId: kid,
      purpose: "endpoint_verification"
    })
  );

  let signaturesHeader: string;
  try {
    if (resolved.metadata !== undefined) {
      const providerCheck = checkKeySigningEligibility(
        resolved.metadata,
        "endpoint_verification",
        now
      );
      if (!providerCheck.eligible) {
        throw new ValidationDomainError({
          code: "STATE_TRANSITION_NOT_ALLOWED",
          message: `Provider key "${kid}" is ineligible for endpoint_verification (${providerCheck.reason})`
        });
      }
    }

    const preimage = encodeWebhookSignaturePreimage(
      {
        version: WEBHOOK_PROTOCOL_VERSION,
        purpose: "endpoint_verification",
        key_id: kid,
        method: "POST",
        external_authority: externalAuthority,
        request_target: requestTarget,
        project_id: projectId,
        endpoint_id: endpointId,
        endpoint_version: endpointVersion,
        signing_policy_version: "0",
        attempt_id: attemptId,
        verification_id: verificationId,
        timestamp_seconds: timestampSeconds,
        traceparent: traceContext.traceparent,
        tracestate: traceContext.tracestate,
        wire_body_sha256: bodySha256,
        raw_wire_body_bytes: wireBytes
      },
      input.authorityValidation
    );

    const macBytes = computeHmacSha256(resolved.handle, preimage);
    signaturesHeader = formatSignaturesHeader([{ kid, mac: encodeBase64Url(macBytes) }]);
  } finally {
    if (resolved.releaseAfterUse === true) {
      resolved.handle.destroy?.();
    }
  }

  const serializedHeaders = serializeEndpointVerificationHeaders({
    verificationId,
    projectId,
    endpointId,
    endpointVersion,
    attemptId,
    timestampSeconds,
    bodySha256,
    signaturesHeader,
    traceparent: traceContext.traceparent,
    tracestate: traceContext.tracestate
  });

  if (serializedHeaders.headers[WEBHOOK_HEADER_NAMES.signingPolicy] !== "0") {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: "Endpoint verification signing policy must be 0"
    });
  }

  return Object.freeze({
    purpose: "endpoint_verification",
    method: "POST",
    externalAuthority,
    requestTarget,
    timestampSeconds,
    bodySha256,
    signaturesHeader,
    signedKeyIds: Object.freeze([kid]),
    headers: serializedHeaders.headers,
    rawHeaderPairs: serializedHeaders.rawHeaderPairs,
    bodyBytes: wireBytes
  });
}
