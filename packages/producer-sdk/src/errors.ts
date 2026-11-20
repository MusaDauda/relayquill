import {
  type BusinessKey,
  type CanonicalUtcTimestamp,
  type HttpFieldError,
  type IdempotencyKey,
  type ProducerId,
  type Sha256Hex
} from "@relayquill/contracts";
import {
  type AcceptanceStatus,
  type DomainErrorCode,
  type EvidenceBoundary,
  MAX_DOMAIN_FIELD_ERRORS,
  type SafeResourceRef
} from "@relayquill/domain";

export type ProducerSdkErrorCode =
  | DomainErrorCode
  | "ABORTED"
  | "TRANSPORT_FAILURE"
  | "PROTOCOL_ERROR"
  | "UNSUPPORTED_RESPONSE_SCHEMA"
  | "WEB_CRYPTO_UNAVAILABLE";

export interface ProducerSdkErrorOptions {
  readonly code: ProducerSdkErrorCode;
  readonly message: string;
  readonly httpStatus?: number | undefined;
  readonly retryable?: boolean | undefined;
  readonly acceptance?: AcceptanceStatus | undefined;
  readonly boundary?: EvidenceBoundary | undefined;
  readonly requestId?: string | undefined;
  readonly observedAt?: CanonicalUtcTimestamp | undefined;
  readonly retryAfterMs?: number | undefined;
  readonly resourceRef?: SafeResourceRef | undefined;
  readonly fieldErrors?: readonly HttpFieldError[] | undefined;
}

export interface SerializedProducerSdkError {
  readonly name: string;
  readonly code: ProducerSdkErrorCode;
  readonly message: string;
  readonly httpStatus?: number;
  readonly retryable: boolean;
  readonly acceptance: AcceptanceStatus;
  readonly boundary?: EvidenceBoundary;
  readonly requestId?: string;
  readonly observedAt?: CanonicalUtcTimestamp;
  readonly retryAfterMs?: number;
  readonly resourceRef?: SafeResourceRef;
  readonly fieldErrors?: readonly HttpFieldError[];
}

function sanitizeFieldErrors(
  fieldErrors: readonly HttpFieldError[] | undefined
): readonly HttpFieldError[] | undefined {
  if (fieldErrors === undefined || fieldErrors.length === 0) {
    return undefined;
  }
  return Object.freeze(
    fieldErrors
      .slice(0, MAX_DOMAIN_FIELD_ERRORS)
      .map((entry) => Object.freeze({ path: entry.path, code: entry.code }))
  );
}

function sanitizeResourceRef(
  resourceRef: SafeResourceRef | undefined
): SafeResourceRef | undefined {
  if (resourceRef === undefined) {
    return undefined;
  }
  return Object.freeze({
    kind: resourceRef.kind,
    id: resourceRef.id
  });
}

export class ProducerSdkError extends Error {
  readonly code: ProducerSdkErrorCode;
  readonly httpStatus?: number;
  readonly retryable: boolean;
  readonly acceptance: AcceptanceStatus;
  readonly boundary?: EvidenceBoundary;
  readonly requestId?: string;
  readonly observedAt?: CanonicalUtcTimestamp;
  readonly retryAfterMs?: number;
  readonly resourceRef?: SafeResourceRef;
  readonly fieldErrors?: readonly HttpFieldError[];

  constructor(options: ProducerSdkErrorOptions) {
    super(options.message);
    this.name = new.target.name;
    Object.setPrototypeOf(this, new.target.prototype);

    this.code = options.code;
    this.retryable = options.retryable ?? false;
    this.acceptance = options.acceptance ?? "known_rejected";

    if (options.httpStatus !== undefined) {
      this.httpStatus = options.httpStatus;
    }
    if (options.boundary !== undefined) {
      this.boundary = options.boundary;
    }
    if (options.requestId !== undefined) {
      this.requestId = options.requestId;
    }
    if (options.observedAt !== undefined) {
      this.observedAt = options.observedAt;
    }
    if (options.retryAfterMs !== undefined) {
      this.retryAfterMs = options.retryAfterMs;
    }
    const safeRef = sanitizeResourceRef(options.resourceRef);
    if (safeRef !== undefined) {
      this.resourceRef = safeRef;
    }
    const safeFields = sanitizeFieldErrors(options.fieldErrors);
    if (safeFields !== undefined) {
      this.fieldErrors = safeFields;
    }
  }

  toJSON(): SerializedProducerSdkError {
    return {
      name: this.name,
      code: this.code,
      message: this.message,
      ...(this.httpStatus !== undefined ? { httpStatus: this.httpStatus } : {}),
      retryable: this.retryable,
      acceptance: this.acceptance,
      ...(this.boundary !== undefined ? { boundary: this.boundary } : {}),
      ...(this.requestId !== undefined ? { requestId: this.requestId } : {}),
      ...(this.observedAt !== undefined ? { observedAt: this.observedAt } : {}),
      ...(this.retryAfterMs !== undefined ? { retryAfterMs: this.retryAfterMs } : {}),
      ...(this.resourceRef !== undefined ? { resourceRef: this.resourceRef } : {}),
      ...(this.fieldErrors !== undefined ? { fieldErrors: this.fieldErrors } : {})
    };
  }

  override toString(): string {
    const statusSuffix = this.httpStatus !== undefined ? ` (HTTP ${String(this.httpStatus)})` : "";
    return `${this.name} [${this.code}]${statusSuffix}: ${this.message}`;
  }

  [Symbol.for("nodejs.util.inspect.custom")](): SerializedProducerSdkError {
    return this.toJSON();
  }
}

export class ProducerValidationError extends ProducerSdkError {
  constructor(
    options: Omit<ProducerSdkErrorOptions, "code"> & {
      readonly code?: ProducerSdkErrorCode | undefined;
    }
  ) {
    super({
      ...options,
      code: options.code ?? "INVALID_VALUE",
      retryable: false,
      acceptance: options.acceptance ?? "known_rejected"
    });
  }
}

export class ProducerAuthError extends ProducerSdkError {
  constructor(
    options: Omit<ProducerSdkErrorOptions, "code"> & {
      readonly code?: "UNAUTHENTICATED" | "FORBIDDEN" | "INVALID_CREDENTIAL_SELECTOR" | undefined;
    }
  ) {
    super({
      ...options,
      code: options.code ?? "UNAUTHENTICATED",
      retryable: false,
      acceptance: options.acceptance ?? "known_rejected"
    });
  }
}

export class ProducerConflictError extends ProducerSdkError {
  readonly businessKey?: BusinessKey;
  readonly idempotencyKey?: IdempotencyKey;
  readonly producerPrepareDigest?: Sha256Hex;

  constructor(
    options: Omit<ProducerSdkErrorOptions, "code"> & {
      readonly code?:
        | "BUSINESS_IDENTITY_CONFLICT"
        | "IDEMPOTENCY_CONFLICT"
        | "PUBLICATION_CONTEXT_CHANGED"
        | "VERSION_CONFLICT"
        | "STATE_TRANSITION_NOT_ALLOWED"
        | undefined;
      readonly businessKey?: BusinessKey | undefined;
      readonly idempotencyKey?: IdempotencyKey | undefined;
      readonly producerPrepareDigest?: Sha256Hex | undefined;
    }
  ) {
    super({
      ...options,
      code: options.code ?? "BUSINESS_IDENTITY_CONFLICT",
      httpStatus: options.httpStatus ?? 409,
      retryable: false,
      acceptance: "known_rejected"
    });
    if (options.businessKey !== undefined) {
      this.businessKey = options.businessKey;
    }
    if (options.idempotencyKey !== undefined) {
      this.idempotencyKey = options.idempotencyKey;
    }
    if (options.producerPrepareDigest !== undefined) {
      this.producerPrepareDigest = options.producerPrepareDigest;
    }
  }
}

export class ProducerContextChangedError extends ProducerConflictError {
  readonly expectedPublicationChannelId?: ProducerId;
  readonly actualPublicationChannelId?: ProducerId | null;

  constructor(options: {
    readonly message: string;
    readonly httpStatus?: number | undefined;
    readonly requestId?: string | undefined;
    readonly observedAt?: CanonicalUtcTimestamp | undefined;
    readonly expectedPublicationChannelId?: ProducerId | undefined;
    readonly actualPublicationChannelId?: ProducerId | null | undefined;
    readonly businessKey?: BusinessKey | undefined;
    readonly idempotencyKey?: IdempotencyKey | undefined;
    readonly producerPrepareDigest?: Sha256Hex | undefined;
  }) {
    super({
      ...options,
      code: "PUBLICATION_CONTEXT_CHANGED",
      httpStatus: options.httpStatus ?? 409
    });
    if (options.expectedPublicationChannelId !== undefined) {
      this.expectedPublicationChannelId = options.expectedPublicationChannelId;
    }
    if (options.actualPublicationChannelId !== undefined) {
      this.actualPublicationChannelId = options.actualPublicationChannelId;
    }
  }
}

export class ProducerPressureError extends ProducerSdkError {
  constructor(
    options: Omit<ProducerSdkErrorOptions, "code"> & {
      readonly code?: "RATE_LIMITED" | "CAPACITY_EXCEEDED" | undefined;
    }
  ) {
    super({
      ...options,
      code: options.code ?? "RATE_LIMITED",
      httpStatus: options.httpStatus ?? 429,
      retryable: options.retryable ?? true,
      acceptance: options.acceptance ?? "known_rejected"
    });
  }
}

export class ProducerAcceptanceUnknownError extends ProducerSdkError {
  readonly businessKey?: BusinessKey;
  readonly idempotencyKey?: IdempotencyKey;
  readonly producerPrepareDigest?: Sha256Hex;
  readonly submittedShapeSha256?: Sha256Hex;
  readonly expectedPublicationChannelId?: ProducerId;

  constructor(options: {
    readonly code?: "ACCEPTANCE_UNKNOWN" | "DEPENDENCY_UNAVAILABLE" | "TRANSPORT_FAILURE" | undefined;
    readonly message: string;
    readonly httpStatus?: number | undefined;
    readonly retryable?: boolean | undefined;
    readonly requestId?: string | undefined;
    readonly observedAt?: CanonicalUtcTimestamp | undefined;
    readonly businessKey?: BusinessKey | undefined;
    readonly idempotencyKey?: IdempotencyKey | undefined;
    readonly producerPrepareDigest?: Sha256Hex | undefined;
    readonly submittedShapeSha256?: Sha256Hex | undefined;
    readonly expectedPublicationChannelId?: ProducerId | undefined;
    readonly resourceRef?: SafeResourceRef | undefined;
  }) {
    super({
      ...options,
      code: options.code ?? "ACCEPTANCE_UNKNOWN",
      retryable: options.retryable ?? true,
      acceptance: "unknown",
      boundary: "accepted"
    });
    if (options.businessKey !== undefined) {
      this.businessKey = options.businessKey;
    }
    if (options.idempotencyKey !== undefined) {
      this.idempotencyKey = options.idempotencyKey;
    }
    if (options.producerPrepareDigest !== undefined) {
      this.producerPrepareDigest = options.producerPrepareDigest;
    }
    if (options.submittedShapeSha256 !== undefined) {
      this.submittedShapeSha256 = options.submittedShapeSha256;
    }
    if (options.expectedPublicationChannelId !== undefined) {
      this.expectedPublicationChannelId = options.expectedPublicationChannelId;
    }
  }
}

export class ProducerProtocolError extends ProducerSdkError {
  readonly responseSchemaVersion?: number;

  constructor(options: {
    readonly code?: "PROTOCOL_ERROR" | "UNSUPPORTED_RESPONSE_SCHEMA" | undefined;
    readonly message: string;
    readonly httpStatus?: number | undefined;
    readonly acceptance?: AcceptanceStatus | undefined;
    readonly requestId?: string | undefined;
    readonly responseSchemaVersion?: number | undefined;
  }) {
    super({
      ...options,
      code: options.code ?? "PROTOCOL_ERROR",
      retryable: false,
      acceptance: options.acceptance ?? "unknown"
    });
    if (options.responseSchemaVersion !== undefined) {
      this.responseSchemaVersion = options.responseSchemaVersion;
    }
  }
}

export class ProducerAbortedError extends ProducerSdkError {
  readonly businessKey?: BusinessKey;
  readonly idempotencyKey?: IdempotencyKey;
  readonly producerPrepareDigest?: Sha256Hex;

  constructor(options: {
    readonly message?: string | undefined;
    readonly acceptance: AcceptanceStatus;
    readonly businessKey?: BusinessKey | undefined;
    readonly idempotencyKey?: IdempotencyKey | undefined;
    readonly producerPrepareDigest?: Sha256Hex | undefined;
  }) {
    super({
      code: "ABORTED",
      message: options.message ?? "Producer operation aborted by caller AbortSignal",
      retryable: options.acceptance === "unknown",
      acceptance: options.acceptance
    });
    if (options.businessKey !== undefined) {
      this.businessKey = options.businessKey;
    }
    if (options.idempotencyKey !== undefined) {
      this.idempotencyKey = options.idempotencyKey;
    }
    if (options.producerPrepareDigest !== undefined) {
      this.producerPrepareDigest = options.producerPrepareDigest;
    }
  }
}
