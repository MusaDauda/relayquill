import { type AcceptanceStatus, type EvidenceBoundary } from "./enums.js";

export const DOMAIN_ERROR_CODES = [
  "INVALID_VALUE",
  "INVALID_UUID",
  "INVALID_TIMESTAMP",
  "INVALID_INT64",
  "INVALID_HASH",
  "INVALID_IDEMPOTENCY_KEY",
  "INVALID_BUSINESS_KEY",
  "INVALID_PRODUCER_NAMESPACE",
  "INVALID_KEY_ID",
  "INVALID_EVENT_TYPE_NAME",
  "INVALID_CREDENTIAL_SELECTOR",
  "INVALID_CURSOR",
  "CURSOR_EXPIRED",
  "UNSUPPORTED_SCHEMA_VERSION",
  "SCHEMA_EVALUATION_LIMIT",
  "UNAUTHENTICATED",
  "FORBIDDEN",
  "NOT_FOUND",
  "PUBLICATION_CONTEXT_CHANGED",
  "BUSINESS_IDENTITY_CONFLICT",
  "IDEMPOTENCY_CONFLICT",
  "VERSION_CONFLICT",
  "STATE_TRANSITION_NOT_ALLOWED",
  "ALREADY_TERMINAL",
  "ALREADY_COMPLETE",
  "EXPIRED",
  "CONTENT_EXPIRED",
  "ORIGINAL_EVENT_CONFLICT",
  "CONSUMER_ORDER_POSITION_CONFLICT",
  "CONSUMER_ORDER_GAP",
  "REDIRECT_NOT_ALLOWED",
  "NO_RETRY_WITHIN_WINDOW",
  "RETRY_BUDGET_EXHAUSTED",
  "RATE_LIMITED",
  "CAPACITY_EXCEEDED",
  "QUOTA_HARD_CAP_REACHED",
  "PAYLOAD_TOO_LARGE",
  "DEPENDENCY_UNAVAILABLE",
  "ACCEPTANCE_UNKNOWN",
  "LOCK_CONTENTION",
  "SECRET_CUSTODY_ERROR",
  "EGRESS_POLICY_DENIED",
  "SIGNATURE_VERIFICATION_FAILED",
  "INVARIANT_VIOLATION"
] as const;

export type DomainErrorCode = (typeof DOMAIN_ERROR_CODES)[number];

export const MAX_DOMAIN_FIELD_ERRORS = 20 as const;

export interface DomainFieldError {
  readonly path: string;
  readonly code: string;
}

export interface SafeResourceRef {
  readonly kind: string;
  readonly id: string;
}

export interface DomainErrorOptions {
  readonly code: DomainErrorCode;
  readonly message: string;
  readonly retryable?: boolean | undefined;
  readonly acceptance?: AcceptanceStatus | undefined;
  readonly boundary?: EvidenceBoundary | undefined;
  readonly fieldErrors?: readonly DomainFieldError[] | undefined;
  readonly resourceRef?: SafeResourceRef | undefined;
}

export interface SerializedDomainError {
  readonly name: string;
  readonly code: DomainErrorCode;
  readonly message: string;
  readonly retryable: boolean;
  readonly acceptance: AcceptanceStatus;
  readonly boundary?: EvidenceBoundary;
  readonly fieldErrors?: readonly DomainFieldError[];
  readonly resourceRef?: SafeResourceRef;
}

function sanitizeFieldErrors(
  fieldErrors: readonly DomainFieldError[] | undefined
): readonly DomainFieldError[] | undefined {
  if (fieldErrors === undefined || fieldErrors.length === 0) {
    return undefined;
  }
  const bounded = fieldErrors
    .slice(0, MAX_DOMAIN_FIELD_ERRORS)
    .map((entry) => Object.freeze({ path: entry.path, code: entry.code }));
  return Object.freeze(bounded);
}

function sanitizeResourceRef(resourceRef: SafeResourceRef | undefined): SafeResourceRef | undefined {
  if (resourceRef === undefined) {
    return undefined;
  }
  return Object.freeze({
    kind: resourceRef.kind,
    id: resourceRef.id
  });
}

export class DomainError extends Error {
  readonly code: DomainErrorCode;
  readonly retryable: boolean;
  readonly acceptance: AcceptanceStatus;
  readonly boundary?: EvidenceBoundary;
  readonly fieldErrors?: readonly DomainFieldError[];
  readonly resourceRef?: SafeResourceRef;

  constructor(options: DomainErrorOptions) {
    super(options.message);
    this.name = new.target.name;
    Object.setPrototypeOf(this, new.target.prototype);

    this.code = options.code;
    this.retryable = options.retryable ?? false;
    this.acceptance = options.acceptance ?? "known_rejected";

    if (options.boundary !== undefined) {
      this.boundary = options.boundary;
    }

    const sanitizedFields = sanitizeFieldErrors(options.fieldErrors);
    if (sanitizedFields !== undefined) {
      this.fieldErrors = sanitizedFields;
    }

    const sanitizedRef = sanitizeResourceRef(options.resourceRef);
    if (sanitizedRef !== undefined) {
      this.resourceRef = sanitizedRef;
    }
  }

  toJSON(): SerializedDomainError {
    return {
      name: this.name,
      code: this.code,
      message: this.message,
      retryable: this.retryable,
      acceptance: this.acceptance,
      ...(this.boundary !== undefined ? { boundary: this.boundary } : {}),
      ...(this.fieldErrors !== undefined ? { fieldErrors: this.fieldErrors } : {}),
      ...(this.resourceRef !== undefined ? { resourceRef: this.resourceRef } : {})
    };
  }

  [Symbol.for("nodejs.util.inspect.custom")](): SerializedDomainError {
    return this.toJSON();
  }
}

export interface SubclassErrorOptions {
  readonly code?: DomainErrorCode | undefined;
  readonly message: string;
  readonly retryable?: boolean | undefined;
  readonly acceptance?: AcceptanceStatus | undefined;
  readonly boundary?: EvidenceBoundary | undefined;
  readonly fieldErrors?: readonly DomainFieldError[] | undefined;
  readonly resourceRef?: SafeResourceRef | undefined;
}

export class ValidationDomainError extends DomainError {
  constructor(options: SubclassErrorOptions) {
    super({
      ...options,
      code: options.code ?? "INVALID_VALUE",
      retryable: options.retryable ?? false,
      acceptance: options.acceptance ?? "known_rejected"
    });
  }
}

export class AuthenticationDomainError extends DomainError {
  constructor(options: SubclassErrorOptions) {
    super({
      ...options,
      code: options.code ?? "UNAUTHENTICATED",
      retryable: options.retryable ?? false,
      acceptance: options.acceptance ?? "known_rejected"
    });
  }
}

export class AuthorizationDomainError extends DomainError {
  constructor(options: SubclassErrorOptions) {
    super({
      ...options,
      code: options.code ?? "FORBIDDEN",
      retryable: options.retryable ?? false,
      acceptance: options.acceptance ?? "known_rejected"
    });
  }
}

export class NotFoundDomainError extends DomainError {
  constructor(options: SubclassErrorOptions) {
    super({
      ...options,
      code: options.code ?? "NOT_FOUND",
      retryable: options.retryable ?? false,
      acceptance: options.acceptance ?? "known_rejected"
    });
  }
}

export class ConflictDomainError extends DomainError {
  constructor(options: SubclassErrorOptions) {
    super({
      ...options,
      code: options.code ?? "VERSION_CONFLICT",
      retryable: options.retryable ?? false,
      acceptance: options.acceptance ?? "known_rejected"
    });
  }
}

export class ExpiredDomainError extends DomainError {
  constructor(options: SubclassErrorOptions) {
    super({
      ...options,
      code: options.code ?? "EXPIRED",
      retryable: options.retryable ?? false,
      acceptance: options.acceptance ?? "known_rejected"
    });
  }
}

export class LimitExceededDomainError extends DomainError {
  constructor(options: SubclassErrorOptions) {
    super({
      ...options,
      code: options.code ?? "CAPACITY_EXCEEDED",
      retryable: options.retryable ?? false,
      acceptance: options.acceptance ?? "known_rejected"
    });
  }
}

export class RateLimitDomainError extends DomainError {
  constructor(options: SubclassErrorOptions) {
    super({
      ...options,
      code: options.code ?? "RATE_LIMITED",
      retryable: options.retryable ?? true,
      acceptance: options.acceptance ?? "known_rejected"
    });
  }
}

export class DependencyUnavailableDomainError extends DomainError {
  constructor(options: SubclassErrorOptions) {
    super({
      ...options,
      code: options.code ?? "DEPENDENCY_UNAVAILABLE",
      retryable: options.retryable ?? true,
      acceptance: options.acceptance ?? "unknown"
    });
  }
}

export class UnsupportedStateTransitionError extends DomainError {
  constructor(options: SubclassErrorOptions) {
    super({
      ...options,
      code: options.code ?? "STATE_TRANSITION_NOT_ALLOWED",
      retryable: options.retryable ?? false,
      acceptance: options.acceptance ?? "known_rejected"
    });
  }
}

export class InvariantViolationError extends DomainError {
  constructor(options: SubclassErrorOptions) {
    super({
      ...options,
      code: options.code ?? "INVARIANT_VIOLATION",
      retryable: options.retryable ?? false,
      acceptance: options.acceptance ?? "not_applicable"
    });
  }
}
