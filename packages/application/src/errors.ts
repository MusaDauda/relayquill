import {
  ConflictDomainError,
  DomainError,
  InvariantViolationError,
  ValidationDomainError,
  type DomainErrorCode
} from "@relayquill/domain";
import {
  type CanonicalUtcTimestamp,
  type ErrorEnvelope,
  type HttpErrorBody,
  createErrorEnvelope,
  errorBodyFromDomainError,
  mapDomainErrorCodeToHttpStatus
} from "@relayquill/contracts";

export {
  DomainError,
  InvariantViolationError,
  errorBodyFromDomainError,
  createErrorEnvelope,
  mapDomainErrorCodeToHttpStatus
};

export interface MappedApplicationError {
  readonly statusCode: number;
  readonly body: HttpErrorBody;
  readonly envelope: ErrorEnvelope;
}

/**
 * Converts an arbitrary error thrown in application workflows into a bounded,
 * redaction-safe contract error envelope with its deterministic HTTP status code.
 */
export function mapErrorToEnvelope(
  err: unknown,
  meta: {
    readonly requestId: string;
    readonly observedAt: CanonicalUtcTimestamp | string;
  }
): MappedApplicationError {
  const domainError = normalizeToDomainError(err);
  const body = errorBodyFromDomainError(domainError);
  const envelope = createErrorEnvelope(body, {
    request_id: meta.requestId,
    observed_at: meta.observedAt
  });
  const statusCode = mapDomainErrorCodeToHttpStatus(domainError.code);
  return Object.freeze({
    statusCode,
    body,
    envelope
  });
}

/**
 * Ensures unexpected non-domain errors never leak raw stack traces, secret bytes,
 * or unvalidated driver details across application boundaries.
 */
export function normalizeToDomainError(err: unknown): DomainError {
  if (err instanceof DomainError) {
    return err;
  }
  if (
    typeof err === "object" &&
    err !== null &&
    "code" in err &&
    "retryable" in err &&
    "acceptance" in err &&
    typeof (err as { code?: unknown }).code === "string" &&
    typeof (err as { message?: unknown }).message === "string"
  ) {
    const candidate = err as {
      readonly code: DomainErrorCode;
      readonly message: string;
      readonly retryable: boolean;
      readonly acceptance: "known_rejected" | "unknown" | "not_applicable";
    };
    return new DomainError({
      code: candidate.code,
      message: candidate.message,
      retryable: candidate.retryable,
      acceptance: candidate.acceptance
    });
  }
  return new InvariantViolationError({
    code: "INVARIANT_VIOLATION",
    message: "Unexpected application failure"
  });
}

export function assertApplicationInvariant(
  condition: unknown,
  message: string,
  code: DomainErrorCode = "INVARIANT_VIOLATION"
): asserts condition {
  if (!condition) {
    throw new InvariantViolationError({ code, message });
  }
}

export function assertExpectedVersion(
  actual: bigint,
  expected: bigint,
  resourceKind: string,
  resourceId: string
): void {
  if (actual !== expected) {
    throw new ConflictDomainError({
      code: "VERSION_CONFLICT",
      message: `${resourceKind} "${resourceId}" version mismatch (expected ${expected}, found ${actual})`,
      resourceRef: { kind: resourceKind, id: resourceId }
    });
  }
}

export function assertPositiveBudget(value: bigint | number, fieldName: string): void {
  const numeric = typeof value === "bigint" ? value : BigInt(Math.trunc(value));
  if (numeric <= 0n) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `${fieldName} must be positive`,
      fieldErrors: [{ path: fieldName, code: "INVALID_VALUE" }]
    });
  }
}
