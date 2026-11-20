import {
  AuthorizationDomainError,
  ConflictDomainError,
  DependencyUnavailableDomainError,
  DomainError,
  ExpiredDomainError,
  LimitExceededDomainError,
  NotFoundDomainError,
  RateLimitDomainError,
  UnsupportedStateTransitionError,
  ValidationDomainError,
  type DomainErrorCode,
  type SafeResourceRef
} from "@relayquill/domain";

export const RETRYABLE_CONTENTION_SQLSTATES = new Set<string>([
  "55P03", // lock_not_available
  "40P01", // deadlock_detected
  "40001" // serialization_failure
]);

export const UNCERTAIN_OUTCOME_SQLSTATES = new Set<string>([
  "57014", // query_canceled / statement_timeout
  "57P01", // admin_shutdown
  "57P02", // crash_shutdown
  "57P03" // cannot_connect_now
]);

export interface PgErrorDetails {
  readonly code?: string | undefined;
  readonly message: string;
  readonly constraint?: string | undefined;
  readonly schema?: string | undefined;
  readonly table?: string | undefined;
  readonly column?: string | undefined;
}

export interface PostgresErrorContext {
  readonly operation?: string | undefined;
  readonly resourceRef?: SafeResourceRef | undefined;
}

function isObjectRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function readOptionalStringProp(record: Record<string, unknown>, key: string): string | undefined {
  const value = record[key];
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

export function extractPgErrorDetails(err: unknown): PgErrorDetails {
  if (!isObjectRecord(err)) {
    return { message: typeof err === "string" ? err : "Unknown PostgreSQL error" };
  }

  const message =
    err instanceof Error && err.message.length > 0
      ? err.message
      : readOptionalStringProp(err, "message") ?? "PostgreSQL error";

  const code =
    readOptionalStringProp(err, "code") ?? readOptionalStringProp(err, "sqlstate");

  return {
    code,
    message,
    constraint: readOptionalStringProp(err, "constraint"),
    schema: readOptionalStringProp(err, "schema"),
    table: readOptionalStringProp(err, "table"),
    column: readOptionalStringProp(err, "column")
  };
}

export function extractSqlState(err: unknown): string | undefined {
  return extractPgErrorDetails(err).code;
}

export function isRetryableContentionError(err: unknown): boolean {
  const code = extractSqlState(err);
  return code !== undefined && RETRYABLE_CONTENTION_SQLSTATES.has(code);
}

export function isUncertainOutcomeError(err: unknown): boolean {
  if (err instanceof DomainError) {
    return err.acceptance === "unknown";
  }
  const details = extractPgErrorDetails(err);
  if (err instanceof Error && err.name === "AbortError") {
    return true;
  }
  const code = details.code;
  if (code === undefined) {
    return false;
  }
  return code.startsWith("08") || UNCERTAIN_OUTCOME_SQLSTATES.has(code);
}

export function isConnectionDiscardRequired(err: unknown): boolean {
  if (err instanceof Error) {
    if (err.name === "AbortError" || err.name === "TransactionAbortedError") {
      return true;
    }
  }
  const code = extractSqlState(err);
  if (code === undefined) {
    return false;
  }
  return (
    code === "25P02" ||
    code === "57014" ||
    code.startsWith("08") ||
    code.startsWith("57P")
  );
}

function inferUniqueConflictCode(details: PgErrorDetails): DomainErrorCode {
  const combined = `${details.constraint ?? ""} ${details.table ?? ""} ${details.message}`.toLowerCase();
  if (combined.includes("business") || combined.includes("anchor")) {
    return "BUSINESS_IDENTITY_CONFLICT";
  }
  if (combined.includes("idempoten") || combined.includes("command_receipt")) {
    return "IDEMPOTENCY_CONFLICT";
  }
  if (combined.includes("order")) {
    return "CONSUMER_ORDER_POSITION_CONFLICT";
  }
  return "VERSION_CONFLICT";
}

function formatOperationPrefix(context?: PostgresErrorContext): string {
  return context?.operation !== undefined ? `${context.operation}: ` : "";
}

/**
 * Translates PostgreSQL SQLSTATE codes and abort/timeout errors into safe `DomainError`
 * instances without leaking credentials or sensitive payloads.
 */
export function mapPostgresError(
  err: unknown,
  context?: PostgresErrorContext
): DomainError {
  if (err instanceof DomainError) {
    return err;
  }

  const details = extractPgErrorDetails(err);
  const prefix = formatOperationPrefix(context);
  const resourceRef = context?.resourceRef;
  const code = details.code;

  if (err instanceof Error && err.name === "AbortError") {
    return new DependencyUnavailableDomainError({
      code: "ACCEPTANCE_UNKNOWN",
      message: `${prefix}Database operation aborted before outcome was confirmed`,
      retryable: false,
      acceptance: "unknown",
      resourceRef
    });
  }

  if (code !== undefined && RETRYABLE_CONTENTION_SQLSTATES.has(code)) {
    return new ConflictDomainError({
      code: "LOCK_CONTENTION",
      message: `${prefix}${details.message}`,
      retryable: true,
      acceptance: "known_rejected",
      resourceRef
    });
  }

  if (code === "P0002") {
    return new NotFoundDomainError({
      code: "NOT_FOUND",
      message: `${prefix}${details.message}`,
      resourceRef
    });
  }

  if (code === "42501") {
    return new AuthorizationDomainError({
      code: "FORBIDDEN",
      message: `${prefix}${details.message}`,
      resourceRef
    });
  }

  if (code === "22023" || (code !== undefined && code.startsWith("22"))) {
    return new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `${prefix}${details.message}`,
      resourceRef
    });
  }

  if (code === "23505") {
    return new ConflictDomainError({
      code: inferUniqueConflictCode(details),
      message: `${prefix}${details.message}`,
      resourceRef
    });
  }

  if (code === "23503" || code === "23514" || code === "23P01") {
    return new ConflictDomainError({
      code: "STATE_TRANSITION_NOT_ALLOWED",
      message: `${prefix}${details.message}`,
      resourceRef
    });
  }

  if (code === "53400" || code === "54000") {
    const lower = details.message.toLowerCase();
    if (lower.includes("rate limit") || lower.includes("rate_limit")) {
      return new RateLimitDomainError({
        code: "RATE_LIMITED",
        message: `${prefix}${details.message}`,
        retryable: true,
        resourceRef
      });
    }
    return new LimitExceededDomainError({
      code: "CAPACITY_EXCEEDED",
      message: `${prefix}${details.message}`,
      resourceRef
    });
  }

  if (code === "55000") {
    const lower = details.message.toLowerCase();
    if (lower.includes("expired") || lower.includes("deadline")) {
      return new ExpiredDomainError({
        code: "EXPIRED",
        message: `${prefix}${details.message}`,
        resourceRef
      });
    }
    if (lower.includes("terminal") || lower.includes("already complete")) {
      return new ConflictDomainError({
        code: "ALREADY_TERMINAL",
        message: `${prefix}${details.message}`,
        resourceRef
      });
    }
    if (lower.includes("cannot transition") || lower.includes("not allowed in")) {
      return new UnsupportedStateTransitionError({
        code: "STATE_TRANSITION_NOT_ALLOWED",
        message: `${prefix}${details.message}`,
        resourceRef
      });
    }
    return new ConflictDomainError({
      code: "VERSION_CONFLICT",
      message: `${prefix}${details.message}`,
      resourceRef
    });
  }

  if (code === "57014") {
    return new DependencyUnavailableDomainError({
      code: "ACCEPTANCE_UNKNOWN",
      message: `${prefix}${details.message}`,
      retryable: false,
      acceptance: "unknown",
      resourceRef
    });
  }

  if (
    code !== undefined &&
    (code.startsWith("08") || code.startsWith("53") || code.startsWith("57"))
  ) {
    return new DependencyUnavailableDomainError({
      code: "DEPENDENCY_UNAVAILABLE",
      message: `${prefix}${details.message}`,
      retryable: true,
      acceptance: "unknown",
      resourceRef
    });
  }

  return new DependencyUnavailableDomainError({
    code: "DEPENDENCY_UNAVAILABLE",
    message: `${prefix}${details.message}`,
    retryable: false,
    acceptance: "unknown",
    resourceRef
  });
}
