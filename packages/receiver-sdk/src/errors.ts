import {
  AuthenticationDomainError,
  ConflictDomainError,
  DependencyUnavailableDomainError,
  DomainError,
  ExpiredDomainError,
  ValidationDomainError
} from "@relayquill/domain";

export type ReceiverSdkErrorCode =
  | "INVALID_VALUE"
  | "INVALID_UUID"
  | "PAYLOAD_TOO_LARGE"
  | "UNSUPPORTED_SCHEMA_VERSION"
  | "SIGNATURE_VERIFICATION_FAILED"
  | "EXPIRED"
  | "CONSUMER_ORDER_GAP"
  | "CONSUMER_ORDER_POSITION_CONFLICT"
  | "IDEMPOTENCY_CONFLICT"
  | "STATE_TRANSITION_NOT_ALLOWED"
  | "SECRET_CUSTODY_ERROR"
  | "INTERNAL_ERROR"
  | (string & {});

export interface ReceiverSdkErrorOptions {
  readonly code: ReceiverSdkErrorCode;
  readonly message: string;
  readonly httpStatus: number;
  readonly retryable?: boolean | undefined;
  readonly safeReason?: string | undefined;
  readonly cause?: unknown;
}

export class ReceiverSdkError extends Error {
  readonly code: ReceiverSdkErrorCode;
  readonly httpStatus: number;
  readonly retryable: boolean;
  readonly safeReason?: string | undefined;

  constructor(options: ReceiverSdkErrorOptions) {
    super(options.message, options.cause !== undefined ? { cause: options.cause } : undefined);
    this.name = new.target.name;
    this.code = options.code;
    this.httpStatus = options.httpStatus;
    this.retryable = options.retryable ?? false;
    if (options.safeReason !== undefined) {
      this.safeReason = options.safeReason;
    }
  }
}

export class ReceiverValidationError extends ReceiverSdkError {
  constructor(options: {
    readonly code?: ReceiverSdkErrorCode | undefined;
    readonly message: string;
    readonly httpStatus?: 400 | 413 | 422 | undefined;
    readonly safeReason?: string | undefined;
    readonly cause?: unknown;
  }) {
    const code = options.code ?? "INVALID_VALUE";
    const status =
      options.httpStatus ??
      (code === "PAYLOAD_TOO_LARGE" ? 413 : code === "UNSUPPORTED_SCHEMA_VERSION" ? 422 : 400);
    super({
      code,
      message: options.message,
      httpStatus: status,
      retryable: false,
      safeReason: options.safeReason,
      cause: options.cause
    });
  }
}

export class ReceiverAuthError extends ReceiverSdkError {
  constructor(options: {
    readonly code?: ReceiverSdkErrorCode | undefined;
    readonly message: string;
    readonly httpStatus?: 401 | 403 | undefined;
    readonly safeReason?: string | undefined;
    readonly cause?: unknown;
  }) {
    super({
      code: options.code ?? "SIGNATURE_VERIFICATION_FAILED",
      message: options.message,
      httpStatus: options.httpStatus ?? 401,
      retryable: false,
      safeReason: options.safeReason,
      cause: options.cause
    });
  }
}

export class ReceiverExpiredError extends ReceiverSdkError {
  constructor(options: {
    readonly code?: ReceiverSdkErrorCode | undefined;
    readonly message: string;
    readonly safeReason?: string | undefined;
    readonly cause?: unknown;
  }) {
    super({
      code: options.code ?? "EXPIRED",
      message: options.message,
      httpStatus: 401,
      retryable: false,
      safeReason: options.safeReason,
      cause: options.cause
    });
  }
}

export class ReceiverConflictError extends ReceiverSdkError {
  constructor(options: {
    readonly code?: ReceiverSdkErrorCode | undefined;
    readonly message: string;
    readonly retryable?: boolean | undefined;
    readonly safeReason?: string | undefined;
    readonly cause?: unknown;
  }) {
    super({
      code: options.code ?? "CONSUMER_ORDER_POSITION_CONFLICT",
      message: options.message,
      httpStatus: 409,
      retryable: options.retryable ?? false,
      safeReason: options.safeReason,
      cause: options.cause
    });
  }
}

export class ReceiverConfigError extends ReceiverSdkError {
  constructor(options: {
    readonly code?: ReceiverSdkErrorCode | undefined;
    readonly message: string;
    readonly safeReason?: string | undefined;
    readonly cause?: unknown;
  }) {
    super({
      code: options.code ?? "SECRET_CUSTODY_ERROR",
      message: options.message,
      httpStatus: 500,
      retryable: false,
      safeReason: options.safeReason,
      cause: options.cause
    });
  }
}

export function toReceiverSdkError(err: unknown): ReceiverSdkError {
  if (err instanceof ReceiverSdkError) {
    return err;
  }
  if (err instanceof ExpiredDomainError) {
    return new ReceiverExpiredError({
      code: err.code,
      message: err.message,
      cause: err
    });
  }
  if (err instanceof AuthenticationDomainError) {
    return new ReceiverAuthError({
      code: err.code,
      message: err.message,
      cause: err
    });
  }
  if (err instanceof ConflictDomainError) {
    return new ReceiverConflictError({
      code: err.code,
      message: err.message,
      retryable: err.code === "CONSUMER_ORDER_GAP",
      cause: err
    });
  }
  if (err instanceof ValidationDomainError) {
    return new ReceiverValidationError({
      code: err.code,
      message: err.message,
      httpStatus:
        err.code === "PAYLOAD_TOO_LARGE"
          ? 413
          : err.code === "UNSUPPORTED_SCHEMA_VERSION"
            ? 422
            : 400,
      cause: err
    });
  }
  if (err instanceof DependencyUnavailableDomainError) {
    return new ReceiverConfigError({
      code: err.code,
      message: err.message,
      cause: err
    });
  }
  if (err instanceof DomainError) {
    return new ReceiverSdkError({
      code: err.code,
      message: err.message,
      httpStatus: 500,
      retryable: false,
      cause: err
    });
  }
  if (err instanceof Error) {
    return new ReceiverSdkError({
      code: "INTERNAL_ERROR",
      message: err.message,
      httpStatus: 500,
      retryable: false,
      cause: err
    });
  }
  return new ReceiverSdkError({
    code: "INTERNAL_ERROR",
    message: String(err),
    httpStatus: 500,
    retryable: false,
    cause: err
  });
}
