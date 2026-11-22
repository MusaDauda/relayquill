import {
  DependencyUnavailableDomainError,
  DomainError,
  LimitExceededDomainError,
  ValidationDomainError,
  formatUtcTimestamp,
  nowUtcInstant
} from "@relayquill/domain";
import {
  type CanonicalUtcTimestamp,
  createErrorEnvelope,
  createSuccessEnvelope,
  mapDomainErrorCodeToHttpStatus
} from "@relayquill/contracts";
import { HttpStatusDomainError } from "./headers.js";
import { sanitizeLogMessage } from "./logger.js";

export function sendSuccessEnvelope<T>(
  reply: { status(code: number): unknown; send(payload: unknown): unknown },
  statusCode: number,
  data: T,
  meta: {
    readonly requestId: string;
    readonly observedAt?: CanonicalUtcTimestamp | undefined;
  }
): unknown {
  const observed_at = meta.observedAt ?? formatUtcTimestamp(nowUtcInstant());
  const envelope = createSuccessEnvelope(data, {
    request_id: meta.requestId,
    observed_at
  });
  reply.status(statusCode);
  return reply.send(envelope);
}

export function mapUnknownErrorToHttpResponse(
  err: unknown,
  meta: {
    readonly requestId: string;
    readonly observedAt?: CanonicalUtcTimestamp | undefined;
  }
): { readonly statusCode: number; readonly envelope: ReturnType<typeof createErrorEnvelope> } {
  const observed_at = meta.observedAt ?? formatUtcTimestamp(nowUtcInstant());

  if (err instanceof HttpStatusDomainError) {
    const envelope = createErrorEnvelope(err, {
      request_id: meta.requestId,
      observed_at
    });
    return { statusCode: err.httpStatus, envelope };
  }

  if (err instanceof DomainError) {
    const statusCode = mapDomainErrorCodeToHttpStatus(err.code);
    const envelope = createErrorEnvelope(err, {
      request_id: meta.requestId,
      observed_at
    });
    return { statusCode, envelope };
  }

  const fastifyErr = err as { statusCode?: unknown; code?: unknown; message?: unknown } | undefined;
  if (fastifyErr && typeof fastifyErr.statusCode === "number") {
    if (fastifyErr.statusCode === 413 || fastifyErr.code === "FST_ERR_CTP_BODY_TOO_LARGE") {
      const limitErr = new LimitExceededDomainError({
        code: "PAYLOAD_TOO_LARGE",
        message: "HTTP request body exceeded configured byte limit"
      });
      return {
        statusCode: 413,
        envelope: createErrorEnvelope(limitErr, { request_id: meta.requestId, observed_at })
      };
    }
    if (fastifyErr.statusCode === 415 || fastifyErr.code === "FST_ERR_CTP_INVALID_MEDIA_TYPE") {
      const mediaErr = new ValidationDomainError({
        code: "INVALID_VALUE",
        message: "Unsupported or missing Content-Type header; expected application/json"
      });
      return {
        statusCode: 415,
        envelope: createErrorEnvelope(mediaErr, { request_id: meta.requestId, observed_at })
      };
    }
    if (fastifyErr.statusCode >= 400 && fastifyErr.statusCode < 500) {
      const valErr = new ValidationDomainError({
        code: "INVALID_VALUE",
        message: sanitizeLogMessage(
          typeof fastifyErr.message === "string" ? fastifyErr.message : "Bad request"
        )
      });
      return {
        statusCode: fastifyErr.statusCode,
        envelope: createErrorEnvelope(valErr, { request_id: meta.requestId, observed_at })
      };
    }
  }

  const internalErr: DomainError = new DependencyUnavailableDomainError({
    code: "DEPENDENCY_UNAVAILABLE",
    message: sanitizeLogMessage(err instanceof Error ? err.message : "Unexpected internal failure"),
    retryable: true,
    acceptance: "unknown"
  });
  return {
    statusCode: 500,
    envelope: createErrorEnvelope(internalErr, { request_id: meta.requestId, observed_at })
  };
}
