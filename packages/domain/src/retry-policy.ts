import { type Temporal } from "@js-temporal/polyfill";
import { createEnumGuard } from "./enums.js";
import { ValidationDomainError } from "./errors.js";
import { addMilliseconds, compareInstants } from "./time.js";

export const RETRY_POLICY_VERSIONS = ["retry_v1"] as const;
export type RetryPolicyVersion = (typeof RETRY_POLICY_VERSIONS)[number];
export const isRetryPolicyVersion = createEnumGuard(RETRY_POLICY_VERSIONS);

export const RETRY_AFTER_PARSE_CLASSES = [
  "none",
  "delay_seconds",
  "http_date",
  "past_date",
  "invalid",
  "oversized",
  "conflicting"
] as const;
export type RetryAfterParseClass = (typeof RETRY_AFTER_PARSE_CLASSES)[number];
export const isRetryAfterParseClass = createEnumGuard(RETRY_AFTER_PARSE_CLASSES);

export const DELIVERY_OUTCOME_CLASSES = [
  "acknowledged",
  "transient_http",
  "permanent_http",
  "permanent_redirect",
  "transport_unknown",
  "permanent_policy_or_security"
] as const;
export type DeliveryOutcomeClass = (typeof DELIVERY_OUTCOME_CLASSES)[number];
export const isDeliveryOutcomeClass = createEnumGuard(DELIVERY_OUTCOME_CLASSES);

export const RETRY_DECISION_OUTCOMES = [
  "acknowledged",
  "retry_wait",
  "dead_letter",
  "expired"
] as const;
export type RetryDecisionOutcome = (typeof RETRY_DECISION_OUTCOMES)[number];
export const isRetryDecisionOutcome = createEnumGuard(RETRY_DECISION_OUTCOMES);

export interface RetryPolicyConfig {
  readonly policyVersion: RetryPolicyVersion;
  readonly baseDelayMs: bigint;
  readonly multiplier: bigint;
  readonly maxDelayMs: bigint;
  readonly retryAfterCapMs: bigint;
  readonly minimumNextWindowMs: bigint;
  readonly maximumSendStarts: number;
}

export const RETRY_V1_POLICY: RetryPolicyConfig = Object.freeze({
  policyVersion: "retry_v1",
  baseDelayMs: 1_000n,
  multiplier: 2n,
  maxDelayMs: 1_800_000n,
  retryAfterCapMs: 1_800_000n,
  minimumNextWindowMs: 10_000n,
  maximumSendStarts: 12
});

export interface HttpOutcomeClassification {
  readonly status: number;
  readonly outcomeClass: DeliveryOutcomeClass;
  readonly retryable: boolean;
  readonly circuitEligible: boolean;
  readonly safeErrorCode: string | null;
}

export function classifyHttpOutcome(status: number): HttpOutcomeClassification {
  if (!Number.isInteger(status) || status < 100 || status > 599) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `HTTP response status must be an integer in 100..599, got ${String(status)}`,
      fieldErrors: [{ path: "response_status", code: "INVALID_VALUE" }]
    });
  }

  if (status >= 200 && status <= 299) {
    return Object.freeze({
      status,
      outcomeClass: "acknowledged",
      retryable: false,
      circuitEligible: true,
      safeErrorCode: null
    });
  }

  if (status >= 300 && status <= 399) {
    return Object.freeze({
      status,
      outcomeClass: "permanent_redirect",
      retryable: false,
      circuitEligible: true,
      safeErrorCode: "REDIRECT_NOT_ALLOWED"
    });
  }

  if (status === 408 || status === 425 || status === 429) {
    return Object.freeze({
      status,
      outcomeClass: "transient_http",
      retryable: true,
      circuitEligible: true,
      safeErrorCode: `HTTP_${status}`
    });
  }

  if (status >= 500 && status <= 599) {
    if (status === 501 || status === 505) {
      return Object.freeze({
        status,
        outcomeClass: "permanent_http",
        retryable: false,
        circuitEligible: true,
        safeErrorCode: `HTTP_${status}`
      });
    }
    return Object.freeze({
      status,
      outcomeClass: "transient_http",
      retryable: true,
      circuitEligible: true,
      safeErrorCode: `HTTP_${status}`
    });
  }

  return Object.freeze({
    status,
    outcomeClass: "permanent_http",
    retryable: false,
    circuitEligible: true,
    safeErrorCode: `HTTP_${status}`
  });
}

export function computeBackoffCeilingMs(
  ordinal: number,
  policy: RetryPolicyConfig = RETRY_V1_POLICY
): bigint {
  if (!Number.isInteger(ordinal) || ordinal < 0) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: "Backoff ordinal must be a non-negative integer",
      fieldErrors: [{ path: "attempt_count", code: "INVALID_VALUE" }]
    });
  }

  let delay = policy.baseDelayMs;
  if (delay >= policy.maxDelayMs) {
    return policy.maxDelayMs;
  }

  const steps = ordinal <= 1 ? 0 : ordinal - 1;
  for (let i = 0; i < steps; i += 1) {
    delay = delay * policy.multiplier;
    if (delay >= policy.maxDelayMs) {
      return policy.maxDelayMs;
    }
  }
  return delay;
}

export type UniformBigIntDraw = (maxInclusive: bigint) => bigint;

export interface RetryDecisionInput {
  readonly policy?: RetryPolicyConfig | undefined;
  readonly outcomeClass: DeliveryOutcomeClass;
  readonly attemptCount: number;
  readonly maximumAttempts?: number | undefined;
  readonly decidedAt: Temporal.Instant;
  readonly deadlineAt: Temporal.Instant;
  readonly retryAfterMs?: bigint | null | undefined;
  readonly retryAfterParseClass?: RetryAfterParseClass | undefined;
  readonly drawUniformBigIntInclusive: UniformBigIntDraw;
}

export interface RetryDecisionResult {
  readonly decision: RetryDecisionOutcome;
  readonly policyVersion: RetryPolicyVersion;
  readonly reasonCode: string | null;
  readonly nextEligibleAt: Temporal.Instant | null;
  readonly backoffCeilingMs: bigint | null;
  readonly jitteredDelayMs: bigint | null;
  readonly cappedRetryAfterMs: bigint | null;
  readonly selectedDelayMs: bigint | null;
}

export function computeRetryDecision(input: RetryDecisionInput): RetryDecisionResult {
  const policy = input.policy ?? RETRY_V1_POLICY;
  const maxAttempts = input.maximumAttempts ?? policy.maximumSendStarts;

  if (!Number.isInteger(input.attemptCount) || input.attemptCount < 0) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: "attemptCount must be a non-negative integer",
      fieldErrors: [{ path: "attempt_count", code: "INVALID_VALUE" }]
    });
  }
  if (!Number.isInteger(maxAttempts) || maxAttempts < 1) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: "maximumAttempts must be a positive integer",
      fieldErrors: [{ path: "maximum_attempts", code: "INVALID_VALUE" }]
    });
  }

  if (input.outcomeClass === "acknowledged") {
    return Object.freeze({
      decision: "acknowledged",
      policyVersion: policy.policyVersion,
      reasonCode: null,
      nextEligibleAt: null,
      backoffCeilingMs: null,
      jitteredDelayMs: null,
      cappedRetryAfterMs: null,
      selectedDelayMs: null
    });
  }

  if (compareInstants(input.decidedAt, input.deadlineAt) >= 0) {
    return Object.freeze({
      decision: "expired",
      policyVersion: policy.policyVersion,
      reasonCode: "EXPIRED",
      nextEligibleAt: null,
      backoffCeilingMs: null,
      jitteredDelayMs: null,
      cappedRetryAfterMs: null,
      selectedDelayMs: null
    });
  }

  if (
    input.outcomeClass === "permanent_http" ||
    input.outcomeClass === "permanent_redirect" ||
    input.outcomeClass === "permanent_policy_or_security"
  ) {
    return Object.freeze({
      decision: "dead_letter",
      policyVersion: policy.policyVersion,
      reasonCode:
        input.outcomeClass === "permanent_redirect"
          ? "REDIRECT_NOT_ALLOWED"
          : input.outcomeClass === "permanent_policy_or_security"
            ? "EGRESS_POLICY_DENIED"
            : "PERMANENT_HTTP_ERROR",
      nextEligibleAt: null,
      backoffCeilingMs: null,
      jitteredDelayMs: null,
      cappedRetryAfterMs: null,
      selectedDelayMs: null
    });
  }

  if (input.attemptCount >= maxAttempts) {
    return Object.freeze({
      decision: "dead_letter",
      policyVersion: policy.policyVersion,
      reasonCode: "RETRY_BUDGET_EXHAUSTED",
      nextEligibleAt: null,
      backoffCeilingMs: null,
      jitteredDelayMs: null,
      cappedRetryAfterMs: null,
      selectedDelayMs: null
    });
  }

  const ordinal = input.attemptCount < 1 ? 1 : input.attemptCount;
  const backoffCeilingMs = computeBackoffCeilingMs(ordinal, policy);
  const jitteredDelayMs = input.drawUniformBigIntInclusive(backoffCeilingMs);
  if (jitteredDelayMs < 0n || jitteredDelayMs > backoffCeilingMs) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Uniform jitter draw must be within [0, ${backoffCeilingMs.toString(10)}]`,
      fieldErrors: [{ path: "jittered_delay_ms", code: "INVALID_VALUE" }]
    });
  }

  const rawRetryAfter = input.retryAfterMs ?? null;
  if (rawRetryAfter !== null && rawRetryAfter < 0n) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: "retryAfterMs cannot be negative",
      fieldErrors: [{ path: "retry_after_ms", code: "INVALID_VALUE" }]
    });
  }

  const cappedRetryAfterMs =
    rawRetryAfter !== null
      ? rawRetryAfter > policy.retryAfterCapMs
        ? policy.retryAfterCapMs
        : rawRetryAfter
      : 0n;

  const selectedDelayMs =
    jitteredDelayMs >= cappedRetryAfterMs ? jitteredDelayMs : cappedRetryAfterMs;

  const nextEligibleAt = addMilliseconds(input.decidedAt, selectedDelayMs, "next_eligible_at");
  const minimumWindowEnd = addMilliseconds(
    nextEligibleAt,
    policy.minimumNextWindowMs,
    "minimum_next_window"
  );

  if (compareInstants(minimumWindowEnd, input.deadlineAt) > 0) {
    return Object.freeze({
      decision: "dead_letter",
      policyVersion: policy.policyVersion,
      reasonCode: "NO_RETRY_WITHIN_WINDOW",
      nextEligibleAt,
      backoffCeilingMs,
      jitteredDelayMs,
      cappedRetryAfterMs,
      selectedDelayMs
    });
  }

  return Object.freeze({
    decision: "retry_wait",
    policyVersion: policy.policyVersion,
    reasonCode: null,
    nextEligibleAt,
    backoffCeilingMs,
    jitteredDelayMs,
    cappedRetryAfterMs,
    selectedDelayMs
  });
}
