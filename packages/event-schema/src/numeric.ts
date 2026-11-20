import {
  EVENT_MAX_NUMERIC_TOKEN_BYTES,
  LimitExceededDomainError,
  ValidationDomainError
} from "@relayquill/domain";
import { isLosslessNumber } from "lossless-json";

export const NUMERIC_MAX_COEFFICIENT_DIGITS = 128 as const;
export const NUMERIC_MIN_EXPONENT = -1024 as const;
export const NUMERIC_MAX_EXPONENT = 1024 as const;

const STRICT_JSON_NUMBER_REGEX =
  /^(-)?(0|[1-9][0-9]*)(?:\.([0-9]+))?(?:[eE]([+-]?[0-9]+))?$/;
const MAX_RAW_EXPONENT_MAGNITUDE = 2048n;

export interface NormalizedDecimal {
  readonly sign: -1 | 0 | 1;
  readonly coefficient: string;
  readonly exponent: number;
}

export function isNormalizedDecimalValue(value: unknown): value is NormalizedDecimal {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return false;
  }
  const proto: unknown = Object.getPrototypeOf(value);
  if (proto !== null && proto !== Object.prototype) {
    return false;
  }
  const rec = value as Record<string, unknown>;
  const sign = rec.sign;
  const coefficient = rec.coefficient;
  const exponent = rec.exponent;
  if (sign !== -1 && sign !== 0 && sign !== 1) {
    return false;
  }
  if (typeof coefficient !== "string" || typeof exponent !== "number") {
    return false;
  }
  if (!Number.isInteger(exponent)) {
    return false;
  }
  if (sign === 0) {
    return coefficient === "0" && exponent === 0;
  }
  if (
    coefficient.length === 0 ||
    coefficient.length > NUMERIC_MAX_COEFFICIENT_DIGITS ||
    !/^[1-9](?:[0-9]*[1-9])?$/.test(coefficient)
  ) {
    return false;
  }
  return exponent >= NUMERIC_MIN_EXPONENT && exponent <= NUMERIC_MAX_EXPONENT;
}

export function parseNormalizedDecimalObject(
  value: unknown,
  fieldPath = "numeric"
): NormalizedDecimal {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Expected normalized decimal object at ${fieldPath}`,
      fieldErrors: [{ path: fieldPath, code: "INVALID_VALUE" }]
    });
  }
  const proto: unknown = Object.getPrototypeOf(value);
  if (proto !== null && proto !== Object.prototype) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Expected plain object for normalized decimal at ${fieldPath}`,
      fieldErrors: [{ path: fieldPath, code: "INVALID_VALUE" }]
    });
  }
  const rec = value as Record<string, unknown>;
  for (const key of Object.keys(rec)) {
    if (key !== "sign" && key !== "coefficient" && key !== "exponent") {
      throw new ValidationDomainError({
        code: "INVALID_VALUE",
        message: `Unsupported field "${key}" in normalized decimal at ${fieldPath}`,
        fieldErrors: [{ path: `${fieldPath}.${key}`, code: "INVALID_VALUE" }]
      });
    }
  }
  if (!isNormalizedDecimalValue(rec)) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Invalid normalized decimal representation at ${fieldPath}`,
      fieldErrors: [{ path: fieldPath, code: "INVALID_VALUE" }]
    });
  }
  return Object.freeze({
    sign: rec.sign,
    coefficient: rec.coefficient,
    exponent: rec.exponent
  });
}

function parseBoundedRawExponent(expText: string, fieldPath: string): bigint {
  if (expText.length === 0) {
    return 0n;
  }
  let negative = false;
  let start = 0;
  if (expText[0] === "-") {
    negative = true;
    start = 1;
  } else if (expText[0] === "+") {
    start = 1;
  }
  while (start < expText.length && expText[start] === "0") {
    start += 1;
  }
  const significantExpDigits = expText.slice(start);
  if (significantExpDigits.length > 6) {
    throw new LimitExceededDomainError({
      code: "SCHEMA_EVALUATION_LIMIT",
      message: `Numeric exponent exceeds profile bounds at ${fieldPath}`,
      fieldErrors: [{ path: fieldPath, code: "SCHEMA_EVALUATION_LIMIT" }]
    });
  }
  if (significantExpDigits.length === 0) {
    return 0n;
  }
  const magnitude = BigInt(significantExpDigits);
  const signed = negative ? -magnitude : magnitude;
  if (signed < -MAX_RAW_EXPONENT_MAGNITUDE || signed > MAX_RAW_EXPONENT_MAGNITUDE) {
    throw new LimitExceededDomainError({
      code: "SCHEMA_EVALUATION_LIMIT",
      message: `Numeric exponent exceeds profile bounds at ${fieldPath}`,
      fieldErrors: [{ path: fieldPath, code: "SCHEMA_EVALUATION_LIMIT" }]
    });
  }
  return signed;
}

export function normalizeNumericToken(token: string, fieldPath = "number"): NormalizedDecimal {
  if (typeof token !== "string" || token.length === 0) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Expected non-empty JSON numeric token at ${fieldPath}`,
      fieldErrors: [{ path: fieldPath, code: "INVALID_VALUE" }]
    });
  }
  if (token.length > EVENT_MAX_NUMERIC_TOKEN_BYTES) {
    throw new LimitExceededDomainError({
      code: "SCHEMA_EVALUATION_LIMIT",
      message: `Numeric token exceeds ${EVENT_MAX_NUMERIC_TOKEN_BYTES} bytes at ${fieldPath}`,
      fieldErrors: [{ path: fieldPath, code: "SCHEMA_EVALUATION_LIMIT" }]
    });
  }

  const match = STRICT_JSON_NUMBER_REGEX.exec(token);
  if (match === null) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Invalid JSON numeric syntax at ${fieldPath}`,
      fieldErrors: [{ path: fieldPath, code: "INVALID_VALUE" }]
    });
  }

  const isNegative = match[1] === "-";
  const intPart = match[2] ?? "0";
  const fracPart = match[3] ?? "";
  const expPart = match[4] ?? "";
  const rawExp = parseBoundedRawExponent(expPart, fieldPath);

  const combinedDigits = `${intPart}${fracPart}`;
  let firstNonZero = 0;
  while (firstNonZero < combinedDigits.length && combinedDigits[firstNonZero] === "0") {
    firstNonZero += 1;
  }

  if (firstNonZero === combinedDigits.length) {
    if (rawExp < BigInt(NUMERIC_MIN_EXPONENT) || rawExp > BigInt(NUMERIC_MAX_EXPONENT)) {
      throw new LimitExceededDomainError({
        code: "SCHEMA_EVALUATION_LIMIT",
        message: `Numeric exponent exceeds [${NUMERIC_MIN_EXPONENT}, ${NUMERIC_MAX_EXPONENT}] at ${fieldPath}`,
        fieldErrors: [{ path: fieldPath, code: "SCHEMA_EVALUATION_LIMIT" }]
      });
    }
    return Object.freeze({
      sign: 0,
      coefficient: "0",
      exponent: 0
    });
  }

  let lastNonZero = combinedDigits.length - 1;
  while (lastNonZero > firstNonZero && combinedDigits[lastNonZero] === "0") {
    lastNonZero -= 1;
  }

  const coefficient = combinedDigits.slice(firstNonZero, lastNonZero + 1);
  if (coefficient.length > NUMERIC_MAX_COEFFICIENT_DIGITS) {
    throw new LimitExceededDomainError({
      code: "SCHEMA_EVALUATION_LIMIT",
      message: `Numeric coefficient exceeds ${NUMERIC_MAX_COEFFICIENT_DIGITS} significant digits at ${fieldPath}`,
      fieldErrors: [{ path: fieldPath, code: "SCHEMA_EVALUATION_LIMIT" }]
    });
  }

  const trailingZeroes = combinedDigits.length - 1 - lastNonZero;
  const normalizedExponentBig = rawExp - BigInt(fracPart.length) + BigInt(trailingZeroes);
  if (
    normalizedExponentBig < BigInt(NUMERIC_MIN_EXPONENT) ||
    normalizedExponentBig > BigInt(NUMERIC_MAX_EXPONENT)
  ) {
    throw new LimitExceededDomainError({
      code: "SCHEMA_EVALUATION_LIMIT",
      message: `Normalized exponent exceeds [${NUMERIC_MIN_EXPONENT}, ${NUMERIC_MAX_EXPONENT}] at ${fieldPath}`,
      fieldErrors: [{ path: fieldPath, code: "SCHEMA_EVALUATION_LIMIT" }]
    });
  }

  return Object.freeze({
    sign: isNegative ? -1 : 1,
    coefficient,
    exponent: Number(normalizedExponentBig)
  });
}

export function normalizeLosslessNumber(
  value: unknown,
  fieldPath = "number"
): NormalizedDecimal {
  if (isLosslessNumber(value)) {
    return normalizeNumericToken(value.value, fieldPath);
  }
  if (typeof value === "string") {
    return normalizeNumericToken(value, fieldPath);
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw new LimitExceededDomainError({
        code: "SCHEMA_EVALUATION_LIMIT",
        message: `Non-finite numeric value is unsupported at ${fieldPath}`,
        fieldErrors: [{ path: fieldPath, code: "SCHEMA_EVALUATION_LIMIT" }]
      });
    }
    if (Number.isInteger(value) && !Number.isSafeInteger(value)) {
      throw new ValidationDomainError({
        code: "INVALID_VALUE",
        message: `Unsafe JavaScript integer without lossless representation at ${fieldPath}`,
        fieldErrors: [{ path: fieldPath, code: "INVALID_VALUE" }]
      });
    }
    return normalizeNumericToken(Object.is(value, -0) ? "0" : value.toString(10), fieldPath);
  }
  if (isNormalizedDecimalValue(value)) {
    return Object.freeze({
      sign: value.sign,
      coefficient: value.coefficient,
      exponent: value.exponent
    });
  }
  throw new ValidationDomainError({
    code: "INVALID_VALUE",
    message: `Expected lossless numeric value at ${fieldPath}`,
    fieldErrors: [{ path: fieldPath, code: "INVALID_VALUE" }]
  });
}

export function isNormalizedInteger(value: NormalizedDecimal): boolean {
  return value.sign === 0 || value.exponent >= 0;
}

export function compareNormalizedDecimals(a: NormalizedDecimal, b: NormalizedDecimal): -1 | 0 | 1 {
  if (a.sign !== b.sign) {
    return a.sign < b.sign ? -1 : 1;
  }
  if (a.sign === 0) {
    return 0;
  }

  const magA = a.coefficient.length + a.exponent;
  const magB = b.coefficient.length + b.exponent;
  let absOrder: -1 | 0 | 1;
  if (magA !== magB) {
    absOrder = magA < magB ? -1 : 1;
  } else if (a.coefficient === b.coefficient) {
    absOrder = 0;
  } else {
    absOrder = a.coefficient < b.coefficient ? -1 : 1;
  }

  if (absOrder === 0) {
    return 0;
  }
  return a.sign === 1 ? absOrder : absOrder === 1 ? -1 : 1;
}

export function equalNormalizedDecimals(a: NormalizedDecimal, b: NormalizedDecimal): boolean {
  return (
    a.sign === b.sign &&
    a.exponent === b.exponent &&
    a.coefficient === b.coefficient
  );
}

export function formatNormalizedDecimal(value: NormalizedDecimal): string {
  if (value.sign === 0) {
    return "0";
  }
  const signPrefix = value.sign < 0 ? "-" : "";
  if (value.exponent === 0) {
    return `${signPrefix}${value.coefficient}`;
  }
  return `${signPrefix}${value.coefficient}e${value.exponent}`;
}
