import {
  LimitExceededDomainError,
  type Sha256Hex,
  ValidationDomainError
} from "@relayquill/domain";
import { isLosslessNumber } from "lossless-json";
import {
  type NormalizedDecimal,
  compareNormalizedDecimals,
  equalNormalizedDecimals,
  isNormalizedInteger,
  normalizeLosslessNumber
} from "./numeric.js";
import {
  type LosslessJsonValue,
  countUnicodeScalarValues,
  isPlainObjectRecord,
  parseEventJsonBytes
} from "./parser.js";
import { formatJsonPointer } from "./pointer.js";
import {
  type CompiledEventSchema,
  type NormalizedConcreteSchemaNode,
  type NormalizedScalarLiteral,
  type NormalizedSchemaNode,
  SCHEMA_MAX_DIAGNOSTICS,
  dereferenceSchemaNode
} from "./profile.js";

export const EVALUATOR_MAX_WORK_UNITS = 500_000 as const;

export type SchemaDiagnosticCode =
  | "TYPE_MISMATCH"
  | "REQUIRED_PROPERTY_MISSING"
  | "ADDITIONAL_PROPERTY_FORBIDDEN"
  | "ARRAY_MIN_ITEMS"
  | "ARRAY_MAX_ITEMS"
  | "STRING_MIN_LENGTH"
  | "STRING_MAX_LENGTH"
  | "NUMBER_MINIMUM"
  | "NUMBER_MAXIMUM"
  | "ENUM_MISMATCH"
  | "CONST_MISMATCH";

export interface SchemaDiagnostic {
  readonly path: string;
  readonly code: SchemaDiagnosticCode;
  readonly message: string;
}

export interface EventEvaluationOptions {
  readonly maxWorkUnits?: number | undefined;
  readonly maxDiagnostics?: number | undefined;
}

export interface EventEvaluationResult {
  readonly valid: boolean;
  readonly diagnostics: readonly SchemaDiagnostic[];
  readonly totalDiagnosticsObserved: number;
  readonly workUnitsUsed: number;
  readonly byteCount?: number | undefined;
  readonly sha256?: Sha256Hex | undefined;
}

function compareCodeUnits(a: string, b: string): number {
  if (a === b) {
    return 0;
  }
  return a < b ? -1 : 1;
}

function matchesScalarLiteral(
  value: unknown,
  normalizedNum: NormalizedDecimal | undefined,
  literal: NormalizedScalarLiteral
): boolean {
  switch (literal.kind) {
    case "null":
      return value === null;
    case "boolean":
      return value === literal.value;
    case "string":
      return value === literal.value;
    case "number":
      return normalizedNum !== undefined && equalNormalizedDecimals(normalizedNum, literal.value);
  }
}

function describeJsonValueType(value: unknown): string {
  if (value === null) {
    return "null";
  }
  if (Array.isArray(value)) {
    return "array";
  }
  if (isLosslessNumber(value)) {
    return "number";
  }
  return typeof value;
}

export function evaluateParsedEvent(
  schema: CompiledEventSchema,
  value: LosslessJsonValue,
  options?: EventEvaluationOptions
): EventEvaluationResult {
  const maxWorkUnits = options?.maxWorkUnits ?? EVALUATOR_MAX_WORK_UNITS;
  const maxDiagnostics = Math.min(
    SCHEMA_MAX_DIAGNOSTICS,
    Math.max(1, options?.maxDiagnostics ?? SCHEMA_MAX_DIAGNOSTICS)
  );

  if (!Number.isInteger(maxWorkUnits) || maxWorkUnits < 1 || maxWorkUnits > EVALUATOR_MAX_WORK_UNITS) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `maxWorkUnits must be within [1, ${EVALUATOR_MAX_WORK_UNITS}]`
    });
  }

  const diagnostics: SchemaDiagnostic[] = [];
  let totalDiagnosticsObserved = 0;
  let workUnits = 0;

  function tickWork(units = 1): void {
    workUnits += units;
    if (workUnits > maxWorkUnits) {
      throw new LimitExceededDomainError({
        code: "SCHEMA_EVALUATION_LIMIT",
        message: `Schema evaluation exceeded work budget of ${maxWorkUnits} units`
      });
    }
  }

  function recordDiagnostic(path: string, code: SchemaDiagnosticCode, message: string): void {
    totalDiagnosticsObserved += 1;
    if (diagnostics.length < maxDiagnostics) {
      diagnostics.push(Object.freeze({ path, code, message }));
    }
  }

  function checkEnumAndConst(
    val: unknown,
    normalizedNum: NormalizedDecimal | undefined,
    node: Exclude<NormalizedConcreteSchemaNode, { kind: "object" | "array" }>,
    pointerPath: string
  ): void {
    if (node.const !== undefined) {
      tickWork();
      if (!matchesScalarLiteral(val, normalizedNum, node.const)) {
        recordDiagnostic(pointerPath, "CONST_MISMATCH", "Value does not match schema const");
      }
    }
    if (node.enum !== undefined) {
      let matched = false;
      for (const candidate of node.enum) {
        tickWork();
        if (matchesScalarLiteral(val, normalizedNum, candidate)) {
          matched = true;
          break;
        }
      }
      if (!matched) {
        recordDiagnostic(pointerPath, "ENUM_MISMATCH", "Value is not one of allowed enum choices");
      }
    }
  }

  function evaluateNode(
    schemaNode: NormalizedSchemaNode,
    val: unknown,
    pathTokens: string[]
  ): void {
    tickWork();
    const concrete = dereferenceSchemaNode(schemaNode, schema);
    const pointerPath = formatJsonPointer(pathTokens);

    if (val === null) {
      if (concrete.kind === "null") {
        checkEnumAndConst(val, undefined, concrete, pointerPath);
        return;
      }
      if (concrete.nullable) {
        if (concrete.kind !== "object" && concrete.kind !== "array") {
          checkEnumAndConst(val, undefined, concrete, pointerPath);
        }
        return;
      }
      recordDiagnostic(pointerPath, "TYPE_MISMATCH", `Expected ${concrete.kind}, got null`);
      return;
    }

    switch (concrete.kind) {
      case "null": {
        recordDiagnostic(
          pointerPath,
          "TYPE_MISMATCH",
          `Expected null, got ${describeJsonValueType(val)}`
        );
        return;
      }

      case "boolean": {
        if (typeof val !== "boolean") {
          recordDiagnostic(
            pointerPath,
            "TYPE_MISMATCH",
            `Expected boolean, got ${describeJsonValueType(val)}`
          );
          return;
        }
        checkEnumAndConst(val, undefined, concrete, pointerPath);
        return;
      }

      case "string": {
        if (typeof val !== "string") {
          recordDiagnostic(
            pointerPath,
            "TYPE_MISMATCH",
            `Expected string, got ${describeJsonValueType(val)}`
          );
          return;
        }
        const scalarLen = countUnicodeScalarValues(val);
        tickWork(Math.ceil(scalarLen / 64));
        if (scalarLen < concrete.minLength) {
          recordDiagnostic(
            pointerPath,
            "STRING_MIN_LENGTH",
            `String scalar length is below minLength ${concrete.minLength}`
          );
        }
        if (scalarLen > concrete.maxLength) {
          recordDiagnostic(
            pointerPath,
            "STRING_MAX_LENGTH",
            `String scalar length exceeds maxLength ${concrete.maxLength}`
          );
        }
        checkEnumAndConst(val, undefined, concrete, pointerPath);
        return;
      }

      case "integer":
      case "number": {
        if (!isLosslessNumber(val) && typeof val !== "number") {
          recordDiagnostic(
            pointerPath,
            "TYPE_MISMATCH",
            `Expected ${concrete.kind}, got ${describeJsonValueType(val)}`
          );
          return;
        }
        const normalizedNum = normalizeLosslessNumber(val, pointerPath || "$");
        tickWork();
        if (concrete.kind === "integer" && !isNormalizedInteger(normalizedNum)) {
          recordDiagnostic(pointerPath, "TYPE_MISMATCH", "Expected integer numeric value");
          return;
        }
        if (
          concrete.minimum !== undefined &&
          compareNormalizedDecimals(normalizedNum, concrete.minimum) < 0
        ) {
          recordDiagnostic(pointerPath, "NUMBER_MINIMUM", "Numeric value is below minimum");
        }
        if (
          concrete.maximum !== undefined &&
          compareNormalizedDecimals(normalizedNum, concrete.maximum) > 0
        ) {
          recordDiagnostic(pointerPath, "NUMBER_MAXIMUM", "Numeric value exceeds maximum");
        }
        checkEnumAndConst(val, normalizedNum, concrete, pointerPath);
        return;
      }

      case "array": {
        if (!Array.isArray(val)) {
          recordDiagnostic(
            pointerPath,
            "TYPE_MISMATCH",
            `Expected array, got ${describeJsonValueType(val)}`
          );
          return;
        }
        if (val.length < concrete.minItems) {
          recordDiagnostic(
            pointerPath,
            "ARRAY_MIN_ITEMS",
            `Array length ${val.length} is below minItems ${concrete.minItems}`
          );
        }
        if (val.length > concrete.maxItems) {
          recordDiagnostic(
            pointerPath,
            "ARRAY_MAX_ITEMS",
            `Array length ${val.length} exceeds maxItems ${concrete.maxItems}`
          );
          return;
        }
        for (let i = 0; i < val.length; i += 1) {
          pathTokens.push(String(i));
          evaluateNode(concrete.items, val[i], pathTokens);
          pathTokens.pop();
        }
        return;
      }

      case "object": {
        if (!isPlainObjectRecord(val)) {
          recordDiagnostic(
            pointerPath,
            "TYPE_MISMATCH",
            `Expected object, got ${describeJsonValueType(val)}`
          );
          return;
        }

        for (const reqProp of concrete.required) {
          tickWork();
          if (!Object.prototype.hasOwnProperty.call(val, reqProp)) {
            pathTokens.push(reqProp);
            recordDiagnostic(
              formatJsonPointer(pathTokens),
              "REQUIRED_PROPERTY_MISSING",
              `Missing required property "${reqProp}"`
            );
            pathTokens.pop();
          }
        }

        const actualKeys = Object.keys(val).sort(compareCodeUnits);
        for (const actualKey of actualKeys) {
          tickWork();
          if (!Object.prototype.hasOwnProperty.call(concrete.properties, actualKey)) {
            recordDiagnostic(
              pointerPath,
              "ADDITIONAL_PROPERTY_FORBIDDEN",
              "Unexpected additional property"
            );
            continue;
          }
          pathTokens.push(actualKey);
          evaluateNode(concrete.properties[actualKey]!, val[actualKey], pathTokens);
          pathTokens.pop();
        }
      }
    }
  }

  evaluateNode(schema.normalizedProfile.root, value, []);

  return Object.freeze({
    valid: totalDiagnosticsObserved === 0,
    diagnostics: Object.freeze(diagnostics),
    totalDiagnosticsObserved,
    workUnitsUsed: workUnits
  });
}

export function evaluateEventBytes(
  schema: CompiledEventSchema,
  rawBytes: Uint8Array,
  options?: EventEvaluationOptions
): EventEvaluationResult {
  const parsed = parseEventJsonBytes(rawBytes);
  const evalResult = evaluateParsedEvent(schema, parsed.value, options);
  return Object.freeze({
    ...evalResult,
    byteCount: parsed.byteCount,
    sha256: parsed.sha256
  });
}
