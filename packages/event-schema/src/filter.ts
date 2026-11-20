import {
  LimitExceededDomainError,
  SUBSCRIPTION_MAX_SCHEMA_VERSIONS,
  type Sha256Hex,
  ValidationDomainError,
  computeUtf8ByteLength,
  hasLoneSurrogate
} from "@relayquill/domain";
import { type CanonicalJsonValue, hashCanonicalJson } from "@relayquill/contracts";
import { isLosslessNumber } from "lossless-json";
import {
  type NormalizedDecimal,
  compareNormalizedDecimals,
  equalNormalizedDecimals,
  isNormalizedInteger,
  normalizeLosslessNumber,
  parseNormalizedDecimalObject
} from "./numeric.js";
import {
  type LosslessJsonValue,
  isPlainObjectRecord,
  parseStrictLosslessJson
} from "./parser.js";
import {
  JSON_POINTER_MAX_TOKENS,
  type ParsedJsonPointer,
  parseJsonPointer,
  resolveJsonPointer
} from "./pointer.js";
import {
  type CompiledEventSchema,
  type NormalizedScalarLiteral,
  SCHEMA_MAX_RAW_BYTES,
  normalizeSchemaScalarLiteral,
  resolveSchemaPointer
} from "./profile.js";

export const FILTER_PROFILE_VERSION = "relayquill.filter.v1" as const;
export const FILTER_MAX_LEAVES = 32 as const;
export const FILTER_MAX_BOOLEAN_DEPTH = 4 as const;
export const FILTER_MAX_BOOLEAN_CHILDREN = 16 as const;
export const FILTER_MAX_IN_LIST = 32 as const;
export const FILTER_MAX_PATH_TOKENS = JSON_POINTER_MAX_TOKENS;

export type FilterLeafOperation = "exists" | "eq" | "in" | "lt" | "lte" | "gt" | "gte";
export type FilterBooleanOperation = "all" | "any" | "not";
export type FilterScalarKind = "string" | "boolean" | "number" | "null";

export interface NormalizedFilterBooleanAllAnyNode {
  readonly kind: "boolean";
  readonly operation: "all" | "any";
  readonly children: readonly NormalizedFilterNode[];
}

export interface NormalizedFilterBooleanNotNode {
  readonly kind: "boolean";
  readonly operation: "not";
  readonly child: NormalizedFilterNode;
}

export interface NormalizedFilterExistsLeaf {
  readonly kind: "leaf";
  readonly operation: "exists";
  readonly path: string;
}

export interface NormalizedFilterEqLeaf {
  readonly kind: "leaf";
  readonly operation: "eq";
  readonly path: string;
  readonly value: NormalizedScalarLiteral;
}

export interface NormalizedFilterInLeaf {
  readonly kind: "leaf";
  readonly operation: "in";
  readonly path: string;
  readonly scalarKind: FilterScalarKind;
  readonly values: readonly NormalizedScalarLiteral[];
}

export interface NormalizedFilterNumericCmpLeaf {
  readonly kind: "leaf";
  readonly operation: "lt" | "lte" | "gt" | "gte";
  readonly path: string;
  readonly value: NormalizedDecimal;
}

export type NormalizedFilterLeafNode =
  | NormalizedFilterExistsLeaf
  | NormalizedFilterEqLeaf
  | NormalizedFilterInLeaf
  | NormalizedFilterNumericCmpLeaf;

export type NormalizedFilterNode =
  | NormalizedFilterBooleanAllAnyNode
  | NormalizedFilterBooleanNotNode
  | NormalizedFilterLeafNode;

export interface NormalizedFilterAst {
  readonly profile_version: typeof FILTER_PROFILE_VERSION;
  readonly root: NormalizedFilterNode;
}

type RuntimeFilterLeafNode =
  | { readonly kind: "leaf"; readonly operation: "exists"; readonly pointer: ParsedJsonPointer }
  | {
      readonly kind: "leaf";
      readonly operation: "eq";
      readonly pointer: ParsedJsonPointer;
      readonly value: NormalizedScalarLiteral;
    }
  | {
      readonly kind: "leaf";
      readonly operation: "in";
      readonly pointer: ParsedJsonPointer;
      readonly scalarKind: FilterScalarKind;
      readonly values: readonly NormalizedScalarLiteral[];
    }
  | {
      readonly kind: "leaf";
      readonly operation: "lt" | "lte" | "gt" | "gte";
      readonly pointer: ParsedJsonPointer;
      readonly value: NormalizedDecimal;
    };

type RuntimeFilterNode =
  | {
      readonly kind: "boolean";
      readonly operation: "all" | "any";
      readonly children: readonly RuntimeFilterNode[];
    }
  | {
      readonly kind: "boolean";
      readonly operation: "not";
      readonly child: RuntimeFilterNode;
    }
  | RuntimeFilterLeafNode;

export interface CompiledFilterAst {
  readonly profileVersion: typeof FILTER_PROFILE_VERSION;
  readonly filterAst: NormalizedFilterAst;
  readonly filterSha256: Sha256Hex;
  readonly leafCount: number;
  readonly maxBooleanDepth: number;
  readonly root: RuntimeFilterNode;
}

interface FilterCompileStats {
  leafCount: number;
  maxBooleanDepth: number;
  readonly leaves: RuntimeFilterLeafNode[];
}

const ALL_ANY_KEYS = new Set(["operation", "children", "kind"]);
const NOT_KEYS = new Set(["operation", "child", "kind"]);
const EXISTS_KEYS = new Set(["operation", "path", "kind"]);
const SINGLE_VALUE_LEAF_KEYS = new Set(["operation", "path", "value", "kind"]);
const IN_LEAF_KEYS = new Set(["operation", "path", "values", "scalarKind", "kind"]);

function failFilterValidation(path: string, code: string, message: string): never {
  throw new ValidationDomainError({
    code: "INVALID_VALUE",
    message,
    fieldErrors: [{ path, code }]
  });
}

function failFilterLimit(path: string, message: string): never {
  throw new LimitExceededDomainError({
    code: "SCHEMA_EVALUATION_LIMIT",
    message,
    fieldErrors: [{ path, code: "SCHEMA_EVALUATION_LIMIT" }]
  });
}

function assertAllowedFilterKeys(
  rec: Record<string, unknown>,
  allowed: ReadonlySet<string>,
  fieldPath: string
): void {
  for (const key of Object.keys(rec)) {
    if (!allowed.has(key)) {
      failFilterValidation(
        `${fieldPath}.${key}`,
        "UNSUPPORTED_FILTER_FIELD",
        `Unsupported field "${key}" in filter node at ${fieldPath}`
      );
    }
  }
}

function parseScalarLiteralOrNormalized(
  raw: unknown,
  fieldPath: string
): NormalizedScalarLiteral {
  if (isPlainObjectRecord(raw)) {
    const kind = raw.kind;
    if (kind === "null" && Object.keys(raw).length === 1) {
      return Object.freeze({ kind: "null" });
    }
    if (kind === "boolean" && typeof raw.value === "boolean" && Object.keys(raw).length === 2) {
      return Object.freeze({ kind: "boolean", value: raw.value });
    }
    if (kind === "string" && typeof raw.value === "string" && Object.keys(raw).length === 2) {
      if (hasLoneSurrogate(raw.value)) {
        failFilterValidation(fieldPath, "LONE_SURROGATE", `Lone surrogate at ${fieldPath}`);
      }
      if (computeUtf8ByteLength(raw.value) > 262_144) {
        failFilterLimit(fieldPath, `Filter string literal exceeds 262144 bytes at ${fieldPath}`);
      }
      return Object.freeze({ kind: "string", value: raw.value });
    }
    if (kind === "number" && Object.keys(raw).length === 2) {
      return Object.freeze({
        kind: "number",
        value: parseNormalizedDecimalObject(raw.value, `${fieldPath}.value`)
      });
    }
  }
  return normalizeSchemaScalarLiteral(raw, fieldPath);
}

function compileFilterNode(
  raw: unknown,
  booleanDepth: number,
  fieldPath: string,
  stats: FilterCompileStats
): { readonly normalized: NormalizedFilterNode; readonly runtime: RuntimeFilterNode } {
  if (!isPlainObjectRecord(raw)) {
    failFilterValidation(fieldPath, "INVALID_FILTER_NODE", `Expected filter object at ${fieldPath}`);
  }

  const operation = raw.operation;
  if (typeof operation !== "string") {
    failFilterValidation(
      `${fieldPath}.operation`,
      "MISSING_FILTER_OPERATION",
      `Missing filter operation at ${fieldPath}`
    );
  }

  if (operation === "all" || operation === "any") {
    assertAllowedFilterKeys(raw, ALL_ANY_KEYS, fieldPath);
    if (raw.kind !== undefined && raw.kind !== "boolean") {
      failFilterValidation(`${fieldPath}.kind`, "INVALID_FILTER_KIND", `Expected kind="boolean" at ${fieldPath}`);
    }
    const nextBooleanDepth = booleanDepth + 1;
    if (nextBooleanDepth > FILTER_MAX_BOOLEAN_DEPTH) {
      failFilterLimit(
        fieldPath,
        `Filter boolean nesting depth exceeds maximum ${FILTER_MAX_BOOLEAN_DEPTH}`
      );
    }
    if (nextBooleanDepth > stats.maxBooleanDepth) {
      stats.maxBooleanDepth = nextBooleanDepth;
    }

    if (!Array.isArray(raw.children)) {
      failFilterValidation(
        `${fieldPath}.children`,
        "INVALID_CHILDREN",
        `Expected children array for "${operation}" at ${fieldPath}`
      );
    }
    if (raw.children.length === 0) {
      failFilterValidation(
        `${fieldPath}.children`,
        "EMPTY_BOOLEAN_NODE",
        `Boolean filter "${operation}" requires at least 1 child predicate at ${fieldPath}`
      );
    }
    if (raw.children.length > FILTER_MAX_BOOLEAN_CHILDREN) {
      failFilterLimit(
        `${fieldPath}.children`,
        `Boolean filter "${operation}" exceeds maximum ${FILTER_MAX_BOOLEAN_CHILDREN} children`
      );
    }

    const normChildren: NormalizedFilterNode[] = [];
    const runtimeChildren: RuntimeFilterNode[] = [];
    for (let i = 0; i < raw.children.length; i += 1) {
      const compiledChild = compileFilterNode(
        raw.children[i],
        nextBooleanDepth,
        `${fieldPath}.children[${i}]`,
        stats
      );
      normChildren.push(compiledChild.normalized);
      runtimeChildren.push(compiledChild.runtime);
    }

    return {
      normalized: Object.freeze({
        kind: "boolean",
        operation,
        children: Object.freeze(normChildren)
      }),
      runtime: Object.freeze({
        kind: "boolean",
        operation,
        children: Object.freeze(runtimeChildren)
      })
    };
  }

  if (operation === "not") {
    assertAllowedFilterKeys(raw, NOT_KEYS, fieldPath);
    if (raw.kind !== undefined && raw.kind !== "boolean") {
      failFilterValidation(`${fieldPath}.kind`, "INVALID_FILTER_KIND", `Expected kind="boolean" at ${fieldPath}`);
    }
    const nextBooleanDepth = booleanDepth + 1;
    if (nextBooleanDepth > FILTER_MAX_BOOLEAN_DEPTH) {
      failFilterLimit(
        fieldPath,
        `Filter boolean nesting depth exceeds maximum ${FILTER_MAX_BOOLEAN_DEPTH}`
      );
    }
    if (nextBooleanDepth > stats.maxBooleanDepth) {
      stats.maxBooleanDepth = nextBooleanDepth;
    }
    if (raw.child === undefined) {
      failFilterValidation(
        `${fieldPath}.child`,
        "MISSING_CHILD",
        `Boolean filter "not" requires exactly one child at ${fieldPath}`
      );
    }
    const compiledChild = compileFilterNode(
      raw.child,
      nextBooleanDepth,
      `${fieldPath}.child`,
      stats
    );
    return {
      normalized: Object.freeze({
        kind: "boolean",
        operation: "not",
        child: compiledChild.normalized
      }),
      runtime: Object.freeze({
        kind: "boolean",
        operation: "not",
        child: compiledChild.runtime
      })
    };
  }

  // Leaf nodes
  stats.leafCount += 1;
  if (stats.leafCount > FILTER_MAX_LEAVES) {
    failFilterLimit(fieldPath, `Filter exceeds maximum ${FILTER_MAX_LEAVES} leaf predicates`);
  }
  if (raw.kind !== undefined && raw.kind !== "leaf") {
    failFilterValidation(`${fieldPath}.kind`, "INVALID_FILTER_KIND", `Expected kind="leaf" at ${fieldPath}`);
  }

  const pointer = parseJsonPointer(raw.path, {
    fieldPath: `${fieldPath}.path`,
    minTokens: 1,
    maxTokens: FILTER_MAX_PATH_TOKENS
  });

  if (operation === "exists") {
    assertAllowedFilterKeys(raw, EXISTS_KEYS, fieldPath);
    const leafRuntime: RuntimeFilterLeafNode = Object.freeze({
      kind: "leaf",
      operation: "exists",
      pointer
    });
    stats.leaves.push(leafRuntime);
    return {
      normalized: Object.freeze({
        kind: "leaf",
        operation: "exists",
        path: pointer.raw
      }),
      runtime: leafRuntime
    };
  }

  if (operation === "eq") {
    assertAllowedFilterKeys(raw, SINGLE_VALUE_LEAF_KEYS, fieldPath);
    if (!Object.prototype.hasOwnProperty.call(raw, "value")) {
      failFilterValidation(
        `${fieldPath}.value`,
        "MISSING_LITERAL",
        `Filter operation "eq" requires a scalar value at ${fieldPath}`
      );
    }
    const literal = parseScalarLiteralOrNormalized(raw.value, `${fieldPath}.value`);
    const leafRuntime: RuntimeFilterLeafNode = Object.freeze({
      kind: "leaf",
      operation: "eq",
      pointer,
      value: literal
    });
    stats.leaves.push(leafRuntime);
    return {
      normalized: Object.freeze({
        kind: "leaf",
        operation: "eq",
        path: pointer.raw,
        value: literal
      }),
      runtime: leafRuntime
    };
  }

  if (operation === "in") {
    assertAllowedFilterKeys(raw, IN_LEAF_KEYS, fieldPath);
    if (!Array.isArray(raw.values)) {
      failFilterValidation(
        `${fieldPath}.values`,
        "INVALID_IN_LIST",
        `Filter operation "in" requires a values array at ${fieldPath}`
      );
    }
    if (raw.values.length === 0) {
      failFilterValidation(
        `${fieldPath}.values`,
        "EMPTY_IN_LIST",
        `Filter operation "in" requires at least 1 literal at ${fieldPath}`
      );
    }
    if (raw.values.length > FILTER_MAX_IN_LIST) {
      failFilterLimit(
        `${fieldPath}.values`,
        `Filter operation "in" exceeds maximum ${FILTER_MAX_IN_LIST} literals`
      );
    }

    const normalizedValues: NormalizedScalarLiteral[] = [];
    let expectedScalarKind: FilterScalarKind | undefined;
    for (let i = 0; i < raw.values.length; i += 1) {
      const lit = parseScalarLiteralOrNormalized(raw.values[i], `${fieldPath}.values[${i}]`);
      if (expectedScalarKind === undefined) {
        expectedScalarKind = lit.kind;
      } else if (lit.kind !== expectedScalarKind) {
        failFilterValidation(
          `${fieldPath}.values[${i}]`,
          "MIXED_IN_LIST_TYPES",
          `Filter operation "in" requires all literals to have the same scalar type at ${fieldPath}`
        );
      }
      normalizedValues.push(lit);
    }
    const scalarKind = expectedScalarKind!;
    if (raw.scalarKind !== undefined && raw.scalarKind !== scalarKind) {
      failFilterValidation(
        `${fieldPath}.scalarKind`,
        "INVALID_SCALAR_KIND",
        `scalarKind mismatch in filter "in" leaf at ${fieldPath}`
      );
    }

    const frozenValues = Object.freeze(normalizedValues);
    const leafRuntime: RuntimeFilterLeafNode = Object.freeze({
      kind: "leaf",
      operation: "in",
      pointer,
      scalarKind,
      values: frozenValues
    });
    stats.leaves.push(leafRuntime);
    return {
      normalized: Object.freeze({
        kind: "leaf",
        operation: "in",
        path: pointer.raw,
        scalarKind,
        values: frozenValues
      }),
      runtime: leafRuntime
    };
  }

  if (operation === "lt" || operation === "lte" || operation === "gt" || operation === "gte") {
    assertAllowedFilterKeys(raw, SINGLE_VALUE_LEAF_KEYS, fieldPath);
    if (!Object.prototype.hasOwnProperty.call(raw, "value")) {
      failFilterValidation(
        `${fieldPath}.value`,
        "MISSING_LITERAL",
        `Numeric comparison "${operation}" requires a numeric value at ${fieldPath}`
      );
    }
    let numericValue: NormalizedDecimal;
    if (isPlainObjectRecord(raw.value)) {
      numericValue = parseNormalizedDecimalObject(raw.value, `${fieldPath}.value`);
    } else if (isLosslessNumber(raw.value) || typeof raw.value === "number") {
      numericValue = normalizeLosslessNumber(raw.value, `${fieldPath}.value`);
    } else {
      failFilterValidation(
        `${fieldPath}.value`,
        "EXPECTED_NUMERIC_LITERAL",
        `Numeric comparison "${operation}" requires a numeric literal at ${fieldPath}`
      );
    }
    const leafRuntime: RuntimeFilterLeafNode = Object.freeze({
      kind: "leaf",
      operation,
      pointer,
      value: numericValue
    });
    stats.leaves.push(leafRuntime);
    return {
      normalized: Object.freeze({
        kind: "leaf",
        operation,
        path: pointer.raw,
        value: numericValue
      }),
      runtime: leafRuntime
    };
  }

  failFilterValidation(
    `${fieldPath}.operation`,
    "UNSUPPORTED_FILTER_OPERATION",
    `Unsupported filter operation "${operation}" at ${fieldPath}`
  );
}

function validateLeafAgainstSchema(
  leaf: RuntimeFilterLeafNode,
  schema: CompiledEventSchema,
  schemaIndex: number
): void {
  const resolved = resolveSchemaPointer(schema, leaf.pointer);
  const node = resolved.node;

  if (leaf.operation === "exists") {
    return;
  }

  if (node.kind === "object" || node.kind === "array") {
    failFilterValidation(
      leaf.pointer.raw,
      "UNSUPPORTED_FILTER_TARGET_TYPE",
      `Filter operation "${leaf.operation}" is unsupported on ${node.kind} path "${leaf.pointer.raw}" (schema[${schemaIndex}])`
    );
  }

  if (leaf.operation === "lt" || leaf.operation === "lte" || leaf.operation === "gt" || leaf.operation === "gte") {
    if (node.kind !== "integer" && node.kind !== "number") {
      failFilterValidation(
        leaf.pointer.raw,
        "FILTER_TYPE_MISMATCH",
        `Numeric filter "${leaf.operation}" requires numeric schema field at "${leaf.pointer.raw}" (schema[${schemaIndex}], got ${node.kind})`
      );
    }
    return;
  }

  const checkLiteralType = (lit: NormalizedScalarLiteral): void => {
    if (lit.kind === "null") {
      if (node.kind !== "null" && !node.nullable) {
        failFilterValidation(
          leaf.pointer.raw,
          "FILTER_TYPE_MISMATCH",
          `Null literal is invalid for non-nullable ${node.kind} at "${leaf.pointer.raw}" (schema[${schemaIndex}])`
        );
      }
      return;
    }
    if (node.kind === "null") {
      failFilterValidation(
        leaf.pointer.raw,
        "FILTER_TYPE_MISMATCH",
        `Non-null literal is invalid for null schema at "${leaf.pointer.raw}" (schema[${schemaIndex}])`
      );
    }
    if (lit.kind === "string" && node.kind !== "string") {
      failFilterValidation(
        leaf.pointer.raw,
        "FILTER_TYPE_MISMATCH",
        `String literal is invalid for ${node.kind} at "${leaf.pointer.raw}" (schema[${schemaIndex}])`
      );
    }
    if (lit.kind === "boolean" && node.kind !== "boolean") {
      failFilterValidation(
        leaf.pointer.raw,
        "FILTER_TYPE_MISMATCH",
        `Boolean literal is invalid for ${node.kind} at "${leaf.pointer.raw}" (schema[${schemaIndex}])`
      );
    }
    if (lit.kind === "number") {
      if (node.kind !== "number" && node.kind !== "integer") {
        failFilterValidation(
          leaf.pointer.raw,
          "FILTER_TYPE_MISMATCH",
          `Numeric literal is invalid for ${node.kind} at "${leaf.pointer.raw}" (schema[${schemaIndex}])`
        );
      }
      if (node.kind === "integer" && !isNormalizedInteger(lit.value)) {
        failFilterValidation(
          leaf.pointer.raw,
          "FILTER_TYPE_MISMATCH",
          `Non-integer numeric literal is invalid for integer field at "${leaf.pointer.raw}" (schema[${schemaIndex}])`
        );
      }
    }
  };

  if (leaf.operation === "eq") {
    checkLiteralType(leaf.value);
    return;
  }

  if (leaf.operation === "in") {
    for (const val of leaf.values) {
      checkLiteralType(val);
    }
  }
}

export function validateFilterAgainstSchemas(
  filter: CompiledFilterAst,
  schemas: readonly CompiledEventSchema[]
): void {
  if (schemas.length === 0 || schemas.length > SUBSCRIPTION_MAX_SCHEMA_VERSIONS) {
    failFilterValidation(
      "schemas",
      "INVALID_SCHEMA_SELECTION",
      `Filter validation requires 1..${SUBSCRIPTION_MAX_SCHEMA_VERSIONS} selected schemas`
    );
  }

  const leaves: RuntimeFilterLeafNode[] = [];
  const stack: RuntimeFilterNode[] = [filter.root];
  while (stack.length > 0) {
    const current = stack.pop()!;
    if (current.kind === "leaf") {
      leaves.push(current);
    } else if (current.operation === "not") {
      stack.push(current.child);
    } else {
      for (const child of current.children) {
        stack.push(child);
      }
    }
  }

  for (let i = 0; i < schemas.length; i += 1) {
    const schema = schemas[i]!;
    for (const leaf of leaves) {
      validateLeafAgainstSchema(leaf, schema, i);
    }
  }
}

export function compileFilterAst(
  input: unknown,
  schemas?: readonly CompiledEventSchema[],
  options?: { readonly fieldPath?: string | undefined }
): CompiledFilterAst {
  const fieldPath = options?.fieldPath ?? "filter";

  let rawObj: unknown = input;
  if (input instanceof Uint8Array || typeof input === "string") {
    rawObj = parseStrictLosslessJson(input, {
      fieldPath,
      minDecodedBytes: 2,
      maxDecodedBytes: SCHEMA_MAX_RAW_BYTES,
      maxDepth: 32,
      maxNodes: 2_048,
      requireObjectRoot: true
    }).value;
  }

  if (!isPlainObjectRecord(rawObj)) {
    failFilterValidation(fieldPath, "INVALID_FILTER", `Expected filter object at ${fieldPath}`);
  }

  let rootInput: unknown = rawObj;
  if (Object.prototype.hasOwnProperty.call(rawObj, "profile_version")) {
    for (const key of Object.keys(rawObj)) {
      if (key !== "profile_version" && key !== "root") {
        failFilterValidation(
          `${fieldPath}.${key}`,
          "UNSUPPORTED_FILTER_FIELD",
          `Unsupported top-level filter envelope field "${key}"`
        );
      }
    }
    if (rawObj.profile_version !== FILTER_PROFILE_VERSION) {
      throw new ValidationDomainError({
        code: "UNSUPPORTED_SCHEMA_VERSION",
        message: `Unsupported filter profile_version; expected ${FILTER_PROFILE_VERSION}`,
        fieldErrors: [{ path: `${fieldPath}.profile_version`, code: "UNSUPPORTED_SCHEMA_VERSION" }]
      });
    }
    rootInput = rawObj.root;
  }

  const stats: FilterCompileStats = {
    leafCount: 0,
    maxBooleanDepth: 0,
    leaves: []
  };

  const compiled = compileFilterNode(rootInput, 0, fieldPath, stats);
  const filterAst: NormalizedFilterAst = Object.freeze({
    profile_version: FILTER_PROFILE_VERSION,
    root: compiled.normalized
  });

  const hashed = hashCanonicalJson(filterAst as unknown as CanonicalJsonValue, fieldPath);

  const result: CompiledFilterAst = Object.freeze({
    profileVersion: FILTER_PROFILE_VERSION,
    filterAst,
    filterSha256: hashed.sha256,
    leafCount: stats.leafCount,
    maxBooleanDepth: stats.maxBooleanDepth,
    root: compiled.runtime
  });

  if (schemas !== undefined) {
    validateFilterAgainstSchemas(result, schemas);
  }

  return result;
}

function matchesScalarValue(actual: unknown, literal: NormalizedScalarLiteral): boolean {
  switch (literal.kind) {
    case "null":
      return actual === null;
    case "boolean":
      return actual === literal.value;
    case "string":
      return typeof actual === "string" && actual === literal.value;
    case "number": {
      if (!isLosslessNumber(actual) && typeof actual !== "number") {
        return false;
      }
      const normalizedActual = normalizeLosslessNumber(actual, "filter.actual");
      return equalNormalizedDecimals(normalizedActual, literal.value);
    }
  }
}

function evaluateFilterNode(node: RuntimeFilterNode, eventValue: LosslessJsonValue): boolean {
  if (node.kind === "boolean") {
    if (node.operation === "not") {
      return !evaluateFilterNode(node.child, eventValue);
    }
    if (node.operation === "all") {
      let matched = true;
      for (const child of node.children) {
        if (!evaluateFilterNode(child, eventValue)) {
          matched = false;
        }
      }
      return matched;
    }
    let matched = false;
    for (const child of node.children) {
      if (evaluateFilterNode(child, eventValue)) {
        matched = true;
      }
    }
    return matched;
  }

  const resolution = resolveJsonPointer(eventValue, node.pointer);
  if (node.operation === "exists") {
    return resolution.present;
  }

  if (!resolution.present) {
    return false;
  }

  const actual = resolution.value;

  if (node.operation === "eq") {
    return matchesScalarValue(actual, node.value);
  }

  if (node.operation === "in") {
    for (const candidate of node.values) {
      if (matchesScalarValue(actual, candidate)) {
        return true;
      }
    }
    return false;
  }

  // lt, lte, gt, gte
  if (actual === null || (!isLosslessNumber(actual) && typeof actual !== "number")) {
    return false;
  }
  const normalizedActual = normalizeLosslessNumber(actual, node.pointer.raw);
  const cmp = compareNormalizedDecimals(normalizedActual, node.value);
  switch (node.operation) {
    case "lt":
      return cmp < 0;
    case "lte":
      return cmp <= 0;
    case "gt":
      return cmp > 0;
    case "gte":
      return cmp >= 0;
  }
}

export function evaluateFilter(
  filter: CompiledFilterAst | null,
  eventValue: LosslessJsonValue
): boolean {
  if (filter === null) {
    return true;
  }
  return evaluateFilterNode(filter.root, eventValue);
}
