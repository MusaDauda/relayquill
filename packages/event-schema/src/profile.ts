import {
  EVENT_MAX_CONTENT_BYTES,
  EVENT_MAX_JSON_NODES,
  LimitExceededDomainError,
  type SchemaCompatibilityPolicy,
  type Sha256Hex,
  ValidationDomainError,
  computeUtf8ByteLength,
  hasLoneSurrogate
} from "@relayquill/domain";
import {
  encodeUtf8Bytes,
  sha256Hex
} from "@relayquill/contracts";
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
  isPlainObjectRecord,
  parseStrictLosslessJson,
  serializeStrictJsonString
} from "./parser.js";
import { decodeJsonPointerToken, type ParsedJsonPointer } from "./pointer.js";

export const EVENT_SCHEMA_DIALECT_2020_12 =
  "https://json-schema.org/draft/2020-12/schema" as const;
export const EVENT_SCHEMA_PROFILE_V1 = "relayquill.event-schema.v1" as const;

export const SCHEMA_MAX_RAW_BYTES = 65_536 as const;
export const SCHEMA_MAX_NORMALIZED_NODES = 2_048 as const;
export const SCHEMA_MAX_DEPTH = 16 as const;
export const SCHEMA_MAX_OBJECT_PROPERTIES = 128 as const;
export const SCHEMA_MAX_ENUM_VALUES = 64 as const;
export const SCHEMA_MAX_DEFS = 32 as const;
export const SCHEMA_MAX_REF_EDGES = 64 as const;
export const SCHEMA_MAX_DIAGNOSTICS = 20 as const;
export const SCHEMA_MAX_TITLE_BYTES = 256 as const;
export const SCHEMA_MAX_DESCRIPTION_BYTES = 2_048 as const;
export const SCHEMA_MAX_DEF_NAME_BYTES = 128 as const;

export const SCHEMA_PRIMITIVE_TYPES = [
  "object",
  "array",
  "string",
  "boolean",
  "null",
  "integer",
  "number"
] as const;
export type SchemaPrimitiveType = (typeof SCHEMA_PRIMITIVE_TYPES)[number];

export const SCHEMA_NON_NULL_TYPES = [
  "object",
  "array",
  "string",
  "boolean",
  "integer",
  "number"
] as const;
export type SchemaNonNullType = (typeof SCHEMA_NON_NULL_TYPES)[number];

const PRIMITIVE_TYPE_SET = new Set<string>(SCHEMA_PRIMITIVE_TYPES);
const NON_NULL_TYPE_SET = new Set<string>(SCHEMA_NON_NULL_TYPES);

export type NormalizedScalarLiteral =
  | { readonly kind: "string"; readonly value: string }
  | { readonly kind: "boolean"; readonly value: boolean }
  | { readonly kind: "null" }
  | { readonly kind: "number"; readonly value: NormalizedDecimal };

interface SchemaNodeBase {
  readonly title?: string | undefined;
  readonly description?: string | undefined;
}

export interface NormalizedObjectSchemaNode extends SchemaNodeBase {
  readonly kind: "object";
  readonly nullable: boolean;
  readonly properties: Readonly<Record<string, NormalizedSchemaNode>>;
  readonly required: readonly string[];
  readonly additionalProperties: false;
}

export interface NormalizedArraySchemaNode extends SchemaNodeBase {
  readonly kind: "array";
  readonly nullable: boolean;
  readonly items: NormalizedSchemaNode;
  readonly minItems: number;
  readonly maxItems: number;
}

export interface NormalizedStringSchemaNode extends SchemaNodeBase {
  readonly kind: "string";
  readonly nullable: boolean;
  readonly minLength: number;
  readonly maxLength: number;
  readonly enum?: readonly NormalizedScalarLiteral[] | undefined;
  readonly const?: NormalizedScalarLiteral | undefined;
}

export interface NormalizedNumericSchemaNode extends SchemaNodeBase {
  readonly kind: "integer" | "number";
  readonly nullable: boolean;
  readonly minimum?: NormalizedDecimal | undefined;
  readonly maximum?: NormalizedDecimal | undefined;
  readonly enum?: readonly NormalizedScalarLiteral[] | undefined;
  readonly const?: NormalizedScalarLiteral | undefined;
}

export interface NormalizedBooleanSchemaNode extends SchemaNodeBase {
  readonly kind: "boolean";
  readonly nullable: boolean;
  readonly enum?: readonly NormalizedScalarLiteral[] | undefined;
  readonly const?: NormalizedScalarLiteral | undefined;
}

export interface NormalizedNullSchemaNode extends SchemaNodeBase {
  readonly kind: "null";
  readonly nullable: false;
  readonly enum?: readonly NormalizedScalarLiteral[] | undefined;
  readonly const?: NormalizedScalarLiteral | undefined;
}

export interface NormalizedRefSchemaNode extends SchemaNodeBase {
  readonly kind: "ref";
  readonly ref: string;
  readonly targetName: string;
}

export type NormalizedConcreteSchemaNode =
  | NormalizedObjectSchemaNode
  | NormalizedArraySchemaNode
  | NormalizedStringSchemaNode
  | NormalizedNumericSchemaNode
  | NormalizedBooleanSchemaNode
  | NormalizedNullSchemaNode;

export type NormalizedSchemaNode = NormalizedConcreteSchemaNode | NormalizedRefSchemaNode;

export interface NormalizedEventSchemaProfile {
  readonly profile_version: typeof EVENT_SCHEMA_PROFILE_V1;
  readonly dialect: typeof EVENT_SCHEMA_DIALECT_2020_12;
  readonly root: NormalizedConcreteSchemaNode;
  readonly defs: Readonly<Record<string, NormalizedSchemaNode>>;
}

export interface CompiledEventSchema {
  readonly profileVersion: typeof EVENT_SCHEMA_PROFILE_V1;
  readonly dialect: typeof EVENT_SCHEMA_DIALECT_2020_12;
  readonly definitionSha256: Sha256Hex;
  readonly profileSha256: Sha256Hex;
  readonly rawByteCount: number;
  readonly normalizedNodeCount: number;
  readonly refEdgeCount: number;
  readonly maxExpandedDepth: number;
  readonly normalizedProfile: NormalizedEventSchemaProfile;
}

export interface ResolvedSchemaPointer {
  readonly node: NormalizedConcreteSchemaNode;
  readonly alwaysRequired: boolean;
}

export interface SchemaCompatibilityCheckResult {
  readonly compatible: boolean;
  readonly recommendedPolicy: SchemaCompatibilityPolicy;
  readonly reasons: readonly string[];
}

const OBJECT_KEYWORDS = new Set([
  "$schema",
  "$defs",
  "type",
  "properties",
  "required",
  "additionalProperties",
  "title",
  "description"
]);
const ARRAY_KEYWORDS = new Set([
  "$schema",
  "$defs",
  "type",
  "items",
  "minItems",
  "maxItems",
  "title",
  "description"
]);
const STRING_KEYWORDS = new Set([
  "$schema",
  "$defs",
  "type",
  "minLength",
  "maxLength",
  "enum",
  "const",
  "title",
  "description"
]);
const NUMERIC_KEYWORDS = new Set([
  "$schema",
  "$defs",
  "type",
  "minimum",
  "maximum",
  "enum",
  "const",
  "title",
  "description"
]);
const BOOLEAN_NULL_KEYWORDS = new Set([
  "$schema",
  "$defs",
  "type",
  "enum",
  "const",
  "title",
  "description"
]);
const REF_KEYWORDS = new Set(["$ref", "title", "description"]);

function failSchemaValidation(path: string, code: string, message: string): never {
  throw new ValidationDomainError({
    code: "INVALID_VALUE",
    message,
    fieldErrors: [{ path, code }]
  });
}

function failSchemaLimit(path: string, message: string): never {
  throw new LimitExceededDomainError({
    code: "SCHEMA_EVALUATION_LIMIT",
    message,
    fieldErrors: [{ path, code: "SCHEMA_EVALUATION_LIMIT" }]
  });
}

function compareCodeUnits(a: string, b: string): number {
  if (a === b) {
    return 0;
  }
  return a < b ? -1 : 1;
}

function parseBoundedAnnotation(
  value: unknown,
  maxBytes: number,
  fieldPath: string
): string {
  if (typeof value !== "string" || hasLoneSurrogate(value)) {
    failSchemaValidation(fieldPath, "INVALID_ANNOTATION", `Invalid annotation string at ${fieldPath}`);
  }
  const len = computeUtf8ByteLength(value);
  if (len > maxBytes) {
    failSchemaLimit(fieldPath, `Annotation exceeds ${maxBytes} UTF-8 bytes at ${fieldPath}`);
  }
  return value;
}

function parseNonNegBoundedInt(
  value: unknown,
  max: number,
  fieldPath: string
): number {
  let num: number;
  if (isLosslessNumber(value)) {
    const dec = normalizeLosslessNumber(value, fieldPath);
    if (!isNormalizedInteger(dec) || dec.sign < 0) {
      failSchemaValidation(fieldPath, "INVALID_BOUND", `Expected non-negative integer at ${fieldPath}`);
    }
    const parsedBig = BigInt(dec.coefficient) * 10n ** BigInt(dec.exponent);
    if (parsedBig > BigInt(max)) {
      failSchemaLimit(fieldPath, `Integer bound exceeds ${max} at ${fieldPath}`);
    }
    num = Number(parsedBig);
  } else if (typeof value === "number") {
    if (!Number.isInteger(value) || !Number.isSafeInteger(value) || value < 0) {
      failSchemaValidation(fieldPath, "INVALID_BOUND", `Expected non-negative integer at ${fieldPath}`);
    }
    if (value > max) {
      failSchemaLimit(fieldPath, `Integer bound exceeds ${max} at ${fieldPath}`);
    }
    num = value;
  } else {
    failSchemaValidation(fieldPath, "INVALID_BOUND", `Expected non-negative integer at ${fieldPath}`);
  }
  return num;
}

function parseSchemaTypeDecl(
  rawType: unknown,
  isRoot: boolean,
  fieldPath: string
): { readonly baseType: SchemaPrimitiveType; readonly nullable: boolean } {
  if (typeof rawType === "string") {
    if (!PRIMITIVE_TYPE_SET.has(rawType)) {
      failSchemaValidation(
        `${fieldPath}.type`,
        "UNSUPPORTED_TYPE",
        `Unsupported schema type "${rawType}" at ${fieldPath}.type`
      );
    }
    return { baseType: rawType as SchemaPrimitiveType, nullable: false };
  }

  if (Array.isArray(rawType)) {
    if (isRoot) {
      failSchemaValidation(
        `${fieldPath}.type`,
        "ROOT_UNION_FORBIDDEN",
        "Root schema must declare a single concrete primitive type"
      );
    }
    if (
      rawType.length !== 2 ||
      typeof rawType[0] !== "string" ||
      !NON_NULL_TYPE_SET.has(rawType[0]) ||
      rawType[1] !== "null"
    ) {
      failSchemaValidation(
        `${fieldPath}.type`,
        "UNSUPPORTED_TYPE_UNION",
        `Type unions must use exact [nonNullType, "null"] form at ${fieldPath}.type`
      );
    }
    return { baseType: rawType[0] as SchemaNonNullType, nullable: true };
  }

  failSchemaValidation(`${fieldPath}.type`, "MISSING_TYPE", `Missing or invalid "type" at ${fieldPath}`);
}

export function scalarLiteralEquals(
  a: NormalizedScalarLiteral,
  b: NormalizedScalarLiteral
): boolean {
  if (a.kind !== b.kind) {
    return false;
  }
  switch (a.kind) {
    case "null":
      return true;
    case "boolean":
      return a.value === (b as { readonly kind: "boolean"; readonly value: boolean }).value;
    case "string":
      return a.value === (b as { readonly kind: "string"; readonly value: string }).value;
    case "number":
      return equalNormalizedDecimals(
        a.value,
        (b as { readonly kind: "number"; readonly value: NormalizedDecimal }).value
      );
  }
}

export function normalizeSchemaScalarLiteral(
  rawValue: unknown,
  fieldPath: string
): NormalizedScalarLiteral {
  if (rawValue === null) {
    return Object.freeze({ kind: "null" });
  }
  if (typeof rawValue === "boolean") {
    return Object.freeze({ kind: "boolean", value: rawValue });
  }
  if (typeof rawValue === "string") {
    if (hasLoneSurrogate(rawValue)) {
      failSchemaValidation(fieldPath, "LONE_SURROGATE", `Lone surrogate disallowed at ${fieldPath}`);
    }
    if (computeUtf8ByteLength(rawValue) > EVENT_MAX_CONTENT_BYTES) {
      failSchemaLimit(fieldPath, `Scalar string literal exceeds ${EVENT_MAX_CONTENT_BYTES} bytes at ${fieldPath}`);
    }
    return Object.freeze({ kind: "string", value: rawValue });
  }
  if (isLosslessNumber(rawValue) || typeof rawValue === "number") {
    return Object.freeze({
      kind: "number",
      value: normalizeLosslessNumber(rawValue, fieldPath)
    });
  }
  failSchemaValidation(
    fieldPath,
    "UNSUPPORTED_LITERAL",
    `Enum/const values must be bounded scalar literals at ${fieldPath}`
  );
}

function validateScalarLiteralAgainstNode(
  literal: NormalizedScalarLiteral,
  node: NormalizedConcreteSchemaNode,
  fieldPath: string
): void {
  if (literal.kind === "null") {
    if (node.kind === "null" || node.nullable) {
      return;
    }
    failSchemaValidation(fieldPath, "TYPE_MISMATCH", `Null literal is invalid for non-nullable ${node.kind} at ${fieldPath}`);
  }

  switch (node.kind) {
    case "null":
      failSchemaValidation(fieldPath, "TYPE_MISMATCH", `Expected null literal at ${fieldPath}`);
      break;
    case "boolean":
      if (literal.kind !== "boolean") {
        failSchemaValidation(fieldPath, "TYPE_MISMATCH", `Expected boolean literal at ${fieldPath}`);
      }
      return;
    case "string": {
      if (literal.kind !== "string") {
        failSchemaValidation(fieldPath, "TYPE_MISMATCH", `Expected string literal at ${fieldPath}`);
      }
      let len = 0;
      for (let i = 0; i < literal.value.length; i += 1) {
        const code = literal.value.charCodeAt(i);
        if (code >= 0xd800 && code <= 0xdbff) {
          i += 1;
        }
        len += 1;
      }
      if (len < node.minLength || len > node.maxLength) {
        failSchemaValidation(
          fieldPath,
          "STRING_LENGTH_OUT_OF_BOUNDS",
          `Literal length ${len} outside [${node.minLength}, ${node.maxLength}] at ${fieldPath}`
        );
      }
      return;
    }
    case "integer":
    case "number": {
      if (literal.kind !== "number") {
        failSchemaValidation(fieldPath, "TYPE_MISMATCH", `Expected numeric literal at ${fieldPath}`);
      }
      if (node.kind === "integer" && !isNormalizedInteger(literal.value)) {
        failSchemaValidation(fieldPath, "EXPECTED_INTEGER", `Expected integer literal at ${fieldPath}`);
      }
      if (node.minimum !== undefined && compareNormalizedDecimals(literal.value, node.minimum) < 0) {
        failSchemaValidation(fieldPath, "BELOW_MINIMUM", `Literal is below minimum at ${fieldPath}`);
      }
      if (node.maximum !== undefined && compareNormalizedDecimals(literal.value, node.maximum) > 0) {
        failSchemaValidation(fieldPath, "ABOVE_MAXIMUM", `Literal exceeds maximum at ${fieldPath}`);
      }
      return;
    }
    case "object":
    case "array":
      failSchemaValidation(
        fieldPath,
        "UNSUPPORTED_ENUM_CONST",
        `enum/const is only supported on scalar schema types at ${fieldPath}`
      );
  }
}

function parseLocalDefRef(refValue: unknown, defs: ReadonlySet<string>, fieldPath: string): string {
  if (typeof refValue !== "string" || hasLoneSurrogate(refValue)) {
    failSchemaValidation(fieldPath, "INVALID_REF", `Invalid $ref value at ${fieldPath}`);
  }
  const prefix = "#/$defs/";
  if (!refValue.startsWith(prefix)) {
    failSchemaValidation(
      fieldPath,
      "EXTERNAL_REF_FORBIDDEN",
      `Only local #/$defs/<name> references are permitted at ${fieldPath}`
    );
  }
  const rawSegment = refValue.slice(prefix.length);
  if (rawSegment.length === 0 || rawSegment.includes("/")) {
    failSchemaValidation(
      fieldPath,
      "INVALID_REF",
      `Local $ref must point directly to #/$defs/<name> at ${fieldPath}`
    );
  }
  const defName = decodeJsonPointerToken(rawSegment, fieldPath);
  if (!defs.has(defName)) {
    failSchemaValidation(
      fieldPath,
      "UNRESOLVED_REF",
      `Referenced definition "${defName}" does not exist in $defs at ${fieldPath}`
    );
  }
  return defName;
}

interface CompileContext {
  nodeCount: number;
  refEdgeCount: number;
  readonly defNames: ReadonlySet<string>;
}

function compileSchemaNode(
  rawNode: unknown,
  isRoot: boolean,
  fieldPath: string,
  ctx: CompileContext
): NormalizedSchemaNode {
  if (!isPlainObjectRecord(rawNode)) {
    failSchemaValidation(fieldPath, "INVALID_SCHEMA_NODE", `Expected schema object at ${fieldPath}`);
  }

  ctx.nodeCount += 1;
  if (ctx.nodeCount > SCHEMA_MAX_NORMALIZED_NODES) {
    failSchemaLimit(
      fieldPath,
      `Schema normalized node count exceeds ${SCHEMA_MAX_NORMALIZED_NODES}`
    );
  }

  const keys = Object.keys(rawNode);

  if (Object.prototype.hasOwnProperty.call(rawNode, "$schema")) {
    if (!isRoot) {
      failSchemaValidation(
        `${fieldPath}.$schema`,
        "NESTED_DIALECT_FORBIDDEN",
        `$schema is only permitted on the root schema object`
      );
    }
    if (rawNode.$schema !== EVENT_SCHEMA_DIALECT_2020_12) {
      throw new ValidationDomainError({
        code: "UNSUPPORTED_SCHEMA_VERSION",
        message: `Unsupported schema dialect; expected ${EVENT_SCHEMA_DIALECT_2020_12}`,
        fieldErrors: [{ path: `${fieldPath}.$schema`, code: "UNSUPPORTED_SCHEMA_VERSION" }]
      });
    }
  }

  if (Object.prototype.hasOwnProperty.call(rawNode, "$defs") && !isRoot) {
    failSchemaValidation(
      `${fieldPath}.$defs`,
      "NESTED_DEFS_FORBIDDEN",
      `$defs must be declared only on the root schema object`
    );
  }

  if (Object.prototype.hasOwnProperty.call(rawNode, "$ref")) {
    if (isRoot) {
      failSchemaValidation(
        `${fieldPath}.$ref`,
        "ROOT_REF_FORBIDDEN",
        "Root schema must declare a concrete root type rather than $ref"
      );
    }
    for (const key of keys) {
      if (!REF_KEYWORDS.has(key)) {
        failSchemaValidation(
          `${fieldPath}.${key}`,
          "REF_SIBLING_KEYWORD_FORBIDDEN",
          `A $ref node cannot include validation sibling keyword "${key}" at ${fieldPath}`
        );
      }
    }
    ctx.refEdgeCount += 1;
    if (ctx.refEdgeCount > SCHEMA_MAX_REF_EDGES) {
      failSchemaLimit(
        fieldPath,
        `Schema reference graph exceeds maximum ${SCHEMA_MAX_REF_EDGES} edges`
      );
    }
    const targetName = parseLocalDefRef(rawNode.$ref, ctx.defNames, `${fieldPath}.$ref`);
    const title =
      rawNode.title !== undefined
        ? parseBoundedAnnotation(rawNode.title, SCHEMA_MAX_TITLE_BYTES, `${fieldPath}.title`)
        : undefined;
    const description =
      rawNode.description !== undefined
        ? parseBoundedAnnotation(
            rawNode.description,
            SCHEMA_MAX_DESCRIPTION_BYTES,
            `${fieldPath}.description`
          )
        : undefined;
    return Object.freeze({
      kind: "ref",
      ref: rawNode.$ref as string,
      targetName,
      ...(title !== undefined ? { title } : {}),
      ...(description !== undefined ? { description } : {})
    });
  }

  const { baseType, nullable } = parseSchemaTypeDecl(rawNode.type, isRoot, fieldPath);
  const allowedKeywords =
    baseType === "object"
      ? OBJECT_KEYWORDS
      : baseType === "array"
        ? ARRAY_KEYWORDS
        : baseType === "string"
          ? STRING_KEYWORDS
          : baseType === "integer" || baseType === "number"
            ? NUMERIC_KEYWORDS
            : BOOLEAN_NULL_KEYWORDS;

  for (const key of keys) {
    if (!allowedKeywords.has(key)) {
      failSchemaValidation(
        `${fieldPath}.${key}`,
        "UNSUPPORTED_KEYWORD",
        `Unsupported or disallowed schema keyword "${key}" for type "${baseType}" at ${fieldPath}`
      );
    }
  }

  const title =
    rawNode.title !== undefined
      ? parseBoundedAnnotation(rawNode.title, SCHEMA_MAX_TITLE_BYTES, `${fieldPath}.title`)
      : undefined;
  const description =
    rawNode.description !== undefined
      ? parseBoundedAnnotation(
          rawNode.description,
          SCHEMA_MAX_DESCRIPTION_BYTES,
          `${fieldPath}.description`
        )
      : undefined;
  const annotations: SchemaNodeBase = {
    ...(title !== undefined ? { title } : {}),
    ...(description !== undefined ? { description } : {})
  };

  if (baseType === "object") {
    if (rawNode.additionalProperties !== false) {
      failSchemaValidation(
        `${fieldPath}.additionalProperties`,
        "ADDITIONAL_PROPERTIES_MUST_BE_FALSE",
        `Object schema must declare additionalProperties=false at ${fieldPath}`
      );
    }
    if (!isPlainObjectRecord(rawNode.properties)) {
      failSchemaValidation(
        `${fieldPath}.properties`,
        "MISSING_PROPERTIES",
        `Object schema must declare a properties object at ${fieldPath}`
      );
    }
    const rawProps = rawNode.properties;
    const propNames = Object.keys(rawProps).sort(compareCodeUnits);
    if (propNames.length > SCHEMA_MAX_OBJECT_PROPERTIES) {
      failSchemaLimit(
        `${fieldPath}.properties`,
        `Object schema exceeds maximum ${SCHEMA_MAX_OBJECT_PROPERTIES} properties`
      );
    }

    const compiledProps: Record<string, NormalizedSchemaNode> = {};
    for (const propName of propNames) {
      if (hasLoneSurrogate(propName)) {
        failSchemaValidation(
          `${fieldPath}.properties`,
          "LONE_SURROGATE",
          `Property name contains lone surrogate at ${fieldPath}`
        );
      }
      if (computeUtf8ByteLength(propName) > 256) {
        failSchemaLimit(
          `${fieldPath}.properties`,
          `Property name exceeds 256 UTF-8 bytes at ${fieldPath}`
        );
      }
      compiledProps[propName] = compileSchemaNode(
        rawProps[propName],
        false,
        `${fieldPath}.properties.${propName}`,
        ctx
      );
    }

    const requiredList: string[] = [];
    if (rawNode.required !== undefined) {
      if (!Array.isArray(rawNode.required)) {
        failSchemaValidation(
          `${fieldPath}.required`,
          "INVALID_REQUIRED",
          `Expected array for required at ${fieldPath}`
        );
      }
      const rawRequired: readonly unknown[] = rawNode.required as readonly unknown[];
      if (rawRequired.length > SCHEMA_MAX_OBJECT_PROPERTIES) {
        failSchemaLimit(
          `${fieldPath}.required`,
          `required list exceeds ${SCHEMA_MAX_OBJECT_PROPERTIES} entries`
        );
      }
      const seenRequired = new Set<string>();
      for (let i = 0; i < rawRequired.length; i += 1) {
        const reqName = rawRequired[i];
        if (typeof reqName !== "string" || hasLoneSurrogate(reqName)) {
          failSchemaValidation(
            `${fieldPath}.required[${i}]`,
            "INVALID_REQUIRED",
            `Expected string in required at ${fieldPath}.required[${i}]`
          );
        }
        if (seenRequired.has(reqName)) {
          failSchemaValidation(
            `${fieldPath}.required[${i}]`,
            "DUPLICATE_REQUIRED",
            `Duplicate required property "${reqName}" at ${fieldPath}`
          );
        }
        if (!Object.prototype.hasOwnProperty.call(compiledProps, reqName)) {
          failSchemaValidation(
            `${fieldPath}.required[${i}]`,
            "UNDECLARED_REQUIRED",
            `Required property "${reqName}" must be declared in properties at ${fieldPath}`
          );
        }
        seenRequired.add(reqName);
        requiredList.push(reqName);
      }
      requiredList.sort(compareCodeUnits);
    }

    return Object.freeze({
      kind: "object",
      nullable,
      properties: Object.freeze(compiledProps),
      required: Object.freeze(requiredList),
      additionalProperties: false,
      ...annotations
    });
  }

  if (baseType === "array") {
    if (rawNode.items === undefined) {
      failSchemaValidation(
        `${fieldPath}.items`,
        "MISSING_ITEMS",
        `Array schema must declare items at ${fieldPath}`
      );
    }
    if (rawNode.maxItems === undefined) {
      failSchemaValidation(
        `${fieldPath}.maxItems`,
        "MISSING_MAX_ITEMS",
        `Array schema must declare explicit maxItems at ${fieldPath}`
      );
    }
    const maxItems = parseNonNegBoundedInt(
      rawNode.maxItems,
      EVENT_MAX_JSON_NODES,
      `${fieldPath}.maxItems`
    );
    const minItems =
      rawNode.minItems !== undefined
        ? parseNonNegBoundedInt(rawNode.minItems, EVENT_MAX_JSON_NODES, `${fieldPath}.minItems`)
        : 0;
    if (minItems > maxItems) {
      failSchemaValidation(
        `${fieldPath}.minItems`,
        "INCONSISTENT_BOUNDS",
        `minItems (${minItems}) cannot exceed maxItems (${maxItems}) at ${fieldPath}`
      );
    }
    const itemsNode = compileSchemaNode(rawNode.items, false, `${fieldPath}.items`, ctx);
    return Object.freeze({
      kind: "array",
      nullable,
      items: itemsNode,
      minItems,
      maxItems,
      ...annotations
    });
  }

  if (baseType === "string") {
    if (rawNode.maxLength === undefined) {
      failSchemaValidation(
        `${fieldPath}.maxLength`,
        "MISSING_MAX_LENGTH",
        `String schema must declare explicit maxLength at ${fieldPath}`
      );
    }
    const maxLength = parseNonNegBoundedInt(
      rawNode.maxLength,
      EVENT_MAX_CONTENT_BYTES,
      `${fieldPath}.maxLength`
    );
    const minLength =
      rawNode.minLength !== undefined
        ? parseNonNegBoundedInt(
            rawNode.minLength,
            EVENT_MAX_CONTENT_BYTES,
            `${fieldPath}.minLength`
          )
        : 0;
    if (minLength > maxLength) {
      failSchemaValidation(
        `${fieldPath}.minLength`,
        "INCONSISTENT_BOUNDS",
        `minLength (${minLength}) cannot exceed maxLength (${maxLength}) at ${fieldPath}`
      );
    }

    const baseNode: NormalizedStringSchemaNode = {
      kind: "string",
      nullable,
      minLength,
      maxLength,
      ...annotations
    };
    const { enumList, constLiteral } = compileEnumAndConst(rawNode, baseNode, fieldPath);
    return Object.freeze({
      ...baseNode,
      ...(enumList !== undefined ? { enum: enumList } : {}),
      ...(constLiteral !== undefined ? { const: constLiteral } : {})
    });
  }

  if (baseType === "integer" || baseType === "number") {
    const minimum =
      rawNode.minimum !== undefined
        ? normalizeLosslessNumber(rawNode.minimum, `${fieldPath}.minimum`)
        : undefined;
    const maximum =
      rawNode.maximum !== undefined
        ? normalizeLosslessNumber(rawNode.maximum, `${fieldPath}.maximum`)
        : undefined;
    if (minimum !== undefined && maximum !== undefined) {
      if (compareNormalizedDecimals(minimum, maximum) > 0) {
        failSchemaValidation(
          `${fieldPath}.minimum`,
          "INCONSISTENT_BOUNDS",
          `minimum cannot exceed maximum at ${fieldPath}`
        );
      }
    }
    const baseNode: NormalizedNumericSchemaNode = {
      kind: baseType,
      nullable,
      ...(minimum !== undefined ? { minimum } : {}),
      ...(maximum !== undefined ? { maximum } : {}),
      ...annotations
    };
    const { enumList, constLiteral } = compileEnumAndConst(rawNode, baseNode, fieldPath);
    return Object.freeze({
      ...baseNode,
      ...(enumList !== undefined ? { enum: enumList } : {}),
      ...(constLiteral !== undefined ? { const: constLiteral } : {})
    });
  }

  if (baseType === "boolean") {
    const baseNode: NormalizedBooleanSchemaNode = {
      kind: "boolean",
      nullable,
      ...annotations
    };
    const { enumList, constLiteral } = compileEnumAndConst(rawNode, baseNode, fieldPath);
    return Object.freeze({
      ...baseNode,
      ...(enumList !== undefined ? { enum: enumList } : {}),
      ...(constLiteral !== undefined ? { const: constLiteral } : {})
    });
  }

  const baseNullNode: NormalizedNullSchemaNode = {
    kind: "null",
    nullable: false,
    ...annotations
  };
  const { enumList, constLiteral } = compileEnumAndConst(rawNode, baseNullNode, fieldPath);
  return Object.freeze({
    ...baseNullNode,
    ...(enumList !== undefined ? { enum: enumList } : {}),
    ...(constLiteral !== undefined ? { const: constLiteral } : {})
  });
}

function compileEnumAndConst(
  rawNode: Record<string, unknown>,
  node: NormalizedConcreteSchemaNode,
  fieldPath: string
): {
  readonly enumList?: readonly NormalizedScalarLiteral[] | undefined;
  readonly constLiteral?: NormalizedScalarLiteral | undefined;
} {
  let enumList: readonly NormalizedScalarLiteral[] | undefined;
  if (Object.prototype.hasOwnProperty.call(rawNode, "enum")) {
    if (!Array.isArray(rawNode.enum)) {
      failSchemaValidation(`${fieldPath}.enum`, "INVALID_ENUM", `Expected array for enum at ${fieldPath}`);
    }
    if (rawNode.enum.length === 0) {
      failSchemaValidation(`${fieldPath}.enum`, "EMPTY_ENUM", `enum must be non-empty at ${fieldPath}`);
    }
    if (rawNode.enum.length > SCHEMA_MAX_ENUM_VALUES) {
      failSchemaLimit(
        `${fieldPath}.enum`,
        `enum exceeds maximum ${SCHEMA_MAX_ENUM_VALUES} values at ${fieldPath}`
      );
    }
    const normalized: NormalizedScalarLiteral[] = [];
    for (let i = 0; i < rawNode.enum.length; i += 1) {
      const lit = normalizeSchemaScalarLiteral(rawNode.enum[i], `${fieldPath}.enum[${i}]`);
      validateScalarLiteralAgainstNode(lit, node, `${fieldPath}.enum[${i}]`);
      normalized.push(lit);
    }
    enumList = Object.freeze(normalized);
  }

  let constLiteral: NormalizedScalarLiteral | undefined;
  if (Object.prototype.hasOwnProperty.call(rawNode, "const")) {
    const lit = normalizeSchemaScalarLiteral(rawNode.const, `${fieldPath}.const`);
    validateScalarLiteralAgainstNode(lit, node, `${fieldPath}.const`);
    if (enumList !== undefined && !enumList.some((item) => scalarLiteralEquals(item, lit))) {
      failSchemaValidation(
        `${fieldPath}.const`,
        "CONST_NOT_IN_ENUM",
        `const literal is not present in enum at ${fieldPath}`
      );
    }
    constLiteral = lit;
  }

  return { enumList, constLiteral };
}

function measureExpandedSchemaDepthAndCheckCycles(
  root: NormalizedConcreteSchemaNode,
  defs: Readonly<Record<string, NormalizedSchemaNode>>
): number {
  const defState = new Map<string, "visiting" | "visited">();
  const defDepths = new Map<string, { containerDepth: number; refChainDepth: number }>();

  function visitNode(node: NormalizedSchemaNode, fieldPath: string): {
    containerDepth: number;
    refChainDepth: number;
  } {
    if (node.kind === "ref") {
      const target = defs[node.targetName];
      if (target === undefined) {
        failSchemaValidation(fieldPath, "UNRESOLVED_REF", `Missing $defs target "${node.targetName}"`);
      }
      const existing = defState.get(node.targetName);
      if (existing === "visiting") {
        failSchemaValidation(
          fieldPath,
          "CYCLIC_REF",
          `Cyclic $ref detected involving "#/$defs/${node.targetName}"`
        );
      }
      let targetMetrics: { containerDepth: number; refChainDepth: number };
      if (existing === "visited") {
        targetMetrics = defDepths.get(node.targetName)!;
      } else {
        defState.set(node.targetName, "visiting");
        targetMetrics = visitNode(target, `#/$defs/${node.targetName}`);
        defState.set(node.targetName, "visited");
        defDepths.set(node.targetName, targetMetrics);
      }
      const refChainDepth = 1 + targetMetrics.refChainDepth;
      if (refChainDepth > SCHEMA_MAX_DEPTH) {
        failSchemaLimit(
          fieldPath,
          `$ref expansion chain exceeds maximum depth ${SCHEMA_MAX_DEPTH}`
        );
      }
      return {
        containerDepth: targetMetrics.containerDepth,
        refChainDepth
      };
    }

    if (node.kind === "object") {
      let maxChildContainer = 0;
      for (const propName of Object.keys(node.properties)) {
        const childMetrics = visitNode(node.properties[propName]!, `${fieldPath}.${propName}`);
        if (childMetrics.containerDepth > maxChildContainer) {
          maxChildContainer = childMetrics.containerDepth;
        }
      }
      const total = 1 + maxChildContainer;
      if (total > SCHEMA_MAX_DEPTH) {
        failSchemaLimit(
          fieldPath,
          `Expanded schema depth ${total} exceeds maximum ${SCHEMA_MAX_DEPTH}`
        );
      }
      return { containerDepth: total, refChainDepth: 0 };
    }

    if (node.kind === "array") {
      const childMetrics = visitNode(node.items, `${fieldPath}.items`);
      const total = 1 + childMetrics.containerDepth;
      if (total > SCHEMA_MAX_DEPTH) {
        failSchemaLimit(
          fieldPath,
          `Expanded schema depth ${total} exceeds maximum ${SCHEMA_MAX_DEPTH}`
        );
      }
      return { containerDepth: total, refChainDepth: 0 };
    }

    return { containerDepth: 0, refChainDepth: 0 };
  }

  const rootMetrics = visitNode(root, "$");
  let maxDepth = rootMetrics.containerDepth;

  // Validate all definitions including unreachable ones
  for (const defName of Object.keys(defs).sort(compareCodeUnits)) {
    if (defState.get(defName) !== "visited") {
      defState.set(defName, "visiting");
      const metrics = visitNode(defs[defName]!, `#/$defs/${defName}`);
      defState.set(defName, "visited");
      defDepths.set(defName, metrics);
      if (metrics.containerDepth > maxDepth) {
        maxDepth = metrics.containerDepth;
      }
    }
  }

  return maxDepth;
}

function canonicalizeProfileValue(value: unknown, depth: number, fieldPath: string): string {
  if (depth > 128) {
    failSchemaLimit(fieldPath, "Normalized profile canonicalization depth exceeds 128");
  }
  if (value === null) {
    return "null";
  }
  if (typeof value === "boolean") {
    return value ? "true" : "false";
  }
  if (typeof value === "number") {
    return Object.is(value, -0) ? "0" : value.toString(10);
  }
  if (typeof value === "string") {
    return serializeStrictJsonString(value, fieldPath);
  }
  if (Array.isArray(value)) {
    const items = value as readonly unknown[];
    const parts: string[] = [];
    for (let i = 0; i < items.length; i += 1) {
      parts.push(canonicalizeProfileValue(items[i], depth + 1, `${fieldPath}[${i}]`));
    }
    return `[${parts.join(",")}]`;
  }
  if (typeof value === "object") {
    const rec = value as Record<string, unknown>;
    const keys = Object.keys(rec).sort(compareCodeUnits);
    const parts: string[] = [];
    for (const key of keys) {
      const prop = rec[key];
      if (prop !== undefined) {
        parts.push(
          `${serializeStrictJsonString(key, `${fieldPath}.${key}`)}:${canonicalizeProfileValue(
            prop,
            depth + 1,
            `${fieldPath}.${key}`
          )}`
        );
      }
    }
    return `{${parts.join(",")}}`;
  }
  failSchemaValidation(fieldPath, "INVALID_PROFILE_VALUE", "Unsupported normalized profile value");
}

function hashNormalizedProfile(profile: NormalizedEventSchemaProfile): {
  readonly bytes: Uint8Array;
  readonly sha256: Sha256Hex;
} {
  const bytes = encodeUtf8Bytes(
    canonicalizeProfileValue(profile, 0, "normalized_profile"),
    "normalized_profile"
  );
  return {
    bytes,
    sha256: sha256Hex(bytes)
  };
}

export function compileEventSchema(
  input: Uint8Array | string | LosslessJsonValue,
  options?: { readonly fieldPath?: string | undefined }
): CompiledEventSchema {
  const fieldPath = options?.fieldPath ?? "schema";

  let rootRawObj: Record<string, unknown>;
  let definitionSha256: Sha256Hex | undefined;
  let rawByteCount = 0;

  if (input instanceof Uint8Array || typeof input === "string") {
    const parsed = parseStrictLosslessJson(input, {
      fieldPath,
      minDecodedBytes: 2,
      maxDecodedBytes: SCHEMA_MAX_RAW_BYTES,
      maxDepth: 64,
      maxNodes: 16_384,
      requireObjectRoot: true
    });
    rootRawObj = parsed.value as Record<string, unknown>;
    definitionSha256 = parsed.sha256;
    rawByteCount = parsed.byteCount;
  } else if (isPlainObjectRecord(input)) {
    rootRawObj = input;
  } else {
    failSchemaValidation(fieldPath, "INVALID_SCHEMA_ROOT", `Expected schema object at ${fieldPath}`);
  }

  const defsObjRaw = rootRawObj.$defs;
  const defNamesSet = new Set<string>();
  const sortedDefNames: string[] = [];

  if (defsObjRaw !== undefined) {
    if (!isPlainObjectRecord(defsObjRaw)) {
      failSchemaValidation(`${fieldPath}.$defs`, "INVALID_DEFS", `Expected object for $defs`);
    }
    const rawDefNames = Object.keys(defsObjRaw).sort(compareCodeUnits);
    if (rawDefNames.length > SCHEMA_MAX_DEFS) {
      failSchemaLimit(
        `${fieldPath}.$defs`,
        `$defs exceeds maximum ${SCHEMA_MAX_DEFS} named definitions`
      );
    }
    for (const defName of rawDefNames) {
      if (defName.length === 0 || hasLoneSurrogate(defName)) {
        failSchemaValidation(
          `${fieldPath}.$defs`,
          "INVALID_DEF_NAME",
          `Invalid definition name in $defs`
        );
      }
      if (computeUtf8ByteLength(defName) > SCHEMA_MAX_DEF_NAME_BYTES) {
        failSchemaLimit(
          `${fieldPath}.$defs`,
          `Definition name exceeds ${SCHEMA_MAX_DEF_NAME_BYTES} UTF-8 bytes`
        );
      }
      defNamesSet.add(defName);
      sortedDefNames.push(defName);
    }
  }

  const ctx: CompileContext = {
    nodeCount: 0,
    refEdgeCount: 0,
    defNames: defNamesSet
  };

  const compiledDefs: Record<string, NormalizedSchemaNode> = {};
  if (defsObjRaw !== undefined && isPlainObjectRecord(defsObjRaw)) {
    for (const defName of sortedDefNames) {
      compiledDefs[defName] = compileSchemaNode(
        defsObjRaw[defName],
        false,
        `${fieldPath}.$defs.${defName}`,
        ctx
      );
    }
  }

  const compiledRoot = compileSchemaNode(rootRawObj, true, fieldPath, ctx);
  if (compiledRoot.kind === "ref") {
    failSchemaValidation(fieldPath, "ROOT_REF_FORBIDDEN", "Root schema cannot be a $ref");
  }

  const maxExpandedDepth = measureExpandedSchemaDepthAndCheckCycles(compiledRoot, compiledDefs);

  const normalizedProfile: NormalizedEventSchemaProfile = Object.freeze({
    profile_version: EVENT_SCHEMA_PROFILE_V1,
    dialect: EVENT_SCHEMA_DIALECT_2020_12,
    root: compiledRoot,
    defs: Object.freeze(compiledDefs)
  });

  const hashedProfile = hashNormalizedProfile(normalizedProfile);

  if (definitionSha256 === undefined) {
    definitionSha256 = hashedProfile.sha256;
    rawByteCount = hashedProfile.bytes.length;
  }

  return Object.freeze({
    profileVersion: EVENT_SCHEMA_PROFILE_V1,
    dialect: EVENT_SCHEMA_DIALECT_2020_12,
    definitionSha256,
    profileSha256: hashedProfile.sha256,
    rawByteCount,
    normalizedNodeCount: ctx.nodeCount,
    refEdgeCount: ctx.refEdgeCount,
    maxExpandedDepth,
    normalizedProfile
  });
}

export function compileEventSchemaFromBytes(
  rawBytes: Uint8Array,
  expectedSha256?: Sha256Hex
): CompiledEventSchema {
  if (!(rawBytes instanceof Uint8Array)) {
    failSchemaValidation("schema_bytes", "INVALID_VALUE", "Expected Uint8Array schema definition");
  }
  if (rawBytes.length > SCHEMA_MAX_RAW_BYTES) {
    throw new ValidationDomainError({
      code: "PAYLOAD_TOO_LARGE",
      message: `Schema raw bytes (${rawBytes.length}) exceed ${SCHEMA_MAX_RAW_BYTES} bytes`
    });
  }
  const actualSha = sha256Hex(rawBytes);
  if (expectedSha256 !== undefined && actualSha !== expectedSha256) {
    throw new ValidationDomainError({
      code: "INVALID_HASH",
      message: "Schema definition_sha256 mismatch"
    });
  }
  return compileEventSchema(rawBytes);
}

export function dereferenceSchemaNode(
  node: NormalizedSchemaNode,
  schema: CompiledEventSchema
): NormalizedConcreteSchemaNode {
  let current: NormalizedSchemaNode = node;
  let hops = 0;
  while (current.kind === "ref") {
    hops += 1;
    if (hops > SCHEMA_MAX_DEPTH) {
      failSchemaLimit("$ref", `Reference chain exceeded ${SCHEMA_MAX_DEPTH} hops`);
    }
    const next = schema.normalizedProfile.defs[current.targetName];
    if (next === undefined) {
      failSchemaValidation("$ref", "UNRESOLVED_REF", `Missing definition "${current.targetName}"`);
    }
    current = next;
  }
  return current;
}

export function resolveSchemaPointer(
  schema: CompiledEventSchema,
  pointer: ParsedJsonPointer
): ResolvedSchemaPointer {
  let current: NormalizedConcreteSchemaNode = schema.normalizedProfile.root;
  let alwaysRequired = true;

  for (let i = 0; i < pointer.tokens.length; i += 1) {
    const token = pointer.tokens[i]!;
    if (current.kind !== "object") {
      failSchemaValidation(
        pointer.raw,
        "NON_OBJECT_TRAVERSAL",
        `Pointer segment ${i} at "${pointer.raw}" cannot traverse non-object schema type "${current.kind}"`
      );
    }
    if (current.nullable) {
      alwaysRequired = false;
    }
    if (!Object.prototype.hasOwnProperty.call(current.properties, token)) {
      failSchemaValidation(
        pointer.raw,
        "UNREGISTERED_POINTER",
        `Pointer "${pointer.raw}" references undeclared property "${token}"`
      );
    }
    if (!current.required.includes(token)) {
      alwaysRequired = false;
    }
    current = dereferenceSchemaNode(current.properties[token]!, schema);
  }

  return Object.freeze({
    node: current,
    alwaysRequired
  });
}

function scalarMatchesConcreteNode(
  lit: NormalizedScalarLiteral,
  node: NormalizedConcreteSchemaNode
): boolean {
  if (lit.kind === "null") {
    if (node.kind !== "null" && !node.nullable) {
      return false;
    }
  } else {
    switch (node.kind) {
      case "null":
        return false;
      case "boolean":
        if (lit.kind !== "boolean") {
          return false;
        }
        break;
      case "string": {
        if (lit.kind !== "string") {
          return false;
        }
        let scalarLen = 0;
        for (let i = 0; i < lit.value.length; i += 1) {
          const c = lit.value.charCodeAt(i);
          if (c >= 0xd800 && c <= 0xdbff) {
            i += 1;
          }
          scalarLen += 1;
        }
        if (scalarLen < node.minLength || scalarLen > node.maxLength) {
          return false;
        }
        break;
      }
      case "integer":
      case "number": {
        if (lit.kind !== "number") {
          return false;
        }
        if (node.kind === "integer" && !isNormalizedInteger(lit.value)) {
          return false;
        }
        if (node.minimum !== undefined && compareNormalizedDecimals(lit.value, node.minimum) < 0) {
          return false;
        }
        if (node.maximum !== undefined && compareNormalizedDecimals(lit.value, node.maximum) > 0) {
          return false;
        }
        break;
      }
      case "object":
      case "array":
        return false;
    }
  }

  if (node.kind !== "object" && node.kind !== "array") {
    if (node.const !== undefined && !scalarLiteralEquals(lit, node.const)) {
      return false;
    }
    if (node.enum !== undefined && !node.enum.some((item) => scalarLiteralEquals(item, lit))) {
      return false;
    }
  }
  return true;
}

function getEffectiveScalarDomain(
  node: NormalizedConcreteSchemaNode
): readonly NormalizedScalarLiteral[] | null {
  if (node.kind === "object" || node.kind === "array") {
    return null;
  }
  if (node.const !== undefined) {
    return [node.const];
  }
  if (node.enum !== undefined) {
    return node.enum;
  }
  if (node.kind === "null") {
    return [{ kind: "null" }];
  }
  if (node.kind === "boolean") {
    const out: NormalizedScalarLiteral[] = [
      { kind: "boolean", value: true },
      { kind: "boolean", value: false }
    ];
    if (node.nullable) {
      out.push({ kind: "null" });
    }
    return out;
  }
  return null;
}

export function isSchemaSubschema(
  subNode: NormalizedSchemaNode,
  subSchema: CompiledEventSchema,
  supNode: NormalizedSchemaNode,
  supSchema: CompiledEventSchema,
  reasons?: string[],
  path = "$"
): boolean {
  const sub = dereferenceSchemaNode(subNode, subSchema);
  const sup = dereferenceSchemaNode(supNode, supSchema);

  if (sub.nullable && !sup.nullable && sup.kind !== "null") {
    reasons?.push(`${path}: nullable source cannot satisfy non-nullable target`);
    return false;
  }

  // If sub has a finite scalar domain (const, enum, null, boolean), exact pointwise verification is complete.
  const subFiniteDomain = getEffectiveScalarDomain(sub);
  if (subFiniteDomain !== null) {
    for (const lit of subFiniteDomain) {
      if (!scalarMatchesConcreteNode(lit, sup)) {
        reasons?.push(`${path}: source scalar value is not accepted by target`);
        return false;
      }
    }
    return true;
  }

  // Target has const/enum on an infinite domain (string/number/integer): conservatively incompatible.
  if (
    sup.kind !== "object" &&
    sup.kind !== "array" &&
    (sup.const !== undefined || sup.enum !== undefined)
  ) {
    reasons?.push(`${path}: target enum/const narrows unbounded source domain`);
    return false;
  }

  if (sub.kind !== sup.kind) {
    if (!(sub.kind === "integer" && sup.kind === "number")) {
      reasons?.push(`${path}: incompatible types (${sub.kind} -> ${sup.kind})`);
      return false;
    }
  }

  switch (sub.kind) {
    case "object": {
      if (sup.kind !== "object") {
        return false;
      }
      for (const propName of Object.keys(sub.properties)) {
        if (!Object.prototype.hasOwnProperty.call(sup.properties, propName)) {
          reasons?.push(`${path}.${propName}: property removed in target schema`);
          return false;
        }
        const ok = isSchemaSubschema(
          sub.properties[propName]!,
          subSchema,
          sup.properties[propName]!,
          supSchema,
          reasons,
          `${path}.${propName}`
        );
        if (!ok) {
          return false;
        }
      }
      const subReqSet = new Set(sub.required);
      for (const supReq of sup.required) {
        if (!subReqSet.has(supReq)) {
          reasons?.push(`${path}.${supReq}: target introduces newly required property`);
          return false;
        }
      }
      return true;
    }

    case "array": {
      if (sup.kind !== "array") {
        return false;
      }
      if (sub.minItems < sup.minItems) {
        reasons?.push(`${path}: minItems narrowed (${sub.minItems} -> ${sup.minItems})`);
        return false;
      }
      if (sub.maxItems > sup.maxItems) {
        reasons?.push(`${path}: maxItems narrowed (${sub.maxItems} -> ${sup.maxItems})`);
        return false;
      }
      return isSchemaSubschema(sub.items, subSchema, sup.items, supSchema, reasons, `${path}[]`);
    }

    case "string": {
      if (sup.kind !== "string") {
        return false;
      }
      if (sub.minLength < sup.minLength) {
        reasons?.push(`${path}: minLength narrowed (${sub.minLength} -> ${sup.minLength})`);
        return false;
      }
      if (sub.maxLength > sup.maxLength) {
        reasons?.push(`${path}: maxLength narrowed (${sub.maxLength} -> ${sup.maxLength})`);
        return false;
      }
      return true;
    }

    case "integer":
    case "number": {
      if (sup.kind !== "integer" && sup.kind !== "number") {
        return false;
      }
      if (sup.minimum !== undefined) {
        if (
          sub.minimum === undefined ||
          compareNormalizedDecimals(sub.minimum, sup.minimum) < 0
        ) {
          reasons?.push(`${path}: minimum constraint narrowed`);
          return false;
        }
      }
      if (sup.maximum !== undefined) {
        if (
          sub.maximum === undefined ||
          compareNormalizedDecimals(sub.maximum, sup.maximum) > 0
        ) {
          reasons?.push(`${path}: maximum constraint narrowed`);
          return false;
        }
      }
      return true;
    }

    case "boolean":
    case "null":
      return true;
  }
}

export function checkSchemaCompatibility(
  previousSchema: CompiledEventSchema,
  nextSchema: CompiledEventSchema
): SchemaCompatibilityCheckResult {
  const reasons: string[] = [];
  const compatible = isSchemaSubschema(
    previousSchema.normalizedProfile.root,
    previousSchema,
    nextSchema.normalizedProfile.root,
    nextSchema,
    reasons,
    "$"
  );
  return Object.freeze({
    compatible,
    recommendedPolicy: compatible ? "additive_compatible" : "new_breaking_version",
    reasons: Object.freeze(reasons.slice(0, SCHEMA_MAX_DIAGNOSTICS))
  });
}

export interface SchemaCacheKey {
  readonly eventTypeId: string;
  readonly schemaVersion: number;
  readonly definitionSha256: Sha256Hex;
  readonly profileVersion?: typeof EVENT_SCHEMA_PROFILE_V1 | undefined;
}

export class SchemaCompilationCache {
  readonly #maxEntries: number;
  readonly #cache = new Map<string, CompiledEventSchema>();

  constructor(maxEntries = 256) {
    if (!Number.isInteger(maxEntries) || maxEntries < 1 || maxEntries > 4096) {
      throw new ValidationDomainError({
        code: "INVALID_VALUE",
        message: "SchemaCompilationCache maxEntries must be within [1, 4096]"
      });
    }
    this.#maxEntries = maxEntries;
  }

  get size(): number {
    return this.#cache.size;
  }

  static formatKey(key: SchemaCacheKey): string {
    const profileVer = key.profileVersion ?? EVENT_SCHEMA_PROFILE_V1;
    return `${key.eventTypeId}:${key.schemaVersion}:${key.definitionSha256}:${profileVer}`;
  }

  get(key: SchemaCacheKey): CompiledEventSchema | undefined {
    const cacheKey = SchemaCompilationCache.formatKey(key);
    const hit = this.#cache.get(cacheKey);
    if (hit === undefined) {
      return undefined;
    }
    this.#cache.delete(cacheKey);
    this.#cache.set(cacheKey, hit);
    return hit;
  }

  getOrCompile(
    key: SchemaCacheKey,
    definitionBytes: Uint8Array
  ): CompiledEventSchema {
    const existing = this.get(key);
    if (existing !== undefined) {
      return existing;
    }
    const compiled = compileEventSchemaFromBytes(definitionBytes, key.definitionSha256);
    const cacheKey = SchemaCompilationCache.formatKey(key);
    if (this.#cache.size >= this.#maxEntries) {
      const oldestKey = this.#cache.keys().next().value;
      if (oldestKey !== undefined) {
        this.#cache.delete(oldestKey);
      }
    }
    this.#cache.set(cacheKey, compiled);
    return compiled;
  }

  clear(): void {
    this.#cache.clear();
  }
}
