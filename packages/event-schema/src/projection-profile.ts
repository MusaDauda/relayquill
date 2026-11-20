import {
  type EventTypeId,
  LimitExceededDomainError,
  type Sha256Hex,
  ValidationDomainError,
  computeUtf8ByteLength,
  hasLoneSurrogate,
  parseEventTypeId
} from "@relayquill/domain";
import {
  type CanonicalJsonValue,
  hashCanonicalJson,
  parsePositiveInt32,
  sha256Hex
} from "@relayquill/contracts";
import { LosslessNumber, isLosslessNumber } from "lossless-json";
import { evaluateParsedEvent } from "./evaluator.js";
import {
  normalizeLosslessNumber,
  parseNormalizedDecimalObject
} from "./numeric.js";
import {
  type LosslessJsonValue,
  isPlainObjectRecord,
  parseStrictLosslessJson,
  serializeStrictJsonString
} from "./parser.js";
import { type ParsedJsonPointer, parseJsonPointer } from "./pointer.js";
import {
  type CompiledEventSchema,
  type NormalizedConcreteSchemaNode,
  type NormalizedObjectSchemaNode,
  SCHEMA_MAX_RAW_BYTES,
  dereferenceSchemaNode,
  isSchemaSubschema,
  resolveSchemaPointer
} from "./profile.js";
import {
  DERIVED_MAX_CONTENT_BYTES,
  type ProjectionLiteralValue,
  computeDerivedWireEnvelopeUpperBoundBytes,
  computeWorstCaseSchemaValueBytes,
  serializePolicyLiteralJson
} from "./projection-size.js";

export const PROJECTION_PROFILE_SCHEMA_VERSION = 1 as const;
export const PROJECTION_COMPILER_VERSION = "relayquill.lossless-projection.v1" as const;
export const PROJECTION_MAX_MAPPINGS = 32 as const;
export const PROJECTION_MAX_TARGET_DEPTH = 8 as const;
export const MAX_ACTIVE_PROFILES_PER_SOURCE_SCHEMA = 8 as const;

export type ProjectionMappingOperation = "copy" | "constant" | "copy_or_default";

export interface NormalizedProjectionCopyRule {
  readonly operation: "copy";
  readonly target_path: string;
  readonly source_path: string;
}

export interface NormalizedProjectionConstantRule {
  readonly operation: "constant";
  readonly target_path: string;
  readonly value: ProjectionLiteralValue;
}

export interface NormalizedProjectionCopyOrDefaultRule {
  readonly operation: "copy_or_default";
  readonly target_path: string;
  readonly source_path: string;
  readonly default_value: ProjectionLiteralValue;
}

export type NormalizedProjectionRule =
  | NormalizedProjectionCopyRule
  | NormalizedProjectionConstantRule
  | NormalizedProjectionCopyOrDefaultRule;

export interface NormalizedProjectionMappingProfile {
  readonly profile_schema_version: typeof PROJECTION_PROFILE_SCHEMA_VERSION;
  readonly compiler_profile_version: typeof PROJECTION_COMPILER_VERSION;
  readonly source_event_type_id: EventTypeId;
  readonly source_schema_version: number;
  readonly target_schema_version: number;
  readonly mappings: readonly NormalizedProjectionRule[];
}

export type CompiledProjectionRule =
  | {
      readonly operation: "copy";
      readonly targetPointer: ParsedJsonPointer;
      readonly sourcePointer: ParsedJsonPointer;
      readonly worstCaseBytes: number;
    }
  | {
      readonly operation: "constant";
      readonly targetPointer: ParsedJsonPointer;
      readonly value: ProjectionLiteralValue;
      readonly worstCaseBytes: number;
    }
  | {
      readonly operation: "copy_or_default";
      readonly targetPointer: ParsedJsonPointer;
      readonly sourcePointer: ParsedJsonPointer;
      readonly defaultValue: ProjectionLiteralValue;
      readonly worstCaseBytes: number;
    };

export type ProjectionWriterNode =
  | {
      readonly kind: "object";
      readonly requiredInTarget: boolean;
      readonly hasUnconditionalOutput: boolean;
      readonly children: ReadonlyMap<string, ProjectionWriterNode>;
      readonly worstCaseBytes: number;
    }
  | {
      readonly kind: "leaf";
      readonly requiredInTarget: boolean;
      readonly hasUnconditionalOutput: boolean;
      readonly rule: CompiledProjectionRule;
      readonly worstCaseBytes: number;
    };

export interface CompiledProjectionProfile {
  readonly profileSchemaVersion: typeof PROJECTION_PROFILE_SCHEMA_VERSION;
  readonly compilerProfileVersion: typeof PROJECTION_COMPILER_VERSION;
  readonly sourceEventTypeId: EventTypeId;
  readonly sourceSchemaVersion: number;
  readonly targetSchemaVersion: number;
  readonly definitionSha256: Sha256Hex;
  readonly normalizedMapping: NormalizedProjectionMappingProfile;
  readonly normalizedMappingSha256: Sha256Hex;
  readonly provenOutputMaxBytes: number;
  readonly maxWireEnvelopeUpperBoundBytes: number;
  readonly sourceSchema: CompiledEventSchema;
  readonly targetSchema: CompiledEventSchema;
  readonly mappings: readonly CompiledProjectionRule[];
  readonly writerRoot: ProjectionWriterNode & { readonly kind: "object" };
}

const TOP_LEVEL_PROFILE_KEYS = new Set([
  "profile_schema_version",
  "compiler_profile_version",
  "source_event_type_id",
  "source_schema_version",
  "target_schema_version",
  "mappings"
]);
const COPY_RULE_KEYS = new Set(["operation", "target_path", "source_path"]);
const CONSTANT_RULE_KEYS = new Set(["operation", "target_path", "value"]);
const COPY_OR_DEFAULT_RULE_KEYS = new Set([
  "operation",
  "target_path",
  "source_path",
  "default_value"
]);

function compareCodeUnits(a: string, b: string): number {
  if (a === b) {
    return 0;
  }
  return a < b ? -1 : 1;
}

function failProjectionValidation(path: string, code: string, message: string): never {
  throw new ValidationDomainError({
    code: "INVALID_VALUE",
    message,
    fieldErrors: [{ path, code }]
  });
}

function failProjectionLimit(path: string, message: string): never {
  throw new LimitExceededDomainError({
    code: "SCHEMA_EVALUATION_LIMIT",
    message,
    fieldErrors: [{ path, code: "SCHEMA_EVALUATION_LIMIT" }]
  });
}

function assertAllowedKeys(
  rec: Record<string, unknown>,
  allowed: ReadonlySet<string>,
  fieldPath: string
): void {
  for (const key of Object.keys(rec)) {
    if (!allowed.has(key)) {
      failProjectionValidation(
        `${fieldPath}.${key}`,
        "UNSUPPORTED_PROJECTION_FIELD",
        `Unsupported field "${key}" in projection profile at ${fieldPath}`
      );
    }
  }
}

function normalizePolicyLiteralAndToLossless(
  raw: unknown,
  depth: number,
  fieldPath: string
): { readonly policyLiteral: ProjectionLiteralValue; readonly losslessAst: LosslessJsonValue } {
  if (depth > PROJECTION_MAX_TARGET_DEPTH) {
    failProjectionLimit(
      fieldPath,
      `Policy literal nesting depth exceeds ${PROJECTION_MAX_TARGET_DEPTH} at ${fieldPath}`
    );
  }
  if (raw === null || typeof raw === "boolean") {
    return { policyLiteral: raw, losslessAst: raw };
  }
  if (typeof raw === "string") {
    if (hasLoneSurrogate(raw)) {
      failProjectionValidation(fieldPath, "LONE_SURROGATE", `Lone surrogate at ${fieldPath}`);
    }
    return { policyLiteral: raw, losslessAst: raw };
  }
  if (isLosslessNumber(raw) || typeof raw === "number") {
    const dec = normalizeLosslessNumber(raw, fieldPath);
    const wrapped: ProjectionLiteralValue = Object.freeze({
      kind: "normalized_number",
      value: dec
    });
    const losslessNum = isLosslessNumber(raw)
      ? raw
      : new LosslessNumber(String(raw));
    return { policyLiteral: wrapped, losslessAst: losslessNum };
  }
  if (Array.isArray(raw)) {
    const rawArr = raw as readonly unknown[];
    const litArr: ProjectionLiteralValue[] = [];
    const astArr: LosslessJsonValue[] = [];
    for (let i = 0; i < rawArr.length; i += 1) {
      const child = normalizePolicyLiteralAndToLossless(
        rawArr[i],
        depth + 1,
        `${fieldPath}[${i}]`
      );
      litArr.push(child.policyLiteral);
      astArr.push(child.losslessAst);
    }
    return {
      policyLiteral: Object.freeze(litArr),
      losslessAst: Object.freeze(astArr)
    };
  }
  if (isPlainObjectRecord(raw)) {
    if (
      raw.kind === "normalized_number" &&
      Object.prototype.hasOwnProperty.call(raw, "value") &&
      Object.keys(raw).length === 2
    ) {
      const dec = parseNormalizedDecimalObject(raw.value, `${fieldPath}.value`);
      const wrapped: ProjectionLiteralValue = Object.freeze({
        kind: "normalized_number",
        value: dec
      });
      const numText =
        dec.sign === 0
          ? "0"
          : `${dec.sign < 0 ? "-" : ""}${dec.coefficient}${dec.exponent === 0 ? "" : `e${dec.exponent}`}`;
      return {
        policyLiteral: wrapped,
        losslessAst: new LosslessNumber(numText)
      };
    }

    const keys = Object.keys(raw).sort(compareCodeUnits);
    const litObj: Record<string, ProjectionLiteralValue> = {};
    const astObj: Record<string, LosslessJsonValue> = {};
    for (const key of keys) {
      if (hasLoneSurrogate(key)) {
        failProjectionValidation(fieldPath, "LONE_SURROGATE", `Lone surrogate key at ${fieldPath}`);
      }
      const child = normalizePolicyLiteralAndToLossless(
        raw[key],
        depth + 1,
        `${fieldPath}.${key}`
      );
      litObj[key] = child.policyLiteral;
      astObj[key] = child.losslessAst;
    }
    return {
      policyLiteral: Object.freeze(litObj),
      losslessAst: Object.freeze(astObj)
    };
  }
  failProjectionValidation(
    fieldPath,
    "UNSUPPORTED_LITERAL",
    `Unsupported literal value at ${fieldPath}`
  );
}

function validateLiteralAgainstTargetSubschema(
  losslessAst: LosslessJsonValue,
  targetNode: NormalizedConcreteSchemaNode,
  targetSchema: CompiledEventSchema,
  fieldPath: string
): void {
  const syntheticSubSchema: CompiledEventSchema = {
    profileVersion: targetSchema.profileVersion,
    dialect: targetSchema.dialect,
    definitionSha256: targetSchema.definitionSha256,
    profileSha256: targetSchema.profileSha256,
    rawByteCount: targetSchema.rawByteCount,
    normalizedNodeCount: targetSchema.normalizedNodeCount,
    refEdgeCount: targetSchema.refEdgeCount,
    maxExpandedDepth: targetSchema.maxExpandedDepth,
    normalizedProfile: {
      profile_version: targetSchema.profileVersion,
      dialect: targetSchema.dialect,
      root: targetNode,
      defs: targetSchema.normalizedProfile.defs
    }
  };
  const evalResult = evaluateParsedEvent(syntheticSubSchema, losslessAst);
  if (!evalResult.valid) {
    failProjectionValidation(
      fieldPath,
      "POLICY_LITERAL_SCHEMA_MISMATCH",
      `Policy literal does not conform to target schema at ${fieldPath}: ${evalResult.diagnostics[0]?.message ?? "invalid"}`
    );
  }
}

interface MutableWriterObject {
  kind: "object";
  children: Map<string, MutableWriterNode>;
}

interface MutableWriterLeaf {
  kind: "leaf";
  rule: CompiledProjectionRule;
  alwaysProvided: boolean;
}

type MutableWriterNode = MutableWriterObject | MutableWriterLeaf;

function checkTotalityAndSizeRecursive(
  writerObj: MutableWriterObject,
  targetSchemaNode: NormalizedObjectSchemaNode,
  targetSchema: CompiledEventSchema,
  requiredInParent: boolean,
  pathStr: string
): ProjectionWriterNode & { readonly kind: "object" } {
  const sortedTargetKeys = Object.keys(targetSchemaNode.properties).sort(compareCodeUnits);
  const compiledChildren = new Map<string, ProjectionWriterNode>();
  let anyUnconditional = false;

  for (const propName of sortedTargetKeys) {
    const childPath = pathStr === "$" ? `/${propName}` : `${pathStr}/${propName}`;
    const propTargetNode = dereferenceSchemaNode(
      targetSchemaNode.properties[propName]!,
      targetSchema
    );
    const propRequired = targetSchemaNode.required.includes(propName);
    const writerChild = writerObj.children.get(propName);

    if (writerChild === undefined) {
      if (propRequired) {
        failProjectionValidation(
          childPath,
          "TARGET_REQUIRED_FIELD_MISSING",
          `Target required property "${childPath}" has no guaranteed source, default, or constant mapping`
        );
      }
      continue;
    }

    if (writerChild.kind === "leaf") {
      if (propRequired && !writerChild.alwaysProvided) {
        failProjectionValidation(
          childPath,
          "OPTIONAL_COPY_INTO_REQUIRED_TARGET",
          `Optional source cannot be copied into required target "${childPath}" without copy_or_default`
        );
      }
      if (writerChild.alwaysProvided) {
        anyUnconditional = true;
      }
      compiledChildren.set(
        propName,
        Object.freeze({
          kind: "leaf",
          requiredInTarget: propRequired,
          hasUnconditionalOutput: writerChild.alwaysProvided,
          rule: writerChild.rule,
          worstCaseBytes: writerChild.rule.worstCaseBytes
        })
      );
      continue;
    }

    // Intermediate object node
    if (propTargetNode.kind !== "object") {
      failProjectionValidation(
        childPath,
        "TARGET_PARENT_NOT_OBJECT",
        `Target intermediate path "${childPath}" is not an object schema`
      );
    }
    const compiledSubObj = checkTotalityAndSizeRecursive(
      writerChild,
      propTargetNode,
      targetSchema,
      propRequired,
      childPath
    );
    if (compiledSubObj.hasUnconditionalOutput || propRequired) {
      anyUnconditional = true;
    }
    compiledChildren.set(propName, compiledSubObj);
  }

  // Ensure no writer child targets an undeclared target property
  for (const mappedKey of writerObj.children.keys()) {
    if (!Object.prototype.hasOwnProperty.call(targetSchemaNode.properties, mappedKey)) {
      const childPath = pathStr === "$" ? `/${mappedKey}` : `${pathStr}/${mappedKey}`;
      failProjectionValidation(
        childPath,
        "UNDECLARED_TARGET_PROPERTY",
        `Target path "${childPath}" is not declared in target schema`
      );
    }
  }

  // Compute worst-case serialized JSON size of this object
  const mappedKeys = Array.from(compiledChildren.keys()).sort(compareCodeUnits);
  let objWorstCase = 2;
  for (let i = 0; i < mappedKeys.length; i += 1) {
    const key = mappedKeys[i]!;
    const child = compiledChildren.get(key)!;
    const keyBytes = computeUtf8ByteLength(serializeStrictJsonString(key));
    const comma = i > 0 ? 1 : 0;
    objWorstCase += keyBytes + 1 + comma + child.worstCaseBytes;
    if (objWorstCase > DERIVED_MAX_CONTENT_BYTES) {
      failProjectionLimit(
        pathStr,
        `Proven output worst-case size (${objWorstCase} bytes) exceeds ${DERIVED_MAX_CONTENT_BYTES} bytes`
      );
    }
  }

  return Object.freeze({
    kind: "object",
    requiredInTarget: requiredInParent,
    hasUnconditionalOutput: anyUnconditional || requiredInParent,
    children: compiledChildren,
    worstCaseBytes: objWorstCase
  });
}

export function assertActiveRepresentationProfileBudget(activeCount: number): void {
  if (!Number.isInteger(activeCount) || activeCount < 0) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: "Active representation profile count must be a non-negative integer"
    });
  }
  if (activeCount >= MAX_ACTIVE_PROFILES_PER_SOURCE_SCHEMA) {
    throw new LimitExceededDomainError({
      code: "CAPACITY_EXCEEDED",
      message: `Maximum ${MAX_ACTIVE_PROFILES_PER_SOURCE_SCHEMA} active representation profiles allowed per source event type/schema`
    });
  }
}

export function compileProjectionProfile(
  input: unknown,
  sourceSchema: CompiledEventSchema,
  targetSchema: CompiledEventSchema,
  options?: {
    readonly fieldPath?: string | undefined;
    readonly originalContentByteCount?: number | undefined;
    readonly eventType?: string | undefined;
  }
): CompiledProjectionProfile {
  const fieldPath = options?.fieldPath ?? "projection_profile";

  if (sourceSchema.normalizedProfile.root.kind !== "object") {
    failProjectionValidation(
      fieldPath,
      "SOURCE_ROOT_NOT_OBJECT",
      "Source event schema root must be an object for derived projection"
    );
  }
  const targetRootNode = targetSchema.normalizedProfile.root;
  if (targetRootNode.kind !== "object") {
    failProjectionValidation(
      fieldPath,
      "TARGET_ROOT_NOT_OBJECT",
      "Target event schema root must be an object for derived projection"
    );
  }
  if (targetSchema.maxExpandedDepth > PROJECTION_MAX_TARGET_DEPTH) {
    failProjectionLimit(
      fieldPath,
      `Target schema depth (${targetSchema.maxExpandedDepth}) exceeds projection limit ${PROJECTION_MAX_TARGET_DEPTH}`
    );
  }

  let rawObj: unknown = input;
  let definitionSha256: Sha256Hex | undefined;

  if (input instanceof Uint8Array || typeof input === "string") {
    const parsed = parseStrictLosslessJson(input, {
      fieldPath,
      minDecodedBytes: 2,
      maxDecodedBytes: SCHEMA_MAX_RAW_BYTES,
      maxDepth: 32,
      maxNodes: 4_096,
      requireObjectRoot: true
    });
    rawObj = parsed.value;
    definitionSha256 = parsed.sha256;
  }

  if (!isPlainObjectRecord(rawObj)) {
    failProjectionValidation(
      fieldPath,
      "INVALID_PROFILE",
      `Expected projection profile object at ${fieldPath}`
    );
  }

  assertAllowedKeys(rawObj, TOP_LEVEL_PROFILE_KEYS, fieldPath);

  if (rawObj.profile_schema_version !== PROJECTION_PROFILE_SCHEMA_VERSION) {
    const rawVer = rawObj.profile_schema_version;
    if (isLosslessNumber(rawVer)) {
      if (rawVer.value !== String(PROJECTION_PROFILE_SCHEMA_VERSION)) {
        throw new ValidationDomainError({
          code: "UNSUPPORTED_SCHEMA_VERSION",
          message: `Unsupported profile_schema_version; expected ${PROJECTION_PROFILE_SCHEMA_VERSION}`
        });
      }
    } else {
      throw new ValidationDomainError({
        code: "UNSUPPORTED_SCHEMA_VERSION",
        message: `Unsupported profile_schema_version; expected ${PROJECTION_PROFILE_SCHEMA_VERSION}`
      });
    }
  }

  if (
    rawObj.compiler_profile_version !== undefined &&
    rawObj.compiler_profile_version !== PROJECTION_COMPILER_VERSION
  ) {
    throw new ValidationDomainError({
      code: "UNSUPPORTED_SCHEMA_VERSION",
      message: `Unsupported compiler_profile_version; expected ${PROJECTION_COMPILER_VERSION}`
    });
  }

  const sourceEventTypeId = parseEventTypeId(
    rawObj.source_event_type_id,
    `${fieldPath}.source_event_type_id`
  );
  const parseIntField = (rawVal: unknown, path: string): number => {
    if (isLosslessNumber(rawVal)) {
      const dec = normalizeLosslessNumber(rawVal, path);
      if (dec.sign !== 1 || dec.exponent < 0) {
        return parsePositiveInt32(-1, path);
      }
      const big = BigInt(dec.coefficient) * 10n ** BigInt(dec.exponent);
      return parsePositiveInt32(Number(big <= 2_147_483_647n ? big : -1), path);
    }
    return parsePositiveInt32(rawVal, path);
  };
  const sourceSchemaVersion = parseIntField(
    rawObj.source_schema_version,
    `${fieldPath}.source_schema_version`
  );
  const targetSchemaVersion = parseIntField(
    rawObj.target_schema_version,
    `${fieldPath}.target_schema_version`
  );

  if (!Array.isArray(rawObj.mappings)) {
    failProjectionValidation(
      `${fieldPath}.mappings`,
      "INVALID_MAPPINGS",
      `Projection profile mappings must be an array at ${fieldPath}`
    );
  }
  const rawMappings: readonly unknown[] = rawObj.mappings as readonly unknown[];
  if (rawMappings.length > PROJECTION_MAX_MAPPINGS) {
    failProjectionLimit(
      `${fieldPath}.mappings`,
      `Projection profile exceeds maximum ${PROJECTION_MAX_MAPPINGS} mappings`
    );
  }

  const writerRoot: MutableWriterObject = {
    kind: "object",
    children: new Map()
  };

  const normalizedRules: NormalizedProjectionRule[] = [];
  const compiledRules: CompiledProjectionRule[] = [];

  for (let i = 0; i < rawMappings.length; i += 1) {
    const rawRule = rawMappings[i];
    const rulePath = `${fieldPath}.mappings[${i}]`;
    if (!isPlainObjectRecord(rawRule)) {
      failProjectionValidation(rulePath, "INVALID_RULE", `Expected mapping object at ${rulePath}`);
    }

    const op = rawRule.operation;
    if (op !== "copy" && op !== "constant" && op !== "copy_or_default") {
      failProjectionValidation(
        `${rulePath}.operation`,
        "UNSUPPORTED_MAPPING_OPERATION",
        `Unsupported projection mapping operation "${String(op)}" at ${rulePath}`
      );
    }

    const targetPointer = parseJsonPointer(rawRule.target_path, {
      fieldPath: `${rulePath}.target_path`,
      minTokens: 1,
      maxTokens: PROJECTION_MAX_TARGET_DEPTH
    });
    const targetResolved = resolveSchemaPointer(targetSchema, targetPointer);

    // Check overlapping parent/child target paths
    let cursorObj = writerRoot;
    for (let t = 0; t < targetPointer.tokens.length - 1; t += 1) {
      const token = targetPointer.tokens[t]!;
      const existing = cursorObj.children.get(token);
      if (existing === undefined) {
        const nextObj: MutableWriterObject = { kind: "object", children: new Map() };
        cursorObj.children.set(token, nextObj);
        cursorObj = nextObj;
      } else if (existing.kind === "leaf") {
        failProjectionValidation(
          targetPointer.raw,
          "OVERLAPPING_TARGET_WRITE",
          `Target path "${targetPointer.raw}" overlaps parent writer at ${rulePath}`
        );
      } else {
        cursorObj = existing;
      }
    }
    const finalTargetToken = targetPointer.tokens[targetPointer.tokens.length - 1]!;
    if (cursorObj.children.has(finalTargetToken)) {
      failProjectionValidation(
        targetPointer.raw,
        "DUPLICATE_OR_OVERLAPPING_TARGET_WRITE",
        `Target path "${targetPointer.raw}" has multiple or overlapping writers at ${rulePath}`
      );
    }

    if (op === "copy") {
      assertAllowedKeys(rawRule, COPY_RULE_KEYS, rulePath);
      const sourcePointer = parseJsonPointer(rawRule.source_path, {
        fieldPath: `${rulePath}.source_path`,
        minTokens: 1,
        maxTokens: PROJECTION_MAX_TARGET_DEPTH
      });
      const sourceResolved = resolveSchemaPointer(sourceSchema, sourcePointer);
      const compatibilityReasons: string[] = [];
      if (
        !isSchemaSubschema(
          sourceResolved.node,
          sourceSchema,
          targetResolved.node,
          targetSchema,
          compatibilityReasons,
          targetPointer.raw
        )
      ) {
        failProjectionValidation(
          rulePath,
          "INCOMPATIBLE_COPY_TYPES",
          `Cannot prove source "${sourcePointer.raw}" fits target "${targetPointer.raw}": ${compatibilityReasons[0] ?? "incompatible"}`
        );
      }

      const sourceWorst = computeWorstCaseSchemaValueBytes(sourceResolved.node, sourceSchema);
      const targetWorst = computeWorstCaseSchemaValueBytes(targetResolved.node, targetSchema);
      const worstCaseBytes = Math.min(sourceWorst, targetWorst);

      const compiledRule: CompiledProjectionRule = Object.freeze({
        operation: "copy",
        targetPointer,
        sourcePointer,
        worstCaseBytes
      });
      compiledRules.push(compiledRule);
      normalizedRules.push(
        Object.freeze({
          operation: "copy",
          target_path: targetPointer.raw,
          source_path: sourcePointer.raw
        })
      );
      cursorObj.children.set(finalTargetToken, {
        kind: "leaf",
        rule: compiledRule,
        alwaysProvided: sourceResolved.alwaysRequired
      });
    } else if (op === "constant") {
      assertAllowedKeys(rawRule, CONSTANT_RULE_KEYS, rulePath);
      if (!Object.prototype.hasOwnProperty.call(rawRule, "value")) {
        failProjectionValidation(
          `${rulePath}.value`,
          "MISSING_CONSTANT_VALUE",
          `constant mapping requires "value" at ${rulePath}`
        );
      }
      const { policyLiteral, losslessAst } = normalizePolicyLiteralAndToLossless(
        rawRule.value,
        0,
        `${rulePath}.value`
      );
      validateLiteralAgainstTargetSubschema(
        losslessAst,
        targetResolved.node,
        targetSchema,
        `${rulePath}.value`
      );
      const exactConstantBytes = computeUtf8ByteLength(serializePolicyLiteralJson(policyLiteral));
      if (exactConstantBytes > DERIVED_MAX_CONTENT_BYTES) {
        failProjectionLimit(
          `${rulePath}.value`,
          `Constant value exceeds ${DERIVED_MAX_CONTENT_BYTES} bytes`
        );
      }

      const compiledRule: CompiledProjectionRule = Object.freeze({
        operation: "constant",
        targetPointer,
        value: policyLiteral,
        worstCaseBytes: exactConstantBytes
      });
      compiledRules.push(compiledRule);
      normalizedRules.push(
        Object.freeze({
          operation: "constant",
          target_path: targetPointer.raw,
          value: policyLiteral
        })
      );
      cursorObj.children.set(finalTargetToken, {
        kind: "leaf",
        rule: compiledRule,
        alwaysProvided: true
      });
    } else {
      assertAllowedKeys(rawRule, COPY_OR_DEFAULT_RULE_KEYS, rulePath);
      const sourcePointer = parseJsonPointer(rawRule.source_path, {
        fieldPath: `${rulePath}.source_path`,
        minTokens: 1,
        maxTokens: PROJECTION_MAX_TARGET_DEPTH
      });
      if (!Object.prototype.hasOwnProperty.call(rawRule, "default_value")) {
        failProjectionValidation(
          `${rulePath}.default_value`,
          "MISSING_DEFAULT_VALUE",
          `copy_or_default mapping requires "default_value" at ${rulePath}`
        );
      }
      const sourceResolved = resolveSchemaPointer(sourceSchema, sourcePointer);
      const compatibilityReasons: string[] = [];
      if (
        !isSchemaSubschema(
          sourceResolved.node,
          sourceSchema,
          targetResolved.node,
          targetSchema,
          compatibilityReasons,
          targetPointer.raw
        )
      ) {
        failProjectionValidation(
          rulePath,
          "INCOMPATIBLE_COPY_TYPES",
          `Cannot prove source "${sourcePointer.raw}" fits target "${targetPointer.raw}": ${compatibilityReasons[0] ?? "incompatible"}`
        );
      }

      const { policyLiteral, losslessAst } = normalizePolicyLiteralAndToLossless(
        rawRule.default_value,
        0,
        `${rulePath}.default_value`
      );
      validateLiteralAgainstTargetSubschema(
        losslessAst,
        targetResolved.node,
        targetSchema,
        `${rulePath}.default_value`
      );
      const exactDefaultBytes = computeUtf8ByteLength(serializePolicyLiteralJson(policyLiteral));
      const sourceWorst = computeWorstCaseSchemaValueBytes(sourceResolved.node, sourceSchema);
      const targetWorst = computeWorstCaseSchemaValueBytes(targetResolved.node, targetSchema);
      const worstCaseBytes = Math.max(Math.min(sourceWorst, targetWorst), exactDefaultBytes);

      const compiledRule: CompiledProjectionRule = Object.freeze({
        operation: "copy_or_default",
        targetPointer,
        sourcePointer,
        defaultValue: policyLiteral,
        worstCaseBytes
      });
      compiledRules.push(compiledRule);
      normalizedRules.push(
        Object.freeze({
          operation: "copy_or_default",
          target_path: targetPointer.raw,
          source_path: sourcePointer.raw,
          default_value: policyLiteral
        })
      );
      cursorObj.children.set(finalTargetToken, {
        kind: "leaf",
        rule: compiledRule,
        alwaysProvided: true
      });
    }
  }

  const compiledWriterRoot = checkTotalityAndSizeRecursive(
    writerRoot,
    targetRootNode,
    targetSchema,
    true,
    "$"
  );

  const provenOutputMaxBytes = compiledWriterRoot.worstCaseBytes;
  if (provenOutputMaxBytes > DERIVED_MAX_CONTENT_BYTES) {
    failProjectionLimit(
      fieldPath,
      `Proven derived projection max size (${provenOutputMaxBytes} bytes) exceeds ${DERIVED_MAX_CONTENT_BYTES} bytes`
    );
  }

  // Validate wire upper bound (conservatively assuming worst-case 256 KiB original if caller didn't supply smaller original size, OR caller's original size)
  const originalMaxForWire =
    options?.originalContentByteCount ??
    computeWorstCaseSchemaValueBytes(
      sourceSchema.normalizedProfile.root,
      sourceSchema,
      262_144
    );
  const maxWireEnvelopeUpperBoundBytes = computeDerivedWireEnvelopeUpperBoundBytes({
    originalContentByteCount: Math.max(1, originalMaxForWire),
    provenDerivedMaxBytes: provenOutputMaxBytes,
    eventType: options?.eventType
  });

  const normalizedMapping: NormalizedProjectionMappingProfile = Object.freeze({
    profile_schema_version: PROJECTION_PROFILE_SCHEMA_VERSION,
    compiler_profile_version: PROJECTION_COMPILER_VERSION,
    source_event_type_id: sourceEventTypeId,
    source_schema_version: sourceSchemaVersion,
    target_schema_version: targetSchemaVersion,
    mappings: Object.freeze(normalizedRules)
  });

  const hashedMapping = hashCanonicalJson(
    normalizedMapping as unknown as CanonicalJsonValue,
    fieldPath
  );

  if (definitionSha256 === undefined) {
    definitionSha256 = sha256Hex(hashedMapping.bytes);
  }

  return Object.freeze({
    profileSchemaVersion: PROJECTION_PROFILE_SCHEMA_VERSION,
    compilerProfileVersion: PROJECTION_COMPILER_VERSION,
    sourceEventTypeId,
    sourceSchemaVersion,
    targetSchemaVersion,
    definitionSha256,
    normalizedMapping,
    normalizedMappingSha256: hashedMapping.sha256,
    provenOutputMaxBytes,
    maxWireEnvelopeUpperBoundBytes,
    sourceSchema,
    targetSchema,
    mappings: Object.freeze(compiledRules),
    writerRoot: compiledWriterRoot
  });
}
