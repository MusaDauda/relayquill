import {
  type LosslessJsonNode,
  parseStrictLosslessJsonText
} from "../../utils/lossless-json.js";

export const FILTER_PROFILE_VERSION = "relayquill.filter.v1" as const;
export const FILTER_MAX_LEAVES = 32 as const;
export const FILTER_MAX_BOOLEAN_DEPTH = 4 as const;
export const FILTER_MAX_BOOLEAN_CHILDREN = 16 as const;
export const FILTER_MAX_IN_LIST = 32 as const;

export type FilterScalarValue = string | number | boolean | null;

export type FilterAstNode =
  | {
      readonly op: "eq" | "neq";
      readonly pointer: string;
      readonly value: FilterScalarValue;
    }
  | {
      readonly op: "in" | "not_in";
      readonly pointer: string;
      readonly values: readonly FilterScalarValue[];
    }
  | {
      readonly op: "exists";
      readonly pointer: string;
      readonly value: boolean;
    }
  | {
      readonly op: "prefix";
      readonly pointer: string;
      readonly value: string;
    }
  | {
      readonly op: "and" | "or";
      readonly children: readonly FilterAstNode[];
    }
  | {
      readonly op: "not";
      readonly child: FilterAstNode;
    };

export interface FilterDefinition {
  readonly version: typeof FILTER_PROFILE_VERSION;
  readonly root: FilterAstNode;
}

const POINTER_REGEX = /^\/[A-Za-z0-9_.-]+(?:\/[A-Za-z0-9_.-]+)*$/;

export function isValidFilterPointer(pointer: string): boolean {
  return POINTER_REGEX.test(pointer) && pointer.length <= 256;
}

export function validateFilterDefinition(def: FilterDefinition): readonly string[] {
  const errors: string[] = [];
  if (String(def.version) !== FILTER_PROFILE_VERSION) {
    errors.push(`Filter version must equal "${FILTER_PROFILE_VERSION}".`);
  }

  let leafCount = 0;

  const visit = (node: FilterAstNode, depth: number): void => {
    switch (node.op) {
      case "and":
      case "or": {
        if (depth > FILTER_MAX_BOOLEAN_DEPTH) {
          errors.push(`Boolean nesting depth exceeds maximum (${FILTER_MAX_BOOLEAN_DEPTH}).`);
        }
        if (node.children.length === 0 || node.children.length > FILTER_MAX_BOOLEAN_CHILDREN) {
          errors.push(
            `"${node.op}" node must contain 1..${FILTER_MAX_BOOLEAN_CHILDREN} children (got ${node.children.length}).`
          );
        }
        for (const child of node.children) {
          visit(child, depth + 1);
        }
        return;
      }
      case "not": {
        if (depth > FILTER_MAX_BOOLEAN_DEPTH) {
          errors.push(`Boolean nesting depth exceeds maximum (${FILTER_MAX_BOOLEAN_DEPTH}).`);
        }
        visit(node.child, depth + 1);
        return;
      }
      case "eq":
      case "neq":
      case "exists": {
        leafCount += 1;
        if (leafCount > FILTER_MAX_LEAVES) {
          errors.push(`Leaf predicate count exceeds maximum (${FILTER_MAX_LEAVES}).`);
        }
        if (!isValidFilterPointer(node.pointer)) {
          errors.push(`Invalid JSON pointer "${node.pointer}"; expected /segment/path.`);
        }
        return;
      }
      case "in":
      case "not_in": {
        leafCount += 1;
        if (leafCount > FILTER_MAX_LEAVES) {
          errors.push(`Leaf predicate count exceeds maximum (${FILTER_MAX_LEAVES}).`);
        }
        if (!isValidFilterPointer(node.pointer)) {
          errors.push(`Invalid JSON pointer "${node.pointer}"; expected /segment/path.`);
        }
        if (node.values.length === 0 || node.values.length > FILTER_MAX_IN_LIST) {
          errors.push(
            `"${node.op}" list length must be 1..${FILTER_MAX_IN_LIST} (got ${node.values.length}).`
          );
        }
        return;
      }
      case "prefix": {
        leafCount += 1;
        if (leafCount > FILTER_MAX_LEAVES) {
          errors.push(`Leaf predicate count exceeds maximum (${FILTER_MAX_LEAVES}).`);
        }
        if (!isValidFilterPointer(node.pointer)) {
          errors.push(`Invalid JSON pointer "${node.pointer}"; expected /segment/path.`);
        }
        if (node.value.length === 0) {
          errors.push(`Prefix predicate on "${node.pointer}" requires a non-empty string prefix.`);
        }
        return;
      }
    }
  };

  visit(def.root, 1);
  return errors;
}

function readLosslessAtPointer(root: LosslessJsonNode, pointer: string): LosslessJsonNode | undefined {
  const segments = pointer.slice(1).split("/");
  let cur: LosslessJsonNode | undefined = root;
  for (const seg of segments) {
    if (cur === undefined || cur === null || typeof cur !== "object" || Array.isArray(cur)) {
      return undefined;
    }
    if ("kind" in cur && cur.kind === "lossless_number") {
      return undefined;
    }
    const obj = cur as { readonly [key: string]: LosslessJsonNode };
    if (!Object.prototype.hasOwnProperty.call(obj, seg)) {
      return undefined;
    }
    cur = obj[seg];
  }
  return cur;
}

function scalarMatchesLossless(node: LosslessJsonNode | undefined, target: FilterScalarValue): boolean {
  if (node === undefined) {
    return false;
  }
  if (target === null) {
    return node === null;
  }
  if (typeof target === "boolean" || typeof target === "string") {
    return node === target;
  }
  if (typeof node === "object" && node !== null && "kind" in node && node.kind === "lossless_number") {
    return node.raw === String(target);
  }
  return false;
}

/**
 * Evaluates a `relayquill.filter.v1` AST against lossless JSON payload text without IEEE-754 float narrowing.
 */
export function evaluateFilterOnLosslessJson(
  def: FilterDefinition,
  rawJsonText: string
): { readonly matched: boolean; readonly validationErrors: readonly string[] } {
  const validationErrors = validateFilterDefinition(def);
  if (validationErrors.length > 0) {
    return { matched: false, validationErrors };
  }

  let parsedRoot: LosslessJsonNode;
  try {
    parsedRoot = parseStrictLosslessJsonText(rawJsonText).root;
  } catch (err) {
    return {
      matched: false,
      validationErrors: [err instanceof Error ? err.message : "Invalid payload JSON."]
    };
  }

  const evalNode = (node: FilterAstNode): boolean => {
    switch (node.op) {
      case "and":
        return node.children.every(evalNode);
      case "or":
        return node.children.some(evalNode);
      case "not":
        return !evalNode(node.child);
      case "exists": {
        const present = readLosslessAtPointer(parsedRoot, node.pointer) !== undefined;
        return node.value ? present : !present;
      }
      case "eq":
        return scalarMatchesLossless(readLosslessAtPointer(parsedRoot, node.pointer), node.value);
      case "neq": {
        const val = readLosslessAtPointer(parsedRoot, node.pointer);
        return val !== undefined && !scalarMatchesLossless(val, node.value);
      }
      case "in": {
        const val = readLosslessAtPointer(parsedRoot, node.pointer);
        return node.values.some((candidate) => scalarMatchesLossless(val, candidate));
      }
      case "not_in": {
        const val = readLosslessAtPointer(parsedRoot, node.pointer);
        return val !== undefined && !node.values.some((candidate) => scalarMatchesLossless(val, candidate));
      }
      case "prefix": {
        const val = readLosslessAtPointer(parsedRoot, node.pointer);
        return typeof val === "string" && val.startsWith(node.value);
      }
    }
  };

  return {
    matched: evalNode(def.root),
    validationErrors: []
  };
}
