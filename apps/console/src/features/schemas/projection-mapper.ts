import {
  type LosslessJsonNode,
  formatLosslessJson,
  parseStrictLosslessJsonText
} from "../../utils/lossless-json.js";

export const PROJECTION_PROFILE_VERSION = "relayquill.lossless-projection.v1" as const;
export const PROJECTION_MAX_MAPPINGS = 32 as const;
export const PROJECTION_MAX_TARGET_DEPTH = 8 as const;

export type ProjectionConstantValue = string | boolean | null | { readonly rawNumber: string };

export type ProjectionMappingRule =
  | {
      readonly op: "copy";
      readonly sourcePointer: string;
      readonly targetPointer: string;
    }
  | {
      readonly op: "constant";
      readonly targetPointer: string;
      readonly value: ProjectionConstantValue;
    }
  | {
      readonly op: "copy_or_default";
      readonly sourcePointer: string;
      readonly targetPointer: string;
      readonly defaultValue: ProjectionConstantValue;
    };

export interface LosslessProjectionSpec {
  readonly profile_version: typeof PROJECTION_PROFILE_VERSION;
  readonly mappings: readonly ProjectionMappingRule[];
}

const SEGMENTED_POINTER_REGEX = /^\/[A-Za-z0-9_.-]+(?:\/[A-Za-z0-9_.-]+)*$/;

export function validateProjectionSpec(spec: LosslessProjectionSpec): readonly string[] {
  const errors: string[] = [];
  if (String(spec.profile_version) !== PROJECTION_PROFILE_VERSION) {
    errors.push(`profile_version must equal "${PROJECTION_PROFILE_VERSION}".`);
  }
  if (spec.mappings.length === 0 || spec.mappings.length > PROJECTION_MAX_MAPPINGS) {
    errors.push(`mappings must contain 1..${PROJECTION_MAX_MAPPINGS} rules.`);
  }

  const normalizedTargets: string[] = [];
  for (let i = 0; i < spec.mappings.length; i += 1) {
    const rule = spec.mappings[i];
    if (rule === undefined) {
      continue;
    }
    if (!SEGMENTED_POINTER_REGEX.test(rule.targetPointer)) {
      errors.push(`Mapping #${i + 1}: invalid targetPointer "${rule.targetPointer}".`);
    } else {
      const depth = rule.targetPointer.slice(1).split("/").length;
      if (depth > PROJECTION_MAX_TARGET_DEPTH) {
        errors.push(
          `Mapping #${i + 1}: targetPointer depth ${depth} exceeds max ${PROJECTION_MAX_TARGET_DEPTH}.`
        );
      }
      normalizedTargets.push(rule.targetPointer);
    }
    if ((rule.op === "copy" || rule.op === "copy_or_default") && !SEGMENTED_POINTER_REGEX.test(rule.sourcePointer)) {
      errors.push(`Mapping #${i + 1}: invalid sourcePointer "${rule.sourcePointer}".`);
    }
  }

  for (let i = 0; i < normalizedTargets.length; i += 1) {
    for (let j = i + 1; j < normalizedTargets.length; j += 1) {
      const a = normalizedTargets[i] ?? "";
      const b = normalizedTargets[j] ?? "";
      if (a === b || a.startsWith(`${b}/`) || b.startsWith(`${a}/`)) {
        errors.push(`Conflicting or overlapping target pointers: "${a}" and "${b}".`);
      }
    }
  }

  return errors;
}

function readSourcePointer(root: LosslessJsonNode, pointer: string): LosslessJsonNode | undefined {
  const segments = pointer.slice(1).split("/");
  let cur: LosslessJsonNode | undefined = root;
  for (const seg of segments) {
    if (cur === undefined || cur === null || typeof cur !== "object" || Array.isArray(cur)) {
      return undefined;
    }
    if ("kind" in cur && cur.kind === "lossless_number") {
      return undefined;
    }
    const rec = cur as { readonly [k: string]: LosslessJsonNode };
    if (!Object.prototype.hasOwnProperty.call(rec, seg)) {
      return undefined;
    }
    cur = rec[seg];
  }
  return cur;
}

function constantToLosslessNode(val: ProjectionConstantValue): LosslessJsonNode {
  if (val !== null && typeof val === "object" && "rawNumber" in val) {
    return {
      kind: "lossless_number",
      raw: val.rawNumber,
      precisionRisk: false
    };
  }
  return val;
}

function assignTargetPointer(
  root: Record<string, LosslessJsonNode>,
  pointer: string,
  value: LosslessJsonNode
): void {
  const segments = pointer.slice(1).split("/");
  let cur: Record<string, LosslessJsonNode> = root;
  for (let i = 0; i < segments.length - 1; i += 1) {
    const seg = segments[i];
    if (seg === undefined) {
      continue;
    }
    const existing = cur[seg];
    if (existing === undefined || existing === null || typeof existing !== "object" || Array.isArray(existing) || ("kind" in existing && existing.kind === "lossless_number")) {
      const nextObj: Record<string, LosslessJsonNode> = {};
      cur[seg] = nextObj;
      cur = nextObj;
    } else {
      cur = existing as Record<string, LosslessJsonNode>;
    }
  }
  const leaf = segments[segments.length - 1];
  if (leaf !== undefined) {
    cur[leaf] = value;
  }
}

/**
 * Applies a validated `relayquill.lossless-projection.v1` spec over lossless JSON source text,
 * preserving arbitrary-precision integers and decimals verbatim without JS Number conversion.
 */
export function applyLosslessProjectionSpec(
  spec: LosslessProjectionSpec,
  sourceJsonText: string
): {
  readonly ok: boolean;
  readonly errors: readonly string[];
  readonly outputJsonText?: string | undefined;
} {
  const errors = validateProjectionSpec(spec);
  if (errors.length > 0) {
    return { ok: false, errors };
  }

  let parsedSource: LosslessJsonNode;
  try {
    parsedSource = parseStrictLosslessJsonText(sourceJsonText).root;
  } catch (err) {
    return {
      ok: false,
      errors: [err instanceof Error ? err.message : "Invalid source JSON text."]
    };
  }

  const out: Record<string, LosslessJsonNode> = {};
  const missingErrors: string[] = [];

  for (const rule of spec.mappings) {
    if (rule.op === "constant") {
      assignTargetPointer(out, rule.targetPointer, constantToLosslessNode(rule.value));
      continue;
    }
    const copied = readSourcePointer(parsedSource, rule.sourcePointer);
    if (copied !== undefined) {
      assignTargetPointer(out, rule.targetPointer, copied);
    } else if (rule.op === "copy_or_default") {
      assignTargetPointer(out, rule.targetPointer, constantToLosslessNode(rule.defaultValue));
    } else {
      missingErrors.push(`Required sourcePointer "${rule.sourcePointer}" missing in sample JSON.`);
    }
  }

  if (missingErrors.length > 0) {
    return { ok: false, errors: missingErrors };
  }

  return {
    ok: true,
    errors: [],
    outputJsonText: formatLosslessJson(out, 2)
  };
}
