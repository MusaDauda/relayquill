import {
  InvariantViolationError,
  ORDERING_KEY_MAX_UTF8_BYTES,
  type OrderingDomainId,
  SUBSCRIPTION_MAX_SCHEMA_VERSIONS,
  type Sha256Hex,
  type SubscriptionId,
  ValidationDomainError,
  computeUtf8ByteLength,
  hasLoneSurrogate
} from "@relayquill/domain";
import {
  type CanonicalJsonValue,
  computeOrderingKeySha256,
  hashCanonicalJson
} from "@relayquill/contracts";
import { type LosslessJsonValue, isPlainObjectRecord, parseStrictLosslessJson } from "./parser.js";
import {
  JSON_POINTER_MAX_TOKENS,
  type ParsedJsonPointer,
  parseJsonPointer,
  resolveJsonPointer
} from "./pointer.js";
import {
  type CompiledEventSchema,
  SCHEMA_MAX_RAW_BYTES,
  resolveSchemaPointer
} from "./profile.js";

export const ORDERING_EXTRACTOR_PROFILE_VERSION = "relayquill.ordering-extractor.v1" as const;

export interface NormalizedOrderingExtractor {
  readonly profile_version: typeof ORDERING_EXTRACTOR_PROFILE_VERSION;
  readonly pointer: string;
  readonly tokens: readonly string[];
}

export interface CompiledOrderingExtractor {
  readonly profileVersion: typeof ORDERING_EXTRACTOR_PROFILE_VERSION;
  readonly pointer: ParsedJsonPointer;
  readonly normalizedExtractor: NormalizedOrderingExtractor;
  readonly extractorSha256: Sha256Hex;
}

export interface OrderingDigestScope {
  readonly orderingDomainId: OrderingDomainId | string;
  readonly subscriptionId: SubscriptionId | string;
  readonly consumerContractScope: string;
}

export interface ExtractedOrderingKeyResult {
  readonly orderingKey: string;
  readonly byteCount: number;
  readonly orderingKeySha256?: Sha256Hex | undefined;
}

const EXTRACTOR_OBJECT_KEYS = new Set(["profile_version", "pointer", "tokens"]);

function failExtractorValidation(path: string, code: string, message: string): never {
  throw new ValidationDomainError({
    code: "INVALID_VALUE",
    message,
    fieldErrors: [{ path, code }]
  });
}

export function compileOrderingExtractor(
  input: unknown,
  schemas?: readonly CompiledEventSchema[],
  options?: { readonly fieldPath?: string | undefined }
): CompiledOrderingExtractor {
  const fieldPath = options?.fieldPath ?? "ordering_extractor";

  let rawValue = input;
  if (input instanceof Uint8Array) {
    rawValue = parseStrictLosslessJson(input, {
      fieldPath,
      minDecodedBytes: 2,
      maxDecodedBytes: SCHEMA_MAX_RAW_BYTES,
      maxDepth: 8,
      maxNodes: 64
    }).value;
  }

  let pointerRaw: unknown;
  if (typeof rawValue === "string") {
    pointerRaw = rawValue;
  } else if (isPlainObjectRecord(rawValue)) {
    for (const key of Object.keys(rawValue)) {
      if (!EXTRACTOR_OBJECT_KEYS.has(key)) {
        failExtractorValidation(
          `${fieldPath}.${key}`,
          "UNSUPPORTED_EXTRACTOR_FIELD",
          `Unsupported field "${key}" in ordering extractor at ${fieldPath}`
        );
      }
    }
    if (
      rawValue.profile_version !== undefined &&
      rawValue.profile_version !== ORDERING_EXTRACTOR_PROFILE_VERSION
    ) {
      throw new ValidationDomainError({
        code: "UNSUPPORTED_SCHEMA_VERSION",
        message: `Unsupported ordering extractor profile_version; expected ${ORDERING_EXTRACTOR_PROFILE_VERSION}`,
        fieldErrors: [{ path: `${fieldPath}.profile_version`, code: "UNSUPPORTED_SCHEMA_VERSION" }]
      });
    }
    pointerRaw = rawValue.pointer;
  } else {
    failExtractorValidation(
      fieldPath,
      "INVALID_EXTRACTOR",
      `Ordering extractor must be a JSON Pointer string or normalized extractor object at ${fieldPath}`
    );
  }

  const pointer = parseJsonPointer(pointerRaw, {
    fieldPath: `${fieldPath}.pointer`,
    minTokens: 1,
    maxTokens: JSON_POINTER_MAX_TOKENS
  });

  if (isPlainObjectRecord(rawValue) && rawValue.tokens !== undefined) {
    if (
      !Array.isArray(rawValue.tokens) ||
      rawValue.tokens.length !== pointer.tokens.length ||
      rawValue.tokens.some((tok, idx) => tok !== pointer.tokens[idx])
    ) {
      failExtractorValidation(
        `${fieldPath}.tokens`,
        "EXTRACTOR_TOKEN_MISMATCH",
        `Ordering extractor tokens do not match pointer at ${fieldPath}`
      );
    }
  }

  const normalizedExtractor: NormalizedOrderingExtractor = Object.freeze({
    profile_version: ORDERING_EXTRACTOR_PROFILE_VERSION,
    pointer: pointer.raw,
    tokens: pointer.tokens
  });

  const hashed = hashCanonicalJson(
    normalizedExtractor as unknown as CanonicalJsonValue,
    fieldPath
  );

  const compiled: CompiledOrderingExtractor = Object.freeze({
    profileVersion: ORDERING_EXTRACTOR_PROFILE_VERSION,
    pointer,
    normalizedExtractor,
    extractorSha256: hashed.sha256
  });

  if (schemas !== undefined) {
    validateOrderingExtractorAgainstSchemas(compiled, schemas);
  }

  return compiled;
}

export function validateOrderingExtractorAgainstSchemas(
  extractor: CompiledOrderingExtractor,
  schemas: readonly CompiledEventSchema[]
): void {
  if (schemas.length === 0 || schemas.length > SUBSCRIPTION_MAX_SCHEMA_VERSIONS) {
    failExtractorValidation(
      "schemas",
      "INVALID_SCHEMA_SELECTION",
      `Ordering extractor validation requires 1..${SUBSCRIPTION_MAX_SCHEMA_VERSIONS} selected schemas`
    );
  }

  for (let i = 0; i < schemas.length; i += 1) {
    const schema = schemas[i]!;
    const resolved = resolveSchemaPointer(schema, extractor.pointer);
    if (!resolved.alwaysRequired) {
      failExtractorValidation(
        extractor.pointer.raw,
        "ORDERING_FIELD_NOT_REQUIRED",
        `Ordering extractor path "${extractor.pointer.raw}" must be required at every step in schema[${i}]`
      );
    }
    if (resolved.node.kind !== "string" || resolved.node.nullable) {
      failExtractorValidation(
        extractor.pointer.raw,
        "ORDERING_FIELD_NOT_NONNULL_STRING",
        `Ordering extractor path "${extractor.pointer.raw}" must be a non-null string in schema[${i}]`
      );
    }
    if (resolved.node.minLength < 1) {
      failExtractorValidation(
        extractor.pointer.raw,
        "ORDERING_FIELD_ALLOWS_EMPTY",
        `Ordering extractor path "${extractor.pointer.raw}" must require minLength >= 1 in schema[${i}]`
      );
    }
    if (resolved.node.maxLength > ORDERING_KEY_MAX_UTF8_BYTES) {
      failExtractorValidation(
        extractor.pointer.raw,
        "ORDERING_FIELD_EXCEEDS_MAX_BYTES",
        `Ordering extractor path "${extractor.pointer.raw}" maxLength (${resolved.node.maxLength}) exceeds ${ORDERING_KEY_MAX_UTF8_BYTES} bytes in schema[${i}]`
      );
    }
  }
}

export function extractOrderingKey(
  eventValue: LosslessJsonValue,
  extractor: CompiledOrderingExtractor,
  digestScope?: OrderingDigestScope
): ExtractedOrderingKeyResult {
  const resolved = resolveJsonPointer(eventValue, extractor.pointer);
  if (!resolved.present) {
    throw new InvariantViolationError({
      code: "INVARIANT_VIOLATION",
      message: `Ordering key path "${extractor.pointer.raw}" is missing from event payload`,
      fieldErrors: [{ path: extractor.pointer.raw, code: "ORDERING_KEY_MISSING" }]
    });
  }

  if (typeof resolved.value !== "string" || hasLoneSurrogate(resolved.value)) {
    throw new InvariantViolationError({
      code: "INVARIANT_VIOLATION",
      message: `Ordering key at "${extractor.pointer.raw}" must be a valid non-null string`,
      fieldErrors: [{ path: extractor.pointer.raw, code: "ORDERING_KEY_INVALID_TYPE" }]
    });
  }

  const byteCount = computeUtf8ByteLength(resolved.value);
  if (byteCount < 1 || byteCount > ORDERING_KEY_MAX_UTF8_BYTES) {
    throw new InvariantViolationError({
      code: "INVARIANT_VIOLATION",
      message: `Ordering key at "${extractor.pointer.raw}" UTF-8 byte length (${byteCount}) outside [1, ${ORDERING_KEY_MAX_UTF8_BYTES}]`,
      fieldErrors: [{ path: extractor.pointer.raw, code: "ORDERING_KEY_BYTE_LIMIT" }]
    });
  }

  let orderingKeySha256: Sha256Hex | undefined;
  if (digestScope !== undefined) {
    orderingKeySha256 = computeOrderingKeySha256({
      ordering_domain_id: digestScope.orderingDomainId,
      subscription_id: digestScope.subscriptionId,
      consumer_contract_scope: digestScope.consumerContractScope,
      ordering_key: resolved.value
    });
  }

  return Object.freeze({
    orderingKey: resolved.value,
    byteCount,
    ...(orderingKeySha256 !== undefined ? { orderingKeySha256 } : {})
  });
}
