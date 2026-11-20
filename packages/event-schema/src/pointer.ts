import {
  ValidationDomainError,
  computeUtf8ByteLength,
  hasLoneSurrogate
} from "@relayquill/domain";

export const JSON_POINTER_MAX_UTF8_BYTES = 1_024 as const;
export const JSON_POINTER_MAX_TOKENS = 8 as const;
export const JSON_POINTER_MAX_TOKEN_BYTES = 128 as const;

export interface ParsedJsonPointer {
  readonly raw: string;
  readonly tokens: readonly string[];
}

export interface JsonPointerParseOptions {
  readonly fieldPath?: string | undefined;
  readonly minTokens?: number | undefined;
  readonly maxTokens?: number | undefined;
  readonly maxPointerBytes?: number | undefined;
  readonly maxTokenBytes?: number | undefined;
}

export type JsonPointerResolution =
  | { readonly present: true; readonly value: unknown }
  | { readonly present: false; readonly value: undefined };

export function decodeJsonPointerToken(rawToken: string, fieldPath = "pointer"): string {
  let decoded = "";
  for (let i = 0; i < rawToken.length; i += 1) {
    const ch = rawToken[i]!;
    if (ch === "~") {
      const next = i + 1 < rawToken.length ? rawToken[i + 1] : undefined;
      if (next === "0") {
        decoded += "~";
        i += 1;
      } else if (next === "1") {
        decoded += "/";
        i += 1;
      } else {
        throw new ValidationDomainError({
          code: "INVALID_VALUE",
          message: `Malformed tilde escape in JSON Pointer at ${fieldPath}`,
          fieldErrors: [{ path: fieldPath, code: "INVALID_VALUE" }]
        });
      }
    } else {
      decoded += ch;
    }
  }
  return decoded;
}

export function encodeJsonPointerToken(token: string): string {
  let encoded = "";
  for (let i = 0; i < token.length; i += 1) {
    const ch = token[i]!;
    if (ch === "~") {
      encoded += "~0";
    } else if (ch === "/") {
      encoded += "~1";
    } else {
      encoded += ch;
    }
  }
  return encoded;
}

export function formatJsonPointer(tokens: readonly string[]): string {
  if (tokens.length === 0) {
    return "";
  }
  return `/${tokens.map(encodeJsonPointerToken).join("/")}`;
}

export function parseJsonPointer(
  pointer: unknown,
  options?: JsonPointerParseOptions
): ParsedJsonPointer {
  const fieldPath = options?.fieldPath ?? "pointer";
  const minTokens = options?.minTokens ?? 1;
  const maxTokens = options?.maxTokens ?? JSON_POINTER_MAX_TOKENS;
  const maxPointerBytes = options?.maxPointerBytes ?? JSON_POINTER_MAX_UTF8_BYTES;
  const maxTokenBytes = options?.maxTokenBytes ?? JSON_POINTER_MAX_TOKEN_BYTES;

  if (typeof pointer !== "string" || hasLoneSurrogate(pointer)) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Expected valid UTF-8 JSON Pointer string at ${fieldPath}`,
      fieldErrors: [{ path: fieldPath, code: "INVALID_VALUE" }]
    });
  }

  const pointerBytes = computeUtf8ByteLength(pointer);
  if (pointerBytes > maxPointerBytes) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `JSON Pointer exceeds ${maxPointerBytes} UTF-8 bytes at ${fieldPath}`,
      fieldErrors: [{ path: fieldPath, code: "INVALID_VALUE" }]
    });
  }

  if (pointer === "") {
    if (minTokens > 0) {
      throw new ValidationDomainError({
        code: "INVALID_VALUE",
        message: `JSON Pointer must reference a property path (at least ${minTokens} token) at ${fieldPath}`,
        fieldErrors: [{ path: fieldPath, code: "INVALID_VALUE" }]
      });
    }
    return Object.freeze({ raw: "", tokens: Object.freeze([]) });
  }

  if (!pointer.startsWith("/")) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `JSON Pointer must begin with '/' at ${fieldPath}`,
      fieldErrors: [{ path: fieldPath, code: "INVALID_VALUE" }]
    });
  }

  const rawTokens = pointer.slice(1).split("/");
  if (rawTokens.length < minTokens || rawTokens.length > maxTokens) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `JSON Pointer depth ${rawTokens.length} outside [${minTokens}, ${maxTokens}] at ${fieldPath}`,
      fieldErrors: [{ path: fieldPath, code: "INVALID_VALUE" }]
    });
  }

  const decodedTokens: string[] = [];
  for (let i = 0; i < rawTokens.length; i += 1) {
    const decoded = decodeJsonPointerToken(rawTokens[i]!, fieldPath);
    const tokenBytes = computeUtf8ByteLength(decoded);
    if (tokenBytes > maxTokenBytes) {
      throw new ValidationDomainError({
        code: "INVALID_VALUE",
        message: `JSON Pointer token exceeds ${maxTokenBytes} UTF-8 bytes at ${fieldPath}`,
        fieldErrors: [{ path: fieldPath, code: "INVALID_VALUE" }]
      });
    }
    decodedTokens.push(decoded);
  }

  return Object.freeze({
    raw: pointer,
    tokens: Object.freeze(decodedTokens)
  });
}

export function resolveJsonPointer(
  root: unknown,
  pointer: ParsedJsonPointer | string
): JsonPointerResolution {
  const parsed = typeof pointer === "string" ? parseJsonPointer(pointer, { minTokens: 0 }) : pointer;
  let current: unknown = root;

  for (const token of parsed.tokens) {
    if (current === null || typeof current !== "object" || Array.isArray(current)) {
      return { present: false, value: undefined };
    }
    const proto: unknown = Object.getPrototypeOf(current);
    if (proto !== Object.prototype && proto !== null) {
      return { present: false, value: undefined };
    }
    if (!Object.prototype.hasOwnProperty.call(current, token)) {
      return { present: false, value: undefined };
    }
    current = (current as Record<string, unknown>)[token];
  }

  return { present: true, value: current };
}
