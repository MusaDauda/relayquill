import {
  EVENT_MAX_CONTENT_BYTES,
  EVENT_MAX_JSON_DEPTH,
  EVENT_MAX_JSON_NODES,
  EVENT_MAX_NUMERIC_TOKEN_BYTES,
  LimitExceededDomainError,
  type Sha256Hex,
  ValidationDomainError,
  computeUtf8ByteLength,
  hasLoneSurrogate
} from "@relayquill/domain";
import {
  decodeUtf8BytesStrict,
  encodeUtf8Bytes,
  sha256Hex
} from "@relayquill/contracts";
import { LosslessNumber, parse as losslessParse } from "lossless-json";

export {
  EVENT_MAX_CONTENT_BYTES,
  EVENT_MAX_JSON_DEPTH,
  EVENT_MAX_JSON_NODES,
  EVENT_MAX_NUMERIC_TOKEN_BYTES
};

export type LosslessJsonPrimitive = null | boolean | string | LosslessNumber;
export type LosslessJsonValue =
  | LosslessJsonPrimitive
  | readonly LosslessJsonValue[]
  | { readonly [key: string]: LosslessJsonValue };

export interface StrictLosslessJsonParseOptions {
  readonly fieldPath?: string | undefined;
  readonly minDecodedBytes?: number | undefined;
  readonly maxDecodedBytes?: number | undefined;
  readonly maxDepth?: number | undefined;
  readonly maxNodes?: number | undefined;
  readonly maxNumericTokenBytes?: number | undefined;
  readonly requireObjectRoot?: boolean | undefined;
}

export interface ParsedLosslessJsonResult<T extends LosslessJsonValue = LosslessJsonValue> {
  readonly value: T;
  readonly rawBytes: Uint8Array;
  readonly byteCount: number;
  readonly sha256: Sha256Hex;
  readonly nodeCount: number;
  readonly maxObservedDepth: number;
}

type Frame =
  | { kind: "object"; expecting: "key_or_end" | "colon" | "value" | "comma_or_end"; seenKeys: Set<string> }
  | { kind: "array"; expecting: "value_or_end" | "comma_or_end" };

interface StructuralScanResult {
  readonly nodeCount: number;
  readonly maxObservedDepth: number;
}

function isJsonWhitespace(code: number): boolean {
  return code === 0x20 || code === 0x09 || code === 0x0a || code === 0x0d;
}

function isDigit(code: number): boolean {
  return code >= 0x30 && code <= 0x39;
}

function isDigit19(code: number): boolean {
  return code >= 0x31 && code <= 0x39;
}

function parseHex4(text: string, start: number): number {
  let acc = 0;
  for (let i = 0; i < 4; i += 1) {
    const code = text.charCodeAt(start + i);
    let nib = -1;
    if (code >= 0x30 && code <= 0x39) {
      nib = code - 0x30;
    } else if (code >= 0x61 && code <= 0x66) {
      nib = code - 0x61 + 10;
    } else if (code >= 0x41 && code <= 0x46) {
      nib = code - 0x41 + 10;
    }
    if (nib < 0) {
      return -1;
    }
    acc = (acc << 4) | nib;
  }
  return acc;
}

function scanJsonTextStrictly(
  text: string,
  options: {
    readonly fieldPath: string;
    readonly maxDepth: number;
    readonly maxNodes: number;
    readonly maxNumericTokenBytes: number;
  }
): StructuralScanResult {
  const { fieldPath, maxDepth, maxNodes, maxNumericTokenBytes } = options;
  const len = text.length;
  let pos = 0;
  let nodes = 0;
  let maxObservedDepth = 0;
  const stack: Frame[] = [];

  function failSyntax(message: string): never {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `${message} in ${fieldPath}`,
      fieldErrors: [{ path: fieldPath, code: "INVALID_VALUE" }]
    });
  }

  function failLimit(message: string): never {
    throw new LimitExceededDomainError({
      code: "SCHEMA_EVALUATION_LIMIT",
      message: `${message} in ${fieldPath}`,
      fieldErrors: [{ path: fieldPath, code: "SCHEMA_EVALUATION_LIMIT" }]
    });
  }

  function skipWs(): void {
    while (pos < len && isJsonWhitespace(text.charCodeAt(pos))) {
      pos += 1;
    }
  }

  function countNode(): void {
    nodes += 1;
    if (nodes > maxNodes) {
      failLimit(`JSON node count exceeds limit ${maxNodes}`);
    }
  }

  function scanString(): string {
    if (pos >= len || text.charCodeAt(pos) !== 0x22) {
      failSyntax("Expected opening quote");
    }
    pos += 1;
    const parts: string[] = [];
    let sliceStart = pos;

    while (pos < len) {
      const ch = text.charCodeAt(pos);
      if (ch === 0x22) {
        if (pos > sliceStart) {
          parts.push(text.slice(sliceStart, pos));
        }
        pos += 1;
        return parts.length === 1 ? parts[0]! : parts.join("");
      }
      if (ch < 0x20) {
        failSyntax("Unescaped control character in JSON string");
      }
      if (ch === 0x5c) {
        if (pos > sliceStart) {
          parts.push(text.slice(sliceStart, pos));
        }
        pos += 1;
        if (pos >= len) {
          failSyntax("Unterminated escape sequence in JSON string");
        }
        const esc = text.charCodeAt(pos);
        pos += 1;
        switch (esc) {
          case 0x22:
            parts.push("\"");
            break;
          case 0x5c:
            parts.push("\\");
            break;
          case 0x2f:
            parts.push("/");
            break;
          case 0x62:
            parts.push("\b");
            break;
          case 0x66:
            parts.push("\f");
            break;
          case 0x6e:
            parts.push("\n");
            break;
          case 0x72:
            parts.push("\r");
            break;
          case 0x74:
            parts.push("\t");
            break;
          case 0x75: {
            if (pos + 4 > len) {
              failSyntax("Invalid \\u escape sequence");
            }
            const codeUnit = parseHex4(text, pos);
            if (codeUnit < 0) {
              failSyntax("Invalid hex digits in \\u escape sequence");
            }
            pos += 4;
            if (codeUnit >= 0xd800 && codeUnit <= 0xdbff) {
              if (pos + 6 > len || text.charCodeAt(pos) !== 0x5c || text.charCodeAt(pos + 1) !== 0x75) {
                failSyntax("Unpaired UTF-16 high surrogate in JSON string");
              }
              const lowUnit = parseHex4(text, pos + 2);
              if (lowUnit < 0xdc00 || lowUnit > 0xdfff) {
                failSyntax("Invalid UTF-16 low surrogate in JSON string");
              }
              pos += 6;
              parts.push(String.fromCharCode(codeUnit, lowUnit));
            } else if (codeUnit >= 0xdc00 && codeUnit <= 0xdfff) {
              failSyntax("Unpaired UTF-16 low surrogate in JSON string");
            } else {
              parts.push(String.fromCharCode(codeUnit));
            }
            break;
          }
          default:
            failSyntax("Invalid escape sequence in JSON string");
        }
        sliceStart = pos;
      } else if (ch >= 0xd800 && ch <= 0xdbff) {
        const next = pos + 1 < len ? text.charCodeAt(pos + 1) : 0;
        if (next < 0xdc00 || next > 0xdfff) {
          failSyntax("Unpaired UTF-16 high surrogate in JSON string");
        }
        pos += 2;
      } else if (ch >= 0xdc00 && ch <= 0xdfff) {
        failSyntax("Unpaired UTF-16 low surrogate in JSON string");
      } else {
        pos += 1;
      }
    }
    failSyntax("Unterminated JSON string");
  }

  function scanNumber(): void {
    const start = pos;
    if (text.charCodeAt(pos) === 0x2d) {
      pos += 1;
    }
    if (pos >= len) {
      failSyntax("Invalid JSON number");
    }
    if (text.charCodeAt(pos) === 0x30) {
      pos += 1;
      if (pos < len && isDigit(text.charCodeAt(pos))) {
        failSyntax("Leading zero in JSON number");
      }
    } else if (isDigit19(text.charCodeAt(pos))) {
      while (pos < len && isDigit(text.charCodeAt(pos))) {
        pos += 1;
      }
    } else {
      failSyntax("Invalid JSON number");
    }

    if (pos < len && text.charCodeAt(pos) === 0x2e) {
      pos += 1;
      if (pos >= len || !isDigit(text.charCodeAt(pos))) {
        failSyntax("Invalid fractional part in JSON number");
      }
      while (pos < len && isDigit(text.charCodeAt(pos))) {
        pos += 1;
      }
    }

    if (pos < len && (text.charCodeAt(pos) === 0x65 || text.charCodeAt(pos) === 0x45)) {
      pos += 1;
      if (pos < len && (text.charCodeAt(pos) === 0x2b || text.charCodeAt(pos) === 0x2d)) {
        pos += 1;
      }
      if (pos >= len || !isDigit(text.charCodeAt(pos))) {
        failSyntax("Invalid exponent in JSON number");
      }
      while (pos < len && isDigit(text.charCodeAt(pos))) {
        pos += 1;
      }
    }

    if (pos - start > maxNumericTokenBytes) {
      failLimit(`Numeric token length ${pos - start} exceeds ${maxNumericTokenBytes} bytes`);
    }
  }

  function afterValueClosed(): void {
    const parent = stack[stack.length - 1];
    if (parent !== undefined) {
      parent.expecting = "comma_or_end";
    }
  }

  function startValue(): boolean {
    skipWs();
    if (pos >= len) {
      failSyntax("Unexpected end of JSON input");
    }
    const ch = text.charCodeAt(pos);
    if (ch === 0x7b) {
      countNode();
      if (stack.length + 1 > maxDepth) {
        failLimit(`JSON nesting depth exceeds limit ${maxDepth}`);
      }
      stack.push({ kind: "object", expecting: "key_or_end", seenKeys: new Set<string>() });
      if (stack.length > maxObservedDepth) {
        maxObservedDepth = stack.length;
      }
      pos += 1;
      return true;
    }
    if (ch === 0x5b) {
      countNode();
      if (stack.length + 1 > maxDepth) {
        failLimit(`JSON nesting depth exceeds limit ${maxDepth}`);
      }
      stack.push({ kind: "array", expecting: "value_or_end" });
      if (stack.length > maxObservedDepth) {
        maxObservedDepth = stack.length;
      }
      pos += 1;
      return true;
    }
    if (ch === 0x22) {
      countNode();
      scanString();
      afterValueClosed();
      return false;
    }
    if (ch === 0x2d || isDigit(ch)) {
      countNode();
      scanNumber();
      afterValueClosed();
      return false;
    }
    if (ch === 0x74 && text.startsWith("true", pos)) {
      countNode();
      pos += 4;
      afterValueClosed();
      return false;
    }
    if (ch === 0x66 && text.startsWith("false", pos)) {
      countNode();
      pos += 5;
      afterValueClosed();
      return false;
    }
    if (ch === 0x6e && text.startsWith("null", pos)) {
      countNode();
      pos += 4;
      afterValueClosed();
      return false;
    }
    failSyntax("Unexpected token in JSON");
  }

  startValue();

  while (stack.length > 0) {
    const top = stack[stack.length - 1]!;
    skipWs();
    if (pos >= len) {
      failSyntax("Unterminated JSON container");
    }
    const ch = text.charCodeAt(pos);

    if (top.kind === "array") {
      if (top.expecting === "value_or_end") {
        if (ch === 0x5d) {
          pos += 1;
          stack.pop();
          afterValueClosed();
          continue;
        }
        startValue();
        continue;
      }
      if (ch === 0x5d) {
        pos += 1;
        stack.pop();
        afterValueClosed();
        continue;
      }
      if (ch === 0x2c) {
        pos += 1;
        skipWs();
        if (pos >= len || text.charCodeAt(pos) === 0x5d) {
          failSyntax("Expected array item after comma");
        }
        startValue();
        continue;
      }
      failSyntax("Expected ',' or ']' in JSON array");
    }

    // Object state machine
    if (top.expecting === "key_or_end") {
      if (ch === 0x7d) {
        pos += 1;
        stack.pop();
        afterValueClosed();
        continue;
      }
      if (ch !== 0x22) {
        failSyntax("Expected quoted property key in JSON object");
      }
      const key = scanString();
      if (top.seenKeys.has(key)) {
        failSyntax(`Duplicate JSON object key "${key}"`);
      }
      top.seenKeys.add(key);
      top.expecting = "colon";
      continue;
    }

    if (top.expecting === "colon") {
      if (ch !== 0x3a) {
        failSyntax("Expected ':' after object key");
      }
      pos += 1;
      top.expecting = "value";
      startValue();
      continue;
    }

    if (top.expecting === "comma_or_end") {
      if (ch === 0x7d) {
        pos += 1;
        stack.pop();
        afterValueClosed();
        continue;
      }
      if (ch === 0x2c) {
        pos += 1;
        skipWs();
        if (pos >= len || text.charCodeAt(pos) !== 0x22) {
          failSyntax("Expected quoted property key after comma");
        }
        const key = scanString();
        if (top.seenKeys.has(key)) {
          failSyntax(`Duplicate JSON object key "${key}"`);
        }
        top.seenKeys.add(key);
        top.expecting = "colon";
        continue;
      }
      failSyntax("Expected ',' or '}' in JSON object");
    }

    failSyntax("Unexpected object parser state");
  }

  skipWs();
  if (pos !== len) {
    failSyntax("Trailing characters or multiple JSON documents are forbidden");
  }

  return {
    nodeCount: nodes,
    maxObservedDepth
  };
}

export function isPlainObjectRecord(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return false;
  }
  const proto: unknown = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

export function countUnicodeScalarValues(value: string): number {
  let count = 0;
  for (let i = 0; i < value.length; i += 1) {
    const code = value.charCodeAt(i);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = i + 1 < value.length ? value.charCodeAt(i + 1) : 0;
      if (next < 0xdc00 || next > 0xdfff) {
        throw new ValidationDomainError({
          code: "INVALID_VALUE",
          message: "String contains an unpaired UTF-16 high surrogate"
        });
      }
      i += 1;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      throw new ValidationDomainError({
        code: "INVALID_VALUE",
        message: "String contains an unpaired UTF-16 low surrogate"
      });
    }
    count += 1;
  }
  return count;
}

export function parseStrictLosslessJson<T extends LosslessJsonValue = LosslessJsonValue>(
  input: Uint8Array | string,
  options?: StrictLosslessJsonParseOptions
): ParsedLosslessJsonResult<T> {
  const fieldPath = options?.fieldPath ?? "json";
  const minDecodedBytes = options?.minDecodedBytes ?? 1;
  const maxDecodedBytes = options?.maxDecodedBytes ?? EVENT_MAX_CONTENT_BYTES;
  const maxDepth = options?.maxDepth ?? EVENT_MAX_JSON_DEPTH;
  const maxNodes = options?.maxNodes ?? EVENT_MAX_JSON_NODES;
  const maxNumericTokenBytes = options?.maxNumericTokenBytes ?? EVENT_MAX_NUMERIC_TOKEN_BYTES;

  let ownedBytes: Uint8Array;
  let text: string;

  if (input instanceof Uint8Array) {
    if (input.length > maxDecodedBytes) {
      throw new ValidationDomainError({
        code: "PAYLOAD_TOO_LARGE",
        message: `Payload byte length ${input.length} exceeds maximum ${maxDecodedBytes} bytes for ${fieldPath}`,
        fieldErrors: [{ path: fieldPath, code: "PAYLOAD_TOO_LARGE" }]
      });
    }
    if (input.length < minDecodedBytes) {
      throw new ValidationDomainError({
        code: "INVALID_VALUE",
        message: `Payload byte length ${input.length} is below minimum ${minDecodedBytes} bytes for ${fieldPath}`,
        fieldErrors: [{ path: fieldPath, code: "INVALID_VALUE" }]
      });
    }
    ownedBytes = new Uint8Array(input);
    text = decodeUtf8BytesStrict(ownedBytes, fieldPath);
  } else if (typeof input === "string") {
    if (hasLoneSurrogate(input)) {
      throw new ValidationDomainError({
        code: "INVALID_VALUE",
        message: `String contains an unpaired UTF-16 surrogate in ${fieldPath}`,
        fieldErrors: [{ path: fieldPath, code: "INVALID_VALUE" }]
      });
    }
    const byteLen = computeUtf8ByteLength(input);
    if (byteLen > maxDecodedBytes) {
      throw new ValidationDomainError({
        code: "PAYLOAD_TOO_LARGE",
        message: `Payload byte length ${byteLen} exceeds maximum ${maxDecodedBytes} bytes for ${fieldPath}`,
        fieldErrors: [{ path: fieldPath, code: "PAYLOAD_TOO_LARGE" }]
      });
    }
    if (byteLen < minDecodedBytes) {
      throw new ValidationDomainError({
        code: "INVALID_VALUE",
        message: `Payload byte length ${byteLen} is below minimum ${minDecodedBytes} bytes for ${fieldPath}`,
        fieldErrors: [{ path: fieldPath, code: "INVALID_VALUE" }]
      });
    }
    ownedBytes = encodeUtf8Bytes(input, fieldPath);
    text = input;
  } else {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Expected Uint8Array or string for ${fieldPath}`,
      fieldErrors: [{ path: fieldPath, code: "INVALID_VALUE" }]
    });
  }

  const scan = scanJsonTextStrictly(text, {
    fieldPath,
    maxDepth,
    maxNodes,
    maxNumericTokenBytes
  });

  const parsed = losslessParse(text, null, {
    parseNumber: (token: string) => new LosslessNumber(token),
    onDuplicateKey: ({ key }) => {
      throw new ValidationDomainError({
        code: "INVALID_VALUE",
        message: `Duplicate JSON object key "${key}" in ${fieldPath}`,
        fieldErrors: [{ path: fieldPath, code: "INVALID_VALUE" }]
      });
    }
  }) as LosslessJsonValue;

  if (options?.requireObjectRoot === true && !isPlainObjectRecord(parsed)) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Expected root JSON object for ${fieldPath}`,
      fieldErrors: [{ path: fieldPath, code: "INVALID_VALUE" }]
    });
  }

  return Object.freeze({
    value: parsed as T,
    rawBytes: ownedBytes,
    byteCount: ownedBytes.length,
    sha256: sha256Hex(ownedBytes),
    nodeCount: scan.nodeCount,
    maxObservedDepth: scan.maxObservedDepth
  });
}

export function parseEventJsonBytes(
  rawBytes: Uint8Array,
  options?: Omit<StrictLosslessJsonParseOptions, "requireObjectRoot">
): ParsedLosslessJsonResult {
  return parseStrictLosslessJson(rawBytes, {
    ...options,
    fieldPath: options?.fieldPath ?? "event_content",
    maxDecodedBytes: options?.maxDecodedBytes ?? EVENT_MAX_CONTENT_BYTES,
    maxDepth: options?.maxDepth ?? EVENT_MAX_JSON_DEPTH,
    maxNodes: options?.maxNodes ?? EVENT_MAX_JSON_NODES,
    maxNumericTokenBytes: options?.maxNumericTokenBytes ?? EVENT_MAX_NUMERIC_TOKEN_BYTES
  });
}

export function parseEventJsonString(
  jsonText: string,
  options?: Omit<StrictLosslessJsonParseOptions, "requireObjectRoot">
): ParsedLosslessJsonResult {
  return parseStrictLosslessJson(jsonText, {
    ...options,
    fieldPath: options?.fieldPath ?? "event_content",
    maxDecodedBytes: options?.maxDecodedBytes ?? EVENT_MAX_CONTENT_BYTES,
    maxDepth: options?.maxDepth ?? EVENT_MAX_JSON_DEPTH,
    maxNodes: options?.maxNodes ?? EVENT_MAX_JSON_NODES,
    maxNumericTokenBytes: options?.maxNumericTokenBytes ?? EVENT_MAX_NUMERIC_TOKEN_BYTES
  });
}

export function serializeStrictJsonString(value: string, fieldPath = "string"): string {
  if (hasLoneSurrogate(value)) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Lone UTF-16 surrogate disallowed in JSON string at ${fieldPath}`,
      fieldErrors: [{ path: fieldPath, code: "INVALID_VALUE" }]
    });
  }
  let out = "\"";
  for (let i = 0; i < value.length; i += 1) {
    const code = value.charCodeAt(i);
    if (code === 0x22) {
      out += "\\\"";
    } else if (code === 0x5c) {
      out += "\\\\";
    } else if (code === 0x08) {
      out += "\\b";
    } else if (code === 0x09) {
      out += "\\t";
    } else if (code === 0x0a) {
      out += "\\n";
    } else if (code === 0x0c) {
      out += "\\f";
    } else if (code === 0x0d) {
      out += "\\r";
    } else if (code < 0x20) {
      out += `\\u00${code.toString(16).padStart(2, "0")}`;
    } else {
      out += value[i]!;
    }
  }
  out += "\"";
  return out;
}
