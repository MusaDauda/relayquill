import {
  type Base64String,
  type Base64UrlString,
  type BusinessKey,
  type CanonicalJsonPrimitive,
  type CanonicalJsonValue,
  type CanonicalUtcTimestamp,
  type CanonicalUuid,
  type DeliveryId,
  EVENT_CONTENT_ENCODING,
  EVENT_CONTENT_MEDIA_TYPE,
  type EventId,
  type EventTypeId,
  type EventTypeName,
  type IdempotencyKey,
  type Int64String,
  type NonNegativeInt64String,
  type PositiveInt64String,
  type PrincipalId,
  type ProducerId,
  type ProducerNamespace,
  type ProjectId,
  type Sha256Hex,
  type TenantId,
  bytesToLowerHex,
  canonicalizeJson,
  canonicalizeJsonBytes,
  computeBusinessKeySha256,
  computeRequestKeySha256,
  decodeBase64Strict,
  decodeBase64UrlStrict,
  encodeBase64,
  encodeBase64Url,
  parseBoundedInteger,
  parseBoundedString,
  parseBusinessKey,
  parseCanonicalUtcTimestamp,
  parseCanonicalUuid,
  parseDeliveryId,
  parseEventId,
  parseEventTypeId,
  parseEventTypeName,
  parseIdempotencyKey,
  parseInt64BigInt,
  parseInt64String,
  parseNonNegativeInt64BigInt,
  parseNonNegativeInt64String,
  parseNullableUtcTimestamp,
  parsePositiveInt32,
  parsePositiveInt64BigInt,
  parsePositiveInt64String,
  parsePrincipalId,
  parseProducerId,
  parseProducerNamespace,
  parseProjectId,
  parseSha256Hex,
  parseStrictBase64,
  parseStrictBase64Url,
  parseTenantId
} from "@relayquill/contracts";
import {
  type AcceptanceStatus,
  type ActorKind,
  type ChannelKind,
  type DomainErrorCode,
  EVENT_MAX_CONTENT_BYTES,
  EVENT_MAX_JSON_DEPTH,
  EVENT_MAX_JSON_NODES,
  EVENT_MAX_NUMERIC_TOKEN_BYTES,
  type EventFanoutState,
  type EventState,
  type EvidenceBoundary,
  type OutboxState,
  type ParsedProducerCredentialToken,
  type ProducerCredentialId,
  type ProducerCredentialSelector,
  type ProducerScopeAction,
  type SafeResourceRef,
  hasLoneSurrogate,
  isProducerCredentialSelector,
  parseProducerCredentialId,
  parseProducerCredentialSelector,
  parseProducerCredentialToken
} from "@relayquill/domain";
import { ProducerSdkError, ProducerValidationError } from "./errors.js";

export {
  type AcceptanceStatus,
  type ActorKind,
  type Base64String,
  type Base64UrlString,
  type BusinessKey,
  type CanonicalJsonPrimitive,
  type CanonicalJsonValue,
  type CanonicalUtcTimestamp,
  type CanonicalUuid,
  type ChannelKind,
  type DeliveryId,
  type DomainErrorCode,
  EVENT_CONTENT_ENCODING,
  EVENT_CONTENT_MEDIA_TYPE,
  EVENT_MAX_CONTENT_BYTES,
  EVENT_MAX_JSON_DEPTH,
  EVENT_MAX_JSON_NODES,
  EVENT_MAX_NUMERIC_TOKEN_BYTES,
  type EventFanoutState,
  type EventId,
  type EventState,
  type EventTypeId,
  type EventTypeName,
  type EvidenceBoundary,
  type IdempotencyKey,
  type Int64String,
  type NonNegativeInt64String,
  type OutboxState,
  type ParsedProducerCredentialToken,
  type PositiveInt64String,
  type PrincipalId,
  type ProducerCredentialId,
  type ProducerCredentialSelector,
  type ProducerId,
  type ProducerNamespace,
  type ProducerScopeAction,
  type ProjectId,
  type SafeResourceRef,
  type Sha256Hex,
  type TenantId,
  bytesToLowerHex,
  canonicalizeJson,
  canonicalizeJsonBytes,
  computeBusinessKeySha256,
  computeRequestKeySha256,
  decodeBase64Strict,
  decodeBase64UrlStrict,
  encodeBase64,
  encodeBase64Url,
  hasLoneSurrogate,
  isProducerCredentialSelector,
  parseBoundedInteger,
  parseBoundedString,
  parseBusinessKey,
  parseCanonicalUtcTimestamp,
  parseCanonicalUuid,
  parseDeliveryId,
  parseEventId,
  parseEventTypeId,
  parseEventTypeName,
  parseIdempotencyKey,
  parseInt64BigInt,
  parseInt64String,
  parseNonNegativeInt64BigInt,
  parseNonNegativeInt64String,
  parseNullableUtcTimestamp,
  parsePositiveInt32,
  parsePositiveInt64BigInt,
  parsePositiveInt64String,
  parsePrincipalId,
  parseProducerCredentialId,
  parseProducerCredentialSelector,
  parseProducerCredentialToken,
  parseProducerId,
  parseProducerNamespace,
  parseProjectId,
  parseSha256Hex,
  parseStrictBase64,
  parseStrictBase64Url,
  parseTenantId
};

export interface WebCryptoSubtleLike {
  digest(algorithm: "SHA-256", data: ArrayBuffer | Uint8Array): Promise<ArrayBuffer>;
}

export interface WebCryptoLike {
  readonly subtle: WebCryptoSubtleLike;
  getRandomValues<T extends Uint8Array>(array: T): T;
}

export function requireWebCrypto(customCrypto?: WebCryptoLike): WebCryptoLike {
  const candidate = customCrypto ?? (globalThis.crypto as WebCryptoLike | undefined);
  if (
    candidate === undefined ||
    candidate === null ||
    typeof candidate.getRandomValues !== "function" ||
    candidate.subtle === undefined ||
    candidate.subtle === null ||
    typeof candidate.subtle.digest !== "function"
  ) {
    throw new ProducerSdkError({
      code: "WEB_CRYPTO_UNAVAILABLE",
      message: "Portable Web Crypto API (crypto.subtle and crypto.getRandomValues) is required",
      retryable: false,
      acceptance: "not_applicable"
    });
  }
  return candidate;
}

export function copyUint8Array(source: Uint8Array): Uint8Array {
  if (!(source instanceof Uint8Array)) {
    throw new ProducerValidationError({
      message: "Expected Uint8Array byte buffer"
    });
  }
  const owned = new Uint8Array(source.byteLength);
  owned.set(source);
  return owned;
}

export function utf8EncodeText(text: string, fieldPath = "text"): Uint8Array {
  if (typeof text !== "string" || hasLoneSurrogate(text)) {
    throw new ProducerValidationError({
      message: `Invalid UTF-8 string (lone surrogate disallowed) at ${fieldPath}`,
      fieldErrors: [{ path: fieldPath, code: "INVALID_VALUE" }]
    });
  }
  const encoder = new TextEncoder();
  return encoder.encode(text);
}

export function utf8DecodeBytesFatal(bytes: Uint8Array, fieldPath = "bytes"): string {
  if (!(bytes instanceof Uint8Array)) {
    throw new ProducerValidationError({
      message: `Expected Uint8Array for ${fieldPath}`,
      fieldErrors: [{ path: fieldPath, code: "INVALID_VALUE" }]
    });
  }
  try {
    const decoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
    return decoder.decode(bytes);
  } catch {
    throw new ProducerValidationError({
      message: `Invalid UTF-8 byte sequence in ${fieldPath}`,
      fieldErrors: [{ path: fieldPath, code: "INVALID_VALUE" }]
    });
  }
}

export async function sha256DigestWebCrypto(
  bytes: Uint8Array,
  customCrypto?: WebCryptoLike
): Promise<Uint8Array> {
  const webCrypto = requireWebCrypto(customCrypto);
  const owned = copyUint8Array(bytes);
  const digestBuffer = await webCrypto.subtle.digest("SHA-256", owned);
  return new Uint8Array(digestBuffer);
}

export async function sha256HexWebCrypto(
  bytes: Uint8Array,
  customCrypto?: WebCryptoLike
): Promise<Sha256Hex> {
  const digest = await sha256DigestWebCrypto(bytes, customCrypto);
  return bytesToLowerHex(digest) as Sha256Hex;
}

export function randomBytesWebCrypto(
  byteLength: number,
  customCrypto?: WebCryptoLike
): Uint8Array {
  if (!Number.isInteger(byteLength) || byteLength < 1 || byteLength > 65_536) {
    throw new ProducerValidationError({
      message: `Invalid random byte length ${String(byteLength)}`
    });
  }
  const webCrypto = requireWebCrypto(customCrypto);
  const out = new Uint8Array(byteLength);
  webCrypto.getRandomValues(out);
  return out;
}

export function generateIdempotencyKey(customCrypto?: WebCryptoLike): IdempotencyKey {
  const randomBytes = randomBytesWebCrypto(24, customCrypto);
  const token = `rq_req_${encodeBase64Url(randomBytes)}`;
  return parseIdempotencyKey(token, "idempotency_key");
}

export interface LosslessNumberToken {
  readonly __relayquill_lossless_number__: true;
  readonly lexeme: string;
}

const STRICT_JSON_NUMBER_LEXEME_REGEX =
  /^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?$/;

export function losslessNumber(lexeme: string, fieldPath = "number"): LosslessNumberToken {
  if (
    typeof lexeme !== "string" ||
    lexeme.length === 0 ||
    lexeme.length > EVENT_MAX_NUMERIC_TOKEN_BYTES ||
    !STRICT_JSON_NUMBER_LEXEME_REGEX.test(lexeme)
  ) {
    throw new ProducerValidationError({
      message: `Invalid lossless JSON numeric lexeme "${String(lexeme)}" at ${fieldPath}`,
      fieldErrors: [{ path: fieldPath, code: "INVALID_VALUE" }]
    });
  }
  return Object.freeze({
    __relayquill_lossless_number__: true,
    lexeme
  });
}

export function isLosslessNumberToken(value: unknown): value is LosslessNumberToken {
  if (typeof value !== "object" || value === null) {
    return false;
  }
  const rec = value as Partial<LosslessNumberToken>;
  return (
    rec.__relayquill_lossless_number__ === true &&
    typeof rec.lexeme === "string" &&
    rec.lexeme.length >= 1 &&
    rec.lexeme.length <= EVENT_MAX_NUMERIC_TOKEN_BYTES &&
    STRICT_JSON_NUMBER_LEXEME_REGEX.test(rec.lexeme)
  );
}

export type LosslessJsonInput =
  | null
  | boolean
  | number
  | bigint
  | string
  | LosslessNumberToken
  | readonly LosslessJsonInput[]
  | { readonly [key: string]: LosslessJsonInput };

/**
 * Validates that a UTF-8 JSON document is a single well-formed JSON document
 * with no BOM, no lone surrogates, no duplicate object keys, depth <= 32,
 * nodes <= 32768, and numeric lexemes <= 256 bytes, without converting numbers
 * to IEEE-754 floats.
 */
export function validateLosslessJsonDocumentText(
  input: string,
  fieldPath = "content"
): void {
  if (typeof input !== "string" || input.length === 0) {
    throw new ProducerValidationError({
      message: `Event content must be a non-empty JSON document at ${fieldPath}`,
      fieldErrors: [{ path: fieldPath, code: "INVALID_VALUE" }]
    });
  }
  if (input.charCodeAt(0) === 0xfeff) {
    throw new ProducerValidationError({
      message: `UTF-8 BOM is not permitted in JSON content at ${fieldPath}`,
      fieldErrors: [{ path: fieldPath, code: "INVALID_VALUE" }]
    });
  }
  if (hasLoneSurrogate(input)) {
    throw new ProducerValidationError({
      message: `Lone UTF-16 surrogate is not permitted in JSON content at ${fieldPath}`,
      fieldErrors: [{ path: fieldPath, code: "INVALID_VALUE" }]
    });
  }

  let pos = 0;
  let nodes = 0;

  function fail(reason: string): never {
    throw new ProducerValidationError({
      message: `${reason} in ${fieldPath}`,
      fieldErrors: [{ path: fieldPath, code: "INVALID_VALUE" }]
    });
  }

  function countNode(): void {
    nodes += 1;
    if (nodes > EVENT_MAX_JSON_NODES) {
      fail(`JSON node count exceeds maximum ${EVENT_MAX_JSON_NODES}`);
    }
  }

  function skipWhitespace(): void {
    while (pos < input.length) {
      const ch = input.charCodeAt(pos);
      if (ch === 0x20 || ch === 0x09 || ch === 0x0a || ch === 0x0d) {
        pos += 1;
      } else {
        break;
      }
    }
  }

  function parseJsonString(): string {
    if (input.charCodeAt(pos) !== 0x22) {
      fail("Expected opening quote");
    }
    pos += 1;
    let out = "";
    while (pos < input.length) {
      const ch = input.charCodeAt(pos);
      if (ch === 0x22) {
        pos += 1;
        return out;
      }
      if (ch < 0x20) {
        fail("Unescaped control character in JSON string");
      }
      if (ch === 0x5c) {
        pos += 1;
        if (pos >= input.length) {
          fail("Unterminated escape sequence");
        }
        const esc = input.charCodeAt(pos);
        pos += 1;
        switch (esc) {
          case 0x22:
            out += "\"";
            break;
          case 0x5c:
            out += "\\";
            break;
          case 0x2f:
            out += "/";
            break;
          case 0x62:
            out += "\b";
            break;
          case 0x66:
            out += "\f";
            break;
          case 0x6e:
            out += "\n";
            break;
          case 0x72:
            out += "\r";
            break;
          case 0x74:
            out += "\t";
            break;
          case 0x75: {
            if (pos + 4 > input.length) {
              fail("Invalid \\u escape");
            }
            const hex4 = input.slice(pos, pos + 4);
            if (!/^[0-9a-fA-F]{4}$/.test(hex4)) {
              fail("Invalid hex digits in \\u escape");
            }
            const codeUnit = Number.parseInt(hex4, 16);
            pos += 4;
            if (codeUnit >= 0xd800 && codeUnit <= 0xdbff) {
              if (input.slice(pos, pos + 2) !== "\\u" || pos + 6 > input.length) {
                fail("Unpaired UTF-16 high surrogate escape");
              }
              const lowHex = input.slice(pos + 2, pos + 6);
              if (!/^[0-9a-fA-F]{4}$/.test(lowHex)) {
                fail("Invalid low surrogate hex escape");
              }
              const lowUnit = Number.parseInt(lowHex, 16);
              if (lowUnit < 0xdc00 || lowUnit > 0xdfff) {
                fail("Invalid UTF-16 low surrogate escape");
              }
              pos += 6;
              out += String.fromCharCode(codeUnit, lowUnit);
            } else if (codeUnit >= 0xdc00 && codeUnit <= 0xdfff) {
              fail("Unpaired UTF-16 low surrogate escape");
            } else {
              out += String.fromCharCode(codeUnit);
            }
            break;
          }
          default:
            fail("Invalid JSON escape sequence");
        }
      } else {
        out += input[pos]!;
        pos += 1;
      }
    }
    fail("Unterminated JSON string");
  }

  function scanJsonNumber(): void {
    const start = pos;
    if (input.charCodeAt(pos) === 0x2d) {
      pos += 1;
    }
    if (pos >= input.length) {
      fail("Invalid JSON number");
    }
    const firstDigit = input.charCodeAt(pos);
    if (firstDigit === 0x30) {
      pos += 1;
      const next = pos < input.length ? input.charCodeAt(pos) : -1;
      if (next >= 0x30 && next <= 0x39) {
        fail("Leading zero in JSON number");
      }
    } else if (firstDigit >= 0x31 && firstDigit <= 0x39) {
      while (pos < input.length) {
        const d = input.charCodeAt(pos);
        if (d >= 0x30 && d <= 0x39) {
          pos += 1;
        } else {
          break;
        }
      }
    } else {
      fail("Invalid JSON number");
    }

    if (pos < input.length && input.charCodeAt(pos) === 0x2e) {
      pos += 1;
      const fracStart = pos;
      while (pos < input.length) {
        const d = input.charCodeAt(pos);
        if (d >= 0x30 && d <= 0x39) {
          pos += 1;
        } else {
          break;
        }
      }
      if (pos === fracStart) {
        fail("Trailing decimal point in JSON number");
      }
    }

    if (pos < input.length && (input.charCodeAt(pos) === 0x65 || input.charCodeAt(pos) === 0x45)) {
      pos += 1;
      if (
        pos < input.length &&
        (input.charCodeAt(pos) === 0x2b || input.charCodeAt(pos) === 0x2d)
      ) {
        pos += 1;
      }
      const expStart = pos;
      while (pos < input.length) {
        const d = input.charCodeAt(pos);
        if (d >= 0x30 && d <= 0x39) {
          pos += 1;
        } else {
          break;
        }
      }
      if (pos === expStart) {
        fail("Missing exponent digits in JSON number");
      }
    }

    const tokenLength = pos - start;
    if (tokenLength > EVENT_MAX_NUMERIC_TOKEN_BYTES) {
      fail(`Numeric token length ${tokenLength} exceeds ${EVENT_MAX_NUMERIC_TOKEN_BYTES} bytes`);
    }
  }

  function scanValue(depth: number): void {
    if (depth > EVENT_MAX_JSON_DEPTH) {
      fail(`JSON nesting depth exceeds maximum ${EVENT_MAX_JSON_DEPTH}`);
    }
    skipWhitespace();
    if (pos >= input.length) {
      fail("Unexpected end of JSON input");
    }
    countNode();
    const ch = input.charCodeAt(pos);
    if (ch === 0x7b) {
      pos += 1;
      skipWhitespace();
      if (pos < input.length && input.charCodeAt(pos) === 0x7d) {
        pos += 1;
        return;
      }
      const seenKeys = new Set<string>();
      while (true) {
        skipWhitespace();
        if (pos >= input.length || input.charCodeAt(pos) !== 0x22) {
          fail("Expected object property name string");
        }
        const key = parseJsonString();
        if (seenKeys.has(key)) {
          fail(`Duplicate JSON object key "${key}" is forbidden`);
        }
        seenKeys.add(key);
        skipWhitespace();
        if (pos >= input.length || input.charCodeAt(pos) !== 0x3a) {
          fail("Expected ':' after object property name");
        }
        pos += 1;
        scanValue(depth + 1);
        skipWhitespace();
        if (pos < input.length && input.charCodeAt(pos) === 0x2c) {
          pos += 1;
          continue;
        }
        if (pos < input.length && input.charCodeAt(pos) === 0x7d) {
          pos += 1;
          return;
        }
        fail("Expected ',' or '}' in JSON object");
      }
    }
    if (ch === 0x5b) {
      pos += 1;
      skipWhitespace();
      if (pos < input.length && input.charCodeAt(pos) === 0x5d) {
        pos += 1;
        return;
      }
      while (true) {
        scanValue(depth + 1);
        skipWhitespace();
        if (pos < input.length && input.charCodeAt(pos) === 0x2c) {
          pos += 1;
          continue;
        }
        if (pos < input.length && input.charCodeAt(pos) === 0x5d) {
          pos += 1;
          return;
        }
        fail("Expected ',' or ']' in JSON array");
      }
    }
    if (ch === 0x22) {
      parseJsonString();
      return;
    }
    if (ch === 0x74) {
      if (input.slice(pos, pos + 4) !== "true") {
        fail("Invalid literal");
      }
      pos += 4;
      return;
    }
    if (ch === 0x66) {
      if (input.slice(pos, pos + 5) !== "false") {
        fail("Invalid literal");
      }
      pos += 5;
      return;
    }
    if (ch === 0x6e) {
      if (input.slice(pos, pos + 4) !== "null") {
        fail("Invalid literal");
      }
      pos += 4;
      return;
    }
    if (ch === 0x2d || (ch >= 0x30 && ch <= 0x39)) {
      scanJsonNumber();
      return;
    }
    fail("Unexpected token");
  }

  scanValue(1);
  skipWhitespace();
  if (pos !== input.length) {
    fail("Trailing content after root JSON document");
  }
}

function serializeLosslessString(value: string, fieldPath: string): string {
  if (hasLoneSurrogate(value)) {
    throw new ProducerValidationError({
      message: `Lone UTF-16 surrogate disallowed at ${fieldPath}`,
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

function serializeLosslessValue(
  value: unknown,
  depth: number,
  fieldPath: string
): string {
  if (depth > EVENT_MAX_JSON_DEPTH) {
    throw new ProducerValidationError({
      message: `JSON nesting depth exceeds ${EVENT_MAX_JSON_DEPTH} at ${fieldPath}`,
      fieldErrors: [{ path: fieldPath, code: "INVALID_VALUE" }]
    });
  }
  if (value === null) {
    return "null";
  }
  if (typeof value === "boolean") {
    return value ? "true" : "false";
  }
  if (typeof value === "bigint") {
    const str = value.toString(10);
    if (str.length > EVENT_MAX_NUMERIC_TOKEN_BYTES) {
      throw new ProducerValidationError({
        message: `BigInt numeric token exceeds ${EVENT_MAX_NUMERIC_TOKEN_BYTES} bytes at ${fieldPath}`,
        fieldErrors: [{ path: fieldPath, code: "INVALID_VALUE" }]
      });
    }
    return str;
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw new ProducerValidationError({
        message: `Non-finite number (${String(value)}) is not valid JSON at ${fieldPath}`,
        fieldErrors: [{ path: fieldPath, code: "INVALID_VALUE" }]
      });
    }
    if (Number.isInteger(value) && !Number.isSafeInteger(value)) {
      throw new ProducerValidationError({
        message: `Unsafe integer number at ${fieldPath}; pass bigint, losslessNumber("..."), or raw UTF-8 JSON bytes`,
        fieldErrors: [{ path: fieldPath, code: "INVALID_VALUE" }]
      });
    }
    return Object.is(value, -0) ? "0" : value.toString(10);
  }
  if (typeof value === "string") {
    return serializeLosslessString(value, fieldPath);
  }
  if (isLosslessNumberToken(value)) {
    return value.lexeme;
  }
  if (Array.isArray(value)) {
    const items = value.map((item, idx) =>
      serializeLosslessValue(item, depth + 1, `${fieldPath}[${idx}]`)
    );
    return `[${items.join(",")}]`;
  }
  if (typeof value === "object") {
    const proto: unknown = Object.getPrototypeOf(value);
    if (proto !== null && proto !== Object.prototype) {
      throw new ProducerValidationError({
        message: `Non-plain object cannot be serialized as JSON content at ${fieldPath}`,
        fieldErrors: [{ path: fieldPath, code: "INVALID_VALUE" }]
      });
    }
    const rec = value as Record<string, unknown>;
    const keys = Object.keys(rec).sort((a, b) => (a === b ? 0 : a < b ? -1 : 1));
    const parts: string[] = [];
    for (const key of keys) {
      const prop = rec[key];
      if (prop === undefined) {
        throw new ProducerValidationError({
          message: `Object property "${key}" cannot be undefined at ${fieldPath}`,
          fieldErrors: [{ path: `${fieldPath}.${key}`, code: "INVALID_VALUE" }]
        });
      }
      parts.push(
        `${serializeLosslessString(key, `${fieldPath}.${key}`)}:${serializeLosslessValue(
          prop,
          depth + 1,
          `${fieldPath}.${key}`
        )}`
      );
    }
    return `{${parts.join(",")}}`;
  }
  throw new ProducerValidationError({
    message: `Unsupported content value type "${typeof value}" at ${fieldPath}`,
    fieldErrors: [{ path: fieldPath, code: "INVALID_VALUE" }]
  });
}

export function encodeEventContentBytes(
  content: Uint8Array | string | LosslessJsonInput,
  fieldPath = "content"
): Uint8Array {
  let ownedBytes: Uint8Array;
  if (content instanceof Uint8Array) {
    ownedBytes = copyUint8Array(content);
    if (ownedBytes.byteLength === 0) {
      throw new ProducerValidationError({
        message: "Event content bytes must be non-empty",
        fieldErrors: [{ path: fieldPath, code: "INVALID_VALUE" }]
      });
    }
    if (ownedBytes.byteLength > EVENT_MAX_CONTENT_BYTES) {
      throw new ProducerValidationError({
        code: "PAYLOAD_TOO_LARGE",
        httpStatus: 413,
        message: `Event content (${ownedBytes.byteLength} bytes) exceeds maximum ${EVENT_MAX_CONTENT_BYTES} bytes`,
        fieldErrors: [{ path: fieldPath, code: "PAYLOAD_TOO_LARGE" }]
      });
    }
    const decodedText = utf8DecodeBytesFatal(ownedBytes, fieldPath);
    validateLosslessJsonDocumentText(decodedText, fieldPath);
    return ownedBytes;
  }

  if (typeof content === "string") {
    validateLosslessJsonDocumentText(content, fieldPath);
    ownedBytes = utf8EncodeText(content, fieldPath);
  } else {
    const serialized = serializeLosslessValue(content, 1, fieldPath);
    validateLosslessJsonDocumentText(serialized, fieldPath);
    ownedBytes = utf8EncodeText(serialized, fieldPath);
  }

  if (ownedBytes.byteLength === 0) {
    throw new ProducerValidationError({
      message: "Event content bytes must be non-empty",
      fieldErrors: [{ path: fieldPath, code: "INVALID_VALUE" }]
    });
  }
  if (ownedBytes.byteLength > EVENT_MAX_CONTENT_BYTES) {
    throw new ProducerValidationError({
      code: "PAYLOAD_TOO_LARGE",
      httpStatus: 413,
      message: `Event content (${ownedBytes.byteLength} bytes) exceeds maximum ${EVENT_MAX_CONTENT_BYTES} bytes`,
      fieldErrors: [{ path: fieldPath, code: "PAYLOAD_TOO_LARGE" }]
    });
  }
  return ownedBytes;
}
