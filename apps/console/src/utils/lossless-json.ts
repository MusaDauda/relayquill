import {
  computeUtf8ByteLength,
  encodeBase64,
  encodeUtf8Bytes,
  hasLoneSurrogate,
  sha256Hex
} from "@relayquill/contracts";
import { type Base64String, type Sha256Hex } from "@relayquill/contracts";

export interface LosslessNumberToken {
  readonly kind: "lossless_number";
  readonly raw: string;
  readonly precisionRisk: boolean;
}

export type LosslessJsonNode =
  | null
  | boolean
  | string
  | LosslessNumberToken
  | readonly LosslessJsonNode[]
  | { readonly [key: string]: LosslessJsonNode };

export interface LosslessJsonValidationResult {
  readonly valid: boolean;
  readonly root?: LosslessJsonNode | undefined;
  readonly formattedText?: string | undefined;
  readonly precisionRiskPaths: readonly string[];
  readonly duplicateKeyPaths: readonly string[];
  readonly error?: string | undefined;
  readonly utf8Bytes: Uint8Array;
  readonly byteCount: number;
  readonly sha256: Sha256Hex;
  readonly base64: Base64String;
}

const DEFAULT_MAX_DEPTH = 32;
const DEFAULT_MAX_NODES = 32_768;

function isDigit(code: number): boolean {
  return code >= 0x30 && code <= 0x39;
}

function isDigit19(code: number): boolean {
  return code >= 0x31 && code <= 0x39;
}

function parseHex4(hex: string): number {
  let out = 0;
  for (let i = 0; i < 4; i += 1) {
    const code = hex.charCodeAt(i);
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
    out = (out << 4) | nib;
  }
  return out;
}

function isNumberPrecisionRisk(raw: string): boolean {
  if (raw.includes(".") || raw.includes("e") || raw.includes("E")) {
    const num = Number(raw);
    if (!Number.isFinite(num)) {
      return true;
    }
    return String(num) !== raw;
  }
  try {
    const big = BigInt(raw);
    return big > BigInt(Number.MAX_SAFE_INTEGER) || big < BigInt(Number.MIN_SAFE_INTEGER);
  } catch {
    return true;
  }
}

export function isLosslessNumberToken(value: unknown): value is LosslessNumberToken {
  return (
    typeof value === "object" &&
    value !== null &&
    (value as { readonly kind?: unknown }).kind === "lossless_number" &&
    typeof (value as { readonly raw?: unknown }).raw === "string"
  );
}

export function parseStrictLosslessJsonText(
  input: string,
  options?: {
    readonly maxDepth?: number | undefined;
    readonly maxNodes?: number | undefined;
  }
): {
  readonly root: LosslessJsonNode;
  readonly precisionRiskPaths: readonly string[];
} {
  const maxDepth = options?.maxDepth ?? DEFAULT_MAX_DEPTH;
  const maxNodes = options?.maxNodes ?? DEFAULT_MAX_NODES;

  if (typeof input !== "string" || input.length === 0) {
    throw new Error("JSON content cannot be empty.");
  }
  if (hasLoneSurrogate(input)) {
    throw new Error("JSON text contains an unpaired UTF-16 surrogate.");
  }

  let pos = 0;
  let nodes = 0;
  const precisionRiskPaths: string[] = [];

  function countNode(): void {
    nodes += 1;
    if (nodes > maxNodes) {
      throw new Error(`JSON node count exceeds maximum ${maxNodes}.`);
    }
  }

  function skipWs(): void {
    while (pos < input.length) {
      const ch = input.charCodeAt(pos);
      if (ch === 0x20 || ch === 0x09 || ch === 0x0a || ch === 0x0d) {
        pos += 1;
      } else {
        break;
      }
    }
  }

  function parseString(): string {
    if (input.charCodeAt(pos) !== 0x22) {
      throw new Error(`Expected opening quote at offset ${pos}.`);
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
        throw new Error(`Unescaped control character in JSON string at offset ${pos}.`);
      }
      if (ch === 0x5c) {
        pos += 1;
        if (pos >= input.length) {
          throw new Error("Unterminated escape sequence in JSON string.");
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
              throw new Error("Invalid \\u escape sequence.");
            }
            const cu = parseHex4(input.slice(pos, pos + 4));
            if (cu < 0) {
              throw new Error("Invalid hex digits in \\u escape.");
            }
            pos += 4;
            if (cu >= 0xd800 && cu <= 0xdbff) {
              if (input.slice(pos, pos + 2) !== "\\u" || pos + 6 > input.length) {
                throw new Error("Unpaired UTF-16 high surrogate escape.");
              }
              const low = parseHex4(input.slice(pos + 2, pos + 6));
              if (low < 0xdc00 || low > 0xdfff) {
                throw new Error("Invalid UTF-16 low surrogate escape.");
              }
              pos += 6;
              out += String.fromCharCode(cu, low);
            } else if (cu >= 0xdc00 && cu <= 0xdfff) {
              throw new Error("Unpaired UTF-16 low surrogate escape.");
            } else {
              out += String.fromCharCode(cu);
            }
            break;
          }
          default:
            throw new Error(`Invalid JSON escape sequence at offset ${pos - 1}.`);
        }
      } else {
        out += input[pos]!;
        pos += 1;
      }
    }
    throw new Error("Unterminated JSON string.");
  }

  function parseNumber(path: string): LosslessNumberToken {
    const start = pos;
    if (input.charCodeAt(pos) === 0x2d) {
      pos += 1;
    }
    if (pos >= input.length) {
      throw new Error(`Invalid JSON number at ${path}.`);
    }
    if (input.charCodeAt(pos) === 0x30) {
      pos += 1;
      if (pos < input.length && isDigit(input.charCodeAt(pos))) {
        throw new Error(`Leading zero disallowed in JSON number at ${path}.`);
      }
    } else if (isDigit19(input.charCodeAt(pos))) {
      while (pos < input.length && isDigit(input.charCodeAt(pos))) {
        pos += 1;
      }
    } else {
      throw new Error(`Invalid JSON number at ${path}.`);
    }

    if (pos < input.length && input.charCodeAt(pos) === 0x2e) {
      pos += 1;
      if (pos >= input.length || !isDigit(input.charCodeAt(pos))) {
        throw new Error(`Invalid fractional JSON number at ${path}.`);
      }
      while (pos < input.length && isDigit(input.charCodeAt(pos))) {
        pos += 1;
      }
    }

    if (pos < input.length) {
      const exp = input.charCodeAt(pos);
      if (exp === 0x65 || exp === 0x45) {
        pos += 1;
        if (pos < input.length) {
          const sign = input.charCodeAt(pos);
          if (sign === 0x2b || sign === 0x2d) {
            pos += 1;
          }
        }
        if (pos >= input.length || !isDigit(input.charCodeAt(pos))) {
          throw new Error(`Invalid exponent in JSON number at ${path}.`);
        }
        while (pos < input.length && isDigit(input.charCodeAt(pos))) {
          pos += 1;
        }
      }
    }

    const raw = input.slice(start, pos);
    const precisionRisk = isNumberPrecisionRisk(raw);
    if (precisionRisk) {
      precisionRiskPaths.push(path);
    }
    return Object.freeze({
      kind: "lossless_number",
      raw,
      precisionRisk
    });
  }

  function parseValue(depth: number, path: string): LosslessJsonNode {
    if (depth > maxDepth) {
      throw new Error(`JSON nesting depth exceeds maximum ${maxDepth}.`);
    }
    skipWs();
    if (pos >= input.length) {
      throw new Error(`Unexpected end of JSON input at ${path}.`);
    }
    countNode();
    const ch = input.charCodeAt(pos);
    if (ch === 0x7b) {
      pos += 1;
      skipWs();
      const obj: Record<string, LosslessJsonNode> = {};
      const seenKeys = new Set<string>();
      if (pos < input.length && input.charCodeAt(pos) === 0x7d) {
        pos += 1;
        return Object.freeze(obj);
      }
      while (true) {
        skipWs();
        const key = parseString();
        if (seenKeys.has(key)) {
          throw new Error(`Duplicate JSON key "${key}" at ${path}.${key}.`);
        }
        seenKeys.add(key);
        skipWs();
        if (input.charCodeAt(pos) !== 0x3a) {
          throw new Error(`Expected ":" after key "${key}" at ${path}.`);
        }
        pos += 1;
        const childPath = path === "$" ? `/${key}` : `${path}/${key}`;
        const val = parseValue(depth + 1, childPath);
        Object.defineProperty(obj, key, {
          value: val,
          enumerable: true,
          writable: false,
          configurable: false
        });
        skipWs();
        if (input.charCodeAt(pos) === 0x2c) {
          pos += 1;
          continue;
        }
        if (input.charCodeAt(pos) === 0x7d) {
          pos += 1;
          return Object.freeze(obj);
        }
        throw new Error(`Expected "," or "}" in JSON object at ${path}.`);
      }
    }
    if (ch === 0x5b) {
      pos += 1;
      skipWs();
      const arr: LosslessJsonNode[] = [];
      if (pos < input.length && input.charCodeAt(pos) === 0x5d) {
        pos += 1;
        return Object.freeze(arr);
      }
      let idx = 0;
      while (true) {
        arr.push(parseValue(depth + 1, `${path}[${idx}]`));
        idx += 1;
        skipWs();
        if (input.charCodeAt(pos) === 0x2c) {
          pos += 1;
          continue;
        }
        if (input.charCodeAt(pos) === 0x5d) {
          pos += 1;
          return Object.freeze(arr);
        }
        throw new Error(`Expected "," or "]" in JSON array at ${path}.`);
      }
    }
    if (ch === 0x22) {
      return parseString();
    }
    if (ch === 0x74 && input.startsWith("true", pos)) {
      pos += 4;
      return true;
    }
    if (ch === 0x66 && input.startsWith("false", pos)) {
      pos += 5;
      return false;
    }
    if (ch === 0x6e && input.startsWith("null", pos)) {
      pos += 4;
      return null;
    }
    if (ch === 0x2d || isDigit(ch)) {
      return parseNumber(path);
    }
    throw new Error(`Unexpected token at ${path} (offset ${pos}).`);
  }

  const root = parseValue(0, "$");
  skipWs();
  if (pos !== input.length) {
    throw new Error(`Unexpected trailing characters at offset ${pos}.`);
  }
  return { root, precisionRiskPaths: Object.freeze(precisionRiskPaths) };
}

export function formatLosslessJson(node: LosslessJsonNode, indent = 2, depth = 0): string {
  if (node === null) {
    return "null";
  }
  if (typeof node === "boolean") {
    return node ? "true" : "false";
  }
  if (typeof node === "string") {
    return JSON.stringify(node);
  }
  if (isLosslessNumberToken(node)) {
    return node.raw;
  }
  if (Array.isArray(node)) {
    const items = node as readonly LosslessJsonNode[];
    if (items.length === 0) {
      return "[]";
    }
    if (indent <= 0) {
      return `[${items.map((item) => formatLosslessJson(item, 0, depth + 1)).join(",")}]`;
    }
    const pad = " ".repeat((depth + 1) * indent);
    const closePad = " ".repeat(depth * indent);
    const lines = items.map((item) => `${pad}${formatLosslessJson(item, indent, depth + 1)}`);
    return `[\n${lines.join(",\n")}\n${closePad}]`;
  }
  const entries = Object.entries(node as Record<string, LosslessJsonNode>);
  if (entries.length === 0) {
    return "{}";
  }
  if (indent <= 0) {
    return `{${entries
      .map(([k, v]) => `${JSON.stringify(k)}:${formatLosslessJson(v, 0, depth + 1)}`)
      .join(",")}}`;
  }
  const pad = " ".repeat((depth + 1) * indent);
  const closePad = " ".repeat(depth * indent);
  const lines = entries.map(
    ([k, v]) => `${pad}${JSON.stringify(k)}: ${formatLosslessJson(v, indent, depth + 1)}`
  );
  return `{\n${lines.join(",\n")}\n${closePad}}`;
}

export function inspectLosslessJsonText(rawText: string): LosslessJsonValidationResult {
  let utf8Bytes: Uint8Array;
  try {
    computeUtf8ByteLength(rawText);
    utf8Bytes = encodeUtf8Bytes(rawText, "content");
  } catch (err) {
    return {
      valid: false,
      precisionRiskPaths: [],
      duplicateKeyPaths: [],
      error: err instanceof Error ? err.message : "Invalid UTF-8 string.",
      utf8Bytes: new Uint8Array(0),
      byteCount: 0,
      sha256: sha256Hex(new Uint8Array(0)),
      base64: encodeBase64(new Uint8Array(0))
    };
  }

  const hash = sha256Hex(utf8Bytes);
  const b64 = encodeBase64(utf8Bytes);

  try {
    const parsed = parseStrictLosslessJsonText(rawText);
    return {
      valid: true,
      root: parsed.root,
      formattedText: formatLosslessJson(parsed.root, 2),
      precisionRiskPaths: parsed.precisionRiskPaths,
      duplicateKeyPaths: [],
      utf8Bytes,
      byteCount: utf8Bytes.length,
      sha256: hash,
      base64: b64
    };
  } catch (err) {
    return {
      valid: false,
      precisionRiskPaths: [],
      duplicateKeyPaths: [],
      error: err instanceof Error ? err.message : "Invalid JSON content.",
      utf8Bytes,
      byteCount: utf8Bytes.length,
      sha256: hash,
      base64: b64
    };
  }
}

export function decodeBase64JsonLossless(
  base64Data: string
): {
  readonly rawText: string;
  readonly formattedText: string;
  readonly precisionRiskPaths: readonly string[];
  readonly validJson: boolean;
  readonly error?: string | undefined;
} {
  const binary = atob(base64Data);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  const rawText = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  try {
    const parsed = parseStrictLosslessJsonText(rawText);
    return {
      rawText,
      formattedText: formatLosslessJson(parsed.root, 2),
      precisionRiskPaths: parsed.precisionRiskPaths,
      validJson: true
    };
  } catch (err) {
    return {
      rawText,
      formattedText: rawText,
      precisionRiskPaths: [],
      validJson: false,
      error: err instanceof Error ? err.message : "Malformed JSON payload"
    };
  }
}
