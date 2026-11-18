import {
  type Sha256Hex,
  ValidationDomainError,
  type Brand
} from "@relayquill/domain";

export type Base64String = Brand<string, "Base64String">;
export type Base64UrlString = Brand<string, "Base64UrlString">;

const LOWER_HEX_CHARS = "0123456789abcdef";
const BASE64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const BASE64URL_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

const BASE64_REVERSE = (() => {
  const table = new Int16Array(128).fill(-1);
  for (let i = 0; i < BASE64_ALPHABET.length; i += 1) {
    table[BASE64_ALPHABET.charCodeAt(i)] = i;
  }
  return table;
})();

const BASE64URL_REVERSE = (() => {
  const table = new Int16Array(128).fill(-1);
  for (let i = 0; i < BASE64URL_ALPHABET.length; i += 1) {
    table[BASE64URL_ALPHABET.charCodeAt(i)] = i;
  }
  return table;
})();

const SHA256_K = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]);

const SHA256_H0 = new Uint32Array([
  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
  0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
]);

function rotr32(value: number, bits: number): number {
  return (value >>> bits) | (value << (32 - bits));
}

export function bytesToLowerHex(bytes: Uint8Array): string {
  let out = "";
  for (let i = 0; i < bytes.length; i += 1) {
    const b = bytes[i] ?? 0;
    out += LOWER_HEX_CHARS[(b >>> 4) & 0x0f] ?? "0";
    out += LOWER_HEX_CHARS[b & 0x0f] ?? "0";
  }
  return out;
}

export function sha256HexToBytes(hex: Sha256Hex): Uint8Array {
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i += 1) {
    const hi = parseHexNibble(hex.charCodeAt(i * 2));
    const lo = parseHexNibble(hex.charCodeAt(i * 2 + 1));
    out[i] = (hi << 4) | lo;
  }
  return out;
}

function parseHexNibble(code: number): number {
  if (code >= 0x30 && code <= 0x39) {
    return code - 0x30;
  }
  if (code >= 0x61 && code <= 0x66) {
    return code - 0x61 + 10;
  }
  if (code >= 0x41 && code <= 0x46) {
    return code - 0x41 + 10;
  }
  return -1;
}

export function encodeUtf8Bytes(value: string, fieldPath = "value"): Uint8Array {
  if (typeof value !== "string") {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Expected string for UTF-8 encoding of ${fieldPath}`,
      fieldErrors: [{ path: fieldPath, code: "INVALID_VALUE" }]
    });
  }
  const maxBytes = value.length * 3;
  const out = new Uint8Array(maxBytes);
  let offset = 0;

  for (let i = 0; i < value.length; i += 1) {
    const code = value.charCodeAt(i);
    if (code <= 0x7f) {
      out[offset++] = code;
    } else if (code <= 0x7ff) {
      out[offset++] = 0xc0 | (code >>> 6);
      out[offset++] = 0x80 | (code & 0x3f);
    } else if (code >= 0xd800 && code <= 0xdbff) {
      const next = i + 1 < value.length ? value.charCodeAt(i + 1) : 0;
      if (next < 0xdc00 || next > 0xdfff) {
        throw new ValidationDomainError({
          code: "INVALID_VALUE",
          message: `String contains an unpaired UTF-16 high surrogate at ${fieldPath}`,
          fieldErrors: [{ path: fieldPath, code: "INVALID_VALUE" }]
        });
      }
      const cp = 0x10000 + ((code - 0xd800) << 10) + (next - 0xdc00);
      out[offset++] = 0xf0 | (cp >>> 18);
      out[offset++] = 0x80 | ((cp >>> 12) & 0x3f);
      out[offset++] = 0x80 | ((cp >>> 6) & 0x3f);
      out[offset++] = 0x80 | (cp & 0x3f);
      i += 1;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      throw new ValidationDomainError({
        code: "INVALID_VALUE",
        message: `String contains an unpaired UTF-16 low surrogate at ${fieldPath}`,
        fieldErrors: [{ path: fieldPath, code: "INVALID_VALUE" }]
      });
    } else {
      out[offset++] = 0xe0 | (code >>> 12);
      out[offset++] = 0x80 | ((code >>> 6) & 0x3f);
      out[offset++] = 0x80 | (code & 0x3f);
    }
  }

  return out.subarray(0, offset);
}

export function decodeUtf8BytesStrict(bytes: Uint8Array, fieldPath = "bytes"): string {
  if (!(bytes instanceof Uint8Array)) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Expected Uint8Array for ${fieldPath}`,
      fieldErrors: [{ path: fieldPath, code: "INVALID_VALUE" }]
    });
  }

  const parts: string[] = [];
  let chunk = "";
  let i = 0;

  while (i < bytes.length) {
    const b0 = bytes[i]!;
    if (b0 <= 0x7f) {
      chunk += String.fromCharCode(b0);
      i += 1;
    } else if (b0 >= 0xc2 && b0 <= 0xdf) {
      if (i + 1 >= bytes.length) {
        throw invalidUtf8Error(fieldPath);
      }
      const b1 = bytes[i + 1]!;
      if ((b1 & 0xc0) !== 0x80) {
        throw invalidUtf8Error(fieldPath);
      }
      const cp = ((b0 & 0x1f) << 6) | (b1 & 0x3f);
      chunk += String.fromCharCode(cp);
      i += 2;
    } else if (b0 >= 0xe0 && b0 <= 0xef) {
      if (i + 2 >= bytes.length) {
        throw invalidUtf8Error(fieldPath);
      }
      const b1 = bytes[i + 1]!;
      const b2 = bytes[i + 2]!;
      if ((b1 & 0xc0) !== 0x80 || (b2 & 0xc0) !== 0x80) {
        throw invalidUtf8Error(fieldPath);
      }
      if (b0 === 0xe0 && b1 < 0xa0) {
        throw invalidUtf8Error(fieldPath);
      }
      if (b0 === 0xed && b1 > 0x9f) {
        throw invalidUtf8Error(fieldPath);
      }
      const cp = ((b0 & 0x0f) << 12) | ((b1 & 0x3f) << 6) | (b2 & 0x3f);
      chunk += String.fromCharCode(cp);
      i += 3;
    } else if (b0 >= 0xf0 && b0 <= 0xf4) {
      if (i + 3 >= bytes.length) {
        throw invalidUtf8Error(fieldPath);
      }
      const b1 = bytes[i + 1]!;
      const b2 = bytes[i + 2]!;
      const b3 = bytes[i + 3]!;
      if ((b1 & 0xc0) !== 0x80 || (b2 & 0xc0) !== 0x80 || (b3 & 0xc0) !== 0x80) {
        throw invalidUtf8Error(fieldPath);
      }
      if (b0 === 0xf0 && b1 < 0x90) {
        throw invalidUtf8Error(fieldPath);
      }
      if (b0 === 0xf4 && b1 > 0x8f) {
        throw invalidUtf8Error(fieldPath);
      }
      const cp = ((b0 & 0x07) << 18) | ((b1 & 0x3f) << 12) | ((b2 & 0x3f) << 6) | (b3 & 0x3f);
      const adjusted = cp - 0x10000;
      chunk += String.fromCharCode(0xd800 | (adjusted >>> 10), 0xdc00 | (adjusted & 0x3ff));
      i += 4;
    } else {
      throw invalidUtf8Error(fieldPath);
    }

    if (chunk.length >= 4096) {
      parts.push(chunk);
      chunk = "";
    }
  }

  if (chunk.length > 0) {
    parts.push(chunk);
  }
  return parts.join("");
}

function invalidUtf8Error(fieldPath: string): ValidationDomainError {
  return new ValidationDomainError({
    code: "INVALID_VALUE",
    message: `Invalid UTF-8 byte sequence in ${fieldPath}`,
    fieldErrors: [{ path: fieldPath, code: "INVALID_VALUE" }]
  });
}

export function sha256Digest(data: Uint8Array): Uint8Array {
  const msgLen = data.length;
  const totalLen = Math.ceil((msgLen + 9) / 64) * 64;
  const padded = new Uint8Array(totalLen);
  padded.set(data, 0);
  padded[msgLen] = 0x80;

  const bitLenHi = Math.floor((msgLen * 8) / 0x1_0000_0000);
  const bitLenLo = (msgLen * 8) >>> 0;
  const view = new DataView(padded.buffer);
  view.setUint32(totalLen - 8, bitLenHi, false);
  view.setUint32(totalLen - 4, bitLenLo, false);

  const h = new Uint32Array(SHA256_H0);
  const w = new Uint32Array(64);

  for (let offset = 0; offset < totalLen; offset += 64) {
    for (let i = 0; i < 16; i += 1) {
      w[i] = view.getUint32(offset + i * 4, false);
    }
    for (let i = 16; i < 64; i += 1) {
      const w15 = w[i - 15]!;
      const w2 = w[i - 2]!;
      const s0 = rotr32(w15, 7) ^ rotr32(w15, 18) ^ (w15 >>> 3);
      const s1 = rotr32(w2, 17) ^ rotr32(w2, 19) ^ (w2 >>> 10);
      w[i] = (w[i - 16]! + s0 + w[i - 7]! + s1) >>> 0;
    }

    let a = h[0]!;
    let b = h[1]!;
    let c = h[2]!;
    let d = h[3]!;
    let e = h[4]!;
    let f = h[5]!;
    let g = h[6]!;
    let hh = h[7]!;

    for (let i = 0; i < 64; i += 1) {
      const S1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
      const ch = (e & f) ^ ((~e) & g);
      const temp1 = (hh + S1 + ch + SHA256_K[i]! + w[i]!) >>> 0;
      const S0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const temp2 = (S0 + maj) >>> 0;

      hh = g;
      g = f;
      f = e;
      e = (d + temp1) >>> 0;
      d = c;
      c = b;
      b = a;
      a = (temp1 + temp2) >>> 0;
    }

    h[0] = (h[0]! + a) >>> 0;
    h[1] = (h[1]! + b) >>> 0;
    h[2] = (h[2]! + c) >>> 0;
    h[3] = (h[3]! + d) >>> 0;
    h[4] = (h[4]! + e) >>> 0;
    h[5] = (h[5]! + f) >>> 0;
    h[6] = (h[6]! + g) >>> 0;
    h[7] = (h[7]! + hh) >>> 0;
  }

  const digest = new Uint8Array(32);
  const outView = new DataView(digest.buffer);
  for (let i = 0; i < 8; i += 1) {
    outView.setUint32(i * 4, h[i]!, false);
  }
  return digest;
}

export function sha256Hex(data: Uint8Array): Sha256Hex {
  return bytesToLowerHex(sha256Digest(data)) as Sha256Hex;
}

export function sha256Utf8Hex(text: string, fieldPath = "text"): Sha256Hex {
  return sha256Hex(encodeUtf8Bytes(text, fieldPath));
}

export function hmacSha256Digest(key: Uint8Array, message: Uint8Array): Uint8Array {
  const blockSize = 64;
  const normalizedKey = key.length > blockSize ? sha256Digest(key) : key;
  const keyBlock = new Uint8Array(blockSize);
  keyBlock.set(normalizedKey, 0);

  const innerPad = new Uint8Array(blockSize + message.length);
  const outerPad = new Uint8Array(blockSize + 32);

  for (let i = 0; i < blockSize; i += 1) {
    const kb = keyBlock[i] ?? 0;
    innerPad[i] = kb ^ 0x36;
    outerPad[i] = kb ^ 0x5c;
  }
  innerPad.set(message, blockSize);
  const innerHash = sha256Digest(innerPad);
  outerPad.set(innerHash, blockSize);
  return sha256Digest(outerPad);
}

export function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) {
    return false;
  }
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) {
    diff |= (a[i] ?? 0) ^ (b[i] ?? 0);
  }
  return diff === 0;
}

export function encodeDomainLengthPrefixed(
  domain: string,
  fields: readonly (string | Uint8Array)[]
): Uint8Array {
  const domainBytes = encodeUtf8Bytes(domain, "domain");
  const encodedFields = fields.map((field, index) =>
    typeof field === "string" ? encodeUtf8Bytes(field, `field[${index}]`) : field
  );

  let totalLength = domainBytes.length + 1;
  for (const fieldBytes of encodedFields) {
    totalLength += 4 + fieldBytes.length;
  }

  const out = new Uint8Array(totalLength);
  const view = new DataView(out.buffer);
  out.set(domainBytes, 0);
  out[domainBytes.length] = 0x00;

  let offset = domainBytes.length + 1;
  for (const fieldBytes of encodedFields) {
    view.setUint32(offset, fieldBytes.length, false);
    offset += 4;
    out.set(fieldBytes, offset);
    offset += fieldBytes.length;
  }

  return out;
}

export function encodeBase64(bytes: Uint8Array): Base64String {
  let out = "";
  let i = 0;
  while (i + 2 < bytes.length) {
    const triplet = ((bytes[i]! << 16) | (bytes[i + 1]! << 8) | bytes[i + 2]!) >>> 0;
    out +=
      BASE64_ALPHABET[(triplet >>> 18) & 0x3f]! +
      BASE64_ALPHABET[(triplet >>> 12) & 0x3f]! +
      BASE64_ALPHABET[(triplet >>> 6) & 0x3f]! +
      BASE64_ALPHABET[triplet & 0x3f]!;
    i += 3;
  }

  const remaining = bytes.length - i;
  if (remaining === 1) {
    const val = bytes[i]!;
    out += `${BASE64_ALPHABET[(val >>> 2) & 0x3f]!}${BASE64_ALPHABET[(val & 0x03) << 4]!}==`;
  } else if (remaining === 2) {
    const val = (bytes[i]! << 8) | bytes[i + 1]!;
    out += `${BASE64_ALPHABET[(val >>> 10) & 0x3f]!}${BASE64_ALPHABET[(val >>> 4) & 0x3f]!}${BASE64_ALPHABET[(val & 0x0f) << 2]!}=`;
  }
  return out as Base64String;
}

export function decodeBase64Strict(
  value: unknown,
  fieldPath = "base64",
  options?: { readonly maxDecodedBytes?: number | undefined }
): Uint8Array {
  if (typeof value !== "string") {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Expected base64 string for ${fieldPath}`,
      fieldErrors: [{ path: fieldPath, code: "INVALID_VALUE" }]
    });
  }
  const len = value.length;
  if (len === 0) {
    return new Uint8Array(0);
  }
  if (len % 4 !== 0) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Invalid base64 padding length for ${fieldPath}`,
      fieldErrors: [{ path: fieldPath, code: "INVALID_VALUE" }]
    });
  }

  let pad = 0;
  if (value.charCodeAt(len - 1) === 0x3d) {
    pad += 1;
    if (value.charCodeAt(len - 2) === 0x3d) {
      pad += 1;
    }
  }
  const decodedLen = (len / 4) * 3 - pad;
  if (options?.maxDecodedBytes !== undefined && decodedLen > options.maxDecodedBytes) {
    throw new ValidationDomainError({
      code: "PAYLOAD_TOO_LARGE",
      message: `Decoded base64 length ${decodedLen} exceeds max ${options.maxDecodedBytes} for ${fieldPath}`,
      fieldErrors: [{ path: fieldPath, code: "PAYLOAD_TOO_LARGE" }]
    });
  }

  const out = new Uint8Array(decodedLen);
  let outIdx = 0;

  for (let i = 0; i < len; i += 4) {
    const isLast = i + 4 === len;
    const c0 = value.charCodeAt(i);
    const c1 = value.charCodeAt(i + 1);
    const c2 = value.charCodeAt(i + 2);
    const c3 = value.charCodeAt(i + 3);

    const v0 = c0 < 128 ? (BASE64_REVERSE[c0] ?? -1) : -1;
    const v1 = c1 < 128 ? (BASE64_REVERSE[c1] ?? -1) : -1;
    if (v0 < 0 || v1 < 0) {
      throw invalidBase64Error(fieldPath);
    }

    if (isLast && pad === 2) {
      if (c2 !== 0x3d || c3 !== 0x3d) {
        throw invalidBase64Error(fieldPath);
      }
      // RFC 4648 canonical padding check: unused lower 4 bits must be 0.
      if ((v1 & 0x0f) !== 0) {
        throw invalidBase64Error(fieldPath);
      }
      out[outIdx++] = (v0 << 2) | (v1 >>> 4);
    } else if (isLast && pad === 1) {
      if (c3 !== 0x3d) {
        throw invalidBase64Error(fieldPath);
      }
      const v2 = c2 < 128 ? (BASE64_REVERSE[c2] ?? -1) : -1;
      if (v2 < 0 || (v2 & 0x03) !== 0) {
        throw invalidBase64Error(fieldPath);
      }
      out[outIdx++] = (v0 << 2) | (v1 >>> 4);
      out[outIdx++] = ((v1 & 0x0f) << 4) | (v2 >>> 2);
    } else {
      const v2 = c2 < 128 ? (BASE64_REVERSE[c2] ?? -1) : -1;
      const v3 = c3 < 128 ? (BASE64_REVERSE[c3] ?? -1) : -1;
      if (v2 < 0 || v3 < 0) {
        throw invalidBase64Error(fieldPath);
      }
      out[outIdx++] = (v0 << 2) | (v1 >>> 4);
      out[outIdx++] = ((v1 & 0x0f) << 4) | (v2 >>> 2);
      out[outIdx++] = ((v2 & 0x03) << 6) | v3;
    }
  }

  return out;
}

function invalidBase64Error(fieldPath: string): ValidationDomainError {
  return new ValidationDomainError({
    code: "INVALID_VALUE",
    message: `Invalid strict base64 encoding for ${fieldPath}`,
    fieldErrors: [{ path: fieldPath, code: "INVALID_VALUE" }]
  });
}

export function isStrictBase64(value: unknown): value is Base64String {
  if (typeof value !== "string") {
    return false;
  }
  try {
    decodeBase64Strict(value);
    return true;
  } catch {
    return false;
  }
}

export function encodeBase64Url(bytes: Uint8Array): Base64UrlString {
  let out = "";
  let i = 0;
  while (i + 2 < bytes.length) {
    const triplet = ((bytes[i]! << 16) | (bytes[i + 1]! << 8) | bytes[i + 2]!) >>> 0;
    out +=
      BASE64URL_ALPHABET[(triplet >>> 18) & 0x3f]! +
      BASE64URL_ALPHABET[(triplet >>> 12) & 0x3f]! +
      BASE64URL_ALPHABET[(triplet >>> 6) & 0x3f]! +
      BASE64URL_ALPHABET[triplet & 0x3f]!;
    i += 3;
  }

  const remaining = bytes.length - i;
  if (remaining === 1) {
    const val = bytes[i]!;
    out += `${BASE64URL_ALPHABET[(val >>> 2) & 0x3f]!}${BASE64URL_ALPHABET[(val & 0x03) << 4]!}`;
  } else if (remaining === 2) {
    const val = (bytes[i]! << 8) | bytes[i + 1]!;
    out += `${BASE64URL_ALPHABET[(val >>> 10) & 0x3f]!}${BASE64URL_ALPHABET[(val >>> 4) & 0x3f]!}${BASE64URL_ALPHABET[(val & 0x0f) << 2]!}`;
  }
  return out as Base64UrlString;
}

export function decodeBase64UrlStrict(
  value: unknown,
  fieldPath = "base64url",
  options?: {
    readonly exactByteLength?: number | undefined;
    readonly maxDecodedBytes?: number | undefined;
  }
): Uint8Array {
  if (typeof value !== "string") {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Expected unpadded base64url string for ${fieldPath}`,
      fieldErrors: [{ path: fieldPath, code: "INVALID_VALUE" }]
    });
  }
  const len = value.length;
  const rem = len % 4;
  if (rem === 1) {
    throw invalidBase64UrlError(fieldPath);
  }
  const decodedLen = Math.floor(len / 4) * 3 + (rem === 2 ? 1 : rem === 3 ? 2 : 0);
  if (options?.exactByteLength !== undefined && decodedLen !== options.exactByteLength) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Decoded base64url length ${decodedLen} does not match expected ${options.exactByteLength} for ${fieldPath}`,
      fieldErrors: [{ path: fieldPath, code: "INVALID_VALUE" }]
    });
  }
  if (options?.maxDecodedBytes !== undefined && decodedLen > options.maxDecodedBytes) {
    throw new ValidationDomainError({
      code: "PAYLOAD_TOO_LARGE",
      message: `Decoded base64url length ${decodedLen} exceeds max ${options.maxDecodedBytes} for ${fieldPath}`,
      fieldErrors: [{ path: fieldPath, code: "PAYLOAD_TOO_LARGE" }]
    });
  }

  const out = new Uint8Array(decodedLen);
  let outIdx = 0;
  const fullQuads = Math.floor(len / 4) * 4;

  for (let i = 0; i < fullQuads; i += 4) {
    const c0 = value.charCodeAt(i);
    const c1 = value.charCodeAt(i + 1);
    const c2 = value.charCodeAt(i + 2);
    const c3 = value.charCodeAt(i + 3);
    const v0 = c0 < 128 ? (BASE64URL_REVERSE[c0] ?? -1) : -1;
    const v1 = c1 < 128 ? (BASE64URL_REVERSE[c1] ?? -1) : -1;
    const v2 = c2 < 128 ? (BASE64URL_REVERSE[c2] ?? -1) : -1;
    const v3 = c3 < 128 ? (BASE64URL_REVERSE[c3] ?? -1) : -1;
    if (v0 < 0 || v1 < 0 || v2 < 0 || v3 < 0) {
      throw invalidBase64UrlError(fieldPath);
    }
    out[outIdx++] = (v0 << 2) | (v1 >>> 4);
    out[outIdx++] = ((v1 & 0x0f) << 4) | (v2 >>> 2);
    out[outIdx++] = ((v2 & 0x03) << 6) | v3;
  }

  if (rem === 2) {
    const c0 = value.charCodeAt(fullQuads);
    const c1 = value.charCodeAt(fullQuads + 1);
    const v0 = c0 < 128 ? (BASE64URL_REVERSE[c0] ?? -1) : -1;
    const v1 = c1 < 128 ? (BASE64URL_REVERSE[c1] ?? -1) : -1;
    if (v0 < 0 || v1 < 0 || (v1 & 0x0f) !== 0) {
      throw invalidBase64UrlError(fieldPath);
    }
    out[outIdx++] = (v0 << 2) | (v1 >>> 4);
  } else if (rem === 3) {
    const c0 = value.charCodeAt(fullQuads);
    const c1 = value.charCodeAt(fullQuads + 1);
    const c2 = value.charCodeAt(fullQuads + 2);
    const v0 = c0 < 128 ? (BASE64URL_REVERSE[c0] ?? -1) : -1;
    const v1 = c1 < 128 ? (BASE64URL_REVERSE[c1] ?? -1) : -1;
    const v2 = c2 < 128 ? (BASE64URL_REVERSE[c2] ?? -1) : -1;
    if (v0 < 0 || v1 < 0 || v2 < 0 || (v2 & 0x03) !== 0) {
      throw invalidBase64UrlError(fieldPath);
    }
    out[outIdx++] = (v0 << 2) | (v1 >>> 4);
    out[outIdx++] = ((v1 & 0x0f) << 4) | (v2 >>> 2);
  }

  return out;
}

function invalidBase64UrlError(fieldPath: string): ValidationDomainError {
  return new ValidationDomainError({
    code: "INVALID_VALUE",
    message: `Invalid strict unpadded base64url encoding for ${fieldPath}`,
    fieldErrors: [{ path: fieldPath, code: "INVALID_VALUE" }]
  });
}

export function isStrictBase64Url(value: unknown): value is Base64UrlString {
  if (typeof value !== "string") {
    return false;
  }
  try {
    decodeBase64UrlStrict(value);
    return true;
  } catch {
    return false;
  }
}

export type StrictJsonValue =
  | null
  | boolean
  | number
  | string
  | readonly StrictJsonValue[]
  | { readonly [key: string]: StrictJsonValue };

export interface StrictJsonParseOptions {
  readonly fieldPath?: string | undefined;
  readonly maxDepth?: number | undefined;
  readonly maxNodes?: number | undefined;
}

export function parseStrictJsonValue(
  input: string,
  options?: StrictJsonParseOptions
): StrictJsonValue {
  const fieldPath = options?.fieldPath ?? "json";
  const maxDepth = options?.maxDepth ?? 32;
  const maxNodes = options?.maxNodes ?? 32_768;

  if (typeof input !== "string" || input.length === 0) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Expected non-empty JSON string for ${fieldPath}`,
      fieldErrors: [{ path: fieldPath, code: "INVALID_VALUE" }]
    });
  }

  let pos = 0;
  let nodes = 0;

  function fail(message: string): never {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `${message} in ${fieldPath}`,
      fieldErrors: [{ path: fieldPath, code: "INVALID_VALUE" }]
    });
  }

  function countNode(): void {
    nodes += 1;
    if (nodes > maxNodes) {
      fail(`JSON node count exceeds limit ${maxNodes}`);
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
              fail("Invalid \\u escape sequence");
            }
            const codeUnit = parseHex4(input.slice(pos, pos + 4));
            if (codeUnit < 0) {
              fail("Invalid hex digits in \\u escape");
            }
            pos += 4;
            if (codeUnit >= 0xd800 && codeUnit <= 0xdbff) {
              if (input.slice(pos, pos + 2) !== "\\u" || pos + 6 > input.length) {
                fail("Unpaired UTF-16 high surrogate escape");
              }
              const lowUnit = parseHex4(input.slice(pos + 2, pos + 6));
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
            fail("Invalid escape sequence");
        }
      } else if (ch >= 0xd800 && ch <= 0xdbff) {
        const next = pos + 1 < input.length ? input.charCodeAt(pos + 1) : 0;
        if (next < 0xdc00 || next > 0xdfff) {
          fail("Unpaired UTF-16 high surrogate in JSON string");
        }
        out += String.fromCharCode(ch, next);
        pos += 2;
      } else if (ch >= 0xdc00 && ch <= 0xdfff) {
        fail("Unpaired UTF-16 low surrogate in JSON string");
      } else {
        out += input[pos]!;
        pos += 1;
      }
    }
    fail("Unterminated JSON string");
  }

  function parseNumber(): number {
    const start = pos;
    if (input.charCodeAt(pos) === 0x2d) {
      pos += 1;
    }
    if (pos >= input.length) {
      fail("Invalid JSON number");
    }
    if (input.charCodeAt(pos) === 0x30) {
      pos += 1;
      if (pos < input.length && isDigit(input.charCodeAt(pos))) {
        fail("Leading zero in JSON number");
      }
    } else if (isDigit19(input.charCodeAt(pos))) {
      while (pos < input.length && isDigit(input.charCodeAt(pos))) {
        pos += 1;
      }
    } else {
      fail("Invalid JSON number");
    }

    if (pos < input.length && input.charCodeAt(pos) === 0x2e) {
      pos += 1;
      if (pos >= input.length || !isDigit(input.charCodeAt(pos))) {
        fail("Invalid fractional part in JSON number");
      }
      while (pos < input.length && isDigit(input.charCodeAt(pos))) {
        pos += 1;
      }
    }

    if (pos < input.length && (input.charCodeAt(pos) === 0x65 || input.charCodeAt(pos) === 0x45)) {
      pos += 1;
      if (pos < input.length && (input.charCodeAt(pos) === 0x2b || input.charCodeAt(pos) === 0x2d)) {
        pos += 1;
      }
      if (pos >= input.length || !isDigit(input.charCodeAt(pos))) {
        fail("Invalid exponent in JSON number");
      }
      while (pos < input.length && isDigit(input.charCodeAt(pos))) {
        pos += 1;
      }
    }

    const num = Number(input.slice(start, pos));
    if (!Number.isFinite(num)) {
      fail("Non-finite JSON number");
    }
    return Object.is(num, -0) ? 0 : num;
  }

  function parseValue(depth: number): StrictJsonValue {
    if (depth > maxDepth) {
      fail(`JSON depth exceeds limit ${maxDepth}`);
    }
    countNode();
    skipWs();
    if (pos >= input.length) {
      fail("Unexpected end of JSON input");
    }

    const ch = input.charCodeAt(pos);
    if (ch === 0x22) {
      return parseString();
    }
    if (ch === 0x7b) {
      pos += 1;
      skipWs();
      const obj: Record<string, StrictJsonValue> = {};
      const seenKeys = new Set<string>();
      if (pos < input.length && input.charCodeAt(pos) === 0x7d) {
        pos += 1;
        return obj;
      }
      while (true) {
        skipWs();
        if (pos >= input.length || input.charCodeAt(pos) !== 0x22) {
          fail("Expected object key string");
        }
        const key = parseString();
        if (seenKeys.has(key)) {
          fail(`Duplicate JSON object key "${key}"`);
        }
        seenKeys.add(key);
        skipWs();
        if (pos >= input.length || input.charCodeAt(pos) !== 0x3a) {
          fail("Expected ':' after object key");
        }
        pos += 1;
        const val = parseValue(depth + 1);
        Object.defineProperty(obj, key, {
          value: val,
          enumerable: true,
          writable: true,
          configurable: true
        });
        skipWs();
        if (pos >= input.length) {
          fail("Unterminated JSON object");
        }
        const delim = input.charCodeAt(pos);
        if (delim === 0x7d) {
          pos += 1;
          return obj;
        }
        if (delim !== 0x2c) {
          fail("Expected ',' or '}' in JSON object");
        }
        pos += 1;
      }
    }
    if (ch === 0x5b) {
      pos += 1;
      skipWs();
      const arr: StrictJsonValue[] = [];
      if (pos < input.length && input.charCodeAt(pos) === 0x5d) {
        pos += 1;
        return arr;
      }
      while (true) {
        arr.push(parseValue(depth + 1));
        skipWs();
        if (pos >= input.length) {
          fail("Unterminated JSON array");
        }
        const delim = input.charCodeAt(pos);
        if (delim === 0x5d) {
          pos += 1;
          return arr;
        }
        if (delim !== 0x2c) {
          fail("Expected ',' or ']' in JSON array");
        }
        pos += 1;
      }
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
      return parseNumber();
    }
    fail("Unexpected token in JSON");
  }

  const root = parseValue(0);
  skipWs();
  if (pos !== input.length) {
    fail("Trailing characters after JSON document");
  }
  return root;
}

function parseHex4(slice: string): number {
  let acc = 0;
  for (let i = 0; i < 4; i += 1) {
    const nib = parseHexNibble(slice.charCodeAt(i));
    if (nib < 0) {
      return -1;
    }
    acc = (acc << 4) | nib;
  }
  return acc;
}

function isDigit(code: number): boolean {
  return code >= 0x30 && code <= 0x39;
}

function isDigit19(code: number): boolean {
  return code >= 0x31 && code <= 0x39;
}

export function assertPlainRecord(
  value: unknown,
  fieldPath = "body"
): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Expected JSON object for ${fieldPath}`,
      fieldErrors: [{ path: fieldPath, code: "INVALID_VALUE" }]
    });
  }
  const proto: unknown = Object.getPrototypeOf(value);
  if (proto !== null && proto !== Object.prototype) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Expected plain JSON object for ${fieldPath}`,
      fieldErrors: [{ path: fieldPath, code: "INVALID_VALUE" }]
    });
  }
  return value as Record<string, unknown>;
}

export function assertAllowedKeys(
  record: Record<string, unknown>,
  allowedKeys: ReadonlySet<string>,
  fieldPath = "body"
): void {
  for (const key of Object.keys(record)) {
    if (!allowedKeys.has(key)) {
      throw new ValidationDomainError({
        code: "INVALID_VALUE",
        message: `Unsupported field "${key}" in ${fieldPath}`,
        fieldErrors: [{ path: `${fieldPath}.${key}`, code: "INVALID_VALUE" }]
      });
    }
  }
}

export function parseStrictJsonObject(
  input: string,
  options?: StrictJsonParseOptions
): Record<string, StrictJsonValue> {
  const parsed = parseStrictJsonValue(input, options);
  return assertPlainRecord(parsed, options?.fieldPath ?? "json") as Record<string, StrictJsonValue>;
}
