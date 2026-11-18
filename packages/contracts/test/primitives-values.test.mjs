import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { ValidationDomainError } from "@relayquill/domain";
import {
  INT64_MAX,
  INT64_MIN,
  bytesToLowerHex,
  constantTimeEqual,
  decodeBase64Strict,
  decodeBase64UrlStrict,
  decodeUtf8BytesStrict,
  encodeBase64,
  encodeBase64Url,
  encodeUtf8Bytes,
  formatInt64,
  hmacSha256Digest,
  isCanonicalUtcTimestamp,
  isCanonicalUuid,
  isInt64String,
  isNonNegativeInt64String,
  isPositiveInt64String,
  isSha256Hex,
  isStrictBase64,
  isStrictBase64Url,
  parseBoundedInteger,
  parseCanonicalUtcTimestamp,
  parseCanonicalUuid,
  parseInt64String,
  parseNonNegativeInt64String,
  parsePositiveInt64String,
  parseSha256Hex,
  parseStrictJsonObject,
  parseStrictJsonValue,
  sha256Digest,
  sha256Hex
} from "@relayquill/contracts";

test("pure ES2023 sha256 and hmacSha256 match node:crypto across boundary lengths", () => {
  const inputs = [
    new Uint8Array(0),
    encodeUtf8Bytes('{"message":"hello"}'),
    new Uint8Array(55).fill(0x61),
    new Uint8Array(56).fill(0x62),
    new Uint8Array(64).fill(0x63),
    new Uint8Array(129).fill(0x64),
    encodeUtf8Bytes("relayquill-\u{1F680}-\u00e9-\u4e2d\u6587")
  ];

  for (const data of inputs) {
    const actualHex = sha256Hex(data);
    const expectedHex = crypto.createHash("sha256").update(data).digest("hex");
    assert.equal(actualHex, expectedHex);
    assert.deepEqual(sha256Digest(data), new Uint8Array(crypto.createHash("sha256").update(data).digest()));
  }

  for (const keyLen of [16, 32, 64, 100]) {
    const key = new Uint8Array(keyLen).map((_, idx) => (idx * 7 + 3) & 0xff);
    const msg = encodeUtf8Bytes("rq.webhook-signature.v1\0test-message");
    const actualMac = hmacSha256Digest(key, msg);
    const expectedMac = new Uint8Array(crypto.createHmac("sha256", key).update(msg).digest());
    assert.deepEqual(actualMac, expectedMac);
    assert.equal(constantTimeEqual(actualMac, expectedMac), true);
    const flipped = new Uint8Array(expectedMac);
    flipped[0] = (flipped[0] ?? 0) ^ 0x01;
    assert.equal(constantTimeEqual(actualMac, flipped), false);
  }
});

test("strict UTF-8 codec handles multi-byte code points and rejects malformed sequences", () => {
  const sample = "hello-\u00e9-\u20ac-\u{1F680}";
  const encoded = encodeUtf8Bytes(sample);
  assert.equal(decodeUtf8BytesStrict(encoded), sample);
  assert.equal(bytesToLowerHex(encodeUtf8Bytes("AB")), "4142");

  // Lone UTF-16 surrogates rejected on encode
  assert.throws(() => encodeUtf8Bytes("bad\ud800"), ValidationDomainError);
  assert.throws(() => encodeUtf8Bytes("bad\udc00"), ValidationDomainError);

  // Overlong encodings, UTF-8 surrogate code points, >U+10FFFF, and truncated bytes rejected
  for (const badBytes of [
    new Uint8Array([0xc0, 0xaf]), // overlong '/'
    new Uint8Array([0xe0, 0x80, 0xaf]), // overlong 3-byte
    new Uint8Array([0xed, 0xa0, 0x80]), // U+D800 surrogate
    new Uint8Array([0xf4, 0x90, 0x80, 0x80]), // > U+10FFFF
    new Uint8Array([0xe2, 0x82]), // truncated
    new Uint8Array([0x80]) // stray continuation
  ]) {
    assert.throws(() => decodeUtf8BytesStrict(badBytes), ValidationDomainError);
  }
});

test("strict base64 and unpadded base64url enforce RFC 4648 canonical bits", () => {
  const raw = encodeUtf8Bytes('{"message":"hello"}');
  const b64 = encodeBase64(raw);
  assert.equal(b64, "eyJtZXNzYWdlIjoiaGVsbG8ifQ==");
  assert.equal(isStrictBase64(b64), true);
  assert.deepEqual(decodeBase64Strict(b64), raw);

  // "a" encodes to "YQ==". "YR==" has non-zero unused padding bit.
  assert.equal(encodeBase64(encodeUtf8Bytes("a")), "YQ==");
  assert.equal(isStrictBase64("YR=="), false);
  assert.throws(() => decodeBase64Strict("YR=="), ValidationDomainError);
  assert.throws(() => decodeBase64Strict("YQ"), ValidationDomainError); // unpadded rejected
  assert.throws(() => decodeBase64Strict("YQ= ="), ValidationDomainError);

  // Base64URL unpadded
  const nonce = new Uint8Array(32).fill(0x41);
  const b64url = encodeBase64Url(nonce);
  assert.equal(b64url.length, 43);
  assert.equal(isStrictBase64Url(b64url), true);
  assert.deepEqual(decodeBase64UrlStrict(b64url, "nonce", { exactByteLength: 32 }), nonce);
  assert.throws(() => decodeBase64UrlStrict(`${b64url}=`), ValidationDomainError);
  assert.throws(() => decodeBase64UrlStrict("YR"), ValidationDomainError); // non-zero trailing bit
  assert.throws(() => decodeBase64UrlStrict("YQ==", "nonce"), ValidationDomainError);
});

test("UUID, SHA-256, int64 boundaries, timestamps, bounded integers, and strict JSON", () => {
  const upperUuid = "00000000-0000-4000-8000-00000000010F";
  const lowerUuid = "00000000-0000-4000-8000-00000000010f";
  assert.equal(parseCanonicalUuid(upperUuid), lowerUuid);
  assert.equal(isCanonicalUuid(lowerUuid), true);
  assert.equal(isCanonicalUuid(upperUuid), false);

  assert.equal(parseSha256Hex("F".repeat(64)), "f".repeat(64));
  assert.equal(isSha256Hex("f".repeat(64)), true);
  assert.equal(isSha256Hex("F".repeat(64)), false);

  assert.equal(parseInt64String(INT64_MIN.toString()), INT64_MIN.toString());
  assert.equal(parseInt64String(INT64_MAX.toString()), INT64_MAX.toString());
  assert.equal(formatInt64(9007199254740993n), "9007199254740993");
  assert.equal(parseNonNegativeInt64String("0"), "0");
  assert.equal(parsePositiveInt64String("1"), "1");
  assert.equal(isInt64String("0"), true);
  assert.equal(isNonNegativeInt64String("-1"), false);
  assert.equal(isPositiveInt64String("0"), false);

  for (const badInt of ["+1", "01", "-0", "1e5", "1.5", "9223372036854775808", "-9223372036854775809"]) {
    assert.throws(() => parseInt64String(badInt), ValidationDomainError);
  }

  assert.equal(
    parseCanonicalUtcTimestamp("2026-11-01T14:00:00.123456+02:00"),
    "2026-11-01T12:00:00.123456Z"
  );
  assert.equal(isCanonicalUtcTimestamp("2026-11-01T12:00:00.123456Z"), true);
  assert.throws(() => parseCanonicalUtcTimestamp("2026-11-01T12:00:00-00:00"), ValidationDomainError);
  assert.throws(() => parseCanonicalUtcTimestamp("2026-11-01T12:00:00.1234567Z"), ValidationDomainError);

  assert.equal(parseBoundedInteger(25, { fieldPath: "limit", min: 1, max: 100 }), 25);
  assert.throws(
    () => parseBoundedInteger(101, { fieldPath: "limit", min: 1, max: 100 }),
    ValidationDomainError
  );
  assert.throws(
    () => parseBoundedInteger(1.5, { fieldPath: "limit", min: 1, max: 100 }),
    ValidationDomainError
  );

  // Strict JSON rejects duplicate keys, trailing data, and lone surrogate escapes
  assert.deepEqual(parseStrictJsonObject('{"a":1,"b":"ok"}'), { a: 1, b: "ok" });
  assert.throws(() => parseStrictJsonObject('{"a":1,"a":2}'), ValidationDomainError);
  assert.throws(() => parseStrictJsonValue('{"a":1} trailing'), ValidationDomainError);
  assert.throws(() => parseStrictJsonValue('{"s":"\\ud800"}'), ValidationDomainError);
});
