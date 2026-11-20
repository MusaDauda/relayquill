import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { LimitExceededDomainError, ValidationDomainError } from "@relayquill/domain";
import { isLosslessNumber } from "lossless-json";
import {
  EVENT_MAX_CONTENT_BYTES,
  EVENT_MAX_JSON_DEPTH,
  EVENT_MAX_JSON_NODES,
  EVENT_MAX_NUMERIC_TOKEN_BYTES,
  NUMERIC_MAX_COEFFICIENT_DIGITS,
  NUMERIC_MAX_EXPONENT,
  NUMERIC_MIN_EXPONENT,
  compareNormalizedDecimals,
  countUnicodeScalarValues,
  equalNormalizedDecimals,
  formatNormalizedDecimal,
  isNormalizedInteger,
  normalizeLosslessNumber,
  normalizeNumericToken,
  parseEventJsonBytes,
  parseEventJsonString
} from "@relayquill/event-schema";

test("parseEventJsonBytes preserves exact raw bytes, SHA-256, and owned buffer copy", () => {
  const inputText = '{"amount":90071992547409931234567890.123456789,"currency":"USD"}';
  const raw = new TextEncoder().encode(inputText);
  const expectedSha = crypto.createHash("sha256").update(raw).digest("hex");

  const parsed = parseEventJsonBytes(raw);
  assert.equal(parsed.byteCount, raw.length);
  assert.equal(parsed.sha256, expectedSha);
  assert.equal(
    parsed.sha256,
    "4fa483dbe4f7cccdeb0fb207aa12edd7f69791928a714f9fdc27f698c35372e4"
  );

  // Mutating caller's buffer must not mutate parsed.rawBytes
  raw[0] = 0x20;
  assert.equal(parsed.rawBytes[0], 0x7b);

  // Whitespace differences produce distinct raw SHA-256 digests
  const spaced = parseEventJsonString('{"message": "hello"}');
  const compact = parseEventJsonString('{"message":"hello"}');
  assert.notEqual(spaced.sha256, compact.sha256);
});

test("parser retains LosslessNumber without Number precision loss or Date auto-coercion", () => {
  const doc =
    '{"bigInt":9007199254740993,"prev":9007199254740992,"huge":1e1024,"isoDate":"2026-11-01T12:00:00.000000Z","negZero":-0,"decimal":1.0}';
  const parsed = parseEventJsonString(doc);
  const obj = parsed.value;

  assert.equal(isLosslessNumber(obj.bigInt), true);
  assert.equal(isLosslessNumber(obj.prev), true);
  assert.equal(isLosslessNumber(obj.huge), true);
  assert.equal(isLosslessNumber(obj.negZero), true);
  assert.equal(isLosslessNumber(obj.decimal), true);

  assert.equal(obj.bigInt.toString(), "9007199254740993");
  assert.equal(obj.prev.toString(), "9007199254740992");
  assert.equal(obj.huge.toString(), "1e1024");
  assert.equal(obj.negZero.toString(), "-0");
  assert.equal(obj.decimal.toString(), "1.0");

  // ISO timestamps remain plain strings (never Date objects)
  assert.equal(typeof obj.isoDate, "string");
  assert.equal(obj.isoDate instanceof Date, false);
  assert.equal(obj.isoDate, "2026-11-01T12:00:00.000000Z");
});

test("parser rejects invalid UTF-8 bytes, lone surrogates, BOM, trailing documents, and duplicate keys", () => {
  // Invalid UTF-8 byte sequences
  for (const badBytes of [
    new Uint8Array([0x22, 0xc0, 0xaf, 0x22]),
    new Uint8Array([0x22, 0xed, 0xa0, 0x80, 0x22]),
    new Uint8Array([0x22, 0xf4, 0x90, 0x80, 0x80, 0x22]),
    new Uint8Array([0x22, 0xe2, 0x82, 0x22]),
    new Uint8Array([0xef, 0xbb, 0xbf, 0x7b, 0x7d]) // UTF-8 BOM
  ]) {
    assert.throws(() => parseEventJsonBytes(badBytes), ValidationDomainError);
  }

  // Literal lone UTF-16 surrogates in strings
  assert.throws(() => parseEventJsonString('{"s":"\ud800"}'), ValidationDomainError);
  assert.throws(() => parseEventJsonString('{"s":"\udc00"}'), ValidationDomainError);

  // Escaped lone UTF-16 surrogates inside JSON strings
  assert.throws(() => parseEventJsonString('{"s":"\\ud800"}'), ValidationDomainError);
  assert.throws(() => parseEventJsonString('{"s":"\\udc00"}'), ValidationDomainError);
  assert.throws(() => parseEventJsonString('{"s":"\\ud800\\u0041"}'), ValidationDomainError);

  // Valid surrogate pair escape succeeds and counts 1 scalar
  const emoji = parseEventJsonString('{"s":"\\ud83d\\ude80"}');
  assert.equal(emoji.value.s, "🚀");
  assert.equal(countUnicodeScalarValues(emoji.value.s), 1);

  // Multiple or trailing documents rejected
  assert.throws(() => parseEventJsonString("{}{}"), ValidationDomainError);
  assert.throws(() => parseEventJsonString('{"a":1} 2'), ValidationDomainError);
  assert.throws(() => parseEventJsonString("   "), ValidationDomainError);

  // Duplicate keys rejected for both different and identical values and escaped keys
  assert.throws(() => parseEventJsonString('{"a":1,"a":2}'), ValidationDomainError);
  assert.throws(() => parseEventJsonString('{"a":1,"a":1}'), ValidationDomainError);
  assert.throws(() => parseEventJsonString('{"a":1,"\\u0061":1}'), ValidationDomainError);
  assert.throws(() => parseEventJsonString('{"nested":{"k":true,"k":true}}'), ValidationDomainError);
});

test("parser enforces 256 KiB byte limit, depth <= 32, nodes <= 32768, and numeric token <= 256B", () => {
  // 256 KiB exact boundary
  const overhead = '{"d":""}'.length;
  const maxStr = "a".repeat(EVENT_MAX_CONTENT_BYTES - overhead);
  const atLimitBytes = new TextEncoder().encode(`{"d":"${maxStr}"}`);
  assert.equal(atLimitBytes.length, EVENT_MAX_CONTENT_BYTES);
  assert.equal(parseEventJsonBytes(atLimitBytes).byteCount, EVENT_MAX_CONTENT_BYTES);

  const overLimitBytes = new TextEncoder().encode(`{"d":"${maxStr}a"}`);
  assert.equal(overLimitBytes.length, EVENT_MAX_CONTENT_BYTES + 1);
  assert.throws(
    () => parseEventJsonBytes(overLimitBytes),
    (err) => err instanceof ValidationDomainError && err.code === "PAYLOAD_TOO_LARGE"
  );

  // Depth boundary: 32 succeeds, 33 fails
  const depth32 = `${"[".repeat(EVENT_MAX_JSON_DEPTH)}1${"]".repeat(EVENT_MAX_JSON_DEPTH)}`;
  assert.equal(parseEventJsonString(depth32).maxObservedDepth, EVENT_MAX_JSON_DEPTH);
  const depth33 = `${"[".repeat(EVENT_MAX_JSON_DEPTH + 1)}1${"]".repeat(EVENT_MAX_JSON_DEPTH + 1)}`;
  assert.throws(
    () => parseEventJsonString(depth33),
    (err) => err instanceof LimitExceededDomainError && err.code === "SCHEMA_EVALUATION_LIMIT"
  );

  // Node count boundary: 32768 succeeds (1 root array + 32767 items), 32769 fails
  const itemsAtLimit = new Array(EVENT_MAX_JSON_NODES - 1).fill("1").join(",");
  const parsedMaxNodes = parseEventJsonString(`[${itemsAtLimit}]`);
  assert.equal(parsedMaxNodes.nodeCount, EVENT_MAX_JSON_NODES);

  const itemsOverLimit = new Array(EVENT_MAX_JSON_NODES).fill("1").join(",");
  assert.throws(
    () => parseEventJsonString(`[${itemsOverLimit}]`),
    (err) => err instanceof LimitExceededDomainError && err.code === "SCHEMA_EVALUATION_LIMIT"
  );

  // Numeric token length boundary: 256 bytes succeeds, 257 fails
  const token256 = `1${"0".repeat(EVENT_MAX_NUMERIC_TOKEN_BYTES - 1)}`;
  assert.equal(parseEventJsonString(token256).value.toString(), token256);

  const token257 = `1${"0".repeat(EVENT_MAX_NUMERIC_TOKEN_BYTES)}`;
  assert.throws(
    () => parseEventJsonString(token257),
    (err) => err instanceof LimitExceededDomainError && err.code === "SCHEMA_EVALUATION_LIMIT"
  );
});

test("numeric normalizer preserves exact decimal arithmetic and rejects overflows cleanly", () => {
  assert.deepEqual(normalizeNumericToken("-12.3400e+2"), {
    sign: -1,
    coefficient: "1234",
    exponent: 0
  });
  assert.deepEqual(normalizeNumericToken("1.0"), {
    sign: 1,
    coefficient: "1",
    exponent: 0
  });
  assert.equal(isNormalizedInteger(normalizeNumericToken("1.0")), true);
  assert.equal(isNormalizedInteger(normalizeNumericToken("1.5")), false);

  const negZero = normalizeNumericToken("-0.00e+5");
  const posZero = normalizeNumericToken("0");
  assert.deepEqual(negZero, { sign: 0, coefficient: "0", exponent: 0 });
  assert.equal(equalNormalizedDecimals(negZero, posZero), true);
  assert.equal(compareNormalizedDecimals(negZero, posZero), 0);

  // Boundary lossless big numbers: 9007199254740993 vs 9007199254740992, 1e1024, 1e-1024, 128 digits
  const n993 = normalizeNumericToken("9007199254740993");
  const n992 = normalizeNumericToken("9007199254740992");
  assert.equal(compareNormalizedDecimals(n993, n992), 1);
  assert.equal(compareNormalizedDecimals(n992, n993), -1);

  const maxExp = normalizeNumericToken(`1e${NUMERIC_MAX_EXPONENT}`);
  assert.deepEqual(maxExp, { sign: 1, coefficient: "1", exponent: NUMERIC_MAX_EXPONENT });
  assert.equal(formatNormalizedDecimal(maxExp), "1e1024");

  const minExp = normalizeNumericToken(`1e${NUMERIC_MIN_EXPONENT}`);
  assert.deepEqual(minExp, { sign: 1, coefficient: "1", exponent: NUMERIC_MIN_EXPONENT });
  assert.equal(compareNormalizedDecimals(maxExp, minExp), 1);

  const maxCoeff = `1${"2".repeat(NUMERIC_MAX_COEFFICIENT_DIGITS - 2)}3`;
  assert.equal(normalizeNumericToken(maxCoeff).coefficient, maxCoeff);

  // Negative comparison ordering and fractional prefixes
  assert.equal(
    compareNormalizedDecimals(normalizeNumericToken("-12.34"), normalizeNumericToken("-12.3")),
    -1
  );
  assert.equal(
    compareNormalizedDecimals(normalizeNumericToken("1.2"), normalizeNumericToken("1.20001")),
    -1
  );

  // Overflows & unsafe JS numbers reject cleanly (never Infinity/null/rounding)
  for (const extreme of [
    `1e${NUMERIC_MAX_EXPONENT + 1}`,
    `10e${NUMERIC_MAX_EXPONENT}`,
    `1e${NUMERIC_MIN_EXPONENT - 1}`,
    `0.1e${NUMERIC_MIN_EXPONENT}`,
    `0e${NUMERIC_MAX_EXPONENT + 1}`,
    `1${"0".repeat(NUMERIC_MAX_COEFFICIENT_DIGITS - 1)}1`
  ]) {
    assert.throws(
      () => normalizeNumericToken(extreme),
      (err) => err instanceof LimitExceededDomainError && err.code === "SCHEMA_EVALUATION_LIMIT"
    );
  }

  assert.throws(() => normalizeLosslessNumber(Number.POSITIVE_INFINITY), LimitExceededDomainError);
  assert.throws(() => normalizeLosslessNumber(Number.NaN), LimitExceededDomainError);
  assert.throws(() => normalizeLosslessNumber(9007199254740992), ValidationDomainError);
});
