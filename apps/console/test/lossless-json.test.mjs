import test from "node:test";
import assert from "node:assert/strict";
import {
  decodeBase64JsonLossless,
  formatLosslessJson,
  inspectLosslessJsonText,
  parseStrictLosslessJsonText
} from "../src/utils/lossless-json.js";

test("lossless-json preserves 64-bit+ integers and exact decimals verbatim", () => {
  const raw = '{"bigInt":9223372036854775807,"minInt":-9223372036854775808,"u64":18446744073709551615,"decimal":0.0825000,"price":19.90}';
  const parsed = parseStrictLosslessJsonText(raw);
  const formatted = formatLosslessJson(parsed.root, 2);

  assert.match(formatted, /9223372036854775807/);
  assert.match(formatted, /-9223372036854775808/);
  assert.match(formatted, /18446744073709551615/);
  assert.match(formatted, /0\.0825000/);
  assert.match(formatted, /19\.90/);
  assert.ok(parsed.precisionRiskPaths.includes("/bigInt"));
  assert.ok(parsed.precisionRiskPaths.includes("/u64"));
});

test("lossless-json rejects duplicate keys, leading zeros, trailing garbage, and isolates prototype", () => {
  assert.throws(
    () => parseStrictLosslessJsonText('{"a":1,"a":2}'),
    /duplicate/i
  );
  assert.throws(
    () => parseStrictLosslessJsonText('{"a":01}'),
    /leading zero/i
  );
  assert.throws(
    () => parseStrictLosslessJsonText('{"a":1} trailing'),
    /unexpected/i
  );

  const protoSafe = parseStrictLosslessJsonText('{"__proto__":{"polluted":true}}');
  assert.equal(Object.getPrototypeOf(protoSafe.root), Object.prototype);
  assert.equal("polluted" in {}, false);
});

test("inspectLosslessJsonText and decodeBase64JsonLossless round-trip UTF-8 bytes without corruption", () => {
  const source = '{"order":"ord-αβγ","ledger":9223372036854775807}';
  const inspected = inspectLosslessJsonText(source);
  assert.equal(inspected.valid, true);
  assert.equal(inspected.byteCount, Buffer.byteLength(source, "utf8"));
  assert.equal(inspected.sha256.length, 64);

  const decoded = decodeBase64JsonLossless(inspected.base64);
  assert.equal(decoded.validJson, true);
  assert.equal(decoded.rawText, source);
  assert.match(decoded.formattedText, /9223372036854775807/);
});
