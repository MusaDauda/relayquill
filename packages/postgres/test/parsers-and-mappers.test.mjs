import test from "node:test";
import assert from "node:assert/strict";
import pg from "pg";
import { Temporal } from "@js-temporal/polyfill";
import { parseEventId, parseSha256Hex } from "@relayquill/domain";
import {
  PG_OID_INT8,
  PG_OID_TIMESTAMP,
  PG_OID_TIMESTAMPTZ,
  RELAYQUILL_PGLITE_PARSERS,
  assertSingleRow,
  byteaToBuffer,
  byteaToSha256Hex,
  createPGliteAdapter,
  createScopedPgTypes,
  parsePgArrayLiteral,
  parsePgInt8String,
  parsePgTimestampToCanonicalUtc,
  readOptionalInt64BigInt,
  readRequiredBoolean,
  readRequiredInt32,
  readRequiredInt64BigInt,
  readRequiredInt64String,
  readRequiredJsonRecord,
  readRequiredUtcTimestamp,
  readRequiredUuid,
  sha256HexToBytea
} from "@relayquill/postgres";

test("pg CustomTypesConfig and PGlite parsers match identically for timestamptz, timestamp, and int8", () => {
  const pgTypes = createScopedPgTypes();
  const pgTimestamptz = pgTypes.getTypeParser(PG_OID_TIMESTAMPTZ, "text");
  const pgTimestamp = pgTypes.getTypeParser(PG_OID_TIMESTAMP, "text");
  const pgInt8 = pgTypes.getTypeParser(PG_OID_INT8, "text");

  const samplesTz = [
    ["2026-11-18 07:08:10.123456+00", "2026-11-18T07:08:10.123456Z"],
    ["2026-11-18 07:08:10+00", "2026-11-18T07:08:10.000000Z"],
    ["2026-11-18 09:08:10.5+02", "2026-11-18T07:08:10.500000Z"],
    ["2026-11-18 01:38:10.0042-05:30", "2026-11-18T07:08:10.004200Z"]
  ];

  for (const [wire, expected] of samplesTz) {
    assert.equal(pgTimestamptz(wire), expected);
    assert.equal(RELAYQUILL_PGLITE_PARSERS[PG_OID_TIMESTAMPTZ](wire), expected);
    assert.equal(typeof pgTimestamptz(wire), "string");
  }

  const samplesNaive = [
    ["2026-11-18 07:08:10.000001", "2026-11-18T07:08:10.000001Z"],
    ["2026-11-18 07:08:10", "2026-11-18T07:08:10.000000Z"]
  ];
  for (const [wire, expected] of samplesNaive) {
    assert.equal(pgTimestamp(wire), expected);
    assert.equal(RELAYQUILL_PGLITE_PARSERS[PG_OID_TIMESTAMP](wire), expected);
  }

  const samplesInt8 = [
    "0",
    "42",
    "9007199254740993",
    "9223372036854775807",
    "-9223372036854775808"
  ];
  for (const wire of samplesInt8) {
    assert.equal(pgInt8(wire), wire);
    assert.equal(RELAYQUILL_PGLITE_PARSERS[PG_OID_INT8](wire), wire);
    assert.equal(typeof pgInt8(wire), "string");
  }

  // Fallback for ordinary OIDs (e.g. text OID 25) still delegates to pg.types
  const fallbackTextParser = pgTypes.getTypeParser(25, "text");
  assert.equal(fallbackTextParser("hello"), pg.types.getTypeParser(25, "text")("hello"));
});

test("timestamp parsers reject infinity and sub-microsecond inputs", () => {
  assert.throws(() => parsePgTimestampToCanonicalUtc("infinity", false), /Unsupported PostgreSQL timestamp/);
  assert.throws(() => parsePgTimestampToCanonicalUtc("-infinity", true), /Unsupported PostgreSQL timestamp/);
  assert.throws(() => parsePgTimestampToCanonicalUtc("2026-11-18 00:00:00.1234567+00", false), /exceeds microsecond precision/);
  assert.throws(() => parsePgInt8String("9223372036854775808"), /signed 64-bit range/);
  assert.deepEqual(parsePgArrayLiteral('{1,NULL,"9223372036854775807"}', parsePgInt8String), [
    "1",
    null,
    "9223372036854775807"
  ]);
});

test("PGlite query round-trips 64-bit ints, microsecond timestamps, UUIDs, sha256 bytea, and JSONB without precision loss", async (t) => {
  const db = await createPGliteAdapter();
  t.after(() => db.close());

  const id = "11111111-1111-4111-8111-111111111111";
  const digest = parseSha256Hex("a".repeat(64));

  const res = await db.query(
    `SELECT
       $1::bigint AS big_val,
       $2::timestamptz AS ts_tz,
       $3::timestamp AS ts_plain,
       $4::uuid AS id_val,
       $5::bytea AS digest_bytes,
       $6::jsonb AS meta_json,
       42::integer AS small_int,
       true AS flag_val`,
    [
      "9223372036854775807",
      "2026-11-18T12:34:56.000789+00:00",
      "2026-11-18T12:34:56.000789",
      id,
      sha256HexToBytea(digest),
      JSON.stringify({ ok: true, count: 3 })
    ]
  );

  const row = assertSingleRow(res, "roundtrip");
  assert.equal(readRequiredInt64String(row, "big_val"), "9223372036854775807");
  assert.equal(readRequiredInt64BigInt(row, "big_val"), 9_223_372_036_854_775_807n);
  assert.equal(readOptionalInt64BigInt({ missing: null }, "missing"), undefined);
  assert.equal(readRequiredUtcTimestamp(row, "ts_tz"), "2026-11-18T12:34:56.000789Z");
  assert.equal(readRequiredUtcTimestamp(row, "ts_plain"), "2026-11-18T12:34:56.000789Z");
  assert.equal(readRequiredUuid(row, "id_val", parseEventId), id);
  assert.equal(byteaToSha256Hex(row["digest_bytes"]), digest);
  assert.equal(byteaToBuffer(row["digest_bytes"]).byteLength, 32);
  assert.deepEqual(readRequiredJsonRecord(row, "meta_json"), { ok: true, count: 3 });
  assert.equal(readRequiredInt32(row, "small_int"), 42);
  assert.equal(readRequiredBoolean(row, "flag_val"), true);
  assert.equal(
    Temporal.Instant.from(readRequiredUtcTimestamp(row, "ts_tz")).epochNanoseconds % 1_000n,
    0n
  );
});
