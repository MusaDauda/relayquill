import test from "node:test";
import assert from "node:assert/strict";
import { inspect } from "node:util";
import {
  AuthenticationDomainError,
  AuthorizationDomainError,
  BUSINESS_KEY_MAX_UTF8_BYTES,
  ConflictDomainError,
  DependencyUnavailableDomainError,
  DomainError,
  ExpiredDomainError,
  INT64_MAX,
  INT64_MIN,
  InvariantViolationError,
  LimitExceededDomainError,
  MAX_DOMAIN_FIELD_ERRORS,
  NotFoundDomainError,
  OpaqueSecret,
  RateLimitDomainError,
  UnsupportedStateTransitionError,
  ValidationDomainError,
  addMilliseconds,
  addSeconds,
  clampDeadline,
  compareInstants,
  computeUtf8ByteLength,
  diffMicroseconds,
  diffMilliseconds,
  formatInt64,
  formatUtcTimestamp,
  fromEpochMicroseconds,
  isBusinessKey,
  isCanonicalUtcTimestamp,
  isCanonicalUuid,
  isEventTypeName,
  isIdempotencyKey,
  isInt64String,
  isKeyId,
  isNonNegativeInt64String,
  isPositiveInt64String,
  isProducerCredentialSelector,
  isProducerNamespace,
  isSha256Hex,
  isExpired,
  parseBusinessKey,
  parseCanonicalUuid,
  parseDeliveryId,
  parseEventId,
  parseEventTypeName,
  parseIdempotencyKey,
  parseInt64BigInt,
  parseInt64String,
  parseKeyId,
  parseNonNegativeInt64String,
  parsePositiveInt64String,
  parseProducerCredentialSelector,
  parseProducerCredentialToken,
  parseProducerNamespace,
  parseSha256Hex,
  parseTenantId,
  parseUtcTimestamp,
  toEpochMicroseconds
} from "@relayquill/domain";

test("UUID parsing normalizes uppercase hex and rejects invalid formats", () => {
  const upper = "00000000-0000-4000-8000-00000000010A";
  const lower = "00000000-0000-4000-8000-00000000010a";

  assert.equal(parseCanonicalUuid(upper), lower);
  assert.equal(parseTenantId(upper), lower);
  assert.equal(parseEventId(upper), lower);
  assert.equal(parseDeliveryId(upper), lower);
  assert.equal(isCanonicalUuid(lower), true);
  assert.equal(isCanonicalUuid(upper), false);

  for (const invalid of [
    "",
    "not-a-uuid",
    `{${lower}}`,
    ` ${lower}`,
    `${lower} `,
    "00000000-0000-4000-8000-00000000010",
    "00000000-0000-4000-8000-00000000010g"
  ]) {
    assert.throws(() => parseCanonicalUuid(invalid), ValidationDomainError);
  }
});

test("Sha256Hex, Int64String, and canonical value brands validate boundaries", () => {
  const digestUpper = "A".repeat(64);
  const digestLower = "a".repeat(64);
  assert.equal(parseSha256Hex(digestUpper), digestLower);
  assert.equal(isSha256Hex(digestLower), true);
  assert.equal(isSha256Hex(digestUpper), false);
  assert.throws(() => parseSha256Hex("a".repeat(63)), ValidationDomainError);

  assert.equal(parseInt64String("0"), "0");
  assert.equal(parseInt64String(INT64_MIN.toString()), INT64_MIN.toString());
  assert.equal(parseInt64String(INT64_MAX.toString()), INT64_MAX.toString());
  assert.equal(parseInt64BigInt("-42"), -42n);
  assert.equal(formatInt64(9007199254740993n), "9007199254740993");
  assert.equal(parseNonNegativeInt64String("0"), "0");
  assert.equal(parsePositiveInt64String("1"), "1");
  assert.equal(isInt64String("42"), true);
  assert.equal(isNonNegativeInt64String("-1"), false);
  assert.equal(isPositiveInt64String("0"), false);

  for (const badInt of [
    "+1",
    "01",
    "-0",
    "1e5",
    "9223372036854775808",
    "-9223372036854775809",
    "1.5"
  ]) {
    assert.throws(() => parseInt64String(badInt), ValidationDomainError);
  }
  assert.throws(() => parseNonNegativeInt64String("-1"), ValidationDomainError);
  assert.throws(() => parsePositiveInt64String("0"), ValidationDomainError);

  assert.equal(parseProducerNamespace("billing.invoices"), "billing.invoices");
  assert.equal(
    parseProducerNamespace("human.00000000-0000-4000-8000-00000000010A"),
    "human.00000000-0000-4000-8000-00000000010a"
  );
  assert.equal(isProducerNamespace("human.not-a-uuid"), false);
  assert.throws(() => parseProducerNamespace("human.invalid"), ValidationDomainError);

  assert.equal(parseKeyId("k1.primary_2026"), "k1.primary_2026");
  assert.equal(isKeyId("bad key"), false);
  assert.equal(parseIdempotencyKey("req-123_abc"), "req-123_abc");
  assert.equal(isIdempotencyKey("has space"), false);
  assert.equal(parseEventTypeName("invoice.payment_succeeded"), "invoice.payment_succeeded");
  assert.equal(isEventTypeName("BadCase"), false);
});

test("BusinessKey enforces 1..128 UTF-8 bytes and rejects lone surrogates", () => {
  const exact128 = "a".repeat(BUSINESS_KEY_MAX_UTF8_BYTES);
  assert.equal(parseBusinessKey(exact128), exact128);
  assert.equal(isBusinessKey("a".repeat(129)), false);

  // 32 x 4-byte emoji = 128 UTF-8 bytes
  const emoji128 = "\u{1F680}".repeat(32);
  assert.equal(computeUtf8ByteLength(emoji128), 128);
  assert.equal(parseBusinessKey(emoji128), emoji128);
  assert.equal(isBusinessKey(`${emoji128}a`), false);

  const loneHigh = "abc\ud800def";
  assert.equal(isBusinessKey(loneHigh), false);
  assert.throws(() => parseBusinessKey(loneHigh), ValidationDomainError);
  assert.throws(() => parseBusinessKey(""), ValidationDomainError);
});

test("OpaqueSecret and ProducerCredentialSelector never leak secrets", () => {
  const rawSecret = "super-sensitive-secret-material";
  const wrapped = new OpaqueSecret(rawSecret);

  assert.equal(wrapped.expose(), rawSecret);
  assert.equal(JSON.stringify({ token: wrapped }), '{"token":"[REDACTED]"}');
  assert.equal(String(wrapped), "[REDACTED]");
  assert.equal(`${wrapped}`, "[REDACTED]");
  assert.equal(inspect(wrapped), "[REDACTED]");
  assert.deepEqual(Object.keys(wrapped), []);
  assert.deepEqual({ ...wrapped }, {});
  assert.throws(() => new OpaqueSecret(""), ValidationDomainError);

  const credUuid = "00000000-0000-4000-8000-000000000105";
  const selector = `rq_p1.${credUuid}`;
  assert.equal(isProducerCredentialSelector(selector), true);
  assert.equal(parseProducerCredentialSelector(selector).credentialId, credUuid);

  const secretPart = "A".repeat(43);
  const fullToken = `${selector}.${secretPart}`;
  const parsed = parseProducerCredentialToken(fullToken);
  assert.equal(parsed.selector, selector);
  assert.equal(parsed.credentialId, credUuid);
  assert.equal(JSON.stringify(parsed).includes(secretPart), false);
  assert.equal(parsed.secret.expose(), secretPart);
  assert.throws(() => parseProducerCredentialToken(`${selector}.too-short`), ValidationDomainError);
});

test("time.ts preserves microseconds, rejects invalid RFC3339 variants, and does exact bigint math", () => {
  const parsedOffset = parseUtcTimestamp("2026-11-01T12:00:00.123456+02:00");
  assert.equal(parsedOffset.canonical, "2026-11-01T10:00:00.123456Z");
  assert.equal(isCanonicalUtcTimestamp(parsedOffset.canonical), true);

  const parsedWholeSec = parseUtcTimestamp("2026-11-01T12:00:00Z");
  assert.equal(parsedWholeSec.canonical, "2026-11-01T12:00:00.000000Z");
  assert.equal(formatUtcTimestamp(parsedWholeSec.instant), "2026-11-01T12:00:00.000000Z");

  const us = toEpochMicroseconds(parsedOffset.instant);
  assert.equal(fromEpochMicroseconds(us).equals(parsedOffset.instant), true);

  const plusMs = addMilliseconds(parsedOffset.instant, 500);
  const plusSec = addSeconds(parsedOffset.instant, 2n);
  assert.equal(diffMicroseconds(plusMs, parsedOffset.instant), 500_000n);
  assert.equal(diffMilliseconds(plusSec, parsedOffset.instant), 2_000n);
  assert.equal(compareInstants(plusMs, plusSec), -1);
  assert.equal(isExpired(parsedOffset.instant, parsedOffset.instant), true);
  assert.equal(isExpired(plusSec, parsedOffset.instant), false);
  assert.equal(clampDeadline(plusSec, plusMs).equals(plusMs), true);

  for (const badTs of [
    "2026-11-01T12:00:00-00:00",
    "2026-11-01T12:00:60Z",
    "2026-11-01T12:00:00",
    "2026-11-01T12:00:00Z[UTC]",
    "2026-11-01T12:00:00.1234567Z",
    "2026-02-30T12:00:00Z",
    "2026-11-01T12:00:00Z ",
    "+002026-11-01T12:00:00Z"
  ]) {
    assert.throws(() => parseUtcTimestamp(badTs), ValidationDomainError);
  }
});

test("errors.ts hierarchy preserves instanceof, safe JSON/inspect, and caps fieldErrors at 20", () => {
  const manyFields = Array.from({ length: 30 }, (_, idx) => ({
    path: `items[${idx}]`,
    code: "INVALID_VALUE"
  }));
  const err = new ValidationDomainError({
    message: "Too many invalid fields",
    boundary: "accepted",
    fieldErrors: manyFields,
    resourceRef: { kind: "event", id: "00000000-0000-4000-8000-000000000105" }
  });

  assert.ok(err instanceof Error);
  assert.ok(err instanceof DomainError);
  assert.ok(err instanceof ValidationDomainError);
  assert.equal(err.retryable, false);
  assert.equal(err.acceptance, "known_rejected");
  assert.equal(err.fieldErrors?.length, MAX_DOMAIN_FIELD_ERRORS);
  assert.equal(err.toJSON().fieldErrors?.length, 20);
  assert.equal(inspect(err).includes("ValidationDomainError"), true);

  const depErr = new DependencyUnavailableDomainError({ message: "db timeout" });
  assert.equal(depErr.retryable, true);
  assert.equal(depErr.acceptance, "unknown");

  const rateErr = new RateLimitDomainError({ message: "throttled" });
  assert.equal(rateErr.retryable, true);

  assert.ok(new AuthenticationDomainError({ message: "a" }) instanceof DomainError);
  assert.ok(new AuthorizationDomainError({ message: "b" }) instanceof DomainError);
  assert.ok(new NotFoundDomainError({ message: "c" }) instanceof DomainError);
  assert.ok(new ConflictDomainError({ message: "d" }) instanceof DomainError);
  assert.ok(new ExpiredDomainError({ message: "e" }) instanceof DomainError);
  assert.ok(new LimitExceededDomainError({ message: "f" }) instanceof DomainError);
  assert.ok(new UnsupportedStateTransitionError({ message: "g" }) instanceof DomainError);
  assert.ok(new InvariantViolationError({ message: "h" }) instanceof DomainError);
});
