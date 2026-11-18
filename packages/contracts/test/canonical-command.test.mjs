import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { ValidationDomainError } from "@relayquill/domain";
import {
  canonicalizeJson,
  computeBusinessKeySha256,
  computeCommandGuardKey,
  computeConsumerEventKeySha256,
  computeEffectiveAdmissionFingerprint,
  computeEventAdmissionCommandFingerprint,
  computeOrderingKeySha256,
  computeOriginalFactsSha256,
  computeRequestKeySha256,
  encodeUtf8Bytes,
  sha256Hex
} from "@relayquill/contracts";

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");
const COMMAND_VECTORS = JSON.parse(
  fs.readFileSync(path.join(REPO_ROOT, "contracts/canonical-command-v1/vectors.json"), "utf8")
);
const COMPAT_VECTORS = JSON.parse(
  fs.readFileSync(path.join(REPO_ROOT, "contracts/compatibility/vectors.json"), "utf8")
);

test("RFC 8785 deterministic canonicalizer sorts UTF-16 code units, escapes control chars, and rejects floats", () => {
  const reorderedA = { z: 1, a: "line\n\t\"\\/\u0001\u{1F680}", m: [true, false, null, -0] };
  const reorderedB = { m: [true, false, null, 0], a: "line\n\t\"\\/\u0001\u{1F680}", z: 1 };

  const jsonA = canonicalizeJson(reorderedA);
  const jsonB = canonicalizeJson(reorderedB);
  assert.equal(jsonA, jsonB);
  assert.equal(
    jsonA,
    '{"a":"line\\n\\t\\"\\\\/\\u0001\u{1F680}","m":[true,false,null,0],"z":1}'
  );

  // Code-unit key order: 'Z' (0x5a) < 'a' (0x61) < '\u00e9' (0xe9)
  assert.equal(canonicalizeJson({ "\u00e9": 1, a: 2, Z: 3 }), '{"Z":3,"a":2,"\u00e9":1}');

  // Floats, NaN, Infinity, lone surrogates, and undefined properties must reject
  assert.throws(() => canonicalizeJson({ bad: 1.5 }), ValidationDomainError);
  assert.throws(() => canonicalizeJson({ bad: Number.NaN }), ValidationDomainError);
  assert.throws(() => canonicalizeJson({ bad: Number.POSITIVE_INFINITY }), ValidationDomainError);
  assert.throws(() => canonicalizeJson({ bad: "\ud800" }), ValidationDomainError);
  assert.throws(() => canonicalizeJson({ bad: undefined }), ValidationDomainError);
});

test("relayquill.command.v1, effective.v1, and original_facts_sha256 match golden vectors", () => {
  for (const vec of COMMAND_VECTORS.command_vectors) {
    const result = computeEventAdmissionCommandFingerprint(vec.input);
    assert.equal(result.canonical_json, vec.expected_canonical_json, vec.name);
    assert.equal(result.sha256, vec.expected_sha256, vec.name);
  }

  // Reordered outer scope/submission keys produce identical hash
  const base = COMMAND_VECTORS.command_vectors[0].input;
  const reordered = computeEventAdmissionCommandFingerprint({
    submission: {
      byte_count: base.submission.byte_count,
      content_sha256: base.submission.content_sha256,
      event_schema_version: base.submission.event_schema_version,
      event_type_id: base.submission.event_type_id,
      business_key: base.submission.business_key
    },
    scope: {
      producer_namespace: base.scope.producer_namespace,
      actor_principal_id: base.scope.actor_principal_id,
      channel_kind: base.scope.channel_kind,
      publication_channel_id: base.scope.publication_channel_id,
      project_id: base.scope.project_id,
      tenant_id: base.scope.tenant_id
    }
  });
  assert.equal(reordered.sha256, COMMAND_VECTORS.command_vectors[0].expected_sha256);

  // Explicit null for optional timestamps is rejected
  assert.throws(
    () =>
      computeEventAdmissionCommandFingerprint({
        ...base,
        submission: { ...base.submission, producer_event_time: null }
      }),
    ValidationDomainError
  );
  assert.throws(
    () =>
      computeEventAdmissionCommandFingerprint({
        ...base,
        submission: { ...base.submission, deadline_at: null }
      }),
    ValidationDomainError
  );

  // Explicit deadline_at changes option_presence and fingerprint
  const withDeadline = computeEventAdmissionCommandFingerprint({
    ...base,
    submission: { ...base.submission, deadline_at: "2026-11-02T12:00:00.000000Z" }
  });
  assert.equal(withDeadline.canonical_object.option_presence.deadline_at, true);
  assert.notEqual(withDeadline.sha256, COMMAND_VECTORS.command_vectors[0].expected_sha256);

  // Effective fingerprint vector
  const eff = computeEffectiveAdmissionFingerprint(COMMAND_VECTORS.effective_vector.input);
  assert.equal(eff.canonical_json, COMMAND_VECTORS.effective_vector.expected_canonical_json);
  assert.equal(eff.sha256, COMMAND_VECTORS.effective_vector.expected_sha256);

  // Original semantic facts fingerprint
  const origFactsSha = computeOriginalFactsSha256(COMMAND_VECTORS.digest_vectors.original_facts);
  assert.equal(origFactsSha, COMMAND_VECTORS.digest_vectors.original_facts.expected_sha256);
});

test("length-prefixed domain digests and raw-content compatibility vectors match", () => {
  const dv = COMMAND_VECTORS.digest_vectors;

  assert.equal(computeBusinessKeySha256(dv.business_key), dv.business_key_sha256);
  assert.equal(computeRequestKeySha256(dv.request_key), dv.request_key_sha256);

  const guard = computeCommandGuardKey(dv.command_guard);
  assert.equal(guard.digest_sha256, dv.command_guard.expected_digest_sha256);
  assert.equal(guard.advisory_lock_key.toString(10), dv.command_guard.expected_advisory_lock_key);

  // Scope ancestry mismatch rejected
  assert.throws(
    () =>
      computeCommandGuardKey({
        ...dv.command_guard,
        scope_kind: "installation"
      }),
    ValidationDomainError
  );

  assert.equal(
    computeConsumerEventKeySha256(dv.consumer_event),
    dv.consumer_event.expected_sha256
  );
  assert.equal(computeOrderingKeySha256(dv.ordering_key), dv.ordering_key.expected_sha256);

  // Raw content whitespace and lossless large numeric bytes preserve distinct SHA-256 hashes
  const rc = COMPAT_VECTORS.raw_content_vectors;
  assert.equal(sha256Hex(encodeUtf8Bytes(rc.compact_echo_utf8)), rc.compact_echo_sha256);
  assert.equal(sha256Hex(encodeUtf8Bytes(rc.spaced_echo_utf8)), rc.spaced_echo_sha256);
  assert.notEqual(rc.compact_echo_sha256, rc.spaced_echo_sha256);
  assert.equal(
    sha256Hex(encodeUtf8Bytes(rc.lossless_large_numeric_utf8)),
    rc.lossless_large_numeric_sha256
  );
});
