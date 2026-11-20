import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { LimitExceededDomainError, ValidationDomainError } from "@relayquill/domain";
import {
  DERIVED_MAX_CONTENT_BYTES,
  EVENT_MAX_ENVELOPE_BYTES,
  MAX_ACTIVE_PROFILES_PER_SOURCE_SCHEMA,
  PROJECTION_COMPILER_VERSION,
  assertActiveRepresentationProfileBudget,
  buildDerivedWebhookEnvelopeV2,
  compileEventSchema,
  compileProjectionProfile,
  computeDerivedWireEnvelopeUpperBoundBytes,
  executeProjection
} from "@relayquill/event-schema";
import { decodeWebhookEnvelopeBytes } from "@relayquill/contracts";

function encodeJson(obj) {
  return new TextEncoder().encode(JSON.stringify(obj));
}

const EVENT_TYPE_ID = "00000000-0000-4000-8000-000000000305";

test("compileProjectionProfile proves totality and size bounds and rejects incomplete or unsafe mappings", () => {
  const sourceSchema = compileEventSchema(
    encodeJson({
      type: "object",
      properties: {
        amount: { type: "number" },
        message: { type: "string", minLength: 1, maxLength: 64 },
        note: { type: "string", maxLength: 32 },
        nullableTag: { type: ["string", "null"], maxLength: 16 },
        flag: { type: "boolean" }
      },
      required: ["amount", "message"],
      additionalProperties: false
    })
  );

  const targetSchema = compileEventSchema(
    encodeJson({
      type: "object",
      properties: {
        amount: { type: "number" },
        summary: {
          type: "object",
          properties: {
            text: { type: "string", minLength: 1, maxLength: 64 },
            note: { type: "string", maxLength: 32 },
            mode: { type: "string", maxLength: 16 },
            scale: { type: "number" }
          },
          required: ["text", "note", "mode", "scale"],
          additionalProperties: false
        },
        flag: { type: "boolean" }
      },
      required: ["amount", "summary"],
      additionalProperties: false
    })
  );

  const validProfile = compileProjectionProfile(
    JSON.stringify({
      profile_schema_version: 1,
      source_event_type_id: EVENT_TYPE_ID,
      source_schema_version: 1,
      target_schema_version: 2,
      mappings: [
        { operation: "copy", target_path: "/amount", source_path: "/amount" },
        { operation: "copy", target_path: "/summary/text", source_path: "/message" },
        {
          operation: "copy_or_default",
          target_path: "/summary/note",
          source_path: "/note",
          default_value: "none"
        },
        { operation: "constant", target_path: "/summary/mode", value: "v2" },
        { operation: "constant", target_path: "/summary/scale", value: 1.5 },
        { operation: "copy", target_path: "/flag", source_path: "/flag" }
      ]
    }),
    sourceSchema,
    targetSchema
  );

  assert.equal(validProfile.compilerProfileVersion, PROJECTION_COMPILER_VERSION);
  assert.equal(validProfile.provenOutputMaxBytes <= DERIVED_MAX_CONTENT_BYTES, true);
  assert.equal(validProfile.maxWireEnvelopeUpperBoundBytes <= EVENT_MAX_ENVELOPE_BYTES, true);

  // Rejects missing required target field (/summary/note omitted)
  assert.throws(
    () =>
      compileProjectionProfile(
        {
          profile_schema_version: 1,
          source_event_type_id: EVENT_TYPE_ID,
          source_schema_version: 1,
          target_schema_version: 2,
          mappings: [
            { operation: "copy", target_path: "/amount", source_path: "/amount" },
            { operation: "copy", target_path: "/summary/text", source_path: "/message" },
            { operation: "constant", target_path: "/summary/mode", value: "v2" },
            { operation: "constant", target_path: "/summary/scale", value: 1.5 }
          ]
        },
        sourceSchema,
        targetSchema
      ),
    ValidationDomainError
  );

  // Rejects optional source copied directly into required target without copy_or_default
  assert.throws(
    () =>
      compileProjectionProfile(
        {
          profile_schema_version: 1,
          source_event_type_id: EVENT_TYPE_ID,
          source_schema_version: 1,
          target_schema_version: 2,
          mappings: [
            { operation: "copy", target_path: "/amount", source_path: "/amount" },
            { operation: "copy", target_path: "/summary/text", source_path: "/message" },
            { operation: "copy", target_path: "/summary/note", source_path: "/note" },
            { operation: "constant", target_path: "/summary/mode", value: "v2" },
            { operation: "constant", target_path: "/summary/scale", value: 1.5 }
          ]
        },
        sourceSchema,
        targetSchema
      ),
    ValidationDomainError
  );

  // Rejects nullable source copied into non-nullable target even with copy_or_default
  assert.throws(
    () =>
      compileProjectionProfile(
        {
          profile_schema_version: 1,
          source_event_type_id: EVENT_TYPE_ID,
          source_schema_version: 1,
          target_schema_version: 2,
          mappings: [
            { operation: "copy", target_path: "/amount", source_path: "/amount" },
            { operation: "copy", target_path: "/summary/text", source_path: "/message" },
            {
              operation: "copy_or_default",
              target_path: "/summary/note",
              source_path: "/nullableTag",
              default_value: "fallback"
            },
            { operation: "constant", target_path: "/summary/mode", value: "v2" },
            { operation: "constant", target_path: "/summary/scale", value: 1.5 }
          ]
        },
        sourceSchema,
        targetSchema
      ),
    ValidationDomainError
  );

  // Rejects overlapping parent/child target writes (/summary and /summary/text)
  assert.throws(
    () =>
      compileProjectionProfile(
        {
          profile_schema_version: 1,
          source_event_type_id: EVENT_TYPE_ID,
          source_schema_version: 1,
          target_schema_version: 2,
          mappings: [
            { operation: "copy", target_path: "/amount", source_path: "/amount" },
            {
              operation: "constant",
              target_path: "/summary",
              value: { text: "hi", note: "n", mode: "v2", scale: 1 }
            },
            { operation: "copy", target_path: "/summary/text", source_path: "/message" }
          ]
        },
        sourceSchema,
        targetSchema
      ),
    ValidationDomainError
  );

  // Rejects target > 96 KiB worst-case size
  const hugeTargetSchema = compileEventSchema(
    encodeJson({
      type: "object",
      properties: {
        blob: { type: "string", maxLength: 20_000 }
      },
      required: ["blob"],
      additionalProperties: false
    })
  );
  const hugeSourceSchema = compileEventSchema(
    encodeJson({
      type: "object",
      properties: {
        blob: { type: "string", maxLength: 20_000 }
      },
      required: ["blob"],
      additionalProperties: false
    })
  );
  assert.throws(
    () =>
      compileProjectionProfile(
        {
          profile_schema_version: 1,
          source_event_type_id: EVENT_TYPE_ID,
          source_schema_version: 1,
          target_schema_version: 2,
          mappings: [{ operation: "copy", target_path: "/blob", source_path: "/blob" }]
        },
        hugeSourceSchema,
        hugeTargetSchema
      ),
    LimitExceededDomainError
  );

  // Worst-case 256 KiB original + 96 KiB derived stays within 512 KiB wire envelope ceiling
  const maxAllowedWireBytes = computeDerivedWireEnvelopeUpperBoundBytes({
    originalContentByteCount: 262_144,
    provenDerivedMaxBytes: 98_304
  });
  assert.equal(maxAllowedWireBytes <= EVENT_MAX_ENVELOPE_BYTES, true);

  // Exceeding 96 KiB derived ceiling rejects wire upper bound calculation
  assert.throws(
    () =>
      computeDerivedWireEnvelopeUpperBoundBytes({
        originalContentByteCount: 262_144,
        provenDerivedMaxBytes: 98_305
      }),
    ValidationDomainError
  );

  // Active profile budget per source schema capped at 8
  assertActiveRepresentationProfileBudget(MAX_ACTIVE_PROFILES_PER_SOURCE_SCHEMA - 1);
  assert.throws(
    () => assertActiveRepresentationProfileBudget(MAX_ACTIVE_PROFILES_PER_SOURCE_SCHEMA),
    LimitExceededDomainError
  );
});

test("executeProjection preserves lossless numbers, handles missing-vs-falsy copy_or_default, and builds valid WebhookEnvelopeV2", () => {
  const sourceSchema = compileEventSchema(
    encodeJson({
      type: "object",
      properties: {
        amount: { type: "number" },
        count: { type: "integer" },
        flag: { type: "boolean" },
        label: { type: ["string", "null"], maxLength: 32 },
        optNum: { type: "number" }
      },
      required: ["amount", "count", "flag"],
      additionalProperties: false
    })
  );

  const targetSchema = compileEventSchema(
    encodeJson({
      type: "object",
      properties: {
        amount: { type: "number" },
        count: { type: "integer" },
        flag: { type: "boolean" },
        label: { type: ["string", "null"], maxLength: 32 },
        optNum: { type: "number" },
        policyScale: { type: "number" }
      },
      required: ["amount", "count", "flag", "label", "optNum", "policyScale"],
      additionalProperties: false
    })
  );

  const profileJson = `{
    "profile_schema_version": 1,
    "source_event_type_id": "${EVENT_TYPE_ID}",
    "source_schema_version": 1,
    "target_schema_version": 2,
    "mappings": [
      { "operation": "copy", "target_path": "/amount", "source_path": "/amount" },
      { "operation": "copy_or_default", "target_path": "/count", "source_path": "/count", "default_value": 99 },
      { "operation": "copy_or_default", "target_path": "/flag", "source_path": "/flag", "default_value": true },
      { "operation": "copy_or_default", "target_path": "/label", "source_path": "/label", "default_value": "defaulted" },
      { "operation": "copy_or_default", "target_path": "/optNum", "source_path": "/optNum", "default_value": 1.5 },
      { "operation": "constant", "target_path": "/policyScale", "value": 1e1024 }
    ]
  }`;
  const profile = compileProjectionProfile(
    profileJson,
    sourceSchema,
    targetSchema
  );

  // Case 1: present 0, false, null are preserved (NOT replaced by defaults); missing optNum uses default 15e-1
  const sourceRaw1 = new TextEncoder().encode(
    '{"amount":9007199254740993,"count":0,"flag":false,"label":null}'
  );
  const res1 = executeProjection(profile, sourceRaw1);
  assert.equal(
    res1.derivedJson,
    '{"amount":9007199254740993,"count":0,"flag":false,"label":null,"optNum":15e-1,"policyScale":1e1024}'
  );

  // Case 2: copied LosslessNumber preserves exact original lexeme (-12.3400e+2)
  const sourceRaw2 = new TextEncoder().encode(
    '{"amount":-12.3400e+2,"count":1.0,"flag":true,"optNum":1e1024}'
  );
  const res2 = executeProjection(profile, sourceRaw2);
  assert.equal(
    res2.derivedJson,
    '{"amount":-12.3400e+2,"count":1.0,"flag":true,"label":"defaulted","optNum":1e1024,"policyScale":1e1024}'
  );

  // Invalid source payload is rejected rather than silently transformed
  assert.throws(
    () => executeProjection(profile, new TextEncoder().encode('{"amount":"bad","count":1,"flag":true}')),
    ValidationDomainError
  );
  assert.equal(
    res1.sourceContentSha256,
    crypto.createHash("sha256").update(sourceRaw1).digest("hex")
  );
  assert.equal(res1.provenance.is_private_data_redaction, false);
  assert.equal(res1.provenance.contains_original_provenance, true);
  assert.deepEqual(res1.provenance.applied_default_paths, ["/optNum"]);
  assert.deepEqual(res1.provenance.policy_constant_paths, ["/policyScale"]);

  // Build valid WebhookEnvelopeV2 retaining original bytes & provenance
  const wireV2 = buildDerivedWebhookEnvelopeV2({
    representation_version: 2,
    project_id: "00000000-0000-4000-8000-000000000105",
    event_id: "00000000-0000-4000-8000-000000000205",
    project_event_sequence: "1",
    event_type_id: EVENT_TYPE_ID,
    event_type: "demo.echoed",
    event_schema_version: 1,
    admitted_at: "2026-11-01T12:00:00.000000Z",
    producer_event_time: null,
    profile_id: "00000000-0000-4000-8000-000000000705",
    profile_version: "1",
    profile_sha256: profile.definitionSha256,
    projection: res1
  });

  const decodedWire = decodeWebhookEnvelopeBytes(wireV2.body_bytes);
  assert.equal(decodedWire.envelope.envelope_version, 2);
  assert.deepEqual(decodedWire.original_content_bytes, sourceRaw1);
  assert.deepEqual(decodedWire.derived_content_bytes, res1.derivedBytes);
});
