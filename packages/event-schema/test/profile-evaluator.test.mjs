import test from "node:test";
import assert from "node:assert/strict";
import { LimitExceededDomainError, ValidationDomainError } from "@relayquill/domain";
import {
  EVENT_SCHEMA_DIALECT_2020_12,
  EVENT_SCHEMA_PROFILE_V1,
  SCHEMA_MAX_DEFS,
  SCHEMA_MAX_DEPTH,
  SCHEMA_MAX_DIAGNOSTICS,
  SCHEMA_MAX_ENUM_VALUES,
  SCHEMA_MAX_OBJECT_PROPERTIES,
  SCHEMA_MAX_RAW_BYTES,
  SCHEMA_MAX_REF_EDGES,
  SchemaCompilationCache,
  checkSchemaCompatibility,
  compileEventSchema,
  evaluateEventBytes,
  evaluateParsedEvent,
  parseEventJsonString
} from "@relayquill/event-schema";

function encodeJson(obj) {
  return new TextEncoder().encode(JSON.stringify(obj));
}

test("compileEventSchema validates bounded JSON Schema 2020-12 subset and rejects unsupported keywords", () => {
  const echoSchemaBytes = encodeJson({
    $schema: EVENT_SCHEMA_DIALECT_2020_12,
    title: "Echo",
    type: "object",
    properties: {
      message: {
        type: "string",
        minLength: 1,
        maxLength: 256
      }
    },
    required: ["message"],
    additionalProperties: false
  });

  const compiled = compileEventSchema(echoSchemaBytes);
  assert.equal(compiled.profileVersion, EVENT_SCHEMA_PROFILE_V1);
  assert.equal(compiled.dialect, EVENT_SCHEMA_DIALECT_2020_12);

  // Valid evaluation
  const validRes = evaluateEventBytes(compiled, encodeJson({ message: "hello" }));
  assert.equal(validRes.valid, true);
  assert.equal(validRes.diagnostics.length, 0);

  // Rejected dialect
  assert.throws(
    () =>
      compileEventSchema(
        encodeJson({
          $schema: "https://json-schema.org/draft-07/schema#",
          type: "string",
          maxLength: 10
        })
      ),
    (err) => err instanceof ValidationDomainError && err.code === "UNSUPPORTED_SCHEMA_VERSION"
  );

  // Unsupported keywords rejected (never ignored)
  for (const badSchema of [
    { type: "string", maxLength: 10, pattern: "^[a-z]+$" },
    { type: "string", maxLength: 64, format: "email" },
    { type: "object", properties: {}, additionalProperties: true },
    { type: "object", properties: {} }, // missing additionalProperties: false
    { type: "object", properties: { a: { type: "string", maxLength: 5 } }, required: ["missing"], additionalProperties: false },
    { type: "array", items: { type: "string", maxLength: 5 } }, // missing maxItems
    { type: "string" }, // missing maxLength
    { type: "string", minLength: 10, maxLength: 5 },
    { type: "integer", minimum: 10, maximum: 5 },
    { type: "array", items: { type: "integer" }, minItems: 5, maxItems: 2 },
    { type: ["string", "integer"] },
    { type: ["null", "string"], maxLength: 10 },
    { $ref: "#/$defs/A", $defs: { A: { type: "string", maxLength: 5 } } }, // root $ref forbidden
    { oneOf: [{ type: "string", maxLength: 5 }] },
    {
      type: "object",
      properties: { a: { type: "string", maxLength: 5 } },
      additionalProperties: false,
      $defs: { Unused: { type: "string", pattern: ".*" } } // unreachable def still validated!
    }
  ]) {
    assert.throws(() => compileEventSchema(encodeJson(badSchema)), ValidationDomainError);
  }
});

test("compileEventSchema enforces local $ref rules, cycle detection, and structural bounds", () => {
  // Local $ref with ~0/~1 escaping works
  const schemaWithRefs = compileEventSchema(
    encodeJson({
      type: "object",
      properties: {
        item: { $ref: "#/$defs/a~1b~0c", description: "referenced" },
        note: { type: ["string", "null"], maxLength: 20 }
      },
      required: ["item"],
      additionalProperties: false,
      $defs: {
        "a/b~c": {
          type: "object",
          properties: { id: { type: "string", minLength: 1, maxLength: 32 } },
          required: ["id"],
          additionalProperties: false
        }
      }
    })
  );
  assert.equal(
    evaluateEventBytes(schemaWithRefs, encodeJson({ item: { id: "x" }, note: null })).valid,
    true
  );

  // External ref and $ref sibling keywords reject
  assert.throws(
    () =>
      compileEventSchema(
        encodeJson({
          type: "object",
          properties: { x: { $ref: "https://example.com/schema.json" } },
          additionalProperties: false
        })
      ),
    ValidationDomainError
  );
  assert.throws(
    () =>
      compileEventSchema(
        encodeJson({
          type: "object",
          properties: { x: { $ref: "#/$defs/S", minLength: 2 } },
          additionalProperties: false,
          $defs: { S: { type: "string", maxLength: 10 } }
        })
      ),
    ValidationDomainError
  );

  // Cyclic $defs (even unreachable) reject
  assert.throws(
    () =>
      compileEventSchema(
        encodeJson({
          type: "object",
          properties: { ok: { type: "boolean" } },
          additionalProperties: false,
          $defs: {
            A: { type: "object", properties: { b: { $ref: "#/$defs/B" } }, additionalProperties: false },
            B: { type: "object", properties: { a: { $ref: "#/$defs/A" } }, additionalProperties: false }
          }
        })
      ),
    ValidationDomainError
  );

  // Raw 64 KiB cap
  const oversizedDesc = "x".repeat(SCHEMA_MAX_RAW_BYTES);
  assert.throws(
    () =>
      compileEventSchema(
        encodeJson({ type: "string", maxLength: 10, description: oversizedDesc })
      ),
    (err) => err instanceof ValidationDomainError && err.code === "PAYLOAD_TOO_LARGE"
  );

  // Max 128 object properties
  const props129 = {};
  for (let i = 0; i < SCHEMA_MAX_OBJECT_PROPERTIES + 1; i += 1) {
    props129[`k${i}`] = { type: "boolean" };
  }
  assert.throws(
    () => compileEventSchema(encodeJson({ type: "object", properties: props129, additionalProperties: false })),
    LimitExceededDomainError
  );

  // Max 64 enum values
  const enum65 = Array.from({ length: SCHEMA_MAX_ENUM_VALUES + 1 }, (_, i) => `v${i}`);
  assert.throws(
    () => compileEventSchema(encodeJson({ type: "string", maxLength: 10, enum: enum65 })),
    LimitExceededDomainError
  );

  // Max 32 $defs
  const defs33 = {};
  for (let i = 0; i < SCHEMA_MAX_DEFS + 1; i += 1) {
    defs33[`D${i}`] = { type: "boolean" };
  }
  assert.throws(
    () => compileEventSchema(encodeJson({ type: "object", properties: {}, additionalProperties: false, $defs: defs33 })),
    LimitExceededDomainError
  );

  // Max 64 $ref edges
  const props65Refs = {};
  for (let i = 0; i < SCHEMA_MAX_REF_EDGES + 1; i += 1) {
    props65Refs[`f${i}`] = { $ref: "#/$defs/Flag" };
  }
  assert.throws(
    () =>
      compileEventSchema(
        encodeJson({
          type: "object",
          properties: props65Refs,
          additionalProperties: false,
          $defs: { Flag: { type: "boolean" } }
        })
      ),
    LimitExceededDomainError
  );

  // Expanded depth 16 allowed, 17 rejected
  const buildNested = (depth) => {
    let cur = { type: "string", maxLength: 8 };
    for (let i = 0; i < depth; i += 1) {
      cur = { type: "object", properties: { next: cur }, additionalProperties: false };
    }
    return cur;
  };
  assert.equal(compileEventSchema(encodeJson(buildNested(SCHEMA_MAX_DEPTH))).maxExpandedDepth, SCHEMA_MAX_DEPTH);
  assert.throws(
    () => compileEventSchema(encodeJson(buildNested(SCHEMA_MAX_DEPTH + 1))),
    LimitExceededDomainError
  );
});

test("evaluator handles lossless large numbers, Unicode scalar counts, prototype safety, and caps", () => {
  const schema = compileEventSchema(
    '{"type":"object","properties":{"amount":{"type":"number","minimum":9007199254740993,"maximum":1e1024},"count":{"type":"integer"},"tag":{"type":"string","minLength":1,"maxLength":2},"opt":{"type":["string","null"],"maxLength":8,"enum":["a","b"]}},"required":["amount","count","tag"],"additionalProperties":false}'
  );

  // Exact integer boundary 9007199254740993 vs 9007199254740992, 1.0 integer, 1 scalar emoji
  const passParsed = parseEventJsonString(
    '{"amount":9007199254740993,"count":1.0,"tag":"🚀"}'
  );
  assert.equal(evaluateParsedEvent(schema, passParsed.value).valid, true);

  const maxExpParsed = parseEventJsonString(
    '{"amount":1e1024,"count":0,"tag":"ok"}'
  );
  assert.equal(evaluateParsedEvent(schema, maxExpParsed.value).valid, true);

  const belowMinParsed = parseEventJsonString(
    '{"amount":9007199254740992,"count":1,"tag":"ok"}'
  );
  const belowRes = evaluateParsedEvent(schema, belowMinParsed.value);
  assert.equal(belowRes.valid, false);
  assert.equal(belowRes.diagnostics[0]?.code, "NUMBER_MINIMUM");

  // 1e1025 rejects cleanly with SCHEMA_EVALUATION_LIMIT
  const overflowParsed = parseEventJsonString(
    '{"amount":1e1025,"count":1,"tag":"ok"}'
  );
  assert.throws(
    () => evaluateParsedEvent(schema, overflowParsed.value),
    (err) => err instanceof LimitExceededDomainError && err.code === "SCHEMA_EVALUATION_LIMIT"
  );

  // String "123" never coerced to integer/number
  const coerced = parseEventJsonString('{"amount":"9007199254740993","count":1,"tag":"ok"}');
  assert.equal(evaluateParsedEvent(schema, coerced.value).valid, false);

  // Nullable with enum omitting null rejects null
  const nullOpt = parseEventJsonString('{"amount":9007199254740993,"count":1,"tag":"ok","opt":null}');
  assert.equal(evaluateParsedEvent(schema, nullOpt.value).valid, false);

  // Inherited prototype objects and Object.prototype properties cannot satisfy required
  const protoParent = { amount: 9007199254740993, count: 1, tag: "ok" };
  const inherited = Object.create(protoParent);
  const inheritedRes = evaluateParsedEvent(schema, inherited);
  assert.equal(inheritedRes.valid, false);
  assert.equal(inheritedRes.diagnostics[0]?.code, "TYPE_MISMATCH");

  const protoPropSchema = compileEventSchema(
    encodeJson({
      type: "object",
      properties: { toString: { type: "string", maxLength: 32 } },
      required: ["toString"],
      additionalProperties: false
    })
  );
  const protoPropRes = evaluateParsedEvent(protoPropSchema, {});
  assert.equal(protoPropRes.valid, false);
  assert.equal(protoPropRes.diagnostics[0]?.code, "REQUIRED_PROPERTY_MISSING");

  // Diagnostic cap (<= 20) & private value omission
  const reqProps = {};
  const reqList = [];
  for (let i = 0; i < 30; i += 1) {
    reqProps[`p${i}`] = { type: "string", maxLength: 4 };
    reqList.push(`p${i}`);
  }
  const bigReqSchema = compileEventSchema(
    encodeJson({ type: "object", properties: reqProps, required: reqList, additionalProperties: false })
  );
  const diagRes = evaluateEventBytes(bigReqSchema, encodeJson({}));
  assert.equal(diagRes.valid, false);
  assert.equal(diagRes.diagnostics.length, SCHEMA_MAX_DIAGNOSTICS);
  assert.equal(diagRes.totalDiagnosticsObserved, 30);

  // Work unit cap
  assert.throws(
    () => evaluateParsedEvent(bigReqSchema, parseEventJsonString("{}").value, { maxWorkUnits: 5 }),
    LimitExceededDomainError
  );
});

test("SchemaCompilationCache and checkSchemaCompatibility work conservatively", () => {
  const v1Bytes = encodeJson({
    type: "object",
    properties: { id: { type: "string", minLength: 1, maxLength: 32 } },
    required: ["id"],
    additionalProperties: false
  });
  const v2AdditiveBytes = encodeJson({
    type: "object",
    properties: {
      id: { type: "string", minLength: 1, maxLength: 64 },
      note: { type: "string", maxLength: 100 }
    },
    required: ["id"],
    additionalProperties: false
  });
  const v2BreakingBytes = encodeJson({
    type: "object",
    properties: {
      id: { type: "string", minLength: 1, maxLength: 32 },
      requiredNew: { type: "string", maxLength: 10 }
    },
    required: ["id", "requiredNew"],
    additionalProperties: false
  });

  const cache = new SchemaCompilationCache(2);
  const s1 = compileEventSchema(v1Bytes);
  const cached1 = cache.getOrCompile(
    { eventTypeId: "00000000-0000-4000-8000-000000000305", schemaVersion: 1, definitionSha256: s1.definitionSha256 },
    v1Bytes
  );
  assert.equal(cached1.definitionSha256, s1.definitionSha256);
  assert.equal(cache.size, 1);

  const s2Add = compileEventSchema(v2AdditiveBytes);
  const s2Break = compileEventSchema(v2BreakingBytes);

  assert.equal(checkSchemaCompatibility(s1, s2Add).recommendedPolicy, "additive_compatible");
  assert.equal(checkSchemaCompatibility(s1, s2Break).recommendedPolicy, "new_breaking_version");
});
