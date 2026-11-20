import test from "node:test";
import assert from "node:assert/strict";
import {
  InvariantViolationError,
  LimitExceededDomainError,
  ValidationDomainError
} from "@relayquill/domain";
import {
  compileEventSchema,
  compileFilterAst,
  compileOrderingExtractor,
  evaluateFilter,
  extractOrderingKey,
  parseEventJsonString,
  parseJsonPointer,
  resolveJsonPointer
} from "@relayquill/event-schema";
import { computeOrderingKeySha256 } from "@relayquill/contracts";

function encodeJson(obj) {
  return new TextEncoder().encode(JSON.stringify(obj));
}

test("JSON Pointer decoding handles single-pass ~0/~1, rejects malformed escapes, and blocks prototype lookup", () => {
  const parsed = parseJsonPointer("/a~1b/c~0d/~01");
  assert.deepEqual(parsed.tokens, ["a/b", "c~d", "~1"]);

  for (const bad of ["", "no_leading_slash", "/bad~2escape", "/trailing~", "/a\ud800"]) {
    assert.throws(() => parseJsonPointer(bad), ValidationDomainError);
  }
  assert.throws(() => parseJsonPointer("/1/2/3/4/5/6/7/8/9"), ValidationDomainError);

  const obj = { nested: { value: null } };
  assert.deepEqual(resolveJsonPointer(obj, "/nested/value"), { present: true, value: null });
  assert.deepEqual(resolveJsonPointer(obj, "/nested/missing"), { present: false, value: undefined });
  assert.deepEqual(resolveJsonPointer(obj, "/constructor"), { present: false, value: undefined });
  assert.deepEqual(resolveJsonPointer(obj, "/toString"), { present: false, value: undefined });
  assert.deepEqual(resolveJsonPointer(obj, "/__proto__"), { present: false, value: undefined });

  const ownProto = parseEventJsonString('{"__proto__":"own-val"}').value;
  assert.deepEqual(resolveJsonPointer(ownProto, "/__proto__"), { present: true, value: "own-val" });
});

test("filter AST enforces grammar bounds, missing-vs-null semantics, and lossless numeric comparisons", () => {
  const schema = compileEventSchema(
    encodeJson({
      type: "object",
      properties: {
        status: { type: ["string", "null"], maxLength: 32 },
        amount: { type: "number" },
        meta: {
          type: "object",
          properties: { tier: { type: "string", maxLength: 16 } },
          additionalProperties: false
        },
        tags: { type: "array", items: { type: "string", maxLength: 16 }, maxItems: 8 }
      },
      required: ["amount"],
      additionalProperties: false
    })
  );

  // Missing vs present null vs not(eq(...))
  const existsFilter = compileFilterAst({ operation: "exists", path: "/status" }, [schema]);
  const eqNullFilter = compileFilterAst({ operation: "eq", path: "/status", value: null }, [schema]);
  const notEqFilter = compileFilterAst(
    { operation: "not", child: { operation: "eq", path: "/status", value: "void" } },
    [schema]
  );
  const presentNotEqFilter = compileFilterAst(
    {
      operation: "all",
      children: [
        { operation: "exists", path: "/status" },
        { operation: "not", child: { operation: "eq", path: "/status", value: "void" } }
      ]
    },
    [schema]
  );

  const missingEvent = parseEventJsonString('{"amount":10}').value;
  const nullEvent = parseEventJsonString('{"amount":10,"status":null}').value;
  const activeEvent = parseEventJsonString('{"amount":10,"status":"active"}').value;

  assert.equal(evaluateFilter(existsFilter, missingEvent), false);
  assert.equal(evaluateFilter(existsFilter, nullEvent), true);
  assert.equal(evaluateFilter(eqNullFilter, missingEvent), false);
  assert.equal(evaluateFilter(eqNullFilter, nullEvent), true);
  assert.equal(evaluateFilter(eqNullFilter, activeEvent), false);
  assert.equal(evaluateFilter(notEqFilter, missingEvent), true);
  assert.equal(evaluateFilter(presentNotEqFilter, missingEvent), false);
  assert.equal(evaluateFilter(presentNotEqFilter, activeEvent), true);

  // Lossless numeric comparison in filter
  const bigFilter = compileFilterAst(
    '{"operation":"lt","path":"/amount","value":9007199254740993}',
    [schema]
  );
  assert.equal(
    evaluateFilter(bigFilter, parseEventJsonString('{"amount":9007199254740992}').value),
    true
  );
  assert.equal(
    evaluateFilter(bigFilter, parseEventJsonString('{"amount":9007199254740993}').value),
    false
  );

  // Evaluation error in not(...) never flips into true
  const notLtFilter = compileFilterAst(
    { operation: "not", child: { operation: "lt", path: "/amount", value: 10 } },
    [schema]
  );
  assert.throws(
    () => evaluateFilter(notLtFilter, parseEventJsonString('{"amount":1e1025}').value),
    LimitExceededDomainError
  );

  // Grammar rejections
  assert.throws(() => compileFilterAst({ operation: "all", children: [] }, [schema]), ValidationDomainError);
  assert.throws(
    () => compileFilterAst({ operation: "in", path: "/status", values: ["a", 1] }, [schema]),
    ValidationDomainError
  );
  assert.throws(
    () => compileFilterAst({ operation: "lt", path: "/meta/tier", value: 5 }, [schema]),
    ValidationDomainError
  );
  assert.throws(
    () => compileFilterAst({ operation: "eq", path: "/tags/0", value: "x" }, [schema]),
    ValidationDomainError
  );

  // Boolean depth 4 allowed, depth 5 rejected
  const wrapNot = (depth) => {
    let node = { operation: "exists", path: "/status" };
    for (let i = 0; i < depth; i += 1) {
      node = { operation: "not", child: node };
    }
    return node;
  };
  assert.equal(compileFilterAst(wrapNot(4), [schema]).maxBooleanDepth, 4);
  assert.throws(() => compileFilterAst(wrapNot(5), [schema]), LimitExceededDomainError);
});

test("ordering extractor validates schema guarantees and exact UTF-8 byte limits without normalization", () => {
  const validSchema = compileEventSchema(
    encodeJson({
      type: "object",
      properties: {
        customer: {
          type: "object",
          properties: {
            key: { type: "string", minLength: 1, maxLength: 64 }
          },
          required: ["key"],
          additionalProperties: false
        },
        optional_key: { type: "string", minLength: 1, maxLength: 32 },
        nullable_key: { type: ["string", "null"], minLength: 1, maxLength: 32 },
        too_wide: { type: "string", minLength: 1, maxLength: 256 }
      },
      required: ["customer"],
      additionalProperties: false
    })
  );

  const extractor = compileOrderingExtractor("/customer/key", [validSchema]);
  assert.equal(extractor.normalizedExtractor.pointer, "/customer/key");

  // Reject optional, nullable, empty-allowing, or >128 maxLength schemas
  assert.throws(() => compileOrderingExtractor("/optional_key", [validSchema]), ValidationDomainError);
  assert.throws(() => compileOrderingExtractor("/nullable_key", [validSchema]), ValidationDomainError);
  assert.throws(() => compileOrderingExtractor("/too_wide", [validSchema]), ValidationDomainError);

  // Exact UTF-8 bytes without case folding or Unicode NFC normalization
  const decomposed = "e\u0301"; // NFD (3 UTF-8 bytes, distinct from NFC \u00e9)
  const scope = {
    orderingDomainId: "00000000-0000-4000-8000-000000000901",
    subscriptionId: "00000000-0000-4000-8000-000000000902",
    consumerContractScope: "demo.order.v1"
  };
  const extracted = extractOrderingKey(
    parseEventJsonString(JSON.stringify({ customer: { key: decomposed } })).value,
    extractor,
    scope
  );
  assert.equal(extracted.orderingKey, decomposed);
  assert.equal(extracted.byteCount, 3);
  assert.equal(
    extracted.orderingKeySha256,
    computeOrderingKeySha256({
      ordering_domain_id: scope.orderingDomainId,
      subscription_id: scope.subscriptionId,
      consumer_contract_scope: scope.consumerContractScope,
      ordering_key: decomposed
    })
  );

  // 40 emojis = 40 scalars (<= maxLength 64) but 160 UTF-8 bytes (> 128) -> explicit contract error!
  const emojiOverBytes = "🚀".repeat(40);
  assert.throws(
    () =>
      extractOrderingKey(
        parseEventJsonString(JSON.stringify({ customer: { key: emojiOverBytes } })).value,
        extractor
      ),
    InvariantViolationError
  );

  // Missing field in corrupted retained event -> explicit contract error, never fallback key!
  assert.throws(
    () => extractOrderingKey(parseEventJsonString("{}").value, extractor),
    InvariantViolationError
  );
});
