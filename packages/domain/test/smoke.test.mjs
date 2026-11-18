import test from "node:test";
import assert from "node:assert/strict";
import { DOMAIN_PACKAGE_VERSION, nowUtcInstant } from "@relayquill/domain";

test("domain package exports version and UTC instant helper", () => {
  assert.equal(DOMAIN_PACKAGE_VERSION, "0.1.0");
  assert.equal(typeof nowUtcInstant().epochNanoseconds, "bigint");
});
