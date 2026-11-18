import test from "node:test";
import assert from "node:assert/strict";
import { RUNTIME_PACKAGE_VERSION, getRuntimeIdentity } from "@relayquill/runtime";

test("runtime package exports identity linked to contracts and domain", () => {
  assert.equal(RUNTIME_PACKAGE_VERSION, "0.1.0");
  assert.deepEqual(getRuntimeIdentity(), {
    contractsVersion: "0.1.0",
    domainVersion: "0.1.0",
    runtimeVersion: "0.1.0",
    platform: process.platform
  });
});
