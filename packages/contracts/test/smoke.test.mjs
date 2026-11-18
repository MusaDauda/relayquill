import test from "node:test";
import assert from "node:assert/strict";
import { CONTRACTS_PACKAGE_VERSION, getContractHandshake } from "@relayquill/contracts";

test("contracts package exports handshake linked to domain", () => {
  assert.equal(CONTRACTS_PACKAGE_VERSION, "0.1.0");
  assert.deepEqual(getContractHandshake(), {
    contractsVersion: "0.1.0",
    domainVersion: "0.1.0"
  });
});
