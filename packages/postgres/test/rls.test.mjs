import test from "node:test";
import assert from "node:assert/strict";
import { ValidationDomainError } from "@relayquill/domain";
import {
  TENANT_RLS_SETTING_NAME,
  bindTenantRlsScope,
  createPGliteAdapter,
  isValidTenantUuid,
  withTenantRlsTransaction
} from "@relayquill/postgres";

const TENANT_A = "11111111-1111-4111-8111-111111111111";
const TENANT_B = "22222222-2222-4222-8222-222222222222";

test("isValidTenantUuid and bindTenantRlsScope validate UUIDs strictly", async (t) => {
  assert.equal(TENANT_RLS_SETTING_NAME, "app.current_tenant_id");
  assert.equal(isValidTenantUuid(TENANT_A), true);
  assert.equal(isValidTenantUuid("not-a-uuid"), false);
  assert.equal(isValidTenantUuid(""), false);

  const db = await createPGliteAdapter({ createSchemaIfMissing: true });
  t.after(() => db.close());

  await assert.rejects(
    () =>
      withTenantRlsTransaction(db, "rq_api", "bad-tenant-id", async () => "unreachable"),
    (err) => err instanceof ValidationDomainError && err.code === "INVALID_UUID"
  );

  await db.withTransaction("rq_api", async (tx) => {
    await assert.rejects(
      () => bindTenantRlsScope(tx, "1234"),
      (err) => err instanceof ValidationDomainError && err.code === "INVALID_UUID"
    );
  });
});

test("withTenantRlsTransaction sets app.current_tenant_id locally and resets across transactions", async (t) => {
  const db = await createPGliteAdapter({ createSchemaIfMissing: true });
  t.after(() => db.close());

  const seenA = await withTenantRlsTransaction(db, "rq_billing", TENANT_A, async (tx) => {
    const res = await tx.query(
      "SELECT pg_catalog.current_setting('app.current_tenant_id', true) AS tenant_id"
    );
    return res.rows[0]?.tenant_id;
  });
  assert.equal(seenA, TENANT_A);

  const outside = await db.withTransaction("rq_billing", async (tx) => {
    const res = await tx.query(
      "SELECT NULLIF(pg_catalog.current_setting('app.current_tenant_id', true), '') AS tenant_id"
    );
    return res.rows[0]?.tenant_id ?? null;
  });
  assert.equal(outside, null);

  const seenB = await withTenantRlsTransaction(db, "rq_audit_ro", TENANT_B, async (tx) => {
    const res = await tx.query(
      "SELECT pg_catalog.current_setting('app.current_tenant_id', true) AS tenant_id"
    );
    return res.rows[0]?.tenant_id;
  });
  assert.equal(seenB, TENANT_B);
});
