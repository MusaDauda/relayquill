import { ValidationDomainError } from "@relayquill/domain";
import {
  type DatabaseRole,
  type PgAdapter,
  type PgTransactionClient,
  type TransactionOptions
} from "./types.js";

export const TENANT_RLS_SETTING_NAME = "app.current_tenant_id" as const;

const STRICT_UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * Validates that a tenant identifier is a canonical UUID string before passing it to PostgreSQL RLS.
 */
export function isValidTenantUuid(value: string): boolean {
  return STRICT_UUID_REGEX.test(value);
}

/**
 * Binds `app.current_tenant_id` transaction-locally inside an open PostgreSQL transaction.
 */
export async function bindTenantRlsScope(
  tx: PgTransactionClient,
  tenantId: string
): Promise<void> {
  if (!isValidTenantUuid(tenantId)) {
    throw new ValidationDomainError({
      code: "INVALID_UUID",
      message: "Invalid tenant UUID for transaction-local RLS binding"
    });
  }
  await tx.query("SELECT pg_catalog.set_config($1::text, $2::text, true)", [
    TENANT_RLS_SETTING_NAME,
    tenantId
  ]);
}

/**
 * Executes a bounded transaction with `app.current_tenant_id` scoped strictly to that transaction.
 */
export async function withTenantRlsTransaction<T>(
  adapter: PgAdapter,
  role: DatabaseRole,
  tenantId: string,
  fn: (tx: PgTransactionClient) => Promise<T>,
  options?: TransactionOptions
): Promise<T> {
  if (!isValidTenantUuid(tenantId)) {
    throw new ValidationDomainError({
      code: "INVALID_UUID",
      message: "Invalid tenant UUID for transaction-local RLS binding"
    });
  }
  return adapter.withTransaction(
    role,
    async (tx) => {
      await bindTenantRlsScope(tx, tenantId);
      return fn(tx);
    },
    options
  );
}
