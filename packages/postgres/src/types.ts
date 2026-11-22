import { type CanonicalUtcTimestamp, type DomainError } from "@relayquill/domain";
import { type DatabaseMode, type SecretHandle } from "@relayquill/runtime";

export const DATABASE_AUTHORITY_SCHEMAS = ["rq", "rc", "pi"] as const;
export type DatabaseAuthoritySchema = (typeof DATABASE_AUTHORITY_SCHEMAS)[number];

export const DATABASE_ISOLATIONS = ["separate_databases", "shared_database_schemas"] as const;
export type PgIsolationMode = (typeof DATABASE_ISOLATIONS)[number];

export const DATABASE_SUPPORT_SCHEMAS = ["rq_support", "extensions"] as const;
export type PgSupportSchema = (typeof DATABASE_SUPPORT_SCHEMAS)[number];

export const RQ_DATABASE_ROLES = [
  "rq_api",
  "rq_relay",
  "rq_fanout",
  "rq_sender",
  "rq_coordinator",
  "rq_reporter",
  "rq_signing_issuer",
  "rq_migrator",
  "rq_recovery",
  "rq_billing",
  "rq_audit_ro",
  "rq_worker"
] as const;
export type RqDatabaseRole = (typeof RQ_DATABASE_ROLES)[number];

export type DatabaseRole =
  | RqDatabaseRole
  | "receiver_migrator"
  | "receiver_runtime"
  | "provider_migrator"
  | "provider_runtime"
  | (string & {});

export interface PgFieldInfo {
  readonly name: string;
  readonly dataTypeID: number;
}

export interface PgQueryResult<
  TRow extends Record<string, unknown> = Record<string, unknown>
> {
  readonly rows: readonly TRow[];
  readonly rowCount: number;
  readonly command: string;
  readonly fields: readonly PgFieldInfo[];
}

export interface PgQueryOptions {
  readonly role?: DatabaseRole | undefined;
  readonly schema?: DatabaseAuthoritySchema | undefined;
  readonly statementTimeoutMs?: number | undefined;
  readonly signal?: AbortSignal | undefined;
}

export interface ContentionRetryEvent {
  readonly attempt: number;
  readonly maxAttempts: number;
  readonly sqlState: string;
  readonly delayMs: number;
  readonly remainingBudgetMs: number;
}

export interface ContentionRetryPolicy {
  readonly retryOnContention?: boolean | undefined;
  readonly maxAttempts?: number | undefined;
  readonly baseBackoffMs?: number | undefined;
  readonly maxBackoffMs?: number | undefined;
  readonly random?: (() => number) | undefined;
  readonly onRetry?: ((event: ContentionRetryEvent) => void) | undefined;
}

export interface TransactionOptions extends ContentionRetryPolicy {
  readonly deadlineMs?: number | undefined;
  readonly lockTimeoutMs?: number | undefined;
  readonly statementTimeoutMs?: number | undefined;
  readonly signal?: AbortSignal | undefined;
  readonly nowMs?: (() => number) | undefined;
  readonly readOnly?: boolean | undefined;
  readonly deferrable?: boolean | undefined;
}

export interface PgSessionIdentity {
  readonly database: string;
  readonly currentUser: string;
  readonly sessionUser: string;
  readonly searchPath: string;
}

export interface PgTransactionClient {
  readonly role: string;
  readonly schema: DatabaseAuthoritySchema;
  readonly supportSchema: PgSupportSchema;
  readonly isolation: PgIsolationMode;
  readonly attemptNumber: number;
  readonly deadlineMs: number;
  readonly signal?: AbortSignal | undefined;
  remainingBudgetMs(): number;
  readClockTimestamp(): Promise<CanonicalUtcTimestamp>;
  query<TRow extends Record<string, unknown> = Record<string, unknown>>(
    sql: string,
    params?: readonly unknown[]
  ): Promise<PgQueryResult<TRow>>;
  exec(sql: string): Promise<void>;
}

export interface PgAdapter {
  readonly backend: "pg" | "pglite";
  readonly mode: DatabaseMode;
  readonly isolation: PgIsolationMode;
  readonly schema: DatabaseAuthoritySchema;
  readonly supportSchema: PgSupportSchema;
  readonly configuredRole: string;
  verifySessionIdentity(expectedUser?: string): Promise<PgSessionIdentity>;
  query<TRow extends Record<string, unknown> = Record<string, unknown>>(
    sql: string,
    params?: readonly unknown[],
    options?: PgQueryOptions
  ): Promise<PgQueryResult<TRow>>;
  exec(sql: string, options?: PgQueryOptions): Promise<void>;
  withTransaction<T>(
    role: DatabaseRole,
    fn: (tx: PgTransactionClient) => Promise<T>,
    options?: TransactionOptions
  ): Promise<T>;
  close(): Promise<void>;
}

export interface IamTokenRequest {
  readonly host: string;
  readonly port: number;
  readonly user: string;
  readonly database: string;
}

export type IamAuthTokenProvider = (
  request: IamTokenRequest
) => Promise<string | SecretHandle>;

export type PasswordSecretResolver = () => Promise<string | SecretHandle>;

export interface StandardPgAdapterOptions {
  readonly iamTokenProvider?: IamAuthTokenProvider | undefined;
  readonly passwordProvider?: PasswordSecretResolver | undefined;
  readonly tlsCaPem?: string | undefined;
  readonly allowInsecureLocalhost?: boolean | undefined;
  readonly applicationName?: string | undefined;
  readonly verifyOnConnect?: boolean | undefined;
  readonly maxConnections?: number | undefined;
  readonly connectionTimeoutMs?: number | undefined;
  readonly idleTimeoutMs?: number | undefined;
  readonly nowMs?: (() => number) | undefined;
  readonly onPoolError?: ((error: DomainError) => void) | undefined;
}

export interface PGliteAdapterOptions {
  readonly dataDir?: string | undefined;
  readonly schema?: DatabaseAuthoritySchema | undefined;
  readonly supportSchema?: PgSupportSchema | undefined;
  readonly isolation?: PgIsolationMode | undefined;
  readonly configuredRole?: DatabaseRole | undefined;
  readonly databaseName?: string | undefined;
  readonly applySetLocalRole?: boolean | undefined;
  readonly createSchemaIfMissing?: boolean | undefined;
  readonly nowMs?: (() => number) | undefined;
}
