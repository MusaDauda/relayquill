import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import {
  ConflictDomainError,
  DependencyUnavailableDomainError,
  ValidationDomainError
} from "@relayquill/domain";
import {
  type PgAdapter,
  type PgTransactionClient,
  type SchemaMigrationRecord,
  readInstallationStatus,
  readSchemaMigrations
} from "@relayquill/postgres";

export const ADMIN_MIGRATION_RUNNER_VERSION = "0.1.0" as const;

export interface LocalMigrationFile {
  readonly migrationId: string;
  readonly filePath: string;
  readonly sql: string;
  readonly checksumHex: string;
  readonly checksumBuffer: Buffer;
}

export interface MigrationChecksumMismatch {
  readonly migrationId: string;
  readonly expectedSha256: string;
  readonly actualSha256: string;
}

export interface DbStatusReport {
  readonly ok: boolean;
  readonly initialized: boolean;
  readonly migrationsDir: string;
  readonly applied: readonly string[];
  readonly pending: readonly string[];
  readonly checksumMismatches: readonly MigrationChecksumMismatch[];
  readonly unknownApplied: readonly string[];
  readonly installationMode?: string | undefined;
  readonly controlEpoch?: string | undefined;
}

export interface DbMigrateResult {
  readonly ok: boolean;
  readonly appliedNow: readonly string[];
  readonly totalApplied: number;
  readonly alreadyApplied: readonly string[];
}

export interface DbVerifyReport {
  readonly ok: boolean;
  readonly initialized: boolean;
  readonly btreeGistInstalled: boolean;
  readonly rqTableCount: number;
  readonly recoveryTableCount: number;
  readonly pending: readonly string[];
  readonly checksumMismatches: readonly MigrationChecksumMismatch[];
  readonly installationMode: string;
  readonly controlEpoch: string;
  readonly failures: readonly string[];
}

function sha256Buffer(text: string): Buffer {
  return crypto.createHash("sha256").update(text, "utf8").digest();
}

export function listLocalMigrations(migrationsDir: string): readonly LocalMigrationFile[] {
  const resolved = path.resolve(migrationsDir);
  if (!fs.existsSync(resolved)) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Migrations directory not found: ${migrationsDir}`
    });
  }
  const entries = fs
    .readdirSync(resolved)
    .filter((file) => /^\d+.*\.sql$/i.test(file))
    .sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));

  return entries.map((file) => {
    const filePath = path.join(resolved, file);
    const sql = fs.readFileSync(filePath, "utf8");
    const checksumBuffer = sha256Buffer(sql);
    return {
      migrationId: file.replace(/\.sql$/i, ""),
      filePath,
      sql,
      checksumHex: checksumBuffer.toString("hex"),
      checksumBuffer
    };
  });
}

async function tryReadSchemaMigrations(
  pgAdapter: PgAdapter
): Promise<{ readonly initialized: boolean; readonly records: readonly SchemaMigrationRecord[] }> {
  return pgAdapter.withTransaction(
    pgAdapter.configuredRole,
    async (tx: PgTransactionClient) => {
      const tableCheck = await tx.query<{ exists: boolean }>(
        `SELECT EXISTS (
           SELECT 1
             FROM pg_catalog.pg_class c
             JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
            WHERE n.nspname = $1 AND c.relname = 'schema_migrations'
         ) AS exists`,
        [pgAdapter.schema]
      );
      if (tableCheck.rows[0]?.exists !== true) {
        return { initialized: false, records: [] };
      }

      const fnCheck = await tx.query<{ exists: boolean }>(
        `SELECT EXISTS (
           SELECT 1
             FROM pg_catalog.pg_proc p
             JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
            WHERE n.nspname = $1 AND p.proname = 'read_schema_migrations'
         ) AS exists`,
        [pgAdapter.schema]
      );

      if (fnCheck.rows[0]?.exists === true) {
        const records = await readSchemaMigrations(tx);
        return { initialized: true, records };
      }

      const direct = await tx.query<Record<string, unknown>>(
        `SELECT migration_id, checksum, applied_at, source_reference, runner_version
           FROM rq.schema_migrations
          ORDER BY migration_id ASC`
      );
      const records: SchemaMigrationRecord[] = direct.rows.map((row) => ({
        migrationId: String(row["migration_id"]),
        checksum: Buffer.isBuffer(row["checksum"])
          ? row["checksum"]
          : Buffer.from(row["checksum"] as Uint8Array),
        appliedAt: String(row["applied_at"]) as SchemaMigrationRecord["appliedAt"],
        sourceReference: String(row["source_reference"]),
        runnerVersion: String(row["runner_version"])
      }));
      return { initialized: true, records };
    },
    { readOnly: true, retryOnContention: true }
  );
}

function compareMigrations(
  local: readonly LocalMigrationFile[],
  appliedRecords: readonly SchemaMigrationRecord[]
): {
  readonly applied: readonly string[];
  readonly pending: readonly string[];
  readonly checksumMismatches: readonly MigrationChecksumMismatch[];
  readonly unknownApplied: readonly string[];
} {
  const localById = new Map<string, LocalMigrationFile>();
  for (const item of local) {
    localById.set(item.migrationId, item);
  }

  const appliedById = new Map<string, SchemaMigrationRecord>();
  for (const rec of appliedRecords) {
    appliedById.set(rec.migrationId, rec);
  }

  const applied: string[] = [];
  const pending: string[] = [];
  const checksumMismatches: MigrationChecksumMismatch[] = [];
  const unknownApplied: string[] = [];

  for (const file of local) {
    const rec = appliedById.get(file.migrationId);
    if (rec === undefined) {
      pending.push(file.migrationId);
      continue;
    }
    const actualHex = Buffer.from(rec.checksum).toString("hex");
    if (actualHex !== file.checksumHex) {
      checksumMismatches.push({
        migrationId: file.migrationId,
        expectedSha256: file.checksumHex,
        actualSha256: actualHex
      });
    } else {
      applied.push(file.migrationId);
    }
  }

  for (const rec of appliedRecords) {
    if (!localById.has(rec.migrationId)) {
      unknownApplied.push(rec.migrationId);
    }
  }

  return { applied, pending, checksumMismatches, unknownApplied };
}

export async function runDbStatus(
  pgAdapter: PgAdapter,
  migrationsDir: string
): Promise<DbStatusReport> {
  const local = listLocalMigrations(migrationsDir);
  const { initialized, records } = await tryReadSchemaMigrations(pgAdapter);
  const diff = compareMigrations(local, records);

  let installationMode: string | undefined;
  let controlEpoch: string | undefined;
  if (initialized) {
    try {
      const status = await pgAdapter.withTransaction(
        pgAdapter.configuredRole,
        async (tx) => readInstallationStatus(tx),
        { readOnly: true }
      );
      installationMode = status.mode;
      controlEpoch = status.controlEpoch;
    } catch {
      // Installation read function may not exist yet if DB is partially migrated.
    }
  }

  return {
    ok: initialized && diff.pending.length === 0 && diff.checksumMismatches.length === 0 && diff.unknownApplied.length === 0,
    initialized,
    migrationsDir,
    applied: diff.applied,
    pending: diff.pending,
    checksumMismatches: diff.checksumMismatches,
    unknownApplied: diff.unknownApplied,
    ...(installationMode !== undefined ? { installationMode } : {}),
    ...(controlEpoch !== undefined ? { controlEpoch } : {})
  };
}

export async function runDbMigrate(
  pgAdapter: PgAdapter,
  migrationsDir: string,
  options: { readonly runnerVersion?: string | undefined } = {}
): Promise<DbMigrateResult> {
  const local = listLocalMigrations(migrationsDir);
  const runnerVersion = options.runnerVersion ?? ADMIN_MIGRATION_RUNNER_VERSION;
  const { records } = await tryReadSchemaMigrations(pgAdapter);
  const diff = compareMigrations(local, records);

  if (diff.checksumMismatches.length > 0) {
    const first = diff.checksumMismatches[0];
    throw new ConflictDomainError({
      code: "VERSION_CONFLICT",
      message: `Migration checksum mismatch for ${first?.migrationId ?? "unknown"}: expected ${first?.expectedSha256 ?? ""}, got ${first?.actualSha256 ?? ""}`
    });
  }

  const appliedSet = new Set(diff.applied);
  const appliedNow: string[] = [];

  for (const file of local) {
    if (appliedSet.has(file.migrationId)) {
      continue;
    }

    await pgAdapter.exec(file.sql);

    await pgAdapter.withTransaction(
      pgAdapter.configuredRole,
      async (tx) => {
        if (pgAdapter.backend === "pg") {
          await tx.query("SELECT pg_catalog.pg_advisory_xact_lock($1::bigint)", [7270001]);
        }
        await tx.query(
          `INSERT INTO rq.schema_migrations (
             migration_id, checksum, source_reference, runner_version
           ) VALUES ($1::text, $2::bytea, $3::text, $4::text)
           ON CONFLICT (migration_id) DO NOTHING`,
          [
            file.migrationId,
            file.checksumBuffer,
            path.basename(file.filePath),
            runnerVersion
          ]
        );
      },
      { statementTimeoutMs: 30_000, lockTimeoutMs: 5_000 }
    );
    appliedNow.push(file.migrationId);
  }

  return {
    ok: true,
    appliedNow,
    alreadyApplied: diff.applied,
    totalApplied: diff.applied.length + appliedNow.length
  };
}

export async function runDbVerify(
  pgAdapter: PgAdapter,
  migrationsDir: string
): Promise<DbVerifyReport> {
  const local = listLocalMigrations(migrationsDir);
  const { initialized, records } = await tryReadSchemaMigrations(pgAdapter);
  const diff = compareMigrations(local, records);
  const failures: string[] = [];

  if (!initialized) {
    failures.push("rq.schema_migrations does not exist");
  }
  if (diff.pending.length > 0) {
    failures.push(`Pending migrations remain: ${diff.pending.join(", ")}`);
  }
  for (const mismatch of diff.checksumMismatches) {
    failures.push(`Checksum mismatch on migration ${mismatch.migrationId}`);
  }
  if (diff.unknownApplied.length > 0) {
    failures.push(`Unknown migrations in database: ${diff.unknownApplied.join(", ")}`);
  }

  const inspection = await pgAdapter.withTransaction(
    pgAdapter.configuredRole,
    async (tx) => {
      const extRes = await tx.query<{ present: boolean }>(
        "SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_extension WHERE extname = 'btree_gist') AS present"
      );
      const rqCountRes = await tx.query<{ cnt: number }>(
        "SELECT count(*)::integer AS cnt FROM information_schema.tables WHERE table_schema = 'rq'"
      );
      const recCountRes = await tx.query<{ cnt: number }>(
        "SELECT count(*)::integer AS cnt FROM information_schema.tables WHERE table_schema = 'rq_recovery'"
      );

      let mode = "unknown";
      let controlEpoch = "unknown";
      if (initialized) {
        try {
          const status = await readInstallationStatus(tx);
          mode = status.mode;
          controlEpoch = status.controlEpoch;
        } catch (err) {
          failures.push(
            `Failed to read rq.read_installation_status(): ${err instanceof Error ? err.message : String(err)}`
          );
        }
      }

      return {
        btreeGistInstalled: extRes.rows[0]?.present === true,
        rqTableCount: rqCountRes.rows[0]?.cnt ?? 0,
        recoveryTableCount: recCountRes.rows[0]?.cnt ?? 0,
        installationMode: mode,
        controlEpoch
      };
    },
    { readOnly: true }
  );

  if (!inspection.btreeGistInstalled) {
    failures.push("Required PostgreSQL extension btree_gist is not installed");
  }
  if (inspection.rqTableCount < 45) {
    failures.push(`Expected rq schema tables >= 45, found ${inspection.rqTableCount}`);
  }
  if (inspection.recoveryTableCount < 10) {
    failures.push(`Expected rq_recovery schema tables >= 10, found ${inspection.recoveryTableCount}`);
  }

  const report: DbVerifyReport = {
    ok: failures.length === 0,
    initialized,
    btreeGistInstalled: inspection.btreeGistInstalled,
    rqTableCount: inspection.rqTableCount,
    recoveryTableCount: inspection.recoveryTableCount,
    pending: diff.pending,
    checksumMismatches: diff.checksumMismatches,
    installationMode: inspection.installationMode,
    controlEpoch: inspection.controlEpoch,
    failures
  };

  if (!report.ok) {
    throw new DependencyUnavailableDomainError({
      code: "DEPENDENCY_UNAVAILABLE",
      message: `Database verification failed: ${failures.join("; ")}`,
      retryable: false,
      acceptance: "known_rejected"
    });
  }

  return report;
}
