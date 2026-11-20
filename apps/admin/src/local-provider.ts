import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import {
  LimitExceededDomainError,
  NotFoundDomainError,
  ValidationDomainError
} from "@relayquill/domain";
import {
  DEFAULT_LOCAL_PROVIDER_MAX_ENTRIES,
  DEFAULT_LOCAL_PROVIDER_MAX_ENTRY_BYTES,
  type IpcChannelRef,
  type IpcSecurityReport,
  type IpcServerHandle,
  type LocalProviderRequest,
  type LocalProviderResponse,
  type ProviderSettings,
  createIpcServer,
  getIpcEndpoint,
  resolveIpcChannelEndpoint
} from "@relayquill/runtime";

interface StoredEntry {
  readonly ref: string;
  readonly value: Buffer;
  readonly version: string;
  readonly expiresAt?: string | undefined;
  readonly metadata?: Readonly<Record<string, string>> | undefined;
}

export interface ProviderSeedEntry {
  readonly ref: string;
  readonly value: Uint8Array | string;
  readonly version?: string | undefined;
  readonly expiresAt?: string | undefined;
  readonly metadata?: Readonly<Record<string, string>> | undefined;
}

export interface StartAdminIpcServerOptions {
  readonly endpoint?: string | undefined;
  readonly ipc?: IpcChannelRef | undefined;
  readonly env?: Readonly<Record<string, string | undefined>> | undefined;
  readonly runtimeDir?: string | undefined;
  readonly providerSettings?: Partial<ProviderSettings> | undefined;
  readonly maxEntries?: number | undefined;
  readonly maxEntryBytes?: number | undefined;
  readonly custodySnapshotEnabled?: boolean | undefined;
  readonly custodySnapshotPath?: string | undefined;
  readonly snapshotKey?: Buffer | undefined;
  readonly allowBuiltInAdmins?: boolean | undefined;
  readonly seedDefaults?: boolean | undefined;
  readonly initialEntries?: readonly ProviderSeedEntry[] | undefined;
}

export interface AdminIpcStatusSnapshot {
  readonly endpoint: string;
  readonly count: number;
  readonly maxEntries: number;
  readonly maxEntryBytes: number;
  readonly refs: readonly string[];
  readonly generation: number;
  readonly custodySnapshotEnabled: boolean;
}

export interface AdminIpcServerHandle {
  readonly endpoint: string;
  verifySecurity(): Promise<IpcSecurityReport>;
  status(): AdminIpcStatusSnapshot;
  reload(): Promise<{ readonly count: number; readonly generation: number }>;
  reseed(entries?: readonly ProviderSeedEntry[]): Promise<{ readonly seeded: number; readonly generation: number }>;
  putSecret(entry: ProviderSeedEntry): void;
  close(): Promise<void>;
}

const VALID_REF_REGEX = /^[a-z0-9][a-z0-9._:/-]{0,254}$/i;

function assertValidRef(ref: string): string {
  if (typeof ref !== "string" || ref.trim().length === 0 || !VALID_REF_REGEX.test(ref.trim())) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: "Invalid secret reference format"
    });
  }
  return ref.trim();
}

function deriveSnapshotKey(
  explicitKey: Buffer | undefined,
  env: Readonly<Record<string, string | undefined>>
): Buffer {
  if (explicitKey !== undefined) {
    if (explicitKey.byteLength !== 32) {
      throw new ValidationDomainError({
        code: "INVALID_VALUE",
        message: "Custody snapshot key must be exactly 32 bytes"
      });
    }
    return Buffer.from(explicitKey);
  }
  const envKey = env["RELAYQUILL_CUSTODY_SNAPSHOT_KEY"];
  if (typeof envKey === "string" && envKey.trim().length > 0) {
    return crypto.createHash("sha256").update(envKey.trim(), "utf8").digest();
  }
  return crypto.randomBytes(32);
}

function buildDevFixtureSeeds(generation: number): readonly ProviderSeedEntry[] {
  const mkKey = (): Buffer => crypto.randomBytes(32);
  return [
    {
      ref: "custody:provider-ingress/producer-credential",
      value: `rq_p1.${crypto.randomUUID()}.${crypto.randomBytes(32).toString("base64url")}`,
      version: `gen-${generation}`
    },
    {
      ref: "custody:dev-endpoint/primary-signing-key",
      value: mkKey().toString("base64url"),
      version: `gen-${generation}`
    }
  ];
}

export async function startAdminIpcServer(
  options: StartAdminIpcServerOptions = {}
): Promise<AdminIpcServerHandle> {
  const env = options.env ?? process.env;
  const ipcRef = options.ipc ?? { env_name: "dev", channel: "provider" };
  const endpoint =
    options.endpoint ??
    (options.runtimeDir !== undefined
      ? getIpcEndpoint(ipcRef.env_name, ipcRef.channel, { runtimeDir: options.runtimeDir })
      : resolveIpcChannelEndpoint(ipcRef, env));

  const maxEntries =
    options.maxEntries ??
    options.providerSettings?.max_entries ??
    DEFAULT_LOCAL_PROVIDER_MAX_ENTRIES;
  const maxEntryBytes =
    options.maxEntryBytes ??
    options.providerSettings?.max_entry_bytes ??
    DEFAULT_LOCAL_PROVIDER_MAX_ENTRY_BYTES;
  const snapshotEnabled =
    options.custodySnapshotEnabled ?? options.providerSettings?.custody_snapshot_enabled ?? false;
  const snapshotPath = options.custodySnapshotPath ?? options.providerSettings?.custody_snapshot_path;

  const snapshotKey = deriveSnapshotKey(options.snapshotKey, env);
  const store = new Map<string, StoredEntry>();
  let generation = 1;

  const serializeStoreToEncryptedSnapshot = (): void => {
    if (!snapshotEnabled || snapshotPath === undefined || snapshotPath.trim().length === 0) {
      return;
    }
    const resolved = path.resolve(snapshotPath);
    fs.mkdirSync(path.dirname(resolved), { recursive: true, mode: 0o700 });
    const records = Array.from(store.values()).map((entry) => ({
      ref: entry.ref,
      valueBase64: entry.value.toString("base64"),
      version: entry.version,
      ...(entry.expiresAt !== undefined ? { expiresAt: entry.expiresAt } : {}),
      ...(entry.metadata !== undefined ? { metadata: entry.metadata } : {})
    }));
    const plaintext = Buffer.from(JSON.stringify({ v: 1, generation, records }), "utf8");
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv("aes-256-gcm", snapshotKey, iv);
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const tag = cipher.getAuthTag();
    const envelope = JSON.stringify({
      v: 1,
      alg: "aes-256-gcm",
      iv: iv.toString("base64"),
      tag: tag.toString("base64"),
      ciphertext: ciphertext.toString("base64")
    });
    fs.writeFileSync(resolved, `${envelope}\n`, { encoding: "utf8", mode: 0o600 });
  };

  const loadStoreFromEncryptedSnapshot = (): boolean => {
    if (!snapshotEnabled || snapshotPath === undefined || snapshotPath.trim().length === 0) {
      return false;
    }
    const resolved = path.resolve(snapshotPath);
    if (!fs.existsSync(resolved)) {
      return false;
    }
    try {
      const parsed = JSON.parse(fs.readFileSync(resolved, "utf8")) as {
        v?: number;
        alg?: string;
        iv?: string;
        tag?: string;
        ciphertext?: string;
      };
      if (
        parsed.v !== 1 ||
        parsed.alg !== "aes-256-gcm" ||
        typeof parsed.iv !== "string" ||
        typeof parsed.tag !== "string" ||
        typeof parsed.ciphertext !== "string"
      ) {
        return false;
      }
      const iv = Buffer.from(parsed.iv, "base64");
      const tag = Buffer.from(parsed.tag, "base64");
      const ciphertext = Buffer.from(parsed.ciphertext, "base64");
      const decipher = crypto.createDecipheriv("aes-256-gcm", snapshotKey, iv);
      decipher.setAuthTag(tag);
      const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString("utf8");
      const payload = JSON.parse(plaintext) as {
        v?: number;
        generation?: number;
        records?: Array<{
          ref: string;
          valueBase64: string;
          version: string;
          expiresAt?: string;
          metadata?: Record<string, string>;
        }>;
      };
      if (payload.v !== 1 || !Array.isArray(payload.records)) {
        return false;
      }
      store.clear();
      if (typeof payload.generation === "number" && Number.isSafeInteger(payload.generation)) {
        generation = payload.generation;
      }
      for (const item of payload.records) {
        const valueBuf = Buffer.from(item.valueBase64, "base64");
        if (valueBuf.byteLength > maxEntryBytes || store.size >= maxEntries) {
          continue;
        }
        store.set(item.ref, {
          ref: assertValidRef(item.ref),
          value: valueBuf,
          version: item.version,
          ...(item.expiresAt !== undefined ? { expiresAt: item.expiresAt } : {}),
          ...(item.metadata !== undefined ? { metadata: item.metadata } : {})
        });
      }
      return true;
    } catch {
      return false;
    }
  };

  const putInternal = (entry: ProviderSeedEntry): StoredEntry => {
    const safeRef = assertValidRef(entry.ref);
    const bytes =
      typeof entry.value === "string"
        ? Buffer.from(entry.value, "utf8")
        : Buffer.from(entry.value);
    if (bytes.byteLength === 0 || bytes.byteLength > maxEntryBytes) {
      throw new LimitExceededDomainError({
        code: "CAPACITY_EXCEEDED",
        message: `Secret entry exceeds bounds (1..${maxEntryBytes} bytes)`
      });
    }
    if (!store.has(safeRef) && store.size >= maxEntries) {
      throw new LimitExceededDomainError({
        code: "CAPACITY_EXCEEDED",
        message: `Local provider store reached maximum entries (${maxEntries})`
      });
    }
    const stored: StoredEntry = {
      ref: safeRef,
      value: bytes,
      version: entry.version ?? `v${generation}`,
      ...(entry.expiresAt !== undefined ? { expiresAt: entry.expiresAt } : {}),
      ...(entry.metadata !== undefined ? { metadata: entry.metadata } : {})
    };
    store.set(safeRef, stored);
    return stored;
  };

  const loaded = loadStoreFromEncryptedSnapshot();
  if (!loaded) {
    if (options.initialEntries !== undefined) {
      for (const entry of options.initialEntries) {
        putInternal(entry);
      }
    } else if (options.seedDefaults === true) {
      for (const entry of buildDevFixtureSeeds(generation)) {
        putInternal(entry);
      }
    }
    serializeStoreToEncryptedSnapshot();
  }

  const handleRequest = (rawRequest: unknown): Promise<LocalProviderResponse> => {
    try {
      if (!rawRequest || typeof rawRequest !== "object") {
        return Promise.resolve({
          ok: false,
          errorCode: "INVALID_REQUEST",
          message: "Request frame must be a JSON object"
        });
      }
      const req = rawRequest as Partial<LocalProviderRequest>;
      switch (req.op) {
        case "get": {
          const ref = assertValidRef(req.ref ?? "");
          const entry = store.get(ref);
          if (entry === undefined) {
            throw new NotFoundDomainError({
              code: "NOT_FOUND",
              message: `Secret reference "${ref}" was not found`
            });
          }
          return Promise.resolve({
            ok: true,
            op: "get",
            ref: entry.ref,
            valueBase64: entry.value.toString("base64"),
            version: entry.version,
            ...(entry.expiresAt !== undefined ? { expiresAt: entry.expiresAt } : {})
          });
        }
        case "put": {
          const ref = assertValidRef(req.ref ?? "");
          if (typeof req.valueBase64 !== "string") {
            throw new ValidationDomainError({
              code: "INVALID_VALUE",
              message: "valueBase64 must be a base64 string"
            });
          }
          const buf = Buffer.from(req.valueBase64, "base64");
          const stored = putInternal({
            ref,
            value: buf,
            ...(req.version !== undefined ? { version: req.version } : {}),
            ...(req.expiresAt !== undefined ? { expiresAt: req.expiresAt } : {}),
            ...(req.metadata !== undefined ? { metadata: req.metadata } : {})
          });
          serializeStoreToEncryptedSnapshot();
          return Promise.resolve({
            ok: true,
            op: "put",
            ref: stored.ref,
            version: stored.version,
            ...(stored.expiresAt !== undefined ? { expiresAt: stored.expiresAt } : {})
          });
        }
        case "retire": {
          const ref = assertValidRef(req.ref ?? "");
          const existed = store.delete(ref);
          if (!existed) {
            throw new NotFoundDomainError({
              code: "NOT_FOUND",
              message: `Secret reference "${ref}" was not found`
            });
          }
          serializeStoreToEncryptedSnapshot();
          return Promise.resolve({
            ok: true,
            op: "retire",
            ref
          });
        }
        case "status": {
          return Promise.resolve({
            ok: true,
            op: "status",
            count: store.size,
            maxEntries,
            refs: Array.from(store.keys()).sort()
          });
        }
        default:
          return Promise.resolve({
            ok: false,
            errorCode: "UNSUPPORTED_OP",
            message: "Unsupported IPC operation"
          });
      }
    } catch (err) {
      if (err instanceof NotFoundDomainError) {
        return Promise.resolve({
          ok: false,
          errorCode: "NOT_FOUND",
          message: err.message
        });
      }
      if (err instanceof LimitExceededDomainError) {
        return Promise.resolve({
          ok: false,
          errorCode: "CAPACITY_EXCEEDED",
          message: err.message
        });
      }
      return Promise.resolve({
        ok: false,
        errorCode: "INVALID_REQUEST",
        message: err instanceof Error ? err.message : String(err)
      });
    }
  };

  const server: IpcServerHandle = createIpcServer(endpoint, handleRequest, {
    allowEmptyProbeDisconnect: true,
    allowBuiltInAdmins: options.allowBuiltInAdmins
  });

  await server.listen();

  return {
    endpoint,
    verifySecurity(): Promise<IpcSecurityReport> {
      return server.verifySecurity();
    },
    status(): AdminIpcStatusSnapshot {
      return {
        endpoint,
        count: store.size,
        maxEntries,
        maxEntryBytes,
        refs: Array.from(store.keys()).sort(),
        generation,
        custodySnapshotEnabled: snapshotEnabled
      };
    },
    reload(): Promise<{ readonly count: number; readonly generation: number }> {
      loadStoreFromEncryptedSnapshot();
      generation += 1;
      return Promise.resolve({ count: store.size, generation });
    },
    reseed(
      entries?: readonly ProviderSeedEntry[]
    ): Promise<{ readonly seeded: number; readonly generation: number }> {
      generation += 1;
      store.clear();
      const toSeed = entries ?? buildDevFixtureSeeds(generation);
      for (const entry of toSeed) {
        putInternal(entry);
      }
      serializeStoreToEncryptedSnapshot();
      return Promise.resolve({ seeded: store.size, generation });
    },
    putSecret(entry: ProviderSeedEntry): void {
      putInternal(entry);
      serializeStoreToEncryptedSnapshot();
    },
    async close(): Promise<void> {
      for (const item of store.values()) {
        item.value.fill(0);
      }
      store.clear();
      await server.close();
    }
  };
}
