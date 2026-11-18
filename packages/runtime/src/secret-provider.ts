import fs from "node:fs";
import path from "node:path";
import {
  DependencyUnavailableDomainError,
  LimitExceededDomainError,
  NotFoundDomainError,
  ValidationDomainError
} from "@relayquill/domain";
import { assertSafeFilesystemPath, resolveEnvMap } from "./env.js";
import {
  resolveIpcChannelEndpoint,
  sendIpcFrame,
  type IpcChannelRef,
  type IpcSecurityOptions
} from "./ipc.js";

export const SECRET_PROVIDER_MODES = [
  "in_memory_test",
  "local_ipc",
  "local_ipc_provider",
  "env_file",
  "env_reference",
  "mounted_file",
  "aws_secrets_manager"
] as const;

export type SecretProviderMode = (typeof SECRET_PROVIDER_MODES)[number];

export type SecretSourceKind =
  | "memory"
  | "env"
  | "env_file"
  | "mounted_file"
  | "local_ipc"
  | "custody";

export const DEFAULT_MAX_SECRET_BYTES = 64 * 1024;
export const DEFAULT_LOCAL_PROVIDER_MAX_ENTRIES = 4096;
export const DEFAULT_LOCAL_PROVIDER_MAX_ENTRY_BYTES = 4096;

const SECRET_HANDLE_TAG = Symbol.for("relayquill.runtime.SecretHandle");

export interface SecretHandleMetadata {
  readonly id?: string | undefined;
  readonly source?: SecretSourceKind | undefined;
  readonly version?: string | undefined;
  readonly expiresAt?: string | undefined;
}

export interface SecretHandle {
  readonly [SECRET_HANDLE_TAG]: true;
  readonly id: string;
  readonly source: SecretSourceKind;
  readonly version: string | undefined;
  readonly expiresAt: string | undefined;
  readonly byteLength: number;
  readonly isDestroyed: boolean;
  readBytes(): Buffer;
  readUtf8(): string;
  useBytes<T>(fn: (bytes: Buffer) => T): T;
  useUtf8<T>(fn: (value: string) => T): T;
  destroy(): void;
  toJSON(): string;
  toString(): string;
  valueOf(): string;
}

class MemorySecretHandle implements SecretHandle {
  readonly [SECRET_HANDLE_TAG] = true as const;
  readonly id: string;
  readonly source: SecretSourceKind;
  readonly version: string | undefined;
  readonly expiresAt: string | undefined;
  readonly byteLength: number;

  #secretBytes: Buffer | null;
  #destroyed = false;

  constructor(bytes: Buffer, metadata: SecretHandleMetadata = {}) {
    const copy = Buffer.allocUnsafe(bytes.byteLength);
    bytes.copy(copy);
    this.#secretBytes = copy;
    this.byteLength = copy.byteLength;
    this.id = metadata.id ?? "anonymous";
    this.source = metadata.source ?? "memory";
    this.version = metadata.version;
    this.expiresAt = metadata.expiresAt;
  }

  get isDestroyed(): boolean {
    return this.#destroyed;
  }

  readBytes(): Buffer {
    if (this.#destroyed || this.#secretBytes === null) {
      throw new DependencyUnavailableDomainError({
        code: "SECRET_CUSTODY_ERROR",
        message: `SecretHandle "${this.id}" has already been destroyed`,
        retryable: false
      });
    }
    const out = Buffer.allocUnsafe(this.#secretBytes.byteLength);
    this.#secretBytes.copy(out);
    return out;
  }

  readUtf8(): string {
    const buf = this.readBytes();
    try {
      return buf.toString("utf8");
    } finally {
      buf.fill(0);
    }
  }

  useBytes<T>(fn: (bytes: Buffer) => T): T {
    const copy = this.readBytes();
    try {
      return fn(copy);
    } finally {
      copy.fill(0);
    }
  }

  useUtf8<T>(fn: (value: string) => T): T {
    return fn(this.readUtf8());
  }

  destroy(): void {
    if (this.#secretBytes !== null) {
      this.#secretBytes.fill(0);
      this.#secretBytes = null;
    }
    this.#destroyed = true;
  }

  toJSON(): string {
    return "[REDACTED]";
  }

  toString(): string {
    return "[REDACTED]";
  }

  valueOf(): string {
    return "[REDACTED]";
  }

  [Symbol.for("nodejs.util.inspect.custom")](): string {
    return `[SecretHandle:${this.id} (${this.source}) REDACTED]`;
  }
}

export function createSecretHandle(
  value: string | Uint8Array,
  metadata: SecretHandleMetadata = {}
): SecretHandle {
  const bytes =
    typeof value === "string"
      ? Buffer.from(value, "utf8")
      : Buffer.from(value.buffer, value.byteOffset, value.byteLength);
  return new MemorySecretHandle(bytes, metadata);
}

export function isSecretHandle(value: unknown): value is SecretHandle {
  return (
    typeof value === "object" &&
    value !== null &&
    (value as { readonly [SECRET_HANDLE_TAG]?: unknown })[SECRET_HANDLE_TAG] === true
  );
}

export type ParsedSecretRef =
  | { readonly scheme: "env"; readonly envVar: string; readonly raw: string }
  | { readonly scheme: "file"; readonly filePath: string; readonly raw: string }
  | { readonly scheme: "custody"; readonly key: string; readonly raw: string }
  | { readonly scheme: "aws-sm"; readonly secretId: string; readonly raw: string };

const ENV_REF_REGEX = /^env:([A-Z][A-Z0-9_]{1,127})$/;
const CUSTODY_REF_REGEX = /^custody:([a-z0-9/_-]{3,128})$/;
const AWS_SM_REF_REGEX = /^aws-sm:([a-zA-Z0-9/_+=.@-]{3,256})$/;

export function parseSecretRef(ref: string): ParsedSecretRef {
  if (typeof ref !== "string" || ref.trim().length === 0) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: "Secret reference must be a non-empty string"
    });
  }
  const trimmed = ref.trim();
  const envMatch = ENV_REF_REGEX.exec(trimmed);
  if (envMatch?.[1] !== undefined) {
    return { scheme: "env", envVar: envMatch[1], raw: trimmed };
  }
  if (trimmed.startsWith("file:")) {
    const rawPath = trimmed.slice("file:".length);
    const safePath = assertSafeFilesystemPath(rawPath, "secret_ref_file");
    return { scheme: "file", filePath: safePath, raw: trimmed };
  }
  const custodyMatch = CUSTODY_REF_REGEX.exec(trimmed);
  if (custodyMatch?.[1] !== undefined) {
    return { scheme: "custody", key: custodyMatch[1], raw: trimmed };
  }
  const awsMatch = AWS_SM_REF_REGEX.exec(trimmed);
  if (awsMatch?.[1] !== undefined) {
    return { scheme: "aws-sm", secretId: awsMatch[1], raw: trimmed };
  }
  throw new ValidationDomainError({
    code: "INVALID_VALUE",
    message: `Unsupported secret reference format "${trimmed}"`
  });
}

export interface SecretMetadata {
  readonly id: string;
  readonly source: SecretSourceKind;
  readonly version?: string | undefined;
  readonly expiresAt?: string | undefined;
  readonly metadata?: Readonly<Record<string, string>> | undefined;
}

export interface PutSecretOptions {
  readonly version?: string | undefined;
  readonly expiresAt?: string | undefined;
  readonly metadata?: Readonly<Record<string, string>> | undefined;
}

export interface SecretProviderStatus {
  readonly mode: SecretProviderMode;
  readonly count: number;
  readonly maxEntries?: number | undefined;
  readonly refs: readonly string[];
}

export interface SecretProvider {
  readonly mode: SecretProviderMode;
  getSecret(ref: string): Promise<SecretHandle>;
  putSecret?(
    ref: string,
    value: string | Uint8Array,
    options?: PutSecretOptions
  ): Promise<SecretMetadata>;
  retireSecret?(ref: string): Promise<void>;
  getStatus?(): Promise<SecretProviderStatus>;
  close?(): Promise<void>;
}

export interface CustodyProviderAdapter {
  readonly name: string;
  getSecret(ref: string): Promise<SecretHandle>;
  putSecret?(
    ref: string,
    value: string | Uint8Array,
    options?: PutSecretOptions
  ): Promise<SecretMetadata>;
  retireSecret?(ref: string): Promise<void>;
  getStatus?(): Promise<SecretProviderStatus>;
  close?(): Promise<void>;
}

interface StoredMemoryEntry {
  bytes: Buffer;
  version: string | undefined;
  expiresAt: string | undefined;
  metadata: Readonly<Record<string, string>> | undefined;
}

export class InMemorySecretProvider implements SecretProvider {
  readonly mode = "in_memory_test" as const;
  readonly #entries = new Map<string, StoredMemoryEntry>();
  readonly #maxEntries: number;
  readonly #maxEntryBytes: number;

  constructor(
    options: {
      readonly maxEntries?: number | undefined;
      readonly maxEntryBytes?: number | undefined;
      readonly initialSecrets?: Readonly<Record<string, string | Uint8Array>> | undefined;
    } = {}
  ) {
    this.#maxEntries = options.maxEntries ?? DEFAULT_LOCAL_PROVIDER_MAX_ENTRIES;
    this.#maxEntryBytes = options.maxEntryBytes ?? DEFAULT_LOCAL_PROVIDER_MAX_ENTRY_BYTES;
    if (options.initialSecrets !== undefined) {
      for (const [key, val] of Object.entries(options.initialSecrets)) {
        this.putSync(key, val);
      }
    }
  }

  putSync(
    ref: string,
    value: string | Uint8Array,
    options: PutSecretOptions = {}
  ): SecretMetadata {
    if (typeof ref !== "string" || ref.trim().length === 0) {
      throw new ValidationDomainError({
        code: "INVALID_VALUE",
        message: "Secret ref must be a non-empty string"
      });
    }
    const rawBuf =
      typeof value === "string"
        ? Buffer.from(value, "utf8")
        : Buffer.from(value.buffer, value.byteOffset, value.byteLength);
    if (rawBuf.byteLength > this.#maxEntryBytes) {
      throw new LimitExceededDomainError({
        code: "CAPACITY_EXCEEDED",
        message: `Secret entry "${ref}" exceeds max ${this.#maxEntryBytes} bytes`
      });
    }
    const existing = this.#entries.get(ref);
    if (existing === undefined && this.#entries.size >= this.#maxEntries) {
      throw new LimitExceededDomainError({
        code: "CAPACITY_EXCEEDED",
        message: `In-memory secret provider capacity (${this.#maxEntries}) reached`
      });
    }
    if (existing !== undefined) {
      existing.bytes.fill(0);
    }
    const copy = Buffer.allocUnsafe(rawBuf.byteLength);
    rawBuf.copy(copy);
    this.#entries.set(ref, {
      bytes: copy,
      version: options.version,
      expiresAt: options.expiresAt,
      metadata: options.metadata
    });
    return {
      id: ref,
      source: "memory",
      version: options.version,
      expiresAt: options.expiresAt,
      metadata: options.metadata
    };
  }

  getSecret(ref: string): Promise<SecretHandle> {
    try {
      const entry = this.#entries.get(ref);
      if (entry === undefined) {
        return Promise.reject(
          new NotFoundDomainError({
            code: "NOT_FOUND",
            message: `Secret "${ref}" is not present in memory provider`
          })
        );
      }
      return Promise.resolve(
        createSecretHandle(entry.bytes, {
          id: ref,
          source: "memory",
          version: entry.version,
          expiresAt: entry.expiresAt
        })
      );
    } catch (err) {
      return Promise.reject(err instanceof Error ? err : new Error(String(err)));
    }
  }

  putSecret(
    ref: string,
    value: string | Uint8Array,
    options?: PutSecretOptions
  ): Promise<SecretMetadata> {
    try {
      return Promise.resolve(this.putSync(ref, value, options));
    } catch (err) {
      return Promise.reject(err instanceof Error ? err : new Error(String(err)));
    }
  }

  retireSecret(ref: string): Promise<void> {
    const existing = this.#entries.get(ref);
    if (existing !== undefined) {
      existing.bytes.fill(0);
      this.#entries.delete(ref);
    }
    return Promise.resolve();
  }

  getStatus(): Promise<SecretProviderStatus> {
    return Promise.resolve({
      mode: this.mode,
      count: this.#entries.size,
      maxEntries: this.#maxEntries,
      refs: Array.from(this.#entries.keys()).sort()
    });
  }

  close(): Promise<void> {
    for (const entry of this.#entries.values()) {
      entry.bytes.fill(0);
    }
    this.#entries.clear();
    return Promise.resolve();
  }
}

export class EnvReferenceSecretProvider implements SecretProvider {
  readonly mode: "env_reference" | "env_file";
  readonly #env: Readonly<Record<string, string | undefined>>;
  readonly #source: "env" | "env_file";

  constructor(
    options: {
      readonly mode?: "env_reference" | "env_file" | undefined;
      readonly env?: Readonly<Record<string, string | undefined>> | undefined;
      readonly envFilePath?: string | undefined;
      readonly requireEnvFile?: boolean | undefined;
    } = {}
  ) {
    this.mode = options.mode ?? "env_reference";
    this.#source = this.mode === "env_file" ? "env_file" : "env";
    this.#env = resolveEnvMap({
      env: options.env,
      envFilePath: options.envFilePath,
      requireEnvFile: options.requireEnvFile
    });
  }

  getSecret(ref: string): Promise<SecretHandle> {
    let parsed: ParsedSecretRef;
    try {
      parsed = parseSecretRef(ref);
    } catch (err) {
      return Promise.reject(err instanceof Error ? err : new Error(String(err)));
    }
    if (parsed.scheme !== "env") {
      return Promise.reject(
        new ValidationDomainError({
          code: "INVALID_VALUE",
          message: `Env secret provider cannot resolve "${parsed.scheme}:" reference (${ref})`
        })
      );
    }
    const rawVal = this.#env[parsed.envVar];
    if (typeof rawVal !== "string" || rawVal.length === 0) {
      return Promise.reject(
        new DependencyUnavailableDomainError({
          code: "SECRET_CUSTODY_ERROR",
          message: `Missing required environment secret "${parsed.envVar}"`,
          retryable: false
        })
      );
    }
    return Promise.resolve(
      createSecretHandle(rawVal, {
        id: ref,
        source: this.#source
      })
    );
  }
}

function stripTrailingLineEndings(buf: Buffer): Buffer {
  let end = buf.byteLength;
  while (end > 0 && (buf[end - 1] === 0x0a || buf[end - 1] === 0x0d)) {
    end -= 1;
  }
  return buf.subarray(0, end);
}

function isInsideDirectory(baseDirReal: string, targetReal: string): boolean {
  const rel = path.relative(baseDirReal, targetReal);
  return rel === "" || (!rel.startsWith("..") && !path.isAbsolute(rel));
}

export class MountedFileSecretProvider implements SecretProvider {
  readonly mode = "mounted_file" as const;
  readonly #secretsDir: string | undefined;
  readonly #fileMap: Readonly<Record<string, string>>;
  readonly #maxFileBytes: number;
  readonly #trimTrailingNewline: boolean;

  constructor(
    options: {
      readonly secretsDir?: string | undefined;
      readonly fileMap?: Readonly<Record<string, string>> | undefined;
      readonly maxFileBytes?: number | undefined;
      readonly trimTrailingNewline?: boolean | undefined;
    } = {}
  ) {
    this.#secretsDir =
      options.secretsDir !== undefined
        ? assertSafeFilesystemPath(options.secretsDir, "secrets_dir")
        : undefined;
    this.#fileMap = options.fileMap ?? {};
    this.#maxFileBytes = options.maxFileBytes ?? DEFAULT_MAX_SECRET_BYTES;
    this.#trimTrailingNewline = options.trimTrailingNewline ?? true;
  }

  #resolveTargetPath(ref: string): string {
    const mapped = this.#fileMap[ref];
    if (mapped !== undefined) {
      return assertSafeFilesystemPath(mapped, "secret_file_map");
    }
    const parsed = parseSecretRef(ref);
    if (parsed.scheme === "file") {
      return parsed.filePath;
    }
    if (parsed.scheme === "custody") {
      if (this.#secretsDir === undefined) {
        throw new DependencyUnavailableDomainError({
          code: "SECRET_CUSTODY_ERROR",
          message: `Mounted file secret provider requires secrets_dir or file_map to resolve "${ref}"`,
          retryable: false
        });
      }
      const candidate = path.join(this.#secretsDir, parsed.key);
      return assertSafeFilesystemPath(candidate, "mounted_secret_path");
    }
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Mounted file secret provider cannot resolve "${parsed.scheme}:" reference (${ref})`
    });
  }

  getSecret(ref: string): Promise<SecretHandle> {
    try {
      const targetPath = this.#resolveTargetPath(ref);
      const resolved = path.resolve(targetPath);
      if (!fs.existsSync(resolved)) {
        return Promise.reject(
          new DependencyUnavailableDomainError({
            code: "SECRET_CUSTODY_ERROR",
            message: `Mounted secret file not found for ref "${ref}"`,
            retryable: false
          })
        );
      }

      const realFile = fs.realpathSync(resolved);
      if (this.#secretsDir !== undefined && !ref.startsWith("file:")) {
        const realDir = fs.realpathSync(path.resolve(this.#secretsDir));
        if (!isInsideDirectory(realDir, realFile)) {
          return Promise.reject(
            new DependencyUnavailableDomainError({
              code: "SECRET_CUSTODY_ERROR",
              message: `Mounted secret path escapes configured secrets_dir for ref "${ref}"`,
              retryable: false
            })
          );
        }
      }

      const stat = fs.statSync(realFile);
      if (!stat.isFile()) {
        return Promise.reject(
          new ValidationDomainError({
            code: "INVALID_VALUE",
            message: `Mounted secret path is not a regular file for ref "${ref}"`
          })
        );
      }
      if (stat.size > this.#maxFileBytes) {
        return Promise.reject(
          new LimitExceededDomainError({
            code: "CAPACITY_EXCEEDED",
            message: `Mounted secret file exceeds max ${this.#maxFileBytes} bytes for ref "${ref}"`
          })
        );
      }

      const raw = fs.readFileSync(realFile);
      try {
        const payload = this.#trimTrailingNewline ? stripTrailingLineEndings(raw) : raw;
        if (payload.byteLength === 0) {
          return Promise.reject(
            new DependencyUnavailableDomainError({
              code: "SECRET_CUSTODY_ERROR",
              message: `Mounted secret file is empty for ref "${ref}"`,
              retryable: false
            })
          );
        }
        return Promise.resolve(
          createSecretHandle(payload, {
            id: ref,
            source: "mounted_file"
          })
        );
      } finally {
        raw.fill(0);
      }
    } catch (err) {
      return Promise.reject(err instanceof Error ? err : new Error(String(err)));
    }
  }
}

export type LocalProviderRequest =
  | { readonly op: "get"; readonly ref: string }
  | {
      readonly op: "put";
      readonly ref: string;
      readonly valueBase64: string;
      readonly version?: string | undefined;
      readonly expiresAt?: string | undefined;
      readonly metadata?: Readonly<Record<string, string>> | undefined;
    }
  | { readonly op: "retire"; readonly ref: string }
  | { readonly op: "status" };

export type LocalProviderResponse =
  | {
      readonly ok: true;
      readonly op: "get";
      readonly ref: string;
      readonly valueBase64: string;
      readonly version?: string | undefined;
      readonly expiresAt?: string | undefined;
    }
  | {
      readonly ok: true;
      readonly op: "put";
      readonly ref: string;
      readonly version?: string | undefined;
      readonly expiresAt?: string | undefined;
    }
  | { readonly ok: true; readonly op: "retire"; readonly ref: string }
  | {
      readonly ok: true;
      readonly op: "status";
      readonly count: number;
      readonly maxEntries: number;
      readonly refs: readonly string[];
    }
  | {
      readonly ok: false;
      readonly errorCode: string;
      readonly message: string;
    };

export interface LocalIpcSecretProviderOptions extends IpcSecurityOptions {
  readonly ipc: IpcChannelRef;
  readonly mode?: "local_ipc" | "local_ipc_provider" | undefined;
  readonly env?: Readonly<Record<string, string | undefined>> | undefined;
  readonly timeoutMs?: number | undefined;
}

export class LocalIpcSecretProvider implements SecretProvider {
  readonly mode: "local_ipc" | "local_ipc_provider";
  readonly endpoint: string;
  readonly #timeoutMs: number | undefined;
  readonly #allowBuiltInAdmins: boolean | undefined;

  constructor(options: LocalIpcSecretProviderOptions) {
    this.mode = options.mode ?? "local_ipc";
    this.endpoint = resolveIpcChannelEndpoint(options.ipc, options.env);
    this.#timeoutMs = options.timeoutMs;
    this.#allowBuiltInAdmins = options.allowBuiltInAdmins;
  }

  async #call(req: LocalProviderRequest): Promise<Extract<LocalProviderResponse, { readonly ok: true }>> {
    const reply = await sendIpcFrame<LocalProviderResponse>(
      this.endpoint,
      req,
      {
        timeoutMs: this.#timeoutMs,
        allowBuiltInAdmins: this.#allowBuiltInAdmins,
        verifySecurity: true
      }
    );
    if (!reply || typeof reply !== "object" || typeof reply.ok !== "boolean") {
      throw new DependencyUnavailableDomainError({
        code: "SECRET_CUSTODY_ERROR",
        message: "Malformed response from local IPC secret provider",
        retryable: true
      });
    }
    if (!reply.ok) {
      if (reply.errorCode === "NOT_FOUND") {
        throw new NotFoundDomainError({
          code: "NOT_FOUND",
          message: reply.message
        });
      }
      if (reply.errorCode === "CAPACITY_EXCEEDED") {
        throw new LimitExceededDomainError({
          code: "CAPACITY_EXCEEDED",
          message: reply.message
        });
      }
      throw new DependencyUnavailableDomainError({
        code: "SECRET_CUSTODY_ERROR",
        message: reply.message,
        retryable: false
      });
    }
    return reply;
  }

  async getSecret(ref: string): Promise<SecretHandle> {
    const res = await this.#call({ op: "get", ref });
    if (res.op !== "get") {
      throw new DependencyUnavailableDomainError({
        code: "SECRET_CUSTODY_ERROR",
        message: "Unexpected IPC response op for getSecret",
        retryable: false
      });
    }
    const decoded = Buffer.from(res.valueBase64, "base64");
    try {
      return createSecretHandle(decoded, {
        id: ref,
        source: "local_ipc",
        version: res.version,
        expiresAt: res.expiresAt
      });
    } finally {
      decoded.fill(0);
    }
  }

  async putSecret(
    ref: string,
    value: string | Uint8Array,
    options: PutSecretOptions = {}
  ): Promise<SecretMetadata> {
    const raw =
      typeof value === "string"
        ? Buffer.from(value, "utf8")
        : Buffer.from(value.buffer, value.byteOffset, value.byteLength);
    const res = await this.#call({
      op: "put",
      ref,
      valueBase64: raw.toString("base64"),
      version: options.version,
      expiresAt: options.expiresAt,
      metadata: options.metadata
    });
    if (res.op !== "put") {
      throw new DependencyUnavailableDomainError({
        code: "SECRET_CUSTODY_ERROR",
        message: "Unexpected IPC response op for putSecret",
        retryable: false
      });
    }
    return {
      id: ref,
      source: "local_ipc",
      version: res.version,
      expiresAt: res.expiresAt
    };
  }

  async retireSecret(ref: string): Promise<void> {
    await this.#call({ op: "retire", ref });
  }

  async getStatus(): Promise<SecretProviderStatus> {
    const res = await this.#call({ op: "status" });
    if (res.op !== "status") {
      throw new DependencyUnavailableDomainError({
        code: "SECRET_CUSTODY_ERROR",
        message: "Unexpected IPC response op for getStatus",
        retryable: false
      });
    }
    return {
      mode: this.mode,
      count: res.count,
      maxEntries: res.maxEntries,
      refs: res.refs
    };
  }
}

export function createLocalIpcProviderClient(
  options: LocalIpcSecretProviderOptions
): LocalIpcSecretProvider {
  return new LocalIpcSecretProvider(options);
}

export interface SecretProviderConfigInput {
  readonly mode: SecretProviderMode;
  readonly ipc?: IpcChannelRef | undefined;
  readonly env_file?: string | undefined;
  readonly secrets_dir?: string | undefined;
  readonly file_map?: Readonly<Record<string, string>> | undefined;
  readonly region?: string | undefined;
  readonly secret_prefix?: string | undefined;
}

export interface CreateSecretProviderOptions extends IpcSecurityOptions {
  readonly env?: Readonly<Record<string, string | undefined>> | undefined;
  readonly initialInMemorySecrets?: Readonly<Record<string, string | Uint8Array>> | undefined;
  readonly custodyProviders?: Readonly<Record<string, CustodyProviderAdapter>> | undefined;
  readonly allowDirectEnvAndFileRefs?: boolean | undefined;
}

class DelegatingCustodySecretProvider implements SecretProvider {
  readonly mode: SecretProviderMode;
  readonly #adapter: CustodyProviderAdapter;

  constructor(mode: SecretProviderMode, adapter: CustodyProviderAdapter) {
    this.mode = mode;
    this.#adapter = adapter;
  }

  getSecret(ref: string): Promise<SecretHandle> {
    return this.#adapter.getSecret(ref);
  }

  putSecret(
    ref: string,
    value: string | Uint8Array,
    options?: PutSecretOptions
  ): Promise<SecretMetadata> {
    if (!this.#adapter.putSecret) {
      return Promise.reject(
        new DependencyUnavailableDomainError({
          code: "SECRET_CUSTODY_ERROR",
          message: `Custody provider "${this.#adapter.name}" is read-only`,
          retryable: false
        })
      );
    }
    return this.#adapter.putSecret(ref, value, options);
  }

  retireSecret(ref: string): Promise<void> {
    if (!this.#adapter.retireSecret) {
      return Promise.reject(
        new DependencyUnavailableDomainError({
          code: "SECRET_CUSTODY_ERROR",
          message: `Custody provider "${this.#adapter.name}" does not support retireSecret`,
          retryable: false
        })
      );
    }
    return this.#adapter.retireSecret(ref);
  }

  getStatus(): Promise<SecretProviderStatus> {
    if (!this.#adapter.getStatus) {
      return Promise.resolve({ mode: this.mode, count: 0, refs: [] });
    }
    return this.#adapter.getStatus();
  }

  close(): Promise<void> {
    return this.#adapter.close ? this.#adapter.close() : Promise.resolve();
  }
}

class CompositeSecretProvider implements SecretProvider {
  readonly mode: SecretProviderMode;
  readonly #primary: SecretProvider;
  readonly #envProvider: EnvReferenceSecretProvider;
  readonly #fileProvider: MountedFileSecretProvider;
  readonly #custodyProviders: Readonly<Record<string, CustodyProviderAdapter>>;
  readonly #allowDirectEnvAndFileRefs: boolean;

  constructor(options: {
    readonly primary: SecretProvider;
    readonly envProvider: EnvReferenceSecretProvider;
    readonly fileProvider: MountedFileSecretProvider;
    readonly custodyProviders: Readonly<Record<string, CustodyProviderAdapter>>;
    readonly allowDirectEnvAndFileRefs: boolean;
  }) {
    this.mode = options.primary.mode;
    this.#primary = options.primary;
    this.#envProvider = options.envProvider;
    this.#fileProvider = options.fileProvider;
    this.#custodyProviders = options.custodyProviders;
    this.#allowDirectEnvAndFileRefs = options.allowDirectEnvAndFileRefs;
  }

  getSecret(ref: string): Promise<SecretHandle> {
    if (this.#primary.mode === "in_memory_test") {
      return this.#primary.getSecret(ref);
    }

    let parsed: ParsedSecretRef;
    try {
      parsed = parseSecretRef(ref);
    } catch (err) {
      return Promise.reject(err instanceof Error ? err : new Error(String(err)));
    }
    if (parsed.scheme === "env") {
      if (this.#primary.mode === "env_reference" || this.#primary.mode === "env_file") {
        return this.#primary.getSecret(ref);
      }
      if (this.#allowDirectEnvAndFileRefs) {
        return this.#envProvider.getSecret(ref);
      }
    }
    if (parsed.scheme === "file") {
      if (this.#primary.mode === "mounted_file") {
        return this.#primary.getSecret(ref);
      }
      if (this.#allowDirectEnvAndFileRefs) {
        return this.#fileProvider.getSecret(ref);
      }
    }
    if (parsed.scheme === "aws-sm") {
      if (this.#primary.mode === "aws_secrets_manager") {
        return this.#primary.getSecret(ref);
      }
      const awsAdapter =
        this.#custodyProviders.aws_secrets_manager ?? this.#custodyProviders["aws-sm"];
      if (awsAdapter !== undefined) {
        return awsAdapter.getSecret(ref);
      }
    }
    if (parsed.scheme === "custody") {
      const custodyAdapter = this.#custodyProviders.custody;
      if (
        this.#primary.mode === "local_ipc" ||
        this.#primary.mode === "local_ipc_provider" ||
        this.#primary.mode === "mounted_file"
      ) {
        return this.#primary.getSecret(ref);
      }
      if (custodyAdapter !== undefined) {
        return custodyAdapter.getSecret(ref);
      }
    }
    return this.#primary.getSecret(ref);
  }

  putSecret(
    ref: string,
    value: string | Uint8Array,
    options?: PutSecretOptions
  ): Promise<SecretMetadata> {
    if (!this.#primary.putSecret) {
      return Promise.reject(
        new DependencyUnavailableDomainError({
          code: "SECRET_CUSTODY_ERROR",
          message: `Secret provider mode "${this.#primary.mode}" does not support putSecret`,
          retryable: false
        })
      );
    }
    return this.#primary.putSecret(ref, value, options);
  }

  retireSecret(ref: string): Promise<void> {
    if (!this.#primary.retireSecret) {
      return Promise.reject(
        new DependencyUnavailableDomainError({
          code: "SECRET_CUSTODY_ERROR",
          message: `Secret provider mode "${this.#primary.mode}" does not support retireSecret`,
          retryable: false
        })
      );
    }
    return this.#primary.retireSecret(ref);
  }

  getStatus(): Promise<SecretProviderStatus> {
    if (!this.#primary.getStatus) {
      return Promise.resolve({ mode: this.mode, count: 0, refs: [] });
    }
    return this.#primary.getStatus();
  }

  close(): Promise<void> {
    return this.#primary.close ? this.#primary.close() : Promise.resolve();
  }
}

export function createSecretProvider(
  config: SecretProviderConfigInput | undefined,
  options: CreateSecretProviderOptions = {}
): SecretProvider {
  const custodyProviders = options.custodyProviders ?? {};
  const allowDirect = options.allowDirectEnvAndFileRefs ?? true;

  const envProvider = new EnvReferenceSecretProvider({
    mode: config?.env_file !== undefined ? "env_file" : "env_reference",
    env: options.env,
    envFilePath: config?.env_file,
    requireEnvFile: config?.mode === "env_file" && config.env_file !== undefined
  });

  const fileProvider = new MountedFileSecretProvider({
    secretsDir: config?.secrets_dir,
    fileMap: config?.file_map
  });

  if (config === undefined) {
    return new CompositeSecretProvider({
      primary: envProvider,
      envProvider,
      fileProvider,
      custodyProviders,
      allowDirectEnvAndFileRefs: true
    });
  }

  let primary: SecretProvider;
  switch (config.mode) {
    case "in_memory_test":
      primary = new InMemorySecretProvider({
        initialSecrets: options.initialInMemorySecrets
      });
      break;
    case "env_reference":
      primary = envProvider;
      break;
    case "env_file":
      primary = new EnvReferenceSecretProvider({
        mode: "env_file",
        env: options.env,
        envFilePath: config.env_file ?? ".env",
        requireEnvFile: config.env_file !== undefined
      });
      break;
    case "mounted_file":
      primary = fileProvider;
      break;
    case "local_ipc":
    case "local_ipc_provider": {
      if (config.ipc === undefined) {
        throw new ValidationDomainError({
          code: "INVALID_VALUE",
          message: `Secret provider mode "${config.mode}" requires an ipc channel configuration`
        });
      }
      primary = new LocalIpcSecretProvider({
        mode: config.mode,
        ipc: config.ipc,
        env: options.env,
        allowBuiltInAdmins: options.allowBuiltInAdmins
      });
      break;
    }
    case "aws_secrets_manager": {
      const adapter = custodyProviders.aws_secrets_manager ?? custodyProviders["aws-sm"];
      if (adapter === undefined) {
        throw new DependencyUnavailableDomainError({
          code: "SECRET_CUSTODY_ERROR",
          message:
            'Secret provider mode "aws_secrets_manager" requires an explicit custodyProviders["aws_secrets_manager"] adapter',
          retryable: false
        });
      }
      primary = new DelegatingCustodySecretProvider("aws_secrets_manager", adapter);
      break;
    }
  }

  return new CompositeSecretProvider({
    primary,
    envProvider,
    fileProvider,
    custodyProviders,
    allowDirectEnvAndFileRefs: allowDirect
  });
}
