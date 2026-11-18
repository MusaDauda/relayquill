import fs from "node:fs";
import path from "node:path";
import { ValidationDomainError, type DomainFieldError } from "@relayquill/domain";
import { assertSafeFilesystemPath, resolveEnvMap } from "./env.js";
import { resolveIpcChannelEndpoint, type IpcChannelRef } from "./ipc.js";
import { createSecretHandle, type SecretHandle, type SecretProviderMode } from "./secret-provider.js";

export const PROFILE_KINDS = [
  "portable_pglite",
  "development_trusted_local",
  "hosted_neon",
  "hosted_supabase",
  "hosted_synadia_ngs",
  "self_hosted",
  "release"
] as const;

export type ProfileKind = (typeof PROFILE_KINDS)[number];

export const CONFIG_PROCESS_ROLES = [
  "api",
  "relay",
  "fanout",
  "sender",
  "coordinator",
  "admin",
  "receiver",
  "receiver_migrator",
  "receiver_operator",
  "provider_ingress",
  "provider_ingress_migrator",
  "provider_ingress_fixture",
  "producer_example"
] as const;

export type ConfigProcessRole = (typeof CONFIG_PROCESS_ROLES)[number];

export const DATABASE_MODES = [
  "portable_pglite",
  "development_trusted_local",
  "hosted_neon",
  "hosted_supabase",
  "standard_tls",
  "release_rds_iam"
] as const;

export type DatabaseMode = (typeof DATABASE_MODES)[number];

export const DATABASE_AUTH_MODES = [
  "in_process_pglite",
  "trusted_local_only",
  "secret_provider_password",
  "scram_sha_256",
  "aws_rds_iam_token"
] as const;

export type DatabaseAuthMode = (typeof DATABASE_AUTH_MODES)[number];

export const DATABASE_TLS_MODES = ["in_process", "disabled_fixture", "verify_full"] as const;
export type DatabaseTlsMode = (typeof DATABASE_TLS_MODES)[number];

export const DATABASE_POOL_MODES = ["direct", "session_pooler", "transaction_pooler"] as const;
export type DatabasePoolMode = (typeof DATABASE_POOL_MODES)[number];

export const BROKER_MODES = [
  "in_memory_test",
  "embedded_go_tls",
  "development_loopback",
  "hosted_synadia_ngs",
  "standard_tls",
  "self_hosted",
  "release_native_tls"
] as const;

export type BrokerMode = (typeof BROKER_MODES)[number];

export const BROKER_AUTH_MODES = ["none_fixture", "nkey_seed", "synadia_creds_jwt"] as const;
export type BrokerAuthMode = (typeof BROKER_AUTH_MODES)[number];

export interface SecretProviderConfig {
  readonly mode: SecretProviderMode;
  readonly ipc?: IpcChannelRef | undefined;
  readonly env_file?: string | undefined;
  readonly secrets_dir?: string | undefined;
  readonly file_map?: Readonly<Record<string, string>> | undefined;
  readonly region?: string | undefined;
  readonly secret_prefix?: string | undefined;
}

export interface HttpBindConfig {
  readonly host: string;
  readonly port: number;
  readonly trust_proxy?: boolean | undefined;
}

export interface HttpConfig extends HttpBindConfig {
  readonly public_origin: string;
  readonly sse_heartbeat_ms: number;
  readonly sse_max_lifetime_ms: number;
}

export interface AuthConfig {
  readonly rp_id: string;
  readonly allowed_origins: readonly string[];
  readonly cookie_profile: "development_only" | "release_https";
}

export interface EgressConfig {
  readonly mode: "trusted_local_fixture" | "strict_public_https";
  readonly allow_fixture_receiver: boolean;
  readonly fixture_receiver_authority?: string | undefined;
  readonly fixture_receiver_path?: string | undefined;
  readonly fixture_resolve_ip?: "127.0.0.1" | undefined;
}

export interface ApiTargetConfig {
  readonly origin: string;
  readonly project_id: string;
  readonly credential_secret_ref: string;
}

export interface DatabaseConfig {
  readonly mode: DatabaseMode;
  readonly isolation: "separate_databases" | "shared_database_schemas";
  readonly host: string;
  readonly port: number;
  readonly name: string;
  readonly schema: "rq" | "rc" | "pi";
  readonly support_schema: "rq_support" | "extensions";
  readonly role: string;
  readonly authentication: DatabaseAuthMode;
  readonly password_secret_ref?: string | undefined;
  readonly tls_mode: DatabaseTlsMode;
  readonly tls_ca_file?: string | undefined;
  readonly pool_mode: DatabasePoolMode;
  readonly maximum_connections: number;
  readonly connection_timeout_ms: number;
  readonly statement_timeout_ms: number;
  readonly lock_timeout_ms: number;
}

export interface BrokerTlsConfig {
  readonly enabled: boolean;
  readonly handshake_first?: boolean | undefined;
  readonly ca_file?: string | undefined;
  readonly reject_unauthorized: true;
}

export interface BrokerConfig {
  readonly mode: BrokerMode;
  readonly servers: readonly string[];
  readonly auth_mode: BrokerAuthMode;
  readonly secret_ref?: string | undefined;
  readonly tls?: BrokerTlsConfig | undefined;
  readonly stream_name: string;
  readonly subject_prefix: string;
  readonly consumer_name: string;
  readonly replicas: 1 | 3;
  readonly max_msgs: number;
  readonly max_bytes: number;
  readonly max_msg_size: 4096;
  readonly max_age_ns: number;
  readonly duplicate_window_ns: 120000000000;
  readonly inbox_prefix?: string | undefined;
}

export interface ProtocolConfig {
  readonly http_schema_version: 1;
  readonly broker_envelope_version: 1;
  readonly webhook_signature_version: 1;
}

export interface TelemetryConfig {
  readonly enabled: boolean;
  readonly service_name: string;
  readonly otlp_endpoint?: string | undefined;
  readonly max_queue_size: 2048;
  readonly max_export_batch_size: 256;
  readonly trace_view_origin?: string | undefined;
}

export interface RelaySettings {
  readonly poll_interval_ms: number;
  readonly batch_size: number;
  readonly claim_lease_ms: number;
  readonly publish_concurrency: number;
  readonly publish_timeout_ms: number;
}

export interface FanoutSettings {
  readonly ack_wait_ms: number;
  readonly max_deliver: number;
  readonly max_ack_pending: number;
  readonly max_batch: number;
  readonly max_bytes: number;
  readonly max_expires_ms: number;
}

export interface SenderSettings {
  readonly dispatch_domain: string;
  readonly approved_slots: number;
  readonly poll_interval_ms: number;
  readonly request_timeout_ms: number;
  readonly max_response_bytes: number;
}

export interface CoordinatorSettings {
  readonly loop_interval_ms: number;
  readonly reaper_batch_size: number;
  readonly retention_batch_size: number;
  readonly projection_batch_size: number;
}

export interface ProviderSettings {
  readonly max_entries: number;
  readonly max_entry_bytes: number;
  readonly custody_snapshot_enabled: boolean;
  readonly custody_snapshot_path?: string | undefined;
}

export interface RecoverySettings {
  readonly actor_role: "operator" | "reviewer";
  readonly plan_dir: string;
  readonly require_two_person_review: boolean;
  readonly target_schema_revision?: string | undefined;
}

export interface DiagnosticsSettings {
  readonly max_rows: number;
  readonly query_timeout_ms: number;
  readonly redact_payloads: true;
}

interface BaseRoleConfig {
  readonly $schema?: string | undefined;
  readonly schema_version: 1;
  readonly profile: ProfileKind;
}

export interface ApiRoleConfig extends BaseRoleConfig {
  readonly process_role: "api";
  readonly http: HttpConfig;
  readonly database: DatabaseConfig;
  readonly auth: AuthConfig;
  readonly secret_provider: SecretProviderConfig;
  readonly operator_channel?: IpcChannelRef | undefined;
  readonly telemetry?: TelemetryConfig | undefined;
  readonly protocol: ProtocolConfig;
}

export interface RelayRoleConfig extends BaseRoleConfig {
  readonly process_role: "relay";
  readonly database: DatabaseConfig;
  readonly broker: BrokerConfig;
  readonly relay: RelaySettings;
  readonly telemetry?: TelemetryConfig | undefined;
  readonly protocol: ProtocolConfig;
}

export interface FanoutRoleConfig extends BaseRoleConfig {
  readonly process_role: "fanout";
  readonly database: DatabaseConfig;
  readonly broker: BrokerConfig;
  readonly fanout: FanoutSettings;
  readonly telemetry?: TelemetryConfig | undefined;
  readonly protocol: ProtocolConfig;
}

export interface SenderRoleConfig extends BaseRoleConfig {
  readonly process_role: "sender";
  readonly database: DatabaseConfig;
  readonly secret_provider: SecretProviderConfig;
  readonly sender: SenderSettings;
  readonly egress: EgressConfig;
  readonly telemetry?: TelemetryConfig | undefined;
  readonly protocol: ProtocolConfig;
}

export interface CoordinatorRoleConfig extends BaseRoleConfig {
  readonly process_role: "coordinator";
  readonly database: DatabaseConfig;
  readonly coordinator: CoordinatorSettings;
  readonly telemetry?: TelemetryConfig | undefined;
  readonly protocol: ProtocolConfig;
}

export interface AdminDbBrokerRoleConfig extends BaseRoleConfig {
  readonly process_role: "admin";
  readonly command_role: "db_and_broker_admin";
  readonly database: DatabaseConfig;
  readonly broker: BrokerConfig;
  readonly migrations_dir: string;
  readonly protocol: ProtocolConfig;
}

export interface AdminSigningIssuerRoleConfig extends BaseRoleConfig {
  readonly process_role: "admin";
  readonly command_role: "signing_issuer";
  readonly database: DatabaseConfig;
  readonly secret_provider: SecretProviderConfig;
  readonly protocol: ProtocolConfig;
}

export interface AdminFixtureProviderRoleConfig extends BaseRoleConfig {
  readonly process_role: "admin";
  readonly command_role: "fixture_provider";
  readonly ipc: IpcChannelRef;
  readonly provider: ProviderSettings;
}

export interface AdminBootstrapOperatorRoleConfig extends BaseRoleConfig {
  readonly process_role: "admin";
  readonly command_role: "bootstrap_operator";
  readonly operator_channel: IpcChannelRef;
}

export interface AdminRecoveryRoleConfig extends BaseRoleConfig {
  readonly process_role: "admin";
  readonly command_role: "recovery_operator" | "recovery_reviewer";
  readonly database?: DatabaseConfig | undefined;
  readonly operator_channel?: IpcChannelRef | undefined;
  readonly recovery: RecoverySettings;
}

export interface AdminDiagnosticsRoleConfig extends BaseRoleConfig {
  readonly process_role: "admin";
  readonly command_role: "diagnostics_operator";
  readonly database?: DatabaseConfig | undefined;
  readonly operator_channel?: IpcChannelRef | undefined;
  readonly diagnostics: DiagnosticsSettings;
}

export interface ReceiverRoleConfig extends BaseRoleConfig {
  readonly process_role: "receiver";
  readonly http: HttpBindConfig;
  readonly database: DatabaseConfig;
  readonly secret_provider: SecretProviderConfig;
  readonly control_channel?: IpcChannelRef | undefined;
  readonly telemetry?: TelemetryConfig | undefined;
  readonly protocol: ProtocolConfig;
}

export interface ReceiverMigratorRoleConfig extends BaseRoleConfig {
  readonly process_role: "receiver_migrator";
  readonly database: DatabaseConfig;
  readonly migrations_dir: string;
}

export interface ReceiverOperatorRoleConfig extends BaseRoleConfig {
  readonly process_role: "receiver_operator";
  readonly control_channel: IpcChannelRef;
}

export interface ProviderIngressRoleConfig extends BaseRoleConfig {
  readonly process_role: "provider_ingress";
  readonly http: HttpBindConfig;
  readonly database: DatabaseConfig;
  readonly secret_provider: SecretProviderConfig;
  readonly relayquill_api: ApiTargetConfig;
  readonly control_channel?: IpcChannelRef | undefined;
  readonly telemetry?: TelemetryConfig | undefined;
  readonly protocol: ProtocolConfig;
}

export interface ProviderIngressMigratorRoleConfig extends BaseRoleConfig {
  readonly process_role: "provider_ingress_migrator";
  readonly database: DatabaseConfig;
  readonly migrations_dir: string;
}

export interface ProviderIngressFixtureRoleConfig extends BaseRoleConfig {
  readonly process_role: "provider_ingress_fixture";
  readonly http_target: {
    readonly base_url: string;
    readonly stripe_path: string;
    readonly paystack_path: string;
  };
  readonly control_channel: IpcChannelRef;
}

export interface ProducerExampleRoleConfig extends BaseRoleConfig {
  readonly process_role: "producer_example";
  readonly api_target: ApiTargetConfig;
  readonly secret_provider: SecretProviderConfig;
  readonly runs_dir: string;
  readonly project_scope: {
    readonly project_slug: string;
    readonly producer_credential_ref: string;
  };
}

export type RoleConfig =
  | ApiRoleConfig
  | RelayRoleConfig
  | FanoutRoleConfig
  | SenderRoleConfig
  | CoordinatorRoleConfig
  | AdminDbBrokerRoleConfig
  | AdminSigningIssuerRoleConfig
  | AdminFixtureProviderRoleConfig
  | AdminBootstrapOperatorRoleConfig
  | AdminRecoveryRoleConfig
  | AdminDiagnosticsRoleConfig
  | ReceiverRoleConfig
  | ReceiverMigratorRoleConfig
  | ReceiverOperatorRoleConfig
  | ProviderIngressRoleConfig
  | ProviderIngressMigratorRoleConfig
  | ProviderIngressFixtureRoleConfig
  | ProducerExampleRoleConfig;

export interface ValidateRoleConfigOptions {
  readonly expectedProcessRole?: ConfigProcessRole | undefined;
  readonly expectedCommandRole?: string | undefined;
}

export interface ResolvedDatabaseEnvConfig {
  readonly host: string;
  readonly port: number;
  readonly name: string;
  readonly schema: "rq" | "rc" | "pi";
  readonly supportSchema: "rq_support" | "extensions";
  readonly configuredRole: string;
  readonly user: string;
  readonly mode: DatabaseMode;
  readonly authentication: DatabaseAuthMode;
  readonly tlsMode: DatabaseTlsMode;
  readonly tlsCaFile?: string | undefined;
  readonly poolMode: DatabasePoolMode;
  readonly passwordSecretRef?: string | undefined;
  readonly passwordHandle?: SecretHandle | undefined;
  readonly envOverrideVar?: string | undefined;
}

export interface ResolvedBrokerEnvConfig {
  readonly mode: BrokerMode;
  readonly servers: readonly string[];
  readonly authMode: BrokerAuthMode;
  readonly secretRef?: string | undefined;
  readonly nkeySeedFile?: string | undefined;
  readonly credsFile?: string | undefined;
  readonly tls?: BrokerTlsConfig | undefined;
  readonly streamName: string;
  readonly subjectPrefix: string;
  readonly consumerName: string;
  readonly inboxPrefix?: string | undefined;
}

export interface ResolvedRuntimeEnvironment {
  readonly config: RoleConfig;
  readonly relayquillEnv: string;
  readonly publicConsoleOrigin?: string | undefined;
  readonly publicApiOrigin?: string | undefined;
  readonly webauthnRpId?: string | undefined;
  readonly database?: ResolvedDatabaseEnvConfig | undefined;
  readonly broker?: ResolvedBrokerEnvConfig | undefined;
  readonly operatorEndpoint?: string | undefined;
  readonly controlEndpoint?: string | undefined;
  readonly ipcEndpoint?: string | undefined;
}

const SECRET_JSON_KEY_REGEX =
  /(?:^|[_-])(?:password|pass|secret|private_key|nkey_seed|creds|api_key|signing_key|token)$/i;
const POSTGRES_CRED_URL_REGEX = /postgres(?:ql)?:\/\/[^/\s:@]+:[^/\s@]+@/i;
const POSTGRES_DSN_REGEX = /^postgres(?:ql)?:\/\//i;
const WIN_USERS_PATH_REGEX = /[a-z]:[/\\]+users[/\\]+/i;
const SECRET_REF_REGEX =
  /^(env:[A-Z][A-Z0-9_]{1,127}|file:[a-zA-Z0-9._:/\\-]{1,260}|custody:[a-z0-9/_-]{3,128}|aws-sm:[a-zA-Z0-9/_+=.@-]{3,256})$/;
const IPC_ENV_NAME_REGEX = /^[a-z0-9][a-z0-9-]{0,31}$/;
const IPC_RUNTIME_DIR_ENV_REGEX = /^[A-Z][A-Z0-9_]{0,63}$/;
const IPC_CHANNELS = new Set([
  "provider",
  "api-admin",
  "receiver-control",
  "provider-ingress-control"
]);

export function isProductionProfile(profile: ProfileKind): boolean {
  return profile === "release" || profile === "self_hosted";
}

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function addFieldError(
  errors: DomainFieldError[],
  pathStr: string,
  code = "INVALID_VALUE"
): void {
  errors.push({ path: pathStr, code });
}

function rejectUnknownKeys(
  obj: Record<string, unknown>,
  allowed: readonly string[],
  basePath: string,
  errors: DomainFieldError[]
): void {
  const allowedSet = new Set(allowed);
  for (const key of Object.keys(obj)) {
    if (!allowedSet.has(key)) {
      addFieldError(errors, `${basePath}.${key}`, "UNKNOWN_FIELD");
    }
  }
}

function scanDisallowedStringsAndKeys(
  value: unknown,
  currentPath: string,
  errors: DomainFieldError[]
): void {
  if (typeof value === "string") {
    if (
      POSTGRES_CRED_URL_REGEX.test(value) ||
      value.includes("-----BEGIN ") ||
      value.includes("rq_p1.")
    ) {
      addFieldError(errors, currentPath, "EMBEDDED_SECRET_VALUE");
    }
    if (
      value.includes("/home/") ||
      value.includes("/Users/") ||
      WIN_USERS_PATH_REGEX.test(value) ||
      value.includes(".sock")
    ) {
      addFieldError(errors, currentPath, "FORBIDDEN_HOST_PATH");
    }
    return;
  }
  if (Array.isArray(value)) {
    for (let i = 0; i < value.length; i += 1) {
      scanDisallowedStringsAndKeys(value[i], `${currentPath}[${i}]`, errors);
    }
    return;
  }
  if (isPlainRecord(value)) {
    for (const [key, nested] of Object.entries(value)) {
      const nextPath = `${currentPath}.${key}`;
      if (SECRET_JSON_KEY_REGEX.test(key)) {
        addFieldError(errors, nextPath, "FORBIDDEN_SECRET_KEY");
      }
      scanDisallowedStringsAndKeys(nested, nextPath, errors);
    }
  }
}

function expectNonEmptyString(
  obj: Record<string, unknown>,
  key: string,
  basePath: string,
  errors: DomainFieldError[],
  opts: { readonly minLength?: number; readonly maxLength?: number; readonly pattern?: RegExp } = {}
): string {
  const val = obj[key];
  const fullPath = `${basePath}.${key}`;
  if (typeof val !== "string") {
    addFieldError(errors, fullPath);
    return "";
  }
  const minLen = opts.minLength ?? 1;
  const maxLen = opts.maxLength ?? 4096;
  if (val.length < minLen || val.length > maxLen) {
    addFieldError(errors, fullPath);
    return "";
  }
  if (opts.pattern !== undefined && !opts.pattern.test(val)) {
    addFieldError(errors, fullPath);
    return "";
  }
  return val;
}

function expectIntInRange(
  obj: Record<string, unknown>,
  key: string,
  min: number,
  max: number,
  basePath: string,
  errors: DomainFieldError[]
): number {
  const val = obj[key];
  const fullPath = `${basePath}.${key}`;
  if (typeof val !== "number" || !Number.isInteger(val) || val < min || val > max) {
    addFieldError(errors, fullPath);
    return min;
  }
  return val;
}

function expectBoolean(
  obj: Record<string, unknown>,
  key: string,
  basePath: string,
  errors: DomainFieldError[]
): boolean {
  const val = obj[key];
  const fullPath = `${basePath}.${key}`;
  if (typeof val !== "boolean") {
    addFieldError(errors, fullPath);
    return false;
  }
  return val;
}

function expectRepoRelativePath(
  obj: Record<string, unknown>,
  key: string,
  basePath: string,
  errors: DomainFieldError[]
): string {
  const val = expectNonEmptyString(obj, key, basePath, errors, { minLength: 1, maxLength: 260 });
  if (val.length === 0) {
    return "";
  }
  try {
    return assertSafeFilesystemPath(val, `${basePath}.${key}`, { allowAbsolute: false });
  } catch {
    addFieldError(errors, `${basePath}.${key}`);
    return "";
  }
}

function expectSecretRef(
  obj: Record<string, unknown>,
  key: string,
  basePath: string,
  errors: DomainFieldError[]
): string {
  const val = expectNonEmptyString(obj, key, basePath, errors, {
    pattern: SECRET_REF_REGEX
  });
  if (val.startsWith("file:")) {
    try {
      assertSafeFilesystemPath(val.slice("file:".length), `${basePath}.${key}`);
    } catch {
      addFieldError(errors, `${basePath}.${key}`);
      return "";
    }
  }
  return val;
}

function validateIpcChannelRef(
  raw: unknown,
  basePath: string,
  errors: DomainFieldError[]
): IpcChannelRef | undefined {
  if (!isPlainRecord(raw)) {
    addFieldError(errors, basePath);
    return undefined;
  }
  rejectUnknownKeys(raw, ["env_name", "channel", "runtime_dir_env"], basePath, errors);
  const envName = expectNonEmptyString(raw, "env_name", basePath, errors, {
    pattern: IPC_ENV_NAME_REGEX
  });
  const channel = expectNonEmptyString(raw, "channel", basePath, errors);
  if (channel.length > 0 && !IPC_CHANNELS.has(channel)) {
    addFieldError(errors, `${basePath}.channel`);
  }
  let runtimeDirEnv: string | undefined;
  if ("runtime_dir_env" in raw) {
    runtimeDirEnv = expectNonEmptyString(raw, "runtime_dir_env", basePath, errors, {
      pattern: IPC_RUNTIME_DIR_ENV_REGEX
    });
  }
  return {
    env_name: envName,
    channel,
    ...(runtimeDirEnv !== undefined ? { runtime_dir_env: runtimeDirEnv } : {})
  };
}

function validateSecretProvider(
  raw: unknown,
  profile: ProfileKind,
  basePath: string,
  errors: DomainFieldError[]
): SecretProviderConfig | undefined {
  if (!isPlainRecord(raw)) {
    addFieldError(errors, basePath);
    return undefined;
  }
  rejectUnknownKeys(
    raw,
    ["mode", "ipc", "env_file", "secrets_dir", "file_map", "region", "secret_prefix"],
    basePath,
    errors
  );
  const mode = expectNonEmptyString(raw, "mode", basePath, errors) as SecretProviderMode;
  if (
    ![
      "in_memory_test",
      "local_ipc",
      "local_ipc_provider",
      "env_file",
      "env_reference",
      "mounted_file",
      "aws_secrets_manager"
    ].includes(mode)
  ) {
    addFieldError(errors, `${basePath}.mode`);
  }

  let ipc: IpcChannelRef | undefined;
  if ("ipc" in raw) {
    ipc = validateIpcChannelRef(raw.ipc, `${basePath}.ipc`, errors);
  }
  if ((mode === "local_ipc" || mode === "local_ipc_provider") && ipc === undefined) {
    addFieldError(errors, `${basePath}.ipc`, "MISSING_REQUIRED");
  }

  let envFile: string | undefined;
  if ("env_file" in raw) {
    envFile = expectNonEmptyString(raw, "env_file", basePath, errors, { maxLength: 260 });
    if (envFile.length > 0) {
      try {
        assertSafeFilesystemPath(envFile, `${basePath}.env_file`);
      } catch {
        addFieldError(errors, `${basePath}.env_file`);
      }
    }
  }

  let secretsDir: string | undefined;
  if ("secrets_dir" in raw) {
    secretsDir = expectNonEmptyString(raw, "secrets_dir", basePath, errors, { maxLength: 260 });
    if (secretsDir.length > 0) {
      try {
        assertSafeFilesystemPath(secretsDir, `${basePath}.secrets_dir`);
      } catch {
        addFieldError(errors, `${basePath}.secrets_dir`);
      }
    }
  }

  let fileMap: Record<string, string> | undefined;
  if ("file_map" in raw) {
    if (!isPlainRecord(raw.file_map)) {
      addFieldError(errors, `${basePath}.file_map`);
    } else {
      fileMap = {};
      for (const [k, v] of Object.entries(raw.file_map)) {
        if (typeof v !== "string" || v.length === 0 || v.length > 260) {
          addFieldError(errors, `${basePath}.file_map.${k}`);
        } else {
          try {
            fileMap[k] = assertSafeFilesystemPath(v, `${basePath}.file_map.${k}`);
          } catch {
            addFieldError(errors, `${basePath}.file_map.${k}`);
          }
        }
      }
    }
  }

  let region: string | undefined;
  if ("region" in raw) {
    region = expectNonEmptyString(raw, "region", basePath, errors, {
      pattern: /^[a-z]{2}-[a-z-]+-[0-9]+$/
    });
  }
  let secretPrefix: string | undefined;
  if ("secret_prefix" in raw) {
    secretPrefix = expectNonEmptyString(raw, "secret_prefix", basePath, errors, {
      maxLength: 128
    });
  }
  if (mode === "aws_secrets_manager" && (region === undefined || secretPrefix === undefined)) {
    addFieldError(errors, basePath, "MISSING_AWS_SECRET_PROVIDER_FIELDS");
  }

  if (profile === "portable_pglite" && mode !== "in_memory_test") {
    addFieldError(errors, `${basePath}.mode`, "PROFILE_INVARIANT");
  }
  if (
    profile === "development_trusted_local" &&
    mode !== "local_ipc" &&
    mode !== "local_ipc_provider"
  ) {
    addFieldError(errors, `${basePath}.mode`, "PROFILE_INVARIANT");
  }
  if (
    profile === "self_hosted" &&
    mode !== "env_file" &&
    mode !== "env_reference" &&
    mode !== "mounted_file"
  ) {
    addFieldError(errors, `${basePath}.mode`, "PROFILE_INVARIANT");
  }
  if (
    profile === "release" &&
    mode !== "env_file" &&
    mode !== "env_reference" &&
    mode !== "mounted_file" &&
    mode !== "aws_secrets_manager"
  ) {
    addFieldError(errors, `${basePath}.mode`, "PROFILE_INVARIANT");
  }

  return {
    mode,
    ...(ipc !== undefined ? { ipc } : {}),
    ...(envFile !== undefined ? { env_file: envFile } : {}),
    ...(secretsDir !== undefined ? { secrets_dir: secretsDir } : {}),
    ...(fileMap !== undefined ? { file_map: Object.freeze(fileMap) } : {}),
    ...(region !== undefined ? { region } : {}),
    ...(secretPrefix !== undefined ? { secret_prefix: secretPrefix } : {})
  };
}

function validateDatabaseConfig(
  raw: unknown,
  profile: ProfileKind,
  expectedRole: string,
  expectedSchema: "rq" | "rc" | "pi",
  allowedPoolModes: readonly DatabasePoolMode[],
  basePath: string,
  errors: DomainFieldError[]
): DatabaseConfig | undefined {
  if (!isPlainRecord(raw)) {
    addFieldError(errors, basePath);
    return undefined;
  }
  rejectUnknownKeys(
    raw,
    [
      "mode",
      "isolation",
      "host",
      "port",
      "name",
      "schema",
      "support_schema",
      "role",
      "authentication",
      "password_secret_ref",
      "tls_mode",
      "tls_ca_file",
      "pool_mode",
      "maximum_connections",
      "connection_timeout_ms",
      "statement_timeout_ms",
      "lock_timeout_ms"
    ],
    basePath,
    errors
  );

  const mode = expectNonEmptyString(raw, "mode", basePath, errors) as DatabaseMode;
  if (!DATABASE_MODES.includes(mode)) {
    addFieldError(errors, `${basePath}.mode`);
  }

  const isolation = expectNonEmptyString(raw, "isolation", basePath, errors) as
    | "separate_databases"
    | "shared_database_schemas";
  if (isolation !== "separate_databases" && isolation !== "shared_database_schemas") {
    addFieldError(errors, `${basePath}.isolation`);
  }

  const host = expectNonEmptyString(raw, "host", basePath, errors, { maxLength: 255 });
  if (POSTGRES_DSN_REGEX.test(host)) {
    addFieldError(errors, `${basePath}.host`, "EMBEDDED_DSN_FORBIDDEN");
  }

  const port = expectIntInRange(raw, "port", 0, 65535, basePath, errors);
  const name = expectNonEmptyString(raw, "name", basePath, errors, {
    pattern: /^[a-z][a-z0-9_]{1,62}$/
  });
  const schema = expectNonEmptyString(raw, "schema", basePath, errors) as "rq" | "rc" | "pi";
  if (schema !== expectedSchema) {
    addFieldError(errors, `${basePath}.schema`);
  }

  const supportSchema = expectNonEmptyString(raw, "support_schema", basePath, errors) as
    | "rq_support"
    | "extensions";
  if (supportSchema !== "rq_support" && supportSchema !== "extensions") {
    addFieldError(errors, `${basePath}.support_schema`);
  }

  const role = expectNonEmptyString(raw, "role", basePath, errors);
  if (role !== expectedRole) {
    addFieldError(errors, `${basePath}.role`, "ROLE_MISMATCH");
  }

  const authentication = expectNonEmptyString(
    raw,
    "authentication",
    basePath,
    errors
  ) as DatabaseAuthMode;
  if (!DATABASE_AUTH_MODES.includes(authentication)) {
    addFieldError(errors, `${basePath}.authentication`);
  }

  let passwordSecretRef: string | undefined;
  if ("password_secret_ref" in raw) {
    passwordSecretRef = expectSecretRef(raw, "password_secret_ref", basePath, errors);
  }

  const tlsMode = expectNonEmptyString(raw, "tls_mode", basePath, errors) as DatabaseTlsMode;
  if (!DATABASE_TLS_MODES.includes(tlsMode)) {
    addFieldError(errors, `${basePath}.tls_mode`);
  }

  let tlsCaFile: string | undefined;
  if ("tls_ca_file" in raw) {
    tlsCaFile = expectNonEmptyString(raw, "tls_ca_file", basePath, errors, { maxLength: 260 });
    if (tlsCaFile.length > 0) {
      try {
        assertSafeFilesystemPath(tlsCaFile, `${basePath}.tls_ca_file`);
      } catch {
        addFieldError(errors, `${basePath}.tls_ca_file`);
      }
    }
  }

  const poolMode = expectNonEmptyString(raw, "pool_mode", basePath, errors) as DatabasePoolMode;
  if (!allowedPoolModes.includes(poolMode)) {
    addFieldError(errors, `${basePath}.pool_mode`);
  }

  const maximumConnections = expectIntInRange(raw, "maximum_connections", 1, 128, basePath, errors);
  const connectionTimeoutMs = expectIntInRange(
    raw,
    "connection_timeout_ms",
    500,
    60000,
    basePath,
    errors
  );
  const statementTimeoutMs = expectIntInRange(
    raw,
    "statement_timeout_ms",
    500,
    300000,
    basePath,
    errors
  );
  const lockTimeoutMs = expectIntInRange(raw, "lock_timeout_ms", 100, 30000, basePath, errors);

  // Mode invariants
  if (mode === "portable_pglite") {
    if (
      authentication !== "in_process_pglite" ||
      tlsMode !== "in_process" ||
      poolMode !== "direct" ||
      port !== 0 ||
      maximumConnections !== 1 ||
      passwordSecretRef !== undefined
    ) {
      addFieldError(errors, basePath, "DB_MODE_INVARIANT");
    }
  } else if (mode === "development_trusted_local") {
    if (
      host !== "127.0.0.1" ||
      authentication !== "trusted_local_only" ||
      tlsMode !== "disabled_fixture" ||
      poolMode !== "direct" ||
      passwordSecretRef !== undefined
    ) {
      addFieldError(errors, basePath, "DB_MODE_INVARIANT");
    }
  } else if (mode === "hosted_neon") {
    if (
      passwordSecretRef === undefined ||
      authentication !== "secret_provider_password" ||
      tlsMode !== "verify_full" ||
      connectionTimeoutMs < 10000
    ) {
      addFieldError(errors, basePath, "DB_MODE_INVARIANT");
    }
  } else if (mode === "hosted_supabase") {
    if (
      passwordSecretRef === undefined ||
      isolation !== "shared_database_schemas" ||
      name !== "postgres" ||
      authentication !== "secret_provider_password" ||
      tlsMode !== "verify_full"
    ) {
      addFieldError(errors, basePath, "DB_MODE_INVARIANT");
    }
  } else if (mode === "standard_tls") {
    if (
      passwordSecretRef === undefined ||
      (authentication !== "secret_provider_password" && authentication !== "scram_sha_256") ||
      tlsMode !== "verify_full" ||
      (poolMode !== "direct" && poolMode !== "session_pooler")
    ) {
      addFieldError(errors, basePath, "DB_MODE_INVARIANT");
    }
  } else if (mode === "release_rds_iam") {
    if (
      authentication !== "aws_rds_iam_token" ||
      tlsMode !== "verify_full" ||
      (poolMode !== "direct" && poolMode !== "session_pooler") ||
      passwordSecretRef !== undefined
    ) {
      addFieldError(errors, basePath, "DB_MODE_INVARIANT");
    }
  }

  // Profile-to-database invariants
  if (profile === "portable_pglite" && mode !== "portable_pglite") {
    addFieldError(errors, `${basePath}.mode`, "PROFILE_INVARIANT");
  }
  if (profile === "development_trusted_local" && mode !== "development_trusted_local") {
    addFieldError(errors, `${basePath}.mode`, "PROFILE_INVARIANT");
  }
  if (profile === "hosted_neon" && mode !== "hosted_neon") {
    addFieldError(errors, `${basePath}.mode`, "PROFILE_INVARIANT");
  }
  if (profile === "hosted_supabase" && mode !== "hosted_supabase") {
    addFieldError(errors, `${basePath}.mode`, "PROFILE_INVARIANT");
  }
  if (profile === "hosted_synadia_ngs" && mode !== "hosted_neon" && mode !== "hosted_supabase") {
    addFieldError(errors, `${basePath}.mode`, "PROFILE_INVARIANT");
  }
  if (profile === "self_hosted" && (mode !== "standard_tls" || tlsMode !== "verify_full")) {
    addFieldError(errors, `${basePath}.mode`, "PROFILE_INVARIANT");
  }
  if (
    profile === "release" &&
    ((mode !== "standard_tls" && mode !== "release_rds_iam") || tlsMode !== "verify_full")
  ) {
    addFieldError(errors, `${basePath}.mode`, "PROFILE_INVARIANT");
  }

  return {
    mode,
    isolation,
    host,
    port,
    name,
    schema,
    support_schema: supportSchema,
    role,
    authentication,
    ...(passwordSecretRef !== undefined ? { password_secret_ref: passwordSecretRef } : {}),
    tls_mode: tlsMode,
    ...(tlsCaFile !== undefined ? { tls_ca_file: tlsCaFile } : {}),
    pool_mode: poolMode,
    maximum_connections: maximumConnections,
    connection_timeout_ms: connectionTimeoutMs,
    statement_timeout_ms: statementTimeoutMs,
    lock_timeout_ms: lockTimeoutMs
  };
}

function validateBrokerConfig(
  raw: unknown,
  profile: ProfileKind,
  basePath: string,
  errors: DomainFieldError[]
): BrokerConfig | undefined {
  if (!isPlainRecord(raw)) {
    addFieldError(errors, basePath);
    return undefined;
  }
  rejectUnknownKeys(
    raw,
    [
      "mode",
      "servers",
      "auth_mode",
      "secret_ref",
      "tls",
      "stream_name",
      "subject_prefix",
      "consumer_name",
      "replicas",
      "max_msgs",
      "max_bytes",
      "max_msg_size",
      "max_age_ns",
      "duplicate_window_ns",
      "inbox_prefix"
    ],
    basePath,
    errors
  );

  const mode = expectNonEmptyString(raw, "mode", basePath, errors) as BrokerMode;
  if (!BROKER_MODES.includes(mode)) {
    addFieldError(errors, `${basePath}.mode`);
  }

  const serversRaw = raw.servers;
  const servers: string[] = [];
  if (!Array.isArray(serversRaw) || serversRaw.length < 1 || serversRaw.length > 5) {
    addFieldError(errors, `${basePath}.servers`);
  } else {
    for (let i = 0; i < serversRaw.length; i += 1) {
      const s: unknown = serversRaw[i];
      if (typeof s !== "string" || s.length < 5 || s.length > 255) {
        addFieldError(errors, `${basePath}.servers[${i}]`);
      } else {
        servers.push(s);
      }
    }
  }

  const authMode = expectNonEmptyString(raw, "auth_mode", basePath, errors) as BrokerAuthMode;
  if (!BROKER_AUTH_MODES.includes(authMode)) {
    addFieldError(errors, `${basePath}.auth_mode`);
  }

  let secretRef: string | undefined;
  if ("secret_ref" in raw) {
    secretRef = expectSecretRef(raw, "secret_ref", basePath, errors);
  }

  let tls: BrokerTlsConfig | undefined;
  if ("tls" in raw) {
    if (!isPlainRecord(raw.tls)) {
      addFieldError(errors, `${basePath}.tls`);
    } else {
      rejectUnknownKeys(
        raw.tls,
        ["enabled", "handshake_first", "ca_file", "reject_unauthorized"],
        `${basePath}.tls`,
        errors
      );
      const enabled = expectBoolean(raw.tls, "enabled", `${basePath}.tls`, errors);
      let handshakeFirst: boolean | undefined;
      if ("handshake_first" in raw.tls) {
        handshakeFirst = expectBoolean(raw.tls, "handshake_first", `${basePath}.tls`, errors);
      }
      let caFile: string | undefined;
      if ("ca_file" in raw.tls) {
        caFile = expectNonEmptyString(raw.tls, "ca_file", `${basePath}.tls`, errors, {
          maxLength: 260
        });
        if (caFile.length > 0) {
          try {
            assertSafeFilesystemPath(caFile, `${basePath}.tls.ca_file`);
          } catch {
            addFieldError(errors, `${basePath}.tls.ca_file`);
          }
        }
      }
      const rejectUnauthorized = expectBoolean(
        raw.tls,
        "reject_unauthorized",
        `${basePath}.tls`,
        errors
      );
      if (!rejectUnauthorized) {
        addFieldError(errors, `${basePath}.tls.reject_unauthorized`);
      }
      tls = {
        enabled,
        ...(handshakeFirst !== undefined ? { handshake_first: handshakeFirst } : {}),
        ...(caFile !== undefined ? { ca_file: caFile } : {}),
        reject_unauthorized: true
      };
    }
  }

  const streamName = expectNonEmptyString(raw, "stream_name", basePath, errors, {
    pattern: /^[A-Z0-9_]{3,64}$/
  });
  const subjectPrefix =
    typeof raw.subject_prefix === "string" && /^([a-z0-9_-]+\.)*$/.test(raw.subject_prefix) && raw.subject_prefix.length <= 64
      ? raw.subject_prefix
      : (addFieldError(errors, `${basePath}.subject_prefix`), "");
  const consumerName = expectNonEmptyString(raw, "consumer_name", basePath, errors, {
    pattern: /^[A-Z0-9_]{3,64}$/
  });

  const replicasVal = raw.replicas;
  if (replicasVal !== 1 && replicasVal !== 3) {
    addFieldError(errors, `${basePath}.replicas`);
  }
  const replicas: 1 | 3 = replicasVal === 3 ? 3 : 1;

  const maxMsgs = expectIntInRange(raw, "max_msgs", 1000, 100000000, basePath, errors);
  const maxBytes = expectIntInRange(raw, "max_bytes", 1048576, 107374182400, basePath, errors);
  if (raw.max_msg_size !== 4096) {
    addFieldError(errors, `${basePath}.max_msg_size`);
  }
  const maxAgeNs = expectIntInRange(raw, "max_age_ns", 60000000000, 604800000000000, basePath, errors);
  if (raw.duplicate_window_ns !== 120000000000) {
    addFieldError(errors, `${basePath}.duplicate_window_ns`);
  }
  let inboxPrefix: string | undefined;
  if ("inbox_prefix" in raw) {
    inboxPrefix = expectNonEmptyString(raw, "inbox_prefix", basePath, errors, {
      pattern: /^_INBOX\.[a-z0-9._-]+$/
    });
  }

  // Broker mode invariants
  if (mode === "in_memory_test") {
    if (
      servers.length !== 1 ||
      servers[0] !== "in-memory" ||
      authMode !== "none_fixture" ||
      replicas !== 1 ||
      secretRef !== undefined
    ) {
      addFieldError(errors, basePath, "BROKER_MODE_INVARIANT");
    }
  } else if (mode === "development_loopback") {
    if (
      servers.some((s) => !/^nats:\/\/127\.0\.0\.1:[0-9]{1,5}$/.test(s)) ||
      authMode !== "none_fixture" ||
      replicas !== 1 ||
      secretRef !== undefined
    ) {
      addFieldError(errors, basePath, "BROKER_MODE_INVARIANT");
    }
  } else if (mode === "embedded_go_tls") {
    if (
      tls === undefined ||
      !tls.enabled ||
      tls.handshake_first !== true ||
      replicas !== 1 ||
      (authMode !== "none_fixture" && authMode !== "nkey_seed") ||
      servers.some((s) => !/^tls:\/\/127\.0\.0\.1:[0-9]{1,5}$/.test(s))
    ) {
      addFieldError(errors, basePath, "BROKER_MODE_INVARIANT");
    }
  } else if (mode === "hosted_synadia_ngs") {
    if (
      secretRef === undefined ||
      tls === undefined ||
      !tls.enabled ||
      tls.handshake_first !== false ||
      authMode !== "synadia_creds_jwt" ||
      servers.some((s) => !/^tls:\/\/[a-z0-9.-]+(:[0-9]{1,5})?$/.test(s))
    ) {
      addFieldError(errors, basePath, "BROKER_MODE_INVARIANT");
    }
  } else if (mode === "standard_tls" || mode === "self_hosted") {
    if (
      secretRef === undefined ||
      tls === undefined ||
      !tls.enabled ||
      tls.handshake_first !== true ||
      tls.ca_file === undefined ||
      authMode !== "nkey_seed" ||
      servers.some((s) => !/^tls:\/\/(?!127\.0\.0\.1|localhost)[a-z0-9.-]+(:[0-9]{1,5})?$/.test(s))
    ) {
      addFieldError(errors, basePath, "BROKER_MODE_INVARIANT");
    }
  } else if (mode === "release_native_tls") {
    if (
      secretRef === undefined ||
      tls === undefined ||
      !tls.enabled ||
      tls.handshake_first !== true ||
      tls.ca_file === undefined ||
      authMode !== "nkey_seed" ||
      replicas !== 3 ||
      servers.length < 3 ||
      servers.some((s) => !/^tls:\/\/(?!127\.0\.0\.1|localhost)[a-z0-9.-]+:[0-9]{1,5}$/.test(s))
    ) {
      addFieldError(errors, basePath, "BROKER_MODE_INVARIANT");
    }
  }

  // Profile-to-broker invariants
  if (profile === "portable_pglite" && mode !== "in_memory_test" && mode !== "embedded_go_tls") {
    addFieldError(errors, `${basePath}.mode`, "PROFILE_INVARIANT");
  }
  if (
    profile === "development_trusted_local" &&
    mode !== "embedded_go_tls" &&
    mode !== "development_loopback"
  ) {
    addFieldError(errors, `${basePath}.mode`, "PROFILE_INVARIANT");
  }
  if (
    (profile === "hosted_neon" ||
      profile === "hosted_supabase" ||
      profile === "hosted_synadia_ngs") &&
    mode !== "hosted_synadia_ngs"
  ) {
    addFieldError(errors, `${basePath}.mode`, "PROFILE_INVARIANT");
  }
  if (profile === "self_hosted" && mode !== "standard_tls" && mode !== "self_hosted") {
    addFieldError(errors, `${basePath}.mode`, "PROFILE_INVARIANT");
  }
  if (
    profile === "release" &&
    mode !== "standard_tls" &&
    mode !== "self_hosted" &&
    mode !== "release_native_tls"
  ) {
    addFieldError(errors, `${basePath}.mode`, "PROFILE_INVARIANT");
  }

  return {
    mode,
    servers: Object.freeze(servers),
    auth_mode: authMode,
    ...(secretRef !== undefined ? { secret_ref: secretRef } : {}),
    ...(tls !== undefined ? { tls } : {}),
    stream_name: streamName,
    subject_prefix: subjectPrefix,
    consumer_name: consumerName,
    replicas,
    max_msgs: maxMsgs,
    max_bytes: maxBytes,
    max_msg_size: 4096,
    max_age_ns: maxAgeNs,
    duplicate_window_ns: 120000000000,
    ...(inboxPrefix !== undefined ? { inbox_prefix: inboxPrefix } : {})
  };
}

function validateProtocolConfig(
  raw: unknown,
  basePath: string,
  errors: DomainFieldError[]
): ProtocolConfig | undefined {
  if (!isPlainRecord(raw)) {
    addFieldError(errors, basePath);
    return undefined;
  }
  rejectUnknownKeys(
    raw,
    ["http_schema_version", "broker_envelope_version", "webhook_signature_version"],
    basePath,
    errors
  );
  if (raw.http_schema_version !== 1) {
    addFieldError(errors, `${basePath}.http_schema_version`);
  }
  if (raw.broker_envelope_version !== 1) {
    addFieldError(errors, `${basePath}.broker_envelope_version`);
  }
  if (raw.webhook_signature_version !== 1) {
    addFieldError(errors, `${basePath}.webhook_signature_version`);
  }
  return {
    http_schema_version: 1,
    broker_envelope_version: 1,
    webhook_signature_version: 1
  };
}

function validateTelemetryConfig(
  raw: unknown,
  profile: ProfileKind,
  basePath: string,
  errors: DomainFieldError[]
): TelemetryConfig | undefined {
  if (!isPlainRecord(raw)) {
    addFieldError(errors, basePath);
    return undefined;
  }
  rejectUnknownKeys(
    raw,
    [
      "enabled",
      "service_name",
      "otlp_endpoint",
      "max_queue_size",
      "max_export_batch_size",
      "trace_view_origin"
    ],
    basePath,
    errors
  );
  const enabled = expectBoolean(raw, "enabled", basePath, errors);
  const serviceName = expectNonEmptyString(raw, "service_name", basePath, errors, {
    maxLength: 128
  });
  let otlpEndpoint: string | undefined;
  if ("otlp_endpoint" in raw) {
    otlpEndpoint = expectNonEmptyString(raw, "otlp_endpoint", basePath, errors, {
      pattern: /^https?:\/\//
    });
  }
  if (raw.max_queue_size !== 2048) {
    addFieldError(errors, `${basePath}.max_queue_size`);
  }
  if (raw.max_export_batch_size !== 256) {
    addFieldError(errors, `${basePath}.max_export_batch_size`);
  }
  let traceViewOrigin: string | undefined;
  if ("trace_view_origin" in raw) {
    traceViewOrigin = expectNonEmptyString(raw, "trace_view_origin", basePath, errors, {
      pattern: isProductionProfile(profile) ? /^https:\/\// : /^https?:\/\//
    });
  }
  return {
    enabled,
    service_name: serviceName,
    ...(otlpEndpoint !== undefined ? { otlp_endpoint: otlpEndpoint } : {}),
    max_queue_size: 2048,
    max_export_batch_size: 256,
    ...(traceViewOrigin !== undefined ? { trace_view_origin: traceViewOrigin } : {})
  };
}

function validateHttpBindConfig(
  raw: unknown,
  basePath: string,
  errors: DomainFieldError[]
): HttpBindConfig | undefined {
  if (!isPlainRecord(raw)) {
    addFieldError(errors, basePath);
    return undefined;
  }
  rejectUnknownKeys(raw, ["host", "port", "trust_proxy"], basePath, errors);
  const host = expectNonEmptyString(raw, "host", basePath, errors, { maxLength: 255 });
  const port = expectIntInRange(raw, "port", 0, 65535, basePath, errors);
  let trustProxy: boolean | undefined;
  if ("trust_proxy" in raw) {
    trustProxy = expectBoolean(raw, "trust_proxy", basePath, errors);
  }
  return {
    host,
    port,
    ...(trustProxy !== undefined ? { trust_proxy: trustProxy } : {})
  };
}

function validateHttpConfig(
  raw: unknown,
  profile: ProfileKind,
  basePath: string,
  errors: DomainFieldError[]
): HttpConfig | undefined {
  if (!isPlainRecord(raw)) {
    addFieldError(errors, basePath);
    return undefined;
  }
  rejectUnknownKeys(
    raw,
    ["host", "port", "public_origin", "trust_proxy", "sse_heartbeat_ms", "sse_max_lifetime_ms"],
    basePath,
    errors
  );
  const host = expectNonEmptyString(raw, "host", basePath, errors, { maxLength: 255 });
  const port = expectIntInRange(raw, "port", 0, 65535, basePath, errors);
  const publicOrigin = expectNonEmptyString(raw, "public_origin", basePath, errors, {
    pattern: isProductionProfile(profile) ? /^https:\/\// : /^https?:\/\//
  });
  if (isProductionProfile(profile) && publicOrigin.includes("receiver.fixture.test")) {
    addFieldError(errors, `${basePath}.public_origin`, "FIXTURE_FORBIDDEN");
  }
  let trustProxy: boolean | undefined;
  if ("trust_proxy" in raw) {
    trustProxy = expectBoolean(raw, "trust_proxy", basePath, errors);
  }
  const sseHeartbeatMs = expectIntInRange(raw, "sse_heartbeat_ms", 1000, 60000, basePath, errors);
  const sseMaxLifetimeMs = expectIntInRange(
    raw,
    "sse_max_lifetime_ms",
    5000,
    3600000,
    basePath,
    errors
  );
  return {
    host,
    port,
    public_origin: publicOrigin,
    ...(trustProxy !== undefined ? { trust_proxy: trustProxy } : {}),
    sse_heartbeat_ms: sseHeartbeatMs,
    sse_max_lifetime_ms: sseMaxLifetimeMs
  };
}

function validateAuthConfig(
  raw: unknown,
  profile: ProfileKind,
  basePath: string,
  errors: DomainFieldError[]
): AuthConfig | undefined {
  if (!isPlainRecord(raw)) {
    addFieldError(errors, basePath);
    return undefined;
  }
  rejectUnknownKeys(raw, ["rp_id", "allowed_origins", "cookie_profile"], basePath, errors);
  const rpId = expectNonEmptyString(raw, "rp_id", basePath, errors, { maxLength: 255 });
  const originsRaw = raw.allowed_origins;
  const allowedOrigins: string[] = [];
  if (!Array.isArray(originsRaw) || originsRaw.length < 1) {
    addFieldError(errors, `${basePath}.allowed_origins`);
  } else {
    const originPattern = isProductionProfile(profile) ? /^https:\/\// : /^https?:\/\//;
    for (let i = 0; i < originsRaw.length; i += 1) {
      const origin: unknown = originsRaw[i];
      if (typeof origin !== "string" || !originPattern.test(origin)) {
        addFieldError(errors, `${basePath}.allowed_origins[${i}]`);
      } else {
        if (isProductionProfile(profile) && origin.includes("receiver.fixture.test")) {
          addFieldError(errors, `${basePath}.allowed_origins[${i}]`, "FIXTURE_FORBIDDEN");
        }
        allowedOrigins.push(origin);
      }
    }
  }
  const cookieProfile = expectNonEmptyString(raw, "cookie_profile", basePath, errors) as
    | "development_only"
    | "release_https";
  if (cookieProfile !== "development_only" && cookieProfile !== "release_https") {
    addFieldError(errors, `${basePath}.cookie_profile`);
  }
  if (
    (profile === "portable_pglite" || profile === "development_trusted_local") &&
    cookieProfile !== "development_only"
  ) {
    addFieldError(errors, `${basePath}.cookie_profile`, "PROFILE_INVARIANT");
  }
  if (
    (isProductionProfile(profile) ||
      profile === "hosted_neon" ||
      profile === "hosted_supabase" ||
      profile === "hosted_synadia_ngs") &&
    cookieProfile !== "release_https"
  ) {
    addFieldError(errors, `${basePath}.cookie_profile`, "PROFILE_INVARIANT");
  }

  return {
    rp_id: rpId,
    allowed_origins: Object.freeze(allowedOrigins),
    cookie_profile: cookieProfile
  };
}

function validateEgressConfig(
  raw: unknown,
  profile: ProfileKind,
  basePath: string,
  errors: DomainFieldError[]
): EgressConfig | undefined {
  if (!isPlainRecord(raw)) {
    addFieldError(errors, basePath);
    return undefined;
  }
  rejectUnknownKeys(
    raw,
    [
      "mode",
      "allow_fixture_receiver",
      "fixture_receiver_authority",
      "fixture_receiver_path",
      "fixture_resolve_ip"
    ],
    basePath,
    errors
  );
  const mode = expectNonEmptyString(raw, "mode", basePath, errors) as
    | "trusted_local_fixture"
    | "strict_public_https";
  if (mode !== "trusted_local_fixture" && mode !== "strict_public_https") {
    addFieldError(errors, `${basePath}.mode`);
  }
  const allowFixture = expectBoolean(raw, "allow_fixture_receiver", basePath, errors);
  let authority: string | undefined;
  if ("fixture_receiver_authority" in raw) {
    authority = expectNonEmptyString(raw, "fixture_receiver_authority", basePath, errors, {
      minLength: 3,
      maxLength: 255
    });
  }
  let fixturePath: string | undefined;
  if ("fixture_receiver_path" in raw) {
    fixturePath = expectNonEmptyString(raw, "fixture_receiver_path", basePath, errors, {
      pattern: /^\//
    });
  }
  let resolveIp: "127.0.0.1" | undefined;
  if ("fixture_resolve_ip" in raw) {
    if (raw.fixture_resolve_ip !== "127.0.0.1") {
      addFieldError(errors, `${basePath}.fixture_resolve_ip`);
    } else {
      resolveIp = "127.0.0.1";
    }
  }
  if (allowFixture) {
    if (
      mode !== "trusted_local_fixture" ||
      authority === undefined ||
      fixturePath === undefined ||
      resolveIp === undefined
    ) {
      addFieldError(errors, basePath, "EGRESS_FIXTURE_INCOMPLETE");
    }
  }
  if (isProductionProfile(profile)) {
    if (
      mode !== "strict_public_https" ||
      allowFixture ||
      (authority !== undefined && authority.includes("receiver.fixture.test"))
    ) {
      addFieldError(errors, basePath, "FIXTURE_FORBIDDEN_IN_PRODUCTION");
    }
  }

  return {
    mode,
    allow_fixture_receiver: allowFixture,
    ...(authority !== undefined ? { fixture_receiver_authority: authority } : {}),
    ...(fixturePath !== undefined ? { fixture_receiver_path: fixturePath } : {}),
    ...(resolveIp !== undefined ? { fixture_resolve_ip: resolveIp } : {})
  };
}

function validateApiTargetConfig(
  raw: unknown,
  profile: ProfileKind,
  basePath: string,
  errors: DomainFieldError[]
): ApiTargetConfig | undefined {
  if (!isPlainRecord(raw)) {
    addFieldError(errors, basePath);
    return undefined;
  }
  rejectUnknownKeys(raw, ["origin", "project_id", "credential_secret_ref"], basePath, errors);
  const origin = expectNonEmptyString(raw, "origin", basePath, errors, {
    pattern: isProductionProfile(profile) ? /^https:\/\// : /^https?:\/\//
  });
  if (isProductionProfile(profile) && origin.includes("receiver.fixture.test")) {
    addFieldError(errors, `${basePath}.origin`, "FIXTURE_FORBIDDEN");
  }
  const projectId = expectNonEmptyString(raw, "project_id", basePath, errors, { maxLength: 128 });
  const credRef = expectSecretRef(raw, "credential_secret_ref", basePath, errors);
  return {
    origin,
    project_id: projectId,
    credential_secret_ref: credRef
  };
}

export function validateRoleConfig(
  raw: unknown,
  options: ValidateRoleConfigOptions = {}
): RoleConfig {
  if (!isPlainRecord(raw)) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: "Role configuration must be a JSON object"
    });
  }

  const errors: DomainFieldError[] = [];
  scanDisallowedStringsAndKeys(raw, "$", errors);

  if ("$schema" in raw && (typeof raw.$schema !== "string" || raw.$schema.length === 0)) {
    addFieldError(errors, "$.$schema");
  }
  if (raw.schema_version !== 1) {
    addFieldError(errors, "$.schema_version");
  }

  const profile = expectNonEmptyString(raw, "profile", "$", errors) as ProfileKind;
  if (!PROFILE_KINDS.includes(profile)) {
    addFieldError(errors, "$.profile");
  }
  const processRole = expectNonEmptyString(raw, "process_role", "$", errors) as ConfigProcessRole;
  if (!CONFIG_PROCESS_ROLES.includes(processRole)) {
    addFieldError(errors, "$.process_role");
  }

  if (options.expectedProcessRole !== undefined && processRole !== options.expectedProcessRole) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Expected process_role "${options.expectedProcessRole}", got "${processRole}"`,
      fieldErrors: [{ path: "$.process_role", code: "ROLE_MISMATCH" }]
    });
  }

  if (options.expectedCommandRole !== undefined) {
    const actualCmdRole = typeof raw.command_role === "string" ? raw.command_role : "";
    if (actualCmdRole !== options.expectedCommandRole) {
      throw new ValidationDomainError({
        code: "INVALID_VALUE",
        message: `Expected command_role "${options.expectedCommandRole}", got "${actualCmdRole}"`,
        fieldErrors: [{ path: "$.command_role", code: "ROLE_MISMATCH" }]
      });
    }
  }

  const schemaField = typeof raw.$schema === "string" ? { $schema: raw.$schema } : {};
  let parsedConfig: RoleConfig | undefined;

  switch (processRole) {
    case "api": {
      rejectUnknownKeys(
        raw,
        [
          "$schema",
          "schema_version",
          "profile",
          "process_role",
          "http",
          "database",
          "auth",
          "secret_provider",
          "operator_channel",
          "telemetry",
          "protocol"
        ],
        "$",
        errors
      );
      const http = validateHttpConfig(raw.http, profile, "$.http", errors);
      const database = validateDatabaseConfig(
        raw.database,
        profile,
        "rq_api",
        "rq",
        DATABASE_POOL_MODES,
        "$.database",
        errors
      );
      const auth = validateAuthConfig(raw.auth, profile, "$.auth", errors);
      const secretProvider = validateSecretProvider(
        raw.secret_provider,
        profile,
        "$.secret_provider",
        errors
      );
      const operatorChannel =
        "operator_channel" in raw
          ? validateIpcChannelRef(raw.operator_channel, "$.operator_channel", errors)
          : undefined;
      const telemetry =
        "telemetry" in raw
          ? validateTelemetryConfig(raw.telemetry, profile, "$.telemetry", errors)
          : undefined;
      const protocol = validateProtocolConfig(raw.protocol, "$.protocol", errors);
      if (http && database && auth && secretProvider && protocol) {
        parsedConfig = {
          ...schemaField,
          schema_version: 1,
          profile,
          process_role: "api",
          http,
          database,
          auth,
          secret_provider: secretProvider,
          ...(operatorChannel !== undefined ? { operator_channel: operatorChannel } : {}),
          ...(telemetry !== undefined ? { telemetry } : {}),
          protocol
        };
      }
      break;
    }

    case "relay": {
      rejectUnknownKeys(
        raw,
        [
          "$schema",
          "schema_version",
          "profile",
          "process_role",
          "database",
          "broker",
          "relay",
          "telemetry",
          "protocol"
        ],
        "$",
        errors
      );
      const database = validateDatabaseConfig(
        raw.database,
        profile,
        "rq_relay",
        "rq",
        ["direct", "session_pooler"],
        "$.database",
        errors
      );
      const broker = validateBrokerConfig(raw.broker, profile, "$.broker", errors);
      let relay: RelaySettings | undefined;
      if (!isPlainRecord(raw.relay)) {
        addFieldError(errors, "$.relay");
      } else {
        rejectUnknownKeys(
          raw.relay,
          [
            "poll_interval_ms",
            "batch_size",
            "claim_lease_ms",
            "publish_concurrency",
            "publish_timeout_ms"
          ],
          "$.relay",
          errors
        );
        relay = {
          poll_interval_ms: expectIntInRange(raw.relay, "poll_interval_ms", 10, 60000, "$.relay", errors),
          batch_size: expectIntInRange(raw.relay, "batch_size", 1, 256, "$.relay", errors),
          claim_lease_ms: expectIntInRange(raw.relay, "claim_lease_ms", 1000, 300000, "$.relay", errors),
          publish_concurrency: expectIntInRange(
            raw.relay,
            "publish_concurrency",
            1,
            128,
            "$.relay",
            errors
          ),
          publish_timeout_ms: expectIntInRange(
            raw.relay,
            "publish_timeout_ms",
            250,
            60000,
            "$.relay",
            errors
          )
        };
      }
      const telemetry =
        "telemetry" in raw
          ? validateTelemetryConfig(raw.telemetry, profile, "$.telemetry", errors)
          : undefined;
      const protocol = validateProtocolConfig(raw.protocol, "$.protocol", errors);
      if (database && broker && relay && protocol) {
        parsedConfig = {
          ...schemaField,
          schema_version: 1,
          profile,
          process_role: "relay",
          database,
          broker,
          relay,
          ...(telemetry !== undefined ? { telemetry } : {}),
          protocol
        };
      }
      break;
    }

    case "fanout": {
      rejectUnknownKeys(
        raw,
        [
          "$schema",
          "schema_version",
          "profile",
          "process_role",
          "database",
          "broker",
          "fanout",
          "telemetry",
          "protocol"
        ],
        "$",
        errors
      );
      const database = validateDatabaseConfig(
        raw.database,
        profile,
        "rq_fanout",
        "rq",
        ["direct", "session_pooler"],
        "$.database",
        errors
      );
      const broker = validateBrokerConfig(raw.broker, profile, "$.broker", errors);
      let fanout: FanoutSettings | undefined;
      if (!isPlainRecord(raw.fanout)) {
        addFieldError(errors, "$.fanout");
      } else {
        rejectUnknownKeys(
          raw.fanout,
          ["ack_wait_ms", "max_deliver", "max_ack_pending", "max_batch", "max_bytes", "max_expires_ms"],
          "$.fanout",
          errors
        );
        fanout = {
          ack_wait_ms: expectIntInRange(raw.fanout, "ack_wait_ms", 1000, 300000, "$.fanout", errors),
          max_deliver: expectIntInRange(raw.fanout, "max_deliver", 1, 100, "$.fanout", errors),
          max_ack_pending: expectIntInRange(
            raw.fanout,
            "max_ack_pending",
            1,
            4096,
            "$.fanout",
            errors
          ),
          max_batch: expectIntInRange(raw.fanout, "max_batch", 1, 256, "$.fanout", errors),
          max_bytes: expectIntInRange(raw.fanout, "max_bytes", 4096, 16777216, "$.fanout", errors),
          max_expires_ms: expectIntInRange(raw.fanout, "max_expires_ms", 500, 60000, "$.fanout", errors)
        };
      }
      const telemetry =
        "telemetry" in raw
          ? validateTelemetryConfig(raw.telemetry, profile, "$.telemetry", errors)
          : undefined;
      const protocol = validateProtocolConfig(raw.protocol, "$.protocol", errors);
      if (database && broker && fanout && protocol) {
        parsedConfig = {
          ...schemaField,
          schema_version: 1,
          profile,
          process_role: "fanout",
          database,
          broker,
          fanout,
          ...(telemetry !== undefined ? { telemetry } : {}),
          protocol
        };
      }
      break;
    }

    case "sender": {
      rejectUnknownKeys(
        raw,
        [
          "$schema",
          "schema_version",
          "profile",
          "process_role",
          "database",
          "secret_provider",
          "sender",
          "egress",
          "telemetry",
          "protocol"
        ],
        "$",
        errors
      );
      const database = validateDatabaseConfig(
        raw.database,
        profile,
        "rq_sender",
        "rq",
        ["direct", "session_pooler"],
        "$.database",
        errors
      );
      const secretProvider = validateSecretProvider(
        raw.secret_provider,
        profile,
        "$.secret_provider",
        errors
      );
      let sender: SenderSettings | undefined;
      if (!isPlainRecord(raw.sender)) {
        addFieldError(errors, "$.sender");
      } else {
        rejectUnknownKeys(
          raw.sender,
          [
            "dispatch_domain",
            "approved_slots",
            "poll_interval_ms",
            "request_timeout_ms",
            "max_response_bytes"
          ],
          "$.sender",
          errors
        );
        sender = {
          dispatch_domain: expectNonEmptyString(raw.sender, "dispatch_domain", "$.sender", errors, {
            maxLength: 64
          }),
          approved_slots: expectIntInRange(raw.sender, "approved_slots", 1, 128, "$.sender", errors),
          poll_interval_ms: expectIntInRange(
            raw.sender,
            "poll_interval_ms",
            10,
            60000,
            "$.sender",
            errors
          ),
          request_timeout_ms: expectIntInRange(
            raw.sender,
            "request_timeout_ms",
            500,
            60000,
            "$.sender",
            errors
          ),
          max_response_bytes: expectIntInRange(
            raw.sender,
            "max_response_bytes",
            1024,
            1048576,
            "$.sender",
            errors
          )
        };
      }
      const egress = validateEgressConfig(raw.egress, profile, "$.egress", errors);
      const telemetry =
        "telemetry" in raw
          ? validateTelemetryConfig(raw.telemetry, profile, "$.telemetry", errors)
          : undefined;
      const protocol = validateProtocolConfig(raw.protocol, "$.protocol", errors);
      if (database && secretProvider && sender && egress && protocol) {
        parsedConfig = {
          ...schemaField,
          schema_version: 1,
          profile,
          process_role: "sender",
          database,
          secret_provider: secretProvider,
          sender,
          egress,
          ...(telemetry !== undefined ? { telemetry } : {}),
          protocol
        };
      }
      break;
    }

    case "coordinator": {
      rejectUnknownKeys(
        raw,
        [
          "$schema",
          "schema_version",
          "profile",
          "process_role",
          "database",
          "coordinator",
          "telemetry",
          "protocol"
        ],
        "$",
        errors
      );
      const database = validateDatabaseConfig(
        raw.database,
        profile,
        "rq_coordinator",
        "rq",
        ["direct", "session_pooler"],
        "$.database",
        errors
      );
      let coordinator: CoordinatorSettings | undefined;
      if (!isPlainRecord(raw.coordinator)) {
        addFieldError(errors, "$.coordinator");
      } else {
        rejectUnknownKeys(
          raw.coordinator,
          ["loop_interval_ms", "reaper_batch_size", "retention_batch_size", "projection_batch_size"],
          "$.coordinator",
          errors
        );
        coordinator = {
          loop_interval_ms: expectIntInRange(
            raw.coordinator,
            "loop_interval_ms",
            100,
            300000,
            "$.coordinator",
            errors
          ),
          reaper_batch_size: expectIntInRange(
            raw.coordinator,
            "reaper_batch_size",
            1,
            1000,
            "$.coordinator",
            errors
          ),
          retention_batch_size: expectIntInRange(
            raw.coordinator,
            "retention_batch_size",
            1,
            1000,
            "$.coordinator",
            errors
          ),
          projection_batch_size: expectIntInRange(
            raw.coordinator,
            "projection_batch_size",
            1,
            1000,
            "$.coordinator",
            errors
          )
        };
      }
      const telemetry =
        "telemetry" in raw
          ? validateTelemetryConfig(raw.telemetry, profile, "$.telemetry", errors)
          : undefined;
      const protocol = validateProtocolConfig(raw.protocol, "$.protocol", errors);
      if (database && coordinator && protocol) {
        parsedConfig = {
          ...schemaField,
          schema_version: 1,
          profile,
          process_role: "coordinator",
          database,
          coordinator,
          ...(telemetry !== undefined ? { telemetry } : {}),
          protocol
        };
      }
      break;
    }

    case "admin": {
      const commandRole = expectNonEmptyString(raw, "command_role", "$", errors);
      switch (commandRole) {
        case "db_and_broker_admin": {
          rejectUnknownKeys(
            raw,
            [
              "$schema",
              "schema_version",
              "profile",
              "process_role",
              "command_role",
              "database",
              "broker",
              "migrations_dir",
              "protocol"
            ],
            "$",
            errors
          );
          const database = validateDatabaseConfig(
            raw.database,
            profile,
            "rq_migrator",
            "rq",
            ["direct", "session_pooler"],
            "$.database",
            errors
          );
          const broker = validateBrokerConfig(raw.broker, profile, "$.broker", errors);
          const migrationsDir = expectRepoRelativePath(raw, "migrations_dir", "$", errors);
          const protocol = validateProtocolConfig(raw.protocol, "$.protocol", errors);
          if (database && broker && protocol) {
            parsedConfig = {
              ...schemaField,
              schema_version: 1,
              profile,
              process_role: "admin",
              command_role: "db_and_broker_admin",
              database,
              broker,
              migrations_dir: migrationsDir,
              protocol
            };
          }
          break;
        }

        case "signing_issuer": {
          rejectUnknownKeys(
            raw,
            [
              "$schema",
              "schema_version",
              "profile",
              "process_role",
              "command_role",
              "database",
              "secret_provider",
              "protocol"
            ],
            "$",
            errors
          );
          const database = validateDatabaseConfig(
            raw.database,
            profile,
            "rq_signing_issuer",
            "rq",
            ["direct", "session_pooler"],
            "$.database",
            errors
          );
          const secretProvider = validateSecretProvider(
            raw.secret_provider,
            profile,
            "$.secret_provider",
            errors
          );
          const protocol = validateProtocolConfig(raw.protocol, "$.protocol", errors);
          if (database && secretProvider && protocol) {
            parsedConfig = {
              ...schemaField,
              schema_version: 1,
              profile,
              process_role: "admin",
              command_role: "signing_issuer",
              database,
              secret_provider: secretProvider,
              protocol
            };
          }
          break;
        }

        case "fixture_provider": {
          rejectUnknownKeys(
            raw,
            ["$schema", "schema_version", "profile", "process_role", "command_role", "ipc", "provider"],
            "$",
            errors
          );
          if (profile !== "portable_pglite" && profile !== "development_trusted_local") {
            addFieldError(errors, "$.profile", "FIXTURE_FORBIDDEN");
          }
          const ipc = validateIpcChannelRef(raw.ipc, "$.ipc", errors);
          let provider: ProviderSettings | undefined;
          if (!isPlainRecord(raw.provider)) {
            addFieldError(errors, "$.provider");
          } else {
            rejectUnknownKeys(
              raw.provider,
              ["max_entries", "max_entry_bytes", "custody_snapshot_enabled", "custody_snapshot_path"],
              "$.provider",
              errors
            );
            const maxEntries = expectIntInRange(
              raw.provider,
              "max_entries",
              1,
              65536,
              "$.provider",
              errors
            );
            const maxEntryBytes = expectIntInRange(
              raw.provider,
              "max_entry_bytes",
              64,
              65536,
              "$.provider",
              errors
            );
            const custodySnapshotEnabled = expectBoolean(
              raw.provider,
              "custody_snapshot_enabled",
              "$.provider",
              errors
            );
            if (isProductionProfile(profile) && custodySnapshotEnabled) {
              addFieldError(errors, "$.provider.custody_snapshot_enabled", "FIXTURE_FORBIDDEN");
            }
            let custodySnapshotPath: string | undefined;
            if ("custody_snapshot_path" in raw.provider) {
              custodySnapshotPath = expectRepoRelativePath(
                raw.provider,
                "custody_snapshot_path",
                "$.provider",
                errors
              );
            }
            provider = {
              max_entries: maxEntries,
              max_entry_bytes: maxEntryBytes,
              custody_snapshot_enabled: custodySnapshotEnabled,
              ...(custodySnapshotPath !== undefined
                ? { custody_snapshot_path: custodySnapshotPath }
                : {})
            };
          }
          if (ipc && provider) {
            parsedConfig = {
              ...schemaField,
              schema_version: 1,
              profile,
              process_role: "admin",
              command_role: "fixture_provider",
              ipc,
              provider
            };
          }
          break;
        }

        case "bootstrap_operator": {
          rejectUnknownKeys(
            raw,
            ["$schema", "schema_version", "profile", "process_role", "command_role", "operator_channel"],
            "$",
            errors
          );
          const operatorChannel = validateIpcChannelRef(
            raw.operator_channel,
            "$.operator_channel",
            errors
          );
          if (operatorChannel) {
            parsedConfig = {
              ...schemaField,
              schema_version: 1,
              profile,
              process_role: "admin",
              command_role: "bootstrap_operator",
              operator_channel: operatorChannel
            };
          }
          break;
        }

        case "recovery_operator":
        case "recovery_reviewer": {
          rejectUnknownKeys(
            raw,
            [
              "$schema",
              "schema_version",
              "profile",
              "process_role",
              "command_role",
              "database",
              "operator_channel",
              "recovery"
            ],
            "$",
            errors
          );
          const database =
            "database" in raw
              ? validateDatabaseConfig(
                  raw.database,
                  profile,
                  "rq_recovery",
                  "rq",
                  DATABASE_POOL_MODES,
                  "$.database",
                  errors
                )
              : undefined;
          const operatorChannel =
            "operator_channel" in raw
              ? validateIpcChannelRef(raw.operator_channel, "$.operator_channel", errors)
              : undefined;
          let recovery: RecoverySettings | undefined;
          if (!isPlainRecord(raw.recovery)) {
            addFieldError(errors, "$.recovery");
          } else {
            rejectUnknownKeys(
              raw.recovery,
              ["actor_role", "plan_dir", "require_two_person_review", "target_schema_revision"],
              "$.recovery",
              errors
            );
            const actorRole = expectNonEmptyString(raw.recovery, "actor_role", "$.recovery", errors) as
              | "operator"
              | "reviewer";
            const expectedActor = commandRole === "recovery_operator" ? "operator" : "reviewer";
            if (actorRole !== expectedActor) {
              addFieldError(errors, "$.recovery.actor_role", "ROLE_MISMATCH");
            }
            const planDir = expectRepoRelativePath(raw.recovery, "plan_dir", "$.recovery", errors);
            const requireTwoPerson = expectBoolean(
              raw.recovery,
              "require_two_person_review",
              "$.recovery",
              errors
            );
            let targetRev: string | undefined;
            if ("target_schema_revision" in raw.recovery) {
              targetRev = expectNonEmptyString(
                raw.recovery,
                "target_schema_revision",
                "$.recovery",
                errors,
                { maxLength: 64 }
              );
            }
            recovery = {
              actor_role: actorRole,
              plan_dir: planDir,
              require_two_person_review: requireTwoPerson,
              ...(targetRev !== undefined ? { target_schema_revision: targetRev } : {})
            };
          }
          if (recovery) {
            parsedConfig = {
              ...schemaField,
              schema_version: 1,
              profile,
              process_role: "admin",
              command_role: commandRole,
              ...(database !== undefined ? { database } : {}),
              ...(operatorChannel !== undefined ? { operator_channel: operatorChannel } : {}),
              recovery
            };
          }
          break;
        }

        case "diagnostics_operator": {
          rejectUnknownKeys(
            raw,
            [
              "$schema",
              "schema_version",
              "profile",
              "process_role",
              "command_role",
              "database",
              "operator_channel",
              "diagnostics"
            ],
            "$",
            errors
          );
          const database =
            "database" in raw
              ? validateDatabaseConfig(
                  raw.database,
                  profile,
                  "rq_reporter",
                  "rq",
                  DATABASE_POOL_MODES,
                  "$.database",
                  errors
                )
              : undefined;
          const operatorChannel =
            "operator_channel" in raw
              ? validateIpcChannelRef(raw.operator_channel, "$.operator_channel", errors)
              : undefined;
          let diagnostics: DiagnosticsSettings | undefined;
          if (!isPlainRecord(raw.diagnostics)) {
            addFieldError(errors, "$.diagnostics");
          } else {
            rejectUnknownKeys(
              raw.diagnostics,
              ["max_rows", "query_timeout_ms", "redact_payloads"],
              "$.diagnostics",
              errors
            );
            const maxRows = expectIntInRange(
              raw.diagnostics,
              "max_rows",
              1,
              10000,
              "$.diagnostics",
              errors
            );
            const queryTimeoutMs = expectIntInRange(
              raw.diagnostics,
              "query_timeout_ms",
              500,
              60000,
              "$.diagnostics",
              errors
            );
            if (raw.diagnostics.redact_payloads !== true) {
              addFieldError(errors, "$.diagnostics.redact_payloads");
            }
            diagnostics = {
              max_rows: maxRows,
              query_timeout_ms: queryTimeoutMs,
              redact_payloads: true
            };
          }
          if (diagnostics) {
            parsedConfig = {
              ...schemaField,
              schema_version: 1,
              profile,
              process_role: "admin",
              command_role: "diagnostics_operator",
              ...(database !== undefined ? { database } : {}),
              ...(operatorChannel !== undefined ? { operator_channel: operatorChannel } : {}),
              diagnostics
            };
          }
          break;
        }

        default:
          addFieldError(errors, "$.command_role");
          break;
      }
      break;
    }

    case "receiver": {
      rejectUnknownKeys(
        raw,
        [
          "$schema",
          "schema_version",
          "profile",
          "process_role",
          "http",
          "database",
          "secret_provider",
          "control_channel",
          "telemetry",
          "protocol"
        ],
        "$",
        errors
      );
      const http = validateHttpBindConfig(raw.http, "$.http", errors);
      const database = validateDatabaseConfig(
        raw.database,
        profile,
        "receiver_runtime",
        "rc",
        ["direct", "session_pooler"],
        "$.database",
        errors
      );
      const secretProvider = validateSecretProvider(
        raw.secret_provider,
        profile,
        "$.secret_provider",
        errors
      );
      const controlChannel =
        "control_channel" in raw
          ? validateIpcChannelRef(raw.control_channel, "$.control_channel", errors)
          : undefined;
      const telemetry =
        "telemetry" in raw
          ? validateTelemetryConfig(raw.telemetry, profile, "$.telemetry", errors)
          : undefined;
      const protocol = validateProtocolConfig(raw.protocol, "$.protocol", errors);
      if (http && database && secretProvider && protocol) {
        parsedConfig = {
          ...schemaField,
          schema_version: 1,
          profile,
          process_role: "receiver",
          http,
          database,
          secret_provider: secretProvider,
          ...(controlChannel !== undefined ? { control_channel: controlChannel } : {}),
          ...(telemetry !== undefined ? { telemetry } : {}),
          protocol
        };
      }
      break;
    }

    case "receiver_migrator": {
      rejectUnknownKeys(
        raw,
        ["$schema", "schema_version", "profile", "process_role", "database", "migrations_dir"],
        "$",
        errors
      );
      const database = validateDatabaseConfig(
        raw.database,
        profile,
        "receiver_migrator",
        "rc",
        ["direct", "session_pooler"],
        "$.database",
        errors
      );
      const migrationsDir = expectRepoRelativePath(raw, "migrations_dir", "$", errors);
      if (database) {
        parsedConfig = {
          ...schemaField,
          schema_version: 1,
          profile,
          process_role: "receiver_migrator",
          database,
          migrations_dir: migrationsDir
        };
      }
      break;
    }

    case "receiver_operator": {
      rejectUnknownKeys(
        raw,
        ["$schema", "schema_version", "profile", "process_role", "control_channel"],
        "$",
        errors
      );
      const controlChannel = validateIpcChannelRef(raw.control_channel, "$.control_channel", errors);
      if (controlChannel) {
        parsedConfig = {
          ...schemaField,
          schema_version: 1,
          profile,
          process_role: "receiver_operator",
          control_channel: controlChannel
        };
      }
      break;
    }

    case "provider_ingress": {
      rejectUnknownKeys(
        raw,
        [
          "$schema",
          "schema_version",
          "profile",
          "process_role",
          "http",
          "database",
          "secret_provider",
          "relayquill_api",
          "control_channel",
          "telemetry",
          "protocol"
        ],
        "$",
        errors
      );
      const http = validateHttpBindConfig(raw.http, "$.http", errors);
      const database = validateDatabaseConfig(
        raw.database,
        profile,
        "provider_runtime",
        "pi",
        ["direct", "session_pooler"],
        "$.database",
        errors
      );
      const secretProvider = validateSecretProvider(
        raw.secret_provider,
        profile,
        "$.secret_provider",
        errors
      );
      const relayquillApi = validateApiTargetConfig(
        raw.relayquill_api,
        profile,
        "$.relayquill_api",
        errors
      );
      const controlChannel =
        "control_channel" in raw
          ? validateIpcChannelRef(raw.control_channel, "$.control_channel", errors)
          : undefined;
      const telemetry =
        "telemetry" in raw
          ? validateTelemetryConfig(raw.telemetry, profile, "$.telemetry", errors)
          : undefined;
      const protocol = validateProtocolConfig(raw.protocol, "$.protocol", errors);
      if (http && database && secretProvider && relayquillApi && protocol) {
        parsedConfig = {
          ...schemaField,
          schema_version: 1,
          profile,
          process_role: "provider_ingress",
          http,
          database,
          secret_provider: secretProvider,
          relayquill_api: relayquillApi,
          ...(controlChannel !== undefined ? { control_channel: controlChannel } : {}),
          ...(telemetry !== undefined ? { telemetry } : {}),
          protocol
        };
      }
      break;
    }

    case "provider_ingress_migrator": {
      rejectUnknownKeys(
        raw,
        ["$schema", "schema_version", "profile", "process_role", "database", "migrations_dir"],
        "$",
        errors
      );
      const database = validateDatabaseConfig(
        raw.database,
        profile,
        "provider_migrator",
        "pi",
        ["direct", "session_pooler"],
        "$.database",
        errors
      );
      const migrationsDir = expectRepoRelativePath(raw, "migrations_dir", "$", errors);
      if (database) {
        parsedConfig = {
          ...schemaField,
          schema_version: 1,
          profile,
          process_role: "provider_ingress_migrator",
          database,
          migrations_dir: migrationsDir
        };
      }
      break;
    }

    case "provider_ingress_fixture": {
      rejectUnknownKeys(
        raw,
        ["$schema", "schema_version", "profile", "process_role", "http_target", "control_channel"],
        "$",
        errors
      );
      let httpTarget: ProviderIngressFixtureRoleConfig["http_target"] | undefined;
      if (!isPlainRecord(raw.http_target)) {
        addFieldError(errors, "$.http_target");
      } else {
        rejectUnknownKeys(
          raw.http_target,
          ["base_url", "stripe_path", "paystack_path"],
          "$.http_target",
          errors
        );
        httpTarget = {
          base_url: expectNonEmptyString(raw.http_target, "base_url", "$.http_target", errors, {
            pattern: isProductionProfile(profile) ? /^https:\/\// : /^https?:\/\//
          }),
          stripe_path: expectNonEmptyString(raw.http_target, "stripe_path", "$.http_target", errors),
          paystack_path: expectNonEmptyString(
            raw.http_target,
            "paystack_path",
            "$.http_target",
            errors
          )
        };
      }
      const controlChannel = validateIpcChannelRef(raw.control_channel, "$.control_channel", errors);
      if (httpTarget && controlChannel) {
        parsedConfig = {
          ...schemaField,
          schema_version: 1,
          profile,
          process_role: "provider_ingress_fixture",
          http_target: httpTarget,
          control_channel: controlChannel
        };
      }
      break;
    }

    case "producer_example": {
      rejectUnknownKeys(
        raw,
        [
          "$schema",
          "schema_version",
          "profile",
          "process_role",
          "api_target",
          "secret_provider",
          "runs_dir",
          "project_scope"
        ],
        "$",
        errors
      );
      const apiTarget = validateApiTargetConfig(raw.api_target, profile, "$.api_target", errors);
      const secretProvider = validateSecretProvider(
        raw.secret_provider,
        profile,
        "$.secret_provider",
        errors
      );
      const runsDir = expectRepoRelativePath(raw, "runs_dir", "$", errors);
      let projectScope: ProducerExampleRoleConfig["project_scope"] | undefined;
      if (!isPlainRecord(raw.project_scope)) {
        addFieldError(errors, "$.project_scope");
      } else {
        rejectUnknownKeys(
          raw.project_scope,
          ["project_slug", "producer_credential_ref"],
          "$.project_scope",
          errors
        );
        projectScope = {
          project_slug: expectNonEmptyString(
            raw.project_scope,
            "project_slug",
            "$.project_scope",
            errors,
            { pattern: /^[a-z0-9][a-z0-9-]{1,62}$/ }
          ),
          producer_credential_ref: expectSecretRef(
            raw.project_scope,
            "producer_credential_ref",
            "$.project_scope",
            errors
          )
        };
      }
      if (apiTarget && secretProvider && projectScope) {
        parsedConfig = {
          ...schemaField,
          schema_version: 1,
          profile,
          process_role: "producer_example",
          api_target: apiTarget,
          secret_provider: secretProvider,
          runs_dir: runsDir,
          project_scope: projectScope
        };
      }
      break;
    }
  }

  if (errors.length > 0 || parsedConfig === undefined) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Role configuration validation failed (${errors.length} error(s))`,
      fieldErrors: errors
    });
  }

  return Object.freeze(parsedConfig);
}

export function loadRoleConfig(
  filePath: string,
  options: ValidateRoleConfigOptions = {}
): RoleConfig {
  const safePath = assertSafeFilesystemPath(filePath, "config_path");
  const resolved = path.resolve(safePath);
  if (!fs.existsSync(resolved)) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Configuration file not found: ${safePath}`
    });
  }
  const text = fs.readFileSync(resolved, "utf8");
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch (err) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Invalid JSON in configuration file ${safePath}: ${err instanceof Error ? err.message : String(err)}`
    });
  }
  return validateRoleConfig(raw, options);
}

function selectDatabaseEnvOverride(
  db: DatabaseConfig,
  env: Readonly<Record<string, string | undefined>>
): { readonly key: string; readonly value: string } | undefined {
  const candidateKeys =
    db.schema === "rc"
      ? ["RECEIVER_DATABASE_URL"]
      : db.schema === "pi"
        ? ["PROVIDER_INGRESS_DATABASE_URL"]
        : db.pool_mode === "direct"
          ? ["DIRECT_DATABASE_URL", "DATABASE_URL"]
          : ["DATABASE_URL", "DIRECT_DATABASE_URL"];

  for (const key of candidateKeys) {
    const val = env[key];
    if (typeof val === "string" && val.trim().length > 0) {
      return { key, value: val.trim() };
    }
  }
  return undefined;
}

function resolveDatabaseFromEnv(
  db: DatabaseConfig,
  profile: ProfileKind,
  env: Readonly<Record<string, string | undefined>>
): ResolvedDatabaseEnvConfig {
  const override = selectDatabaseEnvOverride(db, env);
  if (override === undefined) {
    return Object.freeze({
      host: db.host,
      port: db.port,
      name: db.name,
      schema: db.schema,
      supportSchema: db.support_schema,
      configuredRole: db.role,
      user: db.role,
      mode: db.mode,
      authentication: db.authentication,
      tlsMode: db.tls_mode,
      ...(db.tls_ca_file !== undefined ? { tlsCaFile: db.tls_ca_file } : {}),
      poolMode: db.pool_mode,
      ...(db.password_secret_ref !== undefined
        ? { passwordSecretRef: db.password_secret_ref }
        : {})
    });
  }

  let parsedUrl: URL;
  try {
    parsedUrl = new URL(override.value);
  } catch {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Environment variable ${override.key} is not a valid PostgreSQL URL`
    });
  }
  if (parsedUrl.protocol !== "postgres:" && parsedUrl.protocol !== "postgresql:") {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Environment variable ${override.key} must use postgres:// or postgresql:// scheme`
    });
  }
  if (parsedUrl.hostname.length === 0) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Environment variable ${override.key} is missing database host`
    });
  }
  if (isProductionProfile(profile) && parsedUrl.hostname.includes("receiver.fixture.test")) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Environment variable ${override.key} must not target fixture host in production`
    });
  }

  const sslMode = parsedUrl.searchParams.get("sslmode")?.toLowerCase();
  if (
    db.tls_mode === "verify_full" &&
    (sslMode === "disable" || sslMode === "allow" || sslMode === "prefer")
  ) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Environment variable ${override.key} sslmode="${sslMode}" violates tls_mode="verify_full"`
    });
  }

  const dbName = parsedUrl.pathname.replace(/^\/+/, "");
  const port = parsedUrl.port.length > 0 ? Number(parsedUrl.port) : 5432;
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Environment variable ${override.key} has invalid port "${parsedUrl.port}"`
    });
  }

  const username =
    parsedUrl.username.length > 0 ? decodeURIComponent(parsedUrl.username) : db.role;
  const rawPassword = parsedUrl.password.length > 0 ? decodeURIComponent(parsedUrl.password) : undefined;
  const passwordHandle =
    rawPassword !== undefined
      ? createSecretHandle(rawPassword, { id: `env:${override.key}`, source: "env" })
      : undefined;

  return Object.freeze({
    host: parsedUrl.hostname,
    port,
    name: dbName.length > 0 ? dbName : db.name,
    schema: db.schema,
    supportSchema: db.support_schema,
    configuredRole: db.role,
    user: username,
    mode: db.mode,
    authentication: db.authentication,
    tlsMode: db.tls_mode,
    ...(db.tls_ca_file !== undefined ? { tlsCaFile: db.tls_ca_file } : {}),
    poolMode: db.pool_mode,
    ...(db.password_secret_ref !== undefined ? { passwordSecretRef: db.password_secret_ref } : {}),
    ...(passwordHandle !== undefined ? { passwordHandle } : {}),
    envOverrideVar: override.key
  });
}

function resolveBrokerFromEnv(
  broker: BrokerConfig,
  profile: ProfileKind,
  env: Readonly<Record<string, string | undefined>>
): ResolvedBrokerEnvConfig {
  let servers = broker.servers;
  const natsUrlRaw = env.NATS_URL?.trim();
  if (natsUrlRaw !== undefined && natsUrlRaw.length > 0) {
    const split = natsUrlRaw
      .split(",")
      .map((s) => s.trim())
      .filter((s) => s.length > 0);
    if (split.length === 0) {
      throw new ValidationDomainError({
        code: "INVALID_VALUE",
        message: "NATS_URL must contain at least one broker URL when set"
      });
    }
    const requireTls = broker.tls?.enabled === true || isProductionProfile(profile);
    for (const serverUrl of split) {
      if (requireTls && !serverUrl.startsWith("tls://")) {
        throw new ValidationDomainError({
          code: "INVALID_VALUE",
          message: `NATS_URL entry "${serverUrl}" must use tls:// scheme`
        });
      }
      if (!serverUrl.startsWith("tls://") && !serverUrl.startsWith("nats://")) {
        throw new ValidationDomainError({
          code: "INVALID_VALUE",
          message: `NATS_URL entry "${serverUrl}" must use tls:// or nats:// scheme`
        });
      }
      if (
        isProductionProfile(profile) &&
        (serverUrl.includes("127.0.0.1") ||
          serverUrl.includes("localhost") ||
          serverUrl.includes("receiver.fixture.test"))
      ) {
        throw new ValidationDomainError({
          code: "INVALID_VALUE",
          message: `NATS_URL entry "${serverUrl}" is forbidden in production profile`
        });
      }
    }
    servers = Object.freeze(split);
  }

  const rawNkeyFile = env.NATS_NKEY_SEED_FILE?.trim();
  const nkeySeedFile =
    rawNkeyFile !== undefined && rawNkeyFile.length > 0
      ? assertSafeFilesystemPath(rawNkeyFile, "NATS_NKEY_SEED_FILE")
      : undefined;

  const rawCredsFile = env.NATS_CREDS_FILE?.trim();
  const credsFile =
    rawCredsFile !== undefined && rawCredsFile.length > 0
      ? assertSafeFilesystemPath(rawCredsFile, "NATS_CREDS_FILE")
      : undefined;

  let secretRef = broker.secret_ref;
  if (broker.auth_mode === "nkey_seed" && nkeySeedFile !== undefined) {
    secretRef = `file:${nkeySeedFile}`;
  } else if (broker.auth_mode === "synadia_creds_jwt" && credsFile !== undefined) {
    secretRef = `file:${credsFile}`;
  }

  return Object.freeze({
    mode: broker.mode,
    servers,
    authMode: broker.auth_mode,
    ...(secretRef !== undefined ? { secretRef } : {}),
    ...(nkeySeedFile !== undefined ? { nkeySeedFile } : {}),
    ...(credsFile !== undefined ? { credsFile } : {}),
    ...(broker.tls !== undefined ? { tls: broker.tls } : {}),
    streamName: broker.stream_name,
    subjectPrefix: broker.subject_prefix,
    consumerName: broker.consumer_name,
    ...(broker.inbox_prefix !== undefined ? { inboxPrefix: broker.inbox_prefix } : {})
  });
}

export interface ResolveRuntimeEnvironmentOptions {
  readonly env?: Readonly<Record<string, string | undefined>> | undefined;
  readonly envFilePath?: string | undefined;
  readonly requireEnvFile?: boolean | undefined;
}

export function resolveRuntimeEnvironment(
  config: RoleConfig,
  options: ResolveRuntimeEnvironmentOptions = {}
): ResolvedRuntimeEnvironment {
  const configuredEnvFile =
    "secret_provider" in config && config.secret_provider.env_file !== undefined
      ? config.secret_provider.env_file
      : undefined;
  const env = resolveEnvMap({
    env: options.env,
    envFilePath: options.envFilePath ?? configuredEnvFile,
    requireEnvFile:
      options.requireEnvFile ??
      (configuredEnvFile !== undefined &&
        "secret_provider" in config &&
        config.secret_provider.mode === "env_file")
  });

  const relayquillEnv =
    typeof env.RELAYQUILL_ENV === "string" && env.RELAYQUILL_ENV.trim().length > 0
      ? env.RELAYQUILL_ENV.trim()
      : config.profile;

  const publicConsoleOrigin =
    typeof env.PUBLIC_CONSOLE_ORIGIN === "string" && env.PUBLIC_CONSOLE_ORIGIN.trim().length > 0
      ? env.PUBLIC_CONSOLE_ORIGIN.trim()
      : config.process_role === "api"
        ? config.http.public_origin
        : undefined;

  const publicApiOrigin =
    typeof env.PUBLIC_API_ORIGIN === "string" && env.PUBLIC_API_ORIGIN.trim().length > 0
      ? env.PUBLIC_API_ORIGIN.trim()
      : undefined;

  const webauthnRpId =
    typeof env.WEBAUTHN_RP_ID === "string" && env.WEBAUTHN_RP_ID.trim().length > 0
      ? env.WEBAUTHN_RP_ID.trim()
      : config.process_role === "api"
        ? config.auth.rp_id
        : undefined;

  if (isProductionProfile(config.profile)) {
    for (const [label, origin] of [
      ["PUBLIC_CONSOLE_ORIGIN", publicConsoleOrigin],
      ["PUBLIC_API_ORIGIN", publicApiOrigin]
    ] as const) {
      if (origin !== undefined) {
        if (!origin.startsWith("https://") || origin.includes("receiver.fixture.test")) {
          throw new ValidationDomainError({
            code: "INVALID_VALUE",
            message: `${label} must be an HTTPS non-fixture origin in production profile`
          });
        }
      }
    }
  }

  const database =
    "database" in config && config.database !== undefined
      ? resolveDatabaseFromEnv(config.database, config.profile, env)
      : undefined;

  const broker =
    "broker" in config && config.broker !== undefined
      ? resolveBrokerFromEnv(config.broker, config.profile, env)
      : undefined;

  const operatorEndpoint =
    "operator_channel" in config && config.operator_channel !== undefined
      ? resolveIpcChannelEndpoint(config.operator_channel, env)
      : undefined;

  const controlEndpoint =
    "control_channel" in config && config.control_channel !== undefined
      ? resolveIpcChannelEndpoint(config.control_channel, env)
      : undefined;

  const ipcEndpoint =
    "ipc" in config && config.ipc !== undefined
      ? resolveIpcChannelEndpoint(config.ipc, env)
      : undefined;

  return Object.freeze({
    config,
    relayquillEnv,
    ...(publicConsoleOrigin !== undefined ? { publicConsoleOrigin } : {}),
    ...(publicApiOrigin !== undefined ? { publicApiOrigin } : {}),
    ...(webauthnRpId !== undefined ? { webauthnRpId } : {}),
    ...(database !== undefined ? { database } : {}),
    ...(broker !== undefined ? { broker } : {}),
    ...(operatorEndpoint !== undefined ? { operatorEndpoint } : {}),
    ...(controlEndpoint !== undefined ? { controlEndpoint } : {}),
    ...(ipcEndpoint !== undefined ? { ipcEndpoint } : {})
  });
}
