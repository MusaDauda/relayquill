import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import tls from "node:tls";
import {
  type BrokerGenerationId,
  ValidationDomainError,
  parseBrokerGenerationId
} from "@relayquill/domain";
import {
  type BrokerAuthMode,
  type BrokerConfig,
  type BrokerMode,
  type BrokerTlsConfig,
  type ResolvedBrokerEnvConfig,
  type SecretHandle,
  type SecretProvider,
  assertSafeFilesystemPath,
  createSecretProvider
} from "@relayquill/runtime";
import {
  type Authenticator,
  type ConnectionOptions,
  type NatsConnection,
  type ServerInfo,
  type Status,
  type TlsOptions,
  connect,
  credsAuthenticator,
  nkeyAuthenticator,
  nkeys
} from "@nats-io/transport-node";
import {
  type JetStreamClient,
  type JetStreamManager,
  type JetStreamManagerOptions,
  type JetStreamOptions,
  jetstream,
  jetstreamManager
} from "@nats-io/jetstream";
import {
  BROKER_DEFAULT_REPLICAS,
  BROKER_EVENT_MAX_PAYLOAD_BYTES,
  BROKER_EVENT_STREAM_NAME,
  BrokerUnavailableError,
  FANOUT_CONSUMER_NAME,
  normalizeSubjectPrefix
} from "./types.js";

const STREAM_NAME_REGEX = /^[A-Z0-9_]{3,64}$/;
const CONSUMER_NAME_REGEX = /^[A-Z0-9_]{3,64}$/;
const INBOX_PREFIX_REGEX = /^_INBOX\.[a-z0-9._-]+$/;
const LOOPBACK_TLS_SERVER_REGEX = /^tls:\/\/127\.0\.0\.1:([0-9]{1,5})$/;
const LOOPBACK_PLAINTEXT_SERVER_REGEX = /^nats:\/\/127\.0\.0\.1:([0-9]{1,5})$/;
const HOSTED_TLS_SERVER_REGEX = /^tls:\/\/([a-z0-9.-]+)(?::([0-9]{1,5}))?$/i;

export interface BrokerConnectionInput {
  readonly mode: BrokerMode;
  readonly servers: readonly string[];
  readonly authMode: BrokerAuthMode;
  readonly secretRef?: string | undefined;
  readonly secretHandle?: SecretHandle | undefined;
  readonly secretProvider?: SecretProvider | undefined;
  readonly tls?: BrokerTlsConfig | undefined;
  readonly tlsCaPem?: string | undefined;
  readonly inboxPrefix?: string | undefined;
  readonly clientName?: string | undefined;
  readonly streamName?: string | undefined;
  readonly subjectPrefix?: string | undefined;
  readonly consumerName?: string | undefined;
  readonly replicas?: 1 | 3 | undefined;
  readonly timeoutMs?: number | undefined;
  readonly reconnect?: boolean | undefined;
  readonly maxReconnectAttempts?: number | undefined;
  readonly noRandomize?: boolean | undefined;
  readonly ignoreClusterUpdates?: boolean | undefined;
  readonly waitOnFirstConnect?: boolean | undefined;
}

export interface ValidatedBrokerConnectionSpec {
  readonly mode: Exclude<BrokerMode, "in_memory_test">;
  readonly servers: readonly string[];
  readonly authMode: BrokerAuthMode;
  readonly secretRef?: string | undefined;
  readonly tlsRequired: boolean;
  readonly tlsHandshakeFirst: boolean;
  readonly tlsCaFile?: string | undefined;
  readonly tlsCaPem?: string | undefined;
  readonly inboxPrefix?: string | undefined;
  readonly clientName?: string | undefined;
  readonly streamName: string;
  readonly subjectPrefix: string;
  readonly consumerName: string;
  readonly replicas: 1 | 3;
  readonly timeoutMs: number;
  readonly reconnect: boolean;
  readonly maxReconnectAttempts: number;
  readonly noRandomize: boolean;
  readonly ignoreClusterUpdates: true;
  readonly waitOnFirstConnect: boolean;
}

export interface ConnectNatsBrokerOptions extends BrokerConnectionInput {
  readonly brokerGenerationId?: BrokerGenerationId | string | undefined;
  readonly jetstreamOptions?: JetStreamOptions | undefined;
}

export interface NatsConnectFn {
  (opts?: ConnectionOptions & { tls?: ({ rejectUnauthorized?: boolean } & TlsOptions) | null }): Promise<NatsConnection>;
}

function isForbiddenLoopbackHost(hostname: string): boolean {
  const lower = hostname.toLowerCase();
  return (
    lower === "127.0.0.1" ||
    lower === "localhost" ||
    lower === "::1" ||
    lower === "[::1]" ||
    lower.endsWith(".localhost") ||
    lower.endsWith(".fixture.test")
  );
}

function parseServerPort(portStr: string | undefined, serverUrl: string): number | undefined {
  if (portStr === undefined) {
    return undefined;
  }
  const port = Number(portStr);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Broker server "${serverUrl}" has invalid TCP port`,
      fieldErrors: [{ path: "broker.servers", code: "INVALID_VALUE" }]
    });
  }
  return port;
}

function validateCaPemMaterial(caMaterial: string, label: string): void {
  if (caMaterial.trim().length === 0) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `${label} must not be empty`,
      fieldErrors: [{ path: "broker.tls", code: "INVALID_VALUE" }]
    });
  }
  const certBlocks = caMaterial.match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g);
  if (certBlocks === null || certBlocks.length === 0) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `${label} does not contain any PEM X.509 CERTIFICATE blocks`,
      fieldErrors: [{ path: "broker.tls", code: "INVALID_VALUE" }]
    });
  }
  try {
    for (const block of certBlocks) {
      new crypto.X509Certificate(block);
    }
    tls.createSecureContext({ ca: caMaterial });
  } catch (err) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `${label} is not a valid PEM X.509 certificate bundle: ${err instanceof Error ? err.message : String(err)}`,
      fieldErrors: [{ path: "broker.tls", code: "INVALID_VALUE" }]
    });
  }
}

export function loadAndValidateCaBundle(
  caFile: string | undefined,
  caPem: string | undefined
): string | undefined {
  if (caPem !== undefined) {
    validateCaPemMaterial(caPem, "tlsCaPem");
    return caPem;
  }
  if (caFile === undefined) {
    return undefined;
  }
  const safePath = assertSafeFilesystemPath(caFile, "broker.tls.ca_file");
  const resolved = path.resolve(safePath);
  if (!fs.existsSync(resolved)) {
    throw new BrokerUnavailableError({
      message: `Broker CA certificate file not found: ${safePath}`,
      retryable: false,
      acceptance: "known_rejected",
      reasonCode: "CA_BUNDLE_MISSING"
    });
  }
  const stat = fs.statSync(resolved);
  if (!stat.isFile()) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Broker CA certificate path is not a regular file: ${safePath}`,
      fieldErrors: [{ path: "broker.tls.ca_file", code: "INVALID_VALUE" }]
    });
  }
  const content = fs.readFileSync(resolved, "utf8");
  validateCaPemMaterial(content, `broker.tls.ca_file (${safePath})`);
  return content;
}

function assertValidServerEntryCommon(rawServer: unknown, index: number): string {
  if (typeof rawServer !== "string") {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Broker server[${index}] must be a string`,
      fieldErrors: [{ path: `broker.servers[${index}]`, code: "INVALID_VALUE" }]
    });
  }
  const server = rawServer.trim();
  if (
    server.length < 5 ||
    server.length > 255 ||
    server.includes("*") ||
    server.includes(">") ||
    server.includes("@") ||
    server.includes("?") ||
    server.includes("#") ||
    /\s/.test(server)
  ) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Broker server[${index}] contains invalid characters or wildcard`,
      fieldErrors: [{ path: `broker.servers[${index}]`, code: "INVALID_VALUE" }]
    });
  }
  return server;
}

function assertNoLoopbackDiscovery(input: BrokerConnectionInput): void {
  if (input.ignoreClusterUpdates === false) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: "Cluster discovery updates must remain disabled (ignoreClusterUpdates: true) for explicit broker endpoint policy",
      fieldErrors: [{ path: "broker.ignoreClusterUpdates", code: "INVALID_VALUE" }]
    });
  }
}

export function brokerConnectionInputFromConfig(
  config: BrokerConfig | ResolvedBrokerEnvConfig,
  overrides: Partial<BrokerConnectionInput> = {}
): BrokerConnectionInput {
  const isResolved = "authMode" in config;
  const base: BrokerConnectionInput = isResolved
    ? {
        mode: config.mode,
        servers: config.servers,
        authMode: config.authMode,
        secretRef: config.secretRef,
        tls: config.tls,
        streamName: config.streamName,
        subjectPrefix: config.subjectPrefix,
        consumerName: config.consumerName,
        inboxPrefix: config.inboxPrefix
      }
    : {
        mode: config.mode,
        servers: config.servers,
        authMode: config.auth_mode,
        secretRef: config.secret_ref,
        tls: config.tls,
        streamName: config.stream_name,
        subjectPrefix: config.subject_prefix,
        consumerName: config.consumer_name,
        replicas: config.replicas,
        inboxPrefix: config.inbox_prefix
      };

  return {
    ...base,
    ...overrides
  };
}

export function validateBrokerConnectionOptions(
  input: BrokerConnectionInput
): ValidatedBrokerConnectionSpec {
  if (input.mode === "in_memory_test") {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: "Mode in_memory_test must use InMemoryJetStreamBroker instead of NATS transport connection",
      fieldErrors: [{ path: "broker.mode", code: "INVALID_VALUE" }]
    });
  }

  assertNoLoopbackDiscovery(input);

  if (!Array.isArray(input.servers) || input.servers.length < 1 || input.servers.length > 5) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: "Broker servers must contain between 1 and 5 explicit URLs",
      fieldErrors: [{ path: "broker.servers", code: "INVALID_VALUE" }]
    });
  }

  const servers = input.servers.map((entry, idx) => assertValidServerEntryCommon(entry, idx));

  const streamName = input.streamName ?? BROKER_EVENT_STREAM_NAME;
  if (!STREAM_NAME_REGEX.test(streamName)) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Invalid streamName "${streamName}"`,
      fieldErrors: [{ path: "broker.streamName", code: "INVALID_VALUE" }]
    });
  }
  const consumerName = input.consumerName ?? FANOUT_CONSUMER_NAME;
  if (!CONSUMER_NAME_REGEX.test(consumerName)) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Invalid consumerName "${consumerName}"`,
      fieldErrors: [{ path: "broker.consumerName", code: "INVALID_VALUE" }]
    });
  }
  const subjectPrefix = normalizeSubjectPrefix(input.subjectPrefix);
  const replicas: 1 | 3 = input.replicas ?? BROKER_DEFAULT_REPLICAS;
  if (replicas !== 1 && replicas !== 3) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: "Broker replicas must be 1 or 3",
      fieldErrors: [{ path: "broker.replicas", code: "INVALID_VALUE" }]
    });
  }

  if (input.inboxPrefix !== undefined && !INBOX_PREFIX_REGEX.test(input.inboxPrefix)) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Invalid inboxPrefix "${input.inboxPrefix}"`,
      fieldErrors: [{ path: "broker.inboxPrefix", code: "INVALID_VALUE" }]
    });
  }

  const timeoutMs = input.timeoutMs ?? 5_000;
  if (!Number.isInteger(timeoutMs) || timeoutMs < 250 || timeoutMs > 60_000) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Broker timeoutMs must be within [250, 60000], got ${String(timeoutMs)}`,
      fieldErrors: [{ path: "broker.timeoutMs", code: "INVALID_VALUE" }]
    });
  }

  const tlsCfg = input.tls;
  let tlsRequired = false;
  let tlsHandshakeFirst = false;
  let tlsCaFile: string | undefined;
  const tlsCaPem = input.tlsCaPem;

  switch (input.mode) {
    case "development_loopback": {
      if (input.authMode !== "none_fixture") {
        throw new ValidationDomainError({
          code: "INVALID_VALUE",
          message: "development_loopback requires authMode none_fixture",
          fieldErrors: [{ path: "broker.authMode", code: "INVALID_VALUE" }]
        });
      }
      if (input.secretRef !== undefined || input.secretHandle !== undefined) {
        throw new ValidationDomainError({
          code: "INVALID_VALUE",
          message: "development_loopback must not configure secret credentials",
          fieldErrors: [{ path: "broker.secretRef", code: "INVALID_VALUE" }]
        });
      }
      if (tlsCfg !== undefined && tlsCfg.enabled) {
        throw new ValidationDomainError({
          code: "INVALID_VALUE",
          message: "development_loopback does not support TLS; use embedded_go_tls instead",
          fieldErrors: [{ path: "broker.tls", code: "INVALID_VALUE" }]
        });
      }
      for (const s of servers) {
        const match = LOOPBACK_PLAINTEXT_SERVER_REGEX.exec(s);
        if (match === null) {
          throw new ValidationDomainError({
            code: "INVALID_VALUE",
            message: `development_loopback server "${s}" must match nats://127.0.0.1:<port>`,
            fieldErrors: [{ path: "broker.servers", code: "INVALID_VALUE" }]
          });
        }
        parseServerPort(match[1], s);
      }
      break;
    }

    case "embedded_go_tls": {
      if (input.authMode !== "none_fixture" && input.authMode !== "nkey_seed") {
        throw new ValidationDomainError({
          code: "INVALID_VALUE",
          message: "embedded_go_tls requires authMode none_fixture or nkey_seed",
          fieldErrors: [{ path: "broker.authMode", code: "INVALID_VALUE" }]
        });
      }
      if (replicas !== 1) {
        throw new ValidationDomainError({
          code: "INVALID_VALUE",
          message: "embedded_go_tls requires replicas === 1",
          fieldErrors: [{ path: "broker.replicas", code: "INVALID_VALUE" }]
        });
      }
      if (
        tlsCfg === undefined ||
        !tlsCfg.enabled ||
        tlsCfg.handshake_first !== true ||
        tlsCfg.reject_unauthorized !== true
      ) {
        throw new ValidationDomainError({
          code: "INVALID_VALUE",
          message: "embedded_go_tls requires tls.enabled, tls.handshake_first=true, and tls.reject_unauthorized=true",
          fieldErrors: [{ path: "broker.tls", code: "INVALID_VALUE" }]
        });
      }
      if (tlsCfg.ca_file === undefined && tlsCaPem === undefined) {
        throw new ValidationDomainError({
          code: "INVALID_VALUE",
          message: "embedded_go_tls requires a public CA certificate (tls.ca_file or tlsCaPem)",
          fieldErrors: [{ path: "broker.tls", code: "INVALID_VALUE" }]
        });
      }
      if (input.authMode === "nkey_seed" && input.secretRef === undefined && input.secretHandle === undefined) {
        throw new ValidationDomainError({
          code: "INVALID_VALUE",
          message: "embedded_go_tls with nkey_seed requires secretHandle or secretRef",
          fieldErrors: [{ path: "broker.secretRef", code: "INVALID_VALUE" }]
        });
      }
      for (const s of servers) {
        const match = LOOPBACK_TLS_SERVER_REGEX.exec(s);
        if (match === null) {
          throw new ValidationDomainError({
            code: "INVALID_VALUE",
            message: `embedded_go_tls server "${s}" must match tls://127.0.0.1:<port>`,
            fieldErrors: [{ path: "broker.servers", code: "INVALID_VALUE" }]
          });
        }
        parseServerPort(match[1], s);
      }
      tlsRequired = true;
      tlsHandshakeFirst = true;
      tlsCaFile = tlsCfg.ca_file !== undefined ? assertSafeFilesystemPath(tlsCfg.ca_file, "broker.tls.ca_file") : undefined;
      break;
    }

    case "standard_tls":
    case "self_hosted":
    case "release_native_tls": {
      if (input.authMode !== "nkey_seed") {
        throw new ValidationDomainError({
          code: "INVALID_VALUE",
          message: `${input.mode} requires authMode nkey_seed`,
          fieldErrors: [{ path: "broker.authMode", code: "INVALID_VALUE" }]
        });
      }
      if (input.secretRef === undefined && input.secretHandle === undefined) {
        throw new ValidationDomainError({
          code: "INVALID_VALUE",
          message: `${input.mode} requires NKey seed custody reference (secretHandle or secretRef)`,
          fieldErrors: [{ path: "broker.secretRef", code: "INVALID_VALUE" }]
        });
      }
      if (
        tlsCfg === undefined ||
        !tlsCfg.enabled ||
        tlsCfg.handshake_first !== true ||
        tlsCfg.reject_unauthorized !== true
      ) {
        throw new ValidationDomainError({
          code: "INVALID_VALUE",
          message: `${input.mode} requires tls.enabled=true, tls.handshake_first=true, and tls.reject_unauthorized=true`,
          fieldErrors: [{ path: "broker.tls", code: "INVALID_VALUE" }]
        });
      }
      if (tlsCfg.ca_file === undefined && tlsCaPem === undefined) {
        throw new ValidationDomainError({
          code: "INVALID_VALUE",
          message: `${input.mode} requires a public CA certificate bundle (tls.ca_file or tlsCaPem)`,
          fieldErrors: [{ path: "broker.tls.ca_file", code: "INVALID_VALUE" }]
        });
      }
      if (input.mode === "release_native_tls") {
        if (servers.length < 3) {
          throw new ValidationDomainError({
            code: "INVALID_VALUE",
            message: "release_native_tls requires at least 3 explicit tls:// broker endpoints",
            fieldErrors: [{ path: "broker.servers", code: "INVALID_VALUE" }]
          });
        }
        if (input.replicas !== undefined && input.replicas !== 3) {
          throw new ValidationDomainError({
            code: "INVALID_VALUE",
            message: "release_native_tls requires replicas === 3",
            fieldErrors: [{ path: "broker.replicas", code: "INVALID_VALUE" }]
          });
        }
      }
      for (const s of servers) {
        const match = HOSTED_TLS_SERVER_REGEX.exec(s);
        if (match === null || match[1] === undefined) {
          throw new ValidationDomainError({
            code: "INVALID_VALUE",
            message: `${input.mode} server "${s}" must use tls:// scheme with a valid hostname`,
            fieldErrors: [{ path: "broker.servers", code: "INVALID_VALUE" }]
          });
        }
        if (isForbiddenLoopbackHost(match[1])) {
          throw new ValidationDomainError({
            code: "INVALID_VALUE",
            message: `${input.mode} forbids loopback or fixture host "${match[1]}"`,
            fieldErrors: [{ path: "broker.servers", code: "INVALID_VALUE" }]
          });
        }
        if (input.mode === "release_native_tls" && match[2] === undefined) {
          throw new ValidationDomainError({
            code: "INVALID_VALUE",
            message: `release_native_tls server "${s}" must specify an explicit port`,
            fieldErrors: [{ path: "broker.servers", code: "INVALID_VALUE" }]
          });
        }
        parseServerPort(match[2], s);
      }
      tlsRequired = true;
      tlsHandshakeFirst = true;
      tlsCaFile = tlsCfg.ca_file !== undefined ? assertSafeFilesystemPath(tlsCfg.ca_file, "broker.tls.ca_file") : undefined;
      break;
    }

    case "hosted_synadia_ngs": {
      if (input.authMode !== "synadia_creds_jwt") {
        throw new ValidationDomainError({
          code: "INVALID_VALUE",
          message: "hosted_synadia_ngs requires authMode synadia_creds_jwt",
          fieldErrors: [{ path: "broker.authMode", code: "INVALID_VALUE" }]
        });
      }
      if (input.secretRef === undefined && input.secretHandle === undefined) {
        throw new ValidationDomainError({
          code: "INVALID_VALUE",
          message: "hosted_synadia_ngs requires .creds secretHandle or secretRef",
          fieldErrors: [{ path: "broker.secretRef", code: "INVALID_VALUE" }]
        });
      }
      if (
        tlsCfg === undefined ||
        !tlsCfg.enabled ||
        tlsCfg.handshake_first === true ||
        tlsCfg.reject_unauthorized !== true
      ) {
        throw new ValidationDomainError({
          code: "INVALID_VALUE",
          message: "hosted_synadia_ngs requires tls.enabled=true, tls.handshake_first=false, and tls.reject_unauthorized=true",
          fieldErrors: [{ path: "broker.tls", code: "INVALID_VALUE" }]
        });
      }
      for (const s of servers) {
        const match = HOSTED_TLS_SERVER_REGEX.exec(s);
        if (match === null || match[1] === undefined) {
          throw new ValidationDomainError({
            code: "INVALID_VALUE",
            message: `hosted_synadia_ngs server "${s}" must use tls:// scheme`,
            fieldErrors: [{ path: "broker.servers", code: "INVALID_VALUE" }]
          });
        }
        parseServerPort(match[2], s);
      }
      tlsRequired = true;
      tlsHandshakeFirst = false;
      tlsCaFile = tlsCfg.ca_file !== undefined ? assertSafeFilesystemPath(tlsCfg.ca_file, "broker.tls.ca_file") : undefined;
      break;
    }
  }

  if (tlsCaPem !== undefined) {
    validateCaPemMaterial(tlsCaPem, "tlsCaPem");
  }

  return Object.freeze({
    mode: input.mode,
    servers: Object.freeze(servers),
    authMode: input.authMode,
    ...(input.secretRef !== undefined ? { secretRef: input.secretRef } : {}),
    tlsRequired,
    tlsHandshakeFirst,
    ...(tlsCaFile !== undefined ? { tlsCaFile } : {}),
    ...(tlsCaPem !== undefined ? { tlsCaPem } : {}),
    ...(input.inboxPrefix !== undefined ? { inboxPrefix: input.inboxPrefix } : {}),
    ...(input.clientName !== undefined ? { clientName: input.clientName } : {}),
    streamName,
    subjectPrefix,
    consumerName,
    replicas,
    timeoutMs,
    reconnect: input.reconnect ?? true,
    maxReconnectAttempts: input.maxReconnectAttempts ?? -1,
    noRandomize: input.noRandomize ?? false,
    ignoreClusterUpdates: true,
    waitOnFirstConnect: input.waitOnFirstConnect ?? false
  });
}

function trimAsciiWhitespaceBytes(buf: Buffer): Buffer {
  let start = 0;
  let end = buf.byteLength;
  while (start < end && (buf[start] === 0x20 || buf[start] === 0x09 || buf[start] === 0x0a || buf[start] === 0x0d)) {
    start += 1;
  }
  while (end > start && (buf[end - 1] === 0x20 || buf[end - 1] === 0x09 || buf[end - 1] === 0x0a || buf[end - 1] === 0x0d)) {
    end -= 1;
  }
  const out = Buffer.allocUnsafe(end - start);
  buf.copy(out, 0, start, end);
  return out;
}

export function validateNKeySeedHandle(handle: SecretHandle): string {
  if (handle.isDestroyed) {
    throw new BrokerUnavailableError({
      message: `Broker NKey SecretHandle "${handle.id}" is already destroyed`,
      retryable: false,
      acceptance: "known_rejected",
      reasonCode: "NKEY_HANDLE_DESTROYED"
    });
  }
  return handle.useBytes((raw) => {
    const trimmed = trimAsciiWhitespaceBytes(raw);
    try {
      const kp = nkeys.fromSeed(trimmed);
      try {
        const pub = kp.getPublicKey();
        if (!pub.startsWith("U")) {
          throw new ValidationDomainError({
            code: "SECRET_CUSTODY_ERROR",
            message: "Broker NKey seed must decode to a user public key (U...)"
          });
        }
        return pub;
      } finally {
        kp.clear();
      }
    } catch (err) {
      if (err instanceof ValidationDomainError) {
        throw err;
      }
      throw new ValidationDomainError({
        code: "SECRET_CUSTODY_ERROR",
        message: `Invalid broker NKey seed material for handle "${handle.id}"`
      });
    } finally {
      trimmed.fill(0);
    }
  });
}

function normalizeCredsBytesForAuth(raw: Buffer): Buffer {
  const trimmed = trimAsciiWhitespaceBytes(raw);
  try {
    const out = Buffer.allocUnsafe(trimmed.byteLength + 1);
    let writeIdx = 0;
    for (let i = 0; i < trimmed.byteLength; i += 1) {
      const b = trimmed[i];
      if (b === undefined) {
        continue;
      }
      if (b === 0x0d && trimmed[i + 1] === 0x0a) {
        continue;
      }
      out[writeIdx] = b;
      writeIdx += 1;
    }
    out[writeIdx] = 0x0a;
    return out.subarray(0, writeIdx + 1);
  } finally {
    trimmed.fill(0);
  }
}

export function validateCredsHandle(handle: SecretHandle): void {
  if (handle.isDestroyed) {
    throw new BrokerUnavailableError({
      message: `Broker .creds SecretHandle "${handle.id}" is already destroyed`,
      retryable: false,
      acceptance: "known_rejected",
      reasonCode: "CREDS_HANDLE_DESTROYED"
    });
  }
  handle.useBytes((raw) => {
    const normalized = normalizeCredsBytesForAuth(raw);
    try {
      const auth = credsAuthenticator(() => normalized);
      const authResult = auth("validation-nonce");
      if (authResult instanceof Promise) {
        void authResult.catch(() => undefined);
        throw new Error("Unexpected asynchronous credentials authenticator");
      }
      if (
        authResult === undefined ||
        typeof authResult !== "object" ||
        !("jwt" in authResult) ||
        typeof authResult.jwt !== "string" ||
        authResult.jwt.length === 0 ||
        !("sig" in authResult) ||
        typeof authResult.sig !== "string" ||
        authResult.sig.length === 0
      ) {
        throw new Error("Invalid credentials challenge signature");
      }
    } catch {
      throw new ValidationDomainError({
        code: "SECRET_CUSTODY_ERROR",
        message: `Invalid broker .creds JWT/NKey bundle for handle "${handle.id}"`
      });
    } finally {
      normalized.fill(0);
    }
  });
}

export function createNKeyAuthenticatorFromHandle(handle: SecretHandle): Authenticator {
  validateNKeySeedHandle(handle);
  return (nonce?: string, signal?: AbortSignal) => {
    if (signal?.aborted) {
      throw new BrokerUnavailableError({
        message: "NKey authentication aborted before challenge signing",
        retryable: false,
        acceptance: "known_rejected",
        reasonCode: "AUTH_ABORTED"
      });
    }
    return handle.useBytes((raw) => {
      const trimmed = trimAsciiWhitespaceBytes(raw);
      try {
        const inner = nkeyAuthenticator(() => trimmed);
        return inner(nonce, signal);
      } finally {
        trimmed.fill(0);
      }
    });
  };
}

export function createNKeyAuthenticatorFromResolver(
  resolveHandle: () => Promise<SecretHandle>
): Authenticator {
  return async (nonce?: string, signal?: AbortSignal) => {
    if (signal?.aborted) {
      throw new BrokerUnavailableError({
        message: "NKey authentication aborted before resolving secret",
        retryable: false,
        acceptance: "known_rejected",
        reasonCode: "AUTH_ABORTED"
      });
    }
    const handle = await resolveHandle();
    try {
      validateNKeySeedHandle(handle);
      return handle.useBytes((raw) => {
        const trimmed = trimAsciiWhitespaceBytes(raw);
        try {
          const inner = nkeyAuthenticator(() => trimmed);
          return inner(nonce, signal);
        } finally {
          trimmed.fill(0);
        }
      });
    } finally {
      handle.destroy();
    }
  };
}

export function createCredsAuthenticatorFromHandle(handle: SecretHandle): Authenticator {
  validateCredsHandle(handle);
  return (nonce?: string, signal?: AbortSignal) => {
    if (signal?.aborted) {
      throw new BrokerUnavailableError({
        message: "Creds authentication aborted before challenge signing",
        retryable: false,
        acceptance: "known_rejected",
        reasonCode: "AUTH_ABORTED"
      });
    }
    return handle.useBytes((raw) => {
      const normalized = normalizeCredsBytesForAuth(raw);
      try {
        const inner = credsAuthenticator(() => normalized);
        return inner(nonce, signal);
      } finally {
        normalized.fill(0);
      }
    });
  };
}

export type NatsConnectOptions = ConnectionOptions & {
  tls?: ({ rejectUnauthorized?: boolean } & TlsOptions) | null;
};

export function buildNatsConnectionOptions(
  spec: ValidatedBrokerConnectionSpec,
  options: {
    readonly authenticator?: Authenticator | undefined;
    readonly resolvedCaPem?: string | undefined;
  } = {}
): NatsConnectOptions {
  const tlsOption: NatsConnectOptions["tls"] = spec.tlsRequired
    ? {
        handshakeFirst: spec.tlsHandshakeFirst,
        rejectUnauthorized: true,
        ...(options.resolvedCaPem !== undefined
          ? { ca: options.resolvedCaPem }
          : spec.tlsCaPem !== undefined
            ? { ca: spec.tlsCaPem }
            : spec.tlsCaFile !== undefined
              ? { caFile: spec.tlsCaFile }
              : {})
      }
    : null;

  return {
    servers: [...spec.servers],
    tls: tlsOption,
    ignoreClusterUpdates: true,
    reconnect: spec.reconnect,
    maxReconnectAttempts: spec.maxReconnectAttempts,
    noRandomize: spec.noRandomize,
    timeout: spec.timeoutMs,
    waitOnFirstConnect: spec.waitOnFirstConnect,
    ...(options.authenticator !== undefined ? { authenticator: options.authenticator } : {}),
    ...(spec.inboxPrefix !== undefined ? { inboxPrefix: spec.inboxPrefix } : {}),
    ...(spec.clientName !== undefined ? { name: spec.clientName } : {})
  };
}

async function resolveBrokerSecretHandle(
  input: BrokerConnectionInput
): Promise<{ readonly handle: SecretHandle; readonly owned: boolean } | undefined> {
  if (input.authMode === "none_fixture") {
    return undefined;
  }
  if (input.secretHandle !== undefined) {
    return { handle: input.secretHandle, owned: false };
  }
  if (input.secretRef === undefined) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `authMode "${input.authMode}" requires secretHandle or secretRef`,
      fieldErrors: [{ path: "broker.secretRef", code: "INVALID_VALUE" }]
    });
  }
  const provider =
    input.secretProvider ??
    createSecretProvider(undefined, {
      allowDirectEnvAndFileRefs: true
    });
  const handle = await provider.getSecret(input.secretRef);
  return { handle, owned: true };
}

export class NatsBrokerConnection {
  readonly nc: NatsConnection;
  readonly js: JetStreamClient;
  readonly spec: ValidatedBrokerConnectionSpec;
  readonly brokerGenerationId: BrokerGenerationId;
  readonly #ownedHandles: SecretHandle[];
  readonly #statusHistory: Status[] = [];
  #closed = false;

  constructor(options: {
    readonly nc: NatsConnection;
    readonly js: JetStreamClient;
    readonly spec: ValidatedBrokerConnectionSpec;
    readonly brokerGenerationId: BrokerGenerationId;
    readonly ownedHandles?: readonly SecretHandle[] | undefined;
  }) {
    this.nc = options.nc;
    this.js = options.js;
    this.spec = options.spec;
    this.brokerGenerationId = options.brokerGenerationId;
    this.#ownedHandles = [...(options.ownedHandles ?? [])];
    this.#monitorStatus();
  }

  #monitorStatus(): void {
    void (async () => {
      try {
        for await (const s of this.nc.status()) {
          if (this.#statusHistory.length >= 64) {
            this.#statusHistory.shift();
          }
          this.#statusHistory.push(s);
          if (s.type === "close") {
            break;
          }
        }
      } catch {
        // Status iterator ends cleanly on connection teardown.
      }
    })();
  }

  get mode(): BrokerMode {
    return this.spec.mode;
  }

  get streamName(): string {
    return this.spec.streamName;
  }

  get consumerName(): string {
    return this.spec.consumerName;
  }

  get subjectPrefix(): string {
    return this.spec.subjectPrefix;
  }

  get isClosed(): boolean {
    return this.#closed || this.nc.isClosed();
  }

  getServerInfo(): ServerInfo | undefined {
    return this.nc.info;
  }

  getConnectedServer(): string {
    return this.nc.getServer();
  }

  getRecentStatuses(): readonly Status[] {
    return Object.freeze([...this.#statusHistory]);
  }

  async getJetStreamManager(
    options: { readonly checkApiAccountInfo?: boolean | undefined } & JetStreamManagerOptions = {}
  ): Promise<JetStreamManager> {
    const checkAPI = options.checkApiAccountInfo ?? options.checkAPI ?? false;
    return jetstreamManager(this.nc, {
      ...options,
      timeout: options.timeout ?? this.spec.timeoutMs,
      checkAPI
    });
  }

  async drain(): Promise<void> {
    if (this.#closed) {
      return;
    }
    this.#closed = true;
    try {
      if (!this.nc.isClosed() && !this.nc.isDraining()) {
        await this.nc.drain();
      }
    } finally {
      this.#destroyOwnedHandles();
    }
  }

  async close(): Promise<void> {
    if (this.#closed && this.nc.isClosed()) {
      this.#destroyOwnedHandles();
      return;
    }
    this.#closed = true;
    try {
      if (!this.nc.isClosed()) {
        await this.nc.close();
      }
    } finally {
      this.#destroyOwnedHandles();
    }
  }

  #destroyOwnedHandles(): void {
    for (const h of this.#ownedHandles) {
      try {
        h.destroy();
      } catch {
        // Ignore cleanup errors for already-destroyed handles.
      }
    }
    this.#ownedHandles.length = 0;
  }
}

export async function connectNatsBroker(
  options: ConnectNatsBrokerOptions,
  connectImpl: NatsConnectFn = connect
): Promise<NatsBrokerConnection> {
  const spec = validateBrokerConnectionOptions(options);
  const resolvedCaPem = loadAndValidateCaBundle(spec.tlsCaFile, spec.tlsCaPem);
  const resolvedSecret = await resolveBrokerSecretHandle(options);
  const ownedHandles: SecretHandle[] =
    resolvedSecret !== undefined && resolvedSecret.owned ? [resolvedSecret.handle] : [];

  let authenticator: Authenticator | undefined;
  try {
    if (spec.authMode === "nkey_seed") {
      if (resolvedSecret === undefined) {
        throw new BrokerUnavailableError({
          message: "Missing NKey secret handle for nkey_seed authentication",
          retryable: false,
          acceptance: "known_rejected"
        });
      }
      authenticator = createNKeyAuthenticatorFromHandle(resolvedSecret.handle);
    } else if (spec.authMode === "synadia_creds_jwt") {
      if (resolvedSecret === undefined) {
        throw new BrokerUnavailableError({
          message: "Missing .creds secret handle for synadia_creds_jwt authentication",
          retryable: false,
          acceptance: "known_rejected"
        });
      }
      authenticator = createCredsAuthenticatorFromHandle(resolvedSecret.handle);
    }

    const natsOpts = buildNatsConnectionOptions(spec, {
      authenticator,
      resolvedCaPem
    });

    const nc = await connectImpl(natsOpts);
    const info = nc.info;

    if (info !== undefined) {
      if (info.jetstream !== true) {
        await nc.close().catch(() => undefined);
        throw new BrokerUnavailableError({
          message: "Connected NATS server does not advertise JetStream support",
          retryable: false,
          acceptance: "known_rejected",
          reasonCode: "JETSTREAM_DISABLED"
        });
      }
      if (spec.tlsRequired && info.tls_required !== true && info.tls_available !== true) {
        await nc.close().catch(() => undefined);
        throw new BrokerUnavailableError({
          message: "Connected NATS server does not advertise TLS capability while TLS is required",
          retryable: false,
          acceptance: "known_rejected",
          reasonCode: "TLS_NOT_ADVERTISED"
        });
      }
      if (info.max_payload < BROKER_EVENT_MAX_PAYLOAD_BYTES) {
        await nc.close().catch(() => undefined);
        throw new BrokerUnavailableError({
          message: `Connected NATS server max_payload (${info.max_payload}) is smaller than required ${BROKER_EVENT_MAX_PAYLOAD_BYTES}`,
          retryable: false,
          acceptance: "known_rejected",
          reasonCode: "MAX_PAYLOAD_TOO_SMALL"
        });
      }
    }

    const js = jetstream(nc, {
      ...options.jetstreamOptions,
      timeout: options.jetstreamOptions?.timeout ?? spec.timeoutMs
    });

    const brokerGenerationId = parseBrokerGenerationId(
      options.brokerGenerationId ?? "00000000-0000-4000-8000-000000000001",
      "brokerGenerationId"
    );

    return new NatsBrokerConnection({
      nc,
      js,
      spec,
      brokerGenerationId,
      ownedHandles
    });
  } catch (err) {
    for (const h of ownedHandles) {
      h.destroy();
    }
    if (
      err instanceof ValidationDomainError ||
      err instanceof BrokerUnavailableError
    ) {
      throw err;
    }
    throw new BrokerUnavailableError(
      {
        message: `Failed to connect to NATS JetStream broker (${spec.mode}): ${err instanceof Error ? err.message : String(err)}`,
        retryable: true,
        acceptance: "known_rejected",
        reasonCode: "BROKER_CONNECT_FAILED"
      },
      err
    );
  }
}
