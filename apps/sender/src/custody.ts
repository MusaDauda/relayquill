import {
  DependencyUnavailableDomainError,
  type EndpointId,
  type KeyId,
  parseEndpointId,
  parseKeyId,
  parseProjectId,
  type ProjectId,
  ValidationDomainError
} from "@relayquill/domain";
import {
  createSecretProvider,
  type IpcChannelRef,
  type SecretHandle,
  type SecretProvider,
  type SecretProviderConfig,
  createLocalIpcProviderClient
} from "@relayquill/runtime";
import {
  createMemorySigningKeyHandle,
  type EndpointKeyMetadata,
  WEBHOOK_HMAC_KEY_BYTES,
  type WebhookKeyMaterialResolver
} from "@relayquill/signing";

export interface SenderKeyCustodyOptions {
  readonly getKeyMaterial?: WebhookKeyMaterialResolver | undefined;
  readonly secretProvider?: SecretProvider | undefined;
  readonly secretProviderConfig?: SecretProviderConfig | undefined;
  readonly ipcChannel?: IpcChannelRef | undefined;
  readonly initialInMemorySecrets?: Readonly<Record<string, string | Uint8Array>> | undefined;
  readonly env?: Readonly<Record<string, string | undefined>> | undefined;
  readonly resolveCustodyReference?: ((
    query: {
      readonly projectId: ProjectId;
      readonly endpointId: EndpointId;
      readonly keyId: KeyId;
    }
  ) => string | undefined) | undefined;
}

export interface RecordedKeyCustodyEntry {
  readonly custodyReference: string;
  readonly metadata: EndpointKeyMetadata;
}

function decodeKeyBytes(raw: string | Uint8Array, refLabel: string): Uint8Array {
  if (raw instanceof Uint8Array) {
    if (raw.byteLength === WEBHOOK_HMAC_KEY_BYTES) {
      return new Uint8Array(raw);
    }
    throw new ValidationDomainError({
      code: "SECRET_CUSTODY_ERROR",
      message: `Secret "${refLabel}" must be exactly ${WEBHOOK_HMAC_KEY_BYTES} bytes`
    });
  }

  const trimmed = raw.trim();
  if (/^[0-9a-f]{64}$/i.test(trimmed)) {
    return Uint8Array.from(Buffer.from(trimmed, "hex"));
  }

  if (/^[A-Za-z0-9_-]{43}=?$/.test(trimmed)) {
    const decoded = Buffer.from(trimmed, "base64url");
    if (decoded.byteLength === WEBHOOK_HMAC_KEY_BYTES) {
      return Uint8Array.from(decoded);
    }
  }

  if (/^[A-Za-z0-9+/]{43,44}=?=?$/.test(trimmed)) {
    const decoded = Buffer.from(trimmed, "base64");
    if (decoded.byteLength === WEBHOOK_HMAC_KEY_BYTES) {
      return Uint8Array.from(decoded);
    }
  }

  const utf8 = Buffer.from(trimmed, "utf8");
  if (utf8.byteLength === WEBHOOK_HMAC_KEY_BYTES) {
    return Uint8Array.from(utf8);
  }

  throw new ValidationDomainError({
    code: "SECRET_CUSTODY_ERROR",
    message: `Secret "${refLabel}" does not decode to ${WEBHOOK_HMAC_KEY_BYTES} HMAC key bytes`
  });
}

function extractSecretHandleBytes(handle: SecretHandle, refLabel: string): Uint8Array {
  return handle.useBytes((bytes) => decodeKeyBytes(bytes, refLabel));
}

export class SenderCustodyKeyProvider {
  readonly #injectedResolver: WebhookKeyMaterialResolver | undefined;
  readonly #secretProvider: SecretProvider | undefined;
  readonly #externalRefLookup: SenderKeyCustodyOptions["resolveCustodyReference"] | undefined;
  readonly #custodyEntries = new Map<string, RecordedKeyCustodyEntry>();

  constructor(options: SenderKeyCustodyOptions = {}) {
    this.#injectedResolver = options.getKeyMaterial;
    this.#externalRefLookup = options.resolveCustodyReference;

    if (options.secretProvider !== undefined) {
      this.#secretProvider = options.secretProvider;
    } else if (options.secretProviderConfig !== undefined) {
      const effectiveConfig =
        options.ipcChannel !== undefined
          ? { ...options.secretProviderConfig, ipc: options.ipcChannel }
          : options.secretProviderConfig;

      this.#secretProvider = createSecretProvider(effectiveConfig, {
        env: options.env,
        initialInMemorySecrets: options.initialInMemorySecrets
      });
    } else if (options.ipcChannel !== undefined) {
      this.#secretProvider = createLocalIpcProviderClient({
        ipc: options.ipcChannel,
        env: options.env
      });
    } else if (options.initialInMemorySecrets !== undefined) {
      this.#secretProvider = createSecretProvider(
        { mode: "in_memory_test" },
        { initialInMemorySecrets: options.initialInMemorySecrets }
      );
    }
  }

  recordKeyCustody(
    endpointId: EndpointId,
    keyId: KeyId,
    custodyReference: string,
    metadata: EndpointKeyMetadata
  ): void {
    this.#custodyEntries.set(`${endpointId}:${keyId}`, {
      custodyReference,
      metadata
    });
  }

  asResolver(): WebhookKeyMaterialResolver {
    if (this.#injectedResolver !== undefined) {
      return this.#injectedResolver;
    }

    return async (query) => {
      if (this.#secretProvider === undefined) {
        throw new DependencyUnavailableDomainError({
          code: "SECRET_CUSTODY_ERROR",
          message: `No secret provider or key resolver configured for key "${query.keyId}"`,
          retryable: false
        });
      }

      const projectId = parseProjectId(query.projectId, "projectId");
      const endpointId = parseEndpointId(query.endpointId, "endpointId");
      const keyId = parseKeyId(query.keyId, "keyId");
      const recorded = this.#custodyEntries.get(`${endpointId}:${keyId}`);
      const ref =
        this.#externalRefLookup?.({ projectId, endpointId, keyId }) ??
        recorded?.custodyReference ??
        `webhook_signing/${projectId}/${endpointId}/${keyId}`;

      const secretHandle = await this.#secretProvider.getSecret(ref);
      const rawBytes = extractSecretHandleBytes(secretHandle, ref);
      try {
        const keyHandle = createMemorySigningKeyHandle(rawBytes, {
          id: `${endpointId}:${keyId}`,
          require32Bytes: true
        });
        return {
          handle: keyHandle,
          ...(recorded !== undefined ? { metadata: recorded.metadata } : {}),
          releaseAfterUse: true
        };
      } finally {
        rawBytes.fill(0);
      }
    };
  }
}

export function createSenderCustodyKeyProvider(
  options: SenderKeyCustodyOptions = {}
): SenderCustodyKeyProvider {
  return new SenderCustodyKeyProvider(options);
}
