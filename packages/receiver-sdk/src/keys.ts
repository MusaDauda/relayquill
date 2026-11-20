import { parseEndpointId, parseKeyId, parseProjectId } from "@relayquill/contracts";
import type { EndpointId, KeyId, ProjectId, WebhookPurpose } from "@relayquill/domain";
import {
  type EndpointKeyMetadata,
  InMemoryWebhookKeyProvider,
  type ResolvedSigningKeyMaterial,
  type SigningKeyHandle,
  type VerificationKeyRecord,
  type WebhookKeyMaterialResolver,
  type WebhookVerificationKeyProvider,
  createMemorySigningKeyHandle,
  normalizeResolvedKeyMaterial
} from "@relayquill/signing";
import { ReceiverConfigError, ReceiverValidationError, toReceiverSdkError } from "./errors.js";

export type ReceiverKeyHandle = SigningKeyHandle;
export type ReceiverKeyMetadata = EndpointKeyMetadata;

export interface CreateReceiverKeyHandleOptions {
  readonly id?: string | undefined;
  readonly require32Bytes?: boolean | undefined;
}

export interface RegisterReceiverKeyInput {
  readonly projectId: ProjectId | string;
  readonly endpointId: EndpointId | string;
  readonly metadata: EndpointKeyMetadata;
  readonly secretBytes: Uint8Array;
}

export interface ResolveReceiverKeyQuery {
  readonly projectId: ProjectId | string;
  readonly endpointId: EndpointId | string;
  readonly keyId: KeyId | string;
}

export type ReceiverKeyResolverInput =
  | WebhookVerificationKeyProvider
  | InMemoryReceiverKeyProvider
  | InMemoryWebhookKeyProvider;

export function createReceiverKeyHandle(
  secretBytes: Uint8Array | Buffer,
  options?: CreateReceiverKeyHandleOptions
): SigningKeyHandle {
  try {
    return createMemorySigningKeyHandle(secretBytes, options);
  } catch (err) {
    throw toReceiverSdkError(err);
  }
}

export class InMemoryReceiverKeyProvider {
  readonly #inner = new InMemoryWebhookKeyProvider();

  registerKey(input: RegisterReceiverKeyInput): void {
    try {
      this.#inner.registerKey(input);
    } catch (err) {
      throw toReceiverSdkError(err);
    }
  }

  updateKeyMetadata(input: {
    readonly projectId: ProjectId | string;
    readonly endpointId: EndpointId | string;
    readonly metadata: EndpointKeyMetadata;
  }): void {
    try {
      this.#inner.updateKeyMetadata(input);
    } catch (err) {
      throw toReceiverSdkError(err);
    }
  }

  resolveKey(query: ResolveReceiverKeyQuery): ResolvedSigningKeyMaterial | null {
    try {
      return this.#inner.resolveKey({
        projectId: parseProjectId(query.projectId, "projectId"),
        endpointId: parseEndpointId(query.endpointId, "endpointId"),
        keyId: parseKeyId(query.keyId, "keyId")
      });
    } catch (err) {
      throw toReceiverSdkError(err);
    }
  }

  asVerificationKeyProvider(): WebhookVerificationKeyProvider {
    return (query) => this.#inner.resolveKey(query);
  }

  asSigningKeyResolver(): WebhookKeyMaterialResolver {
    return this.#inner.asResolver();
  }

  destroy(): void {
    this.#inner.destroy();
  }
}

export function normalizeVerificationKeyProvider(
  input: ReceiverKeyResolverInput
): WebhookVerificationKeyProvider {
  if (input instanceof InMemoryReceiverKeyProvider) {
    return input.asVerificationKeyProvider();
  }
  if (input instanceof InMemoryWebhookKeyProvider) {
    return (query) => input.resolveKey(query);
  }
  return input;
}

export async function withResolvedSigningMaterial<T>(
  input: {
    readonly keyHandle?: SigningKeyHandle | undefined;
    readonly keyMetadata?: EndpointKeyMetadata | undefined;
    readonly keyProvider?: ReceiverKeyResolverInput | undefined;
    readonly projectId: ProjectId | string;
    readonly endpointId: EndpointId | string;
    readonly keyId: KeyId | string;
    readonly purpose: WebhookPurpose;
  },
  fn: (material: {
    readonly handle: SigningKeyHandle;
    readonly metadata?: EndpointKeyMetadata | undefined;
  }) => Promise<T> | T
): Promise<T> {
  if (input.keyHandle !== undefined) {
    return await fn({
      handle: input.keyHandle,
      ...(input.keyMetadata !== undefined ? { metadata: input.keyMetadata } : {})
    });
  }

  if (input.keyProvider === undefined) {
    throw new ReceiverValidationError({
      code: "INVALID_VALUE",
      message: "Either keyHandle or keyProvider must be supplied"
    });
  }

  const provider = normalizeVerificationKeyProvider(input.keyProvider);
  const raw = await provider({
    projectId: parseProjectId(input.projectId, "projectId"),
    endpointId: parseEndpointId(input.endpointId, "endpointId"),
    keyId: parseKeyId(input.keyId, "keyId"),
    purpose: input.purpose
  });

  if (raw === null) {
    throw new ReceiverConfigError({
      code: "SECRET_CUSTODY_ERROR",
      message: `Signing key "${input.keyId}" is unavailable for endpoint "${input.endpointId}"`
    });
  }

  const normalized: VerificationKeyRecord | ResolvedSigningKeyMaterial =
    "metadata" in raw
      ? raw
      : normalizeResolvedKeyMaterial(raw);

  try {
    return await fn({
      handle: normalized.handle,
      ...(input.keyMetadata !== undefined
        ? { metadata: input.keyMetadata }
        : normalized.metadata !== undefined
          ? { metadata: normalized.metadata }
          : {})
    });
  } finally {
    if (normalized.releaseAfterUse === true) {
      normalized.handle.destroy?.();
    }
  }
}
