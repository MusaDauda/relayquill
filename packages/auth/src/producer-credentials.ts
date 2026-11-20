import crypto from "node:crypto";
import type { Temporal } from "@js-temporal/polyfill";
import {
  ALLOWED_PRODUCER_CREDENTIAL_TRANSITIONS,
  AuthenticationDomainError,
  AuthorizationDomainError,
  type ChannelKind,
  ConflictDomainError,
  type ControlEpoch,
  type EventTypeId,
  ExpiredDomainError,
  NotFoundDomainError,
  OpaqueSecret,
  PRODUCER_CREDENTIAL_INTENT_TTL_MS,
  PRODUCER_CREDENTIAL_MAX_OVERLAP_MS,
  PRODUCER_CREDENTIAL_MAX_TTL_MS,
  PRODUCER_CREDENTIAL_PREFIX,
  type PrincipalId,
  type ProducerCredentialId,
  type ProducerCredentialIntentId,
  type ProducerCredentialIntentState,
  type ProducerCredentialSelector,
  type ProducerCredentialState,
  type ProducerId,
  type ProducerNamespace,
  type ProducerScopeAction,
  type ProducerScopeVersionState,
  type ProducerState,
  type ProjectId,
  type Sha256Hex,
  type TenantId,
  ValidationDomainError,
  addMilliseconds,
  assertProducerChannelBinding,
  assertProducerCredentialTiming,
  assertProducerScopeBounds,
  assertTransition,
  compareInstants,
  formatProducerCredentialSelector,
  formatUtcTimestamp,
  isCanonicalUuid,
  isHumanWorkflowNamespace,
  isProducerScopeAction,
  minInstant,
  parseEventTypeId,
  parseProducerCredentialId,
  parseProducerCredentialIntentId,
  parseProducerCredentialToken,
  parseProducerId,
  parseProducerNamespace
} from "@relayquill/domain";
import {
  type CanonicalJsonValue,
  decodeBase64UrlStrict,
  encodeBase64Url,
  hashCanonicalJson,
  parsePositiveInt32,
  parseSafeReasonCode
} from "@relayquill/contracts";
import {
  type InstallationAuthoritySnapshot,
  PRODUCER_SECRET_BYTE_LENGTH,
  type PrincipalRecord,
  assertInstallationAllowsOrdinaryAccess,
  computeProducerCredentialDigest,
  constantTimeEqualBytes,
  digestBytesToSha256Hex,
  extractSafeSingleHeaderValue,
  randomBytesCopy,
  resolveSingleHeaderValue
} from "./primitives.js";

const DUMMY_CREDENTIAL_DIGEST = new Uint8Array(32);

export interface ProducerAllowedEventScope {
  readonly eventTypeId: EventTypeId;
  readonly schemaVersions: readonly number[];
}

export interface ProducerScopeDefinition {
  readonly allowedEvents: readonly ProducerAllowedEventScope[];
  readonly actions: readonly ProducerScopeAction[];
}

export interface ProducerRecord {
  readonly id: ProducerId;
  readonly tenantId: TenantId;
  readonly projectId: ProjectId;
  readonly principalId: PrincipalId;
  readonly principalKind: "producer" | "human";
  readonly channelKind: ChannelKind;
  readonly name: string;
  readonly businessNamespace: ProducerNamespace;
  readonly state: ProducerState;
  readonly currentScopeVersion: bigint | null;
  readonly authorityEpoch: bigint;
  readonly version: bigint;
}

export interface ProducerScopeVersionRecord {
  readonly producerId: ProducerId;
  readonly scopeVersion: bigint;
  readonly tenantId: TenantId;
  readonly projectId: ProjectId;
  readonly scopeDefinition: ProducerScopeDefinition;
  readonly scopeSha256: Uint8Array;
  readonly state: ProducerScopeVersionState;
}

export interface ProducerCredentialIntentRecord {
  readonly id: ProducerCredentialIntentId;
  readonly producerId: ProducerId;
  readonly tenantId: TenantId;
  readonly projectId: ProjectId;
  readonly channelKind: "machine_producer";
  readonly controlEpoch: ControlEpoch;
  readonly scopeVersion: bigint;
  readonly scopeSha256: Uint8Array;
  readonly requestedExpiry: Temporal.Instant;
  readonly custodyDestinationReference: string;
  readonly state: ProducerCredentialIntentState;
  readonly credentialId: ProducerCredentialId | null;
  readonly issuerPrincipalId: PrincipalId;
  readonly createdAt: Temporal.Instant;
  readonly expiresAt: Temporal.Instant;
  readonly version: bigint;
}

export interface ProducerCredentialRecord {
  readonly id: ProducerCredentialId;
  readonly producerId: ProducerId;
  readonly tenantId: TenantId;
  readonly projectId: ProjectId;
  readonly principalId: PrincipalId;
  readonly channelKind: "machine_producer";
  readonly controlEpoch: ControlEpoch;
  readonly secretDigest: Uint8Array;
  readonly state: ProducerCredentialState;
  readonly scopeVersion: bigint;
  readonly ownerAuthorityEpoch: bigint;
  readonly issuedBy: PrincipalId;
  readonly intentId: ProducerCredentialIntentId;
  readonly createdAt: Temporal.Instant;
  readonly expiresAt: Temporal.Instant;
  readonly activatedAt: Temporal.Instant | null;
  readonly overlapStartedAt: Temporal.Instant | null;
  readonly overlapEndsAt: Temporal.Instant | null;
  readonly revokedAt: Temporal.Instant | null;
  readonly version: bigint;
}

export interface ProducerCredentialSafeMetadata {
  readonly credential_id: ProducerCredentialId;
  readonly selector: ProducerCredentialSelector;
  readonly producer_id: ProducerId;
  readonly tenant_id: TenantId;
  readonly project_id: ProjectId;
  readonly channel_kind: "machine_producer";
  readonly state: ProducerCredentialState;
  readonly scope_version: string;
  readonly expires_at: string;
  readonly activated_at: string | null;
  readonly overlap_ends_at: string | null;
}

export function toSafeProducerCredentialMetadata(
  cred: ProducerCredentialRecord
): ProducerCredentialSafeMetadata {
  return Object.freeze({
    credential_id: cred.id,
    selector: formatProducerCredentialSelector(cred.id),
    producer_id: cred.producerId,
    tenant_id: cred.tenantId,
    project_id: cred.projectId,
    channel_kind: cred.channelKind,
    state: cred.state,
    scope_version: cred.scopeVersion.toString(10),
    expires_at: formatUtcTimestamp(cred.expiresAt),
    activated_at: cred.activatedAt !== null ? formatUtcTimestamp(cred.activatedAt) : null,
    overlap_ends_at: cred.overlapEndsAt !== null ? formatUtcTimestamp(cred.overlapEndsAt) : null
  });
}

export interface DecodedProducerBearerToken {
  readonly selector: ProducerCredentialSelector;
  readonly credentialId: ProducerCredentialId;
  readonly secretBytes: Uint8Array;
  destroy(): void;
}

export function parseProducerBearerTokenStrict(
  token: unknown,
  fieldPath = "authorization"
): DecodedProducerBearerToken {
  if (typeof token !== "string") {
    throw new ValidationDomainError({
      code: "INVALID_CREDENTIAL_SELECTOR",
      message: `Producer credential must be a string for ${fieldPath}`,
      fieldErrors: [{ path: fieldPath, code: "INVALID_CREDENTIAL_SELECTOR" }]
    });
  }
  const parts = token.split(".");
  if (parts.length !== 3 || parts[0] !== PRODUCER_CREDENTIAL_PREFIX) {
    throw new ValidationDomainError({
      code: "INVALID_CREDENTIAL_SELECTOR",
      message: `Malformed producer credential format for ${fieldPath}`,
      fieldErrors: [{ path: fieldPath, code: "INVALID_CREDENTIAL_SELECTOR" }]
    });
  }
  if (parts[1] === undefined || !isCanonicalUuid(parts[1])) {
    throw new ValidationDomainError({
      code: "INVALID_CREDENTIAL_SELECTOR",
      message: `Producer credential selector UUID must be canonical lowercase for ${fieldPath}`,
      fieldErrors: [{ path: fieldPath, code: "INVALID_CREDENTIAL_SELECTOR" }]
    });
  }

  const parsed = parseProducerCredentialToken(token, fieldPath);
  const rawTokenPart = parsed.secret.expose();
  const secretBytes = decodeBase64UrlStrict(rawTokenPart, fieldPath, {
    exactByteLength: PRODUCER_SECRET_BYTE_LENGTH
  });

  return Object.freeze({
    selector: parsed.selector,
    credentialId: parsed.credentialId,
    secretBytes,
    destroy(): void {
      secretBytes.fill(0);
    }
  });
}

export function extractBearerTokenFromAuthorizationHeader(
  headerValue: string | readonly string[] | undefined
): string {
  const singleHeader = resolveSingleHeaderValue(
    headerValue,
    "Duplicate Authorization header rejected",
    (message) => new AuthenticationDomainError({ code: "UNAUTHENTICATED", message })
  );
  if (singleHeader === null) {
    throw new AuthenticationDomainError({
      code: "UNAUTHENTICATED",
      message: "Missing Authorization bearer header"
    });
  }
  if (!singleHeader.startsWith("Bearer ")) {
    throw new AuthenticationDomainError({
      code: "UNAUTHENTICATED",
      message: "Authorization header must use Bearer scheme"
    });
  }
  const token = singleHeader.slice("Bearer ".length);
  if (token.length === 0 || /\s/.test(token)) {
    throw new AuthenticationDomainError({
      code: "UNAUTHENTICATED",
      message: "Malformed Bearer credential token"
    });
  }
  return token;
}

export function extractBearerTokenFromRawHeaders(rawHeaders: readonly string[]): string {
  const headerValue = extractSafeSingleHeaderValue(rawHeaders, "authorization");
  if (headerValue === null) {
    throw new AuthenticationDomainError({
      code: "UNAUTHENTICATED",
      message: "Missing Authorization header"
    });
  }
  return extractBearerTokenFromAuthorizationHeader(headerValue);
}

export interface GeneratedProducerCredentialMaterial {
  readonly credentialId: ProducerCredentialId;
  readonly selector: ProducerCredentialSelector;
  readonly bearerToken: OpaqueSecret<string>;
  readonly secretDigest: Uint8Array;
  readonly secretDigestSha256: Sha256Hex;
}

export function generateProducerCredentialMaterial(
  credentialIdInput?: ProducerCredentialId | string
): GeneratedProducerCredentialMaterial {
  const credentialId = parseProducerCredentialId(
    credentialIdInput ?? crypto.randomUUID(),
    "credential_id"
  );
  const secretBytes = randomBytesCopy(PRODUCER_SECRET_BYTE_LENGTH);
  try {
    const secretB64 = encodeBase64Url(secretBytes);
    const selector = formatProducerCredentialSelector(credentialId);
    const bearerToken = new OpaqueSecret(`${selector}.${secretB64}`);
    const secretDigest = computeProducerCredentialDigest(credentialId, secretBytes);
    const secretDigestSha256 = digestBytesToSha256Hex(secretDigest, "secret_digest");
    return Object.freeze({
      credentialId,
      selector,
      bearerToken,
      secretDigest,
      secretDigestSha256
    });
  } finally {
    secretBytes.fill(0);
  }
}

export function validateAndHashProducerScopeDefinition(input: {
  readonly allowedEvents: readonly {
    readonly eventTypeId: EventTypeId | string;
    readonly schemaVersions: readonly number[];
  }[];
  readonly actions: readonly string[];
}): {
  readonly definition: ProducerScopeDefinition;
  readonly scopeSha256: Uint8Array;
  readonly scopeSha256Hex: Sha256Hex;
} {
  const isRuntimeArray = (value: unknown): value is readonly unknown[] => Array.isArray(value);
  const allowedEventsInput: readonly {
    readonly eventTypeId: EventTypeId | string;
    readonly schemaVersions: readonly number[];
  }[] = input.allowedEvents;
  const actionsInput: readonly string[] = input.actions;
  if (!isRuntimeArray(allowedEventsInput) || allowedEventsInput.length === 0) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: "Producer scope must allow at least one event type"
    });
  }
  if (!isRuntimeArray(actionsInput) || actionsInput.length === 0) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: "Producer scope must grant at least one action"
    });
  }

  let maxVersions = 0;
  const seenEventTypes = new Set<EventTypeId>();
  const normalizedEvents: ProducerAllowedEventScope[] = [];

  for (let i = 0; i < allowedEventsInput.length; i += 1) {
    const entry = allowedEventsInput[i];
    if (entry === undefined) {
      continue;
    }
    const eventTypeId = parseEventTypeId(entry.eventTypeId, `allowed_events[${i}].event_type_id`);
    if (seenEventTypes.has(eventTypeId)) {
      throw new ValidationDomainError({
        code: "INVALID_VALUE",
        message: `Duplicate event_type_id "${eventTypeId}" in producer scope`
      });
    }
    seenEventTypes.add(eventTypeId);

    const schemaVersionsInput: readonly number[] = entry.schemaVersions;
    if (!isRuntimeArray(schemaVersionsInput) || schemaVersionsInput.length === 0) {
      throw new ValidationDomainError({
        code: "INVALID_VALUE",
        message: `Producer scope entry for ${eventTypeId} requires 1..16 schema versions`
      });
    }
    if (schemaVersionsInput.length > maxVersions) {
      maxVersions = schemaVersionsInput.length;
    }
    const versionSet = new Set<number>();
    for (const v of schemaVersionsInput) {
      const parsedVersion = parsePositiveInt32(v, `allowed_events[${i}].schema_versions`);
      if (versionSet.has(parsedVersion)) {
        throw new ValidationDomainError({
          code: "INVALID_VALUE",
          message: `Duplicate schema_version ${parsedVersion} for ${eventTypeId}`
        });
      }
      versionSet.add(parsedVersion);
    }
    const sortedVersions = Object.freeze(Array.from(versionSet).sort((a, b) => a - b));
    normalizedEvents.push(
      Object.freeze({
        eventTypeId,
        schemaVersions: sortedVersions
      })
    );
  }

  assertProducerScopeBounds(normalizedEvents.length, maxVersions);
  normalizedEvents.sort((a, b) => (a.eventTypeId < b.eventTypeId ? -1 : a.eventTypeId > b.eventTypeId ? 1 : 0));

  const actionSet = new Set<ProducerScopeAction>();
  for (let i = 0; i < actionsInput.length; i += 1) {
    const action = actionsInput[i];
    if (!isProducerScopeAction(action)) {
      throw new AuthorizationDomainError({
        code: "FORBIDDEN",
        message: `Unsupported or privileged action "${String(action)}" cannot be placed in a producer scope`
      });
    }
    actionSet.add(action);
  }
  const sortedActions = Object.freeze(Array.from(actionSet).sort());

  const definition: ProducerScopeDefinition = Object.freeze({
    allowedEvents: Object.freeze(normalizedEvents),
    actions: sortedActions
  });

  const canonicalObj: CanonicalJsonValue = {
    actions: sortedActions,
    allowed_events: normalizedEvents.map((ev) => ({
      event_type_id: ev.eventTypeId,
      schema_versions: [...ev.schemaVersions]
    }))
  };
  const hashed = hashCanonicalJson(canonicalObj, "producer_scope");
  const scopeSha256 = new Uint8Array(crypto.createHash("sha256").update(hashed.bytes).digest());

  return Object.freeze({
    definition,
    scopeSha256,
    scopeSha256Hex: hashed.sha256
  });
}

export function assertMachineProducerChannel(producer: ProducerRecord): void {
  if (producer.channelKind !== "machine_producer" || producer.principalKind !== "producer") {
    throw new AuthorizationDomainError({
      code: "FORBIDDEN",
      message: "Producer credentials apply only to machine_producer channels"
    });
  }
  if (isHumanWorkflowNamespace(producer.businessNamespace)) {
    throw new AuthorizationDomainError({
      code: "FORBIDDEN",
      message: "human_workflow namespace cannot hold machine producer credentials"
    });
  }
  assertProducerChannelBinding(
    producer.channelKind,
    producer.principalKind,
    producer.businessNamespace
  );
}

export function assertHumanWorkflowNamespace(
  principalId: PrincipalId,
  namespace: ProducerNamespace | string
): ProducerNamespace {
  const parsedNs = parseProducerNamespace(namespace, "producer_namespace");
  const expected = `human.${principalId}`;
  if (!isHumanWorkflowNamespace(parsedNs) || parsedNs !== expected || namespace !== expected) {
    throw new AuthorizationDomainError({
      code: "FORBIDDEN",
      message: "human_workflow channel must bind strictly to human.<actor-principal-uuid>"
    });
  }
  assertProducerChannelBinding("human_workflow", "human", parsedNs);
  return parsedNs;
}

export interface ProducerCredentialRepository {
  findProducerById(producerId: ProducerId): Promise<ProducerRecord | null>;
  findPrincipalById(principalId: PrincipalId): Promise<PrincipalRecord | null>;
  findScopeVersion(
    producerId: ProducerId,
    scopeVersion: bigint
  ): Promise<ProducerScopeVersionRecord | null>;
  findCredentialIntentById(
    intentId: ProducerCredentialIntentId
  ): Promise<ProducerCredentialIntentRecord | null>;
  findCredentialById(
    credentialId: ProducerCredentialId
  ): Promise<ProducerCredentialRecord | null>;
  createCredentialIntent(input: {
    readonly id: ProducerCredentialIntentId;
    readonly producerId: ProducerId;
    readonly tenantId: TenantId;
    readonly projectId: ProjectId;
    readonly controlEpoch: ControlEpoch;
    readonly scopeVersion: bigint;
    readonly scopeSha256: Uint8Array;
    readonly requestedExpiry: Temporal.Instant;
    readonly custodyDestinationReference: string;
    readonly issuerPrincipalId: PrincipalId;
    readonly createdAt: Temporal.Instant;
    readonly expiresAt: Temporal.Instant;
  }): Promise<ProducerCredentialIntentRecord>;
  recordDeliveredCredential(input: {
    readonly intentId: ProducerCredentialIntentId;
    readonly expectedIntentVersion: bigint;
    readonly credentialId: ProducerCredentialId;
    readonly secretDigest: Uint8Array;
    readonly expiresAt: Temporal.Instant;
    readonly now: Temporal.Instant;
  }): Promise<{
    readonly intent: ProducerCredentialIntentRecord;
    readonly credential: ProducerCredentialRecord;
  }>;
  activateCredentialAtomic(input: {
    readonly intentId: ProducerCredentialIntentId;
    readonly expectedIntentVersion: bigint;
    readonly credentialId: ProducerCredentialId;
    readonly expectedCredentialVersion: bigint;
    readonly now: Temporal.Instant;
  }): Promise<{
    readonly intent: ProducerCredentialIntentRecord;
    readonly credential: ProducerCredentialRecord;
  }>;
  rotateCredentialOverlapAtomic(input: {
    readonly oldCredentialId: ProducerCredentialId;
    readonly expectedOldVersion: bigint;
    readonly newCredentialId: ProducerCredentialId;
    readonly expectedNewVersion: bigint;
    readonly overlapStartedAt: Temporal.Instant;
    readonly overlapEndsAt: Temporal.Instant;
    readonly now: Temporal.Instant;
  }): Promise<{
    readonly oldCredential: ProducerCredentialRecord;
    readonly newCredential: ProducerCredentialRecord;
  }>;
  revokeCredential(input: {
    readonly credentialId: ProducerCredentialId;
    readonly expectedVersion: bigint;
    readonly revokedAt: Temporal.Instant;
  }): Promise<ProducerCredentialRecord>;
}

export class InMemoryProducerCredentialRepository implements ProducerCredentialRepository {
  readonly #producers = new Map<ProducerId, ProducerRecord>();
  readonly #principals = new Map<PrincipalId, PrincipalRecord>();
  readonly #scopes = new Map<string, ProducerScopeVersionRecord>();
  readonly #intents = new Map<ProducerCredentialIntentId, ProducerCredentialIntentRecord>();
  readonly #credentials = new Map<ProducerCredentialId, ProducerCredentialRecord>();

  seedProducer(input: {
    readonly producer: ProducerRecord;
    readonly principal: PrincipalRecord;
    readonly scopes?: readonly ProducerScopeVersionRecord[] | undefined;
  }): void {
    this.#producers.set(input.producer.id, input.producer);
    this.#principals.set(input.principal.principalId, input.principal);
    for (const s of input.scopes ?? []) {
      this.#scopes.set(`${s.producerId}:${s.scopeVersion.toString(10)}`, s);
    }
  }

  updateProducer(producer: ProducerRecord): void {
    this.#producers.set(producer.id, producer);
  }

  updatePrincipal(principal: PrincipalRecord): void {
    this.#principals.set(principal.principalId, principal);
  }

  putScopeVersion(scope: ProducerScopeVersionRecord): void {
    this.#scopes.set(`${scope.producerId}:${scope.scopeVersion.toString(10)}`, scope);
  }

  findProducerById(producerId: ProducerId): Promise<ProducerRecord | null> {
    return Promise.resolve(this.#producers.get(producerId) ?? null);
  }

  findPrincipalById(principalId: PrincipalId): Promise<PrincipalRecord | null> {
    return Promise.resolve(this.#principals.get(principalId) ?? null);
  }

  findScopeVersion(
    producerId: ProducerId,
    scopeVersion: bigint
  ): Promise<ProducerScopeVersionRecord | null> {
    return Promise.resolve(
      this.#scopes.get(`${producerId}:${scopeVersion.toString(10)}`) ?? null
    );
  }

  findCredentialIntentById(
    intentId: ProducerCredentialIntentId
  ): Promise<ProducerCredentialIntentRecord | null> {
    return Promise.resolve(this.#intents.get(intentId) ?? null);
  }

  findCredentialById(
    credentialId: ProducerCredentialId
  ): Promise<ProducerCredentialRecord | null> {
    return Promise.resolve(this.#credentials.get(credentialId) ?? null);
  }

  createCredentialIntent(input: {
    readonly id: ProducerCredentialIntentId;
    readonly producerId: ProducerId;
    readonly tenantId: TenantId;
    readonly projectId: ProjectId;
    readonly controlEpoch: ControlEpoch;
    readonly scopeVersion: bigint;
    readonly scopeSha256: Uint8Array;
    readonly requestedExpiry: Temporal.Instant;
    readonly custodyDestinationReference: string;
    readonly issuerPrincipalId: PrincipalId;
    readonly createdAt: Temporal.Instant;
    readonly expiresAt: Temporal.Instant;
  }): Promise<ProducerCredentialIntentRecord> {
    if (this.#intents.has(input.id)) {
      return Promise.reject(
        new ConflictDomainError({
          code: "VERSION_CONFLICT",
          message: "Producer credential intent already exists"
        })
      );
    }
    const record: ProducerCredentialIntentRecord = Object.freeze({
      id: input.id,
      producerId: input.producerId,
      tenantId: input.tenantId,
      projectId: input.projectId,
      channelKind: "machine_producer",
      controlEpoch: input.controlEpoch,
      scopeVersion: input.scopeVersion,
      scopeSha256: new Uint8Array(input.scopeSha256),
      requestedExpiry: input.requestedExpiry,
      custodyDestinationReference: input.custodyDestinationReference,
      state: "approved",
      credentialId: null,
      issuerPrincipalId: input.issuerPrincipalId,
      createdAt: input.createdAt,
      expiresAt: input.expiresAt,
      version: 1n
    });
    this.#intents.set(record.id, record);
    return Promise.resolve(record);
  }

  recordDeliveredCredential(input: {
    readonly intentId: ProducerCredentialIntentId;
    readonly expectedIntentVersion: bigint;
    readonly credentialId: ProducerCredentialId;
    readonly secretDigest: Uint8Array;
    readonly expiresAt: Temporal.Instant;
    readonly now: Temporal.Instant;
  }): Promise<{
    readonly intent: ProducerCredentialIntentRecord;
    readonly credential: ProducerCredentialRecord;
  }> {
    const intent = this.#intents.get(input.intentId);
    if (intent === undefined) {
      return Promise.reject(
        new NotFoundDomainError({ code: "NOT_FOUND", message: "Credential intent not found" })
      );
    }
    if (intent.version !== input.expectedIntentVersion) {
      return Promise.reject(
        new ConflictDomainError({ code: "VERSION_CONFLICT", message: "Credential intent version conflict" })
      );
    }
    if (intent.state !== "approved" && intent.state !== "delivering") {
      return Promise.reject(
        new ConflictDomainError({
          code: "STATE_TRANSITION_NOT_ALLOWED",
          message: `Cannot record delivery for intent in state "${intent.state}"`
        })
      );
    }
    const producer = this.#producers.get(intent.producerId);
    if (producer === undefined) {
      return Promise.reject(
        new NotFoundDomainError({ code: "NOT_FOUND", message: "Producer not found" })
      );
    }
    if (this.#credentials.has(input.credentialId)) {
      return Promise.reject(
        new ConflictDomainError({ code: "VERSION_CONFLICT", message: "Credential ID already exists" })
      );
    }

    const credential: ProducerCredentialRecord = Object.freeze({
      id: input.credentialId,
      producerId: intent.producerId,
      tenantId: intent.tenantId,
      projectId: intent.projectId,
      principalId: producer.principalId,
      channelKind: "machine_producer",
      controlEpoch: intent.controlEpoch,
      secretDigest: new Uint8Array(input.secretDigest),
      state: "pending_activation",
      scopeVersion: intent.scopeVersion,
      ownerAuthorityEpoch: producer.authorityEpoch,
      issuedBy: intent.issuerPrincipalId,
      intentId: intent.id,
      createdAt: input.now,
      expiresAt: input.expiresAt,
      activatedAt: null,
      overlapStartedAt: null,
      overlapEndsAt: null,
      revokedAt: null,
      version: 1n
    });
    const updatedIntent: ProducerCredentialIntentRecord = Object.freeze({
      ...intent,
      state: "delivered",
      credentialId: credential.id,
      version: intent.version + 1n
    });
    this.#credentials.set(credential.id, credential);
    this.#intents.set(updatedIntent.id, updatedIntent);
    return Promise.resolve({ intent: updatedIntent, credential });
  }

  activateCredentialAtomic(input: {
    readonly intentId: ProducerCredentialIntentId;
    readonly expectedIntentVersion: bigint;
    readonly credentialId: ProducerCredentialId;
    readonly expectedCredentialVersion: bigint;
    readonly now: Temporal.Instant;
  }): Promise<{
    readonly intent: ProducerCredentialIntentRecord;
    readonly credential: ProducerCredentialRecord;
  }> {
    const intent = this.#intents.get(input.intentId);
    const cred = this.#credentials.get(input.credentialId);
    if (intent === undefined || cred === undefined) {
      return Promise.reject(
        new NotFoundDomainError({ code: "NOT_FOUND", message: "Credential or intent not found" })
      );
    }
    if (intent.version !== input.expectedIntentVersion) {
      return Promise.reject(
        new ConflictDomainError({ code: "VERSION_CONFLICT", message: "Credential intent version conflict" })
      );
    }
    if (cred.version !== input.expectedCredentialVersion) {
      return Promise.reject(
        new ConflictDomainError({ code: "VERSION_CONFLICT", message: "Credential version conflict" })
      );
    }
    assertTransition(
      "producer_credential",
      ALLOWED_PRODUCER_CREDENTIAL_TRANSITIONS,
      cred.state,
      "active",
      { kind: "producer_credential", id: cred.id }
    );
    const updatedCred: ProducerCredentialRecord = Object.freeze({
      ...cred,
      state: "active",
      activatedAt: input.now,
      version: cred.version + 1n
    });
    const updatedIntent: ProducerCredentialIntentRecord = Object.freeze({
      ...intent,
      state: "activated",
      version: intent.version + 1n
    });
    this.#credentials.set(updatedCred.id, updatedCred);
    this.#intents.set(updatedIntent.id, updatedIntent);
    return Promise.resolve({ intent: updatedIntent, credential: updatedCred });
  }

  rotateCredentialOverlapAtomic(input: {
    readonly oldCredentialId: ProducerCredentialId;
    readonly expectedOldVersion: bigint;
    readonly newCredentialId: ProducerCredentialId;
    readonly expectedNewVersion: bigint;
    readonly overlapStartedAt: Temporal.Instant;
    readonly overlapEndsAt: Temporal.Instant;
    readonly now: Temporal.Instant;
  }): Promise<{
    readonly oldCredential: ProducerCredentialRecord;
    readonly newCredential: ProducerCredentialRecord;
  }> {
    const oldCred = this.#credentials.get(input.oldCredentialId);
    const newCred = this.#credentials.get(input.newCredentialId);
    if (oldCred === undefined || newCred === undefined) {
      return Promise.reject(
        new NotFoundDomainError({ code: "NOT_FOUND", message: "Producer credential not found" })
      );
    }
    if (oldCred.version !== input.expectedOldVersion) {
      return Promise.reject(
        new ConflictDomainError({ code: "VERSION_CONFLICT", message: "Old credential version conflict" })
      );
    }
    if (newCred.version !== input.expectedNewVersion) {
      return Promise.reject(
        new ConflictDomainError({ code: "VERSION_CONFLICT", message: "New credential version conflict" })
      );
    }
    assertTransition(
      "producer_credential",
      ALLOWED_PRODUCER_CREDENTIAL_TRANSITIONS,
      oldCred.state,
      "overlap",
      { kind: "producer_credential", id: oldCred.id }
    );
    const updatedOld: ProducerCredentialRecord = Object.freeze({
      ...oldCred,
      state: "overlap",
      overlapStartedAt: input.overlapStartedAt,
      overlapEndsAt: input.overlapEndsAt,
      version: oldCred.version + 1n
    });
    let updatedNew = newCred;
    if (newCred.state === "pending_activation") {
      assertTransition(
        "producer_credential",
        ALLOWED_PRODUCER_CREDENTIAL_TRANSITIONS,
        newCred.state,
        "active",
        { kind: "producer_credential", id: newCred.id }
      );
      updatedNew = Object.freeze({
        ...newCred,
        state: "active",
        activatedAt: input.now,
        version: newCred.version + 1n
      });
    }
    this.#credentials.set(updatedOld.id, updatedOld);
    this.#credentials.set(updatedNew.id, updatedNew);
    return Promise.resolve({ oldCredential: updatedOld, newCredential: updatedNew });
  }

  revokeCredential(input: {
    readonly credentialId: ProducerCredentialId;
    readonly expectedVersion: bigint;
    readonly revokedAt: Temporal.Instant;
  }): Promise<ProducerCredentialRecord> {
    const current = this.#credentials.get(input.credentialId);
    if (current === undefined) {
      return Promise.reject(
        new NotFoundDomainError({ code: "NOT_FOUND", message: "Producer credential not found" })
      );
    }
    if (current.version !== input.expectedVersion) {
      return Promise.reject(
        new ConflictDomainError({ code: "VERSION_CONFLICT", message: "Credential version conflict" })
      );
    }
    if (current.state === "revoked") {
      return Promise.resolve(current);
    }
    assertTransition(
      "producer_credential",
      ALLOWED_PRODUCER_CREDENTIAL_TRANSITIONS,
      current.state,
      "revoked",
      { kind: "producer_credential", id: current.id }
    );
    const revoked: ProducerCredentialRecord = Object.freeze({
      ...current,
      state: "revoked",
      revokedAt: input.revokedAt,
      version: current.version + 1n
    });
    this.#credentials.set(revoked.id, revoked);
    return Promise.resolve(revoked);
  }
}

export async function issueProducerCredentialIntent(input: {
  readonly installation: InstallationAuthoritySnapshot;
  readonly producerId: ProducerId | string;
  readonly expectedProducerVersion: bigint;
  readonly scopeVersion: bigint;
  readonly requestedExpiry: Temporal.Instant;
  readonly custodyDestinationId: string;
  readonly allowedCustodyDestinations: ReadonlySet<string> | readonly string[];
  readonly issuerPrincipalId: PrincipalId;
  readonly repo: ProducerCredentialRepository;
  readonly now: Temporal.Instant;
}): Promise<ProducerCredentialIntentRecord> {
  assertInstallationAllowsOrdinaryAccess(input.installation, "producer credential issuance");
  const producerId = parseProducerId(input.producerId, "producer_id");
  const custodyId = parseSafeReasonCode(input.custodyDestinationId, "custody_destination_id");

  const allowedDestinations = Array.isArray(input.allowedCustodyDestinations)
    ? new Set(input.allowedCustodyDestinations)
    : (input.allowedCustodyDestinations as ReadonlySet<string>);
  if (!allowedDestinations.has(custodyId)) {
    throw new AuthorizationDomainError({
      code: "FORBIDDEN",
      message: `Custody destination "${custodyId}" is not in trusted configuration allowlist`
    });
  }

  const producer = await input.repo.findProducerById(producerId);
  if (producer === null) {
    throw new NotFoundDomainError({ code: "NOT_FOUND", message: "Producer not found" });
  }
  assertMachineProducerChannel(producer);
  if (producer.version !== input.expectedProducerVersion) {
    throw new ConflictDomainError({
      code: "VERSION_CONFLICT",
      message: "Producer version mismatch"
    });
  }
  if (producer.state === "suspended" || producer.state === "retired") {
    throw new ConflictDomainError({
      code: "STATE_TRANSITION_NOT_ALLOWED",
      message: `Cannot issue credential for producer in state "${producer.state}"`
    });
  }

  const scope = await input.repo.findScopeVersion(producer.id, input.scopeVersion);
  if (scope === null) {
    throw new NotFoundDomainError({ code: "NOT_FOUND", message: "Producer scope version not found" });
  }
  if (scope.state !== "approved" && scope.state !== "active") {
    throw new ConflictDomainError({
      code: "STATE_TRANSITION_NOT_ALLOWED",
      message: `Credential intent requires approved or active scope version, got "${scope.state}"`
    });
  }

  const candidateId = parseProducerCredentialId(crypto.randomUUID(), "credential_id");
  assertProducerCredentialTiming({
    credentialId: candidateId,
    issuedAt: input.now,
    expiresAt: input.requestedExpiry
  });

  const intentExpiresAt = addMilliseconds(
    input.now,
    PRODUCER_CREDENTIAL_INTENT_TTL_MS,
    "credential_intent_expires_at"
  );

  return input.repo.createCredentialIntent({
    id: parseProducerCredentialIntentId(crypto.randomUUID(), "intent_id"),
    producerId: producer.id,
    tenantId: producer.tenantId,
    projectId: producer.projectId,
    controlEpoch: input.installation.controlEpoch,
    scopeVersion: scope.scopeVersion,
    scopeSha256: scope.scopeSha256,
    requestedExpiry: input.requestedExpiry,
    custodyDestinationReference: custodyId,
    issuerPrincipalId: input.issuerPrincipalId,
    createdAt: input.now,
    expiresAt: intentExpiresAt
  });
}

export async function deliverProducerCredentialToCustody(input: {
  readonly installation: InstallationAuthoritySnapshot;
  readonly intentId: ProducerCredentialIntentId | string;
  readonly expectedIntentVersion: bigint;
  readonly deliverSecret: (ctx: {
    readonly custodyDestinationReference: string;
    readonly credentialId: ProducerCredentialId;
    readonly selector: ProducerCredentialSelector;
    readonly bearerToken: OpaqueSecret<string>;
    readonly expiresAt: Temporal.Instant;
  }) => Promise<void>;
  readonly repo: ProducerCredentialRepository;
  readonly now: Temporal.Instant;
}): Promise<{
  readonly intent: ProducerCredentialIntentRecord;
  readonly credential: ProducerCredentialSafeMetadata;
}> {
  assertInstallationAllowsOrdinaryAccess(input.installation, "producer credential delivery");
  const intentId = parseProducerCredentialIntentId(input.intentId, "intent_id");
  const intent = await input.repo.findCredentialIntentById(intentId);
  if (intent === null) {
    throw new NotFoundDomainError({ code: "NOT_FOUND", message: "Credential intent not found" });
  }
  if (intent.version !== input.expectedIntentVersion) {
    throw new ConflictDomainError({
      code: "VERSION_CONFLICT",
      message: "Credential intent version conflict"
    });
  }
  if (intent.controlEpoch !== input.installation.controlEpoch) {
    throw new ConflictDomainError({
      code: "STATE_TRANSITION_NOT_ALLOWED",
      message: "Credential intent belongs to a stale control epoch"
    });
  }
  if (compareInstants(input.now, intent.expiresAt) >= 0) {
    throw new ExpiredDomainError({
      code: "EXPIRED",
      message: "Credential intent has expired"
    });
  }

  const maxExpiry = addMilliseconds(input.now, PRODUCER_CREDENTIAL_MAX_TTL_MS, "max_expiry");
  const effectiveExpiry = minInstant(intent.requestedExpiry, maxExpiry);
  const material = generateProducerCredentialMaterial();

  await input.deliverSecret({
    custodyDestinationReference: intent.custodyDestinationReference,
    credentialId: material.credentialId,
    selector: material.selector,
    bearerToken: material.bearerToken,
    expiresAt: effectiveExpiry
  });

  const recorded = await input.repo.recordDeliveredCredential({
    intentId: intent.id,
    expectedIntentVersion: intent.version,
    credentialId: material.credentialId,
    secretDigest: material.secretDigest,
    expiresAt: effectiveExpiry,
    now: input.now
  });

  return Object.freeze({
    intent: recorded.intent,
    credential: toSafeProducerCredentialMetadata(recorded.credential)
  });
}

export async function activateProducerCredentialByPossession(input: {
  readonly installation: InstallationAuthoritySnapshot;
  readonly intentId: ProducerCredentialIntentId | string;
  readonly expectedIntentVersion: bigint;
  readonly bearerToken: string;
  readonly repo: ProducerCredentialRepository;
  readonly now: Temporal.Instant;
}): Promise<{
  readonly activated: true;
  readonly matched_existing: boolean;
  readonly credential: ProducerCredentialSafeMetadata;
  readonly scope_active_for_admission: boolean;
}> {
  const intentId = parseProducerCredentialIntentId(input.intentId, "intent_id");
  const decoded = parseProducerBearerTokenStrict(input.bearerToken, "authorization");
  let digest: Uint8Array;
  try {
    digest = computeProducerCredentialDigest(decoded.credentialId, decoded.secretBytes);
  } finally {
    decoded.destroy();
  }

  const intent = await input.repo.findCredentialIntentById(intentId);
  if (intent === null || intent.credentialId !== decoded.credentialId) {
    throw new AuthenticationDomainError({
      code: "UNAUTHENTICATED",
      message: "Producer credential activation failed"
    });
  }
  const cred = await input.repo.findCredentialById(decoded.credentialId);
  if (cred === null || !constantTimeEqualBytes(digest, cred.secretDigest)) {
    throw new AuthenticationDomainError({
      code: "UNAUTHENTICATED",
      message: "Producer credential activation failed"
    });
  }

  const producer = await input.repo.findProducerById(intent.producerId);
  const principal =
    producer !== null ? await input.repo.findPrincipalById(producer.principalId) : null;

  assertInstallationAllowsOrdinaryAccess(input.installation, "producer credential activation");
  if (
    intent.controlEpoch !== input.installation.controlEpoch ||
    cred.controlEpoch !== input.installation.controlEpoch
  ) {
    throw new AuthenticationDomainError({
      code: "UNAUTHENTICATED",
      message: "Producer credential control epoch is stale"
    });
  }
  if (producer === null || principal === null) {
    throw new NotFoundDomainError({ code: "NOT_FOUND", message: "Producer or principal not found" });
  }
  assertMachineProducerChannel(producer);
  if (producer.state === "suspended" || producer.state === "retired") {
    throw new AuthorizationDomainError({
      code: "FORBIDDEN",
      message: `Producer in state "${producer.state}" cannot activate credentials`
    });
  }
  if (principal.state === "suspended" || principal.state === "retired") {
    throw new AuthorizationDomainError({
      code: "FORBIDDEN",
      message: `Principal in state "${principal.state}" cannot activate credentials`
    });
  }
  if (
    cred.ownerAuthorityEpoch !== producer.authorityEpoch ||
    cred.ownerAuthorityEpoch !== principal.authorityEpoch
  ) {
    throw new AuthenticationDomainError({
      code: "UNAUTHENTICATED",
      message: "Producer authority epoch changed after credential issuance"
    });
  }

  // Idempotent accepted-activation recovery bypasses initial delivered/expiry gates only
  if (intent.state === "activated" && (cred.state === "active" || cred.state === "overlap")) {
    return Object.freeze({
      activated: true,
      matched_existing: true,
      credential: toSafeProducerCredentialMetadata(cred),
      scope_active_for_admission:
        producer.state === "active" && producer.currentScopeVersion === cred.scopeVersion
    });
  }

  if (intent.version !== input.expectedIntentVersion) {
    throw new ConflictDomainError({
      code: "VERSION_CONFLICT",
      message: "Credential intent version mismatch"
    });
  }
  if (intent.state !== "delivered" || cred.state !== "pending_activation") {
    throw new ConflictDomainError({
      code: "STATE_TRANSITION_NOT_ALLOWED",
      message: "Producer credential is not awaiting possession activation"
    });
  }
  if (compareInstants(input.now, intent.expiresAt) >= 0) {
    throw new ExpiredDomainError({
      code: "EXPIRED",
      message: "Producer credential intent has expired"
    });
  }
  if (compareInstants(input.now, cred.expiresAt) >= 0) {
    throw new ExpiredDomainError({
      code: "EXPIRED",
      message: "Producer credential has expired"
    });
  }

  const activated = await input.repo.activateCredentialAtomic({
    intentId: intent.id,
    expectedIntentVersion: intent.version,
    credentialId: cred.id,
    expectedCredentialVersion: cred.version,
    now: input.now
  });

  return Object.freeze({
    activated: true,
    matched_existing: false,
    credential: toSafeProducerCredentialMetadata(activated.credential),
    scope_active_for_admission:
      producer.state === "active" && producer.currentScopeVersion === activated.credential.scopeVersion
  });
}

export interface AuthenticatedProducerCredential {
  readonly credential: ProducerCredentialSafeMetadata;
  readonly producer: ProducerRecord;
  readonly principal: PrincipalRecord;
  readonly scope: ProducerScopeVersionRecord;
}

export async function authenticateProducerCredential(input: {
  readonly installation: InstallationAuthoritySnapshot;
  readonly bearerToken: string;
  readonly repo: ProducerCredentialRepository;
  readonly now: Temporal.Instant;
  readonly purpose?: "ordinary" | "activation_or_self_metadata" | undefined;
  readonly requiredAction?: ProducerScopeAction | undefined;
  readonly requiredEvent?: {
    readonly eventTypeId: EventTypeId | string;
    readonly schemaVersion: number;
  } | undefined;
}): Promise<AuthenticatedProducerCredential> {
  assertInstallationAllowsOrdinaryAccess(input.installation, "producer authentication");
  const purpose = input.purpose ?? "ordinary";
  const decoded = parseProducerBearerTokenStrict(input.bearerToken, "authorization");
  let digest: Uint8Array;
  try {
    digest = computeProducerCredentialDigest(decoded.credentialId, decoded.secretBytes);
  } finally {
    decoded.destroy();
  }

  const cred = await input.repo.findCredentialById(decoded.credentialId);
  if (cred === null) {
    constantTimeEqualBytes(digest, DUMMY_CREDENTIAL_DIGEST);
    throw new AuthenticationDomainError({
      code: "UNAUTHENTICATED",
      message: "Invalid producer credential"
    });
  }
  if (!constantTimeEqualBytes(digest, cred.secretDigest)) {
    throw new AuthenticationDomainError({
      code: "UNAUTHENTICATED",
      message: "Invalid producer credential"
    });
  }

  if (cred.controlEpoch !== input.installation.controlEpoch) {
    throw new AuthenticationDomainError({
      code: "UNAUTHENTICATED",
      message: "Producer credential control epoch is stale"
    });
  }
  if (compareInstants(input.now, cred.expiresAt) >= 0) {
    throw new ExpiredDomainError({
      code: "EXPIRED",
      message: "Producer credential has expired"
    });
  }
  if (cred.state === "revoked" || cred.state === "expired") {
    throw new AuthenticationDomainError({
      code: "UNAUTHENTICATED",
      message: "Producer credential is no longer active"
    });
  }
  if (purpose === "ordinary") {
    if (cred.state !== "active" && cred.state !== "overlap") {
      throw new AuthenticationDomainError({
        code: "UNAUTHENTICATED",
        message: "Producer credential is not activated for ordinary use"
      });
    }
    if (cred.state === "overlap") {
      if (cred.overlapEndsAt === null || compareInstants(input.now, cred.overlapEndsAt) >= 0) {
        throw new ExpiredDomainError({
          code: "EXPIRED",
          message: "Producer credential overlap window has ended"
        });
      }
    }
  }

  const producer = await input.repo.findProducerById(cred.producerId);
  if (producer === null) {
    throw new AuthenticationDomainError({
      code: "UNAUTHENTICATED",
      message: "Producer not found"
    });
  }
  assertMachineProducerChannel(producer);

  const principal = await input.repo.findPrincipalById(producer.principalId);
  if (principal === null || principal.kind !== "producer") {
    throw new AuthenticationDomainError({
      code: "UNAUTHENTICATED",
      message: "Producer principal unavailable"
    });
  }
  if (
    cred.ownerAuthorityEpoch !== producer.authorityEpoch ||
    cred.ownerAuthorityEpoch !== principal.authorityEpoch
  ) {
    throw new AuthenticationDomainError({
      code: "UNAUTHENTICATED",
      message: "Producer credential owner authority epoch is stale"
    });
  }

  if (purpose === "ordinary") {
    if (producer.state !== "active" || principal.state !== "active") {
      throw new AuthorizationDomainError({
        code: "FORBIDDEN",
        message: "Producer or principal is not active"
      });
    }
    if (
      producer.currentScopeVersion === null ||
      producer.currentScopeVersion !== cred.scopeVersion
    ) {
      throw new AuthorizationDomainError({
        code: "PUBLICATION_CONTEXT_CHANGED",
        message: "Producer credential scope version does not match active producer scope"
      });
    }
  } else if (
    producer.state === "suspended" ||
    producer.state === "retired" ||
    principal.state === "suspended" ||
    principal.state === "retired"
  ) {
    throw new AuthorizationDomainError({
      code: "FORBIDDEN",
      message: "Producer or principal is suspended or retired"
    });
  }

  const scope = await input.repo.findScopeVersion(producer.id, cred.scopeVersion);
  if (scope === null) {
    throw new AuthorizationDomainError({
      code: "FORBIDDEN",
      message: "Bound producer scope version is unavailable"
    });
  }

  if (input.requiredAction !== undefined) {
    if (!scope.scopeDefinition.actions.includes(input.requiredAction)) {
      throw new AuthorizationDomainError({
        code: "FORBIDDEN",
        message: `Producer scope does not grant action "${input.requiredAction}"`
      });
    }
  }

  if (input.requiredEvent !== undefined) {
    const reqEventTypeId = parseEventTypeId(input.requiredEvent.eventTypeId, "event_type_id");
    const reqSchemaVer = parsePositiveInt32(
      input.requiredEvent.schemaVersion,
      "event_schema_version"
    );
    const matchedEvent = scope.scopeDefinition.allowedEvents.find(
      (entry) => entry.eventTypeId === reqEventTypeId
    );
    if (matchedEvent === undefined || !matchedEvent.schemaVersions.includes(reqSchemaVer)) {
      throw new AuthorizationDomainError({
        code: "FORBIDDEN",
        message: "Event type or schema version is outside active producer scope"
      });
    }
  }

  return Object.freeze({
    credential: toSafeProducerCredentialMetadata(cred),
    producer,
    principal,
    scope
  });
}

export async function rotateProducerCredentialWithOverlap(input: {
  readonly installation: InstallationAuthoritySnapshot;
  readonly producerId: ProducerId | string;
  readonly expectedProducerVersion: bigint;
  readonly oldCredentialId: ProducerCredentialId | string;
  readonly expectedOldCredentialVersion: bigint;
  readonly newCredentialId: ProducerCredentialId | string;
  readonly expectedNewCredentialVersion: bigint;
  readonly overlapDurationMs: bigint;
  readonly repo: ProducerCredentialRepository;
  readonly now: Temporal.Instant;
}): Promise<{
  readonly old_credential: ProducerCredentialSafeMetadata;
  readonly new_credential: ProducerCredentialSafeMetadata;
  readonly overlap_ends_at: string;
}> {
  assertInstallationAllowsOrdinaryAccess(input.installation, "producer credential rotation");
  const producerId = parseProducerId(input.producerId, "producer_id");
  const oldCredId = parseProducerCredentialId(input.oldCredentialId, "old_credential_id");
  const newCredId = parseProducerCredentialId(input.newCredentialId, "new_credential_id");

  if (oldCredId === newCredId) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: "Credential rotation requires distinct old and new credential IDs"
    });
  }
  if (
    input.overlapDurationMs <= 0n ||
    input.overlapDurationMs > PRODUCER_CREDENTIAL_MAX_OVERLAP_MS
  ) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Same-scope rotation overlap must be within (0, ${PRODUCER_CREDENTIAL_MAX_OVERLAP_MS.toString(10)}ms]`
    });
  }

  const producer = await input.repo.findProducerById(producerId);
  if (producer === null) {
    throw new NotFoundDomainError({ code: "NOT_FOUND", message: "Producer not found" });
  }
  assertMachineProducerChannel(producer);
  if (producer.version !== input.expectedProducerVersion) {
    throw new ConflictDomainError({ code: "VERSION_CONFLICT", message: "Producer version mismatch" });
  }
  if (producer.state !== "active" || producer.currentScopeVersion === null) {
    throw new ConflictDomainError({
      code: "STATE_TRANSITION_NOT_ALLOWED",
      message: "Producer must be active with an active scope version for same-scope rotation"
    });
  }

  const oldCred = await input.repo.findCredentialById(oldCredId);
  const newCred = await input.repo.findCredentialById(newCredId);
  if (oldCred === null || newCred === null) {
    throw new NotFoundDomainError({ code: "NOT_FOUND", message: "Producer credential not found" });
  }
  if (oldCred.producerId !== producer.id || newCred.producerId !== producer.id) {
    throw new AuthorizationDomainError({
      code: "FORBIDDEN",
      message: "Credentials do not belong to the target producer"
    });
  }
  if (
    oldCred.controlEpoch !== input.installation.controlEpoch ||
    newCred.controlEpoch !== input.installation.controlEpoch
  ) {
    throw new ConflictDomainError({
      code: "STATE_TRANSITION_NOT_ALLOWED",
      message: "Credential rotation requires current control epoch"
    });
  }
  if (oldCred.version !== input.expectedOldCredentialVersion) {
    throw new ConflictDomainError({
      code: "VERSION_CONFLICT",
      message: "Old credential version mismatch"
    });
  }
  if (newCred.version !== input.expectedNewCredentialVersion) {
    throw new ConflictDomainError({
      code: "VERSION_CONFLICT",
      message: "New credential version mismatch"
    });
  }
  if (oldCred.state !== "active") {
    throw new ConflictDomainError({
      code: "STATE_TRANSITION_NOT_ALLOWED",
      message: `Old credential must be active to enter overlap (state="${oldCred.state}")`
    });
  }
  if (newCred.state !== "pending_activation" && newCred.state !== "active") {
    throw new ConflictDomainError({
      code: "STATE_TRANSITION_NOT_ALLOWED",
      message: `New credential cannot rotate from state "${newCred.state}"`
    });
  }
  if (compareInstants(input.now, oldCred.expiresAt) >= 0) {
    throw new ExpiredDomainError({ code: "EXPIRED", message: "Old credential has expired" });
  }
  if (compareInstants(input.now, newCred.expiresAt) >= 0) {
    throw new ExpiredDomainError({ code: "EXPIRED", message: "New credential has expired" });
  }

  // Same-scope rotation check: scope changes cannot retain old credential overlap.
  if (
    oldCred.scopeVersion !== producer.currentScopeVersion ||
    newCred.scopeVersion !== producer.currentScopeVersion
  ) {
    throw new AuthorizationDomainError({
      code: "PUBLICATION_CONTEXT_CHANGED",
      message: "Overlap rotation is allowed only between credentials bound to the same active scope version"
    });
  }

  const candidateOverlapEnd = addMilliseconds(input.now, input.overlapDurationMs, "overlap_ends_at");
  const overlapEndsAt = minInstant(
    candidateOverlapEnd,
    minInstant(oldCred.expiresAt, newCred.expiresAt)
  );
  assertProducerCredentialTiming({
    credentialId: oldCred.id,
    issuedAt: oldCred.createdAt,
    expiresAt: oldCred.expiresAt,
    overlapStartedAt: input.now,
    overlapEndsAt
  });

  const rotated = await input.repo.rotateCredentialOverlapAtomic({
    oldCredentialId: oldCred.id,
    expectedOldVersion: oldCred.version,
    newCredentialId: newCred.id,
    expectedNewVersion: newCred.version,
    overlapStartedAt: input.now,
    overlapEndsAt,
    now: input.now
  });

  return Object.freeze({
    old_credential: toSafeProducerCredentialMetadata(rotated.oldCredential),
    new_credential: toSafeProducerCredentialMetadata(rotated.newCredential),
    overlap_ends_at: formatUtcTimestamp(overlapEndsAt)
  });
}
