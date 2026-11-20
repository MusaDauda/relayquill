import crypto from "node:crypto";
import {
  ALLOWED_ENDPOINT_TRANSITIONS,
  ALLOWED_PROJECT_TRANSITIONS,
  ALLOWED_TENANT_TRANSITIONS,
  AuthorizationDomainError,
  ConflictDomainError,
  type CanonicalUtcTimestamp,
  type EndpointId,
  type EndpointState,
  type EndpointVerificationAttemptId,
  type EndpointVerificationIntentId,
  type EventTypeId,
  type EventTypeName,
  type KeyId,
  type OperationProofId,
  type OrderingDomainId,
  type OrderingMode,
  type PrincipalId,
  type ProjectId,
  type ProjectState,
  type RepresentationProfileId,
  type SignatureMode,
  type SigningDeliveryIntentId,
  type SigningKeyVersionId,
  type SubscriptionId,
  type TenantId,
  type TenantState,
  ValidationDomainError,
  addMilliseconds,
  assertSigningPolicyInvariants,
  assertTransition,
  compareInstants,
  formatUtcTimestamp,
  parseCommandReceiptId,
  parseEndpointId,
  parseEndpointVerificationAttemptId,
  parseEndpointVerificationIntentId,
  parseEventTypeId,
  parseEventTypeName,
  parseKeyId,
  parseOperationProofId,
  parseOrderingDomainId,
  parseProjectId,
  parseRepresentationProfileId,
  parseSigningDeliveryIntentId,
  parseSigningKeyVersionId,
  parseSubscriptionId,
  parseTenantId,
  parseUtcTimestamp
} from "@relayquill/domain";
import {
  type AuthenticatedHumanSession,
  authorizeHumanAction,
  verifyAndConsumeOperationProof
} from "@relayquill/auth";
import {
  type CanonicalJsonValue,
  computeCommandGuardKey,
  decodeUtf8BytesStrict,
  hashCanonicalJson,
  parseCanonicalUtcTimestamp,
  parseCanonicalUuid,
  sha256Utf8Hex
} from "@relayquill/contracts";
import {
  type CompiledEventSchema,
  compileEventSchemaFromBytes,
  compileFilterAst,
  compileProjectionProfile
} from "@relayquill/event-schema";
import { normalizeDestinationUrl } from "@relayquill/egress";
import { type EgressConfig, type ProfileKind } from "@relayquill/runtime";
import {
  type AuthRepositoriesBundle,
  type ClockPort,
  type DispatchDomainRecord,
  type EndpointRecord,
  type EventSchemaDefinitionRecord,
  type IdGeneratorPort,
  type InstallationAuthoritySnapshot,
  type ProjectAuthoritySnapshot,
  type RatePolicyDrainRecord,
  type TelemetryPort,
  type TenantAuthoritySnapshot,
  type TopologyCommandResult,
  type TopologyRepositoryPort,
  type UnitOfWorkPort,
  cryptoIdGeneratorPort,
  noopTelemetryPort,
  systemClockPort
} from "./ports.js";

const ENDPOINT_VERIFICATION_INTENT_TTL_MS = 120_000n;

export interface TopologyServiceDeps<TTx> {
  readonly uow: UnitOfWorkPort<TTx>;
  readonly topologyRepo: TopologyRepositoryPort<TTx>;
  readonly authRepos: AuthRepositoriesBundle;
  readonly readInstallationAuthority: (tx: TTx) => Promise<InstallationAuthoritySnapshot>;
  readonly profile?: ProfileKind | undefined;
  readonly egressConfig?: EgressConfig | undefined;
  readonly clock?: ClockPort | undefined;
  readonly idGenerator?: IdGeneratorPort | undefined;
  readonly telemetry?: TelemetryPort | undefined;
}

export interface CreateTenantCommandInput {
  readonly session: AuthenticatedHumanSession;
  readonly slug: string;
  readonly displayName: string;
  readonly stepUpProofId: OperationProofId | string;
  readonly idempotencyKey: string;
}

export interface TransitionTenantCommandInput {
  readonly session: AuthenticatedHumanSession;
  readonly tenantId: TenantId | string;
  readonly expectedVersion: bigint;
  readonly nextState: TenantState;
  readonly stepUpProofId: OperationProofId | string;
  readonly idempotencyKey: string;
}

export interface CreateProjectCommandInput {
  readonly session: AuthenticatedHumanSession;
  readonly tenantId: TenantId | string;
  readonly name: string;
  readonly defaultDeliveryWindowMs: bigint;
  readonly maxDeliveryWindowMs: bigint;
  readonly stepUpProofId: OperationProofId | string;
  readonly idempotencyKey: string;
}

export interface TransitionProjectCommandInput {
  readonly session: AuthenticatedHumanSession;
  readonly tenantId: TenantId | string;
  readonly projectId: ProjectId | string;
  readonly expectedVersion: bigint;
  readonly nextState: ProjectState;
  readonly reasonCode?: string | undefined;
  readonly stepUpProofId: OperationProofId | string;
  readonly idempotencyKey: string;
}

export interface RegisterDraftEndpointInput {
  readonly session: AuthenticatedHumanSession;
  readonly tenantId: TenantId | string;
  readonly projectId: ProjectId | string;
  readonly destinationUrl: string;
  readonly maxInFlight: number;
  readonly rateLimitPerSec: number;
  readonly rateBurst: number;
  readonly idempotencyKey: string;
}

export interface RegisteredEndpointWithCustody {
  readonly endpoint: TopologyCommandResult<EndpointRecord>;
  readonly custody: {
    readonly keyId: KeyId;
    readonly keyVersionId: SigningKeyVersionId;
    readonly custodyIntentId: SigningDeliveryIntentId;
  };
}

export interface SigningKeyCustodyCommandInput {
  readonly session: AuthenticatedHumanSession;
  readonly tenantId: TenantId | string;
  readonly projectId: ProjectId | string;
  readonly endpointId: EndpointId | string;
  readonly expectedEndpointVersion: bigint;
  readonly action: "deliver_custody" | "activate_key" | "rotate_key" | "revoke_key";
  readonly intentId?: SigningDeliveryIntentId | string | undefined;
  readonly newKeyId?: KeyId | string | undefined;
  readonly newKeyVersionId?: SigningKeyVersionId | string | undefined;
  readonly signatureMode?: SignatureMode | undefined;
  readonly overlapUntil?: CanonicalUtcTimestamp | string | undefined;
  readonly verifyUntil?: CanonicalUtcTimestamp | string | undefined;
  readonly stepUpProofId: OperationProofId | string;
  readonly idempotencyKey: string;
}

export interface InitiateEndpointVerificationInput {
  readonly session: AuthenticatedHumanSession;
  readonly tenantId: TenantId | string;
  readonly projectId: ProjectId | string;
  readonly endpointId: EndpointId | string;
  readonly expectedVersion: bigint;
  readonly stepUpProofId: OperationProofId | string;
  readonly idempotencyKey: string;
}

export interface InitiatedEndpointVerification {
  readonly endpoint: TopologyCommandResult<EndpointRecord>;
  readonly verificationIntentId: EndpointVerificationIntentId;
  readonly verificationAttemptId: EndpointVerificationAttemptId;
  readonly publicNonce: string;
  readonly intentExpiresAt: CanonicalUtcTimestamp;
}

export interface TransitionEndpointStateInput {
  readonly session: AuthenticatedHumanSession;
  readonly tenantId: TenantId | string;
  readonly projectId: ProjectId | string;
  readonly endpointId: EndpointId | string;
  readonly expectedVersion: bigint;
  readonly nextState: EndpointState;
  readonly verificationProofPassed?: boolean | undefined;
  readonly reasonCode?: string | undefined;
  readonly stepUpProofId?: OperationProofId | string | undefined;
  readonly idempotencyKey: string;
}

export interface RegisterEventSchemaInput {
  readonly session: AuthenticatedHumanSession;
  readonly tenantId: TenantId | string;
  readonly projectId: ProjectId | string;
  readonly eventTypeId?: EventTypeId | string | undefined;
  readonly eventTypeName: EventTypeName | string;
  readonly schemaVersion: number;
  readonly schemaBytes: Uint8Array;
  readonly targetState: "draft" | "active" | "deprecated";
  readonly stepUpProofId?: OperationProofId | string | undefined;
  readonly idempotencyKey: string;
}

export interface UpsertSubscriptionInput {
  readonly session: AuthenticatedHumanSession;
  readonly tenantId: TenantId | string;
  readonly projectId: ProjectId | string;
  readonly subscriptionId?: SubscriptionId | string | undefined;
  readonly expectedVersion?: bigint | undefined;
  readonly endpointId: EndpointId | string;
  readonly eventTypeId: EventTypeId | string;
  readonly schemaVersions: readonly number[];
  readonly compiledSchemas: readonly CompiledEventSchema[];
  readonly filterAst: Readonly<Record<string, unknown>>;
  readonly orderingMode: OrderingMode;
  readonly orderingDomainId?: OrderingDomainId | string | undefined;
  readonly consumerContractScope: string;
  readonly retryPolicyVersion: string;
  readonly controlAction?: "activate" | "pause" | "resume" | "drain" | "disable" | undefined;
  readonly stepUpProofId?: OperationProofId | string | undefined;
  readonly idempotencyKey: string;
}

export interface RegisterRepresentationProfileInput {
  readonly session: AuthenticatedHumanSession;
  readonly tenantId: TenantId | string;
  readonly projectId: ProjectId | string;
  readonly profileId?: RepresentationProfileId | string | undefined;
  readonly profileVersion: bigint;
  readonly eventTypeId: EventTypeId | string;
  readonly sourceSchema: CompiledEventSchema;
  readonly targetSchema: CompiledEventSchema;
  readonly sourceSchemaVersion: number;
  readonly targetSchemaVersion: number;
  readonly profileBytes: Uint8Array;
  readonly activate: boolean;
  readonly stepUpProofId?: OperationProofId | string | undefined;
  readonly idempotencyKey: string;
}

function parseJsonObjectForCanonicalHash(bytes: Uint8Array, label: string): CanonicalJsonValue {
  const text = decodeUtf8BytesStrict(bytes, label);
  return JSON.parse(text) as CanonicalJsonValue;
}

function inferProjectTransitionAction(nextState: ProjectState): string {
  if (nextState === "admission_paused") {
    return "projects.pause_admission";
  }
  if (nextState === "active") {
    return "projects.resume_admission";
  }
  if (nextState === "retired") {
    return "projects.retire";
  }
  return "projects.create";
}

function inferTenantTransitionAction(nextState: TenantState): string {
  if (nextState === "suspended") {
    return "tenants.suspend";
  }
  if (nextState === "active") {
    return "tenants.restore";
  }
  if (nextState === "retired") {
    return "tenants.retire";
  }
  return "tenants.create";
}

export class TopologyService<TTx> {
  readonly #uow: UnitOfWorkPort<TTx>;
  readonly #topologyRepo: TopologyRepositoryPort<TTx>;
  readonly #authRepos: AuthRepositoriesBundle;
  readonly #readInstallationAuthority: (tx: TTx) => Promise<InstallationAuthoritySnapshot>;
  readonly #profile: ProfileKind | undefined;
  readonly #egressConfig: EgressConfig | undefined;
  readonly #clock: ClockPort;
  readonly #ids: IdGeneratorPort;
  readonly #telemetry: TelemetryPort;

  constructor(deps: TopologyServiceDeps<TTx>) {
    this.#uow = deps.uow;
    this.#topologyRepo = deps.topologyRepo;
    this.#authRepos = deps.authRepos;
    this.#readInstallationAuthority = deps.readInstallationAuthority;
    this.#profile = deps.profile;
    this.#egressConfig = deps.egressConfig;
    this.#clock = deps.clock ?? systemClockPort;
    this.#ids = deps.idGenerator ?? cryptoIdGeneratorPort;
    this.#telemetry = deps.telemetry ?? noopTelemetryPort;
  }

  async createTenant(
    input: CreateTenantCommandInput
  ): Promise<TopologyCommandResult<TenantAuthoritySnapshot>> {
    const span = this.#telemetry.startSpan("relayquill.topology.create_tenant");
    try {
      const slug = input.slug.trim();
      const displayName = input.displayName.trim();
      if (slug.length === 0 || displayName.length === 0) {
        throw new ValidationDomainError({
          code: "INVALID_VALUE",
          message: "Tenant slug and displayName are required"
        });
      }

      const tenantId = parseTenantId(this.#ids.nextUuid(), "tenantId");
      const receiptId = parseCommandReceiptId(this.#ids.nextUuid(), "receiptId");
      const proofId = parseOperationProofId(input.stepUpProofId, "stepUpProofId");
      const nowInstant = this.#clock.nowInstant();
      const now = parseCanonicalUtcTimestamp(formatUtcTimestamp(nowInstant), "now");
      const commandSha256 = hashCanonicalJson(
        { slug, display_name: displayName },
        "create_tenant"
      ).sha256;
      const effectiveSha256 = hashCanonicalJson(
        { tenant_id: tenantId, slug, display_name: displayName },
        "create_tenant_effective"
      ).sha256;
      const idempotencyKeySha256 = computeCommandGuardKey({
        scope_kind: "installation",
        tenant_id: null,
        project_id: null,
        actor_principal_id: input.session.principal.principalId,
        command_family: "tenants.create",
        key_sha256: sha256Utf8Hex(input.idempotencyKey)
      }).digest_sha256;

      const installation = await this.#uow.inTransaction((tx) =>
        this.#readInstallationAuthority(tx)
      );

      await verifyAndConsumeOperationProof({
        proofId,
        authenticatedSession: input.session,
        installation,
        expectedBinding: {
          action: "tenants.create",
          scopeKind: "installation",
          tenantId: null,
          projectId: null,
          targetResourceId: parseCanonicalUuid(tenantId, "tenantId"),
          targetVersion: 1n,
          canonicalCommandSha256: commandSha256
        },
        acceptedReceiptId: receiptId,
        proofRepo: this.#authRepos.stepUp,
        now: nowInstant
      });

      await authorizeHumanAction({
        installation,
        principalId: input.session.principal.principalId,
        action: "tenants.create",
        stepUpVerified: true,
        repo: this.#authRepos.humanAuthorization,
        now: nowInstant
      });

      const res = await this.#uow.inTransaction((tx) =>
        this.#topologyRepo.createTenant(tx, {
          tenantId,
          slug,
          displayName,
          actorPrincipalId: input.session.principal.principalId,
          receiptId,
          idempotencyKeySha256,
          commandSha256,
          effectiveSha256,
          now
        })
      );

      span.end({ code: "OK" });
      return res;
    } catch (err) {
      span.end({
        code: "ERROR",
        message: err instanceof Error ? err.message : "create_tenant_failed"
      });
      throw err;
    }
  }

  async transitionTenantState(
    input: TransitionTenantCommandInput
  ): Promise<TopologyCommandResult<TenantAuthoritySnapshot>> {
    const tenantId = parseTenantId(input.tenantId, "tenantId");
    const proofId = parseOperationProofId(input.stepUpProofId, "stepUpProofId");
    const receiptId = parseCommandReceiptId(this.#ids.nextUuid(), "receiptId");
    const action = inferTenantTransitionAction(input.nextState);
    const nowInstant = this.#clock.nowInstant();
    const now = parseCanonicalUtcTimestamp(formatUtcTimestamp(nowInstant), "now");
    const commandSha256 = hashCanonicalJson(
      {
        tenant_id: tenantId,
        next_state: input.nextState,
        expected_version: input.expectedVersion.toString(10)
      },
      "transition_tenant"
    ).sha256;
    const idempotencyKeySha256 = computeCommandGuardKey({
      scope_kind: "tenant",
      tenant_id: tenantId,
      project_id: null,
      actor_principal_id: input.session.principal.principalId,
      command_family: action,
      key_sha256: sha256Utf8Hex(input.idempotencyKey)
    }).digest_sha256;

    const installation = await this.#uow.inTransaction((tx) =>
      this.#readInstallationAuthority(tx)
    );

    await verifyAndConsumeOperationProof({
      proofId,
      authenticatedSession: input.session,
      installation,
      expectedBinding: {
        action,
        scopeKind: "tenant",
        tenantId,
        projectId: null,
        targetResourceId: parseCanonicalUuid(tenantId, "tenantId"),
        targetVersion: input.expectedVersion,
        canonicalCommandSha256: commandSha256
      },
      acceptedReceiptId: receiptId,
      proofRepo: this.#authRepos.stepUp,
      now: nowInstant
    });

    await authorizeHumanAction({
      installation,
      principalId: input.session.principal.principalId,
      action,
      tenantId,
      stepUpVerified: true,
      repo: this.#authRepos.humanAuthorization,
      now: nowInstant
    });

    return this.#uow.inTransaction(async (tx) => {
      const existing = await this.#topologyRepo.getTenant(tx, tenantId);
      if (existing === undefined) {
        throw new ConflictDomainError({
          code: "NOT_FOUND",
          message: `Tenant "${tenantId}" not found`
        });
      }
      if (existing.version !== input.expectedVersion) {
        throw new ConflictDomainError({
          code: "VERSION_CONFLICT",
          message: `Tenant version mismatch: expected ${input.expectedVersion}, got ${existing.version}`
        });
      }
      assertTransition("tenant", ALLOWED_TENANT_TRANSITIONS, existing.state, input.nextState, {
        kind: "tenant",
        id: tenantId
      });

      return this.#topologyRepo.transitionTenantState(tx, {
        tenantId,
        expectedVersion: input.expectedVersion,
        nextState: input.nextState,
        actorPrincipalId: input.session.principal.principalId,
        receiptId,
        idempotencyKeySha256,
        commandSha256,
        effectiveSha256: commandSha256,
        now
      });
    });
  }

  async createProject(
    input: CreateProjectCommandInput
  ): Promise<TopologyCommandResult<ProjectAuthoritySnapshot>> {
    const tenantId = parseTenantId(input.tenantId, "tenantId");
    const name = input.name.trim();
    if (
      name.length === 0 ||
      input.defaultDeliveryWindowMs <= 0n ||
      input.maxDeliveryWindowMs < input.defaultDeliveryWindowMs
    ) {
      throw new ValidationDomainError({
        code: "INVALID_VALUE",
        message: "Project name and monotonic delivery window bounds are required"
      });
    }

    const projectId = parseProjectId(this.#ids.nextUuid(), "projectId");
    const receiptId = parseCommandReceiptId(this.#ids.nextUuid(), "receiptId");
    const proofId = parseOperationProofId(input.stepUpProofId, "stepUpProofId");
    const nowInstant = this.#clock.nowInstant();
    const now = parseCanonicalUtcTimestamp(formatUtcTimestamp(nowInstant), "now");
    const commandSha256 = hashCanonicalJson(
      {
        tenant_id: tenantId,
        name,
        default_delivery_window_ms: input.defaultDeliveryWindowMs.toString(10),
        max_delivery_window_ms: input.maxDeliveryWindowMs.toString(10)
      },
      "create_project"
    ).sha256;
    const effectiveSha256 = hashCanonicalJson(
      { project_id: projectId, name },
      "project_effective"
    ).sha256;
    const idempotencyKeySha256 = computeCommandGuardKey({
      scope_kind: "tenant",
      tenant_id: tenantId,
      project_id: null,
      actor_principal_id: input.session.principal.principalId,
      command_family: "projects.create",
      key_sha256: sha256Utf8Hex(input.idempotencyKey)
    }).digest_sha256;

    const installation = await this.#uow.inTransaction((tx) =>
      this.#readInstallationAuthority(tx)
    );

    await verifyAndConsumeOperationProof({
      proofId,
      authenticatedSession: input.session,
      installation,
      expectedBinding: {
        action: "projects.create",
        scopeKind: "tenant",
        tenantId,
        projectId: null,
        targetResourceId: parseCanonicalUuid(projectId, "projectId"),
        targetVersion: 1n,
        canonicalCommandSha256: commandSha256
      },
      acceptedReceiptId: receiptId,
      proofRepo: this.#authRepos.stepUp,
      now: nowInstant
    });

    await authorizeHumanAction({
      installation,
      principalId: input.session.principal.principalId,
      action: "projects.create",
      tenantId,
      stepUpVerified: true,
      repo: this.#authRepos.humanAuthorization,
      now: nowInstant
    });

    return this.#uow.inTransaction(async (tx) => {
      const tenant = await this.#topologyRepo.getTenant(tx, tenantId);
      if (tenant === undefined || tenant.state !== "active") {
        throw new ConflictDomainError({
          code: "STATE_TRANSITION_NOT_ALLOWED",
          message: `Tenant "${tenantId}" must be active to create a project`
        });
      }
      return this.#topologyRepo.createProject(tx, {
        tenantId,
        projectId,
        name,
        defaultDeliveryWindowMs: input.defaultDeliveryWindowMs,
        maxDeliveryWindowMs: input.maxDeliveryWindowMs,
        actorPrincipalId: input.session.principal.principalId,
        receiptId,
        idempotencyKeySha256,
        commandSha256,
        effectiveSha256,
        now
      });
    });
  }

  async transitionProjectState(
    input: TransitionProjectCommandInput
  ): Promise<TopologyCommandResult<ProjectAuthoritySnapshot>> {
    const tenantId = parseTenantId(input.tenantId, "tenantId");
    const projectId = parseProjectId(input.projectId, "projectId");
    const proofId = parseOperationProofId(input.stepUpProofId, "stepUpProofId");
    const receiptId = parseCommandReceiptId(this.#ids.nextUuid(), "receiptId");
    const action = inferProjectTransitionAction(input.nextState);
    const scopeKind = input.nextState === "retired" ? "tenant" : "project";
    const nowInstant = this.#clock.nowInstant();
    const now = parseCanonicalUtcTimestamp(formatUtcTimestamp(nowInstant), "now");
    const commandSha256 = hashCanonicalJson(
      {
        tenant_id: tenantId,
        project_id: projectId,
        expected_version: input.expectedVersion.toString(10),
        next_state: input.nextState,
        reason_code: input.reasonCode ?? null
      },
      "transition_project"
    ).sha256;
    const idempotencyKeySha256 = computeCommandGuardKey({
      scope_kind: scopeKind,
      tenant_id: tenantId,
      project_id: scopeKind === "project" ? projectId : null,
      actor_principal_id: input.session.principal.principalId,
      command_family: action,
      key_sha256: sha256Utf8Hex(input.idempotencyKey)
    }).digest_sha256;

    const installation = await this.#uow.inTransaction((tx) =>
      this.#readInstallationAuthority(tx)
    );

    await verifyAndConsumeOperationProof({
      proofId,
      authenticatedSession: input.session,
      installation,
      expectedBinding: {
        action,
        scopeKind,
        tenantId,
        projectId: scopeKind === "project" ? projectId : null,
        targetResourceId: parseCanonicalUuid(projectId, "projectId"),
        targetVersion: input.expectedVersion,
        canonicalCommandSha256: commandSha256
      },
      acceptedReceiptId: receiptId,
      proofRepo: this.#authRepos.stepUp,
      now: nowInstant
    });

    await authorizeHumanAction({
      installation,
      principalId: input.session.principal.principalId,
      action,
      tenantId,
      projectId: scopeKind === "project" ? projectId : null,
      stepUpVerified: true,
      repo: this.#authRepos.humanAuthorization,
      now: nowInstant
    });

    return this.#uow.inTransaction(async (tx) => {
      const existing = await this.#topologyRepo.getProject(tx, tenantId, projectId);
      if (existing === undefined) {
        throw new ConflictDomainError({
          code: "NOT_FOUND",
          message: `Project "${projectId}" not found`
        });
      }
      if (existing.version !== input.expectedVersion) {
        throw new ConflictDomainError({
          code: "VERSION_CONFLICT",
          message: `Project version mismatch: expected ${input.expectedVersion}, got ${existing.version}`
        });
      }
      assertTransition("project", ALLOWED_PROJECT_TRANSITIONS, existing.state, input.nextState, {
        kind: "project",
        id: projectId
      });

      return this.#topologyRepo.transitionProjectState(tx, {
        tenantId,
        projectId,
        expectedVersion: input.expectedVersion,
        nextState: input.nextState,
        actorPrincipalId: input.session.principal.principalId,
        receiptId,
        idempotencyKeySha256,
        commandSha256,
        effectiveSha256: commandSha256,
        reasonCode: input.reasonCode,
        now
      });
    });
  }

  /**
   * Onboarding Step 1: Validates URL policy, computes deterministic RFC 8785 configuration
   * hash, creates initial key + dual custody delivery intent, and registers endpoint in `draft`.
   */
  async registerDraftEndpoint(
    input: RegisterDraftEndpointInput
  ): Promise<RegisteredEndpointWithCustody> {
    const span = this.#telemetry.startSpan("relayquill.topology.register_draft_endpoint");
    try {
      const tenantId = parseTenantId(input.tenantId, "tenantId");
      const projectId = parseProjectId(input.projectId, "projectId");

      const normalizedUrl = normalizeDestinationUrl(input.destinationUrl, {
        ...(this.#profile !== undefined ? { profile: this.#profile } : {}),
        ...(this.#egressConfig !== undefined ? { egressConfig: this.#egressConfig } : {})
      });
      if (input.maxInFlight < 1 || input.rateLimitPerSec < 1 || input.rateBurst < 1) {
        throw new ValidationDomainError({
          code: "INVALID_VALUE",
          message: "Endpoint concurrency and rate limits must be positive integers"
        });
      }

      const endpointId = parseEndpointId(this.#ids.nextUuid(), "endpointId");
      const keyId = parseKeyId(this.#ids.nextUuid(), "keyId");
      const keyVersionId = parseSigningKeyVersionId(this.#ids.nextUuid(), "keyVersionId");
      const custodyIntentId = parseSigningDeliveryIntentId(
        this.#ids.nextUuid(),
        "custodyIntentId"
      );
      const receiptId = parseCommandReceiptId(this.#ids.nextUuid(), "receiptId");

      const configurationSha256 = hashCanonicalJson(
        {
          destination_url: normalizedUrl.canonicalUrl,
          external_authority: normalizedUrl.externalAuthority,
          request_target: normalizedUrl.requestTarget,
          max_in_flight: input.maxInFlight,
          rate_limit_per_sec: input.rateLimitPerSec,
          rate_burst: input.rateBurst
        },
        "endpoint_configuration"
      ).sha256;

      const commandSha256 = hashCanonicalJson(
        {
          tenant_id: tenantId,
          project_id: projectId,
          destination_url: normalizedUrl.canonicalUrl,
          configuration_sha256: configurationSha256
        },
        "register_endpoint"
      ).sha256;
      const idempotencyKeySha256 = computeCommandGuardKey({
        scope_kind: "project",
        tenant_id: tenantId,
        project_id: projectId,
        actor_principal_id: input.session.principal.principalId,
        command_family: "endpoints.create_version",
        key_sha256: sha256Utf8Hex(input.idempotencyKey)
      }).digest_sha256;
      const nowInstant = this.#clock.nowInstant();
      const now = parseCanonicalUtcTimestamp(formatUtcTimestamp(nowInstant), "now");

      const installation = await this.#uow.inTransaction((tx) =>
        this.#readInstallationAuthority(tx)
      );

      await authorizeHumanAction({
        installation,
        principalId: input.session.principal.principalId,
        action: "endpoints.create_version",
        tenantId,
        projectId,
        repo: this.#authRepos.humanAuthorization,
        now: nowInstant
      });

      const endpoint = await this.#uow.inTransaction(async (tx) => {
        const project = await this.#topologyRepo.getProject(tx, tenantId, projectId);
        if (project === undefined || project.state !== "active") {
          throw new ConflictDomainError({
            code: "STATE_TRANSITION_NOT_ALLOWED",
            message: `Project "${projectId}" must be active to register an endpoint`
          });
        }
        return this.#topologyRepo.registerEndpoint(tx, {
          tenantId,
          projectId,
          endpointId,
          destinationUrl: normalizedUrl.canonicalUrl,
          configurationSha256,
          maxInFlight: input.maxInFlight,
          rateLimitPerSec: input.rateLimitPerSec,
          rateBurst: input.rateBurst,
          keyId,
          keyVersionId,
          custodyIntentId,
          actorPrincipalId: input.session.principal.principalId,
          receiptId,
          idempotencyKeySha256,
          commandSha256,
          effectiveSha256: configurationSha256,
          now
        });
      });

      span.end({ code: "OK" });
      return Object.freeze({
        endpoint,
        custody: Object.freeze({
          keyId,
          keyVersionId,
          custodyIntentId
        })
      });
    } catch (err) {
      span.end({
        code: "ERROR",
        message: err instanceof Error ? err.message : "register_endpoint_failed"
      });
      throw err;
    }
  }

  /**
   * Onboarding Steps 2, 3 & Rotation: Advances signing key custody (`deliver_custody` ->
   * `activate_key` -> `rotate_key` -> `revoke_key`) enforcing dual-signing overlap invariants.
   */
  async updateSigningKeyCustodyAndPolicy(
    input: SigningKeyCustodyCommandInput
  ): Promise<TopologyCommandResult<{ readonly signingPolicyVersion: bigint }>> {
    const tenantId = parseTenantId(input.tenantId, "tenantId");
    const projectId = parseProjectId(input.projectId, "projectId");
    const endpointId = parseEndpointId(input.endpointId, "endpointId");
    const proofId = parseOperationProofId(input.stepUpProofId, "stepUpProofId");
    const receiptId = parseCommandReceiptId(this.#ids.nextUuid(), "receiptId");
    const intentId =
      input.intentId !== undefined
        ? parseSigningDeliveryIntentId(input.intentId, "intentId")
        : undefined;
    const newKeyId =
      input.newKeyId !== undefined ? parseKeyId(input.newKeyId, "newKeyId") : undefined;
    const newKeyVersionId =
      input.newKeyVersionId !== undefined
        ? parseSigningKeyVersionId(input.newKeyVersionId, "newKeyVersionId")
        : undefined;
    const overlapUntil =
      input.overlapUntil !== undefined
        ? parseCanonicalUtcTimestamp(input.overlapUntil, "overlapUntil")
        : undefined;
    const verifyUntil =
      input.verifyUntil !== undefined
        ? parseCanonicalUtcTimestamp(input.verifyUntil, "verifyUntil")
        : undefined;

    const nowInstant = this.#clock.nowInstant();
    const now = parseCanonicalUtcTimestamp(formatUtcTimestamp(nowInstant), "now");
    const stepUpAction =
      input.action === "revoke_key"
        ? "signing_keys.revoke"
        : input.action === "activate_key"
          ? "signing_keys.activate"
          : input.action === "deliver_custody"
            ? "signing_key_intents.create"
            : "signing_keys.rotate";
    const governanceAction =
      input.action === "revoke_key"
        ? "signing_keys.revoke"
        : input.action === "activate_key"
          ? "signing_policies.activate"
          : input.action === "deliver_custody"
            ? "signing_key_intents.create"
            : "signing_policies.create";

    const commandSha256 = hashCanonicalJson(
      {
        endpoint_id: endpointId,
        expected_version: input.expectedEndpointVersion.toString(10),
        action: input.action,
        intent_id: intentId ?? null,
        new_key_id: newKeyId ?? null,
        signature_mode: input.signatureMode ?? null
      },
      "signing_key_custody"
    ).sha256;
    const idempotencyKeySha256 = computeCommandGuardKey({
      scope_kind: "project",
      tenant_id: tenantId,
      project_id: projectId,
      actor_principal_id: input.session.principal.principalId,
      command_family: governanceAction,
      key_sha256: sha256Utf8Hex(input.idempotencyKey)
    }).digest_sha256;

    const installation = await this.#uow.inTransaction((tx) =>
      this.#readInstallationAuthority(tx)
    );

    await verifyAndConsumeOperationProof({
      proofId,
      authenticatedSession: input.session,
      installation,
      expectedBinding: {
        action: stepUpAction,
        scopeKind: "project",
        tenantId,
        projectId,
        targetResourceId: parseCanonicalUuid(endpointId, "endpointId"),
        targetVersion: input.expectedEndpointVersion,
        canonicalCommandSha256: commandSha256
      },
      acceptedReceiptId: receiptId,
      proofRepo: this.#authRepos.stepUp,
      now: nowInstant
    });

    await authorizeHumanAction({
      installation,
      principalId: input.session.principal.principalId,
      action: governanceAction,
      tenantId,
      projectId,
      stepUpVerified: true,
      repo: this.#authRepos.humanAuthorization,
      now: nowInstant
    });

    return this.#uow.inTransaction(async (tx) => {
      const endpoint = await this.#topologyRepo.getEndpoint(tx, tenantId, projectId, endpointId);
      if (endpoint === undefined) {
        throw new ConflictDomainError({
          code: "NOT_FOUND",
          message: `Endpoint "${endpointId}" not found`
        });
      }
      if (endpoint.version !== input.expectedEndpointVersion) {
        throw new ConflictDomainError({
          code: "VERSION_CONFLICT",
          message: `Endpoint version mismatch`
        });
      }

      if (intentId !== undefined) {
        const custody = await this.#topologyRepo.getSigningKeyCustodyIntent(tx, intentId);
        if (custody === undefined || custody.endpointId !== endpointId) {
          throw new ConflictDomainError({
            code: "NOT_FOUND",
            message: `Custody intent "${intentId}" not found for endpoint "${endpointId}"`
          });
        }
        if (
          compareInstants(nowInstant, parseUtcTimestamp(custody.expiresAt, "expiresAt").instant) >=
          0
        ) {
          throw new ConflictDomainError({
            code: "EXPIRED",
            message: `Custody intent "${intentId}" has expired`
          });
        }
        if (input.action === "activate_key" && custody.state !== "delivered_to_custody") {
          throw new ConflictDomainError({
            code: "STATE_TRANSITION_NOT_ALLOWED",
            message: `Cannot activate key before custody delivery ("${custody.state}")`
          });
        }
      }

      if (input.signatureMode === "bounded_dual_signature") {
        if (overlapUntil === undefined || verifyUntil === undefined || newKeyVersionId === undefined) {
          throw new ValidationDomainError({
            code: "INVALID_VALUE",
            message:
              "bounded_dual_signature rotation requires newKeyVersionId, overlapUntil, and verifyUntil"
          });
        }
        const primaryKeyVersionId = parseSigningKeyVersionId(
          this.#ids.nextUuid(),
          "primaryPlaceholder"
        );
        assertSigningPolicyInvariants({
          signatureMode: "bounded_dual_signature",
          primaryKeyVersionId: newKeyVersionId,
          overlapKeyVersionId: primaryKeyVersionId,
          overlapStartedAt: nowInstant,
          overlapEndsAt: parseUtcTimestamp(verifyUntil, "verifyUntil").instant,
          oldKeySignUntil: parseUtcTimestamp(overlapUntil, "overlapUntil").instant,
          oldKeyVerifyUntil: parseUtcTimestamp(verifyUntil, "verifyUntil").instant
        });
      }

      return this.#topologyRepo.updateSigningKeyCustodyAndPolicy(tx, {
        tenantId,
        projectId,
        endpointId,
        expectedEndpointVersion: input.expectedEndpointVersion,
        action: input.action,
        intentId,
        newKeyId,
        newKeyVersionId,
        signatureMode: input.signatureMode,
        overlapUntil,
        verifyUntil,
        actorPrincipalId: input.session.principal.principalId,
        receiptId,
        idempotencyKeySha256,
        commandSha256,
        effectiveSha256: commandSha256,
        now
      });
    });
  }

  /**
   * Onboarding Step 4: Begins endpoint verification challenge (`draft -> verification_pending`)
   * verifying signing key custody has been delivered/activated first.
   */
  async initiateEndpointVerification(
    input: InitiateEndpointVerificationInput
  ): Promise<InitiatedEndpointVerification> {
    const tenantId = parseTenantId(input.tenantId, "tenantId");
    const projectId = parseProjectId(input.projectId, "projectId");
    const endpointId = parseEndpointId(input.endpointId, "endpointId");
    const proofId = parseOperationProofId(input.stepUpProofId, "stepUpProofId");
    const verificationIntentId = parseEndpointVerificationIntentId(
      this.#ids.nextUuid(),
      "verificationIntentId"
    );
    const verificationAttemptId = parseEndpointVerificationAttemptId(
      this.#ids.nextUuid(),
      "verificationAttemptId"
    );
    const receiptId = parseCommandReceiptId(this.#ids.nextUuid(), "receiptId");
    const publicNonce = crypto.randomBytes(24).toString("base64url");
    const nowInstant = this.#clock.nowInstant();
    const now = parseCanonicalUtcTimestamp(formatUtcTimestamp(nowInstant), "now");
    const intentExpiresAt = parseCanonicalUtcTimestamp(
      formatUtcTimestamp(
        addMilliseconds(nowInstant, ENDPOINT_VERIFICATION_INTENT_TTL_MS, "intentExpiresAt")
      ),
      "intentExpiresAt"
    );

    const commandSha256 = hashCanonicalJson(
      {
        endpoint_id: endpointId,
        expected_version: input.expectedVersion.toString(10),
        action: "initiate_verification"
      },
      "initiate_endpoint_verification"
    ).sha256;
    const idempotencyKeySha256 = computeCommandGuardKey({
      scope_kind: "project",
      tenant_id: tenantId,
      project_id: projectId,
      actor_principal_id: input.session.principal.principalId,
      command_family: "endpoints.verify",
      key_sha256: sha256Utf8Hex(input.idempotencyKey)
    }).digest_sha256;

    const installation = await this.#uow.inTransaction((tx) =>
      this.#readInstallationAuthority(tx)
    );

    await verifyAndConsumeOperationProof({
      proofId,
      authenticatedSession: input.session,
      installation,
      expectedBinding: {
        action: "endpoints.verify",
        scopeKind: "project",
        tenantId,
        projectId,
        targetResourceId: parseCanonicalUuid(endpointId, "endpointId"),
        targetVersion: input.expectedVersion,
        canonicalCommandSha256: commandSha256
      },
      acceptedReceiptId: receiptId,
      proofRepo: this.#authRepos.stepUp,
      now: nowInstant
    });

    await authorizeHumanAction({
      installation,
      principalId: input.session.principal.principalId,
      action: "endpoints.verify",
      tenantId,
      projectId,
      stepUpVerified: true,
      repo: this.#authRepos.humanAuthorization,
      now: nowInstant
    });

    const endpoint = await this.#uow.inTransaction(async (tx) => {
      const current = await this.#topologyRepo.getEndpoint(tx, tenantId, projectId, endpointId);
      if (current === undefined) {
        throw new ConflictDomainError({
          code: "NOT_FOUND",
          message: `Endpoint "${endpointId}" not found`
        });
      }
      if (current.version !== input.expectedVersion) {
        throw new ConflictDomainError({
          code: "VERSION_CONFLICT",
          message: `Endpoint version mismatch`
        });
      }
      const keys = await this.#topologyRepo.listEndpointSigningKeys(tx, endpointId);
      const hasCustodyKey = keys.some(
        (key) =>
          key.state === "active" ||
          key.state === "overlap" ||
          key.state === "receiver_verified"
      );
      if (!hasCustodyKey) {
        throw new ConflictDomainError({
          code: "STATE_TRANSITION_NOT_ALLOWED",
          message: `Endpoint "${endpointId}" requires an active signing key in custody before verification`
        });
      }

      assertTransition(
        "endpoint",
        ALLOWED_ENDPOINT_TRANSITIONS,
        current.state,
        "verification_pending",
        { kind: "endpoint", id: endpointId }
      );

      return this.#topologyRepo.transitionEndpoint(tx, {
        tenantId,
        projectId,
        endpointId,
        expectedVersion: input.expectedVersion,
        nextState: "verification_pending",
        verificationIntentId,
        verificationAttemptId,
        publicNonce,
        intentExpiresAt,
        actorPrincipalId: input.session.principal.principalId,
        receiptId,
        idempotencyKeySha256,
        commandSha256,
        effectiveSha256: commandSha256,
        now
      });
    });

    return Object.freeze({
      endpoint,
      verificationIntentId,
      verificationAttemptId,
      publicNonce,
      intentExpiresAt
    });
  }

  /**
   * Onboarding Step 6 & Lifecycle: Safely transitions an endpoint (`verification_pending -> active`,
   * `pause`, `quarantine`, `retire`) enforcing state transitions and proof preconditions.
   */
  async transitionEndpointState(
    input: TransitionEndpointStateInput
  ): Promise<TopologyCommandResult<EndpointRecord>> {
    const tenantId = parseTenantId(input.tenantId, "tenantId");
    const projectId = parseProjectId(input.projectId, "projectId");
    const endpointId = parseEndpointId(input.endpointId, "endpointId");
    const receiptId = parseCommandReceiptId(this.#ids.nextUuid(), "receiptId");
    const nowInstant = this.#clock.nowInstant();
    const now = parseCanonicalUtcTimestamp(formatUtcTimestamp(nowInstant), "now");
    const action =
      input.nextState === "active"
        ? input.verificationProofPassed
          ? "endpoints.activate"
          : "endpoints.resume"
        : input.nextState === "paused"
          ? "endpoints.pause"
          : input.nextState === "quarantined"
            ? "endpoints.quarantine"
            : "endpoints.retire";

    const commandSha256 = hashCanonicalJson(
      {
        endpoint_id: endpointId,
        expected_version: input.expectedVersion.toString(10),
        next_state: input.nextState,
        reason_code: input.reasonCode ?? null
      },
      "transition_endpoint"
    ).sha256;
    const idempotencyKeySha256 = computeCommandGuardKey({
      scope_kind: "project",
      tenant_id: tenantId,
      project_id: projectId,
      actor_principal_id: input.session.principal.principalId,
      command_family: action,
      key_sha256: sha256Utf8Hex(input.idempotencyKey)
    }).digest_sha256;

    const installation = await this.#uow.inTransaction((tx) =>
      this.#readInstallationAuthority(tx)
    );

    let stepUpVerified = false;
    if (action !== "endpoints.pause") {
      if (input.stepUpProofId === undefined) {
        throw new AuthorizationDomainError({
          code: "FORBIDDEN",
          message: `Action "${action}" requires stepUpProofId`
        });
      }
      await verifyAndConsumeOperationProof({
        proofId: parseOperationProofId(input.stepUpProofId, "stepUpProofId"),
        authenticatedSession: input.session,
        installation,
        expectedBinding: {
          action,
          scopeKind: "project",
          tenantId,
          projectId,
          targetResourceId: parseCanonicalUuid(endpointId, "endpointId"),
          targetVersion: input.expectedVersion,
          canonicalCommandSha256: commandSha256
        },
        acceptedReceiptId: receiptId,
        proofRepo: this.#authRepos.stepUp,
        now: nowInstant
      });
      stepUpVerified = true;
    }

    await authorizeHumanAction({
      installation,
      principalId: input.session.principal.principalId,
      action,
      tenantId,
      projectId,
      stepUpVerified,
      repo: this.#authRepos.humanAuthorization,
      now: nowInstant
    });

    return this.#uow.inTransaction(async (tx) => {
      const current = await this.#topologyRepo.getEndpoint(tx, tenantId, projectId, endpointId);
      if (current === undefined) {
        throw new ConflictDomainError({
          code: "NOT_FOUND",
          message: `Endpoint "${endpointId}" not found`
        });
      }
      if (current.version !== input.expectedVersion) {
        throw new ConflictDomainError({
          code: "VERSION_CONFLICT",
          message: `Endpoint version mismatch`
        });
      }
      if (
        current.state === "verification_pending" &&
        input.nextState === "active" &&
        input.verificationProofPassed !== true
      ) {
        throw new AuthorizationDomainError({
          code: "FORBIDDEN",
          message: `Endpoint "${endpointId}" cannot activate without passed HTTP 204 proof verification`
        });
      }
      assertTransition("endpoint", ALLOWED_ENDPOINT_TRANSITIONS, current.state, input.nextState, {
        kind: "endpoint",
        id: endpointId
      });

      return this.#topologyRepo.transitionEndpoint(tx, {
        tenantId,
        projectId,
        endpointId,
        expectedVersion: input.expectedVersion,
        nextState: input.nextState,
        reasonCode: input.reasonCode,
        actorPrincipalId: input.session.principal.principalId,
        receiptId,
        idempotencyKeySha256,
        commandSha256,
        effectiveSha256: commandSha256,
        now
      });
    });
  }

  /**
   * Compiles an event JSON Schema, computes its RFC 8785 canonical digest,
   * and registers the immutable schema version.
   */
  async registerEventSchema(
    input: RegisterEventSchemaInput
  ): Promise<TopologyCommandResult<EventSchemaDefinitionRecord>> {
    const tenantId = parseTenantId(input.tenantId, "tenantId");
    const projectId = parseProjectId(input.projectId, "projectId");
    const eventTypeId =
      input.eventTypeId !== undefined
        ? parseEventTypeId(input.eventTypeId, "eventTypeId")
        : parseEventTypeId(this.#ids.nextUuid(), "eventTypeId");
    const eventTypeName = parseEventTypeName(input.eventTypeName, "eventTypeName");
    const compiled = compileEventSchemaFromBytes(input.schemaBytes);
    const schemaRfc8785Sha256 = hashCanonicalJson(
      parseJsonObjectForCanonicalHash(input.schemaBytes, "schemaBytes"),
      "event_schema"
    ).sha256;

    const receiptId = parseCommandReceiptId(this.#ids.nextUuid(), "receiptId");
    const nowInstant = this.#clock.nowInstant();
    const now = parseCanonicalUtcTimestamp(formatUtcTimestamp(nowInstant), "now");
    const action =
      input.targetState === "active" ? "event_schema_versions.publish" : "event_schemas.draft";
    const commandSha256 = hashCanonicalJson(
      {
        event_type_id: eventTypeId,
        event_type_name: eventTypeName,
        schema_version: input.schemaVersion,
        schema_sha256: compiled.definitionSha256,
        rfc8785_sha256: schemaRfc8785Sha256,
        target_state: input.targetState
      },
      "register_event_schema"
    ).sha256;
    const idempotencyKeySha256 = computeCommandGuardKey({
      scope_kind: "project",
      tenant_id: tenantId,
      project_id: projectId,
      actor_principal_id: input.session.principal.principalId,
      command_family: action,
      key_sha256: sha256Utf8Hex(input.idempotencyKey)
    }).digest_sha256;

    const installation = await this.#uow.inTransaction((tx) =>
      this.#readInstallationAuthority(tx)
    );

    let stepUpVerified = false;
    if (action === "event_schema_versions.publish") {
      if (input.stepUpProofId === undefined) {
        throw new AuthorizationDomainError({
          code: "FORBIDDEN",
          message: "Publishing an active event schema version requires stepUpProofId"
        });
      }
      await verifyAndConsumeOperationProof({
        proofId: parseOperationProofId(input.stepUpProofId, "stepUpProofId"),
        authenticatedSession: input.session,
        installation,
        expectedBinding: {
          action,
          scopeKind: "project",
          tenantId,
          projectId,
          targetResourceId: parseCanonicalUuid(eventTypeId, "eventTypeId"),
          targetVersion: BigInt(input.schemaVersion),
          canonicalCommandSha256: commandSha256
        },
        acceptedReceiptId: receiptId,
        proofRepo: this.#authRepos.stepUp,
        now: nowInstant
      });
      stepUpVerified = true;
    }

    await authorizeHumanAction({
      installation,
      principalId: input.session.principal.principalId,
      action,
      tenantId,
      projectId,
      stepUpVerified,
      repo: this.#authRepos.humanAuthorization,
      now: nowInstant
    });

    return this.#uow.inTransaction((tx) =>
      this.#topologyRepo.registerEventSchema(tx, {
        tenantId,
        projectId,
        eventTypeId,
        eventTypeName,
        schemaVersion: input.schemaVersion,
        schemaBytes: input.schemaBytes,
        schemaSha256: schemaRfc8785Sha256,
        targetState: input.targetState,
        actorPrincipalId: input.session.principal.principalId,
        receiptId,
        idempotencyKeySha256,
        commandSha256,
        effectiveSha256: schemaRfc8785Sha256,
        now
      })
    );
  }

  /**
   * Validates filter AST against selected schemas, hashes with RFC 8785,
   * and atomically upserts subscription + increments project topology version.
   */
  async upsertSubscription(
    input: UpsertSubscriptionInput
  ): Promise<
    TopologyCommandResult<{
      readonly topologyVersion: bigint;
      readonly subscriptionVersion: bigint;
    }>
  > {
    const tenantId = parseTenantId(input.tenantId, "tenantId");
    const projectId = parseProjectId(input.projectId, "projectId");
    const subscriptionId =
      input.subscriptionId !== undefined
        ? parseSubscriptionId(input.subscriptionId, "subscriptionId")
        : parseSubscriptionId(this.#ids.nextUuid(), "subscriptionId");
    const endpointId = parseEndpointId(input.endpointId, "endpointId");
    const eventTypeId = parseEventTypeId(input.eventTypeId, "eventTypeId");
    const orderingDomainId =
      input.orderingDomainId !== undefined
        ? parseOrderingDomainId(input.orderingDomainId, "orderingDomainId")
        : undefined;

    if (input.orderingMode === "strict_per_key" && orderingDomainId === undefined) {
      throw new ValidationDomainError({
        code: "INVALID_VALUE",
        message: "strict_per_key subscription requires orderingDomainId"
      });
    }

    const compiledFilter = compileFilterAst(input.filterAst, input.compiledSchemas);
    const filterRfc8785Sha256 = hashCanonicalJson(
      compiledFilter.filterAst as unknown as CanonicalJsonValue,
      "subscription_filter"
    ).sha256;
    const receiptId = parseCommandReceiptId(this.#ids.nextUuid(), "receiptId");
    const nowInstant = this.#clock.nowInstant();
    const now = parseCanonicalUtcTimestamp(formatUtcTimestamp(nowInstant), "now");
    const action =
      input.controlAction === "activate"
        ? "subscriptions.activate"
        : input.controlAction === "resume"
          ? "subscriptions.resume_future"
          : input.controlAction === "disable"
            ? "subscriptions.retire"
            : "subscriptions.create_version";
    const commandSha256 = hashCanonicalJson(
      {
        subscription_id: subscriptionId,
        endpoint_id: endpointId,
        event_type_id: eventTypeId,
        schema_versions: input.schemaVersions,
        filter_sha256: filterRfc8785Sha256,
        ordering_mode: input.orderingMode
      },
      "upsert_subscription"
    ).sha256;
    const idempotencyKeySha256 = computeCommandGuardKey({
      scope_kind: "project",
      tenant_id: tenantId,
      project_id: projectId,
      actor_principal_id: input.session.principal.principalId,
      command_family: action,
      key_sha256: sha256Utf8Hex(input.idempotencyKey)
    }).digest_sha256;

    const installation = await this.#uow.inTransaction((tx) =>
      this.#readInstallationAuthority(tx)
    );

    let stepUpVerified = false;
    if (action !== "subscriptions.create_version") {
      if (input.stepUpProofId === undefined) {
        throw new AuthorizationDomainError({
          code: "FORBIDDEN",
          message: `Action "${action}" requires stepUpProofId`
        });
      }
      await verifyAndConsumeOperationProof({
        proofId: parseOperationProofId(input.stepUpProofId, "stepUpProofId"),
        authenticatedSession: input.session,
        installation,
        expectedBinding: {
          action,
          scopeKind: "project",
          tenantId,
          projectId,
          targetResourceId: parseCanonicalUuid(subscriptionId, "subscriptionId"),
          targetVersion: input.expectedVersion ?? 1n,
          canonicalCommandSha256: commandSha256
        },
        acceptedReceiptId: receiptId,
        proofRepo: this.#authRepos.stepUp,
        now: nowInstant
      });
      stepUpVerified = true;
    }

    await authorizeHumanAction({
      installation,
      principalId: input.session.principal.principalId,
      action,
      tenantId,
      projectId,
      stepUpVerified,
      repo: this.#authRepos.humanAuthorization,
      now: nowInstant
    });

    return this.#uow.inTransaction(async (tx) => {
      const endpoint = await this.#topologyRepo.getEndpoint(tx, tenantId, projectId, endpointId);
      if (endpoint === undefined || endpoint.state === "retired") {
        throw new ConflictDomainError({
          code: "STATE_TRANSITION_NOT_ALLOWED",
          message: `Subscription requires non-retired endpoint "${endpointId}"`
        });
      }
      return this.#topologyRepo.upsertSubscriptionWithTopologyBump(tx, {
        tenantId,
        projectId,
        subscriptionId,
        expectedVersion: input.expectedVersion,
        endpointId,
        eventTypeId,
        schemaVersions: input.schemaVersions,
        filterAst: input.filterAst,
        filterSha256: filterRfc8785Sha256,
        orderingMode: input.orderingMode,
        orderingDomainId,
        consumerContractScope: input.consumerContractScope,
        retryPolicyVersion: input.retryPolicyVersion,
        controlAction: input.controlAction,
        actorPrincipalId: input.session.principal.principalId,
        receiptId,
        idempotencyKeySha256,
        commandSha256,
        effectiveSha256: filterRfc8785Sha256,
        now
      });
    });
  }

  /**
   * Compiles a projection representation profile and computes its RFC 8785 canonical digest.
   */
  async registerRepresentationProfile(
    input: RegisterRepresentationProfileInput
  ): Promise<
    TopologyCommandResult<{
      readonly profileId: RepresentationProfileId;
      readonly profileVersion: bigint;
    }>
  > {
    const tenantId = parseTenantId(input.tenantId, "tenantId");
    const projectId = parseProjectId(input.projectId, "projectId");
    const profileId =
      input.profileId !== undefined
        ? parseRepresentationProfileId(input.profileId, "profileId")
        : parseRepresentationProfileId(this.#ids.nextUuid(), "profileId");
    const eventTypeId = parseEventTypeId(input.eventTypeId, "eventTypeId");

    const parsedJson = parseJsonObjectForCanonicalHash(input.profileBytes, "profileBytes");
    const compiled = compileProjectionProfile(parsedJson, input.sourceSchema, input.targetSchema);
    const profileRfc8785Sha256 = hashCanonicalJson(
      compiled.normalizedMapping as unknown as CanonicalJsonValue,
      "representation_profile"
    ).sha256;

    const receiptId = parseCommandReceiptId(this.#ids.nextUuid(), "receiptId");
    const nowInstant = this.#clock.nowInstant();
    const now = parseCanonicalUtcTimestamp(formatUtcTimestamp(nowInstant), "now");
    const action = input.activate ? "representation_profiles.activate" : "subscriptions.create_version";
    const commandSha256 = hashCanonicalJson(
      {
        profile_id: profileId,
        profile_version: input.profileVersion.toString(10),
        event_type_id: eventTypeId,
        profile_sha256: profileRfc8785Sha256
      },
      "register_representation"
    ).sha256;
    const idempotencyKeySha256 = computeCommandGuardKey({
      scope_kind: "project",
      tenant_id: tenantId,
      project_id: projectId,
      actor_principal_id: input.session.principal.principalId,
      command_family: action,
      key_sha256: sha256Utf8Hex(input.idempotencyKey)
    }).digest_sha256;

    const installation = await this.#uow.inTransaction((tx) =>
      this.#readInstallationAuthority(tx)
    );

    let stepUpVerified = false;
    if (input.activate) {
      if (input.stepUpProofId === undefined) {
        throw new AuthorizationDomainError({
          code: "FORBIDDEN",
          message: "Activating representation profile requires stepUpProofId"
        });
      }
      await verifyAndConsumeOperationProof({
        proofId: parseOperationProofId(input.stepUpProofId, "stepUpProofId"),
        authenticatedSession: input.session,
        installation,
        expectedBinding: {
          action: "representation_profiles.activate",
          scopeKind: "project",
          tenantId,
          projectId,
          targetResourceId: parseCanonicalUuid(profileId, "profileId"),
          targetVersion: input.profileVersion,
          canonicalCommandSha256: commandSha256
        },
        acceptedReceiptId: receiptId,
        proofRepo: this.#authRepos.stepUp,
        now: nowInstant
      });
      stepUpVerified = true;
    }

    await authorizeHumanAction({
      installation,
      principalId: input.session.principal.principalId,
      action,
      tenantId,
      projectId,
      stepUpVerified,
      repo: this.#authRepos.humanAuthorization,
      now: nowInstant
    });

    return this.#uow.inTransaction((tx) =>
      this.#topologyRepo.registerRepresentationProfile(tx, {
        tenantId,
        projectId,
        profileId,
        profileVersion: input.profileVersion,
        eventTypeId,
        sourceSchemaVersion: input.sourceSchemaVersion,
        targetSchemaVersion: input.targetSchemaVersion,
        profileBytes: input.profileBytes,
        profileSha256: profileRfc8785Sha256,
        activate: input.activate,
        actorPrincipalId: input.session.principal.principalId,
        receiptId,
        idempotencyKeySha256,
        commandSha256,
        effectiveSha256: profileRfc8785Sha256,
        now
      })
    );
  }

  async scheduleOrActivateRatePolicyDrain(input: {
    readonly session: AuthenticatedHumanSession;
    readonly tenantId: TenantId | string;
    readonly projectId: ProjectId | string;
    readonly endpointId: EndpointId | string;
    readonly pendingPolicyVersion: bigint;
    readonly targetCapacityMicro: bigint;
    readonly targetRefillMicroPerSec: bigint;
    readonly drainNotBefore: CanonicalUtcTimestamp | string;
    readonly stepUpProofId: OperationProofId | string;
  }): Promise<TopologyCommandResult<RatePolicyDrainRecord>> {
    const tenantId = parseTenantId(input.tenantId, "tenantId");
    const projectId = parseProjectId(input.projectId, "projectId");
    const endpointId = parseEndpointId(input.endpointId, "endpointId");
    const drainNotBefore = parseCanonicalUtcTimestamp(input.drainNotBefore, "drainNotBefore");
    const proofId = parseOperationProofId(input.stepUpProofId, "stepUpProofId");
    const receiptId = parseCommandReceiptId(this.#ids.nextUuid(), "receiptId");
    const nowInstant = this.#clock.nowInstant();
    const now = parseCanonicalUtcTimestamp(formatUtcTimestamp(nowInstant), "now");
    const commandSha256 = hashCanonicalJson(
      {
        endpoint_id: endpointId,
        pending_policy_version: input.pendingPolicyVersion.toString(10),
        target_capacity_micro: input.targetCapacityMicro.toString(10),
        target_refill_micro_per_sec: input.targetRefillMicroPerSec.toString(10),
        drain_not_before: drainNotBefore
      },
      "rate_policy_drain"
    ).sha256;

    const installation = await this.#uow.inTransaction((tx) =>
      this.#readInstallationAuthority(tx)
    );

    await verifyAndConsumeOperationProof({
      proofId,
      authenticatedSession: input.session,
      installation,
      expectedBinding: {
        action: "rate_policy_changes.activate",
        scopeKind: "project",
        tenantId,
        projectId,
        targetResourceId: parseCanonicalUuid(endpointId, "endpointId"),
        targetVersion: input.pendingPolicyVersion,
        canonicalCommandSha256: commandSha256
      },
      acceptedReceiptId: receiptId,
      proofRepo: this.#authRepos.stepUp,
      now: nowInstant
    });

    await authorizeHumanAction({
      installation,
      principalId: input.session.principal.principalId,
      action: "rate_policy_changes.activate",
      tenantId,
      projectId,
      stepUpVerified: true,
      repo: this.#authRepos.humanAuthorization,
      now: nowInstant
    });

    return this.#uow.inTransaction((tx) =>
      this.#topologyRepo.scheduleOrActivateRatePolicyDrain(tx, {
        tenantId,
        projectId,
        endpointId,
        pendingPolicyVersion: input.pendingPolicyVersion,
        targetCapacityMicro: input.targetCapacityMicro,
        targetRefillMicroPerSec: input.targetRefillMicroPerSec,
        drainNotBefore,
        actorPrincipalId: input.session.principal.principalId,
        receiptId,
        commandSha256,
        effectiveSha256: commandSha256,
        now
      })
    );
  }

  async bumpDispatchDomainEpoch(input: {
    readonly session: AuthenticatedHumanSession;
    readonly dispatchDomainId: string;
    readonly expectedVersion: bigint;
    readonly targetResourceId?: string | undefined;
    readonly stepUpProofId: OperationProofId | string;
  }): Promise<TopologyCommandResult<DispatchDomainRecord>> {
    const proofId = parseOperationProofId(input.stepUpProofId, "stepUpProofId");
    const receiptId = parseCommandReceiptId(this.#ids.nextUuid(), "receiptId");
    const nowInstant = this.#clock.nowInstant();
    const now = parseCanonicalUtcTimestamp(formatUtcTimestamp(nowInstant), "now");
    const commandSha256 = hashCanonicalJson(
      {
        dispatch_domain_id: input.dispatchDomainId,
        expected_version: input.expectedVersion.toString(10)
      },
      "bump_dispatch_domain"
    ).sha256;

    const installation = await this.#uow.inTransaction((tx) =>
      this.#readInstallationAuthority(tx)
    );

    await verifyAndConsumeOperationProof({
      proofId,
      authenticatedSession: input.session,
      installation,
      expectedBinding: {
        action: "platform.recovery_controls",
        scopeKind: "installation",
        tenantId: null,
        projectId: null,
        targetResourceId: parseCanonicalUuid(
          input.targetResourceId ?? receiptId,
          "targetResourceId"
        ),
        targetVersion: input.expectedVersion,
        canonicalCommandSha256: commandSha256
      },
      acceptedReceiptId: receiptId,
      proofRepo: this.#authRepos.stepUp,
      now: nowInstant
    });

    await authorizeHumanAction({
      installation,
      principalId: input.session.principal.principalId,
      action: "platform.recovery_controls",
      stepUpVerified: true,
      repo: this.#authRepos.humanAuthorization,
      now: nowInstant
    });

    return this.#uow.inTransaction((tx) =>
      this.#topologyRepo.bumpDispatchDomainEpoch(tx, {
        dispatchDomainId: input.dispatchDomainId,
        expectedVersion: input.expectedVersion,
        actorPrincipalId: input.session.principal.principalId,
        receiptId,
        commandSha256,
        effectiveSha256: commandSha256,
        now
      })
    );
  }
}

export function assertStepUpAuthorizingPrincipal(principalId: PrincipalId, actorId: PrincipalId): void {
  if (principalId !== actorId) {
    throw new AuthorizationDomainError({
      code: "FORBIDDEN",
      message: "Step-up proof principal does not match actor principal"
    });
  }
}
