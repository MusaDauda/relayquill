import crypto from "node:crypto";
import {
  AdmissionService,
  type AuthRepositoriesBundle,
  type ClockPort,
  EvidenceService,
  GovernanceService,
  type IdGeneratorPort,
  type InstallationAuthoritySnapshot,
  OrderingService,
  ReplayGovernanceService,
  type TelemetryPort,
  type UnitOfWorkPort,
  cryptoIdGeneratorPort,
  noopTelemetryPort,
  systemClockPort
} from "@relayquill/application";
import {
  type AuthenticatedHumanSession,
  type AuthorizedHumanDecision,
  GOVERNANCE_ACTION_POLICIES,
  InMemoryTotpReplayGuardStore,
  type NormalizedAuthPolicyConfig,
  type ProducerCredentialSafeMetadata,
  type TotpReplayGuardStore,
  authenticateHumanSession,
  authenticateProducerCredential,
  authenticateSessionMutation,
  authorizeHumanAction,
  extractBearerTokenFromAuthorizationHeader,
  normalizeAuthPolicyConfig,
  verifyAndConsumeOperationProof
} from "@relayquill/auth";
import {
  type AcceptedReceiptDto,
  CAPABILITY_ACTION_REGISTRY,
  type CanonicalJsonValue,
  type CanonicalUtcTimestamp,
  type CanonicalUuid,
  type CapabilityAction,
  type CapabilityEntryDto,
  type CursorPayloadV1,
  type CursorResourceKind,
  type CursorSortOrder,
  decodeCursor,
  encodeCursor,
  hashCanonicalJson,
  parseCanonicalUuid,
  parseInt64String,
  projectCapability,
  sha256Utf8Hex
} from "@relayquill/contracts";
import {
  AuthorizationDomainError,
  type CommandReceiptId,
  type CommandReceiptScopeKind,
  ConflictDomainError,
  type ControlEpoch,
  type PrincipalId,
  type ProjectId,
  type RuntimeInstanceId,
  type Sha256Hex,
  type TenantId,
  ValidationDomainError,
  formatUtcTimestamp,
  nowUtcInstant,
  parseCommandReceiptId,
  parseIdempotencyKey,
  parseOperationProofId,
  parseRuntimeInstanceId,
  parseSha256Hex
} from "@relayquill/domain";
import {
  type PgAdapter,
  type PgTransactionClient,
  readInstallationStatus,
  registerRuntimeInstance
} from "@relayquill/postgres";
import {
  type AuthConfig,
  type ProfileKind,
  type SecretProvider,
  createSecretProvider
} from "@relayquill/runtime";
import { type FastifyBaseLogger, type FastifyRequest } from "fastify";
import {
  HttpStatusDomainError,
  assertStrictRawHeaders,
  extractSingleRawHeader
} from "./http/headers.js";
import {
  createEventSchemaEvaluatorPort,
  createPgAdmissionRepository
} from "./repos/admission-repo.js";
import { createPgAuthRepositories } from "./repos/auth-repos.js";
import {
  createPgEvidenceRepositoryPort,
  createPgGovernanceRepositoryPort,
  createPgOrderingRepositoryPort,
  createPgReplayProposalRepositoryPort,
  createPgUnitOfWork
} from "./repos/operations-repos.js";
import { asText, createAdapterExecutor, createReentrantPgAdapter } from "./repos/sql-helpers.js";

export interface ApiContext {
  readonly pgAdapter: PgAdapter;
  readonly uow: UnitOfWorkPort<PgTransactionClient>;
  readonly authPolicy: NormalizedAuthPolicyConfig;
  readonly authRepos: AuthRepositoriesBundle;
  readonly admissionService: AdmissionService<PgTransactionClient>;
  readonly governanceService: GovernanceService<PgTransactionClient>;
  readonly replayService: ReplayGovernanceService<PgTransactionClient>;
  readonly orderingService: OrderingService<PgTransactionClient>;
  readonly evidenceService: EvidenceService<PgTransactionClient>;
  readonly secretProvider: SecretProvider;
  readonly clock: ClockPort;
  readonly ids: IdGeneratorPort;
  readonly telemetry: TelemetryPort;
  readonly runtimeInstanceId: RuntimeInstanceId;
  readonly profile: ProfileKind;
  readonly buildReference: string;
  readonly allowDevBootstrapRoute: boolean;
  readonly sseHeartbeatMs: number;
  readonly sseMaxLifetimeMs: number;
  readonly cursorSigningKey?: Uint8Array | undefined;
  readonly totpReplayStore: TotpReplayGuardStore;
  readonly totpEncryptionKey: Uint8Array;
  readonly logger: FastifyBaseLogger;
}

export interface CreateApiContextOptions {
  readonly pgAdapter: PgAdapter;
  readonly authConfig?: AuthConfig | undefined;
  readonly profile?: ProfileKind | undefined;
  readonly allowDevBootstrapRoute?: boolean | undefined;
  readonly secretProvider?: SecretProvider | undefined;
  readonly clock?: ClockPort | undefined;
  readonly idGenerator?: IdGeneratorPort | undefined;
  readonly telemetry?: TelemetryPort | undefined;
  readonly runtimeInstanceId?: RuntimeInstanceId | string | undefined;
  readonly buildReference?: string | undefined;
  readonly sseHeartbeatMs?: number | undefined;
  readonly sseMaxLifetimeMs?: number | undefined;
  readonly cursorSigningKey?: Uint8Array | undefined;
  readonly totpReplayStore?: TotpReplayGuardStore | undefined;
  readonly totpEncryptionKey?: Uint8Array | undefined;
  readonly logger: FastifyBaseLogger;
}

export function createApiContext(options: CreateApiContextOptions): ApiContext {
  const profile = options.profile ?? "development_trusted_local";
  const authPolicy = normalizeAuthPolicyConfig(
    options.authConfig ?? {
      rp_id: "localhost",
      allowed_origins: ["http://localhost:5205", "http://localhost:8005"],
      cookie_profile: "development_only"
    }
  );
  const clock = options.clock ?? systemClockPort;
  const ids = options.idGenerator ?? cryptoIdGeneratorPort;
  const telemetry = options.telemetry ?? noopTelemetryPort;
  const pgAdapter = createReentrantPgAdapter(options.pgAdapter);
  const secretProvider = options.secretProvider ?? createSecretProvider({ mode: "in_memory_test" });
  const uow = createPgUnitOfWork(pgAdapter, pgAdapter.configuredRole);
  const authRepos = createPgAuthRepositories(
    createAdapterExecutor(pgAdapter, pgAdapter.configuredRole)
  );
  const readInstallationAuthority = async (
    tx: PgTransactionClient
  ): Promise<InstallationAuthoritySnapshot> => {
    const inst = await readInstallationStatus(tx);
    return {
      controlEpoch: inst.controlEpoch,
      mode: inst.mode,
      allowEventAdmission: inst.allowEventAdmission,
      allowPublication: inst.allowPublication,
      allowFanout: inst.allowFanout,
      allowSend: inst.allowSend,
      allowEndpointVerification: inst.allowEndpointVerification,
      governanceVersion: inst.governanceVersion,
      updatedAt: inst.updatedAt,
      version: inst.version
    };
  };

  const admissionRepo = createPgAdmissionRepository();
  const governanceRepo = createPgGovernanceRepositoryPort();
  const replayRepo = createPgReplayProposalRepositoryPort();
  const orderingRepo = createPgOrderingRepositoryPort();
  const evidenceRepo = createPgEvidenceRepositoryPort();
  const schemaEvaluator = createEventSchemaEvaluatorPort();

  const admissionService = new AdmissionService({
    uow,
    admissionRepo,
    producerCredentialRepo: authRepos.producerCredentials,
    schemaEvaluator,
    clock,
    idGenerator: ids,
    telemetry
  });

  const governanceService = new GovernanceService({
    uow,
    governanceRepo,
    authRepos,
    readInstallationAuthority,
    authPolicy,
    clock,
    idGenerator: ids,
    telemetry
  });

  const replayService = new ReplayGovernanceService({
    uow,
    replayRepo,
    authRepos,
    readInstallationAuthority,
    clock,
    idGenerator: ids,
    telemetry
  });

  const orderingService = new OrderingService({
    uow,
    orderingRepo,
    authRepos,
    readInstallationAuthority,
    clock,
    idGenerator: ids,
    telemetry
  });

  const evidenceService = new EvidenceService({
    uow,
    evidenceRepo,
    telemetry
  });

  const runtimeInstanceId = parseRuntimeInstanceId(
    options.runtimeInstanceId ?? crypto.randomUUID(),
    "runtimeInstanceId"
  );

  const allowDevBootstrapRoute =
    options.allowDevBootstrapRoute ??
    (profile === "development_trusted_local" || profile === "portable_pglite");
  const totpReplayStore = options.totpReplayStore ?? new InMemoryTotpReplayGuardStore();
  const totpEncryptionKey =
    options.totpEncryptionKey ??
    crypto.createHash("sha256").update("relayquill-local-totp-envelope-v1", "utf8").digest();

  return {
    pgAdapter,
    uow,
    authPolicy,
    authRepos,
    admissionService,
    governanceService,
    replayService,
    orderingService,
    evidenceService,
    secretProvider,
    clock,
    ids,
    telemetry,
    runtimeInstanceId,
    profile,
    buildReference: options.buildReference ?? "relayquill-api/0.1.0",
    allowDevBootstrapRoute,
    sseHeartbeatMs: options.sseHeartbeatMs ?? 10_000,
    sseMaxLifetimeMs: options.sseMaxLifetimeMs ?? 60_000,
    cursorSigningKey: options.cursorSigningKey,
    totpReplayStore,
    totpEncryptionKey,
    logger: options.logger
  };
}

export async function readInstallationSnapshot(
  ctx: ApiContext,
  tx: PgTransactionClient
): Promise<InstallationAuthoritySnapshot> {
  const inst = await readInstallationStatus(tx);
  return {
    controlEpoch: inst.controlEpoch,
    mode: inst.mode,
    allowEventAdmission: inst.allowEventAdmission,
    allowPublication: inst.allowPublication,
    allowFanout: inst.allowFanout,
    allowSend: inst.allowSend,
    allowEndpointVerification: inst.allowEndpointVerification,
    governanceVersion: inst.governanceVersion,
    updatedAt: inst.updatedAt,
    version: inst.version
  };
}

export async function ensureApiRuntimeRegistered(
  ctx: ApiContext,
  tx: PgTransactionClient,
  controlEpoch: ControlEpoch
): Promise<void> {
  const exists = await tx.query<{ id: string }>(
    "SELECT id FROM rq.runtime_instances WHERE id = $1::uuid",
    [ctx.runtimeInstanceId]
  );
  if (exists.rows[0] !== undefined) {
    return;
  }
  await registerRuntimeInstance(tx, {
    instanceId: ctx.runtimeInstanceId,
    processRole: "api",
    databaseRole: ctx.pgAdapter.configuredRole === "postgres" ? "rq_api" : ctx.pgAdapter.configuredRole,
    controlEpoch,
    buildReference: ctx.buildReference,
    leaseMs: 300_000n
  });
}

export function deterministicUuid(namespace: string, ...parts: readonly string[]): CanonicalUuid {
  const hash = crypto
    .createHash("sha256")
    .update(`${namespace}:${parts.join(":")}`, "utf8")
    .digest();
  hash[6] = ((hash[6] ?? 0) & 0x0f) | 0x40;
  hash[8] = ((hash[8] ?? 0) & 0x3f) | 0x80;
  const hex = hash.subarray(0, 16).toString("hex");
  return parseCanonicalUuid(
    `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20, 32)}`,
    "deterministic_uuid"
  );
}

export function stripUndefinedJson(
  obj: Readonly<Record<string, unknown>>
): CanonicalJsonValue {
  const out: Record<string, CanonicalJsonValue> = {};
  for (const [k, v] of Object.entries(obj)) {
    if (v !== undefined) {
      out[k] = v as CanonicalJsonValue;
    }
  }
  return out;
}

export function extractCsrfHeader(
  headerMap: ReadonlyMap<string, readonly string[]>
): string | undefined {
  const primary = extractSingleRawHeader(headerMap, "x-csrf-token");
  const relayquill = extractSingleRawHeader(headerMap, "x-relayquill-csrf");
  if (primary !== undefined && relayquill !== undefined && primary !== relayquill) {
    throw new HttpStatusDomainError(
      400,
      "Conflicting X-CSRF-Token and X-Relayquill-CSRF headers",
      "headers.x-csrf-token"
    );
  }
  return primary ?? relayquill;
}

export function extractStepUpHeader(
  headerMap: ReadonlyMap<string, readonly string[]>
): string | undefined {
  return extractSingleRawHeader(headerMap, "x-relayquill-step-up");
}

export function getRawRequestHeaderMap(
  request: FastifyRequest
): ReadonlyMap<string, readonly string[]> {
  return assertStrictRawHeaders(request.raw.rawHeaders);
}

export function getRequestJsonBody(request: FastifyRequest): Record<string, unknown> {
  const body = request.body;
  if (body === null || typeof body !== "object" || Array.isArray(body)) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: "Request body must be a JSON object",
      fieldErrors: [{ path: "body", code: "INVALID_VALUE" }]
    });
  }
  return body as Record<string, unknown>;
}

export function requireIdempotencyKeyHeader(
  headerMap: ReadonlyMap<string, readonly string[]>
): string {
  const raw = extractSingleRawHeader(headerMap, "idempotency-key");
  if (raw === undefined || raw.length === 0) {
    throw new ValidationDomainError({
      code: "INVALID_IDEMPOTENCY_KEY",
      message: "Idempotency-Key header is required",
      fieldErrors: [{ path: "headers.idempotency-key", code: "INVALID_IDEMPOTENCY_KEY" }]
    });
  }
  return parseIdempotencyKey(raw, "headers.idempotency-key");
}

export async function authenticateHumanRead(
  ctx: ApiContext,
  request: FastifyRequest,
  installation: InstallationAuthoritySnapshot
): Promise<{
  readonly auth: AuthenticatedHumanSession;
  readonly headerMap: ReadonlyMap<string, readonly string[]>;
}> {
  const headerMap = getRawRequestHeaderMap(request);
  const cookies = headerMap.get("cookie") ?? [];
  const auth = await authenticateHumanSession({
    policy: ctx.authPolicy,
    installation,
    cookieHeaders: cookies,
    sessionRepo: ctx.authRepos.sessions,
    now: ctx.clock.nowInstant()
  });
  return { auth, headerMap };
}

export async function authenticateHumanMutation(
  ctx: ApiContext,
  request: FastifyRequest,
  installation: InstallationAuthoritySnapshot
): Promise<{
  readonly auth: AuthenticatedHumanSession;
  readonly headerMap: ReadonlyMap<string, readonly string[]>;
  readonly idempotencyKey: string;
  readonly body: Record<string, unknown>;
}> {
  const headerMap = getRawRequestHeaderMap(request);
  const idempotencyKey = requireIdempotencyKeyHeader(headerMap);
  const cookies = headerMap.get("cookie") ?? [];
  const originHeader = extractSingleRawHeader(headerMap, "origin");
  const csrfHeader = extractCsrfHeader(headerMap);

  const auth = await authenticateSessionMutation({
    policy: ctx.authPolicy,
    installation,
    cookieHeaders: cookies,
    originHeader,
    csrfHeader,
    sessionRepo: ctx.authRepos.sessions,
    now: ctx.clock.nowInstant()
  });
  const body = getRequestJsonBody(request);
  return { auth, headerMap, idempotencyKey, body };
}

export type ResolvedActor =
  | { readonly kind: "human"; readonly session: AuthenticatedHumanSession }
  | { readonly kind: "producer"; readonly metadata: ProducerCredentialSafeMetadata };

export async function authenticateHumanOrProducerRead(
  ctx: ApiContext,
  request: FastifyRequest,
  installation: InstallationAuthoritySnapshot
): Promise<{
  readonly actor: ResolvedActor;
  readonly headerMap: ReadonlyMap<string, readonly string[]>;
}> {
  const headerMap = getRawRequestHeaderMap(request);
  const authHeader = extractSingleRawHeader(headerMap, "authorization");

  if (authHeader !== undefined && authHeader.length > 0) {
    const bearerToken = extractBearerTokenFromAuthorizationHeader(authHeader);
    const authenticated = await authenticateProducerCredential({
      installation,
      bearerToken,
      repo: ctx.authRepos.producerCredentials,
      now: ctx.clock.nowInstant()
    });
    return {
      actor: { kind: "producer", metadata: authenticated.credential },
      headerMap
    };
  }

  const cookies = headerMap.get("cookie") ?? [];
  const session = await authenticateHumanSession({
    policy: ctx.authPolicy,
    installation,
    cookieHeaders: cookies,
    sessionRepo: ctx.authRepos.sessions,
    now: ctx.clock.nowInstant()
  });
  return { actor: { kind: "human", session }, headerMap };
}

export async function authorizeAction(
  ctx: ApiContext,
  session: AuthenticatedHumanSession,
  action: string,
  scope: {
    readonly installation?: InstallationAuthoritySnapshot | undefined;
    readonly tenantId?: TenantId | string | null | undefined;
    readonly projectId?: ProjectId | string | null | undefined;
    readonly resourceExistsInTargetScope?: boolean | undefined;
    readonly resourceProducerNamespace?: string | null | undefined;
    readonly stepUpVerified?: boolean | undefined;
    readonly stepUpProofId?: string | undefined;
  } = {}
): Promise<AuthorizedHumanDecision> {
  const installation =
    scope.installation ??
    (await ctx.pgAdapter.withTransaction(
      ctx.pgAdapter.configuredRole,
      (tx) => readInstallationSnapshot(ctx, tx),
      { readOnly: true }
    ));
  return authorizeHumanAction({
    installation,
    principalId: session.principal.principalId,
    action,
    tenantId: scope.tenantId ?? null,
    projectId: scope.projectId ?? null,
    ...(scope.resourceExistsInTargetScope !== undefined
      ? { resourceExistsInTargetScope: scope.resourceExistsInTargetScope }
      : {}),
    ...(scope.resourceProducerNamespace !== undefined
      ? { resourceProducerNamespace: scope.resourceProducerNamespace }
      : {}),
    stepUpVerified:
      scope.stepUpVerified ??
      (scope.stepUpProofId !== undefined && scope.stepUpProofId.trim().length > 0),
    repo: ctx.authRepos.humanAuthorization,
    now: ctx.clock.nowInstant()
  });
}

export async function consumeStepUpProofFromBody(input: {
  readonly ctx: ApiContext;
  readonly auth: AuthenticatedHumanSession;
  readonly installation: InstallationAuthoritySnapshot;
  readonly body: Record<string, unknown>;
  readonly headerMap?: ReadonlyMap<string, readonly string[]> | undefined;
  readonly action: string;
  readonly scopeKind: CommandReceiptScopeKind;
  readonly tenantId: TenantId | null;
  readonly projectId: ProjectId | null;
  readonly targetResourceId: CanonicalUuid | string;
  readonly targetVersion: bigint | string | number;
  readonly receiptId: CommandReceiptId;
  readonly expectedCommandSha256?: Sha256Hex | undefined;
}): Promise<Sha256Hex> {
  const headerProof = input.headerMap !== undefined ? extractStepUpHeader(input.headerMap) : undefined;
  const rawProofId = input.body["operation_proof_id"] ?? headerProof;
  if (typeof rawProofId !== "string" || rawProofId.trim().length === 0) {
    throw new AuthorizationDomainError({
      code: "FORBIDDEN",
      message: `Action "${input.action}" requires operation_proof_id or X-Relayquill-Step-Up from step-up verification`
    });
  }
  const proofId = parseOperationProofId(rawProofId, "operation_proof_id");

  const canonicalCommandSha256 =
    typeof input.body["canonical_command_sha256"] === "string"
      ? parseSha256Hex(input.body["canonical_command_sha256"], "canonical_command_sha256")
      : (input.expectedCommandSha256 ??
          hashCanonicalJson({
            action: input.action,
            tenant_id: input.tenantId,
            project_id: input.projectId,
            target_resource_id: input.targetResourceId,
            target_version: input.targetVersion.toString(10)
          }).sha256);

  await verifyAndConsumeOperationProof({
    proofId,
    authenticatedSession: input.auth,
    installation: input.installation,
    expectedBinding: {
      action: input.action,
      scopeKind: input.scopeKind,
      tenantId: input.tenantId,
      projectId: input.projectId,
      targetResourceId: input.targetResourceId,
      targetVersion: input.targetVersion,
      canonicalCommandSha256
    },
    acceptedReceiptId: input.receiptId,
    proofRepo: input.ctx.authRepos.stepUp,
    now: input.ctx.clock.nowInstant()
  });

  return canonicalCommandSha256;
}

export async function checkCommandReceiptIdempotency(
  tx: PgTransactionClient,
  params: {
    readonly scopeKind: CommandReceiptScopeKind;
    readonly tenantId: TenantId | null;
    readonly projectId: ProjectId | null;
    readonly actorPrincipalId: PrincipalId;
    readonly commandFamily: string;
    readonly idempotencyKey: string;
    readonly submittedShapeSha256: Sha256Hex;
  }
): Promise<AcceptedReceiptDto | null> {
  const keySha256 = sha256Utf8Hex(params.idempotencyKey);
  const keyBuf = Buffer.from(keySha256, "hex");
  const res = await tx.query<Record<string, unknown>>(
    `SELECT id, resource_kind, resource_id, accepted_version, accepted_at, submitted_shape_sha256
       FROM rq.command_receipts
      WHERE scope_kind = $1::text
        AND (($1::text = 'installation' AND tenant_id IS NULL AND project_id IS NULL)
          OR ($1::text = 'tenant' AND tenant_id = $2::uuid AND project_id IS NULL)
          OR ($1::text = 'project' AND project_id = $3::uuid))
        AND actor_principal_id = $4::uuid
        AND command_family = $5::text
        AND key_sha256 = $6::bytea`,
    [
      params.scopeKind,
      params.tenantId,
      params.projectId,
      params.actorPrincipalId,
      params.commandFamily,
      keyBuf
    ]
  );
  const row = res.rows[0];
  if (row === undefined) {
    return null;
  }
  const existingHex = Buffer.isBuffer(row["submitted_shape_sha256"])
    ? row["submitted_shape_sha256"].toString("hex")
    : String(row["submitted_shape_sha256"]).replace(/^\\x/, "");
  if (existingHex !== params.submittedShapeSha256) {
    throw new ConflictDomainError({
      code: "IDEMPOTENCY_CONFLICT",
      message: `Idempotency-Key reused with mismatched payload for ${params.commandFamily}`
    });
  }
  return {
    id: parseCommandReceiptId(row["id"], "receipt.id"),
    accepted_at: formatPgTimestamp(row["accepted_at"]),
    resource_kind: String(row["resource_kind"]),
    resource_id: parseCanonicalUuid(row["resource_id"], "resource_id"),
    accepted_version:
      row["accepted_version"] !== null && row["accepted_version"] !== undefined
        ? parseInt64String(asText(row["accepted_version"]), "accepted_version")
        : null
  };
}

export async function insertCommandReceiptAndAudit(
  tx: PgTransactionClient,
  params: {
    readonly receiptId: CommandReceiptId;
    readonly scopeKind: CommandReceiptScopeKind;
    readonly tenantId: TenantId | null;
    readonly projectId: ProjectId | null;
    readonly actorPrincipalId: PrincipalId;
    readonly commandFamily: string;
    readonly idempotencyKey: string;
    readonly submittedShapeSha256: Sha256Hex;
    readonly effectiveRequestSha256?: Sha256Hex | undefined;
    readonly resourceKind: string;
    readonly resourceId: CanonicalUuid | string;
    readonly acceptedVersion: bigint | null;
    readonly priorVersion?: bigint | null | undefined;
    readonly safeFacts?: Readonly<Record<string, unknown>> | undefined;
    readonly now: CanonicalUtcTimestamp;
  }
): Promise<AcceptedReceiptDto> {
  const keySha256 = sha256Utf8Hex(params.idempotencyKey);
  const effectiveSha = params.effectiveRequestSha256 ?? params.submittedShapeSha256;
  await tx.query(
    `INSERT INTO rq.command_receipts (
       id, scope_kind, tenant_id, project_id, actor_principal_id, command_family,
       key_sha256, submitted_shape_sha256, effective_request_sha256, resource_kind,
       resource_id, accepted_version, applied_defaults, accepted_at, hash_schema_version
     ) VALUES (
       $1::uuid, $2::text, $3::uuid, $4::uuid, $5::uuid, $6::text,
       $7::bytea, $8::bytea, $9::bytea, $10::text,
       $11::uuid, $12::bigint, '{}'::jsonb, $13::timestamptz, 1
     ) ON CONFLICT (id) DO NOTHING`,
    [
      params.receiptId,
      params.scopeKind,
      params.tenantId,
      params.projectId,
      params.actorPrincipalId,
      params.commandFamily,
      Buffer.from(keySha256, "hex"),
      Buffer.from(params.submittedShapeSha256, "hex"),
      Buffer.from(effectiveSha, "hex"),
      params.resourceKind,
      params.resourceId,
      params.acceptedVersion !== null ? params.acceptedVersion.toString(10) : null,
      params.now
    ]
  );

  await tx.query(
    `INSERT INTO rq.audit_events (
       id, tenant_id, project_id, actor_kind, actor_reference, action,
       target_kind, target_id, prior_version, resulting_version, candidate_sha256,
       command_receipt_id, recorded_at, safe_facts
     ) VALUES (
       $1::uuid, $2::uuid, $3::uuid, 'human', $4::uuid, $5::text,
       $6::text, $7::uuid, $8::bigint, $9::bigint, $10::bytea,
       $11::uuid, $12::timestamptz, $13::jsonb
     )`,
    [
      crypto.randomUUID(),
      params.tenantId,
      params.projectId,
      params.actorPrincipalId,
      params.commandFamily,
      params.resourceKind,
      params.resourceId,
      params.priorVersion !== undefined && params.priorVersion !== null
        ? params.priorVersion.toString(10)
        : null,
      params.acceptedVersion !== null ? params.acceptedVersion.toString(10) : null,
      Buffer.from(effectiveSha, "hex"),
      params.receiptId,
      params.now,
      JSON.stringify(params.safeFacts ?? {})
    ]
  );

  return {
    id: params.receiptId,
    accepted_at: params.now,
    resource_kind: params.resourceKind,
    resource_id: parseCanonicalUuid(params.resourceId, "resource_id"),
    accepted_version:
      params.acceptedVersion !== null
        ? parseInt64String(params.acceptedVersion.toString(10), "accepted_version")
        : null
  };
}

export function buildCapabilitiesForActions(
  ctx: ApiContext,
  decision: AuthorizedHumanDecision,
  targetKind: CapabilityEntryDto["target_kind"],
  targetId: CanonicalUuid | string,
  actions: readonly CapabilityAction[],
  options: {
    readonly expectedVersion?: ((action: CapabilityAction) => bigint | null) | bigint | null | undefined;
    readonly stateAllowed?:
      | ((action: CapabilityAction) => { allowed: boolean; reasonCode?: string; reasonMessage?: string })
      | undefined;
    readonly twoPersonBlocked?: ((action: CapabilityAction) => boolean) | undefined;
    readonly grantSatisfied?: ((action: CapabilityAction) => boolean) | undefined;
  } = {}
): readonly CapabilityEntryDto[] {
  const safeTargetId = parseCanonicalUuid(targetId, "target_id");
  const isPlatformAdmin = decision.matchedPlatformRoles.includes("platform_admin");
  const isTenantAdmin = decision.matchedTenantRoles.includes("tenant_admin");

  return actions.map((action) => {
    const spec = CAPABILITY_ACTION_REGISTRY[action];
    const policy = GOVERNANCE_ACTION_POLICIES[action];
    const rbacAllowed =
      isPlatformAdmin ||
      isTenantAdmin ||
      (policy !== undefined &&
        ((policy.projectRoles ?? []).some((r) => decision.matchedProjectRoles.includes(r)) ||
          (policy.tenantRoles ?? []).some((r) => decision.matchedTenantRoles.includes(r)) ||
          (policy.platformRoles ?? []).some((r) => decision.matchedPlatformRoles.includes(r))));

    const stateCheck = options.stateAllowed ? options.stateAllowed(action) : { allowed: true };
    const twoPersonCheck = options.twoPersonBlocked?.(action) ?? false;
    const requiresDataGrant = policy?.requiredDataGrantAction !== undefined;
    const grantSatisfied = options.grantSatisfied
      ? options.grantSatisfied(action)
      : !requiresDataGrant || decision.matchedDataGrantId !== undefined;

    const available = rbacAllowed && stateCheck.allowed && !twoPersonCheck && grantSatisfied;
    let reasonCode: string | null = null;
    if (!available) {
      if (!rbacAllowed) {
        reasonCode = "FORBIDDEN";
      } else if (!grantSatisfied) {
        reasonCode = "DATA_GRANT_REQUIRED";
      } else if (twoPersonCheck) {
        reasonCode = "SELF_APPROVAL_NOT_ALLOWED";
      } else {
        reasonCode = stateCheck.reasonCode ?? "STATE_TRANSITION_NOT_ALLOWED";
      }
    }

    const expectedVersionVal =
      typeof options.expectedVersion === "function"
        ? options.expectedVersion(action)
        : (options.expectedVersion ?? null);

    return projectCapability({
      action,
      target_kind: targetKind,
      target_id: safeTargetId,
      expected_version: expectedVersionVal,
      available,
      reason_code: reasonCode,
      requires_step_up: policy?.requiresStepUp ?? spec.requiresStepUp,
      requires_distinct_reviewer: policy?.requiresDistinctReviewer ?? spec.requiresDistinctReviewer
    });
  });
  void ctx;
}

export function parseCursorQueryParams(
  query: Record<string, unknown>
): { readonly limit: number; readonly rawCursor?: string | undefined } {
  let limit = 50;
  if (typeof query["limit"] === "string" && /^\d+$/.test(query["limit"].trim())) {
    limit = Math.min(100, Math.max(1, Number.parseInt(query["limit"].trim(), 10)));
  } else if (typeof query["limit"] === "number" && Number.isSafeInteger(query["limit"])) {
    limit = Math.min(100, Math.max(1, query["limit"]));
  }
  const rawCursor =
    typeof query["cursor"] === "string" && query["cursor"].trim().length > 0
      ? query["cursor"].trim()
      : undefined;
  return { limit, rawCursor };
}

export function decodeApiCursor(
  ctx: ApiContext,
  rawCursor: string | undefined,
  context: {
    readonly resource: CursorResourceKind;
    readonly tenantId: TenantId | null;
    readonly projectId: ProjectId | null;
    readonly parentId?: CanonicalUuid | null | undefined;
    readonly order: CursorSortOrder;
    readonly filter?: Record<string, unknown> | undefined;
  }
): CursorPayloadV1 | null {
  if (rawCursor === undefined) {
    return null;
  }
  const filterSha = hashCanonicalJson(stripUndefinedJson(context.filter ?? {})).sha256;
  return decodeCursor(
    rawCursor,
    {
      resource: context.resource,
      tenant_id: context.tenantId,
      project_id: context.projectId,
      parent_id: context.parentId ?? null,
      order: context.order,
      filter_sha256: filterSha
    },
    { signingKey: ctx.cursorSigningKey }
  );
}

export function encodeApiCursor(
  ctx: ApiContext,
  context: {
    readonly resource: CursorResourceKind;
    readonly tenantId: TenantId | null;
    readonly projectId: ProjectId | null;
    readonly parentId?: CanonicalUuid | null | undefined;
    readonly order: CursorSortOrder;
    readonly filter?: Record<string, unknown> | undefined;
    readonly boundary: CursorPayloadV1["boundary"];
  }
): string {
  const filterSha = hashCanonicalJson(stripUndefinedJson(context.filter ?? {})).sha256;
  return encodeCursor(
    {
      resource: context.resource,
      tenant_id: context.tenantId,
      project_id: context.projectId,
      parent_id: context.parentId ?? null,
      order: context.order,
      filter_sha256: filterSha,
      boundary: context.boundary
    },
    { signingKey: ctx.cursorSigningKey }
  );
}

export function formatPgTimestamp(val: unknown): CanonicalUtcTimestamp {
  if (val instanceof Date) {
    return val.toISOString() as CanonicalUtcTimestamp;
  }
  if (typeof val === "string") {
    const parsed = new Date(val);
    if (!Number.isNaN(parsed.getTime())) {
      return parsed.toISOString() as CanonicalUtcTimestamp;
    }
  }
  return formatUtcTimestamp(nowUtcInstant());
}
