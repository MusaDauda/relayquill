import {
  AuthorizationDomainError,
  type CanonicalUtcTimestamp,
  type DataGrantAction,
  type DataGrantProjection,
  type EnrollmentIntentId,
  type EventId,
  NotFoundDomainError,
  type OperationProofId,
  type PrincipalId,
  type ProducerNamespace,
  type ProjectId,
  type Sha256Hex,
  type TenantId,
  ValidationDomainError,
  formatUtcTimestamp,
  parseCommandReceiptId,
  parseDataGrantId,
  parseEnrollmentIntentId,
  parseEventId,
  parseOperationProofId,
  parsePrincipalId,
  parseProjectId,
  parseTenantId,
  parseUtcTimestamp
} from "@relayquill/domain";
import {
  type AuthChallengeRepository,
  type AuthPolicyInput,
  type AuthenticatedHumanSession,
  type AuthorizedHumanDecision,
  type CompleteSignInResult,
  type CompletedEnrollmentResult,
  type CreateEnrollmentIntentRequestInput,
  type CreateSignInOptionsResult,
  type CreateStepUpOptionsResult,
  type CreatedEnrollmentIntentResult,
  type EnrollmentIntentRecord,
  type EnrollmentIntentStatusDto,
  type EnrollmentPasskeyOptionsResult,
  type NormalizedAuthPolicyConfig,
  type OperationProofRecord,
  type PasskeyRepository,
  type PreauthContextRepository,
  type SessionContextDto,
  type StepUpTargetBindingInput,
  approveEnrollmentIntent,
  authenticateHumanSession,
  authenticateSessionMutation,
  authorizeHumanAction,
  beginEnrollmentPasskeyOptions,
  completeEnrollmentPasskey,
  completeSignIn,
  completeStepUpChallenge,
  createEnrollmentIntent,
  createSignInOptions,
  createStepUpOptions,
  getAuthenticatedSessionContext,
  getEnrollmentIntentStatus,
  grantProjectDataAccess as validateProjectDataAccessGrant,
  hasActiveProjectDataGrant,
  logoutHumanSession,
  revokeOtherHumanSessionsWithStepUp,
  verifyAndConsumeOperationProof
} from "@relayquill/auth";
import { parseCanonicalUtcTimestamp, parseCanonicalUuid } from "@relayquill/contracts";
import { type AuthConfig } from "@relayquill/runtime";
import {
  type AuthRepositoriesBundle,
  type ClockPort,
  type GovernanceRepositoryPort,
  type IdGeneratorPort,
  type InstallationAuthoritySnapshot,
  type LosslessPayloadViewRecord,
  type TelemetryPort,
  type UnitOfWorkPort,
  cryptoIdGeneratorPort,
  noopTelemetryPort,
  systemClockPort
} from "./ports.js";

export interface GovernanceServiceDeps<TTx> {
  readonly uow: UnitOfWorkPort<TTx>;
  readonly governanceRepo: GovernanceRepositoryPort<TTx>;
  readonly authRepos: AuthRepositoriesBundle;
  readonly readInstallationAuthority: (tx: TTx) => Promise<InstallationAuthoritySnapshot>;
  readonly authPolicy?: NormalizedAuthPolicyConfig | AuthConfig | AuthPolicyInput | undefined;
  readonly clock?: ClockPort | undefined;
  readonly idGenerator?: IdGeneratorPort | undefined;
  readonly telemetry?: TelemetryPort | undefined;
}

export interface AuthorizeRbacActionInput {
  readonly session: AuthenticatedHumanSession;
  readonly action: string;
  readonly tenantId?: TenantId | string | null | undefined;
  readonly projectId?: ProjectId | string | null | undefined;
  readonly resourceExistsInTargetScope?: boolean | undefined;
  readonly resourceProducerNamespace?: ProducerNamespace | string | null | undefined;
  readonly stepUpProofId?: OperationProofId | string | undefined;
  readonly stepUpBinding?: StepUpTargetBindingInput | undefined;
}

export interface GrantDataAccessInput {
  readonly session: AuthenticatedHumanSession;
  readonly tenantId: TenantId | string;
  readonly projectId: ProjectId | string;
  readonly granteePrincipalId: PrincipalId | string;
  readonly allowedActions: readonly DataGrantAction[];
  readonly projection: DataGrantProjection;
  readonly producerNamespace?: ProducerNamespace | string | null | undefined;
  readonly ticketReference: string;
  readonly expiresAt: CanonicalUtcTimestamp | string;
  readonly canonicalCommandSha256: Sha256Hex | string;
  readonly stepUpProofId: OperationProofId | string;
}

export interface ReadLosslessEventContentInput {
  readonly session: AuthenticatedHumanSession;
  readonly tenantId: TenantId | string;
  readonly projectId: ProjectId | string;
  readonly eventId: EventId | string;
  readonly producerNamespace?: ProducerNamespace | string | null | undefined;
}

export class GovernanceService<TTx> {
  readonly #uow: UnitOfWorkPort<TTx>;
  readonly #governanceRepo: GovernanceRepositoryPort<TTx>;
  readonly #authRepos: AuthRepositoriesBundle;
  readonly #readInstallationAuthority: (tx: TTx) => Promise<InstallationAuthoritySnapshot>;
  readonly #authPolicy: NormalizedAuthPolicyConfig | AuthConfig | AuthPolicyInput | undefined;
  readonly #clock: ClockPort;
  readonly #ids: IdGeneratorPort;
  readonly #telemetry: TelemetryPort;

  constructor(deps: GovernanceServiceDeps<TTx>) {
    this.#uow = deps.uow;
    this.#governanceRepo = deps.governanceRepo;
    this.#authRepos = deps.authRepos;
    this.#readInstallationAuthority = deps.readInstallationAuthority;
    this.#authPolicy = deps.authPolicy;
    this.#clock = deps.clock ?? systemClockPort;
    this.#ids = deps.idGenerator ?? cryptoIdGeneratorPort;
    this.#telemetry = deps.telemetry ?? noopTelemetryPort;
  }

  /**
   * Enforces RBAC role membership + optional step-up proof consumption against
   * live installation epoch and scope membership state.
   */
  async authorizeRbacAction(input: AuthorizeRbacActionInput): Promise<AuthorizedHumanDecision> {
    const span = this.#telemetry.startSpan("relayquill.governance.authorize_rbac");
    try {
      const nowInstant = this.#clock.nowInstant();
      const installation = await this.#uow.inTransaction((tx) =>
        this.#readInstallationAuthority(tx)
      );

      let stepUpVerified = false;
      if (input.stepUpProofId !== undefined) {
        if (input.stepUpBinding === undefined) {
          throw new ValidationDomainError({
            code: "INVALID_VALUE",
            message: "stepUpBinding is required when verifying stepUpProofId"
          });
        }
        const receiptId = parseCommandReceiptId(this.#ids.nextUuid(), "receiptId");
        await verifyAndConsumeOperationProof({
          proofId: parseOperationProofId(input.stepUpProofId, "stepUpProofId"),
          authenticatedSession: input.session,
          installation,
          expectedBinding: input.stepUpBinding,
          acceptedReceiptId: receiptId,
          proofRepo: this.#authRepos.stepUp,
          now: nowInstant
        });
        stepUpVerified = true;
      }

      const decision = await authorizeHumanAction({
        installation,
        principalId: input.session.principal.principalId,
        action: input.action,
        tenantId: input.tenantId,
        projectId: input.projectId,
        resourceExistsInTargetScope: input.resourceExistsInTargetScope,
        resourceProducerNamespace: input.resourceProducerNamespace,
        stepUpVerified,
        repo: this.#authRepos.humanAuthorization,
        now: nowInstant
      });

      span.end({ code: "OK" });
      return decision;
    } catch (err) {
      span.end({
        code: "ERROR",
        message: err instanceof Error ? err.message : "authorize_rbac_failed"
      });
      throw err;
    }
  }

  /**
   * Grants explicit, ticket-referenced, expiring `human_data_grants` access
   * to a project member after step-up verification and projection validation.
   */
  async grantProjectDataAccess(input: GrantDataAccessInput) {
    const tenantId = parseTenantId(input.tenantId, "tenantId");
    const projectId = parseProjectId(input.projectId, "projectId");
    const granteePrincipalId = parsePrincipalId(input.granteePrincipalId, "granteePrincipalId");
    const expiresAt = parseCanonicalUtcTimestamp(input.expiresAt, "expiresAt");
    const expiresAtInstant = parseUtcTimestamp(expiresAt, "expiresAt").instant;
    const proofId = parseOperationProofId(input.stepUpProofId, "stepUpProofId");
    const grantId = parseDataGrantId(this.#ids.nextUuid(), "grantId");
    const receiptId = parseCommandReceiptId(this.#ids.nextUuid(), "receiptId");
    const nowInstant = this.#clock.nowInstant();
    const now = parseCanonicalUtcTimestamp(formatUtcTimestamp(nowInstant), "now");

    if (input.allowedActions.length === 0 || input.ticketReference.trim().length === 0) {
      throw new ValidationDomainError({
        code: "INVALID_VALUE",
        message: "Data grant requires non-empty allowedActions and ticketReference"
      });
    }

    const installation = await this.#uow.inTransaction((tx) =>
      this.#readInstallationAuthority(tx)
    );

    const memberships = await this.#authRepos.humanAuthorization.listProjectMembershipsForPrincipal(
      granteePrincipalId,
      tenantId,
      projectId
    );
    const targetMembership = memberships.find((m) => m.state === "active");
    if (targetMembership === undefined) {
      throw new NotFoundDomainError({
        code: "NOT_FOUND",
        message: `Target principal "${granteePrincipalId}" has no active membership in project "${projectId}"`
      });
    }

    await verifyAndConsumeOperationProof({
      proofId,
      authenticatedSession: input.session,
      installation,
      expectedBinding: {
        action: "data_grants.create",
        scopeKind: "project",
        tenantId,
        projectId,
        targetResourceId: parseCanonicalUuid(granteePrincipalId, "granteePrincipalId"),
        targetVersion: targetMembership.version,
        canonicalCommandSha256: input.canonicalCommandSha256
      },
      acceptedReceiptId: receiptId,
      proofRepo: this.#authRepos.stepUp,
      now: nowInstant
    });

    for (const action of input.allowedActions) {
      await validateProjectDataAccessGrant({
        installation,
        actorPrincipalId: input.session.principal.principalId,
        tenantId,
        projectId,
        targetMembership,
        action,
        projection: input.projection,
        producerNamespace: input.producerNamespace ?? null,
        expiresAt: expiresAtInstant,
        stepUpVerified: true,
        repo: this.#authRepos.humanAuthorization,
        now: nowInstant
      });
    }

    return this.#uow.inTransaction((tx) =>
      this.#governanceRepo.grantProjectDataAccess(tx, {
        grantId,
        tenantId,
        projectId,
        granteePrincipalId,
        grantedByPrincipalId: input.session.principal.principalId,
        allowedActions: input.allowedActions,
        ticketReference: input.ticketReference.trim(),
        expiresAt,
        now
      })
    );
  }

  /**
   * Reads raw lossless event content ONLY when the human session passes both
   * RBAC `events.content.read` AND has an active non-expired `human_data_grants` record.
   */
  async readLosslessEventContent(
    input: ReadLosslessEventContentInput
  ): Promise<LosslessPayloadViewRecord> {
    const span = this.#telemetry.startSpan("relayquill.governance.read_lossless_content");
    try {
      const tenantId = parseTenantId(input.tenantId, "tenantId");
      const projectId = parseProjectId(input.projectId, "projectId");
      const eventId = parseEventId(input.eventId, "eventId");
      const nowInstant = this.#clock.nowInstant();
      const now = parseCanonicalUtcTimestamp(formatUtcTimestamp(nowInstant), "now");

      const installation = await this.#uow.inTransaction((tx) =>
        this.#readInstallationAuthority(tx)
      );

      await authorizeHumanAction({
        installation,
        principalId: input.session.principal.principalId,
        action: "events.content.read",
        tenantId,
        projectId,
        resourceProducerNamespace: input.producerNamespace,
        repo: this.#authRepos.humanAuthorization,
        now: nowInstant
      });

      const hasAuthGrant = await hasActiveProjectDataGrant({
        principalId: input.session.principal.principalId,
        tenantId,
        projectId,
        action: "events.content.read",
        resourceProducerNamespace: input.producerNamespace,
        repo: this.#authRepos.humanAuthorization,
        now: nowInstant
      });

      const repoGrants = await this.#uow.inTransaction((tx) =>
        this.#governanceRepo.listDataGrants(
          tx,
          tenantId,
          projectId,
          input.session.principal.principalId,
          now
        )
      );

      if (!hasAuthGrant && repoGrants.length === 0) {
        throw new AuthorizationDomainError({
          code: "FORBIDDEN",
          message: "Lossless content view requires an active events.content.read human_data_grants row"
        });
      }

      const content = await this.#uow.inTransaction((tx) =>
        this.#governanceRepo.readEventContentLossless(tx, tenantId, projectId, eventId)
      );
      if (content === undefined) {
        throw new NotFoundDomainError({
          code: "NOT_FOUND",
          message: `Lossless content for event "${eventId}" not found`
        });
      }

      span.end({ code: "OK" });
      return content;
    } catch (err) {
      span.end({
        code: "ERROR",
        message: err instanceof Error ? err.message : "read_lossless_failed"
      });
      throw err;
    }
  }

  // ---------------------------------------------------------------------------
  // Session & Passkey Enrollment Orchestration
  // ---------------------------------------------------------------------------

  async createSignInOptions(input: {
    readonly cookieHeaders: string | readonly string[] | undefined;
    readonly schemaVersion: unknown;
    readonly timeoutMs?: number | undefined;
  }): Promise<CreateSignInOptionsResult> {
    const policy = this.#requireAuthPolicy();
    const { preauth, challenges } = this.#requireChallengeRepos();
    const installation = await this.#uow.inTransaction((tx) =>
      this.#readInstallationAuthority(tx)
    );
    return createSignInOptions({
      policy,
      installation,
      cookieHeaders: input.cookieHeaders,
      schemaVersion: input.schemaVersion,
      preauthRepo: preauth,
      challengeRepo: challenges,
      now: this.#clock.nowInstant(),
      timeoutMs: input.timeoutMs
    });
  }

  async completeSignIn(input: {
    readonly authChallengeId: string;
    readonly response: unknown;
    readonly cookieHeaders: string | readonly string[] | undefined;
  }): Promise<CompleteSignInResult> {
    const policy = this.#requireAuthPolicy();
    const { preauth, challenges, passkeys } = this.#requirePasskeyRepos();
    const installation = await this.#uow.inTransaction((tx) =>
      this.#readInstallationAuthority(tx)
    );
    return completeSignIn({
      policy,
      installation,
      authChallengeId: input.authChallengeId,
      response: input.response,
      cookieHeaders: input.cookieHeaders,
      preauthRepo: preauth,
      challengeRepo: challenges,
      passkeyRepo: passkeys,
      sessionRepo: this.#authRepos.sessions,
      now: this.#clock.nowInstant()
    });
  }

  async authenticateSession(input: {
    readonly cookieHeaders: string | readonly string[] | undefined;
    readonly allowRecoveryRestricted?: boolean | undefined;
  }): Promise<AuthenticatedHumanSession> {
    const policy = this.#requireAuthPolicy();
    const installation = await this.#uow.inTransaction((tx) =>
      this.#readInstallationAuthority(tx)
    );
    return authenticateHumanSession({
      policy,
      installation,
      cookieHeaders: input.cookieHeaders,
      sessionRepo: this.#authRepos.sessions,
      now: this.#clock.nowInstant(),
      allowRecoveryRestricted: input.allowRecoveryRestricted
    });
  }

  async authenticateSessionMutation(input: {
    readonly cookieHeaders: string | readonly string[] | undefined;
    readonly originHeader: string | readonly string[] | undefined;
    readonly csrfHeader: string | readonly string[] | undefined;
    readonly allowRecoveryRestricted?: boolean | undefined;
  }): Promise<AuthenticatedHumanSession> {
    const policy = this.#requireAuthPolicy();
    const installation = await this.#uow.inTransaction((tx) =>
      this.#readInstallationAuthority(tx)
    );
    return authenticateSessionMutation({
      policy,
      installation,
      cookieHeaders: input.cookieHeaders,
      originHeader: input.originHeader,
      csrfHeader: input.csrfHeader,
      sessionRepo: this.#authRepos.sessions,
      now: this.#clock.nowInstant(),
      allowRecoveryRestricted: input.allowRecoveryRestricted
    });
  }

  async getSessionContext(input: {
    readonly cookieHeaders: string | readonly string[] | undefined;
    readonly allowRecoveryRestricted?: boolean | undefined;
  }): Promise<SessionContextDto> {
    const policy = this.#requireAuthPolicy();
    const installation = await this.#uow.inTransaction((tx) =>
      this.#readInstallationAuthority(tx)
    );
    return getAuthenticatedSessionContext({
      policy,
      installation,
      cookieHeaders: input.cookieHeaders,
      sessionRepo: this.#authRepos.sessions,
      now: this.#clock.nowInstant(),
      allowRecoveryRestricted: input.allowRecoveryRestricted
    });
  }

  async logoutSession(input: {
    readonly cookieHeaders: string | readonly string[] | undefined;
    readonly originHeader: string | readonly string[] | undefined;
    readonly csrfHeader: string | readonly string[] | undefined;
  }): Promise<{ readonly logged_out: true; readonly clearCookieHeader: string }> {
    const policy = this.#requireAuthPolicy();
    const installation = await this.#uow.inTransaction((tx) =>
      this.#readInstallationAuthority(tx)
    );
    const out = await logoutHumanSession({
      policy,
      installation,
      cookieHeaders: input.cookieHeaders,
      originHeader: input.originHeader,
      csrfHeader: input.csrfHeader,
      sessionRepo: this.#authRepos.sessions,
      now: this.#clock.nowInstant()
    });
    return {
      logged_out: out.logged_out,
      clearCookieHeader: out.clearCookieHeader
    };
  }

  async createStepUpOptions(input: {
    readonly session: AuthenticatedHumanSession;
    readonly target: StepUpTargetBindingInput;
    readonly timeoutMs?: number | undefined;
  }): Promise<CreateStepUpOptionsResult> {
    const policy = this.#requireAuthPolicy();
    const { challenges, passkeys } = this.#requirePasskeyRepos();
    const installation = await this.#uow.inTransaction((tx) =>
      this.#readInstallationAuthority(tx)
    );
    return createStepUpOptions({
      policy,
      authenticatedSession: input.session,
      installation,
      target: input.target,
      challengeRepo: challenges,
      passkeyRepo: passkeys,
      now: this.#clock.nowInstant(),
      timeoutMs: input.timeoutMs
    });
  }

  async completeStepUpChallenge(input: {
    readonly session: AuthenticatedHumanSession;
    readonly authChallengeId: string;
    readonly response: unknown;
  }) {
    const policy = this.#requireAuthPolicy();
    const { challenges, passkeys } = this.#requirePasskeyRepos();
    const installation = await this.#uow.inTransaction((tx) =>
      this.#readInstallationAuthority(tx)
    );
    return completeStepUpChallenge({
      policy,
      authenticatedSession: input.session,
      installation,
      authChallengeId: input.authChallengeId,
      response: input.response,
      challengeRepo: challenges,
      passkeyRepo: passkeys,
      proofRepo: this.#authRepos.stepUp,
      now: this.#clock.nowInstant()
    });
  }

  async verifyAndConsumeStepUpProof(input: {
    readonly proofId: OperationProofId | string;
    readonly session: AuthenticatedHumanSession;
    readonly expectedBinding: StepUpTargetBindingInput;
    readonly acceptedReceiptId: string;
  }): Promise<OperationProofRecord> {
    const installation = await this.#uow.inTransaction((tx) =>
      this.#readInstallationAuthority(tx)
    );
    return verifyAndConsumeOperationProof({
      proofId: input.proofId,
      authenticatedSession: input.session,
      installation,
      expectedBinding: input.expectedBinding,
      acceptedReceiptId: parseCommandReceiptId(input.acceptedReceiptId, "acceptedReceiptId"),
      proofRepo: this.#authRepos.stepUp,
      now: this.#clock.nowInstant()
    });
  }

  async revokeOtherSessionsWithStepUp(input: {
    readonly cookieHeaders: string | readonly string[] | undefined;
    readonly originHeader: string | readonly string[] | undefined;
    readonly csrfHeader: string | readonly string[] | undefined;
    readonly operationProofId: OperationProofId | string;
    readonly canonicalCommandSha256: Sha256Hex | string;
    readonly acceptedReceiptId?: string | undefined;
  }): Promise<{ readonly revoked_count: number; readonly kept_session_id: string }> {
    const policy = this.#requireAuthPolicy();
    const installation = await this.#uow.inTransaction((tx) =>
      this.#readInstallationAuthority(tx)
    );
    return revokeOtherHumanSessionsWithStepUp({
      policy,
      installation,
      cookieHeaders: input.cookieHeaders,
      originHeader: input.originHeader,
      csrfHeader: input.csrfHeader,
      operationProofId: input.operationProofId,
      canonicalCommandSha256: input.canonicalCommandSha256,
      acceptedReceiptId:
        input.acceptedReceiptId ??
        parseCommandReceiptId(this.#ids.nextUuid(), "acceptedReceiptId"),
      sessionRepo: this.#authRepos.sessions,
      proofRepo: this.#authRepos.stepUp,
      now: this.#clock.nowInstant()
    });
  }

  async createEnrollmentIntent(
    input: Omit<
      CreateEnrollmentIntentRequestInput,
      "policy" | "installation" | "preauthRepo" | "enrollmentRepo" | "now"
    >
  ): Promise<CreatedEnrollmentIntentResult> {
    const policy = this.#requireAuthPolicy();
    const { preauth } = this.#requireChallengeRepos();
    const installation = await this.#uow.inTransaction((tx) =>
      this.#readInstallationAuthority(tx)
    );
    return createEnrollmentIntent({
      ...input,
      policy,
      installation,
      preauthRepo: preauth,
      enrollmentRepo: this.#authRepos.enrollment,
      now: this.#clock.nowInstant()
    });
  }

  async getEnrollmentIntentStatus(input: {
    readonly intentId: EnrollmentIntentId | string;
    readonly cookieHeaders: string | readonly string[] | undefined;
  }): Promise<EnrollmentIntentStatusDto> {
    const policy = this.#requireAuthPolicy();
    const { preauth } = this.#requireChallengeRepos();
    const installation = await this.#uow.inTransaction((tx) =>
      this.#readInstallationAuthority(tx)
    );
    return getEnrollmentIntentStatus({
      policy,
      installation,
      intentId: parseEnrollmentIntentId(input.intentId, "intentId"),
      cookieHeaders: input.cookieHeaders,
      preauthRepo: preauth,
      enrollmentRepo: this.#authRepos.enrollment,
      now: this.#clock.nowInstant()
    });
  }

  async approveEnrollmentIntent(input: {
    readonly intentId: EnrollmentIntentId | string;
    readonly expectedVersion: bigint;
    readonly expectedComparisonSha256: Sha256Hex | string;
    readonly approverSession?: AuthenticatedHumanSession | undefined;
    readonly approvedByPrincipalId?: PrincipalId | string | undefined;
    readonly tenantId?: TenantId | string | null | undefined;
    readonly projectId?: ProjectId | string | null | undefined;
  }): Promise<EnrollmentIntentRecord> {
    const installation = await this.#uow.inTransaction((tx) =>
      this.#readInstallationAuthority(tx)
    );
    const approvedBy =
      input.approverSession?.principal.principalId ?? input.approvedByPrincipalId;
    return approveEnrollmentIntent({
      installation,
      intentId: parseEnrollmentIntentId(input.intentId, "intentId"),
      expectedVersion: input.expectedVersion,
      expectedComparisonSha256: input.expectedComparisonSha256,
      ...(approvedBy !== undefined ? { approvedByPrincipalId: approvedBy } : {}),
      tenantId: input.tenantId,
      projectId: input.projectId,
      enrollmentRepo: this.#authRepos.enrollment,
      now: this.#clock.nowInstant()
    });
  }

  async beginEnrollmentPasskeyOptions(input: {
    readonly intentId: EnrollmentIntentId | string;
    readonly expectedIntentVersion: bigint;
    readonly authenticatorLabel: string;
    readonly userAccountLabel?: string | undefined;
    readonly cookieHeaders: string | readonly string[] | undefined;
  }): Promise<EnrollmentPasskeyOptionsResult> {
    const policy = this.#requireAuthPolicy();
    const { preauth, challenges, passkeys } = this.#requirePasskeyRepos();
    const installation = await this.#uow.inTransaction((tx) =>
      this.#readInstallationAuthority(tx)
    );
    return beginEnrollmentPasskeyOptions({
      policy,
      installation,
      intentId: parseEnrollmentIntentId(input.intentId, "intentId"),
      expectedIntentVersion: input.expectedIntentVersion,
      authenticatorLabel: input.authenticatorLabel,
      userAccountLabel: input.userAccountLabel,
      cookieHeaders: input.cookieHeaders,
      preauthRepo: preauth,
      challengeRepo: challenges,
      enrollmentRepo: this.#authRepos.enrollment,
      passkeyRepo: passkeys,
      now: this.#clock.nowInstant()
    });
  }

  async completeEnrollmentPasskey(input: {
    readonly intentId: EnrollmentIntentId | string;
    readonly authChallengeId: string;
    readonly response: unknown;
    readonly cookieHeaders: string | readonly string[] | undefined;
  }): Promise<CompletedEnrollmentResult> {
    const policy = this.#requireAuthPolicy();
    const { preauth, challenges } = this.#requireChallengeRepos();
    const installation = await this.#uow.inTransaction((tx) =>
      this.#readInstallationAuthority(tx)
    );
    return completeEnrollmentPasskey({
      policy,
      installation,
      intentId: parseEnrollmentIntentId(input.intentId, "intentId"),
      authChallengeId: input.authChallengeId,
      response: input.response,
      cookieHeaders: input.cookieHeaders,
      preauthRepo: preauth,
      challengeRepo: challenges,
      enrollmentRepo: this.#authRepos.enrollment,
      now: this.#clock.nowInstant()
    });
  }

  #requireAuthPolicy(): NormalizedAuthPolicyConfig | AuthConfig | AuthPolicyInput {
    if (this.#authPolicy === undefined) {
      throw new ValidationDomainError({
        code: "INVALID_VALUE",
        message: "GovernanceService requires authPolicy for session and passkey orchestration"
      });
    }
    return this.#authPolicy;
  }

  #requireChallengeRepos(): {
    readonly preauth: PreauthContextRepository;
    readonly challenges: AuthChallengeRepository;
  } {
    if (this.#authRepos.preauth === undefined || this.#authRepos.challenges === undefined) {
      throw new ValidationDomainError({
        code: "INVALID_VALUE",
        message: "AuthRepositoriesBundle missing preauth and challenges repositories"
      });
    }
    return {
      preauth: this.#authRepos.preauth,
      challenges: this.#authRepos.challenges
    };
  }

  #requirePasskeyRepos(): {
    readonly preauth: PreauthContextRepository;
    readonly challenges: AuthChallengeRepository;
    readonly passkeys: PasskeyRepository;
  } {
    const base = this.#requireChallengeRepos();
    if (this.#authRepos.passkeys === undefined) {
      throw new ValidationDomainError({
        code: "INVALID_VALUE",
        message: "AuthRepositoriesBundle missing passkeys repository"
      });
    }
    return {
      ...base,
      passkeys: this.#authRepos.passkeys
    };
  }
}
