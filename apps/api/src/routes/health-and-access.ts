import {
  STEP_UP_ALLOWED_ACTIONS,
  approveEnrollmentIntent,
  beginEnrollmentPasskeyOptions,
  completeEnrollmentPasskey,
  completeSignIn,
  completeStepUpChallenge,
  createEnrollmentIntent,
  createSignInOptions,
  createStepUpOptions,
  getAuthenticatedSessionContext,
  getEnrollmentIntentStatus,
  logoutHumanSession,
  revokeOtherHumanSessionsWithStepUp
} from "@relayquill/auth";
import { hashCanonicalJson } from "@relayquill/contracts";
import {
  AuthorizationDomainError,
  type CommandReceiptScopeKind,
  ConflictDomainError,
  type ProjectRole,
  type TenantRole,
  ValidationDomainError,
  formatUtcTimestamp,
  parseCanonicalUuid,
  parseCommandReceiptId,
  parseEnrollmentIntentId,
  parseInt64BigInt,
  parseSha256Hex
} from "@relayquill/domain";
import { type FastifyInstance } from "fastify";
import {
  type ApiContext,
  authenticateHumanMutation,
  authenticateHumanRead,
  consumeStepUpProofFromBody,
  extractCsrfHeader,
  extractStepUpHeader,
  getRawRequestHeaderMap,
  getRequestJsonBody,
  readInstallationSnapshot,
  requireIdempotencyKeyHeader
} from "../context.js";
import { sendSuccessEnvelope } from "../http/errors.js";
import { extractSingleRawHeader } from "../http/headers.js";
import { asText } from "../repos/sql-helpers.js";

export function registerHealthAndAccessRoutes(app: FastifyInstance, ctx: ApiContext): void {
  // Health & Version (both root and /api/v1 prefixes)
  for (const path of ["/health/live", "/api/v1/health/live"]) {
    app.get(path, async (request, reply) => {
      return sendSuccessEnvelope(
        reply,
        200,
        {
          status: "live",
          service: "relayquill-api",
          version: ctx.buildReference
        },
        { requestId: request.id }
      );
    });
  }

  for (const path of ["/version", "/api/v1/version"]) {
    app.get(path, async (request, reply) => {
      return sendSuccessEnvelope(
        reply,
        200,
        {
          service: "relayquill-api",
          version: ctx.buildReference,
          profile: ctx.profile,
          http_schema_version: 1
        },
        { requestId: request.id }
      );
    });
  }

  for (const path of ["/health/ready", "/api/v1/health/ready"]) {
    app.get(path, async (request, reply) => {
      const inst = await ctx.pgAdapter.withTransaction(
        ctx.pgAdapter.configuredRole,
        (tx) => readInstallationSnapshot(ctx, tx),
        { readOnly: true }
      );
      return sendSuccessEnvelope(
        reply,
        200,
        {
          status: "ready",
          database: "ok",
          installation_mode: inst.mode,
          control_epoch: inst.controlEpoch,
          allow_event_admission: inst.allowEventAdmission
        },
        { requestId: request.id }
      );
    });
  }

  // Enrollment Intents
  app.post("/api/v1/access/enrollment-intents", async (request, reply) => {
    const headerMap = getRawRequestHeaderMap(request);
    requireIdempotencyKeyHeader(headerMap);
    const body = getRequestJsonBody(request);
    const cookies = headerMap.get("cookie") ?? [];
    const now = ctx.clock.nowInstant();

    const inst = await ctx.pgAdapter.withTransaction(
      ctx.pgAdapter.configuredRole,
      (tx) => readInstallationSnapshot(ctx, tx),
      { readOnly: true }
    );

    const created = await createEnrollmentIntent({
      policy: ctx.authPolicy,
      installation: inst,
      body,
      cookieHeaders: cookies,
      preauthRepo: ctx.authRepos.preauth!,
      enrollmentRepo: ctx.authRepos.enrollment,
      now
    });

    if (created.preauthSetCookieHeader !== undefined) {
      void reply.header("Set-Cookie", created.preauthSetCookieHeader.expose());
    }

    return sendSuccessEnvelope(
      reply,
      201,
      {
        intent_id: created.intent_id,
        purpose: created.purpose,
        state: created.state,
        version: created.version,
        expires_at: created.expires_at,
        comparison_sha256: created.comparison_sha256,
        next_step: created.next_step
      },
      { requestId: request.id, observedAt: formatUtcTimestamp(now) }
    );
  });

  app.get<{ Params: { intent_id: string } }>(
    "/api/v1/access/enrollment-intents/:intent_id",
    async (request, reply) => {
      const headerMap = getRawRequestHeaderMap(request);
      const cookies = headerMap.get("cookie") ?? [];
      const now = ctx.clock.nowInstant();
      const inst = await ctx.pgAdapter.withTransaction(
        ctx.pgAdapter.configuredRole,
        (tx) => readInstallationSnapshot(ctx, tx),
        { readOnly: true }
      );

      const status = await getEnrollmentIntentStatus({
        policy: ctx.authPolicy,
        installation: inst,
        intentId: request.params.intent_id,
        cookieHeaders: cookies,
        preauthRepo: ctx.authRepos.preauth!,
        enrollmentRepo: ctx.authRepos.enrollment,
        now
      });

      return sendSuccessEnvelope(reply, 200, status, {
        requestId: request.id,
        observedAt: formatUtcTimestamp(now)
      });
    }
  );

  // Explicit dev-only bootstrap approval endpoint (strictly disabled in production profiles)
  app.post<{ Params: { intent_id: string } }>(
    "/api/v1/access/enrollment-intents/:intent_id/bootstrap-approve",
    async (request, reply) => {
      if (!ctx.allowDevBootstrapRoute) {
        throw new AuthorizationDomainError({
          code: "FORBIDDEN",
          message: "Dev bootstrap approval endpoint is disabled in this environment profile"
        });
      }
      const headerMap = getRawRequestHeaderMap(request);
      requireIdempotencyKeyHeader(headerMap);
      const body = getRequestJsonBody(request);
      const intentId = parseEnrollmentIntentId(request.params.intent_id, "intent_id");
      const expectedVersion = parseInt64BigInt(body["expected_version"] ?? body["version"], "version");
      const comparisonSha256 = parseSha256Hex(body["comparison_sha256"], "comparison_sha256");
      const operatorRef =
        typeof body["operator_reference"] === "string" && body["operator_reference"].trim().length > 0
          ? body["operator_reference"].trim()
          : "dev-bootstrap-operator";

      const now = ctx.clock.nowInstant();
      const inst = await ctx.pgAdapter.withTransaction(
        ctx.pgAdapter.configuredRole,
        (tx) => readInstallationSnapshot(ctx, tx),
        { readOnly: true }
      );

      const updated = await approveEnrollmentIntent({
        installation: inst,
        intentId,
        expectedVersion,
        expectedComparisonSha256: comparisonSha256,
        operatorEventReference: operatorRef,
        enrollmentRepo: ctx.authRepos.enrollment,
        now
      });

      return sendSuccessEnvelope(
        reply,
        200,
        {
          intent_id: updated.id,
          state: updated.state,
          version: updated.version.toString(10),
          target_principal_id: updated.targetPrincipalId
        },
        { requestId: request.id, observedAt: formatUtcTimestamp(now) }
      );
    }
  );

  app.post<{ Params: { intent_id: string } }>(
    "/api/v1/access/enrollment-intents/:intent_id/passkey-options",
    async (request, reply) => {
      const headerMap = getRawRequestHeaderMap(request);
      requireIdempotencyKeyHeader(headerMap);
      const body = getRequestJsonBody(request);
      if (body["schema_version"] !== 1) {
        throw new ValidationDomainError({
          code: "UNSUPPORTED_SCHEMA_VERSION",
          message: "passkey-options requires schema_version: 1"
        });
      }
      const cookies = headerMap.get("cookie") ?? [];
      const now = ctx.clock.nowInstant();
      const inst = await ctx.pgAdapter.withTransaction(
        ctx.pgAdapter.configuredRole,
        (tx) => readInstallationSnapshot(ctx, tx),
        { readOnly: true }
      );

      const res = await beginEnrollmentPasskeyOptions({
        policy: ctx.authPolicy,
        installation: inst,
        intentId: request.params.intent_id,
        expectedIntentVersion: parseInt64BigInt(
          body["expected_intent_version"] ?? body["intent_version"] ?? 2,
          "expected_intent_version"
        ),
        authenticatorLabel:
          typeof body["authenticator_label"] === "string" ? body["authenticator_label"] : "primary-passkey",
        cookieHeaders: cookies,
        preauthRepo: ctx.authRepos.preauth!,
        enrollmentRepo: ctx.authRepos.enrollment,
        challengeRepo: ctx.authRepos.challenges!,
        passkeyRepo: ctx.authRepos.passkeys!,
        now
      });

      return sendSuccessEnvelope(reply, 200, res, {
        requestId: request.id,
        observedAt: formatUtcTimestamp(now)
      });
    }
  );

  app.post<{ Params: { intent_id: string } }>(
    "/api/v1/access/enrollment-intents/:intent_id/passkey-complete",
    async (request, reply) => {
      const headerMap = getRawRequestHeaderMap(request);
      requireIdempotencyKeyHeader(headerMap);
      const body = getRequestJsonBody(request);
      if (body["schema_version"] !== 1) {
        throw new ValidationDomainError({
          code: "UNSUPPORTED_SCHEMA_VERSION",
          message: "passkey-complete requires schema_version: 1"
        });
      }
      const cookies = headerMap.get("cookie") ?? [];
      const now = ctx.clock.nowInstant();
      const inst = await ctx.pgAdapter.withTransaction(
        ctx.pgAdapter.configuredRole,
        (tx) => readInstallationSnapshot(ctx, tx),
        { readOnly: true }
      );

      const completed = await completeEnrollmentPasskey({
        policy: ctx.authPolicy,
        installation: inst,
        intentId: request.params.intent_id,
        authChallengeId: asText(body["auth_challenge_id"]),
        response: body["response"],
        cookieHeaders: cookies,
        preauthRepo: ctx.authRepos.preauth!,
        enrollmentRepo: ctx.authRepos.enrollment,
        challengeRepo: ctx.authRepos.challenges!,
        now
      });

      return sendSuccessEnvelope(reply, 200, completed, {
        requestId: request.id,
        observedAt: formatUtcTimestamp(now)
      });
    }
  );

  // Sign-In
  app.post("/api/v1/access/sign-in/options", async (request, reply) => {
    const headerMap = getRawRequestHeaderMap(request);
    requireIdempotencyKeyHeader(headerMap);
    const body = getRequestJsonBody(request);
    const cookies = headerMap.get("cookie") ?? [];
    const now = ctx.clock.nowInstant();
    const inst = await ctx.pgAdapter.withTransaction(
      ctx.pgAdapter.configuredRole,
      (tx) => readInstallationSnapshot(ctx, tx),
      { readOnly: true }
    );

    const res = await createSignInOptions({
      policy: ctx.authPolicy,
      installation: inst,
      cookieHeaders: cookies,
      schemaVersion: body["schema_version"],
      preauthRepo: ctx.authRepos.preauth!,
      challengeRepo: ctx.authRepos.challenges!,
      now
    });

    if (res.preauthSetCookieHeader !== undefined) {
      void reply.header("Set-Cookie", res.preauthSetCookieHeader.expose());
    }

    return sendSuccessEnvelope(
      reply,
      200,
      {
        auth_challenge_id: res.auth_challenge_id,
        public_key: res.public_key
      },
      { requestId: request.id, observedAt: formatUtcTimestamp(now) }
    );
  });

  app.post("/api/v1/access/sign-in/complete", async (request, reply) => {
    const headerMap = getRawRequestHeaderMap(request);
    requireIdempotencyKeyHeader(headerMap);
    const body = getRequestJsonBody(request);
    if (body["schema_version"] !== 1) {
      throw new ValidationDomainError({
        code: "UNSUPPORTED_SCHEMA_VERSION",
        message: "sign-in/complete requires schema_version: 1"
      });
    }
    const cookies = headerMap.get("cookie") ?? [];
    const now = ctx.clock.nowInstant();
    const inst = await ctx.pgAdapter.withTransaction(
      ctx.pgAdapter.configuredRole,
      (tx) => readInstallationSnapshot(ctx, tx),
      { readOnly: true }
    );

    const completed = await completeSignIn({
      policy: ctx.authPolicy,
      installation: inst,
      authChallengeId: asText(body["auth_challenge_id"]),
      response: body["response"],
      cookieHeaders: cookies,
      preauthRepo: ctx.authRepos.preauth!,
      challengeRepo: ctx.authRepos.challenges!,
      passkeyRepo: ctx.authRepos.passkeys!,
      sessionRepo: ctx.authRepos.sessions,
      now
    });

    void reply.header("Set-Cookie", completed.sessionSetCookieHeader.expose());
    void reply.header("Cache-Control", completed.cacheControl);

    return sendSuccessEnvelope(
      reply,
      200,
      completed.session,
      { requestId: request.id, observedAt: formatUtcTimestamp(now) }
    );
  });

  // Session Context & CSRF
  app.get("/api/v1/session/context", async (request, reply) => {
    const headerMap = getRawRequestHeaderMap(request);
    const cookies = headerMap.get("cookie") ?? [];
    const now = ctx.clock.nowInstant();
    const inst = await ctx.pgAdapter.withTransaction(
      ctx.pgAdapter.configuredRole,
      (tx) => readInstallationSnapshot(ctx, tx),
      { readOnly: true }
    );

    const sessionCtx = await getAuthenticatedSessionContext({
      policy: ctx.authPolicy,
      installation: inst,
      cookieHeaders: cookies,
      sessionRepo: ctx.authRepos.sessions,
      now,
      allowRecoveryRestricted: true
    });

    const roles = await ctx.pgAdapter.withTransaction(
      ctx.pgAdapter.configuredRole,
      async (tx) => {
        const platformRoles = await ctx.authRepos.humanAuthorization.listPlatformRolesForPrincipal(
          sessionCtx.principal_id
        );
        const wsRes = await tx.query<Record<string, unknown>>(
          `SELECT p.id AS project_id, p.name AS project_name, p.tenant_id,
                  t.slug AS tenant_slug, t.display_name AS tenant_display_name,
                  pm.role AS project_role, tm.role AS tenant_role
             FROM rq.projects p
             JOIN rq.tenants t ON t.id = p.tenant_id
             LEFT JOIN rq.project_memberships pm
               ON pm.project_id = p.id AND pm.principal_id = $1::uuid AND pm.state = 'active'
             LEFT JOIN rq.tenant_memberships tm
               ON tm.tenant_id = t.id AND tm.principal_id = $1::uuid AND tm.state = 'active'
            WHERE (pm.id IS NOT NULL OR tm.id IS NOT NULL OR $2::boolean = true)
            ORDER BY t.slug ASC, p.name ASC`,
          [
            sessionCtx.principal_id,
            platformRoles.some((r) => r.state === "active")
          ]
        );
        const workspaces = wsRes.rows.map((r) => ({
          tenant_id: String(r["tenant_id"]),
          tenant_slug: String(r["tenant_slug"]),
          tenant_display_name: String(r["tenant_display_name"]),
          project_id: String(r["project_id"]),
          project_name: String(r["project_name"]),
          roles: typeof r["project_role"] === "string"
            ? ([r["project_role"] as ProjectRole] as readonly ProjectRole[])
            : ([] as readonly ProjectRole[]),
          tenant_roles: typeof r["tenant_role"] === "string"
            ? ([r["tenant_role"] as TenantRole] as readonly TenantRole[])
            : ([] as readonly TenantRole[])
        }));

        return {
          platform_roles: platformRoles
            .filter((r) => r.state === "active")
            .map((r) => r.role),
          workspaces
        };
      },
      { readOnly: true }
    );

    void reply.header("Cache-Control", sessionCtx.cacheControl);
    return sendSuccessEnvelope(
      reply,
      200,
      {
        session_id: sessionCtx.session_id,
        principal_id: sessionCtx.principal_id,
        display_name: sessionCtx.display_name,
        purpose: sessionCtx.purpose,
        authority_epoch: sessionCtx.authority_epoch,
        created_at: sessionCtx.created_at,
        idle_expires_at: sessionCtx.idle_expires_at,
        absolute_expires_at: sessionCtx.absolute_expires_at,
        csrf_token: sessionCtx.csrf_token.expose(),
        platform_roles: roles.platform_roles,
        workspaces: roles.workspaces
      },
      { requestId: request.id, observedAt: formatUtcTimestamp(now) }
    );
  });

  app.post("/api/v1/session/csrf", async (request, reply) => {
    const inst = await ctx.pgAdapter.withTransaction(
      ctx.pgAdapter.configuredRole,
      (tx) => readInstallationSnapshot(ctx, tx),
      { readOnly: true }
    );
    const { auth } = await authenticateHumanRead(ctx, request, inst);
    try {
      const csrf_token = auth.deriveCsrfToken().expose();
      void reply.header("Cache-Control", "no-store");
      return sendSuccessEnvelope(
        reply,
        200,
        { csrf_token },
        { requestId: request.id, observedAt: formatUtcTimestamp(ctx.clock.nowInstant()) }
      );
    } finally {
      auth.destroySecrets();
    }
  });

  app.post("/api/v1/session/logout", async (request, reply) => {
    const headerMap = getRawRequestHeaderMap(request);
    requireIdempotencyKeyHeader(headerMap);
    const cookies = headerMap.get("cookie") ?? [];
    const originHeader = extractSingleRawHeader(headerMap, "origin");
    const csrfHeader = extractCsrfHeader(headerMap);
    const now = ctx.clock.nowInstant();
    const inst = await ctx.pgAdapter.withTransaction(
      ctx.pgAdapter.configuredRole,
      (tx) => readInstallationSnapshot(ctx, tx),
      { readOnly: true }
    );

    const out = await logoutHumanSession({
      policy: ctx.authPolicy,
      installation: inst,
      cookieHeaders: cookies,
      originHeader,
      csrfHeader,
      sessionRepo: ctx.authRepos.sessions,
      now
    });

    void reply.header("Set-Cookie", out.clearCookieHeader);
    return sendSuccessEnvelope(
      reply,
      200,
      { logged_out: out.logged_out, session_id: out.session_id },
      { requestId: request.id, observedAt: formatUtcTimestamp(now) }
    );
  });

  app.post("/api/v1/session/revoke-others", async (request, reply) => {
    const inst = await ctx.pgAdapter.withTransaction(
      ctx.pgAdapter.configuredRole,
      (tx) => readInstallationSnapshot(ctx, tx),
      { readOnly: true }
    );
    const { auth, headerMap, body } = await authenticateHumanMutation(ctx, request, inst);
    try {
      if (body["schema_version"] !== 1) {
        throw new ValidationDomainError({
          code: "UNSUPPORTED_SCHEMA_VERSION",
          message: "revoke-others requires schema_version: 1"
        });
      }
      const proofId = body["operation_proof_id"] ?? extractStepUpHeader(headerMap);
      if (typeof proofId !== "string" || proofId.trim().length === 0) {
        throw new AuthorizationDomainError({
          code: "FORBIDDEN",
          message: "revoke-others requires operation_proof_id or X-Relayquill-Step-Up"
        });
      }
      const commandSha =
        typeof body["canonical_command_sha256"] === "string"
          ? parseSha256Hex(body["canonical_command_sha256"], "canonical_command_sha256")
          : hashCanonicalJson({ action: "sessions.revoke_others" }).sha256;
      const now = ctx.clock.nowInstant();
      const res = await revokeOtherHumanSessionsWithStepUp({
        policy: ctx.authPolicy,
        installation: inst,
        cookieHeaders: headerMap.get("cookie") ?? [],
        originHeader: extractSingleRawHeader(headerMap, "origin"),
        csrfHeader: extractCsrfHeader(headerMap),
        operationProofId: proofId,
        canonicalCommandSha256: commandSha,
        acceptedReceiptId: parseCommandReceiptId(ctx.ids.nextUuid(), "receipt_id"),
        sessionRepo: ctx.authRepos.sessions,
        proofRepo: ctx.authRepos.stepUp,
        now
      });

      return sendSuccessEnvelope(reply, 200, res, {
        requestId: request.id,
        observedAt: formatUtcTimestamp(now)
      });
    } finally {
      auth.destroySecrets();
    }
  });

  app.post("/api/v1/session/step-up/options", async (request, reply) => {
    const inst = await ctx.pgAdapter.withTransaction(
      ctx.pgAdapter.configuredRole,
      (tx) => readInstallationSnapshot(ctx, tx),
      { readOnly: true }
    );
    const { auth, body } = await authenticateHumanMutation(ctx, request, inst);
    try {
      if (body["schema_version"] !== 1) {
        throw new ValidationDomainError({
          code: "UNSUPPORTED_SCHEMA_VERSION",
          message: "step-up/options requires schema_version: 1"
        });
      }
      const action = asText(body["action"]);
      if (!STEP_UP_ALLOWED_ACTIONS.has(action)) {
        throw new ValidationDomainError({
          code: "INVALID_VALUE",
          message: `Action "${action}" does not permit or require step-up`
        });
      }
      const scopeKind = asText(body["scope_kind"], "project") as CommandReceiptScopeKind;
      const tenantId = typeof body["tenant_id"] === "string" ? body["tenant_id"] : null;
      const projectId = typeof body["project_id"] === "string" ? body["project_id"] : null;
      const targetResourceId = parseCanonicalUuid(
        body["target_resource_id"],
        "target_resource_id"
      );
      const targetVersion = parseInt64BigInt(body["target_version"] ?? 1, "target_version");
      const canonicalCommandSha256 =
        typeof body["canonical_command_sha256"] === "string"
          ? parseSha256Hex(body["canonical_command_sha256"], "canonical_command_sha256")
          : hashCanonicalJson({
              action,
              tenant_id: tenantId,
              project_id: projectId,
              target_resource_id: targetResourceId,
              target_version: targetVersion.toString(10)
            }).sha256;
      const now = ctx.clock.nowInstant();

      const res = await createStepUpOptions({
        policy: ctx.authPolicy,
        authenticatedSession: auth,
        installation: inst,
        target: {
          action,
          scopeKind,
          tenantId,
          projectId,
          targetResourceId,
          targetVersion,
          canonicalCommandSha256
        },
        challengeRepo: ctx.authRepos.challenges!,
        passkeyRepo: ctx.authRepos.passkeys!,
        now
      });

      return sendSuccessEnvelope(reply, 200, res, {
        requestId: request.id,
        observedAt: formatUtcTimestamp(now)
      });
    } finally {
      auth.destroySecrets();
    }
  });

  app.post("/api/v1/session/step-up/complete", async (request, reply) => {
    const inst = await ctx.pgAdapter.withTransaction(
      ctx.pgAdapter.configuredRole,
      (tx) => readInstallationSnapshot(ctx, tx),
      { readOnly: true }
    );
    const { auth, body } = await authenticateHumanMutation(ctx, request, inst);
    try {
      if (body["schema_version"] !== 1) {
        throw new ValidationDomainError({
          code: "UNSUPPORTED_SCHEMA_VERSION",
          message: "step-up/complete requires schema_version: 1"
        });
      }
      const now = ctx.clock.nowInstant();
      const res = await completeStepUpChallenge({
        policy: ctx.authPolicy,
        authenticatedSession: auth,
        installation: inst,
        authChallengeId: asText(body["auth_challenge_id"]),
        response: body["response"],
        challengeRepo: ctx.authRepos.challenges!,
        passkeyRepo: ctx.authRepos.passkeys!,
        proofRepo: ctx.authRepos.stepUp,
        now
      });

      return sendSuccessEnvelope(reply, 200, res, {
        requestId: request.id,
        observedAt: formatUtcTimestamp(now)
      });
    } finally {
      auth.destroySecrets();
    }
  });

  // Helper reference guard so consumeStepUpProofFromBody / ConflictDomainError remain reachable if refactored
  void consumeStepUpProofFromBody;
  void ConflictDomainError;
}
