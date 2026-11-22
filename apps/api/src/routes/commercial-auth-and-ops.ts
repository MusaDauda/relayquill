import crypto from "node:crypto";
import {
  BREAK_GLASS_HEADER_NAME,
  buildBreakGlassWindow,
  buildTotpOtpauthUri,
  computeCsrfDigest,
  computeSessionTokenDigest,
  deriveCsrfTokenBytes,
  formatSetCookieHeader,
  generateRandomBase64UrlToken,
  generateTotpSecret,
  hashBreakGlassToken,
  hashPasswordArgon2id,
  isCommercialUserRole,
  logoutHumanSession,
  mapOidcClaimsToTenantRole,
  mintBreakGlassToken,
  openTotpSecret,
  resolveSessionCookieName,
  sealTotpSecret,
  SESSION_TOKEN_BYTE_LENGTH,
  validateBreakGlassReadScope,
  validateOidcIssuerUrl,
  verifyPasswordArgon2id,
  verifyPkceCodeChallenge,
  verifyTotpWithReplayGuard,
  type CommercialUserRole
} from "@relayquill/auth";
import { encodeBase64Url } from "@relayquill/contracts";
import {
  AuthenticationDomainError,
  AuthorizationDomainError,
  ConflictDomainError,
  HUMAN_SESSION_ABSOLUTE_TTL_MS,
  HUMAN_SESSION_IDLE_TTL_MS,
  isLegalDocumentKind,
  NotFoundDomainError,
  PLAN_CATALOG,
  type PrincipalId,
  type TenantId,
  ValidationDomainError,
  addMilliseconds,
  formatUtcTimestamp,
  parseCanonicalUuid,
  parseTenantId,
  validateSignupSybilHygiene
} from "@relayquill/domain";
import { type PgTransactionClient, bindTenantRlsScope, withTenantRlsTransaction } from "@relayquill/postgres";
import { type FastifyInstance, type FastifyRequest } from "fastify";
import {
  type ApiContext,
  authenticateHumanMutation,
  authenticateHumanRead,
  extractCsrfHeader,
  formatPgTimestamp,
  getRawRequestHeaderMap,
  getRequestJsonBody,
  readInstallationSnapshot,
  requireIdempotencyKeyHeader
} from "../context.js";
import { sendSuccessEnvelope } from "../http/errors.js";
import { assertStrictRawHeaders, extractSingleRawHeader } from "../http/headers.js";
import { asText } from "../repos/sql-helpers.js";

export interface VerifiedBreakGlassRequestContext {
  readonly breakGlassId: string;
  readonly tenantId: TenantId;
  readonly operatorId: string;
  readonly expiresAt: string;
}

const breakGlassSessionByRequest = new WeakMap<object, VerifiedBreakGlassRequestContext>();

function setVerifiedBreakGlassSession(
  request: FastifyRequest,
  session: VerifiedBreakGlassRequestContext
): void {
  breakGlassSessionByRequest.set(request, session);
}

function getVerifiedBreakGlassSession(
  request: FastifyRequest
): VerifiedBreakGlassRequestContext | undefined {
  return breakGlassSessionByRequest.get(request);
}

/**
 * Enforces read-only TTL, revocation, and secret-path boundaries whenever `X-Relayquill-Break-Glass` is sent.
 */
export async function enforceBreakGlassRequestGuard(
  ctx: ApiContext,
  request: FastifyRequest
): Promise<void> {
  const headerMap = assertStrictRawHeaders(request.raw.rawHeaders);
  const rawToken = extractSingleRawHeader(headerMap, BREAK_GLASS_HEADER_NAME);
  if (rawToken === undefined || rawToken.length === 0) {
    return;
  }

  const tokenDigest = hashBreakGlassToken(rawToken);
  if (tokenDigest === null) {
    throw new AuthenticationDomainError({
      code: "UNAUTHENTICATED",
      message: "Malformed support break-glass token"
    });
  }

  const row = await ctx.pgAdapter.withTransaction(
    ctx.pgAdapter.configuredRole,
    async (tx) => {
      const res = await tx.query<{
        id: string;
        tenant_id: string;
        operator_id: string;
        read_only: boolean;
        expires_at: unknown;
        revoked_at: unknown;
      }>(
        `SELECT id, tenant_id, operator_id, read_only, expires_at, revoked_at
           FROM rq.support_break_glass_sessions
          WHERE token_sha256 = $1::bytea`,
        [tokenDigest]
      );
      return res.rows[0];
    },
    { readOnly: true }
  );

  if (row === undefined) {
    throw new AuthenticationDomainError({
      code: "UNAUTHENTICATED",
      message: "Unknown support break-glass session"
    });
  }

  const expiresAtIso = formatPgTimestamp(row.expires_at);
  const expiresAt = new Date(expiresAtIso);
  const revokedAt =
    row.revoked_at !== null && row.revoked_at !== undefined
      ? new Date(formatPgTimestamp(row.revoked_at))
      : null;
  const nowDate = new Date(Number(ctx.clock.nowInstant().epochMilliseconds));
  const routeUrl = request.url.split("?")[0] ?? request.url;

  const decision = validateBreakGlassReadScope(
    {
      expiresAt,
      revokedAt,
      readOnly: Boolean(row.read_only),
      operatorId: String(row.operator_id),
      tenantId: String(row.tenant_id)
    },
    request.method,
    routeUrl,
    nowDate
  );

  if (!decision.allowed) {
    if (decision.status === 401) {
      throw new AuthenticationDomainError({
        code: "UNAUTHENTICATED",
        message: `Support break-glass denied: ${decision.code ?? "BREAK_GLASS_EXPIRED_OR_REVOKED"}`
      });
    }
    throw new AuthorizationDomainError({
      code: "FORBIDDEN",
      message: `Support break-glass denied: ${decision.code ?? "BREAK_GLASS_FORBIDDEN_RESOURCE"}`
    });
  }

  setVerifiedBreakGlassSession(request, {
    breakGlassId: String(row.id),
    tenantId: parseTenantId(row.tenant_id, "break_glass.tenant_id"),
    operatorId: String(row.operator_id),
    expiresAt: expiresAtIso
  });
}

function buildTenantSlug(orgName: string): string {
  const cleaned = orgName
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
  const prefixed = /^[a-z]/.test(cleaned) ? cleaned : `org-${cleaned || "workspace"}`;
  const suffix = crypto.randomBytes(3).toString("hex");
  return `${prefixed.slice(0, 52)}-${suffix}`;
}

async function mintCommercialHumanSession(
  ctx: ApiContext,
  tx: PgTransactionClient,
  principalId: PrincipalId | string
): Promise<{
  readonly sessionId: string;
  readonly csrfToken: string;
  readonly setCookieHeader: string;
}> {
  const inst = await readInstallationSnapshot(ctx, tx);
  if (inst.mode === "recovery_quarantine" || inst.mode === "retired") {
    throw new AuthenticationDomainError({
      code: "UNAUTHENTICATED",
      message: `Installation mode "${inst.mode}" denies human sign-in`
    });
  }

  const principalRes = await tx.query<{ authority_epoch: unknown; state: unknown }>(
    `SELECT authority_epoch, state FROM rq.principals WHERE id = $1::uuid`,
    [principalId]
  );
  const principal = principalRes.rows[0];
  if (principal === undefined || principal.state !== "active") {
    throw new AuthenticationDomainError({
      code: "UNAUTHENTICATED",
      message: "Account principal is not active"
    });
  }

  const authorityEpoch = BigInt(String(principal.authority_epoch));
  const now = ctx.clock.nowInstant();
  const createdAt = formatUtcTimestamp(now);
  const idleExpiresAt = formatUtcTimestamp(addMilliseconds(now, HUMAN_SESSION_IDLE_TTL_MS));
  const absoluteExpiresAt = formatUtcTimestamp(addMilliseconds(now, HUMAN_SESSION_ABSOLUTE_TTL_MS));
  const sessionId = ctx.ids.nextUuid();

  const generated = generateRandomBase64UrlToken(SESSION_TOKEN_BYTE_LENGTH);
  const rawBytes = generated.bytes;
  let csrfBytes: Uint8Array | undefined;

  try {
    const tokenDigest = Buffer.from(computeSessionTokenDigest(rawBytes));
    csrfBytes = deriveCsrfTokenBytes(rawBytes);
    const csrfDigest = Buffer.from(computeCsrfDigest(csrfBytes));
    const csrfToken = encodeBase64Url(csrfBytes);
    const cookieValue = generated.token.expose();

    await tx.query(
      `INSERT INTO rq.human_sessions (
         id, principal_id, control_epoch, token_digest, csrf_digest,
         principal_authority_epoch, purpose, state,
         created_at, last_seen_at, idle_expires_at, absolute_expires_at, version
       ) VALUES (
         $1::uuid, $2::uuid, $3::uuid, $4::bytea, $5::bytea,
         $6::bigint, 'ordinary', 'active',
         $7::timestamptz, $7::timestamptz, $8::timestamptz, $9::timestamptz, 1
       )`,
      [
        sessionId,
        principalId,
        inst.controlEpoch,
        tokenDigest,
        csrfDigest,
        authorityEpoch.toString(10),
        createdAt,
        idleExpiresAt,
        absoluteExpiresAt
      ]
    );

    const setCookieHeader = formatSetCookieHeader({
      name: resolveSessionCookieName(ctx.authPolicy.cookieProfile),
      value: cookieValue,
      maxAgeSeconds: Number(HUMAN_SESSION_ABSOLUTE_TTL_MS / 1000n),
      cookieProfile: ctx.authPolicy.cookieProfile
    });

    return { sessionId, csrfToken, setCookieHeader };
  } finally {
    rawBytes.fill(0);
    if (csrfBytes !== undefined) {
      csrfBytes.fill(0);
    }
  }
}

export async function resolveActorCommercialTenantId(
  tx: PgTransactionClient,
  principalId: PrincipalId,
  requestedTenantId?: unknown
): Promise<{ readonly tenantId: TenantId; readonly userId: string | null; readonly userRole: string | null }> {
  if (typeof requestedTenantId === "string" && requestedTenantId.trim().length > 0) {
    const parsedTenantId = parseTenantId(requestedTenantId.trim(), "tenant_id");
    const userRes = await tx.query<{ id: unknown; role: unknown }>(
      `SELECT id, role FROM rq.users WHERE principal_id = $1::uuid AND tenant_id = $2::uuid`,
      [principalId, parsedTenantId]
    );
    if (userRes.rows[0] !== undefined) {
      return {
        tenantId: parsedTenantId,
        userId: String(userRes.rows[0].id),
        userRole: String(userRes.rows[0].role)
      };
    }
    const memberRes = await tx.query<{ role: unknown }>(
      `SELECT role FROM rq.tenant_memberships
        WHERE principal_id = $1::uuid AND tenant_id = $2::uuid AND state = 'active'
        LIMIT 1`,
      [principalId, parsedTenantId]
    );
    if (memberRes.rows[0] !== undefined) {
      return {
        tenantId: parsedTenantId,
        userId: null,
        userRole: String(memberRes.rows[0].role)
      };
    }
    const platRes = await tx.query<{ role: unknown }>(
      `SELECT role FROM rq.platform_role_assignments
        WHERE principal_id = $1::uuid AND state = 'active'
        LIMIT 1`,
      [principalId]
    );
    if (platRes.rows[0] !== undefined) {
      return {
        tenantId: parsedTenantId,
        userId: null,
        userRole: String(platRes.rows[0].role)
      };
    }
    throw new AuthorizationDomainError({
      code: "FORBIDDEN",
      message: "Principal lacks active membership in target tenant"
    });
  }

  const ownUser = await tx.query<{ id: unknown; tenant_id: unknown; role: unknown }>(
    `SELECT id, tenant_id, role FROM rq.users WHERE principal_id = $1::uuid LIMIT 1`,
    [principalId]
  );
  if (ownUser.rows[0] !== undefined) {
    return {
      tenantId: parseTenantId(ownUser.rows[0].tenant_id, "tenant_id"),
      userId: String(ownUser.rows[0].id),
      userRole: String(ownUser.rows[0].role)
    };
  }
  const ownMember = await tx.query<{ tenant_id: unknown; role: unknown }>(
    `SELECT tenant_id, role FROM rq.tenant_memberships
      WHERE principal_id = $1::uuid AND state = 'active'
      ORDER BY created_at ASC LIMIT 1`,
    [principalId]
  );
  if (ownMember.rows[0] !== undefined) {
    return {
      tenantId: parseTenantId(ownMember.rows[0].tenant_id, "tenant_id"),
      userId: null,
      userRole: String(ownMember.rows[0].role)
    };
  }
  throw new NotFoundDomainError({
    code: "NOT_FOUND",
    message: "No commercial tenant association found for principal"
  });
}

function toBuffer(value: unknown): Buffer {
  if (Buffer.isBuffer(value)) {
    return value;
  }
  if (value instanceof Uint8Array) {
    return Buffer.from(value);
  }
  if (typeof value === "string") {
    const clean = value.startsWith("\\x") ? value.slice(2) : value;
    return Buffer.from(clean, "hex");
  }
  throw new ValidationDomainError({
    code: "INVALID_VALUE",
    message: "Expected binary bytea column value"
  });
}

/**
 * Registers commercial auth (Argon2id, TOTP, OIDC, clickwrap legal), 15m break-glass,
 * public `/status`, and self-serve GDPR erasure routes.
 */
export function registerCommercialAuthAndOpsRoutes(app: FastifyInstance, ctx: ApiContext): void {
  // Public unauthenticated component SLA telemetry (zero tenant leakage)
  for (const statusPath of ["/status", "/api/v1/status"] as const) {
    app.get(statusPath, async (request, reply) => {
      const now = ctx.clock.nowInstant();
      const nowIso = formatUtcTimestamp(now);
      const telemetry = await ctx.pgAdapter.withTransaction(
        ctx.pgAdapter.configuredRole,
        async (tx) => {
          const inst = await readInstallationSnapshot(ctx, tx);
          const outboxRes = await tx.query<{ cnt: unknown }>(
            `SELECT count(*)::bigint AS cnt FROM rq.outbox_events WHERE state IN ('pending', 'publish_unknown')`
          );
          const ackRes = await tx.query<{ total: unknown; acked: unknown }>(
            `SELECT count(*)::bigint AS total,
                    count(*) FILTER (WHERE outcome_class = 'acknowledged')::bigint AS acked
               FROM rq.delivery_attempts
              WHERE prepared_at >= ($1::timestamptz - interval '24 hours')`,
            [nowIso]
          );
          const pendingOutbox = Number(outboxRes.rows[0]?.cnt ?? 0);
          const totalAttempts = Number(ackRes.rows[0]?.total ?? 0);
          const ackedAttempts = Number(ackRes.rows[0]?.acked ?? 0);
          const successRate24h =
            totalAttempts > 0 ? Number((ackedAttempts / totalAttempts).toFixed(4)) : 1;
          return { inst, pendingOutbox, successRate24h };
        },
        { readOnly: true }
      );

      const overallStatus =
        telemetry.inst.mode === "open" || telemetry.inst.mode === "initializing"
          ? "operational"
          : telemetry.inst.mode === "admission_hold"
            ? "degraded"
            : "maintenance";

      return sendSuccessEnvelope(
        reply,
        200,
        {
          service: "relayquill",
          overall_status: overallStatus,
          checked_at: nowIso,
          components: [
            {
              name: "admission_api",
              status: telemetry.inst.allowEventAdmission ? "operational" : "degraded"
            },
            { name: "postgres_18_rq", status: "operational" },
            { name: "outbox_relay", status: "operational", pending_events: telemetry.pendingOutbox },
            { name: "sender_egress_fleet", status: "operational", success_rate_24h: telemetry.successRate24h }
          ]
        },
        { requestId: request.id, observedAt: nowIso }
      );
    });
  }

  // Commercial self-serve signup (Argon2id + Sybil hygiene + clickwrap ToS/DPA + email_outbox)
  app.post("/api/v1/auth/signup", async (request, reply) => {
    const headerMap = getRawRequestHeaderMap(request);
    if (extractSingleRawHeader(headerMap, "idempotency-key") !== undefined) {
      requireIdempotencyKeyHeader(headerMap);
    }
    const body = getRequestJsonBody(request);
    const rawEmail = asText(body["email"]).trim().toLowerCase();
    const sybil = validateSignupSybilHygiene(rawEmail);
    if (!sybil.allowed) {
      throw new ValidationDomainError({
        code: "INVALID_VALUE",
        message: sybil.reason ?? "INVALID_EMAIL_FORMAT",
        fieldErrors: [{ path: "email", code: "INVALID_VALUE" }]
      });
    }

    const password = asText(body["password"]);
    const orgName = asText(body["org_name"]).trim();
    if (orgName.length === 0 || orgName.length > 128) {
      throw new ValidationDomainError({
        code: "INVALID_VALUE",
        message: "org_name must be between 1 and 128 characters",
        fieldErrors: [{ path: "org_name", code: "INVALID_VALUE" }]
      });
    }
    if (body["accept_legal"] !== true) {
      throw new ValidationDomainError({
        code: "INVALID_VALUE",
        message: "Clickwrap legal consent (accept_legal: true) is required",
        fieldErrors: [{ path: "accept_legal", code: "INVALID_VALUE" }]
      });
    }
    const tosVersion = asText(body["tos_version"], "2026-11-01").trim();
    const dpaVersion = asText(body["dpa_version"], "2026-11-01").trim();
    if (tosVersion.length === 0 || tosVersion.length > 64 || dpaVersion.length === 0 || dpaVersion.length > 64) {
      throw new ValidationDomainError({
        code: "INVALID_VALUE",
        message: "tos_version and dpa_version must be 1..64 characters"
      });
    }

    const passwordHash = await hashPasswordArgon2id(password);
    const now = ctx.clock.nowInstant();
    const nowIso = formatUtcTimestamp(now);
    const periodEndIso = formatUtcTimestamp(
      addMilliseconds(now, BigInt(30 * 24 * 60 * 60 * 1000))
    );
    const ipSha256 = crypto.createHash("sha256").update(request.ip || "127.0.0.1", "utf8").digest();

    const created = await ctx.pgAdapter.withTransaction(ctx.pgAdapter.configuredRole, async (tx) => {
      const dup = await tx.query<{ id: unknown }>(
        `SELECT id FROM rq.users WHERE email = $1::text`,
        [rawEmail]
      );
      if (dup.rows[0] !== undefined) {
        throw new ConflictDomainError({
          code: "VERSION_CONFLICT",
          message: "An account with this email already exists"
        });
      }

      const principalId = ctx.ids.nextUuid();
      const tenantId = ctx.ids.nextUuid();
      const userId = ctx.ids.nextUuid();
      const slug = buildTenantSlug(orgName);
      const stripeCustomerPlaceholder = `cus_local_${tenantId.replace(/-/g, "").slice(0, 16)}`;
      const subscriptionId = ctx.ids.nextUuid();
      const freePlan = PLAN_CATALOG.free;

      await tx.query(
        `INSERT INTO rq.principals (id, kind, state, authority_epoch, created_at, updated_at, version)
         VALUES ($1::uuid, 'human', 'active', 1, $2::timestamptz, $2::timestamptz, 1)`,
        [principalId, nowIso]
      );
      await tx.query(
        `INSERT INTO rq.humans (principal_id, principal_kind, display_name, webauthn_user_id, created_at, updated_at, version)
         VALUES ($1::uuid, 'human', $2::text, $3::bytea, $4::timestamptz, $4::timestamptz, 1)`,
        [principalId, orgName, crypto.randomBytes(32), nowIso]
      );
      await tx.query(
        `INSERT INTO rq.tenants (
           id, slug, display_name, state, governance_version,
           tos_version, tos_accepted_at, dpa_version, dpa_accepted_at,
           created_at, updated_at, version
         ) VALUES (
           $1::uuid, $2::text, $3::text, 'active', 1,
           $4::text, $5::timestamptz, $6::text, $5::timestamptz,
           $5::timestamptz, $5::timestamptz, 1
         )`,
        [tenantId, slug, orgName, tosVersion, nowIso, dpaVersion]
      );
      await tx.query(
        `INSERT INTO rq.tenant_memberships (
           id, tenant_id, principal_id, role, state, authority_version, created_at, updated_at, version
         ) VALUES ($1::uuid, $2::uuid, $3::uuid, 'tenant_admin', 'active', 1, $4::timestamptz, $4::timestamptz, 1)`,
        [ctx.ids.nextUuid(), tenantId, principalId, nowIso]
      );
      await bindTenantRlsScope(tx, tenantId);
      await tx.query(
        `INSERT INTO rq.users (
           id, principal_id, tenant_id, email, password_hash, role, mfa_enrolled, created_at, version
         ) VALUES ($1::uuid, $2::uuid, $3::uuid, $4::text, $5::text, 'owner', false, $6::timestamptz, 1)`,
        [userId, principalId, tenantId, rawEmail, passwordHash, nowIso]
      );
      await tx.query(
        `INSERT INTO rq.legal_acceptances (id, tenant_id, user_id, document_kind, doc_version, ip_sha256, accepted_at)
         VALUES ($1::uuid, $2::uuid, $3::uuid, 'tos', $4::text, $5::bytea, $6::timestamptz),
                ($7::uuid, $2::uuid, $3::uuid, 'dpa', $8::text, $5::bytea, $6::timestamptz)`,
        [ctx.ids.nextUuid(), tenantId, userId, tosVersion, ipSha256, nowIso, ctx.ids.nextUuid(), dpaVersion]
      );
      await tx.query(
        `INSERT INTO rq.billing_customers (org_id, stripe_customer_id, billing_email, created_at, updated_at)
         VALUES ($1::uuid, $2::text, $3::text, $4::timestamptz, $4::timestamptz)`,
        [tenantId, stripeCustomerPlaceholder, rawEmail, nowIso]
      );
      await tx.query(
        `INSERT INTO rq.billing_subscriptions (
           subscription_id, org_id, stripe_subscription_id, plan_tier, entitlement_state,
           billing_interval, currency, unit_amount_minor, seat_count,
           current_period_start, current_period_end, updated_at
         ) VALUES (
           $1::uuid, $2::uuid, NULL, 'free', 'FREE',
           'month', 'USD', 0, 1,
           $3::timestamptz, $4::timestamptz, $3::timestamptz
         )`,
        [subscriptionId, tenantId, nowIso, periodEndIso]
      );
      await tx.query(
        `INSERT INTO rq.entitlement_quotas (
           org_id, max_seats, max_concurrency, included_units_month, overage_unit_minor,
           cap_mode, soft_cap_minor, retention_days, sso_enabled, updated_at
         ) VALUES (
           $1::uuid, $2::integer, $3::integer, $4::bigint, 0,
           $5::text, NULL, $6::integer, $7::boolean, $8::timestamptz
         )`,
        [
          tenantId,
          freePlan.maxSeats,
          freePlan.maxConcurrency,
          String(freePlan.includedUnitsMonth),
          freePlan.capMode,
          freePlan.retentionDays,
          freePlan.ssoEnabled,
          nowIso
        ]
      );
      await tx.query(
        `INSERT INTO rq.email_outbox (
           id, tenant_id, idempotency_key, template_code, recipient_email, template_vars, state, created_at
         ) VALUES (
           $1::uuid, $2::uuid, $3::text, 'verify_email', $4::text, $5::jsonb, 'pending', $6::timestamptz
         )`,
        [
          ctx.ids.nextUuid(),
          tenantId,
          `verify-email:${userId}`,
          rawEmail,
          JSON.stringify({ verify_url: "https://console.relayquill.example/verify-email" }),
          nowIso
        ]
      );
      await tx.query(
        `INSERT INTO rq.audit_events (
           id, tenant_id, project_id, actor_kind, actor_reference, action,
           target_kind, target_id, recorded_at, safe_facts
         ) VALUES (
           $1::uuid, $2::uuid, NULL, 'human', $3::uuid, 'auth.signup',
           'tenant', $2::uuid, $4::timestamptz, $5::jsonb
         )`,
        [
          ctx.ids.nextUuid(),
          tenantId,
          principalId,
          nowIso,
          JSON.stringify({ tos_version: tosVersion, dpa_version: dpaVersion })
        ]
      );

      const session = await mintCommercialHumanSession(ctx, tx, principalId);
      return { userId, principalId, tenantId, slug, session };
    });

    void reply.header("Set-Cookie", created.session.setCookieHeader);
    void reply.header("Cache-Control", "no-store");

    return sendSuccessEnvelope(
      reply,
      201,
      {
        user_id: created.userId,
        principal_id: created.principalId,
        tenant_id: created.tenantId,
        tenant_slug: created.slug,
        role: "owner",
        plan_tier: "free",
        mfa_enrolled: false,
        tos_version: tosVersion,
        dpa_version: dpaVersion,
        csrf_token: created.session.csrfToken
      },
      { requestId: request.id, observedAt: nowIso }
    );
  });

  // Password login (+ mandatory TOTP challenge verification when mfa_enrolled = true)
  app.post("/api/v1/auth/login", async (request, reply) => {
    const headerMap = getRawRequestHeaderMap(request);
    if (extractSingleRawHeader(headerMap, "idempotency-key") !== undefined) {
      requireIdempotencyKeyHeader(headerMap);
    }
    const body = getRequestJsonBody(request);
    const email = asText(body["email"]).trim().toLowerCase();
    const password = asText(body["password"]);
    if (email.length === 0 || password.length === 0) {
      throw new AuthenticationDomainError({
        code: "UNAUTHENTICATED",
        message: "Email and password are required"
      });
    }

    const userRow = await ctx.pgAdapter.withTransaction(
      ctx.pgAdapter.configuredRole,
      async (tx) => {
        const res = await tx.query<{
          id: string;
          principal_id: string;
          tenant_id: string;
          password_hash: string;
          role: string;
          mfa_enrolled: boolean;
          totp_secret_enc: unknown;
        }>(
          `SELECT id, principal_id, tenant_id, password_hash, role, mfa_enrolled, totp_secret_enc
             FROM rq.users
            WHERE email = $1::text
            LIMIT 1`,
          [email]
        );
        return res.rows[0];
      },
      { readOnly: true }
    );

    if (userRow === undefined) {
      throw new AuthenticationDomainError({
        code: "UNAUTHENTICATED",
        message: "Invalid email or password"
      });
    }

    const passwordValid = await verifyPasswordArgon2id(password, String(userRow.password_hash));
    if (!passwordValid) {
      throw new AuthenticationDomainError({
        code: "UNAUTHENTICATED",
        message: "Invalid email or password"
      });
    }

    const now = ctx.clock.nowInstant();
    const nowIso = formatUtcTimestamp(now);

    if (Boolean(userRow.mfa_enrolled)) {
      const submittedCode = asText(body["totp_code"]).trim();
      if (submittedCode.length === 0 || userRow.totp_secret_enc === null || userRow.totp_secret_enc === undefined) {
        throw new AuthenticationDomainError({
          code: "UNAUTHENTICATED",
          message: "TOTP MFA verification code is required"
        });
      }
      const secretBytes = openTotpSecret(
        ctx.totpEncryptionKey,
        toBuffer(userRow.totp_secret_enc),
        String(userRow.id)
      );
      const totpResult = await verifyTotpWithReplayGuard({
        store: ctx.totpReplayStore,
        userId: String(userRow.id),
        secretBytes,
        submittedCode,
        nowUnixSec: Math.floor(Number(now.epochMilliseconds) / 1000)
      });
      if (!totpResult.valid) {
        throw new AuthenticationDomainError({
          code: "UNAUTHENTICATED",
          message: "Invalid or replayed TOTP verification code"
        });
      }
    }

    const tenantId = parseTenantId(userRow.tenant_id, "tenant_id");
    const session = await withTenantRlsTransaction(
      ctx.pgAdapter,
      ctx.pgAdapter.configuredRole,
      tenantId,
      async (tx) => {
        await tx.query(
          `UPDATE rq.users SET last_login_at = $2::timestamptz, version = version + 1 WHERE id = $1::uuid`,
          [userRow.id, nowIso]
        );
        await tx.query(
          `INSERT INTO rq.audit_events (
             id, tenant_id, project_id, actor_kind, actor_reference, action,
             target_kind, target_id, recorded_at, safe_facts
           ) VALUES ($1::uuid, $2::uuid, NULL, 'human', $3::uuid, 'auth.login', 'user', $4::uuid, $5::timestamptz, $6::jsonb)`,
          [
            ctx.ids.nextUuid(),
            tenantId,
            userRow.principal_id,
            userRow.id,
            nowIso,
            JSON.stringify({ mfa_enrolled: Boolean(userRow.mfa_enrolled) })
          ]
        );
        return mintCommercialHumanSession(ctx, tx, String(userRow.principal_id));
      }
    );

    void reply.header("Set-Cookie", session.setCookieHeader);
    void reply.header("Cache-Control", "no-store");

    return sendSuccessEnvelope(
      reply,
      200,
      {
        user_id: String(userRow.id),
        principal_id: String(userRow.principal_id),
        tenant_id: tenantId,
        role: String(userRow.role),
        mfa_enrolled: Boolean(userRow.mfa_enrolled),
        csrf_token: session.csrfToken
      },
      { requestId: request.id, observedAt: nowIso }
    );
  });

  // Alias commercial logout to canonical session revocation
  app.post("/api/v1/auth/logout", async (request, reply) => {
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

  // Never-Paywall: TOTP MFA enrollment
  app.post("/api/v1/auth/mfa/totp/enroll", async (request, reply) => {
    const inst = await ctx.pgAdapter.withTransaction(
      ctx.pgAdapter.configuredRole,
      (tx) => readInstallationSnapshot(ctx, tx),
      { readOnly: true }
    );
    const { auth } = await authenticateHumanMutation(ctx, request, inst);
    try {
      const now = ctx.clock.nowInstant();
      const nowIso = formatUtcTimestamp(now);
      const userRow = await ctx.pgAdapter.withTransaction(
        ctx.pgAdapter.configuredRole,
        async (tx) => {
          const res = await tx.query<{ id: string; tenant_id: string; email: string }>(
            `SELECT id, tenant_id, email FROM rq.users WHERE principal_id = $1::uuid LIMIT 1`,
            [auth.principal.principalId]
          );
          return res.rows[0];
        },
        { readOnly: true }
      );
      if (userRow === undefined) {
        throw new NotFoundDomainError({
          code: "NOT_FOUND",
          message: "Commercial user profile not found for principal"
        });
      }
      const tenantId = parseTenantId(userRow.tenant_id, "tenant_id");
      const generated = generateTotpSecret();
      const sealed = sealTotpSecret(ctx.totpEncryptionKey, generated.secretBytes, String(userRow.id));
      await withTenantRlsTransaction(ctx.pgAdapter, ctx.pgAdapter.configuredRole, tenantId, async (tx) => {
        await tx.query(
          `UPDATE rq.users
              SET totp_secret_enc = $2::bytea,
                  mfa_enrolled = false,
                  version = version + 1
            WHERE id = $1::uuid`,
          [userRow.id, sealed]
        );
      });
      const otpauthUri = buildTotpOtpauthUri({
        issuer: ctx.authPolicy.rpName,
        accountEmail: String(userRow.email),
        base32Secret: generated.base32Secret
      });
      const enrolled = { otpauthUri, base32Secret: generated.base32Secret };

      return sendSuccessEnvelope(
        reply,
        200,
        {
          otpauth_uri: enrolled.otpauthUri,
          secret_base32: enrolled.base32Secret,
          enrolled: false
        },
        { requestId: request.id, observedAt: nowIso }
      );
    } finally {
      auth.destroySecrets();
    }
  });

  // Never-Paywall: TOTP MFA verification & activation
  app.post("/api/v1/auth/mfa/totp/verify", async (request, reply) => {
    const inst = await ctx.pgAdapter.withTransaction(
      ctx.pgAdapter.configuredRole,
      (tx) => readInstallationSnapshot(ctx, tx),
      { readOnly: true }
    );
    const { auth, body } = await authenticateHumanMutation(ctx, request, inst);
    try {
      const code = asText(body["totp_code"]).trim();
      const now = ctx.clock.nowInstant();
      const nowIso = formatUtcTimestamp(now);

      const userRow = await ctx.pgAdapter.withTransaction(
        ctx.pgAdapter.configuredRole,
        async (tx) => {
          const res = await tx.query<{ id: string; tenant_id: string; totp_secret_enc: unknown }>(
            `SELECT id, tenant_id, totp_secret_enc FROM rq.users WHERE principal_id = $1::uuid LIMIT 1`,
            [auth.principal.principalId]
          );
          return res.rows[0];
        },
        { readOnly: true }
      );
      if (userRow === undefined || userRow.totp_secret_enc === null || userRow.totp_secret_enc === undefined) {
        throw new NotFoundDomainError({
          code: "NOT_FOUND",
          message: "TOTP enrollment has not been initiated"
        });
      }

      const secretBytes = openTotpSecret(
        ctx.totpEncryptionKey,
        toBuffer(userRow.totp_secret_enc),
        String(userRow.id)
      );
      const verifyResult = await verifyTotpWithReplayGuard({
        store: ctx.totpReplayStore,
        userId: String(userRow.id),
        secretBytes,
        submittedCode: code,
        nowUnixSec: Math.floor(Number(now.epochMilliseconds) / 1000)
      });
      if (!verifyResult.valid) {
        throw new AuthenticationDomainError({
          code: "UNAUTHENTICATED",
          message: "Invalid or replayed TOTP verification code"
        });
      }

      const tenantId = parseTenantId(userRow.tenant_id, "tenant_id");
      await withTenantRlsTransaction(ctx.pgAdapter, ctx.pgAdapter.configuredRole, tenantId, async (tx) => {
        await tx.query(
          `UPDATE rq.users SET mfa_enrolled = true, version = version + 1 WHERE id = $1::uuid`,
          [userRow.id]
        );
        await tx.query(
          `INSERT INTO rq.audit_events (
             id, tenant_id, project_id, actor_kind, actor_reference, action,
             target_kind, target_id, recorded_at, safe_facts
           ) VALUES ($1::uuid, $2::uuid, NULL, 'human', $3::uuid, 'auth.mfa.totp_enrolled', 'user', $4::uuid, $5::timestamptz, $6::jsonb)`,
          [ctx.ids.nextUuid(), tenantId, auth.principal.principalId, userRow.id, nowIso, "{}"]
        );
      });

      return sendSuccessEnvelope(
        reply,
        200,
        { enrolled: true },
        { requestId: request.id, observedAt: nowIso }
      );
    } finally {
      auth.destroySecrets();
    }
  });

  // Enterprise OIDC configuration (gated on entitlement sso_enabled = true; zero sso.tax for Team+)
  app.post("/api/v1/auth/oidc/configure", async (request, reply) => {
    const inst = await ctx.pgAdapter.withTransaction(
      ctx.pgAdapter.configuredRole,
      (tx) => readInstallationSnapshot(ctx, tx),
      { readOnly: true }
    );
    const { auth, body } = await authenticateHumanMutation(ctx, request, inst);
    try {
      const nowIso = formatUtcTimestamp(ctx.clock.nowInstant());
      const resolved = await ctx.pgAdapter.withTransaction(
        ctx.pgAdapter.configuredRole,
        (tx) => resolveActorCommercialTenantId(tx, auth.principal.principalId, body["tenant_id"]),
        { readOnly: true }
      );
      if (
        resolved.userRole !== "owner" &&
        resolved.userRole !== "admin" &&
        resolved.userRole !== "tenant_admin" &&
        resolved.userRole !== "platform_admin"
      ) {
        throw new AuthorizationDomainError({
          code: "FORBIDDEN",
          message: "OIDC configuration requires tenant owner or admin privileges"
        });
      }

      const issuerUrl = validateOidcIssuerUrl(asText(body["issuer_url"]), {
        allowLocalhost:
          ctx.profile !== "release" && ctx.authPolicy.cookieProfile !== "release_https"
      });
      const clientId = asText(body["client_id"]).trim();
      const clientSecretRef = asText(body["client_secret_ref"]).trim();
      if (clientId.length === 0 || clientSecretRef.length === 0) {
        throw new ValidationDomainError({
          code: "INVALID_VALUE",
          message: "client_id and client_secret_ref are required"
        });
      }

      const rawMapping = body["role_mapping"];
      if (rawMapping === null || typeof rawMapping !== "object" || Array.isArray(rawMapping)) {
        throw new ValidationDomainError({
          code: "INVALID_VALUE",
          message: "role_mapping must be an object mapping IdP groups to Relayquill roles"
        });
      }
      const roleMapping: Record<string, CommercialUserRole> = {};
      for (const [groupName, mappedRole] of Object.entries(rawMapping as Record<string, unknown>)) {
        if (!isCommercialUserRole(mappedRole)) {
          throw new ValidationDomainError({
            code: "INVALID_VALUE",
            message: `Unsupported OIDC role mapping "${String(mappedRole)}"`
          });
        }
        roleMapping[groupName] = mappedRole;
      }
      const enabled = body["enabled"] !== false;

      const connId = await withTenantRlsTransaction(
        ctx.pgAdapter,
        ctx.pgAdapter.configuredRole,
        resolved.tenantId,
        async (tx) => {
          const quotaRes = await tx.query<{ sso_enabled: boolean }>(
            `SELECT sso_enabled FROM rq.entitlement_quotas WHERE org_id = $1::uuid`,
            [resolved.tenantId]
          );
          if (quotaRes.rows[0]?.sso_enabled !== true) {
            throw new AuthorizationDomainError({
              code: "FORBIDDEN",
              message: "OIDC SSO requires a Team or Enterprise entitlement"
            });
          }

          const existing = await tx.query<{ id: string }>(
            `SELECT id FROM rq.oidc_connections WHERE tenant_id = $1::uuid`,
            [resolved.tenantId]
          );
          const id = existing.rows[0]?.id ?? ctx.ids.nextUuid();

          await tx.query(
            `INSERT INTO rq.oidc_connections (
               id, tenant_id, issuer_url, client_id, client_secret_ref, role_mapping, enabled, created_at, updated_at
             ) VALUES (
               $1::uuid, $2::uuid, $3::text, $4::text, $5::text, $6::jsonb, $7::boolean, $8::timestamptz, $8::timestamptz
             )
             ON CONFLICT (tenant_id) DO UPDATE SET
               issuer_url = EXCLUDED.issuer_url,
               client_id = EXCLUDED.client_id,
               client_secret_ref = EXCLUDED.client_secret_ref,
               role_mapping = EXCLUDED.role_mapping,
               enabled = EXCLUDED.enabled,
               updated_at = EXCLUDED.updated_at`,
            [
              id,
              resolved.tenantId,
              issuerUrl,
              clientId,
              clientSecretRef,
              JSON.stringify(roleMapping),
              enabled,
              nowIso
            ]
          );
          await tx.query(
            `INSERT INTO rq.audit_events (
               id, tenant_id, project_id, actor_kind, actor_reference, action,
               target_kind, target_id, recorded_at, safe_facts
             ) VALUES ($1::uuid, $2::uuid, NULL, 'human', $3::uuid, 'auth.oidc.configured', 'oidc_connection', $4::uuid, $5::timestamptz, $6::jsonb)`,
            [
              ctx.ids.nextUuid(),
              resolved.tenantId,
              auth.principal.principalId,
              id,
              nowIso,
              JSON.stringify({ issuer_url: issuerUrl, enabled })
            ]
          );
          return id;
        }
      );

      return sendSuccessEnvelope(
        reply,
        200,
        {
          oidc_connection_id: connId,
          tenant_id: resolved.tenantId,
          issuer_url: issuerUrl,
          enabled
        },
        { requestId: request.id, observedAt: nowIso }
      );
    } finally {
      auth.destroySecrets();
    }
  });

  // OIDC PKCE callback + RBAC claim mapper
  app.post("/api/v1/auth/oidc/callback", async (request, reply) => {
    const body = getRequestJsonBody(request);
    const tenantId = parseTenantId(body["tenant_id"], "tenant_id");
    const codeVerifier = asText(body["code_verifier"]);
    const expectedChallenge = asText(body["expected_challenge"]);
    if (!verifyPkceCodeChallenge(codeVerifier, expectedChallenge)) {
      throw new AuthenticationDomainError({
        code: "UNAUTHENTICATED",
        message: "OIDC PKCE S256 verification failed"
      });
    }

    const claims = body["claims"] as Record<string, unknown> | undefined;
    if (claims === null || typeof claims !== "object" || Array.isArray(claims)) {
      throw new ValidationDomainError({
        code: "INVALID_VALUE",
        message: "claims object is required"
      });
    }
    const subject = asText(claims["sub"]).trim();
    const email = asText(claims["email"]).trim().toLowerCase();
    const groups = Array.isArray(claims["groups"])
      ? claims["groups"].filter((g): g is string => typeof g === "string")
      : [];
    if (subject.length === 0 || !email.includes("@")) {
      throw new ValidationDomainError({
        code: "INVALID_VALUE",
        message: "OIDC claims require sub and email"
      });
    }

    const nowIso = formatUtcTimestamp(ctx.clock.nowInstant());
    const outcome = await withTenantRlsTransaction(
      ctx.pgAdapter,
      ctx.pgAdapter.configuredRole,
      tenantId,
      async (tx) => {
        const connRes = await tx.query<{
          id: string;
          role_mapping: Record<string, CommercialUserRole>;
          enabled: boolean;
        }>(
          `SELECT id, role_mapping, enabled FROM rq.oidc_connections WHERE tenant_id = $1::uuid`,
          [tenantId]
        );
        const conn = connRes.rows[0];
        if (conn === undefined || !Boolean(conn.enabled)) {
          throw new AuthorizationDomainError({
            code: "FORBIDDEN",
            message: "Enabled OIDC connection not found for tenant"
          });
        }
        const mappedRole = mapOidcClaimsToTenantRole(groups, conn.role_mapping ?? {});
        if (mappedRole === null) {
          throw new AuthorizationDomainError({
            code: "FORBIDDEN",
            message: "No OIDC group claim matches configured tenant role mapping"
          });
        }

        const existingUser = await tx.query<{ id: string; principal_id: string }>(
          `SELECT id, principal_id FROM rq.users WHERE tenant_id = $1::uuid AND email = $2::text LIMIT 1`,
          [tenantId, email]
        );

        let userId: string;
        let principalId: string;
        if (existingUser.rows[0] !== undefined) {
          userId = String(existingUser.rows[0].id);
          principalId = String(existingUser.rows[0].principal_id);
          await tx.query(
            `UPDATE rq.users
                SET role = $2::text,
                    oidc_subject = $3::text,
                    last_login_at = $4::timestamptz,
                    version = version + 1
              WHERE id = $1::uuid`,
            [userId, mappedRole, subject, nowIso]
          );
        } else {
          userId = ctx.ids.nextUuid();
          principalId = ctx.ids.nextUuid();
          await tx.query(
            `INSERT INTO rq.principals (id, kind, state, authority_epoch, created_at, updated_at, version)
             VALUES ($1::uuid, 'human', 'active', 1, $2::timestamptz, $2::timestamptz, 1)`,
            [principalId, nowIso]
          );
          await tx.query(
            `INSERT INTO rq.humans (principal_id, principal_kind, display_name, webauthn_user_id, created_at, updated_at, version)
             VALUES ($1::uuid, 'human', $2::text, $3::bytea, $4::timestamptz, $4::timestamptz, 1)`,
            [principalId, email.split("@")[0] ?? "SSO User", crypto.randomBytes(32), nowIso]
          );
          await tx.query(
            `INSERT INTO rq.users (
               id, principal_id, tenant_id, email, email_verified_at, password_hash,
               role, mfa_enrolled, oidc_subject, last_login_at, created_at, version
             ) VALUES (
               $1::uuid, $2::uuid, $3::uuid, $4::text, $5::timestamptz, '!OIDC_SSO_MANAGED!',
               $6::text, false, $7::text, $5::timestamptz, $5::timestamptz, 1
             )`,
            [userId, principalId, tenantId, email, nowIso, mappedRole, subject]
          );
        }

        await tx.query(
          `INSERT INTO rq.audit_events (
             id, tenant_id, project_id, actor_kind, actor_reference, action,
             target_kind, target_id, recorded_at, safe_facts
           ) VALUES ($1::uuid, $2::uuid, NULL, 'human', $3::uuid, 'auth.oidc.login', 'user', $4::uuid, $5::timestamptz, $6::jsonb)`,
          [
            ctx.ids.nextUuid(),
            tenantId,
            principalId,
            userId,
            nowIso,
            JSON.stringify({ mapped_role: mappedRole })
          ]
        );

        const session = await mintCommercialHumanSession(ctx, tx, principalId);
        return { userId, principalId, mappedRole, session };
      }
    );

    void reply.header("Set-Cookie", outcome.session.setCookieHeader);
    void reply.header("Cache-Control", "no-store");

    return sendSuccessEnvelope(
      reply,
      200,
      {
        user_id: outcome.userId,
        principal_id: outcome.principalId,
        tenant_id: tenantId,
        role: outcome.mappedRole,
        csrf_token: outcome.session.csrfToken
      },
      { requestId: request.id, observedAt: nowIso }
    );
  });

  // Clickwrap legal document acceptance update (ToS / Privacy / DPA)
  app.post("/api/v1/legal/accept", async (request, reply) => {
    const inst = await ctx.pgAdapter.withTransaction(
      ctx.pgAdapter.configuredRole,
      (tx) => readInstallationSnapshot(ctx, tx),
      { readOnly: true }
    );
    const { auth, body } = await authenticateHumanMutation(ctx, request, inst);
    try {
      const docKind = body["document_kind"];
      if (!isLegalDocumentKind(docKind)) {
        throw new ValidationDomainError({
          code: "INVALID_VALUE",
          message: "document_kind must be one of 'tos', 'privacy', 'dpa'",
          fieldErrors: [{ path: "document_kind", code: "INVALID_VALUE" }]
        });
      }
      const docVersion = asText(body["doc_version"]).trim();
      if (docVersion.length === 0 || docVersion.length > 64) {
        throw new ValidationDomainError({
          code: "INVALID_VALUE",
          message: "doc_version must be 1..64 characters"
        });
      }

      const resolved = await ctx.pgAdapter.withTransaction(
        ctx.pgAdapter.configuredRole,
        (tx) => resolveActorCommercialTenantId(tx, auth.principal.principalId, body["tenant_id"]),
        { readOnly: true }
      );
      const nowIso = formatUtcTimestamp(ctx.clock.nowInstant());
      const ipSha256 = crypto.createHash("sha256").update(request.ip || "127.0.0.1", "utf8").digest();
      const acceptanceId = ctx.ids.nextUuid();

      await withTenantRlsTransaction(ctx.pgAdapter, ctx.pgAdapter.configuredRole, resolved.tenantId, async (tx) => {
        await tx.query(
          `INSERT INTO rq.legal_acceptances (id, tenant_id, user_id, document_kind, doc_version, ip_sha256, accepted_at)
           VALUES ($1::uuid, $2::uuid, $3::uuid, $4::text, $5::text, $6::bytea, $7::timestamptz)`,
          [
            acceptanceId,
            resolved.tenantId,
            resolved.userId ?? auth.principal.principalId,
            docKind,
            docVersion,
            ipSha256,
            nowIso
          ]
        );
        if (docKind === "tos") {
          await tx.query(
            `UPDATE rq.tenants SET tos_version = $2::text, tos_accepted_at = $3::timestamptz, version = version + 1 WHERE id = $1::uuid`,
            [resolved.tenantId, docVersion, nowIso]
          );
        } else if (docKind === "dpa") {
          await tx.query(
            `UPDATE rq.tenants SET dpa_version = $2::text, dpa_accepted_at = $3::timestamptz, version = version + 1 WHERE id = $1::uuid`,
            [resolved.tenantId, docVersion, nowIso]
          );
        }
        await tx.query(
          `INSERT INTO rq.audit_events (
             id, tenant_id, project_id, actor_kind, actor_reference, action,
             target_kind, target_id, recorded_at, safe_facts
           ) VALUES ($1::uuid, $2::uuid, NULL, 'human', $3::uuid, 'legal.accepted', 'tenant', $2::uuid, $4::timestamptz, $5::jsonb)`,
          [
            ctx.ids.nextUuid(),
            resolved.tenantId,
            auth.principal.principalId,
            nowIso,
            JSON.stringify({ document_kind: docKind, doc_version: docVersion })
          ]
        );
      });

      return sendSuccessEnvelope(
        reply,
        200,
        {
          acceptance_id: acceptanceId,
          tenant_id: resolved.tenantId,
          document_kind: docKind,
          doc_version: docVersion,
          accepted_at: nowIso
        },
        { requestId: request.id, observedAt: nowIso }
      );
    } finally {
      auth.destroySecrets();
    }
  });

  // 15-minute dual-logged read-only support break-glass issuance
  app.post("/api/v1/ops/break-glass", async (request, reply) => {
    const inst = await ctx.pgAdapter.withTransaction(
      ctx.pgAdapter.configuredRole,
      (tx) => readInstallationSnapshot(ctx, tx),
      { readOnly: true }
    );
    const { auth, body } = await authenticateHumanMutation(ctx, request, inst);
    try {
      const isPlatformAdmin = await ctx.pgAdapter.withTransaction(
        ctx.pgAdapter.configuredRole,
        async (tx) => {
          const res = await tx.query<{ role: unknown }>(
            `SELECT role FROM rq.platform_role_assignments
              WHERE principal_id = $1::uuid AND role = 'platform_admin' AND state = 'active'`,
            [auth.principal.principalId]
          );
          return res.rows.length > 0;
        },
        { readOnly: true }
      );
      if (!isPlatformAdmin) {
        throw new AuthorizationDomainError({
          code: "FORBIDDEN",
          message: "Support break-glass issuance requires active platform_admin role"
        });
      }
      if (body["mfa_verified"] !== true) {
        throw new AuthorizationDomainError({
          code: "FORBIDDEN",
          message: "Operator MFA verification is required to initiate break-glass"
        });
      }

      const targetTenantId = parseTenantId(body["target_tenant_id"], "target_tenant_id");
      const reason = asText(body["reason"]).trim();
      const ttlMinutes = typeof body["ttl_minutes"] === "number" ? body["ttl_minutes"] : 15;
      const now = ctx.clock.nowInstant();
      const nowIso = formatUtcTimestamp(now);
      const nowDate = new Date(Number(now.epochMilliseconds));
      const window = buildBreakGlassWindow(reason, ttlMinutes, nowDate);
      const startedAtIso = window.startedAt.toISOString();
      const expiresAtIso = window.expiresAt.toISOString();
      const { token, tokenSha256 } = mintBreakGlassToken();
      const breakGlassId = ctx.ids.nextUuid();

      await withTenantRlsTransaction(
        ctx.pgAdapter,
        ctx.pgAdapter.configuredRole,
        targetTenantId,
        async (tx) => {
          await tx.query(
            `INSERT INTO rq.support_break_glass_sessions (
               id, tenant_id, operator_id, reason, mfa_verified_at, read_only, token_sha256, started_at, expires_at
             ) VALUES (
               $1::uuid, $2::uuid, $3::uuid, $4::text, $5::timestamptz, true, $6::bytea, $5::timestamptz, $7::timestamptz
             )`,
            [
              breakGlassId,
              targetTenantId,
              auth.principal.principalId,
              reason,
              startedAtIso,
              tokenSha256,
              expiresAtIso
            ]
          );

          await tx.query(
            `INSERT INTO rq.audit_events (
               id, tenant_id, project_id, actor_kind, operator_reference, action,
               target_kind, target_id, recorded_at, safe_facts
             ) VALUES (
               $1::uuid, $2::uuid, NULL, 'operator', $3::text, 'support.break_glass.started',
               'support_break_glass_session', $4::uuid, $5::timestamptz, $6::jsonb
             )`,
            [
              ctx.ids.nextUuid(),
              targetTenantId,
              auth.principal.principalId,
              breakGlassId,
              startedAtIso,
              JSON.stringify({
                break_glass_id: breakGlassId,
                reason,
                read_only: true,
                ttl_minutes: window.ttlMinutes
              })
            ]
          );

          const ownerRes = await tx.query<{ email: string }>(
            `SELECT email FROM rq.users WHERE tenant_id = $1::uuid AND role IN ('owner', 'admin') ORDER BY created_at ASC LIMIT 1`,
            [targetTenantId]
          );
          const ownerEmail = ownerRes.rows[0]?.email;
          if (ownerEmail !== undefined) {
            await tx.query(
              `INSERT INTO rq.email_outbox (
                 id, tenant_id, idempotency_key, template_code, recipient_email, template_vars, state, created_at
               ) VALUES (
                 $1::uuid, $2::uuid, $3::text, 'break_glass_notice', $4::text, $5::jsonb, 'pending', $6::timestamptz
               )`,
              [
                ctx.ids.nextUuid(),
                targetTenantId,
                `break-glass:${breakGlassId}`,
                ownerEmail,
                JSON.stringify({
                  operator_id: auth.principal.principalId,
                  reason,
                  expires_at: expiresAtIso
                }),
                startedAtIso
              ]
            );
          }
        }
      );

      return sendSuccessEnvelope(
        reply,
        201,
        {
          break_glass_id: breakGlassId,
          target_tenant_id: targetTenantId,
          read_only: true,
          token_once: token,
          started_at: startedAtIso,
          expires_at: expiresAtIso,
          customer_audit_logged: true
        },
        { requestId: request.id, observedAt: nowIso }
      );
    } finally {
      auth.destroySecrets();
    }
  });

  app.post<{ Params: { break_glass_id: string } }>(
    "/api/v1/ops/break-glass/:break_glass_id/revoke",
    async (request, reply) => {
      const breakGlassId = parseCanonicalUuid(request.params.break_glass_id, "break_glass_id");
      const inst = await ctx.pgAdapter.withTransaction(
        ctx.pgAdapter.configuredRole,
        (tx) => readInstallationSnapshot(ctx, tx),
        { readOnly: true }
      );
      const { auth } = await authenticateHumanMutation(ctx, request, inst);
      try {
        const isPlatformAdmin = await ctx.pgAdapter.withTransaction(
          ctx.pgAdapter.configuredRole,
          async (tx) => {
            const res = await tx.query<{ role: unknown }>(
              `SELECT role FROM rq.platform_role_assignments
                WHERE principal_id = $1::uuid AND role = 'platform_admin' AND state = 'active'`,
              [auth.principal.principalId]
            );
            return res.rows.length > 0;
          },
          { readOnly: true }
        );
        if (!isPlatformAdmin) {
          throw new AuthorizationDomainError({
            code: "FORBIDDEN",
            message: "Support break-glass revocation requires platform_admin role"
          });
        }

        const nowIso = formatUtcTimestamp(ctx.clock.nowInstant());
        const tenantId = await ctx.pgAdapter.withTransaction(ctx.pgAdapter.configuredRole, async (tx) => {
          const upd = await tx.query<{ tenant_id: string }>(
            `UPDATE rq.support_break_glass_sessions
                SET revoked_at = COALESCE(revoked_at, $2::timestamptz)
              WHERE id = $1::uuid
              RETURNING tenant_id`,
            [breakGlassId, nowIso]
          );
          const tid = upd.rows[0]?.tenant_id;
          if (tid === undefined) {
            throw new NotFoundDomainError({
              code: "NOT_FOUND",
              message: "Support break-glass session not found"
            });
          }
          await tx.query(
            `INSERT INTO rq.audit_events (
               id, tenant_id, project_id, actor_kind, operator_reference, action,
               target_kind, target_id, recorded_at, safe_facts
             ) VALUES ($1::uuid, $2::uuid, NULL, 'operator', $3::text, 'support.break_glass.revoked', 'support_break_glass_session', $4::uuid, $5::timestamptz, '{}'::jsonb)`,
            [ctx.ids.nextUuid(), tid, auth.principal.principalId, breakGlassId, nowIso]
          );
          return tid;
        });

        return sendSuccessEnvelope(
          reply,
          200,
          { break_glass_id: breakGlassId, target_tenant_id: tenantId, revoked_at: nowIso },
          { requestId: request.id, observedAt: nowIso }
        );
      } finally {
        auth.destroySecrets();
      }
    }
  );

  // Customer audit visibility screen (/settings/audit, Never-Paywall + accessible to active 15m break-glass)
  app.get<{ Querystring: Record<string, unknown> }>(
    "/api/v1/settings/audit",
    async (request, reply) => {
      const nowIso = formatUtcTimestamp(ctx.clock.nowInstant());
      const bgSession = getVerifiedBreakGlassSession(request);
      let tenantId: TenantId;

      if (bgSession !== undefined) {
        const requested = request.query["tenant_id"];
        if (typeof requested === "string" && requested.trim().length > 0) {
          const parsedReq = parseTenantId(requested.trim(), "tenant_id");
          if (parsedReq !== bgSession.tenantId) {
            throw new AuthorizationDomainError({
              code: "FORBIDDEN",
              message: "Break-glass session cannot query another tenant"
            });
          }
        }
        tenantId = bgSession.tenantId;
      } else {
        const inst = await ctx.pgAdapter.withTransaction(
          ctx.pgAdapter.configuredRole,
          (tx) => readInstallationSnapshot(ctx, tx),
          { readOnly: true }
        );
        const { auth } = await authenticateHumanRead(ctx, request, inst);
        try {
          const resolved = await ctx.pgAdapter.withTransaction(
            ctx.pgAdapter.configuredRole,
            (tx) => resolveActorCommercialTenantId(tx, auth.principal.principalId, request.query["tenant_id"]),
            { readOnly: true }
          );
          tenantId = resolved.tenantId;
        } finally {
          auth.destroySecrets();
        }
      }

      const data = await withTenantRlsTransaction(
        ctx.pgAdapter,
        ctx.pgAdapter.configuredRole,
        tenantId,
        async (tx) => {
          const auditRes = await tx.query<{
            id: string;
            actor_kind: string;
            actor_reference: string | null;
            operator_reference: string | null;
            action: string;
            target_kind: string;
            target_id: string;
            safe_facts: Record<string, unknown>;
            recorded_at: unknown;
          }>(
            `SELECT id, actor_kind, actor_reference, operator_reference, action, target_kind, target_id, safe_facts, recorded_at
               FROM rq.audit_events
              WHERE tenant_id = $1::uuid
              ORDER BY recorded_at DESC
              LIMIT 100`,
            [tenantId]
          );
          const bgRes = await tx.query<{
            id: string;
            operator_id: string;
            reason: string;
            read_only: boolean;
            started_at: unknown;
            expires_at: unknown;
            revoked_at: unknown;
          }>(
            `SELECT id, operator_id, reason, read_only, started_at, expires_at, revoked_at
               FROM rq.support_break_glass_sessions
              WHERE tenant_id = $1::uuid
              ORDER BY started_at DESC
              LIMIT 50`,
            [tenantId]
          );

          return {
            tenant_id: tenantId,
            audit_events: auditRes.rows.map((r) => ({
              audit_id: String(r.id),
              actor_kind: String(r.actor_kind),
              actor_reference: r.actor_reference ?? r.operator_reference,
              action: String(r.action),
              target_kind: String(r.target_kind),
              target_id: String(r.target_id),
              metadata: r.safe_facts,
              occurred_at: formatPgTimestamp(r.recorded_at)
            })),
            break_glass_sessions: bgRes.rows.map((r) => ({
              break_glass_id: String(r.id),
              operator_id: String(r.operator_id),
              reason: String(r.reason),
              read_only: Boolean(r.read_only),
              started_at: formatPgTimestamp(r.started_at),
              expires_at: formatPgTimestamp(r.expires_at),
              revoked_at:
                r.revoked_at !== null && r.revoked_at !== undefined
                  ? formatPgTimestamp(r.revoked_at)
                  : null
            }))
          };
        },
        { readOnly: true }
      );

      return sendSuccessEnvelope(reply, 200, data, {
        requestId: request.id,
        observedAt: nowIso
      });
    }
  );

  // Never-Paywall: Self-serve multi-store GDPR erasure request (PG PII/payload purge + 7y anonymized tax preservation)
  app.post("/api/v1/orgs/me/erasure-request", async (request, reply) => {
    const inst = await ctx.pgAdapter.withTransaction(
      ctx.pgAdapter.configuredRole,
      (tx) => readInstallationSnapshot(ctx, tx),
      { readOnly: true }
    );
    const { auth, body } = await authenticateHumanMutation(ctx, request, inst);
    try {
      if (body["confirm_phrase"] !== "DELETE ORGANIZATION") {
        throw new ValidationDomainError({
          code: "INVALID_VALUE",
          message: "confirm_phrase must equal 'DELETE ORGANIZATION'",
          fieldErrors: [{ path: "confirm_phrase", code: "INVALID_VALUE" }]
        });
      }

      const userRow = await ctx.pgAdapter.withTransaction(
        ctx.pgAdapter.configuredRole,
        async (tx) => {
          const res = await tx.query<{
            id: string;
            tenant_id: string;
            email: string;
            password_hash: string;
            role: string;
            mfa_enrolled: boolean;
            totp_secret_enc: unknown;
          }>(
            `SELECT id, tenant_id, email, password_hash, role, mfa_enrolled, totp_secret_enc
               FROM rq.users
              WHERE principal_id = $1::uuid
              LIMIT 1`,
            [auth.principal.principalId]
          );
          return res.rows[0];
        },
        { readOnly: true }
      );

      if (userRow === undefined) {
        throw new NotFoundDomainError({
          code: "NOT_FOUND",
          message: "Commercial organization owner profile not found"
        });
      }
      if (String(userRow.role) !== "owner") {
        throw new AuthorizationDomainError({
          code: "FORBIDDEN",
          message: "Only an organization owner may initiate GDPR erasure"
        });
      }

      const now = ctx.clock.nowInstant();
      const nowIso = formatUtcTimestamp(now);
      const reauthPassword = typeof body["password"] === "string" ? body["password"] : undefined;
      const reauthCode = typeof body["totp_code"] === "string" ? body["totp_code"].trim() : undefined;

      let reauthenticated = false;
      if (reauthPassword !== undefined) {
        reauthenticated = await verifyPasswordArgon2id(reauthPassword, String(userRow.password_hash));
      } else if (
        reauthCode !== undefined &&
        Boolean(userRow.mfa_enrolled) &&
        userRow.totp_secret_enc !== null &&
        userRow.totp_secret_enc !== undefined
      ) {
        const secretBytes = openTotpSecret(
          ctx.totpEncryptionKey,
          toBuffer(userRow.totp_secret_enc),
          String(userRow.id)
        );
        const totpRes = await verifyTotpWithReplayGuard({
          store: ctx.totpReplayStore,
          userId: String(userRow.id),
          secretBytes,
          submittedCode: reauthCode,
          nowUnixSec: Math.floor(Number(now.epochMilliseconds) / 1000)
        });
        reauthenticated = totpRes.valid;
      }
      if (!reauthenticated) {
        throw new AuthenticationDomainError({
          code: "UNAUTHENTICATED",
          message: "GDPR erasure requires valid password or TOTP MFA confirmation"
        });
      }

      const tenantId = parseTenantId(userRow.tenant_id, "tenant_id");
      const erasureRequestId = ctx.ids.nextUuid();
      const receiptSha256 = crypto
        .createHash("sha256")
        .update(`${erasureRequestId}:${tenantId}:${nowIso}`, "utf8")
        .digest();

      await withTenantRlsTransaction(ctx.pgAdapter, ctx.pgAdapter.configuredRole, tenantId, async (tx) => {
        await tx.query(
          `INSERT INTO rq.gdpr_erasure_requests (
             id, org_id, requested_by, state, redis_purged_at, pg_purged_at, tax_anonymized_at, receipt_sha256, requested_at
           ) VALUES (
             $1::uuid, $2::uuid, $3::uuid, 'pg_purged', $4::timestamptz, $4::timestamptz, $4::timestamptz, $5::bytea, $4::timestamptz
           )`,
          [erasureRequestId, tenantId, auth.principal.principalId, nowIso, receiptSha256]
        );

        await tx.query(
          `UPDATE rq.human_sessions
              SET state = 'revoked',
                  revoked_at = COALESCE(revoked_at, $2::timestamptz),
                  version = version + 1
            WHERE principal_id IN (SELECT principal_id FROM rq.users WHERE tenant_id = $1::uuid)
              AND state = 'active'`,
          [tenantId, nowIso]
        );

        await tx.query(
          `UPDATE rq.humans
              SET display_name = 'Erased User',
                  updated_at = $2::timestamptz,
                  version = version + 1
            WHERE principal_id IN (SELECT principal_id FROM rq.users WHERE tenant_id = $1::uuid)`,
          [tenantId, nowIso]
        );

        await tx.query(
          `UPDATE rq.users
              SET email = 'erased-' || id::text || '@redacted.invalid',
                  password_hash = '!ERASED!',
                  totp_secret_enc = NULL,
                  mfa_enrolled = false,
                  oidc_subject = NULL,
                  version = version + 1
            WHERE tenant_id = $1::uuid`,
          [tenantId]
        );

        await tx.query(
          `UPDATE rq.billing_customers
              SET billing_email = 'erased-' || org_id::text || '@redacted.invalid',
                  tax_id_type = NULL,
                  tax_id_value = NULL,
                  tax_id_verified = false,
                  updated_at = $2::timestamptz
            WHERE org_id = $1::uuid`,
          [tenantId, nowIso]
        );

        await tx.query(
          `UPDATE rq.event_payloads
              SET content = NULL,
                  retention_state = 'expired',
                  expired_at = $2::timestamptz,
                  retention_action_id = $3::uuid
            WHERE tenant_id = $1::uuid
              AND retention_state <> 'expired'`,
          [tenantId, nowIso, erasureRequestId]
        );

        await tx.query(
          `UPDATE rq.event_wire_envelopes
              SET body_bytes = NULL,
                  retention_state = 'expired',
                  expired_at = $2::timestamptz,
                  retention_action_id = $3::uuid
            WHERE tenant_id = $1::uuid
              AND retention_state <> 'expired'`,
          [tenantId, nowIso, erasureRequestId]
        );

        await tx.query(
          `INSERT INTO rq.email_outbox (
             id, tenant_id, idempotency_key, template_code, recipient_email, template_vars, state, created_at
           ) VALUES (
             $1::uuid, $2::uuid, $3::text, 'gdpr_erasure_receipt', $4::text, $5::jsonb, 'pending', $6::timestamptz
           )`,
          [
            ctx.ids.nextUuid(),
            tenantId,
            `gdpr-receipt:${erasureRequestId}`,
            String(userRow.email),
            JSON.stringify({ receipt_sha256: receiptSha256.toString("hex"), org_id: tenantId }),
            nowIso
          ]
        );

        await tx.query(
          `INSERT INTO rq.audit_events (
             id, tenant_id, project_id, actor_kind, actor_reference, action,
             target_kind, target_id, recorded_at, safe_facts
           ) VALUES ($1::uuid, $2::uuid, NULL, 'human', $3::uuid, 'org.gdpr.erasure_requested', 'gdpr_erasure_request', $4::uuid, $5::timestamptz, $6::jsonb)`,
          [
            ctx.ids.nextUuid(),
            tenantId,
            auth.principal.principalId,
            erasureRequestId,
            nowIso,
            JSON.stringify({ tax_records_retained_anonymized_years: 7 })
          ]
        );
      });

      return sendSuccessEnvelope(
        reply,
        202,
        {
          erasure_request_id: erasureRequestId,
          org_id: tenantId,
          state: "pg_purged",
          tax_records_retained_anonymized_years: 7,
          receipt_sha256: receiptSha256.toString("hex"),
          requested_at: nowIso
        },
        { requestId: request.id, observedAt: nowIso }
      );
    } finally {
      auth.destroySecrets();
    }
  });

  app.get<{ Params: { request_id: string } }>(
    "/api/v1/orgs/me/erasure-request/:request_id",
    async (request, reply) => {
      const requestId = parseCanonicalUuid(request.params.request_id, "request_id");
      const inst = await ctx.pgAdapter.withTransaction(
        ctx.pgAdapter.configuredRole,
        (tx) => readInstallationSnapshot(ctx, tx),
        { readOnly: true }
      );
      const { auth } = await authenticateHumanRead(ctx, request, inst);
      try {
        const resolved = await ctx.pgAdapter.withTransaction(
          ctx.pgAdapter.configuredRole,
          (tx) => resolveActorCommercialTenantId(tx, auth.principal.principalId),
          { readOnly: true }
        );
        const nowIso = formatUtcTimestamp(ctx.clock.nowInstant());
        const row = await withTenantRlsTransaction(
          ctx.pgAdapter,
          ctx.pgAdapter.configuredRole,
          resolved.tenantId,
          async (tx) => {
            const res = await tx.query<{
              id: string;
              org_id: string;
              state: string;
              receipt_sha256: unknown;
              requested_at: unknown;
              completed_at: unknown;
            }>(
              `SELECT id, org_id, state, receipt_sha256, requested_at, completed_at
                 FROM rq.gdpr_erasure_requests
                WHERE id = $1::uuid`,
              [requestId]
            );
            return res.rows[0];
          },
          { readOnly: true }
        );
        if (row === undefined) {
          throw new NotFoundDomainError({
            code: "NOT_FOUND",
            message: "GDPR erasure request not found"
          });
        }
        return sendSuccessEnvelope(
          reply,
          200,
          {
            erasure_request_id: String(row.id),
            org_id: String(row.org_id),
            state: String(row.state),
            receipt_sha256:
              row.receipt_sha256 !== null && row.receipt_sha256 !== undefined
                ? toBuffer(row.receipt_sha256).toString("hex")
                : null,
            requested_at: formatPgTimestamp(row.requested_at),
            completed_at:
              row.completed_at !== null && row.completed_at !== undefined
                ? formatPgTimestamp(row.completed_at)
                : null
          },
          { requestId: request.id, observedAt: nowIso }
        );
      } finally {
        auth.destroySecrets();
      }
    }
  );
}
