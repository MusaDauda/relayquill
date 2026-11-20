import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import {
  AuthenticationDomainError,
  AuthorizationDomainError,
  ConflictDomainError,
  ExpiredDomainError,
  HUMAN_SESSION_ABSOLUTE_TTL_MS,
  HUMAN_SESSION_IDLE_TTL_MS,
  OPERATION_PROOF_TTL_MS,
  addMilliseconds,
  parseAuthChallengeId,
  parseCommandReceiptId,
  parseControlEpoch,
  parsePrincipalId,
  parseProjectId,
  parseSessionId,
  parseSha256Hex,
  parseTenantId,
  parseUtcTimestamp
} from "@relayquill/domain";
import {
  GOVERNANCE_ACTION_POLICIES,
  InMemoryAuthChallengeRepository,
  InMemoryHumanSessionRepository,
  InMemoryOperationProofRepository,
  InMemoryPasskeyRepository,
  InMemoryPreauthContextRepository,
  STEP_UP_ALLOWED_ACTIONS,
  authenticateHumanSession,
  authenticateSessionMutation,
  completeSignIn,
  completeStepUpChallenge,
  computeSessionTokenDigest,
  createPasskeyRegistrationOptions,
  createSignInOptions,
  createStepUpOptions,
  deriveSessionCsrfForRawToken,
  generateOpaqueWebAuthnUserId,
  getAuthenticatedSessionContext,
  isStepUpAllowedAction,
  logoutHumanSession,
  normalizeAndHashStepUpTarget,
  parseSingleCookieFromHeaderValues,
  revokeOtherHumanSessionsWithStepUp,
  verifyAndConsumeOperationProof,
  verifyPasskeyRegistration
} from "@relayquill/auth";
import { VirtualWebAuthnAuthenticator } from "./helpers/virtual-authenticator.mjs";

const RELEASE_POLICY = {
  rp_id: "console.relayquill.example",
  rp_name: "Relayquill",
  allowed_origins: ["https://console.relayquill.example"],
  cookie_profile: "release_https"
};

const DEV_POLICY = {
  rp_id: "localhost",
  rp_name: "Relayquill Dev",
  allowed_origins: ["http://localhost:5205"],
  cookie_profile: "development_only"
};

function makeInstallation(overrides = {}) {
  return {
    mode: "active",
    controlEpoch: parseControlEpoch(crypto.randomUUID()),
    allowEventAdmission: true,
    allowPublication: true,
    allowFanout: true,
    allowSend: true,
    allowEndpointVerification: true,
    governanceVersion: 1n,
    version: 1n,
    ...overrides
  };
}

function sha256HexOf(text) {
  return parseSha256Hex(crypto.createHash("sha256").update(text, "utf8").digest("hex"), "sha256");
}

function extractCookiePair(setCookieHeader, expectedName) {
  const firstSegment = setCookieHeader.split(";")[0];
  const prefix = `${expectedName}=`;
  assert.ok(firstSegment.startsWith(prefix), `Expected cookie ${expectedName} in ${setCookieHeader}`);
  return firstSegment;
}

async function setupHumanWithPasskey(policy, installation, now) {
  const preauthRepo = new InMemoryPreauthContextRepository();
  const challengeRepo = new InMemoryAuthChallengeRepository();
  const passkeyRepo = new InMemoryPasskeyRepository();
  const sessionRepo = new InMemoryHumanSessionRepository({ challengeRepo, passkeyRepo });
  const proofRepo = new InMemoryOperationProofRepository({ challengeRepo, passkeyRepo });
  const authenticator = new VirtualWebAuthnAuthenticator();

  const principalId = parsePrincipalId(crypto.randomUUID(), "principal_id");
  const webauthnUserId = generateOpaqueWebAuthnUserId();

  sessionRepo.seedHuman({
    principal: {
      principalId,
      kind: "human",
      state: "active",
      authorityEpoch: 1n,
      version: 1n
    },
    human: {
      principalId,
      displayName: "Ada Lovelace",
      webauthnUserId,
      version: 1n
    }
  });

  const regChallengeBytes = crypto.randomBytes(32);
  const regOptions = await createPasskeyRegistrationOptions({
    policy,
    challengeBytes: regChallengeBytes,
    webauthnUserId,
    userName: "ada@console.relayquill.example",
    userDisplayName: "Ada Lovelace"
  });

  const expectedOrigin = policy.allowed_origins[0];
  const attestation = authenticator.createRegistrationResponse(regOptions, {
    rpId: policy.rp_id,
    origin: expectedOrigin,
    backupEligible: true,
    backedUp: true
  });

  const verifiedReg = await verifyPasskeyRegistration({
    policy,
    expectedChallengeBytes: regChallengeBytes,
    response: attestation
  });

  const passkey = await passkeyRepo.createPasskey({
    id: crypto.randomUUID(),
    humanPrincipalId: principalId,
    credentialId: verifiedReg.credentialId,
    publicKey: verifiedReg.publicKey,
    webauthnUserId,
    signCount: verifiedReg.signCount,
    deviceType: verifiedReg.deviceType,
    backedUp: verifiedReg.backedUp,
    transports: verifiedReg.transports,
    state: "active",
    enrolledAt: now
  });

  return {
    preauthRepo,
    challengeRepo,
    passkeyRepo,
    sessionRepo,
    proofRepo,
    authenticator,
    principalId,
    webauthnUserId,
    passkey
  };
}

async function signInHuman({ policy, installation, env, now }) {
  const opts = await createSignInOptions({
    policy,
    installation,
    cookieHeaders: undefined,
    schemaVersion: 1,
    preauthRepo: env.preauthRepo,
    challengeRepo: env.challengeRepo,
    now
  });
  assert.ok(opts.preauthSetCookieHeader);
  const cookieName = policy.cookie_profile === "release_https" ? "__Host-rq_pre" : "rq_pre_dev";
  const preauthCookie = extractCookiePair(opts.preauthSetCookieHeader.expose(), cookieName);
  const assertion = env.authenticator.createAuthenticationResponse(opts.public_key, {
    rpId: policy.rp_id,
    origin: policy.allowed_origins[0]
  });
  const signedIn = await completeSignIn({
    policy,
    installation,
    authChallengeId: opts.auth_challenge_id,
    response: assertion,
    cookieHeaders: preauthCookie,
    preauthRepo: env.preauthRepo,
    challengeRepo: env.challengeRepo,
    passkeyRepo: env.passkeyRepo,
    sessionRepo: env.sessionRepo,
    now
  });
  const sessionCookieName =
    policy.cookie_profile === "release_https" ? "__Host-rq_session" : "rq_session_dev";
  const rawSetCookie = signedIn.sessionSetCookieHeader.expose();
  const sessionCookiePair = extractCookiePair(rawSetCookie, sessionCookieName);
  const rawSessionToken = parseSingleCookieFromHeaderValues(sessionCookiePair, sessionCookieName);
  assert.ok(rawSessionToken !== null);
  return {
    signedIn,
    rawSetCookie,
    sessionCookiePair,
    rawSessionToken,
    opts
  };
}

test("discoverable sign-in sets __Host-rq_session without Domain, stores SHA256 digest only, and derives refresh-safe CSRF token", async () => {
  const t0 = parseUtcTimestamp("2026-11-18T08:00:00Z").instant;
  const installation = makeInstallation();
  const env = await setupHumanWithPasskey(RELEASE_POLICY, installation, t0);

  const { signedIn, rawSetCookie, sessionCookiePair, rawSessionToken, opts } = await signInHuman({
    policy: RELEASE_POLICY,
    installation,
    env,
    now: t0
  });

  assert.equal(signedIn.cacheControl, "no-store");
  assert.equal(signedIn.session.principal_id, env.principalId);
  assert.equal(signedIn.session.display_name, "Ada Lovelace");
  assert.equal(signedIn.session.purpose, "ordinary");

  assert.equal(opts.public_key.userVerification, "required");
  assert.equal(opts.public_key.allowCredentials, undefined);

  assert.match(rawSetCookie, /^__Host-rq_session=/);
  assert.match(rawSetCookie, /;\s*Path=\//);
  assert.match(rawSetCookie, /;\s*HttpOnly/);
  assert.match(rawSetCookie, /;\s*Secure/);
  assert.match(rawSetCookie, /;\s*SameSite=Lax/);
  assert.equal(/\bDomain=/i.test(rawSetCookie), false);

  // Raw cookie token is not persisted; only SHA256("rq.session.v1\0" || bytes) is indexed.
  const rawBytes = Buffer.from(rawSessionToken, "base64url");
  assert.equal(rawBytes.length, 32);
  const storedByDigest = await env.sessionRepo.findSessionByTokenDigest(computeSessionTokenDigest(rawBytes));
  assert.ok(storedByDigest !== null);
  assert.equal(storedByDigest.id, signedIn.session.session_id);

  // Wrong cookie name (dev cookie submitted in release mode) is rejected.
  await assert.rejects(
    () =>
      authenticateHumanSession({
        policy: RELEASE_POLICY,
        installation,
        cookieHeaders: `rq_session_dev=${rawSessionToken}`,
        sessionRepo: env.sessionRepo,
        now: t0
      }),
    AuthenticationDomainError
  );

  // Duplicate session cookie names in Cookie header are rejected.
  await assert.rejects(
    () =>
      authenticateHumanSession({
        policy: RELEASE_POLICY,
        installation,
        cookieHeaders: `${sessionCookiePair}; ${sessionCookiePair}`,
        sessionRepo: env.sessionRepo,
        now: t0
      }),
    AuthenticationDomainError
  );

  // Refresh-safe derived CSRF token matches independent HMAC-SHA256 derivation across reads.
  const ctx1 = await getAuthenticatedSessionContext({
    policy: RELEASE_POLICY,
    installation,
    cookieHeaders: sessionCookiePair,
    sessionRepo: env.sessionRepo,
    now: addMilliseconds(t0, 5_000n)
  });
  const ctx2 = await getAuthenticatedSessionContext({
    policy: RELEASE_POLICY,
    installation,
    cookieHeaders: sessionCookiePair,
    sessionRepo: env.sessionRepo,
    now: addMilliseconds(t0, 90_000n)
  });
  assert.equal(ctx1.cacheControl, "no-store");
  assert.equal(ctx1.csrf_token.expose(), ctx2.csrf_token.expose());
  const independentlyDerived = deriveSessionCsrfForRawToken(rawSessionToken);
  assert.equal(ctx1.csrf_token.expose(), independentlyDerived.expose());

  const expectedHmac = crypto
    .createHmac("sha256", rawBytes)
    .update("rq.csrf.v1", "utf8")
    .digest()
    .toString("base64url");
  assert.equal(ctx1.csrf_token.expose(), expectedHmac);

  // Valid Origin + CSRF authenticates mutation cleanly.
  const authedMutation = await authenticateSessionMutation({
    policy: RELEASE_POLICY,
    installation,
    cookieHeaders: sessionCookiePair,
    originHeader: "https://console.relayquill.example",
    csrfHeader: ctx1.csrf_token.expose(),
    sessionRepo: env.sessionRepo,
    now: addMilliseconds(t0, 95_000n)
  });
  assert.equal(authedMutation.session.id, signedIn.session.session_id);
  authedMutation.destroySecrets();

  // Origin rejection cases: missing, null, wrong origin, duplicate origin.
  for (const badOrigin of [undefined, "null", "https://evil.example", ["https://console.relayquill.example", "https://evil.example"]]) {
    await assert.rejects(
      () =>
        authenticateSessionMutation({
          policy: RELEASE_POLICY,
          installation,
          cookieHeaders: sessionCookiePair,
          originHeader: badOrigin,
          csrfHeader: ctx1.csrf_token.expose(),
          sessionRepo: env.sessionRepo,
          now: addMilliseconds(t0, 96_000n)
        }),
      AuthorizationDomainError
    );
  }

  // CSRF mismatch / missing / duplicate header rejections.
  const wrongCsrfBytes = Buffer.from(ctx1.csrf_token.expose(), "base64url");
  wrongCsrfBytes[0] ^= 0xff;
  const wrongCsrf = wrongCsrfBytes.toString("base64url");
  for (const badCsrf of [undefined, "", wrongCsrf, [ctx1.csrf_token.expose(), ctx1.csrf_token.expose()]]) {
    await assert.rejects(
      () =>
        authenticateSessionMutation({
          policy: RELEASE_POLICY,
          installation,
          cookieHeaders: sessionCookiePair,
          originHeader: "https://console.relayquill.example",
          csrfHeader: badCsrf,
          sessionRepo: env.sessionRepo,
          now: addMilliseconds(t0, 97_000n)
        }),
      AuthorizationDomainError
    );
  }
});

test("session enforces rate-bounded idle touch, 30m idle expiry, 8h absolute ceiling, epoch/state invalidation, and logout", async () => {
  const t0 = parseUtcTimestamp("2026-11-18T08:00:00Z").instant;
  const installation = makeInstallation();
  const env = await setupHumanWithPasskey(DEV_POLICY, installation, t0);
  const { signedIn, sessionCookiePair } = await signInHuman({
    policy: DEV_POLICY,
    installation,
    env,
    now: t0
  });

  // Within default 60s minimum touch interval: idleExpiresAt stays unchanged, version stays 1n.
  const at30s = addMilliseconds(t0, 30_000n);
  const readAt30s = await authenticateHumanSession({
    policy: DEV_POLICY,
    installation,
    cookieHeaders: sessionCookiePair,
    sessionRepo: env.sessionRepo,
    now: at30s
  });
  assert.equal(readAt30s.session.version, 1n);
  assert.equal(readAt30s.session.idleExpiresAt.epochMilliseconds, addMilliseconds(t0, HUMAN_SESSION_IDLE_TTL_MS).epochMilliseconds);
  readAt30s.destroySecrets();

  // After 60s: idleExpiresAt slides forward and version increments.
  const at90s = addMilliseconds(t0, 90_000n);
  const readAt90s = await authenticateHumanSession({
    policy: DEV_POLICY,
    installation,
    cookieHeaders: sessionCookiePair,
    sessionRepo: env.sessionRepo,
    now: at90s
  });
  assert.equal(readAt90s.session.version, 2n);
  assert.equal(readAt90s.session.idleExpiresAt.epochMilliseconds, addMilliseconds(at90s, HUMAN_SESSION_IDLE_TTL_MS).epochMilliseconds);
  readAt90s.destroySecrets();

  // Idle timeout triggers after 30m from last touch.
  const expiredByIdle = addMilliseconds(at90s, HUMAN_SESSION_IDLE_TTL_MS + 1_000n);
  await assert.rejects(
    () =>
      authenticateHumanSession({
        policy: DEV_POLICY,
        installation,
        cookieHeaders: sessionCookiePair,
        sessionRepo: env.sessionRepo,
        now: expiredByIdle
      }),
    ExpiredDomainError
  );

  // Session active via 20m keep-alives up to 8h boundary: idle touch clamps at absoluteExpiresAt and expires past 8h.
  const signIn2 = await signInHuman({
    policy: DEV_POLICY,
    installation,
    env,
    now: t0
  });
  let stepMs = 1_200_000n;
  while (stepMs < HUMAN_SESSION_ABSOLUTE_TTL_MS - 300_000n) {
    const keepAlive = await authenticateHumanSession({
      policy: DEV_POLICY,
      installation,
      cookieHeaders: signIn2.sessionCookiePair,
      sessionRepo: env.sessionRepo,
      now: addMilliseconds(t0, stepMs)
    });
    keepAlive.destroySecrets();
    stepMs += 1_200_000n;
  }
  const nearAbsolute = addMilliseconds(t0, HUMAN_SESSION_ABSOLUTE_TTL_MS - 300_000n);
  const nearRead = await authenticateHumanSession({
    policy: DEV_POLICY,
    installation,
    cookieHeaders: signIn2.sessionCookiePair,
    sessionRepo: env.sessionRepo,
    now: nearAbsolute
  });
  assert.equal(
    nearRead.session.idleExpiresAt.epochMilliseconds,
    addMilliseconds(t0, HUMAN_SESSION_ABSOLUTE_TTL_MS).epochMilliseconds
  );
  nearRead.destroySecrets();

  await assert.rejects(
    () =>
      authenticateHumanSession({
        policy: DEV_POLICY,
        installation,
        cookieHeaders: signIn2.sessionCookiePair,
        sessionRepo: env.sessionRepo,
        now: addMilliseconds(t0, HUMAN_SESSION_ABSOLUTE_TTL_MS + 1n)
      }),
    ExpiredDomainError
  );

  // Installation control_epoch rotation invalidates active sessions immediately.
  const signIn3 = await signInHuman({
    policy: DEV_POLICY,
    installation,
    env,
    now: t0
  });
  const rotatedInstallation = makeInstallation({
    controlEpoch: parseControlEpoch(crypto.randomUUID())
  });
  await assert.rejects(
    () =>
      authenticateHumanSession({
        policy: DEV_POLICY,
        installation: rotatedInstallation,
        cookieHeaders: signIn3.sessionCookiePair,
        sessionRepo: env.sessionRepo,
        now: addMilliseconds(t0, 5_000n)
      }),
    AuthenticationDomainError
  );

  // Principal authorityEpoch bump or suspension immediately invalidates sessions.
  env.sessionRepo.updateSeededPrincipal({
    principalId: env.principalId,
    kind: "human",
    state: "active",
    authorityEpoch: 2n,
    version: 2n
  });
  await assert.rejects(
    () =>
      authenticateHumanSession({
        policy: DEV_POLICY,
        installation,
        cookieHeaders: signIn3.sessionCookiePair,
        sessionRepo: env.sessionRepo,
        now: addMilliseconds(t0, 5_000n)
      }),
    AuthenticationDomainError
  );

  // Logout revokes session and clears cookie.
  env.sessionRepo.updateSeededPrincipal({
    principalId: env.principalId,
    kind: "human",
    state: "active",
    authorityEpoch: 1n,
    version: 3n
  });
  const signIn4 = await signInHuman({
    policy: DEV_POLICY,
    installation,
    env,
    now: t0
  });
  const ctx4 = await getAuthenticatedSessionContext({
    policy: DEV_POLICY,
    installation,
    cookieHeaders: signIn4.sessionCookiePair,
    sessionRepo: env.sessionRepo,
    now: t0
  });
  const loggedOut = await logoutHumanSession({
    policy: DEV_POLICY,
    installation,
    cookieHeaders: signIn4.sessionCookiePair,
    originHeader: "http://localhost:5205",
    csrfHeader: ctx4.csrf_token.expose(),
    sessionRepo: env.sessionRepo,
    now: addMilliseconds(t0, 1_000n)
  });
  assert.equal(loggedOut.logged_out, true);
  assert.equal(loggedOut.session_id, signIn4.signedIn.session.session_id);
  assert.match(loggedOut.clearCookieHeader, /Max-Age=0/);

  await assert.rejects(
    () =>
      authenticateHumanSession({
        policy: DEV_POLICY,
        installation,
        cookieHeaders: signIn4.sessionCookiePair,
        sessionRepo: env.sessionRepo,
        now: addMilliseconds(t0, 2_000n)
      }),
    AuthenticationDomainError
  );

  // Verify recovery_restricted sessions are gated by allowRecoveryRestricted.
  const restrictedToken = crypto.randomBytes(32);
  const restrictedId = parseSessionId(crypto.randomUUID(), "session_id");
  await env.sessionRepo.createSession({
    id: restrictedId,
    principalId: env.principalId,
    controlEpoch: installation.controlEpoch,
    tokenDigest: computeSessionTokenDigest(restrictedToken),
    csrfDigest: crypto.randomBytes(32),
    principalAuthorityEpoch: 1n,
    purpose: "recovery_restricted",
    createdAt: t0,
    idleExpiresAt: addMilliseconds(t0, HUMAN_SESSION_IDLE_TTL_MS),
    absoluteExpiresAt: addMilliseconds(t0, HUMAN_SESSION_ABSOLUTE_TTL_MS)
  });
  const restrictedCookie = `rq_session_dev=${restrictedToken.toString("base64url")}`;
  await assert.rejects(
    () =>
      authenticateHumanSession({
        policy: DEV_POLICY,
        installation,
        cookieHeaders: restrictedCookie,
        sessionRepo: env.sessionRepo,
        now: addMilliseconds(t0, 1_000n)
      }),
    AuthorizationDomainError
  );
  const allowedRestricted = await authenticateHumanSession({
    policy: DEV_POLICY,
    installation,
    cookieHeaders: restrictedCookie,
    sessionRepo: env.sessionRepo,
    now: addMilliseconds(t0, 1_000n),
    allowRecoveryRestricted: true
  });
  assert.equal(allowedRestricted.session.id, restrictedId);
  await assert.rejects(
    () =>
      createStepUpOptions({
        policy: DEV_POLICY,
        authenticatedSession: allowedRestricted,
        installation,
        target: {
          action: "tenants.suspend",
          scopeKind: "installation",
          tenantId: null,
          projectId: null,
          targetResourceId: crypto.randomUUID(),
          targetVersion: 1n,
          canonicalCommandSha256: sha256HexOf("cmd-1")
        },
        challengeRepo: env.challengeRepo,
        passkeyRepo: env.passkeyRepo,
        now: addMilliseconds(t0, 1_000n)
      }),
    AuthorizationDomainError
  );
  allowedRestricted.destroySecrets();
  assert.notEqual(signedIn.session.session_id, restrictedId);
});

test("step-up binds exact action/target/version/command hash, session proof, atomic single consume, and revokes other sessions", async () => {
  const t0 = parseUtcTimestamp("2026-11-18T08:00:00Z").instant;
  const installation = makeInstallation();
  const env = await setupHumanWithPasskey(RELEASE_POLICY, installation, t0);

  const s1 = await signInHuman({ policy: RELEASE_POLICY, installation, env, now: t0 });
  const s2 = await signInHuman({ policy: RELEASE_POLICY, installation, env, now: t0 });

  const authS1 = await authenticateHumanSession({
    policy: RELEASE_POLICY,
    installation,
    cookieHeaders: s1.sessionCookiePair,
    sessionRepo: env.sessionRepo,
    now: addMilliseconds(t0, 1_000n)
  });
  const authS2 = await authenticateHumanSession({
    policy: RELEASE_POLICY,
    installation,
    cookieHeaders: s2.sessionCookiePair,
    sessionRepo: env.sessionRepo,
    now: addMilliseconds(t0, 1_000n)
  });

  const tenantId = parseTenantId(crypto.randomUUID(), "tenant_id");
  const projectId = parseProjectId(crypto.randomUUID(), "project_id");
  const endpointId = crypto.randomUUID();
  const targetBinding = {
    action: "endpoints.activate",
    scopeKind: "project",
    tenantId,
    projectId,
    targetResourceId: endpointId,
    targetVersion: 4n,
    canonicalCommandSha256: sha256HexOf("activate-endpoint-v4")
  };

  // Canonical target hash includes domain separator and length prefixing.
  const normalizedA = normalizeAndHashStepUpTarget(targetBinding);
  const normalizedB = normalizeAndHashStepUpTarget({
    ...targetBinding,
    targetVersion: 5n
  });
  assert.notEqual(normalizedA.targetSha256Hex, normalizedB.targetSha256Hex);

  const stepUpOpts = await createStepUpOptions({
    policy: RELEASE_POLICY,
    authenticatedSession: authS1,
    installation,
    target: targetBinding,
    challengeRepo: env.challengeRepo,
    passkeyRepo: env.passkeyRepo,
    now: addMilliseconds(t0, 2_000n)
  });

  assert.equal(stepUpOpts.action, "endpoints.activate");
  assert.equal(stepUpOpts.target_sha256, normalizedA.targetSha256Hex);
  assert.ok(Array.isArray(stepUpOpts.public_key.allowCredentials));
  assert.equal(stepUpOpts.public_key.allowCredentials.length, 1);

  const stepUpAssertion = env.authenticator.createAuthenticationResponse(stepUpOpts.public_key, {
    rpId: RELEASE_POLICY.rp_id,
    origin: RELEASE_POLICY.allowed_origins[0]
  });

  // Attempting to complete s1's step-up challenge from s2's browser session fails.
  await assert.rejects(
    () =>
      completeStepUpChallenge({
        policy: RELEASE_POLICY,
        authenticatedSession: authS2,
        installation,
        authChallengeId: stepUpOpts.auth_challenge_id,
        response: stepUpAssertion,
        challengeRepo: env.challengeRepo,
        passkeyRepo: env.passkeyRepo,
        proofRepo: env.proofRepo,
        now: addMilliseconds(t0, 3_000n)
      }),
    AuthenticationDomainError
  );

  // Completing from s1 succeeds.
  const completedStepUp = await completeStepUpChallenge({
    policy: RELEASE_POLICY,
    authenticatedSession: authS1,
    installation,
    authChallengeId: stepUpOpts.auth_challenge_id,
    response: stepUpAssertion,
    challengeRepo: env.challengeRepo,
    passkeyRepo: env.passkeyRepo,
    proofRepo: env.proofRepo,
    now: addMilliseconds(t0, 4_000n)
  });

  const receiptId = parseCommandReceiptId(crypto.randomUUID(), "receipt_id");

  // Any binding mismatch rejects without consuming the proof.
  const mutatedBindings = [
    { ...targetBinding, action: "endpoints.retire" },
    { ...targetBinding, scopeKind: "tenant", projectId: null },
    { ...targetBinding, tenantId: parseTenantId(crypto.randomUUID(), "tenant_id") },
    { ...targetBinding, targetResourceId: crypto.randomUUID() },
    { ...targetBinding, targetVersion: 5n },
    { ...targetBinding, canonicalCommandSha256: sha256HexOf("tampered-command") }
  ];
  for (const mismatch of mutatedBindings) {
    await assert.rejects(
      () =>
        verifyAndConsumeOperationProof({
          proofId: completedStepUp.operation_proof_id,
          authenticatedSession: authS1,
          installation,
          expectedBinding: mismatch,
          acceptedReceiptId: receiptId,
          proofRepo: env.proofRepo,
          now: addMilliseconds(t0, 5_000n)
        }),
      AuthorizationDomainError
    );
  }

  // Wrong session rejects.
  await assert.rejects(
    () =>
      verifyAndConsumeOperationProof({
        proofId: completedStepUp.operation_proof_id,
        authenticatedSession: authS2,
        installation,
        expectedBinding: targetBinding,
        acceptedReceiptId: receiptId,
        proofRepo: env.proofRepo,
        now: addMilliseconds(t0, 5_000n)
      }),
    AuthorizationDomainError
  );

  // Matching binding consumes proof atomically once.
  const consumed = await verifyAndConsumeOperationProof({
    proofId: completedStepUp.operation_proof_id,
    authenticatedSession: authS1,
    installation,
    expectedBinding: targetBinding,
    acceptedReceiptId: receiptId,
    proofRepo: env.proofRepo,
    now: addMilliseconds(t0, 6_000n)
  });
  assert.equal(consumed.state, "consumed");
  assert.equal(consumed.acceptedReceiptId, receiptId);

  // Replay is rejected with ConflictDomainError.
  await assert.rejects(
    () =>
      verifyAndConsumeOperationProof({
        proofId: completedStepUp.operation_proof_id,
        authenticatedSession: authS1,
        installation,
        expectedBinding: targetBinding,
        acceptedReceiptId: receiptId,
        proofRepo: env.proofRepo,
        now: addMilliseconds(t0, 7_000n)
      }),
    ConflictDomainError
  );

  // Proof expires after 5m TTL.
  const stepUp2Opts = await createStepUpOptions({
    policy: RELEASE_POLICY,
    authenticatedSession: authS1,
    installation,
    target: targetBinding,
    challengeRepo: env.challengeRepo,
    passkeyRepo: env.passkeyRepo,
    now: addMilliseconds(t0, 8_000n)
  });
  const stepUp2Assertion = env.authenticator.createAuthenticationResponse(stepUp2Opts.public_key, {
    rpId: RELEASE_POLICY.rp_id,
    origin: RELEASE_POLICY.allowed_origins[0]
  });
  const proof2 = await completeStepUpChallenge({
    policy: RELEASE_POLICY,
    authenticatedSession: authS1,
    installation,
    authChallengeId: stepUp2Opts.auth_challenge_id,
    response: stepUp2Assertion,
    challengeRepo: env.challengeRepo,
    passkeyRepo: env.passkeyRepo,
    proofRepo: env.proofRepo,
    now: addMilliseconds(t0, 9_000n)
  });
  await assert.rejects(
    () =>
      verifyAndConsumeOperationProof({
        proofId: proof2.operation_proof_id,
        authenticatedSession: authS1,
        installation,
        expectedBinding: targetBinding,
        acceptedReceiptId: receiptId,
        proofRepo: env.proofRepo,
        now: addMilliseconds(t0, 9_000n + OPERATION_PROOF_TTL_MS + 1_000n)
      }),
    ExpiredDomainError
  );

  // sessions.revoke_others revokes s2 while keeping s1 active.
  const revokeCmdHash = sha256HexOf("revoke-other-sessions");
  const revokeStepUpOpts = await createStepUpOptions({
    policy: RELEASE_POLICY,
    authenticatedSession: authS1,
    installation,
    target: {
      action: "sessions.revoke_others",
      scopeKind: "installation",
      tenantId: null,
      projectId: null,
      targetResourceId: env.principalId,
      targetVersion: 1n,
      canonicalCommandSha256: revokeCmdHash
    },
    challengeRepo: env.challengeRepo,
    passkeyRepo: env.passkeyRepo,
    now: addMilliseconds(t0, 10_000n)
  });
  const revokeAssertion = env.authenticator.createAuthenticationResponse(revokeStepUpOpts.public_key, {
    rpId: RELEASE_POLICY.rp_id,
    origin: RELEASE_POLICY.allowed_origins[0]
  });
  const revokeProof = await completeStepUpChallenge({
    policy: RELEASE_POLICY,
    authenticatedSession: authS1,
    installation,
    authChallengeId: revokeStepUpOpts.auth_challenge_id,
    response: revokeAssertion,
    challengeRepo: env.challengeRepo,
    passkeyRepo: env.passkeyRepo,
    proofRepo: env.proofRepo,
    now: addMilliseconds(t0, 11_000n)
  });
  const ctxS1 = await getAuthenticatedSessionContext({
    policy: RELEASE_POLICY,
    installation,
    cookieHeaders: s1.sessionCookiePair,
    sessionRepo: env.sessionRepo,
    now: addMilliseconds(t0, 12_000n)
  });
  const revokedResult = await revokeOtherHumanSessionsWithStepUp({
    policy: RELEASE_POLICY,
    installation,
    cookieHeaders: s1.sessionCookiePair,
    originHeader: "https://console.relayquill.example",
    csrfHeader: ctxS1.csrf_token.expose(),
    operationProofId: revokeProof.operation_proof_id,
    canonicalCommandSha256: revokeCmdHash,
    acceptedReceiptId: parseCommandReceiptId(crypto.randomUUID(), "revoke_receipt"),
    sessionRepo: env.sessionRepo,
    proofRepo: env.proofRepo,
    now: addMilliseconds(t0, 12_000n)
  });
  assert.equal(revokedResult.revoked_count, 1);
  assert.equal(revokedResult.kept_session_id, s1.signedIn.session.session_id);

  // s2 is now revoked, while s1 continues working.
  await assert.rejects(
    () =>
      authenticateHumanSession({
        policy: RELEASE_POLICY,
        installation,
        cookieHeaders: s2.sessionCookiePair,
        sessionRepo: env.sessionRepo,
        now: addMilliseconds(t0, 13_000n)
      }),
    AuthenticationDomainError
  );
  const stillAliveS1 = await authenticateHumanSession({
    policy: RELEASE_POLICY,
    installation,
    cookieHeaders: s1.sessionCookiePair,
    sessionRepo: env.sessionRepo,
    now: addMilliseconds(t0, 13_000n)
  });
  assert.equal(stillAliveS1.session.id, s1.signedIn.session.session_id);

  stillAliveS1.destroySecrets();
  authS1.destroySecrets();
  authS2.destroySecrets();
  assert.ok(parseAuthChallengeId(stepUpOpts.auth_challenge_id));
});

test("every requiresStepUp action in GOVERNANCE_ACTION_POLICIES is accepted by STEP_UP_ALLOWED_ACTIONS and hashes cleanly", () => {
  const tenantId = parseTenantId(crypto.randomUUID(), "tenant_id");
  const projectId = parseProjectId(crypto.randomUUID(), "project_id");
  const targetResourceId = crypto.randomUUID();
  const cmdHash = sha256HexOf("parity-cmd");

  const stepUpActions = Object.entries(GOVERNANCE_ACTION_POLICIES).filter(
    ([, policySpec]) => policySpec.requiresStepUp
  );
  assert.ok(stepUpActions.length > 0);

  for (const [action, policySpec] of stepUpActions) {
    assert.equal(STEP_UP_ALLOWED_ACTIONS.has(action), true, `Missing step-up action: ${action}`);
    assert.equal(isStepUpAllowedAction(action), true);

    const scopeKind =
      policySpec.scope === "platform"
        ? "installation"
        : policySpec.scope === "tenant"
          ? "tenant"
          : "project";

    const normalized = normalizeAndHashStepUpTarget({
      action,
      scopeKind,
      tenantId: scopeKind === "installation" ? null : tenantId,
      projectId: scopeKind === "project" ? projectId : null,
      targetResourceId,
      targetVersion: 1n,
      canonicalCommandSha256: cmdHash
    });
    assert.equal(normalized.action, action);
    assert.equal(normalized.targetSha256.length, 32);
  }
});
