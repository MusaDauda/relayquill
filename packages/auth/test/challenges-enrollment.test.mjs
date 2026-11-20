import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import {
  AUTH_CHALLENGE_TTL_MS,
  AuthenticationDomainError,
  AuthorizationDomainError,
  ConflictDomainError,
  ENROLLMENT_INTENT_TTL_MS,
  ExpiredDomainError,
  LimitExceededDomainError,
  NotFoundDomainError,
  addMilliseconds,
  parseControlEpoch,
  parsePrincipalId,
  parseUtcTimestamp
} from "@relayquill/domain";
import {
  InMemoryAuthChallengeRepository,
  InMemoryEnrollmentIntentRepository,
  InMemoryPasskeyRepository,
  InMemoryPreauthContextRepository,
  MAX_LIVE_ENROLLMENT_INTENTS_PER_BROWSER,
  MAX_PENDING_INSTALLATION_ENROLLMENT_INTENTS,
  approveEnrollmentIntent,
  beginEnrollmentPasskeyOptions,
  completeEnrollmentPasskey,
  createEnrollmentIntent,
  generateOpaqueWebAuthnUserId,
  getEnrollmentIntentStatus,
  parseSingleCookieFromHeaderValues,
  resolveOrCreatePreauthContext
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
    mode: "initializing",
    controlEpoch: parseControlEpoch(crypto.randomUUID()),
    allowEventAdmission: false,
    allowPublication: false,
    allowFanout: false,
    allowSend: false,
    allowEndpointVerification: false,
    governanceVersion: 1n,
    version: 1n,
    ...overrides
  };
}

function cookiePairFromSetCookie(setCookieSecret) {
  return setCookieSecret.expose().split(";")[0];
}

test("preauth cookies use __Host-rq_pre in release_https, reuse valid context, and reject duplicate cookies", async () => {
  const preauthRepo = new InMemoryPreauthContextRepository();
  const now = parseUtcTimestamp("2026-11-18T10:00:00.000000Z").instant;

  const created = await resolveOrCreatePreauthContext({
    policy: RELEASE_POLICY,
    cookieHeaders: undefined,
    preauthRepo,
    now
  });
  assert.equal(created.reused, false);
  assert.equal(created.cookieName, "__Host-rq_pre");
  const setCookieStr = created.setCookieHeader.expose();
  assert.match(setCookieStr, /^__Host-rq_pre=[A-Za-z0-9_-]{43}; /);
  assert.equal(setCookieStr.includes("Secure"), true);
  assert.equal(setCookieStr.includes("HttpOnly"), true);
  assert.equal(setCookieStr.includes("Path=/"), true);
  assert.equal(setCookieStr.includes("SameSite=Lax"), true);
  assert.equal(setCookieStr.includes("Domain="), false);

  const cookieHeader = cookiePairFromSetCookie(created.setCookieHeader);
  const reused = await resolveOrCreatePreauthContext({
    policy: RELEASE_POLICY,
    cookieHeaders: cookieHeader,
    preauthRepo,
    now: addMilliseconds(now, 10_000n)
  });
  assert.equal(reused.reused, true);
  assert.equal(reused.context.id, created.context.id);
  assert.equal(reused.setCookieHeader, undefined);

  // Duplicate/conflicting preauth cookies rejected immediately
  assert.throws(
    () => parseSingleCookieFromHeaderValues([cookieHeader, cookieHeader], "__Host-rq_pre"),
    AuthenticationDomainError
  );
  await assert.rejects(
    () =>
      resolveOrCreatePreauthContext({
        policy: RELEASE_POLICY,
        cookieHeaders: `${cookieHeader}; ${cookieHeader}`,
        preauthRepo,
        now
      }),
    AuthenticationDomainError
  );

  // Dev profile uses distinct rq_pre_dev cookie
  const devCtx = await resolveOrCreatePreauthContext({
    policy: DEV_POLICY,
    cookieHeaders: undefined,
    preauthRepo,
    now
  });
  assert.equal(devCtx.cookieName, "rq_pre_dev");
  assert.equal(devCtx.setCookieHeader.expose().includes("Secure"), false);
});

test("first_platform_admin bootstrap enforces comparison_sha256, max-5 challenge lockout, replay denial, and no auto-session", async () => {
  const preauthRepo = new InMemoryPreauthContextRepository();
  const challengeRepo = new InMemoryAuthChallengeRepository();
  const passkeyRepo = new InMemoryPasskeyRepository();
  const enrollmentRepo = new InMemoryEnrollmentIntentRepository({ challengeRepo, passkeyRepo });
  const installation = makeInstallation({ mode: "initializing" });
  const t0 = parseUtcTimestamp("2026-11-18T10:00:00.000000Z").instant;

  const created = await createEnrollmentIntent({
    policy: RELEASE_POLICY,
    installation,
    cookieHeaders: undefined,
    body: { schema_version: 1, purpose: "first_platform_admin" },
    preauthRepo,
    enrollmentRepo,
    now: t0
  });
  assert.equal(created.state, "requested");
  assert.equal(created.purpose, "first_platform_admin");
  const cookieHeader = cookiePairFromSetCookie(created.preauthSetCookieHeader);

  // Different browser without matching proof gets non-disclosing 404
  await assert.rejects(
    () =>
      getEnrollmentIntentStatus({
        policy: RELEASE_POLICY,
        installation,
        intentId: created.intent_id,
        cookieHeaders: undefined,
        preauthRepo,
        enrollmentRepo,
        now: t0
      }),
    AuthenticationDomainError
  );

  const otherBrowser = await resolveOrCreatePreauthContext({
    policy: RELEASE_POLICY,
    cookieHeaders: undefined,
    preauthRepo,
    now: t0
  });
  await assert.rejects(
    () =>
      getEnrollmentIntentStatus({
        policy: RELEASE_POLICY,
        installation,
        intentId: created.intent_id,
        cookieHeaders: cookiePairFromSetCookie(otherBrowser.setCookieHeader),
        preauthRepo,
        enrollmentRepo,
        now: t0
      }),
    NotFoundDomainError
  );

  // Operator approval requires exact comparison_sha256 and protected operator_event_reference
  await assert.rejects(
    () =>
      approveEnrollmentIntent({
        installation,
        intentId: created.intent_id,
        expectedVersion: 1n,
        expectedComparisonSha256: "0".repeat(64),
        operatorEventReference: "op-bootstrap-1",
        enrollmentRepo,
        now: addMilliseconds(t0, 5_000n)
      }),
    AuthorizationDomainError
  );
  await assert.rejects(
    () =>
      approveEnrollmentIntent({
        installation,
        intentId: created.intent_id,
        expectedVersion: 1n,
        expectedComparisonSha256: created.comparison_sha256,
        enrollmentRepo,
        now: addMilliseconds(t0, 5_000n)
      }),
    AuthorizationDomainError
  );

  const approved = await approveEnrollmentIntent({
    installation,
    intentId: created.intent_id,
    expectedVersion: 1n,
    expectedComparisonSha256: created.comparison_sha256,
    operatorEventReference: "op-bootstrap-1",
    provisionDisplayName: "Alice Bootstrap Admin",
    enrollmentRepo,
    now: addMilliseconds(t0, 5_000n)
  });
  assert.equal(approved.state, "approved");

  const options = await beginEnrollmentPasskeyOptions({
    policy: RELEASE_POLICY,
    installation,
    intentId: created.intent_id,
    expectedIntentVersion: approved.version,
    authenticatorLabel: "macbook-touchid",
    userAccountLabel: "alice@relayquill.example",
    cookieHeaders: cookieHeader,
    preauthRepo,
    enrollmentRepo,
    challengeRepo,
    passkeyRepo,
    now: addMilliseconds(t0, 10_000n)
  });
  assert.equal(options.public_key.user.name, "alice@relayquill.example");
  assert.equal(options.public_key.user.displayName, "Alice Bootstrap Admin");

  const authenticator = new VirtualWebAuthnAuthenticator();

  // 5 failed attempts lock out the challenge permanently
  for (let i = 0; i < 5; i += 1) {
    const badOriginResponse = authenticator.createRegistrationResponse(options.public_key, {
      origin: "https://attacker.example"
    });
    await assert.rejects(
      () =>
        completeEnrollmentPasskey({
          policy: RELEASE_POLICY,
          installation,
          intentId: created.intent_id,
          authChallengeId: options.auth_challenge_id,
          response: badOriginResponse,
          cookieHeaders: cookieHeader,
          preauthRepo,
          enrollmentRepo,
          challengeRepo,
          now: addMilliseconds(t0, 11_000n + BigInt(i) * 1000n)
        }),
      AuthenticationDomainError
    );
  }
  const lockedChallenge = await challengeRepo.findChallengeById(options.auth_challenge_id);
  assert.equal(lockedChallenge?.failureCount, 5);
  assert.equal(lockedChallenge?.state, "denied");

  // 6th attempt even with valid proof is rejected with LimitExceeded/Conflict before verification
  const validResponse1 = authenticator.createRegistrationResponse(options.public_key, {
    origin: "https://console.relayquill.example"
  });
  await assert.rejects(
    () =>
      completeEnrollmentPasskey({
        policy: RELEASE_POLICY,
        installation,
        intentId: created.intent_id,
        authChallengeId: options.auth_challenge_id,
        response: validResponse1,
        cookieHeaders: cookieHeader,
        preauthRepo,
        enrollmentRepo,
        challengeRepo,
        now: addMilliseconds(t0, 20_000n)
      }),
    LimitExceededDomainError
  );

  // Issue a fresh challenge on the still-enrolling intent and complete properly
  const options2 = await beginEnrollmentPasskeyOptions({
    policy: RELEASE_POLICY,
    installation,
    intentId: created.intent_id,
    expectedIntentVersion: BigInt(options.intent_version),
    authenticatorLabel: "macbook-touchid-2",
    userAccountLabel: "alice@relayquill.example",
    cookieHeaders: cookieHeader,
    preauthRepo,
    enrollmentRepo,
    challengeRepo,
    passkeyRepo,
    now: addMilliseconds(t0, 25_000n)
  });

  // 3-minute challenge expiry enforced
  const expiredChallengeTime = addMilliseconds(t0, 25_000n + AUTH_CHALLENGE_TTL_MS);
  const validResponse2 = authenticator.createRegistrationResponse(options2.public_key, {
    origin: "https://console.relayquill.example"
  });
  await assert.rejects(
    () =>
      completeEnrollmentPasskey({
        policy: RELEASE_POLICY,
        installation,
        intentId: created.intent_id,
        authChallengeId: options2.auth_challenge_id,
        response: validResponse2,
        cookieHeaders: cookieHeader,
        preauthRepo,
        enrollmentRepo,
        challengeRepo,
        now: expiredChallengeTime
      }),
    ExpiredDomainError
  );

  const completed = await completeEnrollmentPasskey({
    policy: RELEASE_POLICY,
    installation,
    intentId: created.intent_id,
    authChallengeId: options2.auth_challenge_id,
    response: validResponse2,
    cookieHeaders: cookieHeader,
    preauthRepo,
    enrollmentRepo,
    challengeRepo,
    now: addMilliseconds(t0, 30_000n)
  });
  assert.equal(completed.completed, true);
  assert.equal(completed.passkey_state, "active");
  assert.equal(completed.next_action, "sign_in");
  assert.equal("sessionSetCookieHeader" in completed, false);

  // Replaying completed challenge / intent fails
  await assert.rejects(
    () =>
      completeEnrollmentPasskey({
        policy: RELEASE_POLICY,
        installation,
        intentId: created.intent_id,
        authChallengeId: options2.auth_challenge_id,
        response: validResponse2,
        cookieHeaders: cookieHeader,
        preauthRepo,
        enrollmentRepo,
        challengeRepo,
        now: addMilliseconds(t0, 31_000n)
      }),
    ConflictDomainError
  );

  // Second first_platform_admin bootstrap attempt fails because platform_admin is now active
  await assert.rejects(
    () =>
      createEnrollmentIntent({
        policy: RELEASE_POLICY,
        installation,
        cookieHeaders: cookieHeader,
        body: { schema_version: 1, purpose: "first_platform_admin" },
        preauthRepo,
        enrollmentRepo,
        now: addMilliseconds(t0, 32_000n)
      }),
    ConflictDomainError
  );
});

test("enrollment enforces 5m expiry, max 5 live intents per browser, and max 1000 pending installation intents", async () => {
  const preauthRepo = new InMemoryPreauthContextRepository();
  const challengeRepo = new InMemoryAuthChallengeRepository();
  const passkeyRepo = new InMemoryPasskeyRepository();
  const enrollmentRepo = new InMemoryEnrollmentIntentRepository({ challengeRepo, passkeyRepo });
  const installation = makeInstallation({ mode: "open" });
  const t0 = parseUtcTimestamp("2026-11-18T10:00:00.000000Z").instant;

  // Fill up 5 live intents for one browser
  let browserCookie;
  for (let i = 0; i < MAX_LIVE_ENROLLMENT_INTENTS_PER_BROWSER; i += 1) {
    const res = await createEnrollmentIntent({
      policy: DEV_POLICY,
      installation,
      cookieHeaders: browserCookie,
      body: {
        schema_version: 1,
        purpose: "invited_human",
        invited_intent_reference: `invite-${i}`
      },
      preauthRepo,
      enrollmentRepo,
      now: addMilliseconds(t0, BigInt(i) * 1000n)
    });
    if (res.preauthSetCookieHeader) {
      browserCookie = cookiePairFromSetCookie(res.preauthSetCookieHeader);
    }
  }

  // 6th live intent in same browser must reject
  await assert.rejects(
    () =>
      createEnrollmentIntent({
        policy: DEV_POLICY,
        installation,
        cookieHeaders: browserCookie,
        body: {
          schema_version: 1,
          purpose: "invited_human",
          invited_intent_reference: "invite-overflow"
        },
        preauthRepo,
        enrollmentRepo,
        now: addMilliseconds(t0, 10_000n)
      }),
    LimitExceededDomainError
  );

  // Fill across distinct browsers up to 1000 installation-wide live intents
  for (let i = MAX_LIVE_ENROLLMENT_INTENTS_PER_BROWSER; i < MAX_PENDING_INSTALLATION_ENROLLMENT_INTENTS; i += 1) {
    await createEnrollmentIntent({
      policy: DEV_POLICY,
      installation,
      cookieHeaders: undefined,
      body: {
        schema_version: 1,
        purpose: "invited_human",
        invited_intent_reference: `install-invite-${i}`
      },
      preauthRepo,
      enrollmentRepo,
      now: addMilliseconds(t0, 11_000n)
    });
  }

  // 1001st pending installation intent must reject
  await assert.rejects(
    () =>
      createEnrollmentIntent({
        policy: DEV_POLICY,
        installation,
        cookieHeaders: undefined,
        body: {
          schema_version: 1,
          purpose: "invited_human",
          invited_intent_reference: "install-overflow"
        },
        preauthRepo,
        enrollmentRepo,
        now: addMilliseconds(t0, 12_000n)
      }),
    LimitExceededDomainError
  );

  // After 5m TTL passes, prior intents expire so a fresh browser intent succeeds
  const afterExpiry = addMilliseconds(t0, ENROLLMENT_INTENT_TTL_MS + 20_000n);
  const freshAfterExpiry = await createEnrollmentIntent({
    policy: DEV_POLICY,
    installation,
    cookieHeaders: undefined,
    body: {
      schema_version: 1,
      purpose: "invited_human",
      invited_intent_reference: "invite-after-expiry"
    },
    preauthRepo,
    enrollmentRepo,
    now: afterExpiry
  });
  assert.equal(freshAfterExpiry.state, "requested");
});

test("restricted_factor_recovery works in recovery_quarantine and yields recovery_pending passkey", async () => {
  const preauthRepo = new InMemoryPreauthContextRepository();
  const challengeRepo = new InMemoryAuthChallengeRepository();
  const passkeyRepo = new InMemoryPasskeyRepository();
  const enrollmentRepo = new InMemoryEnrollmentIntentRepository({ challengeRepo, passkeyRepo });
  const t0 = parseUtcTimestamp("2026-11-18T10:00:00.000000Z").instant;

  const principalId = parsePrincipalId(crypto.randomUUID());
  enrollmentRepo.seedHumanPrincipal({
    principal: {
      principalId,
      kind: "human",
      state: "active",
      authorityEpoch: 2n,
      version: 2n
    },
    human: {
      principalId,
      displayName: "Bob Operator",
      webauthnUserId: generateOpaqueWebAuthnUserId(),
      version: 1n
    }
  });

  const quarantineInstallation = makeInstallation({ mode: "recovery_quarantine" });
  const created = await createEnrollmentIntent({
    policy: DEV_POLICY,
    installation: quarantineInstallation,
    cookieHeaders: undefined,
    body: {
      schema_version: 1,
      purpose: "restricted_factor_recovery",
      target_recovery_reference: "recovery-ticket-7"
    },
    resolvedTarget: { targetPrincipalId: principalId },
    preauthRepo,
    enrollmentRepo,
    now: t0
  });
  const cookieHeader = cookiePairFromSetCookie(created.preauthSetCookieHeader);

  const approved = await approveEnrollmentIntent({
    installation: quarantineInstallation,
    intentId: created.intent_id,
    expectedVersion: 1n,
    expectedComparisonSha256: created.comparison_sha256,
    operatorEventReference: "op-recovery-7",
    enrollmentRepo,
    now: addMilliseconds(t0, 2_000n)
  });

  const options = await beginEnrollmentPasskeyOptions({
    policy: DEV_POLICY,
    installation: quarantineInstallation,
    intentId: created.intent_id,
    expectedIntentVersion: approved.version,
    authenticatorLabel: "yubikey-backup",
    cookieHeaders: cookieHeader,
    preauthRepo,
    enrollmentRepo,
    challengeRepo,
    passkeyRepo,
    now: addMilliseconds(t0, 4_000n)
  });

  const authenticator = new VirtualWebAuthnAuthenticator();
  const regResponse = authenticator.createRegistrationResponse(options.public_key, {
    origin: "http://localhost:5205"
  });
  const completed = await completeEnrollmentPasskey({
    policy: DEV_POLICY,
    installation: quarantineInstallation,
    intentId: created.intent_id,
    authChallengeId: options.auth_challenge_id,
    response: regResponse,
    cookieHeaders: cookieHeader,
    preauthRepo,
    enrollmentRepo,
    challengeRepo,
    now: addMilliseconds(t0, 6_000n)
  });
  assert.equal(completed.passkey_state, "recovery_pending");
  assert.equal(completed.next_action, "restricted_recovery_review");
});
