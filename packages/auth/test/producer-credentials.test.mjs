import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import {
  AuthenticationDomainError,
  AuthorizationDomainError,
  ExpiredDomainError,
  PRODUCER_CREDENTIAL_INTENT_TTL_MS,
  PRODUCER_CREDENTIAL_MAX_OVERLAP_MS,
  PRODUCER_CREDENTIAL_MAX_TTL_MS,
  ValidationDomainError,
  addMilliseconds,
  parseControlEpoch,
  parseEventTypeId,
  parsePrincipalId,
  parseProducerCredentialId,
  parseProducerCredentialIntentId,
  parseProducerId,
  parseProducerNamespace,
  parseProjectId,
  parseTenantId,
  parseUtcTimestamp
} from "@relayquill/domain";
import { encodeDomainLengthPrefixed } from "@relayquill/contracts";
import {
  InMemoryProducerCredentialRepository,
  activateProducerCredentialByPossession,
  assertHumanWorkflowNamespace,
  assertMachineProducerChannel,
  authenticateProducerCredential,
  computeProducerCredentialDigest,
  deliverProducerCredentialToCustody,
  extractBearerTokenFromAuthorizationHeader,
  extractBearerTokenFromRawHeaders,
  generateProducerCredentialMaterial,
  issueProducerCredentialIntent,
  parseProducerBearerTokenStrict,
  rotateProducerCredentialWithOverlap,
  validateAndHashProducerScopeDefinition
} from "@relayquill/auth";

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

function makeSeed(options = {}) {
  const tenantId = parseTenantId(crypto.randomUUID(), "tenant_id");
  const projectId = parseProjectId(crypto.randomUUID(), "project_id");
  const producerId = parseProducerId(crypto.randomUUID(), "producer_id");
  const principalId = parsePrincipalId(crypto.randomUUID(), "principal_id");
  const issuerPrincipalId = parsePrincipalId(crypto.randomUUID(), "issuer_principal_id");
  const eventType1 = parseEventTypeId(crypto.randomUUID(), "event_type_1");
  const eventType2 = parseEventTypeId(crypto.randomUUID(), "event_type_2");

  const scope1 = validateAndHashProducerScopeDefinition({
    allowedEvents: [{ eventTypeId: eventType1, schemaVersions: [1, 2] }],
    actions: ["events.admit", "events.resolve", "events.read_own"]
  });
  const scope2 = validateAndHashProducerScopeDefinition({
    allowedEvents: [{ eventTypeId: eventType2, schemaVersions: [1] }],
    actions: ["events.admit"]
  });

  const channelKind = options.channelKind ?? "machine_producer";
  const principalKind = channelKind === "machine_producer" ? "producer" : "human";

  const producer = {
    id: producerId,
    tenantId,
    projectId,
    principalId,
    principalKind,
    channelKind,
    name: "Billing Ingestor",
    businessNamespace: parseProducerNamespace(
      channelKind === "human_workflow" ? `human.${principalId}` : "billing.core",
      "business_namespace"
    ),
    state: "active",
    currentScopeVersion: 1n,
    authorityEpoch: 1n,
    version: 1n
  };

  const principal = {
    principalId,
    kind: principalKind,
    state: "active",
    authorityEpoch: 1n,
    version: 1n
  };

  const scopeVersion1 = {
    producerId,
    scopeVersion: 1n,
    tenantId,
    projectId,
    scopeDefinition: scope1.definition,
    scopeSha256: scope1.scopeSha256,
    state: "active"
  };
  const scopeVersion2 = {
    producerId,
    scopeVersion: 2n,
    tenantId,
    projectId,
    scopeDefinition: scope2.definition,
    scopeSha256: scope2.scopeSha256,
    state: "active"
  };

  const repo = new InMemoryProducerCredentialRepository();
  repo.seedProducer({
    producer,
    principal,
    scopes: [scopeVersion1]
  });

  return {
    repo,
    tenantId,
    projectId,
    producerId,
    principalId,
    issuerPrincipalId,
    eventType1,
    eventType2,
    producer,
    principal,
    scopeVersion1,
    scopeVersion2
  };
}

async function provisionDeliveredCredential({
  repo,
  installation,
  producerId,
  expectedProducerVersion,
  scopeVersion,
  issuerPrincipalId,
  now,
  lifetimeMs = PRODUCER_CREDENTIAL_MAX_TTL_MS
}) {
  const intent = await issueProducerCredentialIntent({
    installation,
    producerId,
    expectedProducerVersion,
    scopeVersion,
    requestedExpiry: addMilliseconds(now, lifetimeMs),
    custodyDestinationId: "vault.prod.billing",
    allowedCustodyDestinations: ["vault.prod.billing"],
    issuerPrincipalId,
    repo,
    now
  });

  let capturedBearer = null;
  let capturedCredentialId = null;
  const delivered = await deliverProducerCredentialToCustody({
    installation,
    intentId: intent.id,
    expectedIntentVersion: intent.version,
    deliverSecret: (ctx) => {
      capturedBearer = ctx.bearerToken.expose();
      capturedCredentialId = ctx.credentialId;
      return Promise.resolve();
    },
    repo,
    now: addMilliseconds(now, 1_000n)
  });

  assert.ok(capturedBearer !== null && capturedCredentialId !== null);
  return {
    intent: delivered.intent,
    credentialMeta: delivered.credential,
    bearerToken: capturedBearer,
    credentialId: capturedCredentialId
  };
}

test("rq_p1 parser, generator, digest domain separation, and Authorization header extraction enforce strict invariants", () => {
  const generated = generateProducerCredentialMaterial();
  const rawToken = generated.bearerToken.expose();
  assert.match(rawToken, /^rq_p1\.[0-9a-f-]{36}\.[A-Za-z0-9_-]{43}$/);
  assert.equal(generated.selector, `rq_p1.${generated.credentialId}`);

  const parsed = parseProducerBearerTokenStrict(rawToken);
  assert.equal(parsed.credentialId, generated.credentialId);
  assert.equal(parsed.selector, generated.selector);
  assert.equal(parsed.secretBytes.length, 32);

  // Verify length-prefixed SHA256 digest matches independent computation.
  const independent = crypto
    .createHash("sha256")
    .update(
      encodeDomainLengthPrefixed("rq.producer-credential.v1", [
        Buffer.from(generated.credentialId, "utf8"),
        parsed.secretBytes
      ])
    )
    .digest();
  assert.equal(Buffer.compare(generated.secretDigest, independent), 0);
  assert.equal(
    Buffer.compare(computeProducerCredentialDigest(generated.credentialId, parsed.secretBytes), independent),
    0
  );

  // Changing 1 byte in secret yields different digest, and digest alone cannot rebuild rawToken.
  const mutatedSecret = Buffer.from(parsed.secretBytes);
  mutatedSecret[0] ^= 0x01;
  assert.notEqual(
    Buffer.compare(computeProducerCredentialDigest(generated.credentialId, mutatedSecret), independent),
    0
  );
  parsed.destroy();

  // Reject malformed bearer tokens and Authorization headers.
  const validSecretPart = rawToken.split(".")[2];
  for (const badToken of [
    "",
    "not-a-token",
    `rq_p1.${generated.credentialId.toUpperCase()}.${validSecretPart}`,
    `rq_p1.${generated.credentialId}.${validSecretPart}=`,
    `rq_p1.${generated.credentialId}.${Buffer.alloc(31).toString("base64url")}`,
    `rq_p1.${generated.credentialId}.${Buffer.alloc(33).toString("base64url")}`,
    `rq_p2.${generated.credentialId}.${validSecretPart}`,
    `${rawToken}.extra`
  ]) {
    assert.throws(() => parseProducerBearerTokenStrict(badToken), ValidationDomainError);
  }

  assert.equal(extractBearerTokenFromAuthorizationHeader(`Bearer ${rawToken}`), rawToken);
  for (const badAuthHeader of [
    undefined,
    `bearer   ${rawToken}`,
    `Bearer  ${rawToken}`,
    `Basic ${rawToken}`,
    `Bearer ${rawToken}, Bearer ${rawToken}`,
    [`Bearer ${rawToken}`, `Bearer ${rawToken}`],
    `Bearer ${rawToken} extra`
  ]) {
    assert.throws(
      () => extractBearerTokenFromAuthorizationHeader(badAuthHeader),
      AuthenticationDomainError
    );
  }

  // Raw HTTP header pair scanning rejects duplicate Authorization headers.
  assert.equal(
    extractBearerTokenFromRawHeaders(["Host", "api.example", "Authorization", `Bearer ${rawToken}`]),
    rawToken
  );
  assert.throws(
    () =>
      extractBearerTokenFromRawHeaders([
        "Authorization",
        `Bearer ${rawToken}`,
        "authorization",
        `Bearer ${rawToken}`
      ]),
    AuthenticationDomainError
  );
});

test("channel and human_workflow namespace separation strictly isolate machine credentials", async () => {
  const t0 = parseUtcTimestamp("2026-11-18T08:00:00Z").instant;
  const installation = makeInstallation();
  const humanSeed = makeSeed({ channelKind: "human_workflow" });

  assert.throws(() => assertMachineProducerChannel(humanSeed.producer), AuthorizationDomainError);
  await assert.rejects(
    () =>
      issueProducerCredentialIntent({
        installation,
        producerId: humanSeed.producerId,
        expectedProducerVersion: humanSeed.producer.version,
        scopeVersion: 1n,
        requestedExpiry: addMilliseconds(t0, PRODUCER_CREDENTIAL_MAX_TTL_MS),
        custodyDestinationId: "vault.prod.billing",
        allowedCustodyDestinations: ["vault.prod.billing"],
        issuerPrincipalId: humanSeed.issuerPrincipalId,
        repo: humanSeed.repo,
        now: t0
      }),
    AuthorizationDomainError
  );

  // Valid human.<uuid> namespace passes only for matching human principal ID.
  assert.equal(
    assertHumanWorkflowNamespace(humanSeed.principalId, `human.${humanSeed.principalId}`),
    `human.${humanSeed.principalId}`
  );
  const otherHuman = parsePrincipalId(crypto.randomUUID(), "other_human");
  for (const badNs of [`human.${otherHuman}`, "billing.core", `human.${humanSeed.principalId.toUpperCase()}`]) {
    assert.throws(
      () => assertHumanWorkflowNamespace(humanSeed.principalId, badNs),
      AuthorizationDomainError
    );
  }
});

test("custody intent, possession activation, idempotent retry, scope checks, and immediate scope-pointer cutover denial", async () => {
  const t0 = parseUtcTimestamp("2026-11-18T08:00:00Z").instant;
  const installation = makeInstallation();
  const seed = makeSeed();

  // Rejects >30-day requested lifetime and disallowed custody destination.
  await assert.rejects(
    () =>
      issueProducerCredentialIntent({
        installation,
        producerId: seed.producerId,
        expectedProducerVersion: 1n,
        scopeVersion: 1n,
        requestedExpiry: addMilliseconds(t0, PRODUCER_CREDENTIAL_MAX_TTL_MS + 1_000n),
        custodyDestinationId: "vault.prod.billing",
        allowedCustodyDestinations: ["vault.prod.billing"],
        issuerPrincipalId: seed.issuerPrincipalId,
        repo: seed.repo,
        now: t0
      }),
    ValidationDomainError
  );
  await assert.rejects(
    () =>
      issueProducerCredentialIntent({
        installation,
        producerId: seed.producerId,
        expectedProducerVersion: 1n,
        scopeVersion: 1n,
        requestedExpiry: addMilliseconds(t0, PRODUCER_CREDENTIAL_MAX_TTL_MS),
        custodyDestinationId: "untrusted.dest",
        allowedCustodyDestinations: ["vault.prod.billing"],
        issuerPrincipalId: seed.issuerPrincipalId,
        repo: seed.repo,
        now: t0
      }),
    AuthorizationDomainError
  );

  const provisioned = await provisionDeliveredCredential({
    repo: seed.repo,
    installation,
    producerId: seed.producerId,
    expectedProducerVersion: 1n,
    scopeVersion: 1n,
    issuerPrincipalId: seed.issuerPrincipalId,
    now: t0
  });
  assert.equal(provisioned.credentialMeta.state, "pending_activation");

  // Pending-activation credential cannot be used for ordinary traffic.
  await assert.rejects(
    () =>
      authenticateProducerCredential({
        installation,
        bearerToken: provisioned.bearerToken,
        repo: seed.repo,
        now: addMilliseconds(t0, 2_000n)
      }),
    AuthenticationDomainError
  );

  // Wrong secret cannot activate credential.
  const wrongMaterial = generateProducerCredentialMaterial(
    parseProducerCredentialId(provisioned.credentialId, "cred_id")
  );
  await assert.rejects(
    () =>
      activateProducerCredentialByPossession({
        installation,
        intentId: provisioned.intent.id,
        expectedIntentVersion: provisioned.intent.version,
        bearerToken: wrongMaterial.bearerToken.expose(),
        repo: seed.repo,
        now: addMilliseconds(t0, 3_000n)
      }),
    AuthenticationDomainError
  );

  // Real token activates credential cleanly.
  const activated1 = await activateProducerCredentialByPossession({
    installation,
    intentId: provisioned.intent.id,
    expectedIntentVersion: provisioned.intent.version,
    bearerToken: provisioned.bearerToken,
    repo: seed.repo,
    now: addMilliseconds(t0, 4_000n)
  });
  assert.equal(activated1.activated, true);
  assert.equal(activated1.matched_existing, false);
  assert.equal(activated1.scope_active_for_admission, true);
  assert.equal(activated1.credential.state, "active");

  // Idempotent retry with exact prior intentVersion & matching bearer token recovers cleanly.
  const retrySameToken = await activateProducerCredentialByPossession({
    installation,
    intentId: provisioned.intent.id,
    expectedIntentVersion: provisioned.intent.version,
    bearerToken: provisioned.bearerToken,
    repo: seed.repo,
    now: addMilliseconds(t0, 5_000n)
  });
  assert.equal(retrySameToken.activated, true);
  assert.equal(retrySameToken.matched_existing, true);

  // Retry after completion with wrong token rejects.
  await assert.rejects(
    () =>
      activateProducerCredentialByPossession({
        installation,
        intentId: provisioned.intent.id,
        expectedIntentVersion: provisioned.intent.version,
        bearerToken: wrongMaterial.bearerToken.expose(),
        repo: seed.repo,
        now: addMilliseconds(t0, 5_000n)
      }),
    AuthenticationDomainError
  );

  // Ordinary authentication passes inside granted scope & fails outside granted action/event/version.
  const authed = await authenticateProducerCredential({
    installation,
    bearerToken: provisioned.bearerToken,
    repo: seed.repo,
    now: addMilliseconds(t0, 6_000n),
    requiredAction: "events.admit",
    requiredEvent: { eventTypeId: seed.eventType1, schemaVersion: 2 }
  });
  assert.equal(authed.producer.id, seed.producerId);

  await assert.rejects(
    () =>
      authenticateProducerCredential({
        installation,
        bearerToken: provisioned.bearerToken,
        repo: seed.repo,
        now: addMilliseconds(t0, 6_000n),
        requiredAction: "deliveries.read_own"
      }),
    AuthorizationDomainError
  );
  await assert.rejects(
    () =>
      authenticateProducerCredential({
        installation,
        bearerToken: provisioned.bearerToken,
        repo: seed.repo,
        now: addMilliseconds(t0, 6_000n),
        requiredAction: "events.admit",
        requiredEvent: { eventTypeId: seed.eventType1, schemaVersion: 3 }
      }),
    AuthorizationDomainError
  );
  await assert.rejects(
    () =>
      authenticateProducerCredential({
        installation,
        bearerToken: provisioned.bearerToken,
        repo: seed.repo,
        now: addMilliseconds(t0, 6_000n),
        requiredAction: "events.admit",
        requiredEvent: { eventTypeId: seed.eventType2, schemaVersion: 1 }
      }),
    AuthorizationDomainError
  );

  // Immediate scope-pointer cutover denial when producer advances currentScopeVersion to 2n.
  seed.repo.putScopeVersion(seed.scopeVersion2);
  seed.repo.updateProducer({
    ...seed.producer,
    currentScopeVersion: 2n,
    version: 2n
  });
  await assert.rejects(
    () =>
      authenticateProducerCredential({
        installation,
        bearerToken: provisioned.bearerToken,
        repo: seed.repo,
        now: addMilliseconds(t0, 7_000n),
        requiredAction: "events.admit"
      }),
    (err) => err instanceof AuthorizationDomainError && err.code === "PUBLICATION_CONTEXT_CHANGED"
  );

  // Expired intent rejects after 5 minutes.
  const expiredIntent = await issueProducerCredentialIntent({
    installation,
    producerId: seed.producerId,
    expectedProducerVersion: 2n,
    scopeVersion: 2n,
    requestedExpiry: addMilliseconds(t0, PRODUCER_CREDENTIAL_MAX_TTL_MS),
    custodyDestinationId: "vault.prod.billing",
    allowedCustodyDestinations: ["vault.prod.billing"],
    issuerPrincipalId: seed.issuerPrincipalId,
    repo: seed.repo,
    now: t0
  });
  await assert.rejects(
    () =>
      deliverProducerCredentialToCustody({
        installation,
        intentId: parseProducerCredentialIntentId(expiredIntent.id, "intent_id"),
        expectedIntentVersion: expiredIntent.version,
        deliverSecret: () => Promise.resolve(),
        repo: seed.repo,
        now: addMilliseconds(t0, PRODUCER_CREDENTIAL_INTENT_TTL_MS + 1_000n)
      }),
    ExpiredDomainError
  );
});

test("same-scope credential rotation enforces <=15m overlap window, allows both during overlap, and denies old credential past overlap", async () => {
  const t0 = parseUtcTimestamp("2026-11-18T08:00:00Z").instant;
  const installation = makeInstallation();
  const seed = makeSeed();

  const p1 = await provisionDeliveredCredential({
    repo: seed.repo,
    installation,
    producerId: seed.producerId,
    expectedProducerVersion: 1n,
    scopeVersion: 1n,
    issuerPrincipalId: seed.issuerPrincipalId,
    now: t0
  });
  const act1 = await activateProducerCredentialByPossession({
    installation,
    intentId: p1.intent.id,
    expectedIntentVersion: p1.intent.version,
    bearerToken: p1.bearerToken,
    repo: seed.repo,
    now: addMilliseconds(t0, 2_000n)
  });

  const p2 = await provisionDeliveredCredential({
    repo: seed.repo,
    installation,
    producerId: seed.producerId,
    expectedProducerVersion: 1n,
    scopeVersion: 1n,
    issuerPrincipalId: seed.issuerPrincipalId,
    now: addMilliseconds(t0, 3_000n)
  });
  const act2 = await activateProducerCredentialByPossession({
    installation,
    intentId: p2.intent.id,
    expectedIntentVersion: p2.intent.version,
    bearerToken: p2.bearerToken,
    repo: seed.repo,
    now: addMilliseconds(t0, 4_000n)
  });

  const cred1Before = await seed.repo.findCredentialById(p1.credentialId);
  const cred2Before = await seed.repo.findCredentialById(p2.credentialId);
  assert.ok(cred1Before !== null && cred2Before !== null);

  // Reject overlap > 15 minutes.
  await assert.rejects(
    () =>
      rotateProducerCredentialWithOverlap({
        installation,
        producerId: seed.producerId,
        expectedProducerVersion: 1n,
        oldCredentialId: p1.credentialId,
        expectedOldCredentialVersion: cred1Before.version,
        newCredentialId: p2.credentialId,
        expectedNewCredentialVersion: cred2Before.version,
        overlapDurationMs: PRODUCER_CREDENTIAL_MAX_OVERLAP_MS + 1n,
        repo: seed.repo,
        now: addMilliseconds(t0, 5_000n)
      }),
    ValidationDomainError
  );

  // Different-scope rotation is forbidden.
  seed.repo.putScopeVersion(seed.scopeVersion2);
  const pOtherScope = await provisionDeliveredCredential({
    repo: seed.repo,
    installation,
    producerId: seed.producerId,
    expectedProducerVersion: 1n,
    scopeVersion: 2n,
    issuerPrincipalId: seed.issuerPrincipalId,
    now: addMilliseconds(t0, 5_000n)
  });
  await activateProducerCredentialByPossession({
    installation,
    intentId: pOtherScope.intent.id,
    expectedIntentVersion: pOtherScope.intent.version,
    bearerToken: pOtherScope.bearerToken,
    repo: seed.repo,
    now: addMilliseconds(t0, 6_000n)
  });
  const credOther = await seed.repo.findCredentialById(pOtherScope.credentialId);
  assert.ok(credOther !== null);
  await assert.rejects(
    () =>
      rotateProducerCredentialWithOverlap({
        installation,
        producerId: seed.producerId,
        expectedProducerVersion: 1n,
        oldCredentialId: p1.credentialId,
        expectedOldCredentialVersion: cred1Before.version,
        newCredentialId: credOther.id,
        expectedNewCredentialVersion: credOther.version,
        overlapDurationMs: 60_000n,
        repo: seed.repo,
        now: addMilliseconds(t0, 7_000n)
      }),
    AuthorizationDomainError
  );

  // Rotate with exact 15m overlap window.
  const rotateAt = addMilliseconds(t0, 10_000n);
  const rotated = await rotateProducerCredentialWithOverlap({
    installation,
    producerId: seed.producerId,
    expectedProducerVersion: 1n,
    oldCredentialId: p1.credentialId,
    expectedOldCredentialVersion: cred1Before.version,
    newCredentialId: p2.credentialId,
    expectedNewCredentialVersion: cred2Before.version,
    overlapDurationMs: PRODUCER_CREDENTIAL_MAX_OVERLAP_MS,
    repo: seed.repo,
    now: rotateAt
  });
  assert.equal(rotated.old_credential.state, "overlap");
  assert.equal(rotated.new_credential.state, "active");

  // During overlap, both old and new tokens authenticate cleanly.
  const duringOverlap = addMilliseconds(rotateAt, 300_000n);
  const authOldDuring = await authenticateProducerCredential({
    installation,
    bearerToken: p1.bearerToken,
    repo: seed.repo,
    now: duringOverlap
  });
  const authNewDuring = await authenticateProducerCredential({
    installation,
    bearerToken: p2.bearerToken,
    repo: seed.repo,
    now: duringOverlap
  });
  assert.equal(authOldDuring.credential.credential_id, act1.credential.credential_id);
  assert.equal(authNewDuring.credential.credential_id, act2.credential.credential_id);

  // After overlap window expires, old token fails while new token remains valid.
  const afterOverlap = addMilliseconds(rotateAt, PRODUCER_CREDENTIAL_MAX_OVERLAP_MS + 1_000n);
  await assert.rejects(
    () =>
      authenticateProducerCredential({
        installation,
        bearerToken: p1.bearerToken,
        repo: seed.repo,
        now: afterOverlap
      }),
    ExpiredDomainError
  );
  const authNewAfter = await authenticateProducerCredential({
    installation,
    bearerToken: p2.bearerToken,
    repo: seed.repo,
    now: afterOverlap
  });
  assert.equal(authNewAfter.credential.credential_id, act2.credential.credential_id);
});

test("idempotent possession activation retry still enforces installation mode, control epoch, producer/principal state, and authority epoch", async () => {
  const t0 = parseUtcTimestamp("2026-11-18T08:00:00Z").instant;
  const installation = makeInstallation();
  const seed = makeSeed();

  const provisioned = await provisionDeliveredCredential({
    repo: seed.repo,
    installation,
    producerId: seed.producerId,
    expectedProducerVersion: 1n,
    scopeVersion: 1n,
    issuerPrincipalId: seed.issuerPrincipalId,
    now: t0
  });

  const activated = await activateProducerCredentialByPossession({
    installation,
    intentId: provisioned.intent.id,
    expectedIntentVersion: provisioned.intent.version,
    bearerToken: provisioned.bearerToken,
    repo: seed.repo,
    now: addMilliseconds(t0, 2_000n)
  });
  assert.equal(activated.matched_existing, false);

  // Valid retry succeeds even after initial 5-minute intent expiry.
  const retryAfterIntentExpiry = await activateProducerCredentialByPossession({
    installation,
    intentId: provisioned.intent.id,
    expectedIntentVersion: provisioned.intent.version,
    bearerToken: provisioned.bearerToken,
    repo: seed.repo,
    now: addMilliseconds(t0, PRODUCER_CREDENTIAL_INTENT_TTL_MS + 60_000n)
  });
  assert.equal(retryAfterIntentExpiry.matched_existing, true);

  // Retry rejects during recovery_quarantine.
  await assert.rejects(
    () =>
      activateProducerCredentialByPossession({
        installation: makeInstallation({ mode: "recovery_quarantine", controlEpoch: installation.controlEpoch }),
        intentId: provisioned.intent.id,
        expectedIntentVersion: provisioned.intent.version,
        bearerToken: provisioned.bearerToken,
        repo: seed.repo,
        now: addMilliseconds(t0, 3_000n)
      }),
    AuthenticationDomainError
  );

  // Retry rejects when installation control_epoch rotated.
  await assert.rejects(
    () =>
      activateProducerCredentialByPossession({
        installation: makeInstallation({ controlEpoch: parseControlEpoch(crypto.randomUUID()) }),
        intentId: provisioned.intent.id,
        expectedIntentVersion: provisioned.intent.version,
        bearerToken: provisioned.bearerToken,
        repo: seed.repo,
        now: addMilliseconds(t0, 3_000n)
      }),
    AuthenticationDomainError
  );

  // Retry rejects when producer is suspended or retired.
  seed.repo.updateProducer({ ...seed.producer, state: "suspended", version: 2n });
  await assert.rejects(
    () =>
      activateProducerCredentialByPossession({
        installation,
        intentId: provisioned.intent.id,
        expectedIntentVersion: provisioned.intent.version,
        bearerToken: provisioned.bearerToken,
        repo: seed.repo,
        now: addMilliseconds(t0, 3_000n)
      }),
    AuthorizationDomainError
  );

  // Restore producer, suspend principal -> retry rejects.
  seed.repo.updateProducer({ ...seed.producer, state: "active", version: 3n });
  seed.repo.updatePrincipal({ ...seed.principal, state: "suspended", version: 2n });
  await assert.rejects(
    () =>
      activateProducerCredentialByPossession({
        installation,
        intentId: provisioned.intent.id,
        expectedIntentVersion: provisioned.intent.version,
        bearerToken: provisioned.bearerToken,
        repo: seed.repo,
        now: addMilliseconds(t0, 3_000n)
      }),
    AuthorizationDomainError
  );

  // Restore principal active with bumped authorityEpoch -> retry rejects.
  seed.repo.updateProducer({ ...seed.producer, state: "active", authorityEpoch: 2n, version: 4n });
  seed.repo.updatePrincipal({ ...seed.principal, state: "active", authorityEpoch: 2n, version: 3n });
  await assert.rejects(
    () =>
      activateProducerCredentialByPossession({
        installation,
        intentId: provisioned.intent.id,
        expectedIntentVersion: provisioned.intent.version,
        bearerToken: provisioned.bearerToken,
        repo: seed.repo,
        now: addMilliseconds(t0, 3_000n)
      }),
    AuthenticationDomainError
  );
});
