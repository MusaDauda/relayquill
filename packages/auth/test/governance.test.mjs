import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import {
  AuthorizationDomainError,
  ConflictDomainError,
  NotFoundDomainError,
  ValidationDomainError,
  addMilliseconds,
  parseControlEpoch,
  parseDataGrantId,
  parsePlatformRoleAssignmentId,
  parsePrincipalId,
  parseProducerNamespace,
  parseProjectId,
  parseProjectMembershipId,
  parseSha256Hex,
  parseTenantId,
  parseTenantMembershipId,
  parseUtcTimestamp
} from "@relayquill/domain";
import {
  InMemoryGovernanceRepository,
  assertDistinctGovernanceReviewer,
  assertExactGovernanceRoleString,
  assertLastPlatformAdminPreserved,
  assertLastProjectAdminPreserved,
  assertLastTenantAdminPreserved,
  authorizeHumanAction,
  authorizeProposalAdmission,
  authorizeProposalReview,
  grantProjectDataAccess,
  hasActiveProjectDataGrant
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

function sha256HexOf(text) {
  return parseSha256Hex(crypto.createHash("sha256").update(text, "utf8").digest("hex"), "sha256");
}

function makePrincipal(principalId, overrides = {}) {
  return {
    principalId,
    kind: "human",
    state: "active",
    authorityEpoch: 1n,
    version: 1n,
    ...overrides
  };
}

test("assertExactGovernanceRoleString accepts canonical roles and rejects unknown strings", () => {
  assert.equal(assertExactGovernanceRoleString("platform", "platform_admin"), "platform_admin");
  assert.equal(assertExactGovernanceRoleString("platform", "platform_auditor"), "platform_auditor");
  assert.equal(assertExactGovernanceRoleString("tenant", "tenant_admin"), "tenant_admin");
  for (const role of ["project_admin", "integrator", "operator", "publisher", "observer"]) {
    assert.equal(assertExactGovernanceRoleString("project", role), role);
  }
  assert.throws(
    () => assertExactGovernanceRoleString("project", "super_admin"),
    ValidationDomainError
  );
  assert.throws(
    () => assertExactGovernanceRoleString("platform", "tenant_admin"),
    ValidationDomainError
  );
});

test("RBAC matrix, publisher own_namespace isolation, step-up gates, and non-disclosing 404 out-of-scope checks", async () => {
  const t0 = parseUtcTimestamp("2026-11-18T08:00:00Z").instant;
  const installation = makeInstallation();
  const repo = new InMemoryGovernanceRepository();

  const tenantA = parseTenantId(crypto.randomUUID(), "tenant_a");
  const tenantB = parseTenantId(crypto.randomUUID(), "tenant_b");
  const projectA1 = parseProjectId(crypto.randomUUID(), "project_a1");
  const projectA2 = parseProjectId(crypto.randomUUID(), "project_a2");

  const pPlatformAdmin = parsePrincipalId(crypto.randomUUID(), "platform_admin");
  const pPlatformAuditor = parsePrincipalId(crypto.randomUUID(), "platform_auditor");
  const pTenantAdminA = parsePrincipalId(crypto.randomUUID(), "tenant_admin_a");
  const pProjectAdmin = parsePrincipalId(crypto.randomUUID(), "project_admin");
  const pIntegrator = parsePrincipalId(crypto.randomUUID(), "integrator");
  const pOperator = parsePrincipalId(crypto.randomUUID(), "operator");
  const pPublisher = parsePrincipalId(crypto.randomUUID(), "publisher");
  const pObserver = parsePrincipalId(crypto.randomUUID(), "observer");

  for (const id of [
    pPlatformAdmin,
    pPlatformAuditor,
    pTenantAdminA,
    pProjectAdmin,
    pIntegrator,
    pOperator,
    pPublisher,
    pObserver
  ]) {
    repo.putPrincipal(makePrincipal(id));
  }

  repo.putPlatformRole({
    id: parsePlatformRoleAssignmentId(crypto.randomUUID(), "assign_admin"),
    principalId: pPlatformAdmin,
    role: "platform_admin",
    state: "active",
    governanceVersion: 1n,
    createdAt: t0,
    revokedAt: null,
    version: 1n
  });
  repo.putPlatformRole({
    id: parsePlatformRoleAssignmentId(crypto.randomUUID(), "assign_auditor"),
    principalId: pPlatformAuditor,
    role: "platform_auditor",
    state: "active",
    governanceVersion: 1n,
    createdAt: t0,
    revokedAt: null,
    version: 1n
  });

  repo.putTenantMembership({
    id: parseTenantMembershipId(crypto.randomUUID(), "tm_a"),
    tenantId: tenantA,
    principalId: pTenantAdminA,
    role: "tenant_admin",
    state: "active",
    authorityVersion: 1n,
    createdAt: t0,
    updatedAt: t0,
    version: 1n
  });

  const projectRolesToSeed = [
    [pProjectAdmin, "project_admin"],
    [pIntegrator, "integrator"],
    [pOperator, "operator"],
    [pPublisher, "publisher"],
    [pObserver, "observer"]
  ];
  for (const [principalId, role] of projectRolesToSeed) {
    repo.putProjectMembership({
      id: parseProjectMembershipId(crypto.randomUUID(), "pm"),
      tenantId: tenantA,
      projectId: projectA1,
      principalId,
      role,
      state: "active",
      authorityVersion: 1n,
      createdAt: t0,
      updatedAt: t0,
      version: 1n
    });
  }

  // Platform admin requires step-up for mutations and cannot silently enter tenant/project scopes (non-disclosing 404).
  await assert.rejects(
    () =>
      authorizeHumanAction({
        installation,
        principalId: pPlatformAdmin,
        action: "tenants.create",
        stepUpVerified: false,
        repo,
        now: t0
      }),
    AuthorizationDomainError
  );
  const createTenantDecision = await authorizeHumanAction({
    installation,
    principalId: pPlatformAdmin,
    action: "tenants.create",
    stepUpVerified: true,
    repo,
    now: t0
  });
  assert.equal(createTenantDecision.matchedScope, "platform");

  await assert.rejects(
    () =>
      authorizeHumanAction({
        installation,
        principalId: pPlatformAdmin,
        action: "events.read_safe",
        tenantId: tenantA,
        projectId: projectA1,
        repo,
        now: t0
      }),
    NotFoundDomainError
  );

  // Platform auditor can read platform audit but cannot mutate tenants.
  const auditDecision = await authorizeHumanAction({
    installation,
    principalId: pPlatformAuditor,
    action: "platform.audit.read",
    repo,
    now: t0
  });
  assert.equal(auditDecision.matchedPlatformRoles[0], "platform_auditor");
  await assert.rejects(
    () =>
      authorizeHumanAction({
        installation,
        principalId: pPlatformAuditor,
        action: "tenants.suspend",
        stepUpVerified: true,
        repo,
        now: t0
      }),
    AuthorizationDomainError
  );

  // Tenant admin works in tenantA, gets non-disclosing 404 in tenantB.
  const pauseDecision = await authorizeHumanAction({
    installation,
    principalId: pTenantAdminA,
    action: "projects.pause_admission",
    tenantId: tenantA,
    projectId: projectA1,
    stepUpVerified: true,
    repo,
    now: t0
  });
  assert.equal(pauseDecision.matchedScope, "tenant");
  await assert.rejects(
    () =>
      authorizeHumanAction({
        installation,
        principalId: pTenantAdminA,
        action: "projects.create",
        tenantId: tenantB,
        stepUpVerified: true,
        repo,
        now: t0
      }),
    NotFoundDomainError
  );

  // Out-of-scope projectA2 or resourceExistsInTargetScope === false both return NotFoundDomainError (404).
  await assert.rejects(
    () =>
      authorizeHumanAction({
        installation,
        principalId: pProjectAdmin,
        action: "endpoints.activate",
        tenantId: tenantA,
        projectId: projectA2,
        stepUpVerified: true,
        repo,
        now: t0
      }),
    NotFoundDomainError
  );
  await assert.rejects(
    () =>
      authorizeHumanAction({
        installation,
        principalId: pProjectAdmin,
        action: "endpoints.activate",
        tenantId: tenantA,
        projectId: projectA1,
        resourceExistsInTargetScope: false,
        stepUpVerified: true,
        repo,
        now: t0
      }),
    NotFoundDomainError
  );

  // Role separation across integrator, operator, observer, publisher, project_admin.
  await authorizeHumanAction({
    installation,
    principalId: pObserver,
    action: "events.read_safe",
    tenantId: tenantA,
    projectId: projectA1,
    repo,
    now: t0
  });
  await assert.rejects(
    () =>
      authorizeHumanAction({
        installation,
        principalId: pObserver,
        action: "event_schemas.draft",
        tenantId: tenantA,
        projectId: projectA1,
        repo,
        now: t0
      }),
    AuthorizationDomainError
  );

  await authorizeHumanAction({
    installation,
    principalId: pIntegrator,
    action: "endpoints.create_version",
    tenantId: tenantA,
    projectId: projectA1,
    repo,
    now: t0
  });
  await assert.rejects(
    () =>
      authorizeHumanAction({
        installation,
        principalId: pIntegrator,
        action: "endpoints.activate",
        tenantId: tenantA,
        projectId: projectA1,
        stepUpVerified: true,
        repo,
        now: t0
      }),
    AuthorizationDomainError
  );

  await authorizeHumanAction({
    installation,
    principalId: pOperator,
    action: "endpoints.pause",
    tenantId: tenantA,
    projectId: projectA1,
    repo,
    now: t0
  });
  await assert.rejects(
    () =>
      authorizeHumanAction({
        installation,
        principalId: pOperator,
        action: "replay_proposals.review",
        tenantId: tenantA,
        projectId: projectA1,
        stepUpVerified: true,
        repo,
        now: t0
      }),
    AuthorizationDomainError
  );

  // Publisher can only touch human.<publisherPrincipalId>.
  const ownNs = parseProducerNamespace(`human.${pPublisher}`, "own_ns");
  const otherNs = parseProducerNamespace("billing.core", "other_ns");
  await authorizeHumanAction({
    installation,
    principalId: pPublisher,
    action: "events.admit",
    tenantId: tenantA,
    projectId: projectA1,
    resourceProducerNamespace: ownNs,
    repo,
    now: t0
  });
  await assert.rejects(
    () =>
      authorizeHumanAction({
        installation,
        principalId: pPublisher,
        action: "events.admit",
        tenantId: tenantA,
        projectId: projectA1,
        resourceProducerNamespace: otherNs,
        repo,
        now: t0
      }),
    NotFoundDomainError
  );
  await assert.rejects(
    () =>
      authorizeHumanAction({
        installation,
        principalId: pPublisher,
        action: "endpoints.read_safe",
        tenantId: tenantA,
        projectId: projectA1,
        repo,
        now: t0
      }),
    AuthorizationDomainError
  );
});

test("explicit human_data_grants gate sensitive payload/request/receipt reads and enforce publisher own_namespace & expiry", async () => {
  const t0 = parseUtcTimestamp("2026-11-18T08:00:00Z").instant;
  const installation = makeInstallation();
  const repo = new InMemoryGovernanceRepository();
  const tenantId = parseTenantId(crypto.randomUUID(), "tenant");
  const projectId = parseProjectId(crypto.randomUUID(), "project");

  const pAdmin = parsePrincipalId(crypto.randomUUID(), "admin");
  const pOperator = parsePrincipalId(crypto.randomUUID(), "operator");
  const pPublisher = parsePrincipalId(crypto.randomUUID(), "publisher");
  for (const id of [pAdmin, pOperator, pPublisher]) {
    repo.putPrincipal(makePrincipal(id));
  }

  const adminMembership = {
    id: parseProjectMembershipId(crypto.randomUUID(), "pm_admin"),
    tenantId,
    projectId,
    principalId: pAdmin,
    role: "project_admin",
    state: "active",
    authorityVersion: 1n,
    createdAt: t0,
    updatedAt: t0,
    version: 1n
  };
  const opMembership = {
    id: parseProjectMembershipId(crypto.randomUUID(), "pm_op"),
    tenantId,
    projectId,
    principalId: pOperator,
    role: "operator",
    state: "active",
    authorityVersion: 1n,
    createdAt: t0,
    updatedAt: t0,
    version: 1n
  };
  const pubMembership = {
    id: parseProjectMembershipId(crypto.randomUUID(), "pm_pub"),
    tenantId,
    projectId,
    principalId: pPublisher,
    role: "publisher",
    state: "active",
    authorityVersion: 1n,
    createdAt: t0,
    updatedAt: t0,
    version: 1n
  };
  repo.putProjectMembership(adminMembership);
  repo.putProjectMembership(opMembership);
  repo.putProjectMembership(pubMembership);

  // Without explicit grant, even project_admin and operator are denied sensitive reads.
  for (const sensitiveAction of ["events.content.read", "deliveries.request.read", "receiver_receipts.read"]) {
    for (const actor of [pAdmin, pOperator]) {
      await assert.rejects(
        () =>
          authorizeHumanAction({
            installation,
            principalId: actor,
            action: sensitiveAction,
            tenantId,
            projectId,
            repo,
            now: t0
          }),
        AuthorizationDomainError
      );
    }
  }

  // Publisher cannot be granted approved_project.
  await assert.rejects(
    () =>
      grantProjectDataAccess({
        installation,
        actorPrincipalId: pAdmin,
        tenantId,
        projectId,
        targetMembership: pubMembership,
        action: "events.content.read",
        projection: "approved_project",
        producerNamespace: null,
        expiresAt: addMilliseconds(t0, 60_000n),
        stepUpVerified: true,
        repo,
        now: t0
      }),
    AuthorizationDomainError
  );

  // Publisher own_namespace grant allows reading events in own namespace and denies foreign namespace.
  await grantProjectDataAccess({
    installation,
    actorPrincipalId: pAdmin,
    tenantId,
    projectId,
    targetMembership: pubMembership,
    action: "events.content.read",
    projection: "own_namespace",
    producerNamespace: `human.${pPublisher}`,
    expiresAt: addMilliseconds(t0, 60_000n),
    stepUpVerified: true,
    repo,
    now: t0
  });
  await authorizeHumanAction({
    installation,
    principalId: pPublisher,
    action: "events.content.read",
    tenantId,
    projectId,
    resourceProducerNamespace: `human.${pPublisher}`,
    repo,
    now: addMilliseconds(t0, 5_000n)
  });
  await assert.rejects(
    () =>
      authorizeHumanAction({
        installation,
        principalId: pPublisher,
        action: "events.content.read",
        tenantId,
        projectId,
        resourceProducerNamespace: "billing.core",
        repo,
        now: addMilliseconds(t0, 5_000n)
      }),
    NotFoundDomainError
  );

  // Grant deliveries.request.read & receiver_receipts.read to operator with expiry, verify before & after expiry.
  const grantDel = await grantProjectDataAccess({
    installation,
    actorPrincipalId: pAdmin,
    tenantId,
    projectId,
    targetMembership: opMembership,
    action: "deliveries.request.read",
    projection: "approved_project",
    producerNamespace: null,
    expiresAt: addMilliseconds(t0, 120_000n),
    stepUpVerified: true,
    repo,
    now: t0
  });
  const grantRec = await grantProjectDataAccess({
    installation,
    actorPrincipalId: pAdmin,
    tenantId,
    projectId,
    targetMembership: opMembership,
    action: "receiver_receipts.read",
    projection: "approved_project",
    producerNamespace: null,
    expiresAt: addMilliseconds(t0, 120_000n),
    stepUpVerified: true,
    repo,
    now: t0
  });

  const decDel = await authorizeHumanAction({
    installation,
    principalId: pOperator,
    action: "deliveries.request.read",
    tenantId,
    projectId,
    repo,
    now: addMilliseconds(t0, 10_000n)
  });
  assert.equal(decDel.matchedDataGrantId, grantDel.id);
  assert.equal(
    await hasActiveProjectDataGrant({
      principalId: pOperator,
      tenantId,
      projectId,
      action: "receiver_receipts.read",
      repo,
      now: addMilliseconds(t0, 10_000n)
    }),
    true
  );

  // Expired grant denies access cleanly.
  assert.equal(
    await hasActiveProjectDataGrant({
      principalId: pOperator,
      tenantId,
      projectId,
      action: "deliveries.request.read",
      repo,
      now: addMilliseconds(t0, 121_000n)
    }),
    false
  );
  await assert.rejects(
    () =>
      authorizeHumanAction({
        installation,
        principalId: pOperator,
        action: "deliveries.request.read",
        tenantId,
        projectId,
        repo,
        now: addMilliseconds(t0, 121_000n)
      }),
    AuthorizationDomainError
  );

  // Revoked grant denies even before expiry.
  await repo.revokeDataGrant({
    grantId: parseDataGrantId(grantRec.id, "grant_rec"),
    expectedVersion: grantRec.version
  });
  assert.equal(
    await hasActiveProjectDataGrant({
      principalId: pOperator,
      tenantId,
      projectId,
      action: "receiver_receipts.read",
      repo,
      now: addMilliseconds(t0, 10_000n)
    }),
    false
  );
});

test("last-admin protection guards platform_admin, tenant_admin, and project_admin against removal", async () => {
  const t0 = parseUtcTimestamp("2026-11-18T08:00:00Z").instant;
  const repo = new InMemoryGovernanceRepository();
  const tenantId = parseTenantId(crypto.randomUUID(), "tenant");
  const projectId = parseProjectId(crypto.randomUUID(), "project");
  const p1 = parsePrincipalId(crypto.randomUUID(), "p1");
  const p2 = parsePrincipalId(crypto.randomUUID(), "p2");
  repo.putPrincipal(makePrincipal(p1));
  repo.putPrincipal(makePrincipal(p2));

  const plat1 = {
    id: parsePlatformRoleAssignmentId(crypto.randomUUID(), "plat1"),
    principalId: p1,
    role: "platform_admin",
    state: "active",
    governanceVersion: 1n,
    createdAt: t0,
    revokedAt: null,
    version: 1n
  };
  repo.putPlatformRole(plat1);

  await assert.rejects(
    () =>
      assertLastPlatformAdminPreserved({
        assignment: plat1,
        nextState: "revoked",
        repo
      }),
    ConflictDomainError
  );
  repo.putPlatformRole({
    ...plat1,
    id: parsePlatformRoleAssignmentId(crypto.randomUUID(), "plat2"),
    principalId: p2
  });
  await assertLastPlatformAdminPreserved({
    assignment: plat1,
    nextState: "revoked",
    repo
  });

  const tm1 = {
    id: parseTenantMembershipId(crypto.randomUUID(), "tm1"),
    tenantId,
    principalId: p1,
    role: "tenant_admin",
    state: "active",
    authorityVersion: 1n,
    createdAt: t0,
    updatedAt: t0,
    version: 1n
  };
  repo.putTenantMembership(tm1);
  await assert.rejects(
    () =>
      assertLastTenantAdminPreserved({
        membership: tm1,
        nextState: "suspended",
        repo
      }),
    ConflictDomainError
  );
  repo.putTenantMembership({
    ...tm1,
    id: parseTenantMembershipId(crypto.randomUUID(), "tm2"),
    principalId: p2
  });
  await assertLastTenantAdminPreserved({
    membership: tm1,
    nextState: "suspended",
    repo
  });

  const pm1 = {
    id: parseProjectMembershipId(crypto.randomUUID(), "pm1"),
    tenantId,
    projectId,
    principalId: p1,
    role: "project_admin",
    state: "active",
    authorityVersion: 1n,
    createdAt: t0,
    updatedAt: t0,
    version: 1n
  };
  repo.putProjectMembership(pm1);
  await assert.rejects(
    () =>
      assertLastProjectAdminPreserved({
        membership: pm1,
        nextRole: "operator",
        nextState: "active",
        repo
      }),
    ConflictDomainError
  );
  await assert.rejects(
    () =>
      assertLastProjectAdminPreserved({
        membership: pm1,
        nextRole: "project_admin",
        nextState: "revoked",
        repo
      }),
    ConflictDomainError
  );
  repo.putProjectMembership({
    ...pm1,
    id: parseProjectMembershipId(crypto.randomUUID(), "pm2"),
    principalId: p2
  });
  await assertLastProjectAdminPreserved({
    membership: pm1,
    nextRole: "operator",
    nextState: "active",
    repo
  });
});

test("two-person proposal review and admission enforce proposer !== reviewer across replay, order-skip, and suppression", async () => {
  const t0 = parseUtcTimestamp("2026-11-18T08:00:00Z").instant;
  const installation = makeInstallation();
  const repo = new InMemoryGovernanceRepository();
  const tenantId = parseTenantId(crypto.randomUUID(), "tenant");
  const projectId = parseProjectId(crypto.randomUUID(), "project");

  const adminProposer = parsePrincipalId(crypto.randomUUID(), "proposer_admin");
  const adminReviewer = parsePrincipalId(crypto.randomUUID(), "reviewer_admin");
  for (const id of [adminProposer, adminReviewer]) {
    repo.putPrincipal(makePrincipal(id));
    repo.putProjectMembership({
      id: parseProjectMembershipId(crypto.randomUUID(), "pm"),
      tenantId,
      projectId,
      principalId: id,
      role: "project_admin",
      state: "active",
      authorityVersion: 1n,
      createdAt: t0,
      updatedAt: t0,
      version: 1n
    });
  }

  assert.throws(
    () =>
      assertDistinctGovernanceReviewer({
        proposerPrincipalId: adminProposer,
        reviewerPrincipalId: adminProposer
      }),
    AuthorizationDomainError
  );

  const pairs = [
    ["replay_proposals.review", "replay_proposals.admit"],
    ["order_skip_proposals.review", "order_skip_proposals.admit"],
    ["suppression_proposals.review", "suppression_proposals.admit"]
  ];

  for (const [reviewAction, admitAction] of pairs) {
    const candidateSha = sha256HexOf(`proposal-${reviewAction}`);
    const proposal = {
      proposalId: crypto.randomUUID(),
      state: "proposed",
      proposerPrincipalId: adminProposer,
      candidateSha256: candidateSha,
      version: 1n,
      expiresAt: addMilliseconds(t0, 900_000n)
    };

    // Self-review by proposer fails even though proposer is project_admin + stepUpVerified.
    await assert.rejects(
      () =>
        authorizeProposalReview({
          installation,
          tenantId,
          projectId,
          action: reviewAction,
          proposal,
          reviewerPrincipalId: adminProposer,
          decision: "approve",
          expectedVersion: 1n,
          expectedCandidateSha256: candidateSha,
          stepUpVerified: true,
          repo,
          now: addMilliseconds(t0, 5_000n)
        }),
      AuthorizationDomainError
    );

    // Second distinct project_admin reviews cleanly.
    const approved = await authorizeProposalReview({
      installation,
      tenantId,
      projectId,
      action: reviewAction,
      proposal,
      reviewerPrincipalId: adminReviewer,
      decision: "approve",
      expectedVersion: 1n,
      expectedCandidateSha256: candidateSha,
      stepUpVerified: true,
      repo,
      now: addMilliseconds(t0, 10_000n)
    });
    assert.equal(approved.state, "approved");

    // Missing or tampered review record is rejected at admission.
    await assert.rejects(
      () =>
        authorizeProposalAdmission({
          installation,
          tenantId,
          projectId,
          action: admitAction,
          proposal: approved,
          review: null,
          admitterPrincipalId: adminReviewer,
          expectedVersion: approved.version,
          expectedCandidateSha256: candidateSha,
          stepUpVerified: true,
          repo,
          now: addMilliseconds(t0, 15_000n)
        }),
      AuthorizationDomainError
    );
    await assert.rejects(
      () =>
        authorizeProposalAdmission({
          installation,
          tenantId,
          projectId,
          action: admitAction,
          proposal: approved,
          review: {
            reviewId: crypto.randomUUID(),
            proposalId: proposal.proposalId,
            proposalVersion: proposal.version,
            candidateSha256: candidateSha,
            reviewerPrincipalId: adminProposer,
            decision: "approve",
            reviewedAt: addMilliseconds(t0, 10_000n)
          },
          admitterPrincipalId: adminReviewer,
          expectedVersion: approved.version,
          expectedCandidateSha256: candidateSha,
          stepUpVerified: true,
          repo,
          now: addMilliseconds(t0, 15_000n)
        }),
      AuthorizationDomainError
    );

    // Valid distinct review enables admission.
    await authorizeProposalAdmission({
      installation,
      tenantId,
      projectId,
      action: admitAction,
      proposal: approved,
      review: {
        reviewId: crypto.randomUUID(),
        proposalId: proposal.proposalId,
        proposalVersion: proposal.version,
        candidateSha256: candidateSha,
        reviewerPrincipalId: adminReviewer,
        decision: "approve",
        reviewedAt: addMilliseconds(t0, 10_000n)
      },
      admitterPrincipalId: adminReviewer,
      expectedVersion: approved.version,
      expectedCandidateSha256: candidateSha,
      stepUpVerified: true,
      repo,
      now: addMilliseconds(t0, 15_000n)
    });
  }
});
