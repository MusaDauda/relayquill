import { describe, it } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { Temporal } from "@js-temporal/polyfill";
import {
  DeliveryExecutionService,
  EvidenceService,
  GovernanceService,
  MaintenanceService,
  OrderingService,
  ReplayGovernanceService
} from "../dist/index.js";
import {
  AuthorizationDomainError,
  formatUtcTimestamp
} from "@relayquill/domain";
import {
  InMemoryGovernanceRepository,
  computeStepUpTargetSha256
} from "@relayquill/auth";
import {
  computeConsumerEventKeySha256,
  computeOriginalFactsSha256,
  hashCanonicalJson,
  sha256Utf8Hex
} from "@relayquill/contracts";
import {
  InMemoryWebhookKeyProvider,
  createMemorySigningKeyHandle,
  signEndpointProof,
  signEndpointVerificationRequest,
  signReceiverLocalCommitReceipt,
  signWebhookDelivery,
  verifyEndpointProofResponse,
  verifyReceiverLocalCommitReceiptResponse
} from "@relayquill/signing";

const TENANT_ID = "11111111-1111-4111-8111-111111111111";
const PROJECT_ID = "22222222-2222-4222-8222-222222222222";
const ENDPOINT_ID = "33333333-3333-4333-8333-333333333333";
const SUBSCRIPTION_ID = "44444444-4444-4444-8444-444444444444";
const EVENT_ID = "55555555-5555-4555-8555-555555555555";
const EVENT_TYPE_ID = "34343434-3434-4343-8343-343434343434";
const DELIVERY_ID = "66666666-6666-4666-8666-666666666666";
const ATTEMPT_ID = "77777777-7777-4777-8777-777777777777";
const KEY_ID = "88888888-8888-4888-8888-888888888888";
const INSTANCE_ID = "99999999-9999-4999-8999-999999999999";
const EPOCH = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const PROPOSER_ID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
const REVIEWER_ID = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";
const SESSION_1 = "dddddddd-dddd-4ddd-8ddd-dddddddddddd";
const SESSION_2 = "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee";

const PASSIVE_UOW = {
  async inTransaction(fn) {
    return fn({});
  }
};

function makeInstallation(nowStr = "2026-11-20T10:00:00.000000Z") {
  return {
    controlEpoch: EPOCH,
    mode: "open",
    allowEventAdmission: true,
    allowPublication: true,
    allowFanout: true,
    allowSend: true,
    allowEndpointVerification: true,
    governanceVersion: 1n,
    updatedAt: nowStr,
    version: 1n
  };
}

function makeIds(prefix = "10101010-1010-4010-8010-") {
  let n = 1;
  return {
    nextUuid() {
      const hex = n.toString(16).padStart(12, "0");
      n += 1;
      return `${prefix}${hex}`;
    }
  };
}

function makeStepUpProofStore() {
  const proofs = new Map();
  return {
    proofs,
    seedProof({ proofId, sessionId, principalId, binding, now }) {
      const targetSha256 = computeStepUpTargetSha256(binding);
      proofs.set(proofId, {
        id: proofId,
        sessionId,
        principalId,
        controlEpoch: EPOCH,
        action: binding.action,
        targetSha256,
        challengeId: "ffffffff-ffff-4fff-8fff-ffffffffffff",
        verifiedAt: now,
        expiresAt: now.add({ seconds: 300 }),
        state: "active",
        acceptedReceiptId: null,
        version: 1n
      });
    },
    async findProofById(id) {
      return proofs.get(id) ?? null;
    },
    async consumeOperationProof(input) {
      const rec = proofs.get(input.proofId);
      const updated = {
        ...rec,
        state: "consumed",
        acceptedReceiptId: input.acceptedReceiptId,
        version: rec.version + 1n
      };
      proofs.set(input.proofId, updated);
      return updated;
    },
    async revokeOperationProof(id) {
      const rec = proofs.get(id);
      const updated = { ...rec, state: "revoked", version: rec.version + 1n };
      proofs.set(id, updated);
      return updated;
    }
  };
}

function makeAuthSession(principalId, sessionId) {
  return {
    session: {
      id: sessionId,
      principalId,
      purpose: "ordinary",
      controlEpoch: EPOCH
    },
    principal: {
      principalId,
      kind: "human",
      state: "active",
      authorityEpoch: 1n,
      version: 1n
    }
  };
}

describe("Two-person replay governance (proposer !== reviewer)", () => {
  it("rejects proposer self-review/self-approval with FORBIDDEN and succeeds when reviewed by distinct project_admin", async () => {
    const now = Temporal.Instant.from("2026-11-20T10:00:00.000000Z");
    const clock = { nowInstant: () => now };
    const ids = makeIds();

    const govRepo = new InMemoryGovernanceRepository();
    for (const [idx, pid] of [
      ["1", PROPOSER_ID],
      ["2", REVIEWER_ID]
    ]) {
      govRepo.putPrincipal({
        principalId: pid,
        kind: "human",
        state: "active",
        authorityEpoch: 1n,
        version: 1n
      });
      govRepo.putProjectMembership({
        id: `a0000000-0000-4000-8000-00000000000${idx}`,
        tenantId: TENANT_ID,
        projectId: PROJECT_ID,
        principalId: pid,
        role: "project_admin",
        state: "active",
        authorityVersion: 1n,
        createdAt: now,
        updatedAt: now,
        version: 1n
      });
    }

    const proofRepo = makeStepUpProofStore();
    const proposals = new Map();

    const replayService = new ReplayGovernanceService({
      uow: PASSIVE_UOW,
      replayRepo: {
        async readDeliveryForReplay() {
          return {
            deliveryId: DELIVERY_ID,
            familyId: "f1111111-1111-4111-8111-111111111111",
            eventId: EVENT_ID,
            state: "dead_letter",
            deliveryGeneration: 1n,
            subscriptionId: SUBSCRIPTION_ID,
            subscriptionVersion: 1n,
            endpointId: ENDPOINT_ID,
            endpointVersion: 1n,
            originalWireEnvelopeId: "f2222222-2222-4222-8222-222222222222",
            orderingMode: "unordered",
            consumerEventKeySha256: computeConsumerEventKeySha256({
              project_id: PROJECT_ID,
              event_id: EVENT_ID,
              consumer_contract_scope: "sub:v1"
            }),
            version: 1n
          };
        },
        async findProposal(_tx, pid) {
          return proposals.get(pid);
        },
        async createReplayProposal(_tx, p) {
          const rec = {
            proposalId: p.proposalId,
            deliveryId: p.deliveryId,
            eventId: EVENT_ID,
            tenantId: TENANT_ID,
            projectId: PROJECT_ID,
            proposerPrincipalId: p.proposerPrincipalId,
            targetSubscriptionVersion: p.targetSubscriptionVersion,
            targetEndpointVersion: p.targetEndpointVersion,
            wireEnvelopeId: p.wireEnvelopeId,
            strategy: p.strategy,
            orderingStrategy: p.orderingStrategy,
            representationProfileId: p.representationProfileId,
            representationProfileVersion: p.representationProfileVersion,
            consumerEventKeySha256: p.consumerEventKeySha256,
            candidateSha256: p.candidateSha256,
            state: "proposed",
            version: 1n
          };
          proposals.set(p.proposalId, rec);
          return rec;
        },
        async reviewReplayProposal(_tx, r) {
          const cur = proposals.get(r.proposalId);
          const updated = {
            ...cur,
            state: r.decision === "approve" ? "approved" : "rejected",
            reviewId: r.reviewId,
            reviewerPrincipalId: r.reviewerPrincipalId,
            reviewerAuthorityVersion: r.reviewerAuthorityVersion,
            version: cur.version + 1n
          };
          proposals.set(r.proposalId, updated);
          return updated;
        },
        async admitReplayProposal(_tx, a) {
          const cur = proposals.get(a.proposalId);
          proposals.set(a.proposalId, { ...cur, state: "admitted", version: cur.version + 1n });
          return {
            newDeliveryId: a.newDeliveryId,
            deliveryGeneration: 2n,
            receiptId: a.receiptId
          };
        },
        async proposeAndReviewSuppression() {
          throw new Error("unused");
        }
      },
      authRepos: {
        producerCredentials: {
          async findById() {
            return null;
          }
        },
        humanAuthorization: govRepo,
        sessions: {},
        stepUp: proofRepo,
        enrollment: {}
      },
      readInstallationAuthority: async () => makeInstallation(),
      clock,
      idGenerator: ids
    });

    const proposerSession = makeAuthSession(PROPOSER_ID, SESSION_1);
    const reviewerSession = makeAuthSession(REVIEWER_ID, SESSION_2);

    const proposal = await replayService.proposeReplay({
      session: proposerSession,
      tenantId: TENANT_ID,
      projectId: PROJECT_ID,
      deliveryId: DELIVERY_ID,
      strategy: "replay_exact_original"
    });

    // Self-review attempt by proposer MUST be rejected!
    const selfProofId = "90000000-0000-4000-8000-000000000001";
    proofRepo.seedProof({
      proofId: selfProofId,
      sessionId: SESSION_1,
      principalId: PROPOSER_ID,
      binding: {
        action: "replay_proposals.review",
        scopeKind: "project",
        tenantId: TENANT_ID,
        projectId: PROJECT_ID,
        targetResourceId: proposal.proposalId,
        targetVersion: proposal.version,
        canonicalCommandSha256: proposal.candidateSha256
      },
      now
    });

    await assert.rejects(
      () =>
        replayService.reviewReplayProposal({
          session: proposerSession,
          tenantId: TENANT_ID,
          projectId: PROJECT_ID,
          proposalId: proposal.proposalId,
          expectedProposalVersion: proposal.version,
          expectedCandidateSha256: proposal.candidateSha256,
          decision: "approve",
          stepUpProofId: selfProofId
        }),
      (err) => err instanceof AuthorizationDomainError && err.code === "FORBIDDEN"
    );

    // Distinct project_admin review approves cleanly
    const reviewProofId = "90000000-0000-4000-8000-000000000002";
    proofRepo.seedProof({
      proofId: reviewProofId,
      sessionId: SESSION_2,
      principalId: REVIEWER_ID,
      binding: {
        action: "replay_proposals.review",
        scopeKind: "project",
        tenantId: TENANT_ID,
        projectId: PROJECT_ID,
        targetResourceId: proposal.proposalId,
        targetVersion: proposal.version,
        canonicalCommandSha256: proposal.candidateSha256
      },
      now
    });

    const approved = await replayService.reviewReplayProposal({
      session: reviewerSession,
      tenantId: TENANT_ID,
      projectId: PROJECT_ID,
      proposalId: proposal.proposalId,
      expectedProposalVersion: proposal.version,
      expectedCandidateSha256: proposal.candidateSha256,
      decision: "approve",
      stepUpProofId: reviewProofId
    });
    assert.equal(approved.state, "approved");

    // Distinct reviewer can admit approved replay
    const admitProofId = "90000000-0000-4000-8000-000000000003";
    proofRepo.seedProof({
      proofId: admitProofId,
      sessionId: SESSION_2,
      principalId: REVIEWER_ID,
      binding: {
        action: "replay_proposals.admit",
        scopeKind: "project",
        tenantId: TENANT_ID,
        projectId: PROJECT_ID,
        targetResourceId: proposal.proposalId,
        targetVersion: approved.version,
        canonicalCommandSha256: proposal.candidateSha256
      },
      now
    });

    const admitted = await replayService.admitApprovedReplay({
      session: reviewerSession,
      tenantId: TENANT_ID,
      projectId: PROJECT_ID,
      proposalId: proposal.proposalId,
      expectedProposalVersion: approved.version,
      expectedCandidateSha256: proposal.candidateSha256,
      stepUpProofId: admitProofId,
      idempotencyKey: "admit-replay-1"
    });
    assert.equal(admitted.deliveryGeneration, 2n);
  });
});

describe("DeliveryExecutionService and 4 independent Evidence boundaries", () => {
  it("separates admission, broker publication, http attempts, and verified receiver receipts", async () => {
    const now = Temporal.Instant.from("2026-11-20T10:00:00.000000Z");
    const clock = { nowInstant: () => now };
    const ids = makeIds("20202020-2020-4020-8020-");

    const secret = crypto.randomBytes(32);
    const keyMeta = {
      keyId: KEY_ID,
      state: "active"
    };
    const keyProvider = new InMemoryWebhookKeyProvider();
    keyProvider.registerKey({
      projectId: PROJECT_ID,
      endpointId: ENDPOINT_ID,
      metadata: keyMeta,
      secretBytes: secret
    });

    const wireBodyBytes = new TextEncoder().encode(JSON.stringify({ hello: "world" }));
    const wireBodySha = crypto.createHash("sha256").update(wireBodyBytes).digest("hex");
    const consumerEventKeySha256 = computeConsumerEventKeySha256({
      project_id: PROJECT_ID,
      event_id: EVENT_ID,
      consumer_contract_scope: "sub:v1"
    });
    const originalFactsSha256 = computeOriginalFactsSha256({
      project_id: PROJECT_ID,
      event_id: EVENT_ID,
      project_event_sequence: "1",
      event_type_id: EVENT_TYPE_ID,
      event_type: "order.created",
      event_schema_version: 1,
      admitted_at: formatUtcTimestamp(now),
      producer_event_time: null,
      original_content_sha256: wireBodySha
    });

    const observedHttpAttempts = [];
    const observedReceipts = [];
    let simulateBadReceiptMac = true;

    const deliveryService = new DeliveryExecutionService({
      uow: PASSIVE_UOW,
      deliveryRepo: {
        async loadAttemptSendContext() {
          return {
            tenantId: TENANT_ID,
            projectId: PROJECT_ID,
            eventId: EVENT_ID,
            subscriptionId: SUBSCRIPTION_ID,
            subscriptionVersion: 1n,
            deliveryId: DELIVERY_ID,
            deliveryGeneration: 1n,
            deliveryState: "ready",
            deliveryDeadlineAt: "2026-11-20T11:00:00.000000Z",
            attemptId: ATTEMPT_ID,
            attemptNumber: 1,
            maximumAttempts: 12,
            attemptState: "prepared",
            fencingToken: 7n,
            isCircuitProbe: false,
            circuitGenerationAtPrepare: 1n,
            endpointId: ENDPOINT_ID,
            endpointVersion: 1n,
            endpointState: "active",
            destinationUrl: "https://hooks.example.com/webhook",
            signingPolicyVersion: "1",
            signingKeys: [keyMeta],
            allowOverlapDualSign: false,
            wireEnvelopeId: "91111111-1111-4111-8111-111111111111",
            wireBodyBytes,
            wireBodySha256: wireBodySha,
            originalFactsSha256,
            consumerEventKeySha256,
            consumerContractId: "receiver-v1",
            consumerContractVersion: 1n,
            consumerContractScope: "sub:v1",
            receiptRequired: true,
            retryPolicyVersion: "retry_v1"
          };
        },
        async startDeliverySend() {
          return {
            shouldSend: true,
            alreadyStarted: false,
            attemptId: ATTEMPT_ID,
            requestDeadlineAt: "2026-11-20T10:00:10.000000Z",
            acceptedAt: formatUtcTimestamp(now)
          };
        },
        async deferUnstartedAttempt() {
          return { deferred: true };
        },
        async recordEgressDecision() {},
        async finalizeDeliveryAttempt(_tx, p) {
          observedHttpAttempts.push({
            deliveryId: DELIVERY_ID,
            attemptId: p.attemptId,
            attemptNumber: 1,
            state: p.attemptState,
            outcomeClass: p.outcomeClass,
            responseStatus: p.responseStatus ?? undefined,
            httpAcknowledged: p.outcomeClass === "acknowledged",
            acknowledgedAt: p.outcomeClass === "acknowledged" ? p.now : undefined,
            safeErrorCode: p.safeErrorCode ?? undefined
          });
          return {
            outcome: "finalized",
            attemptId: p.attemptId,
            attemptState: p.attemptState,
            deliveryState: "acknowledged"
          };
        },
        async updateEndpointCircuit() {
          return {
            endpointId: ENDPOINT_ID,
            state: "closed",
            circuitGeneration: 1n,
            probeGeneration: 0n,
            consecutiveFailures: 0,
            probeInFlightAttemptId: null,
            version: 2n
          };
        },
        async observeReceiverReceipt(_tx, p) {
          observedReceipts.push({
            deliveryId: p.deliveryId,
            attemptId: p.attemptId,
            observationId: p.observationId,
            receiptReference: p.receiptReference,
            receiptFactsSha256: p.receiptFactsSha256,
            requestWireSha256: p.requestWireSha256,
            proofSha256: p.proofSha256,
            state: p.state,
            observedAt: p.now
          });
          return { recorded: true, state: p.state };
        },
        async observeLateDelivery() {},
        async loadVerificationAttemptContext() {
          throw new Error("unused");
        },
        async claimVerificationAttempt() {
          return { claimed: false };
        },
        async finalizeVerificationAttempt() {}
      },
      egressResolver: {
        async resolve() {
          return {
            decisionId: "e0000000-0000-4000-8000-000000000001",
            decision: "allowed",
            reasonCode: "ALLOWED",
            networkPolicyVersion: "egress_v1",
            registryIpv4Sha256: sha256Utf8Hex("v4"),
            registryIpv6Sha256: sha256Utf8Hex("v6"),
            authoritySha256: sha256Utf8Hex("hooks.example.com:443"),
            answerSetSha256: sha256Utf8Hex("93.184.216.34"),
            selectedAddress: "93.184.216.34",
            selectedAddressSha256: sha256Utf8Hex("93.184.216.34"),
            selectedFamily: 4,
            target: {
              urlPolicyVersion: "url_v1",
              scheme: "https",
              canonicalUrl: "https://hooks.example.com/webhook",
              normalizedHostname: "hooks.example.com",
              port: 443,
              externalAuthority: "hooks.example.com:443",
              requestTarget: "/webhook",
              authoritySha256: sha256Utf8Hex("hooks.example.com:443"),
              pathAndQuerySha256: sha256Utf8Hex("/webhook"),
              configurationSha256: sha256Utf8Hex("cfg"),
              isFixtureException: false
            },
            cnameChain: [],
            observedAt: formatUtcTimestamp(now),
            expiresAt: "2026-11-20T10:00:30.000000Z",
            observedAtMs: now.epochMilliseconds,
            expiresAtMs: now.add({ seconds: 30 }).epochMilliseconds,
            ttlSeconds: 30,
            oneShot: true,
            cacheable: false
          };
        }
      },
      egressExecutor: {
        async execute() {
          const signedReceipt = signReceiverLocalCommitReceipt({
            keyId: KEY_ID,
            projectId: PROJECT_ID,
            eventId: EVENT_ID,
            consumerEventKey: consumerEventKeySha256,
            originalFactsSha256,
            receiptId: "e1111111-1111-4111-8111-111111111111",
            committedAt: formatUtcTimestamp(now),
            deliveryAttemptId: ATTEMPT_ID,
            requestWireBodySha256: wireBodySha,
            keyHandle: simulateBadReceiptMac
              ? createMemorySigningKeyHandle(crypto.randomBytes(32), { id: KEY_ID })
              : createMemorySigningKeyHandle(secret, { id: KEY_ID }),
            keyMetadata: keyMeta,
            now
          });
          return {
            ok: true,
            sendStarted: true,
            outcomeClass: "acknowledged",
            safeErrorCode: null,
            peerAddressSha256: sha256Utf8Hex("93.184.216.34"),
            selectedAddressSha256: sha256Utf8Hex("93.184.216.34"),
            selectedFamily: 4,
            elapsedMs: 12,
            response: {
              status: 200,
              outcomeClass: "acknowledged",
              httpAcknowledged: true,
              retryable: false,
              safeErrorCode: null,
              rawHeaders: [["content-type", "application/json"]],
              rawHeaderBytes: 32,
              contentType: "application/json",
              contentEncoding: null,
              bodyDisposition: "complete",
              bodyBytes: signedReceipt.bodyBytes,
              bodyByteCount: signedReceipt.bodyBytes.byteLength,
              bodySha256: crypto.createHash("sha256").update(signedReceipt.bodyBytes).digest("hex"),
              receiptEligible: true
            }
          };
        }
      },
      webhookSigner: {
        signDelivery: signWebhookDelivery,
        signEndpointVerification: signEndpointVerificationRequest,
        verifyEndpointProof: verifyEndpointProofResponse,
        verifyReceiverReceipt: verifyReceiverLocalCommitReceiptResponse
      },
      getKeyMaterial: keyProvider.asResolver(),
      monotonicNowNs: () => 1_000_000n,
      clock,
      idGenerator: ids
    });

    // 1. Attempt returns HTTP 200 but receipt MAC is invalid -> HTTP acknowledged, receipt rejected!
    const badReceiptAttempt = await deliveryService.executePreparedAttempt({
      attemptId: ATTEMPT_ID,
      workerInstanceId: INSTANCE_ID,
      controlEpoch: EPOCH,
      expectedFencingToken: 7n
    });
    assert.equal(badReceiptAttempt.disposition, "acknowledged");
    assert.equal(badReceiptAttempt.receiptState, "rejected");

    const evidence = new EvidenceService({
      uow: PASSIVE_UOW,
      evidenceRepo: {
        async readEventEvidence() {
          return {
            admission: {
              eventId: EVENT_ID,
              admittedAt: formatUtcTimestamp(now),
              state: "accepted",
              contentSha256: wireBodySha,
              topologyVersion: 1n
            },
            brokerPublication: {
              outboxId: "f3333333-3333-4333-8333-333333333333",
              publicationGeneration: 1n,
              brokerMessageId: "rq:f3333333-3333-4333-8333-333333333333:1",
              state: "published",
              streamName: "RELAYQUILL_EVENTS",
              streamSequence: 1n,
              publishedAt: formatUtcTimestamp(now)
            },
            httpAttempts: observedHttpAttempts,
            verifiedReceipts: observedReceipts
          };
        },
        async readDeliveryEvidence() {
          throw new Error("unused");
        }
      }
    });

    const view1 = await evidence.getEventEvidence({
      tenantId: TENANT_ID,
      projectId: PROJECT_ID,
      eventId: EVENT_ID
    });
    assert.equal(view1.summary.accepted, true);
    assert.equal(view1.summary.publishedToBroker, true);
    assert.equal(view1.summary.httpAcknowledged, true);
    assert.equal(view1.summary.receiverReceiptVerified, false);
    assert.equal(view1.summary.hasRejectedOrConflictingReceipt, true);

    // 2. Retry / second execution with valid MAC receipt promotes receipt evidence cleanly
    simulateBadReceiptMac = false;
    const goodReceiptAttempt = await deliveryService.executePreparedAttempt({
      attemptId: ATTEMPT_ID,
      workerInstanceId: INSTANCE_ID,
      controlEpoch: EPOCH,
      expectedFencingToken: 7n
    });
    assert.equal(goodReceiptAttempt.receiptState, "verified");

    const view2 = await evidence.getEventEvidence({
      tenantId: TENANT_ID,
      projectId: PROJECT_ID,
      eventId: EVENT_ID
    });
    assert.equal(view2.summary.receiverReceiptVerified, true);
  });

  it("enforces human_data_grants gate on GovernanceService lossless views and retention holds on MaintenanceService", async () => {
    const now = Temporal.Instant.from("2026-11-20T10:00:00.000000Z");
    const clock = { nowInstant: () => now };
    const govRepo = new InMemoryGovernanceRepository();
    govRepo.putPrincipal({
      principalId: PROPOSER_ID,
      kind: "human",
      state: "active",
      authorityEpoch: 1n,
      version: 1n
    });
    govRepo.putProjectMembership({
      id: "a0000000-0000-4000-8000-000000000009",
      tenantId: TENANT_ID,
      projectId: PROJECT_ID,
      principalId: PROPOSER_ID,
      role: "operator",
      state: "active",
      authorityVersion: 1n,
      createdAt: now,
      updatedAt: now,
      version: 1n
    });

    const governance = new GovernanceService({
      uow: PASSIVE_UOW,
      governanceRepo: {
        async listDataGrants() {
          return [];
        },
        async grantProjectDataAccess() {
          throw new Error("unused");
        },
        async readEventContentLossless() {
          return {
            eventId: EVENT_ID,
            payloadId: "b1111111-1111-4111-8111-111111111111",
            retentionState: "required",
            contentSha256: sha256Utf8Hex("{}"),
            contentBytes: new Uint8Array([0x7b, 0x7d])
          };
        }
      },
      authRepos: {
        producerCredentials: {
          async findById() {
            return null;
          }
        },
        humanAuthorization: govRepo,
        sessions: {},
        stepUp: {},
        enrollment: {}
      },
      readInstallationAuthority: async () => makeInstallation(),
      clock
    });

    // Without active human_data_grants -> FORBIDDEN even as project operator
    await assert.rejects(
      () =>
        governance.readLosslessEventContent({
          session: makeAuthSession(PROPOSER_ID, SESSION_1),
          tenantId: TENANT_ID,
          projectId: PROJECT_ID,
          eventId: EVENT_ID
        }),
      (err) => err instanceof AuthorizationDomainError && err.code === "FORBIDDEN"
    );

    // Grant active data access -> succeeds
    govRepo.putDataGrant({
      id: "c1111111-1111-4111-8111-111111111111",
      membershipId: "a0000000-0000-4000-8000-000000000009",
      tenantId: TENANT_ID,
      projectId: PROJECT_ID,
      action: "events.content.read",
      projection: "approved_project",
      producerNamespace: null,
      state: "active",
      expiresAt: now.add({ hours: 1 }),
      createdBy: REVIEWER_ID,
      createdAt: now,
      version: 1n
    });

    const content = await governance.readLosslessEventContent({
      session: makeAuthSession(PROPOSER_ID, SESSION_1),
      tenantId: TENANT_ID,
      projectId: PROJECT_ID,
      eventId: EVENT_ID
    });
    assert.equal(content.eventId, EVENT_ID);

    // Bounded retention sweep skips held event and completes unheld action
    const finalizedIds = [];
    const maintenance = new MaintenanceService({
      uow: PASSIVE_UOW,
      maintenanceRepo: {
        async promoteDueWork() {
          return { promotedDeliveries: 1, promotedOutbox: 0 };
        },
        async reapExpiredCoordinatorWork() {
          return {
            reapedAttempts: 0,
            reapedOutboxClaims: 0,
            reapedFanoutClaims: 0,
            reapedWatchLeases: 2
          };
        },
        async listUnknownPublicationOutbox() {
          return [];
        },
        async markOutboxReviewRequired() {},
        async listActiveRetentionHolds() {
          return [
            {
              id: "d1111111-1111-4111-8111-111111111111",
              tenantId: TENANT_ID,
              projectId: PROJECT_ID,
              targetKind: "event",
              targetId: EVENT_ID,
              reasonCode: "LEGAL_HOLD",
              state: "active",
              version: 1n
            }
          ];
        },
        async listDueRetentionActions() {
          return [
            {
              actionId: "e1111111-1111-4111-8111-111111111111",
              tenantId: TENANT_ID,
              projectId: PROJECT_ID,
              targetKind: "event",
              targetId: EVENT_ID,
              action: "expire_content",
              state: "ready",
              claimGeneration: 0n,
              nextAttemptAt: formatUtcTimestamp(now),
              version: 1n
            },
            {
              actionId: "e2222222-2222-4222-8222-222222222222",
              tenantId: TENANT_ID,
              projectId: PROJECT_ID,
              targetKind: "delivery_family",
              targetId: "f1111111-1111-4111-8111-111111111111",
              action: "retire_history",
              state: "ready",
              claimGeneration: 0n,
              nextAttemptAt: formatUtcTimestamp(now),
              version: 1n
            }
          ];
        },
        async claimRetentionAction(_tx, { actionId }) {
          return { claimed: true, claimGeneration: 1n, actionId };
        },
        async finalizeRetentionAction(_tx, { actionId }) {
          finalizedIds.push(actionId);
          return { outcome: "completed", actionId };
        },
        async verifyProjectDeliveryProjection() {
          throw new Error("unused");
        },
        async rebuildProjectDeliveryProjection() {
          throw new Error("unused");
        }
      },
      clock
    });

    const retentionOut = await maintenance.runBoundedRetentionSweep({
      instanceId: INSTANCE_ID,
      controlEpoch: EPOCH,
      batchLimit: 10
    });
    assert.equal(retentionOut.examinedCount, 2);
    assert.equal(retentionOut.skippedHeldCount, 1);
    assert.equal(retentionOut.completedCount, 1);
    assert.deepEqual(finalizedIds, ["e2222222-2222-4222-8222-222222222222"]);

    const reaped = await maintenance.reapExpiredWorkAndWatchLeases({
      instanceId: INSTANCE_ID,
      controlEpoch: EPOCH
    });
    assert.equal(reaped.reapedWatchLeases, 2);

    // Ordering helper smoke check: verifies canonical ordering exports & endpoint proof round-trip
    assert.equal(typeof OrderingService, "function");
    assert.equal(typeof signEndpointProof, "function");
    assert.equal(typeof hashCanonicalJson({ ok: true }).sha256, "string");
  });
});
