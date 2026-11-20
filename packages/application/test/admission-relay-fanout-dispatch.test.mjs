import { describe, it } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { Temporal } from "@js-temporal/polyfill";
import {
  AdmissionService,
  DispatchService,
  FanoutService,
  MaintenanceService,
  RelayService,
  refillMicrotokenBucket,
  reserveMicrotokensForPrepare,
  spendReservedMicrotokensOnSendStart
} from "../dist/index.js";
import {
  ConflictDomainError,
  FANOUT_OUT_OF_ORDER_NAK_MS,
  formatUtcTimestamp
} from "@relayquill/domain";
import {
  encodeBrokerNotificationEnvelope,
  parseCanonicalUtcTimestamp,
  sha256Utf8Hex
} from "@relayquill/contracts";
import { BrokerPublishError } from "@relayquill/broker";

function deterministicIds(prefix = "00000000-0000-4000-8000-") {
  let counter = 1;
  return {
    nextUuid() {
      const hex = counter.toString(16).padStart(12, "0");
      counter += 1;
      return `${prefix}${hex}`;
    }
  };
}

function fixedClock(iso = "2026-11-20T10:00:00.000000Z") {
  const instant = Temporal.Instant.from(iso);
  return {
    nowInstant: () => instant
  };
}

const TENANT_ID = "11111111-1111-4111-8111-111111111111";
const PROJECT_ID = "22222222-2222-4222-8222-222222222222";
const PRODUCER_ID = "33333333-3333-4333-8333-333333333333";
const PRINCIPAL_ID = "44444444-4444-4444-8444-444444444444";
const EVENT_TYPE_ID = "55555555-5555-4555-8555-555555555555";
const INSTANCE_ID = "66666666-6666-4666-8666-666666666666";
const EPOCH = "77777777-7777-4777-8777-777777777777";
const BROKER_GEN = "88888888-8888-4888-8888-888888888888";

const PASSIVE_UOW = {
  async inTransaction(fn) {
    return fn({});
  }
};

describe("AdmissionService 201 / 200 / 409 and lost-response recovery", () => {
  it("returns 201 on first admission, 200 on idempotent retry, 409 on payload conflict, and resolves prepared lost responses", async () => {
    const idGen = deterministicIds("aaaaaaaa-aaaa-4aaa-8aaa-");
    const clock = fixedClock();
    const admittedByKey = new Map();
    const admittedByBusiness = new Map();

    const schemaBytes = new TextEncoder().encode(
      JSON.stringify({
        type: "object",
        properties: { orderId: { type: "string" } },
        required: ["orderId"]
      })
    );
    const schemaSha = sha256Utf8Hex(new TextDecoder().decode(schemaBytes));

    const schemaEvaluator = {
      async validateEvent({ eventBytes }) {
        const parsed = JSON.parse(new TextDecoder().decode(eventBytes));
        const valid = typeof parsed?.orderId === "string";
        const digest = crypto.createHash("sha256").update(eventBytes).digest("hex");
        return {
          valid,
          diagnostics: valid
            ? []
            : [{ path: "/orderId", code: "TYPE_MISMATCH", message: "missing orderId" }],
          byteCount: eventBytes.byteLength,
          sha256: digest
        };
      },
      async evaluateFilterAndExtract() {
        return { schemaValid: true, diagnostics: [], matched: true };
      },
      async executeProjection() {
        throw new Error("unexpected projection");
      }
    };

    const admissionRepo = {
      async readAuthorities() {
        return {
          installation: {
            controlEpoch: EPOCH,
            mode: "open",
            allowEventAdmission: true,
            allowPublication: true,
            allowFanout: true,
            allowSend: true,
            allowEndpointVerification: true,
            governanceVersion: 1n,
            updatedAt: "2026-11-20T10:00:00.000000Z",
            version: 1n
          },
          tenant: {
            tenantId: TENANT_ID,
            slug: "acme",
            displayName: "Acme",
            state: "active",
            governanceVersion: 1n,
            version: 1n
          },
          project: {
            tenantId: TENANT_ID,
            projectId: PROJECT_ID,
            name: "Billing",
            state: "active",
            topologyVersion: 1n,
            nextEventSequence: 1n,
            materializedThroughEventSequence: 0n,
            governanceVersion: 1n,
            defaultDeliveryWindowMs: 3_600_000n,
            maxDeliveryWindowMs: 86_400_000n,
            version: 1n
          },
          quota: {
            maxPendingEvents: 1000n,
            maxUnmaterializedCandidateSlots: 1000n,
            maxPendingDeliveries: 1000n,
            maxActiveAttemptSlots: 64,
            maxRetainedPayloadBytes: 1_000_000n
          },
          capacity: {
            pendingEvents: 0n,
            unmaterializedCandidateSlots: 0n,
            pendingDeliveries: 0n,
            activeAttemptSlots: 0,
            retainedPayloadBytes: 0n,
            reservedPayloadBytes: 0n
          }
        };
      },
      async findProducerScope() {
        return {
          producerId: PRODUCER_ID,
          tenantId: TENANT_ID,
          projectId: PROJECT_ID,
          namespace: `human.${PRINCIPAL_ID}`,
          allowedActions: ["admit", "resolve"],
          allowedEventTypeVersions: [{ eventTypeId: EVENT_TYPE_ID, schemaVersions: [1] }],
          maxDecodedContentBytes: 65536,
          enabled: true,
          version: 1n
        };
      },
      async findEventSchema() {
        return {
          eventTypeId: EVENT_TYPE_ID,
          eventTypeName: "order.created",
          schemaVersion: 1,
          profileVersion: "2020-12",
          state: "active",
          schemaBytes,
          schemaSha256: schemaSha
        };
      },
      async countCandidateSubscriptions() {
        return { count: 2n, maxDerivedEnvelopeUpperBoundBytes: 1024n };
      },
      async resolveAdmittedEvent(_tx, query) {
        const byIdem = admittedByKey.get(query.idempotencyKeySha256);
        if (byIdem) {
          if (byIdem.submittedShapeSha256 !== query.submittedShapeSha256) {
            return {
              found: true,
              matchKind: "conflict",
              conflictCode: "IDEMPOTENCY_CONFLICT",
              message: "Idempotency key reused with conflicting payload"
            };
          }
          return { found: true, matchKind: "idempotent_recovery", ...byIdem };
        }
        const byBiz = admittedByBusiness.get(query.businessKeySha256);
        if (byBiz) {
          return {
            found: true,
            matchKind: "conflict",
            conflictCode: "BUSINESS_IDENTITY_CONFLICT",
            message: "Business key already bound to different facts"
          };
        }
        return { found: false };
      },
      async admitEvent(_tx, rec) {
        const stored = {
          eventId: rec.eventId,
          receiptId: rec.receiptId,
          outboxId: rec.outboxId,
          projectEventSequence: 1n,
          topologyVersion: 1n,
          candidateCount: rec.candidateCount,
          admittedAt: rec.admittedAt,
          deliveryDeadlineAt: rec.deliveryDeadlineAt,
          state: "accepted",
          appliedDefaults: rec.appliedDefaults,
          submittedShapeSha256: rec.submittedShapeSha256,
          effectiveRequestSha256: rec.effectiveRequestSha256,
          originalFactsSha256: rec.originalFactsSha256
        };
        admittedByKey.set(rec.idempotencyKeySha256, stored);
        admittedByBusiness.set(rec.businessKeySha256, stored);
        return { outcome: "accepted", ...stored };
      }
    };

    const admission = new AdmissionService({
      uow: PASSIVE_UOW,
      admissionRepo,
      producerCredentials: {
        async findById() {
          throw new Error("not used in human_workflow");
        }
      },
      schemaEvaluator,
      clock,
      idGenerator: idGen
    });

    const actor = {
      kind: "human_workflow",
      actorPrincipalId: PRINCIPAL_ID,
      publicationChannelId: PRODUCER_ID,
      producerNamespace: `human.${PRINCIPAL_ID}`,
      scopeAuthorized: true
    };
    const payload = new TextEncoder().encode(JSON.stringify({ orderId: "ord-100" }));

    // 1. First call returns 201 Accepted
    const first = await admission.admitEvent({
      tenantId: TENANT_ID,
      projectId: PROJECT_ID,
      actor,
      eventTypeId: EVENT_TYPE_ID,
      eventTypeName: "order.created",
      eventSchemaVersion: 1,
      businessKey: "ord-100",
      idempotencyKey: "idem-key-1",
      contentBytes: payload
    });
    assert.equal(first.statusCode, 201);
    assert.equal(first.outcome, "accepted");

    // 2. Same idempotencyKey + payload returns 200 idempotent_recovery (no duplicate insert)
    const second = await admission.admitEvent({
      tenantId: TENANT_ID,
      projectId: PROJECT_ID,
      actor,
      eventTypeId: EVENT_TYPE_ID,
      eventTypeName: "order.created",
      eventSchemaVersion: 1,
      businessKey: "ord-100",
      idempotencyKey: "idem-key-1",
      contentBytes: payload
    });
    assert.equal(second.statusCode, 200);
    assert.equal(second.outcome, "idempotent_recovery");
    assert.equal(second.eventId, first.eventId);

    // 3. Lost-response recovery endpoint resolves the prepared event
    const resolved = await admission.resolvePreparedEvent({
      tenantId: TENANT_ID,
      projectId: PROJECT_ID,
      actor,
      eventTypeId: EVENT_TYPE_ID,
      eventSchemaVersion: 1,
      businessKey: "ord-100",
      idempotencyKey: "idem-key-1",
      contentBytes: payload
    });
    assert.equal(resolved.found, true);
    if (resolved.found) {
      assert.equal(resolved.eventId, first.eventId);
    }

    // 4. Same idempotencyKey + altered payload rejects with ConflictDomainError (409)
    await assert.rejects(
      () =>
        admission.admitEvent({
          tenantId: TENANT_ID,
          projectId: PROJECT_ID,
          actor,
          eventTypeId: EVENT_TYPE_ID,
          eventTypeName: "order.created",
          eventSchemaVersion: 1,
          businessKey: "ord-100",
          idempotencyKey: "idem-key-1",
          contentBytes: new TextEncoder().encode(JSON.stringify({ orderId: "ord-999" }))
        }),
      (err) => err instanceof ConflictDomainError && err.code === "IDEMPOTENCY_CONFLICT"
    );

    // 5. New idempotencyKey + same businessKey + different payload -> BUSINESS_IDENTITY_CONFLICT (409)
    await assert.rejects(
      () =>
        admission.admitEvent({
          tenantId: TENANT_ID,
          projectId: PROJECT_ID,
          actor,
          eventTypeId: EVENT_TYPE_ID,
          eventTypeName: "order.created",
          eventSchemaVersion: 1,
          businessKey: "ord-100",
          idempotencyKey: "idem-key-2",
          contentBytes: new TextEncoder().encode(JSON.stringify({ orderId: "ord-200" }))
        }),
      (err) => err instanceof ConflictDomainError && err.code === "BUSINESS_IDENTITY_CONFLICT"
    );
  });
});

describe("DispatchService WDRR fairness, 1,000,000-microtoken conservation, and half-open single-probe gating", () => {
  it("conserves microtokens and sub-microsecond remainderNumerator across partial refills", () => {
    const startUs = 1_000_000n;
    const bucket = {
      bucketScope: "endpoint:e1",
      operation: "send_start",
      policyEpoch: 1n,
      tokensMicro: 0n,
      reservedMicro: 0n,
      capacityMicro: 10_000_000n,
      refillMicroPerSec: 1_500_000n, // 1.5 tokens/sec = 1.5 microtokens/us
      remainderNumerator: 0n,
      lastRefillAtUs: startUs,
      enabled: true,
      version: 1n
    };

    // Refill 1 microsecond twice -> 1.5 + 1.5 = exact 3 microtokens, 0 drift
    const after1 = refillMicrotokenBucket(bucket, startUs + 1n);
    assert.equal(after1.tokensMicro, 1n);
    assert.equal(after1.remainderNumerator, 500_000n);

    const after2 = refillMicrotokenBucket(after1, startUs + 2n);
    assert.equal(after2.tokensMicro, 3n);
    assert.equal(after2.remainderNumerator, 0n);

    // Advance 1 full second -> +1,500,000 = 1,500,003 microtokens, reserve+spend 1,000,000 -> 500,003 left
    const afterSec = refillMicrotokenBucket(after2, startUs + 1_000_002n);
    assert.equal(afterSec.tokensMicro, 1_500_003n);
    const prepared = reserveMicrotokensForPrepare([afterSec], startUs + 1_000_000n);
    assert.equal(prepared.allowed, true);
    const spent = spendReservedMicrotokensOnSendStart(
      prepared.updatedBuckets,
      startUs + 1_000_000n
    );
    assert.equal(spent[0].tokensMicro, 500_003n);
    assert.equal(spent[0].reservedMicro, 0n);
  });

  it("enforces WDRR tenant fairness and single-probe gating when circuit is half-open", async () => {
    const clock = fixedClock("2026-11-20T10:05:00.000000Z");
    const ids = deterministicIds("bbbbbbbb-bbbb-4bbb-8bbb-");

    const tenantA = "10000000-0000-4000-8000-000000000001";
    const tenantB = "10000000-0000-4000-8000-000000000002";
    const projA = "20000000-0000-4000-8000-000000000001";
    const projB = "20000000-0000-4000-8000-000000000002";
    const epA = "30000000-0000-4000-8000-000000000001";
    const epB = "30000000-0000-4000-8000-000000000002";

    const circuits = new Map([
      [
        epA,
        {
          endpointId: epA,
          state: "open", // Cooldown elapsed at 10:05 vs reopenNotBefore 10:04 -> allows 1 probe!
          circuitGeneration: 2n,
          probeGeneration: 0n,
          consecutiveFailures: 5,
          reopenNotBefore: "2026-11-20T10:04:00.000000Z",
          probeInFlightAttemptId: null,
          version: 1n
        }
      ],
      [
        epB,
        {
          endpointId: epB,
          state: "closed",
          circuitGeneration: 1n,
          probeGeneration: 0n,
          consecutiveFailures: 0,
          probeInFlightAttemptId: null,
          version: 1n
        }
      ]
    ]);

    const committedBatches = [];
    const candidatesByEp = new Map([
      [
        epA,
        [
          {
            deliveryId: "40000000-0000-4000-8000-000000000001",
            tenantId: tenantA,
            projectId: projA,
            subscriptionId: "50000000-0000-4000-8000-000000000001",
            endpointId: epA,
            endpointVersion: 1n,
            deliveryGeneration: 1n,
            attemptCount: 0,
            deadlineAt: "2026-11-20T12:00:00.000000Z"
          },
          {
            deliveryId: "40000000-0000-4000-8000-000000000002",
            tenantId: tenantA,
            projectId: projA,
            subscriptionId: "50000000-0000-4000-8000-000000000001",
            endpointId: epA,
            endpointVersion: 1n,
            deliveryGeneration: 1n,
            attemptCount: 0,
            deadlineAt: "2026-11-20T12:00:00.000000Z"
          }
        ]
      ],
      [
        epB,
        [
          {
            deliveryId: "40000000-0000-4000-8000-000000000003",
            tenantId: tenantB,
            projectId: projB,
            subscriptionId: "50000000-0000-4000-8000-000000000002",
            endpointId: epB,
            endpointVersion: 1n,
            deliveryGeneration: 1n,
            attemptCount: 0,
            deadlineAt: "2026-11-20T12:00:00.000000Z"
          }
        ]
      ]
    ]);

    const makeBucket = (scope) => ({
      bucketScope: scope,
      operation: "send_start",
      policyEpoch: 1n,
      tokensMicro: 5_000_000n,
      reservedMicro: 0n,
      capacityMicro: 10_000_000n,
      refillMicroPerSec: 1_000_000n,
      remainderNumerator: 0n,
      lastRefillAtUs: 1_000_000n,
      enabled: true,
      version: 1n
    });

    const dispatchRepo = {
      async readInstallationAuthority() {
        return {
          controlEpoch: EPOCH,
          mode: "open",
          allowEventAdmission: true,
          allowPublication: true,
          allowFanout: true,
          allowSend: true,
          allowEndpointVerification: true,
          governanceVersion: 1n,
          updatedAt: "2026-11-20T10:00:00.000000Z",
          version: 1n
        };
      },
      async findDispatchClaimRequest() {
        return undefined;
      },
      async listDispatchDomains() {
        return [
          {
            dispatchDomainId: "default",
            state: "active",
            policyEpoch: 1n,
            version: 1n
          }
        ];
      },
      async listWdrrTenantStates() {
        return [
          {
            scopeKind: "tenant",
            scopeId: tenantA,
            tenantId: tenantA,
            weight: 2,
            deficitUnits: 0,
            policyEpoch: 1n,
            version: 1n
          },
          {
            scopeKind: "tenant",
            scopeId: tenantB,
            tenantId: tenantB,
            weight: 1,
            deficitUnits: 0,
            policyEpoch: 1n,
            version: 1n
          }
        ];
      },
      async listWdrrProjectStates(_tx, _domain, tId) {
        const pId = tId === tenantA ? projA : projB;
        return [
          {
            scopeKind: "project",
            scopeId: pId,
            projectId: pId,
            weight: 1,
            deficitUnits: 0,
            policyEpoch: 1n,
            version: 1n
          }
        ];
      },
      async listWdrrEndpointStates(_tx, _domain, pId) {
        const eId = pId === projA ? epA : epB;
        return [
          {
            scopeKind: "endpoint",
            scopeId: eId,
            endpointId: eId,
            weight: 1,
            deficitUnits: 0,
            policyEpoch: 1n,
            version: 1n
          }
        ];
      },
      async readProjectConcurrencyUsage() {
        return {
          activeAttemptSlots: 0,
          maxActiveAttemptSlots: 10,
          pendingDeliveries: 5n
        };
      },
      async readEndpointConcurrencyUsage() {
        return {
          activeAttemptSlots: 0,
          maxInFlight: 5,
          state: "active"
        };
      },
      async readEndpointCircuit(_tx, eId) {
        return circuits.get(eId);
      },
      async readRateBuckets(_tx, scope) {
        return {
          endpointBucket: makeBucket(`endpoint:${scope.endpointId}`)
        };
      },
      async listDueDeliveriesForEndpoint(_tx, _pId, eId, _now, limit) {
        return (candidatesByEp.get(eId) ?? []).slice(0, limit);
      },
      async commitDispatchBatch(_tx, input) {
        committedBatches.push(input);
        return {
          requestId: input.requestId,
          dispatchDomainId: input.dispatchDomainId,
          requestSha256: input.requestSha256,
          assignments: input.selections.map((s) => ({
            attemptId: s.attemptId,
            deliveryId: s.deliveryId,
            endpointId: s.endpointId,
            fencingToken: 1n,
            isCircuitProbe: s.isCircuitProbe,
            claimExpiresAt: parseCanonicalUtcTimestamp(
              formatUtcTimestamp(Temporal.Instant.from("2026-11-20T10:05:30.000000Z"))
            )
          }))
        };
      }
    };

    const dispatch = new DispatchService({ uow: PASSIVE_UOW, dispatchRepo, clock, idGenerator: ids });
    const out = await dispatch.claimDispatchBatch({
      requestId: "req-1",
      dispatchDomainId: "default",
      workerInstanceId: INSTANCE_ID,
      controlEpoch: EPOCH,
      maximumCount: 4
    });

    // epA gets EXACTLY ONE half-open probe assignment; second epA delivery is gated by half-open probe_in_flight!
    const epAAssignments = out.assignments.filter((a) => a.endpointId === epA);
    const epBAssignments = out.assignments.filter((a) => a.endpointId === epB);
    assert.equal(epAAssignments.length, 1);
    assert.equal(epAAssignments[0].isCircuitProbe, true);
    assert.equal(epBAssignments.length, 1);
    assert.equal(epBAssignments[0].isCircuitProbe, false);

    // Verify exact 1,000,000-microtoken reservation on every selected delivery
    for (const sel of committedBatches[0].selections) {
      assert.equal(sel.reserveMicrotokens, 1_000_000n);
      assert.equal(sel.updatedBuckets[0].reservedMicro, 1_000_000n);
    }
  });
});

describe("FanoutService paginated watermarks and NAK on sequence gaps", () => {
  it("NAKs out-of-order project sequence and materializes contiguous multi-page fanout", async () => {
    const clock = fixedClock();
    const ids = deterministicIds("cccccccc-cccc-4ccc-8ccc-");
    const outboxId = "99999999-9999-4999-8999-999999999999";
    const sub1 = "aaaaaaaa-0000-4000-8000-000000000001";
    const sub2 = "aaaaaaaa-0000-4000-8000-000000000002";
    const sub3 = "aaaaaaaa-0000-4000-8000-000000000003";
    const ep1 = "bbbbbbbb-0000-4000-8000-000000000001";
    const eventId = "cccccccc-0000-4000-8000-000000000001";

    const content = new TextEncoder().encode(JSON.stringify({ tenant: "acme" }));
    const contentSha = crypto.createHash("sha256").update(content).digest("hex");

    const env = encodeBrokerNotificationEnvelope({
      envelope_version: 1,
      outbox_id: outboxId,
      event_id: eventId,
      project_id: PROJECT_ID,
      topology_version: 1n,
      publication_generation: 1n,
      content_sha256: contentSha
    });

    let watermark = 0n;
    let currentSequence = 3n; // Out of order initially! (gap: expected 1, saw 3)
    const committedPages = [];
    const actions = [];

    const fanoutRepo = {
      async readInstallationAuthority() {
        return {
          controlEpoch: EPOCH,
          mode: "open",
          allowEventAdmission: true,
          allowPublication: true,
          allowFanout: true,
          allowSend: true,
          allowEndpointVerification: true,
          governanceVersion: 1n,
          updatedAt: "2026-11-20T10:00:00.000000Z",
          version: 1n
        };
      },
      async acceptBrokerInbox() {
        return {
          inboxId: "dddddddd-0000-4000-8000-000000000001",
          fanoutState: "pending",
          projectEventSequence: currentSequence,
          materializedThroughEventSequence: watermark,
          isNextContiguous: currentSequence === watermark + 1n
        };
      },
      async claimEventFanout() {
        return {
          outcome: "claimed",
          eventId,
          topologyVersion: 1n,
          subscriptionCursor: undefined,
          claimGeneration: 1n,
          claimExpiresAt: "2026-11-20T10:00:30.000000Z",
          candidateCount: 3n,
          examinedCount: 0n
        };
      },
      async readEventForFanout() {
        return {
          tenantId: TENANT_ID,
          projectId: PROJECT_ID,
          eventId,
          eventTypeId: EVENT_TYPE_ID,
          eventTypeName: "order.created",
          eventSchemaVersion: 1,
          projectEventSequence: currentSequence,
          topologyVersion: 1n,
          wireEnvelopeId: "eeeeeeee-0000-4000-8000-000000000001",
          contentBytes: content,
          contentSha256: contentSha,
          admittedAt: "2026-11-20T10:00:00.000000Z",
          schemaBytes: new Uint8Array([0x7b, 0x7d]),
          schemaProfileVersion: "2020-12"
        };
      },
      async listActiveSubscriptionsPage(_tx, params) {
        const all = [sub1, sub2, sub3].map((sid) => ({
          subscriptionId: sid,
          subscriptionVersion: 1n,
          endpointId: ep1,
          endpointVersion: 1n,
          eventTypeId: EVENT_TYPE_ID,
          eventTypeName: "order.created",
          schemaVersion: 1,
          filterProfileVersion: "relayquill.filter.v1",
          filterAst: { kind: "boolean", operation: "all", children: [] },
          filterSha256: contentSha,
          orderingMode: "unordered",
          consumerContractScope: `${sid}:v1`,
          retryPolicyVersion: "retry_v1",
          maxAttempts: 12,
          reservedSlotBytes: 512n
        }));
        const startIdx = params.afterSubscriptionId
          ? all.findIndex((s) => s.subscriptionId === params.afterSubscriptionId) + 1
          : 0;
        return all.slice(startIdx, startIdx + params.limit);
      },
      async reserveOrderingSequence() {
        return { orderingSequence: 1n };
      },
      async commitFanoutPage(_tx, input) {
        committedPages.push(input);
        if (input.complete) {
          watermark = currentSequence;
        }
        return {
          outcome: input.complete ? "completed" : "page_committed",
          newExamined: BigInt(committedPages.length),
          newDeliveries: BigInt(committedPages.reduce((n, p) => n + p.outcomes.length, 0)),
          materializedThroughEventSequence: watermark
        };
      }
    };

    const fanout = new FanoutService({
      uow: PASSIVE_UOW,
      fanoutRepo,
      schemaEvaluator: {
        async validateEvent() {
          throw new Error("unused");
        },
        async evaluateFilterAndExtract() {
          return { schemaValid: true, diagnostics: [], matched: true };
        },
        async executeProjection() {
          throw new Error("unused");
        }
      },
      clock,
      idGenerator: ids
    });

    const msg = {
      msgId: env.broker_message_id,
      payload: env.bytes,
      seq: 1,
      redelivered: false,
      brokerGenerationId: BROKER_GEN,
      async ack() {
        actions.push("ack");
      },
      async nak(delayMs) {
        actions.push(`nak:${delayMs}`);
      },
      async term() {
        actions.push("term");
      },
      async working() {
        actions.push("working");
      }
    };

    // 1. Out-of-order message NAKs with FANOUT_OUT_OF_ORDER_NAK_MS
    const nakResult = await fanout.processBrokerMessage({
      message: msg,
      instanceId: INSTANCE_ID,
      controlEpoch: EPOCH,
      pageSize: 2
    });
    assert.equal(nakResult.disposition, "out_of_order_naked");
    assert.equal(actions[0], `nak:${Number(FANOUT_OUT_OF_ORDER_NAK_MS)}`);
    assert.equal(watermark, 0n);

    // 2. Contiguous sequence (seq=1) commits across 2 paginated pages (2 + 1) then ACKs & advances watermark
    currentSequence = 1n;
    const okResult = await fanout.processBrokerMessage({
      message: msg,
      instanceId: INSTANCE_ID,
      controlEpoch: EPOCH,
      pageSize: 2
    });
    assert.equal(okResult.disposition, "completed");
    assert.equal(okResult.pagesCommitted, 2);
    assert.equal(okResult.deliveriesCreated, 3n);
    assert.equal(okResult.materializedThroughEventSequence, 1n);
    assert.ok(actions.includes("working"));
    assert.equal(actions[actions.length - 1], "ack");
  });
});

describe("RelayService publish_unknown fence recovery and Maintenance no-progress quarantine", () => {
  it("recovers publish_unknown via same/new generation and quarantines to review_required after 5 no-progress generations", async () => {
    const clock = fixedClock();
    const ids = deterministicIds("dddddddd-dddd-4ddd-8ddd-");
    const outboxId = "12121212-1212-4121-8121-121212121212";
    const eventId = "13131313-1313-4131-8131-131313131313";
    const episodeId = "14141414-1414-4141-8141-141414141414";

    const contentSha = sha256Utf8Hex('{"ok":true}');
    const encoded1 = encodeBrokerNotificationEnvelope({
      envelope_version: 1,
      outbox_id: outboxId,
      event_id: eventId,
      project_id: PROJECT_ID,
      topology_version: 1n,
      publication_generation: 1n,
      content_sha256: contentSha
    });

    const publications = [
      {
        publicationGeneration: 1n,
        envelopeSha256: encoded1.envelope_sha256,
        envelopeBytes: encoded1.bytes,
        brokerMessageId: encoded1.broker_message_id,
        state: "publish_unknown"
      }
    ];
    let publishCalls = 0;
    const unknownOutbox = {
      outboxId,
      eventId,
      tenantId: TENANT_ID,
      projectId: PROJECT_ID,
      topologyVersion: 1n,
      state: "publish_unknown",
      currentPublicationGeneration: 1n,
      nextPublishAt: "2026-11-20T10:00:00.000000Z",
      brokerMessageId: encoded1.broker_message_id,
      claimGeneration: 1n,
      recoveryAttemptCount: 0,
      noProgressGenerationCount: 0,
      version: 1n
    };
    const quarantined = [];

    const relay = new RelayService({
      uow: PASSIVE_UOW,
      relayRepo: {
        async readInstallationAuthority() {
          return {
            controlEpoch: EPOCH,
            mode: "open",
            allowEventAdmission: true,
            allowPublication: true,
            allowFanout: true,
            allowSend: true,
            allowEndpointVerification: true,
            governanceVersion: 1n,
            updatedAt: "2026-11-20T10:00:00.000000Z",
            version: 1n
          };
        },
        async listDueOutboxEvents() {
          return [unknownOutbox];
        },
        async claimOutboxEvent() {
          const latest = publications[publications.length - 1];
          return {
            outboxId,
            eventId,
            projectId: PROJECT_ID,
            publicationGeneration: latest.publicationGeneration,
            claimGeneration: 1n,
            claimExpiresAt: "2026-11-20T10:00:15.000000Z",
            brokerMessageId: latest.brokerMessageId,
            envelopeBytes: latest.envelopeBytes
          };
        },
        async observeOutboxPublication(_tx, params) {
          const latest = publications[publications.length - 1];
          if (params.outcome === "published") {
            latest.state = "published";
          }
          return {
            acceptedAsCurrent: true,
            outboxState: params.outcome,
            publicationState: params.outcome
          };
        },
        async listOutboxPublications() {
          return publications;
        },
        async allocateOutboxRecoveryGeneration(_tx, params) {
          const gen = BigInt(publications.length + 1);
          publications.push({
            publicationGeneration: gen,
            envelopeSha256: params.envelopeSha256,
            envelopeBytes: params.envelopeBytes,
            brokerMessageId: params.brokerMessageId,
            state: "pending"
          });
          return {
            outcome: "allocated",
            publicationGeneration: gen,
            brokerMessageId: params.brokerMessageId
          };
        }
      },
      broker: {
        brokerGenerationId: BROKER_GEN,
        streamName: "RELAYQUILL_EVENTS",
        async publish() {
          publishCalls += 1;
          if (publishCalls === 1) {
            throw new BrokerPublishError("puback timed out", {
              code: "ACCEPTANCE_UNKNOWN",
              classification: "publish_unknown",
              acceptance: "unknown",
              retryable: true,
              reasonCode: "BROKER_PUBACK_UNKNOWN"
            });
          }
          return {
            stream: "RELAYQUILL_EVENTS",
            seq: 42,
            duplicate: false,
            brokerGenerationId: BROKER_GEN
          };
        }
      },
      clock,
      idGenerator: ids
    });

    // 1. Initial claim times out with publish_unknown
    const firstAttempt = await relay.publishClaimedOutbox({
      outboxId,
      instanceId: INSTANCE_ID,
      controlEpoch: EPOCH
    });
    assert.equal(firstAttempt.outcome, "publish_unknown");

    // 2. Recovery allocates gen 2 & publishes cleanly with deterministic rq:<outboxId>:2 message ID
    const recovered = await relay.recoverUnknownPublication({
      outboxId,
      episodeId,
      instanceId: INSTANCE_ID,
      controlEpoch: EPOCH,
      noProgressGenerationCount: 1,
      forceNewGeneration: true
    });
    assert.equal(recovered.action, "allocated_and_published_new_generation");
    assert.equal(recovered.publicationGeneration, 2n);
    assert.equal(recovered.brokerMessageId, `rq:${outboxId}:2`);

    // 3. Maintenance sweep moves outbox at >= 5 no-progress generations directly to review_required
    const maintenance = new MaintenanceService({
      uow: PASSIVE_UOW,
      maintenanceRepo: {
        async promoteDueWork() {
          return { promotedDeliveries: 0, promotedOutbox: 0 };
        },
        async reapExpiredCoordinatorWork() {
          return {
            reapedAttempts: 0,
            reapedOutboxClaims: 0,
            reapedFanoutClaims: 0,
            reapedWatchLeases: 0
          };
        },
        async listUnknownPublicationOutbox() {
          return [{ ...unknownOutbox, noProgressGenerationCount: 5 }];
        },
        async markOutboxReviewRequired(_tx, params) {
          quarantined.push(params);
        },
        async listActiveRetentionHolds() {
          return [];
        },
        async listDueRetentionActions() {
          return [];
        },
        async claimRetentionAction() {
          return { claimed: false, claimGeneration: 0n };
        },
        async finalizeRetentionAction() {
          return { outcome: "already_complete", actionId: "00000000-0000-4000-8000-000000000000" };
        },
        async verifyProjectDeliveryProjection() {
          throw new Error("unused");
        },
        async rebuildProjectDeliveryProjection() {
          throw new Error("unused");
        }
      },
      recoverUnknownOutbox: (input) => relay.recoverUnknownPublication(input),
      clock,
      idGenerator: ids
    });

    const sweep = await maintenance.runPublicationRecoverySweep({
      instanceId: INSTANCE_ID,
      controlEpoch: EPOCH
    });
    assert.equal(sweep.reviewRequiredCount, 1);
    assert.deepEqual(sweep.quarantinedOutboxIds, [outboxId]);
    assert.equal(quarantined[0].reasonCode, "NO_PROGRESS_LIMIT_EXCEEDED");
  });
});
