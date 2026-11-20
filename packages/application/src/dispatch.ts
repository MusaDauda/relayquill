import {
  AuthorizationDomainError,
  ConflictDomainError,
  ValidationDomainError,
  compareInstants,
  formatUtcTimestamp,
  parseAttemptId,
  parseControlEpoch,
  parseRuntimeInstanceId,
  parseUtcTimestamp,
  toEpochMicroseconds,
  type AttemptId,
  type CanonicalUtcTimestamp,
  type ControlEpoch,
  type DeliveryId,
  type EndpointId,
  type ProjectId,
  type RuntimeInstanceId,
  type Sha256Hex,
  type TenantId
} from "@relayquill/domain";
import {
  type CanonicalJsonValue,
  hashCanonicalJson,
  parseCanonicalUtcTimestamp
} from "@relayquill/contracts";
import {
  type ClockPort,
  type DispatchClaimRequestRecord,
  type DispatchRepositoryPort,
  type EndpointCircuitSnapshot,
  type IdGeneratorPort,
  type MicrotokenRateBucketRecord,
  type PrepareDispatchAttemptInput,
  type TelemetryPort,
  type UnitOfWorkPort,
  type WdrrScopeState,
  cryptoIdGeneratorPort,
  noopTelemetryPort,
  systemClockPort
} from "./ports.js";

export const MICROTOKENS_PER_REQUEST = 1_000_000n as const;
export const WDRR_TENANT_DEFICIT_CAP = 1_000 as const;
export const WDRR_PROJECT_DEFICIT_CAP = 1_000 as const;
export const WDRR_ENDPOINT_DEFICIT_CAP = 100 as const;
export const WDRR_MAX_SCOPES_PER_PASS = 64 as const;
export const DISPATCH_CLAIM_MAX_BATCH = 8 as const;
export const DEFAULT_DISPATCH_CLAIM_LEASE_MS = 30_000n as const;

// =============================================================================
// Exact Microtoken Rate-Bucket Accounting (1,000,000 microtokens/req, 0 drift)
// =============================================================================

/**
 * Refills a microtoken bucket using exact integer microsecond arithmetic,
 * conserving `remainderNumerator` across partial microtoken intervals and
 * resetting remainder to `0n` only when the bucket saturates at `capacityMicro`.
 */
export function refillMicrotokenBucket(
  bucket: MicrotokenRateBucketRecord,
  nowUs: bigint
): MicrotokenRateBucketRecord {
  if (!bucket.enabled) {
    return bucket;
  }
  const elapsedUs = nowUs > bucket.lastRefillAtUs ? nowUs - bucket.lastRefillAtUs : 0n;
  const effectiveNowUs = nowUs >= bucket.lastRefillAtUs ? nowUs : bucket.lastRefillAtUs;
  if (elapsedUs === 0n && bucket.tokensMicro >= bucket.capacityMicro) {
    return Object.freeze({
      ...bucket,
      tokensMicro: bucket.capacityMicro,
      remainderNumerator: 0n,
      lastRefillAtUs: effectiveNowUs
    });
  }

  const numerator = elapsedUs * bucket.refillMicroPerSec + bucket.remainderNumerator;
  const addedTokens = numerator / MICROTOKENS_PER_REQUEST;
  const remainder = numerator % MICROTOKENS_PER_REQUEST;
  const rawTokens = bucket.tokensMicro + addedTokens;

  if (rawTokens >= bucket.capacityMicro) {
    return Object.freeze({
      ...bucket,
      tokensMicro: bucket.capacityMicro,
      remainderNumerator: 0n,
      lastRefillAtUs: effectiveNowUs
    });
  }

  return Object.freeze({
    ...bucket,
    tokensMicro: rawTokens,
    remainderNumerator: remainder,
    lastRefillAtUs: effectiveNowUs
  });
}

export function canReserveMicrotokenRequest(
  bucket: MicrotokenRateBucketRecord,
  nowUs: bigint
): {
  readonly allowed: boolean;
  readonly refilled: MicrotokenRateBucketRecord;
} {
  const refilled = refillMicrotokenBucket(bucket, nowUs);
  if (!refilled.enabled) {
    return { allowed: true, refilled };
  }
  const available = refilled.tokensMicro - refilled.reservedMicro;
  return {
    allowed: available >= MICROTOKENS_PER_REQUEST,
    refilled
  };
}

export function reserveMicrotokensForPrepare(
  buckets: readonly MicrotokenRateBucketRecord[],
  nowUs: bigint
): {
  readonly allowed: boolean;
  readonly updatedBuckets: readonly MicrotokenRateBucketRecord[];
} {
  const refilledList: MicrotokenRateBucketRecord[] = [];
  for (const bucket of buckets) {
    const check = canReserveMicrotokenRequest(bucket, nowUs);
    if (!check.allowed) {
      return { allowed: false, updatedBuckets: buckets };
    }
    refilledList.push(check.refilled);
  }

  const reservedList = refilledList.map((b) =>
    b.enabled
      ? Object.freeze({
          ...b,
          reservedMicro: b.reservedMicro + MICROTOKENS_PER_REQUEST,
          version: b.version + 1n
        })
      : b
  );
  return {
    allowed: true,
    updatedBuckets: Object.freeze(reservedList)
  };
}

export function spendReservedMicrotokensOnSendStart(
  buckets: readonly MicrotokenRateBucketRecord[],
  nowUs: bigint
): readonly MicrotokenRateBucketRecord[] {
  return Object.freeze(
    buckets.map((bucket) => {
      const refilled = refillMicrotokenBucket(bucket, nowUs);
      if (!refilled.enabled) {
        return refilled;
      }
      const nextTokens =
        refilled.tokensMicro >= MICROTOKENS_PER_REQUEST
          ? refilled.tokensMicro - MICROTOKENS_PER_REQUEST
          : 0n;
      const nextReserved =
        refilled.reservedMicro >= MICROTOKENS_PER_REQUEST
          ? refilled.reservedMicro - MICROTOKENS_PER_REQUEST
          : 0n;
      return Object.freeze({
        ...refilled,
        tokensMicro: nextTokens,
        reservedMicro: nextReserved,
        version: refilled.version + 1n
      });
    })
  );
}

export function releaseUnstartedMicrotokenReservation(
  buckets: readonly MicrotokenRateBucketRecord[]
): readonly MicrotokenRateBucketRecord[] {
  return Object.freeze(
    buckets.map((bucket) => {
      if (!bucket.enabled) {
        return bucket;
      }
      const nextReserved =
        bucket.reservedMicro >= MICROTOKENS_PER_REQUEST
          ? bucket.reservedMicro - MICROTOKENS_PER_REQUEST
          : 0n;
      return Object.freeze({
        ...bucket,
        reservedMicro: nextReserved,
        version: bucket.version + 1n
      });
    })
  );
}

// =============================================================================
// Hierarchical WDRR Deficit Accounting (Tenant -> Project -> Endpoint)
// =============================================================================

export function deficitCapForScope(scopeKind: WdrrScopeState["scopeKind"]): number {
  switch (scopeKind) {
    case "tenant":
      return WDRR_TENANT_DEFICIT_CAP;
    case "project":
      return WDRR_PROJECT_DEFICIT_CAP;
    case "endpoint":
      return WDRR_ENDPOINT_DEFICIT_CAP;
  }
}

export function normalizeWdrrScopeEpoch<T extends WdrrScopeState>(
  state: T,
  currentEpoch: bigint
): T {
  if (state.policyEpoch === currentEpoch) {
    return state;
  }
  return Object.freeze({
    ...state,
    deficitUnits: 0,
    policyEpoch: currentEpoch
  });
}

export function creditWdrrScopeOnVisit<T extends WdrrScopeState>(
  state: T,
  currentEpoch: bigint
): T {
  const normalized = normalizeWdrrScopeEpoch(state, currentEpoch);
  const cap = deficitCapForScope(normalized.scopeKind);
  const weight = Math.max(1, Math.min(cap, Math.trunc(normalized.weight)));
  const nextDeficit = Math.min(cap, normalized.deficitUnits + weight);
  return Object.freeze({
    ...normalized,
    deficitUnits: nextDeficit
  });
}

export function chargeWdrrScopeUnit<T extends WdrrScopeState>(
  state: T,
  servedAt: CanonicalUtcTimestamp
): T {
  if (state.deficitUnits < 1) {
    throw new ValidationDomainError({
      code: "INVARIANT_VIOLATION",
      message: `Cannot charge WDRR unit from scope "${state.scopeId}" with deficit ${state.deficitUnits}`
    });
  }
  return Object.freeze({
    ...state,
    deficitUnits: state.deficitUnits - 1,
    lastServedAt: servedAt,
    version: state.version + 1n
  });
}

export function resetIdleWdrrScopeDeficit<T extends WdrrScopeState>(
  state: T,
  currentEpoch: bigint
): T {
  const normalized = normalizeWdrrScopeEpoch(state, currentEpoch);
  if (normalized.deficitUnits === 0 && state.policyEpoch === currentEpoch) {
    return state;
  }
  return Object.freeze({
    ...normalized,
    deficitUnits: 0,
    version: state.version + 1n
  });
}

export function evaluateCircuitDispatchEligibility(
  circuit: EndpointCircuitSnapshot,
  now: CanonicalUtcTimestamp
): {
  readonly eligible: boolean;
  readonly isCircuitProbe: boolean;
  readonly reasonCode:
    | "closed_allowed"
    | "half_open_probe_allowed"
    | "open_cooldown_active"
    | "half_open_probe_in_flight";
} {
  if (circuit.state === "closed") {
    return {
      eligible: true,
      isCircuitProbe: false,
      reasonCode: "closed_allowed"
    };
  }
  if (circuit.state === "half_open") {
    return {
      eligible: false,
      isCircuitProbe: false,
      reasonCode: "half_open_probe_in_flight"
    };
  }
  // circuit.state === "open"
  if (
    circuit.probeInFlightAttemptId !== undefined &&
    circuit.probeInFlightAttemptId !== null
  ) {
    return {
      eligible: false,
      isCircuitProbe: false,
      reasonCode: "half_open_probe_in_flight"
    };
  }
  if (circuit.reopenNotBefore !== undefined) {
    const nowInst = parseUtcTimestamp(now, "now");
    const reopenInst = parseUtcTimestamp(circuit.reopenNotBefore, "reopenNotBefore");
    if (compareInstants(nowInst.instant, reopenInst.instant) < 0) {
      return {
        eligible: false,
        isCircuitProbe: false,
        reasonCode: "open_cooldown_active"
      };
    }
  }
  return {
    eligible: true,
    isCircuitProbe: true,
    reasonCode: "half_open_probe_allowed"
  };
}

// =============================================================================
// Hierarchical WDRR Dispatch Scheduler Service
// =============================================================================

export interface ClaimDispatchBatchInput {
  readonly requestId: string;
  readonly dispatchDomainId: string;
  readonly workerInstanceId: RuntimeInstanceId | string;
  readonly controlEpoch: ControlEpoch | string;
  readonly maximumCount?: number | undefined;
  readonly claimLeaseMs?: bigint | undefined;
}

export interface ClaimDispatchBatchOutput {
  readonly outcome: "prepared" | "idempotent_recovery";
  readonly requestId: string;
  readonly dispatchDomainId: string;
  readonly assignments: readonly {
    readonly attemptId: AttemptId;
    readonly deliveryId: DeliveryId;
    readonly endpointId: EndpointId;
    readonly fencingToken: bigint;
    readonly isCircuitProbe: boolean;
    readonly claimExpiresAt: CanonicalUtcTimestamp;
  }[];
}

export interface DispatchServiceDeps<TTx> {
  readonly uow: UnitOfWorkPort<TTx>;
  readonly dispatchRepo: DispatchRepositoryPort<TTx>;
  readonly clock?: ClockPort | undefined;
  readonly idGenerator?: IdGeneratorPort | undefined;
  readonly telemetry?: TelemetryPort | undefined;
}

function computeDispatchRequestSha256(input: {
  readonly requestId: string;
  readonly dispatchDomainId: string;
  readonly workerInstanceId: RuntimeInstanceId;
  readonly controlEpoch: ControlEpoch;
  readonly maximumCount: number;
}): Sha256Hex {
  const payload: CanonicalJsonValue = {
    request_id: input.requestId,
    dispatch_domain_id: input.dispatchDomainId,
    worker_instance_id: input.workerInstanceId,
    control_epoch: input.controlEpoch,
    maximum_count: input.maximumCount
  };
  return hashCanonicalJson(payload, "rq.dispatch-claim.v1").sha256;
}

export class DispatchService<TTx> {
  readonly #uow: UnitOfWorkPort<TTx>;
  readonly #dispatchRepo: DispatchRepositoryPort<TTx>;
  readonly #clock: ClockPort;
  readonly #ids: IdGeneratorPort;
  readonly #telemetry: TelemetryPort;

  constructor(deps: DispatchServiceDeps<TTx>) {
    this.#uow = deps.uow;
    this.#dispatchRepo = deps.dispatchRepo;
    this.#clock = deps.clock ?? systemClockPort;
    this.#ids = deps.idGenerator ?? cryptoIdGeneratorPort;
    this.#telemetry = deps.telemetry ?? noopTelemetryPort;
  }

  /**
   * Executes one bounded hierarchical WDRR scheduling pass (Tenant -> Project -> Endpoint)
   * with recoverable `dispatch_claim_requests`, exact `1,000,000`-microtoken reservation,
   * and open -> half-open single-probe circuit-breaker gating.
   */
  async claimDispatchBatch(input: ClaimDispatchBatchInput): Promise<ClaimDispatchBatchOutput> {
    const span = this.#telemetry.startSpan("relayquill.dispatch.claim_batch");
    try {
      const workerInstanceId = parseRuntimeInstanceId(
        input.workerInstanceId,
        "workerInstanceId"
      );
      const controlEpoch = parseControlEpoch(input.controlEpoch, "controlEpoch");
      const maximumCount = input.maximumCount ?? DISPATCH_CLAIM_MAX_BATCH;
      if (
        !Number.isInteger(maximumCount) ||
        maximumCount < 1 ||
        maximumCount > DISPATCH_CLAIM_MAX_BATCH
      ) {
        throw new ValidationDomainError({
          code: "INVALID_VALUE",
          message: `Dispatch maximumCount must be an integer in 1..${DISPATCH_CLAIM_MAX_BATCH}`,
          fieldErrors: [{ path: "maximum_count", code: "INVALID_VALUE" }]
        });
      }

      const claimLeaseMs = input.claimLeaseMs ?? DEFAULT_DISPATCH_CLAIM_LEASE_MS;
      const requestSha256 = computeDispatchRequestSha256({
        requestId: input.requestId,
        dispatchDomainId: input.dispatchDomainId,
        workerInstanceId,
        controlEpoch,
        maximumCount
      });

      const nowInstant = this.#clock.nowInstant();
      const now = parseCanonicalUtcTimestamp(formatUtcTimestamp(nowInstant), "now");
      const nowUs = toEpochMicroseconds(nowInstant);

      const out = await this.#uow.inTransaction(async (tx) => {
        const installation = await this.#dispatchRepo.readInstallationAuthority(tx);
        if (
          installation.mode === "recovery_quarantine" ||
          !installation.allowSend ||
          installation.controlEpoch !== controlEpoch
        ) {
          throw new AuthorizationDomainError({
            code: "FORBIDDEN",
            message: "Installation disallows delivery dispatch or control epoch is stale"
          });
        }

        // Step 1: Recoverable dispatch claim request lookup before re-charging fairness/tokens.
        const existingClaim = await this.#dispatchRepo.findDispatchClaimRequest(
          tx,
          input.requestId
        );
        if (existingClaim !== undefined) {
          if (existingClaim.requestSha256 !== requestSha256) {
            throw new ConflictDomainError({
              code: "IDEMPOTENCY_CONFLICT",
              message: `Dispatch claim request "${input.requestId}" reused with different parameters`
            });
          }
          return Object.freeze<ClaimDispatchBatchOutput>({
            outcome: "idempotent_recovery",
            requestId: existingClaim.requestId,
            dispatchDomainId: existingClaim.dispatchDomainId,
            assignments: existingClaim.assignments
          });
        }

        const domains = await this.#dispatchRepo.listDispatchDomains(tx);
        const domain = domains.find((d) => d.dispatchDomainId === input.dispatchDomainId);
        if (domain === undefined || domain.state !== "active") {
          return Object.freeze<ClaimDispatchBatchOutput>({
            outcome: "prepared",
            requestId: input.requestId,
            dispatchDomainId: input.dispatchDomainId,
            assignments: []
          });
        }

        const currentEpoch = domain.policyEpoch;
        const tenantStatesRaw = await this.#dispatchRepo.listWdrrTenantStates(
          tx,
          domain.dispatchDomainId,
          WDRR_MAX_SCOPES_PER_PASS
        );

        const tenantMap = new Map<TenantId, WdrrScopeState & { readonly tenantId: TenantId }>();
        const projectMap = new Map<ProjectId, WdrrScopeState & { readonly projectId: ProjectId }>();
        const endpointMap = new Map<
          EndpointId,
          WdrrScopeState & { readonly endpointId: EndpointId }
        >();
        const bucketCache = new Map<string, MicrotokenRateBucketRecord>();
        const circuitCache = new Map<EndpointId, EndpointCircuitSnapshot>();
        const projectSlotsUsed = new Map<ProjectId, number>();
        const endpointSlotsUsed = new Map<EndpointId, number>();
        const selectedDeliveryIds = new Set<DeliveryId>();
        const selections: Array<PrepareDispatchAttemptInput["selections"][number]> = [];

        for (const t of tenantStatesRaw) {
          tenantMap.set(t.tenantId, normalizeWdrrScopeEpoch(t, currentEpoch));
        }

        let madeProgressInRound = true;
        while (selections.length < maximumCount && madeProgressInRound) {
          madeProgressInRound = false;
          const visitedTenants = new Set<TenantId>();
          const visitedProjects = new Set<ProjectId>();
          const visitedEndpoints = new Set<EndpointId>();

          for (const rawTenant of tenantStatesRaw) {
            if (selections.length >= maximumCount) {
              break;
            }
            let tenantState = tenantMap.get(rawTenant.tenantId)!;
            if (!visitedTenants.has(tenantState.tenantId)) {
              visitedTenants.add(tenantState.tenantId);
              tenantState = creditWdrrScopeOnVisit(tenantState, currentEpoch);
              tenantMap.set(tenantState.tenantId, tenantState);
            }
            if (tenantState.deficitUnits < 1) {
              continue;
            }

            const projectStatesRaw = await this.#dispatchRepo.listWdrrProjectStates(
              tx,
              domain.dispatchDomainId,
              tenantState.tenantId,
              WDRR_MAX_SCOPES_PER_PASS
            );
            let tenantHasEligibleChild = false;

            for (const rawProject of projectStatesRaw) {
              if (selections.length >= maximumCount || tenantState.deficitUnits < 1) {
                break;
              }
              let projectState =
                projectMap.get(rawProject.projectId) ??
                normalizeWdrrScopeEpoch(rawProject, currentEpoch);
              if (!visitedProjects.has(projectState.projectId)) {
                visitedProjects.add(projectState.projectId);
                projectState = creditWdrrScopeOnVisit(projectState, currentEpoch);
              }
              projectMap.set(projectState.projectId, projectState);

              if (projectState.deficitUnits < 1) {
                continue;
              }

              const projUsage = await this.#dispatchRepo.readProjectConcurrencyUsage(
                tx,
                tenantState.tenantId,
                projectState.projectId
              );
              const extraProjSlots = projectSlotsUsed.get(projectState.projectId) ?? 0;
              if (
                projUsage.activeAttemptSlots + extraProjSlots >=
                  projUsage.maxActiveAttemptSlots ||
                projUsage.pendingDeliveries <= 0n
              ) {
                projectState = resetIdleWdrrScopeDeficit(projectState, currentEpoch);
                projectMap.set(projectState.projectId, projectState);
                continue;
              }

              const endpointStatesRaw = await this.#dispatchRepo.listWdrrEndpointStates(
                tx,
                domain.dispatchDomainId,
                projectState.projectId,
                WDRR_MAX_SCOPES_PER_PASS
              );
              let projectHasEligibleEndpoint = false;

              for (const rawEndpoint of endpointStatesRaw) {
                if (
                  selections.length >= maximumCount ||
                  tenantState.deficitUnits < 1 ||
                  projectState.deficitUnits < 1
                ) {
                  break;
                }
                let endpointState =
                  endpointMap.get(rawEndpoint.endpointId) ??
                  normalizeWdrrScopeEpoch(rawEndpoint, currentEpoch);
                if (!visitedEndpoints.has(endpointState.endpointId)) {
                  visitedEndpoints.add(endpointState.endpointId);
                  endpointState = creditWdrrScopeOnVisit(endpointState, currentEpoch);
                }
                endpointMap.set(endpointState.endpointId, endpointState);

                if (endpointState.deficitUnits < 1) {
                  continue;
                }

                const epUsage = await this.#dispatchRepo.readEndpointConcurrencyUsage(
                  tx,
                  endpointState.endpointId
                );
                const extraEpSlots = endpointSlotsUsed.get(endpointState.endpointId) ?? 0;
                if (
                  epUsage.state !== "active" ||
                  epUsage.activeAttemptSlots + extraEpSlots >= epUsage.maxInFlight
                ) {
                  endpointState = resetIdleWdrrScopeDeficit(endpointState, currentEpoch);
                  endpointMap.set(endpointState.endpointId, endpointState);
                  continue;
                }

                const circuit =
                  circuitCache.get(endpointState.endpointId) ??
                  (await this.#dispatchRepo.readEndpointCircuit(tx, endpointState.endpointId));
                circuitCache.set(endpointState.endpointId, circuit);
                const circuitCheck = evaluateCircuitDispatchEligibility(circuit, now);
                if (!circuitCheck.eligible) {
                  endpointState = resetIdleWdrrScopeDeficit(endpointState, currentEpoch);
                  endpointMap.set(endpointState.endpointId, endpointState);
                  continue;
                }

                const dueCandidates = await this.#dispatchRepo.listDueDeliveriesForEndpoint(
                  tx,
                  projectState.projectId,
                  endpointState.endpointId,
                  now,
                  maximumCount
                );
                const candidate = dueCandidates.find(
                  (d) =>
                    !selectedDeliveryIds.has(d.deliveryId) &&
                    d.orderingBlockedByGap !== true
                );
                if (candidate === undefined) {
                  endpointState = resetIdleWdrrScopeDeficit(endpointState, currentEpoch);
                  endpointMap.set(endpointState.endpointId, endpointState);
                  continue;
                }

                // Resolve and reserve 1,000,000 microtokens across tenant/project/endpoint buckets.
                const loadedBuckets = await this.#dispatchRepo.readRateBuckets(tx, {
                  tenantId: tenantState.tenantId,
                  projectId: projectState.projectId,
                  endpointId: endpointState.endpointId
                });
                const activeBuckets: MicrotokenRateBucketRecord[] = [];
                if (loadedBuckets.tenantBucket !== undefined) {
                  const key = `tenant:${loadedBuckets.tenantBucket.scopeId}`;
                  activeBuckets.push(bucketCache.get(key) ?? loadedBuckets.tenantBucket);
                }
                if (loadedBuckets.projectBucket !== undefined) {
                  const key = `project:${loadedBuckets.projectBucket.scopeId}`;
                  activeBuckets.push(bucketCache.get(key) ?? loadedBuckets.projectBucket);
                }
                const epBucketKey = `endpoint:${loadedBuckets.endpointBucket.scopeId}`;
                activeBuckets.push(
                  bucketCache.get(epBucketKey) ?? loadedBuckets.endpointBucket
                );

                const reservation = reserveMicrotokensForPrepare(activeBuckets, nowUs);
                if (!reservation.allowed) {
                  endpointState = resetIdleWdrrScopeDeficit(endpointState, currentEpoch);
                  endpointMap.set(endpointState.endpointId, endpointState);
                  continue;
                }

                for (const updatedBucket of reservation.updatedBuckets) {
                  bucketCache.set(
                    `${updatedBucket.scopeKind}:${updatedBucket.scopeId}`,
                    updatedBucket
                  );
                }

                // Charge 1 fairness unit across Tenant, Project, and Endpoint atomically.
                tenantState = chargeWdrrScopeUnit(tenantState, now);
                projectState = chargeWdrrScopeUnit(projectState, now);
                endpointState = chargeWdrrScopeUnit(endpointState, now);
                tenantMap.set(tenantState.tenantId, tenantState);
                projectMap.set(projectState.projectId, projectState);
                endpointMap.set(endpointState.endpointId, endpointState);

                const attemptId = parseAttemptId(this.#ids.nextUuid(), "attemptId");
                selectedDeliveryIds.add(candidate.deliveryId);
                projectSlotsUsed.set(projectState.projectId, extraProjSlots + 1);
                endpointSlotsUsed.set(endpointState.endpointId, extraEpSlots + 1);
                projectHasEligibleEndpoint = true;
                tenantHasEligibleChild = true;
                madeProgressInRound = true;

                if (circuitCheck.isCircuitProbe) {
                  circuitCache.set(
                    endpointState.endpointId,
                    Object.freeze({
                      ...circuit,
                      state: "half_open",
                      probeGeneration: circuit.probeGeneration + 1n,
                      probeInFlightAttemptId: attemptId
                    })
                  );
                }

                selections.push({
                  deliveryId: candidate.deliveryId,
                  attemptId,
                  tenantId: tenantState.tenantId,
                  projectId: projectState.projectId,
                  endpointId: endpointState.endpointId,
                  endpointVersion: candidate.endpointVersion,
                  isCircuitProbe: circuitCheck.isCircuitProbe,
                  expectedCircuitGeneration: circuit.circuitGeneration,
                  ...(circuitCheck.isCircuitProbe
                    ? { expectedProbeGeneration: circuit.probeGeneration + 1n }
                    : {}),
                  chargeFairnessUnits: 1,
                  reserveMicrotokens: MICROTOKENS_PER_REQUEST,
                  updatedBuckets: reservation.updatedBuckets
                });
              }

              if (!projectHasEligibleEndpoint) {
                projectState = resetIdleWdrrScopeDeficit(projectState, currentEpoch);
                projectMap.set(projectState.projectId, projectState);
              }
            }

            if (!tenantHasEligibleChild) {
              tenantState = resetIdleWdrrScopeDeficit(tenantState, currentEpoch);
              tenantMap.set(tenantState.tenantId, tenantState);
            }
          }
        }

        const updatedDeficits: WdrrScopeState[] = [
          ...tenantMap.values(),
          ...projectMap.values(),
          ...endpointMap.values()
        ];

        const committed: DispatchClaimRequestRecord =
          await this.#dispatchRepo.commitDispatchBatch(tx, {
            requestId: input.requestId,
            dispatchDomainId: domain.dispatchDomainId,
            workerInstanceId,
            controlEpoch,
            maximumCount,
            requestSha256,
            selections,
            updatedDeficits,
            claimLeaseMs,
            now
          });

        return Object.freeze<ClaimDispatchBatchOutput>({
          outcome: "prepared",
          requestId: committed.requestId,
          dispatchDomainId: committed.dispatchDomainId,
          assignments: committed.assignments
        });
      });

      span.end({ code: "OK" });
      return out;
    } catch (err) {
      span.end({ code: "ERROR", message: err instanceof Error ? err.message : "dispatch_failed" });
      throw err;
    }
  }
}
