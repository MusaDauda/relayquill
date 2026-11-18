import { type Temporal } from "@js-temporal/polyfill";
import { createEnumGuard } from "./enums.js";
import { ConflictDomainError, ValidationDomainError } from "./errors.js";
import {
  type AttemptId,
  type CircuitProbeRequestId,
  type ControlEpoch,
  type EndpointCircuitId,
  type EndpointId,
  type RuntimeInstanceId
} from "./ids.js";
import { type DeliveryOutcomeClass } from "./retry-policy.js";
import { assertTransition, type TransitionMatrix } from "./state-machine.js";
import { addMilliseconds, compareInstants, maxInstant, minInstant } from "./time.js";

export const CIRCUIT_STATES = ["closed", "open", "half_open"] as const;
export type CircuitState = (typeof CIRCUIT_STATES)[number];
export const isCircuitState = createEnumGuard(CIRCUIT_STATES);

export const CIRCUIT_PROBE_REQUEST_STATES = [
  "pending",
  "prepared",
  "obsolete",
  "expired"
] as const;
export type CircuitProbeRequestState = (typeof CIRCUIT_PROBE_REQUEST_STATES)[number];
export const isCircuitProbeRequestState = createEnumGuard(CIRCUIT_PROBE_REQUEST_STATES);

export const CIRCUIT_FAILURE_THRESHOLD = 5 as const;
export const CIRCUIT_INITIAL_OPEN_DELAY_MS = 60_000n;
export const CIRCUIT_MAX_OPEN_DELAY_MS = 900_000n;
export const CIRCUIT_OPEN_DELAY_MULTIPLIER = 2n;
export const CIRCUIT_DIAGNOSTIC_WINDOW_MS = 60_000n;
export const CIRCUIT_PROBE_DEFERRAL_MIN_DELAY_MS = 1_000n;
export const CIRCUIT_PROBE_REQUEST_TTL_MS = 300_000n;

export const ALLOWED_CIRCUIT_TRANSITIONS: TransitionMatrix<CircuitState> = Object.freeze({
  closed: ["closed", "open"],
  open: ["half_open"],
  half_open: ["closed", "open"]
});

export const ALLOWED_CIRCUIT_PROBE_REQUEST_TRANSITIONS: TransitionMatrix<CircuitProbeRequestState> =
  Object.freeze({
    pending: ["prepared", "obsolete", "expired"],
    prepared: ["obsolete", "expired"],
    obsolete: [],
    expired: []
  });

export function computeCircuitOpenDelayMs(reopenCount: number): bigint {
  if (!Number.isInteger(reopenCount) || reopenCount < 0) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: "reopenCount must be a non-negative integer",
      fieldErrors: [{ path: "reopen_count", code: "INVALID_VALUE" }]
    });
  }
  let delay = CIRCUIT_INITIAL_OPEN_DELAY_MS;
  for (let i = 0; i < reopenCount; i += 1) {
    delay = delay * CIRCUIT_OPEN_DELAY_MULTIPLIER;
    if (delay >= CIRCUIT_MAX_OPEN_DELAY_MS) {
      return CIRCUIT_MAX_OPEN_DELAY_MS;
    }
  }
  return delay > CIRCUIT_MAX_OPEN_DELAY_MS ? CIRCUIT_MAX_OPEN_DELAY_MS : delay;
}

export interface EndpointCircuitSnapshot {
  readonly circuitId: EndpointCircuitId;
  readonly endpointId: EndpointId;
  readonly endpointVersion: bigint;
  readonly state: CircuitState;
  readonly circuitGeneration: bigint;
  readonly probeGeneration: bigint;
  readonly consecutiveTransientFailures: number;
  readonly reopenCount: number;
  readonly reopenNotBefore: Temporal.Instant | null;
  readonly probeAttemptId: AttemptId | null;
  readonly probeOwnerInstanceId: RuntimeInstanceId | null;
  readonly probeControlEpoch: ControlEpoch | null;
  readonly probeExpiresAt: Temporal.Instant | null;
  readonly windowStartedAt: Temporal.Instant;
  readonly windowSuccessCount: number;
  readonly windowFailureCount: number;
}

export interface ProbeClaimInput {
  readonly probeAttemptId: AttemptId;
  readonly probeOwnerInstanceId: RuntimeInstanceId;
  readonly probeControlEpoch: ControlEpoch;
  readonly claimExpiresAt: Temporal.Instant;
  readonly deliveryDeadlineAt: Temporal.Instant;
  readonly now: Temporal.Instant;
}

export function claimCircuitProbe(
  circuit: EndpointCircuitSnapshot,
  input: ProbeClaimInput
): EndpointCircuitSnapshot {
  assertTransition("endpoint_circuit", ALLOWED_CIRCUIT_TRANSITIONS, circuit.state, "half_open", {
    kind: "endpoint_circuit",
    id: circuit.circuitId
  });
  if (
    circuit.reopenNotBefore !== null &&
    compareInstants(input.now, circuit.reopenNotBefore) < 0
  ) {
    throw new ConflictDomainError({
      code: "STATE_TRANSITION_NOT_ALLOWED",
      message: "Circuit open cooldown has not elapsed for probe claim",
      resourceRef: { kind: "endpoint_circuit", id: circuit.circuitId }
    });
  }
  const probeExpiresAt = minInstant(input.claimExpiresAt, input.deliveryDeadlineAt);
  return Object.freeze({
    ...circuit,
    state: "half_open",
    probeGeneration: circuit.probeGeneration + 1n,
    probeAttemptId: input.probeAttemptId,
    probeOwnerInstanceId: input.probeOwnerInstanceId,
    probeControlEpoch: input.probeControlEpoch,
    probeExpiresAt
  });
}

export interface ProbeDeferralInput {
  readonly expectedCircuitGeneration: bigint;
  readonly expectedProbeGeneration: bigint;
  readonly probeAttemptId: AttemptId;
  readonly ownerInstanceId: RuntimeInstanceId;
  readonly controlEpoch: ControlEpoch;
  readonly decidedAt: Temporal.Instant;
  readonly prerequisiteDelayUntil?: Temporal.Instant | undefined;
}

export function deferUnstartedCircuitProbe(
  circuit: EndpointCircuitSnapshot,
  input: ProbeDeferralInput
): EndpointCircuitSnapshot {
  if (circuit.state !== "half_open") {
    throw new ConflictDomainError({
      code: "STATE_TRANSITION_NOT_ALLOWED",
      message: `Cannot defer probe when circuit state is "${circuit.state}"`,
      resourceRef: { kind: "endpoint_circuit", id: circuit.circuitId }
    });
  }
  if (
    circuit.circuitGeneration !== input.expectedCircuitGeneration ||
    circuit.probeGeneration !== input.expectedProbeGeneration ||
    circuit.probeAttemptId !== input.probeAttemptId ||
    circuit.probeOwnerInstanceId !== input.ownerInstanceId ||
    circuit.probeControlEpoch !== input.controlEpoch
  ) {
    throw new ConflictDomainError({
      code: "VERSION_CONFLICT",
      message: "Probe deferral fencing mismatch",
      resourceRef: { kind: "endpoint_circuit", id: circuit.circuitId }
    });
  }

  const minDelay = addMilliseconds(input.decidedAt, CIRCUIT_PROBE_DEFERRAL_MIN_DELAY_MS);
  const reopenNotBefore =
    input.prerequisiteDelayUntil !== undefined
      ? maxInstant(minDelay, input.prerequisiteDelayUntil)
      : minDelay;

  return Object.freeze({
    ...circuit,
    state: "open",
    reopenNotBefore,
    probeAttemptId: null,
    probeOwnerInstanceId: null,
    probeControlEpoch: null,
    probeExpiresAt: null
    // Note: reopenCount is intentionally preserved on unstarted probe deferral.
  });
}

export interface CircuitObservationInput {
  readonly circuitGenerationAtStart: bigint;
  readonly probeGenerationAtStart?: bigint | undefined;
  readonly attemptId: AttemptId;
  readonly ownerInstanceId?: RuntimeInstanceId | undefined;
  readonly controlEpoch?: ControlEpoch | undefined;
  readonly decidedAt: Temporal.Instant;
  readonly outcomeClass: DeliveryOutcomeClass | "benign_deferral" | "abandoned_started_probe";
}

export interface CircuitObservationResult {
  readonly applied: boolean;
  readonly circuit: EndpointCircuitSnapshot;
  // Security quarantine lives on Endpoint and is never cleared by circuit recovery.
  readonly clearsSecurityQuarantine: false;
}

function advanceDiagnosticWindow(
  circuit: EndpointCircuitSnapshot,
  decidedAt: Temporal.Instant,
  isSuccess: boolean,
  isFailure: boolean
): {
  readonly windowStartedAt: Temporal.Instant;
  readonly windowSuccessCount: number;
  readonly windowFailureCount: number;
} {
  const windowEnd = addMilliseconds(circuit.windowStartedAt, CIRCUIT_DIAGNOSTIC_WINDOW_MS);
  const rolledOver = compareInstants(decidedAt, windowEnd) >= 0;
  const baseSuccess = rolledOver ? 0 : circuit.windowSuccessCount;
  const baseFailure = rolledOver ? 0 : circuit.windowFailureCount;
  return {
    windowStartedAt: rolledOver ? decidedAt : circuit.windowStartedAt,
    windowSuccessCount: baseSuccess + (isSuccess ? 1 : 0),
    windowFailureCount: baseFailure + (isFailure ? 1 : 0)
  };
}

export function applyCircuitObservation(
  circuit: EndpointCircuitSnapshot,
  input: CircuitObservationInput
): CircuitObservationResult {
  if (input.circuitGenerationAtStart !== circuit.circuitGeneration) {
    return Object.freeze({
      applied: false,
      circuit,
      clearsSecurityQuarantine: false
    });
  }

  if (input.outcomeClass === "benign_deferral") {
    return Object.freeze({
      applied: false,
      circuit,
      clearsSecurityQuarantine: false
    });
  }

  const isSuccess = input.outcomeClass === "acknowledged";
  const isTransientFailure =
    input.outcomeClass === "transient_http" ||
    input.outcomeClass === "transport_unknown" ||
    input.outcomeClass === "abandoned_started_probe";
  const isPermanentHttp =
    input.outcomeClass === "permanent_http" || input.outcomeClass === "permanent_redirect";

  if (circuit.state === "closed") {
    if (input.outcomeClass === "permanent_policy_or_security") {
      return Object.freeze({
        applied: false,
        circuit,
        clearsSecurityQuarantine: false
      });
    }

    const diag = advanceDiagnosticWindow(
      circuit,
      input.decidedAt,
      isSuccess,
      isTransientFailure || isPermanentHttp
    );

    if (isSuccess || isPermanentHttp) {
      return Object.freeze({
        applied: true,
        clearsSecurityQuarantine: false,
        circuit: Object.freeze({
          ...circuit,
          consecutiveTransientFailures: 0,
          windowStartedAt: diag.windowStartedAt,
          windowSuccessCount: diag.windowSuccessCount,
          windowFailureCount: diag.windowFailureCount
        })
      });
    }

    if (isTransientFailure) {
      const nextFailures = circuit.consecutiveTransientFailures + 1;
      if (nextFailures >= CIRCUIT_FAILURE_THRESHOLD) {
        return Object.freeze({
          applied: true,
          clearsSecurityQuarantine: false,
          circuit: Object.freeze({
            ...circuit,
            state: "open",
            circuitGeneration: circuit.circuitGeneration + 1n,
            consecutiveTransientFailures: CIRCUIT_FAILURE_THRESHOLD,
            reopenCount: 0,
            reopenNotBefore: addMilliseconds(input.decidedAt, CIRCUIT_INITIAL_OPEN_DELAY_MS),
            probeAttemptId: null,
            probeOwnerInstanceId: null,
            probeControlEpoch: null,
            probeExpiresAt: null,
            windowStartedAt: input.decidedAt,
            windowSuccessCount: 0,
            windowFailureCount: 0
          })
        });
      }

      return Object.freeze({
        applied: true,
        clearsSecurityQuarantine: false,
        circuit: Object.freeze({
          ...circuit,
          consecutiveTransientFailures: nextFailures,
          windowStartedAt: diag.windowStartedAt,
          windowSuccessCount: diag.windowSuccessCount,
          windowFailureCount: diag.windowFailureCount
        })
      });
    }
  }

  if (circuit.state === "half_open") {
    if (
      input.probeGenerationAtStart !== circuit.probeGeneration ||
      input.attemptId !== circuit.probeAttemptId ||
      input.ownerInstanceId !== circuit.probeOwnerInstanceId ||
      input.controlEpoch !== circuit.probeControlEpoch
    ) {
      return Object.freeze({
        applied: false,
        circuit,
        clearsSecurityQuarantine: false
      });
    }

    if (isSuccess) {
      return Object.freeze({
        applied: true,
        clearsSecurityQuarantine: false,
        circuit: Object.freeze({
          ...circuit,
          state: "closed",
          circuitGeneration: circuit.circuitGeneration + 1n,
          consecutiveTransientFailures: 0,
          reopenCount: 0,
          reopenNotBefore: null,
          probeAttemptId: null,
          probeOwnerInstanceId: null,
          probeControlEpoch: null,
          probeExpiresAt: null,
          windowStartedAt: input.decidedAt,
          windowSuccessCount: 0,
          windowFailureCount: 0
        })
      });
    }

    // Both transient failures and permanent HTTP responses conservatively reopen the half-open circuit.
    const nextReopenCount = circuit.reopenCount + 1;
    const openDelayMs = computeCircuitOpenDelayMs(nextReopenCount);
    return Object.freeze({
      applied: true,
      clearsSecurityQuarantine: false,
      circuit: Object.freeze({
        ...circuit,
        state: "open",
        circuitGeneration: circuit.circuitGeneration + 1n,
        reopenCount: nextReopenCount,
        reopenNotBefore: addMilliseconds(input.decidedAt, openDelayMs),
        probeAttemptId: null,
        probeOwnerInstanceId: null,
        probeControlEpoch: null,
        probeExpiresAt: null,
        windowStartedAt: input.decidedAt,
        windowSuccessCount: 0,
        windowFailureCount: 0
      })
    });
  }

  // Circuit is open: stale in-flight observations from older generations were already fenced above.
  return Object.freeze({
    applied: false,
    circuit,
    clearsSecurityQuarantine: false
  });
}

export function transitionCircuitProbeRequestState(
  from: CircuitProbeRequestState,
  to: CircuitProbeRequestState,
  requestId: CircuitProbeRequestId
): CircuitProbeRequestState {
  assertTransition(
    "circuit_probe_request",
    ALLOWED_CIRCUIT_PROBE_REQUEST_TRANSITIONS,
    from,
    to,
    { kind: "circuit_probe_request", id: requestId }
  );
  return to;
}
