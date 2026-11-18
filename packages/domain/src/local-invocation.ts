import { type Temporal } from "@js-temporal/polyfill";
import { createEnumGuard } from "./enums.js";
import { ConflictDomainError } from "./errors.js";
import { type AttemptId, type ControlEpoch, type RuntimeInstanceId } from "./ids.js";
import { assertTransition, type TransitionMatrix } from "./state-machine.js";

export const LOCAL_INVOCATION_STATES = [
  "permission_pending",
  "permission_accepted",
  "invoking",
  "finished",
  "aborted",
  "unusable"
] as const;
export type LocalInvocationState = (typeof LOCAL_INVOCATION_STATES)[number];
export const isLocalInvocationState = createEnumGuard(LOCAL_INVOCATION_STATES);

export const TERMINAL_LOCAL_INVOCATION_STATES = [
  "finished",
  "aborted",
  "unusable"
] as const;
export type TerminalLocalInvocationState = (typeof TERMINAL_LOCAL_INVOCATION_STATES)[number];

export const LOCAL_INVOCATION_MAX_NETWORK_NS = 10_000_000_000n;

export const ALLOWED_LOCAL_INVOCATION_TRANSITIONS: TransitionMatrix<LocalInvocationState> =
  Object.freeze({
    permission_pending: ["permission_accepted", "aborted", "unusable"],
    permission_accepted: ["invoking", "aborted", "unusable"],
    invoking: ["finished", "aborted", "unusable"],
    finished: [],
    aborted: [],
    unusable: []
  });

export function isTerminalLocalInvocationState(
  state: LocalInvocationState
): state is TerminalLocalInvocationState {
  return state === "finished" || state === "aborted" || state === "unusable";
}

export interface LocalInvocationOwner {
  readonly workerInstanceId: RuntimeInstanceId;
  readonly attemptId: AttemptId;
  readonly fencingToken: bigint;
  readonly controlEpoch: ControlEpoch;
}

export interface LocalInvocationSnapshot {
  readonly owner: LocalInvocationOwner;
  readonly state: LocalInvocationState;
  readonly m0Ns: bigint;
  readonly m1Ns: bigint | null;
  readonly localCutoffNs: bigint | null;
}

export interface CutoffCalculationInput {
  readonly m0Ns: bigint;
  readonly m1Ns: bigint;
  readonly requestDeadlineAt: Temporal.Instant;
  readonly acceptanceDbClock: Temporal.Instant;
}

export type CutoffCalculationResult =
  | {
      readonly usable: true;
      readonly elapsedNs: bigint;
      readonly remainingBudgetNs: bigint;
      readonly localCutoffNs: bigint;
    }
  | {
      readonly usable: false;
      readonly terminalState: "unusable" | "aborted";
      readonly reason: "monotonic_clock_discontinuity" | "deadline_budget_exhausted";
      readonly elapsedNs: bigint;
    };

export function computeLocalInvocationCutoff(
  input: CutoffCalculationInput
): CutoffCalculationResult {
  const elapsedNs = input.m1Ns - input.m0Ns;
  if (elapsedNs < 0n) {
    return Object.freeze({
      usable: false,
      terminalState: "unusable",
      reason: "monotonic_clock_discontinuity",
      elapsedNs
    });
  }

  const serverRemainingNs =
    input.requestDeadlineAt.epochNanoseconds - input.acceptanceDbClock.epochNanoseconds;
  if (serverRemainingNs <= 0n) {
    return Object.freeze({
      usable: false,
      terminalState: "aborted",
      reason: "deadline_budget_exhausted",
      elapsedNs
    });
  }

  const maxNetworkRemaining = LOCAL_INVOCATION_MAX_NETWORK_NS - elapsedNs;
  const serverRemainingAfterRpc = serverRemainingNs - elapsedNs;
  const remainingBudgetNs =
    maxNetworkRemaining <= serverRemainingAfterRpc
      ? maxNetworkRemaining
      : serverRemainingAfterRpc;

  if (remainingBudgetNs <= 0n) {
    return Object.freeze({
      usable: false,
      terminalState: "aborted",
      reason: "deadline_budget_exhausted",
      elapsedNs
    });
  }

  return Object.freeze({
    usable: true,
    elapsedNs,
    remainingBudgetNs,
    localCutoffNs: input.m1Ns + remainingBudgetNs
  });
}

function assertMatchingOwner(
  expected: LocalInvocationOwner,
  actual: LocalInvocationOwner
): void {
  if (
    expected.workerInstanceId !== actual.workerInstanceId ||
    expected.attemptId !== actual.attemptId ||
    expected.fencingToken !== actual.fencingToken ||
    expected.controlEpoch !== actual.controlEpoch
  ) {
    throw new ConflictDomainError({
      code: "VERSION_CONFLICT",
      message: "LocalInvocation owner identity mismatch",
      resourceRef: { kind: "delivery_attempt", id: expected.attemptId }
    });
  }
}

export function resolveLocalInvocationPermission(
  snapshot: LocalInvocationSnapshot,
  input: CutoffCalculationInput & { readonly owner: LocalInvocationOwner }
): LocalInvocationSnapshot {
  assertMatchingOwner(snapshot.owner, input.owner);
  assertTransition(
    "local_invocation",
    ALLOWED_LOCAL_INVOCATION_TRANSITIONS,
    snapshot.state,
    "permission_accepted",
    { kind: "delivery_attempt", id: snapshot.owner.attemptId }
  );

  const cutoff = computeLocalInvocationCutoff(input);
  if (!cutoff.usable) {
    assertTransition(
      "local_invocation",
      ALLOWED_LOCAL_INVOCATION_TRANSITIONS,
      snapshot.state,
      cutoff.terminalState,
      { kind: "delivery_attempt", id: snapshot.owner.attemptId }
    );
    return Object.freeze({
      ...snapshot,
      state: cutoff.terminalState,
      m1Ns: input.m1Ns,
      localCutoffNs: null
    });
  }

  return Object.freeze({
    ...snapshot,
    state: "permission_accepted",
    m1Ns: input.m1Ns,
    localCutoffNs: cutoff.localCutoffNs
  });
}

export function enterLocalInvocation(
  snapshot: LocalInvocationSnapshot,
  owner: LocalInvocationOwner,
  nowMonotonicNs: bigint,
  authorityValid: boolean
): LocalInvocationSnapshot {
  assertMatchingOwner(snapshot.owner, owner);
  if (snapshot.state !== "permission_accepted" || snapshot.localCutoffNs === null) {
    assertTransition(
      "local_invocation",
      ALLOWED_LOCAL_INVOCATION_TRANSITIONS,
      snapshot.state,
      "invoking",
      { kind: "delivery_attempt", id: snapshot.owner.attemptId }
    );
  }
  if (!authorityValid) {
    return Object.freeze({
      ...snapshot,
      state: "aborted"
    });
  }
  if (nowMonotonicNs < snapshot.m0Ns || nowMonotonicNs < (snapshot.m1Ns ?? snapshot.m0Ns)) {
    return Object.freeze({
      ...snapshot,
      state: "unusable"
    });
  }
  if (snapshot.localCutoffNs === null || nowMonotonicNs >= snapshot.localCutoffNs) {
    return Object.freeze({
      ...snapshot,
      state: "aborted"
    });
  }
  assertTransition(
    "local_invocation",
    ALLOWED_LOCAL_INVOCATION_TRANSITIONS,
    snapshot.state,
    "invoking",
    { kind: "delivery_attempt", id: snapshot.owner.attemptId }
  );
  return Object.freeze({
    ...snapshot,
    state: "invoking"
  });
}

export function finishLocalInvocation(
  snapshot: LocalInvocationSnapshot,
  outcome: TerminalLocalInvocationState
): LocalInvocationSnapshot {
  assertTransition(
    "local_invocation",
    ALLOWED_LOCAL_INVOCATION_TRANSITIONS,
    snapshot.state,
    outcome,
    { kind: "delivery_attempt", id: snapshot.owner.attemptId }
  );
  return Object.freeze({
    ...snapshot,
    state: outcome
  });
}
