import {
  ConflictDomainError,
  NotFoundDomainError,
  enterLocalInvocation,
  finishLocalInvocation,
  isTerminalLocalInvocationState,
  resolveLocalInvocationPermission,
  type AttemptId,
  type LocalInvocationOwner,
  type LocalInvocationSnapshot,
  type TerminalLocalInvocationState
} from "@relayquill/domain";
import { type Temporal } from "@js-temporal/polyfill";

export interface MonotonicClock {
  nowNs(): bigint;
}

export const nodeMonotonicClock: MonotonicClock = Object.freeze({
  nowNs(): bigint {
    return process.hrtime.bigint();
  }
});

export interface ResolvePermissionInput {
  readonly owner: LocalInvocationOwner;
  readonly requestDeadlineAt: Temporal.Instant;
  readonly acceptanceDbClock: Temporal.Instant;
}

export interface PermissionResolutionResult {
  readonly usable: boolean;
  readonly snapshot: LocalInvocationSnapshot;
  readonly remainingBudgetNs: bigint;
}

export interface EnterInvocationOptions {
  readonly shuttingDown?: boolean | undefined;
  readonly authorityValid?: boolean | undefined;
  readonly parentSignal?: AbortSignal | undefined;
}

export type EnterInvocationResult =
  | {
      readonly allowed: true;
      readonly snapshot: LocalInvocationSnapshot;
      readonly remainingBudgetNs: bigint;
      readonly signal: AbortSignal;
    }
  | {
      readonly allowed: false;
      readonly snapshot: LocalInvocationSnapshot;
      readonly remainingBudgetNs: 0n;
      readonly reason:
        | "shutting_down"
        | "authority_invalid"
        | "monotonic_clock_discontinuity"
        | "deadline_budget_exhausted"
        | "invalid_state";
    };

export interface BudgetCheckpointResult {
  readonly ok: boolean;
  readonly remainingBudgetNs: bigint;
  readonly reason?:
    | "shutting_down"
    | "authority_invalid"
    | "monotonic_clock_discontinuity"
    | "deadline_budget_exhausted"
    | "aborted"
    | undefined;
}

interface InvocationEntry {
  snapshot: LocalInvocationSnapshot;
  lastObservedNs: bigint;
  controller: AbortController | null;
  timer: ReturnType<typeof setTimeout> | null;
  cleanupListener: (() => void) | null;
}

export class SendDeadlineManager {
  readonly #clock: MonotonicClock;
  readonly #invocations = new Map<AttemptId, InvocationEntry>();

  constructor(clock: MonotonicClock = nodeMonotonicClock) {
    this.#clock = clock;
  }

  getSnapshot(attemptId: AttemptId): LocalInvocationSnapshot | undefined {
    return this.#invocations.get(attemptId)?.snapshot;
  }

  activeCount(): number {
    let count = 0;
    for (const entry of this.#invocations.values()) {
      if (!isTerminalLocalInvocationState(entry.snapshot.state)) {
        count += 1;
      }
    }
    return count;
  }

  beginPermission(owner: LocalInvocationOwner): LocalInvocationSnapshot {
    if (this.#invocations.has(owner.attemptId)) {
      throw new ConflictDomainError({
        code: "VERSION_CONFLICT",
        message: `Local invocation already exists for attempt ${owner.attemptId}`,
        resourceRef: { kind: "delivery_attempt", id: owner.attemptId }
      });
    }
    const m0Ns = this.#clock.nowNs();
    const snapshot: LocalInvocationSnapshot = Object.freeze({
      owner: Object.freeze({ ...owner }),
      state: "permission_pending",
      m0Ns,
      m1Ns: null,
      localCutoffNs: null
    });
    this.#invocations.set(owner.attemptId, {
      snapshot,
      lastObservedNs: m0Ns,
      controller: null,
      timer: null,
      cleanupListener: null
    });
    return snapshot;
  }

  resolvePermission(
    attemptId: AttemptId,
    input: ResolvePermissionInput
  ): PermissionResolutionResult {
    const entry = this.#requireEntry(attemptId);
    const m1Ns = this.#clock.nowNs();
    if (m1Ns >= entry.lastObservedNs) {
      entry.lastObservedNs = m1Ns;
    }

    const updated = resolveLocalInvocationPermission(entry.snapshot, {
      owner: input.owner,
      m0Ns: entry.snapshot.m0Ns,
      m1Ns,
      requestDeadlineAt: input.requestDeadlineAt,
      acceptanceDbClock: input.acceptanceDbClock
    });
    entry.snapshot = updated;

    if (updated.state !== "permission_accepted" || updated.localCutoffNs === null) {
      return Object.freeze({
        usable: false,
        snapshot: updated,
        remainingBudgetNs: 0n
      });
    }

    const remainingBudgetNs = updated.localCutoffNs - m1Ns;
    return Object.freeze({
      usable: remainingBudgetNs > 0n,
      snapshot: updated,
      remainingBudgetNs: remainingBudgetNs > 0n ? remainingBudgetNs : 0n
    });
  }

  checkpointAndEnter(
    attemptId: AttemptId,
    owner: LocalInvocationOwner,
    options: EnterInvocationOptions = {}
  ): EnterInvocationResult {
    const entry = this.#requireEntry(attemptId);
    const nowNs = this.#clock.nowNs();
    const monotonicOk = nowNs >= entry.lastObservedNs;
    if (monotonicOk) {
      entry.lastObservedNs = nowNs;
    }

    const shuttingDown = options.shuttingDown === true || options.parentSignal?.aborted === true;
    const authorityValid = options.authorityValid !== false;

    if (
      entry.snapshot.owner.workerInstanceId !== owner.workerInstanceId ||
      entry.snapshot.owner.attemptId !== owner.attemptId ||
      entry.snapshot.owner.fencingToken !== owner.fencingToken ||
      entry.snapshot.owner.controlEpoch !== owner.controlEpoch
    ) {
      throw new ConflictDomainError({
        code: "VERSION_CONFLICT",
        message: "LocalInvocation owner identity mismatch",
        resourceRef: { kind: "delivery_attempt", id: attemptId }
      });
    }

    if (entry.snapshot.state !== "permission_accepted" || entry.snapshot.localCutoffNs === null) {
      return Object.freeze({
        allowed: false,
        snapshot: entry.snapshot,
        remainingBudgetNs: 0n,
        reason:
          entry.snapshot.state === "unusable"
            ? "monotonic_clock_discontinuity"
            : entry.snapshot.state === "aborted"
              ? "deadline_budget_exhausted"
              : "invalid_state"
      });
    }

    if (!monotonicOk || nowNs < entry.snapshot.m0Ns || nowNs < (entry.snapshot.m1Ns ?? entry.snapshot.m0Ns)) {
      const next = enterLocalInvocation(entry.snapshot, owner, nowNs, true);
      entry.snapshot = next;
      return Object.freeze({
        allowed: false,
        snapshot: next,
        remainingBudgetNs: 0n,
        reason: "monotonic_clock_discontinuity"
      });
    }

    if (shuttingDown || !authorityValid) {
      const next = enterLocalInvocation(entry.snapshot, owner, nowNs, false);
      entry.snapshot = next;
      return Object.freeze({
        allowed: false,
        snapshot: next,
        remainingBudgetNs: 0n,
        reason: shuttingDown ? "shutting_down" : "authority_invalid"
      });
    }

    const next = enterLocalInvocation(entry.snapshot, owner, nowNs, true);
    entry.snapshot = next;

    if (next.state !== "invoking" || next.localCutoffNs === null) {
      return Object.freeze({
        allowed: false,
        snapshot: next,
        remainingBudgetNs: 0n,
        reason: next.state === "unusable" ? "monotonic_clock_discontinuity" : "deadline_budget_exhausted"
      });
    }

    const remainingBudgetNs = next.localCutoffNs - nowNs;
    if (remainingBudgetNs <= 0n) {
      entry.snapshot = finishLocalInvocation(next, "aborted");
      return Object.freeze({
        allowed: false,
        snapshot: entry.snapshot,
        remainingBudgetNs: 0n,
        reason: "deadline_budget_exhausted"
      });
    }

    const controller = new AbortController();
    entry.controller = controller;

    if (options.parentSignal !== undefined) {
      const onParentAbort = (): void => {
        controller.abort(options.parentSignal?.reason ?? new Error("Parent signal aborted"));
      };
      if (options.parentSignal.aborted) {
        onParentAbort();
      } else {
        options.parentSignal.addEventListener("abort", onParentAbort, { once: true });
        entry.cleanupListener = () => {
          options.parentSignal?.removeEventListener("abort", onParentAbort);
        };
      }
    }

    const timeoutMs = Math.max(1, Number((remainingBudgetNs + 999_999n) / 1_000_000n));
    const timer = setTimeout(() => {
      if (!controller.signal.aborted) {
        controller.abort(new Error("Local send deadline elapsed"));
      }
    }, timeoutMs);
    timer.unref();
    entry.timer = timer;

    return Object.freeze({
      allowed: true,
      snapshot: next,
      remainingBudgetNs,
      signal: controller.signal
    });
  }

  checkRemainingBudget(
    attemptId: AttemptId,
    owner: LocalInvocationOwner,
    options: { readonly shuttingDown?: boolean | undefined; readonly authorityValid?: boolean | undefined } = {}
  ): BudgetCheckpointResult {
    const entry = this.#requireEntry(attemptId);
    if (
      entry.snapshot.owner.workerInstanceId !== owner.workerInstanceId ||
      entry.snapshot.owner.fencingToken !== owner.fencingToken ||
      entry.snapshot.owner.controlEpoch !== owner.controlEpoch
    ) {
      throw new ConflictDomainError({
        code: "VERSION_CONFLICT",
        message: "LocalInvocation owner identity mismatch",
        resourceRef: { kind: "delivery_attempt", id: attemptId }
      });
    }

    if (entry.controller?.signal.aborted === true) {
      return Object.freeze({ ok: false, remainingBudgetNs: 0n, reason: "aborted" });
    }
    if (options.shuttingDown === true) {
      entry.controller?.abort(new Error("Process draining"));
      return Object.freeze({ ok: false, remainingBudgetNs: 0n, reason: "shutting_down" });
    }
    if (options.authorityValid === false) {
      entry.controller?.abort(new Error("Runtime authority invalidated"));
      return Object.freeze({ ok: false, remainingBudgetNs: 0n, reason: "authority_invalid" });
    }

    const nowNs = this.#clock.nowNs();
    if (nowNs < entry.lastObservedNs) {
      entry.controller?.abort(new Error("Monotonic clock discontinuity detected"));
      return Object.freeze({
        ok: false,
        remainingBudgetNs: 0n,
        reason: "monotonic_clock_discontinuity"
      });
    }
    entry.lastObservedNs = nowNs;

    if (entry.snapshot.localCutoffNs === null) {
      return Object.freeze({ ok: false, remainingBudgetNs: 0n, reason: "aborted" });
    }
    const remaining = entry.snapshot.localCutoffNs - nowNs;
    if (remaining <= 0n) {
      entry.controller?.abort(new Error("Local send deadline elapsed"));
      return Object.freeze({
        ok: false,
        remainingBudgetNs: 0n,
        reason: "deadline_budget_exhausted"
      });
    }
    return Object.freeze({ ok: true, remainingBudgetNs: remaining });
  }

  finish(attemptId: AttemptId, outcome: TerminalLocalInvocationState): LocalInvocationSnapshot {
    const entry = this.#requireEntry(attemptId);
    this.#clearEntryTimers(entry);
    if (isTerminalLocalInvocationState(entry.snapshot.state)) {
      return entry.snapshot;
    }
    if (outcome === "aborted" || outcome === "unusable") {
      if (entry.controller !== null && !entry.controller.signal.aborted) {
        entry.controller.abort(new Error(`Invocation finished as ${outcome}`));
      }
    }
    const next = finishLocalInvocation(entry.snapshot, outcome);
    entry.snapshot = next;
    return next;
  }

  abortAll(reason = "Runtime draining"): void {
    for (const entry of this.#invocations.values()) {
      this.#clearEntryTimers(entry);
      if (entry.controller !== null && !entry.controller.signal.aborted) {
        entry.controller.abort(new Error(reason));
      }
      if (!isTerminalLocalInvocationState(entry.snapshot.state)) {
        entry.snapshot = finishLocalInvocation(entry.snapshot, "aborted");
      }
    }
  }

  #clearEntryTimers(entry: InvocationEntry): void {
    if (entry.timer !== null) {
      clearTimeout(entry.timer);
      entry.timer = null;
    }
    if (entry.cleanupListener !== null) {
      entry.cleanupListener();
      entry.cleanupListener = null;
    }
  }

  #requireEntry(attemptId: AttemptId): InvocationEntry {
    const entry = this.#invocations.get(attemptId);
    if (entry === undefined) {
      throw new NotFoundDomainError({
        code: "NOT_FOUND",
        message: `Unknown local invocation for attempt ${attemptId}`,
        resourceRef: { kind: "delivery_attempt", id: attemptId }
      });
    }
    return entry;
  }
}
