import test from "node:test";
import assert from "node:assert/strict";
import {
  InMemoryRuntimeRegistryStore,
  RuntimeLifecycleManager,
  SendDeadlineManager,
  abortableDelay,
  nodeMonotonicClock
} from "@relayquill/runtime";
import {
  addMilliseconds,
  parseAttemptId,
  parseControlEpoch,
  parseRuntimeInstanceId,
  parseUtcTimestamp
} from "@relayquill/domain";

const WORKER_ID = parseRuntimeInstanceId("00000000-0000-4000-8000-000000000101");
const EPOCH = parseControlEpoch("00000000-0000-4000-8000-000000000202");

test("SendDeadlineManager enforces monotonic clock, RPC budget subtraction, and pause cutoffs", () => {
  let fakeNowNs = 1_000_000_000_000n;
  const manager = new SendDeadlineManager({ nowNs: () => fakeNowNs });
  const dbClock = parseUtcTimestamp("2026-11-18T06:00:00.000000Z").instant;
  const deadline = addMilliseconds(dbClock, 6_000);

  const attempt1 = parseAttemptId("00000000-0000-4000-8000-000000000301");
  const owner1 = {
    workerInstanceId: WORKER_ID,
    attemptId: attempt1,
    fencingToken: 1n,
    controlEpoch: EPOCH
  };

  const s0 = manager.beginPermission(owner1);
  assert.equal(s0.state, "permission_pending");

  // Duplicate attempt registration rejected
  assert.throws(() => manager.beginPermission(owner1), /already exists/);

  // 1500ms RPC elapsed -> remaining budget = min(10000-1500, 6000-1500) = 4500ms
  fakeNowNs += 1_500_000_000n;
  const perm = manager.resolvePermission(attempt1, {
    owner: owner1,
    requestDeadlineAt: deadline,
    acceptanceDbClock: dbClock
  });
  assert.equal(perm.usable, true);
  assert.equal(perm.remainingBudgetNs, 4_500_000_000n);

  fakeNowNs += 500_000_000n;
  const entered = manager.checkpointAndEnter(attempt1, owner1);
  assert.equal(entered.allowed, true);
  if (entered.allowed) {
    assert.equal(entered.remainingBudgetNs, 4_000_000_000n);
    assert.equal(entered.signal.aborted, false);
  }

  // Duplicate enter attempt is denied cleanly without double invocation
  const secondEnter = manager.checkpointAndEnter(attempt1, owner1);
  assert.equal(secondEnter.allowed, false);

  // Mid-flight checkpoint passes while before cutoff, fails when paused past cutoff
  const midCheck = manager.checkRemainingBudget(attempt1, owner1);
  assert.equal(midCheck.ok, true);

  fakeNowNs += 4_100_000_000n;
  const expiredCheck = manager.checkRemainingBudget(attempt1, owner1);
  assert.equal(expiredCheck.ok, false);
  assert.equal(expiredCheck.reason, "deadline_budget_exhausted");

  const finished = manager.finish(attempt1, "aborted");
  assert.equal(finished.state, "aborted");

  // Schedule C/D: pause past cutoff BEFORE checkpointAndEnter prevents invocation
  const attempt2 = parseAttemptId("00000000-0000-4000-8000-000000000302");
  const owner2 = { ...owner1, attemptId: attempt2 };
  manager.beginPermission(owner2);
  fakeNowNs += 100_000_000n;
  manager.resolvePermission(attempt2, {
    owner: owner2,
    requestDeadlineAt: addMilliseconds(dbClock, 2_000),
    acceptanceDbClock: dbClock
  });
  fakeNowNs += 2_500_000_000n;
  const pausedOut = manager.checkpointAndEnter(attempt2, owner2);
  assert.equal(pausedOut.allowed, false);
  assert.equal(pausedOut.snapshot.state, "aborted");

  // Real Node monotonic clock returns positive bigint
  assert.ok(nodeMonotonicClock.nowNs() > 0n);
});

test("SendDeadlineManager detects backwards monotonic clock as unusable", () => {
  let fakeNowNs = 5_000_000_000n;
  const manager = new SendDeadlineManager({ nowNs: () => fakeNowNs });
  const dbClock = parseUtcTimestamp("2026-11-18T06:00:00.000000Z").instant;
  const attempt = parseAttemptId("00000000-0000-4000-8000-000000000303");
  const owner = {
    workerInstanceId: WORKER_ID,
    attemptId: attempt,
    fencingToken: 1n,
    controlEpoch: EPOCH
  };

  manager.beginPermission(owner);
  fakeNowNs = 4_000_000_000n; // clock moved backwards
  const res = manager.resolvePermission(attempt, {
    owner,
    requestDeadlineAt: addMilliseconds(dbClock, 5_000),
    acceptanceDbClock: dbClock
  });
  assert.equal(res.usable, false);
  assert.equal(res.snapshot.state, "unusable");
});

test("RuntimeLifecycleManager manages registration, heartbeat, bounded worker loops, and SIGTERM drain", async () => {
  const store = new InMemoryRuntimeRegistryStore();
  const lifecycle = new RuntimeLifecycleManager({
    processRole: "sender",
    databaseRole: "rq_sender",
    controlEpoch: EPOCH,
    buildReference: "test-sha",
    store,
    leaseMs: 1_000n,
    heartbeatIntervalMs: 100n,
    drainTimeoutMs: 2_000
  });

  let iterations = 0;
  let hookCalled = false;
  lifecycle.registerWorkerLoop({
    name: "dispatch",
    intervalMs: 15,
    runOnce: async (signal) => {
      iterations += 1;
      await abortableDelay(5, signal);
    }
  });
  lifecycle.registerDrainHook({
    name: "flush",
    drain: () => {
      hookCalled = true;
    }
  });

  const reg = await lifecycle.start();
  assert.equal(reg?.state, "active");
  assert.equal(reg?.processRole, "sender");

  await new Promise((resolve) => setTimeout(resolve, 160));
  assert.ok(iterations >= 2);
  const stored = store.get(lifecycle.instanceId);
  assert.ok(stored && stored.version >= 2n, "Heartbeat should have renewed instance lease");

  const report = await lifecycle.shutdown("SIGTERM");
  assert.equal(report.timedOut, false);
  assert.equal(report.state, "ended");
  assert.equal(hookCalled, true);
  assert.equal(lifecycle.signal.aborted, true);
  assert.equal(store.get(lifecycle.instanceId)?.state, "ended");
});
