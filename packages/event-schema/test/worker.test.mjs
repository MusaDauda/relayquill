import test from "node:test";
import assert from "node:assert/strict";
import { Worker } from "node:worker_threads";
import { EventEmitter } from "node:events";
import {
  DependencyUnavailableDomainError,
  LimitExceededDomainError,
  ValidationDomainError
} from "@relayquill/domain";
import {
  SchemaWorkerPool,
  WORKER_POOL_MAX_QUEUE_SIZE,
  WORKER_POOL_MAX_WORKERS,
  compileEventSchema
} from "@relayquill/event-schema";

function encodeJson(obj) {
  return new TextEncoder().encode(JSON.stringify(obj));
}

test("SchemaWorkerPool executes compile, validate, filter/extract, and projection in real worker_threads", async () => {
  const defaultPool = new SchemaWorkerPool();
  await defaultPool.close();
  const pool = new SchemaWorkerPool({ maxWorkers: 2, maxQueueSize: 16, defaultTimeoutMs: 5_000 });
  try {
    await pool.warmup(2, 10_000);
    const schemaBytes = encodeJson({
      type: "object",
      properties: {
        key: { type: "string", minLength: 1, maxLength: 32 },
        amount: { type: "number", minimum: 9007199254740993 }
      },
      required: ["key", "amount"],
      additionalProperties: false
    });
    const compiledSchema = await pool.compileSchema(schemaBytes);

    const validEvent = encodeJson({ key: "ord-1", amount: 9007199254740993 });
    const validationRes = await pool.validateEvent({
      eventBytes: validEvent,
      compiledSchema
    });
    assert.equal(validationRes.valid, true);
    assert.equal(validationRes.byteCount, validEvent.length);

    // Duplicate key rejected inside worker with ValidationDomainError
    await assert.rejects(
      () =>
        pool.validateEvent({
          eventBytes: new TextEncoder().encode('{"key":"a","key":"a","amount":9007199254740993}'),
          compiledSchema
        }),
      ValidationDomainError
    );

    const filterRes = await pool.evaluateFilterAndExtract({
      eventBytes: validEvent,
      compiledSchema,
      filterAst: { operation: "eq", path: "/key", value: "ord-1" },
      orderingExtractor: "/key",
      orderingScope: {
        orderingDomainId: "00000000-0000-4000-8000-000000000901",
        subscriptionId: "00000000-0000-4000-8000-000000000902",
        consumerContractScope: "demo.order.v1"
      }
    });
    assert.equal(filterRes.schemaValid, true);
    assert.equal(filterRes.matched, true);
    assert.equal(filterRes.ordering?.orderingKey, "ord-1");

    const targetSchema = compileEventSchema(
      encodeJson({
        type: "object",
        properties: {
          key: { type: "string", minLength: 1, maxLength: 32 },
          tag: { type: "string", maxLength: 8 }
        },
        required: ["key", "tag"],
        additionalProperties: false
      })
    );
    const projRes = await pool.executeProjection({
      sourceBytes: validEvent,
      sourceSchema: compiledSchema,
      targetSchema,
      profileDefinition: {
        profile_schema_version: 1,
        source_event_type_id: "00000000-0000-4000-8000-000000000305",
        source_schema_version: 1,
        target_schema_version: 2,
        mappings: [
          { operation: "copy", target_path: "/key", source_path: "/key" },
          { operation: "constant", target_path: "/tag", value: "v2" }
        ]
      }
    });
    assert.equal(projRes.derivedJson, '{"key":"ord-1","tag":"v2"}');
  } finally {
    await pool.close();
  }
});

test("SchemaWorkerPool enforces worker and queue caps and holds terminating slot until exit is observed", async () => {
  assert.throws(
    () => new SchemaWorkerPool({ maxWorkers: WORKER_POOL_MAX_WORKERS + 1 }),
    ValidationDomainError
  );
  assert.throws(
    () => new SchemaWorkerPool({ maxQueueSize: WORKER_POOL_MAX_QUEUE_SIZE + 1 }),
    ValidationDomainError
  );

  let spawnCount = 0;
  let delayedExitTrigger = null;
  const schemaBytes = encodeJson({ type: "string", maxLength: 10 });

  const pool = new SchemaWorkerPool({
    maxWorkers: 1,
    maxQueueSize: 1,
    defaultTimeoutMs: 25,
    workerFactory: () => {
      spawnCount += 1;
      if (spawnCount === 1) {
        const fakeWorker = new EventEmitter();
        fakeWorker.postMessage = () => {
          // Never respond so timeout triggers
        };
        fakeWorker.terminate = () => {
          return new Promise((resolve) => {
            delayedExitTrigger = () => {
              fakeWorker.emit("exit", 1);
              resolve(1);
            };
          });
        };
        return fakeWorker;
      }
      return new Worker(new URL("../dist/worker-entrypoint.js", import.meta.url), { env: {} });
    }
  });

  try {
    // Task 1 occupies the single slot and times out
    const task1Promise = pool.compileSchema(schemaBytes, { timeoutMs: 20 });
    // Task 2 fills the single queue slot
    const task2Promise = pool.compileSchema(schemaBytes, { timeoutMs: 10_000 });
    // Task 3 overflows queue immediately
    await assert.rejects(
      () => pool.compileSchema(schemaBytes, { timeoutMs: 10_000 }),
      (err) => err instanceof LimitExceededDomainError && err.code === "SCHEMA_EVALUATION_LIMIT"
    );

    // Task 1 rejects on timeout
    await assert.rejects(
      () => task1Promise,
      (err) => err instanceof LimitExceededDomainError && err.code === "SCHEMA_EVALUATION_LIMIT"
    );

    // CRITICAL INVARIANT: slot is STILL held in terminating state until "exit" is observed!
    const statsBeforeExit = pool.getStats();
    assert.equal(statsBeforeExit.totalSlots, 1);
    assert.equal(statsBeforeExit.terminatingWorkers, 1);
    assert.equal(statsBeforeExit.queuedTasks, 1);
    assert.equal(spawnCount, 1);

    // Now observe actual worker exit -> slot releases and queued task 2 runs on fresh worker #2
    assert.ok(delayedExitTrigger);
    delayedExitTrigger();

    const compiled = await task2Promise;
    assert.equal(compiled.normalizedProfile.root.kind, "string");
    assert.equal(spawnCount, 2);
  } finally {
    await pool.close();
  }

  await assert.rejects(
    () => pool.compileSchema(schemaBytes),
    DependencyUnavailableDomainError
  );
});

test("SchemaWorkerPool terminates real runaway CPU worker_thread and releases slot only after exit", async () => {
  let spawnCount = 0;
  let exitObserved = false;
  const schemaBytes = encodeJson({ type: "string", maxLength: 10 });

  const pool = new SchemaWorkerPool({
    maxWorkers: 1,
    maxQueueSize: 4,
    defaultTimeoutMs: 50,
    workerFactory: () => {
      spawnCount += 1;
      if (spawnCount === 1) {
        const runaway = new Worker(
          new URL("./fixtures/infinite-loop-worker.mjs", import.meta.url),
          { env: {} }
        );
        runaway.on("exit", () => {
          exitObserved = true;
        });
        return runaway;
      }
      return new Worker(new URL("../dist/worker-entrypoint.js", import.meta.url), { env: {} });
    }
  });

  try {
    const runawayTask = pool.compileSchema(schemaBytes, { timeoutMs: 40 });
    const followupTask = pool.compileSchema(schemaBytes, { timeoutMs: 10_000 });

    await assert.rejects(
      () => runawayTask,
      (err) => err instanceof LimitExceededDomainError && err.code === "SCHEMA_EVALUATION_LIMIT"
    );

    const compiled = await followupTask;
    assert.equal(exitObserved, true);
    assert.equal(spawnCount, 2);
    assert.equal(compiled.normalizedProfile.root.kind, "string");
  } finally {
    await pool.close();
  }
});
