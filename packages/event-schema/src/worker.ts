import { Worker } from "node:worker_threads";
import {
  DependencyUnavailableDomainError,
  DomainError,
  InvariantViolationError,
  LimitExceededDomainError,
  type SerializedDomainError,
  type Sha256Hex,
  ValidationDomainError
} from "@relayquill/domain";
import { type SchemaDiagnostic } from "./evaluator.js";
import { type ExtractedOrderingKeyResult, type OrderingDigestScope } from "./ordering-extractor.js";
import { type CompiledEventSchema } from "./profile.js";
import { type ProjectionProvenanceRecord } from "./projection.js";
import {
  type WorkerRequestMessage,
  type WorkerResponseMessage
} from "./worker-entrypoint.js";

export const WORKER_POOL_MAX_WORKERS = 2 as const;
export const WORKER_POOL_MAX_QUEUE_SIZE = 16 as const;
export const WORKER_DEFAULT_TIMEOUT_MS = 100 as const;

export interface WorkerLike {
  postMessage(value: unknown): void;
  terminate(): Promise<number>;
  on(event: "message", listener: (value: WorkerResponseMessage) => void): unknown;
  on(event: "error", listener: (err: Error) => void): unknown;
  on(event: "exit", listener: (code: number) => void): unknown;
}

export interface SchemaWorkerPoolOptions {
  readonly maxWorkers?: number | undefined;
  readonly maxQueueSize?: number | undefined;
  readonly defaultTimeoutMs?: number | undefined;
  readonly workerFactory?: (() => WorkerLike) | undefined;
}

export interface WorkerRunOptions {
  readonly timeoutMs?: number | undefined;
  readonly signal?: AbortSignal | undefined;
}

export interface WorkerEventValidationResult {
  readonly valid: boolean;
  readonly diagnostics: readonly SchemaDiagnostic[];
  readonly totalDiagnosticsObserved: number;
  readonly workUnitsUsed: number;
  readonly byteCount: number;
  readonly sha256: Sha256Hex;
  readonly nodeCount: number;
  readonly maxObservedDepth: number;
}

export interface WorkerFilterExtractResult {
  readonly schemaValid: boolean;
  readonly diagnostics: readonly SchemaDiagnostic[];
  readonly matched: boolean;
  readonly ordering?: ExtractedOrderingKeyResult | undefined;
}

export interface WorkerProjectionExecutionResult {
  readonly compilerProfileVersion: string;
  readonly sourceByteCount: number;
  readonly sourceContentSha256: Sha256Hex;
  readonly derivedJson: string;
  readonly derivedBytes: Uint8Array;
  readonly derivedByteCount: number;
  readonly derivedContentSha256: Sha256Hex;
  readonly targetSchemaVersion: number;
  readonly provenance: ProjectionProvenanceRecord;
}

export interface SchemaWorkerPoolStats {
  readonly totalSlots: number;
  readonly idleWorkers: number;
  readonly busyWorkers: number;
  readonly terminatingWorkers: number;
  readonly queuedTasks: number;
  readonly closed: boolean;
}

interface PendingTask {
  readonly id: number;
  readonly request: WorkerRequestMessage;
  readonly timeoutMs: number;
  readonly signal: AbortSignal | undefined;
  readonly resolve: (value: unknown) => void;
  readonly reject: (err: unknown) => void;
  abortCleanup?: (() => void) | undefined;
  timeoutHandle?: ReturnType<typeof setTimeout> | undefined;
}

interface WorkerSlot {
  readonly worker: WorkerLike;
  state: "idle" | "busy" | "terminating";
  currentTask: PendingTask | null;
}

const OWNED_WORKER_ENTRYPOINT_URL = new URL("./worker-entrypoint.js", import.meta.url);

function defaultWorkerFactory(): WorkerLike {
  return new Worker(OWNED_WORKER_ENTRYPOINT_URL, {
    env: {},
    execArgv: [],
    resourceLimits: {
      maxOldGenerationSizeMb: 64,
      maxYoungGenerationSizeMb: 16,
      stackSizeMb: 4
    }
  });
}

function hydrateDomainError(serialized: SerializedDomainError): DomainError {
  const options = {
    code: serialized.code,
    message: serialized.message,
    retryable: serialized.retryable,
    acceptance: serialized.acceptance,
    boundary: serialized.boundary,
    fieldErrors: serialized.fieldErrors,
    resourceRef: serialized.resourceRef
  };
  if (serialized.name === "LimitExceededDomainError" || serialized.code === "SCHEMA_EVALUATION_LIMIT") {
    return new LimitExceededDomainError(options);
  }
  if (serialized.name === "ValidationDomainError") {
    return new ValidationDomainError(options);
  }
  if (serialized.name === "DependencyUnavailableDomainError") {
    return new DependencyUnavailableDomainError(options);
  }
  if (serialized.name === "InvariantViolationError") {
    return new InvariantViolationError(options);
  }
  return new DomainError(options);
}

export class SchemaWorkerPool {
  readonly #maxWorkers: number;
  readonly #maxQueueSize: number;
  readonly #defaultTimeoutMs: number;
  readonly #workerFactory: () => WorkerLike;

  readonly #slots = new Set<WorkerSlot>();
  readonly #queue: PendingTask[] = [];
  readonly #exitWaiters: Array<() => void> = [];

  #nextTaskId = 1;
  #closed = false;
  #closePromise: Promise<void> | null = null;

  constructor(options?: SchemaWorkerPoolOptions) {
    const maxWorkers = options?.maxWorkers ?? WORKER_POOL_MAX_WORKERS;
    const maxQueueSize = options?.maxQueueSize ?? WORKER_POOL_MAX_QUEUE_SIZE;
    const defaultTimeoutMs = options?.defaultTimeoutMs ?? WORKER_DEFAULT_TIMEOUT_MS;

    if (!Number.isInteger(maxWorkers) || maxWorkers < 1 || maxWorkers > WORKER_POOL_MAX_WORKERS) {
      throw new ValidationDomainError({
        code: "INVALID_VALUE",
        message: `maxWorkers must be within [1, ${WORKER_POOL_MAX_WORKERS}]`
      });
    }
    if (!Number.isInteger(maxQueueSize) || maxQueueSize < 0 || maxQueueSize > WORKER_POOL_MAX_QUEUE_SIZE) {
      throw new ValidationDomainError({
        code: "INVALID_VALUE",
        message: `maxQueueSize must be within [0, ${WORKER_POOL_MAX_QUEUE_SIZE}]`
      });
    }
    if (!Number.isInteger(defaultTimeoutMs) || defaultTimeoutMs < 1 || defaultTimeoutMs > 10_000) {
      throw new ValidationDomainError({
        code: "INVALID_VALUE",
        message: "defaultTimeoutMs must be within [1, 10000]"
      });
    }

    this.#maxWorkers = maxWorkers;
    this.#maxQueueSize = maxQueueSize;
    this.#defaultTimeoutMs = defaultTimeoutMs;
    this.#workerFactory = options?.workerFactory ?? defaultWorkerFactory;
  }

  getStats(): SchemaWorkerPoolStats {
    let idleWorkers = 0;
    let busyWorkers = 0;
    let terminatingWorkers = 0;
    for (const slot of this.#slots) {
      if (slot.state === "idle") {
        idleWorkers += 1;
      } else if (slot.state === "busy") {
        busyWorkers += 1;
      } else {
        terminatingWorkers += 1;
      }
    }
    return Object.freeze({
      totalSlots: this.#slots.size,
      idleWorkers,
      busyWorkers,
      terminatingWorkers,
      queuedTasks: this.#queue.length,
      closed: this.#closed
    });
  }

  async warmup(count = this.#maxWorkers, timeoutMs = 5_000): Promise<void> {
    if (this.#closed) {
      throw new DependencyUnavailableDomainError({
        code: "DEPENDENCY_UNAVAILABLE",
        message: "Schema worker pool is closed"
      });
    }
    const targetCount = Math.min(this.#maxWorkers, Math.max(1, count));
    const pingSchemaBytes = new TextEncoder().encode('{"type":"null"}');
    const tasks: Promise<CompiledEventSchema>[] = [];
    for (let i = 0; i < targetCount; i += 1) {
      tasks.push(this.compileSchema(pingSchemaBytes, { timeoutMs }));
    }
    await Promise.all(tasks);
  }

  compileSchema(
    rawBytes: Uint8Array,
    options?: WorkerRunOptions
  ): Promise<CompiledEventSchema> {
    return this.#submit<CompiledEventSchema>(
      (id) => ({
        id,
        kind: "compile_schema",
        rawBytes: new Uint8Array(rawBytes)
      }),
      options
    );
  }

  validateEvent(
    input: {
      readonly eventBytes: Uint8Array;
      readonly compiledSchema?: CompiledEventSchema | undefined;
      readonly schemaBytes?: Uint8Array | undefined;
      readonly maxWorkUnits?: number | undefined;
      readonly maxDiagnostics?: number | undefined;
    },
    options?: WorkerRunOptions
  ): Promise<WorkerEventValidationResult> {
    return this.#submit<WorkerEventValidationResult>(
      (id) => ({
        id,
        kind: "validate_event",
        eventBytes: new Uint8Array(input.eventBytes),
        ...(input.compiledSchema !== undefined ? { compiledSchema: input.compiledSchema } : {}),
        ...(input.schemaBytes !== undefined ? { schemaBytes: new Uint8Array(input.schemaBytes) } : {}),
        ...(input.maxWorkUnits !== undefined ? { maxWorkUnits: input.maxWorkUnits } : {}),
        ...(input.maxDiagnostics !== undefined ? { maxDiagnostics: input.maxDiagnostics } : {})
      }),
      options
    );
  }

  evaluateFilterAndExtract(
    input: {
      readonly eventBytes: Uint8Array;
      readonly compiledSchema: CompiledEventSchema;
      readonly filterAst?: unknown;
      readonly orderingExtractor?: unknown;
      readonly orderingScope?: OrderingDigestScope | undefined;
    },
    options?: WorkerRunOptions
  ): Promise<WorkerFilterExtractResult> {
    return this.#submit<WorkerFilterExtractResult>(
      (id) => ({
        id,
        kind: "evaluate_filter_and_extract",
        eventBytes: new Uint8Array(input.eventBytes),
        compiledSchema: input.compiledSchema,
        ...(input.filterAst !== undefined ? { filterAst: input.filterAst } : {}),
        ...(input.orderingExtractor !== undefined ? { orderingExtractor: input.orderingExtractor } : {}),
        ...(input.orderingScope !== undefined ? { orderingScope: input.orderingScope } : {})
      }),
      options
    );
  }

  executeProjection(
    input: {
      readonly sourceBytes: Uint8Array;
      readonly sourceSchema: CompiledEventSchema;
      readonly targetSchema: CompiledEventSchema;
      readonly profileDefinition: unknown;
    },
    options?: WorkerRunOptions
  ): Promise<WorkerProjectionExecutionResult> {
    return this.#submit<WorkerProjectionExecutionResult>(
      (id) => ({
        id,
        kind: "execute_projection",
        sourceBytes: new Uint8Array(input.sourceBytes),
        sourceSchema: input.sourceSchema,
        targetSchema: input.targetSchema,
        profileDefinition: input.profileDefinition
      }),
      options
    );
  }

  close(): Promise<void> {
    if (this.#closePromise !== null) {
      return this.#closePromise;
    }
    this.#closed = true;

    while (this.#queue.length > 0) {
      const queued = this.#queue.shift()!;
      queued.abortCleanup?.();
      queued.reject(
        new DependencyUnavailableDomainError({
          code: "DEPENDENCY_UNAVAILABLE",
          message: "Schema worker pool is shutting down"
        })
      );
    }

    if (this.#slots.size === 0) {
      this.#closePromise = Promise.resolve();
      return this.#closePromise;
    }

    this.#closePromise = new Promise<void>((resolve) => {
      this.#exitWaiters.push(resolve);
    });

    for (const slot of this.#slots) {
      if (slot.state === "busy" && slot.currentTask !== null) {
        const task = slot.currentTask;
        slot.currentTask = null;
        this.#clearTaskTimers(task);
        task.reject(
          new DependencyUnavailableDomainError({
            code: "DEPENDENCY_UNAVAILABLE",
            message: "Schema worker pool closed during evaluation"
          })
        );
      }
      if (slot.state !== "terminating") {
        slot.state = "terminating";
        void slot.worker.terminate().catch(() => {
          // Exit listener handles slot cleanup.
        });
      }
    }

    return this.#closePromise;
  }

  #submit<T>(
    buildRequest: (id: number) => WorkerRequestMessage,
    options?: WorkerRunOptions
  ): Promise<T> {
    if (this.#closed) {
      return Promise.reject(
        new DependencyUnavailableDomainError({
          code: "DEPENDENCY_UNAVAILABLE",
          message: "Schema worker pool is closed"
        })
      );
    }
    if (options?.signal?.aborted) {
      return Promise.reject(
        new LimitExceededDomainError({
          code: "SCHEMA_EVALUATION_LIMIT",
          message: "Schema evaluation aborted before dispatch"
        })
      );
    }

    const timeoutMs = options?.timeoutMs ?? this.#defaultTimeoutMs;
    if (!Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 10_000) {
      return Promise.reject(
        new ValidationDomainError({
          code: "INVALID_VALUE",
          message: "timeoutMs must be within [1, 10000]"
        })
      );
    }

    const id = this.#nextTaskId++;
    const request = buildRequest(id);

    return new Promise<T>((resolve, reject) => {
      const task: PendingTask = {
        id,
        request,
        timeoutMs,
        signal: options?.signal,
        resolve: (value) => resolve(value as T),
        reject
      };

      const idleSlot = this.#findIdleSlot();
      if (idleSlot !== undefined) {
        this.#dispatchToSlot(idleSlot, task);
        return;
      }

      if (this.#slots.size < this.#maxWorkers) {
        const newSlot = this.#spawnSlot();
        this.#dispatchToSlot(newSlot, task);
        return;
      }

      if (this.#queue.length >= this.#maxQueueSize) {
        reject(
          new LimitExceededDomainError({
            code: "SCHEMA_EVALUATION_LIMIT",
            message: `Schema worker evaluation queue full (max ${this.#maxQueueSize})`
          })
        );
        return;
      }

      if (task.signal !== undefined) {
        const onQueuedAbort = (): void => {
          const idx = this.#queue.indexOf(task);
          if (idx !== -1) {
            this.#queue.splice(idx, 1);
            task.abortCleanup = undefined;
            reject(
              new LimitExceededDomainError({
                code: "SCHEMA_EVALUATION_LIMIT",
                message: "Queued schema evaluation aborted"
              })
            );
          }
        };
        task.signal.addEventListener("abort", onQueuedAbort, { once: true });
        task.abortCleanup = () => {
          task.signal?.removeEventListener("abort", onQueuedAbort);
        };
      }

      this.#queue.push(task);
    });
  }

  #findIdleSlot(): WorkerSlot | undefined {
    for (const slot of this.#slots) {
      if (slot.state === "idle") {
        return slot;
      }
    }
    return undefined;
  }

  #spawnSlot(): WorkerSlot {
    const worker = this.#workerFactory();
    const slot: WorkerSlot = {
      worker,
      state: "idle",
      currentTask: null
    };
    this.#slots.add(slot);

    worker.on("message", (msg: WorkerResponseMessage) => {
      if (slot.state !== "busy" || slot.currentTask === null) {
        return;
      }
      if (msg.id !== slot.currentTask.id) {
        return;
      }
      const task = slot.currentTask;
      slot.currentTask = null;
      slot.state = "idle";
      this.#clearTaskTimers(task);

      if (msg.ok) {
        task.resolve(msg.result);
      } else {
        task.reject(hydrateDomainError(msg.error));
      }

      this.#pumpQueue();
    });

    worker.on("error", () => {
      if (slot.state === "busy" && slot.currentTask !== null) {
        const task = slot.currentTask;
        slot.currentTask = null;
        this.#clearTaskTimers(task);
        task.reject(
          new DependencyUnavailableDomainError({
            code: "DEPENDENCY_UNAVAILABLE",
            message: "Schema evaluation worker encountered an unexpected error"
          })
        );
      }
      if (slot.state !== "terminating") {
        slot.state = "terminating";
        void worker.terminate().catch(() => {
          // Exit listener handles slot release.
        });
      }
    });

    worker.on("exit", () => {
      // Release slot ONLY after actual worker resource exit is observed.
      if (slot.currentTask !== null) {
        const task = slot.currentTask;
        slot.currentTask = null;
        this.#clearTaskTimers(task);
        task.reject(
          new LimitExceededDomainError({
            code: "SCHEMA_EVALUATION_LIMIT",
            message: "Schema evaluation worker exited before returning result"
          })
        );
      }
      this.#slots.delete(slot);

      if (this.#closed) {
        if (this.#slots.size === 0) {
          while (this.#exitWaiters.length > 0) {
            this.#exitWaiters.shift()!();
          }
        }
        return;
      }

      this.#pumpQueue();
    });

    return slot;
  }

  #dispatchToSlot(slot: WorkerSlot, task: PendingTask): void {
    task.abortCleanup?.();
    task.abortCleanup = undefined;

    if (task.signal?.aborted) {
      task.reject(
        new LimitExceededDomainError({
          code: "SCHEMA_EVALUATION_LIMIT",
          message: "Schema evaluation aborted before execution"
        })
      );
      this.#pumpQueue();
      return;
    }

    slot.state = "busy";
    slot.currentTask = task;

    const terminateActiveSlot = (reasonMessage: string): void => {
      if (slot.state !== "busy" || slot.currentTask !== task) {
        return;
      }
      // Keep slot held in #slots until the worker's "exit" event fires.
      slot.state = "terminating";
      slot.currentTask = null;
      this.#clearTaskTimers(task);
      task.reject(
        new LimitExceededDomainError({
          code: "SCHEMA_EVALUATION_LIMIT",
          message: reasonMessage
        })
      );
      void slot.worker.terminate().catch(() => {
        // Exit event still drives slot release.
      });
    };

    const timer = setTimeout(() => {
      terminateActiveSlot(`Schema evaluation exceeded ${task.timeoutMs}ms wall budget`);
    }, task.timeoutMs);
    timer.unref();
    task.timeoutHandle = timer;

    if (task.signal !== undefined) {
      const onActiveAbort = (): void => {
        terminateActiveSlot("Schema evaluation aborted during execution");
      };
      task.signal.addEventListener("abort", onActiveAbort, { once: true });
      task.abortCleanup = () => {
        task.signal?.removeEventListener("abort", onActiveAbort);
      };
    }

    try {
      slot.worker.postMessage(task.request);
    } catch {
      terminateActiveSlot("Failed to dispatch task to schema worker");
    }
  }

  #clearTaskTimers(task: PendingTask): void {
    if (task.timeoutHandle !== undefined) {
      clearTimeout(task.timeoutHandle);
      task.timeoutHandle = undefined;
    }
    task.abortCleanup?.();
    task.abortCleanup = undefined;
  }

  #pumpQueue(): void {
    if (this.#closed) {
      return;
    }
    while (this.#queue.length > 0) {
      let targetSlot = this.#findIdleSlot();
      if (targetSlot === undefined && this.#slots.size < this.#maxWorkers) {
        targetSlot = this.#spawnSlot();
      }
      if (targetSlot === undefined) {
        break;
      }
      const nextTask = this.#queue.shift()!;
      this.#dispatchToSlot(targetSlot, nextTask);
    }
  }
}
