import crypto from "node:crypto";
import {
  ALLOWED_RUNTIME_INSTANCE_TRANSITIONS,
  RUNTIME_INSTANCE_HEARTBEAT_INTERVAL_MS,
  RUNTIME_INSTANCE_LEASE_MS,
  assertTransition,
  nowUtcInstant,
  parseControlEpoch,
  parseRuntimeInstanceId,
  type ControlEpoch,
  type ProcessRole as DomainProcessRole,
  type RuntimeInstanceId,
  type RuntimeInstanceState
} from "@relayquill/domain";
import { type Temporal } from "@js-temporal/polyfill";
import { type ConfigProcessRole, type RoleConfig } from "./config.js";
import { SendDeadlineManager, nodeMonotonicClock, type MonotonicClock } from "./deadlines.js";

export * from "./deadlines.js";

export interface RuntimeInstanceRegistration {
  readonly instanceId: RuntimeInstanceId;
  readonly processRole: DomainProcessRole;
  readonly databaseRole: string;
  readonly controlEpoch: ControlEpoch;
  readonly buildReference: string;
  readonly state: RuntimeInstanceState;
  readonly startedAt: Temporal.Instant;
  readonly lastSeenAt: Temporal.Instant;
  readonly expiresAt: Temporal.Instant;
  readonly version: bigint;
}

export interface RegisterRuntimeInstanceInput {
  readonly instanceId: RuntimeInstanceId;
  readonly processRole: DomainProcessRole;
  readonly databaseRole: string;
  readonly controlEpoch: ControlEpoch;
  readonly buildReference: string;
  readonly leaseMs: bigint;
  readonly now: Temporal.Instant;
}

export interface HeartbeatRuntimeInstanceInput {
  readonly instanceId: RuntimeInstanceId;
  readonly controlEpoch: ControlEpoch;
  readonly expectedVersion: bigint;
  readonly leaseMs: bigint;
  readonly now: Temporal.Instant;
}

export interface TransitionRuntimeInstanceInput {
  readonly instanceId: RuntimeInstanceId;
  readonly controlEpoch: ControlEpoch;
  readonly expectedVersion: bigint;
  readonly toState: RuntimeInstanceState;
  readonly now: Temporal.Instant;
}

export interface RuntimeRegistryStore {
  registerInstance(input: RegisterRuntimeInstanceInput): Promise<RuntimeInstanceRegistration>;
  heartbeatInstance(input: HeartbeatRuntimeInstanceInput): Promise<RuntimeInstanceRegistration>;
  transitionInstanceState(
    input: TransitionRuntimeInstanceInput
  ): Promise<RuntimeInstanceRegistration>;
}

export class InMemoryRuntimeRegistryStore implements RuntimeRegistryStore {
  readonly #records = new Map<RuntimeInstanceId, RuntimeInstanceRegistration>();

  get(instanceId: RuntimeInstanceId): RuntimeInstanceRegistration | undefined {
    return this.#records.get(instanceId);
  }

  registerInstance(input: RegisterRuntimeInstanceInput): Promise<RuntimeInstanceRegistration> {
    const expiresAt = input.now.add({ milliseconds: Number(input.leaseMs) });
    const record: RuntimeInstanceRegistration = Object.freeze({
      instanceId: input.instanceId,
      processRole: input.processRole,
      databaseRole: input.databaseRole,
      controlEpoch: input.controlEpoch,
      buildReference: input.buildReference,
      state: "active",
      startedAt: input.now,
      lastSeenAt: input.now,
      expiresAt,
      version: 1n
    });
    this.#records.set(input.instanceId, record);
    return Promise.resolve(record);
  }

  heartbeatInstance(input: HeartbeatRuntimeInstanceInput): Promise<RuntimeInstanceRegistration> {
    const current = this.#records.get(input.instanceId);
    if (current === undefined) {
      return Promise.reject(new Error(`Runtime instance ${input.instanceId} not registered`));
    }
    if (current.controlEpoch !== input.controlEpoch) {
      return Promise.reject(new Error(`Control epoch mismatch for ${input.instanceId}`));
    }
    if (current.version !== input.expectedVersion) {
      return Promise.reject(new Error(`Version conflict for ${input.instanceId}`));
    }
    if (current.state !== "active") {
      return Promise.resolve(current);
    }
    const updated: RuntimeInstanceRegistration = Object.freeze({
      ...current,
      lastSeenAt: input.now,
      expiresAt: input.now.add({ milliseconds: Number(input.leaseMs) }),
      version: current.version + 1n
    });
    this.#records.set(input.instanceId, updated);
    return Promise.resolve(updated);
  }

  transitionInstanceState(
    input: TransitionRuntimeInstanceInput
  ): Promise<RuntimeInstanceRegistration> {
    const current = this.#records.get(input.instanceId);
    if (current === undefined) {
      return Promise.reject(new Error(`Runtime instance ${input.instanceId} not registered`));
    }
    if (current.controlEpoch !== input.controlEpoch) {
      return Promise.reject(new Error(`Control epoch mismatch for ${input.instanceId}`));
    }
    if (current.version !== input.expectedVersion) {
      return Promise.reject(new Error(`Version conflict for ${input.instanceId}`));
    }
    if (current.state === input.toState) {
      return Promise.resolve(current);
    }
    assertTransition(
      "runtime_instance",
      ALLOWED_RUNTIME_INSTANCE_TRANSITIONS,
      current.state,
      input.toState,
      { kind: "runtime_instance", id: input.instanceId }
    );
    const updated: RuntimeInstanceRegistration = Object.freeze({
      ...current,
      state: input.toState,
      lastSeenAt: input.now,
      version: current.version + 1n
    });
    this.#records.set(input.instanceId, updated);
    return Promise.resolve(updated);
  }
}

export function mapConfigRoleToDomainProcessRole(role: ConfigProcessRole): DomainProcessRole {
  switch (role) {
    case "api":
    case "relay":
    case "fanout":
    case "sender":
    case "coordinator":
      return role;
    case "admin":
    case "receiver":
    case "receiver_migrator":
    case "receiver_operator":
    case "provider_ingress":
    case "provider_ingress_migrator":
    case "provider_ingress_fixture":
    case "producer_example":
      return "protected_admin";
  }
}

export interface WorkerLoopSpec {
  readonly name: string;
  readonly intervalMs: number;
  readonly maxIterations?: number | undefined;
  readonly runOnce: (signal: AbortSignal) => Promise<void>;
  readonly onError?: ((err: unknown) => void) | undefined;
}

export interface DrainHookSpec {
  readonly name: string;
  readonly drain: () => Promise<void> | void;
}

export interface RuntimeLifecycleOptions {
  readonly instanceId?: string | undefined;
  readonly processRole: DomainProcessRole;
  readonly databaseRole: string;
  readonly controlEpoch: string;
  readonly buildReference?: string | undefined;
  readonly store?: RuntimeRegistryStore | undefined;
  readonly leaseMs?: bigint | undefined;
  readonly heartbeatIntervalMs?: bigint | undefined;
  readonly drainTimeoutMs?: number | undefined;
  readonly clock?: MonotonicClock | undefined;
  readonly nowFn?: (() => Temporal.Instant) | undefined;
  readonly onAuthorityInvalidated?: ((reason: string) => void) | undefined;
}

export interface ShutdownReport {
  readonly reason: string;
  readonly timedOut: boolean;
  readonly state: RuntimeInstanceState;
}

export function abortableDelay(ms: number, signal: AbortSignal): Promise<boolean> {
  if (signal.aborted) {
    return Promise.resolve(false);
  }
  const boundedMs = Math.max(0, ms);
  return new Promise<boolean>((resolve) => {
    const timer = setTimeout(() => {
      signal.removeEventListener("abort", onAbort);
      resolve(true);
    }, boundedMs);
    timer.unref();

    const onAbort = (): void => {
      clearTimeout(timer);
      resolve(false);
    };
    signal.addEventListener("abort", onAbort, { once: true });
  });
}

export class RuntimeLifecycleManager {
  readonly instanceId: RuntimeInstanceId;
  readonly processRole: DomainProcessRole;
  readonly databaseRole: string;
  readonly controlEpoch: ControlEpoch;
  readonly buildReference: string;
  readonly sendDeadlines: SendDeadlineManager;

  readonly #controller = new AbortController();
  readonly #store: RuntimeRegistryStore | undefined;
  readonly #leaseMs: bigint;
  readonly #heartbeatIntervalMs: bigint;
  readonly #drainTimeoutMs: number;
  readonly #nowFn: () => Temporal.Instant;
  readonly #onAuthorityInvalidated: ((reason: string) => void) | undefined;

  readonly #loops: WorkerLoopSpec[] = [];
  readonly #loopPromises = new Set<Promise<void>>();
  readonly #drainHooks: DrainHookSpec[] = [];

  #registration: RuntimeInstanceRegistration | undefined;
  #heartbeatTimer: ReturnType<typeof setInterval> | null = null;
  #heartbeatInFlight = false;
  #started = false;
  #draining = false;
  #shutdownPromise: Promise<ShutdownReport> | null = null;

  constructor(options: RuntimeLifecycleOptions) {
    this.instanceId = parseRuntimeInstanceId(
      options.instanceId ?? crypto.randomUUID(),
      "instance_id"
    );
    this.processRole = options.processRole;
    this.databaseRole = options.databaseRole;
    this.controlEpoch = parseControlEpoch(options.controlEpoch, "control_epoch");
    this.buildReference = options.buildReference ?? "dev";
    this.sendDeadlines = new SendDeadlineManager(options.clock ?? nodeMonotonicClock);

    this.#store = options.store;
    this.#leaseMs = options.leaseMs ?? RUNTIME_INSTANCE_LEASE_MS;
    this.#heartbeatIntervalMs =
      options.heartbeatIntervalMs ?? RUNTIME_INSTANCE_HEARTBEAT_INTERVAL_MS;
    this.#drainTimeoutMs = options.drainTimeoutMs ?? 10_000;
    this.#nowFn = options.nowFn ?? nowUtcInstant;
    this.#onAuthorityInvalidated = options.onAuthorityInvalidated;
  }

  static fromRoleConfig(
    config: RoleConfig,
    options: {
      readonly controlEpoch: string;
      readonly buildReference?: string | undefined;
      readonly store?: RuntimeRegistryStore | undefined;
      readonly drainTimeoutMs?: number | undefined;
      readonly clock?: MonotonicClock | undefined;
      readonly nowFn?: (() => Temporal.Instant) | undefined;
      readonly onAuthorityInvalidated?: ((reason: string) => void) | undefined;
    }
  ): RuntimeLifecycleManager {
    const dbRole =
      "database" in config && config.database !== undefined ? config.database.role : "none";
    return new RuntimeLifecycleManager({
      processRole: mapConfigRoleToDomainProcessRole(config.process_role),
      databaseRole: dbRole,
      controlEpoch: options.controlEpoch,
      buildReference: options.buildReference,
      store: options.store,
      drainTimeoutMs: options.drainTimeoutMs,
      clock: options.clock,
      nowFn: options.nowFn,
      onAuthorityInvalidated: options.onAuthorityInvalidated
    });
  }

  get signal(): AbortSignal {
    return this.#controller.signal;
  }

  get isDraining(): boolean {
    return this.#draining;
  }

  get registration(): RuntimeInstanceRegistration | undefined {
    return this.#registration;
  }

  registerWorkerLoop(spec: WorkerLoopSpec): void {
    if (this.#started) {
      throw new Error(`Cannot register worker loop "${spec.name}" after start()`);
    }
    this.#loops.push(spec);
  }

  registerDrainHook(hook: DrainHookSpec): void {
    this.#drainHooks.push(hook);
  }

  async start(): Promise<RuntimeInstanceRegistration | undefined> {
    if (this.#started) {
      return this.#registration;
    }
    if (this.#draining) {
      throw new Error("Cannot start RuntimeLifecycleManager after shutdown started");
    }
    this.#started = true;

    if (this.#store !== undefined) {
      this.#registration = await this.#store.registerInstance({
        instanceId: this.instanceId,
        processRole: this.processRole,
        databaseRole: this.databaseRole,
        controlEpoch: this.controlEpoch,
        buildReference: this.buildReference,
        leaseMs: this.#leaseMs,
        now: this.#nowFn()
      });

      const intervalMs = Math.max(100, Number(this.#heartbeatIntervalMs));
      this.#heartbeatTimer = setInterval(() => {
        void this.#tickHeartbeat();
      }, intervalMs);
      this.#heartbeatTimer.unref();
    }

    for (const loopSpec of this.#loops) {
      const task = this.#runWorkerLoop(loopSpec);
      this.#loopPromises.add(task);
      void task.finally(() => {
        this.#loopPromises.delete(task);
      });
    }

    return this.#registration;
  }

  async #tickHeartbeat(): Promise<void> {
    if (
      this.#heartbeatInFlight ||
      this.#draining ||
      this.#store === undefined ||
      this.#registration === undefined
    ) {
      return;
    }
    this.#heartbeatInFlight = true;
    try {
      const updated = await this.#store.heartbeatInstance({
        instanceId: this.instanceId,
        controlEpoch: this.controlEpoch,
        expectedVersion: this.#registration.version,
        leaseMs: this.#leaseMs,
        now: this.#nowFn()
      });
      this.#registration = updated;
      if (updated.state === "quarantined" || updated.state === "ended") {
        this.#onAuthorityInvalidated?.(`instance_state:${updated.state}`);
        void this.shutdown(`Runtime instance transitioned to ${updated.state}`);
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      this.#onAuthorityInvalidated?.(msg);
      void this.shutdown(`Heartbeat failure: ${msg}`);
    } finally {
      this.#heartbeatInFlight = false;
    }
  }

  async #runWorkerLoop(spec: WorkerLoopSpec): Promise<void> {
    let iterations = 0;
    while (!this.#controller.signal.aborted) {
      if (spec.maxIterations !== undefined && iterations >= spec.maxIterations) {
        break;
      }
      iterations += 1;
      try {
        await spec.runOnce(this.#controller.signal);
      } catch (err) {
        if (!this.#controller.signal.aborted) {
          spec.onError?.(err);
        }
      }
      if (this.#controller.signal.aborted) {
        break;
      }
      if (spec.maxIterations !== undefined && iterations >= spec.maxIterations) {
        break;
      }
      await abortableDelay(spec.intervalMs, this.#controller.signal);
    }
  }

  installSignalHandlers(signals: readonly NodeJS.Signals[] = ["SIGTERM", "SIGINT"]): () => void {
    const handlers = new Map<NodeJS.Signals, () => void>();
    for (const sig of signals) {
      const listener = (): void => {
        void this.shutdown(`signal:${sig}`);
      };
      handlers.set(sig, listener);
      process.on(sig, listener);
    }
    return () => {
      for (const [sig, listener] of handlers.entries()) {
        process.off(sig, listener);
      }
      handlers.clear();
    };
  }

  shutdown(reason = "shutdown"): Promise<ShutdownReport> {
    if (this.#shutdownPromise !== null) {
      return this.#shutdownPromise;
    }
    this.#shutdownPromise = this.#executeShutdown(reason);
    return this.#shutdownPromise;
  }

  async #executeShutdown(reason: string): Promise<ShutdownReport> {
    this.#draining = true;
    if (this.#heartbeatTimer !== null) {
      clearInterval(this.#heartbeatTimer);
      this.#heartbeatTimer = null;
    }

    if (
      this.#store !== undefined &&
      this.#registration !== undefined &&
      this.#registration.state === "active"
    ) {
      try {
        this.#registration = await this.#store.transitionInstanceState({
          instanceId: this.instanceId,
          controlEpoch: this.controlEpoch,
          expectedVersion: this.#registration.version,
          toState: "draining",
          now: this.#nowFn()
        });
      } catch {
        // Proceed with local drain even if store is unreachable
      }
    }

    this.#controller.abort(new Error(reason));
    this.sendDeadlines.abortAll(reason);

    const drainTasks: Promise<unknown>[] = [...this.#loopPromises];
    for (const hook of this.#drainHooks) {
      drainTasks.push(Promise.resolve().then(() => hook.drain()));
    }

    let timedOut = false;
    if (drainTasks.length > 0) {
      let timeoutHandle: ReturnType<typeof setTimeout> | null = null;
      const timeoutPromise = new Promise<"timeout">((resolve) => {
        timeoutHandle = setTimeout(() => resolve("timeout"), this.#drainTimeoutMs);
        timeoutHandle.unref();
      });
      const result = await Promise.race([
        Promise.allSettled(drainTasks).then(() => "drained" as const),
        timeoutPromise
      ]);
      if (timeoutHandle !== null) {
        clearTimeout(timeoutHandle);
      }
      timedOut = result === "timeout";
    }

    if (
      this.#store !== undefined &&
      this.#registration !== undefined &&
      this.#registration.state !== "ended"
    ) {
      try {
        this.#registration = await this.#store.transitionInstanceState({
          instanceId: this.instanceId,
          controlEpoch: this.controlEpoch,
          expectedVersion: this.#registration.version,
          toState: "ended",
          now: this.#nowFn()
        });
      } catch {
        // Ignore best-effort end update on shutdown
      }
    }

    return Object.freeze({
      reason,
      timedOut,
      state: this.#registration?.state ?? "ended"
    });
  }
}
