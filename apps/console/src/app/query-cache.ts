import { type CanonicalUtcTimestamp, parseInt64BigInt } from "@relayquill/contracts";
import { type ResourceViewState } from "../features/resource-state/model.js";

export interface ScopedQueryKeyParts {
  readonly principalId: string;
  readonly tenantId: string;
  readonly projectId: string;
  readonly resource: string;
  readonly filter: string;
  readonly projectionEligibility: string;
}

export function buildScopedQueryKey(parts: ScopedQueryKeyParts): string {
  return JSON.stringify([
    parts.principalId,
    parts.tenantId,
    parts.projectId,
    parts.resource,
    parts.filter,
    parts.projectionEligibility
  ]);
}

export interface CacheEntry<T = unknown> {
  readonly key: string;
  readonly scopeKey: string;
  readonly principalId: string;
  readonly viewState: ResourceViewState<T>;
  readonly knownVersion?: string | undefined;
  readonly observedAt?: CanonicalUtcTimestamp | undefined;
}

type CacheListener = () => void;

export class ScopedQueryCache {
  readonly #entries = new Map<string, CacheEntry>();
  readonly #inFlightControllers = new Map<string, Set<AbortController>>();
  readonly #listeners = new Map<string, Set<CacheListener>>();
  #activeScopeKey = "";
  #scopeGeneration = 0;

  get activeScopeKey(): string {
    return this.#activeScopeKey;
  }

  get scopeGeneration(): number {
    return this.#scopeGeneration;
  }

  setActiveScope(scopeKey: string): void {
    if (this.#activeScopeKey === scopeKey) {
      return;
    }
    this.abortScope(this.#activeScopeKey);
    this.#activeScopeKey = scopeKey;
    this.#scopeGeneration += 1;
  }

  registerController(scopeKey: string, controller: AbortController): () => void {
    let set = this.#inFlightControllers.get(scopeKey);
    if (set === undefined) {
      set = new Set();
      this.#inFlightControllers.set(scopeKey, set);
    }
    set.add(controller);
    return () => {
      set.delete(controller);
      if (set.size === 0) {
        this.#inFlightControllers.delete(scopeKey);
      }
    };
  }

  abortScope(scopeKey: string): void {
    if (!scopeKey) {
      return;
    }
    const set = this.#inFlightControllers.get(scopeKey);
    if (set === undefined) {
      return;
    }
    for (const controller of set) {
      controller.abort();
    }
    set.clear();
    this.#inFlightControllers.delete(scopeKey);
  }

  get<T>(key: string): CacheEntry<T> | undefined {
    return this.#entries.get(key) as CacheEntry<T> | undefined;
  }

  commitIfCurrent<T>(opts: {
    readonly key: string;
    readonly scopeKey: string;
    readonly principalId: string;
    readonly requestGeneration: number;
    readonly viewState: ResourceViewState<T>;
    readonly incomingVersion?: string | undefined;
    readonly observedAt?: CanonicalUtcTimestamp | undefined;
  }): boolean {
    if (
      opts.requestGeneration !== this.#scopeGeneration ||
      opts.scopeKey !== this.#activeScopeKey
    ) {
      // Discard out-of-order responses from an old tenant/project/principal scope.
      return false;
    }

    const existing = this.#entries.get(opts.key);
    if (
      existing?.knownVersion !== undefined &&
      opts.incomingVersion !== undefined &&
      opts.viewState.state === "current"
    ) {
      try {
        const prevVer = parseInt64BigInt(existing.knownVersion, "prev_version");
        const nextVer = parseInt64BigInt(opts.incomingVersion, "next_version");
        if (nextVer < prevVer) {
          // Do not overwrite a newer known version with stale replica data.
          this.#entries.set(opts.key, {
            ...existing,
            viewState: existing.viewState.state === "current"
              ? {
                  state: "stale",
                  data: existing.viewState.data,
                  observedAt: existing.viewState.observedAt,
                  reason: `Replica returned older version ${opts.incomingVersion}; retained version ${existing.knownVersion}.`
                }
              : existing.viewState
          });
          this.#notify(opts.key);
          return false;
        }
      } catch {
        // Ignore unparseable comparison and store latest validated state.
      }
    }

    this.#entries.set(opts.key, {
      key: opts.key,
      scopeKey: opts.scopeKey,
      principalId: opts.principalId,
      viewState: opts.viewState,
      knownVersion: opts.incomingVersion ?? existing?.knownVersion,
      observedAt: opts.observedAt ?? existing?.observedAt
    });
    this.#notify(opts.key);
    return true;
  }

  invalidateKey(key: string): void {
    this.#notify(key);
  }

  clearForPrincipal(principalId: string): void {
    for (const [key, entry] of this.#entries.entries()) {
      if (entry.principalId === principalId) {
        this.#entries.delete(key);
        this.#notify(key);
      }
    }
  }

  clearAll(): void {
    for (const scopeKey of this.#inFlightControllers.keys()) {
      this.abortScope(scopeKey);
    }
    const keys = Array.from(this.#entries.keys());
    this.#entries.clear();
    for (const key of keys) {
      this.#notify(key);
    }
  }

  subscribe(key: string, listener: CacheListener): () => void {
    let set = this.#listeners.get(key);
    if (set === undefined) {
      set = new Set();
      this.#listeners.set(key, set);
    }
    set.add(listener);
    return () => {
      set.delete(listener);
      if (set.size === 0) {
        this.#listeners.delete(key);
      }
    };
  }

  #notify(key: string): void {
    const set = this.#listeners.get(key);
    if (set === undefined) {
      return;
    }
    for (const listener of set) {
      listener();
    }
  }
}
