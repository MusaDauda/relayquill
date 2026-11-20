import { useCallback, useEffect, useState } from "react";
import { type HttpApiResult } from "../api/http-client.js";
import {
  type ResourceViewState,
  resourceStateFromApiError
} from "../features/resource-state/model.js";
import { buildScopedQueryKey } from "./query-cache.js";
import { useActiveScope } from "./scope.js";
import { useConsoleRuntime } from "./session.js";

export interface UseScopedQueryOptions<T> {
  readonly resource: string;
  readonly filter?: Record<string, unknown> | undefined;
  readonly enabled?: boolean | undefined;
  readonly isEmpty?: ((data: NoInfer<T>) => boolean) | undefined;
  readonly extractVersion?: ((data: NoInfer<T>) => string | undefined) | undefined;
  readonly fetcher: (signal: AbortSignal) => Promise<HttpApiResult<T>>;
}

export function useScopedQuery<T>(options: UseScopedQueryOptions<T>): {
  readonly view: ResourceViewState<T>;
  readonly reload: () => void;
  readonly queryKey: string;
} {
  const { queryCache } = useConsoleRuntime();
  const scope = useActiveScope();
  const enabled = options.enabled ?? true;
  const filterKey = options.filter === undefined ? "{}" : JSON.stringify(options.filter);

  const queryKey = buildScopedQueryKey({
    principalId: scope.principalId,
    tenantId: scope.tenantId,
    projectId: scope.projectId,
    resource: options.resource,
    filter: filterKey,
    projectionEligibility: scope.projectionEligibility
  });

  const [revision, setRevision] = useState(0);
  const [view, setView] = useState<ResourceViewState<T>>(() => {
    const cached = queryCache.get<T>(queryKey);
    return cached?.viewState ?? { state: "loading" };
  });

  useEffect(() => {
    const unsubscribe = queryCache.subscribe(queryKey, () => {
      const entry = queryCache.get<T>(queryKey);
      if (entry !== undefined) {
        setView(entry.viewState);
      }
    });
    return unsubscribe;
  }, [queryCache, queryKey]);

  const reload = useCallback(() => {
    setRevision((prev) => prev + 1);
  }, []);

  useEffect(() => {
    if (!enabled) {
      return;
    }

    const capturedScopeKey = scope.scopeKey;
    const capturedPrincipal = scope.principalId;
    const capturedGeneration = queryCache.scopeGeneration;
    const controller = new AbortController();
    const unregister = queryCache.registerController(capturedScopeKey, controller);

    const existing = queryCache.get<T>(queryKey);
    if (existing !== undefined && existing.viewState.state === "current") {
      setView({
        state: "refreshing",
        data: existing.viewState.data,
        observedAt: existing.viewState.observedAt,
        requestId: existing.viewState.requestId
      });
    } else {
      setView({ state: "loading" });
    }

    void options.fetcher(controller.signal).then((res) => {
      unregister();
      if (controller.signal.aborted && res.ok === false && res.aborted) {
        return;
      }

      if (res.ok) {
        const empty = options.isEmpty?.(res.data) ?? false;
        const nextView: ResourceViewState<T> = empty
          ? {
              state: "authorized_empty",
              observedAt: res.meta.observed_at,
              requestId: res.meta.request_id
            }
          : {
              state: "current",
              data: res.data,
              observedAt: res.meta.observed_at,
              requestId: res.meta.request_id
            };

        const committed = queryCache.commitIfCurrent({
          key: queryKey,
          scopeKey: capturedScopeKey,
          principalId: capturedPrincipal,
          requestGeneration: capturedGeneration,
          viewState: nextView,
          incomingVersion: options.extractVersion?.(res.data),
          observedAt: res.meta.observed_at
        });
        if (committed) {
          setView(nextView);
        }
        return;
      }

      const retained =
        existing !== undefined &&
        (existing.viewState.state === "current" || existing.viewState.state === "refreshing")
          ? {
              data: existing.viewState.data,
              observedAt: existing.viewState.observedAt
            }
          : undefined;

      const errView = resourceStateFromApiError<T>(
        {
          status: res.status,
          code: res.code,
          message: res.message,
          acceptance: res.acceptance,
          retryable: res.retryable,
          retryAfterSeconds: res.retryAfterSeconds,
          resourceRef: res.resourceRef,
          unsupportedProtocol: res.unsupportedProtocol
        },
        retained
      );

      const committed = queryCache.commitIfCurrent({
        key: queryKey,
        scopeKey: capturedScopeKey,
        principalId: capturedPrincipal,
        requestGeneration: capturedGeneration,
        viewState: errView
      });
      if (committed) {
        setView(errView);
      }
    });

    return () => {
      controller.abort();
      unregister();
    };
  }, [enabled, queryKey, revision, scope.principalId, scope.scopeKey]);

  return { view, reload, queryKey };
}
