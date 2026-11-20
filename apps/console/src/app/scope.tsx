import { createContext, type ReactNode, useContext, useEffect, useMemo } from "react";
import { type WorkspaceProjectOptionDto } from "../api/dtos.js";
import { buildScopePartitionKey } from "../api/prepared-commands.js";
import { useConsoleRouter } from "./router.js";
import { useConsoleRuntime } from "./session.js";

export interface ActiveScopeValue {
  readonly principalId: string;
  readonly tenantId: string;
  readonly projectId: string;
  readonly scopeKey: string;
  readonly workspaceMeta: WorkspaceProjectOptionDto | null;
  readonly projectionEligibility: string;
}

const ScopeContext = createContext<ActiveScopeValue | null>(null);

export function ConsoleScopeProvider({ children }: { readonly children: ReactNode }) {
  const { route } = useConsoleRouter();
  const { session, queryCache, watchManager } = useConsoleRuntime();

  const scope = useMemo<ActiveScopeValue>(() => {
    const principalId = session?.principal_id ?? "anonymous";
    const tenantId = route.kind === "project" ? route.tenantId : "platform";
    const projectId = route.kind === "project" ? route.projectId : "none";
    const workspaceMeta =
      route.kind === "project" && session !== null
        ? session.workspaces.find(
            (w) => w.tenant_id === route.tenantId && w.project_id === route.projectId
          ) ?? null
        : null;
    const rolesSignature =
      workspaceMeta !== null
        ? [...workspaceMeta.roles, ...workspaceMeta.tenant_roles].toSorted().join(",")
        : session?.platform_roles.toSorted().join(",") ?? "none";

    return {
      principalId,
      tenantId,
      projectId,
      scopeKey: buildScopePartitionKey(principalId, tenantId, projectId),
      workspaceMeta,
      projectionEligibility: rolesSignature || "none"
    };
  }, [route, session]);

  useEffect(() => {
    // Switching project/tenant/principal immediately aborts old requests and closes open SSE watches.
    if (queryCache.activeScopeKey !== scope.scopeKey) {
      watchManager.closeAll();
      queryCache.setActiveScope(scope.scopeKey);
    }
  }, [queryCache, scope.scopeKey, watchManager]);

  return <ScopeContext.Provider value={scope}>{children}</ScopeContext.Provider>;
}

export function useActiveScope(): ActiveScopeValue {
  const ctx = useContext(ScopeContext);
  if (ctx === null) {
    throw new Error("useActiveScope must be used inside ConsoleScopeProvider");
  }
  return ctx;
}
