import {
  createContext,
  type ReactNode,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState
} from "react";
import {
  type CanonicalUuid,
  type ProjectId,
  type TenantId,
  parseCanonicalUuid,
  parseProjectId,
  parseTenantId
} from "@relayquill/contracts";

export type AccessSection = "sign-in" | "enroll" | "recovery";
export type PlatformSection = "tenants" | "roles" | "installation" | "recovery" | "audit";
export type ProjectSection =
  | "overview"
  | "events"
  | "deliveries"
  | "replays"
  | "ordering"
  | "endpoints"
  | "subscriptions"
  | "schemas"
  | "representations"
  | "signing"
  | "limits"
  | "audit";

export type ConsoleRoute =
  | { readonly kind: "root" }
  | { readonly kind: "access"; readonly section: AccessSection }
  | { readonly kind: "status" }
  | { readonly kind: "onboarding" }
  | { readonly kind: "billing" }
  | { readonly kind: "settings_audit" }
  | { readonly kind: "platform"; readonly section: PlatformSection }
  | {
      readonly kind: "project";
      readonly tenantId: TenantId;
      readonly projectId: ProjectId;
      readonly section: ProjectSection;
      readonly itemId?: CanonicalUuid | undefined;
    }
  | { readonly kind: "invalid_scope"; readonly reason: string }
  | { readonly kind: "not_found"; readonly pathname: string };

const PROJECT_SECTIONS = new Set<ProjectSection>([
  "overview",
  "events",
  "deliveries",
  "replays",
  "ordering",
  "endpoints",
  "subscriptions",
  "schemas",
  "representations",
  "signing",
  "limits",
  "audit"
]);

const PLATFORM_SECTIONS = new Set<PlatformSection>([
  "tenants",
  "roles",
  "installation",
  "recovery",
  "audit"
]);

export function parseConsolePathname(pathname: string): ConsoleRoute {
  const normalized = pathname.replace(/\/+$/, "") || "/";
  if (normalized === "/") {
    return { kind: "root" };
  }
  if (normalized === "/status") {
    return { kind: "status" };
  }
  if (normalized === "/onboarding") {
    return { kind: "onboarding" };
  }
  if (normalized === "/billing") {
    return { kind: "billing" };
  }
  if (normalized === "/settings/audit") {
    return { kind: "settings_audit" };
  }

  const parts = normalized.slice(1).split("/");
  if (parts[0] === "access") {
    const sub = parts[1];
    if (sub === undefined || sub === "sign-in") {
      return { kind: "access", section: "sign-in" };
    }
    if (sub === "enroll" || sub === "recovery") {
      return { kind: "access", section: sub };
    }
    return { kind: "not_found", pathname };
  }

  if (parts[0] === "platform") {
    const sub = (parts[1] ?? "tenants") as PlatformSection;
    if (PLATFORM_SECTIONS.has(sub) && parts.length <= 2) {
      return { kind: "platform", section: sub };
    }
    return { kind: "not_found", pathname };
  }

  if (parts[0] === "t" && parts[2] === "p" && parts.length >= 4 && parts.length <= 6) {
    let tenantId: TenantId;
    let projectId: ProjectId;
    try {
      tenantId = parseTenantId(parts[1], "route.tenantId");
      projectId = parseProjectId(parts[3], "route.projectId");
    } catch {
      return { kind: "invalid_scope", reason: "URL tenant or project identifier is not a valid canonical UUID." };
    }

    const section = (parts[4] ?? "overview") as ProjectSection;
    if (!PROJECT_SECTIONS.has(section)) {
      return { kind: "not_found", pathname };
    }

    if (parts[5] !== undefined) {
      if (section !== "events" && section !== "deliveries") {
        return { kind: "not_found", pathname };
      }
      try {
        const itemId = parseCanonicalUuid(parts[5], "route.itemId");
        return { kind: "project", tenantId, projectId, section, itemId };
      } catch {
        return { kind: "invalid_scope", reason: "URL resource identifier is not a valid canonical UUID." };
      }
    }

    return { kind: "project", tenantId, projectId, section };
  }

  return { kind: "not_found", pathname };
}

export function buildProjectPath(
  tenantId: string,
  projectId: string,
  section: ProjectSection,
  itemId?: string
): string {
  const base = `/t/${encodeURIComponent(tenantId)}/p/${encodeURIComponent(projectId)}/${section}`;
  return itemId !== undefined ? `${base}/${encodeURIComponent(itemId)}` : base;
}

export function buildPlatformPath(section: PlatformSection): string {
  return `/platform/${section}`;
}

export function buildAccessPath(section: AccessSection): string {
  return `/access/${section}`;
}

export function buildStatusPath(): string {
  return "/status";
}

export function buildOnboardingPath(): string {
  return "/onboarding";
}

export function buildBillingPath(): string {
  return "/billing";
}

export function buildSettingsAuditPath(): string {
  return "/settings/audit";
}

interface RouterContextValue {
  readonly pathname: string;
  readonly route: ConsoleRoute;
  navigate: (path: string, options?: { readonly replace?: boolean | undefined }) => void;
}

const RouterContext = createContext<RouterContextValue | null>(null);

export function ConsoleRouterProvider({ children }: { readonly children: ReactNode }) {
  const [pathname, setPathname] = useState<string>(() =>
    typeof window !== "undefined" ? window.location.pathname : "/"
  );

  useEffect(() => {
    const onPopState = (): void => {
      setPathname(window.location.pathname);
    };
    window.addEventListener("popstate", onPopState);
    return () => {
      window.removeEventListener("popstate", onPopState);
    };
  }, []);

  const navigate = useCallback(
    (nextPath: string, options?: { readonly replace?: boolean | undefined }) => {
      const cleanPath = nextPath.split("?")[0]?.split("#")[0] || "/";
      if (typeof window !== "undefined" && window.location.pathname !== cleanPath) {
        if (options?.replace) {
          window.history.replaceState(null, "", cleanPath);
        } else {
          window.history.pushState(null, "", cleanPath);
        }
      }
      setPathname(cleanPath);
    },
    []
  );

  const route = useMemo(() => parseConsolePathname(pathname), [pathname]);
  const value = useMemo<RouterContextValue>(
    () => ({ pathname, route, navigate }),
    [pathname, route, navigate]
  );

  return <RouterContext.Provider value={value}>{children}</RouterContext.Provider>;
}

export function useConsoleRouter(): RouterContextValue {
  const ctx = useContext(RouterContext);
  if (ctx === null) {
    throw new Error("useConsoleRouter must be used inside ConsoleRouterProvider");
  }
  return ctx;
}
