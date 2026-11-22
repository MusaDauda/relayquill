import { type JSX, useEffect, useRef, useState } from "react";
import { AccessPage } from "../features/access/AccessPage.js";
import { AuditPage } from "../features/audit/AuditPage.js";
import { BillingPage } from "../features/billing/BillingPage.js";
import { DeliveriesPage } from "../features/deliveries/DeliveriesPage.js";
import { EndpointsPage } from "../features/endpoints/EndpointsPage.js";
import { EventsPage } from "../features/events/EventsPage.js";
import { LimitsPage } from "../features/limits/LimitsPage.js";
import { OnboardingPage } from "../features/onboarding/OnboardingPage.js";
import { OrderingPage } from "../features/ordering/OrderingPage.js";
import { PlatformPage } from "../features/platform/PlatformPage.js";
import { OverviewPage } from "../features/projects/OverviewPage.js";
import { ReplaysPage } from "../features/replays/ReplaysPage.js";
import { SchemasPage } from "../features/schemas/SchemasPage.js";
import { SettingsAuditPage } from "../features/settings/SettingsAuditPage.js";
import { SigningPage } from "../features/signing/SigningPage.js";
import { StatusPage } from "../features/status/StatusPage.js";
import { SubscriptionsPage } from "../features/subscriptions/SubscriptionsPage.js";
import { ConsoleIcon } from "../components/Icons.js";
import { ResourceStatePanel } from "../components/ResourceStatePanel.js";
import { StatusBadge } from "../components/StatusBadge.js";
import { formatCountdown } from "../utils/format.js";
import { ConsoleErrorBoundary } from "./ErrorBoundary.js";
import {
  type PlatformSection,
  type ProjectSection,
  ConsoleRouterProvider,
  buildAccessPath,
  buildBillingPath,
  buildOnboardingPath,
  buildPlatformPath,
  buildProjectPath,
  buildSettingsAuditPath,
  buildStatusPath,
  useConsoleRouter
} from "./router.js";
import { ConsoleScopeProvider } from "./scope.js";
import { ConsoleSessionProvider, useConsoleRuntime } from "./session.js";

const PROJECT_NAV_ITEMS: readonly {
  readonly section: ProjectSection;
  readonly label: string;
}[] = [
  { section: "overview", label: "Overview" },
  { section: "events", label: "Events" },
  { section: "deliveries", label: "Deliveries" },
  { section: "replays", label: "Replays & Triage" },
  { section: "ordering", label: "Ordering & Circuits" },
  { section: "endpoints", label: "Endpoints" },
  { section: "subscriptions", label: "Subscriptions" },
  { section: "schemas", label: "Schemas & Contracts" },
  { section: "representations", label: "Representations" },
  { section: "signing", label: "Signing & Keys" },
  { section: "limits", label: "Limits & Grants" },
  { section: "audit", label: "Audit Log" }
];

const PLATFORM_NAV_ITEMS: readonly {
  readonly section: PlatformSection;
  readonly label: string;
}[] = [
  { section: "tenants", label: "Tenants & Projects" },
  { section: "roles", label: "Platform Roles" },
  { section: "installation", label: "Installation Gates" },
  { section: "recovery", label: "Restricted Recovery" },
  { section: "audit", label: "Platform Audit" }
];

function ConsoleShell(): JSX.Element {
  const { pathname, route, navigate } = useConsoleRouter();
  const runtime = useConsoleRuntime();
  const { sessionState, session } = runtime;

  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const mainRef = useRef<HTMLElement | null>(null);

  useEffect(() => {
    setMobileMenuOpen(false);
    if (mainRef.current !== null) {
      mainRef.current.focus();
    }
  }, [pathname]);

  const activeWorkspace =
    route.kind === "project"
      ? session?.workspaces.find(
          (w) => w.tenant_id === route.tenantId && w.project_id === route.projectId
        ) ?? null
      : session?.workspaces[0] ?? null;

  const currentTenantId =
    route.kind === "project" ? route.tenantId : (activeWorkspace?.tenant_id ?? null);
  const currentProjectId =
    route.kind === "project" ? route.projectId : (activeWorkspace?.project_id ?? null);

  const renderMainContent = (): JSX.Element => {
    if (route.kind === "status") {
      return <StatusPage />;
    }

    if (sessionState.status === "loading") {
      return (
        <ResourceStatePanel view={{ state: "loading" }} resourceLabel="Operator session">
          {() => <></>}
        </ResourceStatePanel>
      );
    }

    if (sessionState.status === "unavailable") {
      return (
        <ResourceStatePanel
          view={{
            state: "unavailable",
            code: sessionState.error.code,
            message: sessionState.error.message,
            retryable: sessionState.error.retryable,
            unsupportedProtocol: sessionState.error.unsupportedProtocol
          }}
          resourceLabel="Operator session"
          onRetry={() => {
            void runtime.refreshSession();
          }}
        >
          {() => <></>}
        </ResourceStatePanel>
      );
    }

    if (route.kind === "invalid_scope") {
      return (
        <section className="rq-state-panel" data-tone="error" role="alert">
          <div className="rq-row">
            <StatusBadge status="error" label="Invalid Scope URL" />
            <strong>Route Rejected</strong>
          </div>
          <p className="rq-meta-text">{route.reason}</p>
        </section>
      );
    }

    if (route.kind === "not_found") {
      return (
        <section className="rq-state-panel" data-tone="warn" role="status">
          <div className="rq-row">
            <StatusBadge status="warn" label="Not Found" />
            <strong>Unknown Console Route</strong>
          </div>
          <p className="rq-meta-text mono">{route.pathname}</p>
        </section>
      );
    }

    if (route.kind === "access") {
      return <AccessPage section={route.section} />;
    }

    if (session === null) {
      return <AccessPage section="sign-in" />;
    }

    if (route.kind === "onboarding") {
      return <OnboardingPage />;
    }

    if (route.kind === "billing") {
      return <BillingPage />;
    }

    if (route.kind === "settings_audit") {
      return <SettingsAuditPage />;
    }

    if (route.kind === "root") {
      if (activeWorkspace !== null) {
        return <OverviewPage />;
      }
      if (session.platform_roles.length > 0) {
        return <PlatformPage section="tenants" />;
      }
      return <OnboardingPage />;
    }

    if (route.kind === "platform") {
      return <PlatformPage section={route.section} />;
    }

    return (
      <>
        {route.section === "overview" ? <OverviewPage /> : null}
        {route.section === "events" ? <EventsPage selectedEventId={route.itemId} /> : null}
        {route.section === "deliveries" ? (
          <DeliveriesPage selectedDeliveryId={route.itemId} />
        ) : null}
        {route.section === "replays" ? <ReplaysPage /> : null}
        {route.section === "ordering" ? <OrderingPage /> : null}
        {route.section === "endpoints" ? <EndpointsPage /> : null}
        {route.section === "subscriptions" ? <SubscriptionsPage /> : null}
        {route.section === "schemas" ? <SchemasPage initialTab="schemas" /> : null}
        {route.section === "representations" ? <SchemasPage initialTab="representations" /> : null}
        {route.section === "signing" ? <SigningPage /> : null}
        {route.section === "limits" ? <LimitsPage /> : null}
        {route.section === "audit" ? <AuditPage mode="project" /> : null}
      </>
    );
  };

  return (
    <>
      <a className="skip-link" href="#main-content">
        Skip to main content
      </a>

      <div className="rq-mobile-menu-bar">
        <strong>Relayquill Console</strong>
        <button
          type="button"
          className="rq-btn"
          aria-expanded={mobileMenuOpen}
          aria-controls="console-nav-rail"
          onClick={() => {
            setMobileMenuOpen((prev) => !prev);
          }}
        >
          {mobileMenuOpen ? "Close Menu" : "Menu"}
        </button>
      </div>

      <div className="rq-shell">
        <aside
          id="console-nav-rail"
          className="rq-rail"
          data-mobile-collapsed={mobileMenuOpen ? "false" : "true"}
        >
          <div className="rq-brand">
            <div>
              <h2 className="rq-brand-title">Relayquill</h2>
              <p className="rq-brand-subtitle">Webhook Operations Console</p>
            </div>
            <ConsoleIcon name="shield" />
          </div>

          <nav aria-label="Console navigation" className="rq-stack-sm">
            {currentTenantId !== null && currentProjectId !== null ? (
              <div>
                <h3 className="rq-nav-group-title">Project Scope</h3>
                <ul className="rq-nav-list">
                  {PROJECT_NAV_ITEMS.map((item) => {
                    const href = buildProjectPath(currentTenantId, currentProjectId, item.section);
                    const isActive =
                      (route.kind === "project" && route.section === item.section) ||
                      (route.kind === "root" && item.section === "overview");
                    return (
                      <li key={item.section}>
                        <a
                          href={href}
                          className="rq-nav-link"
                          aria-current={isActive ? "page" : undefined}
                          onClick={(e) => {
                            e.preventDefault();
                            navigate(href);
                          }}
                        >
                          <span>{item.label}</span>
                        </a>
                      </li>
                    );
                  })}
                </ul>
              </div>
            ) : null}

            {session !== null && session.platform_roles.length > 0 ? (
              <div>
                <h3 className="rq-nav-group-title">Platform Scope</h3>
                <ul className="rq-nav-list">
                  {PLATFORM_NAV_ITEMS.map((item) => {
                    const href = buildPlatformPath(item.section);
                    const isActive = route.kind === "platform" && route.section === item.section;
                    return (
                      <li key={item.section}>
                        <a
                          href={href}
                          className="rq-nav-link"
                          aria-current={isActive ? "page" : undefined}
                          onClick={(e) => {
                            e.preventDefault();
                            navigate(href);
                          }}
                        >
                          <span>{item.label}</span>
                        </a>
                      </li>
                    );
                  })}
                </ul>
              </div>
            ) : null}

            <div>
              <h3 className="rq-nav-group-title">Commercial &amp; Account</h3>
              <ul className="rq-nav-list">
                {session !== null ? (
                  <>
                    <li>
                      <a
                        href={buildOnboardingPath()}
                        className="rq-nav-link"
                        aria-current={route.kind === "onboarding" ? "page" : undefined}
                        onClick={(e) => {
                          e.preventDefault();
                          navigate(buildOnboardingPath());
                        }}
                      >
                        <span>Onboarding</span>
                      </a>
                    </li>
                    <li>
                      <a
                        href={buildBillingPath()}
                        className="rq-nav-link"
                        aria-current={route.kind === "billing" ? "page" : undefined}
                        onClick={(e) => {
                          e.preventDefault();
                          navigate(buildBillingPath());
                        }}
                      >
                        <span>Billing &amp; Usage</span>
                      </a>
                    </li>
                    <li>
                      <a
                        href={buildSettingsAuditPath()}
                        className="rq-nav-link"
                        aria-current={route.kind === "settings_audit" ? "page" : undefined}
                        onClick={(e) => {
                          e.preventDefault();
                          navigate(buildSettingsAuditPath());
                        }}
                      >
                        <span>Audit &amp; Privacy</span>
                      </a>
                    </li>
                  </>
                ) : null}
                <li>
                  <a
                    href={buildStatusPath()}
                    className="rq-nav-link"
                    aria-current={route.kind === "status" ? "page" : undefined}
                    onClick={(e) => {
                      e.preventDefault();
                      navigate(buildStatusPath());
                    }}
                  >
                    <span>System Status</span>
                  </a>
                </li>
              </ul>
            </div>

            <div>
              <h3 className="rq-nav-group-title">Access &amp; Passkeys</h3>
              <ul className="rq-nav-list">
                <li>
                  <a
                    href={buildAccessPath("sign-in")}
                    className="rq-nav-link"
                    aria-current={
                      route.kind === "access" && route.section === "sign-in" ? "page" : undefined
                    }
                    onClick={(e) => {
                      e.preventDefault();
                      navigate(buildAccessPath("sign-in"));
                    }}
                  >
                    Sign-In & Sessions
                  </a>
                </li>
                <li>
                  <a
                    href={buildAccessPath("enroll")}
                    className="rq-nav-link"
                    aria-current={
                      route.kind === "access" && route.section === "enroll" ? "page" : undefined
                    }
                    onClick={(e) => {
                      e.preventDefault();
                      navigate(buildAccessPath("enroll"));
                    }}
                  >
                    Bootstrap / Enroll
                  </a>
                </li>
                <li>
                  <a
                    href={buildAccessPath("recovery")}
                    className="rq-nav-link"
                    aria-current={
                      route.kind === "access" && route.section === "recovery" ? "page" : undefined
                    }
                    onClick={(e) => {
                      e.preventDefault();
                      navigate(buildAccessPath("recovery"));
                    }}
                  >
                    Factor Recovery
                  </a>
                </li>
              </ul>
            </div>
          </nav>
        </aside>

        <div className="rq-workspace-column">
          <header className="rq-topbar">
            <div className="rq-scope-bar">
              {session !== null && session.workspaces.length > 0 ? (
                <label className="rq-row">
                  <span className="rq-label">Workspace:</span>
                  <select
                    aria-label="Active tenant and project workspace"
                    className="rq-select"
                    value={
                      currentTenantId !== null && currentProjectId !== null
                        ? `${currentTenantId}:${currentProjectId}`
                        : ""
                    }
                    onChange={(e) => {
                      const [tId, pId] = e.target.value.split(":");
                      if (tId !== undefined && pId !== undefined) {
                        const targetSection =
                          route.kind === "project" ? route.section : "overview";
                        navigate(buildProjectPath(tId, pId, targetSection));
                      }
                    }}
                  >
                    {session.workspaces.map((ws) => (
                      <option
                        key={`${ws.tenant_id}:${ws.project_id}`}
                        value={`${ws.tenant_id}:${ws.project_id}`}
                      >
                        {ws.tenant_display_name} / {ws.project_name}
                      </option>
                    ))}
                  </select>
                </label>
              ) : (
                <span className="rq-meta-text">
                  {session !== null
                    ? "Platform-scoped session (no project workspace bound)"
                    : "Unauthenticated operator session"}
                </span>
              )}
            </div>

            {session !== null ? (
              <div className="rq-row">
                <span className="rq-meta-text">
                  <strong>{session.display_name}</strong> | Idle TTL{" "}
                  <span className="mono">{formatCountdown(session.idle_expires_at)}</span>
                </span>
                <button
                  type="button"
                  className="rq-btn"
                  onClick={() => {
                    void runtime.logout().then(() => {
                      navigate(buildAccessPath("sign-in"));
                    });
                  }}
                >
                  Sign Out
                </button>
              </div>
            ) : null}
          </header>

          <main id="main-content" ref={mainRef} tabIndex={-1} className="rq-main">
            {renderMainContent()}
          </main>
        </div>
      </div>
    </>
  );
}

export function App(): JSX.Element {
  return (
    <ConsoleErrorBoundary>
      <ConsoleSessionProvider>
        <ConsoleRouterProvider>
          <ConsoleScopeProvider>
            <ConsoleShell />
          </ConsoleScopeProvider>
        </ConsoleRouterProvider>
      </ConsoleSessionProvider>
    </ConsoleErrorBoundary>
  );
}
