import { type JSX, useCallback, useEffect, useState } from "react";
import { type PublicStatusComponentDto, type PublicStatusDto } from "../../api/dtos.js";
import { buildAccessPath, useConsoleRouter } from "../../app/router.js";
import { useConsoleRuntime } from "../../app/session.js";
import { CommercialStateBanner } from "../../components/CommercialStateBanner.js";
import { ConsoleIcon } from "../../components/Icons.js";
import { StatusBadge } from "../../components/StatusBadge.js";
import { UtcTimestamp } from "../../components/UtcTimestamp.js";

const COMPONENT_LABELS: Readonly<Record<string, string>> = {
  admission_api: "Admission API",
  postgres_18_rq: "PostgreSQL Primary Ledger",
  outbox_relay: "Transactional Outbox Relay",
  sender_egress_fleet: "Signed Delivery Egress"
};

function renderComponentMetric(component: PublicStatusComponentDto): string {
  if (typeof component.pending_events === "number") {
    return `${component.pending_events} pending outbox events`;
  }
  if (typeof component.success_rate_24h === "number") {
    return `${(component.success_rate_24h * 100).toFixed(2)}% 24h acknowledged rate`;
  }
  return component.status === "operational"
    ? "Accepting authoritative operations"
    : "Check installation mode notes";
}

export function StatusPage(): JSX.Element {
  const { api, session } = useConsoleRuntime();
  const { navigate } = useConsoleRouter();

  const [loading, setLoading] = useState(true);
  const [statusData, setStatusData] = useState<PublicStatusDto | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const loadStatus = useCallback(async (signal?: AbortSignal): Promise<void> => {
    setLoading(true);
    setErrorMessage(null);
    const res = await api.getPublicStatus(signal);
    if (res.ok) {
      setStatusData(res.data);
      setLoading(false);
      return;
    }
    if (!res.aborted) {
      setErrorMessage(`${res.code}: ${res.message}`);
      setLoading(false);
    }
  }, [api]);

  useEffect(() => {
    const controller = new AbortController();
    void loadStatus(controller.signal);
    return () => {
      controller.abort();
    };
  }, [loadStatus]);

  return (
    <div className="rq-stack">
      <header className="rq-page-header">
        <div>
          <h1 className="rq-page-title">Relayquill Platform Status</h1>
          <p className="rq-page-lead">
            Live component readiness and aggregate delivery health without exposing tenant identifiers
            or credentials.
          </p>
        </div>
        <div className="rq-row">
          {statusData !== null ? (
            <StatusBadge
              status={
                statusData.overall_status === "operational"
                  ? "active"
                  : statusData.overall_status === "degraded"
                    ? "pressure"
                    : "paused"
              }
              label={statusData.overall_status.toUpperCase()}
            />
          ) : null}
          <button
            type="button"
            className="rq-btn"
            disabled={loading}
            onClick={() => {
              void loadStatus();
            }}
          >
            <ConsoleIcon name="refresh" />
            <span>{loading ? "Checking..." : "Refresh"}</span>
          </button>
          {session === null ? (
            <button
              type="button"
              className="rq-btn rq-btn-primary"
              onClick={() => {
                navigate(buildAccessPath("sign-in"));
              }}
            >
              Sign In
            </button>
          ) : null}
        </div>
      </header>

      {loading && statusData === null ? (
        <CommercialStateBanner state="loading" detail="Polling /api/v1/status component SLA telemetry..." />
      ) : null}

      {errorMessage !== null ? (
        <CommercialStateBanner
          state="error"
          detail={errorMessage}
          onRetry={() => {
            void loadStatus();
          }}
        />
      ) : null}

      {statusData !== null ? (
        <>
          <section className="rq-card" aria-label="Status overview">
            <div className="rq-row-between">
              <h2 className="rq-section-title">Overall Service State</h2>
              <UtcTimestamp value={statusData.checked_at} showLocal={false} />
            </div>
            <div className="rq-grid-2">
              {statusData.components.map((component) => (
                <article key={component.name} className="rq-card-inset">
                  <div className="rq-row-between">
                    <strong>{COMPONENT_LABELS[component.name] ?? component.name}</strong>
                    <StatusBadge
                      status={component.status === "operational" ? "active" : "pressure"}
                      label={component.status}
                    />
                  </div>
                  <p className="rq-meta-text mono rq-tabular">{renderComponentMetric(component)}</p>
                </article>
              ))}
            </div>
          </section>
        </>
      ) : null}
    </div>
  );
}
