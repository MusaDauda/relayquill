import { type JSX, type ReactNode, useEffect, useState } from "react";
import {
  getResourceStateDescriptor,
  type ResourceViewState
} from "../features/resource-state/model.js";
import { formatDurationSeconds } from "../utils/format.js";
import { ConsoleIcon } from "./Icons.js";
import { LosslessJsonViewer } from "./LosslessJsonViewer.js";
import { StatusBadge } from "./StatusBadge.js";
import { UtcTimestamp } from "./UtcTimestamp.js";

function PressureCountdown({ seconds }: { readonly seconds: number }): JSX.Element {
  const [remaining, setRemaining] = useState(Math.max(0, Math.ceil(seconds)));

  useEffect(() => {
    setRemaining(Math.max(0, Math.ceil(seconds)));
  }, [seconds]);

  useEffect(() => {
    if (remaining <= 0) {
      return;
    }
    const timer = window.setInterval(() => {
      setRemaining((prev) => (prev > 0 ? prev - 1 : 0));
    }, 1000);
    return () => {
      window.clearInterval(timer);
    };
  }, [remaining]);

  return (
    <span className="mono" aria-live="polite">
      {remaining > 0 ? `Retry-After: ${formatDurationSeconds(remaining)}` : "Retry window open"}
    </span>
  );
}

export function ResourceStatePanel<TData, TDraft = unknown>({
  view,
  resourceLabel,
  emptyTitle = "No records found",
  emptyDescription = "Your account is authorized for this scope, and the server returned zero matching items.",
  onRetry,
  onResolveOriginal,
  onReapplyDraft,
  children
}: {
  readonly view: ResourceViewState<TData, TDraft>;
  readonly resourceLabel: string;
  readonly emptyTitle?: string | undefined;
  readonly emptyDescription?: string | undefined;
  readonly onRetry?: (() => void) | undefined;
  readonly onResolveOriginal?: (() => void) | undefined;
  readonly onReapplyDraft?: ((draft: TDraft) => void) | undefined;
  readonly children: (data: NoInfer<TData>) => ReactNode;
}): JSX.Element {
  const descriptor = getResourceStateDescriptor(view.state);

  switch (view.state) {
    case "loading":
      return (
        <section
          className="rq-state-panel"
          data-tone="info"
          role="status"
          aria-live="polite"
          aria-label={`${resourceLabel} loading`}
        >
          <div className="rq-row-between">
            <StatusBadge status="loading" label={descriptor.label} />
            <span className="rq-meta-text">Awaiting authoritative response from server</span>
          </div>
          <p className="rq-meta-text">
            {view.message ?? `Loading ${resourceLabel}. No synthetic zero counts are shown before the server responds.`}
          </p>
        </section>
      );

    case "authorized_empty":
      return (
        <section
          className="rq-state-panel"
          role="status"
          aria-live="polite"
          aria-label={`${resourceLabel} empty`}
        >
          <div className="rq-row-between">
            <div className="rq-row">
              <StatusBadge status="authorized_empty" label={descriptor.label} />
              <strong className="rq-card-title">{emptyTitle}</strong>
            </div>
            {onRetry !== undefined ? (
              <button type="button" className="rq-btn" onClick={onRetry}>
                <ConsoleIcon name="refresh" />
                <span>Refresh</span>
              </button>
            ) : null}
          </div>
          <p className="rq-meta-text">{view.message ?? emptyDescription}</p>
          <div className="rq-row">
            <span className="rq-meta-text">Observed:</span>
            <UtcTimestamp value={view.observedAt} showLocal={false} />
            <span className="rq-meta-text mono">Request: {view.requestId}</span>
          </div>
        </section>
      );

    case "current":
      return <div className="rq-stack">{children(view.data)}</div>;

    case "refreshing":
      return (
        <div className="rq-stack">
          <div className="rq-state-panel" data-tone="info" role="status" aria-live="polite">
            <div className="rq-row-between">
              <StatusBadge status="refreshing" label="Refreshing" />
              <span className="rq-meta-text">
                Showing last verified snapshot while reloading {resourceLabel}.
              </span>
            </div>
          </div>
          {children(view.data)}
        </div>
      );

    case "stale":
      return (
        <div className="rq-stack">
          <section className="rq-state-panel" data-tone="warn" role="status" aria-live="polite">
            <div className="rq-row-between">
              <StatusBadge status="stale" label={descriptor.label} />
              {onRetry !== undefined ? (
                <button type="button" className="rq-btn" onClick={onRetry}>
                  <ConsoleIcon name="refresh" />
                  <span>Reload Latest</span>
                </button>
              ) : null}
            </div>
            <p className="rq-meta-text">
              {view.reason} Last verified observation: <UtcTimestamp value={view.observedAt} showLocal={false} />
            </p>
          </section>
          {children(view.data)}
        </div>
      );

    case "unknown":
      return (
        <div className="rq-stack">
          <section className="rq-state-panel" data-tone="warn" role="alert" aria-live="assertive">
            <div className="rq-row-between">
              <StatusBadge status="acceptance_unknown" label="Acceptance Unknown" />
              <span className="mono">{view.code}</span>
            </div>
            <p>{view.message}</p>
            <p className="rq-meta-text">
              The server outcome could not be confirmed. Do not mutate your business key or append
              random suffixes; resolve or retry the frozen original command instead.
            </p>
            <div className="rq-row">
              {onResolveOriginal !== undefined ? (
                <button type="button" className="rq-btn rq-btn-primary" onClick={onResolveOriginal}>
                  Resolve Original
                </button>
              ) : null}
              {onRetry !== undefined ? (
                <button type="button" className="rq-btn" onClick={onRetry}>
                  <ConsoleIcon name="refresh" />
                  <span>Retry Check</span>
                </button>
              ) : null}
            </div>
          </section>
          {view.data !== undefined ? children(view.data) : null}
        </div>
      );

    case "forbidden":
      return (
        <section className="rq-state-panel" data-tone="error" role="alert">
          <div className="rq-row-between">
            <StatusBadge status="forbidden" label="Forbidden (403)" />
            <span className="mono">{view.code}</span>
          </div>
          <p>{view.message}</p>
          <p className="rq-meta-text">
            {view.requirement ??
              "This action or view requires an explicit role assignment or active human data grant in the current tenant and project scope."}
          </p>
        </section>
      );

    case "not_found":
      return (
        <section className="rq-state-panel" role="alert">
          <div className="rq-row-between">
            <StatusBadge status="not_found" label="Not Found (404)" />
            <span className="mono">{view.code}</span>
          </div>
          <p>{view.message}</p>
          <p className="rq-meta-text">
            The requested {resourceLabel} does not exist in this scope or is outside your tenant and
            project boundary.
          </p>
        </section>
      );

    case "conflict":
      return (
        <section className="rq-state-panel" data-tone="error" role="alert">
          <div className="rq-row-between">
            <StatusBadge status="conflict" label="Conflict (409)" />
            <span className="mono">{view.code}</span>
          </div>
          <p>{view.message}</p>
          <p className="rq-meta-text">
            Your draft input has been preserved in memory. Compare against the latest server state
            before re-submitting with the current version.
          </p>
          {view.resourceRef !== undefined ? (
            <p className="mono">
              Target {view.resourceRef.kind} {view.resourceRef.id}
            </p>
          ) : null}
          {view.preservedDraft !== undefined || view.currentServerState !== undefined ? (
            <div className="rq-diff-grid">
              {view.preservedDraft !== undefined ? (
                <LosslessJsonViewer
                  title="Preserved Draft (Local)"
                  jsonText={JSON.stringify(view.preservedDraft, null, 2)}
                />
              ) : null}
              {view.currentServerState !== undefined ? (
                <LosslessJsonViewer
                  title="Latest Server State"
                  jsonText={JSON.stringify(view.currentServerState, null, 2)}
                />
              ) : null}
            </div>
          ) : null}
          <div className="rq-row">
            {onRetry !== undefined ? (
              <button type="button" className="rq-btn rq-btn-primary" onClick={onRetry}>
                <ConsoleIcon name="refresh" />
                <span>Reload Latest Server State</span>
              </button>
            ) : null}
            {view.preservedDraft !== undefined && onReapplyDraft !== undefined ? (
              <button
                type="button"
                className="rq-btn"
                onClick={() => {
                  onReapplyDraft(view.preservedDraft as TDraft);
                }}
              >
                Restore Draft Into Form
              </button>
            ) : null}
          </div>
        </section>
      );

    case "pressure":
      return (
        <div className="rq-stack">
          <section className="rq-state-panel" data-tone="warn" role="alert" aria-live="polite">
            <div className="rq-row-between">
              <StatusBadge status="pressure" label="Rate Pressure (429)" />
              {view.retryAfterSeconds !== undefined ? (
                <PressureCountdown seconds={view.retryAfterSeconds} />
              ) : (
                <span className="mono">{view.code}</span>
              )}
            </div>
            <p>{view.message}</p>
            {onRetry !== undefined ? (
              <div className="rq-row">
                <button type="button" className="rq-btn" onClick={onRetry}>
                  <ConsoleIcon name="refresh" />
                  <span>Retry Request</span>
                </button>
              </div>
            ) : null}
          </section>
          {view.data !== undefined ? children(view.data) : null}
        </div>
      );

    case "unavailable":
      return (
        <section className="rq-state-panel" data-tone="error" role="alert">
          <div className="rq-row-between">
            <StatusBadge status="unavailable" label="Unavailable (503)" />
            <span className="mono">{view.code}</span>
          </div>
          <p>{view.message}</p>
          {view.unsupportedProtocol === true ? (
            <p className="rq-meta-text">
              The server returned a protocol schema version unsupported by this console build. Reload
              the application or upgrade the console before retrying mutating actions.
            </p>
          ) : null}
          {onRetry !== undefined ? (
            <div className="rq-row">
              <button type="button" className="rq-btn rq-btn-primary" onClick={onRetry}>
                <ConsoleIcon name="refresh" />
                <span>Retry</span>
              </button>
            </div>
          ) : null}
        </section>
      );

    case "expired_content":
      return (
        <div className="rq-stack">
          <section className="rq-state-panel" role="status" aria-live="polite">
            <div className="rq-row-between">
              <StatusBadge status="expired_content" label="Expired Content (410)" />
              <span className="mono">{view.code}</span>
            </div>
            <p>{view.message}</p>
            <p className="rq-meta-text">
              Payload bytes have expired under project retention policy. Cryptographic hashes,
              timestamps, and delivery metadata remain available for audit verification.
            </p>
          </section>
          {view.data !== undefined ? children(view.data) : null}
        </div>
      );
  }
}
