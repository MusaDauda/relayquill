import { type JSX } from "react";
import { CONSOLE_VIEW_STATES, type ConsoleViewState } from "@relayquill/domain";
import { type ConsoleIconName } from "./Icons.js";
import { StatusBadge, type StatusTone } from "./StatusBadge.js";

export interface CommercialViewStateDescriptor {
  readonly state: ConsoleViewState;
  readonly label: string;
  readonly tone: StatusTone;
  readonly icon: ConsoleIconName;
  readonly role: "status" | "alert";
  readonly summary: string;
}

const COMMERCIAL_VIEW_META: Readonly<Record<ConsoleViewState, CommercialViewStateDescriptor>> =
  Object.freeze({
    loading: Object.freeze({
      state: "loading",
      label: "Loading",
      tone: "info",
      icon: "clock",
      role: "status",
      summary: "Fetching authoritative workspace and billing state from the API."
    }),
    empty: Object.freeze({
      state: "empty",
      label: "Empty",
      tone: "neutral",
      icon: "info",
      role: "status",
      summary: "Authorized workspace query returned zero records for this filter."
    }),
    ready: Object.freeze({
      state: "ready",
      label: "Ready",
      tone: "ok",
      icon: "check",
      role: "status",
      summary: "Workspace entitlements and telemetry match authoritative server state."
    }),
    partial: Object.freeze({
      state: "partial",
      label: "Partial Data",
      tone: "warn",
      icon: "alert",
      role: "status",
      summary: "Primary records loaded, while one secondary telemetry feed is still reconciling."
    }),
    error: Object.freeze({
      state: "error",
      label: "Error",
      tone: "error",
      icon: "error",
      role: "alert",
      summary: "The server rejected or failed this request; inspect details and retry safely."
    }),
    unauthorized: Object.freeze({
      state: "unauthorized",
      label: "Unauthorized",
      tone: "error",
      icon: "lock",
      role: "alert",
      summary: "Sign in with a valid operator session or required role permission."
    }),
    rate_limited: Object.freeze({
      state: "rate_limited",
      label: "Rate Limited",
      tone: "warn",
      icon: "clock",
      role: "alert",
      summary: "Request throttling is active; wait for the retry window before repeating."
    }),
    quota_exceeded: Object.freeze({
      state: "quota_exceeded",
      label: "Quota Hard Cap Reached",
      tone: "warn",
      icon: "alert",
      role: "alert",
      summary:
        "Monthly delivery allowance reached hard cap. Upgrade in Billing; security keys, audit export, billing portal, self-cancellation, and GDPR erasure stay unlocked."
    })
  });

/** Resolves UI metadata for all 8 commercial ConsoleViewState variants. */
export function describeCommercialViewState(state: ConsoleViewState): CommercialViewStateDescriptor {
  return COMMERCIAL_VIEW_META[state];
}

export { CONSOLE_VIEW_STATES };

export function CommercialStateBanner({
  state,
  detail,
  onNavigateBilling,
  onRetry
}: {
  readonly state: ConsoleViewState;
  readonly detail?: string | undefined;
  readonly onNavigateBilling?: (() => void) | undefined;
  readonly onRetry?: (() => void) | undefined;
}): JSX.Element {
  const descriptor = describeCommercialViewState(state);

  return (
    <section className="rq-state-panel" data-tone={descriptor.tone} role={descriptor.role}>
      <div className="rq-row-between">
        <div className="rq-row">
          <StatusBadge
            tone={descriptor.tone}
            icon={descriptor.icon}
            label={descriptor.label}
          />
          <strong>{descriptor.label}</strong>
        </div>
        <div className="rq-row">
          {state === "quota_exceeded" && onNavigateBilling !== undefined ? (
            <button type="button" className="rq-btn rq-btn-primary" onClick={onNavigateBilling}>
              Manage Plan &amp; Quota
            </button>
          ) : null}
          {(state === "error" || state === "partial" || state === "rate_limited") &&
          onRetry !== undefined ? (
            <button type="button" className="rq-btn" onClick={onRetry}>
              Retry
            </button>
          ) : null}
        </div>
      </div>
      <p className="rq-meta-text">{detail ?? descriptor.summary}</p>
    </section>
  );
}
