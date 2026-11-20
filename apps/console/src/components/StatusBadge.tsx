import { type JSX } from "react";
import { ConsoleIcon, type ConsoleIconName } from "./Icons.js";

export type StatusTone = "ok" | "info" | "warn" | "error" | "neutral";

export interface StatusPresentation {
  readonly tone: StatusTone;
  readonly icon: ConsoleIconName;
  readonly label: string;
}

const STATUS_MAP: Readonly<Record<string, StatusPresentation>> = {
  current: { tone: "ok", icon: "check", label: "Current" },
  active: { tone: "ok", icon: "check", label: "Active" },
  published: { tone: "ok", icon: "check", label: "Published" },
  approved: { tone: "ok", icon: "check", label: "Approved" },
  completed: { tone: "ok", icon: "check", label: "Completed" },
  verified_supported: { tone: "ok", icon: "shield", label: "Verified" },
  verified: { tone: "ok", icon: "shield", label: "Verified" },
  acknowledged: { tone: "ok", icon: "check", label: "HTTP Acknowledged" },
  http_acknowledged: { tone: "ok", icon: "check", label: "HTTP Acknowledged" },
  accepted: { tone: "ok", icon: "check", label: "Accepted" },
  closed: { tone: "ok", icon: "check", label: "Closed" },
  allowed: { tone: "ok", icon: "check", label: "Allowed" },
  ready: { tone: "info", icon: "activity", label: "Ready" },
  loading: { tone: "info", icon: "clock", label: "Loading" },
  refreshing: { tone: "info", icon: "refresh", label: "Refreshing" },
  sending: { tone: "info", icon: "activity", label: "Sending" },
  pending: { tone: "info", icon: "clock", label: "Pending" },
  preparing: { tone: "info", icon: "clock", label: "Preparing" },
  draft: { tone: "neutral", icon: "info", label: "Draft" },
  validated: { tone: "info", icon: "check", label: "Validated" },
  proposed: { tone: "info", icon: "clock", label: "Proposed" },
  approved_ready: { tone: "info", icon: "shield", label: "Reviewed" },
  awaiting_review: { tone: "warn", icon: "clock", label: "Awaiting Review" },
  awaiting_approval: { tone: "warn", icon: "clock", label: "Awaiting Approval" },
  awaiting_passkey: { tone: "info", icon: "key", label: "Awaiting Passkey" },
  paused_admission: { tone: "warn", icon: "alert", label: "Admission Paused" },
  paused: { tone: "warn", icon: "alert", label: "Paused" },
  paused_future: { tone: "warn", icon: "alert", label: "Future Paused" },
  send_hold: { tone: "warn", icon: "alert", label: "Send Hold" },
  draining: { tone: "warn", icon: "clock", label: "Draining" },
  stale: { tone: "warn", icon: "clock", label: "Stale" },
  half_open: { tone: "warn", icon: "activity", label: "Half-Open Probe" },
  retry_wait: { tone: "warn", icon: "clock", label: "Retry Wait" },
  unknown: { tone: "warn", icon: "alert", label: "Unknown" },
  acceptance_unknown: { tone: "warn", icon: "alert", label: "Acceptance Unknown" },
  outcome_unknown: { tone: "warn", icon: "alert", label: "Outcome Unknown" },
  pressure: { tone: "warn", icon: "alert", label: "Rate Pressure" },
  open: { tone: "error", icon: "alert", label: "Circuit Open" },
  blocked: { tone: "error", icon: "lock", label: "Blocked" },
  quarantined: { tone: "error", icon: "lock", label: "Quarantined" },
  suspended: { tone: "error", icon: "lock", label: "Suspended" },
  forbidden: { tone: "error", icon: "lock", label: "Forbidden" },
  conflict: { tone: "error", icon: "alert", label: "Conflict" },
  dead_letter: { tone: "error", icon: "error", label: "Dead Letter" },
  denied: { tone: "error", icon: "error", label: "Denied" },
  failed: { tone: "error", icon: "error", label: "Failed" },
  unavailable: { tone: "error", icon: "error", label: "Unavailable" },
  revoked: { tone: "neutral", icon: "lock", label: "Revoked" },
  retired: { tone: "neutral", icon: "lock", label: "Retired" },
  suppressed: { tone: "neutral", icon: "lock", label: "Suppressed" },
  withdrawn: { tone: "neutral", icon: "close", label: "Withdrawn" },
  aborted: { tone: "neutral", icon: "close", label: "Aborted" },
  expired: { tone: "neutral", icon: "clock", label: "Expired" },
  expired_content: { tone: "neutral", icon: "clock", label: "Expired Content" },
  not_found: { tone: "neutral", icon: "info", label: "Not Found" },
  authorized_empty: { tone: "neutral", icon: "info", label: "Empty" },
  not_observed: { tone: "neutral", icon: "info", label: "Not Observed" }
};

function formatFallbackLabel(raw: string): string {
  return raw
    .replace(/_/g, " ")
    .replace(/\b\w/g, (c) => c.toUpperCase());
}

export function resolveStatusPresentation(rawStatus: string): StatusPresentation {
  const normalized = rawStatus.trim().toLowerCase();
  const mapped = STATUS_MAP[normalized];
  if (mapped !== undefined) {
    return mapped;
  }
  return {
    tone: "neutral",
    icon: "info",
    label: formatFallbackLabel(rawStatus)
  };
}

export function StatusBadge({
  status,
  tone,
  label,
  icon,
  live,
  role
}: {
  readonly status?: string | undefined;
  readonly tone?: StatusTone | undefined;
  readonly label?: string | undefined;
  readonly icon?: ConsoleIconName | undefined;
  readonly live?: "polite" | "assertive" | undefined;
  readonly role?: "status" | "alert" | undefined;
}): JSX.Element {
  const fallback =
    status !== undefined
      ? resolveStatusPresentation(status)
      : { tone: "neutral" as StatusTone, icon: "info" as ConsoleIconName, label: "Unknown" };
  const resolvedTone = tone ?? fallback.tone;
  const resolvedLabel = label ?? fallback.label;
  const resolvedIcon = icon ?? fallback.icon;

  return (
    <span
      className="rq-badge"
      data-tone={resolvedTone}
      {...(live !== undefined ? { "aria-live": live } : {})}
      {...(role !== undefined ? { role } : {})}
    >
      <ConsoleIcon name={resolvedIcon} statusIcon />
      <span>{resolvedLabel}</span>
    </span>
  );
}
