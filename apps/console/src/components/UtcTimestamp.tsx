import { type JSX } from "react";
import { formatUtcWithLocalOffset } from "../utils/format.js";

export function UtcTimestamp({
  value,
  emptyLabel = "Not recorded",
  showLocal = true
}: {
  readonly value: string | null | undefined;
  readonly emptyLabel?: string | undefined;
  readonly showLocal?: boolean | undefined;
}): JSX.Element {
  if (value === null || value === undefined || value.trim().length === 0) {
    return <span className="rq-meta-text">{emptyLabel}</span>;
  }

  const formatted = formatUtcWithLocalOffset(value);
  return (
    <span className="rq-stack-sm">
      <time dateTime={value} className="mono">
        {formatted.utc}
      </time>
      {showLocal && formatted.local !== null ? (
        <span className="rq-meta-text">{formatted.local}</span>
      ) : null}
    </span>
  );
}
