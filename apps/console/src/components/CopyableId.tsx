import { type JSX, useEffect, useState } from "react";
import { ConsoleIcon } from "./Icons.js";

export function CopyableId({
  value,
  label,
  compact = false
}: {
  readonly value: string;
  readonly label?: string | undefined;
  readonly compact?: boolean | undefined;
}): JSX.Element {
  const [copyState, setCopyState] = useState<"idle" | "copied" | "failed">("idle");

  useEffect(() => {
    if (copyState === "idle") {
      return;
    }
    const handle = window.setTimeout(() => {
      setCopyState("idle");
    }, 2200);
    return () => {
      window.clearTimeout(handle);
    };
  }, [copyState]);

  const displayValue =
    compact && value.length > 20
      ? `${value.slice(0, 8)}...${value.slice(-8)}`
      : value;

  const handleCopy = async (): Promise<void> => {
    try {
      if (typeof navigator !== "undefined" && navigator.clipboard !== undefined) {
        await navigator.clipboard.writeText(value);
        setCopyState("copied");
      } else {
        setCopyState("failed");
      }
    } catch {
      setCopyState("failed");
    }
  };

  return (
    <span className="rq-row">
      {label !== undefined ? <span className="rq-meta-text">{label}:</span> : null}
      <code className="mono" title={value}>
        {displayValue}
      </code>
      <button
        type="button"
        className="rq-btn"
        aria-label={label !== undefined ? `Copy ${label}` : `Copy identifier ${displayValue}`}
        onClick={() => {
          void handleCopy();
        }}
      >
        <ConsoleIcon name={copyState === "copied" ? "check" : "copy"} />
        <span>{copyState === "copied" ? "Copied" : copyState === "failed" ? "Copy Blocked" : "Copy"}</span>
      </button>
      <span className="visually-hidden" aria-live="polite">
        {copyState === "copied"
          ? `${label ?? "Identifier"} copied to clipboard.`
          : copyState === "failed"
            ? "Clipboard write was unavailable in this browser context."
            : ""}
      </span>
    </span>
  );
}
