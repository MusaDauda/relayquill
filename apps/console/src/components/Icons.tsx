import { type JSX } from "react";

export type ConsoleIconName =
  | "check"
  | "clock"
  | "alert"
  | "error"
  | "lock"
  | "refresh"
  | "copy"
  | "shield"
  | "key"
  | "activity"
  | "info"
  | "menu"
  | "close"
  | "chevron_left"
  | "chevron_right";

export function ConsoleIcon({
  name,
  statusIcon = false
}: {
  readonly name: ConsoleIconName;
  readonly statusIcon?: boolean | undefined;
}): JSX.Element {
  const commonProps = {
    width: 16,
    height: 16,
    viewBox: "0 0 16 16",
    fill: "none",
    stroke: "currentColor",
    strokeWidth: 1.6,
    strokeLinecap: "round" as const,
    strokeLinejoin: "round" as const,
    "aria-hidden": true as const,
    ...(statusIcon ? { "data-status-icon": "true" } : {})
  };

  switch (name) {
    case "check":
      return (
        <svg {...commonProps}>
          <path d="M3.2 8.4L6.4 11.4L12.8 4.8" />
        </svg>
      );
    case "clock":
      return (
        <svg {...commonProps}>
          <circle cx="8" cy="8" r="5.5" />
          <path d="M8 5V8.2L10.3 9.7" />
        </svg>
      );
    case "alert":
      return (
        <svg {...commonProps}>
          <path d="M8 2.4L13.8 12.8H2.2L8 2.4Z" />
          <path d="M8 6.4V9.3" />
          <circle cx="8" cy="11.2" r="0.6" fill="currentColor" stroke="none" />
        </svg>
      );
    case "error":
      return (
        <svg {...commonProps}>
          <circle cx="8" cy="8" r="5.5" />
          <path d="M5.7 5.7L10.3 10.3M10.3 5.7L5.7 10.3" />
        </svg>
      );
    case "lock":
      return (
        <svg {...commonProps}>
          <rect x="3.2" y="7.2" width="9.6" height="6.2" rx="1.2" />
          <path d="M5.2 7.2V5.2C5.2 3.65 6.45 2.4 8 2.4C9.55 2.4 10.8 3.65 10.8 5.2V7.2" />
        </svg>
      );
    case "refresh":
      return (
        <svg {...commonProps}>
          <path d="M12.8 7.5A4.8 4.8 0 1 1 11.4 4.1" />
          <path d="M12.8 2.6V5.4H10" />
        </svg>
      );
    case "copy":
      return (
        <svg {...commonProps}>
          <rect x="5.5" y="5.5" width="7.5" height="7.5" rx="1.2" />
          <path d="M3.5 10.2V3.8C3.5 3.1 4.1 2.5 4.8 2.5H11" />
        </svg>
      );
    case "shield":
      return (
        <svg {...commonProps}>
          <path d="M8 2.2L13 4.2V7.8C13 10.9 10.85 13 8 13.9C5.15 13 3 10.9 3 7.8V4.2L8 2.2Z" />
        </svg>
      );
    case "key":
      return (
        <svg {...commonProps}>
          <circle cx="5.4" cy="8" r="2.6" />
          <path d="M8 8H13.6M11.6 8V10.4M13.6 8V10" />
        </svg>
      );
    case "activity":
      return (
        <svg {...commonProps}>
          <path d="M2 8.2H4.5L6.2 4.2L9.2 11.8L11.2 8.2H14" />
        </svg>
      );
    case "info":
      return (
        <svg {...commonProps}>
          <circle cx="8" cy="8" r="5.5" />
          <path d="M8 7.4V11.2" />
          <circle cx="8" cy="5.2" r="0.6" fill="currentColor" stroke="none" />
        </svg>
      );
    case "menu":
      return (
        <svg {...commonProps}>
          <path d="M2.5 4.5H13.5M2.5 8H13.5M2.5 11.5H13.5" />
        </svg>
      );
    case "close":
      return (
        <svg {...commonProps}>
          <path d="M4 4L12 12M12 4L4 12" />
        </svg>
      );
    case "chevron_left":
      return (
        <svg {...commonProps}>
          <path d="M9.8 3.5L5.2 8L9.8 12.5" />
        </svg>
      );
    case "chevron_right":
      return (
        <svg {...commonProps}>
          <path d="M6.2 3.5L10.8 8L6.2 12.5" />
        </svg>
      );
  }
}
