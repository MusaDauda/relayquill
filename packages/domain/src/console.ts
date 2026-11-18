import { type AcceptanceStatus, createEnumGuard } from "./enums.js";

export const CONSOLE_RESOURCE_STATES = [
  "loading",
  "authorized_empty",
  "current",
  "refreshing",
  "stale",
  "unknown",
  "forbidden",
  "not_found",
  "conflict",
  "pressure",
  "unavailable",
  "expired_content"
] as const;

export type ConsoleResourceState = (typeof CONSOLE_RESOURCE_STATES)[number];

export const isConsoleResourceState = createEnumGuard(CONSOLE_RESOURCE_STATES);

export type ConsoleStateCategory = "loading" | "healthy" | "degraded" | "error";

export type ConsoleAccessibilityRole = "status" | "alert";

export type ConsoleNonColorIndicator =
  | "spinner"
  | "empty_box"
  | "check_circle"
  | "sync_spinner"
  | "clock_warning"
  | "question_diamond"
  | "lock_shield"
  | "missing_slash"
  | "split_conflict"
  | "gauge_warning"
  | "plug_offline"
  | "archive_expired";

export interface ConsoleResourceStateDescriptor {
  readonly state: ConsoleResourceState;
  readonly label: string;
  readonly category: ConsoleStateCategory;
  readonly accessibilityRole: ConsoleAccessibilityRole;
  readonly nonColorIndicator: ConsoleNonColorIndicator;
  readonly allowsStaleData: boolean;
  readonly disablesMutations: boolean;
  readonly forbidsSyntheticZero: boolean;
}

export const CONSOLE_RESOURCE_STATE_META: Readonly<
  Record<ConsoleResourceState, ConsoleResourceStateDescriptor>
> = Object.freeze({
  loading: Object.freeze({
    state: "loading",
    label: "Loading",
    category: "loading",
    accessibilityRole: "status",
    nonColorIndicator: "spinner",
    allowsStaleData: false,
    disablesMutations: true,
    forbidsSyntheticZero: true
  }),
  authorized_empty: Object.freeze({
    state: "authorized_empty",
    label: "Authorized empty",
    category: "healthy",
    accessibilityRole: "status",
    nonColorIndicator: "empty_box",
    allowsStaleData: false,
    disablesMutations: false,
    forbidsSyntheticZero: false
  }),
  current: Object.freeze({
    state: "current",
    label: "Current",
    category: "healthy",
    accessibilityRole: "status",
    nonColorIndicator: "check_circle",
    allowsStaleData: false,
    disablesMutations: false,
    forbidsSyntheticZero: false
  }),
  refreshing: Object.freeze({
    state: "refreshing",
    label: "Refreshing",
    category: "loading",
    accessibilityRole: "status",
    nonColorIndicator: "sync_spinner",
    allowsStaleData: true,
    disablesMutations: false,
    forbidsSyntheticZero: true
  }),
  stale: Object.freeze({
    state: "stale",
    label: "Stale",
    category: "degraded",
    accessibilityRole: "status",
    nonColorIndicator: "clock_warning",
    allowsStaleData: true,
    disablesMutations: true,
    forbidsSyntheticZero: true
  }),
  unknown: Object.freeze({
    state: "unknown",
    label: "Unknown",
    category: "degraded",
    accessibilityRole: "alert",
    nonColorIndicator: "question_diamond",
    allowsStaleData: true,
    disablesMutations: true,
    forbidsSyntheticZero: true
  }),
  forbidden: Object.freeze({
    state: "forbidden",
    label: "Forbidden",
    category: "error",
    accessibilityRole: "alert",
    nonColorIndicator: "lock_shield",
    allowsStaleData: false,
    disablesMutations: true,
    forbidsSyntheticZero: true
  }),
  not_found: Object.freeze({
    state: "not_found",
    label: "Not found",
    category: "error",
    accessibilityRole: "alert",
    nonColorIndicator: "missing_slash",
    allowsStaleData: false,
    disablesMutations: true,
    forbidsSyntheticZero: true
  }),
  conflict: Object.freeze({
    state: "conflict",
    label: "Conflict",
    category: "error",
    accessibilityRole: "alert",
    nonColorIndicator: "split_conflict",
    allowsStaleData: false,
    disablesMutations: true,
    forbidsSyntheticZero: true
  }),
  pressure: Object.freeze({
    state: "pressure",
    label: "Pressure",
    category: "degraded",
    accessibilityRole: "alert",
    nonColorIndicator: "gauge_warning",
    allowsStaleData: true,
    disablesMutations: true,
    forbidsSyntheticZero: true
  }),
  unavailable: Object.freeze({
    state: "unavailable",
    label: "Unavailable",
    category: "error",
    accessibilityRole: "alert",
    nonColorIndicator: "plug_offline",
    allowsStaleData: false,
    disablesMutations: true,
    forbidsSyntheticZero: true
  }),
  expired_content: Object.freeze({
    state: "expired_content",
    label: "Expired content",
    category: "error",
    accessibilityRole: "alert",
    nonColorIndicator: "archive_expired",
    allowsStaleData: false,
    disablesMutations: true,
    forbidsSyntheticZero: true
  })
});

export function getConsoleResourceStateDescriptor(
  state: ConsoleResourceState
): ConsoleResourceStateDescriptor {
  return CONSOLE_RESOURCE_STATE_META[state];
}

export function mapHttpStatusToConsoleState(
  status: number,
  acceptance?: AcceptanceStatus
): ConsoleResourceState {
  if (status === 401 || status === 403) {
    return "forbidden";
  }
  if (status === 404) {
    return "not_found";
  }
  if (status === 409) {
    return "conflict";
  }
  if (status === 410) {
    return "expired_content";
  }
  if (status === 429) {
    return "pressure";
  }
  if (status === 503) {
    return acceptance === "unknown" ? "unknown" : "unavailable";
  }
  if (acceptance === "unknown") {
    return "unknown";
  }
  if (status >= 200 && status < 300) {
    return "current";
  }
  return "unavailable";
}
