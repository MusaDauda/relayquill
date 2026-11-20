export function formatLocalTimeWithOffset(canonicalUtc: string): string {
  const normalized = canonicalUtc.replace(/\.(\d{3})\d{3}Z$/, ".$1Z");
  const date = new Date(normalized);
  if (Number.isNaN(date.getTime())) {
    return "Invalid timestamp";
  }
  const offsetMinutes = -date.getTimezoneOffset();
  const sign = offsetMinutes >= 0 ? "+" : "-";
  const absMins = Math.abs(offsetMinutes);
  const hh = String(Math.floor(absMins / 60)).padStart(2, "0");
  const mm = String(absMins % 60).padStart(2, "0");
  return `${date.toLocaleString()} (UTC${sign}${hh}:${mm})`;
}

export function formatCountdownMs(remainingMs: number): string {
  if (remainingMs <= 0) {
    return "Expired";
  }
  const totalSeconds = Math.floor(remainingMs / 1000);
  const minutes = Math.floor(totalSeconds / 60);
  const seconds = totalSeconds % 60;
  return `${minutes}m ${String(seconds).padStart(2, "0")}s`;
}

export function parseCanonicalUtcEpochMs(canonicalUtc: string): number {
  const normalized = canonicalUtc.replace(/\.(\d{3})\d{3}Z$/, ".$1Z");
  return Date.parse(normalized);
}

export function formatByteCount(bytes: number): string {
  if (bytes < 1024) {
    return `${bytes} B`;
  }
  return `${(bytes / 1024).toFixed(1)} KiB (${bytes} B)`;
}

export function formatByteSize(bytes: number): string {
  return formatByteCount(bytes);
}

export function formatDurationSeconds(seconds: number): string {
  if (!Number.isFinite(seconds) || seconds < 0) {
    return "0s";
  }
  const rounded = Math.floor(seconds);
  if (rounded < 60) {
    return `${rounded}s`;
  }
  const mins = Math.floor(rounded / 60);
  const secs = rounded % 60;
  if (mins < 60) {
    return `${mins}m ${String(secs).padStart(2, "0")}s`;
  }
  const hours = Math.floor(mins / 60);
  const remMins = mins % 60;
  return `${hours}h ${String(remMins).padStart(2, "0")}m`;
}

export function formatUtcWithLocalOffset(canonicalUtc: string): {
  readonly utc: string;
  readonly local: string;
} {
  return {
    utc: canonicalUtc,
    local: formatLocalTimeWithOffset(canonicalUtc)
  };
}

export function formatCountdown(expiresAtUtc: string, nowMs = Date.now()): string {
  const epoch = parseCanonicalUtcEpochMs(expiresAtUtc);
  if (Number.isNaN(epoch)) {
    return "Unknown";
  }
  return formatCountdownMs(epoch - nowMs);
}
