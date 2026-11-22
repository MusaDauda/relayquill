const SENSITIVE_PROP_KEY_REGEX =
  /secret|token|password|passwd|api_?key|authorization|cookie|signature|email|totp/i;

export interface ConsoleTelemetryEnv {
  readonly VITE_SENTRY_DSN?: string | undefined;
  readonly VITE_POSTHOG_KEY?: string | undefined;
  readonly VITE_POSTHOG_HOST?: string | undefined;
}

export interface ConsoleTelemetryConfig {
  readonly sentryDsn: string | null;
  readonly posthogKey: string | null;
  readonly posthogHost: string;
}

export interface ConsoleTelemetryClient {
  readonly sentryEnabled: boolean;
  readonly posthogEnabled: boolean;
  captureException(
    error: unknown,
    context?: {
      readonly route?: string | undefined;
      readonly component?: string | undefined;
    }
  ): boolean;
  captureEvent(eventName: string, props?: Readonly<Record<string, unknown>>): boolean;
}

function readNonEmptyEnv(value: string | undefined): string | null {
  if (typeof value !== "string") {
    return null;
  }
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : null;
}

function resolveImportMetaEnv(): ConsoleTelemetryEnv {
  try {
    const meta = import.meta as unknown as { readonly env?: ConsoleTelemetryEnv | undefined };
    return meta.env ?? {};
  } catch {
    return {};
  }
}

/** Reads opt-in browser telemetry configuration from VITE_* build environment variables. */
export function readConsoleTelemetryConfig(
  env: ConsoleTelemetryEnv = resolveImportMetaEnv()
): ConsoleTelemetryConfig {
  return {
    sentryDsn: readNonEmptyEnv(env.VITE_SENTRY_DSN),
    posthogKey: readNonEmptyEnv(env.VITE_POSTHOG_KEY),
    posthogHost: readNonEmptyEnv(env.VITE_POSTHOG_HOST) ?? "https://app.posthog.com"
  };
}

/** Strips query strings and URL fragments so transient tokens and search parameters are never exported. */
export function scrubBrowserRoute(rawUrlOrPath: string): string {
  const withoutHash = rawUrlOrPath.split("#")[0] ?? "/";
  const withoutQuery = withoutHash.split("?")[0] ?? "/";
  const normalized = withoutQuery.trim();
  return normalized.length > 0 ? normalized.slice(0, 200) : "/";
}

/** Redacts sensitive property keys before sending opt-in product or error telemetry. */
export function scrubTelemetryProps(
  props: Readonly<Record<string, unknown>>
): Readonly<Record<string, unknown>> {
  const scrubbed: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(props)) {
    if (SENSITIVE_PROP_KEY_REGEX.test(key)) {
      scrubbed[key] = "[REDACTED]";
      continue;
    }
    if (typeof value === "string") {
      scrubbed[key] = value.slice(0, 200);
    } else if (typeof value === "number" || typeof value === "boolean" || value === null) {
      scrubbed[key] = value;
    }
  }
  return scrubbed;
}

function parseSentryIngestEndpoint(dsn: string): string | null {
  try {
    const url = new URL(dsn);
    const projectId = url.pathname.replace(/^\/+/, "").split("/")[0];
    if (!projectId) {
      return null;
    }
    return `${url.protocol}//${url.host}/api/${projectId}/envelope/`;
  } catch {
    return null;
  }
}

function dispatchBeaconOrFetch(
  endpoint: string,
  payloadText: string,
  fetchFn?: typeof fetch
): boolean {
  try {
    if (typeof navigator !== "undefined" && typeof navigator.sendBeacon === "function") {
      return navigator.sendBeacon(endpoint, payloadText);
    }
    const runner = fetchFn ?? (typeof fetch === "function" ? fetch : undefined);
    if (runner === undefined) {
      return false;
    }
    void runner(endpoint, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: payloadText,
      keepalive: true
    }).catch(() => {
      // Telemetry failures never interrupt UI rendering.
    });
    return true;
  } catch {
    return false;
  }
}

/**
 * Env-gated browser error and product telemetry client.
 * Performs zero network I/O unless VITE_SENTRY_DSN or VITE_POSTHOG_KEY is explicitly configured.
 */
export function createConsoleTelemetry(
  config: ConsoleTelemetryConfig = readConsoleTelemetryConfig(),
  deps?: { readonly fetch?: typeof fetch | undefined }
): ConsoleTelemetryClient {
  const sentryEndpoint =
    config.sentryDsn !== null ? parseSentryIngestEndpoint(config.sentryDsn) : null;
  const posthogKey = config.posthogKey;

  return {
    sentryEnabled: sentryEndpoint !== null,
    posthogEnabled: posthogKey !== null,
    captureException(error, context) {
      if (sentryEndpoint === null) {
        return false;
      }
      const message =
        error instanceof Error ? error.message.slice(0, 240) : "Unexpected UI error";
      const envelopeHeader = JSON.stringify({ dsn: config.sentryDsn });
      const itemHeader = JSON.stringify({ type: "event" });
      const eventBody = JSON.stringify({
        platform: "javascript",
        level: "error",
        message,
        tags: {
          route: scrubBrowserRoute(context?.route ?? "/"),
          ...(context?.component !== undefined ? { component: context.component } : {})
        }
      });
      return dispatchBeaconOrFetch(
        sentryEndpoint,
        `${envelopeHeader}\n${itemHeader}\n${eventBody}`,
        deps?.fetch
      );
    },
    captureEvent(eventName, props = {}) {
      if (posthogKey === null) {
        return false;
      }
      const cleanName = eventName.trim().slice(0, 80);
      if (cleanName.length === 0) {
        return false;
      }
      const host = config.posthogHost.replace(/\/+$/, "");
      const body = JSON.stringify({
        api_key: posthogKey,
        event: cleanName,
        properties: {
          ...scrubTelemetryProps(props),
          $current_url:
            typeof window !== "undefined" ? scrubBrowserRoute(window.location.pathname) : "/"
        }
      });
      return dispatchBeaconOrFetch(`${host}/capture/`, body, deps?.fetch);
    }
  };
}

export const consoleTelemetry = createConsoleTelemetry();
