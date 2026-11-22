import { type FastifyBaseLogger } from "fastify";

const ALLOWLISTED_LOG_KEYS = new Set([
  "request_id",
  "method",
  "path",
  "route",
  "status_code",
  "duration_ms",
  "error_code",
  "tenant_id",
  "project_id",
  "event_id",
  "delivery_id",
  "lease_id",
  "principal_id",
  "actor_kind",
  "process_role",
  "control_epoch",
  "instance_id",
  "component",
  "event"
]);

const SECRET_SUBSTRING_REGEX =
  /(rq_p1\.[a-z0-9._-]+|__host-rq_|rq_session_dev|rq_pre_dev|-----begin |authorization:|set-cookie:)/i;

export interface SafeLogEntry {
  readonly ts: string;
  readonly level: "trace" | "debug" | "info" | "warn" | "error" | "fatal";
  readonly msg: string;
  readonly fields?: Readonly<Record<string, string | number | boolean>> | undefined;
}

export type SafeLogSink = (entry: SafeLogEntry) => void;

export function sanitizeLogMessage(raw: string): string {
  const truncated = raw.length > 512 ? `${raw.slice(0, 512)}...` : raw;
  return truncated.replace(SECRET_SUBSTRING_REGEX, "[REDACTED]");
}

function sanitizeBindings(
  bindings: Record<string, unknown> | undefined
): Record<string, string | number | boolean> {
  const safe: Record<string, string | number | boolean> = {};
  if (bindings === undefined) {
    return safe;
  }
  for (const [key, value] of Object.entries(bindings)) {
    if (!ALLOWLISTED_LOG_KEYS.has(key)) {
      continue;
    }
    if (typeof value === "string") {
      safe[key] = sanitizeLogMessage(value);
    } else if (typeof value === "number" || typeof value === "boolean") {
      safe[key] = value;
    }
  }
  return safe;
}

export function createAllowlistedLogger(options: {
  readonly sink?: SafeLogSink | undefined;
  readonly bindings?: Record<string, unknown> | undefined;
  readonly level?: "silent" | "error" | "warn" | "info" | "debug" | undefined;
} = {}): FastifyBaseLogger {
  const minLevel = options.level ?? "info";
  const levelRank: Record<string, number> = {
    trace: 10,
    debug: 20,
    info: 30,
    warn: 40,
    error: 50,
    fatal: 60,
    silent: 99
  };
  const sink: SafeLogSink =
    options.sink ??
    ((entry) => {
      process.stdout.write(`${JSON.stringify(entry)}\n`);
    });
  const baseBindings = sanitizeBindings(options.bindings);

  const emit = (
    level: SafeLogEntry["level"],
    objOrMsg: unknown,
    maybeMsg?: string
  ): void => {
    if ((levelRank[level] ?? 30) < (levelRank[minLevel] ?? 30)) {
      return;
    }
    let msg = typeof maybeMsg === "string" ? maybeMsg : "";
    let mergedFields = { ...baseBindings };
    if (typeof objOrMsg === "string") {
      msg = objOrMsg;
    } else if (objOrMsg !== null && typeof objOrMsg === "object") {
      const rec = objOrMsg as Record<string, unknown>;
      if (typeof rec["msg"] === "string" && msg.length === 0) {
        msg = rec["msg"];
      } else if (rec["err"] instanceof Error && msg.length === 0) {
        msg = rec["err"].message;
      }
      mergedFields = { ...mergedFields, ...sanitizeBindings(rec) };
    }
    sink({
      ts: new Date().toISOString(),
      level,
      msg: sanitizeLogMessage(msg),
      ...(Object.keys(mergedFields).length > 0 ? { fields: mergedFields } : {})
    });
  };

  const logger: FastifyBaseLogger = {
    level: minLevel,
    trace(obj: unknown, msg?: string): void {
      emit("trace", obj, msg);
    },
    debug(obj: unknown, msg?: string): void {
      emit("debug", obj, msg);
    },
    info(obj: unknown, msg?: string): void {
      emit("info", obj, msg);
    },
    warn(obj: unknown, msg?: string): void {
      emit("warn", obj, msg);
    },
    error(obj: unknown, msg?: string): void {
      emit("error", obj, msg);
    },
    fatal(obj: unknown, msg?: string): void {
      emit("fatal", obj, msg);
    },
    silent(): void {
      // No-op log sink
    },
    child(bindings: Record<string, unknown>): FastifyBaseLogger {
      return createAllowlistedLogger({
        sink,
        level: minLevel,
        bindings: { ...baseBindings, ...bindings }
      });
    }
  };

  return logger;
}
