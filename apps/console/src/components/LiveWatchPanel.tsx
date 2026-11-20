import { type JSX, useEffect, useState } from "react";
import { type WatchEventFrameData, type WatchSnapshotFrameData } from "@relayquill/contracts";
import { type WatchHandle, type WatchStreamStatus } from "../api/watch-client.js";
import { useConsoleRuntime } from "../app/session.js";
import { StatusBadge } from "./StatusBadge.js";
import { UtcTimestamp } from "./UtcTimestamp.js";

export function LiveWatchPanel({
  streamId,
  path,
  label,
  onSnapshot,
  onEvent,
  onResyncRequired
}: {
  readonly streamId: string;
  readonly path: string;
  readonly label: string;
  readonly onSnapshot?: ((frame: WatchSnapshotFrameData) => void) | undefined;
  readonly onEvent?: ((frame: WatchEventFrameData) => void) | undefined;
  readonly onResyncRequired?: ((reason: string) => void) | undefined;
}): JSX.Element {
  const { watchManager } = useConsoleRuntime();
  const [enabled, setEnabled] = useState(false);
  const [status, setStatus] = useState<WatchStreamStatus>("idle");
  const [lastSequence, setLastSequence] = useState<string | null>(null);
  const [lastHeartbeatAt, setLastHeartbeatAt] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  useEffect(() => {
    if (!enabled) {
      watchManager.closeStream(streamId);
      setStatus("idle");
      return;
    }

    let handle: WatchHandle | null = null;
    try {
      handle = watchManager.openStream({
        streamKey: streamId,
        url: path,
        callbacks: {
          onStatus: (next, detail) => {
            setStatus(next);
            if (detail !== undefined) {
              setNotice(detail);
            }
          },
          onSnapshot: (frame) => {
            setNotice(null);
            setLastSequence(frame.high_water_sequence);
            onSnapshot?.(frame);
          },
          onEvent: (frame) => {
            setNotice(null);
            setLastSequence(frame.event_sequence);
            onEvent?.(frame);
          },
          onHeartbeat: () => {
            setLastHeartbeatAt(new Date().toISOString());
          },
          onResyncRequired: (frame) => {
            setNotice(
              `Resync required (${frame.reason_code}). Reloading latest snapshot from authoritative read API.`
            );
            onResyncRequired?.(frame.reason_code);
          },
          onAuthorizationLost: (frame) => {
            setNotice(`Live watch closed: authorization lost (${frame.reason_code}).`);
            setEnabled(false);
          },
          onUnavailable: (frame) => {
            setNotice(`Live watch unavailable: ${frame.reason_code}`);
          }
        }
      });
    } catch (err) {
      setStatus("unavailable");
      setNotice(err instanceof Error ? err.message : "Could not open watch stream.");
      setEnabled(false);
    }

    return () => {
      handle?.close();
    };
  }, [enabled, path, streamId, watchManager]);

  return (
    <section className="rq-card-inset" aria-label={`${label} live stream`}>
      <div className="rq-row-between">
        <div className="rq-row">
          <strong className="rq-label">{label}</strong>
          <StatusBadge
            status={status === "streaming" ? "active" : status === "idle" ? "draft" : status}
            label={
              status === "streaming"
                ? "Live Watch Connected"
                : status === "connecting"
                  ? "Connecting"
                  : status === "resync_required"
                    ? "Resync Required"
                    : status === "authorization_lost"
                      ? "Auth Lost"
                      : status === "unavailable"
                        ? "Watch Unavailable"
                        : status === "limit_reached"
                          ? "Stream Limit Reached"
                          : "Live Watch Off"
            }
            live="polite"
          />
          {lastSequence !== null ? (
            <span className="rq-meta-text mono">Cursor: {lastSequence}</span>
          ) : null}
          {lastHeartbeatAt !== null ? (
            <span className="rq-meta-text">
              Heartbeat: <UtcTimestamp value={lastHeartbeatAt} showLocal={false} />
            </span>
          ) : null}
        </div>
        <button
          type="button"
          className="rq-btn"
          onClick={() => {
            setNotice(null);
            setEnabled((prev) => !prev);
          }}
        >
          {enabled ? "Disconnect Live Watch" : "Enable Live Watch (SSE)"}
        </button>
      </div>
      <p className="rq-meta-text">
        Authenticated fetch SSE with memory-only CSRF header (maximum 2 concurrent streams per
        operator). Closed automatically when switching projects or signing out.
      </p>
      {notice !== null ? (
        <p className="rq-field-error" role="status" aria-live="polite">
          {notice}
        </p>
      ) : null}
    </section>
  );
}
