import {
  type WatchAuthorizationLostFrameData,
  type WatchEventFrameData,
  type WatchResyncRequiredFrameData,
  type WatchSnapshotFrameData,
  type WatchUnavailableFrameData,
  createSseChunkDecoder
} from "@relayquill/contracts";
import { WATCH_MAX_STREAMS_PER_ACTOR } from "@relayquill/domain";

export type WatchStreamStatus =
  | "idle"
  | "connecting"
  | "streaming"
  | "resync_required"
  | "authorization_lost"
  | "unavailable"
  | "limit_reached"
  | "closed";

export interface WatchCallbacks {
  readonly onStatus?: (status: WatchStreamStatus, detail?: string) => void;
  readonly onSnapshot: (frame: WatchSnapshotFrameData, cursorId: string) => void;
  readonly onEvent: (frame: WatchEventFrameData, cursorId: string) => void;
  readonly onResyncRequired: (frame: WatchResyncRequiredFrameData) => void;
  readonly onAuthorizationLost: (frame: WatchAuthorizationLostFrameData | { readonly reason_code: string }) => void;
  readonly onUnavailable: (frame: WatchUnavailableFrameData | { readonly reason_code: string; readonly retryable: boolean }) => void;
  readonly onHeartbeat?: () => void;
}

export interface WatchHandle {
  readonly streamId: string;
  close(): void;
}

export class ConsoleWatchManager {
  readonly #active = new Map<string, AbortController>();
  readonly #fetchImpl: typeof fetch;
  readonly #getCsrfToken: () => string | null;

  constructor(deps: {
    readonly fetchImpl?: typeof fetch | undefined;
    readonly getCsrfToken: () => string | null;
  }) {
    this.#fetchImpl = deps.fetchImpl ?? ((input: RequestInfo | URL, init?: RequestInit) => fetch(input, init));
    this.#getCsrfToken = deps.getCsrfToken;
  }

  activeCount(): number {
    return this.#active.size;
  }

  closeStream(streamKey: string): void {
    const controller = this.#active.get(streamKey);
    if (controller !== undefined) {
      controller.abort();
      this.#active.delete(streamKey);
    }
  }

  closeAll(): void {
    for (const controller of this.#active.values()) {
      controller.abort();
    }
    this.#active.clear();
  }

  openStream(opts: {
    readonly streamKey: string;
    readonly url: string;
    readonly lastCursor?: string | null | undefined;
    readonly callbacks: WatchCallbacks;
  }): WatchHandle {
    const existing = this.#active.get(opts.streamKey);
    if (existing !== undefined) {
      existing.abort();
      this.#active.delete(opts.streamKey);
    }

    if (this.#active.size >= WATCH_MAX_STREAMS_PER_ACTOR) {
      opts.callbacks.onStatus?.(
        "limit_reached",
        `Maximum ${WATCH_MAX_STREAMS_PER_ACTOR} concurrent authenticated watch streams per actor reached. Close another watch stream first.`
      );
      return {
        streamId: opts.streamKey,
        close: () => {}
      };
    }

    const controller = new AbortController();
    this.#active.set(opts.streamKey, controller);
    const seenEventKeys = new Set<string>();
    let lastHandledCursor: string | null = opts.lastCursor ?? null;

    const close = (): void => {
      if (this.#active.get(opts.streamKey) === controller) {
        this.#active.delete(opts.streamKey);
      }
      controller.abort();
      opts.callbacks.onStatus?.("closed");
    };

    void (async () => {
      opts.callbacks.onStatus?.("connecting");
      const headers: Record<string, string> = {
        Accept: "text/event-stream"
      };
      const csrf = this.#getCsrfToken();
      if (csrf !== null && csrf.length > 0) {
        headers["X-CSRF-Token"] = csrf;
      }
      if (lastHandledCursor !== null && lastHandledCursor.length > 0) {
        headers["Last-Event-ID"] = lastHandledCursor;
      }

      let response: Response;
      try {
        response = await this.#fetchImpl(opts.url, {
          method: "GET",
          credentials: "same-origin",
          cache: "no-store",
          headers,
          signal: controller.signal
        });
      } catch {
        if (!controller.signal.aborted) {
          this.#active.delete(opts.streamKey);
          opts.callbacks.onStatus?.("unavailable", "Watch stream connection interrupted.");
          opts.callbacks.onUnavailable({
            reason_code: "WATCH_TRANSPORT_ERROR",
            retryable: true
          });
        }
        return;
      }

      if (response.status === 401 || response.status === 403) {
        this.#active.delete(opts.streamKey);
        opts.callbacks.onStatus?.("authorization_lost", `Watch denied (${response.status}).`);
        opts.callbacks.onAuthorizationLost({ reason_code: `HTTP_${response.status}` });
        return;
      }

      if (response.status === 410) {
        this.#active.delete(opts.streamKey);
        opts.callbacks.onStatus?.("resync_required", "Watch cursor expired; reload snapshot.");
        opts.callbacks.onResyncRequired({
          response_schema_version: 1,
          frame_type: "resync_required",
          reason_code: "CURSOR_EXPIRED",
          snapshot_path: opts.url.replace(/\/watch(?:\?.*)?$/, ""),
          recorded_at: new Date().toISOString().replace("Z", "000Z") as WatchResyncRequiredFrameData["recorded_at"]
        });
        return;
      }

      if (!response.ok || response.body === null) {
        this.#active.delete(opts.streamKey);
        opts.callbacks.onStatus?.("unavailable", `Watch failed with HTTP ${response.status}.`);
        opts.callbacks.onUnavailable({
          reason_code: `HTTP_${response.status}`,
          retryable: response.status >= 500 || response.status === 429
        });
        return;
      }

      opts.callbacks.onStatus?.("streaming");
      const decoder = createSseChunkDecoder();
      const reader = response.body.getReader();

      const processFrames = (frames: ReturnType<typeof decoder.push>): boolean => {
        for (const frame of frames) {
          if (!frame.supported) {
            continue;
          }
          switch (frame.frame_type) {
            case "heartbeat":
              opts.callbacks.onHeartbeat?.();
              break;
            case "snapshot":
              opts.callbacks.onSnapshot(frame.data, frame.id);
              lastHandledCursor = frame.id;
              break;
            case "event": {
              const dedupKey = `${frame.data.resource_kind}:${frame.data.resource_id}:${frame.data.event_sequence}`;
              if (!seenEventKeys.has(dedupKey)) {
                seenEventKeys.add(dedupKey);
                opts.callbacks.onEvent(frame.data, frame.id);
              }
              lastHandledCursor = frame.id;
              break;
            }
            case "resync_required":
              opts.callbacks.onStatus?.("resync_required", frame.data.reason_code);
              opts.callbacks.onResyncRequired(frame.data);
              return false;
            case "authorization_lost":
              opts.callbacks.onStatus?.("authorization_lost", frame.data.reason_code);
              opts.callbacks.onAuthorizationLost(frame.data);
              return false;
            case "unavailable":
              opts.callbacks.onStatus?.("unavailable", frame.data.reason_code);
              opts.callbacks.onUnavailable(frame.data);
              return false;
          }
        }
        return true;
      };

      try {
        while (!controller.signal.aborted) {
          const { done, value } = await reader.read();
          if (done) {
            const trailing = decoder.finish();
            processFrames(trailing);
            break;
          }
          if (value !== undefined) {
            const frames = decoder.push(value);
            const keepGoing = processFrames(frames);
            if (!keepGoing) {
              break;
            }
          }
        }
      } catch {
        if (!controller.signal.aborted) {
          opts.callbacks.onStatus?.("unavailable", "SSE stream read interrupted.");
          opts.callbacks.onUnavailable({
            reason_code: "WATCH_STREAM_INTERRUPTED",
            retryable: true
          });
        }
      } finally {
        try {
          await reader.cancel();
        } catch {
          // Stream already closed.
        }
        if (this.#active.get(opts.streamKey) === controller) {
          this.#active.delete(opts.streamKey);
        }
      }
    })();

    return {
      streamId: opts.streamKey,
      close
    };
  }
}
