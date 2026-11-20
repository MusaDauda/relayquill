import {
  type AcceptanceStatus,
  type ConsoleResourceState,
  CONSOLE_RESOURCE_STATE_META,
  type ConsoleResourceStateDescriptor,
  type SafeResourceRef,
  mapHttpStatusToConsoleState
} from "@relayquill/domain";
import { type CanonicalUtcTimestamp } from "@relayquill/contracts";

export interface ResourceErrorContext<TDraft = unknown> {
  readonly status: number;
  readonly code: string;
  readonly message: string;
  readonly acceptance: AcceptanceStatus;
  readonly retryable: boolean;
  readonly retryAfterSeconds?: number | undefined;
  readonly resourceRef?: SafeResourceRef | undefined;
  readonly preservedDraft?: TDraft | undefined;
  readonly currentServerState?: unknown;
  readonly unsupportedProtocol?: boolean | undefined;
}

export type ResourceViewState<TData, TDraft = unknown> =
  | { readonly state: "loading"; readonly message?: string | undefined }
  | {
      readonly state: "authorized_empty";
      readonly observedAt: CanonicalUtcTimestamp;
      readonly requestId: string;
      readonly message?: string | undefined;
    }
  | {
      readonly state: "current";
      readonly data: TData;
      readonly observedAt: CanonicalUtcTimestamp;
      readonly requestId: string;
    }
  | {
      readonly state: "refreshing";
      readonly data: TData;
      readonly observedAt: CanonicalUtcTimestamp;
      readonly requestId: string;
    }
  | {
      readonly state: "stale";
      readonly data: TData;
      readonly observedAt: CanonicalUtcTimestamp;
      readonly reason: string;
    }
  | {
      readonly state: "unknown";
      readonly code: string;
      readonly message: string;
      readonly acceptance: "unknown";
      readonly data?: TData | undefined;
      readonly observedAt?: CanonicalUtcTimestamp | undefined;
    }
  | {
      readonly state: "forbidden";
      readonly code: string;
      readonly message: string;
      readonly requirement?: string | undefined;
    }
  | {
      readonly state: "not_found";
      readonly code: string;
      readonly message: string;
    }
  | {
      readonly state: "conflict";
      readonly code: string;
      readonly message: string;
      readonly preservedDraft?: TDraft | undefined;
      readonly currentServerState?: unknown;
      readonly resourceRef?: SafeResourceRef | undefined;
    }
  | {
      readonly state: "pressure";
      readonly code: string;
      readonly message: string;
      readonly retryAfterSeconds?: number | undefined;
      readonly data?: TData | undefined;
      readonly observedAt?: CanonicalUtcTimestamp | undefined;
    }
  | {
      readonly state: "unavailable";
      readonly code: string;
      readonly message: string;
      readonly retryable: boolean;
      readonly unsupportedProtocol?: boolean | undefined;
    }
  | {
      readonly state: "expired_content";
      readonly code: string;
      readonly message: string;
      readonly data?: TData | undefined;
      readonly observedAt?: CanonicalUtcTimestamp | undefined;
    };

export function getResourceStateDescriptor(
  state: ConsoleResourceState
): ConsoleResourceStateDescriptor {
  return CONSOLE_RESOURCE_STATE_META[state];
}

export function resourceStateFromApiError<TData, TDraft = unknown>(
  err: ResourceErrorContext<TDraft>,
  retained?: { readonly data?: TData | undefined; readonly observedAt?: CanonicalUtcTimestamp | undefined }
): ResourceViewState<TData, TDraft> {
  const mapped = mapHttpStatusToConsoleState(err.status, err.acceptance);
  switch (mapped) {
    case "unknown":
      return {
        state: "unknown",
        code: err.code,
        message: err.message,
        acceptance: "unknown",
        ...(retained?.data !== undefined ? { data: retained.data } : {}),
        ...(retained?.observedAt !== undefined ? { observedAt: retained.observedAt } : {})
      };
    case "forbidden":
      return {
        state: "forbidden",
        code: err.code,
        message: err.message
      };
    case "not_found":
      return {
        state: "not_found",
        code: err.code,
        message: err.message
      };
    case "conflict":
      return {
        state: "conflict",
        code: err.code,
        message: err.message,
        ...(err.preservedDraft !== undefined ? { preservedDraft: err.preservedDraft } : {}),
        ...(err.currentServerState !== undefined ? { currentServerState: err.currentServerState } : {}),
        ...(err.resourceRef !== undefined ? { resourceRef: err.resourceRef } : {})
      };
    case "pressure":
      return {
        state: "pressure",
        code: err.code,
        message: err.message,
        ...(err.retryAfterSeconds !== undefined ? { retryAfterSeconds: err.retryAfterSeconds } : {}),
        ...(retained?.data !== undefined ? { data: retained.data } : {}),
        ...(retained?.observedAt !== undefined ? { observedAt: retained.observedAt } : {})
      };
    case "expired_content":
      return {
        state: "expired_content",
        code: err.code,
        message: err.message,
        ...(retained?.data !== undefined ? { data: retained.data } : {}),
        ...(retained?.observedAt !== undefined ? { observedAt: retained.observedAt } : {})
      };
    case "unavailable":
    default:
      return {
        state: "unavailable",
        code: err.code,
        message: err.message,
        retryable: err.retryable,
        ...(err.unsupportedProtocol !== undefined
          ? { unsupportedProtocol: err.unsupportedProtocol }
          : {})
      };
  }
}
