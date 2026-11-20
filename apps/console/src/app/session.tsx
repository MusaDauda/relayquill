import {
  createContext,
  type ReactNode,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState
} from "react";
import { createConsoleApi, type ConsoleApi } from "../api/console-api.js";
import { type SessionContextDto } from "../api/dtos.js";
import { createConsoleHttpClient, type HttpApiFailure } from "../api/http-client.js";
import { PreparedCommandMemoryStore } from "../api/prepared-commands.js";
import { ConsoleWatchManager } from "../api/watch-client.js";
import { generateIdempotencyKey } from "../utils/idempotency.js";
import { ScopedQueryCache } from "./query-cache.js";

export type SessionLoadState =
  | { readonly status: "loading" }
  | { readonly status: "unauthenticated"; readonly reason?: string | undefined }
  | { readonly status: "authenticated"; readonly session: SessionContextDto }
  | { readonly status: "unavailable"; readonly error: HttpApiFailure };

export interface ConsoleRuntimeContextValue {
  readonly api: ConsoleApi;
  readonly watchManager: ConsoleWatchManager;
  readonly preparedCommands: PreparedCommandMemoryStore;
  readonly queryCache: ScopedQueryCache;
  readonly sessionState: SessionLoadState;
  readonly session: SessionContextDto | null;
  readonly refreshSession: () => Promise<SessionContextDto | null>;
  readonly clearSensitiveState: (reason?: string) => void;
  readonly logout: () => Promise<void>;
}

const ConsoleRuntimeContext = createContext<ConsoleRuntimeContextValue | null>(null);

export function ConsoleSessionProvider({ children }: { readonly children: ReactNode }) {
  // Memory-only CSRF and session storage: never persisted to localStorage, sessionStorage, or URL.
  const csrfTokenRef = useRef<string | null>(null);
  const lastPrincipalRef = useRef<string | null>(null);

  const [sessionState, setSessionState] = useState<SessionLoadState>({ status: "loading" });

  const preparedCommands = useMemo(() => new PreparedCommandMemoryStore(), []);
  const queryCache = useMemo(() => new ScopedQueryCache(), []);

  const watchManager = useMemo(
    () =>
      new ConsoleWatchManager({
        getCsrfToken: () => csrfTokenRef.current
      }),
    []
  );

  const clearSensitiveState = useCallback(
    (reason?: string) => {
      csrfTokenRef.current = null;
      watchManager.closeAll();
      queryCache.clearAll();
      if (lastPrincipalRef.current !== null) {
        preparedCommands.clearForPrincipal(lastPrincipalRef.current);
      }
      lastPrincipalRef.current = null;
      setSessionState({ status: "unauthenticated", reason });
    },
    [preparedCommands, queryCache, watchManager]
  );

  const api = useMemo(() => {
    const http = createConsoleHttpClient({
      getCsrfToken: () => csrfTokenRef.current,
      onUnauthorized: () => {
        clearSensitiveState("Session expired or revoked; sign in again.");
      }
    });
    return createConsoleApi(http);
  }, [clearSensitiveState]);

  const refreshSession = useCallback(async (): Promise<SessionContextDto | null> => {
    const controller = new AbortController();
    const res = await api.getSessionContext(controller.signal);
    if (res.ok) {
      const nextPrincipal = res.data.principal_id;
      if (lastPrincipalRef.current !== null && lastPrincipalRef.current !== nextPrincipal) {
        watchManager.closeAll();
        queryCache.clearForPrincipal(lastPrincipalRef.current);
        preparedCommands.clearForPrincipal(lastPrincipalRef.current);
      }
      lastPrincipalRef.current = nextPrincipal;
      csrfTokenRef.current = res.data.csrf_token;
      setSessionState({ status: "authenticated", session: res.data });
      return res.data;
    }

    if (res.status === 401 || res.status === 403) {
      clearSensitiveState(res.message);
      return null;
    }

    setSessionState({ status: "unavailable", error: res });
    return null;
  }, [api, clearSensitiveState, preparedCommands, queryCache, watchManager]);

  const logout = useCallback(async () => {
    await api.logout(generateIdempotencyKey("logout"));
    clearSensitiveState("Signed out.");
  }, [api, clearSensitiveState]);

  useEffect(() => {
    void refreshSession();
    return () => {
      watchManager.closeAll();
    };
  }, [refreshSession, watchManager]);

  const value = useMemo<ConsoleRuntimeContextValue>(
    () => ({
      api,
      watchManager,
      preparedCommands,
      queryCache,
      sessionState,
      session: sessionState.status === "authenticated" ? sessionState.session : null,
      refreshSession,
      clearSensitiveState,
      logout
    }),
    [
      api,
      clearSensitiveState,
      logout,
      preparedCommands,
      queryCache,
      refreshSession,
      sessionState,
      watchManager
    ]
  );

  return <ConsoleRuntimeContext.Provider value={value}>{children}</ConsoleRuntimeContext.Provider>;
}

export function useConsoleRuntime(): ConsoleRuntimeContextValue {
  const ctx = useContext(ConsoleRuntimeContext);
  if (ctx === null) {
    throw new Error("useConsoleRuntime must be used inside ConsoleSessionProvider");
  }
  return ctx;
}
