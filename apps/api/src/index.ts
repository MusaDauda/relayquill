import { type FastifyInstance } from "fastify";
import {
  type ApiContext,
  type CreateApiContextOptions,
  createApiContext,
  ensureApiRuntimeRegistered,
  readInstallationSnapshot
} from "./context.js";
import {
  type SafeLogEntry,
  type SafeLogSink,
  createAllowlistedLogger
} from "./http/logger.js";
import { createApiFastifyServer } from "./server.js";

export const API_APP_VERSION = "0.1.0" as const;

export type { ApiContext, CreateApiContextOptions, SafeLogEntry, SafeLogSink };
export {
  createAllowlistedLogger,
  createApiContext,
  createApiFastifyServer,
  ensureApiRuntimeRegistered,
  readInstallationSnapshot
};

export interface CreateApiServerOptions
  extends Omit<CreateApiContextOptions, "logger"> {
  readonly logger?: CreateApiContextOptions["logger"] | undefined;
  readonly logLevel?: "silent" | "error" | "warn" | "info" | "debug" | undefined;
  readonly logSink?: SafeLogSink | undefined;
}

export interface ApiServerHandle {
  readonly app: FastifyInstance;
  readonly ctx: ApiContext;
  start(options: {
    readonly host: string;
    readonly port: number;
    readonly registerRuntime?: boolean | undefined;
  }): Promise<{ readonly host: string; readonly port: number; readonly url: string }>;
  close(): Promise<void>;
}

/**
 * Side-effect-free programmatic factory building a configured Fastify API server
 * without binding sockets or executing network calls on import.
 */
export function createApiServer(options: CreateApiServerOptions): ApiServerHandle {
  const logger =
    options.logger ??
    createAllowlistedLogger({
      level: options.logLevel ?? "info",
      sink: options.logSink,
      bindings: {
        component: "api",
        process_role: "api"
      }
    });

  const ctx = createApiContext({
    pgAdapter: options.pgAdapter,
    authConfig: options.authConfig,
    profile: options.profile,
    allowDevBootstrapRoute: options.allowDevBootstrapRoute,
    secretProvider: options.secretProvider,
    clock: options.clock,
    idGenerator: options.idGenerator,
    telemetry: options.telemetry,
    runtimeInstanceId: options.runtimeInstanceId,
    buildReference: options.buildReference,
    sseHeartbeatMs: options.sseHeartbeatMs,
    sseMaxLifetimeMs: options.sseMaxLifetimeMs,
    cursorSigningKey: options.cursorSigningKey,
    totpReplayStore: options.totpReplayStore,
    totpEncryptionKey: options.totpEncryptionKey,
    quotaRedis: options.quotaRedis,
    billingAdapters: options.billingAdapters,
    emailAdapter: options.emailAdapter,
    errorReporter: options.errorReporter,
    enableQuotaGuard: options.enableQuotaGuard,
    logger
  });

  const app = createApiFastifyServer(ctx);
  let closed = false;

  return {
    app,
    ctx,
    async start(listenOpts) {
      if (listenOpts.registerRuntime !== false) {
        await ctx.pgAdapter.withTransaction(ctx.pgAdapter.configuredRole, async (tx) => {
          const inst = await readInstallationSnapshot(ctx, tx);
          await ensureApiRuntimeRegistered(ctx, tx, inst.controlEpoch);
        });
      }
      const url = await app.listen({
        host: listenOpts.host,
        port: listenOpts.port
      });
      const address = app.server.address();
      const boundPort =
        address !== null && typeof address === "object" ? address.port : listenOpts.port;
      return {
        host: listenOpts.host,
        port: boundPort,
        url
      };
    },
    async close() {
      if (closed) {
        return;
      }
      closed = true;
      app.server.closeIdleConnections?.();
      const closePromise = app.close();
      app.server.closeAllConnections?.();
      await Promise.allSettled([closePromise, ctx.quotaRedis.close()]);
    }
  };
}
