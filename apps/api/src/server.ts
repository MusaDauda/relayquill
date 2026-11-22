import { LimitExceededDomainError, NotFoundDomainError } from "@relayquill/domain";
import Fastify, { LogController, type FastifyInstance } from "fastify";
import { type ApiContext } from "./context.js";
import { mapUnknownErrorToHttpResponse } from "./http/errors.js";
import { assertJsonMediaTypeHeader, assertStrictRawHeaders } from "./http/headers.js";
import {
  DEFAULT_API_BODY_LIMIT_BYTES,
  parseStrictHttpJsonBuffer
} from "./http/json-parser.js";
import { registerEventsAndDeliveriesRoutes } from "./routes/events-and-deliveries.js";
import { registerGovernanceAndStreamsRoutes } from "./routes/governance-and-streams.js";
import { registerHealthAndAccessRoutes } from "./routes/health-and-access.js";
import { registerPlatformAndProjectRoutes } from "./routes/platform-and-projects.js";

const EMPTY_BODY_OPTIONAL_PATHS = new Set([
  "/api/v1/session/logout",
  "/api/v1/session/csrf"
]);

export function createApiFastifyServer(ctx: ApiContext): FastifyInstance {
  const app = Fastify({
    loggerInstance: ctx.logger,
    bodyLimit: DEFAULT_API_BODY_LIMIT_BYTES,
    logController: new LogController({ disableRequestLogging: true }),
    routerOptions: { ignoreTrailingSlash: false },
    trustProxy: false,
    genReqId: () => ctx.ids.nextUuid()
  });

  const requestStartedAt = new WeakMap<object, number>();

  app.removeContentTypeParser("application/json");
  app.removeContentTypeParser("text/plain");

  app.addContentTypeParser(
    "application/json",
    { parseAs: "buffer" },
    (request, rawBody, done) => {
      try {
        const headerMap = assertStrictRawHeaders(request.raw.rawHeaders);
        assertJsonMediaTypeHeader(headerMap);
        const rawBuf = Buffer.isBuffer(rawBody) ? rawBody : Buffer.from(rawBody, "utf8");

        const routeLimit =
          (request.routeOptions.config as { rawBodyLimit?: number } | undefined)?.rawBodyLimit ??
          DEFAULT_API_BODY_LIMIT_BYTES;
        if (rawBuf.byteLength > routeLimit) {
          throw new LimitExceededDomainError({
            code: "PAYLOAD_TOO_LARGE",
            message: `Request body (${rawBuf.byteLength} bytes) exceeds limit (${routeLimit} bytes)`
          });
        }

        const routeUrl = request.url.split("?")[0] ?? request.url;
        const allowEmpty =
          rawBuf.byteLength === 0 && EMPTY_BODY_OPTIONAL_PATHS.has(routeUrl);
        const parsed = parseStrictHttpJsonBuffer(rawBuf, { allowEmpty });
        done(null, parsed);
      } catch (err) {
        done(err instanceof Error ? err : new Error(String(err)), undefined);
      }
    }
  );

  app.addHook("onRequest", (request, _reply, done) => {
    requestStartedAt.set(request, Date.now());
    assertStrictRawHeaders(request.raw.rawHeaders);
    done();
  });

  app.addHook("onSend", (_request, reply, payload, done) => {
    const routeUrl = _request.url.split("?")[0] ?? _request.url;
    if (!routeUrl.endsWith("/watch")) {
      reply.header("Cache-Control", "no-store");
    }
    reply.header("X-Content-Type-Options", "nosniff");
    reply.header("Referrer-Policy", "no-referrer");
    done(null, payload);
  });

  app.addHook("onResponse", (request, reply, done) => {
    const started = requestStartedAt.get(request);
    const durationMs = started !== undefined ? Math.max(0, Date.now() - started) : 0;
    ctx.logger.info(
      {
        request_id: request.id,
        method: request.method,
        route: request.routeOptions.url ?? request.url.split("?")[0],
        status_code: reply.statusCode,
        duration_ms: durationMs
      },
      "http.request.completed"
    );
    done();
  });

  app.setNotFoundHandler((request, reply) => {
    const notFound = new NotFoundDomainError({
      code: "NOT_FOUND",
      message: `Route ${request.method} ${request.url.split("?")[0] ?? request.url} not found`
    });
    const mapped = mapUnknownErrorToHttpResponse(notFound, { requestId: request.id });
    return reply.status(mapped.statusCode).send(mapped.envelope);
  });

  app.setErrorHandler((err, request, reply) => {
    const mapped = mapUnknownErrorToHttpResponse(err, { requestId: request.id });
    if (mapped.statusCode >= 500) {
      ctx.logger.error(
        {
          request_id: request.id,
          method: request.method,
          route: request.routeOptions.url ?? request.url.split("?")[0],
          status_code: mapped.statusCode,
          error_code: mapped.envelope.error.code,
          err
        },
        "http.request.failed"
      );
    } else {
      ctx.logger.warn(
        {
          request_id: request.id,
          method: request.method,
          route: request.routeOptions.url ?? request.url.split("?")[0],
          status_code: mapped.statusCode,
          error_code: mapped.envelope.error.code
        },
        "http.request.rejected"
      );
    }
    if (!reply.sent) {
      return reply.status(mapped.statusCode).send(mapped.envelope);
    }
    return undefined;
  });

  registerHealthAndAccessRoutes(app, ctx);
  registerPlatformAndProjectRoutes(app, ctx);
  registerEventsAndDeliveriesRoutes(app, ctx);
  registerGovernanceAndStreamsRoutes(app, ctx);

  return app;
}
