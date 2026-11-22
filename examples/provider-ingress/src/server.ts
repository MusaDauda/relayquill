import { Buffer } from "node:buffer";
import crypto from "node:crypto";
import Fastify, {
  type FastifyInstance,
  type FastifyReply,
  type FastifyRequest
} from "fastify";
import { parseCanonicalUuid } from "@relayquill/contracts";
import { type RelayquillProducerClient } from "@relayquill/producer-sdk";
import {
  createIpcServer,
  resolveIpcChannelEndpoint,
  type IpcChannelRef,
  type IpcServerHandle,
  type SecretProvider
} from "@relayquill/runtime";
import {
  ProviderIngressDbError,
  ProviderIngressRepository,
  createProviderIngressDbClient,
  type CreateProviderIngressDbOptions,
  type ProviderBindingRecord,
  type ProviderIngressDbClient,
  type ProviderIngressStateSnapshot,
  type ProviderKind
} from "./db.js";
import {
  ProviderOutboxForwarder,
  prepareNormalizedCallbackSubmission,
  type ProviderForwarderOptions
} from "./forwarder.js";
import {
  ProviderVerificationError,
  normalizeGithubPushCallback,
  normalizePaystackCallback,
  normalizeStripeCallback,
  verifyGithubWebhookCallback,
  verifyPaystackWebhookCallback,
  verifyStripeWebhookCallback,
  type NormalizedProviderCallback
} from "./verify.js";

export interface ProviderIngressServerOptions {
  readonly db?: ProviderIngressDbClient | undefined;
  readonly dbOptions?: CreateProviderIngressDbOptions | undefined;
  readonly host?: string | undefined;
  readonly port?: number | undefined;
  readonly stripePath?: string | undefined;
  readonly paystackPath?: string | undefined;
  readonly githubPath?: string | undefined;
  readonly bodyLimitBytes?: number | undefined;
  readonly secretProvider?: SecretProvider | undefined;
  readonly resolveWebhookSecret?: ((binding: ProviderBindingRecord) => Promise<string> | string) | undefined;
  readonly producerClient?: RelayquillProducerClient | undefined;
  readonly forwarderOptions?: Partial<Omit<ProviderForwarderOptions, "db" | "repository" | "producerClient">> | undefined;
  readonly startForwarder?: boolean | undefined;
  readonly forwardOnIngress?: boolean | undefined;
  readonly toleranceSeconds?: number | undefined;
  readonly nowSeconds?: (() => number) | undefined;
  readonly controlChannelEndpoint?: string | undefined;
  readonly controlChannel?: IpcChannelRef | undefined;
  readonly runtimeDir?: string | undefined;
  readonly logRequests?: boolean | undefined;
}

export interface ProviderIngressServerHandle {
  readonly app: FastifyInstance;
  readonly db: ProviderIngressDbClient;
  readonly forwarder?: ProviderOutboxForwarder | undefined;
  readonly address: () => { readonly host: string; readonly port: number } | undefined;
  readonly ipcEndpoint: () => string | undefined;
  start(): Promise<{ readonly host: string; readonly port: number; readonly ipcEndpoint?: string | undefined }>;
  stop(): Promise<void>;
  inspectState(): Promise<ProviderIngressStateSnapshot>;
}

function readRawBodyBytes(body: unknown): Buffer {
  if (Buffer.isBuffer(body)) {
    return body;
  }
  if (body instanceof Uint8Array) {
    return Buffer.from(body);
  }
  if (typeof body === "string") {
    return Buffer.from(body, "utf8");
  }
  return Buffer.alloc(0);
}

function readSingleHeader(request: FastifyRequest, headerName: string): string | undefined {
  const lower = headerName.toLowerCase();
  if (Array.isArray(request.raw.rawHeaders)) {
    for (let i = 0; i + 1 < request.raw.rawHeaders.length; i += 2) {
      const k = request.raw.rawHeaders[i];
      const v = request.raw.rawHeaders[i + 1];
      if (k !== undefined && v !== undefined && k.toLowerCase() === lower) {
        return v;
      }
    }
  }
  const direct = request.headers[lower];
  if (typeof direct === "string") {
    return direct;
  }
  if (Array.isArray(direct) && typeof direct[0] === "string") {
    return direct[0];
  }
  return undefined;
}

async function resolveBindingSecret(
  binding: ProviderBindingRecord,
  options: ProviderIngressServerOptions
): Promise<string> {
  if (options.resolveWebhookSecret !== undefined) {
    const resolved = await options.resolveWebhookSecret(binding);
    if (resolved.length === 0) {
      throw new ProviderVerificationError({
        code: "EMPTY_WEBHOOK_SECRET",
        httpStatus: 500,
        message: `Resolved empty webhook secret for binding ${binding.id}`
      });
    }
    return resolved;
  }
  if (options.secretProvider === undefined) {
    throw new ProviderVerificationError({
      code: "MISSING_SECRET_PROVIDER",
      httpStatus: 500,
      message: "No secretProvider or resolveWebhookSecret configured for provider ingress"
    });
  }
  const handle = await options.secretProvider.getSecret(binding.secretCustodyReference);
  try {
    const secretText = Buffer.from(handle.readBytes()).toString("utf8");
    if (secretText.length === 0) {
      throw new ProviderVerificationError({
        code: "EMPTY_WEBHOOK_SECRET",
        httpStatus: 500,
        message: `Custody secret empty for binding ${binding.id}`
      });
    }
    return secretText;
  } finally {
    handle.destroy();
  }
}

function readOptionalBindingSelector(request: FastifyRequest): string | undefined {
  const q = request.query as Record<string, unknown> | undefined;
  const fromQuery = typeof q?.["binding_id"] === "string" ? q["binding_id"].trim() : "";
  const fromHeader = readSingleHeader(request, "x-relayquill-binding-id")?.trim() ?? "";
  const chosen = fromQuery.length > 0 ? fromQuery : fromHeader.length > 0 ? fromHeader : undefined;
  if (chosen === undefined) {
    return undefined;
  }
  try {
    return parseCanonicalUuid(chosen, "binding_id");
  } catch {
    throw new ProviderVerificationError({
      code: "INVALID_BINDING_ID",
      httpStatus: 400,
      message: `Invalid binding_id selector "${chosen}"`
    });
  }
}

function sendErrorReply(
  reply: FastifyReply,
  status: number,
  code: string,
  message: string
): FastifyReply {
  return reply.code(status).type("application/json").send({
    ok: false,
    error: {
      code,
      message
    }
  });
}

function mapErrorReply(err: unknown): {
  readonly status: number;
  readonly code: string;
  readonly message: string;
} {
  if (err instanceof ProviderVerificationError) {
    return {
      status: err.httpStatus,
      code: err.code,
      message: err.message
    };
  }
  if (err instanceof ProviderIngressDbError) {
    return {
      status: err.httpStatus,
      code: err.code,
      message: err.message
    };
  }
  return {
    status: 500,
    code: "INTERNAL_ERROR",
    message: err instanceof Error ? err.message : "Internal provider ingress error"
  };
}

export async function createProviderIngressServer(
  options: ProviderIngressServerOptions
): Promise<ProviderIngressServerHandle> {
  const db =
    options.db ??
    (options.dbOptions !== undefined ? await createProviderIngressDbClient(options.dbOptions) : undefined);
  if (db === undefined) {
    throw new Error("createProviderIngressServer requires either options.db or options.dbOptions");
  }

  const ownsDb = options.db === undefined;
  const repo = new ProviderIngressRepository();
  const host = options.host ?? "127.0.0.1";
  const port = options.port ?? 19096;
  const stripePath = options.stripePath ?? "/webhooks/stripe";
  const paystackPath = options.paystackPath ?? "/webhooks/paystack";
  const githubPath = options.githubPath ?? "/webhooks/github";
  const bodyLimitBytes = options.bodyLimitBytes ?? 262_144;
  const toleranceSeconds = options.toleranceSeconds ?? 300;
  const forwardOnIngress = options.forwardOnIngress ?? false;

  const forwarder =
    options.producerClient !== undefined
      ? new ProviderOutboxForwarder({
          db,
          repository: repo,
          producerClient: options.producerClient,
          ...options.forwarderOptions
        })
      : undefined;

  const app = Fastify({
    logger: options.logRequests ?? false,
    bodyLimit: bodyLimitBytes
  });

  app.removeContentTypeParser(["application/json", "text/plain"]);
  app.addContentTypeParser("*", { parseAs: "buffer" }, (_request, payload, done) => {
    done(null, payload);
  });

  app.get("/health/live", async (_request, reply) => {
    return reply.code(200).send({
      ok: true,
      status: "live",
      service: "provider-ingress"
    });
  });

  app.get("/health/ready", async (_request, reply) => {
    try {
      await db.inTransaction(async (tx) => {
        await tx.query("SELECT 1 AS ready");
      });
      return await reply.code(200).send({
        ok: true,
        status: "ready",
        backend: db.backend
      });
    } catch (err) {
      return reply.code(503).send({
        ok: false,
        status: "not_ready",
        error: err instanceof Error ? err.message : "Database readiness check failed"
      });
    }
  });

  const handleIngressCallback = async (
    provider: ProviderKind,
    request: FastifyRequest,
    reply: FastifyReply
  ): Promise<FastifyReply> => {
    try {
      const rawBodyBytes = readRawBodyBytes(request.body);
      if (rawBodyBytes.byteLength === 0) {
        return sendErrorReply(reply, 400, "EMPTY_PAYLOAD", "Webhook request body must be non-empty");
      }

      const bindingSelector = readOptionalBindingSelector(request);
      const candidates = await db.inTransaction((tx) =>
        repo.findActiveBindingsByProvider(tx, provider, bindingSelector)
      );

      if (candidates.length === 0) {
        return sendErrorReply(
          reply,
          404,
          "NO_ACTIVE_BINDING",
          `No active ${provider} binding matched request`
        );
      }

      let matchedBinding: ProviderBindingRecord | undefined;
      let normalized: NormalizedProviderCallback | undefined;
      let lastVerificationError: ProviderVerificationError | undefined;

      for (const candidate of candidates) {
        try {
          const webhookSecret = await resolveBindingSecret(candidate, options);
          if (provider === "stripe") {
            const stripeSig = readSingleHeader(request, "stripe-signature");
            const stripeEvent = await verifyStripeWebhookCallback({
              rawBodyBytes,
              signatureHeader: stripeSig,
              webhookSecret,
              toleranceSeconds,
              ...(options.nowSeconds !== undefined ? { receivedAtSeconds: options.nowSeconds() } : {})
            });
            normalized = normalizeStripeCallback({
              binding: candidate,
              event: stripeEvent,
              rawBodyBytes
            });
          } else if (provider === "paystack") {
            const paystackSig = readSingleHeader(request, "x-paystack-signature");
            const paystackPayload = verifyPaystackWebhookCallback({
              rawBodyBytes,
              signatureHeader: paystackSig,
              webhookSecret
            });
            normalized = normalizePaystackCallback({
              binding: candidate,
              payload: paystackPayload,
              rawBodyBytes
            });
          } else {
            const githubSig = readSingleHeader(request, "x-hub-signature-256");
            const githubDelivery = readSingleHeader(request, "x-github-delivery");
            const githubEvent = readSingleHeader(request, "x-github-event");
            const githubPayload = verifyGithubWebhookCallback({
              rawBodyBytes,
              signatureHeader: githubSig,
              webhookSecret
            });
            normalized = normalizeGithubPushCallback({
              binding: candidate,
              payload: githubPayload,
              rawBodyBytes,
              deliveryId: githubDelivery,
              eventHeader: githubEvent
            });
          }
          matchedBinding = candidate;
          break;
        } catch (err) {
          if (err instanceof ProviderVerificationError) {
            lastVerificationError = err;
            if (err.httpStatus === 400) {
              throw err;
            }
            continue;
          }
          throw err;
        }
      }

      if (matchedBinding === undefined || normalized === undefined) {
        if (lastVerificationError !== undefined) {
          throw lastVerificationError;
        }
        throw new ProviderVerificationError({
          code: "VERIFICATION_FAILED",
          httpStatus: 401,
          message: `Failed to verify ${provider} webhook callback`
        });
      }

      const preparedSubmission = await prepareNormalizedCallbackSubmission({
        binding: matchedBinding,
        normalized
      });

      const observationId = crypto.randomUUID();
      const forwardIntentId = crypto.randomUUID();

      const stored = await db.inTransaction((tx) =>
        repo.receiveVerifiedCallback(tx, {
          observationId,
          forwardIntentId,
          bindingId: matchedBinding.id,
          bindingVersion: matchedBinding.currentBindingVersion,
          provider: normalized.provider,
          accountMode: normalized.accountMode,
          payloadProfile: normalized.payloadProfile,
          providerEventId: normalized.providerEventId,
          eventType: normalized.eventType,
          objectReference: normalized.objectReference,
          providerBusinessTime: normalized.providerBusinessTime,
          rawBodySha256Hex: normalized.rawBodySha256Hex,
          identityProfile: normalized.identityProfile,
          semanticKeySha256Hex: normalized.semanticKeySha256Hex,
          normalizedFacts: normalized.normalizedFacts,
          normalizedFactsSha256Hex: normalized.normalizedFactsSha256Hex,
          businessKey: normalized.businessKey,
          requestKey: normalized.requestKey,
          preparedBytes: preparedSubmission.preparedBytes,
          submissionSha256Hex: preparedSubmission.submissionSha256Hex
        })
      );

      if (stored.outcome === "accepted") {
        if (forwardOnIngress && forwarder !== undefined && stored.forwardIntentId !== undefined) {
          await forwarder.processIntent(stored.forwardIntentId, "ready");
        }
        return await reply.code(202).type("application/json").send({
          ok: true,
          outcome: stored.outcome,
          binding_id: stored.bindingId,
          binding_version: stored.bindingVersion.toString(10),
          observation_id: stored.observationId,
          ...(stored.forwardIntentId !== undefined ? { forward_intent_id: stored.forwardIntentId } : {}),
          business_key: normalized.businessKey,
          request_key: normalized.requestKey
        });
      }

      return await reply.code(200).type("application/json").send({
        ok: true,
        outcome: stored.outcome,
        binding_id: stored.bindingId,
        binding_version: stored.bindingVersion.toString(10),
        observation_id: stored.observationId
      });
    } catch (err) {
      const mapped = mapErrorReply(err);
      return sendErrorReply(reply, mapped.status, mapped.code, mapped.message);
    }
  };

  app.post(stripePath, async (request, reply) => handleIngressCallback("stripe", request, reply));
  app.post(paystackPath, async (request, reply) => handleIngressCallback("paystack", request, reply));
  app.post(githubPath, async (request, reply) => handleIngressCallback("github", request, reply));

  let ipcHandle: IpcServerHandle | undefined;
  let boundAddress: { readonly host: string; readonly port: number } | undefined;
  let resolvedIpcEndpoint: string | undefined;

  const inspectState = (): Promise<ProviderIngressStateSnapshot> =>
    db.inTransaction((tx) => repo.inspectState(tx));

  const startControlIpc = async (): Promise<string | undefined> => {
    const endpoint =
      options.controlChannelEndpoint ??
      (options.controlChannel !== undefined
        ? resolveIpcChannelEndpoint(
            options.controlChannel,
            options.runtimeDir !== undefined ? { runtimeDir: options.runtimeDir } : {}
          )
        : undefined);
    if (endpoint === undefined) {
      return undefined;
    }

    ipcHandle = createIpcServer(endpoint, async (rawRequest) => {
      if (typeof rawRequest !== "object" || rawRequest === null || Array.isArray(rawRequest)) {
        return { ok: false, errorCode: "INVALID_REQUEST", message: "IPC request must be a JSON object" };
      }
      const rec = rawRequest as Record<string, unknown>;
      const rawOp = rec["op"] ?? rec["command"] ?? rec["action"];
      if (typeof rawOp !== "string" || rawOp.length === 0) {
        return { ok: false, errorCode: "INVALID_REQUEST", message: "Missing op/command field" };
      }
      switch (rawOp) {
        case "inspect_state":
          return { ok: true, op: rawOp, state: await inspectState() };
        case "get_health":
          return {
            ok: true,
            op: rawOp,
            status: "ready",
            backend: db.backend,
            forwarding: forwarder?.isRunning ?? false
          };
        case "run_forwarder_once":
          if (forwarder === undefined) {
            return {
              ok: false,
              errorCode: "FORWARDER_DISABLED",
              message: "Forwarder is not configured on this provider-ingress server"
            };
          }
          return { ok: true, op: rawOp, summary: await forwarder.runOnce() };
        default:
          return {
            ok: false,
            errorCode: "UNKNOWN_COMMAND",
            message: `Unknown provider-ingress control command: ${rawOp}`
          };
      }
    });

    await ipcHandle.listen();
    return endpoint;
  };

  return {
    app,
    db,
    ...(forwarder !== undefined ? { forwarder } : {}),
    address: () => boundAddress,
    ipcEndpoint: () => resolvedIpcEndpoint,
    async start() {
      const listenResult = await app.listen({ host, port });
      const parsed = new URL(listenResult);
      const actualPort = parsed.port !== "" ? Number(parsed.port) : port;
      boundAddress = Object.freeze({
        host: parsed.hostname || host,
        port: actualPort
      });
      resolvedIpcEndpoint = await startControlIpc();
      if (forwarder !== undefined && options.startForwarder !== false) {
        await forwarder.start();
      }
      return {
        host: boundAddress.host,
        port: boundAddress.port,
        ...(resolvedIpcEndpoint !== undefined ? { ipcEndpoint: resolvedIpcEndpoint } : {})
      };
    },
    async stop() {
      if (forwarder !== undefined) {
        await forwarder.stop().catch(() => undefined);
      }
      if (ipcHandle !== undefined) {
        await ipcHandle.close().catch(() => undefined);
        ipcHandle = undefined;
      }
      await app.close().catch(() => undefined);
      if (ownsDb) {
        await db.close().catch(() => undefined);
      }
    },
    inspectState
  };
}
