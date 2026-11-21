import { Buffer } from "node:buffer";
import Fastify, {
  type FastifyInstance,
  type FastifyReply,
  type FastifyRequest
} from "fastify";
import {
  EVENT_CONTENT_MEDIA_TYPE,
  WEBHOOK_HEADER_NAMES,
  parseEndpointId,
  parsePositiveInt64String,
  parseProjectId
} from "@relayquill/contracts";
import {
  ReceiverSdkError,
  createReceiverKeyHandle,
  createSignedDeliveryReceipt,
  executeIdempotentDelivery,
  handleEndpointProofChallenge,
  verifyWebhookRequest,
  type CanonicalUtcTimestamp,
  type EndpointId,
  type PositiveInt64String,
  type ProjectId,
  type ReceiverKeyResolverInput,
  type VerifyDeliverySuccess,
  type VerifyWebhookFailure
} from "@relayquill/receiver-sdk";
import {
  type IpcChannelRef,
  type IpcServerHandle,
  type SecretProvider
} from "@relayquill/runtime";
import {
  ReceiverRepository,
  createPgDeliveryExecutionScope,
  createReceiverDbClient,
  type CreateReceiverDbOptions,
  type ReceiverDbClient,
  type ReceiverIntegrationRecord,
  type ReceiverStateSnapshot
} from "./db.js";
import { ReceiverFaultController, startReceiverControlIpcServer } from "./faults.js";

export interface ReceiverServerOptions {
  readonly db?: ReceiverDbClient | undefined;
  readonly dbOptions?: CreateReceiverDbOptions | undefined;
  readonly host?: string | undefined;
  readonly port?: number | undefined;
  readonly routePath?: string | undefined;
  readonly bodyLimitBytes?: number | undefined;
  readonly keyProvider?: ReceiverKeyResolverInput | undefined;
  readonly secretProvider?: SecretProvider | undefined;
  readonly controlChannelEndpoint?: string | undefined;
  readonly controlChannel?: IpcChannelRef | undefined;
  readonly runtimeDir?: string | undefined;
  readonly now?: (() => CanonicalUtcTimestamp) | undefined;
  readonly expectedAuthorityOverride?: string | undefined;
  readonly allowDuplicateHeaderLookup?: boolean | undefined;
  readonly allowFixtureAuthority?: boolean | undefined;
  readonly logRequests?: boolean | undefined;
}

export interface ReceiverServerHandle {
  readonly app: FastifyInstance;
  readonly db: ReceiverDbClient;
  readonly faults: ReceiverFaultController;
  readonly address: () => { readonly host: string; readonly port: number } | undefined;
  readonly ipcEndpoint: () => string | undefined;
  start(): Promise<{ readonly host: string; readonly port: number; readonly ipcEndpoint?: string | undefined }>;
  stop(): Promise<void>;
  inspectState(): Promise<ReceiverStateSnapshot>;
}

function readRawRequestBody(body: unknown): Uint8Array {
  if (Buffer.isBuffer(body)) {
    return body;
  }
  if (body instanceof Uint8Array) {
    return body;
  }
  if (typeof body === "string") {
    return Buffer.from(body, "utf8");
  }
  return Buffer.alloc(0);
}

function readRawHeaderList(request: FastifyRequest): readonly string[] {
  if (Array.isArray(request.raw.rawHeaders) && request.raw.rawHeaders.length > 0) {
    return request.raw.rawHeaders;
  }
  const flattened: string[] = [];
  for (const [key, value] of Object.entries(request.headers)) {
    if (typeof value === "string") {
      flattened.push(key, value);
    } else if (Array.isArray(value)) {
      for (const item of value) {
        flattened.push(key, item);
      }
    }
  }
  return flattened;
}

function toSdkProjectId(raw: string): ProjectId {
  const validated: string = parseProjectId(raw, "project_id");
  return validated as ProjectId;
}

function toSdkEndpointId(raw: string): EndpointId {
  const validated: string = parseEndpointId(raw, "endpoint_id");
  return validated as EndpointId;
}

function toSdkPositiveInt64String(raw: string): PositiveInt64String {
  const validated: string = parsePositiveInt64String(raw, "endpoint_version");
  return validated as PositiveInt64String;
}

function readSingleHeader(
  rawHeaders: readonly string[],
  targetName: string
): string | undefined {
  const lower = targetName.toLowerCase();
  for (let i = 0; i + 1 < rawHeaders.length; i += 2) {
    const name = rawHeaders[i];
    const value = rawHeaders[i + 1];
    if (name !== undefined && value !== undefined && name.toLowerCase() === lower) {
      return value;
    }
  }
  return undefined;
}

function buildKeyProvider(
  db: ReceiverDbClient,
  repo: ReceiverRepository,
  options: ReceiverServerOptions
): ReceiverKeyResolverInput {
  if (options.keyProvider !== undefined) {
    return options.keyProvider;
  }

  return async (query) => {
    const meta = await db.inTransaction((tx) =>
      repo.findKeyMetadata(tx, {
        projectId: query.projectId,
        endpointId: query.endpointId,
        keyId: query.keyId
      })
    );
    if (meta === undefined) {
      return null;
    }
    if (options.secretProvider === undefined) {
      return null;
    }

    const secretRef =
      meta.custodyReference.includes("#") || meta.custodyVersionReference.length === 0
        ? meta.custodyReference
        : meta.custodyReference;

    const secretHandle = await options.secretProvider.getSecret(secretRef);
    try {
      if (meta.verifyUntil !== undefined && Date.parse(meta.verifyUntil) <= Date.now()) {
        return null;
      }
      const copy = Uint8Array.from(secretHandle.readBytes());
      return {
        handle: createReceiverKeyHandle(copy, { id: `${meta.keyId}:${meta.custodyVersionReference}` }),
        metadata: {
          keyId: meta.keyId,
          state: meta.state
        },
        releaseAfterUse: true
      };
    } finally {
      secretHandle.destroy();
    }
  };
}

function tamperMacBase64Url(mac: string): string {
  const raw = Buffer.from(mac, "base64url");
  if (raw.byteLength === 0) {
    return mac;
  }
  const mutated = Buffer.from(raw);
  const first = mutated[0] ?? 0;
  mutated[0] = first ^ 0xff;
  return mutated.toString("base64url");
}

function failureHttpStatus(failure: VerifyWebhookFailure): number {
  return failure.httpStatus;
}

function mapErrorToHttpStatus(err: unknown): { readonly status: number; readonly code: string; readonly message: string } {
  if (err instanceof ReceiverSdkError) {
    return {
      status: err.httpStatus,
      code: err.code,
      message: err.message
    };
  }
  const message = err instanceof Error ? err.message : String(err);
  if (message.includes("CONSUMER_ORDER_GAP") || message.includes("ORIGINAL_EVENT_CONFLICT") || message.includes("CONSUMER_ORDER_POSITION_CONFLICT")) {
    return { status: 409, code: "CONFLICT", message };
  }
  return { status: 500, code: "INTERNAL_ERROR", message };
}

export async function createReceiverServer(
  options: ReceiverServerOptions
): Promise<ReceiverServerHandle> {
  const ownsDb = options.db === undefined;
  const db =
    options.db ??
    (await createReceiverDbClient(
      options.dbOptions ?? {
        schema: "rc"
      }
    ));
  const repo = new ReceiverRepository();
  const faults = new ReceiverFaultController();
  const host = options.host ?? "127.0.0.1";
  const port = options.port ?? 19095;
  const routePath = options.routePath ?? "/webhook";
  const bodyLimitBytes = options.bodyLimitBytes ?? 2 * 1024 * 1024;
  const keyProvider = buildKeyProvider(db, repo, options);

  const app = Fastify({
    logger: options.logRequests ?? false,
    bodyLimit: bodyLimitBytes
  });

  // Preserve exact wire bytes without JSON parsing or re-serialization.
  app.removeAllContentTypeParsers();
  app.addContentTypeParser("*", { parseAs: "buffer" }, (_request, body, done) => {
    done(null, body);
  });

  app.get("/health/live", async (_request, reply) => {
    return reply.status(200).send({
      status: "live",
      role: "receiver"
    });
  });

  app.get("/health/ready", async (_request, reply) => {
    try {
      await db.query("SELECT 1 AS ok");
      return await reply.status(200).send({
        status: "ready",
        role: "receiver"
      });
    } catch (err) {
      return reply.status(503).send({
        status: "not_ready",
        role: "receiver",
        error: err instanceof Error ? err.message : String(err)
      });
    }
  });

  const handleWebhookPost = async (request: FastifyRequest, reply: FastifyReply) => {
    const rawBodyBytes = readRawRequestBody(request.body);
    const rawHeaders = readRawHeaderList(request);
    const observedAuthority =
      options.expectedAuthorityOverride ??
      readSingleHeader(rawHeaders, "host") ??
      `${host}:${port}`;
    const rawProjectHeader = readSingleHeader(rawHeaders, WEBHOOK_HEADER_NAMES.projectId);
    const rawEndpointHeader = readSingleHeader(rawHeaders, WEBHOOK_HEADER_NAMES.endpointId);

    let integration: ReceiverIntegrationRecord | undefined;
    let allowedVersions = new Set<PositiveInt64String>();

    try {
      const lookup = await db.inTransaction(async (tx) => {
        const found = await repo.findIntegrationByRequest(tx, {
          requestTarget: request.url,
          ...(rawProjectHeader !== undefined
            ? { projectId: toSdkProjectId(rawProjectHeader) }
            : {}),
          ...(rawEndpointHeader !== undefined
            ? { endpointId: toSdkEndpointId(rawEndpointHeader) }
            : {})
        });
        if (found === undefined) {
          return undefined;
        }
        const versions = await repo.findAllowedEndpointVersions(tx, found.id);
        return { found, versions };
      });

      if (lookup !== undefined) {
        integration = lookup.found;
        const parsedSet = new Set<PositiveInt64String>();
        for (const v of lookup.versions) {
          parsedSet.add(toSdkPositiveInt64String(v));
        }
        allowedVersions = parsedSet;
      }
    } catch (err) {
      const mapped = mapErrorToHttpStatus(err);
      return reply.status(mapped.status).send({
        ok: false,
        error: mapped.code,
        message: mapped.message
      });
    }

    if (integration === undefined) {
      return reply.status(404).send({
        ok: false,
        error: "INTEGRATION_NOT_FOUND",
        message: `No active receiver integration matches request target "${request.url}"`
      });
    }

    const verified = await verifyWebhookRequest({
      method: request.method,
      rawHeaders,
      rawBodyBytes,
      expectedTarget: {
        externalAuthority: integration.expectedExternalAuthority,
        requestTarget: integration.expectedRequestTarget,
        observedAuthority,
        observedRequestTarget: request.url
      },
      expectedContext: {
        projectId: integration.relayProjectId,
        endpointId: integration.endpointId,
        consumerContractScope: integration.consumerContractScope,
        ...(allowedVersions.size > 0 ? { allowedEndpointVersions: allowedVersions } : {})
      },
      ...(options.allowFixtureAuthority === true
        ? {
            authorityValidation: {
              allowFixtureAuthority: true,
              expectedFixtureAuthority: integration.expectedExternalAuthority
            }
          }
        : {}),
      keyProvider
    });

    if (!verified.ok) {
      return reply.status(failureHttpStatus(verified)).send({
        ok: false,
        error: verified.errorCode,
        reason: verified.safeReason
      });
    }

    if (verified.purpose === "endpoint_verification") {
      const proof = await handleEndpointProofChallenge({
        verifiedRequest: verified,
        keyProvider
      });
      return reply.status(proof.statusCode).headers(proof.headers).send();
    }

    const delivery: VerifyDeliverySuccess = verified;
    const scope = createPgDeliveryExecutionScope({
      db,
      repo,
      integrationId: integration.id,
      verifiedDelivery: delivery
    });

    try {
      const execResult = await executeIdempotentDelivery({
        verifiedDelivery: delivery,
        inbox: scope.inbox,
        onBusinessMutation: async () => {
          await scope.onBusinessMutation();
        }
      });

      const commitInfo = scope.getCommitInfo();
      const signedReceipt = await createSignedDeliveryReceipt({
        verifiedDelivery: delivery,
        committedAt: commitInfo.committedAt,
        receiptId: commitInfo.receiptId,
        keyProvider
      });

      const delayMs = faults.consumeCommitDelayMs();
      if (delayMs > 0) {
        await new Promise<void>((resolve) => setTimeout(resolve, delayMs));
      }

      if (faults.consumeCommitDrop()) {
        reply.hijack();
        reply.raw.destroy();
        if (!request.raw.destroyed) {
          request.raw.destroy();
        }
        return;
      }

      if (faults.consumeOversizedReceipt()) {
        const oversizedBody = JSON.stringify({
          ...signedReceipt.receipt,
          _fault_padding: "x".repeat(4500),
          _outcome: execResult.outcome
        });
        return await reply
          .status(200)
          .headers(signedReceipt.headers)
          .type(EVENT_CONTENT_MEDIA_TYPE)
          .send(Buffer.from(oversizedBody, "utf8"));
      }

      if (faults.consumeInvalidReceiptMac()) {
        const tamperedReceipt = {
          ...signedReceipt.receipt,
          mac: tamperMacBase64Url(signedReceipt.receipt.mac)
        };
        return await reply
          .status(200)
          .headers(signedReceipt.headers)
          .type(EVENT_CONTENT_MEDIA_TYPE)
          .send(Buffer.from(JSON.stringify(tamperedReceipt), "utf8"));
      }

      return await reply
        .status(signedReceipt.statusCode)
        .headers(signedReceipt.headers)
        .type(signedReceipt.contentType)
        .send(Buffer.from(signedReceipt.bodyBytes));
    } catch (err) {
      const mapped = mapErrorToHttpStatus(err);
      return reply.status(mapped.status).send({
        ok: false,
        error: mapped.code,
        message: mapped.message
      });
    }
  };

  app.post(routePath, handleWebhookPost);
  if (routePath !== "/webhooks/*") {
    app.post("/webhooks/*", handleWebhookPost);
  }

  let ipcHandle: IpcServerHandle | undefined;
  let boundAddress: { readonly host: string; readonly port: number } | undefined;

  const inspectState = async (): Promise<ReceiverStateSnapshot> => {
    return db.inTransaction((tx) => repo.inspectState(tx));
  };

  return {
    app,
    db,
    faults,
    address: () => boundAddress,
    ipcEndpoint: () => ipcHandle?.endpoint,
    inspectState,
    async start() {
      await app.listen({ host, port });
      const addr = app.server.address();
      if (addr !== null && typeof addr === "object") {
        boundAddress = { host: addr.address, port: addr.port };
      } else {
        boundAddress = { host, port };
      }

      if (options.controlChannelEndpoint !== undefined || options.controlChannel !== undefined) {
        ipcHandle = await startReceiverControlIpcServer({
          endpoint: options.controlChannelEndpoint,
          channelRef: options.controlChannel,
          runtimeDir: options.runtimeDir,
          faults,
          inspectState
        });
      }

      return {
        host: boundAddress.host,
        port: boundAddress.port,
        ...(ipcHandle !== undefined ? { ipcEndpoint: ipcHandle.endpoint } : {})
      };
    },
    async stop() {
      if (ipcHandle !== undefined) {
        await ipcHandle.close().catch(() => undefined);
        ipcHandle = undefined;
      }
      await app.close().catch(() => undefined);
      boundAddress = undefined;
      if (ownsDb) {
        await db.close().catch(() => undefined);
      }
    }
  };
}
