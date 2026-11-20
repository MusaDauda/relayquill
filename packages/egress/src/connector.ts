import http from "node:http";
import https from "node:https";
import type net from "node:net";
import type tls from "node:tls";
import { type Sha256Hex, sha256Utf8Hex } from "@relayquill/contracts";
import {
  type DeliveryOutcomeClass,
  EVENT_MAX_ENVELOPE_BYTES,
  ValidationDomainError
} from "@relayquill/domain";
import { type EgressConfig, type ProfileKind, isProductionProfile } from "@relayquill/runtime";
import {
  normalizeConnectedPeerAddress,
  peerAddressMatchesSelected
} from "./address-policy.js";
import {
  DEFAULT_FIXTURE_RECEIVER_HOST,
  parseConfiguredFixtureTarget
} from "./url-policy.js";
import { type EgressDecision } from "./resolver.js";
import {
  type BoundedResponseResult,
  MAX_RESPONSE_BODY_BYTES,
  MAX_RESPONSE_HEADER_BYTES,
  readBoundedResponse
} from "./response.js";

export const DEFAULT_TCP_CONNECT_TIMEOUT_MS = 2_000 as const;
export const DEFAULT_TLS_HANDSHAKE_TIMEOUT_MS = 2_000 as const;
export const DEFAULT_RESPONSE_HEADER_TIMEOUT_MS = 3_000 as const;
export const DEFAULT_TOTAL_NETWORK_TIMEOUT_MS = 10_000 as const;

const consumedDecisions = new WeakSet<EgressDecision>();

export interface EgressTimeouts {
  readonly tcpConnectMs?: number | undefined;
  readonly tlsHandshakeMs?: number | undefined;
  readonly responseHeaderMs?: number | undefined;
  readonly totalNetworkMs?: number | undefined;
}

export interface ExecutePinnedEgressInput {
  readonly decision: EgressDecision;
  readonly method?: "POST" | undefined;
  readonly headers: Readonly<Record<string, string>>;
  readonly bodyBytes: Uint8Array;
  readonly profile?: ProfileKind | undefined;
  readonly egressConfig?: EgressConfig | undefined;
  readonly timeouts?: EgressTimeouts | undefined;
  readonly maxResponseHeaderBytes?: number | undefined;
  readonly maxResponseBodyBytes?: number | undefined;
  readonly ca?: string | Buffer | readonly (string | Buffer)[] | undefined;
  readonly signal?: AbortSignal | undefined;
  readonly monotonicNowMs?: (() => number) | undefined;
}

export interface EgressExecutionResult {
  readonly ok: boolean;
  readonly sendStarted: boolean;
  readonly outcomeClass: DeliveryOutcomeClass;
  readonly safeErrorCode: string | null;
  readonly peerAddressSha256: Sha256Hex | null;
  readonly selectedAddressSha256: Sha256Hex | null;
  readonly selectedFamily: 4 | 6 | null;
  readonly elapsedMs: number;
  readonly response?: BoundedResponseResult | undefined;
}

function defaultMonotonicMs(): number {
  return Number(process.hrtime.bigint() / 1_000_000n);
}

function buildControlledOutgoingHeaders(
  inputHeaders: Readonly<Record<string, string>>,
  decision: EgressDecision,
  bodyLength: number
): Record<string, string> {
  const controlledHost =
    decision.target.port === 443 && !decision.target.isFixtureException
      ? decision.target.normalizedHostname
      : decision.target.externalAuthority;

  const out: Record<string, string> = {};
  for (const [rawKey, rawVal] of Object.entries(inputHeaders)) {
    const lower = rawKey.toLowerCase();
    if (
      lower === "host" ||
      lower === "accept-encoding" ||
      lower === "content-length" ||
      lower === "proxy-authorization" ||
      lower === "proxy-connection" ||
      lower === "connection"
    ) {
      continue;
    }
    out[rawKey] = rawVal;
  }
  out.Host = controlledHost;
  out["Accept-Encoding"] = "identity";
  out["Content-Length"] = String(bodyLength);
  out.Connection = "close";
  return out;
}

function isTlsAuthErrorCode(err: unknown): boolean {
  if (typeof err !== "object" || err === null) {
    return false;
  }
  const code = (err as { readonly code?: unknown }).code;
  if (typeof code !== "string") {
    return false;
  }
  return (
    code === "DEPTH_ZERO_SELF_SIGNED_CERT" ||
    code === "SELF_SIGNED_CERT_IN_CHAIN" ||
    code === "UNABLE_TO_VERIFY_LEAF_SIGNATURE" ||
    code === "UNABLE_TO_GET_ISSUER_CERT" ||
    code === "UNABLE_TO_GET_ISSUER_CERT_LOCALLY" ||
    code === "CERT_HAS_EXPIRED" ||
    code === "CERT_NOT_YET_VALID" ||
    code === "CERT_REVOKED" ||
    code === "CERT_SIGNATURE_FAILURE" ||
    code === "ERR_TLS_CERT_ALTNAME_INVALID" ||
    code === "CERT_UNTRUSTED" ||
    code === "CERT_REJECTED"
  );
}

export async function executePinnedEgressRequest(
  input: ExecutePinnedEgressInput
): Promise<EgressExecutionResult> {
  const monotonicNowMs = input.monotonicNowMs ?? defaultMonotonicMs;
  const startMs = monotonicNowMs();

  const method = input.method ?? "POST";
  if (method !== "POST") {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Pinned connector only allows POST method, got "${String(method)}"`
    });
  }
  if (!(input.bodyBytes instanceof Uint8Array) || input.bodyBytes.byteLength > EVENT_MAX_ENVELOPE_BYTES) {
    throw new ValidationDomainError({
      code: "PAYLOAD_TOO_LARGE",
      message: `Outbound webhook body exceeds ${EVENT_MAX_ENVELOPE_BYTES} bytes`
    });
  }

  const decision = input.decision;
  if (decision.decision !== "allowed" || decision.selectedAddress === null || decision.selectedFamily === null) {
    return Object.freeze({
      ok: false,
      sendStarted: false,
      outcomeClass: "permanent_policy_or_security",
      safeErrorCode: decision.reasonCode || "EGRESS_POLICY_DENIED",
      peerAddressSha256: null,
      selectedAddressSha256: decision.selectedAddressSha256,
      selectedFamily: decision.selectedFamily,
      elapsedMs: Math.max(0, monotonicNowMs() - startMs)
    });
  }

  if (decision.target.isFixtureException) {
    const prodProfile = input.profile !== undefined && isProductionProfile(input.profile);
    const fixtureEnabled =
      input.egressConfig?.mode === "trusted_local_fixture" &&
      input.egressConfig.allow_fixture_receiver === true;
    if (prodProfile || !fixtureEnabled) {
      return Object.freeze({
        ok: false,
        sendStarted: false,
        outcomeClass: "permanent_policy_or_security",
        safeErrorCode: prodProfile ? "FIXTURE_FORBIDDEN_IN_PRODUCTION" : "FIXTURE_NOT_ENABLED",
        peerAddressSha256: null,
        selectedAddressSha256: decision.selectedAddressSha256,
        selectedFamily: decision.selectedFamily,
        elapsedMs: Math.max(0, monotonicNowMs() - startMs)
      });
    }
    const rawFixtureIp: unknown = input.egressConfig?.fixture_resolve_ip;
    const configuredFixture = parseConfiguredFixtureTarget(input.egressConfig);
    if (
      (rawFixtureIp !== undefined && rawFixtureIp !== "127.0.0.1") ||
      configuredFixture === null ||
      decision.target.normalizedHostname !== DEFAULT_FIXTURE_RECEIVER_HOST ||
      configuredFixture.host !== DEFAULT_FIXTURE_RECEIVER_HOST ||
      decision.target.externalAuthority !== configuredFixture.authority ||
      decision.target.requestTarget !== configuredFixture.path ||
      decision.selectedAddress !== "127.0.0.1"
    ) {
      return Object.freeze({
        ok: false,
        sendStarted: false,
        outcomeClass: "permanent_policy_or_security",
        safeErrorCode: "FIXTURE_TARGET_MISMATCH",
        peerAddressSha256: null,
        selectedAddressSha256: decision.selectedAddressSha256,
        selectedFamily: decision.selectedFamily,
        elapsedMs: Math.max(0, monotonicNowMs() - startMs)
      });
    }
  } else if (decision.target.scheme !== "https") {
    return Object.freeze({
      ok: false,
      sendStarted: false,
      outcomeClass: "permanent_policy_or_security",
      safeErrorCode: "HTTPS_REQUIRED",
      peerAddressSha256: null,
      selectedAddressSha256: decision.selectedAddressSha256,
      selectedFamily: decision.selectedFamily,
      elapsedMs: Math.max(0, monotonicNowMs() - startMs)
    });
  }

  if (consumedDecisions.has(decision)) {
    return Object.freeze({
      ok: false,
      sendStarted: false,
      outcomeClass: "permanent_policy_or_security",
      safeErrorCode: "EGRESS_DECISION_ALREADY_CONSUMED",
      peerAddressSha256: null,
      selectedAddressSha256: decision.selectedAddressSha256,
      selectedFamily: decision.selectedFamily,
      elapsedMs: Math.max(0, monotonicNowMs() - startMs)
    });
  }

  if (startMs >= decision.expiresAtMs) {
    return Object.freeze({
      ok: false,
      sendStarted: false,
      outcomeClass: "transport_unknown",
      safeErrorCode: "EGRESS_DECISION_EXPIRED",
      peerAddressSha256: null,
      selectedAddressSha256: decision.selectedAddressSha256,
      selectedFamily: decision.selectedFamily,
      elapsedMs: Math.max(0, monotonicNowMs() - startMs)
    });
  }

  if (input.signal?.aborted) {
    return Object.freeze({
      ok: false,
      sendStarted: false,
      outcomeClass: "transport_unknown",
      safeErrorCode: "EGRESS_ABORTED",
      peerAddressSha256: null,
      selectedAddressSha256: decision.selectedAddressSha256,
      selectedFamily: decision.selectedFamily,
      elapsedMs: Math.max(0, monotonicNowMs() - startMs)
    });
  }

  // Mark one-use decision consumed once pre-flight checks pass and socket dial begins.
  consumedDecisions.add(decision);

  const selectedAddress = decision.selectedAddress;
  const selectedFamily = decision.selectedFamily;
  const isHttps = decision.target.scheme === "https";
  const maxHeaderBytes = input.maxResponseHeaderBytes ?? MAX_RESPONSE_HEADER_BYTES;
  const maxBodyBytes = input.maxResponseBodyBytes ?? MAX_RESPONSE_BODY_BYTES;

  const totalBudgetMs = Math.min(
    DEFAULT_TOTAL_NETWORK_TIMEOUT_MS,
    Math.max(1, input.timeouts?.totalNetworkMs ?? DEFAULT_TOTAL_NETWORK_TIMEOUT_MS)
  );
  const tcpBudgetMs = Math.max(1, input.timeouts?.tcpConnectMs ?? DEFAULT_TCP_CONNECT_TIMEOUT_MS);
  const tlsBudgetMs = Math.max(1, input.timeouts?.tlsHandshakeMs ?? DEFAULT_TLS_HANDSHAKE_TIMEOUT_MS);
  const headerBudgetMs = Math.max(
    1,
    input.timeouts?.responseHeaderMs ?? DEFAULT_RESPONSE_HEADER_TIMEOUT_MS
  );

  const controlledHeaders = buildControlledOutgoingHeaders(
    input.headers,
    decision,
    input.bodyBytes.byteLength
  );

  const pinnedLookup = (
    hostname: string,
    optsOrCb:
      | number
      | { readonly family?: number | string | undefined; readonly all?: boolean | undefined }
      | ((err: NodeJS.ErrnoException | null, address?: string, family?: number) => void),
    maybeCb?: (
      err: NodeJS.ErrnoException | null,
      address?: string | readonly { readonly address: string; readonly family: number }[],
      family?: number
    ) => void
  ): void => {
    const cb =
      typeof optsOrCb === "function"
        ? (optsOrCb as (
            err: NodeJS.ErrnoException | null,
            address?: string | readonly { readonly address: string; readonly family: number }[],
            family?: number
          ) => void)
        : maybeCb!;
    const opts = typeof optsOrCb === "object" && optsOrCb !== null ? optsOrCb : {};

    if (hostname !== decision.target.normalizedHostname) {
      queueMicrotask(() => cb(new Error("Pinned lookup hostname mismatch")));
      return;
    }
    if (
      opts.family !== undefined &&
      opts.family !== 0 &&
      opts.family !== selectedFamily &&
      opts.family !== `IPv${selectedFamily}`
    ) {
      queueMicrotask(() => cb(new Error("Pinned lookup family mismatch")));
      return;
    }
    if (opts.all === true) {
      queueMicrotask(() => cb(null, [{ address: selectedAddress, family: selectedFamily }]));
      return;
    }
    queueMicrotask(() => cb(null, selectedAddress, selectedFamily));
  };

  return await new Promise<EgressExecutionResult>((resolve) => {
    const bodyController = new AbortController();
    let sendStarted = false;
    let responseReceived = false;
    let settled = false;
    let peerAddressSha256: Sha256Hex | null = null;
    let activeSocket: net.Socket | tls.TLSSocket | null = null;
    let socketClosed = false;
    let socketCloseWaiters: Array<() => void> = [];

    let tcpTimer: ReturnType<typeof setTimeout> | null = null;
    let tlsTimer: ReturnType<typeof setTimeout> | null = null;
    let headerTimer: ReturnType<typeof setTimeout> | null = null;
    let totalTimer: ReturnType<typeof setTimeout> | null = null;
    let parentAbortListener: (() => void) | null = null;

    const remainingTotalMs = (): number =>
      Math.max(1, totalBudgetMs - Math.max(0, monotonicNowMs() - startMs));

    const clearAllTimers = (): void => {
      if (tcpTimer !== null) {
        clearTimeout(tcpTimer);
        tcpTimer = null;
      }
      if (tlsTimer !== null) {
        clearTimeout(tlsTimer);
        tlsTimer = null;
      }
      if (headerTimer !== null) {
        clearTimeout(headerTimer);
        headerTimer = null;
      }
      if (totalTimer !== null) {
        clearTimeout(totalTimer);
        totalTimer = null;
      }
      if (parentAbortListener !== null) {
        input.signal?.removeEventListener("abort", parentAbortListener);
        parentAbortListener = null;
      }
    };

    const waitForSocketClosure = async (): Promise<void> => {
      if (activeSocket === null || socketClosed || activeSocket.destroyed) {
        return;
      }
      await new Promise<void>((resClose) => {
        const safety = setTimeout(resClose, 250);
        safety.unref();
        socketCloseWaiters.push(() => {
          clearTimeout(safety);
          resClose();
        });
      });
    };

    const finalize = async (result: Omit<EgressExecutionResult, "elapsedMs">): Promise<void> => {
      if (settled) {
        return;
      }
      settled = true;
      clearAllTimers();
      await waitForSocketClosure();
      resolve(
        Object.freeze({
          ...result,
          elapsedMs: Math.max(0, monotonicNowMs() - startMs)
        })
      );
    };

    const abortAndFail = (
      outcomeClass: DeliveryOutcomeClass,
      safeErrorCode: string
    ): void => {
      if (settled) {
        return;
      }
      bodyController.abort();
      req.destroy(new Error(safeErrorCode));
      if (activeSocket !== null && !activeSocket.destroyed) {
        activeSocket.destroy();
      }
      void finalize({
        ok: false,
        sendStarted,
        outcomeClass,
        safeErrorCode,
        peerAddressSha256,
        selectedAddressSha256: decision.selectedAddressSha256,
        selectedFamily
      });
    };

    const requestOptions = {
      hostname: decision.target.normalizedHostname,
      port: decision.target.port,
      path: decision.target.requestTarget,
      method: "POST",
      headers: controlledHeaders,
      agent: false as const,
      family: selectedFamily,
      autoSelectFamily: false,
      maxHeaderSize: maxHeaderBytes,
      lookup: pinnedLookup as unknown as net.LookupFunction
    };

    const caOption: string | Buffer | (string | Buffer)[] | undefined =
      input.ca === undefined
        ? undefined
        : Array.isArray(input.ca)
          ? [...(input.ca as readonly (string | Buffer)[])]
          : (input.ca as string | Buffer);

    const req = isHttps
      ? https.request({
          ...requestOptions,
          servername: decision.target.normalizedHostname,
          rejectUnauthorized: true,
          ...(caOption !== undefined ? { ca: caOption } : {})
        })
      : http.request(requestOptions);

    totalTimer = setTimeout(() => {
      abortAndFail("transport_unknown", "TOTAL_NETWORK_TIMEOUT");
    }, totalBudgetMs);
    totalTimer.unref();

    if (input.signal !== undefined) {
      parentAbortListener = () => {
        abortAndFail("transport_unknown", "EGRESS_ABORTED");
      };
      input.signal.addEventListener("abort", parentAbortListener, { once: true });
    }

    const writeRequestPayload = (): void => {
      if (settled) {
        return;
      }
      headerTimer = setTimeout(() => {
        abortAndFail("transport_unknown", "RESPONSE_HEADER_TIMEOUT");
      }, Math.min(headerBudgetMs, remainingTotalMs()));
      headerTimer.unref();

      sendStarted = true;
      if (input.bodyBytes.byteLength > 0) {
        req.write(input.bodyBytes);
      }
      req.end();
    };

    const verifyPeerBeforeTransmit = (sock: net.Socket | tls.TLSSocket): boolean => {
      const normalizedPeer = normalizeConnectedPeerAddress(sock.remoteAddress, selectedFamily);
      if (normalizedPeer !== null) {
        peerAddressSha256 = sha256Utf8Hex(normalizedPeer);
      }
      if (!peerAddressMatchesSelected(sock.remoteAddress, selectedAddress, selectedFamily)) {
        abortAndFail("permanent_policy_or_security", "SOCKET_PEER_MISMATCH");
        return false;
      }
      return true;
    };

    req.on("socket", (sock: net.Socket) => {
      activeSocket = sock;
      sock.once("close", () => {
        socketClosed = true;
        for (const waiter of socketCloseWaiters) {
          waiter();
        }
        socketCloseWaiters = [];
      });

      const handleTcpConnect = (): void => {
        if (tcpTimer !== null) {
          clearTimeout(tcpTimer);
          tcpTimer = null;
        }
        if (settled) {
          return;
        }
        if (sock.remoteAddress !== undefined && !verifyPeerBeforeTransmit(sock)) {
          return;
        }
        if (!isHttps) {
          if (sock.remoteAddress === undefined) {
            abortAndFail("permanent_policy_or_security", "SOCKET_PEER_MISMATCH");
            return;
          }
          writeRequestPayload();
          return;
        }

        const tlsSock = sock as tls.TLSSocket;
        if (tlsSock.authorized === true) {
          if (!verifyPeerBeforeTransmit(tlsSock)) {
            return;
          }
          writeRequestPayload();
          return;
        }

        tlsTimer = setTimeout(() => {
          abortAndFail("transport_unknown", "TLS_HANDSHAKE_TIMEOUT");
        }, Math.min(tlsBudgetMs, remainingTotalMs()));
        tlsTimer.unref();

        tlsSock.once("secureConnect", () => {
          if (tlsTimer !== null) {
            clearTimeout(tlsTimer);
            tlsTimer = null;
          }
          if (settled) {
            return;
          }
          if (!tlsSock.authorized) {
            abortAndFail("permanent_policy_or_security", "TLS_VERIFICATION_FAILED");
            return;
          }
          if (!verifyPeerBeforeTransmit(tlsSock)) {
            return;
          }
          writeRequestPayload();
        });
      };

      if (!sock.connecting) {
        handleTcpConnect();
      } else {
        tcpTimer = setTimeout(() => {
          abortAndFail("transport_unknown", "TCP_CONNECT_TIMEOUT");
        }, Math.min(tcpBudgetMs, remainingTotalMs()));
        tcpTimer.unref();
        sock.once("connect", handleTcpConnect);
      }
    });

    req.on("response", (res: http.IncomingMessage) => {
      responseReceived = true;
      if (headerTimer !== null) {
        clearTimeout(headerTimer);
        headerTimer = null;
      }
      void readBoundedResponse(res, {
        maxHeaderBytes,
        maxBodyBytes,
        signal: bodyController.signal
      })
        .then((response) => {
          req.destroy();
          void finalize({
            ok: response.httpAcknowledged,
            sendStarted,
            outcomeClass: response.outcomeClass,
            safeErrorCode: response.safeErrorCode,
            peerAddressSha256,
            selectedAddressSha256: decision.selectedAddressSha256,
            selectedFamily,
            response
          });
        })
        .catch((err: unknown) => {
          const code =
            typeof err === "object" &&
            err !== null &&
            "safeErrorCode" in err &&
            typeof (err as { safeErrorCode?: unknown }).safeErrorCode === "string"
              ? (err as { safeErrorCode: string }).safeErrorCode
              : "RESPONSE_READ_ERROR";
          abortAndFail("transport_unknown", code);
        });
    });

    req.on("error", (err: unknown) => {
      if (settled || responseReceived) {
        return;
      }
      if (!sendStarted && isTlsAuthErrorCode(err)) {
        abortAndFail("permanent_policy_or_security", "TLS_VERIFICATION_FAILED");
        return;
      }
      const code =
        typeof err === "object" &&
        err !== null &&
        "code" in err &&
        typeof (err as { code?: unknown }).code === "string"
          ? (err as { code: string }).code
          : "NETWORK_ERROR";
      abortAndFail("transport_unknown", code);
    });
  });
}

export class PinnedEgressConnector {
  readonly #profile: ProfileKind | undefined;
  readonly #egressConfig: EgressConfig | undefined;
  readonly #ca: string | Buffer | readonly (string | Buffer)[] | undefined;

  constructor(options: {
    readonly profile?: ProfileKind | undefined;
    readonly egressConfig?: EgressConfig | undefined;
    readonly ca?: string | Buffer | readonly (string | Buffer)[] | undefined;
  } = {}) {
    this.#profile = options.profile;
    this.#egressConfig = options.egressConfig;
    this.#ca = options.ca;
  }

  execute(
    input: Omit<ExecutePinnedEgressInput, "profile" | "egressConfig" | "ca"> & {
      readonly ca?: string | Buffer | readonly (string | Buffer)[] | undefined;
    }
  ): Promise<EgressExecutionResult> {
    return executePinnedEgressRequest({
      ...input,
      profile: this.#profile,
      egressConfig: this.#egressConfig,
      ca: input.ca ?? this.#ca
    });
  }
}
