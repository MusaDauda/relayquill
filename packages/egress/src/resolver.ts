import crypto from "node:crypto";
import dns from "node:dns";
import { type Temporal } from "@js-temporal/polyfill";
import {
  type CanonicalUtcTimestamp,
  type Sha256Hex,
  hashCanonicalJson,
  sha256Utf8Hex
} from "@relayquill/contracts";
import {
  AuthorizationDomainError,
  DependencyUnavailableDomainError,
  ExpiredDomainError,
  addMilliseconds,
  formatUtcTimestamp,
  fromEpochMicroseconds,
  nowUtcInstant
} from "@relayquill/domain";
import {
  type AddressPolicy,
  createAddressPolicy
} from "./address-policy.js";
import {
  type NormalizedDestinationTarget,
  type UrlPolicyOptions,
  assertValidPublicDnsHostname,
  normalizeDestinationUrl
} from "./url-policy.js";

export const DEFAULT_PREFLIGHT_BUDGET_MS = 5_000 as const;
export const DEFAULT_DNS_TIMEOUT_MS = 2_000 as const;
export const MAX_CNAME_CHAIN_LINKS = 8 as const;
export const MAX_RESOLVED_ADDRESSES = 16 as const;
export const MAX_EGRESS_DECISION_TTL_SECONDS = 30 as const;
export const TTL_ZERO_DECISION_WINDOW_MS = 1_000 as const;

export type EgressDecisionStatus = "allowed" | "denied" | "unavailable" | "expired";

export interface DnsAddressRecord {
  readonly address: string;
  readonly family: 4 | 6;
  readonly ttl: number;
}

export interface DnsCnameRecord {
  readonly value: string;
  readonly ttl?: number | undefined;
}

export interface DnsResolverAdapter {
  resolve4(hostname: string): Promise<readonly { readonly address: string; readonly ttl: number }[]>;
  resolve6(hostname: string): Promise<readonly { readonly address: string; readonly ttl: number }[]>;
  resolveCname(hostname: string): Promise<readonly (string | DnsCnameRecord)[]>;
  cancel(): void;
}

export type DnsResolverFactory = () => DnsResolverAdapter;

export function createNodeDnsResolverAdapter(): DnsResolverAdapter {
  const resolver = new dns.promises.Resolver();
  return {
    resolve4(hostname: string) {
      return resolver.resolve4(hostname, { ttl: true });
    },
    resolve6(hostname: string) {
      return resolver.resolve6(hostname, { ttl: true });
    },
    resolveCname(hostname: string) {
      return resolver.resolveCname(hostname);
    },
    cancel() {
      resolver.cancel();
    }
  };
}

export interface EgressDecision {
  readonly decisionId: string;
  readonly decision: EgressDecisionStatus;
  readonly reasonCode: string;
  readonly networkPolicyVersion: string;
  readonly registryIpv4Sha256: Sha256Hex;
  readonly registryIpv6Sha256: Sha256Hex;
  readonly authoritySha256: Sha256Hex;
  readonly answerSetSha256: Sha256Hex;
  readonly selectedAddress: string | null;
  readonly selectedAddressSha256: Sha256Hex | null;
  readonly selectedFamily: 4 | 6 | null;
  readonly target: NormalizedDestinationTarget;
  readonly cnameChain: readonly string[];
  readonly observedAt: CanonicalUtcTimestamp;
  readonly expiresAt: CanonicalUtcTimestamp;
  readonly observedAtMs: number;
  readonly expiresAtMs: number;
  readonly ttlSeconds: number;
  readonly oneShot: boolean;
  readonly cacheable: boolean;
}

export interface ResolveEgressOptions {
  readonly target: string | NormalizedDestinationTarget;
  readonly urlPolicyOptions?: UrlPolicyOptions | undefined;
  readonly addressPolicy?: AddressPolicy | undefined;
  readonly createDnsResolver?: DnsResolverFactory | undefined;
  readonly preflightBudgetMs?: number | undefined;
  readonly dnsTimeoutMs?: number | undefined;
  readonly attemptOrdinal?: number | undefined;
  readonly signal?: AbortSignal | undefined;
  readonly now?: Temporal.Instant | undefined;
  readonly monotonicNowMs?: (() => number) | undefined;
}

function defaultMonotonicMs(): number {
  return Number(process.hrtime.bigint() / 1_000_000n);
}

function getErrorCode(err: unknown): string {
  if (typeof err === "object" && err !== null && "code" in err) {
    const code = (err as { readonly code?: unknown }).code;
    if (typeof code === "string") {
      return code;
    }
  }
  return "";
}

function isNoDataError(err: unknown): boolean {
  const code = getErrorCode(err);
  return code === "ENODATA" || code === "NODATA";
}

function formatInstantUtc(instant: Temporal.Instant): CanonicalUtcTimestamp {
  const epochUs = instant.epochNanoseconds / 1_000n;
  return formatUtcTimestamp(fromEpochMicroseconds(epochUs, "observed_at"), "observed_at");
}

function computeAnswerSetSha256(entries: readonly string[]): Sha256Hex {
  const sorted = [...entries].sort();
  return hashCanonicalJson({ answers: sorted }, "answer_set").sha256;
}

function buildTerminalDecision(params: {
  readonly decision: Exclude<EgressDecisionStatus, "allowed">;
  readonly reasonCode: string;
  readonly target: NormalizedDestinationTarget;
  readonly addressPolicy: AddressPolicy;
  readonly cnameChain: readonly string[];
  readonly answerSetSha256: Sha256Hex;
  readonly observedInstant: Temporal.Instant;
  readonly observedMs: number;
}): EgressDecision {
  const ts = formatInstantUtc(params.observedInstant);
  return Object.freeze({
    decisionId: crypto.randomUUID(),
    decision: params.decision,
    reasonCode: params.reasonCode,
    networkPolicyVersion: params.addressPolicy.networkPolicyVersion,
    registryIpv4Sha256: params.addressPolicy.registryIpv4Sha256,
    registryIpv6Sha256: params.addressPolicy.registryIpv6Sha256,
    authoritySha256: params.target.authoritySha256,
    answerSetSha256: params.answerSetSha256,
    selectedAddress: null,
    selectedAddressSha256: null,
    selectedFamily: null,
    target: params.target,
    cnameChain: Object.freeze([...params.cnameChain]),
    observedAt: ts,
    expiresAt: ts,
    observedAtMs: params.observedMs,
    expiresAtMs: params.observedMs,
    ttlSeconds: 0,
    oneShot: true,
    cacheable: false
  });
}

async function runWithDnsDeadline<T>(
  fn: (
    trackPromise: <P>(promise: Promise<P>) => Promise<P>
  ) => Promise<T>,
  resolver: DnsResolverAdapter,
  timeoutMs: number,
  signal: AbortSignal | undefined
): Promise<T> {
  if (signal?.aborted) {
    resolver.cancel();
    const abortErr = new Error("Preflight aborted");
    (abortErr as { code?: string }).code = "EABORTED";
    throw abortErr;
  }

  const tracked: Array<Promise<unknown>> = [];
  const trackPromise = <P>(promise: Promise<P>): Promise<P> => {
    const guarded = promise.then(
      (v) => v,
      (e: unknown) => {
        throw e;
      }
    );
    guarded.catch(() => undefined);
    tracked.push(guarded);
    return promise;
  };

  let timer: ReturnType<typeof setTimeout> | null = null;
  let onAbort: (() => void) | null = null;

  const deadlinePromise = new Promise<never>((_resolve, reject) => {
    const cancelNow = (code: string, msg: string): void => {
      try {
        resolver.cancel();
      } catch {
        // Best-effort cancel
      }
      const err = new Error(msg);
      (err as { code?: string }).code = code;
      reject(err);
    };

    timer = setTimeout(() => {
      cancelNow("ETIMEOUT", `DNS resolution timed out after ${timeoutMs}ms`);
    }, Math.max(1, timeoutMs));
    timer.unref();

    if (signal !== undefined) {
      onAbort = () => {
        cancelNow("EABORTED", "DNS resolution aborted by preflight signal");
      };
      signal.addEventListener("abort", onAbort, { once: true });
    }
  });

  try {
    return await Promise.race([fn(trackPromise), deadlinePromise]);
  } finally {
    if (timer !== null) {
      clearTimeout(timer);
    }
    if (signal !== undefined && onAbort !== null) {
      signal.removeEventListener("abort", onAbort);
    }
    // Observe termination of in-flight resolver promises after cancel() before returning.
    if (tracked.length > 0) {
      const cleanupTimer = new Promise<void>((resolve) => {
        const t = setTimeout(resolve, 25);
        t.unref();
      });
      await Promise.race([Promise.allSettled(tracked), cleanupTimer]);
    }
  }
}

export async function resolveAndValidateEgress(
  options: ResolveEgressOptions
): Promise<EgressDecision> {
  const monotonicNowMs = options.monotonicNowMs ?? defaultMonotonicMs;
  const startMs = monotonicNowMs();
  const observedInstant = options.now ?? nowUtcInstant();

  const target =
    typeof options.target === "string"
      ? normalizeDestinationUrl(options.target, options.urlPolicyOptions)
      : options.target;

  const addressPolicy =
    options.addressPolicy ??
    createAddressPolicy({
      profile: options.urlPolicyOptions?.profile,
      egressConfig: options.urlPolicyOptions?.egressConfig
    });

  const emptyAnswerSha = computeAnswerSetSha256([]);

  if (target.isFixtureException) {
    const fixtureIp = options.urlPolicyOptions?.egressConfig?.fixture_resolve_ip ?? "127.0.0.1";
    const evalRes = addressPolicy.evaluateAddress(fixtureIp, {
      isFixtureTarget: true,
      hostname: target.normalizedHostname
    });
    if (!evalRes.allowed || evalRes.normalizedAddress === null || evalRes.family !== 4) {
      return buildTerminalDecision({
        decision: "denied",
        reasonCode: evalRes.reasonCode,
        target,
        addressPolicy,
        cnameChain: [],
        answerSetSha256: emptyAnswerSha,
        observedInstant,
        observedMs: startMs
      });
    }
    const answerSha = computeAnswerSetSha256([`4:${evalRes.normalizedAddress}`]);
    const expiresInstant = addMilliseconds(observedInstant, TTL_ZERO_DECISION_WINDOW_MS);
    return Object.freeze({
      decisionId: crypto.randomUUID(),
      decision: "allowed",
      reasonCode: "ALLOWED_FIXTURE",
      networkPolicyVersion: addressPolicy.networkPolicyVersion,
      registryIpv4Sha256: addressPolicy.registryIpv4Sha256,
      registryIpv6Sha256: addressPolicy.registryIpv6Sha256,
      authoritySha256: target.authoritySha256,
      answerSetSha256: answerSha,
      selectedAddress: evalRes.normalizedAddress,
      selectedAddressSha256: sha256Utf8Hex(evalRes.normalizedAddress),
      selectedFamily: 4,
      target,
      cnameChain: Object.freeze([]),
      observedAt: formatInstantUtc(observedInstant),
      expiresAt: formatInstantUtc(expiresInstant),
      observedAtMs: startMs,
      expiresAtMs: startMs + TTL_ZERO_DECISION_WINDOW_MS,
      ttlSeconds: 0,
      oneShot: true,
      cacheable: false
    });
  }

  const preflightBudgetMs = Math.min(
    DEFAULT_PREFLIGHT_BUDGET_MS,
    Math.max(1, options.preflightBudgetMs ?? DEFAULT_PREFLIGHT_BUDGET_MS)
  );
  const dnsTimeoutMs = Math.min(
    preflightBudgetMs,
    Math.max(1, options.dnsTimeoutMs ?? DEFAULT_DNS_TIMEOUT_MS)
  );

  // Per-attempt isolated resolver so cancelling one attempt cannot affect unrelated tenants.
  const resolver = (options.createDnsResolver ?? createNodeDnsResolverAdapter)();

  const cnameChain: string[] = [];
  const visitedHosts = new Set<string>([target.normalizedHostname]);
  let finalHostname = target.normalizedHostname;
  let cnameTtlsKnown = true;
  let minPositiveTtl = Number.POSITIVE_INFINITY;
  let v4Raw: readonly { readonly address: string; readonly ttl: number }[] = [];
  let v6Raw: readonly { readonly address: string; readonly ttl: number }[] = [];

  try {
    await runWithDnsDeadline(
      async (trackPromise) => {
        for (let hop = 0; hop <= MAX_CNAME_CHAIN_LINKS; hop += 1) {
          let cnameResult: readonly (string | DnsCnameRecord)[];
          try {
            cnameResult = await trackPromise(resolver.resolveCname(finalHostname));
          } catch (err) {
            if (isNoDataError(err)) {
              break;
            }
            const errCode = getErrorCode(err);
            if (errCode === "ECNAME_DEPTH") {
              const depthErr = new Error("CNAME depth exceeded");
              (depthErr as { code?: string }).code = "ECNAME_DEPTH";
              throw depthErr;
            }
            if (errCode === "ENOTFOUND" && hop === 0) {
              break;
            }
            throw err;
          }

          if (cnameResult.length !== 1) {
            const malformed = new Error("Invalid CNAME answer cardinality");
            (malformed as { code?: string }).code = "ECNAME_MALFORMED";
            throw malformed;
          }

          const rawEntry = cnameResult[0]!;
          const rawTarget = typeof rawEntry === "string" ? rawEntry : rawEntry.value;
          if (typeof rawEntry !== "string" && typeof rawEntry.ttl === "number") {
            if (rawEntry.ttl >= 0 && rawEntry.ttl < minPositiveTtl) {
              minPositiveTtl = rawEntry.ttl;
            }
          } else {
            cnameTtlsKnown = false;
          }

          const normalizedNext = rawTarget.replace(/\.$/, "").toLowerCase();
          try {
            assertValidPublicDnsHostname(
              normalizedNext,
              options.urlPolicyOptions?.blockedHostnames
            );
          } catch {
            const reservedErr = new Error("CNAME targets reserved or invalid hostname");
            (reservedErr as { code?: string }).code = "ECNAME_RESERVED";
            throw reservedErr;
          }

          if (visitedHosts.has(normalizedNext)) {
            const cycleErr = new Error("CNAME cycle detected");
            (cycleErr as { code?: string }).code = "ECNAME_CYCLE";
            throw cycleErr;
          }

          cnameChain.push(normalizedNext);
          if (cnameChain.length > MAX_CNAME_CHAIN_LINKS) {
            const depthErr = new Error("CNAME chain exceeded maximum 8 hops");
            (depthErr as { code?: string }).code = "ECNAME_DEPTH";
            throw depthErr;
          }
          visitedHosts.add(normalizedNext);
          finalHostname = normalizedNext;
        }

        const [res4, res6] = await Promise.all([
          trackPromise(resolver.resolve4(finalHostname)).catch((err: unknown) => {
            if (isNoDataError(err)) {
              return [] as const;
            }
            throw err;
          }),
          trackPromise(resolver.resolve6(finalHostname)).catch((err: unknown) => {
            if (isNoDataError(err)) {
              return [] as const;
            }
            throw err;
          })
        ]);

        v4Raw = res4;
        v6Raw = res6;
      },
      resolver,
      dnsTimeoutMs,
      options.signal
    );
  } catch (err) {
    const code = getErrorCode(err);
    const observedMs = monotonicNowMs();
    if (code === "ECNAME_DEPTH") {
      return buildTerminalDecision({
        decision: "denied",
        reasonCode: "EGRESS_CNAME_DEPTH_EXCEEDED",
        target,
        addressPolicy,
        cnameChain,
        answerSetSha256: emptyAnswerSha,
        observedInstant,
        observedMs
      });
    }
    if (code === "ECNAME_CYCLE") {
      return buildTerminalDecision({
        decision: "denied",
        reasonCode: "EGRESS_CNAME_CYCLE",
        target,
        addressPolicy,
        cnameChain,
        answerSetSha256: emptyAnswerSha,
        observedInstant,
        observedMs
      });
    }
    if (code === "ECNAME_RESERVED" || code === "ECNAME_MALFORMED") {
      return buildTerminalDecision({
        decision: "denied",
        reasonCode: "EGRESS_CNAME_RESERVED_TARGET",
        target,
        addressPolicy,
        cnameChain,
        answerSetSha256: emptyAnswerSha,
        observedInstant,
        observedMs
      });
    }
    const reasonCode =
      code === "ETIMEOUT"
        ? "DNS_TIMEOUT"
        : code === "EABORTED" || code === "ECANCELLED"
          ? "DNS_CANCELLED"
          : code === "ENOTFOUND"
            ? "DNS_NXDOMAIN"
            : "DNS_UNAVAILABLE";
    return buildTerminalDecision({
      decision: "unavailable",
      reasonCode,
      target,
      addressPolicy,
      cnameChain,
      answerSetSha256: emptyAnswerSha,
      observedInstant,
      observedMs
    });
  }

  const combined: DnsAddressRecord[] = [];
  for (const rec of v4Raw) {
    combined.push({ address: rec.address, family: 4, ttl: rec.ttl });
  }
  for (const rec of v6Raw) {
    combined.push({ address: rec.address, family: 6, ttl: rec.ttl });
  }

  const finishedMs = monotonicNowMs();
  if (combined.length === 0) {
    return buildTerminalDecision({
      decision: "unavailable",
      reasonCode: "DNS_NO_RECORDS",
      target,
      addressPolicy,
      cnameChain,
      answerSetSha256: emptyAnswerSha,
      observedInstant,
      observedMs: finishedMs
    });
  }

  const answerTokens = combined.map((rec) => `${rec.family}:${rec.address}`);
  const answerSetSha256 = computeAnswerSetSha256(answerTokens);

  if (combined.length > MAX_RESOLVED_ADDRESSES) {
    return buildTerminalDecision({
      decision: "denied",
      reasonCode: "EGRESS_ADDRESS_COUNT_EXCEEDED",
      target,
      addressPolicy,
      cnameChain,
      answerSetSha256,
      observedInstant,
      observedMs: finishedMs
    });
  }

  // Evaluate EVERY A/AAAA record; a single denied answer rejects the entire decision.
  const validatedCandidates: Array<{
    readonly address: string;
    readonly family: 4 | 6;
    readonly ttl: number;
  }> = [];

  for (const rec of combined) {
    const evalRes = addressPolicy.evaluateAddress(rec.address, {
      isFixtureTarget: false,
      hostname: finalHostname
    });
    if (!evalRes.allowed || evalRes.normalizedAddress === null || evalRes.family !== rec.family) {
      return buildTerminalDecision({
        decision: "denied",
        reasonCode:
          combined.length > 1 && validatedCandidates.length > 0
            ? "EGRESS_MIXED_ANSWER_DENIED"
            : evalRes.reasonCode,
        target,
        addressPolicy,
        cnameChain,
        answerSetSha256,
        observedInstant,
        observedMs: finishedMs
      });
    }
    validatedCandidates.push({
      address: evalRes.normalizedAddress,
      family: evalRes.family,
      ttl: rec.ttl
    });
    if (!Number.isFinite(rec.ttl) || rec.ttl < 0) {
      minPositiveTtl = 0;
    } else if (rec.ttl < minPositiveTtl) {
      minPositiveTtl = rec.ttl;
    }
  }

  const effectiveMinTtl = Number.isFinite(minPositiveTtl) ? Math.max(0, Math.floor(minPositiveTtl)) : 0;
  const oneShot = effectiveMinTtl === 0;
  const clampedTtlSeconds = oneShot ? 0 : Math.min(MAX_EGRESS_DECISION_TTL_SECONDS, effectiveMinTtl);
  const windowMs = oneShot ? TTL_ZERO_DECISION_WINDOW_MS : clampedTtlSeconds * 1_000;
  const cacheable = !oneShot && (cnameChain.length === 0 || cnameTtlsKnown);

  const ordinal = Math.max(0, Math.trunc(options.attemptOrdinal ?? 0));
  const selected = validatedCandidates[ordinal % validatedCandidates.length]!;
  const expiresInstant = addMilliseconds(observedInstant, windowMs);

  return Object.freeze({
    decisionId: crypto.randomUUID(),
    decision: "allowed",
    reasonCode: "ALLOWED",
    networkPolicyVersion: addressPolicy.networkPolicyVersion,
    registryIpv4Sha256: addressPolicy.registryIpv4Sha256,
    registryIpv6Sha256: addressPolicy.registryIpv6Sha256,
    authoritySha256: target.authoritySha256,
    answerSetSha256,
    selectedAddress: selected.address,
    selectedAddressSha256: sha256Utf8Hex(selected.address),
    selectedFamily: selected.family,
    target,
    cnameChain: Object.freeze([...cnameChain]),
    observedAt: formatInstantUtc(observedInstant),
    expiresAt: formatInstantUtc(expiresInstant),
    observedAtMs: finishedMs,
    expiresAtMs: finishedMs + windowMs,
    ttlSeconds: clampedTtlSeconds,
    oneShot,
    cacheable
  });
}

export function assertAllowedEgressDecision(
  decision: EgressDecision,
  nowMs: number = defaultMonotonicMs()
): void {
  if (decision.decision === "denied") {
    throw new AuthorizationDomainError({
      code: "EGRESS_POLICY_DENIED",
      message: `Egress decision denied (${decision.reasonCode})`
    });
  }
  if (decision.decision === "unavailable") {
    throw new DependencyUnavailableDomainError({
      code: "DEPENDENCY_UNAVAILABLE",
      message: `Egress resolution unavailable (${decision.reasonCode})`,
      retryable: true
    });
  }
  if (decision.decision === "expired" || nowMs >= decision.expiresAtMs) {
    throw new ExpiredDomainError({
      code: "EXPIRED",
      message: "Egress decision expired before send"
    });
  }
  if (decision.selectedAddress === null || decision.selectedFamily === null) {
    throw new AuthorizationDomainError({
      code: "EGRESS_POLICY_DENIED",
      message: "Egress decision has no validated destination address"
    });
  }
}
