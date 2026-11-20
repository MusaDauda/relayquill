import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import ipaddr from "ipaddr.js";
import {
  type CanonicalJsonValue,
  type Sha256Hex,
  hashCanonicalJson
} from "@relayquill/contracts";
import {
  DependencyUnavailableDomainError,
  ValidationDomainError
} from "@relayquill/domain";
import { type EgressConfig, type ProfileKind } from "@relayquill/runtime";
import {
  DEFAULT_FIXTURE_RECEIVER_HOST,
  assertEgressConfigValidForProfile,
  isFixtureExceptionEnabled,
  parseConfiguredFixtureTarget
} from "./url-policy.js";

export const NETWORK_POLICY_VERSION = "network_v1" as const;
export const PINNED_IANA_REGISTRY_ARTIFACT_SHA256 =
  "fd9df1c25dce10e4ed326d9216e15fb87c8b1967a2e76c6621d9dbbef89cd539" as const;

const REQUIRED_IPV4_FLOOR_CIDRS = Object.freeze([
  "0.0.0.0/8",
  "10.0.0.0/8",
  "100.64.0.0/10",
  "127.0.0.0/8",
  "168.63.129.16/32",
  "169.254.0.0/16",
  "172.16.0.0/12",
  "192.0.0.0/24",
  "192.0.2.0/24",
  "192.168.0.0/16",
  "198.18.0.0/15",
  "198.51.100.0/24",
  "203.0.113.0/24",
  "224.0.0.0/4",
  "240.0.0.0/4"
] as const);

const REQUIRED_IPV6_FLOOR_CIDRS = Object.freeze([
  "::/128",
  "::1/128",
  "::/96",
  "::ffff:0:0/96",
  "64:ff9b::/96",
  "64:ff9b:1::/48",
  "100::/64",
  "2001::/32",
  "2001:2::/48",
  "2001:db8::/32",
  "2002::/16",
  "fc00::/7",
  "fe80::/10",
  "ff00::/8"
] as const);

export interface RegistryCidrEntry {
  readonly cidr: string;
  readonly name: string;
  readonly rfc: string;
}

export interface ReviewedAddressRegistryArtifact {
  readonly schema_version: 1;
  readonly network_policy_version: string;
  readonly ipaddr_js_version: string;
  readonly retrieved_at: string;
  readonly sources: readonly string[];
  readonly ipv4_deny_cidrs: readonly RegistryCidrEntry[];
  readonly ipv6_allowed_global_unicast_cidr: string;
  readonly ipv6_deny_cidrs: readonly RegistryCidrEntry[];
}

export interface LoadedAddressRegistry {
  readonly artifact: ReviewedAddressRegistryArtifact;
  readonly artifactSha256: Sha256Hex;
  readonly registryIpv4Sha256: Sha256Hex;
  readonly registryIpv6Sha256: Sha256Hex;
  readonly ipv4DenyRules: ReadonlyArray<{
    readonly rawCidr: string;
    readonly parsed: [ipaddr.IPv4, number];
  }>;
  readonly ipv6GlobalUnicast: [ipaddr.IPv6, number];
  readonly ipv6DenyRules: ReadonlyArray<{
    readonly rawCidr: string;
    readonly parsed: [ipaddr.IPv6, number];
  }>;
}

export interface LoadAddressRegistryOptions {
  readonly artifactPath?: string | undefined;
  readonly expectedArtifactSha256?: string | null | undefined;
}

const DEFAULT_ARTIFACT_PATH = fileURLToPath(
  new URL("../artifacts/iana-special-purpose.v1.json", import.meta.url)
);

function failUnavailable(message: string): never {
  throw new DependencyUnavailableDomainError({
    code: "DEPENDENCY_UNAVAILABLE",
    message,
    retryable: false
  });
}

function isIPv4Addr(addr: ipaddr.IPv4 | ipaddr.IPv6): addr is ipaddr.IPv4 {
  return addr.kind() === "ipv4";
}

function assertValidCidrEntries(
  rawEntries: unknown,
  expectedKind: "ipv4" | "ipv6",
  label: string
): RegistryCidrEntry[] {
  if (!Array.isArray(rawEntries) || rawEntries.length === 0) {
    failUnavailable(`Address registry ${label} is missing or empty`);
  }
  const entries: RegistryCidrEntry[] = [];
  for (let i = 0; i < rawEntries.length; i += 1) {
    const item = rawEntries[i] as Record<string, unknown> | null;
    if (
      item === null ||
      typeof item !== "object" ||
      typeof item.cidr !== "string" ||
      typeof item.name !== "string" ||
      typeof item.rfc !== "string"
    ) {
      failUnavailable(`Malformed entry in address registry ${label}[${i}]`);
    }
    let parsed: [ipaddr.IPv4 | ipaddr.IPv6, number];
    try {
      parsed = ipaddr.parseCIDR(item.cidr);
    } catch {
      failUnavailable(`Invalid CIDR "${item.cidr}" in address registry ${label}[${i}]`);
    }
    if (parsed[0].kind() !== expectedKind) {
      failUnavailable(`Unexpected IP family for CIDR "${item.cidr}" in ${label}`);
    }
    entries.push({ cidr: item.cidr, name: item.name, rfc: item.rfc });
  }
  return entries;
}

export function loadReviewedAddressRegistry(
  options: LoadAddressRegistryOptions = {}
): LoadedAddressRegistry {
  const targetPath = path.resolve(options.artifactPath ?? DEFAULT_ARTIFACT_PATH);
  let rawText: string;
  try {
    rawText = fs.readFileSync(targetPath, "utf8");
  } catch {
    failUnavailable("Required reviewed address-policy artifact could not be read");
  }

  let rawJson: unknown;
  try {
    rawJson = JSON.parse(rawText);
  } catch {
    failUnavailable("Required reviewed address-policy artifact is invalid JSON");
  }

  if (typeof rawJson !== "object" || rawJson === null || Array.isArray(rawJson)) {
    failUnavailable("Required reviewed address-policy artifact must be a JSON object");
  }

  const obj = rawJson as Record<string, unknown>;
  if (
    obj.schema_version !== 1 ||
    typeof obj.network_policy_version !== "string" ||
    obj.network_policy_version.length === 0 ||
    typeof obj.ipaddr_js_version !== "string" ||
    typeof obj.retrieved_at !== "string" ||
    !Array.isArray(obj.sources) ||
    typeof obj.ipv6_allowed_global_unicast_cidr !== "string"
  ) {
    failUnavailable("Reviewed address-policy artifact failed schema validation");
  }

  const expectedHash =
    options.expectedArtifactSha256 === undefined
      ? PINNED_IANA_REGISTRY_ARTIFACT_SHA256
      : options.expectedArtifactSha256;
  const artifactSha256 = hashCanonicalJson(
    rawJson as CanonicalJsonValue,
    "address_registry_artifact"
  ).sha256;

  if (expectedHash !== null && artifactSha256 !== expectedHash) {
    failUnavailable(
      `Address-policy artifact SHA-256 mismatch (expected ${expectedHash}, observed ${artifactSha256})`
    );
  }

  const ipv4Entries = assertValidCidrEntries(obj.ipv4_deny_cidrs, "ipv4", "ipv4_deny_cidrs");
  const ipv6Entries = assertValidCidrEntries(obj.ipv6_deny_cidrs, "ipv6", "ipv6_deny_cidrs");

  const ipv4CidrSet = new Set(ipv4Entries.map((entry) => entry.cidr));
  for (const required of REQUIRED_IPV4_FLOOR_CIDRS) {
    if (!ipv4CidrSet.has(required)) {
      failUnavailable(`Address-policy artifact missing mandatory IPv4 floor prefix ${required}`);
    }
  }
  const ipv6CidrSet = new Set(ipv6Entries.map((entry) => entry.cidr));
  for (const required of REQUIRED_IPV6_FLOOR_CIDRS) {
    if (!ipv6CidrSet.has(required)) {
      failUnavailable(`Address-policy artifact missing mandatory IPv6 floor prefix ${required}`);
    }
  }

  let ipv6Global: [ipaddr.IPv6, number];
  try {
    const parsedGlobal = ipaddr.parseCIDR(obj.ipv6_allowed_global_unicast_cidr);
    if (parsedGlobal[0].kind() !== "ipv6" || obj.ipv6_allowed_global_unicast_cidr !== "2000::/3") {
      failUnavailable("Invalid IPv6 global unicast CIDR policy");
    }
    ipv6Global = parsedGlobal as [ipaddr.IPv6, number];
  } catch {
    failUnavailable("Invalid IPv6 global unicast CIDR syntax");
  }

  const ipv4DenyRules = ipv4Entries.map((entry) => ({
    rawCidr: entry.cidr,
    parsed: ipaddr.IPv4.parseCIDR(entry.cidr)
  }));
  const ipv6DenyRules = ipv6Entries.map((entry) => ({
    rawCidr: entry.cidr,
    parsed: ipaddr.IPv6.parseCIDR(entry.cidr)
  }));

  const registryIpv4Sha256 = hashCanonicalJson(
    {
      network_policy_version: obj.network_policy_version,
      cidrs: ipv4Entries.map((e) => e.cidr).sort()
    },
    "registry_ipv4"
  ).sha256;

  const registryIpv6Sha256 = hashCanonicalJson(
    {
      network_policy_version: obj.network_policy_version,
      allowed_global_unicast: obj.ipv6_allowed_global_unicast_cidr,
      cidrs: ipv6Entries.map((e) => e.cidr).sort()
    },
    "registry_ipv6"
  ).sha256;

  const artifact: ReviewedAddressRegistryArtifact = Object.freeze({
    schema_version: 1,
    network_policy_version: obj.network_policy_version,
    ipaddr_js_version: obj.ipaddr_js_version,
    retrieved_at: obj.retrieved_at,
    sources: Object.freeze([...(obj.sources as string[])]),
    ipv4_deny_cidrs: Object.freeze(ipv4Entries.map((e) => Object.freeze(e))),
    ipv6_allowed_global_unicast_cidr: obj.ipv6_allowed_global_unicast_cidr,
    ipv6_deny_cidrs: Object.freeze(ipv6Entries.map((e) => Object.freeze(e)))
  });

  return Object.freeze({
    artifact,
    artifactSha256,
    registryIpv4Sha256,
    registryIpv6Sha256,
    ipv4DenyRules: Object.freeze(ipv4DenyRules),
    ipv6GlobalUnicast: ipv6Global,
    ipv6DenyRules: Object.freeze(ipv6DenyRules)
  });
}

export interface AddressEvaluationResult {
  readonly allowed: boolean;
  readonly family: 4 | 6 | null;
  readonly normalizedAddress: string | null;
  readonly reasonCode: string;
  readonly matchedCidr?: string | undefined;
}

export interface AddressPolicyOptions {
  readonly profile?: ProfileKind | undefined;
  readonly egressConfig?: EgressConfig | undefined;
  readonly deploymentDenyCidrs?: readonly string[] | undefined;
  readonly registry?: LoadedAddressRegistry | undefined;
  readonly registryOptions?: LoadAddressRegistryOptions | undefined;
}

export class AddressPolicy {
  readonly registry: LoadedAddressRegistry;
  readonly networkPolicyVersion: string;
  readonly registryIpv4Sha256: Sha256Hex;
  readonly registryIpv6Sha256: Sha256Hex;
  readonly #profile: ProfileKind | undefined;
  readonly #egressConfig: EgressConfig | undefined;
  readonly #allowFixture: boolean;
  readonly #fixtureResolveIp: "127.0.0.1" | undefined;
  readonly #fixtureHost: string | undefined;
  readonly #deploymentIpv4Deny: ReadonlyArray<{
    readonly rawCidr: string;
    readonly parsed: [ipaddr.IPv4, number];
  }>;
  readonly #deploymentIpv6Deny: ReadonlyArray<{
    readonly rawCidr: string;
    readonly parsed: [ipaddr.IPv6, number];
  }>;

  constructor(options: AddressPolicyOptions = {}) {
    assertEgressConfigValidForProfile(options.profile, options.egressConfig);
    this.#profile = options.profile;
    this.#egressConfig = options.egressConfig;
    this.#allowFixture = isFixtureExceptionEnabled({
      profile: options.profile,
      egressConfig: options.egressConfig
    });
    const rawFixtureIp: unknown = options.egressConfig?.fixture_resolve_ip;
    if (rawFixtureIp !== undefined && rawFixtureIp !== "127.0.0.1") {
      throw new ValidationDomainError({
        code: "INVALID_VALUE",
        message: 'Trusted fixture exception only permits resolve IP "127.0.0.1"'
      });
    }
    this.#fixtureResolveIp = this.#allowFixture ? "127.0.0.1" : undefined;
    this.#fixtureHost = this.#allowFixture
      ? parseConfiguredFixtureTarget(options.egressConfig)?.host
      : undefined;

    this.registry = options.registry ?? loadReviewedAddressRegistry(options.registryOptions);
    this.networkPolicyVersion = this.registry.artifact.network_policy_version;
    this.registryIpv4Sha256 = this.registry.registryIpv4Sha256;
    this.registryIpv6Sha256 = this.registry.registryIpv6Sha256;

    const depV4: Array<{ readonly rawCidr: string; readonly parsed: [ipaddr.IPv4, number] }> = [];
    const depV6: Array<{ readonly rawCidr: string; readonly parsed: [ipaddr.IPv6, number] }> = [];
    for (const cidr of options.deploymentDenyCidrs ?? []) {
      let parsed: [ipaddr.IPv4 | ipaddr.IPv6, number];
      try {
        parsed = ipaddr.parseCIDR(cidr);
      } catch {
        throw new ValidationDomainError({
          code: "INVALID_VALUE",
          message: `Invalid deployment deny CIDR "${cidr}"`
        });
      }
      if (parsed[0].kind() === "ipv4") {
        depV4.push({ rawCidr: cidr, parsed: parsed as [ipaddr.IPv4, number] });
      } else {
        depV6.push({ rawCidr: cidr, parsed: parsed as [ipaddr.IPv6, number] });
      }
    }
    this.#deploymentIpv4Deny = Object.freeze(depV4);
    this.#deploymentIpv6Deny = Object.freeze(depV6);
  }

  evaluateAddress(
    rawIp: unknown,
    context: { readonly isFixtureTarget?: boolean | undefined; readonly hostname?: string | undefined } = {}
  ): AddressEvaluationResult {
    if (typeof rawIp !== "string" || rawIp.length === 0 || /\s/.test(rawIp) || rawIp.includes("%")) {
      return Object.freeze({
        allowed: false,
        family: null,
        normalizedAddress: null,
        reasonCode: "EGRESS_INVALID_IP_SYNTAX"
      });
    }

    // Never call ipaddr.process(): mapped IPv6 addresses must never be converted to allowed IPv4.
    let parsed: ipaddr.IPv4 | ipaddr.IPv6;
    try {
      parsed = ipaddr.parse(rawIp);
    } catch {
      return Object.freeze({
        allowed: false,
        family: null,
        normalizedAddress: null,
        reasonCode: "EGRESS_INVALID_IP_SYNTAX"
      });
    }

    if (isIPv4Addr(parsed)) {
      if (!ipaddr.IPv4.isValidFourPartDecimal(rawIp)) {
        return Object.freeze({
          allowed: false,
          family: 4,
          normalizedAddress: null,
          reasonCode: "EGRESS_NON_CANONICAL_IPV4"
        });
      }
      const normalized = parsed.toNormalizedString();

      if (
        context.isFixtureTarget === true &&
        this.#allowFixture &&
        this.#fixtureHost === DEFAULT_FIXTURE_RECEIVER_HOST &&
        context.hostname === DEFAULT_FIXTURE_RECEIVER_HOST &&
        normalized === this.#fixtureResolveIp &&
        !this.#isProduction()
      ) {
        return Object.freeze({
          allowed: true,
          family: 4,
          normalizedAddress: normalized,
          reasonCode: "ALLOWED_FIXTURE"
        });
      }

      for (const rule of this.registry.ipv4DenyRules) {
        if (parsed.match(rule.parsed)) {
          return Object.freeze({
            allowed: false,
            family: 4,
            normalizedAddress: null,
            reasonCode: "EGRESS_CIDR_DENIED",
            matchedCidr: rule.rawCidr
          });
        }
      }
      for (const rule of this.#deploymentIpv4Deny) {
        if (parsed.match(rule.parsed)) {
          return Object.freeze({
            allowed: false,
            family: 4,
            normalizedAddress: null,
            reasonCode: "EGRESS_DEPLOYMENT_CIDR_DENIED",
            matchedCidr: rule.rawCidr
          });
        }
      }

      return Object.freeze({
        allowed: true,
        family: 4,
        normalizedAddress: normalized,
        reasonCode: "ALLOWED"
      });
    }

    const v6: ipaddr.IPv6 = parsed;
    if (v6.zoneId !== undefined) {
      return Object.freeze({
        allowed: false,
        family: 6,
        normalizedAddress: null,
        reasonCode: "EGRESS_ZONE_ID_DENIED"
      });
    }

    if (v6.isIPv4MappedAddress()) {
      return Object.freeze({
        allowed: false,
        family: 6,
        normalizedAddress: null,
        reasonCode: "EGRESS_IPV4_MAPPED_DENIED",
        matchedCidr: "::ffff:0:0/96"
      });
    }

    for (const rule of this.registry.ipv6DenyRules) {
      if (v6.match(rule.parsed)) {
        return Object.freeze({
          allowed: false,
          family: 6,
          normalizedAddress: null,
          reasonCode: "EGRESS_CIDR_DENIED",
          matchedCidr: rule.rawCidr
        });
      }
    }

    if (!v6.match(this.registry.ipv6GlobalUnicast)) {
      return Object.freeze({
        allowed: false,
        family: 6,
        normalizedAddress: null,
        reasonCode: "EGRESS_NON_GLOBAL_IPV6_DENIED"
      });
    }

    for (const rule of this.#deploymentIpv6Deny) {
      if (v6.match(rule.parsed)) {
        return Object.freeze({
          allowed: false,
          family: 6,
          normalizedAddress: null,
          reasonCode: "EGRESS_DEPLOYMENT_CIDR_DENIED",
          matchedCidr: rule.rawCidr
        });
      }
    }

    return Object.freeze({
      allowed: true,
      family: 6,
      normalizedAddress: v6.toNormalizedString(),
      reasonCode: "ALLOWED"
    });
  }

  #isProduction(): boolean {
    if (this.#profile === "release" || this.#profile === "self_hosted") {
      return true;
    }
    if (this.#egressConfig?.mode === "strict_public_https") {
      return !this.#allowFixture;
    }
    return false;
  }
}

export function createAddressPolicy(options: AddressPolicyOptions = {}): AddressPolicy {
  return new AddressPolicy(options);
}

export function normalizeConnectedPeerAddress(
  peerRemoteAddress: unknown,
  selectedFamily: 4 | 6
): string | null {
  if (typeof peerRemoteAddress !== "string" || peerRemoteAddress.length === 0 || peerRemoteAddress.includes("%")) {
    return null;
  }
  let parsed: ipaddr.IPv4 | ipaddr.IPv6;
  try {
    parsed = ipaddr.parse(peerRemoteAddress);
  } catch {
    return null;
  }
  if (selectedFamily === 4) {
    if (isIPv4Addr(parsed)) {
      return parsed.toNormalizedString();
    }
    // OS dual-stack sockets may report an IPv4 peer as ::ffff:a.b.c.d.
    if (parsed.isIPv4MappedAddress()) {
      return parsed.toIPv4Address().toNormalizedString();
    }
    return null;
  }
  if (isIPv4Addr(parsed) || parsed.isIPv4MappedAddress() || parsed.zoneId !== undefined) {
    return null;
  }
  return parsed.toNormalizedString();
}

export function peerAddressMatchesSelected(
  peerRemoteAddress: unknown,
  selectedAddress: string,
  selectedFamily: 4 | 6
): boolean {
  const normalizedPeer = normalizeConnectedPeerAddress(peerRemoteAddress, selectedFamily);
  if (normalizedPeer === null) {
    return false;
  }
  let selectedParsed: ipaddr.IPv4 | ipaddr.IPv6;
  try {
    selectedParsed = ipaddr.parse(selectedAddress);
  } catch {
    return false;
  }
  if (selectedFamily === 4 && !isIPv4Addr(selectedParsed)) {
    return false;
  }
  if (selectedFamily === 6 && (isIPv4Addr(selectedParsed) || selectedParsed.isIPv4MappedAddress())) {
    return false;
  }
  return normalizedPeer === selectedParsed.toNormalizedString();
}
