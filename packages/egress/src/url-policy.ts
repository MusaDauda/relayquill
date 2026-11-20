import net from "node:net";
import {
  type Sha256Hex,
  hashCanonicalJson,
  sha256Utf8Hex
} from "@relayquill/contracts";
import {
  AuthorizationDomainError,
  ValidationDomainError,
  hasLoneSurrogate
} from "@relayquill/domain";
import {
  type EgressConfig,
  type ProfileKind,
  isProductionProfile
} from "@relayquill/runtime";

export const URL_POLICY_VERSION = "url_v1" as const;
export const MAX_URL_UTF8_BYTES = 2048 as const;
export const MAX_REQUEST_TARGET_ASCII_BYTES = 1024 as const;
export const DEFAULT_FIXTURE_RECEIVER_HOST = "receiver.fixture.test" as const;
export const DEFAULT_FIXTURE_RECEIVER_PORT = 19095 as const;
export const DEFAULT_FIXTURE_RECEIVER_AUTHORITY = "receiver.fixture.test:19095" as const;
export const DEFAULT_FIXTURE_RECEIVER_PATH = "/hooks/relayquill" as const;

export interface ConfiguredFixtureTarget {
  readonly host: string;
  readonly port: number;
  readonly authority: string;
  readonly path: string;
}

export function parseConfiguredFixtureTarget(
  egressConfig: EgressConfig | undefined
): ConfiguredFixtureTarget | null {
  const configuredAuthority = (
    egressConfig?.fixture_receiver_authority ?? DEFAULT_FIXTURE_RECEIVER_AUTHORITY
  ).toLowerCase();
  const configuredPath =
    egressConfig?.fixture_receiver_path ?? DEFAULT_FIXTURE_RECEIVER_PATH;
  const configuredColon = configuredAuthority.lastIndexOf(":");
  const host =
    configuredColon >= 0 ? configuredAuthority.slice(0, configuredColon) : configuredAuthority;
  if (host.length === 0) {
    return null;
  }
  const rawPort = configuredColon >= 0 ? configuredAuthority.slice(configuredColon + 1) : undefined;
  let port: number = DEFAULT_FIXTURE_RECEIVER_PORT;
  if (rawPort !== undefined) {
    if (!/^[0-9]+$/.test(rawPort)) {
      return null;
    }
    port = Number.parseInt(rawPort, 10);
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      return null;
    }
  }
  return Object.freeze({
    host,
    port,
    authority: `${host}:${port}`,
    path: configuredPath
  });
}

export const RESERVED_HOST_SUFFIXES = Object.freeze([
  ".localhost",
  ".local",
  ".internal",
  ".home.arpa",
  ".test",
  ".invalid",
  ".example",
  ".localdomain"
] as const);

const DNS_LABEL_REGEX = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const ALL_NUMERIC_REGEX = /^[0-9]+$/;
const PORT_DIGITS_REGEX = /^[1-9][0-9]{0,4}$/;
const UNRESERVED_ASCII_BYTE = (code: number): boolean =>
  (code >= 0x41 && code <= 0x5a) || // A-Z
  (code >= 0x61 && code <= 0x7a) || // a-z
  (code >= 0x30 && code <= 0x39) || // 0-9
  code === 0x2d || // -
  code === 0x2e || // .
  code === 0x5f || // _
  code === 0x7e; // ~

export interface UrlPolicyOptions {
  readonly profile?: ProfileKind | undefined;
  readonly egressConfig?: EgressConfig | undefined;
  readonly blockedHostnames?: readonly string[] | undefined;
}

export interface NormalizedDestinationTarget {
  readonly urlPolicyVersion: typeof URL_POLICY_VERSION;
  readonly scheme: "https" | "http";
  readonly canonicalUrl: string;
  readonly normalizedHostname: string;
  readonly port: number;
  readonly externalAuthority: string;
  readonly requestTarget: string;
  readonly authoritySha256: Sha256Hex;
  readonly pathAndQuerySha256: Sha256Hex;
  readonly configurationSha256: Sha256Hex;
  readonly isFixtureException: boolean;
}

function rejectUrl(
  reasonCode: string,
  message: string,
  kind: "policy" | "validation" = "policy"
): never {
  if (kind === "policy") {
    throw new AuthorizationDomainError({
      code: "EGRESS_POLICY_DENIED",
      message,
      fieldErrors: [{ path: "destination_url", code: reasonCode }]
    });
  }
  throw new ValidationDomainError({
    code: "INVALID_VALUE",
    message,
    fieldErrors: [{ path: "destination_url", code: reasonCode }]
  });
}

export function assertEgressConfigValidForProfile(
  profile: ProfileKind | undefined,
  egressConfig: EgressConfig | undefined
): void {
  if (profile !== undefined && isProductionProfile(profile) && egressConfig !== undefined) {
    if (
      egressConfig.mode !== "strict_public_https" ||
      egressConfig.allow_fixture_receiver ||
      (egressConfig.fixture_receiver_authority !== undefined &&
        egressConfig.fixture_receiver_authority.toLowerCase().includes("fixture.test"))
    ) {
      rejectUrl(
        "FIXTURE_FORBIDDEN_IN_PRODUCTION",
        `Trusted local fixture egress exception is forbidden in profile "${profile}"`
      );
    }
  }
  const rawFixtureIp: unknown = egressConfig?.fixture_resolve_ip;
  if (rawFixtureIp !== undefined && rawFixtureIp !== "127.0.0.1") {
    rejectUrl(
      "FIXTURE_IP_FORBIDDEN",
      'Trusted local fixture egress exception only permits resolve IP "127.0.0.1"'
    );
  }
}

export function isFixtureExceptionEnabled(options: UrlPolicyOptions = {}): boolean {
  assertEgressConfigValidForProfile(options.profile, options.egressConfig);
  if (options.profile !== undefined && isProductionProfile(options.profile)) {
    return false;
  }
  return (
    options.egressConfig?.mode === "trusted_local_fixture" &&
    options.egressConfig.allow_fixture_receiver === true
  );
}

export function isReservedOrSpecialHostname(hostname: string): boolean {
  const lower = hostname.toLowerCase();
  if (lower === "localhost" || lower.endsWith(".")) {
    return true;
  }
  for (const suffix of RESERVED_HOST_SUFFIXES) {
    if (lower === suffix.slice(1) || lower.endsWith(suffix)) {
      return true;
    }
  }
  return false;
}

export function assertValidPublicDnsHostname(
  hostname: string,
  blockedHostnames: readonly string[] = []
): string {
  if (typeof hostname !== "string" || hostname.length === 0 || hostname.length > 253) {
    rejectUrl("INVALID_HOSTNAME", "Destination hostname length is out of bounds", "validation");
  }
  if (hostname.endsWith(".")) {
    rejectUrl("TRAILING_DOT_HOSTNAME", "Trailing dot in destination hostname is forbidden", "policy");
  }
  if (hostname.startsWith("[") || hostname.endsWith("]") || net.isIP(hostname) !== 0) {
    rejectUrl("IP_LITERAL_FORBIDDEN", "IP literal destination hosts are forbidden", "policy");
  }

  const lower = hostname.toLowerCase();
  const labels = lower.split(".");
  if (labels.length < 2) {
    rejectUrl(
      "UNQUALIFIED_HOSTNAME",
      "Single-label unqualified destination hostnames are forbidden",
      "policy"
    );
  }
  for (const label of labels) {
    if (!DNS_LABEL_REGEX.test(label)) {
      rejectUrl("INVALID_DNS_LABEL", `Invalid DNS label in hostname "${lower}"`, "validation");
    }
  }
  const tld = labels[labels.length - 1]!;
  if (ALL_NUMERIC_REGEX.test(tld)) {
    rejectUrl("NUMERIC_HOST_FORBIDDEN", "Numeric top-level host labels are forbidden", "policy");
  }

  if (isReservedOrSpecialHostname(lower)) {
    rejectUrl(
      "RESERVED_HOSTNAME",
      `Reserved local/internal/test hostname "${lower}" is forbidden`,
      "policy"
    );
  }

  for (const rawBlocked of blockedHostnames) {
    const blocked = rawBlocked.trim().toLowerCase().replace(/\.$/, "");
    if (blocked.length > 0 && (lower === blocked || lower.endsWith(`.${blocked}`))) {
      rejectUrl(
        "CONTROL_PLANE_HOSTNAME",
        `Destination hostname "${lower}" targets a protected control/management domain`,
        "policy"
      );
    }
  }

  return lower;
}

function parseHexByte(twoHexChars: string): number {
  if (!/^[0-9A-Fa-f]{2}$/.test(twoHexChars)) {
    rejectUrl("INVALID_PERCENT_ESCAPE", "Invalid percent escape sequence in path", "validation");
  }
  return Number.parseInt(twoHexChars, 16);
}

function checkRawPathBeforeNormalization(rawPath: string): void {
  if (rawPath.includes("?") || rawPath.includes("#") || rawPath.includes("\\")) {
    rejectUrl(
      "FORBIDDEN_PATH_CHARACTER",
      "Request target must not contain query, fragment, or backslash",
      "policy"
    );
  }
  if (rawPath.includes("//")) {
    rejectUrl(
      "REPEATED_SLASH_SEGMENT",
      "Repeated slash segments in destination path are forbidden",
      "policy"
    );
  }

  // Inspect raw escapes before WHATWG URL normalization collapses dot segments.
  for (let i = 0; i < rawPath.length; i += 1) {
    if (rawPath.charCodeAt(i) === 0x25) {
      if (i + 2 >= rawPath.length) {
        rejectUrl("TRUNCATED_PERCENT_ESCAPE", "Truncated percent escape in path", "validation");
      }
      const byteVal = parseHexByte(rawPath.slice(i + 1, i + 3));
      if (byteVal === 0x25) {
        rejectUrl("DOUBLE_ENCODING_FORBIDDEN", "Double-encoding marker %25 is forbidden", "policy");
      }
      if (byteVal === 0x2f || byteVal === 0x5c) {
        rejectUrl(
          "ENCODED_SEPARATOR_FORBIDDEN",
          "Percent-encoded path separator is forbidden",
          "policy"
        );
      }
      if (byteVal < 0x20 || byteVal === 0x7f) {
        rejectUrl(
          "ENCODED_CONTROL_FORBIDDEN",
          "Percent-encoded control character in path is forbidden",
          "policy"
        );
      }
      i += 2;
    }
  }

  if (rawPath.length > 1) {
    const segments = rawPath.slice(1).split("/");
    for (const seg of segments) {
      let decodedAsciiSeg = "";
      for (let i = 0; i < seg.length; i += 1) {
        if (seg.charCodeAt(i) === 0x25) {
          const byteVal = parseHexByte(seg.slice(i + 1, i + 3));
          decodedAsciiSeg += byteVal <= 0x7f ? String.fromCharCode(byteVal) : `\u0080`;
          i += 2;
        } else {
          decodedAsciiSeg += seg[i]!;
        }
      }
      if (seg === "." || seg === ".." || decodedAsciiSeg === "." || decodedAsciiSeg === "..") {
        rejectUrl("DOT_SEGMENT_FORBIDDEN", "Dot path segments (. or ..) are forbidden", "policy");
      }
    }
  }
}

export function normalizeRequestTargetFromUrlPathname(rawPath: string, parsedPathname: string): string {
  checkRawPathBeforeNormalization(rawPath);

  const candidate = parsedPathname.length === 0 ? "/" : parsedPathname;
  if (!candidate.startsWith("/") || candidate.includes("//")) {
    rejectUrl("INVALID_REQUEST_TARGET", "Normalized request target must be a single-slash path", "policy");
  }

  let normalized = "";
  for (let i = 0; i < candidate.length; i += 1) {
    const ch = candidate[i]!;
    if (ch === "%") {
      if (i + 2 >= candidate.length) {
        rejectUrl("TRUNCATED_PERCENT_ESCAPE", "Truncated percent escape in normalized path", "validation");
      }
      const hex = candidate.slice(i + 1, i + 3);
      const byteVal = parseHexByte(hex);
      if (byteVal === 0x25 || byteVal === 0x2f || byteVal === 0x5c || byteVal < 0x20 || byteVal === 0x7f) {
        rejectUrl("FORBIDDEN_PERCENT_ESCAPE", "Forbidden percent escape in normalized path", "policy");
      }
      if (UNRESERVED_ASCII_BYTE(byteVal)) {
        normalized += String.fromCharCode(byteVal);
      } else {
        normalized += `%${hex.toUpperCase()}`;
      }
      i += 2;
    } else {
      const code = ch.charCodeAt(0);
      if (code <= 0x20 || code >= 0x7f) {
        rejectUrl("NON_ASCII_NORMALIZED_PATH", "Normalized path must contain printable ASCII", "validation");
      }
      normalized += ch;
    }
  }

  if (normalized.includes("//")) {
    rejectUrl("REPEATED_SLASH_SEGMENT", "Normalized path contains repeated slashes", "policy");
  }
  for (const seg of normalized.slice(1).split("/")) {
    if (seg === "." || seg === "..") {
      rejectUrl("DOT_SEGMENT_FORBIDDEN", "Normalized path contains dot segments", "policy");
    }
  }
  if (normalized.length > MAX_REQUEST_TARGET_ASCII_BYTES) {
    rejectUrl(
      "REQUEST_TARGET_TOO_LONG",
      `Normalized request target exceeds ${MAX_REQUEST_TARGET_ASCII_BYTES} ASCII bytes`,
      "validation"
    );
  }

  return normalized;
}

export function normalizeDestinationUrl(
  rawUrl: unknown,
  options: UrlPolicyOptions = {}
): NormalizedDestinationTarget {
  const allowFixture = isFixtureExceptionEnabled(options);

  if (typeof rawUrl !== "string" || rawUrl.length === 0 || hasLoneSurrogate(rawUrl)) {
    rejectUrl("INVALID_URL_STRING", "Destination URL must be a non-empty valid UTF-8 string", "validation");
  }

  const utf8ByteLength = Buffer.byteLength(rawUrl, "utf8");
  if (utf8ByteLength > MAX_URL_UTF8_BYTES) {
    rejectUrl(
      "URL_TOO_LONG",
      `Destination URL (${utf8ByteLength} bytes) exceeds ${MAX_URL_UTF8_BYTES} bytes`,
      "validation"
    );
  }

  for (let i = 0; i < rawUrl.length; i += 1) {
    const code = rawUrl.charCodeAt(i);
    if (code <= 0x20 || code === 0x7f || code === 0x5c) {
      rejectUrl(
        "FORBIDDEN_URL_CHARACTER",
        "Destination URL must not contain whitespace, control characters, or backslashes",
        "policy"
      );
    }
  }
  if (/\s/.test(rawUrl)) {
    rejectUrl("FORBIDDEN_URL_WHITESPACE", "Destination URL must not contain whitespace", "policy");
  }
  if (rawUrl.includes("?") || rawUrl.includes("#")) {
    rejectUrl("QUERY_OR_FRAGMENT_FORBIDDEN", "Destination URL must not contain query or fragment", "policy");
  }

  const isHttpsPrefix = rawUrl.startsWith("https://");
  const isHttpPrefix = rawUrl.startsWith("http://");
  if (!isHttpsPrefix && !(allowFixture && isHttpPrefix)) {
    rejectUrl(
      "UNSUPPORTED_SCHEME",
      "Destination URL must use explicit https:// authority form",
      "policy"
    );
  }

  const schemeLen = isHttpsPrefix ? "https://".length : "http://".length;
  const slashIdx = rawUrl.indexOf("/", schemeLen);
  const rawAuthority = slashIdx === -1 ? rawUrl.slice(schemeLen) : rawUrl.slice(schemeLen, slashIdx);
  const rawPath = slashIdx === -1 ? "" : rawUrl.slice(slashIdx);

  if (rawAuthority.length === 0) {
    rejectUrl("EMPTY_AUTHORITY", "Destination URL authority is empty", "validation");
  }
  if (rawAuthority.includes("@")) {
    rejectUrl("USERINFO_FORBIDDEN", "Destination URL userinfo (@) is forbidden", "policy");
  }

  let parsed: URL;
  try {
    parsed = new URL(rawUrl);
  } catch {
    rejectUrl("MALFORMED_URL", "Destination URL failed WHATWG URL parsing", "validation");
  }

  if (parsed.username !== "" || parsed.password !== "") {
    rejectUrl("USERINFO_FORBIDDEN", "Destination URL userinfo is forbidden", "policy");
  }
  if (parsed.search !== "" || parsed.hash !== "") {
    rejectUrl("QUERY_OR_FRAGMENT_FORBIDDEN", "Destination URL query or fragment is forbidden", "policy");
  }

  const colonIdx = rawAuthority.indexOf(":");
  if (rawAuthority.includes("[") || rawAuthority.includes("]")) {
    rejectUrl("IP_LITERAL_FORBIDDEN", "IPv6 literal destination hosts are forbidden", "policy");
  }
  if (colonIdx !== -1 && rawAuthority.lastIndexOf(":") !== colonIdx) {
    rejectUrl("MALFORMED_AUTHORITY_PORT", "Malformed authority port delimiter", "validation");
  }

  let rawHost = rawAuthority;
  let explicitPort: number | null = null;
  if (colonIdx !== -1) {
    rawHost = rawAuthority.slice(0, colonIdx);
    const rawPort = rawAuthority.slice(colonIdx + 1);
    if (!PORT_DIGITS_REGEX.test(rawPort)) {
      rejectUrl("INVALID_PORT", "Destination URL port must be canonical decimal digits", "policy");
    }
    const portNum = Number.parseInt(rawPort, 10);
    if (portNum < 1 || portNum > 65535) {
      rejectUrl("INVALID_PORT", "Destination URL port out of range", "policy");
    }
    explicitPort = portNum;
  }

  if (rawHost.endsWith(".")) {
    rejectUrl("TRAILING_DOT_HOSTNAME", "Trailing dot in destination hostname is forbidden", "policy");
  }

  const requestTarget = normalizeRequestTargetFromUrlPathname(rawPath, parsed.pathname);

  if (allowFixture) {
    const configuredFixture = parseConfiguredFixtureTarget(options.egressConfig);
    const normalizedParsedHost = parsed.hostname.toLowerCase();
    if (
      normalizedParsedHost === DEFAULT_FIXTURE_RECEIVER_HOST ||
      (parsed.protocol === "http:" &&
        configuredFixture !== null &&
        normalizedParsedHost === configuredFixture.host)
    ) {
      if (configuredFixture === null) {
        rejectUrl(
          "FIXTURE_TARGET_MISMATCH",
          "Configured local fixture authority is invalid"
        );
      }
      if (
        normalizedParsedHost !== DEFAULT_FIXTURE_RECEIVER_HOST ||
        normalizedParsedHost !== configuredFixture.host
      ) {
        rejectUrl(
          "FIXTURE_HOST_MISMATCH",
          `Trusted fixture exception only permits "${DEFAULT_FIXTURE_RECEIVER_HOST}" matching configured fixture authority`
        );
      }
      const effectivePort = explicitPort ?? (parsed.protocol === "https:" ? 443 : 80);
      if (effectivePort !== configuredFixture.port || requestTarget !== configuredFixture.path) {
        rejectUrl(
          "FIXTURE_TARGET_MISMATCH",
          "Destination does not match configured local fixture authority and path"
        );
      }
      const externalAuthority = `${normalizedParsedHost}:${configuredFixture.port}`;
      const scheme = parsed.protocol === "https:" ? "https" : "http";
      const canonicalUrl = `${scheme}://${externalAuthority}${requestTarget}`;
      const authoritySha256 = sha256Utf8Hex(externalAuthority);
      const pathAndQuerySha256 = sha256Utf8Hex(requestTarget);
      const configurationSha256 = hashCanonicalJson({
        url_policy_version: URL_POLICY_VERSION,
        scheme,
        external_authority: externalAuthority,
        request_target: requestTarget
      }).sha256;

      return Object.freeze({
        urlPolicyVersion: URL_POLICY_VERSION,
        scheme,
        canonicalUrl,
        normalizedHostname: normalizedParsedHost,
        port: configuredFixture.port,
        externalAuthority,
        requestTarget,
        authoritySha256,
        pathAndQuerySha256,
        configurationSha256,
        isFixtureException: true
      });
    }
  }

  if (parsed.protocol !== "https:") {
    rejectUrl("HTTPS_REQUIRED", "Release destination URLs require https://", "policy");
  }
  if (explicitPort !== null && explicitPort !== 443) {
    rejectUrl("NON_443_PORT_FORBIDDEN", "Release HTTPS destinations only permit port 443", "policy");
  }

  const normalizedHostname = assertValidPublicDnsHostname(
    parsed.hostname,
    options.blockedHostnames
  );
  const externalAuthority = `${normalizedHostname}:443`;
  const canonicalUrl = `https://${normalizedHostname}${requestTarget}`;
  const authoritySha256 = sha256Utf8Hex(externalAuthority);
  const pathAndQuerySha256 = sha256Utf8Hex(requestTarget);
  const configurationSha256 = hashCanonicalJson({
    url_policy_version: URL_POLICY_VERSION,
    scheme: "https",
    external_authority: externalAuthority,
    request_target: requestTarget
  }).sha256;

  return Object.freeze({
    urlPolicyVersion: URL_POLICY_VERSION,
    scheme: "https",
    canonicalUrl,
    normalizedHostname,
    port: 443,
    externalAuthority,
    requestTarget,
    authoritySha256,
    pathAndQuerySha256,
    configurationSha256,
    isFixtureException: false
  });
}
