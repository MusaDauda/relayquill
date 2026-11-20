import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { DependencyUnavailableDomainError, DomainError } from "@relayquill/domain";
import {
  DEFAULT_FIXTURE_RECEIVER_AUTHORITY,
  DEFAULT_FIXTURE_RECEIVER_HOST,
  DEFAULT_FIXTURE_RECEIVER_PATH,
  PINNED_IANA_REGISTRY_ARTIFACT_SHA256,
  createAddressPolicy,
  loadReviewedAddressRegistry,
  normalizeDestinationUrl,
  peerAddressMatchesSelected
} from "../dist/index.js";

const TRUSTED_LOCAL_EGRESS = Object.freeze({
  mode: "trusted_local_fixture",
  allow_fixture_receiver: true,
  fixture_receiver_authority: DEFAULT_FIXTURE_RECEIVER_AUTHORITY,
  fixture_receiver_path: DEFAULT_FIXTURE_RECEIVER_PATH,
  fixture_resolve_ip: "127.0.0.1"
});

test("URL policy normalizes valid HTTPS URLs and rejects all disallowed URL/path forms", () => {
  const normalized = normalizeDestinationUrl("https://Hooks.Merchant.COM:443/v1/events/utf8%7e");
  assert.equal(normalized.normalizedHostname, "hooks.merchant.com");
  assert.equal(normalized.port, 443);
  assert.equal(normalized.externalAuthority, "hooks.merchant.com:443");
  assert.equal(normalized.requestTarget, "/v1/events/utf8~");
  assert.equal(normalized.canonicalUrl, "https://hooks.merchant.com/v1/events/utf8~");
  assert.equal(normalized.isFixtureException, false);

  const rootTarget = normalizeDestinationUrl("https://hooks.merchant.com");
  assert.equal(rootTarget.requestTarget, "/");

  const unicodeNormalized = normalizeDestinationUrl("https://hooks.merchant.com/caf\u00e9");
  assert.equal(unicodeNormalized.requestTarget, "/caf%C3%A9");

  const invalidUrls = [
    "",
    `https://hooks.merchant.com/${"a".repeat(2040)}`,
    `https://hooks.merchant.com/${"a".repeat(1025)}`,
    "http://hooks.merchant.com/hooks",
    "https:hooks.merchant.com/hooks",
    "https://hooks.merchant.com:8443/hooks",
    "https://hooks.merchant.com:0/hooks",
    "https://hooks.merchant.com:/hooks",
    "https://user:pass@hooks.merchant.com/hooks",
    "https://@hooks.merchant.com/hooks",
    "https://hooks.merchant.com/hooks?token=1",
    "https://hooks.merchant.com/hooks?",
    "https://hooks.merchant.com/hooks#frag",
    "https://hooks.merchant.com/hooks#",
    "https://127.0.0.1/hooks",
    "https://93.184.216.34/hooks",
    "https://[::1]/hooks",
    "https://[2606:4700::1]/hooks",
    "https://0x7f000001/hooks",
    "https://0177.0.0.1/hooks",
    "https://2130706433/hooks",
    "https://127.1/hooks",
    "https://hooks.merchant.com./hooks",
    "https://intranet/hooks",
    "https://localhost/hooks",
    "https://sub.localhost/hooks",
    "https://app.local/hooks",
    "https://db.internal/hooks",
    "https://nas.home.arpa/hooks",
    "https://dev.test/hooks",
    "https://bad.invalid/hooks",
    "https://receiver.example/hooks",
    "https://hooks.merchant.com/a/../b",
    "https://hooks.merchant.com/a/./b",
    "https://hooks.merchant.com/a/%2e%2e/b",
    "https://hooks.merchant.com/a/%2e/b",
    "https://hooks.merchant.com/a//b",
    "https://hooks.merchant.com/a%252Fb",
    "https://hooks.merchant.com/a%2Fb",
    "https://hooks.merchant.com/a%5Cb",
    "https://hooks.merchant.com/a\\b",
    "https://hooks.merchant.com/a%0Ab",
    "https://hooks.merchant.com/a\tb",
    " https://hooks.merchant.com/hooks"
  ];

  for (const candidate of invalidUrls) {
    assert.throws(
      () =>
        normalizeDestinationUrl(candidate, {
          blockedHostnames: ["control.relayquill.org"]
        }),
      DomainError,
      `expected reject: ${candidate}`
    );
  }

  // Control/management hostnames are blocked
  assert.throws(
    () =>
      normalizeDestinationUrl("https://api.control.relayquill.org/hooks", {
        blockedHostnames: ["control.relayquill.org"]
      }),
    (err) => err instanceof DomainError && err.code === "EGRESS_POLICY_DENIED"
  );
});

test("fixture exception receiver.fixture.test:19095 is allowed only in trusted dev config and forbidden in release/self_hosted", () => {
  const fixtureUrl = `http://${DEFAULT_FIXTURE_RECEIVER_AUTHORITY}${DEFAULT_FIXTURE_RECEIVER_PATH}`;

  // Default (no fixture config) rejects
  assert.throws(() => normalizeDestinationUrl(fixtureUrl), DomainError);

  // Release and self_hosted strictly reject even if fixture config is supplied
  for (const prodProfile of ["release", "self_hosted"]) {
    assert.throws(
      () =>
        normalizeDestinationUrl(fixtureUrl, {
          profile: prodProfile,
          egressConfig: TRUSTED_LOCAL_EGRESS
        }),
      (err) => err instanceof DomainError && err.code === "EGRESS_POLICY_DENIED"
    );
    assert.throws(
      () =>
        createAddressPolicy({
          profile: prodProfile,
          egressConfig: TRUSTED_LOCAL_EGRESS
        }),
      (err) => err instanceof DomainError && err.code === "EGRESS_POLICY_DENIED"
    );
  }

  // Allowed in portable_pglite / development_trusted_local ONLY for exact configured authority & path
  const okFixture = normalizeDestinationUrl(fixtureUrl, {
    profile: "portable_pglite",
    egressConfig: TRUSTED_LOCAL_EGRESS
  });
  assert.equal(okFixture.isFixtureException, true);
  assert.equal(okFixture.externalAuthority, DEFAULT_FIXTURE_RECEIVER_AUTHORITY);
  assert.equal(okFixture.requestTarget, DEFAULT_FIXTURE_RECEIVER_PATH);

  assert.throws(
    () =>
      normalizeDestinationUrl(`http://${DEFAULT_FIXTURE_RECEIVER_AUTHORITY}/wrong-path`, {
        profile: "portable_pglite",
        egressConfig: TRUSTED_LOCAL_EGRESS
      }),
    DomainError
  );

  // Fixture authority configured with a different host must not allow receiver.fixture.test
  // nor hijack normal https:// targets on that other host
  const otherHostCfg = {
    ...TRUSTED_LOCAL_EGRESS,
    fixture_receiver_authority: "other.example.com:19095"
  };
  assert.throws(
    () =>
      normalizeDestinationUrl(fixtureUrl, {
        profile: "portable_pglite",
        egressConfig: otherHostCfg
      }),
    (err) => err instanceof DomainError && err.code === "EGRESS_POLICY_DENIED"
  );
  assert.throws(
    () =>
      normalizeDestinationUrl(`http://other.example.com:19095${DEFAULT_FIXTURE_RECEIVER_PATH}`, {
        profile: "portable_pglite",
        egressConfig: otherHostCfg
      }),
    (err) => err instanceof DomainError && err.code === "EGRESS_POLICY_DENIED"
  );
  assert.equal(
    normalizeDestinationUrl("https://other.example.com/webhooks", {
      profile: "portable_pglite",
      egressConfig: otherHostCfg
    }).isFixtureException,
    false
  );
  const otherHostPolicy = createAddressPolicy({
    profile: "portable_pglite",
    egressConfig: otherHostCfg
  });
  assert.equal(
    otherHostPolicy.evaluateAddress("127.0.0.1", {
      isFixtureTarget: true,
      hostname: DEFAULT_FIXTURE_RECEIVER_HOST
    }).allowed,
    false
  );

  // Fixture authority omitting port normalizes to default port 19095
  const normalizedDefaultPortFixture = normalizeDestinationUrl(fixtureUrl, {
    profile: "portable_pglite",
    egressConfig: {
      ...TRUSTED_LOCAL_EGRESS,
      fixture_receiver_authority: DEFAULT_FIXTURE_RECEIVER_HOST
    }
  });
  assert.equal(normalizedDefaultPortFixture.externalAuthority, DEFAULT_FIXTURE_RECEIVER_AUTHORITY);

  // Non-127.0.0.1 fixture_resolve_ip is rejected even in trusted dev profiles
  for (const disallowedIp of ["127.0.0.2", "169.254.169.254"]) {
    const badIpConfig = {
      ...TRUSTED_LOCAL_EGRESS,
      fixture_resolve_ip: disallowedIp
    };
    assert.throws(
      () =>
        normalizeDestinationUrl(fixtureUrl, {
          profile: "portable_pglite",
          egressConfig: badIpConfig
        }),
      (err) => err instanceof DomainError && err.code === "EGRESS_POLICY_DENIED"
    );
    assert.throws(
      () =>
        createAddressPolicy({
          profile: "portable_pglite",
          egressConfig: badIpConfig
        }),
      (err) => err instanceof DomainError && err.code === "EGRESS_POLICY_DENIED"
    );
  }

  const devPolicy = createAddressPolicy({
    profile: "portable_pglite",
    egressConfig: TRUSTED_LOCAL_EGRESS
  });
  assert.equal(
    devPolicy.evaluateAddress("127.0.0.1", {
      isFixtureTarget: true,
      hostname: "receiver.fixture.test"
    }).allowed,
    true
  );
  assert.equal(
    devPolicy.evaluateAddress("169.254.169.254", {
      isFixtureTarget: true,
      hostname: "receiver.fixture.test"
    }).allowed,
    false
  );
  assert.equal(
    devPolicy.evaluateAddress("127.0.0.2", {
      isFixtureTarget: true,
      hostname: "receiver.fixture.test"
    }).allowed,
    false
  );
});

test("reviewed offline IANA address-policy artifact fails closed on missing/tampered file and enforces CIDR denies", (t) => {
  const registry = loadReviewedAddressRegistry();
  assert.equal(registry.artifactSha256, PINNED_IANA_REGISTRY_ARTIFACT_SHA256);

  // Missing or tampered artifact makes connector unavailable (fail-closed)
  assert.throws(
    () => loadReviewedAddressRegistry({ artifactPath: path.join(os.tmpdir(), "nonexistent-registry.json") }),
    DependencyUnavailableDomainError
  );

  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "rq-reg-"));
  t.after(() => fs.rmSync(tmpDir, { recursive: true, force: true }));
  const tamperedPath = path.join(tmpDir, "tampered.json");
  fs.writeFileSync(
    tamperedPath,
    JSON.stringify({ ...registry.artifact, retrieved_at: "2026-12-01T00:00:00Z" }),
    "utf8"
  );
  assert.throws(() => loadReviewedAddressRegistry({ artifactPath: tamperedPath }), DependencyUnavailableDomainError);

  const policy = createAddressPolicy({
    profile: "release",
    deploymentDenyCidrs: ["198.51.101.0/24", "2001:4860:9999::/48"]
  });

  const deniedAddresses = [
    "0.0.0.0",
    "0.1.2.3",
    "10.0.0.1",
    "100.64.0.1",
    "127.0.0.1",
    "169.254.169.254",
    "172.16.0.1",
    "172.31.255.254",
    "192.168.1.1",
    "192.0.0.1",
    "192.0.2.10",
    "198.18.0.1",
    "198.51.100.10",
    "203.0.113.10",
    "224.0.0.1",
    "240.0.0.1",
    "255.255.255.255",
    "168.63.129.16",
    "198.51.101.55",
    "0177.0.0.1",
    "::",
    "::1",
    "::ffff:127.0.0.1",
    "::ffff:169.254.169.254",
    "::ffff:93.184.216.34",
    "64:ff9b::169.254.169.254",
    "64:ff9b:1::10.0.0.1",
    "100::1",
    "2001::1",
    "2001:2::1",
    "2001:db8::1",
    "2002:5db8:d822::1",
    "3fff::1",
    "5f00::1",
    "fc00::1",
    "fd12:3456::1",
    "fe80::1",
    "fe80::1%eth0",
    "ff02::1",
    "2001:4860:9999::1"
  ];
  for (const ip of deniedAddresses) {
    const res = policy.evaluateAddress(ip);
    assert.equal(res.allowed, false, `expected address denied: ${ip}`);
  }

  assert.equal(policy.evaluateAddress("93.184.216.34").allowed, true);
  assert.equal(policy.evaluateAddress("2606:4700:4700::1111").allowed, true);

  // Socket peer normalization allows ::ffff:a.b.c.d only when selectedFamily === 4
  assert.equal(peerAddressMatchesSelected("::ffff:93.184.216.34", "93.184.216.34", 4), true);
  assert.equal(peerAddressMatchesSelected("::ffff:93.184.216.34", "93.184.216.34", 6), false);
  assert.equal(peerAddressMatchesSelected("10.0.0.1", "93.184.216.34", 4), false);
});
