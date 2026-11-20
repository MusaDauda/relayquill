import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { EventEmitter } from "node:events";
import http from "node:http";
import https from "node:https";
import {
  generateSelfSignedCert
} from "../../../tests/e2e/harness/https-double.mjs";
import {
  PinnedEgressConnector,
  createAddressPolicy,
  executePinnedEgressRequest,
  normalizeDestinationUrl,
  resolveAndValidateEgress
} from "../dist/index.js";

function createMockDnsFactory(handlerMap) {
  let instancesCreated = 0;
  const cancelledInstances = [];
  const factory = () => {
    const id = ++instancesCreated;
    let cancelled = false;
    return {
      async resolve4(hostname) {
        if (cancelled) {
          throw Object.assign(new Error("ECANCELLED"), { code: "ECANCELLED" });
        }
        const entry = handlerMap[hostname];
        if (!entry) {
          throw Object.assign(new Error("ENOTFOUND"), { code: "ENOTFOUND" });
        }
        if (entry.resolve4) {
          return await entry.resolve4(() => cancelled);
        }
        if (entry.v4Error) {
          throw Object.assign(new Error(entry.v4Error), { code: entry.v4Error });
        }
        if (!entry.v4 || entry.v4.length === 0) {
          throw Object.assign(new Error("ENODATA"), { code: "ENODATA" });
        }
        return entry.v4;
      },
      async resolve6(hostname) {
        if (cancelled) {
          throw Object.assign(new Error("ECANCELLED"), { code: "ECANCELLED" });
        }
        const entry = handlerMap[hostname];
        if (!entry) {
          throw Object.assign(new Error("ENOTFOUND"), { code: "ENOTFOUND" });
        }
        if (entry.resolve6) {
          return await entry.resolve6(() => cancelled);
        }
        if (entry.v6Error) {
          throw Object.assign(new Error(entry.v6Error), { code: entry.v6Error });
        }
        if (!entry.v6 || entry.v6.length === 0) {
          throw Object.assign(new Error("ENODATA"), { code: "ENODATA" });
        }
        return entry.v6;
      },
      async resolveCname(hostname) {
        if (cancelled) {
          throw Object.assign(new Error("ECANCELLED"), { code: "ECANCELLED" });
        }
        const entry = handlerMap[hostname];
        if (!entry) {
          throw Object.assign(new Error("ENOTFOUND"), { code: "ENOTFOUND" });
        }
        if (entry.cname && entry.cname.length > 0) {
          return entry.cname;
        }
        throw Object.assign(new Error("ENODATA"), { code: "ENODATA" });
      },
      cancel() {
        cancelled = true;
        cancelledInstances.push(id);
      }
    };
  };
  return { factory, getCancelled: () => cancelledInstances, getCount: () => instancesCreated };
}

test("resolver enforces whole-answer validation (mixed A/AAAA), CNAME limits/cycles, address cap, TTL rules, and isolated cancellation", async () => {
  const addressPolicy = createAddressPolicy({ profile: "release" });

  // 1. Mixed public + private A/AAAA rejects the ENTIRE decision
  const mixedDns = createMockDnsFactory({
    "mixed.merchant.com": {
      v4: [{ address: "93.184.216.34", ttl: 60 }],
      v6: [{ address: "fe80::1", ttl: 60 }]
    },
    "mixed-v4.merchant.com": {
      v4: [
        { address: "93.184.216.34", ttl: 60 },
        { address: "10.0.0.5", ttl: 60 }
      ]
    },
    "mapped-v6.merchant.com": {
      v4: [{ address: "93.184.216.34", ttl: 60 }],
      v6: [{ address: "::ffff:127.0.0.1", ttl: 60 }]
    }
  });

  for (const host of ["mixed.merchant.com", "mixed-v4.merchant.com", "mapped-v6.merchant.com"]) {
    const res = await resolveAndValidateEgress({
      target: `https://${host}/hooks`,
      addressPolicy,
      createDnsResolver: mixedDns.factory
    });
    assert.equal(res.decision, "denied", `expected denied for ${host}`);
    assert.equal(res.selectedAddress, null);
  }

  // 2. >16 addresses cap
  const manyDns = createMockDnsFactory({
    "many.merchant.com": {
      v4: Array.from({ length: 17 }, (_, i) => ({ address: `93.184.216.${10 + i}`, ttl: 60 }))
    }
  });
  const manyRes = await resolveAndValidateEgress({
    target: "https://many.merchant.com/hooks",
    addressPolicy,
    createDnsResolver: manyDns.factory
  });
  assert.equal(manyRes.decision, "denied");
  assert.equal(manyRes.reasonCode, "EGRESS_ADDRESS_COUNT_EXCEEDED");

  // 3. CNAME chain: 8 hops allowed (non-cacheable when TTL unknown), 9 hops rejected, cycle & reserved rejected
  const cnameMap = {
    "ok8.merchant.com": { cname: ["h1.cdn.com"] },
    "h1.cdn.com": { cname: ["h2.cdn.com"] },
    "h2.cdn.com": { cname: ["h3.cdn.com"] },
    "h3.cdn.com": { cname: ["h4.cdn.com"] },
    "h4.cdn.com": { cname: ["h5.cdn.com"] },
    "h5.cdn.com": { cname: ["h6.cdn.com"] },
    "h6.cdn.com": { cname: ["h7.cdn.com"] },
    "h7.cdn.com": { cname: ["h8.cdn.com"] },
    "h8.cdn.com": { v4: [{ address: "93.184.216.34", ttl: 120 }] },
    "bad9.merchant.com": { cname: ["ok8.merchant.com"] },
    "cycle.merchant.com": { cname: ["c1.merchant.com"] },
    "c1.merchant.com": { cname: ["cycle.merchant.com"] },
    "evil-cname.merchant.com": { cname: ["metadata.internal"] }
  };
  const cnameDns = createMockDnsFactory(cnameMap);

  const ok8 = await resolveAndValidateEgress({
    target: "https://ok8.merchant.com/hooks",
    addressPolicy,
    createDnsResolver: cnameDns.factory
  });
  assert.equal(ok8.decision, "allowed");
  assert.equal(ok8.cnameChain.length, 8);
  assert.equal(ok8.ttlSeconds, 30); // Clamped from 120s to 30s
  assert.equal(ok8.cacheable, false); // CNAME TTL unknown -> cross-attempt caching disabled

  const bad9 = await resolveAndValidateEgress({
    target: "https://bad9.merchant.com/hooks",
    addressPolicy,
    createDnsResolver: cnameDns.factory
  });
  assert.equal(bad9.decision, "denied");
  assert.equal(bad9.reasonCode, "EGRESS_CNAME_DEPTH_EXCEEDED");

  const cycleRes = await resolveAndValidateEgress({
    target: "https://cycle.merchant.com/hooks",
    addressPolicy,
    createDnsResolver: cnameDns.factory
  });
  assert.equal(cycleRes.decision, "denied");
  assert.equal(cycleRes.reasonCode, "EGRESS_CNAME_CYCLE");

  const reservedCnameRes = await resolveAndValidateEgress({
    target: "https://evil-cname.merchant.com/hooks",
    addressPolicy,
    createDnsResolver: cnameDns.factory
  });
  assert.equal(reservedCnameRes.decision, "denied");
  assert.equal(reservedCnameRes.reasonCode, "EGRESS_CNAME_RESERVED_TARGET");

  // 4. TTL=0 is immediate one-shot (<=1s) and non-cacheable; AAAA error does not pass A-only
  const ttlZeroDns = createMockDnsFactory({
    "ttl0.merchant.com": { v4: [{ address: "93.184.216.34", ttl: 0 }] },
    "v6fail.merchant.com": {
      v4: [{ address: "93.184.216.34", ttl: 60 }],
      v6Error: "ETIMEOUT"
    }
  });
  const ttl0Res = await resolveAndValidateEgress({
    target: "https://ttl0.merchant.com/hooks",
    addressPolicy,
    createDnsResolver: ttlZeroDns.factory
  });
  assert.equal(ttl0Res.decision, "allowed");
  assert.equal(ttl0Res.oneShot, true);
  assert.equal(ttl0Res.cacheable, false);
  assert.equal(ttl0Res.expiresAtMs - ttl0Res.observedAtMs, 1_000);

  const v6FailRes = await resolveAndValidateEgress({
    target: "https://v6fail.merchant.com/hooks",
    addressPolicy,
    createDnsResolver: ttlZeroDns.factory
  });
  assert.equal(v6FailRes.decision, "unavailable");

  // 5. Isolated per-attempt cancellation does not affect concurrent attempt
  const isoDns = createMockDnsFactory({
    "slow.merchant.com": {
      resolve4: (isCancelled) =>
        new Promise((resolve, reject) => {
          const timer = setInterval(() => {
            if (isCancelled()) {
              clearInterval(timer);
              reject(Object.assign(new Error("ECANCELLED"), { code: "ECANCELLED" }));
            }
          }, 5);
          setTimeout(() => {
            clearInterval(timer);
            resolve([{ address: "93.184.216.34", ttl: 60 }]);
          }, 500);
        })
    },
    "fast.merchant.com": {
      v4: [{ address: "93.184.216.34", ttl: 60 }]
    }
  });

  const [slowRes, fastRes] = await Promise.all([
    resolveAndValidateEgress({
      target: "https://slow.merchant.com/hooks",
      addressPolicy,
      createDnsResolver: isoDns.factory,
      dnsTimeoutMs: 40
    }),
    resolveAndValidateEgress({
      target: "https://fast.merchant.com/hooks",
      addressPolicy,
      createDnsResolver: isoDns.factory,
      dnsTimeoutMs: 500
    })
  ]);
  assert.equal(slowRes.decision, "unavailable");
  assert.equal(slowRes.reasonCode, "DNS_TIMEOUT");
  assert.equal(fastRes.decision, "allowed");
  assert.equal(isoDns.getCancelled().length, 1);
});

test("pinned connector enforces SNI, TLS cert, HTTP_PROXY bypass, one-use/rebinding refusal, redirects, and header/body limits", async (t) => {
  const validCert = generateSelfSignedCert({
    commonName: "receiver.fixture.test",
    dnsNames: ["receiver.fixture.test"],
    ipAddresses: []
  });
  const wrongCert = generateSelfSignedCert({
    commonName: "wrong.example.org",
    dnsNames: ["wrong.example.org"],
    ipAddresses: []
  });

  let mode = "ok";
  let requestsReceived = 0;
  let activeServer = https.createServer(
    { key: validCert.keyPem, cert: validCert.certPem },
    (req, res) => {
      requestsReceived += 1;
      req.on("data", () => undefined);
      req.on("end", () => {
        if (mode === "redirect") {
          res.writeHead(302, { Location: "https://169.254.169.254/latest/meta-data" });
          res.end();
          return;
        }
        if (mode === "hang_headers") {
          return;
        }
        if (mode === "oversized_headers") {
          res.writeHead(200, { "X-Huge": "a".repeat(9000), "Content-Type": "application/json" });
          res.end('{"ok":true}');
          return;
        }
        if (mode === "compressed_200") {
          res.writeHead(200, { "Content-Encoding": "gzip", "Content-Type": "application/json" });
          res.end(Buffer.from([0x1f, 0x8b, 0x08, 0x00]));
          return;
        }
        if (mode === "oversized_body_200") {
          res.writeHead(200, { "Content-Type": "application/json" });
          res.end(Buffer.alloc(70_000, 0x61));
          return;
        }
        if (mode === "partial_body_200") {
          res.writeHead(200, { "Content-Type": "application/json", "Content-Length": "1024" });
          res.write('{"partial":true', () => {
            setTimeout(() => {
              req.socket.destroy();
            }, 15).unref();
          });
          return;
        }
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end('{"receipt_version":1}');
      });
    }
  );
  await new Promise((r) => activeServer.listen(0, "127.0.0.1", r));
  const port = activeServer.address().port;
  t.after(async () => {
    await new Promise((r) => activeServer.close(() => r()));
  });

  const egressConfig = {
    mode: "trusted_local_fixture",
    allow_fixture_receiver: true,
    fixture_receiver_authority: `receiver.fixture.test:${port}`,
    fixture_receiver_path: "/hooks/relayquill",
    fixture_resolve_ip: "127.0.0.1"
  };
  const urlPolicyOptions = { profile: "portable_pglite", egressConfig };
  const targetUrl = `https://receiver.fixture.test:${port}/hooks/relayquill`;

  // 1. Successful pinned HTTPS delivery even when HTTP_PROXY/HTTPS_PROXY point to unreachable dead proxy
  const prevHttpProxy = process.env.HTTP_PROXY;
  const prevHttpsProxy = process.env.HTTPS_PROXY;
  process.env.HTTP_PROXY = "http://127.0.0.1:1";
  process.env.HTTPS_PROXY = "http://127.0.0.1:1";
  t.after(() => {
    if (prevHttpProxy === undefined) delete process.env.HTTP_PROXY;
    else process.env.HTTP_PROXY = prevHttpProxy;
    if (prevHttpsProxy === undefined) delete process.env.HTTPS_PROXY;
    else process.env.HTTPS_PROXY = prevHttpsProxy;
  });

  const decision1 = await resolveAndValidateEgress({ target: targetUrl, urlPolicyOptions });
  assert.equal(decision1.decision, "allowed");

  const okRes = await executePinnedEgressRequest({
    decision: decision1,
    headers: { "Content-Type": "application/json", Host: "evil.override.com" },
    bodyBytes: Buffer.from('{"hello":"world"}'),
    profile: "portable_pglite",
    egressConfig,
    ca: validCert.certPem
  });
  assert.equal(okRes.ok, true);
  assert.equal(okRes.sendStarted, true);
  assert.equal(okRes.outcomeClass, "acknowledged");
  assert.equal(okRes.response.status, 200);
  assert.equal(okRes.response.receiptEligible, true);
  assert.equal(okRes.peerAddressSha256, decision1.selectedAddressSha256);

  // 2. Reusing the same EgressDecision is refused
  const reuseRes = await executePinnedEgressRequest({
    decision: decision1,
    headers: { "Content-Type": "application/json" },
    bodyBytes: Buffer.from("{}"),
    profile: "portable_pglite",
    egressConfig,
    ca: validCert.certPem
  });
  assert.equal(reuseRes.ok, false);
  assert.equal(reuseRes.sendStarted, false);
  assert.equal(reuseRes.safeErrorCode, "EGRESS_DECISION_ALREADY_CONSUMED");

  // 3. Release profile rejects fixture decision before dialing
  const decisionReleaseAttempt = await resolveAndValidateEgress({ target: targetUrl, urlPolicyOptions });
  const releaseBlocked = await executePinnedEgressRequest({
    decision: decisionReleaseAttempt,
    headers: { "Content-Type": "application/json" },
    bodyBytes: Buffer.from("{}"),
    profile: "release"
  });
  assert.equal(releaseBlocked.ok, false);
  assert.equal(releaseBlocked.sendStarted, false);
  assert.equal(releaseBlocked.safeErrorCode, "FIXTURE_FORBIDDEN_IN_PRODUCTION");

  // 4. Redirect 302 is never followed
  mode = "redirect";
  const decRedirect = await resolveAndValidateEgress({ target: targetUrl, urlPolicyOptions });
  const resRedirect = await executePinnedEgressRequest({
    decision: decRedirect,
    headers: { "Content-Type": "application/json" },
    bodyBytes: Buffer.from("{}"),
    profile: "portable_pglite",
    egressConfig,
    ca: validCert.certPem
  });
  assert.equal(resRedirect.ok, false);
  assert.equal(resRedirect.outcomeClass, "permanent_redirect");
  assert.equal(resRedirect.safeErrorCode, "REDIRECT_NOT_ALLOWED");

  // 5. Slow response headers timeout
  mode = "hang_headers";
  const decSlow = await resolveAndValidateEgress({ target: targetUrl, urlPolicyOptions });
  const resSlow = await executePinnedEgressRequest({
    decision: decSlow,
    headers: { "Content-Type": "application/json" },
    bodyBytes: Buffer.from("{}"),
    profile: "portable_pglite",
    egressConfig,
    ca: validCert.certPem,
    timeouts: { responseHeaderMs: 60, totalNetworkMs: 500 }
  });
  assert.equal(resSlow.ok, false);
  assert.equal(resSlow.sendStarted, true);
  assert.equal(resSlow.outcomeClass, "transport_unknown");
  assert.equal(resSlow.safeErrorCode, "RESPONSE_HEADER_TIMEOUT");

  // 6. Compressed 200 preserves HTTP acknowledgement while blocking decompression & receipt eligibility
  mode = "compressed_200";
  const decComp = await resolveAndValidateEgress({ target: targetUrl, urlPolicyOptions });
  const resComp = await executePinnedEgressRequest({
    decision: decComp,
    headers: { "Content-Type": "application/json" },
    bodyBytes: Buffer.from("{}"),
    profile: "portable_pglite",
    egressConfig,
    ca: validCert.certPem
  });
  assert.equal(resComp.ok, true);
  assert.equal(resComp.outcomeClass, "acknowledged");
  assert.equal(resComp.response.bodyDisposition, "unsupported_encoding");
  assert.equal(resComp.response.receiptEligible, false);
  assert.equal(resComp.response.bodyBytes.byteLength, 0);

  // 7. Oversized >64KiB 200 body & partial/dropped 200 body preserve HTTP acknowledgement without receipt eligibility
  mode = "oversized_body_200";
  const decBigBody = await resolveAndValidateEgress({ target: targetUrl, urlPolicyOptions });
  const resBigBody = await executePinnedEgressRequest({
    decision: decBigBody,
    headers: { "Content-Type": "application/json" },
    bodyBytes: Buffer.from("{}"),
    profile: "portable_pglite",
    egressConfig,
    ca: validCert.certPem
  });
  assert.equal(resBigBody.ok, true);
  assert.equal(resBigBody.response.bodyDisposition, "oversized");
  assert.equal(resBigBody.response.receiptEligible, false);

  mode = "partial_body_200";
  const decPartial = await resolveAndValidateEgress({ target: targetUrl, urlPolicyOptions });
  const resPartial = await executePinnedEgressRequest({
    decision: decPartial,
    headers: { "Content-Type": "application/json" },
    bodyBytes: Buffer.from("{}"),
    profile: "portable_pglite",
    egressConfig,
    ca: validCert.certPem
  });
  assert.equal(resPartial.ok, true);
  assert.equal(resPartial.response.bodyDisposition, "truncated_or_lost");
  assert.equal(resPartial.response.receiptEligible, false);

  // 8. Oversized response headers (>8 KiB) fails cleanly
  mode = "oversized_headers";
  const decBigHdr = await resolveAndValidateEgress({ target: targetUrl, urlPolicyOptions });
  const resBigHdr = await executePinnedEgressRequest({
    decision: decBigHdr,
    headers: { "Content-Type": "application/json" },
    bodyBytes: Buffer.from("{}"),
    profile: "portable_pglite",
    egressConfig,
    ca: validCert.certPem
  });
  assert.equal(resBigHdr.ok, false);
  assert.equal(resBigHdr.outcomeClass, "transport_unknown");

  // 9. TLS SAN mismatch rejects BEFORE writing request headers/body
  const countBeforeBadTls = requestsReceived;
  const badTlsServer = https.createServer(
    { key: wrongCert.keyPem, cert: wrongCert.certPem },
    (_req, res) => res.end("should-not-happen")
  );
  await new Promise((r) => badTlsServer.listen(0, "127.0.0.1", r));
  const badPort = badTlsServer.address().port;
  t.after(async () => {
    await new Promise((r) => badTlsServer.close(() => r()));
  });

  const badTlsCfg = { ...egressConfig, fixture_receiver_authority: `receiver.fixture.test:${badPort}` };
  const badTlsDecision = await resolveAndValidateEgress({
    target: `https://receiver.fixture.test:${badPort}/hooks/relayquill`,
    urlPolicyOptions: { profile: "portable_pglite", egressConfig: badTlsCfg }
  });
  const badTlsRes = await executePinnedEgressRequest({
    decision: badTlsDecision,
    headers: { "Content-Type": "application/json" },
    bodyBytes: Buffer.from("{}"),
    profile: "portable_pglite",
    egressConfig: badTlsCfg,
    ca: wrongCert.certPem
  });
  assert.equal(badTlsRes.ok, false);
  assert.equal(badTlsRes.sendStarted, false);
  assert.equal(badTlsRes.outcomeClass, "permanent_policy_or_security");
  assert.equal(badTlsRes.safeErrorCode, "TLS_VERIFICATION_FAILED");
  assert.equal(requestsReceived, countBeforeBadTls);

  // 10. Default PinnedEgressConnector() without egressConfig fails closed on fixture decisions,
  // and mismatched fixture authority/path is rejected before dialing
  const countBeforeUnconfiguredFixture = requestsReceived;
  const defaultConnector = new PinnedEgressConnector();
  const decUnconfigured = await resolveAndValidateEgress({ target: targetUrl, urlPolicyOptions });
  const unconfiguredRes = await defaultConnector.execute({
    decision: decUnconfigured,
    headers: { "Content-Type": "application/json" },
    bodyBytes: Buffer.from("{}"),
    ca: validCert.certPem
  });
  assert.equal(unconfiguredRes.ok, false);
  assert.equal(unconfiguredRes.sendStarted, false);
  assert.equal(unconfiguredRes.outcomeClass, "permanent_policy_or_security");
  assert.equal(unconfiguredRes.safeErrorCode, "FIXTURE_NOT_ENABLED");
  assert.equal(requestsReceived, countBeforeUnconfiguredFixture);

  const decMismatchCfg = await resolveAndValidateEgress({ target: targetUrl, urlPolicyOptions });
  const mismatchCfgRes = await executePinnedEgressRequest({
    decision: decMismatchCfg,
    headers: { "Content-Type": "application/json" },
    bodyBytes: Buffer.from("{}"),
    profile: "portable_pglite",
    egressConfig: { ...egressConfig, fixture_receiver_path: "/hooks/other" },
    ca: validCert.certPem
  });
  assert.equal(mismatchCfgRes.ok, false);
  assert.equal(mismatchCfgRes.sendStarted, false);
  assert.equal(mismatchCfgRes.outcomeClass, "permanent_policy_or_security");
  assert.equal(mismatchCfgRes.safeErrorCode, "FIXTURE_TARGET_MISMATCH");
  assert.equal(requestsReceived, countBeforeUnconfiguredFixture);

  // 11. Connected socket peer IP mismatch rejects BEFORE writing headers or body
  mode = "ok";
  const countBeforePeerMismatch = requestsReceived;
  const decPeerMismatch = await resolveAndValidateEgress({ target: targetUrl, urlPolicyOptions });
  const origHttpsRequest = https.request;
  const httpsMock = t.mock.method(https, "request", function patchedRequest(...args) {
    const req = origHttpsRequest.apply(this, args);
    req.prependOnceListener("socket", (sock) => {
      Object.defineProperty(sock, "remoteAddress", {
        configurable: true,
        get: () => "169.254.169.254"
      });
    });
    return req;
  });
  let peerMismatchRes;
  try {
    peerMismatchRes = await executePinnedEgressRequest({
      decision: decPeerMismatch,
      headers: { "Content-Type": "application/json" },
      bodyBytes: Buffer.from('{"sensitive":true}'),
      profile: "portable_pglite",
      egressConfig,
      ca: validCert.certPem
    });
  } finally {
    httpsMock.mock.restore();
  }
  assert.equal(peerMismatchRes.ok, false);
  assert.equal(peerMismatchRes.sendStarted, false);
  assert.equal(peerMismatchRes.outcomeClass, "permanent_policy_or_security");
  assert.equal(peerMismatchRes.safeErrorCode, "SOCKET_PEER_MISMATCH");
  assert.equal(
    peerMismatchRes.peerAddressSha256,
    crypto.createHash("sha256").update("169.254.169.254", "utf8").digest("hex")
  );
  assert.notEqual(peerMismatchRes.peerAddressSha256, peerMismatchRes.selectedAddressSha256);
  assert.equal(requestsReceived, countBeforePeerMismatch);

  // 12. DNS rebinding caught on re-resolution, and pinned HTTP fixture delivery binds peer IP
  let currentDnsIp = "93.184.216.34";
  const rebindDns = createMockDnsFactory({
    "rebind.merchant.com": {
      resolve4: async () => [{ address: currentDnsIp, ttl: 0 }],
      v6Error: "ENODATA"
    }
  });
  const preRebind = await resolveAndValidateEgress({
    target: "https://rebind.merchant.com/events",
    createDnsResolver: rebindDns.factory
  });
  assert.equal(preRebind.decision, "allowed");
  assert.equal(preRebind.selectedAddress, "93.184.216.34");
  currentDnsIp = "169.254.169.254";
  const postRebind = await resolveAndValidateEgress({
    target: "https://rebind.merchant.com/events",
    createDnsResolver: rebindDns.factory
  });
  assert.equal(postRebind.decision, "denied");
  assert.equal(postRebind.reasonCode, "EGRESS_CIDR_DENIED");

  let httpRequestsReceived = 0;
  const httpServer = http.createServer((_req, res) => {
    httpRequestsReceived += 1;
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end('{"ok":true}');
  });
  await new Promise((r) => httpServer.listen(0, "127.0.0.1", r));
  const httpPort = httpServer.address().port;
  t.after(async () => {
    await new Promise((r) => httpServer.close(() => r()));
  });

  const httpCfg = { ...egressConfig, fixture_receiver_authority: `receiver.fixture.test:${httpPort}` };
  const targetHttp = normalizeDestinationUrl(`http://receiver.fixture.test:${httpPort}/hooks/relayquill`, {
    profile: "portable_pglite",
    egressConfig: httpCfg
  });
  const fixtureHttpDecision = await resolveAndValidateEgress({
    target: targetHttp,
    urlPolicyOptions: { profile: "portable_pglite", egressConfig: httpCfg }
  });
  const fixtureHttpRes = await executePinnedEgressRequest({
    decision: fixtureHttpDecision,
    headers: { "Content-Type": "application/json" },
    bodyBytes: Buffer.from("{}"),
    profile: "portable_pglite",
    egressConfig: httpCfg
  });
  assert.equal(fixtureHttpRes.ok, true);
  assert.equal(fixtureHttpRes.peerAddressSha256, fixtureHttpDecision.selectedAddressSha256);

  // 13. HTTP fixture SOCKET_PEER_MISMATCH rejects BEFORE transmitting HTTP bytes
  const countBeforeHttpPeerMismatch = httpRequestsReceived;
  const fixtureHttpPeerMismatchDecision = await resolveAndValidateEgress({
    target: targetHttp,
    urlPolicyOptions: { profile: "portable_pglite", egressConfig: httpCfg }
  });
  const origHttpRequest = http.request;
  const httpMock = t.mock.method(http, "request", function patchedHttpRequest(...args) {
    const req = origHttpRequest.apply(this, args);
    req.prependOnceListener("socket", (sock) => {
      Object.defineProperty(sock, "remoteAddress", {
        configurable: true,
        get: () => "10.0.0.99"
      });
    });
    return req;
  });
  let httpPeerMismatchRes;
  try {
    httpPeerMismatchRes = await executePinnedEgressRequest({
      decision: fixtureHttpPeerMismatchDecision,
      headers: { "Content-Type": "application/json" },
      bodyBytes: Buffer.from('{"secret":"never-sent"}'),
      profile: "portable_pglite",
      egressConfig: httpCfg
    });
  } finally {
    httpMock.mock.restore();
  }
  assert.equal(httpPeerMismatchRes.ok, false);
  assert.equal(httpPeerMismatchRes.sendStarted, false);
  assert.equal(httpPeerMismatchRes.outcomeClass, "permanent_policy_or_security");
  assert.equal(httpPeerMismatchRes.safeErrorCode, "SOCKET_PEER_MISMATCH");
  assert.equal(httpRequestsReceived, countBeforeHttpPeerMismatch);

  // 14. Real TLS untrusted CA (no custom ca option) and specific TLS auth error codes reject cleanly before send
  const countBeforeUntrustedCa = requestsReceived;
  const untrustedTlsDecision = await resolveAndValidateEgress({ target: targetUrl, urlPolicyOptions });
  const untrustedTlsRes = await executePinnedEgressRequest({
    decision: untrustedTlsDecision,
    headers: { "Content-Type": "application/json" },
    bodyBytes: Buffer.from('{"secret":"never-sent"}'),
    profile: "portable_pglite",
    egressConfig
  });
  assert.equal(untrustedTlsRes.ok, false);
  assert.equal(untrustedTlsRes.sendStarted, false);
  assert.equal(untrustedTlsRes.outcomeClass, "permanent_policy_or_security");
  assert.equal(untrustedTlsRes.safeErrorCode, "TLS_VERIFICATION_FAILED");
  assert.equal(requestsReceived, countBeforeUntrustedCa);

  for (const tlsErrorCode of [
    "UNABLE_TO_GET_ISSUER_CERT",
    "UNABLE_TO_GET_ISSUER_CERT_LOCALLY",
    "CERT_REVOKED",
    "CERT_SIGNATURE_FAILURE"
  ]) {
    const tlsCodeDecision = await resolveAndValidateEgress({ target: targetUrl, urlPolicyOptions });
    const mockReq = new EventEmitter();
    mockReq.destroyed = false;
    mockReq.destroy = () => {
      mockReq.destroyed = true;
    };
    mockReq.write = () => true;
    mockReq.end = () => {};
    const tlsErrMock = t.mock.method(https, "request", () => {
      queueMicrotask(() => {
        mockReq.emit("error", Object.assign(new Error(tlsErrorCode), { code: tlsErrorCode }));
      });
      return mockReq;
    });
    let errRes;
    try {
      errRes = await executePinnedEgressRequest({
        decision: tlsCodeDecision,
        headers: { "Content-Type": "application/json" },
        bodyBytes: Buffer.from("{}"),
        profile: "portable_pglite",
        egressConfig
      });
    } finally {
      tlsErrMock.mock.restore();
    }
    assert.equal(errRes.ok, false, tlsErrorCode);
    assert.equal(errRes.sendStarted, false, tlsErrorCode);
    assert.equal(errRes.outcomeClass, "permanent_policy_or_security", tlsErrorCode);
    assert.equal(errRes.safeErrorCode, "TLS_VERIFICATION_FAILED", tlsErrorCode);
  }
});
