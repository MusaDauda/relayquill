import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { nkeys } from "@nats-io/transport-node";
import {
  AckPolicy,
  DeliverPolicy,
  DiscardPolicy,
  JetStreamApiError,
  ReplayPolicy,
  RetentionPolicy,
  StorageType
} from "@nats-io/jetstream";
import {
  ValidationDomainError,
  parseBrokerGenerationId
} from "@relayquill/domain";
import { InMemorySecretProvider } from "@relayquill/runtime";
import {
  BROKER_DEFAULT_ACK_WAIT_NS,
  BROKER_DEFAULT_DUPLICATE_WINDOW_NS,
  BROKER_DEFAULT_MAX_AGE_NS,
  BROKER_DEFAULT_MAX_BYTES,
  BROKER_DEFAULT_MAX_MSGS,
  BROKER_DEFAULT_PULL_MAX_EXPIRES_NS,
  BROKER_EVENT_MAX_PAYLOAD_BYTES,
  BROKER_EVENT_STREAM_NAME,
  BrokerTopologyMismatchError,
  BrokerUnavailableError,
  DEFAULT_DEV_BROKER_TOPOLOGY,
  FANOUT_CONSUMER_NAME,
  FANOUT_MAX_ACK_PENDING,
  FANOUT_MAX_DELIVER,
  FANOUT_PULL_MAX_BATCH,
  FANOUT_PULL_MAX_BYTES,
  brokerConnectionInputFromConfig,
  buildBrokerStreamGenerationProvenance,
  buildBrokerTopologyContract,
  buildNatsConnectionOptions,
  connectNatsBroker,
  createCredsAuthenticatorFromHandle,
  createNKeyAuthenticatorFromHandle,
  createNKeyAuthenticatorFromResolver,
  diffConsumerConfig,
  diffStreamConfig,
  ensureBrokerTopology,
  inspectBrokerTopology,
  loadAndValidateCaBundle,
  toNatsConsumerConfig,
  toNatsStreamConfig,
  validateBrokerConnectionOptions,
  validateCredsHandle,
  validateNKeySeedHandle,
  verifyConsumerCompatibility,
  verifyStreamCompatibility
} from "../dist/index.js";

function derLength(len) {
  if (len < 0x80) {
    return Buffer.from([len]);
  }
  const bytes = [];
  let remaining = len;
  while (remaining > 0) {
    bytes.unshift(remaining & 0xff);
    remaining >>= 8;
  }
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}

function derTag(tag, content) {
  const buf = Buffer.isBuffer(content) ? content : Buffer.from(content);
  return Buffer.concat([Buffer.from([tag]), derLength(buf.length), buf]);
}

function derSequence(items) {
  return derTag(0x30, Buffer.concat(items));
}

function derSet(items) {
  return derTag(0x31, Buffer.concat(items));
}

function derOid(bytes) {
  return derTag(0x06, Buffer.from(bytes));
}

function derIntegerSmall(value) {
  return derTag(0x02, Buffer.from([value]));
}

function derBitString(bytes) {
  return derTag(0x03, Buffer.concat([Buffer.from([0x00]), bytes]));
}

/**
 * Generates an ephemeral valid X.509 v3 self-signed ECDSA P-256 CA PEM
 * purely with Node crypto and minimal DER encoding.
 */
function createSelfSignedEcCaPem() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", {
    namedCurve: "prime256v1"
  });
  const spkiDer = publicKey.export({ type: "spki", format: "der" });
  const ecdsaSha256Alg = derSequence([
    derOid([0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02])
  ]);
  const commonName = derSequence([
    derSet([
      derSequence([
        derOid([0x55, 0x04, 0x03]),
        derTag(0x0c, Buffer.from("Relayquill Test CA", "utf8"))
      ])
    ])
  ]);
  const validity = derSequence([
    derTag(0x17, Buffer.from("250101000000Z", "ascii")),
    derTag(0x17, Buffer.from("350101000000Z", "ascii"))
  ]);
  const basicConstraintsExtn = derSequence([
    derOid([0x55, 0x1d, 0x13]),
    derTag(0x01, Buffer.from([0xff])),
    derTag(0x04, derSequence([derTag(0x01, Buffer.from([0xff]))]))
  ]);
  const extensions = derTag(0xa3, derSequence([basicConstraintsExtn]));

  const tbsCertificate = derSequence([
    derTag(0xa0, derIntegerSmall(2)),
    derIntegerSmall(1),
    ecdsaSha256Alg,
    commonName,
    validity,
    commonName,
    spkiDer,
    extensions
  ]);

  const signature = crypto.sign("sha256", tbsCertificate, privateKey);
  const fullCert = derSequence([tbsCertificate, ecdsaSha256Alg, derBitString(signature)]);
  const b64 = fullCert.toString("base64");
  const lines = b64.match(/.{1,64}/g) ?? [];
  return `-----BEGIN CERTIFICATE-----\n${lines.join("\n")}\n-----END CERTIFICATE-----\n`;
}

function createFakeNKeySeed() {
  const kp = nkeys.createUser();
  return {
    kp,
    seed: kp.getSeed(),
    publicKey: kp.getPublicKey()
  };
}

function createSyntheticCredsString(seedString) {
  const b64url = (obj) =>
    Buffer.from(JSON.stringify(obj), "utf8").toString("base64url");
  const dummyJwt = `${b64url({ typ: "JWT", alg: "ed25519-nkey" })}.${b64url({
    sub: "UFAKE",
    iat: 1_700_000_000,
    nats: { type: "user" }
  })}.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`;
  return [
    "-----BEGIN NATS USER JWT-----",
    dummyJwt,
    "------END NATS USER JWT------",
    "",
    "************************* IMPORTANT *************************",
    "-----BEGIN USER NKEY SEED-----",
    seedString,
    "------END USER NKEY SEED------"
  ].join("\n");
}

function createMockStreamInfo(contract, overrides = {}) {
  return {
    config: {
      ...toNatsStreamConfig(contract.stream),
      ...(overrides.config ?? {})
    },
    created: overrides.created ?? "2026-11-18T00:00:00.000Z",
    state: {
      messages: 0,
      bytes: 0,
      first_seq: 1,
      last_seq: 0,
      deleted: 0,
      consumer_count: 1,
      ...(overrides.state ?? {})
    }
  };
}

function createMockConsumerInfo(contract, overrides = {}) {
  return {
    stream_name: contract.stream.name,
    name: contract.consumer.durable_name,
    created: overrides.created ?? "2026-11-18T00:00:00.000Z",
    config: {
      ...toNatsConsumerConfig(contract.consumer),
      ...(overrides.config ?? {})
    },
    delivered: { consumer_seq: 0, stream_seq: 0 },
    ack_floor: { consumer_seq: 0, stream_seq: 0 },
    num_ack_pending: 0,
    num_redelivered: 0,
    num_waiting: 0,
    num_pending: 0
  };
}

test("connection options validate standard_tls, release_native_tls, embedded_go_tls, development_loopback, and hosted_synadia_ngs", () => {
  const caPem = createSelfSignedEcCaPem();

  const standardSpec = validateBrokerConnectionOptions({
    mode: "standard_tls",
    servers: ["tls://nats-01.internal.relayquill.example:4222"],
    authMode: "nkey_seed",
    secretRef: "secret:broker/relay-nkey",
    tls: { enabled: true, handshake_first: true, reject_unauthorized: true },
    tlsCaPem: caPem,
    replicas: 1
  });
  assert.equal(standardSpec.mode, "standard_tls");
  assert.equal(standardSpec.tlsRequired, true);
  assert.equal(standardSpec.tlsHandshakeFirst, true);
  assert.equal(standardSpec.ignoreClusterUpdates, true);

  const selfHostedSpec = validateBrokerConnectionOptions({
    mode: "self_hosted",
    servers: ["tls://nats-broker.prod.internal:4222"],
    authMode: "nkey_seed",
    secretRef: "secret:broker/self-hosted-nkey",
    tls: { enabled: true, handshake_first: true, reject_unauthorized: true },
    tlsCaPem: caPem,
    replicas: 3
  });
  assert.equal(selfHostedSpec.mode, "self_hosted");
  assert.equal(selfHostedSpec.replicas, 3);

  const releaseSpec = validateBrokerConnectionOptions({
    mode: "release_native_tls",
    servers: [
      "tls://nats-0.nats.internal:4222",
      "tls://nats-1.nats.internal:4222",
      "tls://nats-2.nats.internal:4222"
    ],
    authMode: "nkey_seed",
    secretRef: "secret:broker/release-nkey",
    tls: { enabled: true, handshake_first: true, reject_unauthorized: true },
    tlsCaPem: caPem,
    replicas: 3
  });
  assert.equal(releaseSpec.servers.length, 3);
  assert.equal(releaseSpec.ignoreClusterUpdates, true);

  const devSpec = validateBrokerConnectionOptions({
    mode: "development_loopback",
    servers: ["nats://127.0.0.1:4222"],
    authMode: "none_fixture"
  });
  assert.equal(devSpec.tlsRequired, false);
  assert.equal(devSpec.tlsHandshakeFirst, false);

  const embeddedSpec = validateBrokerConnectionOptions({
    mode: "embedded_go_tls",
    servers: ["tls://127.0.0.1:4422"],
    authMode: "nkey_seed",
    secretRef: "secret:broker/embedded-nkey",
    tls: { enabled: true, handshake_first: true, reject_unauthorized: true },
    tlsCaPem: caPem
  });
  assert.equal(embeddedSpec.tlsRequired, true);
  assert.equal(embeddedSpec.tlsHandshakeFirst, true);

  const hostedSpec = validateBrokerConnectionOptions({
    mode: "hosted_synadia_ngs",
    servers: ["tls://connect.ngs.global:4222"],
    authMode: "synadia_creds_jwt",
    secretRef: "secret:broker/synadia-creds",
    tls: { enabled: true, handshake_first: false, reject_unauthorized: true },
    tlsCaPem: caPem
  });
  assert.equal(hostedSpec.authMode, "synadia_creds_jwt");
  assert.equal(hostedSpec.ignoreClusterUpdates, true);
});

test("connection option validation rejects insecure, loopback, wildcard, or misconfigured options", () => {
  const caPem = createSelfSignedEcCaPem();

  assert.throws(
    () =>
      validateBrokerConnectionOptions({
        mode: "in_memory_test",
        servers: ["nats://127.0.0.1:4222"],
        authMode: "none_fixture"
      }),
    ValidationDomainError
  );

  assert.throws(
    () =>
      validateBrokerConnectionOptions({
        mode: "standard_tls",
        servers: ["tls://127.0.0.1:4222"],
        authMode: "nkey_seed",
        secretRef: "secret:broker/nkey",
        tls: { enabled: true, handshake_first: true, reject_unauthorized: true },
        tlsCaPem: caPem
      }),
    (err) => err instanceof ValidationDomainError && /loopback/i.test(err.message)
  );

  assert.throws(
    () =>
      validateBrokerConnectionOptions({
        mode: "standard_tls",
        servers: ["tls://*.nats.internal:4222"],
        authMode: "nkey_seed",
        secretRef: "secret:broker/nkey",
        tls: { enabled: true, handshake_first: true, reject_unauthorized: true },
        tlsCaPem: caPem
      }),
    ValidationDomainError
  );

  assert.throws(
    () =>
      validateBrokerConnectionOptions({
        mode: "standard_tls",
        servers: ["tls://user:pass@nats.internal:4222"],
        authMode: "nkey_seed",
        secretRef: "secret:broker/nkey",
        tls: { enabled: true, handshake_first: true, reject_unauthorized: true },
        tlsCaPem: caPem
      }),
    ValidationDomainError
  );

  assert.throws(
    () =>
      validateBrokerConnectionOptions({
        mode: "release_native_tls",
        servers: ["tls://nats-0.internal:4222", "tls://nats-1.internal:4222"],
        authMode: "nkey_seed",
        secretRef: "secret:broker/nkey",
        tls: { enabled: true, handshake_first: true, reject_unauthorized: true },
        tlsCaPem: caPem
      }),
    (err) => err instanceof ValidationDomainError && /at least 3/i.test(err.message)
  );

  assert.throws(
    () =>
      validateBrokerConnectionOptions({
        mode: "standard_tls",
        servers: ["tls://nats.internal:4222"],
        authMode: "synadia_creds_jwt",
        secretRef: "secret:broker/creds",
        tls: { enabled: true, handshake_first: true, reject_unauthorized: true },
        tlsCaPem: caPem
      }),
    ValidationDomainError
  );

  assert.throws(
    () =>
      validateBrokerConnectionOptions({
        mode: "standard_tls",
        servers: ["tls://nats.internal:4222"],
        authMode: "nkey_seed",
        secretRef: "secret:broker/nkey",
        tls: { enabled: true, handshake_first: true, reject_unauthorized: true }
      }),
    (err) => err instanceof ValidationDomainError && /CA/i.test(err.message)
  );

  assert.throws(
    () =>
      validateBrokerConnectionOptions({
        mode: "standard_tls",
        servers: ["tls://nats.internal:4222"],
        authMode: "nkey_seed",
        secretRef: "secret:broker/nkey",
        tlsCaPem: caPem,
        tls: { enabled: true, handshake_first: false, reject_unauthorized: true }
      }),
    ValidationDomainError
  );

  assert.throws(
    () =>
      validateBrokerConnectionOptions({
        mode: "standard_tls",
        servers: ["tls://nats.internal:4222"],
        authMode: "nkey_seed",
        secretRef: "secret:broker/nkey",
        tlsCaPem: caPem,
        tls: { enabled: true, handshake_first: true, reject_unauthorized: false }
      }),
    ValidationDomainError
  );

  assert.throws(
    () =>
      validateBrokerConnectionOptions({
        mode: "standard_tls",
        servers: ["tls://nats.internal:4222"],
        authMode: "nkey_seed",
        secretRef: "secret:broker/nkey",
        tls: { enabled: true, handshake_first: true, reject_unauthorized: true },
        tlsCaPem: caPem,
        ignoreClusterUpdates: false
      }),
    ValidationDomainError
  );

  assert.throws(
    () =>
      validateBrokerConnectionOptions({
        mode: "standard_tls",
        servers: ["tls://nats.internal:4222"],
        authMode: "nkey_seed",
        secretRef: "secret:broker/nkey",
        tls: { enabled: true, handshake_first: true, reject_unauthorized: true },
        tlsCaPem: caPem,
        inboxPrefix: "BAD.PREFIX"
      }),
    ValidationDomainError
  );
});

test("CA bundle validation accepts valid PEMs on disk or inline and rejects corrupt/missing bundles", (t) => {
  const caPem = createSelfSignedEcCaPem();
  assert.equal(loadAndValidateCaBundle(undefined, caPem), caPem);

  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "rq-broker-ca-"));
  t.after(() => {
    fs.rmSync(tempDir, { recursive: true, force: true });
  });
  const caPath = path.join(tempDir, "ca.pem");
  fs.writeFileSync(caPath, caPem, "utf8");
  assert.equal(loadAndValidateCaBundle(caPath, undefined), caPem);

  assert.throws(
    () => loadAndValidateCaBundle(undefined, "not-a-valid-pem"),
    ValidationDomainError
  );
  assert.throws(
    () =>
      loadAndValidateCaBundle(
        undefined,
        "-----BEGIN CERTIFICATE-----\nINVALID\n-----END CERTIFICATE-----"
      ),
    ValidationDomainError
  );

  assert.throws(
    () => loadAndValidateCaBundle(path.join(tempDir, "missing-ca.pem"), undefined),
    BrokerUnavailableError
  );
});

test("NKey and creds authenticators sign nonces from SecretHandles without leaking plaintext", async () => {
  const { seed, publicKey } = createFakeNKeySeed();
  const provider = new InMemorySecretProvider({
    initialSecrets: {
      "secret:broker/nkey": new Uint8Array(seed),
      "secret:broker/invalid-nkey": Buffer.from(publicKey, "utf8"),
      "secret:broker/creds": Buffer.from(
        createSyntheticCredsString(Buffer.from(seed).toString("utf8")),
        "utf8"
      )
    }
  });

  const nkeyHandle = await provider.getSecret("secret:broker/nkey");
  assert.equal(validateNKeySeedHandle(nkeyHandle), publicKey);

  const nkeyAuth = createNKeyAuthenticatorFromHandle(nkeyHandle);
  const nonce = "rq-challenge-nonce-123";
  const signed = await nkeyAuth(nonce);
  assert.ok(signed && typeof signed === "object" && "nkey" in signed && "sig" in signed);
  assert.equal(signed.nkey, publicKey);
  assert.equal(
    nkeys.fromPublic(publicKey).verify(new TextEncoder().encode(nonce), nkeys.decode(signed.sig)),
    true
  );

  const resolverAuth = createNKeyAuthenticatorFromResolver(async () => nkeyHandle);
  const signedViaResolver = await resolverAuth(nonce);
  assert.equal(signedViaResolver && "nkey" in signedViaResolver ? signedViaResolver.nkey : "", publicKey);

  const ac = new AbortController();
  ac.abort();
  await assert.rejects(
    async () => resolverAuth(nonce, ac.signal),
    BrokerUnavailableError
  );

  const badHandle = await provider.getSecret("secret:broker/invalid-nkey");
  assert.throws(() => validateNKeySeedHandle(badHandle), ValidationDomainError);

  const credsHandle = await provider.getSecret("secret:broker/creds");
  validateCredsHandle(credsHandle);
  const credsAuth = createCredsAuthenticatorFromHandle(credsHandle);
  const credsSigned = await credsAuth(nonce);
  assert.ok(
    credsSigned &&
      typeof credsSigned === "object" &&
      "jwt" in credsSigned &&
      "sig" in credsSigned
  );

  nkeyHandle.destroy();
  credsHandle.destroy();
  assert.throws(() => validateNKeySeedHandle(nkeyHandle), BrokerUnavailableError);
  assert.throws(() => validateCredsHandle(credsHandle), BrokerUnavailableError);
});

test("buildNatsConnectionOptions and connectNatsBroker enforce TLS/NKey options and inspect ServerInfo", async () => {
  const caPem = createSelfSignedEcCaPem();
  const { seed } = createFakeNKeySeed();
  const provider = new InMemorySecretProvider({
    initialSecrets: {
      "secret:broker/nkey": new Uint8Array(seed)
    }
  });

  const input = brokerConnectionInputFromConfig(
    {
      mode: "standard_tls",
      servers: ["tls://nats-01.prod.internal:4222"],
      auth_mode: "nkey_seed",
      secret_ref: "secret:broker/nkey",
      tls: {
        enabled: true,
        handshake_first: true,
        reject_unauthorized: true
      },
      stream_name: BROKER_EVENT_STREAM_NAME,
      subject_prefix: "rq.prod.",
      consumer_name: FANOUT_CONSUMER_NAME,
      replicas: 1
    },
    { tlsCaPem: caPem, secretProvider: provider, clientName: "relayquill-relay-test" }
  );

  const spec = validateBrokerConnectionOptions(input);
  const handle = await provider.getSecret("secret:broker/nkey");
  const auth = createNKeyAuthenticatorFromHandle(handle);
  const natsOpts = buildNatsConnectionOptions(spec, {
    authenticator: auth,
    resolvedCaPem: caPem
  });

  assert.equal(natsOpts.ignoreClusterUpdates, true);
  assert.equal(natsOpts.noRandomize, false);
  assert.equal(natsOpts.name, "relayquill-relay-test");
  assert.deepEqual(natsOpts.servers, ["tls://nats-01.prod.internal:4222"]);
  assert.equal(typeof natsOpts.authenticator, "function");
  assert.equal(natsOpts.tls?.handshakeFirst, true);
  assert.equal(natsOpts.tls?.ca, caPem);
  assert.equal("user" in natsOpts, false);
  assert.equal("pass" in natsOpts, false);
  assert.equal("token" in natsOpts, false);

  const devOpts = buildNatsConnectionOptions(
    validateBrokerConnectionOptions({
      mode: "development_loopback",
      servers: ["nats://127.0.0.1:4222"],
      authMode: "none_fixture"
    })
  );
  assert.equal(devOpts.tls, null);
  assert.equal(devOpts.ignoreClusterUpdates, true);

  let closed = false;
  let capturedOpts;
  const mockNc = {
    options: {
      inboxPrefix: "_INBOX"
    },
    info: {
      jetstream: true,
      tls_required: true,
      max_payload: 65536,
      server_id: "NATS-SERVER-1"
    },
    isClosed: () => closed,
    isDraining: () => false,
    getServer: () => "tls://nats-01.prod.internal:4222",
    status: () => ({
      async *[Symbol.asyncIterator]() {
        // empty status stream
      }
    }),
    close: async () => {
      closed = true;
    }
  };

  const conn = await connectNatsBroker(input, async (opts) => {
    capturedOpts = opts;
    return mockNc;
  });

  assert.equal(capturedOpts?.ignoreClusterUpdates, true);
  assert.equal(capturedOpts?.tls?.handshakeFirst, true);
  assert.equal(conn.isClosed, false);
  assert.equal(conn.getConnectedServer(), "tls://nats-01.prod.internal:4222");
  await conn.close();
  assert.equal(closed, true);
  assert.equal(conn.isClosed, true);

  await assert.rejects(
    async () =>
      connectNatsBroker(input, async () => ({
        ...mockNc,
        info: { jetstream: false, tls_required: true, max_payload: 65536 },
        close: async () => undefined
      })),
    (err) => err instanceof BrokerUnavailableError && err.reasonCode === "JETSTREAM_DISABLED"
  );

  await assert.rejects(
    async () =>
      connectNatsBroker(input, async () => ({
        ...mockNc,
        info: { jetstream: true, tls_required: false, max_payload: 65536 },
        close: async () => undefined
      })),
    (err) => err instanceof BrokerUnavailableError && err.reasonCode === "TLS_NOT_ADVERTISED"
  );

  await assert.rejects(
    async () =>
      connectNatsBroker(input, async () => ({
        ...mockNc,
        info: { jetstream: true, tls_required: true, max_payload: 2048 },
        close: async () => undefined
      })),
    (err) => err instanceof BrokerUnavailableError && err.reasonCode === "MAX_PAYLOAD_TOO_SMALL"
  );

  handle.destroy();
});

test("stream-contract defines exact RELAYQUILL_EVENTS_V1 / RELAYQUILL_FANOUT_V1 invariants and never silently recreates", async () => {
  assert.equal(DEFAULT_DEV_BROKER_TOPOLOGY.stream.name, BROKER_EVENT_STREAM_NAME);
  assert.equal(DEFAULT_DEV_BROKER_TOPOLOGY.stream.storage, StorageType.File);
  assert.equal(DEFAULT_DEV_BROKER_TOPOLOGY.stream.retention, RetentionPolicy.Limits);
  assert.equal(DEFAULT_DEV_BROKER_TOPOLOGY.stream.discard, DiscardPolicy.New);
  assert.equal(DEFAULT_DEV_BROKER_TOPOLOGY.stream.max_msgs, BROKER_DEFAULT_MAX_MSGS);
  assert.equal(DEFAULT_DEV_BROKER_TOPOLOGY.stream.max_bytes, BROKER_DEFAULT_MAX_BYTES);
  assert.equal(DEFAULT_DEV_BROKER_TOPOLOGY.stream.max_msg_size, BROKER_EVENT_MAX_PAYLOAD_BYTES);
  assert.equal(DEFAULT_DEV_BROKER_TOPOLOGY.stream.max_age_ns, BROKER_DEFAULT_MAX_AGE_NS);
  assert.equal(
    DEFAULT_DEV_BROKER_TOPOLOGY.stream.duplicate_window_ns,
    BROKER_DEFAULT_DUPLICATE_WINDOW_NS
  );
  assert.equal(DEFAULT_DEV_BROKER_TOPOLOGY.stream.replicas, 1);

  assert.equal(DEFAULT_DEV_BROKER_TOPOLOGY.consumer.durable_name, FANOUT_CONSUMER_NAME);
  assert.equal(DEFAULT_DEV_BROKER_TOPOLOGY.consumer.deliver_policy, DeliverPolicy.All);
  assert.equal(DEFAULT_DEV_BROKER_TOPOLOGY.consumer.ack_policy, AckPolicy.Explicit);
  assert.equal(DEFAULT_DEV_BROKER_TOPOLOGY.consumer.replay_policy, ReplayPolicy.Instant);
  assert.equal(DEFAULT_DEV_BROKER_TOPOLOGY.consumer.ack_wait_ns, BROKER_DEFAULT_ACK_WAIT_NS);
  assert.equal(DEFAULT_DEV_BROKER_TOPOLOGY.consumer.max_deliver, FANOUT_MAX_DELIVER);
  assert.equal(DEFAULT_DEV_BROKER_TOPOLOGY.consumer.max_ack_pending, FANOUT_MAX_ACK_PENDING);
  assert.equal(DEFAULT_DEV_BROKER_TOPOLOGY.consumer.max_batch, FANOUT_PULL_MAX_BATCH);
  assert.equal(DEFAULT_DEV_BROKER_TOPOLOGY.consumer.max_bytes, FANOUT_PULL_MAX_BYTES);
  assert.equal(
    DEFAULT_DEV_BROKER_TOPOLOGY.consumer.max_expires_ns,
    BROKER_DEFAULT_PULL_MAX_EXPIRES_NS
  );

  const prodContract = buildBrokerTopologyContract({
    subjectPrefix: "rq.prod.",
    replicas: 3
  });
  assert.deepEqual(prodContract.stream.subjects, ["rq.prod.rq.events.*.accepted"]);
  assert.equal(prodContract.stream.replicas, 3);
  assert.notEqual(
    prodContract.configuration_sha256,
    DEFAULT_DEV_BROKER_TOPOLOGY.configuration_sha256
  );

  const matchingStream = createMockStreamInfo(prodContract);
  const matchingConsumer = createMockConsumerInfo(prodContract);
  assert.deepEqual(diffStreamConfig(matchingStream, prodContract.stream), []);
  assert.deepEqual(diffConsumerConfig(matchingConsumer, prodContract.consumer), []);
  verifyStreamCompatibility(matchingStream, prodContract.stream);
  verifyConsumerCompatibility(matchingConsumer, prodContract.consumer);

  const badStream = createMockStreamInfo(prodContract, {
    config: { discard: DiscardPolicy.Old, duplicate_window: 60_000_000_000 }
  });
  assert.throws(
    () => verifyStreamCompatibility(badStream, prodContract.stream),
    (err) => err instanceof BrokerTopologyMismatchError && err.mismatches.length === 2
  );

  const badConsumer = createMockConsumerInfo(prodContract, {
    config: { max_deliver: 3, ack_policy: AckPolicy.None }
  });
  assert.throws(
    () => verifyConsumerCompatibility(badConsumer, prodContract.consumer),
    (err) => err instanceof BrokerTopologyMismatchError && err.mismatches.length === 2
  );

  let storedStream = null;
  let storedConsumer = null;
  let streamAdds = 0;
  let consumerAdds = 0;
  let mutationsAfterMismatch = 0;

  const mockJsm = {
    streams: {
      info: async (name) => {
        if (storedStream === null || name !== prodContract.stream.name) {
          throw new JetStreamApiError({
            code: 404,
            err_code: 10059,
            description: "stream not found"
          });
        }
        return storedStream;
      },
      add: async (cfg) => {
        streamAdds += 1;
        storedStream = createMockStreamInfo(prodContract, { config: cfg });
        return storedStream;
      },
      delete: async () => {
        mutationsAfterMismatch += 1;
        return true;
      },
      purge: async () => {
        mutationsAfterMismatch += 1;
        return { purged: 0, success: true };
      }
    },
    consumers: {
      info: async (streamName, durableName) => {
        if (
          storedConsumer === null ||
          streamName !== prodContract.stream.name ||
          durableName !== prodContract.consumer.durable_name
        ) {
          throw new JetStreamApiError({
            code: 404,
            err_code: 10014,
            description: "consumer not found"
          });
        }
        return storedConsumer;
      },
      add: async (_streamName, cfg) => {
        consumerAdds += 1;
        storedConsumer = createMockConsumerInfo(prodContract, { config: cfg });
        return storedConsumer;
      },
      delete: async () => {
        mutationsAfterMismatch += 1;
        return true;
      }
    }
  };

  await assert.rejects(
    async () => inspectBrokerTopology(mockJsm, prodContract),
    (err) => err instanceof BrokerUnavailableError && err.reasonCode === "STREAM_NOT_FOUND"
  );

  const created = await ensureBrokerTopology(mockJsm, prodContract);
  assert.equal(streamAdds, 1);
  assert.equal(consumerAdds, 1);
  assert.equal(created.observedStreamCreatedAt, "2026-11-18T00:00:00.000Z");

  await ensureBrokerTopology(mockJsm, prodContract);
  assert.equal(streamAdds, 1);
  assert.equal(consumerAdds, 1);

  const genId = parseBrokerGenerationId("11111111-1111-4111-8111-111111111111");
  const provenance = buildBrokerStreamGenerationProvenance(genId, created);
  assert.equal(provenance.broker_generation_id, genId);
  assert.equal(provenance.stream_name, prodContract.stream.name);
  assert.equal(provenance.observed_stream_created_at, created.observedStreamCreatedAt);

  await assert.rejects(
    async () =>
      inspectBrokerTopology(mockJsm, prodContract, {
        expectedStreamCreatedAt: "2026-11-17T00:00:00.000Z"
      }),
    (err) =>
      err instanceof BrokerTopologyMismatchError &&
      err.mismatches.some((m) => m.field === "created")
  );

  storedStream = createMockStreamInfo(prodContract, {
    config: { max_msgs: 12345 }
  });
  await assert.rejects(
    async () => ensureBrokerTopology(mockJsm, prodContract),
    BrokerTopologyMismatchError
  );
  assert.equal(mutationsAfterMismatch, 0);
  assert.equal(streamAdds, 1);
});
