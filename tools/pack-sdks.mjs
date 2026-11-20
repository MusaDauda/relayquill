import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";
import zlib from "node:zlib";
import { Temporal } from "@js-temporal/polyfill";
import {
  SDK_DEFINITIONS,
  buildSdks
} from "./build-sdk.mjs";
import {
  isMainModule,
  runNodeScript,
  runNpm
} from "./lib/workspaces.mjs";

function parseTarEntries(tgzBuffer) {
  const tar = zlib.gunzipSync(tgzBuffer);
  const entries = new Map();
  let offset = 0;

  while (offset + 512 <= tar.length) {
    const header = tar.subarray(offset, offset + 512);
    if (header.every((b) => b === 0)) {
      break;
    }
    const nameRaw = header.subarray(0, 100).toString("utf8").replace(/\0.*$/, "");
    const sizeOctal = header.subarray(124, 136).toString("utf8").replace(/\0.*$/, "").trim();
    const prefixRaw = header.subarray(345, 500).toString("utf8").replace(/\0.*$/, "");
    const fullName = prefixRaw.length > 0 ? `${prefixRaw}/${nameRaw}` : nameRaw;
    const size = sizeOctal.length > 0 ? Number.parseInt(sizeOctal, 8) : 0;

    offset += 512;
    const content = Buffer.from(tar.subarray(offset, offset + size));
    entries.set(fullName.replace(/^\.\//, ""), content);

    const blocks = Math.ceil(size / 512);
    offset += blocks * 512;
  }

  return entries;
}

function createPublishManifest(sourcePkg, sdkDef) {
  const cleanDeps = {};
  for (const [depName, version] of Object.entries(sourcePkg.dependencies ?? {})) {
    if (!depName.startsWith("@relayquill/")) {
      cleanDeps[depName] = version;
    }
  }

  return {
    name: sourcePkg.name,
    version: sourcePkg.version,
    private: false,
    type: "module",
    exports: {
      ".": {
        types: "./dist/index.d.ts",
        import: "./dist/index.js",
        default: "./dist/index.js"
      }
    },
    main: "./dist/index.js",
    types: "./dist/index.d.ts",
    files: ["dist"],
    dependencies: cleanDeps,
    ...(sdkDef.platform === "node"
      ? { engines: { node: ">=24.0.0" } }
      : {})
  };
}

function verifyTarballArchive(tgzPath, expectedPkgName) {
  const tgzBuffer = fs.readFileSync(tgzPath);
  const entries = parseTarEntries(tgzBuffer);

  const requiredFiles = [
    "package/package.json",
    "package/dist/index.js",
    "package/dist/index.d.ts"
  ];
  for (const required of requiredFiles) {
    const fileBuf = entries.get(required);
    if (!fileBuf || fileBuf.byteLength === 0) {
      throw new Error(`[pack-sdks] Tarball ${tgzPath} is missing non-empty "${required}"`);
    }
  }

  const packedPkg = JSON.parse(entries.get("package/package.json").toString("utf8"));
  if (packedPkg.name !== expectedPkgName) {
    throw new Error(`[pack-sdks] Unexpected package name in ${tgzPath}: ${packedPkg.name}`);
  }
  if (packedPkg.private !== false) {
    throw new Error(`[pack-sdks] Staged tarball manifest must set private: false (${tgzPath})`);
  }
  const internalDeps = Object.keys(packedPkg.dependencies ?? {}).filter((d) =>
    d.startsWith("@relayquill/")
  );
  if (internalDeps.length > 0) {
    throw new Error(
      `[pack-sdks] Tarball ${tgzPath} must have zero @relayquill/* dependencies, found: ${internalDeps.join(", ")}`
    );
  }

  return {
    fileCount: entries.size,
    entries: Array.from(entries.keys()).sort()
  };
}

async function generateConsumerFixtures(rootDir) {
  const contractsUrl = pathToFileURL(
    path.join(rootDir, "packages", "contracts", "dist", "index.js")
  ).href;
  const signingUrl = pathToFileURL(
    path.join(rootDir, "packages", "signing", "dist", "index.js")
  ).href;

  const contracts = await import(contractsUrl);
  const signing = await import(signingUrl);

  const projectId = "11111111-1111-4111-8111-111111111111";
  const tenantId = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
  const producerId = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
  const principalId = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";
  const endpointId = "22222222-2222-4222-8222-222222222222";
  const subscriptionId = "33333333-3333-4333-8333-333333333333";
  const eventTypeId = "44444444-4444-4444-8444-444444444444";
  const eventId = "55555555-5555-4555-8555-555555555555";
  const deliveryId = "66666666-6666-4666-8666-666666666666";
  const deliveryAttemptId = "77777777-7777-4777-8777-777777777777";
  const verificationId = "88888888-8888-4888-8888-888888888888";
  const verificationAttemptId = "99999999-9999-4999-8999-999999999999";
  const keyId = "k_smoke_1";
  const authority = "smoke.receiver.example.com:443";
  const requestTarget = "/hooks/smoke";
  const configSha = "c".repeat(64);
  const secretBytes = crypto.createHash("sha256").update("relayquill-tarball-smoke-key").digest();
  const now = Temporal.Instant.from("2026-11-20T12:00:00.000000Z");

  const keyProvider = new signing.InMemoryWebhookKeyProvider();
  const metadata = {
    keyId,
    state: "active",
    projectId,
    endpointId
  };
  keyProvider.registerKey({
    projectId,
    endpointId,
    metadata,
    secretBytes
  });

  const publicNonce = contracts.encodeBase64Url(crypto.randomBytes(32));
  const serializedProofBody = contracts.serializeEndpointVerificationBody({
    envelope_version: 1,
    verification_id: verificationId,
    endpoint_id: endpointId,
    endpoint_version: "1",
    key_id: keyId,
    purpose: "verify_destination_and_key",
    public_nonce: publicNonce,
    configuration_sha256: configSha
  });
  const signedProofReq = await signing.signEndpointVerificationRequest({
    externalAuthority: authority,
    requestTarget,
    projectId,
    endpointId,
    endpointVersion: "1",
    attemptId: verificationAttemptId,
    verificationId,
    body: serializedProofBody.body,
    rawWireBodyBytes: serializedProofBody.body_bytes,
    signingKey: metadata,
    now,
    getKeyMaterial: keyProvider.asResolver()
  });

  const payloadBytes = new TextEncoder().encode('{"smokeOrderId":"ord-900","qty":2}');
  const payloadSha = crypto.createHash("sha256").update(payloadBytes).digest("hex");
  const serializedDelivery = contracts.serializeWebhookEnvelope({
    envelope_version: 1,
    representation_version: 1,
    project_id: projectId,
    event_id: eventId,
    project_event_sequence: "1",
    event_type_id: eventTypeId,
    event_type: "order.created",
    event_schema_version: 1,
    admitted_at: "2026-11-20T11:59:59.000000Z",
    producer_event_time: null,
    content: {
      media_type: "application/json",
      encoding: "base64",
      byte_count: payloadBytes.byteLength,
      sha256: payloadSha,
      data: contracts.encodeBase64(payloadBytes)
    }
  });
  const consumerEventKey = contracts.computeConsumerEventKeySha256({
    project_id: projectId,
    event_id: eventId,
    consumer_contract_scope: "default"
  });
  const signedDeliveryReq = await signing.signWebhookDelivery({
    externalAuthority: authority,
    requestTarget,
    projectId,
    eventId,
    subscriptionId,
    endpointId,
    endpointVersion: "1",
    signingPolicyVersion: "1",
    deliveryId,
    deliveryGeneration: "0",
    attemptId: deliveryAttemptId,
    consumerEventKey,
    rawWireBodyBytes: serializedDelivery.body_bytes,
    now,
    signingKeys: [metadata],
    getKeyMaterial: keyProvider.asResolver()
  });

  keyProvider.destroy();

  return {
    contracts,
    signing,
    fixture: {
      tenantId,
      projectId,
      producerId,
      principalId,
      endpointId,
      subscriptionId,
      eventTypeId,
      eventId,
      deliveryAttemptId,
      verificationId,
      verificationAttemptId,
      keyId,
      publicNonce,
      configSha,
      consumerEventKey,
      originalFactsSha256: serializedDelivery.original_facts_sha256,
      authority,
      requestTarget,
      nowIso: now.toString(),
      secretBase64: secretBytes.toString("base64"),
      proofRequest: {
        method: "POST",
        rawHeaders: signedProofReq.rawHeaderPairs,
        bodyBase64: Buffer.from(signedProofReq.bodyBytes).toString("base64")
      },
      deliveryRequest: {
        method: "POST",
        rawHeaders: signedDeliveryReq.rawHeaderPairs,
        bodyBase64: Buffer.from(serializedDelivery.body_bytes).toString("base64")
      }
    }
  };
}

function buildConsumerSmokeScript() {
  return `import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { prepareEvent } from "@relayquill/producer-sdk";
import {
  InMemoryReceiverKeyProvider,
  createReceiverKeyHandle,
  createSignedDeliveryReceipt,
  handleEndpointProofChallenge,
  verifyWebhookRequest
} from "@relayquill/receiver-sdk";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const fixture = JSON.parse(fs.readFileSync(path.join(__dirname, "fixtures.json"), "utf8"));

const prepared = await prepareEvent({
  expectedPublicationChannelId: fixture.producerId,
  eventTypeId: fixture.eventTypeId,
  eventSchemaVersion: 1,
  businessKey: "ord-smoke-900",
  idempotencyKey: "idem-smoke-900",
  content: '{"smokeOrderId":"ord-900","qty":2}',
  scope: {
    tenantId: fixture.tenantId,
    projectId: fixture.projectId,
    actorPrincipalId: fixture.principalId,
    channelKind: "machine_producer",
    producerNamespace: "billing"
  }
});
assert.match(prepared.contentSha256, /^[0-9a-f]{64}$/);
assert.match(prepared.producerPrepareDigest, /^[0-9a-f]{64}$/);

const secretBytes = Buffer.from(fixture.secretBase64, "base64");
const keyProvider = new InMemoryReceiverKeyProvider();
const metadata = {
  keyId: fixture.keyId,
  state: "active",
  projectId: fixture.projectId,
  endpointId: fixture.endpointId
};
keyProvider.registerKey({
  projectId: fixture.projectId,
  endpointId: fixture.endpointId,
  metadata,
  secretBytes
});
const keyHandle = createReceiverKeyHandle(secretBytes, { id: fixture.keyId });

const proofReqBody = Buffer.from(fixture.proofRequest.bodyBase64, "base64");
const proofVerified = await verifyWebhookRequest({
  method: fixture.proofRequest.method,
  rawHeaders: fixture.proofRequest.rawHeaders,
  rawBodyBytes: proofReqBody,
  expectedTarget: {
    externalAuthority: fixture.authority,
    requestTarget: fixture.requestTarget
  },
  expectedContext: {
    projectId: fixture.projectId,
    endpointId: fixture.endpointId
  },
  keyProvider,
  nowUnixSeconds: BigInt(Math.floor(Date.parse(fixture.nowIso) / 1000))
});
assert.equal(proofVerified.ok, true);
assert.equal(proofVerified.purpose, "endpoint_verification");

const proofResponse = await handleEndpointProofChallenge({
  verifiedRequest: proofVerified,
  keyHandle,
  keyMetadata: metadata
});
assert.equal(proofResponse.statusCode, 204);
assert.equal(proofResponse.body.byteLength, 0);

const deliveryBody = Buffer.from(fixture.deliveryRequest.bodyBase64, "base64");
const deliveryVerified = await verifyWebhookRequest({
  method: fixture.deliveryRequest.method,
  rawHeaders: fixture.deliveryRequest.rawHeaders,
  rawBodyBytes: deliveryBody,
  expectedTarget: {
    externalAuthority: fixture.authority,
    requestTarget: fixture.requestTarget
  },
  expectedContext: {
    projectId: fixture.projectId,
    endpointId: fixture.endpointId,
    subscriptionId: fixture.subscriptionId
  },
  keyProvider,
  nowUnixSeconds: BigInt(Math.floor(Date.parse(fixture.nowIso) / 1000))
});
assert.equal(deliveryVerified.ok, true);
assert.equal(deliveryVerified.purpose, "delivery");

const receiptResponse = await createSignedDeliveryReceipt({
  verifiedDelivery: deliveryVerified,
  keyHandle,
  keyMetadata: metadata
});
assert.equal(receiptResponse.statusCode, 200);
assert.ok(receiptResponse.bodyBytes.byteLength > 0 && receiptResponse.bodyBytes.byteLength <= 4096);

const installedRelayquillPkgs = fs.readdirSync(path.join(__dirname, "node_modules", "@relayquill")).sort();
assert.deepEqual(installedRelayquillPkgs, ["producer-sdk", "receiver-sdk"]);

const summary = {
  installedRelayquillPkgs,
  preparedContentSha256: prepared.contentSha256,
  proofHeaderName: proofResponse.headerName,
  proofHeaderValue: proofResponse.headerValue,
  proofRequestTimestampSeconds: proofVerified.headers.timestamp_seconds,
  proofRequestBodySha256: proofVerified.bodySha256,
  deliveryRequestBodySha256: deliveryVerified.bodySha256,
  receiptHeaders: Object.entries(receiptResponse.headers),
  receiptBodyBase64: Buffer.from(receiptResponse.bodyBytes).toString("base64")
};
console.log(JSON.stringify(summary));
keyHandle.destroy?.();
keyProvider.destroy();
`;
}

export async function packAndVerifySdks(rootDir, options = {}) {
  const resolvedRoot = path.resolve(rootDir);
  const quiet = Boolean(options.quiet);

  await buildSdks(resolvedRoot, {
    skipDependencies: Boolean(options.skipDependencies),
    quiet
  });

  const buildRoot = path.join(resolvedRoot, "build");
  const stageRoot = path.join(buildRoot, "sdk-stage");
  const tarballsDir = path.join(buildRoot, "sdk-tarballs");
  const consumerDir = path.join(buildRoot, "consumer-check");

  fs.rmSync(stageRoot, { recursive: true, force: true });
  fs.rmSync(tarballsDir, { recursive: true, force: true });
  fs.rmSync(consumerDir, { recursive: true, force: true });

  fs.mkdirSync(stageRoot, { recursive: true });
  fs.mkdirSync(tarballsDir, { recursive: true });
  fs.mkdirSync(consumerDir, { recursive: true });

  const packedTarballs = [];

  for (const sdk of SDK_DEFINITIONS) {
    const sdkDir = path.join(resolvedRoot, sdk.relDir);
    const stageDir = path.join(stageRoot, sdk.stageSlug);
    const stageDistDir = path.join(stageDir, "dist");

    fs.mkdirSync(stageDistDir, { recursive: true });
    fs.cpSync(path.join(sdkDir, "dist"), stageDistDir, { recursive: true });

    const sourcePkg = JSON.parse(fs.readFileSync(path.join(sdkDir, "package.json"), "utf8"));
    const publishPkg = createPublishManifest(sourcePkg, sdk);
    fs.writeFileSync(
      path.join(stageDir, "package.json"),
      `${JSON.stringify(publishPkg, null, 2)}\n`,
      "utf8"
    );

    const packRes = runNpm(
      resolvedRoot,
      ["pack", "--json", "--pack-destination", tarballsDir],
      { cwd: stageDir, stdio: "pipe" }
    );
    if (packRes.status !== 0) {
      throw new Error(
        `[pack-sdks] npm pack failed for ${sdk.name}:\n${packRes.stderr || packRes.stdout}`
      );
    }

    const packInfo = JSON.parse(packRes.stdout);
    const tgzFilename = Array.isArray(packInfo) ? packInfo[0]?.filename : packInfo?.filename;
    if (typeof tgzFilename !== "string" || tgzFilename.length === 0) {
      throw new Error(`[pack-sdks] npm pack did not emit a tarball filename for ${sdk.name}`);
    }
    const tgzPath = path.join(tarballsDir, tgzFilename);
    const verifiedArchive = verifyTarballArchive(tgzPath, sdk.name);

    packedTarballs.push({
      name: sdk.name,
      tgzPath,
      tgzFilename,
      ...verifiedArchive
    });

    if (!quiet) {
      console.log(
        `[pack-sdks] Packed & verified ${tgzFilename} (${verifiedArchive.fileCount} files: ${verifiedArchive.entries.join(", ")})`
      );
    }
  }

  // Write isolated consumer package & fixtures, install packed tarballs cleanly, and run smoke test
  fs.writeFileSync(
    path.join(consumerDir, "package.json"),
    `${JSON.stringify(
      {
        name: "relayquill-sdk-consumer-check",
        version: "0.1.0",
        private: true,
        type: "module"
      },
      null,
      2
    )}\n`,
    "utf8"
  );

  const installRes = runNpm(
    resolvedRoot,
    [
      "install",
      "--offline",
      "--no-audit",
      "--no-fund",
      "--ignore-scripts",
      "--workspaces=false",
      ...packedTarballs.map((t) => t.tgzPath)
    ],
    { cwd: consumerDir, stdio: "pipe" }
  );
  if (installRes.status !== 0) {
    throw new Error(
      `[pack-sdks] Consumer tarball install failed:\n${installRes.stderr || installRes.stdout}`
    );
  }

  const { signing, fixture } = await generateConsumerFixtures(resolvedRoot);
  fs.writeFileSync(
    path.join(consumerDir, "fixtures.json"),
    `${JSON.stringify(fixture, null, 2)}\n`,
    "utf8"
  );
  const smokePath = path.join(consumerDir, "smoke.mjs");
  fs.writeFileSync(smokePath, buildConsumerSmokeScript(), "utf8");

  const smokeRes = runNodeScript(smokePath, [], {
    cwd: consumerDir,
    stdio: "pipe"
  });
  if (smokeRes.status !== 0) {
    throw new Error(
      `[pack-sdks] Consumer runtime smoke check failed:\n${smokeRes.stderr || smokeRes.stdout}`
    );
  }

  const summary = JSON.parse(smokeRes.stdout.trim());

  // Cross-verify the consumer SDK's outputs back through @relayquill/signing
  const keyHandle = signing.createMemorySigningKeyHandle(
    Buffer.from(fixture.secretBase64, "base64"),
    { id: fixture.keyId }
  );
  try {
    const proofCheck = signing.verifyEndpointProofResponse({
      statusCode: 204,
      rawHeaders: [[summary.proofHeaderName, summary.proofHeaderValue]],
      rawBodyBytes: new Uint8Array(0),
      expected: {
        verificationIntentId: fixture.verificationId,
        endpointId: fixture.endpointId,
        endpointVersion: "1",
        configurationSha256: fixture.configSha,
        keyId: fixture.keyId,
        publicNonce: fixture.publicNonce,
        verificationAttemptId: fixture.verificationAttemptId,
        requestTimestampSeconds: summary.proofRequestTimestampSeconds,
        requestWireBodySha256: summary.proofRequestBodySha256,
        intentExpiresAt: Temporal.Instant.from("2026-11-20T12:05:00.000000Z")
      },
      keyHandle,
      now: Temporal.Instant.from(fixture.nowIso)
    });
    if (!proofCheck.ok) {
      throw new Error(
        `[pack-sdks] Consumer endpoint proof failed signing verification: ${proofCheck.safeReason}`
      );
    }

    const receiptBytes = Buffer.from(summary.receiptBodyBase64, "base64");
    const receiptCheck = await signing.verifyReceiverLocalCommitReceiptResponse({
      statusCode: 200,
      rawHeaders: summary.receiptHeaders,
      rawBodyBytes: receiptBytes,
      receiptProfile: "receiver_local_commit_v1",
      expected: {
        projectId: fixture.projectId,
        eventId: fixture.eventId,
        consumerEventKey: fixture.consumerEventKey,
        originalFactsSha256: fixture.originalFactsSha256,
        deliveryAttemptId: fixture.deliveryAttemptId,
        requestWireBodySha256: summary.deliveryRequestBodySha256,
        allowedKeyIds: new Set([fixture.keyId])
      },
      resolveVerificationKey: () => ({ handle: keyHandle }),
      now: Temporal.Instant.from(fixture.nowIso)
    });
    if (!receiptCheck.ok) {
      throw new Error(
        `[pack-sdks] Consumer receipt failed signing verification: ${receiptCheck.safeReason}`
      );
    }
  } finally {
    keyHandle.destroy?.();
  }

  if (!quiet) {
    console.log(
      `[pack-sdks] Consumer check passed cleanly (${summary.installedRelayquillPkgs.join(", ")})`
    );
  }

  return {
    ok: true,
    tarballs: packedTarballs,
    consumerDir,
    summary
  };
}

function parseCliArgs(argv) {
  let rootDir = process.cwd();
  let skipDependencies = false;
  let quiet = false;

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--skip-deps") {
      skipDependencies = true;
    } else if (arg === "--quiet") {
      quiet = true;
    } else if (arg === "--root") {
      const next = argv[i + 1];
      if (!next) {
        throw new Error("--root requires a directory argument");
      }
      rootDir = path.resolve(next);
      i += 1;
    } else {
      throw new Error(`Unknown argument: ${arg}`);
    }
  }

  return { rootDir, skipDependencies, quiet };
}

if (isMainModule(import.meta.url)) {
  try {
    const opts = parseCliArgs(process.argv.slice(2));
    await packAndVerifySdks(opts.rootDir, opts);
  } catch (err) {
    console.error(err instanceof Error ? err.message : String(err));
    process.exit(1);
  }
}
