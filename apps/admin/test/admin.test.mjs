import crypto from "node:crypto";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import { InMemoryJetStreamBroker } from "@relayquill/broker";
import { createPGliteAdapter, readInstallationStatus } from "@relayquill/postgres";
import {
  InMemorySecretProvider,
  LocalIpcSecretProvider,
  createIpcServer,
  getIpcEndpoint
} from "@relayquill/runtime";
import { runAdminCommand, startAdminIpcServer } from "../dist/index.js";

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");
const MIGRATIONS_DIR = path.join(REPO_ROOT, "migrations");
const ADMIN_MAIN_JS = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../dist/main.js");

function makeTempDir(t, prefix = "rq-admin-test-") {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  return dir;
}

test("admin CLI --help and validation reject unknown/secret flags", () => {
  const helpRes = spawnSync(process.execPath, [ADMIN_MAIN_JS, "--help"], {
    cwd: REPO_ROOT,
    encoding: "utf8",
    shell: false
  });
  assert.equal(helpRes.status, 0, helpRes.stderr);
  assert.match(helpRes.stdout, /Usage: relayquill-admin/i);

  const badFlag = spawnSync(process.execPath, [ADMIN_MAIN_JS, "--unknown-flag-xyz"], {
    cwd: REPO_ROOT,
    encoding: "utf8",
    shell: false
  });
  assert.notEqual(badFlag.status, 0);

  const secretFlag = spawnSync(
    process.execPath,
    [ADMIN_MAIN_JS, "db", "status", "--password", "secret123"],
    {
      cwd: REPO_ROOT,
      encoding: "utf8",
      shell: false
    }
  );
  assert.notEqual(secretFlag.status, 0);
  assert.match(secretFlag.stderr, /secret-bearing CLI argument/i);
});

test("admin db status, db migrate (idempotent), and db verify run cleanly on PGlite", async (t) => {
  const pg = await createPGliteAdapter({
    schema: "rq",
    supportSchema: "rq_support",
    isolation: "shared_database_schemas",
    configuredRole: "rq_migrator"
  });
  t.after(() => pg.close());

  const beforeStatus = await runAdminCommand(["db", "status"], {
    pgAdapter: pg,
    migrationsDir: MIGRATIONS_DIR
  });
  assert.equal(beforeStatus.ok, false);
  assert.equal(beforeStatus.initialized, false);
  assert.ok(Array.isArray(beforeStatus.pending) && beforeStatus.pending.length >= 9);

  const firstMigrate = await runAdminCommand(["db", "migrate"], {
    pgAdapter: pg,
    migrationsDir: MIGRATIONS_DIR
  });
  assert.equal(firstMigrate.ok, true);
  assert.ok(Array.isArray(firstMigrate.appliedNow) && firstMigrate.appliedNow.length >= 9);

  const secondMigrate = await runAdminCommand(["db", "migrate"], {
    pgAdapter: pg,
    migrationsDir: MIGRATIONS_DIR
  });
  assert.equal(secondMigrate.ok, true);
  assert.deepEqual(secondMigrate.appliedNow, []);
  assert.equal(secondMigrate.totalApplied, firstMigrate.totalApplied);

  const verify = await runAdminCommand(["db", "verify"], {
    pgAdapter: pg,
    migrationsDir: MIGRATIONS_DIR
  });
  assert.equal(verify.ok, true);
  assert.equal(verify.btreeGistInstalled, true);
  assert.ok(verify.rqTableCount >= 45);
  assert.ok(verify.recoveryTableCount >= 10);

  const afterStatus = await runAdminCommand(["db", "status"], {
    pgAdapter: pg,
    migrationsDir: MIGRATIONS_DIR
  });
  assert.equal(afterStatus.ok, true);
  assert.deepEqual(afterStatus.pending, []);
});

test("admin broker ensure, inspect, and verify manage InMemoryJetStreamBroker topology", async (t) => {
  const broker = new InMemoryJetStreamBroker({ autoCreateTopology: false });
  t.after(() => broker.close());

  await assert.rejects(
    () => runAdminCommand(["broker", "verify"], { inMemoryBroker: broker }),
    /does not exist/i
  );

  const ensured = await runAdminCommand(["broker", "ensure"], { inMemoryBroker: broker });
  assert.equal(ensured.ok, true);
  assert.equal(ensured.streamName, "RELAYQUILL_EVENTS_V1");
  assert.equal(ensured.consumerName, "RELAYQUILL_FANOUT_V1");

  const inspected = await runAdminCommand(["broker", "inspect"], { inMemoryBroker: broker });
  assert.equal(inspected.ok, true);
  assert.equal(inspected.configurationSha256, ensured.configurationSha256);

  const verified = await runAdminCommand(["broker", "verify"], { inMemoryBroker: broker });
  assert.equal(verified.ok, true);
  assert.equal(verified.streamName, ensured.streamName);
});

test("admin access approve-enrollment works via PGlite and via protected operator_channel IPC", async (t) => {
  const pg = await createPGliteAdapter({
    schema: "rq",
    supportSchema: "rq_support",
    isolation: "shared_database_schemas",
    configuredRole: "postgres"
  });
  t.after(() => pg.close());
  await runAdminCommand(["db", "migrate"], {
    pgAdapter: pg,
    migrationsDir: MIGRATIONS_DIR
  });

  const preauthId = crypto.randomUUID();
  const intentId = crypto.randomUUID();
  const browserProofDigest = crypto.randomBytes(32);
  const comparisonDigest = crypto.createHash("sha256").update("bootstrap-check").digest();
  const comparisonHex = comparisonDigest.toString("hex");

  const inst = await pg.withTransaction("postgres", (tx) => readInstallationStatus(tx));
  await pg.query(
    `INSERT INTO rq.preauth_contexts (id, proof_digest, state, created_at, expires_at, version)
     VALUES ($1::uuid, $2::bytea, 'active', pg_catalog.clock_timestamp(), pg_catalog.clock_timestamp() + interval '1 hour', 1)`,
    [preauthId, crypto.randomBytes(32)]
  );
  await pg.query(
    `INSERT INTO rq.enrollment_intents (
       id, control_epoch, purpose, browser_proof_digest, preauth_context_id,
       comparison_sha256, state, created_at, expires_at, version
     ) VALUES (
       $1::uuid, $2::uuid, 'first_platform_admin', $3::bytea, $4::uuid,
       $5::bytea, 'requested', pg_catalog.clock_timestamp(), pg_catalog.clock_timestamp() + interval '1 hour', 1
     )`,
    [intentId, inst.controlEpoch, browserProofDigest, preauthId, comparisonDigest]
  );

  // Wrong comparison hash is rejected cleanly
  await assert.rejects(
    () =>
      runAdminCommand(
        [
          "access",
          "approve-enrollment",
          "--intent-id",
          intentId,
          "--version",
          "1",
          "--comparison-sha256",
          "0".repeat(64),
          "--operator-ref",
          "ops-alice"
        ],
        { pgAdapter: pg }
      ),
    /comparison/i
  );

  // Valid approval updates DB and provisions pending human principal
  const approved = await runAdminCommand(
    [
      "access",
      "approve-enrollment",
      "--intent-id",
      intentId,
      "--version",
      "1",
      "--comparison-sha256",
      comparisonHex,
      "--operator-ref",
      "ops-alice"
    ],
    { pgAdapter: pg }
  );
  assert.equal(approved.ok, true);
  assert.equal(approved.state, "approved");
  assert.equal(approved.version, "2");
  assert.ok(typeof approved.target_principal_id === "string");

  // Protected IPC operator_channel client path
  const tmpDir = makeTempDir(t, "rq-admin-op-ipc-");
  const endpoint = getIpcEndpoint(`optest-${process.pid}`, "api-admin", { runtimeDir: tmpDir });
  let capturedReq;
  const ipcServer = createIpcServer(
    endpoint,
    async (req) => {
      capturedReq = req;
      return {
        ok: true,
        intent_id: req.intent_id,
        state: "approved",
        version: "2",
        target_principal_id: crypto.randomUUID()
      };
    },
    { allowEmptyProbeDisconnect: true }
  );
  await ipcServer.listen();
  t.after(() => ipcServer.close());

  const ipcApproved = await runAdminCommand(
    [
      "access",
      "approve-enrollment",
      "--intent-id",
      intentId,
      "--version",
      "1",
      "--comparison-sha256",
      comparisonHex,
      "--operator-ref",
      "ops-bob"
    ],
    { operatorEndpoint: endpoint }
  );
  assert.equal(ipcApproved.ok, true);
  assert.equal(ipcApproved.state, "approved");
  assert.equal(capturedReq.op, "access.approve_enrollment");
  assert.equal(capturedReq.operator_reference, "ops-bob");
});

test("admin protected IPC custody provider supports roundtrip get/put/retire, snapshot reload, and reseed", async (t) => {
  const tmpDir = makeTempDir(t, "rq-admin-custody-");
  const endpoint = getIpcEndpoint(`custtest-${process.pid}`, "provider", { runtimeDir: tmpDir });
  const snapshotPath = path.join(tmpDir, "custody.enc");
  const snapshotKey = crypto.randomBytes(32);

  const server = await startAdminIpcServer({
    endpoint,
    custodySnapshotEnabled: true,
    custodySnapshotPath: snapshotPath,
    snapshotKey,
    seedDefaults: true
  });
  t.after(() => server.close());

  const secReport = await server.verifySecurity();
  assert.equal(secReport.ok, true, `IPC security violations: ${JSON.stringify(secReport)}`);

  const client = new LocalIpcSecretProvider({
    ipc: { env_name: `custtest-${process.pid}`, channel: "provider" },
    mode: "local_ipc_provider"
  });
  // Override endpoint lookup by testing directly against server.endpoint
  const directClient = new LocalIpcSecretProvider({
    ipc: { env_name: `custtest-${process.pid}`, channel: "provider", runtime_dir_env: "RQ_TEST_RUNTIME_DIR" },
    env: { RQ_TEST_RUNTIME_DIR: tmpDir },
    mode: "local_ipc_provider"
  });
  void client;

  const initialStatus = await directClient.getStatus();
  assert.ok(initialStatus.count >= 2);

  const ref = "custody:endpoint-alpha/key-v1";
  const secretBytes = Buffer.from("hmac-material-not-logged-32-bytes!");
  await directClient.putSecret(ref, secretBytes, { version: "v1" });

  // Encrypted snapshot file exists and never stores plaintext secret value
  const rawDisk = fs.readFileSync(snapshotPath, "utf8");
  assert.equal(rawDisk.includes("hmac-material-not-logged"), false);

  const handle = await directClient.getSecret(ref);
  assert.equal(handle.readUtf8(), secretBytes.toString("utf8"));
  assert.equal(handle.version, "v1");
  handle.destroy();

  // Reload preserves persisted entries and increments generation
  const reloaded = await server.reload();
  assert.equal(reloaded.generation, 2);
  const handleAfterReload = await directClient.getSecret(ref);
  assert.equal(handleAfterReload.readUtf8(), secretBytes.toString("utf8"));
  handleAfterReload.destroy();

  // Reseed replaces custody store cleanly
  const reseeded = await server.reseed([{ ref: "custody:reseed/test", value: "new-seed-val" }]);
  assert.equal(reseeded.seeded, 1);
  assert.equal(reseeded.generation, 3);
  await assert.rejects(() => directClient.getSecret(ref), /not found/i);

  const reseedHandle = await directClient.getSecret("custody:reseed/test");
  assert.equal(reseedHandle.readUtf8(), "new-seed-val");
  reseedHandle.destroy();

  await directClient.retireSecret("custody:reseed/test");
  await assert.rejects(() => directClient.getSecret("custody:reseed/test"), /not found/i);
});

test("admin signing deliver provisions signing key into SecretProvider and finalizes DB intent", async (t) => {
  const pg = await createPGliteAdapter({
    schema: "rq",
    supportSchema: "rq_support",
    isolation: "shared_database_schemas",
    configuredRole: "postgres"
  });
  t.after(() => pg.close());
  await runAdminCommand(["db", "migrate"], {
    pgAdapter: pg,
    migrationsDir: MIGRATIONS_DIR
  });

  const inst = await pg.withTransaction("postgres", (tx) => readInstallationStatus(tx));
  const tenantId = crypto.randomUUID();
  const projectId = crypto.randomUUID();
  const humanId = crypto.randomUUID();
  const endpointId = crypto.randomUUID();
  const keyVerId = crypto.randomUUID();
  const intentId = crypto.randomUUID();
  const cfgSha = crypto.randomBytes(32);

  await pg.exec(`
    INSERT INTO rq.principals (id, kind, state) VALUES ('${humanId}', 'human', 'active');
    INSERT INTO rq.humans (principal_id, display_name, webauthn_user_id)
      VALUES ('${humanId}', 'Issuer', decode('${crypto.randomBytes(16).toString("hex")}', 'hex'));
    INSERT INTO rq.tenants (id, slug, display_name, state) VALUES ('${tenantId}', 'acme-dev', 'Acme', 'active');
    INSERT INTO rq.projects (id, tenant_id, name, state) VALUES ('${projectId}', '${tenantId}', 'proj', 'active');
    INSERT INTO rq.endpoints (id, tenant_id, project_id, name, state, current_version, created_by)
      VALUES ('${endpointId}', '${tenantId}', '${projectId}', 'ep1', 'active', 1, '${humanId}');
    INSERT INTO rq.endpoint_versions (
      endpoint_id, endpoint_version, tenant_id, project_id, destination_url,
      normalized_hostname, port, path_and_query_sha256, url_policy_version,
      network_policy_version, request_profile_version, response_profile_version,
      configuration_sha256, created_by
    ) VALUES (
      '${endpointId}', 1, '${tenantId}', '${projectId}', 'https://hooks.example.com/events',
      'hooks.example.com', 443, decode('${cfgSha.toString("hex")}', 'hex'), 'url_v1',
      'network_v1', 'request_v1', 'response_v1',
      decode('${cfgSha.toString("hex")}', 'hex'), '${humanId}'
    );
    INSERT INTO rq.signing_key_versions (
      id, tenant_id, project_id, endpoint_id, key_version, key_id, algorithm,
      custody_reference, custody_version_reference, state
    ) VALUES (
      '${keyVerId}', '${tenantId}', '${projectId}', '${endpointId}', 1, 'k1', 'hmac-sha256-v1',
      'custody:sender/k1', 'v1', 'prepared'
    );
    INSERT INTO rq.signing_delivery_intents (
      id, tenant_id, project_id, endpoint_id, endpoint_version, key_version_id, control_epoch,
      sender_destination_reference, receiver_destination_reference, candidate_sha256, state,
      created_by, expires_at
    ) VALUES (
      '${intentId}', '${tenantId}', '${projectId}', '${endpointId}', 1, '${keyVerId}', '${inst.controlEpoch}',
      'custody:sender/k1', 'custody:receiver/k1', decode('${cfgSha.toString("hex")}', 'hex'), 'approved',
      '${humanId}', pg_catalog.clock_timestamp() + interval '1 hour'
    );
  `);

  const provider = new InMemorySecretProvider();
  const result = await runAdminCommand(["signing", "deliver", "--intent-id", intentId], {
    pgAdapter: pg,
    secretProvider: provider
  });
  assert.equal(result.ok, true);
  assert.equal(result.delivered.length, 1);
  assert.equal(result.delivered[0].state, "delivered");

  const senderHandle = await provider.getSecret("custody:sender/k1");
  const receiverHandle = await provider.getSecret("custody:receiver/k1");
  assert.equal(senderHandle.readBytes().byteLength, 32);
  assert.deepEqual(senderHandle.readBytes(), receiverHandle.readBytes());
  senderHandle.destroy();
  receiverHandle.destroy();
});
