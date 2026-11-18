import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  isProductionProfile,
  isSecretHandle,
  loadRoleConfig,
  parseDotEnv,
  resolveRuntimeEnvironment,
  validateRoleConfig
} from "@relayquill/runtime";

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");
const CONFIG_DIR = path.join(REPO_ROOT, "config");

const SELFHOSTED_ROLES = [
  "api",
  "relay",
  "fanout",
  "sender",
  "coordinator",
  "admin",
  "receiver",
  "receiver-migrator",
  "provider-ingress",
  "provider-ingress-migrator"
];

test("loads and validates all selfhosted role configs and checks production flags", () => {
  assert.equal(isProductionProfile("release"), true);
  assert.equal(isProductionProfile("self_hosted"), true);
  assert.equal(isProductionProfile("development_trusted_local"), false);
  assert.equal(isProductionProfile("portable_pglite"), false);

  for (const suffix of SELFHOSTED_ROLES) {
    const cfg = loadRoleConfig(path.join(CONFIG_DIR, `selfhosted.${suffix}.json`));
    assert.equal(cfg.profile, "self_hosted");
    if ("database" in cfg && cfg.database !== undefined) {
      assert.equal(cfg.database.mode, "standard_tls");
      assert.equal(cfg.database.tls_mode, "verify_full");
      assert.ok(cfg.database.password_secret_ref?.startsWith("file:/run/secrets/"));
    }
    if ("broker" in cfg && cfg.broker !== undefined) {
      assert.equal(cfg.broker.mode, "standard_tls");
      assert.equal(cfg.broker.auth_mode, "nkey_seed");
      assert.equal(cfg.broker.tls?.enabled, true);
      assert.equal(cfg.broker.tls?.handshake_first, true);
    }
  }
});

test("release profile accepts standard_tls self-hosted DB and broker without forcing AWS", () => {
  const selfHostedApi = JSON.parse(
    fs.readFileSync(path.join(CONFIG_DIR, "selfhosted.api.json"), "utf8")
  );
  selfHostedApi.profile = "release";
  const validatedApi = validateRoleConfig(selfHostedApi, { expectedProcessRole: "api" });
  assert.equal(validatedApi.profile, "release");
  assert.equal(validatedApi.database.mode, "standard_tls");

  const selfHostedRelay = JSON.parse(
    fs.readFileSync(path.join(CONFIG_DIR, "selfhosted.relay.json"), "utf8")
  );
  selfHostedRelay.profile = "release";
  selfHostedRelay.broker.mode = "self_hosted";
  const validatedRelay = validateRoleConfig(selfHostedRelay, { expectedProcessRole: "relay" });
  assert.equal(validatedRelay.broker.mode, "self_hosted");
});

test("rejects unknown fields, secret-bearing DSNs, raw secrets, and role mismatches", () => {
  const api = JSON.parse(fs.readFileSync(path.join(CONFIG_DIR, "selfhosted.api.json"), "utf8"));

  // Unknown field on root
  assert.throws(
    () => validateRoleConfig({ ...api, unexpected_flag: true }),
    /validation failed/i
  );

  // Unknown field inside nested object
  assert.throws(
    () =>
      validateRoleConfig({
        ...api,
        database: { ...api.database, extra_pool_option: 1 }
      }),
    /validation failed/i
  );

  // Expected process role mismatch
  assert.throws(
    () => validateRoleConfig(api, { expectedProcessRole: "sender" }),
    /Expected process_role "sender"/
  );

  // Secret-bearing DSN inside JSON config
  assert.throws(
    () =>
      validateRoleConfig({
        ...api,
        database: {
          ...api.database,
          host: "postgres://rq_api:supersecret@db.internal:5432/relayquill"
        }
      }),
    /validation failed/i
  );

  // Raw secret JSON key inside config
  assert.throws(
    () =>
      validateRoleConfig({
        ...api,
        database: { ...api.database, db_password: "not-allowed-in-json" }
      }),
    /validation failed/i
  );

  // Embedded PEM or credential prefix
  assert.throws(
    () =>
      validateRoleConfig({
        ...api,
        telemetry: {
          ...api.telemetry,
          service_name: "rq_p1.leaked_secret_value"
        }
      }),
    /validation failed/i
  );
});

test("rejects fixture exceptions and insecure overrides in release and self_hosted profiles", () => {
  for (const profile of ["release", "self_hosted"]) {
    const sender = JSON.parse(
      fs.readFileSync(path.join(CONFIG_DIR, "selfhosted.sender.json"), "utf8")
    );
    sender.profile = profile;

    assert.throws(() =>
      validateRoleConfig({
        ...sender,
        egress: {
          mode: "trusted_local_fixture",
          allow_fixture_receiver: true,
          fixture_receiver_authority: "receiver.fixture.test:19095",
          fixture_receiver_path: "/hooks/relayquill",
          fixture_resolve_ip: "127.0.0.1"
        }
      })
    );

    const api = JSON.parse(fs.readFileSync(path.join(CONFIG_DIR, "selfhosted.api.json"), "utf8"));
    api.profile = profile;
    assert.throws(() =>
      validateRoleConfig({
        ...api,
        http: { ...api.http, public_origin: "http://console.relayquill.example" }
      })
    );
    assert.throws(() =>
      validateRoleConfig({
        ...api,
        auth: { ...api.auth, cookie_profile: "development_only" }
      })
    );

    const relay = JSON.parse(
      fs.readFileSync(path.join(CONFIG_DIR, "selfhosted.relay.json"), "utf8")
    );
    relay.profile = profile;
    assert.throws(() =>
      validateRoleConfig({
        ...relay,
        broker: {
          ...relay.broker,
          servers: ["tls://127.0.0.1:4222"]
        }
      })
    );
  }
});

test("parseDotEnv and resolveRuntimeEnvironment resolve DB/NATS env overrides securely", (t) => {
  const parsed = parseDotEnv(`
    # comment line
    DATABASE_URL="postgres://rq_api:pass%40word@pg-pool.internal:6432/relayquill?sslmode=verify-full"
    export DIRECT_DATABASE_URL='postgresql://rq_relay:directpass@pg-direct.internal:5432/relayquill?sslmode=verify-full'
    NATS_URL=tls://nats-1.internal:4222,tls://nats-2.internal:4222 # inline comment
    NATS_NKEY_SEED_FILE=/run/secrets/override-relay.seed
  `);

  assert.equal(
    parsed.DATABASE_URL,
    "postgres://rq_api:pass%40word@pg-pool.internal:6432/relayquill?sslmode=verify-full"
  );
  assert.equal(parsed.NATS_NKEY_SEED_FILE, "/run/secrets/override-relay.seed");

  assert.throws(() => parseDotEnv("INVALID_LINE_NO_EQUALS"), /Malformed .env/);
  assert.throws(() => parseDotEnv("__proto__=evil"), /Invalid environment variable/);

  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "rq-cfg-env-"));
  t.after(() => fs.rmSync(tmpDir, { recursive: true, force: true }));
  const envFile = path.join(tmpDir, ".env");
  fs.writeFileSync(
    envFile,
    [
      "RELAYQUILL_ENV=selfhosted-staging",
      "DATABASE_URL=postgres://rq_api:secret_from_env@pg-main.internal:5432/relayquill?sslmode=verify-full",
      "DIRECT_DATABASE_URL=postgres://rq_relay:relay_secret@pg-direct.internal:5432/relayquill?sslmode=verify-full",
      "RECEIVER_DATABASE_URL=postgres://receiver_runtime:rc_secret@pg-rc.internal:5432/relayquill_receiver?sslmode=verify-full",
      "PROVIDER_INGRESS_DATABASE_URL=postgres://provider_runtime:pi_secret@pg-pi.internal:5432/relayquill_provider?sslmode=verify-full",
      "NATS_URL=tls://b1.internal:4222,tls://b2.internal:4222",
      "NATS_NKEY_SEED_FILE=/run/secrets/override.nk",
      "PUBLIC_CONSOLE_ORIGIN=https://console.staging.example"
    ].join("\n"),
    "utf8"
  );

  const apiCfg = loadRoleConfig(path.join(CONFIG_DIR, "selfhosted.api.json"));
  const resolvedApi = resolveRuntimeEnvironment(apiCfg, { envFilePath: envFile, env: {} });
  assert.equal(resolvedApi.relayquillEnv, "selfhosted-staging");
  assert.equal(resolvedApi.publicConsoleOrigin, "https://console.staging.example");
  assert.equal(resolvedApi.database?.host, "pg-direct.internal");
  assert.equal(resolvedApi.database?.envOverrideVar, "DIRECT_DATABASE_URL");
  assert.ok(isSecretHandle(resolvedApi.database?.passwordHandle));
  assert.equal(resolvedApi.database?.passwordHandle.readUtf8(), "relay_secret");
  assert.equal(JSON.stringify(resolvedApi).includes("relay_secret"), false);
  resolvedApi.database?.passwordHandle.destroy();

  const rcCfg = loadRoleConfig(path.join(CONFIG_DIR, "selfhosted.receiver.json"));
  const resolvedRc = resolveRuntimeEnvironment(rcCfg, { envFilePath: envFile, env: {} });
  assert.equal(resolvedRc.database?.host, "pg-rc.internal");
  assert.equal(resolvedRc.database?.envOverrideVar, "RECEIVER_DATABASE_URL");
  resolvedRc.database?.passwordHandle?.destroy();

  const piCfg = loadRoleConfig(path.join(CONFIG_DIR, "selfhosted.provider-ingress.json"));
  const resolvedPi = resolveRuntimeEnvironment(piCfg, { envFilePath: envFile, env: {} });
  assert.equal(resolvedPi.database?.host, "pg-pi.internal");
  assert.equal(resolvedPi.database?.envOverrideVar, "PROVIDER_INGRESS_DATABASE_URL");
  resolvedPi.database?.passwordHandle?.destroy();

  const relayCfg = loadRoleConfig(path.join(CONFIG_DIR, "selfhosted.relay.json"));
  const resolvedRelay = resolveRuntimeEnvironment(relayCfg, { envFilePath: envFile, env: {} });
  assert.deepEqual(resolvedRelay.broker?.servers, [
    "tls://b1.internal:4222",
    "tls://b2.internal:4222"
  ]);
  assert.equal(resolvedRelay.broker?.secretRef, "file:/run/secrets/override.nk");
  resolvedRelay.database?.passwordHandle?.destroy();

  // Explicit env overrides .env and insecure overrides in production fail closed.
  assert.throws(
    () =>
      resolveRuntimeEnvironment(apiCfg, {
        envFilePath: envFile,
        env: {
          DIRECT_DATABASE_URL: "postgres://rq_api:pw@pg.internal:5432/relayquill?sslmode=disable"
        }
      }),
    /violates tls_mode="verify_full"/
  );
  assert.throws(
    () =>
      resolveRuntimeEnvironment(relayCfg, {
        env: { NATS_URL: "nats://broker-1.internal:4222" }
      }),
    /must use tls:\/\/ scheme/
  );
  assert.throws(
    () =>
      resolveRuntimeEnvironment(apiCfg, {
        env: { PUBLIC_CONSOLE_ORIGIN: "http://receiver.fixture.test:5205" }
      }),
    /HTTPS non-fixture origin/
  );
});
