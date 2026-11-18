import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import util from "node:util";
import {
  InMemorySecretProvider,
  createIpcServer,
  createSecretHandle,
  createSecretProvider,
  getIpcEndpoint,
  isSecretHandle
} from "@relayquill/runtime";

test("MemorySecretHandle is non-serializable, redacted in inspect/toJSON, and zeroizable", () => {
  const secretValue = "super-sensitive-signing-key-material";
  const handle = createSecretHandle(secretValue, { id: "custody:ep-1", source: "memory" });

  assert.equal(isSecretHandle(handle), true);
  assert.equal(isSecretHandle({ not: "a-handle" }), false);
  assert.equal(JSON.stringify(handle), '"[REDACTED]"');
  assert.equal(JSON.stringify({ secret: handle }), '{"secret":"[REDACTED]"}');
  assert.equal(String(handle), "[REDACTED]");
  assert.equal(util.inspect(handle).includes(secretValue), false);
  assert.equal(Object.keys(handle).includes(secretValue), false);
  assert.equal(JSON.stringify({ ...handle }).includes(secretValue), false);

  assert.equal(handle.readUtf8(), secretValue);
  assert.equal(
    handle.useBytes((buf) => buf.toString("utf8")),
    secretValue
  );

  handle.destroy();
  assert.equal(handle.isDestroyed, true);
  assert.throws(() => handle.readUtf8(), /destroyed/i);
  assert.throws(() => handle.readBytes(), /destroyed/i);
});

test("env_reference, env_file, mounted_file, and in_memory_test secret providers", async (t) => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "rq-sec-"));
  t.after(() => fs.rmSync(tmpDir, { recursive: true, force: true }));

  const secretsDir = path.join(tmpDir, "secrets");
  fs.mkdirSync(secretsDir, { recursive: true });
  const pgPassFile = path.join(secretsDir, "pg_pass");
  fs.writeFileSync(pgPassFile, "pg-scram-secret\n", "utf8");

  const envFile = path.join(tmpDir, ".env");
  fs.writeFileSync(
    envFile,
    "FROM_FILE_KEY=file-secret-value\nOVERRIDE_KEY=from-env-file\n",
    "utf8"
  );

  const memProvider = new InMemorySecretProvider({
    maxEntries: 2,
    maxEntryBytes: 64
  });
  await memProvider.putSecret("custody:k1", "val1", { version: "v1" });
  await memProvider.putSecret("custody:k2", "val2");
  await assert.rejects(() => memProvider.putSecret("custody:k3", "val3"), /capacity/i);
  await assert.rejects(() => memProvider.putSecret("custody:k1", "x".repeat(65)), /exceeds max/i);
  const status = await memProvider.getStatus();
  assert.equal(status.count, 2);
  assert.equal(JSON.stringify(status).includes("val1"), false);
  const memHandle = await memProvider.getSecret("custody:k1");
  assert.equal(memHandle.readUtf8(), "val1");
  memHandle.destroy();
  await memProvider.retireSecret("custody:k1");
  await assert.rejects(() => memProvider.getSecret("custody:k1"), /not present/i);
  await memProvider.close();

  const envFileProvider = createSecretProvider(
    { mode: "env_file", env_file: envFile },
    { env: { OVERRIDE_KEY: "from-process-env" } }
  );
  const h1 = await envFileProvider.getSecret("env:FROM_FILE_KEY");
  assert.equal(h1.readUtf8(), "file-secret-value");
  h1.destroy();

  const h2 = await envFileProvider.getSecret("env:OVERRIDE_KEY");
  assert.equal(h2.readUtf8(), "from-process-env");
  h2.destroy();

  const mountedProvider = createSecretProvider({
    mode: "mounted_file",
    secrets_dir: secretsDir
  });
  const h3 = await mountedProvider.getSecret(`file:${pgPassFile}`);
  assert.equal(h3.readUtf8(), "pg-scram-secret");
  h3.destroy();

  const h4 = await mountedProvider.getSecret("custody:pg_pass");
  assert.equal(h4.readUtf8(), "pg-scram-secret");
  h4.destroy();

  await assert.rejects(
    () => mountedProvider.getSecret("file:../outside"),
    /traversal/i
  );
});

test("local_ipc secret provider and pluggable custody adapter", async (t) => {
  const backing = new InMemorySecretProvider();
  const envName = `rt-sec-ipc-${process.pid}-${Date.now()}`;
  let runtimeDir;
  if (process.platform !== "win32") {
    runtimeDir = fs.mkdtempSync(path.join(os.tmpdir(), "rq-sec-ipc-"));
    fs.chmodSync(runtimeDir, 0o700);
    t.after(() => fs.rmSync(runtimeDir, { recursive: true, force: true }));
  }

  const endpoint = getIpcEndpoint(envName, "provider", { runtimeDir });
  const server = createIpcServer(endpoint, async (req) => {
    const r = req;
    if (r.op === "put") {
      const bytes = Buffer.from(r.valueBase64, "base64");
      const meta = await backing.putSecret(r.ref, bytes, {
        version: r.version,
        expiresAt: r.expiresAt
      });
      return { ok: true, op: "put", ref: r.ref, version: meta.version };
    }
    if (r.op === "get") {
      try {
        const h = await backing.getSecret(r.ref);
        const valueBase64 = h.useBytes((b) => b.toString("base64"));
        const version = h.version;
        h.destroy();
        return { ok: true, op: "get", ref: r.ref, valueBase64, version };
      } catch (err) {
        return {
          ok: false,
          errorCode: "NOT_FOUND",
          message: err instanceof Error ? err.message : String(err)
        };
      }
    }
    if (r.op === "retire") {
      await backing.retireSecret(r.ref);
      return { ok: true, op: "retire", ref: r.ref };
    }
    const st = await backing.getStatus();
    return { ok: true, op: "status", ...st };
  });

  await server.listen();
  t.after(async () => {
    await server.close();
    await backing.close();
  });

  const ipcProvider = createSecretProvider(
    {
      mode: "local_ipc",
      ipc: { env_name: envName, channel: "provider", runtime_dir_env: "RQ_TEST_RUNTIME_DIR" }
    },
    { env: runtimeDir !== undefined ? { RQ_TEST_RUNTIME_DIR: runtimeDir } : {} }
  );

  await ipcProvider.putSecret?.("custody:signing/ep-1", "ephemeral-hmac-key", { version: "1" });
  const fetched = await ipcProvider.getSecret("custody:signing/ep-1");
  assert.equal(fetched.readUtf8(), "ephemeral-hmac-key");
  assert.equal(fetched.version, "1");
  fetched.destroy();

  const status = await ipcProvider.getStatus?.();
  assert.equal(status?.count, 1);
  assert.deepEqual(status?.refs, ["custody:signing/ep-1"]);

  await ipcProvider.retireSecret?.("custody:signing/ep-1");
  await assert.rejects(() => ipcProvider.getSecret("custody:signing/ep-1"), /not present/i);

  // Pluggable custody provider for aws_secrets_manager fails closed without adapter
  assert.throws(
    () =>
      createSecretProvider({
        mode: "aws_secrets_manager",
        region: "us-east-1",
        secret_prefix: "relayquill/prod/"
      }),
    /custodyProviders/i
  );

  const plugged = createSecretProvider(
    {
      mode: "aws_secrets_manager",
      region: "us-east-1",
      secret_prefix: "relayquill/prod/"
    },
    {
      custodyProviders: {
        aws_secrets_manager: {
          name: "mock-aws-sm",
          async getSecret(ref) {
            return createSecretHandle(`mocked:${ref}`, { id: ref, source: "custody" });
          }
        }
      }
    }
  );
  const pluggedHandle = await plugged.getSecret("aws-sm:relayquill/prod/test");
  assert.equal(pluggedHandle.readUtf8(), "mocked:aws-sm:relayquill/prod/test");
  pluggedHandle.destroy();
});
