import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import {
  MAX_IPC_FRAME_BYTES,
  createIpcServer,
  getIpcEndpoint,
  inspectIpcEndpoint,
  parseSddlDacl,
  resolveIpcChannelEndpoint,
  sendIpcFrame,
  validateWindowsPipeSddl,
  verifyIpcEndpoint
} from "@relayquill/runtime";

test("IPC endpoint formatting and SDDL DACL parser/validator", () => {
  const endpoint = getIpcEndpoint("unit-env", "api-admin", {
    runtimeDir: "/run/relayquill-test"
  });
  if (process.platform === "win32") {
    assert.equal(endpoint, "\\\\.\\pipe\\relayquill-unit-env-api-admin");
  } else {
    assert.equal(endpoint, "/run/relayquill-test/api-admin.sock");
  }

  assert.throws(
    () =>
      resolveIpcChannelEndpoint(
        { env_name: "dev", channel: "provider", runtime_dir_env: "RQ_DIR" },
        { RQ_DIR: "relative/path" }
      ),
    /absolute path/
  );
  assert.throws(
    () =>
      resolveIpcChannelEndpoint(
        { env_name: "dev", channel: "provider", runtime_dir_env: "RQ_DIR" },
        { RQ_DIR: "/tmp/../escape" }
      ),
    /traversal/
  );

  const userSid = "S-1-5-21-100-200-300-1001";
  const goodSddl = `O:${userSid}G:SYD:P(A;;GA;;;${userSid})(A;;GA;;;SY)`;
  const parsed = parseSddlDacl(goodSddl);
  assert.equal(parsed.ownerSid, userSid);
  assert.equal(parsed.daclProtected, true);
  assert.equal(parsed.aces.length, 2);

  assert.equal(validateWindowsPipeSddl(goodSddl, userSid).ok, true);
  assert.equal(
    validateWindowsPipeSddl(`O:${userSid}D:(A;;GA;;;${userSid})(A;;GA;;;SY)`, userSid).ok,
    false
  );
  assert.equal(
    validateWindowsPipeSddl(`O:${userSid}D:P(A;;GA;;;${userSid})(A;;GA;;;SY)(A;;GA;;;WD)`, userSid)
      .ok,
    false
  );
  assert.equal(
    validateWindowsPipeSddl("O:S-1-5-18D:P(A;;GA;;;S-1-5-18)(A;;GA;;;SY)", userSid).ok,
    false
  );
});

test("hardened dual-platform IPC server & client verify security and enforce frame bounds", async (t) => {
  const envName = `rt-${process.pid}-${Date.now()}`;
  const runtimeDir =
    process.platform === "win32"
      ? undefined
      : fs.mkdtempSync(path.join(os.tmpdir(), "rq-ipc-test-"));
  if (runtimeDir !== undefined) {
    fs.chmodSync(runtimeDir, 0o700);
    t.after(() => fs.rmSync(runtimeDir, { recursive: true, force: true }));
  }

  const endpoint = getIpcEndpoint(envName, "provider", { runtimeDir });
  const server = createIpcServer(endpoint, async (req) => {
    const payload = req && typeof req === "object" ? req : {};
    return { ok: true, echo: payload };
  });

  const report = await server.listen();
  t.after(async () => {
    await server.close();
  });

  assert.equal(report.ok, true, JSON.stringify(report));
  if (report.platform === "win32") {
    assert.equal(report.daclProtected, true);
    assert.equal(report.ownerSid, report.currentUserSid);
  } else {
    assert.equal(report.dirMode, "700");
    assert.equal(report.sockMode, "600");
  }

  const verified = await verifyIpcEndpoint(endpoint);
  assert.equal(verified.ok, true);

  const reply = await sendIpcFrame(endpoint, { op: "ping", seq: 1 });
  assert.deepEqual(reply, { ok: true, echo: { op: "ping", seq: 1 } });

  const serverCheck = await server.verifySecurity();
  assert.equal(serverCheck.ok, true);

  await assert.rejects(
    () => sendIpcFrame(endpoint, '{"a":1}\n{"a":2}'),
    (err) => err?.code === "EIPC_INVALID_FRAME"
  );

  await assert.rejects(
    () => sendIpcFrame(endpoint, { huge: "x".repeat(MAX_IPC_FRAME_BYTES + 16) }),
    (err) => err?.code === "EIPC_FRAME_TOO_LARGE"
  );
});

test("client refuses to transmit over unhardened IPC endpoint", async (t) => {
  const envName = `rt-unhardened-${process.pid}-${Date.now()}`;
  let runtimeDir;
  if (process.platform !== "win32") {
    runtimeDir = fs.mkdtempSync(path.join(os.tmpdir(), "rq-ipc-bad-"));
    fs.chmodSync(runtimeDir, 0o700);
    t.after(() => fs.rmSync(runtimeDir, { recursive: true, force: true }));
  }

  const endpoint = getIpcEndpoint(envName, "control", { runtimeDir });
  let receivedAnyBytes = false;
  const sockets = new Set();
  const rawServer = net.createServer((socket) => {
    sockets.add(socket);
    socket.on("close", () => sockets.delete(socket));
    socket.on("data", () => {
      receivedAnyBytes = true;
    });
  });

  await new Promise((resolve, reject) => {
    rawServer.once("error", reject);
    rawServer.listen(endpoint, resolve);
  });

  t.after(async () => {
    for (const s of sockets) {
      s.destroy();
    }
    await new Promise((resolve) => rawServer.close(() => resolve()));
  });

  if (process.platform !== "win32") {
    fs.chmodSync(endpoint, 0o644);
  }

  const inspection = await inspectIpcEndpoint(endpoint);
  assert.equal(inspection.ok, false);

  await assert.rejects(
    () => sendIpcFrame(endpoint, { secret: "must-never-be-sent" }),
    (err) => err?.code === "EIPC_SECURITY_VIOLATION"
  );
  assert.equal(receivedAnyBytes, false);
});
