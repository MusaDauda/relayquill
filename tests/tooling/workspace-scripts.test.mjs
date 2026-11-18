import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { orderWorkspacesTopologically } from "../../tools/lib/workspaces.mjs";
import { buildWorkspaces } from "../../tools/build-workspaces.mjs";

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");

function createFixtureRoot(t, files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "rq-scripts-"));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  for (const [relPath, content] of Object.entries(files)) {
    const fullPath = path.join(dir, relPath);
    fs.mkdirSync(path.dirname(fullPath), { recursive: true });
    fs.writeFileSync(fullPath, content, "utf8");
  }
  return dir;
}

test("orders real repository workspaces topologically with domain -> contracts -> runtime", () => {
  const ordered = orderWorkspacesTopologically(REPO_ROOT).map((ws) => ws.name);
  const idxDomain = ordered.indexOf("@relayquill/domain");
  const idxContracts = ordered.indexOf("@relayquill/contracts");
  const idxRuntime = ordered.indexOf("@relayquill/runtime");
  assert.ok(idxDomain !== -1 && idxContracts !== -1 && idxRuntime !== -1);
  assert.ok(idxDomain < idxContracts);
  assert.ok(idxContracts < idxRuntime);
});

test("fails when workspace directory tree is empty", (t) => {
  const dir = createFixtureRoot(t, {
    "package.json": JSON.stringify({ name: "empty", private: true })
  });
  assert.throws(() => orderWorkspacesTopologically(dir), /No workspaces found/);
});

test("buildWorkspaces skips absent categories and propagates workspace build failures", (t) => {
  const dir = createFixtureRoot(t, {
    "package.json": JSON.stringify({
      name: "fixture-root",
      private: true,
      workspaces: ["apps/*", "packages/*", "examples/*"]
    }),
    "packages/domain/package.json": JSON.stringify({
      name: "@relayquill/domain",
      version: "0.1.0",
      scripts: { build: "node -e \"process.exit(0)\"" }
    }),
    "packages/contracts/package.json": JSON.stringify({
      name: "@relayquill/contracts",
      version: "0.1.0",
      dependencies: { "@relayquill/domain": "0.1.0" },
      scripts: { build: "node -e \"process.exit(2)\"" }
    })
  });

  assert.throws(
    () => buildWorkspaces(dir, { quiet: true, stdio: "pipe" }),
    /FAILED: @relayquill\/contracts/
  );
});
