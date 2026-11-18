import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  extractModuleSpecifiers,
  verifyWorkspaceBoundaries
} from "../../tools/verify-import-boundaries.mjs";

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");

function createTempWorkspace(t, files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "rq-boundaries-"));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  for (const [relPath, content] of Object.entries(files)) {
    const fullPath = path.join(dir, relPath);
    fs.mkdirSync(path.dirname(fullPath), { recursive: true });
    fs.writeFileSync(fullPath, content, "utf8");
  }
  return dir;
}

test("real repository passes import boundary verification", () => {
  const report = verifyWorkspaceBoundaries(REPO_ROOT);
  assert.equal(report.ok, true, JSON.stringify(report.violations, null, 2));
  assert.equal(report.violations.length, 0);
  assert.ok(report.workspacesChecked >= 3);
});

test("valid temporary DAG (domain <- contracts <- runtime) passes", (t) => {
  const dir = createTempWorkspace(t, {
    "packages/domain/package.json": JSON.stringify({ name: "@relayquill/domain", version: "0.1.0" }),
    "packages/domain/src/index.ts": "export const id = 'ok';\n",
    "packages/contracts/package.json": JSON.stringify({
      name: "@relayquill/contracts",
      version: "0.1.0",
      dependencies: { "@relayquill/domain": "0.1.0" }
    }),
    "packages/contracts/src/index.ts": "import { id } from '@relayquill/domain'; export const x = id;\n",
    "packages/runtime/package.json": JSON.stringify({
      name: "@relayquill/runtime",
      version: "0.1.0",
      dependencies: { "@relayquill/domain": "0.1.0", "@relayquill/contracts": "0.1.0" }
    }),
    "packages/runtime/src/index.ts":
      "import path from 'node:path'; import { x } from '@relayquill/contracts'; export const out = path.basename(x);\n"
  });

  const report = verifyWorkspaceBoundaries(dir);
  assert.equal(report.ok, true, JSON.stringify(report.violations, null, 2));
});

test("detects package.json dependency cycle", (t) => {
  const dir = createTempWorkspace(t, {
    "packages/domain/package.json": JSON.stringify({
      name: "@relayquill/domain",
      dependencies: { "@relayquill/contracts": "0.1.0" }
    }),
    "packages/domain/src/index.ts": "export const a = 1;\n",
    "packages/contracts/package.json": JSON.stringify({
      name: "@relayquill/contracts",
      dependencies: { "@relayquill/domain": "0.1.0" }
    }),
    "packages/contracts/src/index.ts": "export const b = 2;\n"
  });

  const report = verifyWorkspaceBoundaries(dir);
  assert.equal(report.ok, false);
  assert.ok(report.violations.some((v) => v.type === "cycle"));
});

test("detects src import cycle", (t) => {
  const dir = createTempWorkspace(t, {
    "packages/domain/package.json": JSON.stringify({ name: "@relayquill/domain" }),
    "packages/domain/src/index.ts": "import '@relayquill/contracts'; export const a = 1;\n",
    "packages/contracts/package.json": JSON.stringify({
      name: "@relayquill/contracts",
      dependencies: { "@relayquill/domain": "0.1.0" }
    }),
    "packages/contracts/src/index.ts": "import '@relayquill/domain'; export const b = 2;\n"
  });

  const report = verifyWorkspaceBoundaries(dir);
  assert.equal(report.ok, false);
  assert.ok(report.violations.some((v) => v.type === "cycle"));
});

test("rejects forbidden imports in domain, contracts, and runtime", (t) => {
  const dir = createTempWorkspace(t, {
    "packages/domain/package.json": JSON.stringify({ name: "@relayquill/domain" }),
    "packages/domain/src/index.ts": "import pg from 'pg'; import fs from 'node:fs'; export { pg, fs };\n",
    "packages/contracts/package.json": JSON.stringify({
      name: "@relayquill/contracts",
      dependencies: { "@relayquill/domain": "0.1.0", "@relayquill/runtime": "0.1.0" }
    }),
    "packages/contracts/src/index.ts": "import '@relayquill/runtime';\n",
    "packages/runtime/package.json": JSON.stringify({
      name: "@relayquill/runtime",
      dependencies: { "@relayquill/domain": "0.1.0", "@relayquill/contracts": "0.1.0" }
    }),
    "packages/runtime/src/index.ts": "import Fastify from 'fastify'; export { Fastify };\n"
  });

  const report = verifyWorkspaceBoundaries(dir);
  assert.equal(report.ok, false);
  assert.ok(report.violations.some((v) => v.workspace === "@relayquill/domain" && v.specifier === "pg"));
  assert.ok(report.violations.some((v) => v.workspace === "@relayquill/domain" && v.specifier === "node:fs"));
  assert.ok(report.violations.some((v) => v.workspace === "@relayquill/contracts" && v.specifier === "@relayquill/runtime"));
  assert.ok(report.violations.some((v) => v.workspace === "@relayquill/runtime" && v.specifier === "fastify"));
});

test("rejects private subpath imports and relative escapes across workspaces", (t) => {
  const dir = createTempWorkspace(t, {
    "packages/domain/package.json": JSON.stringify({
      name: "@relayquill/domain",
      exports: { ".": "./dist/index.js" }
    }),
    "packages/domain/src/ids.ts": "export const id = 1;\n",
    "packages/contracts/package.json": JSON.stringify({
      name: "@relayquill/contracts",
      dependencies: { "@relayquill/domain": "0.1.0" }
    }),
    "packages/contracts/src/index.ts":
      "import '@relayquill/domain/src/ids.js';\nimport '../../domain/src/ids.js';\n"
  });

  const report = verifyWorkspaceBoundaries(dir);
  assert.equal(report.ok, false);
  assert.ok(report.violations.some((v) => v.type === "private_subpath"));
  assert.ok(report.violations.some((v) => v.type === "relative_escape"));
});

test("AST extraction ignores comments and string literals containing import syntax", () => {
  const content = `
    // import pg from "pg";
    /* export * from "fastify"; */
    const doc = "import { secret } from '@relayquill/postgres';";
    import type { RealType } from "@relayquill/domain";
    export { RealType };
  `;
  const specs = extractModuleSpecifiers("sample.ts", content);
  assert.deepEqual(
    specs.map((s) => s.specifier),
    ["@relayquill/domain"]
  );
});

test("enforces downstream layer policies for console, producer-sdk, receiver-sdk, and application", (t) => {
  const dir = createTempWorkspace(t, {
    "apps/console/package.json": JSON.stringify({ name: "@relayquill/console" }),
    "apps/console/src/main.ts": "import '@relayquill/postgres';\n",
    "packages/producer-sdk/package.json": JSON.stringify({ name: "@relayquill/producer-sdk" }),
    "packages/producer-sdk/src/index.ts": "import crypto from 'node:crypto'; export { crypto };\n",
    "packages/receiver-sdk/package.json": JSON.stringify({ name: "@relayquill/receiver-sdk" }),
    "packages/receiver-sdk/src/index.ts": "import pg from 'pg'; export { pg };\n",
    "packages/application/package.json": JSON.stringify({ name: "@relayquill/application" }),
    "packages/application/src/index.ts": "import '@relayquill/postgres';\n"
  });

  const report = verifyWorkspaceBoundaries(dir);
  assert.equal(report.ok, false);
  assert.ok(report.violations.some((v) => v.workspace === "@relayquill/console" && v.type === "forbidden_import"));
  assert.ok(report.violations.some((v) => v.workspace === "@relayquill/producer-sdk" && v.specifier === "node:crypto"));
  assert.ok(report.violations.some((v) => v.workspace === "@relayquill/receiver-sdk" && v.specifier === "pg"));
  assert.ok(report.violations.some((v) => v.workspace === "@relayquill/application" && v.specifier === "@relayquill/postgres"));
});
