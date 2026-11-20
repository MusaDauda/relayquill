import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import * as esbuild from "esbuild";
import { Extractor, ExtractorConfig } from "@microsoft/api-extractor";
import { buildWorkspaces } from "./build-workspaces.mjs";
import {
  discoverWorkspaces,
  isMainModule,
  orderWorkspacesTopologically,
  resolveTscBin
} from "./lib/workspaces.mjs";

const DEPENDENCY_WORKSPACE_ALLOWLIST = new Set([
  "@relayquill/domain",
  "@relayquill/contracts",
  "@relayquill/runtime",
  "@relayquill/event-schema",
  "@relayquill/egress",
  "@relayquill/signing",
  "@relayquill/broker",
  "@relayquill/auth"
]);

export const SDK_DEFINITIONS = Object.freeze([
  Object.freeze({
    name: "@relayquill/producer-sdk",
    relDir: "packages/producer-sdk",
    stageSlug: "producer-sdk",
    platform: "neutral",
    external: Object.freeze([]),
    forbidNodeBuiltins: true
  }),
  Object.freeze({
    name: "@relayquill/receiver-sdk",
    relDir: "packages/receiver-sdk",
    stageSlug: "receiver-sdk",
    platform: "node",
    external: Object.freeze(["node:*"]),
    forbidNodeBuiltins: false
  })
]);

function cleanSdkOutputs(sdkDir) {
  const distDir = path.join(sdkDir, "dist");
  const buildDir = path.join(sdkDir, "build");
  const typesDir = path.join(buildDir, "types");
  const apiReportDir = path.join(buildDir, "api-report");
  const apiReportTempDir = path.join(buildDir, "api-report-temp");
  const metafilePath = path.join(buildDir, "metafile.json");

  fs.rmSync(distDir, { recursive: true, force: true });
  fs.rmSync(typesDir, { recursive: true, force: true });
  fs.rmSync(apiReportDir, { recursive: true, force: true });
  fs.rmSync(apiReportTempDir, { recursive: true, force: true });
  fs.rmSync(metafilePath, { force: true });

  fs.mkdirSync(distDir, { recursive: true });
  fs.mkdirSync(apiReportDir, { recursive: true });
  fs.mkdirSync(apiReportTempDir, { recursive: true });

  return { distDir, buildDir, metafilePath };
}

function validateEmittedDeclarationRollup(sdkName, dtsPath) {
  if (!fs.existsSync(dtsPath)) {
    throw new Error(`[build-sdk] Missing rolled-up declaration file for ${sdkName}: ${dtsPath}`);
  }
  const content = fs.readFileSync(dtsPath, "utf8");
  if (content.trim().length === 0) {
    throw new Error(`[build-sdk] Empty declaration file emitted for ${sdkName}: ${dtsPath}`);
  }
  if (/["']@relayquill\//.test(content)) {
    throw new Error(
      `[build-sdk] Rolled-up declarations for ${sdkName} still contain unresolved "@relayquill/*" reference: ${dtsPath}`
    );
  }
}

function validateMetafileImports(sdk, metafile) {
  const outputs = Object.values(metafile?.outputs ?? {});
  if (outputs.length === 0) {
    throw new Error(`[build-sdk] esbuild emitted no outputs for ${sdk.name}`);
  }

  for (const outputObj of outputs) {
    for (const imp of outputObj?.imports ?? []) {
      const impPath = imp?.path;
      if (typeof impPath !== "string") {
        continue;
      }
      if (impPath.startsWith("./") || impPath.startsWith("../")) {
        continue;
      }
      if (impPath.startsWith("@relayquill/")) {
        throw new Error(
          `[build-sdk] Bundle for ${sdk.name} failed to inline internal package "${impPath}"`
        );
      }
      if (sdk.forbidNodeBuiltins && impPath.startsWith("node:")) {
        throw new Error(
          `[build-sdk] Portable bundle for ${sdk.name} contains forbidden Node built-in "${impPath}"`
        );
      }
      if (!sdk.forbidNodeBuiltins && !impPath.startsWith("node:")) {
        throw new Error(
          `[build-sdk] Self-contained bundle for ${sdk.name} contains unexpected external import "${impPath}"`
        );
      }
      if (sdk.forbidNodeBuiltins) {
        throw new Error(
          `[build-sdk] Self-contained bundle for ${sdk.name} contains unexpected external import "${impPath}"`
        );
      }
    }
  }
}

export async function buildSdks(rootDir, options = {}) {
  const resolvedRoot = path.resolve(rootDir);
  const quiet = Boolean(options.quiet);

  if (!options.skipDependencies) {
    const discovered = discoverWorkspaces(resolvedRoot);
    const activeSet = new Set(discovered.map((ws) => ws.name));
    const ordered = orderWorkspacesTopologically(resolvedRoot, { requireAll: false });
    const depsToBuild = ordered
      .map((ws) => ws.name)
      .filter((name) => activeSet.has(name) && DEPENDENCY_WORKSPACE_ALLOWLIST.has(name));

    if (depsToBuild.length > 0) {
      if (!quiet) {
        console.log(`[build-sdk] Building internal dependencies: ${depsToBuild.join(", ")}`);
      }
      buildWorkspaces(resolvedRoot, {
        workspaces: depsToBuild,
        quiet,
        stdio: quiet ? "pipe" : "inherit"
      });
    }
  }

  const tscBin = resolveTscBin(resolvedRoot);
  const results = [];

  for (const sdk of SDK_DEFINITIONS) {
    const sdkDir = path.join(resolvedRoot, sdk.relDir);
    if (!fs.existsSync(sdkDir)) {
      throw new Error(`[build-sdk] Missing SDK directory: ${sdkDir}`);
    }

    if (!quiet) {
      console.log(`[build-sdk] Preparing declarations & bundle for ${sdk.name}...`);
    }

    const { distDir, metafilePath } = cleanSdkOutputs(sdkDir);

    // 1. Emit build/types/*.d.ts cleanly via tsconfig.types.json
    const tsconfigTypesPath = path.join(sdkDir, "tsconfig.types.json");
    const tscRes = spawnSync(process.execPath, [tscBin, "-p", tsconfigTypesPath], {
      cwd: sdkDir,
      encoding: "utf8"
    });
    if (tscRes.status !== 0) {
      const output = [tscRes.stdout, tscRes.stderr].filter(Boolean).join("\n");
      throw new Error(`[build-sdk] Type emission failed for ${sdk.name}:\n${output}`);
    }

    // 2. Roll up and verify public types into dist/index.d.ts via API Extractor
    const extractorConfigPath = path.join(sdkDir, "api-extractor.json");
    const extractorConfig = ExtractorConfig.loadFileAndPrepare(extractorConfigPath);
    const extractorMessages = [];
    const extractorResult = Extractor.invoke(extractorConfig, {
      localBuild: true,
      showVerboseMessages: false,
      messageCallback(msg) {
        if (msg.logLevel === "error" || msg.logLevel === "warning") {
          extractorMessages.push(`[${msg.logLevel}] ${msg.messageId}: ${msg.text}`);
        }
        msg.handled = true;
      }
    });

    if (!extractorResult.succeeded || extractorResult.errorCount > 0) {
      throw new Error(
        `[build-sdk] API Extractor failed for ${sdk.name} (${extractorResult.errorCount} errors, ${extractorResult.warningCount} warnings):\n${extractorMessages.join("\n")}`
      );
    }

    const dtsOutPath = path.join(distDir, "index.d.ts");
    validateEmittedDeclarationRollup(sdk.name, dtsOutPath);

    // 3. Bundle self-contained ESM dist/index.js + sourcemap + build/metafile.json
    const jsOutPath = path.join(distDir, "index.js");
    const buildResult = await esbuild.build({
      entryPoints: [path.join(sdkDir, "src", "index.ts")],
      outfile: jsOutPath,
      bundle: true,
      format: "esm",
      platform: sdk.platform,
      target: ["es2023"],
      mainFields: ["module", "main"],
      conditions:
        sdk.platform === "neutral"
          ? ["import", "module", "default"]
          : ["node", "import", "module", "default"],
      sourcemap: true,
      metafile: true,
      absWorkingDir: resolvedRoot,
      external: [...sdk.external],
      logLevel: "silent"
    });

    if (buildResult.errors.length > 0) {
      throw new Error(
        `[build-sdk] esbuild failed for ${sdk.name}: ${buildResult.errors.map((e) => e.text).join("; ")}`
      );
    }

    validateMetafileImports(sdk, buildResult.metafile);
    fs.writeFileSync(metafilePath, `${JSON.stringify(buildResult.metafile, null, 2)}\n`, "utf8");

    const bundleStat = fs.statSync(jsOutPath);
    const dtsStat = fs.statSync(dtsOutPath);

    results.push({
      name: sdk.name,
      sdkDir,
      jsOutPath,
      dtsOutPath,
      metafilePath,
      bundleBytes: bundleStat.size,
      dtsBytes: dtsStat.size
    });

    if (!quiet) {
      console.log(
        `[build-sdk] ${sdk.name}: dist/index.js (${bundleStat.size}B), dist/index.d.ts (${dtsStat.size}B), build/metafile.json`
      );
    }
  }

  return { ok: true, sdks: results };
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
        throw new Error("--root requires a directory path");
      }
      rootDir = path.resolve(next);
      i += 1;
    } else {
      throw new Error(`Unknown CLI argument: ${arg}`);
    }
  }

  return { rootDir, skipDependencies, quiet };
}

if (isMainModule(import.meta.url)) {
  try {
    const opts = parseCliArgs(process.argv.slice(2));
    await buildSdks(opts.rootDir, opts);
  } catch (err) {
    console.error(err instanceof Error ? err.message : String(err));
    process.exit(1);
  }
}
