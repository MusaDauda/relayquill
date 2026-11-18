import fs from "node:fs";
import path from "node:path";
import ts from "typescript";
import {
  REVIEWED_WORKSPACE_ORDER,
  isMainModule,
  orderWorkspacesTopologically,
  parseCommonCliArgs,
  resolveTscBin,
  runNodeScript,
  runNpm
} from "./lib/workspaces.mjs";

function readTsConfig(tsconfigPath) {
  const parsed = ts.readConfigFile(tsconfigPath, (filePath) => ts.sys.readFile(filePath));
  if (parsed.error) {
    const msg = ts.flattenDiagnosticMessageText(parsed.error.messageText, "\n");
    throw new Error(`Failed to parse ${tsconfigPath}: ${msg}`);
  }
  return parsed.config ?? {};
}

export function typecheckWorkspaces(rootDir, options = {}) {
  const resolvedRoot = path.resolve(rootDir);
  const ordered = orderWorkspacesTopologically(resolvedRoot, {
    requireAll: Boolean(options.requireAll)
  });

  const activeNames = new Set(ordered.map((ws) => ws.name));
  const requested = Array.isArray(options.workspaces) ? options.workspaces : [];
  if (requested.length > 0) {
    for (const req of requested) {
      if (!activeNames.has(req)) {
        throw new Error(`Requested workspace not found: ${req}`);
      }
    }
  }

  if (!options.requireAll && requested.length === 0 && !options.quiet) {
    const absent = REVIEWED_WORKSPACE_ORDER.filter((name) => !activeNames.has(name));
    if (absent.length > 0) {
      console.log(`[typecheck] skipping absent workspaces (${absent.length}): ${absent.join(", ")}`);
    }
  }

  const tscBin = resolveTscBin(resolvedRoot);
  const targets = requested.length > 0
    ? ordered.filter((ws) => requested.includes(ws.name))
    : ordered;

  const checked = [];
  for (const ws of targets) {
    const tsconfigPath = path.join(ws.dirPath, "tsconfig.json");
    if (!fs.existsSync(tsconfigPath)) {
      if (typeof ws.pkg.scripts?.typecheck === "string" && ws.pkg.scripts.typecheck.trim().length > 0) {
        if (!options.quiet) {
          console.log(`[typecheck] ${ws.name} (npm script)`);
        }
        const res = runNpm(resolvedRoot, ["run", "typecheck", "--workspace", ws.name], {
          cwd: resolvedRoot,
          stdio: options.stdio ?? "inherit"
        });
        if (res.status !== 0) {
          const code = typeof res.status === "number" ? res.status : 1;
          const err = new Error(`[typecheck] FAILED: ${ws.name} (exit ${code})`);
          err.exitCode = code;
          throw err;
        }
        checked.push(ws.name);
        continue;
      }
      throw new Error(`[typecheck] workspace "${ws.name}" is missing tsconfig.json and typecheck script`);
    }

    const config = readTsConfig(tsconfigPath);
    const isComposite = config?.compilerOptions?.composite === true;
    const tscArgs = isComposite
      ? (options.force ? ["-b", "--force", tsconfigPath] : ["-b", tsconfigPath])
      : ["--noEmit", "-p", tsconfigPath];

    if (!options.quiet) {
      console.log(`[typecheck] ${ws.name} (${isComposite ? "tsc -b" : "tsc --noEmit"})`);
    }
    const result = runNodeScript(tscBin, tscArgs, {
      cwd: resolvedRoot,
      stdio: options.stdio ?? "inherit"
    });
    if (result.status !== 0) {
      const code = typeof result.status === "number" ? result.status : 1;
      const err = new Error(`[typecheck] FAILED: ${ws.name} (exit ${code})`);
      err.exitCode = code;
      throw err;
    }

    const typesTsConfig = path.join(ws.dirPath, "tsconfig.types.json");
    if (fs.existsSync(typesTsConfig)) {
      const typesRes = runNodeScript(tscBin, ["--noEmit", "-p", typesTsConfig], {
        cwd: resolvedRoot,
        stdio: options.stdio ?? "inherit"
      });
      if (typesRes.status !== 0) {
        const code = typeof typesRes.status === "number" ? typesRes.status : 1;
        const err = new Error(`[typecheck] FAILED (tsconfig.types.json): ${ws.name} (exit ${code})`);
        err.exitCode = code;
        throw err;
      }
    }

    checked.push(ws.name);
  }

  return { ok: true, checked };
}

if (isMainModule(import.meta.url)) {
  try {
    const args = parseCommonCliArgs(process.argv.slice(2));
    const res = typecheckWorkspaces(args.rootDir, {
      requireAll: args.requireAll,
      workspaces: args.workspaces,
      force: args.force
    });
    console.log(`[typecheck] succeeded (${res.checked.length} workspaces)`);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    console.error(message);
    const code =
      typeof err === "object" && err !== null && "exitCode" in err && typeof err.exitCode === "number"
        ? err.exitCode
        : 1;
    process.exit(code);
  }
}
