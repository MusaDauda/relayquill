import path from "node:path";
import {
  REVIEWED_WORKSPACE_ORDER,
  isMainModule,
  orderWorkspacesTopologically,
  parseCommonCliArgs,
  runNpm
} from "./lib/workspaces.mjs";

export function buildWorkspaces(rootDir, options = {}) {
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
      console.log(`[build] skipping absent workspaces (${absent.length}): ${absent.join(", ")}`);
    }
  }

  const targets = requested.length > 0
    ? ordered.filter((ws) => requested.includes(ws.name))
    : ordered;

  const built = [];
  for (const ws of targets) {
    if (typeof ws.pkg.scripts?.build !== "string" || ws.pkg.scripts.build.trim().length === 0) {
      throw new Error(`[build] workspace "${ws.name}" is missing a "build" script`);
    }
    if (!options.quiet) {
      console.log(`[build] ${ws.name} (${ws.relPath})`);
    }
    const result = runNpm(resolvedRoot, ["run", "build", "--workspace", ws.name], {
      cwd: resolvedRoot,
      stdio: options.stdio ?? "inherit"
    });
    if (result.status !== 0) {
      const code = typeof result.status === "number" ? result.status : 1;
      const err = new Error(`[build] FAILED: ${ws.name} (exit ${code})`);
      err.exitCode = code;
      throw err;
    }
    built.push(ws.name);
  }

  return { ok: true, built };
}

if (isMainModule(import.meta.url)) {
  try {
    const args = parseCommonCliArgs(process.argv.slice(2));
    const res = buildWorkspaces(args.rootDir, {
      requireAll: args.requireAll,
      workspaces: args.workspaces
    });
    console.log(`[build] succeeded (${res.built.length} workspaces)`);
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
