import { spawnSync } from "node:child_process";
import fs from "node:fs";
import { createRequire } from "node:module";
import path from "node:path";
import { fileURLToPath } from "node:url";

export const REVIEWED_WORKSPACE_ORDER = Object.freeze([
  // Tier 1: Shared Libraries
  "@relayquill/domain",
  "@relayquill/contracts",
  "@relayquill/event-schema",
  "@relayquill/egress",
  "@relayquill/signing",
  "@relayquill/broker",
  "@relayquill/runtime",
  "@relayquill/auth",
  "@relayquill/application",
  "@relayquill/postgres",
  "@relayquill/billing",
  // Tier 2: Public SDKs
  "@relayquill/producer-sdk",
  "@relayquill/receiver-sdk",
  // Tier 3: Server Applications & Examples
  "@relayquill/api",
  "@relayquill/relay",
  "@relayquill/fanout",
  "@relayquill/sender",
  "@relayquill/coordinator",
  "@relayquill/admin",
  "@relayquill/example-receiver",
  "@relayquill/example-provider-ingress",
  "@relayquill/example-producer",
  // Tier 4: Browser Console
  "@relayquill/console"
]);

const WORKSPACE_CATEGORIES = Object.freeze(["packages", "apps", "examples"]);
const INTERNAL_SCOPE_PREFIX = "@relayquill/";

function reviewedOrderIndex(name) {
  const idx = REVIEWED_WORKSPACE_ORDER.indexOf(name);
  return idx === -1 ? Number.MAX_SAFE_INTEGER : idx;
}

function compareWorkspaceNames(a, b) {
  const idxA = reviewedOrderIndex(a);
  const idxB = reviewedOrderIndex(b);
  if (idxA !== idxB) {
    return idxA - idxB;
  }
  return a.localeCompare(b);
}

export function isMainModule(importMetaUrl) {
  if (!process.argv[1]) {
    return false;
  }
  const metaPath = path.resolve(fileURLToPath(importMetaUrl));
  const argvPath = path.resolve(process.argv[1]);
  if (metaPath === argvPath) {
    return true;
  }
  try {
    return fs.realpathSync(metaPath) === fs.realpathSync(argvPath);
  } catch {
    return false;
  }
}

export function discoverWorkspaces(rootDir) {
  const resolvedRoot = path.resolve(rootDir);
  const discovered = [];
  const seenNames = new Map();

  for (const category of WORKSPACE_CATEGORIES) {
    const categoryDir = path.join(resolvedRoot, category);
    if (!fs.existsSync(categoryDir)) {
      continue;
    }
    const stat = fs.statSync(categoryDir);
    if (!stat.isDirectory()) {
      continue;
    }

    const entries = fs.readdirSync(categoryDir, { withFileTypes: true })
      .filter((entry) => entry.isDirectory())
      .sort((a, b) => a.name.localeCompare(b.name));

    for (const entry of entries) {
      const wsDir = path.join(categoryDir, entry.name);
      const pkgPath = path.join(wsDir, "package.json");
      if (!fs.existsSync(pkgPath)) {
        continue;
      }
      const raw = fs.readFileSync(pkgPath, "utf8");
      const pkg = JSON.parse(raw);
      if (typeof pkg.name !== "string" || pkg.name.length === 0) {
        throw new Error(`Workspace manifest missing valid "name": ${pkgPath}`);
      }
      if (seenNames.has(pkg.name)) {
        throw new Error(
          `Duplicate workspace name "${pkg.name}" in ${pkgPath} and ${seenNames.get(pkg.name)}`
        );
      }
      seenNames.set(pkg.name, pkgPath);
      discovered.push({
        name: pkg.name,
        category,
        dirName: entry.name,
        dirPath: wsDir,
        relPath: path.relative(resolvedRoot, wsDir).replace(/\\/g, "/"),
        pkg
      });
    }
  }

  return discovered.sort((a, b) => compareWorkspaceNames(a.name, b.name));
}

export function collectInternalDependencies(pkg, options = {}) {
  const includeDev = options.includeDev !== false;
  const sections = ["dependencies", "peerDependencies", "optionalDependencies"];
  if (includeDev) {
    sections.push("devDependencies");
  }
  const deps = new Set();
  for (const section of sections) {
    const map = pkg?.[section];
    if (!map || typeof map !== "object") {
      continue;
    }
    for (const depName of Object.keys(map)) {
      if (depName.startsWith(INTERNAL_SCOPE_PREFIX)) {
        deps.add(depName);
      }
    }
  }
  return Array.from(deps).sort();
}

export function findCycleInGraph(adjacency) {
  const WHITE = 0;
  const GRAY = 1;
  const BLACK = 2;
  const color = new Map();
  const stack = [];

  for (const node of adjacency.keys()) {
    color.set(node, WHITE);
  }

  function dfs(node) {
    color.set(node, GRAY);
    stack.push(node);

    const neighbors = Array.from(adjacency.get(node) ?? []).sort();
    for (const next of neighbors) {
      if (!adjacency.has(next)) {
        continue;
      }
      const nextColor = color.get(next) ?? WHITE;
      if (nextColor === GRAY) {
        const cycleStart = stack.indexOf(next);
        return [...stack.slice(cycleStart), next];
      }
      if (nextColor === WHITE) {
        const found = dfs(next);
        if (found) {
          return found;
        }
      }
    }

    stack.pop();
    color.set(node, BLACK);
    return null;
  }

  const nodes = Array.from(adjacency.keys()).sort();
  for (const node of nodes) {
    if (color.get(node) === WHITE) {
      const cycle = dfs(node);
      if (cycle) {
        return cycle;
      }
    }
  }
  return null;
}

export function orderWorkspacesTopologically(rootDir, options = {}) {
  const workspaces = discoverWorkspaces(rootDir);
  if (workspaces.length === 0) {
    throw new Error(`No workspaces found under ${path.resolve(rootDir)}`);
  }

  const byName = new Map(workspaces.map((ws) => [ws.name, ws]));

  if (options.requireAll) {
    const missing = REVIEWED_WORKSPACE_ORDER.filter((name) => !byName.has(name));
    if (missing.length > 0) {
      throw new Error(`Missing required workspaces: ${missing.join(", ")}`);
    }
  }

  // Adjacency: dep -> Set<dependent> for Kahn's topological sort
  const dependents = new Map();
  // Dependency graph: ws -> Set<dep> for cycle reporting
  const depGraph = new Map();
  const inDegree = new Map();

  for (const ws of workspaces) {
    dependents.set(ws.name, new Set());
    depGraph.set(ws.name, new Set());
    inDegree.set(ws.name, 0);
  }

  for (const ws of workspaces) {
    const deps = collectInternalDependencies(ws.pkg);
    for (const dep of deps) {
      if (dep === ws.name) {
        throw new Error(`Workspace dependency cycle detected: ${ws.name} -> ${ws.name}`);
      }
      if (!byName.has(dep)) {
        throw new Error(
          `Workspace "${ws.name}" declares missing internal dependency "${dep}"`
        );
      }
      depGraph.get(ws.name).add(dep);
      dependents.get(dep).add(ws.name);
      inDegree.set(ws.name, inDegree.get(ws.name) + 1);
    }
  }

  const ready = workspaces
    .filter((ws) => inDegree.get(ws.name) === 0)
    .map((ws) => ws.name)
    .sort(compareWorkspaceNames);

  const ordered = [];
  while (ready.length > 0) {
    const current = ready.shift();
    ordered.push(byName.get(current));
    for (const dependent of dependents.get(current)) {
      const nextDegree = inDegree.get(dependent) - 1;
      inDegree.set(dependent, nextDegree);
      if (nextDegree === 0) {
        ready.push(dependent);
        ready.sort(compareWorkspaceNames);
      }
    }
  }

  if (ordered.length !== workspaces.length) {
    const cycle = findCycleInGraph(depGraph);
    const detail = cycle ? cycle.join(" -> ") : "unknown cycle";
    throw new Error(`Workspace dependency cycle detected: ${detail}`);
  }

  return ordered;
}

export function resolveTscBin(rootDir) {
  const candidates = [];
  try {
    const requireFromRoot = createRequire(path.join(path.resolve(rootDir), "package.json"));
    candidates.push(requireFromRoot.resolve("typescript/bin/tsc"));
  } catch {
    // Fall through to direct node_modules and tooling-relative resolution
  }
  candidates.push(path.join(path.resolve(rootDir), "node_modules", "typescript", "bin", "tsc"));
  try {
    const requireFromHere = createRequire(import.meta.url);
    candidates.push(requireFromHere.resolve("typescript/bin/tsc"));
  } catch {
    // Ignore
  }

  for (const candidate of candidates) {
    if (fs.existsSync(candidate)) {
      return candidate;
    }
  }
  throw new Error("Unable to locate typescript/bin/tsc");
}

export function resolveNpmCli() {
  const execPath = process.env.npm_execpath;
  if (
    typeof execPath === "string" &&
    /\.(?:mjs|cjs|js)$/i.test(execPath) &&
    fs.existsSync(execPath)
  ) {
    return execPath;
  }
  const nodeDir = path.dirname(process.execPath);
  const candidates = [
    path.resolve(nodeDir, "node_modules", "npm", "bin", "npm-cli.js"),
    path.resolve(nodeDir, "..", "lib", "node_modules", "npm", "bin", "npm-cli.js")
  ];
  for (const candidate of candidates) {
    if (fs.existsSync(candidate)) {
      return candidate;
    }
  }
  return null;
}

export function runNodeScript(scriptPath, args, options = {}) {
  const result = spawnSync(process.execPath, [scriptPath, ...args], {
    cwd: options.cwd,
    stdio: options.stdio ?? "inherit",
    encoding: "utf8",
    env: options.env ?? process.env
  });
  if (result.error) {
    throw result.error;
  }
  return result;
}

export function runNpm(rootDir, args, options = {}) {
  const npmCli = resolveNpmCli();
  if (npmCli) {
    return runNodeScript(npmCli, args, {
      cwd: options.cwd ?? rootDir,
      stdio: options.stdio,
      env: options.env
    });
  }
  const result = spawnSync("npm", args, {
    cwd: options.cwd ?? rootDir,
    stdio: options.stdio ?? "inherit",
    encoding: "utf8",
    shell: process.platform === "win32",
    env: options.env ?? process.env
  });
  if (result.error) {
    throw result.error;
  }
  return result;
}

export function parseCommonCliArgs(argv) {
  let rootDir = process.cwd();
  let requireAll = false;
  let force = false;
  const workspaces = [];

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--root") {
      const next = argv[++i];
      if (!next) {
        throw new Error("--root requires a directory argument");
      }
      rootDir = path.resolve(next);
    } else if (arg === "--require-all") {
      requireAll = true;
    } else if (arg === "--force") {
      force = true;
    } else if (arg === "--workspace" || arg === "-w") {
      const next = argv[++i];
      if (!next) {
        throw new Error(`${arg} requires a workspace name`);
      }
      workspaces.push(next);
    } else {
      throw new Error(`Unknown argument: ${arg}`);
    }
  }

  return { rootDir, requireAll, force, workspaces };
}
