import fs from "node:fs";
import { builtinModules } from "node:module";
import path from "node:path";
import ts from "typescript";
import {
  collectInternalDependencies,
  discoverWorkspaces,
  findCycleInGraph,
  isMainModule,
  parseCommonCliArgs
} from "./lib/workspaces.mjs";

const NODE_BUILTIN_SET = new Set([
  ...builtinModules,
  ...builtinModules.map((mod) => (mod.startsWith("node:") ? mod.slice(5) : `node:${mod}`))
]);

const ALL_APPS = [
  "@relayquill/api",
  "@relayquill/relay",
  "@relayquill/fanout",
  "@relayquill/sender",
  "@relayquill/coordinator",
  "@relayquill/admin",
  "@relayquill/console"
];

const ALL_EXAMPLES = [
  "@relayquill/example-receiver",
  "@relayquill/example-provider-ingress",
  "@relayquill/example-producer"
];

const PRIVATE_SERVER_LIBS = [
  "@relayquill/postgres",
  "@relayquill/application",
  "@relayquill/auth",
  "@relayquill/egress",
  "@relayquill/broker",
  "@relayquill/signing"
];

const UI_LIBS = ["react", "react-dom", "vite", "@vitejs/*"];
const DB_LIBS = ["pg", "pg-*", "@electric-sql/*"];
const BROKER_LIBS = ["@nats-io/*"];
const HTTP_SERVER_LIBS = ["fastify", "@fastify/*"];

export const WORKSPACE_POLICIES = Object.freeze({
  "@relayquill/domain": {
    allowedInternal: [],
    forbidAllNodeBuiltins: true,
    forbiddenPackages: [...HTTP_SERVER_LIBS, ...DB_LIBS, ...BROKER_LIBS, ...UI_LIBS, "@simplewebauthn/*", "stripe"]
  },
  "@relayquill/contracts": {
    allowedInternal: ["@relayquill/domain"],
    forbidAllNodeBuiltins: true,
    forbiddenPackages: [...HTTP_SERVER_LIBS, ...DB_LIBS, ...BROKER_LIBS, ...UI_LIBS, "@simplewebauthn/*", "stripe"]
  },
  "@relayquill/runtime": {
    allowedInternal: ["@relayquill/domain", "@relayquill/contracts"],
    forbidAllNodeBuiltins: false,
    forbiddenPackages: [...HTTP_SERVER_LIBS, ...DB_LIBS, ...BROKER_LIBS, ...UI_LIBS, "@simplewebauthn/*", "stripe"]
  },
  "@relayquill/event-schema": {
    allowedInternal: ["@relayquill/domain", "@relayquill/contracts", "@relayquill/runtime"],
    forbidAllNodeBuiltins: false,
    forbiddenPackages: [...HTTP_SERVER_LIBS, ...DB_LIBS, ...BROKER_LIBS, ...UI_LIBS, "@simplewebauthn/*", "stripe"]
  },
  "@relayquill/egress": {
    allowedInternal: ["@relayquill/domain", "@relayquill/contracts", "@relayquill/runtime"],
    forbidAllNodeBuiltins: false,
    forbiddenPackages: [...HTTP_SERVER_LIBS, ...DB_LIBS, ...BROKER_LIBS, ...UI_LIBS, "@simplewebauthn/*", "stripe"]
  },
  "@relayquill/signing": {
    allowedInternal: ["@relayquill/domain", "@relayquill/contracts", "@relayquill/runtime"],
    forbidAllNodeBuiltins: false,
    forbiddenPackages: [...HTTP_SERVER_LIBS, ...DB_LIBS, ...BROKER_LIBS, ...UI_LIBS, "@simplewebauthn/*", "stripe"]
  },
  "@relayquill/broker": {
    allowedInternal: ["@relayquill/domain", "@relayquill/contracts", "@relayquill/runtime"],
    forbidAllNodeBuiltins: false,
    forbiddenPackages: [...HTTP_SERVER_LIBS, ...DB_LIBS, ...UI_LIBS, "@simplewebauthn/*", "stripe"]
  },
  "@relayquill/auth": {
    allowedInternal: ["@relayquill/domain", "@relayquill/contracts", "@relayquill/runtime"],
    forbidAllNodeBuiltins: false,
    forbiddenPackages: [...HTTP_SERVER_LIBS, ...DB_LIBS, ...BROKER_LIBS, ...UI_LIBS, "stripe"]
  },
  "@relayquill/application": {
    allowedInternal: [
      "@relayquill/domain",
      "@relayquill/contracts",
      "@relayquill/auth",
      "@relayquill/event-schema",
      "@relayquill/signing",
      "@relayquill/egress",
      "@relayquill/broker",
      "@relayquill/runtime"
    ],
    forbidAllNodeBuiltins: false,
    forbiddenPackages: ["@relayquill/postgres", ...HTTP_SERVER_LIBS, ...DB_LIBS, ...UI_LIBS]
  },
  "@relayquill/postgres": {
    allowedInternal: [
      "@relayquill/domain",
      "@relayquill/contracts",
      "@relayquill/application",
      "@relayquill/auth",
      "@relayquill/runtime"
    ],
    forbidAllNodeBuiltins: false,
    forbiddenPackages: [...HTTP_SERVER_LIBS, ...BROKER_LIBS, ...UI_LIBS, "@simplewebauthn/*"]
  },
  "@relayquill/producer-sdk": {
    allowedInternal: ["@relayquill/domain", "@relayquill/contracts"],
    forbidAllNodeBuiltins: true,
    forbiddenPackages: [
      ...HTTP_SERVER_LIBS,
      ...DB_LIBS,
      ...BROKER_LIBS,
      ...UI_LIBS,
      "@relayquill/runtime",
      ...PRIVATE_SERVER_LIBS
    ]
  },
  "@relayquill/receiver-sdk": {
    allowedInternal: ["@relayquill/domain", "@relayquill/contracts", "@relayquill/signing"],
    forbidAllNodeBuiltins: false,
    forbiddenPackages: [
      ...HTTP_SERVER_LIBS,
      ...DB_LIBS,
      ...BROKER_LIBS,
      ...UI_LIBS,
      "@relayquill/runtime",
      "@relayquill/postgres",
      "@relayquill/application",
      "@relayquill/auth",
      "@relayquill/egress",
      "@relayquill/broker"
    ]
  },
  "@relayquill/console": {
    allowedInternal: ["@relayquill/domain", "@relayquill/contracts", "@relayquill/producer-sdk"],
    forbidAllNodeBuiltins: true,
    forbiddenPackages: [
      ...HTTP_SERVER_LIBS,
      ...DB_LIBS,
      ...BROKER_LIBS,
      "@relayquill/runtime",
      ...PRIVATE_SERVER_LIBS,
      "@relayquill/receiver-sdk",
      "@simplewebauthn/server",
      "stripe"
    ]
  },
  "@relayquill/api": {
    allowedInternal: [
      "@relayquill/domain",
      "@relayquill/contracts",
      "@relayquill/runtime",
      "@relayquill/auth",
      "@relayquill/application",
      "@relayquill/postgres",
      "@relayquill/event-schema",
      "@relayquill/signing"
    ],
    forbidAllNodeBuiltins: false,
    forbiddenPackages: [
      ...ALL_APPS.filter((name) => name !== "@relayquill/api"),
      ...ALL_EXAMPLES,
      ...UI_LIBS,
      "@relayquill/producer-sdk",
      "@relayquill/receiver-sdk",
      "@relayquill/broker",
      "@relayquill/egress",
      ...BROKER_LIBS
    ]
  },
  "@relayquill/relay": {
    allowedInternal: [
      "@relayquill/domain",
      "@relayquill/contracts",
      "@relayquill/runtime",
      "@relayquill/application",
      "@relayquill/postgres",
      "@relayquill/broker"
    ],
    forbidAllNodeBuiltins: false,
    forbiddenPackages: [
      ...ALL_APPS.filter((name) => name !== "@relayquill/relay"),
      ...ALL_EXAMPLES,
      ...UI_LIBS,
      ...HTTP_SERVER_LIBS,
      "@relayquill/egress",
      "@relayquill/signing",
      "@relayquill/auth"
    ]
  },
  "@relayquill/fanout": {
    allowedInternal: [
      "@relayquill/domain",
      "@relayquill/contracts",
      "@relayquill/runtime",
      "@relayquill/application",
      "@relayquill/postgres",
      "@relayquill/broker",
      "@relayquill/event-schema"
    ],
    forbidAllNodeBuiltins: false,
    forbiddenPackages: [
      ...ALL_APPS.filter((name) => name !== "@relayquill/fanout"),
      ...ALL_EXAMPLES,
      ...UI_LIBS,
      ...HTTP_SERVER_LIBS,
      "@relayquill/egress",
      "@relayquill/signing",
      "@relayquill/auth"
    ]
  },
  "@relayquill/sender": {
    allowedInternal: [
      "@relayquill/domain",
      "@relayquill/contracts",
      "@relayquill/runtime",
      "@relayquill/application",
      "@relayquill/postgres",
      "@relayquill/egress",
      "@relayquill/signing"
    ],
    forbidAllNodeBuiltins: false,
    forbiddenPackages: [
      ...ALL_APPS.filter((name) => name !== "@relayquill/sender"),
      ...ALL_EXAMPLES,
      ...UI_LIBS,
      ...HTTP_SERVER_LIBS,
      ...BROKER_LIBS,
      "@relayquill/broker",
      "@relayquill/auth"
    ]
  },
  "@relayquill/coordinator": {
    allowedInternal: [
      "@relayquill/domain",
      "@relayquill/contracts",
      "@relayquill/runtime",
      "@relayquill/application",
      "@relayquill/postgres",
      "@relayquill/broker"
    ],
    forbidAllNodeBuiltins: false,
    forbiddenPackages: [
      ...ALL_APPS.filter((name) => name !== "@relayquill/coordinator"),
      ...ALL_EXAMPLES,
      ...UI_LIBS,
      ...HTTP_SERVER_LIBS,
      "@relayquill/egress",
      "@relayquill/auth"
    ]
  },
  "@relayquill/admin": {
    allowedInternal: [
      "@relayquill/domain",
      "@relayquill/contracts",
      "@relayquill/runtime",
      "@relayquill/auth",
      "@relayquill/application",
      "@relayquill/postgres",
      "@relayquill/broker",
      "@relayquill/signing"
    ],
    forbidAllNodeBuiltins: false,
    forbiddenPackages: [
      ...ALL_APPS.filter((name) => name !== "@relayquill/admin"),
      ...ALL_EXAMPLES,
      ...UI_LIBS,
      ...HTTP_SERVER_LIBS
    ]
  },
  "@relayquill/example-receiver": {
    allowedInternal: ["@relayquill/domain", "@relayquill/contracts", "@relayquill/receiver-sdk", "@relayquill/runtime"],
    forbidAllNodeBuiltins: false,
    forbiddenPackages: [
      ...ALL_APPS,
      ...ALL_EXAMPLES.filter((name) => name !== "@relayquill/example-receiver"),
      ...UI_LIBS,
      ...PRIVATE_SERVER_LIBS,
      ...BROKER_LIBS
    ]
  },
  "@relayquill/example-provider-ingress": {
    allowedInternal: ["@relayquill/domain", "@relayquill/contracts", "@relayquill/producer-sdk", "@relayquill/runtime"],
    forbidAllNodeBuiltins: false,
    forbiddenPackages: [
      ...ALL_APPS,
      ...ALL_EXAMPLES.filter((name) => name !== "@relayquill/example-provider-ingress"),
      ...UI_LIBS,
      ...PRIVATE_SERVER_LIBS,
      ...BROKER_LIBS
    ]
  },
  "@relayquill/example-producer": {
    allowedInternal: ["@relayquill/domain", "@relayquill/contracts", "@relayquill/producer-sdk"],
    forbidAllNodeBuiltins: false,
    forbiddenPackages: [
      ...ALL_APPS,
      ...ALL_EXAMPLES.filter((name) => name !== "@relayquill/example-producer"),
      ...UI_LIBS,
      ...PRIVATE_SERVER_LIBS,
      ...DB_LIBS,
      ...BROKER_LIBS,
      "@relayquill/runtime"
    ]
  }
});

const SOURCE_EXTENSIONS = new Set([".ts", ".tsx", ".mts", ".cts", ".js", ".mjs", ".cjs"]);

function getScriptKind(filePath) {
  const ext = path.extname(filePath).toLowerCase();
  if (ext === ".tsx") {
    return ts.ScriptKind.TSX;
  }
  if (ext === ".jsx") {
    return ts.ScriptKind.JSX;
  }
  if (ext === ".js" || ext === ".mjs" || ext === ".cjs") {
    return ts.ScriptKind.JS;
  }
  return ts.ScriptKind.TS;
}

export function extractModuleSpecifiers(filePath, content) {
  const sourceFile = ts.createSourceFile(
    filePath,
    content,
    ts.ScriptTarget.Latest,
    true,
    getScriptKind(filePath)
  );
  const specifiers = [];

  function record(specifier, node, kind) {
    const { line } = sourceFile.getLineAndCharacterOfPosition(node.getStart(sourceFile));
    specifiers.push({ specifier, line: line + 1, kind });
  }

  function visit(node) {
    if (ts.isImportDeclaration(node) && ts.isStringLiteralLike(node.moduleSpecifier)) {
      record(node.moduleSpecifier.text, node, "import");
    } else if (ts.isExportDeclaration(node) && node.moduleSpecifier && ts.isStringLiteralLike(node.moduleSpecifier)) {
      record(node.moduleSpecifier.text, node, "export");
    } else if (
      ts.isImportEqualsDeclaration(node) &&
      ts.isExternalModuleReference(node.moduleReference) &&
      ts.isStringLiteralLike(node.moduleReference.expression)
    ) {
      record(node.moduleReference.expression.text, node, "import_equals");
    } else if (
      ts.isImportTypeNode(node) &&
      ts.isLiteralTypeNode(node.argument) &&
      ts.isStringLiteralLike(node.argument.literal)
    ) {
      record(node.argument.literal.text, node, "import_type");
    } else if (ts.isCallExpression(node) && node.arguments.length >= 1) {
      const firstArg = node.arguments[0];
      if (node.expression.kind === ts.SyntaxKind.ImportKeyword && firstArg && ts.isStringLiteralLike(firstArg)) {
        record(firstArg.text, node, "dynamic_import");
      } else if (
        ts.isIdentifier(node.expression) &&
        node.expression.text === "require" &&
        firstArg &&
        ts.isStringLiteralLike(firstArg)
      ) {
        record(firstArg.text, node, "require");
      } else if (
        ts.isPropertyAccessExpression(node.expression) &&
        ts.isIdentifier(node.expression.name) &&
        firstArg &&
        ts.isStringLiteralLike(firstArg)
      ) {
        const propName = node.expression.name.text;
        const targetExpr = node.expression.expression;
        if (
          propName === "getBuiltinModule" &&
          ((ts.isIdentifier(targetExpr) && targetExpr.text === "process") ||
            (ts.isPropertyAccessExpression(targetExpr) &&
              ts.isIdentifier(targetExpr.name) &&
              targetExpr.name.text === "process"))
        ) {
          record(firstArg.text, node, "get_builtin_module");
        } else if (propName === "resolve" && ts.isIdentifier(targetExpr) && targetExpr.text === "require") {
          record(firstArg.text, node, "require_resolve");
        }
      }
    }
    ts.forEachChild(node, visit);
  }

  visit(sourceFile);
  return specifiers;
}

export function detectWorkspaceCycles(graph) {
  const cycles = [];
  const WHITE = 0;
  const GRAY = 1;
  const BLACK = 2;
  const color = new Map();
  const stack = [];
  const seenSignatures = new Set();

  for (const node of graph.keys()) {
    color.set(node, WHITE);
  }

  function dfs(node) {
    color.set(node, GRAY);
    stack.push(node);

    const neighbors = Array.from(graph.get(node) ?? []).sort();
    for (const next of neighbors) {
      if (!graph.has(next)) {
        continue;
      }
      const nextColor = color.get(next) ?? WHITE;
      if (nextColor === GRAY) {
        const idx = stack.indexOf(next);
        const cycle = [...stack.slice(idx), next];
        const sig = cycle.join("->");
        if (!seenSignatures.has(sig)) {
          seenSignatures.add(sig);
          cycles.push(cycle);
        }
      } else if (nextColor === WHITE) {
        dfs(next);
      }
    }

    stack.pop();
    color.set(node, BLACK);
  }

  for (const node of Array.from(graph.keys()).sort()) {
    if (color.get(node) === WHITE) {
      dfs(node);
    }
  }
  return cycles;
}

function walkSourceFiles(dirPath) {
  if (!fs.existsSync(dirPath)) {
    return [];
  }
  const files = [];
  const stack = [dirPath];
  while (stack.length > 0) {
    const current = stack.pop();
    const entries = fs.readdirSync(current, { withFileTypes: true })
      .sort((a, b) => a.name.localeCompare(b.name));
    for (const entry of entries) {
      if (entry.name === "node_modules" || entry.name === "dist" || entry.name === "build") {
        continue;
      }
      const fullPath = path.join(current, entry.name);
      if (entry.isDirectory()) {
        stack.push(fullPath);
      } else if (entry.isFile() && SOURCE_EXTENSIONS.has(path.extname(entry.name).toLowerCase())) {
        files.push(fullPath);
      }
    }
  }
  return files.sort();
}

function getPackageNameFromSpecifier(specifier) {
  if (specifier.startsWith("node:")) {
    return specifier;
  }
  if (specifier.startsWith("@")) {
    const parts = specifier.split("/");
    return parts.length >= 2 ? `${parts[0]}/${parts[1]}` : specifier;
  }
  const slashIdx = specifier.indexOf("/");
  return slashIdx === -1 ? specifier : specifier.slice(0, slashIdx);
}

function matchesPattern(pkgName, pattern) {
  if (pattern.endsWith("/*")) {
    const prefix = pattern.slice(0, -1);
    return pkgName.startsWith(prefix);
  }
  if (pattern.endsWith("*")) {
    const prefix = pattern.slice(0, -1);
    return pkgName.startsWith(prefix);
  }
  return pkgName === pattern;
}

function checkForbiddenPackage(policy, pkgName) {
  if (!policy) {
    return null;
  }
  if (policy.forbidAllNodeBuiltins && NODE_BUILTIN_SET.has(pkgName)) {
    return `Node built-in "${pkgName}" is forbidden in this workspace`;
  }
  for (const pattern of policy.forbiddenPackages) {
    if (matchesPattern(pkgName, pattern)) {
      return `Package "${pkgName}" matches forbidden policy "${pattern}"`;
    }
  }
  return null;
}

function isRelativeSpecifier(specifier) {
  return specifier === "." || specifier === ".." || specifier.startsWith("./") || specifier.startsWith("../");
}

function isPathInside(parentDir, candidatePath) {
  const rel = path.relative(parentDir, candidatePath);
  return rel === "" || (!rel.startsWith("..") && !path.isAbsolute(rel));
}

function readTsConfigReferences(ws, byDirPath) {
  const tsconfigPath = path.join(ws.dirPath, "tsconfig.json");
  if (!fs.existsSync(tsconfigPath)) {
    return [];
  }
  const parsed = ts.readConfigFile(tsconfigPath, (p) => ts.sys.readFile(p));
  if (parsed.error || !Array.isArray(parsed.config?.references)) {
    return [];
  }
  const refs = [];
  for (const ref of parsed.config.references) {
    if (ref && typeof ref.path === "string") {
      const targetPath = path.resolve(ws.dirPath, ref.path);
      const targetDir = targetPath.toLowerCase().endsWith(".json")
        ? path.dirname(targetPath)
        : targetPath;
      const targetWs = byDirPath.get(targetDir);
      if (targetWs) {
        refs.push(targetWs.name);
      }
    }
  }
  return refs;
}

function extractPackageNameFromMetafileInput(inputPath) {
  const normalized = inputPath.replace(/\\/g, "/");
  const nmMarker = "node_modules/";
  const idx = normalized.lastIndexOf(nmMarker);
  if (idx === -1) {
    return null;
  }
  const rest = normalized.slice(idx + nmMarker.length);
  return getPackageNameFromSpecifier(rest);
}

export function verifyWorkspaceBoundaries(rootDir) {
  const resolvedRoot = path.resolve(rootDir);
  const workspaces = discoverWorkspaces(resolvedRoot);
  if (workspaces.length === 0) {
    return {
      ok: false,
      workspacesChecked: 0,
      filesScanned: 0,
      violations: [
        {
          type: "empty_workspace_tree",
          workspace: "<root>",
          file: "package.json",
          line: 1,
          specifier: "",
          message: `No workspaces found under ${resolvedRoot}`
        }
      ]
    };
  }

  const byName = new Map(workspaces.map((ws) => [ws.name, ws]));
  const byDirPath = new Map(workspaces.map((ws) => [path.resolve(ws.dirPath), ws]));
  const graph = new Map();
  const violations = [];
  let filesScanned = 0;

  for (const ws of workspaces) {
    graph.set(ws.name, new Set());
  }

  for (const ws of workspaces) {
    const policy = WORKSPACE_POLICIES[ws.name];
    const pkgJsonRel = `${ws.relPath}/package.json`;

    if (!policy) {
      violations.push({
        type: "missing_policy",
        workspace: ws.name,
        file: pkgJsonRel,
        line: 1,
        specifier: ws.name,
        message: `Workspace "${ws.name}" is not registered in WORKSPACE_POLICIES`
      });
    }

    // 1. Check package.json dependencies
    const depSections = ["dependencies", "peerDependencies", "optionalDependencies", "devDependencies"];
    const declaredRuntimeInternal = new Set(
      collectInternalDependencies(ws.pkg, { includeDev: true })
    );

    for (const section of depSections) {
      const map = ws.pkg?.[section];
      if (!map || typeof map !== "object") {
        continue;
      }
      for (const depName of Object.keys(map)) {
        if (depName === ws.name) {
          violations.push({
            type: "self_import",
            workspace: ws.name,
            file: pkgJsonRel,
            line: 1,
            specifier: depName,
            message: `Workspace "${ws.name}" declares a self-dependency in ${section}`
          });
          continue;
        }
        if (depName.startsWith("@relayquill/")) {
          graph.get(ws.name).add(depName);
          if (policy && !policy.allowedInternal.includes(depName)) {
            violations.push({
              type: "forbidden_dependency",
              workspace: ws.name,
              file: pkgJsonRel,
              line: 1,
              specifier: depName,
              message: `Internal dependency "${depName}" is not allowed in "${ws.name}"`
            });
          }
        }
        const forbiddenMsg = checkForbiddenPackage(policy, depName);
        if (forbiddenMsg) {
          violations.push({
            type: "forbidden_dependency",
            workspace: ws.name,
            file: pkgJsonRel,
            line: 1,
            specifier: depName,
            message: `${forbiddenMsg} (declared in ${section})`
          });
        }
      }
    }

    // Add tsconfig references into cycle graph
    for (const refName of readTsConfigReferences(ws, byDirPath)) {
      graph.get(ws.name).add(refName);
    }

    // 2. AST scan of src/ files
    const srcDir = path.join(ws.dirPath, "src");
    const srcFiles = walkSourceFiles(srcDir);
    for (const filePath of srcFiles) {
      filesScanned += 1;
      const relFile = path.relative(resolvedRoot, filePath).replace(/\\/g, "/");
      const content = fs.readFileSync(filePath, "utf8");
      const specifiers = extractModuleSpecifiers(filePath, content);

      for (const { specifier, line } of specifiers) {
        if (isRelativeSpecifier(specifier)) {
          const targetPath = path.resolve(path.dirname(filePath), specifier);
          if (!isPathInside(ws.dirPath, targetPath)) {
            violations.push({
              type: "relative_escape",
              workspace: ws.name,
              file: relFile,
              line,
              specifier,
              message: `Relative import "${specifier}" escapes workspace "${ws.name}"`
            });
          }
          continue;
        }

        const pkgName = getPackageNameFromSpecifier(specifier);
        if (pkgName.startsWith("@relayquill/")) {
          if (pkgName === ws.name) {
            violations.push({
              type: "self_import",
              workspace: ws.name,
              file: relFile,
              line,
              specifier,
              message: `Workspace "${ws.name}" cannot import itself via package specifier "${specifier}"`
            });
            continue;
          }

          graph.get(ws.name).add(pkgName);

          // Check private subpath (anything beyond @relayquill/<pkg>)
          if (specifier !== pkgName) {
            const targetWs = byName.get(pkgName);
            const subpath = `./${specifier.slice(pkgName.length + 1)}`;
            const exportsObj = targetWs?.pkg?.exports;
            const hasExport =
              exportsObj &&
              typeof exportsObj === "object" &&
              Object.prototype.hasOwnProperty.call(exportsObj, subpath);
            if (!hasExport) {
              violations.push({
                type: "private_subpath",
                workspace: ws.name,
                file: relFile,
                line,
                specifier,
                message: `Private subpath import "${specifier}" into "${pkgName}" is forbidden`
              });
            }
          }

          // Check declared in package.json
          if (!declaredRuntimeInternal.has(pkgName)) {
            violations.push({
              type: "undeclared_import",
              workspace: ws.name,
              file: relFile,
              line,
              specifier,
              message: `Internal import "${pkgName}" is not declared in ${pkgJsonRel}`
            });
          }

          // Check layer allowlist
          if (policy && !policy.allowedInternal.includes(pkgName)) {
            violations.push({
              type: "forbidden_import",
              workspace: ws.name,
              file: relFile,
              line,
              specifier,
              message: `Internal import "${pkgName}" is forbidden in "${ws.name}"`
            });
          }
        }

        const forbiddenMsg = checkForbiddenPackage(policy, pkgName);
        if (forbiddenMsg) {
          violations.push({
            type: "forbidden_import",
            workspace: ws.name,
            file: relFile,
            line,
            specifier,
            message: forbiddenMsg
          });
        }
      }
    }

    // 3. Optional SDK esbuild metafile check
    const metafilePath = path.join(ws.dirPath, "build", "metafile.json");
    if (fs.existsSync(metafilePath)) {
      const metafileRel = path.relative(resolvedRoot, metafilePath).replace(/\\/g, "/");
      const meta = JSON.parse(fs.readFileSync(metafilePath, "utf8"));
      for (const inputPath of Object.keys(meta?.inputs ?? {})) {
        const externalPkg = extractPackageNameFromMetafileInput(inputPath);
        if (externalPkg) {
          const msg = checkForbiddenPackage(policy, externalPkg);
          if (msg) {
            violations.push({
              type: "metafile_violation",
              workspace: ws.name,
              file: metafileRel,
              line: 1,
              specifier: externalPkg,
              message: `Bundle input "${inputPath}" violates policy: ${msg}`
            });
          }
        }
      }
      for (const outputObj of Object.values(meta?.outputs ?? {})) {
        for (const imp of outputObj?.imports ?? []) {
          if (typeof imp?.path === "string" && !isRelativeSpecifier(imp.path)) {
            const pkgName = getPackageNameFromSpecifier(imp.path);
            const msg = checkForbiddenPackage(policy, pkgName);
            if (msg) {
              violations.push({
                type: "metafile_violation",
                workspace: ws.name,
                file: metafileRel,
                line: 1,
                specifier: imp.path,
                message: `Bundle output import "${imp.path}" violates policy: ${msg}`
              });
            }
          }
        }
      }
    }
  }

  // 4. Cycle detection across full combined graph
  const cycles = detectWorkspaceCycles(graph);
  for (const cycle of cycles) {
    violations.push({
      type: "cycle",
      workspace: cycle[0],
      file: "package.json",
      line: 1,
      specifier: cycle.join(" -> "),
      message: `Workspace dependency cycle detected: ${cycle.join(" -> ")}`
    });
  }

  // Also flag cycles in raw graph if single-edge self loop already detected
  void findCycleInGraph;

  return {
    ok: violations.length === 0,
    workspacesChecked: workspaces.length,
    filesScanned,
    violations
  };
}

if (isMainModule(import.meta.url)) {
  try {
    const args = parseCommonCliArgs(process.argv.slice(2));
    const report = verifyWorkspaceBoundaries(args.rootDir);
    if (!report.ok) {
      for (const v of report.violations) {
        console.error(`[boundaries] ${v.type} ${v.file}:${v.line} (${v.workspace}): ${v.message}`);
      }
      process.exit(1);
    }
    console.log(
      `[boundaries] ok (${report.workspacesChecked} workspaces, ${report.filesScanned} source files, 0 violations)`
    );
  } catch (err) {
    console.error(err instanceof Error ? err.message : String(err));
    process.exit(1);
  }
}
