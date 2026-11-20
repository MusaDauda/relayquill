import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { isMainModule, parseCommonCliArgs } from "./lib/workspaces.mjs";

// Build all forbidden patterns dynamically from fragments so this scanner never self-triggers.
const SPEC_DIR_NAME = ["Day", "05", "Relayquill"].join("-");
const DAY_WORD = ["d", "ay"].join("");
const HAND_BOOK = ["hand", "book"].join("");
const BLUE_PRINT = ["blue", "print"].join("");
const CHAP_TER = ["chap", "ter"].join("");
const CH_PREFIX = ["c", "h"].join("");
const ATTRIBUTION_TRAILER_PARTS = ["co", "authored", "by"];

const AI_BRANDS = [
  ["cl", "aude"].join(""),
  ["anthro", "pic"].join(""),
  ["open", "ai"].join(""),
  ["chat", "gpt"].join(""),
  ["co", "dex"].join(""),
  ["gem", "ini"].join(""),
  ["copi", "lot"].join(""),
  ["anti", "gravity"].join("")
];

const HOME_PREFIX = `/${["ho", "me"].join("")}/`;
const USERS_PREFIX = `/${["Us", "ers"].join("")}/`;
const WIN_USERS_PATH_REGEX = new RegExp(`[a-z]:[/\\\\]+${["us", "ers"].join("")}[/\\\\]+`, "i");
const SOCK_SUFFIX = [".so", "ck"].join("");
const PEM_HEADER = ["-----BEG", "IN "].join("");
const PROD_CRED_PREFIX = ["rq_", "p1."].join("");

const BINARY_EXTENSIONS = new Set([
  ".wasm",
  ".png",
  ".jpg",
  ".jpeg",
  ".gif",
  ".ico",
  ".woff",
  ".woff2",
  ".pdf",
  ".zip",
  ".tar",
  ".gz",
  ".tgz",
  ".exe",
  ".dll",
  ".so",
  ".dylib"
]);

const HYGIENE_RULES = [
  {
    id: "spec_day_ref",
    regex: new RegExp(`(?:^|[^a-z])${DAY_WORD}[\\s_-]*0?5(?![0-9])`, "i"),
    message: "Forbidden scratch numbering reference"
  },
  {
    id: "spec_doc_ref",
    regex: new RegExp(`${HAND_BOOK}`, "i"),
    message: "Forbidden scratch artifact noun"
  },
  {
    id: "spec_plan_ref",
    regex: new RegExp(`${BLUE_PRINT}`, "i"),
    message: "Forbidden scratch artifact noun"
  },
  {
    id: "section_num_ref",
    regex: new RegExp(
      `(?:^|[^a-z])${CHAP_TER}s?(?:[\\s_.:#-]*\\d{1,3}(?![0-9])|[/\\\\]\\d{2}-)|(?:^|[^a-z0-9])${CH_PREFIX}(?:_|\\s*[.:#-]?\\s*|\\s+)\\d{1,3}(?=$|[^a-z0-9])`,
      "i"
    ),
    message: "Forbidden section number citation"
  },
  {
    id: "attribution_trailer",
    regex: new RegExp(`(?:^|[^a-z])${ATTRIBUTION_TRAILER_PARTS.join("[\\s_-]*")}(?=$|[^a-z])`, "i"),
    message: "Forbidden attribution trailer"
  },
  {
    id: "ai_attribution",
    regex: new RegExp(
      `(?:^|[^a-z])(?:${AI_BRANDS.join("|")})(?=$|[^a-z])|(?:^|[^a-z])(?:llm[\\s_-]*(?:generated|authored|assistant)|(?:generated|written|authored|created)\\s+by\\s+(?:ai|an?\\s+llm))(?=$|[^a-z])`,
      "i"
    ),
    message: "Forbidden AI tooling attribution"
  }
];

const SECRET_KEY_SUFFIXES = [
  ["pass", "word"].join(""),
  ["pa", "ss"].join(""),
  ["sec", "ret"].join(""),
  ["private", "key"].join("_"),
  ["nkey", "seed"].join("_"),
  ["cre", "ds"].join(""),
  ["api", "key"].join("_"),
  ["signing", "key"].join("_"),
  ["tok", "en"].join("")
].join("|");

const FORBIDDEN_SECRET_JSON_KEY = new RegExp(`(?:^|[_-])(?:${SECRET_KEY_SUFFIXES})$`, "i");

const ALLOWED_EXCLUSION_LINE_REGEX = new RegExp(`^/?${SPEC_DIR_NAME}/?$`);
const TRACKED_SPEC_DIR_REGEX = new RegExp(`^${SPEC_DIR_NAME}(?:/|$)`);
const POSTGRES_CRED_URL_REGEX = /postgres(?:ql)?:\/\/[^/\s:@]+:[^/\s@]+@/i;

function normalizeRelPath(filePath) {
  return filePath.replace(/\\/g, "/");
}

function isIgnoreExclusionLine(trimmedLine) {
  return ALLOWED_EXCLUSION_LINE_REGEX.test(trimmedLine);
}

function isConfigFile(relPath) {
  return relPath.startsWith("config/");
}

function isLikelyBinary(filePath, buffer) {
  if (BINARY_EXTENSIONS.has(path.extname(filePath).toLowerCase())) {
    return true;
  }
  const checkLen = Math.min(buffer.length, 8192);
  for (let i = 0; i < checkLen; i += 1) {
    if (buffer[i] === 0) {
      return true;
    }
  }
  return false;
}

function walkJsonForSecretKeys(value, jsonPath, findings) {
  if (Array.isArray(value)) {
    for (let i = 0; i < value.length; i += 1) {
      walkJsonForSecretKeys(value[i], `${jsonPath}[${i}]`, findings);
    }
    return;
  }
  if (value && typeof value === "object") {
    for (const [key, nested] of Object.entries(value)) {
      const nextPath = jsonPath ? `${jsonPath}.${key}` : key;
      if (FORBIDDEN_SECRET_JSON_KEY.test(key)) {
        findings.push({
          rule: "config_raw_secret_key",
          line: 1,
          message: `Forbidden raw secret JSON key "${key}" at ${nextPath}`
        });
      }
      walkJsonForSecretKeys(nested, nextPath, findings);
    }
  }
}

function scanConfigSpecificLines(text, relPath) {
  const findings = [];
  const lines = text.split(/\r?\n/);

  for (let i = 0; i < lines.length; i += 1) {
    const line = lines[i];
    const lineNo = i + 1;
    if (
      line.includes(HOME_PREFIX) ||
      line.includes(USERS_PREFIX) ||
      WIN_USERS_PATH_REGEX.test(line)
    ) {
      findings.push({
        rule: "config_hardcoded_user_path",
        line: lineNo,
        message: "Forbidden machine-specific user path inside config/"
      });
    }
    if (line.includes(SOCK_SUFFIX)) {
      findings.push({
        rule: "config_hardcoded_sock_path",
        line: lineNo,
        message: "Forbidden hardcoded Unix socket path inside config/; use { env_name, channel }"
      });
    }
    if (line.includes(PEM_HEADER) || line.includes(PROD_CRED_PREFIX) || POSTGRES_CRED_URL_REGEX.test(line)) {
      findings.push({
        rule: "config_raw_secret_value",
        line: lineNo,
        message: "Forbidden raw secret/credential literal inside config/"
      });
    }
  }

  if (relPath.endsWith(".json") && !relPath.startsWith("config/schema/")) {
    try {
      const parsed = JSON.parse(text);
      walkJsonForSecretKeys(parsed, "", findings);
    } catch (err) {
      findings.push({
        rule: "config_invalid_json",
        line: 1,
        message: `Invalid JSON in ${relPath}: ${err instanceof Error ? err.message : String(err)}`
      });
    }
  }

  return findings;
}

export function scanTextForHygiene(text, options = {}) {
  const relPath = normalizeRelPath(options.filePath ?? "");
  const allowIgnoreEntry = options.allowIgnoreEntry ?? (relPath === ".gitignore" || relPath === ".dockerignore");
  const lines = text.split(/\r?\n/);
  const findings = [];

  for (let i = 0; i < lines.length; i += 1) {
    const line = lines[i];
    if (allowIgnoreEntry && isIgnoreExclusionLine(line.trim())) {
      continue;
    }
    for (const rule of HYGIENE_RULES) {
      if (rule.regex.test(line)) {
        findings.push({
          rule: rule.id,
          line: i + 1,
          message: rule.message
        });
      }
    }
  }

  if (isConfigFile(relPath)) {
    findings.push(...scanConfigSpecificLines(text, relPath));
  }

  return findings;
}

function runGit(rootDir, args, encoding = "utf8") {
  return spawnSync("git", args, {
    cwd: rootDir,
    encoding,
    maxBuffer: 64 * 1024 * 1024
  });
}

function readRepoFileBytes(rootDir, relPath, hasHead) {
  const fullPath = path.join(rootDir, relPath);
  if (fs.existsSync(fullPath)) {
    const stat = fs.statSync(fullPath);
    if (stat.isFile()) {
      return fs.readFileSync(fullPath);
    }
    return null;
  }
  if (hasHead) {
    const showRes = runGit(rootDir, ["show", `HEAD:${relPath}`], null);
    if (showRes.status === 0 && Buffer.isBuffer(showRes.stdout)) {
      return showRes.stdout;
    }
  }
  return null;
}

function parseNullDelimitedPaths(buffer) {
  if (!Buffer.isBuffer(buffer) || buffer.length === 0) {
    return [];
  }
  const paths = [];
  let start = 0;
  for (let i = 0; i < buffer.length; i += 1) {
    if (buffer[i] === 0) {
      if (i > start) {
        paths.push(buffer.subarray(start, i).toString("utf8"));
      }
      start = i + 1;
    }
  }
  if (start < buffer.length) {
    paths.push(buffer.subarray(start).toString("utf8"));
  }
  return paths;
}

export function checkTrackedFiles(rootDir, options = {}) {
  const resolvedRoot = path.resolve(rootDir);
  const violations = [];

  const trackedRes = runGit(resolvedRoot, ["ls-files", "-z"], null);
  if (trackedRes.status !== 0) {
    throw new Error(`git ls-files failed in ${resolvedRoot}: ${trackedRes.stderr?.toString("utf8") ?? ""}`);
  }
  const trackedPaths = parseNullDelimitedPaths(trackedRes.stdout);

  for (const rawPath of trackedPaths) {
    const relPath = normalizeRelPath(rawPath);
    if (TRACKED_SPEC_DIR_REGEX.test(relPath)) {
      violations.push({
        type: "tracked_spec_dir",
        file: relPath,
        line: 1,
        rule: "tracked_spec_dir",
        message: "Local scratch directory must never be tracked by git"
      });
    }
  }

  const headRes = runGit(resolvedRoot, ["rev-parse", "--verify", "HEAD"]);
  const hasHead = headRes.status === 0;

  let candidatePaths = trackedPaths;
  if (options.includeUntracked !== false) {
    const allRes = runGit(resolvedRoot, ["ls-files", "-z", "--cached", "--others", "--exclude-standard"], null);
    if (allRes.status === 0) {
      candidatePaths = Array.from(new Set([...trackedPaths, ...parseNullDelimitedPaths(allRes.stdout)])).sort();
    }
  }

  if (options.requireIgnoreFiles !== false) {
    for (const ignoreName of [".gitignore", ".dockerignore"]) {
      const ignorePath = path.join(resolvedRoot, ignoreName);
      if (!fs.existsSync(ignorePath)) {
        violations.push({
          type: "missing_ignore_file",
          file: ignoreName,
          line: 1,
          rule: "missing_ignore_file",
          message: `Required ignore file ${ignoreName} is missing`
        });
      } else {
        const ignoreText = fs.readFileSync(ignorePath, "utf8");
        const hasExclusion = ignoreText
          .split(/\r?\n/)
          .some((line) => isIgnoreExclusionLine(line.trim()));
        if (!hasExclusion) {
          violations.push({
            type: "missing_spec_ignore_rule",
            file: ignoreName,
            line: 1,
            rule: "missing_spec_ignore_rule",
            message: `${ignoreName} must exclude /${SPEC_DIR_NAME}/`
          });
        }
      }
    }
  }

  let filesScanned = 0;
  for (const rawPath of candidatePaths) {
    const relPath = normalizeRelPath(rawPath);
    if (TRACKED_SPEC_DIR_REGEX.test(relPath)) {
      continue;
    }
    const pathFindings = scanTextForHygiene(relPath, { filePath: "", allowIgnoreEntry: false });
    for (const f of pathFindings) {
      violations.push({
        type: "path_hygiene",
        file: relPath,
        line: 1,
        rule: f.rule,
        message: `${f.message} (in file path)`
      });
    }
    const bytes = readRepoFileBytes(resolvedRoot, relPath, hasHead);
    if (!bytes || isLikelyBinary(relPath, bytes)) {
      continue;
    }
    filesScanned += 1;
    const text = bytes.toString("utf8");
    const findings = scanTextForHygiene(text, { filePath: relPath });
    for (const f of findings) {
      violations.push({
        type: "file_hygiene",
        file: relPath,
        line: f.line,
        rule: f.rule,
        message: f.message
      });
    }
  }

  return { filesScanned, violations };
}

export function checkCommitHistory(rootDir) {
  const resolvedRoot = path.resolve(rootDir);
  const headCheck = runGit(resolvedRoot, ["rev-parse", "--verify", "HEAD"]);
  if (headCheck.status !== 0) {
    return { commitsScanned: 0, violations: [] };
  }

  const logRes = runGit(
    resolvedRoot,
    ["log", "--all", "--format=%H%x1f%an%x1f%ae%x1f%cn%x1f%ce%x1f%B%x1e"],
    "utf8"
  );
  if (logRes.status !== 0) {
    throw new Error(`git log failed in ${resolvedRoot}: ${logRes.stderr ?? ""}`);
  }

  const records = logRes.stdout.split("\x1e").filter((entry) => entry.trim().length > 0);
  const violations = [];

  for (const record of records) {
    const parts = record.split("\x1f");
    const hash = (parts[0] ?? "").trim();
    const authorName = parts[1] ?? "";
    const authorEmail = parts[2] ?? "";
    const committerName = parts[3] ?? "";
    const committerEmail = parts[4] ?? "";
    const body = parts.slice(5).join("\x1f");

    const fields = [
      { label: "author_name", text: authorName },
      { label: "author_email", text: authorEmail },
      { label: "committer_name", text: committerName },
      { label: "committer_email", text: committerEmail },
      { label: "commit_message", text: body }
    ];

    for (const field of fields) {
      const findings = scanTextForHygiene(field.text, { filePath: "", allowIgnoreEntry: false });
      for (const f of findings) {
        violations.push({
          type: "commit_hygiene",
          commit: hash,
          field: field.label,
          line: f.line,
          rule: f.rule,
          message: f.message
        });
      }
    }
  }

  return { commitsScanned: records.length, violations };
}

export function checkRepoHygiene(rootDir, options = {}) {
  const resolvedRoot = path.resolve(rootDir);
  const filesResult = checkTrackedFiles(resolvedRoot, options);
  const commitsResult = checkCommitHistory(resolvedRoot);
  const violations = [...filesResult.violations, ...commitsResult.violations];

  return {
    ok: violations.length === 0,
    filesScanned: filesResult.filesScanned,
    commitsScanned: commitsResult.commitsScanned,
    violations
  };
}

if (isMainModule(import.meta.url)) {
  try {
    const args = parseCommonCliArgs(process.argv.slice(2));
    const report = checkRepoHygiene(args.rootDir);
    if (!report.ok) {
      for (const v of report.violations) {
        if (v.type === "commit_hygiene") {
          console.error(`[hygiene] ${v.rule} commit ${v.commit} (${v.field}:${v.line}): ${v.message}`);
        } else {
          console.error(`[hygiene] ${v.rule} ${v.file}:${v.line}: ${v.message}`);
        }
      }
      process.exit(1);
    }
    console.log(
      `[hygiene] ok (${report.filesScanned} files, ${report.commitsScanned} commits, 0 violations)`
    );
  } catch (err) {
    console.error(err instanceof Error ? err.message : String(err));
    process.exit(1);
  }
}
