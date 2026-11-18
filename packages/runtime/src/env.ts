import fs from "node:fs";
import path from "node:path";
import {
  DependencyUnavailableDomainError,
  ValidationDomainError
} from "@relayquill/domain";

const ENV_KEY_REGEX = /^[A-Za-z_][A-Za-z0-9_]*$/;
const FORBIDDEN_ENV_KEYS = new Set(["__proto__", "constructor", "prototype"]);

export function assertSafeFilesystemPath(
  filePath: string,
  label = "path",
  options: { readonly allowAbsolute?: boolean | undefined } = {}
): string {
  if (typeof filePath !== "string" || filePath.trim().length === 0) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `${label} must be a non-empty string`,
      fieldErrors: [{ path: label, code: "INVALID_VALUE" }]
    });
  }
  if (filePath.includes("\0")) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `${label} contains an invalid NUL byte`,
      fieldErrors: [{ path: label, code: "INVALID_VALUE" }]
    });
  }
  const normalized = filePath.trim();
  const segments = normalized.split(/[\\/]/);
  if (segments.includes("..")) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `${label} must not contain parent-directory traversal ("..")`,
      fieldErrors: [{ path: label, code: "INVALID_VALUE" }]
    });
  }
  if (options.allowAbsolute === false && /^(\/|\\|[A-Za-z]:)/.test(normalized)) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `${label} must be a repository-relative path`,
      fieldErrors: [{ path: label, code: "INVALID_VALUE" }]
    });
  }
  return normalized;
}

function unescapeDoubleQuoted(raw: string): string {
  let out = "";
  for (let i = 0; i < raw.length; i += 1) {
    const ch = raw[i];
    if (ch !== "\\") {
      out += ch;
      continue;
    }
    const next = raw[i + 1];
    if (next === undefined) {
      out += "\\";
      break;
    }
    i += 1;
    switch (next) {
      case "n":
        out += "\n";
        break;
      case "r":
        out += "\r";
        break;
      case "t":
        out += "\t";
        break;
      case '"':
        out += '"';
        break;
      case "\\":
        out += "\\";
        break;
      default:
        out += `\\${next}`;
        break;
    }
  }
  return out;
}

function parseDotEnvValue(rawValue: string, lineNumber: number): string {
  const trimmedStart = rawValue.trimStart();
  if (trimmedStart.length === 0) {
    return "";
  }
  const first = trimmedStart[0];
  if (first === '"' || first === "'") {
    let endIdx = -1;
    for (let i = 1; i < trimmedStart.length; i += 1) {
      const ch = trimmedStart[i];
      if (first === '"' && ch === "\\") {
        i += 1;
        continue;
      }
      if (ch === first) {
        endIdx = i;
        break;
      }
    }
    if (endIdx === -1) {
      throw new ValidationDomainError({
        code: "INVALID_VALUE",
        message: `Unterminated quoted value on .env line ${lineNumber}`
      });
    }
    const trailing = trimmedStart.slice(endIdx + 1).trim();
    if (trailing.length > 0 && !trailing.startsWith("#")) {
      throw new ValidationDomainError({
        code: "INVALID_VALUE",
        message: `Unexpected trailing characters after quoted value on .env line ${lineNumber}`
      });
    }
    const inner = trimmedStart.slice(1, endIdx);
    return first === '"' ? unescapeDoubleQuoted(inner) : inner;
  }

  let commentIdx = -1;
  for (let i = 0; i < trimmedStart.length; i += 1) {
    if (trimmedStart[i] === "#" && i > 0 && /\s/.test(trimmedStart[i - 1] ?? "")) {
      commentIdx = i;
      break;
    }
  }
  const valuePart = commentIdx === -1 ? trimmedStart : trimmedStart.slice(0, commentIdx);
  return valuePart.trim();
}

export function parseDotEnv(content: string): Readonly<Record<string, string>> {
  if (typeof content !== "string") {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: ".env content must be a string"
    });
  }
  if (content.includes("\0")) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: ".env content must not contain NUL bytes"
    });
  }

  const result: Record<string, string> = {};
  const lines = content.split(/\r?\n/);

  for (let i = 0; i < lines.length; i += 1) {
    const lineNo = i + 1;
    const rawLine = lines[i] ?? "";
    const trimmed = rawLine.trim();
    if (trimmed.length === 0 || trimmed.startsWith("#")) {
      continue;
    }
    const withoutExport = trimmed.startsWith("export ")
      ? trimmed.slice("export ".length).trimStart()
      : trimmed;
    const eqIdx = withoutExport.indexOf("=");
    if (eqIdx <= 0) {
      throw new ValidationDomainError({
        code: "INVALID_VALUE",
        message: `Malformed .env entry on line ${lineNo}`
      });
    }
    const key = withoutExport.slice(0, eqIdx).trim();
    if (!ENV_KEY_REGEX.test(key) || FORBIDDEN_ENV_KEYS.has(key)) {
      throw new ValidationDomainError({
        code: "INVALID_VALUE",
        message: `Invalid environment variable name "${key}" on .env line ${lineNo}`
      });
    }
    const rawVal = withoutExport.slice(eqIdx + 1);
    const parsedVal = parseDotEnvValue(rawVal, lineNo);
    if (parsedVal.includes("\0")) {
      throw new ValidationDomainError({
        code: "INVALID_VALUE",
        message: `Environment variable "${key}" contains a NUL byte`
      });
    }
    result[key] = parsedVal;
  }

  return Object.freeze(result);
}

export function loadDotEnvFile(
  filePath: string,
  options: { readonly required?: boolean | undefined } = {}
): Readonly<Record<string, string>> {
  const safePath = assertSafeFilesystemPath(filePath, "env_file");
  const resolved = path.resolve(safePath);
  if (!fs.existsSync(resolved)) {
    if (options.required) {
      throw new DependencyUnavailableDomainError({
        code: "SECRET_CUSTODY_ERROR",
        message: `Required .env file not found at ${safePath}`,
        retryable: false
      });
    }
    return Object.freeze({});
  }
  const stat = fs.statSync(resolved);
  if (!stat.isFile()) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `.env path is not a regular file: ${safePath}`
    });
  }
  const content = fs.readFileSync(resolved, "utf8");
  return parseDotEnv(content);
}

export function resolveEnvMap(options: {
  readonly env?: Readonly<Record<string, string | undefined>> | undefined;
  readonly envFilePath?: string | undefined;
  readonly requireEnvFile?: boolean | undefined;
} = {}): Readonly<Record<string, string | undefined>> {
  const baseEnv = options.env ?? process.env;
  const candidateFile =
    options.envFilePath ??
    (typeof baseEnv.RELAYQUILL_ENV_FILE === "string" && baseEnv.RELAYQUILL_ENV_FILE.trim().length > 0
      ? baseEnv.RELAYQUILL_ENV_FILE.trim()
      : undefined);

  if (candidateFile === undefined) {
    return Object.freeze({ ...baseEnv });
  }

  const fromFile = loadDotEnvFile(candidateFile, {
    required: options.requireEnvFile ?? options.envFilePath !== undefined
  });

  const merged: Record<string, string | undefined> = { ...fromFile };
  for (const [key, val] of Object.entries(baseEnv)) {
    if (val !== undefined && !FORBIDDEN_ENV_KEYS.has(key)) {
      merged[key] = val;
    }
  }
  return Object.freeze(merged);
}
