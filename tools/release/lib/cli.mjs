import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

export class CliError extends Error {
  constructor(message, exitCode = 1) {
    super(message);
    this.name = "CliError";
    this.exitCode = exitCode;
  }
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

const SECRET_FLAG_REGEX =
  /^(?:password|db[-_]?password|passphrase|secret|client[-_]?secret|webhook[-_]?secret|session[-_]?secret|private[-_]?key|nkey[-_]?seed|signing[-_]?key|api[-_]?key|auth[-_]?token|bearer[-_]?token|access[-_]?token|refresh[-_]?token|token|credential|raw[-_]?key)$/i;

const SECRET_KEY_SUFFIX_REGEX =
  /(?:^|[_-])(password|passphrase|secret|private_key|nkey_seed|creds|api_key|signing_key|access_token|refresh_token|bearer_token|session_hmac|master_key)$/i;

const RAW_SECRET_VALUE_PATTERNS = [
  /-----BEGIN\s+[A-Z0-9 ]+-----/,
  /\brq_p1\.[A-Za-z0-9._-]{8,}/,
  /\bSU[A-Z2-7]{40,}\b/,
  /postgres(?:ql)?:\/\/[^/\s:@]+:[^/\s@]+@/i,
  /\b(?:sk_live|sk_test|rk_live|rk_test|whsec)_[A-Za-z0-9]{12,}\b/,
  /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/,
  /^Bearer\s+rq_/i
];

export function isForbiddenSecretFlag(flagName) {
  const normalized = flagName.replace(/^--?/, "").trim();
  return SECRET_FLAG_REGEX.test(normalized);
}

export function hasForbiddenRawSecretValue(rawValue) {
  if (typeof rawValue !== "string") {
    return false;
  }
  return RAW_SECRET_VALUE_PATTERNS.some((pattern) => pattern.test(rawValue));
}

export function isSensitiveFieldName(key) {
  if (typeof key !== "string" || key.length === 0) {
    return false;
  }
  const normalized = key.replace(/-/g, "_");
  if (
    /(?:_ref|_refs|_dir|_prefix|_path|_mode|_version|_versions|_sha256|_digest|_digests|_count|_counts|_enabled|_env|_channel|_name|_id|_ids|_window_days)$/i.test(
      normalized
    )
  ) {
    return false;
  }
  if (normalized.toLowerCase() === "secret_provider" || normalized.toLowerCase() === "secrets") {
    return false;
  }
  return SECRET_KEY_SUFFIX_REGEX.test(normalized) || /^(?:authorization|raw_body|raw_payload|cookie|set-cookie)$/i.test(normalized);
}

export function redactAwsAccountInString(text) {
  return text.replace(
    /(arn:aws[a-z-]*:iam::)(\d{12})(:)/g,
    (_m, prefix, digits, suffix) => `${prefix}********${digits.slice(-4)}${suffix}`
  );
}

export function redactSensitiveData(value, keyHint = "") {
  if (value === null || value === undefined) {
    return value;
  }
  if (typeof value === "bigint") {
    return value.toString();
  }
  if (typeof value === "string") {
    if (isSensitiveFieldName(keyHint)) {
      return "[REDACTED]";
    }
    let out = value;
    for (const pattern of RAW_SECRET_VALUE_PATTERNS) {
      const globalPattern = new RegExp(pattern.source, pattern.flags.includes("g") ? pattern.flags : `${pattern.flags}g`);
      out = out.replace(globalPattern, "[REDACTED]");
    }
    return redactAwsAccountInString(out);
  }
  if (Array.isArray(value)) {
    return value.map((item) => redactSensitiveData(item));
  }
  if (typeof value === "object") {
    const out = {};
    for (const [key, nested] of Object.entries(value)) {
      if (isSensitiveFieldName(key)) {
        out[key] = nested === null || nested === undefined ? nested : "[REDACTED]";
      } else {
        out[key] = redactSensitiveData(nested, key);
      }
    }
    return out;
  }
  return value;
}

export function findRawSecretsInObject(value, jsonPath = "$", findings = []) {
  if (typeof value === "string") {
    if (hasForbiddenRawSecretValue(value)) {
      findings.push(`Raw secret literal detected at ${jsonPath}`);
    }
    return findings;
  }
  if (Array.isArray(value)) {
    for (let i = 0; i < value.length; i += 1) {
      findRawSecretsInObject(value[i], `${jsonPath}[${i}]`, findings);
    }
    return findings;
  }
  if (value && typeof value === "object") {
    for (const [key, nested] of Object.entries(value)) {
      const nextPath = `${jsonPath}.${key}`;
      if (isSensitiveFieldName(key) && nested !== null && nested !== undefined && nested !== "") {
        findings.push(`Forbidden raw secret field "${key}" at ${nextPath}`);
      }
      findRawSecretsInObject(nested, nextPath, findings);
    }
  }
  return findings;
}

function checkStrictJsonTokens(rawText, sourceLabel) {
  let i = 0;
  const len = rawText.length;

  function skipWhitespace() {
    while (i < len) {
      const ch = rawText[i];
      if (ch === " " || ch === "\t" || ch === "\n" || ch === "\r") {
        i += 1;
      } else {
        break;
      }
    }
  }

  function readString() {
    if (rawText[i] !== "\"") {
      throw new Error(`Expected string in ${sourceLabel} at offset ${i}`);
    }
    i += 1;
    let out = "";
    while (i < len) {
      const ch = rawText[i];
      if (ch === "\"") {
        i += 1;
        return out;
      }
      if (ch === "\\") {
        i += 1;
        if (i >= len) {
          throw new Error(`Unterminated escape in ${sourceLabel}`);
        }
        const esc = rawText[i];
        if (esc === "u") {
          const hex = rawText.slice(i + 1, i + 5);
          if (!/^[0-9a-fA-F]{4}$/.test(hex)) {
            throw new Error(`Invalid unicode escape in ${sourceLabel}`);
          }
          out += String.fromCharCode(Number.parseInt(hex, 16));
          i += 5;
        } else {
          const escapes = { "\"": "\"", "\\": "\\", "/": "/", b: "\b", f: "\f", n: "\n", r: "\r", t: "\t" };
          out += escapes[esc] ?? esc;
          i += 1;
        }
      } else {
        out += ch;
        i += 1;
      }
    }
    throw new Error(`Unterminated string in ${sourceLabel}`);
  }

  function readValue() {
    skipWhitespace();
    if (i >= len) {
      throw new Error(`Unexpected end of JSON in ${sourceLabel}`);
    }
    const ch = rawText[i];
    if (ch === "{") {
      i += 1;
      skipWhitespace();
      const keys = new Set();
      if (rawText[i] === "}") {
        i += 1;
        return;
      }
      while (i < len) {
        skipWhitespace();
        const key = readString();
        if (key === "__proto__" || key === "constructor" || key === "prototype") {
          throw new Error(`Forbidden prototype key "${key}" in ${sourceLabel}`);
        }
        if (keys.has(key)) {
          throw new Error(`Duplicate JSON key "${key}" in ${sourceLabel}`);
        }
        keys.add(key);
        skipWhitespace();
        if (rawText[i] !== ":") {
          throw new Error(`Expected ':' after key "${key}" in ${sourceLabel}`);
        }
        i += 1;
        readValue();
        skipWhitespace();
        if (rawText[i] === ",") {
          i += 1;
          continue;
        }
        if (rawText[i] === "}") {
          i += 1;
          return;
        }
        throw new Error(`Expected ',' or '}' in ${sourceLabel} at offset ${i}`);
      }
      throw new Error(`Unterminated object in ${sourceLabel}`);
    }
    if (ch === "[") {
      i += 1;
      skipWhitespace();
      if (rawText[i] === "]") {
        i += 1;
        return;
      }
      while (i < len) {
        readValue();
        skipWhitespace();
        if (rawText[i] === ",") {
          i += 1;
          continue;
        }
        if (rawText[i] === "]") {
          i += 1;
          return;
        }
        throw new Error(`Expected ',' or ']' in ${sourceLabel} at offset ${i}`);
      }
      throw new Error(`Unterminated array in ${sourceLabel}`);
    }
    if (ch === "\"") {
      readString();
      return;
    }
    while (i < len) {
      const cur = rawText[i];
      if (cur === "," || cur === "}" || cur === "]" || cur === " " || cur === "\t" || cur === "\n" || cur === "\r") {
        break;
      }
      i += 1;
    }
  }

  readValue();
  skipWhitespace();
  if (i !== len) {
    throw new Error(`Trailing content in JSON ${sourceLabel}`);
  }
}

export function parseStrictJson(rawText, sourceLabel = "input", options = {}) {
  const maxBytes = options.maxBytes ?? 1024 * 1024;
  const byteLength = Buffer.byteLength(rawText, "utf8");
  if (byteLength > maxBytes) {
    throw new CliError(
      `${sourceLabel} exceeds maximum allowed size (${byteLength} > ${maxBytes} bytes)`,
      options.exitCode ?? 1
    );
  }
  try {
    checkStrictJsonTokens(rawText, sourceLabel);
    return JSON.parse(rawText);
  } catch (err) {
    throw new CliError(
      `Invalid strict JSON in ${sourceLabel}: ${err instanceof Error ? err.message : String(err)}`,
      options.exitCode ?? 1
    );
  }
}

export function readStrictJsonFile(filePath, options = {}) {
  const resolved = path.resolve(filePath);
  if (!fs.existsSync(resolved)) {
    throw new CliError(`File not found: ${resolved}`, options.exitCode ?? 1);
  }
  const stat = fs.statSync(resolved);
  if (!stat.isFile()) {
    throw new CliError(`Expected file path, got non-file: ${resolved}`, options.exitCode ?? 1);
  }
  const rawText = fs.readFileSync(resolved, "utf8");
  return parseStrictJson(rawText, resolved, options);
}

export function canonicalizeJson(value) {
  if (value === null) {
    return "null";
  }
  if (typeof value === "boolean" || typeof value === "number") {
    if (typeof value === "number" && !Number.isFinite(value)) {
      throw new Error(`Non-finite number cannot be canonicalized: ${value}`);
    }
    return JSON.stringify(value);
  }
  if (typeof value === "bigint") {
    return value.toString();
  }
  if (typeof value === "string") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((item) => canonicalizeJson(item)).join(",")}]`;
  }
  if (typeof value === "object") {
    const keys = Object.keys(value)
      .filter((k) => value[k] !== undefined)
      .sort();
    return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalizeJson(value[k])}`).join(",")}}`;
  }
  throw new Error(`Unsupported value type in canonicalizeJson: ${typeof value}`);
}

export function sha256Hex(input) {
  const data = typeof input === "string" || Buffer.isBuffer(input) ? input : canonicalizeJson(input);
  return crypto.createHash("sha256").update(data).digest("hex");
}

function coerceOptionValue(spec, rawVal, flagName, errorCode) {
  if (spec.type === "integer") {
    if (!/^-?\d+$/.test(rawVal)) {
      throw new CliError(`Flag ${flagName} requires an integer value`, errorCode);
    }
    const parsed = Number.parseInt(rawVal, 10);
    if (!Number.isSafeInteger(parsed)) {
      throw new CliError(`Flag ${flagName} integer out of safe range`, errorCode);
    }
    if (typeof spec.min === "number" && parsed < spec.min) {
      throw new CliError(`Flag ${flagName} must be >= ${spec.min}`, errorCode);
    }
    if (typeof spec.max === "number" && parsed > spec.max) {
      throw new CliError(`Flag ${flagName} must be <= ${spec.max}`, errorCode);
    }
    return parsed;
  }
  if (spec.type === "number") {
    const parsed = Number(rawVal);
    if (!Number.isFinite(parsed)) {
      throw new CliError(`Flag ${flagName} requires a finite numeric value`, errorCode);
    }
    if (typeof spec.min === "number" && parsed < spec.min) {
      throw new CliError(`Flag ${flagName} must be >= ${spec.min}`, errorCode);
    }
    if (typeof spec.max === "number" && parsed > spec.max) {
      throw new CliError(`Flag ${flagName} must be <= ${spec.max}`, errorCode);
    }
    return parsed;
  }
  if (Array.isArray(spec.enum) && !spec.enum.includes(rawVal)) {
    throw new CliError(
      `Invalid value for ${flagName}: "${rawVal}". Expected one of: ${spec.enum.join(", ")}`,
      errorCode
    );
  }
  return rawVal;
}

export function parseCliFlags(argv, schema = {}) {
  const errorCode = schema.errorExitCode ?? 1;
  const optionsSpec = schema.options ?? {};
  const result = {
    help: false,
    options: {},
    positionals: []
  };

  for (const [key, spec] of Object.entries(optionsSpec)) {
    if (spec.multiple) {
      result.options[key] = [];
    } else if (Object.prototype.hasOwnProperty.call(spec, "default")) {
      result.options[key] = spec.default;
    } else if (spec.type === "boolean") {
      result.options[key] = false;
    } else {
      result.options[key] = undefined;
    }
  }

  for (const arg of argv) {
    if (arg === "--help" || arg === "-h") {
      result.help = true;
      return result;
    }
  }

  for (const arg of argv) {
    if (arg === "--") {
      continue;
    }
    if (arg.startsWith("-")) {
      const eqIdx = arg.indexOf("=");
      const flagName = eqIdx === -1 ? arg : arg.slice(0, eqIdx);
      const inlineVal = eqIdx === -1 ? undefined : arg.slice(eqIdx + 1);
      if (isForbiddenSecretFlag(flagName)) {
        throw new CliError(
          `Refusing secret-bearing CLI argument "${flagName}"; secrets must use protected custody references`,
          errorCode
        );
      }
      if (inlineVal !== undefined && hasForbiddenRawSecretValue(inlineVal)) {
        throw new CliError(
          `Refusing secret-like literal in CLI argument "${flagName}"`,
          errorCode
        );
      }
    } else if (hasForbiddenRawSecretValue(arg)) {
      throw new CliError("Refusing secret-like literal in CLI argument", errorCode);
    }
  }

  let endOfFlags = false;
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (!endOfFlags && arg === "--") {
      endOfFlags = true;
      continue;
    }
    if (!endOfFlags && arg.startsWith("-")) {
      const eqIdx = arg.indexOf("=");
      const flagName = eqIdx === -1 ? arg : arg.slice(0, eqIdx);
      const inlineVal = eqIdx === -1 ? undefined : arg.slice(eqIdx + 1);

      if (isForbiddenSecretFlag(flagName)) {
        throw new CliError(
          `Refusing secret-bearing CLI argument "${flagName}"; secrets must use protected custody references`,
          errorCode
        );
      }

      const spec = optionsSpec[flagName];
      if (!spec) {
        throw new CliError(`Unknown CLI flag: ${flagName}`, errorCode);
      }

      if (spec.type === "boolean") {
        if (inlineVal !== undefined) {
          if (inlineVal !== "true" && inlineVal !== "false") {
            throw new CliError(`Flag ${flagName} expects true or false`, errorCode);
          }
          result.options[flagName] = inlineVal === "true";
        } else {
          result.options[flagName] = true;
        }
        continue;
      }

      const val = inlineVal !== undefined ? inlineVal : argv[++i];
      if (val === undefined || (inlineVal === undefined && val.startsWith("--"))) {
        throw new CliError(`Flag ${flagName} requires a value`, errorCode);
      }
      if (hasForbiddenRawSecretValue(val)) {
        throw new CliError(
          `Refusing secret-like literal in CLI argument "${flagName}"`,
          errorCode
        );
      }
      const coerced = coerceOptionValue(spec, val, flagName, errorCode);
      if (spec.multiple) {
        result.options[flagName].push(coerced);
      } else {
        result.options[flagName] = coerced;
      }
      continue;
    }

    if (hasForbiddenRawSecretValue(arg)) {
      throw new CliError("Refusing secret-like literal in CLI positional argument", errorCode);
    }
    result.positionals.push(arg);
  }

  const maxPositionals = schema.maxPositionals ?? 0;
  const minPositionals = schema.minPositionals ?? 0;
  if (result.positionals.length < minPositionals) {
    throw new CliError(
      schema.missingPositionalMessage ?? `Expected at least ${minPositionals} positional argument(s)`,
      errorCode
    );
  }
  if (result.positionals.length > maxPositionals) {
    throw new CliError(`Unexpected positional argument: ${result.positionals[maxPositionals]}`, errorCode);
  }

  for (const [flagName, spec] of Object.entries(optionsSpec)) {
    if (spec.required && result.options[flagName] === undefined) {
      throw new CliError(`Missing required flag: ${flagName}`, errorCode);
    }
  }

  return result;
}

export function runCliMain(importMetaUrl, helpText, handler, options = {}) {
  if (!isMainModule(importMetaUrl)) {
    return;
  }
  const errorExitCode = options.errorExitCode ?? 1;
  Promise.resolve()
    .then(async () => {
      const outcome = await handler(process.argv.slice(2));
      if (outcome && outcome.help) {
        process.stdout.write(`${helpText.trimEnd()}\n`);
        process.exit(0);
      }
      const exitCode = typeof outcome?.exitCode === "number" ? outcome.exitCode : 0;
      if (outcome && outcome.output !== undefined) {
        const serialized =
          typeof outcome.output === "string"
            ? outcome.output
            : JSON.stringify(redactSensitiveData(outcome.output), null, 2);
        process.stdout.write(`${serialized}\n`);
      }
      process.exit(exitCode);
    })
    .catch((err) => {
      const message = redactSensitiveData(err instanceof Error ? err.message : String(err));
      const exitCode =
        err && typeof err === "object" && "exitCode" in err && typeof err.exitCode === "number"
          ? err.exitCode
          : errorExitCode;
      process.stderr.write(`ERROR: ${message}\n`);
      process.exit(exitCode);
    });
}
