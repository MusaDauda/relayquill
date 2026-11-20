import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  CliError,
  canonicalizeJson,
  findRawSecretsInObject,
  readStrictJsonFile,
  sha256Hex
} from "./cli.mjs";

const DEFAULT_REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");

const ALLOWED_SECRET_PURPOSES = new Set([
  "db_password",
  "auth_session_hmac",
  "nats_nkey_seed",
  "endpoint_signing_key",
  "tls_server_key",
  "tls_route_key",
  "producer_credential",
  "stripe_webhook_secret",
  "paystack_webhook_secret",
  "oauth_client_secret"
]);

const ALLOWED_ROLE_NAMES = new Set([
  "api",
  "relay",
  "fanout",
  "sender",
  "coordinator",
  "admin",
  "console",
  "broker",
  "broker-node-1",
  "broker-node-2",
  "broker-node-3",
  "receiver",
  "provider_ingress"
]);

const FORBIDDEN_RELEASE_HOSTS = new Set([
  "localhost",
  "127.0.0.1",
  "::1",
  "0.0.0.0",
  "receiver.fixture.test"
]);

function resolvePointer(rootSchema, ref, schemasByFile, currentFile) {
  const [filePart, fragmentPart] = ref.split("#");
  let baseSchema = rootSchema;
  let baseFile = currentFile;
  if (filePart && filePart.length > 0) {
    baseFile = path.resolve(path.dirname(currentFile), filePart);
    baseSchema = schemasByFile.get(baseFile);
    if (!baseSchema) {
      throw new Error(`Unresolved schema ref file: ${ref} from ${currentFile}`);
    }
  }
  if (!fragmentPart || fragmentPart === "/") {
    return { schema: baseSchema, rootSchema: baseSchema, schemaFile: baseFile };
  }
  const parts = fragmentPart.replace(/^\//, "").split("/");
  let node = baseSchema;
  for (const part of parts) {
    const key = part.replace(/~1/g, "/").replace(/~0/g, "~");
    node = node?.[key];
    if (node === undefined) {
      throw new Error(`Unresolved JSON pointer "${ref}" in ${baseFile}`);
    }
  }
  return { schema: node, rootSchema: baseSchema, schemaFile: baseFile };
}

export function validateAgainstSchema(
  value,
  schema,
  rootSchema,
  schemaFile,
  schemasByFile,
  jsonPath = "$"
) {
  const errors = [];
  if (schema === true) {
    return errors;
  }
  if (schema === false) {
    return [`${jsonPath}: disallowed by false schema`];
  }
  if (schema.$ref) {
    const target = resolvePointer(rootSchema, schema.$ref, schemasByFile, schemaFile);
    errors.push(
      ...validateAgainstSchema(
        value,
        target.schema,
        target.rootSchema,
        target.schemaFile,
        schemasByFile,
        jsonPath
      )
    );
  }
  if (schema.type) {
    const actual = Array.isArray(value) ? "array" : value === null ? "null" : typeof value;
    if (schema.type === "integer") {
      if (typeof value !== "number" || !Number.isInteger(value)) {
        errors.push(`${jsonPath}: expected integer, got ${actual}`);
        return errors;
      }
    } else if (actual !== schema.type) {
      errors.push(`${jsonPath}: expected ${schema.type}, got ${actual}`);
      return errors;
    }
  }
  if (Object.prototype.hasOwnProperty.call(schema, "const") && value !== schema.const) {
    errors.push(`${jsonPath}: expected const ${JSON.stringify(schema.const)}, got ${JSON.stringify(value)}`);
  }
  if (Array.isArray(schema.enum) && !schema.enum.includes(value)) {
    errors.push(`${jsonPath}: expected one of ${JSON.stringify(schema.enum)}, got ${JSON.stringify(value)}`);
  }
  if (typeof value === "string") {
    if (typeof schema.minLength === "number" && value.length < schema.minLength) {
      errors.push(`${jsonPath}: string shorter than ${schema.minLength}`);
    }
    if (typeof schema.maxLength === "number" && value.length > schema.maxLength) {
      errors.push(`${jsonPath}: string longer than ${schema.maxLength}`);
    }
    if (typeof schema.pattern === "string" && !new RegExp(schema.pattern).test(value)) {
      errors.push(`${jsonPath}: string ${JSON.stringify(value)} failed pattern ${schema.pattern}`);
    }
  }
  if (typeof value === "number") {
    if (typeof schema.minimum === "number" && value < schema.minimum) {
      errors.push(`${jsonPath}: ${value} < minimum ${schema.minimum}`);
    }
    if (typeof schema.maximum === "number" && value > schema.maximum) {
      errors.push(`${jsonPath}: ${value} > maximum ${schema.maximum}`);
    }
  }
  if (Array.isArray(value)) {
    if (typeof schema.minItems === "number" && value.length < schema.minItems) {
      errors.push(`${jsonPath}: array length ${value.length} < minItems ${schema.minItems}`);
    }
    if (typeof schema.maxItems === "number" && value.length > schema.maxItems) {
      errors.push(`${jsonPath}: array length ${value.length} > maxItems ${schema.maxItems}`);
    }
    if (schema.items) {
      value.forEach((item, idx) => {
        errors.push(
          ...validateAgainstSchema(
            item,
            schema.items,
            rootSchema,
            schemaFile,
            schemasByFile,
            `${jsonPath}[${idx}]`
          )
        );
      });
    }
  }
  if (value !== null && typeof value === "object" && !Array.isArray(value)) {
    const keys = Object.keys(value);
    if (typeof schema.minProperties === "number" && keys.length < schema.minProperties) {
      errors.push(`${jsonPath}: fewer than ${schema.minProperties} properties`);
    }
    if (Array.isArray(schema.required)) {
      for (const reqKey of schema.required) {
        if (!Object.prototype.hasOwnProperty.call(value, reqKey)) {
          errors.push(`${jsonPath}: missing required property "${reqKey}"`);
        }
      }
    }
    if (schema.properties) {
      for (const [propKey, propSchema] of Object.entries(schema.properties)) {
        if (Object.prototype.hasOwnProperty.call(value, propKey)) {
          errors.push(
            ...validateAgainstSchema(
              value[propKey],
              propSchema,
              rootSchema,
              schemaFile,
              schemasByFile,
              `${jsonPath}.${propKey}`
            )
          );
        }
      }
    }
    if (schema.additionalProperties === false) {
      const allowed = new Set(Object.keys(schema.properties ?? {}));
      for (const key of keys) {
        if (!allowed.has(key)) {
          errors.push(`${jsonPath}: unknown property "${key}"`);
        }
      }
    } else if (schema.additionalProperties && typeof schema.additionalProperties === "object") {
      const explicit = new Set(Object.keys(schema.properties ?? {}));
      for (const key of keys) {
        if (!explicit.has(key)) {
          errors.push(
            ...validateAgainstSchema(
              value[key],
              schema.additionalProperties,
              rootSchema,
              schemaFile,
              schemasByFile,
              `${jsonPath}.${key}`
            )
          );
        }
      }
    }
  }
  if (schema.not) {
    const notErrs = validateAgainstSchema(value, schema.not, rootSchema, schemaFile, schemasByFile, jsonPath);
    if (notErrs.length === 0) {
      errors.push(`${jsonPath}: matched disallowed "not" schema`);
    }
  }
  if (Array.isArray(schema.allOf)) {
    for (const sub of schema.allOf) {
      errors.push(...validateAgainstSchema(value, sub, rootSchema, schemaFile, schemasByFile, jsonPath));
    }
  }
  if (Array.isArray(schema.oneOf)) {
    const matches = schema.oneOf.filter(
      (sub) => validateAgainstSchema(value, sub, rootSchema, schemaFile, schemasByFile, jsonPath).length === 0
    );
    if (matches.length !== 1) {
      errors.push(`${jsonPath}: expected exactly 1 oneOf match, got ${matches.length}`);
    }
  }
  if (schema.if && schema.then) {
    const ifErrs = validateAgainstSchema(value, schema.if, rootSchema, schemaFile, schemasByFile, jsonPath);
    if (ifErrs.length === 0) {
      errors.push(...validateAgainstSchema(value, schema.then, rootSchema, schemaFile, schemasByFile, jsonPath));
    }
  }
  return errors;
}

export function loadConfigSchemas(repoRoot = DEFAULT_REPO_ROOT) {
  const schemaDir = path.join(path.resolve(repoRoot), "config", "schema");
  const schemasByFile = new Map();
  if (!fs.existsSync(schemaDir)) {
    throw new CliError(`Config schema directory missing: ${schemaDir}`);
  }
  for (const name of fs.readdirSync(schemaDir)) {
    if (name.endsWith(".json")) {
      const fullPath = path.join(schemaDir, name);
      schemasByFile.set(fullPath, readStrictJsonFile(fullPath));
    }
  }
  return { schemaDir, schemasByFile };
}

export function validateRoleConfigObject(roleConfig, options = {}) {
  const repoRoot = path.resolve(options.repoRoot ?? DEFAULT_REPO_ROOT);
  const { schemaDir, schemasByFile } = options.schemas ?? loadConfigSchemas(repoRoot);
  const roleSchemaPath = path.join(schemaDir, "role-config.schema.json");
  const roleSchema = schemasByFile.get(roleSchemaPath);
  const errors = [];

  const secretFindings = findRawSecretsInObject(roleConfig, "$");
  errors.push(...secretFindings);

  errors.push(
    ...validateAgainstSchema(roleConfig, roleSchema, roleSchema, roleSchemaPath, schemasByFile)
  );

  if (options.requireProductionProfile) {
    if (roleConfig.profile !== "release" && roleConfig.profile !== "self_hosted") {
      errors.push(`$.profile: production deployment requires "release" or "self_hosted", got "${roleConfig.profile}"`);
    }
  }

  if (roleConfig.profile === "release" || roleConfig.profile === "self_hosted") {
    if (roleConfig.database) {
      const host = String(roleConfig.database.host ?? "").toLowerCase();
      if (
        FORBIDDEN_RELEASE_HOSTS.has(host) ||
        (host.endsWith(".local") && !host.endsWith(".svc.cluster.local")) ||
        host.endsWith(".localhost")
      ) {
        errors.push(`$.database.host: forbidden local/loopback host "${host}" in ${roleConfig.profile} profile`);
      }
      if (roleConfig.database.tls_mode !== "verify_full") {
        errors.push(`$.database.tls_mode: must be "verify_full" in ${roleConfig.profile}`);
      }
    }
    if (roleConfig.broker) {
      for (const srv of roleConfig.broker.servers ?? []) {
        if (/^nats:\/\//i.test(srv) || /(?:127\.0\.0\.1|localhost)/i.test(srv)) {
          errors.push(`$.broker.servers: plaintext or loopback server "${srv}" forbidden in ${roleConfig.profile}`);
        }
      }
      if (roleConfig.broker.tls?.reject_unauthorized !== true || roleConfig.broker.tls?.enabled !== true) {
        errors.push(`$.broker.tls: TLS verification must be enabled with reject_unauthorized=true`);
      }
    }
    if (roleConfig.http?.public_origin) {
      if (!/^https:\/\//i.test(roleConfig.http.public_origin) || /127\.0\.0\.1|localhost/i.test(roleConfig.http.public_origin)) {
        errors.push(`$.http.public_origin: must be public HTTPS origin in ${roleConfig.profile}`);
      }
    }
    if (roleConfig.egress?.allow_fixture_receiver === true) {
      errors.push(`$.egress.allow_fixture_receiver: must be false in ${roleConfig.profile}`);
    }
  }

  return errors;
}

function isSelfHostedDeploymentProfile(profile) {
  if (profile.deployment_mode === "self_hosted" || profile.profile === "self_hosted") {
    return true;
  }
  const infraRoot = String(profile.infrastructure_root ?? "").replace(/\\/g, "/");
  if (
    infraRoot.includes("compose.prod.yaml") ||
    infraRoot.includes("overlays/selfhosted")
  ) {
    return true;
  }
  return false;
}

function checkOriginNoLocal(origin, fieldPath, errors) {
  if (typeof origin !== "string" || !origin.startsWith("https://")) {
    errors.push(`${fieldPath}: must start with https://`);
    return;
  }
  try {
    const u = new URL(origin);
    const h = u.hostname.toLowerCase();
    if (h === "localhost" || h === "127.0.0.1" || h === "::1" || h.endsWith(".local")) {
      errors.push(`${fieldPath}: loopback/local host "${h}" not permitted in production profile`);
    }
  } catch {
    errors.push(`${fieldPath}: invalid URL`);
  }
}

function validateRichRoleEntries(roles, errors) {
  const seen = new Set();
  for (let i = 0; i < roles.length; i += 1) {
    const entry = roles[i];
    const prefix = `$.roles[${i}]`;
    if (typeof entry === "string") {
      if (!ALLOWED_ROLE_NAMES.has(entry)) {
        errors.push(`${prefix}: unknown role "${entry}"`);
      }
      seen.add(entry);
      continue;
    }
    if (!entry || typeof entry !== "object" || Array.isArray(entry)) {
      errors.push(`${prefix}: expected role string or role object`);
      continue;
    }
    const allowedKeys = new Set([
      "process",
      "workspace",
      "health_contract",
      "instance_profile_ref",
      "config_digest",
      "desired_count",
      "db_role",
      "secret_purposes",
      "outbound_destinations"
    ]);
    for (const k of Object.keys(entry)) {
      if (!allowedKeys.has(k)) {
        errors.push(`${prefix}: unknown role field "${k}"`);
      }
    }
    if (typeof entry.process !== "string" || !ALLOWED_ROLE_NAMES.has(entry.process)) {
      errors.push(`${prefix}.process: unrecognized role "${entry.process}"`);
    } else {
      seen.add(entry.process);
    }
    if (typeof entry.desired_count !== "number" || !Number.isInteger(entry.desired_count) || entry.desired_count < 1) {
      errors.push(`${prefix}.desired_count: must be a positive integer`);
    }
    if (entry.secret_purposes !== undefined) {
      if (!Array.isArray(entry.secret_purposes)) {
        errors.push(`${prefix}.secret_purposes: must be an array`);
      } else {
        for (const purpose of entry.secret_purposes) {
          if (typeof purpose !== "string" || !ALLOWED_SECRET_PURPOSES.has(purpose)) {
            errors.push(`${prefix}.secret_purposes: forbidden or unknown purpose "${purpose}"`);
          }
        }
      }
    }
    if (entry.db_role !== undefined && (entry.db_role === "postgres" || entry.db_role === "rq_owner")) {
      errors.push(`${prefix}.db_role: runtime role cannot use superuser/owner "${entry.db_role}"`);
    }
  }
  return seen;
}

function validateSelfHostedProfileShape(profile, errors) {
  const allowedTop = new Set([
    "$schema",
    "profile_version",
    "deployment_mode",
    "profile",
    "deployment_name",
    "region",
    "cpu_platform",
    "dns_names",
    "roles",
    "resource_tags",
    "artifact_repositories",
    "infrastructure_root",
    "backend_config_path",
    "configuration_paths",
    "expected_schema_revision",
    "release_record_directory",
    "expected_identity_reference"
  ]);
  for (const key of Object.keys(profile)) {
    if (!allowedTop.has(key)) {
      errors.push(`$: unknown property "${key}"`);
    }
  }
  if (profile.profile_version !== 1) {
    errors.push("$.profile_version: must be 1");
  }
  if (typeof profile.deployment_name !== "string" || !/^[a-z0-9][a-z0-9-]{1,62}$/.test(profile.deployment_name)) {
    errors.push("$.deployment_name: must match ^[a-z0-9][a-z0-9-]{1,62}$");
  }
  if (profile.cpu_platform !== "linux/amd64" && profile.cpu_platform !== "linux/arm64") {
    errors.push('$.cpu_platform: must be "linux/amd64" or "linux/arm64"');
  }
  if (!profile.dns_names || typeof profile.dns_names !== "object") {
    errors.push("$.dns_names: required object");
  } else {
    checkOriginNoLocal(profile.dns_names.console_origin, "$.dns_names.console_origin", errors);
    checkOriginNoLocal(profile.dns_names.api_origin, "$.dns_names.api_origin", errors);
  }
  if (!Array.isArray(profile.roles) || profile.roles.length < 6) {
    errors.push("$.roles: must include at least 6 roles");
  }
  if (typeof profile.infrastructure_root !== "string" || profile.infrastructure_root.length === 0) {
    errors.push("$.infrastructure_root: required string");
  }
  if (!profile.configuration_paths || typeof profile.configuration_paths !== "object") {
    errors.push("$.configuration_paths: required map");
  }
  if (typeof profile.expected_schema_revision !== "string" || !/^[0-9]{4}$/.test(profile.expected_schema_revision)) {
    errors.push("$.expected_schema_revision: must be 4-digit revision string");
  }
  if (typeof profile.release_record_directory !== "string" || profile.release_record_directory.length === 0) {
    errors.push("$.release_record_directory: required string");
  }
  if (typeof profile.expected_identity_reference !== "string" || profile.expected_identity_reference.length === 0) {
    errors.push("$.expected_identity_reference: required string");
  }
}

export function validateDeploymentProfileFile(profilePath, options = {}) {
  const resolvedProfilePath = path.resolve(profilePath);
  const repoRoot = path.resolve(options.repoRoot ?? DEFAULT_REPO_ROOT);
  const schemas = loadConfigSchemas(repoRoot);
  const profile = readStrictJsonFile(resolvedProfilePath);
  const errors = [];

  errors.push(...findRawSecretsInObject(profile, "$"));

  const selfHosted = isSelfHostedDeploymentProfile(profile);
  const deploymentMode = selfHosted ? "self_hosted" : "aws_release";

  if (selfHosted) {
    validateSelfHostedProfileShape(profile, errors);
  } else if (Array.isArray(profile.roles) && profile.roles.some((r) => typeof r === "object" && r !== null)) {
    const withoutRoles = { ...profile, roles: profile.roles.map((r) => (typeof r === "string" ? r : r?.process ?? "unknown")) };
    const schemaPath = path.join(schemas.schemaDir, "deployment-profile.schema.json");
    const schema = schemas.schemasByFile.get(schemaPath);
    errors.push(...validateAgainstSchema(withoutRoles, schema, schema, schemaPath, schemas.schemasByFile));
  } else {
    const schemaPath = path.join(schemas.schemaDir, "deployment-profile.schema.json");
    const schema = schemas.schemasByFile.get(schemaPath);
    errors.push(...validateAgainstSchema(profile, schema, schema, schemaPath, schemas.schemasByFile));
  }

  if (profile.dns_names) {
    checkOriginNoLocal(profile.dns_names.console_origin, "$.dns_names.console_origin", errors);
    checkOriginNoLocal(profile.dns_names.api_origin, "$.dns_names.api_origin", errors);
  }

  const seenRoles = Array.isArray(profile.roles) ? validateRichRoleEntries(profile.roles, errors) : new Set();
  for (const requiredRole of ["api", "relay", "fanout", "sender", "coordinator", "admin"]) {
    if (!seenRoles.has(requiredRole)) {
      errors.push(`$.roles: missing required core role "${requiredRole}"`);
    }
  }

  if (typeof profile.expected_identity_reference === "string") {
    const idRef = profile.expected_identity_reference;
    if (/:root\b/i.test(idRef) || /:user\//i.test(idRef)) {
      errors.push("$.expected_identity_reference: root or static IAM user identity is forbidden; use workload/role federation");
    }
  }

  const baseDir = repoRoot;
  if (typeof profile.infrastructure_root === "string") {
    const infraAbs = path.resolve(baseDir, profile.infrastructure_root);
    if (!fs.existsSync(infraAbs)) {
      errors.push(`$.infrastructure_root: path does not exist (${profile.infrastructure_root})`);
    }
  }
  if (typeof profile.backend_config_path === "string" && profile.backend_config_path.length > 0) {
    const backendAbs = path.resolve(baseDir, profile.backend_config_path);
    if (!fs.existsSync(backendAbs)) {
      errors.push(`$.backend_config_path: path does not exist (${profile.backend_config_path})`);
    } else {
      const hcl = fs.readFileSync(backendAbs, "utf8");
      if (/\b(?:access_key|secret_key|session_token|token)\s*=/i.test(hcl)) {
        errors.push(`$.backend_config_path: backend HCL must never contain static credential attributes`);
      }
    }
  }

  const roleConfigs = {};
  const roleConfigDigests = {};
  if (profile.configuration_paths && typeof profile.configuration_paths === "object") {
    for (const [roleName, relConfigPath] of Object.entries(profile.configuration_paths)) {
      if (typeof relConfigPath !== "string" || path.isAbsolute(relConfigPath)) {
        errors.push(`$.configuration_paths.${roleName}: must be a repo-relative path`);
        continue;
      }
      const configAbs = path.resolve(baseDir, relConfigPath);
      if (!fs.existsSync(configAbs)) {
        errors.push(`$.configuration_paths.${roleName}: file missing (${relConfigPath})`);
        continue;
      }
      const cfg = readStrictJsonFile(configAbs);
      const roleErrors = validateRoleConfigObject(cfg, {
        repoRoot: baseDir,
        schemas,
        requireProductionProfile: true
      });
      for (const err of roleErrors) {
        errors.push(`configuration_paths.${roleName} (${relConfigPath}): ${err}`);
      }
      const expectedProcessRole = roleName === "provider_ingress" ? "provider_ingress" : roleName;
      if (cfg.process_role !== expectedProcessRole) {
        errors.push(
          `configuration_paths.${roleName}: expected process_role="${expectedProcessRole}", got "${cfg.process_role}"`
        );
      }
      if (selfHosted && cfg.profile !== "self_hosted") {
        errors.push(`configuration_paths.${roleName}: self_hosted deployment requires profile="self_hosted", got "${cfg.profile}"`);
      }
      if (!selfHosted && cfg.profile !== "release") {
        errors.push(`configuration_paths.${roleName}: AWS release deployment requires profile="release", got "${cfg.profile}"`);
      }
      if (roleName === "api" && ("broker" in cfg || "egress" in cfg)) {
        errors.push(`configuration_paths.api: api role must not hold broker or egress config`);
      }
      if (roleName === "sender" && ("broker" in cfg || "auth" in cfg)) {
        errors.push(`configuration_paths.sender: sender role must not hold broker or auth config`);
      }
      roleConfigs[roleName] = cfg;
      roleConfigDigests[roleName] = sha256Hex(canonicalizeJson(cfg));
    }
  }

  return {
    ok: errors.length === 0,
    deploymentMode,
    profilePath: resolvedProfilePath,
    profileSha256: sha256Hex(fs.readFileSync(resolvedProfilePath)),
    profile,
    roleConfigs,
    roleConfigDigests,
    errors
  };
}
