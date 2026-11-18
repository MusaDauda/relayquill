import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const CONFIG_DIR = path.join(REPO_ROOT, "config");

function loadJson(filePath) {
  return JSON.parse(fs.readFileSync(filePath, "utf8"));
}

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

function validateAgainstSchema(value, schema, rootSchema, schemaFile, schemasByFile, jsonPath = "$") {
  const errors = [];
  if (schema === true) {
    return errors;
  }
  if (schema === false) {
    return [`${jsonPath}: disallowed by false schema`];
  }
  if (schema.$ref) {
    const target = resolvePointer(rootSchema, schema.$ref, schemasByFile, schemaFile);
    errors.push(...validateAgainstSchema(value, target.schema, target.rootSchema, target.schemaFile, schemasByFile, jsonPath));
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
        errors.push(...validateAgainstSchema(item, schema.items, rootSchema, schemaFile, schemasByFile, `${jsonPath}[${idx}]`));
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
            ...validateAgainstSchema(value[propKey], propSchema, rootSchema, schemaFile, schemasByFile, `${jsonPath}.${propKey}`)
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

const schemaDir = path.join(CONFIG_DIR, "schema");
const schemasByFile = new Map(
  fs.readdirSync(schemaDir)
    .filter((name) => name.endsWith(".json"))
    .map((name) => {
      const fullPath = path.join(schemaDir, name);
      return [fullPath, loadJson(fullPath)];
    })
);

test("all config JSON templates parse cleanly and validate against their declared $schema", () => {
  const jsonFiles = fs.readdirSync(CONFIG_DIR)
    .filter((name) => name.endsWith(".json"))
    .sort();
  assert.ok(jsonFiles.length >= 40, `Expected full baseline templates, found ${jsonFiles.length}`);

  const observedProfiles = new Set();

  for (const fileName of jsonFiles) {
    const filePath = path.join(CONFIG_DIR, fileName);
    const data = loadJson(filePath);
    assert.equal(typeof data.$schema, "string", `${fileName} must declare $schema`);
    const schemaPath = path.resolve(CONFIG_DIR, data.$schema);
    assert.ok(fs.existsSync(schemaPath), `${fileName} $schema target missing: ${schemaPath}`);

    const schema = schemasByFile.get(schemaPath);
    const errors = validateAgainstSchema(data, schema, schema, schemaPath, schemasByFile);
    assert.deepEqual(errors, [], `${fileName} failed schema validation:\n${errors.join("\n")}`);

    if (typeof data.profile === "string") {
      observedProfiles.add(data.profile);
    }
  }

  for (const requiredProfile of [
    "portable_pglite",
    "development_trusted_local",
    "hosted_neon",
    "hosted_supabase",
    "hosted_synadia_ngs",
    "release"
  ]) {
    assert.ok(observedProfiles.has(requiredProfile), `Missing template for profile ${requiredProfile}`);
  }
});

test("role-config schema rejects privilege/role leaks and insecure release or hosted mutations", () => {
  const roleSchemaPath = path.join(schemaDir, "role-config.schema.json");
  const roleSchema = schemasByFile.get(roleSchemaPath);

  // 1. Unknown/dormant broker block on api role
  const apiWithBroker = loadJson(path.join(CONFIG_DIR, "development.api.json"));
  apiWithBroker.broker = loadJson(path.join(CONFIG_DIR, "development.relay.json")).broker;
  assert.ok(validateAgainstSchema(apiWithBroker, roleSchema, roleSchema, roleSchemaPath, schemasByFile).length > 0);

  // 2. Release profile with allow_fixture_receiver: true
  const badReleaseSender = loadJson(path.join(CONFIG_DIR, "release.sender.json"));
  badReleaseSender.egress.allow_fixture_receiver = true;
  assert.ok(validateAgainstSchema(badReleaseSender, roleSchema, roleSchema, roleSchemaPath, schemasByFile).length > 0);

  // 3. Hosted Neon with connection_timeout_ms < 10000
  const badNeon = loadJson(path.join(CONFIG_DIR, "hosted.neon.api.json"));
  badNeon.database.connection_timeout_ms = 5000;
  assert.ok(validateAgainstSchema(badNeon, roleSchema, roleSchema, roleSchemaPath, schemasByFile).length > 0);

  // 4. Hosted Supabase with separate_databases
  const badSupabase = loadJson(path.join(CONFIG_DIR, "hosted.supabase.api.json"));
  badSupabase.database.isolation = "separate_databases";
  assert.ok(validateAgainstSchema(badSupabase, roleSchema, roleSchema, roleSchemaPath, schemasByFile).length > 0);
});
