import fs from "node:fs";
import path from "node:path";

function stripInlineComment(raw) {
  let inSingle = false;
  let inDouble = false;
  let bracketDepth = 0;
  let braceDepth = 0;

  for (let i = 0; i < raw.length; i += 1) {
    const ch = raw[i];
    if (inSingle) {
      if (ch === "'") {
        if (raw[i + 1] === "'") {
          i += 1;
        } else {
          inSingle = false;
        }
      }
      continue;
    }
    if (inDouble) {
      if (ch === "\\") {
        i += 1;
      } else if (ch === "\"") {
        inDouble = false;
      }
      continue;
    }
    if (ch === "'") {
      inSingle = true;
    } else if (ch === "\"") {
      inDouble = true;
    } else if (ch === "[") {
      bracketDepth += 1;
    } else if (ch === "]") {
      bracketDepth = Math.max(0, bracketDepth - 1);
    } else if (ch === "{") {
      braceDepth += 1;
    } else if (ch === "}") {
      braceDepth = Math.max(0, braceDepth - 1);
    } else if (ch === "#" && bracketDepth === 0 && braceDepth === 0) {
      if (i === 0 || raw[i - 1] === " " || raw[i - 1] === "\t") {
        return raw.slice(0, i).trimEnd();
      }
    }
  }
  return raw.trimEnd();
}

function splitKeyValue(line) {
  let inSingle = false;
  let inDouble = false;
  let bracketDepth = 0;
  let braceDepth = 0;

  for (let i = 0; i < line.length; i += 1) {
    const ch = line[i];
    if (inSingle) {
      if (ch === "'") {
        if (line[i + 1] === "'") {
          i += 1;
        } else {
          inSingle = false;
        }
      }
      continue;
    }
    if (inDouble) {
      if (ch === "\\") {
        i += 1;
      } else if (ch === "\"") {
        inDouble = false;
      }
      continue;
    }
    if (ch === "'") {
      inSingle = true;
    } else if (ch === "\"") {
      inDouble = true;
    } else if (ch === "[") {
      bracketDepth += 1;
    } else if (ch === "]") {
      bracketDepth = Math.max(0, bracketDepth - 1);
    } else if (ch === "{") {
      braceDepth += 1;
    } else if (ch === "}") {
      braceDepth = Math.max(0, braceDepth - 1);
    } else if (ch === ":" && bracketDepth === 0 && braceDepth === 0) {
      const next = line[i + 1];
      if (next === undefined || next === " " || next === "\t") {
        const rawKey = line.slice(0, i).trim();
        const rawVal = line.slice(i + 1).trim();
        if (rawKey.length === 0) {
          return null;
        }
        return { key: unquoteKey(rawKey), value: rawVal };
      }
    }
  }
  return null;
}

function unquoteKey(rawKey) {
  if (rawKey.startsWith("\"") && rawKey.endsWith("\"") && rawKey.length >= 2) {
    try {
      return JSON.parse(rawKey);
    } catch {
      return rawKey.slice(1, -1);
    }
  }
  if (rawKey.startsWith("'") && rawKey.endsWith("'") && rawKey.length >= 2) {
    return rawKey.slice(1, -1).replace(/''/g, "'");
  }
  return rawKey;
}

function splitTopLevelFlow(inner) {
  const parts = [];
  let start = 0;
  let inSingle = false;
  let inDouble = false;
  let depth = 0;

  for (let i = 0; i < inner.length; i += 1) {
    const ch = inner[i];
    if (inSingle) {
      if (ch === "'") {
        if (inner[i + 1] === "'") {
          i += 1;
        } else {
          inSingle = false;
        }
      }
      continue;
    }
    if (inDouble) {
      if (ch === "\\") {
        i += 1;
      } else if (ch === "\"") {
        inDouble = false;
      }
      continue;
    }
    if (ch === "'") {
      inSingle = true;
    } else if (ch === "\"") {
      inDouble = true;
    } else if (ch === "[" || ch === "{") {
      depth += 1;
    } else if (ch === "]" || ch === "}") {
      depth -= 1;
    } else if (ch === "," && depth === 0) {
      parts.push(inner.slice(start, i).trim());
      start = i + 1;
    }
  }
  const tail = inner.slice(start).trim();
  if (tail.length > 0) {
    parts.push(tail);
  }
  return parts;
}

function parseScalar(raw) {
  const trimmed = raw.trim();
  if (trimmed === "" || trimmed === "null" || trimmed === "~") {
    return null;
  }
  if (trimmed === "true") {
    return true;
  }
  if (trimmed === "false") {
    return false;
  }
  if (trimmed.startsWith("'") && trimmed.endsWith("'") && trimmed.length >= 2) {
    return trimmed.slice(1, -1).replace(/''/g, "'");
  }
  if (trimmed.startsWith("\"") && trimmed.endsWith("\"") && trimmed.length >= 2) {
    try {
      return JSON.parse(trimmed);
    } catch {
      return trimmed.slice(1, -1);
    }
  }
  if (trimmed.startsWith("[") && trimmed.endsWith("]")) {
    const inner = trimmed.slice(1, -1).trim();
    if (inner.length === 0) {
      return [];
    }
    return splitTopLevelFlow(inner).map((item) => parseScalar(item));
  }
  if (trimmed.startsWith("{") && trimmed.endsWith("}")) {
    const inner = trimmed.slice(1, -1).trim();
    if (inner.length === 0) {
      return {};
    }
    const obj = {};
    for (const pair of splitTopLevelFlow(inner)) {
      const kv = splitKeyValue(pair);
      if (!kv) {
        throw new Error(`Invalid flow mapping entry: ${pair}`);
      }
      obj[kv.key] = parseScalar(kv.value);
    }
    return obj;
  }
  if (/^-?(?:0|[1-9]\d*)$/.test(trimmed)) {
    const num = Number.parseInt(trimmed, 10);
    if (Number.isSafeInteger(num)) {
      return num;
    }
  }
  if (/^0[0-7]+$/.test(trimmed)) {
    return Number.parseInt(trimmed, 8);
  }
  if (/^-?\d+\.\d+$/.test(trimmed)) {
    const num = Number(trimmed);
    if (Number.isFinite(num)) {
      return num;
    }
  }
  return trimmed;
}

function getIndent(line) {
  let count = 0;
  while (count < line.length && line[count] === " ") {
    count += 1;
  }
  return count;
}

function isBlankOrComment(line) {
  const trimmed = line.trim();
  return trimmed.length === 0 || trimmed.startsWith("#");
}

function isDocSeparator(line) {
  return /^(?:---|\.\.\.)(?:\s*(?:#.*)?)?$/.test(line.trim()) && getIndent(line) === 0;
}

function parseBlockScalar(lines, state, parentIndent, indicator) {
  const folded = indicator.startsWith(">");
  const chompStrip = indicator.includes("-");
  const chompKeep = indicator.includes("+");
  const collected = [];
  let blockIndent = null;

  while (state.index < lines.length) {
    const rawLine = lines[state.index];
    if (rawLine.trim().length === 0) {
      collected.push("");
      state.index += 1;
      continue;
    }
    const indent = getIndent(rawLine);
    if (indent <= parentIndent) {
      break;
    }
    if (blockIndent === null) {
      blockIndent = indent;
    }
    if (indent < blockIndent) {
      break;
    }
    collected.push(rawLine.slice(blockIndent));
    state.index += 1;
  }

  let trailingEmpty = 0;
  while (collected.length > 0 && collected[collected.length - 1] === "") {
    collected.pop();
    trailingEmpty += 1;
  }

  let body = folded ? collected.join(" ") : collected.join("\n");
  if (chompKeep) {
    body += "\n".repeat(trailingEmpty + 1);
  } else if (!chompStrip && body.length > 0) {
    body += "\n";
  }
  return body;
}

function skipIgnored(lines, state) {
  while (state.index < lines.length && isBlankOrComment(lines[state.index])) {
    state.index += 1;
  }
}

function parseSequence(lines, state, seqIndent) {
  const items = [];
  while (state.index < lines.length) {
    skipIgnored(lines, state);
    if (state.index >= lines.length || isDocSeparator(lines[state.index])) {
      break;
    }
    const line = lines[state.index];
    const indent = getIndent(line);
    if (indent < seqIndent) {
      break;
    }
    if (indent > seqIndent) {
      throw new Error(`Unexpected indentation at line ${state.index + 1}: ${line}`);
    }
    const trimmed = line.slice(indent);
    if (!trimmed.startsWith("-") || (trimmed.length > 1 && trimmed[1] !== " " && trimmed[1] !== "\t")) {
      break;
    }

    const afterDashRaw = trimmed.slice(1);
    const leadingSpaces = afterDashRaw.length - afterDashRaw.trimStart().length;
    const contentOffset = indent + 1 + Math.max(leadingSpaces, 1);
    const content = stripInlineComment(afterDashRaw.trim());
    state.index += 1;

    if (content.length === 0) {
      skipIgnored(lines, state);
      if (state.index >= lines.length || isDocSeparator(lines[state.index]) || getIndent(lines[state.index]) <= seqIndent) {
        items.push(null);
      } else {
        items.push(parseBlock(lines, state, getIndent(lines[state.index])));
      }
      continue;
    }

    if (/^[|>][+-]?$/.test(content)) {
      items.push(parseBlockScalar(lines, state, seqIndent, content));
      continue;
    }

    const kv = splitKeyValue(content);
    if (kv) {
      const obj = {};
      assignMappingEntry(obj, kv, lines, state, contentOffset);
      while (state.index < lines.length) {
        skipIgnored(lines, state);
        if (state.index >= lines.length || isDocSeparator(lines[state.index])) {
          break;
        }
        const nextLine = lines[state.index];
        const nextIndent = getIndent(nextLine);
        if (nextIndent < contentOffset) {
          break;
        }
        if (nextIndent !== contentOffset) {
          throw new Error(`Unexpected mapping indentation inside list at line ${state.index + 1}`);
        }
        const nextClean = stripInlineComment(nextLine.slice(nextIndent));
        const nextKv = splitKeyValue(nextClean);
        if (!nextKv) {
          break;
        }
        state.index += 1;
        assignMappingEntry(obj, nextKv, lines, state, contentOffset);
      }
      items.push(obj);
      continue;
    }

    items.push(parseScalar(content));
  }
  return items;
}

function assignMappingEntry(obj, kv, lines, state, keyIndent) {
  if (kv.key === "__proto__" || kv.key === "constructor" || kv.key === "prototype") {
    throw new Error(`Forbidden prototype key "${kv.key}" in YAML`);
  }
  if (kv.value.length === 0) {
    skipIgnored(lines, state);
    if (state.index >= lines.length || isDocSeparator(lines[state.index])) {
      obj[kv.key] = null;
      return;
    }
    const nextLine = lines[state.index];
    const nextIndent = getIndent(nextLine);
    const nextTrimmed = nextLine.slice(nextIndent);
    if (nextIndent > keyIndent) {
      obj[kv.key] = parseBlock(lines, state, nextIndent);
    } else if (
      nextIndent === keyIndent &&
      (nextTrimmed === "-" || nextTrimmed.startsWith("- "))
    ) {
      obj[kv.key] = parseSequence(lines, state, nextIndent);
    } else {
      obj[kv.key] = null;
    }
    return;
  }

  if (/^[|>][+-]?$/.test(kv.value)) {
    obj[kv.key] = parseBlockScalar(lines, state, keyIndent, kv.value);
    return;
  }

  obj[kv.key] = parseScalar(kv.value);
}

function parseMapping(lines, state, mapIndent) {
  const obj = {};
  while (state.index < lines.length) {
    skipIgnored(lines, state);
    if (state.index >= lines.length || isDocSeparator(lines[state.index])) {
      break;
    }
    const line = lines[state.index];
    const indent = getIndent(line);
    if (indent < mapIndent) {
      break;
    }
    if (indent > mapIndent) {
      throw new Error(`Unexpected indentation at line ${state.index + 1}: ${line}`);
    }
    const clean = stripInlineComment(line.slice(indent));
    const kv = splitKeyValue(clean);
    if (!kv) {
      throw new Error(`Expected mapping key: value at line ${state.index + 1}: ${line}`);
    }
    state.index += 1;
    assignMappingEntry(obj, kv, lines, state, mapIndent);
  }
  return obj;
}

function parseBlock(lines, state, indent) {
  const line = lines[state.index];
  const trimmed = line.slice(indent);
  if (trimmed === "-" || trimmed.startsWith("- ")) {
    return parseSequence(lines, state, indent);
  }
  return parseMapping(lines, state, indent);
}

export function parseYamlDocuments(yamlText, sourceLabel = "yaml") {
  const lines = yamlText.replace(/\r\n/g, "\n").replace(/\r/g, "\n").split("\n");
  const state = { index: 0 };
  const docs = [];

  while (state.index < lines.length) {
    skipIgnored(lines, state);
    if (state.index >= lines.length) {
      break;
    }
    const line = lines[state.index];
    if (isDocSeparator(line)) {
      state.index += 1;
      continue;
    }
    const indent = getIndent(line);
    try {
      const doc = parseBlock(lines, state, indent);
      if (doc !== null && doc !== undefined) {
        docs.push(doc);
      }
    } catch (err) {
      throw new Error(
        `YAML parse error in ${sourceLabel}: ${err instanceof Error ? err.message : String(err)}`
      );
    }
  }
  return docs;
}

function deepStrategicMerge(target, patch) {
  if (patch === null || patch === undefined) {
    return target;
  }
  if (typeof patch !== "object" || Array.isArray(patch)) {
    return patch;
  }
  if (!target || typeof target !== "object" || Array.isArray(target)) {
    return structuredClone(patch);
  }
  const merged = { ...target };
  for (const [key, val] of Object.entries(patch)) {
    if (Array.isArray(val) && Array.isArray(merged[key])) {
      merged[key] = structuredClone(val);
    } else if (val && typeof val === "object" && !Array.isArray(val)) {
      merged[key] = deepStrategicMerge(merged[key], val);
    } else {
      merged[key] = val;
    }
  }
  return merged;
}

function resourceKey(doc) {
  const apiVersion = String(doc?.apiVersion ?? "");
  const kind = String(doc?.kind ?? "");
  const name = String(doc?.metadata?.name ?? "");
  const namespace = String(doc?.metadata?.namespace ?? "");
  return `${apiVersion}|${kind}|${namespace}|${name}`;
}

function applyImageTransform(imageStr, imageRules) {
  if (typeof imageStr !== "string" || imageRules.length === 0) {
    return imageStr;
  }
  const withoutDigest = imageStr.split("@")[0];
  const lastColon = withoutDigest.lastIndexOf(":");
  const lastSlash = withoutDigest.lastIndexOf("/");
  const hasTag = lastColon > lastSlash;
  const repoName = hasTag ? withoutDigest.slice(0, lastColon) : withoutDigest;

  for (const rule of imageRules) {
    if (rule?.name === repoName || rule?.name === imageStr) {
      const newName = rule.newName ?? repoName;
      if (rule.digest) {
        const digestPart = rule.digest.startsWith("sha256:") ? rule.digest : `sha256:${rule.digest}`;
        return `${newName}@${digestPart}`;
      }
      if (rule.newTag) {
        return `${newName}:${rule.newTag}`;
      }
      return hasTag ? `${newName}${withoutDigest.slice(lastColon)}` : newName;
    }
  }
  return imageStr;
}

function applyImagesToWorkloads(docs, imageRules) {
  if (!Array.isArray(imageRules) || imageRules.length === 0) {
    return docs;
  }
  for (const doc of docs) {
    const podSpec =
      doc?.kind === "Pod"
        ? doc?.spec
        : doc?.spec?.template?.spec ?? doc?.spec?.jobTemplate?.spec?.template?.spec;
    if (!podSpec || typeof podSpec !== "object") {
      continue;
    }
    for (const field of ["initContainers", "containers", "ephemeralContainers"]) {
      const list = podSpec[field];
      if (!Array.isArray(list)) {
        continue;
      }
      for (const container of list) {
        if (typeof container?.image === "string") {
          container.image = applyImageTransform(container.image, imageRules);
        }
      }
    }
  }
  return docs;
}

export function loadKustomizeDirectory(dirPath, options = {}) {
  const resolvedDir = path.resolve(dirPath);
  const kustomFile = ["kustomization.yaml", "kustomization.yml"]
    .map((f) => path.join(resolvedDir, f))
    .find((p) => fs.existsSync(p));

  const sources = options.sources ?? new WeakMap();
  const explicitImageRules = options.imageRules ?? [];

  if (!kustomFile) {
    const docs = [];
    const entries = fs
      .readdirSync(resolvedDir, { withFileTypes: true })
      .filter((e) => e.isFile() && /\.(?:yaml|yml)$/i.test(e.name))
      .sort((a, b) => a.name.localeCompare(b.name));
    for (const entry of entries) {
      const fullPath = path.join(resolvedDir, entry.name);
      const parsed = parseYamlDocuments(fs.readFileSync(fullPath, "utf8"), fullPath);
      for (const doc of parsed) {
        sources.set(doc, fullPath);
        docs.push(doc);
      }
    }
    return { documents: docs, sources, imageRules: explicitImageRules };
  }

  const kustomDocs = parseYamlDocuments(fs.readFileSync(kustomFile, "utf8"), kustomFile);
  const kustom = kustomDocs[0] ?? {};
  const docs = [];
  const docByKey = new Map();

  const resources = Array.isArray(kustom.resources) ? kustom.resources : [];
  for (const resEntry of resources) {
    const targetPath = path.resolve(resolvedDir, String(resEntry));
    if (!fs.existsSync(targetPath)) {
      throw new Error(`Kustomization resource not found: ${resEntry} (from ${kustomFile})`);
    }
    const stat = fs.statSync(targetPath);
    if (stat.isDirectory()) {
      const child = loadKustomizeDirectory(targetPath, { sources, imageRules: explicitImageRules });
      for (const d of child.documents) {
        const key = resourceKey(d);
        if (!docByKey.has(key)) {
          docByKey.set(key, docs.length);
          docs.push(d);
        } else {
          docs[docByKey.get(key)] = d;
        }
      }
    } else {
      const parsed = parseYamlDocuments(fs.readFileSync(targetPath, "utf8"), targetPath);
      for (const d of parsed) {
        sources.set(d, targetPath);
        const key = resourceKey(d);
        if (!docByKey.has(key)) {
          docByKey.set(key, docs.length);
          docs.push(d);
        } else {
          docs[docByKey.get(key)] = d;
        }
      }
    }
  }

  const patches = Array.isArray(kustom.patches) ? kustom.patches : [];
  for (const patchEntry of patches) {
    const patchRel = typeof patchEntry === "string" ? patchEntry : patchEntry?.path;
    if (!patchRel) {
      continue;
    }
    const patchPath = path.resolve(resolvedDir, String(patchRel));
    if (!fs.existsSync(patchPath)) {
      throw new Error(`Kustomization patch not found: ${patchRel} (from ${kustomFile})`);
    }
    const patchDocs = parseYamlDocuments(fs.readFileSync(patchPath, "utf8"), patchPath);
    for (const patchDoc of patchDocs) {
      const key = resourceKey(patchDoc);
      const idx = docByKey.get(key);
      if (idx !== undefined) {
        const prevSource = sources.get(docs[idx]);
        const merged = deepStrategicMerge(docs[idx], patchDoc);
        sources.set(merged, `${prevSource ?? kustomFile} + ${patchPath}`);
        docs[idx] = merged;
      }
    }
  }

  const localImages = Array.isArray(kustom.images) ? kustom.images : [];
  if (localImages.length > 0) {
    applyImagesToWorkloads(docs, localImages);
    explicitImageRules.push(...localImages);
  }

  return { documents: docs, sources, imageRules: explicitImageRules };
}
