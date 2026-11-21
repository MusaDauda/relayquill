import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";

export interface ProducerIpcRef {
  readonly env_name: string;
  readonly channel: string;
  readonly runtime_dir_env?: string | undefined;
}

export interface ProducerSecretProviderSettings {
  readonly mode: string;
  readonly ipc?: ProducerIpcRef | undefined;
  readonly ipc_endpoint?: string | undefined;
}

function sanitizeSegment(value: string, fallback: string): string {
  const cleaned = value.trim().replace(/[^a-zA-Z0-9_-]/g, "-");
  return cleaned.length > 0 ? cleaned : fallback;
}

export function resolveCustodyIpcEndpoint(
  ref: ProducerIpcRef,
  env: Readonly<Record<string, string | undefined>> = process.env
): string {
  const safeEnv = sanitizeSegment(ref.env_name || "dev", "dev");
  const safeChannel = sanitizeSegment(ref.channel || "provider", "provider");
  if (process.platform === "win32") {
    return `\\\\.\\pipe\\relayquill-${safeEnv}-${safeChannel}`;
  }
  let runtimeDir: string | undefined;
  if (ref.runtime_dir_env !== undefined) {
    const rawDir = env[ref.runtime_dir_env];
    if (typeof rawDir === "string" && rawDir.trim().length > 0) {
      const trimmed = rawDir.trim();
      if (trimmed.includes("\0") || trimmed.split(/[\\/]/).includes("..")) {
        throw new Error(`Invalid runtime directory env ${ref.runtime_dir_env}`);
      }
      if (!path.isAbsolute(trimmed)) {
        throw new Error(`Runtime directory env ${ref.runtime_dir_env} must be an absolute path`);
      }
      runtimeDir = trimmed;
    }
  }
  const baseDir = runtimeDir ?? path.join(os.tmpdir(), `relayquill-${safeEnv}`);
  return path.join(baseDir, `${safeChannel}.sock`);
}

async function fetchSecretViaIpc(
  endpoint: string,
  secretRef: string,
  timeoutMs = 5_000
): Promise<string> {
  return new Promise<string>((resolve, reject) => {
    const socket = net.connect(endpoint);
    let settled = false;
    const chunks: Buffer[] = [];

    const timer = setTimeout(() => {
      if (!settled) {
        settled = true;
        socket.destroy();
        reject(new Error(`Timed out reading custody secret "${secretRef}" over IPC`));
      }
    }, timeoutMs);

    const done = (err: Error | null, value?: string): void => {
      if (settled) {
        return;
      }
      settled = true;
      clearTimeout(timer);
      socket.destroy();
      if (err !== null) {
        reject(err);
      } else {
        resolve(value ?? "");
      }
    };

    socket.on("error", (err) => done(err));
    socket.on("data", (chunk) => {
      chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
      const combined = Buffer.concat(chunks);
      const newlineIdx = combined.indexOf(0x0a);
      if (newlineIdx === -1) {
        return;
      }
      const line = combined.subarray(0, newlineIdx).toString("utf8").trim();
      let parsed: unknown;
      try {
        parsed = JSON.parse(line);
      } catch (err) {
        done(err instanceof Error ? err : new Error("Invalid IPC JSON response"));
        return;
      }
      if (typeof parsed !== "object" || parsed === null) {
        done(new Error("Malformed IPC response object"));
        return;
      }
      const rec = parsed as Record<string, unknown>;
      if (rec["ok"] !== true) {
        const msg = typeof rec["message"] === "string" ? rec["message"] : "IPC custody lookup failed";
        done(new Error(msg));
        return;
      }
      const b64 = rec["valueBase64"];
      if (typeof b64 !== "string" || b64.length === 0) {
        done(new Error("IPC custody response missing valueBase64"));
        return;
      }
      const decoded = Buffer.from(b64, "base64").toString("utf8").trim();
      done(null, decoded);
    });

    socket.on("connect", () => {
      socket.write(`${JSON.stringify({ op: "get", ref: secretRef })}\n`);
    });
  });
}

export async function resolveProducerCredentialFromRef(params: {
  readonly secretRef: string;
  readonly env?: Readonly<Record<string, string | undefined>> | undefined;
  readonly secretProvider?: ProducerSecretProviderSettings | undefined;
}): Promise<string> {
  const env = params.env ?? process.env;
  const trimmed = params.secretRef.trim();

  if (trimmed.startsWith("env:")) {
    const varName = trimmed.slice("env:".length);
    if (!/^[A-Z][A-Z0-9_]{1,127}$/.test(varName)) {
      throw new Error(`Invalid environment secret reference: "${trimmed}"`);
    }
    const val = env[varName];
    if (typeof val !== "string" || val.trim().length === 0) {
      throw new Error(`Environment variable "${varName}" referenced by "${trimmed}" is unset or empty`);
    }
    return val.trim();
  }

  if (trimmed.startsWith("file:")) {
    const rawPath = trimmed.slice("file:".length);
    if (rawPath.length === 0 || rawPath.includes("\0") || rawPath.split(/[\\/]/).includes("..")) {
      throw new Error(`Unsafe file secret reference path: "${trimmed}"`);
    }
    const content = fs.readFileSync(path.resolve(rawPath), "utf8").trim();
    if (content.length === 0) {
      throw new Error(`Secret file referenced by "${trimmed}" is empty`);
    }
    return content;
  }

  if (trimmed.startsWith("custody:")) {
    const endpoint =
      params.secretProvider?.ipc_endpoint ??
      (params.secretProvider?.ipc !== undefined
        ? resolveCustodyIpcEndpoint(params.secretProvider.ipc, env)
        : undefined);
    if (endpoint === undefined) {
      throw new Error(
        `Cannot resolve custody secret "${trimmed}" without secret_provider.ipc configuration`
      );
    }
    const val = await fetchSecretViaIpc(endpoint, trimmed);
    if (val.length === 0) {
      throw new Error(`Empty custody secret returned for "${trimmed}"`);
    }
    return val;
  }

  throw new Error(
    `Unsupported credential reference "${trimmed}". Expected env:<VAR>, file:<PATH>, or custody:<KEY>.`
  );
}
