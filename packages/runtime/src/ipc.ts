import { spawn } from "node:child_process";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";

export const MAX_IPC_FRAME_BYTES = 64 * 1024;
export const DEFAULT_IPC_TIMEOUT_MS = 5_000;

export type IpcErrorCode =
  | "EIPC_INVALID_FRAME"
  | "EIPC_FRAME_TOO_LARGE"
  | "EIPC_SECURITY_VIOLATION"
  | "EIPC_TIMEOUT"
  | "EIPC_PROTOCOL"
  | "EIPC_INVALID_ENDPOINT";

export class IpcError extends Error {
  readonly code: IpcErrorCode;

  constructor(code: IpcErrorCode, message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "IpcError";
    Object.setPrototypeOf(this, new.target.prototype);
    this.code = code;
  }
}

export interface IpcChannelRef {
  readonly env_name: string;
  readonly channel: string;
  readonly runtime_dir_env?: string | undefined;
}

export interface SddlAce {
  readonly type: string;
  readonly flags: string;
  readonly rights: string;
  readonly objectGuid: string;
  readonly inheritObjectGuid: string;
  readonly trustee: string;
}

export interface WindowsPipeSddlValidation {
  readonly ok: boolean;
  readonly ownerSid: string | null;
  readonly daclProtected: boolean;
  readonly aces: readonly SddlAce[];
  readonly violations: readonly string[];
}

export interface WindowsPipeSecurityReport extends WindowsPipeSddlValidation {
  readonly platform: "win32";
  readonly endpoint: string;
  readonly currentUserSid: string;
  readonly sddl: string;
}

export interface PosixSocketSecurityReport {
  readonly platform: NodeJS.Platform;
  readonly endpoint: string;
  readonly dirMode: string;
  readonly sockMode: string;
  readonly ok: boolean;
  readonly violations: readonly string[];
}

export type IpcSecurityReport = WindowsPipeSecurityReport | PosixSocketSecurityReport;

export interface IpcSecurityOptions {
  readonly allowBuiltInAdmins?: boolean | undefined;
}

export interface IpcEndpointOptions {
  readonly runtimeDir?: string | undefined;
}

export interface SendIpcFrameOptions extends IpcSecurityOptions {
  readonly maxFrameBytes?: number | undefined;
  readonly timeoutMs?: number | undefined;
  readonly verifySecurity?: boolean | undefined;
}

export interface IpcServerOptions extends IpcSecurityOptions {
  readonly maxFrameBytes?: number | undefined;
  readonly allowEmptyProbeDisconnect?: boolean | undefined;
}

export type IpcRequestHandler = (request: unknown) => Promise<unknown>;

export interface IpcServerHandle {
  readonly endpoint: string;
  listen(): Promise<IpcSecurityReport>;
  verifySecurity(): Promise<IpcSecurityReport>;
  close(): Promise<void>;
}

function sanitizeSegment(value: string, fallback: string): string {
  const cleaned = value.trim().replace(/[^a-zA-Z0-9_-]/g, "-");
  return cleaned.length > 0 ? cleaned : fallback;
}

export function getIpcEndpoint(
  envName: string,
  channel: string,
  options: IpcEndpointOptions = {}
): string {
  const safeEnv = sanitizeSegment(envName || "dev", "dev");
  const safeChannel = sanitizeSegment(channel || "control", "control");
  if (process.platform === "win32") {
    return `\\\\.\\pipe\\relayquill-${safeEnv}-${safeChannel}`;
  }
  const baseDir = options.runtimeDir ?? path.join(os.tmpdir(), `relayquill-${safeEnv}`);
  return path.join(baseDir, `${safeChannel}.sock`);
}

export function resolveIpcChannelEndpoint(
  ref: IpcChannelRef,
  env: Readonly<Record<string, string | undefined>> = process.env
): string {
  let runtimeDir: string | undefined;
  if (ref.runtime_dir_env !== undefined) {
    const rawDir = env[ref.runtime_dir_env];
    if (typeof rawDir === "string" && rawDir.trim().length > 0) {
      const trimmed = rawDir.trim();
      if (trimmed.includes("\0") || trimmed.split(/[\\/]/).includes("..")) {
        throw new IpcError(
          "EIPC_INVALID_ENDPOINT",
          `Runtime directory env ${ref.runtime_dir_env} contains invalid path traversal`
        );
      }
      if (!path.isAbsolute(trimmed)) {
        throw new IpcError(
          "EIPC_INVALID_ENDPOINT",
          `Runtime directory env ${ref.runtime_dir_env} must be an absolute path`
        );
      }
      runtimeDir = trimmed;
    }
  }
  return getIpcEndpoint(ref.env_name, ref.channel, { runtimeDir });
}

export function parseSddlDacl(sddl: string): {
  readonly ownerSid: string | null;
  readonly daclProtected: boolean;
  readonly aces: readonly SddlAce[];
} {
  if (typeof sddl !== "string" || sddl.length === 0) {
    return { ownerSid: null, daclProtected: false, aces: [] };
  }
  const ownerMatch = sddl.match(/O:(.+?)(?=G:|D:|S:|$)/);
  const ownerSid = ownerMatch?.[1] ?? null;
  const daclIdx = sddl.indexOf("D:");
  if (daclIdx === -1) {
    return { ownerSid, daclProtected: false, aces: [] };
  }
  const afterD = sddl.slice(daclIdx + 2);
  const saclIdx = afterD.indexOf("S:");
  const daclSegment = saclIdx === -1 ? afterD : afterD.slice(0, saclIdx);
  const firstParen = daclSegment.indexOf("(");
  const flags = firstParen === -1 ? daclSegment : daclSegment.slice(0, firstParen);
  const daclProtected = flags.includes("P");

  const aces: SddlAce[] = [];
  const aceRegex = /\(([^)]*)\)/g;
  let match = aceRegex.exec(daclSegment);
  while (match !== null) {
    const body = match[1] ?? "";
    const parts = body.split(";");
    aces.push({
      type: parts[0] ?? "",
      flags: parts[1] ?? "",
      rights: parts[2] ?? "",
      objectGuid: parts[3] ?? "",
      inheritObjectGuid: parts[4] ?? "",
      trustee: parts[5] ?? ""
    });
    match = aceRegex.exec(daclSegment);
  }

  return { ownerSid, daclProtected, aces };
}

export function validateWindowsPipeSddl(
  sddl: string,
  currentUserSid: string,
  options: IpcSecurityOptions = {}
): WindowsPipeSddlValidation {
  const parsed = parseSddlDacl(sddl);
  const violations: string[] = [];
  const allowedTrustees = new Set<string>([currentUserSid, "SY"]);
  if (options.allowBuiltInAdmins) {
    allowedTrustees.add("BA");
  }

  if (!parsed.ownerSid) {
    violations.push("Missing owner SID in security descriptor");
  } else if (parsed.ownerSid !== currentUserSid) {
    violations.push(`Owner SID ${parsed.ownerSid} does not match current user SID ${currentUserSid}`);
  }

  if (!parsed.daclProtected) {
    violations.push("DACL is not protected (missing D:P flag)");
  }

  let hasUserAllow = false;
  let hasSystemAllow = false;

  for (const ace of parsed.aces) {
    if (ace.type !== "A") {
      violations.push(`Unexpected ACE type "${ace.type}" for trustee "${ace.trustee}"`);
      continue;
    }
    if (ace.trustee === "WD" || ace.trustee === "AN" || ace.trustee === "AU") {
      violations.push(`Forbidden broad trustee "${ace.trustee}" granted access (${ace.rights})`);
      continue;
    }
    if (!allowedTrustees.has(ace.trustee)) {
      violations.push(`Unexpected trustee "${ace.trustee}" in pipe DACL (${ace.rights})`);
      continue;
    }
    const hasFullRights = ace.rights === "FA" || ace.rights === "GA";
    if (!hasFullRights) {
      violations.push(
        `Trustee "${ace.trustee}" has unexpected rights "${ace.rights}" (expected FA or GA)`
      );
      continue;
    }
    if (ace.trustee === currentUserSid) {
      hasUserAllow = true;
    }
    if (ace.trustee === "SY") {
      hasSystemAllow = true;
    }
  }

  if (!hasUserAllow) {
    violations.push(`Missing full-access ACE for current user SID ${currentUserSid}`);
  }
  if (!hasSystemAllow) {
    violations.push("Missing full-access ACE for LocalSystem (SY)");
  }

  return {
    ok: violations.length === 0,
    ownerSid: parsed.ownerSid,
    daclProtected: parsed.daclProtected,
    aces: parsed.aces,
    violations
  };
}

const WIN32_PIPE_CS = `
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;

public static class RelayquillRuntimePipeSec {
  [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
  public static extern bool WaitNamedPipeW(string lpNamedPipeName, int nTimeOut);

  [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
  public static extern IntPtr CreateFileW(
    string lpFileName,
    uint dwDesiredAccess,
    uint dwShareMode,
    IntPtr lpSecurityAttributes,
    uint dwCreationDisposition,
    uint dwFlagsAndAttributes,
    IntPtr hTemplateFile
  );

  [DllImport("kernel32.dll", SetLastError = true)]
  public static extern bool CloseHandle(IntPtr hObject);

  [DllImport("kernel32.dll", SetLastError = true)]
  public static extern IntPtr LocalFree(IntPtr hMem);

  [DllImport("advapi32.dll", SetLastError = true)]
  public static extern uint GetSecurityInfo(
    IntPtr handle,
    int objectType,
    uint securityInfo,
    out IntPtr pSidOwner,
    out IntPtr pSidGroup,
    out IntPtr pDacl,
    out IntPtr pSacl,
    out IntPtr pSecurityDescriptor
  );

  [DllImport("advapi32.dll", SetLastError = true)]
  public static extern uint SetSecurityInfo(
    IntPtr handle,
    int objectType,
    uint securityInfo,
    IntPtr pSidOwner,
    IntPtr pSidGroup,
    IntPtr pDacl,
    IntPtr pSacl
  );

  [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
  public static extern bool ConvertSecurityDescriptorToStringSecurityDescriptorW(
    IntPtr SecurityDescriptor,
    uint RequestedStringSDRevision,
    uint SecurityInformation,
    out IntPtr StringSecurityDescriptor,
    out uint StringSecurityDescriptorLen
  );

  [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
  public static extern bool ConvertStringSecurityDescriptorToSecurityDescriptorW(
    string StringSecurityDescriptor,
    uint StringSDRevision,
    out IntPtr SecurityDescriptor,
    out uint SecurityDescriptorSize
  );

  [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
  public static extern bool GetSecurityDescriptorDacl(
    IntPtr pSecurityDescriptor,
    out bool lpbDaclPresent,
    out IntPtr pDacl,
    out bool lpbDaclDefaulted
  );

  [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
  public static extern bool ConvertSidToStringSidW(IntPtr pSid, out IntPtr strSid);

  private static IntPtr OpenPipeWithRetry(string pipePath, uint access) {
    for (int i = 0; i < 20; i++) {
      IntPtr h = CreateFileW(pipePath, access, 7, IntPtr.Zero, 3, 0, IntPtr.Zero);
      if (h != new IntPtr(-1)) {
        return h;
      }
      int err = Marshal.GetLastWin32Error();
      if (err == 231) {
        WaitNamedPipeW(pipePath, 500);
        continue;
      }
      throw new Win32Exception(err, "CreateFileW failed for pipe");
    }
    throw new Win32Exception(231, "Pipe busy after retries");
  }

  public static string Inspect(string pipePath) {
    const uint READ_CONTROL = 0x00020000;
    const int SE_KERNEL_OBJECT = 6;
    const uint OWNER_AND_DACL = 5;
    string userSid = WindowsIdentity.GetCurrent().User.Value;
    IntPtr h = OpenPipeWithRetry(pipePath, READ_CONTROL);
    IntPtr pSd = IntPtr.Zero;
    IntPtr pSddl = IntPtr.Zero;
    IntPtr pOwnerStr = IntPtr.Zero;
    try {
      IntPtr pSidOwner, pSidGroup, pDacl, pSacl;
      uint rc = GetSecurityInfo(h, SE_KERNEL_OBJECT, OWNER_AND_DACL, out pSidOwner, out pSidGroup, out pDacl, out pSacl, out pSd);
      if (rc != 0) {
        throw new Win32Exception((int)rc, "GetSecurityInfo failed");
      }
      uint len;
      if (!ConvertSecurityDescriptorToStringSecurityDescriptorW(pSd, 1, OWNER_AND_DACL, out pSddl, out len)) {
        throw new Win32Exception(Marshal.GetLastWin32Error(), "ConvertSecurityDescriptorToStringSecurityDescriptorW failed");
      }
      if (!ConvertSidToStringSidW(pSidOwner, out pOwnerStr)) {
        throw new Win32Exception(Marshal.GetLastWin32Error(), "ConvertSidToStringSidW failed");
      }
      string sddl = Marshal.PtrToStringUni(pSddl);
      string owner = Marshal.PtrToStringUni(pOwnerStr);
      return userSid + "|" + owner + "|" + sddl;
    } finally {
      if (pOwnerStr != IntPtr.Zero) LocalFree(pOwnerStr);
      if (pSddl != IntPtr.Zero) LocalFree(pSddl);
      if (pSd != IntPtr.Zero) LocalFree(pSd);
      CloseHandle(h);
    }
  }

  public static string Harden(string pipePath) {
    const uint READ_WRITE_DAC = 0x00060000;
    const int SE_KERNEL_OBJECT = 6;
    const uint DACL_PROTECTED = 0x80000004;
    string userSid = WindowsIdentity.GetCurrent().User.Value;
    string sddl = "D:P(A;;GA;;;" + userSid + ")(A;;GA;;;SY)";
    IntPtr h = OpenPipeWithRetry(pipePath, READ_WRITE_DAC);
    IntPtr pSd = IntPtr.Zero;
    try {
      uint sdSize;
      if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1, out pSd, out sdSize)) {
        throw new Win32Exception(Marshal.GetLastWin32Error(), "ConvertStringSecurityDescriptorToSecurityDescriptorW failed");
      }
      bool present, defaulted;
      IntPtr pDacl;
      if (!GetSecurityDescriptorDacl(pSd, out present, out pDacl, out defaulted) || !present) {
        throw new InvalidOperationException("Parsed SD missing DACL");
      }
      uint rc = SetSecurityInfo(h, SE_KERNEL_OBJECT, DACL_PROTECTED, IntPtr.Zero, IntPtr.Zero, pDacl, IntPtr.Zero);
      if (rc != 0) {
        throw new Win32Exception((int)rc, "SetSecurityInfo failed");
      }
      return sddl;
    } finally {
      if (pSd != IntPtr.Zero) LocalFree(pSd);
      CloseHandle(h);
    }
  }
}
`;

function assertValidWindowsPipePath(pipePath: string): void {
  if (!/^\\\\\.\\pipe\\[a-zA-Z0-9._-]+$/.test(pipePath)) {
    throw new IpcError(
      "EIPC_INVALID_ENDPOINT",
      `Invalid Windows named pipe path "${pipePath}"`
    );
  }
}

async function runWin32PipeAction(
  action: "inspect" | "harden",
  pipePath: string
): Promise<string> {
  if (process.platform !== "win32") {
    throw new IpcError(
      "EIPC_INVALID_ENDPOINT",
      `Win32 pipe action "${action}" is only supported on win32`
    );
  }
  assertValidWindowsPipePath(pipePath);

  const script = [
    "$ErrorActionPreference = 'Stop'",
    "Add-Type -TypeDefinition @'",
    WIN32_PIPE_CS.trim(),
    "'@",
    "$pipePath = $env:RELAYQUILL_IPC_PIPE",
    "if ($env:RELAYQUILL_IPC_ACTION -eq 'harden') {",
    "  Write-Output ([RelayquillRuntimePipeSec]::Harden($pipePath))",
    "} else {",
    "  Write-Output ([RelayquillRuntimePipeSec]::Inspect($pipePath))",
    "}"
  ].join("\n");
  const encoded = Buffer.from(script, "utf16le").toString("base64");

  return new Promise((resolve, reject) => {
    const child = spawn(
      "powershell.exe",
      ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand", encoded],
      {
        env: {
          ...process.env,
          RELAYQUILL_IPC_PIPE: pipePath,
          RELAYQUILL_IPC_ACTION: action
        },
        stdio: ["ignore", "pipe", "pipe"]
      }
    );

    const stdoutChunks: Buffer[] = [];
    const stderrChunks: Buffer[] = [];
    child.stdout.on("data", (chunk: Buffer) => stdoutChunks.push(chunk));
    child.stderr.on("data", (chunk: Buffer) => stderrChunks.push(chunk));
    child.once("error", (err) => {
      reject(
        new IpcError(
          "EIPC_SECURITY_VIOLATION",
          `Failed to spawn PowerShell Win32 pipe ${action}: ${err.message}`,
          { cause: err }
        )
      );
    });
    child.once("close", (code) => {
      const stdout = Buffer.concat(stdoutChunks).toString("utf8").trim();
      const stderr = Buffer.concat(stderrChunks).toString("utf8").trim();
      if (code !== 0) {
        reject(
          new IpcError(
            "EIPC_SECURITY_VIOLATION",
            `PowerShell Win32 pipe ${action} failed (exit ${String(code)}): ${stderr || stdout}`
          )
        );
        return;
      }
      resolve(stdout);
    });
  });
}

export async function inspectWindowsPipeSecurity(
  pipePath: string,
  options: IpcSecurityOptions = {}
): Promise<WindowsPipeSecurityReport> {
  const raw = await runWin32PipeAction("inspect", pipePath);
  const parts = raw.split("|");
  const currentUserSid = parts[0] ?? "";
  const sddl = parts.slice(2).join("|");
  const validation = validateWindowsPipeSddl(sddl, currentUserSid, options);
  return {
    platform: "win32",
    endpoint: pipePath,
    currentUserSid,
    sddl,
    ...validation
  };
}

export function hardenWindowsPipe(pipePath: string): Promise<string> {
  return runWin32PipeAction("harden", pipePath);
}

export function inspectPosixSocketSecurity(socketPath: string): PosixSocketSecurityReport {
  const violations: string[] = [];
  const dirPath = path.dirname(socketPath);
  const dirStat = fs.lstatSync(dirPath);
  const sockStat = fs.lstatSync(socketPath);

  const dirMode = dirStat.mode & 0o777;
  const sockMode = sockStat.mode & 0o777;
  const expectedUid = typeof process.getuid === "function" ? process.getuid() : null;

  if (dirStat.isSymbolicLink() || !dirStat.isDirectory()) {
    violations.push(`Runtime directory ${dirPath} must be a real directory, not a symlink`);
  }
  if (sockStat.isSymbolicLink() || !sockStat.isSocket()) {
    violations.push(`Path ${socketPath} is not a Unix domain socket`);
  }
  if (dirMode !== 0o700) {
    violations.push(`Runtime directory mode is ${dirMode.toString(8)}, expected 700`);
  }
  if (sockMode !== 0o600) {
    violations.push(`Socket mode is ${sockMode.toString(8)}, expected 600`);
  }
  if (expectedUid !== null && dirStat.uid !== expectedUid) {
    violations.push(`Directory UID ${dirStat.uid} does not match current UID ${expectedUid}`);
  }
  if (expectedUid !== null && sockStat.uid !== expectedUid) {
    violations.push(`Socket UID ${sockStat.uid} does not match current UID ${expectedUid}`);
  }

  return {
    platform: process.platform,
    endpoint: socketPath,
    dirMode: dirMode.toString(8),
    sockMode: sockMode.toString(8),
    ok: violations.length === 0,
    violations
  };
}

export async function inspectIpcEndpoint(
  endpoint: string,
  options: IpcSecurityOptions = {}
): Promise<IpcSecurityReport> {
  if (process.platform === "win32") {
    return await inspectWindowsPipeSecurity(endpoint, options);
  }
  return inspectPosixSocketSecurity(endpoint);
}

export async function verifyIpcEndpoint(
  endpoint: string,
  options: IpcSecurityOptions = {}
): Promise<IpcSecurityReport> {
  const report = await inspectIpcEndpoint(endpoint, options);
  if (!report.ok) {
    throw new IpcError(
      "EIPC_SECURITY_VIOLATION",
      `IPC endpoint ${endpoint} failed security verification: ${report.violations.join("; ")}`
    );
  }
  return report;
}

function preparePosixSocketPath(socketPath: string): void {
  const dirPath = path.dirname(socketPath);
  if (!fs.existsSync(dirPath)) {
    fs.mkdirSync(dirPath, { recursive: true, mode: 0o700 });
  }
  const dirStat = fs.lstatSync(dirPath);
  if (dirStat.isSymbolicLink() || !dirStat.isDirectory()) {
    throw new IpcError(
      "EIPC_SECURITY_VIOLATION",
      `Runtime directory ${dirPath} must be a real directory, not a symlink`
    );
  }
  const expectedUid = typeof process.getuid === "function" ? process.getuid() : null;
  if (expectedUid !== null && dirStat.uid !== expectedUid) {
    throw new IpcError(
      "EIPC_SECURITY_VIOLATION",
      `Runtime directory ${dirPath} UID ${dirStat.uid} does not match current UID ${expectedUid}`
    );
  }
  if ((dirStat.mode & 0o777) !== 0o700) {
    fs.chmodSync(dirPath, 0o700);
  }

  if (fs.existsSync(socketPath)) {
    const existing = fs.lstatSync(socketPath);
    if (existing.isSymbolicLink() || !existing.isSocket()) {
      throw new IpcError(
        "EIPC_SECURITY_VIOLATION",
        `Refusing to replace non-socket path at ${socketPath}`
      );
    }
    if (expectedUid !== null && existing.uid !== expectedUid) {
      throw new IpcError(
        "EIPC_SECURITY_VIOLATION",
        `Refusing to unlink socket ${socketPath} owned by UID ${existing.uid}`
      );
    }
    fs.unlinkSync(socketPath);
  }
}

export function createIpcServer(
  endpoint: string,
  handler: IpcRequestHandler,
  options: IpcServerOptions = {}
): IpcServerHandle {
  const maxFrameBytes = options.maxFrameBytes ?? MAX_IPC_FRAME_BYTES;
  const allowEmptyProbeDisconnect = options.allowEmptyProbeDisconnect ?? true;
  const sockets = new Set<net.Socket>();
  let listening = false;

  const server = net.createServer((socket) => {
    sockets.add(socket);
    socket.once("close", () => {
      sockets.delete(socket);
    });

    let buffer = Buffer.alloc(0);
    let handled = false;

    const failSocket = (code: string, message: string): void => {
      if (handled || socket.destroyed) {
        return;
      }
      handled = true;
      const errFrame = `${JSON.stringify({ ok: false, errorCode: code, message })}\n`;
      socket.end(errFrame);
    };

    socket.on("data", (chunk: Buffer) => {
      if (handled) {
        return;
      }
      buffer = Buffer.concat([buffer, chunk]);
      if (buffer.byteLength > maxFrameBytes) {
        failSocket("EIPC_FRAME_TOO_LARGE", `IPC request exceeds max ${maxFrameBytes} bytes`);
        return;
      }
      const newlineIdx = buffer.indexOf(0x0a);
      if (newlineIdx === -1) {
        return;
      }
      const rawLine = buffer.subarray(0, newlineIdx).toString("utf8");
      handled = true;

      void (async () => {
        try {
          const parsed: unknown = JSON.parse(rawLine);
          const reply = await handler(parsed);
          const serialized = JSON.stringify(reply);
          const replyBuf = Buffer.from(`${serialized}\n`, "utf8");
          if (replyBuf.byteLength > maxFrameBytes) {
            socket.end(
              `${JSON.stringify({
                ok: false,
                errorCode: "EIPC_FRAME_TOO_LARGE",
                message: `IPC response exceeds max ${maxFrameBytes} bytes`
              })}\n`
            );
            return;
          }
          if (!socket.destroyed) {
            socket.end(replyBuf);
          }
        } catch (err: unknown) {
          if (!socket.destroyed) {
            const message = err instanceof Error ? err.message : String(err);
            socket.end(
              `${JSON.stringify({
                ok: false,
                errorCode: "EIPC_PROTOCOL",
                message
              })}\n`
            );
          }
        }
      })();
    });

    socket.once("end", () => {
      if (!handled && buffer.byteLength === 0 && allowEmptyProbeDisconnect) {
        handled = true;
        socket.end();
      }
    });

    socket.once("error", () => {
      socket.destroy();
    });
  });

  return {
    endpoint,

    async listen(): Promise<IpcSecurityReport> {
      if (process.platform === "win32") {
        assertValidWindowsPipePath(endpoint);
      } else {
        preparePosixSocketPath(endpoint);
      }

      await new Promise<void>((resolve, reject) => {
        const onError = (err: Error): void => {
          reject(err);
        };
        server.once("error", onError);
        server.listen(endpoint, () => {
          server.removeListener("error", onError);
          listening = true;
          resolve();
        });
      });

      try {
        if (process.platform === "win32") {
          await hardenWindowsPipe(endpoint);
        } else {
          fs.chmodSync(endpoint, 0o600);
        }
        return await verifyIpcEndpoint(endpoint, options);
      } catch (err) {
        await this.close();
        throw err;
      }
    },

    verifySecurity(): Promise<IpcSecurityReport> {
      return verifyIpcEndpoint(endpoint, options);
    },

    async close(): Promise<void> {
      for (const s of sockets) {
        s.destroy();
      }
      sockets.clear();
      if (listening) {
        listening = false;
        await new Promise<void>((resolve) => {
          server.close(() => resolve());
        });
      }
      if (process.platform !== "win32" && fs.existsSync(endpoint)) {
        try {
          const stat = fs.lstatSync(endpoint);
          if (stat.isSocket() && !stat.isSymbolicLink()) {
            fs.unlinkSync(endpoint);
          }
        } catch {
          // Ignore cleanup race on shutdown
        }
      }
    }
  };
}

export async function sendIpcFrame<TResponse = unknown>(
  endpoint: string,
  frame: string | object,
  options: SendIpcFrameOptions = {}
): Promise<TResponse> {
  const maxBytes = options.maxFrameBytes ?? MAX_IPC_FRAME_BYTES;
  const timeoutMs = options.timeoutMs ?? DEFAULT_IPC_TIMEOUT_MS;
  const verifySecurity = options.verifySecurity !== false;

  if (typeof frame === "string" && /[\r\n]/.test(frame)) {
    throw new IpcError(
      "EIPC_INVALID_FRAME",
      "Raw IPC string frame must not contain CR or LF characters"
    );
  }
  const serialized = typeof frame === "string" ? frame : JSON.stringify(frame);
  const frameBuf = Buffer.from(`${serialized}\n`, "utf8");
  if (frameBuf.byteLength > maxBytes) {
    throw new IpcError(
      "EIPC_FRAME_TOO_LARGE",
      `IPC frame size ${frameBuf.byteLength} exceeds max ${maxBytes} bytes`
    );
  }

  if (verifySecurity) {
    await verifyIpcEndpoint(endpoint, options);
  }

  return new Promise<TResponse>((resolve, reject) => {
    const socket = net.connect(endpoint);
    let settled = false;
    const chunks: Buffer[] = [];

    const timer = setTimeout(() => {
      if (!settled) {
        settled = true;
        socket.destroy();
        reject(new IpcError("EIPC_TIMEOUT", `IPC request timed out after ${timeoutMs}ms`));
      }
    }, timeoutMs);

    const finish = (err: Error | null, value?: TResponse): void => {
      if (settled) {
        return;
      }
      settled = true;
      clearTimeout(timer);
      socket.destroy();
      if (err !== null) {
        reject(err);
      } else {
        resolve(value as TResponse);
      }
    };

    socket.once("error", (err) => finish(err));
    socket.once("connect", () => {
      socket.write(frameBuf);
    });
    socket.on("data", (chunk: Buffer) => {
      chunks.push(chunk);
      const total = Buffer.concat(chunks);
      if (total.byteLength > maxBytes) {
        finish(
          new IpcError("EIPC_FRAME_TOO_LARGE", `IPC response exceeded max ${maxBytes} bytes`)
        );
        return;
      }
      const newlineIdx = total.indexOf(0x0a);
      if (newlineIdx !== -1) {
        const line = total.subarray(0, newlineIdx).toString("utf8");
        try {
          finish(null, JSON.parse(line) as TResponse);
        } catch (err) {
          finish(
            new IpcError(
              "EIPC_PROTOCOL",
              `Invalid JSON IPC response: ${err instanceof Error ? err.message : String(err)}`,
              { cause: err }
            )
          );
        }
      }
    });
    socket.once("end", () => {
      if (!settled) {
        const text = Buffer.concat(chunks).toString("utf8").trim();
        if (text.length === 0) {
          finish(
            new IpcError("EIPC_PROTOCOL", "IPC socket closed before sending a response frame")
          );
          return;
        }
        try {
          finish(null, JSON.parse(text) as TResponse);
        } catch (err) {
          finish(
            new IpcError(
              "EIPC_PROTOCOL",
              `Invalid JSON IPC response: ${err instanceof Error ? err.message : String(err)}`,
              { cause: err }
            )
          );
        }
      }
    });
  });
}
