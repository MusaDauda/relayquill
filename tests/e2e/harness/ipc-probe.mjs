import { spawn } from 'node:child_process';
import fs from 'node:fs';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';

export const MAX_IPC_FRAME_BYTES = 64 * 1024;

export function getIpcEndpoint(envName, channel, options = {}) {
  const safeEnv = String(envName || 'dev').replace(/[^a-zA-Z0-9_-]/g, '-');
  const safeChannel = String(channel || 'control').replace(/[^a-zA-Z0-9_-]/g, '-');
  if (process.platform === 'win32') {
    return `\\\\.\\pipe\\relayquill-${safeEnv}-${safeChannel}`;
  }
  const baseDir = options.runtimeDir ?? path.join(os.tmpdir(), `relayquill-${safeEnv}`);
  return path.join(baseDir, `${safeChannel}.sock`);
}

export function parseSddlDacl(sddl) {
  if (typeof sddl !== 'string' || !sddl) {
    return { ownerSid: null, daclProtected: false, aces: [] };
  }
  const ownerMatch = sddl.match(/O:(.+?)(?=G:|D:|S:|$)/);
  const ownerSid = ownerMatch ? ownerMatch[1] : null;
  const daclIdx = sddl.indexOf('D:');
  if (daclIdx === -1) {
    return { ownerSid, daclProtected: false, aces: [] };
  }
  const afterD = sddl.slice(daclIdx + 2);
  const saclIdx = afterD.indexOf('S:');
  const daclSegment = saclIdx === -1 ? afterD : afterD.slice(0, saclIdx);
  const firstParen = daclSegment.indexOf('(');
  const flags = firstParen === -1 ? daclSegment : daclSegment.slice(0, firstParen);
  const daclProtected = flags.includes('P');

  const aces = [];
  const aceRegex = /\(([^)]*)\)/g;
  let match = aceRegex.exec(daclSegment);
  while (match !== null) {
    const parts = match[1].split(';');
    aces.push({
      type: parts[0] ?? '',
      flags: parts[1] ?? '',
      rights: parts[2] ?? '',
      objectGuid: parts[3] ?? '',
      inheritObjectGuid: parts[4] ?? '',
      trustee: parts[5] ?? ''
    });
    match = aceRegex.exec(daclSegment);
  }

  return { ownerSid, daclProtected, aces };
}

export function validateWindowsPipeSddl(sddl, currentUserSid, options = {}) {
  const parsed = parseSddlDacl(sddl);
  const violations = [];
  const allowedTrustees = new Set([currentUserSid, 'SY']);
  if (options.allowBuiltInAdmins) {
    allowedTrustees.add('BA');
  }

  if (!parsed.ownerSid) {
    violations.push('Missing owner SID in security descriptor');
  } else if (parsed.ownerSid !== currentUserSid) {
    violations.push(`Owner SID ${parsed.ownerSid} does not match current user SID ${currentUserSid}`);
  }

  if (!parsed.daclProtected) {
    violations.push('DACL is not protected (missing D:P flag)');
  }

  let hasUserAllow = false;
  let hasSystemAllow = false;

  for (const ace of parsed.aces) {
    if (ace.type !== 'A') {
      violations.push(`Unexpected ACE type "${ace.type}" for trustee "${ace.trustee}"`);
      continue;
    }
    if (ace.trustee === 'WD' || ace.trustee === 'AN' || ace.trustee === 'AU') {
      violations.push(`Forbidden broad trustee "${ace.trustee}" granted access (${ace.rights})`);
      continue;
    }
    if (!allowedTrustees.has(ace.trustee)) {
      violations.push(`Unexpected trustee "${ace.trustee}" in pipe DACL (${ace.rights})`);
      continue;
    }
    const hasFullRights = ace.rights === 'FA' || ace.rights === 'GA';
    if (!hasFullRights) {
      violations.push(`Trustee "${ace.trustee}" has unexpected rights "${ace.rights}" (expected FA or GA)`);
      continue;
    }
    if (ace.trustee === currentUserSid) {
      hasUserAllow = true;
    }
    if (ace.trustee === 'SY') {
      hasSystemAllow = true;
    }
  }

  if (!hasUserAllow) {
    violations.push(`Missing full-access ACE for current user SID ${currentUserSid}`);
  }
  if (!hasSystemAllow) {
    violations.push('Missing full-access ACE for LocalSystem (SY)');
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

public static class RelayquillPipeSec {
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
    for (int i = 0; i < 10; i++) {
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

async function runWin32PipeAction(action, pipePath) {
  if (process.platform !== 'win32') {
    throw new Error(`Win32 pipe action "${action}" is only supported on win32`);
  }
  const script = [
    "$ErrorActionPreference = 'Stop'",
    "Add-Type -TypeDefinition @'",
    WIN32_PIPE_CS.trim(),
    "'@",
    '$pipePath = $env:RELAYQUILL_PROBE_PIPE',
    "if ($env:RELAYQUILL_PROBE_ACTION -eq 'harden') {",
    '  Write-Output ([RelayquillPipeSec]::Harden($pipePath))',
    '} else {',
    '  Write-Output ([RelayquillPipeSec]::Inspect($pipePath))',
    '}'
  ].join('\n');
  const encoded = Buffer.from(script, 'utf16le').toString('base64');

  return new Promise((resolve, reject) => {
    const child = spawn(
      'powershell.exe',
      ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-EncodedCommand', encoded],
      {
        env: {
          ...process.env,
          RELAYQUILL_PROBE_PIPE: pipePath,
          RELAYQUILL_PROBE_ACTION: action
        },
        stdio: ['ignore', 'pipe', 'pipe']
      }
    );

    const stdoutChunks = [];
    const stderrChunks = [];
    child.stdout.on('data', (chunk) => stdoutChunks.push(chunk));
    child.stderr.on('data', (chunk) => stderrChunks.push(chunk));
    child.once('error', (err) => {
      reject(new Error(`Failed to spawn PowerShell Win32 pipe ${action}: ${err.message}`, { cause: err }));
    });
    child.once('close', (code) => {
      const stdout = Buffer.concat(stdoutChunks).toString('utf8').trim();
      const stderr = Buffer.concat(stderrChunks).toString('utf8').trim();
      if (code !== 0) {
        reject(new Error(`PowerShell Win32 pipe ${action} failed (exit ${code}): ${stderr || stdout}`));
        return;
      }
      resolve(stdout);
    });
  });
}

export async function inspectWindowsPipeSecurity(pipePath, options = {}) {
  const raw = await runWin32PipeAction('inspect', pipePath);
  const [currentUserSid, ownerSid, ...sddlRest] = raw.split('|');
  const sddl = sddlRest.join('|');
  const validation = validateWindowsPipeSddl(sddl, currentUserSid, options);
  return {
    platform: 'win32',
    endpoint: pipePath,
    currentUserSid,
    ownerSid,
    sddl,
    ...validation
  };
}

export async function hardenWindowsPipeForTest(pipePath) {
  return runWin32PipeAction('harden', pipePath);
}

export function inspectPosixSocketSecurity(socketPath) {
  const violations = [];
  const dirPath = path.dirname(socketPath);
  const dirStat = fs.statSync(dirPath);
  const sockStat = fs.lstatSync(socketPath);

  const dirMode = dirStat.mode & 0o777;
  const sockMode = sockStat.mode & 0o777;
  const expectedUid = typeof process.getuid === 'function' ? process.getuid() : null;

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

export async function probeIpcEndpoint(endpoint, options = {}) {
  if (process.platform === 'win32') {
    return inspectWindowsPipeSecurity(endpoint, options);
  }
  return inspectPosixSocketSecurity(endpoint, options);
}

export async function sendIpcFrame(endpoint, frame, options = {}) {
  const maxBytes = options.maxFrameBytes ?? MAX_IPC_FRAME_BYTES;
  const timeoutMs = options.timeoutMs ?? 5_000;

  if (typeof frame === 'string' && /[\r\n]/.test(frame)) {
    const err = new Error('Raw IPC string frame must not contain CR or LF characters');
    err.code = 'EIPC_INVALID_FRAME';
    throw err;
  }
  const serialized = typeof frame === 'string' ? frame : JSON.stringify(frame);
  const frameBuf = Buffer.from(`${serialized}\n`, 'utf8');
  if (frameBuf.byteLength > maxBytes) {
    const err = new Error(`IPC frame size ${frameBuf.byteLength} exceeds max ${maxBytes} bytes`);
    err.code = 'EIPC_FRAME_TOO_LARGE';
    throw err;
  }

  return new Promise((resolve, reject) => {
    const socket = net.connect(endpoint);
    let settled = false;
    const chunks = [];

    const timer = setTimeout(() => {
      if (!settled) {
        settled = true;
        socket.destroy();
        reject(new Error(`IPC request timed out after ${timeoutMs}ms`));
      }
    }, timeoutMs);

    const finish = (err, value) => {
      if (settled) {
        return;
      }
      settled = true;
      clearTimeout(timer);
      socket.destroy();
      if (err) {
        reject(err);
      } else {
        resolve(value);
      }
    };

    socket.once('error', (err) => finish(err));
    socket.once('connect', () => {
      socket.write(frameBuf);
    });
    socket.on('data', (chunk) => {
      chunks.push(chunk);
      const total = Buffer.concat(chunks);
      if (total.byteLength > maxBytes) {
        finish(new Error(`IPC response exceeded max ${maxBytes} bytes`));
        return;
      }
      const newlineIdx = total.indexOf(0x0a);
      if (newlineIdx !== -1) {
        const line = total.subarray(0, newlineIdx).toString('utf8');
        try {
          finish(null, JSON.parse(line));
        } catch (err) {
          finish(new Error(`Invalid JSON IPC response: ${err instanceof Error ? err.message : String(err)}`, { cause: err }));
        }
      }
    });
    socket.once('end', () => {
      if (!settled) {
        const text = Buffer.concat(chunks).toString('utf8').trim();
        if (!text) {
          finish(new Error('IPC socket closed before sending a response frame'));
          return;
        }
        try {
          finish(null, JSON.parse(text));
        } catch (err) {
          finish(new Error(`Invalid JSON IPC response: ${err instanceof Error ? err.message : String(err)}`, { cause: err }));
        }
      }
    });
  });
}
