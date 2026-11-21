import {
  createIpcServer,
  resolveIpcChannelEndpoint,
  type IpcChannelRef,
  type IpcServerHandle
} from "@relayquill/runtime";
import { type ReceiverStateSnapshot } from "./db.js";

export interface ReceiverFaultSnapshot {
  readonly commitDropRemaining: number;
  readonly commitDelayMs: number;
  readonly commitDelayRemaining: number;
  readonly oversizedReceiptRemaining: number;
  readonly invalidReceiptMacRemaining: number;
}

export class ReceiverFaultController {
  #commitDropRemaining = 0;
  #commitDelayMs = 0;
  #commitDelayRemaining = 0;
  #oversizedReceiptRemaining = 0;
  #invalidReceiptMacRemaining = 0;

  getState(): ReceiverFaultSnapshot {
    return Object.freeze({
      commitDropRemaining: this.#commitDropRemaining,
      commitDelayMs: this.#commitDelayMs,
      commitDelayRemaining: this.#commitDelayRemaining,
      oversizedReceiptRemaining: this.#oversizedReceiptRemaining,
      invalidReceiptMacRemaining: this.#invalidReceiptMacRemaining
    });
  }

  armCommitDropResponse(count = 1): void {
    this.#commitDropRemaining = Math.max(0, Math.trunc(count));
  }

  armCommitDelayResponse(delayMs: number, count = 1): void {
    this.#commitDelayMs = Math.max(0, Math.trunc(delayMs));
    this.#commitDelayRemaining = Math.max(0, Math.trunc(count));
  }

  armOversizedReceiptResponse(count = 1): void {
    this.#oversizedReceiptRemaining = Math.max(0, Math.trunc(count));
  }

  armInvalidReceiptMac(count = 1): void {
    this.#invalidReceiptMacRemaining = Math.max(0, Math.trunc(count));
  }

  resetFaults(): void {
    this.#commitDropRemaining = 0;
    this.#commitDelayMs = 0;
    this.#commitDelayRemaining = 0;
    this.#oversizedReceiptRemaining = 0;
    this.#invalidReceiptMacRemaining = 0;
  }

  consumeCommitDelayMs(): number {
    if (this.#commitDelayRemaining <= 0 || this.#commitDelayMs <= 0) {
      return 0;
    }
    this.#commitDelayRemaining -= 1;
    const ms = this.#commitDelayMs;
    if (this.#commitDelayRemaining === 0) {
      this.#commitDelayMs = 0;
    }
    return ms;
  }

  consumeCommitDrop(): boolean {
    if (this.#commitDropRemaining <= 0) {
      return false;
    }
    this.#commitDropRemaining -= 1;
    return true;
  }

  consumeOversizedReceipt(): boolean {
    if (this.#oversizedReceiptRemaining <= 0) {
      return false;
    }
    this.#oversizedReceiptRemaining -= 1;
    return true;
  }

  consumeInvalidReceiptMac(): boolean {
    if (this.#invalidReceiptMacRemaining <= 0) {
      return false;
    }
    this.#invalidReceiptMacRemaining -= 1;
    return true;
  }
}

function readOptionalPositiveInt(rec: Record<string, unknown>, key: string, fallback: number): number {
  const raw = rec[key];
  if (raw === undefined || raw === null) {
    return fallback;
  }
  const num = typeof raw === "number" ? raw : Number(raw);
  if (!Number.isFinite(num) || num < 0) {
    throw new Error(`Invalid numeric parameter "${key}": ${typeof raw === "string" || typeof raw === "number" ? String(raw) : JSON.stringify(raw)}`);
  }
  return Math.trunc(num);
}

export async function startReceiverControlIpcServer(options: {
  readonly endpoint?: string | undefined;
  readonly channelRef?: IpcChannelRef | undefined;
  readonly runtimeDir?: string | undefined;
  readonly faults: ReceiverFaultController;
  readonly inspectState: () => Promise<ReceiverStateSnapshot>;
}): Promise<IpcServerHandle> {
  const endpoint =
    options.endpoint ??
    (options.channelRef !== undefined
      ? resolveIpcChannelEndpoint(
          options.channelRef,
          options.runtimeDir !== undefined ? { runtimeDir: options.runtimeDir } : {}
        )
      : undefined);

  if (endpoint === undefined) {
    throw new Error("Either endpoint or channelRef must be provided to startReceiverControlIpcServer");
  }

  const handle = createIpcServer(endpoint, async (rawRequest) => {
    if (typeof rawRequest !== "object" || rawRequest === null || Array.isArray(rawRequest)) {
      return { ok: false, errorCode: "INVALID_REQUEST", message: "IPC request must be a JSON object" };
    }
    const rec = rawRequest as Record<string, unknown>;
    const rawOp = rec["op"] ?? rec["command"] ?? rec["action"];
    if (typeof rawOp !== "string" || rawOp.length === 0) {
      return { ok: false, errorCode: "INVALID_REQUEST", message: "Missing op/command field" };
    }

    switch (rawOp) {
      case "commit_drop_response": {
        const count = readOptionalPositiveInt(rec, "count", 1);
        options.faults.armCommitDropResponse(count);
        return { ok: true, op: rawOp, faults: options.faults.getState() };
      }
      case "commit_delay_response": {
        const delayMs = readOptionalPositiveInt(
          rec,
          rec["delay_ms"] !== undefined ? "delay_ms" : "delayMs",
          250
        );
        const count = readOptionalPositiveInt(rec, "count", 1);
        options.faults.armCommitDelayResponse(delayMs, count);
        return { ok: true, op: rawOp, faults: options.faults.getState() };
      }
      case "oversized_receipt_response": {
        const count = readOptionalPositiveInt(rec, "count", 1);
        options.faults.armOversizedReceiptResponse(count);
        return { ok: true, op: rawOp, faults: options.faults.getState() };
      }
      case "invalid_receipt_mac": {
        const count = readOptionalPositiveInt(rec, "count", 1);
        options.faults.armInvalidReceiptMac(count);
        return { ok: true, op: rawOp, faults: options.faults.getState() };
      }
      case "reset_faults": {
        options.faults.resetFaults();
        return { ok: true, op: rawOp, faults: options.faults.getState() };
      }
      case "inspect_state": {
        const state = await options.inspectState();
        return { ok: true, op: rawOp, state, faults: options.faults.getState() };
      }
      default:
        return { ok: false, errorCode: "UNKNOWN_COMMAND", message: `Unknown fault/control command: ${rawOp}` };
    }
  });

  await handle.listen();
  return handle;
}
