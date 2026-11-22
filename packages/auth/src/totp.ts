import crypto from "node:crypto";
import { ValidationDomainError } from "@relayquill/domain";

const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567" as const;

export const TOTP_REPLAY_WINDOW_TTL_SECONDS = 120 as const;

export interface TotpReplayGuardStore {
  acquireStepLock(userId: string, step: string, ttlSeconds: number): Promise<boolean>;
}

/**
 * Process-local replay-window guard for TOTP step locks when Redis is not wired.
 */
export class InMemoryTotpReplayGuardStore implements TotpReplayGuardStore {
  readonly #locks = new Map<string, number>();
  readonly #nowMs: () => number;

  constructor(nowMs: () => number = () => Date.now()) {
    this.#nowMs = nowMs;
  }

  acquireStepLock(userId: string, step: string, ttlSeconds: number): Promise<boolean> {
    const now = this.#nowMs();
    for (const [k, exp] of this.#locks.entries()) {
      if (exp <= now) {
        this.#locks.delete(k);
      }
    }
    const key = `${userId}:${step}`;
    const existing = this.#locks.get(key);
    if (existing !== undefined && existing > now) {
      return Promise.resolve(false);
    }
    this.#locks.set(key, now + Math.max(1, ttlSeconds) * 1000);
    return Promise.resolve(true);
  }
}

/**
 * Encodes arbitrary bytes into uppercase unpadded RFC 4648 Base32.
 */
export function encodeBase32(bytes: Uint8Array): string {
  let bits = 0;
  let value = 0;
  let output = "";
  for (const byte of bytes) {
    value = (value << 8) | (byte & 0xff);
    bits += 8;
    while (bits >= 5) {
      const idx = (value >>> (bits - 5)) & 0x1f;
      output += BASE32_ALPHABET.charAt(idx);
      bits -= 5;
    }
  }
  if (bits > 0) {
    const idx = (value << (5 - bits)) & 0x1f;
    output += BASE32_ALPHABET.charAt(idx);
  }
  return output;
}

/**
 * Decodes an RFC 4648 Base32 string (case-insensitive, optional `=` padding) to raw bytes.
 */
export function decodeBase32(encoded: string): Uint8Array {
  const cleaned = encoded.trim().toUpperCase().replace(/=+$/g, "").replace(/[\s-]+/g, "");
  if (cleaned.length === 0) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: "Base32 secret must not be empty"
    });
  }
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (let i = 0; i < cleaned.length; i += 1) {
    const ch = cleaned.charAt(i);
    const idx = BASE32_ALPHABET.indexOf(ch);
    if (idx === -1) {
      throw new ValidationDomainError({
        code: "INVALID_VALUE",
        message: "Invalid Base32 character in TOTP secret"
      });
    }
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Uint8Array.from(out);
}

/**
 * Generates a fresh random TOTP seed (default 20 bytes / 160 bits) and its Base32 form.
 */
export function generateTotpSecret(byteLength = 20): {
  readonly secretBytes: Uint8Array;
  readonly base32Secret: string;
} {
  if (!Number.isInteger(byteLength) || byteLength < 16 || byteLength > 64) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: "TOTP seed length must be between 16 and 64 bytes"
    });
  }
  const secretBytes = new Uint8Array(crypto.randomBytes(byteLength));
  return {
    secretBytes,
    base32Secret: encodeBase32(secretBytes)
  };
}

/**
 * Formats an `otpauth://totp/...` URI compatible with standard authenticator apps.
 */
export function buildTotpOtpauthUri(params: {
  readonly issuer: string;
  readonly accountEmail: string;
  readonly base32Secret: string;
}): string {
  const issuer = params.issuer.trim() || "Relayquill";
  const account = params.accountEmail.trim();
  if (account.length === 0) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: "TOTP accountEmail must not be empty"
    });
  }
  const label = `${encodeURIComponent(issuer)}:${encodeURIComponent(account)}`;
  const qs = new URLSearchParams({
    secret: params.base32Secret,
    issuer,
    algorithm: "SHA1",
    digits: "6",
    period: "30"
  });
  return `otpauth://totp/${label}?${qs.toString()}`;
}

/**
 * Computes an RFC 4226 6-digit HOTP value for a secret seed and counter.
 */
export function computeHotp6Digits(secretBytes: Uint8Array, counter: bigint): string {
  if (secretBytes.byteLength < 10) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: "HOTP secret seed must be at least 10 bytes"
    });
  }
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64BE(counter, 0);
  const hmac = crypto.createHmac("sha1", Buffer.from(secretBytes)).update(buf).digest();
  const lastByte = hmac[hmac.byteLength - 1] ?? 0;
  const offset = lastByte & 0x0f;
  const b0 = hmac[offset] ?? 0;
  const b1 = hmac[offset + 1] ?? 0;
  const b2 = hmac[offset + 2] ?? 0;
  const b3 = hmac[offset + 3] ?? 0;
  const binary = ((b0 & 0x7f) << 24) | ((b1 & 0xff) << 16) | ((b2 & 0xff) << 8) | (b3 & 0xff);
  return String(binary % 1_000_000).padStart(6, "0");
}

/**
 * Computes the current RFC 6238 6-digit TOTP value for a Unix timestamp in seconds.
 */
export function computeTotp6Digits(
  secretBytes: Uint8Array,
  nowUnixSec: number,
  stepSeconds = 30
): string {
  const step = BigInt(Math.floor(nowUnixSec / stepSeconds));
  return computeHotp6Digits(secretBytes, step);
}

export interface VerifyTotpResult {
  readonly valid: boolean;
  readonly matchedStep?: string;
}

/**
 * Verifies a 6-digit RFC 6238 TOTP code across `[-1, 0, +1]` steps and rejects same-step replay.
 */
export async function verifyTotpWithReplayGuard(params: {
  readonly store: TotpReplayGuardStore;
  readonly userId: string;
  readonly secretBytes: Uint8Array;
  readonly submittedCode: string;
  readonly nowUnixSec: number;
  readonly stepSeconds?: number | undefined;
}): Promise<VerifyTotpResult> {
  if (!/^\d{6}$/.test(params.submittedCode)) {
    return { valid: false };
  }
  const stepSeconds = params.stepSeconds ?? 30;
  const currentStep = BigInt(Math.floor(params.nowUnixSec / stepSeconds));
  const submittedBuf = Buffer.from(params.submittedCode, "utf8");

  for (const offset of [0n, -1n, 1n] as const) {
    const step = currentStep + offset;
    if (step < 0n) {
      continue;
    }
    const expected = computeHotp6Digits(params.secretBytes, step);
    const expectedBuf = Buffer.from(expected, "utf8");
    if (crypto.timingSafeEqual(submittedBuf, expectedBuf)) {
      const acquired = await params.store.acquireStepLock(
        params.userId,
        step.toString(10),
        TOTP_REPLAY_WINDOW_TTL_SECONDS
      );
      if (!acquired) {
        return { valid: false };
      }
      return { valid: true, matchedStep: step.toString(10) };
    }
  }
  return { valid: false };
}

function assert32ByteKey(dataKey32: Uint8Array): Buffer {
  if (dataKey32.byteLength !== 32) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: "TOTP envelope encryption key must be exactly 32 bytes"
    });
  }
  return Buffer.from(dataKey32);
}

/**
 * Seals a TOTP seed using AES-256-GCM bound to the owning user ID (`iv || tag || ciphertext`).
 */
export function sealTotpSecret(
  dataKey32: Uint8Array,
  secretBytes: Uint8Array,
  userId: string
): Buffer {
  const key = assert32ByteKey(dataKey32);
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  cipher.setAAD(Buffer.from(`rq.totp.v1:${userId}`, "utf8"));
  const ciphertext = Buffer.concat([cipher.update(secretBytes), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, ciphertext]);
}

/**
 * Decrypts and authenticates an AES-256-GCM sealed TOTP seed bound to `userId`.
 */
export function openTotpSecret(
  dataKey32: Uint8Array,
  sealed: Uint8Array,
  userId: string
): Buffer {
  const key = assert32ByteKey(dataKey32);
  const buf = Buffer.from(sealed);
  if (buf.byteLength < 29) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: "Malformed sealed TOTP secret payload"
    });
  }
  const iv = buf.subarray(0, 12);
  const tag = buf.subarray(12, 28);
  const ciphertext = buf.subarray(28);
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAAD(Buffer.from(`rq.totp.v1:${userId}`, "utf8"));
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}
