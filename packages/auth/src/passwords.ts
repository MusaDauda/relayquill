import crypto from "node:crypto";
import { promisify } from "node:util";
import { ValidationDomainError } from "@relayquill/domain";

const argon2Async = promisify(crypto.argon2);

export const MIN_PASSWORD_LENGTH = 12 as const;
export const MAX_PASSWORD_LENGTH = 256 as const;

export const ARGON2ID_DEFAULTS = Object.freeze({
  memory: 65_536,
  passes: 3,
  parallelism: 1,
  tagLength: 32,
  saltLength: 16
});

export interface Argon2idHashOptions {
  readonly memory?: number | undefined;
  readonly passes?: number | undefined;
  readonly parallelism?: number | undefined;
  readonly tagLength?: number | undefined;
  readonly salt?: Uint8Array | undefined;
}

function stripBase64Padding(buf: Buffer): string {
  return buf.toString("base64").replace(/=+$/g, "");
}

function decodeBase64Unpadded(segment: string): Buffer | null {
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(segment)) {
    return null;
  }
  const padLen = (4 - (segment.length % 4)) % 4;
  return Buffer.from(segment + "=".repeat(padLen), "base64");
}

function assertBoundedPassword(password: string): Buffer {
  if (typeof password !== "string") {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: "Password must be a string",
      fieldErrors: [{ path: "password", code: "INVALID_VALUE" }]
    });
  }
  const buf = Buffer.from(password, "utf8");
  if (password.length < MIN_PASSWORD_LENGTH || buf.byteLength > MAX_PASSWORD_LENGTH) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Password must be between ${MIN_PASSWORD_LENGTH} characters and ${MAX_PASSWORD_LENGTH} UTF-8 bytes`,
      fieldErrors: [{ path: "password", code: "INVALID_VALUE" }]
    });
  }
  return buf;
}

function clampArgon2Option(value: number | undefined, fallback: number, min: number, max: number, label: string): number {
  const effective = value ?? fallback;
  if (!Number.isInteger(effective) || effective < min || effective > max) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Argon2id ${label} must be an integer between ${min} and ${max}`
    });
  }
  return effective;
}

/**
 * Hashes a user passphrase with Argon2id (`v=19`, `m=65536,t=3,p=1` by default) into canonical PHC format.
 */
export async function hashPasswordArgon2id(
  password: string,
  options: Argon2idHashOptions = {}
): Promise<string> {
  const message = assertBoundedPassword(password);
  const memory = clampArgon2Option(options.memory, ARGON2ID_DEFAULTS.memory, 1024, 262_144, "memory");
  const passes = clampArgon2Option(options.passes, ARGON2ID_DEFAULTS.passes, 1, 10, "passes");
  const parallelism = clampArgon2Option(options.parallelism, ARGON2ID_DEFAULTS.parallelism, 1, 8, "parallelism");
  const tagLength = clampArgon2Option(options.tagLength, ARGON2ID_DEFAULTS.tagLength, 16, 64, "tagLength");

  const salt =
    options.salt !== undefined ? Buffer.from(options.salt) : crypto.randomBytes(ARGON2ID_DEFAULTS.saltLength);
  if (salt.byteLength < 8 || salt.byteLength > 64) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: "Argon2id salt must be between 8 and 64 bytes"
    });
  }

  const derived = await argon2Async("argon2id", {
    message,
    nonce: salt,
    memory,
    passes,
    parallelism,
    tagLength
  });

  return `$argon2id$v=19$m=${memory},t=${passes},p=${parallelism}$${stripBase64Padding(salt)}$${stripBase64Padding(Buffer.from(derived))}`;
}

interface ParsedArgon2idPhc {
  readonly memory: number;
  readonly passes: number;
  readonly parallelism: number;
  readonly salt: Buffer;
  readonly hash: Buffer;
}

function parseArgon2idPhc(encodedHash: string): ParsedArgon2idPhc | null {
  if (typeof encodedHash !== "string" || !encodedHash.startsWith("$argon2id$")) {
    return null;
  }
  const parts = encodedHash.split("$");
  // Expected: ["", "argon2id", "v=19", "m=...,t=...,p=...", "<salt>", "<hash>"]
  if (parts.length !== 6) {
    return null;
  }
  const versionPart = parts[2];
  const paramPart = parts[3];
  const saltPart = parts[4];
  const hashPart = parts[5];
  if (
    versionPart !== "v=19" ||
    paramPart === undefined ||
    saltPart === undefined ||
    hashPart === undefined
  ) {
    return null;
  }

  const paramMatch = /^m=(\d+),t=(\d+),p=(\d+)$/.exec(paramPart);
  if (paramMatch === null) {
    return null;
  }
  const memory = Number.parseInt(paramMatch[1] ?? "", 10);
  const passes = Number.parseInt(paramMatch[2] ?? "", 10);
  const parallelism = Number.parseInt(paramMatch[3] ?? "", 10);
  if (
    !Number.isInteger(memory) ||
    memory < 1024 ||
    memory > 262_144 ||
    !Number.isInteger(passes) ||
    passes < 1 ||
    passes > 10 ||
    !Number.isInteger(parallelism) ||
    parallelism < 1 ||
    parallelism > 8
  ) {
    return null;
  }

  const salt = decodeBase64Unpadded(saltPart);
  const hash = decodeBase64Unpadded(hashPart);
  if (
    salt === null ||
    hash === null ||
    salt.byteLength < 8 ||
    salt.byteLength > 64 ||
    hash.byteLength < 16 ||
    hash.byteLength > 64
  ) {
    return null;
  }

  return { memory, passes, parallelism, salt, hash };
}

/**
 * Verifies a plaintext password against a stored PHC `$argon2id$` hash in constant time.
 */
export async function verifyPasswordArgon2id(
  password: string,
  encodedHash: string
): Promise<boolean> {
  if (typeof password !== "string" || password.length === 0) {
    return false;
  }
  const message = Buffer.from(password, "utf8");
  if (message.byteLength > MAX_PASSWORD_LENGTH) {
    return false;
  }
  const parsed = parseArgon2idPhc(encodedHash);
  if (parsed === null) {
    return false;
  }

  const candidate = Buffer.from(
    await argon2Async("argon2id", {
      message,
      nonce: parsed.salt,
      memory: parsed.memory,
      passes: parsed.passes,
      parallelism: parsed.parallelism,
      tagLength: parsed.hash.byteLength
    })
  );

  if (candidate.byteLength !== parsed.hash.byteLength) {
    return false;
  }
  return crypto.timingSafeEqual(candidate, parsed.hash);
}
