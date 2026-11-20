import { type IdempotencyKey, parseIdempotencyKey } from "@relayquill/contracts";

export function generateIdempotencyKey(prefix: string): IdempotencyKey {
  const cleanPrefix = prefix.replace(/[^A-Za-z0-9._-]/g, "-").slice(0, 48) || "cmd";
  const randomBytes = new Uint8Array(12);
  crypto.getRandomValues(randomBytes);
  let hex = "";
  for (let i = 0; i < randomBytes.length; i += 1) {
    hex += (randomBytes[i] ?? 0).toString(16).padStart(2, "0");
  }
  return parseIdempotencyKey(`${cleanPrefix}-${hex}`, "idempotency_key");
}
