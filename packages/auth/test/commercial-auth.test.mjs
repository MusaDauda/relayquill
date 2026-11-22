import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";
import { ValidationDomainError } from "@relayquill/domain";
import {
  BREAK_GLASS_MAX_TTL_MINUTES,
  InMemoryTotpReplayGuardStore,
  buildBreakGlassWindow,
  buildOidcAuthorizationUrl,
  buildTotpOtpauthUri,
  computeTotp6Digits,
  decodeBase32,
  encodeBase32,
  generatePkcePair,
  generateTotpSecret,
  hashBreakGlassToken,
  hashPasswordArgon2id,
  mapOidcClaimsToTenantRole,
  mintBreakGlassToken,
  openTotpSecret,
  sealTotpSecret,
  validateBreakGlassReadScope,
  validateOidcIssuerUrl,
  verifyPasswordArgon2id,
  verifyPkceCodeChallenge,
  verifyTotpWithReplayGuard
} from "@relayquill/auth";

test("hashPasswordArgon2id and verifyPasswordArgon2id enforce length bounds and PHC verification", async () => {
  await assert.rejects(
    () => hashPasswordArgon2id("short"),
    (err) => err instanceof ValidationDomainError && err.code === "INVALID_VALUE"
  );

  const hash = await hashPasswordArgon2id("CorrectHorseBatteryStaple!99", {
    memory: 8192,
    passes: 2,
    parallelism: 1
  });
  assert.ok(hash.startsWith("$argon2id$v=19$m=8192,t=2,p=1$"));
  assert.equal(await verifyPasswordArgon2id("CorrectHorseBatteryStaple!99", hash), true);
  assert.equal(await verifyPasswordArgon2id("WrongPasswordAttempt!99", hash), false);
  assert.equal(await verifyPasswordArgon2id("CorrectHorseBatteryStaple!99", "$bcrypt$invalid$hash"), false);
});

test("TOTP generation, Base32 round-trip, AES-256-GCM envelope, and replay-window guard", async () => {
  const { secretBytes, base32Secret } = generateTotpSecret();
  assert.deepEqual(decodeBase32(base32Secret), secretBytes);
  assert.equal(encodeBase32(Buffer.from("12345678901234567890", "utf8")), "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");

  const uri = buildTotpOtpauthUri({
    issuer: "Relayquill",
    accountEmail: "owner@acme.example",
    base32Secret
  });
  assert.match(uri, /^otpauth:\/\/totp\/Relayquill:owner%40acme\.example\?/);

  const dataKey = crypto.randomBytes(32);
  const sealed = sealTotpSecret(dataKey, secretBytes, "user-1");
  assert.deepEqual(openTotpSecret(dataKey, sealed, "user-1"), Buffer.from(secretBytes));
  assert.throws(() => openTotpSecret(dataKey, sealed, "other-user"));

  const store = new InMemoryTotpReplayGuardStore();
  const nowSec = 1_760_000_000;
  const code = computeTotp6Digits(secretBytes, nowSec);
  const first = await verifyTotpWithReplayGuard({
    store,
    userId: "user-1",
    secretBytes,
    submittedCode: code,
    nowUnixSec: nowSec
  });
  assert.equal(first.valid, true);

  const replay = await verifyTotpWithReplayGuard({
    store,
    userId: "user-1",
    secretBytes,
    submittedCode: code,
    nowUnixSec: nowSec
  });
  assert.equal(replay.valid, false);
});

test("OIDC PKCE, issuer HTTPS validation, and role mapping enforce strict rules", () => {
  assert.equal(validateOidcIssuerUrl("https://sso.acme.example/oauth2/"), "https://sso.acme.example/oauth2");
  assert.throws(
    () => validateOidcIssuerUrl("http://sso.acme.example"),
    (err) => err instanceof ValidationDomainError && err.code === "INVALID_VALUE"
  );
  assert.throws(
    () => validateOidcIssuerUrl("https://127.0.0.1:8443"),
    (err) => err instanceof ValidationDomainError && err.code === "INVALID_VALUE"
  );

  const pkce = generatePkcePair();
  assert.equal(pkce.method, "S256");
  assert.equal(verifyPkceCodeChallenge(pkce.codeVerifier, pkce.codeChallenge), true);
  assert.equal(verifyPkceCodeChallenge(`${pkce.codeVerifier}tamper`, pkce.codeChallenge), false);

  const authUrl = buildOidcAuthorizationUrl(
    { issuerUrl: "https://sso.acme.example", clientId: "rq-client" },
    {
      redirectUri: "https://console.relayquill.example/auth/callback",
      state: "st-1",
      nonce: "n-1",
      codeChallenge: pkce.codeChallenge
    }
  );
  assert.match(authUrl, /code_challenge_method=S256/);

  const role = mapOidcClaimsToTenantRole(["devs", "sec-admins"], {
    "sec-admins": "admin",
    devs: "developer"
  });
  assert.equal(role, "admin");
  assert.equal(mapOidcClaimsToTenantRole(["unmapped"], { "sec-admins": "admin" }), null);
});

test("Support break-glass enforces 15m TTL, >= 12 char reason, read-only methods, and secret path denies", () => {
  assert.equal(BREAK_GLASS_MAX_TTL_MINUTES, 15);
  const now = new Date("2026-11-22T12:00:00.000Z");

  assert.throws(
    () => buildBreakGlassWindow("short", 10, now),
    (err) => err instanceof ValidationDomainError && err.code === "INVALID_VALUE"
  );
  assert.throws(
    () => buildBreakGlassWindow("Investigating customer delivery stall", 16, now),
    (err) => err instanceof ValidationDomainError && err.code === "INVALID_VALUE"
  );

  const win = buildBreakGlassWindow("Investigating customer delivery stall", 15, now);
  assert.equal(win.expiresAt.getTime() - win.startedAt.getTime(), 15 * 60_000);

  const minted = mintBreakGlassToken();
  assert.ok(minted.token.startsWith("rq_bg_"));
  assert.deepEqual(hashBreakGlassToken(minted.token), minted.tokenSha256);
  assert.equal(hashBreakGlassToken("bad_prefix"), null);

  const session = {
    expiresAt: win.expiresAt,
    revokedAt: null,
    readOnly: true,
    operatorId: "op-1",
    tenantId: "tenant-1"
  };

  assert.equal(validateBreakGlassReadScope(session, "GET", "/api/v1/settings/audit", now).allowed, true);
  assert.deepEqual(validateBreakGlassReadScope(session, "POST", "/api/v1/endpoints", now), {
    allowed: false,
    status: 403,
    code: "BREAK_GLASS_READ_ONLY_VIOLATION"
  });
  assert.deepEqual(validateBreakGlassReadScope(session, "GET", "/api/v1/endpoints/ep_1/signing-keys", now), {
    allowed: false,
    status: 403,
    code: "BREAK_GLASS_FORBIDDEN_RESOURCE"
  });
  assert.deepEqual(
    validateBreakGlassReadScope(session, "GET", "/api/v1/settings/audit", new Date(win.expiresAt.getTime() + 1)),
    {
      allowed: false,
      status: 401,
      code: "BREAK_GLASS_EXPIRED_OR_REVOKED"
    }
  );
});
