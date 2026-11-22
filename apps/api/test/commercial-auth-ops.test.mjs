import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { computeTotp6Digits, decodeBase32, generatePkcePair } from "@relayquill/auth";
import { parseUtcTimestamp } from "@relayquill/domain";
import { createPGliteAdapter } from "@relayquill/postgres";
import { createAllowlistedLogger, createApiServer } from "../dist/index.js";

const TEST_DIR = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(TEST_DIR, "../../..");
const MIGRATIONS_DIR = path.join(REPO_ROOT, "migrations");
const CONSOLE_ORIGIN = "http://localhost:5205";

async function applyMigrations(pg) {
  const files = fs
    .readdirSync(MIGRATIONS_DIR)
    .filter((f) => f.endsWith(".sql"))
    .sort();
  for (const file of files) {
    await pg.exec(fs.readFileSync(path.join(MIGRATIONS_DIR, file), "utf8"));
  }
}

function extractCookiePair(setCookieHeader, cookieName) {
  const headers = Array.isArray(setCookieHeader) ? setCookieHeader : [setCookieHeader];
  for (const h of headers) {
    if (typeof h === "string" && h.startsWith(`${cookieName}=`)) {
      return h.split(";")[0];
    }
  }
  return null;
}

test("Commercial auth (Argon2id, TOTP MFA, OIDC PKCE, clickwrap legal), 15m break-glass, /status, and GDPR erasure", async (t) => {
  const pg = await createPGliteAdapter({
    schema: "rq",
    supportSchema: "rq_support",
    isolation: "shared_database_schemas",
    configuredRole: "rq_api"
  });
  t.after(() => pg.close());
  await applyMigrations(pg);

  await pg.exec(`
    UPDATE rq.installation_state
       SET mode = 'open',
           allow_event_admission = true,
           allow_publication = true,
           allow_fanout = true,
           allow_send = true,
           allow_endpoint_verification = true,
           version = version + 1
     WHERE id = 1;
  `);

  let fixedMs = Date.UTC(2026, 10, 22, 12, 0, 0);
  const fixedClock = {
    nowMs: () => fixedMs,
    nowInstant: () => parseUtcTimestamp(new Date(fixedMs).toISOString()).instant,
    nowTimestamp: () => new Date(fixedMs).toISOString()
  };

  const logs = [];
  const server = createApiServer({
    pgAdapter: pg,
    profile: "development_trusted_local",
    allowDevBootstrapRoute: true,
    clock: fixedClock,
    logger: createAllowlistedLogger({ level: "warn", sink: (e) => logs.push(e) })
  });
  t.after(() => server.close());
  const { app } = server;

  // 1. Unauthenticated /status returns safe telemetry with zero tenant identifiers
  const statusRes = await app.inject({ method: "GET", url: "/status" });
  assert.equal(statusRes.statusCode, 200, statusRes.body);
  const statusBody = statusRes.json().data;
  assert.equal(statusBody.service, "relayquill");
  assert.equal(statusBody.overall_status, "operational");
  assert.ok(Array.isArray(statusBody.components) && statusBody.components.length >= 4);

  // 2. Signup rejects disposable email and missing clickwrap consent
  const badDisposable = await app.inject({
    method: "POST",
    url: "/api/v1/auth/signup",
    headers: { "content-type": "application/json" },
    payload: JSON.stringify({
      email: "sybil@mailinator.com",
      password: "ExamplePassphrase!ChangeBeforeUse",
      org_name: "Sybil Org",
      accept_legal: true
    })
  });
  assert.equal(badDisposable.statusCode, 400);

  const badNoConsent = await app.inject({
    method: "POST",
    url: "/api/v1/auth/signup",
    headers: { "content-type": "application/json" },
    payload: JSON.stringify({
      email: "founder@acme-saas.example",
      password: "ExamplePassphrase!ChangeBeforeUse",
      org_name: "Acme SaaS Corp",
      accept_legal: false
    })
  });
  assert.equal(badNoConsent.statusCode, 400);

  // 3. Valid signup issues Argon2id user, Free tier entitlements, legal acceptances, verify_email outbox, and session cookie
  const signupRes = await app.inject({
    method: "POST",
    url: "/api/v1/auth/signup",
    headers: { "content-type": "application/json" },
    payload: JSON.stringify({
      email: "founder@acme-saas.example",
      password: "ExamplePassphrase!ChangeBeforeUse",
      org_name: "Acme SaaS Corp",
      tos_version: "2026-11-01",
      dpa_version: "2026-11-01",
      accept_legal: true
    })
  });
  assert.equal(signupRes.statusCode, 201, signupRes.body);
  const signupData = signupRes.json().data;
  assert.equal(signupData.plan_tier, "free");
  assert.equal(signupData.role, "owner");
  assert.equal(signupData.mfa_enrolled, false);
  const cookie1 = extractCookiePair(signupRes.headers["set-cookie"], "rq_session_dev");
  assert.ok(cookie1);
  const csrf1 = signupData.csrf_token;

  const outboxCheck = await pg.query(
    `SELECT template_code, state FROM rq.email_outbox WHERE tenant_id = $1::uuid`,
    [signupData.tenant_id]
  );
  assert.equal(outboxCheck.rows[0]?.template_code, "verify_email");

  // 4. Legal re-acceptance updates version
  const legalRes = await app.inject({
    method: "POST",
    url: "/api/v1/legal/accept",
    headers: {
      "content-type": "application/json",
      cookie: cookie1,
      origin: CONSOLE_ORIGIN,
      "x-relayquill-csrf": csrf1,
      "idempotency-key": "legal-upd-1"
    },
    payload: JSON.stringify({ document_kind: "tos", doc_version: "2026-11-15" })
  });
  assert.equal(legalRes.statusCode, 200, legalRes.body);

  // 5. Enroll + verify TOTP MFA, then confirm login rejects wrong/missing/replayed TOTP codes
  const enrollTotpRes = await app.inject({
    method: "POST",
    url: "/api/v1/auth/mfa/totp/enroll",
    headers: {
      "content-type": "application/json",
      cookie: cookie1,
      origin: CONSOLE_ORIGIN,
      "x-relayquill-csrf": csrf1,
      "idempotency-key": "totp-enroll-1"
    },
    payload: "{}"
  });
  assert.equal(enrollTotpRes.statusCode, 200, enrollTotpRes.body);
  const secretBytes = decodeBase32(enrollTotpRes.json().data.secret_base32);
  const enrollCode = computeTotp6Digits(secretBytes, Math.floor(fixedMs / 1000));

  const verifyTotpRes = await app.inject({
    method: "POST",
    url: "/api/v1/auth/mfa/totp/verify",
    headers: {
      "content-type": "application/json",
      cookie: cookie1,
      origin: CONSOLE_ORIGIN,
      "x-relayquill-csrf": csrf1,
      "idempotency-key": "totp-verify-1"
    },
    payload: JSON.stringify({ totp_code: enrollCode })
  });
  assert.equal(verifyTotpRes.statusCode, 200, verifyTotpRes.body);
  assert.equal(verifyTotpRes.json().data.enrolled, true);

  // Advance clock +30s to next TOTP window for MFA login
  fixedMs += 30_000;
  const loginCode = computeTotp6Digits(secretBytes, Math.floor(fixedMs / 1000));

  const missingCodeLogin = await app.inject({
    method: "POST",
    url: "/api/v1/auth/login",
    headers: { "content-type": "application/json" },
    payload: JSON.stringify({
      email: "founder@acme-saas.example",
      password: "ExamplePassphrase!ChangeBeforeUse"
    })
  });
  assert.equal(missingCodeLogin.statusCode, 401);

  const mfaLoginRes = await app.inject({
    method: "POST",
    url: "/api/v1/auth/login",
    headers: { "content-type": "application/json" },
    payload: JSON.stringify({
      email: "founder@acme-saas.example",
      password: "ExamplePassphrase!ChangeBeforeUse",
      totp_code: loginCode
    })
  });
  assert.equal(mfaLoginRes.statusCode, 200, mfaLoginRes.body);
  const cookie2 = extractCookiePair(mfaLoginRes.headers["set-cookie"], "rq_session_dev");
  const csrf2 = mfaLoginRes.json().data.csrf_token;
  assert.ok(cookie2);

  // Same TOTP step replay must be rejected (401)
  const replayLoginRes = await app.inject({
    method: "POST",
    url: "/api/v1/auth/login",
    headers: { "content-type": "application/json" },
    payload: JSON.stringify({
      email: "founder@acme-saas.example",
      password: "ExamplePassphrase!ChangeBeforeUse",
      totp_code: loginCode
    })
  });
  assert.equal(replayLoginRes.statusCode, 401);

  // 6. Enterprise OIDC denied on Free tier, enabled once sso_enabled=true, and PKCE login maps role
  const freeOidcDenied = await app.inject({
    method: "POST",
    url: "/api/v1/auth/oidc/configure",
    headers: {
      "content-type": "application/json",
      cookie: cookie2,
      origin: CONSOLE_ORIGIN,
      "x-relayquill-csrf": csrf2,
      "idempotency-key": "oidc-free-deny"
    },
    payload: JSON.stringify({
      issuer_url: "https://idp.acme-saas.example",
      client_id: "rq-client",
      client_secret_ref: "env:OIDC_SECRET",
      role_mapping: { "platform-devs": "developer" }
    })
  });
  assert.equal(freeOidcDenied.statusCode, 403);

  await pg.query(`UPDATE rq.entitlement_quotas SET sso_enabled = true WHERE org_id = $1::uuid`, [
    signupData.tenant_id
  ]);

  const teamOidcOk = await app.inject({
    method: "POST",
    url: "/api/v1/auth/oidc/configure",
    headers: {
      "content-type": "application/json",
      cookie: cookie2,
      origin: CONSOLE_ORIGIN,
      "x-relayquill-csrf": csrf2,
      "idempotency-key": "oidc-team-ok"
    },
    payload: JSON.stringify({
      issuer_url: "https://idp.acme-saas.example",
      client_id: "rq-client",
      client_secret_ref: "env:OIDC_SECRET",
      role_mapping: { "platform-devs": "developer" }
    })
  });
  assert.equal(teamOidcOk.statusCode, 200, teamOidcOk.body);

  const pkce = generatePkcePair();
  const oidcCallbackRes = await app.inject({
    method: "POST",
    url: "/api/v1/auth/oidc/callback",
    headers: { "content-type": "application/json" },
    payload: JSON.stringify({
      tenant_id: signupData.tenant_id,
      code_verifier: pkce.codeVerifier,
      expected_challenge: pkce.codeChallenge,
      claims: { sub: "oidc-sub-1", email: "dev@acme-saas.example", groups: ["platform-devs"] }
    })
  });
  assert.equal(oidcCallbackRes.statusCode, 200, oidcCallbackRes.body);
  assert.equal(oidcCallbackRes.json().data.role, "developer");

  // 7. 15m Dual-Logged Read-Only Support Break-Glass + Customer /settings/audit visibility
  await pg.query(
    `INSERT INTO rq.platform_role_assignments (id, principal_id, role, state, governance_version, created_at, version)
     VALUES ($1::uuid, $2::uuid, 'platform_admin', 'active', 1, pg_catalog.clock_timestamp(), 1)`,
    [crypto.randomUUID(), signupData.principal_id]
  );

  const shortReasonBg = await app.inject({
    method: "POST",
    url: "/api/v1/ops/break-glass",
    headers: {
      "content-type": "application/json",
      cookie: cookie2,
      origin: CONSOLE_ORIGIN,
      "x-relayquill-csrf": csrf2,
      "idempotency-key": "bg-short"
    },
    payload: JSON.stringify({
      target_tenant_id: signupData.tenant_id,
      reason: "too short",
      ttl_minutes: 15,
      mfa_verified: true
    })
  });
  assert.equal(shortReasonBg.statusCode, 400);

  const bgOkRes = await app.inject({
    method: "POST",
    url: "/api/v1/ops/break-glass",
    headers: {
      "content-type": "application/json",
      cookie: cookie2,
      origin: CONSOLE_ORIGIN,
      "x-relayquill-csrf": csrf2,
      "idempotency-key": "bg-create-1"
    },
    payload: JSON.stringify({
      target_tenant_id: signupData.tenant_id,
      reason: "Investigating webhook timeout ticket #441",
      ttl_minutes: 15,
      mfa_verified: true
    })
  });
  assert.equal(bgOkRes.statusCode, 201, bgOkRes.body);
  const bgData = bgOkRes.json().data;
  assert.equal(bgData.read_only, true);
  assert.equal(bgData.customer_audit_logged, true);

  // Break-glass token can read customer /settings/audit and sees dual audit + session
  const bgReadAudit = await app.inject({
    method: "GET",
    url: "/api/v1/settings/audit",
    headers: { "x-relayquill-break-glass": bgData.token_once }
  });
  assert.equal(bgReadAudit.statusCode, 200, bgReadAudit.body);
  assert.ok(
    bgReadAudit.json().data.audit_events.some((e) => e.action === "support.break_glass.started")
  );
  assert.equal(bgReadAudit.json().data.break_glass_sessions.length, 1);

  // Break-glass token CANNOT mutate anything or read signing-keys paths (403)
  const bgWriteDenied = await app.inject({
    method: "POST",
    url: "/api/v1/legal/accept",
    headers: {
      "content-type": "application/json",
      "x-relayquill-break-glass": bgData.token_once
    },
    payload: JSON.stringify({ document_kind: "tos", doc_version: "2026-12-01" })
  });
  assert.equal(bgWriteDenied.statusCode, 403);

  const bgSecretDenied = await app.inject({
    method: "GET",
    url: `/api/v1/tenants/${signupData.tenant_id}/projects/00000000-0000-4000-8000-000000000001/endpoints/ep1/signing-keys`,
    headers: { "x-relayquill-break-glass": bgData.token_once }
  });
  assert.equal(bgSecretDenied.statusCode, 403);

  // Revoke break-glass token -> subsequent read fails 401
  const revokeBgRes = await app.inject({
    method: "POST",
    url: `/api/v1/ops/break-glass/${bgData.break_glass_id}/revoke`,
    headers: {
      "content-type": "application/json",
      cookie: cookie2,
      origin: CONSOLE_ORIGIN,
      "x-relayquill-csrf": csrf2,
      "idempotency-key": "bg-revoke-1"
    },
    payload: "{}"
  });
  assert.equal(revokeBgRes.statusCode, 200);

  const bgAfterRevoke = await app.inject({
    method: "GET",
    url: "/api/v1/settings/audit",
    headers: { "x-relayquill-break-glass": bgData.token_once }
  });
  assert.equal(bgAfterRevoke.statusCode, 401);

  // 8. Self-serve Never-Paywall GDPR erasure redacts user PII and retains anonymized 7-year tax ref
  const badPhrase = await app.inject({
    method: "POST",
    url: "/api/v1/orgs/me/erasure-request",
    headers: {
      "content-type": "application/json",
      cookie: cookie2,
      origin: CONSOLE_ORIGIN,
      "x-relayquill-csrf": csrf2,
      "idempotency-key": "gdpr-bad-phrase"
    },
    payload: JSON.stringify({
      confirm_phrase: "NOPE",
      password: "ExamplePassphrase!ChangeBeforeUse"
    })
  });
  assert.equal(badPhrase.statusCode, 400);

  const gdprRes = await app.inject({
    method: "POST",
    url: "/api/v1/orgs/me/erasure-request",
    headers: {
      "content-type": "application/json",
      cookie: cookie2,
      origin: CONSOLE_ORIGIN,
      "x-relayquill-csrf": csrf2,
      "idempotency-key": "gdpr-exec-1"
    },
    payload: JSON.stringify({
      confirm_phrase: "DELETE ORGANIZATION",
      password: "ExamplePassphrase!ChangeBeforeUse"
    })
  });
  assert.equal(gdprRes.statusCode, 202, gdprRes.body);
  assert.equal(gdprRes.json().data.tax_records_retained_anonymized_years, 7);

  const redactedUser = await pg.query(
    `SELECT email, password_hash FROM rq.users WHERE id = $1::uuid`,
    [signupData.user_id]
  );
  assert.match(String(redactedUser.rows[0]?.email), /^erased-.*@redacted\.invalid$/);
  assert.equal(redactedUser.rows[0]?.password_hash, "!ERASED!");

  const retainedCustomer = await pg.query(
    `SELECT billing_email, stripe_customer_id FROM rq.billing_customers WHERE org_id = $1::uuid`,
    [signupData.tenant_id]
  );
  assert.match(String(retainedCustomer.rows[0]?.billing_email), /^erased-.*@redacted\.invalid$/);
  assert.ok(String(retainedCustomer.rows[0]?.stripe_customer_id).startsWith("cus_local_"));
});
