import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import {
  AuthenticationDomainError,
  ValidationDomainError,
  nowUtcInstant,
  parsePrincipalId
} from "@relayquill/domain";
import {
  InMemoryPasskeyRepository,
  createPasskeyAuthenticationOptions,
  createPasskeyRegistrationOptions,
  generateOpaqueWebAuthnUserId,
  normalizeAuthPolicyConfig,
  parsePasskeyAuthenticationAssertionShape,
  verifyPasskeyAuthentication,
  verifyPasskeyRegistration
} from "@relayquill/auth";
import { VirtualWebAuthnAuthenticator } from "./helpers/virtual-authenticator.mjs";

const DEV_POLICY = {
  rp_id: "localhost",
  rp_name: "Relayquill Dev",
  allowed_origins: ["http://localhost:5205"],
  cookie_profile: "development_only"
};

test("passkeys policy rejects localhost/HTTP/fixture origins in release_https mode", () => {
  assert.throws(
    () =>
      normalizeAuthPolicyConfig({
        rp_id: "localhost",
        allowed_origins: ["https://localhost"],
        cookie_profile: "release_https"
      }),
    ValidationDomainError
  );
  assert.throws(
    () =>
      normalizeAuthPolicyConfig({
        rp_id: "console.relayquill.example",
        allowed_origins: ["http://console.relayquill.example"],
        cookie_profile: "release_https"
      }),
    ValidationDomainError
  );
  assert.throws(
    () =>
      normalizeAuthPolicyConfig({
        rp_id: "receiver.fixture.test",
        allowed_origins: ["https://receiver.fixture.test"],
        cookie_profile: "release_https"
      }),
    ValidationDomainError
  );
  assert.throws(
    () =>
      normalizeAuthPolicyConfig({
        rp_id: "app.example.com",
        allowed_origins: ["https://evil.example.com"],
        cookie_profile: "release_https"
      }),
    ValidationDomainError
  );

  const releasePolicy = normalizeAuthPolicyConfig({
    rp_id: "relayquill.example",
    allowed_origins: ["https://console.relayquill.example"],
    cookie_profile: "release_https"
  });
  assert.equal(releasePolicy.rpId, "relayquill.example");
  assert.deepEqual(releasePolicy.allowedOrigins, ["https://console.relayquill.example"]);
});

test("passkeys pair opaque 32-byte webauthn_user_id with human-readable user.name and user.displayName", async () => {
  const webauthnUserId = generateOpaqueWebAuthnUserId();
  assert.equal(webauthnUserId.byteLength, 32);

  const challenge = crypto.randomBytes(32);
  const regOptions = await createPasskeyRegistrationOptions({
    policy: DEV_POLICY,
    challengeBytes: challenge,
    webauthnUserId,
    userName: "alice@example.com",
    userDisplayName: "Alice Administrator"
  });

  assert.equal(regOptions.rp.id, "localhost");
  assert.equal(regOptions.user.name, "alice@example.com");
  assert.equal(regOptions.user.displayName, "Alice Administrator");
  assert.equal(
    Buffer.from(regOptions.user.id, "base64url").equals(Buffer.from(webauthnUserId)),
    true
  );
  assert.equal(regOptions.authenticatorSelection?.userVerification, "required");
  assert.equal(regOptions.authenticatorSelection?.residentKey, "required");

  // Reject whitespace-only or control-character human labels
  await assert.rejects(
    () =>
      createPasskeyRegistrationOptions({
        policy: DEV_POLICY,
        challengeBytes: challenge,
        webauthnUserId,
        userName: "   "
      }),
    ValidationDomainError
  );
  await assert.rejects(
    () =>
      createPasskeyRegistrationOptions({
        policy: DEV_POLICY,
        challengeBytes: challenge,
        webauthnUserId,
        userName: "alice\nadmin"
      }),
    ValidationDomainError
  );
});

test("passkeys verify ES256 and EdDSA registration & authentication with UV, origin, RP, userHandle, and counter semantics", async () => {
  for (const algorithm of ["ES256", "EdDSA"]) {
    const authenticator = new VirtualWebAuthnAuthenticator({ algorithm });
    const repo = new InMemoryPasskeyRepository();
    const principalId = parsePrincipalId(crypto.randomUUID());
    const webauthnUserId = generateOpaqueWebAuthnUserId();
    const regChallenge = crypto.randomBytes(32);

    const regOptions = await createPasskeyRegistrationOptions({
      policy: DEV_POLICY,
      challengeBytes: regChallenge,
      webauthnUserId,
      userName: "operator@acme.test",
      userDisplayName: "Acme Operator"
    });

    // Wrong origin must be rejected
    const badOriginReg = authenticator.createRegistrationResponse(regOptions, {
      origin: "https://evil.example.com"
    });
    await assert.rejects(
      () =>
        verifyPasskeyRegistration({
          policy: DEV_POLICY,
          response: badOriginReg,
          expectedChallengeBytes: regChallenge
        }),
      AuthenticationDomainError
    );

    // Wrong RP ID hash must be rejected
    const badRpReg = authenticator.createRegistrationResponse(regOptions, {
      rpId: "evil.example.com"
    });
    await assert.rejects(
      () =>
        verifyPasskeyRegistration({
          policy: DEV_POLICY,
          response: badRpReg,
          expectedChallengeBytes: regChallenge
        }),
      AuthenticationDomainError
    );

    // Missing UV must be rejected
    const noUvReg = authenticator.createRegistrationResponse(regOptions, {
      userVerified: false
    });
    await assert.rejects(
      () =>
        verifyPasskeyRegistration({
          policy: DEV_POLICY,
          response: noUvReg,
          expectedChallengeBytes: regChallenge
        }),
      AuthenticationDomainError
    );

    // Valid registration (synced passkey flags BE=1, BS=1, counter=0)
    const validReg = authenticator.createRegistrationResponse(regOptions, {
      backupEligible: true,
      backedUp: true,
      initialCounter: 0
    });
    const verifiedReg = await verifyPasskeyRegistration({
      policy: DEV_POLICY,
      response: validReg,
      expectedChallengeBytes: regChallenge
    });
    assert.equal(verifiedReg.deviceType, "multiDevice");
    assert.equal(verifiedReg.backedUp, true);
    assert.equal(verifiedReg.signCount, 0n);

    const stored = await repo.createPasskey({
      id: crypto.randomUUID(),
      humanPrincipalId: principalId,
      credentialId: verifiedReg.credentialId,
      publicKey: verifiedReg.publicKey,
      webauthnUserId,
      signCount: verifiedReg.signCount,
      deviceType: verifiedReg.deviceType,
      backedUp: verifiedReg.backedUp,
      transports: verifiedReg.transports,
      state: "active",
      enrolledAt: nowUtcInstant()
    });

    // Synced passkey authentication with counter staying 0 -> 0 MUST succeed
    const authChallenge1 = crypto.randomBytes(32);
    const authOptions1 = await createPasskeyAuthenticationOptions({
      policy: DEV_POLICY,
      challengeBytes: authChallenge1
    });
    const validAssertion1 = authenticator.createAuthenticationResponse(authOptions1, {
      credentialIdBase64Url: validReg.id,
      counter: 0,
      backupEligible: true,
      backedUp: true
    });
    const verifiedAuth1 = await verifyPasskeyAuthentication({
      policy: DEV_POLICY,
      assertion: parsePasskeyAuthenticationAssertionShape(validAssertion1),
      storedPasskey: stored,
      expectedChallengeBytes: authChallenge1
    });
    assert.equal(verifiedAuth1.newSignCount, 0n);
    assert.equal(verifiedAuth1.deviceType, "multiDevice");
    assert.equal(verifiedAuth1.backedUp, true);

    // Tampered signature, missing UV, wrong origin, wrong RP, wrong userHandle must fail
    const badSig = authenticator.createAuthenticationResponse(authOptions1, {
      credentialIdBase64Url: validReg.id,
      tamperSignature: true
    });
    await assert.rejects(
      () =>
        verifyPasskeyAuthentication({
          policy: DEV_POLICY,
          assertion: parsePasskeyAuthenticationAssertionShape(badSig),
          storedPasskey: stored,
          expectedChallengeBytes: authChallenge1
        }),
      AuthenticationDomainError
    );

    const badUvAuth = authenticator.createAuthenticationResponse(authOptions1, {
      credentialIdBase64Url: validReg.id,
      userVerified: false
    });
    await assert.rejects(
      () =>
        verifyPasskeyAuthentication({
          policy: DEV_POLICY,
          assertion: parsePasskeyAuthenticationAssertionShape(badUvAuth),
          storedPasskey: stored,
          expectedChallengeBytes: authChallenge1
        }),
      AuthenticationDomainError
    );

    const badUserHandleAuth = authenticator.createAuthenticationResponse(authOptions1, {
      credentialIdBase64Url: validReg.id,
      userHandle: crypto.randomBytes(32)
    });
    await assert.rejects(
      () =>
        verifyPasskeyAuthentication({
          policy: DEV_POLICY,
          assertion: parsePasskeyAuthenticationAssertionShape(badUserHandleAuth),
          storedPasskey: stored,
          expectedChallengeBytes: authChallenge1
        }),
      AuthenticationDomainError
    );

    // Hardware counter rollback protection when counter > 0
    const updatedStored = await repo.recordPasskeyUse({
      passkeyId: stored.id,
      expectedVersion: stored.version,
      newSignCount: 5n,
      deviceType: "singleDevice",
      backedUp: false,
      usedAt: nowUtcInstant()
    });
    const rollbackAssertion = authenticator.createAuthenticationResponse(authOptions1, {
      credentialIdBase64Url: validReg.id,
      counter: 4
    });
    await assert.rejects(
      () =>
        verifyPasskeyAuthentication({
          policy: DEV_POLICY,
          assertion: parsePasskeyAuthenticationAssertionShape(rollbackAssertion),
          storedPasskey: updatedStored,
          expectedChallengeBytes: authChallenge1
        }),
      AuthenticationDomainError
    );
  }
});
