import crypto from "node:crypto";

function encodeCborLength(majorType, length) {
  const prefix = majorType << 5;
  if (length < 24) {
    return Buffer.from([prefix | length]);
  }
  if (length <= 0xff) {
    return Buffer.from([prefix | 24, length]);
  }
  if (length <= 0xffff) {
    const buf = Buffer.allocUnsafe(3);
    buf[0] = prefix | 25;
    buf.writeUInt16BE(length, 1);
    return buf;
  }
  const buf = Buffer.allocUnsafe(5);
  buf[0] = prefix | 26;
  buf.writeUInt32BE(length, 1);
  return buf;
}

function encodeCborInt(value) {
  if (value >= 0) {
    return encodeCborLength(0, value);
  }
  return encodeCborLength(1, -1 - value);
}

function encodeCborBytes(buf) {
  return Buffer.concat([encodeCborLength(2, buf.length), buf]);
}

function encodeCborText(text) {
  const utf8 = Buffer.from(text, "utf8");
  return Buffer.concat([encodeCborLength(3, utf8.length), utf8]);
}

function encodeCborMap(entries) {
  const parts = [encodeCborLength(5, entries.length)];
  for (const [k, v] of entries) {
    parts.push(typeof k === "number" ? encodeCborInt(k) : encodeCborText(k));
    parts.push(v);
  }
  return Buffer.concat(parts);
}

function toBase64Url(buf) {
  return Buffer.from(buf).toString("base64url");
}

function pad32(buf) {
  if (buf.length === 32) {
    return buf;
  }
  if (buf.length > 32) {
    return buf.subarray(buf.length - 32);
  }
  const out = Buffer.alloc(32);
  buf.copy(out, 32 - buf.length);
  return out;
}

export class VirtualWebAuthnAuthenticator {
  constructor(options = {}) {
    this.algorithm = options.algorithm ?? "ES256";
    this.aaguid = options.aaguid ?? Buffer.alloc(16, 0x42);
    this.credentials = new Map();
  }

  createRegistrationResponse(creationOptions, overrides = {}) {
    const rpId = overrides.rpId ?? creationOptions.rp.id;
    const origin = overrides.origin ?? "http://localhost:5205";
    const challenge = overrides.challenge ?? creationOptions.challenge;
    const uv = overrides.userVerified !== false;
    const up = overrides.userPresent !== false;
    const backupEligible = overrides.backupEligible ?? false;
    const backedUp = overrides.backedUp ?? false;
    const initialCounter = overrides.initialCounter ?? 0;
    const userHandle = Buffer.from(creationOptions.user.id, "base64url");

    const credentialId = crypto.randomBytes(32);
    let publicKeyCose;
    let privateKey;

    if (this.algorithm === "EdDSA") {
      const pair = crypto.generateKeyPairSync("ed25519");
      privateKey = pair.privateKey;
      const jwk = pair.publicKey.export({ format: "jwk" });
      const x = Buffer.from(jwk.x, "base64url");
      publicKeyCose = encodeCborMap([
        [1, encodeCborInt(1)],
        [3, encodeCborInt(-8)],
        [-1, encodeCborInt(6)],
        [-2, encodeCborBytes(x)]
      ]);
    } else {
      const pair = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
      privateKey = pair.privateKey;
      const jwk = pair.publicKey.export({ format: "jwk" });
      const x = pad32(Buffer.from(jwk.x, "base64url"));
      const y = pad32(Buffer.from(jwk.y, "base64url"));
      publicKeyCose = encodeCborMap([
        [1, encodeCborInt(2)],
        [3, encodeCborInt(-7)],
        [-1, encodeCborInt(1)],
        [-2, encodeCborBytes(x)],
        [-3, encodeCborBytes(y)]
      ]);
    }

    const credIdB64 = toBase64Url(credentialId);
    this.credentials.set(credIdB64, {
      credentialId,
      rpId,
      userHandle,
      privateKey,
      algorithm: this.algorithm,
      counter: initialCounter,
      backupEligible,
      backedUp
    });

    const rpIdHash = crypto.createHash("sha256").update(rpId, "utf8").digest();
    const flagsByte =
      (up ? 0x01 : 0) |
      (uv ? 0x04 : 0) |
      (backupEligible ? 0x08 : 0) |
      (backedUp ? 0x10 : 0) |
      0x40; // AT flag

    const signCountBuf = Buffer.allocUnsafe(4);
    signCountBuf.writeUInt32BE(initialCounter, 0);

    const credIdLenBuf = Buffer.allocUnsafe(2);
    credIdLenBuf.writeUInt16BE(credentialId.length, 0);

    const authData = Buffer.concat([
      rpIdHash,
      Buffer.from([flagsByte]),
      signCountBuf,
      this.aaguid,
      credIdLenBuf,
      credentialId,
      publicKeyCose
    ]);

    const attestationObject = encodeCborMap([
      ["fmt", encodeCborText("none")],
      ["attStmt", encodeCborMap([])],
      ["authData", encodeCborBytes(authData)]
    ]);

    const clientDataJSON = Buffer.from(
      JSON.stringify({
        type: overrides.type ?? "webauthn.create",
        challenge,
        origin,
        crossOrigin: false
      }),
      "utf8"
    );

    return {
      id: credIdB64,
      rawId: credIdB64,
      type: "public-key",
      authenticatorAttachment: overrides.authenticatorAttachment ?? "platform",
      clientExtensionResults: {},
      response: {
        clientDataJSON: toBase64Url(clientDataJSON),
        attestationObject: toBase64Url(attestationObject),
        transports: overrides.transports ?? ["internal"]
      }
    };
  }

  createAuthenticationResponse(requestOptions, overrides = {}) {
    const allowed = requestOptions.allowCredentials;
    let cred = null;
    if (overrides.credentialIdBase64Url !== undefined) {
      cred = this.credentials.get(overrides.credentialIdBase64Url) ?? null;
    } else if (Array.isArray(allowed) && allowed.length > 0) {
      for (const item of allowed) {
        const found = this.credentials.get(item.id);
        if (found) {
          cred = found;
          break;
        }
      }
    } else {
      const first = this.credentials.values().next();
      if (!first.done) {
        cred = first.value;
      }
    }
    if (!cred) {
      throw new Error("No matching credential in virtual authenticator");
    }

    const rpId = overrides.rpId ?? requestOptions.rpId ?? cred.rpId;
    const origin = overrides.origin ?? "http://localhost:5205";
    const challenge = overrides.challenge ?? requestOptions.challenge;
    const uv = overrides.userVerified !== false;
    const up = overrides.userPresent !== false;
    const backupEligible = overrides.backupEligible ?? cred.backupEligible;
    const backedUp = overrides.backedUp ?? cred.backedUp;

    let nextCounter;
    if (overrides.counter !== undefined) {
      nextCounter = overrides.counter;
    } else if (cred.counter > 0 || overrides.incrementCounter === true) {
      cred.counter += 1;
      nextCounter = cred.counter;
    } else {
      nextCounter = 0;
    }

    const rpIdHash = crypto.createHash("sha256").update(rpId, "utf8").digest();
    const flagsByte =
      (up ? 0x01 : 0) |
      (uv ? 0x04 : 0) |
      (backupEligible ? 0x08 : 0) |
      (backedUp ? 0x10 : 0);

    const signCountBuf = Buffer.allocUnsafe(4);
    signCountBuf.writeUInt32BE(nextCounter, 0);

    const authData = Buffer.concat([rpIdHash, Buffer.from([flagsByte]), signCountBuf]);

    const clientDataJSON = Buffer.from(
      JSON.stringify({
        type: overrides.type ?? "webauthn.get",
        challenge,
        origin,
        crossOrigin: false
      }),
      "utf8"
    );
    const clientDataHash = crypto.createHash("sha256").update(clientDataJSON).digest();
    const signatureBase = Buffer.concat([authData, clientDataHash]);

    let signature =
      cred.algorithm === "EdDSA"
        ? crypto.sign(null, signatureBase, cred.privateKey)
        : crypto.sign("sha256", signatureBase, cred.privateKey);

    if (overrides.tamperSignature) {
      signature = Buffer.from(signature);
      signature[signature.length - 1] ^= 0xff;
    }

    const credIdB64 = toBase64Url(cred.credentialId);
    const userHandle =
      overrides.omitUserHandle === true
        ? undefined
        : overrides.userHandle !== undefined
          ? toBase64Url(overrides.userHandle)
          : toBase64Url(cred.userHandle);

    return {
      id: credIdB64,
      rawId: credIdB64,
      type: "public-key",
      authenticatorAttachment: "platform",
      clientExtensionResults: {},
      response: {
        clientDataJSON: toBase64Url(clientDataJSON),
        authenticatorData: toBase64Url(authData),
        signature: toBase64Url(signature),
        ...(userHandle !== undefined ? { userHandle } : {})
      }
    };
  }
}
