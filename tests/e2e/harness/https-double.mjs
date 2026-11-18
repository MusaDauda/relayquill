import crypto from 'node:crypto';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';

function derLen(length) {
  if (length < 0x80) {
    return Buffer.from([length]);
  }
  const bytes = [];
  let rem = length;
  while (rem > 0) {
    bytes.unshift(rem & 0xff);
    rem >>= 8;
  }
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}

function derTag(tag, content) {
  const buf = Buffer.isBuffer(content) ? content : Buffer.from(content);
  return Buffer.concat([Buffer.from([tag]), derLen(buf.length), buf]);
}

function derSeq(...items) {
  return derTag(0x30, Buffer.concat(items));
}

function derSet(...items) {
  return derTag(0x31, Buffer.concat(items));
}

function derInt(value) {
  let buf;
  if (Buffer.isBuffer(value)) {
    buf = value;
  } else {
    const rawHex = value.toString(16);
    const hex = rawHex.length % 2 === 1 ? `0${rawHex}` : rawHex;
    buf = Buffer.from(hex, 'hex');
  }
  if (buf.length === 0) {
    buf = Buffer.from([0]);
  }
  if (buf[0] & 0x80) {
    buf = Buffer.concat([Buffer.from([0x00]), buf]);
  }
  return derTag(0x02, buf);
}

function derOid(dotted) {
  const parts = dotted.split('.').map(Number);
  const out = [parts[0] * 40 + parts[1]];
  for (let i = 2; i < parts.length; i += 1) {
    let val = parts[i];
    const encoded = [val & 0x7f];
    val >>= 7;
    while (val > 0) {
      encoded.unshift((val & 0x7f) | 0x80);
      val >>= 7;
    }
    out.push(...encoded);
  }
  return derTag(0x06, Buffer.from(out));
}

function derOctet(buf) {
  return derTag(0x04, buf);
}

function derBitString(buf, unusedBits = 0) {
  return derTag(0x03, Buffer.concat([Buffer.from([unusedBits]), buf]));
}

function derUtf8(str) {
  return derTag(0x0c, Buffer.from(str, 'utf8'));
}

function derUtcTime(date) {
  const pad = (n) => String(n).padStart(2, '0');
  const yy = pad(date.getUTCFullYear() % 100);
  const mm = pad(date.getUTCMonth() + 1);
  const dd = pad(date.getUTCDate());
  const hh = pad(date.getUTCHours());
  const mi = pad(date.getUTCMinutes());
  const ss = pad(date.getUTCSeconds());
  return derTag(0x17, Buffer.from(`${yy}${mm}${dd}${hh}${mi}${ss}Z`, 'ascii'));
}

function derExplicit(tagNum, inner) {
  return derTag(0xa0 | tagNum, inner);
}

function ipv4ToBytes(ip) {
  return Buffer.from(ip.split('.').map((octet) => Number(octet)));
}

function ipv6ToBytes(ip) {
  const clean = ip.split('%')[0];
  const [leftRaw, rightRaw] = clean.split('::');
  const parsePart = (part) => {
    if (!part) {
      return [];
    }
    const groups = [];
    for (const token of part.split(':')) {
      if (token.includes('.')) {
        const v4 = ipv4ToBytes(token);
        groups.push((v4[0] << 8) | v4[1], (v4[2] << 8) | v4[3]);
      } else {
        groups.push(Number.parseInt(token, 16));
      }
    }
    return groups;
  };

  const left = parsePart(leftRaw);
  const right = rightRaw !== undefined ? parsePart(rightRaw) : [];
  const missing = 8 - left.length - right.length;
  const full = rightRaw !== undefined
    ? [...left, ...new Array(Math.max(0, missing)).fill(0), ...right]
    : left;

  const out = Buffer.alloc(16);
  for (let i = 0; i < 8; i += 1) {
    out.writeUInt16BE(full[i] ?? 0, i * 2);
  }
  return out;
}

function toPem(der, label) {
  const b64 = der.toString('base64');
  const wrapped = b64.match(/.{1,64}/g)?.join('\n') ?? b64;
  return `-----BEGIN ${label}-----\n${wrapped}\n-----END ${label}-----\n`;
}

export function generateSelfSignedCert(options = {}) {
  const commonName = options.commonName ?? 'localhost';
  const dnsNames = options.dnsNames ?? ['localhost', 'receiver.fixture.test'];
  const ipAddresses = options.ipAddresses ?? ['127.0.0.1', '::1'];
  const validityDays = options.validityDays ?? 7;

  const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', {
    namedCurve: 'prime256v1'
  });

  const spkiDer = publicKey.export({ type: 'spki', format: 'der' });
  const serial = crypto.randomBytes(12);
  serial[0] &= 0x7f;
  if (serial[0] === 0) {
    serial[0] = 1;
  }

  const now = new Date();
  const notBefore = new Date(now.getTime() - 60_000);
  const notAfter = new Date(now.getTime() + validityDays * 86_400_000);

  const nameSeq = derSeq(derSet(derSeq(derOid('2.5.4.3'), derUtf8(commonName))));
  const sigAlg = derSeq(derOid('1.2.840.10045.4.3.2')); // ecdsa-with-SHA256

  const sanEntries = [];
  for (const dns of dnsNames) {
    sanEntries.push(derTag(0x82, Buffer.from(dns, 'ascii')));
  }
  for (const ip of ipAddresses) {
    if (net.isIPv4(ip)) {
      sanEntries.push(derTag(0x87, ipv4ToBytes(ip)));
    } else if (net.isIPv6(ip)) {
      sanEntries.push(derTag(0x87, ipv6ToBytes(ip)));
    } else {
      throw new Error(`Invalid IP SAN entry: ${ip}`);
    }
  }

  const extBasicConstraints = derSeq(
    derOid('2.5.29.19'),
    Buffer.from([0x01, 0x01, 0xff]), // critical = TRUE
    derOctet(derSeq(Buffer.from([0x01, 0x01, 0xff]))) // cA = TRUE
  );
  const extKeyUsage = derSeq(
    derOid('2.5.29.15'),
    Buffer.from([0x01, 0x01, 0xff]),
    derOctet(derBitString(Buffer.from([0x84]), 2)) // digitalSignature + keyCertSign
  );
  const extExtKeyUsage = derSeq(
    derOid('2.5.29.37'),
    derOctet(derSeq(derOid('1.3.6.1.5.5.7.3.1'))) // id-kp-serverAuth
  );
  const extSan = derSeq(
    derOid('2.5.29.17'),
    derOctet(derSeq(...sanEntries))
  );

  const extensions = derExplicit(
    3,
    derSeq(extBasicConstraints, extKeyUsage, extExtKeyUsage, extSan)
  );

  const tbsCert = derSeq(
    derExplicit(0, derInt(2)), // v3
    derInt(serial),
    sigAlg,
    nameSeq,
    derSeq(derUtcTime(notBefore), derUtcTime(notAfter)),
    nameSeq,
    spkiDer,
    extensions
  );

  const signature = crypto.sign('sha256', tbsCert, privateKey);
  const certDer = derSeq(tbsCert, sigAlg, derBitString(signature, 0));

  const certPem = toPem(certDer, 'CERTIFICATE');
  const keyPem = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();

  return { certPem, keyPem, publicKey };
}

export const SSRF_TEST_VECTORS = Object.freeze({
  loopbackV4: '127.0.0.1',
  loopbackV6: '::1',
  unspecifiedV4: '0.0.0.0',
  rfc1918_10: '10.0.0.1',
  rfc1918_172: '172.16.0.1',
  rfc1918_192: '192.168.1.1',
  cgnat: '100.64.0.1',
  awsMetadata: '169.254.169.254',
  azureMetadata: '168.63.129.16',
  ipv4MappedV6: '::ffff:127.0.0.1',
  ipv4MappedMetadata: '::ffff:169.254.169.254',
  nat64: '64:ff9b::169.254.169.254',
  ulaV6: 'fc00::1',
  linkLocalV6: 'fe80::1',
  multicastV4: '224.0.0.1',
  publicExample: '93.184.216.34',
  cnameDepthExceeded: Array.from({ length: 9 }, (_, i) => `hop${i + 1}.cname.fixture.test`),
  excessiveAddressRecords: Array.from({ length: 17 }, (_, i) => ({
    address: `93.184.216.${10 + i}`,
    family: 4,
    ttl: 60
  })),
  ttlZeroRecord: { address: '93.184.216.34', family: 4, ttl: 0 },
  mixedAllowedAndDenied: [
    { address: '93.184.216.34', family: 4, ttl: 60 },
    { address: '10.0.0.5', family: 4, ttl: 60 }
  ]
});

export function createDnsLookupMock(recordsMap = {}) {
  const calls = [];

  function lookup(hostname, optionsOrCb, maybeCb) {
    const cb = typeof optionsOrCb === 'function' ? optionsOrCb : maybeCb;
    const opts = typeof optionsOrCb === 'function' ? {} : (optionsOrCb ?? {});
    calls.push({ hostname, options: opts, timestamp: Date.now() });

    const entry = recordsMap[hostname];
    if (!entry) {
      const err = new Error(`getaddrinfo ENOTFOUND ${hostname}`);
      err.code = 'ENOTFOUND';
      err.hostname = hostname;
      queueMicrotask(() => cb(err));
      return;
    }

    const recordsRaw = Array.isArray(entry) ? entry : (entry.records ?? []);
    const records = recordsRaw.map((rec) => ({
      address: rec.address,
      family: rec.family ?? (net.isIPv6(rec.address) ? 6 : 4),
      ttl: rec.ttl ?? 60
    }));

    const deliver = () => {
      if (entry.cnameChain && entry.cnameChain.length > 8) {
        const err = new Error(`CNAME chain depth exceeded (${entry.cnameChain.length}) for ${hostname}`);
        err.code = 'ECNAME_DEPTH';
        err.cnameChain = entry.cnameChain;
        cb(err);
        return;
      }
      if (records.length === 0) {
        const err = new Error(`getaddrinfo ENODATA ${hostname}`);
        err.code = 'ENODATA';
        cb(err);
        return;
      }
      if (opts.all === true) {
        cb(null, records.map(({ address, family }) => ({ address, family })));
        return;
      }
      cb(null, records[0].address, records[0].family);
    };

    if (entry.delayMs && entry.delayMs > 0) {
      setTimeout(deliver, entry.delayMs);
    } else {
      queueMicrotask(deliver);
    }
  }

  lookup.calls = calls;
  lookup.getRecords = (hostname) => recordsMap[hostname];
  return lookup;
}

export async function createHttpTestDouble(options = {}) {
  const protocol = options.protocol ?? 'https';
  const tlsConfig = options.sanMismatch
    ? {
      commonName: 'wrong-san.fixture.test',
      dnsNames: ['wrong-san.fixture.test'],
      ipAddresses: []
    }
    : (options.tls ?? {});

  const generatedCert = protocol === 'https'
    ? (options.cert ?? generateSelfSignedCert(tlsConfig))
    : null;

  const behavior = {
    status: options.status ?? 200,
    headers: { 'content-type': 'application/json', ...(options.headers ?? {}) },
    body: options.body ?? JSON.stringify({ ok: true }),
    redirectTo: options.redirectTo ?? null,
    redirectStatus: options.redirectStatus ?? 302,
    delayMs: options.delayMs ?? 0,
    hang: options.hang ?? false,
    partialBody: options.partialBody ?? null,
    onRequest: options.onRequest ?? null
  };

  const requests = [];
  const sockets = new Set();
  const timers = new Set();

  const requestHandler = (req, res) => {
    const chunks = [];
    req.on('data', (chunk) => chunks.push(chunk));
    req.on('end', async () => {
      const rawBody = Buffer.concat(chunks);
      requests.push({
        method: req.method,
        url: req.url,
        headers: { ...req.headers },
        rawBody,
        bodyText: rawBody.toString('utf8'),
        receivedAt: new Date().toISOString()
      });

      if (behavior.hang) {
        return;
      }

      const sendResponse = async () => {
        if (res.destroyed || req.socket.destroyed) {
          return;
        }
        if (typeof behavior.onRequest === 'function') {
          const handled = await behavior.onRequest(req, rawBody, res);
          if (handled === true || res.writableEnded) {
            return;
          }
        }
        if (behavior.redirectTo) {
          res.writeHead(behavior.redirectStatus, {
            Location: behavior.redirectTo,
            'Content-Length': '0'
          });
          res.end();
          return;
        }
        if (behavior.partialBody) {
          const declaredLen = behavior.partialBody.declaredLength ?? 1024;
          const partialChunk = behavior.partialBody.chunk ?? '{"partial":true';
          res.writeHead(behavior.status, {
            ...behavior.headers,
            'Content-Length': String(declaredLen)
          });
          res.write(partialChunk);
          req.socket.destroy();
          return;
        }
        const bodyBuf = Buffer.isBuffer(behavior.body)
          ? behavior.body
          : Buffer.from(String(behavior.body), 'utf8');
        res.writeHead(behavior.status, {
          ...behavior.headers,
          'Content-Length': String(bodyBuf.length)
        });
        res.end(bodyBuf);
      };

      if (behavior.delayMs > 0) {
        const timer = setTimeout(() => {
          timers.delete(timer);
          void sendResponse();
        }, behavior.delayMs);
        timers.add(timer);
      } else {
        await sendResponse();
      }
    });
  };

  const server = protocol === 'https'
    ? https.createServer({ key: generatedCert.keyPem, cert: generatedCert.certPem }, requestHandler)
    : http.createServer(requestHandler);

  server.on('connection', (socket) => {
    sockets.add(socket);
    socket.on('close', () => sockets.delete(socket));
  });

  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });

  const addr = server.address();
  const port = typeof addr === 'object' && addr ? addr.port : 0;
  const origin = `${protocol}://127.0.0.1:${port}`;
  const localhostOrigin = `${protocol}://localhost:${port}`;

  return {
    protocol,
    port,
    origin,
    localhostOrigin,
    certPem: generatedCert?.certPem ?? null,
    keyPem: generatedCert?.keyPem ?? null,
    requests,
    clearRequests() {
      requests.length = 0;
    },
    setBehavior(next = {}) {
      Object.assign(behavior, next);
    },
    async cleanup() {
      for (const timer of timers) {
        clearTimeout(timer);
      }
      timers.clear();
      for (const socket of sockets) {
        socket.destroy();
      }
      sockets.clear();
      await new Promise((resolve) => {
        server.close(() => resolve());
      });
    }
  };
}

function canonicalString(fields, orderedKeys) {
  return orderedKeys.map((k) => `${k}=${String(fields[k] ?? '')}`).join('\n');
}

const RECEIPT_KEYS = [
  'schema',
  'delivery_id',
  'event_id',
  'endpoint_id',
  'attempt_id',
  'receiver_commit_seq',
  'committed_at',
  'payload_sha256'
];

export function signReceiverLocalCommitReceipt(fields, secret) {
  const payload = {
    schema: fields.schema ?? 'rq.receiver-receipt.v1',
    delivery_id: fields.delivery_id,
    event_id: fields.event_id,
    endpoint_id: fields.endpoint_id,
    attempt_id: fields.attempt_id,
    receiver_commit_seq: String(fields.receiver_commit_seq),
    committed_at: fields.committed_at,
    payload_sha256: fields.payload_sha256
  };
  const message = `receiver_local_commit_v1\n${canonicalString(payload, RECEIPT_KEYS)}`;
  const mac = crypto.createHmac('sha256', secret).update(message, 'utf8').digest('hex');
  return { ...payload, mac };
}

export function verifyReceiverLocalCommitReceipt(receipt, secret) {
  if (!receipt || typeof receipt.mac !== 'string') {
    return false;
  }
  const expected = signReceiverLocalCommitReceipt(receipt, secret).mac;
  const a = Buffer.from(receipt.mac, 'hex');
  const b = Buffer.from(expected, 'hex');
  if (a.length !== b.length || a.length === 0) {
    return false;
  }
  return crypto.timingSafeEqual(a, b);
}

const PROOF_KEYS = ['schema', 'endpoint_id', 'challenge', 'issued_at'];

export function signEndpointProof(fields, secret) {
  const payload = {
    schema: fields.schema ?? 'rq.endpoint-proof.v1',
    endpoint_id: fields.endpoint_id,
    challenge: fields.challenge,
    issued_at: fields.issued_at
  };
  const message = `endpoint-proof-v1\n${canonicalString(payload, PROOF_KEYS)}`;
  const mac = crypto.createHmac('sha256', secret).update(message, 'utf8').digest('hex');
  return { ...payload, mac };
}

export function verifyEndpointProof(proof, secret) {
  if (!proof || typeof proof.mac !== 'string') {
    return false;
  }
  const expected = signEndpointProof(proof, secret).mac;
  const a = Buffer.from(proof.mac, 'hex');
  const b = Buffer.from(expected, 'hex');
  if (a.length !== b.length || a.length === 0) {
    return false;
  }
  return crypto.timingSafeEqual(a, b);
}
