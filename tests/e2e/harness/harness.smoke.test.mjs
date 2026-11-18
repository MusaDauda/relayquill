import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import https from 'node:https';
import net from 'node:net';
import path from 'node:path';
import { describe, it } from 'node:test';

import {
  BrokerLimitError,
  InMemoryJetStreamBroker,
  PubAckTimeoutError,
  launchEmbeddedGoBroker
} from './broker-harness.mjs';
import {
  SSRF_TEST_VECTORS,
  createDnsLookupMock,
  createHttpTestDouble,
  generateSelfSignedCert,
  signEndpointProof,
  signReceiverLocalCommitReceipt,
  verifyEndpointProof,
  verifyReceiverLocalCommitReceipt
} from './https-double.mjs';
import {
  MAX_IPC_FRAME_BYTES,
  getIpcEndpoint,
  hardenWindowsPipeForTest,
  probeIpcEndpoint,
  sendIpcFrame
} from './ipc-probe.mjs';
import { createPgHarness } from './pg-pglite.mjs';
import { createE2EStack } from './stack.mjs';

describe('E2E Harness Smoke Suite', () => {
  it('pg-pglite: separate_databases, shared_database_schemas, btree_gist 23P01, exact OIDs, barrier & retry', async () => {
    const sep = await createPgHarness({ mode: 'separate_databases' });
    try {
      await sep.dbs.rq.exec(`
        CREATE TABLE items (
          id bigserial PRIMARY KEY,
          big_id int8 NOT NULL,
          big_arr int8[] NOT NULL,
          ts_utc timestamptz NOT NULL,
          ts_plain timestamp NOT NULL
        );
      `);
      await sep.dbs.rc.exec('CREATE TABLE rc_only (id int PRIMARY KEY);');

      // Verify isolation between rq and rc databases.
      await assert.rejects(
        () => sep.dbs.rc.query('SELECT * FROM items'),
        (err) => err?.code === '42P01'
      );

      await sep.dbs.rq.query(
        'INSERT INTO items (big_id, big_arr, ts_utc, ts_plain) VALUES ($1, $2, $3, $4)',
        [
          '9223372036854775807',
          ['9007199254740993', '-9223372036854775808'],
          '2026-11-18T05:00:00.123456Z',
          '2026-11-18 05:00:00.123456'
        ]
      );

      const res = await sep.dbs.rq.query('SELECT big_id, big_arr, ts_utc, ts_plain FROM items');
      const row = res.rows[0];
      assert.equal(typeof row.big_id, 'string');
      assert.equal(row.big_id, '9223372036854775807');
      assert.deepEqual(row.big_arr, ['9007199254740993', '-9223372036854775808']);
      assert.equal(typeof row.ts_utc, 'string');
      assert.match(row.ts_utc, /2026-11-18 05:00:00\.123456/);
      assert.equal(typeof row.ts_plain, 'string');
      assert.equal(row.ts_plain, '2026-11-18 05:00:00.123456');

      // Verify btree_gist EXCLUDE USING gist enforces 23P01.
      await sep.dbs.rq.exec(`
        CREATE TABLE lease_windows (
          scope text NOT NULL,
          win tstzrange NOT NULL,
          EXCLUDE USING gist (scope WITH =, win WITH &&)
        );
      `);
      await sep.dbs.rq.query(
        `INSERT INTO lease_windows (scope, win) VALUES ('p1', '[2026-11-18T05:00:00Z, 2026-11-18T05:10:00Z)')`
      );
      await assert.rejects(
        () => sep.dbs.rq.query(
          `INSERT INTO lease_windows (scope, win) VALUES ('p1', '[2026-11-18T05:05:00Z, 2026-11-18T05:15:00Z)')`
        ),
        (err) => err?.code === '23P01'
      );

      // Verify deterministic barrier + contention SQLSTATE retries.
      const barrier = sep.createBarrier(2);
      const order = [];
      await Promise.all([
        (async () => {
          order.push('a1');
          await barrier.arrive();
          order.push('a2');
        })(),
        (async () => {
          order.push('b1');
          await barrier.arrive();
          order.push('b2');
        })()
      ]);
      assert.equal(barrier.count, 2);
      assert.deepEqual(new Set(order.slice(0, 2)), new Set(['a1', 'b1']));
      assert.deepEqual(new Set(order.slice(2, 4)), new Set(['a2', 'b2']));

      const injector = sep.createContentionFaultInjector([
        { sqlState: '55P03' },
        { sqlState: '40P01' },
        { sqlState: '40001' }
      ]);
      const retries = [];
      const value = await sep.dbs.rq.withTransaction(
        async (tx) => {
          injector.maybeFail();
          const q = await tx.query('SELECT 42 AS answer');
          return q.rows[0].answer;
        },
        {
          retryOnContention: true,
          baseDelayMs: 2,
          maxDelayMs: 5,
          random: () => 0.5,
          onRetry: (info) => retries.push(info)
        }
      );
      assert.equal(value, 42);
      assert.equal(injector.injectedCount, 3);
      assert.deepEqual(retries.map((r) => r.code), ['55P03', '40P01', '40001']);
    } finally {
      await sep.cleanup();
    }

    // Verify shared_database_schemas mode.
    const shared = await createPgHarness({ mode: 'shared_database_schemas' });
    try {
      await shared.dbs.rq.exec('CREATE TABLE shared_tbl (v text);');
      await shared.dbs.rc.exec('CREATE TABLE shared_tbl (v text);');
      await shared.dbs.rq.query('INSERT INTO shared_tbl (v) VALUES ($1)', ['from-rq']);
      await shared.dbs.rc.query('INSERT INTO shared_tbl (v) VALUES ($1)', ['from-rc']);

      const rqRows = await shared.dbs.rq.query('SELECT v FROM shared_tbl');
      const rcRows = await shared.dbs.rc.query('SELECT v FROM shared_tbl');
      assert.deepEqual(rqRows.rows, [{ v: 'from-rq' }]);
      assert.deepEqual(rcRows.rows, [{ v: 'from-rc' }]);
    } finally {
      await shared.cleanup();
    }

    // Verify live PG separate_databases mode rejects missing per-authority pgUrls.
    await assert.rejects(
      () => createPgHarness({ pgUrl: 'postgres://127.0.0.1:5432/relayquill_test', mode: 'separate_databases' }),
      /pgUrls/i
    );

    // Verify optional live PG URL fails clearly when pg package is absent.
    await assert.rejects(
      () => createPgHarness({ pgUrl: 'postgres://127.0.0.1:5432/relayquill_test' }),
      /pg/i
    );
  });

  it('broker-harness: InMemoryJetStreamBroker limits, dedup, pull ack/nak/working/term & fault hooks', async () => {
    let clockMs = 1_000_000;
    const broker = new InMemoryJetStreamBroker({ nowMs: () => clockMs });

    try {
      broker.ensureStream('RQ_DELIVERIES', {
        policy: 'limits',
        discard: 'new',
        subjects: ['rq.deliveries.>'],
        maxMsgs: 3,
        maxBytes: 128,
        duplicateWindowMs: 120_000
      });
      broker.ensureConsumer('RQ_DELIVERIES', {
        durableName: 'sender_worker',
        ackWaitMs: 5_000,
        maxDeliver: 2,
        maxAckPending: 2
      });

      const ack1 = await broker.publish('rq.deliveries.p1', '{"id":1}', { msgId: 'msg-1' });
      assert.deepEqual(ack1, { stream: 'RQ_DELIVERIES', seq: 1, duplicate: false });

      // Duplicate Nats-Msg-Id inside 2m window returns duplicate: true with original seq.
      const dup1 = await broker.publish('rq.deliveries.p1', '{"id":1}', { msgId: 'msg-1' });
      assert.deepEqual(dup1, { stream: 'RQ_DELIVERIES', seq: 1, duplicate: true });

      // Fault hook: dropNextPubAckAfterStore stores message, throws PUBACK_LOST, retry dedups!
      broker.dropNextPubAckAfterStore();
      await assert.rejects(
        () => broker.publish('rq.deliveries.p1', '{"id":2}', { msgId: 'msg-2' }),
        (err) => err instanceof PubAckTimeoutError && err.code === 'PUBACK_LOST'
      );
      const retryAck2 = await broker.publish('rq.deliveries.p1', '{"id":2}', { msgId: 'msg-2' });
      assert.deepEqual(retryAck2, { stream: 'RQ_DELIVERIES', seq: 2, duplicate: true });

      // Fault hook: forceStreamFull rejects new publish with BrokerLimitError.
      broker.forceStreamFull(true);
      await assert.rejects(
        () => broker.publish('rq.deliveries.p1', '{"id":3}', { msgId: 'msg-3' }),
        (err) => err instanceof BrokerLimitError
      );
      broker.forceStreamFull(false);

      const ack3 = await broker.publish('rq.deliveries.p1', '{"id":3}', { msgId: 'msg-3' });
      assert.equal(ack3.seq, 3);

      // maxMsgs = 3 reached -> DiscardNew rejects 4th message.
      await assert.rejects(
        () => broker.publish('rq.deliveries.p1', '{"id":4}', { msgId: 'msg-4' }),
        (err) => err instanceof BrokerLimitError
      );

      // Pull consumer MaxAckPending = 2 limits first batch to 2 messages.
      const batch1 = broker.pullBatch({
        stream: 'RQ_DELIVERIES',
        consumer: 'sender_worker',
        maxBatch: 5
      });
      assert.equal(batch1.length, 2);
      assert.equal(batch1[0].seq, 1);
      assert.equal(batch1[1].seq, 2);

      // Fault hook: dropNextAck leaves seq 1 pending until AckWait expires.
      // Advance clock 3s, call working() on seq 2, then advance 3s more (total 6s > 5s AckWait).
      // seq 1 expires and is redelivered; seq 2 stays in-flight because working() extended its AckWait.
      broker.dropNextAck();
      await batch1[0].ack();
      clockMs += 3_000;
      await batch1[1].working();
      clockMs += 3_000;

      const batch2 = broker.pullBatch({
        stream: 'RQ_DELIVERIES',
        consumer: 'sender_worker',
        maxBatch: 5
      });
      assert.equal(batch2.length, 1);
      assert.equal(batch2[0].seq, 1);
      assert.equal(batch2[0].redelivered, true);
      assert.equal(batch2[0].deliveryCount, 2);

      // Superseded delivery-1 handle on seq 1 must be a safe no-op.
      await batch1[0].nak();
      await batch1[0].term();
      assert.equal(broker.getConsumerStats('RQ_DELIVERIES', 'sender_worker').terminated, 0);

      await batch2[0].ack();
      await batch1[1].nak(100);

      clockMs += 150;
      const batch3 = [];
      for await (const msg of broker.consume({
        stream: 'RQ_DELIVERIES',
        consumer: 'sender_worker',
        maxBatch: 5
      })) {
        batch3.push(msg);
      }
      assert.deepEqual(batch3.map((m) => m.seq), [2, 3]);
      for (const msg of batch3) {
        await msg.term();
      }

      // expireMessages prunes stream entries.
      const expired = broker.expireMessages(0);
      assert.equal(expired, 3);
      assert.equal(broker.getStreamStats('RQ_DELIVERIES').messages, 0);

      // Embedded Go launcher check does not crash when tools/broker-launcher is absent.
      const goStatus = await launchEmbeddedGoBroker();
      assert.equal(goStatus.available, false);
      await goStatus.cleanup();
    } finally {
      await broker.cleanup();
    }
  });

  it('https-double: pure-JS X.509 SANs, TLS/mismatch, redirect, partial-body, DNS mock & receipts', async () => {
    const certBundle = generateSelfSignedCert({
      commonName: 'receiver.fixture.test',
      dnsNames: ['receiver.fixture.test', 'localhost'],
      ipAddresses: ['127.0.0.1', '::1']
    });
    const x509 = new crypto.X509Certificate(certBundle.certPem);
    assert.equal(x509.verify(certBundle.publicKey), true);
    assert.equal(x509.checkHost('receiver.fixture.test'), 'receiver.fixture.test');
    assert.equal(x509.checkIP('127.0.0.1'), '127.0.0.1');
    assert.equal(x509.checkIP('::1'), '::1');
    assert.equal(x509.checkHost('evil.example.test'), undefined);

    const server = await createHttpTestDouble({ cert: certBundle });
    const badSanServer = await createHttpTestDouble({ sanMismatch: true });

    try {
      const dnsLookup = createDnsLookupMock({
        'receiver.fixture.test': [{ address: '127.0.0.1', family: 4, ttl: 60 }],
        'cname-loop.fixture.test': {
          cnameChain: SSRF_TEST_VECTORS.cnameDepthExceeded,
          records: [{ address: SSRF_TEST_VECTORS.publicExample, family: 4 }]
        }
      });

      const agent = new https.Agent({ ca: server.certPem, lookup: dnsLookup });
      try {
        const okRes = await new Promise((resolve, reject) => {
          const req = https.request(
            `https://receiver.fixture.test:${server.port}/webhook`,
            { method: 'POST', agent, headers: { 'content-type': 'application/json' } },
            (res) => {
              const chunks = [];
              res.on('data', (c) => chunks.push(c));
              res.on('end', () => resolve({ status: res.statusCode, body: Buffer.concat(chunks).toString('utf8') }));
            }
          );
          req.on('error', reject);
          req.end('{"hello":"world"}');
        });
        assert.equal(okRes.status, 200);
        assert.equal(JSON.parse(okRes.body).ok, true);
        assert.equal(server.requests.length, 1);
        assert.equal(dnsLookup.calls[0].options.all, true);
      } finally {
        agent.destroy();
      }

      // Untrusted self-signed cert rejected by default fetch.
      await assert.rejects(() => fetch(`${server.origin}/webhook`));

      // SAN mismatch rejected even when CA matches.
      const mismatchAgent = new https.Agent({ ca: badSanServer.certPem });
      try {
        await assert.rejects(
          () => new Promise((resolve, reject) => {
            const req = https.request(
              `https://127.0.0.1:${badSanServer.port}/webhook`,
              { agent: mismatchAgent },
              resolve
            );
            req.on('error', reject);
            req.end();
          }),
          (err) => err?.code === 'ERR_TLS_CERT_ALTNAME_INVALID'
        );
      } finally {
        mismatchAgent.destroy();
      }

      // 3xx redirect trap.
      server.setBehavior({ redirectTo: 'http://169.254.169.254/latest/meta-data/' });
      const redirAgent = new https.Agent({ ca: server.certPem });
      try {
        const redirRes = await new Promise((resolve, reject) => {
          const req = https.request(
            `${server.origin}/redirect`,
            { agent: redirAgent },
            (res) => resolve({ status: res.statusCode, location: res.headers.location })
          );
          req.on('error', reject);
          req.end();
        });
        assert.equal(redirRes.status, 302);
        assert.equal(redirRes.location, 'http://169.254.169.254/latest/meta-data/');
      } finally {
        redirAgent.destroy();
      }

      // Partial-body truncation fault mode.
      server.setBehavior({
        redirectTo: null,
        partialBody: { declaredLength: 4096, chunk: '{"truncated":' }
      });
      const truncAgent = new https.Agent({ ca: server.certPem });
      try {
        await assert.rejects(
          () => new Promise((resolve, reject) => {
            const req = https.request(`${server.origin}/partial`, { agent: truncAgent }, (res) => {
              res.on('data', () => {});
              res.on('error', reject);
              res.on('aborted', () => reject(new Error('RESPONSE_ABORTED')));
              res.on('end', () => resolve('ended'));
            });
            req.on('error', reject);
            req.end();
          })
        );
      } finally {
        truncAgent.destroy();
      }

      // Receipt and endpoint proof signing/verification.
      const receipt = signReceiverLocalCommitReceipt(
        {
          delivery_id: 'del-1',
          event_id: 'evt-1',
          endpoint_id: 'ep-1',
          attempt_id: 'att-1',
          receiver_commit_seq: '1',
          committed_at: '2026-11-18T05:00:00.000000Z',
          payload_sha256: 'abc123'
        },
        'receipt-signing-test-material'
      );
      assert.equal(verifyReceiverLocalCommitReceipt(receipt, 'receipt-signing-test-material'), true);
      assert.equal(
        verifyReceiverLocalCommitReceipt({ ...receipt, receiver_commit_seq: '2' }, 'receipt-signing-test-material'),
        false
      );

      const proof = signEndpointProof(
        {
          endpoint_id: 'ep-1',
          challenge: 'chal-1',
          issued_at: '2026-11-18T05:00:00.000000Z'
        },
        'endpoint-proof-test-material'
      );
      assert.equal(verifyEndpointProof(proof, 'endpoint-proof-test-material'), true);
      assert.equal(verifyEndpointProof({ ...proof, challenge: 'chal-2' }, 'endpoint-proof-test-material'), false);
    } finally {
      await server.cleanup();
      await badSanServer.cleanup();
    }
  });

  it('ipc-probe: verifies unhardened rejection, hardened pipe DACL/UDS, frame roundtrip & size cap', async () => {
    const envName = `smoke-${process.pid}-${Date.now()}`;
    const endpoint = getIpcEndpoint(envName, 'control');

    if (process.platform !== 'win32') {
      fs.mkdirSync(path.dirname(endpoint), { recursive: true, mode: 0o700 });
    }

    const sockets = new Set();
    const server = net.createServer((socket) => {
      sockets.add(socket);
      socket.on('close', () => sockets.delete(socket));
      let buf = '';
      socket.on('data', (chunk) => {
        buf += chunk.toString('utf8');
        const idx = buf.indexOf('\n');
        if (idx !== -1) {
          const line = buf.slice(0, idx);
          const parsed = JSON.parse(line);
          socket.write(`${JSON.stringify({ ok: true, echo: parsed.ping })}\n`);
        }
      });
    });

    await new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen(endpoint, resolve);
    });

    try {
      if (process.platform === 'win32') {
        const unhardened = await probeIpcEndpoint(endpoint);
        assert.equal(unhardened.ok, false, 'Default node:net named pipe must fail DACL check');
        assert.ok(unhardened.violations.length > 0);

        await hardenWindowsPipeForTest(endpoint);
        const hardened = await probeIpcEndpoint(endpoint);
        assert.equal(
          hardened.ok,
          true,
          `Hardened pipe failed inspection: ${hardened.violations.join('; ')} (SDDL=${hardened.sddl})`
        );
        assert.equal(hardened.daclProtected, true);
        assert.equal(hardened.ownerSid, hardened.currentUserSid);

        // Execute >= 6 consecutive Win32 pipe inspections without artificial delays
        // to prove async spawn allows libuv to recycle CreateNamedPipeW handles.
        for (let i = 0; i < 6; i += 1) {
          const consecutive = await probeIpcEndpoint(endpoint);
          assert.equal(consecutive.ok, true, `Consecutive pipe probe #${i + 1} failed`);
        }
      } else {
        fs.chmodSync(endpoint, 0o644);
        assert.equal((await probeIpcEndpoint(endpoint)).ok, false);
        fs.chmodSync(endpoint, 0o600);
        assert.equal((await probeIpcEndpoint(endpoint)).ok, true);
      }

      const reply = await sendIpcFrame(endpoint, { ping: 'pong' });
      assert.deepEqual(reply, { ok: true, echo: 'pong' });

      await assert.rejects(
        () => sendIpcFrame(endpoint, '{"ping":"line1"}\n{"ping":"line2"}'),
        (err) => err?.code === 'EIPC_INVALID_FRAME'
      );

      const oversized = { ping: 'x'.repeat(MAX_IPC_FRAME_BYTES + 100) };
      await assert.rejects(
        () => sendIpcFrame(endpoint, oversized),
        (err) => err?.code === 'EIPC_FRAME_TOO_LARGE'
      );
    } finally {
      for (const s of sockets) {
        s.destroy();
      }
      await new Promise((resolve) => server.close(() => resolve()));
      if (process.platform !== 'win32') {
        fs.rmSync(path.dirname(endpoint), { recursive: true, force: true });
      }
    }
  });

  it('stack: createE2EStack composes all components and cleans up deterministically', async () => {
    const stack = await createE2EStack({ ports: ['api', 'console'] });
    try {
      assert.ok(stack.pg);
      assert.ok(stack.broker);
      assert.ok(stack.receiver);
      assert.ok(stack.ports.api > 0);
      assert.ok(stack.ports.console > 0);

      const localHttp = await stack.startLocalHttpServer((_req, res) => {
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ service: 'stack-smoke' }));
      });
      const res = await fetch(`${localHttp.origin}/health`);
      assert.equal(res.status, 200);
      assert.deepEqual(await res.json(), { service: 'stack-smoke' });
    } finally {
      await stack.cleanup();
    }
  });
});
