import fs from 'node:fs';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const harnessDir = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(harnessDir, '..', '..', '..');

export function matchNatsSubject(pattern, subject) {
  const patTokens = pattern.split('.');
  const subTokens = subject.split('.');

  for (let i = 0; i < patTokens.length; i += 1) {
    const pat = patTokens[i];
    if (pat === '>') {
      return i < subTokens.length;
    }
    if (i >= subTokens.length) {
      return false;
    }
    if (pat !== '*' && pat !== subTokens[i]) {
      return false;
    }
  }

  return patTokens.length === subTokens.length;
}

function toUint8Array(payload) {
  if (payload instanceof Uint8Array) {
    return new Uint8Array(payload);
  }
  if (typeof payload === 'string') {
    return new TextEncoder().encode(payload);
  }
  throw new TypeError('Broker payload must be a Uint8Array or string');
}

export class BrokerLimitError extends Error {
  constructor(message, code = 'JS_STREAM_LIMIT') {
    super(message);
    this.name = 'BrokerLimitError';
    this.code = code;
  }
}

export class PubAckTimeoutError extends Error {
  constructor(message, stream, seq) {
    super(message);
    this.name = 'PubAckTimeoutError';
    this.code = 'PUBACK_LOST';
    this.stream = stream;
    this.seq = seq;
  }
}

export class InMemoryJetStreamBroker {
  #nowMs;
  #streams = new Map();
  #forceStreamFull = false;
  #dropPubAckCount = 0;
  #dropAckCount = 0;
  #closed = false;

  constructor(options = {}) {
    this.#nowMs = options.nowMs ?? (() => Date.now());
  }

  #assertOpen() {
    if (this.#closed) {
      throw new Error('InMemoryJetStreamBroker is closed');
    }
  }

  ensureStream(name, config = {}) {
    this.#assertOpen();
    if (this.#streams.has(name)) {
      return this.#streams.get(name);
    }
    const stream = {
      name,
      policy: config.policy ?? 'limits',
      discard: config.discard ?? 'new',
      subjects: [...(config.subjects ?? [`${name}.>`])],
      maxMsgs: config.maxMsgs ?? Number.POSITIVE_INFINITY,
      maxBytes: config.maxBytes ?? Number.POSITIVE_INFINITY,
      maxAgeMs: config.maxAgeMs ?? Number.POSITIVE_INFINITY,
      duplicateWindowMs: config.duplicateWindowMs ?? 120_000,
      nextSeq: 1,
      messages: [],
      totalBytes: 0,
      dedupIndex: new Map(), // msgId -> { seq, storedAtMs }
      consumers: new Map()
    };
    this.#streams.set(name, stream);
    return stream;
  }

  ensureConsumer(streamName, config = {}) {
    this.#assertOpen();
    const stream = this.#streams.get(streamName);
    if (!stream) {
      throw new Error(`Stream not found: ${streamName}`);
    }
    const durableName = config.durableName ?? config.name;
    if (!durableName) {
      throw new Error('Consumer durableName is required');
    }
    if (stream.consumers.has(durableName)) {
      return stream.consumers.get(durableName);
    }
    const consumer = {
      streamName,
      durableName,
      filterSubject: config.filterSubject ?? null,
      ackWaitMs: config.ackWaitMs ?? 30_000,
      maxDeliver: config.maxDeliver ?? 5,
      maxAckPending: config.maxAckPending ?? 1_000,
      nextCursorSeq: 1,
      pending: new Map(), // seq -> { deliveredCount, firstDeliveredAtMs, deadlineAtMs, availableAtMs, inFlight }
      acked: new Set(),
      terminated: new Set(),
      maxDeliverExceeded: new Set()
    };
    stream.consumers.set(durableName, consumer);
    return consumer;
  }

  #findStreamForSubject(subject) {
    for (const stream of this.#streams.values()) {
      if (stream.subjects.some((pat) => matchNatsSubject(pat, subject))) {
        return stream;
      }
    }
    return null;
  }

  #pruneStreamExpired(stream, nowMs) {
    if (!Number.isFinite(stream.maxAgeMs)) {
      return 0;
    }
    let removed = 0;
    const kept = [];
    for (const msg of stream.messages) {
      if (nowMs - msg.storedAtMs >= stream.maxAgeMs) {
        stream.totalBytes -= msg.payload.byteLength;
        removed += 1;
      } else {
        kept.push(msg);
      }
    }
    stream.messages = kept;
    return removed;
  }

  #pruneDedupWindow(stream, nowMs) {
    for (const [msgId, entry] of stream.dedupIndex.entries()) {
      if (nowMs - entry.storedAtMs >= stream.duplicateWindowMs) {
        stream.dedupIndex.delete(msgId);
      }
    }
  }

  async publish(subject, payload, opts = {}) {
    this.#assertOpen();
    const stream = this.#findStreamForSubject(subject);
    if (!stream) {
      throw new Error(`No stream matches subject: ${subject}`);
    }

    const nowMs = this.#nowMs();
    this.#pruneStreamExpired(stream, nowMs);
    this.#pruneDedupWindow(stream, nowMs);

    const msgId = opts.msgId ?? opts.headers?.['Nats-Msg-Id'] ?? null;
    if (msgId && stream.dedupIndex.has(msgId)) {
      const existing = stream.dedupIndex.get(msgId);
      return {
        stream: stream.name,
        seq: existing.seq,
        duplicate: true
      };
    }

    const bytes = toUint8Array(payload);

    if (this.#forceStreamFull) {
      throw new BrokerLimitError(`Stream ${stream.name} is full (injected fault)`);
    }

    if (stream.policy === 'limits' && stream.discard === 'new') {
      if (stream.messages.length >= stream.maxMsgs) {
        throw new BrokerLimitError(`Stream ${stream.name} exceeded maxMsgs (${stream.maxMsgs})`);
      }
      if (stream.totalBytes + bytes.byteLength > stream.maxBytes) {
        throw new BrokerLimitError(`Stream ${stream.name} exceeded maxBytes (${stream.maxBytes})`);
      }
    }

    const seq = stream.nextSeq;
    stream.nextSeq += 1;
    const record = {
      stream: stream.name,
      seq,
      subject,
      payload: bytes,
      headers: { ...(opts.headers ?? {}), ...(msgId ? { 'Nats-Msg-Id': msgId } : {}) },
      storedAtMs: nowMs
    };

    stream.messages.push(record);
    stream.totalBytes += bytes.byteLength;
    if (msgId) {
      stream.dedupIndex.set(msgId, { seq, storedAtMs: nowMs });
    }

    if (this.#dropPubAckCount > 0) {
      this.#dropPubAckCount -= 1;
      throw new PubAckTimeoutError(
        `PubAck lost after storing ${stream.name}#${seq}`,
        stream.name,
        seq
      );
    }

    return {
      stream: stream.name,
      seq,
      duplicate: false
    };
  }

  #buildMessageHandle(stream, consumer, record, deliveryCount) {
    const state = consumer.pending.get(record.seq);
    const expectedDeliveryCount = deliveryCount;
    let settled = false;

    const isCurrentAttempt = () => {
      const current = consumer.pending.get(record.seq);
      return current === state && state.inFlight && state.deliveredCount === expectedDeliveryCount;
    };

    const handle = {
      stream: stream.name,
      consumer: consumer.durableName,
      subject: record.subject,
      seq: record.seq,
      deliveryCount,
      redelivered: deliveryCount > 1,
      payload: new Uint8Array(record.payload),
      headers: { ...record.headers },
      ack: async () => {
        if (settled || !isCurrentAttempt()) {
          return;
        }
        settled = true;
        if (this.#dropAckCount > 0) {
          this.#dropAckCount -= 1;
          // Simulate dropped ACK on wire: stays inFlight until AckWait expires.
          return;
        }
        consumer.pending.delete(record.seq);
        consumer.acked.add(record.seq);
      },
      nak: async (delayMs = 0) => {
        if (settled || !isCurrentAttempt()) {
          return;
        }
        settled = true;
        const nowMs = this.#nowMs();
        state.inFlight = false;
        state.availableAtMs = nowMs + Math.max(0, delayMs);
        state.deadlineAtMs = Number.POSITIVE_INFINITY;
      },
      working: async () => {
        if (settled || !isCurrentAttempt()) {
          return;
        }
        const nowMs = this.#nowMs();
        state.deadlineAtMs = nowMs + consumer.ackWaitMs;
      },
      term: async () => {
        if (settled || !isCurrentAttempt()) {
          return;
        }
        settled = true;
        consumer.pending.delete(record.seq);
        consumer.terminated.add(record.seq);
      }
    };

    return handle;
  }

  pullBatch(opts = {}) {
    this.#assertOpen();
    const stream = this.#streams.get(opts.stream);
    if (!stream) {
      throw new Error(`Stream not found: ${opts.stream}`);
    }
    const consumer = stream.consumers.get(opts.consumer);
    if (!consumer) {
      throw new Error(`Consumer not found: ${opts.consumer} on stream ${opts.stream}`);
    }

    const nowMs = this.#nowMs();
    this.#pruneStreamExpired(stream, nowMs);

    const maxBatch = opts.maxBatch ?? 10;
    const maxBytes = opts.maxBytes ?? Number.POSITIVE_INFINITY;
    const msgBySeq = new Map(stream.messages.map((m) => [m.seq, m]));

    // Re-evaluate pending messages for AckWait expiry or nak readiness.
    let activeInFlight = 0;
    const redeliverCandidates = [];
    for (const [seq, state] of consumer.pending.entries()) {
      const record = msgBySeq.get(seq);
      if (!record) {
        consumer.pending.delete(seq);
        continue;
      }
      if (state.inFlight && nowMs >= state.deadlineAtMs) {
        state.inFlight = false;
        state.availableAtMs = nowMs;
      }
      if (state.inFlight) {
        activeInFlight += 1;
      } else if (nowMs >= state.availableAtMs) {
        if (state.deliveredCount >= consumer.maxDeliver) {
          consumer.pending.delete(seq);
          consumer.maxDeliverExceeded.add(seq);
        } else {
          redeliverCandidates.push({ seq, record, state });
        }
      }
    }

    const delivered = [];
    let deliveredBytes = 0;

    const canAcceptMore = (nextRecord) => {
      if (delivered.length >= maxBatch) {
        return false;
      }
      if (activeInFlight >= consumer.maxAckPending) {
        return false;
      }
      if (delivered.length > 0 && deliveredBytes + nextRecord.payload.byteLength > maxBytes) {
        return false;
      }
      if (nextRecord.payload.byteLength > maxBytes) {
        return false;
      }
      return true;
    };

    redeliverCandidates.sort((a, b) => a.seq - b.seq);
    for (const candidate of redeliverCandidates) {
      if (!canAcceptMore(candidate.record)) {
        break;
      }
      candidate.state.deliveredCount += 1;
      candidate.state.inFlight = true;
      candidate.state.deadlineAtMs = nowMs + consumer.ackWaitMs;
      activeInFlight += 1;
      deliveredBytes += candidate.record.payload.byteLength;
      delivered.push(
        this.#buildMessageHandle(stream, consumer, candidate.record, candidate.state.deliveredCount)
      );
    }

    for (const record of stream.messages) {
      if (record.seq < consumer.nextCursorSeq) {
        continue;
      }
      consumer.nextCursorSeq = record.seq + 1;
      if (consumer.filterSubject && !matchNatsSubject(consumer.filterSubject, record.subject)) {
        continue;
      }
      if (!canAcceptMore(record)) {
        // Rewind cursor so unpulled message remains queued.
        consumer.nextCursorSeq = record.seq;
        break;
      }
      consumer.pending.set(record.seq, {
        deliveredCount: 1,
        firstDeliveredAtMs: nowMs,
        deadlineAtMs: nowMs + consumer.ackWaitMs,
        availableAtMs: nowMs,
        inFlight: true
      });
      activeInFlight += 1;
      deliveredBytes += record.payload.byteLength;
      delivered.push(this.#buildMessageHandle(stream, consumer, record, 1));
    }

    return delivered;
  }

  async *consume(opts = {}) {
    const batch = this.pullBatch(opts);
    for (const msg of batch) {
      yield msg;
    }
  }

  getStreamStats(streamName) {
    const stream = this.#streams.get(streamName);
    if (!stream) {
      return null;
    }
    return {
      name: stream.name,
      messages: stream.messages.length,
      bytes: stream.totalBytes,
      firstSeq: stream.messages[0]?.seq ?? 0,
      lastSeq: stream.nextSeq - 1
    };
  }

  getConsumerStats(streamName, durableName) {
    const stream = this.#streams.get(streamName);
    const consumer = stream?.consumers.get(durableName);
    if (!consumer) {
      return null;
    }
    return {
      durableName: consumer.durableName,
      pending: consumer.pending.size,
      acked: consumer.acked.size,
      terminated: consumer.terminated.size,
      maxDeliverExceeded: consumer.maxDeliverExceeded.size
    };
  }

  // Deterministic fault hooks
  dropNextPubAckAfterStore(count = 1) {
    this.#dropPubAckCount = count;
  }

  forceStreamFull(enabled = true) {
    this.#forceStreamFull = Boolean(enabled);
  }

  expireMessages(maxAgeMs = 0) {
    let totalExpired = 0;
    const nowMs = this.#nowMs();
    for (const stream of this.#streams.values()) {
      const kept = [];
      for (const msg of stream.messages) {
        if (nowMs - msg.storedAtMs >= maxAgeMs) {
          stream.totalBytes -= msg.payload.byteLength;
          totalExpired += 1;
        } else {
          kept.push(msg);
        }
      }
      stream.messages = kept;
    }
    return totalExpired;
  }

  dropNextAck(count = 1) {
    this.#dropAckCount = count;
  }

  async cleanup() {
    this.#closed = true;
    this.#streams.clear();
  }
}

export async function launchEmbeddedGoBroker(options = {}) {
  if (options.disableBinaryLookup) {
    return {
      available: false,
      reason: 'Embedded Go broker lookup disabled',
      async cleanup() {}
    };
  }

  const launcherDir = options.launcherDir ?? path.join(repoRoot, 'tools', 'broker-launcher');
  const mainGoPath = options.mainGoPath ?? path.join(launcherDir, 'cmd', 'relayquill-broker', 'main.go');
  const binName = process.platform === 'win32' ? 'relayquill-broker.exe' : 'relayquill-broker';
  const prebuiltBin = options.binaryPath ?? path.join(launcherDir, binName);

  const hasSource = fs.existsSync(mainGoPath);
  const hasBinary = fs.existsSync(prebuiltBin);

  if (!hasBinary && !hasSource) {
    return {
      available: false,
      reason: 'tools/broker-launcher is not yet present in workspace',
      async cleanup() {}
    };
  }

  const command = hasBinary ? prebuiltBin : 'go';
  const args = hasBinary
    ? (options.args ?? [])
    : ['run', './cmd/relayquill-broker', ...(options.args ?? [])];

  const child = spawn(command, args, {
    cwd: launcherDir,
    env: { ...process.env, ...(options.env ?? {}) },
    detached: process.platform !== 'win32' && command === 'go',
    stdio: ['ignore', 'pipe', 'pipe']
  });

  const stdoutChunks = [];
  const stderrChunks = [];
  const logs = [];
  child.stdout?.on('data', (chunk) => {
    const text = chunk.toString('utf8');
    stdoutChunks.push(text);
    logs.push(text);
  });
  child.stderr?.on('data', (chunk) => {
    const text = chunk.toString('utf8');
    stderrChunks.push(text);
    logs.push(text);
  });

  let closed = false;
  let spawnErr = null;
  const exitPromise = new Promise((resolve) => {
    child.once('error', (err) => {
      spawnErr = err;
      closed = true;
      logs.push(err instanceof Error ? err.message : String(err));
      resolve({ code: null, signal: null, error: err });
    });
    child.once('close', (code, signal) => {
      closed = true;
      resolve({ code, signal, error: null });
    });
  });

  return {
    available: true,
    pid: child.pid,
    process: child,
    getStdout: () => stdoutChunks.join(''),
    getStderr: () => stderrChunks.join(''),
    getLogs: () => logs.join(''),
    waitForExit: () => exitPromise,
    async cleanup() {
      if (closed || spawnErr || child.exitCode !== null || child.signalCode !== null) {
        await exitPromise;
        return;
      }
      if (process.platform === 'win32' && command === 'go' && child.pid) {
        await new Promise((resolve) => {
          const killer = spawn('taskkill', ['/PID', String(child.pid), '/T', '/F'], {
            stdio: 'ignore'
          });
          killer.once('error', () => {
            try {
              child.kill('SIGKILL');
            } catch {
              // Ignore already-exited process.
            }
            resolve();
          });
          killer.once('close', () => resolve());
        });
        await new Promise((resolve) => {
          let settled = false;
          const finish = () => {
            if (!settled) {
              settled = true;
              resolve();
            }
          };
          const timer = setTimeout(finish, 1_000);
          exitPromise.then(() => {
            clearTimeout(timer);
            finish();
          });
        });
        return;
      }

      const sendSignal = (sig) => {
        if (process.platform !== 'win32' && command === 'go' && child.pid) {
          try {
            process.kill(-child.pid, sig);
            return;
          } catch {
            // Fall back to direct process kill.
          }
        }
        child.kill(sig);
      };

      try {
        sendSignal('SIGTERM');
      } catch {
        // Ignore already-exited process.
      }
      await new Promise((resolve) => {
        let settled = false;
        const finish = () => {
          if (!settled) {
            settled = true;
            resolve();
          }
        };
        const timer = setTimeout(() => {
          try {
            sendSignal('SIGKILL');
          } catch {
            // Ignore already-exited process.
          }
          finish();
        }, 2_000);
        exitPromise.then(() => {
          clearTimeout(timer);
          finish();
        });
      });
    }
  };
}

export async function createBrokerHarness(options = {}) {
  const mode = options.mode ?? 'in_memory';
  if (mode === 'in_memory') {
    return new InMemoryJetStreamBroker(options);
  }
  if (mode === 'embedded_go_tls') {
    return launchEmbeddedGoBroker(options);
  }
  throw new Error(`Unsupported broker harness mode: ${mode}`);
}
