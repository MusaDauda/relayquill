import http from 'node:http';
import net from 'node:net';
import { createBrokerHarness } from './broker-harness.mjs';
import { createHttpTestDouble } from './https-double.mjs';
import { createPgHarness } from './pg-pglite.mjs';

export async function allocateEphemeralPort(host = '127.0.0.1') {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.unref();
    server.once('error', reject);
    server.listen(0, host, () => {
      const address = server.address();
      const port = typeof address === 'object' && address ? address.port : 0;
      server.close((closeErr) => {
        if (closeErr) {
          reject(closeErr);
        } else {
          resolve(port);
        }
      });
    });
  });
}

export async function createE2EStack(options = {}) {
  const cleanups = [];
  const trackedServers = new Set();

  try {
    const pg = options.pg === false
      ? null
      : await createPgHarness(typeof options.pg === 'object' ? options.pg : {});
    if (pg) {
      cleanups.push(() => pg.cleanup());
    }

    const broker = options.broker === false
      ? null
      : await createBrokerHarness(typeof options.broker === 'object' ? options.broker : {});
    if (broker) {
      cleanups.push(() => broker.cleanup());
    }

    const receiver = options.receiver === false
      ? null
      : await createHttpTestDouble(typeof options.receiver === 'object' ? options.receiver : {});
    if (receiver) {
      cleanups.push(() => receiver.cleanup());
    }

    const allocatedPorts = {};
    if (Array.isArray(options.ports)) {
      for (const name of options.ports) {
        allocatedPorts[name] = await allocateEphemeralPort('127.0.0.1');
      }
    }

    async function startLocalHttpServer(handler, listenHost = '127.0.0.1') {
      const sockets = new Set();
      const server = http.createServer(handler);
      server.on('connection', (socket) => {
        sockets.add(socket);
        socket.on('close', () => sockets.delete(socket));
      });
      await new Promise((resolve, reject) => {
        server.once('error', reject);
        server.listen(0, listenHost, resolve);
      });
      const addr = server.address();
      const port = typeof addr === 'object' && addr ? addr.port : 0;
      const entry = {
        server,
        port,
        origin: `http://${listenHost}:${port}`,
        localhostOrigin: `http://localhost:${port}`,
        async close() {
          for (const socket of sockets) {
            socket.destroy();
          }
          sockets.clear();
          await new Promise((resolve) => server.close(() => resolve()));
          trackedServers.delete(entry);
        }
      };
      trackedServers.add(entry);
      return entry;
    }

    let cleanedUp = false;

    return {
      pg,
      broker,
      receiver,
      ports: allocatedPorts,
      allocatePort: () => allocateEphemeralPort('127.0.0.1'),
      startLocalHttpServer,
      registerCleanup(fn) {
        cleanups.push(fn);
      },
      async cleanup() {
        if (cleanedUp) {
          return;
        }
        cleanedUp = true;
        const errors = [];

        for (const entry of [...trackedServers]) {
          try {
            await entry.close();
          } catch (err) {
            errors.push(err);
          }
        }

        for (let i = cleanups.length - 1; i >= 0; i -= 1) {
          try {
            await cleanups[i]();
          } catch (err) {
            errors.push(err);
          }
        }

        if (errors.length > 0) {
          throw new AggregateError(errors, 'E2E stack cleanup encountered errors');
        }
      }
    };
  } catch (err) {
    for (let i = cleanups.length - 1; i >= 0; i -= 1) {
      try {
        await cleanups[i]();
      } catch {
        // Best-effort rollback on partial initialization failure.
      }
    }
    throw err;
  }
}
