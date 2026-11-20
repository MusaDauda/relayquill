import http from "node:http";

export interface RelayHealthProbe {
  getHealth(): {
    readonly live: boolean;
    readonly ready: boolean;
    readonly role: string;
    readonly instanceId: string;
    readonly controlEpoch?: string | undefined;
    readonly draining: boolean;
    readonly lastTickAt?: string | undefined;
    readonly lastError?: string | undefined;
  };
}

export interface RelayHealthServerOptions {
  readonly host?: string | undefined;
  readonly port?: number | undefined;
  readonly probe: RelayHealthProbe;
}

export class RelayHealthServer {
  readonly #server: http.Server;
  readonly #host: string;
  readonly #port: number;
  #boundPort: number | undefined;

  constructor(options: RelayHealthServerOptions) {
    this.#host = options.host ?? "127.0.0.1";
    this.#port = options.port ?? 0;

    this.#server = http.createServer((req, res) => {
      const url = req.url?.split("?")[0] ?? "/";
      const snapshot = options.probe.getHealth();

      if (req.method === "GET" && url === "/health/live") {
        const code = snapshot.live ? 200 : 503;
        const body = JSON.stringify({
          status: snapshot.live ? "live" : "not_live",
          role: snapshot.role,
          instance_id: snapshot.instanceId,
          draining: snapshot.draining
        });
        res.writeHead(code, {
          "content-type": "application/json; charset=utf-8",
          "cache-control": "no-store"
        });
        res.end(body);
        return;
      }

      if (req.method === "GET" && url === "/health/ready") {
        const code = snapshot.ready ? 200 : 503;
        const body = JSON.stringify({
          status: snapshot.ready ? "ready" : "not_ready",
          role: snapshot.role,
          instance_id: snapshot.instanceId,
          ...(snapshot.controlEpoch !== undefined
            ? { control_epoch: snapshot.controlEpoch }
            : {}),
          draining: snapshot.draining,
          ...(snapshot.lastTickAt !== undefined ? { last_tick_at: snapshot.lastTickAt } : {}),
          ...(snapshot.lastError !== undefined ? { last_error: snapshot.lastError } : {})
        });
        res.writeHead(code, {
          "content-type": "application/json; charset=utf-8",
          "cache-control": "no-store"
        });
        res.end(body);
        return;
      }

      res.writeHead(404, { "content-type": "application/json; charset=utf-8" });
      res.end('{"error":"NOT_FOUND"}');
    });
  }

  get port(): number | undefined {
    return this.#boundPort;
  }

  get host(): string {
    return this.#host;
  }

  async start(): Promise<{ readonly host: string; readonly port: number }> {
    await new Promise<void>((resolve, reject) => {
      const onError = (err: Error): void => {
        this.#server.off("listening", onListening);
        reject(err);
      };
      const onListening = (): void => {
        this.#server.off("error", onError);
        const addr = this.#server.address();
        if (addr !== null && typeof addr === "object") {
          this.#boundPort = addr.port;
        }
        resolve();
      };
      this.#server.once("error", onError);
      this.#server.once("listening", onListening);
      this.#server.listen(this.#port, this.#host);
    });
    return { host: this.#host, port: this.#boundPort ?? this.#port };
  }

  async stop(): Promise<void> {
    await new Promise<void>((resolve) => {
      this.#server.close(() => {
        resolve();
      });
    });
  }
}

export function createRelayHealthServer(options: RelayHealthServerOptions): RelayHealthServer {
  return new RelayHealthServer(options);
}
