import { type BrokerMode, type FanoutSettings, type RelaySettings } from "@relayquill/runtime";
import { type BrokerGenerationId } from "@relayquill/domain";
import {
  type ConnectNatsBrokerOptions,
  type NatsBrokerConnection,
  connectNatsBroker
} from "./connection.js";
import { NatsBrokerConsumer } from "./consumer.js";
import { InMemoryJetStreamBroker, type InMemoryJetStreamBrokerOptions } from "./in-memory-broker.js";
import { NatsBrokerPublisher } from "./publisher.js";
import {
  buildBrokerTopologyContract,
  inspectBrokerTopology
} from "./stream-contract.js";
import {
  type BrokerAdapter,
  type BrokerConsumeOptions,
  type BrokerHealthStatus,
  type BrokerMessage,
  type BrokerPublishInput,
  type BrokerPublishResult,
  type BrokerPullOptions,
  type BrokerTopologyContract,
  type BrokerTopologyInspection,
  type InspectBrokerTopologyOptions
} from "./types.js";

export const BROKER_PACKAGE_VERSION = "0.1.0" as const;

export * from "./types.js";
export * from "./connection.js";
export * from "./stream-contract.js";
export * from "./publisher.js";
export * from "./consumer.js";
export * from "./in-memory-broker.js";

export interface CreateNatsBrokerAdapterOptions extends ConnectNatsBrokerOptions {
  readonly relaySettings?: RelaySettings | undefined;
  readonly fanoutSettings?: FanoutSettings | undefined;
  readonly verifyTopologyOnConnect?: boolean | undefined;
  readonly verifyConsumerOnConnect?: boolean | undefined;
  readonly expectedStreamCreatedAt?: string | undefined;
  readonly allowedTracestateKeys?: readonly string[] | undefined;
  readonly allowAnyValidTracestateKey?: boolean | undefined;
  readonly validateEnvelopePayload?: boolean | undefined;
}

export class NatsJetStreamBrokerAdapter implements BrokerAdapter {
  readonly connection: NatsBrokerConnection;
  readonly publisher: NatsBrokerPublisher;
  readonly consumer: NatsBrokerConsumer;
  readonly topologyContract: BrokerTopologyContract;

  constructor(options: {
    readonly connection: NatsBrokerConnection;
    readonly publisher: NatsBrokerPublisher;
    readonly consumer: NatsBrokerConsumer;
    readonly topologyContract: BrokerTopologyContract;
  }) {
    this.connection = options.connection;
    this.publisher = options.publisher;
    this.consumer = options.consumer;
    this.topologyContract = options.topologyContract;
  }

  get mode(): BrokerMode {
    return this.connection.mode;
  }

  get brokerGenerationId(): BrokerGenerationId {
    return this.connection.brokerGenerationId;
  }

  get streamName(): string {
    return this.connection.streamName;
  }

  get consumerName(): string {
    return this.connection.consumerName;
  }

  get subjectPrefix(): string {
    return this.connection.subjectPrefix;
  }

  publish(input: BrokerPublishInput): Promise<BrokerPublishResult> {
    return this.publisher.publish(input);
  }

  pullBatch(options?: BrokerPullOptions): Promise<readonly BrokerMessage[]> {
    return this.consumer.pullBatch(options);
  }

  consume(options?: BrokerConsumeOptions): AsyncIterable<BrokerMessage> {
    return this.consumer.consume(options);
  }

  async inspectTopology(
    options: InspectBrokerTopologyOptions = {}
  ): Promise<BrokerTopologyInspection> {
    const jsm = await this.connection.getJetStreamManager({ checkApiAccountInfo: false });
    return inspectBrokerTopology(jsm, this.topologyContract, options);
  }

  getHealth(): Promise<BrokerHealthStatus> {
    const info = this.connection.getServerInfo();
    const recent = this.connection.getRecentStatuses();
    const lastStatus = recent[recent.length - 1];
    const healthy = !this.connection.isClosed && lastStatus?.type !== "disconnect";
    const connectedServer = this.connection.getConnectedServer();

    return Promise.resolve(
      Object.freeze({
        healthy,
        mode: this.mode,
        encrypted: this.connection.spec.tlsRequired,
        connectedServers: Object.freeze(
          connectedServer.length > 0 ? [connectedServer] : [...this.connection.spec.servers]
        ),
        streamName: this.streamName,
        consumerName: this.consumerName,
        brokerGenerationId: this.brokerGenerationId,
        ...(lastStatus?.type === "error"
          ? { lastError: lastStatus.error.message }
          : info === undefined
            ? { lastError: "no_server_info" }
            : {})
      })
    );
  }

  async close(): Promise<void> {
    this.publisher.close();
    this.consumer.close();
    await this.connection.drain().catch(() => this.connection.close());
  }
}

export async function createNatsBrokerAdapter(
  options: CreateNatsBrokerAdapterOptions
): Promise<NatsJetStreamBrokerAdapter> {
  const connection = await connectNatsBroker(options);
  try {
    const topologyContract = buildBrokerTopologyContract({
      streamName: connection.streamName,
      consumerName: connection.consumerName,
      subjectPrefix: connection.subjectPrefix,
      replicas: connection.spec.replicas,
      fanout: options.fanoutSettings
    });

    if (options.verifyTopologyOnConnect) {
      const jsm = await connection.getJetStreamManager({ checkApiAccountInfo: false });
      await inspectBrokerTopology(jsm, topologyContract, {
        verifyConsumer: options.verifyConsumerOnConnect ?? true,
        expectedStreamCreatedAt: options.expectedStreamCreatedAt
      });
    }

    const publisher = new NatsBrokerPublisher({
      js: connection.js,
      nc: connection.nc,
      streamName: connection.streamName,
      subjectPrefix: connection.subjectPrefix,
      brokerGenerationId: connection.brokerGenerationId,
      timeoutMs: options.relaySettings?.publish_timeout_ms ?? connection.spec.timeoutMs,
      maxInFlight: options.relaySettings?.publish_concurrency,
      allowedTracestateKeys: options.allowedTracestateKeys,
      allowAnyValidTracestateKey: options.allowAnyValidTracestateKey,
      validateEnvelopePayload: options.validateEnvelopePayload
    });

    const consumer = new NatsBrokerConsumer({
      js: connection.js,
      streamName: connection.streamName,
      consumerName: connection.consumerName,
      brokerGenerationId: connection.brokerGenerationId,
      maxBatchLimit: options.fanoutSettings?.max_batch,
      maxBytesLimit: options.fanoutSettings?.max_bytes,
      maxExpiresMsLimit: options.fanoutSettings?.max_expires_ms,
      allowedTracestateKeys: options.allowedTracestateKeys,
      allowAnyValidTracestateKey: options.allowAnyValidTracestateKey
    });

    return new NatsJetStreamBrokerAdapter({
      connection,
      publisher,
      consumer,
      topologyContract
    });
  } catch (err) {
    await connection.close().catch(() => undefined);
    throw err;
  }
}

export type CreateBrokerAdapterOptions =
  | ({ readonly mode: "in_memory_test" } & InMemoryJetStreamBrokerOptions)
  | CreateNatsBrokerAdapterOptions;

export async function createBrokerAdapter(
  options: CreateBrokerAdapterOptions
): Promise<BrokerAdapter> {
  if (options.mode === "in_memory_test") {
    return new InMemoryJetStreamBroker(options);
  }
  return createNatsBrokerAdapter(options);
}
