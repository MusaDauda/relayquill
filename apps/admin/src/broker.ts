import {
  type BrokerTopologyInspection,
  type BrokerTopologyManager,
  type BuildBrokerTopologyContractOptions,
  InMemoryJetStreamBroker,
  type NatsJetStreamBrokerAdapter,
  brokerConnectionInputFromConfig,
  buildBrokerTopologyContract,
  createNatsBrokerAdapter,
  ensureBrokerTopology,
  inspectBrokerTopology
} from "@relayquill/broker";
import { type BrokerConfig, type ResolvedBrokerEnvConfig, type SecretProvider } from "@relayquill/runtime";

export type BrokerSubcommand = "inspect" | "ensure" | "verify";

export interface RunBrokerCommandOptions {
  readonly subcommand: BrokerSubcommand;
  readonly brokerConfig?: BrokerConfig | ResolvedBrokerEnvConfig | undefined;
  readonly topologyManager?: BrokerTopologyManager | undefined;
  readonly inMemoryBroker?: InMemoryJetStreamBroker | undefined;
  readonly secretProvider?: SecretProvider | undefined;
  readonly contractOptions?: BuildBrokerTopologyContractOptions | undefined;
}

export interface BrokerCommandResult {
  readonly ok: boolean;
  readonly subcommand: BrokerSubcommand;
  readonly streamName: string;
  readonly consumerName: string;
  readonly subjectPrefix: string;
  readonly configurationSha256: string;
  readonly observedStreamCreatedAt: string;
  readonly messages: number;
  readonly consumerPending: number;
}

function summarizeInspection(
  subcommand: BrokerSubcommand,
  inspection: BrokerTopologyInspection,
  contract: ReturnType<typeof buildBrokerTopologyContract>,
  subjectPrefix: string
): BrokerCommandResult {
  const stateMessages = inspection.streamInfo.state.messages;
  const consumerPending = inspection.consumerInfo?.num_pending ?? 0;
  return {
    ok: true,
    subcommand,
    streamName: contract.stream.name,
    consumerName: contract.consumer.durable_name,
    subjectPrefix,
    configurationSha256: inspection.configurationSha256,
    observedStreamCreatedAt: inspection.observedStreamCreatedAt,
    messages: typeof stateMessages === "number" ? stateMessages : Number(stateMessages),
    consumerPending: typeof consumerPending === "number" ? consumerPending : Number(consumerPending)
  };
}

export async function runBrokerCommand(
  options: RunBrokerCommandOptions
): Promise<BrokerCommandResult> {
  const contract = buildBrokerTopologyContract({
    broker: options.brokerConfig,
    ...options.contractOptions
  });
  const subjectPrefix =
    options.contractOptions?.subjectPrefix ??
    (options.brokerConfig !== undefined
      ? "subjectPrefix" in options.brokerConfig
        ? options.brokerConfig.subjectPrefix
        : options.brokerConfig.subject_prefix
      : "");

  if (options.topologyManager !== undefined || options.inMemoryBroker !== undefined) {
    const manager = options.topologyManager ?? options.inMemoryBroker?.manager;
    if (manager === undefined) {
      throw new Error("Expected BrokerTopologyManager instance");
    }
    const inspection =
      options.subcommand === "ensure"
        ? await ensureBrokerTopology(manager, contract)
        : await inspectBrokerTopology(manager, contract, { verifyConsumer: true });
    return summarizeInspection(options.subcommand, inspection, contract, subjectPrefix);
  }

  if (options.brokerConfig === undefined) {
    const fallback = new InMemoryJetStreamBroker({
      streamName: contract.stream.name,
      consumerName: contract.consumer.durable_name,
      subjectPrefix,
      replicas: contract.stream.replicas,
      autoCreateTopology: options.subcommand === "ensure"
    });
    const inspection =
      options.subcommand === "ensure"
        ? await ensureBrokerTopology(fallback.manager, contract)
        : await inspectBrokerTopology(fallback.manager, contract, { verifyConsumer: true });
    await fallback.close();
    return summarizeInspection(options.subcommand, inspection, contract, subjectPrefix);
  }

  let adapter: NatsJetStreamBrokerAdapter | undefined;
  try {
    const connInput = brokerConnectionInputFromConfig(
      options.brokerConfig,
      options.secretProvider !== undefined ? { secretProvider: options.secretProvider } : {}
    );
    adapter = await createNatsBrokerAdapter({
      ...connInput,
      verifyTopologyOnConnect: false
    });
    const jsm = await adapter.connection.getJetStreamManager({ checkApiAccountInfo: false });
    const inspection =
      options.subcommand === "ensure"
        ? await ensureBrokerTopology(jsm, contract)
        : await inspectBrokerTopology(jsm, contract, { verifyConsumer: true });
    return summarizeInspection(options.subcommand, inspection, contract, subjectPrefix);
  } finally {
    if (adapter !== undefined) {
      await adapter.close().catch(() => undefined);
    }
  }
}
