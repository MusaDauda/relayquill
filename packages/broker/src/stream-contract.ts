import {
  type BrokerGenerationId,
  ValidationDomainError,
  parseBrokerGenerationId
} from "@relayquill/domain";
import {
  canonicalizeJson,
  sha256Utf8Hex,
  type CanonicalJsonValue
} from "@relayquill/contracts";
import {
  type BrokerConfig,
  type FanoutSettings,
  type ResolvedBrokerEnvConfig
} from "@relayquill/runtime";
import {
  AckPolicy,
  type ConsumerConfig,
  type ConsumerInfo,
  DeliverPolicy,
  DiscardPolicy,
  JetStreamApiCodes,
  JetStreamApiError,
  ReplayPolicy,
  RetentionPolicy,
  StorageType,
  type StreamConfig,
  type StreamInfo
} from "@nats-io/jetstream";
import {
  BROKER_DEFAULT_ACK_WAIT_NS,
  BROKER_DEFAULT_DUPLICATE_WINDOW_NS,
  BROKER_DEFAULT_MAX_AGE_NS,
  BROKER_DEFAULT_MAX_BYTES,
  BROKER_DEFAULT_MAX_MSGS,
  BROKER_DEFAULT_PULL_MAX_EXPIRES_MS,
  BROKER_DEFAULT_PULL_MAX_EXPIRES_NS,
  BROKER_DEFAULT_REPLICAS,
  BROKER_EVENT_MAX_PAYLOAD_BYTES,
  BROKER_EVENT_STREAM_NAME,
  BrokerTopologyMismatchError,
  type BrokerConsumerContract,
  type BrokerStreamContract,
  type BrokerTopologyContract,
  type BrokerTopologyInspection,
  type BrokerTopologyManager,
  type BrokerTopologyMismatch,
  BrokerUnavailableError,
  FANOUT_ACK_WAIT_MS,
  FANOUT_CONSUMER_NAME,
  FANOUT_MAX_ACK_PENDING,
  FANOUT_MAX_DELIVER,
  FANOUT_PULL_MAX_BATCH,
  FANOUT_PULL_MAX_BYTES,
  type InspectBrokerTopologyOptions,
  formatStreamSubjectPattern,
  normalizeSubjectPrefix
} from "./types.js";

const STREAM_NAME_REGEX = /^[A-Z0-9_]{3,64}$/;
const CONSUMER_NAME_REGEX = /^[A-Z0-9_]{3,64}$/;
const NS_PER_MS = 1_000_000;

export interface BuildBrokerTopologyContractOptions {
  readonly broker?: BrokerConfig | ResolvedBrokerEnvConfig | undefined;
  readonly fanout?: FanoutSettings | undefined;
  readonly streamName?: string | undefined;
  readonly consumerName?: string | undefined;
  readonly subjectPrefix?: string | undefined;
  readonly replicas?: 1 | 3 | undefined;
  readonly maxMsgs?: number | undefined;
  readonly maxBytes?: number | undefined;
  readonly maxAgeNs?: number | undefined;
  readonly ackWaitMs?: number | undefined;
  readonly maxDeliver?: number | undefined;
  readonly maxAckPending?: number | undefined;
  readonly maxBatch?: number | undefined;
  readonly pullMaxBytes?: number | undefined;
  readonly maxExpiresMs?: number | undefined;
}

function assertBoundedPositiveInt(value: number, min: number, max: number, fieldPath: string): number {
  if (!Number.isSafeInteger(value) || value < min || value > max) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `${fieldPath} must be an integer within [${min}, ${max}], got ${String(value)}`,
      fieldErrors: [{ path: fieldPath, code: "INVALID_VALUE" }]
    });
  }
  return value;
}

export function buildBrokerTopologyContract(
  options: BuildBrokerTopologyContractOptions = {}
): BrokerTopologyContract {
  const brokerCfg = options.broker;
  const fanoutCfg = options.fanout;

  const isBrokerResolved = brokerCfg !== undefined && "streamName" in brokerCfg;
  const rawStreamName =
    options.streamName ??
    (brokerCfg !== undefined
      ? isBrokerResolved
        ? brokerCfg.streamName
        : brokerCfg.stream_name
      : BROKER_EVENT_STREAM_NAME);
  if (!STREAM_NAME_REGEX.test(rawStreamName)) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Invalid stream name "${rawStreamName}"`,
      fieldErrors: [{ path: "stream.name", code: "INVALID_VALUE" }]
    });
  }

  const rawConsumerName =
    options.consumerName ??
    (brokerCfg !== undefined
      ? isBrokerResolved
        ? brokerCfg.consumerName
        : brokerCfg.consumer_name
      : FANOUT_CONSUMER_NAME);
  if (!CONSUMER_NAME_REGEX.test(rawConsumerName)) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Invalid consumer durable name "${rawConsumerName}"`,
      fieldErrors: [{ path: "consumer.durable_name", code: "INVALID_VALUE" }]
    });
  }

  const rawPrefix =
    options.subjectPrefix ??
    (brokerCfg !== undefined
      ? isBrokerResolved
        ? brokerCfg.subjectPrefix
        : brokerCfg.subject_prefix
      : "");
  const subjectPrefix = normalizeSubjectPrefix(rawPrefix);
  const subjectPattern = formatStreamSubjectPattern(subjectPrefix);

  const replicas =
    options.replicas ??
    (brokerCfg !== undefined && !isBrokerResolved ? brokerCfg.replicas : BROKER_DEFAULT_REPLICAS);
  if (replicas !== 1 && replicas !== 3) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Broker stream replicas must be 1 or 3, got ${String(replicas)}`,
      fieldErrors: [{ path: "stream.replicas", code: "INVALID_VALUE" }]
    });
  }

  const maxMsgs = assertBoundedPositiveInt(
    options.maxMsgs ??
      (brokerCfg !== undefined && !isBrokerResolved ? brokerCfg.max_msgs : BROKER_DEFAULT_MAX_MSGS),
    1_000,
    100_000_000,
    "stream.max_msgs"
  );
  const maxBytes = assertBoundedPositiveInt(
    options.maxBytes ??
      (brokerCfg !== undefined && !isBrokerResolved ? brokerCfg.max_bytes : BROKER_DEFAULT_MAX_BYTES),
    1_048_576,
    107_374_182_400,
    "stream.max_bytes"
  );
  const maxAgeNs = assertBoundedPositiveInt(
    options.maxAgeNs ??
      (brokerCfg !== undefined && !isBrokerResolved ? brokerCfg.max_age_ns : BROKER_DEFAULT_MAX_AGE_NS),
    60_000_000_000,
    604_800_000_000_000,
    "stream.max_age_ns"
  );

  const ackWaitMs = assertBoundedPositiveInt(
    options.ackWaitMs ?? fanoutCfg?.ack_wait_ms ?? Number(FANOUT_ACK_WAIT_MS),
    1_000,
    300_000,
    "consumer.ack_wait_ms"
  );
  const maxDeliver = assertBoundedPositiveInt(
    options.maxDeliver ?? fanoutCfg?.max_deliver ?? FANOUT_MAX_DELIVER,
    1,
    100,
    "consumer.max_deliver"
  );
  const maxAckPending = assertBoundedPositiveInt(
    options.maxAckPending ?? fanoutCfg?.max_ack_pending ?? FANOUT_MAX_ACK_PENDING,
    1,
    4_096,
    "consumer.max_ack_pending"
  );
  const maxBatch = assertBoundedPositiveInt(
    options.maxBatch ?? fanoutCfg?.max_batch ?? FANOUT_PULL_MAX_BATCH,
    1,
    256,
    "consumer.max_batch"
  );
  const pullMaxBytes = assertBoundedPositiveInt(
    options.pullMaxBytes ?? fanoutCfg?.max_bytes ?? FANOUT_PULL_MAX_BYTES,
    4_096,
    16_777_216,
    "consumer.max_bytes"
  );
  const maxExpiresMs = assertBoundedPositiveInt(
    options.maxExpiresMs ?? fanoutCfg?.max_expires_ms ?? BROKER_DEFAULT_PULL_MAX_EXPIRES_MS,
    1_000,
    60_000,
    "consumer.max_expires_ms"
  );

  const stream: BrokerStreamContract = Object.freeze({
    name: rawStreamName,
    subject_prefix: subjectPrefix,
    subjects: Object.freeze<readonly [string]>([subjectPattern]),
    storage: StorageType.File,
    retention: RetentionPolicy.Limits,
    discard: DiscardPolicy.New,
    discard_new_per_subject: false,
    max_msgs: maxMsgs,
    max_bytes: maxBytes,
    max_msg_size: BROKER_EVENT_MAX_PAYLOAD_BYTES,
    max_age_ns: maxAgeNs,
    duplicate_window_ns: BROKER_DEFAULT_DUPLICATE_WINDOW_NS,
    replicas
  });

  const consumer: BrokerConsumerContract = Object.freeze({
    stream_name: rawStreamName,
    durable_name: rawConsumerName,
    deliver_policy: DeliverPolicy.All,
    ack_policy: AckPolicy.Explicit,
    replay_policy: ReplayPolicy.Instant,
    ack_wait_ns: ackWaitMs * NS_PER_MS,
    max_deliver: maxDeliver,
    max_ack_pending: maxAckPending,
    max_batch: maxBatch,
    max_bytes: pullMaxBytes,
    max_expires_ns: maxExpiresMs * NS_PER_MS
  });

  const configDigest = sha256Utf8Hex(
    canonicalizeJson({ stream, consumer } as unknown as CanonicalJsonValue, "broker_topology_contract"),
    "broker_topology_contract"
  );

  return Object.freeze({
    stream,
    consumer,
    configuration_sha256: configDigest
  });
}

export const DEFAULT_DEV_BROKER_TOPOLOGY: BrokerTopologyContract = buildBrokerTopologyContract();

export const DEFAULT_DEV_STREAM_CONTRACT: BrokerStreamContract = DEFAULT_DEV_BROKER_TOPOLOGY.stream;

export const DEFAULT_DEV_CONSUMER_CONTRACT: BrokerConsumerContract =
  DEFAULT_DEV_BROKER_TOPOLOGY.consumer;

export function toNatsStreamConfig(
  contract: BrokerStreamContract
): Partial<StreamConfig> & { name: string } {
  return {
    name: contract.name,
    subjects: [...contract.subjects],
    storage: StorageType.File,
    retention: RetentionPolicy.Limits,
    discard: DiscardPolicy.New,
    discard_new_per_subject: false,
    max_msgs: contract.max_msgs,
    max_bytes: contract.max_bytes,
    max_msg_size: contract.max_msg_size,
    max_age: contract.max_age_ns,
    duplicate_window: contract.duplicate_window_ns,
    num_replicas: contract.replicas
  };
}

export function toNatsConsumerConfig(
  contract: BrokerConsumerContract
): Partial<ConsumerConfig> {
  return {
    durable_name: contract.durable_name,
    deliver_policy: DeliverPolicy.All,
    ack_policy: AckPolicy.Explicit,
    replay_policy: ReplayPolicy.Instant,
    ack_wait: contract.ack_wait_ns,
    max_deliver: contract.max_deliver,
    max_ack_pending: contract.max_ack_pending,
    max_batch: contract.max_batch,
    max_bytes: contract.max_bytes,
    max_expires: contract.max_expires_ns
  };
}

export function diffStreamConfig(
  actual: StreamInfo,
  expected: BrokerStreamContract
): readonly BrokerTopologyMismatch[] {
  const mismatches: BrokerTopologyMismatch[] = [];
  const cfg = actual.config;

  const check = (field: string, expectedVal: unknown, actualVal: unknown): void => {
    if (expectedVal !== actualVal) {
      mismatches.push({
        resource: "stream",
        field,
        expected: String(expectedVal),
        actual: String(actualVal)
      });
    }
  };

  check("name", expected.name, cfg.name);
  check("storage", expected.storage, cfg.storage);
  check("retention", expected.retention, cfg.retention);
  check("discard", expected.discard, cfg.discard);
  check("discard_new_per_subject", false, Boolean(cfg.discard_new_per_subject));
  check("max_msgs", expected.max_msgs, cfg.max_msgs);
  check("max_bytes", expected.max_bytes, cfg.max_bytes);
  check("max_msg_size", expected.max_msg_size, cfg.max_msg_size);
  check("max_age", expected.max_age_ns, cfg.max_age);
  check("duplicate_window", expected.duplicate_window_ns, cfg.duplicate_window);
  check("num_replicas", expected.replicas, cfg.num_replicas);

  const actualSubjects = Array.isArray(cfg.subjects) ? [...cfg.subjects] : [];
  if (
    actualSubjects.length !== expected.subjects.length ||
    actualSubjects[0] !== expected.subjects[0]
  ) {
    mismatches.push({
      resource: "stream",
      field: "subjects",
      expected: JSON.stringify(expected.subjects),
      actual: JSON.stringify(actualSubjects)
    });
  }

  if (typeof actual.created !== "string" || actual.created.trim().length === 0) {
    mismatches.push({
      resource: "stream",
      field: "created",
      expected: "non-empty ISO timestamp",
      actual: String(actual.created)
    });
  }

  return Object.freeze(mismatches);
}

export function diffConsumerConfig(
  actual: ConsumerInfo,
  expected: BrokerConsumerContract
): readonly BrokerTopologyMismatch[] {
  const mismatches: BrokerTopologyMismatch[] = [];
  const cfg = actual.config;

  const check = (field: string, expectedVal: unknown, actualVal: unknown): void => {
    if (expectedVal !== actualVal) {
      mismatches.push({
        resource: "consumer",
        field,
        expected: String(expectedVal),
        actual: String(actualVal)
      });
    }
  };

  check("stream_name", expected.stream_name, actual.stream_name);
  check("name", expected.durable_name, actual.name);
  check("durable_name", expected.durable_name, cfg.durable_name);
  check("deliver_policy", expected.deliver_policy, cfg.deliver_policy);
  check("ack_policy", expected.ack_policy, cfg.ack_policy);
  check("replay_policy", expected.replay_policy, cfg.replay_policy);
  check("ack_wait", expected.ack_wait_ns, cfg.ack_wait);
  check("max_deliver", expected.max_deliver, cfg.max_deliver);
  check("max_ack_pending", expected.max_ack_pending, cfg.max_ack_pending);
  check("max_batch", expected.max_batch, cfg.max_batch);
  check("max_bytes", expected.max_bytes, cfg.max_bytes);
  check("max_expires", expected.max_expires_ns, cfg.max_expires);

  if (cfg.deliver_subject !== undefined && cfg.deliver_subject !== "") {
    mismatches.push({
      resource: "consumer",
      field: "deliver_subject",
      expected: "unset (pull consumer)",
      actual: cfg.deliver_subject
    });
  }

  if (cfg.filter_subject !== undefined && cfg.filter_subject !== "") {
    mismatches.push({
      resource: "consumer",
      field: "filter_subject",
      expected: "unset",
      actual: cfg.filter_subject
    });
  }

  if (Array.isArray(cfg.filter_subjects) && cfg.filter_subjects.length > 0) {
    mismatches.push({
      resource: "consumer",
      field: "filter_subjects",
      expected: "unset",
      actual: JSON.stringify(cfg.filter_subjects)
    });
  }

  return Object.freeze(mismatches);
}

export function verifyStreamCompatibility(
  actual: StreamInfo,
  expected: BrokerStreamContract
): void {
  const mismatches = diffStreamConfig(actual, expected);
  if (mismatches.length > 0) {
    const summary = mismatches
      .map((m) => `${m.resource}.${m.field}: expected ${m.expected}, got ${m.actual}`)
      .join("; ");
    throw new BrokerTopologyMismatchError(
      `JetStream stream "${expected.name}" configuration mismatch: ${summary}`,
      mismatches
    );
  }
}

export function verifyConsumerCompatibility(
  actual: ConsumerInfo,
  expected: BrokerConsumerContract
): void {
  const mismatches = diffConsumerConfig(actual, expected);
  if (mismatches.length > 0) {
    const summary = mismatches
      .map((m) => `${m.resource}.${m.field}: expected ${m.expected}, got ${m.actual}`)
      .join("; ");
    throw new BrokerTopologyMismatchError(
      `JetStream consumer "${expected.durable_name}" configuration mismatch: ${summary}`,
      mismatches
    );
  }
}

function isStreamNotFoundError(err: unknown): boolean {
  if (err instanceof JetStreamApiError && err.code === JetStreamApiCodes.StreamNotFound) {
    return true;
  }
  if (err instanceof Error && err.name === "StreamNotFoundError") {
    return true;
  }
  return false;
}

function isConsumerNotFoundError(err: unknown): boolean {
  if (err instanceof JetStreamApiError && err.code === JetStreamApiCodes.ConsumerNotFound) {
    return true;
  }
  if (err instanceof Error && err.name === "ConsumerNotFoundError") {
    return true;
  }
  return false;
}

export async function inspectBrokerTopology(
  jsm: BrokerTopologyManager,
  contract: BrokerTopologyContract,
  options: InspectBrokerTopologyOptions = {}
): Promise<BrokerTopologyInspection> {
  if (
    options.expectedConfigurationSha256 !== undefined &&
    options.expectedConfigurationSha256 !== contract.configuration_sha256
  ) {
    throw new BrokerTopologyMismatchError("Broker topology configuration digest mismatch", [
      {
        resource: "stream",
        field: "configuration_sha256",
        expected: options.expectedConfigurationSha256,
        actual: contract.configuration_sha256
      }
    ]);
  }

  let streamInfo: StreamInfo;
  try {
    streamInfo = await jsm.streams.info(contract.stream.name);
  } catch (err) {
    if (isStreamNotFoundError(err)) {
      throw new BrokerUnavailableError(
        {
          message: `Required JetStream stream "${contract.stream.name}" does not exist`,
          retryable: true,
          acceptance: "known_rejected",
          stream: contract.stream.name,
          reasonCode: "STREAM_NOT_FOUND"
        },
        err
      );
    }
    throw new BrokerUnavailableError(
      {
        message: `Failed to inspect JetStream stream "${contract.stream.name}": ${err instanceof Error ? err.message : String(err)}`,
        retryable: true,
        acceptance: "known_rejected",
        stream: contract.stream.name,
        reasonCode: "STREAM_INFO_FAILED"
      },
      err
    );
  }

  verifyStreamCompatibility(streamInfo, contract.stream);

  if (
    options.expectedStreamCreatedAt !== undefined &&
    streamInfo.created !== options.expectedStreamCreatedAt
  ) {
    throw new BrokerTopologyMismatchError(
      `JetStream stream "${contract.stream.name}" creation timestamp changed unexpectedly`,
      [
        {
          resource: "stream",
          field: "created",
          expected: options.expectedStreamCreatedAt,
          actual: streamInfo.created
        }
      ]
    );
  }

  let consumerInfo: ConsumerInfo | undefined;
  if (options.verifyConsumer !== false) {
    try {
      consumerInfo = await jsm.consumers.info(
        contract.stream.name,
        contract.consumer.durable_name
      );
    } catch (err) {
      if (isConsumerNotFoundError(err)) {
        throw new BrokerUnavailableError(
          {
            message: `Required JetStream durable consumer "${contract.consumer.durable_name}" does not exist on stream "${contract.stream.name}"`,
            retryable: true,
            acceptance: "known_rejected",
            stream: contract.stream.name,
            reasonCode: "CONSUMER_NOT_FOUND"
          },
          err
        );
      }
      throw new BrokerUnavailableError(
        {
          message: `Failed to inspect JetStream consumer "${contract.consumer.durable_name}": ${err instanceof Error ? err.message : String(err)}`,
          retryable: true,
          acceptance: "known_rejected",
          stream: contract.stream.name,
          reasonCode: "CONSUMER_INFO_FAILED"
        },
        err
      );
    }
    verifyConsumerCompatibility(consumerInfo, contract.consumer);
  }

  return Object.freeze({
    streamInfo,
    ...(consumerInfo !== undefined ? { consumerInfo } : {}),
    observedStreamCreatedAt: streamInfo.created,
    configurationSha256: contract.configuration_sha256
  });
}

export async function ensureBrokerTopology(
  jsm: BrokerTopologyManager,
  contract: BrokerTopologyContract
): Promise<BrokerTopologyInspection> {
  let streamInfo: StreamInfo;
  try {
    streamInfo = await jsm.streams.info(contract.stream.name);
    verifyStreamCompatibility(streamInfo, contract.stream);
  } catch (err) {
    if (!isStreamNotFoundError(err)) {
      if (err instanceof BrokerTopologyMismatchError) {
        throw err;
      }
      throw new BrokerUnavailableError(
        {
          message: `Failed to verify JetStream stream "${contract.stream.name}": ${err instanceof Error ? err.message : String(err)}`,
          retryable: true,
          acceptance: "known_rejected",
          stream: contract.stream.name,
          reasonCode: "STREAM_INFO_FAILED"
        },
        err
      );
    }
    streamInfo = await jsm.streams.add(toNatsStreamConfig(contract.stream));
    verifyStreamCompatibility(streamInfo, contract.stream);
  }

  let consumerInfo: ConsumerInfo;
  try {
    consumerInfo = await jsm.consumers.info(
      contract.stream.name,
      contract.consumer.durable_name
    );
    verifyConsumerCompatibility(consumerInfo, contract.consumer);
  } catch (err) {
    if (!isConsumerNotFoundError(err)) {
      if (err instanceof BrokerTopologyMismatchError) {
        throw err;
      }
      throw new BrokerUnavailableError(
        {
          message: `Failed to verify JetStream consumer "${contract.consumer.durable_name}": ${err instanceof Error ? err.message : String(err)}`,
          retryable: true,
          acceptance: "known_rejected",
          stream: contract.stream.name,
          reasonCode: "CONSUMER_INFO_FAILED"
        },
        err
      );
    }
    consumerInfo = await jsm.consumers.add(
      contract.stream.name,
      toNatsConsumerConfig(contract.consumer)
    );
    verifyConsumerCompatibility(consumerInfo, contract.consumer);
  }

  return Object.freeze({
    streamInfo,
    consumerInfo,
    observedStreamCreatedAt: streamInfo.created,
    configurationSha256: contract.configuration_sha256
  });
}

export interface BrokerStreamGenerationProvenance {
  readonly broker_generation_id: BrokerGenerationId;
  readonly stream_name: string;
  readonly observed_stream_created_at: string;
  readonly configuration_sha256: string;
}

export function buildBrokerStreamGenerationProvenance(
  brokerGenerationId: BrokerGenerationId | string,
  inspection: BrokerTopologyInspection
): BrokerStreamGenerationProvenance {
  return Object.freeze({
    broker_generation_id: parseBrokerGenerationId(brokerGenerationId, "broker_generation_id"),
    stream_name: inspection.streamInfo.config.name,
    observed_stream_created_at: inspection.observedStreamCreatedAt,
    configuration_sha256: inspection.configurationSha256
  });
}

export {
  BROKER_DEFAULT_ACK_WAIT_NS,
  BROKER_DEFAULT_DUPLICATE_WINDOW_NS,
  BROKER_DEFAULT_MAX_AGE_NS,
  BROKER_DEFAULT_MAX_BYTES,
  BROKER_DEFAULT_MAX_MSGS,
  BROKER_DEFAULT_PULL_MAX_EXPIRES_MS,
  BROKER_DEFAULT_PULL_MAX_EXPIRES_NS
};
