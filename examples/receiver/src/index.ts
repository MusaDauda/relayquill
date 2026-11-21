export const EXAMPLE_RECEIVER_VERSION = "0.1.0" as const;

export {
  ReceiverRepository,
  createPgDeliveryExecutionScope,
  createReceiverDbClient,
  rawToSha256Hex,
  sha256HexToBuffer,
  type BoundDeliveryCommitInfo,
  type CreateReceiverDbOptions,
  type PGliteCompatibleClient,
  type ReceiverDbClient,
  type ReceiverIntegrationRecord,
  type ReceiverKeyMetadataRecord,
  type ReceiverQueryResult,
  type ReceiverSqlTxClient,
  type ReceiverStateSnapshot
} from "./db.js";
export {
  ReceiverFaultController,
  startReceiverControlIpcServer,
  type ReceiverFaultSnapshot
} from "./faults.js";
export {
  createReceiverServer,
  type ReceiverServerHandle,
  type ReceiverServerOptions
} from "./server.js";
export {
  parseReceiverCliArgs,
  runReceiverCli,
  type ReceiverCliOptions
} from "./main.js";
