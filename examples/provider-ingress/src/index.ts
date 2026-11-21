export const EXAMPLE_PROVIDER_INGRESS_VERSION = "0.1.0" as const;

export {
  ProviderIngressDbError,
  ProviderIngressRepository,
  createProviderIngressDbClient,
  sha256HexToBuffer,
  type AccountMode,
  type ClaimForwardIntentResult,
  type CreateProviderIngressDbOptions,
  type DueForwardIntentRecord,
  type FinalizeForwardIntentResult,
  type ForwardFinalizeOutcome,
  type PGliteCompatibleClient,
  type ProviderBindingRecord,
  type ProviderIngressDbClient,
  type ProviderIngressQueryResult,
  type ProviderIngressSqlTxClient,
  type ProviderIngressStateSnapshot,
  type ProviderKind,
  type ReceiveVerifiedCallbackParams,
  type ReceiveVerifiedCallbackResult
} from "./db.js";
export {
  ProviderVerificationError,
  normalizePaystackCallback,
  normalizeStripeCallback,
  verifyPaystackWebhookCallback,
  verifyStripeWebhookCallback,
  type NormalizedProviderCallback
} from "./verify.js";
export {
  PREPARED_SUBMISSION_SCHEMA_VERSION,
  ProviderOutboxForwarder,
  prepareNormalizedCallbackSubmission,
  reconstructPreparedForwardPayload,
  type ForwardCycleSummary,
  type ForwardIntentProcessOutcome,
  type PreparedCallbackSubmission,
  type PreparedForwardPayload,
  type ProviderForwarderOptions
} from "./forwarder.js";
export {
  createProviderIngressServer,
  type ProviderIngressServerHandle,
  type ProviderIngressServerOptions
} from "./server.js";
export {
  generatePaystackWebhookFixture,
  generateStripeWebhookFixture,
  runProviderIngressFixtures,
  type FixtureCheckResult,
  type GeneratedWebhookFixture,
  type ProviderIngressFixtureSuiteResult
} from "./fixtures.js";
export {
  parseProviderIngressCliArgs,
  runProviderIngressCli,
  type ProviderIngressCliOptions
} from "./main.js";
