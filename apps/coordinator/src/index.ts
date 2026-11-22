export const COORDINATOR_APP_VERSION = "0.1.0" as const;

export {
  CoordinatorRelayRepository,
  PostgresMaintenanceRepository,
  type CoordinatorDeltaCompactionSummary,
  type CoordinatorProjectScope
} from "./repository.js";
export {
  CoordinatorWorker,
  createCoordinatorWorker,
  type CoordinatorProjectionSweepOutput,
  type CoordinatorWorkerHealthSnapshot,
  type CoordinatorWorkerOptions,
  type CoordinatorWorkerRunResult
} from "./worker.js";
export {
  CoordinatorHealthServer,
  createCoordinatorHealthServer,
  type CoordinatorHealthProbe,
  type CoordinatorHealthServerOptions
} from "./health.js";
export {
  parseCoordinatorCliArgs,
  runCoordinatorCli,
  type CoordinatorCliOptions
} from "./main.js";
export {
  runBillingGraceExpirySweep,
  runEmailOutboxSweep,
  runGdprErasureCompletionSweep,
  type BillingGraceSweepOptions,
  type BillingGraceSweepSummary,
  type EmailOutboxSweepOptions,
  type GdprErasureSweepOptions,
  type GdprErasureSweepSummary
} from "./commercial-sweeps.js";
