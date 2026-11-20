export const SENDER_APP_VERSION = "0.1.0" as const;

export * from "./custody.js";
export * from "./repository.js";
export * from "./health.js";
export * from "./worker.js";
export { parseSenderCliArgs, runSenderCli, type SenderCliOptions } from "./main.js";
