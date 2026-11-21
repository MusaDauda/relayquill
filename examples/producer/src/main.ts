import process from "node:process";
import { runProducerCli } from "./index.js";

const isDirectExecution =
  process.argv[1] !== undefined &&
  (import.meta.url.endsWith(process.argv[1].replace(/\\/g, "/")) ||
    process.argv[1].endsWith("main.js") ||
    process.argv[1].endsWith("main.ts"));

if (isDirectExecution) {
  runProducerCli()
    .then((code) => {
      process.exitCode = code;
    })
    .catch((err) => {
      const msg = err instanceof Error ? err.stack ?? err.message : String(err);
      process.stderr.write(`${msg}\n`);
      process.exitCode = 1;
    });
}
