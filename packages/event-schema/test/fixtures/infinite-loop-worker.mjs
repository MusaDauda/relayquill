import { parentPort } from "node:worker_threads";

if (parentPort !== null) {
  parentPort.on("message", () => {
    // Deliberate infinite CPU spin for timeout termination testing
    for (;;) {
      // spin until worker.terminate() kills the thread
    }
  });
}
