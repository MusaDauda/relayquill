import {
  ADMIN_HELP_TEXT,
  createAdminApp,
  formatAdminJsonOutput,
  parseAdminCliArgs
} from "./index.js";

async function runCli(argv: readonly string[]): Promise<void> {
  const parsed = parseAdminCliArgs(argv);
  if (parsed.help) {
    process.stdout.write(`${ADMIN_HELP_TEXT}\n`);
    return;
  }

  const [group, subcommand] = parsed.positionals;
  const app = createAdminApp({
    configPath: parsed.configPath,
    envFilePath: parsed.envFilePath
  });

  if (group === "provider" && subcommand === "serve") {
    const noSeed = parsed.flags.get("--no-seed") === true;
    const seedDev = parsed.flags.get("--seed-dev") === true || !noSeed;
    const allowAdmins = parsed.flags.get("--allow-admins") === true;
    const handle = await app.startProviderServer({
      seedDefaults: seedDev,
      allowBuiltInAdmins: allowAdmins
    });
    if (parsed.flags.get("--reseed") === true) {
      await handle.reseed();
    }

    process.stdout.write(
      `${formatAdminJsonOutput({
        ok: true,
        event: "provider.listening",
        endpoint: handle.endpoint,
        count: handle.status().count
      })}\n`
    );

    let closed = false;
    const shutdown = async (): Promise<void> => {
      if (closed) {
        return;
      }
      closed = true;
      await app.close();
      process.exit(0);
    };

    process.once("SIGINT", () => {
      void shutdown();
    });
    process.once("SIGTERM", () => {
      void shutdown();
    });
    if (process.platform !== "win32") {
      process.on("SIGHUP", () => {
        void handle.reload().then((res) => {
          process.stdout.write(
            `${formatAdminJsonOutput({ ok: true, event: "provider.reloaded", ...res })}\n`
          );
        });
      });
    }
    await new Promise<void>(() => {
      // Remain running until SIGINT/SIGTERM triggers drain.
    });
    return;
  }

  try {
    const result = await app.run(argv);
    process.stdout.write(`${formatAdminJsonOutput(result)}\n`);
  } finally {
    await app.close();
  }
}

runCli(process.argv.slice(2)).catch((err: unknown) => {
  const message = err instanceof Error ? err.message : String(err);
  process.stderr.write(`relayquill-admin error: ${message}\n`);
  process.exit(1);
});
