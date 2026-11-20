import { ValidationDomainError } from "@relayquill/domain";

const SECRET_FLAG_NAMES = new Set([
  "--password",
  "--secret",
  "--token",
  "--api-key",
  "--credential",
  "--private-key",
  "--signing-key",
  "--nkey-seed",
  "--bearer"
]);

const KNOWN_VALUE_FLAGS = new Set([
  "--config",
  "--env-file",
  "--migrations-dir",
  "--manifest",
  "--intent-id",
  "--version",
  "--comparison-sha256",
  "--operator-ref",
  "--note",
  "--event-id",
  "--project-id",
  "--tenant-id",
  "--limit",
  "--kind",
  "--action-id",
  "--operation-id",
  "--incident-id",
  "--plan-file",
  "--reviewer-ref",
  "--decision",
  "--evidence-ref",
  "--reason-code"
]);

const KNOWN_BOOLEAN_FLAGS = new Set([
  "--help",
  "-h",
  "--json",
  "--seed-dev",
  "--no-seed",
  "--reseed",
  "--allow-admins",
  "--pending"
]);

const SECRET_LITERAL_PATTERN = /(^rq_p1\.|-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----|password\s*=|secret\s*=)/i;

export interface ParsedAdminCliArgs {
  readonly help: boolean;
  readonly configPath?: string | undefined;
  readonly envFilePath?: string | undefined;
  readonly positionals: readonly string[];
  readonly flags: ReadonlyMap<string, string | boolean>;
}

export const ADMIN_HELP_TEXT = `Usage: relayquill-admin [--config <path>] <command> <subcommand> [options]

Commands:
  db status                             Show applied/pending migrations and checksum status
  db migrate                            Apply pending SQL migrations in order
  db verify                             Verify migration checksums, extensions, and schema state
  broker inspect                        Inspect JetStream stream/consumer topology against contract
  broker ensure                         Ensure JetStream stream and durable consumer exist and match contract
  broker verify                         Verify JetStream topology matches contract (non-zero on drift)
  provider serve                        Run protected local IPC secret provider (Win32 DACL / POSIX 0600)
  access approve-enrollment             Approve a pending human passkey enrollment intent
  signing deliver                       Deliver pending signing key or credential intents to custody
  recovery inspect|plan|review|execute  Execute bounded two-person protected recovery actions
  diagnostics event|project|summary     Read redacted diagnostic views safely

Global options:
  --config <path>                       Path to role configuration JSON file
  --env-file <path>                     Optional .env file override
  -h, --help                            Show this help message
`;

export function parseAdminCliArgs(argv: readonly string[]): ParsedAdminCliArgs {
  const positionals: string[] = [];
  const flags = new Map<string, string | boolean>();
  let help = false;
  let configPath: string | undefined;
  let envFilePath: string | undefined;

  for (let i = 0; i < argv.length; i += 1) {
    const token = argv[i];
    if (token === undefined) {
      continue;
    }

    if (token === "--") {
      for (let j = i + 1; j < argv.length; j += 1) {
        const rest = argv[j];
        if (rest !== undefined) {
          if (SECRET_LITERAL_PATTERN.test(rest)) {
            throw new ValidationDomainError({
              code: "INVALID_VALUE",
              message: "Refusing secret-like literal in CLI arguments"
            });
          }
          positionals.push(rest);
        }
      }
      break;
    }

    if (token.startsWith("-")) {
      const eqIdx = token.indexOf("=");
      const flagName = eqIdx === -1 ? token : token.slice(0, eqIdx);
      const inlineValue = eqIdx === -1 ? undefined : token.slice(eqIdx + 1);

      if (SECRET_FLAG_NAMES.has(flagName)) {
        throw new ValidationDomainError({
          code: "INVALID_VALUE",
          message: `Refusing secret-bearing CLI argument "${flagName}"; use a secret provider instead`
        });
      }

      if (KNOWN_BOOLEAN_FLAGS.has(flagName)) {
        if (inlineValue !== undefined) {
          throw new ValidationDomainError({
            code: "INVALID_VALUE",
            message: `Flag "${flagName}" does not take a value`
          });
        }
        if (flagName === "--help" || flagName === "-h") {
          help = true;
        }
        flags.set(flagName, true);
        continue;
      }

      if (!KNOWN_VALUE_FLAGS.has(flagName)) {
        throw new ValidationDomainError({
          code: "INVALID_VALUE",
          message: `Unknown CLI flag "${flagName}"`
        });
      }

      let value = inlineValue;
      if (value === undefined) {
        i += 1;
        value = argv[i];
        if (value === undefined || value.startsWith("-")) {
          throw new ValidationDomainError({
            code: "INVALID_VALUE",
            message: `Flag "${flagName}" requires a value`
          });
        }
      }

      if (SECRET_LITERAL_PATTERN.test(value)) {
        throw new ValidationDomainError({
          code: "INVALID_VALUE",
          message: `Refusing secret-like literal passed to "${flagName}"`
        });
      }

      if (flagName === "--config") {
        configPath = value;
      } else if (flagName === "--env-file") {
        envFilePath = value;
      }
      flags.set(flagName, value);
      continue;
    }

    if (SECRET_LITERAL_PATTERN.test(token)) {
      throw new ValidationDomainError({
        code: "INVALID_VALUE",
        message: "Refusing secret-like literal in CLI arguments"
      });
    }
    positionals.push(token);
  }

  return Object.freeze({
    help,
    ...(configPath !== undefined ? { configPath } : {}),
    ...(envFilePath !== undefined ? { envFilePath } : {}),
    positionals: Object.freeze(positionals),
    flags
  });
}

export function getStringFlag(
  flags: ReadonlyMap<string, string | boolean>,
  name: string
): string | undefined {
  const val = flags.get(name);
  return typeof val === "string" ? val : undefined;
}

export function getRequiredStringFlag(
  flags: ReadonlyMap<string, string | boolean>,
  name: string
): string {
  const val = getStringFlag(flags, name);
  if (val === undefined || val.trim().length === 0) {
    throw new ValidationDomainError({
      code: "INVALID_VALUE",
      message: `Missing required CLI flag "${name}"`,
      fieldErrors: [{ path: name, code: "INVALID_VALUE" }]
    });
  }
  return val.trim();
}
