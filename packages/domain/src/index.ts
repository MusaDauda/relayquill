import { Temporal } from "@js-temporal/polyfill";

export const DOMAIN_PACKAGE_VERSION = "0.1.0" as const;

export function nowUtcInstant(): Temporal.Instant {
  return Temporal.Now.instant();
}
