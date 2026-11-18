import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";

const REPO_ROOT = path.resolve(import.meta.dirname, "../../..");
const TSC_BIN = path.join(REPO_ROOT, "node_modules", "typescript", "bin", "tsc");
const DOMAIN_DTS = path.join(REPO_ROOT, "packages", "domain", "dist", "index.d.ts").replace(
  /\\/g,
  "/"
);

test("Branded types preserve nominal isolation without collapsing to never", () => {
  const tempDir = mkdtempSync(path.join(os.tmpdir(), "relayquill-brand-types-"));
  try {
    const tsconfigPath = path.join(tempDir, "tsconfig.json");
    const probePath = path.join(tempDir, "probe.ts");

    writeFileSync(
      tsconfigPath,
      JSON.stringify(
        {
          compilerOptions: {
            target: "ES2023",
            module: "NodeNext",
            moduleResolution: "NodeNext",
            verbatimModuleSyntax: true,
            isolatedModules: true,
            strict: true,
            exactOptionalPropertyTypes: true,
            noUncheckedIndexedAccess: true,
            types: [],
            noEmit: true,
            paths: {
              "@relayquill/domain": [DOMAIN_DTS]
            }
          },
          include: ["probe.ts"]
        },
        null,
        2
      ),
      "utf8"
    );

    const probeSource = `
import type {
  CanonicalUtcTimestamp,
  CanonicalUuid,
  DeliveryId,
  EventId,
  Int64String,
  NonNegativeInt64String,
  PositiveInt64String,
  ProjectId,
  Sha256Hex,
  TenantId
} from "@relayquill/domain";

type AssertTrue<T extends true> = T;
type AssertEqual<T, U> = [T] extends [U] ? ([U] extends [T] ? true : false) : false;

declare const canonicalUuid: CanonicalUuid;
declare const tenantId: TenantId;
declare const projectId: ProjectId;
declare const eventId: EventId;
declare const deliveryId: DeliveryId;
declare const int64: Int64String;
declare const nonNegInt64: NonNegativeInt64String;
declare const posInt64: PositiveInt64String;
declare const rawString: string;

// Positive subtype assignability checks
const uuidFromTenant: CanonicalUuid = tenantId;
const strFromTenant: string = tenantId;
const nonNegFromPos: NonNegativeInt64String = posInt64;
const int64FromPos: Int64String = posInt64;
const strFromPos: string = posInt64;
void uuidFromTenant;
void strFromTenant;
void nonNegFromPos;
void int64FromPos;
void strFromPos;

// Type-level equality and non-never verification
type _CheckTenantNotProject = AssertTrue<AssertEqual<TenantId extends ProjectId ? true : false, false>>;
type _CheckEventNotDelivery = AssertTrue<AssertEqual<EventId extends DeliveryId ? true : false, false>>;
type _CheckTenantSubCanonical = AssertTrue<AssertEqual<TenantId extends CanonicalUuid ? true : false, true>>;
type _CheckTenantNotNever = AssertTrue<AssertEqual<TenantId extends never ? true : false, false>>;
type _CheckPosSubNonNeg = AssertTrue<AssertEqual<PositiveInt64String extends NonNegativeInt64String ? true : false, true>>;
type _CheckNonNegNotPos = AssertTrue<AssertEqual<NonNegativeInt64String extends PositiveInt64String ? true : false, false>>;

// Negative assignability checks (must fail tsc without @ts-expect-error)
// @ts-expect-error TenantId must not be assignable to ProjectId
const badProject: ProjectId = tenantId;
// @ts-expect-error ProjectId must not be assignable to TenantId
const badTenantFromProject: TenantId = projectId;
// @ts-expect-error EventId must not be assignable to DeliveryId
const badDelivery: DeliveryId = eventId;
// @ts-expect-error DeliveryId must not be assignable to EventId
const badEvent: EventId = deliveryId;
// @ts-expect-error CanonicalUuid must not be assignable to TenantId
const badTenantFromUuid: TenantId = canonicalUuid;
// @ts-expect-error NonNegativeInt64String must not be assignable to PositiveInt64String
const badPosFromNonNeg: PositiveInt64String = nonNegInt64;
// @ts-expect-error Int64String must not be assignable to NonNegativeInt64String
const badNonNegFromInt64: NonNegativeInt64String = int64;
// @ts-expect-error TenantId must not be assignable to number (fails if collapsed to never)
const badNumberFromTenant: number = tenantId;
// @ts-expect-error string must not be assignable to CanonicalUtcTimestamp
const badTimestamp: CanonicalUtcTimestamp = rawString;
// @ts-expect-error string must not be assignable to Sha256Hex
const badHash: Sha256Hex = rawString;
// @ts-expect-error string must not be assignable to CanonicalUuid
const badUuid: CanonicalUuid = rawString;

void badProject;
void badTenantFromProject;
void badDelivery;
void badEvent;
void badTenantFromUuid;
void badPosFromNonNeg;
void badNonNegFromInt64;
void badNumberFromTenant;
void badTimestamp;
void badHash;
void badUuid;
`;

    writeFileSync(probePath, probeSource, "utf8");

    execFileSync(process.execPath, [TSC_BIN, "-p", tsconfigPath, "--noEmit"], {
      cwd: tempDir,
      encoding: "utf8",
      stdio: "pipe"
    });
  } catch (error) {
    const details =
      error instanceof Error && "stdout" in error
        ? `${String(error.stdout)}\n${String(error.stderr)}`
        : String(error);
    assert.fail(`TypeScript brand isolation check failed:\n${details}`);
  } finally {
    rmSync(tempDir, { recursive: true, force: true });
  }
});
