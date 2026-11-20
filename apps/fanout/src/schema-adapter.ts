import { DomainError, type Sha256Hex, ValidationDomainError } from "@relayquill/domain";
import { sha256Hex } from "@relayquill/contracts";
import { type SchemaEvaluatorPort } from "@relayquill/application";
import {
  type CompiledEventSchema,
  SchemaWorkerPool,
  type WorkerProjectionExecutionResult
} from "@relayquill/event-schema";

const MAX_SCHEMA_CACHE_ENTRIES = 256;

export type TargetSchemaResolver = (
  profileSha256: Sha256Hex,
  targetSchemaVersion: number
) => Promise<Uint8Array | undefined> | Uint8Array | undefined;

export class WorkerSchemaEvaluatorAdapter implements SchemaEvaluatorPort {
  readonly #pool: SchemaWorkerPool;
  readonly #ownsPool: boolean;
  readonly #schemaCache = new Map<string, Promise<CompiledEventSchema>>();
  readonly #targetSchemaRegistry = new Map<string, Uint8Array>();
  readonly #resolveTargetSchemaBytes: TargetSchemaResolver | undefined;
  #warmupPromise: Promise<void> | undefined;

  constructor(options: {
    readonly pool?: SchemaWorkerPool | undefined;
    readonly resolveTargetSchemaBytes?: TargetSchemaResolver | undefined;
  } = {}) {
    this.#pool = options.pool ?? new SchemaWorkerPool();
    this.#ownsPool = options.pool === undefined;
    this.#resolveTargetSchemaBytes = options.resolveTargetSchemaBytes;
  }

  #ensureWarmedUp(): Promise<void> {
    if (this.#warmupPromise === undefined) {
      this.#warmupPromise = this.#pool.warmup().catch((err) => {
        this.#warmupPromise = undefined;
        throw err;
      });
    }
    return this.#warmupPromise;
  }

  get pool(): SchemaWorkerPool {
    return this.#pool;
  }

  registerTargetSchema(profileSha256: Sha256Hex, targetSchemaBytes: Uint8Array): void {
    if (this.#targetSchemaRegistry.size >= MAX_SCHEMA_CACHE_ENTRIES) {
      const oldest = this.#targetSchemaRegistry.keys().next().value;
      if (oldest !== undefined) {
        this.#targetSchemaRegistry.delete(oldest);
      }
    }
    this.#targetSchemaRegistry.set(profileSha256, new Uint8Array(targetSchemaBytes));
  }

  async #getCompiledSchema(schemaBytes: Uint8Array): Promise<CompiledEventSchema> {
    await this.#ensureWarmedUp();
    const key = sha256Hex(schemaBytes);
    const cached = this.#schemaCache.get(key);
    if (cached !== undefined) {
      return cached;
    }

    const compilePromise = this.#pool.compileSchema(schemaBytes).catch((err) => {
      this.#schemaCache.delete(key);
      throw err;
    });

    if (this.#schemaCache.size >= MAX_SCHEMA_CACHE_ENTRIES) {
      const oldest = this.#schemaCache.keys().next().value;
      if (oldest !== undefined) {
        this.#schemaCache.delete(oldest);
      }
    }
    this.#schemaCache.set(key, compilePromise);
    return compilePromise;
  }

  async validateEvent(input: {
    readonly schemaBytes: Uint8Array;
    readonly profileVersion: string;
    readonly eventBytes: Uint8Array;
  }): Promise<{
    readonly valid: boolean;
    readonly diagnostics: SchemaEvaluatorPort extends { validateEvent(i: never): Promise<infer R> }
      ? R extends { readonly diagnostics: infer D }
        ? D
        : never
      : never;
    readonly byteCount: number;
    readonly sha256: Sha256Hex;
  }> {
    const compiledSchema = await this.#getCompiledSchema(input.schemaBytes);
    const result = await this.#pool.validateEvent({
      eventBytes: input.eventBytes,
      compiledSchema
    });
    return {
      valid: result.valid,
      diagnostics: result.diagnostics,
      byteCount: result.byteCount,
      sha256: result.sha256
    };
  }

  async evaluateFilterAndExtract(input: Parameters<SchemaEvaluatorPort["evaluateFilterAndExtract"]>[0]): ReturnType<SchemaEvaluatorPort["evaluateFilterAndExtract"]> {
    const compiledSchema = await this.#getCompiledSchema(input.schemaBytes);
    try {
      const res = await this.#pool.evaluateFilterAndExtract({
        eventBytes: input.eventBytes,
        compiledSchema,
        filterAst: input.filterAst,
        ...(input.orderingExtractorSpec !== undefined
          ? { orderingExtractor: input.orderingExtractorSpec }
          : {}),
        ...(input.orderingDigestScope !== undefined
          ? { orderingScope: input.orderingDigestScope }
          : {})
      });
      return {
        schemaValid: res.schemaValid,
        diagnostics: res.diagnostics,
        matched: res.matched,
        ...(res.ordering !== undefined ? { ordering: res.ordering } : {})
      };
    } catch (err) {
      if (
        err instanceof DomainError &&
        input.orderingExtractorSpec !== undefined &&
        (err.code.includes("ORDERING") || err.code === "INVALID_VALUE")
      ) {
        return {
          schemaValid: true,
          diagnostics: [],
          matched: true,
          orderingErrorCode: err.code
        };
      }
      throw err;
    }
  }

  async executeProjection(
    input: Parameters<SchemaEvaluatorPort["executeProjection"]>[0]
  ): ReturnType<SchemaEvaluatorPort["executeProjection"]> {
    const profileSha256 = sha256Hex(input.profileBytes);
    let profileJson: unknown;
    try {
      const text = new TextDecoder("utf-8", { fatal: true }).decode(input.profileBytes);
      profileJson = JSON.parse(text) as unknown;
    } catch {
      throw new ValidationDomainError({
        code: "INVALID_VALUE",
        message: "Invalid UTF-8/JSON in representation profile definition"
      });
    }
    const targetVersionRaw =
      typeof profileJson === "object" && profileJson !== null && !Array.isArray(profileJson)
        ? (profileJson as Record<string, unknown>)["target_schema_version"]
        : undefined;
    const targetSchemaVersion =
      typeof targetVersionRaw === "number" && Number.isInteger(targetVersionRaw)
        ? targetVersionRaw
        : 1;

    let targetSchemaBytes = this.#targetSchemaRegistry.get(profileSha256);
    if (targetSchemaBytes === undefined && this.#resolveTargetSchemaBytes !== undefined) {
      targetSchemaBytes = await this.#resolveTargetSchemaBytes(profileSha256, targetSchemaVersion);
      if (targetSchemaBytes !== undefined) {
        this.registerTargetSchema(profileSha256, targetSchemaBytes);
      }
    }

    const sourceSchema = await this.#getCompiledSchema(input.sourceSchemaBytes);
    const targetSchema =
      targetSchemaBytes !== undefined
        ? await this.#getCompiledSchema(targetSchemaBytes)
        : sourceSchema;

    const executed: WorkerProjectionExecutionResult = await this.#pool.executeProjection({
      sourceBytes: input.sourceEventBytes,
      sourceSchema,
      targetSchema,
      profileDefinition: profileJson
    });

    return {
      derivedJson: executed.derivedJson,
      derivedBytes: executed.derivedBytes,
      derivedByteCount: executed.derivedByteCount,
      derivedContentSha256: executed.derivedContentSha256,
      targetSchemaVersion: executed.targetSchemaVersion,
      provenance: executed.provenance
    };
  }

  async close(): Promise<void> {
    this.#schemaCache.clear();
    this.#targetSchemaRegistry.clear();
    if (this.#ownsPool) {
      await this.#pool.close();
    }
  }
}
